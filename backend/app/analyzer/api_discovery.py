"""
API & Endpoint Discovery — Engine v2.0.0
=========================================
Builds Endpoint and ServiceCall models with precise route matching:
- Normalized path template matching (/orders/{id} <-> /orders/123)
- Query string stripping, trailing slash normalization, and prefix handling
- Strict caller-to-callee endpoint matching (prevents checking 'all endpoints')
- Precise identity provenance mapping from AST data-flow facts
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models.schemas import (
    Endpoint, Service, ServiceCall,
    IDENTITY_FORWARDED_USER_JWT, IDENTITY_SERVICE_TOKEN,
    IDENTITY_STRIPPED, IDENTITY_UNKNOWN,
)
from ..models.ir import IdentityProvenance
from .ast_visitor import FileAnalysisResult, RouteDefinition, HttpCallDefinition

logger = logging.getLogger(__name__)


def _extract_url_path(url: str) -> str:
    """Extract path component from URL string, stripping schema, host, and query params."""
    if not url or url == "<dynamic>":
        return url or "/"
    clean = re.sub(r"^https?://[^/]+", "", url)
    clean = re.sub(r"[?#].*$", "", clean)
    clean = clean.strip()
    if not clean:
        return "/"
    return clean


def normalize_route_pattern(route: str) -> str:
    """
    Normalize route path for consistent template matching:
    - Replaces path parameters like {id}, {order_id}, :id with standard token {param}
    - Strips trailing slash unless path is '/'
    """
    clean = _extract_url_path(route)
    # Replace FastAPI {param_name} or Express :param_name
    normalized = re.sub(r"\{[a-zA-Z0-9_\-]+\}", "{param}", clean)
    normalized = re.sub(r":[a-zA-Z0-9_\-]+", "{param}", normalized)
    normalized = re.sub(r"/+", "/", normalized)
    if len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    return normalized


def routes_match(declared_route: str, called_route: str) -> bool:
    """
    Check if a called URL path matches a declared route template:
    Example: '/orders/{id}' matches '/orders/123' and '/orders/abc'
    """
    decl_norm = normalize_route_pattern(declared_route)
    call_norm = normalize_route_pattern(called_route)

    if decl_norm == call_norm:
        return True

    # Build regex from declared route
    # Replace {param} with regex pattern [^/]+
    regex_pattern = "^" + re.escape(decl_norm).replace(r"\{param\}", r"[^/]+") + "$"
    if re.match(regex_pattern, call_norm):
        return True

    # Suffix matching for stripped prefixes e.g. /v1/refund matching /refund
    if len(decl_norm) > 3 and (call_norm.endswith(decl_norm) or decl_norm.endswith(call_norm)):
        return True

    return False


def _infer_target_service(
    url: str,
    services: List[Service],
    endpoints: Optional[List[Endpoint]] = None,
) -> str:
    """
    Infer target service from URL hostname, service names, and route paths.
    Returns service_id if resolved with confidence, or 'UNKNOWN'.
    """
    if not url or url == "<dynamic>":
        return "UNKNOWN"

    url_lower = url.lower()

    # 1. Match against known service names and path segments
    for service in services:
        candidates = [
            service.name.lower(),
            service.name.lower().replace("-", "_"),
            service.name.lower().replace("_", "-"),
            service.service_id.lower().replace("svc_", ""),
            Path(service.path).name.lower(),
            Path(service.path).name.lower().replace("_", "-"),
            Path(service.path).name.lower().replace("-", "_"),
        ]
        for pattern in dict.fromkeys(candidates):
            if pattern and len(pattern) > 2 and pattern in url_lower:
                return service.service_id

    # 2. Match URL path against known endpoint routes if endpoints are provided
    if endpoints:
        path = _extract_url_path(url)
        if path and path not in ("<dynamic>", "/"):
            for ep in endpoints:
                if routes_match(ep.route, path):
                    return ep.service_id

    return "UNKNOWN"


def _match_target_endpoint(
    method: str,
    called_route: str,
    target_service_id: str,
    endpoints: List[Endpoint],
) -> Optional[Endpoint]:
    """
    Find the specific endpoint handler in target service that matches the method and route.
    Prevents false assumptions over all endpoints in target service.
    """
    method_upper = method.upper()
    target_eps = [e for e in endpoints if e.service_id == target_service_id]

    # Exact method + route match
    for ep in target_eps:
        if ep.method == method_upper and routes_match(ep.route, called_route):
            return ep

    # Method-independent route match fallback
    for ep in target_eps:
        if routes_match(ep.route, called_route):
            return ep

    return None


def _make_endpoint_id(service_id: str, method: str, route: str) -> str:
    """Deterministic endpoint ID."""
    slug = re.sub(r"[^a-z0-9]", "_", route.lower().strip("/"))
    slug = re.sub(r"_+", "_", slug).strip("_")
    return f"ep_{service_id.replace('svc_', '')}_{method.lower()}_{slug[:30]}"


def _make_call_id(source_ep_id: str, line: int) -> str:
    """Deterministic call ID."""
    return f"call_{source_ep_id}_{line}"


def discover_endpoints(
    ast_results: List[FileAnalysisResult],
    services: List[Service],
    workspace_root: Path,
) -> List[Endpoint]:
    """Build Endpoint objects from AST results and assign them to services."""
    endpoints: List[Endpoint] = []
    seen_ids: set = set()

    file_to_service = _build_file_service_map(ast_results, services)

    for result in ast_results:
        if result.parse_error and not result.routes:
            continue

        service_id = file_to_service.get(result.file_path, _guess_service_from_path(result.file_path, services))

        for route in result.routes:
            ep_id = _make_endpoint_id(service_id, route.method, route.path)

            counter = 1
            base_id = ep_id
            while ep_id in seen_ids:
                ep_id = f"{base_id}_{counter}"
                counter += 1
            seen_ids.add(ep_id)

            combined_checks = list(route.authz_checks) + list(route.auth_deps) + list(route.rejection_paths)

            endpoint = Endpoint(
                endpoint_id=ep_id,
                service_id=service_id,
                method=route.method,
                route=route.path,
                handler=route.handler_name,
                file=result.file_path,
                line_start=route.line_start,
                line_end=route.line_end,
                authentication=route.has_authentication,
                authorization_checks=list(dict.fromkeys(combined_checks)),
                is_sensitive=route.is_sensitive,
                authn_state=route.authn_state.value if hasattr(route, "authn_state") else "AUTHENTICATION_UNKNOWN",
                authz_state=route.authz_state.value if hasattr(route, "authz_state") else "AUTHORIZATION_UNKNOWN",
                authz_type=route.authz_type.value if hasattr(route, "authz_type") else "UNKNOWN",
            )
            endpoints.append(endpoint)

    logger.info("Endpoint discovery: found %d endpoints", len(endpoints))
    return endpoints


def discover_service_calls(
    ast_results: List[FileAnalysisResult],
    services: List[Service],
    endpoints: List[Endpoint],
) -> List[ServiceCall]:
    """Build ServiceCall objects linking source endpoints to destination services and endpoints."""
    calls: List[ServiceCall] = []

    file_to_service = _build_file_service_map(ast_results, services)

    file_to_endpoints: Dict[str, List[Endpoint]] = {}
    for ep in endpoints:
        if ep.file not in file_to_endpoints:
            file_to_endpoints[ep.file] = []
        file_to_endpoints[ep.file].append(ep)

    for result in ast_results:
        source_service_id = file_to_service.get(result.file_path, "UNKNOWN")
        file_eps = file_to_endpoints.get(result.file_path, [])

        for http_call in result.http_calls:
            # 1. Associate source endpoint by handler name if available, else by line
            source_ep_id = None
            if http_call.source_handler:
                for ep in file_eps:
                    if ep.handler == http_call.source_handler:
                        source_ep_id = ep.endpoint_id
                        break

            if not source_ep_id:
                source_ep_id = _find_containing_endpoint(http_call.line, file_eps)

            # 2. Infer target service with endpoint routes context
            dest_service_id = _infer_target_service(http_call.url, services, endpoints)
            dest_route = _extract_url_path(http_call.url)

            # 3. Match specific destination endpoint
            matched_ep = _match_target_endpoint(http_call.method, dest_route, dest_service_id, endpoints)
            matched_ep_id = matched_ep.endpoint_id if matched_ep else ("UNKNOWN_TARGET_ENDPOINT" if dest_service_id != "UNKNOWN" else None)

            # 4. Classify identity propagation using AST provenance
            identity_prop = _classify_identity_propagation(http_call)

            call_id = _make_call_id(source_ep_id or f"ep_{source_service_id}", http_call.line)

            call = ServiceCall(
                call_id=call_id,
                source_service_id=source_service_id,
                source_endpoint_id=source_ep_id or f"ep_{source_service_id}_unknown",
                destination_service_id=dest_service_id,
                destination_route=dest_route,
                http_method=http_call.method,
                source_file=result.file_path,
                source_line=http_call.line,
                call_type="HTTP_CLIENT",
                identity_propagation=identity_prop,
                passed_headers=http_call.passed_headers,
                provenance_state=http_call.provenance.value if hasattr(http_call.provenance, "value") else "UNKNOWN",
                matched_endpoint_id=matched_ep_id,
            )
            calls.append(call)

    logger.info("Service call discovery: identified %d service calls", len(calls))
    return calls


def _build_file_service_map(
    ast_results: List[FileAnalysisResult],
    services: List[Service],
) -> Dict[str, str]:
    file_to_service: Dict[str, str] = {}

    for service in services:
        service_path = service.path

        for result in ast_results:
            file_path = result.file_path
            if service_path == ".":
                if len(Path(file_path).parts) == 1:
                    file_to_service[file_path] = service.service_id
            elif file_path.startswith(service_path + "/") or file_path.startswith(service_path + "\\"):
                file_to_service[file_path] = service.service_id
            elif Path(file_path).parts[:len(Path(service_path).parts)] == Path(service_path).parts:
                file_to_service[file_path] = service.service_id

    return file_to_service


def _guess_service_from_path(file_path: str, services: List[Service]) -> str:
    parts = Path(file_path).parts
    for service in services:
        for part in parts:
            if part.lower() in service.name.lower() or service.name.lower() in part.lower():
                return service.service_id
    return "svc_unknown"


def _find_containing_endpoint(line: int, endpoints: List[Endpoint]) -> Optional[str]:
    best: Optional[Endpoint] = None
    for ep in endpoints:
        if ep.line_start <= line <= (ep.line_end + 30):
            if best is None or ep.line_start > best.line_start:
                best = ep
    return best.endpoint_id if best else None


def _classify_identity_propagation(http_call: HttpCallDefinition) -> str:
    """
    Classify identity propagation based on verified AST evidence:
    - FORWARDED_USER_JWT: Authorization header forwarded
    - SERVICE_TOKEN: Service credential passed without user JWT
    - STRIPPED: No auth headers attached
    - UNKNOWN: Dynamic or unresolvable headers
    """
    if http_call.has_authorization_header:
        return IDENTITY_FORWARDED_USER_JWT
    elif http_call.has_service_token:
        return IDENTITY_SERVICE_TOKEN
    elif not http_call.passed_headers:
        return IDENTITY_STRIPPED
    else:
        if any("<var:" in h for h in http_call.passed_headers):
            return IDENTITY_UNKNOWN
        return IDENTITY_STRIPPED
