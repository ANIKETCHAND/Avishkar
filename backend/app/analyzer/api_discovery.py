"""
API & Endpoint Discovery — Upgraded
=====================================
Builds Endpoint objects from AST analysis results and service assignments.
Extracts:
- HTTP method and route path
- Handler function name and line range
- Authentication and authorization checks (including router-level and semantic checks)
- Sensitive operation flags (method + state-mutation intent)

Discovers ServiceCall objects from outgoing HTTP client calls:
- Precise endpoint association by handler name & line range
- Strong URL resolution (constants, f-strings, hostname, route matching)
- Semantic identity propagation classification
"""

from __future__ import annotations

import logging
import re
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models.schemas import (
    Endpoint, Service, ServiceCall,
    IDENTITY_FORWARDED_USER_JWT, IDENTITY_SERVICE_TOKEN,
    IDENTITY_STRIPPED, IDENTITY_UNKNOWN,
)
from .ast_visitor import FileAnalysisResult, RouteDefinition, HttpCallDefinition

logger = logging.getLogger(__name__)


def _extract_url_path(url: str) -> str:
    """Extract path component from URL string."""
    if not url or url == "<dynamic>":
        return url or "/"
    url = re.sub(r"^https?://[^/]+", "", url)
    url = re.sub(r"[?#].*$", "", url)
    return url or "/"


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
                if ep.route == path or (len(ep.route) > 3 and path.endswith(ep.route.rstrip("/"))):
                    return ep.service_id

    return "UNKNOWN"


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
            )
            endpoints.append(endpoint)

    logger.info("Endpoint discovery: found %d endpoints", len(endpoints))
    return endpoints


def discover_service_calls(
    ast_results: List[FileAnalysisResult],
    services: List[Service],
    endpoints: List[Endpoint],
) -> List[ServiceCall]:
    """Build ServiceCall objects linking source endpoints to destination services."""
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

            # 3. Classify identity propagation
            identity_prop = _classify_identity_propagation(http_call)

            call_id = _make_call_id(source_ep_id or f"ep_{source_service_id}", http_call.line)
            dest_route = _extract_url_path(http_call.url)

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
        # Check if any passed header is dynamic
        if any("<var:" in h for h in http_call.passed_headers):
            return IDENTITY_UNKNOWN
        return IDENTITY_STRIPPED
