"""
API & Endpoint Discovery — Phase 5
=====================================
Builds Endpoint objects from AST analysis results and service assignments.
Extracts:
- HTTP method and route path
- Handler function name and line range
- Authentication and authorization checks
- Sensitive operation flags

Also discovers ServiceCall objects from outgoing HTTP client calls,
linking them to their source endpoints and inferring target services.
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

# ─────────────────────────── URL Pattern Utilities ───────────────────────

def _extract_url_path(url: str) -> str:
    """Extract just the path component from a URL string."""
    if not url or url == "<dynamic>":
        return url or "/"
    # Remove scheme and host
    url = re.sub(r"^https?://[^/]+", "", url)
    # Remove query string and fragment
    url = re.sub(r"[?#].*$", "", url)
    return url or "/"


def _infer_target_service(url: str, services: List[Service]) -> str:
    """
    Attempt to infer the target service from a URL string.
    Matches URL hostname patterns against known service names.
    Handles f-string templates, variable-based URLs, and hostname patterns.
    """
    if not url or url == "<dynamic>":
        return "UNKNOWN"

    url_lower = url.lower()

    # Try to match service name or service_id in the URL
    for service in services:
        # Build multiple candidate patterns to match against
        candidates = [
            service.name.lower(),
            service.name.lower().replace("-", "_"),
            service.name.lower().replace("_", "-"),
            service.service_id.lower().replace("svc_", ""),
            # Also match path segments from service path
            Path(service.path).name.lower(),
            Path(service.path).name.lower().replace("_", "-"),
            Path(service.path).name.lower().replace("-", "_"),
        ]
        # De-duplicate and match
        for pattern in dict.fromkeys(candidates):
            if pattern and len(pattern) > 2 and pattern in url_lower:
                return service.service_id

    return "UNKNOWN"


def _make_endpoint_id(service_id: str, method: str, route: str) -> str:
    """Create a deterministic endpoint ID from its components."""
    slug = re.sub(r"[^a-z0-9]", "_", route.lower().strip("/"))
    slug = re.sub(r"_+", "_", slug).strip("_")
    return f"ep_{service_id.replace('svc_', '')}_{method.lower()}_{slug[:30]}"


def _make_call_id(source_ep_id: str, line: int) -> str:
    """Create a unique call ID."""
    return f"call_{source_ep_id}_{line}"


# ─────────────────────────── Main Discovery Functions ─────────────────────

def discover_endpoints(
    ast_results: List[FileAnalysisResult],
    services: List[Service],
    workspace_root: Path,
) -> List[Endpoint]:
    """
    Build Endpoint objects from AST analysis results, assigned to services.

    Args:
        ast_results: All file analysis results.
        services: Discovered services.
        workspace_root: Workspace root for path computation.

    Returns:
        List of Endpoint objects.
    """
    endpoints: List[Endpoint] = []
    seen_ids: set = set()

    # Build a map: file_path -> service_id
    file_to_service = _build_file_service_map(ast_results, services)

    for result in ast_results:
        if result.parse_error and not result.routes:
            continue

        service_id = file_to_service.get(result.file_path, _guess_service_from_path(result.file_path, services))

        for route in result.routes:
            ep_id = _make_endpoint_id(service_id, route.method, route.path)

            # Handle duplicate IDs
            counter = 1
            base_id = ep_id
            while ep_id in seen_ids:
                ep_id = f"{base_id}_{counter}"
                counter += 1
            seen_ids.add(ep_id)

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
                authorization_checks=route.authz_checks + route.auth_deps,
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
    """
    Build ServiceCall objects from discovered HTTP client calls.

    Args:
        ast_results: All file analysis results.
        services: Discovered services.
        endpoints: Previously discovered endpoints.

    Returns:
        List of ServiceCall objects.
    """
    calls: List[ServiceCall] = []

    # Build a map: file_path -> service_id
    file_to_service = _build_file_service_map(ast_results, services)

    # Build a map: file_path -> list of endpoints (for finding source endpoint)
    file_to_endpoints: Dict[str, List[Endpoint]] = {}
    for ep in endpoints:
        if ep.file not in file_to_endpoints:
            file_to_endpoints[ep.file] = []
        file_to_endpoints[ep.file].append(ep)

    for result in ast_results:
        source_service_id = file_to_service.get(result.file_path, "UNKNOWN")

        for http_call in result.http_calls:
            # Find the closest endpoint that contains this HTTP call line
            source_ep_id = _find_containing_endpoint(
                http_call.line,
                file_to_endpoints.get(result.file_path, []),
            )

            # Infer target service
            dest_service_id = _infer_target_service(http_call.url, services)

            # Classify identity propagation
            identity_prop = _classify_identity_propagation(http_call)

            call_id = _make_call_id(source_ep_id or f"ep_{source_service_id}", http_call.line)

            # Extract path from URL
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

    logger.info("Service call discovery: found %d service calls", len(calls))
    return calls


# ─────────────────────────── Helper Functions ─────────────────────────────

def _build_file_service_map(
    ast_results: List[FileAnalysisResult],
    services: List[Service],
) -> Dict[str, str]:
    """Build a mapping from file path to service_id."""
    file_to_service: Dict[str, str] = {}

    for service in services:
        service_path = service.path

        for result in ast_results:
            file_path = result.file_path
            # Check if file is within the service's path
            if service_path == ".":
                # Root service: files at top level (1 component paths)
                if len(Path(file_path).parts) == 1:
                    file_to_service[file_path] = service.service_id
            elif file_path.startswith(service_path + "/") or file_path.startswith(service_path + "\\"):
                file_to_service[file_path] = service.service_id
            elif Path(file_path).parts[:len(Path(service_path).parts)] == Path(service_path).parts:
                file_to_service[file_path] = service.service_id

    return file_to_service


def _guess_service_from_path(file_path: str, services: List[Service]) -> str:
    """Fallback: guess service ID by matching path segments against service names."""
    parts = Path(file_path).parts
    for service in services:
        for part in parts:
            if part.lower() in service.name.lower() or service.name.lower() in part.lower():
                return service.service_id
    return "svc_unknown"


def _find_containing_endpoint(line: int, endpoints: List[Endpoint]) -> Optional[str]:
    """Find the endpoint whose line range contains the given line number."""
    best: Optional[Endpoint] = None
    for ep in endpoints:
        if ep.line_start <= line <= (ep.line_end + 50):  # allow some slack
            if best is None or ep.line_start > best.line_start:
                best = ep
    return best.endpoint_id if best else None


def _classify_identity_propagation(http_call: HttpCallDefinition) -> str:
    """
    Classify how user identity is propagated in the outgoing HTTP call.

    Rules:
    - FORWARDED_USER_JWT: Authorization header is passed (user JWT)
    - SERVICE_TOKEN: Only service-level credential headers present
    - STRIPPED: No auth headers at all
    - UNKNOWN: Cannot determine
    """
    if http_call.has_authorization_header:
        return IDENTITY_FORWARDED_USER_JWT
    elif http_call.has_service_token:
        return IDENTITY_SERVICE_TOKEN
    elif not http_call.passed_headers:
        return IDENTITY_STRIPPED
    else:
        # Has some headers but none we recognize as auth
        return IDENTITY_UNKNOWN
