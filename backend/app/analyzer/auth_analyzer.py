"""
Authorization & Privilege Analyzer — Phase 7
==============================================
Analyzes authentication and authorization patterns across services:
- Infers per-service privilege levels based on route patterns and auth deps
- Identifies privilege boundaries between services
- Classifies identity propagation in service calls
- Produces PrivilegeBoundary objects for cross-service calls

Works in conjunction with service_discovery.py and api_discovery.py.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set, Tuple

from ..models.schemas import (
    Service, Endpoint, ServiceCall, PrivilegeBoundary,
    PRIVILEGE_RANK, PRIVILEGE_UNKNOWN, PRIVILEGE_PUBLIC,
    PRIVILEGE_USER, PRIVILEGE_SERVICE, PRIVILEGE_ADMIN,
    CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    IDENTITY_FORWARDED_USER_JWT, IDENTITY_SERVICE_TOKEN,
    IDENTITY_STRIPPED, IDENTITY_UNKNOWN,
)

logger = logging.getLogger(__name__)


def analyze_privilege_boundaries(
    services: List[Service],
    service_calls: List[ServiceCall],
) -> List[PrivilegeBoundary]:
    """
    Detect privilege boundary transitions in service-to-service calls.

    A privilege boundary exists when a call crosses between different privilege levels.
    Example: USER service calling a SERVICE-level endpoint.

    Args:
        services: List of discovered services.
        service_calls: List of inter-service HTTP calls.

    Returns:
        List of PrivilegeBoundary objects.
    """
    boundaries: List[PrivilegeBoundary] = []
    service_map: Dict[str, Service] = {s.service_id: s for s in services}
    seen: Set[str] = set()

    for call in service_calls:
        src_service = service_map.get(call.source_service_id)
        dst_service = service_map.get(call.destination_service_id)

        if not src_service or not dst_service:
            continue

        src_priv = src_service.privilege_level
        dst_priv = dst_service.privilege_level

        # Only create a boundary if privilege differs
        src_rank = PRIVILEGE_RANK.get(src_priv, -1)
        dst_rank = PRIVILEGE_RANK.get(dst_priv, -1)

        boundary_key = f"{call.source_service_id}→{call.destination_service_id}"
        if boundary_key in seen:
            continue
        seen.add(boundary_key)

        # Determine evidence text
        if src_rank >= 0 and dst_rank >= 0 and src_rank != dst_rank:
            direction = "escalation" if dst_rank > src_rank else "de-escalation"
            evidence = (
                f"Service call from '{src_service.name}' (privilege={src_priv}) "
                f"to '{dst_service.name}' (privilege={dst_priv}) — "
                f"privilege {direction} detected via static analysis."
            )
            confidence = dst_service.confidence
        else:
            # Same privilege level — boundary still recorded for context
            evidence = (
                f"Service call from '{src_service.name}' (privilege={src_priv}) "
                f"to '{dst_service.name}' (privilege={dst_priv})."
            )
            confidence = CONFIDENCE_LOW

        boundary = PrivilegeBoundary(
            boundary_id=f"pb_{call.source_service_id}_{call.destination_service_id}",
            source_service_id=call.source_service_id,
            destination_service_id=call.destination_service_id,
            source_privilege=src_priv,
            destination_privilege=dst_priv,
            evidence=evidence,
            confidence=confidence,
        )
        boundaries.append(boundary)

    logger.info("Found %d privilege boundaries", len(boundaries))
    return boundaries


def refine_service_privileges(
    services: List[Service],
    endpoints: List[Endpoint],
) -> List[Service]:
    """
    Refine service privilege levels based on their endpoint analysis.
    Upgrades/downgrades privilege levels if endpoint evidence is stronger
    than the initial service-level inference.

    Args:
        services: Services with initial privilege inference.
        endpoints: All discovered endpoints.

    Returns:
        Updated list of services with refined privilege levels.
    """
    # Group endpoints by service
    service_endpoints: Dict[str, List[Endpoint]] = {}
    for ep in endpoints:
        if ep.service_id not in service_endpoints:
            service_endpoints[ep.service_id] = []
        service_endpoints[ep.service_id].append(ep)

    updated_services: List[Service] = []
    for service in services:
        eps = service_endpoints.get(service.service_id, [])
        if not eps:
            updated_services.append(service)
            continue

        # Check if any endpoints have admin or service-level characteristics
        has_admin_ep = any(_is_admin_endpoint(ep) for ep in eps)
        has_service_ep = any(_is_service_endpoint(ep) for ep in eps)
        has_user_auth = any(ep.authentication for ep in eps)
        all_unauthenticated = all(not ep.authentication for ep in eps)

        # Keep existing privilege if already inferred with high confidence
        if service.confidence == CONFIDENCE_HIGH:
            updated_services.append(service)
            continue

        # Refine based on endpoint evidence
        new_privilege = service.privilege_level
        new_confidence = service.confidence

        if has_admin_ep:
            new_privilege = PRIVILEGE_ADMIN
            new_confidence = CONFIDENCE_MEDIUM
        elif has_service_ep:
            new_privilege = PRIVILEGE_SERVICE
            new_confidence = CONFIDENCE_HIGH
        elif has_user_auth:
            current_rank = PRIVILEGE_RANK.get(service.privilege_level, -1)
            user_rank = PRIVILEGE_RANK.get(PRIVILEGE_USER, 1)
            if current_rank < user_rank:
                new_privilege = PRIVILEGE_USER
                new_confidence = CONFIDENCE_MEDIUM
        elif all_unauthenticated and len(eps) > 0:
            new_privilege = PRIVILEGE_PUBLIC
            new_confidence = CONFIDENCE_LOW

        # Create updated service (Pydantic models are immutable by default in v2)
        updated = service.model_copy(update={
            "privilege_level": new_privilege,
            "confidence": new_confidence,
        })
        updated_services.append(updated)

    return updated_services


def _is_admin_endpoint(endpoint: Endpoint) -> bool:
    """Check if an endpoint is admin-level based on route and auth checks."""
    route_lower = endpoint.route.lower()
    admin_patterns = ["admin", "superuser", "root", "manage", "sudo"]

    if any(p in route_lower for p in admin_patterns):
        return True

    for check in endpoint.authorization_checks:
        if any(p in check.lower() for p in ["admin", "superuser", "is_admin"]):
            return True

    return False


def _is_service_endpoint(endpoint: Endpoint) -> bool:
    """Check if an endpoint is internal service-level."""
    route_lower = endpoint.route.lower()
    if any(p in route_lower for p in ["/internal", "/service", "/rpc", "/private"]):
        return True
    for check in endpoint.authorization_checks:
        check_lower = check.lower()
        if any(p in check_lower for p in ["service", "service_token", "service_key", "internal"]):
            return True
    return False
