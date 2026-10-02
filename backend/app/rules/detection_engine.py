"""
Detection Engine — Phases 8 & 9
=================================
Implements the four Confused Deputy detection rules:

CD-001: Potential Privilege-Boundary Confused Deputy
CD-002: Privileged Downstream Service with Missing Demonstrable Authorization
CD-003: Untrusted Identity Propagation via Unverified Headers
CD-004: Gateway-Only Authorization Policy with Unprotected Internal Services

Each rule follows the exact algorithm defined in LOGIC.md.
Rules operate on the NetworkX call graph and AST metadata.

IMPORTANT: Rules produce POTENTIAL findings — static analysis limitations
are always documented. We never assert a proven exploitable vulnerability.
"""

from __future__ import annotations

import logging
import uuid
from typing import Dict, List, Optional, Set, Tuple

from ..graph.call_graph import CallGraph, NODE_TYPE_SERVICE, NODE_TYPE_ENDPOINT
from ..models.schemas import (
    Service, Endpoint, ServiceCall, Finding,
    PRIVILEGE_RANK, PRIVILEGE_USER, PRIVILEGE_SERVICE,
    PRIVILEGE_ADMIN, PRIVILEGE_PUBLIC, PRIVILEGE_UNKNOWN,
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
    CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    IDENTITY_FORWARDED_USER_JWT, IDENTITY_SERVICE_TOKEN,
    IDENTITY_STRIPPED, IDENTITY_UNKNOWN,
)
from ..analyzer.ast_visitor import redact_secrets

logger = logging.getLogger(__name__)


# ─────────────────────────── Finding ID Counter ───────────────────────────

_finding_counter = 0


def _next_finding_id(rule_id: str) -> str:
    global _finding_counter
    _finding_counter += 1
    return f"FINDING-{rule_id}-{_finding_counter:02d}"


# ─────────────────────────── Severity Matrix ─────────────────────────────

def compute_severity(
    src_privilege: str,
    dst_privilege: str,
    is_sensitive: bool,
    identity_propagation: str,
) -> str:
    """
    Compute severity based on the privilege delta matrix from LOGIC.md.

    | Privilege Delta | Target Operation | Downstream Auth | Severity |
    | USER → ADMIN   | Sensitive         | Missing         | CRITICAL |
    | USER → SERVICE | Sensitive/Write   | Service Token   | HIGH     |
    | USER → SERVICE | Read-only         | Missing         | MEDIUM   |
    | Any → Any      | Non-sensitive     | Missing         | LOW      |
    """
    src_rank = PRIVILEGE_RANK.get(src_privilege, -1)
    dst_rank = PRIVILEGE_RANK.get(dst_privilege, -1)

    if src_rank <= 0 or dst_rank <= 0:
        return SEVERITY_MEDIUM

    if src_rank == PRIVILEGE_RANK[PRIVILEGE_USER] and dst_rank >= PRIVILEGE_RANK[PRIVILEGE_ADMIN]:
        if is_sensitive:
            return SEVERITY_CRITICAL
        return SEVERITY_HIGH

    if src_rank <= PRIVILEGE_RANK[PRIVILEGE_USER] and dst_rank >= PRIVILEGE_RANK[PRIVILEGE_SERVICE]:
        if is_sensitive:
            return SEVERITY_HIGH
        return SEVERITY_MEDIUM

    if is_sensitive:
        return SEVERITY_MEDIUM

    return SEVERITY_LOW


def compute_confidence(
    identity_propagation: str,
    passed_headers: List[str],
    has_explicit_service_token_literal: bool = False,
) -> str:
    """
    Compute confidence based on evidence certainty.

    HIGH: Explicit hardcoded service token literal detected in AST
    MEDIUM: Variable-based headers or partial evidence
    LOW: Cannot determine from static analysis
    """
    if has_explicit_service_token_literal:
        return CONFIDENCE_HIGH
    elif identity_propagation == IDENTITY_SERVICE_TOKEN:
        return CONFIDENCE_HIGH
    elif identity_propagation == IDENTITY_FORWARDED_USER_JWT:
        return CONFIDENCE_MEDIUM  # JWT forwarded but downstream check unknown
    elif identity_propagation == IDENTITY_STRIPPED:
        return CONFIDENCE_MEDIUM
    elif identity_propagation == IDENTITY_UNKNOWN:
        return CONFIDENCE_LOW
    return CONFIDENCE_MEDIUM


# ─────────────────────────── Rule CD-001 ─────────────────────────────────

def run_cd001(
    call_graph: CallGraph,
    services: Dict[str, Service],
    endpoints: Dict[str, Endpoint],
    service_calls: List[ServiceCall],
) -> List[Finding]:
    """
    CD-001: Potential Privilege-Boundary Confused Deputy

    Detects: User-originated request traverses from a lower-privilege service
    to a higher-privilege service that performs a sensitive operation,
    WITHOUT proper end-to-end user authorization verification.

    Required evidence:
    1. Entry service at USER privilege boundary
    2. Downstream service at SERVICE or ADMIN privilege
    3. Downstream endpoint performs sensitive operation
    4. Service credential used (SERVICE_TOKEN) without forwarded user identity
    """
    findings: List[Finding] = []
    seen_pairs: Set[str] = set()

    for call in service_calls:
        src_service = services.get(call.source_service_id)
        dst_service = services.get(call.destination_service_id)

        if not src_service or not dst_service:
            continue

        src_priv = src_service.privilege_level
        dst_priv = dst_service.privilege_level
        src_rank = PRIVILEGE_RANK.get(src_priv, -1)
        dst_rank = PRIVILEGE_RANK.get(dst_priv, -1)

        # Condition 1: Privilege escalation (USER → SERVICE or higher)
        if src_rank < PRIVILEGE_RANK.get(PRIVILEGE_USER, 1):
            continue
        if src_rank >= dst_rank:
            continue
        if dst_rank < PRIVILEGE_RANK.get(PRIVILEGE_SERVICE, 2):
            continue

        # Condition 2: Identity NOT properly forwarded (service token used)
        identity_prop = call.identity_propagation
        if identity_prop == IDENTITY_FORWARDED_USER_JWT:
            # User JWT forwarded — now check if downstream has ownership verification
            dst_eps = [e for e in endpoints.values() if e.service_id == dst_service.service_id]
            all_have_ownership_check = all(
                _has_ownership_check(ep) for ep in dst_eps if ep.is_sensitive
            )
            if all_have_ownership_check:
                continue  # Secure: downstream verifies ownership

        # Condition 3: Downstream service has sensitive endpoints
        dst_sensitive_eps = [
            e for e in endpoints.values()
            if e.service_id == dst_service.service_id and e.is_sensitive
        ]
        if not dst_sensitive_eps:
            continue

        pair_key = f"{call.source_service_id}→{call.destination_service_id}"
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)

        # Condition 4: Downstream endpoint lacks user authorization check
        for dst_ep in dst_sensitive_eps:
            if _has_user_authorization(dst_ep):
                continue  # This specific endpoint is protected

            severity = compute_severity(src_priv, dst_priv, True, identity_prop)
            confidence = compute_confidence(
                identity_prop,
                call.passed_headers,
                identity_prop == IDENTITY_SERVICE_TOKEN,
            )

            # Build evidence snippet
            evidence = _build_evidence_snippet(call, dst_ep, src_service, dst_service)

            finding = Finding(
                finding_id=_next_finding_id("CD001"),
                rule_id="CD-001",
                title="Potential Privilege-Boundary Confused Deputy",
                severity=severity,
                confidence=confidence,
                source_service_id=call.source_service_id,
                destination_service_id=call.destination_service_id,
                endpoint_id=dst_ep.endpoint_id,
                request_path=[call.source_endpoint_id, call.call_id, dst_ep.endpoint_id],
                evidence_snippet=evidence,
                source_file=call.source_file,
                line_number=call.source_line,
                authorization_observations=[
                    f"Source service '{src_service.name}' operates at {src_priv} privilege level.",
                    f"Inter-service call uses identity propagation: {identity_prop}.",
                    f"Downstream service '{dst_service.name}' operates at {dst_priv} privilege level.",
                    f"Downstream endpoint '{dst_ep.handler}' ({dst_ep.method} {dst_ep.route}) "
                    f"is flagged as sensitive but lacks demonstrable user ownership verification.",
                    _get_auth_check_observation(dst_ep),
                ],
                privilege_observations=[
                    f"Privilege escalation: {src_priv} (rank={src_rank}) → {dst_priv} (rank={dst_rank}).",
                    f"Source service '{src_service.name}' authenticates users but calls downstream "
                    f"using {'service credential' if identity_prop == IDENTITY_SERVICE_TOKEN else 'unknown identity context'}.",
                    f"Downstream service has direct access to sensitive operations without verifying "
                    f"whether the originating user is authorized for the specific resource.",
                ],
                limitations=(
                    "Static AST analysis cannot evaluate: runtime token validation scope, "
                    "external authorization proxies (e.g., Envoy/Istio sidecars), "
                    "database-level ownership checks not visible in route handler code, "
                    "or dynamic URL/header construction patterns. "
                    "This finding requires manual security review to confirm exploitability."
                ),
                remediation=(
                    "Option 1 (Preferred): Forward the original user JWT (Authorization header) "
                    "to the downstream service. The downstream service should then cryptographically "
                    "verify the JWT and extract the user identity to perform resource ownership checks.\n\n"
                    "Option 2: Implement explicit user resource ownership validation in the downstream "
                    f"endpoint handler (e.g., verify that the user_id in the request owns {dst_ep.route}).\n\n"
                    "Option 3: Implement a dedicated authorization middleware in the downstream service "
                    "that validates user claims independently of the calling service's trust."
                ),
            )
            findings.append(finding)

            # Mark the graph edge as risky
            call_graph.mark_edge_as_risky(
                call.source_service_id,
                call.destination_service_id,
                "CD-001",
            )

    logger.info("CD-001: %d findings", len(findings))
    return findings


# ─────────────────────────── Rule CD-002 ─────────────────────────────────

def run_cd002(
    call_graph: CallGraph,
    services: Dict[str, Service],
    endpoints: Dict[str, Endpoint],
    service_calls: List[ServiceCall],
) -> List[Finding]:
    """
    CD-002: Privileged Downstream Service with Missing Demonstrable Authorization

    Detects: Internal downstream endpoints reachable from user-facing services
    that contain NO detectable authentication or authorization checks.
    """
    findings: List[Finding] = []
    seen_eps: Set[str] = set()

    for call in service_calls:
        src_service = services.get(call.source_service_id)
        dst_service = services.get(call.destination_service_id)

        if not src_service or not dst_service:
            continue

        # Check if destination service is reachable from user-facing entry points
        src_priv = src_service.privilege_level
        if PRIVILEGE_RANK.get(src_priv, -1) < PRIVILEGE_RANK.get(PRIVILEGE_USER, 1):
            continue  # Source not user-facing

        # Find downstream endpoints with no auth at all
        dst_eps = [e for e in endpoints.values() if e.service_id == dst_service.service_id]
        for dst_ep in dst_eps:
            if dst_ep.endpoint_id in seen_eps:
                continue

            # CD-002 condition: ZERO auth checks and not authenticated
            if dst_ep.authentication or dst_ep.authorization_checks:
                continue

            # Verify reachability from public/user entry point
            if not call_graph.is_reachable_from_public(dst_ep.endpoint_id):
                # Try service-level reachability
                if not call_graph.is_reachable_from_public(dst_service.service_id):
                    continue

            seen_eps.add(dst_ep.endpoint_id)

            severity = SEVERITY_HIGH
            confidence = CONFIDENCE_HIGH  # Zero auth in FastAPI is very clear

            evidence = (
                f"@{dst_ep.method.lower()} route '{dst_ep.route}' in handler '{dst_ep.handler}' "
                f"(file: {dst_ep.file}, line: {dst_ep.line_start}) contains no FastAPI Depends() "
                f"security guards and no detected authorization logic."
            )

            finding = Finding(
                finding_id=_next_finding_id("CD002"),
                rule_id="CD-002",
                title="Privileged Downstream Service with Missing Demonstrable Authorization",
                severity=severity,
                confidence=confidence,
                source_service_id=call.source_service_id,
                destination_service_id=call.destination_service_id,
                endpoint_id=dst_ep.endpoint_id,
                request_path=[call.source_endpoint_id, call.call_id, dst_ep.endpoint_id],
                evidence_snippet=redact_secrets(evidence),
                source_file=dst_ep.file,
                line_number=dst_ep.line_start,
                authorization_observations=[
                    f"Endpoint '{dst_ep.handler}' ({dst_ep.method} {dst_ep.route}) in "
                    f"'{dst_service.name}' has zero detectable authentication dependencies.",
                    "No FastAPI Depends() security guards found in function signature.",
                    "No explicit IF-statement authorization checks detected in function body.",
                    f"This endpoint is reachable from user-facing service '{src_service.name}'.",
                ],
                privilege_observations=[
                    f"Source service '{src_service.name}' is user-accessible (privilege={src_priv}).",
                    f"Downstream service '{dst_service.name}' exposes endpoint without any "
                    f"authentication enforcement (privilege={dst_service.privilege_level}).",
                ],
                limitations=(
                    "Static analysis cannot verify: custom router-level middleware applied at "
                    "framework level, external API gateway authorization, network-level ACL "
                    "restrictions, or authentication implemented in a non-standard pattern "
                    "not visible in FastAPI route decorator inspection."
                ),
                remediation=(
                    f"Add explicit authentication and authorization to the endpoint:\n\n"
                    f"  @{dst_ep.handler}\n"
                    f"  async def {dst_ep.handler}(..., service: ServiceAuth = Depends(verify_service_token), "
                    f"user: UserClaims = Depends(verify_user_jwt)):\n"
                    f"      # Implement ownership/permission check here\n\n"
                    "Ensure the endpoint validates both service identity AND user authorization "
                    "before executing any state-modifying operations."
                ),
            )
            findings.append(finding)

    logger.info("CD-002: %d findings", len(findings))
    return findings


# ─────────────────────────── Rule CD-003 ─────────────────────────────────

def run_cd003(
    call_graph: CallGraph,
    services: Dict[str, Service],
    endpoints: Dict[str, Endpoint],
    service_calls: List[ServiceCall],
) -> List[Finding]:
    """
    CD-003: Untrusted Identity Propagation via Unverified Headers

    Detects: Downstream services accepting unverified identity headers
    (X-User-Id, X-User-Role) without cryptographic verification.
    """
    findings: List[Finding] = []
    seen_calls: Set[str] = set()

    # Identify service calls that pass X-User-Id / X-User-Role but NOT Authorization JWT
    for call in service_calls:
        if call.call_id in seen_calls:
            continue

        # Look for calls passing X-User-Id or X-User-Role without Authorization
        has_plain_user_header = any(
            h.lower() in {"x-user-id", "x-user-role", "x-user-email"}
            for h in call.passed_headers
        )
        has_jwt = any(
            h.lower() == "authorization"
            for h in call.passed_headers
        )

        # CD-003 fires when plain user identity header is passed WITHOUT a signed JWT
        if not has_plain_user_header:
            continue
        if has_jwt:
            continue  # JWT provides cryptographic verification

        if call.call_id in seen_calls:
            continue
        seen_calls.add(call.call_id)

        src_service = services.get(call.source_service_id)
        dst_service = services.get(call.destination_service_id)

        if not src_service or not dst_service:
            continue

        evidence = (
            f"HTTP {call.http_method} call to '{call.destination_route}' "
            f"(file: {call.source_file}, line: {call.source_line}) "
            f"passes plain identity header(s) {[h for h in call.passed_headers if 'user' in h.lower()]} "
            f"without an accompanying cryptographic Authorization Bearer JWT. "
            f"The downstream service cannot verify these headers were not forged by the upstream service."
        )

        finding = Finding(
            finding_id=_next_finding_id("CD003"),
            rule_id="CD-003",
            title="Untrusted Identity Propagation via Unverified Headers",
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            source_service_id=call.source_service_id,
            destination_service_id=call.destination_service_id,
            endpoint_id=f"ep_{call.destination_service_id}_unknown",
            request_path=[call.source_endpoint_id, call.call_id],
            evidence_snippet=redact_secrets(evidence),
            source_file=call.source_file,
            line_number=call.source_line,
            authorization_observations=[
                f"Call from '{src_service.name}' to '{dst_service.name}' passes "
                f"plain HTTP headers as user identity: {call.passed_headers}.",
                "Plain HTTP headers (X-User-Id, X-User-Role) can be spoofed by any "
                "service in the call chain — they are not cryptographically verifiable.",
                "No Authorization Bearer JWT detected in the outgoing call headers.",
            ],
            privilege_observations=[
                f"Source service '{src_service.name}' (privilege={src_service.privilege_level}) "
                "injects user identity via plain headers.",
                f"Downstream service '{dst_service.name}' (privilege={dst_service.privilege_level}) "
                "may accept these headers as authoritative user identity without signature verification.",
            ],
            limitations=(
                "Static analysis cannot determine if the downstream service uses "
                "additional cryptographic verification of these headers, or if a "
                "service mesh (mTLS + header signing) provides verification at the "
                "infrastructure layer. Manual review required."
            ),
            remediation=(
                "Replace plain identity headers with a cryptographically signed identity assertion:\n\n"
                "1. Forward the original user JWT: set Authorization header = original user Bearer token.\n"
                "2. The downstream service validates the JWT signature independently.\n"
                "3. Extract user identity from verified JWT claims, not from plain X-User-Id headers.\n\n"
                "If a service mesh is used, ensure it signs forwarded headers with mTLS client certificates."
            ),
        )
        findings.append(finding)

    logger.info("CD-003: %d findings", len(findings))
    return findings


# ─────────────────────────── Rule CD-004 ─────────────────────────────────

def run_cd004(
    call_graph: CallGraph,
    services: Dict[str, Service],
    endpoints: Dict[str, Endpoint],
    service_calls: List[ServiceCall],
) -> List[Finding]:
    """
    CD-004: Gateway-Only Authorization Policy

    Detects: Architecture where authorization checks exist ONLY at an upstream
    gateway/entry service, with ALL downstream internal service endpoints
    lacking any authorization logic.
    """
    findings: List[Finding] = []

    # Find services that call downstream services
    entry_services = []
    downstream_services = []

    for call in service_calls:
        src_service = services.get(call.source_service_id)
        dst_service = services.get(call.destination_service_id)

        if not src_service or not dst_service:
            continue

        src_priv = src_service.privilege_level
        if PRIVILEGE_RANK.get(src_priv, -1) >= PRIVILEGE_RANK.get(PRIVILEGE_USER, 1):
            if src_service.service_id not in [s.service_id for s in entry_services]:
                entry_services.append(src_service)
        if dst_service.service_id not in [s.service_id for s in downstream_services]:
            downstream_services.append(dst_service)

    for entry_svc in entry_services:
        # Check if entry service has auth (it should for CD-004 to fire)
        entry_eps = [e for e in endpoints.values() if e.service_id == entry_svc.service_id]
        entry_has_auth = any(e.authentication for e in entry_eps)

        if not entry_has_auth:
            continue  # Entry service itself has no auth — different problem

        # Check all directly reachable downstream services
        direct_downstream = call_graph.get_downstream_services(entry_svc.service_id)

        for dst_svc_id in direct_downstream:
            dst_service = services.get(dst_svc_id)
            if not dst_service:
                continue

            # CD-004 requires ALL downstream endpoints to lack auth
            dst_eps = [e for e in endpoints.values() if e.service_id == dst_svc_id]
            if not dst_eps:
                continue

            all_missing_auth = all(
                not e.authentication and not e.authorization_checks
                for e in dst_eps
            )

            if not all_missing_auth:
                continue  # At least one downstream endpoint has auth — not a pure gateway-only pattern

            evidence = (
                f"Service '{entry_svc.name}' (privilege={entry_svc.privilege_level}) "
                f"has authentication guards on its endpoints, but all {len(dst_eps)} "
                f"endpoint(s) in downstream service '{dst_service.name}' lack "
                f"any detectable authorization logic. "
                f"If an attacker bypasses the gateway (e.g., direct network access), "
                f"the downstream service has no independent protection."
            )

            finding = Finding(
                finding_id=_next_finding_id("CD004"),
                rule_id="CD-004",
                title="Gateway-Only Authorization Policy with Unprotected Internal Services",
                severity=SEVERITY_MEDIUM,
                confidence=CONFIDENCE_MEDIUM,
                source_service_id=entry_svc.service_id,
                destination_service_id=dst_svc_id,
                endpoint_id=dst_eps[0].endpoint_id if dst_eps else f"ep_{dst_svc_id}",
                request_path=[entry_svc.service_id, dst_svc_id],
                evidence_snippet=redact_secrets(evidence),
                source_file=dst_eps[0].file if dst_eps else "",
                line_number=dst_eps[0].line_start if dst_eps else 0,
                authorization_observations=[
                    f"Gateway service '{entry_svc.name}' implements authentication at its entry points.",
                    f"All {len(dst_eps)} endpoint(s) in downstream service '{dst_service.name}' "
                    "lack demonstrable FastAPI authorization guards.",
                    "This creates a single point of authorization failure — if the gateway is bypassed, "
                    "the internal service provides no defense-in-depth.",
                ],
                privilege_observations=[
                    f"Entry service '{entry_svc.name}' operates at {entry_svc.privilege_level} privilege.",
                    f"Downstream service '{dst_service.name}' operates at {dst_service.privilege_level} privilege.",
                    "Defense-in-depth principle requires authorization at each service boundary.",
                ],
                limitations=(
                    "This finding reflects a structural defense-in-depth concern. "
                    "Static analysis cannot verify: network security groups preventing direct "
                    "downstream access, service mesh mTLS enforcement, or other infrastructure-level "
                    "controls that prevent gateway bypass. MEDIUM confidence reflects this uncertainty."
                ),
                remediation=(
                    "Implement zero-trust authorization within each downstream microservice:\n\n"
                    "1. Add service identity verification to all internal endpoints: "
                    "  Depends(verify_service_token)\n"
                    "2. Add user identity verification where applicable: "
                    "  Depends(verify_user_jwt)\n"
                    "3. Do not rely solely on network perimeter controls for authorization.\n"
                    "4. Implement defense-in-depth: each service independently validates "
                    "authority before executing privileged operations."
                ),
            )
            findings.append(finding)

    logger.info("CD-004: %d findings", len(findings))
    return findings


# ─────────────────────────── Helper Functions ─────────────────────────────

def _has_ownership_check(endpoint: Endpoint) -> bool:
    """Check if endpoint has a user ownership/resource check."""
    ownership_patterns = [
        "ownership", "verify_user_own", "verify_own", "check_own",
        "owns_order", "owns_resource", "owns_payment", "verify_user",
    ]
    for check in endpoint.authorization_checks:
        if any(p in check.lower() for p in ownership_patterns):
            return True
    return False


def _has_user_authorization(endpoint: Endpoint) -> bool:
    """
    Check if endpoint has demonstrable user authorization
    (beyond just service token validation).
    """
    # Pure service-only auth is NOT sufficient for CD-001
    service_only_patterns = ["verify_service", "service_key", "service_token"]
    user_auth_patterns = [
        "verify_user", "get_current_user", "verify_jwt", "user_jwt",
        "verify_owner", "ownership", "check_permission", "require_role",
        "is_admin", "user_id", "current_user",
    ]

    has_user_check = any(
        any(p in check.lower() for p in user_auth_patterns)
        for check in endpoint.authorization_checks
    )

    return has_user_check


def _get_auth_check_observation(endpoint: Endpoint) -> str:
    """Describe what auth checks ARE present (or absent) on an endpoint."""
    if not endpoint.authorization_checks:
        return "No authorization dependencies or checks detected in endpoint handler."

    service_checks = [
        c for c in endpoint.authorization_checks
        if any(p in c.lower() for p in ["service", "service_key", "service_token"])
    ]
    user_checks = [
        c for c in endpoint.authorization_checks
        if any(p in c.lower() for p in ["user", "jwt", "owner", "permission", "role"])
    ]

    obs_parts = []
    if service_checks:
        obs_parts.append(f"Service-level auth found: {service_checks}")
    if user_checks:
        obs_parts.append(f"User-level auth found: {user_checks}")
    else:
        obs_parts.append("No user resource ownership check detected.")

    return " ".join(obs_parts)


def _build_evidence_snippet(
    call: ServiceCall,
    dst_ep: Endpoint,
    src_service: Service,
    dst_service: Service,
) -> str:
    """Build a descriptive evidence snippet for a finding."""
    header_info = f"Headers passed: {call.passed_headers}" if call.passed_headers else "No auth headers detected"

    snippet = (
        f"# Evidence: Potential Confused Deputy Call\n"
        f"# Source: {src_service.name} ({src_service.privilege_level} privilege)\n"
        f"# File: {call.source_file}, Line: {call.source_line}\n"
        f"# Call: HTTP {call.http_method} → {call.destination_route}\n"
        f"# Identity Propagation: {call.identity_propagation}\n"
        f"# {header_info}\n"
        f"#\n"
        f"# Target: {dst_service.name} ({dst_service.privilege_level} privilege)\n"
        f"# Target Endpoint: {dst_ep.method} {dst_ep.route} → handler '{dst_ep.handler}'\n"
        f"# Target File: {dst_ep.file}, Lines: {dst_ep.line_start}-{dst_ep.line_end}\n"
        f"# Target Auth Checks: {dst_ep.authorization_checks or 'NONE DETECTED'}\n"
        f"# Is Sensitive: {dst_ep.is_sensitive}"
    )
    return redact_secrets(snippet)


# ─────────────────────────── Detection Engine ────────────────────────────

def resolve_unknown_destinations(
    service_calls: List[ServiceCall],
    services: List[Service],
    endpoints: List[Endpoint],
) -> List[ServiceCall]:
    """
    Attempt to resolve service calls with UNKNOWN destination_service_id
    by matching the destination_route against known endpoint routes.

    This handles cases where the target URL was a variable/f-string
    that couldn't be statically resolved.
    """
    resolved: List[ServiceCall] = []

    for call in service_calls:
        if call.destination_service_id != "UNKNOWN":
            resolved.append(call)
            continue

        # Try to find a service whose endpoints match the destination_route
        dest_route = call.destination_route
        if not dest_route or dest_route in ("<dynamic>", "/"):
            resolved.append(call)
            continue

        best_match: Optional[str] = None
        for ep in endpoints:
            if ep.service_id == call.source_service_id:
                continue  # Don't match to self
            # Check if the call's route matches this endpoint's route
            if dest_route == ep.route:
                best_match = ep.service_id
                break
            # Partial match: the call route contains a known endpoint path
            if dest_route and ep.route and len(ep.route) > 3:
                ep_normalized = ep.route.rstrip("/")
                dest_normalized = dest_route.rstrip("/")
                if ep_normalized == dest_normalized or dest_normalized.endswith(ep_normalized):
                    best_match = ep.service_id
                    break

        if best_match:
            resolved.append(call.model_copy(update={"destination_service_id": best_match}))
        else:
            resolved.append(call)

    return resolved


def run_all_rules(
    call_graph: CallGraph,
    services: List[Service],
    endpoints: List[Endpoint],
    service_calls: List[ServiceCall],
) -> List[Finding]:
    """
    Execute all detection rules (CD-001 through CD-004) and return combined findings.

    Args:
        call_graph: Populated NetworkX call graph.
        services: Discovered services.
        endpoints: Discovered endpoints.
        service_calls: Discovered inter-service calls.

    Returns:
        Combined list of all findings from all rules.
    """
    global _finding_counter
    _finding_counter = 0  # Reset counter for deterministic IDs

    # Resolve unknown destination service IDs before running rules
    resolved_calls = resolve_unknown_destinations(service_calls, services, endpoints)

    service_map = {s.service_id: s for s in services}
    endpoint_map = {e.endpoint_id: e for e in endpoints}

    all_findings: List[Finding] = []

    cd001 = run_cd001(call_graph, service_map, endpoint_map, resolved_calls)
    cd002 = run_cd002(call_graph, service_map, endpoint_map, resolved_calls)
    cd003 = run_cd003(call_graph, service_map, endpoint_map, resolved_calls)
    cd004 = run_cd004(call_graph, service_map, endpoint_map, resolved_calls)

    all_findings.extend(cd001)
    all_findings.extend(cd002)
    all_findings.extend(cd003)
    all_findings.extend(cd004)

    # Mark risky services in graph for visualization
    risky_services: Set[str] = set()
    for finding in all_findings:
        risky_services.add(finding.source_service_id)
        risky_services.add(finding.destination_service_id)

    for svc_id in risky_services:
        if svc_id in call_graph.graph:
            call_graph.graph.nodes[svc_id]["hasRisk"] = True

    logger.info(
        "Detection complete: %d total findings (CD-001: %d, CD-002: %d, CD-003: %d, CD-004: %d)",
        len(all_findings), len(cd001), len(cd002), len(cd003), len(cd004),
    )

    return all_findings

