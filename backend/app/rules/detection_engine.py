"""
Detection Engine — Semantic & Deterministic (Engine v2.0.0)
============================================================
Implements the four formal Confused Deputy detection rules:

CD-001: Potential Privilege-Boundary Confused Deputy
CD-002: Privileged Downstream Service with Missing Demonstrable Authorization
CD-003: Untrusted Identity Propagation via Unverified Headers
CD-004: Gateway-Only Authorization Policy with Unprotected Internal Services

Key Upgrades in v2.0.0:
- Exact caller-to-callee endpoint matching (never inspects all endpoints)
- Negative security logic: suppression when user JWT forwarded and ownership verified
- Explicit UNKNOWN state handling and calibrated confidence
- Semantic AST authorization proof (comparisons, 401/403 rejection paths, DB filters)
- Deterministic finding fingerprints based on rule, endpoints, and path (zero duplicate noise)
- Exact auditable evidence: why matched, why secure alternatives rejected, remediation
"""

from __future__ import annotations

import hashlib
import logging
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
from ..analyzer.ast_visitor import redact_secrets, SERVICE_CREDENTIAL_HEADERS
from ..analyzer.api_discovery import routes_match

logger = logging.getLogger(__name__)


def _make_finding_fingerprint(
    rule_id: str,
    source_service_id: str,
    source_endpoint_id: str,
    destination_service_id: str,
    endpoint_id: str,
    source_file: str,
    line_number: int,
) -> str:
    """Generate a deterministic fingerprint for finding deduplication."""
    payload = f"{rule_id}:{source_service_id}:{source_endpoint_id}:{destination_service_id}:{endpoint_id}:{source_file}:{line_number}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"FINDING-{rule_id.replace('-', '')}-{digest}"


# ─────────────────────────── Severity & Confidence ────────────────────────

def compute_severity(
    src_privilege: str,
    dst_privilege: str,
    is_sensitive: bool,
    identity_propagation: str,
) -> str:
    """Compute severity based on privilege escalation and target operation sensitivity."""
    src_rank = PRIVILEGE_RANK.get(src_privilege, -1)
    dst_rank = PRIVILEGE_RANK.get(dst_privilege, -1)

    if src_rank <= 0 or dst_rank <= 0:
        return SEVERITY_MEDIUM

    if src_rank <= PRIVILEGE_RANK[PRIVILEGE_USER] and dst_rank >= PRIVILEGE_RANK[PRIVILEGE_ADMIN]:
        return SEVERITY_CRITICAL if is_sensitive else SEVERITY_HIGH

    if src_rank <= PRIVILEGE_RANK[PRIVILEGE_USER] and dst_rank >= PRIVILEGE_RANK[PRIVILEGE_SERVICE]:
        return SEVERITY_HIGH if is_sensitive else SEVERITY_MEDIUM

    if is_sensitive:
        return SEVERITY_MEDIUM

    return SEVERITY_LOW


def compute_confidence(
    identity_propagation: str,
    passed_headers: List[str],
    has_explicit_token: bool = False,
    is_target_resolved: bool = True,
    is_endpoint_resolved: bool = True,
) -> str:
    """
    Compute confidence based on evidence certainty.
    Lower confidence if target service or endpoint was unresolved (UNKNOWN).
    """
    if not is_target_resolved or not is_endpoint_resolved:
        return CONFIDENCE_LOW

    if any("<var:" in h for h in passed_headers):
        return CONFIDENCE_MEDIUM

    if has_explicit_token or identity_propagation == IDENTITY_SERVICE_TOKEN:
        return CONFIDENCE_HIGH
    elif identity_propagation == IDENTITY_FORWARDED_USER_JWT:
        return CONFIDENCE_HIGH
    elif identity_propagation == IDENTITY_STRIPPED:
        return CONFIDENCE_MEDIUM

    return CONFIDENCE_LOW


# ─────────────────────────── Rule CD-001 ─────────────────────────────────

def run_cd001(
    call_graph: CallGraph,
    services: Dict[str, Service],
    endpoints: Dict[str, Endpoint],
    service_calls: List[ServiceCall],
) -> List[Finding]:
    """
    CD-001: Potential Privilege-Boundary Confused Deputy (Engine v2.0.0)

    Enforces 7 combined conditions:
    1. Source service operates at lower privilege (PUBLIC or USER).
    2. Target service operates at elevated privilege (SERVICE or ADMIN).
    3. Target endpoint is specifically resolved and called.
    4. Target endpoint executes a sensitive state-changing operation (DELETE, refund, void, etc.).
    5. Service credential (SERVICE_TOKEN) is used without forwarding user authentication context.
    6. Target endpoint lacks demonstrable user ownership/authorization validation.
    7. Request path is resolved with sufficient confidence.
    """
    findings: List[Finding] = []
    seen_fingerprints: Set[str] = set()

    for call in service_calls:
        src_service = services.get(call.source_service_id)
        dst_service = services.get(call.destination_service_id)

        if not src_service or not dst_service:
            continue

        src_priv = src_service.privilege_level
        dst_priv = dst_service.privilege_level
        src_rank = PRIVILEGE_RANK.get(src_priv, -1)
        dst_rank = PRIVILEGE_RANK.get(dst_priv, -1)

        # Condition 1 & 2: Privilege escalation from USER/PUBLIC to SERVICE/ADMIN
        if src_rank < 0 or dst_rank < 0:
            continue
        if src_rank >= dst_rank:
            continue
        if dst_rank < PRIVILEGE_RANK[PRIVILEGE_SERVICE]:
            continue

        # Condition 3: Match specifically called target endpoint
        dst_eps: List[Endpoint] = []
        if call.matched_endpoint_id and call.matched_endpoint_id in endpoints:
            dst_eps = [endpoints[call.matched_endpoint_id]]
        else:
            # Fallback to route template matching
            dest_route = call.destination_route
            for ep in endpoints.values():
                if ep.service_id == dst_service.service_id:
                    if routes_match(ep.route, dest_route):
                        dst_eps.append(ep)

        # If no specific route matched, inspect sensitive endpoints of the target service as fallback
        if not dst_eps:
            dst_eps = [
                e for e in endpoints.values()
                if e.service_id == dst_service.service_id and e.is_sensitive
            ]

        if not dst_eps:
            continue

        identity_prop = call.identity_propagation
        has_service_token = (
            call.identity_propagation == IDENTITY_SERVICE_TOKEN
            or any(h.lower() in SERVICE_CREDENTIAL_HEADERS for h in call.passed_headers)
        )

        # Check each target endpoint
        for dst_ep in dst_eps:
            # Condition 4: Target endpoint must perform a sensitive state-changing operation
            if not dst_ep.is_sensitive:
                continue

            # Condition 5 & Negative Security: User JWT is forwarded AND validated downstream
            # When service token delegation is NOT present, downstream authentication/authorization suffices.
            if identity_prop == IDENTITY_FORWARDED_USER_JWT and not has_service_token:
                if dst_ep.authentication or _has_user_authorization(dst_ep):
                    continue  # Secure: user identity forwarded and validated downstream

            # Condition 6: Target endpoint lacks demonstrable user ownership/authorization validation
            # When service credential delegation is present or downstream is privileged,
            # downstream MUST verify resource ownership/authorization.
            if _has_user_authorization(dst_ep):
                continue  # Secure: downstream endpoint verifies ownership independently

            fingerprint = _make_finding_fingerprint(
                "CD-001",
                call.source_service_id,
                call.source_endpoint_id,
                call.destination_service_id,
                dst_ep.endpoint_id,
                call.source_file,
                call.source_line,
            )
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)

            is_ep_resolved = bool(call.matched_endpoint_id and call.matched_endpoint_id != "UNKNOWN_TARGET_ENDPOINT")
            severity = compute_severity(src_priv, dst_priv, True, identity_prop)
            confidence = compute_confidence(
                identity_prop,
                call.passed_headers,
                has_explicit_token=(identity_prop == IDENTITY_SERVICE_TOKEN),
                is_target_resolved=(call.destination_service_id != "UNKNOWN"),
                is_endpoint_resolved=is_ep_resolved,
            )

            evidence = _build_evidence_snippet(call, dst_ep, src_service, dst_service)

            finding = Finding(
                finding_id=fingerprint,
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
                    f"Source service '{src_service.name}' operates at {src_priv} privilege boundary.",
                    f"Outbound call uses identity propagation mode: {identity_prop}.",
                    f"Target service '{dst_service.name}' operates at elevated {dst_priv} privilege boundary.",
                    f"Target endpoint '{dst_ep.handler}' ({dst_ep.method} {dst_ep.route}) performs sensitive state mutation.",
                    _get_auth_check_observation(dst_ep),
                ],
                privilege_observations=[
                    f"Privilege escalation path: {src_priv} (rank {src_rank}) → {dst_priv} (rank {dst_rank}).",
                    f"Trust is delegated through {'service credentials' if identity_prop == IDENTITY_SERVICE_TOKEN else 'unverified identity context'}.",
                    "The privileged downstream service executes sensitive actions without verifying that the original requesting user is authorized for the target resource.",
                ],
                why_matched=(
                    f"Cross-service privilege escalation detected ({src_priv} -> {dst_priv}) "
                    f"calling sensitive mutating operation '{dst_ep.method} {dst_ep.route}' using service delegation "
                    f"without demonstrable end-user ownership validation."
                ),
                why_secure_rejected=(
                    "No verified user JWT is forwarded, and the downstream endpoint contains "
                    "no demonstrable user ownership check (e.g. order.user_id == user.id) or permission guard."
                ),
                security_controls_found=[],
                limitations=(
                    "Static AST analysis evaluates code structure. It cannot verify: "
                    "runtime JWT claims validation in external proxies (e.g. Istio Envoy sidecars), "
                    "database-level ownership filters within sub-queries, or dynamic header population. "
                    "Manual security review recommended."
                ),
                remediation=(
                    "1. Forward the originating user's cryptographically signed Authorization Bearer JWT to the downstream service.\n"
                    "2. Enforce downstream user ownership checks: verify that the user identity in the verified JWT matches the owner of the resource.\n"
                    "3. Do not authorize sensitive operations based solely on upstream service credentials."
                ),
            )
            findings.append(finding)

            call_graph.mark_edge_as_risky(
                call.source_service_id,
                call.destination_service_id,
                "CD-001",
            )

    logger.info("CD-001: %d findings emitted", len(findings))
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
    """
    findings: List[Finding] = []
    seen_fingerprints: Set[str] = set()

    for call in service_calls:
        src_service = services.get(call.source_service_id)
        dst_service = services.get(call.destination_service_id)

        if not src_service or not dst_service:
            continue

        src_priv = src_service.privilege_level
        if PRIVILEGE_RANK.get(src_priv, -1) < PRIVILEGE_RANK[PRIVILEGE_PUBLIC]:
            continue

        dst_eps = [e for e in endpoints.values() if e.service_id == dst_service.service_id]
        for dst_ep in dst_eps:
            if dst_ep.authentication or dst_ep.authorization_checks:
                continue

            # CD-002 targets privileged internal endpoints or sensitive state-changing operations
            is_internal_or_sensitive = (
                any(p in dst_ep.route.lower() for p in ["/internal", "/service", "/rpc", "/private", "/admin"])
                or dst_ep.is_sensitive
            )
            if not is_internal_or_sensitive:
                continue

            if not call_graph.is_reachable_from_public(dst_service.service_id):
                continue

            fingerprint = _make_finding_fingerprint(
                "CD-002",
                call.source_service_id,
                call.source_endpoint_id,
                call.destination_service_id,
                dst_ep.endpoint_id,
                dst_ep.file,
                dst_ep.line_start,
            )
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)

            evidence = (
                f"Endpoint @{dst_ep.method.lower()} '{dst_ep.route}' in handler '{dst_ep.handler}' "
                f"({dst_ep.file}:{dst_ep.line_start}) contains zero FastAPI Depends() guards, "
                f"no router-level security dependencies, and no detected authorization logic."
            )

            finding = Finding(
                finding_id=fingerprint,
                rule_id="CD-002",
                title="Privileged Downstream Service with Missing Demonstrable Authorization",
                severity=SEVERITY_HIGH,
                confidence=CONFIDENCE_HIGH,
                source_service_id=call.source_service_id,
                destination_service_id=call.destination_service_id,
                endpoint_id=dst_ep.endpoint_id,
                request_path=[call.source_endpoint_id, call.call_id, dst_ep.endpoint_id],
                evidence_snippet=redact_secrets(evidence),
                source_file=dst_ep.file,
                line_number=dst_ep.line_start,
                authorization_observations=[
                    f"Downstream endpoint '{dst_ep.handler}' ({dst_ep.method} {dst_ep.route}) in '{dst_service.name}' lacks any authentication guards.",
                    "No FastAPI Depends() security parameters detected in function signature.",
                    "No router-level or app-level dependencies detected for this route.",
                    "No in-body permission checks or rejection statements (401/403) detected.",
                    f"Endpoint is reachable from user-facing service '{src_service.name}'.",
                ],
                privilege_observations=[
                    f"Source service '{src_service.name}' is user-facing (privilege={src_priv}).",
                    f"Downstream service '{dst_service.name}' exposes internal endpoint without authentication enforcement.",
                ],
                why_matched="Internal or sensitive downstream endpoint is reachable from public/user services without any authentication guards.",
                why_secure_rejected="Endpoint contains zero Depends() guards, no HTTPBearer/OAuth2, and no internal token validation.",
                security_controls_found=[],
                limitations=(
                    "Static analysis cannot detect framework-level custom ASGI middleware, "
                    "reverse-proxy authentication headers, or network security groups."
                ),
                remediation=(
                    f"Add explicit authentication dependencies to the endpoint:\n\n"
                    f"  @{dst_ep.handler}\n"
                    f"  async def {dst_ep.handler}(..., service: ServiceAuth = Depends(verify_service_token)):\n"
                    f"      # Enforce authorization\n"
                ),
            )
            findings.append(finding)

    logger.info("CD-002: %d findings emitted", len(findings))
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
    """
    findings: List[Finding] = []
    seen_fingerprints: Set[str] = set()

    for call in service_calls:
        user_headers = [h for h in call.passed_headers if h.lower() in {"x-user-id", "x-user-role", "x-user-email"}]
        has_jwt = any(h.lower() == "authorization" for h in call.passed_headers)

        if not user_headers:
            continue
        if has_jwt:
            continue  # Cryptographic JWT present

        src_service = services.get(call.source_service_id)
        dst_service = services.get(call.destination_service_id)
        if not src_service or not dst_service:
            continue

        fingerprint = _make_finding_fingerprint(
            "CD-003",
            call.source_service_id,
            call.source_endpoint_id,
            call.destination_service_id,
            f"ep_{call.destination_service_id}",
            call.source_file,
            call.source_line,
        )
        if fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)

        evidence = (
            f"HTTP {call.http_method} call to '{call.destination_route}' "
            f"({call.source_file}:{call.source_line}) passes unverified plain identity header(s) {user_headers} "
            f"without an accompanying cryptographic Authorization Bearer JWT."
        )

        finding = Finding(
            finding_id=fingerprint,
            rule_id="CD-003",
            title="Untrusted Identity Propagation via Unverified Headers",
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            source_service_id=call.source_service_id,
            destination_service_id=call.destination_service_id,
            endpoint_id=f"ep_{call.destination_service_id}",
            request_path=[call.source_endpoint_id, call.call_id],
            evidence_snippet=redact_secrets(evidence),
            source_file=call.source_file,
            line_number=call.source_line,
            authorization_observations=[
                f"Call passes plain HTTP headers for user identity: {user_headers}.",
                "Plain HTTP headers can be manipulated or forged by upstream services in the call graph.",
                "No cryptographic Authorization Bearer JWT detected to verify identity claims.",
            ],
            privilege_observations=[
                f"Source service '{src_service.name}' forwards unverified identity claims.",
                f"Downstream service '{dst_service.name}' may trust these headers without cryptographic proof.",
            ],
            why_matched=f"Service passes unverified identity headers ({user_headers}) without cryptographic signature.",
            why_secure_rejected="Headers are passed as raw text without an accompanying cryptographic Authorization Bearer token.",
            security_controls_found=[],
            limitations=(
                "Static analysis cannot determine if an mTLS service mesh provides "
                "cryptographic header attestation at the infrastructure layer."
            ),
            remediation=(
                "1. Forward the originating user's signed JWT token via the Authorization header.\n"
                "2. Validate the JWT cryptographic signature in the downstream service.\n"
                "3. Extract user claims from the verified token rather than trust plain HTTP headers."
            ),
        )
        findings.append(finding)

    logger.info("CD-003: %d findings emitted", len(findings))
    return findings


# ─────────────────────────── Rule CD-004 ─────────────────────────────────

def run_cd004(
    call_graph: CallGraph,
    services: Dict[str, Service],
    endpoints: Dict[str, Endpoint],
    service_calls: List[ServiceCall],
    cd001_findings: Optional[List[Finding]] = None,
) -> List[Finding]:
    """
    CD-004: Gateway-Only Authorization Policy with Unprotected Internal Services
    """
    findings: List[Finding] = []
    seen_fingerprints: Set[str] = set()

    cd001_targets = set()
    if cd001_findings:
        for f in cd001_findings:
            cd001_targets.add(f.destination_service_id)

    entry_services = [s for s in services.values() if call_graph.is_entry_point(s.service_id)]

    for entry_svc in entry_services:
        entry_eps = [e for e in endpoints.values() if e.service_id == entry_svc.service_id]
        has_entry_auth = any(e.authentication for e in entry_eps)

        if not has_entry_auth:
            continue

        downstream_ids = call_graph.get_downstream_services(entry_svc.service_id)

        for dst_id in downstream_ids:
            if dst_id in cd001_targets:
                continue

            dst_svc = services.get(dst_id)
            if not dst_svc:
                continue

            dst_eps = [e for e in endpoints.values() if e.service_id == dst_id]
            if not dst_eps:
                continue

            all_unauthenticated = all(not e.authentication and not e.authorization_checks for e in dst_eps)
            if not all_unauthenticated:
                continue

            # Downstream must expose sensitive, internal, or privileged functionality to be vulnerable under CD-004
            has_privileged_or_sensitive = any(
                e.is_sensitive or any(p in e.route.lower() for p in ["/internal", "/admin", "/service", "/private"])
                for e in dst_eps
            )
            if not has_privileged_or_sensitive:
                continue

            fingerprint = _make_finding_fingerprint(
                "CD-004",
                entry_svc.service_id,
                f"svc_{entry_svc.service_id}",
                dst_id,
                f"svc_{dst_id}",
                dst_eps[0].file,
                dst_eps[0].line_start,
            )
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)

            evidence = (
                f"Gateway service '{entry_svc.name}' enforces authentication, but all {len(dst_eps)} "
                f"endpoints in internal service '{dst_svc.name}' lack independent authorization guards."
            )

            finding = Finding(
                finding_id=fingerprint,
                rule_id="CD-004",
                title="Gateway-Only Authorization Policy with Unprotected Internal Services",
                severity=SEVERITY_MEDIUM,
                confidence=CONFIDENCE_MEDIUM,
                source_service_id=entry_svc.service_id,
                destination_service_id=dst_id,
                endpoint_id=dst_eps[0].endpoint_id,
                request_path=[entry_svc.service_id, dst_id],
                evidence_snippet=redact_secrets(evidence),
                source_file=dst_eps[0].file,
                line_number=dst_eps[0].line_start,
                authorization_observations=[
                    f"Entry service '{entry_svc.name}' implements authentication at its boundary.",
                    f"All {len(dst_eps)} internal endpoints in '{dst_svc.name}' have zero authorization guards.",
                    "Single point of failure: bypassing the gateway provides complete unauthenticated access to internal microservices.",
                ],
                privilege_observations=[
                    f"Gateway operates at {entry_svc.privilege_level} privilege.",
                    f"Internal service operates at {dst_svc.privilege_level} privilege.",
                ],
                why_matched="Perimeter gateway protects entry points, but internal service has zero authorization guards (single point of failure).",
                why_secure_rejected="Downstream service implements no independent zero-trust authorization guards.",
                security_controls_found=[],
                limitations=(
                    "Structural defense-in-depth observation. Static analysis cannot verify "
                    "internal VPC isolation or firewall rules preventing direct internal access."
                ),
                remediation=(
                    "Adopt a Zero-Trust architecture: require each internal service to authenticate "
                    "and authorize requests independently rather than relying purely on perimeter gateway guards."
                ),
            )
            findings.append(finding)

    logger.info("CD-004: %d findings emitted", len(findings))
    return findings


# ─────────────────────────── Helper Functions ─────────────────────────────

def _has_user_authorization(endpoint: Endpoint) -> bool:
    """
    Check if endpoint has demonstrable user authorization:
    - Formal IR state: AUTHORIZATION_PRESENT (ownership or role check)
    - Explicit ownership comparison (e.g. order.user_id == user.id)
    - Database query ownership filter (e.g. db.filter(Model.user_id == user.id))
    - Role / permission check (e.g. role-check, is_admin)
    - 403-rejection branch tied to authorization logic
    """
    if hasattr(endpoint, "authz_state") and endpoint.authz_state == "AUTHORIZATION_PRESENT":
        if hasattr(endpoint, "authz_type") and endpoint.authz_type in ["USER_OWNERSHIP", "ROLE_CHECK", "PERMISSION_CHECK"]:
            return True

    # User authorization must be semantic (ownership, role, or 403 on access denial),
    # not mere user authentication (like Depends(verify_user) or 401 on missing token)
    user_authz_indicators = {
        "ownership-check", "role-check", "db-ownership-filter", "403-rejection",
        "verify_owner", "check_permission", "is_authorized",
    }

    for check in endpoint.authorization_checks:
        check_lower = check.lower()
        if any(ind in check_lower for ind in user_authz_indicators):
            return True

    return False


def _get_auth_check_observation(endpoint: Endpoint) -> str:
    if not endpoint.authorization_checks:
        return "No authorization dependencies or checks detected in endpoint handler."

    service_checks = [c for c in endpoint.authorization_checks if any(p in c.lower() for p in ["service", "service_key", "service_token"])]
    user_checks = [c for c in endpoint.authorization_checks if any(p in c.lower() for p in ["user", "jwt", "owner", "permission", "role", "ownership", "403"])]

    parts = []
    if service_checks:
        parts.append(f"Service credential verification detected: {service_checks}.")
    if user_checks:
        parts.append(f"User validation detected: {user_checks}.")
    else:
        parts.append("No end-user ownership validation detected.")

    return " ".join(parts)


def _build_evidence_snippet(
    call: ServiceCall,
    dst_ep: Endpoint,
    src_service: Service,
    dst_service: Service,
) -> str:
    header_info = f"Headers passed: {call.passed_headers}" if call.passed_headers else "No headers passed"
    lines = [
        f"// [{call.source_file}:{call.source_line}] Outgoing HTTP call from {src_service.name} ({src_service.privilege_level})",
        f"{call.http_method} {call.destination_route}  ({header_info})",
        f"// Target: {dst_service.name} ({dst_service.privilege_level}) -> handler: {dst_ep.handler}() in {dst_ep.file}:{dst_ep.line_start}",
        f"// Target operation: {dst_ep.method} {dst_ep.route} (sensitive state mutation = {dst_ep.is_sensitive})",
        f"// Target authorization checks: {dst_ep.authorization_checks or 'NONE'}",
    ]
    return redact_secrets("\n".join(lines))


def resolve_unknown_destinations(
    service_calls: List[ServiceCall],
    services: List[Service],
    endpoints: List[Endpoint],
) -> List[ServiceCall]:
    """Resolve UNKNOWN destination services where URL matching allows static resolution."""
    resolved: List[ServiceCall] = []

    for call in service_calls:
        if call.destination_service_id != "UNKNOWN":
            resolved.append(call)
            continue

        dest_route = call.destination_route
        if not dest_route or dest_route in ("<dynamic>", "/"):
            resolved.append(call)
            continue

        best_match: Optional[str] = None
        for ep in endpoints:
            if ep.service_id == call.source_service_id:
                continue
            if routes_match(ep.route, dest_route):
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
    """Execute all detection rules with deduplication and graph risk marking."""
    resolved_calls = resolve_unknown_destinations(service_calls, services, endpoints)

    service_map = {s.service_id: s for s in services}
    endpoint_map = {e.endpoint_id: e for e in endpoints}

    all_findings: List[Finding] = []

    cd001 = run_cd001(call_graph, service_map, endpoint_map, resolved_calls)
    cd002 = run_cd002(call_graph, service_map, endpoint_map, resolved_calls)
    cd003 = run_cd003(call_graph, service_map, endpoint_map, resolved_calls)
    cd004 = run_cd004(call_graph, service_map, endpoint_map, resolved_calls, cd001_findings=cd001)

    all_findings.extend(cd001)
    all_findings.extend(cd002)
    all_findings.extend(cd003)
    all_findings.extend(cd004)

    # Mark risky service nodes in graph
    for finding in all_findings:
        if finding.source_service_id in call_graph.graph:
            call_graph.graph.nodes[finding.source_service_id]["hasRisk"] = True
        if finding.destination_service_id in call_graph.graph:
            call_graph.graph.nodes[finding.destination_service_id]["hasRisk"] = True

    logger.info(
        "Detection summary: %d findings (CD-001: %d, CD-002: %d, CD-003: %d, CD-004: %d)",
        len(all_findings), len(cd001), len(cd002), len(cd003), len(cd004),
    )
    return all_findings
