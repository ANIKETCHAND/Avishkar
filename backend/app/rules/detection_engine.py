"""
Detection Engine — Semantic & Deterministic (Upgraded)
========================================================
Implements the four formal Confused Deputy detection rules:

CD-001: Potential Privilege-Boundary Confused Deputy
CD-002: Privileged Downstream Service with Missing Demonstrable Authorization
CD-003: Untrusted Identity Propagation via Unverified Headers
CD-004: Gateway-Only Authorization Policy with Unprotected Internal Services

Key Improvements:
- Combined semantic evidence (not simple keyword presence)
- Deterministic finding fingerprints based on rule, endpoints, and path (zero duplicate noise)
- Exact evidence snippets with line numbers and secret redaction
- Accurate severity vs. confidence scoring based on static evidence certainty
- Avoids false positives on read-only endpoints, benign service tokens, or secure ownership checks
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
from ..analyzer.ast_visitor import redact_secrets

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
    """
    Compute severity based on privilege escalation and target operation sensitivity.
    """
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
) -> str:
    """
    Compute confidence based on evidence certainty.
    Lower confidence if target service was unresolved (UNKNOWN) or headers are dynamic.
    """
    if not is_target_resolved:
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
    CD-001: Potential Privilege-Boundary Confused Deputy

    Requires 5 combined conditions:
    1. Source service operates at lower privilege (PUBLIC or USER).
    2. Target service operates at elevated privilege (SERVICE or ADMIN).
    3. Target endpoint executes a sensitive state-changing operation (DELETE, refund, void, etc.).
    4. Service credential (SERVICE_TOKEN) is used without forwarding user authentication context.
    5. Target endpoint lacks demonstrable user ownership/authorization validation.
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

        # Condition 3 & 4: Check if identity is NOT properly forwarded as verified JWT
        identity_prop = call.identity_propagation
        if identity_prop == IDENTITY_FORWARDED_USER_JWT:
            # User JWT is forwarded. Check if target verifies ownership.
            dst_eps = [e for e in endpoints.values() if e.service_id == dst_service.service_id and e.is_sensitive]
            all_verified = all(_has_user_authorization(ep) for ep in dst_eps)
            if all_verified and dst_eps:
                continue  # Secure: user identity forwarded and validated downstream

        # Find target sensitive endpoints
        dst_sensitive_eps = [
            e for e in endpoints.values()
            if e.service_id == dst_service.service_id and e.is_sensitive
        ]
        if not dst_sensitive_eps:
            # If the called route itself is not sensitive, benign service-token call
            continue

        # Check each sensitive endpoint
        for dst_ep in dst_sensitive_eps:
            # Condition 5: If downstream endpoint has demonstrable user authorization, it's NOT vulnerable
            if _has_user_authorization(dst_ep):
                continue

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

            severity = compute_severity(src_priv, dst_priv, True, identity_prop)
            confidence = compute_confidence(
                identity_prop,
                call.passed_headers,
                has_explicit_token=(identity_prop == IDENTITY_SERVICE_TOKEN),
                is_target_resolved=(call.destination_service_id != "UNKNOWN"),
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

    Detects: Internal downstream endpoints reachable from user-facing services
    that have ZERO detectable authentication or authorization logic.
    """
    findings: List[Finding] = []
    seen_fingerprints: Set[str] = set()

    for call in service_calls:
        src_service = services.get(call.source_service_id)
        dst_service = services.get(call.destination_service_id)

        if not src_service or not dst_service:
            continue

        src_priv = src_service.privilege_level
        if PRIVILEGE_RANK.get(src_priv, -1) < PRIVILEGE_RANK[PRIVILEGE_USER]:
            continue

        dst_eps = [e for e in endpoints.values() if e.service_id == dst_service.service_id]
        for dst_ep in dst_eps:
            # If endpoint has authentication or authorization checks, it is NOT CD-002
            if dst_ep.authentication or dst_ep.authorization_checks:
                continue

            # CD-002 targets privileged internal endpoints or sensitive state-changing operations
            is_internal_or_sensitive = (
                any(p in dst_ep.route.lower() for p in ["/internal", "/service", "/rpc", "/private", "/admin"])
                or dst_ep.is_sensitive
            )
            if not is_internal_or_sensitive:
                continue

            # Verify reachability from public/user service
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

    Detects: Inter-service calls passing plain identity headers (X-User-Id, X-User-Role)
    WITHOUT cryptographic signature or accompanied Authorization Bearer JWT.
    """
    findings: List[Finding] = []
    seen_fingerprints: Set[str] = set()

    for call in service_calls:
        # Check if call passes plain user headers
        user_headers = [h for h in call.passed_headers if h.lower() in {"x-user-id", "x-user-role", "x-user-email"}]
        has_jwt = any(h.lower() == "authorization" for h in call.passed_headers)

        if not user_headers:
            continue
        if has_jwt:
            continue  # JWT provides cryptographic verification context

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
    CD-004: Gateway-Only Authorization Policy

    Detects: Upstream entrypoint has authentication, but 100% of reachable
    internal downstream endpoints have zero independent authorization guards.
    Deduplicates against CD-001 so the same flow is not redundantly flagged.
    """
    findings: List[Finding] = []
    seen_fingerprints: Set[str] = set()

    # Find service pairs already flagged by CD-001 to avoid duplicate noise
    cd001_service_pairs = set()
    if cd001_findings:
        for f in cd001_findings:
            cd001_service_pairs.add((f.source_service_id, f.destination_service_id))

    entry_services = [s for s in services.values() if PRIVILEGE_RANK.get(s.privilege_level, -1) >= PRIVILEGE_RANK[PRIVILEGE_USER]]

    for entry_svc in entry_services:
        entry_eps = [e for e in endpoints.values() if e.service_id == entry_svc.service_id]
        if not any(e.authentication for e in entry_eps):
            continue

        downstream_ids = call_graph.get_downstream_services(entry_svc.service_id)
        for dst_id in downstream_ids:
            # Skip if CD-001 already identified a concrete confused-deputy path on this pair
            if (entry_svc.service_id, dst_id) in cd001_service_pairs:
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

            fingerprint = _make_finding_fingerprint(
                "CD-004",
                entry_svc.service_id,
                entry_eps[0].endpoint_id,
                dst_id,
                dst_eps[0].endpoint_id,
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
    - User authentication dependency (e.g. Depends(verify_user_jwt))
    - Explicit ownership checks (e.g. verify_user_owns_order, owner_id == user.id)
    - Rejection statements (HTTP 403 / 401)
    - Role checks
    """
    service_only_indicators = {"service", "service_key", "service_token", "internal_token"}
    user_authz_indicators = {
        "user", "jwt", "owner", "ownership", "verify_user", "get_current_user",
        "permission", "role", "admin", "owns", "can_", "authorize",
        "403-rejection", "401-rejection", "ownership-check", "role-check",
    }

    has_user_check = False
    for check in endpoint.authorization_checks:
        check_lower = check.lower()
        if any(ind in check_lower for ind in user_authz_indicators):
            # Ensure it is not purely service token validation
            if not all(s in check_lower for s in service_only_indicators):
                has_user_check = True
                break

    return has_user_check


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

    snippet = (
        f"# Confused Deputy Exploit Path Evidence\n"
        f"# Source: {src_service.name} ({src_service.privilege_level})\n"
        f"# Outbound Call: HTTP {call.http_method} → {call.destination_route}\n"
        f"# File: {call.source_file}:{call.source_line}\n"
        f"# Identity Propagation: {call.identity_propagation}\n"
        f"# {header_info}\n"
        f"#\n"
        f"# Target: {dst_service.name} ({dst_service.privilege_level})\n"
        f"# Target Endpoint: {dst_ep.method} {dst_ep.route} [Handler: {dst_ep.handler}]\n"
        f"# Target File: {dst_ep.file}:{dst_ep.line_start}\n"
        f"# Sensitive Mutation: {dst_ep.is_sensitive}\n"
        f"# Downstream Auth Checks: {dst_ep.authorization_checks or 'NONE'}"
    )
    return redact_secrets(snippet)


def resolve_unknown_destinations(
    service_calls: List[ServiceCall],
    services: List[Service],
    endpoints: List[Endpoint],
) -> List[ServiceCall]:
    """Resolve calls with UNKNOWN destination_service_id using route matching."""
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
            if dest_route == ep.route:
                best_match = ep.service_id
                break
            if dest_route and ep.route and len(ep.route) > 3:
                ep_norm = ep.route.rstrip("/")
                dest_norm = dest_route.rstrip("/")
                if ep_norm == dest_norm or dest_norm.endswith(ep_norm):
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
