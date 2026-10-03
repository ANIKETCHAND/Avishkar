"""
Semantic Intermediate Representation (IR) Models — Phase 1
============================================================
Defines structured AST observations, data-flow facts, identity provenance,
and authorization evidence models.

These classes provide an auditable, typed intermediate representation (IR)
between raw AST visitors and security detection rules.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ─────────────────────────── Formal Enums ─────────────────────────────────

class IdentityProvenance(str, Enum):
    """Formal provenance states for identity tokens and headers."""
    USER_AUTHENTICATED = "USER_AUTHENTICATED"
    USER_JWT_VERIFIED = "USER_JWT_VERIFIED"
    USER_ID_FROM_VERIFIED_PRINCIPAL = "USER_ID_FROM_VERIFIED_PRINCIPAL"
    USER_ROLE_FROM_VERIFIED_PRINCIPAL = "USER_ROLE_FROM_VERIFIED_PRINCIPAL"
    SERVICE_CREDENTIAL = "SERVICE_CREDENTIAL"
    STATIC_SECRET = "STATIC_SECRET"
    UNVERIFIED_USER_HEADER = "UNVERIFIED_USER_HEADER"
    DERIVED_IDENTITY = "DERIVED_IDENTITY"
    NO_IDENTITY = "NO_IDENTITY"
    UNKNOWN = "UNKNOWN"


class AuthenticationState(str, Enum):
    """Explicit authentication states."""
    AUTHENTICATION_PRESENT = "AUTHENTICATION_PRESENT"
    AUTHENTICATION_ABSENT = "AUTHENTICATION_ABSENT"
    AUTHENTICATION_UNKNOWN = "AUTHENTICATION_UNKNOWN"


class AuthorizationState(str, Enum):
    """Explicit authorization states."""
    AUTHORIZATION_PRESENT = "AUTHORIZATION_PRESENT"
    AUTHORIZATION_ABSENT = "AUTHORIZATION_ABSENT"
    AUTHORIZATION_UNKNOWN = "AUTHORIZATION_UNKNOWN"


class AuthorizationType(str, Enum):
    """Categories of authorization checks."""
    USER_OWNERSHIP = "USER_OWNERSHIP"
    ROLE_CHECK = "ROLE_CHECK"
    PERMISSION_CHECK = "PERMISSION_CHECK"
    RESOURCE_POLICY = "RESOURCE_POLICY"
    TENANT_ISOLATION = "TENANT_ISOLATION"
    SERVICE_ONLY = "SERVICE_ONLY"
    ADMIN_ONLY = "ADMIN_ONLY"
    UNKNOWN = "UNKNOWN"


class SecurityControlKind(str, Enum):
    """Explicit security controls used to verify safe flows."""
    USER_JWT_VERIFIED = "USER_JWT_VERIFIED"
    RESOURCE_OWNER_CHECK = "RESOURCE_OWNER_CHECK"
    ROLE_CHECK = "ROLE_CHECK"
    PERMISSION_CHECK = "PERMISSION_CHECK"
    TENANT_CHECK = "TENANT_CHECK"
    SERVICE_AUTH = "SERVICE_AUTH"
    SIGNED_DELEGATION = "SIGNED_DELEGATION"
    CAPABILITY_SCOPE = "CAPABILITY_SCOPE"


# ─────────────────────────── IR Core Models ───────────────────────────────

class SourceLocation(BaseModel):
    """Pinpoints an exact AST node location in source code."""
    file_path: str
    start_line: int
    end_line: int
    start_col: int = 0
    end_col: int = 0
    snippet: str = ""


class Symbol(BaseModel):
    """Represents a named identifier, variable, or function in code."""
    name: str
    symbol_type: str  # "variable", "parameter", "function", "class", "module"
    scope: str        # e.g. "order_service.main.cancel_order"
    location: SourceLocation
    inferred_type: Optional[str] = None


class VariableAssignment(BaseModel):
    """Tracks a variable assignment and its source expression."""
    target: str
    source_expression: str
    location: SourceLocation
    assigned_value: Optional[Any] = None
    is_dict: bool = False
    dict_entries: Dict[str, str] = Field(default_factory=dict)


class IdentitySource(BaseModel):
    """Origin point of user or service identity."""
    provenance: IdentityProvenance
    source_type: str  # "header", "jwt_payload", "dependency", "constant", "param"
    name: str
    location: SourceLocation
    is_verified: bool = False
    evidence_text: str = ""


class IdentitySink(BaseModel):
    """Sink point where identity is consumed or forwarded."""
    sink_type: str  # "http_header", "authz_check", "db_query", "log"
    name: str
    location: SourceLocation
    passed_provenance: IdentityProvenance = IdentityProvenance.UNKNOWN
    evidence_text: str = ""


class DataFlowFact(BaseModel):
    """Represents a verified intra- or inter-procedural flow step."""
    fact_type: str  # "alias", "header_flow", "parameter_flow", "return_flow"
    source_symbol: str
    target_symbol: str
    source_location: SourceLocation
    target_location: SourceLocation
    confidence: str = "HIGH"
    description: str = ""


class ResourceOwnershipCheck(BaseModel):
    """Represents semantic proof of resource ownership validation."""
    resource_id_symbol: str
    principal_id_symbol: str
    comparison_operator: str  # "==", "!=", "in"
    has_rejection_branch: bool = True  # raises 403/401 on mismatch
    location: SourceLocation
    is_verified: bool = True
    evidence_text: str = ""


class AuthorizationCheck(BaseModel):
    """Structured authorization observation."""
    authz_type: AuthorizationType
    state: AuthorizationState
    guard_mechanism: str  # "comparison", "decorator", "dependency", "helper_call"
    location: SourceLocation
    confidence: str = "HIGH"
    evidence_text: str = ""
    related_symbol: Optional[str] = None
    ownership_check: Optional[ResourceOwnershipCheck] = None


class SensitiveOperationEvidence(BaseModel):
    """Evidence proving a route performs sensitive state mutation."""
    operation_type: str  # "financial_refund", "account_deletion", "permission_grant", "db_mutation"
    http_method: str
    target_path: str
    handler_name: str
    location: SourceLocation
    confidence: str = "HIGH"
    evidence_text: str = ""
    db_mutation_detected: bool = False


class EndpointMatchEvidence(BaseModel):
    """Proof linking an outgoing HTTP call to a specific destination endpoint."""
    source_call_id: str
    matched_endpoint_id: str
    raw_url: str
    normalized_path: str
    match_strategy: str  # "exact_literal", "template_parameter", "service_name_routing"
    confidence: str = "HIGH"
    is_resolved: bool = True


class ServiceBoundaryEvidence(BaseModel):
    """Evidence classifying a microservice boundary."""
    service_id: str
    declared_name: str
    root_path: str
    detected_via: List[str] = Field(default_factory=list)  # "directory", "fastapi_app", "docker_compose"
    entrypoints: List[str] = Field(default_factory=list)
    confidence: str = "HIGH"


class PrivilegeEvidence(BaseModel):
    """Multi-signal evidence for inferred service privilege level."""
    inferred_level: str  # "PUBLIC", "USER", "SERVICE", "ADMIN", "UNKNOWN"
    confidence: str = "HIGH"
    primary_reasons: List[str] = Field(default_factory=list)
    supporting_locations: List[SourceLocation] = Field(default_factory=list)
    opposing_signals: List[str] = Field(default_factory=list)


class SecurityControlEvidence(BaseModel):
    """Explicit security control found in the path that protects against confused deputy."""
    control_kind: SecurityControlKind
    enforced_at_service: str
    enforced_at_endpoint: str
    location: SourceLocation
    evidence_text: str
    is_effective: bool = True


class RouteSecurityModel(BaseModel):
    """Complete security profile of a route handler."""
    route_id: str
    method: str
    path: str
    handler: str
    location: SourceLocation
    authn_state: AuthenticationState = AuthenticationState.AUTHENTICATION_UNKNOWN
    authz_state: AuthorizationState = AuthorizationState.AUTHORIZATION_UNKNOWN
    authz_checks: List[AuthorizationCheck] = Field(default_factory=list)
    sensitive_evidence: Optional[SensitiveOperationEvidence] = None
    security_controls: List[SecurityControlEvidence] = Field(default_factory=list)
    is_internal_only: bool = False


class HttpCallModel(BaseModel):
    """Detailed model of an outgoing HTTP client call."""
    call_id: str
    source_service_id: str
    source_endpoint_id: str
    source_handler: str
    raw_url: str
    resolved_url: str
    http_method: str
    location: SourceLocation
    identity_source: Optional[IdentitySource] = None
    identity_sink: Optional[IdentitySink] = None
    data_flow_facts: List[DataFlowFact] = Field(default_factory=list)
    endpoint_match: Optional[EndpointMatchEvidence] = None
