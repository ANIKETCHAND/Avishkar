"""
Pydantic v2 Data Models
========================
Defines all structured data schemas for the Confused Deputy Detector.
These match DATA_SCHEMA.md exactly and are used throughout the backend pipeline.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


# ---------------------------------------------------------------------------
# Enumerations (using plain string literals for Pydantic v2 compatibility)
# ---------------------------------------------------------------------------

# Privilege levels
PRIVILEGE_PUBLIC = "PUBLIC"
PRIVILEGE_USER = "USER"
PRIVILEGE_SERVICE = "SERVICE"
PRIVILEGE_ADMIN = "ADMIN"
PRIVILEGE_ELEVATED = "ELEVATED"  # alias used in documentation
PRIVILEGE_UNKNOWN = "UNKNOWN"

PRIVILEGE_RANK: Dict[str, int] = {
    "PUBLIC": 0,
    "USER": 1,
    "SERVICE": 2,
    "ELEVATED": 2,  # treat as SERVICE
    "ADMIN": 3,
    "UNKNOWN": -1,
}

# Severity levels
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# Confidence levels
CONFIDENCE_LOW = "LOW"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_HIGH = "HIGH"

# Identity propagation types
IDENTITY_FORWARDED_USER_JWT = "FORWARDED_USER_JWT"
IDENTITY_SERVICE_TOKEN = "SERVICE_TOKEN"
IDENTITY_STRIPPED = "STRIPPED"
IDENTITY_UNKNOWN = "UNKNOWN"

# Scan statuses
STATUS_PENDING = "PENDING"
STATUS_PROCESSING = "PROCESSING"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"


# ---------------------------------------------------------------------------
# Core Data Models
# ---------------------------------------------------------------------------

class Project(BaseModel):
    """Root uploaded application metadata."""
    project_id: str = Field(default_factory=lambda: f"proj_{uuid.uuid4().hex[:8]}")
    project_name: str
    uploaded_at: str  # ISO 8601 timestamp
    language: str = "python"
    framework: str = "fastapi"
    total_files: int = 0
    scan_status: str = STATUS_PENDING
    analysis_version: str = "1.0.0"


class Service(BaseModel):
    """Represents a discovered microservice boundary."""
    service_id: str  # e.g., "svc_order"
    name: str        # e.g., "order-service"
    path: str        # Relative filesystem root path
    language: str = "python"
    framework: str = "fastapi"
    privilege_level: str = PRIVILEGE_UNKNOWN
    confidence: str = CONFIDENCE_MEDIUM
    entry_points: List[str] = Field(default_factory=list)


class Endpoint(BaseModel):
    """Represents an HTTP API route handler defined within a service."""
    endpoint_id: str
    service_id: str
    method: str          # GET, POST, PUT, DELETE, PATCH
    route: str           # URL path template e.g. "/api/v1/orders/{id}"
    handler: str         # Python function name
    file: str            # Source file path relative to repo root
    line_start: int
    line_end: int
    authentication: bool = False
    authorization_checks: List[str] = Field(default_factory=list)
    is_sensitive: bool = False


class ServiceCall(BaseModel):
    """Represents an outgoing HTTP client call initiated from an endpoint handler."""
    call_id: str
    source_service_id: str
    source_endpoint_id: str
    destination_service_id: str = "UNKNOWN"
    destination_route: str
    http_method: str
    source_file: str
    source_line: int
    call_type: str = "HTTP_CLIENT"
    identity_propagation: str = IDENTITY_UNKNOWN
    passed_headers: List[str] = Field(default_factory=list)


class PrivilegeBoundary(BaseModel):
    """Represents a transition between differing privilege contexts."""
    boundary_id: str
    source_service_id: str
    destination_service_id: str
    source_privilege: str
    destination_privilege: str
    evidence: str
    confidence: str = CONFIDENCE_MEDIUM


class Finding(BaseModel):
    """Represents a confirmed security rule finding."""
    finding_id: str
    rule_id: str          # "CD-001", "CD-002", "CD-003", "CD-004"
    title: str
    severity: str         # LOW, MEDIUM, HIGH, CRITICAL
    confidence: str       # LOW, MEDIUM, HIGH
    source_service_id: str
    destination_service_id: str
    endpoint_id: str
    request_path: List[str] = Field(default_factory=list)
    evidence_snippet: str
    source_file: str
    line_number: int
    authorization_observations: List[str] = Field(default_factory=list)
    privilege_observations: List[str] = Field(default_factory=list)
    limitations: str = ""
    remediation: str = ""


class GraphNode(BaseModel):
    """A node in the React Flow / NetworkX graph."""
    id: str
    label: str
    type: str  # "SERVICE_NODE" or "ENDPOINT_NODE"
    data: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """A directed edge in the React Flow / NetworkX graph."""
    id: str
    source: str
    target: str
    label: str = ""
    data: Dict[str, Any] = Field(default_factory=dict)


class GraphModel(BaseModel):
    """Serialized graph payload for React Flow rendering."""
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Complete serialized scan result JSON."""
    scan_id: str
    project: Project
    services: List[Service] = Field(default_factory=list)
    endpoints: List[Endpoint] = Field(default_factory=list)
    service_calls: List[ServiceCall] = Field(default_factory=list)
    privilege_boundaries: List[PrivilegeBoundary] = Field(default_factory=list)
    graph: GraphModel = Field(default_factory=GraphModel)
    findings: List[Finding] = Field(default_factory=list)
    summary_stats: Dict[str, int] = Field(default_factory=dict)
    scan_duration_seconds: Optional[float] = None
    warnings: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# API Request/Response Models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Request model for initiating a scan via benchmark demo."""
    demo_type: Optional[str] = None  # "vulnerable" or "secure"


class ScanSummaryResponse(BaseModel):
    """Lightweight scan summary for listing/status endpoints."""
    scan_id: str
    project_name: str
    scan_status: str
    total_services: int
    total_endpoints: int
    total_findings: int
    scan_duration_seconds: Optional[float] = None
    uploaded_at: str


class ParseError(BaseModel):
    """Records a file that failed AST parsing."""
    file: str
    error: str
    line: Optional[int] = None
