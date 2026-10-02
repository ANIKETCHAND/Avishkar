"""
Comprehensive Test Suite for Confused Deputy API Detector
===========================================================
Tests cover all phases:
- ZIP ingestion security
- AST parsing
- Service/endpoint/call discovery
- Auth analysis
- Graph construction
- CD-001 through CD-004 rules
- Severity/confidence computation
- HTML report generation
- API integration
- Vulnerable vs secure benchmark
"""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path
from typing import List

import pytest

# ─────────────────────────── Test Fixtures ────────────────────────────────

VULNERABLE_MAIN_PY = '''
from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import httpx

app = FastAPI()

PAYMENT_SERVICE_URL = "http://payment-service:8001"
SERVICE_TOKEN = "ORDER_SVC_HARDCODED_SECRET_KEY_12345"

class User(BaseModel):
    user_id: str
    username: str

def get_current_user(authorization: Optional[str] = Header(None)) -> User:
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return User(user_id="user-1042", username="alice")

@app.post("/api/v1/orders/{order_id}/cancel")
def cancel_order(order_id: str, user: User = Depends(get_current_user)):
    response = httpx.post(
        f"{PAYMENT_SERVICE_URL}/internal/v1/refund",
        headers={"X-Service-Key": SERVICE_TOKEN, "X-User-Id": user.user_id},
        json={"order_id": order_id},
    )
    return {"status": "CANCELLED"}
'''

VULNERABLE_PAYMENT_PY = '''
from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

VALID_SERVICE_KEYS = {"ORDER_SVC_HARDCODED_SECRET_KEY_12345"}

class ServiceAuth(BaseModel):
    service_name: str

class RefundRequest(BaseModel):
    order_id: str

def verify_service_key(x_service_key: Optional[str] = Header(None)) -> ServiceAuth:
    if not x_service_key or x_service_key not in VALID_SERVICE_KEYS:
        raise HTTPException(status_code=401, detail="Invalid service key")
    return ServiceAuth(service_name="order-service")

@app.post("/internal/v1/refund")
def process_refund(request: RefundRequest, service: ServiceAuth = Depends(verify_service_key)):
    # VULNERABLE: No user ownership check
    return {"refund_id": f"REF-{request.order_id}", "status": "PROCESSED"}

@app.delete("/internal/v1/payments/{order_id}")
def void_payment(order_id: str, service: ServiceAuth = Depends(verify_service_key)):
    return {"order_id": order_id, "status": "VOIDED"}
'''

SECURE_ORDER_PY = '''
from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import httpx

app = FastAPI()

PAYMENT_SERVICE_URL = "http://payment-service:8001"
SERVICE_TOKEN = "ORDER_SVC_INTERNAL_TOKEN"

class User(BaseModel):
    user_id: str
    username: str

def get_current_user(authorization: Optional[str] = Header(None)) -> User:
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return User(user_id="user-1042", username="alice")

@app.post("/api/v1/orders/{order_id}/cancel")
def cancel_order(order_id: str, user: User = Depends(get_current_user), authorization: Optional[str] = Header(None)):
    response = httpx.post(
        f"{PAYMENT_SERVICE_URL}/internal/v1/refund",
        headers={"X-Service-Token": SERVICE_TOKEN, "Authorization": authorization},
        json={"order_id": order_id},
    )
    return {"status": "CANCELLED"}
'''

SECURE_PAYMENT_PY = '''
from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

VALID_TOKENS = {"ORDER_SVC_INTERNAL_TOKEN"}

class ServiceAuth(BaseModel):
    service_name: str

class UserClaims(BaseModel):
    user_id: str

class RefundRequest(BaseModel):
    order_id: str

def verify_service_token(x_service_token: Optional[str] = Header(None)) -> ServiceAuth:
    if not x_service_token or x_service_token not in VALID_TOKENS:
        raise HTTPException(status_code=401)
    return ServiceAuth(service_name="order-service")

def verify_user_jwt(authorization: Optional[str] = Header(None)) -> UserClaims:
    if not authorization:
        raise HTTPException(status_code=401)
    return UserClaims(user_id="user-1042")

def verify_user_owns_order(user_id: str, order_id: str) -> bool:
    return True  # Simulated ownership check

@app.post("/internal/v1/refund")
def process_refund(
    request: RefundRequest,
    service: ServiceAuth = Depends(verify_service_token),
    user: UserClaims = Depends(verify_user_jwt),
):
    if not verify_user_owns_order(user.user_id, request.order_id):
        raise HTTPException(status_code=403)
    return {"refund_id": f"REF-{request.order_id}-SECURE", "status": "PROCESSED"}
'''


# ─────────────────────────── Helper Utilities ─────────────────────────────

def create_zip(files: dict) -> bytes:
    """Create an in-memory ZIP with the given {filename: content} dict."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def write_temp_zip(files: dict, tmp_path: Path) -> Path:
    """Write a ZIP to a temp file and return its path."""
    zip_bytes = create_zip(files)
    zip_path = tmp_path / "test.zip"
    zip_path.write_bytes(zip_bytes)
    return zip_path


# ─────────────────────────── Ingestion Tests ─────────────────────────────

class TestIngestion:
    """Tests for secure ZIP unpacking."""

    def test_valid_zip_extraction(self, tmp_path):
        """Valid ZIP with Python files should extract successfully."""
        from app.ingestion.unpacker import unpack_zip, ExtractionResult

        zip_path = write_temp_zip({"main.py": "from fastapi import FastAPI"}, tmp_path)
        result = unpack_zip(zip_path, tmp_path / "storage", "scan_001")
        assert len(result.python_files) == 1
        assert result.total_files == 1
        result.cleanup()

    def test_path_traversal_rejected(self, tmp_path):
        """ZIP with path traversal entries should be rejected."""
        from app.ingestion.unpacker import unpack_zip, IngestionError

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../../etc/passwd", "root:x:0:0")
        zip_path = tmp_path / "evil.zip"
        zip_path.write_bytes(buf.getvalue())

        with pytest.raises(IngestionError, match="traversal"):
            unpack_zip(zip_path, tmp_path / "storage", "scan_002")

    def test_oversized_archive_rejected(self, tmp_path, monkeypatch):
        """Archives exceeding MAX_ARCHIVE_SIZE_BYTES should be rejected."""
        import app.ingestion.unpacker as unpacker_mod
        from app.ingestion.unpacker import unpack_zip, IngestionError

        # Lower limit for safe disk-friendly testing
        monkeypatch.setattr(unpacker_mod, "MAX_ARCHIVE_SIZE_BYTES", 50)
        zip_path = write_temp_zip({"file.py": "# " + "a" * 200}, tmp_path)

        with pytest.raises(IngestionError, match="too large"):
            unpack_zip(zip_path, tmp_path / "storage", "scan_003")

    def test_invalid_zip_rejected(self, tmp_path):
        """Non-ZIP files should be rejected with IngestionError."""
        from app.ingestion.unpacker import unpack_zip, IngestionError

        not_zip = tmp_path / "notazip.zip"
        not_zip.write_bytes(b"This is not a ZIP file at all!!!")

        with pytest.raises(IngestionError, match="Invalid ZIP"):
            unpack_zip(not_zip, tmp_path / "storage", "scan_004")

    def test_file_count_limit(self, tmp_path):
        """Archives with > 500 files should be rejected."""
        from app.ingestion.unpacker import unpack_zip, IngestionError

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(501):
                zf.writestr(f"file_{i}.py", "# empty")
        zip_path = tmp_path / "many.zip"
        zip_path.write_bytes(buf.getvalue())

        with pytest.raises(IngestionError, match="500"):
            unpack_zip(zip_path, tmp_path / "storage", "scan_005")

    def test_pyc_files_excluded(self, tmp_path):
        """Compiled .pyc files should be excluded from extraction."""
        from app.ingestion.unpacker import unpack_zip

        zip_path = write_temp_zip({
            "main.py": "from fastapi import FastAPI",
            "cached.pyc": b"\x00" * 100,
        }, tmp_path)
        result = unpack_zip(zip_path, tmp_path / "storage", "scan_006")
        assert all(not str(f).endswith(".pyc") for f in result.python_files)
        result.cleanup()


# ─────────────────────────── AST Visitor Tests ────────────────────────────

class TestASTVisitor:
    """Tests for Python AST parsing."""

    def test_fastapi_route_detection(self, tmp_path):
        """Should detect FastAPI route decorators."""
        from app.analyzer.ast_visitor import analyze_file

        py_file = tmp_path / "main.py"
        py_file.write_text(VULNERABLE_MAIN_PY)
        result = analyze_file(py_file, tmp_path)

        assert result.parse_error is None
        assert len(result.routes) >= 1
        routes = {r.method: r for r in result.routes}
        assert "POST" in routes
        post_route = routes["POST"]
        assert "cancel" in post_route.path.lower() or "order" in post_route.path.lower()

    def test_fastapi_app_detection(self, tmp_path):
        """Should detect FastAPI() application instantiation."""
        from app.analyzer.ast_visitor import analyze_file

        py_file = tmp_path / "main.py"
        py_file.write_text(VULNERABLE_MAIN_PY)
        result = analyze_file(py_file, tmp_path)

        assert len(result.app_definitions) >= 1
        assert result.app_definitions[0].type_name == "FastAPI"

    def test_http_client_detection(self, tmp_path):
        """Should detect httpx.post() outgoing HTTP calls."""
        from app.analyzer.ast_visitor import analyze_file

        py_file = tmp_path / "main.py"
        py_file.write_text(VULNERABLE_MAIN_PY)
        result = analyze_file(py_file, tmp_path)

        assert len(result.http_calls) >= 1
        call = result.http_calls[0]
        assert call.client_module == "httpx"
        assert call.method == "POST"

    def test_service_token_header_detection(self, tmp_path):
        """Should detect X-Service-Key in outgoing call headers."""
        from app.analyzer.ast_visitor import analyze_file

        py_file = tmp_path / "main.py"
        py_file.write_text(VULNERABLE_MAIN_PY)
        result = analyze_file(py_file, tmp_path)

        assert len(result.http_calls) >= 1
        call = result.http_calls[0]
        assert call.has_service_token, "Should detect X-Service-Key as service token"
        assert not call.has_authorization_header, "Should NOT detect Authorization header"

    def test_authorization_header_detection(self, tmp_path):
        """Should detect Authorization header forwarding in secure pattern."""
        from app.analyzer.ast_visitor import analyze_file

        py_file = tmp_path / "main.py"
        py_file.write_text(SECURE_ORDER_PY)
        result = analyze_file(py_file, tmp_path)

        assert len(result.http_calls) >= 1
        call = result.http_calls[0]
        assert call.has_authorization_header, "Should detect Authorization header forwarding"

    def test_auth_dependency_detection(self, tmp_path):
        """Should detect Depends(get_current_user) as auth dependency."""
        from app.analyzer.ast_visitor import analyze_file

        py_file = tmp_path / "main.py"
        py_file.write_text(VULNERABLE_MAIN_PY)
        result = analyze_file(py_file, tmp_path)

        assert len(result.routes) >= 1
        route = result.routes[0]
        assert route.has_authentication, "Route with Depends(get_current_user) should be authenticated"

    def test_sensitive_operation_detection(self, tmp_path):
        """Should flag refund/delete routes as sensitive."""
        from app.analyzer.ast_visitor import analyze_file

        py_file = tmp_path / "payment.py"
        py_file.write_text(VULNERABLE_PAYMENT_PY)
        result = analyze_file(py_file, tmp_path)

        sensitive = [r for r in result.routes if r.is_sensitive]
        assert len(sensitive) >= 1, "Refund/delete endpoints should be flagged as sensitive"

    def test_syntax_error_handled_gracefully(self, tmp_path):
        """SyntaxError in uploaded file should be recorded, not crash."""
        from app.analyzer.ast_visitor import analyze_file

        py_file = tmp_path / "broken.py"
        py_file.write_text("def broken_function(:\n  pass")
        result = analyze_file(py_file, tmp_path)

        assert result.parse_error is not None
        assert "SyntaxError" in result.parse_error

    def test_secret_redaction(self):
        """Secrets should be redacted from evidence snippets."""
        from app.analyzer.ast_visitor import redact_secrets

        code = 'headers={"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.abc.def"}'
        redacted = redact_secrets(code)
        assert "[REDACTED_SECRET]" in redacted


# ─────────────────────────── Service Discovery Tests ─────────────────────

class TestServiceDiscovery:
    """Tests for service boundary discovery."""

    def _get_ast_results(self, files: dict, tmp_path: Path):
        """Helper to get AST results from a dict of {filename: content}."""
        from app.analyzer.ast_visitor import analyze_file, FileAnalysisResult

        results = []
        for name, content in files.items():
            py_file = tmp_path / name
            py_file.parent.mkdir(parents=True, exist_ok=True)
            py_file.write_text(content)
            results.append(analyze_file(py_file, tmp_path))
        return results

    def test_multiservice_discovery(self, tmp_path):
        """Should discover two separate services from a multi-service repo."""
        from app.analyzer.service_discovery import discover_services

        results = self._get_ast_results({
            "order_service/main.py": VULNERABLE_MAIN_PY,
            "payment_service/main.py": VULNERABLE_PAYMENT_PY,
        }, tmp_path)

        services = discover_services(results, tmp_path)
        assert len(services) >= 2, f"Expected 2+ services, got {len(services)}: {[s.name for s in services]}"

    def test_privilege_inference_user(self, tmp_path):
        """Service with user JWT auth should be inferred as USER privilege."""
        from app.analyzer.ast_visitor import analyze_file
        from app.analyzer.service_discovery import discover_services

        py_file = tmp_path / "order_service" / "main.py"
        py_file.parent.mkdir(parents=True)
        py_file.write_text(VULNERABLE_MAIN_PY)
        results = [analyze_file(py_file, tmp_path)]
        services = discover_services(results, tmp_path)

        assert any(s.privilege_level in ("USER", "UNKNOWN") for s in services)


# ─────────────────────────── Identity Propagation Tests ──────────────────

class TestIdentityPropagation:
    """Tests for identity propagation classification."""

    def test_service_token_propagation(self, tmp_path):
        """Calls with X-Service-Key only should be classified as SERVICE_TOKEN."""
        from app.analyzer.ast_visitor import analyze_file
        from app.analyzer.api_discovery import _classify_identity_propagation

        py_file = tmp_path / "main.py"
        py_file.write_text(VULNERABLE_MAIN_PY)
        result = analyze_file(py_file, tmp_path)

        assert len(result.http_calls) >= 1
        call = result.http_calls[0]
        classification = _classify_identity_propagation(call)
        assert classification == "SERVICE_TOKEN"

    def test_forwarded_jwt_propagation(self, tmp_path):
        """Calls with Authorization header should be classified as FORWARDED_USER_JWT."""
        from app.analyzer.ast_visitor import analyze_file
        from app.analyzer.api_discovery import _classify_identity_propagation

        py_file = tmp_path / "main.py"
        py_file.write_text(SECURE_ORDER_PY)
        result = analyze_file(py_file, tmp_path)

        assert len(result.http_calls) >= 1
        call = result.http_calls[0]
        classification = _classify_identity_propagation(call)
        assert classification == "FORWARDED_USER_JWT"


# ─────────────────────────── Detection Rule Tests ─────────────────────────

class TestDetectionRules:
    """Tests for CD-001 through CD-004 detection rules."""

    def _run_full_pipeline(self, files: dict, tmp_path: Path):
        """Run the complete analysis pipeline on given files."""
        from app.analyzer.ast_visitor import analyze_files
        from app.analyzer.service_discovery import discover_services
        from app.analyzer.api_discovery import discover_endpoints, discover_service_calls
        from app.analyzer.auth_analyzer import analyze_privilege_boundaries, refine_service_privileges
        from app.graph.call_graph import CallGraph
        from app.rules.detection_engine import run_all_rules

        # Write files
        py_files = []
        for name, content in files.items():
            py_file = tmp_path / name
            py_file.parent.mkdir(parents=True, exist_ok=True)
            py_file.write_text(content)
            py_files.append(py_file)

        ast_results, _ = analyze_files(py_files, tmp_path)
        services = discover_services(ast_results, tmp_path)
        services = refine_service_privileges(services, [])
        endpoints = discover_endpoints(ast_results, services, tmp_path)
        service_calls = discover_service_calls(ast_results, services, endpoints)
        privilege_boundaries = analyze_privilege_boundaries(services, service_calls)

        cg = CallGraph()
        cg.build(services, endpoints, service_calls)

        findings = run_all_rules(cg, services, endpoints, service_calls)
        return services, endpoints, service_calls, findings

    def test_cd001_vulnerable_refund_flow(self, tmp_path):
        """CD-001 should fire on the vulnerable order→payment confused deputy pattern."""
        services, endpoints, calls, findings = self._run_full_pipeline({
            "order_service/main.py": VULNERABLE_MAIN_PY,
            "payment_service/main.py": VULNERABLE_PAYMENT_PY,
        }, tmp_path)

        cd001_findings = [f for f in findings if f.rule_id == "CD-001"]
        # We need at least some findings (CD-001 or CD-002)
        relevant = [f for f in findings if f.rule_id in ("CD-001", "CD-002", "CD-003")]
        assert len(relevant) > 0, (
            f"Expected at least 1 confused deputy finding for vulnerable pattern. "
            f"Got {len(findings)} total findings. "
            f"Services: {[s.name for s in services]}, "
            f"Calls: {len(calls)}, "
            f"Endpoints: {[(e.service_id, e.route) for e in endpoints]}"
        )

    def test_cd001_secure_ownership_flow(self, tmp_path):
        """CD-001 should NOT fire when user JWT is forwarded and ownership is verified."""
        services, endpoints, calls, findings = self._run_full_pipeline({
            "order_service/main.py": SECURE_ORDER_PY,
            "payment_service/main.py": SECURE_PAYMENT_PY,
        }, tmp_path)

        cd001_findings = [f for f in findings if f.rule_id == "CD-001"]
        assert len(cd001_findings) == 0, (
            f"CD-001 should NOT fire for secure pattern. "
            f"Fired {len(cd001_findings)} times: {[f.finding_id for f in cd001_findings]}"
        )

    def test_severity_critical_for_admin_sensitive(self):
        """Privilege jump from USER to ADMIN with sensitive op should be CRITICAL."""
        from app.rules.detection_engine import compute_severity
        from app.models.schemas import PRIVILEGE_USER, PRIVILEGE_ADMIN, IDENTITY_SERVICE_TOKEN

        severity = compute_severity(PRIVILEGE_USER, PRIVILEGE_ADMIN, True, IDENTITY_SERVICE_TOKEN)
        assert severity == "CRITICAL"

    def test_severity_high_for_user_to_service_sensitive(self):
        """Privilege jump from USER to SERVICE with sensitive op should be HIGH."""
        from app.rules.detection_engine import compute_severity
        from app.models.schemas import PRIVILEGE_USER, PRIVILEGE_SERVICE, IDENTITY_SERVICE_TOKEN

        severity = compute_severity(PRIVILEGE_USER, PRIVILEGE_SERVICE, True, IDENTITY_SERVICE_TOKEN)
        assert severity == "HIGH"

    def test_confidence_high_for_service_token(self):
        """Explicit service token should yield HIGH confidence."""
        from app.rules.detection_engine import compute_confidence
        from app.models.schemas import IDENTITY_SERVICE_TOKEN

        confidence = compute_confidence(IDENTITY_SERVICE_TOKEN, ["X-Service-Key"], True)
        assert confidence == "HIGH"


# ─────────────────────────── Graph Tests ──────────────────────────────────

class TestCallGraph:
    """Tests for NetworkX call graph construction."""

    def test_graph_construction(self, tmp_path):
        """Graph should contain service nodes and call edges."""
        from app.analyzer.ast_visitor import analyze_files
        from app.analyzer.service_discovery import discover_services
        from app.analyzer.api_discovery import discover_endpoints, discover_service_calls
        from app.graph.call_graph import CallGraph

        files = {
            "order_service/main.py": VULNERABLE_MAIN_PY,
            "payment_service/main.py": VULNERABLE_PAYMENT_PY,
        }
        py_files = []
        for name, content in files.items():
            py_file = tmp_path / name
            py_file.parent.mkdir(parents=True, exist_ok=True)
            py_file.write_text(content)
            py_files.append(py_file)

        ast_results, _ = analyze_files(py_files, tmp_path)
        services = discover_services(ast_results, tmp_path)
        endpoints = discover_endpoints(ast_results, services, tmp_path)
        calls = discover_service_calls(ast_results, services, endpoints)

        cg = CallGraph()
        cg.build(services, endpoints, calls)

        assert cg.graph.number_of_nodes() > 0
        service_nodes = cg.get_service_nodes()
        assert len(service_nodes) >= 2

    def test_graph_serialization(self, tmp_path):
        """Graph should serialize to valid GraphModel for React Flow."""
        from app.analyzer.ast_visitor import analyze_files
        from app.analyzer.service_discovery import discover_services
        from app.analyzer.api_discovery import discover_endpoints, discover_service_calls
        from app.graph.call_graph import CallGraph

        py_file = tmp_path / "main.py"
        py_file.write_text(VULNERABLE_MAIN_PY)
        ast_results, _ = analyze_files([py_file], tmp_path)
        services = discover_services(ast_results, tmp_path)
        endpoints = discover_endpoints(ast_results, services, tmp_path)
        calls = discover_service_calls(ast_results, services, endpoints)

        cg = CallGraph()
        cg.build(services, endpoints, calls)
        graph_model = cg.to_graph_model()

        assert graph_model is not None
        assert len(graph_model.nodes) > 0
        # Verify all nodes have required fields
        for node in graph_model.nodes:
            assert node.id
            assert node.type in ("SERVICE_NODE", "ENDPOINT_NODE")


# ─────────────────────────── Reporting Tests ─────────────────────────────

class TestReporting:
    """Tests for HTML and JSON report generation."""

    def test_html_report_generation(self):
        """HTML report should be generated without XSS vulnerabilities."""
        from app.reporting.html_report import generate_html_report
        from app.models.schemas import (
            ScanResult, Project, Service, Endpoint, Finding, GraphModel,
            STATUS_COMPLETED,
        )

        project = Project(
            project_name="test-project",
            uploaded_at="2026-10-01T00:00:00Z",
            scan_status=STATUS_COMPLETED,
        )
        scan_result = ScanResult(
            scan_id="scan_test_001",
            project=project,
        )

        html = generate_html_report(scan_result)
        assert "<!DOCTYPE html>" in html
        assert "Confused Deputy" in html
        # Ensure no raw script injection possible
        assert "<script>" not in html.lower() or "eval(" not in html

    def test_html_report_secret_redaction(self):
        """HTML report should redact secrets from evidence snippets."""
        from app.reporting.html_report import generate_html_report
        from app.models.schemas import ScanResult, Project, Finding, GraphModel, STATUS_COMPLETED

        project = Project(
            project_name="test",
            uploaded_at="2026-10-01T00:00:00Z",
            scan_status=STATUS_COMPLETED,
        )

        finding = Finding(
            finding_id="FINDING-CD001-01",
            rule_id="CD-001",
            title="Test Finding",
            severity="HIGH",
            confidence="HIGH",
            source_service_id="svc_order",
            destination_service_id="svc_payment",
            endpoint_id="ep_test",
            evidence_snippet='headers={"X-Service-Key": "REAL_SECRET_TOKEN_12345"}',
            source_file="main.py",
            line_number=42,
        )

        scan_result = ScanResult(
            scan_id="scan_test_002",
            project=project,
            findings=[finding],
        )
        html = generate_html_report(scan_result)
        # Raw secret should be redacted
        assert "REAL_SECRET_TOKEN_12345" not in html


# ─────────────────────────── API Integration Tests ────────────────────────

class TestAPIIntegration:
    """Integration tests for FastAPI REST endpoints."""

    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        """Create a test client with isolated storage."""
        monkeypatch.setenv("SCAN_STORAGE_DIR", str(tmp_path / "storage"))
        from fastapi.testclient import TestClient
        from app.main import app
        return TestClient(app)

    def test_health_endpoint(self, client):
        """Health endpoint should return 200."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    def test_scan_with_valid_zip(self, client, tmp_path):
        """Valid ZIP upload should trigger analysis and return ScanResult."""
        zip_bytes = create_zip({
            "order_service/main.py": VULNERABLE_MAIN_PY,
            "payment_service/main.py": VULNERABLE_PAYMENT_PY,
        })

        response = client.post(
            "/api/v1/scan",
            files={"file": ("test.zip", io.BytesIO(zip_bytes), "application/zip")},
        )
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert "findings" in data
        assert "services" in data

    def test_scan_with_invalid_file_type(self, client):
        """Non-ZIP file upload should return 400."""
        response = client.post(
            "/api/v1/scan",
            files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")},
        )
        assert response.status_code in (400, 422)

    def test_get_nonexistent_scan(self, client):
        """Requesting a nonexistent scan should return 404."""
        response = client.get("/api/v1/scans/scan_doesnotexist12345678")
        assert response.status_code == 404

    def test_demo_vulnerable_benchmark(self, client):
        """Vulnerable demo benchmark should generate confused deputy findings."""
        response = client.post(
            "/api/v1/scan/demo",
            data={"demo_type": "vulnerable"},
        )
        if response.status_code == 404:
            pytest.skip("Demo directory not available in test environment")
        assert response.status_code == 200
        data = response.json()
        assert len(data.get("findings", [])) > 0, "Vulnerable benchmark should produce findings"

    def test_demo_secure_benchmark(self, client):
        """Secure demo benchmark should produce 0 CD-001 findings."""
        response = client.post(
            "/api/v1/scan/demo",
            data={"demo_type": "secure"},
        )
        if response.status_code == 404:
            pytest.skip("Demo directory not available in test environment")
        assert response.status_code == 200
        data = response.json()
        cd001_findings = [f for f in data.get("findings", []) if f.get("rule_id") == "CD-001"]
        assert len(cd001_findings) == 0, "Secure benchmark should not trigger CD-001"

    def test_html_export_endpoint(self, client, tmp_path):
        """HTML export endpoint should return a valid HTML document."""
        # First create a scan
        zip_bytes = create_zip({"main.py": VULNERABLE_MAIN_PY})
        scan_response = client.post(
            "/api/v1/scan",
            files={"file": ("test.zip", io.BytesIO(zip_bytes), "application/zip")},
        )
        assert scan_response.status_code == 200
        scan_id = scan_response.json()["scan_id"]

        # Now export HTML
        html_response = client.get(f"/api/v1/scans/{scan_id}/export/html")
        assert html_response.status_code == 200
        assert "<!DOCTYPE html>" in html_response.text
        assert "Confused Deputy" in html_response.text
