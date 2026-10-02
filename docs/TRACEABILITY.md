# Requirements Traceability Matrix
## Confused Deputy API Detector for Microservices

---

## 1. Traceability Matrix Table

| Requirement ID & Title | Architecture Component | Data Schema | Logic Rule / Engine | API Endpoint | UI Component | Automated Test |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **FR-001** Safe Archive Ingestion | Project Ingestion (`unpacker.py`) | `Project` schema | Archive Sanitizer & ZipBomb Check | `POST /api/v1/scan` | `UploadPanel` | `test_ingestion_valid_zip()` |
| **FR-002** Service Discovery | Service Discovery (`service_discovery.py`) | `Service` schema | AST Directory & FastAPI App Parser | `POST /api/v1/scan` | `ServiceNode` | `test_service_discovery()` |
| **FR-003** Endpoint Discovery | API Discovery (`api_discovery.py`) | `Endpoint` schema | Route Decorator Visitor (`@app.get`) | `GET /api/v1/scans/{id}` | `FindingTable` | `test_endpoint_extraction()` |
| **FR-004** Service-Call Discovery | Source Analyzer (`ast_visitor.py`) | `ServiceCall` schema | HTTP Client Call Visitor (`httpx`) | `GET /api/v1/scans/{id}` | `RiskEdge` | `test_http_client_call_visitor()` |
| **FR-005** Auth Control Analysis | Auth Analyzer (`auth_analyzer.py`) | `Endpoint.authorization_checks` | `Depends()` Guard Parser | `GET /api/v1/scans/{id}` | `FindingDetails` | `test_auth_dependency_parsing()` |
| **FR-006** Identity Tracing | Auth Analyzer (`auth_analyzer.py`) | `ServiceCall.identity_propagation` | Dict Literal Header Tracing | `GET /api/v1/scans/{id}` | `FindingDetails` | `test_identity_header_tracing()` |
| **FR-007** Privilege Inferencing | Privilege Analyzer (`auth_analyzer.py`) | `Service.privilege_level` | Privilege Hierarchy Scorer | `GET /api/v1/scans/{id}` | `ServiceNode` | `test_privilege_level_scoring()` |
| **FR-008** Call Graph Builder | Call Graph Engine (`call_graph.py`) | `GraphModel` schema | NetworkX Directed Graph Builder | `GET /api/v1/scans/{id}` | `ArchitectureGraph` | `test_networkx_graph_builder()` |
| **FR-009** Detection Engine | Detection Engine (`detection_engine.py`) | `Finding` schema | Rules CD-001 to CD-004 | `GET /api/v1/scans/{id}` | `FindingTable` | `test_cd001_to_cd004_rules()` |
| **FR-010** Risk & Confidence | Risk Engine (`risk_engine.py`) | `Finding.severity` & `.confidence` | Severity Matrix & Confidence Scorer | `GET /api/v1/scans/{id}` | `SeverityBadge` | `test_severity_confidence_scoring()` |
| **FR-011** Interactive UI | React Dashboard (`frontend/src`) | `ScanResult` payload | REST JSON Serialization | All API Endpoints | `ArchitectureGraph` | `test_frontend_api_integration()` |
| **FR-012** Code Evidence Viewer | Finding Engine (`finding_engine.py`) | `Finding.evidence_snippet` | AST Line Extractor & Redactor | `GET /api/v1/scans/{id}` | `CodeEvidenceViewer` | `test_code_evidence_redaction()` |
| **FR-013** Report Export | Reporting Engine (`html_report.py`) | `ScanResult` JSON / HTML | Jinja2 HTML Exporter | `GET /scans/{id}/export/html` | `ReportPanel` | `test_html_report_export()` |
| **FR-014** Demo Benchmarks | Benchmark Suite (`demo/`) | Benchmark ZIP payloads | End-to-End Pipeline Evaluation | `POST /scan?demo=vulnerable` | Quick Demo Buttons | `test_benchmark_vulnerable_secure()` |
