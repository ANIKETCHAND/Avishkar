# Project Development Roadmap
## Confused Deputy API Detector for Microservices

---

## 1. Overview & Phase Structure

The roadmap outlines the execution plan from initial architecture design through hackathon demonstration across 17 structured phases (Phases 0 through 16).

---

## 2. Detailed Phase Specifications

### Phase 0: Technical Planning & Architecture Blueprint
- **Objective:** Establish comprehensive technical design foundation before implementation.
- **Tasks:** Author PRD, Tech Stack, Architecture, Data Schema, UI Design, Detection Logic, Roadmap, Traceability Matrix, Architecture Decision Records, and Out-of-Scope boundaries.
- **Dependencies:** None.
- **Deliverables:** `docs/` folder containing 10 markdown specification documents.
- **Acceptance Criteria:** All 10 documents written, cross-referenced, and audited for technical consistency.
- **Definition of Done:** Planning audit approved.

### Phase 1: Benchmark Demo Microservices Suite
- **Objective:** Create synthetic vulnerable and secure Python/FastAPI microservice projects to test detection logic deterministically.
- **Tasks:** Implement `demo/vulnerable` (Order Svc + Payment Svc with confused deputy flow) and `demo/secure` (with identity propagation and ownership validation).
- **Dependencies:** Phase 0.
- **Deliverables:** `demo/vulnerable/` and `demo/secure/` source code trees.
- **Acceptance Criteria:** Both demo apps pass Python syntax compilation.
- **Definition of Done:** Benchmark microservices ready for static AST parsing.

### Phase 2: Project Ingestion & Safe Unpacker Module
- **Objective:** Build secure file upload, archive validation, and extraction pipeline.
- **Tasks:** Implement `app/ingestion/unpacker.py` with ZipBomb limits, symlink filtering, path traversal stripping, and temp workspace management.
- **Dependencies:** Phase 0.
- **Deliverables:** Python ingestion module and unit tests.
- **Acceptance Criteria:** Successfully extracts valid ZIP archives while rejecting malicious or oversized archives.
- **Definition of Done:** `pytest backend/tests/test_ingestion.py` passes 100%.

### Phase 3: AST Source Code Analyzer Core
- **Objective:** Develop Python standard library AST parsing infrastructure.
- **Tasks:** Implement `ast.NodeVisitor` subclasses in `app/analyzer/ast_visitor.py` to parse Python source code into structured AST nodes.
- **Dependencies:** Phase 2.
- **Deliverables:** AST visitor class hierarchy.
- **Acceptance Criteria:** Parses Python functions, decorators, imports, and client call expressions cleanly.
- **Definition of Done:** AST visitor extracts route functions and outgoing HTTP call nodes.

### Phase 4: Service Discovery Engine
- **Objective:** Group parsed Python files into distinct microservice entities.
- **Tasks:** Implement `app/analyzer/service_discovery.py` to inspect directory hierarchies and `FastAPI()` instantiation points.
- **Dependencies:** Phase 3.
- **Deliverables:** `Service` object list generation logic.
- **Acceptance Criteria:** Correctly groups `demo/vulnerable` into `order-service` and `payment-service`.
- **Definition of Done:** Service boundaries mapped automatically from source repositories.

### Phase 5: API Endpoint & Handler Discovery Engine
- **Objective:** Extract all HTTP routes, handlers, methods, and line ranges exported by microservices.
- **Tasks:** Implement `app/analyzer/api_discovery.py` to map `@app.get/post/delete` decorators and identify sensitive operations.
- **Dependencies:** Phase 4.
- **Deliverables:** `Endpoint` object catalog.
- **Acceptance Criteria:** Extracts routes like `/api/v1/orders/{id}/cancel` and flags HTTP `DELETE` or `refund` as sensitive.
- **Definition of Done:** Endpoint catalog populated accurately.

### Phase 6: Inter-Service Call Graph Builder
- **Objective:** Synthesize NetworkX directed call graph from discovered services and outgoing HTTP calls.
- **Tasks:** Implement `app/graph/call_graph.py` using NetworkX `nx.DiGraph`.
- **Dependencies:** Phase 5.
- **Deliverables:** Graph builder module with node/edge serialization.
- **Acceptance Criteria:** Directed edges connect caller service endpoints to target service routes.
- **Definition of Done:** `call_graph.to_json()` outputs valid React Flow compatible payload.

### Phase 7: Authorization & Identity Propagation Analyzer
- **Objective:** Analyze authentication dependencies and identity header propagation in outgoing HTTP calls.
- **Tasks:** Implement `app/analyzer/auth_analyzer.py` to check `Depends()` guards and header dictionaries (`Authorization`, `X-Service-Token`).
- **Dependencies:** Phase 6.
- **Deliverables:** Authorization observations and identity propagation classification.
- **Acceptance Criteria:** Distinguishes forwarded user JWTs from hardcoded service keys.
- **Definition of Done:** Call graph edges annotated with identity propagation flags.

### Phase 8: Confused Deputy Detection Engine
- **Objective:** Implement deterministic detection rules CD-001 through CD-004.
- **Tasks:** Write `app/rules/cd_001.py` through `app/rules/cd_004.py` rule evaluators.
- **Dependencies:** Phase 7.
- **Deliverables:** Detection Engine executing all 4 rules against the NetworkX call graph.
- **Acceptance Criteria:** Identifies confused deputy flow in `demo/vulnerable` and yields 0 findings in `demo/secure`.
- **Definition of Done:** Benchmark rule tests pass 100%.

### Phase 9: Risk & Confidence Scoring Engine
- **Objective:** Calculate Severity (LOW..CRITICAL) and Confidence (LOW..HIGH) independently for findings.
- **Tasks:** Implement `app/engine/risk_engine.py` applying the severity matrix and confidence criteria.
- **Dependencies:** Phase 8.
- **Deliverables:** Finding object builder with severity/confidence justification text.
- **Acceptance Criteria:** Every finding includes explicit severity and confidence scores.
- **Definition of Done:** Structured findings generated cleanly.

### Phase 10: FastAPI Backend REST API Layer
- **Objective:** Expose analysis pipeline via async REST endpoints.
- **Tasks:** Implement `app/api/endpoints.py` with `POST /scan` and `GET /scan/{id}`.
- **Dependencies:** Phase 9.
- **Deliverables:** Complete FastAPI backend service.
- **Acceptance Criteria:** Swagger UI (`/docs`) allows end-to-end execution via REST API.
- **Definition of Done:** Uvicorn server runs and processes scan requests.

### Phase 11: React Dashboard UI & Layout
- **Objective:** Build modern dark-themed React frontend shell.
- **Tasks:** Create React + TypeScript project with Tailwind CSS styling, upload panel, summary metric cards, and navigation tabs.
- **Dependencies:** Phase 10.
- **Deliverables:** Frontend application rendering in browser.
- **Acceptance Criteria:** Drag-and-drop upload interface connects to backend REST API.
- **Definition of Done:** Frontend communicates seamlessly with FastAPI.

### Phase 12: React Flow Topology Visualization
- **Objective:** Render interactive cross-service call graph canvas.
- **Tasks:** Implement `ArchitectureGraph.tsx` using `@xyflow/react` with custom `ServiceNode` and `RiskEdge` components.
- **Dependencies:** Phase 11.
- **Deliverables:** Interactive visual call graph canvas.
- **Acceptance Criteria:** Risk edges display highlighted red animation; node clicks show endpoint details.
- **Definition of Done:** Graph canvas enables fluid zoom, pan, and node inspection.

### Phase 13: Finding Details & Report Generator
- **Objective:** Implement side-by-side code evidence viewer and HTML/JSON export engine.
- **Tasks:** Implement `FindingDetails.tsx`, `CodeEvidenceViewer.tsx`, and backend Jinja2 HTML report generator (`app/reporting/html_report.py`).
- **Dependencies:** Phase 12.
- **Deliverables:** Code evidence viewer and downloadable HTML reports.
- **Acceptance Criteria:** Highlights source code lines with secret redaction; HTML report downloads on button click.
- **Definition of Done:** Complete report export functionality verified.

### Phase 14: Automated Benchmark Verification & Unit Testing
- **Objective:** Verify analysis accuracy across test suites.
- **Tasks:** Execute complete Pytest test suite covering ingestion, AST parsing, graph building, rule execution, and API endpoints.
- **Dependencies:** Phase 13.
- **Deliverables:** Pytest test suite with code coverage report.
- **Acceptance Criteria:** >85% code coverage across backend modules; 100% pass rate on benchmark tests.
- **Definition of Done:** `pytest` runs green.

### Phase 15: Security Hardening & Secret Scrubbing Audit
- **Objective:** Audit system for static isolation, input sanitization, and secret redaction.
- **Tasks:** Enforce path canonicalization, XSS sanitization in React, regex secret redaction in AST evidence, and non-root Docker user configs.
- **Dependencies:** Phase 14.
- **Deliverables:** Hardened production/demo build.
- **Acceptance Criteria:** Zero raw credentials rendered in UI or JSON outputs.
- **Definition of Done:** Security review complete.

### Phase 16: Hackathon Demonstration Preparation
- **Objective:** Package project for live hackathon demonstration.
- **Tasks:** Configure `docker-compose.up`, create demo recording/screenshots, write quickstart `README.md`.
- **Dependencies:** Phase 15.
- **Deliverables:** One-command launcher (`docker-compose up`) and demo presentation materials.
- **Acceptance Criteria:** Complete system launches in <60 seconds via Docker.
- **Definition of Done:** Project ready for hackathon evaluation.
