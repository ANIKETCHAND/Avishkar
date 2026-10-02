# Product Requirements Document
## Confused Deputy API Detector for Microservices

---

## 1. Executive Summary

### 1.1 Product Overview
The **Confused Deputy API Detector for Microservices** is a specialized static security analyzer designed to identify microservices authorization flow vulnerabilities—specifically confused-deputy authorization flaws—in Python (FastAPI) multi-service codebases. 

In a distributed microservices architecture, downstream services often execute with elevated service-level privileges (e.g., direct DB access or administrative service tokens). When an upstream entry service forwards user requests to a privileged downstream service without verifying that the originating user possesses permission for the specific target action or resource, the privileged service acts as a "confused deputy." 

This tool ingests a packaged microservices repository, extracts service definitions, endpoint topologies, intra-service HTTP client calls, and authorization guard logic via static Python AST (Abstract Syntax Tree) parsing, constructs an enriched cross-service call graph, and evaluates deterministic detection rules to pinpoint potential privilege boundary bypasses with evidence-backed findings.

### 1.2 Problem Solved
Traditional Static Application Security Testing (SAST) tools analyze isolated single-repository code files for localized flaws (e.g., SQL injection, hardcoded secrets), while Dynamic Application Security Testing (DAST) tools treat endpoints as black boxes without cross-service context. Neither natively maps distributed authorization contexts or cross-service identity propagation across service boundaries. Our tool fills this gap by evaluating inter-service trust dynamics and privilege elevation risks statically without requiring application execution or deployment.

### 1.3 Target Audience
- **Application Security Engineers:** Seeking to audit microservice architectures for cross-service authorization flaws during security reviews.
- **Backend Developers & Architects:** Designing multi-service FastAPI systems who need rapid feedback on service boundary privilege risks.
- **DevSecOps Engineers:** Integrating static architecture audit checkpoints into CI/CD pipelines.
- **Security Researchers:** Analyzing microservices authorization patterns and attack surfaces.

### 1.4 Business & Security Impact
- Prevents cross-service privilege escalation vulnerabilities prior to production deployment.
- Dramatically reduces manual architectural threat-modeling and code-review effort.
- Provides visual and code-backed evidence to bridge communication gaps between security teams and developers.

### 1.5 MVP Demonstration Scope
The Minimum Viable Product (MVP) will ingest a ZIP archive containing multiple Python/FastAPI microservices (including intentional vulnerable and secure demo projects), statically extract cross-service call topologies, analyze JWT/header identity propagation and authorization dependencies, run four core Confused Deputy detection rules, display an interactive service call graph using React Flow, render evidence-backed findings with severity/confidence scoring, and export machine/human readable audit reports (JSON/HTML).

---

## 2. Problem Statement

### 2.1 The Confused Deputy in Microservices
A confused deputy flaw occurs when a computer program (the deputy) is tricked by a less-privileged entity into abusing its authority to perform an unauthorized action on behalf of that entity. In microservice architectures, services often use service-to-service authentication (such as mutual TLS, shared API keys, or service account JWTs) to trust incoming HTTP requests from peer services.

### 2.2 Concrete Example Flow

```
User (Role: Basic User, ID: 1042)
  │
  │ HTTP POST /orders/1042/cancel (User JWT included)
  ▼
[Order Service] (Privilege: USER Level)
  │  • Validates User JWT for /orders/1042/cancel
  │  • Makes internal HTTP call to Payment Service:
  │    POST http://payment-service/api/v1/refund
  │    Headers: { "X-Service-Token": "ORDER_SVC_SECRET_KEY", "user_id": "1042" }
  ▼
[Payment Service] (Privilege: ELEVATED / DB Direct Access)
  │  • Validates X-Service-Token ("Order Service is allowed to call refund")
  │  • DOES NOT verify whether User 1042 actually owns the payment transaction
  │  • Executes financial refund in Database
  ▼
Financial Refund Processed (Unauthorized Access / Escalation)
```

**Why this is a Confused Deputy vulnerability:**
1. **Order Service** acted as a deputy on behalf of User 1042.
2. **Payment Service** trusted **Order Service**'s high-privilege service credential (`X-Service-Token`).
3. **Payment Service** failed to enforce end-to-end authorization (resource-level ownership check or delegative scoping) for User 1042.
4. An attacker with standard user privileges could manipulate inputs to Order Service to trigger unauthorized refunds via Payment Service.

---

## 3. Target Users

| User Persona | Role | Primary Goal | Key Pain Point Solved |
| :--- | :--- | :--- | :--- |
| **AppSec Engineer** | Security Auditor | Verify cross-service privilege boundaries and identity propagation | Lack of tools that visualize and analyze multi-service HTTP call chains |
| **Backend Developer** | Software Engineer | Check if internal HTTP calls introduce unauthorized privilege bypasses | Security requirements are often abstract and hard to trace across services |
| **DevSecOps Engineer** | Pipeline Specialist | Automate architecture-level security gates | Standard SAST fails on cross-repository microservice boundaries |
| **Software Architect** | System Designer | Ensure least-privilege boundaries and identity delegation standards | Hard to enforce consistent authorization rules across independently built services |

---

## 4. Goals and Non-Goals

### 4.1 Core Goals
1. **Discover Microservices Topology:** Parse Python FastAPI source repositories to identify service boundaries, exported HTTP API routes, handlers, and outgoing HTTP client requests (`httpx`, `requests`, `aiohttp`).
2. **Trace Identity & Auth Controls:** Identify authentication middleware/dependencies (`HTTPBearer`, `OAuth2PasswordBearer`, custom header parsers), authorization checks (`Depends(verify_role)`, permission checks), and identity propagation headers across service calls.
3. **Build Cross-Service Call Graph:** Construct a directed graph representing service nodes, endpoint routes, client calls, and privilege boundaries.
4. **Detect Confused-Deputy Patterns:** Implement rule engines for privilege boundary jumping, downstream missing authorization, untrusted identity propagation, and gateway-only authorization.
5. **Generate Evidence-Backed Findings:** Produce findings linked directly to source file lines, displaying exact AST evidence, authorization gaps, severity, and confidence levels.
6. **Provide Interactive Visualization & Reporting:** Render interactive network topologies via React Flow and generate machine-readable JSON and styled HTML reports.

### 4.2 Non-Goals (Out of Scope for MVP)
- **No Code Execution:** The analyzer will NOT execute uploaded code, launch dynamic containers, or perform dynamic API fuzzing.
- **No Production Exploitation:** The tool will not generate active attack payloads or attempt exploit generation.
- **No Multi-Language Parsing in MVP:** Languages other than Python (e.g., Java, Go, Node.js) are explicitly deferred.
- **No Service Mesh / Dynamic Runtime Tracing:** Analyzing live eBPF data, Jaeger traces, or Kubernetes Envoy configurations is out of scope.
- **No Guarantees of 100% Exploitability:** Static analysis reports potential vulnerabilities and structural risks; it does not guarantee exploitability.

---

## 5. MVP Features & Workflow

```
[Project Upload (ZIP)]
        │
        ▼
[Safe Archive Extraction & Structure Parsing]
        │
        ▼
[Service & AST Discovery Engine]
  ├── Service Boundary Detection
  ├── Endpoint & Handler Extraction
  └── Outgoing HTTP Call Analysis
        │
        ▼
[Authorization & Privilege Inferencing Engine]
  ├── AuthN/AuthZ Dependency Mapping
  ├── Identity Propagation Header Tracing
  └── Privilege Level Classification
        │
        ▼
[Call Graph Construction (NetworkX)]
        │
        ▼
[Confused Deputy Detection Engine (CD-001..CD-004)]
        │
        ▼
[Risk & Confidence Scoring]
        │
        ▼
[React UI Dashboard & Interactive Visualization]
        │
        ▼
[JSON / HTML Report Generation]
```

---

## 6. User Stories

- **US-01:** As a developer, I want to upload a ZIP file of my Python microservices repository so that the system can analyze the cross-service authorization architecture without executing any code.
- **US-02:** As a security engineer, I want to view a visual graph of service-to-service calls so that I can quickly spot risky privilege boundaries and unauthenticated inter-service links.
- **US-03:** As an auditor, I want each finding to reference specific file paths and line numbers so that I can inspect the exact code snippet responsible for an authorization flaw.
- **US-04:** As a developer, I want actionable remediation guidance for each finding so that I know how to implement proper identity propagation and downstream authorization checks.
- **US-05:** As a DevSecOps engineer, I want to export structured JSON reports so that I can consume scan results programmatically.

---

## 7. Functional Requirements

| Requirement ID | Module | Description | Priority | Acceptance Criteria |
| :--- | :--- | :--- | :--- | :--- |
| **FR-001** | Ingestion | Accept `.zip` uploads up to 50MB containing Python microservice repositories. | P0 (Must Have) | Validates archive integrity, enforces file count/size caps, rejects symlinks, extracts safely to isolated directory. |
| **FR-002** | Service Discovery | Identify distinct microservices based on project directories, main entrypoints (`FastAPI()`), or configuration files. | P0 (Must Have) | Correctly identifies service names and root paths for multi-service repos. |
| **FR-003** | Endpoint Discovery | Extract FastAPI HTTP routes (`@app.get`, `@app.post`, `@router.delete`, etc.), handler names, file locations, and line numbers. | P0 (Must Have) | Captures HTTP method, URL template, handler function name, and source line range. |
| **FR-004** | Call Discovery | Statically parse outgoing HTTP requests (`httpx.get/post`, `requests.post`, `aiohttp`) inside route handlers. | P0 (Must Have) | Identifies target endpoint URL/pattern, HTTP method, headers passed, and calling function location. |
| **FR-005** | Auth Analysis | Detect presence of authentication middleware, FastAPI `Depends()` security schemes, and authorization function checks. | P0 (Must Have) | Flags endpoints as Authenticated, Unauthenticated, or Explicit Role/Permission checked. |
| **FR-006** | Identity Tracing | Track headers passed in outgoing service calls (e.g., `Authorization`, `X-User-Id`, `X-User-Role`, `X-Service-Token`). | P0 (Must Have) | Distinguishes between forwarding incoming user identity vs substituting with hardcoded/service identity. |
| **FR-007** | Privilege Inferences| Assign privilege abstraction levels (PUBLIC, USER, SERVICE, ADMIN) to endpoints and services based on route names, auth checks, and ops. | P1 (Should Have) | Evaluates endpoints and flags privilege jumps between caller service and downstream target. |
| **FR-008** | Call Graph | Build a NetworkX graph with services/endpoints as nodes and calls/privilege transitions as directed edges. | P0 (Must Have) | Graph contains all discovered services, routes, inter-service edges, and annotated attributes. |
| **FR-009** | Detection Rules | Execute rule engine evaluating CD-001 (Privilege Jump), CD-002 (Missing Downstream AuthZ), CD-003 (Untrusted Identity Prop), CD-004 (Gateway Only AuthZ). | P0 (Must Have) | Outputs structured finding objects containing Rule ID, evidence, severity, and confidence for violations. |
| **FR-010** | Risk & Confidence | Calculate Severity (LOW, MEDIUM, HIGH, CRITICAL) and Confidence (LOW, MEDIUM, HIGH) independently based on explicit evidence criteria. | P0 (Must Have) | Every finding includes separate severity and confidence metrics with justification text. |
| **FR-011** | Interactive UI | Render dashboard with summary metrics, React Flow call graph, search/filter controls, and detailed finding viewer. | P0 (Must Have) | Users can click graph nodes/edges to view endpoint details and click findings to view code snippets. |
| **FR-012** | Code Evidence Viewer | Render source code context around findings with line highlighting and redacted secret patterns. | P0 (Must Have) | Code viewer highlights target lines and masks detected authorization token literals. |
| **FR-013** | Report Export | Generate JSON and standalone HTML reports containing complete scan statistics, graph summaries, and finding details. | P1 (Should Have) | One-click download of JSON payload and self-contained styled HTML file. |
| **FR-014** | Demo Benchmarks | Provide built-in `/demo/vulnerable` and `/demo/secure` benchmark test cases for deterministic verification. | P0 (Must Have) | Scanning vulnerable benchmark triggers expected CD findings; scanning secure benchmark passes cleanly. |

---

## 8. Non-Functional Requirements

### 8.1 Security
- **Static Ingestion Isolation:** Uploaded archives extracted into temporary, randomized workspace directories with strict permission masking (`0700`).
- **No Command/Code Execution:** No use of `eval()`, `exec()`, `subprocess` invocation of uploaded code, or dynamic module importing (`importlib`).
- **Secret Redaction:** Regex-based sanitization of secrets/tokens prior to storing evidence or rendering in UI.
- **Input Validation:** Strict Pydantic validation on all REST API path parameters, query parameters, and payload schemas.

### 8.2 Performance
- **Scan Speed:** Complete static analysis of a 10-service FastAPI project (up to 50,000 LOC) in under 15 seconds on a standard dual-core laptop.
- **UI Responsiveness:** Graph visualizer renders topologies of up to 50 nodes and 100 edges smoothly without browser lag (>30 FPS).

### 8.3 Reliability & Determinism
- **Determinism:** Scanning the exact same codebase twice must produce identical findings, severity scores, confidence levels, and graph structures.
- **Graceful Partial Failure:** If AST parsing fails on an invalid Python syntax file, log warning evidence and continue parsing remaining valid files.

### 8.4 Usability & Accessibility
- Dark-mode developer interface with clear semantic color indicators (Red for High/Critical risks, Yellow for Medium/Low or uncertain checks, Green for verified controls, Gray for info).
- Responsive layout supporting standard desktop viewport resolutions (1280x720 and higher).

---

## 9. Security Requirements

1. **Safe Archive Processing:** ZipBomb prevention (max 500 files, max uncompressed size 100MB, max compression ratio 10:1). Path traversal prevention (`../` stripping and canonical path checking). Symlinks and hard links ignored during extraction.
2. **Least Privilege Execution:** Backend process runs under a non-root unprivileged container user.
3. **Safe Frontend Rendering:** Sanitize all source code snippets rendered in HTML/React to prevent Cross-Site Scripting (XSS).
4. **Secret Redaction:** Automatically scrub potential JWT strings, API keys, passwords, and tokens matching `bearer\s+[A-Za-z0-9\-\._~\+\/]+=*` from AST code snippets.

---

## 10. MVP Acceptance Criteria

The project reaches MVP completion when:
1. A multi-service Python/FastAPI project uploaded via `.zip` is safely extracted and processed within 15 seconds without running uploaded files.
2. Service boundaries, FastAPI HTTP routes, and inter-service HTTP client calls are accurately parsed into a structured NetworkX graph.
3. All four core detection rules (CD-001 through CD-004) execute deterministically against the AST model.
4. The React dashboard renders the complete interactive React Flow architecture diagram and interactive findings table.
5. Code evidence viewer displays source file lines with highlight formatting and secret redaction.
6. The analyzer correctly distinguishes between `/demo/vulnerable` (detecting findings) and `/demo/secure` (zero false positives for verified controls).
7. Downloadable JSON and HTML reports are successfully generated.
