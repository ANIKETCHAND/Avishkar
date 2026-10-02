# Architecture Decision Records (ADR)
## Confused Deputy API Detector for Microservices

---

## ADR-001: Backend Language Selection — Python 3.11+
- **Status:** Approved
- **Context:** The system requires rapid development of AST code parsing, graph manipulation, and API server functionality during a hackathon timeline.
- **Alternatives Considered:** Node.js (TypeScript), Go, Rust.
- **Chosen Option:** Python 3.11+.
- **Reason:** Python features native standard library AST parsing (`ast` module) and the standard library graph library (`NetworkX`).
- **Trade-offs:** Python execution is slower than Go/Rust, but execution speed for small microservices repos (<50,000 LOC) completes in under 15 seconds, making development velocity the higher priority.

---

## ADR-002: Web Framework — FastAPI
- **Status:** Approved
- **Context:** Need an async REST API framework that generates OpenAPI documentation and validates data payloads cleanly.
- **Alternatives Considered:** Flask, Django REST Framework, Express.js.
- **Chosen Option:** FastAPI (with Pydantic v2).
- **Reason:** Automatic Swagger UI (`/docs`) generation, high performance async I/O, native Pydantic integration matching frontend TypeScript interfaces.
- **Trade-offs:** Requires ASGI server (Uvicorn).

---

## ADR-003: Static Parsing Infrastructure — Python `ast` Standard Library
- **Status:** Approved
- **Context:** The analyzer must parse Python FastAPI code to discover routes, dependency guards, and client HTTP calls without executing uploaded source code.
- **Alternatives Considered:** Tree-sitter, LibCST, Dynamic Code Importing (`importlib`).
- **Chosen Option:** Built-in Python `ast` module.
- **Reason:** Zero compiled C dependencies, zero external library vulnerabilities, 100% safe execution in isolated CPU memory, standard AST node visitor patterns.
- **Trade-offs:** `ast` discards formatting comments. Loss of comments is irrelevant for AST structural security checks.

---

## ADR-004: Graph Engine — NetworkX
- **Status:** Approved
- **Context:** The tool must construct and traverse directed graphs of services and endpoints to evaluate privilege boundaries and request paths.
- **Alternatives Considered:** Neo4j, igraph, Custom Graph Dictionary.
- **Chosen Option:** NetworkX (`nx.DiGraph`).
- **Reason:** Pure Python, zero external database container required, native graph traversal algorithms, direct serialization to JSON.
- **Trade-offs:** In-memory graph library. Adequate for microservice topologies up to 1,000 nodes.

---

## ADR-005: Frontend Visualization — React Flow (`@xyflow/react`)
- **Status:** Approved
- **Context:** Need an interactive UI canvas to render custom microservice nodes, directed API edges, and animated risk indicators.
- **Alternatives Considered:** D3.js, Cytoscape.js, Vis.js.
- **Chosen Option:** React Flow (`@xyflow/react`).
- **Reason:** Native React component lifecycle integration, clean styling with Tailwind CSS, custom node/edge renderer support.
- **Trade-offs:** Requires layout helper for automatic node positioning.

---

## ADR-006: Analysis Paradigm — Static Analysis First (Zero Code Execution)
- **Status:** Approved
- **Context:** Ingesting user-submitted repository archives presents arbitrary code execution security risks.
- **Alternatives Considered:** Dynamic sandbox execution, Docker container instantiation, dynamic API fuzzing.
- **Chosen Option:** 100% Static Code Analysis.
- **Reason:** Absolute security against malicious code execution during analysis; instant scan start time without waiting for container boot.
- **Trade-offs:** Cannot evaluate dynamic runtime-constructed URLs or database-driven auth policies. Documented clearly in confidence scoring and limitations.

---

## ADR-007: Persistence Layer — JSON File Storage Engine for MVP
- **Status:** Approved
- **Context:** Need to store scan results and graph artifacts for UI rendering and HTML report export.
- **Alternatives Considered:** PostgreSQL, SQLite, MongoDB.
- **Chosen Option:** File-based JSON artifact storage (`storage/scans/{scan_id}.json`).
- **Reason:** Scans are stateless analysis jobs. Eliminates database daemon configuration, Alembic migrations, and ORM boilerplate during hackathon.
- **Trade-offs:** Not suitable for multi-tenant cross-scan querying across millions of historical records. Can be upgraded to PostgreSQL post-MVP via `ScanRepository` interface.

---

## ADR-008: Rule Engine — Deterministic Pattern Rules vs ML/LLM Detection
- **Status:** Approved
- **Context:** Need a reliable engine to flag security findings.
- **Alternatives Considered:** LLM Prompting (GPT-4 / Gemini API for vulnerability classification), Fine-tuned ML Model.
- **Chosen Option:** Deterministic Rule Engine (CD-001 through CD-004).
- **Reason:** 100% deterministic, repeatable results; zero API costs; zero latency delay; zero hallucination risk; instant offline execution.
- **Trade-offs:** Relies on explicitly authored rule heuristics.

---

## ADR-009: Risk Metric — Decoupled Severity and Confidence Models
- **Status:** Approved
- **Context:** Static analysis often conflates potential flaw impact with evidence certainty, causing developer distrust.
- **Alternatives Considered:** Combined single numerical score (e.g., CVSS 1-10).
- **Chosen Option:** Explicitly separate **Severity** (LOW, MEDIUM, HIGH, CRITICAL) from **Confidence** (LOW, MEDIUM, HIGH).
- **Reason:** A potential privilege escalation in a financial refund handler is CRITICAL severity. However, if the target URL string was constructed dynamically via variable concatenation, static evidence certainty is MEDIUM confidence. Decoupling allows developers to filter high-confidence findings first.
- **Trade-offs:** Requires rendering two status badges per finding in the UI.
