# Static Analysis Engine Accuracy & Architecture Audit
## Confused Deputy API Detector for Microservices

**Audit Date:** 2026-10-03  
**Auditor:** Senior Application Security & SAST Architect  
**Repository:** [ANIKETCHAND/Avishkar](https://github.com/ANIKETCHAND/Avishkar)  
**Document Status:** Complete (Phase 0 Audit)

---

## 1. Executive Summary

This audit assesses the detection capabilities, intermediate representation, data-flow tracking, rule precision, and architectural limitations of the static analyzer in `backend/app/`. 

The current system has established foundational AST parsing, NetworkX call-graph construction, secret redaction, and multi-service discovery. However, rigorous security analysis reveals several areas where heuristic name-matching, intra-function limitations, coarse endpoint matching, and lack of explicit intermediate representation (IR) introduce risks of false positives, false negatives, or heuristic false certainty.

---

## 2. Current Detection Architecture

The existing analysis pipeline follows an 8-stage linear sequence:
```
ZIP Archive / Directory
        │
        ▼ (ingestion/unpacker.py)
Safe Extraction & Path Validation
        │
        ▼ (analyzer/ast_visitor.py)
AST Parsing & FastAPIVisitor
        │
        ▼ (analyzer/service_discovery.py)
Directory & File-based Service Discovery
        │
        ▼ (analyzer/api_discovery.py)
Route Extraction & Outgoing HTTP Client Call Mapping
        │
        ▼ (analyzer/auth_analyzer.py)
Privilege Boundary & Identity Classification
        │
        ▼ (graph/call_graph.py)
NetworkX DiGraph Construction
        │
        ▼ (rules/detection_engine.py)
Rule Evaluation (CD-001 through CD-004)
        │
        ▼ (engine/risk_engine.py)
ScanResult Assembly, HTML/JSON Reporting
```

---

## 3. Detailed Component Audit

### 3.1 AST Visitor (`backend/app/analyzer/ast_visitor.py`)
- **Current Strengths:**
  - Standard library `ast.NodeVisitor` guarantees zero code execution.
  - Basic tracking of `FastAPI` and `APIRouter` variable instances and prefixes.
  - Secret redaction for Bearer tokens, JWTs, and API keys.
  - Intra-function data-flow dictionary tracking for header literals and `{**base_headers}` unpacking.
- **Weaknesses & Risks:**
  - **Single-function Scope (Intra-procedural only):** Values flowing through helper functions (e.g. `def get_headers(): return {"Authorization": token}`) cannot be tracked across procedural boundaries.
  - **Name-heuristic Overreliance:** Dependency extraction checks whether parameter default contains `Depends(func)` and tests function names against `AUTH_DEP_KEYWORDS` (`"auth"`, `"user"`, `"token"`). A function named `get_user_profile()` is assumed to authenticate a user even if it only fetches static public data.
  - **Lack of True Intermediate Representation (IR):** Extracted facts are stored directly in dataclasses (`RouteDefinition`, `HttpCallDefinition`) without preserving full symbol definitions, scope trees, or typed provenance models.

### 3.2 Service Discovery (`backend/app/analyzer/service_discovery.py`)
- **Current Strengths:**
  - Detects entry points (`main.py`, `app.py`) and clusters files by directory boundaries.
  - Basic subdirectory splitting for multi-service repositories.
- **Weaknesses & Risks:**
  - **Directory-Centric Heuristics:** If services are laid out by layer (e.g., `controllers/`, `services/`, `models/`) rather than per-service folders, the analyzer risks treating layer directories as distinct services.
  - **Docker Compose Ignored:** Does not parse `docker-compose.yml` or container definitions where service names, exposed ports, and network aliases are explicitly declared.
  - **Binary Privilege Inference:** Infers `PRIVILEGE_SERVICE` if any parameter has `"service_token"`. Does not track fine-grained privilege capabilities.

### 3.3 Endpoint Matching & URL Resolution (`backend/app/analyzer/api_discovery.py`)
- **Current Strengths:**
  - Resolves static string URLs, constant references (`PAYMENT_URL + "/refund"`), and simple f-strings.
  - Matches target services based on service names and path substrings.
- **Weaknesses & Risks:**
  - **Coarse Target Endpoint Matching:** When a caller issues `client.post("http://payment-service/refund")`, the engine resolves the target *service* (`payment_service`), but in some rule evaluations, it inspects *all* sensitive endpoints of the target service rather than strictly validating only the specific route (`/refund`) called.
  - **Path Parameter Incompatibility:** Does not normalize template routes (e.g. matching `POST /orders/{id}/refund` against `POST /orders/123/refund`).

### 3.4 Authentication & Authorization Separation (`backend/app/analyzer/auth_analyzer.py`)
- **Current Strengths:**
  - Identifies privilege escalation (`USER -> SERVICE`, `USER -> ADMIN`).
  - Classifies identity propagation into 4 categories (`FORWARDED_USER_JWT`, `SERVICE_TOKEN`, `STRIPPED`, `UNKNOWN`).
- **Weaknesses & Risks:**
  - **Conflation of AuthN and AuthZ:** An endpoint having `Depends(verify_token)` is treated as both authenticated and authorized. The engine fails to distinguish *who the caller is* (Authentication) from *whether the caller owns the resource* (Authorization / BOLA guard).
  - **Missing Authorization Types:** Does not categorize authorization checks into `USER_OWNERSHIP`, `ROLE_CHECK`, `PERMISSION_CHECK`, `TENANT_ISOLATION`, or `SERVICE_ONLY`.

### 3.5 Rule Engine (`backend/app/rules/detection_engine.py`)
- **CD-001 (Privilege-Boundary Confused Deputy):**
  - *Risk:* Incomplete resolution if a downstream service handles both public and sensitive routes; if route matching defaults to any sensitive route, false positives can occur.
- **CD-002 (Unauthenticated Internal Route):**
  - *Risk:* Routes using custom middleware or ASGI handlers are marked as unauthenticated rather than `AUTHENTICATION_UNKNOWN`, creating false certainty.
- **CD-003 (Unverified Identity Header Injection):**
  - *Risk:* Relies on header key strings (`X-User-Id`) rather than tracking whether the value originates from untrusted client input vs a verified cryptographic JWT claim.
- **CD-004 (Gateway-Only Security Policy):**
  - *Risk:* Emits findings if downstream lacks explicit function names with `"auth"`, ignoring internal network policies or token checks passed through dependencies.

---

## 4. Ambiguous Cases & False Positive/Negative Risks

| Category | Vulnerable / Ambiguous Scenario | False Finding Risk | Desired Engine Behavior |
| :--- | :--- | :--- | :--- |
| **Helper AuthZ** | `if not check_access(user, order): raise 403` | False Positive (FN of authz) if `check_access` is in another helper | Track helper call AST, inspect return value / 403 raise; if unresolvable, mark `AUTHORIZATION_UNKNOWN` with lowered confidence. |
| **Adversarial Names** | `def verify_owner(): pass` (empty mock) | False Negative (bypasses detection) | Inspect function body for actual comparison or rejection statements; do not trust name alone. |
| **Read-Only Refund** | `GET /refund-policy` called with service token | False Positive (CD-001) | Read-only HTTP methods (`GET`, `HEAD`, `OPTIONS`) must never be flagged as sensitive state mutations. |
| **Path Normalization** | `POST http://payment:8000/api/v1/refund/` | False Negative (Target service or route mismatch) | Normalize trailing slashes, strip query strings, and strip standard API prefixes. |
| **Unverified Header** | `headers['X-User-Id'] = jwt.decode(...)['sub']` | False Positive (CD-003) | Provenance tracking recognizes identity source was a verified JWT claim, not raw request header. |

---

## 5. Files Requiring Modification & Extension

1. `backend/app/models/schemas.py` & `backend/app/models/ir.py`:
   - Introduce rich semantic IR: `SourceLocation`, `Symbol`, `FunctionModel`, `RouteSecurityModel`, `DataFlowFact`, `IdentityProvenance`, `SecurityControlEvidence`.
   - Add explicit `UNKNOWN` states for auth, authz, privilege, and target matching.
   - Add `ANALYSIS_ENGINE_VERSION = "2.0.0"` to `ScanResult` and `Project`.
2. `backend/app/analyzer/ast_visitor.py`:
   - Upgrade visitor with AST symbol table, inter-function call resolution, and semantic comparison analysis.
   - Remove hardcoded keyword reliance; use AST pattern matching (status codes, comparisons, exceptions).
3. `backend/app/analyzer/service_discovery.py`:
   - Incorporate Docker Compose parsing, package manifests, and multi-signal privilege inference.
4. `backend/app/analyzer/api_discovery.py`:
   - Implement route parameter normalization (`/orders/{id}` $\leftrightarrow$ `/orders/123`), host normalization, and strict caller-to-callee endpoint matching.
5. `backend/app/analyzer/auth_analyzer.py`:
   - Formal provenance tracking (`USER_AUTHENTICATED`, `USER_JWT_VERIFIED`, `SERVICE_CREDENTIAL`, `UNVERIFIED_USER_HEADER`, `DERIVED_IDENTITY`, `UNKNOWN`).
   - Strict separation of `AuthenticationState` vs `AuthorizationState`.
6. `backend/app/rules/detection_engine.py`:
   - Rebuild CD-001 through CD-004 to enforce multi-condition evidence, target endpoint exactness, negative security controls, and calibrated confidence.
7. `backend/app/graph/call_graph.py`:
   - Extend graph to path-sensitive representation: `User Entry -> Source Endpoint -> Service Call -> Target Endpoint -> Sensitive Mutation`.
8. `backend/tests/`:
   - Create massive benchmark corpus (`tests/accuracy/`, `demo/accuracy_benchmarks/`), property tests, mutation tests, and automated confusion matrix evaluator.

---

## 6. Audit Conclusion & Roadmap

The static analyzer architecture is sound, but its reasoning must transition from heuristic string matching to **formal semantic intermediate representations, bounded interprocedural data-flow tracking, and exact endpoint route matching**. 

The subsequent phases will implement this without breaking existing APIs, Pydantic schemas, or the React dashboard.
