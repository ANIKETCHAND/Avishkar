# Confused Deputy Detection Logic & Analysis Specification
## Confused Deputy API Detector for Microservices

---

## 1. Comprehensive 17-Step Static Analysis Pipeline

The analyzer evaluates microservices repositories across 17 sequential steps without executing application source code.

```
[1. Archive Ingestion] ──► [2. File Discovery] ──► [3. Service Discovery]
                                                          │
[6. Service Call Disc] ◄── [5. Endpoint Disc]  ◄── [4. AST Parsing]
         │
         ▼
[7. AuthN Analysis]   ──► [8. AuthZ Analysis]  ──► [9. Identity Prop Analysis]
                                                          │
[12. Graph Construction]◄─[11. Privilege Analysis]◄[10. Sensitive Op Analysis]
         │
         ▼
[13. Path Tracing]    ──► [14. Rule Execution] ──► [15. Severity Engine]
                                                          │
[17. Finding Generation] ◄────────────────────── [16. Confidence Engine]
```

1. **Project Ingestion:** Validate ZIP archive payload, check file counts/sizes, and unpack safely to an isolated temporary workspace directory.
2. **File Discovery:** Scan extracted directory tree for Python source files (`*.py`) and configuration manifests (`pyproject.toml`, `requirements.txt`).
3. **Service Discovery:** Identify distinct microservice root directories based on directory structure or presence of FastAPI application instances (`app = FastAPI()`).
4. **AST Parsing:** Parse each Python file into Abstract Syntax Trees using standard library `ast.parse()`.
5. **Endpoint Discovery:** Traverse AST nodes to discover FastAPI route handlers (`@app.get`, `@app.post`, `@router.delete`, etc.), recording HTTP method, path template, function name, file path, and line numbers.
6. **Service-Call Discovery:** Inspect AST body of route handlers for HTTP client calls (`httpx.Client`, `httpx.AsyncClient`, `requests.post`, `aiohttp`) and extract destination URL string templates and headers.
7. **Authentication Analysis:** Identify authentication guards (`HTTPBearer`, `OAuth2PasswordBearer`, custom auth dependencies) attached to FastAPI routes via `Depends()`.
8. **Authorization Analysis:** Identify explicit permission or ownership verification logic (`verify_user_ownership`, `require_role("admin")`) inside handlers or dependencies.
9. **Identity Propagation Analysis:** Analyze header dictionaries in outgoing HTTP calls to verify whether incoming user tokens/IDs (`Authorization`, `X-User-Id`) are forwarded or replaced with service account tokens (`X-Service-Token`).
10. **Sensitive Operation Analysis:** Flag endpoints performing state-modifying or privileged operations (e.g., HTTP `DELETE`, route templates containing `refund`, `admin`, `password`, `grant`, `role`).
11. **Privilege Analysis:** Assign abstract privilege levels (PUBLIC=0, USER=1, SERVICE=2, ADMIN=3) to services and endpoints based on auth dependencies and route capabilities.
12. **Graph Construction:** Build a NetworkX directed graph (`nx.DiGraph`) where nodes represent services and endpoints, and edges represent HTTP calls annotated with header propagation attributes.
13. **Path Tracing:** Trace all directed paths from user-accessible entrypoint endpoints down to internal downstream service endpoints.
14. **Detection Rule Execution:** Evaluate deterministic security rules (CD-001 through CD-004) against traced call graph paths and AST attributes.
15. **Severity Scoring:** Compute Severity (LOW, MEDIUM, HIGH, CRITICAL) based on privilege delta, operation sensitivity, and authorization gaps.
16. **Confidence Scoring:** Compute Confidence (LOW, MEDIUM, HIGH) based on AST evidence clarity (e.g., explicit string literal vs dynamic template variable).
17. **Finding Generation:** Synthesize evidence-backed finding payloads with highlighted source code snippets, observations, limitations, and remediation guidance.

---

## 2. Core Confused Deputy Detection Rules

### 2.1 Rule CD-001: Potential Privilege-Boundary Confused Deputy
- **Rule ID:** `CD-001`
- **Name:** Potential Privilege-Boundary Confused Deputy
- **Purpose:** Detect when a user-originated request traverses from a lower-privilege service to a higher-privilege service that performs a sensitive operation without end-to-end user authorization verification.
- **Inputs:** NetworkX Call Graph, AST Route Definitions, Header Dictionary ASTs.
- **Required Evidence:**
  1. Entrypoint service operates at `USER` (1) privilege boundary.
  2. Downstream service operates at `SERVICE` (2) or `ADMIN` (3) privilege boundary.
  3. Downstream endpoint performs a sensitive operation (e.g., `refund`, `DELETE`, `password_reset`).
  4. Inter-service call passes service credentials (`X-Service-Token`) without forwarding user authorization or enforcing downstream user ownership.
- **Algorithm:**
  ```python
  for path in graph.get_all_paths(source=entry_service, target=downstream_service):
      if path.entrypoint.privilege <= USER and path.target.privilege >= SERVICE:
          if path.target.is_sensitive:
              if not path.edge.identity_propagated and not path.target.has_user_authz:
                  emit_finding(rule_id="CD-001", path=path)
  ```
- **Graph Conditions:** Path exists from `Node(Privilege=USER)` to `Node(Privilege>=SERVICE)` where `Edge(IdentityProp=SERVICE_TOKEN)`.
- **Source-Code Conditions:** Outgoing client call constructs headers with hardcoded or service token; target handler lacks `user_id` validation guard.
- **Positive Example (Vulnerable):**
  ```python
  # Order Service (User Auth)
  @app.post("/orders/{order_id}/cancel")
  def cancel_order(order_id: str, user: User = Depends(get_current_user)):
      # Calls Payment Service using service key only
      httpx.post("http://payment-service/internal/refund", headers={"X-Service-Key": "SECRET_KEY"}, json={"order_id": order_id})

  # Payment Service (Elevated)
  @app.post("/internal/refund")
  def refund(data: dict, service: Service = Depends(verify_service_key)):
      # VULNERABLE: No check if original user owns the order!
      db.execute_refund(data["order_id"])
  ```
- **Negative Example (Secure):**
  ```python
  # Payment Service (Secure)
  @app.post("/internal/refund")
  def refund(data: dict, service: Service = Depends(verify_service_key)):
      # SECURE: Explicit user ownership check enforced downstream
      if not verify_user_owns_order(data["user_id"], data["order_id"]):
          raise HTTPException(status_code=403, detail="Unauthorized")
      db.execute_refund(data["order_id"])
  ```
- **False Positives:** Internal microservices operating within an isolated network perimeter where zero trust identity headers are injected by an upstream Envoy service mesh.
- **False Negatives:** Dynamic URL dispatching where `httpx.post(target_url)` receives `target_url` from an external database at runtime.
- **Severity Guidance:** **HIGH** (or **CRITICAL** if financial refund or administrative data deletion is involved).
- **Confidence Guidance:** **HIGH** if hardcoded service key header literal is present in AST; **MEDIUM** if variable-based headers.
- **Remediation:** Pass the original user JWT downstream or require the downstream service to validate user resource ownership before executing sensitive state changes.
- **Automated Tests:** `test_cd001_vulnerable_refund_flow()`, `test_cd001_secure_ownership_flow()`.

---

### 2.2 Rule CD-002: Downstream Service Missing Demonstrable Authorization
- **Rule ID:** `CD-002`
- **Name:** Privileged Downstream Service with Missing Demonstrable Authorization
- **Purpose:** Identify internal downstream endpoints reachable from user-facing services that contain no detectable authentication scheme or authorization checks in code.
- **Inputs:** AST Endpoint Handler ASTs, NetworkX Call Graph.
- **Required Evidence:** Reachable downstream route handler contains zero FastAPI `Depends()` security guards and zero explicit IF-statement authorization checks.
- **Algorithm:**
  ```python
  for endpoint in downstream_service.endpoints:
      if graph.is_reachable_from_public(endpoint):
          if len(endpoint.auth_checks) == 0 and not endpoint.has_middleware_auth:
              emit_finding(rule_id="CD-002", endpoint=endpoint)
  ```
- **Severity Guidance:** **HIGH**.
- **Confidence Guidance:** **HIGH** for standard FastAPI routes; **MEDIUM** if custom router middleware is used.
- **Remediation:** Add explicit authentication and authorization dependencies (`Depends(verify_token)`) to the downstream endpoint definition.

---

### 2.3 Rule CD-003: Untrusted Identity Propagation
- **Rule ID:** `CD-003`
- **Name:** Untrusted Identity Propagation via Unverified Headers
- **Purpose:** Detect instances where downstream services accept unverified identity headers (e.g., `X-User-Id`, `X-User-Role`) passed from upstream services without cryptographic verification (such as JWT signature validation).
- **Inputs:** AST Header Dictionary Parsers, Route Handlers.
- **Required Evidence:** Downstream handler reads raw HTTP header `X-User-Id` directly from request object without verifying an accompanying signature or bearer token.
- **Severity Guidance:** **MEDIUM** to **HIGH**.
- **Confidence Guidance:** **HIGH**.
- **Remediation:** Use cryptographically signed identity assertions (such as nested JWTs or mTLS client certificates) rather than plain unverified HTTP headers.

---

### 2.4 Rule CD-004: Gateway-Only Authorization Policy
- **Rule ID:** `CD-004`
- **Name:** Gateway-Only Authorization Policy with Unprotected Internal Services
- **Purpose:** Identify architectures where authorization checks exist solely at an upstream API Gateway, leaving downstream internal service endpoints unprotected if an attacker bypasses the gateway or accesses internal networks.
- **Inputs:** Service boundaries, Route Auth ASTs.
- **Required Evidence:** Upstream gateway service contains auth guards, but 100% of downstream internal microservice endpoints lack authorization logic.
- **Severity Guidance:** **MEDIUM** (Structural defense-in-depth risk).
- **Confidence Guidance:** **MEDIUM** (Static analysis cannot verify network network security groups or mTLS).
- **Remediation:** Implement zero-trust authorization checks within downstream microservices.

---

## 3. Privilege & Severity Models

### 3.1 Privilege Abstraction Hierarchy
- `PUBLIC` (Level 0): Unauthenticated public endpoints (e.g., `/health`, `/login`).
- `USER` (Level 1): Authenticated basic user endpoints (e.g., `/orders/me`).
- `SERVICE` (Level 2): Internal service-to-service communication endpoints.
- `ADMIN` (Level 3): Privileged administrative actions (e.g., `/admin/users/delete`).
- `UNKNOWN`: Unresolved privilege context (Treated as neutral; does NOT default to HIGH privilege).

### 3.2 Severity Matrix

| Privilege Delta (Caller → Target) | Target Operation | Downstream Auth Check | Severity Rating |
| :--- | :--- | :--- | :--- |
| USER (1) → ADMIN (3) | Sensitive (Delete/Refund) | Missing / Unverified | **CRITICAL** |
| USER (1) → SERVICE (2) | Sensitive (Refund/Write) | Service Token Only | **HIGH** |
| USER (1) → SERVICE (2) | Read-only | Missing | **MEDIUM** |
| Any → Any | Non-sensitive Read | Missing | **LOW** |

---

## 4. Static Analysis Limitations & Uncertainty Communication

To maintain scientific rigor and avoid false assertions, findings must clearly distinguish between **verified evidence** and **static analysis limitations**.

> [!WARNING]
> **Static Uncertainty Requirement:** When static analysis cannot conclusively prove the presence or absence of a control (e.g., external OAuth2 sidecar proxy or dynamic runtime policy engine), the system MUST output:  
> `"Authorization enforcement could not be established statically."`  
> It MUST NOT state: `"Authorization does not exist."`

---

## 5. Benchmark Demo Projects (`demo/vulnerable` vs `demo/secure`)

The repository includes two static benchmark microservices test suites to verify analyzer accuracy deterministically.

```
demo/
├── vulnerable/
│   ├── order_service/main.py      (Calls Payment Svc using hardcoded X-Service-Key)
│   └── payment_service/main.py    (Executes refund without User Ownership check)
└── secure/
    ├── order_service/main.py      (Forwards User Bearer JWT downstream)
    └── payment_service/main.py    (Verifies User JWT & ownership before refund)
```

- **Vulnerable Benchmark Expectation:** Pipeline MUST trigger `CD-001` and `CD-002` findings with HIGH severity and HIGH confidence.
- **Secure Benchmark Expectation:** Pipeline MUST yield **0 findings** for `CD-001` to `CD-004`.

---

## 6. Legal and Ethical Considerations

1. **Authorized Usage:** The Confused Deputy API Detector is designed strictly for authorized security auditing of source code owned by or licensed to the user.
2. **Synthetic Data Only:** All test benchmarks, code snippets, and JSON examples provided in documentation use synthetic data. No real secrets or production credentials are included.
3. **Indian Cybersecurity Regulatory Context:**
   - *Information Technology Act, 2000 (and Amendments):* Securing software architectures supports compliance with cyber safety mandates under IT Act Sec 43A and 70B.
   - *Digital Personal Data Protection (DPDP) Act, 2023:* Identifying authorization flaws prevents unauthorized access to personal data, aiding Data Fiduciaries in implementing technical safeguards under DPDP requirements.
   - *CERT-In Directions:* Helps organizations proactively identify system vulnerabilities prior to mandatory incident reporting thresholds.
4. **Responsible Disclosure:** Security researchers using this tool to analyze third-party open-source microservices must follow responsible disclosure guidelines.
5. **Third-Party AI & Data Privacy Notice:** The core analysis engine operates 100% locally and offline. Uploaded source code is never transmitted to external third-party LLM APIs or external cloud servers.
