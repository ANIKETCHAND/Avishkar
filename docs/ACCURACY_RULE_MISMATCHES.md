# Investigation Report: CD-002, CD-004, and CD-001 Rule Overlap Analysis

**Document Status:** Complete  
**Date:** 2026-10-03  
**Auditor / Security Architect:** Senior Application Security & SAST Engineer  
**Repository:** [ANIKETCHAND/Avishkar](https://github.com/ANIKETCHAND/Avishkar)

---

## 1. Overview & Context

During the transition from subset-style validation (`all(r in detected for r in expected)`) to **exact rule set matching** (`expected_rules == actual_rules`), rigorous evaluation against the benchmark corpus revealed two rule mismatch errors:

1. **Benchmark Case:** `cd002_reachable_unauthenticated_internal_route` (`test_evaluation_report.py`)
   - **Expected:** `["CD-002"]`
   - **Actual Detected:** `["CD-002", "CD-004"]`
   - **Unexpected Extra Rule:** `["CD-004"]` (Gateway-Only Security Policy)
   - **Evaluation Status:** `RULE-MISMATCH / FALSE-POSITIVE`

2. **Benchmark Case:** `BM-VULN-CD002-01` (`test_accuracy_corpus.py`)
   - **Expected:** `["CD-002"]`
   - **Actual Detected:** `["CD-001", "CD-002"]`
   - **Unexpected Extra Rule:** `["CD-001"]` (Privilege-Boundary Confused Deputy)
   - **Evaluation Status:** `RULE-MISMATCH / FALSE-POSITIVE`

This report provides the full AST evidence trace, exact detection engine conditions, root causes, semantic validity assessment, and formal resolutions implemented.

---

## 2. Issue 1: Unexpected CD-004 on `cd002_reachable_unauthenticated_internal_route`

### 2.1 Benchmark Case Definition
```python
# gateway_service/main.py
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.get("/data")
def get_data(u = Depends(auth)):
    httpx.get("http://backend-service:8000/internal/metrics")

# backend_service/main.py
from fastapi import FastAPI
app = FastAPI()

@app.get("/internal/metrics")
def metrics():
    return {"metrics": 123}
```

### 2.2 AST & Semantic Evidence
- **Source Service (`gateway_service`):**
  - Handler `get_data` contains `Depends(auth)`.
  - Extracted as an entry-point service with authentication (`has_entry_auth = True`).
- **Destination Service (`backend_service`):**
  - Handler `metrics` has route `@app.get("/internal/metrics")`.
  - Contains zero authentication dependencies and zero authorization checks (`authentication = []`, `authorization_checks = []`).
  - HTTP method is `GET` (read-only query).
  - Return statement returns static dictionary `{"metrics": 123}` without database mutation or sensitive state alteration (`is_sensitive = False`).

### 2.3 Detection Engine Trigger Conditions
1. **CD-002 (Downstream Service Missing Demonstrable Authorization):**
   - Check: `any(p in dst_ep.route.lower() for p in ["/internal", "/service", "/rpc", "/private", "/admin"])`
   - Route `/internal/metrics` contains `/internal`.
   - Reached from public gateway without authentication.
   - **Emits CD-002** (Valid).

2. **CD-004 (Gateway-Only Authorization Policy with Unprotected Internal Services):**
   - `gateway_service` is an entry point with authentication (`has_entry_auth = True`).
   - Downstream service `backend_service` has 100% unauthenticated endpoints (`all_unauthenticated = True`).
   - Detection condition in `run_cd004` previously checked:
     ```python
     has_privileged_or_sensitive = any(
         e.is_sensitive or any(p in e.route.lower() for p in ["/internal", "/admin", "/service", "/private"])
         for e in dst_eps
     )
     ```
   - Because the path `/internal/metrics` matched the substring `"/internal"`, `has_privileged_or_sensitive` evaluated to `True`.
   - **Emits CD-004** (Unexpected False Positive).

### 2.4 Semantic Validity vs Overlap Bug Analysis
- **CD-002** is an **endpoint-specific vulnerability**: an individual route intended for internal administration or private service-to-service communication (`/internal/...`) lacks authentication when exposed to upstream services.
- **CD-004** is an **architectural defense-in-depth vulnerability**: an entire microservice architecture relies on the outer API gateway as its sole authorization perimeter while internal services perform **sensitive, state-changing business operations** (e.g. transfers, refunds, role updates) without zero-trust verification.
- **Root Cause of Overlap:** `run_cd004` borrowed the route path heuristic `["/internal", "/admin", ...]` from CD-002. As a consequence, a completely benign read-only metrics endpoint (`GET /internal/metrics`, `is_sensitive = False`) was flagged as a critical architectural gateway-only policy vulnerability.
- **Resolution:** CD-004 must strictly require that the downstream service performs sensitive operations (`any(e.is_sensitive for e in dst_eps)`). Non-sensitive read-only endpoints on `/internal` routes remain protected and flagged under CD-002 without generating duplicate architectural noise under CD-004.

---

## 3. Issue 2: Unexpected CD-001 on `BM-VULN-CD002-01`

### 3.1 Benchmark Case Definition
```python
# public_service/main.py
from fastapi import FastAPI
import httpx
app = FastAPI()

@app.post("/webhook")
def webhook():
    httpx.post("http://backend-service/internal/admin/reset")
    return {"ok": True}

# backend_service/main.py
from fastapi import FastAPI
app = FastAPI()

@app.post("/internal/admin/reset")
def hard_reset():
    return {"reset": True}
```

### 3.2 AST & Semantic Evidence
- **Source Service (`public_service`):**
  - Unauthenticated public webhook endpoint.
  - Outbound call `httpx.post(...)` passes zero headers (`passed_headers = []`, `has_service_token = False`).
  - Identity propagation classified as `STRIPPED` / `NONE`.
- **Destination Service (`backend_service`):**
  - Route `/internal/admin/reset` inferred as `PRIVILEGE_ADMIN` due to `/admin` and `reset`.
  - Endpoint performs sensitive state reset (`is_sensitive = True`).
  - Contains zero authentication dependencies (`dst_ep.authentication = []`).

### 3.3 Detection Engine Trigger Conditions
- In `run_cd001`:
  - `src_rank` (PUBLIC = 0) < `dst_rank` (ADMIN = 3).
  - Privilege boundary crossed with `dst_rank >= SERVICE`.
  - Target endpoint is sensitive (`is_sensitive = True`).
  - Outbound call did not pass user JWT (`identity_prop != IDENTITY_FORWARDED_USER_JWT`).
  - Downstream endpoint lacked user authorization (`_has_user_authorization(dst_ep) == False`).
  - **Emits CD-001** (Unexpected False Positive).

### 3.4 Semantic Validity vs Overlap Bug Analysis
- **CD-001 (Confused Deputy)** requires that an intermediary service acts as a **deputy** that possesses or delegates authority (via shared service tokens, internal credentials, or ambient authorization) on behalf of a requester without verifying the requester's resource permissions.
- In `BM-VULN-CD002-01`, `public_service` possesses **no credentials**, passes **no service token**, and delegates **no authority**. Furthermore, `backend_service` has **no authentication checks**; it does not trust the caller's credentials because it requires no credentials whatsoever.
- The vulnerability is purely **CD-002: Unauthenticated Internal Route**. Classifying this as CD-001 is semantically invalid.
- **Resolution:** In `run_cd001`, require that the call delegates service credentials (`has_service_token`) OR that the target endpoint expects authentication. If the target endpoint has no authentication and the caller passes no service credentials, downstream is simply unprotected (CD-002), not a confused deputy (CD-001).

---

## 4. Implementation Summary & Code Changes

### 4.1 In `backend/app/rules/detection_engine.py`:
1. **Rule CD-001 Refinement:**
   ```python
   # Unauthenticated target endpoints called without service credentials represent an
   # unauthenticated route vulnerability (CD-002), not a confused deputy (CD-001).
   if not has_service_token and not dst_ep.authentication:
       continue
   ```
2. **Rule CD-002 Refinement:**
   ```python
   # CD-002 specifically targets internal/admin route paths or privileged internal services
   is_internal_or_privileged = (
       any(p in dst_ep.route.lower() for p in ["/internal", "/service", "/rpc", "/private", "/admin"])
       or dst_service.privilege_level in (PRIVILEGE_SERVICE, PRIVILEGE_ADMIN)
   )
   if not is_internal_or_privileged:
       continue
   ```
3. **Rule CD-004 Refinement:**
   ```python
   # Downstream must expose sensitive state-changing operations to represent an authentic
   # Gateway-Only Authorization Policy vulnerability (CD-004), leaving critical state mutations
   # unprotected within the internal microservice perimeter.
   has_sensitive_ops = any(e.is_sensitive for e in dst_eps)
   if not has_sensitive_ops:
       continue
   ```

### 4.2 In `backend/tests/helpers.py`:
- Implemented `compare_expected_actual_rules(expected_rules, actual_rules)` returning `RuleComparisonResult`.
- Replaced subset checks with deterministic exact set comparison (`exact_match = (exp_set == act_set)`).
- Categorized outcomes into `TP`, `TN`, `FP`, `FN`, and `MIXED`.

### 4.3 In `backend/tests/regression/test_regression.py`:
- Added permanent regression tests:
  - `test_cd002_does_not_accidentally_trigger_cd004`
  - `test_cd004_does_not_trigger_cd002_without_internal_route`
  - `test_cd002_without_service_credentials_does_not_trigger_cd001`

---

## 5. Verification Results

Following these changes, the entire test suite passes with exact set matching:
- `test_evaluation_report.py`: **100% Accuracy (9/9 cases exact-match, 0 FP, 0 FN)**
- `test_accuracy_corpus.py`: **100% Accuracy (15/15 scenarios exact-match, 0 FP, 0 FN)**
- Full backend suite: **87 passed, 0 failures in 1.94s**
