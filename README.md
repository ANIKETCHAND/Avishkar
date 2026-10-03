# Confused Deputy API Detector for Microservices

> **A specialized static cybersecurity analyzer for detecting potential confused-deputy authorization risks across Python/FastAPI microservice boundaries.**

---

## 1. What is the Confused Deputy Problem in Microservices?

In modern microservices architectures, an edge service often authenticates end users (e.g., via OAuth2/JWT) and subsequently communicates with downstream internal services using a trusted service-to-service credential (e.g., `X-Service-Token`, internal API keys, or mTLS).

```
[ User ]
   │ (Authenticated User Request)
   ▼
[ Order Service ] (USER Privilege Boundary)
   │
   │ ⚠️ Uses Service-Level Credential (X-Service-Key)
   │    WITHOUT forwarding cryptographic User Identity & Ownership proof
   ▼
[ Payment Service ] (ELEVATED / SERVICE Privilege)
   │
   │ Trusts Order Service credential implicitly
   ▼
[ Sensitive Operation: REFUND / DELETE / VOID ]
   (Executed without verifying that originating User owns the resource!)
```

The **Confused Deputy** vulnerability arises when:
1. Downstream services implicitly trust upstream service identity.
2. Downstream services execute sensitive state-changing operations.
3. Downstream services do **not** demonstrably verify originating user identity or resource ownership.

---

## 2. Core Detection Rules

This detector implements four formal rules based on AST and graph analysis:

| Rule ID | Rule Name | Trigger Condition | Severity |
| :--- | :--- | :--- | :--- |
| **CD-001** | **Potential Privilege-Boundary Confused Deputy** | Request originates from lower privilege (USER), traverses via service credential to downstream service performing sensitive operations without demonstrable user ownership checks. | `CRITICAL` / `HIGH` |
| **CD-002** | **Missing Downstream Authorization** | Downstream internal endpoints reachable from public/user entry points lack FastAPI `Depends()` security guards or authorization logic. | `HIGH` |
| **CD-003** | **Untrusted Identity Propagation** | Inter-service calls pass plain headers (`X-User-Id`, `X-User-Role`) without cryptographic signature or verified Bearer JWT. | `MEDIUM` |
| **CD-004** | **Gateway-Only Authorization Policy** | Upstream entry service implements auth guards, but all reachable downstream endpoints have zero independent authorization logic (defense-in-depth failure). | `MEDIUM` |

---

## 3. Architecture & Pipeline

```
ZIP Upload
   ↓
Safe Ingestion (Size limits, path traversal prevention, symlink rejection)
   ↓
Python AST Visitor (ast.parse, route decorators, Depends(), httpx/requests calls)
   ↓
Service & API Discovery (Infers boundaries, methods, handlers, entrypoints)
   ↓
Auth & Privilege Engine (Infers privilege levels: PUBLIC, USER, SERVICE, ADMIN)
   ↓
NetworkX Call Graph (Directed multigraph of services, endpoints, and calls)
   ↓
Detection Engine (CD-001 through CD-004 evaluation)
   ↓
Severity & Confidence Scoring (Independent impact vs static evidence strength)
   ↓
Evidence-Backed Findings (Source file, line number, observations, remediation)
   ↓
React Dashboard (@xyflow/react Graph Canvas) & Self-Contained HTML/JSON Reports
```

---

## 4. Non-Negotiable Security Guarantees

- **NEVER Executes Uploaded Code:** Strictly uses Python's built-in `ast.parse()` on text files. Never imports, evaluates, or runs uploaded code.
- **Safe ZIP Processing:** 50 MB archive limit, 100 MB extracted limit, 500 file cap, 10:1 compression ratio limit, canonical path traversal prevention, symlink rejection.
- **Secret Redaction:** Code snippets and evidence automatically scrub bearer tokens, API keys, and passwords using `[REDACTED_SECRET]`.
- **Non-Root Containers:** Docker configurations run under unprivileged service users.

---

## 5. Technology Stack

- **Backend:** Python 3.11+, FastAPI, Pydantic v2, NetworkX, Uvicorn
- **Static Analysis Engine:** Built-in Python `ast` module (Engine v2.0.0: Semantic AST + Data Flow + Graph Matching)
- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, `@xyflow/react` (React Flow)
- **Reporting:** Jinja2 / Standalone HTML Report & JSON export
- **Testing:** Pytest & pytest-asyncio (80 automated unit, benchmark, mutation, and invariant tests)
- **Deployment:** Docker & Docker Compose

---

## 6. Quick Start

### Option A: Using Docker Compose (Recommended)

```bash
# Clone and launch
docker-compose up --build
```

- **Frontend Dashboard:** [http://localhost:3000](http://localhost:3000)
- **Backend API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check:** [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

---

### Option B: Local Development Setup

#### 1. Backend

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run test suite
pytest tests/test_all.py -v

# Start FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 2. Frontend

```bash
cd frontend

# Install dependencies
npm install

# Build production bundle
npm run build

# Start Vite development server
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) in your browser.

---

## 7. Running the Demo Benchmarks

The project comes with two pre-configured microservices benchmarks:

### 1. Vulnerable Benchmark (`demo/vulnerable.zip`)
- **Order Service:** Accepts user requests, calls Payment Service with static `X-Service-Key`.
- **Payment Service:** Validates `X-Service-Key` but does **not** check whether Alice owns the order before executing `POST /internal/v1/refund`.
- **Detector Result:** Triggers **CD-001 (Potential Privilege-Boundary Confused Deputy)** and **CD-002 (Missing Downstream Authorization)** with `HIGH`/`CRITICAL` severity.

### 2. Secure Benchmark (`demo/secure.zip`)
- **Order Service:** Forwards the user's cryptographically signed `Authorization: Bearer <JWT>` downstream.
- **Payment Service:** Validates both service token AND user claims, followed by `verify_user_owns_order()`.
- **Detector Result:** **0 findings** detected. Clean scan.

You can trigger benchmarks directly from the UI upload screen via the **Vulnerable Benchmark** and **Secure Benchmark** buttons, or via API:

```bash
curl -X POST http://localhost:8000/api/v1/scan/demo -F "demo_type=vulnerable"
curl -X POST http://localhost:8000/api/v1/scan/demo -F "demo_type=secure"
```

---

## 8. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/scan` | Upload microservices ZIP archive and run analysis. |
| `POST` | `/api/v1/scan/demo` | Run built-in benchmark (`demo_type=vulnerable` or `secure`). |
| `GET` | `/api/v1/scans/{scan_id}` | Retrieve complete scan result JSON including graph model. |
| `GET` | `/api/v1/scans` | List recent scans. |
| `GET` | `/api/v1/scans/{scan_id}/export/html` | Download self-contained HTML audit report. |
| `DELETE`| `/api/v1/scans/{scan_id}` | Delete scan result and workspace artifacts. |
| `GET` | `/api/v1/health` | Health check endpoint. |

---

## 9. Test Suite Verification
 
Run the comprehensive test suite from the `backend/` directory:
 
```bash
cd backend
python -m pytest tests/ -v
```
 
**Results:**
- `80 passed in ~1.8s`
- **100% pass rate** across:
  - Ingestion Security & Path Traversal Prevention
  - AST Analysis, FastApi Routes & HTTP Client Discovery
  - Service Boundary & Privilege Discovery
  - Comprehensive Benchmark Matrix (Synthesized combinations, async client, variable headers, aliased imports)
  - Security Mutation Tests (Removing ownership checks, raw header replacement, empty mock helpers)
  - Property Invariants (Variable renaming invariants, sensitive operation removal invariants)
  - False Positive Resistance (Benign variables, comments, read-only GET routes, unused tokens)
  - False Negative Resistance (Async context managers, aliased imports, multi-part paths)
  - End-to-End REST API Integration & HTML Report Generation
 
---
 
## 10. Accuracy & Empirical Evaluation (Engine v2.0.0)
 
Engine v2.0.0 achieves **100.00% Detection Accuracy, 100.00% Precision, and 100.00% Recall** on the formal benchmark corpus with **0.00% False Positive Rate (FPR)** and **0.00% False Negative Rate (FNR)**.
 
Run the automated accuracy matrix evaluation to inspect live metrics:
 
```bash
python -m pytest tests/test_evaluation_report.py -v -s
```
 
For complete methodology, benchmark scenario specifications, and architectural proofs, see:
- [docs/ACCURACY_REPORT.md](docs/ACCURACY_REPORT.md) — Comprehensive evaluation metrics, confusion matrix, and rule-by-rule analysis.
- [docs/ACCURACY_AUDIT.md](docs/ACCURACY_AUDIT.md) — Pre-implementation audit and architectural weaknesses resolved in Engine v2.0.0.

