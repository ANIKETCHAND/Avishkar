# System Architecture Document
## Confused Deputy API Detector for Microservices

---

## 1. System Overview & Core Pipeline Architecture

The **Confused Deputy API Detector** processes microservices codebases in a single, multi-stage static analysis pipeline. The system ingests packaged microservice repositories, extracts structural syntax ASTs without executing application code, maps cross-service HTTP client calls and identity headers, builds a NetworkX directed graph model, evaluates security detection rules, and presents findings visually via a React dashboard.

```
[ Upload ZIP Archive ]
          │
          ▼
[ 1. Project Ingestion ] ────► Safe Archive Extraction & Validation
          │
          ▼
[ 2. Source Analyzer ] ─────► Python AST Parser (FastAPI routes, AST visitor)
          │
          ▼
[ 3. Service Discovery ] ───► Identify Microservices & Boundaries
          │
          ▼
[ 4. API Discovery ] ───────► Map Endpoints, HTTP Methods & Handlers
          │
          ▼
[ 5. Authorization ] ──────► AuthN/AuthZ Dependencies & Identity Headers
          │
          ▼
[ 6. Call Graph Engine ] ───► NetworkX Directed Call Graph Synthesis
          │
          ▼
[ 7. Detection Engine ] ────► Execute CD-001 to CD-004 Rule Checks
          │
          ▼
[ 8. Risk & Finding Engine]► Severity/Confidence Calculation & Evidence Framing
          │
          ▼
[ 9. FastAPI REST Layer ] ──► JSON Endpoints & HTML/JSON Exporters
          │
          ▼
[ 10. React Dashboard ] ───► React Flow Graph Visualizer & Code Evidence Viewer
```

---

## 2. Component Breakdown & Responsibilities

### 2.1 Project Ingestion Module (`app/ingestion/`)
- **Responsibilities:**
  - Ingest ZIP file payload from FastAPI REST endpoint.
  - Validate file headers, enforce size limits (max 50MB archive, max 100MB extracted), and verify file counts (max 500 files).
  - Strip dangerous path traversal characters (`../`, absolute path roots).
  - Unpack files safely into a temporary workspace directory under `storage/scans/{scan_id}/extracted`.
  - Scan directory tree to locate Python files (`.py`) and metadata configuration files (`pyproject.toml`, `Dockerfile`, `requirements.txt`).

### 2.2 Source Analyzer Module (`app/analyzer/ast_visitor.py`)
- **Responsibilities:**
  - Parse Python source code files into Abstract Syntax Trees using standard library `ast.parse()`.
  - Implement custom `ast.NodeVisitor` classes to inspect:
    - FastAPI app definitions (`app = FastAPI()`, `router = APIRouter()`).
    - Route decorators (`@app.get()`, `@app.post()`, `@router.delete()`).
    - Dependency injection parameters (`Depends(...)`, `Security(...)`).
    - HTTP client calls (`httpx.Client`, `httpx.AsyncClient`, `requests.get/post`, `aiohttp.ClientSession`).
    - String literals representing URL endpoints and custom header key-value pairs (`X-User-Id`, `Authorization`, `X-Service-Token`).

### 2.3 Service Discovery Module (`app/analyzer/service_discovery.py`)
- **Responsibilities:**
  - Group Python source files into logical microservice units based on directory trees, distinct `FastAPI()` instantiations, or service configuration files.
  - Assign unique `service_id` and name attributes (e.g., `order-service`, `payment-service`).
  - Catalog root entrypoint files and declared environment port configurations.

### 2.4 API Discovery Module (`app/analyzer/api_discovery.py`)
- **Responsibilities:**
  - Construct endpoint definitions for each discovered service route.
  - Extract target path template (e.g., `/api/v1/orders/{order_id}`), HTTP method (`GET`, `POST`, `DELETE`), function handler name, file location, and line number ranges.
  - Flag sensitive operations (e.g., operations containing `DELETE`, `refund`, `admin`, `password`, `role`).

### 2.5 Authorization & Privilege Analyzer (`app/analyzer/auth_analyzer.py`)
- **Responsibilities:**
  - Analyze security dependencies (`OAuth2PasswordBearer`, `HTTPBearer`, custom auth functions) attached to FastAPI routes.
  - Detect role checks (`verify_admin`, `require_role("admin")`), ownership checks (`verify_order_owner`), or unauthenticated public routes.
  - Inspect outgoing HTTP client call header dictionary arguments to evaluate identity propagation:
    - *Forwarding User Identity:* Passes incoming request user JWT / user ID downstream.
    - *Service Token Substitution:* Uses hardcoded service key or service-account token without forwarding user context.
    - *Stripped Context:* Drops all authentication headers.

### 2.6 Call Graph Engine (`app/graph/call_graph.py`)
- **Responsibilities:**
  - Instantiate NetworkX `nx.DiGraph` representing the cross-service system topology.
  - Add Node objects for Services and Endpoints annotated with privilege levels, auth guards, and route paths.
  - Add Directed Edge objects for service-to-service HTTP client calls annotated with call type, header types, identity propagation flags, and source code line references.
  - Provide graph querying utilities (e.g., downstream reachability from public entrypoints, path tracing).

### 2.7 Detection Engine (`app/rules/detection_engine.py`)
- **Responsibilities:**
  - Evaluate deterministic rules (CD-001 through CD-004) against the NetworkX call graph and AST metadata model.
  - Trace request paths starting from user-accessible entrypoints down to privileged internal services.
  - Match graph edge patterns against rule definitions.

### 2.8 Risk & Finding Engine (`app/engine/risk_engine.py`)
- **Responsibilities:**
  - Compute Severity (LOW, MEDIUM, HIGH, CRITICAL) based on privilege delta, operation sensitivity, and downstream auth gaps.
  - Compute Confidence (LOW, MEDIUM, HIGH) based on evidence certainty (e.g., explicit AST string literal vs dynamic string template).
  - Construct structured `Finding` objects containing source code evidence, AST line references, limitations, and remediation guidance.

### 2.9 API & Reporting Layer (`app/api/` & `app/reporting/`)
- **Responsibilities:**
  - Expose FastAPI endpoints (`POST /api/v1/scan`, `GET /api/v1/scans/{scan_id}`, `GET /api/v1/scans/{scan_id}/export/html`).
  - Render self-contained HTML audit reports using Jinja2 templates.

### 2.10 Frontend React Dashboard (`frontend/src/`)
- **Responsibilities:**
  - Interactive upload interface with drag-and-drop support.
  - React Flow graph visualizer showing service nodes, API routes, and risk-annotated edges.
  - Finding detail viewer with side-by-side source code evidence and remediation guides.

---

## 3. Architecture Diagrams (Mermaid)

### Diagram 1: High-Level System Architecture
```mermaid
flowchart TD
    User([User / Security Auditor]) -->|Uploads ZIP Archive| UI[React Dashboard - Port 3000]
    UI -->|POST /api/v1/scan| API[FastAPI Backend - Port 8000]
    
    subgraph Backend Pipeline
        API --> Ingest[Project Ingestion & Zip Sanitizer]
        Ingest --> AST[Python AST Parsing Engine]
        AST --> SvcDisc[Service & API Discovery]
        SvcDisc --> AuthAnal[AuthN/AuthZ & Identity Tracing]
        AuthAnal --> GraphEng[NetworkX Call Graph Engine]
        GraphEng --> DetectEng[Confused Deputy Detection Engine]
        DetectEng --> RiskEng[Risk & Confidence Engine]
        RiskEng --> ReportEng[Report Generator & Storage]
    end
    
    ReportEng -->|Returns JSON Payload| UI
    UI -->|Renders Visual Topology| ReactFlow[React Flow Canvas]
    UI -->|Displays Findings & Code| CodeViewer[Code Evidence Viewer]
```

### Diagram 2: Static Analysis Pipeline
```mermaid
flowchart LR
    Zip[Raw ZIP Archive] -->|Safe Unpack| Files[Python Source Files]
    Files -->|ast.parse| AST[AST Node Tree]
    
    subgraph AST Visitor Inspections
        AST -->|Visit Class/Function| Routes[FastAPI Routes & Handlers]
        AST -->|Visit Dependencies| AuthGuard[AuthN / Role Checks]
        AST -->|Visit Call Nodes| HttpCalls[httpx / requests Calls]
        AST -->|Visit Dict Nodes| Headers[Header Dictionary Tracing]
    end
    
    Routes --> Model[Unified AST Metadata Model]
    AuthGuard --> Model
    HttpCalls --> Model
    Headers --> Model
    
    Model --> Graph[Graph & Detection Engine Pipeline]
```

### Diagram 3: Service-Call Graph Representation
```mermaid
flowchart LR
    subgraph Public Entry Boundary
        U([User Client]) -->|POST /orders/refund| GW[API Gateway / Router]
    end

    subgraph Service Layer: Order Service (USER Privilege)
        GW -->|User JWT Auth| OrderSvc[Order Service Handler]
        OrderSvc -->|Validates User JWT| OrderAuth[Auth Check: Valid]
    end

    subgraph Service Layer: Payment Service (ELEVATED Privilege)
        OrderSvc -->|HTTP POST /api/v1/payment/refund| PaySvc[Payment Service Handler]
        PaySvc -->|X-Service-Token Auth| PayAuth[Auth Check: Service Only]
        PayAuth -.->|MISSING USER AUTHZ CHECK| VulnerableOp[(Financial Refund Database)]
    end

    style VulnerableOp fill:#f9f,stroke:#333,stroke-width:2px,fill:#ff4d4d,color:#fff
    style PayAuth fill:#ffffb3,stroke:#333,stroke-width:1px
```

### Diagram 4: Backend Component Architecture
```mermaid
graph TD
    subgraph FastAPI Application Framework
        Router[API Router: /api/v1] --> ScanEndpoint[Scan Controller]
        ScanEndpoint --> IngestionSvc[Ingestion Service]
        ScanEndpoint --> AnalysisSvc[Analysis Orchestrator]
    end

    subgraph Analysis Engine Core
        AnalysisSvc --> ASTEngine[AST Parser Engine]
        ASTEngine --> SvcCatalog[Service Catalog]
        ASTEngine --> EndpointsCatalog[Endpoints Catalog]
        
        AnalysisSvc --> AuthTracker[Identity & Header Tracker]
        
        SvcCatalog --> GraphBuilder[NetworkX Graph Builder]
        EndpointsCatalog --> GraphBuilder
        AuthTracker --> GraphBuilder
        
        GraphBuilder --> RuleRunner[Detection Rule Runner]
        RuleRunner --> CD001[CD-001: Privilege Jump]
        RuleRunner --> CD002[CD-002: Downstream Missing Auth]
        RuleRunner --> CD003[CD-003: Untrusted Identity Prop]
        RuleRunner --> CD004[CD-004: Gateway Only Auth]
        
        CD001 --> RiskScorer[Risk & Confidence Scorer]
        CD002 --> RiskScorer
        CD003 --> RiskScorer
        CD004 --> RiskScorer
    end

    subgraph Data & Storage
        RiskScorer --> Store[JSON File Storage: storage/scans/]
        Store --> HTMLGen[HTML Report Exporter]
    end
```

### Diagram 5: Frontend/Backend Communication Sequence
```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as React Frontend
    participant API as FastAPI Backend
    participant Engine as Static Analysis Engine
    participant Store as JSON Storage

    User->>UI: Selects & Uploads microservices.zip
    UI->>API: POST /api/v1/scan (multipart/form-data)
    API->>Engine: Process ZIP & Run Pipeline
    Engine->>Engine: Extract AST, Build Graph, Run Rules
    Engine->>Store: Persist scan_{scan_id}.json
    Engine-->>API: Return Scan Result Payload
    API-->>UI: 200 OK with Scan JSON Payload
    UI->>UI: Render React Flow Graph & Findings Table
    User->>UI: Clicks Finding Item
    UI->>UI: Open Finding Details & Code Evidence Highlight
    User->>UI: Clicks Export HTML Report
    UI->>API: GET /api/v1/scans/{scan_id}/export/html
    API-->>UI: 200 OK (Content-Type: text/html)
    UI-->>User: Trigger Browser File Download
```

### Diagram 6: Finding-Generation Flow
```mermaid
flowchart TD
    Start[Graph & AST Ready] --> FetchPath[Extract Entrypoint-to-Downstream Paths]
    FetchPath --> PathLoop{For Each Path in Graph}
    
    PathLoop --> CheckBoundary[Evaluate Privilege Delta: Src vs Dst]
    CheckBoundary --> CheckAuth[Inspect Downstream Handler Auth Guards]
    CheckAuth --> CheckHeaders[Inspect Identity Headers Forwarded]
    
    CheckHeaders --> RuleEval{Evaluate CD Rules}
    
    RuleEval -->|CD-001 Match| GenCD001[Generate Privilege Jump Finding]
    RuleEval -->|CD-002 Match| GenCD002[Generate Downstream Missing Auth Finding]
    RuleEval -->|CD-003 Match| GenCD003[Generate Untrusted Identity Prop Finding]
    RuleEval -->|CD-004 Match| GenCD004[Generate Gateway Only Auth Finding]
    RuleEval -->|No Match| NextPath[Proceed to Next Path]
    
    GenCD001 --> AttachEvidence[Attach AST Snippets, File & Line Range]
    GenCD002 --> AttachEvidence
    GenCD003 --> AttachEvidence
    GenCD004 --> AttachEvidence
    
    AttachEvidence --> ScoreRisk[Compute Severity & Confidence]
    ScoreRisk --> Deduplicate[Deduplicate & Format Finding]
    Deduplicate --> NextPath
    NextPath --> PathLoop
    PathLoop -->|Completed All Paths| FinalFindings[Final Structured Findings List]
```

### Diagram 7: User Interaction Flow
```mermaid
stateDiagram-v2
    [*] --> Idle: Open Dashboard
    Idle --> Uploading: Drag & Drop microservices.zip
    Uploading --> Processing: API Sends ZIP Payload
    Processing --> DisplayDashboard: Scan Complete (200 OK)
    Processing --> ErrorState: Zip Invalid / Extraction Error
    ErrorState --> Idle: Reset & Try Again
    
    state DisplayDashboard {
        [*] --> OverviewTab
        OverviewTab --> GraphTab: Click 'Architecture Graph'
        OverviewTab --> FindingsTab: Click 'Findings List'
        
        GraphTab --> NodeDetailModal: Click Graph Node / Service Edge
        FindingsTab --> CodeViewerModal: Click Finding Row
        
        NodeDetailModal --> GraphTab: Close Modal
        CodeViewerModal --> FindingsTab: Close Modal
    }
    
    DisplayDashboard --> ExportingReport: Click 'Export Report'
    ExportingReport --> DisplayDashboard: File Downloaded
```
