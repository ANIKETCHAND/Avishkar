# Technical Stack Specification
## Confused Deputy API Detector for Microservices

---

## 1. Stack Overview & Core Philosophy

The technical stack is chosen specifically to satisfy hackathon velocity, zero dynamic code execution constraints, deterministic static parsing performance, and interactive graph visual capabilities.

```
[ Frontend: React 18 + TypeScript + Tailwind CSS + React Flow (@xyflow/react) ]
                                    │
                               REST / JSON
                                    ▼
             [ Backend API: FastAPI 0.110+ & Pydantic v2 ]
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
[ Python AST Parser ]     [ NetworkX Graph Engine ]    [ JSON File Storage ]
(Built-in ast module)     (In-Memory Service Graph)    (Storage Engine)
```

---

## 2. Technology Selection & Rationales

### 2.1 Backend Framework: Python & FastAPI
- **Purpose:** Core web server, REST API provider, static analysis orchestrator, and report generator.
- **Why Selected:** Python offers standard-library AST parsing capabilities (`ast` module) and standard library file handling. FastAPI provides fast async I/O, automatic OpenAPI schema generation, and integration with Pydantic for validation.
- **Alternatives Considered:** 
  - *Node.js/Express:* Weaker built-in Python parsing tools (requires external tree-sitter bindings).
  - *Go (Gin):* Excellent performance, but lacks native Python AST parsing standard libraries.
- **Advantages:** Native Python AST processing, fast setup, auto-generated Swagger UI (`/docs`), strong typing with Pydantic v2.
- **Limitations:** Single-threaded execution per worker (mitigated by asynchronous endpoint handlers and fast execution times < 15s).
- **Where Used:** Entire backend pipeline (`/backend/app`).

### 2.2 Static Analysis: Built-in Python `ast` (+ optional `LibCST`)
- **Purpose:** Parse Python source code into Abstract Syntax Trees to extract service routes, decorator signatures, `httpx`/`requests` calls, and header dictionaries without executing target code.
- **Why Selected:** Standard library module `ast` requires zero external compiled C dependencies, executes safely in isolated CPU memory, and guarantees zero dynamic execution of target code. `LibCST` is optionally evaluated for concrete syntax tree retention when precise source code offsets are required.
- **Alternatives Considered:** 
  - *Tree-sitter:* Fast multi-language parser, but adds native C library compilation overhead for hackathon scope.
  - *Bandit:* Generic security scanner, but built for localized code patterns, not cross-service call graph synthesis.
- **Advantages:** Lightweight, native to Python 3.11+, 100% deterministic, robust against malformed syntax (with try-except guards).
- **Limitations:** Static limitation on dynamic variable lookups (e.g., dynamic HTTP target URLs constructed at runtime). Handled via string literal extraction and pattern heuristics.
- **Where Used:** `backend/app/analyzer/ast_visitor.py`.

### 2.3 Graph Analysis Engine: NetworkX
- **Purpose:** Construct, analyze, traverse, and score the directed service-to-service call graph.
- **Why Selected:** NetworkX is the standard Python graph theory library. It natively supports directed multigraphs (`nx.DiGraph`), graph algorithms (shortest paths, cycle detection, reachability, topological sorting), and graph JSON serialization (`nx.node_link_data`).
- **Alternatives Considered:** 
  - *Neo4j:* Enterprise graph database, excessive infrastructure overhead for MVP.
  - *igraph / RustWorkX:* Faster for massive graphs (>1M nodes), but NetworkX is more than adequate for microservices graphs (<1,000 nodes).
- **Advantages:** Pure Python, zero external database daemon required, instant node/edge attributes, native JSON export.
- **Limitations:** In-memory graph library (not persistent across system restarts unless serialized to JSON).
- **Where Used:** `backend/app/graph/call_graph.py`.

### 2.4 Frontend Framework: React 18, TypeScript, Tailwind CSS
- **Purpose:** Deliver a responsive cybersecurity dashboard, code evidence viewer, interactive findings table, and graph visualizer.
- **Why Selected:** React 18 combined with TypeScript ensures type safety matching backend Pydantic models. Tailwind CSS provides high-utility styling for modern dark-themed developer interfaces.
- **Alternatives Considered:** 
  - *Vue.js / Svelte:* Quick setup, but React has the standard library support for graph visualization (`React Flow`).
- **Advantages:** Ecosystem depth, component modularity, seamless React Flow integration.
- **Limitations:** Requires Node.js build step (Vite).
- **Where Used:** `frontend/src`.

### 2.5 Graph Visualization: React Flow (`@xyflow/react`)
- **Purpose:** Render the interactive cross-service call graph with custom service nodes, endpoint targets, risk-highlighted directed edges, and click handlers.
- **Why Selected:** React Flow is the industry-standard node-based diagramming library for React. It natively supports custom node types, custom edge styling, layout engines (Dagre/D3), zooming, panning, and event triggers.
- **Alternatives Considered:** 
  - *D3.js:* Lower-level, high boilerplate for interactive drag/zoom canvas.
  - *Cytoscape.js:* Powerful, but less React-idiomatic than React Flow.
- **Advantages:** Native React component lifecycle integration, clean styling with Tailwind CSS, excellent performance.
- **Limitations:** Requires layout calculations (e.g., Dagre or simple grid layout) to arrange nodes automatically.
- **Where Used:** `frontend/src/components/ArchitectureGraph.tsx`.

### 2.6 Testing Framework: Pytest
- **Purpose:** Execute unit tests, static AST parser tests, detection rule benchmark verification, and API integration tests.
- **Why Selected:** Standard Python testing framework with fixture support and assertion introspections.
- **Where Used:** `backend/tests/`.

### 2.7 Containerization & Orchestration: Docker & Docker Compose
- **Purpose:** Package frontend, backend, and benchmark demo projects into isolated runtime environments.
- **Why Selected:** Ensures cross-platform consistency (Windows, Linux, macOS) for hackathon evaluation.
- **Where Used:** `Dockerfile`, `docker-compose.yml`.

---

## 3. Persistent Storage Evaluation: JSON Files vs Database

### 3.1 Decision & Justification
For the MVP scope, **JSON File-Based Storage** is explicitly chosen over a relational database (PostgreSQL) or document store (MongoDB).

**Rationale:**
1. **Stateless Scan Processing:** Each repository upload is an independent, ephemeral analysis job. The input is a `.zip` file, and the output is a single `scan_result.json` document.
2. **Zero Database Infrastructure Overhead:** Eliminates database installation, migrations (Alembic), ORM mapping overhead (SQLAlchemy), and connection pooling code for the hackathon.
3. **Immutability & Auditability:** Scan results can be written directly to `data/scans/{scan_id}.json` as immutable static artifacts, allowing instant replay, static HTML rendering, and easy archiving.
4. **Upgrade Path:** The backend data layer uses repository interfaces (`ScanRepository`). If persistence across thousands of scans is needed post-MVP, `ScanRepository` can be swapped with a PostgreSQL/SQLAlchemy implementation without altering the detection engine or API schemas.

---

## 4. Dependencies & Version Strategy

### 4.1 Backend Dependencies (`backend/requirements.txt`)
```text
fastapi>=0.110.0,<0.111.0
uvicorn[standard]>=0.28.0,<0.29.0
pydantic>=2.6.0,<3.0.0
networkx>=3.2.1,<4.0.0
python-multipart>=0.0.9
jinja2>=3.1.3
pytest>=8.0.0
httpx>=0.27.0
```

### 4.2 Frontend Dependencies (`frontend/package.json`)
```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "@xyflow/react": "^12.0.0",
    "lucide-react": "^0.344.0",
    "clsx": "^2.1.0",
    "tailwind-merge": "^2.2.1"
  },
  "devDependencies": {
    "@types/react": "^18.2.64",
    "@types/react-dom": "^18.2.21",
    "@vitejs/plugin-react": "^4.2.1",
    "autoprefixer": "^10.4.18",
    "postcss": "^8.4.35",
    "tailwindcss": "^3.4.1",
    "typescript": "^5.3.3",
    "vite": "^5.1.6"
  }
}
```

---

## 5. Environment & Container Architecture

```
                                  [ Docker Compose Host ]
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
          [ Container 1: Frontend ]                   [ Container 2: Backend ]
          - Nginx / Vite Preview                      - Uvicorn (FastAPI)
          - Port 3000                                 - Port 8000
          - React App Artifacts                       - Python 3.11 AST Engine
                                                      - In-memory NetworkX
                                                      - Temp File Storage: /tmp/scans
```

### 5.1 Development Environment Setup
- Python 3.11+ virtual environment (`venv`).
- Node.js 18+ / npm 9+.
- Docker Engine & Docker Compose.
- Code Editor: VS Code / Antigravity with Python and React extensions.
