# UI/UX and System Design Specification
## Confused Deputy API Detector for Microservices

---

## 1. Visual Design Philosophy & Palette

### 1.1 Aesthetics & Theme
The user interface follows a modern, technical, dark-themed cybersecurity aesthetic inspired by professional security audit suites (e.g., Burp Suite, Datadog, AWS GuardDuty). The interface prioritizes readability, high information density, structural hierarchy, and responsive interactivity.

- **Background Colors:** Slate dark (`#0f172a`, `#1e293b`).
- **Surface & Panel Colors:** Slate gray (`#334155`, `#475569`).
- **Text Styling:** High contrast white/slate-100 (`#f8fafc`) for headers, muted gray (`#94a3b8`) for secondary metadata, monospace font (`Fira Code`, `JetBrains Mono`) for file paths, code snippets, and IDs.

### 1.2 Semantic Risk Color Palette

> [!IMPORTANT]
> **Risk Communication Principle:** A red highlight indicates a **potential high-risk authorization flaw** requiring investigation based on static evidence. It does NOT assert a guaranteed exploitable vulnerability in live production.

| Semantic Purpose | Color Code | Tailwind Class | UI Representation |
| :--- | :--- | :--- | :--- |
| **Critical / High Risk** | `#ef4444` (Crimson) | `bg-red-500/10 text-red-400 border-red-500/30` | High-confidence Confused Deputy flaw, privilege jump |
| **Medium / Low Risk / Warning** | `#f59e0b` (Amber) | `bg-amber-500/10 text-amber-400 border-amber-500/30` | Inconclusive authorization check, gateway-only auth guard |
| **Verified Secure Control** | `#10b981` (Emerald) | `bg-emerald-500/10 text-emerald-400 border-emerald-500/30` | Explicit end-to-end user identity check or ownership guard |
| **Informational / Neutral** | `#64748b` (Slate) | `bg-slate-500/10 text-slate-400 border-slate-500/30` | Public routes, internal HTTP calls, general topology nodes |

---

## 2. Screen Specifications

### 2.1 Upload Screen (`UploadPanel`)
- **Layout:** Centered drag-and-drop card with dashed border indicators.
- **Controls:** File selector (`.zip`), project name override input, "Run Confused Deputy Analysis" submit button, and Quick Benchmark triggers (`/demo/vulnerable` and `/demo/secure`).
- **Feedback:** Real-time upload progress bar, zip validation error toast, and animated scan processing indicator.

### 2.2 Dashboard Overview (`ScanSummary`)
- **Top Metric Cards:** 4 key metrics displaying Total Services Discovered, Total API Endpoints, Inter-Service Call Edges, and Findings Count broken down by Severity badges.
- **Scan Status Banner:** Displays project name, upload timestamp, analysis engine version, and execution duration.

### 2.3 Interactive Architecture Graph (`ArchitectureGraph`)
- **Canvas:** Full-bleed React Flow interactive canvas supporting pan, zoom, layout toggle (Horizontal Dagre vs Vertical Grid), and mini-map.
- **Nodes:** Custom `ServiceNode` components displaying service name, privilege badge, and exported endpoints list.
- **Edges:** Directed arrows connecting service nodes with method/path labels. Edges matching security rule violations flash red/amber and feature animated pulse dots.
- **Interactivity:** Clicking a node or edge opens an inspector drawer showing underlying AST properties and endpoint routes.

### 2.4 Findings Table (`FindingTable`)
- **Controls:** Multi-attribute filtering (Filter by Rule ID, Severity, Confidence, Affected Service) and search input.
- **Table Columns:** `Finding ID`, `Rule ID & Title`, `Severity Badge`, `Confidence Badge`, `Source Service → Target Service`, `Line Number`, `Actions` (`View Code`).

### 2.5 Finding Details & Code Evidence Modal (`FindingDetails` & `CodeEvidenceViewer`)
- **Header:** Finding Title, Rule ID, Severity & Confidence Badges, Affected Request Path breadcrumbs.
- **Code Viewer Panel:** Monospace code window with line numbers, highlighting the exact line of the outgoing HTTP call or missing authorization check. Detected hardcoded tokens or secrets are automatically masked (`[REDACTED_SECRET]`).
- **Analysis Accordion:**
  - *Authorization Observations:* Bulleted list of detected or missing auth dependencies.
  - *Privilege Observations:* Explanation of privilege boundaries between source and target services.
  - *Static Limitations:* Clear statement of static uncertainties (e.g., dynamic target URL resolution).
  - *Remediation Guidance:* Actionable code snippet showing recommended fix (e.g., user identity propagation or downstream ownership guard).

### 2.6 Report Export View (`ReportPanel`)
- **Controls:** Download JSON Scan Artifact button and Download Standalone HTML Report button.

---

## 3. Reusable UI Components

### 3.1 `ServiceNode` (React Flow Node)
```tsx
interface ServiceNodeProps {
  data: {
    label: string;
    privilege: 'PUBLIC' | 'USER' | 'SERVICE' | 'ELEVATED' | 'ADMIN';
    endpointsCount: number;
    hasRisk: boolean;
  };
}
```
Renders a rounded dark panel displaying service name, privilege pill badge, and warning indicator icon if `hasRisk` is true.

### 3.2 `RiskEdge` (React Flow Edge)
```tsx
interface RiskEdgeProps {
  id: string;
  source: string;
  target: string;
  label: string;
  data: {
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    ruleId?: string;
  };
}
```
Renders a custom SVG bezier edge connecting service nodes. Red animated stroke if associated with HIGH/CRITICAL finding.

### 3.3 `SeverityBadge` & `ConfidenceBadge`
```tsx
interface BadgeProps {
  value: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}
```
Renders rounded status pills styled with corresponding semantic colors.

### 3.4 `CodeEvidenceViewer`
```tsx
interface CodeViewerProps {
  fileName: string;
  codeSnippet: string;
  highlightLine: number;
  observations: string[];
}
```
Renders a dark code block with line numbering, active line highlight, and copy-to-clipboard button.

---

## 4. UI Component Architecture (React Tree)

```
[ App Layout ]
  ├── [ Header Navbar ] (Logo, Version, Run Benchmark Buttons, Export Button)
  └── [ Main Container ]
        ├── [ UploadPanel ] (Renders when scan_status == IDLE or PENDING)
        └── [ Dashboard Workspace ] (Renders when scan_status == COMPLETED)
              ├── [ ScanSummary Cards ]
              ├── [ View Mode Tabs: Graph View | Findings View | Report Export ]
              ├── [ ArchitectureGraph Canvas ] (React Flow)
              │     ├── Custom [ ServiceNode ]
              │     └── Custom [ RiskEdge ]
              ├── [ FindingTable View ]
              │     ├── [ SeverityBadge ]
              │     └── [ ConfidenceBadge ]
              └── [ FindingDetails Drawer / Modal ]
                    ├── [ CodeEvidenceViewer ]
                    ├── [ ObservationList ]
                    └── [ RemediationBox ]
```
