# Out-of-Scope Specification
## Confused Deputy API Detector for Microservices

---

## 1. Explicitly Deferred Features & Scope Boundaries

To guarantee successful delivery within the hackathon timeline and maintain strict focus on static authorization-flow analysis, the following features are explicitly deferred from the MVP scope.

### 1.1 Non-Python Language Parsers
- **Deferred:** Java (Spring Boot), Go (Gin/Fiber), Node.js (Express/NestJS), C# (.NET).
- **Rationale:** MVP exclusively targets Python FastAPI repositories to leverage native standard-library AST capabilities. Multi-language support will be added post-MVP via Tree-sitter bindings.

### 1.2 Infrastructure & Service Mesh Parsing
- **Deferred:** Kubernetes YAML manifests, Helm charts, Istio VirtualServices, Envoy sidecar configurations, Linkerd policies.
- **Rationale:** Focus is strictly on application-layer source code and service-to-service HTTP client calls. Service mesh policies require complex multi-file YAML AST modeling.

### 1.3 Dynamic Tracing & Runtime Monitoring
- **Deferred:** eBPF kernel tracing, Jaeger / Zipkin distributed tracing ingestion, OpenTelemetry telemetry feeds.
- **Rationale:** The tool is 100% static and offline. It does not require running target applications or capturing network traffic.

### 1.4 Dynamic Testing & Exploitation
- **Deferred:** DAST API fuzzing, active HTTP payload injection, automatic exploit POC generation.
- **Rationale:** The tool performs static analysis only. It does not execute target code or issue network requests to live servers.

### 1.5 Cloud IAM & Enterprise IAM Integration
- **Deferred:** AWS IAM policies, GCP IAM, Azure RBAC, Okta / Keycloak server integration.
- **Rationale:** In-scope authorization evaluation focuses on application-level guards (`Depends()`, JWT headers), not cloud infrastructure policy documents.

### 1.6 IDE & Pipeline Extensions
- **Deferred:** VS Code extension, Antigravity IDE plugin, GitHub Actions Marketplace action.
- **Rationale:** MVP delivers a standalone React web dashboard and REST API server.

---

## 2. Deferred Feature Summary Matrix

| Deferred Capability | Category | Planned Future Phase | Post-MVP Priority |
| :--- | :--- | :--- | :--- |
| **Go & Java AST Parsers** | Multi-Language | Phase 17 (v2.0) | High |
| **Tree-Sitter Multi-Language Engine** | Parser Infrastructure | Phase 17 (v2.0) | High |
| **Kubernetes / Istio YAML Parser** | Infrastructure | Phase 18 (v2.1) | Medium |
| **OpenTelemetry Trace Correlation** | Dynamic Analysis | Phase 19 (v2.2) | Low |
| **GitHub Actions Pipeline Gate** | DevSecOps CI/CD | Phase 20 (v2.3) | High |
| **VS Code Security Extension** | IDE Integration | Phase 21 (v2.4) | Medium |
