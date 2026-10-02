/**
 * TypeScript types matching backend Pydantic schemas exactly.
 * Mirrors DATA_SCHEMA.md definitions.
 */

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH';
export type PrivilegeLevel = 'PUBLIC' | 'USER' | 'SERVICE' | 'ADMIN' | 'ELEVATED' | 'UNKNOWN';
export type IdentityPropagation = 'FORWARDED_USER_JWT' | 'SERVICE_TOKEN' | 'STRIPPED' | 'UNKNOWN';
export type ScanStatus = 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
export type RuleId = 'CD-001' | 'CD-002' | 'CD-003' | 'CD-004';

export interface Project {
  project_id: string;
  project_name: string;
  uploaded_at: string;
  language: string;
  framework: string;
  total_files: number;
  scan_status: ScanStatus;
  analysis_version: string;
}

export interface Service {
  service_id: string;
  name: string;
  path: string;
  language: string;
  framework: string;
  privilege_level: PrivilegeLevel;
  confidence: Confidence;
  entry_points: string[];
}

export interface Endpoint {
  endpoint_id: string;
  service_id: string;
  method: string;
  route: string;
  handler: string;
  file: string;
  line_start: number;
  line_end: number;
  authentication: boolean;
  authorization_checks: string[];
  is_sensitive: boolean;
}

export interface ServiceCall {
  call_id: string;
  source_service_id: string;
  source_endpoint_id: string;
  destination_service_id: string;
  destination_route: string;
  http_method: string;
  source_file: string;
  source_line: number;
  call_type: string;
  identity_propagation: IdentityPropagation;
  passed_headers: string[];
}

export interface PrivilegeBoundary {
  boundary_id: string;
  source_service_id: string;
  destination_service_id: string;
  source_privilege: PrivilegeLevel;
  destination_privilege: PrivilegeLevel;
  evidence: string;
  confidence: Confidence;
}

export interface Finding {
  finding_id: string;
  rule_id: RuleId;
  title: string;
  severity: Severity;
  confidence: Confidence;
  source_service_id: string;
  destination_service_id: string;
  endpoint_id: string;
  request_path: string[];
  evidence_snippet: string;
  source_file: string;
  line_number: number;
  authorization_observations: string[];
  privilege_observations: string[];
  limitations: string;
  remediation: string;
}

export interface GraphNodeData {
  privilege?: PrivilegeLevel;
  confidence?: Confidence;
  endpointsCount?: number;
  path?: string;
  entryPoints?: string[];
  hasRisk?: boolean;
  // Endpoint-specific
  serviceId?: string;
  method?: string;
  route?: string;
  handler?: string;
  file?: string;
  lineStart?: number;
  lineEnd?: number;
  authenticated?: boolean;
  authorizationChecks?: string[];
  isSensitive?: boolean;
  [key: string]: unknown;
}

export interface GraphEdgeData {
  callType?: string;
  identityPropagation?: IdentityPropagation;
  passedHeaders?: string[];
  sourceFile?: string;
  sourceLine?: number;
  privilegeEscalation?: boolean;
  risk?: boolean;
  riskRule?: string | null;
  severity?: Severity | null;
  [key: string]: unknown;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'SERVICE_NODE' | 'ENDPOINT_NODE';
  data: GraphNodeData;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  data: GraphEdgeData;
}

export interface GraphModel {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ScanResult {
  scan_id: string;
  project: Project;
  services: Service[];
  endpoints: Endpoint[];
  service_calls: ServiceCall[];
  privilege_boundaries: PrivilegeBoundary[];
  graph: GraphModel;
  findings: Finding[];
  summary_stats: Record<string, number>;
  scan_duration_seconds: number | null;
  warnings: string[];
}

export interface ScanSummary {
  scan_id: string;
  project_name: string;
  scan_status: ScanStatus;
  total_services: number;
  total_endpoints: number;
  total_findings: number;
  scan_duration_seconds: number | null;
  uploaded_at: string;
}
