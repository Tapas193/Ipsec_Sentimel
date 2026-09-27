export interface ApiErrorBody {
  code: string
  message: string
  details?: Record<string, unknown> | null
}

export interface ApiResponse<T> {
  success: boolean
  data: T | null
  error: ApiErrorBody | null
  meta: Record<string, unknown>
}

export interface PaginationMeta {
  page: number
  page_size: number
  total: number
  total_pages: number
}

export interface PaginatedData<T> {
  items: T[]
  pagination: PaginationMeta
}

export interface HealthData {
  status: string
  version: string
  database: string
}

export interface DashboardStats {
  captures: number
  analysis_jobs: number
  pending_jobs: number
  analyses: number
  security_findings: number
  reports: number
}

export interface SystemComponent {
  name: string
  status: string
  detail: string | null
}

export interface SystemInfoData {
  application: string
  version: string
  environment: string
  python_version: string
  components: SystemComponent[]
}

// ---------------------------------------------------------------------------
// Phase 2 — Captures
// ---------------------------------------------------------------------------

export type CaptureStatus =
  | 'uploaded'
  | 'validating'
  | 'valid'
  | 'invalid'
  | 'analyzing'
  | 'analyzed'
  | 'failed'

export interface Capture {
  id: string
  capture_reference: string
  capture_id: string | null
  filename: string
  original_filename: string
  stored_filename: string | null
  file_size: number
  sha256: string
  capture_format: string | null
  packet_count: number | null
  duration: number | null
  first_packet_time: string | null
  last_packet_time: string | null
  status: CaptureStatus
  analysis_status: string | null
  uploaded_at: string
}

export interface AnalyzeResponse {
  analysis_id: string
  analysis_reference: string
}

// ---------------------------------------------------------------------------
// Phase 2 — Analysis
// ---------------------------------------------------------------------------

export type JobStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed'

export interface AnalysisJob {
  id: string
  job_id: string | null
  capture_id: string
  status: JobStatus
  progress: number
  current_stage: string | null
  stage_message: string | null
  error_message: string | null
  started_at: string | null
  completed_at: string | null
}

export type AnalysisStatus = 'running' | 'completed' | 'partial' | 'failed'

export interface Analysis {
  id: string
  analysis_id: string | null
  capture_id: string
  status: AnalysisStatus
  protocol: string | null
  protocol_detected: string | null
  protocol_confidence: string | null
  ike_detected: boolean | null
  ike_confidence: string | null
  esp_detected: boolean | null
  ah_detected: boolean | null
  ipv4_detected: boolean | null
  ipv6_detected: boolean | null
  ike_version: string | null
  vpn_mode: string | null
  security_score: number | null
  risk_level: string | null
  overall_confidence: number | null
  packet_count: number | null
  byte_count: number | null
  flow_count: number | null
  duration: number | null
  error_message: string | null
  analyzer_version: string | null
  parser_version: string | null
  rule_version: string | null
  model_version: string | null
  dataset_version: string | null
  started_at: string | null
  completed_at: string | null
}

export interface AnalysisSummary {
  analysis: Analysis
  job: AnalysisJob | null
  protocol_observations: string[]
  ike_message_count: number
  esp_packet_count: number
  ah_packet_count: number
  flow_count: number
}

// ---------------------------------------------------------------------------
// Phase 2 — Packet analysis sub-resources
// ---------------------------------------------------------------------------

export interface ProtocolObservation {
  id: string
  protocol: string
  packet_count: number
  byte_count: number
  first_seen: string | null
  last_seen: string | null
  confidence: string | null
  evidence: string[]
}

export interface IkeProposal {
  id: string
  proposal_number: number | null
  protocol_id: number
  protocol_name: string
  encryption: string
  encryption_id: number | null
  key_length: number | null
  integrity: string
  integrity_id: number | null
  prf: string
  prf_id: number | null
  dh_group: number | null
  esn: number | null
  status: string
  transform_confidence: string
}

export interface IkeMessage {
  id: string
  packet_id: number
  timestamp: string
  source_ip: string
  destination_ip: string
  source_port: number
  destination_port: number
  version: string
  exchange_type: number
  exchange_name: string
  flags: number
  message_id: string
  length: number
  next_payload: number
  payload_types: string[]
  initiator_spi: string
  responder_spi: string
  direction: string
  proposals: IkeProposal[]
}

export interface EspPacket {
  id: string
  packet_id: number
  timestamp: string
  source_ip: string
  destination_ip: string
  spi: string
  sequence_number: number | null
  length: number
  direction: string
  encryption_algorithm: string
}

export interface AhPacket {
  id: string
  packet_id: number
  timestamp: string
  source_ip: string
  destination_ip: string
  spi: string
  sequence_number: number | null
  length: number
  direction: string
  next_header: number | null
}

export interface Flow {
  id: string
  flow_id: string
  source_ip: string
  destination_ip: string
  source_port: number | null
  destination_port: number | null
  protocol: string
  transport: string | null
  ip_version: number | null
  start_time: string
  end_time: string
  duration: number
  packet_count: number
  byte_count: number
  upstream_packets: number
  downstream_packets: number
  upstream_bytes: number
  downstream_bytes: number
  direction: string
  spi: string | null
  ike_packets: number
  esp_packets: number
  ah_packets: number
}

export interface FlowFeatures {
  id: string
  /** Foreign key to the flow row (a per-analysis UUID). Not a stable identifier. */
  flow_id: string
  /** Stable, human-readable flow identity, e.g. `10.0.0.1:500-udp/4->10.0.0.2:500`. */
  flow_key: string | null
  feature_schema_version: string
  features: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Phase 3 — Security assessment
// ---------------------------------------------------------------------------

export interface FindingEvidenceItem {
  source: string
  field: string
  observed_value: string | null
  expected_value: string | null
  observation_status: string
}

export interface FindingEvidence {
  version: string | null
  items: FindingEvidenceItem[]
  packet_ids: number[]
  message_ids: string[]
  notes: string[]
}

export interface SecurityFinding {
  id: string
  analysis_id: string
  finding_id: string | null
  rule_id: string
  rule_version: string | null
  title: string
  severity: string
  finding_type: string
  category: string
  confidence: string
  status: string
  description: string | null
  impact: string | null
  recommendation: string | null
  observed_value: string | null
  expected_value: string | null
  source: string | null
  evidence: FindingEvidence | null
  created_at: string
}

export interface RuleAssessment {
  rule_id: string
  created: number
  skipped: number
}

export interface AssessmentResult {
  analysis_id: string
  rule_version: string
  rules_run: number
  created: number
  skipped: number
  total_findings: number
  duration_ms: number
  rules: RuleAssessment[]
  completed_at: string
}

// ---------------------------------------------------------------------------
// Phase 2 — System tools
// ---------------------------------------------------------------------------

export interface ToolStatus {
  name: string
  installed: boolean
  version: string | null
  detail: string | null
}

export interface ToolsData {
  active_reader: string
  tools: ToolStatus[]
}