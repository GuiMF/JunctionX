// QuantumTrace Interchange Contract v1
// Strictly aligned with schemas/ScanResult.schema.json and core/models.py

export type SourceType = 'pcap' | 'source' | 'cloud';

export type UsageType =
  | 'key_establishment'
  | 'signature'
  | 'encryption'
  | 'hash'
  | 'mac'
  | 'kdf'
  | 'unknown';

export type EvidenceKind = 'declared' | 'configured' | 'offered' | 'observed';

export type ConfidenceLevel = 'high' | 'medium' | 'low';

export type QuantumStatus =
  | 'vulnerable'
  | 'resistant_primitive'
  | 'hybrid'
  | 'unknown'
  | 'not_applicable';

export type ChallengeTier = 'critical' | 'medium' | 'resilient' | 'unknown';

export interface FindingEvidence {
  file: string;
  locator: string;
  detail: string;
}

export interface FindingParameters {
  key_bits?: number | null;
  mode?: string | null;
  named_group?: string | null;
  hash_algorithm?: string | null;
  iterations?: number | null;
}

export interface Finding {
  schema_version: '1.0';
  id: string;
  asset_id: string;
  source_type: SourceType;
  algorithm: string;
  parameters: FindingParameters;
  usage: UsageType;
  evidence_kind: EvidenceKind;
  evidence: FindingEvidence[];
  confidence: ConfidenceLevel;
  quantum_status: QuantumStatus;
  challenge_tier: ChallengeTier;
  classical_issues: string[];
  posture_issues: string[];
  owner?: string | null;
  observed_at?: string | null;
  rule_id?: string | null;
  rationale?: string | null;
  recommendation?: string | null;
  references: string[];
}

export type CoverageUnit = 'files' | 'packets' | 'sessions' | 'resources' | 'inputs';

export interface CoverageItem {
  source_type: SourceType;
  input_name: string;
  unit: CoverageUnit;
  assessed: number;
  unknown: number;
  unsupported: number;
  failed: number;
}

export interface ScanError {
  source_type: SourceType;
  input_name: string;
  code: string;
  message: string;
}

export interface Relationship {
  source_asset_id: string;
  target_asset_id: string;
  kind: string;
  evidence: FindingEvidence[];
}

export interface ExposureScore {
  policy_version: string;
  label: string;
  value: number;
  weights: Record<string, number>;
  denominator: string;
  assessed_assets: number;
  total_assets: number;
  unknown_assets: number;
  assets_with_unknowns: number;
  offered_only_assets: number;
  not_applicable_assets: number;
  quantum_vulnerable_assets?: number;
  hybrid_assets?: number;
  classical_issue_assets?: number;
  posture_issue_assets?: number;
  assets_by_evidence_kind?: Record<string, number>;
  limitations?: string;
}

export interface ScanResult {
  schema_version: '1.0';
  scan_id: string;
  status: 'completed' | 'partial' | 'failed';
  started_at: string;
  evaluated_at: string;
  ruleset_version: string;
  tool_versions: Record<string, string>;
  input_hashes: Record<string, string>;
  findings: Finding[];
  coverage: CoverageItem[];
  errors: ScanError[];
  relationships: Relationship[];
  score: ExposureScore | Record<string, any>;
  label?: string | null;
  synthetic?: boolean;
}

export interface MigrationComparison {
  asset_id: string;
  name: string;
  description: string;
  original: {
    policy: string;
    tls_version: string;
    quantum_status: QuantumStatus;
    wire_status: 'unverified' | 'classical_observed' | 'pq_observed';
    findings: Finding[];
  };
  upgraded: {
    policy: string;
    tls_version: string;
    quantum_status: QuantumStatus;
    wire_status: 'unverified' | 'classical_observed' | 'pq_observed';
    findings: Finding[];
  };
  summary_note: string;
}
