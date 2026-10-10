// QuantumTrace Finding v1 & ScanResult v1 Shared Contract
// Aligned with QUANTUMTRACE_PLAN.md Section 4

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
  locator: string; // Line range / JSON pointer / frame & stream
  detail: string;
}

export interface Finding {
  schema_version: '1.0';
  id: string;
  asset_id: string;
  source_type: SourceType;
  algorithm: string;
  parameters: {
    key_bits?: number | null;
    mode?: string | null;
    named_group?: string | null;
  };
  usage: UsageType;
  evidence_kind: EvidenceKind;
  evidence: FindingEvidence[];
  confidence: ConfidenceLevel;
  quantum_status: QuantumStatus;
  challenge_tier: ChallengeTier;
  classical_issues: string[];
  owner?: string | null;
  observed_at?: string | null;
  rule_id: string;
  rationale: string;
  recommendation: string;
  references: string[];
}

export interface CoverageBreakdown {
  assessed: number;
  unknown: number;
  unsupported: number;
  failed: number;
  unit: string; // e.g. "sessions", "files", "resources"
}

export interface ScanCoverage {
  network: CoverageBreakdown;
  source: CoverageBreakdown;
  cloud: CoverageBreakdown;
}

export interface ScanResult {
  schema_version: '1.0';
  scan_id: string;
  started_at: string;
  evaluated_at: string;
  ruleset_version: string;
  tool_versions: Record<string, string>;
  input_hashes: Record<string, string>;
  findings: Finding[];
  coverage: ScanCoverage;
  errors: string[];
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
