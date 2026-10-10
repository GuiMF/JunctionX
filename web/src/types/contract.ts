export * from './generated';
import type { Finding, Coverage, ScanResult } from './generated';

export type SourceType = Finding['source_type'];
export type EvidenceKind = Finding['evidence_kind'];
export type QuantumStatus = Finding['quantum_status'];
export type ChallengeTier = Finding['challenge_tier'];
export type CoverageItem = Coverage;
export type CoverageUnit = Coverage['unit'];
export type ExposureScore = ScanResult['score'];
