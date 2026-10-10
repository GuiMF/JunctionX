import type { Finding, QuantumStatus } from './contract';

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
