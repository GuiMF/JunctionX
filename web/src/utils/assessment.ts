import type { Finding } from '../types/contract';

export const assessmentTier = (finding: Finding) =>
  finding.quantum_status === 'not_applicable' ? 'not_applicable' : finding.challenge_tier;

export const assessmentLabel = (finding: Finding) =>
  assessmentTier(finding) === 'not_applicable' ? 'Not applicable' : finding.challenge_tier;

export function assessmentGap(finding: Finding): string | null {
  if (finding.quantum_status === 'not_applicable' ||
    (finding.quantum_status !== 'unknown' && finding.challenge_tier !== 'unknown')) return null;
  const rule = finding.rule_id?.split('@')[0];
  if (rule === 'QT-AES-PARAMETERS') return 'AES parameters unresolved';
  if (rule === 'QT-TLS-NEGOTIATION-UNOBSERVED') return 'Negotiation not observed';
  if (['QT-HASH-CONTEXT', 'QT-HMAC-PARAMETERS', 'QT-PBKDF2-PARAMETERS'].includes(rule ?? '')) return 'Security context needed';
  if (rule === 'QT-PRESTANDARD-PQC') return 'Draft algorithm needs review';
  return 'Insufficient or unsupported evidence';
}
