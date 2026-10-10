import React from 'react';
import { Atom, ShieldAlert, KeyRound, AlertTriangle, HelpCircle, Radio } from 'lucide-react';
import type { Finding, ExposureScore } from '../types/contract';

interface RiskPostureBannerProps {
  findings: Finding[];
  score?: ExposureScore | Record<string, any>;
}

export const RiskPostureBanner: React.FC<RiskPostureBannerProps> = ({ findings, score }) => {
  // Deduplicate by asset_id to compute exact unique asset metrics (following core/scoring.py)
  const assetsMap = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = assetsMap.get(f.asset_id) || [];
    list.push(f);
    assetsMap.set(f.asset_id, list);
  }

  let quantumVulnerableAssets = 0;
  let hybridReadyAssets = 0;
  let classicalIssueAssets = 0;
  let postureIssueAssets = 0;
  let offeredOnlyAssets = 0;
  let unknownAssets = 0;

  for (const group of assetsMap.values()) {
    const active = group.filter((f) => f.evidence_kind !== 'offered');
    if (active.length === 0) {
      offeredOnlyAssets++;
      continue;
    }

    if (active.some((f) => f.quantum_status === 'vulnerable')) {
      quantumVulnerableAssets++;
    }
    if (active.some((f) => f.quantum_status === 'hybrid' || f.quantum_status === 'resistant_primitive')) {
      hybridReadyAssets++;
    }
    if (active.some((f) => f.classical_issues && f.classical_issues.length > 0)) {
      classicalIssueAssets++;
    }
    if (active.some((f) => f.posture_issues && f.posture_issues.length > 0)) {
      postureIssueAssets++;
    }
    if (active.every((f) => f.quantum_status === 'unknown')) {
      unknownAssets++;
    }
  }

  // Use backend score values if available, else derived
  const vuln = score?.quantum_vulnerable_assets ?? quantumVulnerableAssets;
  const hybrid = score?.hybrid_assets ?? hybridReadyAssets;
  const classical = score?.classical_issue_assets ?? classicalIssueAssets;
  const posture = score?.posture_issue_assets ?? postureIssueAssets;
  const offered = score?.offered_only_assets ?? offeredOnlyAssets;
  const unknowns = score?.unknown_assets ?? unknownAssets;
  const exposureScore = score?.value;

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 shadow-sm">
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Atom className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-semibold text-white tracking-tight">
              Cryptographic Posture & Risk Decomposition
            </h2>
            {typeof exposureScore === 'number' && (
              <span className="ml-2 text-xs font-mono font-bold bg-rose-950/80 text-rose-300 border border-rose-800/80 px-2 py-0.5 rounded-full">
                Exposure Score: {exposureScore}/100
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400">
            Deduplicated asset counts separating Shor vulnerability from classical flaws, operational posture, and unselected offers.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          {/* Quantum Vulnerable */}
          <div className="flex items-center gap-2 bg-rose-950/40 border border-rose-900/60 px-3 py-1.5 rounded-lg">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <div>
              <span className="text-[10px] text-rose-300 uppercase font-semibold block leading-tight">Quantum Vulnerable</span>
              <span className="text-xs font-mono font-bold text-rose-200">{vuln} Assets</span>
            </div>
          </div>

          {/* Hybrid / PQC Ready (Negotiated or Configured only) */}
          <div className="flex items-center gap-2 bg-teal-950/40 border border-teal-900/60 px-3 py-1.5 rounded-lg">
            <KeyRound className="w-4 h-4 text-teal-400" />
            <div>
              <span className="text-[10px] text-teal-300 uppercase font-semibold block leading-tight">PQC Active</span>
              <span className="text-xs font-mono font-bold text-teal-200">{hybrid} Assets</span>
            </div>
          </div>

          {/* Classical Weaknesses */}
          <div className="flex items-center gap-2 bg-amber-950/40 border border-amber-900/60 px-3 py-1.5 rounded-lg">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <div>
              <span className="text-[10px] text-amber-300 uppercase font-semibold block leading-tight">Classical Weakness</span>
              <span className="text-xs font-mono font-bold text-amber-200">{classical} Assets</span>
            </div>
          </div>

          {/* Operational Posture Issues */}
          {posture > 0 && (
            <div className="flex items-center gap-2 bg-purple-950/40 border border-purple-900/60 px-3 py-1.5 rounded-lg">
              <div>
                <span className="text-[10px] text-purple-300 uppercase font-semibold block leading-tight">Posture Issues</span>
                <span className="text-xs font-mono font-bold text-purple-200">{posture} Assets</span>
              </div>
            </div>
          )}

          {/* Offered-Only Capabilities */}
          {offered > 0 && (
            <div className="flex items-center gap-2 bg-sky-950/40 border border-sky-900/60 px-3 py-1.5 rounded-lg" title="Client advertised only; unverified or classical negotiation">
              <Radio className="w-3.5 h-3.5 text-sky-400" />
              <div>
                <span className="text-[10px] text-sky-300 uppercase font-semibold block leading-tight">Offered Only</span>
                <span className="text-xs font-mono font-bold text-sky-200">{offered} Assets</span>
              </div>
            </div>
          )}

          {/* Unknown / Hidden */}
          <div className="flex items-center gap-2 bg-slate-800/60 border border-slate-700/60 px-3 py-1.5 rounded-lg">
            <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
            <div>
              <span className="text-[10px] text-slate-400 uppercase font-semibold block leading-tight">Unknown</span>
              <span className="text-xs font-mono font-bold text-slate-300">{unknowns} Assets</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
