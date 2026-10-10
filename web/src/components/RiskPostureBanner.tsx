import React from 'react';
import { ShieldAlert, KeyRound, AlertTriangle, HelpCircle, Radio, Layers, Settings2 } from 'lucide-react';
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
  let hybridAssets = 0;
  let classicalIssueAssets = 0;
  let postureIssueAssets = 0;
  let offeredOnlyAssets = 0;
  let assetsWithUnknowns = 0;

  for (const group of assetsMap.values()) {
    const active = group.filter((f) => f.evidence_kind !== 'offered');
    if (active.length === 0) {
      offeredOnlyAssets++;
      continue;
    }

    if (active.some((f) => f.quantum_status === 'vulnerable')) {
      quantumVulnerableAssets++;
    }
    if (active.some((f) => f.quantum_status === 'hybrid')) {
      hybridAssets++;
    }
    if (active.some((f) => f.classical_issues && f.classical_issues.length > 0)) {
      classicalIssueAssets++;
    }
    if (active.some((f) => f.posture_issues && f.posture_issues.length > 0)) {
      postureIssueAssets++;
    }
    if (active.some((f) => f.quantum_status !== 'not_applicable' &&
      (f.quantum_status === 'unknown' || f.challenge_tier === 'unknown'))) {
      assetsWithUnknowns++;
    }
  }

  // Use backend score values if available, else derived
  const vuln = score?.quantum_vulnerable_assets ?? quantumVulnerableAssets;
  const hybrid = score?.hybrid_assets ?? hybridAssets;
  const classical = score?.classical_issue_assets ?? classicalIssueAssets;
  const posture = score?.posture_issue_assets ?? postureIssueAssets;
  const offered = score?.offered_only_assets ?? offeredOnlyAssets;
  const unknowns = score?.assets_with_unknowns ?? assetsWithUnknowns;
  const exposureScore = score?.value;

  const finiteScore = typeof exposureScore === 'number' && Number.isFinite(exposureScore);
  const scoreWidth = finiteScore ? Math.min(100, Math.max(0, exposureScore)) : 0;
  const metrics = [
    { label: 'Quantum Vulnerable', value: vuln, icon: ShieldAlert, color: 'text-rose-700', surface: 'bg-rose-50/70' },
    { label: 'Hybrid key establishment', value: hybrid, icon: KeyRound, color: 'text-emerald-700', surface: 'bg-emerald-50/70' },
    { label: 'Classical Weakness', value: classical, icon: AlertTriangle, color: 'text-amber-700', surface: 'bg-amber-50/70' },
    { label: 'Posture Issues', value: posture, icon: Settings2, color: 'text-violet-700', surface: 'bg-violet-50/70' },
    { label: 'Assets with unknowns', value: unknowns, icon: HelpCircle, color: 'text-slate-600', surface: 'bg-slate-50' },
    { label: 'Offered Only', value: offered, icon: Radio, color: 'text-sky-700', surface: 'bg-sky-50/70' },
  ];

  return (
    <div className="overflow-hidden rounded-md border border-slate-200 bg-white">
      <div className="grid xl:grid-cols-[260px_1fr]">
        <div className="border-b border-slate-200 bg-slate-50/60 p-5 xl:border-b-0 xl:border-r">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-slate-500" aria-hidden="true" />
            <h2 className="text-[13px] font-semibold uppercase tracking-[0.06em] text-slate-600">Quantum exposure</h2>
          </div>
          <div className="mt-3 flex items-baseline gap-1.5" aria-label={finiteScore ? `Exposure Score: ${exposureScore}/100` : 'Exposure score unavailable'}>
            <span className="font-mono text-[44px] font-semibold leading-none tracking-[-0.06em] text-slate-900">{finiteScore ? exposureScore : '—'}</span>
            <span className="font-mono text-[15px] text-slate-500">/ 100</span>
          </div>
          <div className="mt-4 h-1.5 overflow-hidden rounded-sm bg-slate-200" aria-hidden="true">
            <div className="h-full bg-rose-500" style={{ width: `${scoreWidth}%` }} />
          </div>
          <p className="mt-2 text-[13px] text-slate-500">Higher means more exposure</p>
          <div className="mt-4 flex items-center gap-1.5 border-t border-slate-200 pt-3 text-[13px] text-slate-600">
            <Layers className="h-3.5 w-3.5 text-slate-500" aria-hidden="true" />
            {typeof score?.assessed_assets === 'number' ? (
              <span><strong className="font-mono font-semibold text-slate-900">{score.assessed_assets}</strong> assessed / <strong className="font-mono font-semibold text-slate-900">{score.total_assets ?? assetsMap.size}</strong> total assets</span>
            ) : (
              <span><strong className="font-mono font-semibold text-slate-900">{assetsMap.size}</strong> unique assets in inventory</span>
            )}
          </div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3">
          {metrics.map((metric, index) => {
            const Icon = metric.icon;
            return (
              <div key={metric.label} className={`min-w-0 p-5 ${metric.surface} ${index < 3 ? 'sm:border-b sm:border-slate-100' : ''} ${index % 3 !== 2 ? 'sm:border-r sm:border-slate-100' : ''}`}>
                <div className="mb-2 flex items-center gap-1.5">
                  <Icon className={`h-4 w-4 shrink-0 ${metric.color}`} aria-hidden="true" />
                  <h3 className="text-[13px] font-medium text-slate-600">{metric.label}</h3>
                </div>
                <div className="flex items-baseline gap-1.5">
                  <strong className={`font-mono text-2xl font-semibold leading-none tracking-tight ${metric.color}`}>{metric.value}</strong>
                  <span className="text-[13px] text-slate-500">Assets</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
