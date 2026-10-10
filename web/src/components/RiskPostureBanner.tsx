import React from 'react';
import { Atom, ShieldAlert, KeyRound, AlertTriangle } from 'lucide-react';
import type { Finding } from '../types/contract';

interface RiskPostureBannerProps {
  findings: Finding[];
}

export const RiskPostureBanner: React.FC<RiskPostureBannerProps> = ({ findings }) => {
  const quantumVulnerableCount = findings.filter((f) => f.quantum_status === 'vulnerable').length;
  const classicalIssuesCount = findings.filter((f) => f.classical_issues.length > 0).length;
  const hybridCount = findings.filter((f) => f.quantum_status === 'hybrid').length;
  const unknownCount = findings.filter((f) => f.quantum_status === 'unknown').length;

  return (
    <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-4">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Atom className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-semibold text-white tracking-tight">
              Cryptographic Posture & Risk Decomposition
            </h2>
          </div>
          <p className="text-xs text-slate-400">
            Strict separation between Shor-vulnerable asymmetric primitives, classical flaws, and operational hygiene.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <div className="flex items-center gap-2 bg-rose-950/40 border border-rose-900/60 px-3 py-1.5 rounded-lg">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <div>
              <span className="text-[10px] text-rose-300 uppercase font-semibold block leading-tight">Quantum Vulnerable</span>
              <span className="text-xs font-mono font-bold text-rose-200">{quantumVulnerableCount} Assets</span>
            </div>
          </div>

          <div className="flex items-center gap-2 bg-amber-950/40 border border-amber-900/60 px-3 py-1.5 rounded-lg">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <div>
              <span className="text-[10px] text-amber-300 uppercase font-semibold block leading-tight">Classical Weaknesses</span>
              <span className="text-xs font-mono font-bold text-amber-200">{classicalIssuesCount} Flags</span>
            </div>
          </div>

          <div className="flex items-center gap-2 bg-teal-950/40 border border-teal-900/60 px-3 py-1.5 rounded-lg">
            <KeyRound className="w-4 h-4 text-teal-400" />
            <div>
              <span className="text-[10px] text-teal-300 uppercase font-semibold block leading-tight">Hybrid / PQC Ready</span>
              <span className="text-xs font-mono font-bold text-teal-200">{hybridCount} Assets</span>
            </div>
          </div>

          <div className="flex items-center gap-2 bg-slate-800/60 border border-slate-700/60 px-3 py-1.5 rounded-lg">
            <div>
              <span className="text-[10px] text-slate-400 uppercase font-semibold block leading-tight">Uncertain / Hidden</span>
              <span className="text-xs font-mono font-bold text-slate-300">{unknownCount} Records</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
