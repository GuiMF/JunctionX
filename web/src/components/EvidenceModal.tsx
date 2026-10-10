import React from 'react';
import { X, ExternalLink, ShieldAlert, CheckCircle, FileText, Network, Cloud } from 'lucide-react';
import type { Finding } from '../types/contract';

interface EvidenceModalProps {
  finding: Finding | null;
  onClose: () => void;
}

export const EvidenceModal: React.FC<EvidenceModalProps> = ({ finding, onClose }) => {
  if (!finding) return null;

  const getSourceIcon = (source: string) => {
    switch (source) {
      case 'pcap':
        return <Network className="w-4 h-4 text-cyan-400" />;
      case 'source':
        return <FileText className="w-4 h-4 text-amber-400" />;
      case 'cloud':
        return <Cloud className="w-4 h-4 text-indigo-400" />;
      default:
        return null;
    }
  };

  const getTierBadge = (tier: string) => {
    switch (tier) {
      case 'critical':
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">Critical Exposure</span>;
      case 'medium':
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30">Medium Risk</span>;
      case 'resilient':
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-teal-500/20 text-teal-300 border border-teal-500/30">PQ Resilient</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-500/20 text-slate-300 border border-slate-500/30">Unknown Status</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-slate-800 border border-slate-700">
              {getSourceIcon(finding.source_type)}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white font-mono">{finding.algorithm}</h3>
                {getTierBadge(finding.challenge_tier)}
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">Asset ID: {finding.asset_id}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content body */}
        <div className="p-6 overflow-y-auto space-y-5 text-sm">
          {/* Evidence Card */}
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Verifiable Evidence</span>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-900 px-2 py-0.5 rounded">
                Kind: {finding.evidence_kind}
              </span>
            </div>
            {finding.evidence.map((ev, index) => (
              <div key={index} className="space-y-2 mt-2">
                <div className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
                  <span className="text-slate-500">File:</span>
                  <span className="text-cyan-300 font-semibold">{ev.file}</span>
                  <span className="text-slate-600">|</span>
                  <span className="text-slate-500">Locator:</span>
                  <span className="text-amber-300 font-semibold">{ev.locator}</span>
                </div>
                <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 text-xs text-slate-300 font-mono leading-relaxed whitespace-pre-wrap">
                  {ev.detail}
                </div>
              </div>
            ))}
          </div>

          {/* Rationale & Classification */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Detection & Rationale</h4>
            <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-xs text-slate-300 leading-relaxed">
              <p className="mb-2 font-medium text-slate-200">{finding.rationale}</p>
              <div className="text-[11px] text-slate-500 font-mono">
                Evaluated by Rule: <span className="text-slate-400">{finding.rule_id}</span> | Confidence:{' '}
                <span className="text-slate-400 uppercase">{finding.confidence}</span>
              </div>
            </div>
          </div>

          {/* Classical Issues */}
          {finding.classical_issues.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-amber-400 mb-2 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5" /> Classical Flaws & Policy Warnings
              </h4>
              <ul className="space-y-1.5">
                {finding.classical_issues.map((issue, idx) => (
                  <li
                    key={idx}
                    className="p-2.5 bg-amber-950/20 border border-amber-900/40 rounded-lg text-xs text-amber-200"
                  >
                    {issue}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Actionable Recommendation */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400 mb-2 flex items-center gap-1.5">
              <CheckCircle className="w-3.5 h-3.5" /> Migration Next Step
            </h4>
            <div className="p-3.5 bg-emerald-950/20 border border-emerald-900/40 rounded-xl text-xs text-emerald-200 leading-relaxed font-medium">
              {finding.recommendation}
            </div>
          </div>

          {/* References */}
          {finding.references.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Standardization Sources</h4>
              <div className="space-y-1">
                {finding.references.map((url, i) => (
                  <a
                    key={i}
                    href={url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 hover:underline font-mono"
                  >
                    <ExternalLink className="w-3 h-3" /> {url}
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between text-xs text-slate-400">
          <span>Owner: {finding.owner || 'Unassigned'}</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-medium transition-colors"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
};
