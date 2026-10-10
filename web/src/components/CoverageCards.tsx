import React from 'react';
import { Network, FileCode, Cloud, HelpCircle, AlertOctagon, XCircle } from 'lucide-react';
import type { CoverageItem, SourceType } from '../types/contract';

interface CoverageCardsProps {
  coverage: CoverageItem[];
}

export const CoverageCards: React.FC<CoverageCardsProps> = ({ coverage }) => {
  // Aggregate per source_type
  const aggregate = (type: SourceType) => {
    const items = coverage.filter((c) => c.source_type === type);
    const assessed = items.reduce((sum, i) => sum + i.assessed, 0);
    const unknown = items.reduce((sum, i) => sum + i.unknown, 0);
    const unsupported = items.reduce((sum, i) => sum + i.unsupported, 0);
    const failed = items.reduce((sum, i) => sum + i.failed, 0);
    const unit = items[0]?.unit || (type === 'pcap' ? 'sessions' : type === 'source' ? 'files' : 'resources');
    return { assessed, unknown, unsupported, failed, unit };
  };

  const cards = [
    {
      title: 'Network Traffic',
      icon: Network,
      stats: aggregate('pcap'),
      label: 'PCAP Dissection (TShark)',
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/10',
      borderColor: 'border-cyan-500/20'
    },
    {
      title: 'Source Code',
      icon: FileCode,
      stats: aggregate('source'),
      label: 'Python, Java, Go Repositories',
      color: 'text-amber-400',
      bgColor: 'bg-amber-500/10',
      borderColor: 'border-amber-500/20'
    },
    {
      title: 'Cloud Infrastructure',
      icon: Cloud,
      stats: aggregate('cloud'),
      label: 'AWS KMS, ALB, ACM Certificates',
      color: 'text-indigo-400',
      bgColor: 'bg-indigo-500/10',
      borderColor: 'border-indigo-500/20'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {cards.map((card) => {
        const Icon = card.icon;
        const total =
          card.stats.assessed +
          card.stats.unknown +
          card.stats.unsupported +
          card.stats.failed;

        return (
          <div
            key={card.title}
            className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col justify-between shadow-sm relative overflow-hidden"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <div className={`p-2 rounded-lg ${card.bgColor} ${card.color} ${card.borderColor} border`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200">{card.title}</h3>
                    <p className="text-[11px] text-slate-400">{card.label}</p>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-lg font-bold text-white font-mono">{total}</span>
                  <span className="text-[10px] text-slate-500 block uppercase tracking-wider">{card.stats.unit}</span>
                </div>
              </div>

              {/* 4-way disjoint coverage breakdown: Assessed, Unknown, Unsupported, Failed */}
              <div className="grid grid-cols-4 gap-1.5 mt-3 pt-3 border-t border-slate-800/80 text-center">
                <div className="bg-slate-950/40 rounded-lg p-1.5 border border-slate-800/50">
                  <span className="text-[9px] text-emerald-400 font-medium block">Assessed</span>
                  <span className="text-xs font-mono font-bold text-slate-200">{card.stats.assessed}</span>
                </div>
                <div className="bg-slate-950/40 rounded-lg p-1.5 border border-slate-800/50">
                  <span className="text-[9px] text-amber-400 font-medium flex items-center justify-center gap-0.5">
                    <HelpCircle className="w-2.5 h-2.5" /> Unknown
                  </span>
                  <span className="text-xs font-mono font-bold text-slate-200">{card.stats.unknown}</span>
                </div>
                <div className="bg-slate-950/40 rounded-lg p-1.5 border border-slate-800/50">
                  <span className="text-[9px] text-slate-400 font-medium flex items-center justify-center gap-0.5">
                    <AlertOctagon className="w-2.5 h-2.5" /> Unsupp.
                  </span>
                  <span className="text-xs font-mono font-bold text-slate-200">{card.stats.unsupported}</span>
                </div>
                <div
                  className={`rounded-lg p-1.5 border ${
                    card.stats.failed > 0
                      ? 'bg-rose-950/40 border-rose-800 text-rose-300'
                      : 'bg-slate-950/40 border-slate-800/50 text-slate-400'
                  }`}
                >
                  <span className="text-[9px] font-medium flex items-center justify-center gap-0.5">
                    <XCircle className="w-2.5 h-2.5" /> Failed
                  </span>
                  <span className="text-xs font-mono font-bold">{card.stats.failed}</span>
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};
