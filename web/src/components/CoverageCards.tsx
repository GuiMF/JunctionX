import React from 'react';
import { Network, FileCode, Cloud, HelpCircle, AlertOctagon, XCircle } from 'lucide-react';
import type { CoverageItem, CoverageUnit, SourceType } from '../types/contract';

interface CoverageCardsProps {
  coverage: CoverageItem[];
}

export const CoverageCards: React.FC<CoverageCardsProps> = ({ coverage }) => {
  // Different units describe different populations, even within the same source.
  const aggregate = (type: SourceType) => {
    const groups = new Map<CoverageUnit, CoverageItem>();
    for (const item of coverage.filter((c) => c.source_type === type)) {
      const group = groups.get(item.unit);
      if (group) {
        group.assessed += item.assessed;
        group.unknown += item.unknown;
        group.unsupported += item.unsupported;
        group.failed += item.failed;
      } else {
        groups.set(item.unit, { ...item });
      }
    }
    return Array.from(groups.values());
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
              </div>

              {card.stats.length === 0 && (
                <p className="text-xs text-slate-400 mt-3">No coverage reported.</p>
              )}
              {card.stats.map((stats) => (
                <section key={stats.unit} aria-label={`${card.title}: ${stats.unit}`} className="mt-3 pt-3 border-t border-slate-800/80">
                  <div className="text-sm font-mono text-white mb-2">
                    <strong>{stats.assessed + stats.unknown + stats.unsupported + stats.failed}</strong>{' '}
                    <span className="text-slate-400">{stats.unit}</span>
                  </div>
                  {/* 4-way disjoint coverage breakdown: Assessed, Unknown, Unsupported, Failed */}
                  <div className="grid grid-cols-4 gap-1.5 text-center">
                    <div className="bg-slate-950/40 rounded-lg p-1.5 border border-slate-800/50">
                      <span className="text-[9px] text-emerald-400 font-medium block">Assessed</span>
                      <span className="text-xs font-mono font-bold text-slate-200">{stats.assessed}</span>
                    </div>
                    <div className="bg-slate-950/40 rounded-lg p-1.5 border border-slate-800/50">
                      <span className="text-[9px] text-amber-400 font-medium flex items-center justify-center gap-0.5">
                        <HelpCircle className="w-2.5 h-2.5" /> Unknown
                      </span>
                      <span className="text-xs font-mono font-bold text-slate-200">{stats.unknown}</span>
                    </div>
                    <div className="bg-slate-950/40 rounded-lg p-1.5 border border-slate-800/50">
                      <span className="text-[9px] text-slate-400 font-medium flex items-center justify-center gap-0.5">
                        <AlertOctagon className="w-2.5 h-2.5" /> Unsupp.
                      </span>
                      <span className="text-xs font-mono font-bold text-slate-200">{stats.unsupported}</span>
                    </div>
                    <div
                      className={`rounded-lg p-1.5 border ${
                        stats.failed > 0
                          ? 'bg-rose-950/40 border-rose-800 text-rose-300'
                          : 'bg-slate-950/40 border-slate-800/50 text-slate-400'
                      }`}
                    >
                      <span className="text-[9px] font-medium flex items-center justify-center gap-0.5">
                        <XCircle className="w-2.5 h-2.5" /> Failed
                      </span>
                      <span className="text-xs font-mono font-bold">{stats.failed}</span>
                    </div>
                  </div>
                </section>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
};
