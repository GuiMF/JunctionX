import React from 'react';
import { Network, FileCode, Cloud } from 'lucide-react';
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
      label: 'TLS handshakes · PCAP',
      accent: 'border-t-sky-400',
      iconStyle: 'border-sky-200 bg-sky-50 text-sky-700',
    },
    {
      title: 'Source Code',
      icon: FileCode,
      stats: aggregate('source'),
      label: 'Python · Java · Go',
      accent: 'border-t-sky-400',
      iconStyle: 'border-violet-200 bg-violet-50 text-violet-700',
    },
    {
      title: 'Cloud Infrastructure',
      icon: Cloud,
      stats: aggregate('cloud'),
      label: 'AWS KMS · ALB · ACM',
      accent: 'border-t-sky-400',
      iconStyle: 'border-cyan-200 bg-cyan-50 text-cyan-700',
    }
  ];

  return (
    <div className="grid grid-cols-1 gap-3">
      {cards.map((card) => {
        const Icon = card.icon;

        return (
          <div
            key={card.title}
            className={`rounded-md border border-t-[3px] border-slate-200 bg-white p-3 ${card.accent}`}
          >
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className={`rounded border p-2 ${card.iconStyle}`}>
                    <Icon className="h-4 w-4" aria-hidden="true" />
                  </div>
                  <div>
                    <h3 className="text-[15px] font-semibold text-slate-900">{card.title}</h3>
                    <p className="mt-0.5 text-[13px] text-slate-500">{card.label}</p>
                  </div>
                </div>
              </div>

              {card.stats.length === 0 && (
                <p className="mt-4 border-t border-slate-100 pt-3 text-[13px] text-slate-500">No coverage reported.</p>
              )}
              {card.stats.map((stats) => {
                const total = stats.assessed + stats.unknown + stats.unsupported + stats.failed;
                const segments = [
                  { label: 'Assessed', value: stats.assessed, color: 'bg-sky-500', text: 'text-sky-700' },
                  { label: 'Unknown', value: stats.unknown, color: 'bg-amber-400', text: 'text-amber-700' },
                  { label: 'Unsupp.', value: stats.unsupported, color: 'bg-slate-300', text: 'text-slate-500' },
                  { label: 'Failed', value: stats.failed, color: 'bg-rose-500', text: stats.failed > 0 ? 'text-rose-600' : 'text-slate-500' },
                ];
                return (
                <section key={stats.unit} aria-label={`${card.title}: ${stats.unit}`} className="mt-3 border-t border-slate-100 pt-2">
                  <div className="mb-2 flex items-baseline gap-1.5 text-slate-900">
                    <strong className="font-mono text-2xl font-semibold tracking-tight">{total}</strong>{' '}
                    <span className="text-[13px] text-slate-500">{stats.unit}</span>
                  </div>
                  <div className="mb-3 flex h-1.5 overflow-hidden rounded-sm bg-slate-100" aria-hidden="true">
                    {segments.map((segment) => (
                      <div key={segment.label} className={segment.color} style={{ width: `${total > 0 ? (segment.value / total) * 100 : 0}%` }} />
                    ))}
                  </div>
                  <div className="grid grid-cols-4 gap-2">
                    {segments.map((segment) => (
                      <div key={segment.label}>
                        <span className={`block text-[12px] font-medium ${segment.text}`} title={segment.label === 'Unsupp.' ? 'Unsupported' : undefined}>{segment.label}</span>
                        <span className="mt-1.5 block font-mono text-xl font-medium leading-7 text-slate-900">{segment.value}</span>
                      </div>
                    ))}
                  </div>
                </section>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
};
