import React, { useState } from 'react';
import { Search, ArrowRight, Network, FileCode2, Cloud, AlertCircle, ShieldAlert, ListFilter, X } from 'lucide-react';
import type { Finding, SourceType, ChallengeTier, EvidenceKind } from '../types/contract';
import { assessmentGap, assessmentLabel, assessmentTier } from '../utils/assessment';

interface FindingsTableProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  selectedFindingId?: string;
}
const tierStyles: Record<ChallengeTier, string> = {
  critical: 'border-rose-200 bg-rose-50 text-rose-600',
  medium: 'border-amber-200 bg-amber-50 text-amber-700',
  resilient: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  unknown: 'border-slate-200 bg-slate-100 text-slate-600',
};
const sourceLabels: Record<SourceType, string> = { pcap: 'Network', source: 'Source code', cloud: 'Cloud' };
const sourceStyles: Record<SourceType, string> = { pcap: 'text-sky-700', source: 'text-violet-700', cloud: 'text-cyan-700' };
const evidenceStyles: Record<EvidenceKind, string> = { observed: 'border-sky-200 bg-sky-50 text-sky-800', offered: 'border-amber-200 bg-amber-50 text-amber-800', configured: 'border-cyan-200 bg-cyan-50 text-cyan-800', declared: 'border-violet-200 bg-violet-50 text-violet-800' };
const sourceIcons = { pcap: Network, source: FileCode2, cloud: Cloud };
const evidenceDescriptions: Record<EvidenceKind, string> = {
  observed: 'Seen in captured traffic',
  offered: 'Advertised capability; not necessarily negotiated',
  configured: 'Present in cloud configuration; runtime behavior not verified',
  declared: 'Present in source code',
};
const filterClass = 'h-9 rounded border border-slate-300 bg-white pl-2.5 pr-6 text-[13px] text-slate-600 focus:border-sky-600 focus:outline-none focus:ring-1 focus:ring-sky-600';

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings, onSelectFinding, selectedFindingId }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSource, setSelectedSource] = useState('all');
  const [selectedTier, setSelectedTier] = useState('all');
  const [selectedEvidenceKind, setSelectedEvidenceKind] = useState('all');
  const [selectedOwner, setSelectedOwner] = useState('all');
  const [selectedGap, setSelectedGap] = useState('all');
  const gaps = new Map<string, number>();
  for (const finding of findings) {
    const gap = assessmentGap(finding);
    if (gap) gaps.set(gap, (gaps.get(gap) ?? 0) + 1);
  }
  const owners = Array.from(new Set(findings.flatMap((finding) => finding.owner ? [finding.owner] : []))).sort();
  const query = searchTerm.trim().toLowerCase();
  const filteredFindings = findings.filter((finding) => {
    const searchable = [finding.algorithm, finding.asset_id, finding.owner ?? '', ...finding.evidence.flatMap((evidence) => [evidence.file, evidence.locator])];
    return (!query || searchable.some((value) => value.toLowerCase().includes(query)))
      && (selectedSource === 'all' || finding.source_type === selectedSource)
      && (selectedTier === 'all' || assessmentTier(finding) === selectedTier)
      && (selectedGap === 'all' || assessmentGap(finding) === selectedGap)
      && (selectedEvidenceKind === 'all' || finding.evidence_kind === selectedEvidenceKind)
      && (selectedOwner === 'all' || (selectedOwner === '__unassigned' ? !finding.owner : finding.owner === selectedOwner));
  });
  const activeFilters = [selectedSource, selectedTier, selectedEvidenceKind, selectedOwner, selectedGap].filter((value) => value !== 'all').length + (query ? 1 : 0);
  const resetFilters = () => { setSearchTerm(''); setSelectedSource('all'); setSelectedTier('all'); setSelectedEvidenceKind('all'); setSelectedOwner('all'); setSelectedGap('all'); };

  return (
    <section className="overflow-hidden rounded-lg border border-slate-200 bg-white" aria-labelledby="inventory-heading">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-5 py-4">
        <div className="flex items-center gap-2.5"><h2 id="inventory-heading" className="text-[15px] font-semibold text-slate-900">Cryptographic inventory</h2><span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[13px] text-slate-500">{findings.length}</span></div>
      </div>
      <div className="space-y-3 border-b border-slate-200 px-5 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[220px] flex-1"><Search aria-hidden="true" className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-500" /><input aria-label="Search findings" type="search" placeholder="Search algorithms, assets, owners…" value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} className="h-9 w-full rounded border border-slate-300 bg-white pl-8 pr-3 text-[13px] text-slate-900 placeholder:text-slate-500 focus:border-sky-600 focus:outline-none focus:ring-1 focus:ring-sky-600" /></div>
          <ListFilter aria-hidden="true" className="ml-1 hidden h-4 w-4 text-slate-500 xl:block" />
          <select aria-label="Filter by source" value={selectedSource} onChange={(event) => setSelectedSource(event.target.value)} className={filterClass}><option value="all">All sources</option><option value="pcap">Network</option><option value="source">Source code</option><option value="cloud">Cloud</option></select>
          <select aria-label="Filter by quantum tier" value={selectedTier} onChange={(event) => setSelectedTier(event.target.value)} className={filterClass}><option value="all">All tiers</option><option value="critical">Critical</option><option value="medium">Medium</option><option value="resilient">Resilient</option><option value="unknown">Unknown</option><option value="not_applicable">Not applicable</option></select>
          <select aria-label="Filter by evidence kind" value={selectedEvidenceKind} onChange={(event) => setSelectedEvidenceKind(event.target.value)} className={filterClass}><option value="all">All evidence</option><option value="observed">Observed</option><option value="offered">Offered</option><option value="configured">Configured</option><option value="declared">Declared</option></select>
          <select aria-label="Filter by owner" value={selectedOwner} onChange={(event) => setSelectedOwner(event.target.value)} className={filterClass}><option value="all">All owners</option><option value="__unassigned">Unassigned</option>{owners.map((owner) => <option key={owner} value={owner}>{owner}</option>)}</select>
        </div>
        {activeFilters > 0 && <div className="flex items-center justify-between text-[13px] text-slate-500" aria-live="polite"><span>{filteredFindings.length} of {findings.length} findings · {activeFilters} active {activeFilters === 1 ? 'filter' : 'filters'}</span><button onClick={resetFilters} className="inline-flex items-center gap-1 font-medium text-sky-700 hover:text-sky-900"><X className="h-3 w-3" />Clear filters</button></div>}
      </div>
      {gaps.size > 0 && <details className="border-b border-slate-200 bg-slate-50 px-5 py-3 text-[13px]">
        <summary className="cursor-pointer font-medium text-slate-700">Why are {Array.from(gaps.values()).reduce((total, count) => total + count, 0)} findings unresolved?</summary>
        <p className="mt-2 text-slate-600">These counts describe findings, not unique assets or failed scans. Select a reason to inspect the evidence and recommended action.</p>
        <div className="mt-2 flex flex-wrap gap-2">{Array.from(gaps).map(([reason, count]) => <button key={reason} aria-pressed={selectedGap === reason} onClick={() => { resetFilters(); setSelectedGap(reason); }} className="rounded border border-slate-300 bg-white px-2 py-1 text-sky-800 hover:bg-sky-50">{reason}: {count}</button>)}</div>
      </details>}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[900px] border-collapse text-left text-[13px]">
          <thead className="border-b border-sky-100 bg-sky-50/60 text-[12px] uppercase tracking-[0.06em] text-slate-500"><tr><th scope="col" className="px-5 py-2.5 font-semibold">Quantum tier</th><th scope="col" className="px-3 py-2.5 font-semibold">Algorithm / usage</th><th scope="col" className="px-3 py-2.5 font-semibold">Asset / location</th><th scope="col" className="px-3 py-2.5 font-semibold">Source</th><th scope="col" className="px-3 py-2.5 font-semibold">Evidence</th><th scope="col" className="px-3 py-2.5 font-semibold">Owner</th><th scope="col" className="px-4 py-2.5 text-right font-semibold">Inspect</th></tr></thead>
          <tbody className="divide-y divide-slate-100">
            {filteredFindings.map((finding) => {
              const SourceIcon = sourceIcons[finding.source_type];
              return <tr key={finding.id} onClick={() => onSelectFinding(finding)} className={`group cursor-pointer hover:bg-slate-50 ${selectedFindingId === finding.id ? 'bg-sky-50' : 'bg-white'}`}>
                <td className="whitespace-nowrap px-5 py-3"><span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[12px] font-semibold capitalize ${tierStyles[finding.challenge_tier]}`}>{assessmentLabel(finding)}</span>{assessmentGap(finding) && <div className="mt-1 whitespace-normal text-[12px] text-slate-500" title={finding.rationale ?? undefined}>{assessmentGap(finding)}</div>}</td>
                <td className="px-3 py-3"><div className="whitespace-nowrap font-mono text-[13px] font-medium text-slate-900 group-hover:text-sky-700">{finding.algorithm}</div><div className="mt-1 flex items-center gap-1.5 text-[12px] text-slate-500"><span className="capitalize">{finding.usage.replace(/_/g, ' ')}</span>{finding.classical_issues.length > 0 && <span title="Classical weakness detected" aria-label="Classical weakness detected"><AlertCircle className="h-3 w-3 text-amber-600" /></span>}{finding.posture_issues.length > 0 && <span title="Operational issue detected" aria-label="Operational issue detected"><ShieldAlert className="h-3 w-3 text-slate-500" /></span>}</div></td>
                <td className="max-w-[240px] px-3 py-3"><div title={finding.asset_id} className="truncate font-mono text-[13px] text-slate-700">{finding.asset_id}</div><div title={finding.evidence[0]?.locator} className="mt-1 truncate font-mono text-[12px] text-slate-500">{finding.evidence[0]?.locator || 'No locator available'}</div></td>
                <td className="whitespace-nowrap px-3 py-3"><div className={`flex items-center gap-1.5 text-[13px] ${sourceStyles[finding.source_type]}`}><SourceIcon className="h-4 w-4" />{sourceLabels[finding.source_type]}</div></td>
                <td className="px-3 py-3"><span title={evidenceDescriptions[finding.evidence_kind]} className={`rounded border px-2 py-1 font-mono text-[12px] capitalize ${evidenceStyles[finding.evidence_kind]}`}>{finding.evidence_kind}</span></td>
                <td className="whitespace-nowrap px-3 py-3 text-[13px] text-slate-500">{finding.owner || 'Unassigned'}</td>
                <td className="px-4 py-3 text-right"><button aria-label={`View evidence for ${finding.algorithm} on ${finding.asset_id}`} onClick={(event) => { event.stopPropagation(); onSelectFinding(finding); }} className="inline-flex h-7 w-7 items-center justify-center rounded border border-transparent text-slate-500 hover:border-sky-200 hover:bg-sky-50 hover:text-sky-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-500"><ArrowRight className="h-4 w-4" /></button></td>
              </tr>;
            })}
            {filteredFindings.length === 0 && <tr><td colSpan={7} className="px-5 py-14 text-center"><Search className="mx-auto mb-3 h-6 w-6 text-slate-300" /><p className="font-medium text-slate-700">No matching findings</p><p className="mt-1 text-slate-500">Try a different search or clear your filters.</p>{activeFilters > 0 && <button onClick={resetFilters} className="mt-3 text-sky-700 hover:underline">Clear filters</button>}</td></tr>}
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200 bg-slate-50/70 px-5 py-2.5 text-[13px] text-slate-500"><span aria-live="polite">Showing {filteredFindings.length} of {findings.length} findings</span></div>
    </section>
  );
};
