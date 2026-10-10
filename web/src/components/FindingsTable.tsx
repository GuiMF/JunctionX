import React, { useState } from 'react';
import { Search, ArrowUpRight, Network, FileText, Cloud, AlertCircle, ShieldAlert } from 'lucide-react';
import type { Finding, SourceType, ChallengeTier, EvidenceKind } from '../types/contract';

interface FindingsTableProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings, onSelectFinding }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSource, setSelectedSource] = useState<string>('all');
  const [selectedTier, setSelectedTier] = useState<string>('all');
  const [selectedEvidenceKind, setSelectedEvidenceKind] = useState<string>('all');
  const [selectedOwner, setSelectedOwner] = useState<string>('all');

  const owners = Array.from(new Set(findings.map((f) => f.owner).filter(Boolean))) as string[];

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      searchTerm === '' ||
      f.algorithm.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.asset_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.owner && f.owner.toLowerCase().includes(searchTerm.toLowerCase())) ||
      f.evidence.some((e) => e.file.toLowerCase().includes(searchTerm.toLowerCase()) || e.locator.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesSource = selectedSource === 'all' || f.source_type === selectedSource;
    const matchesTier = selectedTier === 'all' || f.challenge_tier === selectedTier;
    const matchesEvidence = selectedEvidenceKind === 'all' || f.evidence_kind === selectedEvidenceKind;
    const matchesOwner = selectedOwner === 'all' || f.owner === selectedOwner;

    return matchesSearch && matchesSource && matchesTier && matchesEvidence && matchesOwner;
  });

  const getSourceIcon = (source: SourceType) => {
    switch (source) {
      case 'pcap':
        return (
          <span title="Network Capture">
            <Network className="w-3.5 h-3.5 text-cyan-400" />
          </span>
        );
      case 'source':
        return (
          <span title="Source Code">
            <FileText className="w-3.5 h-3.5 text-amber-400" />
          </span>
        );
      case 'cloud':
        return (
          <span title="Cloud Resource">
            <Cloud className="w-3.5 h-3.5 text-indigo-400" />
          </span>
        );
    }
  };

  const getTierBadge = (tier: ChallengeTier) => {
    switch (tier) {
      case 'critical':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-500/15 text-rose-300 border border-rose-500/30">Critical</span>;
      case 'medium':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">Medium</span>;
      case 'resilient':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-teal-500/15 text-teal-300 border border-teal-500/30">Resilient</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-500/15 text-slate-300 border border-slate-500/30">Unknown</span>;
    }
  };

  const getEvidenceKindBadge = (kind: EvidenceKind) => {
    const colors: Record<EvidenceKind, string> = {
      observed: 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60',
      offered: 'text-amber-400 bg-amber-950/60 border-amber-800/60',
      configured: 'text-cyan-400 bg-cyan-950/60 border-cyan-800/60',
      declared: 'text-purple-400 bg-purple-950/60 border-purple-800/60'
    };
    return (
      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${colors[kind]}`}>
        {kind}
      </span>
    );
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
      {/* Filters Toolbar */}
      <div className="p-4 border-b border-slate-800 bg-slate-950/30 space-y-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by algorithm, asset, owner, or locator..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={selectedSource}
              onChange={(e) => setSelectedSource(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-slate-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-emerald-500"
            >
              <option value="all">All Sources</option>
              <option value="pcap">PCAP Network</option>
              <option value="source">Source Code</option>
              <option value="cloud">AWS Cloud</option>
            </select>

            <select
              value={selectedTier}
              onChange={(e) => setSelectedTier(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-slate-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-emerald-500"
            >
              <option value="all">All Tiers</option>
              <option value="critical">Critical</option>
              <option value="medium">Medium</option>
              <option value="resilient">Resilient</option>
              <option value="unknown">Unknown</option>
            </select>

            <select
              value={selectedEvidenceKind}
              onChange={(e) => setSelectedEvidenceKind(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-slate-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-emerald-500"
            >
              <option value="all">All Evidence Kinds</option>
              <option value="observed">Observed (Wire)</option>
              <option value="offered">Offered (ClientHello)</option>
              <option value="configured">Configured (Cloud)</option>
              <option value="declared">Declared (Source)</option>
            </select>

            <select
              value={selectedOwner}
              onChange={(e) => setSelectedOwner(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-slate-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-emerald-500"
            >
              <option value="all">All Owners</option>
              {owners.map((owner) => (
                <option key={owner} value={owner}>
                  {owner}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex items-center justify-between text-xs text-slate-400">
          <span>Showing <strong className="text-white">{filteredFindings.length}</strong> of {findings.length} findings</span>
          {(searchTerm || selectedSource !== 'all' || selectedTier !== 'all' || selectedEvidenceKind !== 'all' || selectedOwner !== 'all') && (
            <button
              onClick={() => {
                setSearchTerm('');
                setSelectedSource('all');
                setSelectedTier('all');
                setSelectedEvidenceKind('all');
                setSelectedOwner('all');
              }}
              className="text-emerald-400 hover:underline"
            >
              Reset filters
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/50 text-slate-400 uppercase text-[10px] tracking-wider">
              <th className="py-3 px-4">Tier</th>
              <th className="py-3 px-4">Algorithm & Usage</th>
              <th className="py-3 px-4">Source</th>
              <th className="py-3 px-4">Evidence Kind</th>
              <th className="py-3 px-4">Primary Locator</th>
              <th className="py-3 px-4">Owner</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filteredFindings.map((finding) => (
              <tr
                key={finding.id}
                onClick={() => onSelectFinding(finding)}
                className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
              >
                <td className="py-3 px-4 whitespace-nowrap">
                  {getTierBadge(finding.challenge_tier)}
                </td>
                <td className="py-3 px-4">
                  <div className="font-semibold text-slate-200 font-mono text-xs group-hover:text-emerald-400 transition-colors">
                    {finding.algorithm}
                  </div>
                  <div className="text-[11px] text-slate-400 capitalize">
                    {finding.usage.replace('_', ' ')}
                    {finding.classical_issues && finding.classical_issues.length > 0 && (
                      <span className="ml-2 inline-flex items-center text-amber-400 text-[10px]" title="Classical weakness detected">
                        <AlertCircle className="w-2.5 h-2.5 mr-0.5 inline" /> Classical flaw
                      </span>
                    )}
                    {finding.posture_issues && finding.posture_issues.length > 0 && (
                      <span className="ml-2 inline-flex items-center text-purple-400 text-[10px]" title="Posture issue detected">
                        <ShieldAlert className="w-2.5 h-2.5 mr-0.5 inline" /> Posture issue
                      </span>
                    )}
                  </div>
                </td>
                <td className="py-3 px-4 whitespace-nowrap">
                  <div className="flex items-center gap-1.5 text-slate-300 font-mono capitalize">
                    {getSourceIcon(finding.source_type)}
                    <span>{finding.source_type}</span>
                  </div>
                </td>
                <td className="py-3 px-4 whitespace-nowrap">
                  {getEvidenceKindBadge(finding.evidence_kind)}
                </td>
                <td className="py-3 px-4 font-mono text-slate-400 text-[11px] max-w-[220px] truncate" title={finding.evidence[0]?.locator}>
                  {finding.evidence[0]?.locator || 'N/A'}
                </td>
                <td className="py-3 px-4 whitespace-nowrap text-slate-300">
                  {finding.owner ? (
                    <span className="bg-slate-800 px-2 py-0.5 rounded text-[11px] font-mono text-slate-300 border border-slate-700">
                      {finding.owner}
                    </span>
                  ) : (
                    <span className="text-slate-500 italic text-[11px]">Unassigned</span>
                  )}
                </td>
                <td className="py-3 px-4 text-right whitespace-nowrap">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelectFinding(finding);
                    }}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-emerald-500 hover:text-slate-950 text-slate-300 text-xs font-medium transition-colors"
                  >
                    Evidence <ArrowUpRight className="w-3 h-3" />
                  </button>
                </td>
              </tr>
            ))}
            {filteredFindings.length === 0 && (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-400">
                  No findings match the selected filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
