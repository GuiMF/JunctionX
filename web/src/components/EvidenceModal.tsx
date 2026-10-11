import React, { useEffect, useRef } from 'react';
import { X, ExternalLink, ShieldAlert, ArrowRight, FileText, Network, Cloud, ScanLine } from 'lucide-react';
import type { Finding, EvidenceKind } from '../types/contract';

interface EvidenceModalProps { finding: Finding | null; onClose: () => void; }
const evidenceDescriptions: Record<EvidenceKind, string> = {
  observed: 'Observed in captured traffic.',
  offered: 'Advertised by a client. This does not establish the negotiated algorithm.',
  configured: 'Present in cloud configuration. Runtime negotiation has not been verified by this evidence.',
  declared: 'Declared in source code. This does not establish runtime execution.',
};
const tierStyles = {
  critical: 'border-rose-200 bg-rose-50 text-rose-600', medium: 'border-amber-200 bg-amber-50 text-amber-700',
  resilient: 'border-emerald-200 bg-emerald-50 text-emerald-700', unknown: 'border-slate-200 bg-slate-100 text-slate-600',
};

export const EvidenceModal: React.FC<EvidenceModalProps> = ({ finding, onClose }) => {
  const drawerRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const isOpen = !!finding;
  useEffect(() => {
    if (!isOpen) return;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    closeRef.current?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); onCloseRef.current(); }
      if (event.key !== 'Tab') return;
      const elements = Array.from(drawerRef.current?.querySelectorAll<HTMLElement>('button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), [tabindex="0"]') ?? []);
      const first = elements[0];
      const last = elements[elements.length - 1];
      if (event.shiftKey && (document.activeElement === first || !drawerRef.current?.contains(document.activeElement))) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || !drawerRef.current?.contains(document.activeElement))) { event.preventDefault(); first?.focus(); }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => { document.removeEventListener('keydown', handleKeyDown); document.body.style.overflow = previousOverflow; previousFocus?.focus(); };
  }, [isOpen]);
  if (!finding) return null;
  const SourceIcon = finding.source_type === 'pcap' ? Network : finding.source_type === 'source' ? FileText : Cloud;
  const sourceLabel = finding.source_type === 'pcap' ? 'Network capture' : finding.source_type === 'source' ? 'Source code' : 'Cloud configuration';

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-900/20" onClick={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <div ref={drawerRef} role="dialog" aria-modal="true" aria-labelledby="evidence-title" aria-describedby="evidence-description" className="flex h-full w-full max-w-[600px] flex-col border-l border-slate-300 bg-white shadow-xl">
        <header className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-6 py-3.5">
          <div className="flex items-center gap-2 text-[13px] font-semibold text-slate-600"><ScanLine className="h-4 w-4 text-sky-600" />Evidence inspector</div>
          <button ref={closeRef} aria-label="Close evidence inspector" onClick={onClose} className="flex h-7 w-7 items-center justify-center rounded text-slate-500 hover:bg-slate-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-500"><X className="h-4 w-4" /></button>
        </header>
        <div className="flex-1 overflow-y-auto px-6 py-6 text-[15px]">
          <div className="mb-6">
            <div className="mb-3 flex items-center justify-between gap-3"><span className="flex items-center gap-1.5 text-[13px] text-slate-500"><SourceIcon className="h-3.5 w-3.5" />{sourceLabel}</span><span className={`rounded border px-2 py-0.5 text-[13px] font-semibold capitalize ${tierStyles[finding.challenge_tier]}`}>{finding.challenge_tier} tier</span></div>
            <h2 id="evidence-title" className="break-words font-mono text-xl font-semibold tracking-tight text-slate-900">{finding.algorithm}</h2>
            <p id="evidence-description" className="mt-2 break-all font-mono text-[13px] text-slate-500">{finding.asset_id}</p>
            <dl className="mt-5 grid grid-cols-2 gap-x-4 gap-y-4 rounded-md border border-slate-200 bg-slate-50 p-4 text-[13px]">
              <div><dt className="mb-1 text-slate-500">Usage</dt><dd className="capitalize text-slate-800">{finding.usage.replace(/_/g, ' ')}</dd></div>
              <div><dt className="mb-1 text-slate-500">Owner</dt><dd className="text-slate-800">{finding.owner || 'Unassigned'}</dd></div>
              <div><dt className="mb-1 text-slate-500">Quantum classification</dt><dd className="capitalize text-slate-800">{finding.quantum_status.replace(/_/g, ' ')}</dd></div>
              <div><dt className="mb-1 text-slate-500">Confidence</dt><dd className="capitalize text-slate-800">{finding.confidence}</dd></div>
            </dl>
          </div>
          <section className="mb-6"><h3 className="mb-2 text-[13px] font-semibold text-slate-900">Why it matters</h3><p className="leading-relaxed text-slate-600">{finding.rationale || 'No assessment rationale available.'}</p><p className="mt-2 font-mono text-[12px] text-slate-500">RULE {finding.rule_id || 'Not available'}</p></section>
          <section className="mb-6">
            <div className="mb-2 flex items-center justify-between"><h3 className="text-[13px] font-semibold text-slate-900">Traceable evidence</h3><span className="rounded border border-sky-200 bg-sky-50 px-1.5 py-0.5 font-mono text-[12px] capitalize text-sky-700">{finding.evidence_kind}</span></div>
            <p className="mb-3 text-[13px] leading-relaxed text-slate-500">{evidenceDescriptions[finding.evidence_kind]}</p>
            <div className="space-y-3">{finding.evidence.map((evidence, index) => <div key={index} className="overflow-hidden rounded-md border border-slate-200"><div className="space-y-1 border-b border-slate-200 bg-slate-50 px-3 py-2.5 font-mono text-[12px]"><p className="break-all text-slate-600"><span className="mr-2 text-slate-500">FILE</span>{evidence.file}</p><p className="break-all text-sky-700"><span className="mr-2 text-slate-500">LOCATOR</span>{evidence.locator}</p></div><pre className="overflow-x-auto whitespace-pre-wrap break-words bg-slate-50/50 p-3 font-mono text-[13px] leading-5 text-slate-700">{evidence.detail}</pre></div>)}</div>
            {finding.evidence.length === 0 && <p className="rounded border border-slate-200 bg-slate-50 p-3 text-[13px] text-slate-500">No evidence records available.</p>}
          </section>
          {finding.classical_issues.length > 0 && <section className="mb-6"><h3 className="mb-2 flex items-center gap-1.5 text-[13px] font-semibold text-amber-700"><ShieldAlert className="h-3.5 w-3.5" />Classical weaknesses</h3><ul className="space-y-2">{finding.classical_issues.map((issue, index) => <li key={index} className="rounded border border-amber-200 bg-amber-50 px-3 py-2 text-[13px] leading-relaxed text-amber-800">{issue}</li>)}</ul></section>}
          {finding.posture_issues.length > 0 && <section className="mb-6"><h3 className="mb-2 text-[13px] font-semibold text-slate-900">Operational issues</h3><ul className="space-y-2">{finding.posture_issues.map((issue, index) => <li key={index} className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-[13px] leading-relaxed text-slate-600">{issue}</li>)}</ul></section>}
          <section className="mb-6 rounded-md border border-sky-200 bg-sky-50 p-4"><h3 className="mb-2 flex items-center gap-1.5 text-[13px] font-semibold text-sky-800"><ArrowRight className="h-3.5 w-3.5" />Recommended action</h3><p className="text-[13px] leading-relaxed text-sky-900">{finding.recommendation || 'No specific migration action defined.'}</p></section>
          {finding.references.length > 0 && <section><h3 className="mb-2 text-[13px] font-semibold text-slate-900">Standards & references</h3><div className="space-y-2">{finding.references.map((url, index) => <a key={index} href={url} target="_blank" rel="noreferrer" className="flex items-start gap-1.5 break-all font-mono text-[12px] leading-4 text-sky-700 hover:underline"><ExternalLink className="mt-0.5 h-3 w-3 shrink-0" />{url}</a>)}</div></section>}
        </div>
        <footer className="flex items-center justify-end gap-3 border-t border-slate-200 bg-slate-50 px-6 py-3"><button onClick={onClose} className="h-8 rounded border border-slate-300 bg-white px-3 text-[13px] font-medium text-slate-700 hover:bg-slate-100">Close inspector</button></footer>
      </div>
    </div>
  );
};
