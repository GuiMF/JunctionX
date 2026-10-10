import React from 'react';
import { AlertTriangle, ArrowRight, GitCompareArrows, HelpCircle, Network, Server } from 'lucide-react';
import type { MigrationComparison } from '../types/ui';

interface MigrationViewProps {
  comparison: MigrationComparison;
}

const wireLabels = {
  unverified: 'Unverified (Needs PCAP)',
  classical_observed: 'Classical negotiation observed',
  pq_observed: 'Post-quantum negotiation observed',
};

export const MigrationView: React.FC<MigrationViewProps> = ({ comparison }) => {
  const states = [
    { label: 'Original configuration', caption: 'BEFORE', state: comparison.original, upgraded: false },
    { label: 'Updated configuration', caption: 'AFTER', state: comparison.upgraded, upgraded: true },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-wider text-slate-500">
            <GitCompareArrows className="h-3.5 w-3.5" /> Configuration comparison
          </div>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded border border-amber-200 bg-amber-50 px-2.5 py-1.5 text-[13px] font-medium text-amber-700">
          <HelpCircle className="h-3.5 w-3.5" /> Runtime verification pending
        </span>
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-200 bg-white">
        <div className="flex items-center gap-3 border-b border-slate-200 px-5 py-4">
          <div className="rounded-md border border-slate-200 bg-slate-50 p-2 text-slate-500"><Server className="h-5 w-5" /></div>
          <div className="min-w-0">
            <h2 className="font-mono text-[15px] font-medium text-slate-900">{comparison.name}</h2>
            <p className="mt-1 text-[13px] text-slate-500">{comparison.description}</p>
          </div>
        </div>
        <div className="flex items-start gap-2.5 bg-amber-50/60 px-5 py-3">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
          <p className="text-[13px] leading-5 text-amber-900"><span className="font-semibold">Configuration evidence only. </span>{comparison.summary_note}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {states.map(({ label, caption, state, upgraded }) => {
          const policy = state.findings.find((finding) => finding.parameters.configured_tls_policy)?.parameters.configured_tls_policy;
          return (
            <section key={caption} className="min-w-0 overflow-hidden rounded-lg border border-slate-200 bg-white">
              <div className={`flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-5 py-3.5 ${upgraded ? 'bg-sky-50/60' : 'bg-slate-50'}`}>
                <div className="flex items-center gap-2.5">
                  <span className={`rounded border px-1.5 py-0.5 font-mono text-[12px] font-medium ${upgraded ? 'border-sky-200 bg-white text-sky-700' : 'border-slate-200 bg-white text-slate-500'}`}>{caption}</span>
                  <h3 className="text-[15px] font-semibold text-slate-900">{label}</h3>
                </div>
                <span className="text-[13px] text-slate-500">Configured evidence</span>
              </div>
              <div className="space-y-5 p-5">
                <div>
                  <p className="mb-2 text-[13px] font-semibold uppercase tracking-wider text-slate-500">SSL security policy</p>
                  <div className={`break-all rounded border px-3 py-3 font-mono text-[13px] leading-5 ${upgraded ? 'border-sky-200 bg-sky-50/50 text-sky-800' : 'border-slate-200 bg-slate-50 text-slate-700'}`}>{state.policy}</div>
                </div>
                <dl className="divide-y divide-slate-100 text-[13px]">
                  <div className="flex items-center justify-between gap-4 py-2.5"><dt className="text-slate-500">Protocol support</dt><dd className="font-mono text-slate-800">{state.tls_version}</dd></div>
                  <div className="flex items-center justify-between gap-4 py-2.5"><dt className="text-slate-500">Hybrid capability</dt><dd className={`rounded border px-1.5 py-0.5 text-[13px] ${policy?.hybrid_pq_capable ? 'border-amber-200 bg-amber-50 text-amber-700' : 'border-slate-200 bg-slate-50 text-slate-600'}`}>{policy?.hybrid_pq_capable === true ? 'Configured' : policy?.hybrid_pq_capable === false ? 'Not configured' : 'Unknown'}</dd></div>
                  <div className="flex items-center justify-between gap-4 py-2.5"><dt className="text-slate-500">Classical fallback</dt><dd className="text-slate-700">{policy?.classical_fallback === true ? 'Available' : policy?.classical_fallback === false ? 'Unavailable' : 'Unknown'}</dd></div>
                  <div className="flex items-center justify-between gap-4 py-2.5"><dt className="text-slate-500">Wire negotiation</dt><dd className="flex items-center gap-1.5 text-right font-medium text-amber-700"><HelpCircle className="h-3.5 w-3.5 shrink-0" />{wireLabels[state.wire_status]}</dd></div>
                </dl>
                <div>
                  <p className="mb-2 text-[13px] font-semibold uppercase tracking-wider text-slate-500">Configured hybrid groups</p>
                  <div className="flex min-h-10 flex-wrap items-center gap-1.5 rounded border border-slate-200 bg-slate-50 p-2.5">
                    {policy?.hybrid_groups?.length ? policy.hybrid_groups.map((group) => <code key={group} className="rounded border border-amber-200 bg-amber-50 px-1.5 py-0.5 text-[13px] text-amber-800">{group}</code>) : <span className="text-[13px] text-slate-500">No hybrid groups recorded</span>}
                  </div>
                </div>
                <div>
                  <p className="mb-2 text-[13px] font-semibold uppercase tracking-wider text-slate-500">Assessment & evidence</p>
                  <div className="space-y-3">
                    {state.findings.map((finding) => (
                      <div key={finding.id} className="rounded border border-slate-200 p-3">
                        <div className="flex items-center justify-between gap-3">
                          <span className="font-mono text-[13px] font-medium text-slate-700">{finding.algorithm}</span>
                          <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[12px] capitalize text-slate-600">{finding.quantum_status.replace(/_/g, ' ')}</span>
                        </div>
                        <p className="mt-2 text-[13px] leading-5 text-slate-600">{finding.rationale}</p>
                        {finding.evidence.map((evidence, index) => <div key={`${evidence.file}-${index}`} className="mt-3 border-t border-slate-100 pt-2 font-mono text-[12px] leading-4 text-slate-500"><span className="text-slate-600">{evidence.file}</span><div className="mt-1 break-all">{evidence.locator}</div></div>)}
                        {upgraded && finding.recommendation && <p className="mt-3 border-t border-slate-100 pt-2 text-[13px] leading-5 text-slate-600"><span className="font-medium text-slate-800">Next step: </span>{finding.recommendation}</p>}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>
          );
        })}
      </div>

      <section className="overflow-hidden rounded-lg border border-slate-200 bg-white">
        <div className="flex items-center gap-2 border-b border-slate-200 px-5 py-3.5"><Network className="h-4 w-4 text-slate-500" /><h3 className="text-[15px] font-semibold text-slate-900">Verification workplan</h3><span className="ml-auto text-[13px] text-slate-500">Cloud team · 3 next steps</span></div>
        <ol className="grid grid-cols-1 divide-y divide-slate-200 lg:grid-cols-3 lg:divide-x lg:divide-y-0">
          {[
            { title: 'Review client compatibility', body: <>Confirm partner client support for <code className="font-mono text-[13px] text-slate-800">X25519MLKEM768</code> and evaluate fallback requirements.</> },
            { title: 'Evaluate the updated policy', body: <>After compatibility checks, evaluate <code className="break-all font-mono text-[13px] text-slate-800">{comparison.upgraded.policy}</code> in your cloud environment.</> },
            { title: 'Capture & verify', body: <>Capture post-migration traffic and re-scan through QuantumTrace to verify the negotiated cryptography with observed evidence.</> },
          ].map((step, index) => <li key={step.title} className="p-5"><div className="mb-2 flex items-center gap-2"><span className="flex h-5 w-5 items-center justify-center rounded border border-slate-200 bg-slate-50 font-mono text-[12px] text-slate-500">0{index + 1}</span><h4 className="text-[13px] font-semibold text-slate-800">{step.title}</h4>{index < 2 && <ArrowRight className="ml-auto h-3.5 w-3.5 text-slate-300" />}</div><p className="text-[13px] leading-5 text-slate-500">{step.body}</p></li>)}
        </ol>
      </section>
    </div>
  );
};
