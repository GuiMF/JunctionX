import React from 'react';
import { CheckCircle2, AlertTriangle, ShieldCheck, HelpCircle } from 'lucide-react';
import type { MigrationComparison } from '../types/contract';

interface MigrationViewProps {
  comparison: MigrationComparison;
}

export const MigrationView: React.FC<MigrationViewProps> = ({ comparison }) => {
  return (
    <div className="space-y-6">
      {/* Intro & Warning Banner */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white tracking-tight">
              Before & After Migration: {comparison.name}
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">{comparison.description}</p>
          </div>
        </div>

        {/* Critical Honesty / Anti-Hallucination Callout */}
        <div className="mt-4 p-3.5 bg-amber-950/30 border border-amber-900/60 rounded-lg flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs text-amber-200 leading-relaxed">
            <strong className="text-amber-300 block mb-0.5">Verification Integrity Rule:</strong>
            {comparison.summary_note}
          </div>
        </div>
      </div>

      {/* Side by side diff */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Original State */}
        <div className="bg-slate-900/40 border border-rose-900/40 rounded-xl p-5 relative overflow-hidden flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <span className="text-xs uppercase font-mono font-bold tracking-wider text-rose-400">
                1. Original State (Pre-Migration)
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
                Quantum Vulnerable
              </span>
            </div>

            <div>
              <span className="text-xs text-slate-500 block mb-1">Configured SSL Security Policy</span>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-rose-300 font-bold">
                {comparison.original.policy}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-0.5 text-[11px]">Protocol Support</span>
                <span className="text-slate-200 font-semibold">{comparison.original.tls_version}</span>
              </div>
              <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-0.5 text-[11px]">Wire Negotiation</span>
                <span className="text-rose-300 font-semibold font-mono">Classical ECDHE Observed</span>
              </div>
            </div>

            <div>
              <span className="text-xs text-slate-500 block mb-1">Associated Cryptographic Findings</span>
              <div className="space-y-2">
                {comparison.original.findings.map((f) => (
                  <div key={f.id} className="p-3 bg-slate-950 rounded-lg border border-slate-800/80 text-xs">
                    <div className="font-semibold text-slate-200 font-mono">{f.algorithm}</div>
                    <p className="text-slate-400 text-[11px] mt-1">{f.rationale}</p>
                    <div className="mt-2 text-[10px] font-mono text-slate-500">
                      Locator: {f.evidence[0]?.locator}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Upgraded State */}
        <div className="bg-slate-900/40 border border-emerald-900/40 rounded-xl p-5 relative overflow-hidden flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <span className="text-xs uppercase font-mono font-bold tracking-wider text-emerald-400">
                2. Upgraded State (Hybrid Post-Quantum)
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                Hybrid PQ Capable
              </span>
            </div>

            <div>
              <span className="text-xs text-slate-500 block mb-1">Upgraded SSL Security Policy</span>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-emerald-900/50 font-mono text-xs text-emerald-300 font-bold">
                {comparison.upgraded.policy}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-0.5 text-[11px]">Protocol Support</span>
                <span className="text-slate-200 font-semibold">{comparison.upgraded.tls_version}</span>
              </div>
              <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
                <span className="text-slate-500 block mb-0.5 text-[11px]">Wire Negotiation</span>
                <span className="text-amber-300 font-semibold font-mono flex items-center gap-1">
                  <HelpCircle className="w-3.5 h-3.5" /> Unverified (Needs PCAP)
                </span>
              </div>
            </div>

            <div>
              <span className="text-xs text-slate-500 block mb-1">Upgraded Cryptographic Posture</span>
              <div className="space-y-2">
                {comparison.upgraded.findings.map((f) => (
                  <div key={f.id} className="p-3 bg-slate-950 rounded-lg border border-slate-800/80 text-xs">
                    <div className="font-semibold text-emerald-400 font-mono">{f.algorithm}</div>
                    <p className="text-slate-300 text-[11px] mt-1">{f.rationale}</p>
                    <div className="mt-2 text-[10px] font-mono text-emerald-400/80">
                      Recommendation: {f.recommendation}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Migration Workplan Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-white mb-3">Actionable Next Steps for Cloud Team</h3>
        <div className="space-y-2 text-xs">
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center gap-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="text-slate-300">
              Update Terraform / AWS CLI listener policy to <code className="text-cyan-300">ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09</code>.
            </span>
          </div>
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center gap-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="text-slate-300">
              Verify client support: Ensure partner clients support <code className="text-cyan-300">X25519MLKEM768</code> group.
            </span>
          </div>
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center gap-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="text-slate-300">
              Capture post-migration network traffic and re-scan through QuantumTrace to convert <em>Unverified</em> to <em>Observed PQ</em>.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
