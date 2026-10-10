import React, { useEffect, useRef, useState } from 'react';
import { Navbar } from './components/Navbar';
import { CoverageCards } from './components/CoverageCards';
import { RiskPostureBanner } from './components/RiskPostureBanner';
import { FindingsTable } from './components/FindingsTable';
import { EvidenceModal } from './components/EvidenceModal';
import { MigrationView } from './components/MigrationView';
import { UploadBar } from './components/UploadBar';
import { mockScanResult, mockMigrationComparison } from './fixtures/mockData';
import type { Finding, ScanResult } from './types/contract';
import { prepareScan } from './utils/scanInputs';
import { submitScan } from './api/client';
import { exportProjectJson, exportCycloneDxCbom } from './utils/cbomExport';

export const App: React.FC = () => {
  const [scanResult, setScanResult] = useState<ScanResult>(mockScanResult);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [activeTab, setActiveTab] = useState<'inventory' | 'migration'>('inventory');
  const [resetCounter, setResetCounter] = useState<number>(0);
  const [exportError, setExportError] = useState<string | null>(null);

  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [isDemo, setIsDemo] = useState(true);
  const pending = useRef<AbortController | null>(null);
  const pendingExport = useRef<AbortController | null>(null);
  useEffect(() => () => { pending.current?.abort(); pendingExport.current?.abort(); }, []);

  const handleExport = async (format: 'json' | 'cyclonedx') => {
    pendingExport.current?.abort();
    const controller = new AbortController();
    pendingExport.current = controller;
    setExportError(null);
    try {
      await (format === 'json' ? exportProjectJson : exportCycloneDxCbom)(scanResult, controller.signal);
    } catch (error) {
      if (!controller.signal.aborted) setExportError(error instanceof Error ? error.message : 'Export failed. Please retry.');
    }
  };

  const cancelScan = () => {
    pending.current?.abort();
    pending.current = null;
    setIsScanning(false);
  };

  const handleScan = async (files: File[]) => {
    if (pending.current) return;
    const controller = new AbortController();
    pending.current = controller;
    pendingExport.current?.abort();
    setIsScanning(true);
    setScanError(null);
    setExportError(null);
    try {
      const request = await prepareScan(files);
      if (controller.signal.aborted) return;
      const result = await submitScan(request, controller.signal);
      if (controller.signal.aborted || pending.current !== controller) return;
      pendingExport.current?.abort();
      setExportError(null);
      setSelectedFinding(null);
      setScanResult(result);
      setIsDemo(false);
    } catch (error) {
      if (!controller.signal.aborted) setScanError(error instanceof Error ? error.message : 'Scan failed. Please retry.');
    } finally {
      if (pending.current === controller) {
        pending.current = null;
        setIsScanning(false);
      }
    }
  };

  const handleResetDemo = () => {
    cancelScan();
    pendingExport.current?.abort();
    setScanError(null);
    setExportError(null);
    setSelectedFinding(null);
    setIsDemo(true);
    setScanResult(mockScanResult);
    setResetCounter((prev) => prev + 1);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500 selection:text-slate-950">
      <Navbar
        onExportJson={() => handleExport('json')}
        onExportCbom={() => handleExport('cyclonedx')}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onResetDemo={handleResetDemo}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {exportError && (
          <p role="alert" className="rounded-lg border border-rose-800 bg-rose-950/40 p-3 text-sm text-rose-200">
            {exportError}
          </p>
        )}
        {activeTab === 'inventory' ? (
          <>
            {/* Multi-source Ingestion Bar */}
            <UploadBar
              onLoadDemoData={handleResetDemo}
              key={resetCounter}
              onScan={handleScan}
              onCancel={cancelScan}
              isScanning={isScanning}
              error={scanError}
            />

            <section aria-label="Active scan" className="rounded-lg border border-slate-800 p-4 space-y-2">
              <p className="text-sm font-semibold">{isDemo ? 'Demo mode — validated fixtures' : 'Live scan'} · Status: {scanResult.status}</p>
              <p className="text-xs font-mono text-slate-400">Scan: {scanResult.scan_id}</p>
              {!isDemo && <p className="text-xs text-slate-300">{
                scanResult.status === 'completed' ? 'All inputs processed. Review coverage and unknowns; completion does not establish security.' :
                scanResult.status === 'partial' ? 'Some inputs or resources could not be assessed. Review the errors and coverage below, then correct the files and scan again.' :
                'Scan failed. Review the errors below, correct the files and scan again.'
              }</p>}
              {scanResult.errors.length > 0 && <ul aria-label="Input errors" className="text-xs text-rose-300 space-y-1">
                {scanResult.errors.map((error, index) => <li key={index}>{error.input_name} ({error.source_type}) — {error.code}: {error.message}</li>)}
              </ul>}
            </section>

            {/* Coverage Summary across Network, Source Code, and Cloud */}
            <CoverageCards coverage={scanResult.coverage} />

            {/* Posture Banner: Shor Risk vs Classical Flaws vs Operational Posture */}
            <RiskPostureBanner
              findings={scanResult.findings}
              score={scanResult.score}
            />

            {/* Interactive Prioritized Findings Table with Filtering */}
            <FindingsTable
              key={scanResult.scan_id}
              findings={scanResult.findings}
              onSelectFinding={(finding) => setSelectedFinding(finding)}
            />
          </>
        ) : (
          <div className="space-y-4"><p className="text-sm text-amber-300">Demo comparison — synthetic fixtures, independent of the active scan.</p><MigrationView comparison={mockMigrationComparison} /></div>
        )}
      </main>

      {/* Deep-dive Evidence Drawer/Modal */}
      <EvidenceModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>
            QuantumTrace &copy; 2026 &middot; JunctionX Lisbon Demo Platform
          </span>
          <span className="font-mono text-[11px] text-slate-400">
            Ruleset: {scanResult.ruleset_version} &middot; Scan: {scanResult.scan_id} &middot; Status: {scanResult.status}
          </span>
        </div>
      </footer>
    </div>
  );
};

export default App;
