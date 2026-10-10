import React, { useEffect, useRef, useState } from 'react';
import { Database, Upload } from 'lucide-react';
import { Navbar } from './components/Navbar';
import { CoverageCards } from './components/CoverageCards';
import { RiskPostureBanner } from './components/RiskPostureBanner';
import { FindingsTable } from './components/FindingsTable';
import { EvidenceModal } from './components/EvidenceModal';
import { UploadBar } from './components/UploadBar';
import type { Finding, ScanResult } from './types/contract';
import { submitFiles } from './api/client';
import { exportProjectJson, exportCycloneDxCbom } from './utils/cbomExport';

export const App: React.FC = () => {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(() => typeof window === 'undefined' || window.innerWidth > 760);
  const [importOpen, setImportOpen] = useState(false);
  const [resetCounter, setResetCounter] = useState(0);
  const [exportError, setExportError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const pending = useRef<AbortController | null>(null);
  const pendingExport = useRef<AbortController | null>(null);
  useEffect(() => () => { pending.current?.abort(); pendingExport.current?.abort(); }, []);

  const handleExport = async (format: 'json' | 'cyclonedx') => {
    if (!scanResult) return;
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
  const closeImport = () => { cancelScan(); setImportOpen(false); };
  const handleScan = async (files: File[]) => {
    if (pending.current) return;
    const controller = new AbortController();
    pending.current = controller;
    pendingExport.current?.abort();
    setIsScanning(true);
    setScanProgress(null);
    setScanError(null);
    setExportError(null);
    setNotice(null);
    try {
      const result = await submitFiles(files, controller.signal, message => {
        if (pending.current === controller && !controller.signal.aborted) setScanProgress(message);
      });
      if (controller.signal.aborted || pending.current !== controller) return;
      pendingExport.current?.abort();
      setExportError(null);
      setSelectedFinding(null);
      setScanResult(result);
      setResetCounter(value => value + 1);
      setImportOpen(false);
      setNotice(`Scan ${result.status} · ${result.findings.length} findings`);
    } catch (error) {
      if (!controller.signal.aborted) setScanError(error instanceof Error ? error.message : 'Scan failed. Please retry.');
    } finally {
      if (pending.current === controller) { pending.current = null; setIsScanning(false); }
    }
  };
  return (
    <div className="workspace">
      <a className="skip-link" href="#main-content">Skip to dashboard</a>
      <Navbar canExport={scanResult !== null} onExportJson={() => handleExport('json')} onExportCbom={() => handleExport('cyclonedx')} onImport={() => { setScanError(null); setImportOpen(true); }} sidebarOpen={sidebarOpen} onToggleSidebar={() => setSidebarOpen(!sidebarOpen)} />
      <div className="workspace-body">
        {sidebarOpen && <aside className="sidebar" aria-label="Workspace navigation">
          <div className="sidebar-section-label mt-6">ANALYSIS</div>
          <nav className="space-y-1 px-3">
            <button className="nav-item active" onClick={() => { setSelectedFinding(null); if (window.innerWidth <= 760) setSidebarOpen(false); }} aria-current="page"><Database size={16} /><span>Inventory & evidence</span><span className="nav-count">{scanResult?.findings.length ?? 0}</span></button>
          </nav>
          <section aria-labelledby="sidebar-coverage-heading" className="mt-6 px-3 pb-5">
            <h2 id="sidebar-coverage-heading" className="mb-3 px-1 text-[15px] font-medium text-slate-700">Discovery coverage</h2>
            <CoverageCards coverage={scanResult?.coverage ?? []} />
          </section>
        </aside>}
        <main aria-label="Active scan" data-scan-id={scanResult?.scan_id} data-scan-status={scanResult?.status ?? 'empty'} id="main-content" className="dashboard-main" tabIndex={-1}>
          {exportError && <div role="alert" className="mb-4 rounded border border-rose-200 bg-rose-50 p-3 text-[13px] text-rose-700">{exportError}</div>}
          {notice && <div role="status" className="mb-4 flex items-center justify-between gap-3 rounded border border-sky-200 bg-sky-50 p-3 text-[13px] text-sky-800">{notice}<button className="underline" onClick={() => setNotice(null)}>Dismiss</button></div>}
          {scanResult && scanResult.errors.length > 0 && <section aria-label="Input errors" className="mb-4 rounded border border-amber-200 bg-amber-50 p-4 text-[13px] text-amber-900">
            <h2 className="mb-2 font-medium">{scanResult.status === 'failed' ? 'Scan failed' : 'Some inputs could not be assessed'}</h2>
            <ul className="space-y-1">{scanResult.errors.map((error, index) => <li key={index}>{error.input_name} ({error.source_type}) — {error.code}: {error.message}</li>)}</ul>
          </section>}
          {scanResult ? <div className="space-y-5"><RiskPostureBanner findings={scanResult.findings} score={scanResult.score} /><FindingsTable key={resetCounter} findings={scanResult.findings} onSelectFinding={setSelectedFinding} selectedFindingId={selectedFinding?.id} /></div> : <section className="rounded-md border border-slate-200 bg-white px-6 py-16 text-center" aria-labelledby="empty-inventory-title">
            <Database size={32} className="mx-auto mb-4 text-slate-400" aria-hidden="true" />
            <h1 id="empty-inventory-title" className="text-xl font-semibold text-slate-900">No scans yet</h1>
            <p className="mx-auto mb-6 mt-2 max-w-md text-sm text-slate-500">Import source code, network captures, or AWS snapshots to discover cryptographic assets and assess their exposure.</p>
            <button className="button button-primary mx-auto" onClick={() => { setScanError(null); setImportOpen(true); }}><Upload size={14} />Import files</button>
          </section>}
        </main>
      </div>
      {importOpen && <UploadBar onClose={closeImport} onScan={handleScan} onCancel={cancelScan} isScanning={isScanning} progress={scanProgress} error={scanError} />}
      <EvidenceModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  );
};
export default App;
