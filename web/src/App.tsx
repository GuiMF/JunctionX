import React, { useEffect, useRef, useState } from 'react';
import { ArrowRightLeft, Database } from 'lucide-react';
import { Navbar } from './components/Navbar';
import { CoverageCards } from './components/CoverageCards';
import { RiskPostureBanner } from './components/RiskPostureBanner';
import { FindingsTable } from './components/FindingsTable';
import { EvidenceModal } from './components/EvidenceModal';
import { MigrationView } from './components/MigrationView';
import { UploadBar } from './components/UploadBar';
import { mockScanResult, mockMigrationComparison } from './fixtures/mockData';
import type { Finding, ScanResult } from './types/contract';
import { submitFiles } from './api/client';
import { exportProjectJson, exportCycloneDxCbom } from './utils/cbomExport';

export const App: React.FC = () => {
  const [scanResult, setScanResult] = useState<ScanResult>(mockScanResult);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [activeTab, setActiveTab] = useState<'inventory' | 'migration'>('inventory');
  const [sidebarOpen, setSidebarOpen] = useState(() => typeof window === 'undefined' || window.innerWidth > 760);
  const [importOpen, setImportOpen] = useState(false);
  const [resetCounter, setResetCounter] = useState(0);
  const [exportError, setExportError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<string | null>(null);
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
      setIsDemo(false);
      setActiveTab('inventory');
      setResetCounter(value => value + 1);
      setImportOpen(false);
      setNotice(`Scan ${result.status} · ${result.findings.length} findings`);
    } catch (error) {
      if (!controller.signal.aborted) setScanError(error instanceof Error ? error.message : 'Scan failed. Please retry.');
    } finally {
      if (pending.current === controller) { pending.current = null; setIsScanning(false); }
    }
  };
  const resetDemo = () => {
    cancelScan();
    pendingExport.current?.abort();
    setScanError(null);
    setExportError(null);
    setSelectedFinding(null);
    setScanResult(mockScanResult);
    setIsDemo(true);
    setActiveTab('inventory');
    setResetCounter(value => value + 1);
    setImportOpen(false);
    setNotice(`Demo dataset loaded · ${mockScanResult.findings.length} findings`);
  };
  const navigate = (tab: 'inventory' | 'migration') => { setActiveTab(tab); setNotice(null); setSelectedFinding(null); if (window.innerWidth <= 760) setSidebarOpen(false); };
  return (
    <div className="workspace">
      <a className="skip-link" href="#main-content">Skip to dashboard</a>
      <Navbar activeTab={activeTab} onExportJson={() => handleExport('json')} onExportCbom={() => handleExport('cyclonedx')} onImport={() => { setScanError(null); setImportOpen(true); }} sidebarOpen={sidebarOpen} onToggleSidebar={() => setSidebarOpen(!sidebarOpen)} />
      <div className="workspace-body">
        {sidebarOpen && <aside className="sidebar" aria-label="Workspace navigation">
          <div className="sidebar-section-label mt-6">ANALYSIS</div>
          <nav className="space-y-1 px-3">
            <button className={`nav-item ${activeTab === 'inventory' ? 'active' : ''}`} onClick={() => navigate('inventory')} aria-current={activeTab === 'inventory' ? 'page' : undefined}><Database size={16} /><span>Inventory & evidence</span><span className="nav-count">{scanResult.findings.length}</span></button>
            <button className={`nav-item ${activeTab === 'migration' ? 'active' : ''}`} onClick={() => navigate('migration')} aria-current={activeTab === 'migration' ? 'page' : undefined}><ArrowRightLeft size={16} /><span>Migration comparison</span></button>
          </nav>
          {activeTab === 'inventory' && <section aria-labelledby="sidebar-coverage-heading" className="mt-6 px-3 pb-5">
            <h2 id="sidebar-coverage-heading" className="mb-3 px-1 text-[15px] font-medium text-slate-700">Discovery coverage</h2>
            <CoverageCards coverage={scanResult.coverage} />
          </section>}
        </aside>}
        <main aria-label="Active scan" data-scan-id={scanResult.scan_id} data-scan-status={scanResult.status} data-demo={isDemo} id="main-content" className="dashboard-main" tabIndex={-1}>
          {activeTab === 'migration' && <div className="page-heading"><h1>Migration comparison</h1></div>}
          {exportError && <div role="alert" className="mb-4 rounded border border-rose-200 bg-rose-50 p-3 text-[13px] text-rose-700">{exportError}</div>}
          {notice && <div role="status" className="mb-4 flex items-center justify-between gap-3 rounded border border-sky-200 bg-sky-50 p-3 text-[13px] text-sky-800">{notice}<button className="underline" onClick={() => setNotice(null)}>Dismiss</button></div>}
          {activeTab === 'inventory' && scanResult.errors.length > 0 && <section aria-label="Input errors" className="mb-4 rounded border border-amber-200 bg-amber-50 p-4 text-[13px] text-amber-900">
            <h2 className="mb-2 font-medium">{scanResult.status === 'failed' ? 'Scan failed' : 'Some inputs could not be assessed'}</h2>
            <ul className="space-y-1">{scanResult.errors.map((error, index) => <li key={index}>{error.input_name} ({error.source_type}) — {error.code}: {error.message}</li>)}</ul>
          </section>}
          {activeTab === 'migration' && !isDemo && <p className="mb-4 rounded border border-sky-200 bg-sky-50 p-3 text-[13px] text-sky-900">Sample comparison — independent of your uploaded scan.</p>}
          {activeTab === 'inventory' ? <div className="space-y-5"><RiskPostureBanner findings={scanResult.findings} score={scanResult.score} /><FindingsTable key={resetCounter} findings={scanResult.findings} onSelectFinding={setSelectedFinding} selectedFindingId={selectedFinding?.id} /></div> : <MigrationView comparison={mockMigrationComparison} />}
        </main>
      </div>
      {importOpen && <UploadBar onLoadDemoData={resetDemo} onClose={closeImport} onScan={handleScan} onCancel={cancelScan} isScanning={isScanning} progress={scanProgress} error={scanError} />}
      <EvidenceModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  );
};
export default App;
