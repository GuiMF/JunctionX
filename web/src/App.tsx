import React, { useState } from 'react';
import { ArrowRightLeft, Database } from 'lucide-react';
import { Navbar } from './components/Navbar';
import { CoverageCards } from './components/CoverageCards';
import { RiskPostureBanner } from './components/RiskPostureBanner';
import { FindingsTable } from './components/FindingsTable';
import { EvidenceModal } from './components/EvidenceModal';
import { MigrationView } from './components/MigrationView';
import { UploadBar } from './components/UploadBar';
import { mockScanResult, mockMigrationComparison } from './fixtures/mockData';
import type { Finding } from './types/contract';
import { exportProjectJson, exportCycloneDxCbom } from './utils/cbomExport';

export const App: React.FC = () => {
  const scanResult = mockScanResult;
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [activeTab, setActiveTab] = useState<'inventory' | 'migration'>('inventory');
  const [sidebarOpen, setSidebarOpen] = useState(() => typeof window === 'undefined' || window.innerWidth > 760);
  const [importOpen, setImportOpen] = useState(false);
  const [resetCounter, setResetCounter] = useState(0);
  const [exportError, setExportError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const resetDemo = () => { setExportError(null); setSelectedFinding(null); setActiveTab('inventory'); setResetCounter(value => value + 1); setImportOpen(false); setNotice(`Demo dataset loaded. Showing ${scanResult.findings.length} findings from three synthetic sources.`); };
  const exportCbom = async () => { setExportError(null); try { await exportCycloneDxCbom(scanResult); } catch (error) { setExportError(error instanceof Error ? error.message : 'Export failed. Please retry.'); } };
  const navigate = (tab: 'inventory' | 'migration') => { setActiveTab(tab); setNotice(null); setSelectedFinding(null); if (window.innerWidth <= 760) setSidebarOpen(false); };
  return (
    <div className="workspace">
      <a className="skip-link" href="#main-content">Skip to dashboard</a>
      <Navbar activeTab={activeTab} onExportJson={() => exportProjectJson(scanResult)} onExportCbom={exportCbom} onImport={() => setImportOpen(true)} sidebarOpen={sidebarOpen} onToggleSidebar={() => setSidebarOpen(!sidebarOpen)} />
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
        <main id="main-content" className="dashboard-main" tabIndex={-1}>
          {activeTab === 'migration' && <div className="page-heading"><h1>Migration comparison</h1></div>}
          {exportError && <div role="alert" className="mb-4 rounded border border-rose-200 bg-rose-50 p-3 text-[13px] text-rose-700">{exportError}</div>}
          {notice && <div role="status" className="mb-4 flex items-center justify-between gap-3 rounded border border-sky-200 bg-sky-50 p-3 text-[13px] text-sky-800">{notice}<button className="underline" onClick={() => setNotice(null)}>Dismiss</button></div>}
          {activeTab === 'inventory' ? <div className="space-y-5"><RiskPostureBanner findings={scanResult.findings} score={scanResult.score} /><FindingsTable key={resetCounter} findings={scanResult.findings} onSelectFinding={setSelectedFinding} selectedFindingId={selectedFinding?.id} /></div> : <MigrationView comparison={mockMigrationComparison} />}
        </main>
      </div>
      {importOpen && <UploadBar onLoadDemoData={resetDemo} onClose={() => setImportOpen(false)} />}
      <EvidenceModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  );
};
export default App;
