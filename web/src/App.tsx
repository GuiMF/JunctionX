import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { CoverageCards } from './components/CoverageCards';
import { RiskPostureBanner } from './components/RiskPostureBanner';
import { FindingsTable } from './components/FindingsTable';
import { EvidenceModal } from './components/EvidenceModal';
import { MigrationView } from './components/MigrationView';
import { UploadBar } from './components/UploadBar';
import { mockScanResult, mockMigrationComparison } from './fixtures/mockData';
import type { Finding, ScanResult } from './types/contract';
import { exportProjectJson, exportCycloneDxCbom } from './utils/cbomExport';

export const App: React.FC = () => {
  const [scanResult, setScanResult] = useState<ScanResult>(mockScanResult);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [activeTab, setActiveTab] = useState<'inventory' | 'migration'>('inventory');
  const [resetCounter, setResetCounter] = useState<number>(0);

  const handleExportJson = () => {
    exportProjectJson(scanResult);
  };

  const handleExportCbom = async () => {
    await exportCycloneDxCbom(scanResult);
  };

  const handleResetDemo = () => {
    setScanResult(mockScanResult);
    setResetCounter((prev) => prev + 1);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500 selection:text-slate-950">
      <Navbar
        onExportJson={handleExportJson}
        onExportCbom={handleExportCbom}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onResetDemo={handleResetDemo}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {activeTab === 'inventory' ? (
          <>
            {/* Multi-source Ingestion Bar */}
            <UploadBar
              onLoadDemoData={handleResetDemo}
              onSimulateScan={() => {}}
              resetTrigger={resetCounter}
            />

            {/* Coverage Summary across Network, Source Code, and Cloud */}
            <CoverageCards coverage={scanResult.coverage} />

            {/* Posture Banner: Shor Risk vs Classical Flaws vs Operational Posture */}
            <RiskPostureBanner
              findings={scanResult.findings}
              score={scanResult.score}
            />

            {/* Interactive Prioritized Findings Table with Filtering */}
            <FindingsTable
              findings={scanResult.findings}
              onSelectFinding={(finding) => setSelectedFinding(finding)}
            />
          </>
        ) : (
          <MigrationView comparison={mockMigrationComparison} />
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
