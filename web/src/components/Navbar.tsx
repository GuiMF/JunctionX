import React from 'react';
import { ShieldCheck, Download, Sparkles, RefreshCw } from 'lucide-react';

interface NavbarProps {
  onExportJson: () => void;
  onExportCbom: () => void;
  activeTab: 'inventory' | 'migration';
  setActiveTab: (tab: 'inventory' | 'migration') => void;
  onResetDemo: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onExportJson,
  onExportCbom,
  activeTab,
  setActiveTab,
  onResetDemo
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold text-lg shadow-sm">
              QT
            </div>
            <div>
              <span className="font-semibold text-white tracking-tight text-base">QuantumTrace</span>
              <span className="ml-2 text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/50 px-2 py-0.5 rounded-full">
                JunctionX Demo
              </span>
            </div>
          </div>

          <nav className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1 rounded-lg">
            <button
              onClick={() => setActiveTab('inventory')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                activeTab === 'inventory'
                  ? 'bg-emerald-500 text-slate-950 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Inventory & Evidence
            </button>
            <button
              onClick={() => setActiveTab('migration')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
                activeTab === 'migration'
                  ? 'bg-emerald-500 text-slate-950 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              Before / After Migration
            </button>
          </nav>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onResetDemo}
            title="Reset to hackathon starter demo data"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded-lg transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Reset Data
          </button>

          <button
            onClick={onExportJson}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            Project JSON
          </button>

          <button
            onClick={onExportCbom}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-emerald-950 bg-emerald-400 hover:bg-emerald-300 rounded-lg shadow-sm transition-colors"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            CycloneDX 1.6 CBOM
          </button>
        </div>
      </div>
    </header>
  );
};
