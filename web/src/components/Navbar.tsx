import React, { useEffect, useRef, useState } from 'react';
import { ArrowDownToLine, Braces, ChevronDown, ChevronRight, PanelLeftClose, PanelLeftOpen, Upload } from 'lucide-react';

interface NavbarProps {
  onExportJson: () => void;
  onExportCbom: () => void;
  activeTab: 'inventory' | 'migration';
  onImport: () => void;
  sidebarOpen: boolean;
  onToggleSidebar: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onExportJson, onExportCbom, activeTab, onImport, sidebarOpen, onToggleSidebar }) => {
  const [exportOpen, setExportOpen] = useState(false);
  const exportRef = useRef<HTMLDivElement>(null);
  const exportButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const close = (event: MouseEvent) => { if (!exportRef.current?.contains(event.target as Node)) setExportOpen(false); };
    const escape = (event: KeyboardEvent) => { if (event.key === 'Escape' && exportOpen) { setExportOpen(false); exportButton.current?.focus(); } };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', escape);
    return () => { document.removeEventListener('mousedown', close); document.removeEventListener('keydown', escape); };
  }, [exportOpen]);
  return (
    <header className="app-header">
      <div className="brand-lockup"><span>QuantumTrace</span></div>
      <div className="flex min-w-0 flex-1 items-center gap-3 px-4">
        <button className="icon-button" aria-label={sidebarOpen ? 'Collapse navigation' : 'Expand navigation'} aria-expanded={sidebarOpen} onClick={onToggleSidebar}>{sidebarOpen ? <PanelLeftClose size={16} /> : <PanelLeftOpen size={16} />}</button>
        <div className="hidden items-center gap-2 text-[13px] text-slate-500 sm:flex"><span>Workspace</span><ChevronRight size={12} /><span className="font-medium text-slate-800">{activeTab === 'inventory' ? 'Cryptographic inventory' : 'Migration comparison'}</span></div>
      </div>
      <div className="flex items-center gap-2 pr-4">
        <div ref={exportRef} className="relative">
          <button ref={exportButton} aria-label="Export current scan" className="button button-secondary" aria-expanded={exportOpen} aria-controls="export-options" onClick={() => setExportOpen(!exportOpen)}><ArrowDownToLine size={14} /><span className="hidden sm:inline">Export</span><ChevronDown size={12} /></button>
          {exportOpen && <div id="export-options" className="export-menu"><div className="px-3 py-2 text-[12px] font-semibold uppercase tracking-wider text-slate-500">Download current scan</div><button onClick={() => { onExportJson(); setExportOpen(false); exportButton.current?.focus(); }}><Braces size={15} /><span>Project JSON<small>Findings, coverage & evidence</small></span></button><button onClick={() => { onExportCbom(); setExportOpen(false); exportButton.current?.focus(); }}><ArrowDownToLine size={15} /><span>CycloneDX 1.6 CBOM<small>Cryptographic bill of materials</small></span></button></div>}
        </div>
        <button onClick={onImport} className="button button-primary"><Upload size={14} /><span>Import data</span></button>
      </div>
    </header>
  );
};
