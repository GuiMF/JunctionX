import React, { useEffect, useRef, useState } from 'react';
import { ArrowRight, Check, Cloud, FileCode2, FileUp, FlaskConical, Info, Layers, Loader2, Network, Upload, X } from 'lucide-react';

interface UploadBarProps {
  onLoadDemoData: () => void;
  onClose: () => void;
  onScan: (files: File[]) => void;
  onCancel: () => void;
  isScanning: boolean;
  error: string | null;
}
const sources = [
  { id: 'all', label: 'Mixed sources', detail: 'All supported files', icon: Layers, accept: '.pcap,.pcapng,.cap,.py,.java,.go,.json' },
  { id: 'pcap', label: 'Network capture', detail: 'PCAP / PCAPNG / CAP', icon: Network, accept: '.pcap,.pcapng,.cap' },
  { id: 'source', label: 'Source code', detail: 'Python, Java, Go', icon: FileCode2, accept: '.py,.java,.go' },
  { id: 'cloud', label: 'AWS configuration', detail: 'JSON snapshots', icon: Cloud, accept: '.json' },
];

export const UploadBar: React.FC<UploadBarProps> = ({ onLoadDemoData, onClose, onScan, onCancel, isScanning, error }) => {
  const [source, setSource] = useState(sources[0]);
  const [files, setFiles] = useState<File[]>([]);
  const [dragging, setDragging] = useState(false);
  const [selectionError, setSelectionError] = useState<string | null>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    dialog.current?.focus();
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); closeRef.current(); }
      if (event.key !== 'Tab') return;
      const nodes = dialog.current?.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]):not(.hidden), [tabindex="0"]');
      if (!nodes?.length) return;
      const first = nodes[0]; const last = nodes[nodes.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog.current)) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || document.activeElement === dialog.current)) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', handleKey);
    return () => { document.body.style.overflow = overflow; document.removeEventListener('keydown', handleKey); previous?.focus(); };
  }, []);
  const selectFiles = (selected: File[]) => {
    if (isScanning) return;
    const extensions = source.accept.split(',');
    const valid = selected.filter(file => extensions.some(ext => file.name.toLowerCase().endsWith(ext)));
    setFiles(previous => {
      const next = [...previous];
      for (const file of valid) {
        if (!next.some(existing => existing.name === file.name && existing.size === file.size && existing.lastModified === file.lastModified)) next.push(file);
      }
      return next;
    });
    setSelectionError(valid.length !== selected.length ? `Some files were not added. Choose ${source.detail.toLowerCase()} for this source type, or select Mixed sources.` : null);
  };
  const fileCountError = files.length > 16 ? 'Select up to 16 files per scan. Remove files before continuing.' : null;
  return <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/20 p-4" onMouseDown={event => { if (event.target === event.currentTarget) onClose(); }}>
    <div ref={dialog} role="dialog" aria-modal="true" aria-labelledby="import-title" tabIndex={-1} className="max-h-[90vh] w-full max-w-[700px] overflow-y-auto rounded-lg border border-slate-400 bg-white shadow-xl outline-none">
      <div className="flex items-center justify-between border-b border-slate-200 px-6 py-4"><div className="flex items-center gap-3"><div className="flex h-9 w-9 items-center justify-center rounded border border-sky-100 bg-sky-50 text-sky-600"><Upload size={18} /></div><div><h2 id="import-title" className="text-base font-semibold">Import discovery data</h2><p className="mt-0.5 text-[13px] text-slate-500">Combine sources into one cryptographic assessment.</p></div></div><button className="icon-button" aria-label="Close import dialog" onClick={onClose}><X size={18} /></button></div>
      <div className="space-y-5 p-6">
        <div><h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-slate-500">01 / Select a source</h3><div className="grid grid-cols-2 gap-2 sm:grid-cols-4">{sources.map(item => <button key={item.id} disabled={isScanning} aria-pressed={source.id === item.id} onClick={() => { setSource(item); setSelectionError(null); if (fileInput.current) fileInput.current.value = ''; }} className={`relative rounded-md border p-3 text-left disabled:cursor-not-allowed disabled:opacity-60 ${source.id === item.id ? 'border-sky-500 bg-sky-50 text-sky-800' : 'border-slate-200 text-slate-600 hover:border-slate-400'}`}><item.icon size={18} className="mb-3" />{source.id === item.id && <Check size={13} className="absolute right-3 top-3" />}<strong className="block text-[13px] font-semibold">{item.label}</strong><span className="mt-1 block text-[11px] opacity-75">{item.detail}</span></button>)}</div></div>
        <div><h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-slate-500">02 / Add files</h3><div onDragOver={event => { event.preventDefault(); if (!isScanning) setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={event => { event.preventDefault(); setDragging(false); selectFiles(Array.from(event.dataTransfer.files)); }} className={`rounded-md border border-dashed p-6 text-center ${dragging && !isScanning ? 'border-sky-500 bg-sky-50' : 'border-slate-300 bg-slate-50'}`}><FileUp size={25} className="mx-auto mb-3 text-slate-500" /><p className="text-[15px] font-medium text-slate-700">Drop your files here</p><p className="mb-4 mt-1 text-[13px] text-slate-500">{source.detail} · add files across source types</p><button disabled={isScanning} className="button button-secondary disabled:cursor-not-allowed disabled:opacity-50" onClick={() => fileInput.current?.click()}>Browse files</button><input ref={fileInput} aria-label="Select discovery files" className="hidden" type="file" multiple disabled={isScanning} accept={source.accept} onChange={event => { selectFiles(Array.from(event.target.files || [])); event.target.value = ''; }} /></div><p className="mt-2 text-[11px] leading-5 text-slate-500">1–16 files · 8 MiB per encoded input · 16 MiB combined. Captures expand in base64; related AWS files are combined into one input.</p></div>
        {selectionError && <p role="alert" className="text-[13px] text-rose-600">{selectionError}</p>}
        {files.length > 0 && <div aria-live="polite" className="rounded border border-slate-200"><div className="border-b border-slate-200 bg-slate-50 px-3 py-2 text-[13px] font-medium text-slate-500">{files.length} file{files.length === 1 ? '' : 's'} selected · {isScanning ? 'analysis in progress' : 'ready to scan'}</div><div className="max-h-44 overflow-y-auto">{files.map((file, index) => <div key={`${file.name}-${index}`} className="flex items-center gap-2 px-3 py-2 text-[13px]"><FileCode2 size={14} className="shrink-0 text-slate-500" /><span className="min-w-0 flex-1 truncate font-mono text-[12px]" title={file.name}>{file.name}</span><span className="shrink-0 text-[11px] text-slate-500">{Math.max(1, Math.round(file.size / 1024))} KB</span><button disabled={isScanning} className="icon-button disabled:cursor-not-allowed disabled:opacity-40" aria-label={`Remove ${file.name}`} onClick={() => setFiles(previous => previous.filter((_, i) => i !== index))}><X size={13} /></button></div>)}</div></div>}
        {fileCountError && <p role="alert" className="text-[13px] text-rose-600">{fileCountError}</p>}
        {isScanning && <div role="status" className="flex items-center gap-2.5 rounded border border-sky-200 bg-sky-50 p-3 text-[13px] text-sky-900"><Loader2 size={17} className="shrink-0 animate-spin" />Reading files and analyzing cryptographic evidence…</div>}
        {error && <div role="alert" className="rounded border border-rose-200 bg-rose-50 p-3 text-[13px] leading-5 text-rose-700"><p className="font-semibold">Scan could not complete</p><p className="mt-1">{error}</p><p className="mt-1">Your selection is preserved. Adjust the files if needed, then retry.</p></div>}
        <div className="flex gap-2.5 rounded border border-sky-100 bg-sky-50 p-3"><Info size={16} className="mt-0.5 shrink-0 text-sky-600" /><p className="text-[13px] leading-5 text-sky-900">Select related AWS snapshots together to resolve certificate references. Files are submitted for analysis when you start the scan; your previous result remains available until a new result is ready.</p></div>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 bg-slate-50 px-6 py-4"><button className="button button-secondary" onClick={onLoadDemoData}><FlaskConical size={14} />Load demo dataset</button><div className="flex items-center gap-2"><button className="button button-secondary" onClick={isScanning ? onCancel : onClose}>{isScanning ? 'Cancel scan' : 'Cancel'}</button><button disabled={isScanning || !files.length || !!fileCountError} className="button button-primary disabled:cursor-not-allowed disabled:opacity-50" onClick={() => onScan(files)}>{isScanning ? <><Loader2 size={14} className="animate-spin" />Scanning…</> : <>{error ? 'Retry scan' : 'Scan selected files'}<ArrowRight size={14} /></>}</button></div></div>
    </div>
  </div>;
};
