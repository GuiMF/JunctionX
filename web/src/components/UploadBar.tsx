import React, { useState } from 'react';
import { UploadCloud, Sparkles } from 'lucide-react';

interface UploadBarProps {
  onLoadDemoData: () => void;
  onScan: (files: File[]) => void;
  onCancel: () => void;
  isScanning: boolean;
  error: string | null;
}

export const UploadBar: React.FC<UploadBarProps> = ({ onLoadDemoData, onScan, onCancel, isScanning, error }) => {
  const [files, setFiles] = useState<File[]>([]);
  return (
    <section aria-label="File ingestion" className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
      <h2 className="text-sm font-semibold flex items-center gap-2"><UploadCloud className="w-4 h-4 text-emerald-400" />Ingest Multi-Source Discovery Data</h2>
      <p className="text-xs text-slate-400">Python (.py), Java (.java), Go (.go), PCAP (.pcap, .pcapng, .cap), and AWS snapshot JSON. Select related AWS snapshots together to resolve certificate references.</p>
      <p className="text-xs text-slate-400">1–16 files; 8 MiB per encoded input and 16 MiB combined. Captures expand in base64; AWS files are combined into one input.</p>
      <div className="flex flex-wrap items-center gap-3">
        <label className="text-sm">Select Files
          <input aria-label="Select Files" type="file" multiple disabled={isScanning}
            accept=".py,.java,.go,.json,.pcap,.pcapng,.cap" className="block mt-1 text-xs"
            onChange={event => setFiles(Array.from(event.target.files ?? []))} />
        </label>
        <button onClick={() => onScan(files)} disabled={isScanning || !files.length}
          className="px-4 py-2 rounded-lg bg-emerald-400 text-slate-950 text-xs font-semibold disabled:opacity-40">
          {isScanning ? 'Scanning…' : error ? 'Retry Scan' : 'Scan Selected Files'}
        </button>
        {isScanning && <button onClick={onCancel} className="text-xs underline">Cancel Scan</button>}
        <button onClick={onLoadDemoData} className="flex items-center gap-2 text-xs text-emerald-300"><Sparkles className="w-4 h-4" />Load Validated Fixture Dataset</button>
      </div>
      {files.length > 0 && <p className="text-xs text-slate-300">Selected: {files.map(file => file.name).join(', ')}. {isScanning ? 'Scanning; the previous result remains visible below.' : 'Click Scan to analyze these files.'}</p>}
      {isScanning && <p role="status" className="text-sm text-amber-300">Reading files and waiting for the scan API…</p>}
      {error && <p role="alert" className="text-sm text-rose-300">{error}</p>}
    </section>
  );
};
