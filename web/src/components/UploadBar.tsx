import React, { useState } from 'react';
import { UploadCloud, Sparkles, CheckCircle2 } from 'lucide-react';

interface UploadBarProps {
  onLoadDemoData: () => void;
  onSimulateScan: (filesCount: number) => void;
}

export const UploadBar: React.FC<UploadBarProps> = ({ onLoadDemoData, onSimulateScan }) => {
  const [isScanning, setIsScanning] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState<string[]>([]);

  const handleSimulatedScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      setIsScanning(false);
      onLoadDemoData();
    }, 1000);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const names = Array.from(e.target.files).map((f) => f.name);
      setUploadedFiles(names);
      onSimulateScan(names.length);
    }
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm">
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
            <UploadCloud className="w-4 h-4 text-emerald-400" />
            Ingest Multi-Source Discovery Data
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Ingest PCAP network captures, multi-language source code (Python, Java, Go), and AWS JSON exports.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <label className="cursor-pointer inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 transition-colors">
            <UploadCloud className="w-3.5 h-3.5 text-slate-400" />
            Upload Files
            <input
              type="file"
              multiple
              onChange={handleFileChange}
              className="hidden"
            />
          </label>

          <button
            onClick={handleSimulatedScan}
            disabled={isScanning}
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs shadow-sm transition-colors"
          >
            {isScanning ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                Analyzing Cryptography...
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5" />
                Load Hackathon Dataset
              </>
            )}
          </button>
        </div>
      </div>

      {uploadedFiles.length > 0 && (
        <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center gap-2 text-xs text-emerald-400">
          <CheckCircle2 className="w-3.5 h-3.5" />
          <span>Uploaded {uploadedFiles.length} file(s): {uploadedFiles.slice(0, 3).join(', ')}{uploadedFiles.length > 3 ? '...' : ''}</span>
        </div>
      )}
    </div>
  );
};
