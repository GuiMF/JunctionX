import type { ScanResult } from '../types/contract';
import { apiRequest } from '../api/client';

async function exportScan(scanResult: ScanResult, format: 'json' | 'cyclonedx', signal?: AbortSignal) {
  const filename = format === 'json' ? `quantumtrace-scan-${scanResult.scan_id}.json` : `quantumtrace-cbom-${scanResult.scan_id}.cdx.json`;
  // The browser owns the displayed result; another server instance may have no
  // record of its ID. Submit that exact result for stateless conversion.
  const blob = await apiRequest(`/api/exports?format=${format}`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(scanResult), signal },
    response => response.blob(), 10_000);
  if (signal?.aborted) return;
  const url = window.URL.createObjectURL(blob);
  try { download(url, filename); }
  finally { window.URL.revokeObjectURL(url); }
}

function download(href: string, filename: string) {
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}

export function exportProjectJson(scanResult: ScanResult, signal?: AbortSignal) {
  return exportScan(scanResult, 'json', signal);
}

export function exportCycloneDxCbom(scanResult: ScanResult, signal?: AbortSignal) {
  return exportScan(scanResult, 'cyclonedx', signal);
}
