import type { ScanResult } from '../types/contract';
import mockCycloneDxCbom from '../../../examples/scan-original.cdx.json';
import { mockScanResult } from '../fixtures/mockData';
import { apiRequest } from '../api/client';

async function exportScan(scanResult: ScanResult, format: 'json' | 'cyclonedx', signal?: AbortSignal) {
  const filename = format === 'json' ? `quantumtrace-scan-${scanResult.scan_id}.json` : `quantumtrace-cbom-${scanResult.scan_id}.cdx.json`;
  // Only the exact fixture has a bundled report; never substitute demo evidence.
  if (JSON.stringify(scanResult) === JSON.stringify(mockScanResult)) {
    const data = format === 'json' ? scanResult : mockCycloneDxCbom;
    download('data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(data, null, 2)), filename);
    return;
  }
  const blob = await apiRequest(`/api/scans/${encodeURIComponent(scanResult.scan_id)}/export?format=${format}`,
    { signal }, response => response.blob(), 10_000);
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
