import type { ScanResult } from '../types/contract';
import { mockCycloneDxCbom } from '../fixtures/mockCbom';
import { mockScanResult } from '../fixtures/mockData';

export function exportProjectJson(scanResult: ScanResult) {
  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(scanResult, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute('href', dataStr);
  downloadAnchor.setAttribute('download', `quantumtrace-scan-${scanResult.scan_id}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

export async function exportCycloneDxCbom(scanResult: ScanResult) {
  const filename = `quantumtrace-cbom-${scanResult.scan_id}.cdx.json`;
  // Only this exact fixture has a bundled report. Other synthetic scans still
  // need their own export; never substitute sample evidence for a different scan.
  if (JSON.stringify(scanResult) === JSON.stringify(mockScanResult)) {
    const a = document.createElement('a');
    a.href = 'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(mockCycloneDxCbom, null, 2));
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    return;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(`http://127.0.0.1:8000/api/scans/${encodeURIComponent(scanResult.scan_id)}/export?format=cyclonedx`, {
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`CBOM export failed (HTTP ${res.status}). Please retry.`);
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  } catch (error) {
    if (controller.signal.aborted) throw new Error('CBOM export timed out. Please retry.');
    throw error instanceof Error ? error : new Error('CBOM export failed. Please retry.');
  } finally {
    clearTimeout(timeout);
  }
}
