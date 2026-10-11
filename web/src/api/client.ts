import type { ScanRequest, ScanResult } from '../types/contract';
import { MAX_BATCH_BYTES, prepareScan, prepareScanBatches, validateFileSelection } from '../utils/scanInputs';

export function apiUrl(path: string): string {
  // Browser requests use the public service rewrite; internal bindings belong
  // to server functions and must never be embedded in a Vite build.
  const base = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '');
  return `${base}${path}`;
}

export async function apiRequest<T>(path: string, options: RequestInit, read: (response: Response) => Promise<T>, timeoutMs = 300_000): Promise<T> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener('abort', abort, { once: true });
  if (options.signal?.aborted) controller.abort();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
  try {
    const response = await fetch(apiUrl(path), { ...options, signal: controller.signal });
    if (!response.ok) {
      if (path.startsWith('/api/uploads')) {
        const body = await response.json().catch(() => null);
        if (typeof body?.detail === 'string') throw new Error(body.detail);
      }
      if (response.status === 404) throw new Error('Scan is missing or was evicted (HTTP 404). Scan the files again before exporting.');
      if (response.status === 422) throw new Error('API validation failed (HTTP 422). Check the file types, names and size limits, then retry.');
      throw new Error(`API request failed (HTTP ${response.status}). Please retry.`);
    }
    return await read(response);
  } catch (error) {
    if (timedOut) throw new Error('Request timed out. Retry with fewer files. The server may still finish the previous scan.');
    if (options.signal?.aborted) throw new DOMException('Request cancelled', 'AbortError');
    if (error instanceof TypeError) throw new Error('Cannot reach the scan API. Check that it is running and VITE_API_BASE_URL and CORS are configured, then retry.');
    throw error;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', abort);
  }
}

export function submitScan(request: ScanRequest, signal: AbortSignal): Promise<ScanResult> {
  return apiRequest('/api/scans', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request), signal,
  }, readScanResult);
}

async function readScanResult(response: Response): Promise<ScanResult> {
  const scan: ScanResult = await response.json();
  if (!scan.scan_id || !['completed', 'partial', 'failed'].includes(scan.status) ||
      !Array.isArray(scan.findings) || !Array.isArray(scan.coverage) || !Array.isArray(scan.errors) || !scan.score) {
    throw new Error('The API returned an invalid scan result. Check the API version and retry.');
  }
  return scan;
}

export async function submitFiles(files: File[], signal: AbortSignal, progress: (message: string) => void = () => {}): Promise<ScanResult> {
  const total = validateFileSelection(files);
  signal.throwIfAborted();
  if (total <= MAX_BATCH_BYTES) {
    const request = await prepareScan(files);
    signal.throwIfAborted();
    return submitScan(request, signal);
  }
  const { upload_id } = await apiRequest<{ upload_id: string }>('/api/uploads', { method: 'POST', signal }, response => response.json());
  if (!upload_id) throw new Error('The API did not create an upload. Please retry.');
  const path = `/api/uploads/${encodeURIComponent(upload_id)}`;
  let completed = false;
  try {
    for await (const batch of prepareScanBatches(files, signal)) {
      const receipt = await apiRequest<{ received_bytes: number }>(`${path}/batches`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(batch), signal,
      }, response => response.json());
      progress(`Uploaded ${Math.round(receipt.received_bytes / 1024 / 1024)} MiB of approximately ${Math.ceil(total / 1024 / 1024)} MiB…`);
    }
    signal.throwIfAborted();
    progress('Upload complete. Analyzing files…');
    const result = await apiRequest(`${path}/complete`, { method: 'POST', signal }, readScanResult, 30 * 60_000);
    completed = true;
    return result;
  } finally {
    // Cancellation uses a fresh signal so the server can discard temporary content.
    if (!completed) await apiRequest(path, { method: 'DELETE' }, async () => undefined, 10_000).catch(() => {});
  }
}
