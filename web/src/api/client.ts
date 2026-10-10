import type { ScanRequest, ScanResult } from '../types/contract';

export function apiUrl(path: string): string {
  const base = (import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000').replace(/\/+$/, '');
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
  }, async (response) => {
    const scan: ScanResult = await response.json();
    if (!scan.scan_id || !['completed', 'partial', 'failed'].includes(scan.status) ||
        !Array.isArray(scan.findings) || !Array.isArray(scan.coverage) || !Array.isArray(scan.errors) || !scan.score) {
      throw new Error('The API returned an invalid scan result. Check the API version and retry.');
    }
    return scan;
  });
}
