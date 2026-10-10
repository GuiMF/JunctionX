import type { ScanInput, ScanRequest } from '../types/contract';
import { filePath } from './folderFiles';

export const MAX_SCAN_FILES = 10_000;

const MIB = 1024 * 1024;
export const MAX_INPUT_MIB = 64;
export const MAX_SCAN_MIB = 256;
export const MAX_INPUT_BYTES = MAX_INPUT_MIB * MIB;
const encoder = new TextEncoder();
const cloudCollections = {
  Keys: 'kms_key_inventory.json',
  Certificates: 'acm_certificates.json',
  LoadBalancers: 'load_balancer_listeners.json',
};

function checkSize(name: string, bytes: number) {
  if (bytes > MAX_INPUT_BYTES) throw new Error(`${name}: exceeds ${MAX_INPUT_MIB} MiB encoded. Choose a smaller file (captures expand in base64).`);
}

export function validateInputs(inputs: ScanInput[]): void {
  if (inputs.length < 1 || inputs.length > MAX_SCAN_FILES) throw new Error(`Select 1–${MAX_SCAN_FILES} inputs per scan.`);
  const names = inputs.map(input => input.name.trim());
  if (names.some(name => !name) || new Set(names).size !== names.length) {
    throw new Error('Input names must be nonempty and unique. Rename duplicate files and select them again.');
  }
  let total = 0;
  for (const input of inputs) {
    const bytes = encoder.encode(input.content).byteLength;
    checkSize(input.name, bytes);
    total += bytes;
  }
  if (total > MAX_SCAN_MIB * MIB) throw new Error(`Combined inputs exceed ${MAX_SCAN_MIB} MiB encoded. Select fewer or smaller files.`);
}

// Related snapshots in each directory share an adapter invocation so certificate links resolve.
export async function prepareScan(files: File[]): Promise<ScanRequest> {
  if (!files.length || files.length > MAX_SCAN_FILES) throw new Error(`Select 1–${MAX_SCAN_FILES} files per scan.`);
  if (new Set(files.map(file => filePath(file).trim())).size !== files.length) {
    throw new Error('Input names must be unique. Rename duplicate files and select them again.');
  }
  let estimatedTotal = 0;
  for (const file of files) {
    const size = /\.(pcap|pcapng|cap)$/i.test(file.name) ? 4 * Math.ceil(file.size / 3) : file.size;
    checkSize(filePath(file), size);
    estimatedTotal += size;
  }
  if (estimatedTotal > MAX_SCAN_MIB * MIB) throw new Error(`Combined inputs exceed ${MAX_SCAN_MIB} MiB encoded. Select fewer or smaller files.`);
  const inputs: ScanInput[] = [];
  const cloudGroups = new Map<string, { snapshots: Map<string, string>; names: string[] }>();
  for (const file of files) {
    const extension = file.name.split('.').pop()?.toLowerCase();
    const capture = ['pcap', 'pcapng', 'cap'].includes(extension ?? '');
    const source = ['py', 'java', 'go'].includes(extension ?? '');
    if (!capture && !source && extension !== 'json') {
      throw new Error(`${filePath(file)}: unsupported type. Select .py, .java, .go, .pcap, .pcapng, .cap or AWS snapshot .json files.`);
    }
    let bytes: Uint8Array;
    try { bytes = new Uint8Array(await file.arrayBuffer()); }
    catch { throw new Error(`${filePath(file)}: could not read this file. Check that it is accessible and select it again.`); }
    let content: string;
    if (capture) {
      let binary = '';
      for (let offset = 0; offset < bytes.length; offset += 32768) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
      }
      content = btoa(binary);
    } else {
      try { content = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
      catch { throw new Error(`${filePath(file)}: invalid UTF-8. Save the source or snapshot as UTF-8 and select it again.`); }
    }
    if (extension === 'json') {
      const entries = cloudSnapshotEntries(content, filePath(file));
      const directory = filePath(file).includes('/') ? filePath(file).slice(0, filePath(file).lastIndexOf('/') + 1) : '';
      const group = cloudGroups.get(directory) ?? { snapshots: new Map<string, string>(), names: [] };
      cloudGroups.set(directory, group);
      const { snapshots } = group;
      for (const [key, snapshot] of entries) {
        if (snapshots.has(key)) throw new Error(`${filePath(file)}: duplicate AWS snapshot ${key}. Select one related snapshot of each kind; scan other environments separately.`);
        snapshots.set(key, snapshot);
      }
      group.names.push(filePath(file));
    } else {
      inputs.push({ name: filePath(file), source_type: capture ? 'pcap' : 'source', format: 'raw', encoding: capture ? 'base64' : 'utf-8', content });
    }
  }
  for (const [directory, { snapshots, names: cloudNames }] of cloudGroups) {
    // Preserve raw snapshot text, including keys that backend validation must inspect.
    const content = `{${[...snapshots].map(([key, snapshot]) => `${JSON.stringify(key)}:${snapshot}`).join(',')}}`;
    inputs.push({ name: cloudNames.length === 1 ? cloudNames[0] : `${directory}aws-snapshots.json`, source_type: 'cloud', format: 'raw', encoding: 'utf-8', content });
  }
  validateInputs(inputs);
  return { inputs, synthetic: false };
}

// Shared by folder discovery and scan preparation; arbitrary JSON is not a cloud input.
export function cloudSnapshotEntries(content: string, name: string): [string, string][] {
  let value: Record<string, unknown>;
  try { value = JSON.parse(content); }
  catch { throw new Error(`${name}: invalid JSON. Fix the snapshot and select it again.`); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${name}: expected an AWS snapshot object.`);
  }
  const collections = Object.entries(cloudCollections).filter(([key]) => key in value);
  let entries: [string, string][];
  if (collections.length === 1 && Array.isArray(value[collections[0][0]])) {
    entries = [[collections[0][1], content]];
  } else if (collections.length === 0 && Object.keys(value).length &&
      Object.keys(value).every(key => Object.values(cloudCollections).includes(key))) {
    entries = Object.entries(value).map(([key, snapshot]) => [key, JSON.stringify(snapshot)]);
  } else {
    throw new Error(`${name}: ambiguous or unsupported JSON. Use an AWS snapshot with Keys, Certificates or LoadBalancers, or a documented filename-keyed bundle.`);
  }
  return entries;
}
