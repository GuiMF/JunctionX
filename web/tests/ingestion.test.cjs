const assert = require('node:assert/strict');
const { test, afterEach, mock } = require('node:test');
require('./register.cjs');
const { prepareScan, validateInputs } = require('../src/utils/scanInputs.ts');
const { mockScanResult } = require('../src/fixtures/mockData.ts');
const { JSDOM } = require('jsdom');
const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost:5173' });
global.window = dom.window;
global.document = dom.window.document;
global.IS_REACT_ACT_ENVIRONMENT = true;
const React = require('react');
const { act } = React;
const { createRoot } = require('react-dom/client');
const { App } = require('../src/App.tsx');
const file = (name = 'example.py', content = 'import hashlib\nhashlib.md5(b"data")') => new File([content], name);
const response = (status = 'completed') => ({ ...structuredClone(mockScanResult), scan_id: `live-${status}`, synthetic: false, status,
  errors: status === 'completed' ? [] : [{ input_name: 'broken.pcap', source_type: 'pcap', code: 'parse_failed', message: 'Invalid capture' }] });
afterEach(() => { mock.restoreAll(); delete global.__TEST_VITE_ENV__; document.body.innerHTML = ''; });

async function mount(t) {
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => root.render(React.createElement(App)));
  t.after(async () => { await act(async () => root.unmount()); container.remove(); });
  return container;
}
const button = (label) => [...document.querySelectorAll('button')].find(node => node.textContent.includes(label));
async function click(label) { assert.ok(button(label), label); await act(async () => button(label).click()); }
async function select(files) {
  const input = document.querySelector('input[type=file]');
  Object.defineProperty(input, 'files', { configurable: true, value: files });
  await act(async () => input.dispatchEvent(new window.Event('change', { bubbles: true })));
}

test('source content is UTF-8 raw and binary captures are base64', async () => {
  const request = await prepareScan([file('source.py', '# café'), file('capture.pcap', new Uint8Array([0, 255, 128, 13]))]);
  assert.deepEqual(request.inputs.map(x => [x.source_type, x.format, x.encoding, x.content]), [
    ['source', 'raw', 'utf-8', '# café'], ['pcap', 'raw', 'base64', 'AP+ADQ==']]);
});

test('AWS snapshots become one documented bundle, including prebundled snapshots', async () => {
  const acm = { Certificates: [], GeneratedAt: '2026-10-10T00:00:00Z' };
  const listeners = { LoadBalancers: [], GeneratedAt: '2026-10-10T00:00:00Z' };
  const { inputs } = await prepareScan([file('renamed.json', JSON.stringify(acm)), file('bundle.json', JSON.stringify({ 'load_balancer_listeners.json': listeners }))]);
  assert.equal(inputs.length, 1);
  assert.equal(inputs[0].source_type, 'cloud');
  assert.deepEqual(JSON.parse(inputs[0].content), { 'acm_certificates.json': acm, 'load_balancer_listeners.json': listeners });
  await assert.rejects(prepareScan([file('one.json', JSON.stringify(acm)), file('two.json', JSON.stringify(acm))]), /duplicate AWS snapshot/);
});

test('unsupported, ambiguous, malformed and non-UTF-8 files have actionable errors', async () => {
  for (const [input, expected] of [
    [file('data.txt'), /unsupported type/], [file('unknown.json', '{}'), /ambiguous or unsupported/],
    [file('ambiguous.json', '{"Keys":[],"Certificates":[]}'), /ambiguous/],
    [file('bad.json', '{'), /invalid JSON/], [file('bad.py', new Uint8Array([255])), /invalid UTF-8/],
  ]) await assert.rejects(prepareScan([input]), expected);
});

test('count, names and encoded byte limits apply before reading and after AWS bundling', async () => {
  await assert.rejects(prepareScan([]), /1–16/);
  await assert.rejects(prepareScan(Array.from({ length: 17 }, (_, i) => file(`${i}.py`))), /1–16/);
  await assert.rejects(prepareScan([file(), file()]), /unique/);
  const huge = { name: 'huge.pcap', size: 6 * 1024 * 1024 + 1, arrayBuffer() { throw Error('must not read'); } };
  await assert.rejects(prepareScan([huge]), /8 MiB encoded/);
  const input = { name: 'a.py', source_type: 'source', format: 'raw', content: 'é'.repeat(4 * 1024 * 1024) };
  validateInputs([input]);
  assert.throws(() => validateInputs([{ ...input, content: input.content + 'é' }]), /8 MiB/);
  assert.throws(() => validateInputs([input, { ...input, name: 'b.py' }, { ...input, name: 'c.py', content: 'x' }]), /16 MiB/);
  const snapshot = JSON.stringify({ Keys: [], padding: ' '.repeat(4 * 1024 * 1024) });
  await assert.rejects(prepareScan([file('keys.json', snapshot), file('certs.json', snapshot.replace('Keys', 'Certificates'))]), /8 MiB/);
});

test('successful scan updates the active result, clears evidence, and exports both formats from a custom API port', async (t) => {
  global.__TEST_VITE_ENV__ = { VITE_API_BASE_URL: 'http://127.0.0.1:8123/' };
  const live = response();
  live.score.value = 12.5;
  live.findings = [{ ...live.findings[0], algorithm: 'LIVE-ALGORITHM' }];
  live.coverage = [{ source_type: 'source', input_name: 'example.py', unit: 'files', assessed: 37, unknown: 0, unsupported: 0, failed: 0 }];
  const requests = [];
  mock.method(global, 'fetch', async (url, options) => {
    requests.push([url, options]);
    return url.endsWith('/api/scans') ? { ok: true, json: async () => live } : { ok: true, blob: async () => new Blob(['live export']) };
  });
  const downloads = [];
  window.URL.createObjectURL = () => 'blob:live'; window.URL.revokeObjectURL = () => {};
  mock.method(window.HTMLAnchorElement.prototype, 'click', function () { downloads.push(this.download); });
  const container = await mount(t);
  await act(async () => container.querySelector('tbody button').click()); assert.match(container.textContent, /Verifiable Evidence/);
  await select([file()]); await click('Scan Selected Files');
  assert.doesNotMatch(container.textContent, /Verifiable Evidence/);
  assert.match(container.querySelector('[aria-label="Active scan"]').textContent, /Live scan · Status: completed.*live-completed/);
  assert.match(container.querySelector('tbody').textContent, /LIVE-ALGORITHM/);
  assert.match(container.textContent, /37 files/);
  assert.match(container.textContent, /Exposure Score: 12.5\/100/);
  assert.equal(JSON.parse(requests[0][1].body).inputs[0].content, await file().text());
  await click('Project JSON'); await click('CycloneDX 1.6 CBOM');
  assert.deepEqual(requests.map(x => x[0]), ['http://127.0.0.1:8123/api/scans', 'http://127.0.0.1:8123/api/scans/live-completed/export?format=json', 'http://127.0.0.1:8123/api/scans/live-completed/export?format=cyclonedx']);
  assert.deepEqual(downloads, ['quantumtrace-scan-live-completed.json', 'quantumtrace-cbom-live-completed.cdx.json']);
});

for (const status of ['partial', 'failed']) test(`HTTP 201 ${status} exposes per-input errors and the actual scan status`, async (t) => {
  mock.method(global, 'fetch', async () => ({ ok: true, status: 201, json: async () => response(status) }));
  const container = await mount(t);
  await select([file(), file('broken.pcap')]); await click('Scan Selected Files');
  assert.match(container.querySelector('[aria-label="Active scan"]').textContent, new RegExp(`Status: ${status}`));
  assert.match(container.querySelector('[aria-label="Input errors"]').textContent, /broken.pcap.*parse_failed: Invalid capture/);
});

for (const scenario of ['offline', 'validation', 'timeout']) test(`${scenario} failure offers retry and preserves the active scan`, async (t) => {
  const nativeTimeout = global.setTimeout;
  if (scenario === 'timeout') mock.method(global, 'setTimeout', (callback) => nativeTimeout(callback, 1));
  mock.method(global, 'fetch', async (_url, options) => {
    if (scenario === 'offline') throw new TypeError('Failed to fetch');
    if (scenario === 'validation') return { ok: false, status: 422 };
    return new Promise((_, reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted'))));
  });
  const container = await mount(t);
  await select([file()]); await click('Scan Selected Files');
  if (scenario === 'timeout') await act(async () => new Promise(resolve => nativeTimeout(resolve, 10)));
  assert.match(container.querySelector('[role=alert]').textContent, scenario === 'offline' ? /Cannot reach/ : scenario === 'validation' ? /validation failed/ : /timed out/);
  assert.equal(button('Retry Scan').disabled, false);
  assert.match(container.querySelector('[aria-label="Active scan"]').textContent, /Demo mode/);
  mock.restoreAll();
  mock.method(global, 'fetch', async () => ({ ok: true, json: async () => response() }));
  await click('Retry Scan');
  assert.match(container.querySelector('[aria-label="Active scan"]').textContent, /Live scan/);
});

test('invalid and oversized selections never submit and allow replacing the files', async (t) => {
  const fetch = mock.method(global, 'fetch', async () => { throw Error('must not submit'); });
  const container = await mount(t);
  await select([file('unknown.txt')]); await click('Scan Selected Files');
  assert.match(container.querySelector('[role=alert]').textContent, /unsupported type/);
  await select([{ name: 'big.py', size: 9 * 1024 * 1024 }]); await click('Retry Scan');
  assert.match(container.querySelector('[role=alert]').textContent, /8 MiB/);
  assert.equal(fetch.mock.callCount(), 0);
  assert.equal(document.querySelector('input[type=file]').disabled, false);
});

test('pending state prevents duplicate requests; reset and a newer scan ignore stale responses', async (t) => {
  const pending = [];
  const fetch = mock.method(global, 'fetch', (_url, options) => new Promise(resolve => pending.push({ resolve, signal: options.signal })));
  const container = await mount(t);
  await select([file()]); await click('Scan Selected Files');
  assert.equal(button('Scanning…').disabled, true);
  await click('Scanning…'); assert.equal(fetch.mock.callCount(), 1);
  assert.ok(container.querySelector('[role=status]'));
  await click('Reset Data'); assert.equal(pending[0].signal.aborted, true);
  assert.equal(document.querySelector('input[type=file]').files.length, 0);
  await select([file('new.py')]); await click('Scan Selected Files');
  await act(async () => pending[1].resolve({ ok: true, json: async () => ({ ...response(), scan_id: 'newest' }) }));
  await act(async () => pending[0].resolve({ ok: true, json: async () => ({ ...response(), scan_id: 'stale' }) }));
  assert.match(container.querySelector('[aria-label="Active scan"]').textContent, /newest/);
  assert.doesNotMatch(container.querySelector('[aria-label="Active scan"]').textContent, /stale/);
});

test('missing backend exports show errors without downloading demo evidence; reset restores offline exports', async (t) => {
  mock.method(global, 'fetch', async () => ({ ok: true, json: async () => response() }));
  const downloads = [];
  mock.method(window.HTMLAnchorElement.prototype, 'click', function () { downloads.push(this.href); });
  const container = await mount(t);
  await select([file()]); await click('Scan Selected Files');
  mock.method(global, 'fetch', async () => ({ ok: false, status: 404 }));
  for (const label of ['Project JSON', 'CycloneDX 1.6 CBOM']) {
    await click(label); assert.match(container.querySelector('[role=alert]').textContent, /evicted.*Scan the files again/);
  }
  assert.equal(downloads.length, 0);
  await click('Reset Data'); await click('Project JSON'); await click('CycloneDX 1.6 CBOM');
  assert.equal(downloads.length, 2);
  assert.deepEqual(JSON.parse(decodeURIComponent(downloads[0].split(',')[1])), mockScanResult);
});

test('reset during file reading prevents submission and clears the pending selection', async (t) => {
  let finishRead;
  const fetch = mock.method(global, 'fetch', async () => { throw Error('must not submit'); });
  const container = await mount(t);
  await select([{ name: 'slow.py', size: 10, arrayBuffer: () => new Promise(resolve => { finishRead = resolve; }) }]);
  await click('Scan Selected Files');
  await click('Reset Data');
  await act(async () => finishRead(new TextEncoder().encode('# source').buffer));
  assert.equal(fetch.mock.callCount(), 0);
  assert.equal(button('Scan Selected Files').disabled, true);
  assert.match(container.querySelector('[aria-label="Active scan"]').textContent, /Demo mode/);
});

test('unreadable local files explain how to recover without submitting', async () => {
  await assert.rejects(prepareScan([{ name: 'gone.py', size: 10, arrayBuffer: async () => { throw new Error('unavailable'); } }]), /gone.py: could not read.*select it again/);
});
