const assert = require('node:assert/strict');
const { test, afterEach, mock } = require('node:test');
require('./register.cjs');
const { prepareScan, validateInputs } = require('../src/utils/scanInputs.ts');
const { mockScanResult } = require('../src/fixtures/mockData.ts');
const { JSDOM } = require('jsdom');
const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost:5173' });
global.window = dom.window;
global.document = dom.window.document;
global.HTMLElement = dom.window.HTMLElement;
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
const button = (label) => [...document.querySelectorAll('button')].find(node => node.textContent.includes(label) || node.getAttribute('aria-label') === label);
async function click(label) { assert.ok(button(label), label); await act(async () => button(label).click()); }
async function select(files) {
  if (!document.querySelector('input[type=file]')) await click('Import data');
  const input = document.querySelector('input[type=file]');
  assert.ok(input, 'import dialog exposes file selection');
  Object.defineProperty(input, 'files', { configurable: true, value: files });
  await act(async () => input.dispatchEvent(new window.Event('change', { bubbles: true })));
}

const activeScan = (container) => container.querySelector('main[aria-label="Active scan"]');
function assertActiveScan(container, { id, status }) {
  const active = activeScan(container);
  assert.ok(active, 'active scan metadata remains accessible');
  assert.equal(active.dataset.scanId, id);
  assert.equal(active.dataset.scanStatus, status);
}
async function exportFormat(label) { await click('Export'); await click(label); }
test('dashboard starts empty with no demo controls and export disabled', async (t) => {
  const container = await mount(t);
  assertActiveScan(container, { id: undefined, status: 'empty' });
  assert.match(container.textContent, /No scans yet/);
  assert.equal(container.querySelector('tbody'), null);
  assert.equal(button('Export current scan').disabled, true);
  assert.doesNotMatch(container.textContent, /Migration comparison/);
  await click('Import files');
  assert.ok(container.querySelector('[role=dialog]'));
  assert.equal(button('Load demo dataset'), undefined);
});

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
  await assert.rejects(prepareScan([]), /1–10000/);
  await assert.rejects(prepareScan(Array.from({ length: 10001 }, (_, i) => file(`${i}.py`))), /1–10000/);
  await assert.rejects(prepareScan([file(), file()]), /unique/);
  const huge = { name: 'huge.pcap', size: 48 * 1024 * 1024 + 1, arrayBuffer() { throw Error('must not read'); } };
  await assert.rejects(prepareScan([huge]), /64 MiB encoded/);
  const input = { name: 'a.py', source_type: 'source', format: 'raw', content: 'é'.repeat(32 * 1024 * 1024) };
  validateInputs([input]);
  assert.throws(() => validateInputs([{ ...input, content: input.content + 'é' }]), /64 MiB/);
  assert.throws(() => validateInputs([...Array.from({ length: 4 }, (_, i) => ({ ...input, name: `${i}.py` })), { ...input, name: 'extra.py', content: 'x' }]), /256 MiB/);
  const snapshot = JSON.stringify({ Keys: [], padding: ' '.repeat(32 * 1024 * 1024) });
  await assert.rejects(prepareScan([file('keys.json', snapshot), file('certs.json', snapshot.replace('Keys', 'Certificates'))]), /64 MiB/);
});

test('successful scan updates the active result and evidence, closes import, and exports both formats from a custom API port', async (t) => {
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
  await select([file()]); await click('Scan selected files');
  assert.equal(container.querySelector('[role=dialog]'), null, 'successful scan closes the import dialog');
  assertActiveScan(container, { id: 'live-completed', status: 'completed' });
  assert.match(container.querySelector('tbody').textContent, /LIVE-ALGORITHM/);
  assert.match(container.textContent, /37 files/);
  assert.ok(container.querySelector('[aria-label="Exposure Score: 12.5/100"]'));
  await act(async () => container.querySelector('tbody button').click());
  assert.match(container.querySelector('[role=dialog]').textContent, /LIVE-ALGORITHM/);
  await click('Close evidence inspector');
  assert.equal(JSON.parse(requests[0][1].body).inputs[0].content, await file().text());
  await exportFormat('Project JSON'); await exportFormat('CycloneDX 1.6 CBOM');
  assert.deepEqual(requests.map(x => x[0]), ['http://127.0.0.1:8123/api/scans', 'http://127.0.0.1:8123/api/scans/live-completed/export?format=json', 'http://127.0.0.1:8123/api/scans/live-completed/export?format=cyclonedx']);
  assert.deepEqual(downloads, ['quantumtrace-scan-live-completed.json', 'quantumtrace-cbom-live-completed.cdx.json']);
});

for (const status of ['partial', 'failed']) test(`HTTP 201 ${status} exposes per-input errors and the actual scan status`, async (t) => {
  mock.method(global, 'fetch', async () => ({ ok: true, status: 201, json: async () => response(status) }));
  const container = await mount(t);
  await select([file(), file('broken.pcap')]); await click('Scan selected files');
  assertActiveScan(container, { id: `live-${status}`, status });
  assert.equal(container.querySelector('[role=dialog]'), null, 'accepted API results close import even with per-input failures');
  assert.match(container.querySelector('[aria-label="Input errors"]').textContent, /broken.pcap.*parse_failed: Invalid capture/);
});

for (const scenario of ['offline', 'validation', 'timeout']) test(`${scenario} failure offers retry and preserves the active scan`, async (t) => {
  mock.method(global, 'fetch', async () => ({ ok: true, json: async () => response() }));
  const container = await mount(t);
  await select([file()]); await click('Scan selected files');
  const nativeTimeout = global.setTimeout;
  if (scenario === 'timeout') mock.method(global, 'setTimeout', (callback) => nativeTimeout(callback, 1));
  mock.method(global, 'fetch', async (_url, options) => {
    if (scenario === 'offline') throw new TypeError('Failed to fetch');
    if (scenario === 'validation') return { ok: false, status: 422 };
    return new Promise((_, reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted'))));
  });
  await select([file()]); await click('Scan selected files');
  if (scenario === 'timeout') await act(async () => new Promise(resolve => nativeTimeout(resolve, 10)));
  assert.match(container.querySelector('[role=alert]').textContent, scenario === 'offline' ? /Cannot reach/ : scenario === 'validation' ? /validation failed/ : /timed out/);
  assert.equal(button('Retry scan').disabled, false);
  assertActiveScan(container, { id: 'live-completed', status: 'completed' });
  mock.restoreAll();
  mock.method(global, 'fetch', async () => ({ ok: true, json: async () => response() }));
  await click('Retry scan');
  assertActiveScan(container, { id: 'live-completed', status: 'completed' });
  assert.equal(container.querySelector('[role=dialog]'), null);
});

test('invalid and oversized selections never submit and allow replacing the files', async (t) => {
  const fetch = mock.method(global, 'fetch', async () => { throw Error('must not submit'); });
  const container = await mount(t);
  await select([file('unknown.txt')]);
  assert.match(container.querySelector('[role=alert]').textContent, /files were not added.*supported files/);
  assert.equal(button('Scan selected files').disabled, true, 'unsupported selection cannot be submitted');
  await select([{ name: 'big.py', size: 65 * 1024 * 1024 }]); await click('Scan selected files');
  assert.match(container.querySelector('[role=alert]').textContent, /64 MiB/);
  assert.equal(fetch.mock.callCount(), 0);
  assert.equal(document.querySelector('input[type=file]').disabled, false);
});

test('pending state prevents duplicate requests; cancellation and a newer scan ignore stale responses', async (t) => {
  const pending = [];
  const fetch = mock.method(global, 'fetch', (_url, options) => new Promise(resolve => pending.push({ resolve, signal: options.signal })));
  const container = await mount(t);
  await select([file()]); await click('Scan selected files');
  assert.equal(button('Scanning…').disabled, true);
  await click('Scanning…'); assert.equal(fetch.mock.callCount(), 1);
  assert.ok(container.querySelector('[role=status]'));
  await click('Close import dialog'); assert.equal(pending[0].signal.aborted, true);
  assertActiveScan(container, { id: undefined, status: 'empty' });
  await click('Import data');
  assert.equal(document.querySelector('input[type=file]').files.length, 0);
  await select([file('new.py')]); await click('Scan selected files');
  await act(async () => pending[1].resolve({ ok: true, json: async () => ({ ...response(), scan_id: 'newest' }) }));
  await act(async () => pending[0].resolve({ ok: true, json: async () => ({ ...response(), scan_id: 'stale' }) }));
  assertActiveScan(container, { id: 'newest', status: 'completed' });
  assert.notEqual(activeScan(container).dataset.scanId, 'stale');
});

test('missing backend exports show errors without downloading demo evidence', async (t) => {
  mock.method(global, 'fetch', async () => ({ ok: true, json: async () => response() }));
  const downloads = [];
  mock.method(window.HTMLAnchorElement.prototype, 'click', function () { downloads.push(this.href); });
  const container = await mount(t);
  await select([file()]); await click('Scan selected files');
  mock.method(global, 'fetch', async () => ({ ok: false, status: 404 }));
  for (const label of ['Project JSON', 'CycloneDX 1.6 CBOM']) {
    await exportFormat(label); assert.match(container.querySelector('[role=alert]').textContent, /evicted.*Scan the files again/);
  }
  assert.equal(downloads.length, 0);
});

test('closing import during file reading prevents submission and clears the pending selection', async (t) => {
  let finishRead;
  const fetch = mock.method(global, 'fetch', async () => { throw Error('must not submit'); });
  const container = await mount(t);
  await select([{ name: 'slow.py', size: 10, arrayBuffer: () => new Promise(resolve => { finishRead = resolve; }) }]);
  await click('Scan selected files');
  await click('Close import dialog');
  await act(async () => finishRead(new TextEncoder().encode('# source').buffer));
  assert.equal(fetch.mock.callCount(), 0);
  await click('Import data');
  assert.equal(document.querySelector('input[type=file]').files.length, 0);
  assert.equal(button('Scan selected files').disabled, true);
  assertActiveScan(container, { id: undefined, status: 'empty' });
});

test('unreadable local files explain how to recover without submitting', async () => {
  await assert.rejects(prepareScan([{ name: 'gone.py', size: 10, arrayBuffer: async () => { throw new Error('unavailable'); } }]), /gone.py: could not read.*select it again/);
});

const folderFile = (path, content) => Object.defineProperty(file(path.split('/').pop(), content), 'webkitRelativePath', { value: path });

test('folder picker filters unsupported files, preserves duplicate basenames and submits over 16 files', async (t) => {
  let submitted;
  mock.method(global, 'fetch', async (_url, options) => {
    submitted = JSON.parse(options.body);
    return { ok: true, json: async () => response() };
  });
  const container = await mount(t);
  await click('Import data');
  const input = document.querySelector('input[webkitdirectory]');
  assert.ok(input, 'folder input requests recursive selection');
  const sources = Array.from({ length: 24 }, (_, i) => folderFile(`project/service-${i}/crypto.py`));
  Object.defineProperty(input, 'files', { value: [...sources,
    folderFile('project/package.json', '{"name":"project"}'),
    folderFile('project/README.md', '# Docs'),
    folderFile('project/aws/keys.json', '{"Keys":[]}'),
  ] });
  await act(async () => input.dispatchEvent(new window.Event('change', { bubbles: true })));
  assert.match(container.textContent, /27 files discovered · 25 compatible · 2 skipped/);
  assert.match(container.textContent, /project\/service-23\/crypto.py/);
  assert.equal(button('Scan selected files').disabled, false);
  await click('Scan selected files');
  assert.equal(submitted.inputs.length, 25);
  assert.deepEqual(submitted.inputs.slice(0, 24).map(input => input.name), sources.map(file => file.webkitRelativePath));
  assert.equal(submitted.inputs[24].name, 'project/aws/keys.json');
});

test('AWS snapshots in separate folders do not collide or get bundled across environments', async () => {
  const { inputs } = await prepareScan([
    folderFile('project/dev/keys.json', '{"Keys":[]}'),
    folderFile('project/dev/certs.json', '{"Certificates":[]}'),
    folderFile('project/prod/keys.json', '{"Keys":[]}'),
    folderFile('project/prod/certs.json', '{"Certificates":[]}'),
  ]);
  assert.deepEqual(inputs.map(input => input.name), ['project/dev/aws-snapshots.json', 'project/prod/aws-snapshots.json']);
  assert.ok(inputs.every(input => Object.keys(JSON.parse(input.content)).length === 2));
});

test('folder checks block scanning and ignore results after closing the dialog', async (t) => {
  let finishRead;
  const container = await mount(t);
  await select([file()]);
  const input = document.querySelector('input[webkitdirectory]');
  Object.defineProperty(input, 'files', { value: [{ name: 'slow.json', size: 10, webkitRelativePath: 'project/slow.json',
    arrayBuffer: () => new Promise(resolve => { finishRead = resolve; }) }] });
  await act(async () => input.dispatchEvent(new window.Event('change', { bubbles: true })));
  assert.equal(button('Scan selected files').disabled, true);
  assert.match(container.textContent, /Checking folders/);
  await click('Close import dialog');
  await click('Import data');
  await act(async () => finishRead(new TextEncoder().encode('{"Keys":[]}').buffer));
  assert.equal(button('Scan selected files').disabled, true);
  assert.doesNotMatch(container.textContent, /slow.json/);
});

test('uncertainty reasons filter findings and keep HTTP out of the unknown tier', async (t) => {
  const live = response();
  const base = live.findings[0];
  live.findings = [
    { ...base, id: 'aes', algorithm: 'AES', quantum_status: 'unknown', challenge_tier: 'unknown', rule_id: 'QT-AES-PARAMETERS@1.1.0' },
    { ...base, id: 'hmac', algorithm: 'HMAC', quantum_status: 'unknown', challenge_tier: 'unknown', rule_id: 'QT-HMAC-PARAMETERS@1.1.0' },
    { ...base, id: 'http', algorithm: 'HTTP', quantum_status: 'not_applicable', challenge_tier: 'unknown' },
    { ...base, id: 'sha1', algorithm: 'SHA-1', quantum_status: 'quantum_weakened', challenge_tier: 'medium' },
  ];
  mock.method(global, 'fetch', async () => ({ ok: true, json: async () => live }));
  const container = await mount(t);
  await select([file()]); await click('Scan selected files');
  assert.match(container.textContent, /Why are 2 findings unresolved/);
  await act(async () => {
    container.querySelector('details summary').click();
  });
  await click('AES parameters unresolved: 1');
  assert.equal(container.querySelectorAll('tbody tr').length, 1);
  assert.match(container.querySelector('tbody').textContent, /AES/);
  await click('Clear filters');
  const tier = container.querySelector('[aria-label="Filter by quantum tier"]');
  await act(async () => { tier.value = 'unknown'; tier.dispatchEvent(new window.Event('change', { bubbles: true })); });
  assert.equal(container.querySelectorAll('tbody tr').length, 2);
  assert.doesNotMatch(container.querySelector('tbody').textContent, /HTTP|SHA-1/);
  await act(async () => { tier.value = 'not_applicable'; tier.dispatchEvent(new window.Event('change', { bubbles: true })); });
  assert.equal(container.querySelectorAll('tbody tr').length, 1);
  assert.match(container.querySelector('tbody').textContent, /Not applicable.*HTTP/);
  await act(async () => container.querySelector('tbody button').click());
  assert.match(container.querySelector('[role=dialog]').textContent, /Not applicable/);
  assert.doesNotMatch(container.querySelector('[role=dialog]').textContent, /unknown tier/i);
});

test('partial coverage without input errors remains explained after dismissing notification', async (t) => {
  const live = response('partial');
  live.errors = [];
  live.coverage = [{ source_type: 'pcap', input_name: 'network.pcap', unit: 'sessions', assessed: 97, unknown: 0, unsupported: 38, failed: 0 }];
  mock.method(global, 'fetch', async () => ({ ok: true, json: async () => live }));
  const container = await mount(t);
  await select([file()]); await click('Scan selected files');
  await click('Dismiss');
  const notice = container.querySelector('[aria-label="Incomplete scan coverage"]');
  assert.match(notice.textContent, /Scan partially completed/);
  assert.match(notice.textContent, /network.pcap \(pcap\): 38 unsupported, 0 failed sessions/);
  assert.equal(container.querySelector('[aria-label="Input errors"]'), null);
});
