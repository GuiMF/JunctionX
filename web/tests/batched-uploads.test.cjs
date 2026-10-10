const assert = require('node:assert/strict');
const { test, afterEach, mock } = require('node:test');
require('./register.cjs');
const { validateFileSelection, MAX_SCAN_BYTES, MAX_BATCH_BYTES, prepareScanBatches } = require('../src/utils/scanInputs.ts');
const { submitFiles } = require('../src/api/client.ts');
const { mockScanResult } = require('../src/fixtures/mockData.ts');
afterEach(() => mock.restoreAll());
const file = (name, content) => new File([content], name);
const ok = body => ({ ok: true, json: async () => body });

test('three GB preflight accepts the exact boundary and rejects overflow without reading files', () => {
  assert.equal(MAX_SCAN_BYTES, 3_000_000_000);
  const files = Array.from({ length: 50 }, (_, i) => ({ name: `${i}.py`, size: 60_000_000,
    arrayBuffer() { throw Error('must not read'); } }));
  assert.equal(validateFileSelection(files), MAX_SCAN_BYTES);
  assert.throws(() => validateFileSelection([...files, { name: 'extra.py', size: 1 }]), /3 GB/);
  // Capture overhead still counts toward the limit.
  assert.throws(() => validateFileSelection(Array.from({ length: 50 }, (_, i) => ({ name: `${i}.pcap`, size: 46_000_000 }))), /3 GB/);
});

test('large folders use bounded batches, one completion, progress and no giant scan request', async () => {
  const content = '#' + 'x'.repeat(24 * 1024 * 1024);
  const files = [0, 1, 2].map(i => file(`${i}.py`, content));
  const calls = [], progress = [];
  let total = 0;
  mock.method(global, 'fetch', async (url, options) => {
    calls.push([url, options.method]);
    if (url.endsWith('/api/uploads')) return ok({ upload_id: 'test-upload' });
    if (url.endsWith('/batches')) {
      const request = JSON.parse(options.body);
      const bytes = request.inputs.reduce((sum, input) => sum + Buffer.byteLength(input.content), 0);
      assert.ok(bytes <= MAX_BATCH_BYTES);
      total += bytes;
      return ok({ received_bytes: total });
    }
    assert.ok(url.endsWith('/complete'));
    return ok(mockScanResult);
  });
  const result = await submitFiles(files, new AbortController().signal, value => progress.push(value));
  assert.equal(result.scan_id, mockScanResult.scan_id);
  assert.deepEqual(calls.map(([url]) => url.split('/').pop()), ['uploads', 'batches', 'batches', 'complete']);
  assert.equal(total, files.reduce((sum, f) => sum + f.size, 0));
  assert.equal(progress.length, 3);
});

test('cancellation between batches deletes temporary upload and does not complete', async () => {
  const controller = new AbortController();
  const calls = [];
  const files = [0, 1].map(i => ({ name: `${i}.py`, size: 40 * 1024 * 1024,
    async arrayBuffer() { return new TextEncoder().encode('# source').buffer; } }));
  mock.method(global, 'fetch', async (url, options) => {
    calls.push(options.method);
    if (url.endsWith('/api/uploads')) return ok({ upload_id: 'cancel-me' });
    if (url.endsWith('/batches')) { controller.abort(); return ok({ received_bytes: 8 }); }
    assert.equal(options.method, 'DELETE');
    assert.equal(options.signal.aborted, false);
    return ok(null);
  });
  await assert.rejects(submitFiles(files, controller.signal), { name: 'AbortError' });
  assert.deepEqual(calls, ['POST', 'POST', 'DELETE']);
});

test('failed batch reports the API error and deletes uploaded content', async () => {
  const calls = [];
  const files = [0, 1].map(i => ({ name: `${i}.py`, size: 40 * 1024 * 1024,
    async arrayBuffer() { return new TextEncoder().encode('# source').buffer; } }));
  mock.method(global, 'fetch', async (url, options) => {
    calls.push(options.method);
    if (url.endsWith('/api/uploads')) return ok({ upload_id: 'disk-full' });
    if (url.endsWith('/batches')) return { ok: false, status: 507, json: async () => ({ detail: 'Not enough temporary storage' }) };
    return ok(null);
  });
  await assert.rejects(submitFiles(files, new AbortController().signal), /Not enough temporary storage/);
  assert.deepEqual(calls, ['POST', 'POST', 'DELETE']);
});

test('batch preparation keeps related snapshots together and stops reading when aborted', async () => {
  const controller = new AbortController();
  const request = [];
  for await (const batch of prepareScanBatches([
    file('keys.json', '{"Keys":[]}'), file('source.py', '# source'), file('certs.json', '{"Certificates":[]}'),
  ], controller.signal)) request.push(...batch.inputs);
  assert.equal(request.length, 2);
  assert.deepEqual(Object.keys(JSON.parse(request[0].content)), ['kms_key_inventory.json', 'acm_certificates.json']);
  controller.abort();
  const reader = prepareScanBatches([{ name: 'never.py', size: 1, arrayBuffer() { throw Error('must not read'); } }], controller.signal);
  await assert.rejects(reader.next(), { name: 'AbortError' });
});
