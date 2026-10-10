const assert = require('node:assert/strict');
const fs = require('node:fs');
const { test, afterEach, mock } = require('node:test');
const ts = require('typescript');

// Exercise the actual components/exporter without adding a second build tool.
for (const extension of ['.ts', '.tsx']) {
  require.extensions[extension] = (module, filename) => {
    const result = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
      compilerOptions: {
        target: ts.ScriptTarget.ES2020,
        module: ts.ModuleKind.CommonJS,
        jsx: ts.JsxEmit.ReactJSX,
        esModuleInterop: true
      }
    });
    module._compile(result.outputText, filename);
  };
}

const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const { CoverageCards } = require('../src/components/CoverageCards.tsx');
const { RiskPostureBanner } = require('../src/components/RiskPostureBanner.tsx');
const { mockScanResult } = require('../src/fixtures/mockData.ts');
const { mockCycloneDxCbom } = require('../src/fixtures/mockCbom.ts');
const { exportCycloneDxCbom } = require('../src/utils/cbomExport.ts');

afterEach(() => mock.restoreAll());
const plain = (html) => html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
const render = (component, props) => renderToStaticMarkup(React.createElement(component, props));

test('coverage keeps sessions, packets and failed inputs separate, combining only matching units', () => {
  const base = { source_type: 'pcap', input_name: 'capture', unknown: 0, unsupported: 0, failed: 0 };
  const coverage = [
    { ...base, unit: 'sessions', assessed: 2 },
    { ...base, unit: 'packets', assessed: 100 },
    { ...base, input_name: 'second', unit: 'sessions', assessed: 3 },
    { ...base, input_name: 'failed', unit: 'inputs', assessed: 0, failed: 1 }
  ];
  const original = structuredClone(coverage);
  const html = render(CoverageCards, { coverage });
  const sections = [...html.matchAll(/<section[^>]*>(.*?)<\/section>/g)].map((match) => plain(match[1]));
  assert.deepEqual(sections, [
    '5 sessions Assessed 5 Unknown 0 Unsupp. 0 Failed 0',
    '100 packets Assessed 100 Unknown 0 Unsupp. 0 Failed 0',
    '1 inputs Assessed 0 Unknown 0 Unsupp. 0 Failed 1'
  ]);
  assert.deepEqual(coverage, original, 'rendering must not mutate the scan exported later');
});

test('uncertainty includes mixed known/unknown assets with and without a backend score', () => {
  const initial = plain(render(RiskPostureBanner, { findings: mockScanResult.findings, score: mockScanResult.score }));
  assert.match(initial, /Assets with unknowns 2 Assets/);
  const network = mockScanResult.findings.filter((finding) => finding.source_type === 'pcap');
  const fallback = plain(render(RiskPostureBanner, { findings: network }));
  assert.match(fallback, /Quantum Vulnerable 1 Assets/);
  assert.match(fallback, /Assets with unknowns 1 Assets/);
});

test('unknown tiers count once per asset and unselected offers do not add uncertainty', () => {
  const base = mockScanResult.findings[0];
  const findings = [
    { ...base, challenge_tier: 'unknown' },
    { ...base, id: 'second-role', quantum_status: 'unknown' },
    { ...base, id: 'offer', asset_id: 'offer-only', evidence_kind: 'offered', quantum_status: 'unknown' },
    { ...base, id: 'na', asset_id: 'not-applicable', quantum_status: 'not_applicable', challenge_tier: 'unknown' }
  ];
  const output = plain(render(RiskPostureBanner, { findings }));
  assert.match(output, /Assets with unknowns 1 Assets/);
  assert.match(output, /Offered Only 1 Assets/);
});

function stubDownloads(t) {
  const previous = global.document;
  const downloads = [];
  global.document = {
    createElement: () => ({
      setAttribute(key, value) { this[key] = value; },
      click() { downloads.push({ href: this.href, download: this.download }); },
      remove() {}
    }),
    body: { appendChild() {} }
  };
  t.after(() => {
    if (previous === undefined) delete global.document;
    else global.document = previous;
  });
  return downloads;
}

test('matching demo exports immediately even if the API would never respond', async (t) => {
  const downloads = stubDownloads(t);
  const fetch = mock.method(global, 'fetch', () => new Promise(() => {}));
  const outcome = await Promise.race([
    exportCycloneDxCbom(structuredClone(mockScanResult)).then(() => 'downloaded'),
    new Promise((resolve) => {
      const timer = setTimeout(() => resolve('stalled'), 100);
      t.after(() => clearTimeout(timer));
    })
  ]);
  assert.equal(outcome, 'downloaded');
  assert.equal(fetch.mock.callCount(), 0);
  assert.equal(downloads.length, 1);
  assert.deepEqual(JSON.parse(decodeURIComponent(downloads[0].href.split(',')[1])), mockCycloneDxCbom);
});

test('a changed scan with the demo ID cannot silently download unrelated fixture evidence', async (t) => {
  const downloads = stubDownloads(t);
  const scan = { ...mockScanResult, findings: [] };
  mock.method(global, 'fetch', async () => ({ ok: false, status: 404 }));
  await assert.rejects(exportCycloneDxCbom(scan), /HTTP 404/);
  assert.equal(downloads.length, 0);
});

test('a stalled live request is aborted and reports a timeout without a demo download', async (t) => {
  const downloads = stubDownloads(t);
  const originalSetTimeout = global.setTimeout;
  let deadline;
  mock.method(global, 'setTimeout', (callback, milliseconds) => {
    deadline = milliseconds;
    return originalSetTimeout(callback, 1);
  });
  let signal;
  mock.method(global, 'fetch', (_url, options) => {
    signal = options.signal;
    return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('Aborted')), { once: true }));
  });
  await assert.rejects(exportCycloneDxCbom({ ...mockScanResult, scan_id: 'live-scan', synthetic: false }), /timed out/);
  assert.equal(deadline, 10_000);
  assert.equal(signal.aborted, true);
  assert.equal(downloads.length, 0);
});

test('successful live export downloads the API response and clears its timeout', async (t) => {
  const downloads = stubDownloads(t);
  const previous = global.window;
  const revoked = [];
  const blob = new Blob(['live report']);
  global.window = { URL: {
    createObjectURL(value) { assert.equal(value, blob); return 'blob:live-report'; },
    revokeObjectURL(url) { revoked.push(url); }
  } };
  t.after(() => { if (previous === undefined) delete global.window; else global.window = previous; });
  const fetch = mock.method(global, 'fetch', async () => ({ ok: true, blob: async () => blob }));
  const clear = mock.method(global, 'clearTimeout');
  await exportCycloneDxCbom({ ...mockScanResult, scan_id: 'live/scan', synthetic: false });
  assert.match(fetch.mock.calls[0].arguments[0], /live%2Fscan\/export/);
  assert.deepEqual(downloads, [{ href: 'blob:live-report', download: 'quantumtrace-cbom-live/scan.cdx.json' }]);
  assert.deepEqual(revoked, ['blob:live-report']);
  assert.equal(clear.mock.callCount(), 1);
});
