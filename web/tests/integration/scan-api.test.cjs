const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
require('../register.cjs');
const { prepareScan } = require('../../src/utils/scanInputs.ts');
const root = path.resolve(__dirname, '../../..');
const pythonSetting = process.env.PYTHON || 'python3';
const python = pythonSetting.includes('/') ? path.resolve(pythonSetting) : pythonSetting;
const file = (relative) => new File([fs.readFileSync(path.join(root, relative))], path.basename(relative));

function scanAndExport(request) {
  // Exercise real FastAPI validation, default adapters, storage and both export routes
  // without requiring a server socket or TShark for source/cloud integration.
  const result = spawnSync(python, ['-c', `
import json, sys
from fastapi.testclient import TestClient
from api.main import create_app
with TestClient(create_app()) as client:
    response = client.post('/api/scans', json=json.load(sys.stdin))
    assert response.status_code == 201, response.text
    scan = response.json()
    exports = {}
    for format in ('json', 'cyclonedx'):
        exported = client.get('/api/scans/' + scan['scan_id'] + '/export', params={'format': format})
        assert exported.status_code == 200, exported.text
        exports[format] = exported.json()
    print(json.dumps({'scan': scan, 'exports': exports}))
`], { cwd: root, input: JSON.stringify(request), encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  return JSON.parse(result.stdout);
}

test('browser-prepared source and AWS inputs resolve certificates and export the actual scan', async () => {
  const request = await prepareScan([
    file('tests/fixtures/source/holdout/positive.py'),
    file('tests/fixtures/source/holdout/Positive.java'),
    file('tests/fixtures/source/holdout/positive.go'),
    file('cloud-posture/kms_key_inventory.json'),
    file('cloud-posture/acm_certificates.json'),
    file('cloud-posture/load_balancer_listeners.json'),
  ]);
  assert.equal(request.inputs.length, 4);
  const { scan, exports } = scanAndExport(request);
  assert.equal(scan.status, 'completed');
  assert.ok(scan.findings.some(finding => finding.source_type === 'source'));
  assert.ok(scan.findings.some(finding => finding.source_type === 'cloud'));
  assert.ok(scan.relationships.some(relationship => relationship.kind === 'uses_certificate'));
  assert.equal(scan.errors.length, 0);
  assert.deepEqual(exports.json, scan);
  assert.equal(exports.cyclonedx.bomFormat, 'CycloneDX');
  assert.equal(exports.cyclonedx.specVersion, '1.6');
  assert.ok(exports.cyclonedx.components.length > 0);
  assert.notEqual(scan.scan_id, 'example-scan-original');
});

test('real adapter failures produce partial and failed scans, preserving successful findings', async () => {
  const invalid = new File([JSON.stringify({ Keys: [{}], GeneratedAt: '2026-10-10T00:00:00Z' })], 'invalid.json');
  const partial = scanAndExport(await prepareScan([file('tests/fixtures/source/holdout/positive.py'), invalid]));
  assert.equal(partial.scan.status, 'partial');
  assert.ok(partial.scan.findings.length > 0);
  assert.equal(partial.scan.errors[0].input_name, 'invalid.json');
  assert.deepEqual(partial.exports.json, partial.scan);
  const failed = scanAndExport(await prepareScan([invalid]));
  assert.equal(failed.scan.status, 'failed');
  assert.equal(failed.scan.findings.length, 0);
  assert.ok(failed.scan.errors.length > 0);
});

test('native AWS descriptions reach the API and export without synthetic timestamps or rewritten evidence', async () => {
  const metadata = { Arn: 'arn:aws:kms:us-east-1:123456789012:key/native', KeySpec: 'SYMMETRIC_DEFAULT', KeyUsage: 'ENCRYPT_DECRYPT' };
  const certificate = { CertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/native', KeyAlgorithm: 'EC_secp521r1', SignatureAlgorithm: 'SHA512WITHECDSA' };
  const request = await prepareScan([
    new File([JSON.stringify({ KeyMetadata: metadata })], 'key.json'),
    new File([JSON.stringify({ Certificate: certificate })], 'certificate.json'),
  ]);
  const { scan, exports } = scanAndExport(request);
  assert.equal(scan.status, 'completed');
  assert.equal(scan.findings.length, 3);
  assert.deepEqual(scan.snapshots, []);
  for (const finding of scan.findings) {
    assert.equal(finding.observed_at, null);
    const input = request.inputs.find(item => item.name === finding.evidence[0].file);
    assert.ok(input);
    for (const evidence of finding.evidence) {
      let value = JSON.parse(input.content);
      for (const part of evidence.locator.split('/').slice(1)) value = value[part];
      assert.deepEqual(value, JSON.parse(evidence.detail));
    }
  }
  assert.equal(scan.findings.find(item => item.algorithm === 'AES').parameters.key_bits, 256);
  assert.equal(scan.findings.find(item => item.algorithm === 'EC').parameters.named_group, 'secp521r1');
  assert.deepEqual(exports.json, scan);
  assert.equal(exports.cyclonedx.components.length, 3);
});

test('folder scans preserve every relative path through discovery, evidence and exports beyond 16 files', async () => {
  const files = Array.from({ length: 24 }, (_, i) => Object.defineProperty(
    new File(['import hashlib\nhashlib.md5(b"data")'], 'crypto.py'),
    'webkitRelativePath', { value: `project/service-${i}/crypto.py` },
  ));
  const { scan, exports } = scanAndExport(await prepareScan(files));
  assert.equal(scan.status, 'completed');
  assert.equal(scan.coverage.length, 24);
  assert.deepEqual(scan.coverage.map(item => item.input_name), files.map(file => file.webkitRelativePath));
  assert.equal(new Set(scan.findings.flatMap(finding => finding.evidence.map(e => e.file))).size, 24);
  assert.deepEqual(exports.json, scan);
  assert.equal(exports.cyclonedx.components.length, 24);
});

test('larger source uploads exceed the former per-input and combined limits and scan successfully', async () => {
  const content = 'import hashlib\nhashlib.md5(b"data")\n#' + 'x'.repeat(9 * 1024 * 1024);
  const request = await prepareScan([new File([content], 'one.py'), new File([content], 'two.py')]);
  const { scan, exports } = scanAndExport(request);
  assert.equal(scan.status, 'completed');
  assert.equal(scan.findings.length, 2);
  assert.deepEqual(scan.coverage.map(item => item.assessed), [1, 1]);
  assert.deepEqual(exports.json, scan);
});
