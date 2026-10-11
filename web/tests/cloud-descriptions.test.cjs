const assert = require('node:assert/strict');
const { test } = require('node:test');
require('./register.cjs');
const { cloudSnapshotEntries, prepareScan, prepareScanBatches } = require('../src/utils/scanInputs.ts');

const description = (name, envelope) => new File([JSON.stringify(envelope)], name);

test('native AWS descriptions retain original files and evidence structure alongside snapshots', async () => {
  const key = { KeyMetadata: { Arn: 'arn:aws:kms:us-east-1:123456789012:key/test', KeySpec: 'SYMMETRIC_DEFAULT' } };
  const cert = { Certificate: { CertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/test', KeyAlgorithm: 'RSA_2048' } };
  const files = [description('key1.json', key), description('key2.json', key),
    description('cert.json', cert), description('inventory.json', { Keys: [] })];
  const request = await prepareScan(files);
  assert.equal(request.inputs.length, 4);
  for (const [i, expected] of [key, key, cert].entries()) {
    assert.equal(request.inputs[i].name, files[i].name);
    assert.equal(request.inputs[i].source_type, 'cloud');
    assert.deepEqual(JSON.parse(request.inputs[i].content), expected);
    assert.equal(cloudSnapshotEntries(request.inputs[i].content, files[i].name), null);
  }
  assert.deepEqual(JSON.parse(request.inputs[3].content), { 'kms_key_inventory.json': { Keys: [] } });
  const batches = [];
  for await (const batch of prepareScanBatches(files, new AbortController().signal)) batches.push(batch);
  assert.deepEqual(batches.flatMap(batch => batch.inputs), request.inputs);
});

test('native AWS descriptions reject ambiguous and malformed envelopes during folder discovery', () => {
  for (const value of [
    { KeyMetadata: {}, Certificate: {} }, { KeyMetadata: {}, Keys: [] },
    { Certificate: {}, Certificates: [] }, { KeyMetadata: [] },
    { Certificate: null }, { KeyMetadata: {}, 'kms_key_inventory.json': {} },
  ]) assert.throws(() => cloudSnapshotEntries(JSON.stringify(value), 'ambiguous.json'), /ambiguous or unsupported/);
});
