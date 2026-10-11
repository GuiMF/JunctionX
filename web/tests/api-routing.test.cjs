const assert = require('node:assert/strict');
const { test } = require('node:test');
require('./register.cjs');
const { apiUrl, submitScan } = require('../src/api/client.ts');

test('browser scans and exports use public same-origin paths by default', async () => {
  const originalFetch = global.fetch;
  const originalEnv = global.__TEST_VITE_ENV__;
  try {
    global.__TEST_VITE_ENV__ = {};
    assert.equal(apiUrl('/api/scans/id/export?format=json'), '/api/scans/id/export?format=json');
    global.fetch = async (url, options) => {
      assert.equal(url, '/api/scans');
      assert.equal(options.method, 'POST');
      return new Response(JSON.stringify({ scan_id: 'id', status: 'completed', findings: [], coverage: [], errors: [], score: {} }));
    };
    assert.equal((await submitScan({ inputs: [] }, new AbortController().signal)).scan_id, 'id');
  } finally {
    global.fetch = originalFetch;
    global.__TEST_VITE_ENV__ = originalEnv;
  }
});

test('explicit external API override remains available for separate local servers', () => {
  const originalEnv = global.__TEST_VITE_ENV__;
  try {
    global.__TEST_VITE_ENV__ = { VITE_API_BASE_URL: 'http://127.0.0.1:8123/' };
    assert.equal(apiUrl('/api/scans'), 'http://127.0.0.1:8123/api/scans');
    global.__TEST_VITE_ENV__ = { VITE_API_BASE_URL: '' };
    assert.equal(apiUrl('/api/uploads'), '/api/uploads');
  } finally {
    global.__TEST_VITE_ENV__ = originalEnv;
  }
});
