const assert = require('node:assert/strict');
const { test } = require('node:test');
require('./register.cjs');
const { collectDroppedFiles, filePath } = require('../src/utils/folderFiles.ts');

const entry = name => ({ name, isFile: true, file: resolve => resolve(new File(['# source'], name)) });
const directory = (name, batches) => ({ name, isDirectory: true, createReader() {
  let index = 0;
  return { readEntries: resolve => resolve(batches[index++] || []) };
} });
const transfer = entries => ({ items: entries.map(entry => ({ kind: 'file', webkitGetAsEntry: () => entry, getAsFile: () => null })), files: [] });

test('dropped directories are crawled through all batches and nested levels; read failures preserve siblings', async () => {
  const broken = { name: 'unreadable.py', isFile: true, file: (_resolve, reject) => reject(new Error('denied')) };
  const root = directory('project', [
    Array.from({ length: 100 }, (_, i) => entry(`${i}.py`)),
    [directory('nested', [[entry('0.py'), broken]]), entry('last.go')],
  ]);
  const result = await collectDroppedFiles(transfer([root]));
  assert.equal(result.files.length, 102);
  assert.equal(filePath(result.files[0]), 'project/0.py');
  assert.equal(filePath(result.files[100]), 'project/nested/0.py');
  assert.equal(filePath(result.files[101]), 'project/last.go');
  assert.match(result.issues[0], /project\/nested\/unreadable.py: could not read/);
});

test('drops fall back to ordinary files when directory APIs are unavailable', async () => {
  const file = new File(['# source'], 'crypto.py');
  for (const data of [{ files: [file] }, { items: [{ kind: 'file', getAsFile: () => file }], files: [file] }]) {
    const result = await collectDroppedFiles(data);
    assert.deepEqual(result.files, [file]);
    assert.equal(filePath(result.files[0]), 'crypto.py');
  }
});
