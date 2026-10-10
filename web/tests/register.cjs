const fs = require('node:fs');
const ts = require('typescript');
// Exercise the actual components/exporter without adding a second build tool.
for (const extension of ['.ts', '.tsx']) {
  require.extensions[extension] = (module, filename) => {
    const result = ts.transpileModule(fs.readFileSync(filename, 'utf8').replaceAll('import.meta.env', '(globalThis.__TEST_VITE_ENV__ || {})'), {
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

