import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const stringDecoderSource = readFileSync(
  path.join(repoRoot, 'src', 'builtins', 'string-decoder.js'),
  'utf8',
);

test('StringDecoder installs its toString override after primordial lockdown', () => {
  const sandbox: any = {
    Buffer,
    module: { exports: {} },
  };
  sandbox.exports = sandbox.module.exports;
  vm.createContext(sandbox);
  vm.runInContext(
    'Object.defineProperty(Object.prototype, "toString", {' +
      'writable: false, configurable: false' +
      '});',
    sandbox,
  );
  vm.runInContext(
    `(function(module, exports) { "use strict"; ${stringDecoderSource}\n})(module, exports);`,
    sandbox,
    { filename: 'node:string_decoder' },
  );

  const StringDecoder = sandbox.module.exports.StringDecoder;
  expect(
    Object.prototype.hasOwnProperty.call(
      StringDecoder.prototype,
      'toString',
    ),
  ).toBe(true);
  expect(new StringDecoder('utf8').toString()).toBe('[object StringDecoder]');
});
