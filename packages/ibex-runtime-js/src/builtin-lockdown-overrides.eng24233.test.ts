import { expect, test } from 'bun:test';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const hasOwn = Object.prototype.hasOwnProperty;

function withNonWritableInheritedProperties(
  target: object,
  names: string[],
  run: (sentinels: Map<string, Function>) => void,
) {
  const originals = new Map<string, PropertyDescriptor | undefined>();
  const sentinels = new Map<string, Function>();
  try {
    for (const name of names) {
      originals.set(name, Object.getOwnPropertyDescriptor(target, name));
      const sentinel = function lockedPrimordialMethod() {
        throw new Error(`inherited primordial ${name} was substituted`);
      };
      sentinels.set(name, sentinel);
      Object.defineProperty(target, name, {
        value: sentinel,
        writable: false,
        configurable: true,
        enumerable: false,
      });
    }
    run(sentinels);
  } finally {
    for (const name of names) {
      const original = originals.get(name);
      if (original) Object.defineProperty(target, name, original);
      else delete (target as Record<string, unknown>)[name];
    }
  }
}

test('lazy Buffer initialization installs own overrides over locked primordials', () => {
  const modulePath = require.resolve('../../../src/builtins/buffer.js');
  const methodNames = [
    'fill',
    'includes',
    'indexOf',
    'lastIndexOf',
    'slice',
    'subarray',
    'toString',
  ];
  withNonWritableInheritedProperties(
    Uint8Array.prototype,
    methodNames,
    (sentinels) => {
      delete require.cache[modulePath];
      const Buffer = require(modulePath).Buffer;
      for (const name of methodNames) {
        const descriptor = Object.getOwnPropertyDescriptor(
          Buffer.prototype,
          name,
        );
        expect(hasOwn.call(Buffer.prototype, name)).toBe(true);
        expect(descriptor?.value).not.toBe(sentinels.get(name));
        expect(descriptor?.writable).toBe(true);
        expect(descriptor?.configurable).toBe(true);
      }
    },
  );
  delete require.cache[modulePath];
});

test('lazy assert initialization installs its own constructor over a locked Error prototype', () => {
  const modulePath = require.resolve('../../../src/builtins/assert.js');
  withNonWritableInheritedProperties(
    Error.prototype,
    ['constructor'],
    (sentinels) => {
      delete require.cache[modulePath];
      const ibexAssert = require(modulePath);
      const descriptor = Object.getOwnPropertyDescriptor(
        ibexAssert.AssertionError.prototype,
        'constructor',
      );
      expect(hasOwn.call(ibexAssert.AssertionError.prototype, 'constructor')).toBe(
        true,
      );
      expect(descriptor?.value).toBe(ibexAssert.AssertionError);
      expect(descriptor?.value).not.toBe(sentinels.get('constructor'));
      expect(descriptor?.writable).toBe(true);
      expect(descriptor?.configurable).toBe(true);
      expect(descriptor?.enumerable).toBe(false);
    },
  );
  delete require.cache[modulePath];
});
