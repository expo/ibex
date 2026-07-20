import { afterEach, describe, expect, test } from 'bun:test';
import { Headers } from './Headers.ts';

const contextDescriptor = Object.getOwnPropertyDescriptor(globalThis, '__exactRuntimeContext');
const hostEnvDescriptor = Object.getOwnPropertyDescriptor(globalThis, '__exactHostEnv');

function restoreGlobal(name: string, descriptor: PropertyDescriptor | undefined): void {
  if (descriptor) {
    Object.defineProperty(globalThis, name, descriptor);
  } else {
    delete (globalThis as Record<string, unknown>)[name];
  }
}

afterEach(() => {
  restoreGlobal('__exactRuntimeContext', contextDescriptor);
  restoreGlobal('__exactHostEnv', hostEnvDescriptor);
});

describe('Headers compatibility environment reads', () => {
  test('ordinary sorted iteration does not consult compatibility state', () => {
    const reads: string[] = [];
    Object.defineProperty(globalThis, '__exactRuntimeContext', {
      configurable: true,
      value: 'runtime',
    });
    Object.defineProperty(globalThis, '__exactHostEnv', {
      configurable: true,
      value: new Proxy(Object.create(null), {
        get(_target, key) {
          reads.push(String(key));
          return undefined;
        },
      }),
    });

    expect(Array.from(new Headers({ z: '2', a: '1' }).entries())).toEqual([
      ['a', '1'],
      ['z', '2'],
    ]);
    expect(reads).toEqual([]);
  });

  test('consults compatibility state only when it can move set-cookie', () => {
    const reads: string[] = [];
    const values: Record<string, string> = {
      EXACT_COMPAT_TEST: '1',
      EXACT_TEST_SECTION: 'bun',
    };
    Object.defineProperty(globalThis, '__exactRuntimeContext', {
      configurable: true,
      value: 'runtime',
    });
    Object.defineProperty(globalThis, '__exactHostEnv', {
      configurable: true,
      value: new Proxy(values, {
        get(target, key) {
          reads.push(String(key));
          return target[String(key)];
        },
      }),
    });

    expect(Array.from(new Headers({ z: '2', 'set-cookie': 'v=1', a: '1' }).entries())).toEqual([
      ['a', '1'],
      ['z', '2'],
      ['set-cookie', 'v=1'],
    ]);
    expect(reads.length).toBeGreaterThan(0);
    expect([...new Set(reads)]).toEqual(['EXACT_COMPAT_TEST', 'EXACT_TEST_SECTION']);
  });
});
