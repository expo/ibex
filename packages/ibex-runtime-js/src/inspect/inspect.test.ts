import { describe, expect, it } from 'bun:test';
import { inspect } from './inspect';

const plain = (value: unknown, opts: Record<string, unknown> = {}) =>
  inspect(value, { colors: false, ...opts });

// ENG-22980 finding 1: console.log must not invoke arbitrary getters/Proxy
// traps bare, and must never throw out of inspect().
describe('inspect: accessors and Proxy traps (ENG-22980 #1)', () => {
  it('does not throw when a getter throws, and does not invoke it', () => {
    let invoked = false;
    const obj = {
      get boom() {
        invoked = true;
        throw new Error('lazy');
      },
    };

    let out = '';
    expect(() => {
      out = plain(obj);
    }).not.toThrow();
    expect(invoked).toBe(false); // getter is described, not run
    expect(out).toContain('[Getter]');
  });

  it('describes a non-throwing getter without executing it (no logging side effect)', () => {
    let invoked = false;
    const obj = {
      get lazy() {
        invoked = true;
        return 42;
      },
    };

    const out = plain(obj);
    expect(invoked).toBe(false);
    expect(out).toContain('lazy: [Getter]');
    expect(out).not.toContain('42');
  });

  it('labels getter/setter and setter-only accessors', () => {
    const getterSetter: Record<string, unknown> = {};
    Object.defineProperty(getterSetter, 'gs', {
      get() {
        return 1;
      },
      set() {
        /* noop */
      },
      enumerable: true,
    });
    expect(plain(getterSetter)).toContain('gs: [Getter/Setter]');

    const setterOnly: Record<string, unknown> = {};
    Object.defineProperty(setterOnly, 'so', {
      set() {
        /* noop */
      },
      enumerable: true,
    });
    expect(plain(setterOnly)).toContain('so: [Setter]');
  });

  it('still renders ordinary data properties normally', () => {
    const out = plain({ a: 1, b: 'two' });
    expect(out).toContain('a: 1');
    expect(out).toContain('b: "two"');
  });

  it('does not throw on a revoked Proxy', () => {
    const { proxy, revoke } = Proxy.revocable({ a: 1 }, {});
    revoke();
    expect(() => plain(proxy)).not.toThrow();
  });

  it('does not throw when a Proxy trap throws, and reports it safely', () => {
    const proxy = new Proxy(
      { visible: 1 },
      {
        get() {
          throw new Error('trap boom');
        },
        getOwnPropertyDescriptor() {
          throw new Error('descriptor boom');
        },
      },
    );
    let out = '';
    expect(() => {
      out = plain(proxy);
    }).not.toThrow();
    // The throw surfaces as a safe marker rather than propagating.
    expect(out).toContain('[unlistable:');
  });
});

// ENG-22980 finding 2: plain objects that merely have default/exports/__esModule
// keys must not be misclassified as value-less Modules.
describe('inspect: module misclassification (ENG-22980 #2)', () => {
  it('renders a plain object with a default key as a normal object with values', () => {
    const out = plain({ default: 'dark', options: [1, 2, 3] });
    expect(out).not.toContain('Module');
    expect(out).toContain('default: "dark"');
    expect(out).toContain('options:');
    expect(out).toContain('1');
    expect(out).toContain('3');
  });

  it('renders a plain object with an exports key normally', () => {
    const out = plain({ exports: { a: 1 } });
    expect(out).not.toContain('Module');
    expect(out).toContain('exports:');
    expect(out).toContain('a: 1');
  });

  it('renders a plain object with __esModule normally (values preserved)', () => {
    const out = plain({ __esModule: true, default: 'x', foo: 'bar' });
    expect(out).toContain('default: "x"');
    expect(out).toContain('foo: "bar"');
  });

  it('still labels a genuine ES module namespace (Symbol.toStringTag=Module) and shows its values', () => {
    const ns = { default: 'dark', foo: 'bar' } as Record<string, unknown>;
    Object.defineProperty(ns, Symbol.toStringTag, { value: 'Module' });
    const out = plain(ns);
    expect(out).toContain('Module');
    expect(out).toContain('default: "dark"');
    expect(out).toContain('foo: "bar"');
  });
});

// ENG-22980 finding 3: a cumulative output budget must bound total work so a
// huge or shared/DAG-shaped structure cannot hang or OOM.
describe('inspect: output budget (ENG-22980 #3)', () => {
  it('truncates output that exceeds maxOutputLength and stays bounded', () => {
    const wide: Record<string, unknown> = {};
    for (let i = 0; i < 100; i++) {
      wide['key' + i] = 'x'.repeat(50);
    }
    const tree = { a: wide, b: wide, c: [wide, wide, wide] };
    const out = plain(tree, { maxOutputLength: 500, depth: 8 });
    expect(out).toContain('...');
    // Bounded well under an unbudgeted full render of the shared subtree.
    expect(out.length).toBeLessThan(2000);
  });

  it('does not blow up on a deep DAG re-expanded at every occurrence', () => {
    // Diamond: each level references the previous twice. Unbudgeted+un-deduped
    // this is exponential in depth; the budget must keep it bounded and fast.
    let node: Record<string, unknown> = { leaf: 'x'.repeat(20) };
    for (let i = 0; i < 40; i++) {
      node = { left: node, right: node };
    }
    const start = Date.now();
    let out = '';
    expect(() => {
      out = plain(node, { maxOutputLength: 5000, depth: 1000 });
    }).not.toThrow();
    expect(Date.now() - start).toBeLessThan(2000);
    expect(out.length).toBeLessThan(20000);
    expect(out).toContain('...');
  });

  it('does not truncate a normal small object (no spurious ellipsis)', () => {
    const out = plain({ a: 1, b: { c: 2, d: [3, 4] } });
    expect(out).not.toContain('...');
    expect(out).toContain('c: 2');
  });
});

// Regression guards for behavior that must be preserved.
describe('inspect: preserved behavior', () => {
  it('still detects circular references', () => {
    const a: Record<string, unknown> = { name: 'a' };
    a.self = a;
    expect(plain(a)).toContain('[Circular]');
  });

  it('still renders arrays, dates, maps, and sets', () => {
    expect(plain([1, 2, 3])).toContain('1, 2, 3');
    expect(plain(new Date('2020-01-01T00:00:00.000Z'))).toContain('2020-01-01');
    expect(plain(new Map([['k', 'v']]))).toContain('Map(');
    expect(plain(new Set([1, 2]))).toContain('Set(');
  });
});
