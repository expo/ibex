// ENG-22974 — correctness/perf fixes for the web IndexedDB shim
// (packages/ibex-runtime-js/src/indexeddb/). Exercises the five audit findings
// against a real (file-backed) SQLite backend via bun:sqlite so persistence,
// transactions and rollback behave like production. Run with: bun test.

import { afterAll, describe, expect, test } from 'bun:test';
import { Database } from 'bun:sqlite';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { IDBFactory } from './IDBFactory';
import { IDBKeyRange, compareKeys } from './IDBKeyRange';

// ---------------------------------------------------------------------------
// Test harness: a file-backed SQLite provider (real persistence across opens).
// ---------------------------------------------------------------------------

const tmpDirs: string[] = [];

function makeFactory(): IDBFactory {
  const dir = mkdtempSync(join(tmpdir(), 'idb-eng22974-'));
  tmpDirs.push(dir);
  const provider = {
    create(name: string) {
      return new Database(join(dir, encodeURIComponent(name) + '.sqlite'));
    },
    delete(name: string) {
      for (const suffix of ['', '-wal', '-shm', '-journal']) {
        try {
          rmSync(join(dir, encodeURIComponent(name) + '.sqlite' + suffix));
        } catch (_) {}
      }
    },
  };
  return new IDBFactory(provider as any);
}

afterAll(() => {
  for (const dir of tmpDirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch (_) {}
  }
});

const flush = () => new Promise<void>((r) => setTimeout(r, 0));

function openDb(
  factory: IDBFactory,
  name: string,
  version: number | undefined,
  onUpgrade?: (db: any, event: any) => void,
): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = factory.open(name, version);
    if (onUpgrade) {
      req.onupgradeneeded = (e: any) => onUpgrade(e.target.result, e);
    }
    req.onsuccess = (e: any) => resolve(e.target.result);
    req.onerror = () => reject(req.error ?? new Error('open failed'));
  });
}

function txDone(tx: any): Promise<'complete' | 'abort'> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve('complete');
    tx.onabort = () => resolve('abort');
    tx.onerror = () => reject(tx.error ?? new Error('tx error'));
  });
}

function reqDone<T = any>(req: any): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('request failed'));
  });
}

// ===========================================================================
// Finding 1 — transaction lifecycle: nested-onsuccess writes stay in one txn,
// abort rolls them ALL back, and ops on a finished txn throw.
// ===========================================================================

describe('finding 1: transaction lifecycle & inactivity', () => {
  test('writes chained through deeply nested onsuccess handlers all commit atomically', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'f1a', 1, (d) => {
      d.createObjectStore('s', { keyPath: 'id' });
    });

    const tx = db.transaction('s', 'readwrite');
    const store = tx.objectStore('s');
    // Three levels of onsuccess nesting — pre-fix, only the first put ran
    // inside the transaction and the rest leaked after COMMIT.
    const r1 = store.put({ id: 1, v: 'a' });
    r1.onsuccess = () => {
      const r2 = store.put({ id: 2, v: 'b' });
      r2.onsuccess = () => {
        const r3 = store.put({ id: 3, v: 'c' });
        r3.onsuccess = () => {
          store.put({ id: 4, v: 'd' });
        };
      };
    };
    expect(await txDone(tx)).toBe('complete');

    const rtx = db.transaction('s', 'readonly');
    const count = await reqDone<number>(rtx.objectStore('s').count());
    expect(count).toBe(4);
    db.close();
  });

  test('abort after a nested chain rolls back every write, not just the first', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'f1b', 1, (d) => {
      d.createObjectStore('s', { keyPath: 'id' });
    });

    const tx = db.transaction('s', 'readwrite');
    const store = tx.objectStore('s');
    const r1 = store.put({ id: 1, v: 'a' });
    r1.onsuccess = () => {
      const r2 = store.put({ id: 2, v: 'b' });
      r2.onsuccess = () => {
        const r3 = store.put({ id: 3, v: 'c' });
        r3.onsuccess = () => {
          tx.abort();
        };
      };
    };
    expect(await txDone(tx)).toBe('abort');

    const rtx = db.transaction('s', 'readonly');
    const count = await reqDone<number>(rtx.objectStore('s').count());
    expect(count).toBe(0); // all three rolled back
    db.close();
  });

  test('issuing an operation on a finished transaction throws TransactionInactiveError', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'f1c', 1, (d) => {
      d.createObjectStore('s', { keyPath: 'id' });
    });
    const tx = db.transaction('s', 'readwrite');
    const store = tx.objectStore('s');
    store.put({ id: 1 });
    await txDone(tx);

    let err: any;
    try {
      store.put({ id: 2 });
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err.name).toBe('TransactionInactiveError');
    db.close();
  });
});

// ===========================================================================
// Finding 2 — structured serialization of values & keys, and key comparison.
// ===========================================================================

describe('finding 2: structured serialization & key comparison', () => {
  test('Date / TypedArray / ArrayBuffer / Map / Set / undefined round-trip', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'f2a', 1, (d) => {
      d.createObjectStore('s');
    });

    const value = {
      when: new Date('2021-06-15T12:00:00.000Z'),
      bytes: new Uint8Array([1, 2, 3, 250]),
      floats: new Float64Array([1.5, -2.25]),
      buf: new Uint8Array([9, 8, 7]).buffer,
      map: new Map<string, number>([['a', 1], ['b', 2]]),
      set: new Set([1, 2, 3]),
      missing: undefined,
      nested: { d: new Date(0) },
    };

    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put(value, 'k');
    await txDone(wtx);

    const rtx = db.transaction('s', 'readonly');
    const out: any = await reqDone(rtx.objectStore('s').get('k'));

    expect(out.when).toBeInstanceOf(Date);
    expect(out.when.getTime()).toBe(Date.parse('2021-06-15T12:00:00.000Z'));
    expect(out.bytes).toBeInstanceOf(Uint8Array);
    expect(Array.from(out.bytes)).toEqual([1, 2, 3, 250]);
    expect(out.floats).toBeInstanceOf(Float64Array);
    expect(Array.from(out.floats)).toEqual([1.5, -2.25]);
    expect(out.buf).toBeInstanceOf(ArrayBuffer);
    expect(Array.from(new Uint8Array(out.buf))).toEqual([9, 8, 7]);
    expect(out.map).toBeInstanceOf(Map);
    expect(out.map.get('b')).toBe(2);
    expect(out.set).toBeInstanceOf(Set);
    expect(out.set.has(3)).toBe(true);
    expect('missing' in out).toBe(true);
    expect(out.missing).toBeUndefined();
    expect(out.nested.d).toBeInstanceOf(Date);
    db.close();
  });

  test('Date keys sort correctly and Date-bounded ranges include the right records', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'f2b', 1, (d) => {
      d.createObjectStore('s');
    });
    const d1 = new Date('2020-01-01T00:00:00Z');
    const d2 = new Date('2021-01-01T00:00:00Z');
    const d3 = new Date('2022-01-01T00:00:00Z');

    const wtx = db.transaction('s', 'readwrite');
    const ws = wtx.objectStore('s');
    // Insert out of order.
    ws.put('c', d3);
    ws.put('a', d1);
    ws.put('b', d2);
    await txDone(wtx);

    // getAll returns values ordered by Date key.
    const rtx = db.transaction('s', 'readonly');
    const all = await reqDone<any[]>(rtx.objectStore('s').getAll());
    expect(all).toEqual(['a', 'b', 'c']);

    // A Date-bounded range [d1, d2) includes only d1's record.
    const rtx2 = db.transaction('s', 'readonly');
    const ranged = await reqDone<any[]>(
      rtx2.objectStore('s').getAll(IDBKeyRange.bound(d1, d2, false, true)),
    );
    expect(ranged).toEqual(['a']);

    // Exact Date-key lookup works.
    const rtx3 = db.transaction('s', 'readonly');
    const one = await reqDone(rtx3.objectStore('s').get(d2));
    expect(one).toBe('b');
    db.close();
  });

  test('compareKeys orders binary keys and throws DataError for invalid keys', () => {
    // Type ordering: number < date < string < binary < array.
    expect(compareKeys(1, new Date(0))).toBeLessThan(0);
    expect(compareKeys(new Date(0), 'x')).toBeLessThan(0);
    expect(compareKeys('x', new Uint8Array([0]))).toBeLessThan(0);
    expect(compareKeys(new Uint8Array([0]), [0])).toBeLessThan(0);

    // Binary byte-wise ordering.
    expect(compareKeys(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBeLessThan(0);
    expect(compareKeys(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(0);
    expect(compareKeys(new Uint8Array([1, 2, 0]), new Uint8Array([1, 2]))).toBeGreaterThan(0);

    for (const bad of [true, null, undefined, { a: 1 }, NaN]) {
      let err: any;
      try {
        compareKeys(bad, 1);
      } catch (e) {
        err = e;
      }
      expect(err, `expected DataError for ${String(bad)}`).toBeDefined();
      expect(err.name).toBe('DataError');
    }
  });
});

// ===========================================================================
// Finding 3 — reopen after close().
// ===========================================================================

describe('finding 3: reopen after close', () => {
  test('a database can be reopened after close() (cache is evicted)', async () => {
    const factory = makeFactory();
    const db1 = await openDb(factory, 'f3', 1, (d) => {
      const s = d.createObjectStore('s', { keyPath: 'id' });
      s.createIndex('byV', 'v');
    });
    const wtx = db1.transaction('s', 'readwrite');
    wtx.objectStore('s').put({ id: 1, v: 'x' });
    await txDone(wtx);
    db1.close();

    // Pre-fix this reused the closed SQLite handle and threw on every open.
    const db2 = await openDb(factory, 'f3', undefined);
    expect(db2.version).toBe(1);
    expect(db2.objectStoreNames.contains('s')).toBe(true);
    const rtx = db2.transaction('s', 'readonly');
    const rec: any = await reqDone(rtx.objectStore('s').get(1));
    expect(rec.v).toBe('x');
    db2.close();
  });
});

// ===========================================================================
// Finding 4 — an aborted upgrade rolls back schema + version (no wedged db).
// ===========================================================================

describe('finding 4: versionchange rollback', () => {
  test('a throwing onupgradeneeded rolls back created stores so the db reopens', async () => {
    const factory = makeFactory();

    // First upgrade creates store A then throws.
    let firstErr: any;
    try {
      await openDb(factory, 'f4', 1, (d) => {
        d.createObjectStore('A', { keyPath: 'id' });
        throw new Error('boom during upgrade');
      });
    } catch (e) {
      firstErr = e;
    }
    expect(firstErr).toBeDefined();

    // Pre-fix the half-applied CREATE TABLE for A survived, so this retry threw
    // ConstraintError re-creating A and every subsequent open failed forever.
    const db = await openDb(factory, 'f4', 1, (d) => {
      d.createObjectStore('A', { keyPath: 'id' });
      d.createObjectStore('B', { keyPath: 'id' });
    });
    expect(db.version).toBe(1);
    expect(db.objectStoreNames.contains('A')).toBe(true);
    expect(db.objectStoreNames.contains('B')).toBe(true);
    db.close();

    // Version was rolled back too: reopening from disk sees version 1 (the
    // successful upgrade), not a phantom bump from the failed attempt.
    const db2 = await openDb(factory, 'f4', undefined);
    expect(db2.version).toBe(1);
    db2.close();
  });
});

// ===========================================================================
// Finding 5 — autoIncrement counter is cached/persistent, and key-only /
// batched paths stay correct.
// ===========================================================================

describe('finding 5: autoIncrement counter & key-only paths', () => {
  test('autoIncrement keys are monotonic across transactions and survive reopen', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'f5a', 1, (d) => {
      d.createObjectStore('s', { keyPath: 'id', autoIncrement: true });
    });

    const tx1 = db.transaction('s', 'readwrite');
    const k1 = await reqDone(tx1.objectStore('s').add({ v: 'a' }));
    await txDone(tx1);
    const tx2 = db.transaction('s', 'readwrite');
    const k2 = await reqDone(tx2.objectStore('s').add({ v: 'b' }));
    await txDone(tx2);
    expect(k1).toBe(1);
    expect(k2).toBe(2);
    db.close();

    // Reopen: the generator base is recomputed from disk, so the next key is 3.
    const db2 = await openDb(factory, 'f5a', undefined);
    const tx3 = db2.transaction('s', 'readwrite');
    const k3 = await reqDone(tx3.objectStore('s').add({ v: 'c' }));
    await txDone(tx3);
    expect(k3).toBe(3);
    db2.close();
  });

  test('an explicit numeric key advances the generator so keys never collide', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'f5b', 1, (d) => {
      d.createObjectStore('s', { keyPath: 'id', autoIncrement: true });
    });
    // Both adds must be issued synchronously: awaiting between operations would
    // (correctly) let the transaction auto-commit and finish.
    const tx = db.transaction('s', 'readwrite');
    const s = tx.objectStore('s');
    const r1 = s.add({ id: 100, v: 'x' });
    const r2 = s.add({ v: 'y' });
    await txDone(tx);
    expect(r1.result).toBe(100);
    expect(r2.result).toBe(101);
    db.close();
  });

  test('range delete, count and getAllKeys stay correct', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'f5c', 1, (d) => {
      d.createObjectStore('s');
    });
    const wtx = db.transaction('s', 'readwrite');
    const ws = wtx.objectStore('s');
    for (let i = 1; i <= 10; i++) ws.put(`v${i}`, i);
    await txDone(wtx);

    const ctx = db.transaction('s', 'readonly');
    expect(await reqDone(ctx.objectStore('s').count(IDBKeyRange.bound(3, 7)))).toBe(5);

    const ktx = db.transaction('s', 'readonly');
    expect(await reqDone(ktx.objectStore('s').getAllKeys())).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    const dtx = db.transaction('s', 'readwrite');
    dtx.objectStore('s').delete(IDBKeyRange.bound(3, 7));
    await txDone(dtx);

    const atx = db.transaction('s', 'readonly');
    expect(await reqDone(atx.objectStore('s').getAllKeys())).toEqual([1, 2, 8, 9, 10]);
    db.close();
  });
});
