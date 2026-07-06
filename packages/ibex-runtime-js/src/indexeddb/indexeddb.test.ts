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
import { IDBCursorWithValue } from './IDBCursor';
import { encodeOrderedKey, serializeKey, serializeValue } from './serialization';

// ---------------------------------------------------------------------------
// Test harness: a file-backed SQLite provider (real persistence across opens).
// ---------------------------------------------------------------------------

const tmpDirs: string[] = [];

function dbPath(dir: string, name: string): string {
  return join(dir, encodeURIComponent(name) + '.sqlite');
}

function makeProvider(dir: string, onSql?: (sql: string) => void) {
  return {
    create(name: string) {
      const real = new Database(dbPath(dir, name));
      if (!onSql) return real;
      // Record every SQL string so tests can assert range/order pushdown.
      const rec = (sql: string) => onSql(sql);
      return {
        query(sql: string) { rec(sql); return real.query(sql); },
        exec(sql: string, ...p: any[]) { rec(sql); return (real as any).exec(sql, ...p); },
        run(sql: string, ...p: any[]) { rec(sql); return (real as any).run(sql, ...p); },
        prepare(sql: string) { rec(sql); return (real as any).prepare(sql); },
        close() { return real.close(); },
      };
    },
    delete(name: string) {
      for (const suffix of ['', '-wal', '-shm', '-journal']) {
        try {
          rmSync(dbPath(dir, name) + suffix);
        } catch (_) {}
      }
    },
  };
}

function makeDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'idb-eng22974-'));
  tmpDirs.push(dir);
  return dir;
}

function makeFactory(): IDBFactory {
  return new IDBFactory(makeProvider(makeDir()) as any);
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

// ===========================================================================
// ENG-22999 — order-preserving key encoding + SQL range/order pushdown.
// ===========================================================================

describe('ENG-22999: ordered key encoding', () => {
  test('encoded byte order matches compareKeys order for random keys', () => {
    const strcmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
    const sgn = (n: number) => (n < 0 ? -1 : n > 0 ? 1 : 0);

    const randKey = (depth: number): any => {
      const r = Math.random();
      if (depth > 0 && r < 0.2) {
        const len = Math.floor(Math.random() * 4);
        return Array.from({ length: len }, () => randKey(depth - 1));
      }
      switch (Math.floor(Math.random() * 4)) {
        case 0: {
          // Finite numbers only: compareKeys(a,b) = a-b is NaN for equal
          // infinities, so ±Infinity is a compareKeys quirk, not an encoding one.
          const picks = [0, -0, 1, -1, 3.5, -3.5, 42, 41.9999, 255, 256, 1e12, -1e12];
          return Math.random() < 0.5
            ? picks[Math.floor(Math.random() * picks.length)]
            : (Math.random() - 0.5) * 10 ** (Math.floor(Math.random() * 16) - 6);
        }
        case 1:
          return new Date(Math.floor((Math.random() - 0.5) * 4e12));
        case 2: {
          const words = ['', 'a', 'b', 'ab', 'abc', 'app', 'apple', 'apply', 'Z', 'z', 'é', '😀'];
          if (Math.random() < 0.6) return words[Math.floor(Math.random() * words.length)];
          let s = '';
          for (let i = 0, n = Math.floor(Math.random() * 4); i < n; i++) {
            s += String.fromCharCode(Math.floor(Math.random() * 400));
          }
          return s;
        }
        default: {
          const n = Math.floor(Math.random() * 4);
          const bytes = new Uint8Array(n);
          for (let i = 0; i < n; i++) bytes[i] = Math.floor(Math.random() * 256);
          return bytes;
        }
      }
    };

    for (let i = 0; i < 20000; i++) {
      const a = randKey(2);
      const b = randKey(2);
      const raw = compareKeys(a, b);
      const enc = strcmp(encodeOrderedKey(a), encodeOrderedKey(b));
      expect(sgn(raw)).toBe(enc);
    }
  });

  test('encoding is deterministic and collates -0 equal to 0', () => {
    expect(encodeOrderedKey(0)).toBe(encodeOrderedKey(-0));
    expect(encodeOrderedKey([1, 'a'])).toBe(encodeOrderedKey([1, 'a']));
    // Cross-type: every number sorts before every date before every string
    // before binary before array, regardless of value.
    expect(encodeOrderedKey(1e300) < encodeOrderedKey(new Date(0))).toBe(true);
    expect(encodeOrderedKey(new Date(8e12)) < encodeOrderedKey('')).toBe(true);
    expect(encodeOrderedKey('￿') < encodeOrderedKey(new Uint8Array([0]))).toBe(true);
    expect(encodeOrderedKey(new Uint8Array([255])) < encodeOrderedKey([])).toBe(true);
  });
});

describe('ENG-22999: SQL range/order pushdown', () => {
  test('ranged reads/count/delete return correct results on a large mixed store', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'p1', 1, (d) => d.createObjectStore('s'));

    const wtx = db.transaction('s', 'readwrite');
    const ws = wtx.objectStore('s');
    for (let i = 0; i < 500; i++) ws.put(`v${i}`, i);
    await txDone(wtx);

    // getAll(range) ordered + bounded.
    let tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').getAll(IDBKeyRange.bound(100, 104))))
      .toEqual(['v100', 'v101', 'v102', 'v103', 'v104']);

    // Open-ended + count limit.
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').getAll(IDBKeyRange.lowerBound(490), 3)))
      .toEqual(['v490', 'v491', 'v492']);

    // getAllKeys(range) and count(range).
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').getAllKeys(IDBKeyRange.bound(10, 12, true, false))))
      .toEqual([11, 12]);
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').count(IDBKeyRange.bound(200, 299)))).toBe(100);

    // get(range) / getKey(range) return the first (smallest) match.
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').get(IDBKeyRange.lowerBound(300)))).toBe('v300');
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').getKey(IDBKeyRange.bound(42, 99)))).toBe(42);

    // delete(range) removes exactly the range.
    const dtx = db.transaction('s', 'readwrite');
    dtx.objectStore('s').delete(IDBKeyRange.bound(0, 449));
    await txDone(dtx);
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').count())).toBe(50);
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').getKey(IDBKeyRange.lowerBound(0)))).toBe(450);
    db.close();
  });

  test('mixed key types sort per spec (number < date < string < binary < array)', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'p2', 1, (d) => d.createObjectStore('s'));

    const keys: any[] = [
      [2, 'b'], [1], 'zzz', 'a', new Date(1000), new Date(0), 5, -3,
      new Uint8Array([0, 1]), new Uint8Array([0]),
    ];
    const wtx = db.transaction('s', 'readwrite');
    const ws = wtx.objectStore('s');
    keys.forEach((k, i) => ws.put(i, k));
    await txDone(wtx);

    const sorted = [...keys].sort(compareKeys);
    const tx = db.transaction('s', 'readonly');
    const gotKeys = await reqDone<any[]>(tx.objectStore('s').getAllKeys());
    // getAllKeys returns keys already in IndexedDB order via ORDER BY keyenc.
    // Normalize binary keys (which deserialize back to Uint8Array) for compare.
    const norm = (k: any) =>
      ArrayBuffer.isView(k) ? { bin: Array.from(k as any) } : k instanceof Date ? { ms: k.getTime() } : k;
    expect(gotKeys.map(norm)).toEqual(sorted.map(norm));
    db.close();
  });

  test('openCursor streams only the matching range, in both directions', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'p3', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    const ws = wtx.objectStore('s');
    for (let i = 0; i < 50; i++) ws.put(`v${i}`, i);
    await txDone(wtx);

    const collect = (store: any, range: any, dir: any) =>
      new Promise<any[]>((resolve, reject) => {
        const out: any[] = [];
        const req = store.openCursor(range, dir);
        req.onsuccess = () => {
          const cur = req.result;
          if (!cur) return resolve(out);
          out.push([cur.key, cur.value]);
          cur.continue();
        };
        req.onerror = () => reject(req.error);
      });

    let tx = db.transaction('s', 'readonly');
    expect(await collect(tx.objectStore('s'), IDBKeyRange.bound(5, 8), 'next'))
      .toEqual([[5, 'v5'], [6, 'v6'], [7, 'v7'], [8, 'v8']]);

    tx = db.transaction('s', 'readonly');
    expect(await collect(tx.objectStore('s'), IDBKeyRange.bound(5, 8), 'prev'))
      .toEqual([[8, 'v8'], [7, 'v7'], [6, 'v6'], [5, 'v5']]);

    // Cursor write-loop: mutate every record in a range via cursor.update.
    const utx = db.transaction('s', 'readwrite');
    await new Promise<void>((resolve, reject) => {
      const req = utx.objectStore('s').openCursor(IDBKeyRange.bound(10, 12));
      req.onsuccess = () => {
        const cur = req.result;
        if (!cur) return;
        cur.update(`U${cur.key}`);
        cur.continue();
      };
      req.onerror = () => reject(req.error);
      utx.oncomplete = () => resolve();
    });
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').getAll(IDBKeyRange.bound(10, 12))))
      .toEqual(['U10', 'U11', 'U12']);
    db.close();
  });

  test('count(range) and getAll(range) push filtering into SQL (no full-table scan)', async () => {
    const seen: string[] = [];
    const dir = makeDir();
    const factory = new IDBFactory(makeProvider(dir, (sql) => seen.push(sql)) as any);
    const db = await openDb(factory, 'p4', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    for (let i = 0; i < 100; i++) wtx.objectStore('s').put(`v${i}`, i);
    await txDone(wtx);

    // count(range): a COUNT with a keyenc WHERE, and no full row materialization.
    seen.length = 0;
    const ctx = db.transaction('s', 'readonly');
    await reqDone(ctx.objectStore('s').count(IDBKeyRange.bound(10, 20)));
    expect(seen.some((s) => /COUNT\(\*\)/.test(s) && /WHERE keyenc/.test(s))).toBe(true);
    expect(seen.some((s) => /SELECT key, value FROM/.test(s))).toBe(false);

    // getAll(range): a WHERE keyenc + ORDER BY keyenc; only matching rows read.
    seen.length = 0;
    const gtx = db.transaction('s', 'readonly');
    await reqDone(gtx.objectStore('s').getAll(IDBKeyRange.bound(10, 20)));
    expect(seen.some((s) => /WHERE keyenc/.test(s) && /ORDER BY keyenc/.test(s))).toBe(true);
    db.close();
  });

  test('legacy store without keyenc is migrated (ALTER + backfill) and range-queryable', async () => {
    const dir = makeDir();
    const name = 'legacy';

    // Hand-build a database in the pre-ENG-22999 on-disk shape: a store table
    // with only (key, value) and no keyenc column/index.
    const raw = new Database(dbPath(dir, name));
    raw.run(`CREATE TABLE _idb_meta (key TEXT PRIMARY KEY, value TEXT)`);
    raw.run(`INSERT INTO _idb_meta(key, value) VALUES ('version', '1')`);
    raw.run(`CREATE TABLE _idb_stores (store_name TEXT PRIMARY KEY, key_path TEXT, auto_increment INTEGER DEFAULT 0)`);
    raw.run(`INSERT INTO _idb_stores(store_name, key_path, auto_increment) VALUES ('s', 'null', 0)`);
    raw.run(`CREATE TABLE _idb_indexes (store_name TEXT, index_name TEXT, key_path TEXT, unique_flag INTEGER DEFAULT 0, multi_entry INTEGER DEFAULT 0, PRIMARY KEY (store_name, index_name))`);
    raw.run(`CREATE TABLE "idb_store_s" (key TEXT PRIMARY KEY, value TEXT)`);
    for (let i = 1; i <= 10; i++) {
      raw.run(
        `INSERT INTO "idb_store_s" (key, value) VALUES (?, ?)`,
        serializeKey(i),
        serializeValue(`v${i}`),
      );
    }
    raw.close();

    const factory = new IDBFactory(makeProvider(dir) as any);
    const db = await openDb(factory, name, undefined);
    expect(db.version).toBe(1);

    // Range/order queries work on the migrated data (backfilled keyenc).
    let tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').getAllKeys()))
      .toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').getAll(IDBKeyRange.bound(3, 7))))
      .toEqual(['v3', 'v4', 'v5', 'v6', 'v7']);
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').count(IDBKeyRange.lowerBound(8)))).toBe(3);

    // New writes keep keyenc in sync and remain range-queryable.
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put('v11', 11);
    await txDone(wtx);
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').getAll(IDBKeyRange.lowerBound(9))))
      .toEqual(['v9', 'v10', 'v11']);
    db.close();
  });
});

// ===========================================================================
// ENG-23026 — index accessors return index-key order (not primary-key order),
// count of 0 means "all", clear() preserves the key generator, key cursors
// don't expose values, and getKey distinguishes a stored `undefined` from a
// missing record.
// ===========================================================================

describe('ENG-23026: index & accessor correctness', () => {
  // Finding 1: index get/getAll/getAllKeys must be in INDEX-key order, with the
  // primary key as tiebreak — not the store's primary-key order.
  test('index get/getAll/getAllKeys/count return index-key order with primaryKey tiebreak', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'e23026-1', 1, (d) => {
      const s = d.createObjectStore('people', { keyPath: 'id' });
      s.createIndex('byAge', 'age');
    });

    const wtx = db.transaction('people', 'readwrite');
    const ws = wtx.objectStore('people');
    // Inserted in primary-key order; ages are out of order. Two records share
    // age 20 to exercise the primary-key tiebreak.
    ws.put({ id: 1, age: 30 });
    ws.put({ id: 2, age: 20 });
    ws.put({ id: 3, age: 25 });
    ws.put({ id: 5, age: 20 });
    await txDone(wtx);

    let tx = db.transaction('people', 'readonly');
    const all = await reqDone<any[]>(tx.objectStore('people').index('byAge').getAll());
    expect(all.map((r) => r.age)).toEqual([20, 20, 25, 30]);
    // Equal index keys ordered by ascending primary key (2 before 5).
    expect(all.map((r) => r.id)).toEqual([2, 5, 3, 1]);

    tx = db.transaction('people', 'readonly');
    expect(await reqDone(tx.objectStore('people').index('byAge').getAllKeys()))
      .toEqual([2, 5, 3, 1]);

    // get / getKey over a lower-bounded range return the smallest INDEX key,
    // i.e. the youngest person, not primary key 1.
    tx = db.transaction('people', 'readonly');
    const first = await reqDone<any>(tx.objectStore('people').index('byAge').get(IDBKeyRange.lowerBound(0)));
    expect(first.id).toBe(2);
    tx = db.transaction('people', 'readonly');
    expect(await reqDone(tx.objectStore('people').index('byAge').getKey(IDBKeyRange.lowerBound(0)))).toBe(2);

    tx = db.transaction('people', 'readonly');
    expect(await reqDone(tx.objectStore('people').index('byAge').count())).toBe(4);
    db.close();
  });

  // Finding 2: records with no value at the index key path are not in the index,
  // including the unbounded getAll/getAllKeys/count branch.
  test('index excludes records missing the indexed property (unbounded branch)', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'e23026-2', 1, (d) => {
      const s = d.createObjectStore('people', { keyPath: 'id' });
      s.createIndex('byAge', 'age');
    });
    const wtx = db.transaction('people', 'readwrite');
    const ws = wtx.objectStore('people');
    ws.put({ id: 1, age: 30 });
    ws.put({ id: 2 }); // no `age`
    await txDone(wtx);

    let tx = db.transaction('people', 'readonly');
    expect(await reqDone(tx.objectStore('people').index('byAge').count())).toBe(1);
    tx = db.transaction('people', 'readonly');
    expect(await reqDone<any[]>(tx.objectStore('people').index('byAge').getAllKeys())).toEqual([1]);
    tx = db.transaction('people', 'readonly');
    expect((await reqDone<any[]>(tx.objectStore('people').index('byAge').getAll())).length).toBe(1);
    db.close();
  });

  // Finding 3: count of 0 (like absent) means "all", for both store and index.
  test('getAll/getAllKeys with count 0 return all records (store and index)', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'e23026-3', 1, (d) => {
      const s = d.createObjectStore('s', { keyPath: 'id' });
      s.createIndex('byV', 'v');
    });
    const wtx = db.transaction('s', 'readwrite');
    const ws = wtx.objectStore('s');
    ws.put({ id: 1, v: 'a' });
    ws.put({ id: 2, v: 'b' });
    ws.put({ id: 3, v: 'c' });
    await txDone(wtx);

    let tx = db.transaction('s', 'readonly');
    expect((await reqDone<any[]>(tx.objectStore('s').getAll(undefined, 0))).length).toBe(3);
    tx = db.transaction('s', 'readonly');
    expect(await reqDone<any[]>(tx.objectStore('s').getAllKeys(undefined, 0))).toEqual([1, 2, 3]);
    tx = db.transaction('s', 'readonly');
    expect((await reqDone<any[]>(tx.objectStore('s').index('byV').getAll(undefined, 0))).length).toBe(3);
    tx = db.transaction('s', 'readonly');
    expect(await reqDone<any[]>(tx.objectStore('s').index('byV').getAllKeys(undefined, 0))).toEqual([1, 2, 3]);
    db.close();
  });

  // Finding 4: clear() must not reset the autoIncrement generator.
  test('clear() does not reset the autoIncrement key generator', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'e23026-4', 1, (d) => {
      d.createObjectStore('s', { autoIncrement: true });
    });

    const tx1 = db.transaction('s', 'readwrite');
    const s1 = tx1.objectStore('s');
    const r1 = s1.add({});
    const r2 = s1.add({});
    await txDone(tx1);
    expect(r1.result).toBe(1);
    expect(r2.result).toBe(2);

    const tx2 = db.transaction('s', 'readwrite');
    tx2.objectStore('s').clear();
    await txDone(tx2);

    const tx3 = db.transaction('s', 'readwrite');
    const r3 = tx3.objectStore('s').add({});
    await txDone(tx3);
    expect(r3.result).toBe(3); // continues from 2, not reset back to 1
    db.close();
  });

  // Finding 5: key cursors yield a plain IDBCursor with no value.
  test('openKeyCursor yields a valueless cursor (store and index)', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'e23026-5', 1, (d) => {
      const s = d.createObjectStore('s', { keyPath: 'id' });
      s.createIndex('byV', 'v');
    });
    const wtx = db.transaction('s', 'readwrite');
    const ws = wtx.objectStore('s');
    ws.put({ id: 1, v: 'a' });
    ws.put({ id: 2, v: 'b' });
    await txDone(wtx);

    const firstCursor = (store: any, method: 'openKeyCursor', src: 'store' | 'index') =>
      new Promise<any>((resolve, reject) => {
        const source = src === 'index' ? store.index('byV') : store;
        const req = source[method]();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });

    let tx = db.transaction('s', 'readonly');
    const c1 = await firstCursor(tx.objectStore('s'), 'openKeyCursor', 'store');
    expect(c1).toBeDefined();
    expect(c1).not.toBeInstanceOf(IDBCursorWithValue);
    expect('value' in c1).toBe(false);
    expect(c1.value).toBeUndefined();
    expect(c1.key).toBe(1);

    tx = db.transaction('s', 'readonly');
    const c2 = await firstCursor(tx.objectStore('s'), 'openKeyCursor', 'index');
    expect(c2).not.toBeInstanceOf(IDBCursorWithValue);
    expect(c2.value).toBeUndefined();
    expect(c2.key).toBe('a'); // index key
    expect(c2.primaryKey).toBe(1);
    db.close();
  });

  // Finding 6: a stored `undefined` value is a real record; getKey must not
  // report it as missing.
  test('getKey reports an existing record whose stored value is undefined', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'e23026-6', 1, (d) => {
      d.createObjectStore('s'); // out-of-line keys
    });
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put(undefined, 'k');
    await txDone(wtx);

    let tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').getKey('k'))).toBe('k');
    // A genuinely absent key still yields undefined.
    tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').getKey('missing'))).toBeUndefined();
    db.close();
  });
});
