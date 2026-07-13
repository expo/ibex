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
import { Blob as IbexBlob } from '../blob/Blob';
import { File as IbexFile } from '../blob/File';

// ---------------------------------------------------------------------------
// Test harness: a file-backed SQLite provider (real persistence across opens).
// ---------------------------------------------------------------------------

const tmpRoot = mkdtempSync(join(tmpdir(), 'idb-eng22974-suite-'));

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
  // Keep each factory isolated while making suite cleanup a single recursive
  // operation. Removing dozens of separate SQLite directories can exceed
  // Bun's default hook timeout when the full test matrix is under disk load.
  return mkdtempSync(join(tmpRoot, 'case-'));
}

function makeFactory(): IDBFactory {
  return new IDBFactory(makeProvider(makeDir()) as any);
}

afterAll(() => {
  try {
    rmSync(tmpRoot, { recursive: true, force: true });
  } catch (_) {}
}, 30_000);

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

// Like txDone but tolerant of request error events bubbling to the
// transaction (used with preventDefault()-ed request failures, where the
// transaction still completes). (ENG-23117)
function txSettled(tx: any): Promise<'complete' | 'abort'> {
  return new Promise((resolve) => {
    tx.oncomplete = () => resolve('complete');
    tx.onabort = () => resolve('abort');
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

  test('multi-megabyte binary values persist as compact SQLite BLOBs', async () => {
    const dir = makeDir();
    const name = 'f2-binary-blob';
    const factory = new IDBFactory(makeProvider(dir) as any);
    const db = await openDb(factory, name, 1, (d) => d.createObjectStore('s'));
    const payload = new Uint8Array(2 * 1024 * 1024);
    for (let i = 0; i < payload.length; i++) payload[i] = (i * 31) & 0xff;

    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put({ payload }, 'large');
    await txDone(wtx);
    db.close();

    const raw = new Database(dbPath(dir, name), { readonly: true });
    const row = raw
      .query(`SELECT typeof(value) AS storageType, length(value) AS storedLength FROM "idb_store_s" WHERE key = ?`)
      .get(serializeKey('large')) as any;
    raw.close();
    expect(row.storageType).toBe('blob');
    // The v2 envelope adds only a small metadata header. Base64 would require
    // at least 4/3 of the payload and the old JSON number array roughly 3-4x.
    expect(row.storedLength).toBeLessThan(payload.byteLength + 1024);

    const reopened = await openDb(factory, name, undefined);
    const value: any = await reqDone(
      reopened.transaction('s', 'readonly').objectStore('s').get('large'),
    );
    expect(value.payload).toBeInstanceOf(Uint8Array);
    expect(value.payload.byteLength).toBe(payload.byteLength);
    expect(value.payload[0]).toBe(0);
    expect(value.payload[1]).toBe(31);
    expect(value.payload[payload.length - 1]).toBe(payload[payload.length - 1]);
    reopened.close();
  });

  test('autoIncrement keyPath injection reuses the owned large-binary clone', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'f2-auto-large-clone', 1, (d) => {
      d.createObjectStore('s', { keyPath: 'id', autoIncrement: true });
    });
    const payload = new Uint8Array(2 * 1024 * 1024);
    payload[0] = 17;
    payload[payload.length - 1] = 93;
    const original: any = { payload };

    const tx = db.transaction('s', 'readwrite');
    const key = await reqDone(tx.objectStore('s').add(original));
    await txDone(tx);
    expect(key).toBe(1);
    expect(original.id).toBeUndefined();

    const out: any = await reqDone(db.transaction('s', 'readonly').objectStore('s').get(1));
    expect(out.id).toBe(1);
    expect(out.payload).toBeInstanceOf(Uint8Array);
    expect(out.payload.byteLength).toBe(payload.byteLength);
    expect(out.payload[0]).toBe(17);
    expect(out.payload[payload.length - 1]).toBe(93);
    db.close();
  });

  test('legacy tagged-JSON TEXT values remain readable', async () => {
    const dir = makeDir();
    const name = 'f2-legacy-text';
    const raw = new Database(dbPath(dir, name));
    raw.run(`CREATE TABLE _idb_meta (key TEXT PRIMARY KEY, value TEXT)`);
    raw.run(`INSERT INTO _idb_meta(key, value) VALUES ('version', '1')`);
    raw.run(`CREATE TABLE _idb_stores (store_name TEXT PRIMARY KEY, key_path TEXT, auto_increment INTEGER DEFAULT 0)`);
    raw.run(`INSERT INTO _idb_stores(store_name, key_path, auto_increment) VALUES ('s', 'null', 0)`);
    raw.run(`CREATE TABLE _idb_indexes (store_name TEXT, index_name TEXT, key_path TEXT, unique_flag INTEGER DEFAULT 0, multi_entry INTEGER DEFAULT 0, PRIMARY KEY (store_name, index_name))`);
    raw.run(`CREATE TABLE "idb_store_s" (key TEXT PRIMARY KEY, value TEXT, keyenc TEXT)`);
    raw.run(
      `INSERT INTO "idb_store_s" (key, value, keyenc) VALUES (?, ?, ?)`,
      serializeKey('legacy'),
      JSON.stringify({ bytes: { __idb_tag__: 'ArrayBuffer', data: 'AQID' } }),
      encodeOrderedKey('legacy'),
    );
    raw.close();

    const db = await openDb(new IDBFactory(makeProvider(dir) as any), name, undefined);
    const value: any = await reqDone(
      db.transaction('s', 'readonly').objectStore('s').get('legacy'),
    );
    expect(Array.from(new Uint8Array(value.bytes))).toEqual([1, 2, 3]);
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
    // Normalize binary keys for compare: stored binary keys deserialize to
    // canonical ArrayBuffers (ENG-23134) while `sorted` holds the original
    // Uint8Array views.
    const norm = (k: any) =>
      k instanceof ArrayBuffer
        ? { bin: Array.from(new Uint8Array(k)) }
        : ArrayBuffer.isView(k)
          ? { bin: Array.from(k as any) }
          : k instanceof Date
            ? { ms: k.getTime() }
            : k;
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

// ===========================================================================
// ENG-23016 — per-index SQLite key tables (sublinear index lookups, multiEntry
// + unique maintenance, migration) and bounded-memory (batched) streaming
// object-store cursors.
// ===========================================================================

describe('ENG-23016: per-index key tables', () => {
  test('index reads run against the companion index table, not a full store scan', async () => {
    const seen: string[] = [];
    const dir = makeDir();
    const factory = new IDBFactory(makeProvider(dir, (sql) => seen.push(sql)) as any);
    const db = await openDb(factory, 'ix-sql', 1, (d) => {
      const s = d.createObjectStore('people', { keyPath: 'id' });
      s.createIndex('byAge', 'age');
    });
    const wtx = db.transaction('people', 'readwrite');
    const ws = wtx.objectStore('people');
    for (let i = 0; i < 50; i++) ws.put({ id: i, age: 100 - i });
    await txDone(wtx);

    seen.length = 0;
    const tx = db.transaction('people', 'readonly');
    await reqDone(tx.objectStore('people').index('byAge').getAll(IDBKeyRange.bound(60, 70)));
    // The read joins the per-index table; it never scans the whole store.
    expect(seen.some((s) => /FROM "idb_index_people"/.test(s) && /JOIN/.test(s))).toBe(true);
    expect(seen.some((s) => /ORDER BY ix\.keyenc/.test(s))).toBe(true);

    // count(range) is a COUNT over the index table with no JOIN / row read.
    seen.length = 0;
    const ctx = db.transaction('people', 'readonly');
    await reqDone(ctx.objectStore('people').index('byAge').count(IDBKeyRange.bound(60, 70)));
    expect(seen.some((s) => /COUNT\(\*\)/.test(s) && /FROM "idb_index_people"/.test(s))).toBe(true);
    db.close();
  });

  test('multiEntry index expands array keys and dedupes duplicate subkeys', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'multi', 1, (d) => {
      const s = d.createObjectStore('docs', { keyPath: 'id' });
      s.createIndex('tags', 'tags', { multiEntry: true });
    });
    const wtx = db.transaction('docs', 'readwrite');
    const ws = wtx.objectStore('docs');
    ws.put({ id: 1, tags: ['a', 'b'] });
    ws.put({ id: 2, tags: ['b', 'c'] });
    ws.put({ id: 3, tags: ['x', 'x'] }); // duplicate subkeys collapse to one entry
    await txDone(wtx);

    let tx = db.transaction('docs', 'readonly');
    expect(await reqDone(tx.objectStore('docs').index('tags').getAllKeys('b'))).toEqual([1, 2]);
    tx = db.transaction('docs', 'readonly');
    expect(await reqDone(tx.objectStore('docs').index('tags').count('b'))).toBe(2);
    tx = db.transaction('docs', 'readonly');
    expect(await reqDone(tx.objectStore('docs').index('tags').count('x'))).toBe(1);
    // Unbounded getAllKeys: one entry per (deduped) tag, index-key order then pk.
    tx = db.transaction('docs', 'readonly');
    expect(await reqDone(tx.objectStore('docs').index('tags').getAllKeys()))
      .toEqual([1, 1, 2, 2, 3]); // a(1) b(1) b(2) c(2) x(3)

    // Deleting a record removes all of its multiEntry rows.
    const dtx = db.transaction('docs', 'readwrite');
    dtx.objectStore('docs').delete(2);
    await txDone(dtx);
    tx = db.transaction('docs', 'readonly');
    expect(await reqDone(tx.objectStore('docs').index('tags').getAllKeys('b'))).toEqual([1]);
    db.close();
  });

  test('unique index rejects a conflicting write with ConstraintError but allows same-key replace', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'uniq', 1, (d) => {
      const s = d.createObjectStore('users', { keyPath: 'id' });
      s.createIndex('email', 'email', { unique: true });
    });

    const tx1 = db.transaction('users', 'readwrite');
    const s1 = tx1.objectStore('users');
    const ok = s1.add({ id: 1, email: 'a@x.com' });
    const dup = s1.add({ id: 2, email: 'a@x.com' }); // conflicts on the unique index
    // Per spec an unhandled request error aborts the whole transaction;
    // preventDefault() opts out so the other writes commit. (ENG-23117)
    dup.onerror = (e: any) => e.preventDefault();
    expect(await txSettled(tx1)).toBe('complete');
    expect(ok.result).toBe(1);
    expect(dup.error).toBeDefined();
    expect(dup.error.name).toBe('ConstraintError');

    // Only the first record made it in.
    let tx = db.transaction('users', 'readonly');
    expect(await reqDone(tx.objectStore('users').index('email').getAllKeys('a@x.com'))).toEqual([1]);

    // Replacing the SAME record's value keeps the same index key — no self-conflict.
    const tx2 = db.transaction('users', 'readwrite');
    tx2.objectStore('users').put({ id: 1, email: 'a@x.com', n: 2 });
    await txDone(tx2);
    tx = db.transaction('users', 'readonly');
    expect(await reqDone(tx.objectStore('users').index('email').count('a@x.com'))).toBe(1);

    // Moving record 3 onto record 1's email conflicts.
    const tx3 = db.transaction('users', 'readwrite');
    const s3 = tx3.objectStore('users');
    s3.add({ id: 3, email: 'c@x.com' });
    const clash = s3.put({ id: 3, email: 'a@x.com' });
    clash.onerror = (e: any) => e.preventDefault();
    expect(await txSettled(tx3)).toBe('complete');
    expect(clash.error?.name).toBe('ConstraintError');
    db.close();
  });

  test('createIndex backfills from records already in the store', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'backfill', 1, (d) => {
      const s = d.createObjectStore('s', { keyPath: 'id' });
      // Write rows during the upgrade BEFORE the index exists, then create the
      // index: its companion rows must be backfilled from the existing data.
      s.put({ id: 1, v: 'x' });
      s.put({ id: 2, v: 'y' });
      s.createIndex('byV', 'v');
    });
    let tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').index('byV').getAllKeys())).toEqual([1, 2]);
    tx = db.transaction('s', 'readonly');
    const rec: any = await reqDone(tx.objectStore('s').index('byV').get('y'));
    expect(rec.id).toBe(2);
    db.close();
  });

  test('a legacy database without a per-index table is migrated on first index read', async () => {
    const dir = makeDir();
    const name = 'legacy-index';

    // Hand-build the pre-ENG-23016 on-disk shape: a store with keyenc + index
    // METADATA, but no `idb_index_<store>` companion table and no marker.
    const raw = new Database(dbPath(dir, name));
    raw.run(`CREATE TABLE _idb_meta (key TEXT PRIMARY KEY, value TEXT)`);
    raw.run(`INSERT INTO _idb_meta(key, value) VALUES ('version', '1')`);
    raw.run(`CREATE TABLE _idb_stores (store_name TEXT PRIMARY KEY, key_path TEXT, auto_increment INTEGER DEFAULT 0)`);
    raw.run(`INSERT INTO _idb_stores(store_name, key_path, auto_increment) VALUES ('s', '"id"', 0)`);
    raw.run(`CREATE TABLE _idb_indexes (store_name TEXT, index_name TEXT, key_path TEXT, unique_flag INTEGER DEFAULT 0, multi_entry INTEGER DEFAULT 0, PRIMARY KEY (store_name, index_name))`);
    raw.run(`INSERT INTO _idb_indexes(store_name, index_name, key_path, unique_flag, multi_entry) VALUES ('s', 'byV', '"v"', 0, 0)`);
    raw.run(`CREATE TABLE "idb_store_s" (key TEXT PRIMARY KEY, value TEXT, keyenc TEXT)`);
    for (let i = 1; i <= 5; i++) {
      raw.run(
        `INSERT INTO "idb_store_s" (key, value, keyenc) VALUES (?, ?, ?)`,
        serializeKey(i),
        serializeValue({ id: i, v: `v${6 - i}` }), // v5,v4,v3,v2,v1 for ids 1..5
        encodeOrderedKey(i),
      );
    }
    raw.close();

    const factory = new IDBFactory(makeProvider(dir) as any);
    const db = await openDb(factory, name, undefined);
    // First index read migrates (builds + backfills the companion table).
    let tx = db.transaction('s', 'readonly');
    expect(await reqDone(tx.objectStore('s').index('byV').getAllKeys()))
      .toEqual([5, 4, 3, 2, 1]); // ordered by v1..v5 -> ids 5..1
    tx = db.transaction('s', 'readonly');
    const rec: any = await reqDone(tx.objectStore('s').index('byV').get('v3'));
    expect(rec.id).toBe(3);
    db.close();
  });
});

describe('ENG-23016: bounded-memory streaming cursors', () => {
  // Drive a cursor to completion, collecting [key, value] pairs.
  const drain = (store: any, range: any, dir: any, key = false) =>
    new Promise<any[]>((resolve, reject) => {
      const out: any[] = [];
      const req = key ? store.openKeyCursor(range, dir) : store.openCursor(range, dir);
      req.onsuccess = () => {
        const cur = req.result;
        if (!cur) return resolve(out);
        out.push(key ? cur.key : [cur.key, cur.value]);
        cur.continue();
      };
      req.onerror = () => reject(req.error);
    });

  test('an unbounded cursor over a large store pages in bounded batches', async () => {
    const seen: string[] = [];
    const dir = makeDir();
    const factory = new IDBFactory(makeProvider(dir, (sql) => seen.push(sql)) as any);
    const db = await openDb(factory, 'stream-big', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    for (let i = 0; i < 300; i++) wtx.objectStore('s').put(`v${i}`, i);
    await txDone(wtx);

    seen.length = 0;
    const tx = db.transaction('s', 'readonly');
    const rows = await drain(tx.objectStore('s'), null, 'next');
    expect(rows.length).toBe(300);
    expect(rows[0]).toEqual([0, 'v0']);
    expect(rows[299]).toEqual([299, 'v299']);
    // Bounded memory: the cursor issued several batched SELECTs (LIMIT), never a
    // single fetch of the whole store.
    const fetches = seen.filter((s) => /SELECT key, value, keyenc FROM "idb_store_s"/.test(s) && /LIMIT/.test(s));
    expect(fetches.length).toBeGreaterThan(1);
    db.close();
  });

  test('streaming cursor iterates correctly in reverse over a large store', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'stream-rev', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    for (let i = 0; i < 300; i++) wtx.objectStore('s').put(`v${i}`, i);
    await txDone(wtx);

    const tx = db.transaction('s', 'readonly');
    const rows = await drain(tx.objectStore('s'), null, 'prev');
    expect(rows.length).toBe(300);
    expect(rows[0]).toEqual([299, 'v299']);
    expect(rows[299]).toEqual([0, 'v0']);
    db.close();
  });

  test('continue(key) re-seeks across batch boundaries', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'stream-seek', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    for (let i = 0; i < 300; i++) wtx.objectStore('s').put(`v${i}`, i);
    await txDone(wtx);

    const out = await new Promise<any[]>((resolve, reject) => {
      const acc: any[] = [];
      let jumped = false;
      const req = db.transaction('s', 'readonly').objectStore('s').openCursor();
      req.onsuccess = () => {
        const cur = req.result;
        if (!cur) return resolve(acc);
        if (!jumped) {
          jumped = true;
          expect(cur.key).toBe(0);
          cur.continue(250); // jump well past the first batch
          return;
        }
        acc.push(cur.key);
        cur.continue();
      };
      req.onerror = () => reject(req.error);
    });
    expect(out[0]).toBe(250);
    expect(out[out.length - 1]).toBe(299);
    expect(out.length).toBe(50);
    db.close();
  });

  test('advance() skips across batch boundaries', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'stream-adv', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    for (let i = 0; i < 300; i++) wtx.objectStore('s').put(`v${i}`, i);
    await txDone(wtx);

    const landed = await new Promise<any>((resolve, reject) => {
      const req = db.transaction('s', 'readonly').objectStore('s').openCursor();
      let advanced = false;
      req.onsuccess = () => {
        const cur = req.result;
        if (!cur) return resolve(undefined);
        if (!advanced) {
          advanced = true;
          cur.advance(150); // 0 -> 150, crossing the 128-row batch boundary
          return;
        }
        resolve(cur.key);
      };
      req.onerror = () => reject(req.error);
    });
    expect(landed).toBe(150);
    db.close();
  });

  test('streaming key cursor over a large store yields keys only, in bounded batches', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'stream-key', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    for (let i = 0; i < 300; i++) wtx.objectStore('s').put(`v${i}`, i);
    await txDone(wtx);

    const tx = db.transaction('s', 'readonly');
    const keys = await drain(tx.objectStore('s'), IDBKeyRange.lowerBound(100), 'next', true);
    expect(keys.length).toBe(200);
    expect(keys[0]).toBe(100);
    expect(keys[199]).toBe(299);
    db.close();
  });
});

// ===========================================================================
// ENG-23117 — transaction atomicity & isolation: overlapping transactions get
// their own SQLite transaction (via the per-connection scheduler), schema
// mutation requires an active versionchange transaction, unhandled request
// errors abort, COMMIT failures surface as 'abort', sibling connections share
// a refcounted handle + key generator, openRequest.transaction is live during
// upgradeneeded, transaction modes are enforced, and rollback restores the
// lazy-migration memos.
// ===========================================================================

describe('ENG-23117: overlapping transaction isolation', () => {
  test('aborting the second of two overlapping readwrite txns rolls back only its own write', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'iso1', 1, (d) => d.createObjectStore('s'));

    const t1 = db.transaction('s', 'readwrite');
    const t2 = db.transaction('s', 'readwrite');
    t1.objectStore('s').put('from-t1', 'a');
    t2.objectStore('s').put('from-t2', 'b');
    const d1 = txSettled(t1);
    const d2 = txSettled(t2);
    t2.abort();
    expect(await d1).toBe('complete');
    expect(await d2).toBe('abort');

    // Pre-fix, t2's BEGIN failed silently and its put landed inside t1's
    // transaction — the aborted t2 write persisted.
    const all = await reqDone<any[]>(db.transaction('s', 'readonly').objectStore('s').getAll());
    expect(all).toEqual(['from-t1']);
    db.close();
  });

  test('aborting the first txn does not roll back the second (which fired complete)', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'iso2', 1, (d) => d.createObjectStore('s'));

    const t1 = db.transaction('s', 'readwrite');
    const t2 = db.transaction('s', 'readwrite');
    t1.objectStore('s').put('from-t1', 'a');
    t2.objectStore('s').put('from-t2', 'b');
    const d1 = txSettled(t1);
    const d2 = txSettled(t2);
    t1.abort();
    expect(await d1).toBe('abort');
    expect(await d2).toBe('complete');

    // Pre-fix, t1's ROLLBACK swept away t2's interleaved write even though t2
    // reported success.
    const all = await reqDone<any[]>(db.transaction('s', 'readonly').objectStore('s').getAll());
    expect(all).toEqual(['from-t2']);
    db.close();
  });

  test('a readonly txn queued behind a readwrite txn never sees uncommitted writes', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'iso3', 1, (d) => d.createObjectStore('s'));
    const seed = db.transaction('s', 'readwrite');
    seed.objectStore('s').put('committed', 1);
    await txDone(seed);

    // Writer adds a row then aborts; the overlapping readonly txn created
    // while the writer is live must observe only the committed state.
    const w = db.transaction('s', 'readwrite');
    w.objectStore('s').put('dirty', 2);
    const r = db.transaction('s', 'readonly');
    const countP = reqDone<number>(r.objectStore('s').count());
    const settled = txSettled(w);
    w.abort();
    await settled;
    expect(await countP).toBe(1);
    db.close();
  });

  test('a transaction created in another transaction\'s onsuccess queues and both commit', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'iso4', 1, (d) => d.createObjectStore('s'));

    const order: string[] = [];
    const t1 = db.transaction('s', 'readwrite');
    const r1 = t1.objectStore('s').put('one', 1);
    const done = new Promise<void>((resolve, reject) => {
      r1.onsuccess = () => {
        const t2 = db.transaction('s', 'readwrite');
        t2.objectStore('s').put('two', 2);
        t2.oncomplete = () => { order.push('t2'); resolve(); };
        t2.onabort = () => reject(new Error('t2 aborted'));
      };
      t1.oncomplete = () => order.push('t1');
      t1.onabort = () => reject(new Error('t1 aborted'));
    });
    await done;
    expect(order).toEqual(['t1', 't2']);
    const all = await reqDone<any[]>(db.transaction('s', 'readonly').objectStore('s').getAll());
    expect(all).toEqual(['one', 'two']);
    db.close();
  });
});

describe('ENG-23117: schema mutation requires an active versionchange txn', () => {
  test('createObjectStore/deleteObjectStore/createIndex/deleteIndex throw InvalidStateError outside upgradeneeded', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'guard1', 1, (d) => {
      const s = d.createObjectStore('s', { keyPath: 'id' });
      s.createIndex('byV', 'v');
    });
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put({ id: 1, v: 'x' });
    await txDone(wtx);

    // Pre-fix the inverted guard PASSED whenever no upgrade was running, so
    // this DROP TABLE destroyed the store's data with no transaction at all.
    expect(() => db.deleteObjectStore('s')).toThrow();
    try { db.deleteObjectStore('s'); } catch (e: any) { expect(e.name).toBe('InvalidStateError'); }
    expect(() => db.createObjectStore('t')).toThrow();
    try { db.createObjectStore('t'); } catch (e: any) { expect(e.name).toBe('InvalidStateError'); }

    const tx = db.transaction('s', 'readwrite');
    const store = tx.objectStore('s');
    try { store.createIndex('byW', 'w'); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('InvalidStateError'); }
    try { store.deleteIndex('byV'); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('InvalidStateError'); }
    tx.abort();

    // The store and its data survived every rejected mutation.
    const rec: any = await reqDone(db.transaction('s', 'readonly').objectStore('s').get(1));
    expect(rec.v).toBe('x');
    db.close();
  });
});

describe('ENG-23117: request errors abort the transaction', () => {
  test('an unhandled failing request aborts and rolls back every write', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'errabort1', 1, (d) => d.createObjectStore('s', { keyPath: 'id' }));

    const tx = db.transaction('s', 'readwrite');
    const s = tx.objectStore('s');
    s.add({ id: 1 });
    s.add({ id: 1 }); // ConstraintError — no preventDefault
    s.add({ id: 2 });
    expect(await txSettled(tx)).toBe('abort');
    expect(tx.error?.name).toBe('ConstraintError');

    // Pre-fix the transaction went on to COMMIT records 1 and 2.
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(0);
    db.close();
  });

  test('preventDefault() on the error event lets the transaction commit the other writes', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'errabort2', 1, (d) => d.createObjectStore('s', { keyPath: 'id' }));

    const tx = db.transaction('s', 'readwrite');
    const s = tx.objectStore('s');
    s.add({ id: 1 });
    const dup = s.add({ id: 1 });
    dup.onerror = (e: any) => e.preventDefault();
    s.add({ id: 2 });
    expect(await txSettled(tx)).toBe('complete');
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(2);
    db.close();
  });

  test('an exception thrown in a success handler aborts the transaction', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'errabort3', 1, (d) => d.createObjectStore('s', { keyPath: 'id' }));

    const tx = db.transaction('s', 'readwrite');
    const r = tx.objectStore('s').put({ id: 1 });
    r.onsuccess = () => { throw new Error('handler boom'); };
    expect(await txSettled(tx)).toBe('abort');
    expect(tx.error?.name).toBe('AbortError');
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(0);
    db.close();
  });
});

describe('ENG-23117: COMMIT/ROLLBACK failures surface', () => {
  test("a failed COMMIT fires 'abort' with the underlying error, not 'complete'", async () => {
    const dir = makeDir();
    const control = { failCommits: 0 };
    const provider = {
      create(name: string) {
        const real = new Database(dbPath(dir, name));
        const guard = (sql: string) => {
          if (control.failCommits > 0 && /^COMMIT\b/i.test(sql.trim())) {
            control.failCommits--;
            throw new Error('database or disk is full');
          }
        };
        return {
          query(sql: string) { return real.query(sql); },
          exec(sql: string, ...p: any[]) { guard(sql); return (real as any).exec(sql, ...p); },
          run(sql: string, ...p: any[]) { guard(sql); return (real as any).run(sql, ...p); },
          close() { return real.close(); },
        };
      },
      delete(_: string) {},
    };
    const factory = new IDBFactory(provider as any);
    const db = await openDb(factory, 'commitfail', 1, (d) => d.createObjectStore('s'));

    const tx = db.transaction('s', 'readwrite');
    tx.objectStore('s').put('v', 'k');
    control.failCommits = 1;
    // Pre-fix the COMMIT failure was swallowed and 'complete' fired — the app
    // was told its data was durable when the transaction failed.
    expect(await txSettled(tx)).toBe('abort');
    expect(String(tx.error?.message)).toContain('disk is full');

    // The write was rolled back, and the connection still works.
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(0);
    const tx2 = db.transaction('s', 'readwrite');
    tx2.objectStore('s').put('v2', 'k2');
    expect(await txSettled(tx2)).toBe('complete');
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(1);
    db.close();
  });
});

describe('ENG-23117: sibling connections', () => {
  test('close() on one connection does not brick its sibling; the key generator is shared', async () => {
    const factory = makeFactory();
    const db1 = await openDb(factory, 'sib', 1, (d) => {
      d.createObjectStore('s', { autoIncrement: true });
    });
    const db2 = await openDb(factory, 'sib', undefined);
    expect(db2.version).toBe(1);

    // Alternating adds draw from ONE generator (pre-fix each connection cached
    // its own counter and handed out colliding keys).
    const t1 = db1.transaction('s', 'readwrite');
    expect(await reqDone(t1.objectStore('s').add({}))).toBe(1);
    await txDone(t1);
    const t2 = db2.transaction('s', 'readwrite');
    expect(await reqDone(t2.objectStore('s').add({}))).toBe(2);
    await txDone(t2);
    const t3 = db1.transaction('s', 'readwrite');
    expect(await reqDone(t3.objectStore('s').add({}))).toBe(3);
    await txDone(t3);

    // Pre-fix db1.close() closed the SHARED handle and every db2 op threw.
    db1.close();
    const t4 = db2.transaction('s', 'readwrite');
    expect(await reqDone(t4.objectStore('s').add({}))).toBe(4);
    await txDone(t4);
    expect(await reqDone<number>(db2.transaction('s', 'readonly').objectStore('s').count())).toBe(4);
    db2.close();

    // With both connections closed the handle really is released: a fresh
    // open() works from disk.
    const db3 = await openDb(factory, 'sib', undefined);
    expect(await reqDone<number>(db3.transaction('s', 'readonly').objectStore('s').count())).toBe(4);
    db3.close();
  });
});

describe('ENG-23117: upgrade transaction wiring', () => {
  test('e.target.transaction works during upgradeneeded (canonical add-index migration)', async () => {
    const factory = makeFactory();
    const db1 = await openDb(factory, 'upg1', 1, (d) => {
      d.createObjectStore('users', { keyPath: 'id' });
    });
    const seed = db1.transaction('users', 'readwrite');
    seed.objectStore('users').put({ id: 1, email: 'a@x.com' });
    await txDone(seed);
    db1.close();

    // The MDN-standard migration idiom: reach the store through the OPEN
    // REQUEST's transaction. Pre-fix request.transaction was null and this
    // threw, rolling back the whole upgrade.
    let sawTxn: any = null;
    const db2 = await new Promise<any>((resolve, reject) => {
      const req = factory.open('upg1', 2);
      req.onupgradeneeded = (e: any) => {
        sawTxn = e.target.transaction;
        expect(e.target.transaction).toBe(e.transaction);
        const store = e.target.transaction.objectStore('users');
        store.createIndex('byEmail', 'email');
        // A store created mid-upgrade joins the transaction's scope.
        e.target.result.createObjectStore('logs');
        expect(() => e.target.transaction.objectStore('logs')).not.toThrow();
      };
      req.onsuccess = () => {
        // Outside upgradeneeded the open request's transaction is null again.
        expect(req.transaction).toBeNull();
        resolve(req.result);
      };
      req.onerror = () => reject(req.error);
    });
    expect(sawTxn).not.toBeNull();

    // The index created through the request transaction is live and backfilled.
    const rec: any = await reqDone(
      db2.transaction('users', 'readonly').objectStore('users').index('byEmail').get('a@x.com'),
    );
    expect(rec.id).toBe(1);
    expect(db2.objectStoreNames.contains('logs')).toBe(true);
    db2.close();
  });
});

describe('ENG-23117: transaction mode enforcement', () => {
  test('mutating operations on a readonly transaction throw ReadOnlyError', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'mode1', 1, (d) => d.createObjectStore('s'));
    const seed = db.transaction('s', 'readwrite');
    seed.objectStore('s').put('v', 'k');
    await txDone(seed);

    const ro = db.transaction('s', 'readonly');
    const store = ro.objectStore('s');
    for (const op of [
      () => store.put('x', 'k2'),
      () => store.add('x', 'k3'),
      () => store.delete('k'),
      () => store.clear(),
    ]) {
      try { op(); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('ReadOnlyError'); }
    }
    // cursor.update/delete are gated too (checked inside the cursor's success
    // handler, while the transaction is still active).
    const cursorErrs = await new Promise<string[]>((resolve, reject) => {
      const names: string[] = [];
      const req = store.openCursor();
      req.onsuccess = () => {
        const cur = req.result;
        try { cur.update('y'); } catch (e: any) { names.push(e.name); }
        try { cur.delete(); } catch (e: any) { names.push(e.name); }
        resolve(names);
      };
      req.onerror = () => reject(req.error);
    });
    expect(cursorErrs).toEqual(['ReadOnlyError', 'ReadOnlyError']);

    // Nothing was written; pre-fix the readonly put auto-committed instantly.
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(1);
    db.close();
  });

  test("db.transaction rejects 'versionchange' and junk modes with TypeError", async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'mode2', 1, (d) => d.createObjectStore('s'));
    expect(() => db.transaction('s', 'versionchange' as any)).toThrow(TypeError);
    expect(() => db.transaction('s', 'readwriteflush' as any)).toThrow(TypeError);
    db.close();
  });
});

describe('ENG-23117: rollback restores lazy-migration state', () => {
  test('aborting the txn that lazily created the index table lets later txns rebuild it', async () => {
    const dir = makeDir();
    const name = 'rollback-idx';
    // Pre-ENG-23016 shape: index metadata but no companion table/marker.
    const raw = new Database(dbPath(dir, name));
    raw.run(`CREATE TABLE _idb_meta (key TEXT PRIMARY KEY, value TEXT)`);
    raw.run(`INSERT INTO _idb_meta(key, value) VALUES ('version', '1')`);
    raw.run(`CREATE TABLE _idb_stores (store_name TEXT PRIMARY KEY, key_path TEXT, auto_increment INTEGER DEFAULT 0)`);
    raw.run(`INSERT INTO _idb_stores(store_name, key_path, auto_increment) VALUES ('s', '"id"', 0)`);
    raw.run(`CREATE TABLE _idb_indexes (store_name TEXT, index_name TEXT, key_path TEXT, unique_flag INTEGER DEFAULT 0, multi_entry INTEGER DEFAULT 0, PRIMARY KEY (store_name, index_name))`);
    raw.run(`INSERT INTO _idb_indexes(store_name, index_name, key_path, unique_flag, multi_entry) VALUES ('s', 'byV', '"v"', 0, 0)`);
    raw.run(`CREATE TABLE "idb_store_s" (key TEXT PRIMARY KEY, value TEXT, keyenc TEXT)`);
    for (let i = 1; i <= 3; i++) {
      raw.run(
        `INSERT INTO "idb_store_s" (key, value, keyenc) VALUES (?, ?, ?)`,
        serializeKey(i),
        serializeValue({ id: i, v: `v${i}` }),
        encodeOrderedKey(i),
      );
    }
    raw.close();

    const factory = new IDBFactory(makeProvider(dir) as any);
    const db = await openDb(factory, name, undefined);

    // This readwrite txn's put() lazily CREATEs + backfills the index table
    // inside its BEGIN; abort() rolls that DDL back. Pre-fix the ready-memo
    // survived the rollback, so every later index read hit "no such table".
    const tx1 = db.transaction('s', 'readwrite');
    tx1.objectStore('s').put({ id: 4, v: 'v4' });
    const settled = txSettled(tx1);
    tx1.abort();
    expect(await settled).toBe('abort');

    const keys = await reqDone<any[]>(
      db.transaction('s', 'readonly').objectStore('s').index('byV').getAllKeys(),
    );
    expect(keys).toEqual([1, 2, 3]);

    // Writes keep working (index maintenance re-created the table).
    const tx2 = db.transaction('s', 'readwrite');
    tx2.objectStore('s').put({ id: 5, v: 'v5' });
    expect(await txSettled(tx2)).toBe('complete');
    expect(await reqDone<any[]>(
      db.transaction('s', 'readonly').objectStore('s').index('byV').getAllKeys('v5'),
    )).toEqual([5]);
    db.close();
  });

  test('aborting the txn that lazily ALTERed keyenc onto a legacy store recovers', async () => {
    const dir = makeDir();
    const name = 'rollback-keyenc';
    // Pre-ENG-22999 shape: (key, value) only, no keyenc column.
    const raw = new Database(dbPath(dir, name));
    raw.run(`CREATE TABLE _idb_meta (key TEXT PRIMARY KEY, value TEXT)`);
    raw.run(`INSERT INTO _idb_meta(key, value) VALUES ('version', '1')`);
    raw.run(`CREATE TABLE _idb_stores (store_name TEXT PRIMARY KEY, key_path TEXT, auto_increment INTEGER DEFAULT 0)`);
    raw.run(`INSERT INTO _idb_stores(store_name, key_path, auto_increment) VALUES ('s', 'null', 0)`);
    raw.run(`CREATE TABLE _idb_indexes (store_name TEXT, index_name TEXT, key_path TEXT, unique_flag INTEGER DEFAULT 0, multi_entry INTEGER DEFAULT 0, PRIMARY KEY (store_name, index_name))`);
    raw.run(`CREATE TABLE "idb_store_s" (key TEXT PRIMARY KEY, value TEXT)`);
    for (let i = 1; i <= 3; i++) {
      raw.run(`INSERT INTO "idb_store_s" (key, value) VALUES (?, ?)`, serializeKey(i), serializeValue(`v${i}`));
    }
    raw.close();

    const factory = new IDBFactory(makeProvider(dir) as any);
    const db = await openDb(factory, name, undefined);

    // First touch happens inside an aborted readwrite txn: the ALTER TABLE ...
    // ADD COLUMN keyenc rolls back with it. Pre-fix the memo said the column
    // existed, and every later read failed with "no such column: keyenc".
    const tx1 = db.transaction('s', 'readwrite');
    tx1.objectStore('s').put('v9', 9);
    const settled = txSettled(tx1);
    tx1.abort();
    expect(await settled).toBe('abort');

    expect(await reqDone<any[]>(
      db.transaction('s', 'readonly').objectStore('s').getAll(IDBKeyRange.bound(1, 2)),
    )).toEqual(['v1', 'v2']);
    const tx2 = db.transaction('s', 'readwrite');
    tx2.objectStore('s').put('v4', 4);
    expect(await txSettled(tx2)).toBe('complete');
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(4);
    db.close();
  });

  test('abort reverts the autoIncrement key generator (per spec)', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'rollback-ai', 1, (d) => {
      d.createObjectStore('s', { autoIncrement: true });
    });

    const tx1 = db.transaction('s', 'readwrite');
    const s1 = tx1.objectStore('s');
    s1.add({});
    s1.add({});
    const r3 = s1.add({});
    const settled = txSettled(tx1);
    tx1.abort();
    expect(await settled).toBe('abort');
    void r3;

    // The generator reverts to its pre-transaction state, so the next add()
    // hands out 1 again, not 4.
    const tx2 = db.transaction('s', 'readwrite');
    expect(await reqDone(tx2.objectStore('s').add({}))).toBe(1);
    await txDone(tx2);
    db.close();
  });
});

// ===========================================================================
// ENG-23134 — data correctness & cursors: binary key canonicalization,
// collision-free store table names, Blob/File/Error value fidelity, live
// streaming index cursors (direction ordering + unique dedupe), key
// validation, and cursor/put argument validation.
// ===========================================================================

describe('ENG-23134: binary key canonicalization', () => {
  test('a typed-array view key and an ArrayBuffer of the same bytes are the same key', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'bin1', 1, (d) => d.createObjectStore('s'));

    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put('v', new Uint8Array([1, 2]));
    await txDone(wtx);

    // get() with a bare ArrayBuffer of the same bytes finds the record
    // (pre-fix: undefined — views and buffers serialized under different tags).
    const buf = Uint8Array.from([1, 2]).buffer;
    expect(await reqDone(db.transaction('s', 'readonly').objectStore('s').get(buf))).toBe('v');

    // add() with the buffer twin is a ConstraintError, not a duplicate row.
    const atx = db.transaction('s', 'readwrite');
    const dup = atx.objectStore('s').add('w', buf);
    dup.onerror = (e: any) => e.preventDefault();
    expect(await txSettled(atx)).toBe('complete');
    expect(dup.error?.name).toBe('ConstraintError');
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(1);

    // Binary keys come back in canonical ArrayBuffer form.
    const keys = await reqDone<any[]>(db.transaction('s', 'readonly').objectStore('s').getAllKeys());
    expect(keys.length).toBe(1);
    expect(keys[0]).toBeInstanceOf(ArrayBuffer);
    expect(Array.from(new Uint8Array(keys[0]))).toEqual([1, 2]);
    const gotKey = await reqDone<any>(db.transaction('s', 'readonly').objectStore('s').getKey(new Uint8Array([1, 2])));
    expect(gotKey).toBeInstanceOf(ArrayBuffer);

    // delete() through a DataView twin removes the record.
    const dtx = db.transaction('s', 'readwrite');
    dtx.objectStore('s').delete(new DataView(Uint8Array.from([1, 2]).buffer));
    await txDone(dtx);
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(0);
    db.close();
  });

  test('array keys containing views match their buffer twins', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'bin2', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put('v', [1, new Uint8Array([7])]);
    await txDone(wtx);
    expect(await reqDone(
      db.transaction('s', 'readonly').objectStore('s').get([1, Uint8Array.from([7]).buffer]),
    )).toBe('v');
    db.close();
  });
});

describe('ENG-23134: collision-free store table names', () => {
  test('stores whose names collide under the old sanitizer are isolated', async () => {
    const factory = makeFactory();
    const names = ['user-data', 'user_data', 'Settings', 'settings'];
    const db = await openDb(factory, 'names1', 1, (d) => {
      for (const n of names) d.createObjectStore(n);
    });

    const wtx = db.transaction(names, 'readwrite');
    for (const n of names) wtx.objectStore(n).put(`from ${n}`, 'k');
    await txDone(wtx);

    // Pre-fix "user-data"/"user_data" (and, case-insensitively, "Settings"/
    // "settings") shared one SQLite table: writes merged and reads leaked
    // across stores.
    for (const n of names) {
      const tx = db.transaction(n, 'readonly');
      expect(await reqDone<any[]>(tx.objectStore(n).getAll())).toEqual([`from ${n}`]);
    }
    db.close();

    // Deleting one of the twins must not destroy the other's data
    // (pre-fix: DROP TABLE on the shared table).
    const db2 = await openDb(factory, 'names1', 2, (d) => {
      d.deleteObjectStore('user-data');
      d.deleteObjectStore('Settings');
    });
    expect(await reqDone<any[]>(db2.transaction('user_data', 'readonly').objectStore('user_data').getAll()))
      .toEqual(['from user_data']);
    expect(await reqDone<any[]>(db2.transaction('settings', 'readonly').objectStore('settings').getAll()))
      .toEqual(['from settings']);
    db2.close();
  });

  test('a legacy database with old-sanitizer table names is migrated on first access', async () => {
    const dir = makeDir();
    const name = 'legacy-names';
    // Old builds stored store "user-data" in table idb_store_user_data.
    const raw = new Database(dbPath(dir, name));
    raw.run(`CREATE TABLE _idb_meta (key TEXT PRIMARY KEY, value TEXT)`);
    raw.run(`INSERT INTO _idb_meta(key, value) VALUES ('version', '1')`);
    raw.run(`CREATE TABLE _idb_stores (store_name TEXT PRIMARY KEY, key_path TEXT, auto_increment INTEGER DEFAULT 0)`);
    raw.run(`INSERT INTO _idb_stores(store_name, key_path, auto_increment) VALUES ('user-data', 'null', 0)`);
    raw.run(`CREATE TABLE _idb_indexes (store_name TEXT, index_name TEXT, key_path TEXT, unique_flag INTEGER DEFAULT 0, multi_entry INTEGER DEFAULT 0, PRIMARY KEY (store_name, index_name))`);
    raw.run(`CREATE TABLE "idb_store_user_data" (key TEXT PRIMARY KEY, value TEXT, keyenc TEXT)`);
    for (let i = 1; i <= 3; i++) {
      raw.run(
        `INSERT INTO "idb_store_user_data" (key, value, keyenc) VALUES (?, ?, ?)`,
        serializeKey(i), serializeValue(`v${i}`), encodeOrderedKey(i),
      );
    }
    raw.close();

    const factory = new IDBFactory(makeProvider(dir) as any);
    const db = await openDb(factory, name, undefined);
    // First access renames the legacy table to the collision-free name.
    expect(await reqDone<any[]>(db.transaction('user-data', 'readonly').objectStore('user-data').getAll()))
      .toEqual(['v1', 'v2', 'v3']);
    const wtx = db.transaction('user-data', 'readwrite');
    wtx.objectStore('user-data').put('v4', 4);
    await txDone(wtx);
    db.close();

    // Data survives reopen (the rename persisted).
    const db2 = await openDb(factory, name, undefined);
    expect(await reqDone<number>(db2.transaction('user-data', 'readonly').objectStore('user-data').count())).toBe(4);
    db2.close();
  });

  test('a legacy table already claimed by a safe-named twin store is not stolen', async () => {
    const dir = makeDir();
    const name = 'legacy-claimed';
    // Both "user-data" and "user_data" exist; under the old sanitizer they
    // (ambiguously) shared idb_store_user_data — which is still the CURRENT
    // table of "user_data". The migration must leave it with "user_data".
    const raw = new Database(dbPath(dir, name));
    raw.run(`CREATE TABLE _idb_meta (key TEXT PRIMARY KEY, value TEXT)`);
    raw.run(`INSERT INTO _idb_meta(key, value) VALUES ('version', '1')`);
    raw.run(`CREATE TABLE _idb_stores (store_name TEXT PRIMARY KEY, key_path TEXT, auto_increment INTEGER DEFAULT 0)`);
    raw.run(`INSERT INTO _idb_stores(store_name, key_path, auto_increment) VALUES ('user-data', 'null', 0)`);
    raw.run(`INSERT INTO _idb_stores(store_name, key_path, auto_increment) VALUES ('user_data', 'null', 0)`);
    raw.run(`CREATE TABLE _idb_indexes (store_name TEXT, index_name TEXT, key_path TEXT, unique_flag INTEGER DEFAULT 0, multi_entry INTEGER DEFAULT 0, PRIMARY KEY (store_name, index_name))`);
    raw.run(`CREATE TABLE "idb_store_user_data" (key TEXT PRIMARY KEY, value TEXT, keyenc TEXT)`);
    raw.run(
      `INSERT INTO "idb_store_user_data" (key, value, keyenc) VALUES (?, ?, ?)`,
      serializeKey(1), serializeValue('merged'), encodeOrderedKey(1),
    );
    raw.close();

    const factory = new IDBFactory(makeProvider(dir) as any);
    const db = await openDb(factory, name, undefined);
    expect(await reqDone<any[]>(db.transaction('user_data', 'readonly').objectStore('user_data').getAll()))
      .toEqual(['merged']);
    // "user-data" starts from a fresh (empty) table instead of stealing it.
    expect(await reqDone<any[]>(db.transaction('user-data', 'readonly').objectStore('user-data').getAll()))
      .toEqual([]);
    db.close();
  });
});

describe('ENG-23134: structured-clone value fidelity', () => {
  test('ENG-24277: put() and add() snapshot values synchronously at call time', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'vals-call-time-snapshot', 1, (d) =>
      d.createObjectStore('s'));
    const putValue = {
      label: 'put-before',
      nested: { count: 1 },
      bytes: new Uint8Array([1, 2, 3]),
    };
    const addValue = {
      label: 'add-before',
      nested: { count: 2 },
      bytes: new Uint8Array([4, 5, 6]),
    };
    const tx = db.transaction('s', 'readwrite');
    const store = tx.objectStore('s');
    const putRequest = store.put(putValue, 'put');
    const addRequest = store.add(addValue, 'add');
    const putDone = reqDone(putRequest);
    const addDone = reqDone(addRequest);
    const transactionDone = txDone(tx);

    // Mutate both ordinary objects and their backing buffers before the
    // transaction gets a chance to execute either queued request.
    putValue.label = 'put-after';
    putValue.nested.count = 10;
    putValue.bytes.fill(9);
    addValue.label = 'add-after';
    addValue.nested.count = 20;
    addValue.bytes.fill(8);

    expect(await putDone).toBe('put');
    expect(await addDone).toBe('add');
    await transactionDone;

    const read = db.transaction('s', 'readonly').objectStore('s');
    const [storedPut, storedAdd]: any[] = await Promise.all([
      reqDone(read.get('put')),
      reqDone(read.get('add')),
    ]);
    expect(storedPut).toEqual({
      label: 'put-before',
      nested: { count: 1 },
      bytes: new Uint8Array([1, 2, 3]),
    });
    expect(storedAdd).toEqual({
      label: 'add-before',
      nested: { count: 2 },
      bytes: new Uint8Array([4, 5, 6]),
    });
    db.close();
  });

  test('Blob and File round-trip through put/get', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'vals1', 1, (d) => d.createObjectStore('s'));

    const blob = new IbexBlob([new Uint8Array([1, 2, 3])], { type: 'image/png' });
    const file = new IbexFile([new Uint8Array([9, 8])], 'shot.jpg', { type: 'image/jpeg', lastModified: 123456 });
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put({ img: blob, f: file }, 'k');
    expect(await txSettled(wtx)).toBe('complete');

    const out: any = await reqDone(db.transaction('s', 'readonly').objectStore('s').get('k'));
    // Pre-fix both stored as {} — the payload silently vanished. Values are
    // reconstructed with the environment's Blob/File constructors.
    expect(out.img).toBeInstanceOf((globalThis as any).Blob);
    expect(out.img.type).toBe('image/png');
    expect(Array.from(new Uint8Array(await out.img.arrayBuffer()))).toEqual([1, 2, 3]);
    expect(out.f).toBeInstanceOf((globalThis as any).File);
    expect(out.f.name).toBe('shot.jpg');
    expect(out.f.lastModified).toBe(123456);
    expect(Array.from(new Uint8Array(await out.f.arrayBuffer()))).toEqual([9, 8]);
    db.close();
  });

  test('Error values round-trip with name/message/stack/cause', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'vals2', 1, (d) => d.createObjectStore('s'));
    const err = new TypeError('bad thing');
    (err as any).cause = new Error('root');
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put({ e: err }, 'k');
    await txDone(wtx);
    const out: any = await reqDone(db.transaction('s', 'readonly').objectStore('s').get('k'));
    expect(out.e).toBeInstanceOf(TypeError);
    expect(out.e.name).toBe('TypeError');
    expect(out.e.message).toBe('bad thing');
    expect(typeof out.e.stack).toBe('string');
    expect(out.e.cause).toBeInstanceOf(Error);
    expect(out.e.cause.message).toBe('root');
    db.close();
  });

  test('boxed primitives round-trip as objects', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'vals3', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put({ n: new Number(42), s: new String('x'), b: new Boolean(false) }, 'k');
    await txDone(wtx);
    const out: any = await reqDone(db.transaction('s', 'readonly').objectStore('s').get('k'));
    expect(typeof out.n).toBe('object');
    expect(out.n.valueOf()).toBe(42);
    expect(typeof out.s).toBe('object');
    expect(out.s.valueOf()).toBe('x');
    expect(typeof out.b).toBe('object');
    expect(out.b.valueOf()).toBe(false);
    db.close();
  });

  test('non-cloneable values throw DataCloneError synchronously instead of storing {}', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'vals4', 1, (d) => d.createObjectStore('s'));

    // A function value.
    const t1 = db.transaction('s', 'readwrite');
    expect(() => t1.objectStore('s').put({ fn: () => 1 }, 'k1')).toThrow(
      expect.objectContaining({ name: 'DataCloneError' }),
    );
    expect(await txSettled(t1)).toBe('complete');

    // A host Blob with no synchronous byte access (bun's native Blob).
    const t2 = db.transaction('s', 'readwrite');
    expect(() =>
      t2.objectStore('s').put({ b: new (globalThis as any).Blob(['x']) }, 'k2'),
    ).toThrow(expect.objectContaining({ name: 'DataCloneError' }));
    expect(await txSettled(t2)).toBe('complete');

    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(0);
    db.close();
  });
});

describe('ENG-23134: live streaming index cursors', () => {
  test('records deleted mid-iteration are skipped and inserted ones visited (across batches)', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'live1', 1, (d) => {
      const s = d.createObjectStore('s', { keyPath: 'id' });
      s.createIndex('byV', 'v');
    });
    const wtx = db.transaction('s', 'readwrite');
    for (let i = 0; i < 200; i++) wtx.objectStore('s').put({ id: i, v: i });
    await txDone(wtx);

    // Iterate the index inside a readwrite txn; on the FIRST record, delete a
    // record ahead (v=150, in the second batch) and insert one ahead
    // (v=140.5). Pre-fix the cursor iterated a snapshot: the deleted record
    // was still delivered and the inserted one never visited.
    const seen = await new Promise<any[]>((resolve, reject) => {
      const acc: any[] = [];
      const tx = db.transaction('s', 'readwrite');
      const store = tx.objectStore('s');
      const req = store.index('byV').openCursor();
      let first = true;
      req.onsuccess = () => {
        const cur = req.result;
        if (!cur) return resolve(acc);
        if (first) {
          first = false;
          store.delete(150);
          store.put({ id: 500, v: 140.5 });
        }
        acc.push(cur.key);
        cur.continue();
      };
      req.onerror = () => reject(req.error);
    });
    expect(seen.length).toBe(200); // 200 - deleted + inserted
    expect(seen).not.toContain(150);
    expect(seen).toContain(140.5);
    // Still in index-key order.
    expect(seen.indexOf(140.5)).toBe(seen.indexOf(141) - 1);
    db.close();
  });

  test('prev direction visits duplicate-key records in descending primary-key order', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'live2', 1, (d) => {
      const s = d.createObjectStore('s', { keyPath: 'id' });
      s.createIndex('byAge', 'age');
    });
    const wtx = db.transaction('s', 'readwrite');
    const ws = wtx.objectStore('s');
    ws.put({ id: 1, age: 30 });
    ws.put({ id: 2, age: 20 });
    ws.put({ id: 5, age: 20 });
    ws.put({ id: 9, age: 20 });
    await txDone(wtx);

    const pks = await new Promise<any[]>((resolve, reject) => {
      const acc: any[] = [];
      const req = db.transaction('s', 'readonly').objectStore('s').index('byAge').openCursor(null, 'prev');
      req.onsuccess = () => {
        const cur = req.result;
        if (!cur) return resolve(acc);
        acc.push(cur.primaryKey);
        cur.continue();
      };
      req.onerror = () => reject(req.error);
    });
    // Spec: descending index key, and DESCENDING primary key within a
    // duplicate-key group (pre-fix: ascending — 2, 5, 9).
    expect(pks).toEqual([1, 9, 5, 2]);
    db.close();
  });

  test('nextunique/prevunique visit each key once with the lowest primary key, including binary keys', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'live3', 1, (d) => {
      const s = d.createObjectStore('s', { keyPath: 'id' });
      s.createIndex('byHash', 'hash');
    });
    const hashA = new Uint8Array([0xaa, 0x01]);
    const hashB = new Uint8Array([0xbb, 0x02]);
    const wtx = db.transaction('s', 'readwrite');
    const ws = wtx.objectStore('s');
    ws.put({ id: 2, hash: hashA });
    ws.put({ id: 1, hash: hashA });
    ws.put({ id: 3, hash: hashB });
    await txDone(wtx);

    const collect = (dir: any) => new Promise<any[]>((resolve, reject) => {
      const acc: any[] = [];
      const req = db.transaction('s', 'readonly').objectStore('s').index('byHash').openCursor(null, dir);
      req.onsuccess = () => {
        const cur = req.result;
        if (!cur) return resolve(acc);
        acc.push([Array.from(new Uint8Array(cur.key)), cur.primaryKey]);
        cur.continue();
      };
      req.onerror = () => reject(req.error);
    });

    // Pre-fix the JSON.stringify dedupe stringified every binary key to '{}',
    // collapsing all key groups into one.
    expect(await collect('nextunique')).toEqual([
      [[0xaa, 0x01], 1],
      [[0xbb, 0x02], 3],
    ]);
    // prevunique iterates keys descending but still yields each group's
    // LOWEST primary key (spec).
    expect(await collect('prevunique')).toEqual([
      [[0xbb, 0x02], 3],
      [[0xaa, 0x01], 1],
    ]);
    db.close();
  });
});

describe('ENG-23134: key validation', () => {
  test('index.get/getKey with undefined or invalid keys throw DataError', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'keyval1', 1, (d) => {
      const s = d.createObjectStore('users', { keyPath: 'id' });
      s.createIndex('byEmail', 'email');
    });
    const wtx = db.transaction('users', 'readwrite');
    wtx.objectStore('users').put({ id: 1, email: 'a@x.com' });
    await txDone(wtx);

    const tx = db.transaction('users', 'readonly');
    const idx = tx.objectStore('users').index('byEmail');
    // Pre-fix index.get(undefined) returned the FIRST record — the wrong user.
    for (const bad of [undefined, null, true, {}]) {
      try { idx.get(bad); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('DataError'); }
      try { idx.getKey(bad); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('DataError'); }
    }
    // getAll/count keep the "undefined means everything" behavior.
    expect(await reqDone<number>(tx.objectStore('users').index('byEmail').count())).toBe(1);
    db.close();
  });

  test('store get/getKey/delete with invalid keys throw DataError', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'keyval2', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put('v', 'k');
    await txDone(wtx);

    const tx = db.transaction('s', 'readwrite');
    const store = tx.objectStore('s');
    for (const bad of [undefined, null, true, {}]) {
      try { store.get(bad); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('DataError'); }
      try { store.getKey(bad); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('DataError'); }
      try { store.delete(bad); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('DataError'); }
    }
    tx.abort();
    db.close();
  });
});

describe('ENG-23134: cursor and put argument validation', () => {
  test('advance() without a positive integer throws TypeError', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'curval1', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    for (let i = 0; i < 3; i++) wtx.objectStore('s').put(`v${i}`, i);
    await txDone(wtx);

    const errs = await new Promise<string[]>((resolve, reject) => {
      const names: string[] = [];
      const req = db.transaction('s', 'readonly').objectStore('s').openCursor();
      req.onsuccess = () => {
        const cur = req.result;
        // Pre-fix advance() slid the position to NaN and silently ended the cursor.
        for (const bad of [undefined, 0, -1, 1.5, '2']) {
          try { cur.advance(bad as any); names.push('no-throw'); } catch (e: any) { names.push(e.constructor.name); }
        }
        resolve(names);
      };
      req.onerror = () => reject(req.error);
    });
    expect(errs).toEqual(['TypeError', 'TypeError', 'TypeError', 'TypeError', 'TypeError']);
    db.close();
  });

  test('continue(key) at or behind the position throws DataError', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'curval2', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    for (let i = 0; i < 10; i++) wtx.objectStore('s').put(`v${i}`, i);
    await txDone(wtx);

    const out = await new Promise<any>((resolve, reject) => {
      const req = db.transaction('s', 'readonly').objectStore('s').openCursor(IDBKeyRange.lowerBound(5));
      let checked = false;
      req.onsuccess = () => {
        const cur = req.result;
        if (!cur) return resolve('ended');
        if (!checked) {
          checked = true;
          expect(cur.key).toBe(5);
          // Same key and an earlier key both violate iteration order.
          try { cur.continue(5); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('DataError'); }
          try { cur.continue(3); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('DataError'); }
          try { cur.continue(false); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('DataError'); }
          cur.continue(8); // forward is fine
          return;
        }
        resolve(cur.key);
      };
      req.onerror = () => reject(req.error);
    });
    expect(out).toBe(8);
    db.close();
  });

  test('update/delete on a key cursor throw InvalidStateError', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'curval3', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put('v', 1);
    await txDone(wtx);

    const names = await new Promise<string[]>((resolve, reject) => {
      const acc: string[] = [];
      const tx = db.transaction('s', 'readwrite');
      const req = tx.objectStore('s').openKeyCursor();
      req.onsuccess = () => {
        const cur = req.result;
        try { cur.update('x'); acc.push('no-throw'); } catch (e: any) { acc.push(e.name); }
        try { cur.delete(); acc.push('no-throw'); } catch (e: any) { acc.push(e.name); }
        resolve(acc);
      };
      req.onerror = () => reject(req.error);
    });
    expect(names).toEqual(['InvalidStateError', 'InvalidStateError']);
    // The record survived both attempts.
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(1);
    db.close();
  });

  test('cursor.update with a mismatched inline key throws DataError', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'curval4', 1, (d) => d.createObjectStore('s', { keyPath: 'id' }));
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put({ id: 1, v: 'a' });
    await txDone(wtx);

    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('s', 'readwrite');
      const req = tx.objectStore('s').openCursor();
      req.onsuccess = () => {
        const cur = req.result;
        // Pre-fix this silently re-keyed the record to id 2.
        try { cur.update({ id: 2, v: 'hijack' }); reject(new Error('should throw')); return; } catch (e: any) { expect(e.name).toBe('DataError'); }
        try { cur.update({ v: 'no-key' }); reject(new Error('should throw')); return; } catch (e: any) { expect(e.name).toBe('DataError'); }
        cur.update({ id: 1, v: 'b' }); // matching key is fine
        resolve();
      };
      req.onerror = () => reject(req.error);
    });
    const rec: any = await reqDone(db.transaction('s', 'readonly').objectStore('s').get(1));
    expect(rec.v).toBe('b');
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(1);
    db.close();
  });

  test('put/add with an explicit key on a keyPath store throw DataError', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'curval5', 1, (d) => d.createObjectStore('s', { keyPath: 'id' }));
    const tx = db.transaction('s', 'readwrite');
    const store = tx.objectStore('s');
    try { store.put({ id: 1 }, 99); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('DataError'); }
    try { store.add({ id: 1 }, 99); expect(false).toBe(true); } catch (e: any) { expect(e.name).toBe('DataError'); }
    store.put({ id: 1 }); // in-line key still works
    await txDone(tx);
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(1);
    db.close();
  });
});

describe('ENG-23134: failed upgrades do not leak SQLite handles', () => {
  test('every handle opened by a failed upgrade is closed before rejecting', async () => {
    const dir = makeDir();
    const counts = { creates: 0, closes: 0 };
    const provider = {
      create(name: string) {
        counts.creates++;
        const real = new Database(dbPath(dir, name));
        return {
          query(sql: string) { return real.query(sql); },
          exec(sql: string, ...p: any[]) { return (real as any).exec(sql, ...p); },
          run(sql: string, ...p: any[]) { return (real as any).run(sql, ...p); },
          close() { counts.closes++; return real.close(); },
        };
      },
      delete(_: string) {},
    };
    const factory = new IDBFactory(provider as any);

    // Three failed upgrade attempts (the retry-loop pattern from the finding).
    for (let i = 0; i < 3; i++) {
      let err: any;
      try {
        await openDb(factory, 'leak', 1, () => { throw new Error('upgrade boom'); });
      } catch (e) { err = e; }
      expect(err).toBeDefined();
    }
    // Pre-fix each attempt leaked one live handle (+ WAL locks).
    expect(counts.creates).toBe(3);
    expect(counts.closes).toBe(3);

    // A subsequent successful open works from a fresh handle.
    const db = await openDb(factory, 'leak', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put('v', 'k');
    await txDone(wtx);
    expect(await reqDone(db.transaction('s', 'readonly').objectStore('s').get('k'))).toBe('v');
    db.close();
    // The read transaction commits when control returns to the event loop
    // (spec lifecycle, ENG-23446); the handle refcount-closes after that.
    await flush();
    expect(counts.closes).toBe(4);
  });
});

// ===========================================================================
// ENG-23446 — transaction/connection lifecycle & API-contract fixes.
// ===========================================================================

describe('ENG-23446: await-chained transactions (idb/Dexie pattern)', () => {
  test('a transaction stays active across awaited request continuations', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'aw1', 1, (d) => d.createObjectStore('s'));

    const tx = db.transaction('s', 'readwrite');
    const store = tx.objectStore('s');
    // Pre-fix the transaction auto-committed at the microtask boundary of the
    // first request's dispatch, so the second put threw
    // TransactionInactiveError. This is the exact idb/Dexie usage shape.
    expect(await reqDone(store.put('a', 'k1'))).toBe('k1');
    expect(await reqDone(store.put('b', 'k2'))).toBe('k2');
    // Read-your-writes inside the same transaction, after awaits.
    expect(await reqDone(store.get('k1'))).toBe('a');
    expect(await reqDone(store.put('c', 'k3'))).toBe('k3');
    expect(await txSettled(tx)).toBe('complete');

    const out = await reqDone(db.transaction('s', 'readonly').objectStore('s').getAll());
    expect(out).toEqual(['a', 'b', 'c']);
    db.close();
  });

  test('plain microtask gaps (await Promise.resolve()) do not deactivate the transaction', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'aw2', 1, (d) => d.createObjectStore('s'));
    const tx = db.transaction('s', 'readwrite');
    tx.objectStore('s').put('a', 'k1');
    await Promise.resolve();
    await Promise.resolve();
    tx.objectStore('s').put('b', 'k2');
    expect(await txSettled(tx)).toBe('complete');
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(2);
    db.close();
  });

  test('awaited cursor iteration works across continuations', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'aw3', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    for (let i = 0; i < 5; i++) wtx.objectStore('s').put(`v${i}`, `k${i}`);
    await txDone(wtx);

    // The common promisified-cursor loop: each iteration awaits the request,
    // then calls continue() from the continuation.
    const tx = db.transaction('s', 'readonly');
    const req = tx.objectStore('s').openCursor();
    const seen: string[] = [];
    let cursor: any = await reqDone(req);
    while (cursor) {
      seen.push(cursor.value);
      cursor.continue();
      cursor = await reqDone(req);
    }
    expect(seen).toEqual(['v0', 'v1', 'v2', 'v3', 'v4']);
    db.close();
  });

  test('a real task boundary still deactivates and auto-commits the transaction', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'aw4', 1, (d) => d.createObjectStore('s'));
    const tx = db.transaction('s', 'readwrite');
    const store = tx.objectStore('s');
    store.put('a', 'k1');
    await flush(); // setTimeout(0): control returned to the event loop
    let err: any;
    try {
      store.put('b', 'k2');
    } catch (e) { err = e; }
    expect(err?.name).toBe('TransactionInactiveError');
    // And objectStore() on the finished transaction is an InvalidStateError.
    let err2: any;
    try { tx.objectStore('s'); } catch (e) { err2 = e; }
    expect(err2?.name).toBe('InvalidStateError');
    // The first write committed.
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(1);
    db.close();
  });

  test('commit() refuses subsequent requests and commits the accepted ones', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'aw5', 1, (d) => d.createObjectStore('s'));
    const tx = db.transaction('s', 'readwrite');
    tx.objectStore('s').put('a', 'k1');
    tx.commit();
    let err: any;
    try { tx.objectStore('s').put('b', 'k2'); } catch (e) { err = e; }
    expect(err?.name).toBe('TransactionInactiveError');
    expect(await txSettled(tx)).toBe('complete');
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(1);
    db.close();
  });

  test('await-chained requests during upgradeneeded stay in the versionchange transaction', async () => {
    const factory = makeFactory();
    const db = await new Promise<any>((resolve, reject) => {
      const req = factory.open('aw6', 1);
      req.onupgradeneeded = async (e: any) => {
        const store = e.target.result.createObjectStore('s');
        await reqDone(store.put('seed1', 'a'));
        await reqDone(store.put('seed2', 'b')); // pre-fix: upgrade had already committed
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    expect(db.version).toBe(1);
    const out = await reqDone(db.transaction('s', 'readonly').objectStore('s').getAll());
    expect(out).toEqual(['seed1', 'seed2']);
    db.close();
  });
});

describe('ENG-23446: close() with an in-flight transaction (finding 2 regression)', () => {
  test('writes issued before close() commit, fire complete, and persist', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'cl1', 1, (d) => d.createObjectStore('s'));
    const tx = db.transaction('s', 'readwrite');
    tx.objectStore('s').put('v', 'k');
    db.close(); // must not yank the SQLite handle from under the transaction
    expect(await txSettled(tx)).toBe('complete');

    const db2 = await openDb(factory, 'cl1', undefined);
    expect(await reqDone(db2.transaction('s', 'readonly').objectStore('s').get('k'))).toBe('v');
    db2.close();
  });
});

describe('ENG-23446: upgradeneeded via addEventListener (finding 3)', () => {
  test('listeners registered with addEventListener fire and can create the schema', async () => {
    const factory = makeFactory();
    const db = await new Promise<any>((resolve, reject) => {
      const req = factory.open('ael1', 1);
      req.addEventListener('upgradeneeded', (e: any) => {
        e.target.result.createObjectStore('s');
      });
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    expect(db.objectStoreNames.contains('s')).toBe(true);
    // The store is really there.
    const tx = db.transaction('s', 'readwrite');
    tx.objectStore('s').put('v', 'k');
    expect(await txSettled(tx)).toBe('complete');
    db.close();
  });

  test('a throwing upgradeneeded listener aborts the upgrade like a throwing handler', async () => {
    const factory = makeFactory();
    let err: any;
    try {
      await new Promise<any>((resolve, reject) => {
        const req = factory.open('ael2', 1);
        req.addEventListener('upgradeneeded', () => { throw new Error('listener boom'); });
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error('open failed'));
      });
    } catch (e) { err = e; }
    expect(err).toBeDefined();
    // Retry works (nothing half-committed).
    const db = await openDb(factory, 'ael2', 1, (d) => d.createObjectStore('s'));
    expect(db.objectStoreNames.contains('s')).toBe(true);
    db.close();
  });
});

describe('ENG-23446: error/abort events bubble to the connection (finding 4)', () => {
  test('a failed request fires db.onerror and an un-prevented error aborts (db.onabort fires)', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'bub1', 1, (d) => d.createObjectStore('s'));

    const dbErrors: string[] = [];
    const dbAborts: string[] = [];
    db.onerror = (e: any) => { dbErrors.push(e.target.error?.name); };
    db.onabort = (e: any) => { dbAborts.push(e.type); };

    const tx = db.transaction('s', 'readwrite');
    tx.objectStore('s').add('first', 'k');
    tx.objectStore('s').add('dup', 'k'); // ConstraintError, unhandled
    expect(await txSettled(tx)).toBe('abort');
    expect(dbErrors).toEqual(['ConstraintError']);
    expect(dbAborts).toEqual(['abort']);
    // The whole transaction rolled back.
    expect(await reqDone<number>(db.transaction('s', 'readonly').objectStore('s').count())).toBe(0);
    db.close();
  });
});

describe('ENG-23446: key generator bounds (finding 6)', () => {
  test('the generator refuses to run past 2^53 with ConstraintError instead of silently overwriting', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'gen1', 1, (d) => d.createObjectStore('s', { autoIncrement: true }));
    const tx = db.transaction('s', 'readwrite');
    const store = tx.objectStore('s');
    // Push the generator to its ceiling via an explicit key.
    await reqDone(store.put('near-max', 2 ** 53 - 1));
    expect(await reqDone(store.add('max'))).toBe(2 ** 53); // last valid generated key
    // Pre-fix: += 1 was a float no-op at 2^53 and this silently overwrote key
    // 2^53 forever. Now the generation step fails with ConstraintError.
    const failing = store.add('beyond');
    let err: any;
    failing.onerror = (e: any) => { err = failing.error; e.preventDefault(); };
    await new Promise<void>((r) => { failing.onsuccess = () => r(); failing.onerror = (e: any) => { err = failing.error; e.preventDefault(); r(); }; });
    expect(err?.name).toBe('ConstraintError');
    db.close();
  });
});

describe('ENG-23446: transaction() argument validation (finding 7)', () => {
  test('an empty scope throws InvalidAccessError; objectStoreNames is a DOMStringList', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'val1', 1, (d) => {
      d.createObjectStore('a');
      d.createObjectStore('b');
    });
    let err: any;
    try { db.transaction([]); } catch (e) { err = e; }
    expect(err?.name).toBe('InvalidAccessError');

    const tx = db.transaction(['b', 'a', 'a']); // duplicates dedupe
    expect(Array.from(tx.objectStoreNames)).toEqual(['a', 'b']);
    expect(tx.objectStoreNames.contains('a')).toBe(true);
    expect(tx.objectStoreNames.contains('zzz')).toBe(false);
    expect(tx.objectStoreNames.item(0)).toBe('a');
    db.close();
  });
});

describe('ENG-23446: versionchange/blocked lifecycle (finding 9)', () => {
  test('deleteDatabase fires versionchange + blocked and waits for connections to close', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'del1', 1, (d) => d.createObjectStore('s'));
    const seed = db.transaction('s', 'readwrite');
    seed.objectStore('s').put('v', 'k');
    await txDone(seed);

    const events: string[] = [];
    db.onversionchange = (e: any) => {
      events.push(`versionchange:${e.oldVersion}->${String(e.newVersion)}`);
      // Deliberately do NOT close here, so the request must go through blocked.
    };

    const delReq = factory.deleteDatabase('del1');
    let deleted = false;
    const deletedPromise = new Promise<void>((resolve, reject) => {
      delReq.onsuccess = () => { deleted = true; resolve(); };
      delReq.onerror = () => reject(delReq.error);
    });
    delReq.onblocked = () => events.push('blocked');

    await flush();
    expect(events).toEqual(['versionchange:1->null', 'blocked']);
    expect(deleted).toBe(false); // still waiting on the open connection

    db.close();
    await deletedPromise;
    expect(deleted).toBe(true);

    // The database is really gone: reopening upgrades from version 0.
    let sawUpgrade: any = null;
    const db2 = await new Promise<any>((resolve, reject) => {
      const req = factory.open('del1', 1);
      req.onupgradeneeded = (e: any) => { sawUpgrade = e.oldVersion; e.target.result.createObjectStore('s'); };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    expect(sawUpgrade).toBe(0);
    expect(await reqDone<number>(db2.transaction('s', 'readonly').objectStore('s').count())).toBe(0);
    db2.close();
  });

  test('a version upgrade over a live connection fires versionchange and proceeds once it closes', async () => {
    const factory = makeFactory();
    const db1 = await openDb(factory, 'upgblock', 1, (d) => d.createObjectStore('s'));

    // The standard pattern: the old connection closes itself on versionchange.
    const events: string[] = [];
    db1.onversionchange = (e: any) => {
      events.push(`versionchange:${e.oldVersion}->${e.newVersion}`);
      db1.close();
    };

    const db2 = await new Promise<any>((resolve, reject) => {
      const req = factory.open('upgblock', 2);
      req.onupgradeneeded = (e: any) => e.target.result.createObjectStore('extra');
      req.onblocked = () => events.push('blocked');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    expect(db2.version).toBe(2);
    expect(db2.objectStoreNames.contains('extra')).toBe(true);
    expect(events).toEqual(['versionchange:1->2']); // closed promptly: never blocked
    db2.close();
  });

  test('a version upgrade blocked by a lingering connection completes after it finally closes', async () => {
    const factory = makeFactory();
    const db1 = await openDb(factory, 'upgblock2', 1, (d) => d.createObjectStore('s'));
    const events: string[] = [];
    db1.onversionchange = () => events.push('versionchange'); // does not close

    let db2: any = null;
    const opened = new Promise<void>((resolve, reject) => {
      const req = factory.open('upgblock2', 2);
      req.onupgradeneeded = (e: any) => e.target.result.createObjectStore('extra');
      req.onblocked = () => events.push('blocked');
      req.onsuccess = () => { db2 = req.result; resolve(); };
      req.onerror = () => reject(req.error);
    });

    await flush();
    expect(events).toEqual(['versionchange', 'blocked']);
    expect(db2).toBeNull(); // upgrade waiting

    db1.close();
    await opened;
    expect(db2.version).toBe(2);
    db2.close();
  });
});

describe('ENG-23446: cursor & key-range validation (finding 11)', () => {
  test('continue()/advance() on an exhausted cursor throw InvalidStateError', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'cur1', 1, (d) => d.createObjectStore('s'));
    const wtx = db.transaction('s', 'readwrite');
    wtx.objectStore('s').put('v', 'k');
    await txDone(wtx);

    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('s', 'readonly');
      const req = tx.objectStore('s').openCursor();
      let cursor: any = null;
      let steps = 0;
      req.onsuccess = () => {
        steps++;
        if (req.result) {
          cursor = req.result;
          cursor.continue();
        } else {
          // Exhausted: further movement must throw, not resurrect the cursor.
          try {
            expect(() => cursor.continue()).toThrow();
            try { cursor.continue(); } catch (e: any) { expect(e.name).toBe('InvalidStateError'); }
            try { cursor.advance(1); } catch (e: any) { expect(e.name).toBe('InvalidStateError'); }
            expect(steps).toBe(2);
            resolve();
          } catch (e) { reject(e); }
        }
      };
      req.onerror = () => reject(req.error);
    });
    db.close();
  });

  test('IDBKeyRange validates its keys and rejects empty open intervals', () => {
    expect(() => IDBKeyRange.only({} as any)).toThrow();
    try { IDBKeyRange.only(null as any); } catch (e: any) { expect(e.name).toBe('DataError'); }
    try { IDBKeyRange.lowerBound(true as any); } catch (e: any) { expect(e.name).toBe('DataError'); }
    try { IDBKeyRange.bound(1, 1, true, false); } catch (e: any) { expect(e.name).toBe('DataError'); }
    try { IDBKeyRange.bound(1, 1, false, true); } catch (e: any) { expect(e.name).toBe('DataError'); }
    // Closed equal bounds are fine (only()-shaped).
    expect(IDBKeyRange.bound(1, 1).includes(1)).toBe(true);
  });

  test('getAll/count/openCursor with an invalid (non-null) query throw DataError synchronously', async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'cur2', 1, (d) => {
      const s = d.createObjectStore('s');
      s.createIndex('byV', 'v');
    });
    const tx = db.transaction('s', 'readonly');
    const store = tx.objectStore('s');
    for (const call of [
      () => store.getAll(true),
      () => store.getAllKeys({}),
      () => store.count(true),
      () => store.openCursor(false),
      () => store.openKeyCursor({}),
      () => store.index('byV').getAll(true),
      () => store.index('byV').count(true),
      () => store.index('byV').openCursor(false),
    ]) {
      let err: any;
      try { call(); } catch (e) { err = e; }
      expect(err?.name).toBe('DataError');
    }
    db.close();
  });
});

describe('ENG-23446: generated keys are injected into the clone (finding 12)', () => {
  test("add() does not mutate the caller's object; the stored record has the key", async () => {
    const factory = makeFactory();
    const db = await openDb(factory, 'clone1', 1, (d) =>
      d.createObjectStore('s', { keyPath: 'id', autoIncrement: true }));
    const tx = db.transaction('s', 'readwrite');
    const original: any = { v: 1, nested: { deep: true } };
    const key = await reqDone(tx.objectStore('s').add(original));
    expect(key).toBe(1);
    expect('id' in original).toBe(false); // caller's object untouched
    expect(await txSettled(tx)).toBe('complete');

    const stored: any = await reqDone(db.transaction('s', 'readonly').objectStore('s').get(1));
    expect(stored.id).toBe(1); // clone got the generated key
    expect(stored.v).toBe(1);
    db.close();
  });
});
