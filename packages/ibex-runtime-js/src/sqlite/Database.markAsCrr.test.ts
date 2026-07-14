import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { createRequire } from 'module';
import { Database } from './Database';

const require = createRequire(import.meta.url);
const ModuleDatabase = require('./module.js').Database;
const g = globalThis as any;

const SQLITE_GLOBAL_KEYS = [
  '__exactSqliteOpen',
  '__exactSqliteExec',
  '__exactSqlitePrepare',
  '__exactSqliteFinalize',
  '__exactSqliteClose',
  '__exactSqliteInTransaction',
] as const;

let originals = new Map<string, any>();
let executedSql: string[] = [];

function installSqliteStubs(): void {
  originals = new Map();
  for (const key of SQLITE_GLOBAL_KEYS) {
    originals.set(key, g[key]);
  }
  executedSql = [];
  g.__exactSqliteOpen = () => ({ handle: 1 });
  g.__exactSqliteExec = (_handle: any, sql: string) => {
    executedSql.push(sql);
    return { changes: 0, lastInsertRowid: 0 };
  };
  g.__exactSqlitePrepare = () => ({
    handle: 2,
    columnNames: [],
    declaredTypes: [],
    paramsCount: 0,
    readOnly: true,
  });
  g.__exactSqliteFinalize = () => {};
  g.__exactSqliteClose = () => {};
  g.__exactSqliteInTransaction = () => false;
}

function restoreSqliteStubs(): void {
  for (const key of SQLITE_GLOBAL_KEYS) {
    if (originals.get(key) === undefined) {
      delete g[key];
    } else {
      g[key] = originals.get(key);
    }
  }
  originals = new Map();
  executedSql = [];
}

function openCrrReadyDatabase(DatabaseCtor: any): any {
  const db = new DatabaseCtor(':memory:');
  executedSql = [];
  db._crSqliteLoaded = true;
  return db;
}

beforeEach(installSqliteStubs);
afterEach(restoreSqliteStubs);

for (const [label, DatabaseCtor] of [
  ['Database.ts', Database],
  ['module.js', ModuleDatabase],
] as const) {
  describe(`markAsCrr table name validation (${label})`, () => {
    test('allows simple SQLite identifiers', () => {
      const db = openCrrReadyDatabase(DatabaseCtor);

      db.markAsCrr('users_2026');

      expect(executedSql).toEqual(["SELECT crsql_as_crr('users_2026')"]);
    });

    test('accepts the full SQLite identifier space and SQL-quotes apostrophes', () => {
      const names = [
        '9users',
        'users-name',
        'users.name',
        'users name',
        '用户',
        "users'archive",
        "users'); DROP TABLE users; --",
      ];

      for (const tableName of names) {
        const db = openCrrReadyDatabase(DatabaseCtor);
        db.markAsCrr(tableName);
        expect(executedSql.pop()).toBe(
          `SELECT crsql_as_crr('${tableName.replace(/'/g, "''")}')`,
        );
      }
    });

    test('rejects only non-strings, empty names, and embedded NUL', () => {
      for (const tableName of ['', 'bad\0name', null, 42]) {
        const db = openCrrReadyDatabase(DatabaseCtor);
        expect(() => db.markAsCrr(tableName as any)).toThrow(TypeError);
        expect(executedSql).toEqual([]);
      }
    });
  });

  describe(`owner-retryable SQLite release (${label})`, () => {
    test('caller-writable cache lookalikes cannot inject or finalize statements', () => {
      const db = new DatabaseCtor(':memory:');
      const sql = 'SELECT private cache';
      let fakeFinalizeCalls = 0;
      const fakeStatement = {
        finalize() {
          fakeFinalizeCalls += 1;
        },
      };
      // Cover both historical cache shapes. Database.ts used a Map while the
      // generated CommonJS module used a string-keyed object.
      const injected: any = new Map([[sql, fakeStatement]]);
      injected[sql] = fakeStatement;
      db._queryCache = injected;

      const actual = db.query(sql);
      expect(actual).not.toBe(fakeStatement);
      expect(actual._handle).toBeDefined();

      db.close(true);
      expect(fakeFinalizeCalls).toBe(0);
    });

    test('private selectors survive rejected finalize and close calls', () => {
      const db = new DatabaseCtor(':memory:');
      const dbHandle = db.handle;
      const statement = db.prepare('SELECT 1');
      const statementHandle = statement._handle;
      let principal = 'foreign';
      const finalizeAttempts: Array<[string, any]> = [];
      const closeAttempts: Array<[string, any]> = [];
      g.__exactSqliteFinalize = (handle: any) => {
        finalizeAttempts.push([principal, handle]);
        if (principal === 'foreign') throw new Error('wrong statement principal');
      };
      g.__exactSqliteClose = (handle: any) => {
        closeAttempts.push([principal, handle]);
        if (principal === 'foreign') throw new Error('wrong database principal');
      };

      expect(() => { statement._handle = 999; }).toThrow(/private/);
      expect(() => { statement._finalized = true; }).toThrow(/private/);
      expect(() => statement.finalize()).toThrow('wrong statement principal');
      expect(statement._handle).toBe(statementHandle);
      expect(statement._finalized).toBe(false);

      // Database.close() preserves its historical non-throwing default while
      // leaving owner state untouched when native release is denied.
      expect(() => { db._handle = 999; }).toThrow(/private/);
      expect(() => { db._closed = true; }).toThrow(/private/);
      expect(() => db.close()).not.toThrow();
      expect(db.handle).toBe(dbHandle);
      expect(db._closed).toBe(false);
      expect(db.inTransaction).toBe(false);

      principal = 'owner';
      statement.finalize();
      db.close(true);
      expect(statement._finalized).toBe(true);
      expect(db._closed).toBe(true);
      expect(finalizeAttempts).toEqual([
        ['foreign', statementHandle],
        ['owner', statementHandle],
      ]);
      expect(closeAttempts).toEqual([
        ['foreign', dbHandle],
        ['owner', dbHandle],
      ]);
    });

    test('a failed database close does not leave finalized statements cached', () => {
      const db = new DatabaseCtor(':memory:');
      const cachedBefore = db.query('SELECT cached');
      let closeAttempts = 0;
      g.__exactSqliteClose = () => {
        closeAttempts += 1;
        if (closeAttempts === 1) throw new Error('transient close failure');
      };

      expect(() => db.close()).not.toThrow();
      expect(db._closed).toBe(false);
      expect(cachedBefore._finalized).toBe(true);

      const cachedAfter = db.query('SELECT cached');
      expect(cachedAfter).not.toBe(cachedBefore);
      expect(cachedAfter._finalized).toBe(false);

      db.close(true);
      expect(db._closed).toBe(true);
      expect(closeAttempts).toBe(2);
    });
  });
}
