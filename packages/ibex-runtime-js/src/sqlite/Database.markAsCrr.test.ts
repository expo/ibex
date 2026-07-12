import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { createRequire } from 'module';
import { Database } from './Database';

const require = createRequire(import.meta.url);
const ModuleDatabase = require('./module.js').Database;
const g = globalThis as any;

const SQLITE_GLOBAL_KEYS = [
  '__exactSqliteOpen',
  '__exactSqliteExec',
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
}
