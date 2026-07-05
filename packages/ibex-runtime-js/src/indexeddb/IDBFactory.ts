// @ts-nocheck
/**
 * IDBFactory - IndexedDB Factory
 *
 * The main entry point for IndexedDB. Provides open() and deleteDatabase().
 * Backed by SQLite via the exact:sqlite module.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBFactory
 */

import { IDBDatabase } from './IDBDatabase';
import { IDBOpenDBRequest } from './IDBRequest';
import { IDBTransaction } from './IDBTransaction';
import { compareKeys } from './IDBKeyRange';
import { DOMException } from './utils';

/**
 * Interface for creating SQLite database instances.
 * This allows the factory to work with either the real Database class
 * or a mock for testing.
 */
export interface SQLiteDatabaseProvider {
  create(name: string): any;
  delete?(name: string): void;
}

/**
 * Default provider that uses exact:sqlite Database.
 */
class DefaultSQLiteProvider implements SQLiteDatabaseProvider {
  create(name: string): any {
    const g = globalThis as any;
    if (typeof g.__exactSqliteOpen !== 'function' && typeof g.__exactEnsureSqlite === 'function') {
      g.__exactEnsureSqlite();
    }
    if (g.__exactSqliteOpen) {
      // Import is done lazily to avoid circular dependencies
      const { Database } = require('../sqlite');
      return new Database(indexedDbPath(name));
    }
    throw new Error(
      'IndexedDB requires SQLite support. The exact:sqlite native bridge is not available.'
    );
  }

  delete(name: string): void {
    const g = globalThis as any;
    if (typeof g.__exactUnlink !== 'function' && typeof g.__exactEnsureFs === 'function') {
      g.__exactEnsureFs();
    }
    if (typeof g.__exactUnlink !== 'function') return;
    for (const path of [indexedDbPath(name), `${indexedDbPath(name)}-wal`, `${indexedDbPath(name)}-shm`]) {
      try {
        g.__exactUnlink(path);
      } catch (_) {}
    }
  }
}

function trimTrailingSlash(path: string): string {
  return path.replace(/\/+$/, '') || '/';
}

function indexedDbRoot(): string {
  const g = globalThis as any;
  const androidFilesDir = g.__exactAndroidStoragePaths?.filesDir;
  if (typeof androidFilesDir === 'string' && androidFilesDir.length > 0) {
    return trimTrailingSlash(androidFilesDir);
  }

  const env = g.process?.env;
  const envFilesDir = env?.EXACT_ANDROID_FILES_DIR ?? env?.HOME;
  if (typeof envFilesDir === 'string' && envFilesDir.length > 0) {
    return trimTrailingSlash(envFilesDir);
  }

  return '/tmp';
}

function ensureIndexedDbDirectory(directory: string): void {
  const g = globalThis as any;
  try {
    if (typeof g.__exactMkdir !== 'function' && typeof g.__exactEnsureFs === 'function') {
      g.__exactEnsureFs();
    }
    if (typeof g.__exactMkdir === 'function') {
      g.__exactMkdir(directory, true);
    }
  } catch (_) {}
}

function indexedDbPath(name: string): string {
  // @ref LLP 0008#android-backend-matrix — IndexedDB persists under Android app filesDir.
  const directory = `${indexedDbRoot()}/.ibex/indexeddb`;
  ensureIndexedDbDirectory(directory);
  const encodedName = encodeURIComponent(String(name)) || 'default';
  return `${directory}/${encodedName}.sqlite`;
}

function readStoredVersion(sqliteDb: any): number {
  try {
    const row = sqliteDb.query('SELECT value FROM _idb_meta WHERE key = ?').get('version');
    const version = Number(row?.value);
    return Number.isFinite(version) && version > 0 ? Math.floor(version) : 0;
  } catch (_) {
    return 0;
  }
}

function writeStoredVersion(sqliteDb: any, version: number): void {
  try {
    sqliteDb.run(`
      CREATE TABLE IF NOT EXISTS _idb_meta (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `);
    sqliteDb.run(
      'INSERT INTO _idb_meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
      'version',
      String(version),
    );
  } catch (_) {}
}

export class IDBFactory {
  /** @internal - Map of database name -> { version, sqliteDb } */
  private _databases: Map<string, { version: number; sqliteDb: any }> = new Map();
  /** @internal - SQLite provider for creating database instances */
  private _sqliteProvider: SQLiteDatabaseProvider;

  constructor(provider?: SQLiteDatabaseProvider) {
    this._sqliteProvider = provider ?? new DefaultSQLiteProvider();
  }

  /**
   * Open (or create) a database with the given name and optional version.
   *
   * Returns an IDBOpenDBRequest. Set onupgradeneeded and onsuccess handlers
   * on the request before the event loop yields.
   */
  open(name: string, version?: number): IDBOpenDBRequest<IDBDatabase> {
    const request = new IDBOpenDBRequest<IDBDatabase>();

    if (
      version !== undefined &&
      (version <= 0 || !Number.isFinite(version) || Math.floor(version) !== version)
    ) {
      queueMicrotask(() => {
        request._reject(new TypeError(
          `The version provided (${version}) is not a valid positive integer.`
        ));
      });
      return request;
    }

    // Process in a microtask to allow handlers to be attached
    queueMicrotask(() => {
      try {
        const existing = this._databases.get(name);

        let sqliteDb: any;
        let oldVersion = 0;
        if (existing) {
          sqliteDb = existing.sqliteDb;
          oldVersion = existing.version;
        } else {
          sqliteDb = this._sqliteProvider.create(name);
          oldVersion = readStoredVersion(sqliteDb);
        }
        const resolvedVersion = version ?? (oldVersion > 0 ? oldVersion : 1);
        if (oldVersion > 0 && resolvedVersion < oldVersion) {
          throw new DOMException(
            `The requested version (${resolvedVersion}) is less than the existing version (${oldVersion}).`,
            'VersionError',
          );
        }

        const db = new IDBDatabase(name, resolvedVersion, sqliteDb, this);

        // Set the result on the request before upgradeneeded fires,
        // because onupgradeneeded handlers access event.target.result
        // to get a reference to the database.
        request._setResult(db);

        // Version upgrade needed?
        if (resolvedVersion > oldVersion) {
          // Create an upgrade transaction so createObjectStore/deleteObjectStore
          // can detect that they are being called during upgradeneeded.
          const storeNames = Array.from((db as any)._objectStores?.keys?.() ?? []);
          const upgradeTxn = new IDBTransaction(db, storeNames, 'versionchange');
          db._upgradeTransaction = upgradeTxn;

          // Wrap the whole upgrade (schema changes + version bump) in a single
          // SQLite transaction. If onupgradeneeded throws after creating some
          // object stores, we roll everything back so the database can be
          // reopened and the upgrade retried, rather than being permanently
          // wedged (a re-run would hit ConstraintError re-creating store A).
          upgradeTxn._beginVersionChange();
          try {
            // Fire onupgradeneeded synchronously
            if (request.onupgradeneeded) {
              const event = {
                type: 'upgradeneeded',
                target: request,
                oldVersion,
                newVersion: resolvedVersion,
              };
              // During upgradeneeded, the database is in a special state
              // where createObjectStore/deleteObjectStore can be called
              request.onupgradeneeded(event);
            }

            // Clear the upgrade transaction after upgradeneeded completes
            db._upgradeTransaction = null;
            writeStoredVersion(sqliteDb, resolvedVersion);
            upgradeTxn._commitVersionChange();
          } catch (upgradeError: any) {
            db._upgradeTransaction = null;
            upgradeTxn._abortVersionChange();
            throw upgradeError;
          }
        } else {
          writeStoredVersion(sqliteDb, resolvedVersion);
        }

        // Store the database reference (only reached once the upgrade, if any,
        // has committed successfully).
        this._databases.set(name, { version: resolvedVersion, sqliteDb });

        // Fire onsuccess
        request._resolveSync(db);
      } catch (e: any) {
        request._reject(e);
      }
    });

    return request;
  }

  /**
   * @internal - Evict a cached connection when its IDBDatabase.close() runs.
   *
   * open() reuses a cached sqliteDb handle for a name; without eviction, once a
   * connection is closed the cache would keep handing out the dead handle and
   * every subsequent open() would fail. Eviction lets the next open() create a
   * fresh handle from the persisted SQLite file.
   */
  _handleConnectionClose(name: string, sqliteDb: any): void {
    const entry = this._databases.get(name);
    if (entry && entry.sqliteDb === sqliteDb) {
      this._databases.delete(name);
    }
  }

  /**
   * Delete a database.
   */
  deleteDatabase(name: string): IDBOpenDBRequest<undefined> {
    const request = new IDBOpenDBRequest<undefined>();

    queueMicrotask(() => {
      try {
        const existing = this._databases.get(name);
        if (existing) {
          // Close the SQLite database
          if (existing.sqliteDb && existing.sqliteDb.close) {
            existing.sqliteDb.close();
          }
          this._databases.delete(name);
        }
        this._sqliteProvider.delete?.(name);
        request._resolveSync(undefined);
      } catch (e: any) {
        request._reject(e);
      }
    });

    return request;
  }

  /**
   * Compare two keys using IndexedDB key comparison rules.
   */
  cmp(first: any, second: any): number {
    const result = compareKeys(first, second);
    return result < 0 ? -1 : result > 0 ? 1 : 0;
  }

  /**
   * List all databases. Returns a promise.
   */
  databases(): Promise<Array<{ name: string; version: number }>> {
    const result = Array.from(this._databases.entries()).map(([name, info]) => ({
      name,
      version: info.version,
    }));
    return Promise.resolve(result);
  }
}
