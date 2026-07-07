// @ts-nocheck
/**
 * IDBFactory - IndexedDB Factory
 *
 * The main entry point for IndexedDB. Provides open() and deleteDatabase().
 * Backed by SQLite via the exact:sqlite module.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBFactory
 */

import { IDBDatabase, SharedConnectionState } from './IDBDatabase';
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
  /**
   * @internal - Map of database name -> shared connection state (SQLite
   * handle, transaction scheduler, refcounted connections). Cached as soon as
   * the handle is created — including for opens whose upgrade later fails —
   * so sibling open() calls share ONE coordinated handle and a failed upgrade
   * cannot leak an uncached handle. Evicted (via onClosed) when the last
   * connection closes and the handle is actually closed. (ENG-23117)
   */
  private _databases: Map<string, SharedConnectionState> = new Map();
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
      let shared: SharedConnectionState | null = null;
      try {
        const existing = this._databases.get(name);

        if (existing && !existing.closed) {
          shared = existing;
        } else {
          const sqliteDb = this._sqliteProvider.create(name);
          shared = new SharedConnectionState(sqliteDb, readStoredVersion(sqliteDb));
          // Evict the cache entry when the handle actually closes (last
          // connection gone + transactions drained), so the next open()
          // creates a fresh handle instead of reusing a dead one.
          const entry = shared;
          entry.onClosed = () => {
            if (this._databases.get(name) === entry) {
              this._databases.delete(name);
            }
          };
          this._databases.set(name, shared);
        }
        const sqliteDb = shared.sqliteDb;
        const oldVersion = shared.version;
        const resolvedVersion = version ?? (oldVersion > 0 ? oldVersion : 1);
        if (oldVersion > 0 && resolvedVersion < oldVersion) {
          throw new DOMException(
            `The requested version (${resolvedVersion}) is less than the existing version (${oldVersion}).`,
            'VersionError',
          );
        }

        const db = new IDBDatabase(name, resolvedVersion, shared, this);

        // Set the result on the request before upgradeneeded fires,
        // because onupgradeneeded handlers access event.target.result
        // to get a reference to the database.
        request._setResult(db);

        // Version upgrade needed?
        if (resolvedVersion > oldVersion) {
          // Create an upgrade transaction so createObjectStore/deleteObjectStore
          // can detect that they are being called during upgradeneeded, and so
          // the standard `e.target.transaction` migration idiom works.
          // (ENG-23117)
          const storeNames = Array.from((db as any)._objectStores?.keys?.() ?? []);
          const upgradeTxn = new IDBTransaction(db, storeNames, 'versionchange');
          db._upgradeTransaction = upgradeTxn;
          request.transaction = upgradeTxn;

          // The version bump commits atomically with the upgrade's schema
          // changes, inside the same SQLite transaction.
          upgradeTxn._beforeCommit = () => {
            writeStoredVersion(sqliteDb, resolvedVersion);
          };
          // The open request settles when the versionchange transaction
          // finishes. The transaction now lives the normal lifecycle — it
          // stays active through the upgradeneeded task's microtasks (awaited
          // upgrade bodies work) and auto-commits once idle — instead of
          // being force-committed the moment onupgradeneeded returned.
          // (ENG-23446)
          upgradeTxn._onFinished = (committed: boolean, error: any) => {
            db._upgradeTransaction = null;
            request.transaction = null;
            if (committed) {
              shared!.version = resolvedVersion;
              request._resolveSync(db);
            } else {
              // The connection was never delivered; release it (closing the
              // shared handle if this was the only reference — a retried
              // open() then starts from a fresh handle instead of leaking one
              // per attempt).
              db.close();
              request._reject(
                error ?? new DOMException('The upgrade transaction was aborted.', 'AbortError'),
              );
            }
          };

          // The upgrade body runs when the connection scheduler grants the
          // transaction (immediately when the connection is idle; after any
          // in-flight sibling-connection transactions otherwise). The whole
          // upgrade (schema changes + version bump) runs in a single SQLite
          // transaction: if onupgradeneeded throws after creating some object
          // stores, everything rolls back so the upgrade can be retried,
          // rather than being permanently wedged (a re-run would hit
          // ConstraintError re-creating store A).
          upgradeTxn._onStart = () => {
            try {
              upgradeTxn._beginVersionChange();
              const event = {
                type: 'upgradeneeded',
                target: request,
                transaction: upgradeTxn,
                oldVersion,
                newVersion: resolvedVersion,
              };
              // During upgradeneeded, the database is in a special state
              // where createObjectStore/deleteObjectStore can be called.
              if (request.onupgradeneeded) {
                request.onupgradeneeded(event);
              }
              // addEventListener('upgradeneeded', ...) listeners fire too —
              // previously they were silently skipped, so schemas registered
              // that way were never created. A throwing listener aborts the
              // upgrade like a throwing property handler. (ENG-23446)
              request._invokeListeners('upgradeneeded', event);
              // Deactivation + auto-commit proceed like a normal transaction.
              upgradeTxn._scheduleDeactivation();
            } catch (upgradeError: any) {
              // Roll back schema + version; _onFinished rejects the request.
              upgradeTxn._abortWith(upgradeError);
            }
          };

          // Per spec, other open connections to this database get a
          // versionchange event first; if any remain open the request fires
          // 'blocked' and the upgrade waits for them to close. Previously the
          // upgrade barged ahead regardless. (ENG-23446)
          const scheduleUpgrade = () => db._scheduleTransaction(upgradeTxn);
          const blockers = () =>
            Array.from(shared!.connections).filter((c: any) => c !== db);
          const others = blockers();
          if (others.length > 0) {
            for (const conn of others) {
              (conn as any)._fireVersionChange(oldVersion, resolvedVersion);
            }
            if (blockers().length > 0) {
              const blockedEvent = {
                type: 'blocked',
                target: request,
                oldVersion,
                newVersion: resolvedVersion,
              };
              if (request.onblocked) {
                try { request.onblocked(blockedEvent); } catch (_) { /* swallow */ }
              }
              try { request._invokeListeners('blocked', blockedEvent); } catch (_) { /* swallow */ }
              shared!.addConnectionWaiter(() => {
                if (blockers().length > 0) return false;
                scheduleUpgrade();
                return true;
              });
            } else {
              scheduleUpgrade();
            }
          } else {
            scheduleUpgrade();
          }
        } else {
          writeStoredVersion(sqliteDb, resolvedVersion);
          // Fire onsuccess
          request._resolveSync(db);
        }
      } catch (e: any) {
        request._reject(e);
        // Don't keep an unused handle cached for an open() that never
        // produced a connection (e.g. VersionError).
        shared?.releaseIfUnused();
      }
    });

    return request;
  }

  /**
   * Delete a database.
   */
  deleteDatabase(name: string): IDBOpenDBRequest<undefined> {
    const request = new IDBOpenDBRequest<undefined>();

    queueMicrotask(() => {
      const existing = this._databases.get(name);
      const oldVersion = existing?.version ?? 0;
      const finish = () => {
        try {
          this._sqliteProvider.delete?.(name);
          request._resolveSync(undefined);
        } catch (e: any) {
          request._reject(e);
        }
      };

      if (!existing || existing.closed || existing.connections.size === 0) {
        // No live connections: close the cached handle (its onClosed callback
        // evicts the cache entry) and delete immediately.
        try {
          if (existing) {
            existing.forceClose();
            this._databases.delete(name);
          }
        } catch (e: any) {
          request._reject(e);
          return;
        }
        finish();
        return;
      }

      // Live connections hold the database open. Per spec: fire versionchange
      // (newVersion null) at each, and if any remain open fire 'blocked' on
      // the request and wait — the delete proceeds only once the last
      // connection closes. Previously the handle was force-closed out from
      // under live connections, bricking their in-flight transactions.
      // (ENG-23446)
      for (const conn of Array.from(existing.connections)) {
        (conn as any)._fireVersionChange(oldVersion, null);
      }
      if (existing.connections.size > 0) {
        const blockedEvent = {
          type: 'blocked',
          target: request,
          oldVersion,
          newVersion: null,
        };
        if (request.onblocked) {
          try { request.onblocked(blockedEvent); } catch (_) { /* swallow */ }
        }
        try { request._invokeListeners('blocked', blockedEvent); } catch (_) { /* swallow */ }
      }
      const runDelete = () => {
        this._databases.delete(name);
        finish();
      };
      if (existing.closed) {
        // Every connection closed (and transactions drained) during the
        // versionchange dispatch; the handle is already gone.
        runDelete();
        return;
      }
      // Wait for the handle to ACTUALLY close (last connection gone AND
      // in-flight transactions drained) before unlinking the files — deleting
      // a SQLite file under a live handle mid-transaction loses data
      // silently. onClosed also evicts the factory cache (prevOnClosed).
      const prevOnClosed = existing.onClosed;
      existing.onClosed = () => {
        if (prevOnClosed) prevOnClosed();
        runDelete();
      };
      // Covers connections.size having reached zero with the handle still
      // open (no further connectionClosed will fire).
      existing.releaseIfUnused();
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
