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

/**
 * Interface for creating SQLite database instances.
 * This allows the factory to work with either the real Database class
 * or a mock for testing.
 */
export interface SQLiteDatabaseProvider {
  create(name: string): any;
}

/**
 * Default provider that uses exact:sqlite Database.
 */
class DefaultSQLiteProvider implements SQLiteDatabaseProvider {
  create(name: string): any {
    const g = globalThis as any;
    // Try to use the exact:sqlite Database
    if (g.__exactSqliteOpen) {
      // Import is done lazily to avoid circular dependencies
      const { Database } = require('../sqlite');
      return new Database(`:memory:`);
    }
    throw new Error(
      'IndexedDB requires SQLite support. The exact:sqlite native bridge is not available.'
    );
  }
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
    const resolvedVersion = version ?? 1;

    if (resolvedVersion <= 0 || !Number.isFinite(resolvedVersion) || Math.floor(resolvedVersion) !== resolvedVersion) {
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
        const oldVersion = existing ? existing.version : 0;

        let sqliteDb: any;
        if (existing) {
          sqliteDb = existing.sqliteDb;
        } else {
          sqliteDb = this._sqliteProvider.create(name);
        }

        const db = new IDBDatabase(name, resolvedVersion, sqliteDb);

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
        }

        // Store the database reference
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
