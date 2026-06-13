// @ts-nocheck
/**
 * IDBTransaction - IndexedDB Transaction
 *
 * Groups database operations that must succeed or fail as a unit.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBTransaction
 */

import { IDBObjectStore } from './IDBObjectStore';
import { DOMException } from './utils';

export type IDBTransactionMode = 'readonly' | 'readwrite' | 'versionchange';

export class IDBTransaction {
  private _db: any;
  private _mode: IDBTransactionMode;
  private _storeNames: string[];
  private _stores: Map<string, IDBObjectStore> = new Map();
  private _committed = false;
  private _aborted = false;
  private _error: DOMException | null = null;
  /** @internal */
  _state: 'active' | 'inactive' | 'committing' | 'finished' = 'active';
  /** @internal - Whether a SQLite BEGIN has been issued for this transaction */
  private _sqliteBegan = false;
  /** @internal - EventTarget listeners keyed by event type */
  private _listeners: Record<string, Function[]> = {};

  oncomplete: ((event: any) => void) | null = null;
  onerror: ((event: any) => void) | null = null;
  onabort: ((event: any) => void) | null = null;

  constructor(db: any, storeNames: string[], mode: IDBTransactionMode) {
    this._db = db;
    this._storeNames = storeNames;
    this._mode = mode;

    // Begin a SQLite transaction for readwrite transactions to enable rollback
    if (mode === 'readwrite') {
      this._beginSqlite();
    }
  }

  get db(): any {
    return this._db;
  }

  get mode(): IDBTransactionMode {
    return this._mode;
  }

  get objectStoreNames(): string[] {
    return [...this._storeNames].sort();
  }

  get error(): DOMException | null {
    return this._error;
  }

  addEventListener(type: string, fn: Function): void {
    if (!this._listeners[type]) this._listeners[type] = [];
    this._listeners[type].push(fn);
  }

  removeEventListener(type: string, fn: Function): void {
    const list = this._listeners[type];
    if (list) this._listeners[type] = list.filter(f => f !== fn);
  }

  /** @internal */
  private _fireListeners(type: string, event: any): void {
    const list = this._listeners[type];
    if (list) {
      for (const fn of list) {
        try { fn(event); } catch (_) { /* swallow */ }
      }
    }
  }

  /**
   * Get an object store from this transaction.
   */
  objectStore(name: string): IDBObjectStore {
    if (!this._storeNames.includes(name)) {
      throw new DOMException(
        `Object store "${name}" is not in this transaction's scope`,
        'NotFoundError',
      );
    }
    if (this._aborted) {
      throw new DOMException(
        'Transaction has been aborted',
        'InvalidStateError',
      );
    }

    let store = this._stores.get(name);
    if (!store) {
      store = this._db._getObjectStore(name, this);
      if (!store) {
        throw new DOMException(
          `Object store "${name}" does not exist`,
          'NotFoundError',
        );
      }
      this._stores.set(name, store);
    }
    return store;
  }

  /**
   * Commit the transaction.
   */
  commit(): void {
    if (this._committed || this._aborted) return;
    this._committed = true;
    this._state = 'finished';
    // Commit SQLite transaction if one was started
    this._commitSqlite();
    // Fire oncomplete asynchronously
    const event = { type: 'complete', target: this };
    queueMicrotask(() => {
      if (this.oncomplete) {
        this.oncomplete(event);
      }
      this._fireListeners('complete', event);
    });
  }

  /**
   * Abort the transaction.
   */
  abort(): void {
    if (this._committed || this._aborted) return;
    this._aborted = true;
    this._state = 'finished';
    this._error = new DOMException('Transaction was aborted', 'AbortError');
    // Rollback SQLite transaction if one was started
    this._rollbackSqlite();
    const event = { type: 'abort', target: this };
    queueMicrotask(() => {
      if (this.onabort) {
        this.onabort(event);
      }
      this._fireListeners('abort', event);
    });
  }

  /** @internal - Handle an error from a request */
  _handleError(error: any): void {
    this._error = error instanceof DOMException
      ? error
      : new DOMException(error?.message ?? 'Unknown error', 'UnknownError');
    const event = { type: 'error', target: this };
    queueMicrotask(() => {
      if (this.onerror) {
        this.onerror(event);
      }
      this._fireListeners('error', event);
    });
  }

  /** @internal - Auto-commit if no abort was called (called after all microtasks drain) */
  _autoCommit(): void {
    if (!this._committed && !this._aborted) {
      this.commit();
    }
  }

  // ================================================================
  // SQLite transaction wrapping
  // ================================================================

  /** @internal - Begin a SQLite transaction */
  private _beginSqlite(): void {
    if (this._sqliteBegan) return;
    try {
      this._db._exec('BEGIN TRANSACTION');
      this._sqliteBegan = true;
    } catch (_) {
      // Some environments may not support explicit transactions; that's OK
    }
  }

  /** @internal - Commit the SQLite transaction */
  private _commitSqlite(): void {
    if (!this._sqliteBegan) return;
    try {
      this._db._exec('COMMIT');
    } catch (_) {
      // Ignore
    }
    this._sqliteBegan = false;
  }

  /** @internal - Rollback the SQLite transaction */
  private _rollbackSqlite(): void {
    if (!this._sqliteBegan) return;
    try {
      this._db._exec('ROLLBACK');
    } catch (_) {
      // Ignore
    }
    this._sqliteBegan = false;
  }
}
