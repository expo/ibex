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
  /**
   * @internal - Lifecycle state.
   *  - `active`: operations may be issued (during the creating task and while a
   *     bound request is dispatching its success/error event).
   *  - `inactive`: control has returned to the event loop; issuing an operation
   *     throws TransactionInactiveError until a bound event reactivates it.
   *  - `finished`: committed or aborted; terminal.
   */
  _state: 'active' | 'inactive' | 'finished' = 'active';
  /**
   * @internal - Count of requests bound to this transaction whose success/error
   * event has been scheduled but not yet finished dispatching. The transaction
   * auto-commits only when this reaches zero and it is no longer active, so
   * requests chained through nested onsuccess handlers all execute inside a
   * single SQLite BEGIN/COMMIT.
   */
  _pending = 0;
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

    // Begin a SQLite transaction for readwrite so writes can roll back on
    // abort. versionchange transactions are begun explicitly by IDBFactory.open
    // via _beginVersionChange() so schema changes roll back if upgrade throws.
    if (mode === 'readwrite') {
      this._beginSqlite();
    }

    // A readonly/readwrite transaction is active for the duration of the task
    // that created it, then goes inactive at the microtask checkpoint. Each
    // bound request reactivates it while its event handler runs. Auto-commit
    // fires once it is idle (no in-flight requests) and no longer active.
    if (mode !== 'versionchange') {
      queueMicrotask(() => {
        if (this._state === 'active') this._state = 'inactive';
        this._maybeAutoCommit();
      });
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
    if (this._state === 'finished') {
      throw new DOMException(
        'The transaction has finished.',
        'InvalidStateError',
      );
    }
    if (!this._storeNames.includes(name)) {
      throw new DOMException(
        `Object store "${name}" is not in this transaction's scope`,
        'NotFoundError',
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

  // ================================================================
  // Lifecycle: active-state gating and idle-driven auto-commit
  // ================================================================

  /**
   * @internal - Throw if an operation may not be issued right now. Matches the
   * spec requirement that add/put/get/... raise TransactionInactiveError when
   * the transaction is not active, rather than silently running SQL after the
   * transaction has committed.
   */
  _assertActive(): void {
    if (this._state !== 'active') {
      throw new DOMException(
        this._state === 'finished'
          ? 'The transaction has finished.'
          : 'The transaction is not active.',
        'TransactionInactiveError',
      );
    }
  }

  /** @internal - A bound request's event is about to be dispatched. */
  _beginEventDispatch(): void {
    if (this._state === 'inactive') this._state = 'active';
  }

  /** @internal - A bound request's event finished dispatching. */
  _endEventDispatch(): void {
    if (this._state === 'active') this._state = 'inactive';
  }

  /** @internal - A bound request has scheduled a success/error event. */
  _retain(): void {
    this._pending++;
  }

  /** @internal - A bound request's success/error event finished dispatching. */
  _release(): void {
    if (this._pending > 0) this._pending--;
    this._maybeAutoCommit();
  }

  /** @internal - Commit once no requests are in flight and control has yielded. */
  private _maybeAutoCommit(): void {
    if (this._state !== 'inactive') return;
    if (this._mode === 'versionchange') return;
    if (this._pending > 0) return;
    this.commit();
  }

  // ================================================================
  // SQLite transaction wrapping
  // ================================================================

  /** @internal - Begin the SQLite transaction backing a versionchange upgrade. */
  _beginVersionChange(): void {
    this._beginSqlite();
  }

  /** @internal - Commit a versionchange upgrade's schema/data changes. */
  _commitVersionChange(): void {
    this._committed = true;
    this._state = 'finished';
    this._commitSqlite();
  }

  /** @internal - Roll back a versionchange upgrade whose onupgradeneeded threw. */
  _abortVersionChange(): void {
    this._aborted = true;
    this._state = 'finished';
    this._rollbackSqlite();
  }

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
