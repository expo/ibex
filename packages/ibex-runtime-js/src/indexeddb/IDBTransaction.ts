// @ts-nocheck
/**
 * IDBTransaction - IndexedDB Transaction
 *
 * Groups database operations that must succeed or fail as a unit.
 *
 * Every connection to one database name shares a single SQLite handle, so at
 * most one transaction at a time may hold the SQLite BEGIN. Transactions are
 * therefore serialized by the shared-connection scheduler (see
 * SharedConnectionState in IDBDatabase): a transaction created while an
 * earlier one is live QUEUES — its operations are recorded and executed, in
 * creation order, once every earlier transaction has committed or aborted.
 * Previously a second concurrent readwrite transaction's BEGIN failed
 * silently and both transactions interleaved inside the first one's SQLite
 * transaction, so aborting one rolled back (or committed) the other's writes.
 * The spec requires transactions with overlapping scopes to run in creation
 * order; running ALL of a connection's transactions in creation order is a
 * conservative, spec-permitted schedule. (ENG-23117)
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBTransaction
 */

import { IDBObjectStore } from './IDBObjectStore';
import { DOMException, enqueueTask, makeDOMStringList } from './utils';

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
   *  - `active`: operations may be issued (during the task that created the
   *     transaction or dispatched one of its request events, AND during any
   *     microtasks that task queued — awaited request continuations must still
   *     see an active transaction, per the idb/Dexie pattern).
   *  - `inactive`: control has returned to the event loop (a full TASK
   *     boundary, after the microtask queue drained); issuing an operation
   *     throws TransactionInactiveError until a bound event reactivates it.
   *  - `finished`: committed or aborted; terminal.
   * (ENG-23446)
   */
  _state: 'active' | 'inactive' | 'finished' = 'active';
  /**
   * @internal - Depth of request success/error event dispatches currently on
   * the stack. Deactivation is suppressed while a dispatch is in progress.
   */
  private _dispatchDepth = 0;
  /** @internal - A deactivation task is already queued. */
  private _deactivatePending = false;
  /**
   * @internal - commit() was called: no further requests may be issued, and
   * the transaction commits as soon as its in-flight requests drain (without
   * waiting for the deactivation task).
   */
  private _commitRequested = false;
  /**
   * @internal - Runs inside the SQLite transaction immediately before COMMIT.
   * Used by versionchange upgrades to persist the version bump atomically
   * with the schema changes. (ENG-23446)
   */
  _beforeCommit: (() => void) | null = null;
  /**
   * @internal - Invoked exactly once when the transaction reaches a terminal
   * state, after its complete/abort event handlers have run:
   * `(committed, error)`. Used by IDBFactory.open to settle the open request
   * once the versionchange transaction finishes. (ENG-23446)
   */
  _onFinished: ((committed: boolean, error: any) => void) | null = null;
  /** @internal - _onFinished has already fired. */
  private _finishedNotified = false;
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
  /**
   * @internal - Whether the connection scheduler has started this transaction.
   * Until then operations queue in `_opQueue` and auto-commit is deferred.
   * (ENG-23117)
   */
  _started = false;
  /**
   * @internal - Operations issued while this transaction waited its turn.
   * Each entry's `run` performs the SQL and settles its request; `request` is
   * rejected with AbortError if the transaction aborts before starting.
   */
  private _opQueue: Array<{ request: any; run: () => void }> = [];
  /**
   * @internal - For versionchange transactions: the upgrade body, invoked by
   * the scheduler when the transaction may run (see IDBFactory.open).
   */
  _onStart: (() => void) | null = null;
  /** @internal - EventTarget listeners keyed by event type */
  private _listeners: Record<string, Function[]> = {};

  oncomplete: ((event: any) => void) | null = null;
  onerror: ((event: any) => void) | null = null;
  onabort: ((event: any) => void) | null = null;

  constructor(db: any, storeNames: string[], mode: IDBTransactionMode) {
    this._db = db;
    this._storeNames = [...storeNames];
    this._mode = mode;

    // Register with the connection's transaction scheduler. If no other
    // transaction is live this starts (and, for readwrite, BEGINs)
    // synchronously, so the transaction is usable during its creating task;
    // otherwise it queues until every earlier transaction finishes.
    // versionchange transactions are scheduled explicitly by IDBFactory.open
    // once their upgrade body (_onStart) is attached. (ENG-23117)
    if (mode !== 'versionchange') {
      db._scheduleTransaction(this);

      // A readonly/readwrite transaction is active for the duration of the
      // TASK that created it — including every microtask that task queues
      // (awaited request continuations) — then deactivates when control truly
      // returns to the event loop. Each bound request reactivates it while its
      // event dispatches. Auto-commit fires once it is idle (no in-flight
      // requests) and deactivated. (ENG-23446)
      this._scheduleDeactivation();
    }
  }

  get db(): any {
    return this._db;
  }

  get mode(): IDBTransactionMode {
    return this._mode;
  }

  get objectStoreNames(): string[] {
    // DOMStringList shape (contains()/item()), matching db.objectStoreNames —
    // consumers routinely call tx.objectStoreNames.contains(...). (ENG-23446)
    return makeDOMStringList([...this._storeNames].sort());
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
   *
   * Per spec this only refuses new requests; the actual COMMIT happens once
   * every in-flight (and still-queued) request has finished.
   */
  commit(): void {
    if (this._state === 'finished') return;
    // Per spec commit() puts the transaction in a "committing" state: no new
    // requests are accepted (see _assertActive), and the COMMIT happens as
    // soon as every in-flight (and still-queued) request has finished —
    // without waiting for the deactivation task. (ENG-23446)
    this._commitRequested = true;
    this._maybeAutoCommit();
  }

  /**
   * Abort the transaction.
   */
  abort(): void {
    this._abortWith(new DOMException('Transaction was aborted', 'AbortError'));
  }

  /**
   * @internal - Abort with a specific error: explicit abort(), a request error
   * event that no handler preventDefault()-ed, an exception thrown by a
   * success/error handler, or a BEGIN/COMMIT failure. Rolls back this
   * transaction's writes (and only this transaction's — see the scheduler
   * notes above), fails any operations that never got to run, and hands the
   * connection to the next queued transaction. (ENG-23117)
   */
  _abortWith(error: any): void {
    if (this._committed || this._aborted) return;
    this._aborted = true;
    this._state = 'finished';
    // Keep the caller's original error object for _onFinished (IDBFactory
    // rejects the open request with it verbatim), while transaction.error is
    // always a DOMException.
    const rawError = error;
    this._error = error instanceof DOMException
      ? error
      : new DOMException(error?.message ?? 'Transaction was aborted', 'AbortError');

    // Operations queued while waiting for the connection never ran; their
    // requests fail with AbortError per the spec's abort steps.
    const queued = this._opQueue;
    this._opQueue = [];

    this._rollbackSqlite();
    this._db._transactionFinished(this);

    for (const { request } of queued) {
      if (request) {
        request._abort(new DOMException('The transaction was aborted.', 'AbortError'));
      }
    }

    const event = { type: 'abort', target: this };
    queueMicrotask(() => {
      if (this.onabort) {
        this.onabort(event);
      }
      this._fireListeners('abort', event);
      // Per spec the abort event bubbles to the connection. (ENG-23446)
      this._bubbleToDb('abort', event);
      this._notifyFinished(false, rawError ?? this._error);
    });
  }

  /**
   * @internal - A bound request rejected and has finished dispatching its own
   * error handlers. The event bubbles to the transaction, and — per spec —
   * unless some handler called preventDefault(), the transaction aborts and
   * rolls back every write it performed. Previously the error was reported and
   * the transaction went on to COMMIT its partial writes. (ENG-23117)
   */
  _requestErrored(event: any, error: any): void {
    this._error = error instanceof DOMException
      ? error
      : new DOMException(error?.message ?? 'Unknown error', 'UnknownError');
    if (this.onerror) {
      try {
        this.onerror(event);
      } catch (e: any) {
        this._abortWith(new DOMException(
          e?.message ?? 'Exception in error handler',
          'AbortError',
        ));
      }
    }
    this._fireListeners('error', event);
    // Per spec the error event bubbles request -> transaction -> database.
    // Previously it stopped at the transaction, so db.onerror (the standard
    // catch-all logging hook) never fired. (ENG-23446)
    this._bubbleToDb('error', event);
    if (!event.defaultPrevented) {
      this._abortWith(this._error);
    }
  }

  /**
   * @internal - Bubble an event to the owning connection's `on<type>` handler
   * and addEventListener listeners. Handler exceptions are swallowed — the
   * transaction-level consequences (abort) were already decided at the
   * transaction hop. (ENG-23446)
   */
  private _bubbleToDb(type: string, event: any): void {
    const db = this._db;
    if (!db) return;
    const handler = db[`on${type}`];
    if (typeof handler === 'function') {
      try { handler.call(db, event); } catch (_) { /* swallow */ }
    }
    if (typeof db._fireListeners === 'function') {
      db._fireListeners(type, event);
    }
  }

  /** @internal - Fire _onFinished exactly once. */
  private _notifyFinished(committed: boolean, error: any): void {
    if (this._finishedNotified) return;
    this._finishedNotified = true;
    if (this._onFinished) this._onFinished(committed, error);
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
    if (this._state === 'finished') {
      throw new DOMException(
        'The transaction has finished.',
        'TransactionInactiveError',
      );
    }
    // After commit() the transaction refuses new requests even though its
    // event dispatches may still reactivate it. (ENG-23446)
    if (this._commitRequested || this._state !== 'active') {
      throw new DOMException(
        'The transaction is not active.',
        'TransactionInactiveError',
      );
    }
  }

  /**
   * @internal - Throw ReadOnlyError for a mutating operation on a readonly
   * transaction. Previously the mode was never enforced, so readonly writes
   * executed (outside any BEGIN) and even survived abort(). (ENG-23117)
   */
  _assertWritable(): void {
    if (this._mode === 'readonly') {
      throw new DOMException(
        'The transaction is read-only.',
        'ReadOnlyError',
      );
    }
  }

  /** @internal - A bound request's event is about to be dispatched. */
  _beginEventDispatch(): void {
    this._dispatchDepth++;
    if (this._state === 'inactive') this._state = 'active';
  }

  /**
   * @internal - A bound request's event finished dispatching. The transaction
   * stays ACTIVE: promise continuations queued during the dispatch (idb-style
   * `await request`) run as microtasks and must still be able to issue
   * requests. Deactivation happens in a separate TASK, after the microtask
   * queue has drained. (ENG-23446)
   */
  _endEventDispatch(): void {
    if (this._dispatchDepth > 0) this._dispatchDepth--;
    this._scheduleDeactivation();
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

  /**
   * @internal - Queue a task (macrotask) that deactivates the transaction and
   * attempts the auto-commit. Because it is a TASK, every microtask queued by
   * the creating task or an event dispatch — awaited request continuations
   * included — runs first; a request issued from such a continuation keeps the
   * transaction alive (its own dispatch re-schedules deactivation).
   * (ENG-23446)
   */
  _scheduleDeactivation(): void {
    if (this._deactivatePending || this._state === 'finished') return;
    this._deactivatePending = true;
    enqueueTask(() => {
      this._deactivatePending = false;
      if (this._state === 'active' && this._dispatchDepth === 0) {
        this._state = 'inactive';
      }
      this._maybeAutoCommit();
    });
  }

  /** @internal - Commit once no requests are in flight and control has yielded. */
  private _maybeAutoCommit(): void {
    if (this._state === 'finished') return;
    // Not started yet: queued behind an earlier transaction. Its queued
    // operations must still run (and their events dispatch) before committing.
    if (!this._started) return;
    if (this._pending > 0) return;
    if (this._opQueue.length > 0) return;
    if (this._commitRequested) {
      // Explicit commit(): fire as soon as the current dispatch (if any)
      // unwinds — do not wait for the deactivation task.
      if (this._dispatchDepth > 0) return;
    } else if (this._state !== 'inactive') {
      return;
    }
    this._finishCommit();
  }

  // ================================================================
  // Scheduling: deferred operations (ENG-23117)
  // ================================================================

  /**
   * @internal - Execute an operation now if this transaction has started, or
   * queue it until the scheduler starts the transaction. `request` (nullable)
   * is rejected with AbortError if the transaction aborts before starting.
   */
  _enqueueOp(request: any, run: () => void): void {
    if (this._started) {
      run();
      return;
    }
    this._opQueue.push({ request, run });
  }

  /**
   * @internal - Called by the connection scheduler when this transaction may
   * run: issues BEGIN (readwrite), then executes the operations that queued
   * while it waited. versionchange transactions instead run their upgrade
   * body, which manages BEGIN/COMMIT itself.
   */
  _start(): void {
    if (this._started || this._state === 'finished') return;
    this._started = true;

    if (this._mode === 'readwrite') {
      try {
        this._beginSqlite();
      } catch (e: any) {
        // Fail loud: a transaction that cannot BEGIN has no rollback boundary,
        // so running its writes anyway would break atomicity. (ENG-23117)
        this._abortWith(new DOMException(
          `Could not begin transaction: ${e?.message ?? e}`,
          'UnknownError',
        ));
        return;
      }
    }

    if (this._onStart) {
      const run = this._onStart;
      this._onStart = null;
      run();
      return;
    }

    while (this._opQueue.length > 0 && this._state !== 'finished') {
      const op = this._opQueue.shift()!;
      op.run();
    }
    this._maybeAutoCommit();
  }

  /** @internal - createObjectStore adds the new store to the upgrade scope. */
  _addToScope(name: string): void {
    if (!this._storeNames.includes(name)) this._storeNames.push(name);
  }

  /** @internal - deleteObjectStore removes the store from the upgrade scope. */
  _removeFromScope(name: string): void {
    this._storeNames = this._storeNames.filter(n => n !== name);
    this._stores.delete(name);
  }

  // ================================================================
  // SQLite transaction wrapping
  // ================================================================

  /** @internal - Finish a transaction by committing. */
  private _finishCommit(): void {
    if (this._state === 'finished') return;
    this._state = 'finished';

    if (this._sqliteBegan) {
      try {
        // Work that must be atomic with the transaction's writes (the
        // versionchange version bump) runs inside the BEGIN, right before
        // COMMIT. (ENG-23446)
        if (this._beforeCommit) this._beforeCommit();
        this._db._exec('COMMIT');
        this._sqliteBegan = false;
        this._db._commitTxnSnapshot();
      } catch (e: any) {
        // COMMIT failed (SQLITE_FULL/BUSY/IOERR — realistic on a full mobile
        // disk): the writes are NOT durable. Roll back and report 'abort' with
        // the underlying error; firing 'complete' here would tell the app its
        // data persisted when it did not. (ENG-23117)
        this._aborted = true;
        this._error = new DOMException(
          `Transaction commit failed: ${e?.message ?? e}`,
          'UnknownError',
        );
        try {
          this._db._exec('ROLLBACK');
        } catch (_) {
          // Best-effort: after a failed COMMIT, SQLite has usually rolled the
          // transaction back already; the abort event carries the COMMIT error.
        }
        this._sqliteBegan = false;
        this._db._rollbackTxnSnapshot();
        this._db._transactionFinished(this);
        const abortEvent = { type: 'abort', target: this };
        queueMicrotask(() => {
          if (this.onabort) {
            this.onabort(abortEvent);
          }
          this._fireListeners('abort', abortEvent);
          this._bubbleToDb('abort', abortEvent);
          this._notifyFinished(false, this._error);
        });
        return;
      }
    }

    this._committed = true;
    this._db._transactionFinished(this);
    const event = { type: 'complete', target: this };
    queueMicrotask(() => {
      if (this.oncomplete) {
        this.oncomplete(event);
      }
      this._fireListeners('complete', event);
      // 'complete' fires on the transaction BEFORE the open request's success
      // (versionchange), matching the spec's event order. (ENG-23446)
      this._notifyFinished(true, null);
    });
  }

  /**
   * @internal - Begin the SQLite transaction backing a versionchange upgrade
   * and (re)activate it for the upgradeneeded dispatch. From here the upgrade
   * transaction lives the same lifecycle as any other transaction: it stays
   * active through the dispatching task's microtasks (idb-style awaited
   * upgrades work) and auto-commits once idle and deactivated; IDBFactory
   * observes the outcome through _beforeCommit/_onFinished. (ENG-23446)
   */
  _beginVersionChange(): void {
    this._started = true;
    this._state = 'active';
    this._beginSqlite();
  }

  /**
   * @internal - Begin a SQLite transaction. Throws on failure — the scheduler
   * guarantees no other transaction holds the connection's BEGIN, so a failure
   * here is a real error (e.g. SQLITE_BUSY from another process), and
   * swallowing it is exactly what let overlapping transactions interleave
   * inside one another's BEGIN. (ENG-23117)
   */
  private _beginSqlite(): void {
    if (this._sqliteBegan) return;
    this._db._exec('BEGIN TRANSACTION');
    this._sqliteBegan = true;
    // Snapshot the connection-level caches (autoIncrement key generators,
    // keyenc/index-table migration memos): SQLite DDL is transactional, so a
    // rollback that undoes a lazy ALTER/CREATE must also undo the memo that
    // says it happened. (ENG-23117)
    this._db._beginTxnSnapshot();
  }

  /** @internal - Roll back the SQLite transaction. */
  private _rollbackSqlite(): void {
    if (!this._sqliteBegan) return;
    this._sqliteBegan = false;
    try {
      this._db._exec('ROLLBACK');
    } catch (e: any) {
      // Surface a failed ROLLBACK instead of reporting a clean abort: the
      // transaction's writes may have persisted. (ENG-23117)
      this._error = new DOMException(
        `Transaction rollback failed: ${e?.message ?? e}`,
        'UnknownError',
      );
    }
    // Whether or not ROLLBACK succeeded the cached generators/memos may no
    // longer match disk — restore the pre-transaction snapshot.
    this._db._rollbackTxnSnapshot();
  }
}
