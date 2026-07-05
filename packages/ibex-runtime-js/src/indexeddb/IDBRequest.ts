// @ts-nocheck
/**
 * IDBRequest - IndexedDB Request
 *
 * Represents an asynchronous request to the database. IndexedDB's async model
 * uses onsuccess/onerror callbacks instead of Promises.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/IDBRequest
 */

import { DOMException } from './utils';

export type IDBRequestReadyState = 'pending' | 'done';

export class IDBRequest<T = any> {
  private _result: T | undefined = undefined;
  private _error: DOMException | null = null;
  private _readyState: IDBRequestReadyState = 'pending';
  private _source: any = null;
  private _transaction: any = null;
  /** @internal - EventTarget listeners keyed by event type */
  private _listeners: Record<string, Function[]> = {};

  onsuccess: ((event: any) => void) | null = null;
  onerror: ((event: any) => void) | null = null;

  get result(): T {
    if (this._readyState === 'pending') {
      throw new DOMException(
        'The request has not finished.',
        'InvalidStateError'
      );
    }
    return this._result as T;
  }

  get error(): DOMException | null {
    if (this._readyState === 'pending') {
      throw new DOMException(
        'The request has not finished.',
        'InvalidStateError'
      );
    }
    return this._error;
  }

  get readyState(): IDBRequestReadyState {
    return this._readyState;
  }

  get source(): any {
    return this._source;
  }

  set source(s: any) {
    this._source = s;
  }

  get transaction(): any {
    return this._transaction;
  }

  set transaction(t: any) {
    this._transaction = t;
  }

  addEventListener(type: string, fn: Function): void {
    if (!this._listeners[type]) this._listeners[type] = [];
    this._listeners[type].push(fn);
  }

  removeEventListener(type: string, fn: Function): void {
    const list = this._listeners[type];
    if (list) this._listeners[type] = list.filter(f => f !== fn);
  }

  /** @internal - Fire listeners for a given event type */
  private _fireListeners(type: string, event: any): void {
    const list = this._listeners[type];
    if (list) {
      for (const fn of list) {
        try {
          fn(event);
        } catch (e) {
          if (this._transaction && this._transaction._handleError) {
            this._transaction._handleError(e);
          }
        }
      }
    }
  }

  /** @internal - Resolve the request with a result */
  _resolve(value: T): void {
    this._readyState = 'done';
    this._result = value;
    this._error = null;
    // Fire onsuccess in a microtask to match async behavior.
    // Check onsuccess inside the microtask so handlers set after
    // _resolve() is called (but before the microtask runs) still fire.
    const event = { type: 'success', target: this };
    const tx = this._transaction;
    // Keep the owning transaction alive until this event has finished
    // dispatching, so a request issued from the onsuccess handler still runs
    // inside the same transaction (see IDBTransaction lifecycle notes).
    if (tx && tx._retain) tx._retain();
    queueMicrotask(() => {
      if (tx && tx._beginEventDispatch) tx._beginEventDispatch();
      try {
        if (this.onsuccess) {
          try {
            this.onsuccess(event);
          } catch (e) {
            // Errors in handlers propagate to transaction
            if (tx && tx._handleError) {
              tx._handleError(e);
            }
          }
        }
        this._fireListeners('success', event);
      } finally {
        if (tx && tx._endEventDispatch) tx._endEventDispatch();
        if (tx && tx._release) tx._release();
      }
    });
  }

  /** @internal - Reject the request with an error */
  _reject(error: DOMException | Error): void {
    this._readyState = 'done';
    this._error = error instanceof DOMException
      ? error
      : new DOMException(error.message, 'UnknownError');
    this._result = undefined as any;
    const event = { type: 'error', target: this };
    const tx = this._transaction;
    if (tx && tx._retain) tx._retain();
    queueMicrotask(() => {
      if (tx && tx._beginEventDispatch) tx._beginEventDispatch();
      try {
        if (this.onerror) {
          this.onerror(event);
        }
        this._fireListeners('error', event);
      } finally {
        if (tx && tx._endEventDispatch) tx._endEventDispatch();
        if (tx && tx._release) tx._release();
      }
    });
  }

  /** @internal - Resolve synchronously (used during upgradeneeded) */
  _resolveSync(value: T): void {
    this._readyState = 'done';
    this._result = value;
    this._error = null;
    const event = { type: 'success', target: this };
    if (this.onsuccess) {
      this.onsuccess(event);
    }
    this._fireListeners('success', event);
  }

  /**
   * @internal - Set the result value without changing readyState or firing events.
   * Used by IDBFactory.open() to make the result accessible to onupgradeneeded
   * handlers before the request formally completes.
   */
  _setResult(value: T): void {
    this._readyState = 'done';
    this._result = value;
    this._error = null;
  }
}

/**
 * IDBOpenDBRequest extends IDBRequest with onupgradeneeded and onblocked.
 */
export class IDBOpenDBRequest<T = any> extends IDBRequest<T> {
  onupgradeneeded: ((event: any) => void) | null = null;
  onblocked: ((event: any) => void) | null = null;
}
