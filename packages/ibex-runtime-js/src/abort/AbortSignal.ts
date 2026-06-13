/**
 * AbortSignal - Web Standard AbortSignal Implementation
 *
 * @see https://dom.spec.whatwg.org/#interface-abortsignal
 */

import { Event, EventTarget } from "../events";
import { DOMException } from "../events";

const ABORT_SIGNAL_BRAND = Symbol.for("@exact/AbortSignal");

export function isAbortSignal(value: unknown): value is AbortSignal {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  if ((value as { [ABORT_SIGNAL_BRAND]?: true })[ABORT_SIGNAL_BRAND] === true) {
    return true;
  }

  try {
    return (
      typeof (value as { aborted?: unknown }).aborted === "boolean" &&
      "reason" in (value as object) &&
      typeof (value as { addEventListener?: unknown }).addEventListener === "function" &&
      typeof (value as { removeEventListener?: unknown }).removeEventListener === "function"
    );
  } catch {
    return false;
  }
}

export class AbortSignal extends EventTarget {
  private [ABORT_SIGNAL_BRAND] = true;

  private _aborted: boolean = false;
  private _reason: any = undefined;

  // Event handler property
  onabort: ((this: AbortSignal, ev: Event) => any) | null = null;

  constructor() {
    super();
    // Private constructor - use static methods or AbortController
  }

  get aborted(): boolean {
    return this._aborted;
  }

  get reason(): any {
    return this._reason;
  }

  throwIfAborted(): void {
    if (this._aborted) {
      throw this._reason;
    }
  }

  /**
   * Abort the signal
   * @internal - Called by AbortController
   */
  _abort(reason?: any): void {
    if (this._aborted) return;

    this._aborted = true;
    this._reason =
      reason === undefined
        ? new DOMException("The operation was aborted.", "AbortError")
        : reason;

    // Dispatch abort event
    const event = new Event("abort");
    
    // Call handler property
    if (this.onabort) {
      try {
        this.onabort.call(this, event);
      } catch (e) {
        console.error("Error in onabort handler:", e);
      }
    }

    // Dispatch to listeners
    this.dispatchEvent(event);
  }

  /**
   * Create an already-aborted signal
   */
  static abort(reason?: any): AbortSignal {
    const signal = new AbortSignal();
    signal._abort(reason);
    return signal;
  }

  /**
   * Create a signal that aborts after a timeout
   */
  static timeout(milliseconds: number): AbortSignal {
    const signal = new AbortSignal();

    setTimeout(() => {
      signal._abort(new DOMException("The operation timed out.", "TimeoutError"));
    }, milliseconds);

    return signal;
  }

  /**
   * Create a signal that aborts when any of the given signals abort
   */
  static any(signals: AbortSignal[]): AbortSignal {
    const signal = new AbortSignal();

    // Check if any signal is already aborted
    for (const s of signals) {
      if (s.aborted) {
        signal._abort(s.reason);
        return signal;
      }
    }

    // Listen for abort on all signals
    const listeners = new Map<AbortSignal, () => void>();
    const cleanup = () => {
      for (const [source, listener] of listeners) {
        source.removeEventListener("abort", listener);
      }
      listeners.clear();
    };

    const onAbort = () => {
      for (const s of signals) {
        if (s.aborted) {
          cleanup();
          signal._abort(s.reason);
          break;
        }
      }
    };

    for (const s of signals) {
      listeners.set(s, onAbort);
      s.addEventListener("abort", onAbort, { once: true });
    }

    return signal;
  }
}
