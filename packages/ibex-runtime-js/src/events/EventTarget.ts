// @ts-nocheck
/**
 * EventTarget - Web Standard EventTarget Implementation
 *
 * @see https://dom.spec.whatwg.org/#interface-eventtarget
 */

import { Event } from "./Event";
import { createInvalidStateError } from "./DOMException";

export type EventListener = (event: Event) => void;

export interface EventListenerObject {
  handleEvent(event: Event): void;
}

export type EventListenerOrEventListenerObject =
  | EventListener
  | EventListenerObject;

export interface AddEventListenerOptions {
  capture?: boolean;
  once?: boolean;
  passive?: boolean;
  signal?: any; // AbortSignal - use 'any' to avoid circular dependency
}

export interface EventListenerOptions {
  capture?: boolean;
}

interface ListenerEntry {
  callback: EventListenerOrEventListenerObject;
  capture: boolean;
  once: boolean;
  passive: boolean;
  removed: boolean;
  signal?: any; // AbortSignal - use 'any' to avoid circular dependency
  abortListener?: () => void; // the "abort" listener registered on `signal`
}

export class EventTarget {
  private _listeners: Map<string, ListenerEntry[]> = new Map();

  // Lazily resolve the listener storage. Some builtins graft EventTarget's
  // prototype onto their own class via Object.setPrototypeOf WITHOUT running
  // EventTarget's constructor (e.g. Performance, WebSocket) so the instance
  // field initializer above never runs and `_listeners` is undefined. Accessing
  // it through this helper means those instances get working listener storage
  // instead of throwing on the first addEventListener/dispatchEvent. (ENG-22985)
  private _listenerMap(): Map<string, ListenerEntry[]> {
    if (!this._listeners) {
      this._listeners = new Map();
    }
    return this._listeners;
  }

  // Deactivate a listener entry: mark it removed AND unregister the "abort"
  // listener it installed on its AbortSignal (if any). Without unregistering,
  // removing a listener (or a once-listener firing) leaves a closure on a
  // long-lived signal that strongly retains this EventTarget until the signal
  // aborts (possibly never) -- a per-render leak with `{signal}`. (ENG-22985)
  private _deactivateEntry(entry: ListenerEntry): void {
    if (entry.removed) {
      return;
    }
    entry.removed = true;
    const abortListener = entry.abortListener;
    const signal = entry.signal;
    entry.abortListener = undefined;
    entry.signal = undefined;
    if (signal && abortListener) {
      try {
        signal.removeEventListener("abort", abortListener);
      } catch {
        // Best-effort: never let signal cleanup break listener removal.
      }
    }
  }

  private compactListeners(type: string): void {
    const map = this._listenerMap();
    const listeners = map.get(type);
    if (!listeners) {
      return;
    }

    const activeListeners = listeners.filter((l) => !l.removed);
    if (activeListeners.length === 0) {
      map.delete(type);
    } else if (activeListeners.length !== listeners.length) {
      map.set(type, activeListeners);
    }
  }

  addEventListener(
    type: string,
    callback: EventListenerOrEventListenerObject | null,
    options?: AddEventListenerOptions | boolean
  ): void {
    if (callback === null) {
      return;
    }

    const capture =
      typeof options === "boolean" ? options : options?.capture ?? false;
    const once = typeof options === "object" ? options?.once ?? false : false;
    const passive =
      typeof options === "object" ? options?.passive ?? false : false;
    const signal =
      typeof options === "object" ? options?.signal : undefined;

    // If signal is already aborted, don't add
    if (signal?.aborted) {
      return;
    }

    const map = this._listenerMap();
    let listeners = map.get(type);
    if (!listeners) {
      listeners = [];
      map.set(type, listeners);
    }

    // Check if already exists (same callback and capture)
    const exists = listeners.some(
      (l) =>
        l.callback === callback && l.capture === capture && !l.removed
    );
    if (exists) {
      return;
    }

    const entry: ListenerEntry = {
      callback,
      capture,
      once,
      passive,
      removed: false,
      signal,
    };

    listeners.push(entry);

    // Handle abort signal
    if (signal) {
      const removeOnAbort = () => {
        this._deactivateEntry(entry);
        this.compactListeners(type);
      };
      entry.abortListener = removeOnAbort;
      signal.addEventListener("abort", removeOnAbort, { once: true });
    }
  }

  removeEventListener(
    type: string,
    callback: EventListenerOrEventListenerObject | null,
    options?: EventListenerOptions | boolean
  ): void {
    if (callback === null) {
      return;
    }

    const capture =
      typeof options === "boolean" ? options : options?.capture ?? false;

    const listeners = this._listenerMap().get(type);
    if (!listeners) {
      return;
    }

    const index = listeners.findIndex(
      (l) => l.callback === callback && l.capture === capture && !l.removed
    );

    if (index !== -1) {
      this._deactivateEntry(listeners[index]);
      this.compactListeners(type);
    }
  }

  dispatchEvent(event: Event | string | { type: string; [key: string]: unknown }): boolean {
    const dispatchEvent = this.normalizeDispatchEventArgument(event);

    // Per DOM spec, dispatching an Event whose dispatch flag is already set
    // throws InvalidStateError. This both matches the spec and stops a listener
    // that re-dispatches the SAME Event from clobbering the outer dispatch's
    // propagation/canceled flags mid-flight. (ENG-22985)
    if (
      typeof (dispatchEvent as any)._isBeingDispatched === "function" &&
      (dispatchEvent as any)._isBeingDispatched()
    ) {
      throw createInvalidStateError(
        "Failed to execute 'dispatchEvent' on 'EventTarget': The event is already being dispatched."
      );
    }
    if (typeof (dispatchEvent as any)._setDispatchFlag === "function") {
      (dispatchEvent as any)._setDispatchFlag(true);
    }

    try {
      // Set target
      (dispatchEvent as any)._setTarget(this);
      (dispatchEvent as any)._setCurrentTarget(this);
      (dispatchEvent as any)._setEventPhase(Event.AT_TARGET);

      const listeners = this._listenerMap().get(dispatchEvent.type);
      if (listeners) {
        // Create a copy to iterate (listeners may be modified during iteration)
        const listenersCopy = [...listeners];

        for (const entry of listenersCopy) {
          if (entry.removed) {
            continue;
          }

          if ((dispatchEvent as any)._isImmediatePropagationStopped()) {
            break;
          }

          // Remove if once (also unregisters any AbortSignal cleanup listener)
          if (entry.once) {
            this._deactivateEntry(entry);
          }

          // Set passive flag before calling listener
          (dispatchEvent as any)._setInPassiveListener(entry.passive);

          try {
            if (typeof entry.callback === "function") {
              entry.callback.call(this, dispatchEvent);
            } else {
              entry.callback.handleEvent(dispatchEvent);
            }
          } catch (error) {
            // Report error but continue with other listeners
            console.error("Error in event listener:", error);
          } finally {
            // Reset passive flag after listener
            (dispatchEvent as any)._setInPassiveListener(false);
          }
        }

        this.compactListeners(dispatchEvent.type);
      }

      // Reset event state for potential re-dispatch
      (dispatchEvent as any)._setCurrentTarget(null);
      (dispatchEvent as any)._setEventPhase(Event.NONE);

      // Per spec, the return value is false iff the canceled flag is set. The
      // canceled (defaultPrevented) flag is intentionally NOT cleared by
      // _resetFlags, so it stays observable after this returns. (ENG-22985)
      const result = !dispatchEvent.defaultPrevented;

      // Reset only the propagation flags so the event can be re-dispatched.
      (dispatchEvent as any)._resetFlags();

      return result;
    } finally {
      if (typeof (dispatchEvent as any)._setDispatchFlag === "function") {
        (dispatchEvent as any)._setDispatchFlag(false);
      }
    }
  }

  private normalizeDispatchEventArgument(
    event: Event | string | { type: string; [key: string]: unknown }
  ): Event {
    if (!event) {
      throw new TypeError(
        "Failed to execute 'dispatchEvent' on 'EventTarget': parameter 1 is not of type 'Event'."
      );
    }

    if (typeof event === "string") {
      event = new Event(event) as unknown as Event;
    }

    if (
      typeof (event as any)._setTarget === "function" &&
      typeof (event as any)._setCurrentTarget === "function" &&
      typeof (event as any)._setEventPhase === "function" &&
      typeof (event as any)._resetFlags === "function"
    ) {
      return event;
    }

    if (typeof (event as any).type !== "string") {
      throw new TypeError(
        "Failed to execute 'dispatchEvent' on 'EventTarget': parameter 1 is not of type 'Event'."
      );
    }

    const source = event as Event & {
      bubbles?: boolean;
      cancelable?: boolean;
      composed?: boolean;
    };
    const wrapped = new Event(source.type, {
      bubbles: source.bubbles ?? false,
      cancelable: source.cancelable ?? false,
      composed: source.composed ?? false,
    }) as Event;

    for (const key of Object.keys(source as Record<string, unknown>)) {
      if (
        key === "type" ||
        key === "bubbles" ||
        key === "cancelable" ||
        key === "composed" ||
        key === "defaultPrevented" ||
        key === "isTrusted" ||
        key === "timeStamp" ||
        key === "target" ||
        key === "currentTarget" ||
        key === "eventPhase" ||
        key === "detail"
      ) {
        continue;
      }

      const wrappedDescriptor =
        Object.getOwnPropertyDescriptor(wrapped, key) ||
        Object.getOwnPropertyDescriptor(Object.getPrototypeOf(wrapped), key);
      if (
        wrappedDescriptor &&
        ((wrappedDescriptor.writable === false && wrappedDescriptor.set === undefined) ||
          wrappedDescriptor.get !== undefined)
      ) {
        continue;
      }
      (wrapped as any)[key] = (source as Record<string, unknown>)[key];
    }

    return wrapped;
  }

  /**
   * Helper to check if there are any listeners for a type
   */
  protected hasListeners(type: string): boolean {
    const listeners = this._listenerMap().get(type);
    return listeners ? listeners.some((l) => !l.removed) : false;
  }
}
