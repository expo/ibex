// @ts-nocheck
/**
 * EventTarget - Web Standard EventTarget Implementation
 *
 * @see https://dom.spec.whatwg.org/#interface-eventtarget
 */

import { Event } from "./Event";

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
}

export class EventTarget {
  private _listeners: Map<string, ListenerEntry[]> = new Map();
  private compactListeners(type: string): void {
    const listeners = this._listeners.get(type);
    if (!listeners) {
      return;
    }

    const activeListeners = listeners.filter((l) => !l.removed);
    if (activeListeners.length === 0) {
      this._listeners.delete(type);
    } else if (activeListeners.length !== listeners.length) {
      this._listeners.set(type, activeListeners);
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

    let listeners = this._listeners.get(type);
    if (!listeners) {
      listeners = [];
      this._listeners.set(type, listeners);
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
        entry.removed = true;
        this.compactListeners(type);
      };
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

    const listeners = this._listeners.get(type);
    if (!listeners) {
      return;
    }

    const index = listeners.findIndex(
      (l) => l.callback === callback && l.capture === capture && !l.removed
    );

    if (index !== -1) {
      listeners[index].removed = true;
      this.compactListeners(type);
    }
  }

  dispatchEvent(event: Event | string | { type: string; [key: string]: unknown }): boolean {
    const dispatchEvent = this.normalizeDispatchEventArgument(event);

    // Set target
    (dispatchEvent as any)._setTarget(this);
    (dispatchEvent as any)._setCurrentTarget(this);
    (dispatchEvent as any)._setEventPhase(Event.AT_TARGET);

    const listeners = this._listeners.get(dispatchEvent.type);
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

        // Mark for removal if once
        if (entry.once) {
          entry.removed = true;
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
    
    const result = !dispatchEvent.defaultPrevented;
    
    // Reset flags after dispatch so event can be re-dispatched
    (dispatchEvent as any)._resetFlags();

    return result;
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
    const listeners = this._listeners.get(type);
    return listeners ? listeners.some((l) => !l.removed) : false;
  }
}
