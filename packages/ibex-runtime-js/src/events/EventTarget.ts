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

type EventTargetAdmission = (target: object) => void;

// Some EventTargets front owner-bound native resources. Listener maps and
// their admission hooks must not live in forgeable `_` fields: a retained
// foreign wrapper could otherwise subscribe to inbound data by calling a
// saved base-prototype method or by mutating the listener table directly.
// @ref LLP 0004#retained-native-wrapper-invariant — event state and every internal path stay owner-authenticated and module-private
const eventTargetListenerMaps = new WeakMap<object, Map<string, ListenerEntry[]>>();
const eventTargetAdmissions = new WeakMap<object, EventTargetAdmission>();

function assertEventTargetAccess(target: object): void {
  eventTargetAdmissions.get(target)?.(target);
}

function eventTargetListenerMap(target: object): Map<string, ListenerEntry[]> {
  assertEventTargetAccess(target);
  let listeners = eventTargetListenerMaps.get(target);
  if (!listeners) {
    // Some builtins graft EventTarget's prototype onto their own class without
    // running this constructor (for example Performance). Preserve that
    // compatibility without storing authoritative state on the instance.
    listeners = new Map();
    eventTargetListenerMaps.set(target, listeners);
  }
  return listeners;
}

function deactivateEventTargetEntry(target: object, entry: ListenerEntry): void {
  // AbortSignal callbacks may run later under a different principal. Admit
  // before reading or mutating the closure-private listener entry.
  assertEventTargetAccess(target);
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

function compactEventTargetListeners(target: object, type: string): void {
  const map = eventTargetListenerMap(target);
  const listeners = map.get(type);
  if (!listeners) {
    return;
  }

  const activeListeners = listeners.filter((listener) => !listener.removed);
  if (activeListeners.length === 0) {
    map.delete(type);
  } else if (activeListeners.length !== listeners.length) {
    map.set(type, activeListeners);
  }
}

function normalizeDispatchEventArgument(
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

export class EventTarget {
  constructor(...internalAdmissions: EventTargetAdmission[]) {
    const admission = internalAdmissions[0];
    if (admission !== undefined) {
      if (typeof admission !== "function") {
        throw new TypeError("Internal EventTarget admission must be a function");
      }
      eventTargetAdmissions.set(this, admission);
    }
    eventTargetListenerMaps.set(this, new Map());
  }

  // Preserve the historical compatibility field as an authenticated
  // projection while keeping the authoritative map module-private.
  private get _listeners(): Map<string, ListenerEntry[]> {
    return eventTargetListenerMap(this);
  }

  private set _listeners(value: Map<string, ListenerEntry[]>) {
    assertEventTargetAccess(this);
    if (!(value instanceof Map)) {
      throw new TypeError("EventTarget listener map must be a Map");
    }
    eventTargetListenerMaps.set(this, value);
  }

  addEventListener(
    type: string,
    callback: EventListenerOrEventListenerObject | null,
    options?: AddEventListenerOptions | boolean
  ): void {
    assertEventTargetAccess(this);
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

    const map = eventTargetListenerMap(this);
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
        deactivateEventTargetEntry(this, entry);
        compactEventTargetListeners(this, type);
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
    assertEventTargetAccess(this);
    if (callback === null) {
      return;
    }

    const capture =
      typeof options === "boolean" ? options : options?.capture ?? false;

    const listeners = eventTargetListenerMap(this).get(type);
    if (!listeners) {
      return;
    }

    const index = listeners.findIndex(
      (l) => l.callback === callback && l.capture === capture && !l.removed
    );

    if (index !== -1) {
      deactivateEventTargetEntry(this, listeners[index]);
      compactEventTargetListeners(this, type);
    }
  }

  dispatchEvent(event: Event | string | { type: string; [key: string]: unknown }): boolean {
    assertEventTargetAccess(this);
    const dispatchEvent = normalizeDispatchEventArgument(event);

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

      const listeners = eventTargetListenerMap(this).get(dispatchEvent.type);
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
            deactivateEventTargetEntry(this, entry);
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

        compactEventTargetListeners(this, dispatchEvent.type);
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

  /**
   * Helper to check if there are any listeners for a type
   */
  protected hasListeners(type: string): boolean {
    assertEventTargetAccess(this);
    const listeners = eventTargetListenerMap(this).get(type);
    return listeners ? listeners.some((l) => !l.removed) : false;
  }
}
