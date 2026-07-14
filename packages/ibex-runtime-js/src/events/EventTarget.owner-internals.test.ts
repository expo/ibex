import { expect, test } from "bun:test";

import { EventTarget } from "./EventTarget";

function poisonLegacyInternalHelpers(
  target: EventTarget,
  calls: Array<{ name: string; args: unknown[] }>
): void {
  const record = (name: string, result?: unknown) =>
    (...args: unknown[]) => {
      calls.push({ name, args });
      return result;
    };

  Object.defineProperties(target, {
    normalizeDispatchEventArgument: {
      configurable: true,
      value: (...args: unknown[]) => {
        calls.push({ name: "normalizeDispatchEventArgument", args });
        return args[0];
      },
    },
    _listenerMap: {
      configurable: true,
      value: record("_listenerMap", new Map()),
    },
    _deactivateEntry: {
      configurable: true,
      value: record("_deactivateEntry"),
    },
    compactListeners: {
      configurable: true,
      value: record("compactListeners"),
    },
  });
}

test("captured EventTarget dispatch never calls shadowed internal helpers", () => {
  let admitted = true;
  const target = new EventTarget(() => {
    if (!admitted) {
      throw new Error("ERR_CAPABILITY_PRINCIPAL");
    }
  });
  const received: string[] = [];
  target.addEventListener(
    "message",
    ((event: { data: string }) => received.push(event.data)) as any,
    { once: true }
  );

  const poisonedCalls: Array<{ name: string; args: unknown[] }> = [];
  poisonLegacyInternalHelpers(target, poisonedCalls);
  const capturedDispatch = EventTarget.prototype.dispatchEvent;

  expect(capturedDispatch.call(target, { type: "message", data: "owner secret" })).toBe(true);
  expect(received).toEqual(["owner secret"]);
  expect(poisonedCalls).toEqual([]);

  // Once-listener deactivation and post-dispatch compaction also stay on the
  // module-private path rather than consulting poisoned instance properties.
  expect(capturedDispatch.call(target, { type: "message", data: "second" })).toBe(true);
  expect(received).toEqual(["owner secret"]);
  expect(poisonedCalls).toEqual([]);

  admitted = false;
  let eventReads = 0;
  expect(() => capturedDispatch.call(target, {
    get type() {
      eventReads++;
      return "message";
    },
  } as any)).toThrow("ERR_CAPABILITY_PRINCIPAL");
  expect(eventReads).toBe(0);
  expect(poisonedCalls).toEqual([]);
});

test("AbortSignal cleanup admits before touching private listener state", () => {
  let admitted = true;
  const target = new EventTarget(() => {
    if (!admitted) {
      throw new Error("ERR_CAPABILITY_PRINCIPAL");
    }
  });
  let abortListener: (() => void) | undefined;
  let signalCleanupCalls = 0;
  const signal = {
    aborted: false,
    addEventListener(type: string, listener: () => void) {
      expect(type).toBe("abort");
      abortListener = listener;
    },
    removeEventListener(type: string, listener: () => void) {
      expect(type).toBe("abort");
      expect(listener).toBe(abortListener);
      signalCleanupCalls++;
    },
  };
  let delivered = 0;
  target.addEventListener("message", () => delivered++, { signal });
  expect(abortListener).toBeDefined();

  const poisonedCalls: Array<{ name: string; args: unknown[] }> = [];
  poisonLegacyInternalHelpers(target, poisonedCalls);

  // A signal can fire later under a foreign principal. It must fail before a
  // poisoned helper receives the closure-private ListenerEntry.
  admitted = false;
  expect(() => abortListener!()).toThrow("ERR_CAPABILITY_PRINCIPAL");
  expect(poisonedCalls).toEqual([]);
  expect(signalCleanupCalls).toBe(0);

  admitted = true;
  abortListener!();
  expect(poisonedCalls).toEqual([]);
  expect(signalCleanupCalls).toBe(1);

  EventTarget.prototype.dispatchEvent.call(target, { type: "message" });
  expect(delivered).toBe(0);
  expect(poisonedCalls).toEqual([]);
});
