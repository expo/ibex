/**
 * requestIdleCallback / cancelIdleCallback implementation for Ibex runtime
 * 
 * Schedules callbacks to run during idle periods.
 * @see https://w3c.github.io/requestidlecallback/
 */

import { getNativeModule } from '../native/NativeModules';

export interface IdleRequestOptions {
  timeout?: number;
}

export interface IdleDeadline {
  readonly didTimeout: boolean;
  timeRemaining(): number;
}

export type IdleRequestCallback = (deadline: IdleDeadline) => void;

// Callback storage
interface PendingCallback {
  callback: IdleRequestCallback;
  timeout?: number;
  scheduledTime: number;
  // Handle of the per-callback timeout timer (fallback path only), so it can be
  // cancelled when the callback runs or is cancelled instead of leaking a
  // full-duration timer + closure. (ENG-22985)
  timeoutHandle?: ReturnType<typeof setTimeout>;
}

const callbacks = new Map<number, PendingCallback>();
let nextId = 1;
let isScheduled = false;

// Idle period is typically 50ms max per spec recommendation
const MAX_IDLE_PERIOD = 50;
// How often to check for idle time
const IDLE_CHECK_INTERVAL = 100;

/**
 * Requests that a callback be called during an idle period.
 * Returns an ID that can be used to cancel the request.
 */
export function requestIdleCallback(
  callback: IdleRequestCallback,
  options?: IdleRequestOptions
): number {
  if (typeof callback !== 'function') {
    throw new TypeError('Failed to execute \'requestIdleCallback\': parameter 1 is not of type \'Function\'.');
  }

  const id = nextId++;
  const timeout = options?.timeout;
  const scheduledTime = performance?.now?.() ?? Date.now();

  callbacks.set(id, {
    callback,
    timeout,
    scheduledTime,
  });

  // Check for native implementation
  const nativeScheduling = getNativeModule('scheduling');
  if (nativeScheduling?.requestIdleCallback) {
    nativeScheduling.requestIdleCallback((deadline: IdleDeadline) => {
      runCallback(id, deadline);
    }, options);
    return id;
  }

  // Fallback: simulate idle callback using setTimeout
  scheduleIdleCheck();

  // If timeout is specified, ensure callback runs within that time. Store the
  // timer handle so it is cancelled once the callback runs or is cancelled;
  // otherwise every completed request leaves a dead full-duration timer +
  // closure pending. (ENG-22985)
  if (timeout !== undefined && timeout > 0) {
    const timeoutHandle = setTimeout(() => {
      const pending = callbacks.get(id);
      if (pending) {
        runCallback(id, createDeadline(true, 0));
      }
    }, timeout);
    const pending = callbacks.get(id);
    if (pending) {
      pending.timeoutHandle = timeoutHandle;
    }
  }

  return id;
}

/**
 * Cancels a previously scheduled idle callback.
 */
export function cancelIdleCallback(id: number): void {
  const pending = callbacks.get(id);
  if (pending?.timeoutHandle !== undefined) {
    clearTimeout(pending.timeoutHandle);
  }
  callbacks.delete(id);
}

/**
 * Schedule a check for idle time.
 */
function scheduleIdleCheck(): void {
  if (isScheduled || callbacks.size === 0) {
    return;
  }

  isScheduled = true;

  // Use setTimeout as a simple idle heuristic
  // In practice, if we're running this callback, the main thread is likely idle
  setTimeout(() => {
    isScheduled = false;
    runIdleCallbacks();
  }, IDLE_CHECK_INTERVAL);
}

/**
 * Run callbacks that can fit in the current idle period.
 */
function runIdleCallbacks(): void {
  const now = performance?.now?.() ?? Date.now();
  const idleDeadline = now + MAX_IDLE_PERIOD;

  // Snapshot the handles present at the start of this idle period. Iterating the
  // live Map would also visit callbacks that requestIdleCallback inserts DURING
  // iteration (Map iteration observes concurrent insertions), so a callback that
  // reschedules itself would re-run back-to-back until the whole budget is
  // exhausted. Per spec, callbacks scheduled from within an idle callback must
  // wait for the NEXT idle period. (ENG-22985)
  const handles = Array.from(callbacks.keys());

  // Process callbacks until we run out of time or snapshotted callbacks
  for (const id of handles) {
    const pending = callbacks.get(id);
    if (!pending) {
      // Cancelled (or already run) during this period.
      continue;
    }

    const remaining = idleDeadline - (performance?.now?.() ?? Date.now());

    if (remaining <= 0) {
      // No more idle time; the remaining snapshotted callbacks stay pending.
      break;
    }

    // Check if this callback has timed out
    const elapsed = now - pending.scheduledTime;
    const didTimeout = pending.timeout !== undefined && elapsed >= pending.timeout;

    runCallback(id, createDeadline(didTimeout, remaining));
  }

  // Anything still pending -- snapshotted callbacks we ran out of time for, plus
  // callbacks scheduled during this period -- needs a fresh idle check.
  if (callbacks.size > 0) {
    scheduleIdleCheck();
  }
}

/**
 * Run a specific callback and remove it from the pending set.
 */
function runCallback(id: number, deadline: IdleDeadline): void {
  const pending = callbacks.get(id);
  if (!pending) {
    return;
  }

  callbacks.delete(id);

  // Cancel the per-callback timeout timer (if any) so it doesn't linger. (ENG-22985)
  if (pending.timeoutHandle !== undefined) {
    clearTimeout(pending.timeoutHandle);
    pending.timeoutHandle = undefined;
  }

  try {
    pending.callback(deadline);
  } catch (error) {
    console.error('Error in requestIdleCallback:', error);
  }
}

/**
 * Create an IdleDeadline object.
 */
function createDeadline(didTimeout: boolean, remainingTime: number): IdleDeadline {
  const deadlineEnd = (performance?.now?.() ?? Date.now()) + remainingTime;

  return {
    didTimeout,
    timeRemaining(): number {
      const now = performance?.now?.() ?? Date.now();
      return Math.max(0, deadlineEnd - now);
    },
  };
}

export default { requestIdleCallback, cancelIdleCallback };
