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

  // If timeout is specified, ensure callback runs within that time
  if (timeout !== undefined && timeout > 0) {
    setTimeout(() => {
      const pending = callbacks.get(id);
      if (pending) {
        runCallback(id, createDeadline(true, 0));
      }
    }, timeout);
  }

  return id;
}

/**
 * Cancels a previously scheduled idle callback.
 */
export function cancelIdleCallback(id: number): void {
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

  // Process callbacks until we run out of time or callbacks
  for (const [id, pending] of callbacks) {
    const remaining = idleDeadline - (performance?.now?.() ?? Date.now());
    
    if (remaining <= 0) {
      // No more idle time, schedule another check
      scheduleIdleCheck();
      break;
    }

    // Check if this callback has timed out
    const elapsed = now - pending.scheduledTime;
    const didTimeout = pending.timeout !== undefined && elapsed >= pending.timeout;

    runCallback(id, createDeadline(didTimeout, remaining));
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
