/**
 * requestAnimationFrame / cancelAnimationFrame implementation for Exact runtime
 * 
 * Schedules callbacks to run before the next repaint.
 * @see https://html.spec.whatwg.org/multipage/imagebitmap-and-animations.html#dom-animationframeprovider-requestanimationframe
 */

import { getNativeModule } from '../native/NativeModules.js';
import {
  trackAnimationFrameCancelled,
  trackAnimationFrameExecuted,
  trackAnimationFrameRequested,
} from '../core/agent-state.js';

export type FrameRequestCallback = (time: DOMHighResTimeStamp) => void;
type DOMHighResTimeStamp = number;

// Callback storage
const callbacks = new Map<number, FrameRequestCallback>();
let nextId = 1;
let isScheduled = false;

// Target ~60fps = 16.67ms for runtimes that are not already display-linked.
const FRAME_TIME = 16;

/**
 * Requests that a callback be called before the next repaint.
 * Returns an ID that can be used to cancel the request.
 */
export function requestAnimationFrame(callback: FrameRequestCallback): number {
  if (typeof callback !== 'function') {
    throw new TypeError('Failed to execute \'requestAnimationFrame\': parameter 1 is not of type \'Function\'.');
  }

  const id = nextId++;
  callbacks.set(id, callback);
  trackAnimationFrameRequested(id);

  // Check for native implementation
  const nativeScheduling = getNativeModule('scheduling');
  if (nativeScheduling?.requestAnimationFrame) {
    // Use native RAF which is tied to the display refresh rate
    nativeScheduling.requestAnimationFrame(() => {
      runCallbacks();
    });
    return id;
  }

  // Fallback: use setTimeout to approximate 60fps
  if (!isScheduled) {
    isScheduled = true;
    setTimeout(() => {
      isScheduled = false;
      runCallbacks();
    }, fallbackFrameDelayMs());
  }

  return id;
}

/**
 * Cancels a previously scheduled animation frame request.
 */
export function cancelAnimationFrame(id: number): void {
  if (callbacks.delete(id)) {
    trackAnimationFrameCancelled(id);
  }
}

/**
 * Run all pending callbacks with the current timestamp.
 */
function runCallbacks(): void {
  // Get current time
  const timestamp = typeof performance !== 'undefined' && performance.now
    ? performance.now()
    : Date.now();

  // Copy callbacks to allow adding new ones during iteration
  const pending = new Map(callbacks);
  callbacks.clear();
  trackAnimationFrameExecuted(Array.from(pending.keys()));

  for (const [, callback] of pending) {
    try {
      callback(timestamp);
    } catch (error) {
      // Report error but continue with other callbacks
      console.error('Error in requestAnimationFrame callback:', error);
    }
  }
}

function fallbackFrameDelayMs(): number {
  return (globalThis as { __exactDisplayLinkedEventLoop?: boolean })
    .__exactDisplayLinkedEventLoop === true
    ? 0
    : FRAME_TIME;
}

export default { requestAnimationFrame, cancelAnimationFrame };
