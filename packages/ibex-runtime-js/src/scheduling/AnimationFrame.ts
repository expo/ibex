/**
 * requestAnimationFrame / cancelAnimationFrame implementation for Ibex runtime
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
    if (!isScheduled) {
      isScheduled = true;
      nativeScheduling.requestAnimationFrame(() => {
        isScheduled = false;
        runCallbacks();
      });
    }
    return id;
  }

  // Fallback: use setTimeout to approximate 60fps
  if (!isScheduled) {
    isScheduled = true;
    setTimeout(() => {
      isScheduled = false;
      runCallbacks();
    }, FRAME_TIME);
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

  // Per the HTML spec, snapshot the handles present at the start of this frame,
  // then process them one at a time, removing each from the LIVE map immediately
  // before invoking it. This means:
  //  - callbacks requested from within a callback are deferred to the next frame
  //    (they aren't in the snapshot), and
  //  - cancelAnimationFrame(id2) called from id1's callback actually cancels id2
  //    (we re-check the live map and skip handles removed during the frame).
  // We also only report the callbacks we actually invoked as executed. (ENG-22985)
  const handles = Array.from(callbacks.keys());
  const executed: number[] = [];

  for (const id of handles) {
    const callback = callbacks.get(id);
    if (callback === undefined) {
      // Cancelled during this frame (e.g. by an earlier same-frame callback).
      continue;
    }
    callbacks.delete(id);
    executed.push(id);

    try {
      callback(timestamp);
    } catch (error) {
      // Report error but continue with other callbacks
      console.error('Error in requestAnimationFrame callback:', error);
    }
  }

  trackAnimationFrameExecuted(executed);
}

export default { requestAnimationFrame, cancelAnimationFrame };
