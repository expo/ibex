// setTimeout / setInterval / clearTimeout / clearInterval.
//
// The wheel is Rust's — deadlines, ordering, interval rescheduling. This file
// holds the one thing that cannot cross the boundary: the callback. Closures
// live here in a Map keyed by the integer handle Rust mints, and the pump calls
// __ibex2_fire_timer(handle) when Rust says that handle is due.
(function (global) {
  "use strict";

  var callbacks = new Map();

  function schedule(repeating, handler, delay) {
    if (typeof handler !== "function") {
      // The string form of setTimeout compiles source, and dynamic code is
      // closed at construction (LLP 0060 D4). Refusing beats a confusing
      // "Parsing source code unsupported" from three frames down.
      throw new TypeError(
        "setTimeout/setInterval require a function; the string form needs eval, which is disabled"
      );
    }
    var ms = Number(delay);
    if (!isFinite(ms) || ms < 0) ms = 0;
    var extra = Array.prototype.slice.call(arguments, 3);
    var handle = repeating
      ? global.__ibex2_timer_set_repeating(ms)
      : global.__ibex2_timer_set(ms);
    callbacks.set(handle, { fn: handler, args: extra, repeating: repeating });
    return handle;
  }

  global.setTimeout = function (handler, delay) {
    return schedule.apply(
      null,
      [false, handler, delay].concat(Array.prototype.slice.call(arguments, 2))
    );
  };

  global.setInterval = function (handler, delay) {
    return schedule.apply(
      null,
      [true, handler, delay].concat(Array.prototype.slice.call(arguments, 2))
    );
  };

  function cancel(handle) {
    // clearTimeout(undefined) and clearTimeout(0) are no-ops in a browser.
    if (handle === undefined || handle === null) return;
    callbacks.delete(handle);
    global.__ibex2_timer_clear(Number(handle));
  }

  global.clearTimeout = cancel;
  global.clearInterval = cancel;

  // Called by the pump, once per due timer.
  global.__ibex2_fire_timer = function (handle) {
    var entry = callbacks.get(handle);
    if (!entry) return;
    // A one-shot is forgotten before it runs, so a callback that clears itself
    // — or throws — cannot leave a dead entry behind.
    if (!entry.repeating) callbacks.delete(handle);
    entry.fn.apply(undefined, entry.args);
  };

  global.performance = global.performance || {};
  if (!global.performance.now) {
    global.performance.now = function () {
      return global.__ibex2_performance_now();
    };
  }
})(globalThis);
