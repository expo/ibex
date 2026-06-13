"use strict";

/**
 * bun:jsc shim for Bun compat tests.
 *
 * Bun ships a "bun:jsc" module for JS engine introspection (JavaScriptCore).
 * This shim provides stub implementations that let tests run without crashing,
 * though GC leak detection tests won't get accurate heap data.
 */

function unsupportedHeapMetrics() {
  throw new Error("bun:jsc heap metrics are not available in Exact");
}

function heapStats() {
  unsupportedHeapMetrics();
}

function noInline(fn) {
  // Optimizer hint — no-op in our runtime
  return fn;
}

function serialize(value) {
  // Use JSON as a fallback for structured clone serialization
  var json = JSON.stringify(value);
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(json).buffer;
  }
  var buf = new ArrayBuffer(json.length);
  var view = new Uint8Array(buf);
  for (var i = 0; i < json.length; i++) {
    view[i] = json.charCodeAt(i);
  }
  return buf;
}

function deserialize(buffer) {
  var bytes;
  if (buffer instanceof ArrayBuffer) {
    bytes = new Uint8Array(buffer);
  } else if (buffer instanceof Uint8Array) {
    bytes = buffer;
  } else {
    bytes = new Uint8Array(buffer);
  }
  if (typeof TextDecoder !== "undefined") {
    return JSON.parse(new TextDecoder().decode(bytes));
  }
  var str = "";
  for (var i = 0; i < bytes.length; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return JSON.parse(str);
}

function estimateShallowMemoryUsageOf(obj) {
  unsupportedHeapMetrics();
}

function gcAndSweep() {
  if (typeof global !== "undefined" && typeof global.gc === "function") {
    global.gc();
  }
}

function fullGC() {
  gcAndSweep();
}

function edenGC() {
  gcAndSweep();
}

var jsc = {
  heapStats: heapStats,
  noInline: noInline,
  serialize: serialize,
  deserialize: deserialize,
  estimateShallowMemoryUsageOf: estimateShallowMemoryUsageOf,
  gcAndSweep: gcAndSweep,
  fullGC: fullGC,
  edenGC: edenGC,
  setRandomSeed: function () {},
  releaseWeakRefs: function () {},
  totalCompileTime: function () { return 0; },
  getRandomSeed: function () { return 0; },
  callerSourceOrigin: function () { return ""; },
  jscDescribe: function (val) { return String(val); },
  jscDescribeArray: function (arr) { return String(arr); },
  drainMicrotasks: function () {},
  startRemoteDebugger: function () {},
  numberOfDFGCompiles: function () { return 0; },
  setImpureGetterDelegate: function () {},
  profile: function (fn) { return fn(); },
  run: function (fn) { return fn(); },
};

module.exports = jsc;
module.exports.heapStats = heapStats;
module.exports.noInline = noInline;
module.exports.serialize = serialize;
module.exports.deserialize = deserialize;
module.exports.estimateShallowMemoryUsageOf = estimateShallowMemoryUsageOf;
module.exports.gcAndSweep = gcAndSweep;
module.exports.fullGC = fullGC;
module.exports.edenGC = edenGC;
module.exports.default = jsc;
