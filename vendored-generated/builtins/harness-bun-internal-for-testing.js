"use strict";

/**
 * bun:internal-for-testing shim for Bun compat tests.
 *
 * Provides minimal stubs so tests can at least load and run
 * (most will skip/fail on the actual internal functionality).
 */

var stubs = {
  fsStreamInternals: {},
  memfd_create: function () { return -1; },
  setSyntheticAllocationLimitForTesting: function () {},
  setSocketOptions: function (socket, option, value) {
    if (!socket || typeof socket !== "object") {
      return;
    }
    // Bun tests use option 1 to shrink the send buffer and force write pacing.
    if (option === 1) {
      var size = Number(value);
      if (isFinite(size) && size > 0) {
        socket.__exactSendBufferSize = size;
      }
    }
  },
  canonicalizeIP: function (ip) { return ip; },
  nativeFrameForTesting: function () {},
  getEventLoopStats: function () { return { min: 0, max: 0, avg: 0, count: 0 }; },
  timerInternals: {
    timerClockMs: function () { return Date.now(); },
  },
  structuredCloneAdvanced: function (val) {
    return JSON.parse(JSON.stringify(val));
  },
};

module.exports = stubs;
