"use strict";

/**
 * node-harness shim for Bun compat tests.
 *
 * Bun ships a "node-harness" module used by its Node.js compatibility tests.
 * It exports a `createTest(path)` factory that returns bun:test globals
 * along with Node.js-style test helpers (`createCallCheckCtx`, `createDoneDotAll`, `assert`).
 */

var nodeAssert;
try {
  nodeAssert = require("node:assert");
} catch (_) {
  // Minimal assert fallback
  nodeAssert = {
    ok: function (val, msg) {
      if (!val) throw new Error(msg || "Assertion failed");
    },
    strictEqual: function (a, b, msg) {
      if (a !== b) throw new Error(msg || "Expected " + a + " === " + b);
    },
    deepStrictEqual: function (a, b, msg) {
      if (JSON.stringify(a) !== JSON.stringify(b))
        throw new Error(msg || "Deep strict equal failed");
    },
    notStrictEqual: function (a, b, msg) {
      if (a === b) throw new Error(msg || "Expected " + a + " !== " + b);
    },
    throws: function (fn, expected, msg) {
      var threw = false;
      try { fn(); } catch (e) {
        threw = true;
        if (expected && typeof expected === "function" && !(e instanceof expected)) {
          throw new Error(msg || "Threw wrong error type");
        }
      }
      if (!threw) throw new Error(msg || "Expected function to throw");
    },
    doesNotThrow: function (fn, msg) {
      try { fn(); } catch (e) {
        throw new Error(msg || "Expected function not to throw: " + e.message);
      }
    },
    rejects: async function (fn, expected, msg) {
      var threw = false;
      try { await (typeof fn === "function" ? fn() : fn); } catch (e) {
        threw = true;
        if (expected && typeof expected === "function" && !(e instanceof expected)) {
          throw new Error(msg || "Rejected with wrong error type");
        }
      }
      if (!threw) throw new Error(msg || "Expected promise to reject");
    },
    match: function (str, regex, msg) {
      if (!regex.test(str)) throw new Error(msg || "Expected " + str + " to match " + regex);
    },
    ifError: function (err) {
      if (err) throw err;
    },
  };
}

/**
 * createCallCheckCtx(done, timeout)
 *
 * Returns { mustCall, mustNotCall } helpers.
 * - mustCall(fn, count) wraps fn so it must be called exactly `count` times
 *   (default 1). When all mustCalls are satisfied, `done()` is invoked.
 * - mustNotCall() returns a function that fails the test if called.
 */
function createCallCheckCtx(done, timeout) {
  timeout = timeout || 5000;
  var pending = [];
  var finished = false;

  function checkDone() {
    if (finished) return;
    for (var i = 0; i < pending.length; i++) {
      if (pending[i].remaining > 0) return;
    }
    finished = true;
    clearTimeout(timer);
    done();
  }

  var timer = setTimeout(function () {
    if (finished) return;
    finished = true;
    var uncalled = [];
    for (var i = 0; i < pending.length; i++) {
      if (pending[i].remaining > 0) {
        uncalled.push(pending[i].name + " (remaining: " + pending[i].remaining + ")");
      }
    }
    done(new Error("Timed out waiting for mustCall callbacks: " + uncalled.join(", ")));
  }, timeout);

  // Prevent timer from keeping the process alive
  if (timer && typeof timer.unref === "function") {
    timer.unref();
  }

  function mustCall(fn, count) {
    if (typeof fn === "number") {
      count = fn;
      fn = function () {};
    }
    if (typeof fn !== "function") {
      fn = function () {};
    }
    count = count === undefined ? 1 : count;
    var entry = { name: fn.name || "<anonymous>", remaining: count };
    pending.push(entry);

    if (count === 0) {
      // Must be called exactly 0 times — check done immediately
      setTimeout(checkDone, 0);
    }

    return function () {
      entry.remaining--;
      var result;
      try {
        result = fn.apply(this, arguments);
      } catch (err) {
        if (!finished) {
          finished = true;
          clearTimeout(timer);
          done(err);
        }
        return;
      }
      checkDone();
      return result;
    };
  }

  function mustNotCall(msg) {
    return function () {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        done(new Error(msg || "mustNotCall function was called"));
      }
    };
  }

  function mustSucceed(fn) {
    return mustCall(function (err) {
      if (err) {
        if (!finished) {
          finished = true;
          clearTimeout(timer);
          done(err instanceof Error ? err : new Error(String(err)));
        }
        return;
      }
      if (typeof fn === "function") {
        return fn.apply(this, Array.prototype.slice.call(arguments, 1));
      }
    });
  }

  return { mustCall: mustCall, mustNotCall: mustNotCall, mustSucceed: mustSucceed };
}

/**
 * createDoneDotAll(done)
 *
 * Returns a factory `createDone(timeout)` that creates sub-done callbacks.
 * The original `done` is called only when ALL sub-dones have been invoked.
 */
function createDoneDotAll(done) {
  var total = 0;
  var completed = 0;
  var finished = false;
  var timers = [];

  function checkDone() {
    if (finished) return;
    if (completed >= total) {
      finished = true;
      for (var i = 0; i < timers.length; i++) {
        clearTimeout(timers[i]);
      }
      done();
    }
  }

  return function createDone(timeout) {
    timeout = timeout || 5000;
    total++;
    var called = false;

    var t = setTimeout(function () {
      if (!called && !finished) {
        finished = true;
        done(new Error("createDoneDotAll: sub-done timed out after " + timeout + "ms"));
      }
    }, timeout);

    if (t && typeof t.unref === "function") {
      t.unref();
    }
    timers.push(t);

    return function subDone(err) {
      if (called) return;
      called = true;
      clearTimeout(t);
      if (err) {
        if (!finished) {
          finished = true;
          done(err instanceof Error ? err : new Error(String(err)));
        }
        return;
      }
      completed++;
      checkDone();
    };
  };
}

/**
 * createTest(filePath)
 *
 * Returns the standard test harness object expected by Bun's node-compat tests.
 */
function createTest(filePath) {
  // Pull globals installed by bun:test
  var _describe = typeof describe === "function" ? describe : function (name, fn) { fn(); };
  var _it = typeof it === "function" ? it : function (name, fn) { fn(); };
  var _test = typeof test === "function" ? test : _it;
  var _expect = typeof expect === "function" ? expect : function () { return {}; };
  var _beforeAll = typeof beforeAll === "function" ? beforeAll : function (fn) { fn(); };
  var _afterAll = typeof afterAll === "function" ? afterAll : function () {};
  var _beforeEach = typeof beforeEach === "function" ? beforeEach : function (fn) { fn(); };
  var _afterEach = typeof afterEach === "function" ? afterEach : function () {};

  return {
    describe: _describe,
    it: _it,
    test: _test,
    expect: _expect,
    beforeAll: _beforeAll,
    afterAll: _afterAll,
    beforeEach: _beforeEach,
    afterEach: _afterEach,
    assert: nodeAssert,
    createCallCheckCtx: createCallCheckCtx,
    createDoneDotAll: createDoneDotAll,
  };
}

module.exports = { createTest: createTest };
module.exports.createTest = createTest;
module.exports.createCallCheckCtx = createCallCheckCtx;
module.exports.createDoneDotAll = createDoneDotAll;
try {
  var harnessApi = require("harness");
  if (harnessApi && typeof harnessApi.exampleSite === "function") {
    module.exports.exampleSite = harnessApi.exampleSite;
  }
} catch (_) {}
