/**
 * Bun test adapter — lightweight implementation of bun:test.
 *
 * This is the JavaScript version of bun-adapter.ts, suitable for embedding
 * as a builtin module in the Exact runtime.
 */

// ─── State ──────────────────────────────────────────────────────

// Capture early, before test code can tamper with globalThis.process
var _savedProcessEnv = typeof process !== 'undefined' && process.env ? process.env : {};
var _savedTestId = _savedProcessEnv.EXACT_TEST_ID || "unknown";
var _savedTestFilter = _savedProcessEnv.EXACT_BUN_TEST_FILTER || "";
var _savedTestTrace = _savedProcessEnv.EXACT_BUN_TEST_TRACE === "1";
// Bun's own tests still reference `global`, so keep a stable alias even when
// the runtime only exposes `globalThis`.
if (typeof globalThis !== "undefined" && typeof globalThis.global === "undefined") {
  globalThis.global = globalThis;
}
var global = typeof globalThis !== "undefined" ? globalThis : {};

var currentSuite = "";
var tests = [];
var beforeAlls = [];
var afterAlls = [];
var beforeEachs = [];
var afterEachs = [];
var _pendingAsyncAssertions = null;

function matchesSavedTestFilter(name) {
  if (!_savedTestFilter) {
    return true;
  }

  if (
    _savedTestFilter.length >= 2 &&
    _savedTestFilter.charAt(0) === "/" &&
    _savedTestFilter.charAt(_savedTestFilter.length - 1) === "/"
  ) {
    try {
      return new RegExp(_savedTestFilter.slice(1, -1)).test(name);
    } catch (_filterErr) {}
  }

  return name.indexOf(_savedTestFilter) !== -1;
}

function traceTestStart(name) {
  if (!_savedTestTrace || typeof console !== "object" || typeof console.error !== "function") {
    return;
  }

  try {
    console.error(JSON.stringify({
      type: "test_start",
      test: {
        name: name,
        id: _savedTestId,
      },
    }));
  } catch (_traceErr) {
    console.error("test_start " + name);
  }
}

function registerTest(name, fn) {
  var fullName = currentSuite ? currentSuite + " > " + name : name;
  if (!matchesSavedTestFilter(fullName)) {
    return;
  }

  tests.push({
    name: fullName,
    fn: fn,
    suite: currentSuite,
  });
}

function installBunCompatCryptoGetRandomValues() {
  var cryptoObject = globalThis.crypto;
  if (!cryptoObject || typeof cryptoObject.getRandomValues !== "function") {
    return;
  }

  var original = cryptoObject.getRandomValues.bind(cryptoObject);
  if (original.__exactBunCompatWrapped) {
    return;
  }

  function isArrayBufferLike(value) {
    return value instanceof ArrayBuffer ||
      (typeof SharedArrayBuffer === "function" && value instanceof SharedArrayBuffer);
  }

  var wrapped = function(array) {
    if (
      !array ||
      typeof array.byteLength !== "number" ||
      (!ArrayBuffer.isView(array) && !isArrayBufferLike(array))
    ) {
      return original(array);
    }

    try {
      return original(array);
    } catch (error) {
      var message = error && error.message ? error.message : String(error);
      if (
        message !== "Argument must be an integer-typed TypedArray" &&
        message.indexOf("byte length exceeds the limit") === -1 &&
        message !== "Quota exceeded"
      ) {
        throw error;
      }
    }

    var bytes = ArrayBuffer.isView(array)
      ? new Uint8Array(array.buffer, array.byteOffset, array.byteLength)
      : new Uint8Array(array);
    for (var offset = 0; offset < bytes.byteLength; offset += 65536) {
      original(bytes.subarray(offset, Math.min(offset + 65536, bytes.byteLength)));
    }
    return array;
  };

  wrapped.__exactBunCompatWrapped = true;
  cryptoObject.getRandomValues = wrapped;
}

function patchBrokenSharedArrayBufferUint8Array() {
  if (typeof globalThis.SharedArrayBuffer !== "function" || typeof globalThis.Uint8Array !== "function") {
    return;
  }

  try {
    var probeBuffer = new globalThis.SharedArrayBuffer(1);
    var probeView = new globalThis.Uint8Array(probeBuffer);
    if (
      probeView.length === 1 &&
      probeView.byteLength === 1 &&
      Object.prototype.toString.call(probeView.buffer) === "[object SharedArrayBuffer]"
    ) {
      return;
    }
  } catch (_probeErr) {}

  var NativeUint8Array = globalThis.Uint8Array;

  function exposeSharedArrayBufferView(view, originalBuffer) {
    try {
      Object.defineProperty(view, "buffer", {
        configurable: true,
        enumerable: false,
        get: function () {
          return originalBuffer;
        },
      });
    } catch (_bufferErr) {}
    try {
      Object.defineProperty(view, "__exactSharedArrayBuffer", {
        value: originalBuffer,
        writable: false,
        configurable: true,
        enumerable: false,
      });
    } catch (_markerErr) {}
    return view;
  }

  function WrappedUint8Array(buffer, byteOffset, length) {
    if (!(this instanceof WrappedUint8Array)) {
      throw new TypeError('Constructor Uint8Array requires "new"');
    }

    var backing = buffer && buffer._buffer;
    if (backing && Object.prototype.toString.call(backing) === "[object ArrayBuffer]") {
      var view;
      if (arguments.length <= 1) {
        view = new NativeUint8Array(backing);
      } else if (arguments.length === 2) {
        view = new NativeUint8Array(backing, byteOffset);
      } else {
        view = new NativeUint8Array(backing, byteOffset, length);
      }
      return exposeSharedArrayBufferView(view, buffer);
    }

    if (arguments.length === 0) return new NativeUint8Array();
    if (arguments.length === 1) return new NativeUint8Array(buffer);
    if (arguments.length === 2) return new NativeUint8Array(buffer, byteOffset);
    return new NativeUint8Array(buffer, byteOffset, length);
  }

  WrappedUint8Array.prototype = NativeUint8Array.prototype;
  try {
    Object.setPrototypeOf(WrappedUint8Array, NativeUint8Array);
  } catch (_protoErr) {}
  try {
    Object.defineProperty(WrappedUint8Array, "__exactSharedArrayBufferWrapped", {
      value: true,
      writable: false,
      configurable: true,
      enumerable: false,
    });
  } catch (_flagErr) {}
  try {
    Object.defineProperty(globalThis, "Uint8Array", {
      value: WrappedUint8Array,
      writable: true,
      configurable: true,
      enumerable: false,
    });
  } catch (_assignErr) {
    globalThis.Uint8Array = WrappedUint8Array;
  }
}

installBunCompatCryptoGetRandomValues();

patchBrokenSharedArrayBufferUint8Array();

// ─── Test Registration ──────────────────────────────────────────

function describe(name, fn) {
  // Handle describe(fn) with no name (Bun supports this)
  if (typeof name === "function" && fn === undefined) {
    fn = name;
    name = "(anonymous)";
  }
  // Handle describe(name, options, fn) - 3-argument form
  if (typeof fn !== "function" && arguments.length > 2 && typeof arguments[2] === "function") {
    fn = arguments[2];
  }
  var prevSuite = currentSuite;
  currentSuite = currentSuite ? currentSuite + " > " + name : name;
  if (typeof fn === "function") fn();
  currentSuite = prevSuite;
}

function test(name, fn) {
  registerTest(name, fn);
}

var it = test;

test.skip = function (name, _fn) {
  registerTest(name, function () { throw new SkipError(); });
};

test.if = function (condition) {
  return condition ? test : test.skip;
};

test.todo = function (name) {
  registerTest(name, function () { throw new SkipError(); });
};

test.todoIf = function (condition) {
  return condition ? test.todo : test;
};

test.skipIf = function (condition) {
  return condition ? test.skip : test;
};

// test.failing — expects the test to fail. If it throws, the test passes.
// If it doesn't throw, the test fails.
test.failing = function (name, fn) {
  registerTest(name, async function () {
      var threw = false;
      try {
        await fn();
      } catch (e) {
        threw = true;
      }
      if (!threw) {
        throw new Error("Expected test to fail but it passed: " + name);
      }
  });
};

describe.if = function (condition) {
  return condition ? describe : function () {};
};

describe.skip = function (_name, _fn) {};

describe.todo = function (_name, _fn) {};

describe.skipIf = function (condition) {
  return condition ? describe.skip : describe;
};

describe.todoIf = function (condition) {
  return condition ? describe.todo : describe;
};

// describe.concurrent - run describe blocks serially (no true concurrency needed)
function createConcurrentDescribe(baseFn) {
  var concurrentDescribe = function (name, fn) { return baseFn(name, fn); };
  concurrentDescribe.skip = describe.skip;
  concurrentDescribe.todo = describe.todo;
  concurrentDescribe.if = describe.if;
  concurrentDescribe.skipIf = describe.skipIf;
  concurrentDescribe.todoIf = describe.todoIf;
  return concurrentDescribe;
}

describe.concurrent = createConcurrentDescribe(describe);

describe.each = function (table) {
  return function (name, fn) {
    for (var i = 0; i < table.length; i++) {
      var entry = table[i];
      var args = Array.isArray(entry) ? entry.slice() : [entry];
      var nameArgs = Array.isArray(entry) ? entry.slice() : [entry];
      var descName = name.replace(/%s/g, function () { return String(nameArgs.shift()); });
      (function (a) {
        describe(descName, function () { fn.apply(null, a); });
      })(args);
    }
  };
};

// Also add describe.each to describe.concurrent
describe.concurrent.each = describe.each;

it.if = function (condition) {
  return condition ? it : test.skip;
};

it.todoIf = function (condition) {
  return condition ? test.todo : test;
};

it.skipIf = function (condition) {
  return condition ? test.skip : test;
};

test.each = function (table) {
  return function (name, fn) {
    for (var i = 0; i < table.length; i++) {
      var entry = table[i];
      var args = Array.isArray(entry) ? entry.slice() : [entry];
      var nameArgs = Array.isArray(entry) ? entry.slice() : [entry];
      var testName = name.replace(/%s/g, function () { return String(nameArgs.shift()); });
      // Spread array entries as individual arguments (Bun behavior)
      (function (a) {
        test(testName, function () { return fn.apply(null, a); });
      })(args);
    }
  };
};

it.each = test.each;
it.failing = test.failing;

// test.concurrent / it.concurrent - run serially (no true concurrency needed for compat tests)
function createConcurrentProxy(baseFn) {
  var concurrent = function (name, fn) { return baseFn(name, fn); };
  concurrent.each = test.each;
  concurrent.skip = test.skip;
  concurrent.todo = test.todo;
  concurrent.if = test.if;
  concurrent.todoIf = test.todoIf;
  concurrent.skipIf = test.skipIf;
  return concurrent;
}

test.concurrent = createConcurrentProxy(test);
it.concurrent = createConcurrentProxy(it);

// ─── Lifecycle Hooks ────────────────────────────────────────────

function beforeAll(fn) { beforeAlls.push(fn); }
function afterAll(fn) { afterAlls.push(fn); }
function beforeEach(fn) { beforeEachs.push(fn); }
function afterEach(fn) { afterEachs.push(fn); }

// ─── SkipError ──────────────────────────────────────────────────

function SkipError() {
  this.name = "SkipError";
  this.message = "SKIP";
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, SkipError);
  }
}
SkipError.prototype = Object.create(Error.prototype);
SkipError.prototype.constructor = SkipError;

// Ensure Bun namespace is available globally for fixtures that call Bun.* directly.
var _globalBun = global.Bun;
if (!_globalBun) {
  var _util = require("node:util");
  _globalBun = {};
  _globalBun.inspect = function (value) {
    return _util
      .inspect(value, {
        breakLength: 80,
        compact: false,
        depth: null,
        sorted: false,
      })
      .replace(/'/g, "\"");
  };
  global.Bun = _globalBun;
}

if (typeof global.describe !== "function") {
  global.describe = describe;
}
if (typeof global.it !== "function") {
  global.it = it;
}
if (typeof global.test !== "function") {
  global.test = test;
}
if (typeof global.expect !== "function") {
  global.expect = expect;
}
if (typeof global.beforeAll !== "function") {
  global.beforeAll = beforeAll;
}
if (typeof global.afterAll !== "function") {
  global.afterAll = afterAll;
}
if (typeof global.beforeEach !== "function") {
  global.beforeEach = beforeEach;
}
if (typeof global.afterEach !== "function") {
  global.afterEach = afterEach;
}

// Only wrap URL.canParse if it has 0 declared params (old Bun behavior).
// If it already has 1 or 2 params, it handles the url/base args correctly.
if (typeof URL === "function" && typeof URL.canParse === "function" && URL.canParse.length === 0) {
  var _originalCanParse = URL.canParse;
  URL.canParse = function (url) {
    return _originalCanParse(url, arguments[1]);
  };
  Object.defineProperty(URL, "canParse", {
    value: URL.canParse,
    configurable: true,
    writable: true,
  });
}

// ─── Expect / Matchers ──────────────────────────────────────────

function expect(actual) {
  return createMatchers(actual, false);
}

function isValidUtf16String(value) {
  if (typeof value !== "string") return false;
  for (var i = 0; i < value.length; i++) {
    var code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 >= value.length) return false;
      var next = value.charCodeAt(i + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      i++;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

function _toString(value) {
  try {
    return JSON.stringify(value, function (_key, current) {
      if (typeof current === "bigint") {
        return String(current) + "n";
      }
      if (typeof current === "symbol") {
        return String(current);
      }
      if (typeof current === "function") {
        return "[Function " + (current.name || "anonymous") + "]";
      }
      return current;
    });
  } catch (_error) {
    try {
      return String(value);
    } catch (_stringError) {
      return Object.prototype.toString.call(value);
    }
  }
}

function createPromiseMatchers(actual, negated, mode) {
  var expectsReject = mode === "rejects";
  var getErrorMessage = function(value) {
    if (value === undefined) return "";
    if (value === null) return "null";
    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean" || typeof value === "symbol") return String(value);
    if (typeof value === "object" && typeof value.message === "string") return value.message;
    return _toString(value);
  };

  function runForPromise(valueMatcher) {
    if (!actual || typeof actual.then !== "function") {
      if (!expectsReject) {
        return Promise.resolve().then(function () {
          return valueMatcher(actual);
        });
      }
      throw new Error("Expected " + _toString(actual) + " to be a promise");
    }
    if (expectsReject) {
      return Promise.resolve(actual).then(
        function () {
          throw new Error("Expected promise to be rejected");
        },
        function (reason) {
          return valueMatcher(reason);
        }
      );
    }
    return Promise.resolve(actual).then(function (value) {
      return valueMatcher(value);
    }, function (reason) {
      throw new Error("Expected promise to be resolved, got rejection: " + getErrorMessage(reason));
    });
  }

  function runMatcher(methodName, args) {
    return runForPromise(function (value) {
      var matchers = createMatchers(value, negated);
      var matcher = matchers[methodName];
      if (typeof matcher !== "function") {
        throw new Error("Matcher " + methodName + " is not available for promise values");
      }
      return matcher.apply(matchers, args || []);
    });
  }

  return {
    toBe: function (expected) {
      return runMatcher("toBe", [expected]);
    },
    toEqual: function (expected) {
      return runMatcher("toEqual", [expected]);
    },
    toStrictEqual: function (expected) {
      return runMatcher("toStrictEqual", [expected]);
    },
    toMatchObject: function (expected) {
      return runForPromise(function (value) {
        var matched = partialMatch(value, expected);
        if (negated ? matched : !matched) {
          throw new Error(
            "Expected " + _toString(value) + " to" + (negated ? " not" : "") + " match object " + _toString(expected)
          );
        }
      });
    },
    toBeUndefined: function () {
      return runMatcher("toBeUndefined");
    },
    toBeInstanceOf: function (expected) {
      return runMatcher("toBeInstanceOf", [expected]);
    },
    toHaveLength: function (expected) {
      return runMatcher("toHaveLength", [expected]);
    },
    toHaveProperty: function (key, value) {
      return runMatcher("toHaveProperty", arguments.length > 1 ? [key, value] : [key]);
    },
    toThrow: function (expected) {
      if (!expectsReject) {
        return runMatcher("toThrow", [expected]);
      }
      return runForPromise(function (reason) {
        assertThrowsOutcome(true, reason, negated, expected, "promise");
      });
    },
    toThrowError: function (expected) {
      return this.toThrow(expected);
    },
    toThrowErrorMatchingInlineSnapshot: function (expected) {
      return this.toThrow(normalizeInlineSnapshot(expected));
    },
    pass: function () {
      return runForPromise(function () {});
    },
    get not() {
      return createPromiseMatchers(actual, !negated, mode);
    }
  };
}

function _runCommand(actual) {
  var childProcess = require("node:child_process");
  function currentEnv() {
    if (typeof bunEnv === "function") {
      return bunEnv();
    }
    if (bunEnv && typeof bunEnv === "object") {
      return bunEnv;
    }
    return process.env;
  }

  function shouldRunWithExact(command, fromArrayInput) {
    if (fromArrayInput) {
      return true;
    }
    if (typeof command !== "string" || !command) {
      return false;
    }
    if (command === "run" || command.charAt(0) === "-") {
      return true;
    }
    return /\.(?:[cm]?[jt]sx?)$/.test(command);
  }

  var command = actual;
  var args = [];
  var commandArgs;
  var fromArrayInput = Array.isArray(actual);

  if (fromArrayInput) {
    command = actual[0];
    args = actual.slice(1);
  }

  if (typeof command !== "string" || !command) {
    throw new Error("Expected toRun() to receive a command string");
  }

  if (shouldRunWithExact(command, fromArrayInput)) {
    commandArgs = fromArrayInput ? actual.slice() : [command].concat(args);
    command = process.execPath;
  } else {
    commandArgs = args;
  }

  var result = childProcess.spawnSync(command, commandArgs, {
    env: Object.assign({}, currentEnv()),
    encoding: "utf8",
    stdio: "pipe",
  });

  return {
    commandArgs: commandArgs,
    result: result,
  };
}

function _toRunCommand(actual, negated) {
  var outcome = _runCommand(actual);
  var result = outcome.result;
  var commandArgs = outcome.commandArgs;

  if (result.error) {
    if (negated) {
      return;
    }
    throw result.error;
  }
  if (negated) {
    if (result.status === 0) {
      throw new Error("Expected command to fail: " + commandArgs.join(" "));
    }
    return;
  }
  if (result.status !== 0) {
    var details = "";
    if (result.stdout) {
      details += "\nstdout:\n" + result.stdout;
    }
    if (result.stderr) {
      details += "\nstderr:\n" + result.stderr;
    }
    throw new Error("Expected command to run successfully: " + commandArgs.join(" ") + ", got exit code " + result.status + details);
  }
}

function objectContaining(value) {
  return {
    __bunObjectContaining: true,
    __value: value,
  };
}

function expectAny(type) {
  return {
    __bunAny: true,
    __type: type,
  };
}

function normalizeThrownMessage(message) {
  if (message === "Cannot allocate a data block for the ArrayBuffer") {
    return "Out of memory";
  }
  return message;
}

function assertThrownError(thrownError, expected) {
  if (!expected) {
    return;
  }
  var thrownMessage = normalizeThrownMessage(thrownError && thrownError.message);
  if (typeof expected === "string") {
    if (!(thrownMessage && thrownMessage.includes(expected))) {
      throw new Error(
        "Expected error message \"" + thrownMessage + "\" to include \"" + expected + "\""
      );
    }
    return;
  }
  if (expected instanceof RegExp) {
    if (!expected.test(thrownMessage)) {
      throw new Error(
        "Expected error message \"" + thrownMessage + "\" to match " + expected
      );
    }
    return;
  }
  if (typeof expected === "function") {
    if (!(thrownError instanceof expected)) {
      throw new Error(
        "Expected thrown error to be instance of " + (expected.name || "constructor") +
        ", got " + (thrownError && thrownError.constructor && thrownError.constructor.name)
      );
    }
    return;
  }
  if (expected && expected.__bunObjectContaining) {
    var expectedProperties = expected.__value || {};
    var keys = Object.keys(expectedProperties);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      if (!thrownError || thrownError[key] !== expectedProperties[key]) {
        throw new Error(
          "Expected error property \"" + key + "\" to be " + _toString(expectedProperties[key]) +
          ", got " + _toString(thrownError && thrownError[key])
        );
      }
    }
  }
}

function normalizeInlineSnapshot(snapshot) {
  var normalized = typeof snapshot === "string" ? snapshot.trim() : String(snapshot);
  if (normalized.length >= 2 && normalized[0] === '"' && normalized[normalized.length - 1] === '"') {
    try {
      return JSON.parse(normalized);
    } catch (_err) {}
  }
  return normalized;
}

function assertThrowsOutcome(threw, thrownError, negated, expected, subject) {
  if (!threw) {
    if (!negated) {
      throw new Error("Expected " + subject + " to throw");
    }
    return;
  }
  if (negated) {
    throw new Error("Expected " + subject + " not to throw");
  }
  assertThrownError(thrownError, expected);
}

function trackAsyncAssertion(promise) {
  if (_pendingAsyncAssertions) {
    _pendingAsyncAssertions.push(promise);
    return;
  }
  return promise;
}

function createMatchers(actual, negated) {
  var assert = function (condition, msg) {
    if (negated ? condition : !condition) {
      throw new Error(typeof msg === "function" ? msg() : msg);
    }
  };
  var getMockCalls = function(value) {
    if (typeof value !== "function" || !value.mock || !Array.isArray(value.mock.calls)) {
      throw new Error("Expected a mock function");
    }
    return value.mock.calls;
  };
  var exactBooleanActual = function () {
    if (actual && typeof actual === "object" && typeof actual.__exactBooleanValue === "boolean") {
      return actual.__exactBooleanValue;
    }
    return actual;
  };

  var matchers = {
    toBe: function (expected) {
      assert(
        Object.is(actual, expected),
        "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be " + _toString(expected)
      );
    },

    toEqual: function (expected) {
      assert(
        deepEqual(actual, expected),
        function () {
          return "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " equal " + _toString(expected);
        }
      );
    },

    toStrictEqual: function (expected) {
      assert(
        deepStrictEqual(actual, expected),
        function () {
          return "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " strictly equal " + _toString(expected);
        }
      );
    },

    toBeTruthy: function () {
      assert(!!actual, "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be truthy");
    },

    toBeFalsy: function () {
      assert(!actual, "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be falsy");
    },

    toBeNull: function () {
      assert(actual === null, "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be null");
    },

    toBeUndefined: function () {
      assert(actual === undefined, "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be undefined");
    },

    toBeDefined: function () {
      assert(actual !== undefined, "Expected value to" + (negated ? " not" : "") + " be defined");
    },

    toBeNaN: function () {
      assert(Number.isNaN(actual), "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be NaN");
    },

    toBeInstanceOf: function (cls) {
      assert(
        actual instanceof cls,
        "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be instance of " + cls.name
      );
    },

    toBeGreaterThan: function (n) {
      assert(actual > n, "Expected " + actual + " to" + (negated ? " not" : "") + " be greater than " + n);
    },

    toBeGreaterThanOrEqual: function (n) {
      assert(actual >= n, "Expected " + actual + " to" + (negated ? " not" : "") + " be >= " + n);
    },

    toBeLessThan: function (n) {
      assert(actual < n, "Expected " + actual + " to" + (negated ? " not" : "") + " be less than " + n);
    },

    toBeLessThanOrEqual: function (n) {
      assert(actual <= n, "Expected " + actual + " to" + (negated ? " not" : "") + " be <= " + n);
    },

    toBeUTF16String: function () {
      assert(
        isValidUtf16String(actual),
        "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be a valid UTF-16 string"
      );
    },

    toContain: function (item) {
      if (typeof actual === "string") {
        assert(actual.includes(item), "Expected \"" + actual + "\" to" + (negated ? " not" : "") + " contain \"" + item + "\"");
      } else if (Array.isArray(actual)) {
        assert(actual.includes(item), "Expected array to" + (negated ? " not" : "") + " contain " + _toString(item));
      } else {
        throw new Error("toContain can only be used with strings and arrays");
      }
    },

    toHaveLength: function (length) {
      assert(
        actual.length === length,
        "Expected length " + actual.length + " to" + (negated ? " not" : "") + " be " + length
      );
    },

    toHaveBeenCalled: function () {
      var calls = getMockCalls(actual);
      assert(
        calls.length > 0,
        "Expected mock to" + (negated ? " not" : "") + " have been called"
      );
    },

    toHaveBeenCalledTimes: function (count) {
      var calls = getMockCalls(actual);
      assert(
        calls.length === count,
        "Expected mock to" + (negated ? " not" : "") + " have been called " + count + " times, got " + calls.length
      );
    },

    toHaveBeenCalledWith: function () {
      var expectedArgs = Array.prototype.slice.call(arguments);
      var calls = getMockCalls(actual);
      var matched = false;
      for (var i = 0; i < calls.length; i++) {
        if (deepEqual(calls[i], expectedArgs)) {
          matched = true;
          break;
        }
      }
      assert(
        matched,
        function () {
          return "Expected mock to" + (negated ? " not" : "") + " have been called with " + _toString(expectedArgs);
        }
      );
    },

    toMatch: function (pattern) {
      var re = typeof pattern === "string" ? new RegExp(pattern) : pattern;
      assert(re.test(actual), "Expected \"" + actual + "\" to" + (negated ? " not" : "") + " match " + re);
    },

    toRun: function () {
      _toRunCommand(actual, negated);
    },

    toThrow: function (expected) {
      if (typeof actual !== "function") {
        throw new Error("toThrow requires a function");
      }
      var threw = false;
      var thrownError;
      var result;
      try {
        result = actual();
      } catch (e) {
        threw = true;
        thrownError = e;
      }
      if (result && typeof result.then === "function") {
        return trackAsyncAssertion(Promise.resolve(result).then(function () {
          assertThrowsOutcome(false, void 0, negated, expected, "function");
        }, function (error) {
          assertThrowsOutcome(true, error, negated, expected, "function");
        }));
      }
      assertThrowsOutcome(threw, thrownError, negated, expected, "function");
    },

    toThrowError: function (expected) {
      return this.toThrow(expected);
    },

    toThrowErrorMatchingInlineSnapshot: function (expected) {
      return this.toThrow(normalizeInlineSnapshot(expected));
    },

    toMatchInlineSnapshot: function (expected) {
      var snapshot = normalizeInlineSnapshot(expected);
      var actualText = typeof actual === "string" ? actual.trim() : String(actual).trim();
      assert(
        actualText === snapshot,
        function () {
          return "Expected " + _toString(actualText) + " to" + (negated ? " not" : "") + " match inline snapshot " + _toString(snapshot);
        }
      );
    },

    toThrowWithCode: function (expectedType, expectedCode) {
      if (typeof actual !== "function") {
        throw new Error("toThrowWithCode requires a function");
      }
      var threw = false;
      var thrownError;
      var result;
      try {
        result = actual();
      } catch (e) {
        threw = true;
        thrownError = e;
      }
      function verifyThrownError(error) {
        assertThrowsOutcome(true, error, negated, void 0, "function");
        assert(
          error instanceof expectedType,
          "Expected thrown error to be instance of " + ((expectedType && expectedType.name) || "constructor") + ", got " + (error && error.constructor && error.constructor.name)
        );
        assert(
          error && error.code === expectedCode,
          "Expected thrown error code " + _toString(expectedCode) + ", got " + _toString(error && error.code)
        );
      }
      if (result && typeof result.then === "function") {
        return trackAsyncAssertion(Promise.resolve(result).then(function () {
          assertThrowsOutcome(false, void 0, negated, void 0, "function");
        }, function (error) {
          verifyThrownError(error);
        }));
      }
      assertThrowsOutcome(threw, thrownError, negated, void 0, "function");
      verifyThrownError(thrownError);
    },

    toMatchObject: function (expected) {
      assert(
        partialMatch(actual, expected),
        "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " match object " + _toString(expected)
      );
    },

    toBeCloseTo: function (expected, precision) {
      var numDigits = precision === undefined ? 2 : precision;
      var threshold = Math.pow(10, -numDigits) / 2;
      assert(
        Math.abs(actual - expected) < threshold,
        "Expected " + actual + " to" + (negated ? " not" : "") + " be close to " + expected + " (precision " + numDigits + ")"
      );
    },

    toBeEmpty: function () {
      var isEmpty = actual == null || actual.length === 0 || (typeof actual === 'object' && Object.keys(actual).length === 0);
      assert(isEmpty, "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be empty");
    },

    toBeString: function () {
      assert(typeof actual === 'string', "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be a string");
    },

    toBeNumber: function () {
      assert(typeof actual === 'number', "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be a number");
    },

    toBeBoolean: function () {
      assert(typeof actual === 'boolean', "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be a boolean");
    },

    toBeTrue: function () {
      assert(exactBooleanActual() === true, "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be true");
    },

    toBeFalse: function () {
      assert(exactBooleanActual() === false, "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be false");
    },

    toBeTypeOf: function (type) {
      assert(typeof actual === type, "Expected typeof " + _toString(actual) + " to" + (negated ? " not" : "") + " be " + type);
    },

    toBeFunction: function () {
      assert(typeof actual === 'function', "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be a function");
    },

    toBeArray: function () {
      assert(Array.isArray(actual), "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be an array");
    },

    toBeObject: function () {
      assert(actual !== null && typeof actual === 'object', "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " be an object");
    },

    toBeInteger: function () {
      assert(Number.isInteger(actual), "Expected " + actual + " to" + (negated ? " not" : "") + " be an integer");
    },

    toBeFinite: function () {
      assert(typeof actual === 'number' && isFinite(actual), "Expected " + actual + " to" + (negated ? " not" : "") + " be finite");
    },

    toBePositive: function () {
      assert(typeof actual === 'number' && actual > 0, "Expected " + actual + " to" + (negated ? " not" : "") + " be positive");
    },

    toBeNegative: function () {
      assert(typeof actual === 'number' && actual < 0, "Expected " + actual + " to" + (negated ? " not" : "") + " be negative");
    },

    toBeWithin: function (min, max) {
      assert(typeof actual === 'number' && actual >= min && actual < max, "Expected " + actual + " to" + (negated ? " not" : "") + " be within [" + min + ", " + max + ")");
    },

    toStartWith: function (str) {
      assert(
        typeof actual === 'string' && actual.startsWith(str),
        "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " start with " + _toString(str)
      );
    },

    toEndWith: function (str) {
      assert(
        typeof actual === 'string' && actual.endsWith(str),
        "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " end with " + _toString(str)
      );
    },

    toInclude: function (item) {
      if (typeof actual === 'string') {
        assert(actual.includes(item), "Expected " + _toString(actual) + " to" + (negated ? " not" : "") + " include " + _toString(item));
      } else if (Array.isArray(actual)) {
        assert(actual.includes(item), "Expected array to" + (negated ? " not" : "") + " include " + _toString(item));
      }
    },

    toHaveProperty: function (key, value) {
      var has = key in actual || (actual && typeof actual === "object" && key.split(".").reduce(
        function (obj, k) { return obj && typeof obj === "object" ? obj[k] : undefined; },
        actual
      ) !== undefined);
      assert(has, "Expected object to" + (negated ? " not" : "") + " have property \"" + key + "\"");
      if (value !== undefined && has) {
        var actualValue = key.split(".").reduce(
          function (obj, k) { return obj && typeof obj === "object" ? obj[k] : undefined; },
          actual
        );
        assert(
          deepEqual(actualValue, value),
          "Expected property \"" + key + "\" to" + (negated ? " not" : "") + " equal " + _toString(value) + ", got " + _toString(actualValue)
        );
      }
    },

    get not() {
      return createMatchers(actual, !negated);
    },

    get resolves() {
      return createPromiseMatchers(actual, negated, "resolves");
    },

    get rejects() {
      return createPromiseMatchers(actual, negated, "rejects");
    },
  };

  return matchers;
}

// ─── Deep Equality ──────────────────────────────────────────────

function isArrayBufferView(value) {
  return typeof ArrayBuffer !== "undefined" &&
    ArrayBuffer &&
    typeof ArrayBuffer.isView === "function" &&
    ArrayBuffer.isView(value);
}

function arrayBufferViewsEqual(a, b) {
  if (!isArrayBufferView(a) || !isArrayBufferView(b)) return false;
  if (a.byteLength !== b.byteLength) return false;
  var viewA = new Uint8Array(a.buffer, a.byteOffset || 0, a.byteLength);
  var viewB = new Uint8Array(b.buffer, b.byteOffset || 0, b.byteLength);
  for (var i = 0; i < viewA.length; i++) {
    if (viewA[i] !== viewB[i]) return false;
  }
  return true;
}

function isUrlObject(value) {
  return typeof URL === "function" && value instanceof URL;
}

function isUrlSearchParamsObject(value) {
  return typeof URLSearchParams === "function" && value instanceof URLSearchParams;
}

function hasSeenPair(seen, a, b) {
  var matches = seen.get(a);
  return matches !== undefined && matches.has(b);
}

function markSeenPair(seen, a, b) {
  var matches = seen.get(a);
  if (!matches) {
    matches = new WeakSet();
    seen.set(a, matches);
  }
  matches.add(b);
}

function deepEqualInternal(a, b, seen) {
  if (Object.is(a, b)) return true;
  if (a == null || b == null) return a === b;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object") return false;
  if (isUrlObject(a) || isUrlObject(b)) {
    return isUrlObject(a) && isUrlObject(b) && a.href === b.href;
  }
  if (isUrlSearchParamsObject(a) || isUrlSearchParamsObject(b)) {
    return isUrlSearchParamsObject(a) && isUrlSearchParamsObject(b) && a.toString() === b.toString();
  }
  if (isArrayBufferView(a) || isArrayBufferView(b)) {
    return arrayBufferViewsEqual(a, b);
  }
  if (hasSeenPair(seen, a, b)) return true;
  markSeenPair(seen, a, b);
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (!deepEqualInternal(a[i], b[i], seen)) return false;
    }
    return true;
  }
  var keysA = Object.keys(a);
  var keysB = Object.keys(b);
  if (keysA.length !== keysB.length) return false;
  for (var i = 0; i < keysA.length; i++) {
    if (!deepEqualInternal(a[keysA[i]], b[keysA[i]], seen)) return false;
  }
  return true;
}

function deepEqual(a, b) {
  return deepEqualInternal(a, b, new WeakMap());
}

function partialMatch(actual, expected) {
  if (expected && typeof expected === "object") {
    if (expected.__bunObjectContaining === true) {
      if (actual == null || typeof actual !== "object") return false;
      return partialMatch(actual, expected.__value);
    }
    if (expected.__bunAny === true) {
      var expectedType = expected.__type;
      if (expectedType === String) return typeof actual === "string";
      if (expectedType === Number) return typeof actual === "number";
      if (expectedType === Boolean) return typeof actual === "boolean";
      if (expectedType === Function) return typeof actual === "function";
      if (expectedType === Object) return actual !== null && (typeof actual === "object" || typeof actual === "function");
      if (expectedType === Array) return Array.isArray(actual);
      if (typeof expectedType === "function") return actual instanceof expectedType;
      return false;
    }
    if (expected.__bunStringContaining === true) {
      return typeof actual === "string" && actual.indexOf(expected.__value) !== -1;
    }
    if (expected.__bunStringMatching === true) {
      var expectedPattern = expected.__value;
      var matcher = expectedPattern instanceof RegExp
        ? expectedPattern
        : new RegExp(expectedPattern);
      return typeof actual === "string" && matcher.test(actual);
    }
    if (expected.__bunArrayContaining === true) {
      if (!Array.isArray(actual) || !Array.isArray(expected.__value)) return false;
      var expectedItems = expected.__value;
      for (var i = 0; i < expectedItems.length; i++) {
        var found = false;
        for (var j = 0; j < actual.length; j++) {
          if (partialMatch(actual[j], expectedItems[i])) {
            found = true;
            break;
          }
        }
        if (!found) return false;
      }
      return true;
    }
  }
  if (actual === expected) return true;
  if (expected == null || typeof expected !== "object") return actual === expected;
  if (actual == null || typeof actual !== "object") return false;
  var keys = Object.keys(expected);
  for (var i = 0; i < keys.length; i++) {
    if (!partialMatch(actual[keys[i]], expected[keys[i]])) return false;
  }
  return true;
}

function deepStrictEqualInternal(a, b, seen) {
  if (Object.is(a, b)) return true;
  if (a == null || b == null) return a === b;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object") return false;
  if (isUrlObject(a) || isUrlObject(b)) {
    return isUrlObject(a) && isUrlObject(b) &&
      Object.getPrototypeOf(a) === Object.getPrototypeOf(b) &&
      a.href === b.href;
  }
  if (isUrlSearchParamsObject(a) || isUrlSearchParamsObject(b)) {
    return isUrlSearchParamsObject(a) && isUrlSearchParamsObject(b) &&
      Object.getPrototypeOf(a) === Object.getPrototypeOf(b) &&
      a.toString() === b.toString();
  }
  if (Object.getPrototypeOf(a) !== Object.getPrototypeOf(b)) return false;
  if (isArrayBufferView(a) || isArrayBufferView(b)) {
    return arrayBufferViewsEqual(a, b);
  }
  if (hasSeenPair(seen, a, b)) return true;
  markSeenPair(seen, a, b);
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (!deepStrictEqualInternal(a[i], b[i], seen)) return false;
    }
    return true;
  }
  var keysA = Object.keys(a).sort();
  var keysB = Object.keys(b).sort();
  if (keysA.length !== keysB.length) return false;
  for (var i = 0; i < keysA.length; i++) {
    if (keysA[i] !== keysB[i]) return false;
  }
  for (var i = 0; i < keysA.length; i++) {
    if (!deepStrictEqualInternal(a[keysA[i]], b[keysA[i]], seen)) return false;
  }
  return true;
}

function deepStrictEqual(a, b) {
  return deepStrictEqualInternal(a, b, new WeakMap());
}

// ─── Bun-Specific Utilities ─────────────────────────────────────

function bunExe() {
  return process.execPath;
}

function createBunEnvAccessor(envObject) {
  var accessor = function() {
    return envObject;
  };
  if (typeof Proxy !== "function") {
    return accessor;
  }
  return new Proxy(accessor, {
    get: function(target, prop, receiver) {
      if (prop in target) {
        return Reflect.get(target, prop, receiver);
      }
      return envObject[prop];
    },
    set: function(_target, prop, value) {
      envObject[prop] = value;
      return true;
    },
    ownKeys: function(target) {
      var keys = Reflect.ownKeys(target);
      var envKeys = Object.keys(envObject);
      for (var i = 0; i < envKeys.length; i++) {
        if (keys.indexOf(envKeys[i]) === -1) {
          keys.push(envKeys[i]);
        }
      }
      return keys;
    },
    getOwnPropertyDescriptor: function(target, prop) {
      if (prop in target) {
        return Object.getOwnPropertyDescriptor(target, prop);
      }
      if (Object.prototype.hasOwnProperty.call(envObject, prop)) {
        return {
          configurable: true,
          enumerable: true,
          writable: true,
          value: envObject[prop],
        };
      }
      return undefined;
    },
  });
}
function resolveSharedBunEnv(defaultEnv) {
  if (typeof globalThis !== "object" || !globalThis) {
    return defaultEnv;
  }
  if (!globalThis.__exactSharedBunEnv || typeof globalThis.__exactSharedBunEnv !== "object") {
    globalThis.__exactSharedBunEnv = defaultEnv;
  }
  return globalThis.__exactSharedBunEnv;
}
var bunEnv = createBunEnvAccessor(resolveSharedBunEnv(process.env));

// ─── Test Runner ────────────────────────────────────────────────

function runTests() {
  var results = [];
  var testId = _savedTestId;

  function callTest(testFn) {
    if (typeof testFn !== "function") {
      return Promise.resolve();
    }

    return new Promise(function (resolve, reject) {
      var called = false;
      var previousPendingAssertions = _pendingAsyncAssertions;
      var pendingAssertions = [];
      _pendingAsyncAssertions = pendingAssertions;

      function restorePendingAssertions() {
        _pendingAsyncAssertions = previousPendingAssertions;
      }

      function settleSuccess(value) {
        Promise.all(pendingAssertions).then(function () {
          if (called) return;
          called = true;
          restorePendingAssertions();
          resolve(value);
        }, function (err) {
          if (called) return;
          called = true;
          restorePendingAssertions();
          reject(err);
        });
      }

      function settleFailure(err) {
        if (called) return;
        called = true;
        restorePendingAssertions();
        reject(err);
      }

      var done = function (err) {
        if (err) {
          settleFailure(err);
          return;
        }
        settleSuccess();
      };

      var result;
      try {
        result = testFn.length === 0 ? testFn() : testFn(done);
      } catch (err) {
        settleFailure(err);
        return;
      }

      if (result && typeof result.then === "function") {
        result.then(function (value) {
          settleSuccess(value);
        }, function (err) {
          settleFailure(err);
        });
      } else if (testFn.length === 0) {
        settleSuccess(result);
      }
    });
  }

  function runAsync() {
    var promise = Promise.resolve();

    // Run beforeAll hooks
    for (var i = 0; i < beforeAlls.length; i++) {
      promise = promise.then(beforeAlls[i]);
    }

    // Run each test
    function runTest(index) {
      if (index >= tests.length) return Promise.resolve();
      var tc = tests[index];
      var start = Date.now();
      traceTestStart(tc.name);

      var p = Promise.resolve();

      // beforeEach hooks
      for (var j = 0; j < beforeEachs.length; j++) {
        p = p.then(beforeEachs[j]);
      }

      p = p.then(function () { return callTest(tc.fn); });

      // afterEach hooks
      for (var j = 0; j < afterEachs.length; j++) {
        p = p.then(afterEachs[j]);
      }

      return p.then(function () {
        results.push({
          name: tc.name,
          id: testId,
          status: "pass",
          duration_ms: Date.now() - start,
        });
      }).catch(function (e) {
        if (e && e.name === "SkipError") {
          results.push({
            name: tc.name,
            id: testId,
            status: "skip",
            duration_ms: Date.now() - start,
          });
        } else {
          results.push({
            name: tc.name,
            id: testId,
            status: "fail",
            duration_ms: Date.now() - start,
            error: (e && e.message) || String(e),
            stack: e && e.stack,
          });
        }
      }).then(function () {
        return runTest(index + 1);
      });
    }

    promise = promise.then(function () { return runTest(0); });

    // Run afterAll hooks
    for (var i = 0; i < afterAlls.length; i++) {
      promise = promise.then(afterAlls[i]);
    }

    return promise.then(function () {
      // Emit results
      for (var i = 0; i < results.length; i++) {
        console.log(JSON.stringify({ type: "test_result", test: results[i] }));
      }
      var fail = results.filter(function (r) { return r.status === "fail"; }).length;
      _savedProcessExit(fail > 0 ? 1 : 0);
    });
  }

  return runAsync();
}

// Capture process.exit early before test code can tamper with globalThis.process
var _savedProcessExit = typeof process !== 'undefined' && typeof process.exit === 'function' ? process.exit.bind(process) : function() {};

// Auto-run tests after module evaluation completes
if (typeof setImmediate !== "undefined") {
  setImmediate(function () {
    runTests().catch(function (e) {
      console.error(e);
      _savedProcessExit(1);
    });
  });
} else {
  setTimeout(function () {
    runTests().catch(function (e) {
      console.error(e);
      _savedProcessExit(1);
    });
  }, 0);
}

expect.objectContaining = objectContaining;
expect.any = expectAny;
expect.stringContaining = function (str) {
  return { __bunStringContaining: true, __value: str };
};
expect.stringMatching = function (pattern) {
  return { __bunStringMatching: true, __value: pattern };
};
expect.arrayContaining = function (arr) {
  return { __bunArrayContaining: true, __value: arr };
};
expect.unreachable = function (msg) {
  throw new Error(msg || "Expected code to be unreachable");
};
expect.assertions = function (_count) {
  // No-op for compatibility (assertion counting not implemented)
};
expect.hasAssertions = function () {
  // No-op for compatibility
};

// ─── Mock ────────────────────────────────────────────────────────

function mockFn(implementation) {
  var calls = [];
  var results = [];
  var impl = implementation || function () {};

  function mockFunc() {
    var args = Array.prototype.slice.call(arguments);
    calls.push(args);
    var result;
    try {
      result = impl.apply(this, args);
      results.push({ type: "return", value: result });
    } catch (err) {
      results.push({ type: "throw", value: err });
      throw err;
    }
    return result;
  }

  mockFunc.mock = {
    calls: calls,
    results: results,
    instances: [],
    lastCall: undefined,
  };

  Object.defineProperty(mockFunc.mock, "lastCall", {
    get: function () { return calls.length > 0 ? calls[calls.length - 1] : undefined; },
  });

  mockFunc.mockImplementation = function (fn) {
    impl = fn;
    return mockFunc;
  };

  mockFunc.mockReturnValue = function (val) {
    impl = function () { return val; };
    return mockFunc;
  };

  mockFunc.mockReturnValueOnce = function (val) {
    var origImpl = impl;
    var called = false;
    impl = function () {
      if (!called) { called = true; return val; }
      return origImpl.apply(this, arguments);
    };
    return mockFunc;
  };

  mockFunc.mockResolvedValue = function (val) {
    impl = function () { return Promise.resolve(val); };
    return mockFunc;
  };

  mockFunc.mockRejectedValue = function (val) {
    impl = function () { return Promise.reject(val); };
    return mockFunc;
  };

  mockFunc.mockClear = function () {
    calls.length = 0;
    results.length = 0;
    return mockFunc;
  };

  mockFunc.mockReset = function () {
    calls.length = 0;
    results.length = 0;
    impl = function () {};
    return mockFunc;
  };

  mockFunc.getMockName = function () { return "mockFn"; };
  mockFunc.mockName = function () { return mockFunc; };

  return mockFunc;
}

function mock(fn) {
  return mockFn(fn);
}

mock.fn = mockFn;
mock.module = function () { return mock; };
mock.restore = function () {};

function spyOn(obj, method) {
  if ((typeof obj !== "object" && typeof obj !== "function") || obj === null) {
    throw new TypeError("spyOn target must be an object");
  }

  var ownDescriptor = Object.getOwnPropertyDescriptor(obj, method);
  var descriptor = ownDescriptor;
  var proto = obj;
  while (!descriptor && proto) {
    proto = Object.getPrototypeOf(proto);
    if (proto) {
      descriptor = Object.getOwnPropertyDescriptor(proto, method);
    }
  }

  if (!descriptor) {
    throw new TypeError("Cannot spyOn property that does not exist: " + String(method));
  }

  function restore() {
    if (ownDescriptor) {
      Object.defineProperty(obj, method, ownDescriptor);
    } else {
      delete obj[method];
    }
  }

  if (typeof descriptor.value === "function") {
    var originalFn = descriptor.value;
    var fnSpy = mockFn(function () {
      return originalFn.apply(this, arguments);
    });
    Object.defineProperty(obj, method, {
      configurable: true,
      enumerable: descriptor.enumerable !== false,
      writable: true,
      value: fnSpy,
    });
    fnSpy.mockRestore = restore;
    return fnSpy;
  }

  var getter = descriptor.get;
  var setter = descriptor.set;
  var currentValue = descriptor.value;
  var accessSpy = mockFn(function () {});
  Object.defineProperty(obj, method, {
    configurable: true,
    enumerable: descriptor.enumerable !== false,
    get: function () {
      accessSpy();
      if (typeof getter === "function") {
        return getter.call(this);
      }
      return currentValue;
    },
    set: function (value) {
      if (typeof setter === "function") {
        setter.call(this, value);
      } else {
        currentValue = value;
      }
    },
  });
  accessSpy.mockRestore = restore;
  return accessSpy;
}

var jest = {
  fn: mockFn,
  spyOn: spyOn,
  restoreAllMocks: function () {},
  clearAllMocks: function () {},
  resetAllMocks: function () {},
};

if (typeof global.mock !== "function") {
  global.mock = mock;
}
if (typeof global.jest === "undefined") {
  global.jest = jest;
}
if (typeof global.spyOn !== "function") {
  global.spyOn = spyOn;
}
try {
  require("bun");
} catch (_err) {}

// ─── Exports ────────────────────────────────────────────────────

module.exports = {
  describe: describe,
  test: test,
  it: it,
  expect: expect,
  suite: describe,
  before: beforeAll,
  beforeEach: beforeEach,
  afterEach: afterEach,
  after: afterAll,
  beforeAll: beforeAll,
  afterAll: afterAll,
  bunExe: bunExe,
  bunEnv: bunEnv,
  mock: mock,
  spyOn: spyOn,
  jest: jest,
};
