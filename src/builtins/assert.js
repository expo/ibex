function _typeof(v) {
  return v === null ? 'null' : typeof v;
}

function _inspect(v) {
  var isNodeUtil = false;
  if (!_inspect._initialized) {
    try {
      _inspect._util = require('util').inspect;
      isNodeUtil = true;
    } catch (e) {
      _inspect._util = null;
    }
    _inspect._initialized = true;
  }

  if (_inspect._util) {
    try {
      return _inspect._util(v, {
        compact: true,
        breakLength: Infinity,
      });
    } catch (e) {
      // fall back
    }
  }

  if (v === undefined) return 'undefined';
  if (v === null) return 'null';
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'function') return '[Function' + (v.name ? ': ' + v.name : '') + ']';
  try {
    return JSON.stringify(v);
  } catch (e) {
    return String(v);
  }
}

class AssertionError extends Error {
  constructor(opts) {
    if (!opts || _typeof(opts) !== 'object') {
      var typeErr = new TypeError('The "options" argument must be of type object.' +
          ' Received type "' + _typeof(opts) + '"');
      typeErr.code = 'ERR_INVALID_ARG_TYPE';
      throw typeErr;
    }

    var msg = opts.message || ('Expected values to be ' + (opts.operator || 'truthy'));
    super(msg);
    this.name = 'AssertionError';
    this.actual = opts.actual;
    this.expected = opts.expected;
    this.operator = opts.operator;
    this.code = 'ERR_ASSERTION';
    this.generatedMessage = opts.generatedMessage !== undefined ? opts.generatedMessage : (opts.message ? false : true);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, AssertionError);
    }
  }
}

function _isErrorConstructor(expected) {
  return (
    typeof expected === 'function' &&
    expected.prototype &&
    expected.prototype instanceof Error
  );
}

function _ifErrorValue(err) {
  if (err === undefined || err === null) return '';
  if (err instanceof Error) {
    return (typeof err.message === 'string' && err.message.length > 0)
      ? err.message
      : (typeof err.name === 'string' ? err.name : String(err));
  }
  if (_typeof(err) === 'object' && Object.prototype.hasOwnProperty.call(err, 'message')) {
    return typeof err.message === 'string' ? err.message : _inspect(err.message);
  }
  if (_typeof(err) === 'string') return err;
  if (_typeof(err) === 'boolean' || _typeof(err) === 'number' || _typeof(err) === 'symbol') {
    return String(err);
  }
  return _inspect(err);
}

function _errorTypeName(err) {
  if (err === null || err === undefined) return String(err);
  if (_typeof(err) === 'string') return err;
  if (_typeof(err) === 'number' || _typeof(err) === 'boolean' || _typeof(err) === 'symbol') return String(err);
  if (_typeof(err) === 'object' && err.name) return String(err.name);
  return _inspect(err);
}

function _deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;

  // Handle NaN
  if (typeof a === 'number' && isNaN(a) && isNaN(b)) return true;

  if (typeof a !== 'object') return false;

  // Handle Date
  if (a instanceof Date && b instanceof Date) {
    return a.getTime() === b.getTime();
  }

  // Handle RegExp
  if (a instanceof RegExp && b instanceof RegExp) {
    return a.source === b.source && a.flags === b.flags;
  }

  // Handle Error
  if (a instanceof Error && b instanceof Error) {
    return a.message === b.message && a.name === b.name;
  }

  // Handle ArrayBuffer
  if (typeof ArrayBuffer !== 'undefined' && a instanceof ArrayBuffer && b instanceof ArrayBuffer) {
    if (a.byteLength !== b.byteLength) return false;
    var viewA = new Uint8Array(a);
    var viewB = new Uint8Array(b);
    for (var i = 0; i < viewA.length; i++) {
      if (viewA[i] !== viewB[i]) return false;
    }
    return true;
  }

  // Handle TypedArrays
  if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(a) && ArrayBuffer.isView(b)) {
    if (a.constructor !== b.constructor) return false;
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (!_deepEqual(a[i], b[i])) return false;
    }
    return true;
  }

  // Handle Map
  if (typeof Map !== 'undefined' && a instanceof Map && b instanceof Map) {
    if (a.size !== b.size) return false;
    var aEntries = Array.from(a.entries());
    for (var i = 0; i < aEntries.length; i++) {
      var key = aEntries[i][0];
      if (!b.has(key)) return false;
      if (!_deepEqual(aEntries[i][1], b.get(key))) return false;
    }
    return true;
  }

  // Handle Set
  if (typeof Set !== 'undefined' && a instanceof Set && b instanceof Set) {
    if (a.size !== b.size) return false;
    var aArr = Array.from(a);
    var bArr = Array.from(b);
    // For primitive values, use direct comparison
    // For objects, try to find matching elements
    var matched = new Array(bArr.length);
    for (var i = 0; i < aArr.length; i++) {
      var found = false;
      for (var j = 0; j < bArr.length; j++) {
        if (!matched[j] && _deepEqual(aArr[i], bArr[j])) {
          matched[j] = true;
          found = true;
          break;
        }
      }
      if (!found) return false;
    }
    return true;
  }

  // Ensure same constructor/prototype
  if (a.constructor !== b.constructor) {
    // Allow comparison between plain objects and Object.create(null)
    if (!(
      (a.constructor === Object || a.constructor === undefined) &&
      (b.constructor === Object || b.constructor === undefined)
    )) {
      return false;
    }
  }

  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (!_deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  var keysA = Object.keys(a);
  var keysB = Object.keys(b);
  if (keysA.length !== keysB.length) return false;
  for (var i = 0; i < keysA.length; i++) {
    var key = keysA[i];
    if (!Object.prototype.hasOwnProperty.call(b, key)) return false;
    if (!_deepEqual(a[key], b[key])) return false;
  }
  return true;
}

function ok(value, message) {
  if (!value) {
    throw new AssertionError({
      message: message || 'The expression evaluated to a falsy value',
      actual: value,
      expected: true,
      operator: '=='
    });
  }
}

function equal(actual, expected, message) {
  if (actual != expected) {
    throw new AssertionError({ message: message, actual: actual, expected: expected, operator: '==' });
  }
}

function notEqual(actual, expected, message) {
  if (actual == expected) {
    throw new AssertionError({ message: message, actual: actual, expected: expected, operator: '!=' });
  }
}

function strictEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new AssertionError({ message: message, actual: actual, expected: expected, operator: '===' });
  }
}

function notStrictEqual(actual, expected, message) {
  if (actual === expected) {
    throw new AssertionError({ message: message, actual: actual, expected: expected, operator: '!==' });
  }
}

function deepEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected)) {
    throw new AssertionError({ message: message, actual: actual, expected: expected, operator: 'deepEqual' });
  }
}

function deepStrictEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected)) {
    throw new AssertionError({ message: message, actual: actual, expected: expected, operator: 'deepStrictEqual' });
  }
}

function notDeepEqual(actual, expected, message) {
  if (_deepEqual(actual, expected)) {
    throw new AssertionError({ message: message, actual: actual, expected: expected, operator: 'notDeepEqual' });
  }
}

function notDeepStrictEqual(actual, expected, message) {
  if (_deepEqual(actual, expected)) {
    throw new AssertionError({ message: message, actual: actual, expected: expected, operator: 'notDeepStrictEqual' });
  }
}

function throws(fn, expected, message) {
  var threw = false;
  var caught;
  try {
    fn();
  } catch (e) {
    threw = true;
    caught = e;
  }
  if (!threw) {
    throw new AssertionError({
      message: message || 'Missing expected exception',
      operator: 'throws'
    });
  }
  if (expected) {
    if (_isErrorConstructor(expected)) {
      if (caught instanceof expected) return;
      throw new AssertionError({
        message: 'The error is expected to be an instance of "' +
            (expected.name || 'Error') +
            '". ' +
            'Received "' + _errorTypeName(caught) + '"\n\nError message:\n\n' +
            _inspect(caught),
        actual: caught,
        expected: expected,
        operator: 'throws'
      });
    }

    if (typeof expected === 'function') {
      if (expected(caught) === true) return;
      throw new AssertionError({ message: message || 'Unexpected exception', actual: caught, expected: expected, operator: 'throws' });
    }
    if (expected instanceof RegExp) {
      if (expected.test(String(caught))) return;
      throw new AssertionError({ message: message || 'Unexpected exception', actual: caught, expected: expected, operator: 'throws' });
    }
    // Plain object: validate each property against caught error
    if (typeof expected === 'object' && expected !== null) {
      var keys = Object.keys(expected);
      for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        if (expected[key] instanceof RegExp) {
          if (!expected[key].test(String(caught[key]))) {
            throw new AssertionError({
              message: message || 'The error property "' + key + '" ("' + caught[key] + '") does not match ' + expected[key],
              actual: caught,
              expected: expected,
              operator: 'throws'
            });
          }
        } else if (!_deepEqual(caught[key], expected[key])) {
          throw new AssertionError({
            message: message || 'Expected error property "' + key + '" to be ' + _inspect(expected[key]) + ', got ' + _inspect(caught[key]),
            actual: caught,
            expected: expected,
            operator: 'throws'
          });
        }
      }
      return;
    }
  }
}

function doesNotThrow(fn, expected, message) {
  try {
    fn();
  } catch (e) {
    throw new AssertionError({
      message: message || 'Got unwanted exception',
      actual: e,
      operator: 'doesNotThrow'
    });
  }
}

function ifError(err) {
  if (err !== null && err !== undefined) {
    throw new AssertionError({
      message: 'ifError got unwanted exception: ' + _ifErrorValue(err),
      actual: err,
      expected: null,
      operator: 'ifError'
    });
  }
}

function fail(message) {
  if (message === undefined) {
    throw new AssertionError({
      message: 'Failed',
      operator: 'fail',
      generatedMessage: true
    });
  }
  if (message instanceof Error) {
    throw message;
  }
  throw new AssertionError({
    message: message || 'Failed',
    operator: 'fail'
  });
}

function match(string, regexp, message) {
  if (!regexp.test(string)) {
    throw new AssertionError({ message: message, actual: string, expected: regexp, operator: 'match' });
  }
}

function doesNotMatch(string, regexp, message) {
  if (regexp.test(string)) {
    throw new AssertionError({ message: message, actual: string, expected: regexp, operator: 'doesNotMatch' });
  }
}

async function rejects(asyncFn, expected, message) {
  var threw = false;
  var caught;
  try {
    var promise = typeof asyncFn === 'function' ? asyncFn() : asyncFn;
    await promise;
  } catch (e) {
    threw = true;
    caught = e;
  }
  if (!threw) {
    throw new AssertionError({
      message: message || 'Missing expected rejection',
      operator: 'rejects'
    });
  }
  if (expected !== undefined && expected !== null) {
    if (_isErrorConstructor(expected)) {
      if (caught instanceof expected) return;
      throw new AssertionError({
        message: 'The error is expected to be an instance of "' +
            (expected.name || 'Error') + '". ' +
            'Received "' + _errorTypeName(caught) + '"',
        actual: caught,
        expected: expected,
        operator: 'rejects'
      });
    }
    if (typeof expected === 'function') {
      if (expected(caught) === true) return;
      throw new AssertionError({ message: message || 'Unexpected rejection', actual: caught, expected: expected, operator: 'rejects' });
    }
    if (expected instanceof RegExp) {
      if (expected.test(String(caught))) return;
      throw new AssertionError({ message: message || 'Unexpected rejection', actual: caught, expected: expected, operator: 'rejects' });
    }
    if (typeof expected === 'object') {
      // Validate error properties
      var keys = Object.keys(expected);
      for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        if (key === 'message' && expected.message instanceof RegExp) {
          if (!expected.message.test(caught.message)) {
            throw new AssertionError({
              message: message || 'Error message mismatch',
              actual: caught.message,
              expected: expected.message,
              operator: 'rejects'
            });
          }
        } else if (!_deepEqual(caught[key], expected[key])) {
          throw new AssertionError({
            message: message || 'Error property "' + key + '" mismatch',
            actual: caught[key],
            expected: expected[key],
            operator: 'rejects'
          });
        }
      }
      return;
    }
  }
}

async function doesNotReject(asyncFn, expected, message) {
  try {
    var promise = typeof asyncFn === 'function' ? asyncFn() : asyncFn;
    await promise;
  } catch (e) {
    throw new AssertionError({
      message: message || 'Got unwanted rejection: ' + _ifErrorValue(e),
      actual: e,
      operator: 'doesNotReject'
    });
  }
}

function assert(value, message) {
  ok(value, message);
}

assert.ok = ok;
assert.equal = equal;
assert.notEqual = notEqual;
assert.strictEqual = strictEqual;
assert.notStrictEqual = notStrictEqual;
assert.deepEqual = deepEqual;
assert.deepStrictEqual = deepStrictEqual;
assert.notDeepEqual = notDeepEqual;
assert.notDeepStrictEqual = notDeepStrictEqual;
assert.throws = throws;
assert.doesNotThrow = doesNotThrow;
assert.rejects = rejects;
assert.doesNotReject = doesNotReject;
assert.ifError = ifError;
assert.fail = fail;
assert.match = match;
assert.doesNotMatch = doesNotMatch;
assert.AssertionError = AssertionError;
assert.strict = assert;

module.exports = assert;
