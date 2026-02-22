function _typeof(v) {
  return v === null ? 'null' : typeof v;
}

function _inspect(v) {
  if (v === undefined) return 'undefined';
  if (v === null) return 'null';
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'function') return '[Function' + (v.name ? ': ' + v.name : '') + ']';
  try { return JSON.stringify(v); } catch(e) { return String(v); }
}

function AssertionError(opts) {
  var msg = opts.message || ('Expected values to be ' + (opts.operator || 'truthy'));
  if (opts.actual !== undefined && opts.expected !== undefined) {
    msg += '\n  actual: ' + _inspect(opts.actual) + '\n  expected: ' + _inspect(opts.expected);
  }
  var err = new Error(msg);
  err.name = 'AssertionError';
  err.actual = opts.actual;
  err.expected = opts.expected;
  err.operator = opts.operator;
  err.code = 'ERR_ASSERTION';
  return err;
}

function _deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return false;
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
    throw AssertionError({
      message: message || 'The expression evaluated to a falsy value',
      actual: value,
      expected: true,
      operator: '=='
    });
  }
}

function equal(actual, expected, message) {
  if (actual != expected) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: '==' });
  }
}

function notEqual(actual, expected, message) {
  if (actual == expected) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: '!=' });
  }
}

function strictEqual(actual, expected, message) {
  if (actual !== expected) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: '===' });
  }
}

function notStrictEqual(actual, expected, message) {
  if (actual === expected) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: '!==' });
  }
}

function deepEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected)) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: 'deepEqual' });
  }
}

function deepStrictEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected)) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: 'deepStrictEqual' });
  }
}

function notDeepEqual(actual, expected, message) {
  if (_deepEqual(actual, expected)) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: 'notDeepEqual' });
  }
}

function notDeepStrictEqual(actual, expected, message) {
  if (_deepEqual(actual, expected)) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: 'notDeepStrictEqual' });
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
    throw AssertionError({
      message: message || 'Missing expected exception',
      operator: 'throws'
    });
  }
  if (expected) {
    if (typeof expected === 'function') {
      if (expected.prototype && caught instanceof expected) return;
      if (expected(caught) === true) return;
      throw AssertionError({ message: message || 'Unexpected exception', actual: caught, expected: expected, operator: 'throws' });
    }
    if (expected instanceof RegExp) {
      if (expected.test(String(caught))) return;
      throw AssertionError({ message: message || 'Unexpected exception', actual: caught, expected: expected, operator: 'throws' });
    }
  }
}

function doesNotThrow(fn, expected, message) {
  try {
    fn();
  } catch (e) {
    throw AssertionError({
      message: message || 'Got unwanted exception',
      actual: e,
      operator: 'doesNotThrow'
    });
  }
}

function ifError(err) {
  if (err !== null && err !== undefined) {
    throw err;
  }
}

function fail(message) {
  throw AssertionError({
    message: message || 'Failed',
    operator: 'fail'
  });
}

function match(string, regexp, message) {
  if (!regexp.test(string)) {
    throw AssertionError({ message: message, actual: string, expected: regexp, operator: 'match' });
  }
}

function doesNotMatch(string, regexp, message) {
  if (regexp.test(string)) {
    throw AssertionError({ message: message, actual: string, expected: regexp, operator: 'doesNotMatch' });
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
assert.ifError = ifError;
assert.fail = fail;
assert.match = match;
assert.doesNotMatch = doesNotMatch;
assert.AssertionError = AssertionError;
assert.strict = assert;

module.exports = assert;
