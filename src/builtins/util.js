function inherits(constructor, superConstructor) {
  if (typeof constructor !== 'function') {
    var e1 = new TypeError('The "ctor" argument must be of type function. Received ' + (constructor === null ? 'null' : typeof constructor));
    e1.code = 'ERR_INVALID_ARG_TYPE';
    throw e1;
  }
  if (superConstructor === null || (typeof superConstructor !== 'function' && typeof superConstructor !== 'object')) {
    var e2 = new TypeError('The "superCtor" argument must be of type function. Received ' + (superConstructor === null ? 'null' : typeof superConstructor));
    e2.code = 'ERR_INVALID_ARG_TYPE';
    throw e2;
  }
  if (superConstructor.prototype === undefined) {
    var e3 = new TypeError('The "superCtor.prototype" property must be of type object. Received undefined');
    e3.code = 'ERR_INVALID_ARG_TYPE';
    throw e3;
  }
  Object.defineProperty(constructor, 'super_', {
    value: superConstructor,
    writable: true,
    configurable: true,
    enumerable: false,
  });
  Object.setPrototypeOf(constructor.prototype, superConstructor.prototype);
}

var kCustomPromisifiedSymbol = Symbol.for('nodejs.util.promisify.custom');

function promisify(fn) {
  if (typeof fn !== "function") {
    throw new TypeError("util.promisify requires a function");
  }
  // Check for custom promisify implementation
  var customSymbol = promisify.custom;
  if (customSymbol != null) {
    var custom = fn[customSymbol];
    if (custom != null) {
      if (typeof custom !== "function") {
        var customErr = new TypeError("The promisify custom value must be a function");
        customErr.code = 'ERR_INVALID_ARG_TYPE';
        throw customErr;
      }
      return custom;
    }
  }
  return function() {
    var args = [];
    var i = 0;
    while (i < arguments.length) {
      args.push(arguments[i]);
      i += 1;
    }
    var self = this;
    var resolve, reject;
    var promise = new Promise(function(res, rej) {
      resolve = res;
      reject = rej;
    });
    args.push(function(err) {
      if (err) {
        return reject(err);
      }
      if (arguments.length <= 1) return resolve(undefined);
      if (arguments.length === 2) return resolve(arguments[1]);
      var output = [];
      for (var j = 1; j < arguments.length; j++) {
        output.push(arguments[j]);
      }
      return resolve(output);
    });
    fn.apply(self, args);
    return promise;
  };
}

function format(value) {
  if (arguments.length === 0) return "";
  if (typeof value !== "string") {
    var parts = [];
    for (var i = 0; i < arguments.length; i++) {
      var part = arguments[i];
      parts.push(typeof part === 'string' ? part : inspect(part));
    }
    return parts.join(' ');
  }
  var i = 1;
  var args = arguments;
  var result = value.replace(/%[sdifjoOc%]/g, function(match) {
    if (match === "%%") return "%";
    if (i >= args.length) return match;
    var arg = args[i];
    i += 1;
    if (match === "%s") return String(arg);
    if (match === "%d") return String(Number(arg));
    if (match === "%i") return String(parseInt(arg, 10));
    if (match === "%f") return String(parseFloat(arg));
    if (match === "%c") return "";
    if (match === "%j") return JSON.stringify(arg);
    if (match === "%o" || match === "%O") return inspect(arg);
    return match;
  });
  while (i < args.length) {
    result += ' ' + (typeof args[i] === 'string' ? args[i] : inspect(args[i]));
    i++;
  }
  return result;
}

function formatWithOptions(inspectOptions) {
  if (arguments.length <= 1) return "";
  var value = arguments[1];
  if (typeof value !== "string") {
    var parts = [];
    for (var i = 1; i < arguments.length; i++) {
      var part = arguments[i];
      parts.push(typeof part === 'string' ? part : inspect(part, inspectOptions));
    }
    return parts.join(' ');
  }
  var i = 2;
  var args = arguments;
  var opts = inspectOptions;
  var result = value.replace(/%[sdifjoOc%]/g, function(match) {
    if (match === "%%") return "%";
    if (i >= args.length) return match;
    var arg = args[i];
    i += 1;
    if (match === "%s") return String(arg);
    if (match === "%d") return String(Number(arg));
    if (match === "%i") return String(parseInt(arg, 10));
    if (match === "%f") return String(parseFloat(arg));
    if (match === "%c") return "";
    if (match === "%j") return JSON.stringify(arg);
    if (match === "%o" || match === "%O") return inspect(arg, opts);
    return match;
  });
  while (i < args.length) {
    result += ' ' + (typeof args[i] === 'string' ? args[i] : inspect(args[i], opts));
    i++;
  }
  return result;
}

function log() {
  var now = new Date();
  var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var d = now.getDate();
  var h = now.getHours();
  var m = now.getMinutes();
  var s = now.getSeconds();
  var ts = d + ' ' + months[now.getMonth()] + ' ' +
    (h < 10 ? '0' + h : '' + h) + ':' +
    (m < 10 ? '0' + m : '' + m) + ':' +
    (s < 10 ? '0' + s : '' + s);
  var msg = format.apply(null, arguments);
  if (typeof process !== 'undefined' && process.stdout && typeof process.stdout.write === 'function') {
    process.stdout.write(ts + ' - ' + msg + '\n');
  }
}

function inspect(value, options) {
  var opts = options || {};
  var depth = opts.depth !== undefined ? opts.depth : 2;
  var colors = opts.colors || false;
  var breakLength = opts.breakLength !== undefined ? opts.breakLength : 72;
  var seen = [];
  var cache = new Map();
  var _indentCache = {};
  function _makeIndent(n) {
    if (n <= 0) return '';
    if (_indentCache[n]) return _indentCache[n];
    var s = '';
    for (var i = 0; i < n; i++) s += ' ';
    if (n < 100) _indentCache[n] = s;
    return s;
  }
  function _colorize(str, styleType) {
    if (!colors) return str;
    var codes;
    switch (styleType) {
      case 'number': codes = ['\x1b[33m', '\x1b[39m']; break; // yellow
      case 'boolean': codes = ['\x1b[33m', '\x1b[39m']; break; // yellow
      case 'string': codes = ['\x1b[32m', '\x1b[39m']; break; // green
      case 'null': codes = ['\x1b[1m', '\x1b[22m']; break; // bold
      case 'undefined': codes = ['\x1b[90m', '\x1b[39m']; break; // grey
      case 'special': codes = ['\x1b[36m', '\x1b[39m']; break; // cyan
      case 'regexp': codes = ['\x1b[31m', '\x1b[39m']; break; // red
      case 'date': codes = ['\x1b[35m', '\x1b[39m']; break; // magenta
      case 'symbol': codes = ['\x1b[32m', '\x1b[39m']; break; // green
      case 'bigint': codes = ['\x1b[33m', '\x1b[39m']; break; // yellow
      default: return str;
    }
    return codes[0] + str + codes[1];
  }
  function _inspect(val, currentDepth) {
    if (val === null) return _colorize('null', 'null');
    if (val === undefined) return _colorize('undefined', 'undefined');
    var t = typeof val;
    if (t === 'string') return _colorize("'" + val.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'", 'string');
    if (t === 'number') return _colorize(String(val), 'number');
    if (t === 'boolean') return _colorize(String(val), 'boolean');
    if (t === 'symbol') return _colorize(val.toString(), 'symbol');
    if (t === 'function') {
      var name = val.name || 'anonymous';
      return _colorize('[Function: ' + name + ']', 'special');
    }
    if (t === 'bigint') return _colorize(val.toString() + 'n', 'bigint');
    // Object types
    if (seen.indexOf(val) !== -1) return '[Circular]';
    if (cache.has(val)) return cache.get(val);

    // Support util.inspect.custom symbol
    try {
      var customInspect = inspect.custom && val[inspect.custom];
      if (typeof customInspect === 'function') {
        var customResult = customInspect.call(val, currentDepth, opts);
        return typeof customResult === 'string' ? customResult : _inspect(customResult, currentDepth);
      }
    } catch(proxyErr) {
      // Revoked proxy - property access throws
      return 'Object [revoked Proxy] {}';
    }

    seen.push(val);
    var result;
    try {
      if (currentDepth > depth && depth !== null) {
        if (Array.isArray(val)) {
          result = '[Array]';
        } else if (val.constructor && val.constructor.name && val.constructor.name !== 'Object') {
          result = val.constructor.name;
        } else {
          result = '[Object]';
        }
      } else if (Array.isArray(val)) {
        if (val.length === 0) {
          result = '[]';
        } else {
          var items = [];
          for (var i = 0; i < val.length; i++) {
            items.push(_inspect(val[i], currentDepth + 1));
          }
          var singleLine = '[ ' + items.join(', ') + ' ]';
          if (breakLength > 0 && currentDepth < 10 && singleLine.length > breakLength) {
            var indent = _makeIndent((currentDepth + 1) * 2);
            var baseIndent = _makeIndent(currentDepth * 2);
            result = '[\n';
            for (var ai = 0; ai < items.length; ai++) {
              result += indent + items[ai];
              if (ai < items.length - 1) result += ',';
              result += '\n';
            }
            result += baseIndent + ']';
          } else {
            result = singleLine;
          }
        }
      } else if (typeof Map !== 'undefined' && val instanceof Map) {
        var mapParts = [];
        val.forEach(function(mapValue, mapKey) {
          mapParts.push(_inspect(mapKey, currentDepth + 1) + ' => ' + _inspect(mapValue, currentDepth + 1));
        });
        result = 'Map(' + val.size + ') {' + (mapParts.length ? ' ' + mapParts.join(', ') + ' ' : '') + '}';
      } else if (typeof Set !== 'undefined' && val instanceof Set) {
        var setParts = [];
        val.forEach(function(setValue) {
          setParts.push(_inspect(setValue, currentDepth + 1));
        });
        result = 'Set(' + val.size + ') {' + (setParts.length ? ' ' + setParts.join(', ') + ' ' : '') + '}';
      } else if (val instanceof Date) {
        result = _colorize(val.toISOString(), 'date');
      } else if (val instanceof RegExp) {
        result = _colorize(String(val), 'regexp');
      } else if (val instanceof Error) {
        var stack = typeof val.stack === 'string' && val.stack ? val.stack : '';
        if (!stack) {
          stack = (val.constructor && val.constructor.name ? val.constructor.name : 'Error') +
            (val.message ? ': ' + val.message : '');
        }
        result = stack;
      } else if (typeof val.constructor === 'function' && val.constructor.name === 'Buffer') {
        result = '<Buffer ' + Array.prototype.slice.call(val, 0, Math.min(val.length, 50)).map(function(b) { return (b < 16 ? '0' : '') + b.toString(16); }).join(' ') + (val.length > 50 ? ' ... ' + (val.length - 50) + ' more bytes' : '') + '>';
      } else {
        // Plain object
        var ctorPrefix = '';
        if (val.constructor && val.constructor.name && val.constructor.name !== 'Object') {
          ctorPrefix = val.constructor.name + ' ';
        }
        var keys = Object.keys(val);
        if (keys.length === 0) {
          result = ctorPrefix + '{}';
        } else {
          var parts = [];
          for (var ki = 0; ki < keys.length; ki++) {
            var k = keys[ki];
            var v;
            try { v = _inspect(val[k], currentDepth + 1); } catch(e) { v = '[Getter/Error]'; }
            parts.push(k + ': ' + v);
          }
          var singleObj = ctorPrefix + '{ ' + parts.join(', ') + ' }';
          if (breakLength > 0 && currentDepth < 10 && singleObj.length > breakLength) {
            var objIndent = _makeIndent((currentDepth + 1) * 2);
            var objBase = _makeIndent(currentDepth * 2);
            result = ctorPrefix + '{\n';
            for (var pi = 0; pi < parts.length; pi++) {
              result += objIndent + parts[pi];
              if (pi < parts.length - 1) result += ',';
              result += '\n';
            }
            result += objBase + '}';
          } else {
            result = singleObj;
          }
        }
      }
    } catch(inspectErr) {
      // Handle revoked proxies and other errors during inspection
      result = 'Object [revoked Proxy] {}';
    } finally {
      seen.pop();
      if (result !== undefined) {
        cache.set(val, result);
      }
    }

    return result;
  }
  return _inspect(value, 0);
}
inspect.custom = Symbol.for('nodejs.util.inspect.custom');
inspect.styles = {};
inspect.colors = {};
inspect.defaultOptions = { depth: 2, colors: false };

function deprecated(message) {
  return function() {
    if (typeof console !== "undefined" && console.warn) {
      console.warn(message);
    }
    if (typeof deprecated._fn === "function") {
      return deprecated._fn.apply(this, arguments);
    }
    return undefined;
  };
}

// Manifest-authored builtin dependencies are resolvable only while this body
// is synchronously evaluating. Capturing the assert module here keeps the
// exported function from leaking a late trusted-require closure after that
// window closes.
// @ref LLP 0022#7-capabilities-principals-and-affordance-parity — trusted
// builtin plumbing must not become an import-policy exemption callable later.
var _assertModule = require("assert");

var util = {
  inherits: inherits,
  promisify: promisify,
  format: format,
  formatWithOptions: formatWithOptions,
  log: log,
  inspect: inspect,
  deprecate: function(fn, message, code) {
    if (code !== undefined && typeof code !== 'string') {
      var codeDetail;
      if (code === null) codeDetail = ' Received null';
      else if (typeof code === 'object') {
        if (code.constructor && code.constructor.name) codeDetail = ' Received an instance of ' + code.constructor.name;
        else codeDetail = ' Received ' + String(code);
      }
      else if (typeof code === 'boolean') codeDetail = ' Received type boolean (' + code + ')';
      else if (typeof code === 'number') codeDetail = ' Received type number (' + code + ')';
      else codeDetail = ' Received type ' + typeof code + ' (' + String(code) + ')';
      var codeErr = new TypeError('The "code" argument must be of type string.' + codeDetail);
      codeErr.code = 'ERR_INVALID_ARG_TYPE';
      throw codeErr;
    }
    if (typeof fn !== "function") return undefined;
    var wrapped = function() {
      if (wrapped._warned !== true && typeof console !== "undefined" && console.warn) {
        console.warn(message);
        wrapped._warned = true;
      }
      return fn.apply(this, arguments);
    };
    return wrapped;
  },
  types: {
    isPromise: function(value) { return value instanceof Promise || (value && typeof value.then === "function"); },
    isModuleNamespaceObject: function(value) {
      if (value === null || typeof value !== "object") return false;
      if (typeof Symbol === 'function' && Symbol.toStringTag && value[Symbol.toStringTag] === "Module") return true;
      return Object.prototype.toString.call(value) === "[object Module]";
    },
    isAsyncFunction: function(value) { return value && value.constructor && value.constructor.name === "AsyncFunction"; },
    isArrayBufferView: function(value) {
      return value && (typeof ArrayBuffer !== "undefined") && ArrayBuffer.isView(value);
    },
    isAnyArrayBuffer: function(value) {
      return value instanceof ArrayBuffer ||
        (typeof SharedArrayBuffer !== "undefined" && value instanceof SharedArrayBuffer);
    },
    isArgumentsObject: function(value) {
      return Object.prototype.toString.call(value) === "[object Arguments]";
    },
    isDate: function(value) { return value instanceof Date; },
    isRegExp: function(value) { return value instanceof RegExp; },
    isSet: function(value) { return typeof Set !== "undefined" && value instanceof Set; },
    isSetIterator: function(value) {
      return Object.prototype.toString.call(value) === "[object Set Iterator]";
    },
    isMap: function(value) { return typeof Map !== "undefined" && value instanceof Map; },
    isMapIterator: function(value) {
      return Object.prototype.toString.call(value) === "[object Map Iterator]";
    },
    isTypedArray: function(value) {
      return value && (value instanceof Int8Array || value instanceof Uint8Array ||
        value instanceof Uint8ClampedArray || value instanceof Int16Array ||
        value instanceof Uint16Array || value instanceof Int32Array ||
        value instanceof Uint32Array || value instanceof Float32Array ||
        value instanceof Float64Array ||
        (typeof BigInt64Array !== "undefined" && value instanceof BigInt64Array) ||
        (typeof BigUint64Array !== "undefined" && value instanceof BigUint64Array));
    },
    isNativeError: function(value) { return value instanceof Error; },
    isNumberObject: function(value) { return typeof value === "object" && value instanceof Number; },
    isStringObject: function(value) { return typeof value === "object" && value instanceof String; },
    isBooleanObject: function(value) { return typeof value === "object" && value instanceof Boolean; },
    isSymbolObject: function(value) {
      return Object.prototype.toString.call(value) === "[object Symbol]" && typeof value === "object";
    },
    isBigInt64Array: function(value) {
      return typeof BigInt64Array !== "undefined" && value instanceof BigInt64Array;
    },
    isBigUint64Array: function(value) {
      return typeof BigUint64Array !== "undefined" && value instanceof BigUint64Array;
    },
    isBoxedPrimitive: function(value) {
      return value instanceof Number || value instanceof String ||
        value instanceof Boolean ||
        (typeof Symbol !== "undefined" && Object.prototype.toString.call(value) === "[object Symbol]" && typeof value === "object") ||
        (typeof BigInt !== "undefined" && Object.prototype.toString.call(value) === "[object BigInt]" && typeof value === "object");
    },
    isDataView: function(value) { return value instanceof DataView; },
    isExternal: function(value) {
      // V8 external values are not available in Hermes; always return false
      return false;
    },
    isFloat32Array: function(value) { return value instanceof Float32Array; },
    isFloat64Array: function(value) { return value instanceof Float64Array; },
    isGeneratorFunction: function(value) {
      return value && value.constructor && value.constructor.name === "GeneratorFunction";
    },
    isGeneratorObject: function(value) {
      return Object.prototype.toString.call(value) === "[object Generator]";
    },
    isInt8Array: function(value) { return value instanceof Int8Array; },
    isInt16Array: function(value) { return value instanceof Int16Array; },
    isInt32Array: function(value) { return value instanceof Int32Array; },
    isProxy: function(value) {
      // Cannot reliably detect Proxy in userland; always return false
      return false;
    },
    isSharedArrayBuffer: function(value) {
      return typeof SharedArrayBuffer !== "undefined" && value instanceof SharedArrayBuffer;
    },
    isUint8Array: function(value) { return value instanceof Uint8Array; },
    isUint8ClampedArray: function(value) { return value instanceof Uint8ClampedArray; },
    isUint16Array: function(value) { return value instanceof Uint16Array; },
    isUint32Array: function(value) { return value instanceof Uint32Array; },
    isWeakMap: function(value) { return typeof WeakMap !== "undefined" && value instanceof WeakMap; },
    isWeakSet: function(value) { return typeof WeakSet !== "undefined" && value instanceof WeakSet; }
  },
  TextEncoder: typeof TextEncoder !== "undefined" ? TextEncoder : undefined,
  TextDecoder: typeof TextDecoder !== "undefined" ? TextDecoder : undefined,
  callbackify: function(fn) {
    return function() {
      var args = Array.prototype.slice.call(arguments);
      var callback = args.pop();
      fn.apply(this, args).then(
        function(result) { callback(null, result); },
        function(err) { callback(err); }
      );
    };
  },
  isDeepStrictEqual: function(a, b) {
    // Delegate to assert's strict deep-equality comparator so this stays in
    // lock-step with assert.deepStrictEqual instead of being a separate naive
    // copy that mishandled 0/-0, NaN, Dates, RegExps, Maps/Sets, prototypes and
    // cycles. (ENG-22968)
    if (typeof _assertModule._isDeepStrictEqual === "function") {
      return _assertModule._isDeepStrictEqual(a, b);
    }
    // Fallback when `require("assert")` resolves to a comparator without the
    // internal hook (e.g. a host runtime's own assert): use deepStrictEqual as
    // an oracle — it throws only on inequality.
    try {
      _assertModule.deepStrictEqual(a, b);
      return true;
    } catch (e) {
      if (e && e.code === "ERR_ASSERTION") return false;
      throw e;
    }
  }
};

util.promisify.custom = kCustomPromisifiedSymbol;

util._extend = function _extend(target, source) {
  if (target == null) return target;
  if (!source || (typeof source !== 'object' && typeof source !== 'function')) {
    return target;
  }
  var keys = Object.keys(source);
  for (var i = 0; i < keys.length; i++) {
    target[keys[i]] = source[keys[i]];
  }
  return target;
};

util.parseArgs = function parseArgs(config) {
  config = config || {};
  var args = config.args || (typeof process !== 'undefined' ? process.argv.slice(2) : []);
  var options = config.options || {};
  var strict = config.strict !== false;
  var allowPositionals = config.allowPositionals !== false;

  var values = {};
  var positionals = [];
  var tokens = [];

  // Initialize defaults
  for (var name in options) {
    if (Object.prototype.hasOwnProperty.call(options, name)) {
      var opt = options[name];
      if (opt.default !== undefined) values[name] = opt.default;
      else if (opt.type === 'boolean') values[name] = false;
      else if (opt.multiple) values[name] = [];
    }
  }

  function findOption(arg) {
    // Check long form
    for (var name in options) {
      if (Object.prototype.hasOwnProperty.call(options, name)) {
        if ('--' + name === arg) return name;
        if (options[name].short && ('-' + options[name].short) === arg) return name;
      }
    }
    return null;
  }

  var i = 0;
  var dashdash = false;
  while (i < args.length) {
    var arg = args[i];
    if (dashdash) { positionals.push(arg); i++; continue; }
    if (arg === '--') { dashdash = true; i++; continue; }
    if (arg.indexOf('--') === 0) {
      var eqIdx = arg.indexOf('=');
      var key, val;
      if (eqIdx !== -1) { key = arg.substring(0, eqIdx); val = arg.substring(eqIdx + 1); }
      else { key = arg; val = undefined; }
      var optName = findOption(key);
      if (!optName && strict) throw new Error('Unknown option: ' + key);
      if (optName) {
        var optDef = options[optName];
        if (optDef.type === 'boolean') {
          val = val !== undefined ? val !== 'false' : true;
        } else if (val === undefined && i + 1 < args.length) {
          i++; val = args[i];
        }
        if (optDef.multiple) {
          if (!values[optName]) values[optName] = [];
          values[optName].push(val);
        } else {
          values[optName] = val;
        }
      }
    } else if (arg.indexOf('-') === 0 && arg.length > 1) {
      var optName2 = findOption(arg);
      if (optName2) {
        var optDef2 = options[optName2];
        if (optDef2.type === 'boolean') {
          if (optDef2.multiple) {
            if (!values[optName2]) values[optName2] = [];
            values[optName2].push(true);
          } else { values[optName2] = true; }
        } else if (i + 1 < args.length) {
          i++;
          if (optDef2.multiple) {
            if (!values[optName2]) values[optName2] = [];
            values[optName2].push(args[i]);
          } else { values[optName2] = args[i]; }
        }
      } else if (strict) { throw new Error('Unknown option: ' + arg); }
      else { positionals.push(arg); }
    } else {
      if (!allowPositionals && strict) throw new Error('Unexpected positional: ' + arg);
      positionals.push(arg);
    }
    i++;
  }

  return { values: values, positionals: positionals };
};

var nodeDebugEnv = (typeof process !== 'undefined' && process.env && process.env.NODE_DEBUG) ? process.env.NODE_DEBUG : '';
var debugNamespaces = {};
(function parseNodeDebugEnv() {
  if (!nodeDebugEnv || typeof nodeDebugEnv !== 'string') return;
  var parts = nodeDebugEnv.split(/[\s,]+/);
  for (var i = 0; i < parts.length; i++) {
    var ns = parts[i] && parts[i].trim();
    if (!ns) continue;
    debugNamespaces[ns.toUpperCase()] = true;
  }
})();

util.debuglog = function debuglog(set) {
  if (typeof set !== 'string' || !set) {
    return function() {};
  }
  var normalized = set.toUpperCase();
  var isEnabled = normalized === 'NODE_DEBUG' || debugNamespaces[normalized] ||
    debugNamespaces['*'] ||
    debugNamespaces[normalized.toLowerCase()] === true;

  if (!isEnabled) {
    return function() {};
  }

  var pid = (typeof process !== 'undefined' && process.pid != null) ? process.pid : 0;
  return function() {
    var args = Array.prototype.slice.call(arguments);
    if (typeof console !== 'undefined' && console.error) {
      args.unshift('[' + set + '] ' + pid + ':');
      console.error.apply(console, args);
    }
  };
};

// System error name mapping (errno -> string code)
var _errnoMap = {
  1: 'EPERM', 2: 'ENOENT', 3: 'ESRCH', 4: 'EINTR', 5: 'EIO',
  9: 'EBADF', 12: 'ENOMEM', 13: 'EACCES', 14: 'EFAULT', 17: 'EEXIST',
  20: 'ENOTDIR', 21: 'EISDIR', 22: 'EINVAL', 23: 'ENFILE', 24: 'EMFILE',
  28: 'ENOSPC', 32: 'EPIPE', 34: 'ERANGE', 35: 'EAGAIN', 36: 'EINPROGRESS',
  38: 'ENOTSOCK', 40: 'EMSGSIZE', 43: 'EPROTONOSUPPORT', 47: 'EAFNOSUPPORT',
  48: 'EADDRINUSE', 49: 'EADDRNOTAVAIL', 51: 'ENETUNREACH',
  53: 'ECONNABORTED', 54: 'ECONNRESET', 55: 'ENOBUFS', 56: 'EISCONN',
  57: 'ENOTCONN', 60: 'ETIMEDOUT', 61: 'ECONNREFUSED', 63: 'ENAMETOOLONG',
  65: 'EHOSTUNREACH', 66: 'ENOTEMPTY'
};

util.getSystemErrorName = function getSystemErrorName(err) {
  if (typeof err !== 'number') {
    var e = new TypeError('The "err" argument must be of type number. Received type ' + typeof err);
    e.code = 'ERR_INVALID_ARG_TYPE';
    throw e;
  }
  var code = _errnoMap[Math.abs(err)];
  return code || ('Unknown system error ' + err);
};

util._errnoMap = _errnoMap;

module.exports = util;
