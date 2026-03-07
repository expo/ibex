(function() {
  if (globalThis.__exactRequire) {
    return;
  }
  var g = globalThis;
  const cache = Object.create(null);
  var mainModule = null;
  function normalizeSpecifier(specifier) {
    if (typeof specifier !== 'string') {
      return String(specifier || '');
    }
    var out = specifier.replace(/\\/g, '/');
    if (out.indexOf('node:') === 0) {
      out = out.slice(5);
    }
    if (out.slice(-3) === '.js') {
      out = out.slice(0, -3);
    }
    return out;
  }
  function formatTime(ms) {
    var t = typeof ms === 'number' ? ms : Number(ms);
    if (!isFinite(t) || t < 0) {
      return String(t) + 'ms';
    }
    if (t < 1000) {
      return t.toFixed(3).replace(/\.?0+$/, '') + 'ms';
    }
    if (t < 60000) {
      return (t / 1000).toFixed(3) + 's';
    }
    var totalSeconds = Math.floor(t / 1000);
    var hours = Math.floor(totalSeconds / 3600);
    var remainingSeconds = totalSeconds % 3600;
    var minutes = Math.floor(remainingSeconds / 60);
    var seconds = remainingSeconds % 60;
    var millis = Math.round(t) % 1000;
    var secondPart = String(seconds).padStart(2, '0') + '.' + String(millis).padStart(3, '0');
    if (hours > 0) {
      return hours + ':' + String(minutes).padStart(2, '0') + ':' + secondPart + ' (h:mm:ss.mmm)';
    }
    return minutes + ':' + secondPart + ' (m:ss.mmm)';
  }
  var _internalAsyncIdCounter = 0;
  var _internalAsyncHooksSymbols = {
    async_id_symbol: Symbol.for('nodejs.async_id_symbol')
  };
  function _internalOptionNames(flag) {
    var names = [flag];
    if (typeof flag === 'string') {
      if (flag.indexOf('_') !== -1) {
        names.push(flag.replace(/_/g, '-'));
      } else {
        names.push(flag.replace(/-/g, '_'));
      }
    }
    return names;
  }
  function _internalFindExecArgvOption(flag) {
    var execArgv = (typeof process === 'object' && process !== null && Array.isArray(process.execArgv))
      ? process.execArgv
      : (Array.isArray(globalThis.__exactExecArgv) ? globalThis.__exactExecArgv : []);
    var names = _internalOptionNames(flag);
    for (var i = 0; i < execArgv.length; i++) {
      var arg = String(execArgv[i]);
      for (var j = 0; j < names.length; j++) {
        var name = names[j];
        if (arg === name) return true;
        if (arg.indexOf(name + '=') === 0) return arg.slice(name.length + 1);
      }
    }
    return undefined;
  }
  function _internalGetOptionValue(flag) {
    var found = _internalFindExecArgvOption(flag);
    if (found !== undefined) {
      if (flag === '--max-http-header-size' || flag === '--test-concurrency') {
        var numeric = Number(found);
        return isFinite(numeric) ? numeric : undefined;
      }
      if (flag === '--inspect-port') {
        var inspectPort = found === true ? 9229 : Number(found);
        return { port: isFinite(inspectPort) ? inspectPort : 9229 };
      }
      return found;
    }
    if (flag === '--pending-deprecation') {
      var env = (typeof process === 'object' && process !== null && process.env) ? process.env : {};
      return !!(env && env.NODE_PENDING_DEPRECATION && String(env.NODE_PENDING_DEPRECATION).charAt(0) === '1');
    }
    if (flag === '--max-http-header-size') return 16384;
    return undefined;
  }
  function _patchBrokenSharedArrayBufferViews() {
    if (typeof SharedArrayBuffer !== 'function' || typeof Uint8Array !== 'function') {
      return;
    }
    var probeView;
    try {
      probeView = new Uint8Array(new SharedArrayBuffer(1));
      if (
        probeView.length !== 0 &&
        probeView.byteLength !== 0 &&
        Object.prototype.toString.call(probeView.buffer) === '[object SharedArrayBuffer]'
      ) {
        return;
      }
    } catch (_probeErr) {}

    function getSharedArrayBufferBacking(buffer) {
      if (!buffer || typeof buffer !== 'object') return null;
      if (Object.prototype.toString.call(buffer) !== '[object SharedArrayBuffer]') return null;
      if (!buffer._buffer || Object.prototype.toString.call(buffer._buffer) !== '[object ArrayBuffer]') {
        return null;
      }
      return buffer._buffer;
    }

    function exposeSharedArrayBufferView(view, originalBuffer) {
      if (!view || !originalBuffer) return view;
      try {
        Object.defineProperty(view, 'buffer', {
          configurable: true,
          enumerable: false,
          get: function() {
            return originalBuffer;
          }
        });
      } catch (_bufferErr) {}
      try {
        Object.defineProperty(view, '__exactSharedArrayBuffer', {
          value: originalBuffer,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (_markerErr) {}
      return view;
    }

    function wrapCtor(name) {
      var NativeCtor = globalThis[name];
      if (typeof NativeCtor !== 'function' || NativeCtor.__exactSharedArrayBufferWrapped) {
        return;
      }

      function WrappedCtor(buffer, byteOffset, length) {
        if (!(this instanceof WrappedCtor)) {
          throw new TypeError('Constructor ' + name + ' requires "new"');
        }

        var backing = getSharedArrayBufferBacking(buffer);
        if (backing) {
          var view;
          if (arguments.length <= 1) {
            view = new NativeCtor(backing);
          } else if (arguments.length === 2) {
            view = new NativeCtor(backing, byteOffset);
          } else {
            view = new NativeCtor(backing, byteOffset, length);
          }
          return exposeSharedArrayBufferView(view, buffer);
        }

        if (arguments.length === 0) return new NativeCtor();
        if (arguments.length === 1) return new NativeCtor(buffer);
        if (arguments.length === 2) return new NativeCtor(buffer, byteOffset);
        return new NativeCtor(buffer, byteOffset, length);
      }

      var propNames = Object.getOwnPropertyNames(NativeCtor);
      for (var i = 0; i < propNames.length; i++) {
        var propName = propNames[i];
        if (propName === 'prototype' || propName === 'length' || propName === 'name') {
          continue;
        }
        try {
          Object.defineProperty(WrappedCtor, propName, Object.getOwnPropertyDescriptor(NativeCtor, propName));
        } catch (_copyErr) {}
      }
      WrappedCtor.prototype = NativeCtor.prototype;
      try {
        Object.defineProperty(WrappedCtor.prototype, 'constructor', {
          value: WrappedCtor,
          writable: true,
          configurable: true,
          enumerable: false
        });
      } catch (_ctorErr) {}
      try {
        Object.defineProperty(WrappedCtor, '__exactSharedArrayBufferWrapped', {
          value: true,
          writable: false,
          configurable: true,
          enumerable: false
        });
      } catch (_wrappedErr) {}
      globalThis[name] = WrappedCtor;
    }

    var ctorNames = [
      'Int8Array',
      'Uint8Array',
      'Uint8ClampedArray',
      'Int16Array',
      'Uint16Array',
      'Int32Array',
      'Uint32Array',
      'Float32Array',
      'Float64Array'
    ];
    if (typeof globalThis.Float16Array === 'function') ctorNames.push('Float16Array');
    if (typeof globalThis.BigInt64Array === 'function') ctorNames.push('BigInt64Array');
    if (typeof globalThis.BigUint64Array === 'function') ctorNames.push('BigUint64Array');
    for (var i = 0; i < ctorNames.length; i++) {
      wrapCtor(ctorNames[i]);
    }
    wrapCtor('DataView');
  }
  _patchBrokenSharedArrayBufferViews();
  function _createNodeTestModule() {
    var context = {
      tests: [],
      afters: []
    };
    function _createMock() {
      return {
        method: function(target, propertyName) {
          if (typeof propertyName !== 'string') {
            throw new TypeError('The "propertyName" argument must be a string');
          }
          if (!target || (typeof target !== 'object' && typeof target !== 'function')) {
            throw new TypeError('Cannot mock property on non-object target');
          }
          if (typeof target[propertyName] !== 'function') {
            throw new TypeError('Cannot mock a non-function property');
          }

          var calls = [];
          var original = target[propertyName];
          var restored = false;

          var mocked = function() {
            var call = {
              thisArg: this,
              arguments: Array.prototype.slice.call(arguments),
              result: undefined,
              error: undefined
            };
            calls.push(call);
            try {
              call.result = original.apply(this, arguments);
              return call.result;
            } catch (e) {
              call.error = e;
              throw e;
            }
          };
          mocked.mock = { calls: calls };
          mocked.restore = function() {
            if (!restored) {
              target[propertyName] = original;
              restored = true;
            }
          };

          target[propertyName] = mocked;
          return mocked;
        }
      };
    }
    function _createTestContext() {
      return {
        mock: _createMock()
      };
    }
    function _runAfterQueue(afters) {
      var promise = Promise.resolve();
      for (var i = 0; i < afters.length; i++) {
        (function(hook) {
          promise = promise.then(function() {
            return hook();
          });
        })(afters[i]);
      }
      return promise;
    }
    function describe() {
      var fn = arguments[1];
      if (typeof fn !== 'function') {
        return Promise.resolve();
      }
      var localContext = { tests: [], afters: [] };
      var previousContext = context;
      context = localContext;
      var result;
      try {
        result = fn();
      } catch (err) {
        context = previousContext;
        throw err;
      }
      context = previousContext;
      var done = Promise.resolve(result)
        .then(function() {
          return Promise.all(localContext.tests);
        })
        .then(function() {
          return _runAfterQueue(localContext.afters);
        });
      done.catch(function(err) { setTimeout(function() { throw err; }, 0); });
      return done;
    }
    function it() {
      var fn = arguments[1];
      if (typeof fn !== 'function') {
        return Promise.resolve();
      }
      var promise;
      var testContext = _createTestContext();
      if (fn.length >= 2) {
        promise = new Promise(function(resolve, reject) {
          var doneCalled = false;
          var done = function(error) {
            if (doneCalled) return;
            doneCalled = true;
            if (error) {
              reject(error);
            } else {
              resolve();
            }
          };
          try {
            fn(testContext, done);
          } catch (err) {
            if (!doneCalled) {
              reject(err);
            }
          }
        });
      } else {
        try {
          promise = Promise.resolve(fn(testContext));
        } catch (err) {
          promise = Promise.reject(err);
        }
      }
      if (context) {
        context.tests.push(promise);
      }
      return promise;
    }
    function test() {
      return it.apply(this, arguments);
    }
    function suite(name, fn) {
      return describe(name, fn);
    }
    function before() {}
    function beforeEach() {}
    function afterEach() {}
    function after(fn) {
      if (typeof fn !== 'function') return Promise.resolve();
      if (context) {
        context.afters.push(fn);
        return;
      }
      return Promise.resolve(fn());
    }
    // mock support for node:test
    var _mockRestoreList = [];
    var mock = {
      method: function(obj, methodName, impl) {
        var original = obj[methodName];
        var calls = [];
        var wrapper = function() {
          var result;
          var error;
          try {
            result = impl.apply(this, arguments);
          } catch (e) {
            error = e;
            throw e;
          } finally {
            calls.push({ arguments: Array.prototype.slice.call(arguments), result: result, error: error, this: this });
          }
          return result;
        };
        wrapper.mock = { calls: calls, callCount: function() { return calls.length; }, restore: function() { obj[methodName] = original; } };
        obj[methodName] = wrapper;
        _mockRestoreList.push(function() { obj[methodName] = original; });
        return wrapper;
      },
      fn: function(impl) {
        impl = impl || function() {};
        var calls = [];
        var wrapper = function() {
          var result = impl.apply(this, arguments);
          calls.push({ arguments: Array.prototype.slice.call(arguments), result: result });
          return result;
        };
        wrapper.mock = { calls: calls, callCount: function() { return calls.length; } };
        return wrapper;
      },
      restoreAll: function() {
        for (var i = 0; i < _mockRestoreList.length; i++) _mockRestoreList[i]();
        _mockRestoreList = [];
      }
    };
    return {
      describe: describe,
      it: it,
      test: test,
      suite: suite,
      before: before,
      beforeEach: beforeEach,
      afterEach: afterEach,
      after: after,
      mock: mock
    };
  }
  // internal/linkedlist: circular doubly-linked list
  var _L = {
    init: function(item) { item._idleNext = item; item._idlePrev = item; },
    peek: function(item) { return item._idleNext === item ? null : item._idleNext; },
    remove: function(item) {
      if (item._idleNext) { item._idleNext._idlePrev = item._idlePrev; }
      if (item._idlePrev) { item._idlePrev._idleNext = item._idleNext; }
      item._idleNext = item; item._idlePrev = item;
    },
    append: function(list, item) {
      if (item._idleNext !== item) { _L.remove(item); }
      item._idleNext = list;
      item._idlePrev = list._idlePrev;
      list._idlePrev._idleNext = item;
      list._idlePrev = item;
    },
    isEmpty: function(item) { return item._idleNext === item; }
  };
  function _internalFsUtilsInvalidArgValue(name, value, reason) {
    var err = new TypeError('The "' + name + '" argument must be ' + reason + '. Received ' + value);
    err.code = 'ERR_INVALID_ARG_VALUE';
    return err;
  }
  function _internalFsUtilsRangeError(name, value, min, max) {
    var message = 'The value of "' + name + '" is out of range. It must be >= ' + min + ' && <= ' + max + '. Received ' + value;
    var err = new RangeError(message);
    err.code = 'ERR_OUT_OF_RANGE';
    return err;
  }
  function _internalFsUtilsStringToInt(value) {
    return parseInt(value, 10);
  }
  function _internalFsUtilsValidateOffsetLength(offset, length, byteLength, mode, maxLength) {
    if (!Number.isInteger(offset) || offset < 0) {
      var offsetErr = new RangeError('The value of "offset" is out of range. It must be >= 0. Received ' + offset);
      offsetErr.code = 'ERR_OUT_OF_RANGE';
      throw offsetErr;
    }
    if (!Number.isInteger(length) || length < 0) {
      var lengthErr = new RangeError('The value of "length" is out of range. It must be >= 0. Received ' + length);
      lengthErr.code = 'ERR_OUT_OF_RANGE';
      throw lengthErr;
    }
    if (mode === 'write') {
      if (offset > byteLength) {
        var writeOffsetErr = new RangeError('The value of "offset" is out of range. It must be <= ' + byteLength + '. Received ' + offset);
        writeOffsetErr.code = 'ERR_OUT_OF_RANGE';
        throw writeOffsetErr;
      }
    }
    if (length > maxLength) {
      var maxLenErr = new RangeError('The value of "length" is out of range. It must be <= ' + maxLength + '. Received ' + length);
      maxLenErr.code = 'ERR_OUT_OF_RANGE';
      throw maxLenErr;
    }
    var max = byteLength - offset;
    if (length > max) {
      var lenErr = new RangeError('The value of "length" is out of range. It must be <= ' + max + '. Received ' + length);
      lenErr.code = 'ERR_OUT_OF_RANGE';
      throw lenErr;
    }
  }
  var internalModules = {
    'internal/util/debuglog': {
      formatTime: formatTime,
      debuglog: function() { return function() {}; }
    },
    'internal/linkedlist': _L,
    'internal/util': {
      sleep: function(ms) {
        var end = Date.now() + ms;
        while (Date.now() < end) { /* busy-wait */ }
      }
    },
    'internal/options': {
      getOptionValue: _internalGetOptionValue,
      generateConfigJsonSchema: function() { return {}; }
    },
    'internal/http': {
      kOutHeaders: Symbol.for('nodejs.http.outHeadersKey')
    },
    'internal/async_hooks': {
      newAsyncId: function() {
        _internalAsyncIdCounter += 1;
        return _internalAsyncIdCounter;
      },
      symbols: _internalAsyncHooksSymbols
    },
    'internal/timers': {
      kTimeout: Symbol.for('kTimeout'),
      enroll: function() {},
      unenroll: function() {},
      active: function() {},
      setUnrefTimeout: function(callback, after) {
        if (typeof callback !== 'function') {
          var err = new TypeError('The "callback" argument must be of type function. Received ' + typeof callback);
          err.code = 'ERR_INVALID_ARG_TYPE';
          throw err;
        }
        var timer = setTimeout(callback, after);
        timer.unref();
        return timer;
      }
    },
    'internal/assert/myers_diff': {
      myersDiff: function(arr1, arr2) {
        var max = arr1.length + arr2.length;
        if (max >= 0x80000000) {
          var err = new RangeError(
            'The value of "myersDiff input size" is out of range. It must be < 2^31. Received ' + max
          );
          err.code = 'ERR_OUT_OF_RANGE';
          throw err;
        }
        return [];
      }
    },
    'internal/url': {
      isURL: function(value) {
        return typeof globalThis.URL === 'function' && value instanceof globalThis.URL;
      }
    },
    'internal/crypto/util': {
      getOpenSSLSecLevel: function() { return 0; }
    },
    'internal/crypto/x509': {
      isX509Certificate: function(value) {
        return !!(value && value.constructor && value.constructor.name === 'X509Certificate');
      }
    },
    'internal/url': {
      isURL: function(value) {
        if (!value || (typeof value !== 'object' && typeof value !== 'function')) {
          return false;
        }
        return !!(
          value.constructor &&
          value.constructor.name === 'URL' &&
          typeof value.href === 'string'
        );
      }
    },
    'internal/fs/utils': {
      validateOffsetLengthRead: function(offset, length, byteLength, lengthIsBigInt) {
        if (lengthIsBigInt !== undefined && lengthIsBigInt) {
          if (typeof offset === 'bigint' || typeof length === 'bigint') {
            offset = _internalFsUtilsStringToInt(offset);
            length = _internalFsUtilsStringToInt(length);
          }
        }
        _internalFsUtilsValidateOffsetLength(offset, length, byteLength, 'read', (2 ** 31) - 1);
      },
      validateOffsetLengthWrite: function(offset, length, byteLength, lengthIsBigInt) {
        if (lengthIsBigInt !== undefined && lengthIsBigInt) {
          if (typeof offset === 'bigint' || typeof length === 'bigint') {
            offset = _internalFsUtilsStringToInt(offset);
            length = _internalFsUtilsStringToInt(length);
          }
        }
        _internalFsUtilsValidateOffsetLength(offset, length, byteLength, 'write', (2 ** 31) - 1);
      },
      stringToFlags: function(flag) {
        var constants = require('fs').constants || {};
        if (typeof flag !== 'string' || flag === '') {
          var err = new TypeError('The flags argument must be a valid flags string. Received ' + flag);
          err.code = 'ERR_INVALID_ARG_VALUE';
          throw err;
        }
        var hasPlus = flag.indexOf('+') !== -1;
        if (flag.indexOf('+') !== flag.lastIndexOf('+')) {
          throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
        }
        if (hasPlus && flag.indexOf('+') !== flag.length - 1) {
          throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
        }
        var flagChars = hasPlus ? flag.slice(0, -1) : flag;
        var hasSync = false;
        var hasExclusive = false;
        var modeFlags = '';
        for (var i = 0; i < flagChars.length; i++) {
          var ch = flagChars.charAt(i);
          if (ch === 's') {
            if (hasSync) throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
            hasSync = true;
          } else if (ch === 'x') {
            if (hasExclusive) throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
            hasExclusive = true;
          } else if (ch === 'r' || ch === 'w' || ch === 'a') {
            if (modeFlags.length >= 1) throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
            modeFlags = ch;
          } else {
            throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
          }
        }
        if (modeFlags.length !== 1) {
          throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
        }
        if (hasExclusive && modeFlags === 'r') {
          throw _internalFsUtilsInvalidArgValue('flags', flag, 'a valid flag string');
        }
        var oSync = constants.O_SYNC || 0;
        var result = 0;
        if (modeFlags === 'r') {
          result = hasPlus ? constants.O_RDWR || 2 : constants.O_RDONLY || 0;
        } else if (modeFlags === 'w') {
          result = (constants.O_WRONLY || 1) | (constants.O_CREAT || 64) | (constants.O_TRUNC || 512);
        } else {
          result = (constants.O_APPEND || 1024) | (constants.O_CREAT || 64) | (constants.O_WRONLY || 1);
        }
        if (hasPlus) {
          result = (result & ~(constants.O_WRONLY || 1)) | (constants.O_RDWR || 2);
        }
        if (hasExclusive) {
          result |= constants.O_EXCL || 128;
        }
        if (hasSync) {
          result |= oSync;
        }
        return result;
      },
      BigIntStats: function(
        dev,
        mode,
        nlink,
        uid,
        gid,
        rdev,
        blksize,
        ino,
        size,
        blocks,
        atimeMs,
        mtimeMs,
        ctimeMs,
        birthtimeMs,
        atimeNs,
        mtimeNs,
        ctimeNs,
        birthtimeNs
      ) {
        function coerceBigInt(value) {
          if (typeof value === 'bigint') return value;
          return BigInt(typeof value === 'number' ? value : 0);
        }
        function coerceNumber(value) {
          if (typeof value === 'bigint') return Number(value);
          return typeof value === 'number' ? value : 0;
        }
        var modeBigint = coerceBigInt(mode);
        var modeType = modeBigint & 0xF000n;
        this.dev = coerceBigInt(dev);
        this.ino = coerceBigInt(ino);
        this.mode = coerceBigInt(mode);
        this.nlink = coerceBigInt(nlink);
        this.uid = coerceBigInt(uid);
        this.gid = coerceBigInt(gid);
        this.rdev = coerceBigInt(rdev);
        this.size = coerceBigInt(size);
        this.blksize = coerceBigInt(blksize);
        this.blocks = coerceBigInt(blocks);
        this.atimeMs = coerceBigInt(atimeMs);
        this.mtimeMs = coerceBigInt(mtimeMs);
        this.ctimeMs = coerceBigInt(ctimeMs);
        this.birthtimeMs = coerceBigInt(birthtimeMs);
        this.atimeNs = coerceBigInt(atimeNs);
        this.mtimeNs = coerceBigInt(mtimeNs);
        this.ctimeNs = coerceBigInt(ctimeNs);
        this.birthtimeNs = coerceBigInt(birthtimeNs);
        this.atime = new Date(coerceNumber(this.atimeMs));
        this.mtime = new Date(coerceNumber(this.mtimeMs));
        this.ctime = new Date(coerceNumber(this.ctimeMs));
        this.birthtime = new Date(coerceNumber(this.birthtimeMs));
        this._isFile = modeType === 0x8000n;
        this._isDir = modeType === 0x4000n;
        this._isSymlink = modeType === 0xA000n;
        this._isBlkDev = modeType === 0x6000n;
        this._isChrDev = modeType === 0x2000n;
        this._isFifo = modeType === 0x1000n;
        this._isSock = modeType === 0xC000n;
      },
      getDirents: function(path, entries, callback) {
        if (callback === undefined || callback === null) {
          callback = null;
        }
        if (callback !== null && typeof callback !== 'function') {
          var callbackErr = new TypeError(
            'The "callback" argument must be of type function. Received ' + typeof callback
          );
          callbackErr.code = 'ERR_INVALID_ARG_TYPE';
          throw callbackErr;
        }
        var pair = entries || [];
        var names = Array.isArray(pair[0]) ? pair[0] : [];
        var types = Array.isArray(pair[1]) ? pair[1] : [];
        if (typeof path !== 'string' && !Buffer.isBuffer(path)) {
          var err = new TypeError('The "path" argument must be of type string or an ' +
            'instance of Buffer. Received type ' + (path === null ? 'null' : typeof path) +
            ' (' + path + ')');
          if (callback) return callback(err);
          throw err;
        }
        var fs = require('fs');
        var direntTypeUnknown = 0;
        var direntTypeFile = 1;
        var direntTypeDir = 2;
        var direntTypeLink = 3;
        var direntTypeFifo = 4;
        var direntTypeSocket = 5;
        var direntTypeChar = 6;
        var direntTypeBlock = 7;
        function statFromType(parentPath, entryName, type) {
          if (type === direntTypeFile) {
            return {
              isFile: function() { return true; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return false; },
              isSocket: function() { return false; },
            };
          }
          if (type === direntTypeDir) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return true; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return false; },
              isSocket: function() { return false; },
            };
          }
          if (type === direntTypeLink) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return true; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return false; },
              isSocket: function() { return false; },
            };
          }
          if (type === direntTypeFifo) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return true; },
              isSocket: function() { return false; },
            };
          }
          if (type === direntTypeSocket) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return false; },
              isSocket: function() { return true; },
            };
          }
          if (type === direntTypeChar) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return false; },
              isCharacterDevice: function() { return true; },
              isFIFO: function() { return false; },
              isSocket: function() { return false; },
            };
          }
          if (type === direntTypeBlock) {
            return {
              isFile: function() { return false; },
              isDirectory: function() { return false; },
              isSymbolicLink: function() { return false; },
              isBlockDevice: function() { return true; },
              isCharacterDevice: function() { return false; },
              isFIFO: function() { return false; },
              isSocket: function() { return false; },
            };
          }
          var fullPath = String(path);
          if (typeof entryName === 'string') {
            fullPath += '/' + entryName;
          } else {
            fullPath += '/' + String(entryName);
          }
          try {
            return fs.lstatSync(fullPath);
          } catch (_ignored) {
            return null;
          }
        }
        var out = [];
        for (var i = 0; i < names.length; i++) {
          out.push(new (require('fs').Dirent)(
            names[i],
            path,
            statFromType(path, names[i], types[i])
          ));
        }
        if (callback) {
          return callback(null, out);
        }
        return out;
      },
      getDirent: function(path, name, type, callback) {
        if (callback !== undefined && typeof callback !== 'function') {
          var callbackErr = new TypeError(
            'The "callback" argument must be of type function. Received ' + typeof callback
          );
          callbackErr.code = 'ERR_INVALID_ARG_TYPE';
          throw callbackErr;
        }
        if (typeof path !== 'string' && !Buffer.isBuffer(path)) {
          var err = new TypeError('The "path" argument must be of type string or an ' +
            'instance of Buffer. Received type ' + (path === null ? 'null' : typeof path) +
            ' (' + path + ')');
          if (callback) return callback(err);
          throw err;
        }
        if (typeof name !== 'string' && !Buffer.isBuffer(name)) {
          var nameErr = new TypeError('The "name" argument must be of type string or an ' +
            'instance of Buffer. Received type ' + (name === null ? 'null' : typeof name) +
            ' (' + name + ')');
          if (callback) return callback(nameErr);
          throw nameErr;
        }
        var fs = require('fs');
        var constants = internalModules['internal/test/binding'].internalBinding.call(
          internalModules['internal/test/binding'],
          'constants'
        ).fs;
        var unknown = constants && constants.UV_DIRENT_UNKNOWN;
        var stat = null;
        if (type === unknown) {
          try {
            stat = fs.lstatSync(String(path) + '/' + name);
          } catch (_ignored) {}
        } else {
          stat = {
            isFile: function() { return type === constants.UV_DIRENT_FILE; },
            isDirectory: function() { return type === constants.UV_DIRENT_DIR; },
            isSymbolicLink: function() { return type === constants.UV_DIRENT_LINK; },
            isBlockDevice: function() { return type === constants.UV_DIRENT_BLOCK; },
            isCharacterDevice: function() { return type === constants.UV_DIRENT_CHAR; },
            isFIFO: function() { return type === constants.UV_DIRENT_FIFO; },
            isSocket: function() { return type === constants.UV_DIRENT_SOCKET; },
          };
        }
        var result = new (require('fs').Dirent)(name, path, stat);
        if (callback) return callback(null, result);
        return result;
      }
    },
    'internal/test/binding': {
      internalBinding: function(name) {
      if (name === 'crypto') {
        return {
          testFipsCrypto: function() {
            return 0;
          }
        };
      }
      if (name === 'fs') {
        return {
          FSReqCallback: function() {},
          fstat: function() {
            return [0, 0, 0, 0, 0, 0, 0, 0, 0];
          },
          readdir: function(path, encoding, types, req, ctx) {
            var entries = [];
            var entryTypes = [];
            var name = typeof _pathToString === 'function' ? _pathToString(path) : String(path);
            var dirs = require('fs').readdirSync(name);
            for (var i = 0; i < dirs.length; i++) {
              entries.push(dirs[i]);
              entryTypes.push(types ? 1 : 0);
            }
            if (req && typeof req.oncomplete === 'function') {
              req.oncomplete(null, [entries, entryTypes]);
              return;
            }
            return [entries, entryTypes];
          },
          writeFileUtf8: function(path, data) {
            var buffer = (typeof data === 'string') ? Buffer.from(data, 'utf8') : Buffer.from(data);
            return require('fs').writeFileSync(String(path), buffer);
          },
          openFileHandle: function(path, flags, mode, cb, ctx) {
            var handle = {
              fd: -1,
              close: function() {
                var closePath = this.path;
                if (typeof this.fd === 'number' && this.fd >= 0) {
                  require('fs').closeSync(this.fd);
                  this.fd = -1;
                }
              }
            };
            try {
              handle.fd = require('fs').openSync(String(path), flags, mode);
              if (ctx && typeof ctx === 'object') {
                ctx.errno = undefined;
              }
              handle.path = String(path);
            } catch (err) {
              if (ctx && typeof ctx === 'object') {
                ctx.errno = err && err.errno;
              }
              throw err;
            }
            return handle;
          },
        };
      }
      if (name === 'uv') {
        return {
          UV_EACCES: -13,
            UV_EBADF: -9,
            UV_EBUSY: -16,
            UV_EEXIST: -17,
            UV_EIO: -5,
            UV_EISDIR: -21,
            UV_ELOOP: -40,
            UV_EMFILE: -24,
            UV_ENAMETOOLONG: -63,
            UV_ENOENT: -2,
            UV_ENOMEM: -12,
            UV_ENOSPC: -28,
            UV_ENOSYS: -78,
            UV_ENOTDIR: -20,
            UV_ENOTEMPTY: -66,
            UV_EPERM: -1,
            UV_ERANGE: -34,
            UV_EROFS: -30,
            UV_ESPIPE: -29,
            UV_EXDEV: -18,
            UV_ETXTBSY: -26,
            UV_UNKNOWN: -4094,
          };
        }
        if (name === 'constants') {
          return {
            fs: {
              UV_FS_SYMLINK_DIR: 1,
              UV_FS_SYMLINK_JUNCTION: 2,
              UV_DIRENT_UNKNOWN: 0,
              UV_DIRENT_FILE: 1,
              UV_DIRENT_DIR: 2,
              UV_DIRENT_LINK: 3,
              UV_DIRENT_FIFO: 4,
              UV_DIRENT_SOCKET: 5,
              UV_DIRENT_CHAR: 6,
              UV_DIRENT_BLOCK: 7,
              UV_FS_O_FILEMAP: 0,
              UV_FS_COPYFILE_EXCL: 1,
              UV_FS_COPYFILE_FICLONE: 2,
              UV_FS_COPYFILE_FICLONE_FORCE: 4,
            },
          };
        }
        if (name === 'timers') {
          return {
            getLibuvNow: function() { return typeof performance !== 'undefined' && typeof performance.now === 'function' ? (Math.floor(performance.now()) | 0) : 0; },
            scheduleTimer: function() {},
            toggleTimerRef: function() {},
            toggleImmediateRef: function() {}
          };
        }
        if (name === 'test' && this && this.test) {
          return this.test;
        }
        return {};
      }
    },
    'internal/child_process': (function() {
      var kChannelHandle = Symbol.for('kChannelHandle');
      function getValidStdio(stdio, sync) {
        if (typeof stdio === 'string') {
          if (stdio !== 'ignore' && stdio !== 'pipe' && stdio !== 'inherit' && stdio !== 'overlapped') {
            var err1 = new TypeError('The value "' + stdio + '" is invalid for option "stdio"');
            err1.code = 'ERR_INVALID_ARG_VALUE';
            throw err1;
          }
          stdio = [stdio, stdio, stdio];
        } else if (!Array.isArray(stdio)) {
          var err2 = new TypeError('The value "' + String(stdio) + '" is invalid for option "stdio"');
          err2.code = 'ERR_INVALID_ARG_VALUE';
          throw err2;
        }
        while (stdio.length < 3) stdio.push(undefined);
        var result = { stdio: [], ipc: undefined, ipcFd: undefined };
        for (var i = 0; i < stdio.length; i++) {
          var s = stdio[i];
          if (s === 'ignore' || s === undefined || s === null) {
            result.stdio.push({ type: 'ignore' });
          } else if (s === 'pipe' || s === 'overlapped') {
            result.stdio.push({ type: 'pipe' });
          } else if (s === 'inherit') {
            result.stdio.push({ type: 'fd', fd: i });
          } else if (s === 'ipc') {
            if (sync) {
              var err3 = new Error('IPC is not supported with synchronous forks');
              err3.code = 'ERR_IPC_SYNC_FORK';
              throw err3;
            }
            if (result.ipc !== undefined) {
              var err4 = new Error('Only one IPC pipe is allowed');
              err4.code = 'ERR_IPC_ONE_PIPE';
              throw err4;
            }
            result.ipc = { type: 'ipc' };
            result.ipcFd = i;
            result.stdio.push({ type: 'ipc' });
          } else if (typeof s === 'number') {
            result.stdio.push({ type: 'fd', fd: s });
          } else if (s && typeof s === 'object') {
            if (typeof s.fd === 'number') {
              result.stdio.push({ type: 'fd', fd: s.fd });
            } else if (s._handle || s.handle || s._writableState || s._readableState) {
              result.stdio.push({ type: 'fd', fd: i });
            } else {
              var err5 = new TypeError('The value "' + String(s) + '" is invalid for option "stdio"');
              err5.code = 'ERR_INVALID_ARG_VALUE';
              throw err5;
            }
          } else {
            var err6 = new TypeError('The value "' + String(s) + '" is invalid for option "stdio"');
            err6.code = 'ERR_INVALID_SYNC_FORK_INPUT';
            throw err6;
          }
        }
        return result;
      }
      return {
        getValidStdio: getValidStdio,
        kChannelHandle: kChannelHandle,
        ChildProcess: null  // Will be set after child_process is loaded
      };
    })(),
    'bun:internal-for-testing': {
      fsStreamInternals: {},
      memfd_create: function() { return -1; },
      setSyntheticAllocationLimitForTesting: function() {},
      setSocketOptions: function() {},
      canonicalizeIP: function(ip) { return ip; },
      nativeFrameForTesting: function() {},
      getEventLoopStats: function() {
        return { min: 0, max: 0, avg: 0, count: 0 };
      },
      timerInternals: {
        timerClockMs: function() { return Date.now(); },
      },
      structuredCloneAdvanced: function(value) {
        return JSON.parse(JSON.stringify(value));
      },
    }
  };
  var streamBuiltinsCache = null;
  var streamInternalModuleCache = null;

  function _resolveAbortError(name) {
    var err = new Error(name + ' is missing');
    err.code = 'ERR_STREAM_PREMATURE_CLOSE';
    return err;
  }

  function _addAbortSignalCompat(signal, stream) {
    if (!stream || typeof stream.destroy !== 'function') {
      return stream;
    }
    if (signal && typeof signal.addEventListener === 'function') {
      signal.addEventListener('abort', function() {
        var abortErr = new Error('The operation was aborted');
        abortErr.code = 'ABORT_ERR';
        abortErr.name = 'AbortError';
        stream.destroy(abortErr);
      });
    }
    return stream;
  }

  function _getStreamBuiltins() {
    if (!streamBuiltinsCache) {
      try {
        streamBuiltinsCache = load('stream');
      } catch (err) {
        streamBuiltinsCache = {};
      }
    }
    return streamBuiltinsCache;
  }

  function _loadNamedStreamInternal(name) {
    if (!streamInternalModuleCache) {
      streamInternalModuleCache = Object.create(null);
    }
    if (Object.prototype.hasOwnProperty.call(streamInternalModuleCache, name)) {
      return streamInternalModuleCache[name];
    }
    var stream = _getStreamBuiltins();
    var result = null;

    if (name === 'internal/streams/add-abort-signal') {
      var streamAddAbortSignal = stream.addAbortSignal || _addAbortSignalCompat;
      result = {
        addAbortSignal: streamAddAbortSignal,
        addAbortSignalNoValidate: function(_signal, streamInstance) {
          return _addAbortSignalCompat(_signal, streamInstance);
        }
      };
    } else if (name === 'internal/streams/compose') {
      result = stream.compose || function() {
        throw _resolveAbortError('compose');
      };
    } else if (name === 'internal/streams/state') {
      result = {
        getDefaultHighWaterMark: stream.getDefaultHighWaterMark || function(_objectMode) { return _objectMode ? 16 : 16384; },
        setDefaultHighWaterMark: stream.setDefaultHighWaterMark || function() {}
      };
    } else if (name === 'internal/streams/destroy') {
      result = {
        destroy: function(streamInstance, err) {
          if (streamInstance && typeof streamInstance.destroy === 'function') {
            streamInstance.destroy(err);
          }
          return streamInstance;
        },
        undestroy: function(streamInstance) {
          if (streamInstance && typeof streamInstance._undestroy === 'function') {
            streamInstance._undestroy();
          }
        },
        errorOrDestroy: function(streamInstance, err) {
          if (err && streamInstance && typeof streamInstance.destroy === 'function') {
            streamInstance.destroy(err);
          }
          return streamInstance;
        },
        destroyer: function(streamInstance, err) {
          if (streamInstance && typeof streamInstance.destroy === 'function') {
            streamInstance.destroy(err);
          }
          return streamInstance;
        }
      };
    } else if (name === 'internal/streams/duplex') {
      result = stream.Duplex;
    } else if (name === 'internal/streams/end-of-stream') {
      result = stream.finished || function() {};
    } else if (name === 'internal/streams/from') {
      var streamFrom = stream.Readable && stream.Readable.from ? stream.Readable.from : function() {};
      streamFrom.from = streamFrom;
      streamFrom.default = streamFrom;
      result = streamFrom;
    } else if (name === 'internal/streams/legacy') {
      result = stream;
    } else if (name === 'internal/streams/operators') {
      if (stream && stream.Readable && stream.Readable.prototype) {
        result = {
          map: function(source, fn, options) { return stream.Readable.prototype.map.call(source, fn, options); },
          filter: function(source, fn, options) { return stream.Readable.prototype.filter.call(source, fn, options); },
          reduce: function(source, fn, initial, options) { return stream.Readable.prototype.reduce.call(source, fn, initial, options); },
          toArray: function(source, options) { return stream.Readable.prototype.toArray.call(source, options); },
          forEach: function(source, fn, options) { return stream.Readable.prototype.forEach.call(source, fn, options); },
          some: function(source, fn, options) { return stream.Readable.prototype.some.call(source, fn, options); },
          every: function(source, fn, options) { return stream.Readable.prototype.every.call(source, fn, options); },
          find: function(source, fn, options) { return stream.Readable.prototype.find.call(source, fn, options); },
          flatMap: function(source, fn, options) { return stream.Readable.prototype.flatMap.call(source, fn, options); },
          drop: function(source, count, options) { return stream.Readable.prototype.drop.call(source, count, options); },
          take: function(source, count, options) { return stream.Readable.prototype.take.call(source, count, options); }
        };
      } else {
        result = {};
      }
    } else if (name === 'internal/streams/passthrough') {
      result = stream.PassThrough;
    } else if (name === 'internal/streams/pipeline') {
      var streamPipeline = stream.pipeline;
      var streamPromises = stream.promises && stream.promises.pipeline;
      result = function() {
        var args = [];
        for (var pi = 0; pi < arguments.length; pi++) args.push(arguments[pi]);
        var hasCallback = args.length > 0 && typeof args[args.length - 1] === 'function';

        if (typeof streamPipeline !== 'function') {
          throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "pipeline" method is not available');
        }
        if (hasCallback) {
          return streamPipeline.apply(stream, args);
        }

        if (typeof streamPromises === 'function') {
          return streamPromises.apply(stream.promises, args);
        }

        return new Promise(function(resolve, reject) {
          args.push(function(err) {
            if (err) {
              reject(err);
            } else {
              resolve();
            }
          });
          try {
            streamPipeline.apply(stream, args);
          } catch (err) {
            reject(err);
          }
        });
      };
    } else if (name === 'internal/streams/readable') {
      result = stream.Readable;
    } else if (name === 'internal/streams/transform') {
      result = stream.Transform;
    } else if (name === 'internal/streams/utils') {
      result = {
        isDisturbed: stream.isDisturbed || function() { return false; },
        isReadable: stream.isReadable || function() { return false; },
        isWritable: stream.isWritable || function() { return false; },
        isErrored: stream.isErrored || function() { return false; }
      };
    } else if (name === 'internal/streams/writable') {
      result = stream.Writable;
    } else if (name === 'stream/promises') {
      result = stream.promises || {};
    } else if (name === 'stream/consumers') {
      result = stream.consumers || {};
    } else if (name === '_stream_readable') {
      result = stream.Readable;
    } else if (name === '_stream_writable') {
      result = stream.Writable;
    } else if (name === '_stream_duplex') {
      result = stream.Duplex;
    } else if (name === '_stream_transform') {
      result = stream.Transform;
    } else if (name === '_stream_passthrough') {
      result = stream.PassThrough;
    }

    streamInternalModuleCache[name] = result;
    return result;
  }

  function createEventTargetModule() {
    return {
      get kEvents() { return Symbol.for('nodejs.internal.event_target.kEvents'); },
      get kWeakHandler() { return Symbol.for('nodejs.internal.event_target.kWeakHandler'); },
      get Event() { return globalThis.Event; },
      get EventTarget() { return globalThis.EventTarget; },
      get CustomEvent() { return globalThis.CustomEvent; },
      get NodeEventTarget() {
        if (globalThis.EventTarget) {
          return globalThis.EventTarget;
        }
        return undefined;
      }
    };
  }
  function loadInternal(specifier) {
    var normalized = normalizeSpecifier(specifier);
    if (normalized === 'dns/promises') {
      if (!cache[normalized]) {
        var dnsModule = load('dns', '');
        cache[normalized] = {
          exports: dnsModule && dnsModule.promises ? dnsModule.promises : {},
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized === 'readline/promises') {
      if (!cache[normalized]) {
        var readlineModule = load('readline', '');
        cache[normalized] = {
          exports: readlineModule && readlineModule.promises ? readlineModule.promises : {},
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized === 'assert/strict') {
      var assertModule = load('assert', '');
      if (!cache[normalized]) {
        cache[normalized] = {
          exports: assertModule && assertModule.strict ? assertModule.strict : assert,
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      if (cache[normalized].exports === undefined && assertModule && assertModule.strict) {
        cache[normalized].exports = assertModule.strict;
      }
      return cache[normalized].exports;
    }
    if (normalized === 'test') {
      if (!cache[normalized]) {
        cache[normalized] = {
          exports: _createNodeTestModule(),
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized === 'internal/event_target') {
      if (!cache[normalized]) {
        cache[normalized] = {
          exports: createEventTargetModule(),
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    if (normalized.indexOf('internal/util/debuglog') !== -1) {
      normalized = 'internal/util/debuglog';
    }
    var legacyStreamModule = _loadNamedStreamInternal(normalized);
    if (legacyStreamModule !== null && legacyStreamModule !== undefined) {
      if (!cache[normalized]) {
        cache[normalized] = {
          exports: legacyStreamModule,
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
      }
      return cache[normalized].exports;
    }
    var internal = internalModules.hasOwnProperty(normalized) ? internalModules[normalized] : undefined;
    if (!internal) return null;
    if (!cache[normalized]) {
      cache[normalized] = {
        exports: internal,
        loaded: true,
        id: normalized,
        filename: normalized,
        path: '',
        __exactId: idToModuleId(normalized),
        parent: null,
        children: []
      };
    }
    return cache[normalized].exports;
  }
  function isSameModule(a, b) {
    if (!a || !b) return false;
    return a === b;
  }
  function addChild(parent, child) {
    if (!parent || !child) {
      return;
    }
    if (!parent.children) {
      parent.children = [];
    }
    for (var i = 0; i < parent.children.length; i++) {
      if (isSameModule(parent.children[i], child)) {
        return;
      }
    }
    parent.children.push(child);
  }
  function dirname(path) {
    if (!path) {
      return "";
    }
    const normalized = path.replace(/\\/g, "/");
    const idx = normalized.lastIndexOf("/");
    if (idx <= 0) {
      return "";
    }
    return normalized.slice(0, idx);
  }
  function resolveModulePath(basePath, relativePath) {
    if (!relativePath) {
      return "";
    }
    if (/^([A-Za-z]:\\|[A-Za-z]:\/|\/|\\\\|\\)/.test(relativePath)) {
      return relativePath.replace(/\\/g, "/");
    }
    if (relativePath.indexOf("./") === 0 || relativePath.indexOf("../") === 0) {
      const normalizedBase = dirname(basePath).replace(/\\/g, "/");
      const normalizedRelative = relativePath.replace(/\\/g, "/");
      const stack = normalizedBase ? normalizedBase.split("/") : [];
      const segments = normalizedRelative.split("/");
      for (var i = 0; i < segments.length; i++) {
        var part = segments[i];
        if (!part || part === ".") {
          continue;
        }
        if (part === "..") {
          if (stack.length) {
            stack.pop();
          }
          continue;
        }
        stack.push(part);
      }
      return stack.join("/");
    }
    return relativePath.replace(/\\/g, "/");
  }
  function applyRolldownCjsDirnameBindings(source, bundlePath) {
    // Strip const/let/var __dirname/__filename declarations to avoid
    // clashing with the function parameters injected by the module loader.
    if (source && (source.indexOf("__dirname") !== -1 || source.indexOf("__filename") !== -1)) {
      source = source.replace(/\b(const|let|var)\s+__dirname\s*=[^;\n]+[;\n]/g, '/* __dirname provided by loader */\n');
      source = source.replace(/\b(const|let|var)\s+__filename\s*=[^;\n]+[;\n]/g, '/* __filename provided by loader */\n');
    }
    return source;
  }
  function fixEsmCjsInterop(source) {
    // Patch rolldown's __toCommonJS to return .default with named exports
    // merged, so require('esm-pkg') returns the default export directly.
    if (!source || source.indexOf("__toCommonJS") === -1) return source;
    var marker = "var __toCommonJS = (mod) =>";
    var idx = source.indexOf(marker);
    if (idx === -1) return source;
    var end = source.indexOf(";", idx);
    if (end === -1) return source;
    var replacement = marker + " {\n" +
      "  if (__hasOwnProp.call(mod, 'module.exports')) return mod['module.exports'];\n" +
      "  var __ns = __copyProps(__defProp({}, '__esModule', { value: true }), mod);\n" +
      "  if (__ns.default !== undefined) {\n" +
      "    var __def = __ns.default;\n" +
      "    if (__def && (typeof __def === 'function' || typeof __def === 'object')) {\n" +
      "      var __ks = Object.keys(__ns);\n" +
      "      for (var __ki = 0; __ki < __ks.length; __ki++) {\n" +
      "        if (__ks[__ki] !== 'default' && __ks[__ki] !== '__esModule' && !(__ks[__ki] in __def)) {\n" +
      "          try { __def[__ks[__ki]] = __ns[__ks[__ki]]; } catch(e) {}\n" +
      "        }\n" +
      "      }\n" +
      "    }\n" +
      "    return __def;\n" +
      "  }\n" +
      "  return __ns;\n" +
      "}";
    return source.slice(0, idx) + replacement + source.slice(end + 1);
  }
  function __exactPinProcessStreams() {
    if (typeof process !== 'object' || process === null) {
      return;
    }
    if (process.__exactStreamPinned) {
      return;
    }
    function createWritableProxy(stream) {
      if (!stream) return stream;
      var writeFn = stream.write;
      var proxy = Object.create(stream);
      Object.defineProperty(proxy, "write", {
        configurable: true,
        enumerable: true,
        get: function() { return writeFn; },
        set: function(value) {
          writeFn = value;
        },
      });
      return proxy;
    }
    try {
      if (typeof process.stdout !== 'object' || process.stdout === null) {
        return;
      }
      var stdout = process.stdout;
      var stderr = process.stderr;
      if (stdout && stdout.writable === undefined) {
        stdout = createWritableProxy(stdout);
        if (stdout.writable === undefined) {
          stdout.writable = true;
        }
      }
      Object.defineProperty(process, 'stdout', {
        value: stdout,
        writable: true,
        configurable: true,
        enumerable: true,
      });
      if (stderr) {
        if (stderr.writable === undefined) {
          stderr = createWritableProxy(stderr);
          if (stderr.writable === undefined) {
            stderr.writable = true;
          }
        }
        Object.defineProperty(process, 'stderr', {
          value: stderr,
          writable: true,
          configurable: true,
          enumerable: true,
        });
      }
      if (process.stdin) {
        Object.defineProperty(process, 'stdin', {
          value: process.stdin,
          writable: true,
          configurable: true,
          enumerable: true,
        });
      }
      process.__exactStreamPinned = true;
    } catch (_) {
      // Keep module loading resilient if process stream patching is not possible.
    }
  }
  function fixForOfScoping(source) {
    if (!source || !/\bfor\s*\(\s*(?:const|let)\b[^)]*\bof\b/.test(source)) {
      return source;
    }
    var lines = source.split("\n");
    var out = [];
    var i = 0;
    while (i < lines.length) {
      var line = lines[i];
      // Match: for (const/let BINDING of EXPR) {
      // Use precise parsing instead of regex to handle nested parens correctly
      var trimmed = line.replace(/^\s*/, "");
      var indent = line.slice(0, line.length - trimmed.length);
      if (!/^for\s*\(/.test(trimmed)) {
        out.push(line);
        i++;
        continue;
      }
      // Find the balanced closing paren for the for(...)
      var forStart = trimmed.indexOf("(");
      if (forStart === -1) { out.push(line); i++; continue; }
      var parenDepth = 0;
      var forEnd = -1;
      var inStr2 = false;
      var strCh2 = 0;
      for (var fi = forStart; fi < trimmed.length; fi++) {
        var fc = trimmed.charCodeAt(fi);
        if (inStr2) {
          if (fc === strCh2 && (fi === 0 || trimmed.charCodeAt(fi-1) !== 92)) inStr2 = false;
        } else {
          if (fc === 34 || fc === 39 || fc === 96) { inStr2 = true; strCh2 = fc; }
          else if (fc === 40) parenDepth++;
          else if (fc === 41) { parenDepth--; if (parenDepth === 0) { forEnd = fi; break; } }
        }
      }
      if (forEnd === -1) { out.push(line); i++; continue; }
      var inner = trimmed.slice(forStart + 1, forEnd).replace(/^\s+|\s+$/g, "");
      // Check if it's const/let ... of ...
      var ofMatch = inner.match(/^(?:const|let)\s+(\S+)\s+of\s+([\s\S]+)$/);
      if (!ofMatch) { out.push(line); i++; continue; }
      var binding = ofMatch[1];
      var expr = ofMatch[2];
      // Rest of line after for(...) must be just "{"
      var afterFor = trimmed.slice(forEnd + 1).replace(/^\s+|\s+$/g, "");
      if (afterFor !== "{") { out.push(line); i++; continue; }
      // Now find the matching closing brace
      var depth = 1;
      var bodyLines = [];
      var j = i + 1;
      var hasBreakContinue = false;
      var inStr = false;
      var strCh = 0;
      var inBlockComment = false;
      while (j < lines.length && depth > 0) {
        var bl = lines[j];
        var inLineComment = false;
        for (var k = 0; k < bl.length; k++) {
          var ch = bl.charCodeAt(k);
          var next = k + 1 < bl.length ? bl.charCodeAt(k + 1) : 0;
          if (inLineComment) break;
          if (inBlockComment) {
            if (ch === 42 && next === 47) {
              inBlockComment = false;
              k++;
            }
            continue;
          }
          if (inStr) {
            if (ch === 92) {
              k++;
              continue;
            }
            if (ch === strCh) {
              inStr = false;
              strCh = 0;
            }
            continue;
          }
          if (ch === 47 && next === 47) {
            inLineComment = true;
            break;
          }
          if (ch === 47 && next === 42) {
            inBlockComment = true;
            k++;
            continue;
          }
          if (ch === 34 || ch === 39 || ch === 96) {
            inStr = true;
            strCh = ch;
            continue;
          }
          if (ch === 123) depth++;
          else if (ch === 125) depth--;
          if (depth <= 0) break;
        }
        if (depth > 0) {
          bodyLines.push(bl);
          if (/\b(break|continue)\s*[;\n}]/.test(bl) || /\byield\b/.test(bl) || /\bawait\b/.test(bl) || /\breturn\b/.test(bl)) hasBreakContinue = true;
        }
        j++;
      }
      if (hasBreakContinue || depth !== 0) {
        out.push(line);
        i++;
        continue;
      }
      out.push(indent + "Array.from(" + expr + ").forEach(function(" + binding + ") {");
      for (var b = 0; b < bodyLines.length; b++) {
        out.push(bodyLines[b]);
      }
      out.push(indent + "});");
      i = j;
    }
    return out.join("\n");
  }
  function aliasNodePathGlobals(source) {
    if (!source || (source.indexOf("__dirname") === -1 && source.indexOf("__filename") === -1)) {
      return source;
    }
    return source.replace(/\b__dirname\b/g, "globalThis.__dirname").replace(/\b__filename\b/g, "globalThis.__filename");
  }
  function transformImportMeta(source) {
    if (!source || source.indexOf("import.meta") === -1) {
      return source;
    }
    return source
      .replace(/import\.meta\.url/g, '("file://" + __filename)')
      .replace(/import\.meta\.path/g, "__filename")
      .replace(/import\.meta\.filename/g, "__filename")
      .replace(/import\.meta\.file(?!name)/g, "(typeof __filename !== 'undefined' ? __filename.split('/').pop() : '')")
      .replace(/import\.meta\.dir/g, "__dirname")
      .replace(/import\.meta\.main/g, "(typeof __filename !== 'undefined' && __filename === (globalThis.process && globalThis.process.argv && globalThis.process.argv[1]))")
      .replace(/import\.meta\.require/g, "require");
  }
  function transformDynamicImport(source) {
    if (!source || source.indexOf("import(") === -1) {
      return source;
    }
    // Replace dynamic import() calls with globalThis["import"]() polyfill.
    // Skip replacements inside string literals to avoid breaking error messages etc.
    var result = "";
    var i = 0;
    var len = source.length;
    while (i < len) {
      var ch = source[i];
      // Skip string literals
      if (ch === '"' || ch === "'" || ch === '`') {
        var quote = ch;
        var j = i + 1;
        while (j < len) {
          if (source[j] === '\\') { j += 2; continue; }
          if (source[j] === quote) { j++; break; }
          j++;
        }
        result += source.slice(i, j);
        i = j;
        continue;
      }
      // Check for import( pattern
      if (source.slice(i, i + 7) === 'import(' || source.slice(i, i + 7) === 'import ') {
        var rest = source.slice(i);
        var m = rest.match(/^import\s*\(/);
        if (m) {
          result += 'globalThis["import"](';
          i += m[0].length;
          continue;
        }
      }
      result += ch;
      i++;
    }
    return result;
  }
  function transformEsmToCjs(source) {
    if (!source) {
      return "";
    }
    var lines = String(source).split("\n");
    var out = [];
    var importCounter = 0;
    var isIdent = /^[A-Za-z_$][\w$]*$/;
    var isExportName = function(value) {
      return value === "default" || isIdent.test(value);
    };
    var quote = function(value) {
      return JSON.stringify(value);
    };
    var emitNamedBindings = function(spec, modName) {
      var parts = spec ? spec.split(",") : [];
      for (var i = 0; i < parts.length; i++) {
        var item = parts[i].trim();
        if (!item) {
          continue;
        }
        var asMatch = item.match(/^(.+?)\s+as\s+(.+)$/);
        if (asMatch) {
          var sourceName = asMatch[1].trim();
          var localName = asMatch[2].trim();
          if (!isExportName(sourceName) || !isIdent.test(localName) || localName === "default") {
            continue;
          }
          if (sourceName === "default") {
            out.push("var " + localName + " = " + modName + " && " + modName + ".default;");
          } else {
            out.push("var " + localName + " = " + modName + "." + sourceName + ";");
          }
        } else if (isIdent.test(item)) {
          out.push("var " + item + " = " + modName + "." + item + ";");
        }
      }
    };
    var emitExportBindings = function(spec, sourceExpr, allowBareDefault, useLocals) {
      var entries = spec ? spec.split(",") : [];
      for (var i = 0; i < entries.length; i++) {
        var item = entries[i].trim();
        if (!item) {
          continue;
        }
        var asMatch = item.match(/^(.+?)\s+as\s+(.+)$/);
        if (asMatch) {
          var sourceName = asMatch[1].trim();
          var exportName = asMatch[2].trim();
          if (!isExportName(sourceName) || !isExportName(exportName)) {
            continue;
          }
          if (useLocals) {
            out.push("module.exports." + exportName + " = " + sourceName + ";");
          } else {
            out.push("module.exports." + exportName + " = " + sourceExpr + "." + sourceName + ";");
          }
          continue;
        }
        if (!allowBareDefault && item === "default") {
          continue;
        }
        if (isExportName(item)) {
          if (useLocals) {
            out.push("module.exports." + item + " = " + item + ";");
          } else {
            out.push("module.exports." + item + " = " + sourceExpr + "." + item + ";");
          }
        }
      }
    };
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var trimmed = line.trim();
      var statement = line;
      if (/^\s*(import|export)\b/.test(trimmed) && trimmed.indexOf(";") === -1) {
        for (var j = i + 1; j < lines.length; j++) {
          statement = statement + "\n" + lines[j];
          if (statement.indexOf(";") !== -1) {
            i = j;
            break;
          }
        }
      }
      if (line.indexOf("import.meta") !== -1) {
        statement = transformImportMeta(statement);
      }
      var transformed = statement;
      trimmed = transformed.trim();
      var m;

      if (!trimmed) {
        out.push("");
        continue;
      }

      m = trimmed.match(/^\s*import\s+(["'])([^'"]+)\1\s*;?\s*$/);
      if (m) {
        out.push("require(" + quote(m[2]) + ");");
        continue;
      }

      m = trimmed.match(/^\s*import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        out.push("var " + m[1] + " = require(" + quote(m[3]) + ");");
        continue;
      }

      m = trimmed.match(
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\{([\s\S]*?)\}\s+from\s+(["'])([^'"]+)\3\s*;?\s*$/
      );
      if (m) {
        var namedImport = "__exmod" + (importCounter++);
        out.push("var " + namedImport + " = require(" + quote(m[4]) + ");");
        out.push(
          "var " +
            m[1] +
            " = " +
            namedImport +
            " && " +
            namedImport +
            ".__esModule ? " +
            namedImport +
            ".default : " +
            namedImport +
            ";"
        );
        emitNamedBindings(m[2], namedImport);
        continue;
      }

      m = trimmed.match(
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\3\s*;?\s*$/
      );
      if (m) {
        var nsImport = "__exmod" + (importCounter++);
        out.push("var " + nsImport + " = require(" + quote(m[4]) + ");");
        out.push(
          "var " +
            m[1] +
            " = " +
            nsImport +
            " && " +
            nsImport +
            ".__esModule ? " +
            nsImport +
            ".default : " +
            nsImport +
            ";"
        );
        out.push("var " + m[2] + " = " + nsImport + ";");
        continue;
      }

      m = trimmed.match(/^\s*import\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        out.push(
          "var " +
            m[1] +
            " = require(" +
            quote(m[3]) +
            ").default || require(" +
            quote(m[3]) +
            ");"
        );
        continue;
      }

      m = trimmed.match(/^\s*import\s+\{([\s\S]*?)\}\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        var named = "__exmod" + (importCounter++);
        out.push("var " + named + " = require(" + quote(m[3]) + ");");
        emitNamedBindings(m[1], named);
        continue;
      }

      m = trimmed.match(/^\s*export\s+\*\s+from\s+(["'])([^'"]+)\1\s*;?\s*$/);
      if (m) {
        var exportFrom = "__exmod" + (importCounter++);
        out.push("var " + exportFrom + " = require(" + quote(m[2]) + ");");
        out.push("for (var __exk in " + exportFrom + ") {");
        out.push("  if (Object.prototype.hasOwnProperty.call(" + exportFrom + ", __exk)) {");
        out.push("    module.exports[__exk] = " + exportFrom + "[__exk];");
        out.push("  }");
        out.push("}");
        continue;
      }

      m = trimmed.match(/^\s*export\s+\{([\s\S]*?)\}\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        var exportFrom = "__exmod" + (importCounter++);
        out.push("var " + exportFrom + " = require(" + quote(m[3]) + ");");
        emitExportBindings(m[1], exportFrom, true, false);
        continue;
      }

      m = trimmed.match(
        /^\s*export\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/
      );
      if (m) {
        var nsExport = "__exmod" + (importCounter++);
        out.push("var " + nsExport + " = require(" + quote(m[3]) + ");");
        out.push("module.exports." + m[1] + " = " + nsExport + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+(function|class)\s+([A-Za-z_$][\w$]*)/);
      if (m) {
        out.push(transformed.replace(/\bexport\s+/, ""));
        out.push("module.exports." + m[2] + " = " + m[2] + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+default\s+(.+)\s*$/);
      if (m) {
        out.push("module.exports.default = " + m[1] + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+(const|let|var)\s+([A-Za-z_$][\w$]*)/);
      if (m) {
        out.push(transformed.replace(/\bexport\s+/, ""));
        out.push("module.exports." + m[2] + " = " + m[2] + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+\{([^}]*)\}\s*;?\s*$/);
      if (m) {
        emitExportBindings(m[1], null, false, true);
        continue;
      }

      out.push(transformed);
    }
    return out.join("\n");
  }
  function load(specifier, referrer, parent) {
    __exactPinProcessStreams();

    // Lazy-load triggers: ensure non-essential bootstrap blocks are loaded
    // when their corresponding modules are first required.
    if (typeof __exactEnsureStreamEnhance === 'function') {
      if (specifier === 'stream' || specifier === 'stream/web' ||
          specifier === 'node:stream' || specifier === 'node:stream/web') {
        __exactEnsureStreamEnhance();
      }
    }
    if (typeof __exactEnsureWebCrypto === 'function') {
      if (specifier === 'crypto' || specifier === 'node:crypto') {
        __exactEnsureWebCrypto();
      }
    }
    if (typeof __exactEnsureDns === 'function') {
      if (specifier === 'dns' || specifier === 'node:dns' ||
          specifier === 'dns/promises' || specifier === 'node:dns/promises') {
        __exactEnsureDns();
      }
    }
    if (typeof __exactEnsureFs === 'function') {
      if (specifier === 'fs' || specifier === 'node:fs' ||
          specifier === 'fs/promises' || specifier === 'node:fs/promises' ||
          specifier === 'path' || specifier === 'node:path' ||
          specifier === 'path/posix' || specifier === 'node:path/posix' ||
          specifier === 'path/win32' || specifier === 'node:path/win32') {
        __exactEnsureFs();
      }
    }
    if (typeof __exactEnsureChildProcess === 'function') {
      if (specifier === 'child_process' || specifier === 'node:child_process') {
        __exactEnsureChildProcess();
      }
    }
    if (typeof __exactEnsureNet === 'function') {
      if (specifier === 'net' || specifier === 'node:net' ||
          specifier === 'tls' || specifier === 'node:tls' ||
          specifier === 'dgram' || specifier === 'node:dgram') {
        __exactEnsureNet();
      }
    }
    if (typeof __exactEnsureSqlite === 'function') {
      if (specifier === 'bun:sqlite' || specifier === 'better-sqlite3') {
        __exactEnsureSqlite();
      }
    }
    var normalized = normalizeSpecifier(specifier);
    if (normalized === 'fs/promises') {
      if (cache[normalized] && cache[normalized].loaded) {
        return cache[normalized].exports;
      }
      var fsModule = cache.fs || cache['node:fs'] || cache['fs/promises'] || cache['node:fs/promises'];
      var fsExports = fsModule && fsModule.exports ? fsModule.exports : fsModule;
      if (!fsExports || !fsExports.promises) {
        fsExports = load('fs', referrer, parent);
      }
      if (fsExports && fsExports.promises) {
        var cachedFsPromises = {
          exports: fsExports.promises,
          loaded: true,
          id: normalized,
          filename: normalized,
          path: '',
          __exactId: idToModuleId(normalized),
          parent: null,
          children: []
        };
        cache[normalized] = cache[normalized] || cachedFsPromises;
        cache[normalized].exports = cachedFsPromises.exports;
        cache[normalized].loaded = true;
        return cache[normalized].exports;
      }
      return {};
    }
    if (typeof __exactEnsureHttp === 'function') {
      if (specifier === 'http' || specifier === 'node:http' ||
          specifier === 'https' || specifier === 'node:https' ||
          specifier === 'http2' || specifier === 'node:http2') {
        __exactEnsureHttp();
      }
    }
    normalized = normalizeSpecifier(specifier);
    if (internalModules.hasOwnProperty(normalized)) {
      if (!cache[normalized]) {
        cache[normalized] = { exports: internalModules[normalized], loaded: true };
      }
      return cache[normalized].exports;
    }
    const json = __exactModuleResolve(specifier, referrer || "");
    if (!json) {
      throw new Error("Module not found: " + specifier);
    }
    let record;
    try {
      record = JSON.parse(json);
    } catch (err) {
      throw new Error("Module resolve failed: " + err.message);
    }
    if (record.error) {
      throw new Error(record.error);
    }
    const id = record.id || specifier;
    var moduleId = idToModuleId(id);
    if (cache[id]) {
      return cache[id].exports;
    }
    const kind = record.kind || "cjs";
    const source = record.source || "";
    var filename = record.path || id;
    // For the entry module, use the original source path so that
    // __dirname/__filename and require.resolve work relative to
    // the source dir, not the bundle cache dir.
    if (g.__exactEntryFile && !g.__exactEntryFileConsumed && filename.indexOf('/Caches/') !== -1) {
      filename = g.__exactEntryFile;
      g.__exactEntryFileConsumed = true;
    }
    const modulePath = filename.indexOf('/') === -1 ? filename : dirname(filename);
    // Compute node_modules search paths for this module
    var modulePaths = [];
    var pathParts = modulePath.split('/');
    for (var pi = pathParts.length - 1; pi >= 0; pi--) {
      if (pathParts[pi] === 'node_modules') continue;
      modulePaths.push(pathParts.slice(0, pi + 1).join('/') + '/node_modules');
    }
    const module = {
      id: id,
      __exactId: moduleId,
      filename: filename,
      path: modulePath,
      exports: {},
      loaded: false,
      parent: parent || null,
      children: [],
      paths: modulePaths,
    };
    cache[id] = module;
    if (!parent && !mainModule) {
      mainModule = module;
    }
    addChild(parent, module);

    module.require = function(next, options) {
      grantCapabilities(next, options, module.__exactId);
      return localRequire(next);
    };

    if (kind === "json") {
      try {
        module.exports = JSON.parse(source || "null");
      } catch (err) {
        delete cache[id];
        throw err;
      }
      module.loaded = true;
      return module.exports;
    }
    const dir = dirname(filename);
    const looksLikeModuleSyntax = function(text) {
      return /\n?\s*(?:import|export)\b/m.test(text || "");
    };
    var localRequire = function(next) {
      var internal = loadInternal(next);
      if (internal) return internal;
      var exports = load(next, filename, module);
      // Skip interop for ESM-shimmed modules — the shim's generated
      // import bindings already handle default/named/namespace access.
      if (exports && exports.__esmShimmed) {
        return exports;
      }
      // ESM/CJS interop: when a bundled ESM module is loaded via require(),
      // rolldown wraps it with __esModule:true. Return .default so that
      // require('pkg') returns the default export directly, with named
      // exports merged onto it so destructuring still works.
      if (exports && exports.__esModule && exports.default !== undefined) {
        var def = exports.default;
        if (def && (typeof def === "function" || typeof def === "object")) {
          var keys = Object.keys(exports);
          for (var ki = 0; ki < keys.length; ki++) {
            var k = keys[ki];
            if (k !== "default" && k !== "__esModule" && !(k in def)) {
              try { def[k] = exports[k]; } catch (e) {}
            }
          }
        }
        return def;
      }
      return exports;
    };
    localRequire.resolve = function(specifier) {
      var json = __exactModuleResolve(specifier, filename || "");
      if (!json) {
        throw new Error("Cannot find module '" + specifier + "'");
      }
      var rec = JSON.parse(json);
      if (rec.error) {
        throw new Error("Cannot find module '" + specifier + "'");
      }
      return rec.path || rec.id || specifier;
    };
    localRequire.resolve.paths = function(specifier) {
      return null;
    };
    localRequire.cache = cache;
    localRequire.main = mainModule;
    const restoreModuleId = function(previousId) {
      if (typeof g.__exactSetActiveModuleId === "function") {
        g.__exactSetActiveModuleId(previousId || 0);
      }
    };
    const previousModuleId = typeof g.__exactSetActiveModuleId === "function"
      ? g.__exactSetActiveModuleId(module.__exactId)
      : 0;
    const previousNodeFilename = g.__filename;
    const previousNodeDirname = g.__dirname;
    try {
      const directSource =
        transformDynamicImport(transformImportMeta(applyRolldownCjsDirnameBindings(fixForOfScoping(fixEsmCjsInterop(source || "")), filename))) +
        "\n//# sourceURL=" + filename;
      g.__exactDebugModuleSources = (g.__exactDebugModuleSources || []);
      if (Array.isArray(g.__exactDebugModuleSources)) {
        g.__exactDebugModuleSources.push({ id: id, filename: filename, source: directSource.slice(0, 2000) });
      }
      g.__exactDebugModuleSource = directSource;
      try {
        g.__filename = filename;
        g.__dirname = dir;
        const directFn = new Function(
          "require",
          "module",
          "exports",
          "__filename",
          "__dirname",
          directSource
        );
        directFn(localRequire, module, module.exports, filename, dir);
      } catch (err) {
        const shouldFallback = (kind === "esm" || looksLikeModuleSyntax(directSource));
        const canFallback = shouldFallback &&
          err &&
          err.name === "SyntaxError" &&
          directSource.length > 0;
        if (!canFallback) {
          throw err;
        }
        const runtimeSource =
          transformDynamicImport(transformImportMeta(applyRolldownCjsDirnameBindings(fixForOfScoping(transformEsmToCjs(directSource)), filename))) +
            "\n//# sourceURL=" + filename;
        if (Array.isArray(g.__exactDebugModuleSources)) {
          g.__exactDebugModuleSources.push({ id: id, filename: filename, source: runtimeSource.slice(0, 2000), fallback: true });
        }
        g.__exactDebugModuleSource = runtimeSource;
        const fallbackFn = new Function(
          "require",
          "module",
          "exports",
          "__filename",
          "__dirname",
          runtimeSource
        );
        g.__filename = filename;
        g.__dirname = dir;
        fallbackFn(localRequire, module, module.exports, filename, dir);
        if (module.exports && typeof module.exports === "object") {
          module.exports.__esModule = true;
          Object.defineProperty(module.exports, '__esmShimmed', { value: true });
        }
      }
    } catch (err) {
      delete cache[id];
      throw err;
    } finally {
      if (typeof previousNodeFilename === "undefined") {
        delete g.__filename;
      } else {
        g.__filename = previousNodeFilename;
      }
      if (typeof previousNodeDirname === "undefined") {
        delete g.__dirname;
      } else {
        g.__dirname = previousNodeDirname;
      }
      restoreModuleId(previousModuleId);
    }
    module.loaded = true;
    return module.exports;
  }
  // Convert a module specifier or id to a numeric module identifier used
  // by runtime capability checks.
  var idToModuleId = function(specifier) {
    var id = typeof specifier === "string" ? specifier : String(specifier || "");
    var moduleId = 0;
    for (var i = 0; i < id.length; i++) {
      moduleId = ((moduleId << 5) - moduleId) + id.charCodeAt(i);
      moduleId = moduleId & moduleId;
    }
    return moduleId < 0 ? -moduleId : moduleId;
  };

  // Helper to grant capabilities from options parameter
  var grantCapabilities = function(specifier, options, moduleId) {
    if (!options || typeof options !== 'object') return;
    var needs = options.needs;
    if (!needs) return;

    var numericModuleId = typeof moduleId === 'number' && isFinite(moduleId) ? moduleId : idToModuleId(specifier);
    if (numericModuleId < 0) {
      numericModuleId = -numericModuleId;
    }

    // Grant capabilities using Exact.setModuleCapabilities
    if (typeof globalThis.Exact === 'object' &&
        typeof globalThis.Exact.setModuleCapabilities === 'function') {
      var caps = Array.isArray(needs) ? needs : [needs];
      globalThis.Exact.setModuleCapabilities(numericModuleId, caps);
    }
  };

  globalThis.require = function(specifier, options) {
    // Grant capabilities if provided
    grantCapabilities(specifier, options, 0);
    var internal = loadInternal(specifier);
    if (internal) return internal;
    return load(specifier, "");
  };
  globalThis.require.cache = cache;
  globalThis.require.resolve = function(specifier) {
    var json = __exactModuleResolve(specifier, "");
    if (!json) {
      throw new Error("Cannot find module '" + specifier + "'");
    }
    var record = JSON.parse(json);
    if (record.error) {
      throw new Error("Cannot find module '" + specifier + "'");
    }
    return record.path || record.id || specifier;
  };
  globalThis.require.resolve.paths = function(specifier) {
    return null;
  };
  Object.defineProperty(globalThis.require, 'main', {
    get: function() { return mainModule; },
    configurable: true,
    enumerable: true
  });
  globalThis.__exactRequire = load;

  // Polyfill dynamic import() using require()
  // import() returns a Promise that resolves to the module
  // ESM default export becomes { default: ... }, named exports are direct properties
  var importImpl = function(specifier, options) {
    return Promise.resolve().then(function() {
      // Grant capabilities if provided
      grantCapabilities(specifier, options);

      var module = load(specifier, "");
      // Wrap CommonJS modules to look like ESM: { default: module, ...module }
      // This allows: const mod = await import('foo'); mod.default or mod.something
      if (module && !module.__esModule) {
        var moduleType = typeof module;
        // Wrap objects and functions
        if (moduleType === 'object' || moduleType === 'function') {
          var wrapped = { default: module };
          // For objects, copy properties to wrapped
          if (moduleType === 'object') {
            for (var key in module) {
              if (module.hasOwnProperty(key)) {
                wrapped[key] = module[key];
              }
            }
          }
          return wrapped;
        }
      }
      return module;
    });
  };

  // Set as globalThis.import (use globalThis.import('foo') or globalThis['import']('foo'))
  if (typeof globalThis.import === 'undefined') {
    Object.defineProperty(globalThis, 'import', {
      value: importImpl,
      writable: false,
      enumerable: false,
      configurable: true
    });
  }

  // Also provide as importModule() for convenience (since import(...) triggers parser)
  globalThis.importModule = importImpl;

  // Wrap queueMicrotask to throw TypeError for non-function arguments (spec requirement)
  if (typeof queueMicrotask === 'function') {
    var _nativeQueueMicrotask = queueMicrotask;
    globalThis.queueMicrotask = function queueMicrotask(callback) {
      if (typeof callback !== 'function') {
        throw new TypeError("Failed to execute 'queueMicrotask': parameter 1 is not of type 'Function'.");
      }
      return _nativeQueueMicrotask(callback);
    };
  }

  // Fix console global to match WPT/spec requirements:
  // - non-enumerable on globalThis
  // - Symbol.toStringTag = "console"
  // - prototype chain: console -> {} -> Object.prototype
  if (typeof console !== 'undefined') {
    // Make the console property non-enumerable (spec requirement)
    Object.defineProperty(globalThis, 'console', {
      value: console,
      writable: true,
      enumerable: false,
      configurable: true
    });

    // Add Symbol.toStringTag so Object.prototype.toString returns "[object console]"
    if (typeof Symbol !== 'undefined' && Symbol.toStringTag) {
      Object.defineProperty(console, Symbol.toStringTag, {
        value: 'console',
        writable: false,
        enumerable: false,
        configurable: true
      });
    }

    // Fix prototype chain: console should have an empty prototype object
    // between it and Object.prototype (per WebIDL namespace spec)
    var consoleProto = Object.getPrototypeOf(console);
    if (consoleProto === Object.prototype || (consoleProto && Object.getOwnPropertyNames(consoleProto).length > 0)) {
      var emptyProto = Object.create(Object.prototype);
      Object.setPrototypeOf(console, emptyProto);
    }
  }
})();
