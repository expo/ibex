(function() {
  var g = globalThis;
  if (!g.global) {
    g.global = g;
  }

  // Polyfill Symbol.dispose and Symbol.asyncDispose if missing
  if (typeof Symbol === 'function') {
    if (!Symbol.dispose) {
      Symbol.dispose = Symbol.for('nodejs.dispose');
    }
    if (!Symbol.asyncDispose) {
      Symbol.asyncDispose = Symbol.for('nodejs.asyncDispose');
    }
  }

  (function installNodeTimerHelpers() {
    if (typeof g.setTimeout !== 'function' || typeof g.setInterval !== 'function') {
      return;
    }

    var nativeSetTimeout = g.setTimeout;
    var nativeClearTimeout = g.clearTimeout || function() {};
    var nativeSetInterval = g.setInterval;
    var nativeClearInterval = g.clearInterval || function() {};

    function Timeout(handle, clearHandle, schedule, args) {
      if (handle && typeof handle === 'object' && typeof handle.unref === 'function') {
        return handle;
      }

      this._exactHandle = handle;
      this._clear = clearHandle;
      this._schedule = schedule;
      this._args = args;
      this._destroyed = false;
      this._repeat = null;
      this._idleTimeout = -1;
      this._refed = true;
    }
    Timeout.prototype.ref = function() {
      this._refed = true;
      // Handle nested Timeout objects (e.g. setImmediate wrapping setTimeout)
      var h = this._exactHandle;
      if (h && typeof h === 'object' && typeof h.ref === 'function') {
        h.ref();
      } else if (typeof g.__exactTimerRef === 'function' && h != null) {
        g.__exactTimerRef(h);
      }
      return this;
    };
    Timeout.prototype.unref = function() {
      this._refed = false;
      // Handle nested Timeout objects (e.g. setImmediate wrapping setTimeout)
      var h = this._exactHandle;
      if (h && typeof h === 'object' && typeof h.unref === 'function') {
        h.unref();
      } else if (typeof g.__exactTimerUnref === 'function' && h != null) {
        g.__exactTimerUnref(h);
      }
      return this;
    };
    Timeout.prototype.hasRef = function() { return this._refed; };
    Timeout.prototype.refresh = function() {
      if (typeof this._clear === 'function' && this._exactHandle != null) {
        this._clear(this._exactHandle);
      }
      this._destroyed = false;
      if (typeof this._schedule === 'function') {
        this._exactHandle = this._schedule.apply(g, this._args || []);
      }
      return this;
    };
    Timeout.prototype.close = function() {
      if (typeof this._clear === 'function' && this._exactHandle != null) {
        this._clear(this._exactHandle);
      }
      this._destroyed = true;
      return this;
    };
    Timeout.prototype.valueOf = function() { return this._exactHandle; };
    Timeout.prototype.toString = function() { return '[object Timeout]'; };
    if (typeof Symbol === 'function' && Symbol.toPrimitive) {
      Timeout.prototype[Symbol.toPrimitive] = function() { return this._exactHandle; };
    }
    if (typeof Symbol === 'function' && Symbol.dispose) {
      Timeout.prototype[Symbol.dispose] = function() { this.close(); };
    }

    function Immediate(handle, clearHandle, schedule, args) {
      this._exactHandle = handle;
      this._clear = clearHandle;
      this._schedule = schedule;
      this._args = args;
      this._destroyed = false;
      this._refed = true;
    }
    Immediate.prototype = Object.create(Timeout.prototype);
    Immediate.prototype.constructor = Immediate;

    function createTimeoutObject(handle, clearHandle, schedule, args) {
      if (handle && typeof handle === 'object' && typeof handle.unref === 'function') {
        return handle;
      }
      return new Timeout(handle, clearHandle, schedule, args);
    }

    function createImmediateObject(handle, clearHandle, schedule, args) {
      return new Immediate(handle, clearHandle, schedule, args);
    }

    function _validateTimerCb(callback) {
      if (typeof callback === 'function') {
        return callback;
      }
      // HTML spec: non-function arguments are stringified and eval'd.
      // This handles both string literals and objects with toString().
      var code = String(callback);
      return function() { (0, eval)(code); };
    }

    var _apply = Function.prototype.apply;
    var _call = Function.prototype.call;

    function wrapSetTimeout(callback, delay) {
      callback = _validateTimerCb(callback);
      // WebIDL `long` conversion and HTML spec delay clamping
      delay = delay | 0;
      if (delay < 0) delay = 0;

      var args = [];
      for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
      var timer;
      var cb = function() {
        timer._destroyed = true;
        _call.call(_apply, callback, timer, args);
      };
      var handle = nativeSetTimeout(cb, delay);
      timer = createTimeoutObject(handle, nativeClearTimeout, function() {
        return nativeSetTimeout(cb, delay);
      }, [callback, delay]);
      return timer;
    }

    function wrapSetInterval(callback, delay) {
      callback = _validateTimerCb(callback);
      // WebIDL `long` conversion and HTML spec delay clamping
      delay = delay | 0;
      if (delay < 0) delay = 0;

      var args = [];
      for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
      var timer;
      var cb = function() {
        _call.call(_apply, callback, timer, args);
      };
      var handle = nativeSetInterval(cb, delay);
      timer = createTimeoutObject(handle, nativeClearInterval, function() {
        return nativeSetInterval(cb, delay);
      }, [callback, delay]);
      return timer;
    }

    g.clearTimeout = function(handle) {
      if (handle && typeof handle === 'object' && handle._exactHandle != null) {
        handle._destroyed = true;
        return nativeClearTimeout(handle._exactHandle);
      }
      return nativeClearTimeout(handle);
    };

    g.clearInterval = function(handle) {
      if (handle && typeof handle === 'object' && handle._exactHandle != null) {
        handle._destroyed = true;
        return nativeClearInterval(handle._exactHandle);
      }
      return nativeClearInterval(handle);
    };

    if (typeof g.setImmediate === 'function' && typeof g.clearImmediate === 'function') {
      var nativeSetImmediate = g.setImmediate;
      var nativeClearImmediate = g.clearImmediate;

      g.setImmediate = function(callback) {
        callback = _validateTimerCb(callback);
        var args = [];
        for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
        var timer;
        var cb = function() {
          timer._destroyed = true;
          _call.call(_apply, callback, timer, args);
        };
        var handle = nativeSetImmediate(cb);
        timer = createImmediateObject(handle, nativeClearImmediate, function() { return nativeSetImmediate(cb); }, [callback]);
        return timer;
      };

      g.clearImmediate = function(handle) {
        if (handle && typeof handle === 'object' && handle._exactHandle != null) {
          handle._destroyed = true;
          return nativeClearImmediate(handle._exactHandle);
        }
        return nativeClearImmediate(handle);
      };
    }

    g.setTimeout = wrapSetTimeout;
    g.setInterval = wrapSetInterval;
  })();

  (function ensureProcessEventEmitter() {
    var p = g.process;
    if (!p) return;
    if (typeof p.on === 'function') return;

    if (typeof __exactEnsureStreamEnhance === 'function') {
      try {
        __exactEnsureStreamEnhance();
        return;
      } catch (e) {}
    }

    var listeners = {};
    p.on = function(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].push({ fn: fn, once: false });
      return p;
    };
    p.addListener = p.on;
    p.once = function(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].push({ fn: fn, once: true });
      return p;
    };
    p.emit = function(event) {
      var args = [];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      var list = listeners[event];
      if (!list) return false;
      var keep = [];
      for (var i = 0; i < list.length; i++) {
        var entry = list[i];
        if (!entry || typeof entry.fn !== 'function') continue;
        entry.fn.apply(p, args);
        if (!entry.once) keep.push(entry);
      }
      listeners[event] = keep;
      return true;
    };
    p.removeListener = function(event, fn) {
      var list = listeners[event];
      if (!list) return p;
      var keep = [];
      for (var i = 0; i < list.length; i++) {
        var entry = list[i];
        if (!entry || entry.fn === fn) continue;
        if (typeof entry.fn !== 'function') continue;
        keep.push(entry);
      }
      listeners[event] = keep;
      return p;
    };
    p.off = p.removeListener;
    p.removeAllListeners = function(event) {
      if (event) { listeners[event] = []; } else { listeners = {}; }
      return p;
    };
  })();

  // Compatibility shim: web stream queuing strategy constructors require
  // unrestricted-double conversion only for highWaterMark.
  (function installQueuingStrategyCompatibility() {
    if (typeof g.CountQueuingStrategy !== 'function' || typeof g.ByteLengthQueuingStrategy !== 'function') {
      return;
    }
    if (g.CountQueuingStrategy.__exactUnrestrictedDoublePatched) {
      return;
    }

    function toUnrestrictedDouble(value) {
      return Number(value);
    }

    function getHighWaterMark(options) {
      if (options === null || (typeof options !== 'object' && typeof options !== 'function')) {
        throw new TypeError('Cannot convert options to object');
      }
      if (!('highWaterMark' in options)) {
        throw new TypeError('The options object must include a highWaterMark');
      }
      return toUnrestrictedDouble(options.highWaterMark);
    }

    var countSize = (function() {
      return {
        size: () => 1
      }.size;
    }()).size;

    var byteLengthSize = (function() {
      return {
        size: (chunk) => {
          if (chunk == null) {
            throw new TypeError('The chunk argument must not be null or undefined');
          }
          return chunk.byteLength;
        }
      }.size;
    }()).size;

    function ExactCountQueuingStrategy(options) {
      if (!(this instanceof ExactCountQueuingStrategy)) {
        throw new TypeError('Class constructor CountQueuingStrategy cannot be invoked without new');
      }
      this.highWaterMark = getHighWaterMark(options);
    }

    function ExactByteLengthQueuingStrategy(options) {
      if (!(this instanceof ExactByteLengthQueuingStrategy)) {
        throw new TypeError('Class constructor ByteLengthQueuingStrategy cannot be invoked without new');
      }
      this.highWaterMark = getHighWaterMark(options);
    }

    ExactCountQueuingStrategy.prototype.size = countSize;
    ExactByteLengthQueuingStrategy.prototype.size = byteLengthSize;

    g.CountQueuingStrategy = ExactCountQueuingStrategy;
    g.ByteLengthQueuingStrategy = ExactByteLengthQueuingStrategy;
    g.CountQueuingStrategy.__exactUnrestrictedDoublePatched = true;
  })();

  var MIME = {
    '.txt':'text/plain;charset=utf-8','.html':'text/html;charset=utf-8','.htm':'text/html;charset=utf-8',
    '.css':'text/css;charset=utf-8','.js':'text/javascript;charset=utf-8','.mjs':'text/javascript;charset=utf-8',
    '.ts':'text/typescript;charset=utf-8','.tsx':'text/typescript;charset=utf-8','.jsx':'text/javascript;charset=utf-8',
    '.json':'application/json;charset=utf-8','.xml':'application/xml;charset=utf-8','.svg':'image/svg+xml;charset=utf-8',
    '.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.webp':'image/webp',
    '.pdf':'application/pdf','.zip':'application/zip','.gz':'application/gzip','.wasm':'application/wasm',
    '.mp3':'audio/mpeg','.mp4':'video/mp4','.webm':'video/webm','.ogg':'audio/ogg','.wav':'audio/wav',
    '.woff':'font/woff','.woff2':'font/woff2','.ttf':'font/ttf','.otf':'font/otf',
    '.md':'text/markdown;charset=utf-8','.yaml':'text/yaml;charset=utf-8','.yml':'text/yaml;charset=utf-8',
    '.toml':'text/toml;charset=utf-8','.csv':'text/csv;charset=utf-8','.sh':'application/x-sh','.sql':'application/sql'
  };
  function mimeType(p) {
    var i = p.lastIndexOf('.');
    return i === -1 ? 'application/octet-stream' : (MIME[p.slice(i).toLowerCase()] || 'application/octet-stream');
  }
  function decode(bytes) {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(bytes);
    var r = '';
    for (var i = 0; i < bytes.length; i++) r += String.fromCharCode(bytes[i]);
    return r;
  }
  function toBytes(data) {
    if (typeof data === 'string') {
      if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(data);
      var buf = new Uint8Array(data.length * 3), o = 0;
      for (var i = 0; i < data.length; i++) {
        var c = data.charCodeAt(i);
        if (c < 0x80) buf[o++] = c;
        else if (c < 0x800) { buf[o++] = 0xc0|(c>>6); buf[o++] = 0x80|(c&0x3f); }
        else { buf[o++] = 0xe0|(c>>12); buf[o++] = 0x80|((c>>6)&0x3f); buf[o++] = 0x80|(c&0x3f); }
      }
      return buf.slice(0, o);
    }
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(data))
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new Uint8Array(data);
  }

  function ExactFile(path, opts) {
    this.name = path;
    this.type = (opts && opts.type) || mimeType(path);
  }
  var _exactFsInitialized = false;
  function ensureExactFs() {
    if (_exactFsInitialized) return;
    if (typeof g.__exactEnsureFs === 'function') {
      try { g.__exactEnsureFs(); }
      catch (e) {}
    }
    _exactFsInitialized = true;
  }
  Object.defineProperty(ExactFile.prototype, 'size', {
    get: function() {
      ensureExactFs();
      try { var s = JSON.parse(g.__exactStat(this.name)); return s.size; } catch(e) { return 0; }
    }
  });
  Object.defineProperty(ExactFile.prototype, 'lastModified', {
    get: function() {
      ensureExactFs();
      try { var s = JSON.parse(g.__exactStat(this.name)); return s.mtime_ms; } catch(e) { return 0; }
    }
  });
  ExactFile.prototype.text = function() {
    var n = this.name;
    ensureExactFs();
    return Promise.resolve().then(function() { return decode(g.__exactReadFile(n)); });
  };
  ExactFile.prototype.json = function() {
    var n = this.name;
    ensureExactFs();
    return Promise.resolve().then(function() { return JSON.parse(decode(g.__exactReadFile(n))); });
  };
  ExactFile.prototype.arrayBuffer = function() {
    var n = this.name;
    ensureExactFs();
    return Promise.resolve().then(function() {
      var b = g.__exactReadFile(n);
      return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
    });
  };
  ExactFile.prototype.bytes = function() {
    var n = this.name;
    ensureExactFs();
    return Promise.resolve().then(function() { return g.__exactReadFile(n); });
  };
  ExactFile.prototype.exists = function() {
    var n = this.name;
    ensureExactFs();
    return Promise.resolve().then(function() {
      try { g.__exactAccess(n, 0); return true; } catch(e) { return false; }
    });
  };
  ExactFile.prototype.stat = function() {
    var n = this.name;
    ensureExactFs();
    return Promise.resolve().then(function() {
      try { return JSON.parse(g.__exactStat(n)); } catch(e) { return null; }
    });
  };
  ExactFile.prototype.slice = function(begin, end, type) {
    ensureExactFs();
    var b = g.__exactReadFile(this.name);
    var s = b.slice(begin || 0, end === undefined ? b.length : end);
    return new Blob([s], { type: type || this.type });
  };
  ExactFile.prototype.stream = function() {
    var n = this.name;
    ensureExactFs();
    return new ReadableStream({
      start: function(c) {
        try { c.enqueue(g.__exactReadFile(n)); c.close(); } catch(e) { c.error(e); }
      }
    });
  };
  ExactFile.prototype.writer = function() {
    var n = this.name, started = false;
    return {
      write: function(data) {
        ensureExactFs();
        var b = toBytes(data);
        if (!started) { g.__exactWriteFile(n, b); started = true; }
        else if (typeof g.__exactAppendFile === 'function') { g.__exactAppendFile(n, b); }
        return b.length;
      },
      end: function() {},
      flush: function() {}
    };
  };
  ExactFile.prototype.toString = function() { return 'ExactFile("' + this.name + '")'; };

  var E = g.Exact || {};
  function toModuleId(value) {
    if (typeof value === 'number' && isFinite(value) && value >= 0) {
      return value;
    }
    if (typeof value === 'string') {
      var parsed = Number(value);
      return isFinite(parsed) && parsed >= 0 ? parsed : 0;
    }
    return 0;
  }
  E.version = '0.1.0';
  E.platform = 'cli';
  E.file = function(path, opts) { return new ExactFile(path, opts); };
  E.write = function(dest, data) {
    var path = typeof dest === 'string' ? dest : dest.name;
    ensureExactFs();
    var b = toBytes(data);
    return Promise.resolve().then(function() { g.__exactWriteFile(path, b); return b.length; });
  };
  E.gc = function() {};
  E.env = (function() {
    var _store = {};
    return new Proxy(_store, {
      get: function(target, prop) {
        if (typeof prop === 'symbol') return undefined;
        if (prop === 'toJSON') {
          return function() {
            var all = {};
            var k;
            for (k in target) { if (Object.prototype.hasOwnProperty.call(target, k)) all[k] = target[k]; }
            if (typeof g.__exactGetAllEnv === 'function') {
              var native = g.__exactGetAllEnv();
              for (k in native) { if (Object.prototype.hasOwnProperty.call(native, k)) all[k] = native[k]; }
            }
            return all;
          };
        }
        if (prop === 'get') {
          return function(k) {
            if (typeof g.__exactGetEnv === 'function') { var v = g.__exactGetEnv(k); if (v !== undefined) return v; }
            return target[k];
          };
        }
        if (typeof g.__exactGetEnv === 'function') {
          var v = g.__exactGetEnv(prop);
          if (v !== undefined) return v;
        }
        return target[prop];
      },
      set: function(target, prop, value) {
        if (typeof prop === 'symbol') return false;
        target[prop] = String(value);
        return true;
      },
      has: function(target, prop) {
        if (typeof prop === 'symbol') return false;
        if (typeof g.__exactGetEnv === 'function') {
          if (g.__exactGetEnv(prop) !== undefined) return true;
        }
        return prop in target;
      },
      deleteProperty: function(target, prop) {
        if (typeof prop === 'symbol') return false;
        delete target[prop];
        return true;
      },
      ownKeys: function(target) {
        var keys = new Set(Object.keys(target));
        if (typeof g.__exactGetAllEnv === 'function') {
          var native = g.__exactGetAllEnv();
          Object.keys(native).forEach(function(k) { keys.add(k); });
        }
        return Array.from(keys);
      },
      getOwnPropertyDescriptor: function(target, prop) {
        if (typeof prop === 'symbol') return undefined;
        var val;
        if (typeof g.__exactGetEnv === 'function') {
          val = g.__exactGetEnv(prop);
          if (val !== undefined) return { value: val, writable: true, enumerable: true, configurable: true };
        }
        if (Object.prototype.hasOwnProperty.call(target, prop)) {
          return { value: target[prop], writable: true, enumerable: true, configurable: true };
        }
        return undefined;
      }
    });
  })();
  E.sleep = function(ms) { return new Promise(function(r) { setTimeout(r, ms || 0); }); };
  E.sleepSync = function() {};
  E.nanoseconds = function() { return Date.now() * 1e6; };
  E.escapeHTML = function(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
  };
  E.setModuleCapabilities = function(moduleId, capabilities) {
    var normalizedModuleId = toModuleId(moduleId);
    if (typeof g.__exactGrantCapability !== 'function') return;
    if (!capabilities) return;

    var caps = Array.isArray(capabilities) ? capabilities : [capabilities];
    for (var i = 0; i < caps.length; i++) {
      if (typeof caps[i] !== 'string') continue;
      g.__exactGrantCapability(normalizedModuleId, caps[i]);
    }
  };
  E.deepEquals = function deepEquals(a, b) {
    if (a === b) return true;
    if (a == null || b == null) return a === b;
    if (typeof a !== typeof b) return false;
    if (typeof a !== 'object') return a === b;
    if (Array.isArray(a) !== Array.isArray(b)) return false;
    if (Array.isArray(a)) {
      if (a.length !== b.length) return false;
      for (var i = 0; i < a.length; i++) if (!deepEquals(a[i], b[i])) return false;
      return true;
    }
    var ka = Object.keys(a), kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    for (var j = 0; j < ka.length; j++) {
      if (!Object.prototype.hasOwnProperty.call(b, ka[j])) return false;
      if (!deepEquals(a[ka[j]], b[ka[j]])) return false;
    }
    return true;
  };
  E.inspect = function(obj, opts) {
    var seen = new WeakSet(), depth = (opts && opts.depth) || 4;
    function iv(v, d) {
      if (d > depth) return '[...]';
      if (v === null) return 'null';
      if (v === undefined) return 'undefined';
      var t = typeof v;
      if (t === 'string') return JSON.stringify(v);
      if (t === 'number' || t === 'boolean') return String(v);
      if (t === 'function') return '[Function: ' + (v.name || 'anonymous') + ']';
      if (t === 'symbol') return v.toString();
      if (t !== 'object') return String(v);
      if (seen.has(v)) return '[Circular]';
      seen.add(v);
      if (Array.isArray(v)) return v.length ? '[ ' + v.map(function(x){return iv(x,d+1)}).join(', ') + ' ]' : '[]';
      var k = Object.keys(v);
      return k.length ? '{ ' + k.map(function(x){return x+': '+iv(v[x],d+1)}).join(', ') + ' }' : '{}';
    }
    return iv(obj, 0);
  };
  E.peek = function(p) {
    if (!(p instanceof Promise)) return { status: 'fulfilled', value: p };
    var s = 'pending', r;
    Promise.race([p.then(function(v){s='fulfilled';r=v},function(e){s='rejected';r=e}),Promise.resolve()]);
    return s === 'pending' ? { status: 'pending' } : s === 'fulfilled' ? { status: 'fulfilled', value: r } : { status: 'rejected', reason: r };
  };
  E.concatArrayBuffers = function concatArrayBuffers(buffers) {
    if (!Array.isArray(buffers)) {
      throw new TypeError('First argument must be an array of ArrayBuffer-like values');
    }
    if (buffers.length === 0) {
      return new Uint8Array(0).buffer;
    }
    var views = new Array(buffers.length);
    var totalLength = 0;
    var i;
    for (i = 0; i < buffers.length; i++) {
      var value = buffers[i];
      if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
        views[i] = new Uint8Array(value);
      } else if (value && typeof value === 'object' && ArrayBuffer.isView(value)) {
        views[i] = new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength || value.length);
      } else if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(value)) {
        views[i] = new Uint8Array(value.buffer || value, value.byteOffset || 0, value.byteLength || value.length);
      } else {
        throw new TypeError('Bun.concatArrayBuffers expects an array of ArrayBuffers or typed arrays');
      }
      totalLength += views[i].length;
      if (totalLength > 0x7fffffff) {
        throw new Error('Failed to allocate ArrayBuffer');
      }
    }
    var output;
    try {
      output = new Uint8Array(totalLength);
    } catch (e) {
      throw new Error('Failed to allocate ArrayBuffer');
    }
    var offset = 0;
    for (i = 0; i < views.length; i++) {
      output.set(views[i], offset);
      offset += views[i].length;
    }
    return output.buffer;
  };

  // --- Bun aliases ---
  E.fetch = (typeof fetch === 'function') ? fetch : undefined;
  E.resolve = function() {
    var path = require('path');
    return path.resolve.apply(path, arguments);
  };
  E.resolveSync = function() {
    return E.resolve.apply(E, arguments);
  };

  // Bun.password (stub for auth libraries)
  E.password = {
    hash: function(password, opts) {
      return Promise.reject(new Error('Bun.password.hash requires native bcrypt/argon2 support'));
    },
    hashSync: function(password, opts) {
      throw new Error('Bun.password.hashSync requires native bcrypt/argon2 support');
    },
    verify: function(password, hash) {
      return Promise.reject(new Error('Bun.password.verify requires native bcrypt/argon2 support'));
    },
    verifySync: function(password, hash) {
      throw new Error('Bun.password.verifySync requires native bcrypt/argon2 support');
    },
  };

  // Bun.color(name, format) - returns CSS color values for named colors
  E.color = function(name, format) {
    var colors = {
      red: [255,0,0], green: [0,128,0], blue: [0,0,255], white: [255,255,255],
      black: [0,0,0], yellow: [255,255,0], cyan: [0,255,255], magenta: [255,0,255],
      orange: [255,165,0], purple: [128,0,128], pink: [255,192,203],
      gray: [128,128,128], grey: [128,128,128],
    };
    var c = colors[name];
    if (!c) return null;
    if (format === 'css') return 'rgb(' + c[0] + ', ' + c[1] + ', ' + c[2] + ')';
    if (format === 'ansi') return '\x1b[38;2;' + c[0] + ';' + c[1] + ';' + c[2] + 'm';
    if (format === 'number') return (c[0] << 16) | (c[1] << 8) | c[2];
    if (format === 'rgba') return { r: c[0], g: c[1], b: c[2], a: 255 };
    return c;
  };

  // Bun.stringWidth(str) - approximate string display width
  E.stringWidth = function(str) {
    if (typeof str !== 'string') return 0;
    var width = 0;
    for (var i = 0; i < str.length; i++) {
      var code = str.charCodeAt(i);
      if (code === 0x1B) {
        while (i < str.length && str.charCodeAt(i) !== 0x6D) i++;
        continue;
      }
      if (code < 0x20 || (code >= 0x7F && code < 0xA0)) continue;
      if ((code >= 0x1100 && code <= 0x115F) ||
          (code >= 0x2E80 && code <= 0xA4CF && code !== 0x303F) ||
          (code >= 0xAC00 && code <= 0xD7A3) ||
          (code >= 0xF900 && code <= 0xFAFF) ||
          (code >= 0xFE10 && code <= 0xFE6F) ||
          (code >= 0xFF01 && code <= 0xFF60) ||
          (code >= 0xFFE0 && code <= 0xFFE6)) {
        width += 2;
      } else {
        width += 1;
      }
    }
    return width;
  };

  // Bun.pathToFileURL / Bun.fileURLToPath
  E.pathToFileURL = function(path) {
    return new URL('file://' + encodeURI(path.replace(/\\/g, '/')));
  };
  E.fileURLToPath = function(url) {
    var u = typeof url === 'string' ? new URL(url) : url;
    if (u.protocol !== 'file:') throw new TypeError('URL must be file: protocol');
    return decodeURIComponent(u.pathname);
  };

  // Bun.$ (shell template tag)
  E.$ = function(strings) {
    var cmd = '';
    for (var i = 0; i < strings.length; i++) {
      cmd += strings[i];
      if (i < arguments.length - 1) cmd += String(arguments[i + 1]);
    }
    var cp = require('child_process');
    var result = cp.execSync(cmd.trim(), { encoding: 'utf8' });
    return {
      text: function() { return result; },
      toString: function() { return result; },
      exitCode: 0,
    };
  };

  // Bun.semver (version comparison)
  E.semver = {
    satisfies: function(version, range) {
      try { var semver = require('semver'); return semver.satisfies(version, range); } catch(e) {}
      return true;
    },
    order: function(a, b) {
      var pa = a.split('.').map(Number);
      var pb = b.split('.').map(Number);
      for (var i = 0; i < 3; i++) {
        if ((pa[i] || 0) < (pb[i] || 0)) return -1;
        if ((pa[i] || 0) > (pb[i] || 0)) return 1;
      }
      return 0;
    },
  };

  // Bun.dns (DNS resolution wrapper)
  E.dns = {
    lookup: function(hostname, opts) {
      return new Promise(function(resolve, reject) {
        var dns = require('dns');
        dns.lookup(hostname, opts || {}, function(err, address, family) {
          if (err) return reject(err);
          resolve({ address: address, family: family });
        });
      });
    },
    resolve: function(hostname, type) {
      return new Promise(function(resolve, reject) {
        var dns = require('dns');
        dns.resolve(hostname, type || 'A', function(err, records) {
          if (err) return reject(err);
          resolve(records);
        });
      });
    },
  };

  // Metadata
  E.revision = '0000000';
  E.origin = '';
  E.enableANSIColors = true;
  E.Transpiler = function() { throw new Error('Bun.Transpiler is not available in Exact CLI mode'); };


  // --- Bun.spawn() and Bun.spawnSync() ---
  E.spawn = function(cmd, opts) {
    var args, options;
    if (Array.isArray(cmd)) {
      args = cmd;
      options = opts || {};
    } else if (cmd && typeof cmd === 'object') {
      args = cmd.cmd;
      options = {};
      for (var k in cmd) {
        if (k !== 'cmd') options[k] = cmd[k];
      }
      if (opts) {
        for (var k2 in opts) options[k2] = opts[k2];
      }
    } else {
      throw new TypeError('Bun.spawn: first argument must be an array or object with cmd property');
    }
    if (!args || !args.length) {
      throw new TypeError('Bun.spawn: command array must not be empty');
    }
    var cp = require('child_process');
    var proc = cp.spawn(args[0], args.slice(1), options);
    var result = {
      pid: proc.pid,
      stdin: proc.stdin || null,
      stdout: proc.stdout || null,
      stderr: proc.stderr || null,
      killed: false,
      exitCode: null,
      signalCode: null,
      kill: function(sig) { result.killed = true; return proc.kill(sig); },
      ref: function() { proc.ref(); return result; },
      unref: function() { proc.unref(); return result; }
    };
    result.exited = new Promise(function(resolve) {
      proc.on('close', function(code, signal) {
        result.exitCode = code;
        result.signalCode = signal || null;
        resolve(code);
      });
      proc.on('error', function() {
        result.exitCode = -1;
        result.killed = true;
        resolve(-1);
      });
    });
    return result;
  };

  E.spawnSync = function(cmd, opts) {
    var args, options;
    if (Array.isArray(cmd)) {
      args = cmd;
      options = opts || {};
    } else if (cmd && typeof cmd === 'object') {
      args = cmd.cmd;
      options = {};
      for (var k in cmd) {
        if (k !== 'cmd') options[k] = cmd[k];
      }
      if (opts) {
        for (var k2 in opts) options[k2] = opts[k2];
      }
    } else {
      throw new TypeError('Bun.spawnSync: first argument must be an array or object with cmd property');
    }
    if (!args || !args.length) {
      throw new TypeError('Bun.spawnSync: command array must not be empty');
    }
    var cp = require('child_process');
    var r = cp.spawnSync(args[0], args.slice(1), options);
    return {
      stdout: r.stdout || '',
      stderr: r.stderr || '',
      exitCode: r.status != null ? r.status : -1,
      success: r.status === 0
    };
  };

  // --- Bun.which() ---
  E.which = function(cmd) {
    if (typeof cmd !== 'string' || !cmd) return null;
    if (typeof g.__exactWhich === 'function') return g.__exactWhich(cmd);
    return null;
  };

  // --- Bun.hash() ---
  E.hash = function(data, seed) {
    if (typeof data === 'string') {
      var h = seed || 0;
      for (var i = 0; i < data.length; i++) {
        h = ((h << 5) - h + data.charCodeAt(i)) | 0;
      }
      return h >>> 0;
    }
    if (data && typeof data === 'object' && data.length !== undefined) {
      var h2 = seed || 0;
      for (var j = 0; j < data.length; j++) {
        h2 = ((h2 << 5) - h2 + (data[j] & 0xff)) | 0;
      }
      return h2 >>> 0;
    }
    return 0;
  };
  E.hash.wyhash = E.hash;
  E.hash.adler32 = function(data) {
    if (typeof data === 'string') {
      var a = 1, b = 0;
      for (var i = 0; i < data.length; i++) {
        a = (a + data.charCodeAt(i)) % 65521;
        b = (b + a) % 65521;
      }
      return ((b << 16) | a) >>> 0;
    }
    return 1;
  };
  E.hash.crc32 = function(data) {
    if (typeof data === 'string') {
      var crc = 0xFFFFFFFF;
      for (var i = 0; i < data.length; i++) {
        crc = crc ^ data.charCodeAt(i);
        for (var j = 0; j < 8; j++) {
          crc = (crc >>> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
      }
      return (crc ^ 0xFFFFFFFF) >>> 0;
    }
    return 0;
  };

  // --- Bun.sha() ---
  E.sha = function(data, encoding) {
    if (typeof g.__exactHashSync === 'function') {
      var input = typeof data === 'string' ? data : '';
      var hex = g.__exactHashSync('sha512', input);
      if (encoding === 'hex' || encoding === undefined) return hex;
      if (encoding === 'base64') {
        var bytes = [];
        for (var i = 0; i < hex.length; i += 2) {
          bytes.push(parseInt(hex.substr(i, 2), 16));
        }
        if (typeof btoa === 'function') {
          var str = '';
          for (var j = 0; j < bytes.length; j++) str += String.fromCharCode(bytes[j]);
          return btoa(str);
        }
        return hex;
      }
      return hex;
    }
    return '';
  };

  // --- Bun compression helpers ---
  E.gzipSync = function(data) {
    if (typeof g.__exactDeflateSync !== 'function') throw new Error('gzipSync not available');
    return g.__exactDeflateSync(toBytes(data), -1, 1);
  };
  E.gunzipSync = function(data) {
    if (typeof g.__exactInflateSync !== 'function') throw new Error('gunzipSync not available');
    return g.__exactInflateSync(toBytes(data), 1);
  };
  E.deflateSync = function(data, opts) {
    if (typeof g.__exactDeflateSync !== 'function') throw new Error('deflateSync not available');
    var level = (opts && opts.level !== undefined) ? opts.level : -1;
    return g.__exactDeflateSync(toBytes(data), level, 0);
  };
  E.inflateSync = function(data) {
    if (typeof g.__exactInflateSync !== 'function') throw new Error('inflateSync not available');
    return g.__exactInflateSync(toBytes(data), 0);
  };

  // --- Bun.readableStreamTo*() helpers ---
  E.readableStreamToText = function(stream) {
    if (typeof Response !== 'undefined') {
      return new Response(stream).text();
    }
    return new Promise(function(resolve, reject) {
      var chunks = [];
      var reader = stream.getReader();
      function pump() {
        reader.read().then(function(result) {
          if (result.done) { resolve(chunks.join('')); return; }
          chunks.push(typeof result.value === 'string' ? result.value : decode(result.value));
          pump();
        }, reject);
      }
      pump();
    });
  };
  E.readableStreamToArrayBuffer = function(stream) {
    if (typeof Response !== 'undefined') {
      return new Response(stream).arrayBuffer();
    }
    return new Promise(function(resolve, reject) {
      var chunks = [], totalLen = 0;
      var reader = stream.getReader();
      function pump() {
        reader.read().then(function(result) {
          if (result.done) {
            var out = new Uint8Array(totalLen), offset = 0;
            for (var i = 0; i < chunks.length; i++) { out.set(chunks[i], offset); offset += chunks[i].length; }
            resolve(out.buffer);
            return;
          }
          var chunk = result.value instanceof Uint8Array ? result.value : toBytes(result.value);
          chunks.push(chunk); totalLen += chunk.length;
          pump();
        }, reject);
      }
      pump();
    });
  };
  E.readableStreamToBlob = function(stream) {
    if (typeof Response !== 'undefined') {
      return new Response(stream).blob();
    }
    return E.readableStreamToArrayBuffer(stream).then(function(buf) {
      return new Blob([buf]);
    });
  };
  E.readableStreamToJSON = function(stream) {
    return E.readableStreamToText(stream).then(function(text) {
      return JSON.parse(text);
    });
  };
  E.readableStreamToArray = function(stream) {
    return new Promise(function(resolve, reject) {
      var chunks = [];
      var reader = stream.getReader();
      function pump() {
        reader.read().then(function(result) {
          if (result.done) { resolve(chunks); return; }
          chunks.push(result.value);
          pump();
        }).catch(reject);
      }
      pump();
    });
  };

  // --- Bun.argv, Bun.main, Bun.isMainThread ---
  E.argv = (typeof process !== 'undefined' && process.argv) ? process.argv : [];
  E.main = (typeof process !== 'undefined' && process.argv && process.argv[1]) ? process.argv[1] : '';
  E.stdin = (typeof process !== 'undefined') ? process.stdin : null;
  E.stdout = (typeof process !== 'undefined') ? process.stdout : null;
  E.stderr = (typeof process !== 'undefined') ? process.stderr : null;
  E.isMainThread = false;

  // Bun.serve() implementation
  E.serve = function(options) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('Bun.serve() expects an options object');
    }
    var fetchHandler = options.fetch;
    if (typeof fetchHandler !== 'function') {
      throw new TypeError('Bun.serve() requires a fetch handler function');
    }
    var errorHandler = options.error || function(err) {
      return new Response('Internal Server Error: ' + (err && err.message ? err.message : String(err)), {
        status: 500, headers: { 'Content-Type': 'text/plain' }
      });
    };
    var port = options.port || 3000;
    var hostname = options.hostname || '0.0.0.0';

    if (typeof __exactHttpServe !== 'function') {
      throw new Error('HTTP server not available in this environment');
    }

    var resultJson = __exactHttpServe(port, hostname);
    var result;
    try { result = JSON.parse(resultJson); } catch(e) {
      throw new Error('Failed to start HTTP server');
    }
    if (result.error) throw new Error(result.error);

    var serverId = result.id;
    var actualPort = result.port || port;
    var closing = false;

    function buildRequest(data) {
      var method = data.method || 'GET';
      var url = data.url || '/';
      var fullUrl;
      if (url.indexOf('http://') === 0 || url.indexOf('https://') === 0) {
        fullUrl = url;
      } else {
        var h = hostname === '0.0.0.0' ? 'localhost' : hostname;
        fullUrl = 'http://' + h + ':' + actualPort + url;
      }
      var headers = new Headers();
      if (data.headers) {
        if (Array.isArray(data.headers)) {
          for (var i = 0; i < data.headers.length; i++) {
            var pair = data.headers[i];
            if (!pair || pair.length < 2) {
              continue;
            }
            headers.set(pair[0], pair[1]);
          }
        } else if (typeof data.headers === 'object') {
          for (var k in data.headers) {
            if (Object.prototype.hasOwnProperty.call(data.headers, k)) headers.set(k, data.headers[k]);
          }
        }
      }
      var init = { method: method, headers: headers };
      if (method !== 'GET' && method !== 'HEAD' && data.body) {
        try { init.body = atob(data.body); } catch(e) { init.body = data.body; }
      }
      return new Request(fullUrl, init);
    }

    function sendResponse(requestId, response) {
      var status = response.status || 200;
      var hdrs = [];
      if (response.headers) response.headers.forEach(function(val, key) { hdrs.push([key, val]); });
      var headersJson = JSON.stringify(hdrs);
      response.text().then(function(bodyText) {
        if (typeof __exactHttpRespondString === 'function') {
          __exactHttpRespondString(serverId, requestId, status, headersJson, bodyText || '');
        }
      }).catch(function() {
        if (typeof __exactHttpRespondString === 'function') {
          __exactHttpRespondString(serverId, requestId, 500, '{"content-type":"text/plain"}', 'Internal Server Error');
        }
      });
    }

    function handleRequest(json) {
      var data;
      try { data = JSON.parse(json); } catch(e) { return; }
      var requestId = data.id || 0;
      var request;
      try { request = buildRequest(data); } catch(e) {
        sendResponse(requestId, new Response('Bad Request', { status: 400 }));
        return;
      }
      try {
        var result = fetchHandler(request);
        if (result && typeof result.then === 'function') {
          result.then(function(response) {
            sendResponse(requestId, response instanceof Response ? response : new Response(String(response || '')));
          }).catch(function(err) {
            try {
              var errR = errorHandler(err);
              if (errR && typeof errR.then === 'function') {
                errR.then(function(r) { sendResponse(requestId, r instanceof Response ? r : new Response(String(r || ''), { status: 500 })); })
                  .catch(function() { sendResponse(requestId, new Response('Internal Server Error', { status: 500 })); });
              } else {
                sendResponse(requestId, errR instanceof Response ? errR : new Response(String(errR || ''), { status: 500 }));
              }
            } catch(e2) { sendResponse(requestId, new Response('Internal Server Error', { status: 500 })); }
          });
        } else if (result instanceof Response) {
          sendResponse(requestId, result);
        } else {
          sendResponse(requestId, new Response(String(result || '')));
        }
      } catch(err) {
        try {
          var errR2 = errorHandler(err);
          sendResponse(requestId, errR2 instanceof Response ? errR2 : new Response(String(errR2 || ''), { status: 500 }));
        } catch(e2) { sendResponse(requestId, new Response('Internal Server Error', { status: 500 })); }
      }
    }

    function pollLoop() {
      if (closing) return;
      function poll() {
        if (closing) return;
        var json = typeof __exactHttpPoll === 'function' ? __exactHttpPoll(serverId) : null;
        if (json) { handleRequest(json); setTimeout(poll, 0); }
        else if (typeof __exactHttpWait === 'function') {
          __exactHttpWait(serverId, 1000).then(function(wj) { if (wj) handleRequest(wj); setTimeout(poll, 0); })
            .catch(function() { setTimeout(poll, 50); });
        } else { setTimeout(poll, 50); }
      }
      poll();
    }
    pollLoop();

    var h = hostname === '0.0.0.0' ? 'localhost' : hostname;
    return {
      port: actualPort, hostname: h,
      url: 'http://' + h + ':' + actualPort + '/',
      development: options.development !== undefined ? !!options.development : false,
      id: '', pendingRequests: 0,
      stop: function(force) { closing = true; if (typeof __exactHttpClose === 'function') __exactHttpClose(serverId, force ? 1 : 0); },
      reload: function(o) { if (o && typeof o.fetch === 'function') fetchHandler = o.fetch; if (o && typeof o.error === 'function') errorHandler = o.error; },
      ref: function() { if (typeof __exactHttpSetRef === 'function') __exactHttpSetRef(serverId, 1); },
      unref: function() { if (typeof __exactHttpSetRef === 'function') __exactHttpSetRef(serverId, 0); },
      requestIP: function() { return null; }, upgrade: function() { return false; }, publish: function() {},
      fetch: fetchHandler
    };
  };

  // Bun.listen() - TCP server (Bun-compatible API)
  E.listen = function(options) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('Bun.listen() expects an options object');
    }
    var handlers = options.socket;
    if (!handlers || typeof handlers !== 'object') {
      throw new TypeError('Bun.listen() requires a socket handlers object');
    }
    var hostname = options.hostname || '0.0.0.0';
    var port = options.port || 0;

    if (typeof __exactTcpListen !== 'function') {
      throw new Error('TCP server not available in this environment');
    }

    var serverHandle = __exactTcpListen(hostname, port, 128);
    var actualPort = port;
    try {
      var info = JSON.parse(__exactTcpLocalAddr(serverHandle));
      actualPort = info.port;
      if (info.address && info.address !== '0.0.0.0') hostname = info.address;
    } catch(e) {}

    var closing = false;
    var activeSockets = [];

    function BunSocket(handle) {
      this._handle = handle;
      this._destroyed = false;
      this._pollTimer = null;
      this.data = options.data !== undefined ? options.data : undefined;
      this.remoteAddress = '127.0.0.1';
      try {
        var r = JSON.parse(__exactTcpRemoteAddr(handle));
        this.remoteAddress = r.address;
      } catch(e) {}
    }
    BunSocket.prototype.write = function(data) {
      if (this._destroyed) return 0;
      try {
        var str = (typeof data === 'string') ? data :
          (data instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(data))) ?
            (typeof Buffer !== 'undefined' ? Buffer.from(data).toString() : String.fromCharCode.apply(null, data)) : String(data);
        return __exactTcpWrite(this._handle, str);
      } catch(e) { return 0; }
    };
    BunSocket.prototype.end = function(data) {
      if (data !== undefined) this.write(data);
      this._cleanup();
    };
    BunSocket.prototype.flush = function() { return this; };
    BunSocket.prototype.terminate = function() { this._cleanup(); };
    BunSocket.prototype._cleanup = function() {
      if (this._destroyed) return;
      this._destroyed = true;
      if (this._pollTimer != null) { clearTimeout(this._pollTimer); this._pollTimer = null; }
      try { __exactTcpClose(this._handle); } catch(e) {}
      var idx = activeSockets.indexOf(this);
      if (idx !== -1) activeSockets.splice(idx, 1);
      if (handlers.close) { try { handlers.close(this); } catch(e) {} }
    };
    BunSocket.prototype._startPolling = function() {
      var self = this;
      function poll() {
        if (self._destroyed) return;
        try {
          var data = __exactTcpRead(self._handle, 65536);
          if (data === null) {
            self._cleanup();
            return;
          }
          if (data.length > 0 && handlers.data) {
            var buf = data;
            if (typeof Buffer !== 'undefined' && Buffer.from) {
              if (typeof data === 'string') {
                buf = Buffer.from(data);
              } else if (data instanceof Uint8Array || (Buffer.isBuffer && Buffer.isBuffer(data))) {
                buf = Buffer.from(data.buffer || data, data.byteOffset || 0, data.byteLength || data.length);
              } else {
                try {
                  buf = Buffer.from(data);
                } catch (e) {}
              }
            }
            try { handlers.data(self, buf); } catch(e) {
              if (handlers.error) { try { handlers.error(self, e); } catch(e2) {} }
            }
          }
        } catch(e) {
          if (handlers.error) { try { handlers.error(self, e); } catch(e2) {} }
          self._cleanup();
          return;
        }
        self._pollTimer = setTimeout(poll, 5);
      }
      self._pollTimer = setTimeout(poll, 0);
    };

    var acceptTimer = null;
    function acceptLoop() {
      if (closing) return;
      try {
        var clientHandle = __exactTcpAccept(serverHandle);
        if (clientHandle !== -1) {
          var sock = new BunSocket(clientHandle);
          activeSockets.push(sock);
          if (handlers.open) { try { handlers.open(sock); } catch(e) {
            if (handlers.error) { try { handlers.error(sock, e); } catch(e2) {} }
          }}
          sock._startPolling();
        }
      } catch(e) {}
      acceptTimer = setTimeout(acceptLoop, 10);
    }
    acceptTimer = setTimeout(acceptLoop, 0);

    return {
      port: actualPort,
      hostname: hostname,
      stop: function(closeActive) {
        closing = true;
        if (acceptTimer != null) { clearTimeout(acceptTimer); acceptTimer = null; }
        if (closeActive) {
          var socks = activeSockets.slice();
          for (var i = 0; i < socks.length; i++) { socks[i]._cleanup(); }
        }
        try { __exactTcpClose(serverHandle); } catch(e) {}
      },
      ref: function() { return this; },
      unref: function() { return this; },
      reload: function(newHandlers) {
        if (newHandlers && newHandlers.socket) handlers = newHandlers.socket;
      }
    };
  };

  // Bun.CryptoHasher
  E.CryptoHasher = (function() {
    function CH(algorithm) {
      if (!(this instanceof CH)) return new CH(algorithm);
      if (!algorithm || typeof algorithm !== 'string') throw new TypeError('algorithm must be a string');
      this._algo = algorithm.toLowerCase().replace('-', '');
      this._chunks = [];
    }
    CH.hash = function(algorithm, data, encoding) {
      var h = new CH(algorithm); h.update(data); return h.digest(encoding || 'hex');
    };
    CH.prototype.update = function(data) {
      if (typeof data === 'string') { this._chunks.push(data); }
      else if (data && data.length !== undefined) {
        var str = ''; for (var i = 0; i < data.length; i++) str += String.fromCharCode(data[i]);
        this._chunks.push(str);
      }
      return this;
    };
    CH.prototype.digest = function(encoding) {
      var joined = this._chunks.join('');
      if (typeof g.__exactHashSync === 'function') {
        var hex = g.__exactHashSync(this._algo, joined);
        if (!encoding || encoding === 'hex') return hex;
        if (encoding === 'base64') {
          var bytes = []; for (var i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
          if (typeof btoa === 'function') { var s = ''; for (var j = 0; j < bytes.length; j++) s += String.fromCharCode(bytes[j]); return btoa(s); }
        }
        if (!encoding) {
          var b = new Uint8Array(hex.length / 2);
          for (var k = 0; k < hex.length; k += 2) b[k / 2] = parseInt(hex.substr(k, 2), 16);
          return b;
        }
        return hex;
      }
      throw new Error('Native hash not available');
    };
    CH.prototype.copy = function() { var h = new CH(this._algo); h._chunks = this._chunks.slice(); return h; };
    return CH;
  })();

  // Bun.deepMatch(subset, object)
  E.deepMatch = function deepMatch(subset, object) {
    if (subset === object) return true;
    if (subset == null || object == null) return subset === object;
    if (typeof subset !== 'object' || typeof object !== 'object') return subset === object;
    if (Array.isArray(subset)) {
      if (!Array.isArray(object) || subset.length !== object.length) return false;
      for (var i = 0; i < subset.length; i++) { if (!deepMatch(subset[i], object[i])) return false; }
      return true;
    }
    var keys = Object.keys(subset);
    for (var j = 0; j < keys.length; j++) {
      var k = keys[j];
      if (!Object.prototype.hasOwnProperty.call(object, k) || !deepMatch(subset[k], object[k])) return false;
    }
    return true;
  };

  g.Exact = E;
  g.Bun = E;
})();
