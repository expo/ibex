//! Runtime orchestration for the `ibex` CLI.
//!
//! This module wires together the engine, host configuration, security policy,
//! and build/transpile helpers used by the CLI entrypoints.

use crate::agent_logs;
use crate::cli::{BundleFormat, Cli};
use crate::engine::{self, Engine, EngineFeature};
use crate::host::{Host, HostConfig};
use crate::subprocess::{output_with_timeout, timeout_from_env, DEFAULT_BUNDLER_TIMEOUT_MS};
use anyhow::{Context, Result};
use std::borrow::Cow;
use std::env;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Set when bytecode loading fails (e.g. version mismatch between hermesc
/// and the embedded Hermes runtime). Once set, we skip further bytecode
/// compilation attempts for the rest of the process lifetime.
static BYTECODE_INCOMPATIBLE: AtomicBool = AtomicBool::new(false);

const WINDOWS_MINIMAL_RUNTIME_BOOTSTRAP: &str = r#"(function(g) {
  if (typeof g.TextEncoder !== 'function') {
    g.TextEncoder = function TextEncoder() {};
    g.TextEncoder.prototype.encode = function(value) {
      var str = String(value == null ? '' : value);
      var out = [];
      for (var i = 0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        if (code < 0x80) {
          out.push(code);
        } else if (code < 0x800) {
          out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
        } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
          var next = str.charCodeAt(++i);
          var cp = 0x10000 + (((code & 0x3ff) << 10) | (next & 0x3ff));
          out.push(
            0xf0 | (cp >> 18),
            0x80 | ((cp >> 12) & 0x3f),
            0x80 | ((cp >> 6) & 0x3f),
            0x80 | (cp & 0x3f)
          );
        } else {
          out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        }
      }
      return new Uint8Array(out);
    };
  }

  if (typeof g.TextDecoder !== 'function') {
    g.TextDecoder = function TextDecoder() {};
    g.TextDecoder.prototype.decode = function(input) {
      var bytes;
      if (input == null) {
        bytes = new Uint8Array(0);
      } else if (input instanceof ArrayBuffer) {
        bytes = new Uint8Array(input);
      } else if (ArrayBuffer.isView(input)) {
        bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
      } else {
        bytes = new Uint8Array(input);
      }
      var out = '';
      for (var i = 0; i < bytes.length;) {
        var b0 = bytes[i++];
        if (b0 < 0x80) {
          out += String.fromCharCode(b0);
        } else if ((b0 & 0xe0) === 0xc0) {
          var b1 = bytes[i++] || 0;
          out += String.fromCharCode(((b0 & 0x1f) << 6) | (b1 & 0x3f));
        } else if ((b0 & 0xf0) === 0xe0) {
          var b2 = bytes[i++] || 0;
          var b3 = bytes[i++] || 0;
          out += String.fromCharCode(((b0 & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f));
        } else {
          var b4 = bytes[i++] || 0;
          var b5 = bytes[i++] || 0;
          var b6 = bytes[i++] || 0;
          var cp = ((b0 & 0x07) << 18) | ((b4 & 0x3f) << 12) | ((b5 & 0x3f) << 6) | (b6 & 0x3f);
          cp -= 0x10000;
          out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
        }
      }
      return out;
    };
  }

  g.process = (typeof g.process === 'object' && g.process !== null) ? g.process : {};
  g.process.platform = g.process.platform || 'win32';
  g.process.env = g.process.env || {};
  g.process.cwd = typeof g.process.cwd === 'function' ? g.process.cwd : function cwd() {
    if (typeof g.__exactGetCwd === 'function') {
      var value = g.__exactGetCwd();
      if (typeof value === 'string' && value.length) return value;
    }
    return '.';
  };
  g.process.chdir = typeof g.process.chdir === 'function' ? g.process.chdir : function chdir(path) {
    if (typeof g.__exactSetCwd === 'function') {
      g.__exactSetCwd(String(path));
      return;
    }
    throw new Error('process.chdir is not available');
  };
  g.process.nextTick = typeof g.process.nextTick === 'function' ? g.process.nextTick : function nextTick(callback) {
    return queueMicrotask(callback);
  };
  g.process.exitCode = typeof g.process.exitCode === 'number' ? g.process.exitCode : 0;
  g.process.exit = typeof g.process.exit === 'function' ? g.process.exit : function exit(code) {
    var status = code == null ? g.process.exitCode || 0 : Number(code) || 0;
    g.process.exitCode = status;
    if (typeof g.__exactExit === 'function') {
      g.__exactExit(status);
    }
  };

  if (typeof g.Buffer !== 'function' && typeof require === 'function') {
    try {
      var bufferModule = require('buffer');
      if (bufferModule && typeof bufferModule.Buffer === 'function') {
        g.Buffer = bufferModule.Buffer;
      }
    } catch (_) {}
  }
  if (typeof g.crypto !== 'object' || g.crypto === null) {
    var exactRandomBytes = function(size) {
      size = Number(size) || 0;
      if (size < 0) size = 0;
      if (typeof g.__exactRandomBytes === 'function') {
        return g.__exactRandomBytes(size);
      }
      var fallback = new Uint8Array(size);
      for (var i = 0; i < fallback.length; i++) fallback[i] = Math.floor(Math.random() * 256) & 255;
      return fallback;
    };
    g.crypto = {
      getRandomValues: function(arr) {
        if (!arr || !ArrayBuffer.isView(arr)) {
          throw new TypeError('Expected an integer TypedArray');
        }
        var bytes = exactRandomBytes(arr.byteLength);
        var view = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
        for (var i = 0; i < view.length; i++) view[i] = bytes[i] || 0;
        return arr;
      },
      randomUUID: function() {
        var b = exactRandomBytes(16);
        b[6] = (b[6] & 15) | 64;
        b[8] = (b[8] & 63) | 128;
        var hex = '0123456789abcdef';
        var out = '';
        for (var i = 0; i < 16; i++) {
          if (i === 4 || i === 6 || i === 8 || i === 10) out += '-';
          out += hex[(b[i] >> 4) & 15] + hex[b[i] & 15];
        }
        return out;
      }
    };
  }

  function Headers(init) {
    this._entries = [];
    if (init instanceof Headers) {
      var source = init.entries();
      for (var s = 0; s < source.length; s++) this.append(source[s][0], source[s][1]);
    } else if (Array.isArray(init)) {
      for (var i = 0; i < init.length; i++) this.append(init[i][0], init[i][1]);
    } else if (init && typeof init === 'object') {
      for (var key in init) this.append(key, init[key]);
    }
  }
  Headers.prototype.append = function(name, value) {
    this._entries.push([String(name).toLowerCase(), String(value)]);
  };
  Headers.prototype.delete = function(name) {
    name = String(name).toLowerCase();
    this._entries = this._entries.filter(function(entry) { return entry[0] !== name; });
  };
  Headers.prototype.get = function(name) {
    name = String(name).toLowerCase();
    for (var i = this._entries.length - 1; i >= 0; i--) {
      if (this._entries[i][0] === name) return this._entries[i][1];
    }
    return null;
  };
  Headers.prototype.has = function(name) {
    return this.get(name) !== null;
  };
  Headers.prototype.set = function(name, value) {
    this.delete(name);
    this.append(name, value);
  };
  Headers.prototype.entries = function() {
    return this._entries.slice();
  };
  Headers.prototype.forEach = function(callback, thisArg) {
    for (var i = 0; i < this._entries.length; i++) callback.call(thisArg, this._entries[i][1], this._entries[i][0], this);
  };

  function URLSearchParams(init) {
    this._pairs = [];
    if (typeof init === 'string') {
      var value = init.charAt(0) === '?' ? init.slice(1) : init;
      if (value.length) {
        var parts = value.split('&');
        for (var i = 0; i < parts.length; i++) {
          if (!parts[i]) continue;
          var eq = parts[i].indexOf('=');
          var key = eq === -1 ? parts[i] : parts[i].slice(0, eq);
          var val = eq === -1 ? '' : parts[i].slice(eq + 1);
          this.append(decodeURIComponent(key.replace(/\+/g, ' ')), decodeURIComponent(val.replace(/\+/g, ' ')));
        }
      }
    } else if (Array.isArray(init)) {
      for (var a = 0; a < init.length; a++) this.append(init[a][0], init[a][1]);
    } else if (init && typeof init === 'object') {
      if (typeof init.entries === 'function') {
        var entries = init.entries();
        for (var next = entries.next(); !next.done; next = entries.next()) this.append(next.value[0], next.value[1]);
      } else {
        for (var name in init) this.append(name, init[name]);
      }
    }
  }
  URLSearchParams.prototype.append = function(name, value) { this._pairs.push([String(name), String(value)]); };
  URLSearchParams.prototype.delete = function(name) {
    name = String(name);
    this._pairs = this._pairs.filter(function(pair) { return pair[0] !== name; });
  };
  URLSearchParams.prototype.get = function(name) {
    name = String(name);
    for (var i = 0; i < this._pairs.length; i++) if (this._pairs[i][0] === name) return this._pairs[i][1];
    return null;
  };
  URLSearchParams.prototype.getAll = function(name) {
    name = String(name);
    var out = [];
    for (var i = 0; i < this._pairs.length; i++) if (this._pairs[i][0] === name) out.push(this._pairs[i][1]);
    return out;
  };
  URLSearchParams.prototype.has = function(name) {
    return this.get(name) !== null;
  };
  URLSearchParams.prototype.set = function(name, value) {
    this.delete(name);
    this.append(name, value);
  };
  URLSearchParams.prototype.entries = function() {
    var pairs = this._pairs.slice();
    var index = 0;
    return { next: function() { return index < pairs.length ? { value: pairs[index++], done: false } : { value: undefined, done: true }; } };
  };
  URLSearchParams.prototype.forEach = function(callback, thisArg) {
    for (var i = 0; i < this._pairs.length; i++) callback.call(thisArg, this._pairs[i][1], this._pairs[i][0], this);
  };
  URLSearchParams.prototype.toString = function() {
    return this._pairs.map(function(pair) {
      return encodeURIComponent(pair[0]).replace(/%20/g, '+') + '=' + encodeURIComponent(pair[1]).replace(/%20/g, '+');
    }).join('&');
  };

  function parseUrl(value, base) {
    var input = String(value);
    if (!/^[A-Za-z][A-Za-z0-9+.-]*:/.test(input) && base) {
      var baseUrl = new URL(base);
      if (input.charAt(0) === '/') {
        input = baseUrl.origin + input;
      } else {
        var dir = baseUrl.pathname.replace(/\/[^\/]*$/, '/');
        input = baseUrl.origin + dir + input;
      }
    }
    var match = input.match(/^([A-Za-z][A-Za-z0-9+.-]*:)(?:\/\/([^\/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/);
    if (!match) throw new TypeError('Invalid URL');
    var authority = match[2] || '';
    var hostname = authority;
    var port = '';
    if (authority.charAt(0) === '[') {
      var close = authority.indexOf(']');
      hostname = close === -1 ? authority : authority.slice(0, close + 1);
      if (close !== -1 && authority.charAt(close + 1) === ':') port = authority.slice(close + 2);
    } else {
      var colon = authority.lastIndexOf(':');
      if (colon !== -1) {
        hostname = authority.slice(0, colon);
        port = authority.slice(colon + 1);
      }
    }
    var pathname = match[3] || (authority ? '/' : '');
    return {
      protocol: match[1],
      host: authority,
      hostname: hostname,
      port: port,
      pathname: pathname,
      search: match[4] !== undefined ? '?' + match[4] : '',
      hash: match[5] !== undefined ? '#' + match[5] : ''
    };
  }
  function URL(value, base) {
    if (!(this instanceof URL)) return new URL(value, base);
    var parsed = parseUrl(value, base);
    this.protocol = parsed.protocol;
    this.hostname = parsed.hostname;
    this.port = parsed.port;
    this.pathname = parsed.pathname;
    this.search = parsed.search;
    this.hash = parsed.hash;
    this.searchParams = new URLSearchParams(this.search);
    this._sync();
  }
  URL.prototype._sync = function() {
    this.host = this.hostname + (this.port ? ':' + this.port : '');
    this.origin = this.protocol + '//' + this.host;
    this.href = this.origin + (this.pathname || '/') + (this.searchParams.toString() ? '?' + this.searchParams.toString() : this.search) + this.hash;
  };
  URL.prototype.toString = function() { this._sync(); return this.href; };
  URL.prototype.toJSON = URL.prototype.toString;

  function Blob(parts, options) {
    parts = parts || [];
    options = options || {};
    var chunks = [];
    var size = 0;
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      var bytes;
      if (typeof part === 'string') bytes = new TextEncoder().encode(part);
      else if (part instanceof ArrayBuffer) bytes = new Uint8Array(part);
      else if (ArrayBuffer.isView(part)) bytes = new Uint8Array(part.buffer, part.byteOffset, part.byteLength);
      else bytes = new TextEncoder().encode(String(part));
      chunks.push(bytes);
      size += bytes.byteLength;
    }
    this._chunks = chunks;
    this.size = size;
    this.type = options.type ? String(options.type).toLowerCase() : '';
  }
  Blob.prototype.arrayBuffer = function() {
    var out = new Uint8Array(this.size);
    var offset = 0;
    for (var i = 0; i < this._chunks.length; i++) {
      out.set(this._chunks[i], offset);
      offset += this._chunks[i].byteLength;
    }
    return Promise.resolve(out.buffer);
  };
  Blob.prototype.text = function() {
    return this.arrayBuffer().then(function(buffer) { return new TextDecoder().decode(buffer); });
  };
  Blob.prototype.slice = function(start, end, type) {
    var out = new Uint8Array(this.size);
    var offset = 0;
    for (var i = 0; i < this._chunks.length; i++) {
      out.set(this._chunks[i], offset);
      offset += this._chunks[i].byteLength;
    }
    return new Blob([out.slice(start || 0, end === undefined ? this.size : end)], { type: type || '' });
  };

  function FormData() { this._entries = []; }
  FormData.prototype.append = function(name, value, filename) { this._entries.push([String(name), value, filename]); };
  FormData.prototype.delete = function(name) {
    name = String(name);
    this._entries = this._entries.filter(function(entry) { return entry[0] !== name; });
  };
  FormData.prototype.get = function(name) {
    name = String(name);
    for (var i = 0; i < this._entries.length; i++) if (this._entries[i][0] === name) return this._entries[i][1];
    return null;
  };
  FormData.prototype.getAll = function(name) {
    name = String(name);
    var out = [];
    for (var i = 0; i < this._entries.length; i++) if (this._entries[i][0] === name) out.push(this._entries[i][1]);
    return out;
  };
  FormData.prototype.has = function(name) { return this.get(name) !== null; };
  FormData.prototype.set = function(name, value, filename) { this.delete(name); this.append(name, value, filename); };
  FormData.prototype.entries = function() {
    var entries = this._entries.map(function(entry) { return [entry[0], entry[1]]; });
    var index = 0;
    return { next: function() { return index < entries.length ? { value: entries[index++], done: false } : { value: undefined, done: true }; } };
  };
  FormData.prototype.forEach = function(callback, thisArg) {
    for (var i = 0; i < this._entries.length; i++) callback.call(thisArg, this._entries[i][1], this._entries[i][0], this);
  };

  function Request(input, init) {
    init = init || {};
    var source = input && typeof input === 'object' ? input : null;
    this.url = source && source.url ? String(source.url) : String(input);
    this.method = String(init.method || (source && source.method) || 'GET').toUpperCase();
    this.headers = new Headers(init.headers || (source && source.headers) || []);
    this._body = init.body !== undefined ? init.body : (source && source._body !== undefined ? source._body : null);
    this.signal = init.signal || (source && source.signal) || null;
  }

  function Response(body, init) {
    init = init || {};
    this.status = init.status == null ? 200 : init.status;
    this.statusText = init.statusText || '';
    this.url = init.url || '';
    this.redirected = !!init.redirected;
    this.ok = this.status >= 200 && this.status <= 299;
    this.headers = new Headers(init.headers || []);
    if (body == null) {
      this._body = new Uint8Array(0);
    } else if (typeof body === 'string') {
      this._body = new TextEncoder().encode(body);
    } else if (body instanceof Uint8Array) {
      this._body = body;
    } else if (body instanceof ArrayBuffer) {
      this._body = new Uint8Array(body);
    } else if (ArrayBuffer.isView(body)) {
      this._body = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    } else {
      this._body = new TextEncoder().encode(String(body));
    }
    this.bodyUsed = false;
  }
  Response.prototype.arrayBuffer = function() {
    this.bodyUsed = true;
    var copy = new Uint8Array(this._body.length);
    copy.set(this._body);
    return Promise.resolve(copy.buffer);
  };
  Response.prototype.text = function() {
    this.bodyUsed = true;
    return Promise.resolve(new TextDecoder().decode(this._body));
  };
  Response.prototype.json = function() {
    return this.text().then(function(text) { return JSON.parse(text); });
  };

  function responseFromNative(nativeResponse) {
    return new Response(nativeResponse.body, {
      status: nativeResponse.status,
      statusText: nativeResponse.statusText,
      headers: nativeResponse.headers,
      url: nativeResponse.url,
      redirected: nativeResponse.redirected
    });
  }

  function ExactEventTarget() {
    this.__listeners = {};
  }
  ExactEventTarget.prototype.addEventListener = function(type, listener) {
    if (typeof listener !== 'function') return;
    type = String(type);
    (this.__listeners[type] || (this.__listeners[type] = [])).push(listener);
  };
  ExactEventTarget.prototype.removeEventListener = function(type, listener) {
    type = String(type);
    var list = this.__listeners[type];
    if (!list) return;
    for (var i = 0; i < list.length; i++) {
      if (list[i] === listener) {
        list.splice(i, 1);
        return;
      }
    }
  };
  ExactEventTarget.prototype.dispatchEvent = function(event) {
    event.target = event.target || this;
    event.currentTarget = this;
    var handler = this['on' + event.type];
    if (typeof handler === 'function') {
      handler.call(this, event);
    }
    var list = this.__listeners[event.type];
    if (list) {
      list = list.slice();
      for (var i = 0; i < list.length; i++) {
        list[i].call(this, event);
      }
    }
    return true;
  };

  if (typeof g.WebSocket !== 'function' && typeof g.__exactWsConnect === 'function') {
    function ExactWebSocket(url, protocols) {
      if (!(this instanceof ExactWebSocket)) {
        throw new TypeError("Failed to construct 'WebSocket': Please use the 'new' operator");
      }
      ExactEventTarget.call(this);
      this.url = String(url);
      this.protocol = '';
      this.extensions = '';
      this.readyState = ExactWebSocket.CONNECTING;
      this.bufferedAmount = 0;
      this.binaryType = 'blob';
      this.onopen = null;
      this.onmessage = null;
      this.onerror = null;
      this.onclose = null;
      this._handleOpen = ExactWebSocket.prototype._handleOpen.bind(this);
      this._handleMessage = ExactWebSocket.prototype._handleMessage.bind(this);
      this._handleError = ExactWebSocket.prototype._handleError.bind(this);
      this._handleClose = ExactWebSocket.prototype._handleClose.bind(this);
      this._handleBytesSent = ExactWebSocket.prototype._handleBytesSent.bind(this);
      var protocolList = [];
      if (Array.isArray(protocols)) {
        protocolList = protocols.map(String);
      } else if (protocols !== undefined) {
        protocolList = [String(protocols)];
      }
      this.__id = g.__exactWsConnect(this.url, protocolList.join(','), this);
      if (typeof this.__id !== 'number') {
        this.__id = 0;
      }
    }
    ExactWebSocket.CONNECTING = 0;
    ExactWebSocket.OPEN = 1;
    ExactWebSocket.CLOSING = 2;
    ExactWebSocket.CLOSED = 3;
    ExactWebSocket.prototype = Object.create(ExactEventTarget.prototype);
    ExactWebSocket.prototype.constructor = ExactWebSocket;
    ExactWebSocket.prototype.CONNECTING = ExactWebSocket.CONNECTING;
    ExactWebSocket.prototype.OPEN = ExactWebSocket.OPEN;
    ExactWebSocket.prototype.CLOSING = ExactWebSocket.CLOSING;
    ExactWebSocket.prototype.CLOSED = ExactWebSocket.CLOSED;
    ExactWebSocket.prototype.send = function(data) {
      if (this.readyState !== ExactWebSocket.OPEN) {
        throw new Error('WebSocket is not open');
      }
      var payload = data;
      var bytes = 0;
      if (typeof data === 'string') {
        bytes = new TextEncoder().encode(data).byteLength;
      } else if (data instanceof ArrayBuffer) {
        payload = new Uint8Array(data);
        bytes = payload.byteLength;
      } else if (ArrayBuffer.isView(data)) {
        payload = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
        bytes = payload.byteLength;
      } else {
        payload = String(data);
        bytes = new TextEncoder().encode(payload).byteLength;
      }
      this.bufferedAmount += bytes;
      g.__exactWsSend(this.__id, payload);
    };
    ExactWebSocket.prototype.close = function(code, reason) {
      if (this.readyState === ExactWebSocket.CLOSED || this.readyState === ExactWebSocket.CLOSING) return;
      this.readyState = ExactWebSocket.CLOSING;
      if (this.__id) {
        g.__exactWsClose(this.__id, code == null ? 1005 : code, reason == null ? '' : String(reason));
      }
    };
    ExactWebSocket.prototype._handleOpen = function(protocol, extensions) {
      this.protocol = protocol || '';
      this.extensions = extensions || '';
      this.readyState = ExactWebSocket.OPEN;
      this.dispatchEvent({ type: 'open' });
    };
    ExactWebSocket.prototype._handleMessage = function(data) {
      this.dispatchEvent({ type: 'message', data: data });
    };
    ExactWebSocket.prototype._handleError = function(message) {
      this.dispatchEvent({ type: 'error', message: message || 'WebSocket error' });
      if (this.readyState !== ExactWebSocket.CLOSED) {
        this.readyState = ExactWebSocket.CLOSED;
        this.dispatchEvent({ type: 'close', code: 1006, reason: message || '', wasClean: false });
      }
    };
    ExactWebSocket.prototype._handleClose = function(code, reason, wasClean) {
      this.readyState = ExactWebSocket.CLOSED;
      this.dispatchEvent({ type: 'close', code: code, reason: reason || '', wasClean: !!wasClean });
    };
    ExactWebSocket.prototype._handleBytesSent = function(bytes) {
      this.bufferedAmount = Math.max(0, this.bufferedAmount - (bytes || 0));
    };
    g.WebSocket = ExactWebSocket;
  }

  if (typeof g.AbortController !== 'function') {
    function AbortSignal() {
      ExactEventTarget.call(this);
      this.aborted = false;
      this.reason = undefined;
    }
    AbortSignal.prototype = Object.create(ExactEventTarget.prototype);
    AbortSignal.prototype.constructor = AbortSignal;
    AbortSignal.prototype.throwIfAborted = function() {
      if (this.aborted) throw this.reason || new Error('The operation was aborted');
    };
    function AbortController() {
      this.signal = new AbortSignal();
    }
    AbortController.prototype.abort = function(reason) {
      if (this.signal.aborted) return;
      this.signal.aborted = true;
      this.signal.reason = reason || new Error('The operation was aborted');
      this.signal.dispatchEvent({ type: 'abort' });
    };
    g.AbortController = AbortController;
    g.AbortSignal = AbortSignal;
  }

  if (typeof g.__nativeFetchSync === 'function') {
    g.fetch = function fetch(input, init) {
      var request = input instanceof Request ? new Request(input, init) : new Request(input, init || {});
      return Promise.resolve().then(function() {
        if (request.signal && request.signal.aborted) {
          throw request.signal.reason || new Error('The operation was aborted');
        }
        var nativeUrl = request.url.replace(/^http:\/\/127\.0\.0\.1(?=[:\/]|$)/, 'http://localhost');
        var nativeInit = {
          method: request.method || 'GET',
          headers: request.headers instanceof Headers ? request.headers.entries() : [],
          decompress: !init || init.decompress !== false,
          timeout: init && init.timeout || 30000
        };
        var body = request._body == null
          ? null
          : (typeof request._body === 'string' ? new TextEncoder().encode(request._body) : request._body);
        var response = responseFromNative(g.__nativeFetchSync(nativeUrl, nativeInit, body));
        response.url = request.url;
        return response;
      });
    };
  }

  g.URL = URL;
  g.URLSearchParams = URLSearchParams;
  g.Blob = Blob;
  g.FormData = FormData;
  g.Headers = Headers;
  g.Request = Request;
  g.Response = Response;

  function exactToBytes(data) {
    if (typeof data === 'string') return new TextEncoder().encode(data);
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new TextEncoder().encode(String(data));
  }

  function exactDecode(bytes) {
    return new TextDecoder().decode(bytes);
  }

  function exactEnsureFs() {
    if (typeof g.__exactEnsureFs === 'function') {
      try { g.__exactEnsureFs(); } catch (_) {}
    }
  }

  function ExactFile(path, options) {
    this.name = String(path && typeof path === 'object' && path.pathname ? decodeURIComponent(path.pathname) : path);
    this.type = options && options.type || 'application/octet-stream';
  }
  Object.defineProperty(ExactFile.prototype, 'size', {
    get: function() {
      exactEnsureFs();
      try { return JSON.parse(g.__exactStat(this.name)).size || 0; } catch (_) { return 0; }
    }
  });
  Object.defineProperty(ExactFile.prototype, 'lastModified', {
    get: function() {
      exactEnsureFs();
      try { return JSON.parse(g.__exactStat(this.name)).mtime_ms || 0; } catch (_) { return 0; }
    }
  });
  ExactFile.prototype.text = function() {
    var name = this.name;
    exactEnsureFs();
    return Promise.resolve().then(function() { return exactDecode(g.__exactReadFile(name)); });
  };
  ExactFile.prototype.json = function() {
    return this.text().then(function(text) { return JSON.parse(text); });
  };
  ExactFile.prototype.arrayBuffer = function() {
    var name = this.name;
    exactEnsureFs();
    return Promise.resolve().then(function() {
      var bytes = g.__exactReadFile(name);
      var out = new Uint8Array(bytes.byteLength || bytes.length || 0);
      for (var i = 0; i < out.length; i++) out[i] = bytes[i];
      return out.buffer;
    });
  };
  ExactFile.prototype.bytes = function() {
    var name = this.name;
    exactEnsureFs();
    return Promise.resolve().then(function() { return g.__exactReadFile(name); });
  };
  ExactFile.prototype.exists = function() {
    var name = this.name;
    exactEnsureFs();
    return Promise.resolve().then(function() {
      try { g.__exactAccess(name, 0); return true; } catch (_) { return false; }
    });
  };
  ExactFile.prototype.stat = function() {
    var name = this.name;
    exactEnsureFs();
    return Promise.resolve().then(function() {
      try { return JSON.parse(g.__exactStat(name)); } catch (_) { return null; }
    });
  };
  ExactFile.prototype.slice = function(begin, end, type) {
    exactEnsureFs();
    var bytes = g.__exactReadFile(this.name);
    return new Blob([bytes.slice(begin || 0, end === undefined ? bytes.length : end)], { type: type || this.type });
  };
  ExactFile.prototype.writer = function() {
    var name = this.name;
    var started = false;
    return {
      write: function(data) {
        exactEnsureFs();
        var bytes = exactToBytes(data);
        if (!started || typeof g.__exactAppendFile !== 'function') {
          g.__exactWriteFile(name, bytes);
          started = true;
        } else {
          g.__exactAppendFile(name, bytes);
        }
        return bytes.length;
      },
      end: function() {},
      flush: function() {}
    };
  };
  ExactFile.prototype.toString = function() { return 'ExactFile("' + this.name + '")'; };

  var Exact = g.Exact || {};
  Exact.version = Exact.version || '0.1.0';
  Exact.platform = Exact.platform || 'cli';
  Exact.file = typeof Exact.file === 'function' ? Exact.file : function(path, options) {
    return new ExactFile(path, options);
  };
  Exact.write = typeof Exact.write === 'function' ? Exact.write : function(dest, data) {
    exactEnsureFs();
    return Promise.resolve().then(function() {
      var path = typeof dest === 'string' ? dest : dest.name;
      var bytes = exactToBytes(data);
      g.__exactWriteFile(path, bytes);
      return bytes.length;
    });
  };
  Exact.env = Exact.env || g.process.env;
  g.Exact = Exact;
  var Bun = g.Bun || Exact;
  Bun.file = typeof Bun.file === 'function' ? Bun.file : Exact.file;
  Bun.write = typeof Bun.write === 'function' ? Bun.write : Exact.write;
  Bun.env = Bun.env || g.process.env;
  Bun.fetch = typeof Bun.fetch === 'function' ? Bun.fetch : g.fetch;
  Bun.argv = Bun.argv || g.process.argv || [];
  Bun.main = Bun.main || (g.process.argv && g.process.argv[1]) || '';
  Bun.which = typeof Bun.which === 'function' ? Bun.which : function(cmd) {
    if (typeof cmd !== 'string' || !cmd) return null;
    if (typeof g.__exactWhich !== 'function' &&
        typeof g.__exactEnsureChildProcess === 'function') {
      try { g.__exactEnsureChildProcess(); } catch (_) {}
    }
    if (typeof g.__exactWhich === 'function') return g.__exactWhich(cmd);
    return null;
  };

  function normalizeBunCommand(cmd, opts) {
    var args;
    var options = opts || {};
    if (Array.isArray(cmd)) {
      args = cmd.slice();
    } else if (cmd && typeof cmd === 'object' && Array.isArray(cmd.cmd)) {
      args = cmd.cmd.slice();
      options = {};
      for (var key in cmd) if (key !== 'cmd') options[key] = cmd[key];
      if (opts) for (var key2 in opts) options[key2] = opts[key2];
    } else {
      throw new TypeError('Bun.spawn expects a command array or object with cmd');
    }
    if (!args.length) throw new TypeError('Bun.spawn command array must not be empty');
    return { args: args, options: options };
  }

  Bun.spawnSync = typeof Bun.spawnSync === 'function' ? Bun.spawnSync : function(cmd, opts) {
    var normalized = normalizeBunCommand(cmd, opts);
    var cp = require('node:child_process');
    var result = cp.spawnSync(normalized.args[0], normalized.args.slice(1), normalized.options);
    return {
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      exitCode: result.status == null ? -1 : result.status,
      success: result.status === 0
    };
  };
  Bun.spawn = typeof Bun.spawn === 'function' ? Bun.spawn : function(cmd, opts) {
    var result = Bun.spawnSync(cmd, opts);
    var stdout = result.stdout || '';
    var stderr = result.stderr || '';
    return {
      pid: 0,
      stdout: { text: function() { return Promise.resolve(String(stdout)); } },
      stderr: { text: function() { return Promise.resolve(String(stderr)); } },
      exited: Promise.resolve(result.exitCode),
      exitCode: result.exitCode,
      killed: false,
      kill: function() { return false; },
      ref: function() { return this; },
      unref: function() { return this; }
    };
  };

  function exactDecodeBase64(value) {
    if (!value) return new Uint8Array(0);
    if (typeof atob === 'function') {
      var binary = atob(String(value));
      var out = new Uint8Array(binary.length);
      for (var i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
      return out;
    }
    return new Uint8Array(0);
  }

  Bun.serve = typeof Bun.serve === 'function' ? Bun.serve : function(options) {
    if (!options || typeof options !== 'object') throw new TypeError('Bun.serve() expects an options object');
    var fetchHandler = options.fetch;
    if (typeof fetchHandler !== 'function') throw new TypeError('Bun.serve() requires a fetch handler function');
    if (typeof g.__exactHttpServe !== 'function' && typeof g.__exactEnsureHttp === 'function') {
      g.__exactEnsureHttp();
    }
    if (typeof g.__exactHttpServe !== 'function') throw new Error('HTTP server not available');
    var port = options.port == null ? 3000 : Number(options.port);
    var hostname = options.hostname == null ? '127.0.0.1' : String(options.hostname);
    var result = JSON.parse(g.__exactHttpServe(port, hostname));
    if (result.error) throw new Error(result.error);
    var serverId = result.id;
    var actualPort = result.port || port;
    var closed = false;

    function buildRequest(data) {
      var requestUrl = data.url || '/';
      if (requestUrl.indexOf('http://') !== 0 && requestUrl.indexOf('https://') !== 0) {
        requestUrl = 'http://' + (hostname === '0.0.0.0' ? 'localhost' : hostname) + ':' + actualPort + requestUrl;
      }
      var init = { method: data.method || 'GET', headers: data.headers || [] };
      if (data.hasBody && data.body) init.body = exactDecodeBase64(data.body);
      return new Request(requestUrl, init);
    }
    function sendResponse(requestId, response) {
      if (!(response instanceof Response)) response = new Response(response == null ? '' : String(response));
      var headers = [];
      response.headers.forEach(function(value, key) { headers.push([key, value]); });
      response.arrayBuffer().then(function(buffer) {
        g.__exactHttpRespond(serverId, requestId, response.status || 200, JSON.stringify(headers), new Uint8Array(buffer));
      }, function() {
        g.__exactHttpRespond(serverId, requestId, 500, JSON.stringify([['content-type', 'text/plain']]), new TextEncoder().encode('Internal Server Error'));
      });
    }
    function handleRequest(json) {
      var data;
      try { data = JSON.parse(json); } catch (_) { return; }
      var request;
      try { request = buildRequest(data); } catch (_) {
        sendResponse(data.id || 0, new Response('Bad Request', { status: 400 }));
        return;
      }
      Promise.resolve()
        .then(function() { return fetchHandler(request, server); })
        .then(function(response) { sendResponse(data.id || 0, response); })
        .catch(function(err) {
          var errorHandler = options.error;
          if (typeof errorHandler === 'function') {
            try {
              Promise.resolve(errorHandler(err)).then(function(response) {
                sendResponse(data.id || 0, response);
              }, function() {
                sendResponse(data.id || 0, new Response('Internal Server Error', { status: 500 }));
              });
              return;
            } catch (_) {}
          }
          sendResponse(data.id || 0, new Response('Internal Server Error', { status: 500 }));
        });
    }
    function poll() {
      if (closed) return;
      var handled = false;
      if (typeof g.__exactHttpPoll === 'function') {
        while (true) {
          var json = g.__exactHttpPoll(serverId);
          if (!json) break;
          handled = true;
          handleRequest(json);
        }
      }
      if (typeof g.__exactHttpWait === 'function') {
        g.__exactHttpWait(serverId, 1000).then(function(json) {
          if (json) handleRequest(json);
          if (!closed) setTimeout(poll, 0);
        }, function() {
          if (!closed) setTimeout(poll, 50);
        });
      } else {
        setTimeout(poll, handled ? 0 : 50);
      }
    }
    var server = {
      port: actualPort,
      hostname: hostname === '0.0.0.0' ? 'localhost' : hostname,
      url: new URL('http://' + (hostname === '0.0.0.0' ? 'localhost' : hostname) + ':' + actualPort + '/'),
      development: !!options.development,
      id: String(serverId),
      pendingRequests: 0,
      stop: function(force) {
        closed = true;
        if (typeof g.__exactHttpClose === 'function') g.__exactHttpClose(serverId, force ? 1 : 0);
      },
      reload: function(next) {
        if (next && typeof next.fetch === 'function') fetchHandler = next.fetch;
      },
      ref: function() { if (typeof g.__exactHttpSetRef === 'function') g.__exactHttpSetRef(serverId, 1); return server; },
      unref: function() { if (typeof g.__exactHttpSetRef === 'function') g.__exactHttpSetRef(serverId, 0); return server; },
      requestIP: function() { return null; },
      upgrade: function() { return false; },
      publish: function() {},
      fetch: fetchHandler
    };
    setTimeout(poll, 0);
    return server;
  };
  g.Bun = Bun;

  g.__exactRuntimeLoaded = true;
})(globalThis);"#;

/// Mark bytecode as incompatible with the embedded runtime.
/// Called from the engine layer when bytecode loading fails.
pub fn mark_bytecode_incompatible() {
    BYTECODE_INCOMPATIBLE.store(true, Ordering::Relaxed);
}

fn build_exec_argv(cli: &Cli) -> Vec<String> {
    let mut exec_argv = Vec::new();

    if cli.expose_internals {
        exec_argv.push("--expose-internals".to_string());
    }
    if let Some(stack_size) = &cli.stack_size {
        exec_argv.push(format!("--stack-size={stack_size}"));
    }
    if let Some(max_http_header_size) = cli.max_http_header_size {
        exec_argv.push(format!("--max-http-header-size={max_http_header_size}"));
    }
    if cli.inspect {
        exec_argv.push("--inspect".to_string());
    }
    if cli.inspect_wait {
        exec_argv.push("--inspect-wait".to_string());
    }
    if cli.inspect_open {
        exec_argv.push("--inspect-open".to_string());
    }
    if cli.inspect_pause {
        exec_argv.push("--inspect-pause".to_string());
    }
    if cli.keep_alive {
        exec_argv.push("--keep-alive".to_string());
    }
    if let Some(port) = cli.inspect_port {
        exec_argv.push(format!("--inspect-port={port}"));
    }
    if let Some(host) = &cli.inspect_host {
        exec_argv.push(format!("--inspect-host={host}"));
    }
    if let Ok(extra_exec_argv) = env::var("EXACT_COMPAT_EXEC_ARGV") {
        if let Ok(extra_args) = serde_json::from_str::<Vec<String>>(&extra_exec_argv) {
            exec_argv.extend(extra_args.into_iter().filter(|arg| !arg.is_empty()));
        }
    }

    exec_argv
}

fn read_raw_argv0(exec_path: &str) -> String {
    env::var("EXACT_RAW_ARGV0")
        .ok()
        .unwrap_or_else(|| env::args().next().unwrap_or_else(|| exec_path.to_string()))
}

fn normalize_candidate(candidate: impl AsRef<Path>) -> Option<String> {
    let candidate = candidate.as_ref();
    let path = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(candidate)
    };

    if path.exists() && path.is_file() {
        path.to_str().map(|path| path.to_string())
    } else {
        None
    }
}

fn resolve_exec_path(extra_candidates: &[&str]) -> String {
    env::var("EXACT_EXECUTABLE")
        .ok()
        .and_then(normalize_candidate)
        .or_else(|| {
            env::var("EXACT_COMPAT_EXECUTABLE")
                .ok()
                .and_then(normalize_candidate)
        })
        .or_else(|| {
            env::current_exe()
                .ok()
                .filter(|path| path.exists() && path.is_file())
                .and_then(|path| path.to_str().map(|path| path.to_string()))
        })
        .or_else(|| env::args().next().and_then(normalize_candidate))
        .or_else(|| normalize_candidate(".cargo-targets/main/debug/ibex"))
        .or_else(|| normalize_candidate(".cargo-targets/main/release/ibex"))
        .or_else(|| normalize_candidate("target/debug/ibex"))
        .or_else(|| normalize_candidate("target/release/ibex"))
        .or_else(|| extra_candidates.iter().find_map(normalize_candidate))
        .unwrap_or_else(|| "ibex".to_string())
}

/// Runtime wrapper that owns the engine and host configuration.
pub struct Runtime {
    engine: Arc<dyn Engine>,
    _host: Host,
    bundle_format: BundleFormat,
    exec_argv: Vec<String>,
    compat_modes: Vec<String>,
}

impl Runtime {
    /// Build a runtime from CLI configuration.
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let (host, armed_snapshot_digest) = build_host(cli)?;

        // Opt-in compat surfaces ride the env contract so the runtime bundle
        // sees them regardless of bootstrap ordering, and child spawns inherit
        // them. `__exactCompatModes` is also seeded in the preload for JS-side
        // introspection. Validate armed startup before this process-global
        // mutation so a rejected compatibility facade has no side effect.
        if cli.compat.as_deref() == Some("bun") {
            std::env::set_var("EXACT_COMPAT_BUN", "1");
        }
        crate::host::abi::install_host(host.clone());
        let engine = engine::create_engine(&cli.engine, armed_snapshot_digest.as_deref())?;

        // If the engine doesn't support ESM, fall back to CJS bundling.
        // Hermes evaluateJavaScript() only supports script mode, not ES modules.
        let bundle_format = if cli.bundle_format == BundleFormat::Esm
            && !engine.supports_feature(EngineFeature::EsmModules)
        {
            BundleFormat::Cjs
        } else {
            cli.bundle_format
        };

        Ok(Self {
            engine,
            _host: host,
            bundle_format,
            exec_argv: build_exec_argv(cli),
            compat_modes: cli.compat.iter().cloned().collect(),
        })
    }

    pub fn engine(&self) -> Arc<dyn Engine> {
        self.engine.clone()
    }

    pub async fn load_runtime(&self) -> Result<()> {
        let exec_path = resolve_exec_path(&[]);
        let raw_argv0 = env::var("EXACT_RAW_ARGV0")
            .ok()
            .unwrap_or_else(|| env::args().next().unwrap_or_else(|| exec_path.clone()));
        let exec_path_json = serde_json::to_string(&exec_path)
            .with_context(|| format!("Failed to serialize exec path {}", exec_path))?;
        let raw_argv0_json =
            serde_json::to_string(&raw_argv0).unwrap_or_else(|_| format!("\"{}\"", exec_path));
        let exec_argv_json =
            serde_json::to_string(&self.exec_argv).unwrap_or_else(|_| "[]".to_string());
        let compat_modes_json =
            serde_json::to_string(&self.compat_modes).unwrap_or_else(|_| "[]".to_string());
        let preload_bootstrap = format!(
            "\
            globalThis.__exactExecPath = {};\n\
            globalThis.__exactExecArgv = {};\n\
            globalThis.__exactRawArgv0 = {};\n\
            globalThis.__exactCompatModes = {};\n\
            if (Array.isArray(globalThis.__exactCompatModes) && \
                globalThis.__exactCompatModes.indexOf('bun') !== -1 && \
                !globalThis.Bun && globalThis.Exact) {{\n\
              globalThis.Bun = globalThis.Exact;\n\
            }}\n\
            if (typeof globalThis.__exactWhich === 'function') {{\n\
              if (globalThis.Exact) globalThis.Exact.which = globalThis.__exactWhich;\n\
              if (globalThis.Bun) globalThis.Bun.which = globalThis.__exactWhich;\n\
            }}\n\
            ",
            exec_path_json, exec_argv_json, raw_argv0_json, compat_modes_json
        );
        self.engine.eval_immediate(&preload_bootstrap).await?;
        if cfg!(windows) {
            self.engine
                .eval_immediate(WINDOWS_MINIMAL_RUNTIME_BOOTSTRAP)
                .await?;
            return Ok(());
        }

        self.engine.load_runtime().await
    }

    pub async fn eval(&self, code: &str) -> Result<Option<String>> {
        if cfg!(windows) {
            let code = normalize_hashbang_for_eval(code);
            let code = wrap_source_for_tla_eval(code, true);
            return self.engine.eval(&code).await;
        }

        let exec_path = resolve_exec_path(&[]);
        let exec_path_json = serde_json::to_string(&exec_path)
            .with_context(|| format!("Failed to serialize exec path {}", exec_path))?;
        let raw_argv0 = read_raw_argv0(&exec_path);
        let raw_argv0_json =
            serde_json::to_string(&raw_argv0).unwrap_or_else(|_| format!("\"{}\"", exec_path));
        let exec_argv_json =
            serde_json::to_string(&self.exec_argv).unwrap_or_else(|_| "[]".to_string());
        let exec_bootstrap = format!(
            "\
            globalThis.__exactExecPath = {};\n\
            globalThis.__exactExecArgv = {};\n\
            globalThis.__exactRawArgv0 = {};\n\
            if (typeof globalThis.process === 'object' && globalThis.process !== null) {{\n\
                if (!Array.isArray(globalThis.process.argv)) {{ globalThis.process.argv = [globalThis.__exactExecPath]; }}\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'execArgv', {{\n\
                        value: globalThis.__exactExecArgv || [],\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.execArgv = globalThis.__exactExecArgv || [];\n\
                }}\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'argv0', {{\n\
                        value: globalThis.__exactRawArgv0 || globalThis.__exactExecPath,\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.argv0 = globalThis.__exactRawArgv0 || globalThis.__exactExecPath;\n\
                }}\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'execPath', {{\n\
                        value: globalThis.__exactExecPath,\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.execPath = globalThis.__exactExecPath;\n\
                }}\n\
            }} else {{\n\
                globalThis.process = {{\n\
                    argv: [globalThis.__exactExecPath],\n\
                    execArgv: globalThis.__exactExecArgv || [],\n\
                    argv0: globalThis.__exactRawArgv0,\n\
                    execPath: globalThis.__exactExecPath\n\
                }};\n\
            }}\n\
            ",
            exec_path_json, exec_argv_json, raw_argv0_json
        );
        self.engine.eval_immediate(&exec_bootstrap).await?;
        self.engine.eval(code).await
    }

    pub async fn run_file_with_args(&self, file: &str, args: &[String]) -> Result<Option<String>> {
        // Use runtime module loader instead of bundling
        // This makes require() work and enables proper module resolution
        let absolute_path = std::fs::canonicalize(file)
            .with_context(|| format!("Failed to resolve file: {}", file))?;
        let absolute_path = normalize_windows_tool_path(absolute_path);
        let path_str = absolute_path.to_string_lossy();
        let exec_path = resolve_exec_path(&["ibex"]);
        let entry_path = match absolute_path.extension().and_then(|s| s.to_str()) {
            Some(ext)
                if matches!(
                    ext.to_ascii_lowercase().as_str(),
                    "mjs" | "js" | "cjs" | "ts" | "tsx" | "jsx" | "mts" | "cts"
                ) =>
            {
                prepare_entry_with_format(&path_str, self.bundle_format).await?
            }
            _ => absolute_path.clone(),
        };
        let entry_str = entry_path.to_string_lossy();

        let mut argv: Vec<String> = vec![exec_path.clone(), path_str.to_string()];
        argv.extend(args.iter().cloned());
        let argv_json = serde_json::to_string(&argv)
            .with_context(|| format!("Failed to serialize argv for file {}", file))?;
        let exec_path_json = serde_json::to_string(&exec_path)
            .with_context(|| format!("Failed to serialize exec path {}", exec_path))?;
        // Raw OS argv[0] - may differ from exec_path when argv0 option is used in spawn
        let raw_argv0 = read_raw_argv0(&exec_path);
        let raw_argv0_json =
            serde_json::to_string(&raw_argv0).unwrap_or_else(|_| format!("\"{}\"", exec_path));
        let exec_argv_json =
            serde_json::to_string(&self.exec_argv).unwrap_or_else(|_| "[]".to_string());
        // Tell the module loader the original source file path so that
        // __dirname/__filename and require.resolve work correctly even when
        // the entry is a bundle in the cache directory.
        let entry_file_json = serde_json::to_string(&path_str.to_string())
            .with_context(|| "Failed to serialize entry file path")?;
        let process_versions_code = format!(
            r#"var __exactIdentityVersions = {versions};
            if (typeof globalThis.process === 'object' && globalThis.process !== null) {{
                var __exactExistingVersions = globalThis.process.versions;
                if (!(__exactExistingVersions && typeof __exactExistingVersions === 'object')) {{
                    try {{
                        Object.defineProperty(globalThis.process, 'versions', {{
                            value: __exactIdentityVersions,
                            writable: true,
                            enumerable: true,
                            configurable: true
                        }});
                    }} catch (_) {{}}
                }}
                if (!globalThis.process.version) {{
                    globalThis.process.version = 'v' + __exactIdentityVersions.node;
                }}
            }}"#,
            versions = ibex_runtime::identity_generated::VERSIONS_JS_OBJECT,
        );
        let process_versions_code = process_versions_code.as_str();
        let compat_reapply_code = if std::env::var_os("EXACT_COMPAT_TEST").is_some() {
            "if (typeof globalThis.__exactReapplyCompatPolyfills === 'function') {\n\
                try { globalThis.__exactReapplyCompatPolyfills(); } catch (_) {}\n\
            }\n"
        } else {
            ""
        };
        let argv_code = format!(
            "\
            globalThis.__exactArgv = {};\n\
            globalThis.__exactExecArgv = {};\n\
            globalThis.__exactEntryFile = {};\n\
            globalThis.__exactExecPath = {};\n\
            globalThis.__exactRawArgv0 = {};\n\
            if (typeof globalThis.process === 'object' && globalThis.process !== null) {{\n\
                globalThis.process.argv = globalThis.__exactArgv;\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'execArgv', {{\n\
                        value: globalThis.__exactExecArgv || [],\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.execArgv = globalThis.__exactExecArgv || [];\n\
                }}\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'argv0', {{\n\
                        value: globalThis.__exactRawArgv0 || globalThis.__exactArgv[0] || '',\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.argv0 = globalThis.__exactRawArgv0 || globalThis.__exactArgv[0] || '';\n\
                }}\n\
                try {{\n\
                    Object.defineProperty(globalThis.process, 'execPath', {{\n\
                        value: globalThis.__exactExecPath,\n\
                        writable: true,\n\
                        configurable: true,\n\
                        enumerable: true\n\
                    }});\n\
                }} catch (_) {{\n\
                    globalThis.process.execPath = {};\n\
                }}\n\
            }} else {{\n\
                globalThis.process = {{ argv: globalThis.__exactArgv, execArgv: globalThis.__exactExecArgv || [], argv0: (globalThis.__exactRawArgv0 || globalThis.__exactArgv[0] || ''), execPath: {} }};\n\
            }}\n\
            {}\n\
            {}\n\
            ",
            argv_json,
            exec_argv_json,
            entry_file_json,
            exec_path_json,
            raw_argv0_json,
            exec_path_json,
            exec_path_json,
            process_versions_code,
            compat_reapply_code
        );
        // @ref LLP 0013#mechanism-3 — under per-package chunking the entry
        // bundle requires sibling chunk files (`__ibexpkg__*`) from the cache
        // dir. Tell the loader that dir so it can resolve those requires
        // absolutely, while the entry's own `__dirname`/`__filename` stay mapped
        // to the source (the loader only redirects the `__ibexpkg__` specifiers).
        let argv_code = if crate::env_flag_enabled("IBEX_PER_PACKAGE_CHUNKS") {
            let chunk_dir = entry_path
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let chunk_dir_json =
                serde_json::to_string(&chunk_dir).unwrap_or_else(|_| "\"\"".to_string());
            format!("globalThis.__exactChunkDir = {chunk_dir_json};\n{argv_code}")
        } else {
            argv_code
        };

        if cfg!(windows) {
            let source = tokio::fs::read_to_string(&entry_path)
                .await
                .with_context(|| format!("Failed to read file {}", entry_path.display()))?;
            let source = normalize_hashbang_for_eval(&source);
            let source = wrap_source_for_tla_eval(source, true);
            let code = format!("{argv_code}\n{source}");
            return self.engine.eval(&code).await;
        }

        // For .hbc bytecode files, set up argv then use engine.run_file() directly
        // since require() / module_loader uses read_to_string() which can't handle binary.
        let is_bytecode = entry_path.extension().and_then(|s| s.to_str()) == Some("hbc");
        if is_bytecode {
            self.engine.eval_immediate(&argv_code).await?;
            match self.engine.run_file(&entry_str).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    // Only a genuine load failure — the bytecode buffer was
                    // rejected before any of the program ran — may delete the
                    // cached .hbc and re-run from JS source. The engine
                    // reports an eval THROW through the same Err surface; it
                    // must propagate as-is, or every side effect the program
                    // already performed (stdout, writes, network) runs a
                    // second time and the still-valid cache is discarded on
                    // every future run. (ENG-23484)
                    // @ref LLP 0005#bytecode-precompilation-hermesc — entry
                    // bytecode falls back to source on LOAD failure only,
                    // unlike the always-fall-back startup bootstrap.
                    if !engine::hermes::is_bytecode_load_error(&format!("{e:#}")) {
                        return Err(e);
                    }
                    // Bytecode failed to load (version mismatch or corrupt).
                    // Mark bytecode as incompatible so we don't re-compile.
                    BYTECODE_INCOMPATIBLE.store(true, Ordering::Relaxed);
                    // Delete the stale .hbc and fall through to require() with JS source.
                    let _ = tokio::fs::remove_file(&entry_path).await;
                    // Derive the JS source path from bytecode source path.
                    // .hbc files can be produced from either a raw source (.ts)
                    // or a bundled output (.bundle.mjs/.bundle.js), so fallback
                    // must try a few likely source variants.
                    // The .hbc was produced by `entry.with_extension("hbc")`,
                    // so reversing that with `.with_extension("js")` etc.
                    // correctly reconstructs the original bundle path
                    // (e.g. foo.bundle.hbc → foo.bundle.js / foo.bundle.mjs).
                    let fallback_paths: Vec<std::path::PathBuf> = vec![
                        entry_path.with_extension("js"),
                        entry_path.with_extension("mjs"),
                        entry_path.with_extension("ts"),
                        entry_path.with_extension("tsx"),
                        entry_path.with_extension("jsx"),
                    ];

                    if let Some(js_path) = fallback_paths.iter().find(|p| p.exists()) {
                        let js_str = js_path.to_string_lossy().to_string();
                        let js_json = serde_json::to_string(&js_str).with_context(|| {
                            format!("Failed to serialize fallback path {}", js_str)
                        })?;
                        // Determine format from the actual file extension, not
                        // self.bundle_format, since TLA may have switched CJS→ESM.
                        let is_esm = js_path.extension().and_then(|e| e.to_str()) == Some("mjs");
                        return if is_esm {
                            self.run_entry_with_tla_shim(js_path, true).await
                        } else {
                            let fallback_code = format!("require({});", js_json);
                            self.engine.eval(&fallback_code).await
                        };
                    }
                    anyhow::bail!("Bytecode loading failed and no JS source fallback found");
                }
            }
        }

        // An entry that skipped the bundler (standalone runs) may still carry
        // top-level await, which the loader's CJS `require()` chain cannot
        // evaluate — both branches below must route it through the async
        // entry shim, which transpiles in-process and wraps.
        let entry_untranspiled_tla = entry_path == absolute_path && {
            let raw = tokio::fs::read_to_string(&entry_path)
                .await
                .unwrap_or_default();
            contains_top_level_await(&raw)
        };

        if !self.engine.supports_feature(EngineFeature::TopLevelAwait) {
            self.engine.eval_immediate(&argv_code).await?;

            let entry_is_esm = entry_path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("mjs"));
            if self.bundle_format == BundleFormat::Cjs && !entry_is_esm && !entry_untranspiled_tla {
                let entry_json = serde_json::to_string(&entry_str)
                    .with_context(|| format!("Failed to serialize path {}", path_str))?;
                let code = format!("require({});", entry_json);
                return self.engine.eval(&code).await;
            }

            return self.run_entry_with_tla_shim(&entry_path, true).await;
        }

        match self.bundle_format {
            BundleFormat::Cjs => {
                self.engine.eval_immediate(&argv_code).await?;

                // An entry that skipped the bundler (standalone runs) may
                // still carry top-level await, which the loader's CJS
                // `require()` chain cannot evaluate — route it through the
                // async entry shim, which transpiles in-process and wraps.
                if entry_untranspiled_tla {
                    return self.run_entry_with_tla_shim(&entry_path, true).await;
                }

                let entry_json = serde_json::to_string(&entry_str.to_string())
                    .with_context(|| format!("Failed to serialize path {}", path_str))?;
                let code = format!(
                    "\
                    require({});",
                    entry_json
                );

                // Load the file through the module system using require()
                self.engine.eval(&code).await
            }
            BundleFormat::Esm => {
                self.engine.eval_immediate(&argv_code).await?;
                self.engine.run_file(&entry_str).await
            }
        }
    }

    async fn run_entry_with_tla_shim(
        &self,
        entry_path: &Path,
        is_main_file: bool,
    ) -> Result<Option<String>> {
        let source = tokio::fs::read_to_string(entry_path)
            .await
            .with_context(|| format!("Failed to read JS source {}", entry_path.display()))?;
        // When the entry reaches this path untranspiled (standalone runs skip
        // the bundler), lower TS/ESM in-process before wrapping.
        let needs_lowering = entry_path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                matches!(
                    ext.to_ascii_lowercase().as_str(),
                    // review R3/R4: .mts/.cts crashed on raw types and .mjs/.js
                    // ESM entries got an undefined import.meta — all source
                    // extensions lower in-process before wrapping.
                    "ts" | "tsx" | "jsx" | "mts" | "cts" | "mjs" | "js"
                )
            });
        let source = if needs_lowering {
            ibex_runtime::module_loader::transpile::transpile_to_cjs(&source, entry_path)?
        } else {
            source
        };
        let source = std::borrow::Cow::Owned(source);
        let source = normalize_hashbang_for_eval(&source);

        // Check if the source needs the async IIFE wrapper.
        // We check for `await` as a keyword anywhere in the source (not just at
        // brace depth 0) because `await` inside top-level for/if/while blocks is
        // still TLA even though it's at brace depth > 0. The async IIFE wrapper
        // is harmless for code that doesn't use TLA, so false positives are fine.
        //
        // The run-the-file-raw fast path is only sound when NO lowering
        // happened: the shim check ran on the LOWERED source, and a lowered
        // entry's on-disk file may be raw ESM/TS that Hermes cannot parse in
        // script mode (a static-import .mjs with no TLA hit exactly this —
        // clean lowering, "no shim needed", then SyntaxError on the raw
        // imports). Once lowering happened, evaluate the lowered source; the
        // wrapper also supplies the module/exports/__filename/__dirname
        // bindings the swc CJS output references. (ENG-23484)
        if !needs_lowering && !source_needs_tla_shim(source.as_ref()) {
            let entry_str = entry_path.to_string_lossy().to_string();
            return self.engine.run_file(&entry_str).await;
        }

        let wrapped = wrap_entry_source_for_eval(source, is_main_file, needs_lowering);
        self.engine.eval(&wrapped).await
    }

    pub async fn start_inspector(&self, host: &str, port: u16) -> Result<()> {
        self.engine.start_inspector(host, port).await
    }

    pub async fn stop_inspector(&self) -> Result<()> {
        self.engine.stop_inspector().await
    }

    pub async fn wait_for_inspector(&self) -> Result<()> {
        self.engine.wait_for_inspector().await
    }

    pub async fn wait_for_debugger(&self) -> Result<()> {
        self.engine.wait_for_debugger().await
    }
}

/// Authenticate the immutable production snapshot before either the host or
/// Hermes can observe project code. The independently generated expected
/// identity is launcher input, not policy authority, and is discarded after
/// arming. @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
fn build_host(cli: &Cli) -> Result<(Host, Option<String>)> {
    use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
    use std::sync::Arc;

    match (&cli.capsec_armed_snapshot, &cli.capsec_arming_identity) {
        (None, None) => Ok((Host::new(build_host_config(cli)?), None)),
        (Some(_), None) | (None, Some(_)) => anyhow::bail!(
            "--capsec-armed-snapshot and --capsec-arming-identity must be provided together"
        ),
        (Some(snapshot_path), Some(identity_path)) => {
            if cli.inspect
                || cli.inspect_wait
                || cli.inspect_open
                || cli.inspect_pause
                || cli.inspect_port.is_some()
                || cli.inspect_host.is_some()
            {
                anyhow::bail!(
                    "armed capability startup closes inspector activation and configuration"
                );
            }
            if cli.compat.is_some() {
                anyhow::bail!("armed capability startup closes compatibility facades");
            }
            if cli.policy.is_some()
                || !cli.allow.is_empty()
                || !cli.deny.is_empty()
                || cli.allow_all
                || cli.allow_env_endowments
                || cli.capsec != crate::cli::CapSecMode::Auto
            {
                anyhow::bail!(
                    "armed capability startup cannot be combined with legacy policy, mode, allow, deny, allow-all, or environment-endowment overrides"
                );
            }
            let snapshot_bytes = std::fs::read(snapshot_path).with_context(|| {
                format!(
                    "failed to read armed capability snapshot {}",
                    snapshot_path.display()
                )
            })?;
            let identity_bytes = std::fs::read(identity_path).with_context(|| {
                format!(
                    "failed to read capsec arming identity {}",
                    identity_path.display()
                )
            })?;
            let identity_text = std::str::from_utf8(&identity_bytes)
                .context("capsec arming identity is not UTF-8")?;
            let identity_value = capsec_semantics::strict_json::parse_strict(identity_text)
                .context("invalid strict JSON in capsec arming identity")?;
            let expected: ExpectedArmingIdentity =
                serde_json::from_value(identity_value).context("invalid capsec arming identity")?;
            let snapshot = Arc::new(
                ArmedSnapshot::load(&snapshot_bytes, &expected)
                    .context("refused to arm capability snapshot")?,
            );
            let digest = snapshot.digest().as_str().to_owned();
            let host = Host::new_armed(
                HostConfig {
                    mode: crate::host::SecurityMode::Enforce,
                    ..Default::default()
                },
                snapshot,
            )
            .context("failed to construct armed capability host")?;
            Ok((host, Some(digest)))
        }
    }
}

/// Whether the policy path was explicitly configured (via `--policy` or the
/// `IBEX_POLICY`/`EXACT_POLICY` env), as opposed to the auto-discovered default.
/// An explicit-but-missing policy is a hard error; a missing default is not.
fn policy_is_explicit(cli: &Cli) -> bool {
    if cli.policy.is_some() {
        return true;
    }
    crate::runtime_env("IBEX_POLICY", "EXACT_POLICY")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

fn build_host_config(cli: &Cli) -> Result<HostConfig> {
    let policy_path = resolve_policy_path(cli);
    // Parse the policy artifact exactly ONCE per startup and thread the parsed
    // struct through mode resolution, readiness, endowments, and (via
    // HostConfig) Host::new — this path used to read + JSON-parse the same
    // file four times. (ENG-22644)
    let policy = load_policy_file(cli, policy_path.as_deref())?;
    let mode = resolve_security_mode(cli, policy.as_deref(), policy_path.as_deref())?;

    enable_isolation_prerequisites(mode);
    for line in check_capsec_readiness(
        mode,
        CapsecStage::Run,
        capsec_readiness(cli, policy.as_deref()),
        capsec_advisory_allowed(cli),
    )? {
        eprintln!("{line}");
    }
    apply_policy_endowments(policy.as_deref(), mode, cli.allow_env_endowments);

    Ok(HostConfig {
        mode,
        policy_path,
        policy,
        allow: cli.allow.clone(),
        deny: cli.deny.clone(),
        root_dir: None,
        allowed_hosts: None,
    })
}

/// Load + validate the policy artifact once. A configured policy that exists
/// but cannot be parsed FAILS CLOSED as an error: a malformed committed policy
/// (which may carry `mode: "enforce"`) must not silently degrade the run to
/// permissive. An explicitly configured policy that is missing is likewise an
/// error; only a MISSING auto-discovered default resolves to `None`.
/// (ENG-22620/ENG-22644)
fn load_policy_file(
    cli: &Cli,
    policy_path: Option<&Path>,
) -> Result<Option<std::sync::Arc<crate::host::policy::PolicyFile>>> {
    use crate::host::policy::PolicyFile;
    match policy_path {
        Some(p) if p.exists() => {
            let policy = PolicyFile::load(p)
                .with_context(|| format!("failed to load capability policy {}", p.display()))?;
            Ok(Some(std::sync::Arc::new(policy)))
        }
        Some(p) => {
            if policy_is_explicit(cli) {
                anyhow::bail!("capability policy {} not found", p.display());
            }
            Ok(None)
        }
        None => Ok(None),
    }
}

/// Resolve the effective `SecurityMode` from the CLI flags and the policy
/// artifact's declared `mode`. Shared by the run path (`build_host_config`) and
/// `ibex build` (`apply_build_isolation`) so a built artifact is chunked for
/// per-package attribution exactly when a run of the same app would enforce —
/// otherwise `ibex build` under an enforce policy silently emits a flat,
/// single-principal bundle. (ENG-22760)
fn resolve_security_mode(
    cli: &Cli,
    policy: Option<&crate::host::policy::PolicyFile>,
    policy_path: Option<&Path>,
) -> Result<crate::host::SecurityMode> {
    use crate::cli::CapSecMode;
    use crate::host::SecurityMode;

    // `policy` is the artifact `load_policy_file` parsed once for this
    // startup (ENG-22644); loading/parse failures already failed closed there
    // (ENG-22620). The declared mode reuses `SecurityMode::from_policy_str`
    // — the single source of truth for mode-string parsing (formerly duplicated
    // by `policy_declared_mode`). @ref LLP 0014#runtime-and-cli
    let declared_mode = match policy {
        Some(policy) => match policy.mode.as_deref() {
            None => None,
            Some(raw) => match SecurityMode::from_policy_str(raw) {
                Some(m) => Some(m),
                // Present but unrecognized (a typo like "enfore"): fail closed
                // rather than silently degrading an Auto run to permissive —
                // the same class ENG-22620 targets. (review follow-up)
                None => anyhow::bail!(
                    "capability policy {} declares an unrecognized mode {:?} \
                     (expected enforce | audit | permissive)",
                    policy_path
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<unknown>".to_string()),
                    raw
                ),
            },
        },
        None => None,
    };

    // Map CLI mode to host SecurityMode.
    // --allow-all overrides --capsec for backward compatibility.
    let mode = if cli.allow_all {
        SecurityMode::Permissive
    } else {
        // @ref LLP 0013#phase-1 — Audit maps to the log-but-proceed mode.
        match cli.capsec {
            CapSecMode::Permissive => SecurityMode::Permissive,
            CapSecMode::Audit => SecurityMode::Audit,
            CapSecMode::Enforce => SecurityMode::Enforce,
            // Default (no explicit --capsec): honor the policy artifact's declared
            // `mode` when it has one — the generated policy is the security config,
            // so `mode: "enforce"` takes effect without a redundant flag. Explicit
            // `--capsec permissive` (and `--allow-all`) still force Permissive.
            CapSecMode::Auto => declared_mode.unwrap_or(SecurityMode::Permissive),
        }
    };

    Ok(mode)
}

/// Apply the enforce/audit isolation prerequisite (per-package chunking) for the
/// `ibex build` path, mirroring what `build_host_config` does for a run. Without
/// this, a build under an enforce policy compiles a flat single-Domain bundle and
/// the resulting `.hbc`, run under `--capsec enforce`, attributes every
/// `node_modules` frame to the trusted root — the capability gate never fires for
/// a dependency. Returns the resolved mode (Enforce/Audit imply chunking).
/// @ref LLP 0013#mechanism-3 — (ENG-22760)
pub(crate) fn apply_build_isolation(cli: &Cli) -> Result<crate::host::SecurityMode> {
    let policy_path = resolve_policy_path(cli);
    let policy = load_policy_file(cli, policy_path.as_deref())?;
    let mode = resolve_security_mode(cli, policy.as_deref(), policy_path.as_deref())?;
    enable_isolation_prerequisites(mode);
    for line in check_capsec_readiness(
        mode,
        CapsecStage::Build,
        capsec_readiness(cli, policy.as_deref()),
        capsec_advisory_allowed(cli),
    )? {
        eprintln!("{line}");
    }
    Ok(mode)
}

/// Snapshot of the attribution prerequisites behind the capsec model at the
/// moment a run/build resolves its security mode (ENG-22884). Selecting
/// `enforce`/`audit` only changes host-boundary *decision* logic; whether those
/// decisions bind to real per-package principals depends on these
/// prerequisites, and nothing previously reported when they were missing.
/// @ref LLP 0013#mechanism-3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CapsecReadiness {
    /// Frame-derived attribution is compiled in: the linked Hermes exports
    /// `ex_hermes_vm_current_package_id`, so build.rs defined
    /// `EXACT_HAVE_FRAME_ATTRIBUTION` (cfg `exact_frame_attribution`). When
    /// false the engine falls back to native-callback / thread-local module-id
    /// attribution, which stored callbacks and patched prototypes can defeat.
    frame_attribution: bool,
    /// Per-package principal isolation state after
    /// `enable_isolation_prerequisites` has applied the enforce/audit default.
    package_isolation: PackageIsolation,
    /// Reachability hardening (Mechanism 1 lockdown / Mechanism 2 compartment
    /// withholding) requested for this process.
    lockdown: bool,
    /// The policy artifact declares a runtime-grant ceiling for dynamic
    /// permission prompts.
    dynamic_ceiling: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackageIsolation {
    /// Per-package chunking is on (the enforce/audit default): each bundled
    /// npm package gets its own chunk → Domain → principal.
    Enabled,
    /// The operator explicitly set `IBEX_PER_PACKAGE_CHUNKS=0`: bundled
    /// dependencies collapse into the trusted root principal, so the
    /// capability gate never fires for them. Only the unbundled loader path
    /// still attributes per package.
    DisabledByOperator,
}

/// Which pipeline stage is consulting readiness. A missing frame-attribution
/// bridge is a property of the *executing* engine, and a built `.hbc` may run
/// under a different (patched) engine — so it hard-fails only `Run` and warns
/// on `Build`. An explicitly disabled package layout is baked into the built
/// artifact, so it is a hard prerequisite at both stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapsecStage {
    Run,
    Build,
}

/// Gather the live readiness snapshot. Call after
/// `enable_isolation_prerequisites` so `IBEX_PER_PACKAGE_CHUNKS` reflects the
/// enforce/audit default; a remaining `0` is an explicit operator opt-out.
fn capsec_readiness(
    cli: &Cli,
    policy: Option<&crate::host::policy::PolicyFile>,
) -> CapsecReadiness {
    let package_isolation = match std::env::var("IBEX_PER_PACKAGE_CHUNKS") {
        Ok(v) if v.trim() == "0" => PackageIsolation::DisabledByOperator,
        _ => PackageIsolation::Enabled,
    };
    let dynamic_ceiling = policy
        .map(|policy| !policy.ceiling.is_empty())
        .unwrap_or(false);
    CapsecReadiness {
        frame_attribution: cfg!(exact_frame_attribution),
        package_isolation,
        lockdown: cli.lockdown
            || crate::env_flag_enabled("IBEX_LOCKDOWN")
            || crate::env_flag_enabled("IBEX_COMPARTMENTS"),
        dynamic_ceiling,
    }
}

/// The operator explicitly accepted advisory attribution under enforce
/// (`--capsec-allow-advisory`, or `IBEX_CAPSEC_ALLOW_ADVISORY=1` for spawned
/// children and wrapper scripts).
fn capsec_advisory_allowed(cli: &Cli) -> bool {
    cli.capsec_allow_advisory || crate::env_flag_enabled("IBEX_CAPSEC_ALLOW_ADVISORY")
}

/// ENG-22884 — decide whether the resolved capsec mode may proceed with the
/// observed readiness, and produce the stderr report lines. Enforce fails
/// closed when a hard attribution prerequisite is missing unless the operator
/// passed the advisory escape hatch; audit always proceeds but reports
/// conspicuously; permissive stays silent (capsec is not being claimed).
fn check_capsec_readiness(
    mode: crate::host::SecurityMode,
    stage: CapsecStage,
    readiness: CapsecReadiness,
    allow_advisory: bool,
) -> Result<Vec<String>> {
    use crate::host::SecurityMode;
    if mode == SecurityMode::Permissive {
        return Ok(Vec::new());
    }

    let report = format!(
        "capsec readiness: frame-attribution={} package-isolation={} lockdown={} dynamic-ceiling={}",
        if readiness.frame_attribution {
            "present"
        } else {
            "missing"
        },
        match readiness.package_isolation {
            PackageIsolation::Enabled => "per-package",
            PackageIsolation::DisabledByOperator => "disabled(IBEX_PER_PACKAGE_CHUNKS=0)",
        },
        if readiness.lockdown { "on" } else { "off" },
        if readiness.dynamic_ceiling {
            "configured"
        } else {
            "not-configured"
        },
    );

    // Hard prerequisites: enforce refuses to proceed without them (absent the
    // advisory escape hatch). Soft: always warn, never fail.
    let mut hard: Vec<String> = Vec::new();
    let mut soft: Vec<String> = Vec::new();
    if !readiness.frame_attribution {
        let detail = "frame-derived attribution (the linked Hermes engine lacks the \
                      ex_hermes_vm_current_package_id bridge, so attribution falls back to a \
                      forgeable thread-local module id)";
        match stage {
            CapsecStage::Run => hard.push(detail.to_string()),
            CapsecStage::Build => soft.push(format!(
                "this engine build lacks {detail}; running the built artifact under this \
                 engine's enforce mode will fail closed"
            )),
        }
    }
    if readiness.package_isolation == PackageIsolation::DisabledByOperator {
        hard.push(
            "per-package principal isolation (IBEX_PER_PACKAGE_CHUNKS=0: bundled dependencies \
             collapse into the trusted root principal)"
                .to_string(),
        );
    }
    if mode == SecurityMode::Enforce && !readiness.lockdown {
        soft.push(
            "capsec enforce is running without lockdown: shared intrinsics remain mutable, \
             so intrinsic-integrity attacks between packages are not defended"
                .to_string(),
        );
    }

    if hard.is_empty() && soft.is_empty() {
        return Ok(vec![report]);
    }

    if mode == SecurityMode::Enforce && !hard.is_empty() && !allow_advisory {
        anyhow::bail!(
            "capsec enforce requires attribution prerequisites this {} does not satisfy:\n  - {}\n{}\n\
             Refusing to present advisory attribution as enforcement. Pass --capsec-allow-advisory \
             (or hidden alias --allow-advisory-attribution), set IBEX_CAPSEC_ALLOW_ADVISORY=1 \
             to proceed anyway, or use --capsec audit.",
            match stage {
                CapsecStage::Run => "run",
                CapsecStage::Build => "build",
            },
            hard.join("\n  - "),
            report,
        );
    }

    let mode_label = if mode == SecurityMode::Enforce {
        "enforce"
    } else {
        "audit"
    };
    let mut lines = Vec::new();
    if !hard.is_empty() {
        lines.push(format!(
            "warning: capsec {mode_label} is proceeding with ADVISORY attribution — capability \
             decisions may attribute a dependency's access to the trusted root:"
        ));
        for item in &hard {
            lines.push(format!("warning:   missing prerequisite: {item}"));
        }
    }
    for item in soft {
        lines.push(format!("warning: {item}"));
    }
    lines.push(report);
    Ok(lines)
}

/// Enable the per-package **attribution** prerequisite that enforce/audit mode
/// implies (ENG-22681). Selecting enforce (via `--capsec enforce` or a policy
/// artifact's `mode: "enforce"`) only changes the host-boundary *decision*
/// logic; on its own it does not give a bundled dependency its own runtime
/// principal. A default flat bundle collapses to one Hermes Domain, so every
/// `node_modules` frame carries the trusted root principal and the capability
/// gate — which only bites non-root principals — never fires for a dependency.
/// That makes a generated enforce policy a footgun: it looks like enforcement
/// while a dependency's `fs`/`env`/network access is attributed to root.
///
/// So under enforce **and** audit we turn on per-package chunking (each npm
/// package becomes its own chunk → its own Domain → its own principal). An
/// explicit `IBEX_PER_PACKAGE_CHUNKS=0` is treated as advisory attribution by
/// `check_capsec_readiness`: audit warns, and enforce fails closed unless the
/// operator also passes `--capsec-allow-advisory`. This is the attribution
/// prerequisite the RFC's Mechanism 3 needs for a bundled app; the unbundled
/// loader path already attributes per package, and a bundler that is unavailable
/// degrades to that path, so this never hard-fails a run on its own. Set as an
/// env var (before engine boot and before bundling) so it reaches the bundler,
/// the bundle-cache key, and any spawned children uniformly.
///
/// Reachability hardening (Mechanism 1 lockdown + Mechanism 2 compartment
/// withholding) stays **opt-in** via `--lockdown`: freezing intrinsics is the
/// RFC's documented top compat risk (Risks §1) and is orthogonal to the
/// attribution footgun this closes — an ungranted package's dangerous op is
/// already denied at the host boundary once it is attributed to its own
/// principal. @ref LLP 0013#mechanism-3
fn enable_isolation_prerequisites(mode: crate::host::SecurityMode) {
    use crate::host::SecurityMode;
    if !matches!(mode, SecurityMode::Enforce | SecurityMode::Audit) {
        return;
    }
    // Respect an explicit operator choice here; the readiness gate decides
    // whether that choice is acceptable for the selected capsec mode.
    if std::env::var_os("IBEX_PER_PACKAGE_CHUNKS").is_none() {
        std::env::set_var("IBEX_PER_PACKAGE_CHUNKS", "1");
        eprintln!(
            "note: {} enables per-package isolation so bundled dependencies get \
             their own principal (opt out with IBEX_PER_PACKAGE_CHUNKS=0)",
            match mode {
                SecurityMode::Enforce => "capsec enforce",
                _ => "capsec audit",
            }
        );
    }
    // @ref LLP 0013 — §self-grant — under enforce the runtime package
    // self-grant surface (`Exact.setModuleCapabilities`, the `require({needs})`
    // channel) must not be reachable: grants come from the policy artifact. Audit
    // mode observes would-deny self-grant attempts while preserving permissive
    // behavior, so sealing is limited to enforce. (ENG-22695/ENG-22770)
    if mode == SecurityMode::Enforce {
        std::env::set_var("IBEX_SEAL_SELF_GRANT", "1");
    }
}

/// Compose the compartment endowment map from the policy artifact's
/// `packages.*.endow` lists into `IBEX_ENDOW` (`pkg:a,b;pkg2:c`) — the channel
/// the engine's compartment registry reads at boot — so the generated policy
/// drives Mechanism 2 end-to-end. Applied once per process, before engine boot.
///
/// Precedence depends on the effective mode (ENG-22684). The registry's
/// per-package parse is last-write-wins, so whichever `pkg:` group appears last
/// in the string wins:
///
/// - **Enforce / Audit (fail closed):** the policy artifact is the *sole*
///   endowment source. A pre-existing (ambient/operator/wrapper-set)
///   `IBEX_ENDOW` is dropped — never appended — so it cannot widen a package's
///   globals (`process`, `fetch`, `eval`, …) past what the reviewed artifact
///   grants. A stale value is cleared even when the policy contributes no
///   groups. The `--allow-env-endowments` development escape hatch restores the
///   append-merge. A dropped non-empty value is reported on stderr.
/// - **Permissive (dev/legacy):** keep the append-merge so `IBEX_ENDOW` stays a
///   usable ambient override, mirroring how `--capsec permissive`/`--allow-all`
///   already relax enforcement.
///
/// @ref LLP 0014#runtime-and-cli
fn apply_policy_endowments(
    policy: Option<&crate::host::policy::PolicyFile>,
    mode: crate::host::SecurityMode,
    allow_env: bool,
) {
    use crate::host::SecurityMode;
    static APPLIED: AtomicBool = AtomicBool::new(false);
    let fail_closed = matches!(mode, SecurityMode::Enforce | SecurityMode::Audit) && !allow_env;
    // `policy` is the once-parsed artifact from `load_policy_file` (ENG-22644);
    // an unreadable policy file already failed the run upstream, so there is no
    // silent-return path to double-report here anymore.
    let mut groups: Vec<String> = match policy {
        Some(policy) => policy
            .packages
            .iter()
            .filter_map(|(pkg, package_policy)| {
                let endow = package_policy.endow.as_ref()?;
                if endow.is_empty() {
                    None
                } else {
                    Some(format!("{}:{}", pkg, endow.join(",")))
                }
            })
            .collect(),
        None => Vec::new(),
    };
    groups.sort();

    // Under enforce/audit, the policy is the sole endowment source and a stale
    // ambient IBEX_ENDOW must be cleared even when the policy has no groups —
    // otherwise an inherited value would survive untouched. In permissive/hatch
    // mode with no policy groups there is nothing to compose, so leave any
    // ambient value in place.
    if groups.is_empty() && !fail_closed {
        return;
    }
    if APPLIED.swap(true, Ordering::SeqCst) {
        return;
    }

    let policy_value = groups.join(";");
    let existing = std::env::var("IBEX_ENDOW")
        .ok()
        .filter(|v| !v.trim().is_empty());

    let value = if fail_closed {
        if let Some(env) = &existing {
            eprintln!(
                "warning: IBEX_ENDOW ignored under enforce/audit mode (would widen \
                 compartment endowments: {env}); pass --allow-env-endowments to override"
            );
        }
        policy_value
    } else {
        // Permissive, or the explicit escape hatch: the ambient value keeps
        // precedence (appended last → wins the registry's per-package parse).
        match existing {
            Some(env) if policy_value.is_empty() => env,
            Some(env) => format!("{};{}", policy_value, env),
            None => policy_value,
        }
    };
    if value.is_empty() {
        std::env::remove_var("IBEX_ENDOW");
    } else {
        std::env::set_var("IBEX_ENDOW", value);
    }
}

fn resolve_policy_path(cli: &Cli) -> Option<PathBuf> {
    if let Some(path) = &cli.policy {
        return Some(path.clone());
    }

    if let Ok(path) =
        crate::runtime_env("IBEX_POLICY", "EXACT_POLICY").ok_or(std::env::VarError::NotPresent)
    {
        if !path.trim().is_empty() {
            return Some(PathBuf::from(path));
        }
    }

    default_policy_path()
}

fn default_policy_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|home| {
            home.join("Library")
                .join("Application Support")
                .join("Ibex")
                .join("policy.json")
        })
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(config_dir) = dirs::config_dir() {
            return Some(config_dir.join("ibex").join("policy.json"));
        }
        dirs::home_dir().map(|home| home.join(".config").join("ibex").join("policy.json"))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

pub async fn prepare_entry_with_format(
    entry: &str,
    bundle_format: BundleFormat,
) -> Result<PathBuf> {
    let path = PathBuf::from(entry);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let path = normalize_windows_tool_path(path);
    if !path.exists() {
        anyhow::bail!("Entry file not found: {}", path.display());
    }
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

    if ext.eq_ignore_ascii_case("hbc") {
        return Ok(path);
    }

    let is_compat_js_fixture =
        std::env::var_os("EXACT_COMPAT_TEST").is_some() && matches!(ext, "js" | "cjs" | "mjs");
    if is_compat_js_fixture {
        // Compatibility fixtures depend on the raw loader behavior and can
        // break when the entry file is pre-bundled before execution.
        return Ok(path);
    }

    let needs_bundle = matches!(
        ext,
        "ts" | "tsx" | "jsx" | "js" | "mjs" | "cjs" | "mts" | "cts"
    );
    if !needs_bundle {
        return Ok(path);
    }

    let cache_dir = runtime_cache_dir()?;
    let cache_key = bundle_cache_key(&path, bundle_format)?;
    let output = bundle_output_path(&cache_dir, &cache_key, bundle_format);

    if bundle_cache_is_fresh(&output, &path).await {
        // Bundle is cached. Try bytecode if not already known incompatible.
        if !BYTECODE_INCOMPATIBLE.load(Ordering::Relaxed)
            && crate::runtime_env("IBEX_NO_BYTECODE", "EX_NO_BYTECODE").is_none()
        {
            if let Ok(bytecode_path) = prepare_bytecode_entry(&output).await {
                return Ok(bytecode_path);
            }
        }
        return Ok(output);
    }

    tokio::fs::create_dir_all(&cache_dir).await?;

    // If the source uses top-level await and we're targeting CJS, use ESM instead.
    // Rolldown rejects TLA in CJS mode, but ESM handles it fine. The TLA shim in
    // run_file_with_args will wrap the ESM output in an async IIFE for Hermes.
    let effective_format = if bundle_format == BundleFormat::Cjs {
        let source = tokio::fs::read_to_string(&path).await.unwrap_or_default();
        if contains_top_level_await(&source) {
            BundleFormat::Esm
        } else {
            bundle_format
        }
    } else {
        bundle_format
    };

    // If format changed, recompute output path
    let output = if effective_format != bundle_format {
        let new_key = bundle_cache_key(&path, effective_format)?;
        bundle_output_path(&cache_dir, &new_key, effective_format)
    } else {
        output
    };

    let prepared = match run_bundler(&path, &output, effective_format).await {
        Ok(()) => output,
        Err(err) => {
            let err_msg = format!("{}", err);
            // If rolldown rejects TLA in CJS mode (e.g. await inside for/if/while
            // blocks that our heuristic missed), retry with ESM format.
            if effective_format == BundleFormat::Cjs && err_msg.contains("Top-level await") {
                let esm_key = bundle_cache_key(&path, BundleFormat::Esm)?;
                let esm_output = bundle_output_path(&cache_dir, &esm_key, BundleFormat::Esm);
                match run_bundler(&path, &esm_output, BundleFormat::Esm).await {
                    Ok(()) => esm_output,
                    Err(esm_err) => return Err(esm_err),
                }
            } else if needs_bundle {
                let mut context = serde_json::Map::new();
                context.insert(
                    "entry".to_string(),
                    serde_json::Value::String(path.display().to_string()),
                );
                context.insert(
                    "format".to_string(),
                    serde_json::Value::String(effective_format.as_str().to_string()),
                );
                context.insert(
                    "error".to_string(),
                    serde_json::Value::String(err.to_string()),
                );
                // Bundling is an optimization, never a requirement: a missing
                // bun/node runner is the normal standalone case. The
                // in-process loader pipeline takes over silently; real
                // bundler failures still warn.
                let missing_runner = err_msg.contains("required to run the bundler");
                agent_logs::record_bundler_log(
                    if missing_runner { "info" } else { "warn" },
                    format!(
                        "Bundler unavailable; using the in-process module pipeline. {}",
                        err
                    ),
                    Some(context),
                );
                if !missing_runner {
                    eprintln!(
                        "Warning: bundler failed ({}). Using the in-process module pipeline.",
                        err
                    );
                }
                path
            } else {
                return Err(err);
            }
        }
    };

    // Try to compile to bytecode for faster startup on subsequent runs.
    // Skip if we've already detected that hermesc produces incompatible bytecode,
    // or if bytecode is explicitly disabled.
    if BYTECODE_INCOMPATIBLE.load(Ordering::Relaxed)
        || crate::runtime_env("IBEX_NO_BYTECODE", "EX_NO_BYTECODE").is_some()
    {
        return Ok(prepared);
    }
    match prepare_bytecode_entry(&prepared).await {
        Ok(bytecode_path) => Ok(bytecode_path),
        Err(_err) => {
            // hermesc not available or compilation failed — run JS source directly
            Ok(prepared)
        }
    }
}

fn deps_manifest_path(output: &Path) -> PathBuf {
    PathBuf::from(format!("{}.deps.json", output.display()))
}

/// A cached bundle is fresh only when its dependency manifest exists and no
/// module in the recorded graph — nor the entry itself — is newer than the
/// bundle output. Missing or unreadable manifests are stale, so caches
/// produced before the manifest existed rebuild exactly once.
async fn bundle_cache_is_fresh(output: &Path, entry: &Path) -> bool {
    let Ok(out_meta) = tokio::fs::metadata(output).await else {
        return false;
    };
    let Ok(out_time) = out_meta.modified() else {
        return false;
    };

    match tokio::fs::metadata(entry).await {
        Ok(meta) => match meta.modified() {
            Ok(entry_time) if entry_time <= out_time => {}
            _ => return false,
        },
        Err(_) => return false,
    }

    let Ok(raw) = tokio::fs::read_to_string(deps_manifest_path(output)).await else {
        return false;
    };
    let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    let Some(deps) = manifest.get("deps").and_then(|deps| deps.as_array()) else {
        return false;
    };

    for dep in deps.iter().filter_map(|dep| dep.as_str()) {
        // A deleted or unreadable dependency invalidates the cache too.
        let Ok(meta) = tokio::fs::metadata(dep).await else {
            return false;
        };
        let Ok(dep_time) = meta.modified() else {
            return false;
        };
        if dep_time > out_time {
            return false;
        }
    }

    true
}

async fn prepare_bytecode_entry(entry: &Path) -> Result<PathBuf> {
    let hbc_path = entry.with_extension("hbc");
    if hbc_path.exists() {
        let entry_meta = tokio::fs::metadata(entry).await;
        let hbc_meta = tokio::fs::metadata(&hbc_path).await;
        if let (Ok(entry_meta), Ok(hbc_meta)) = (entry_meta, hbc_meta) {
            if let (Ok(entry_modified), Ok(hbc_modified)) =
                (entry_meta.modified(), hbc_meta.modified())
            {
                if hbc_modified > entry_modified {
                    return Ok(hbc_path);
                }
            }
        }
    }

    engine::hermes::compile_to_bytecode(&entry.to_string_lossy(), &hbc_path, None).await?;

    Ok(hbc_path)
}

fn normalize_hashbang_for_eval(source: &str) -> Cow<'_, str> {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let has_source_mapping_url = source.contains("sourceMappingURL=");
    if !source.starts_with("#!") && !has_source_mapping_url {
        return Cow::Borrowed(source);
    }

    let mut normalized = String::with_capacity(source.len());
    for (index, line) in source.split_inclusive('\n').enumerate() {
        if index == 0 && line.starts_with("#!") {
            normalized.push_str("//");
            normalized.push_str(&line[2..]);
            continue;
        }

        // Strip a sourceMappingURL comment only when the whole line is that
        // comment (leading whitespace aside) — that is the only position this
        // textual scan can prove is a comment. A mid-line match is NOT
        // provably one: `out.push("//# sourceMappingURL=" + url);` is code
        // that GENERATES sourcemap comments, and truncating at the marker
        // corrupted such source into a syntax error (ENG-23484).
        // Under-stripping merely leaves a stale sourcemap pointer behind,
        // which is harmless by comparison.
        let trimmed = line.trim_start();
        if trimmed.starts_with("//#") && trimmed.contains("sourceMappingURL=") {
            if line.ends_with('\n') {
                normalized.push('\n');
            }
            continue;
        }

        normalized.push_str(line);
    }
    Cow::Owned(normalized)
}

fn normalize_windows_tool_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let value = path.to_string_lossy();
        if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = value.strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }
    }
    path
}

fn source_needs_tla_shim(source: &str) -> bool {
    // String/comment-aware: `await` inside a string literal (or a comment)
    // must not trigger the wrapper. The dynamic-import check stays a
    // substring match: the wrapper rewrite is required whenever a real
    // `import(` exists, and a false positive only costs a harmless wrap.
    contains_await_keyword(source) || source.contains("import(")
}

fn wrap_source_for_tla_eval(source: Cow<'_, str>, is_main_file: bool) -> String {
    wrap_source_for_tla_eval_with(source, is_main_file, false)
}

/// `already_lowered` marks swc output from the in-process pipeline: its
/// imports, `import.meta`, and dynamic `import()` are already CJS, so the
/// legacy string rewrites must not touch it (review R2 — they corrupted
/// string literals and identifiers like `reimport(`). The rewrites survive
/// only for rolldown ESM bundle outputs (Implementation Notes deferral 10).
fn wrap_source_for_tla_eval_with(
    source: Cow<'_, str>,
    is_main_file: bool,
    already_lowered: bool,
) -> String {
    if !source_needs_tla_shim(source.as_ref()) {
        return source.into_owned();
    }
    wrap_entry_source_for_eval(source, is_main_file, already_lowered)
}

/// Unconditionally wrap an entry source in the async-IIFE eval shim. Callers
/// that may pass source needing no shim at all should go through
/// `wrap_source_for_tla_eval_with`, which passes such source through
/// untouched. `run_entry_with_tla_shim` calls this directly for every lowered
/// entry — even one with no TLA — because bare eval of swc's CJS output lacks
/// the `module`/`exports`/`__filename`/`__dirname` bindings the wrapper's IIFE
/// parameters supply, and the async wrap is harmless for non-TLA code.
/// (ENG-23484)
fn wrap_entry_source_for_eval(
    source: Cow<'_, str>,
    is_main_file: bool,
    already_lowered: bool,
) -> String {
    let transformed = if already_lowered {
        source.into_owned()
    } else {
        let mut transformed = if source.contains("import ") || source.contains("export ") {
            transpile_esm_to_script(source.as_ref())
        } else {
            source.into_owned()
        };
        transformed = transformed.replace("import.meta", "globalThis.__exactImportMeta");
        transformed = transformed.replace("import(", "globalThis.require(");
        transformed
    };

    // `__filename`/`__dirname` are IIFE *parameters* (not a prelude inside the
    // body) so a leading "use strict" directive in the source stays the first
    // statement of the function body. The bundler's `define` lowers
    // `import.meta.url` to a `__filename`-based expression that only the CJS
    // module wrapper used to provide — evaluating the ESM/TLA output without
    // these bindings was ledger item 1 (`ReferenceError: __filename`).
    // `module`/`exports` bindings let in-process-lowered CJS entries run
    // under the same wrap; an entry's own exports are discarded, matching
    // `require(entry)` semantics.
    format!(
        "globalThis.__exactImportMeta = globalThis.__exactImportMeta || {{}};\n\
         globalThis.__exactImportMeta.main = {};\n\
         (async function(__filename, __dirname, module, exports) {{\n{}\n}})(\
         (typeof globalThis.__exactEntryFile === 'string' ? globalThis.__exactEntryFile : ''), \
         (function (p) {{ var s = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\\\')); return s > 0 ? p.slice(0, s) : p; }})\
         (typeof globalThis.__exactEntryFile === 'string' ? globalThis.__exactEntryFile : ''), \
         {{ exports: {{}} }}, {{}});",
        if is_main_file { "true" } else { "false" },
        transformed
    )
}

/// String-, comment-, and regex-aware scan for an `await` keyword anywhere in
/// the source. Any depth counts: `await` inside top-level `for`/`if` blocks is
/// still TLA, and wrapping non-TLA async code is harmless, so no brace tracking
/// is needed — only literals, comments, and regex literals are excluded.
///
/// Identifiers are consumed as whole words so `await` is matched only on a word
/// boundary (`awaited`/`awaitTime`/`kawaii` are not TLA). A `/` is disambiguated
/// between a regex literal and a division operator by tracking whether the
/// previous significant token was value-producing: without this, `await` inside
/// a regex literal (`var re = /await/g`) was read as a real keyword, so the REPL
/// wrapped the line in an async IIFE and the `var`/function binding no longer
/// leaked to the global object — a silent regression of the bug ENG-22957
/// aimed to close. (ENG-23031)
///
/// Shared with the REPL so `.time`/prompt input use the same detection instead
/// of a raw `contains("await")`. (ENG-22957)
pub(crate) fn contains_await_keyword(source: &str) -> bool {
    scan_for_await_keyword(source, false)
}

/// Like `contains_await_keyword`, but only reports `await` at brace depth 0
/// (true top-level): `await` inside functions, methods, or class bodies is not
/// top-level await. Used to pick the bundle format and to route untranspiled
/// entries / `-e` code through the TLA shim.
///
/// Built on the same string-, comment-, and regex-aware scanner as
/// `contains_await_keyword`: the previous standalone implementation was not
/// regex-aware, so a depth-0 regex literal containing `await` (e.g.
/// `const RE = /(await)/;`) flipped the bundle format CJS→ESM and re-routed
/// execution of a perfectly valid app (ENG-23484; scanner-level fix mirrors
/// ENG-23031's for `contains_await_keyword`).
pub(crate) fn contains_top_level_await(source: &str) -> bool {
    scan_for_await_keyword(source, true)
}

/// The shared scanner behind `contains_await_keyword` (any depth) and
/// `contains_top_level_await` (`top_level_only`, brace depth 0 with an
/// `await:` label exclusion). See `contains_await_keyword` for the tokenizer
/// rationale.
fn scan_for_await_keyword(source: &str, top_level_only: bool) -> bool {
    let bytes = source.as_bytes();
    let mut i = 0usize;
    // Whether a `/` here begins a regex literal (value position) rather than a
    // division operator. True at input start and after operators/punctuators
    // that expect an expression; false after a value token (identifier, `)`,
    // `]`, number, string, regex).
    let mut regex_allowed = true;
    // Brace depth for `top_level_only`: braces inside strings, comments, and
    // regex literals are consumed by their opaque spans and never counted.
    let mut brace_depth: i32 = 0;

    while i < bytes.len() {
        let b = bytes[i];

        // Whitespace never produces a value, so it must not disturb
        // `regex_allowed` (`a /b/` is division, not a regex after the space).
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c') {
            i += 1;
            continue;
        }

        // Comments: skip without changing the previous significant token.
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }

        // String / template literal: opaque span. Template interpolation is not
        // inspected (matching the prior scanner); a literal is a value, so a
        // following `/` is division.
        if b == b'\'' || b == b'"' || b == b'`' {
            let quote = b;
            i += 1;
            while i < bytes.len() {
                let c = bytes[i];
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                i += 1;
                if c == quote {
                    break;
                }
            }
            regex_allowed = false;
            continue;
        }

        // Regex literal in value position: skip `/…/flags`, honoring escapes and
        // `[…]` character classes (which may contain an unescaped `/`).
        if b == b'/' && regex_allowed {
            i += 1;
            let mut in_class = false;
            while i < bytes.len() {
                let c = bytes[i];
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == b'\n' {
                    break; // unterminated literal; stop scanning it
                }
                i += 1;
                match c {
                    b'[' => in_class = true,
                    b']' => in_class = false,
                    b'/' if !in_class => break,
                    _ => {}
                }
            }
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1; // regex flags
            }
            regex_allowed = false;
            continue;
        }

        // Identifier / keyword.
        if b == b'_' || b == b'$' || b.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && is_ident_byte(bytes[i]) {
                i += 1;
            }
            if &source[start..i] == "await"
                // Top-level mode: only depth 0 counts, and `await:` is a
                // label (in sloppy scripts `await` is not reserved), not TLA.
                && (!top_level_only || (brace_depth == 0 && bytes.get(i) != Some(&b':')))
            {
                return true;
            }
            // After a value identifier `/` is division; after a keyword that
            // expects an expression it starts a regex.
            regex_allowed = keyword_precedes_expression(&source[start..i]);
            continue;
        }

        // Braces: track depth for `top_level_only`. Both act like the generic
        // punctuation below for regex disambiguation (a `/` after `{` or `}`
        // starts a regex, matching the prior scanner behavior).
        if b == b'{' {
            brace_depth += 1;
            regex_allowed = true;
            i += 1;
            continue;
        }
        if b == b'}' {
            brace_depth -= 1;
            regex_allowed = true;
            i += 1;
            continue;
        }

        // Numeric literal: a value, so a following `/` is division. Consuming a
        // little loosely (digits, `.`, exponent/hex letters) is fine — we only
        // need `regex_allowed` to end up false.
        if b.is_ascii_digit() {
            i += 1;
            while i < bytes.len() && (is_ident_byte(bytes[i]) || bytes[i] == b'.') {
                i += 1;
            }
            regex_allowed = false;
            continue;
        }

        // Any other punctuation/operator. A `/` after a closing `)`/`]` is
        // division; after everything else (`= , ( { [ ! ? : ; + - * % < > & | ^`)
        // it starts a regex.
        regex_allowed = !matches!(b, b')' | b']');
        i += 1;
    }
    false
}

/// Keywords after which a `/` begins a regex literal rather than division,
/// because they syntactically expect an expression to follow. (ENG-23031)
fn keyword_precedes_expression(word: &str) -> bool {
    matches!(
        word,
        "return"
            | "typeof"
            | "instanceof"
            | "in"
            | "of"
            | "new"
            | "delete"
            | "void"
            | "do"
            | "else"
            | "yield"
            | "await"
            | "case"
            | "throw"
    )
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn hash_path_metadata<H: Hasher>(hasher: &mut H, path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(modified) = meta.modified() {
            if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                duration.as_nanos().hash(hasher);
            }
        }
        meta.len().hash(hasher);
    }
}

fn hash_file_contents<H: Hasher>(hasher: &mut H, path: &Path) -> Result<()> {
    path.hash(hasher);
    let bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read bundle cache input {}", path.display()))?;
    bytes.hash(hasher);
    Ok(())
}

fn bundler_cache_input_paths() -> Vec<PathBuf> {
    // Outside a checkout there is no bundler to run and no scripts to hash;
    // the cache key must not require a repo.
    let Ok(root) = repo_root() else {
        return Vec::new();
    };
    vec![
        root.join("packages")
            .join("ibex-devtools")
            .join("src")
            .join("scripts")
            .join("rolldown-bundle.mjs"),
        root.join("packages")
            .join("ibex-devtools")
            .join("src")
            .join("scripts")
            .join("transforms.mjs"),
        // @ref LLP 0019#consequences — ENG-22987: the canonical Hermes-compat transforms
        // (for-of scoping, exponentiation, BigInt, async generators) moved out
        // of transforms.mjs into hermes-compat.mjs, which transforms.mjs now
        // re-exports. The bundle cache must hash the file the logic actually
        // lives in, or an edit to the transform semantics would not invalidate
        // cached bundles.
        root.join("packages")
            .join("ibex-devtools")
            .join("src")
            .join("scripts")
            .join("hermes-compat.mjs"),
        // @ref LLP 0014#parse-and-strip — the grant-attribute strip runs in
        // every bundle; its logic changing must invalidate cached bundles.
        root.join("packages")
            .join("ibex-devtools")
            .join("src")
            .join("scripts")
            .join("import-grants.mjs"),
    ]
}

fn bundle_cache_key(entry: &Path, bundle_format: BundleFormat) -> Result<String> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    "bundle-cache-v6-deps-manifest".hash(&mut hasher);
    bundle_format.as_str().hash(&mut hasher);
    // @ref LLP 0013#mechanism-2 — a compartmentalized bundle references the
    // `__compartments` registry, which only exists under lockdown/compartments.
    // It MUST NOT be reused for a non-compartment run (the reference would throw
    // ReferenceError), nor vice versa. Fold the state into the cache key so the
    // two variants are cached under distinct paths. This mirrors the same signal
    // `run_bundler` uses to pass `--compartments`.
    // Resolve with the same truthiness parse the engine uses (ENG-22634), and
    // key the cache on that resolved bool so a compartmentalized bundle can never
    // be reused for a non-compartment run (or vice versa).
    let compartments =
        crate::env_flag_enabled("IBEX_LOCKDOWN") || crate::env_flag_enabled("IBEX_COMPARTMENTS");
    compartments.hash(&mut hasher);
    // @ref LLP 0013#mechanism-3 — per-package chunking changes the output shape
    // (multiple chunk files), so it must key distinctly from a flat bundle. Use
    // the same truthiness parse as the other two read sites so `=0` is a real
    // opt-out and the cache key agrees with what the bundler actually emitted.
    crate::env_flag_enabled("IBEX_PER_PACKAGE_CHUNKS").hash(&mut hasher);
    hash_file_contents(&mut hasher, entry)?;

    for bundler_input in bundler_cache_input_paths() {
        hash_file_contents(&mut hasher, &bundler_input)?;
    }

    if let Some(parent) = entry.parent() {
        let mut current = Some(parent);
        let mut depth = 0;
        while let Some(dir) = current {
            hash_path_metadata(&mut hasher, dir);
            depth += 1;
            current = if depth >= 2 { None } else { dir.parent() };
        }
    }
    Ok(format!("{:x}", hasher.finish()))
}

fn bundle_file_ext(format: BundleFormat) -> &'static str {
    match format {
        BundleFormat::Cjs => "js",
        BundleFormat::Esm => "mjs",
    }
}

/// Where a bundle's entry file lands in the cache. A flat bundle is a single
/// file named by the cache key. A per-package-chunked bundle also emits sibling
/// chunk files (`__ibexpkg__*`, and the shared `rolldown-runtime.js`) into the
/// entry's directory with **fixed, cross-bundle names** — so it gets its own
/// per-key subdirectory, otherwise two concurrently-bundled apps race on the
/// shared `rolldown-runtime.js` name and corrupt each other's cache (a real
/// hazard for concurrent `ibex run` of different apps, surfaced once enforce
/// began auto-enabling chunking — ENG-22681). @ref LLP 0013#mechanism-3
fn bundle_output_path(cache_dir: &Path, key: &str, format: BundleFormat) -> PathBuf {
    let ext = bundle_file_ext(format);
    if crate::env_flag_enabled("IBEX_PER_PACKAGE_CHUNKS") {
        cache_dir.join(key).join(format!("bundle.{}", ext))
    } else {
        cache_dir.join(format!("{}.bundle.{}", key, ext))
    }
}

/// Copy the per-package chunk siblings a chunked bundle emitted — the
/// `__ibexpkg__*` package chunks and the shared `rolldown-runtime.js` — from the
/// bundle entry's directory into `dest_dir`. A flat `.hbc` produced by
/// `ibex build` lives away from its cache-dir chunks; the run path sets
/// `__exactChunkDir` to the artifact's own directory, so the chunks must sit next
/// to the built `.hbc` or the entry's `require('__ibexpkg__…')` fails to resolve.
/// The copied set is exactly what the loader's chunk-redirect recognizes
/// (module-loader.js). Returns the number of chunk files copied. (ENG-22760)
/// @ref LLP 0013#mechanism-3
pub(crate) fn ship_chunk_siblings(bundle_entry: &Path, dest_dir: &Path) -> Result<usize> {
    let Some(src_dir) = bundle_entry.parent() else {
        return Ok(0);
    };
    // No-op when the bundle already lives in the destination (an in-place run).
    if src_dir == dest_dir {
        return Ok(0);
    }
    std::fs::create_dir_all(dest_dir)?;
    let mut copied = 0usize;
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Mirror the loader's recognized chunk set; any other file (the entry
        // bundle, a source map) is not a chunk and must not be copied.
        let is_chunk = name_str.starts_with("__ibexpkg__") || name_str == "rolldown-runtime.js";
        if !is_chunk || !entry.file_type()?.is_file() {
            continue;
        }
        std::fs::copy(entry.path(), dest_dir.join(&name)).with_context(|| {
            format!(
                "failed to copy chunk {} into {}",
                name_str,
                dest_dir.display()
            )
        })?;
        copied += 1;
    }
    Ok(copied)
}

fn transpile_esm_to_script(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut import_id = 0usize;
    let mut export_block_depth: Option<usize> = None;

    for line in source.split_inclusive('\n') {
        let trimmed = line.trim_start();

        if let Some(depth) = export_block_depth.as_mut() {
            *depth = update_export_block_depth(*depth, line);
            if *depth == 0 {
                export_block_depth = None;
            }
            continue;
        }

        if trimmed.starts_with("import ") {
            if let Some(imported) = transpile_esm_import_statement(trimmed, &mut import_id) {
                output.push_str(&imported);
            }
            continue;
        }

        if trimmed.starts_with("export {") {
            let remaining_depth = update_export_block_depth(0, line);
            if remaining_depth != 0 {
                export_block_depth = Some(remaining_depth);
            }
            continue;
        }

        if trimmed.starts_with("export * from ") || trimmed == "export {}" {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("export ") {
            if let Some(prefix_len) = line.find("export ") {
                output.push_str(&line[..prefix_len]);
                output.push_str(rest);
                if line.ends_with('\n') {
                    output.push('\n');
                }
                continue;
            }
        }

        output.push_str(line);
    }

    output
}

fn update_export_block_depth(mut depth: usize, line: &str) -> usize {
    let mut chars = line.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_template = false;
    let mut escaping = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            break;
        }

        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }

        if escaping {
            escaping = false;
            continue;
        }

        if in_single_quote {
            if ch == '\\' {
                escaping = true;
            } else if ch == '\'' {
                in_single_quote = false;
            }
            continue;
        }

        if in_double_quote {
            if ch == '\\' {
                escaping = true;
            } else if ch == '"' {
                in_double_quote = false;
            }
            continue;
        }

        if in_template {
            if ch == '\\' {
                escaping = true;
            } else if ch == '`' {
                in_template = false;
            }
            continue;
        }

        if ch == '/' {
            match chars.peek().copied() {
                Some('/') => {
                    chars.next();
                    in_line_comment = true;
                    continue;
                }
                Some('*') => {
                    chars.next();
                    in_block_comment = true;
                    continue;
                }
                _ => {}
            }
        }

        match ch {
            '\'' => in_single_quote = true,
            '"' => in_double_quote = true,
            '`' => in_template = true,
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }

    depth
}

fn transpile_esm_import_statement(line: &str, import_id: &mut usize) -> Option<String> {
    let line = line.trim();
    if !line.starts_with("import ") {
        return None;
    }

    let body = line
        .trim_start_matches("import ")
        .trim()
        .trim_end_matches(';')
        .trim();
    if body.is_empty() {
        return None;
    }

    if !body.contains(" from ") {
        return Some(format!("globalThis.require({});\n", body));
    }

    let mut parts = body.splitn(2, " from ");
    let imports = parts.next()?.trim();
    let module = parts.next()?.trim().trim_end_matches(';');
    if imports.is_empty() {
        return Some(format!("globalThis.require({});\n", module));
    }

    if imports.starts_with("* as ") {
        let alias = imports.trim_start_matches("* as ").trim();
        return Some(format!("const {alias} = globalThis.require({module});\n"));
    }

    if imports.starts_with('{') && imports.ends_with('}') {
        // Convert ESM `as` aliases to destructuring `:` syntax.
        // e.g. `{ setTimeout as setTimeout$1 }` → `{ setTimeout: setTimeout$1 }`
        let destructured = convert_import_as_to_destructure(imports);
        return Some(format!(
            "const {destructured} = globalThis.require({module});\n"
        ));
    }

    if let Some((default_name, named_part)) = imports.split_once(',') {
        let default_name = default_name.trim();
        let named_part = named_part.trim();
        if default_name.is_empty() {
            return None;
        }

        let module_var = format!("__ex_module_{import_id}");
        *import_id += 1;
        let mut out = String::new();
        out.push_str(&format!(
            "const {module_var} = globalThis.require({module});\n"
        ));
        out.push_str(&format!(
            "const {default_name} = {module_var}.default ?? {module_var};\n"
        ));
        if named_part.starts_with('{') && named_part.ends_with('}') {
            out.push_str(&format!("const {named_part} = {module_var};\n"));
        } else if named_part.starts_with("* as ") {
            let alias = named_part.trim_start_matches("* as ").trim();
            out.push_str(&format!("const {alias} = {module_var};\n"));
        }
        return Some(out);
    }

    Some(format!(
        "const {imports} = globalThis.require({module}).default ?? globalThis.require({module});\n"
    ))
}

/// Convert ESM import `as` aliases to destructuring `:` syntax.
/// E.g. `{ setTimeout as setTimeout$1, foo }` → `{ setTimeout: setTimeout$1, foo }`
fn convert_import_as_to_destructure(imports: &str) -> String {
    // Strip outer braces, process each binding, re-wrap
    let inner = imports.trim_start_matches('{').trim_end_matches('}').trim();
    let bindings: Vec<String> = inner
        .split(',')
        .map(|b| {
            let b = b.trim();
            if let Some((orig, alias)) = b.split_once(" as ") {
                format!("{}: {}", orig.trim(), alias.trim())
            } else {
                b.to_string()
            }
        })
        .collect();
    format!("{{ {} }}", bindings.join(", "))
}

async fn run_bundler(entry: &Path, output: &Path, bundle_format: BundleFormat) -> Result<()> {
    let (runner, runner_name) = find_js_runner()?;
    let script = bundler_script_path()?;
    let working_dir = bundler_working_dir()?;
    let timeout = timeout_from_env("EXACT_BUNDLER_TIMEOUT_MS", DEFAULT_BUNDLER_TIMEOUT_MS);

    // The output may live in a per-key subdir (per-package chunking); make sure
    // it exists before the bundler writes the entry + sibling chunks there.
    if let Some(parent) = output.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    let mut command = tokio::process::Command::new(&runner);
    command
        .arg(&script)
        .arg("--entry")
        .arg(entry)
        .arg("--out")
        .arg(output)
        .arg("--format")
        .arg(bundle_format.as_str())
        .arg("--sourcemap")
        .current_dir(&working_dir);
    // @ref LLP 0013#mechanism-2 — when the runtime boots with lockdown, bundle
    // package (node_modules) code through the per-package compartment rewrite so
    // its bare globals resolve against the runtime compartment registry.
    if crate::env_flag_enabled("IBEX_LOCKDOWN") || crate::env_flag_enabled("IBEX_COMPARTMENTS") {
        command.arg("--compartments");
    }
    // @ref LLP 0013#mechanism-3 — per-package chunking so a bundled app gets
    // per-package frame attribution (each package chunk loads into its own
    // Domain). Auto-enabled under enforce/audit (see enable_isolation_prereqs);
    // `IBEX_PER_PACKAGE_CHUNKS=0` opts out. iife can't split; the bundler
    // ignores the flag there.
    if crate::env_flag_enabled("IBEX_PER_PACKAGE_CHUNKS") {
        command.arg("--per-package-chunks");
    }
    let cmd_output = output_with_timeout(
        &mut command,
        timeout,
        &format!("bundler via {}", runner_name),
    )
    .await?;

    if !cmd_output.status.success() {
        let stderr = String::from_utf8_lossy(&cmd_output.stderr);
        let stdout = String::from_utf8_lossy(&cmd_output.stdout);
        let combined = format!("{}{}", stderr, stdout);
        let mut context = serde_json::Map::new();
        context.insert(
            "entry".to_string(),
            serde_json::Value::String(entry.display().to_string()),
        );
        context.insert(
            "output".to_string(),
            serde_json::Value::String(output.display().to_string()),
        );
        context.insert(
            "format".to_string(),
            serde_json::Value::String(bundle_format.as_str().to_string()),
        );
        context.insert(
            "status".to_string(),
            serde_json::Value::String(cmd_output.status.to_string()),
        );
        agent_logs::record_bundler_log(
            "error",
            format!(
                "Bundler exited with status {}: {}",
                cmd_output.status, combined
            ),
            Some(context),
        );
        anyhow::bail!(
            "Bundler exited with status {}: {}",
            cmd_output.status,
            combined
        );
    }

    Ok(())
}

fn bundler_script_path() -> Result<PathBuf> {
    let root = repo_root()?;
    let script = root
        .join("packages")
        .join("ibex-devtools")
        .join("src")
        .join("scripts")
        .join("rolldown-bundle.mjs");
    if !script.exists() {
        anyhow::bail!("Bundler script not found at {}", script.display());
    }
    Ok(script)
}

/// `ibex policy generate|check` — runs the LLP 0014 policy generator with the
/// same JS-runner resolution as the bundler. The generator's exit code is the
/// command's exit code (`check` uses 1 for drift, the CI-gate contract).
/// @ref LLP 0014#runtime-and-cli
pub async fn run_policy_command(command: &crate::cli::PolicyCommands) -> Result<()> {
    use crate::cli::PolicyCommands;

    let root = repo_root()?;
    let script = root
        .join("packages")
        .join("ibex-devtools")
        .join("src")
        .join("scripts")
        .join("generate-policy.mjs");
    if !script.exists() {
        anyhow::bail!("Policy generator not found at {}", script.display());
    }
    let (runner, _runner_name) = find_js_runner()?;

    let mut cmd = tokio::process::Command::new(&runner);
    cmd.arg(&script);
    match command {
        PolicyCommands::Generate { entry, out, mode } => {
            cmd.arg("--entry").arg(entry);
            if let Some(out) = out {
                cmd.arg("--out").arg(out);
            }
            if let Some(mode) = mode {
                cmd.arg("--mode").arg(mode);
            }
        }
        PolicyCommands::Check { entry, out, mode } => {
            cmd.arg("--entry").arg(entry).arg("--check");
            if let Some(out) = out {
                cmd.arg("--out").arg(out);
            }
            // Forward the mode so the regenerated artifact stamps the same
            // `mode` the committed one carries — else an audit-mode policy
            // false-drifts against an enforce-default regeneration. (ENG-22642)
            if let Some(mode) = mode {
                cmd.arg("--mode").arg(mode);
            }
        }
    }
    // Inherit stdio: the generator's report is the user-facing output.
    let status = cmd
        .status()
        .await
        .context("failed to spawn the policy generator")?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn bundler_working_dir() -> Result<PathBuf> {
    let root = repo_root()?;
    let legacy_js_dir = root.join("js");
    if legacy_js_dir.is_dir() {
        return Ok(legacy_js_dir);
    }
    Ok(root)
}

fn find_js_runner() -> Result<(PathBuf, &'static str)> {
    #[cfg(windows)]
    {
        if let Ok(path) = which::which("node") {
            return Ok((path, "node"));
        }
    }

    if let Ok(path) = which::which("bun") {
        return Ok((path, "bun"));
    }
    if let Ok(path) = which::which("node") {
        return Ok((path, "node"));
    }
    anyhow::bail!("bun or node is required to run the bundler")
}

fn repo_root() -> Result<PathBuf> {
    fn find_from(start: &Path) -> Option<PathBuf> {
        start.ancestors().find_map(|ancestor| {
            if ancestor.join("vendored-generated").is_dir()
                && ancestor
                    .join("packages")
                    .join("ibex-runtime-js")
                    .join("package.json")
                    .is_file()
                && ancestor
                    .join("packages")
                    .join("ibex-devtools")
                    .join("package.json")
                    .is_file()
            {
                Some(ancestor.to_path_buf())
            } else {
                None
            }
        })
    }

    if let Ok(root) = std::env::var("IBEX_REPO_ROOT").or_else(|_| std::env::var("EXACT_REPO_ROOT"))
    {
        let root = PathBuf::from(root);
        if let Some(found) = find_from(&root) {
            return Ok(found);
        }
    }

    if let Ok(current_dir) = std::env::current_dir() {
        if let Some(found) = find_from(&current_dir) {
            return Ok(found);
        }
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(found) = find_from(&exe_path) {
            return Ok(found);
        }
    }

    anyhow::bail!("Failed to resolve repo root. Run from an Ibex checkout or set IBEX_REPO_ROOT")
}

/// Determine runtime cache directory.
pub fn runtime_cache_dir() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join("Library").join("Caches").join("Ibex"));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(dir) = dirs::cache_dir() {
            return Ok(dir.join("ibex"));
        }
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join(".cache").join("ibex"));
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        if let Some(dir) = dirs::cache_dir() {
            return Ok(dir.join("ibex"));
        }
    }

    anyhow::bail!("Failed to determine cache directory")
}

/// Compute default output path for `ibex build`.
pub fn compute_build_output(file: &str, outdir: Option<&Path>) -> Result<PathBuf> {
    let entry_path = Path::new(file);
    let stem = entry_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid entry file"))?;

    let output_dir = outdir
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dist"));

    if !output_dir.exists() {
        std::fs::create_dir_all(&output_dir)?;
    }

    Ok(output_dir.join(format!("{}.hbc", stem)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;
    use tempfile::tempdir;

    fn write_arming_fixture(directory: &Path) -> (PathBuf, PathBuf, String) {
        use capsec_semantics::arming::ExpectedArmingIdentity;
        use capsec_semantics::model::Digest;

        let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        value["workflow"] = serde_json::Value::String("production".into());
        value["effectiveMode"] = serde_json::Value::String("enforce".into());
        let digest = capsec_semantics::digest::compute_domain_digest(
            capsec_semantics::digest::ARMED_SNAPSHOT_DOMAIN,
            &value,
            &["armedSnapshotDigest".to_string()],
        )
        .unwrap();
        value["armedSnapshotDigest"] = serde_json::Value::String(digest.clone());
        let digest_at = |path: &[&str]| {
            let field = path
                .iter()
                .fold(&value, |current, segment| &current[*segment]);
            Digest::new(field.as_str().unwrap()).unwrap()
        };
        let expected = ExpectedArmingIdentity {
            profile: value["capsVocab"].as_str().unwrap().into(),
            semantic_core: value["semanticCore"].as_str().unwrap().into(),
            vocab_digest: digest_at(&["vocabDigest"]),
            registry_digest: digest_at(&["registryDigest"]),
            policy_digest: digest_at(&["policyDigest"]),
            target: value["engine"]["target"].as_str().unwrap().into(),
            engine_binary_digest: digest_at(&["engine", "binaryDigest"]),
            features: value["engine"]["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            target_complete_and_advertised: true,
        };
        let snapshot_path = directory.join("armed.json");
        let identity_path = directory.join("identity.json");
        std::fs::write(&snapshot_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        std::fs::write(
            &identity_path,
            serde_json::to_vec_pretty(&expected).unwrap(),
        )
        .unwrap();
        (snapshot_path, identity_path, digest)
    }

    #[test]
    fn armed_startup_requires_paired_artifacts() {
        let cli = Cli::parse_from(["ibex", "--capsec-armed-snapshot", "snapshot.json", "app.ts"]);
        let error = build_host(&cli)
            .err()
            .expect("must reject unpaired artifacts")
            .to_string();
        assert!(error.contains("must be provided together"), "{error}");
    }

    #[test]
    fn armed_startup_rejects_legacy_authority_overrides_before_io() {
        let cli = Cli::parse_from([
            "ibex",
            "--capsec-armed-snapshot",
            "missing-snapshot.json",
            "--capsec-arming-identity",
            "missing-identity.json",
            "--allow",
            "fs:read:/tmp",
            "app.ts",
        ]);
        let error = build_host(&cli)
            .err()
            .expect("must reject legacy overrides")
            .to_string();
        assert!(error.contains("cannot be combined with legacy"), "{error}");
        assert!(
            !error.contains("failed to read"),
            "override must fail before artifact I/O: {error}"
        );
    }

    #[test]
    fn armed_startup_closes_every_inspector_activation_before_io() {
        for inspector_args in [
            vec!["--inspect"],
            vec!["--inspect-wait"],
            vec!["--inspect-open"],
            vec!["--inspect-pause"],
            vec!["--inspect-port", "9230"],
            vec!["--inspect-host", "127.0.0.1"],
        ] {
            let mut args = vec![
                "ibex",
                "--capsec-armed-snapshot",
                "missing-snapshot.json",
                "--capsec-arming-identity",
                "missing-identity.json",
            ];
            args.extend(inspector_args);
            args.push("app.ts");
            let cli = Cli::parse_from(args);
            let error = build_host(&cli)
                .err()
                .expect("armed inspector configuration must be closed")
                .to_string();
            assert!(error.contains("closes inspector"), "{error}");
            assert!(
                !error.contains("failed to read"),
                "inspector closure must precede artifact I/O: {error}"
            );
        }
    }

    #[test]
    fn armed_startup_closes_compatibility_facades_before_io() {
        let cli = Cli::parse_from([
            "ibex",
            "--capsec-armed-snapshot",
            "missing-snapshot.json",
            "--capsec-arming-identity",
            "missing-identity.json",
            "--compat",
            "bun",
            "app.ts",
        ]);
        let error = build_host(&cli)
            .err()
            .expect("armed compatibility facade must be closed")
            .to_string();
        assert!(error.contains("closes compatibility"), "{error}");
        assert!(
            !error.contains("failed to read"),
            "compatibility closure must precede artifact I/O: {error}"
        );
    }

    #[test]
    fn armed_startup_authenticates_snapshot_and_returns_engine_digest() {
        let directory = tempdir().unwrap();
        let (snapshot, identity, expected_digest) = write_arming_fixture(directory.path());
        let cli = Cli::parse_from([
            "ibex".into(),
            "--capsec-armed-snapshot".into(),
            snapshot.into_os_string(),
            "--capsec-arming-identity".into(),
            identity.into_os_string(),
            "app.ts".into(),
        ]);
        let (host, digest) = build_host(&cli).expect("fixture must arm");
        assert_eq!(digest.as_deref(), Some(expected_digest.as_str()));
        assert_eq!(
            host.armed_snapshot().unwrap().digest().as_str(),
            expected_digest
        );
    }

    fn file_hash(path: &Path) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        hash_file_contents(&mut hasher, path).expect("hashing file contents should succeed");
        hasher.finish()
    }

    // ENG-22760 — `ibex build` under enforce/audit must ship the per-package
    // chunk siblings next to the `.hbc`, or the built artifact silently loses
    // per-package attribution (a flat single-Domain run). Ship exactly the set
    // the loader's chunk-redirect recognizes (`__ibexpkg__*`, `rolldown-runtime.js`)
    // and nothing else (not the entry bundle, its deps json, or unrelated files).
    #[test]
    fn ship_chunk_siblings_copies_only_recognized_chunks() {
        let src = tempdir().unwrap();
        let dest = tempdir().unwrap();
        // A chunked bundle dir as the bundler emits it.
        std::fs::write(src.path().join("bundle.js"), "entry").unwrap();
        std::fs::write(src.path().join("bundle.js.map"), "{}").unwrap();
        std::fs::write(src.path().join("bundle.js.deps.json"), "[]").unwrap();
        std::fs::write(src.path().join("__ibexpkg__evil-pkg@1.0.0.js"), "chunk").unwrap();
        std::fs::write(src.path().join("__ibexpkg__evil-pkg@1.0.0.js.map"), "{}").unwrap();
        std::fs::write(src.path().join("rolldown-runtime.js"), "rt").unwrap();
        std::fs::write(src.path().join("unrelated.txt"), "x").unwrap();

        let entry = src.path().join("bundle.js");
        let copied = ship_chunk_siblings(&entry, dest.path()).unwrap();

        // The chunk, its map, and the shared runtime are shipped...
        assert!(dest.path().join("__ibexpkg__evil-pkg@1.0.0.js").exists());
        assert!(dest
            .path()
            .join("__ibexpkg__evil-pkg@1.0.0.js.map")
            .exists());
        assert!(dest.path().join("rolldown-runtime.js").exists());
        assert_eq!(copied, 3);
        // ...but the entry bundle, its deps json, its map, and unrelated files
        // are not (they'd shadow the entry / bloat the artifact).
        assert!(!dest.path().join("bundle.js").exists());
        assert!(!dest.path().join("bundle.js.map").exists());
        assert!(!dest.path().join("bundle.js.deps.json").exists());
        assert!(!dest.path().join("unrelated.txt").exists());

        // Shipping into the bundle's own directory (an in-place run) is a no-op.
        assert_eq!(ship_chunk_siblings(&entry, src.path()).unwrap(), 0);
    }

    // ENG-22760 — `ibex build` under an enforce policy must NOT emit a flat,
    // single-principal bundle. The build path (`apply_build_isolation`) turns on
    // per-package chunking exactly when `resolve_security_mode` reports
    // Enforce/Audit, so this guards that resolution: a committed policy declaring
    // `mode: "enforce"` yields Enforce under the default (Auto) CLI mode — the
    // signal that drives `enable_isolation_prerequisites` for the build and run
    // paths alike. Platform-independent cover for the wiring the run-path
    // integration tests can't reach on the unpatched checked-in Hermes (they
    // skip vacuously). @ref LLP 0013#mechanism-3
    #[test]
    fn resolve_security_mode_honors_committed_enforce_policy() {
        use crate::host::SecurityMode;

        let dir = tempdir().unwrap();
        let write_policy = |mode: &str| {
            let p = dir.path().join(format!("ibex-policy.{mode}.json"));
            std::fs::write(&p, format!(r#"{{"mode":"{mode}"}}"#)).unwrap();
            p
        };
        let enforce = write_policy("enforce");
        let audit = write_policy("audit");
        let permissive = write_policy("permissive");

        // Load once + resolve, mirroring the production single-parse flow
        // (build_host_config / apply_build_isolation). (ENG-22644)
        let resolve = |cli: &Cli, path: Option<&Path>| {
            let policy = load_policy_file(cli, path).unwrap();
            resolve_security_mode(cli, policy.as_deref(), path).unwrap()
        };

        // Default CLI (capsec = Auto): the committed policy's declared mode wins,
        // so an enforce policy resolves to Enforce — the build path then enables
        // per-package chunking instead of emitting a flat, single-principal bundle.
        let cli = Cli::parse_from(["ibex", "app.ts"]);
        assert_eq!(
            resolve(&cli, Some(enforce.as_path())),
            SecurityMode::Enforce,
        );
        // Audit likewise implies per-package attribution.
        assert_eq!(resolve(&cli, Some(audit.as_path())), SecurityMode::Audit);
        assert_eq!(
            resolve(&cli, Some(permissive.as_path())),
            SecurityMode::Permissive,
        );

        // No policy under Auto stays Permissive: an absent auto-discovered default
        // must not silently flip a build to chunked/enforced.
        assert_eq!(resolve(&cli, None), SecurityMode::Permissive);

        // The documented operator opt-outs override a committed enforce policy, so
        // a build under either stays flat: explicit `--capsec permissive` ...
        let forced = Cli::parse_from(["ibex", "--capsec", "permissive", "app.ts"]);
        assert_eq!(
            resolve(&forced, Some(enforce.as_path())),
            SecurityMode::Permissive,
        );
        // ... and `--allow-all` (back-compat legacy escape hatch).
        let allow_all = Cli::parse_from(["ibex", "--allow-all", "app.ts"]);
        assert_eq!(
            resolve(&allow_all, Some(enforce.as_path())),
            SecurityMode::Permissive,
        );
    }

    // ENG-22884 — enforce must not silently proceed as full-strength capsec when
    // an attribution prerequisite is missing. The readiness snapshot is passed
    // as data so the missing-EXACT_HAVE_FRAME_ATTRIBUTION and
    // IBEX_PER_PACKAGE_CHUNKS=0 shapes are simulated without recompiling or
    // mutating process-global env.
    #[test]
    fn capsec_enforce_fails_closed_without_attribution_prerequisites() {
        use crate::host::SecurityMode;

        let ready = CapsecReadiness {
            frame_attribution: true,
            package_isolation: PackageIsolation::Enabled,
            lockdown: true,
            dynamic_ceiling: false,
        };

        // Fully-ready enforce proceeds and emits exactly the readiness report.
        let lines =
            check_capsec_readiness(SecurityMode::Enforce, CapsecStage::Run, ready, false).unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("frame-attribution=present"));
        assert!(lines[0].contains("package-isolation=per-package"));

        // Enforce without lockdown is allowed for compatibility, but it must not
        // silently imply full shared-intrinsics integrity.
        let enforce_without_lockdown = CapsecReadiness {
            lockdown: false,
            ..ready
        };
        let lines = check_capsec_readiness(
            SecurityMode::Enforce,
            CapsecStage::Run,
            enforce_without_lockdown,
            false,
        )
        .unwrap();
        assert!(
            lines.iter().any(|line| line.contains("without lockdown"))
                && lines
                    .iter()
                    .any(|line| line.contains("intrinsic-integrity attacks")),
            "enforce without lockdown must state the claim ceiling: {lines:?}"
        );

        // Missing frame attribution (an engine built without
        // EXACT_HAVE_FRAME_ATTRIBUTION): an enforce run fails closed with the
        // escape hatch named in the error...
        let advisory = CapsecReadiness {
            frame_attribution: false,
            ..ready
        };
        let err = check_capsec_readiness(SecurityMode::Enforce, CapsecStage::Run, advisory, false)
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("frame-derived attribution"));
        assert!(msg.contains("--capsec-allow-advisory"));

        // ...unless the operator explicitly opts into advisory attribution, which
        // still reports loudly.
        let lines = check_capsec_readiness(SecurityMode::Enforce, CapsecStage::Run, advisory, true)
            .unwrap();
        assert!(lines.iter().any(|l| l.contains("ADVISORY")));
        assert!(lines
            .iter()
            .any(|l| l.contains("frame-attribution=missing")));

        // An explicit IBEX_PER_PACKAGE_CHUNKS=0 collapses bundled dependencies
        // into the root principal — hard prerequisite at run AND build stage
        // (the flat layout is baked into the built artifact).
        let collapsed = CapsecReadiness {
            package_isolation: PackageIsolation::DisabledByOperator,
            ..ready
        };
        assert!(
            check_capsec_readiness(SecurityMode::Enforce, CapsecStage::Run, collapsed, false)
                .is_err()
        );
        assert!(check_capsec_readiness(
            SecurityMode::Enforce,
            CapsecStage::Build,
            collapsed,
            false
        )
        .is_err());

        // Building with an attribution-less engine proceeds (the artifact may
        // run under a patched engine) but warns instead of staying silent.
        let lines =
            check_capsec_readiness(SecurityMode::Enforce, CapsecStage::Build, advisory, false)
                .unwrap();
        assert!(lines.iter().any(|l| l.starts_with("warning:")));

        // Audit never fails closed but must be conspicuous about advisory
        // attribution.
        let lines =
            check_capsec_readiness(SecurityMode::Audit, CapsecStage::Run, advisory, false).unwrap();
        assert!(lines.iter().any(|l| l.contains("ADVISORY")));
        assert!(lines.iter().any(|l| l.contains("audit")));

        // Permissive claims no capsec, so it stays silent.
        assert!(check_capsec_readiness(
            SecurityMode::Permissive,
            CapsecStage::Run,
            advisory,
            false
        )
        .unwrap()
        .is_empty());
    }

    #[tokio::test]
    async fn bundle_cache_freshness_tracks_dep_mtimes() {
        let dir = tempdir().expect("tempdir");
        let entry = dir.path().join("entry.ts");
        let dep = dir.path().join("dep.ts");
        let output = dir.path().join("entry.bundle.js");
        std::fs::write(&entry, "import './dep.ts';").expect("write entry");
        std::fs::write(&dep, "export const v = 1;").expect("write dep");
        std::fs::write(&output, "bundled").expect("write output");

        // No dependency manifest → stale (pre-manifest caches rebuild once).
        assert!(!bundle_cache_is_fresh(&output, &entry).await);

        let manifest = serde_json::json!({
            "version": 1,
            "deps": [entry.to_string_lossy(), dep.to_string_lossy()],
        });
        std::fs::write(deps_manifest_path(&output), manifest.to_string()).expect("write manifest");
        // Re-write the output so it is the newest file in the set.
        std::thread::sleep(std::time::Duration::from_millis(15));
        std::fs::write(&output, "bundled-2").expect("rewrite output");
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // Editing an *imported* dependency (not the entry) must invalidate —
        // the entry-mtime-only check missed exactly this (ledger item 2).
        std::thread::sleep(std::time::Duration::from_millis(15));
        std::fs::write(&dep, "export const v = 2;").expect("edit dep");
        assert!(!bundle_cache_is_fresh(&output, &entry).await);

        // A deleted dependency invalidates too.
        std::thread::sleep(std::time::Duration::from_millis(15));
        std::fs::write(&output, "bundled-3").expect("rewrite output");
        assert!(bundle_cache_is_fresh(&output, &entry).await);
        std::fs::remove_file(&dep).expect("remove dep");
        assert!(!bundle_cache_is_fresh(&output, &entry).await);
    }

    #[test]
    fn await_detection_ignores_strings_and_comments() {
        assert!(contains_await_keyword("const x = await f();"));
        assert!(contains_await_keyword("for (const y of z) { await y; }"));
        assert!(!contains_await_keyword("console.log(\"await\")"));
        assert!(!contains_await_keyword("// await in a comment"));
        assert!(!contains_await_keyword("/* await */ let a = 1;"));
        assert!(!contains_await_keyword("let awaited = `await ${'await'}`;"));
        assert!(!contains_await_keyword("let kawaii = 1;"));
    }

    #[test]
    fn await_detection_skips_regex_literals() {
        // `await` inside a regex literal is not a keyword — the scanner must not
        // report TLA (which would move a `var`/function binding into an async
        // IIFE and drop it from the global scope). (ENG-23031)
        assert!(!contains_await_keyword("var re = /await/g"));
        assert!(!contains_await_keyword("var re = /(await)/"));
        assert!(!contains_await_keyword("const re = /a\\/await/;"));
        assert!(!contains_await_keyword("var re = /[/await]/"));
        assert!(!contains_await_keyword("x.replace(/await/g, '')"));
        assert!(!contains_await_keyword("return /await/.test(s)"));

        // A `/` after a value is division, so a real `await` following it is
        // still detected (the regex heuristic must not swallow later code).
        assert!(contains_await_keyword("var q = a / b; await c"));
        assert!(contains_await_keyword("var q = /re/.source; await c"));
        // `typeof x` is a value, so `/ await y` is a division then a real await.
        assert!(contains_await_keyword("typeof x / await y"));
    }

    #[test]
    fn tla_wrap_binds_filename_for_import_meta_lowering() {
        let wrapped = wrap_source_for_tla_eval(
            std::borrow::Cow::Borrowed("console.log((\"file://\" + __filename));\nawait 1;"),
            true,
        );
        assert!(
            wrapped.contains("(async function(__filename, __dirname, module, exports)"),
            "wrapped: {wrapped}"
        );
        assert!(wrapped.contains("__exactEntryFile"), "wrapped: {wrapped}");
    }

    #[test]
    fn hash_file_contents_changes_when_content_changes() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("entry.js");

        std::fs::write(&path, "aaaa").expect("write initial contents");
        let first = file_hash(&path);

        std::fs::write(&path, "bbbb").expect("write updated contents");
        let second = file_hash(&path);

        assert_ne!(first, second);
    }

    #[test]
    fn bundler_cache_input_paths_cover_shared_bundler_sources() {
        // In-repo runs hash both bundler scripts; outside a checkout the list
        // is empty by design.
        let paths = bundler_cache_input_paths();

        assert_eq!(paths.len(), 4);
        assert!(paths
            .iter()
            .any(|path| path.ends_with("packages/ibex-devtools/src/scripts/rolldown-bundle.mjs")));
        assert!(paths
            .iter()
            .any(|path| path.ends_with("packages/ibex-devtools/src/scripts/transforms.mjs")));
        // @ref LLP 0019#decision — ENG-22987: the extracted canonical transform source.
        assert!(paths
            .iter()
            .any(|path| path.ends_with("packages/ibex-devtools/src/scripts/hermes-compat.mjs")));
        assert!(paths
            .iter()
            .any(|path| path.ends_with("packages/ibex-devtools/src/scripts/import-grants.mjs")));
        assert!(paths.iter().all(|path| path.exists()));
    }

    #[test]
    fn detects_top_level_await_call_syntax() {
        assert!(contains_top_level_await("await(fetchStuff())\n"));
        assert!(!contains_top_level_await(
            "async function run() { await(fetchStuff()); }\n"
        ));
    }

    #[test]
    fn top_level_await_detection_skips_regex_literals() {
        // `await` inside a depth-0 regex literal is not TLA — the false
        // positive flipped the bundle format CJS→ESM and hard-failed valid
        // apps that merely declared a regex mentioning `await`. (ENG-23484;
        // mirrors the ENG-23031 fix for contains_await_keyword.)
        assert!(!contains_top_level_await("const RE = /(await)/;"));
        assert!(!contains_top_level_await("var re = /await/g"));
        assert!(!contains_top_level_await("const re = /a\\/await/;"));
        assert!(!contains_top_level_await("x.replace(/await/g, '')"));

        // A `/` after a value is division; a real `await` after it is still
        // detected, and a regex must not swallow the rest of the line.
        assert!(contains_top_level_await("var q = a / b; await c"));
        assert!(contains_top_level_await("const re = /await/; await go()"));
    }

    #[test]
    fn top_level_await_detection_keeps_depth_and_context_rules() {
        // Depth: only brace depth 0 is top-level.
        assert!(contains_top_level_await("await x;"));
        assert!(contains_top_level_await("const v = await f();"));
        assert!(!contains_top_level_await("if (x) { await y; }"));
        assert!(!contains_top_level_await(
            "class C { async m() { await x; } }"
        ));
        // Strings, comments, identifiers, labels.
        assert!(!contains_top_level_await("console.log(\"await\")"));
        assert!(!contains_top_level_await("// await\nlet a = 1;"));
        assert!(!contains_top_level_await("/* await */ let a = 1;"));
        assert!(!contains_top_level_await("let awaited = `await`;"));
        assert!(!contains_top_level_await("await: {}"));
        // Braces inside a regex literal must not corrupt the depth count.
        assert!(contains_top_level_await("const re = /a{2}[{]/; await x"));
    }

    #[test]
    fn transpile_esm_to_script_skips_multiline_export_block_without_semicolon_heuristic() {
        let source = r#"
export {
  thing,
  other // semicolon; in comment should not end the block
} from "./mod.js";
console.log("kept");
"#;
        let transpiled = transpile_esm_to_script(source);
        assert!(transpiled.contains("console.log(\"kept\");"));
        assert!(!transpiled.contains("export {"));
        assert!(!transpiled.contains("from \"./mod.js\""));
    }

    #[test]
    fn normalize_candidate_returns_existing_file_path() {
        let dir = tempdir().expect("temp dir");
        let file = dir.path().join("entry.js");
        std::fs::write(&file, "console.log('hi')").expect("write temp file");
        let resolved = normalize_candidate(&file).expect("resolved candidate");

        assert_eq!(resolved, file.to_string_lossy());
    }

    #[test]
    fn normalize_hashbang_for_eval_rewrites_hashbang_as_comment() {
        let normalized = normalize_hashbang_for_eval("#!/usr/bin/env node\nconsole.log('ok');\n");

        assert_eq!(
            normalized.as_ref(),
            "///usr/bin/env node\nconsole.log('ok');\n"
        );
    }

    #[test]
    fn normalize_hashbang_for_eval_strips_only_whole_line_sourcemap_comments() {
        // A line that IS a sourceMappingURL comment (leading whitespace aside)
        // is stripped; the marker inside a string literal — code that
        // generates sourcemap comments — must survive untouched. Truncating
        // it mid-line corrupted the source on every TLA-shim evaluation.
        // (ENG-23484)
        let source = "const banner = \"//# sourceMappingURL=x.map\";\n\
                      out.push(\"//# sourceMappingURL=\" + url);\n\
                      \t//# sourceMappingURL=indented.map\n\
                      //# sourceMappingURL=real.map\n";
        let normalized = normalize_hashbang_for_eval(source);

        assert_eq!(
            normalized.as_ref(),
            "const banner = \"//# sourceMappingURL=x.map\";\n\
             out.push(\"//# sourceMappingURL=\" + url);\n\
             \n\
             \n"
        );
    }

    #[test]
    fn normalize_hashbang_for_eval_keeps_trailing_code_before_sourcemap_comment() {
        // A trailing same-line comment after real code is no longer stripped:
        // this scan cannot prove comment position mid-line, and keeping a
        // stale sourcemap pointer is harmless next to truncating code.
        let source = "doWork(); //# sourceMappingURL=inline.map\n";
        let normalized = normalize_hashbang_for_eval(source);

        assert_eq!(normalized.as_ref(), source);
    }

    #[tokio::test]
    async fn runtime_executes_hashbang_entry_files() {
        let dir = tempdir().expect("temp dir");
        let module_file = dir.path().join("module.js");
        let entry_file = dir.path().join("entry.js");

        std::fs::write(
            &module_file,
            "#!/usr/bin/env node\nmodule.exports = { value: 'module-ok' };\n",
        )
        .expect("write shebang module");
        std::fs::write(
            &entry_file,
            "#!/usr/bin/env node\nglobalThis.__hashbangEntry = 'entry';\nawait Promise.resolve();\nglobalThis.__hashbangEntry += '-ok';\n",
        )
        .expect("write shebang entry");

        let cli = Cli::parse_from(["ibex".to_string(), entry_file.to_string_lossy().to_string()]);
        let runtime = Runtime::from_cli(&cli).expect("runtime");
        runtime.load_runtime().await.expect("load runtime");

        let module_json = serde_json::to_string(&module_file.to_string_lossy().to_string())
            .expect("serialize module path");
        let module_result = runtime
            .eval(&format!(
                "(function() {{ return require({}).value === 'module-ok'; }})()",
                module_json
            ))
            .await
            .expect("require shebang module")
            .unwrap_or_default();
        assert_eq!(module_result.trim(), "true");

        runtime
            .run_file_with_args(entry_file.to_str().expect("entry path"), &[])
            .await
            .expect("run shebang entry");

        let entry_result = runtime
            .eval("(function() { return globalThis.__hashbangEntry === 'entry-ok'; })()")
            .await
            .expect("inspect entry result")
            .unwrap_or_default();
        assert_eq!(entry_result.trim(), "true");
    }

    #[tokio::test]
    async fn module_loader_preserves_nested_syntax_error_after_partial_exports() {
        let dir = tempdir().expect("temp dir");
        let parent_file = dir.path().join("parent.mjs");
        let child_file = dir.path().join("child.js");

        std::fs::write(
            &child_file,
            "var err = new SyntaxError('nested syntax root');\nthrow err;\n",
        )
        .expect("write child module");
        std::fs::write(
            &parent_file,
            r#"
function _export(target, all) {
  for (var name in all) {
    Object.defineProperty(target, name, { enumerable: true, get: all[name] });
  }
}
var value = "parent export";
_export(module.exports, { value: function() { return value; } });
require("./child.js");
"#,
        )
        .expect("write parent module");

        let cli = Cli::parse_from([
            "ibex".to_string(),
            parent_file.to_string_lossy().to_string(),
        ]);
        let runtime = Runtime::from_cli(&cli).expect("runtime");
        runtime.load_runtime().await.expect("load runtime");

        let parent_json = serde_json::to_string(&parent_file.to_string_lossy().to_string())
            .expect("serialize parent path");
        let err = runtime
            .eval(&format!("require({});", parent_json))
            .await
            .expect_err("nested SyntaxError should be preserved");
        let message = format!("{err:#}");

        assert!(
            message.contains("nested syntax root"),
            "root nested error should survive: {message}"
        );
        assert!(
            !message.contains("property is not configurable")
                && !message.contains("Cannot redefine property"),
            "partial parent module must not be rerun and mask the root error: {message}"
        );
    }

    #[tokio::test]
    async fn module_loader_async_fn_await_import_stays_on_direct_path() {
        // Guard against over-broad await-fallback routing (ENG-22811 review):
        // a module whose only `await import()` lives inside an ordinary async
        // function must load on the direct path — its top-level throws stay
        // synchronous errors instead of being swallowed as promise rejections
        // by an async wrapper, and its exports must not be ESM-shimmed.
        let dir = tempdir().expect("temp dir");
        let dep_file = dir.path().join("dep.js");
        let ok_file = dir.path().join("ok.js");
        let throwing_file = dir.path().join("throwing.js");

        std::fs::write(&dep_file, "module.exports = { ok: true };\n").expect("write dep module");
        std::fs::write(
            &ok_file,
            r#"
async function lazy() {
  var mod = await import("./dep.js");
  return mod.ok;
}
module.exports.lazy = lazy;
"#,
        )
        .expect("write ok module");
        std::fs::write(
            &throwing_file,
            r#"
async function lazy() {
  return await import("./dep.js");
}
module.exports.lazy = lazy;
throw new Error("sync-throw-marker");
"#,
        )
        .expect("write throwing module");

        let cli = Cli::parse_from(["ibex".to_string(), ok_file.to_string_lossy().to_string()]);
        let runtime = Runtime::from_cli(&cli).expect("runtime");
        runtime.load_runtime().await.expect("load runtime");

        let ok_json = serde_json::to_string(&ok_file.to_string_lossy().to_string())
            .expect("serialize ok path");
        let direct_result = runtime
            .eval(&format!(
                "(function() {{ var m = require({ok_json}); return (typeof m.lazy === 'function') && m.__esmShimmed === undefined; }})();"
            ))
            .await
            .expect("async-fn await module should load directly")
            .unwrap_or_default();
        assert_eq!(
            direct_result.trim(),
            "true",
            "module with await inside an async function must not be routed through the fallback"
        );

        let throwing_json = serde_json::to_string(&throwing_file.to_string_lossy().to_string())
            .expect("serialize throwing path");
        let err = runtime
            .eval(&format!("require({throwing_json});"))
            .await
            .expect_err("top-level throw must stay a synchronous require error");
        let message = format!("{err:#}");
        assert!(
            message.contains("sync-throw-marker"),
            "synchronous top-level throw should propagate, not become a rejection: {message}"
        );
    }
}
