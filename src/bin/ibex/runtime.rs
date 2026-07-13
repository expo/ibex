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
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Set when bytecode loading fails (e.g. version mismatch between hermesc
/// and the embedded Hermes runtime). Once set, we skip further bytecode
/// compilation attempts for the rest of the process lifetime.
static BYTECODE_INCOMPATIBLE: AtomicBool = AtomicBool::new(false);

const WINDOWS_MINIMAL_RUNTIME_BOOTSTRAP: &str = r#"(function(g) {
  if (g.__exactRuntimeLoaded === true) return;

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

const WINDOWS_RUNTIME_LOADED_PROBE: &str =
    "typeof globalThis === 'object' && globalThis.__exactRuntimeLoaded === true";

async fn load_windows_minimal_runtime(engine: &dyn Engine) -> Result<()> {
    let loaded = engine
        .eval_immediate(WINDOWS_RUNTIME_LOADED_PROBE)
        .await
        .context("failed to probe the Windows minimal runtime")?;
    if !matches!(loaded.as_deref().map(str::trim), Some("true")) {
        engine
            .eval_immediate(WINDOWS_MINIMAL_RUNTIME_BOOTSTRAP)
            .await?;
    }
    engine::hermes::finalize_compartment_baseline(engine).await
}

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

/// Preserve the explicit foreground-audit entry when child-process shims
/// reconstruct an Ibex invocation from `process.execArgv`.
fn build_audit_exec_argv(cli: &Cli) -> Vec<String> {
    let mut exec_argv = vec!["capsec".to_string(), "audit".to_string()];
    exec_argv.extend(build_exec_argv(cli));
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

    pub fn from_audit_cli(cli: &Cli) -> Result<Self> {
        validate_diagnostic_audit_inputs(cli)?;
        if cli.policy.is_some() || crate::runtime_env("IBEX_POLICY", "EXACT_POLICY").is_some() {
            anyhow::bail!("foreground audit does not accept durable policy inputs");
        }
        let host = Host::new(HostConfig {
            mode: crate::host::SecurityMode::Audit,
            ..Default::default()
        });
        crate::host::abi::install_host(host.clone());
        let engine = engine::create_engine(&cli.engine, None)?;
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
            exec_argv: build_audit_exec_argv(cli),
            compat_modes: Vec::new(),
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
            load_windows_minimal_runtime(self.engine.as_ref()).await?;
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
        // Hold a shared OS file lock for the entire execution. Quota pruning
        // takes the exclusive side, so lazy per-package chunk loads remain
        // safe without PID files (which leaked and were vulnerable to reuse).
        let _bundle_lease = acquire_bundle_execution_lease(&entry_path).await?;
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
        let chunk_dir = entry_path
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let chunk_dir_json =
            serde_json::to_string(&chunk_dir).unwrap_or_else(|_| "\"\"".to_string());
        let argv_code = format!("globalThis.__exactChunkDir = {chunk_dir_json};\n{argv_code}");

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
            let content_dir = entry_path.parent().filter(|parent| {
                parent
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == ".bytecode-cache")
            });
            // Content-addressed HBC is untrusted cache data. Read and verify it
            // once, then pass those exact bytes to Hermes. Direct user-supplied
            // .hbc files retain the normal engine path behavior.
            let verified = match content_dir {
                Some(_) => Some(
                    engine::hermes::load_verified_bytecode_artifact(None, &entry_path)
                        .await
                        .context("Bytecode cache changed before execution")?,
                ),
                None => None,
            };
            let manifest_source = verified
                .as_ref()
                .map(|artifact| artifact.source_path.clone());
            let execution = match verified.as_ref() {
                Some(artifact) => {
                    self.engine
                        .run_bytecode_bytes(&artifact.bytes, &entry_str)
                        .await
                }
                None => self.engine.run_file(&entry_str).await,
            };
            match execution {
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
                    if !engine::hermes::is_bytecode_load_error(&e) {
                        return Err(e);
                    }
                    // Bytecode failed to load (version mismatch or corrupt).
                    // Mark bytecode as incompatible so we don't re-compile.
                    BYTECODE_INCOMPATIBLE.store(true, Ordering::Relaxed);
                    // Delete the stale .hbc and fall through to require() with JS source.
                    if let Some(content_dir) = content_dir {
                        let _ = tokio::fs::remove_dir_all(content_dir).await;
                    } else {
                        let _ = tokio::fs::remove_file(&entry_path).await;
                    }
                    // Derive the JS source path from bytecode source path.
                    // .hbc files can be produced from either a raw source (.ts)
                    // or a bundled output (.bundle.mjs/.bundle.js), so fallback
                    // must try a few likely source variants.
                    // The .hbc was produced by `entry.with_extension("hbc")`,
                    // so reversing that with `.with_extension("js")` etc.
                    // correctly reconstructs the original bundle path
                    // (e.g. foo.bundle.hbc → foo.bundle.js / foo.bundle.mjs).
                    let mut fallback_paths: Vec<std::path::PathBuf> =
                        manifest_source.into_iter().collect();
                    fallback_paths.extend([
                        entry_path.with_extension("js"),
                        entry_path.with_extension("mjs"),
                        entry_path.with_extension("ts"),
                        entry_path.with_extension("tsx"),
                        entry_path.with_extension("jsx"),
                    ]);

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

const PRODUCTION_RUN_NONCE_BYTES: usize = 16;
const CONTRACT_FIXTURE_RUN_NONCE: &str = "AQIDBAUGBwgJCgsMDQ4PEA";

fn production_run_nonce_from_bytes(bytes: &[u8; PRODUCTION_RUN_NONCE_BYTES]) -> Result<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let nonce = URL_SAFE_NO_PAD.encode(bytes);
    anyhow::ensure!(
        nonce != CONTRACT_FIXTURE_RUN_NONCE,
        "OS randomness produced the reserved capsec contract-fixture run nonce"
    );
    Ok(nonce)
}

fn fresh_production_run_nonce() -> Result<String> {
    let mut bytes = [0u8; PRODUCTION_RUN_NONCE_BYTES];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        anyhow::anyhow!("OS randomness unavailable for production run nonce: {error}")
    })?;
    production_run_nonce_from_bytes(&bytes)
}

fn finalize_production_snapshot(value: &mut serde_json::Value) -> Result<()> {
    value["runNonce"] = serde_json::json!(fresh_production_run_nonce()?);
    let digest = capsec_semantics::digest::compute_domain_digest(
        capsec_semantics::digest::ARMED_SNAPSHOT_DOMAIN,
        value,
        &["armedSnapshotDigest".to_string()],
    )?;
    value["armedSnapshotDigest"] = serde_json::json!(digest);
    Ok(())
}

/// Authenticate the immutable production snapshot before either the host or
/// Hermes can observe project code. The independently generated expected
/// identity is launcher input, not policy authority, and is discarded after
/// arming. @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
fn build_host(cli: &Cli) -> Result<(Host, Option<String>)> {
    use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
    use std::sync::Arc;

    validate_production_inputs(cli)?;
    match (&cli.capsec_armed_snapshot, &cli.capsec_arming_identity) {
        (None, None) => build_default_armed_host(cli),
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
            if cli.expose_internals
                || cli.stack_size.is_some()
                || cli.max_http_header_size.is_some()
            {
                anyhow::bail!(
                    "armed capability startup closes hidden runtime-fidelity configuration"
                );
            }
            if cli.policy.is_some()
                || !cli.allow.is_empty()
                || !cli.deny.is_empty()
                || cli.allow_all
                || cli.allow_env_endowments
                || !matches!(
                    cli.capsec,
                    crate::cli::CapSecMode::Auto | crate::cli::CapSecMode::Enforce
                )
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
            let mut expected = observed_arming_identity(expected)?;
            // Authenticate the launcher-supplied document before changing it.
            // Its nonce is template/test input only: runtime construction owns
            // the fresh nonce and therefore the final armed digest.
            let template = ArmedSnapshot::load(&snapshot_bytes, &expected)
                .context("refused to authenticate capability snapshot template")?;
            let mut runtime_document = template.document().clone();
            finalize_production_snapshot(&mut runtime_document)
                .context("failed to finalize fresh production capability snapshot")?;
            expected.armed_snapshot_digest = capsec_semantics::model::Digest::new(
                runtime_document["armedSnapshotDigest"]
                    .as_str()
                    .context("finalized capability snapshot has no digest")?,
            )
            .map_err(anyhow::Error::msg)?;
            let snapshot = Arc::new(
                ArmedSnapshot::load(&serde_json::to_vec(&runtime_document)?, &expected)
                    .context("refused to arm finalized capability snapshot")?,
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

fn build_default_armed_host(cli: &Cli) -> Result<(Host, Option<String>)> {
    use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
    use capsec_semantics::digest::{
        compute_checked_contract_digest, compute_domain_digest, DigestKind,
    };
    use capsec_semantics::model::Digest;

    validate_production_inputs(cli)?;
    for line in check_capsec_readiness(
        crate::host::SecurityMode::Enforce,
        CapsecStage::Run,
        capsec_readiness(cli, None),
        false,
    )? {
        eprintln!("{line}");
    }
    if cli.capsec == crate::cli::CapSecMode::Audit {
        anyhow::bail!("foreground audit requires its separate diagnostic arming workflow");
    }
    let entry = cli.file.as_deref().or(match cli.command.as_ref() {
        Some(crate::cli::Commands::Run { file, .. })
        | Some(crate::cli::Commands::Build { file, .. }) => Some(file.as_str()),
        _ => None,
    });
    let project_root = authenticated_project_root(cli, entry)?;
    let root_object = runtime_object_identity_json(&project_root)?;
    let components = runtime_path_components_json(&project_root)?;

    let engine_identity = crate::engine::hermes::HermesEngine::loaded_engine_identity()?;
    let engine_digest = engine_identity.binary_digest.clone();
    let engine_object = serde_json::to_value(&engine_identity.object)?;
    if crate::runtime_env("IBEX_POLICY", "EXACT_POLICY").is_some() {
        anyhow::bail!("environment-selected policy paths are forbidden in production");
    }
    let current_identity: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/armed-snapshot.canonical.json"
    )))?;
    let digest_from_current = |field: &str| -> Result<capsec_semantics::model::Digest> {
        capsec_semantics::model::Digest::new(
            current_identity[field]
                .as_str()
                .with_context(|| format!("current CapSec identity is missing {field}"))?,
        )
        .map_err(anyhow::Error::msg)
    };
    let expected_policy_identity = capsec_semantics::policy::ExpectedPolicyIdentity {
        profile: "ibex/capsec/1".into(),
        semantic_core: "capsec/semantics/1".into(),
        vocab_digest: digest_from_current("vocabDigest")?,
        registry_digest: digest_from_current("registryDigest")?,
    };
    let policy_profile = capsec_semantics::registry::ValidatedProfile::from_json(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/capability-definitions.json"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/policy-rules.json"
        )),
    )?;
    let policy_path = cli
        .policy
        .clone()
        .unwrap_or_else(|| project_root.join("ibex-policy.json"));
    let mut policy = serde_json::json!({
        "policySchema": "ibex/capsec-policy/1",
        "capsVocab": "ibex/capsec/1",
        "semanticCore": "capsec/semantics/1",
        "vocabDigest": expected_policy_identity.vocab_digest.clone(),
        "registryDigest": expected_policy_identity.registry_digest.clone(),
        "policyDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "purpose": "production",
        "mode": "enforce",
        "principals": [],
    });
    let policy_loaded = policy_path.exists();
    if policy_loaded {
        let bytes = std::fs::read(&policy_path).with_context(|| {
            format!("failed to read canonical policy {}", policy_path.display())
        })?;
        let text = std::str::from_utf8(&bytes).context("canonical policy is not UTF-8")?;
        policy = capsec_semantics::strict_json::parse_strict(text)
            .context("canonical policy is not strict JSON")?;
    } else if cli.policy.is_some() {
        anyhow::bail!("canonical policy {} not found", policy_path.display());
    }
    for (field, expected) in [
        ("policySchema", "ibex/capsec-policy/1"),
        ("capsVocab", "ibex/capsec/1"),
        ("semanticCore", "capsec/semantics/1"),
        ("purpose", "production"),
        ("mode", "enforce"),
    ] {
        if policy[field].as_str() != Some(expected) {
            anyhow::bail!("canonical production policy has invalid {field}");
        }
    }
    let policy_digest = compute_checked_contract_digest(DigestKind::Policy, &policy)?;
    if policy_loaded && policy["policyDigest"].as_str() != Some(policy_digest.as_str()) {
        anyhow::bail!("canonical policy digest is stale or tampered");
    } else {
        policy["policyDigest"] = serde_json::json!(policy_digest.as_str());
    }
    let canonical_policy = capsec_semantics::policy::CanonicalPolicy::load(
        &serde_json::to_vec(&policy)?,
        &expected_policy_identity,
        &policy_profile.definitions,
    )
    .context("canonical production policy failed typed validation")?;
    let policy_digest = canonical_policy.policy_digest.as_str().to_owned();
    policy = serde_json::to_value(canonical_policy)?;
    let policy_principals = policy["principals"]
        .as_array()
        .context("canonical policy principals must be an array")?;
    let mut root_builtins = crate::module_loader::RUNTIME_GATED_NODE_BUILTINS
        .iter()
        .map(|name| format!("node:{name}"))
        .collect::<Vec<_>>();
    root_builtins.sort();
    let mut root_package_imports = policy_principals
        .iter()
        .filter_map(|row| row["principal"]["locator"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    root_package_imports.sort();
    let mut snapshot_principals = vec![serde_json::json!({
        "principal": {"kind": "root", "identity": "project-root"},
        "floor": [],
        "denials": [],
        "escalationCeiling": [],
        "imports": {
            "builtins": root_builtins,
            "packages": root_package_imports
        },
        "endowments": [],
    })];
    let mut graph_nodes = Vec::new();
    let mut graph_edges = Vec::new();
    let mut endowment_groups = Vec::new();
    let root_principal = serde_json::json!({"kind": "root", "identity": "project-root"});
    let mut package_bindings = Vec::new();
    let installed_packages = authenticated_installed_packages(&project_root, policy_principals)?;
    for row in policy_principals {
        let principal = row["principal"].clone();
        let authority_rows = |field: &str| -> Result<Vec<serde_json::Value>> {
            row[field]
                .as_array()
                .context("canonical authority rows must be arrays")?
                .iter()
                .map(|entry| {
                    entry
                        .get("authority")
                        .cloned()
                        .context("canonical authority row is missing authority")
                })
                .collect()
        };
        snapshot_principals.push(serde_json::json!({
            "principal": principal,
            "floor": authority_rows("floor")?,
            "denials": authority_rows("denials")?,
            "escalationCeiling": authority_rows("escalationCeiling")?,
            "imports": row["imports"].clone(),
            "endowments": row["endowments"].clone(),
        }));
        graph_nodes.push(serde_json::json!({"principal": principal}));
        graph_edges.push(serde_json::json!({
            "importer": root_principal,
            "imported": principal,
        }));
        if let (Some(locator), Some(endowments)) =
            (principal["locator"].as_str(), row["endowments"].as_array())
        {
            if !endowments.is_empty() {
                let values = endowments
                    .iter()
                    .map(|value| value.as_str().context("endowment must be a string"))
                    .collect::<Result<Vec<_>>>()?;
                endowment_groups.push(format!("{locator}:{}", values.join(",")));
            }
        }
        if let (Some(name), Some(locator), Some(integrity)) = (
            principal["name"].as_str(),
            principal["locator"].as_str(),
            principal["integrity"].as_str(),
        ) {
            let matches = installed_packages
                .iter()
                .filter(|package| {
                    package.name == name
                        && package.locator == locator
                        && package.integrity == integrity
                })
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                anyhow::bail!(
                    "authenticated package principal {locator} has {} installed roots",
                    matches.len()
                );
            }
            let package_root = matches[0].root.clone();
            let object = runtime_object_identity_json(&package_root)?;
            let package_components = runtime_path_components_json(&package_root)?;
            package_bindings.push(serde_json::json!({
                    "logicalRoot": "package",
                    "owner": principal,
                    "hostPath": {"root": "absolute", "components": package_components, "hostBound": true},
                    "object": object,
                }));
        }
    }
    let principals_by_locator = policy_principals
        .iter()
        .filter_map(|row| {
            Some((
                row["principal"]["locator"].as_str()?.to_string(),
                row["principal"].clone(),
            ))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for row in policy_principals {
        let importer = row["principal"].clone();
        for locator in row["imports"]["packages"]
            .as_array()
            .context("canonical package imports must be an array")?
        {
            let locator = locator
                .as_str()
                .context("canonical package import must be a locator string")?;
            let imported = principals_by_locator.get(locator).with_context(|| {
                format!("canonical policy imports unknown package locator {locator}")
            })?;
            graph_edges.push(serde_json::json!({
                "importer": importer,
                "imported": imported,
            }));
        }
    }
    endowment_groups.sort();
    let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/armed-snapshot.canonical.json"
    )))?;
    value["workflow"] = serde_json::json!("production");
    value["effectiveMode"] = serde_json::json!("enforce");
    value["policyDigest"] = serde_json::json!(policy_digest);
    value["engine"] = serde_json::json!({
        "target": exact_runtime_target(),
        "binaryDigest": engine_digest,
        "features": observed_structural_features(),
    });
    value["packageGraph"] = serde_json::json!({
        "digest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "nodes": graph_nodes,
        "importEdges": graph_edges,
    });
    let graph_digest = compute_domain_digest(
        "ibex:capsec:package-graph:1",
        &value["packageGraph"],
        &["digest".to_string()],
    )?;
    value["packageGraph"]["digest"] = serde_json::json!(graph_digest);
    value["principals"] = serde_json::Value::Array(snapshot_principals);
    let mut epoch = [0u8; 8];
    getrandom::getrandom(&mut epoch).context("failed to generate CapSec channel epoch")?;
    value["channelEpoch"] = serde_json::json!(u64::from_le_bytes(epoch).max(1).to_string());
    let mut root_bindings = vec![serde_json::json!({
        "logicalRoot": "project",
        "hostPath": {"root": "absolute", "components": components, "hostBound": true},
        "object": root_object,
    })];
    let cache_root = runtime_cache_dir()?;
    std::fs::create_dir_all(&cache_root)?;
    let cache_root = std::fs::canonicalize(cache_root)?;
    let cache_components = runtime_path_components_json(&cache_root)?;
    let cache_object = runtime_object_identity_json(&cache_root)?;
    root_bindings.push(serde_json::json!({
        "logicalRoot": "home",
        "hostPath": {"root": "absolute", "components": cache_components, "hostBound": true},
        "object": cache_object,
    }));
    root_bindings.extend(package_bindings);
    value["rootBindings"] = serde_json::Value::Array(root_bindings);
    let policy_bytes = capsec_semantics::canonical::to_jcs_bytes(&policy)?;
    let graph_bytes = capsec_semantics::canonical::to_jcs_bytes(&value["packageGraph"])?;
    let registry_record = serde_json::json!({
        "registryDigest": value["registryDigest"],
        "capabilityDefinitions": serde_json::from_str::<serde_json::Value>(
            ibex_runtime::capsec_registry_generated::CAPSEC_CAPABILITY_DEFINITIONS_JSON,
        )?,
        "coverageEdges": serde_json::from_str::<serde_json::Value>(
            ibex_runtime::capsec_registry_generated::CAPSEC_COVERAGE_EDGES_JSON,
        )?,
        "targetCells": serde_json::from_str::<serde_json::Value>(
            ibex_runtime::capsec_registry_generated::CAPSEC_TARGET_CELLS_JSON,
        )?,
        "policyRules": serde_json::from_str::<serde_json::Value>(
            ibex_runtime::capsec_registry_generated::CAPSEC_POLICY_RULES_JSON,
        )?,
    });
    let registry_bytes = capsec_semantics::canonical::to_jcs_bytes(&registry_record)?;
    let policy_object = materialize_protected_artifact(
        &cache_root,
        "armed-policy",
        value["policyDigest"]
            .as_str()
            .context("policy digest missing")?,
        &policy_bytes,
    )?;
    let graph_object = materialize_protected_artifact(
        &cache_root,
        "package-graph",
        value["packageGraph"]["digest"]
            .as_str()
            .context("package graph digest missing")?,
        &graph_bytes,
    )?;
    let registry_object = materialize_protected_artifact(
        &cache_root,
        "registry",
        value["registryDigest"]
            .as_str()
            .context("registry digest missing")?,
        &registry_bytes,
    )?;
    value["protectedObjects"] = serde_json::json!([
        {"role": "armed-policy", "object": policy_object.object, "deniedActions": ["fs:write"]},
        {"role": "engine-binary", "object": engine_object, "deniedActions": ["fs:write"]},
        {"role": "package-graph", "object": graph_object.object, "deniedActions": ["fs:write"]},
        {"role": "registry", "object": registry_object.object, "deniedActions": ["fs:write"]},
    ]);
    finalize_production_snapshot(&mut value)?;
    let digest_at = |path: &[&str]| -> Result<Digest> {
        let field = path
            .iter()
            .fold(&value, |current, segment| &current[*segment]);
        Digest::new(field.as_str().context("missing default arming digest")?)
            .map_err(anyhow::Error::msg)
    };
    let engine_host_path = serde_json::from_value(serde_json::json!({
        "root": "absolute",
        "components": runtime_path_components_json(&engine_identity.engine_artifact_path)?,
        "hostBound": true,
    }))?;
    let expected = ExpectedArmingIdentity {
        profile: value["capsVocab"].as_str().unwrap().into(),
        semantic_core: value["semanticCore"].as_str().unwrap().into(),
        vocab_digest: digest_at(&["vocabDigest"])?,
        registry_digest: digest_at(&["registryDigest"])?,
        policy_digest: digest_at(&["policyDigest"])?,
        armed_snapshot_digest: Digest::new(
            value["armedSnapshotDigest"]
                .as_str()
                .context("missing armed snapshot digest")?,
        )
        .map_err(anyhow::Error::msg)?,
        target: value["engine"]["target"].as_str().unwrap().into(),
        engine_binary_digest: digest_at(&["engine", "binaryDigest"])?,
        features: value["engine"]["features"]
            .as_array()
            .unwrap()
            .iter()
            .map(|feature| feature.as_str().unwrap().into())
            .collect(),
        package_graph_digest: digest_at(&["packageGraph", "digest"])?,
        protected_artifacts: vec![
            capsec_semantics::arming::ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::ArmedPolicy,
                host_path: policy_object.host_path,
                object: serde_json::from_value(value["protectedObjects"][0]["object"].clone())?,
                content_digest: policy_object.content_digest,
            },
            capsec_semantics::arming::ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::EngineBinary,
                host_path: engine_host_path,
                object: engine_identity.object,
                content_digest: digest_at(&["engine", "binaryDigest"])?,
            },
            capsec_semantics::arming::ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::PackageGraph,
                host_path: graph_object.host_path,
                object: serde_json::from_value(value["protectedObjects"][2]["object"].clone())?,
                content_digest: graph_object.content_digest,
            },
            capsec_semantics::arming::ExpectedProtectedArtifact {
                role: capsec_semantics::arming::ProtectedArtifactRole::Registry,
                host_path: registry_object.host_path,
                object: serde_json::from_value(value["protectedObjects"][3]["object"].clone())?,
                content_digest: registry_object.content_digest,
            },
        ],
    };
    let snapshot = Arc::new(ArmedSnapshot::load(
        &serde_json::to_vec(&value)?,
        &expected,
    )?);
    let digest = snapshot.digest().as_str().to_owned();
    let host = Host::new_armed(
        HostConfig {
            mode: crate::host::SecurityMode::Enforce,
            ..Default::default()
        },
        snapshot,
    )?;
    Ok((host, Some(digest)))
}

fn exact_runtime_target() -> String {
    let architecture = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        "x86" => "i686",
        other => other,
    };
    let suffix = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "ios" => "apple-ios",
        "linux" => "unknown-linux-gnu",
        "android" => "linux-android",
        "windows" => "pc-windows-msvc",
        other => other,
    };
    format!("{architecture}-{suffix}")
}

fn observed_structural_features() -> Vec<String> {
    ibex_runtime::engine::loaded_engine_structural_features()
}

fn observed_arming_identity(
    mut supplied: capsec_semantics::arming::ExpectedArmingIdentity,
) -> Result<capsec_semantics::arming::ExpectedArmingIdentity> {
    use capsec_semantics::model::Digest;

    let compiled: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/armed-snapshot.canonical.json"
    )))?;
    supplied.profile = ibex_runtime::capsec_registry_generated::CAPSEC_PROFILE.into();
    supplied.semantic_core = ibex_runtime::capsec_registry_generated::CAPSEC_SEMANTIC_CORE.into();
    supplied.vocab_digest = Digest::new(
        compiled["vocabDigest"]
            .as_str()
            .context("compiled vocabulary digest is missing")?,
    )
    .map_err(anyhow::Error::msg)?;
    supplied.registry_digest = Digest::new(
        compiled["registryDigest"]
            .as_str()
            .context("compiled registry digest is missing")?,
    )
    .map_err(anyhow::Error::msg)?;
    supplied.target = exact_runtime_target();
    supplied.features = observed_structural_features();
    supplied.engine_binary_digest =
        Digest::new(crate::engine::hermes::HermesEngine::loaded_engine_identity()?.binary_digest)
            .map_err(anyhow::Error::msg)?;
    Ok(supplied)
}

/// Select the one project root whose object identity will be bound into the
/// generated armed snapshot. Discovery requires an authenticated manifest
/// ancestor; package-less layouts need an explicit trusted launcher input.
/// @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
fn authenticated_project_root(cli: &Cli, entry: Option<&str>) -> Result<std::path::PathBuf> {
    let entry_path = entry
        .map(|entry| {
            std::fs::canonicalize(entry)
                .with_context(|| format!("failed to authenticate entry path {entry}"))
        })
        .transpose()?;
    if let Some(explicit) = cli.project_root.as_deref() {
        let root = std::fs::canonicalize(explicit).with_context(|| {
            format!("failed to authenticate project root {}", explicit.display())
        })?;
        if !root.is_dir() {
            anyhow::bail!("project root is not a directory: {}", root.display());
        }
        if entry_path
            .as_ref()
            .is_some_and(|entry| !entry.starts_with(&root))
        {
            anyhow::bail!(
                "entry is outside the explicitly authenticated project root {}",
                root.display()
            );
        }
        return Ok(root);
    }

    let start = entry_path
        .as_deref()
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf)
        .unwrap_or(std::env::current_dir()?);
    let mut cursor = std::fs::canonicalize(&start)
        .with_context(|| format!("failed to authenticate project path {}", start.display()))?;
    loop {
        if cursor.join("package.json").is_file() {
            return Ok(cursor);
        }
        let Some(parent) = cursor.parent() else {
            break;
        };
        cursor = parent.to_path_buf();
    }
    anyhow::bail!(
        "no authenticated project root: pass --project-root or place the entry beneath a package.json"
    )
}

#[derive(Clone, Debug)]
struct InstalledPackageIdentity {
    name: String,
    locator: String,
    integrity: String,
    root: std::path::PathBuf,
}

fn authenticated_installed_packages(
    project_root: &std::path::Path,
    principals: &[serde_json::Value],
) -> Result<Vec<InstalledPackageIdentity>> {
    use std::collections::{BTreeSet, VecDeque};

    let wanted = principals
        .iter()
        .map(|row| {
            let principal = &row["principal"];
            Ok((
                principal["name"]
                    .as_str()
                    .context("package principal is missing name")?
                    .to_owned(),
                principal["locator"]
                    .as_str()
                    .context("package principal is missing locator")?
                    .to_owned(),
                principal["integrity"]
                    .as_str()
                    .context("package principal is missing integrity")?
                    .to_owned(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut queue = VecDeque::from([project_root.join("node_modules")]);
    let mut visited_node_modules = BTreeSet::new();
    let mut candidate_roots = BTreeSet::new();
    while let Some(node_modules) = queue.pop_front() {
        let canonical_nm = match std::fs::canonicalize(&node_modules) {
            Ok(path) => path,
            Err(_) => continue,
        };
        if !visited_node_modules.insert(canonical_nm.clone()) {
            continue;
        }
        let mut entries = std::fs::read_dir(&canonical_nm)
            .with_context(|| format!("failed to enumerate {}", canonical_nm.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name();
            let path = entry.path();
            if name == ".bin" {
                continue;
            }
            if name.to_string_lossy().starts_with('@') {
                let mut scoped = match std::fs::read_dir(&path) {
                    Ok(entries) => entries.collect::<std::io::Result<Vec<_>>>()?,
                    Err(_) => continue,
                };
                scoped.sort_by_key(std::fs::DirEntry::file_name);
                for package in scoped {
                    if package.path().join("package.json").is_file() {
                        let root = std::fs::canonicalize(package.path())?;
                        queue.push_back(root.join("node_modules"));
                        candidate_roots.insert(root);
                    }
                }
                continue;
            }
            if name == ".pnpm" {
                for store_entry in std::fs::read_dir(&path)? {
                    queue.push_back(store_entry?.path().join("node_modules"));
                }
                continue;
            }
            if path.join("package.json").is_file() {
                let root = std::fs::canonicalize(path)?;
                queue.push_back(root.join("node_modules"));
                candidate_roots.insert(root);
            }
        }
    }

    let mut discovered = Vec::new();
    for root in candidate_roots {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("package.json"))?)
                .with_context(|| format!("invalid package manifest in {}", root.display()))?;
        let Some(name) = manifest.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let locator = manifest
            .get("version")
            .and_then(serde_json::Value::as_str)
            .map(|version| format!("{name}@{version}"))
            .unwrap_or_else(|| name.to_owned());
        let matches_any = wanted.iter().any(|(wanted_name, wanted_locator, _)| {
            wanted_name == name && wanted_locator == &locator
        });
        if !matches_any {
            continue;
        }
        let integrity = crate::module_loader::package_tree_integrity(&root)
            .with_context(|| format!("failed to authenticate package tree {}", root.display()))?;
        discovered.push(InstalledPackageIdentity {
            name: name.to_owned(),
            locator,
            integrity,
            root,
        });
    }

    for (name, locator, integrity) in &wanted {
        let candidates = discovered
            .iter()
            .filter(|package| &package.name == name && &package.locator == locator)
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            anyhow::bail!(
                "package principal {locator} resolved to {} installed roots; duplicate name+locator roots are ambiguous even when only one integrity matches",
                candidates.len()
            );
        }
        if &candidates[0].integrity != integrity {
            anyhow::bail!(
                "package principal {locator} has installed integrity {}, expected {integrity}",
                candidates[0].integrity
            );
        }
    }
    Ok(discovered)
}

fn runtime_object_identity_json(path: &std::path::Path) -> Result<serde_json::Value> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to identify {}", path.display()))?;
    runtime_object_identity_from_metadata(&metadata)
}

fn runtime_object_identity_from_metadata(
    metadata: &std::fs::Metadata,
) -> Result<serde_json::Value> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Ok(serde_json::json!({
            "platform": if cfg!(any(target_os = "macos", target_os = "ios")) {
                "apple"
            } else if cfg!(target_os = "android") {
                "android"
            } else {
                "unix"
            },
            "volume": format!("dev:{}", metadata.dev()),
            "file": format!("ino:{}", metadata.ino()),
        }));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Ok(serde_json::json!({
            "platform": "windows",
            "volume": format!("volume:{}", metadata.volume_serial_number().unwrap_or(0)),
            "file": format!("file:{}", metadata.file_index().unwrap_or(0)),
        }))
    }
}

fn runtime_path_components_json(path: &std::path::Path) -> Result<Vec<serde_json::Value>> {
    use std::path::Component;

    path.components()
        .filter_map(|component| match component {
            Component::Prefix(prefix) => Some(runtime_path_component_json(prefix.as_os_str())),
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir => Some(Err(anyhow::anyhow!(
                "authenticated runtime path contains an unresolved parent component"
            ))),
            Component::Normal(value) => Some(runtime_path_component_json(value)),
        })
        .collect()
}

fn runtime_path_component_json(value: &std::ffi::OsStr) -> Result<serde_json::Value> {
    let component = if let Some(value) = value.to_str() {
        capsec_semantics::model::PathComponent::utf8(value.to_owned())
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            capsec_semantics::model::PathComponent::binary(value.as_bytes().to_vec())
        }
        #[cfg(not(unix))]
        {
            return Err(anyhow::anyhow!(
                "non-Unicode runtime path cannot be represented on this target"
            ));
        }
    }
    .map_err(anyhow::Error::msg)?;
    serde_json::to_value(component).map_err(Into::into)
}

#[derive(Debug)]
struct MaterializedProtectedArtifact {
    host_path: capsec_semantics::model::LogicalPath,
    object: serde_json::Value,
    content_digest: capsec_semantics::model::Digest,
}

fn materialize_protected_artifact(
    cache_root: &std::path::Path,
    role: &str,
    digest: &str,
    bytes: &[u8],
) -> Result<MaterializedProtectedArtifact> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    use std::io::{Read as _, Seek as _, Write as _};

    fn validate_pinned_artifact(
        file: &mut std::fs::File,
        expected: &[u8],
        path: &std::path::Path,
    ) -> Result<serde_json::Value> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            anyhow::bail!(
                "protected artifact is not a regular file: {}",
                path.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o222 != 0 {
                anyhow::bail!("protected artifact is mutable: {}", path.display());
            }
        }
        #[cfg(not(unix))]
        if !metadata.permissions().readonly() {
            anyhow::bail!("protected artifact is mutable: {}", path.display());
        }
        file.rewind()?;
        let mut observed = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut observed)?;
        if observed != expected {
            anyhow::bail!("protected artifact content mismatch at {}", path.display());
        }
        runtime_object_identity_from_metadata(&metadata)
    }

    let directory = cache_root.join("capsec-artifacts");
    std::fs::create_dir_all(&directory)?;
    let directory_metadata = std::fs::symlink_metadata(&directory)?;
    if !directory_metadata.is_dir() || directory_metadata.file_type().is_symlink() {
        anyhow::bail!(
            "protected artifact parent is not a stable directory: {}",
            directory.display()
        );
    }
    let directory = std::fs::canonicalize(directory)?;
    let filename_digest = digest
        .strip_prefix("sha256-")
        .unwrap_or(digest)
        .replace(|character: char| !character.is_ascii_alphanumeric(), "_");
    let path = directory.join(format!("{filename_digest}.{role}.json"));

    let open_existing = || -> Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        options
            .open(&path)
            .with_context(|| format!("failed to pin protected artifact {}", path.display()))
    };

    let object = if path.exists() {
        let mut file = open_existing()?;
        validate_pinned_artifact(&mut file, bytes, &path)?
    } else {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .context("failed to name protected artifact staging file")?;
        let temporary = directory.join(format!(
            ".{filename_digest}.{role}.{}.tmp",
            URL_SAFE_NO_PAD.encode(nonce)
        ));
        let mut staged = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let publish_result = (|| -> Result<serde_json::Value> {
            staged.write_all(bytes)?;
            staged.sync_all()?;
            let mut permissions = staged.metadata()?.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                permissions.set_mode(0o400);
            }
            #[cfg(not(unix))]
            permissions.set_readonly(true);
            staged.set_permissions(permissions)?;
            staged.sync_all()?;
            let identity = validate_pinned_artifact(&mut staged, bytes, &temporary)?;

            match std::fs::hard_link(&temporary, &path) {
                Ok(()) => {
                    std::fs::File::open(&directory)?.sync_all()?;
                    Ok(identity)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let mut existing = open_existing()?;
                    validate_pinned_artifact(&mut existing, bytes, &path)
                }
                Err(error) => Err(error.into()),
            }
        })();
        let _ = std::fs::remove_file(&temporary);
        publish_result?
    };
    let path = std::fs::canonicalize(&path)?;
    let host_path = serde_json::from_value(serde_json::json!({
        "root": "absolute",
        "components": runtime_path_components_json(&path)?,
        "hostBound": true,
    }))?;
    let content_digest = capsec_semantics::model::Digest::new(format!(
        "sha256-{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
    .map_err(anyhow::Error::msg)?;
    Ok(MaterializedProtectedArtifact {
        host_path,
        object,
        content_digest,
    })
}

/// Ad-hoc evaluation and runtime-registry diagnostics are separate diagnostic
/// workflows, not production entry surfaces. Reject them before arming
/// artifacts, Hermes allocation, or project code can be observed.
/// @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
pub(crate) fn reject_closed_production_cli(cli: &Cli) -> Result<()> {
    let closed_command = matches!(
        cli.command.as_ref(),
        Some(crate::cli::Commands::Eval { .. })
            | Some(crate::cli::Commands::Repl)
            | Some(crate::cli::Commands::Debug { .. })
    );
    let implicit_repl = cli.command.is_none()
        && cli.file.is_none()
        && cli.eval_code.is_none()
        && cli.print_eval.is_none();
    if cli.eval_code.is_some() || cli.print_eval.is_some() || closed_command || implicit_repl {
        anyhow::bail!(
            "production capability enforcement closes ad-hoc evaluation, REPL, and debug commands"
        );
    }
    Ok(())
}

fn validate_runtime_inputs(cli: &Cli, reject_closed_environment: bool) -> Result<()> {
    reject_closed_production_cli(cli)?;
    if crate::runtime_env("IBEX_POLICY", "EXACT_POLICY").is_some() {
        anyhow::bail!("environment-selected policy paths are forbidden in production");
    }
    if reject_closed_environment {
        crate::host::reject_closed_startup_environment()?;
    }
    if cli.allow_all
        || matches!(
            cli.capsec,
            crate::cli::CapSecMode::Audit | crate::cli::CapSecMode::Permissive
        )
        || !cli.allow.is_empty()
        || !cli.deny.is_empty()
        || cli.allow_env_endowments
        || cli.capsec_allow_advisory
        || crate::env_flag_enabled("IBEX_CAPSEC_ALLOW_ADVISORY")
    {
        anyhow::bail!(
            "production capability enforcement rejects legacy allow/deny, environment endowment widening, and advisory-attribution overrides"
        );
    }
    let run_inspector = matches!(
        cli.command.as_ref(),
        Some(crate::cli::Commands::Run { inspect: true, .. })
            | Some(crate::cli::Commands::Run {
                inspect_wait: true,
                ..
            })
            | Some(crate::cli::Commands::Run {
                inspect_open: true,
                ..
            })
            | Some(crate::cli::Commands::Run {
                inspect_pause: true,
                ..
            })
            | Some(crate::cli::Commands::Run {
                inspect_port: Some(_),
                ..
            })
            | Some(crate::cli::Commands::Run {
                inspect_host: Some(_),
                ..
            })
    );
    if cli.compat.is_some()
        || cli.inspect
        || cli.inspect_wait
        || cli.inspect_open
        || cli.inspect_pause
        || cli.inspect_port.is_some()
        || cli.inspect_host.is_some()
        || cli.expose_internals
        || cli.stack_size.is_some()
        || cli.max_http_header_size.is_some()
        || run_inspector
    {
        anyhow::bail!(
            "production capability enforcement closes compatibility, inspector, and runtime-fidelity overrides"
        );
    }
    Ok(())
}

pub(crate) fn validate_production_inputs(cli: &Cli) -> Result<()> {
    validate_runtime_inputs(cli, true)
}

/// The separately named foreground audit is the diagnostic channel for
/// exercising legacy startup branches. It retains every CLI/policy restriction
/// above, but does not apply the production registry's ambient-control closure.
/// @ref LLP 0021#default-execution-contract
fn validate_diagnostic_audit_inputs(cli: &Cli) -> Result<()> {
    validate_runtime_inputs(cli, false)
}

/// Apply the enforce/audit isolation prerequisite (per-package chunking) for the
/// `ibex build` path, mirroring what `build_host_config` does for a run. Without
/// this, a build under an enforce policy compiles a flat single-Domain bundle and
/// the resulting `.hbc`, run under `--capsec enforce`, attributes every
/// `node_modules` frame to the trusted root — the capability gate never fires for
/// a dependency. Returns the resolved mode (Enforce/Audit imply chunking).
/// @ref LLP 0013#mechanism-3 — (ENG-22760)
pub(crate) fn apply_build_isolation(cli: &Cli) -> Result<crate::host::SecurityMode> {
    validate_production_inputs(cli)?;
    if cli.capsec == crate::cli::CapSecMode::Audit {
        anyhow::bail!("foreground audit cannot be persisted as a production build posture");
    }
    let mode = crate::host::SecurityMode::Enforce;
    for line in
        check_capsec_readiness(mode, CapsecStage::Build, capsec_readiness(cli, None), false)?
    {
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
    _cli: &Cli,
    policy: Option<&crate::host::policy::PolicyFile>,
) -> CapsecReadiness {
    let package_isolation = PackageIsolation::Enabled;
    let dynamic_ceiling = policy
        .map(|policy| !policy.ceiling.is_empty())
        .unwrap_or(false);
    CapsecReadiness {
        frame_attribution: cfg!(exact_frame_attribution),
        package_isolation,
        lockdown: true,
        dynamic_ceiling,
    }
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
    _allow_advisory: bool,
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
    if !readiness.lockdown {
        hard.push(
            "structural runtime lockdown (shared intrinsics would remain mutable)".to_string(),
        );
    }

    if hard.is_empty() && soft.is_empty() {
        return Ok(vec![report]);
    }

    if mode == SecurityMode::Enforce && !hard.is_empty() {
        anyhow::bail!(
            "capsec enforce requires attribution prerequisites this {} does not satisfy:\n  - {}\n{}\n\
             Refusing to present advisory attribution as enforcement; use the separately named \
             foreground capsec audit workflow for diagnostics.",
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
pub async fn prepare_entry_with_format(
    entry: &str,
    bundle_format: BundleFormat,
) -> Result<PathBuf> {
    prepare_entry_with_format_and_bytecode(entry, bundle_format, true).await
}

/// Prepare source for the build command. The build command is itself producing
/// the requested HBC, so feeding it an entry-cache HBC would ask hermesc to
/// compile bytecode as JavaScript and would also lose the bundle directory
/// containing per-package chunks.
pub async fn prepare_entry_for_bytecode_build(
    entry: &str,
    bundle_format: BundleFormat,
) -> Result<PathBuf> {
    prepare_entry_with_format_and_bytecode(entry, bundle_format, false).await
}

async fn prepare_entry_with_format_and_bytecode(
    entry: &str,
    bundle_format: BundleFormat,
    allow_bytecode: bool,
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
    let artifact_root = bundle_artifact_root(&cache_dir, &cache_key);

    if let Some(output) = find_fresh_bundle(&artifact_root, &path, bundle_format).await {
        // Bundle is cached. Try bytecode if not already known incompatible.
        if allow_bytecode
            && !BYTECODE_INCOMPATIBLE.load(Ordering::Relaxed)
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
    let artifact_root = if effective_format != bundle_format {
        let new_key = bundle_cache_key(&path, effective_format)?;
        bundle_artifact_root(&cache_dir, &new_key)
    } else {
        artifact_root
    };

    if let Some(output) = find_fresh_bundle(&artifact_root, &path, effective_format).await {
        return if allow_bytecode
            && !BYTECODE_INCOMPATIBLE.load(Ordering::Relaxed)
            && crate::runtime_env("IBEX_NO_BYTECODE", "EX_NO_BYTECODE").is_none()
        {
            prepare_bytecode_entry(&output).await.or(Ok(output))
        } else {
            Ok(output)
        };
    }

    let prepared = match run_bundler(&path, &artifact_root, effective_format).await {
        Ok(output) => output,
        Err(err) => {
            let err_msg = format!("{}", err);
            // If rolldown rejects TLA in CJS mode (e.g. await inside for/if/while
            // blocks that our heuristic missed), retry with ESM format.
            if effective_format == BundleFormat::Cjs && err_msg.contains("Top-level await") {
                let esm_key = bundle_cache_key(&path, BundleFormat::Esm)?;
                let esm_root = bundle_artifact_root(&cache_dir, &esm_key);
                match run_bundler(&path, &esm_root, BundleFormat::Esm).await {
                    Ok(output) => output,
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
    if !allow_bytecode
        || BYTECODE_INCOMPATIBLE.load(Ordering::Relaxed)
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
    let mut path = output.as_os_str().to_os_string();
    path.push(".deps.json");
    PathBuf::from(path)
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleDigestRecord {
    path: String,
    sha256: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct BundleResolutionInput {
    kind: String,
    path: String,
    sha256: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleCacheManifest {
    version: u32,
    entry: String,
    resolution_digest: String,
    graph_digest: String,
    deps: Vec<BundleDigestRecord>,
    outputs: Vec<BundleDigestRecord>,
    resolution_inputs: Vec<BundleResolutionInput>,
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

async fn sha256_file(path: &Path) -> Result<String> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("Failed to hash {}", path.display()))?;
    Ok(sha256_bytes(&bytes))
}

async fn read_bundle_manifest(output: &Path) -> Result<BundleCacheManifest> {
    let raw = tokio::fs::read(deps_manifest_path(output))
        .await
        .context("read bundle cache manifest")?;
    serde_json::from_slice(&raw).context("parse bundle cache manifest")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn bundle_resolution_input_digest(input: &BundleResolutionInput) -> Option<String> {
    let path = Path::new(&input.path);
    match input.kind.as_str() {
        "file" => std::fs::read(path).ok().map(|bytes| sha256_bytes(&bytes)),
        "symlink" => std::fs::read_link(path)
            .ok()
            .and_then(|target| target.to_str().map(|value| sha256_bytes(value.as_bytes()))),
        "missing" => match std::fs::symlink_metadata(path) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                Some(sha256_bytes(b"missing"))
            }
            _ => None,
        },
        "directory" => {
            let mut entries = std::fs::read_dir(path)
                .ok()?
                .collect::<std::io::Result<Vec<_>>>()
                .ok()?;
            entries.sort_by(|left, right| {
                left.file_name()
                    .to_str()
                    .unwrap_or("")
                    .as_bytes()
                    .cmp(right.file_name().to_str().unwrap_or("").as_bytes())
            });
            let mut encoded = Vec::new();
            for entry in entries {
                let name = entry.file_name();
                let name = name.to_str()?;
                let metadata = std::fs::symlink_metadata(entry.path()).ok()?;
                let kind = if metadata.file_type().is_symlink() {
                    b'l'
                } else if metadata.is_dir() {
                    b'd'
                } else if metadata.is_file() {
                    b'f'
                } else {
                    b'o'
                };
                encoded.push(kind);
                encoded.push(0);
                encoded.extend_from_slice(name.as_bytes());
                encoded.push(0);
                if metadata.file_type().is_symlink() {
                    let target = std::fs::read_link(entry.path()).ok()?;
                    encoded.extend_from_slice(target.to_str()?.as_bytes());
                }
                encoded.push(b'\n');
            }
            Some(sha256_bytes(&encoded))
        }
        _ => None,
    }
}

fn normalized_relative_artifact_path(path: &Path) -> Option<String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return None;
    }
    Some(
        path.components()
            .filter_map(|component| match component {
                std::path::Component::Normal(part) => Some(part.to_string_lossy()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn collect_bundle_output_files(root: &Path, current: &Path, files: &mut Vec<String>) -> bool {
    let Ok(entries) = std::fs::read_dir(current) else {
        return false;
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            return false;
        };
        let Ok(relative) = path.strip_prefix(root) else {
            return false;
        };
        let Some(relative_string) = normalized_relative_artifact_path(relative) else {
            return false;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if metadata.file_type().is_symlink() {
            // Published generated code is immutable regular-file content; a
            // symlink could retarget after digest verification.
            return false;
        }
        if metadata.is_dir() {
            // Derived bytecode/control directories are not bundler outputs.
            if name.starts_with('.') {
                continue;
            }
            if !collect_bundle_output_files(root, &path, files) {
                return false;
            }
        } else if metadata.is_file() {
            if name == ".last-used"
                || name == ".lease"
                || relative_string.ends_with(".deps.json")
                || relative_string.ends_with(".hbc")
                || relative_string.ends_with(".hbc.meta.json")
            {
                continue;
            }
            files.push(relative_string);
        } else {
            return false;
        }
    }
    true
}

/// A cached bundle is fresh only when every dependency and every output still
/// matches the SHA-256 digest committed by its v2 manifest. File size and mtime
/// are never source identity (ENG-24257).
async fn bundle_cache_is_fresh(output: &Path, entry: &Path) -> bool {
    if !output.is_file() {
        return false;
    }
    let Ok(manifest) = read_bundle_manifest(output).await else {
        return false;
    };
    if manifest.version != 3
        || !valid_sha256(&manifest.graph_digest)
        || !valid_sha256(&manifest.resolution_digest)
    {
        return false;
    }
    let canonical_entry = std::fs::canonicalize(entry).unwrap_or_else(|_| entry.to_path_buf());
    let manifest_entry =
        std::fs::canonicalize(&manifest.entry).unwrap_or_else(|_| PathBuf::from(&manifest.entry));
    if canonical_entry != manifest_entry {
        return false;
    }

    if manifest.resolution_inputs.is_empty() {
        return false;
    }
    let mut previous_resolution: Option<(&str, &str)> = None;
    for input in &manifest.resolution_inputs {
        if !Path::new(&input.path).is_absolute() || !valid_sha256(&input.sha256) {
            return false;
        }
        let ordering_key = (input.path.as_str(), input.kind.as_str());
        if previous_resolution.is_some_and(|previous| previous >= ordering_key) {
            return false;
        }
        previous_resolution = Some(ordering_key);
        if bundle_resolution_input_digest(input).as_deref() != Some(input.sha256.as_str()) {
            return false;
        }
    }
    let Ok(encoded_resolution) = serde_json::to_vec(&manifest.resolution_inputs) else {
        return false;
    };
    if sha256_bytes(&encoded_resolution) != manifest.resolution_digest {
        return false;
    }

    if manifest.deps.is_empty() {
        return false;
    }
    let mut previous_dep: Option<&str> = None;
    let canonical_entry_string = canonical_entry.to_string_lossy();
    let mut includes_entry = false;
    for dep in &manifest.deps {
        if !valid_sha256(&dep.sha256)
            || previous_dep.is_some_and(|previous| previous >= dep.path.as_str())
        {
            return false;
        }
        previous_dep = Some(&dep.path);
        let path = Path::new(&dep.path);
        let Ok(canonical_dep) = std::fs::canonicalize(path) else {
            return false;
        };
        if canonical_dep.to_string_lossy() != dep.path {
            return false;
        }
        includes_entry |= dep.path == canonical_entry_string;
        let Ok(digest) = sha256_file(path).await else {
            return false;
        };
        if digest != dep.sha256 {
            return false;
        }
    }
    if !includes_entry {
        return false;
    }
    let Ok(encoded_deps) = serde_json::to_vec(&manifest.deps) else {
        return false;
    };
    if sha256_bytes(&encoded_deps) != manifest.graph_digest {
        return false;
    }

    let Some(artifact_dir) = output.parent() else {
        return false;
    };
    if manifest.outputs.is_empty() {
        return false;
    }
    let Some(expected_entry_output) = output
        .strip_prefix(artifact_dir)
        .ok()
        .and_then(normalized_relative_artifact_path)
    else {
        return false;
    };
    let mut previous_output: Option<&str> = None;
    let mut includes_output = false;
    let mut expected_files = Vec::with_capacity(manifest.outputs.len());
    for artifact in &manifest.outputs {
        let relative = Path::new(&artifact.path);
        let Some(normalized) = normalized_relative_artifact_path(relative) else {
            return false;
        };
        if normalized != artifact.path
            || !valid_sha256(&artifact.sha256)
            || previous_output.is_some_and(|previous| previous >= artifact.path.as_str())
        {
            return false;
        }
        previous_output = Some(&artifact.path);
        includes_output |= artifact.path == expected_entry_output;
        let Ok(digest) = sha256_file(&artifact_dir.join(relative)).await else {
            return false;
        };
        if digest != artifact.sha256 {
            return false;
        }
        expected_files.push(artifact.path.clone());
    }
    if !includes_output {
        return false;
    }
    let mut actual_files = Vec::new();
    if !collect_bundle_output_files(artifact_dir, artifact_dir, &mut actual_files) {
        return false;
    }
    actual_files.sort();
    if actual_files != expected_files {
        return false;
    }

    true
}

#[cfg(test)]
fn bytecode_manifest_path(bytecode: &Path) -> PathBuf {
    let mut path = bytecode.as_os_str().to_os_string();
    path.push(".meta.json");
    PathBuf::from(path)
}

async fn bytecode_cache_is_fresh(source: &Path, bytecode: &Path) -> bool {
    engine::hermes::bytecode_artifact_is_fresh(source, bytecode).await
}

fn touch_bytecode_artifact(artifact_dir: &Path) {
    std::fs::write(artifact_dir.join(".last-used"), []).ok();
}

fn is_bytecode_cache_key(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.len() == 64
            && name
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    })
}

fn ensure_bytecode_cache_root(cache_parent: &Path) -> Result<PathBuf> {
    let cache_parent = cache_parent.to_path_buf();
    std::fs::create_dir_all(&cache_parent).with_context(|| {
        format!(
            "Failed to create runtime cache directory {}",
            cache_parent.display()
        )
    })?;
    let cache_parent = std::fs::canonicalize(&cache_parent).with_context(|| {
        format!(
            "Failed to authenticate runtime cache directory {}",
            cache_parent.display()
        )
    })?;
    let cache_root = cache_parent.join(".bytecode-cache");
    match std::fs::symlink_metadata(&cache_root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(&cache_root) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(
                            &cache_root,
                            std::fs::Permissions::from_mode(0o700),
                        )?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("Failed to create bytecode cache {}", cache_root.display())
                    })
                }
            }
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(&cache_root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "Bytecode cache root must be a real directory, not a symlink or file: {}",
            cache_root.display()
        );
    }
    let authenticated = std::fs::canonicalize(&cache_root).with_context(|| {
        format!(
            "Failed to authenticate bytecode cache {}",
            cache_root.display()
        )
    })?;
    if authenticated.parent() != Some(cache_parent.as_path()) {
        anyhow::bail!(
            "Bytecode cache {} escapes runtime cache {}",
            authenticated.display(),
            cache_parent.display()
        );
    }
    Ok(authenticated)
}

fn bytecode_cache_parent_for_source(source: &Path) -> Result<PathBuf> {
    let runtime_root = runtime_cache_dir()?;
    std::fs::create_dir_all(&runtime_root)?;
    let runtime_root = std::fs::canonicalize(runtime_root)?;
    let bundles_root = runtime_root.join("bundles");
    if source.starts_with(&bundles_root) {
        return source
            .parent()
            .map(Path::to_path_buf)
            .context("bundle cache source has no parent");
    }
    Ok(runtime_root)
}

fn cleanup_abandoned_bytecode_temp_dirs(cache_root: &Path) {
    let Ok(entries) = std::fs::read_dir(cache_root) else {
        return;
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let owner = [".stage-", ".invalid-", ".evict-"]
            .iter()
            .find_map(|prefix| {
                name.strip_prefix(prefix)
                    .and_then(|rest| rest.split('-').next())
                    .and_then(|pid| pid.parse::<u32>().ok())
            });
        if owner.is_some_and(|pid| !process_is_running(pid)) {
            std::fs::remove_dir_all(entry.path()).ok();
        }
    }
}

fn prune_bytecode_cache_to_limit(cache_root: &Path, keep: &Path, limit: u64) {
    cleanup_abandoned_bytecode_temp_dirs(cache_root);
    let Ok(entries) = std::fs::read_dir(cache_root) else {
        return;
    };
    let mut artifacts = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let file_type = entry.file_type().ok()?;
            if path == keep || !file_type.is_dir() || !is_bytecode_cache_key(&entry.file_name()) {
                return None;
            }
            let metadata = entry.metadata().ok()?;
            let recency = std::fs::metadata(path.join(".last-used"))
                .and_then(|marker| marker.modified())
                .or_else(|_| metadata.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            Some((recency, cached_directory_size(&path), path))
        })
        .collect::<Vec<_>>();
    let mut total = cached_directory_size(cache_root);
    artifacts.sort_by_key(|(modified, _, _)| *modified);
    for (_, size, path) in artifacts {
        if total <= limit {
            break;
        }
        let Ok(Some(gate)) = try_acquire_bundle_artifact_gate(&path) else {
            continue;
        };
        if bundle_artifact_has_live_lease(&path) {
            drop(gate);
            continue;
        }
        let quarantine = cache_root.join(format!(
            ".evict-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0),
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("artifact")
        ));
        let renamed = std::fs::rename(&path, &quarantine).is_ok();
        drop(gate);
        if renamed && std::fs::remove_dir_all(&quarantine).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

fn enforce_bytecode_cache_quota(cache_root: &Path, keep: &Path) {
    const DEFAULT_LIMIT: u64 = 256 * 1024 * 1024;
    let limit = std::env::var("IBEX_BYTECODE_CACHE_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LIMIT);
    prune_bytecode_cache_to_limit(cache_root, keep, limit);
}

async fn prepare_bytecode_entry(entry: &Path) -> Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let source_identity = std::fs::canonicalize(entry)
        .with_context(|| format!("Failed to authenticate bytecode source {}", entry.display()))?;
    // A bundle-cache source may be evicted by another process. Hold its shared
    // lease through the single source read, compilation, and HBC publication.
    let _source_lease = acquire_bundle_execution_lease(&source_identity).await?;
    let source = tokio::fs::read(&source_identity).await?;
    let source_digest_before = sha256_bytes(&source);
    // Generated-code caches fail closed unless the mapped runtime binary can
    // be attested. Explicit `ibex build` output is not a cache and remains
    // available on platforms (currently Windows) without mapped-module
    // identity support; the cache-specific gate belongs here, not in the
    // generic compiler wrapper.
    ibex_runtime::engine::loaded_engine_binary_identity()
        .map_err(anyhow::Error::msg)
        .context("cannot authenticate the loaded Hermes engine for bytecode cache use")?;
    let toolchain_identity = engine::hermes::bytecode_cache_identity();
    let source_path = source_identity
        .to_str()
        .context("bytecode cache does not support non-UTF-8 source paths")?;
    let cache_key = sha256_bytes(
        format!("bytecode-cache-v3\0{source_path}\0{source_digest_before}\0{toolchain_identity}")
            .as_bytes(),
    );
    let cache_parent = bytecode_cache_parent_for_source(&source_identity)?;
    let cache_root = ensure_bytecode_cache_root(&cache_parent)?;
    let final_dir = cache_root.join(&cache_key);
    let hbc_path = final_dir.join("entry.hbc");
    if bytecode_cache_is_fresh(&source_identity, &hbc_path).await {
        touch_bytecode_artifact(&final_dir);
        return Ok(hbc_path);
    }

    tokio::fs::create_dir_all(&cache_root).await?;
    let seq = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let stage_dir = cache_root.join(format!(
        ".stage-{}-{seq}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    tokio::fs::create_dir(&stage_dir).await?;
    let stage_hbc = stage_dir.join("entry.hbc");
    if let Err(error) =
        engine::hermes::compile_source_to_bytecode(&source_identity, &source, &stage_hbc, None)
            .await
    {
        tokio::fs::remove_dir_all(&stage_dir).await.ok();
        return Err(error);
    }
    let source_digest_after = sha256_file(&source_identity).await?;
    if source_digest_before != source_digest_after {
        tokio::fs::remove_dir_all(&stage_dir).await.ok();
        anyhow::bail!(
            "Source changed while compiling bytecode for {}",
            source_identity.display()
        );
    }

    let gate = acquire_bundle_artifact_gate(&final_dir).await?;
    let mut quarantine = None;
    if final_dir.exists() {
        if bytecode_cache_is_fresh(&source_identity, &hbc_path).await {
            tokio::fs::remove_dir_all(&stage_dir).await.ok();
            touch_bytecode_artifact(&final_dir);
            return Ok(hbc_path);
        }
        let invalid = cache_root.join(format!(
            ".invalid-{}-{}-{seq}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        tokio::fs::rename(&final_dir, &invalid).await?;
        quarantine = Some(invalid);
    }
    if let Err(error) = tokio::fs::rename(&stage_dir, &final_dir).await {
        if let Some(invalid) = quarantine.as_ref() {
            tokio::fs::rename(invalid, &final_dir).await.ok();
        }
        return Err(error)
            .with_context(|| format!("Failed to publish bytecode cache {}", final_dir.display()));
    }
    if let Some(invalid) = quarantine {
        tokio::fs::remove_dir_all(invalid).await.ok();
    }
    touch_bytecode_artifact(&final_dir);
    drop(gate);
    enforce_bytecode_cache_quota(&cache_root, &final_dir);

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

fn digest_field(hasher: &mut Sha256, label: &str, bytes: &[u8]) {
    hasher.update((label.len() as u64).to_le_bytes());
    hasher.update(label.as_bytes());
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn bundler_cache_input_paths() -> Result<Vec<PathBuf>> {
    // Outside a checkout there is no bundler to run and no scripts to hash;
    // the cache key must not require a repo.
    let Ok(root) = repo_root() else {
        return Ok(Vec::new());
    };
    [
        "packages/ibex-devtools/src/scripts/rolldown-bundle.mjs",
        "packages/ibex-devtools/src/scripts/transforms.mjs",
        // @ref LLP 0019#consequences — ENG-22987: the canonical Hermes-compat transforms
        // (for-of scoping, exponentiation, BigInt, async generators) moved out
        // of transforms.mjs into hermes-compat.mjs, which transforms.mjs now
        // re-exports. The bundle cache must hash the file the logic actually
        // lives in, or an edit to the transform semantics would not invalidate
        // cached bundles.
        "packages/ibex-devtools/src/scripts/hermes-compat.mjs",
        // @ref LLP 0014#parse-and-strip — the grant-attribute strip runs in
        // every bundle; its logic changing must invalidate cached bundles.
        "packages/ibex-devtools/src/scripts/import-grants.mjs",
    ]
    .into_iter()
    .map(|relative| authenticated_repo_file(&root, Path::new(relative)))
    .collect()
}

#[derive(Clone)]
struct BundlerToolchainIdentity {
    runner: PathBuf,
    runner_name: &'static str,
    digest: [u8; 32],
}

fn collect_authenticated_tool_files(
    path: &Path,
    package_store_root: &Path,
    visited_dirs: &mut std::collections::HashSet<PathBuf>,
    visited_files: &mut std::collections::HashSet<PathBuf>,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    const MAX_TOOL_FILES: usize = 4096;
    let canonical = std::fs::canonicalize(path).with_context(|| {
        format!(
            "Failed to authenticate bundler dependency {}",
            path.display()
        )
    })?;
    if !canonical.starts_with(package_store_root) {
        anyhow::bail!(
            "Bundler dependency {} escapes authenticated package store {}",
            canonical.display(),
            package_store_root.display()
        );
    }
    let metadata = std::fs::metadata(&canonical)?;
    if metadata.is_file() {
        if visited_files.insert(canonical.clone()) {
            if files.len() >= MAX_TOOL_FILES {
                anyhow::bail!("Bundler dependency tree exceeds {MAX_TOOL_FILES} files");
            }
            files.push(canonical);
        }
        return Ok(());
    }
    if !metadata.is_dir() || !visited_dirs.insert(canonical.clone()) {
        return Ok(());
    }
    let mut entries = std::fs::read_dir(&canonical)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    for entry in entries {
        collect_authenticated_tool_files(
            &entry.path(),
            package_store_root,
            visited_dirs,
            visited_files,
            files,
        )?;
    }
    Ok(())
}

fn compute_bundler_toolchain_identity() -> Result<BundlerToolchainIdentity> {
    const MAX_TOOL_BYTES: u64 = 512 * 1024 * 1024;
    let root = repo_root()?;
    let (runner, runner_name) = find_js_runner()?;
    let runner = std::fs::canonicalize(&runner)
        .with_context(|| format!("Failed to authenticate JS runner {}", runner.display()))?;
    let runner_bytes = std::fs::read(&runner)
        .with_context(|| format!("Failed to read JS runner {}", runner.display()))?;
    if runner_bytes.len() as u64 > MAX_TOOL_BYTES {
        anyhow::bail!("JS runner exceeds the authenticated tool size limit");
    }

    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "identity-version", b"bundler-toolchain-v1");
    digest_field(&mut hasher, "runner-name", runner_name.as_bytes());
    digest_field(
        &mut hasher,
        "runner-path",
        runner.to_string_lossy().as_bytes(),
    );
    digest_field(&mut hasher, "runner-content", &runner_bytes);

    let mut inputs = bundler_cache_input_paths()?;
    for relative in ["package.json", "bun.lock"] {
        let candidate = root.join(relative);
        if candidate.is_file() {
            inputs.push(authenticated_repo_file(&root, Path::new(relative))?);
        }
    }

    // Rolldown's JS package loads a platform-specific native binding and
    // helper packages from the enclosing installation node_modules directory.
    // Bind that exact resolved tree, not just package.json/lockfile metadata.
    let package_store_root = std::fs::canonicalize(root.join("node_modules"))
        .context("Failed to authenticate the installed package store")?;
    let rolldown = std::fs::canonicalize(root.join("node_modules/rolldown"))
        .context("Failed to authenticate the installed rolldown package")?;
    let install_root = rolldown
        .parent()
        .context("Installed rolldown package has no dependency root")?;
    let mut tool_files = Vec::new();
    collect_authenticated_tool_files(
        install_root,
        &package_store_root,
        &mut std::collections::HashSet::new(),
        &mut std::collections::HashSet::new(),
        &mut tool_files,
    )?;
    inputs.extend(tool_files);
    inputs.sort();
    inputs.dedup();

    let mut total = runner_bytes.len() as u64;
    for input in inputs {
        let bytes = std::fs::read(&input)
            .with_context(|| format!("Failed to read bundler input {}", input.display()))?;
        total = total
            .checked_add(bytes.len() as u64)
            .context("Bundler tooling size overflow")?;
        if total > MAX_TOOL_BYTES {
            anyhow::bail!("Bundler dependency tree exceeds the authenticated tool size limit");
        }
        digest_field(&mut hasher, "tool-path", input.to_string_lossy().as_bytes());
        digest_field(&mut hasher, "tool-content", &bytes);
    }

    Ok(BundlerToolchainIdentity {
        runner,
        runner_name,
        digest: hasher.finalize().into(),
    })
}

fn bundler_toolchain_identity() -> Result<BundlerToolchainIdentity> {
    // Computing this identity authenticates the runner plus thousands of
    // installed tool files. Serialize the cold path so concurrent bundle
    // publishers do not all repeat that scan before one of them fills the
    // cache. Failed scans remain retryable.
    static CACHED: std::sync::OnceLock<std::sync::Mutex<Option<BundlerToolchainIdentity>>> =
        std::sync::OnceLock::new();
    let mut cached = CACHED
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .map_err(|_| anyhow::anyhow!("Bundler toolchain identity cache is poisoned"))?;
    if let Some(identity) = cached.as_ref() {
        return Ok(identity.clone());
    }
    let identity = compute_bundler_toolchain_identity()?;
    *cached = Some(identity.clone());
    Ok(identity)
}

fn verify_bundler_toolchain_identity(expected: &BundlerToolchainIdentity) -> Result<()> {
    let current = compute_bundler_toolchain_identity()?;
    if current.runner != expected.runner
        || current.runner_name != expected.runner_name
        || current.digest != expected.digest
    {
        anyhow::bail!("Bundler runner or dependency tree changed during this process");
    }
    Ok(())
}

fn bundle_cache_key(entry: &Path, bundle_format: BundleFormat) -> Result<String> {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "cache-version", b"bundle-cache-v8-sha256");
    digest_field(&mut hasher, "format", bundle_format.as_str().as_bytes());
    // @ref LLP 0013#mechanism-2 — a compartmentalized bundle references the
    // `__compartments` registry, which only exists under lockdown/compartments.
    // It MUST NOT be reused for a non-compartment run (the reference would throw
    // ReferenceError), nor vice versa. Fold the state into the cache key so the
    // two variants are cached under distinct paths. This mirrors the same signal
    // `run_bundler` uses to pass `--compartments`.
    // Resolve with the same truthiness parse the engine uses (ENG-22634), and
    // key the cache on that resolved bool so a compartmentalized bundle can never
    // be reused for a non-compartment run (or vice versa).
    digest_field(&mut hasher, "compartments", b"1");
    // @ref LLP 0013#mechanism-3 — per-package chunking changes the output shape
    // (multiple chunk files), so it must key distinctly from a flat bundle. Use
    // the same truthiness parse as the other two read sites so `=0` is a real
    // opt-out and the cache key agrees with what the bundler actually emitted.
    digest_field(&mut hasher, "per-package-chunks", b"1");
    let canonical_entry = std::fs::canonicalize(entry)
        .with_context(|| format!("Failed to resolve bundle entry {}", entry.display()))?;
    let canonical_entry_utf8 = canonical_entry.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "Bundle cache does not support a non-UTF-8 entry path: {}",
            canonical_entry.display()
        )
    })?;
    digest_field(&mut hasher, "entry-path", canonical_entry_utf8.as_bytes());
    digest_field(
        &mut hasher,
        "entry-content",
        &std::fs::read(&canonical_entry)?,
    );

    // Outside a checkout (or when no runner is installed), bundling is
    // unavailable and the loader falls back to its in-process path. Preserve
    // that fallback while ensuring every actually runnable bundler cache key
    // includes the exact runner, Rolldown JS/native packages, lockfile, and
    // transform scripts that will produce the artifact.
    match bundler_toolchain_identity() {
        Ok(identity) => digest_field(&mut hasher, "bundler-toolchain", &identity.digest),
        Err(_) => digest_field(&mut hasher, "bundler-toolchain", b"unavailable"),
    }

    Ok(format!("{:x}", hasher.finalize()))
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
fn bundle_artifact_root(cache_dir: &Path, key: &str) -> PathBuf {
    cache_dir.join("bundles").join(key)
}

fn bundle_entry_path(artifact_dir: &Path, format: BundleFormat) -> PathBuf {
    artifact_dir.join(format!("bundle.{}", bundle_file_ext(format)))
}

fn process_is_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        return result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    }
    #[cfg(windows)]
    {
        type Handle = *mut std::ffi::c_void;
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
            fn CloseHandle(handle: Handle) -> i32;
        }
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        unsafe { CloseHandle(handle) };
        return true;
    }
    #[allow(unreachable_code)]
    false
}

struct BundleArtifactGate {
    file: std::fs::File,
}

impl Drop for BundleArtifactGate {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn bundle_gate_path(artifact_dir: &Path) -> PathBuf {
    let name = artifact_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact");
    artifact_dir.with_file_name(format!(".{name}.gate"))
}

fn try_acquire_bundle_artifact_gate(artifact_dir: &Path) -> Result<Option<BundleArtifactGate>> {
    let gate = bundle_gate_path(artifact_dir);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&gate)
        .with_context(|| format!("Failed to open bundle artifact gate {}", gate.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(BundleArtifactGate { file })),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => Err(error)
            .with_context(|| format!("Failed to lock bundle artifact gate {}", gate.display())),
    }
}

async fn acquire_bundle_artifact_gate(artifact_dir: &Path) -> Result<BundleArtifactGate> {
    for _ in 0..500 {
        if let Some(gate) = try_acquire_bundle_artifact_gate(artifact_dir)? {
            return Ok(gate);
        }
        // Never park a Tokio worker while another process publishes/prunes.
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let gate = bundle_gate_path(artifact_dir);
    anyhow::bail!(
        "Timed out acquiring bundle artifact gate {}",
        gate.display()
    )
}

pub(crate) struct BundleLease {
    files: Vec<std::fs::File>,
}

impl Drop for BundleLease {
    fn drop(&mut self) {
        for file in &self.files {
            let _ = file.unlock();
        }
    }
}

fn acquire_bundle_lease(artifact_dir: &Path) -> Result<BundleLease> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(artifact_dir.join(".lease"))
        .with_context(|| format!("Failed to lease bundle artifact {}", artifact_dir.display()))?;
    file.lock_shared()
        .with_context(|| format!("Failed to lock bundle artifact {}", artifact_dir.display()))?;
    std::fs::write(artifact_dir.join(".last-used"), []).ok();
    Ok(BundleLease { files: vec![file] })
}

fn bundle_artifact_has_live_lease(artifact_dir: &Path) -> bool {
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(artifact_dir.join(".lease"))
    else {
        return false;
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(std::fs::TryLockError::WouldBlock) => true,
        Err(_) => true,
    }
}

pub(crate) async fn acquire_bundle_execution_lease(path: &Path) -> Result<Option<BundleLease>> {
    let mut retained = None;
    if let (Some(artifact_dir), Some(cache_root)) =
        (path.parent(), path.parent().and_then(Path::parent))
    {
        if cache_root
            .file_name()
            .is_some_and(|name| name == ".bytecode-cache")
            && artifact_dir.file_name().is_some_and(is_bytecode_cache_key)
        {
            let gate = acquire_bundle_artifact_gate(artifact_dir).await?;
            if !artifact_dir.is_dir() {
                anyhow::bail!(
                    "Bytecode cache artifact disappeared before execution: {}",
                    artifact_dir.display()
                );
            }
            retained = Some(acquire_bundle_lease(artifact_dir)?);
            drop(gate);
        }
    }

    let bundles_root = runtime_cache_dir()?.join("bundles");
    let mut current = path.parent();
    while let Some(directory) = current {
        if directory
            .parent()
            .and_then(Path::parent)
            .is_some_and(|parent| parent == bundles_root)
        {
            let gate = acquire_bundle_artifact_gate(directory).await?;
            if !directory.is_dir() {
                anyhow::bail!(
                    "Bundle cache artifact disappeared before execution: {}",
                    directory.display()
                );
            }
            let mut lease = acquire_bundle_lease(directory)?;
            drop(gate);
            if let Some(mut bytecode_lease) = retained {
                bytecode_lease.files.append(&mut lease.files);
                return Ok(Some(bytecode_lease));
            }
            return Ok(Some(lease));
        }
        if !directory.starts_with(&bundles_root) {
            break;
        }
        current = directory.parent();
    }
    Ok(retained)
}

async fn find_fresh_bundle(
    artifact_root: &Path,
    entry: &Path,
    format: BundleFormat,
) -> Option<PathBuf> {
    let mut entries = tokio::fs::read_dir(artifact_root).await.ok()?;
    while let Ok(Some(candidate)) = entries.next_entry().await {
        let file_type = candidate.file_type().await.ok()?;
        if !file_type.is_dir() || candidate.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let candidate_path = candidate.path();
        let _gate = acquire_bundle_artifact_gate(&candidate_path).await.ok()?;
        let output = bundle_entry_path(&candidate_path, format);
        if bundle_cache_is_fresh(&output, entry).await {
            std::fs::write(candidate_path.join(".last-used"), []).ok();
            return Some(output);
        }
    }
    None
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

fn unique_bundle_stage_dir(artifact_root: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    artifact_root.join(format!(
        ".stage-{}-{seq}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ))
}

fn cached_directory_size(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => cached_directory_size(&entry.path()),
            Ok(file_type) if file_type.is_file() => {
                entry.metadata().map(|metadata| metadata.len()).unwrap_or(0)
            }
            _ => 0,
        })
        .sum()
}

fn cleanup_abandoned_bundle_temp_dirs(bundles_root: &Path) {
    let Ok(keys) = std::fs::read_dir(bundles_root) else {
        return;
    };
    for key in keys.filter_map(|entry| entry.ok()) {
        let Ok(children) = std::fs::read_dir(key.path()) else {
            continue;
        };
        for child in children.filter_map(|entry| entry.ok()) {
            let name = child.file_name().to_string_lossy().into_owned();
            let owner = [".stage-", ".invalid-", ".evict-"]
                .iter()
                .find_map(|prefix| {
                    name.strip_prefix(prefix)
                        .and_then(|rest| rest.split('-').next())
                        .and_then(|pid| pid.parse::<u32>().ok())
                });
            if owner.is_some_and(|pid| !process_is_running(pid)) {
                std::fs::remove_dir_all(child.path()).ok();
            }
        }
    }
}

fn prune_bundle_cache_to_limit(bundles_root: &Path, keep: &Path, limit: u64) {
    cleanup_abandoned_bundle_temp_dirs(bundles_root);
    let Ok(keys) = std::fs::read_dir(bundles_root) else {
        return;
    };
    let mut artifacts = Vec::new();
    for key in keys.filter_map(|entry| entry.ok()) {
        let Ok(children) = std::fs::read_dir(key.path()) else {
            continue;
        };
        for child in children.filter_map(|entry| entry.ok()) {
            let path = child.path();
            let Ok(metadata) = child.metadata() else {
                continue;
            };
            if path == keep
                || !metadata.is_dir()
                || child.file_name().to_string_lossy().starts_with('.')
            {
                continue;
            }
            let recency = std::fs::metadata(path.join(".last-used"))
                .and_then(|marker| marker.modified())
                .or_else(|_| metadata.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            artifacts.push((recency, cached_directory_size(&path), path));
        }
    }
    // Include active stages/gates/quarantines in accounting even though only
    // completed, unlocked artifacts are eviction candidates.
    let mut total = cached_directory_size(bundles_root);
    artifacts.sort_by_key(|(modified, _, _)| *modified);
    for (_, size, path) in artifacts {
        if total <= limit {
            break;
        }
        let Ok(Some(gate)) = try_acquire_bundle_artifact_gate(&path) else {
            continue;
        };
        if bundle_artifact_has_live_lease(&path) {
            drop(gate);
            continue;
        }
        let quarantine = path.with_file_name(format!(
            ".evict-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0),
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("artifact")
        ));
        let renamed = std::fs::rename(&path, &quarantine).is_ok();
        drop(gate);
        if renamed && std::fs::remove_dir_all(&quarantine).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

fn enforce_bundle_cache_quota(artifact_root: &Path, keep: &Path) {
    const DEFAULT_LIMIT: u64 = 512 * 1024 * 1024;
    let limit = std::env::var("IBEX_BUNDLE_CACHE_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LIMIT);
    if let Some(bundles_root) = artifact_root.parent() {
        prune_bundle_cache_to_limit(bundles_root, keep, limit);
    }
}

async fn run_bundler(
    entry: &Path,
    artifact_root: &Path,
    bundle_format: BundleFormat,
) -> Result<PathBuf> {
    if entry.to_str().is_none() || artifact_root.to_str().is_none() {
        anyhow::bail!(
            "Bundling/cache publication does not support non-UTF-8 paths: entry={}, cache={}",
            entry.display(),
            artifact_root.display()
        );
    }
    let toolchain = bundler_toolchain_identity()?;
    verify_bundler_toolchain_identity(&toolchain)?;
    let runner = toolchain.runner.clone();
    let runner_name = toolchain.runner_name;
    let script = bundler_script_path()?;
    let working_dir = bundler_working_dir()?;
    let timeout = timeout_from_env("EXACT_BUNDLER_TIMEOUT_MS", DEFAULT_BUNDLER_TIMEOUT_MS);

    tokio::fs::create_dir_all(artifact_root)
        .await
        .with_context(|| format!("Failed to create {}", artifact_root.display()))?;
    let stage_dir = unique_bundle_stage_dir(artifact_root);
    tokio::fs::create_dir(&stage_dir)
        .await
        .with_context(|| format!("Failed to create bundle stage {}", stage_dir.display()))?;
    let output = bundle_entry_path(&stage_dir, bundle_format);

    let mut command = tokio::process::Command::new(&runner);
    command
        .arg(&script)
        .arg("--entry")
        .arg(entry)
        .arg("--out")
        .arg(&output)
        .arg("--format")
        .arg(bundle_format.as_str())
        .arg("--sourcemap")
        .arg("--cache-manifest")
        .current_dir(&working_dir);
    // @ref LLP 0013#mechanism-2 — when the runtime boots with lockdown, bundle
    // package (node_modules) code through the per-package compartment rewrite so
    // its bare globals resolve against the runtime compartment registry.
    command.arg("--compartments");
    // @ref LLP 0013#mechanism-3 — per-package chunking so a bundled app gets
    // per-package frame attribution (each package chunk loads into its own
    // Domain). Auto-enabled under enforce/audit (see enable_isolation_prereqs);
    // `IBEX_PER_PACKAGE_CHUNKS=0` opts out. iife can't split; the bundler
    // ignores the flag there.
    command.arg("--per-package-chunks");
    let cmd_output = match output_with_timeout(
        &mut command,
        timeout,
        &format!("bundler via {}", runner_name),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => {
            tokio::fs::remove_dir_all(&stage_dir).await.ok();
            return Err(error);
        }
    };

    if let Err(error) = verify_bundler_toolchain_identity(&toolchain) {
        tokio::fs::remove_dir_all(&stage_dir).await.ok();
        return Err(error).context("Bundler toolchain changed while producing cache output");
    }

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
        tokio::fs::remove_dir_all(&stage_dir).await.ok();
        anyhow::bail!(
            "Bundler exited with status {}: {}",
            cmd_output.status,
            combined
        );
    }

    if !bundle_cache_is_fresh(&output, entry).await {
        tokio::fs::remove_dir_all(&stage_dir).await.ok();
        anyhow::bail!(
            "Bundler did not produce a complete digest-verified artifact in {}",
            stage_dir.display()
        );
    }
    let manifest = read_bundle_manifest(&output).await?;
    let final_dir = artifact_root.join(&manifest.graph_digest);
    let final_output = bundle_entry_path(&final_dir, bundle_format);
    let gate = acquire_bundle_artifact_gate(&final_dir).await?;
    let mut quarantined = None;
    if final_dir.exists() {
        if bundle_cache_is_fresh(&final_output, entry).await {
            tokio::fs::remove_dir_all(&stage_dir).await.ok();
            std::fs::write(final_dir.join(".last-used"), []).ok();
            drop(gate);
            enforce_bundle_cache_quota(artifact_root, &final_dir);
            return Ok(final_output);
        }
        if bundle_artifact_has_live_lease(&final_dir) {
            tokio::fs::remove_dir_all(&stage_dir).await.ok();
            anyhow::bail!(
                "Cannot repair invalid bundle artifact {} while another process holds a live lease",
                final_dir.display()
            );
        }
        let quarantine = final_dir.with_file_name(format!(
            ".invalid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        tokio::fs::rename(&final_dir, &quarantine)
            .await
            .with_context(|| {
                format!(
                    "Failed to quarantine invalid bundle artifact {}",
                    final_dir.display()
                )
            })?;
        quarantined = Some(quarantine);
    }
    if let Err(error) = tokio::fs::rename(&stage_dir, &final_dir).await {
        if let Some(quarantine) = quarantined.as_ref() {
            let _ = tokio::fs::rename(quarantine, &final_dir).await;
        }
        return Err(error).with_context(|| {
            format!(
                "Failed to atomically publish bundle cache {}",
                final_dir.display()
            )
        });
    }
    if let Some(quarantine) = quarantined {
        tokio::fs::remove_dir_all(quarantine).await.ok();
    }
    std::fs::write(final_dir.join(".last-used"), []).ok();
    drop(gate);
    enforce_bundle_cache_quota(artifact_root, &final_dir);
    Ok(final_output)
}

fn bundler_script_path() -> Result<PathBuf> {
    let root = repo_root()?;
    authenticated_repo_file(
        &root,
        Path::new("packages/ibex-devtools/src/scripts/rolldown-bundle.mjs"),
    )
}

/// `ibex policy generate|check` — runs the LLP 0014 policy generator with the
/// same JS-runner resolution as the bundler. The generator's exit code is the
/// command's exit code (`check` uses 1 for drift, the CI-gate contract).
/// @ref LLP 0014#runtime-and-cli
pub async fn run_policy_command(command: &crate::cli::PolicyCommands) -> Result<()> {
    use crate::cli::PolicyCommands;

    let root = repo_root()?;
    let script = authenticated_repo_file(
        &root,
        Path::new("packages/ibex-devtools/src/scripts/generate-policy.mjs"),
    )?;
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
                std::fs::canonicalize(ancestor).ok()
            } else {
                None
            }
        })
    }

    if let Some(raw) =
        std::env::var_os("IBEX_REPO_ROOT").or_else(|| std::env::var_os("EXACT_REPO_ROOT"))
    {
        let root = PathBuf::from(raw);
        if !root.is_absolute() {
            anyhow::bail!("IBEX_REPO_ROOT must be an absolute authenticated directory");
        }
        return find_from(&root).ok_or_else(|| {
            anyhow::anyhow!(
                "IBEX_REPO_ROOT does not identify an Ibex checkout: {}",
                root.display()
            )
        });
    }

    // The compile-time checkout is authenticated by the build. Never inspect
    // the application cwd or its ancestors: an app can create a lookalike
    // packages/ tree and otherwise select executable bundler code (the same
    // confused-tool-discovery class as ENG-24254's fake Hermes compiler).
    if let Some(found) = find_from(Path::new(env!("CARGO_MANIFEST_DIR"))) {
        return Ok(found);
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(found) = find_from(&exe_path) {
            return Ok(found);
        }
    }

    anyhow::bail!(
        "Failed to resolve an authenticated Ibex tooling root. Set IBEX_REPO_ROOT to an absolute trusted checkout"
    )
}

fn authenticated_repo_file(root: &Path, relative: &Path) -> Result<PathBuf> {
    let canonical_root = std::fs::canonicalize(root).with_context(|| {
        format!(
            "Failed to authenticate Ibex tooling root {}",
            root.display()
        )
    })?;
    let candidate = canonical_root.join(relative);
    let canonical = std::fs::canonicalize(&candidate)
        .with_context(|| format!("Ibex tooling file not found at {}", candidate.display()))?;
    if !canonical.starts_with(&canonical_root) || !canonical.is_file() {
        anyhow::bail!(
            "Ibex tooling file {} escapes authenticated root {}",
            canonical.display(),
            canonical_root.display()
        );
    }
    Ok(canonical)
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

    #[derive(Default)]
    struct WindowsMinimalBootstrapEngine {
        evaluated: std::sync::Mutex<Vec<String>>,
        runtime_loaded: AtomicBool,
    }

    #[async_trait::async_trait]
    impl Engine for WindowsMinimalBootstrapEngine {
        fn name(&self) -> &str {
            "windows-minimal-bootstrap-test"
        }

        fn version(&self) -> Result<String> {
            Ok("test".to_string())
        }

        async fn load_runtime(&self) -> Result<()> {
            anyhow::bail!("the Windows minimal bootstrap must not load the full runtime")
        }

        async fn eval(&self, _code: &str) -> Result<Option<String>> {
            anyhow::bail!("the Windows minimal bootstrap must use immediate evaluation")
        }

        async fn eval_immediate(&self, code: &str) -> Result<Option<String>> {
            self.evaluated.lock().unwrap().push(code.to_string());
            if code == WINDOWS_RUNTIME_LOADED_PROBE {
                Ok(Some(self.runtime_loaded.load(Ordering::SeqCst).to_string()))
            } else if code == WINDOWS_MINIMAL_RUNTIME_BOOTSTRAP {
                self.runtime_loaded.store(true, Ordering::SeqCst);
                Ok(None)
            } else if code == crate::engine::hermes::FINALIZE_COMPARTMENT_BASELINE {
                Ok(Some("true".to_string()))
            } else {
                anyhow::bail!("unexpected bootstrap script")
            }
        }

        async fn run_file(&self, _path: &str) -> Result<Option<String>> {
            anyhow::bail!("unexpected file evaluation")
        }

        async fn start_inspector(&self, _host: &str, _port: u16) -> Result<()> {
            anyhow::bail!("unexpected inspector start")
        }

        async fn stop_inspector(&self) -> Result<()> {
            anyhow::bail!("unexpected inspector stop")
        }

        fn supports_feature(&self, _feature: EngineFeature) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn windows_minimal_bootstrap_runs_once_and_finalizes_each_load() {
        let engine = WindowsMinimalBootstrapEngine::default();

        load_windows_minimal_runtime(&engine).await.unwrap();
        load_windows_minimal_runtime(&engine).await.unwrap();

        let evaluated = engine.evaluated.lock().unwrap();
        assert_eq!(evaluated.len(), 5);
        assert_eq!(evaluated[0], WINDOWS_RUNTIME_LOADED_PROBE);
        assert_eq!(evaluated[1], WINDOWS_MINIMAL_RUNTIME_BOOTSTRAP);
        assert_eq!(
            evaluated[2],
            crate::engine::hermes::FINALIZE_COMPARTMENT_BASELINE
        );
        assert_eq!(evaluated[3], WINDOWS_RUNTIME_LOADED_PROBE);
        assert_eq!(
            evaluated[4],
            crate::engine::hermes::FINALIZE_COMPARTMENT_BASELINE
        );
    }

    struct ProductionEnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl ProductionEnvGuard {
        fn capture() -> Self {
            Self(
                [
                    "IBEX_LOCKDOWN",
                    "IBEX_PER_PACKAGE_CHUNKS",
                    "IBEX_SEAL_SELF_GRANT",
                    "IBEX_ENDOW",
                    "IBEX_REPO_ROOT",
                    "EXACT_REPO_ROOT",
                ]
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect(),
            )
        }
    }

    impl Drop for ProductionEnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn authenticated_project_root_requires_explicit_or_manifest_backed_root() {
        let manifestless = tempdir().unwrap();
        let entry = manifestless.path().join("src/app.js");
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(&entry, "console.log('manifestless');\n").unwrap();
        let implicit = Cli::parse_from(["ibex", entry.to_str().unwrap()]);
        let error = authenticated_project_root(&implicit, implicit.file.as_deref()).unwrap_err();
        assert!(
            error.to_string().contains("no authenticated project root"),
            "unexpected refusal: {error:#}"
        );

        let explicit = Cli::parse_from([
            "ibex",
            "--project-root",
            manifestless.path().to_str().unwrap(),
            entry.to_str().unwrap(),
        ]);
        assert_eq!(
            authenticated_project_root(&explicit, explicit.file.as_deref()).unwrap(),
            std::fs::canonicalize(manifestless.path()).unwrap()
        );
    }

    #[test]
    fn authenticated_project_root_discovers_manifest_above_src_entry() {
        let project = tempdir().unwrap();
        let entry = project.path().join("src/app.js");
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(project.path().join("package.json"), "{\"name\":\"app\"}\n").unwrap();
        std::fs::write(&entry, "console.log('src entry');\n").unwrap();
        let cli = Cli::parse_from(["ibex", entry.to_str().unwrap()]);
        assert_eq!(
            authenticated_project_root(&cli, cli.file.as_deref()).unwrap(),
            std::fs::canonicalize(project.path()).unwrap()
        );
    }

    #[test]
    fn authenticated_packages_reject_duplicate_locator_with_one_drifted_copy() {
        let project = tempdir().unwrap();
        let first = project.path().join("node_modules/dup");
        let parent = project.path().join("node_modules/parent");
        let second = parent.join("node_modules/dup");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(
            first.join("package.json"),
            r#"{"name":"dup","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(first.join("index.js"), "module.exports = 'valid';").unwrap();
        std::fs::write(
            parent.join("package.json"),
            r#"{"name":"parent","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            second.join("package.json"),
            r#"{"name":"dup","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(second.join("index.js"), "module.exports = 'drifted';").unwrap();
        let expected = crate::module_loader::package_tree_integrity(&first).unwrap();
        let principals = vec![serde_json::json!({
            "principal": {
                "kind": "package",
                "name": "dup",
                "locator": "dup@1.0.0",
                "integrity": expected,
            }
        })];

        let error = authenticated_installed_packages(project.path(), &principals).unwrap_err();
        assert!(
            error.to_string().contains("duplicate name+locator roots"),
            "{error:#}"
        );
    }

    #[test]
    fn protected_artifacts_are_distinct_pinned_and_reject_mutable_reuse() {
        let cache = tempdir().unwrap();
        let roles = ["armed-policy", "engine-binary", "package-graph", "registry"];
        let mut identities = std::collections::BTreeSet::new();
        for role in roles {
            let bytes = format!("protected:{role}");
            let identity = materialize_protected_artifact(
                cache.path(),
                role,
                "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                bytes.as_bytes(),
            )
            .unwrap();
            assert!(identities.insert(identity.object.to_string()));
        }
        assert_eq!(identities.len(), 4);

        let directory = cache.path().join("capsec-artifacts");
        let policy = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.to_string_lossy().contains("armed-policy"))
            .unwrap();
        let mut permissions = std::fs::metadata(&policy).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o600);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        std::fs::set_permissions(&policy, permissions).unwrap();
        let error = materialize_protected_artifact(
            cache.path(),
            "armed-policy",
            "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            b"protected:armed-policy",
        )
        .unwrap_err();
        assert!(error.to_string().contains("mutable"), "{error:#}");
    }

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
        let engine = crate::engine::hermes::HermesEngine::loaded_engine_identity()
            .expect("arming fixture requires the authenticated loaded engine");
        value["engine"]["target"] = serde_json::Value::String(exact_runtime_target());
        value["engine"]["binaryDigest"] = serde_json::Value::String(engine.binary_digest.clone());
        value["engine"]["features"] = serde_json::to_value(observed_structural_features()).unwrap();
        let protected_engine = value["protectedObjects"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["role"] == "engine-binary")
            .unwrap();
        protected_engine["object"] = serde_json::to_value(&engine.object).unwrap();
        let policy_artifact = materialize_protected_artifact(
            directory,
            "armed-policy",
            value["policyDigest"].as_str().unwrap(),
            b"authenticated canonical policy fixture",
        )
        .unwrap();
        let graph_artifact = materialize_protected_artifact(
            directory,
            "package-graph",
            value["packageGraph"]["digest"].as_str().unwrap(),
            b"authenticated package graph fixture",
        )
        .unwrap();
        let registry_artifact = materialize_protected_artifact(
            directory,
            "registry",
            value["registryDigest"].as_str().unwrap(),
            b"authenticated registry fixture",
        )
        .unwrap();
        for (role, object) in [
            ("armed-policy", &policy_artifact.object),
            ("package-graph", &graph_artifact.object),
            ("registry", &registry_artifact.object),
        ] {
            value["protectedObjects"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["role"] == role)
                .unwrap()["object"] = object.clone();
        }
        let digest = capsec_semantics::digest::compute_checked_contract_digest(
            capsec_semantics::digest::DigestKind::ArmedSnapshot,
            &value,
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
            armed_snapshot_digest: digest_at(&["armedSnapshotDigest"]),
            target: value["engine"]["target"].as_str().unwrap().into(),
            engine_binary_digest: digest_at(&["engine", "binaryDigest"]),
            features: value["engine"]["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            protected_artifacts: vec![
                capsec_semantics::arming::ExpectedProtectedArtifact {
                    role: capsec_semantics::arming::ProtectedArtifactRole::ArmedPolicy,
                    host_path: policy_artifact.host_path,
                    object: serde_json::from_value(value["protectedObjects"][0]["object"].clone())
                        .unwrap(),
                    content_digest: policy_artifact.content_digest,
                },
                capsec_semantics::arming::ExpectedProtectedArtifact {
                    role: capsec_semantics::arming::ProtectedArtifactRole::EngineBinary,
                    host_path: serde_json::from_value(serde_json::json!({
                        "root": "absolute",
                        "components": runtime_path_components_json(&engine.engine_artifact_path)
                            .unwrap(),
                        "hostBound": true,
                    }))
                    .unwrap(),
                    object: engine.object,
                    content_digest: digest_at(&["engine", "binaryDigest"]),
                },
                capsec_semantics::arming::ExpectedProtectedArtifact {
                    role: capsec_semantics::arming::ProtectedArtifactRole::PackageGraph,
                    host_path: graph_artifact.host_path,
                    object: serde_json::from_value(value["protectedObjects"][2]["object"].clone())
                        .unwrap(),
                    content_digest: graph_artifact.content_digest,
                },
                capsec_semantics::arming::ExpectedProtectedArtifact {
                    role: capsec_semantics::arming::ProtectedArtifactRole::Registry,
                    host_path: registry_artifact.host_path,
                    object: serde_json::from_value(value["protectedObjects"][3]["object"].clone())
                        .unwrap(),
                    content_digest: registry_artifact.content_digest,
                },
            ],
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

    #[tokio::test]
    async fn production_entry_closes_eval_repl_and_debug_before_artifact_io() {
        let _env = ProductionEnvGuard::capture();
        let vectors = [
            vec!["--eval", "globalThis.__closedEval = true"],
            vec!["--print", "globalThis.__closedPrint = true"],
            vec!["eval", "globalThis.__closedCommandEval = true"],
            vec!["repl"],
            vec!["debug", "modules"],
            vec![
                "--eval",
                "globalThis.__closedSmuggledEval = true",
                "debug",
                "modules",
            ],
            vec![],
        ];
        for vector in vectors {
            let mut argv = vec![
                "ibex",
                "--capsec-armed-snapshot",
                "missing-snapshot.json",
                "--capsec-arming-identity",
                "missing-identity.json",
            ];
            argv.extend(vector);
            let cli = Cli::parse_from(argv);
            let error = crate::run(cli)
                .await
                .expect_err("production diagnostic entry must be closed");
            let error = format!("{error:#}");
            assert!(
                error.contains("closes ad-hoc evaluation, REPL, and debug commands"),
                "{error}"
            );
            assert!(
                !error.contains("failed to read") && !error.contains("__closed"),
                "diagnostic input reached artifact or evaluator I/O: {error}"
            );
        }
    }

    #[test]
    fn foreground_audit_remains_open_and_propagates_its_entry_to_children() {
        let cli = Cli::parse_from(["ibex", "capsec", "audit", "fixture.js"]);
        reject_closed_production_cli(&cli).expect("explicit foreground audit remains open");
        let exec_argv = build_audit_exec_argv(&cli);
        assert_eq!(exec_argv.get(0).map(String::as_str), Some("capsec"));
        assert_eq!(exec_argv.get(1).map(String::as_str), Some("audit"));
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
        assert!(
            error.contains("rejects legacy allow/deny")
                && error.contains("environment endowment widening"),
            "{error}"
        );
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
            assert!(
                error.contains("closes compatibility, inspector")
                    && error.contains("runtime-fidelity overrides"),
                "{error}"
            );
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
    fn armed_startup_closes_hidden_runtime_fidelity_flags_before_io() {
        for fidelity_args in [
            vec!["--expose-internals"],
            vec!["--stack-size", "2048"],
            vec!["--max-http-header-size", "32768"],
        ] {
            let mut args = vec![
                "ibex",
                "--capsec-armed-snapshot",
                "missing-snapshot.json",
                "--capsec-arming-identity",
                "missing-identity.json",
            ];
            args.extend(fidelity_args);
            args.push("app.ts");
            let cli = Cli::parse_from(args);
            let error = build_host(&cli)
                .err()
                .expect("armed hidden runtime configuration must be closed")
                .to_string();
            assert!(error.contains("runtime-fidelity"), "{error}");
            assert!(
                !error.contains("failed to read"),
                "runtime configuration closure must precede artifact I/O: {error}"
            );
        }
    }

    #[test]
    fn production_run_nonce_is_canonical_and_rejects_the_contract_vector() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let nonce = production_run_nonce_from_bytes(&[0; PRODUCTION_RUN_NONCE_BYTES]).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&nonce).unwrap().len(), 16);
        assert!(!nonce.contains('='));

        let contract_bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let error = production_run_nonce_from_bytes(&contract_bytes)
            .expect_err("the committed contract nonce must never arm production")
            .to_string();
        assert!(
            error.contains("reserved capsec contract-fixture"),
            "{error}"
        );
    }

    #[test]
    fn armed_startup_authenticates_engine_before_refusing_unadvertised_target() {
        let directory = tempdir().unwrap();
        let (snapshot, identity, _) = write_arming_fixture(directory.path());
        let cli = Cli::parse_from([
            "ibex".into(),
            "--capsec-armed-snapshot".into(),
            snapshot.into_os_string(),
            "--capsec-arming-identity".into(),
            identity.into_os_string(),
            "app.ts".into(),
        ]);
        let default_error = build_host(&cli)
            .err()
            .expect("unadvertised target must not arm");
        let default_error = format!("{default_error:#}");
        assert!(
            default_error.contains("no unique verified advertisement"),
            "{default_error}"
        );
        assert!(!default_error.contains("engine object"), "{default_error}");
        let (snapshot, identity, _) = write_arming_fixture(directory.path());
        let explicit = Cli::parse_from([
            "ibex".into(),
            "--capsec".into(),
            "enforce".into(),
            "--capsec-armed-snapshot".into(),
            snapshot.into_os_string(),
            "--capsec-arming-identity".into(),
            identity.into_os_string(),
            "app.ts".into(),
        ]);
        let explicit_error = build_host(&explicit)
            .err()
            .expect("explicit enforce cannot bypass target advertisements");
        let explicit_error = format!("{explicit_error:#}");
        assert_eq!(explicit_error, default_error);
    }

    #[test]
    fn armed_startup_rejects_tampered_template_before_freshening() {
        let directory = tempdir().unwrap();
        let (snapshot, identity, _) = write_arming_fixture(directory.path());
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&snapshot).unwrap()).unwrap();
        tampered["runNonce"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAA");
        std::fs::write(&snapshot, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
        let cli = Cli::parse_from([
            "ibex".into(),
            "--capsec-armed-snapshot".into(),
            snapshot.into_os_string(),
            "--capsec-arming-identity".into(),
            identity.into_os_string(),
            "app.ts".into(),
        ]);
        let error = build_host(&cli)
            .err()
            .expect("freshening must not repair an unauthenticated template");
        let message = format!("{error:#}");
        assert!(message.contains("digest is stale or tampered"), "{message}");
    }

    #[test]
    fn external_snapshot_refuses_mismatched_protected_artifact_identity_and_content() {
        let directory = tempdir().unwrap();
        let (snapshot, identity, _) = write_arming_fixture(directory.path());
        let original_identity = std::fs::read(&identity).unwrap();

        let mut mismatched_object: serde_json::Value =
            serde_json::from_slice(&original_identity).unwrap();
        let first = mismatched_object["protectedArtifacts"][0]["object"].clone();
        mismatched_object["protectedArtifacts"][0]["object"] =
            mismatched_object["protectedArtifacts"][1]["object"].clone();
        mismatched_object["protectedArtifacts"][1]["object"] = first;
        std::fs::write(&identity, serde_json::to_vec(&mismatched_object).unwrap()).unwrap();
        let cli = Cli::parse_from([
            "ibex".into(),
            "--capsec-armed-snapshot".into(),
            snapshot.clone().into_os_string(),
            "--capsec-arming-identity".into(),
            identity.clone().into_os_string(),
            "app.ts".into(),
        ]);
        let error = format!(
            "{:#}",
            build_host(&cli).err().expect("object mismatch must refuse")
        );
        assert!(
            error.contains("independently authenticated artifact role"),
            "{error}"
        );

        let mut mismatched_content: serde_json::Value =
            serde_json::from_slice(&original_identity).unwrap();
        mismatched_content["protectedArtifacts"][0]["contentDigest"] =
            serde_json::json!("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        std::fs::write(&identity, serde_json::to_vec(&mismatched_content).unwrap()).unwrap();
        let error = format!(
            "{:#}",
            build_host(&cli)
                .err()
                .expect("content mismatch must refuse")
        );
        assert!(error.contains("content digest changed"), "{error}");
        assert!(
            !error.contains("no unique verified advertisement"),
            "artifact mismatch must refuse before target promotion: {error}"
        );
    }

    fn file_hash(path: &Path) -> String {
        sha256_bytes(&std::fs::read(path).expect("read file for digest"))
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

    #[tokio::test]
    async fn production_build_isolation_is_always_enforce_and_rejects_weakening() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        use crate::host::SecurityMode;
        let cli = Cli::parse_from(["ibex", "app.ts"]);
        assert_eq!(apply_build_isolation(&cli).unwrap(), SecurityMode::Enforce);
        let forced = Cli::parse_from(["ibex", "--capsec", "permissive", "app.ts"]);
        assert!(apply_build_isolation(&forced).is_err());
        let allow_all = Cli::parse_from(["ibex", "--allow-all", "app.ts"]);
        assert!(apply_build_isolation(&allow_all).is_err());
        let audit = Cli::parse_from(["ibex", "--capsec", "audit", "app.ts"]);
        assert!(apply_build_isolation(&audit).is_err());
    }

    #[tokio::test]
    async fn default_and_explicit_enforce_refuse_the_same_unadvertised_target() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        let project = tempdir().unwrap();
        let entry = project.path().join("app.ts");
        std::fs::write(project.path().join("package.json"), "{\"name\":\"app\"}\n").unwrap();
        std::fs::write(&entry, "1 + 1\n").unwrap();
        let auto = Cli::parse_from(["ibex", entry.to_str().unwrap()]);
        let explicit = Cli::parse_from(["ibex", "--capsec", "enforce", entry.to_str().unwrap()]);
        let auto_error = build_host(&auto)
            .err()
            .expect("default enforce must refuse an unadvertised target");
        let explicit_error = build_host(&explicit)
            .err()
            .expect("explicit enforce cannot bypass target advertisements");
        let auto_error = format!("{auto_error:#}");
        let explicit_error = format!("{explicit_error:#}");
        assert_eq!(auto_error, explicit_error);
        assert!(
            auto_error.contains("no unique verified advertisement"),
            "{auto_error}"
        );
    }

    #[tokio::test]
    async fn default_arming_ingests_only_digest_valid_canonical_policy() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        let directory = tempdir().unwrap();
        let entry = directory.path().join("app.ts");
        std::fs::write(
            directory.path().join("package.json"),
            "{\"name\":\"test-app\"}\n",
        )
        .unwrap();
        std::fs::write(&entry, "1 + 1").unwrap();
        let package_root = directory.path().join("node_modules/image-lib");
        std::fs::create_dir_all(&package_root).unwrap();
        std::fs::write(
            package_root.join("package.json"),
            r#"{"name":"image-lib","version":"2.4.1"}"#,
        )
        .unwrap();
        std::fs::write(package_root.join("index.js"), "module.exports = {};\n").unwrap();
        let package_integrity =
            crate::module_loader::package_tree_integrity(&package_root).unwrap();
        let mut policy: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/canonical-policy.canonical.json"
        )))
        .unwrap();
        policy["principals"][0]["principal"]["integrity"] = serde_json::json!(package_integrity);
        let policy_digest = capsec_semantics::digest::compute_checked_contract_digest(
            capsec_semantics::digest::DigestKind::Policy,
            &policy,
        )
        .unwrap();
        policy["policyDigest"] = serde_json::json!(policy_digest);
        std::fs::write(
            directory.path().join("ibex-policy.json"),
            capsec_semantics::canonical::to_jcs_bytes(&policy).unwrap(),
        )
        .unwrap();
        let cli = Cli::parse_from(["ibex", entry.to_str().unwrap()]);
        let error = build_host(&cli)
            .err()
            .expect("valid policy and package root must reach the promotion gate");
        let error = format!("{error:#}");
        assert!(
            error.contains("no unique verified advertisement"),
            "{error}"
        );

        let mut tampered = policy.clone();
        tampered["principals"][0]["floor"] = serde_json::json!([]);
        std::fs::write(
            directory.path().join("ibex-policy.json"),
            serde_json::to_vec(&tampered).unwrap(),
        )
        .unwrap();
        let error = build_host(&cli).err().expect("tampered policy must fail");
        let error = format!("{error:#}");
        assert!(error.contains("digest is stale or tampered"), "{error}");

        for field in ["vocabDigest", "registryDigest"] {
            let mut stale = policy.clone();
            stale[field] = serde_json::json!("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            let digest = capsec_semantics::digest::compute_domain_digest(
                capsec_semantics::digest::POLICY_DOMAIN,
                &stale,
                &["policyDigest".to_string()],
            )
            .unwrap();
            stale["policyDigest"] = serde_json::json!(digest);
            std::fs::write(
                directory.path().join("ibex-policy.json"),
                serde_json::to_vec(&stale).unwrap(),
            )
            .unwrap();
            let error = build_host(&cli)
                .err()
                .expect("stale semantic identity must fail");
            let error = format!("{error:#}");
            assert!(error.contains("failed typed validation"), "{error}");
        }
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

        // Lockdown is a structural prerequisite, not an optional claim ceiling.
        let enforce_without_lockdown = CapsecReadiness {
            lockdown: false,
            ..ready
        };
        let error = check_capsec_readiness(
            SecurityMode::Enforce,
            CapsecStage::Run,
            enforce_without_lockdown,
            false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("structural runtime lockdown"));

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
        assert!(msg.contains("foreground capsec audit"));

        // The removed advisory override cannot weaken enforce.
        assert!(
            check_capsec_readiness(SecurityMode::Enforce, CapsecStage::Run, advisory, true)
                .is_err()
        );

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
    async fn bundle_cache_freshness_tracks_dependency_and_output_digests() {
        let dir = tempdir().expect("tempdir");
        let artifact_dir = tempdir().expect("artifact tempdir");
        let entry = dir.path().join("entry.ts");
        let dep = dir.path().join("dep.ts");
        let output = artifact_dir.path().join("entry.bundle.js");
        std::fs::write(&entry, "import './dep.ts';").expect("write entry");
        std::fs::write(&dep, "export const v = 1;").expect("write dep");
        std::fs::write(&output, "bundled").expect("write output");
        let canonical_entry = std::fs::canonicalize(&entry).unwrap();
        let canonical_dep = std::fs::canonicalize(&dep).unwrap();

        // No dependency manifest → stale (pre-manifest caches rebuild once).
        assert!(!bundle_cache_is_fresh(&output, &entry).await);

        let mut deps = vec![
            BundleDigestRecord {
                path: canonical_entry.to_string_lossy().into_owned(),
                sha256: sha256_file(&entry).await.unwrap(),
            },
            BundleDigestRecord {
                path: canonical_dep.to_string_lossy().into_owned(),
                sha256: sha256_file(&dep).await.unwrap(),
            },
        ];
        deps.sort_by(|left, right| left.path.cmp(&right.path));
        let graph_digest = sha256_bytes(&serde_json::to_vec(&deps).unwrap());
        let mut resolution_inputs = vec![BundleResolutionInput {
            kind: "directory".into(),
            path: dir.path().to_string_lossy().into_owned(),
            sha256: String::new(),
        }];
        resolution_inputs[0].sha256 =
            bundle_resolution_input_digest(&resolution_inputs[0]).unwrap();
        let resolution_digest = sha256_bytes(&serde_json::to_vec(&resolution_inputs).unwrap());
        let mut manifest = BundleCacheManifest {
            version: 3,
            entry: canonical_entry.to_string_lossy().into_owned(),
            resolution_digest,
            graph_digest,
            deps,
            outputs: vec![BundleDigestRecord {
                path: output.file_name().unwrap().to_string_lossy().into_owned(),
                sha256: sha256_file(&output).await.unwrap(),
            }],
            resolution_inputs,
        };
        std::fs::write(
            deps_manifest_path(&output),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .expect("write manifest");
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // A newly-added resolution candidate can retarget an import even when
        // every old positive dependency still exists unchanged.
        let candidate = dir.path().join("dep.js");
        std::fs::write(&candidate, "export const v = 'new candidate';").unwrap();
        assert!(!bundle_cache_is_fresh(&output, &entry).await);
        std::fs::remove_file(&candidate).unwrap();
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // The manifest is a closed inventory: unbound emitted files are never
        // allowed to sit beside executable chunks/maps.
        let unbound_output = artifact_dir.path().join("unbound.js");
        std::fs::write(&unbound_output, "tampered").unwrap();
        assert!(!bundle_cache_is_fresh(&output, &entry).await);
        std::fs::remove_file(&unbound_output).unwrap();
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        let correct_graph_digest = manifest.graph_digest.clone();
        manifest.graph_digest = "0".repeat(64);
        std::fs::write(
            deps_manifest_path(&output),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(!bundle_cache_is_fresh(&output, &entry).await);
        manifest.graph_digest = correct_graph_digest;
        std::fs::write(
            deps_manifest_path(&output),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // Same-length edits invalidate even when an attacker restores the old
        // timestamp, so a coarse filesystem clock cannot preserve stale code.
        let original_modified = std::fs::metadata(&dep).unwrap().modified().unwrap();
        std::fs::write(&dep, "export const v = 2;").expect("edit dep");
        std::fs::File::options()
            .write(true)
            .open(&dep)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_modified))
            .unwrap();
        assert_eq!(
            std::fs::metadata(&dep).unwrap().modified().unwrap(),
            original_modified
        );
        assert!(!bundle_cache_is_fresh(&output, &entry).await);

        std::fs::write(&dep, "export const v = 1;").expect("restore dep");
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // Clock skew alone is not content identity either: an unchanged file
        // remains valid even when its mtime jumps into the future.
        std::fs::File::options()
            .write(true)
            .open(&dep)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::SystemTime::now() + std::time::Duration::from_secs(86_400),
            ))
            .unwrap();
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // Output tampering is rejected before execution too.
        std::fs::write(&output, "tampered").expect("tamper output");
        assert!(!bundle_cache_is_fresh(&output, &entry).await);
        std::fs::write(&output, "bundled").expect("restore output");
        assert!(bundle_cache_is_fresh(&output, &entry).await);

        // A deleted dependency invalidates too.
        std::fs::remove_file(&dep).expect("remove dep");
        assert!(!bundle_cache_is_fresh(&output, &entry).await);
    }

    #[cfg(unix)]
    #[test]
    fn bundle_resolution_witness_tracks_symlink_retargets() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let entry = dir.path().join("entry.js");
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        std::fs::write(first.join("index.js"), "one").unwrap();
        std::fs::write(second.join("index.js"), "two").unwrap();
        std::fs::write(&entry, "require('./selected')").unwrap();
        let selected = dir.path().join("selected");
        symlink(&first, &selected).unwrap();
        let before = BundleResolutionInput {
            kind: "symlink".into(),
            path: selected.to_string_lossy().into_owned(),
            sha256: String::new(),
        };
        let before_digest = bundle_resolution_input_digest(&before).unwrap();
        std::fs::remove_file(&selected).unwrap();
        symlink(&second, &selected).unwrap();
        let after_digest = bundle_resolution_input_digest(&before).unwrap();
        assert_ne!(before_digest, after_digest);
    }

    #[test]
    fn bundle_resolution_witness_treats_a_child_of_a_file_as_missing() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("entry.js");
        std::fs::write(&file, "module.exports = 1;").unwrap();
        let impossible_child = file.join("index.js");
        let witness = BundleResolutionInput {
            kind: "missing".into(),
            path: impossible_child.to_string_lossy().into_owned(),
            sha256: sha256_bytes(b"missing"),
        };

        assert_eq!(
            bundle_resolution_input_digest(&witness),
            Some(witness.sha256.clone())
        );
    }

    #[tokio::test]
    async fn bytecode_cache_rejects_same_length_source_and_output_tampering() {
        let dir = tempdir().expect("tempdir");
        let source = dir.path().join("entry.js");
        let bytecode = dir.path().join("entry.hbc");
        std::fs::write(&source, "module.exports = 1").unwrap();
        std::fs::write(&bytecode, b"valid-looking-bytecode").unwrap();
        let manifest = serde_json::json!({
            "version": 2,
            "sourcePath": std::fs::canonicalize(&source).unwrap().to_string_lossy(),
            "sourceSha256": sha256_file(&source).await.unwrap(),
            "bytecodeSha256": sha256_file(&bytecode).await.unwrap(),
            "sourceMapPath": null,
            "sourceMapSha256": null,
            "toolchainIdentity": engine::hermes::bytecode_cache_identity(),
        });
        std::fs::write(
            bytecode_manifest_path(&bytecode),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(bytecode_cache_is_fresh(&source, &bytecode).await);

        std::fs::write(&source, "module.exports = 2").unwrap();
        assert!(!bytecode_cache_is_fresh(&source, &bytecode).await);
        std::fs::write(&source, "module.exports = 1").unwrap();
        std::fs::write(&bytecode, b"tampered-bytecode---").unwrap();
        assert!(!bytecode_cache_is_fresh(&source, &bytecode).await);
    }

    #[tokio::test]
    async fn content_addressed_bytecode_cache_repairs_corrupt_existing_unit() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("entry.js");
        std::fs::write(&source, "globalThis.__bytecodeRepair = 1;\n").unwrap();
        let first = match prepare_bytecode_entry(&source).await {
            Ok(path) => path,
            Err(_) => return, // checked-in hermesc is optional in minimal dev envs
        };
        assert!(bytecode_cache_is_fresh(&source, &first).await);
        std::fs::write(&first, b"corrupt-bytecode").unwrap();
        assert!(!bytecode_cache_is_fresh(&source, &first).await);
        let repaired = prepare_bytecode_entry(&source).await.unwrap();
        assert_eq!(repaired, first);
        assert!(bytecode_cache_is_fresh(&source, &repaired).await);
        assert!(repaired
            .components()
            .any(|component| component.as_os_str() == ".bytecode-cache"));
        std::fs::remove_dir_all(repaired.parent().unwrap()).ok();
    }

    #[test]
    fn bytecode_cache_quota_evicts_lru_units_and_skips_locked_publishers() {
        let dir = tempdir().unwrap();
        let old = dir.path().join("a".repeat(64));
        let locked = dir.path().join("b".repeat(64));
        let leased = dir.path().join("c".repeat(64));
        let current = dir.path().join("d".repeat(64));
        for artifact in [&old, &locked, &leased, &current] {
            std::fs::create_dir(artifact).unwrap();
            std::fs::write(artifact.join("entry.hbc"), vec![0u8; 64]).unwrap();
            touch_bytecode_artifact(artifact);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let mut dead_pid = std::process::id().saturating_add(1_000_000);
        while process_is_running(dead_pid) {
            dead_pid = dead_pid.saturating_add(1);
        }
        let abandoned = dir.path().join(format!(".stage-{dead_pid}-1-dead"));
        let live = dir
            .path()
            .join(format!(".stage-{}-1-live", std::process::id()));
        std::fs::create_dir(&abandoned).unwrap();
        std::fs::create_dir(&live).unwrap();
        let locked_gate = try_acquire_bundle_artifact_gate(&locked)
            .unwrap()
            .expect("test owns publisher gate");
        let execution_lease = acquire_bundle_lease(&leased).unwrap();

        prune_bytecode_cache_to_limit(dir.path(), &current, 64);
        assert!(!old.exists(), "oldest unlocked HBC unit should be evicted");
        assert!(
            locked.exists(),
            "a live publisher gate must prevent eviction"
        );
        assert!(
            leased.exists(),
            "a live execution lease must prevent eviction"
        );
        assert!(current.exists(), "the current HBC unit must be retained");
        assert!(
            !abandoned.exists(),
            "dead publisher stages must be reclaimed"
        );
        assert!(live.exists(), "live publisher stages must not be reclaimed");
        drop(execution_lease);
        drop(locked_gate);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_bundle_publishers_converge_on_one_complete_artifact() {
        let dir = tempdir().expect("tempdir");
        let artifact_dir = tempdir().expect("artifact tempdir");
        let entry = dir.path().join("entry.js");
        let artifact_root = artifact_dir.path().join("cache-key");
        std::fs::write(&entry, "module.exports = { answer: 42 };\n").unwrap();

        let mut tasks = Vec::new();
        for _ in 0..4 {
            let entry = entry.clone();
            let artifact_root = artifact_root.clone();
            tasks.push(tokio::spawn(async move {
                run_bundler(&entry, &artifact_root, BundleFormat::Cjs).await
            }));
        }
        let mut outputs = Vec::new();
        for task in tasks {
            outputs.push(task.await.unwrap().unwrap());
        }
        assert!(outputs.iter().all(|output| output == &outputs[0]));
        assert!(bundle_cache_is_fresh(&outputs[0], &entry).await);
        assert_eq!(
            std::fs::read_dir(&artifact_root)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".stage-"))
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn corrupt_existing_bundle_graph_is_quarantined_and_repaired() {
        let source_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let entry = source_dir.path().join("entry.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(&entry, "module.exports = 42;\n").unwrap();
        let first = run_bundler(&entry, &artifact_root, BundleFormat::Cjs)
            .await
            .unwrap();
        std::fs::write(&first, "tampered output").unwrap();
        assert!(!bundle_cache_is_fresh(&first, &entry).await);

        let repaired = run_bundler(&entry, &artifact_root, BundleFormat::Cjs)
            .await
            .unwrap();
        assert_eq!(repaired, first);
        assert!(bundle_cache_is_fresh(&repaired, &entry).await);
        assert_eq!(
            std::fs::read_dir(&artifact_root)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".invalid-"))
                .count(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bundle_rejects_source_mutation_after_rolldown_capture() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        bundler_toolchain_identity().expect("authenticate bundler before timed barrier");
        let source_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let barrier_dir = tempdir().unwrap();
        let entry = source_dir.path().join("entry.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(&entry, "module.exports = 'before';\n").unwrap();
        // The shared test lock owns these process-global hook variables until
        // the child has exited and they have been removed.
        unsafe {
            std::env::set_var("IBEX_TEST_BUNDLE_BARRIER_ENTRY", &entry);
            std::env::set_var("IBEX_TEST_BUNDLE_BARRIER_DIR", barrier_dir.path());
        }
        let task_entry = entry.clone();
        let task_root = artifact_root.clone();
        let task =
            tokio::spawn(
                async move { run_bundler(&task_entry, &task_root, BundleFormat::Cjs).await },
            );
        let captured = barrier_dir.path().join("captured");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !captured.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let reached_barrier = captured.exists();
        if reached_barrier {
            std::fs::write(&entry, "module.exports = 'after!';\n").unwrap();
        }
        // Always unblock and join the child before asserting so a timeout
        // cannot strand a subprocess or leak the process-global test hook.
        std::fs::write(barrier_dir.path().join("release"), []).unwrap();
        let result = task.await.unwrap();
        unsafe {
            std::env::remove_var("IBEX_TEST_BUNDLE_BARRIER_ENTRY");
            std::env::remove_var("IBEX_TEST_BUNDLE_BARRIER_DIR");
        }
        assert!(
            reached_barrier,
            "bundler never reached source capture barrier: {result:?}"
        );
        assert!(result.is_err(), "mixed-version bundle must not publish");
        assert!(
            std::fs::read_dir(&artifact_root)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .all(|entry| entry.file_name().to_string_lossy().starts_with('.')),
            "no completed graph may survive a mid-build source edit"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bundle_rejects_resolution_candidate_added_after_resolver_decision() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        bundler_toolchain_identity().expect("authenticate bundler before timed barrier");
        let source_dir = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let barrier_dir = tempdir().unwrap();
        let entry = source_dir.path().join("entry.js");
        let selected = source_dir.path().join("dep.ts");
        let higher_precedence = source_dir.path().join("dep.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(&entry, "module.exports = require('./dep').value;\n").unwrap();
        std::fs::write(&selected, "exports.value = 'typescript';\n").unwrap();
        unsafe {
            std::env::set_var("IBEX_TEST_BUNDLE_BARRIER_ENTRY", &selected);
            std::env::set_var("IBEX_TEST_BUNDLE_BARRIER_DIR", barrier_dir.path());
        }
        let task_entry = entry.clone();
        let task_root = artifact_root.clone();
        let task =
            tokio::spawn(
                async move { run_bundler(&task_entry, &task_root, BundleFormat::Cjs).await },
            );
        let captured = barrier_dir.path().join("captured");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !captured.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let reached_barrier = captured.exists();
        if reached_barrier {
            std::fs::write(&higher_precedence, "exports.value = 'javascript';\n").unwrap();
        }
        std::fs::write(barrier_dir.path().join("release"), []).unwrap();
        let result = task.await.unwrap();
        unsafe {
            std::env::remove_var("IBEX_TEST_BUNDLE_BARRIER_ENTRY");
            std::env::remove_var("IBEX_TEST_BUNDLE_BARRIER_DIR");
        }
        assert!(
            reached_barrier,
            "bundler never resolved/captured dep.ts: {result:?}"
        );
        assert!(
            result.is_err(),
            "a build whose resolution precedence changed must not publish"
        );
        assert!(std::fs::read_dir(&artifact_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .all(|entry| entry.file_name().to_string_lossy().starts_with('.')));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bundle_witnesses_hoisted_packages_above_nested_project_boundaries() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        bundler_toolchain_identity().expect("authenticate bundler before timed barrier");
        let workspace = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let barrier_dir = tempdir().unwrap();
        let project = workspace.path().join("apps/project");
        let selected_package = workspace.path().join("node_modules/pkg");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::create_dir_all(&selected_package).unwrap();
        let entry = project.join("entry.js");
        let selected = selected_package.join("index.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(&entry, "module.exports = require('pkg').value;\n").unwrap();
        std::fs::write(
            selected_package.join("package.json"),
            r#"{"name":"pkg","main":"index.js"}"#,
        )
        .unwrap();
        std::fs::write(&selected, "exports.value = 'workspace';\n").unwrap();
        unsafe {
            std::env::set_var("IBEX_TEST_BUNDLE_BARRIER_ENTRY", &selected);
            std::env::set_var("IBEX_TEST_BUNDLE_BARRIER_DIR", barrier_dir.path());
        }

        let task_entry = entry.clone();
        let task_root = artifact_root.clone();
        let task =
            tokio::spawn(
                async move { run_bundler(&task_entry, &task_root, BundleFormat::Cjs).await },
            );
        let captured = barrier_dir.path().join("captured");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !captured.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let reached_barrier = captured.exists();

        // Node lookup ignores the nested .git boundary. This newly-created
        // package is closer to the importer than the package selected above,
        // so publication must fail even though the selected source is intact.
        let closer_package = workspace.path().join("apps/node_modules/pkg");
        if reached_barrier {
            std::fs::create_dir_all(&closer_package).unwrap();
            std::fs::write(
                closer_package.join("package.json"),
                r#"{"name":"pkg","main":"index.js"}"#,
            )
            .unwrap();
            std::fs::write(
                closer_package.join("index.js"),
                "exports.value = 'closer';\n",
            )
            .unwrap();
        }
        std::fs::write(barrier_dir.path().join("release"), []).unwrap();
        let result = task.await.unwrap();
        unsafe {
            std::env::remove_var("IBEX_TEST_BUNDLE_BARRIER_ENTRY");
            std::env::remove_var("IBEX_TEST_BUNDLE_BARRIER_DIR");
        }
        assert!(
            reached_barrier,
            "bundler never resolved hoisted package: {result:?}"
        );
        assert!(
            result.is_err(),
            "a closer hoisted package added mid-build must prevent publication"
        );
        assert!(std::fs::read_dir(&artifact_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .all(|entry| entry.file_name().to_string_lossy().starts_with('.')));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bundle_witnesses_bare_package_subpath_extension_precedence() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        bundler_toolchain_identity().expect("authenticate bundler before timed barrier");
        let project = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let barrier_dir = tempdir().unwrap();
        let package = project.path().join("node_modules/pkg");
        let nested = package.join("lib");
        std::fs::create_dir_all(&nested).unwrap();
        let entry = project.path().join("entry.js");
        let selected = nested.join("value.ts");
        let higher_precedence = nested.join("value.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(&entry, "module.exports = require('pkg/lib/value').value;\n").unwrap();
        std::fs::write(&selected, "exports.value = 'typescript';\n").unwrap();
        unsafe {
            std::env::set_var("IBEX_TEST_BUNDLE_BARRIER_ENTRY", &selected);
            std::env::set_var("IBEX_TEST_BUNDLE_BARRIER_DIR", barrier_dir.path());
        }

        let task_entry = entry.clone();
        let task_root = artifact_root.clone();
        let task =
            tokio::spawn(
                async move { run_bundler(&task_entry, &task_root, BundleFormat::Cjs).await },
            );
        let captured = barrier_dir.path().join("captured");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !captured.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let reached_barrier = captured.exists();
        if reached_barrier {
            std::fs::write(&higher_precedence, "exports.value = 'javascript';\n").unwrap();
        }
        std::fs::write(barrier_dir.path().join("release"), []).unwrap();
        let result = task.await.unwrap();
        unsafe {
            std::env::remove_var("IBEX_TEST_BUNDLE_BARRIER_ENTRY");
            std::env::remove_var("IBEX_TEST_BUNDLE_BARRIER_DIR");
        }
        assert!(
            reached_barrier,
            "bundler never resolved package subpath: {result:?}"
        );
        assert!(
            result.is_err(),
            "adding a higher-precedence package subpath candidate must prevent publication"
        );
        assert!(std::fs::read_dir(&artifact_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .all(|entry| entry.file_name().to_string_lossy().starts_with('.')));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bundle_witnesses_package_main_target_extension_precedence() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        bundler_toolchain_identity().expect("authenticate bundler before timed barrier");
        let project = tempdir().unwrap();
        let cache_dir = tempdir().unwrap();
        let barrier_dir = tempdir().unwrap();
        let package = project.path().join("node_modules/pkg");
        let nested = package.join("lib");
        std::fs::create_dir_all(&nested).unwrap();
        let entry = project.path().join("entry.js");
        let selected = nested.join("value.json");
        let higher_precedence = nested.join("value.js");
        let artifact_root = cache_dir.path().join("cache-key");
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0","main":"lib/value"}"#,
        )
        .unwrap();
        std::fs::write(&entry, "module.exports = require('pkg').value;\n").unwrap();
        std::fs::write(&selected, r#"{"value":"json"}"#).unwrap();
        unsafe {
            std::env::set_var("IBEX_TEST_BUNDLE_BARRIER_ENTRY", &selected);
            std::env::set_var("IBEX_TEST_BUNDLE_BARRIER_DIR", barrier_dir.path());
        }

        let task_entry = entry.clone();
        let task_root = artifact_root.clone();
        let task =
            tokio::spawn(
                async move { run_bundler(&task_entry, &task_root, BundleFormat::Cjs).await },
            );
        let captured = barrier_dir.path().join("captured");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !captured.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let reached_barrier = captured.exists();
        if reached_barrier {
            std::fs::write(&higher_precedence, "exports.value = 'javascript';\n").unwrap();
        }
        std::fs::write(barrier_dir.path().join("release"), []).unwrap();
        let result = task.await.unwrap();
        unsafe {
            std::env::remove_var("IBEX_TEST_BUNDLE_BARRIER_ENTRY");
            std::env::remove_var("IBEX_TEST_BUNDLE_BARRIER_DIR");
        }
        assert!(
            reached_barrier,
            "bundler never resolved package main target: {result:?}"
        );
        assert!(
            result.is_err(),
            "adding a higher-precedence package main candidate must prevent publication"
        );
        assert!(std::fs::read_dir(&artifact_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .all(|entry| entry.file_name().to_string_lossy().starts_with('.')));
    }

    #[test]
    fn bundle_cache_quota_evicts_old_graphs_but_keeps_current() {
        let dir = tempdir().unwrap();
        let old = dir.path().join("key-a/graph-old");
        let keep = dir.path().join("key-b/graph-current");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("bundle.js"), vec![0u8; 64]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::write(keep.join("bundle.js"), vec![0u8; 64]).unwrap();

        prune_bundle_cache_to_limit(dir.path(), &keep, 64);
        assert!(!old.exists());
        assert!(keep.exists());
    }

    #[test]
    fn bundle_cache_quota_respects_raii_file_lock_lease() {
        let dir = tempdir().unwrap();
        let keep = dir.path().join("key-new").join("graph-new");
        let leased = dir.path().join("key-old").join("graph-old");
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::create_dir_all(&leased).unwrap();
        std::fs::write(keep.join("bundle.js"), vec![0u8; 64]).unwrap();
        std::fs::write(leased.join("bundle.js"), vec![0u8; 64]).unwrap();
        let lease = acquire_bundle_lease(&leased).unwrap();

        prune_bundle_cache_to_limit(dir.path(), &keep, 64);
        assert!(leased.exists(), "live shared lease must prevent eviction");
        drop(lease);
        prune_bundle_cache_to_limit(dir.path(), &keep, 64);
        assert!(
            !leased.exists(),
            "RAII drop must make the artifact evictable"
        );
    }

    #[tokio::test]
    async fn failed_bundle_publish_cleans_incomplete_stage() {
        let dir = tempdir().unwrap();
        let artifact_dir = tempdir().expect("artifact tempdir");
        let entry = dir.path().join("invalid.js");
        let artifact_root = artifact_dir.path().join("cache-key");
        std::fs::write(&entry, "function broken( {\n").unwrap();
        assert!(run_bundler(&entry, &artifact_root, BundleFormat::Cjs)
            .await
            .is_err());
        let stage_count = std::fs::read_dir(&artifact_root)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".stage-"))
            .count();
        assert_eq!(stage_count, 0);
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
        let paths = bundler_cache_input_paths().unwrap();

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
    fn bundler_toolchain_identity_authenticates_selected_runner_and_install() {
        if find_js_runner().is_err() {
            return;
        }
        let identity = compute_bundler_toolchain_identity().unwrap();
        assert!(identity.runner.is_absolute());
        assert!(identity.runner.is_file());
        assert_ne!(identity.digest, [0; 32]);
        assert_eq!(
            identity.digest,
            bundler_toolchain_identity().unwrap().digest,
            "the cached identity must describe the same captured toolchain"
        );
    }

    #[tokio::test]
    async fn application_cwd_cannot_select_lookalike_bundler_tooling() {
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
        std::env::remove_var("IBEX_REPO_ROOT");
        std::env::remove_var("EXACT_REPO_ROOT");

        let fake = tempdir().unwrap();
        std::fs::create_dir_all(fake.path().join("vendored-generated")).unwrap();
        std::fs::create_dir_all(fake.path().join("packages/ibex-runtime-js")).unwrap();
        std::fs::create_dir_all(fake.path().join("packages/ibex-devtools/src/scripts")).unwrap();
        std::fs::write(
            fake.path().join("packages/ibex-runtime-js/package.json"),
            "{}",
        )
        .unwrap();
        std::fs::write(
            fake.path().join("packages/ibex-devtools/package.json"),
            "{}",
        )
        .unwrap();
        std::fs::write(
            fake.path()
                .join("packages/ibex-devtools/src/scripts/rolldown-bundle.mjs"),
            "throw new Error('application-controlled bundler executed');",
        )
        .unwrap();

        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(fake.path()).unwrap();
        let selected = bundler_script_path();
        std::env::set_current_dir(original).unwrap();

        let selected = selected.unwrap();
        assert!(selected.starts_with(std::fs::canonicalize(env!("CARGO_MANIFEST_DIR")).unwrap()));
        assert!(!selected.starts_with(fake.path()));
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
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
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
        let runtime = Runtime::from_audit_cli(&cli).expect("diagnostic runtime");
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
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
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
        let runtime = Runtime::from_audit_cli(&cli).expect("diagnostic runtime");
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
        let _lock = crate::engine::hermes::hermes_engine_test_lock()
            .lock()
            .await;
        let _env = ProductionEnvGuard::capture();
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
        let runtime = Runtime::from_audit_cli(&cli).expect("diagnostic runtime");
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
