(function() {
  try {
    var buf = globalThis.require('buffer');
    if (buf && buf.Buffer) {
      globalThis.Buffer = buf.Buffer;
    }
  } catch(e) {}
  try {
    var urlMod = globalThis.require('url');
    if (urlMod) {
      if (urlMod.URL && typeof globalThis.URL === 'undefined') {
        globalThis.URL = urlMod.URL;
      }
      if (urlMod.URLSearchParams && typeof globalThis.URLSearchParams === 'undefined') {
        globalThis.URLSearchParams = urlMod.URLSearchParams;
      }
    }
  } catch(e) {}
  // setImmediate / clearImmediate (Node.js global)
  if (typeof globalThis.setImmediate === 'undefined') {
    globalThis.setImmediate = function(callback) {
      var args = [];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      return globalThis.setTimeout(function() { callback.apply(null, args); }, 0);
    };
    globalThis.clearImmediate = function(handle) {
      globalThis.clearTimeout(handle);
    };
  }
  // AbortController / AbortSignal (Web API)
  if (typeof globalThis.AbortController === 'undefined') {
    function AbortSignal() {
      this.aborted = false;
      this.reason = undefined;
      this._listeners = [];
    }
    AbortSignal.prototype.addEventListener = function(type, listener) {
      if (type === 'abort') this._listeners.push(listener);
    };
    AbortSignal.prototype.removeEventListener = function(type, listener) {
      if (type === 'abort') {
        var idx = this._listeners.indexOf(listener);
        if (idx !== -1) this._listeners.splice(idx, 1);
      }
    };
    AbortSignal.prototype.throwIfAborted = function() {
      if (this.aborted) throw this.reason;
    };
    AbortSignal.abort = function(reason) {
      var s = new AbortSignal();
      s.aborted = true;
      s.reason = reason !== undefined ? reason : new DOMException('The operation was aborted.', 'AbortError');
      return s;
    };
    AbortSignal.timeout = function(ms) {
      var s = new AbortSignal();
      globalThis.setTimeout(function() {
        s.aborted = true;
        s.reason = new DOMException('The operation was aborted due to timeout.', 'TimeoutError');
        for (var i = 0; i < s._listeners.length; i++) {
          try { s._listeners[i]({ type: 'abort', target: s }); } catch(e) {}
        }
      }, ms);
      return s;
    };
    function AbortController() {
      this.signal = new AbortSignal();
    }
    AbortController.prototype.abort = function(reason) {
      if (this.signal.aborted) return;
      this.signal.aborted = true;
      this.signal.reason = reason !== undefined ? reason : new DOMException('The operation was aborted.', 'AbortError');
      var listeners = this.signal._listeners.slice();
      for (var i = 0; i < listeners.length; i++) {
        try { listeners[i]({ type: 'abort', target: this.signal }); } catch(e) {}
      }
    };
    globalThis.AbortController = AbortController;
    globalThis.AbortSignal = AbortSignal;
  }
  // DOMException polyfill (if not available)
  if (typeof globalThis.DOMException === 'undefined') {
    function DOMException(message, name) {
      this.message = message || '';
      this.name = name || 'Error';
    }
    DOMException.prototype = Object.create(Error.prototype);
    DOMException.prototype.constructor = DOMException;
    globalThis.DOMException = DOMException;
  }
  // structuredClone (Web API)
  if (typeof globalThis.structuredClone === 'undefined') {
    globalThis.structuredClone = function(value) {
      return JSON.parse(JSON.stringify(value));
    };
  }
  // performance (Web API) — use perf_hooks if available
  if (typeof globalThis.performance === 'undefined') {
    var _perfStart = Date.now();
    globalThis.performance = {
      now: function() {
        if (typeof __exactHrtime === 'function') {
          var parts = __exactHrtime();
          if (typeof parts === 'string') {
            var p = parts.split(',');
            return (parseInt(p[0], 10) * 1000) + (parseInt(p[1], 10) / 1000000);
          }
        }
        return Date.now() - _perfStart;
      },
      timeOrigin: _perfStart,
      mark: function() {},
      measure: function() {},
      getEntries: function() { return []; },
      getEntriesByName: function() { return []; },
      getEntriesByType: function() { return []; },
      clearMarks: function() {},
      clearMeasures: function() {}
    };
  }
  // Event / EventTarget / CustomEvent (Web API)
  if (typeof globalThis.EventTarget === 'undefined') {
    function EventTarget() {
      this._listeners = {};
    }
    EventTarget.prototype.addEventListener = function(type, listener, options) {
      if (!this._listeners[type]) this._listeners[type] = [];
      this._listeners[type].push({ fn: listener, once: options && options.once });
    };
    EventTarget.prototype.removeEventListener = function(type, listener) {
      if (!this._listeners[type]) return;
      this._listeners[type] = this._listeners[type].filter(function(l) { return l.fn !== listener; });
    };
    EventTarget.prototype.dispatchEvent = function(event) {
      if (!event || !event.type) return true;
      var listeners = this._listeners[event.type];
      if (!listeners) return true;
      event.target = this;
      event.currentTarget = this;
      var toRemove = [];
      for (var i = 0; i < listeners.length; i++) {
        try { listeners[i].fn.call(this, event); } catch(e) {}
        if (listeners[i].once) toRemove.push(i);
      }
      for (var j = toRemove.length - 1; j >= 0; j--) {
        listeners.splice(toRemove[j], 1);
      }
      return !event.defaultPrevented;
    };
    globalThis.EventTarget = EventTarget;
  }
  if (typeof globalThis.Event === 'undefined') {
    function Event(type, options) {
      this.type = type;
      this.bubbles = (options && options.bubbles) || false;
      this.cancelable = (options && options.cancelable) || false;
      this.composed = (options && options.composed) || false;
      this.defaultPrevented = false;
      this.target = null;
      this.currentTarget = null;
      this.timeStamp = Date.now();
    }
    Event.prototype.preventDefault = function() {
      if (this.cancelable) this.defaultPrevented = true;
    };
    Event.prototype.stopPropagation = function() {};
    Event.prototype.stopImmediatePropagation = function() {};
    globalThis.Event = Event;
  }
  if (typeof globalThis.CustomEvent === 'undefined') {
    function CustomEvent(type, options) {
      Event.call(this, type, options);
      this.detail = (options && options.detail) || null;
    }
    CustomEvent.prototype = Object.create(Event.prototype);
    CustomEvent.prototype.constructor = CustomEvent;
    globalThis.CustomEvent = CustomEvent;
  }
  // Blob (Web API)
  if (typeof globalThis.Blob === 'undefined') {
    function Blob(parts, options) {
      this._parts = parts || [];
      this.type = (options && options.type) || '';
      var totalSize = 0;
      for (var i = 0; i < this._parts.length; i++) {
        var part = this._parts[i];
        if (typeof part === 'string') totalSize += part.length;
        else if (part instanceof Uint8Array) totalSize += part.length;
        else if (part instanceof ArrayBuffer) totalSize += part.byteLength;
        else if (part && part._parts) totalSize += part.size;
        else totalSize += String(part).length;
      }
      this.size = totalSize;
    }
    Blob.prototype.text = function() {
      var result = '';
      for (var i = 0; i < this._parts.length; i++) {
        var part = this._parts[i];
        if (typeof part === 'string') result += part;
        else if (part instanceof Uint8Array) {
          for (var j = 0; j < part.length; j++) result += String.fromCharCode(part[j]);
        } else result += String(part);
      }
      return Promise.resolve(result);
    };
    Blob.prototype.arrayBuffer = function() {
      var self = this;
      return this.text().then(function(text) {
        var buf = new Uint8Array(text.length);
        for (var i = 0; i < text.length; i++) buf[i] = text.charCodeAt(i);
        return buf.buffer;
      });
    };
    Blob.prototype.slice = function(start, end, contentType) {
      return this.text().then(function(text) {
        return new Blob([text.slice(start, end)], { type: contentType || '' });
      });
    };
    Blob.prototype.stream = function() { return null; };
    globalThis.Blob = Blob;

    // File extends Blob
    function File(parts, name, options) {
      Blob.call(this, parts, options);
      this.name = name;
      this.lastModified = (options && options.lastModified) || Date.now();
    }
    File.prototype = Object.create(Blob.prototype);
    File.prototype.constructor = File;
    globalThis.File = File;
  }
})();
