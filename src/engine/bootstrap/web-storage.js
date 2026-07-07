(function() {
  'use strict';
  var _homedir = typeof process !== 'undefined' && process.env && process.env.HOME ? process.env.HOME : '/tmp';
  var _storePath = _homedir + '/.exact/localStorage.json';
  var _mkdirPath = _homedir + '/.exact';

  function _utf8Encode(str) {
    if (typeof TextEncoder === 'function') {
      try { return new TextEncoder().encode(str); } catch(e) {}
    }
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
      var code = str.codePointAt(i);
      if (code > 0xffff) i++;
      if (code < 0x80) {
        bytes.push(code);
      } else if (code < 0x800) {
        bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
      } else if (code < 0x10000) {
        bytes.push(
          0xe0 | (code >> 12),
          0x80 | ((code >> 6) & 0x3f),
          0x80 | (code & 0x3f));
      } else {
        bytes.push(
          0xf0 | (code >> 18),
          0x80 | ((code >> 12) & 0x3f),
          0x80 | ((code >> 6) & 0x3f),
          0x80 | (code & 0x3f));
      }
    }
    return new Uint8Array(bytes);
  }

  function _utf8Decode(bytes) {
    if (typeof TextDecoder === 'function') {
      try { return new TextDecoder('utf-8').decode(bytes); } catch(e) {}
    }
    var out = '';
    for (var i = 0; i < bytes.length;) {
      var b0 = bytes[i++];
      if (b0 < 0x80) {
        out += String.fromCharCode(b0);
      } else if ((b0 & 0xe0) === 0xc0 && i < bytes.length) {
        var b1 = bytes[i++];
        out += String.fromCharCode(((b0 & 0x1f) << 6) | (b1 & 0x3f));
      } else if ((b0 & 0xf0) === 0xe0 && i + 1 < bytes.length) {
        var b2 = bytes[i++];
        var b3 = bytes[i++];
        out += String.fromCharCode(((b0 & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f));
      } else if ((b0 & 0xf8) === 0xf0 && i + 2 < bytes.length) {
        var b4 = bytes[i++];
        var b5 = bytes[i++];
        var b6 = bytes[i++];
        var code = ((b0 & 0x07) << 18) | ((b4 & 0x3f) << 12) | ((b5 & 0x3f) << 6) | (b6 & 0x3f);
        code -= 0x10000;
        out += String.fromCharCode(0xd800 + (code >> 10), 0xdc00 + (code & 0x3ff));
      } else {
        out += '\ufffd';
      }
    }
    return out;
  }

  function _load() {
    try {
      if (typeof __exactReadFile === 'function') {
        var bytes = __exactReadFile(_storePath);
        if (bytes && bytes.length > 0) {
          return JSON.parse(_utf8Decode(bytes));
        }
      }
    } catch(e) {}
    return {};
  }

  function _save(data) {
    try {
      if (typeof __exactWriteFile === 'function' && typeof __exactMkdir === 'function') {
        try { __exactMkdir(_mkdirPath); } catch(e) {}
        var json = JSON.stringify(data);
        __exactWriteFile(_storePath, _utf8Encode(json));
      }
    } catch(e) {}
  }

  function StorageImpl(persistent) {
    this._data = persistent ? _load() : {};
    this._persistent = persistent;
  }
  Object.defineProperty(StorageImpl.prototype, 'length', {
    get: function() {
      return Object.keys(this._data).length;
    }
  });
  StorageImpl.prototype.key = function(index) {
    var keys = Object.keys(this._data);
    return index >= 0 && index < keys.length ? keys[index] : null;
  };
  StorageImpl.prototype.getItem = function(key) {
    var k = String(key);
    return this._data.hasOwnProperty(k) ? this._data[k] : null;
  };
  StorageImpl.prototype.setItem = function(key, value) {
    this._data[String(key)] = String(value);
    if (this._persistent) _save(this._data);
  };
  StorageImpl.prototype.removeItem = function(key) {
    delete this._data[String(key)];
    if (this._persistent) _save(this._data);
  };
  StorageImpl.prototype.clear = function() {
    this._data = {};
    if (this._persistent) _save(this._data);
  };

  globalThis.localStorage = new StorageImpl(true);
  globalThis.sessionStorage = new StorageImpl(false);
})();
