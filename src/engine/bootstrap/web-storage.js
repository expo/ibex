(function() {
  'use strict';
  var _homedir = typeof process !== 'undefined' && process.env && process.env.HOME ? process.env.HOME : '/tmp';
  var _storePath = _homedir + '/.exact/localStorage.json';
  var _mkdirPath = _homedir + '/.exact';

  function _load() {
    try {
      if (typeof __exactReadFile === 'function') {
        var bytes = __exactReadFile(_storePath);
        if (bytes && bytes.length > 0) {
          var str = '';
          for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
          return JSON.parse(str);
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
        var bytes = new Uint8Array(json.length);
        for (var i = 0; i < json.length; i++) bytes[i] = json.charCodeAt(i);
        __exactWriteFile(_storePath, bytes);
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
