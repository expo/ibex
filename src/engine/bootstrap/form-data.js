(function() {
  function FormData() {
    this._entries = [];
  }
  FormData.prototype.append = function(name, value, filename) {
    this._entries.push({ name: String(name), value: value, filename: filename });
  };
  FormData.prototype.set = function(name, value, filename) {
    this.delete(name);
    this.append(name, value, filename);
  };
  FormData.prototype.get = function(name) {
    for (var i = 0; i < this._entries.length; i++) {
      if (this._entries[i].name === name) return this._entries[i].value;
    }
    return null;
  };
  FormData.prototype.getAll = function(name) {
    var result = [];
    for (var i = 0; i < this._entries.length; i++) {
      if (this._entries[i].name === name) result.push(this._entries[i].value);
    }
    return result;
  };
  FormData.prototype.has = function(name) {
    for (var i = 0; i < this._entries.length; i++) {
      if (this._entries[i].name === name) return true;
    }
    return false;
  };
  FormData.prototype.delete = function(name) {
    this._entries = this._entries.filter(function(e) { return e.name !== name; });
  };
  FormData.prototype.keys = function() {
    var keys = [];
    for (var i = 0; i < this._entries.length; i++) keys.push(this._entries[i].name);
    return keys[Symbol.iterator] ? keys[Symbol.iterator]() : { _i: 0, _a: keys, next: function() {
      return this._i < this._a.length ? { value: this._a[this._i++], done: false } : { done: true };
    }};
  };
  FormData.prototype.values = function() {
    var vals = [];
    for (var i = 0; i < this._entries.length; i++) vals.push(this._entries[i].value);
    return vals[Symbol.iterator] ? vals[Symbol.iterator]() : { _i: 0, _a: vals, next: function() {
      return this._i < this._a.length ? { value: this._a[this._i++], done: false } : { done: true };
    }};
  };
  FormData.prototype.entries = function() {
    var ents = [];
    for (var i = 0; i < this._entries.length; i++) {
      ents.push([this._entries[i].name, this._entries[i].value]);
    }
    return ents[Symbol.iterator] ? ents[Symbol.iterator]() : { _i: 0, _a: ents, next: function() {
      return this._i < this._a.length ? { value: this._a[this._i++], done: false } : { done: true };
    }};
  };
  FormData.prototype.forEach = function(callback, thisArg) {
    for (var i = 0; i < this._entries.length; i++) {
      callback.call(thisArg, this._entries[i].value, this._entries[i].name, this);
    }
  };
  FormData.prototype[Symbol.iterator] = FormData.prototype.entries;

  // Parse multipart/form-data body
  FormData._parseMultipart = function(body, boundary) {
    var fd = new FormData();
    if (!body || !boundary) return fd;
    var bodyStr = typeof body === 'string' ? body :
      (typeof TextDecoder === 'function' ? new TextDecoder().decode(body) : String(body));
    var parts = bodyStr.split('--' + boundary);
    for (var i = 1; i < parts.length; i++) {
      var part = parts[i];
      if (part.indexOf('--') === 0) break; // end boundary
      var headerEnd = part.indexOf('\r\n\r\n');
      if (headerEnd < 0) headerEnd = part.indexOf('\n\n');
      if (headerEnd < 0) continue;
      var sep = part.indexOf('\r\n\r\n') >= 0 ? '\r\n\r\n' : '\n\n';
      var headerSection = part.substring(0, headerEnd);
      var value = part.substring(headerEnd + sep.length);
      // Trim trailing \r\n
      if (value.endsWith('\r\n')) value = value.slice(0, -2);
      else if (value.endsWith('\n')) value = value.slice(0, -1);
      // Parse Content-Disposition
      var nameMatch = headerSection.match(/name="([^"]+)"/);
      var filenameMatch = headerSection.match(/filename="([^"]+)"/);
      if (nameMatch) {
        fd.append(nameMatch[1], value, filenameMatch ? filenameMatch[1] : undefined);
      }
    }
    return fd;
  };

  globalThis.FormData = FormData;
})();
