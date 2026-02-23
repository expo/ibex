var g = globalThis;
var _exactFsInitialized = false;
function ensureExactFs() {
  if (_exactFsInitialized) return;
  if (typeof g.__exactEnsureFs === 'function') {
    try { g.__exactEnsureFs(); } catch (e) {}
  }
  _exactFsInitialized = true;
}

// Argument validation helpers (match Node.js ERR_INVALID_ARG_TYPE format)
function _fsInvalidArgType(name, expected, actual) {
  var received;
  if (actual === null) received = 'null';
  else if (actual === undefined) received = 'undefined';
  else if (Array.isArray(actual)) received = 'an instance of Array';
  else if (typeof actual === 'string') received = "type string (" + actual + ")";
  else if (typeof actual === 'number') received = 'type number (' + actual + ')';
  else if (typeof actual === 'boolean') received = 'type boolean (' + actual + ')';
  else received = 'type ' + typeof actual;
  var err = new TypeError('The "' + name + '" argument must be of type ' + expected + '. Received ' + received);
  err.code = 'ERR_INVALID_ARG_TYPE';
  return err;
}

function _validateFd(fd) {
  if (typeof fd !== 'number' || fd < 0 || !Number.isInteger(fd)) {
    throw _fsInvalidArgType('fd', 'number', fd);
  }
}

function _validatePath(path, propName) {
  if (typeof path !== 'string' && !Buffer.isBuffer(path)) {
    throw _fsInvalidArgType(propName || 'path', 'string', path);
  }
  if (typeof path === 'string' && path.indexOf('\u0000') !== -1) {
    var err = new TypeError('The argument "' + (propName || 'path') + '" must be a string, Uint8Array, or URL without null bytes. Received ' + JSON.stringify(path));
    err.code = 'ERR_INVALID_ARG_VALUE';
    throw err;
  }
}

function _validateCallback(cb) {
  if (typeof cb !== 'function') {
    throw _fsInvalidArgType('callback', 'function', cb);
  }
}

function toUint8Array(data) {
  if (typeof data === 'string') {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(data);
    var buf = new Uint8Array(data.length * 3);
    var offset = 0;
    for (var i = 0; i < data.length; i++) {
      var code = data.charCodeAt(i);
      if (code < 0x80) { buf[offset++] = code; }
      else if (code < 0x800) { buf[offset++] = 0xc0 | (code >> 6); buf[offset++] = 0x80 | (code & 0x3f); }
      else { buf[offset++] = 0xe0 | (code >> 12); buf[offset++] = 0x80 | ((code >> 6) & 0x3f); buf[offset++] = 0x80 | (code & 0x3f); }
    }
    return buf.slice(0, offset);
  }
  if (data instanceof Uint8Array) return data;
  return new Uint8Array(data);
}

function decodeBytes(bytes, encoding) {
  if (!encoding || encoding === 'buffer') return bytes;
  var enc = encoding.toLowerCase().replace('-', '');
  if (enc === 'utf8' || enc === 'utf-8') enc = 'utf8';
  if (enc === 'utf8') {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(bytes);
    var result = '';
    for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i]);
    return result;
  }
  if (enc === 'ascii' || enc === 'latin1' || enc === 'binary') {
    var result = '';
    for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i]);
    return result;
  }
  if (enc === 'hex') {
    var result = '';
    for (var i = 0; i < bytes.length; i++) result += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return result;
  }
  if (enc === 'base64') {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return typeof btoa === 'function' ? btoa(binary) : binary;
  }
  if (typeof TextDecoder !== 'undefined') return new TextDecoder(encoding).decode(bytes);
  var result = '';
  for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i]);
  return result;
}

function wrapBuffer(bytes) {
  bytes.toString = function(encoding, start, end) {
    var slice = (start !== undefined || end !== undefined) ? bytes.slice(start || 0, end) : bytes;
    if (!encoding) return decodeBytes(slice, 'utf8');
    return decodeBytes(slice, encoding);
  };
  return bytes;
}

function readFileSync(path, options) {
  _validatePath(path);
  ensureExactFs();
  var encoding = typeof options === 'string' ? options : (options && options.encoding);
  var bytes = g.__exactReadFile(path);
  if (encoding) return decodeBytes(bytes, encoding);
  return wrapBuffer(bytes);
}

function writeFileSync(path, data, options) {
  _validatePath(path);
  ensureExactFs();
  g.__exactWriteFile(path, toUint8Array(data));
}

function appendFileSync(path, data, options) {
  _validatePath(path);
  ensureExactFs();
  g.__exactAppendFile(path, toUint8Array(data));
}

function statSync(path) {
  _validatePath(path);
  ensureExactFs();
  var json = g.__exactStat(path);
  var raw = JSON.parse(json);
  raw.isFile = function() { return raw.is_file; };
  raw.isDirectory = function() { return raw.is_dir; };
  raw.isSymbolicLink = function() { return !!raw.is_symlink; };
  raw.isBlockDevice = function() { return false; };
  raw.isCharacterDevice = function() { return false; };
  raw.isFIFO = function() { return false; };
  raw.isSocket = function() { return false; };
  raw.mtimeMs = raw.mtime_ms;
  raw.mtime = new Date(raw.mtime_ms);
  raw.atimeMs = raw.mtime_ms;
  raw.atime = new Date(raw.mtime_ms);
  raw.ctimeMs = raw.mtime_ms;
  raw.ctime = new Date(raw.mtime_ms);
  return raw;
}

function lstatSync(path) {
  _validatePath(path);
  ensureExactFs();
  var json = g.__exactLstat(path);
  var raw = JSON.parse(json);
  raw.isFile = function() { return raw.is_file; };
  raw.isDirectory = function() { return raw.is_dir; };
  raw.isSymbolicLink = function() { return !!raw.is_symlink; };
  raw.isBlockDevice = function() { return false; };
  raw.isCharacterDevice = function() { return false; };
  raw.isFIFO = function() { return false; };
  raw.isSocket = function() { return false; };
  raw.mtimeMs = raw.mtime_ms;
  raw.mtime = new Date(raw.mtime_ms);
  return raw;
}

function readdirSync(path) {
  _validatePath(path);
  ensureExactFs();
  return JSON.parse(g.__exactReaddir(path));
}

function mkdirSync(path, options) {
  _validatePath(path);
  ensureExactFs();
  var recursive = typeof options === 'object' && options !== null ? !!options.recursive : false;
  g.__exactMkdir(path, recursive);
}

function rmdirSync(path) { _validatePath(path); ensureExactFs(); g.__exactRmdir(path); }
function unlinkSync(path) { _validatePath(path); ensureExactFs(); g.__exactUnlink(path); }
function renameSync(oldPath, newPath) { _validatePath(oldPath, 'oldPath'); _validatePath(newPath, 'newPath'); ensureExactFs(); g.__exactRename(oldPath, newPath); }
function copyFileSync(src, dest) { _validatePath(src, 'src'); _validatePath(dest, 'dest'); ensureExactFs(); g.__exactCopyFile(src, dest); }
function accessSync(path, mode) { _validatePath(path); ensureExactFs(); g.__exactAccess(path, mode || 0); }
function chmodSync(path, mode) { _validatePath(path); ensureExactFs(); g.__exactChmod(path, mode); }
function realpathSync(path) { _validatePath(path); ensureExactFs(); return g.__exactRealpath(path); }
function mkdtempSync(prefix) { _validatePath(prefix, 'prefix'); ensureExactFs(); return g.__exactMkdtemp(prefix); }

function existsSync(path) {
  ensureExactFs();
  try { g.__exactAccess(path, 0); return true; } catch(e) { return false; }
}

function wrapCallback(fn, cb) {
  try {
    var result = fn();
    if (typeof queueMicrotask === 'function') { queueMicrotask(function() { cb(null, result); }); }
    else { cb(null, result); }
  } catch(err) {
    var error = err instanceof Error ? err : new Error(String(err));
    if (typeof queueMicrotask === 'function') { queueMicrotask(function() { cb(error); }); }
    else { cb(error); }
  }
}

function readFile(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  wrapCallback(function() { return readFileSync(path, opts); }, callback);
}

function writeFile(path, data, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  wrapCallback(function() { writeFileSync(path, data, opts); }, callback);
}

function appendFile(path, data, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  wrapCallback(function() { appendFileSync(path, data, opts); }, callback);
}

function stat(path, cb) { wrapCallback(function() { return statSync(path); }, cb); }
function lstat(path, cb) { wrapCallback(function() { return lstatSync(path); }, cb); }
function readdir(path, optOrCb, cb) {
  var callback = typeof optOrCb === 'function' ? optOrCb : cb;
  wrapCallback(function() { return readdirSync(path); }, callback);
}
function mkdir(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  wrapCallback(function() { mkdirSync(path, opts); }, callback);
}
function rmdir(path, cb) { wrapCallback(function() { rmdirSync(path); }, cb); }
function unlink(path, cb) { wrapCallback(function() { unlinkSync(path); }, cb); }
function rename(o, n, cb) { wrapCallback(function() { renameSync(o, n); }, cb); }
function copyFile(s, d, cb) { wrapCallback(function() { copyFileSync(s, d); }, cb); }
function access(path, modeOrCb, cb) {
  var mode, callback;
  if (typeof modeOrCb === 'function') { callback = modeOrCb; } else { mode = modeOrCb; callback = cb; }
  wrapCallback(function() { accessSync(path, mode); }, callback);
}
function chmod(path, mode, cb) { wrapCallback(function() { chmodSync(path, mode); }, cb); }
function realpath(path, cb) { wrapCallback(function() { return realpathSync(path); }, cb); }
function mkdtemp(prefix, cb) { wrapCallback(function() { return mkdtempSync(prefix); }, cb); }
function exists(path, cb) {
  if (typeof queueMicrotask === 'function') { queueMicrotask(function() { cb(existsSync(path)); }); }
  else { cb(existsSync(path)); }
}

function openSync(path, flags, mode) {
  ensureExactFs();
  var f = flags || 'r';
  var m = (mode !== undefined && mode !== null) ? mode : 438;
  return g.__exactFsOpen(path, f, m);
}

function closeSync(fd) {
  ensureExactFs();
  g.__exactFsClose(fd);
}

function readSync(fd, buffer, offset, length, position) {
  ensureExactFs();
  var off = (typeof offset === 'number') ? offset : 0;
  var len = (typeof length === 'number') ? length : (buffer ? buffer.length - off : 0);
  var pos = (typeof position === 'number' && position !== null) ? position : -1;
  var data = g.__exactFsRead(fd, len, pos);
  if (buffer && data.length > 0) {
    for (var i = 0; i < data.length; i++) {
      buffer[off + i] = data[i];
    }
  }
  return data.length;
}

function writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position) {
  ensureExactFs();
  if (typeof bufferOrString === 'string') {
    var pos = (typeof offsetOrPosition === 'number') ? offsetOrPosition : -1;
    var bytes = toUint8Array(bufferOrString);
    return g.__exactFsWrite(fd, bytes, pos);
  }
  var off = (typeof offsetOrPosition === 'number') ? offsetOrPosition : 0;
  var len = (typeof lengthOrEncoding === 'number') ? lengthOrEncoding : (bufferOrString ? bufferOrString.length - off : 0);
  var pos = (typeof position === 'number' && position !== null) ? position : -1;
  var slice = bufferOrString;
  if (off !== 0 || len !== bufferOrString.length) {
    slice = bufferOrString.slice(off, off + len);
  }
  return g.__exactFsWrite(fd, slice, pos);
}

function open(path, flagsOrCb, modeOrCb, cb) {
  var flags, mode, callback;
  if (typeof flagsOrCb === 'function') { callback = flagsOrCb; flags = 'r'; mode = 438; }
  else if (typeof modeOrCb === 'function') { callback = modeOrCb; flags = flagsOrCb; mode = 438; }
  else { callback = cb; flags = flagsOrCb; mode = modeOrCb; }
  wrapCallback(function() { return openSync(path, flags, mode); }, callback);
}

function close(fd, cb) {
  wrapCallback(function() { closeSync(fd); }, cb);
}

function fsRead(fd, buffer, offset, length, position, cb) {
  wrapCallback(function() { return readSync(fd, buffer, offset, length, position); }, cb);
}

function fsWrite(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position, cb) {
  if (typeof offsetOrPosition === 'function') {
    cb = offsetOrPosition;
    wrapCallback(function() { return writeSync(fd, bufferOrString); }, cb);
    return;
  }
  if (typeof lengthOrEncoding === 'function') {
    cb = lengthOrEncoding;
    wrapCallback(function() { return writeSync(fd, bufferOrString, offsetOrPosition); }, cb);
    return;
  }
  if (typeof position === 'function') {
    cb = position;
    wrapCallback(function() { return writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding); }, cb);
    return;
  }
  wrapCallback(function() { return writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position); }, cb);
}

function createReadStream(path, options) {
  ensureExactFs();
  var Stream = require('node:stream');
  var opts = typeof options === 'string' ? { encoding: options } : (options || {});
  var encoding = opts.encoding || null;
  var start = opts.start || 0;
  var end = opts.end;
  var highWaterMark = opts.highWaterMark || 65536;

  var rs = new Stream.Readable({ highWaterMark: highWaterMark });
  rs.path = path;
  rs.bytesRead = 0;
  rs.pending = true;

  var pushed = false;
  rs._read = function() {
    if (pushed) return;
    pushed = true;
    try {
      var bytes = g.__exactReadFile(path);
      rs.pending = false;
      rs.emit('open');
      var data = bytes;
      if (start > 0 || end !== undefined) {
        var e = (end !== undefined) ? end + 1 : bytes.length;
        data = bytes.slice(start, e);
      }
      if (encoding) {
        rs.push(decodeBytes(data, encoding));
      } else {
        var chunk;
        var offset = 0;
        while (offset < data.length) {
          var chunkEnd = Math.min(offset + highWaterMark, data.length);
          chunk = data.slice(offset, chunkEnd);
          rs.push(wrapBuffer(chunk));
          offset = chunkEnd;
        }
      }
      rs.bytesRead = data.length;
      rs.push(null);
    } catch(err) {
      rs.pending = false;
      rs.emit('error', err);
      rs.emit('close');
    }
  };

  if (typeof queueMicrotask === 'function') {
    queueMicrotask(function() { rs._read(); });
  }

  return rs;
}

function createWriteStream(path, options) {
  ensureExactFs();
  var Stream = require('node:stream');
  var opts = typeof options === 'string' ? { encoding: options } : (options || {});
  var flags = opts.flags || 'w';
  var mode = opts.mode || 438;
  var encoding = opts.encoding || 'utf8';
  var autoClose = opts.autoClose !== false;
  var start = opts.start;

  var ws = new Stream.Writable();
  ws.path = path;
  ws.bytesWritten = 0;
  ws.pending = true;

  var fd = null;
  var opened = false;

  function ensureOpen() {
    if (!opened) {
      opened = true;
      fd = openSync(path, flags, mode);
      ws.pending = false;
      ws.fd = fd;
      if (typeof start === 'number' && start >= 0) {
        writeSync(fd, '', start);
      }
      ws.emit('open', fd);
    }
  }

  ws._write = function(chunk, enc, callback) {
    try {
      ensureOpen();
      var bytes = toUint8Array(chunk);
      var written = writeSync(fd, bytes, 0, bytes.length, -1);
      ws.bytesWritten += written;
      if (typeof callback === 'function') callback();
    } catch(err) {
      if (typeof callback === 'function') callback(err);
    }
  };

  ws._final = function(callback) {
    if (fd !== null && autoClose) {
      try { closeSync(fd); } catch(e) {}
      fd = null;
    }
    if (typeof callback === 'function') callback();
  };

  ws.destroy = function(err) {
    if (fd !== null && autoClose) {
      try { closeSync(fd); } catch(e) {}
      fd = null;
    }
    if (err) ws.emit('error', err);
    ws.emit('close');
    return ws;
  };

  return ws;
}

// fs.watch / fs.watchFile / fs.unwatchFile
function FSWatcher() {
  this._events = {};
  this._closed = false;
}
FSWatcher.prototype.on = function(ev, fn) { if (!this._events[ev]) this._events[ev] = []; this._events[ev].push(fn); return this; };
FSWatcher.prototype.emit = function(ev) { var a = [].slice.call(arguments, 1); var l = this._events[ev] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
FSWatcher.prototype.once = function(ev, fn) { var self = this; function w() { self.removeListener(ev, w); fn.apply(this, arguments); } this.on(ev, w); return this; };
FSWatcher.prototype.removeListener = function(ev, fn) { var l = this._events[ev]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn) n.push(l[i]); } this._events[ev] = n; } return this; };
FSWatcher.prototype.close = function() { this._closed = true; if (this._timer) clearInterval(this._timer); this.emit('close'); };
FSWatcher.prototype.ref = function() { return this; };
FSWatcher.prototype.unref = function() { return this; };

function watch(filename, options, listener) {
  if (typeof options === 'function') { listener = options; options = {}; }
  options = options || {};
  var watcher = new FSWatcher();
  if (listener) watcher.on('change', listener);
  // Poll-based watch using stat
  var lastMtime = 0;
  try { var s = statSync(filename); lastMtime = s.mtimeMs || 0; } catch(e) {}
  watcher._timer = setInterval(function() {
    if (watcher._closed) return;
    try {
      var s = statSync(filename);
      var mtime = s.mtimeMs || 0;
      if (mtime !== lastMtime) { lastMtime = mtime; watcher.emit('change', 'change', filename); }
    } catch(e) { watcher.emit('change', 'rename', filename); }
  }, options.interval || 1007);
  return watcher;
}

var _watchedFiles = {};
function watchFile(filename, options, listener) {
  if (typeof options === 'function') { listener = options; options = {}; }
  options = options || {};
  var interval = options.interval || 5007;
  var prev;
  try { prev = statSync(filename); } catch(e) { prev = { size: 0, mtimeMs: 0 }; }
  var timer = setInterval(function() {
    var curr;
    try { curr = statSync(filename); } catch(e) { curr = { size: 0, mtimeMs: 0 }; }
    if ((curr.mtimeMs || 0) !== (prev.mtimeMs || 0)) { if (listener) listener(curr, prev); prev = curr; }
  }, interval);
  _watchedFiles[filename] = timer;
}

function unwatchFile(filename) {
  if (_watchedFiles[filename]) { clearInterval(_watchedFiles[filename]); delete _watchedFiles[filename]; }
}

// fs.symlink/link/readlink/truncate/chown/utimes/rm
function symlinkSync(target, path, type) {
  ensureExactFs();
  if (typeof g.__exactSymlink === 'function') return g.__exactSymlink(target, path);
  throw new Error('symlink not available');
}
function symlink(target, path, type, cb) {
  if (typeof type === 'function') { cb = type; type = null; }
  try { symlinkSync(target, path, type); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}
function linkSync(existingPath, newPath) {
  ensureExactFs();
  if (typeof g.__exactLink === 'function') return g.__exactLink(existingPath, newPath);
  throw new Error('link not available');
}
function link(existingPath, newPath, cb) {
  try { linkSync(existingPath, newPath); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}
function readlinkSync(path) {
  ensureExactFs();
  if (typeof g.__exactReadlink === 'function') return g.__exactReadlink(path);
  throw new Error('readlink not available');
}
function readlink(path, options, cb) {
  if (typeof options === 'function') { cb = options; }
  try { var r = readlinkSync(path); if (cb) cb(null, r); } catch(e) { if (cb) cb(e); }
}
function truncateSync(path, len) {
  ensureExactFs();
  if (typeof g.__exactTruncate === 'function') return g.__exactTruncate(path, len || 0);
  throw new Error('truncate not available');
}
function truncate(path, len, cb) {
  if (typeof len === 'function') { cb = len; len = 0; }
  try { truncateSync(path, len); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}
function chownSync(path, uid, gid) {
  ensureExactFs();
  if (typeof g.__exactChown === 'function') return g.__exactChown(path, uid, gid);
  // No-op if native chown not available
}
function chown(path, uid, gid, cb) {
  try { chownSync(path, uid, gid); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}
function utimesSync(path, atime, mtime) {
  ensureExactFs();
  if (typeof g.__exactUtimes === 'function') return g.__exactUtimes(path, atime, mtime);
  // No-op if native utimes not available
}
function utimes(path, atime, mtime, cb) {
  try { utimesSync(path, atime, mtime); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}
function rmSync(path, options) {
  ensureExactFs();
  options = options || {};
  try {
    var info = statSync(path);
    if (typeof info.isDirectory === 'function' ? info.isDirectory() : info.is_dir) {
      if (options.recursive) {
        var entries = readdirSync(path);
        for (var i = 0; i < entries.length; i++) {
          rmSync(path + '/' + entries[i], options);
        }
      }
      rmdirSync(path);
    } else {
      unlinkSync(path);
    }
  } catch(e) { if (!(options.force)) throw e; }
}
function rm(path, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  try { rmSync(path, options); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}

var promises = {
  readFile: function(p, o) { return Promise.resolve(readFileSync(p, o)); },
  writeFile: function(p, d, o) { writeFileSync(p, d, o); return Promise.resolve(); },
  appendFile: function(p, d, o) { appendFileSync(p, d, o); return Promise.resolve(); },
  stat: function(p) { return Promise.resolve(statSync(p)); },
  lstat: function(p) { return Promise.resolve(lstatSync(p)); },
  readdir: function(p) { return Promise.resolve(readdirSync(p)); },
  mkdir: function(p, o) { mkdirSync(p, o); return Promise.resolve(); },
  rmdir: function(p) { rmdirSync(p); return Promise.resolve(); },
  unlink: function(p) { unlinkSync(p); return Promise.resolve(); },
  rename: function(o, n) { renameSync(o, n); return Promise.resolve(); },
  copyFile: function(s, d) { copyFileSync(s, d); return Promise.resolve(); },
  access: function(p, m) { accessSync(p, m); return Promise.resolve(); },
  chmod: function(p, m) { chmodSync(p, m); return Promise.resolve(); },
  realpath: function(p) { return Promise.resolve(realpathSync(p)); },
  mkdtemp: function(p) { return Promise.resolve(mkdtempSync(p)); },
  rm: function(p, o) {
    ensureExactFs();
    try {
      var info = statSync(p);
      if (typeof info.isDirectory === 'function' ? info.isDirectory() : info.is_dir) rmdirSync(p);
      else unlinkSync(p);
    } catch(e) { if (!(o && o.force)) throw e; }
    return Promise.resolve();
  },
  open: function(p, f, m) { return Promise.resolve(openSync(p, f, m)); },
  close: function(fd) { closeSync(fd); return Promise.resolve(); },
  symlink: function(t, p, ty) { symlinkSync(t, p, ty); return Promise.resolve(); },
  link: function(e, n) { linkSync(e, n); return Promise.resolve(); },
  readlink: function(p) { return Promise.resolve(readlinkSync(p)); },
  truncate: function(p, l) { truncateSync(p, l); return Promise.resolve(); },
  chown: function(p, u, g) { chownSync(p, u, g); return Promise.resolve(); },
  utimes: function(p, a, m) { utimesSync(p, a, m); return Promise.resolve(); },
  watch: function(p, o) { return watch(p, o); },
  constants: { F_OK: 0, R_OK: 1, W_OK: 2, X_OK: 4 }
};

var constants = { F_OK: 0, R_OK: 1, W_OK: 2, X_OK: 4 };

// fchmod/fchmodSync — file descriptor-based chmod
function fchmod(fd, mode, callback) {
  _validateFd(fd);
  if (typeof mode !== 'number') throw _fsInvalidArgType('mode', 'number', mode);
  if (typeof callback !== 'function') throw _fsInvalidArgType('callback', 'function', callback);
  ensureExactFs();
  // Stub: not fully implemented, call callback with no error
  if (typeof g.__exactFsFchmod === 'function') {
    g.__exactFsFchmod(fd, mode, callback);
  } else {
    var err = new Error('fchmod is not supported');
    err.code = 'ENOSYS';
    callback(err);
  }
}
function fchmodSync(fd, mode) {
  _validateFd(fd);
  if (typeof mode !== 'number') throw _fsInvalidArgType('mode', 'number', mode);
  ensureExactFs();
  if (typeof g.__exactFsFchmodSync === 'function') {
    return g.__exactFsFchmodSync(fd, mode);
  }
  var err = new Error('fchmodSync is not supported');
  err.code = 'ENOSYS';
  throw err;
}

// fchown/fchownSync — file descriptor-based chown
function fchown(fd, uid, gid, callback) {
  _validateFd(fd);
  if (typeof uid !== 'number') throw _fsInvalidArgType('uid', 'number', uid);
  if (typeof gid !== 'number') throw _fsInvalidArgType('gid', 'number', gid);
  if (typeof callback !== 'function') throw _fsInvalidArgType('callback', 'function', callback);
  ensureExactFs();
  if (typeof g.__exactFsFchown === 'function') {
    g.__exactFsFchown(fd, uid, gid, callback);
  } else {
    var err = new Error('fchown is not supported');
    err.code = 'ENOSYS';
    callback(err);
  }
}
function fchownSync(fd, uid, gid) {
  _validateFd(fd);
  if (typeof uid !== 'number') throw _fsInvalidArgType('uid', 'number', uid);
  if (typeof gid !== 'number') throw _fsInvalidArgType('gid', 'number', gid);
  ensureExactFs();
  if (typeof g.__exactFsFchownSync === 'function') {
    return g.__exactFsFchownSync(fd, uid, gid);
  }
  var err = new Error('fchownSync is not supported');
  err.code = 'ENOSYS';
  throw err;
}

// ftruncate/ftruncateSync — file descriptor-based truncate
function ftruncate(fd, len, callback) {
  if (typeof len === 'function') { callback = len; len = 0; }
  _validateFd(fd);
  ensureExactFs();
  if (typeof g.__exactFsFtruncate === 'function') {
    g.__exactFsFtruncate(fd, len, callback);
  } else {
    callback(null);
  }
}
function ftruncateSync(fd, len) {
  _validateFd(fd);
  ensureExactFs();
  if (typeof g.__exactFsFtruncateSync === 'function') {
    return g.__exactFsFtruncateSync(fd, len || 0);
  }
}

// fdatasync/fdatasyncSync
function fdatasync(fd, callback) {
  _validateFd(fd);
  if (typeof callback !== 'function') throw _fsInvalidArgType('callback', 'function', callback);
  callback(null);
}
function fdatasyncSync(fd) {
  _validateFd(fd);
}

// fsync/fsyncSync
function fsync(fd, callback) {
  _validateFd(fd);
  if (typeof callback !== 'function') throw _fsInvalidArgType('callback', 'function', callback);
  callback(null);
}
function fsyncSync(fd) {
  _validateFd(fd);
}

// fstat/fstatSync
function fstat(fd, opts, callback) {
  if (typeof opts === 'function') { callback = opts; opts = {}; }
  _validateFd(fd);
  ensureExactFs();
  if (typeof g.__exactFsFstat === 'function') {
    g.__exactFsFstat(fd, callback);
  } else {
    var err = new Error('fstat is not supported');
    err.code = 'ENOSYS';
    callback(err);
  }
}
function fstatSync(fd, opts) {
  _validateFd(fd);
  ensureExactFs();
  if (typeof g.__exactFsFstatSync === 'function') {
    return g.__exactFsFstatSync(fd);
  }
  var err = new Error('fstatSync is not supported');
  err.code = 'ENOSYS';
  throw err;
}

// futimes/futimesSync
function futimes(fd, atime, mtime, callback) {
  _validateFd(fd);
  if (typeof callback !== 'function') throw _fsInvalidArgType('callback', 'function', callback);
  callback(null);
}
function futimesSync(fd, atime, mtime) {
  _validateFd(fd);
}

// lchmod/lchmodSync  
function lchmod(path, mode, callback) {
  _validatePath(path);
  callback(null);
}
function lchmodSync(path, mode) {
  _validatePath(path);
}

// lchown/lchownSync
function lchown(path, uid, gid, callback) {
  _validatePath(path);
  callback(null);
}
function lchownSync(path, uid, gid) {
  _validatePath(path);
}

// lutimes/lutimesSync
function lutimes(path, atime, mtime, callback) {
  _validatePath(path);
  callback(null);
}
function lutimesSync(path, atime, mtime) {
  _validatePath(path);
}

module.exports = {
  readFile: readFile,
  readFileSync: readFileSync,
  writeFile: writeFile,
  writeFileSync: writeFileSync,
  appendFile: appendFile,
  appendFileSync: appendFileSync,
  stat: stat,
  statSync: statSync,
  lstat: lstat,
  lstatSync: lstatSync,
  readdir: readdir,
  readdirSync: readdirSync,
  mkdir: mkdir,
  mkdirSync: mkdirSync,
  rmdir: rmdir,
  rmdirSync: rmdirSync,
  unlink: unlink,
  unlinkSync: unlinkSync,
  rename: rename,
  renameSync: renameSync,
  copyFile: copyFile,
  copyFileSync: copyFileSync,
  access: access,
  accessSync: accessSync,
  chmod: chmod,
  chmodSync: chmodSync,
  realpath: realpath,
  realpathSync: realpathSync,
  mkdtemp: mkdtemp,
  mkdtempSync: mkdtempSync,
  exists: exists,
  existsSync: existsSync,
  open: open,
  openSync: openSync,
  close: close,
  closeSync: closeSync,
  read: fsRead,
  readSync: readSync,
  write: fsWrite,
  writeSync: writeSync,
  createReadStream: createReadStream,
  createWriteStream: createWriteStream,
  watch: watch,
  watchFile: watchFile,
  unwatchFile: unwatchFile,
  FSWatcher: FSWatcher,
  symlink: symlink,
  symlinkSync: symlinkSync,
  link: link,
  linkSync: linkSync,
  readlink: readlink,
  readlinkSync: readlinkSync,
  truncate: truncate,
  truncateSync: truncateSync,
  chown: chown,
  chownSync: chownSync,
  utimes: utimes,
  utimesSync: utimesSync,
  rm: rm,
  rmSync: rmSync,
  fchmod: fchmod,
  fchmodSync: fchmodSync,
  fchown: fchown,
  fchownSync: fchownSync,
  ftruncate: ftruncate,
  ftruncateSync: ftruncateSync,
  fdatasync: fdatasync,
  fdatasyncSync: fdatasyncSync,
  fsync: fsync,
  fsyncSync: fsyncSync,
  fstat: fstat,
  fstatSync: fstatSync,
  futimes: futimes,
  futimesSync: futimesSync,
  lchmod: lchmod,
  lchmodSync: lchmodSync,
  lchown: lchown,
  lchownSync: lchownSync,
  lutimes: lutimes,
  lutimesSync: lutimesSync,
  promises: promises,
  constants: constants
};
