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
  else if (typeof actual === 'object') {
    var className = actual.constructor && actual.constructor.name ? actual.constructor.name : 'Object';
    received = 'an instance of ' + className;
  } else if (typeof actual === 'string') received = 'type string (' + actual + ')';
  else if (typeof actual === 'number') received = 'type number (' + actual + ')';
  else if (typeof actual === 'boolean') received = 'type boolean (' + actual + ')';
  else received = 'type ' + typeof actual;
  var err = new TypeError('The "' + name + '" argument must be of type ' + expected + '. Received ' + received);
  err.code = 'ERR_INVALID_ARG_TYPE';
  return err;
}

function _fsOutOfRange(name, received, min, max) {
  var message;
  if (min === null) {
    message = 'The value of "' + name + '" is out of range. It must be an integer. Received ' + received;
  } else {
    message = 'The value of "' + name + '" is out of range. It must be >= ' + min + ' && <= ' + max + '. Received ' + received;
  }
  var err = new RangeError(message);
  err.code = 'ERR_OUT_OF_RANGE';
  return err;
}

function _validateInt(name, value, min, max) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value % 1 !== 0) {
    throw _fsOutOfRange(name, value, null, null);
  }
  if (value < min || value > max) {
    throw _fsOutOfRange(name, value, min, max);
  }
}

function _validateInt32(name, value) {
  _validateInt(name, value, -2147483648, 2147483647);
}

function _validateUidOrGid(name, value) {
  _validateInt(name, value, -1, 4294967295);
}

function _validateUint32(name, value) {
  _validateInt(name, value, 0, 4294967295);
}

function _fsInvalidArgValue(name, value, reason) {
  var received;
  if (typeof value === 'string') {
    received = "'" + value + "'";
  } else if (value === undefined) {
    received = 'undefined';
  } else if (value === null) {
    received = 'null';
  } else {
    received = String(value);
  }
  var err = new TypeError('The argument "' + name + '" must be ' + reason + '. Received ' + received);
  err.code = 'ERR_INVALID_ARG_VALUE';
  return err;
}

function _coerceMode(mode) {
  if (typeof mode === 'number') return mode;
  if (typeof mode === 'string') {
    var normalized = mode;
    if (normalized.slice(0, 2).toLowerCase() === '0o') normalized = normalized.slice(2);
    if (normalized.length === 0) {
      return 0;
    }
    for (var i = 0; i < normalized.length; i++) {
      var code = normalized.charCodeAt(i);
      if (code < 48 || code > 55) {
        throw _fsInvalidArgValue('mode', mode, 'a 32-bit unsigned integer or an octal string');
      }
    }
    return parseInt(normalized, 8);
  }
  throw _fsInvalidArgType('mode', 'number', mode);
}

function _validateFd(fd) {
  if (typeof fd !== 'number') {
    throw _fsInvalidArgType('fd', 'number', fd);
  }
  _validateInt('fd', fd, 0, 2147483647);
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

// Valid encodings supported by Node.js
var _validEncodings = ['utf8', 'utf-8', 'ascii', 'binary', 'base64', 'base64url',
  'ucs2', 'ucs-2', 'utf16le', 'utf-16le', 'latin1', 'hex', 'buffer'];

function _assertEncoding(encoding) {
  if (encoding && _validEncodings.indexOf(encoding.toLowerCase()) === -1) {
    var err = new TypeError("The argument 'encoding' is invalid encoding. Received '" + encoding + "'");
    err.code = 'ERR_INVALID_ARG_VALUE';
    throw err;
  }
}

function _validateEncodingOption(options) {
  var encoding = typeof options === 'string' ? options : (options && options.encoding);
  if (encoding) _assertEncoding(encoding);
}

function toUint8Array(data, encoding) {
  if (typeof data === 'string') {
    if (typeof Buffer !== 'undefined' && Buffer.from) {
      return Buffer.from(data, encoding || 'utf8');
    }
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
  _validateEncodingOption(options);
  ensureExactFs();
  var encoding = typeof options === 'string' ? options : (options && options.encoding);
  var bytes = g.__exactReadFile(path);
  if (encoding) return decodeBytes(bytes, encoding);
  return wrapBuffer(bytes);
}

function writeFileSync(path, data, options) {
  _validatePath(path);
  _validateEncodingOption(options);
  ensureExactFs();
  g.__exactWriteFile(path, toUint8Array(data));
}

function appendFileSync(path, data, options) {
  _validatePath(path);
  _validateEncodingOption(options);
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

function readdirSync(path, options) {
  _validatePath(path);
  _validateEncodingOption(options);
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
function realpathSync(path, options) { _validatePath(path); _validateEncodingOption(options); ensureExactFs(); return g.__exactRealpath(path); }
function mkdtempSync(prefix, options) { _validatePath(prefix, 'prefix'); _validateEncodingOption(options); ensureExactFs(); return g.__exactMkdtemp(prefix); }

function existsSync(path) {
  ensureExactFs();
  try { g.__exactAccess(path, 0); return true; } catch(e) { return false; }
}

function wrapCallback(fn, cb, arg1, arg2) {
  try {
    var result = fn();
    if (typeof queueMicrotask === 'function') {
      queueMicrotask(function() { cb(null, result, arg1, arg2); });
    }
    else { cb(null, result, arg1, arg2); }
  } catch(err) {
    var error = err instanceof Error ? err : new Error(String(err));
    if (typeof queueMicrotask === 'function') { queueMicrotask(function() { cb(error); }); }
    else { cb(error); }
  }
}

function readFile(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateEncodingOption(opts);
  wrapCallback(function() { return readFileSync(path, opts); }, callback);
}

function writeFile(path, data, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateEncodingOption(opts);
  wrapCallback(function() { writeFileSync(path, data, opts); }, callback);
}

function appendFile(path, data, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateEncodingOption(opts);
  wrapCallback(function() { appendFileSync(path, data, opts); }, callback);
}

function stat(path, cb) { wrapCallback(function() { return statSync(path); }, cb); }
function lstat(path, cb) { wrapCallback(function() { return lstatSync(path); }, cb); }
function readdir(path, optOrCb, cb) {
  var opts = typeof optOrCb === 'function' ? undefined : optOrCb;
  var callback = typeof optOrCb === 'function' ? optOrCb : cb;
  _validateEncodingOption(opts);
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
function realpath(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateEncodingOption(opts);
  wrapCallback(function() { return realpathSync(path, opts); }, callback);
}
function mkdtemp(prefix, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateEncodingOption(opts);
  wrapCallback(function() { return mkdtempSync(prefix, opts); }, callback);
}
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
    wrapCallback(function() { return writeSync(fd, bufferOrString); }, cb, bufferOrString);
    return;
  }
  if (typeof lengthOrEncoding === 'function') {
    cb = lengthOrEncoding;
    wrapCallback(function() {
      return writeSync(fd, bufferOrString, offsetOrPosition);
    }, cb, bufferOrString);
    return;
  }
  if (typeof position === 'function') {
    cb = position;
    wrapCallback(function() {
      return writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding);
    }, cb, bufferOrString);
    return;
  }
  wrapCallback(
    function() { return writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position); },
    cb,
    bufferOrString
  );
}

function createReadStream(path, options) {
  _validateEncodingOption(options);
  ensureExactFs();
  var Stream = require('node:stream');
  var opts = typeof options === 'string' ? { encoding: options } : (options || {});
  var encoding = opts.encoding || null;
  var hasFsOption = opts.fs !== undefined;
  if (hasFsOption) {
    var fsErr = new Error('The FileHandle with fs method is not implemented');
    fsErr.code = 'ERR_METHOD_NOT_IMPLEMENTED';
    throw fsErr;
  }
  var start = typeof opts.start === 'number' ? opts.start : 0;
  var end = opts.end;
  var highWaterMark = opts.highWaterMark || opts.bufferSize || 65536;
  var autoClose = opts.autoClose !== false;
  var fdOption = opts.fd;
  var sourceFd = null;
  var sourceHandle = null;
  var sourceIsHandle = false;
  if (fdOption === undefined || fdOption === null) {
    _validatePath(path, 'path');
  } else if (typeof fdOption === 'object') {
    if (fdOption && typeof fdOption.fd === 'number') {
      sourceHandle = fdOption;
      sourceFd = fdOption.fd;
      sourceIsHandle = true;
    } else {
      throw _fsInvalidArgType('fd', 'number', fdOption);
    }
  } else if (typeof fdOption === 'number') {
    sourceFd = fdOption;
  } else {
    throw _fsInvalidArgType('fd', 'number', fdOption);
  }

  if (typeof sourceFd === 'number' && sourceFd !== null && sourceFd !== undefined) {
    _validateFd(sourceFd);
  }

  var rs = new Stream.Readable({ highWaterMark: highWaterMark });
  rs.path = path;
  rs.readable = true;
  rs.bytesRead = 0;
  rs.closed = false;
  rs.fd = null;
  rs.pending = true;
  rs._position = start;
  rs._end = end;
  rs._autoClose = autoClose;

  function closeFd() {
    if (rs.closed) return;
    rs.closed = true;
    rs.fd = null;
    if (!sourceIsHandle) {
      if (rs._opened && rs._shouldAutoClose) {
        try { if (typeof rs._openFd === 'number') closeSync(rs._openFd); } catch (e) {}
      }
    } else if (sourceHandle && typeof sourceHandle.close === 'function') {
      try { sourceHandle.close(); } catch (e) {}
    }
    rs.emit('close');
  }

  rs._openFd = sourceFd;
  rs._opened = sourceFd !== null;
  rs._shouldAutoClose = sourceIsHandle ? false : rs._autoClose;
  rs._opening = false;
  rs._readyEmitted = false;
  if (rs._opened) {
    rs.pending = false;
    rs._readyEmitted = true;
    rs.emit('ready');
  }

  function markReady() {
    if (!rs.pending) return;
    rs.pending = false;
    rs._readyEmitted = true;
    rs.emit('ready');
  }

  function ensureOpen() {
    if (rs.closed || rs.destroyed || rs._opened || rs._opening) return;
    rs._opening = true;
    try {
      var fsModule = require('node:fs');
      if (!sourceIsHandle && sourceFd === null) {
        rs._openFd = openSync(path, opts.flags || 'r', opts.mode || 438);
        rs._opened = true;
        rs._shouldAutoClose = rs._autoClose;
        rs.fd = rs._openFd;
        rs.emit('open', rs._openFd);
        markReady();
      }
    } catch(err) {
      rs._opening = false;
      rs.emit('error', err);
      if (autoClose) closeFd();
    }
    rs._opening = false;
  }

  if (!rs._opened) {
    if (typeof queueMicrotask === 'function') queueMicrotask(ensureOpen);
    else setTimeout(ensureOpen, 0);
  }

  rs._read = function() {
    if (rs.destroyed || rs.closed) return;
    if (typeof rs._reading === 'boolean' && rs._reading) return;
    rs._reading = true;
    try {
      var fsModule = require('node:fs');
      if (!rs._opened) {
        ensureOpen();
        if (!rs._opened) {
          rs._reading = false;
          return;
        }
      }

      if (sourceIsHandle && sourceHandle && sourceHandle.fd === null) {
        rs._reading = false;
        rs.push(null);
        return;
      }
      rs.fd = rs._openFd || sourceFd;
      var chunkSize = highWaterMark;
      if (end !== undefined) {
        var remaining = end - rs._position + 1;
        if (remaining <= 0) {
          rs._reading = false;
          rs.push(null);
          if (autoClose) closeFd();
          return;
        }
        if (remaining < chunkSize) chunkSize = remaining;
      }

      var buf = new Uint8Array(chunkSize);
      var readDone = function(err, bytesRead, data) {
        rs._reading = false;
        if (err) {
          rs.emit('error', err);
          if (autoClose) closeFd();
          return;
        }
        if (bytesRead <= 0) {
          rs.push(null);
          if (autoClose) closeFd();
          return;
        }
        rs.bytesRead += bytesRead;
        rs._position += bytesRead;
        var chunk = data ? data.slice(0, bytesRead) : buf.slice(0, bytesRead);
        if (encoding) {
          rs.push(decodeBytes(chunk, encoding));
        } else {
          rs.push(wrapBuffer(chunk));
        }
      };

        if (sourceIsHandle && sourceHandle && typeof sourceHandle.read === 'function') {
          sourceHandle.read(buf, 0, chunkSize, rs._position, readDone);
      } else {
        var readArgs = [rs.fd, buf, 0, chunkSize, rs._position];
        fsModule.read.apply(null, readArgs.concat(readDone));
      }
    } catch(err) {
      rs.emit('error', err);
      if (autoClose) closeFd();
    }
  };
  rs.close = function() { if (!rs.closed) closeFd(); };
  rs.on('error', function() { closeFd(); });
  if (sourceIsHandle && sourceHandle && typeof sourceHandle.on === 'function') {
    sourceHandle.on('close', rs.close);
  }

  return rs;
}

function createWriteStream(path, options) {
  _validateEncodingOption(options);
  ensureExactFs();
  var Stream = require('node:stream');
  var opts = typeof options === 'string' ? { encoding: options } : (options || {});
  var flags = opts.flags || 'w';
  var mode = opts.mode || 438;
  var encoding = opts.encoding || 'utf8';
  var autoClose = opts.autoClose !== false;
  var start = typeof opts.start === 'number' ? opts.start : null;
  var fdOption = opts.fd;
  var fd = null;
  var opened = false;

  var usingHandle = false;
  if (fdOption !== undefined && fdOption !== null) {
    if (typeof fdOption === 'number') {
      fd = fdOption;
      opened = true;
    } else if (typeof fdOption === 'object' && typeof fdOption.fd === 'number') {
      fd = fdOption.fd;
      opened = true;
      usingHandle = true;
    } else {
      throw _fsInvalidArgType('fd', 'number', fdOption);
    }
  }

  var ws = new Stream.Writable({ emitClose: autoClose });
  ws.path = path;
  ws.fd = fd;
  ws.closed = false;
  ws.pending = !opened;
  ws.bytesWritten = 0;
  ws._encoding = encoding;
  ws._shouldAutoClose = autoClose;
  ws._shouldWriteAt = start;
  ws._readyEmitted = false;

  if (fdOption === undefined || fdOption === null) {
    _validatePath(path, 'path');
  }

  ws._emitClose = function() {
    if (!autoClose || ws.closed || ws._closed) return;
    ws._closed = true;
    ws.closed = true;
    ws.emit('close');
  };

  var origClose = ws._close;
  ws._close = function(force) {
    if (!autoClose) return;
    if (ws.closed || ws._closed) return;
    ws._closed = true;
    ws.closed = true;
    ws.fd = null;
    ws.emit('close');
  };

  function closeWriteFd() {
    if (fd === null) return;
    try { closeSync(fd); } catch(e) {}
    fd = null;
    ws.fd = null;
  }

  function ensureOpen() {
    if (!opened) {
      if (ws.closed || ws.destroyed) return;
      opened = true;
      fd = openSync(path, flags, mode);
      ws.fd = fd;
      if (start !== null && start >= 0) {
        ws._shouldWriteAt = start;
      }
      ws.emit('open', fd);
      if (!ws._readyEmitted) {
        ws._readyEmitted = true;
        ws.pending = false;
        ws.emit('ready');
      }
    } else if (!ws._readyEmitted) {
      ws._readyEmitted = true;
      ws.pending = false;
      ws.emit('ready');
    }
  }

  if (!opened) {
    setTimeout(ensureOpen, 0);
  } else if (opened) {
    ws.pending = false;
    ws._readyEmitted = true;
    ws.emit('ready');
  }

  ws._write = function(chunk, enc, callback) {
    try {
      ensureOpen();
      var bytes = toUint8Array(chunk, encoding);
      var position = ws._shouldWriteAt;
      var written = writeSync(fd, bytes, 0, bytes.length, typeof position === 'number' ? position : -1);
      if (typeof ws._shouldWriteAt === 'number') {
        ws._shouldWriteAt += written;
      }
      ws.bytesWritten += written;
      if (typeof callback === 'function') callback();
    } catch(err) {
      if (typeof callback === 'function') callback(err);
    }
  };

  ws._final = function(callback) {
    if (typeof callback !== 'function') {
      callback = function() {};
    }
    if (!opened) {
      setTimeout(function() {
        try {
          ensureOpen();
          if (autoClose) {
            closeWriteFd();
          }
          callback();
        } catch(err) {
          callback(err);
        }
      }, 0);
      return;
    }
    if (autoClose) {
      closeWriteFd();
    }
    callback();
  };

  ws.destroy = function(err) {
    if (!ws.destroyed && autoClose) {
      closeWriteFd();
    }
    if (!autoClose) {
      ws.destroyed = true;
      return ws;
    }
    if (err) ws.emit('error', err);
    ws._emitClose();
    return ws;
  };

  return ws;
}

// fs.watch / fs.watchFile / fs.unwatchFile
function FSWatcher() {
  this._events = {};
  this._closed = false;
  this._stopped = false;
  this._unrefed = false;
}
FSWatcher.prototype.on = function(ev, fn) { if (!this._events[ev]) this._events[ev] = []; this._events[ev].push(fn); return this; };
FSWatcher.prototype.emit = function(ev) { var a = [].slice.call(arguments, 1); var l = this._events[ev] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
FSWatcher.prototype.once = function(ev, fn) { var self = this; function w() { self.removeListener(ev, w); fn.apply(this, arguments); } this.on(ev, w); return this; };
FSWatcher.prototype.removeListener = function(ev, fn) { var l = this._events[ev]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn) n.push(l[i]); } this._events[ev] = n; } return this; };
FSWatcher.prototype.close = function() {
  if (this._closed) return this;
  this._closed = true;
  if (this._stop) this._stop();
  else if (this._timer) clearInterval(this._timer);
  this.emit('close');
  return this;
};
FSWatcher.prototype.stop = function() {
  if (this._stopped) return this;
  this._stopped = true;
  this.close();
  this.emit('stop');
  return this;
};
FSWatcher.prototype.ref = function() {
  this._unrefed = false;
  if (this._start) this._start();
  if (this._timer && this._timer.ref) this._timer.ref();
  return this;
};
FSWatcher.prototype.unref = function() {
  this._unrefed = true;
  if (this._stop) this._stop();
  return this;
};
FSWatcher.prototype.listenerCount = function(ev) { return this._events[ev] ? this._events[ev].length : 0; };

function pathBasename(filePath) {
  var slash = filePath.lastIndexOf('/');
  var backslash = filePath.lastIndexOf('\\');
  if (backslash > slash) slash = backslash;
  if (slash === -1) return filePath;
  return filePath.slice(slash + 1);
}
function pathJoin(base, child) {
  if (!base) return child;
  var last = base.charAt(base.length - 1);
  if (last === '/' || last === '\\') return base + child;
  return base + '/' + child;
}
function watchFilename(filename, encoding) {
  if (filename === null || filename === undefined) return filename;
  if (typeof encoding === 'string') encoding = encoding.toLowerCase();
  if (encoding === 'buffer') {
    if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
      return Buffer.from(filename);
    }
    return toUint8Array(filename);
  }
  if (!encoding || encoding === 'utf8' || encoding === 'utf-8') return filename;
  if (encoding === 'hex') {
    var bytes = toUint8Array(filename);
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
      hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return hex;
  }
  return decodeBytes(toUint8Array(filename), encoding);
}
function buildWatchDirState(dirname, recursive, prefix) {
  var entries = {};
  try {
    var dirStat = statSync(dirname);
    entries.__meta = {
      mtime: dirStat.mtimeMs || 0
    };
  } catch(e) {
    return null;
  }
  var files = [];
  try { files = readdirSync(dirname); } catch(e) { return null; }
  for (var i = 0; i < files.length; i++) {
    var file = files[i];
    var fullPath = pathJoin(dirname, file);
    var stat;
    try { stat = statSync(fullPath); } catch(e) { continue; }
    var key = prefix ? prefix + '/' + file : file;
    entries[key] = {
      isDirectory: typeof stat.isDirectory === 'function' && stat.isDirectory(),
      mtime: stat.mtimeMs || 0,
      size: stat.size || 0
    };
    if (recursive && entries[key].isDirectory) {
      var childState = buildWatchDirState(fullPath, true, key);
      if (childState) {
        for (var k in childState) {
          if (k === '__meta') continue;
          entries[k] = childState[k];
        }
      }
    }
  }
  return entries;
}
function emitWatchDirectoryChanges(watcher, encoding, prevState, nextState) {
  if (!prevState) prevState = {};
  if (!nextState) nextState = {};
  var prevMeta = prevState.__meta || {};
  var nextMeta = nextState.__meta || {};
  if ((prevMeta.mtime || 0) !== (nextMeta.mtime || 0)) {
    watcher.emit('change', 'rename', watchFilename(null, encoding));
  }
  for (var key in nextState) {
    if (key === '__meta') continue;
    if (!prevState[key]) {
      watcher.emit('change', 'rename', watchFilename(pathBasename(key), encoding));
      continue;
    }
    if (!nextState[key].isDirectory && !prevState[key].isDirectory &&
        (nextState[key].mtime !== prevState[key].mtime || nextState[key].size !== prevState[key].size)) {
      watcher.emit('change', 'change', watchFilename(pathBasename(key), encoding));
    }
  }
  for (var key2 in prevState) {
    if (key2 === '__meta') continue;
    if (!nextState[key2]) watcher.emit('change', 'rename', watchFilename(pathBasename(key2), encoding));
  }
}
function makeZeroStats() {
  var zero = new Date(0);
  return {
    __exactExists: false,
    dev: 0,
    mode: 0,
    nlink: 0,
    uid: 0,
    gid: 0,
    rdev: 0,
    blksize: 0,
    ino: 0,
    size: 0,
    blocks: 0,
    atimeMs: 0,
    mtimeMs: 0,
    ctimeMs: 0,
    birthtimeMs: 0,
    atime: zero,
    mtime: zero,
    ctime: zero,
    birthtime: zero,
    isFile: function() { return false; },
    isDirectory: function() { return false; },
    isSymbolicLink: function() { return false; },
    isBlockDevice: function() { return false; },
    isCharacterDevice: function() { return false; },
    isFIFO: function() { return false; },
    isSocket: function() { return false; }
  };
}

function watch(filename, options, listener) {
  if (typeof options === 'function') { listener = options; options = {}; }
  if (typeof options === 'string') { _assertEncoding(options); options = { encoding: options }; }
  options = options || {};
  _validateEncodingOption(options);
  if (listener && typeof listener !== 'function') _validateCallback(listener);
  _validatePath(filename, 'filename');
  var watcher = new FSWatcher();
  watcher._filename = filename;
  if (options.recursive !== undefined && typeof options.recursive !== 'boolean') {
    throw _fsInvalidArgType('options.recursive', 'boolean', options.recursive);
  }

  var encoding = options.encoding || 'utf8';
  if (listener) watcher.on('change', listener);

  var stat;
  var targetIsDirectory = false;
  try { stat = statSync(filename); targetIsDirectory = !!(stat && stat.isDirectory && stat.isDirectory()); } catch(e) {}

  if (targetIsDirectory) {
    watcher._isDirectory = true;
    watcher._recursive = !!options.recursive;
    watcher._prevState = buildWatchDirState(filename, watcher._recursive);
    var directoryInterval = options.interval || 25;
    watcher._poll = function() {
      if (watcher._closed || watcher._stopped) return;
      var nextState = buildWatchDirState(filename, watcher._recursive);
      if (!nextState) {
        watcher.emit('change', 'rename', watchFilename(pathBasename(filename), encoding));
        watcher._prevState = {};
        return;
      }
      emitWatchDirectoryChanges(watcher, encoding, watcher._prevState, nextState);
      watcher._prevState = nextState;
    };
    watcher._pollInterval = directoryInterval;
    watcher._start = function() {
      if (watcher._timer || watcher._closed || watcher._stopped || watcher._unrefed) return;
      watcher._timer = setInterval(watcher._poll, watcher._pollInterval);
    };
    watcher._stop = function() {
      if (watcher._timer) {
        clearInterval(watcher._timer);
        watcher._timer = null;
      }
    };
    watcher._start();
  } else {
    var lastMtime = 0;
    try { var s = stat || statSync(filename); lastMtime = s.mtimeMs || 0; } catch(e) {}
    var fileInterval = options.interval || 25;
    watcher._poll = function() {
      if (watcher._closed) return;
      try {
        var s2 = statSync(filename);
        var mtime = s2.mtimeMs || 0;
        if (mtime !== lastMtime) {
          lastMtime = mtime;
          watcher.emit('change', 'change', watchFilename(pathBasename(filename), encoding));
        }
      } catch(e) {
        if (lastMtime !== 0) {
          lastMtime = 0;
          watcher.emit('change', 'rename', watchFilename(pathBasename(filename), encoding));
        }
      }
    };
    watcher._pollInterval = fileInterval;
    watcher._start = function() {
      if (watcher._timer || watcher._closed || watcher._stopped || watcher._unrefed) return;
      watcher._timer = setInterval(watcher._poll, watcher._pollInterval);
    };
    watcher._stop = function() {
      if (watcher._timer) {
        clearInterval(watcher._timer);
        watcher._timer = null;
      }
    };
    watcher._start();
  }

  if (options.persistent === false) watcher.unref();
  return watcher;
}

var _watchedFiles = {};
function watchFile(filename, options, listener) {
  if (typeof options === 'function') { listener = options; options = {}; }
  options = options || {};
  if (listener && typeof listener !== 'function') _validateCallback(listener);
  _validatePath(filename, 'filename');
  var watcher = _watchedFiles[filename];
  if (!watcher) {
    watcher = new FSWatcher();
    watcher._filename = filename;
    watcher._listeners = [];
    watcher._initialized = false;
    watcher._hadInitialStat = false;
    watcher._timer = null;
    watcher._prev = makeZeroStats();
    try { watcher._prev = statSync(filename); watcher._prev.__exactExists = true; watcher._hadInitialStat = true; } catch(e) { watcher._prev.__exactExists = false; }
    var watchFileInterval = options.interval || 5007;
    watcher._poll = function() {
      if (watcher._closed || watcher._stopped) return;
      var curr;
      try {
        curr = statSync(filename);
        curr.__exactExists = true;
      } catch(e) {
        curr = makeZeroStats();
        curr.__exactExists = false;
      }
      if (!watcher._initialized) watcher._initialized = true;
      if (watcher._prev.__exactExists !== curr.__exactExists ||
          (curr.mtimeMs || 0) !== (watcher._prev.mtimeMs || 0) ||
          (curr.size || 0) !== (watcher._prev.size || 0)) {
        watcher.emit('change', curr, watcher._prev);
        watcher._prev = curr;
      }
      watcher._prev = curr;
    };
    watcher._pollInterval = watchFileInterval;
    watcher._start = function() {
      if (watcher._timer || watcher._closed || watcher._stopped || watcher._unrefed) return;
      watcher._timer = setInterval(watcher._poll, watcher._pollInterval);
    };
    watcher._stop = function() {
      if (watcher._timer) {
        clearInterval(watcher._timer);
        watcher._timer = null;
      }
    };
    watcher._start();
    if (options.persistent === false) watcher.unref();
    _watchedFiles[filename] = watcher;
  }

  if (listener) {
    var wrapped = function(curr, prev) {
      listener(curr, prev);
    };
    wrapped._exactListener = listener;
    watcher._listeners.push(wrapped);
    watcher.on('change', wrapped);
  }

  return watcher;
}

function unwatchFile(filename) {
  _validatePath(filename, 'filename');
  var watcher = _watchedFiles[filename];
  if (!watcher) return;
  if (!watcher._listeners) watcher._listeners = [];
  if (arguments.length > 1 && arguments[1] !== undefined) {
    if (typeof arguments[1] !== 'function') _validateCallback(arguments[1]);
    var listener = arguments[1];
    var next = [];
    var removed = false;
    for (var i = 0; i < watcher._listeners.length; i++) {
      var entry = watcher._listeners[i];
      if (!removed && entry._exactListener === listener) {
        watcher.removeListener('change', entry);
        removed = true;
        continue;
      }
      next.push(entry);
    }
    watcher._listeners = next;
    if (watcher._listeners.length === 0) {
      watcher.stop();
      delete _watchedFiles[filename];
    }
    return;
  }
  watcher.stop();
  delete _watchedFiles[filename];
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
function readlinkSync(path, options) {
  _validatePath(path, 'path');
  _validateEncodingOption(options);
  ensureExactFs();
  if (typeof g.__exactReadlink === 'function') return g.__exactReadlink(path);
  throw new Error('readlink not available');
}
function readlink(path, options, cb) {
  if (typeof options === 'function') { cb = options; options = undefined; }
  _validatePath(path, 'path');
  _validateEncodingOption(options);
  if (cb !== undefined) {
    _validateCallback(cb);
  }
  try {
    var r = readlinkSync(path);
    if (cb) {
      if (typeof queueMicrotask === 'function') {
        queueMicrotask(function() { cb(null, r); });
      } else {
        cb(null, r);
      }
    } else {
      return r;
    }
  } catch(e) {
    if (cb) {
      if (typeof queueMicrotask === 'function') {
        queueMicrotask(function() { cb(e); });
      } else {
        cb(e);
      }
      return;
    }
    throw e;
  }
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
  mode = _coerceMode(mode);
  _validateUint32('mode', mode);
  if (callback !== undefined && typeof callback !== 'function') _validateCallback(callback);
  ensureExactFs();
  if (typeof callback === 'function') {
    if (typeof g.__exactFsFchmod === 'function') {
      g.__exactFsFchmod(fd, mode, callback);
    } else {
      wrapCallback(function() { fchmodSync(fd, mode); }, callback);
    }
    return;
  }
  return fchmodSync(fd, mode);
}
function fchmodSync(fd, mode) {
  _validateFd(fd);
  mode = _coerceMode(mode);
  _validateUint32('mode', mode);
  ensureExactFs();
  if (typeof g.__exactFsFchmodSync === 'function') {
    return g.__exactFsFchmodSync(fd, mode);
  }
  var err = new Error('fchmod is not supported');
  err.code = 'ENOSYS';
  throw err;
}

// fchown/fchownSync — file descriptor-based chown
function fchown(fd, uid, gid, callback) {
  _validateFd(fd);
  if (typeof uid !== 'number') throw _fsInvalidArgType('uid', 'number', uid);
  if (typeof uid === 'number') _validateUidOrGid('uid', uid);
  if (typeof gid !== 'number') throw _fsInvalidArgType('gid', 'number', gid);
  _validateUidOrGid('gid', gid);
  if (callback !== undefined && typeof callback !== 'function') _validateCallback(callback);
  ensureExactFs();
  if (typeof callback === 'function') {
    if (typeof g.__exactFsFchown === 'function') {
      g.__exactFsFchown(fd, uid, gid, callback);
    } else {
      wrapCallback(function() { fchownSync(fd, uid, gid); }, callback);
    }
    return;
  }
  if (typeof g.__exactFsFchownSync === 'function') {
    return g.__exactFsFchownSync(fd, uid, gid);
  }
  if (typeof g.__exactFsFchown === 'function') {
    return g.__exactFsFchown(fd, uid, gid, function() {});
  }
  var err = new Error('fchown is not supported');
  err.code = 'ENOSYS';
  throw err;
}
function fchownSync(fd, uid, gid) {
  _validateFd(fd);
  if (typeof uid !== 'number') throw _fsInvalidArgType('uid', 'number', uid);
  if (typeof uid === 'number') _validateUidOrGid('uid', uid);
  if (typeof gid !== 'number') throw _fsInvalidArgType('gid', 'number', gid);
  _validateUidOrGid('gid', gid);
  ensureExactFs();
  if (typeof g.__exactFsFchownSync === 'function') {
    return g.__exactFsFchownSync(fd, uid, gid);
  }
  var err = new Error('fchown is not supported');
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

// opendirSync
function opendirSync(path, options) {
  _validatePath(path);
  if (options && options.encoding) {
    _assertEncoding(options.encoding);
  }
  throw new Error('opendirSync is not supported in this runtime');
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
  ReadStream: createReadStream,
  WriteStream: createWriteStream,
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
  opendirSync: opendirSync,
  promises: promises,
  constants: constants
};
