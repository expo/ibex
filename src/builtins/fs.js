var g = globalThis;
var _nativeFs = (function() {
  try {
    return require('fs');
  } catch (e) {
    return null;
  }
})();
var _nativeFsOpen = _nativeFs ? _nativeFs.open : null;
var _nativeFsClose = _nativeFs ? _nativeFs.close : null;
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
  else if (typeof actual === 'function') received = actual.name ? 'function ' + actual.name : 'function ';
  else if (typeof actual === 'object') {
    var className = actual.constructor && actual.constructor.name ? actual.constructor.name : 'Object';
    received = 'an instance of ' + className;
  } else if (typeof actual === 'string') received = 'type string (' + actual + ')';
  else if (typeof actual === 'number') received = 'type number (' + actual + ')';
  else if (typeof actual === 'boolean') received = 'type boolean (' + actual + ')';
  else if (typeof actual === 'symbol') received = 'type symbol (' + String(actual) + ')';
  else received = 'type ' + typeof actual;
  var err = new TypeError('The "' + name + '" argument must be of type ' + expected + '. Received ' + received);
  err.code = 'ERR_INVALID_ARG_TYPE';
  err.toString = function() {
    return 'TypeError [ERR_INVALID_ARG_TYPE]: ' + this.message;
  };
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
  if (typeof value !== 'number') {
    throw _fsInvalidArgType(name, 'number', value);
  }
  if (!Number.isInteger(value)) {
    throw _fsOutOfRange(name, value, null, null);
  }
  if (value < -1 || value > 4294967295) {
    throw _fsOutOfRange(name, value, -1, 4294967295);
  }
}

function _validateUint32(name, value) {
  if ((name === 'uid' || name === 'gid') && value === -1) {
    if (typeof value !== 'number') {
      throw _fsInvalidArgType(name, 'number', value);
    }
    if (!Number.isInteger(value)) {
      throw _fsOutOfRange(name, value, null, null);
    }
    return;
  }
  if (typeof value !== 'number') {
    throw _fsInvalidArgType(name, 'number', value);
  }
  if (!Number.isInteger(value)) {
    throw _fsOutOfRange(name, value, null, null);
  }
  if (value < 0 || value > 4294967295) {
    throw _fsOutOfRange(name, value, 0, 4294967295);
  }
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
  _validateInt('fd', fd, -1, 2147483647);
}

function _validateFdNonNegative(fd) {
  if (typeof fd !== 'number') {
    throw _fsInvalidArgType('fd', 'number', fd);
  }
  _validateInt('fd', fd, 0, 2147483647);
}

function _getFdOrPath(path, propName) {
  if (typeof path === 'number') {
    return { fd: path, path: undefined };
  }
  if (path && typeof path === 'object' && typeof path.fd === 'number') {
    return { fd: path.fd, path: undefined };
  }
  _validatePath(path, propName);
  return { fd: null, path: _pathToString(path) };
}

function _isPathBufferView(path) {
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(path)) return true;
  if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function') {
    return ArrayBuffer.isView(path);
  }
  return false;
}

function _pathBufferViewToUint8Array(path) {
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(path)) return path;
  if (_isPathBufferView(path)) {
    return new Uint8Array(path.buffer, path.byteOffset || 0, path.byteLength);
  }
  return null;
}

function _pathBufferViewToString(path) {
  var bytes = _pathBufferViewToUint8Array(path);
  if (!bytes) return String(path);
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return Buffer.from(bytes.buffer, bytes.byteOffset || 0, bytes.byteLength).toString();
  }
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    out += String.fromCharCode(bytes[i]);
  }
  return out;
}

function _validatePath(path, propName) {
  path = _coercePathFromURL(path, propName);
  // Support URL objects with file: protocol
  if (path && typeof path === 'object' && typeof path.href === 'string' && path.protocol === 'file:') {
    // _coercePathFromURL already validated and returned a URL string.
    return;
  }
  if (typeof path !== 'string' && !_isPathBufferView(path)) {
    throw _fsInvalidArgType(propName || 'path', 'string or an instance of Buffer or URL', path);
  }
  if (typeof path === 'string' && path.indexOf('\u0000') !== -1) {
    var err = new TypeError('The argument "' + (propName || 'path') + '" must be a string, Uint8Array, or URL without null bytes. Received ' + JSON.stringify(path));
    err.code = 'ERR_INVALID_ARG_VALUE';
    throw err;
  }
  var pathBytes = _pathBufferViewToUint8Array(path);
  if (pathBytes) {
    for (var i = 0; i < pathBytes.length; i++) {
      if (pathBytes[i] !== 0) continue;
      var err = new TypeError('The argument "' + (propName || 'path') + '" must be a string, Uint8Array, or URL without null bytes. Received ' + JSON.stringify(_pathBufferViewToString(path)));
      err.code = 'ERR_INVALID_ARG_VALUE';
      throw err;
    }
  }
}

function _coercePathFromURL(path, propName) {
  if (!path || typeof path !== 'object') return path;
  if (typeof path.href !== 'string' || typeof path.protocol !== 'string') return path;
  if (path.protocol !== 'file:') {
    var schemeErr = new TypeError('The URL must be of scheme file');
    schemeErr.code = 'ERR_INVALID_URL_SCHEME';
    throw schemeErr;
  }
  var isWindows = typeof process === 'object' && process !== null && process.platform === 'win32';
  if (!isWindows && path.hostname && path.hostname !== 'localhost') {
    var hostErr = new TypeError('File URL host must be "localhost" or empty on non-Windows platforms');
    hostErr.code = 'ERR_INVALID_FILE_URL_HOST';
    throw hostErr;
  }
  var pathname = path.pathname;
  if (!pathname) {
    var err = new TypeError('The URL must have a pathname');
    if (propName) {
      err.name = 'TypeError';
    }
    throw err;
  }
  if (/%2f/i.test(pathname) || (isWindows && /%5c/i.test(pathname))) {
    var pathErr = new TypeError('File URL path must not include encoded path separators');
    pathErr.code = 'ERR_INVALID_FILE_URL_PATH';
    throw pathErr;
  }
  var decoded = decodeURIComponent(pathname);
  if (decoded.indexOf('\u0000') !== -1) {
    var nullErr = new TypeError('The argument "' + (propName || 'path') +
      '" must be a string, Uint8Array, or URL without null bytes. Received ' +
      JSON.stringify(decoded));
    nullErr.code = 'ERR_INVALID_ARG_VALUE';
    throw nullErr;
  }
  return decoded;
}

function _emitFsDeprecation(code, message) {
  if (typeof process === 'object' && process !== null && typeof process.emitWarning === 'function') {
    process.emitWarning(message, 'DeprecationWarning', code);
  }
}

function _isBufferLike(value) {
  if (!value) return false;
  if (Buffer.isBuffer(value)) return true;
  if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function') {
    if (ArrayBuffer.isView(value)) return true;
  }
  if (typeof value === 'object' && value !== null) {
    if (typeof value.byteLength === 'number' && typeof value.byteOffset === 'number' && typeof value.buffer === 'object') {
      return true;
    }
    if (typeof value.byteLength === 'number' && typeof value.length === 'number' && value.constructor && typeof value.constructor.BYTES_PER_ELEMENT === 'number') {
      return true;
    }
    var typeTag = Object.prototype.toString.call(value);
    if (typeTag !== '[object Array]' && typeTag.indexOf('Array') !== -1) {
      return true;
    }
    if (typeTag === '[object DataView]') {
      return true;
    }
  }
  return false;
}

function _bufferLikeLength(value) {
  if (!value) return 0;
  if (typeof value.length === 'number') return value.length;
  if (typeof value.byteLength === 'number') return value.byteLength;
  return 0;
}

function _describeBufferLike(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  var name = value.constructor && value.constructor.name ? value.constructor.name : 'Object';
  var length = _bufferLikeLength(value);
  return name + '(' + length + ') []';
}

function _throwEmptyBufferError(name, value) {
  var err = new TypeError('The argument \'' + name + '\' is empty and cannot be written. Received ' + _describeBufferLike(value));
  err.code = 'ERR_INVALID_ARG_VALUE';
  return err;
}

function _validateCopyFileMode(mode) {
  if (typeof mode !== 'number') {
    var err = new TypeError('mode must be int32 or null/undefined');
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  _validateInt('mode', mode, 0, 7);
}

function _validateAccessMode(mode) {
  if (mode === undefined || mode === null) return 0;
  if (typeof mode !== 'number') {
    var err = new TypeError('mode must be int32 or null/undefined');
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  _validateInt('mode', mode, 0, 7);
  return mode;
}

function _validateReadSyncLength(length, bufferLength) {
  if (typeof length === 'undefined' || length === null) {
    return bufferLength;
  }
  if (typeof length !== 'number' || !Number.isFinite(length) || length % 1 !== 0) {
    throw _fsInvalidArgType('length', 'number', length);
  }
  if (length < 0 || length > bufferLength) {
    throw _fsOutOfRange('length', length, 0, bufferLength);
  }
  return length;
}

function _normalizeTruncateLen(len) {
  if (len === undefined) {
    return 0;
  }
  if (typeof len !== 'number') {
    throw _fsInvalidArgType('len', 'number', len);
  }
  if (!Number.isFinite(len) || len % 1 !== 0) {
    throw _fsOutOfRange('len', len, null, null);
  }
  return len < 0 ? 0 : len;
}

function _validateReadWritePosition(name, position) {
  if (position === undefined || position === null) {
    return -1;
  }
  if (typeof position !== 'number') {
    throw _fsInvalidArgType(name, 'bigint or integer', position);
  }
  if (!Number.isFinite(position) || position % 1 !== 0) {
    throw _fsOutOfRange(name, position, null, null);
  }
  if (position < -1 || position > Number.MAX_SAFE_INTEGER) {
    throw _fsOutOfRange(name, position, -1, Number.MAX_SAFE_INTEGER);
  }
  return position;
}

function _validateOffset(name, offset, bufferLength) {
  if (typeof offset !== 'number') {
    throw _fsInvalidArgType(name, 'number', offset);
  }
  if (!Number.isFinite(offset) || offset % 1 !== 0) {
    throw _fsOutOfRange(name, offset, null, null);
  }
  if (offset < 0 || offset > bufferLength) {
    throw _fsOutOfRange(name, offset, 0, bufferLength);
  }
  return offset;
}

function _validateCallback(cb) {
  if (typeof cb !== 'function') {
    throw _fsInvalidArgType('callback', 'function', cb);
  }
}

function _deferFsCallback(callback) {
  if (typeof setImmediate === 'function') {
    setImmediate(callback);
  } else {
    setTimeout(callback, 0);
  }
}

function _pathToString(path) {
  if (typeof path === 'string') return _resolvePathFromCwd(path);
  if (_isPathBufferView(path)) return _pathBufferViewToString(path);
  if (path && typeof path === 'object' && typeof path.href === 'string' && path.protocol === 'file:') {
    return _coercePathFromURL(path);
  }
  var resolved = String(path);
  return _resolvePathFromCwd(resolved);
}

function _isAbsolutePath(path) {
  if (!path || typeof path !== 'string') return false;
  return path.charAt(0) === '/' || path.charAt(1) === ':' || path.indexOf('\\\\') === 0;
}

function _normalizePathSegments(parts) {
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var segment = parts[i];
    if (!segment || segment === '.') continue;
    if (segment === '..') {
      if (out.length > 0) out.pop();
    } else {
      out.push(segment);
    }
  }
  return out;
}

function _currentProcessCwd() {
  if (typeof globalThis === 'object' && globalThis && globalThis.process &&
      typeof globalThis.process.cwd === 'function') {
    var globalCwd = globalThis.process.cwd();
    if (typeof globalCwd === 'string' && globalCwd.length > 0) {
      return globalCwd;
    }
  }
  try {
    if (typeof require === 'function') {
      var processModule = require('process');
      if (processModule && typeof processModule.cwd === 'function') {
        var moduleCwd = processModule.cwd();
        if (typeof moduleCwd === 'string' && moduleCwd.length > 0) {
          return moduleCwd;
        }
      }
    }
  } catch (_processModuleErr) {}
  if (typeof process === 'object' && process && typeof process.cwd === 'function') {
    var wrapperCwd = process.cwd();
    if (typeof wrapperCwd === 'string' && wrapperCwd.length > 0) {
      return wrapperCwd;
    }
  }
  return "/";
}

function _resolvePathFromCwd(path) {
  if (!_isAbsolutePath(path)) {
    var cwd = _currentProcessCwd();
    if (!cwd) cwd = "/";
    var separator = '/';
    var cwdParts = cwd.replace(/\\\\/g, separator).split(separator);
    var pathParts = path.replace(/\\\\/g, separator).split(separator);
    if (cwd === separator && cwdParts.length === 1) {
      cwdParts = [];
    }
    var combined = _normalizePathSegments(cwdParts.concat(pathParts));
    if (path === '.' && combined.length === 0) {
      return separator;
    }
    return separator + combined.join(separator);
  }
  return path;
}

function _getFirstMissingPath(targetPath) {
  var normalized = targetPath.replace(/\\\\/g, '/');
  var parts = normalized.split('/');
  var current = normalized.charAt(0) === '/' ? '/' : '';
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i];
    if (!part) continue;
    current = current === '/' ? '/' + part : (current ? current + '/' + part : part);
    try {
      var stat = statSync(current);
      if (!stat || typeof stat.isDirectory !== 'function' || !stat.isDirectory()) {
        return current;
      }
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        return current;
      }
      throw err;
    }
  }
  return undefined;
}

function _dirnamePath(value) {
  var lastSlash = value.lastIndexOf('/');
  var lastBackslash = value.lastIndexOf('\\');
  var sepIndex = Math.max(lastSlash, lastBackslash);
  if (sepIndex === -1) return '.';
  if (sepIndex === 0) return '/';
  return value.slice(0, sepIndex);
}

function _fsInvalidArgTypeProperty(propName, expected, actual) {
  var err = _fsInvalidArgType(propName, expected, actual);
  err.message = err.message.replace(' argument', ' property');
  if (typeof actual === 'string') {
    err.message = err.message.replace(
      'type string (' + actual + ')',
      "type string ('" + actual.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "')"
    );
  }
  return err;
}

var _uvErrnoMap = {
  'EACCES': 13, 'EBADF': 9, 'EBUSY': 16, 'EEXIST': 17,
  'EFAULT': 14, 'EINVAL': 22, 'EIO': 5, 'EISDIR': 21,
  'ELOOP': 40, 'EMFILE': 24, 'ENAMETOOLONG': 63, 'ENOENT': 2,
  'ENOMEM': 12, 'ENOSPC': 28, 'ENOSYS': 78, 'ENOTDIR': 20,
  'ENOTEMPTY': 66, 'EPERM': 1, 'ERANGE': 34, 'EROFS': 30,
  'ESPIPE': 29, 'EXDEV': 18, 'ETXTBSY': 26, 'UNKNOWN': 4094
};

var _uvErrnoMessage = {
  'EACCES': 'permission denied',
  'EBADF': 'bad file descriptor',
  'EBUSY': 'resource busy or locked',
  'EEXIST': 'file already exists',
  'EFAULT': 'bad address in system call argument',
  'EINVAL': 'invalid argument',
  'EIO': 'i/o error',
  'EISDIR': 'illegal operation on a directory',
  'ELOOP': 'too many symbolic links encountered',
  'EMFILE': 'too many open files',
  'ENAMETOOLONG': 'name too long',
  'ENOENT': 'no such file or directory',
  'ENOMEM': 'not enough memory',
  'ENOSPC': 'no space left on device',
  'ENOSYS': 'function not implemented',
  'ENOTDIR': 'not a directory',
  'ENOTEMPTY': 'directory not empty',
  'EPERM': 'operation not permitted',
  'ERANGE': 'result too large',
  'EROFS': 'read-only file system',
  'ESPIPE': 'invalid seek',
  'EXDEV': 'cross-device link not permitted',
  'ETXTBSY': 'text file is busy'
};

function _uvCodeFromErrno(errno) {
  if (typeof errno !== 'number' || Number.isNaN(errno)) return null;
  var normalized = Math.abs(errno);
  for (var code in _uvErrnoMap) {
    if (Object.prototype.hasOwnProperty.call(_uvErrnoMap, code) && _uvErrnoMap[code] === normalized) {
      return code;
    }
  }
  return null;
}

function _extractFsCode(message) {
  if (typeof message !== 'string') return null;
  var match = message.match(/^([A-Z][A-Z0-9_]+):/);
  return match ? match[1] : null;
}

function _makeFsThisError(name) {
  var err = new TypeError('The "' + name + '" property was accessed on an object that is not a Dir.');
  err.code = 'ERR_INVALID_THIS';
  return err;
}

function _makeDirError(code, message, path) {
  var err = new Error(code + ': ' + message + (path ? " '" + path + "'" : ''));
  err.code = code;
  if (path) err.path = path;
  return err;
}

function _makeDirClosedError(path) {
  return _makeDirError('ERR_DIR_CLOSED', 'Directory handle is closed', path);
}

function _makeDirConcurrentOperationError(path) {
  return _makeDirError('ERR_DIR_CONCURRENT_OPERATION', 'Directory handle is busy', path);
}

function _buildFsErrorMessage(code, syscall, pathValue, destValue) {
  var out = code + ': ' + (_uvErrnoMessage[code] || 'unknown error') + ', ' + syscall;
  if (pathValue !== undefined) out += " '" + pathValue + "'";
  if (destValue !== undefined) out += " -> '" + destValue + "'";
  return out;
}

function _makeFsError(err, syscall, path, dest) {
  err = err || {};
  var sourceMessage = typeof err.message === 'string' ? err.message : String(err);
  var code = typeof err.code === 'string' ? err.code : null;
  if (!code || !Object.prototype.hasOwnProperty.call(_uvErrnoMessage, code)) {
    code = _extractFsCode(sourceMessage) || _uvCodeFromErrno(err.errno);
  }
  var resolvedSyscall = syscall;
  var resolvedPath = path;
  var resolvedDest = dest;

  if (resolvedSyscall === undefined && typeof err.syscall === 'string') {
    resolvedSyscall = err.syscall;
  }
  if (resolvedPath === undefined && err.path !== undefined) {
    resolvedPath = err.path;
  }
  if (resolvedDest === undefined && err.dest !== undefined) {
    resolvedDest = err.dest;
  }

  var message = sourceMessage;
  if (code && _uvErrnoMessage[code] && resolvedSyscall) {
    message = _buildFsErrorMessage(code, resolvedSyscall, resolvedPath, resolvedDest);
  }

  var fsErr = new Error(message);
  if (code) fsErr.code = code;
  if (resolvedSyscall) fsErr.syscall = resolvedSyscall;
  if (resolvedPath !== undefined) fsErr.path = resolvedPath;
  if (resolvedDest !== undefined) fsErr.dest = resolvedDest;
  if (typeof err.errno === 'number' && !Number.isNaN(err.errno)) {
    fsErr.errno = err.errno >= 0 ? -err.errno : err.errno;
  } else if (code && _uvErrnoMap[code] !== undefined) {
    fsErr.errno = -_uvErrnoMap[code];
  } else if (err.code && _uvErrnoMap[err.code] !== undefined) {
    fsErr.errno = -_uvErrnoMap[err.code];
  } else {
    fsErr.errno = -_uvErrnoMap.UNKNOWN;
  }
  return fsErr;
}

function _parseFsOpenFlags(flags) {
  if (typeof flags !== 'string') {
    var err = new TypeError('The flags argument must be a string or a number. Received ' + (flags === null ? 'null' : typeof flags));
    err.code = 'ERR_INVALID_ARG_VALUE';
    throw err;
  }
  if (flags.length === 0) {
    var emptyErr = new TypeError('The flags argument must be a valid flags string. Received ' + JSON.stringify(flags));
    emptyErr.code = 'ERR_INVALID_ARG_VALUE';
    throw emptyErr;
  }
  var hasPlus = flags.indexOf('+') !== -1;
  if (flags.indexOf('+') !== flags.lastIndexOf('+')) {
    var plusErr = new TypeError('The value of \"flags\" is invalid. It must be a valid flags string. Received ' + JSON.stringify(flags));
    plusErr.code = 'ERR_INVALID_ARG_VALUE';
    throw plusErr;
  }
  if (hasPlus && flags.indexOf('+') !== flags.length - 1) {
    var plusPosErr = new TypeError('The value of \"flags\" is invalid. It must be a valid flags string. Received ' + JSON.stringify(flags));
    plusPosErr.code = 'ERR_INVALID_ARG_VALUE';
    throw plusPosErr;
  }
  var flagChars = hasPlus ? flags.slice(0, -1) : flags;
  var hasSync = false;
  var hasExclusive = false;
  var modeFlags = '';
  for (var i = 0; i < flagChars.length; i++) {
    var ch = flagChars.charAt(i);
    if (ch === 's') {
      if (hasSync) {
        var syncErr = new TypeError('The value of \"flags\" is invalid. It must be a valid flags string. Received ' + JSON.stringify(flags));
        syncErr.code = 'ERR_INVALID_ARG_VALUE';
        throw syncErr;
      }
      hasSync = true;
    } else if (ch === 'x') {
      if (hasExclusive) {
        var exclusiveErr = new TypeError('The value of \"flags\" is invalid. It must be a valid flags string. Received ' + JSON.stringify(flags));
        exclusiveErr.code = 'ERR_INVALID_ARG_VALUE';
        throw exclusiveErr;
      }
      hasExclusive = true;
    } else if (ch === 'r' || ch === 'w' || ch === 'a') {
      if (modeFlags.length >= 1) {
        var modeErr = new TypeError('The value of \"flags\" is invalid. It must be a valid flags string. Received ' + JSON.stringify(flags));
        modeErr.code = 'ERR_INVALID_ARG_VALUE';
        throw modeErr;
      }
      modeFlags = ch;
    } else {
      var charErr = new TypeError('The value of \"flags\" is invalid. It must be a valid flags string. Received ' + JSON.stringify(flags));
      charErr.code = 'ERR_INVALID_ARG_VALUE';
      throw charErr;
    }
  }
  if (modeFlags.length !== 1 || (hasExclusive && modeFlags === 'r')) {
    var invalidErr = new TypeError('The value of \"flags\" is invalid. It must be a valid flags string. Received ' + JSON.stringify(flags));
    invalidErr.code = 'ERR_INVALID_ARG_VALUE';
    throw invalidErr;
  }
  var result = 0;
  if (modeFlags === 'r') {
    result = constants.O_RDONLY;
  } else if (modeFlags === 'w') {
    result = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC;
  } else {
    result = constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND;
  }
  if (hasPlus) {
    result = (result & ~constants.O_WRONLY) | constants.O_RDWR;
  }
  if (hasExclusive) {
    result |= constants.O_EXCL;
  }
  if (hasSync) {
    result |= constants.O_SYNC;
  }
  return result;
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

function _validateFlushOption(value) {
  if (value === undefined || value === null || typeof value === 'boolean') return;
  throw _fsInvalidArgType('options.flush', 'boolean', value);
}

function _makeAbortError() {
  var err = new Error('The operation was aborted');
  err.name = 'AbortError';
  err.code = 'ABORT_ERR';
  if (arguments.length > 0) {
    err.cause = arguments[0];
  }
  return err;
}

function _normalizeWatchOptions(options) {
  if (options === undefined || options === null) {
    return {};
  }
  if (typeof options === 'string') {
    _assertEncoding(options);
    return { encoding: options };
  }
  if (typeof options !== 'object') {
    throw _fsInvalidArgType('options', 'string or an object', options);
  }
  _validateEncodingOption(options);
  if (options.recursive !== undefined && typeof options.recursive !== 'boolean') {
    throw _fsInvalidArgType('options.recursive', 'boolean', options.recursive);
  }
  if (options.persistent !== undefined && typeof options.persistent !== 'boolean') {
    throw _fsInvalidArgType('options.persistent', 'boolean', options.persistent);
  }
  if (options.signal !== undefined && options.signal !== null && (typeof options.signal !== 'object' || typeof options.signal.addEventListener !== 'function')) {
    throw _fsInvalidArgType('options.signal', 'AbortSignal', options.signal);
  }
  return _extend({}, options);
}

function _normalizeWatchFileOptions(path, options) {
  options = _normalizeWatchOptions(options);
  if (options.signal && options.signal.aborted === true) {
    throw _makeAbortError(options.signal.reason);
  }
  if (options.maxQueue !== undefined) {
    if (typeof options.maxQueue !== 'number' || !Number.isFinite(options.maxQueue) || options.maxQueue % 1 !== 0) {
      throw _fsInvalidArgValue('options.maxQueue', options.maxQueue, 'a number');
    }
    if (options.maxQueue < 0) {
      throw _fsInvalidArgValue('options.maxQueue', options.maxQueue, 'a non-negative number');
    }
  }
  if (options.overflow !== undefined) {
    if (options.overflow !== 'throw' && options.overflow !== 'ignore') {
      throw _fsInvalidArgValue('options.overflow', options.overflow, 'one of "throw", "ignore"');
    }
  }
  return options;
}

function _checkForAbortedSignal(options) {
  if (options && typeof options === 'object' && options.signal && options.signal.aborted === true) {
    throw _makeAbortError();
  }
}

function _normalizeWriteOptions(options) {
  if (options === undefined || options === null) return {};
  if (typeof options === 'string') {
    _assertEncoding(options);
    return { encoding: options };
  }
  if (typeof options !== 'object') {
    throw _fsInvalidArgType('options', 'string or an object', options);
  }
  _validateEncodingOption(options);
  _validateFlushOption(options.flush);
  _checkForAbortedSignal(options);
  return _extend({}, options);
}

function _validateEncodingOption(options) {
  var encoding = typeof options === 'string' ? options : (options && options.encoding);
  if (encoding) _assertEncoding(encoding);
}

function _validateMkdirRecursiveOption(options) {
  if (options && typeof options === 'object' &&
      options.recursive !== undefined &&
      typeof options.recursive !== 'boolean') {
    var err = _fsInvalidArgType('options.recursive', 'boolean', options.recursive);
    err.message = err.message.replace(' argument', ' property');
    throw err;
  }
}

function _isAsyncIterable(value) {
  if (!value || typeof value !== 'object') return false;
  if (typeof Symbol === 'undefined' || !Symbol.asyncIterator) return false;
  return typeof value[Symbol.asyncIterator] === 'function';
}

function _isSyncIterable(value) {
  if (!value || typeof value !== 'object') return false;
  if (typeof Symbol === 'undefined' || !Symbol.iterator) return false;
  return typeof value[Symbol.iterator] === 'function';
}

function _coerceWriteFileChunk(value, encoding) {
  if (typeof value === 'string' || _isBufferLike(value) || (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer)) {
    return toUint8Array(value, encoding);
  }
  throw _fsInvalidArgType('data', 'string or an instance of Buffer, TypedArray, or DataView', value);
}

function _writeFileFromSyncIterable(fd, iterable, encoding) {
  var iterator = iterable[Symbol.iterator]();
  while (true) {
    var step = iterator.next();
    if (step.done) break;
    var bytes = _coerceWriteFileChunk(step.value, encoding);
    writeSync(fd, bytes, 0, bytes.length, -1);
  }
}

function _writeFileFromAsyncIterable(fd, iterable, encoding) {
  var iterator = iterable[Symbol.asyncIterator]();
  return Promise.resolve().then(function readNext() {
    return Promise.resolve(iterator.next()).then(function(step) {
      if (!step || step.done) return;
      var bytes = _coerceWriteFileChunk(step.value, encoding);
      writeSync(fd, bytes, 0, bytes.length, -1);
      return readNext();
    });
  });
}

function _writeFileToDescriptor(fd, data, options) {
  var encoding = options && options.encoding;
  if (_isAsyncIterable(data)) {
    return _writeFileFromAsyncIterable(fd, data, encoding);
  }
  if (_isSyncIterable(data) && typeof data !== 'string' && !_isBufferLike(data)) {
    _writeFileFromSyncIterable(fd, data, encoding);
    if (options && options.flush === true) {
      _callFsyncSync(fd);
    }
    return Promise.resolve();
  }
  var bytes = _coerceWriteFileChunk(data, encoding);
  writeSync(fd, bytes, 0, bytes.length, -1);
  if (options && options.flush === true) {
    _callFsyncSync(fd);
  }
  return Promise.resolve();
}

function _promisesWriteFile(target, data, options) {
  var writeOptions;
  try {
    writeOptions = _normalizeWriteOptions(options);
  } catch (err) {
    return Promise.reject(err);
  }
  var targetInfo = _getFdOrPath(target, 'path');
  var signal = writeOptions && writeOptions.signal;
  if (signal && signal.aborted === true) {
    return Promise.reject(_makeAbortError());
  }

  var fd = targetInfo.fd;
  var needsClose = false;
  if (fd === null) {
    fd = openSync(targetInfo.path, writeOptions.flag || writeOptions.flags || 'w', writeOptions.mode);
    needsClose = true;
  }

  return _writeFileToDescriptor(fd, data, writeOptions).then(function() {
    if (needsClose) closeSync(fd);
    return;
  }, function(err) {
    if (needsClose) {
      try { closeSync(fd); } catch(e) {}
    }
    throw err;
  });
}

function _validateFsOptions(optionName, value, requiredMethods) {
  if (value === undefined) return;
  if (value === null || typeof value !== 'object') {
    throw _fsInvalidArgTypeProperty(optionName, 'Object', value);
  }
  for (var i = 0; i < requiredMethods.length; i++) {
    var method = requiredMethods[i];
    var actual = value[method];
    if (actual === undefined) continue;
    if (typeof actual !== 'function') {
      throw _fsInvalidArgTypeProperty(optionName + '.' + method, 'function', actual);
    }
  }
}

function _getCurrentExport(name) {
  return (typeof module !== 'undefined' && module.exports && module.exports[name]) || null;
}

function _callFsync(fd, callback) {
  var fn = _getCurrentExport('fsync');
  if (typeof fn === 'function') return fn(fd, callback);
  return fsync(fd, callback);
}

function _callFsyncSync(fd) {
  var fn = _getCurrentExport('fsyncSync');
  if (typeof fn === 'function') return fn(fd);
  return fsyncSync(fd);
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
  if (typeof ArrayBuffer !== 'undefined') {
    if (data instanceof ArrayBuffer) {
      return new Uint8Array(data);
    }
    if (typeof ArrayBuffer.isView === 'function' && ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer, data.byteOffset || 0, data.byteLength);
    }
  }
  return new Uint8Array(data);
}

function decodeBytes(bytes, encoding) {
  if (!encoding || encoding === 'buffer') return bytes;
  var enc = encoding.toLowerCase().replace('-', '');
  if (enc === 'utf8' || enc === 'utf-8') enc = 'utf8';
  if (enc === 'utf8') {
    if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
      return Buffer.from(bytes.buffer, bytes.byteOffset || 0, bytes.byteLength).toString('utf8');
    }
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
  if (typeof Buffer !== 'undefined' && Buffer.from) {
    return Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  }
  bytes.toString = function(encoding, start, end) {
    var slice = (start !== undefined || end !== undefined) ? bytes.slice(start || 0, end) : bytes;
    if (!encoding) return decodeBytes(slice, 'utf8');
    return decodeBytes(slice, encoding);
  };
  return bytes;
}

function readFileSync(path, options) {
  // Support fd as first arg
  if (typeof path === 'number') {
    ensureExactFs();
    var encoding = typeof options === 'string' ? options : (options && options.encoding);
    var chunks = [];
    var buf = new Uint8Array(65536);
    var bytesRead;
    do {
      bytesRead = readSync(path, buf, 0, buf.length, -1);
      if (bytesRead > 0) chunks.push(buf.slice(0, bytesRead));
    } while (bytesRead > 0);
    var totalLen = 0;
    for (var ci = 0; ci < chunks.length; ci++) totalLen += chunks[ci].length;
    var result = new Uint8Array(totalLen);
    var pos = 0;
    for (var cj = 0; cj < chunks.length; cj++) {
      result.set(chunks[cj], pos);
      pos += chunks[cj].length;
    }
    if (encoding) return decodeBytes(result, encoding);
    return wrapBuffer(result);
  }
  _validatePath(path);
  _validateEncodingOption(options);
  ensureExactFs();
  var p = _pathToString(path);
  var encoding = typeof options === 'string' ? options : (options && options.encoding);
  var fd;
  try {
    fd = openSync(p, 'r');
  } catch(e) {
    throw _makeFsError(e, 'open', p);
  }
  try {
    var chunks = [];
    var fileBuffer = new Uint8Array(65536);
    var fileBytesRead;
    do {
      fileBytesRead = readSync(fd, fileBuffer, 0, fileBuffer.length, -1);
      if (fileBytesRead > 0) chunks.push(fileBuffer.slice(0, fileBytesRead));
    } while (fileBytesRead > 0);
    var totalLen = 0;
    for (var fileChunkIndex = 0; fileChunkIndex < chunks.length; fileChunkIndex++) {
      totalLen += chunks[fileChunkIndex].length;
    }
    var fileResult = new Uint8Array(totalLen);
    var filePos = 0;
    for (var fileChunk = 0; fileChunk < chunks.length; fileChunk++) {
      fileResult.set(chunks[fileChunk], filePos);
      filePos += chunks[fileChunk].length;
    }
    if (encoding) return decodeBytes(fileResult, encoding);
    return wrapBuffer(fileResult);
  } catch(e) {
    throw _makeFsError(e, 'read', p);
  } finally {
    try { closeSync(fd); } catch(_ignore) {}
  }
}

function writeFileSync(path, data, options) {
  _validateWriteData(data);
  var writeOptions = _normalizeWriteOptions(options);
  // Support fd as first arg
  if (typeof path === 'number') {
    ensureExactFs();
    var fdData = toUint8Array(data, writeOptions.encoding);
    writeSync(path, fdData, 0, fdData.length, -1);
    if (writeOptions.flush === true) {
      _callFsyncSync(path);
    }
    return;
  }
  _validatePath(path);
  ensureExactFs();
  var p = _pathToString(path);
  try {
    var writeData = toUint8Array(data, writeOptions.encoding);
    var writeFd = openSync(p, writeOptions.flag || writeOptions.flags || 'w', writeOptions.mode);
    try {
      writeSync(writeFd, writeData, 0, writeData.length, -1);
      if (writeOptions.flush === true) {
        _callFsyncSync(writeFd);
      }
    } finally {
      closeSync(writeFd);
    }
  } catch(e) {
    throw _makeFsError(e, 'open', p);
  }
}

function _validateWriteData(data) {
  if (typeof data !== 'string' && !_isBufferLike(data)) {
    throw _fsInvalidArgType('data', 'string or an instance of Buffer, TypedArray, or DataView', data);
  }
}

function appendFileSync(path, data, options) {
  _validateWriteData(data);
  var writeOptions = _normalizeWriteOptions(options);
  var target = _getFdOrPath(path, 'path');

  // Support fd and FileHandle-like objects as first arg
  if (target.fd !== null) {
    ensureExactFs();
    var fdData = toUint8Array(data, writeOptions.encoding);
    writeSync(target.fd, fdData, 0, fdData.length, -1);
    if (writeOptions.flush === true) {
      _callFsyncSync(target.fd);
    }
    return;
  }

  ensureExactFs();
  var p = target.path;
  try {
    var appendData = toUint8Array(data, writeOptions.encoding);
    var appendFallbackFd = openSync(p, writeOptions.flag || writeOptions.flags || 'a', writeOptions.mode);
    try {
      writeSync(appendFallbackFd, appendData, 0, appendData.length, -1);
      if (writeOptions.flush === true) {
        _callFsyncSync(appendFallbackFd);
      }
    } finally {
      closeSync(appendFallbackFd);
    }
  } catch(e) {
    throw _makeFsError(e, 'open', p);
  }
}

function _coerceStatsValue(raw, useBigInt) {
  if (useBigInt) {
    if (typeof raw === 'bigint') return raw;
    return BigInt(raw || 0);
  }
  return raw || 0;
}

var _internalFsUtilsBigIntStats;

function _getInternalBigIntStats() {
  if (_internalFsUtilsBigIntStats === undefined) {
    var ctor = null;
    try {
      var fsUtils = require('internal/fs/utils');
      if (fsUtils && typeof fsUtils.BigIntStats === 'function') {
        ctor = fsUtils.BigIntStats;
      }
    } catch (e) {}
    _internalFsUtilsBigIntStats = ctor;
  }
  return _internalFsUtilsBigIntStats;
}

function _coerceToBigInt(raw) {
  if (typeof raw === 'bigint') return raw;
  if (typeof raw === 'number' && !isNaN(raw)) return BigInt(raw);
  return 0n;
}

function _makeBigIntStats(raw) {
  var ctor = _getInternalBigIntStats();
  if (typeof ctor !== 'function') {
    return new Stats(raw || {}, true);
  }
  var safe = raw || {};
  var mt = safe.mtime_ms || safe.mtimeMs || 0;
  var at = safe.atime_ms || safe.atimeMs || mt;
  var ct = safe.ctime_ms || safe.ctimeMs || mt;
  var bt = safe.birthtime_ms || safe.birthtimeMs || mt;
  return new ctor(
    _coerceToBigInt(safe.dev),
    _coerceToBigInt(safe.mode),
    _coerceToBigInt(safe.nlink || 1),
    _coerceToBigInt(safe.uid),
    _coerceToBigInt(safe.gid),
    _coerceToBigInt(safe.rdev),
    _coerceToBigInt(safe.blksize || 4096),
    _coerceToBigInt(safe.ino),
    _coerceToBigInt(safe.size),
    _coerceToBigInt(safe.blocks),
    _coerceToBigInt(at),
    _coerceToBigInt(mt),
    _coerceToBigInt(ct),
    _coerceToBigInt(bt),
    _coerceToBigInt(safe.atime_ns || safe.atimeNs || 0),
    _coerceToBigInt(safe.mtime_ns || safe.mtimeNs || 0),
    _coerceToBigInt(safe.ctime_ns || safe.ctimeNs || 0),
    _coerceToBigInt(safe.birthtime_ns || safe.birthtimeNs || 0)
  );
}

function _coerceStatsDate(raw) {
  return new Date(raw || 0);
}

function Stats(raw, useBigInt) {
  var toValue = useBigInt ? _coerceStatsValue : function(v) { return v || 0; };
  this.dev = toValue(raw.dev);
  this.ino = toValue(raw.ino);
  this.mode = toValue(raw.mode);
  this.nlink = toValue(raw.nlink || 1);
  this.uid = toValue(raw.uid);
  this.gid = toValue(raw.gid);
  this.rdev = toValue(raw.rdev);
  this.size = toValue(raw.size);
  this.blksize = toValue(raw.blksize || 4096);
  this.blocks = toValue(raw.blocks);
  var mt = raw.mtime_ms || raw.mtimeMs || 0;
  var at = raw.atime_ms || raw.atimeMs || mt;
  var ct = raw.ctime_ms || raw.ctimeMs || mt;
  var bt = raw.birthtime_ms || raw.birthtimeMs || mt;
  this.atimeMs = toValue(at);
  this.mtimeMs = toValue(mt);
  this.ctimeMs = toValue(ct);
  this.birthtimeMs = toValue(bt);
  this.atimeNs = toValue(raw.atime_ns || raw.atimeNs || 0);
  this.mtimeNs = toValue(raw.mtime_ns || raw.mtimeNs || 0);
  this.ctimeNs = toValue(raw.ctime_ns || raw.ctimeNs || 0);
  this.birthtimeNs = toValue(raw.birthtime_ns || raw.birthtimeNs || 0);
  this.atime = _coerceStatsDate(Number(at));
  this.mtime = _coerceStatsDate(Number(mt));
  this.ctime = _coerceStatsDate(Number(ct));
  this.birthtime = _coerceStatsDate(Number(bt));
  this._isFile = !!raw.is_file;
  this._isDir = !!raw.is_dir;
  this._isSymlink = !!raw.is_symlink;
  this._isChrDev = !!raw.is_char_device;
  this._isBlkDev = !!raw.is_block_device;
  this._isFifo = !!raw.is_fifo;
  this._isSock = !!raw.is_socket;
}
Stats.prototype.isFile = function() { return this._isFile; };
Stats.prototype.isDirectory = function() { return this._isDir; };
Stats.prototype.isSymbolicLink = function() { return this._isSymlink; };
Stats.prototype.isBlockDevice = function() { return this._isBlkDev; };
Stats.prototype.isCharacterDevice = function() { return this._isChrDev; };
Stats.prototype.isFIFO = function() { return this._isFifo; };
Stats.prototype.isSocket = function() { return this._isSock; };

function _makeStats(json, opts) {
  var raw = JSON.parse(json);
  var options = _extractStatOptions(opts);
  return new Stats(raw, options.bigint);
}

function _coerceStatOptions(options) {
  if (options === undefined || options === null) return {};
  if (typeof options !== 'object') {
    throw _fsInvalidArgType('options', 'Object', options);
  }
  return options;
}

function _extractStatOptions(options) {
  var opts = _coerceStatOptions(options);
  return {
    bigint: !!opts.bigint,
    throwIfNoEntry: opts.throwIfNoEntry === false ? false : true
  };
}

function StatFs(raw, useBigInt) {
  var toBigInt = useBigInt ? function(v) { return BigInt(v); } : function(v) { return Number(v); };
  this.type = toBigInt(raw.type || 0);
  this.bsize = toBigInt(raw.bsize || 0);
  this.blocks = toBigInt(raw.blocks || 0);
  this.bfree = toBigInt(raw.bfree || 0);
  this.bavail = toBigInt(raw.bavail || 0);
  this.files = toBigInt(raw.files || 0);
  this.ffree = toBigInt(raw.ffree || 0);
}

function statSync(path, options) {
  _validatePath(path);
  ensureExactFs();
  _coerceStatOptions(options);
  var p = _pathToString(path);
  var opts = _extractStatOptions(options);
  try {
    var json = g.__exactStat(p);
    return _makeStats(json, opts);
  } catch(e) {
    if (opts.throwIfNoEntry === false && e && e.code === 'ENOENT') {
      return undefined;
    }
    throw _makeFsError(e, 'stat', p);
  }
}

function lstatSync(path, options) {
  _validatePath(path);
  ensureExactFs();
  _coerceStatOptions(options);
  var p = _pathToString(path);
  var opts = _extractStatOptions(options);
  try {
    var json = g.__exactLstat(p);
    return _makeStats(json, opts);
  } catch(e) {
    if (opts.throwIfNoEntry === false && e && e.code === 'ENOENT') {
      return undefined;
    }
    throw _makeFsError(e, 'lstat', p);
  }
}

function Dirent(name, parentPath, stat) {
  this.name = name;
  this.parentPath = parentPath;
  this.path = parentPath;
  this._stat = stat;
}
Dirent.prototype.isFile = function() { return this._stat ? this._stat.isFile() : false; };
Dirent.prototype.isDirectory = function() { return this._stat ? this._stat.isDirectory() : false; };
Dirent.prototype.isSymbolicLink = function() { return this._stat ? this._stat.isSymbolicLink() : false; };
Dirent.prototype.isBlockDevice = function() { return this._stat ? this._stat.isBlockDevice() : false; };
Dirent.prototype.isCharacterDevice = function() { return this._stat ? this._stat.isCharacterDevice() : false; };
Dirent.prototype.isFIFO = function() { return this._stat ? this._stat.isFIFO() : false; };
Dirent.prototype.isSocket = function() { return this._stat ? this._stat.isSocket() : false; };

function _normalizeDirEntryName(name, encoding) {
  if (encoding === 'buffer') {
    return Buffer.isBuffer(name) ? name : Buffer.from(name);
  }
  return name;
}

function _buildDirEntries(path, options) {
  var recursive = options && options.recursive;
  var encoding = options && options.encoding;
  var list = [];
  var dirPath = _pathToString(path);
  var raw = readdirSync(dirPath, { withFileTypes: false, encoding: encoding });
  for (var i = 0; i < raw.length; i++) {
    var name = raw[i];
    var fullPath = pathJoin(dirPath, name);
    var stat = null;
    try { stat = lstatSync(fullPath); } catch(e) {}
    var entryName = _normalizeDirEntryName(name, encoding);
    var entry = new Dirent(entryName, dirPath, stat);
    entry.path = dirPath;
    list.push(entry);
    if (recursive && stat && typeof stat.isDirectory === 'function' && stat.isDirectory()) {
      var nested = _buildDirEntries(fullPath, options);
      for (var j = 0; j < nested.length; j++) {
        list.push(nested[j]);
      }
    }
  }
  return list;
}

function Dir(path, options) {
  this._path = path;
  this._entries = _buildDirEntries(path, options || {});
  this._index = 0;
  this._closed = false;
  this._closing = false;
  this._asyncReads = 0;
  this._closeCallbacks = [];
}

Object.defineProperty(Dir.prototype, 'path', {
  get: function() {
    if (!(this instanceof Dir)) throw _makeFsThisError('path');
    return this._path;
  },
  set: function(value) {
    if (!(this instanceof Dir)) throw _makeFsThisError('path');
    this._path = value;
  },
  configurable: true
});

function _ensureDirReadableState(dir) {
  if (dir._closed) {
    throw _makeDirClosedError(dir._path);
  }
  if (dir._asyncReads > 0) {
    throw _makeDirConcurrentOperationError(dir._path);
  }
  if (dir._closing) {
    throw _makeDirClosedError(dir._path);
  }
}

function _completeDirClose(dir, error) {
  dir._closed = true;
  dir._closing = false;
  var callbacks = dir._closeCallbacks || [];
  dir._closeCallbacks = [];
  if (!error) {
    for (var i = 0; i < callbacks.length; i++) {
      _deferFsCallback((function(cb) {
        return function() { cb(null); };
      })(callbacks[i]));
    }
    return;
  }
  for (var j = 0; j < callbacks.length; j++) {
    _deferFsCallback((function(cb, e) {
      return function() { cb(e); };
    })(callbacks[j], error));
  }
}

function _drainDirReadResult(dir, callback, err, value) {
  dir._asyncReads -= 1;
  if (!dir._closed && dir._closing && dir._asyncReads === 0) {
    _completeDirClose(dir, null);
  }
  _deferFsCallback(function() {
    callback(err, value);
  });
}

Dir.prototype.readSync = function() {
  _ensureDirReadableState(this);
  if (this._index >= this._entries.length) return null;
  return this._entries[this._index++];
};

Dir.prototype._nextEntry = function() {
  if (this._index >= this._entries.length) return null;
  return this._entries[this._index++];
};

Dir.prototype.read = function(callback) {
  if (typeof callback === 'undefined') {
    var self = this;
    return new Promise(function(resolve, reject) {
      try {
        self.read(function(err, value) {
          if (err) {
            reject(err);
          } else {
            resolve(value);
          }
        });
      } catch (err) {
        reject(err);
      }
    });
  }
  _validateCallback(callback);
  if (this._closed || this._closing) {
    return _deferFsCallback(function() {
      callback(_makeDirClosedError(this._path));
    }.bind(this));
  }
  this._asyncReads += 1;
  _deferFsCallback(function() {
    var err = null;
    var value = null;
    try {
      value = this._nextEntry();
    } catch(e) {
      err = e;
    }
    _drainDirReadResult(this, callback, err, value);
  }.bind(this));
};

Dir.prototype.close = function(callback) {
  if (typeof callback === 'undefined') {
    var self = this;
    return new Promise(function(resolve, reject) {
      try {
        self.close(function(err) {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      } catch (err) {
        reject(err);
      }
    });
  }
  if (callback !== undefined && callback !== null) _validateCallback(callback);
  if (this._closed || this._closing) {
    if (typeof callback === 'function') {
      _deferFsCallback(function() { callback(_makeDirClosedError(this._path)); }.bind(this));
    }
    return;
  }
  this._closing = true;
  if (typeof callback === 'function') {
    this._closeCallbacks.push(callback);
  }
  if (this._asyncReads === 0) {
    _completeDirClose(this, null);
  }
};

Dir.prototype.closeSync = function() {
  if (this._closed || this._closing) {
    throw _makeDirClosedError(this._path);
  }
  if (this._asyncReads > 0) {
    throw _makeDirConcurrentOperationError(this._path);
  }
  this._closed = true;
};

Dir.prototype[Symbol.asyncIterator] = function() {
  var self = this;
  return {
    next: function() {
      return Promise.resolve().then(function() {
        var value;
        try {
          value = self.readSync();
        } catch (e) {
          return { done: true, value: undefined };
        }
        if (value === null) return { done: true };
        return { done: false, value: value };
      });
    },
    return: function() {
      return new Promise(function(resolve, reject) {
        try {
          self.close(function(err) {
            if (err) reject(err);
            else resolve({ done: true });
          });
        } catch (e) {
          if (e && e.code) {
            reject(e);
          } else {
            reject(_makeDirConcurrentOperationError(self._path));
          }
        }
      });
    }
  };
};

function opendirSync(path, options) {
  _validatePath(path);
  if (options && typeof options === 'object') {
    if (options.encoding) {
      _validateEncodingOption(options.encoding);
    }
    if (Object.prototype.hasOwnProperty.call(options, 'bufferSize')) {
      if (typeof options.bufferSize !== 'number') {
        throw _fsInvalidArgType('bufferSize', 'number', options.bufferSize);
      }
      _validateInt('bufferSize', options.bufferSize, 1, 0x7fffffff);
    }
  }
  return new Dir(path, options);
}

function opendir(path, options, cb) {
  var opts, callback;
  if (typeof options === 'function') { callback = options; options = {}; }
  else { opts = options; callback = cb; }
  _validateCallback(callback);
  _validatePath(path);
  wrapCallback(function() { return opendirSync(path, opts); }, callback, 'opendir', _pathToString(path));
}

function readdirSync(path, options) {
  _validatePath(path);
  _validateEncodingOption(options);
  ensureExactFs();
  var p = _pathToString(path);
  var opts = typeof options === 'string' ? { encoding: options } : (options || {});
  var withFileTypes = !!opts.withFileTypes;
  var recursive = !!opts.recursive;
  var encoding = opts.encoding;
  try {
    var rawEntries = JSON.parse(g.__exactReaddir(p));
    var entries = rawEntries;
    if (encoding === 'buffer') {
      entries = rawEntries.map(function(e) { return Buffer.from(e); });
    } else if (typeof encoding === 'string' && encoding !== 'utf8' && encoding !== 'utf-8') {
      entries = rawEntries.map(function(e) {
        return decodeBytes(Buffer.from(e), encoding);
      });
    }
    if (!withFileTypes && !recursive) {
      return entries;
    }
    if (withFileTypes) {
      var dirents = [];
      for (var i = 0; i < entries.length; i++) {
        var fullPath = p + '/' + rawEntries[i];
        var st;
        try { st = lstatSync(fullPath); } catch(e) { st = null; }
        dirents.push(new Dirent(entries[i], p, st));
      }
      if (recursive) {
        var more = [];
        for (var j = 0; j < dirents.length; j++) {
          if (dirents[j].isDirectory()) {
            var recursePath = p + '/' + rawEntries[j];
            var sub = readdirSync(recursePath, { withFileTypes: true, recursive: true });
            for (var k = 0; k < sub.length; k++) more.push(sub[k]);
          }
        }
        dirents = dirents.concat(more);
      }
      return dirents;
    }
    if (recursive) {
      var all = entries.slice();
      for (var ri = 0; ri < entries.length; ri++) {
        var rFullPath = p + '/' + rawEntries[ri];
        try {
          var rSt = lstatSync(rFullPath);
          if (rSt.isDirectory()) {
            var rSub = readdirSync(rFullPath, { recursive: true });
            for (var rk = 0; rk < rSub.length; rk++) all.push(entries[ri] + '/' + rSub[rk]);
          }
        } catch(e) {}
      }
      return all;
    }
    return entries;
  } catch(e) {
    throw _makeFsError(e, 'scandir', p);
  }
}

function _toDirentLike(name, parentPath, statVal, withFileTypes) {
  if (!withFileTypes) {
    return name;
  }
  return new Dirent(name, parentPath, statVal || null);
}

function cpSync(src, dest, options) {
  _validatePath(src, 'src');
  _validatePath(dest, 'dest');
  options = options || {};
  var filter = options.filter;
  var recursive = !!options.recursive;
  var dereference = !!options.dereference;
  var errorOnExist = !!options.errorOnExist;
  var force = options.force !== false;
  var preserveTimestamps = !!options.preserveTimestamps;
  var srcPath = _pathToString(src);
  var destPath = _pathToString(dest);
  if (typeof filter !== 'undefined' && typeof filter !== 'function') {
    throw _fsInvalidArgType('filter', 'function', filter);
  }
  if (typeof options.mode === 'number') {
    _validateUint32('mode', options.mode);
  }
  if (typeof options.verbatimSymlinks !== 'undefined' && typeof options.verbatimSymlinks !== 'boolean') {
    throw _fsInvalidArgType('verbatimSymlinks', 'boolean', options.verbatimSymlinks);
  }

  function shouldSkip(srcItem, destItem) {
    if (!filter) return false;
    return filter(srcItem, destItem) === false;
  }

  function copyOne(source, destination) {
    if (filter && shouldSkip(source, destination)) return;
    var st = lstatSync(source);
    if (st.isSymbolicLink()) {
      if (dereference) {
        copyOne(realpathSync(source), destination);
        return;
      }
      var linkTarget = readlinkSync(source);
      return symlinkSync(linkTarget, destination);
    }
    if (st.isDirectory()) {
      if (!recursive) {
        var err = new Error('EISDIR: illegal operation on a directory, copyfile \'' + source + '\' -> \'' + destination + '\'');
        err.code = 'EISDIR';
        err.errno = _uvErrnoMap.EISDIR;
        throw err;
      }
      if (filter && shouldSkip(source, destination)) return;
      if (force && !existsSync(destination)) {
        mkdirSync(destination, { recursive: true });
      } else if (!existsSync(destination)) {
        mkdirSync(destination, { recursive: true });
      } else if (!lstatSync(destination).isDirectory()) {
        if (errorOnExist) {
          var err = new Error('EEXIST: file already exists, mkdir \'' + destination + '\'');
          err.code = 'EEXIST';
          err.errno = _uvErrnoMap.EEXIST;
          throw err;
        }
        rmSync(destination, { recursive: true, force: true });
        mkdirSync(destination);
      }
      var list = readdirSync(source, { withFileTypes: true });
      for (var i = 0; i < list.length; i++) {
        var childName = list[i].name;
        copyOne(pathJoin(source, childName), pathJoin(destination, childName));
      }
      return;
    }
    if (st.isFile()) {
      if (errorOnExist && !force && existsSync(destination)) {
        var alreadyErr = new Error('EEXIST: file already exists, copyFile \'' + source + '\' -> \'' + destination + '\'');
        alreadyErr.code = 'EEXIST';
        alreadyErr.errno = _uvErrnoMap.EEXIST;
        throw alreadyErr;
      }
      if (existsSync(destination) && force) {
        unlinkSync(destination);
      }
      if (preserveTimestamps) {
        var data = readFileSync(source);
        writeFileSync(destination, data);
      } else {
        var fd = openSync(source, 'r');
        var outFd = openSync(destination, 'w', options.mode);
        try {
          var buf = Buffer.alloc(65536);
          var bytes = readSync(fd, buf, 0, buf.length, -1);
          while (bytes > 0) {
            writeSync(outFd, buf, 0, bytes, -1);
            bytes = readSync(fd, buf, 0, buf.length, -1);
          }
        } finally {
          closeSync(fd);
          closeSync(outFd);
        }
      }
      return;
    }
    if (!st.isSymbolicLink()) {
      copyOne(realpathSync(source), destination);
      return;
    }
  }

  copyOne(srcPath, destPath);
}

function cp(src, dest, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  _validateCallback(cb);
  wrapCallback(function() { cpSync(src, dest, options); }, cb, 'copyfile', _pathToString(src));
}

function statfsSync(path, options) {
  _validatePath(path);
  _validateEncodingOption(options);
  ensureExactFs();
  var p = _pathToString(path);
  if (!g.__exactStatfs) {
    var err = new Error('ENOSYS: statfs is not supported');
    err.code = 'ENOSYS';
    err.errno = _uvErrnoMap.ENOSYS;
    throw err;
  }
  try {
    var payload = g.__exactStatfs(p);
    var parsed = typeof payload === 'string' ? JSON.parse(payload) : payload;
    return new StatFs(parsed, options && options.bigint);
  } catch(e) {
    throw _makeFsError(e, 'statfs', p);
  }
}
function statfs(path, options, cb) {
  if (typeof options === 'function') { cb = options; options = undefined; }
  _validateCallback(cb);
  _validatePath(path);
  wrapCallback(function() { return statfsSync(path, options); }, cb, 'statfs', _pathToString(path));
}

function _patternToRegex(pattern) {
  var escaped = '';
  var i = 0;
  while (i < pattern.length) {
    var ch = pattern.charAt(i);
    if (ch === '\\\\') {
      escaped += '\\\\';
      i += 1;
    } else if (pattern.slice(i, i + 2) === '**') {
      if (pattern.charAt(i + 2) === '/') {
        escaped += '(?:[^/]+/)*?';
        i += 3;
      } else {
        escaped += '.*';
        i += 2;
      }
    } else if (ch === '*') {
      escaped += '[^/]*';
      i += 1;
    } else if (ch === '?') {
      escaped += '.';
      i += 1;
    } else if (ch === '[') {
      var close = pattern.indexOf(']', i + 1);
      if (close === -1) {
        escaped += '\\\\[';
        i += 1;
      } else {
        escaped += pattern.slice(i, close + 1);
        i = close + 1;
      }
    } else {
      if (ch === '.' || ch === '+' || ch === '^' || ch === '$' || ch === '(' || ch === ')' || ch === '|' || ch === '{' || ch === '}' || ch === '[' || ch === ']' || ch === '\\') {
        escaped += '\\' + ch;
      } else {
        escaped += ch;
      }
      i += 1;
    }
  }
  return new RegExp('^' + escaped + '$');
}

function _collectAllEntries(root, prefix, includeFiles, includeDirs) {
  var out = [];
  var stats;
  try { stats = statSync(root); } catch(_e) { return out; }
  if (!stats.isDirectory()) {
    out.push(prefix || '');
    return out;
  }
  var entries = readdirSync(root, { withFileTypes: true });
  for (var i = 0; i < entries.length; i++) {
    var child = entries[i];
    var childPrefix = prefix ? prefix + '/' + child.name : child.name;
    if (child.isDirectory()) {
      if (includeDirs) out.push(childPrefix + '/');
      Array.prototype.push.apply(out, _collectAllEntries(pathJoin(root, child.name), childPrefix, includeFiles, includeDirs));
    } else if (includeFiles) {
      out.push(childPrefix);
    }
  }
  return out;
}

function globSync(pattern, options) {
  options = options || {};
  var cwd = options.cwd || _currentProcessCwd();
  _validatePath(cwd, 'cwd');
  _validatePath(pattern, 'pattern');
  _validateEncodingOption(options);
  var withTypes = !!options.withFileTypes;
  var exclude = options.exclude;
  var regex = _patternToRegex(pattern);
  if (exclude && !Array.isArray(exclude) && typeof exclude !== 'function') {
    throw _fsInvalidArgType('exclude', 'function or array', exclude);
  }
  var paths = [];
  var all = _collectAllEntries(cwd, '', true, false);
  for (var i = 0; i < all.length; i++) {
    var candidate = all[i].replace(/\\\\/g, '/');
    if (exclude) {
      var isExcluded = Array.isArray(exclude)
        ? exclude.indexOf(candidate) !== -1
        : typeof exclude === 'function' && !exclude(candidate);
      if (isExcluded) continue;
    }
    if (!regex.test(candidate)) continue;
    if (withTypes) {
      var full = pathJoin(cwd, candidate);
      var stat = null;
      try { stat = lstatSync(full); } catch(_e) {}
      paths.push(new Dirent(candidate, full, stat || null));
    } else {
      paths.push(candidate);
    }
  }
  if (options.withFileTypes) {
    return paths;
  }
  if (options.encoding === 'buffer') {
    return paths.map(function(item) { return Buffer.from(item); });
  }
  return paths.sort();
}

function glob(pattern, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  _validateCallback(callback);
  var cwd = options && options.cwd ? options.cwd : _currentProcessCwd();
  if (typeof options === 'string') {
    options = { pattern: options };
  }
  wrapCallback(function() { return globSync(pattern, options); }, callback, 'glob', _pathToString(cwd));
}

function mkdirSync(path, options) {
  _validatePath(path);
  ensureExactFs();
  var p = _pathToString(path);
  var recursive = false;
  var mode;
  var firstCreatedPath;
  if (typeof options === 'object' && options !== null) {
    _validateMkdirRecursiveOption(options);
    recursive = options.recursive === true;
    mode = options.mode;
  } else if (typeof options === 'string' || typeof options === 'number') {
    mode = options;
  }
  if (mode !== undefined) {
    mode = _coerceMode(mode) & 0o777;
  }
  try {
    if (recursive) {
      firstCreatedPath = _getFirstMissingPath(p);
    }
    if (typeof path === 'string' && path.charAt(0) !== '/') {
      try {
        statSync(_currentProcessCwd());
      } catch (cwdErr) {
        if (cwdErr && cwdErr.code === 'ENOENT') {
          throw cwdErr;
        }
      }
    }
    g.__exactMkdir(p, recursive);
    if (mode !== undefined) {
      try {
        chmodSync(p, mode);
      } catch (_chmodErr) {}
    }
    if (recursive) return firstCreatedPath;
  } catch(e) {
    throw _makeFsError(e, 'mkdir', p);
  }
}

function rmdirSync(path, options) {
  _validatePath(path); ensureExactFs();
  var p = _pathToString(path);
  try { g.__exactRmdir(p); } catch(e) { throw _makeFsError(e, 'rmdir', p); }
}
function unlinkSync(path) {
  _validatePath(path); ensureExactFs();
  var p = _pathToString(path);
  try { g.__exactUnlink(p); } catch(e) { throw _makeFsError(e, 'unlink', p); }
}
function renameSync(oldPath, newPath) {
  _validatePath(oldPath, 'oldPath'); _validatePath(newPath, 'newPath'); ensureExactFs();
  var op = _pathToString(oldPath); var np = _pathToString(newPath);
  try { g.__exactRename(op, np); } catch(e) { throw _makeFsError(e, 'rename', op, np); }
}
function copyFileSync(src, dest, mode) {
  _validatePath(src, 'src'); _validatePath(dest, 'dest'); ensureExactFs();
  var s = _pathToString(src); var d = _pathToString(dest);
  if (mode !== undefined && mode !== null) {
    _validateCopyFileMode(mode);
  }
  // Keep behavior aligned with Node.js:
  // copyFile with COPYFILE_EXCL (mode bit 1) must fail if destination exists.
  // Validate source first so `ENOENT` from missing source wins over exclusive checks.
  try {
    lstatSync(s);
  } catch(err) {
    if (err && err.code === 'ENOENT') {
      var copyfileSrcErr = new Error("ENOENT: no such file or directory, copyfile '" + s + "' -> '" + d + "'");
      throw _makeFsError(copyfileSrcErr, 'copyfile', s, d);
    }
    if (err) {
      var normalizedSrcErr = _makeFsError(err, 'copyfile', s, d);
      throw normalizedSrcErr;
    }
  }
  if ((mode & 1) === 1) {
    try {
      lstatSync(d);
      var exclusiveErr = new Error("EEXIST: file already exists, copyfile '" + s + "' -> '" + d + "'");
      throw _makeFsError(exclusiveErr, 'copyfile', s, d);
    } catch(err) {
      if (err.code !== 'ENOENT') {
        throw err;
      }
    }
  }
  try { g.__exactCopyFile(s, d); } catch(e) { throw _makeFsError(e, 'copyfile', s, d); }
}
function accessSync(path, mode) {
  _validatePath(path); ensureExactFs();
  var p = _pathToString(path);
  var validatedMode = _validateAccessMode(mode);
  try { g.__exactAccess(p, validatedMode); } catch(e) { throw _makeFsError(e, 'access', p); }
}
function chmodSync(path, mode) {
  _validatePath(path); ensureExactFs();
  var p = _pathToString(path);
  var m = typeof mode === 'string' ? parseInt(mode, 8) : mode;
  try { g.__exactChmod(p, m); } catch(e) { throw _makeFsError(e, 'chmod', p); }
}
function realpathSync(path, options) {
  _validatePath(path); _validateEncodingOption(options); ensureExactFs();
  var p = _pathToString(path);
  // Match Node.js behavior: non-native realpath path checks use lstat,
  // so a missing path reports "lstat" rather than "realpath".
  lstatSync(p);
  try { return g.__exactRealpath(p); } catch(e) { throw _makeFsError(e, 'realpath', p); }
}
function realpathSyncNative(path) {
  _validatePath(path);
  ensureExactFs();
  var p = _pathToString(path);
  try { return g.__exactRealpath(p); } catch(e) { throw _makeFsError(e, 'realpath', p); }
}
realpathSync.native = realpathSyncNative;

function _mkdtempDisposableFromPath(pathValue, removePath, returnPromise) {
  var disposalPath = removePath || pathValue;
  var removed = false;
  function removeDisposablePath() {
    try {
      rmSync(disposalPath, { recursive: true, force: false });
      removed = true;
      return;
    } catch(err) {
      if (err && err.code === 'ENOENT') {
        removed = true;
        return;
      }
      removed = false;
      throw err;
    }
  }
  var result = {
    path: pathValue,
    remove: function() {
      if (removed) return returnPromise ? Promise.resolve() : undefined;
      if (returnPromise) {
        try {
          removeDisposablePath();
          return Promise.resolve();
        } catch(err) {
          return Promise.reject(_makeFsError(err, 'rm', disposalPath));
        }
      }
      try {
        removeDisposablePath();
      } catch(err) {
        throw _makeFsError(err, 'rm', disposalPath);
      }
      return;
    }
  };
  if (typeof Symbol !== 'undefined' && Symbol.dispose) {
    result[Symbol.dispose] = result.remove;
  }
  if (typeof Symbol !== 'undefined' && Symbol.asyncDispose && returnPromise) {
    result[Symbol.asyncDispose] = function() {
      if (removed) return Promise.resolve();
      return new Promise(function(resolve, reject) {
        try {
          removeDisposablePath();
          resolve();
        } catch(err) {
          reject(_makeFsError(err, 'rm', disposalPath));
        }
      });
    };
  }
  return result;
}

function _mkdtempResult(prefix, options) {
  _validatePath(prefix, 'prefix'); _validateEncodingOption(options); ensureExactFs();
  var prefixPath = _pathToString(prefix);
  var parent = _dirnamePath(prefixPath);
  var rawPrefix = typeof prefix === 'string' ? prefix :
    (typeof Buffer !== 'undefined' && Buffer.isBuffer(prefix) ? prefix.toString() : null);
  if (!existsSync(parent)) {
    var err = new Error("ENOENT: no such file or directory, mkdtemp '" + prefix + "'");
    throw _makeFsError(err, 'mkdtemp', prefix);
  }
  try {
    var createdPath = g.__exactMkdtemp(prefixPath);
    return {
      actualPath: createdPath,
      publicPath: rawPrefix !== null && !_isAbsolutePath(rawPrefix) ? relativePathFromCwd(createdPath) : createdPath
    };
  } catch(e) {
    throw _makeFsError(e, 'mkdtemp', prefix);
  }
}
function mkdtempSync(prefix, options) {
  return _mkdtempResult(prefix, options).publicPath;
}
function mkdtempDisposableSync(prefix, options) {
  var tempResult = _mkdtempResult(prefix, options);
  return _mkdtempDisposableFromPath(tempResult.publicPath, tempResult.actualPath, false);
}

function existsSync(path) {
  // existsSync never throws - returns false for invalid paths
  try {
    if (
      typeof path !== 'string' &&
      !Buffer.isBuffer(path) &&
      !(path && typeof path === 'object' && path.href !== undefined && path.protocol !== undefined)
    ) {
      _emitFsDeprecation('DEP0187', 'Passing invalid argument types to fs.existsSync is deprecated');
      return false;
    }
    ensureExactFs();
    g.__exactAccess(_pathToString(path), 0);
    return true;
  } catch(e) { return false; }
}

function wrapCallback(fn, cb, syscall, path) {
  try {
    var result = fn();
    _deferFsCallback(function() {
      if (result === undefined) cb(null);
      else cb(null, result);
    });
  } catch(err) {
    var error = _makeFsError(err, syscall, path);
    _deferFsCallback(function() { cb(error); });
  }
}

function readFile(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateCallback(callback);
  if (typeof path !== 'number') _validatePath(path);
  _validateEncodingOption(opts);
  wrapCallback(function() { return readFileSync(path, opts); }, callback, 'open', typeof path === 'number' ? undefined : _pathToString(path));
}

function writeFile(path, data, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateCallback(callback);
  var target = _getFdOrPath(path, 'path');
  var writeOptions;
  try {
    writeOptions = _normalizeWriteOptions(opts);
  } catch(err) {
    if (err && err.code === 'ABORT_ERR') {
      _deferFsCallback(function() { callback(err); });
      return;
    }
    throw err;
  }
  if (writeOptions.flush === true) {
    _writeFileWithFlushCallback(target, data, writeOptions, false, callback);
    return;
  }
  wrapCallback(function() { writeFileSync(target.path || target.fd, data, writeOptions); }, callback, 'open', target.path);
}

function appendFile(path, data, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateCallback(callback);
  var target = _getFdOrPath(path, 'path');
  var writeOptions;
  try {
    writeOptions = _normalizeWriteOptions(opts);
  } catch(err) {
    if (err && err.code === 'ABORT_ERR') {
      _deferFsCallback(function() { callback(err); });
      return;
    }
    throw err;
  }
  if (writeOptions.flush === true) {
    _writeFileWithFlushCallback(target, data, writeOptions, true, callback);
    return;
  }
  wrapCallback(function() { appendFileSync(target.path || target.fd, data, writeOptions); }, callback, 'open', target.path);
}

function stat(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateCallback(callback);
  _validatePath(path);
  wrapCallback(function() { return statSync(path, opts); }, callback, 'stat', _pathToString(path));
}
function lstat(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateCallback(callback);
  _validatePath(path);
  wrapCallback(function() { return lstatSync(path, opts); }, callback, 'lstat', _pathToString(path));
}
function readdir(path, optOrCb, cb) {
  var opts = typeof optOrCb === 'function' ? undefined : optOrCb;
  var callback = typeof optOrCb === 'function' ? optOrCb : cb;
  _validateCallback(callback);
  _validatePath(path);
  _validateEncodingOption(opts);
  wrapCallback(function() { return readdirSync(path, opts); }, callback, 'scandir', _pathToString(path));
}
function mkdir(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateCallback(callback);
  _validatePath(path);
  _validateMkdirRecursiveOption(opts);
  wrapCallback(function() { return mkdirSync(path, opts); }, callback, 'mkdir', _pathToString(path));
}
function rmdir(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateCallback(callback);
  _validatePath(path);
  wrapCallback(function() { rmdirSync(path, opts); }, callback, 'rmdir', _pathToString(path));
}
function unlink(path, cb) { _validateCallback(cb); _validatePath(path); wrapCallback(function() { unlinkSync(path); }, cb, 'unlink', _pathToString(path)); }
function rename(o, n, cb) { _validateCallback(cb); _validatePath(o, 'oldPath'); _validatePath(n, 'newPath'); wrapCallback(function() { renameSync(o, n); }, cb, 'rename', _pathToString(o)); }
function copyFile(s, d, modeOrCb, cb) {
  var mode, callback;
  if (typeof modeOrCb === 'function') { callback = modeOrCb; } else { mode = modeOrCb; callback = cb; }
  _validateCallback(callback);
  _validatePath(s, 'src');
  _validatePath(d, 'dest');
  if (mode !== undefined && mode !== null) {
    _validateCopyFileMode(mode);
  }
  wrapCallback(function() { copyFileSync(s, d, mode); }, callback, 'copyfile', _pathToString(s));
}
function access(path, modeOrCb, cb) {
  var mode, callback;
  if (typeof modeOrCb === 'function') { callback = modeOrCb; } else { mode = modeOrCb; callback = cb; }
  _validateCallback(callback);
  _validatePath(path);
  if (mode !== undefined && mode !== null) _validateAccessMode(mode);
  wrapCallback(function() { accessSync(path, mode); }, callback, 'access', _pathToString(path));
}
function chmod(path, mode, cb) { _validateCallback(cb); _validatePath(path); wrapCallback(function() { chmodSync(path, mode); }, cb, 'chmod', _pathToString(path)); }
function realpath(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateCallback(callback);
  _validatePath(path);
  _validateEncodingOption(opts);
  wrapCallback(function() { return realpathSync(path, opts); }, callback, 'lstat', _pathToString(path));
}
realpath.native = function(path, callback) {
  _validateCallback(callback);
  _validatePath(path);
  wrapCallback(function() { return realpathSyncNative(path); }, callback, 'realpath', _pathToString(path));
};
function mkdtemp(prefix, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateCallback(callback);
  _validatePath(prefix, 'prefix');
  _validateEncodingOption(opts);
  wrapCallback(function() { return _mkdtempResult(prefix, opts).publicPath; }, callback, 'mkdtemp', prefix);
}
function mkdtempDisposable(prefix, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  _validateCallback(callback);
  _validatePath(prefix, 'prefix');
  _validateEncodingOption(opts);
  wrapCallback(function() {
    var tempResult = _mkdtempResult(prefix, opts);
    return _mkdtempDisposableFromPath(tempResult.publicPath, tempResult.actualPath, true);
  }, callback, 'mkdtemp', prefix);
}
function exists(path, cb) {
  _validateCallback(cb);
  _deferFsCallback(function() { try { cb(existsSync(path)); } catch(e) {} });
}

function openSync(path, flags, mode) {
  _validatePath(path);
  ensureExactFs();
  var p = _pathToString(path);
  var f = flags === undefined ? 'r' : flags;
  if (typeof f === 'number') {
    if (!Number.isFinite(f) || f % 1 !== 0 || f < 0 || f > 0x7fffffff) {
      var invalidNumErr = new TypeError('The value of \"flags\" is invalid. It must be a valid flags string. Received ' + JSON.stringify(f));
      invalidNumErr.code = 'ERR_INVALID_ARG_VALUE';
      throw invalidNumErr;
    }
  } else if (typeof f === 'string') {
    f = _parseFsOpenFlags(f);
  } else {
    var flagsErr = new TypeError('The value of \"flags\" is invalid. It must be a string or a number. Received ' + JSON.stringify(f));
    flagsErr.code = 'ERR_INVALID_ARG_VALUE';
    throw flagsErr;
  }
  var m;
  if (mode === undefined || mode === null) {
    m = 438; // 0o666
  } else if (typeof mode === 'number') {
    m = mode;
  } else if (typeof mode === 'string') {
    m = parseInt(mode, 8);
    if (isNaN(m)) {
      var err = new TypeError('The argument \'mode\' must be a 32-bit unsigned integer or an octal string. Received ' + JSON.stringify(mode));
      err.code = 'ERR_INVALID_ARG_VALUE';
      throw err;
    }
  } else {
    throw _fsInvalidArgType('mode', 'number', mode);
  }
  try { return g.__exactFsOpen(p, f, m); } catch(e) { throw _makeFsError(e, 'open', p); }
}

function closeSync(fd) {
  _validateFd(fd);
  ensureExactFs();
  try { g.__exactFsClose(fd); } catch(e) { throw _makeFsError(e, 'close'); }
}

function readSync(fd, buffer, offset, length, position) {
  ensureExactFs();
  _validateFd(fd);
  // Handle readSync(fd, buffer, options) form
  if (typeof offset === 'object' && offset !== null) {
    var ropts = offset;
    offset = ropts.offset === undefined ? 0 : ropts.offset;
    length = ropts.length;
    position = ropts.position;
  }
  if (!_isBufferLike(buffer)) {
    throw _fsInvalidArgType('buffer', 'Buffer, TypedArray, or DataView', buffer);
  }
  var targetBuffer = toUint8Array(buffer);
  var bufferLen = targetBuffer.length;
  if (bufferLen === 0) {
    throw _throwEmptyBufferError('buffer', buffer);
  }
  var off = _validateOffset('offset', offset === undefined || offset === null ? 0 : offset, bufferLen);
  var len = _validateReadSyncLength(length, bufferLen - off);
  var pos = _validateReadWritePosition('position', position);
  try {
    var data = g.__exactFsRead(fd, len, pos);
    if (buffer && data.length > 0) {
      if (typeof targetBuffer.set === 'function') {
        targetBuffer.set(data, off);
      } else {
        for (var i = 0; i < data.length; i++) {
          targetBuffer[off + i] = data[i];
        }
      }
    }
    return data.length;
  } catch(err) {
    throw _makeFsError(err, 'read');
  }
}

function writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position) {
  ensureExactFs();
  _validateFd(fd);
  // Handle writeSync(fd, buffer, options) form
  if (typeof bufferOrString !== 'string' && typeof offsetOrPosition === 'object' && offsetOrPosition !== null) {
    var wopts = offsetOrPosition;
    offsetOrPosition = wopts.offset === undefined ? 0 : wopts.offset;
    lengthOrEncoding = wopts.length;
    position = wopts.position;
  }
  if (typeof bufferOrString === 'string') {
    if (offsetOrPosition !== undefined && offsetOrPosition !== null && typeof offsetOrPosition !== 'number') {
      throw _fsInvalidArgType('position', 'bigint or integer', offsetOrPosition);
    }
    var pos = _validateReadWritePosition('position', offsetOrPosition);
    if (lengthOrEncoding !== undefined && lengthOrEncoding !== null && typeof lengthOrEncoding === 'string') {
      _assertEncoding(lengthOrEncoding);
    }
    var bytes = toUint8Array(bufferOrString, lengthOrEncoding);
    try {
      return g.__exactFsWrite(fd, bytes, pos);
    } catch(err) { throw _makeFsError(err, 'write'); }
  }
  if (!_isBufferLike(bufferOrString)) {
    throw _fsInvalidArgType('buffer', 'Buffer, TypedArray, or DataView', bufferOrString);
  }
  var bytesBuffer = toUint8Array(bufferOrString);
  var bufferLen = bytesBuffer.length;
  var off = _validateOffset('offset', offsetOrPosition === undefined || offsetOrPosition === null ? 0 : offsetOrPosition, bufferLen);
  var len = (typeof lengthOrEncoding === 'number') ? lengthOrEncoding : (bufferLen - off);
  if (typeof len === 'number') {
    if (!Number.isFinite(len) || len % 1 !== 0 || off + len > bufferLen || len < 0) {
      throw _fsOutOfRange('length', len, 0, bufferLen - off);
    }
  } else {
    len = bufferLen - off;
  }
  var pos = _validateReadWritePosition('position', position);
  var slice = bytesBuffer;
  if (off !== 0 || len !== bufferLen) {
    slice = bytesBuffer.subarray(off, off + len);
  }
  try {
    return g.__exactFsWrite(fd, slice, pos);
  } catch(err) { throw _makeFsError(err, 'write'); }
}

function _writeFileWithFlushCallback(target, data, writeOptions, isAppend, callback) {
  var p = target && target.path;
  var fd = target && target.fd;
  var bytes = toUint8Array(data, writeOptions && writeOptions.encoding);
  var done = function(err) {
    _deferFsCallback(function() { callback(err); });
  };

  if (fd !== null && fd !== undefined) {
    try {
      writeSync(fd, bytes, 0, bytes.length, -1);
    } catch(err) {
      done(_makeFsError(err, 'write', p));
      return;
    }
    if (writeOptions && writeOptions.flush === true) {
      _callFsync(fd, function(err) {
        done(err ? _makeFsError(err, 'fsync', p) : null);
      });
    } else {
      done(null);
    }
    return;
  }

  var flags = (writeOptions && (writeOptions.flag || writeOptions.flags)) || (isAppend ? 'a' : 'w');
  var fd = null;
  try {
    fd = openSync(p, flags, writeOptions && writeOptions.mode);
  } catch(err) {
    done(_makeFsError(err, 'open', p));
    return;
  }

  try {
    writeSync(fd, bytes, 0, bytes.length, -1);
  } catch(err) {
    try { closeSync(fd); } catch(_ignore) {}
    done(_makeFsError(err, 'write', p));
    return;
  }

  if (writeOptions && writeOptions.flush === true) {
    _callFsync(fd, function(err) {
      if (err) {
        try { closeSync(fd); } catch(_ignore) {}
        done(_makeFsError(err, 'fsync', p));
        return;
      }
      try {
        closeSync(fd);
      } catch(closeErr) {
        done(_makeFsError(closeErr, 'close', p));
        return;
      }
      done(null);
    });
    return;
  }

  try {
    closeSync(fd);
  } catch(closeErr) {
    done(_makeFsError(closeErr, 'close', p));
    return;
  }
  done(null);
}

function readvSync(fd, buffers, position) {
  _validateFd(fd);
  if (!Array.isArray(buffers)) {
    throw _fsInvalidArgType('buffers', 'Array', buffers);
  }
  for (var i = 0; i < buffers.length; i++) {
    if (!_isBufferLike(buffers[i])) {
      throw _fsInvalidArgType('buffers[' + i + ']', 'string or an instance of Buffer, TypedArray, or DataView', buffers[i]);
    }
  }
  if (position !== undefined && position !== null && typeof position !== 'number') {
    throw _fsInvalidArgType('position', 'number', position);
  }
  if (typeof g.__exactFsReadv === 'function') {
    try {
      var pos = (typeof position === 'number') ? position : -1;
      return g.__exactFsReadv(fd, buffers, pos);
    } catch(err) {
      throw _makeFsError(err, 'readv');
    }
  }
  if (buffers.length === 0) return 0;
  var pos = (typeof position === 'number') ? position : -1;
  var bytesRead = 0;
  for (var i = 0; i < buffers.length; i++) {
    var buffer = buffers[i];
    if (!Buffer.isBuffer(buffer) && !(buffer instanceof Uint8Array)) {
      throw _fsInvalidArgType('buffers[' + i + ']', 'string or an instance of Buffer, TypedArray, or DataView', buffer);
    }
    var currentPos = (pos === -1) ? -1 : (pos + bytesRead);
    var read = readSync(fd, buffer, 0, buffer.length, currentPos);
    bytesRead += read;
    if (read < buffer.length) break;
  }
  return bytesRead;
}

function writevSync(fd, buffers, position) {
  _validateFd(fd);
  if (!Array.isArray(buffers)) {
    throw _fsInvalidArgType('buffers', 'Array', buffers);
  }
  for (var i = 0; i < buffers.length; i++) {
    if (!_isBufferLike(buffers[i])) {
      throw _fsInvalidArgType('buffers[' + i + ']', 'string or an instance of Buffer, TypedArray, or DataView', buffers[i]);
    }
  }
  if (position !== undefined && position !== null && typeof position !== 'number') {
    throw _fsInvalidArgType('position', 'number', position);
  }
  if (typeof g.__exactFsWritev === 'function' && typeof position === 'number') {
    try {
      var pos = position;
      return g.__exactFsWritev(fd, buffers, pos);
    } catch(err) {
      throw _makeFsError(err, 'writev');
    }
  }
  if (buffers.length === 0) return 0;
  var pos = (typeof position === 'number') ? position : -1;
  var bytesWritten = 0;
  for (var i = 0; i < buffers.length; i++) {
    var buffer = buffers[i];
    if (!Buffer.isBuffer(buffer) && !(buffer instanceof Uint8Array)) {
      throw _fsInvalidArgType('buffers[' + i + ']', 'string or an instance of Buffer, TypedArray, or DataView', buffer);
    }
    var currentPos = (pos === -1) ? -1 : (pos + bytesWritten);
    var written = writeSync(fd, buffer, 0, buffer.length, currentPos);
    bytesWritten += written;
  }
  return bytesWritten;
}

function readv(fd, buffers, position, callback) {
  if (typeof position === 'function') {
    callback = position;
    position = undefined;
  }
  _validateFd(fd);
  _validateCallback(callback);
  if (position !== undefined && position !== null && typeof position !== 'number') {
    throw _fsInvalidArgType('position', 'number', position);
  }
  if (!Array.isArray(buffers)) {
    throw _fsInvalidArgType('buffers', 'Array', buffers);
  }
  for (var i = 0; i < buffers.length; i++) {
    var buffer = buffers[i];
    if (!_isBufferLike(buffer)) {
      throw _fsInvalidArgType('buffers[' + i + ']', 'string or an instance of Buffer, TypedArray, or DataView', buffer);
    }
  }
  try {
    if (typeof g.__exactFsReadv === 'function') {
      var pos = (typeof position === 'number') ? position : -1;
      g.__exactFsReadv(fd, buffers, pos, function(err, bytesRead) {
        _deferFsCallback(function() {
          if (err) {
            callback(_makeFsError(err, 'readv'));
          } else {
            callback(null, bytesRead, buffers);
          }
        });
      });
      return;
    }
    var bytesRead = readvSync(fd, buffers, position);
    _deferFsCallback(function() { callback(null, bytesRead, buffers); });
  } catch(err) {
    var error = _makeFsError(err, 'readv');
    _deferFsCallback(function() { callback(error); });
  }
}

function writev(fd, buffers, position, callback) {
  if (typeof position === 'function') {
    callback = position;
    position = undefined;
  }
  _validateFd(fd);
  _validateCallback(callback);
  if (position !== undefined && position !== null && typeof position !== 'number') {
    throw _fsInvalidArgType('position', 'number', position);
  }
  if (!Array.isArray(buffers)) {
    throw _fsInvalidArgType('buffers', 'Array', buffers);
  }
  for (var i = 0; i < buffers.length; i++) {
    var buffer = buffers[i];
    if (!_isBufferLike(buffer)) {
      throw _fsInvalidArgType('buffers[' + i + ']', 'string or an instance of Buffer, TypedArray, or DataView', buffer);
    }
  }
  try {
  if (typeof g.__exactFsWritev === 'function' && typeof position === 'number') {
    var pos = position;
    g.__exactFsWritev(fd, buffers, pos, function(err, bytesWritten) {
      _deferFsCallback(function() {
        if (err) {
          callback(_makeFsError(err, 'writev'));
        } else {
            callback(null, bytesWritten, buffers);
          }
        });
      });
      return;
    }
    var bytesWritten = writevSync(fd, buffers, position);
    _deferFsCallback(function() { callback(null, bytesWritten, buffers); });
  } catch(err) {
    var error = _makeFsError(err, 'writev');
    _deferFsCallback(function() { callback(error); });
  }
}

function open(path, flagsOrCb, modeOrCb, cb) {
  var flags, mode, callback;
  if (typeof flagsOrCb === 'function') { callback = flagsOrCb; flags = 'r'; mode = 438; }
  else if (typeof modeOrCb === 'function') { callback = modeOrCb; flags = flagsOrCb; mode = 438; }
  else { callback = cb; flags = flagsOrCb; mode = modeOrCb; }
  _validateCallback(callback);
  _validatePath(path);
  // Validate mode synchronously (Node.js throws for invalid modes before async)
  if (mode !== undefined && mode !== null && mode !== 438) {
    if (typeof mode === 'string') {
      var parsed = parseInt(mode, 8);
      if (isNaN(parsed)) {
        var err = new TypeError('The argument \'mode\' must be a 32-bit unsigned integer or an octal string. Received ' + JSON.stringify(mode));
        err.code = 'ERR_INVALID_ARG_VALUE';
        throw err;
      }
    } else if (typeof mode !== 'number') {
      throw _fsInvalidArgType('mode', 'number', mode);
    }
  }
  wrapCallback(function() { return openSync(path, flags, mode); }, callback, 'open', _pathToString(path));
}

function close(fd, cb) {
  if (typeof cb === 'function') {
    wrapCallback(function() { closeSync(fd); }, cb, 'close');
  } else if (cb !== undefined) {
    _validateCallback(cb);
  } else {
    closeSync(fd);
  }
}

function fsRead(fd, buffer, offset, length, position, cb) {
  // Support fs.read(fd, callback)
  if (typeof buffer === 'function') {
    cb = buffer;
    buffer = Buffer.alloc(16384);
    offset = 0;
    length = buffer.length;
    position = -1;
  }
  // Support fs.read(fd, options, callback)
  else if (typeof buffer === 'object' && buffer !== null && !Buffer.isBuffer(buffer) && !(buffer instanceof Uint8Array)) {
    var opts = buffer;
    cb = offset;
    buffer = opts.buffer || Buffer.alloc(16384);
    offset = opts.offset || 0;
    length = opts.length !== undefined ? opts.length : (buffer.length - offset);
    position = opts.position !== undefined ? opts.position : -1;
  }
  // Support fs.read(fd, buffer, options, callback)
  else if (typeof offset === 'object' && offset !== null) {
    var readOpts = offset;
    cb = typeof length === 'function' ? length : position;
    offset = readOpts.offset || 0;
    length = readOpts.length !== undefined ? readOpts.length : (buffer ? buffer.length - offset : 0);
    position = readOpts.position !== undefined ? readOpts.position : -1;
  }
  // Handle various callback positions
  if (typeof offset === 'function') {
    cb = offset;
    if (!buffer) buffer = Buffer.alloc(16384);
    offset = 0; length = buffer.length; position = -1;
  }
  else if (typeof length === 'function') { cb = length; length = buffer ? buffer.length - (offset || 0) : 0; position = -1; }
  else if (typeof position === 'function') { cb = position; position = -1; }
  _validateCallback(cb);
  try {
    var bytesRead = readSync(fd, buffer, offset, length, position);
    _deferFsCallback(function() { cb(null, bytesRead, buffer); });
  } catch(err) {
    if (err && typeof err.code === 'string' && err.code.indexOf('ERR_') === 0) {
      throw err;
    }
    var error = _makeFsError(err, 'read');
    _deferFsCallback(function() { cb(error); });
  }
}

function fsWrite(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position, cb) {
  // Determine which call signature is being used:
  // 1. fs.write(fd, buffer[, offset[, length[, position]]], callback)
  // 2. fs.write(fd, string[, position[, encoding]], callback)
  // 3. fs.write(fd, buffer, options, callback) -- options is an object with offset/length/position

  // First, figure out which argument is the callback
  if (typeof position === 'function') {
    cb = position;
    position = undefined;
  } else if (typeof lengthOrEncoding === 'function') {
    // Could be: (fd, buffer, options, cb) or (fd, string, position, cb) or (fd, buffer, offset, cb)
    if (typeof offsetOrPosition === 'number' || typeof offsetOrPosition === 'undefined') {
      // (fd, buffer, offset, cb) or (fd, string, position, cb)
      cb = lengthOrEncoding;
      lengthOrEncoding = undefined;
      position = undefined;
    } else {
      // (fd, buffer, options, cb) where options may be valid object or invalid type
      cb = lengthOrEncoding;
      if (typeof offsetOrPosition === 'object' && offsetOrPosition !== null) {
        var wopts = offsetOrPosition;
        offsetOrPosition = wopts.offset;
        lengthOrEncoding = wopts.length;
        position = wopts.position;
      } else {
        // Invalid options type - will be validated below
        // Keep offsetOrPosition as-is; it will fail type validation
        lengthOrEncoding = undefined;
        position = undefined;
      }
    }
  } else if (typeof offsetOrPosition === 'function') {
    cb = offsetOrPosition;
    offsetOrPosition = typeof bufferOrString === 'string' ? undefined : 0;
    lengthOrEncoding = typeof bufferOrString === 'string' ? undefined : (bufferOrString ? bufferOrString.length : 0);
    position = undefined;
  }

  // Validate buffer/string argument
  if (typeof bufferOrString !== 'string' && !Buffer.isBuffer(bufferOrString) && !(bufferOrString instanceof Uint8Array) && !ArrayBuffer.isView(bufferOrString)) {
    throw _fsInvalidArgType('buffer', 'string or an instance of Buffer or Uint8Array', bufferOrString);
  }
  _validateCallback(cb);

  // For buffer writes, validate offset/length/position
  if (typeof bufferOrString !== 'string') {
    var bufLen = _bufferLikeLength(bufferOrString);
    var off = offsetOrPosition !== undefined && offsetOrPosition !== null ? offsetOrPosition : 0;
    var len = lengthOrEncoding !== undefined && lengthOrEncoding !== null ? lengthOrEncoding : (bufLen - off);

    // Validate types
    if (typeof off !== 'number') {
      throw _fsInvalidArgType('offset', 'number', off);
    }
    if (typeof len !== 'number') {
      // length can be implicit
    }

    // Validate ranges
    if (off < 0 || off > bufLen) {
      throw _fsOutOfRange('offset', off, 0, bufLen);
    }
    if (typeof len === 'number' && (len < 0 || off + len > bufLen)) {
      throw _fsOutOfRange('length', len, 0, bufLen - off);
    }
  }
  try {
    var written = writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position);
    _deferFsCallback(function() { cb(null, written, bufferOrString); });
  } catch(err) {
    if (err && typeof err.code === 'string' && err.code.indexOf('ERR_') === 0) {
      throw err;
    }
    var error = _makeFsError(err, 'write');
    _deferFsCallback(function() { cb(error); });
  }
}

function createReadStream(path, options) {
  return new ReadStream(path, options);
}

function ReadStream(path, options) {
  var Stream = require('node:stream');
  if (!(this instanceof Stream.Readable)) {
    return new ReadStream(path, options);
  }
  return _initReadStream(this, path, options);
}

ReadStream.prototype = Object.create(require('node:stream').Readable.prototype);
ReadStream.prototype.constructor = ReadStream;

function _initReadStream(rs, path, options) {
  if (options !== undefined && options !== null && typeof options !== 'string' && typeof options !== 'object') {
    throw _fsInvalidArgType('options', 'string or an object', options);
  }
  _validateEncodingOption(options);
  ensureExactFs();
  var Stream = require('node:stream');
  var opts = typeof options === 'string' ? { encoding: options } : (options || {});
  var fsModule = opts.fs || require('fs');
  var useNativeFs = opts.fs === undefined && _nativeFs !== null && fsModule === _nativeFs &&
    fsModule.open === _nativeFsOpen && fsModule.close === _nativeFsClose;
  _validateFsOptions('options.fs', opts.fs, ['open', 'close', 'read']);
  var encoding = opts.encoding || null;
  var start = 0;
  var end = opts.end;

  if (opts.start !== undefined) {
    if (typeof opts.start !== 'number') throw _fsInvalidArgType('start', 'number', opts.start);
    _validateInt('start', opts.start, 0, Number.MAX_SAFE_INTEGER);
    start = opts.start;
  }
  if (end !== undefined) {
    if (typeof end !== 'number') throw _fsInvalidArgType('end', 'number', end);
    if (end !== Infinity) {
      _validateInt('end', end, 0, Number.MAX_SAFE_INTEGER);
    }
  }
  if (end !== undefined && end !== Infinity && start > end) {
    var startAfterEnd = _fsOutOfRange('start', start, 0, end);
    startAfterEnd.message = 'The value of "start" is out of range. It must be <= "end" (here: ' + end + '). Received ' + start;
    throw startAfterEnd;
  }
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

  if (!rs._exactReadStreamInitialized) {
    Stream.Readable.call(rs, {
      highWaterMark: highWaterMark,
      autoDestroy: autoClose,
      emitClose: autoClose
    });
    rs._exactReadStreamInitialized = true;
  }
  if (encoding) {
    rs.setEncoding(encoding);
  }
  rs.path = ((fdOption === undefined || fdOption === null) || path !== null && path !== undefined) ? path : undefined;
  rs.start = start;
  rs.end = end;
  rs.autoClose = autoClose;
  rs.readable = true;
  rs.bytesRead = 0;
  rs.closed = false;
  rs.destroyed = false;
  rs.fd = null;
  rs.pending = true;
  rs._position = start;
  rs._end = end;
  rs._autoClose = autoClose;
  function closeOpenDescriptor(fdToClose, callback) {
    if (typeof fdToClose !== 'number') {
      if (typeof callback === 'function') _deferFsCallback(callback);
      return;
    }
    var closeSyncFn = typeof fsModule.closeSync === 'function' ? fsModule.closeSync : closeSync;
    var closeFn = typeof fsModule.close === 'function' ? fsModule.close : null;
    var done = function() {
      rs._openFd = null;
      rs.fd = null;
      if (typeof callback === 'function') _deferFsCallback(callback);
    };
    try {
      if (typeof closeFn === 'function') {
        closeFn.call(fsModule, fdToClose, function() { done(); });
        return;
      }
      if (typeof closeSyncFn === 'function') {
        closeSyncFn(fdToClose);
        done();
        return;
      }
    } catch (e) {}
    done();
  }

  function closeFd() {
    if (rs.closed) return;
    rs.destroyed = true;
    rs.closed = true;
    var afterClose = function() {
      rs.fd = null;
      rs.emit('close');
    };
    if (!sourceIsHandle) {
      if (typeof rs._openFd === 'number' && rs._shouldAutoClose) {
        closeOpenDescriptor(rs._openFd, afterClose);
        return;
      }
    } else if (sourceHandle && typeof sourceHandle.close === 'function') {
      try {
        var handleCloseResult = sourceHandle.close();
        if (handleCloseResult && typeof handleCloseResult.then === 'function') {
          handleCloseResult.then(afterClose, afterClose);
          return;
        }
      } catch (e) {}
      afterClose();
      return;
    }
    afterClose();
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
    if (sourceIsHandle || sourceFd !== null) {
      rs._opening = false;
      return;
    }
    try {
      var openSyncFn = typeof fsModule.openSync === 'function' ? fsModule.openSync : openSync;
      var openFn = typeof fsModule.open === 'function' ? fsModule.open : null;
      if (!openFn && !openSyncFn) {
        throw new Error('open is not a function');
      }
      if (openFn) {
        openFn.call(fsModule, path, opts.flags || 'r', opts.mode || 438, function(err, fd) {
          rs._opening = false;
          if (err) {
            rs.emit('error', _makeFsError(err, 'open', path));
            if (autoClose) closeFd();
            return;
          }
          if (rs.closed || rs.destroyed) {
            if (typeof fd === 'number' && rs._shouldAutoClose) {
              closeOpenDescriptor(fd);
            }
            return;
          }
          rs._openFd = fd;
          rs._opened = true;
          rs._shouldAutoClose = rs._autoClose;
          rs.fd = rs._openFd;
          rs.emit('open', rs._openFd);
          markReady();
          rs._read();
        });
        return;
      }
      rs._openFd = openSyncFn(path, opts.flags || 'r', opts.mode || 438);
        if (rs.closed || rs.destroyed) {
          closeOpenDescriptor(rs._openFd);
          rs._opened = false;
          rs._opening = false;
          return;
        }
      rs._opened = true;
      rs._shouldAutoClose = rs._autoClose;
      rs.fd = rs._openFd;
      rs.emit('open', rs._openFd);
      markReady();
      rs._read();
    } catch(err) {
      rs._opening = false;
      rs.emit('error', err);
      if (autoClose) closeFd();
      return;
    }
    rs._opening = false;
  }

    if (!rs._opened && rs._shouldAutoClose) {
      _deferFsCallback(ensureOpen);
  }

  rs._read = function() {
    if (rs.destroyed || rs.closed) return;
    if (typeof rs._reading === 'boolean' && rs._reading) return;
    rs._reading = true;
    try {
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
        var shouldContinue = encoding ? rs.push(decodeBytes(chunk, encoding)) : rs.push(wrapBuffer(chunk));
        if (bytesRead < chunkSize) {
          rs.push(null);
          if (autoClose) closeFd();
          return;
        }
        if (shouldContinue && !rs.destroyed && !rs.closed) {
          _deferFsCallback(function() {
            rs._read();
          });
        }
      };

      if (sourceIsHandle && sourceHandle && typeof sourceHandle.read === 'function') {
        sourceHandle.read(buf, 0, chunkSize, rs._position, readDone);
      } else {
        var readFn = typeof fsModule.read === 'function' ? fsModule.read : fsRead;
        var readArgs = [rs.fd, buf, 0, chunkSize, rs._position];
        readFn.apply(fsModule, readArgs.concat(readDone));
      }
  } catch(err) {
    rs.emit('error', err);
      if (autoClose) closeFd();
    }
  };
  rs.open = function() {
    if (rs._opened || rs._opening || rs.closed) return rs;
    ensureOpen();
    return rs;
  };
  rs.close = function() {
    if (!rs.closed) {
      rs.destroyed = true;
      closeFd();
    }
  };
  rs.destroy = function() {
    if (rs.destroyed) return rs;
    rs.destroyed = true;
    closeFd();
    return rs;
  };
  rs.on('error', function() {
    if (!autoClose) return;
    rs.destroyed = true;
    closeFd();
  });
  if (sourceIsHandle && sourceHandle && typeof sourceHandle.on === 'function') {
    sourceHandle.on('close', rs.close);
  }

  return rs;
}

function createWriteStream(path, options) {
  return new WriteStream(path, options);
}

function WriteStream(path, options) {
  var Stream = require('node:stream');
  if (!(this instanceof Stream.Writable)) {
    return new WriteStream(path, options);
  }
  return _initWriteStream(this, path, options);
}

WriteStream.prototype = Object.create(require('node:stream').Writable.prototype);
WriteStream.prototype.constructor = WriteStream;

function _initWriteStream(ws, path, options) {
  var opts = _normalizeWriteOptions(options);
  _validateEncodingOption(opts);
  _validateFlushOption(opts.flush);
  ensureExactFs();
  var Stream = require('node:stream');
  var fsModule = opts.fs || require('fs');
  _validateFsOptions('options.fs', opts.fs, ['open', 'close', 'write', 'writev']);
  var flags = opts.flags || 'w';
  var mode = opts.mode || 438;
  var encoding = opts.encoding || 'utf8';
  var autoClose = opts.autoClose !== false;
  var start = null;
  var openError = null;
  var fdOption = opts.fd;
  var fd = null;
  var opened = false;
  var opening = false;
  var fileHandle = null;
  var usingHandle = false;
  var pendingWrites = [];
  var processingWrite = false;

  if (opts.start !== undefined) {
    if (typeof opts.start !== 'number') throw _fsInvalidArgType('start', 'number', opts.start);
    _validateInt('start', opts.start, 0, Number.MAX_SAFE_INTEGER);
    start = opts.start;
  }

  if (fdOption !== undefined && fdOption !== null) {
    if (typeof fdOption === 'number') {
      fd = fdOption;
      opened = true;
      if (typeof _validateFd === 'function') _validateFd(fd);
    } else if (typeof fdOption === 'object' && typeof fdOption.fd === 'number') {
      fd = fdOption.fd;
      opened = true;
      fileHandle = fdOption;
      usingHandle = true;
      if (typeof _validateFd === 'function') _validateFd(fd);
    } else {
      throw _fsInvalidArgType('fd', 'number', fdOption);
    }
  } else {
    _validatePath(path, 'path');
  }

  if (!ws._exactWriteStreamInitialized) {
    Stream.Writable.call(ws, { emitClose: autoClose });
    ws._exactWriteStreamInitialized = true;
  }
  if (encoding) {
    ws.setDefaultEncoding(encoding);
  }
  ws.path = path;
  ws.fd = fd;
  ws.closed = false;
  ws._closed = false;
  ws.destroyed = false;
  ws.pending = !opened;
  ws.bytesWritten = 0;
  ws._encoding = encoding;
  ws._shouldAutoClose = autoClose;
  ws._shouldWriteAt = typeof start === 'number' ? start : null;
  ws._readyEmitted = false;
  ws._flush = opts.flush === true;
  ws._writeErrorClosed = false;

  ws._emitClose = function() {
    if (ws.closed || ws._closed) return;
    ws.closed = true;
    ws._closed = true;
    ws.fd = null;
    ws.emit('close');
  };

  function closeWriteFd(callback) {
    if (!autoClose || fd === null) {
      if (typeof callback === 'function') _deferFsCallback(callback);
      return;
    }
    var closeSyncFn = typeof fsModule.closeSync === 'function' ? fsModule.closeSync : closeSync;
    var closeFn = typeof fsModule.close === 'function' ? fsModule.close : null;
    var done = function(err) {
      var closeErr = err ? _makeFsError(err, 'close', path) : null;
      fd = null;
      ws.fd = null;
      if (typeof callback === 'function') {
        _deferFsCallback(function() { callback(closeErr); });
      }
    };

    if (usingHandle && fileHandle && typeof fileHandle.close === 'function') {
      try {
        var handleCloseResult = fileHandle.close();
        if (handleCloseResult && typeof handleCloseResult.then === 'function') {
          handleCloseResult.then(function() { done(); }, function(err) { done(err); });
          return;
        }
      } catch (_ignore) {
        try {
          if (typeof closeSyncFn === 'function') closeSyncFn(fd);
        } catch (_ignored) {}
      }
      done();
      return;
    }

    try {
      if (typeof closeFn === 'function') {
        closeFn.call(fsModule, fd, function(err) { done(err); });
        return;
      }
      if (typeof closeSyncFn === 'function') {
        closeSyncFn(fd);
        done();
      } else {
        done();
      }
    } catch (err) {
      done(err);
    }
  }

function makeWriteError(err, operation) {
    if (!err) {
      return _makeFsError(new Error((operation || 'write') + ' failed'), operation || 'write', path);
    }
    if (typeof err.code === 'string') {
      if (err.code === 'ABORT_ERR' || err.code.indexOf('ERR_STREAM_') === 0) {
        return err;
      }
      return _makeFsError(err, operation || 'write', path);
    }
    if (err instanceof Error) {
      return err;
    }
    return _makeFsError(err, operation || 'write', path);
  }

function emitWriteError(err, callback, operation) {
    var writeErr = makeWriteError(err, operation);
    if (ws._writableState) {
      ws._writableState.autoDestroy = false;
    }
    if (!ws._writeErrorClosed && autoClose) {
      ws._writeErrorClosed = true;
      closeWriteFd(function(closeErr) {
        if (closeErr) {
          ws.emit('error', closeErr);
        }
        ws._emitClose();
        if (typeof callback === 'function') {
          callback(writeErr);
        }
        ws.emit('error', writeErr);
      });
      return;
    }
    if (typeof callback === 'function') {
      callback(writeErr);
    }
    ws.emit('error', writeErr);
  }

  function normalizeWritePosition() {
    return typeof ws._shouldWriteAt === 'number' ? ws._shouldWriteAt : null;
  }

  function failPendingWrites(err) {
    var next;
    while ((next = pendingWrites.shift())) {
      emitWriteError(err, next.callback, 'open');
    }
    processingWrite = false;
  }

  function setOpened(newFd) {
    openError = null;
    if (!opened && typeof _validateFd === 'function') _validateFd(newFd);
    opened = true;
    opening = false;
    fd = newFd;
    ws.fd = fd;
    if (typeof start === 'number') {
      ws._shouldWriteAt = start;
    }
    ws.emit('open', fd);
    if (!ws._readyEmitted) {
      ws._readyEmitted = true;
      ws.pending = false;
      ws.emit('ready');
    }
    drainPendingWrites();
  }

  function ensureOpen() {
    if (opened || ws.closed || ws.destroyed || opening) return;
    var openSyncFn = typeof fsModule.openSync === 'function' ? fsModule.openSync : openSync;
    var openFn = typeof fsModule.open === 'function' ? fsModule.open : null;
    if (!fdOption && !openFn && !openSyncFn) {
      var openFnError = makeWriteError(new Error('open is not a function'), 'open');
      openError = openFnError;
      ws.emit('error', openFnError);
      failPendingWrites(openFnError);
      return;
    }
    opening = true;
    if (openFn) {
      openFn.call(fsModule, path, flags, mode, function(err, openedFd) {
        if (err) {
          opening = false;
          openError = makeWriteError(err, 'open');
          failPendingWrites(err);
          ws.emit('error', openError);
          return;
        }
        setOpened(openedFd);
      });
      return;
    }
    try {
      setOpened(openSyncFn.call(fsModule, path, flags, mode));
    } catch(err) {
      opening = false;
      openError = makeWriteError(err, 'open');
      failPendingWrites(err);
      ws.emit('error', openError);
    }
  }

  function performWrite(chunk, enc, callback) {
    var bytes = toUint8Array(chunk, enc || encoding);
    var position = normalizeWritePosition();
    var writeSyncFn = typeof fsModule.writeSync === 'function' ? fsModule.writeSync : writeSync;
    var writeFn = typeof fsModule.write === 'function' ? fsModule.write : null;
    var done = function(err, written) {
      if (err) {
        emitWriteError(err, callback, 'write');
        return;
      }
      var writtenBytes = typeof written === 'number' ? written : bytes.length;
      if (typeof position === 'number') {
        ws._shouldWriteAt += writtenBytes;
      }
      ws.bytesWritten += writtenBytes;
      if (typeof callback === 'function') callback();
    };

    if (usingHandle && fileHandle && typeof fileHandle.write === 'function') {
      try {
        var handleResult = fileHandle.write(bytes, 0, bytes.length, position);
        if (handleResult && typeof handleResult.then === 'function') {
          handleResult.then(function(result) {
            if (typeof result === 'object' && result !== null && typeof result.bytesWritten === 'number') {
              done(null, result.bytesWritten);
              return;
            }
            done(null, bytes.length);
          }).catch(function(err) {
            done(err);
          });
          return;
        }
        if (typeof handleResult === 'number') {
          done(null, handleResult);
        } else {
          done();
        }
        return;
      } catch(err) {
        done(err);
      }
      return;
    }

    if (typeof writeFn === 'function') {
      try {
        writeFn.call(fsModule, fd, bytes, 0, bytes.length, position, function(err, written) {
          done(err, written);
        });
      } catch(err) {
        done(err);
      }
      return;
    }

    try {
      var written = writeSyncFn.call(fsModule, fd, bytes, 0, bytes.length, position === null ? -1 : position);
      done(null, written);
    } catch(err) {
      done(err);
    }
  }

  function buffersFromChunks(chunks) {
    var buffers = new Array(chunks.length);
    for (var i = 0; i < chunks.length; i++) {
      var chunk = chunks[i];
      buffers[i] = toUint8Array(chunk.chunk, chunk.encoding || encoding);
    }
    return buffers;
  }

  function sumBufferLengths(buffers) {
    var total = 0;
    for (var i = 0; i < buffers.length; i++) {
      total += buffers[i].length;
    }
    return total;
  }

  function performWritev(chunks, callback) {
  var buffers = buffersFromChunks(chunks);
  var position = normalizeWritePosition();
    var writeSyncFn = typeof fsModule.writeSync === 'function' ? fsModule.writeSync : writeSync;
    var done = function(err, written) {
      if (err) {
        emitWriteError(err, callback, 'writev');
        return;
      }
      var writtenBytes = typeof written === 'number' ? written : sumBufferLengths(buffers);
      if (typeof position === 'number') {
        ws._shouldWriteAt += writtenBytes;
      }
      ws.bytesWritten += writtenBytes;
      if (typeof callback === 'function') callback();
    };

    try {
      var writtenTotal = 0;
      for (var i = 0; i < buffers.length; i++) {
        var buf = buffers[i];
        var currentOffset = position === null ? -1 : position + writtenTotal;
        writtenTotal += writeSyncFn.call(fsModule, fd, buf, 0, buf.length, currentOffset);
      }
      done(null, writtenTotal);
    } catch(err) {
      done(err);
    }
  }

  function drainPendingWrites() {
    if (processingWrite || !opened || ws.closed || ws.destroyed) return;
    var next = pendingWrites.shift();
    if (!next) {
      return;
    }
    processingWrite = true;
    var finishWrite = function(err) {
      processingWrite = false;
      if (typeof next.callback === 'function') next.callback(err);
      drainPendingWrites();
    };
    if (next.type === 'write') {
      performWrite(next.chunk, next.encoding, finishWrite);
      return;
    }
    performWritev(next.chunks, finishWrite);
  }

  function enqueueWrite(type, payload, callback) {
    if (ws.closed || ws._closed) {
      var closedErr = new Error('write after end');
      closedErr.code = 'ERR_STREAM_WRITE_AFTER_END';
      if (ws._writableState) {
        ws._writableState.autoDestroy = false;
        ws._writableState.errored = closedErr;
        ws._writableState.errorEmitted = true;
      }
      ws.errored = closedErr;
      if (typeof callback === 'function') {
        _deferFsCallback(function() {
          callback(closedErr);
        });
      }
      return;
    }
    if (ws.destroyed) {
      var destroyedErr = new Error('Cannot call write after a stream was destroyed');
      destroyedErr.code = 'ERR_STREAM_DESTROYED';
      if (ws._writableState) {
        ws._writableState.autoDestroy = false;
        ws._writableState.errored = destroyedErr;
        ws._writableState.errorEmitted = true;
      }
      ws.errored = destroyedErr;
      if (typeof callback === 'function') {
        _deferFsCallback(function() {
          callback(destroyedErr);
        });
      }
      return;
    }
    pendingWrites.push({
      type: type,
      chunk: payload && payload.chunk ? payload.chunk : null,
      encoding: payload && payload.encoding,
      chunks: payload && payload.chunks ? payload.chunks : null,
      callback: callback
    });
    if (!opened) {
      if (!opening) ensureOpen();
      return;
    }
    if (!processingWrite) {
      drainPendingWrites();
    }
  }

  if (!opened && !fdOption) {
    _deferFsCallback(ensureOpen);
  } else if (opened && !ws._readyEmitted) {
    ws._readyEmitted = true;
    ws.pending = false;
    ws.emit('ready');
  }

  ws._write = function(chunk, enc, callback) {
    enqueueWrite('write', { chunk: chunk, encoding: enc }, callback);
  };

  ws._writev = function(chunks, callback) {
    enqueueWrite('writev', { chunks: chunks }, callback);
  };

  ws._final = function(callback) {
    if (typeof callback !== 'function') {
      callback = function() {};
    }
    var finish = function(err) {
      if (err) {
        callback(err);
        return;
      }
      if (autoClose) {
        closeWriteFd(function(closeErr) {
          if (closeErr) {
            callback(closeErr);
            return;
          }
          ws._emitClose();
          callback();
        });
        return;
      }
      callback();
    };
    var flushAndClose = function() {
      if (!autoClose || !ws._flush || typeof fd !== 'number') {
        finish();
        return;
      }
      _callFsync(fd, function(err) {
        if (err) {
          callback(err);
          return;
        }
        finish();
      });
    };

    if (!opened && !fdOption) {
      ensureOpen();
      var waitForOpen = function() {
        if (opening) {
          _deferFsCallback(waitForOpen);
          return;
        }
        if (openError) {
          callback(openError);
          return;
        }
        if (processingWrite) {
          _deferFsCallback(waitForOpen);
          return;
        }
        flushAndClose();
      };
      waitForOpen();
      return;
    }
    flushAndClose();
  };

  ws.destroy = function(err) {
    if (ws.destroyed) return ws;
    ws.destroyed = true;
    if (err) ws.emit('error', err);
    if (autoClose) {
      closeWriteFd(function() {
        ws._emitClose();
      });
    } else {
      ws._emitClose();
    }
    return ws;
  };

  ws.open = function() {
    if (opened) {
      if (!ws._readyEmitted) {
        ws._readyEmitted = true;
        ws.pending = false;
        ws.emit('ready');
      }
      return ws;
    }
    ensureOpen();
    return ws;
  };

  ws.close = function(callback) {
    if (typeof callback === 'function') {
      if (ws.closed || ws._closed) {
        _deferFsCallback(callback);
        return ws;
      }
      ws.once('close', callback);
      if (!autoClose) {
        ws._emitClose();
      } else {
        closeWriteFd(function(err) {
          if (err) {
            ws.emit('error', err);
          }
          ws._emitClose();
        });
      }
      return ws;
    }
    if (autoClose && !ws.closed && !ws._closed) {
      closeWriteFd(function() {
        ws._emitClose();
      });
      return ws;
    }
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
FSWatcher.prototype.addListener = FSWatcher.prototype.on;
FSWatcher.prototype.emit = function(ev) { var a = [].slice.call(arguments, 1); var l = this._events[ev] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
FSWatcher.prototype.once = function(ev, fn) { var self = this; function w() { self.removeListener(ev, w); fn.apply(this, arguments); } w.listener = fn; this.on(ev, w); return this; };
FSWatcher.prototype.removeListener = function(ev, fn) { var l = this._events[ev]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn && l[i].listener !== fn) n.push(l[i]); } this._events[ev] = n; } return this; };
FSWatcher.prototype.off = function(ev, fn) { return this.removeListener(ev, fn); };
FSWatcher.prototype.close = function() {
  if (this._closed) return this;
  this._closed = true;
  if (this._onSignalAbort && this._signal && typeof this._signal.removeEventListener === 'function') {
    this._signal.removeEventListener('abort', this._onSignalAbort);
  }
  if (this._stop) this._stop();
  else if (this._timer) clearInterval(this._timer);
  this.emit('close');
  return this;
};
FSWatcher.prototype.stop = function() {
  if (this._stopped) return this;
  this._stopped = true;
  this.close();
  _deferFsCallback((function() {
    if (this._stopped) {
      this.emit('stop');
    }
  }).bind(this));
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
function relativePathFromCwd(path) {
  if (!_isAbsolutePath(path)) return path;
  var cwd = _resolvePathFromCwd('.');
  if (path === cwd) return '.';
  if (cwd === '/') return path.slice(1);
  if (path.indexOf(cwd + '/') === 0) return path.slice(cwd.length + 1);
  return path;
}
function _watchEventPath(filename, encoding, recursive) {
  if (filename === null || filename === undefined) return watchFilename(filename, encoding);
  return watchFilename(recursive ? filename : pathBasename(filename), encoding);
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
  var changed = false;
  if (!prevState) prevState = {};
  if (!nextState) nextState = {};
  for (var key in nextState) {
    if (key === '__meta') continue;
    if (!prevState[key]) {
      watcher.emit('change', 'rename', _watchEventPath(key, encoding, watcher._recursive));
      changed = true;
      continue;
    }
    if (!nextState[key].isDirectory && !prevState[key].isDirectory &&
        (nextState[key].mtime !== prevState[key].mtime || nextState[key].size !== prevState[key].size)) {
      watcher.emit('change', 'change', _watchEventPath(key, encoding, watcher._recursive));
      changed = true;
    }
  }
  for (var key2 in prevState) {
    if (key2 === '__meta') continue;
    if (!nextState[key2]) {
      watcher.emit('change', 'rename', _watchEventPath(key2, encoding, watcher._recursive));
      changed = true;
    }
  }
  return changed;
}
function makeZeroStats(bigint) {
  var s = !!bigint ? _makeBigIntStats({}) : new Stats({}, false);
  s.__exactExists = false;
  return s;
}

function watch(filename, options, listener) {
  if (typeof options === 'function') {
    listener = options;
    options = {};
  }
  options = _normalizeWatchOptions(options);
  if (listener && typeof listener !== 'function') _validateCallback(listener);
  _validatePath(filename, 'filename');
  var watcher = new FSWatcher();
  watcher._filename = _pathToString(filename);
  watcher._signal = options.signal;
  watcher._handle = {
    onchange: function(code, errorName, pathValue) {
      var errCode = errorName || _uvCodeFromErrno(code);
      var err = _makeFsError(
        {
          errno: code,
          code: typeof errCode === 'string' ? errCode : undefined,
          path: pathValue,
          filename: pathValue,
          syscall: 'watch'
        },
        'watch',
        pathValue
      );
      watcher.emit('error', err);
    }
  };
  watcher._onSignalAbort = function() {
    watcher.close();
  };
  if (watcher._signal && typeof watcher._signal.addEventListener === 'function') {
    watcher._signal.addEventListener('abort', watcher._onSignalAbort);
  }

  if (watcher._signal && watcher._signal.aborted === true) {
    _deferFsCallback(function() { watcher.close(); });
    return watcher;
  }

  var encoding = options.encoding || 'utf8';
  if (listener) watcher.on('change', listener);

  var stat;
  var targetIsDirectory = false;
  try {
    stat = statSync(watcher._filename);
    targetIsDirectory = !!(stat && stat.isDirectory && stat.isDirectory());
  } catch(e) {
    throw _makeFsError(e, 'watch', watcher._filename);
  }

  if (targetIsDirectory) {
    watcher._isDirectory = true;
    watcher._recursive = !!options.recursive;
    watcher._prevState = buildWatchDirState(watcher._filename, watcher._recursive);
    var directoryInterval = options.interval || 25;
    watcher._poll = function() {
      if (watcher._closed || watcher._stopped) return;
      var nextState = buildWatchDirState(watcher._filename, watcher._recursive);
      if (!nextState) {
        watcher.emit('change', 'rename', watchFilename(pathBasename(watcher._filename), encoding));
        watcher._prevState = {};
        return;
      }
      var changed = emitWatchDirectoryChanges(watcher, encoding, watcher._prevState, nextState);
      if (!changed && watcher._prevState && nextState.__meta && watcher._prevState.__meta &&
          nextState.__meta.mtime !== watcher._prevState.__meta.mtime) {
        watcher.emit('change', 'rename', null);
      }
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
    try { var s = stat || statSync(watcher._filename); lastMtime = s.mtimeMs || 0; } catch(e) {}
    var fileInterval = options.interval || 25;
    watcher._poll = function() {
      if (watcher._closed) return;
      try {
        var s2 = statSync(watcher._filename);
        var mtime = s2.mtimeMs || 0;
        if (mtime !== lastMtime) {
          lastMtime = mtime;
          watcher.emit('change', 'change', watchFilename(pathBasename(watcher._filename), encoding));
        }
      } catch(e) {
        if (lastMtime !== 0) {
          lastMtime = 0;
          watcher.emit('change', 'rename', watchFilename(pathBasename(watcher._filename), encoding));
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

function _promisesWatch(path, options) {
  options = _normalizeWatchFileOptions(path, options);
  var signal = options && options.signal;
  var syncWatcher = watch(path, options);
  var queue = [];
  var waiting = null;
  var closed = false;
  var abortError = null;

  function onChange(eventType, filename) {
    if (closed) return;
    var payload = { eventType: eventType, filename: filename };
    if (waiting) {
      var waitingNext = waiting;
      waiting = null;
      waitingNext(Promise.resolve({ done: false, value: payload }));
    } else {
      queue.push(payload);
    }
  }

  function closeWatch() {
    if (closed) return;
    closed = true;
    syncWatcher.removeListener('change', onChange);
    syncWatcher.close();
    if (waiting) {
      var pending = waiting;
      waiting = null;
      if (abortError) {
        pending(Promise.reject(abortError));
      } else {
        pending(Promise.resolve({ done: true }));
      }
    }
  }

  function onSignalAbort() {
    abortError = _makeAbortError(signal && signal.reason);
    closeWatch();
  }
  if (signal && typeof signal.addEventListener === 'function') {
    signal.addEventListener('abort', onSignalAbort);
  }

  syncWatcher.on('change', onChange);

  return {
    next: function() {
      if (closed) {
        if (abortError) {
          return Promise.reject(abortError);
        }
        return Promise.resolve({ done: true });
      }
      if (queue.length > 0) {
        return Promise.resolve({ done: false, value: queue.shift() });
      }
      return new Promise(function(resolve, reject) {
        waiting = function(nextValue) {
          Promise.resolve(nextValue).then(function(resolved) {
            resolve(resolved);
          }, function(rejected) {
            reject(rejected);
          });
        };
      });
    },
    return: function() {
      if (!closed) {
        closeWatch();
      }
      if (signal && typeof signal.removeEventListener === 'function') {
        signal.removeEventListener('abort', onSignalAbort);
      }
      return Promise.resolve({ done: true });
    },
    [Symbol.asyncIterator]: function() { return this; }
  };
}

var _watchedFiles = {};
function watchFile(filename, options, listener) {
  if (typeof options === 'function') { listener = options; options = {}; }
  options = options || {};
  options = _normalizeWatchFileOptions(filename, options);
  if (!listener) {
    throw _fsInvalidArgType('listener', 'function', listener);
  }
  if (typeof listener !== 'function') _validateCallback(listener);
  _validatePath(filename, 'filename');
  var resolvedFilename = _pathToString(filename);
  var statOptions = { bigint: options.bigint };
  var watcher = _watchedFiles[resolvedFilename];
  if (!watcher) {
    watcher = new FSWatcher();
    watcher._filename = resolvedFilename;
    watcher._listeners = [];
    watcher._initialized = false;
    watcher._hadInitialStat = false;
    watcher._timer = null;
    watcher._statOptions = statOptions;
    watcher._prev = makeZeroStats(watcher._statOptions.bigint);
    try {
      var prevStats = statSync(resolvedFilename, watcher._statOptions);
      watcher._prev = watcher._statOptions.bigint ? _makeBigIntStats(prevStats) : prevStats;
      watcher._prev.__exactExists = true;
      watcher._hadInitialStat = true;
    } catch(e) {
      watcher._prev.__exactExists = false;
    }
    var watchFileInterval = options.interval || 5007;
    watcher._poll = function() {
      if (watcher._closed || watcher._stopped) return;
      var curr;
      try {
        var rawCurr = statSync(resolvedFilename, watcher._statOptions);
        curr = watcher._statOptions.bigint ? _makeBigIntStats(rawCurr) : rawCurr;
        curr.__exactExists = true;
      } catch(e) {
        curr = makeZeroStats(watcher._statOptions.bigint);
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
    _watchedFiles[resolvedFilename] = watcher;
    if (!watcher._prev.__exactExists) {
      _deferFsCallback(function() {
        if (!watcher._closed) {
          watcher.emit('change', watcher._prev, watcher._prev);
        }
      });
    }
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
  var resolvedFilename = _pathToString(filename);
  var watcher = _watchedFiles[resolvedFilename];
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
      delete _watchedFiles[resolvedFilename];
    }
    return;
  }
  watcher.stop();
  delete _watchedFiles[resolvedFilename];
}

// fs.symlink/link/readlink/truncate/chown/utimes/rm
function symlinkSync(target, path, type) {
  var t = _coercePathFromURL(target, 'target');
  _validatePath(t, 'target');
  _validatePath(path, 'path');
  ensureExactFs();
  var p = _pathToString(path);
  var targetPath = typeof t === 'string' ? t : Buffer.isBuffer(t) ? t.toString() : _coercePathFromURL(t, 'target');
  var linkPath = '' + p;
  try {
    if (typeof g.__exactSymlink === 'function') return g.__exactSymlink(targetPath, linkPath);
    throw new Error('ENOSYS: symlink not available');
  } catch(e) { throw _makeFsError(e, 'symlink', targetPath, linkPath); }
}
function symlink(target, path, type, cb) {
  if (typeof type === 'function') { cb = type; type = null; }
  _validateCallback(cb);
  _validatePath(target, 'target');
  _validatePath(path);
  wrapCallback(function() { symlinkSync(target, path, type); }, cb, 'symlink');
}
function linkSync(existingPath, newPath) {
  _validatePath(existingPath, 'existingPath');
  _validatePath(newPath, 'newPath');
  ensureExactFs();
  var ep = _pathToString(existingPath); var np = _pathToString(newPath);
  try {
    if (typeof g.__exactLink === 'function') return g.__exactLink(ep, np);
    throw new Error('ENOSYS: link not available');
  } catch(e) { throw _makeFsError(e, 'link', ep, np); }
}
function link(existingPath, newPath, cb) {
  _validateCallback(cb);
  _validatePath(existingPath, 'existingPath');
  _validatePath(newPath, 'newPath');
  wrapCallback(function() { linkSync(existingPath, newPath); }, cb, 'link');
}
function readlinkSync(path, options) {
  _validatePath(path, 'path');
  _validateEncodingOption(options);
  ensureExactFs();
  var p = _pathToString(path);
  try {
    if (typeof g.__exactReadlink === 'function') return g.__exactReadlink(p);
    throw new Error('ENOSYS: readlink not available');
  } catch(e) { throw _makeFsError(e, 'readlink', p); }
}
function readlink(path, options, cb) {
  if (typeof options === 'function') { cb = options; options = undefined; }
  _validateCallback(cb);
  _validatePath(path, 'path');
  _validateEncodingOption(options);
  wrapCallback(function() { return readlinkSync(path, options); }, cb, 'readlink', _pathToString(path));
}
function truncateSync(path, len) {
  // Support fd as first arg (delegates to ftruncateSync)
  if (typeof path === 'number') {
    return ftruncateSync(path, len);
  }
  _validatePath(path);
  len = _normalizeTruncateLen(len);
  ensureExactFs();
  var p = _pathToString(path);
  try {
    if (typeof g.__exactTruncate === 'function') return g.__exactTruncate(p, len);
    throw new Error('ENOSYS: truncate not available');
  } catch(e) { throw _makeFsError(e, 'truncate', p); }
}
function truncate(path, len, cb) {
  if (typeof len === 'function') { cb = len; len = undefined; }
  // Support fd as first arg
  if (typeof path === 'number') {
    return ftruncate(path, len, cb);
  }
  _validatePath(path);
  len = _normalizeTruncateLen(len);
  _validateCallback(cb);
  wrapCallback(function() { truncateSync(path, len); }, cb, 'truncate', _pathToString(path));
}
function chownSync(path, uid, gid) {
  _validatePath(path);
  _validateUidOrGid('uid', uid);
  _validateUidOrGid('gid', gid);
  if (uid === -1 && gid === -1) return;
  ensureExactFs();
  var p = _pathToString(path);
  try {
    if (typeof g.__exactChown === 'function') return g.__exactChown(p, uid, gid);
  } catch(e) { throw _makeFsError(e, 'chown', p); }
}
function chown(path, uid, gid, cb) {
  _validateCallback(cb);
  _validatePath(path);
  _validateUidOrGid('uid', uid);
  _validateUidOrGid('gid', gid);
  wrapCallback(function() { chownSync(path, uid, gid); }, cb, 'chown', _pathToString(path));
}
function lchownSync(path, uid, gid) {
  _validatePath(path);
  _validateUidOrGid('uid', uid);
  _validateUidOrGid('gid', gid);
  if (uid === -1 && gid === -1) return;
  ensureExactFs();
  var p = _pathToString(path);
  try {
    if (typeof g.__exactLchown === 'function') return g.__exactLchown(p, uid, gid);
  } catch(e) { throw _makeFsError(e, 'lchown', p); }
}
function utimesSync(path, atime, mtime) {
  _validatePath(path);
  ensureExactFs();
  var p = _pathToString(path);
  var at = atime instanceof Date ? atime.getTime() / 1000 : (typeof atime === 'string' ? Number(atime) : atime);
  var mt = mtime instanceof Date ? mtime.getTime() / 1000 : (typeof mtime === 'string' ? Number(mtime) : mtime);
  try {
    if (typeof g.__exactUtimes === 'function') return g.__exactUtimes(p, at, mt);
  } catch(e) { throw _makeFsError(e, 'utime', p); }
}
function utimes(path, atime, mtime, cb) {
  _validateCallback(cb);
  _validatePath(path);
  wrapCallback(function() { utimesSync(path, atime, mtime); }, cb, 'utime', _pathToString(path));
}
function rmSync(path, options) {
  ensureExactFs();
  if (typeof options === 'boolean') {
    options = { recursive: true, force: true };
  } else {
    options = options || {};
  }
  var recursive = !!(options && options.recursive);
  var force = !!(options && options.force);
  var maxRetries = (options && typeof options.maxRetries === 'number' && options.maxRetries > 0)
    ? Math.floor(options.maxRetries)
    : 0;
  function removeEntry(targetPath, isDirectory) {
    try {
      if (isDirectory) {
        rmdirSync(targetPath);
      } else {
        unlinkSync(targetPath);
      }
      return;
    } catch(err) {
      if (!force || !err || (err.code !== 'EACCES' && err.code !== 'EPERM')) {
        throw err;
      }
      chmodSync(targetPath, isDirectory ? 0o777 : 0o666);
      if (isDirectory) {
        rmdirSync(targetPath);
      } else {
        unlinkSync(targetPath);
      }
    }
  }

  function performRemove() {
    // Use lstatSync to not follow symlinks - symlinks should be unlinked, not traversed
    var info = lstatSync(path);
    if (typeof info.isDirectory === 'function' ? info.isDirectory() : info.is_dir) {
      if (recursive) {
        var entries;
        if (force) {
          try { chmodSync(path, 0o777); } catch(_ignore) {}
        }
        try {
          entries = readdirSync(path);
        } catch(e2) {
          if (force && e2 && (e2.code === 'EACCES' || e2.code === 'EPERM')) {
            chmodSync(path, 0o777);
            entries = readdirSync(path);
          } else {
            throw e2;
          }
        }
        for (var i = 0; i < entries.length; i++) {
          rmSync(pathJoin(path, entries[i]), options);
        }
      }
      removeEntry(path, true);
    } else {
      removeEntry(path, false);
    }
  }

  function shouldRetryRm(err) {
    if (!err || typeof err.code !== 'string') {
      return false;
    }
    return err.code === 'EBUSY' ||
      err.code === 'EMFILE' ||
      err.code === 'ENFILE' ||
      err.code === 'ENOTEMPTY' ||
      err.code === 'EPERM';
  }

  for (var attempt = 0;; attempt++) {
    try {
      performRemove();
      return;
    } catch(e) {
      if (force && e && (e.code === 'ENOENT' || e.code === 'ENOTDIR')) return;
      if (attempt < maxRetries && shouldRetryRm(e)) {
        continue;
      }
      throw e;
    }
  }
}
function rm(path, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  _validateCallback(cb);
  wrapCallback(function() { rmSync(path, options); }, cb, 'rm', _pathToString(path));
}

function _resolveAsync(value) {
  return function() {
    return Promise.resolve().then(function() {
      return value();
    });
  };
}
function _fileHandleErrorFromClosed() {
  var err = new Error('ERR_FS_FILE_CLOSED: FileHandle is already closed');
  err.code = 'ERR_FS_FILE_CLOSED';
  return err;
}

function FileHandlePromise(fd, path, flags) {
  this.fd = (typeof fd === 'number') ? fd : null;
  this.path = path;
  this.flags = flags || 'r';
  this._closed = false;
}
FileHandlePromise.prototype._ensureOpen = function() {
  if (this._closed || this.fd === null) throw _fileHandleErrorFromClosed();
};
FileHandlePromise.prototype.close = function() {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    var fd = handle.fd;
    handle._closed = true;
    handle.fd = null;
    return closeSync(fd);
  })();
};

if (typeof Symbol !== 'undefined' && typeof Symbol.asyncDispose === 'symbol') {
  FileHandlePromise.prototype[Symbol.asyncDispose] = function() {
    return this.close();
  };
} else {
  FileHandlePromise.prototype.asyncDispose = function() {
    return this.close();
  };
}

FileHandlePromise.prototype.read = function(buffer, offset, length, position) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    if (typeof buffer === 'object' && buffer !== null && buffer.length !== undefined) {
      var off = (typeof offset === 'number') ? offset : 0;
      var len = (typeof length === 'number') ? length : (buffer.length - off);
      var pos = (position === undefined || position === null) ? -1 : position;
      var bytesRead = readSync(handle.fd, buffer, off, len, pos);
      return { bytesRead: bytesRead, buffer: buffer };
    }
    throw _fsInvalidArgType('buffer', 'string or an instance of Buffer or Uint8Array', buffer);
  })();
};
FileHandlePromise.prototype.write = function(buffer, offset, length, position) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    var off = (typeof offset === 'number') ? offset : 0;
    var len = (typeof length === 'number') ? length : (buffer.length - off);
    var pos = (position === undefined || position === null) ? -1 : position;
    var bytesWritten = writeSync(handle.fd, buffer, off, len, pos);
    return { bytesWritten: bytesWritten, buffer: buffer };
  })();
};
FileHandlePromise.prototype.readv = function(buffers, position) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    return { bytesRead: readvSync(handle.fd, buffers, position), buffers: buffers };
  })();
};
FileHandlePromise.prototype.writev = function(buffers, position) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    return { bytesWritten: writevSync(handle.fd, buffers, position), buffers: buffers };
  })();
};
FileHandlePromise.prototype.readFile = function(options) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    return readFileSync(handle.fd, options);
  })();
};
FileHandlePromise.prototype.writeFile = function(data, options) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    return _promisesWriteFile(handle.fd, data, options);
  })();
};
FileHandlePromise.prototype.appendFile = function(data, options) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    appendFileSync(handle.fd, data, options);
    return toUint8Array(data, options && options.encoding).length;
  })();
};
FileHandlePromise.prototype.createReadStream = function(options) {
  this._ensureOpen();
  var fileOptions = options ? _extend(options, { fd: this, autoClose: false }) : { fd: this, autoClose: false };
  return createReadStream(this.path, fileOptions);
};
FileHandlePromise.prototype.createWriteStream = function(options) {
  this._ensureOpen();
  var fileOptions = options ? _extend(options, { fd: this, autoClose: false }) : { fd: this, autoClose: false };
  return createWriteStream(this.path, fileOptions);
};
FileHandlePromise.prototype.truncate = function(len) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    ftruncateSync(handle.fd, len);
  })();
};
FileHandlePromise.prototype.sync = function() {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    _callFsyncSync(handle.fd);
  })();
};
FileHandlePromise.prototype.datasync = function() {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    fdatasyncSync(handle.fd);
  })();
};
FileHandlePromise.prototype.readLines = function() {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    var contents = readFileSync(handle.fd, 'utf8');
    var lines = contents.split('\n');
    if (lines.length > 0 && lines[lines.length - 1] === '') {
      lines.pop();
    }
    return _makeAsyncIteratorFromArray(lines);
  })();
};
FileHandlePromise.prototype.stat = function(options) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    return fstatSync(handle.fd, options);
  })();
};
FileHandlePromise.prototype.chmod = function(mode) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    fchmodSync(handle.fd, mode);
  })();
};
FileHandlePromise.prototype.chown = function(uid, gid) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    fchownSync(handle.fd, uid, gid);
  })();
};
FileHandlePromise.prototype.utimes = function(atime, mtime) {
  var handle = this;
  return _resolveAsync(function() {
    handle._ensureOpen();
    futimesSync(handle.fd, atime, mtime);
  })();
};
function _makeAsyncIteratorFromArray(values) {
  var i = 0;
  return {
    next: function() {
      if (i >= values.length) return Promise.resolve({ done: true });
      var value = values[i++];
      return Promise.resolve({ done: false, value: value });
    },
    return: function() { return { done: true }; },
    [Symbol.asyncIterator]: function() { return this; }
  };
}
function _extend(target, source) {
  if (!source) return target;
  var keys = Object.keys(source);
  for (var i = 0; i < keys.length; i++) {
    target[keys[i]] = source[keys[i]];
  }
  return target;
}

var promises = {
  readFile: function(p, o) { return _resolveAsync(function() { return readFileSync(p, o); })(); },
  writeFile: function(p, d, o) {
    return _promisesWriteFile(p, d, o);
  },
  appendFile: function(p, d, o) {
    return _resolveAsync(function() {
      appendFileSync(p, d, o);
      return toUint8Array(d, o && o.encoding).length;
    })();
  },
  stat: function(p, o) { return _resolveAsync(function() { return statSync(p, o); })(); },
  lstat: function(p, o) { return _resolveAsync(function() { return lstatSync(p, o); })(); },
  readdir: function(p, o) { return _resolveAsync(function() { return readdirSync(p, o); })(); },
  mkdir: function(p, o) {
    return _resolveAsync(function() {
      return mkdirSync(p, o);
    })();
  },
  rmdir: function(p, o) { return _resolveAsync(function() { rmdirSync(p, o); })(); },
  unlink: function(p) { return _resolveAsync(function() { unlinkSync(p); })(); },
  rename: function(o, n) { return _resolveAsync(function() { renameSync(o, n); })(); },
  copyFile: function(s, d, m) { return _resolveAsync(function() { copyFileSync(s, d, m); })(); },
  access: function(p, m) { return _resolveAsync(function() { accessSync(p, m); })(); },
  chmod: function(p, m) { return _resolveAsync(function() { chmodSync(p, m); })(); },
  realpath: function(p, o) { return _resolveAsync(function() { return realpathSync(p, o); })(); },
  mkdtemp: function(p, o) { return _resolveAsync(function() { return mkdtempSync(p, o); })(); },
  rm: function(p, o) { return _resolveAsync(function() { rmSync(p, o); })(); },
  cp: function(s, d, o) { return _resolveAsync(function() { cpSync(s, d, o); })(); },
  glob: function(pattern, o) {
    return _makeAsyncIteratorFromArray(globSync(pattern, o));
  },
  statfs: function(path, o) { return _resolveAsync(function() { return statfsSync(path, o); })(); },
  readv: function(fd, buffers, position) { return _resolveAsync(function() { return { bytesRead: readvSync(fd, buffers, position), buffers: buffers }; })(); },
  writev: function(fd, buffers, position) { return _resolveAsync(function() { return { bytesWritten: writevSync(fd, buffers, position), buffers: buffers }; })(); },
  fdatasync: function(fd) { return _resolveAsync(function() { fdatasyncSync(fd); })(); },
  fsync: function(fd) { return _resolveAsync(function() { fsyncSync(fd); })(); },
  fstat: function(fd) { return _resolveAsync(function() { return fstatSync(fd); })(); },
  watch: function(p, o) {
    return _promisesWatch(p, o);
  },
  read: function(fd, buffer, offset, length, position) { return _resolveAsync(function() { return { bytesRead: readSync(fd, buffer, offset, length, position), buffer: buffer }; })(); },
  write: function(fd, bufferOrString, offset, length, position) { return _resolveAsync(function() { return { bytesWritten: writeSync(fd, bufferOrString, offset, length, position), buffer: bufferOrString }; })(); },
  open: function(p, f, m) {
    return _resolveAsync(function() { return new FileHandlePromise(openSync(p, f, m), _pathToString(p), f); })();
  },
  truncate: function(p, l) { return _resolveAsync(function() { truncateSync(p, l); })(); },
  lchown: function(p, u, gi) { return _resolveAsync(function() { lchownSync(p, u, gi); })(); },
  chown: function(p, u, gi) { return _resolveAsync(function() { chownSync(p, u, gi); })(); },
  utimes: function(p, a, m) { return _resolveAsync(function() { utimesSync(p, a, m); })(); },
  lutimes: function(p, a, m) { return _resolveAsync(function() { lutimesSync(p, a, m); })(); },
  lchmod: function(p, m) { return _resolveAsync(function() { lchmodSync(p, m); })(); },
  opendir: function(p, o) { return _resolveAsync(function() { return opendirSync(p, o); })(); },
  close: function(fd) { return _resolveAsync(function() { closeSync(fd); })(); },
  symlink: function(t, p, ty) { return _resolveAsync(function() { symlinkSync(t, p, ty); })(); },
  link: function(e, n) { return _resolveAsync(function() { linkSync(e, n); })(); },
  readlink: function(p, o) { return _resolveAsync(function() { return readlinkSync(p, o); })(); },
  fchmod: function(fd, m) { return _resolveAsync(function() { fchmodSync(fd, m); })(); },
  fchown: function(fd, u, g) { return _resolveAsync(function() { fchownSync(fd, u, g); })(); },
  ftruncate: function(fd, l) { return _resolveAsync(function() { ftruncateSync(fd, l); })(); },
  FileHandle: FileHandlePromise,
  constants: constants
};

var constants = Object.create(null);
// Access mode constants
constants.F_OK = 0;
constants.R_OK = 4;
constants.W_OK = 2;
constants.X_OK = 1;
// File open constants
constants.O_RDONLY = 0;
constants.O_WRONLY = 1;
constants.O_RDWR = 2;
constants.O_CREAT = 512;
constants.O_EXCL = 2048;
constants.O_NOCTTY = 131072;
constants.O_TRUNC = 1024;
constants.O_APPEND = 8;
constants.O_DIRECTORY = 1048576;
// O_NOATIME is Linux-only; do not expose on other platforms
if (typeof process !== 'undefined' && process.platform === 'linux') {
  constants.O_NOATIME = 262144;
}
constants.O_NOFOLLOW = 256;
constants.O_DIRECT = 65536;
constants.O_SYNC = 128;
constants.O_DSYNC = 4194304;
constants.O_SYMLINK = 2097152;
constants.O_NONBLOCK = 4;
// File type constants
constants.S_IFMT = 61440;
constants.S_IFREG = 32768;
constants.S_IFDIR = 16384;
constants.S_IFCHR = 8192;
constants.S_IFBLK = 24576;
constants.S_IFIFO = 4096;
constants.S_IFLNK = 40960;
constants.S_IFSOCK = 49152;
// File permission constants
constants.S_IRWXU = 448;
constants.S_IRUSR = 256;
constants.S_IWUSR = 128;
constants.S_IXUSR = 64;
constants.S_IRWXG = 56;
constants.S_IRGRP = 32;
constants.S_IWGRP = 16;
constants.S_IXGRP = 8;
constants.S_IRWXO = 7;
constants.S_IROTH = 4;
constants.S_IWOTH = 2;
constants.S_IXOTH = 1;
// UV constants
constants.UV_FS_SYMLINK_DIR = 1;
constants.UV_FS_SYMLINK_JUNCTION = 2;
constants.UV_DIRENT_UNKNOWN = 0;
constants.UV_DIRENT_FILE = 1;
constants.UV_DIRENT_DIR = 2;
constants.UV_DIRENT_LINK = 3;
constants.UV_DIRENT_FIFO = 4;
constants.UV_DIRENT_SOCKET = 5;
constants.UV_DIRENT_CHAR = 6;
constants.UV_DIRENT_BLOCK = 7;
constants.UV_FS_O_FILEMAP = 0;
// Copy file constants
constants.UV_FS_COPYFILE_EXCL = 1;
constants.COPYFILE_EXCL = 1;
constants.UV_FS_COPYFILE_FICLONE = 2;
constants.COPYFILE_FICLONE = 2;
constants.UV_FS_COPYFILE_FICLONE_FORCE = 4;
constants.COPYFILE_FICLONE_FORCE = 4;
promises.constants = constants;

// fchmod/fchmodSync — file descriptor-based chmod
function fchmod(fd, mode, callback) {
  _validateFdNonNegative(fd);
  mode = _coerceMode(mode);
  _validateUint32('mode', mode);
  if (callback !== undefined && typeof callback !== 'function') _validateCallback(callback);
  ensureExactFs();
  if (typeof callback === 'function') {
    if (typeof g.__exactFsFchmod === 'function') {
      g.__exactFsFchmod(fd, mode, function(err) {
        _deferFsCallback(function() {
          if (err) callback(_makeFsError(err, 'fchmod'));
          else callback(null);
        });
      });
    } else {
      wrapCallback(function() { fchmodSync(fd, mode); }, callback, 'fchmod');
    }
    return;
  }
  return fchmodSync(fd, mode);
}
function fchmodSync(fd, mode) {
  _validateFdNonNegative(fd);
  mode = _coerceMode(mode);
  _validateUint32('mode', mode);
  ensureExactFs();
  try {
    if (typeof g.__exactFsFchmodSync === 'function') {
      return g.__exactFsFchmodSync(fd, mode);
    }
  } catch(e) { throw _makeFsError(e, 'fchmod'); }
  if (typeof g.__exactFsFchmodSync !== 'function') {
    var err = new Error('fchmod is not supported');
    err.code = 'ENOSYS';
    throw err;
  }
}

// fchown/fchownSync — file descriptor-based chown
function fchown(fd, uid, gid, callback) {
  _validateFdNonNegative(fd);
  if (typeof uid !== 'number') throw _fsInvalidArgType('uid', 'number', uid);
  _validateUidOrGid('uid', uid);
  if (typeof gid !== 'number') throw _fsInvalidArgType('gid', 'number', gid);
  _validateUidOrGid('gid', gid);
  if (callback !== undefined && typeof callback !== 'function') _validateCallback(callback);
  // Match fchownSync: no-op when both uid and gid are -1
  if (uid === -1 && gid === -1) {
    if (typeof callback === 'function') {
      _deferFsCallback(function() { callback(null); });
    }
    return;
  }
  ensureExactFs();
  if (typeof callback === 'function') {
    if (typeof g.__exactFsFchown === 'function') {
      g.__exactFsFchown(fd, uid, gid, function(err) {
        _deferFsCallback(function() {
          if (err) callback(_makeFsError(err, 'fchown'));
          else callback(null);
        });
      });
    } else {
      wrapCallback(function() { fchownSync(fd, uid, gid); }, callback, 'fchown');
    }
    return;
  }
  if (typeof g.__exactFsFchownSync === 'function') {
    try {
      return g.__exactFsFchownSync(fd, uid, gid);
    } catch(e) { throw _makeFsError(e, 'fchown'); }
  }
  if (typeof g.__exactFsFchown === 'function') {
    return g.__exactFsFchown(fd, uid, gid, function() {});
  }
  var err = new Error('fchown is not supported');
  err.code = 'ENOSYS';
  throw err;
}
function fchownSync(fd, uid, gid) {
  _validateFdNonNegative(fd);
  if (typeof uid !== 'number') throw _fsInvalidArgType('uid', 'number', uid);
  _validateUidOrGid('uid', uid);
  if (typeof gid !== 'number') throw _fsInvalidArgType('gid', 'number', gid);
  _validateUidOrGid('gid', gid);
  if (uid === -1 && gid === -1) return;
  ensureExactFs();
  try {
    if (typeof g.__exactFsFchownSync === 'function') {
      return g.__exactFsFchownSync(fd, uid, gid);
    }
  } catch(e) { throw _makeFsError(e, 'fchown'); }
  var err = new Error('fchown is not supported');
  err.code = 'ENOSYS';
  throw err;
}

// ftruncate/ftruncateSync — file descriptor-based truncate
function ftruncate(fd, len, callback) {
  if (typeof len === 'function') { callback = len; len = undefined; }
  _validateFd(fd);
  len = _normalizeTruncateLen(len);
  _validateCallback(callback);
  ensureExactFs();
  try {
    ftruncateSync(fd, len);
    _deferFsCallback(function() { callback(null); });
  } catch(e) {
    var err = _makeFsError(e, 'ftruncate');
    _deferFsCallback(function() { callback(err); });
  }
}
function ftruncateSync(fd, len) {
  _validateFd(fd);
  len = _normalizeTruncateLen(len);
  ensureExactFs();
  try {
    if (typeof g.__exactFsFtruncateSync === 'function') {
      return g.__exactFsFtruncateSync(fd, len);
    }
  } catch(e) { throw _makeFsError(e, 'ftruncate'); }
}

// fdatasync/fdatasyncSync
function fdatasync(fd, callback) {
  _validateFd(fd);
  _validateCallback(callback);
  ensureExactFs();
  try {
    if (typeof g.__exactFsFdatasyncSync === 'function') g.__exactFsFdatasyncSync(fd);
    _deferFsCallback(function() { callback(null); });
  } catch(e) {
    var err = _makeFsError(e, 'fdatasync');
    _deferFsCallback(function() { callback(err); });
  }
}
function fdatasyncSync(fd) {
  _validateFd(fd);
  ensureExactFs();
  try {
    if (typeof g.__exactFsFdatasyncSync === 'function') g.__exactFsFdatasyncSync(fd);
  } catch(e) { throw _makeFsError(e, 'fdatasync'); }
}

// fsync/fsyncSync
function fsync(fd, callback) {
  _validateFd(fd);
  _validateCallback(callback);
  ensureExactFs();
  try {
    if (typeof g.__exactFsFsyncSync === 'function') g.__exactFsFsyncSync(fd);
    _deferFsCallback(function() { callback(null); });
  } catch(e) {
    var err = _makeFsError(e, 'fsync');
    _deferFsCallback(function() { callback(err); });
  }
}
function fsyncSync(fd) {
  _validateFd(fd);
  ensureExactFs();
  try {
    if (typeof g.__exactFsFsyncSync === 'function') g.__exactFsFsyncSync(fd);
  } catch(e) { throw _makeFsError(e, 'fsync'); }
}

// fstat/fstatSync
function fstat(fd, opts, callback) {
  if (typeof opts === 'function') { callback = opts; opts = {}; }
  _validateFd(fd);
  _validateCallback(callback);
  ensureExactFs();
  try {
    var result = fstatSync(fd, opts);
    _deferFsCallback(function() { callback(null, result); });
  } catch(e) {
    var err = _makeFsError(e, 'fstat');
    _deferFsCallback(function() { callback(err); });
  }
}
function fstatSync(fd, opts) {
  _validateFd(fd);
  ensureExactFs();
  _coerceStatOptions(opts);
  var statOptions = _extractStatOptions(opts);
  try {
    if (typeof g.__exactFsFstatSync === 'function') {
      var json = g.__exactFsFstatSync(fd);
      return _makeStats(json, statOptions);
    }
    var err = new Error('ENOSYS: fstatSync is not supported');
    err.code = 'ENOSYS';
    throw err;
  } catch(e) { throw _makeFsError(e, 'fstat'); }
}

// futimes/futimesSync
function futimes(fd, atime, mtime, callback) {
  _validateFd(fd);
  _validateCallback(callback);
  ensureExactFs();
  try {
    futimesSync(fd, atime, mtime);
    _deferFsCallback(function() { callback(null); });
  } catch(e) {
    var err = _makeFsError(e, 'futime');
    if (err && typeof err.message === 'string') {
      err.message = err.message.replace('futimes', 'futime');
    }
    _deferFsCallback(function() { callback(err); });
  }
}
function futimesSync(fd, atime, mtime) {
  _validateFd(fd);
  ensureExactFs();
  try {
    if (typeof g.__exactFsFutimesSync === 'function') {
      var at = atime instanceof Date ? atime.getTime() : (typeof atime === 'number' ? atime : 0);
      var mt = mtime instanceof Date ? mtime.getTime() : (typeof mtime === 'number' ? mtime : 0);
      g.__exactFsFutimesSync(fd, at, mt);
    }
  } catch(e) {
    var err = _makeFsError(e, 'futime');
    if (err && typeof err.message === 'string') {
      err.message = err.message.replace('futimes', 'futime');
    }
    throw err;
  }
}

// lchmod/lchmodSync
function lchmod(path, mode, callback) {
  _validatePath(path);
  mode = _coerceMode(mode);
  _validateUint32('mode', mode);
  _validateCallback(callback);
  return wrapCallback(function() { lchmodSync(path, mode); }, callback, 'lchmod', _pathToString(path));
}
function lchmodSync(path, mode) {
  _validatePath(path);
  mode = _coerceMode(mode);
  _validateUint32('mode', mode);
  ensureExactFs();
  if (typeof g.__exactLchmod === 'function') {
    g.__exactLchmod(path, mode);
    return;
  }
  if (typeof g.__exactLchmodSync === 'function') {
    g.__exactLchmodSync(path, mode);
    return;
  }
  var err = new Error('ENOSYS: lchmod is not supported');
  err.code = 'ENOSYS';
  throw err;
}

// lchown/lchownSync is defined above with error enrichment
function lchown(path, uid, gid, callback) {
  _validatePath(path);
  _validateUidOrGid('uid', uid);
  _validateUidOrGid('gid', gid);
  _validateCallback(callback);
  wrapCallback(function() { lchownSync(path, uid, gid); }, callback, 'lchown', _pathToString(path));
}

// lutimes/lutimesSync
function lutimes(path, atime, mtime, callback) {
  _validatePath(path);
  _validateCallback(callback);
  wrapCallback(function() { lutimesSync(path, atime, mtime); }, callback, 'lutimes', _pathToString(path));
}
function lutimesSync(path, atime, mtime) {
  _validatePath(path);
  ensureExactFs();
  var at = atime instanceof Date ? atime.getTime() : (typeof atime === 'number' ? atime : 0);
  var mt = mtime instanceof Date ? mtime.getTime() : (typeof mtime === 'number' ? mtime : 0);
  if (typeof g.__exactLutimes === 'function') {
    g.__exactLutimes(path, at, mt);
    return;
  }
  if (typeof g.__exactLutimesSync === 'function') {
    g.__exactLutimesSync(path, at, mt);
    return;
  }
  var err = new Error('ENOSYS: lutimes is not supported');
  err.code = 'ENOSYS';
  throw err;
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
  mkdtempDisposable: mkdtempDisposable,
  mkdtempDisposableSync: mkdtempDisposableSync,
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
  ReadStream: ReadStream,
  WriteStream: WriteStream,
  watch: watch,
  watchFile: watchFile,
  unwatchFile: unwatchFile,
  FSWatcher: FSWatcher,
  Stats: Stats,
  Dir: Dir,
  Dirent: Dirent,
  symlink: symlink,
  symlinkSync: symlinkSync,
  link: link,
  linkSync: linkSync,
  cp: cp,
  cpSync: cpSync,
  readlink: readlink,
  readlinkSync: readlinkSync,
  glob: glob,
  globSync: globSync,
  truncate: truncate,
  truncateSync: truncateSync,
  statfs: statfs,
  statfsSync: statfsSync,
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
  readvSync: readvSync,
  readv: readv,
  writevSync: writevSync,
  writev: writev,
  lchmod: lchmod,
  lchmodSync: lchmodSync,
  lchown: lchown,
  lchownSync: lchownSync,
  lutimes: lutimes,
  lutimesSync: lutimesSync,
  opendir: opendir,
  opendirSync: opendirSync,
  promises: promises,
  constants: constants
};

// Add F_OK, R_OK, W_OK, X_OK as read-only properties (deprecated but still accessible)
['F_OK', 'R_OK', 'W_OK', 'X_OK'].forEach(function(name) {
  Object.defineProperty(module.exports, name, {
    get: function() {
      _emitFsDeprecation('DEP0176', 'fs.' + name + ' is deprecated, use fs.constants.' + name + ' instead');
      return constants[name];
    },
    set: function() { throw new TypeError('Cannot assign to read only property \'' + name + '\' of object \'#<Object>\''); },
    enumerable: false,
    configurable: false
  });
});
