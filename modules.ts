export interface Source {
  kind: 'generated' | 'repo' | 'inline';
  path?: string;
  code?: string;
}

export interface SpecifierGroup {
  names: readonly string[];
  source: string;
  bundleExternal?: boolean;
  moduleBuiltin?: boolean;
}

export interface PublicBuiltin {
  name: string;
  nodeOnly?: boolean;
}

export const meta = {
  reservedNodeOnly: ['sqlite', 'sea'] as const,
  defaults: {
    bundleExternal: true,
    moduleBuiltin: true,
    nodeOnly: false,
  },
} as const;

const nodeStreamConsumersSource = String.raw`var _bufferMod = require('buffer');
var _Buffer = _bufferMod && _bufferMod.Buffer ? _bufferMod.Buffer : null;

function _toUint8Array(chunk) {
  if (!chunk) {
    return new Uint8Array(0);
  }
  if (chunk instanceof Uint8Array) {
    return chunk;
  }
  if (chunk instanceof ArrayBuffer) {
    return new Uint8Array(chunk);
  }
  if (ArrayBuffer.isView(chunk)) {
    return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  }
  if (typeof chunk === 'string') {
    if (typeof TextEncoder === 'function') {
      return new TextEncoder().encode(chunk);
    }
    if (_Buffer && typeof _Buffer.from === 'function') {
      return _Buffer.from(chunk);
    }
    return new Uint8Array(chunk.length);
  }
  return _Buffer && _Buffer.isBuffer(chunk) ? chunk : new Uint8Array(0);
}

function _collect(stream) {
  if (!stream) {
    return Promise.reject(new TypeError('The "stream" argument must be of type stream. Received ' + String(stream)));
  }
  if (typeof stream.getReader === 'function') {
    return new Promise(function(resolve, reject) {
      var chunks = [];
      var reader = stream.getReader();
      function read() {
        reader.read().then(function(result) {
          if (result.done) {
            resolve(chunks);
            return;
          }
          chunks.push(_toUint8Array(result.value));
          read();
        }).catch(reject);
      }
      read();
    });
  }
  if (typeof stream.on === 'function') {
    return new Promise(function(resolve, reject) {
      var chunks = [];
      var ended = false;

      function cleanup() {
        stream.removeListener && stream.removeListener('data', onData);
        stream.removeListener && stream.removeListener('error', onError);
        stream.removeListener && stream.removeListener('end', onEnd);
        stream.removeListener && stream.removeListener('close', onEnd);
      }
      function onData(chunk) {
        chunks.push(_toUint8Array(chunk));
      }
      function onError(err) {
        if (ended) {
          return;
        }
        ended = true;
        cleanup();
        reject(err);
      }
      function onEnd() {
        if (ended) {
          return;
        }
        ended = true;
        cleanup();
        resolve(chunks);
      }
      stream.on('data', onData);
      stream.on('error', onError);
      stream.on('end', onEnd);
      stream.on('close', onEnd);
      if (stream.readableEnded) {
        onEnd();
      }
    });
  }
  return Promise.reject(new TypeError('The "stream" argument must be of type stream. Received ' + String(stream)));
}

function _concatChunks(chunks) {
  var total = 0;
  for (var i = 0; i < chunks.length; i++) {
    total += chunks[i].byteLength || 0;
  }
  var merged = new Uint8Array(total);
  var offset = 0;
  for (var j = 0; j < chunks.length; j++) {
    var chunk = chunks[j];
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

function _streamToBuffer(chunks) {
  if (_Buffer && _Buffer.concat) {
    return _Buffer.concat(chunks);
  }
  var merged = _concatChunks(chunks);
  return _Buffer ? _Buffer.from(merged) : merged;
}

function _decode(chunks) {
  var merged = _concatChunks(chunks);
  if (typeof TextDecoder === 'function') {
    return new TextDecoder().decode(merged);
  }
  var out = '';
  for (var i = 0; i < merged.length; i++) {
    out += String.fromCharCode(merged[i]);
  }
  return out;
}

function buffer(stream) {
  return _collect(stream).then(function(chunks) {
    return _streamToBuffer(chunks);
  });
}

function arrayBuffer(stream) {
  return _collect(stream).then(function(chunks) {
    return _concatChunks(chunks).buffer;
  });
}

function text(stream) {
  return _collect(stream).then(function(chunks) {
    return _decode(chunks);
  });
}

function blob(stream, options) {
  return _collect(stream).then(function(chunks) {
    if (typeof Blob === 'function') {
      return new Blob(chunks, options);
    }
    var data = _concatChunks(chunks);
    return {
      size: data.length,
      type: options && options.type || '',
      arrayBuffer: function() {
        return Promise.resolve(data.buffer);
      }
    };
  });
}

function json(stream) {
  return text(stream).then(JSON.parse);
}

module.exports = {
  blob: blob,
  buffer: buffer,
  arrayBuffer: arrayBuffer,
  text: text,
  json: json
};`;

const urlAliasSource = String.raw`const nodeUrl = require('node:url');
const exported = {};
Object.defineProperties(exported, Object.getOwnPropertyDescriptors(nodeUrl));
module.exports = exported;`;

const internalFsUtilsSource = String.raw`function isFd(fd) {
  return typeof fd === 'number' && Number.isInteger(fd) && fd >= 0;
}

function isFileMode(mode) {
  return typeof mode === 'number' && Number.isInteger(mode);
}

function validateFd(fd) {
  if (!isFd(fd)) {
    throw new TypeError('The "fd" argument must be a non-negative integer. Received ' + String(fd));
  }
}

function toPathIfFileURL(value) {
  if (typeof value === 'string' || value instanceof String) {
    return value;
  }
  if (value && typeof value === 'object' && typeof value.path === 'string') {
    return value.path;
  }
  return value;
}

function _invalidValueError(name, value, extra) {
  var received;
  if (value === null) {
    received = 'null';
  } else if (value === undefined) {
    received = 'undefined';
  } else if (typeof value === 'number') {
    received = 'type number (' + value + ')';
  } else if (value === '') {
    received = 'type string';
  } else {
    received = 'type ' + typeof value;
  }
  if (extra) {
    return new TypeError('The "' + name + '" argument ' + extra + '. Received ' + received);
  }
  return new TypeError('The "' + name + '" argument must be of type object. Received ' + received);
}

function _invalidArgType(name, value, expected, check) {
  var err = new TypeError('The "' + name + '" argument must be of type ' + expected + '. Received ' + (value === null ? 'null' : typeof value));
  err.code = 'ERR_INVALID_ARG_TYPE';
  if (check) throw err;
  return err;
}

function _invalidArgValue(name, value, reason) {
  var err = new TypeError('The "' + name + '" argument must be ' + reason + '. Received ' + (value === null ? 'null' : value));
  err.code = 'ERR_INVALID_ARG_VALUE';
  return err;
}

function _stringToInt(value) {
  return Number.parseInt(value, 10);
}

function _rangeError(name, value, min, max) {
  var err = new RangeError('The value of "' + name + '" is out of range. It must be ' + min + '. Received ' + value);
  err.code = 'ERR_OUT_OF_RANGE';
  return err;
}

function _validateOffsetLength(offset, length, byteLength, mode, maxLength) {
  if (!Number.isInteger(offset) || offset < 0) {
    throw _rangeError('offset', offset, '>= 0', offset);
  }
  if (!Number.isInteger(length) || length < 0) {
    throw _rangeError('length', length, '>= 0', length);
  }
  if (mode === 'write') {
    if (offset > byteLength) {
      var offsetErr = new RangeError('The value of "offset" is out of range. It must be <= ' + byteLength + '. Received ' + offset);
      offsetErr.code = 'ERR_OUT_OF_RANGE';
      throw offsetErr;
    }
  }
  if (length > maxLength) {
    var maxLenErr = new RangeError('The value of "length" is out of range. It must be <= ' + maxLength + '. Received ' + length);
    maxLenErr.code = 'ERR_OUT_OF_RANGE';
    throw maxLenErr;
  }
  var max = byteLength - offset;
  if (length > max) {
    var err = new RangeError('The value of "length" is out of range. It must be <= ' + max + '. Received ' + length);
    err.code = 'ERR_OUT_OF_RANGE';
    throw err;
  }
}

function validateOffsetLengthRead(offset, length, byteLength, lengthIsBigInt) {
  if (lengthIsBigInt !== undefined && lengthIsBigInt) {
    if (typeof offset === 'bigint' || typeof length === 'bigint') {
      offset = _stringToInt(offset);
      length = _stringToInt(length);
    }
  }
  _validateOffsetLength(offset, length, byteLength, 'read', (2 ** 31) - 1);
}

function validateOffsetLengthWrite(offset, length, byteLength, lengthIsBigInt) {
  if (lengthIsBigInt !== undefined && lengthIsBigInt) {
    if (typeof offset === 'bigint' || typeof length === 'bigint') {
      offset = _stringToInt(offset);
      length = _stringToInt(length);
    }
  }
  _validateOffsetLength(offset, length, byteLength, 'write', (2 ** 31) - 1);
}

function _validateOption(name, value, expectedType) {
  if (expectedType === 'boolean' && typeof value !== 'boolean') {
    var boolErr = new TypeError('The "options.' + name + '" property must be of type boolean. Received type ' + typeof value + '.');
    boolErr.code = 'ERR_INVALID_ARG_TYPE';
    throw boolErr;
  }
  if (expectedType === 'number' && (typeof value !== 'number' || !Number.isFinite(value))) {
    var rangeError = new RangeError('The value of "options.' + name + '" is out of range. Received ' + value);
    rangeError.code = 'ERR_OUT_OF_RANGE';
    throw rangeError;
  }
}

function validateRmdirOptions(options) {
  if (options === undefined) {
    return { retryDelay: 100, maxRetries: 0, recursive: false };
  }
  if (options === null || typeof options !== 'object') {
    var e = _invalidArgType('options', options, 'object');
    e.code = 'ERR_INVALID_ARG_TYPE';
    throw e;
  }
  if (Object.prototype.hasOwnProperty.call(options, 'recursive')) {
    _validateOption('recursive', options.recursive, 'boolean');
  }
  if (Object.prototype.hasOwnProperty.call(options, 'retryDelay')) {
    if (typeof options.retryDelay !== 'number' || !Number.isFinite(options.retryDelay) || options.retryDelay < 0) {
      var retryErr = new RangeError('The value of "options.retryDelay" is out of range. Received ' + options.retryDelay);
      retryErr.code = 'ERR_OUT_OF_RANGE';
      throw retryErr;
    }
  }
  if (Object.prototype.hasOwnProperty.call(options, 'maxRetries')) {
    if (typeof options.maxRetries !== 'number' || !Number.isFinite(options.maxRetries) || options.maxRetries < 0) {
      var maxErr = new RangeError('The value of "options.maxRetries" is out of range. Received ' + options.maxRetries);
      maxErr.code = 'ERR_OUT_OF_RANGE';
      throw maxErr;
    }
  }
  return {
    retryDelay: options.retryDelay === undefined ? 100 : options.retryDelay,
    maxRetries: options.maxRetries === undefined ? 0 : options.maxRetries,
    recursive: options.recursive === undefined ? false : options.recursive
  };
}

function validateRmOptionsSync(path, options) {
  var base = validateRmdirOptions(options);
  var hasForce = !!(options && Object.prototype.hasOwnProperty.call(options, 'force'));
  if (hasForce) {
    _validateOption('force', options.force, 'boolean');
  }
  return {
    retryDelay: base.retryDelay,
    maxRetries: base.maxRetries,
    recursive: base.recursive,
    force: hasForce ? options.force : false
  };
}

function _validatePathLike(value, name) {
  if (typeof value === 'string' || Buffer.isBuffer(value)) return;
  if (value && typeof value === 'object' && typeof value.href === 'string' && value.protocol === 'file:') {
    return;
  }
  var err = new TypeError('The "' + name + '" argument must be of type string or an instance of Buffer. Received type ' + (value === null ? 'object' : typeof value) + ' (' + String(value) + ')');
  err.code = 'ERR_INVALID_ARG_TYPE';
  throw err;
}

function Dirent(name, parentPath, type) {
  this.name = name;
  this.path = parentPath;
  this.parentPath = parentPath;
  this._type = type;
}

Dirent.prototype.isFile = function() { return this._type === 1; };
Dirent.prototype.isDirectory = function() { return this._type === 2; };
Dirent.prototype.isSymbolicLink = function() { return this._type === 3; };
Dirent.prototype.isFIFO = function() { return this._type === 4; };
Dirent.prototype.isSocket = function() { return this._type === 5; };
Dirent.prototype.isCharacterDevice = function() { return this._type === 6; };
Dirent.prototype.isBlockDevice = function() { return this._type === 7; };

function getDirent(path, name, type, callback) {
  _validatePathLike(path, 'path');
  var dirent = new Dirent(name, path, type);
  if (callback) {
    callback(null, dirent);
    return null;
  }
  return dirent;
}

function getDirents(path, entries, callback) {
  _validatePathLike(path, 'path');
  var result = [];
  for (var i = 0; i < entries.length; i++) {
    var entry = entries[i];
    if (!entry || !entry.length) {
      continue;
    }
    result.push(getDirent(path, entry[0], entry[1]));
  }
  callback(null, result);
}

function stringToFlags(flags) {
  if (typeof flags !== 'string' || flags === '') {
    var err = new TypeError('The flags argument must be a valid flags string. Received ' + flags);
    err.code = 'ERR_INVALID_ARG_VALUE';
    throw err;
  }
  var hasPlus = flags.indexOf('+') !== -1;
  if (flags.indexOf('+') !== flags.lastIndexOf('+')) {
    throw _invalidArgValue('flags', flags, 'a valid flag string');
  }
  if (hasPlus && flags.indexOf('+') !== flags.length - 1) {
    throw _invalidArgValue('flags', flags, 'a valid flag string');
  }
  var flagChars = hasPlus ? flags.slice(0, -1) : flags;
  var hasSync = false;
  var hasExclusive = false;
  var modeFlags = '';
  for (var i = 0; i < flagChars.length; i++) {
    var ch = flagChars.charAt(i);
    if (ch === 's') {
      if (hasSync) throw _invalidArgValue('flags', flags, 'a valid flag string');
      hasSync = true;
    } else if (ch === 'x') {
      if (hasExclusive) throw _invalidArgValue('flags', flags, 'a valid flag string');
      hasExclusive = true;
    } else if (ch === 'r' || ch === 'w' || ch === 'a') {
      if (modeFlags.length >= 1) throw _invalidArgValue('flags', flags, 'a valid flag string');
      modeFlags = ch;
    } else {
      throw _invalidArgValue('flags', flags, 'a valid flag string');
    }
  }

  if (modeFlags.length !== 1) {
    throw _invalidArgValue('flags', flags, 'a valid flag string');
  }
  if (hasExclusive && modeFlags === 'r') {
    throw _invalidArgValue('flags', flags, 'a valid flag string');
  }
  var result = 0;
  if (modeFlags === 'r') {
    result = hasPlus ? 2 : 0;
  } else if (modeFlags === 'w') {
    result = 0x200 | 0x400 | 0x1;
  } else {
    result = 0x8 | 0x200 | 0x1;
  }
  if (hasPlus) {
    result = (result & ~0x1) | 0x2;
  }
  if (hasExclusive) result |= 0x800;
  if (hasSync) result |= 0x80;
  return result;
}

function BigIntStats(dev, mode, nlink, uid, gid, rdev, blksize, ino, size, blocks, atimeMs, mtimeMs, ctimeMs, birthtimeMs, atimeNs, mtimeNs, ctimeNs, birthtimeNs) {
  this.dev = BigInt(dev);
  this.mode = BigInt(mode);
  this.nlink = BigInt(nlink);
  this.uid = BigInt(uid);
  this.gid = BigInt(gid);
  this.rdev = BigInt(rdev);
  this.size = BigInt(size);
  this.blksize = BigInt(blksize);
  this.blocks = BigInt(blocks);
  this.atimeMs = BigInt(atimeMs);
  this.mtimeMs = BigInt(mtimeMs);
  this.ctimeMs = BigInt(ctimeMs);
  this.birthtimeMs = BigInt(birthtimeMs);
  this.atimeNs = BigInt(atimeNs || 0);
  this.mtimeNs = BigInt(mtimeNs || 0);
  this.ctimeNs = BigInt(ctimeNs || 0);
  this.birthtimeNs = BigInt(birthtimeNs || 0);
  this.atime = new Date(Number(this.atimeMs));
  this.mtime = new Date(Number(this.mtimeMs));
  this.ctime = new Date(Number(this.ctimeMs));
  this.birthtime = new Date(Number(this.birthtimeMs));
  this._isFile = (mode & 0o170000) === 0o100000;
  this._isDir = (mode & 0o170000) === 0o40000;
  this._isChrDev = (mode & 0o170000) === 0o20000;
  this._isBlkDev = (mode & 0o170000) === 0o60000;
  this._isFifo = (mode & 0o170000) === 0o10000;
  this._isSocket = (mode & 0o170000) === 0o140000;
  this._isSymlink = (mode & 0o170000) === 0o120000;
}
BigIntStats.prototype.isFile = function() { return this._isFile; };
BigIntStats.prototype.isDirectory = function() { return this._isDir; };
BigIntStats.prototype.isBlockDevice = function() { return this._isBlkDev; };
BigIntStats.prototype.isCharacterDevice = function() { return this._isChrDev; };
BigIntStats.prototype.isFIFO = function() { return this._isFifo; };
BigIntStats.prototype.isSocket = function() { return this._isSocket; };
BigIntStats.prototype.isSymbolicLink = function() { return this._isSymlink; };

function SyncWriteStream() {}
SyncWriteStream.prototype = {
  _write: function(chunk, encoding, cb) {
    if (cb && typeof cb === 'function') {
      cb();
    }
  }
};

module.exports = {
  isFd: isFd,
  isFileMode: isFileMode,
  validateFd: validateFd,
  toPathIfFileURL: toPathIfFileURL,
  stringToFlags: stringToFlags,
  validateOffsetLengthRead: validateOffsetLengthRead,
  validateOffsetLengthWrite: validateOffsetLengthWrite,
  validateRmdirOptions: validateRmdirOptions,
  validateRmOptionsSync: validateRmOptionsSync,
  getDirents: getDirents,
  getDirent: getDirent,
  BigIntStats: BigIntStats,
  SyncWriteStream: SyncWriteStream,
  kMinPoolSpace: 8192
};`;

export const sources = {
  exact_process: { kind: 'generated', path: 'builtins/process.js' },
  exact_crypto: { kind: 'generated', path: 'builtins/crypto.js' },
  exact_clipboard: { kind: 'generated', path: 'builtins/clipboard.js' },
  exact_http: {
    kind: 'repo',
    path: 'packages/ibex-runtime-js/src/http-server/index.js',
  },
  exact_sqlite: {
    kind: 'repo',
    path: 'packages/ibex-runtime-js/src/sqlite/module.js',
  },
  node_fs: { kind: 'generated', path: 'builtins/fs.js' },
  node_fs_promises: { kind: 'generated', path: 'builtins/fs-promises.js' },
  node_path: { kind: 'generated', path: 'builtins/path.js' },
  path_posix_alias: { kind: 'inline', code: "module.exports = require('path').posix;" },
  path_win32_alias: { kind: 'inline', code: "module.exports = require('path').win32;" },
  node_events: { kind: 'generated', path: 'builtins/events.js' },
  node_stream: { kind: 'generated', path: 'builtins/stream.js' },
  legacy_stream_readable: { kind: 'inline', code: "module.exports = require('stream').Readable;" },
  legacy_stream_writable: { kind: 'inline', code: "module.exports = require('stream').Writable;" },
  legacy_stream_duplex: { kind: 'inline', code: "module.exports = require('stream').Duplex;" },
  legacy_stream_transform: { kind: 'inline', code: "module.exports = require('stream').Transform;" },
  legacy_stream_passthrough: { kind: 'inline', code: "module.exports = require('stream').PassThrough;" },
  node_stream_consumers: { kind: 'inline', code: nodeStreamConsumersSource },
  node_stream_promises: { kind: 'generated', path: 'builtins/stream-promises.js' },
  node_buffer: { kind: 'generated', path: 'builtins/buffer.js' },
  node_util: { kind: 'generated', path: 'builtins/util.js' },
  util_types_alias: { kind: 'inline', code: "module.exports = require('util').types;" },
  node_util_types_alias: { kind: 'inline', code: "module.exports = require('node:util').types;" },
  node_timers: { kind: 'generated', path: 'builtins/timers.js' },
  node_timers_promises: { kind: 'generated', path: 'builtins/timers-promises.js' },
  node_http: { kind: 'generated', path: 'builtins/http.js' },
  node_https: { kind: 'generated', path: 'builtins/https.js' },
  node_stream_web: { kind: 'generated', path: 'builtins/stream-web.js' },
  node_url: { kind: 'generated', path: 'builtins/url.js' },
  url_alias: { kind: 'inline', code: urlAliasSource },
  node_assert: { kind: 'generated', path: 'builtins/assert.js' },
  node_os: { kind: 'generated', path: 'builtins/os.js' },
  node_tty: { kind: 'generated', path: 'builtins/tty.js' },
  node_string_decoder: { kind: 'generated', path: 'builtins/string-decoder.js' },
  node_querystring: { kind: 'generated', path: 'builtins/querystring.js' },
  node_punycode: { kind: 'generated', path: 'builtins/punycode.js' },
  node_child_process: { kind: 'generated', path: 'builtins/child-process.js' },
  node_readline: { kind: 'generated', path: 'builtins/readline.js' },
  node_module: { kind: 'generated', path: 'builtins/module.js' },
  node_zlib: { kind: 'generated', path: 'builtins/zlib.js' },
  node_tls: { kind: 'generated', path: 'builtins/tls.js' },
  node_dns: { kind: 'generated', path: 'builtins/dns.js' },
  node_dns_promises: { kind: 'generated', path: 'builtins/dns-promises.js' },
  internal_fs_utils: { kind: 'inline', code: internalFsUtilsSource },
  node_net: { kind: 'generated', path: 'builtins/net.js' },
  node_perf_hooks: { kind: 'generated', path: 'builtins/perf-hooks.js' },
  node_async_hooks: { kind: 'generated', path: 'builtins/async-hooks.js' },
  node_worker_threads: { kind: 'generated', path: 'builtins/worker-threads.js' },
  node_vm: { kind: 'generated', path: 'builtins/vm.js' },
  node_console: { kind: 'generated', path: 'builtins/console.js' },
  node_cluster: { kind: 'generated', path: 'builtins/cluster.js' },
  node_dgram: { kind: 'generated', path: 'builtins/dgram.js' },
  node_domain: { kind: 'generated', path: 'builtins/domain.js' },
  node_v8: { kind: 'generated', path: 'builtins/v8.js' },
  node_constants: { kind: 'generated', path: 'builtins/constants.js' },
  ws: { kind: 'generated', path: 'builtins/ws.js' },
  node_http2: { kind: 'generated', path: 'builtins/http2.js' },
  node_diagnostics_channel: { kind: 'generated', path: 'builtins/diagnostics-channel.js' },
  node_trace_events: { kind: 'generated', path: 'builtins/trace-events.js' },
  node_inspector: { kind: 'generated', path: 'builtins/inspector.js' },
  node_wasi: { kind: 'generated', path: 'builtins/wasi.js' },
} as const satisfies Record<string, Source>;

export const publicBuiltins = [
  { name: 'assert' },
  { name: 'assert/strict' },
  { name: 'async_hooks' },
  { name: 'buffer' },
  { name: 'child_process' },
  { name: 'cluster' },
  { name: 'console' },
  { name: 'constants' },
  { name: 'crypto' },
  { name: 'dgram' },
  { name: 'diagnostics_channel' },
  { name: 'dns' },
  { name: 'dns/promises' },
  { name: 'domain' },
  { name: 'events' },
  { name: 'fs' },
  { name: 'fs/promises' },
  { name: 'http' },
  { name: 'http2' },
  { name: 'https' },
  { name: 'inspector' },
  { name: 'inspector/promises' },
  { name: 'module' },
  { name: 'net' },
  { name: 'os' },
  { name: 'path' },
  { name: 'path/posix' },
  { name: 'path/win32' },
  { name: 'perf_hooks' },
  { name: 'process' },
  { name: 'punycode' },
  { name: 'querystring' },
  { name: 'readline' },
  { name: 'readline/promises' },
  { name: 'stream' },
  { name: 'stream/consumers' },
  { name: 'stream/promises' },
  { name: 'stream/web' },
  { name: 'string_decoder' },
  { name: 'sys' },
  { name: 'timers' },
  { name: 'timers/promises' },
  { name: 'tls' },
  { name: 'trace_events' },
  { name: 'tty' },
  { name: 'url' },
  { name: 'util' },
  { name: 'util/types' },
  { name: 'v8' },
  { name: 'vm' },
  { name: 'wasi' },
  { name: 'worker_threads' },
  { name: 'zlib' },
] as const satisfies readonly PublicBuiltin[];

export const specifiers = [
  {
    names: ['exact:process'],
    source: 'exact_process',
    moduleBuiltin: false,
  },
  {
    names: ['exact:crypto'],
    source: 'exact_crypto',
    moduleBuiltin: false,
  },
  {
    names: ['exact:clipboard'],
    source: 'exact_clipboard',
    moduleBuiltin: false,
  },
  {
    names: ['exact:http'],
    source: 'exact_http',
    moduleBuiltin: false,
  },
  {
    names: ['exact:sqlite', 'bun:sqlite'],
    source: 'exact_sqlite',
    moduleBuiltin: false,
  },
  {
    names: ['bun:fs', 'node:fs', 'fs'],
    source: 'node_fs',
  },
  {
    names: ['node:process', 'process'],
    source: 'exact_process',
  },
  {
    names: ['bun:fs/promises', 'node:fs/promises', 'fs/promises'],
    source: 'node_fs_promises',
  },
  {
    names: ['internal/fs/promises'],
    source: 'node_fs_promises',
    moduleBuiltin: false,
    bundleExternal: false,
  },
  {
    names: ['node:path', 'path'],
    source: 'node_path',
  },
  {
    names: ['node:path/posix', 'path/posix'],
    source: 'path_posix_alias',
  },
  {
    names: ['node:path/win32', 'path/win32'],
    source: 'path_win32_alias',
  },
  {
    names: ['node:crypto', 'crypto'],
    source: 'exact_crypto',
  },
  {
    names: ['node:events', 'events'],
    source: 'node_events',
  },
  {
    names: ['node:stream', 'stream'],
    source: 'node_stream',
  },
  {
    names: ['_stream_readable'],
    source: 'legacy_stream_readable',
    moduleBuiltin: false,
    bundleExternal: false,
  },
  {
    names: ['_stream_writable'],
    source: 'legacy_stream_writable',
    moduleBuiltin: false,
    bundleExternal: false,
  },
  {
    names: ['_stream_duplex'],
    source: 'legacy_stream_duplex',
    moduleBuiltin: false,
    bundleExternal: false,
  },
  {
    names: ['_stream_transform'],
    source: 'legacy_stream_transform',
    moduleBuiltin: false,
    bundleExternal: false,
  },
  {
    names: ['_stream_passthrough'],
    source: 'legacy_stream_passthrough',
    moduleBuiltin: false,
    bundleExternal: false,
  },
  {
    names: ['node:stream/consumers', 'stream/consumers'],
    source: 'node_stream_consumers',
  },
  {
    names: ['node:stream/promises', 'stream/promises'],
    source: 'node_stream_promises',
  },
  {
    names: ['node:buffer', 'buffer'],
    source: 'node_buffer',
  },
  {
    names: ['node:util', 'util', 'sys', 'node:sys'],
    source: 'node_util',
  },
  {
    names: ['util/types'],
    source: 'util_types_alias',
  },
  {
    names: ['node:util/types'],
    source: 'node_util_types_alias',
  },
  {
    names: ['node:timers', 'timers'],
    source: 'node_timers',
  },
  {
    names: ['node:timers/promises', 'timers/promises'],
    source: 'node_timers_promises',
  },
  {
    names: ['node:http', 'http'],
    source: 'node_http',
  },
  {
    names: ['_http_agent', '_http_common', '_http_server', '_http_outgoing', '_http_incoming'],
    source: 'node_http',
    moduleBuiltin: false,
    bundleExternal: false,
  },
  {
    names: ['node:https', 'https'],
    source: 'node_https',
  },
  {
    names: ['node:stream/web', 'stream/web'],
    source: 'node_stream_web',
  },
  {
    names: ['node:url'],
    source: 'node_url',
  },
  {
    names: ['url'],
    source: 'url_alias',
  },
  {
    names: ['node:os', 'os'],
    source: 'node_os',
  },
  {
    names: ['node:tty', 'tty'],
    source: 'node_tty',
  },
  {
    names: ['node:assert', 'assert', 'node:assert/strict', 'assert/strict'],
    source: 'node_assert',
  },
  {
    names: ['node:string_decoder', 'string_decoder'],
    source: 'node_string_decoder',
  },
  {
    names: ['node:querystring', 'querystring'],
    source: 'node_querystring',
  },
  {
    names: ['node:punycode', 'punycode'],
    source: 'node_punycode',
  },
  {
    names: ['node:child_process', 'child_process'],
    source: 'node_child_process',
  },
  {
    names: ['node:readline', 'readline', 'node:readline/promises', 'readline/promises'],
    source: 'node_readline',
  },
  {
    names: ['node:module', 'module'],
    source: 'node_module',
  },
  {
    names: ['node:zlib', 'zlib'],
    source: 'node_zlib',
  },
  {
    names: ['node:tls', 'tls'],
    source: 'node_tls',
  },
  {
    names: ['node:dns', 'dns'],
    source: 'node_dns',
  },
  {
    names: ['node:dns/promises', 'dns/promises'],
    source: 'node_dns_promises',
  },
  {
    names: ['internal/fs/utils'],
    source: 'internal_fs_utils',
    moduleBuiltin: false,
    bundleExternal: false,
  },
  {
    names: ['node:net', 'net'],
    source: 'node_net',
  },
  {
    names: ['node:perf_hooks', 'perf_hooks'],
    source: 'node_perf_hooks',
  },
  {
    names: ['node:async_hooks', 'async_hooks'],
    source: 'node_async_hooks',
  },
  {
    names: ['node:worker_threads', 'worker_threads'],
    source: 'node_worker_threads',
  },
  {
    names: ['node:vm', 'vm'],
    source: 'node_vm',
  },
  {
    names: ['node:console', 'console'],
    source: 'node_console',
  },
  {
    names: ['node:cluster', 'cluster'],
    source: 'node_cluster',
  },
  {
    names: ['node:dgram', 'dgram'],
    source: 'node_dgram',
  },
  {
    names: ['node:domain', 'domain'],
    source: 'node_domain',
  },
  {
    names: ['node:v8', 'v8'],
    source: 'node_v8',
  },
  {
    names: ['node:constants', 'constants'],
    source: 'node_constants',
  },
  {
    names: ['ws'],
    source: 'ws',
  },
  {
    names: ['node:http2', 'http2'],
    source: 'node_http2',
  },
  {
    names: ['node:diagnostics_channel', 'diagnostics_channel'],
    source: 'node_diagnostics_channel',
  },
  {
    names: ['node:trace_events', 'trace_events'],
    source: 'node_trace_events',
  },
  {
    names: ['node:inspector', 'inspector', 'node:inspector/promises', 'inspector/promises'],
    source: 'node_inspector',
  },
  {
    names: ['node:wasi', 'wasi'],
    source: 'node_wasi',
  },
] as const satisfies readonly SpecifierGroup[];

export const bootstrapInternalModules = [
  'internal/util/debuglog',
  'internal/linkedlist',
  'internal/util',
  'internal/util/inspect',
  'internal/options',
  'internal/http',
  'internal/net',
  'internal/async_hooks',
  'internal/timers',
  'internal/assert/myers_diff',
  'internal/crypto/util',
  'internal/crypto/x509',
  'internal/url',
  'internal/fs/utils',
  'internal/test/binding',
  'internal/child_process',
] as const;
