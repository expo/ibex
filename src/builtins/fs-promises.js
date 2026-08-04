var fs = require('node:fs');
var base = fs.promises || {};

function FileHandle(fd, path, flags) {
  this._fd = fd;
  this._path = path;
  this._flags = flags || 'r';
  this._closed = false;
  this._listeners = {};
}

Object.defineProperty(FileHandle.prototype, 'fd', {
  configurable: true,
  get: function() {
    if (this._closed) return null;
    return this._fd;
  },
});

function handleError(err) {
  if (err && err instanceof Error) return err;
  return new Error(String(err));
}

function withHandle(path, flags, mode, callback) {
  var fd;
  try {
    fd = fs.openSync(path, flags, mode);
  } catch (err) {
    return Promise.reject(handleError(err));
  }

  var handle = new FileHandle(fd, path, flags);
  try {
    var result = callback(handle);
    return Promise.resolve(result).then(
      function(value) {
        return handle.close().then(function() { return value; }, function(closeErr) {
          throw handleError(closeErr);
        });
      },
      function(err) {
        return handle.close().then(function() { throw err; }, function() { throw handleError(err); });
      }
    );
  } catch (err) {
    return handle.close().then(function() {
      throw handleError(err);
    }, function() {
      throw handleError(err);
    });
  }
}

FileHandle.prototype.close = function() {
  if (this._closed) {
    return Promise.resolve();
  }
  this._closed = true;
  try {
    var fd = this.fd;
    if (fd !== null && fd !== undefined) {
      fs.closeSync(fd);
    }
    this._fd = null;
    if (this._listeners && this._listeners.close) {
      var closeListeners = this._listeners.close.slice();
      for (var i = 0; i < closeListeners.length; i++) {
        closeListeners[i]();
      }
    }
    return Promise.resolve();
  } catch (err) {
    return Promise.reject(handleError(err));
  }
};

FileHandle.prototype.on = function(event, listener) {
  if (!this._listeners[event]) this._listeners[event] = [];
  this._listeners[event].push(listener);
  return this;
};

FileHandle.prototype.emit = function(event) {
  var listeners = this._listeners[event] || [];
  var args = [].slice.call(arguments, 1);
  for (var i = 0; i < listeners.length; i++) {
    listeners[i].apply(this, args);
  }
};

FileHandle.prototype.read = function(buffer, offset, length, position, callback) {
  var fd = this.fd;
  if (fd === null || fd === undefined) {
    return Promise.reject(new Error('File descriptor is not open'));
  }
  if (typeof callback === 'function') {
    return fs.read(fd, buffer, offset, length, position, callback);
  }
  // Node supports read(buffer[, options]) and read([options]) in addition to
  // the positional read(buffer, offset, length, position) form. Detect the
  // options-object variants; a real buffer is an ArrayBuffer view, an options
  // bag is a plain object.
  if (buffer != null && typeof buffer === 'object' && !ArrayBuffer.isView(buffer)) {
    var readOpts = buffer;
    buffer = readOpts.buffer;
    offset = readOpts.offset;
    length = readOpts.length;
    position = readOpts.position;
  } else if (offset != null && typeof offset === 'object') {
    var readOpts2 = offset;
    offset = readOpts2.offset;
    length = readOpts2.length;
    position = readOpts2.position;
  }
  if (buffer === undefined || buffer === null) {
    buffer = new Uint8Array(16384);
  }
  if (offset === undefined || offset === null) offset = 0;
  if (length === undefined || length === null) {
    var capacity = buffer.byteLength !== undefined ? buffer.byteLength : buffer.length;
    length = capacity - offset;
  }
  if (position === undefined) position = null;
  return new Promise(function(resolve, reject) {
    fs.read(fd, buffer, offset, length, position, function(err, bytesRead, data) {
      if (err) {
        reject(handleError(err));
        return;
      }
      resolve({ bytesRead: bytesRead, buffer: data });
    });
  });
};

FileHandle.prototype.write = function(buffer, offset, length, position) {
  var fd = this.fd;
  if (fd === null || fd === undefined) {
    return Promise.reject(new Error('File descriptor is not open'));
  }
  return new Promise(function(resolve, reject) {
    fs.write(fd, buffer, offset, length, position, function(err, bytesWritten, data) {
      if (err) {
        reject(handleError(err));
        return;
      }
      resolve({ bytesWritten: bytesWritten, buffer: data });
    });
  });
};

FileHandle.prototype.readFile = function(options) {
  var fd = this.fd;
  if (fd === null || fd === undefined) {
    return Promise.reject(new Error('File descriptor is not open'));
  }
  try {
    return Promise.resolve(fs.readFileSync(fd, options));
  } catch (err) {
    return Promise.reject(handleError(err));
  }
};

FileHandle.prototype.writeFile = function(data, options) {
  var fd = this.fd;
  if (fd === null || fd === undefined) {
    return Promise.reject(new Error('File descriptor is not open'));
  }
  try {
    fs.writeFileSync(fd, data, options);
    return Promise.resolve();
  } catch (err) {
    return Promise.reject(handleError(err));
  }
};

FileHandle.prototype.stat = function(options) {
  var fd = this.fd;
  if (fd === null || fd === undefined) {
    return Promise.reject(new Error('File descriptor is not open'));
  }
  try {
    return Promise.resolve(fs.fstatSync(fd, options));
  } catch (err) {
    return Promise.reject(handleError(err));
  }
};

FileHandle.prototype.chmod = function(mode) {
  var fd = this.fd;
  if (fd === null || fd === undefined) {
    return Promise.reject(new Error('File descriptor is not open'));
  }
  try {
    fs.fchmodSync(fd, mode);
    return Promise.resolve();
  } catch (err) {
    return Promise.reject(handleError(err));
  }
};

FileHandle.prototype.chown = function(uid, gid) {
  var fd = this.fd;
  if (fd === null || fd === undefined) {
    return Promise.reject(new Error('File descriptor is not open'));
  }
  try {
    fs.fchownSync(fd, uid, gid);
    return Promise.resolve();
  } catch (err) {
    return Promise.reject(handleError(err));
  }
};

FileHandle.prototype.readv = function(buffers, position) {
  var fd = this.fd;
  if (fd === null || fd === undefined) {
    return Promise.reject(new Error('File descriptor is not open'));
  }
  try {
    var bytesRead = fs.readvSync(fd, buffers, position);
    return Promise.resolve({ bytesRead: bytesRead, buffers: buffers });
  } catch (err) {
    return Promise.reject(handleError(err));
  }
};

FileHandle.prototype.writev = function(buffers, position) {
  var fd = this.fd;
  if (fd === null || fd === undefined) {
    return Promise.reject(new Error('File descriptor is not open'));
  }
  try {
    var bytesWritten = fs.writevSync(fd, buffers, position);
    return Promise.resolve({ bytesWritten: bytesWritten, buffers: buffers });
  } catch (err) {
    return Promise.reject(handleError(err));
  }
};

FileHandle.prototype.truncate = function(len) {
  var fd = this.fd;
  if (fd === null || fd === undefined) {
    return Promise.reject(new Error('File descriptor is not open'));
  }
  try {
    if (typeof fs.ftruncateSync === 'function') {
      fs.ftruncateSync(fd, len);
    } else if (typeof fs.truncateSync === 'function') {
      fs.truncateSync(this._path, len);
    }
    return Promise.resolve();
  } catch (err) {
    return Promise.reject(handleError(err));
  }
};

var promises = {
  readFile: function(filePath, options) {
    return withHandle(filePath, 'r', 0, function(handle) {
      var fd = handle.fd;
      return fs.readFileSync(filePath, options);
    });
  },
  writeFile: function(filePath, data, options) {
    // Forward options ({encoding, mode, flag}) straight to writeFileSync. The
    // previous implementation opened the file first with mode 0 (permission
    // 000) via withHandle, then wrote with no options, so {flag:'a'} truncated,
    // {flag:'wx'} never raised EEXIST, and new files landed with mode 000.
    try {
      fs.writeFileSync(filePath, data, options);
      return Promise.resolve();
    } catch (err) {
      return Promise.reject(handleError(err));
    }
  },
  truncate: function(filePath, len) {
    try {
      fs.truncateSync(filePath, len);
      return Promise.resolve();
    } catch (err) {
      return Promise.reject(handleError(err));
    }
  },
  lchmod: function(filePath, mode) {
    try {
      if (typeof fs.lchmodSync === 'function') {
        fs.lchmodSync(filePath, mode);
      } else if (typeof fs.chmodSync === 'function') {
        fs.chmodSync(filePath, mode);
      }
      return Promise.resolve();
    } catch (err) {
      return Promise.reject(handleError(err));
    }
  },
  open: function(filePath, flags, mode) {
    return new Promise(function(resolve, reject) {
      try {
        resolve(new FileHandle(fs.openSync(filePath, flags, mode)));
      } catch (err) {
        reject(handleError(err));
      }
    });
  },
  FileHandle: FileHandle,
  constants: base.constants || { F_OK: 0, R_OK: 4, W_OK: 2, X_OK: 1 },
  access: base.access || function(path, mode) { return Promise.resolve(fs.accessSync(path, mode)); },
  stat: base.stat || function(path) { return Promise.resolve(fs.statSync(path)); },
  lstat: base.lstat || function(path) { return Promise.resolve(fs.lstatSync(path)); },
  mkdir: base.mkdir || function(path, options) { fs.mkdirSync(path, options); return Promise.resolve(); },
  rmdir: base.rmdir || function(path) { fs.rmdirSync(path); return Promise.resolve(); },
  unlink: base.unlink || function(path) { fs.unlinkSync(path); return Promise.resolve(); },
  rename: base.rename || function(from, to) { fs.renameSync(from, to); return Promise.resolve(); },
  copyFile: base.copyFile || function(from, to) { fs.copyFileSync(from, to); return Promise.resolve(); },
  symlink: base.symlink || function(target, path) { fs.symlinkSync(target, path); return Promise.resolve(); },
  link: base.link || function(source, target) { fs.linkSync(source, target); return Promise.resolve(); },
  readlink: base.readlink || function(path) { return Promise.resolve(fs.readlinkSync(path)); },
  realpath: base.realpath || function(path) { return Promise.resolve(fs.realpathSync(path)); },
  readdir: base.readdir || function(path) { return Promise.resolve(fs.readdirSync(path)); },
  appendFile: base.appendFile || function(path, data) { fs.appendFileSync(path, data); return Promise.resolve(); },
  utimes: base.utimes || function(path, atime, mtime) { fs.utimesSync(path, atime, mtime); return Promise.resolve(); },
  chmod: base.chmod || function(path, mode) {
    try { fs.chmodSync(path, mode); return Promise.resolve(); }
    catch (err) { return Promise.reject(handleError(err)); }
  },
  chown: base.chown || function(path, uid, gid) { fs.chownSync(path, uid, gid); return Promise.resolve(); },
  lchown: base.lchown || function(path, uid, gid) {
    try { fs.lchownSync(path, uid, gid); return Promise.resolve(); }
    catch (err) { return Promise.reject(handleError(err)); }
  },
  lutimes: base.lutimes || function(path, atime, mtime) {
    try { fs.lutimesSync(path, atime, mtime); return Promise.resolve(); }
    catch (err) { return Promise.reject(handleError(err)); }
  },
  statfs: base.statfs || function(path, options) {
    try { return Promise.resolve(fs.statfsSync(path, options)); }
    catch (err) { return Promise.reject(handleError(err)); }
  },
  readv: base.readv || function(fd, buffers, position) {
    try {
      return Promise.resolve({
        bytesRead: fs.readvSync(fd, buffers, position),
        buffers: buffers,
      });
    } catch (err) {
      return Promise.reject(handleError(err));
    }
  },
  writev: base.writev || function(fd, buffers, position) {
    try {
      return Promise.resolve({
        bytesWritten: fs.writevSync(fd, buffers, position),
        buffers: buffers,
      });
    } catch (err) {
      return Promise.reject(handleError(err));
    }
  },
  fdatasync: base.fdatasync || function(fd) { return Promise.resolve(); },
  fsync: base.fsync || function(fd) { return Promise.resolve(); },
  sendFile: base.sendFile,
  opendir: base.opendir || function(path, options) {
    try {
      var dir = fs.opendirSync(path, options);
      return Promise.resolve(dir);
    } catch (err) {
      return Promise.reject(handleError(err));
    }
  },
  rm: base.rm || function(path, options) { fs.rmSync(path, options || {}); return Promise.resolve(); },
  mkdtemp: base.mkdtemp || function(prefix) { return Promise.resolve(fs.mkdtempSync(prefix)); },
  readFileSync: function(path, options) { return fs.readFileSync(path, options); },
  // Some admitted host surfaces enumerate an own `toString`. Declare that
  // hazardous inherited name statically so the fallback copy remains both
  // lockdown-safe and visible to the capability-surface scanner.
  toString: base.toString,
};

for (var key in base) {
  if (key === 'FileHandle' || key === 'constants') continue;
  if (!Object.prototype.hasOwnProperty.call(promises, key)) {
    promises[key] = base[key];
  }
}

module.exports = promises;
