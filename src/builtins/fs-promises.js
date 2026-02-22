var fs = require('node:fs');
var base = fs.promises || {};

function FileHandle(fd, path, flags) {
  this._fd = fd;
  this._path = path;
  this._flags = flags || 'r';
  this._closed = false;
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
    return Promise.resolve();
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
    if (typeof fs.truncateSync === 'function') {
      fs.truncateSync(this._path, len);
    } else {
      fs.ftruncateSync(fd, len);
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
    return withHandle(filePath, 'w', 0, function(handle) {
      var fd = handle.fd;
      fs.writeFileSync(filePath, data);
      return null;
    });
  },
  truncate: function(filePath, len) {
    return withHandle(filePath, 'r', 0, function(handle) {
      var fd = handle.fd;
      fs.truncateSync(filePath, len);
      return null;
    });
  },
  lchmod: function(filePath, mode) {
    return withHandle(filePath, 'r', 0, function(handle) {
      var fd = handle.fd;
      if (typeof fs.lchmodSync === 'function') {
        fs.lchmodSync(filePath, mode);
      } else if (typeof fs.chmodSync === 'function') {
        fs.chmodSync(filePath, mode);
      }
      return null;
    });
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
  constants: base.constants || { F_OK: 0, R_OK: 1, W_OK: 2, X_OK: 4 },
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
  chown: base.chown || function(path, uid, gid) { fs.chownSync(path, uid, gid); return Promise.resolve(); },
  readv: base.readv || function(fd, buffers, position) { return Promise.resolve(); },
  writev: base.writev || function(fd, buffers, position) { return Promise.resolve(); },
  fdatasync: base.fdatasync || function(fd) { return Promise.resolve(); },
  fsync: base.fsync || function(fd) { return Promise.resolve(); },
  sendFile: base.sendFile,
  opendir: base.opendir || function(path, options) { return Promise.resolve({ path: path, options: options }); },
  rm: base.rm || function(path, options) { fs.rmSync(path, options || {}); return Promise.resolve(); },
  mkdtemp: base.mkdtemp || function(prefix) { return Promise.resolve(fs.mkdtempSync(prefix)); },
  readFileSync: function(path, options) { return fs.readFileSync(path, options); },
};

for (var key in base) {
  if (key === 'FileHandle' || key === 'constants') continue;
  if (typeof promises[key] === 'undefined') {
    promises[key] = base[key];
  }
}

module.exports = promises;
