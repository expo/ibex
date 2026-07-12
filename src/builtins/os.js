var _platform = (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.platform) || "darwin";
var _arch = (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.arch) || "arm64";
var _processPriority = 0;

function legacyStringValue(getter) {
  getter.toString = function() {
    var value = getter();
    if (value === undefined || value === null) return "";
    return String(value);
  };
  getter.valueOf = getter.toString;
  return getter;
}

function legacyNumberValue(getter) {
  getter.toString = function() {
    return String(getter());
  };
  getter.valueOf = function() {
    return Number(getter());
  };
  return getter;
}

function authorizeSystemInfo(kind) {
  if (typeof __exactAuthorizeSystemInfo === 'function') {
    __exactAuthorizeSystemInfo(kind);
  }
}

function androidPlatformVersion() {
  // @ref LLP 0008#os-info — Android reports the Java host SDK version through os.release/version.
  if (_platform !== "android" || typeof globalThis === "undefined") return null;
  if (typeof globalThis.__exactPlatformVersion === "string" &&
      globalThis.__exactPlatformVersion.length > 0) {
    return globalThis.__exactPlatformVersion;
  }
  if (globalThis.process &&
      typeof globalThis.process.__exactOSRelease === "string" &&
      globalThis.process.__exactOSRelease.length > 0) {
    return globalThis.process.__exactOSRelease;
  }
  return null;
}

function platform() {
  authorizeSystemInfo(11);
  return _platform;
}
function arch() {
  authorizeSystemInfo(0);
  return _arch;
}
function type() {
  authorizeSystemInfo(11);
  if (_platform === "android") return "Android";
  if (_platform === "darwin") return "Darwin";
  if (_platform === "linux") return "Linux";
  if (_platform === "win32") return "Windows_NT";
  return "Unknown";
}
function release() {
  authorizeSystemInfo(10);
  var androidVersion = androidPlatformVersion();
  if (androidVersion) return androidVersion;
  if (typeof globalThis !== "undefined" && globalThis.process) {
    if (globalThis.process.__exactOSRelease) return globalThis.process.__exactOSRelease;
  }
  return "0.0.0";
}
function homedir() {
  authorizeSystemInfo(13);
  if (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.env) {
    return globalThis.process.env.HOME || globalThis.process.env.USERPROFILE || "/";
  }
  return "/";
}
function tmpdir() {
  authorizeSystemInfo(13);
  if (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.env) {
    var tempPath =
      globalThis.process.env.TMPDIR ||
      globalThis.process.env.TMP ||
      globalThis.process.env.TEMP ||
      "/tmp";
    if (typeof tempPath === "string" &&
        tempPath.length > 1 &&
        tempPath[tempPath.length - 1] === "/" &&
        tempPath.indexOf('\\') === -1) {
      return tempPath.slice(0, -1);
    }
    return tempPath;
  }
  return "/tmp";
}
function hostname() {
  if (typeof __exactGetHostname === 'function') return __exactGetHostname();
  return "localhost";
}
function version() {
  authorizeSystemInfo(10);
  var androidVersion = androidPlatformVersion();
  if (androidVersion) return "Android " + androidVersion;
  if (typeof __exactGetOsVersion === 'function') {
    return __exactGetOsVersion();
  }
  if (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.__exactOSVersion) {
    return globalThis.process.__exactOSVersion;
  }
  return release();
}
function machine() {
  authorizeSystemInfo(0);
  return _arch;
}
function availableParallelism() {
  var processors = cpus();
  return processors.length > 0 ? processors.length : 1;
}

function _validatePid(pid) {
  if (pid !== undefined && typeof pid !== 'number') {
    var err = new TypeError('The "pid" argument must be of type number. Received type ' + typeof pid);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (pid !== undefined && typeof pid === 'number') {
    if (!Number.isFinite(pid) || pid !== Math.trunc(pid) || pid > 2147483647 || pid < -2147483648) {
      var err2 = new RangeError('The value of "pid" is out of range. It must be an integer. Received ' + pid);
      err2.code = 'ERR_OUT_OF_RANGE';
      throw err2;
    }
  }
}
function _validatePriority(priority) {
  if (typeof priority !== 'number') {
    var err = new TypeError('The "priority" argument must be of type number. Received type ' + typeof priority);
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }
  if (!Number.isFinite(priority) || priority !== Math.trunc(priority) || priority < -20 || priority > 19) {
    var err2 = new RangeError('The value of "priority" is out of range. It must be >= ' + (-20) + ' && <= 19. Received ' + priority);
    err2.code = 'ERR_OUT_OF_RANGE';
    throw err2;
  }
}
function getPriority(pid) {
  if (pid !== undefined) _validatePid(pid);
  if (typeof pid === 'number' && pid < 0) {
    var sysErr = new Error('A system error occurred: uv_os_getpriority returned ESRCH (no such process)');
    sysErr.code = 'ERR_SYSTEM_ERROR';
    sysErr.name = 'SystemError';
    sysErr.info = { code: 'ESRCH', message: 'no such process', syscall: 'uv_os_getpriority' };
    throw sysErr;
  }
  return _processPriority;
}

function setPriority(pid, priority) {
  if (priority === undefined) {
    priority = pid;
    pid = 0;
  }
  _validatePid(pid);
  _validatePriority(priority);
  _processPriority = priority;
  return 0;
}
function cpus() {
  var count = 0;
  if (typeof __exactGetCpuCount === 'function') count = __exactGetCpuCount();
  if (count <= 0) return [];
  var result = [];
  for (var i = 0; i < count; i++) {
    result.push({ model: "unknown", speed: 0, times: { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 } });
  }
  return result;
}
function totalmem() {
  if (typeof __exactGetTotalMem === 'function') return __exactGetTotalMem();
  return 0;
}
function freemem() {
  if (typeof __exactGetFreeMem === 'function') return __exactGetFreeMem();
  return 0;
}
function uptime() {
  if (typeof __exactGetUptime === 'function') {
    var value = __exactGetUptime();
    if (isFinite(Number(value))) {
      return Number(value);
    }
  }
  return 1;
}
function endianness() {
  authorizeSystemInfo(0);
  return "LE";
}
function networkInterfaces() {
  if (typeof __exactGetNetworkInterfaces === 'function') return __exactGetNetworkInterfaces();
  return {};
}
function loadavg() {
  if (typeof __exactGetLoadAvg === 'function') return __exactGetLoadAvg();
  return [0, 0, 0];
}
function userInfo() {
  if (typeof __exactGetUserInfo === 'function') {
    var info = __exactGetUserInfo();
    return {
      uid: info.uid !== undefined ? info.uid : -1,
      gid: info.gid !== undefined ? info.gid : -1,
      username: info.username || "",
      homedir: info.homedir || homedir(),
      shell: info.shell !== undefined ? info.shell : null
    };
  }
  return {
    uid: -1,
    gid: -1,
    username: "",
    homedir: homedir(),
    shell: null
  };
}
function toBufferValue(value) {
  if (typeof Buffer === 'function' && Buffer.from) {
    return Buffer.from(value || "", "utf8");
  }
  return value;
}
function userInfoCompat(options) {
  var info = userInfo();
  if (!options || options.encoding !== "buffer") {
    return info;
  }
  return {
    uid: info.uid,
    gid: info.gid,
    username: toBufferValue(info.username),
    shell: info.shell === null ? null : toBufferValue(info.shell),
    homedir: toBufferValue(info.homedir)
  };
}

var EOL = _platform === "win32" ? "\r\n" : "\n";
var devNull = _platform === "win32" ? "\\\\.\\NUL" : "/dev/null";

function pickConstants(prefixRe) {
  var out = {};
  try {
    var nodeConstants = require('constants');
    var keys = Object.keys(nodeConstants || {});
    for (var i = 0; i < keys.length; i++) {
      if (prefixRe.test(keys[i]) && typeof nodeConstants[keys[i]] === 'number') {
        out[keys[i]] = nodeConstants[keys[i]];
      }
    }
  } catch (_) { /* ignored: optional constants module; the section stays empty */ }
  return out;
}

var constants = {
  signals: pickConstants(/^SIG/),
  errno: pickConstants(/^E[A-Z0-9]+$/),
  priority: {
    PRIORITY_LOW: 19,
    PRIORITY_BELOW_NORMAL: 10,
    PRIORITY_NORMAL: 0,
    PRIORITY_ABOVE_NORMAL: -7,
    PRIORITY_HIGH: -14,
    PRIORITY_HIGHEST: -20
  }
};
Object.freeze(constants.signals);
Object.freeze(constants.errno);
Object.freeze(constants.priority);
Object.freeze(constants);

legacyStringValue(platform);
legacyStringValue(arch);
legacyStringValue(type);
legacyStringValue(release);
legacyStringValue(homedir);
legacyStringValue(tmpdir);
legacyStringValue(hostname);
legacyNumberValue(totalmem);
legacyNumberValue(freemem);
legacyNumberValue(uptime);
legacyStringValue(endianness);
legacyStringValue(version);
legacyStringValue(machine);
legacyNumberValue(availableParallelism);

module.exports = {
  platform: platform,
  arch: arch,
  type: type,
  release: release,
  homedir: homedir,
  tmpdir: tmpdir,
  hostname: hostname,
  cpus: cpus,
  totalmem: totalmem,
  freemem: freemem,
  uptime: uptime,
  endianness: endianness,
  networkInterfaces: networkInterfaces,
  loadavg: loadavg,
  version: version,
  machine: machine,
  availableParallelism: availableParallelism,
  getPriority: getPriority,
  setPriority: setPriority,
  userInfo: userInfoCompat,
  devNull: devNull,
  constants: constants
};
Object.defineProperty(module.exports, 'EOL', {
  value: EOL,
  writable: false,
  enumerable: true,
  configurable: true
});
