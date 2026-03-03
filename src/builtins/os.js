var _platform = (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.platform) || "darwin";
var _arch = (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.arch) || "arm64";
var _processPriority = 0;

function legacyStringValue(getter) {
  var fn = function() {
    return getter();
  };
  fn.toString = function() {
    var value = getter();
    if (value === undefined || value === null) return "";
    return String(value);
  };
  fn.valueOf = fn.toString;
  return fn;
}

function legacyNumberValue(getter) {
  var fn = function() {
    return getter();
  };
  fn.toString = function() {
    return String(getter());
  };
  fn.valueOf = function() {
    return Number(getter());
  };
  return fn;
}

function platform() { return _platform; }
function arch() { return _arch; }
function type() {
  if (_platform === "darwin") return "Darwin";
  if (_platform === "linux") return "Linux";
  if (_platform === "win32") return "Windows_NT";
  return "Unknown";
}
function release() {
  if (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.version) {
    return globalThis.process.version;
  }
  return "0.0.0";
}
function homedir() {
  if (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.env) {
    return globalThis.process.env.HOME || globalThis.process.env.USERPROFILE || "/";
  }
  return "/";
}
function tmpdir() {
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
  if (typeof __exactGetOsVersion === 'function') {
    return __exactGetOsVersion();
  }
  return release();
}
function machine() { return _arch; }
function availableParallelism() {
  return cpus().length > 0 ? cpus().length : 1;
}

function getPriority() {
  return _processPriority;
}

function setPriority() {
  var value = null;
  if (arguments.length === 1 && typeof arguments[0] === 'number') {
    value = arguments[0];
  } else if (arguments.length > 1 && typeof arguments[1] === 'number') {
    value = arguments[1];
  }
  if (value === null || isNaN(value)) {
    return 0;
  }
  _processPriority = value;
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
function endianness() { return "LE"; }
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

var constants = {
  signals: {
    SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
    SIGIOT: 6, SIGBUS: 10, SIGFPE: 8, SIGKILL: 9, SIGUSR1: 30, SIGSEGV: 11,
    SIGUSR2: 31, SIGPIPE: 13, SIGALRM: 14, SIGTERM: 15, SIGCHLD: 20,
    SIGCONT: 19, SIGSTOP: 17, SIGTSTP: 18, SIGTTIN: 21, SIGTTOU: 22,
    SIGURG: 16, SIGXCPU: 24, SIGXFSZ: 25, SIGVTALRM: 26, SIGPROF: 27,
    SIGWINCH: 28, SIGIO: 23, SIGINFO: 29, SIGSYS: 12
  },
  errno: {},
  priority: {
    PRIORITY_LOW: 10,
    PRIORITY_BELOW_NORMAL: 5,
    PRIORITY_NORMAL: 0,
    PRIORITY_ABOVE_NORMAL: -2,
    PRIORITY_HIGH: -5
  }
};

module.exports = {
  platform: legacyStringValue(platform),
  arch: legacyStringValue(arch),
  type: legacyStringValue(type),
  release: legacyStringValue(release),
  homedir: legacyStringValue(homedir),
  tmpdir: legacyStringValue(tmpdir),
  hostname: legacyStringValue(hostname),
  cpus: cpus,
  totalmem: legacyNumberValue(totalmem),
  freemem: legacyNumberValue(freemem),
  uptime: legacyNumberValue(uptime),
  endianness: legacyStringValue(endianness),
  networkInterfaces: networkInterfaces,
  loadavg: loadavg,
  version: legacyStringValue(version),
  machine: legacyStringValue(machine),
  availableParallelism: legacyNumberValue(availableParallelism),
  getPriority: getPriority,
  setPriority: setPriority,
  userInfo: userInfoCompat,
  EOL: EOL,
  devNull: devNull,
  constants: constants
};
