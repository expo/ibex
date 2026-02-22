var _platform = (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.platform) || "darwin";
var _arch = (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.arch) || "arm64";

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
    return globalThis.process.env.TMPDIR || globalThis.process.env.TMP || "/tmp";
  }
  return "/tmp";
}
function hostname() {
  if (typeof __exactGetHostname === 'function') return __exactGetHostname();
  return "localhost";
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
  if (typeof __exactGetUptime === 'function') return __exactGetUptime();
  return 0;
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

var EOL = _platform === "win32" ? "\r\n" : "\n";
var devNull = _platform === "win32" ? "\\\\.\\NUL" : "/dev/null";

var constants = {
  signals: {},
  errno: {},
  priority: {}
};

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
  userInfo: userInfo,
  EOL: EOL,
  devNull: devNull,
  constants: constants
};
