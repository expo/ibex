//#region src/builtins/os.js
var _platform = typeof globalThis !== "undefined" && globalThis.process && globalThis.process.platform || "darwin";
var _arch = typeof globalThis !== "undefined" && globalThis.process && globalThis.process.arch || "arm64";
var _processPriority = 0;
function legacyStringValue(getter) {
	var fn = function() {
		return getter();
	};
	fn.toString = function() {
		var value = getter();
		if (value === void 0 || value === null) return "";
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
function androidPlatformVersion() {
	if (_platform !== "android" || typeof globalThis === "undefined") return null;
	if (typeof globalThis.__exactPlatformVersion === "string" && globalThis.__exactPlatformVersion.length > 0) return globalThis.__exactPlatformVersion;
	if (globalThis.process && typeof globalThis.process.__exactOSRelease === "string" && globalThis.process.__exactOSRelease.length > 0) return globalThis.process.__exactOSRelease;
	return null;
}
function platform() {
	return _platform;
}
function arch() {
	return _arch;
}
function type() {
	if (_platform === "android") return "Android";
	if (_platform === "darwin") return "Darwin";
	if (_platform === "linux") return "Linux";
	if (_platform === "win32") return "Windows_NT";
	return "Unknown";
}
function release() {
	var androidVersion = androidPlatformVersion();
	if (androidVersion) return androidVersion;
	if (typeof globalThis !== "undefined" && globalThis.process) {
		if (globalThis.process.__exactOSRelease) return globalThis.process.__exactOSRelease;
	}
	return "0.0.0";
}
function homedir() {
	if (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.env) return globalThis.process.env.HOME || globalThis.process.env.USERPROFILE || "/";
	return "/";
}
function tmpdir() {
	if (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.env) {
		var tempPath = globalThis.process.env.TMPDIR || globalThis.process.env.TMP || globalThis.process.env.TEMP || "/tmp";
		if (typeof tempPath === "string" && tempPath.length > 1 && tempPath[tempPath.length - 1] === "/" && tempPath.indexOf("\\") === -1) return tempPath.slice(0, -1);
		return tempPath;
	}
	return "/tmp";
}
function hostname() {
	if (typeof __exactGetHostname === "function") return __exactGetHostname();
	return "localhost";
}
function version() {
	var androidVersion = androidPlatformVersion();
	if (androidVersion) return "Android " + androidVersion;
	if (typeof __exactGetOsVersion === "function") return __exactGetOsVersion();
	if (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.__exactOSVersion) return globalThis.process.__exactOSVersion;
	return release();
}
function machine() {
	return _arch;
}
function availableParallelism() {
	return cpus().length > 0 ? cpus().length : 1;
}
function _validatePid(pid) {
	if (pid !== void 0 && typeof pid !== "number") {
		var err = /* @__PURE__ */ new TypeError("The \"pid\" argument must be of type number. Received type " + typeof pid);
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	if (pid !== void 0 && typeof pid === "number") {
		if (!Number.isFinite(pid) || pid !== Math.trunc(pid) || pid > 2147483647 || pid < -2147483648) {
			var err2 = /* @__PURE__ */ new RangeError("The value of \"pid\" is out of range. It must be an integer. Received " + pid);
			err2.code = "ERR_OUT_OF_RANGE";
			throw err2;
		}
	}
}
function _validatePriority(priority) {
	if (typeof priority !== "number") {
		var err = /* @__PURE__ */ new TypeError("The \"priority\" argument must be of type number. Received type " + typeof priority);
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	if (!Number.isFinite(priority) || priority !== Math.trunc(priority) || priority < -20 || priority > 19) {
		var err2 = /* @__PURE__ */ new RangeError("The value of \"priority\" is out of range. It must be >= -20 && <= 19. Received " + priority);
		err2.code = "ERR_OUT_OF_RANGE";
		throw err2;
	}
}
function getPriority(pid) {
	if (pid !== void 0) _validatePid(pid);
	if (typeof pid === "number" && pid < 0) {
		var sysErr = /* @__PURE__ */ new Error("A system error occurred: uv_os_getpriority returned ESRCH (no such process)");
		sysErr.code = "ERR_SYSTEM_ERROR";
		sysErr.name = "SystemError";
		sysErr.info = {
			code: "ESRCH",
			message: "no such process",
			syscall: "uv_os_getpriority"
		};
		throw sysErr;
	}
	return _processPriority;
}
function setPriority(pid, priority) {
	if (priority === void 0) {
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
	if (typeof __exactGetCpuCount === "function") count = __exactGetCpuCount();
	if (count <= 0) return [];
	var result = [];
	for (var i = 0; i < count; i++) result.push({
		model: "unknown",
		speed: 0,
		times: {
			user: 0,
			nice: 0,
			sys: 0,
			idle: 0,
			irq: 0
		}
	});
	return result;
}
function totalmem() {
	if (typeof __exactGetTotalMem === "function") return __exactGetTotalMem();
	return 0;
}
function freemem() {
	if (typeof __exactGetFreeMem === "function") return __exactGetFreeMem();
	return 0;
}
function uptime() {
	if (typeof __exactGetUptime === "function") {
		var value = __exactGetUptime();
		if (isFinite(Number(value))) return Number(value);
	}
	return 1;
}
function endianness() {
	return "LE";
}
function networkInterfaces() {
	if (typeof __exactGetNetworkInterfaces === "function") return __exactGetNetworkInterfaces();
	return {};
}
function loadavg() {
	if (typeof __exactGetLoadAvg === "function") return __exactGetLoadAvg();
	return [
		0,
		0,
		0
	];
}
function userInfo() {
	if (typeof __exactGetUserInfo === "function") {
		var info = __exactGetUserInfo();
		return {
			uid: info.uid !== void 0 ? info.uid : -1,
			gid: info.gid !== void 0 ? info.gid : -1,
			username: info.username || "",
			homedir: info.homedir || homedir(),
			shell: info.shell !== void 0 ? info.shell : null
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
	if (typeof Buffer === "function" && Buffer.from) return Buffer.from(value || "", "utf8");
	return value;
}
function userInfoCompat(options) {
	var info = userInfo();
	if (!options || options.encoding !== "buffer") return info;
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
		SIGHUP: 1,
		SIGINT: 2,
		SIGQUIT: 3,
		SIGILL: 4,
		SIGTRAP: 5,
		SIGABRT: 6,
		SIGIOT: 6,
		SIGBUS: 10,
		SIGFPE: 8,
		SIGKILL: 9,
		SIGUSR1: 30,
		SIGSEGV: 11,
		SIGUSR2: 31,
		SIGPIPE: 13,
		SIGALRM: 14,
		SIGTERM: 15,
		SIGCHLD: 20,
		SIGCONT: 19,
		SIGSTOP: 17,
		SIGTSTP: 18,
		SIGTTIN: 21,
		SIGTTOU: 22,
		SIGURG: 16,
		SIGXCPU: 24,
		SIGXFSZ: 25,
		SIGVTALRM: 26,
		SIGPROF: 27,
		SIGWINCH: 28,
		SIGIO: 23,
		SIGINFO: 29,
		SIGSYS: 12
	},
	errno: {},
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
module.exports = {
	platform: legacyStringValue(platform),
	arch: legacyStringValue(arch),
	type: legacyStringValue(type),
	release: legacyStringValue(release),
	homedir: legacyStringValue(homedir),
	tmpdir: legacyStringValue(tmpdir),
	hostname: legacyStringValue(hostname),
	cpus,
	totalmem: legacyNumberValue(totalmem),
	freemem: legacyNumberValue(freemem),
	uptime: legacyNumberValue(uptime),
	endianness: legacyStringValue(endianness),
	networkInterfaces,
	loadavg,
	version: legacyStringValue(version),
	machine: legacyStringValue(machine),
	availableParallelism: legacyNumberValue(availableParallelism),
	getPriority,
	setPriority,
	userInfo: userInfoCompat,
	devNull,
	constants
};
Object.defineProperty(module.exports, "EOL", {
	value: EOL,
	writable: false,
	enumerable: true,
	configurable: true
});
//#endregion
