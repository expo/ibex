//#region src/builtins/constants.js
var _platform = typeof process !== "undefined" && process.platform || "darwin";
var _arch = typeof process !== "undefined" && process.arch || "arm64";
var _signalsDarwin = {
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
};
var _signalsLinux = {
	SIGHUP: 1,
	SIGINT: 2,
	SIGQUIT: 3,
	SIGILL: 4,
	SIGTRAP: 5,
	SIGABRT: 6,
	SIGIOT: 6,
	SIGBUS: 7,
	SIGFPE: 8,
	SIGKILL: 9,
	SIGUSR1: 10,
	SIGSEGV: 11,
	SIGUSR2: 12,
	SIGPIPE: 13,
	SIGALRM: 14,
	SIGTERM: 15,
	SIGSTKFLT: 16,
	SIGCHLD: 17,
	SIGCONT: 18,
	SIGSTOP: 19,
	SIGTSTP: 20,
	SIGTTIN: 21,
	SIGTTOU: 22,
	SIGURG: 23,
	SIGXCPU: 24,
	SIGXFSZ: 25,
	SIGVTALRM: 26,
	SIGPROF: 27,
	SIGWINCH: 28,
	SIGIO: 29,
	SIGPOLL: 29,
	SIGPWR: 30,
	SIGSYS: 31
};
function _fallbackSignals() {
	return _platform === "linux" || _platform === "android" ? _signalsLinux : _signalsDarwin;
}
function _signalNumbers() {
	var fallback = _fallbackSignals();
	var out = {};
	for (var fk in fallback) out[fk] = fallback[fk];
	var nativeMap = null;
	if (typeof globalThis !== "undefined" && globalThis.__exactSignalNumbersMap) nativeMap = globalThis.__exactSignalNumbersMap;
	else if (typeof __exactSignalNumbers === "function") try {
		nativeMap = __exactSignalNumbers();
	} catch (_) {}
	if (nativeMap) {
		for (var nk in nativeMap) if (typeof nativeMap[nk] === "number") out[nk] = nativeMap[nk];
	}
	return out;
}
function _fsFlags() {
	var out = {
		O_RDONLY: 0,
		O_WRONLY: 1,
		O_RDWR: 2
	};
	if (_platform === "linux" || _platform === "android") {
		var linuxX86 = _arch === "x64" || _arch === "ia32";
		out.O_CREAT = 64;
		out.O_EXCL = 128;
		out.O_NOCTTY = 256;
		out.O_TRUNC = 512;
		out.O_APPEND = 1024;
		out.O_NONBLOCK = 2048;
		out.O_DSYNC = 4096;
		out.O_DIRECT = linuxX86 ? 16384 : 65536;
		out.O_DIRECTORY = linuxX86 ? 65536 : 16384;
		out.O_NOFOLLOW = linuxX86 ? 131072 : 32768;
		out.O_NOATIME = 262144;
		out.O_SYNC = 1052672;
	} else {
		out.O_CREAT = 512;
		out.O_EXCL = 2048;
		out.O_NOCTTY = 131072;
		out.O_TRUNC = 1024;
		out.O_APPEND = 8;
		out.O_NONBLOCK = 4;
		out.O_DSYNC = 4194304;
		out.O_DIRECTORY = 1048576;
		out.O_NOFOLLOW = 256;
		out.O_SYNC = 128;
		out.O_SYMLINK = 2097152;
	}
	return out;
}
var _errnoDarwin = {
	E2BIG: 7,
	EACCES: 13,
	EADDRINUSE: 48,
	EADDRNOTAVAIL: 49,
	EAFNOSUPPORT: 47,
	EAGAIN: 35,
	EALREADY: 37,
	EBADF: 9,
	EBADMSG: 94,
	EBUSY: 16,
	ECANCELED: 89,
	ECHILD: 10,
	ECONNABORTED: 53,
	ECONNREFUSED: 61,
	ECONNRESET: 54,
	EDEADLK: 11,
	EDESTADDRREQ: 39,
	EDOM: 33,
	EEXIST: 17,
	EFAULT: 14,
	EFBIG: 27,
	EHOSTUNREACH: 65,
	EIDRM: 90,
	EILSEQ: 92,
	EINPROGRESS: 36,
	EINTR: 4,
	EINVAL: 22,
	EIO: 5,
	EISCONN: 56,
	EISDIR: 21,
	ELOOP: 62,
	EMFILE: 24,
	EMLINK: 31,
	EMSGSIZE: 40,
	ENAMETOOLONG: 63,
	ENETDOWN: 50,
	ENETRESET: 52,
	ENETUNREACH: 51,
	ENFILE: 23,
	ENOBUFS: 55,
	ENODEV: 19,
	ENOENT: 2,
	ENOMEM: 12,
	ENOPROTOOPT: 42,
	ENOSPC: 28,
	ENOSYS: 78,
	ENOTCONN: 57,
	ENOTDIR: 20,
	ENOTEMPTY: 66,
	ENOTSOCK: 38,
	ENOTSUP: 45,
	ENOTTY: 25,
	ENXIO: 6,
	EOPNOTSUPP: 102,
	EOVERFLOW: 84,
	EPERM: 1,
	EPIPE: 32,
	EPROTO: 100,
	EPROTONOSUPPORT: 43,
	EPROTOTYPE: 41,
	ERANGE: 34,
	EROFS: 30,
	ESPIPE: 29,
	ESRCH: 3,
	ETIMEDOUT: 60,
	ETXTBSY: 26,
	EXDEV: 18
};
var _errnoLinux = {
	E2BIG: 7,
	EACCES: 13,
	EADDRINUSE: 98,
	EADDRNOTAVAIL: 99,
	EAFNOSUPPORT: 97,
	EAGAIN: 11,
	EALREADY: 114,
	EBADF: 9,
	EBADMSG: 74,
	EBUSY: 16,
	ECANCELED: 125,
	ECHILD: 10,
	ECONNABORTED: 103,
	ECONNREFUSED: 111,
	ECONNRESET: 104,
	EDEADLK: 35,
	EDESTADDRREQ: 89,
	EDOM: 33,
	EDQUOT: 122,
	EEXIST: 17,
	EFAULT: 14,
	EFBIG: 27,
	EHOSTUNREACH: 113,
	EIDRM: 43,
	EILSEQ: 84,
	EINPROGRESS: 115,
	EINTR: 4,
	EINVAL: 22,
	EIO: 5,
	EISCONN: 106,
	EISDIR: 21,
	ELOOP: 40,
	EMFILE: 24,
	EMLINK: 31,
	EMSGSIZE: 90,
	EMULTIHOP: 72,
	ENAMETOOLONG: 36,
	ENETDOWN: 100,
	ENETRESET: 102,
	ENETUNREACH: 101,
	ENFILE: 23,
	ENOBUFS: 105,
	ENODATA: 61,
	ENODEV: 19,
	ENOENT: 2,
	ENOMEM: 12,
	ENOLINK: 67,
	ENOPROTOOPT: 92,
	ENOSPC: 28,
	ENOSR: 63,
	ENOSTR: 60,
	ENOSYS: 38,
	ENOTCONN: 107,
	ENOTDIR: 20,
	ENOTEMPTY: 39,
	ENOTSOCK: 88,
	ENOTSUP: 95,
	ENOTTY: 25,
	ENXIO: 6,
	EOPNOTSUPP: 95,
	EOVERFLOW: 75,
	EPERM: 1,
	EPIPE: 32,
	EPROTO: 71,
	EPROTONOSUPPORT: 93,
	EPROTOTYPE: 91,
	ERANGE: 34,
	EROFS: 30,
	ESPIPE: 29,
	ESRCH: 3,
	ESTALE: 116,
	ETIME: 62,
	ETIMEDOUT: 110,
	ETXTBSY: 26,
	EWOULDBLOCK: 11,
	EXDEV: 18
};
function _errno() {
	return _platform === "linux" || _platform === "android" ? _errnoLinux : _errnoDarwin;
}
var constants = {};
function _assign(values) {
	for (var key in values) constants[key] = values[key];
}
_assign(_signalNumbers());
_assign(_fsFlags());
_assign({
	S_IFMT: 61440,
	S_IFREG: 32768,
	S_IFDIR: 16384,
	S_IFCHR: 8192,
	S_IFBLK: 24576,
	S_IFIFO: 4096,
	S_IFLNK: 40960,
	S_IFSOCK: 49152,
	S_IRWXU: 448,
	S_IRUSR: 256,
	S_IWUSR: 128,
	S_IXUSR: 64,
	S_IRWXG: 56,
	S_IRGRP: 32,
	S_IWGRP: 16,
	S_IXGRP: 8,
	S_IRWXO: 7,
	S_IROTH: 4,
	S_IWOTH: 2,
	S_IXOTH: 1,
	F_OK: 0,
	R_OK: 4,
	W_OK: 2,
	X_OK: 1,
	UV_UDP_REUSEADDR: 4
});
_assign(_errno());
module.exports = constants;
//#endregion
