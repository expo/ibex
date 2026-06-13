//#region src/builtins/tty.js
var net;
try {
	net = require("net");
} catch (e) {
	net = null;
}
var EventEmitter;
try {
	EventEmitter = require("events");
} catch (e) {
	EventEmitter = null;
}
function isatty(fd) {
	if (typeof fd !== "number") return false;
	var p = typeof globalThis !== "undefined" && globalThis.process;
	if (!p) return false;
	if (fd === 0) return !!(p.stdin && p.stdin.isTTY);
	if (fd === 1) return !!(p.stdout && p.stdout.isTTY);
	if (fd === 2) return !!(p.stderr && p.stderr.isTTY);
	return false;
}
function ReadStream(fd, options) {
	if (!(this instanceof ReadStream)) return new ReadStream(fd, options);
	if (net && net.Socket) net.Socket.call(this, Object.assign({}, options, {
		readable: true,
		writable: false
	}));
	else if (EventEmitter) EventEmitter.call(this);
	this.fd = fd !== void 0 ? fd : 0;
	this.isTTY = false;
	this.isRaw = false;
}
if (net && net.Socket && net.Socket.prototype) {
	ReadStream.prototype = Object.create(net.Socket.prototype);
	if (typeof Object.setPrototypeOf === "function") Object.setPrototypeOf(ReadStream, net.Socket);
} else if (EventEmitter && EventEmitter.prototype) ReadStream.prototype = Object.create(EventEmitter.prototype);
else ReadStream.prototype = {};
ReadStream.prototype.constructor = ReadStream;
ReadStream.prototype.setRawMode = function setRawMode(mode) {
	this.isRaw = !!mode;
	return this;
};
function WriteStream(fd, options) {
	if (!(this instanceof WriteStream)) return new WriteStream(fd, options);
	if (net && net.Socket) net.Socket.call(this, Object.assign({}, options, {
		readable: false,
		writable: true
	}));
	else if (EventEmitter) EventEmitter.call(this);
	this.fd = fd !== void 0 ? fd : 1;
	this.columns = void 0;
	this.rows = void 0;
	this._refreshSize();
}
if (net && net.Socket && net.Socket.prototype) {
	WriteStream.prototype = Object.create(net.Socket.prototype);
	if (typeof Object.setPrototypeOf === "function") Object.setPrototypeOf(WriteStream, net.Socket);
} else if (EventEmitter && EventEmitter.prototype) WriteStream.prototype = Object.create(EventEmitter.prototype);
else WriteStream.prototype = {};
WriteStream.prototype.constructor = WriteStream;
Object.defineProperty(WriteStream.prototype, "isTTY", {
	get: function() {
		if (Object.prototype.hasOwnProperty.call(this, "_isTTY")) return this._isTTY;
		return false;
	},
	set: function(value) {
		this._isTTY = value;
	},
	configurable: true,
	enumerable: true
});
WriteStream.prototype._refreshSize = function _refreshSize() {
	var env = typeof globalThis !== "undefined" && globalThis.process && globalThis.process.env || {};
	var cols = parseInt(env.COLUMNS, 10);
	var rows = parseInt(env.LINES, 10);
	if (cols > 0) this.columns = cols;
	if (rows > 0) this.rows = rows;
};
WriteStream.prototype.getColorDepth = function getColorDepth(env) {
	env = env || typeof globalThis !== "undefined" && globalThis.process && globalThis.process.env || {};
	if (env.NO_COLOR !== void 0) return 1;
	if (env.FORCE_COLOR !== void 0) {
		var forceColor = env.FORCE_COLOR;
		if (forceColor === "" || forceColor === "true" || forceColor === "1") return 4;
		if (forceColor === "2") return 8;
		if (forceColor === "3") return 24;
		if (forceColor === "0" || forceColor === "false") return 1;
	}
	if (env.COLORTERM === "truecolor" || env.COLORTERM === "24bit") return 24;
	var term = env.TERM || "";
	if (term === "dumb") return 1;
	if (/\-256color$/i.test(term)) return 8;
	if (/^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux/i.test(term)) return 4;
	return 1;
};
WriteStream.prototype.hasColors = function hasColors(count, env) {
	if (typeof count === "object" && count !== null && !Array.isArray(count)) {
		env = count;
		count = 16;
	}
	if (count === void 0) count = 16;
	if (typeof count !== "number" || count < 2) count = 2;
	var depth = this.getColorDepth(env);
	return Math.pow(2, depth) >= count;
};
WriteStream.prototype.getWindowSize = function getWindowSize() {
	return [this.columns, this.rows];
};
WriteStream.prototype.cursorTo = function cursorTo(x, y, callback) {
	if (typeof y === "function") {
		callback = y;
		y = void 0;
	}
	if (typeof x !== "number") {
		if (typeof callback === "function") callback();
		return true;
	}
	var data;
	if (typeof y !== "number") data = "\x1B[" + (x + 1) + "G";
	else data = "\x1B[" + (y + 1) + ";" + (x + 1) + "H";
	if (typeof this.write === "function") return this.write(data, callback);
	if (typeof callback === "function") callback();
	return true;
};
WriteStream.prototype.moveCursor = function moveCursor(dx, dy, callback) {
	if (typeof callback !== "function" && typeof dy === "function") {
		callback = dy;
		dy = void 0;
	}
	var data = "";
	if (dx < 0) data += "\x1B[" + -dx + "D";
	else if (dx > 0) data += "\x1B[" + dx + "C";
	if (dy < 0) data += "\x1B[" + -dy + "A";
	else if (dy > 0) data += "\x1B[" + dy + "B";
	if (data.length === 0) {
		if (typeof callback === "function") callback();
		return true;
	}
	if (typeof this.write === "function") return this.write(data, callback);
	if (typeof callback === "function") callback();
	return true;
};
WriteStream.prototype.clearLine = function clearLine(dir, callback) {
	if (typeof dir === "function") {
		callback = dir;
		dir = 0;
	}
	var code;
	if (dir === -1) code = "\x1B[1K";
	else if (dir === 1) code = "\x1B[0K";
	else code = "\x1B[2K";
	if (typeof this.write === "function") return this.write(code, callback);
	if (typeof callback === "function") callback();
	return true;
};
WriteStream.prototype.clearScreenDown = function clearScreenDown(callback) {
	if (typeof this.write === "function") return this.write("\x1B[0J", callback);
	if (typeof callback === "function") callback();
	return true;
};
module.exports = {
	isatty,
	ReadStream,
	WriteStream
};
//#endregion
