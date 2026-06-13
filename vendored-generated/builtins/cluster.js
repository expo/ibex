//#region src/builtins/cluster.js
var EventEmitter = require("events");
var cp = require("child_process");
var cluster = Object.create(EventEmitter.prototype);
EventEmitter.call(cluster);
function _isWorkerProcess() {
	if (typeof process !== "object" || process === null) return false;
	return !!(process.env && (process.env.EXACT_CLUSTER_WORKER || process.env.NODE_UNIQUE_ID || process.env.NODE_CHANNEL_FD));
}
cluster.isWorker = _isWorkerProcess();
cluster.isMaster = !cluster.isWorker;
cluster.isPrimary = !cluster.isWorker;
cluster.workers = {};
cluster._nextWorkerId = 1;
cluster.settings = {};
cluster.SCHED_NONE = 1;
cluster.SCHED_RR = 2;
cluster.schedulingPolicy = 2;
function Worker(id, childProcess) {
	this.id = String(id);
	this.process = childProcess;
	this.state = "online";
	this.exitedAfterDisconnect = false;
	EventEmitter.call(this);
	if (EventEmitter.prototype) {
		var proto = EventEmitter.prototype;
		for (var k in proto) if (!this[k]) this[k] = proto[k];
	}
	this.send = function(message, sendHandle, options, callback) {
		if (!this.process || typeof this.process.send !== "function") {
			if (typeof callback === "function") callback(/* @__PURE__ */ new Error("Worker has no process"));
			return false;
		}
		return this.process.send(message, sendHandle, options, callback);
	};
	this.disconnect = function(callback) {
		this.exitedAfterDisconnect = true;
		if (!this.process || typeof this.process.disconnect !== "function") {
			if (typeof callback === "function") setTimeout(callback, 0);
			return false;
		}
		if (typeof callback === "function") this.process.once("disconnect", callback);
		this.process.disconnect();
		return true;
	};
	this.isConnected = function() {
		return !!(this.process && this.process.connected);
	};
	this.kill = function(signal) {
		return !!(this.process && this.process.kill(signal));
	};
}
cluster.setupMaster = function(settings) {
	if (settings) {
		for (var k in settings) if (Object.prototype.hasOwnProperty.call(settings, k)) cluster.settings[k] = settings[k];
	}
};
cluster.setupPrimary = cluster.setupMaster;
function _mergeEnvForCluster(extra) {
	var env = {};
	if (typeof process === "object" && process !== null && process.env) {
		var pEnv = process.env;
		for (var key in pEnv) if (Object.prototype.hasOwnProperty.call(pEnv, key)) env[key] = pEnv[key];
	}
	if (extra) {
		for (var k2 in extra) if (Object.prototype.hasOwnProperty.call(extra, k2)) env[k2] = String(extra[k2]);
	}
	return env;
}
cluster.fork = function(env) {
	if (cluster.isWorker) throw new Error("cluster.fork() cannot be called from a worker process");
	var workerEnv = env;
	if (!workerEnv || typeof workerEnv !== "object") workerEnv = {};
	var entry = typeof process !== "undefined" && process.argv && process.argv[1] ? process.argv[1] : "";
	var exec = cluster.settings.exec || entry;
	var args = cluster.settings.args ? cluster.settings.args.slice() : [];
	var workerId = cluster._nextWorkerId++;
	var clusterEnv = _mergeEnvForCluster(workerEnv);
	clusterEnv.EXACT_CLUSTER_WORKER = "1";
	clusterEnv.EXACT_CLUSTER_ID = String(workerId);
	var child = cp.fork(exec, args, {
		cwd: cluster.settings.cwd,
		execPath: cluster.settings.execPath || (typeof process !== "undefined" ? process.execPath : void 0),
		execArgv: cluster.settings.execArgv || (typeof process !== "undefined" ? process.execArgv : []),
		env: clusterEnv,
		silent: true,
		detached: cluster.settings.detached
	});
	if (cluster.settings.detached) child.unref();
	var worker = new Worker(workerId, child);
	cluster.workers[worker.id] = worker;
	var emittedOnline = false;
	var emitWorkerOnline = function() {
		if (emittedOnline) return;
		emittedOnline = true;
		cluster.emit("online", worker);
		worker.emit("online");
	};
	setTimeout(emitWorkerOnline, 0);
	child.once("online", emitWorkerOnline);
	child.on("message", function(message, sendHandle) {
		worker.emit("message", message, sendHandle);
		cluster.emit("message", worker, message, sendHandle);
	});
	child.on("error", function(err) {
		worker.emit("error", err);
		cluster.emit("error", err, worker);
	});
	child.once("disconnect", function() {
		worker.emit("disconnect");
		cluster.emit("disconnect", worker);
	});
	child.once("exit", function(code, signal) {
		worker.state = "dead";
		cluster.emit("exit", worker, code, signal);
		worker.emit("exit", code, signal);
		delete cluster.workers[worker.id];
	});
	child.once("close", function(code, signal) {
		cluster.emit("close", worker, code, signal);
		worker.emit("close", code, signal);
	});
	return worker;
};
cluster.disconnect = function(callback) {
	var workerIds = Object.keys(cluster.workers);
	if (workerIds.length === 0) {
		if (typeof callback === "function") setTimeout(callback, 0);
		return;
	}
	var pending = workerIds.length;
	var done = function() {
		pending -= 1;
		if (pending <= 0 && typeof callback === "function") callback();
	};
	for (var i = 0; i < workerIds.length; i++) {
		var worker = cluster.workers[workerIds[i]];
		if (worker && typeof worker.disconnect === "function") worker.disconnect(done);
		else done();
	}
};
if (cluster.isWorker) cluster.worker = {
	id: typeof process !== "undefined" && process && process.env && (process.env.EXACT_CLUSTER_ID || process.env.NODE_UNIQUE_ID) ? String(process.env.EXACT_CLUSTER_ID || process.env.NODE_UNIQUE_ID) : "0",
	process,
	send: function(message, sendHandle, options, callback) {
		return process.send(message, sendHandle, options, callback);
	},
	isConnected: function() {
		return !!(process && process.connected);
	},
	disconnect: function() {
		return process.disconnect();
	},
	kill: function(signal) {
		if (typeof process === "object" && process !== null) return process.kill(process.pid, signal);
		return false;
	}
};
module.exports = cluster;
//#endregion
