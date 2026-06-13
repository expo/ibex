//#region src/builtins/diagnostics-channel.js
var channels = {};
function Channel(name) {
	this.name = name;
	this._subscribers = [];
	this._hasSubscribers = false;
}
Channel.prototype.subscribe = function(onMessage) {
	if (typeof onMessage !== "function") throw new TypeError("onMessage must be a function");
	this._subscribers.push(onMessage);
	this._hasSubscribers = true;
};
Channel.prototype.unsubscribe = function(onMessage) {
	var idx = this._subscribers.indexOf(onMessage);
	if (idx === -1) return false;
	this._subscribers.splice(idx, 1);
	this._hasSubscribers = this._subscribers.length > 0;
	return true;
};
Channel.prototype.publish = function(message) {
	for (var i = 0; i < this._subscribers.length; i++) try {
		this._subscribers[i](message, this.name);
	} catch (e) {}
};
Object.defineProperty(Channel.prototype, "hasSubscribers", { get: function() {
	return this._hasSubscribers;
} });
function channel(name) {
	if (typeof name !== "string" && typeof name !== "symbol") throw new TypeError("Channel name must be a string or Symbol");
	var key = String(name);
	if (!channels[key]) channels[key] = new Channel(name);
	return channels[key];
}
function hasSubscribers(name) {
	var key = String(name);
	if (!channels[key]) return false;
	return channels[key].hasSubscribers;
}
function TracingChannel(nameOrChannels) {
	if (typeof nameOrChannels === "string") {
		this.start = channel(nameOrChannels + ":start");
		this.end = channel(nameOrChannels + ":end");
		this.asyncStart = channel(nameOrChannels + ":asyncStart");
		this.asyncEnd = channel(nameOrChannels + ":asyncEnd");
		this.error = channel(nameOrChannels + ":error");
	} else {
		this.start = nameOrChannels.start || new Channel("start");
		this.end = nameOrChannels.end || new Channel("end");
		this.asyncStart = nameOrChannels.asyncStart || new Channel("asyncStart");
		this.asyncEnd = nameOrChannels.asyncEnd || new Channel("asyncEnd");
		this.error = nameOrChannels.error || new Channel("error");
	}
}
TracingChannel.prototype.subscribe = function(handlers) {
	if (handlers.start) this.start.subscribe(handlers.start);
	if (handlers.end) this.end.subscribe(handlers.end);
	if (handlers.asyncStart) this.asyncStart.subscribe(handlers.asyncStart);
	if (handlers.asyncEnd) this.asyncEnd.subscribe(handlers.asyncEnd);
	if (handlers.error) this.error.subscribe(handlers.error);
};
TracingChannel.prototype.unsubscribe = function(handlers) {
	if (handlers.start) this.start.unsubscribe(handlers.start);
	if (handlers.end) this.end.unsubscribe(handlers.end);
	if (handlers.asyncStart) this.asyncStart.unsubscribe(handlers.asyncStart);
	if (handlers.asyncEnd) this.asyncEnd.unsubscribe(handlers.asyncEnd);
	if (handlers.error) this.error.unsubscribe(handlers.error);
};
TracingChannel.prototype.traceSync = function(fn, context) {
	var ctx = context || {};
	this.start.publish(ctx);
	try {
		var result = fn(ctx);
		ctx.result = result;
		return result;
	} catch (e) {
		ctx.error = e;
		this.error.publish(ctx);
		throw e;
	} finally {
		this.end.publish(ctx);
	}
};
function tracingChannel(nameOrChannels) {
	return new TracingChannel(nameOrChannels);
}
module.exports = {
	channel,
	hasSubscribers,
	Channel,
	TracingChannel,
	tracingChannel
};
//#endregion
