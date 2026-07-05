//#region src/builtins/stream-web.js
var Stream = require("node:stream");
var g = typeof globalThis === "object" && globalThis !== null ? globalThis : {};
var cacheKey = "__exactNodeStreamWebModuleCache__";
var cachedModule = g[cacheKey];
if (cachedModule) module.exports = cachedModule;
else {
	var ReadableStream = g.ReadableStream;
	var ReadableStreamDefaultReader = g.ReadableStreamDefaultReader;
	var ReadableStreamBYOBReader = g.ReadableStreamBYOBReader;
	var WritableStream = g.WritableStream;
	var WritableStreamDefaultWriter = g.WritableStreamDefaultWriter;
	var TransformStream = g.TransformStream;
	var ByteLengthQueuingStrategy = g.ByteLengthQueuingStrategy;
	var CountQueuingStrategy = g.CountQueuingStrategy;
	if (typeof ReadableStream !== "function" || typeof WritableStream !== "function" || typeof TransformStream !== "function") throw new TypeError("Web Streams API constructors are unavailable");
	function isReadableStream(value) {
		if (typeof g.__exactIsReadableStream === "function") return g.__exactIsReadableStream(value);
		return !!(value && typeof value === "object" && typeof value.getReader === "function" && typeof value.cancel === "function");
	}
	function isWritableStream(value) {
		return value && typeof value.getWriter === "function";
	}
	function fromWeb(stream) {
		if (!isReadableStream(stream)) throw new TypeError("Expected web readable stream");
		var reader = stream.getReader();
		var nodeReadable = new Stream.Readable();
		var pump = function() {
			reader.read().then(function(result) {
				if (!result || result.done) nodeReadable.push(null);
				else {
					nodeReadable.push(result.value);
					pump();
				}
			}).catch(function(err) {
				nodeReadable.emit("error", err);
			});
		};
		pump();
		return nodeReadable;
	}
	function toWeb(nodeReadable) {
		var closed = false;
		var errored = false;
		function closeController(controller) {
			if (closed || errored) return;
			closed = true;
			try {
				controller.close();
			} catch (e) {}
		}
		return new ReadableStream({
			start: function(controller) {
				if (!nodeReadable || typeof nodeReadable.on !== "function") {
					closed = true;
					controller.close();
					return;
				}
				nodeReadable.on("data", function(chunk) {
					if (closed || errored) return;
					try {
						controller.enqueue(chunk);
					} catch (e) {
						return;
					}
					if (typeof controller.desiredSize === "number" && controller.desiredSize <= 0 && typeof nodeReadable.pause === "function") nodeReadable.pause();
				});
				nodeReadable.on("end", function() {
					closeController(controller);
				});
				nodeReadable.on("error", function(err) {
					if (closed || errored) return;
					errored = true;
					try {
						controller.error(err);
					} catch (e) {}
				});
				nodeReadable.on("close", function() {
					closeController(controller);
				});
			},
			pull: function() {
				if (nodeReadable && typeof nodeReadable.resume === "function") nodeReadable.resume();
			},
			cancel: function(reason) {
				if (nodeReadable && typeof nodeReadable.destroy === "function") nodeReadable.destroy(reason);
			}
		});
	}
	cachedModule = {
		ReadableStream,
		ReadableStreamDefaultReader,
		ReadableStreamBYOBReader,
		WritableStream,
		WritableStreamDefaultWriter,
		TransformStream,
		ByteLengthQueuingStrategy,
		CountQueuingStrategy,
		isReadableStream,
		isWritableStream,
		fromWeb,
		toWeb
	};
	g[cacheKey] = cachedModule;
	module.exports = cachedModule;
}
//#endregion
