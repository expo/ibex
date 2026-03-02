
//#region ../packages/exact-runtime/src/builtins/stream-promises.js
var stream = require("node:stream");
function pipeline() {
	var args = [];
	for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
	if (args.length > 0 && typeof args[args.length - 1] === "function") return Promise.reject(/* @__PURE__ */ new TypeError("The callback argument is not supported"));
	if (typeof stream.pipeline === "function") {
		if (stream.promises && typeof stream.promises.pipeline === "function") try {
			return stream.promises.pipeline.apply(stream.promises, args);
		} catch (err) {
			return Promise.reject(err);
		}
		return new Promise(function(resolve, reject) {
			args.push(function(err) {
				if (err) {
					reject(err);
					return;
				}
				resolve();
			});
			try {
				stream.pipeline.apply(stream, args);
			} catch (err) {
				reject(err);
			}
		});
	}
	return Promise.reject(/* @__PURE__ */ new Error("stream.pipeline is not available"));
}
function finished(streamLike, options) {
	if (typeof options === "function") return Promise.reject(/* @__PURE__ */ new TypeError("The callback argument is not supported"));
	if (typeof stream.finished === "function") {
		return new Promise(function(resolve, reject) {
			var called = false;
			function done(err) {
				if (called) return;
				called = true;
				if (err) reject(err);
				else resolve();
			}
			try {
				var result = stream.finished(streamLike, options || {}, done);
				if (result && typeof result.then === "function") {
					result.then(resolve, reject);
				}
			} catch (err) {
				reject(err);
			}
		});
	}
	return Promise.reject(/* @__PURE__ */ new Error("stream.finished is not available"));
}
module.exports = {
	pipeline,
	finished
};

//#endregion
