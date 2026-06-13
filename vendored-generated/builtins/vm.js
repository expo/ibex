//#region src/builtins/vm.js
function Script(code, options) {
	this._code = code;
	this._options = options || {};
}
Script.prototype.runInThisContext = function(options) {
	return (0, eval)(this._code);
};
Script.prototype.runInNewContext = function(sandbox, options) {
	var keys = sandbox ? Object.keys(sandbox) : [];
	var values = keys.map(function(k) {
		return sandbox[k];
	});
	var varDecls = keys.length > 0 ? "var " + keys.join(",") + ";\n" : "";
	var assigns = "";
	for (var i = 0; i < keys.length; i++) assigns += keys[i] + " = arguments[" + i + "];\n";
	var body = varDecls + assigns + "return (" + this._code + ");\n";
	return new Function(body).apply(null, values);
};
function createContext(sandbox) {
	return sandbox || {};
}
function runInThisContext(code, options) {
	return new Script(code, options).runInThisContext(options);
}
function runInNewContext(code, sandbox, options) {
	return new Script(code, options).runInNewContext(sandbox, options);
}
function compileFunction(code, params, options) {
	params = params || [];
	return new Function(params.join(","), code);
}
module.exports = {
	Script,
	createContext,
	runInThisContext,
	runInNewContext,
	compileFunction,
	isContext: function(sandbox) {
		return typeof sandbox === "object" && sandbox !== null;
	}
};
//#endregion
