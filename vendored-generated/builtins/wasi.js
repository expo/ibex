//#region src/builtins/wasi.js
function WASI(options) {
	this._options = options || {};
	this.wasiImport = {};
}
WASI.prototype.start = function(instance) {
	throw new Error("WASI is not supported in this runtime");
};
WASI.prototype.initialize = function(instance) {
	throw new Error("WASI is not supported in this runtime");
};
WASI.prototype.getImportObject = function() {
	return { wasi_snapshot_preview1: this.wasiImport };
};
module.exports = { WASI };
//#endregion
