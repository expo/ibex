//#region src/builtins/trace-events.js
function Tracing(categories) {
	this.categories = categories || [];
	this.enabled = false;
}
Tracing.prototype.enable = function() {
	this.enabled = true;
};
Tracing.prototype.disable = function() {
	this.enabled = false;
};
function createTracing(options) {
	var categories = [];
	if (options && options.categories) if (Array.isArray(options.categories)) categories = options.categories;
	else throw new TypeError("categories must be an array");
	return new Tracing(categories);
}
function getEnabledCategories() {}
module.exports = {
	createTracing,
	getEnabledCategories
};
//#endregion
