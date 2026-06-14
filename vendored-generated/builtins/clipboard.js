//#region src/builtins/clipboard.js
function readText() {
	if (typeof globalThis.__exactClipboardRead === "function") return globalThis.__exactClipboardRead();
	throw new Error("Exact clipboard not available");
}
function writeText(text) {
	if (typeof globalThis.__exactClipboardWrite === "function") {
		globalThis.__exactClipboardWrite(String(text));
		return;
	}
	throw new Error("Exact clipboard not available");
}
module.exports = {
	readText,
	writeText
};
//#endregion
