//#region src/builtins/assert.js
function _typeof(v) {
	return v === null ? "null" : typeof v;
}
function _inspect(v) {
	if (!_inspect._initialized) {
		try {
			_inspect._util = require("util").inspect;
		} catch (e) {
			_inspect._util = null;
		}
		_inspect._initialized = true;
	}
	if (_inspect._util) try {
		return _inspect._util(v, {
			compact: true,
			breakLength: Infinity
		});
	} catch (e) {}
	if (v === void 0) return "undefined";
	if (v === null) return "null";
	if (typeof v === "string") return JSON.stringify(v);
	if (typeof v === "function") return "[Function" + (v.name ? ": " + v.name : "") + "]";
	try {
		return JSON.stringify(v);
	} catch (e) {
		return String(v);
	}
}
var __assertSourceCache = {};
var __assertFailDeprecationWarned = false;
var __sharedArrayBufferZeroBug = null;
try {
	if (typeof SharedArrayBuffer === "function") {
		var __sab = new SharedArrayBuffer(3);
		var __sabArray = new Uint8Array(__sab);
		__sabArray.fill(1);
		if (__sabArray.byteLength === 0 || __sabArray.buffer.byteLength === 0) __sharedArrayBufferZeroBug = true;
	}
} catch (e) {}
function _quoteString(value) {
	return "'" + String(value).replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "'";
}
function _isSharedArrayBufferByteLengthBug() {
	if (__sharedArrayBufferZeroBug !== null) return __sharedArrayBufferZeroBug;
	if (typeof SharedArrayBuffer !== "function") {
		__sharedArrayBufferZeroBug = false;
		return false;
	}
	try {
		var __sab = new SharedArrayBuffer(3);
		var __sabArray = new Uint8Array(__sab);
		__sabArray.fill(1);
		__sharedArrayBufferZeroBug = __sabArray.byteLength === 0 || __sabArray.buffer.byteLength === 0;
	} catch (e) {
		__sharedArrayBufferZeroBug = false;
	}
	return __sharedArrayBufferZeroBug;
}
function _isFunction(value) {
	return typeof value === "function";
}
function _formatReceivedValue(value) {
	if (value === null) return "null";
	if (value === void 0) return "undefined";
	var type = typeof value;
	if (type === "number" || type === "boolean") return "type " + type + " (" + value + ")";
	if (type === "string") return "type string";
	if (type === "function") return "type function";
	if (value && value.constructor && value.constructor.name) return "an instance of " + value.constructor.name;
	return "type " + type;
}
function _formatPromiseExpectation(value) {
	if (value && value.constructor && value.constructor.name) return "an instance of " + value.constructor.name;
	return "an instance of " + (value === null ? "null" : typeof value);
}
function _throwInvalidArgType(promiseFn, errMessage) {
	var err = new TypeError(errMessage || "The \"promiseFn\" argument must be of type function or an instance of Promise. Received " + _formatReceivedValue(promiseFn));
	err.code = "ERR_INVALID_ARG_TYPE";
	throw err;
}
function _parseCallerInfo(stackLine) {
	if (typeof stackLine !== "string") return null;
	var m = stackLine.match(/\(([^()]+):(\d+):(\d+)\)$/);
	if (!m) m = stackLine.match(/at\s+(.+):(\d+):(\d+)$/);
	if (!m || m.length < 4) return null;
	return {
		file: m[1],
		line: Number(m[2]),
		column: Number(m[3])
	};
}
function _extractCallerLineSnippet(sourceLine, column, stackStartFunctionName) {
	if (typeof sourceLine !== "string") return "";
	var line = sourceLine;
	function _extractStatement(lineStart) {
		var start = lineStart;
		if (start < 0) start = 0;
		if (start >= line.length) start = line.length - 1;
		while (start > 0 && line.charCodeAt(start - 1) !== 59) start--;
		if (start > 0 && line.charCodeAt(start - 1) === 59) start++;
		while (start < line.length && line.charCodeAt(start) === 32) start++;
		var end = lineStart;
		if (end < 0) end = 0;
		if (end >= line.length) end = line.length - 1;
		while (end < line.length && line.charCodeAt(end) !== 59) end++;
		var extracted = line.slice(start, end).trim();
		return extracted === ")" ? line.trim() : extracted;
	}
	if (stackStartFunctionName) {
		var tokenIndex = line.lastIndexOf("." + stackStartFunctionName + "(");
		if (tokenIndex !== -1) return _extractStatement(tokenIndex);
		tokenIndex = line.lastIndexOf(stackStartFunctionName + "(");
		if (tokenIndex !== -1) return _extractStatement(tokenIndex);
	}
	if (column && isFinite(column) && column > 0) {
		var hasToken = stackStartFunctionName ? true : false;
		var idx = column - 1;
		if (idx < 0) idx = 0;
		if (idx >= line.length) idx = line.length - 1;
		if (hasToken && line.indexOf("." + stackStartFunctionName + "(") !== -1) {
			var tokenIndex = line.lastIndexOf("." + stackStartFunctionName + "(", idx);
			if (tokenIndex === -1) tokenIndex = line.indexOf("." + stackStartFunctionName + "(", 0);
			if (tokenIndex !== -1) return _extractStatement(tokenIndex);
		}
		return _extractStatement(idx);
	}
	return line.trim();
}
function _getCallerLine(stackStartFunction) {
	try {
		var stack = (/* @__PURE__ */ new Error()).stack || "";
		var lines = String(stack).split("\n");
		var stackStartName = stackStartFunction && stackStartFunction.name ? stackStartFunction.name : "";
		for (var i = 0; i < lines.length; i++) {
			var parsed = _parseCallerInfo(lines[i]);
			if (!parsed) continue;
			if (!parsed.file || parsed.file === "[native]" || parsed.file === "<anonymous>" || parsed.file === "[stdin]") continue;
			if (parsed.file === "assert" || parsed.file === "assert.js" || /^node:/.test(parsed.file) || /(^|[/\\])assert(\.js)?$/.test(parsed.file)) continue;
			if (/events\.js$/.test(parsed.file) && lines[i].indexOf("emit") !== -1) continue;
			if (/[/\\]module-loader\.js$/.test(parsed.file)) continue;
			if (stackStartFunction) {
				if (stackStartName && (lines[i].indexOf(stackStartName + "(") !== -1 || lines[i].indexOf("." + stackStartName + "(") !== -1)) continue;
			}
			var cacheKey = parsed.file + ":" + parsed.line;
			if (!__assertSourceCache[cacheKey]) try {
				__assertSourceCache[cacheKey] = require("fs").readFileSync(parsed.file, "utf8").split(/\r?\n/)[parsed.line - 1] || "";
			} catch (e) {
				__assertSourceCache[cacheKey] = "";
			}
			var sourceLine = __assertSourceCache[cacheKey];
			if (sourceLine) return "  " + _extractCallerLineSnippet(sourceLine, parsed.column, stackStartName);
		}
	} catch (e) {}
	return "";
}
function _formatFailValue(value) {
	if (typeof value === "string") return _quoteString(value);
	if (value instanceof RegExp || Object.prototype.toString.call(value) === "[object RegExp]") return String(value);
	return _inspect(value);
}
function _objectKeys(value) {
	return Object.keys(value);
}
function _formatValue(value, seen, strictMode) {
	if (value === null) return "null";
	if (value === void 0) return "undefined";
	if (seen === void 0) seen = [];
	var type = _typeof(value);
	if (type === "string") return _quoteString(value);
	if (type === "number" || type === "boolean" || type === "bigint") return String(value);
	if (type === "symbol") return value.toString();
	if (type === "function") return "[Function: " + (value.name || "anonymous") + "]";
	if (type !== "object") return String(value);
	if (seen.indexOf(value) !== -1) return "[Circular]";
	seen.push(value);
	if (typeof Buffer !== "undefined" && (value instanceof Buffer || Buffer.isBuffer(value))) {
		var bufferValue = _formatTypedArray(value, seen);
		seen.pop();
		return bufferValue;
	}
	if (typeof ArrayBuffer !== "undefined" && value instanceof Date) {
		var dateText = "";
		try {
			dateText = value.toISOString();
		} catch (e) {}
		if (value.constructor && value.constructor.name && value.constructor.name !== "Date") {
			if (strictMode) {
				if (_objectKeys(value).length === 0) {
					seen.pop();
					return "Date {}";
				}
				var namedDate = value.constructor.name + " " + (dateText || "Invalid Date") + _formatObjectBody(value, 0, seen);
				seen.pop();
				return namedDate;
			}
			seen.pop();
			return dateText || "Date {}";
		}
		seen.pop();
		return dateText || "Date {}";
	}
	if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(value)) {
		var typedArrayValue = _formatTypedArray(value, seen);
		seen.pop();
		return typedArrayValue;
	}
	if (Array.isArray(value)) {
		if (value.length === 0) {
			seen.pop();
			return "[]";
		}
		var arrayRows = [];
		for (var ai = 0; ai < value.length; ai++) arrayRows.push(_formatValue(value[ai], seen));
		seen.pop();
		return "[ " + arrayRows.join(", ") + " ]";
	}
	if (value instanceof RegExp || Object.prototype.toString.call(value) === "[object RegExp]") {
		var regText = String(value);
		if (strictMode && value.constructor && value.constructor.name && value.constructor.name !== "RegExp") {
			var namedRegExp = value.constructor.name + " " + regText + _formatObjectBody(value, 0, seen);
			seen.pop();
			return namedRegExp;
		}
		seen.pop();
		return regText;
	}
	if (value instanceof Error) {
		seen.pop();
		return "[" + (value.name || "Error") + ": " + (value.message || "") + "]";
	}
	var keys = _objectKeys(value);
	if (keys.length === 0) {
		if (typeof Set !== "undefined" && value instanceof Set) {
			seen.pop();
			return "Set {}";
		}
		if (typeof Map !== "undefined" && value instanceof Map) {
			seen.pop();
			return "Map {}";
		}
		if (value.constructor && value.constructor.name && value.constructor.name !== "Object") {
			seen.pop();
			return value.constructor.name + " {}";
		}
		seen.pop();
		return "{}";
	}
	var ctorName = value.constructor && value.constructor.name ? value.constructor.name : "";
	var prefix = ctorName && ctorName !== "Object" ? ctorName + " " : "";
	var parts = [];
	for (var ki = 0; ki < keys.length; ki++) parts.push(_formatPropertyKey(keys[ki]) + ": " + _formatValue(value[keys[ki]], seen));
	var compact = prefix + "{ " + parts.join(", ") + " }";
	if (compact.length <= 72 || keys.length <= 5) {
		seen.pop();
		return compact;
	}
	var multiline = prefix + "{\n  " + parts.join(",\n  ") + "\n}";
	seen.pop();
	return multiline;
}
function _formatObjectBody(value, depth, seen) {
	var indent = "";
	for (var i = 0; i < depth; i++) indent += "  ";
	var keys = _objectKeys(value);
	if (keys.length === 0) return " {}";
	var rows = [];
	for (var i = 0; i < keys.length; i++) {
		var key = keys[i];
		rows.push(_formatPropertyKey(key) + ": " + _formatValue(value[key], seen));
	}
	var sep = "\n" + indent + "  ";
	return " {\n" + indent + "  " + rows.join(sep) + "\n" + indent + "}";
}
function _formatPropertyKey(key) {
	if (typeof key === "number") return _quoteString(String(key));
	if (/^[A-Za-z_$][0-9A-Za-z_$]*$/.test(key)) return key;
	return _quoteString(key);
}
function _formatTypedArray(value, seen) {
	var isBuffer = typeof Buffer !== "undefined" && value instanceof Buffer;
	var name = isBuffer ? "Buffer" : value.constructor && value.constructor.name ? value.constructor.name : "TypedArray";
	var lines = [];
	var keys = _objectKeys(value);
	var hasExtraProps = false;
	var extraKeys = [];
	var i;
	for (i = 0; i < keys.length; i++) if (!/^\d+$/.test(keys[i]) || Number(keys[i]) >= value.length) {
		hasExtraProps = true;
		extraKeys.push(keys[i]);
	}
	var indices = [];
	if (!hasExtraProps && value.length > 8) {
		indices.push(0);
		indices.push(1);
		for (i = Math.max(3, value.length - 2); i < value.length; i++) indices.push(i);
	} else for (i = 0; i < value.length; i++) indices.push(i);
	for (i = 0; i < indices.length; i++) {
		var index = indices[i];
		var prev = i === 0 ? null : indices[i - 1];
		if (prev !== null && index > prev + 1) lines.push("...");
		lines.push("  " + _formatValue(value[index], seen) + (index !== value.length - 1 ? "," : ""));
	}
	for (i = 0; i < extraKeys.length; i++) {
		if (lines.length > 0 && lines[lines.length - 1].slice(-1) !== ",") lines[lines.length - 1] += ",";
		lines.push("  " + _formatPropertyKey(extraKeys[i]) + ": " + _formatValue(value[extraKeys[i]], seen));
	}
	var header = isBuffer ? "Buffer(" + value.length + ") [Uint8Array] [\n" : name + "(" + value.length + ") [\n";
	if (lines.length === 0) return header + "]";
	return header + lines.join("\n") + "\n  ]";
}
function _toByteArray(value, seen) {
	if (!value || value.byteLength === void 0) return null;
	if (!seen) seen = [];
	if (seen.indexOf(value) !== -1) return null;
	seen.push(value);
	var byteLength = value.byteLength;
	var backing = value;
	if (value.buffer !== void 0) backing = value.buffer;
	if (backing && backing._buffer !== void 0 && backing._buffer !== backing) backing = backing._buffer;
	else if (value._buffer !== void 0 && value._buffer !== value) backing = value._buffer;
	if (byteLength === 0) {
		if (Object.prototype.toString.call(value) === "[object SharedArrayBuffer]" && _isSharedArrayBufferByteLengthBug()) {
			seen.pop();
			return null;
		}
		if (value._buffer !== void 0 && value._buffer !== value) {
			var nestedBytes = _toByteArray(value._buffer, seen);
			if (nestedBytes !== null) {
				seen.pop();
				return nestedBytes;
			}
			seen.pop();
			return null;
		}
		if (value.buffer && value.buffer !== value && value.buffer.constructor === void 0 && value.buffer.byteLength === 0) {
			seen.pop();
			return null;
		}
		if (value.constructor && value.constructor.name === "SharedArrayBuffer" && value._buffer === void 0) {
			seen.pop();
			return null;
		}
		if (value.length !== void 0 && value.length > 0) {
			seen.pop();
			return null;
		}
		if (backing && backing !== value && backing.byteLength > 0) {
			var backingBytes = _toByteArray(backing, seen);
			if (backingBytes !== null) {
				seen.pop();
				return backingBytes;
			}
		}
		seen.pop();
		return [];
	}
	try {
		if (typeof value.length === "number" && value.BYTES_PER_ELEMENT === 1) {
			var directBytes = new Array(byteLength);
			for (var j = 0; j < value.length; j++) {
				var byteValue = value[j];
				if (typeof byteValue !== "number") break;
				directBytes[j] = byteValue & 255;
			}
			if (j === value.length) {
				seen.pop();
				return directBytes;
			}
		}
	} catch (e) {}
	try {
		var source = backing || value;
		var typedArray = value.buffer !== void 0 || source !== value ? new Uint8Array(source, value.byteOffset || 0, byteLength) : new Uint8Array(source);
		var typedLength = typedArray.length;
		if (typedLength === byteLength) {
			var typedBytes = new Array(typedLength);
			for (var i = 0; i < typedLength; i++) typedBytes[i] = typedArray[i];
			seen.pop();
			return typedBytes;
		}
	} catch (e) {}
	if (typeof DataView !== "undefined") try {
		var dataViewSource = backing || value;
		var dataView = value.buffer !== void 0 || dataViewSource !== value ? new DataView(dataViewSource, value.byteOffset || 0, byteLength) : new DataView(dataViewSource, 0, byteLength);
		var dataBytes = new Array(byteLength);
		for (var k = 0; k < byteLength; k++) dataBytes[k] = dataView.getUint8(k);
		seen.pop();
		return dataBytes;
	} catch (e) {}
	if (value._buffer !== void 0 && value._buffer !== value) {
		var nestedBytes = _toByteArray(value._buffer, seen);
		if (nestedBytes !== null) {
			seen.pop();
			return nestedBytes;
		}
	}
	seen.pop();
	return null;
}
function _typedArrayBytesEqual(a, b) {
	if (!a || !b) return false;
	var aByteLength = a.byteLength;
	var bByteLength = b.byteLength;
	if (aByteLength === void 0 || bByteLength === void 0) return false;
	if (aByteLength !== bByteLength) return false;
	if (aByteLength === 0) return true;
	var aBytes = _toByteArray(a);
	var bBytes = _toByteArray(b);
	if (aBytes === null || bBytes === null) return false;
	if (aBytes.length !== bBytes.length) return false;
	for (var i = 0; i < aByteLength; i++) if (aBytes[i] !== bBytes[i]) return false;
	return true;
}
function _buffersAreByteEqual(a, b) {
	if (!a || !b) return false;
	if (a.byteLength !== b.byteLength) return false;
	if (a.byteLength === 0) {
		if (Object.prototype.toString.call(a) === "[object SharedArrayBuffer]" && _isSharedArrayBufferByteLengthBug() && a !== b) return false;
		if (_isSharedArrayBufferByteLengthBug() && Object.prototype.toString.call(a) === "[object ArrayBuffer]" && Object.prototype.toString.call(b) === "[object ArrayBuffer]" && a !== b) return false;
		var aZeroBytes = _toByteArray(a);
		var bZeroBytes = _toByteArray(b);
		if (aZeroBytes === null || bZeroBytes === null) return false;
		if (aZeroBytes.length !== bZeroBytes.length) return false;
		return true;
	}
	var aBytes = _toByteArray(a);
	var bBytes = _toByteArray(b);
	if (aBytes === null || bBytes === null) return false;
	if (aBytes.length !== bBytes.length) return false;
	for (var i = 0; i < aBytes.length; i++) if (aBytes[i] !== bBytes[i]) return false;
	return true;
}
function _collapseDiffLines(actualOut, expectedOut) {
	if (actualOut.length !== expectedOut.length || actualOut.length < 6) return null;
	if (actualOut[0] === expectedOut[0]) return null;
	var actualHeader = actualOut[0];
	var expectedHeader = expectedOut[0];
	function _isTypedArraySummaryHeader(line) {
		if (typeof line !== "string" || line.length < 3) return false;
		if (line.charCodeAt(1) !== 32) return false;
		if (line[0] !== "+" && line[0] !== "-") return false;
		var header = line.slice(2);
		return header.indexOf("Buffer(") === 0 || header.indexOf("Array(") !== -1;
	}
	for (var i = 1; i < actualOut.length - 2; i++) if (actualOut[i] !== expectedOut[i]) return null;
	if (_isTypedArraySummaryHeader(actualHeader) && _isTypedArraySummaryHeader(expectedHeader)) {
		var expectedTail = [
			expectedOut[1],
			"...",
			expectedOut.length > 3 ? expectedOut[expectedOut.length - 3] : "",
			expectedOut[expectedOut.length - 2],
			expectedOut[expectedOut.length - 1]
		].join("\n");
		expectedTail = expectedTail.replace(/^ {4}\]$/m, "  ]");
		return {
			actual: actualHeader,
			expected: expectedHeader + "\n" + expectedTail
		};
	}
	var actualTail = [
		actualOut[actualOut.length - 3],
		actualOut[actualOut.length - 2],
		actualOut[actualOut.length - 1]
	].join("\n");
	var expectedTail = [
		expectedOut[expectedOut.length - 3],
		expectedOut[expectedOut.length - 2],
		expectedOut[expectedOut.length - 1]
	].join("\n");
	actualTail = actualTail.replace(/^ {4}\]$/m, "  ]");
	expectedTail = expectedTail.replace(/^ {4}\]$/m, "  ]");
	return {
		actual: actualOut[0] + "\n" + actualOut[1] + "\n...\n" + actualTail,
		expected: expectedOut[0] + "\n" + expectedOut[1] + "\n...\n" + expectedTail
	};
}
function _hasSeenPair(aSeen, bSeen, a, b) {
	for (var i = 0; i < aSeen.length; i++) if (aSeen[i] === a && bSeen[i] === b) return true;
	return false;
}
function _shouldUseLinesSkippedHeader(a, b) {
	if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(a) && ArrayBuffer.isView(b)) {
		if (!a || !b || a.constructor === b.constructor) return false;
		if (a.length !== b.length) return false;
		if (_typedArrayBytesEqual(a, b)) return true;
	}
	return false;
}
function _normalizeDiffLine(line) {
	if (typeof line !== "string") return line;
	if (line.length > 0 && line.charCodeAt(line.length - 1) === 44) return line.slice(0, -1);
	return line;
}
function _normalizeDiffLines(lines) {
	if (!lines) return lines;
	var normalized = [];
	for (var i = 0; i < lines.length; i++) normalized.push((lines[i] || "").replace(/^ {4}\]$/m, "  ]"));
	return normalized;
}
function _trimTrailingNewline(text) {
	if (!text) return text;
	return text.replace(/\n+$/, "");
}
function _trimLeadingNewline(text) {
	if (!text) return text;
	return text.replace(/^\n+/, "");
}
function _diffLines(actualText, expectedText) {
	var actualLines = actualText.split("\n");
	var expectedLines = expectedText.split("\n");
	var actualLength = actualLines.length;
	var expectedLength = expectedLines.length;
	if (actualLength === 1 && expectedLength === 1) return {
		actual: "+ " + actualText,
		expected: "- " + expectedText
	};
	var dp = new Array(actualLength + 1);
	var x;
	for (x = 0; x <= actualLength; x++) {
		dp[x] = new Array(expectedLength + 1);
		dp[x][0] = 0;
	}
	for (x = 0; x <= expectedLength; x++) dp[0][x] = 0;
	var i;
	var j;
	for (i = 1; i <= actualLength; i++) for (j = 1; j <= expectedLength; j++) if (actualLines[i - 1] === expectedLines[j - 1] || _normalizeDiffLine(actualLines[i - 1]) === _normalizeDiffLine(expectedLines[j - 1])) dp[i][j] = dp[i - 1][j - 1] + 1;
	else dp[i][j] = dp[i - 1][j] >= dp[i][j - 1] ? dp[i - 1][j] : dp[i][j - 1];
	var ops = [];
	i = actualLength;
	j = expectedLength;
	var hasActualOnly = false;
	var hasExpectedOnly = false;
	while (i > 0 || j > 0) {
		if (i > 0 && j > 0 && (actualLines[i - 1] === expectedLines[j - 1] || _normalizeDiffLine(actualLines[i - 1]) === _normalizeDiffLine(expectedLines[j - 1]))) {
			ops.push({
				type: "equal",
				actualLine: actualLines[i - 1],
				expectedLine: expectedLines[j - 1]
			});
			i--;
			j--;
			continue;
		}
		if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
			ops.push({
				type: "expected-only",
				expectedLine: expectedLines[j - 1]
			});
			hasExpectedOnly = true;
			j--;
			continue;
		}
		if (i > 0) {
			ops.push({
				type: "actual-only",
				actualLine: actualLines[i - 1]
			});
			hasActualOnly = true;
			i--;
			continue;
		}
		j--;
	}
	var actualOut = [];
	var expectedOut = [];
	for (i = ops.length - 1; i >= 0; i--) {
		var op = ops[i];
		if (op.type === "equal") {
			actualOut.push("  " + op.actualLine);
			expectedOut.push("  " + op.expectedLine);
		} else if (op.type === "actual-only") actualOut.push("+ " + op.actualLine);
		else if (op.type === "expected-only") expectedOut.push("- " + op.expectedLine);
	}
	actualOut = _normalizeDiffLines(actualOut);
	expectedOut = _normalizeDiffLines(expectedOut);
	if (hasActualOnly && !hasExpectedOnly) return {
		actual: actualOut.join("\n"),
		expected: ""
	};
	if (hasExpectedOnly && !hasActualOnly) return {
		actual: "",
		expected: expectedOut.join("\n")
	};
	var collapsed = _collapseDiffLines(actualOut, expectedOut);
	if (collapsed) return collapsed;
	return {
		actual: actualOut.join("\n"),
		expected: expectedOut.join("\n")
	};
}
function _buildDeepEqualMessage(actual, expected, strict) {
	var header = strict ? "Expected values to be strictly deep-equal:" : "Expected values to be loosely deep-equal:";
	if (!strict) return header + "\n\n" + _formatValue(actual, void 0, false) + "\n\nshould loosely deep-equal\n\n" + _formatValue(expected, void 0, false);
	var message = header + "\n+ actual - expected";
	if (_shouldUseLinesSkippedHeader(actual, expected)) message += " ... Lines skipped";
	var diff = _diffLines(_formatValue(actual, void 0, strict), _formatValue(expected, void 0, strict));
	var trimmedActual = _trimLeadingNewline(_trimTrailingNewline(diff.actual));
	var trimmedExpected = _trimLeadingNewline(_trimTrailingNewline(diff.expected));
	if (trimmedActual && trimmedExpected) return message + "\n\n" + trimmedActual + "\n" + trimmedExpected;
	if (trimmedActual) return message + "\n\n" + trimmedActual;
	if (trimmedExpected) return message + "\n\n" + trimmedExpected;
	return message + "\n\n";
}
function AssertionError(opts) {
	if (!(this instanceof AssertionError)) return new AssertionError(opts);
	if (!opts || _typeof(opts) !== "object") {
		var typeErr = /* @__PURE__ */ new TypeError("The \"options\" argument must be of type object. Received type \"" + _typeof(opts) + "\"");
		typeErr.code = "ERR_INVALID_ARG_TYPE";
		throw typeErr;
	}
	var msg = opts.message || "Expected values to be " + (opts.operator || "truthy");
	this.message = msg;
	this.name = "AssertionError";
	this.actual = opts.actual;
	this.expected = opts.expected;
	this.operator = opts.operator;
	this.code = "ERR_ASSERTION";
	this.generatedMessage = opts.generatedMessage !== void 0 ? opts.generatedMessage : opts.message ? false : true;
	if (Error.captureStackTrace) {
		var stackStart = opts.stackStartFn || opts.stackStartFunction;
		Error.captureStackTrace(this, stackStart || AssertionError);
		if (typeof this.stack === "string") {
			var lines = this.stack.split("\n");
			var firstStackLine = 1;
			while (firstStackLine < lines.length) {
				var frame = lines[firstStackLine];
				if (frame === "    at apply (native)" || frame === "    at call (native)") {
					firstStackLine++;
					continue;
				}
				if (frame.indexOf("(events") !== -1 || frame.indexOf("(node:events") !== -1) {
					firstStackLine++;
					continue;
				}
				break;
			}
			if (firstStackLine > 1) {
				lines.splice(1, firstStackLine - 1);
				this.stack = lines.join("\n");
			}
		}
	} else try {
		this.stack = new Error(msg).stack;
	} catch (_) {}
}
AssertionError.prototype = Object.create(Error.prototype);
Object.defineProperty(AssertionError.prototype, "constructor", {
	value: AssertionError,
	writable: true,
	configurable: true,
	enumerable: false
});
function _partialDeepStrictEqual(actual, expected, aSeen, bSeen) {
	if (Object.is(actual, expected)) return true;
	if (typeof actual === "number" && typeof expected === "number" && isNaN(actual) && isNaN(expected)) return true;
	if (actual === null || expected === null) return false;
	if (actual === void 0 || expected === void 0) return false;
	if (typeof actual !== "object" && typeof expected !== "object") return false;
	if (typeof actual !== "object" || typeof expected !== "object") return false;
	if (aSeen === void 0) aSeen = [];
	if (bSeen === void 0) bSeen = [];
	if (_hasSeenPair(aSeen, bSeen, actual, expected)) return true;
	aSeen.push(actual);
	bSeen.push(expected);
	var aTag = Object.prototype.toString.call(actual);
	var bTag = Object.prototype.toString.call(expected);
	if (aTag === "[object WeakSet]" || bTag === "[object WeakSet]" || aTag === "[object WeakMap]" || bTag === "[object WeakMap]") {
		aSeen.pop();
		bSeen.pop();
		return false;
	}
	if (aTag !== bTag) {
		aSeen.pop();
		bSeen.pop();
		return false;
	}
	if (aTag === "[object Date]") {
		var aTime, bTime;
		try {
			aTime = Date.prototype.valueOf.call(actual);
		} catch (e) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		try {
			bTime = Date.prototype.valueOf.call(expected);
		} catch (e) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		if (aTime !== bTime) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
	}
	if (aTag === "[object RegExp]") {
		if (actual.source !== expected.source || actual.flags !== expected.flags) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
	}
	if (aTag === "[object ArrayBuffer]" || aTag === "[object SharedArrayBuffer]") {
		if (aTag !== bTag) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		if (expected.byteLength > actual.byteLength) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		if (_isSharedArrayBufferByteLengthBug() && actual.byteLength === 0 && expected.byteLength === 0 && actual !== expected) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		var aBytes = _toByteArray(actual);
		var bBytes = _toByteArray(expected);
		if (aBytes === null || bBytes === null) {
			aSeen.pop();
			bSeen.pop();
			return actual === expected;
		}
		for (var i = 0; i < bBytes.length; i++) if (aBytes[i] !== bBytes[i]) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		aSeen.pop();
		bSeen.pop();
		return true;
	}
	if (aTag === "[object DataView]" && bTag === "[object DataView]") {
		if (expected.byteLength > actual.byteLength) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		var actualViewBytes = _toByteArray(actual);
		var expectedViewBytes = _toByteArray(expected);
		if (actualViewBytes === null || expectedViewBytes === null) {
			aSeen.pop();
			bSeen.pop();
			return actual === expected;
		}
		for (var dvi = 0; dvi < expectedViewBytes.length; dvi++) if (actualViewBytes[dvi] !== expectedViewBytes[dvi]) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		aSeen.pop();
		bSeen.pop();
		return true;
	}
	if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(actual) && ArrayBuffer.isView(expected)) {
		if (aTag !== bTag) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		if (expected.length > actual.length) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		var ai = 0;
		for (var ei = 0; ei < expected.length; ei++) {
			var found = false;
			while (ai < actual.length) {
				if (Object.is(actual[ai], expected[ei])) {
					found = true;
					ai++;
					break;
				}
				ai++;
			}
			if (!found) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
		}
		var expectedSymbols = Object.getOwnPropertySymbols(expected).filter(function(s) {
			return Object.prototype.propertyIsEnumerable.call(expected, s);
		});
		for (var si = 0; si < expectedSymbols.length; si++) {
			var sym = expectedSymbols[si];
			if (!Object.prototype.propertyIsEnumerable.call(actual, sym)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
			if (!_partialDeepStrictEqual(actual[sym], expected[sym], aSeen, bSeen)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
		}
		var expectedExtraKeys = Object.keys(expected).filter(function(k) {
			return isNaN(Number(k)) || Number(k) >= expected.length;
		});
		var actualExtraKeys = Object.keys(actual).filter(function(k) {
			return isNaN(Number(k)) || Number(k) >= actual.length;
		});
		for (var ki = 0; ki < expectedExtraKeys.length; ki++) {
			var key = expectedExtraKeys[ki];
			if (actualExtraKeys.indexOf(key) === -1) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
			if (!Object.prototype.propertyIsEnumerable.call(actual, key)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
			if (!_partialDeepStrictEqual(actual[key], expected[key], aSeen, bSeen)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
		}
		aSeen.pop();
		bSeen.pop();
		return true;
	}
	if (actual instanceof Error && expected instanceof Error) {
		var expectedKeys = Object.keys(expected);
		for (var i = 0; i < expectedKeys.length; i++) {
			var key = expectedKeys[i];
			if (!Object.prototype.hasOwnProperty.call(actual, key)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
			if (!_partialDeepStrictEqual(actual[key], expected[key], aSeen, bSeen)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
		}
		if (expected.message !== "" && actual.message !== expected.message) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		if (Object.prototype.hasOwnProperty.call(expected, "cause")) {
			if (!Object.prototype.hasOwnProperty.call(actual, "cause")) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
			if (!_partialDeepStrictEqual(actual.cause, expected.cause, aSeen, bSeen)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
		}
		if (Object.prototype.hasOwnProperty.call(expected, "errors") && Array.isArray(expected.errors)) {
			if (!Object.prototype.hasOwnProperty.call(actual, "errors") || !Array.isArray(actual.errors)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
			if (!_partialDeepStrictEqual(actual.errors, expected.errors, aSeen, bSeen)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
		}
		aSeen.pop();
		bSeen.pop();
		return true;
	}
	if (typeof Map !== "undefined" && actual instanceof Map && expected instanceof Map) {
		if (expected.size > actual.size) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		var expectedEntries = Array.from(expected.entries());
		var actualEntries = Array.from(actual.entries());
		var matched = new Array(actualEntries.length);
		for (var i = 0; i < expectedEntries.length; i++) {
			var foundEntry = false;
			for (var j = 0; j < actualEntries.length; j++) if (!matched[j] && _deepEqual(expectedEntries[i][0], actualEntries[j][0], [], [], true) && _partialDeepStrictEqual(actualEntries[j][1], expectedEntries[i][1], aSeen, bSeen)) {
				matched[j] = true;
				foundEntry = true;
				break;
			}
			if (!foundEntry) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
		}
		aSeen.pop();
		bSeen.pop();
		return true;
	}
	if (typeof Set !== "undefined" && actual instanceof Set && expected instanceof Set) {
		if (expected.size > actual.size) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		var expectedArr = Array.from(expected);
		var actualArr = Array.from(actual);
		var matchedSet = new Array(actualArr.length);
		for (var i = 0; i < expectedArr.length; i++) {
			var foundElem = false;
			for (var j = 0; j < actualArr.length; j++) if (!matchedSet[j] && _partialDeepStrictEqual(actualArr[j], expectedArr[i], aSeen, bSeen)) {
				matchedSet[j] = true;
				foundElem = true;
				break;
			}
			if (!foundElem) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
		}
		aSeen.pop();
		bSeen.pop();
		return true;
	}
	if (Array.isArray(actual) && Array.isArray(expected)) {
		if (expected.length > actual.length) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		var expectedIndexKeys = Object.keys(expected).filter(function(k) {
			var n = Number(k);
			return !isNaN(n) && n >= 0 && n < expected.length && k === String(Math.floor(n));
		}).sort(function(a, b) {
			return Number(a) - Number(b);
		});
		var actualIndexKeys = Object.keys(actual).filter(function(k) {
			var n = Number(k);
			return !isNaN(n) && n >= 0 && n < actual.length && k === String(Math.floor(n));
		}).sort(function(a, b) {
			return Number(a) - Number(b);
		});
		var actualKeyIndex = 0;
		for (var eki = 0; eki < expectedIndexKeys.length; eki++) {
			var expectedKey = expectedIndexKeys[eki];
			var foundEl = false;
			while (actualKeyIndex < actualIndexKeys.length) {
				var actualKey = actualIndexKeys[actualKeyIndex];
				if (_partialDeepStrictEqual(actual[actualKey], expected[expectedKey], aSeen, bSeen)) {
					foundEl = true;
					actualKeyIndex++;
					break;
				}
				actualKeyIndex++;
			}
			if (!foundEl) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
		}
		var expectedExtraKeys = Object.keys(expected).filter(function(k) {
			var n = Number(k);
			return isNaN(n) || n >= expected.length || n < 0 || k !== String(Math.floor(n));
		});
		for (var ki = 0; ki < expectedExtraKeys.length; ki++) {
			var key = expectedExtraKeys[ki];
			if (!Object.prototype.hasOwnProperty.call(actual, key)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
			if (!Object.prototype.propertyIsEnumerable.call(actual, key)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
			if (!_partialDeepStrictEqual(actual[key], expected[key], aSeen, bSeen)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
		}
		var expectedSymbols = Object.getOwnPropertySymbols(expected).filter(function(s) {
			return Object.prototype.propertyIsEnumerable.call(expected, s);
		});
		for (var si = 0; si < expectedSymbols.length; si++) {
			var sym = expectedSymbols[si];
			if (!Object.prototype.propertyIsEnumerable.call(actual, sym)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
			if (!_partialDeepStrictEqual(actual[sym], expected[sym], aSeen, bSeen)) {
				aSeen.pop();
				bSeen.pop();
				return false;
			}
		}
		aSeen.pop();
		bSeen.pop();
		return true;
	}
	var expectedKeys = Object.keys(expected);
	for (var i = 0; i < expectedKeys.length; i++) {
		var key = expectedKeys[i];
		if (!Object.prototype.hasOwnProperty.call(actual, key)) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		if (!Object.prototype.propertyIsEnumerable.call(actual, key)) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		if (!_partialDeepStrictEqual(actual[key], expected[key], aSeen, bSeen)) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
	}
	var expectedSymbols = Object.getOwnPropertySymbols(expected).filter(function(s) {
		return Object.prototype.propertyIsEnumerable.call(expected, s);
	});
	for (var si = 0; si < expectedSymbols.length; si++) {
		var sym = expectedSymbols[si];
		if (!Object.prototype.propertyIsEnumerable.call(actual, sym)) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
		if (!_partialDeepStrictEqual(actual[sym], expected[sym], aSeen, bSeen)) {
			aSeen.pop();
			bSeen.pop();
			return false;
		}
	}
	aSeen.pop();
	bSeen.pop();
	return true;
}
function partialDeepStrictEqual(actual, expected, message) {
	if (!_partialDeepStrictEqual(actual, expected)) throw new AssertionError({
		message: message || _buildDeepEqualMessage(actual, expected, true),
		actual,
		expected,
		operator: "partialDeepStrictEqual",
		stackStartFn: partialDeepStrictEqual
	});
}
function _isErrorConstructor(expected) {
	return typeof expected === "function" && expected.prototype && (expected === Error || expected.prototype === Error.prototype || expected.prototype instanceof Error);
}
function _ifErrorValue(err) {
	if (err === void 0 || err === null) return "";
	if (err instanceof Error) return typeof err.message === "string" && err.message.length > 0 ? err.message : typeof err.name === "string" ? err.name : String(err);
	if (_typeof(err) === "object" && Object.prototype.hasOwnProperty.call(err, "message")) return typeof err.message === "string" ? err.message : _inspect(err.message);
	if (_typeof(err) === "string") return err;
	if (_typeof(err) === "boolean" || _typeof(err) === "number" || _typeof(err) === "symbol") return String(err);
	return _inspect(err);
}
function _errorTypeName(err) {
	if (err === null || err === void 0) return String(err);
	if (_typeof(err) === "string") return err;
	if (_typeof(err) === "number" || _typeof(err) === "boolean" || _typeof(err) === "symbol") return String(err);
	if (_typeof(err) === "object" && err.name) return String(err.name);
	return _inspect(err);
}
function _isBoxedPrimitiveTag(tag) {
	return tag === "[object Number]" || tag === "[object String]" || tag === "[object Boolean]" || tag === "[object BigInt]" || tag === "[object Symbol]";
}
function _boxedPrimitivesEqual(a, b, tag) {
	if (tag === "[object Number]") return Object.is(Number.prototype.valueOf.call(a), Number.prototype.valueOf.call(b));
	if (tag === "[object String]") return String.prototype.valueOf.call(a) === String.prototype.valueOf.call(b);
	if (tag === "[object Boolean]") return Boolean.prototype.valueOf.call(a) === Boolean.prototype.valueOf.call(b);
	if (tag === "[object BigInt]") return BigInt.prototype.valueOf.call(a) === BigInt.prototype.valueOf.call(b);
	return Symbol.prototype.valueOf.call(a) === Symbol.prototype.valueOf.call(b);
}
function _deepEqual(a, b, aSeen, bSeen, strict) {
	if (strict === void 0) strict = false;
	if (a === b) {
		if (a !== 0) return true;
		return strict ? Object.is(a, b) : true;
	}
	if (strict) {
		if (a === null || typeof a !== "object") return typeof a === "number" && Number.isNaN(a) && Number.isNaN(b);
		if (b === null || typeof b !== "object") return false;
	} else {
		if (a === null || typeof a !== "object") {
			if (b === null || typeof b !== "object") return a == b || Number.isNaN(a) && Number.isNaN(b);
			return false;
		}
		if (b === null || typeof b !== "object") return false;
	}
	if (aSeen === void 0) aSeen = [];
	if (bSeen === void 0) bSeen = [];
	if (_hasSeenPair(aSeen, bSeen, a, b)) return true;
	aSeen.push(a);
	bSeen.push(b);
	var deepEqualResult = _deepEqualObjects(a, b, aSeen, bSeen, strict);
	aSeen.pop();
	bSeen.pop();
	return deepEqualResult;
}
function _symbolKeysEqual(a, b, aSeen, bSeen) {
	var aSymbols = Object.getOwnPropertySymbols(a).filter(function(s) {
		return Object.prototype.propertyIsEnumerable.call(a, s);
	});
	var bSymbols = Object.getOwnPropertySymbols(b).filter(function(s) {
		return Object.prototype.propertyIsEnumerable.call(b, s);
	});
	if (aSymbols.length !== bSymbols.length) return false;
	for (var i = 0; i < aSymbols.length; i++) {
		var sym = aSymbols[i];
		if (!Object.prototype.propertyIsEnumerable.call(b, sym)) return false;
		if (!_deepEqual(a[sym], b[sym], aSeen, bSeen, true)) return false;
	}
	return true;
}
function _deepEqualObjects(a, b, aSeen, bSeen, strict) {
	var aTag = Object.prototype.toString.call(a);
	var bTag = Object.prototype.toString.call(b);
	if (aTag !== bTag) return false;
	if (_isBoxedPrimitiveTag(aTag)) {
		var boxedEqual;
		try {
			boxedEqual = _boxedPrimitivesEqual(a, b, aTag);
		} catch (e) {
			boxedEqual = void 0;
		}
		if (boxedEqual === false) return false;
	}
	if (aTag === "[object Date]") {
		if (!(a instanceof Date) || !(b instanceof Date)) return false;
		var aTime, bTime;
		try {
			aTime = Date.prototype.valueOf.call(a);
		} catch (e) {
			return false;
		}
		try {
			bTime = Date.prototype.valueOf.call(b);
		} catch (e) {
			return false;
		}
		if (strict && a.constructor !== b.constructor) return false;
		if (aTime !== bTime) return false;
	}
	if (aTag === "[object RegExp]") return a.source === b.source && a.flags === b.flags && a.constructor === b.constructor && (function() {
		var aKeys = Object.keys(a);
		var bKeys = Object.keys(b);
		if (aKeys.length !== bKeys.length) return false;
		for (var i = 0; i < aKeys.length; i++) {
			var key = aKeys[i];
			if (!Object.prototype.propertyIsEnumerable.call(b, key)) return false;
			if (!_deepEqual(a[key], b[key], aSeen, bSeen, strict)) return false;
		}
		return true;
	})();
	if (a instanceof Error && b instanceof Error) {
		if (a.message !== b.message || a.name !== b.name) return false;
	}
	if (typeof ArrayBuffer !== "undefined" && (aTag === "[object ArrayBuffer]" || aTag === "[object SharedArrayBuffer]")) {
		if (aTag !== bTag) return false;
		return _buffersAreByteEqual(a, b);
	}
	if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(a) && ArrayBuffer.isView(b)) {
		if (strict) {
			if (a.constructor !== b.constructor) return false;
		} else if (a.constructor !== b.constructor) {
			if (!(a instanceof b.constructor) && !(b instanceof a.constructor)) return false;
		}
		if (a.length !== b.length) return false;
		if (strict) {
			if (_buffersAreByteEqual(a, b) === false) return false;
		} else for (var i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
		var aKeys = Object.keys(a).filter(function(k) {
			return isNaN(Number(k));
		});
		var bKeys = Object.keys(b).filter(function(k) {
			return isNaN(Number(k));
		});
		if (aKeys.length !== bKeys.length) return false;
		for (var i = 0; i < aKeys.length; i++) {
			var key = aKeys[i];
			if (!Object.prototype.propertyIsEnumerable.call(b, key)) return false;
			if (!_deepEqual(a[key], b[key], aSeen, bSeen, strict)) return false;
		}
		return true;
	}
	if (strict) {
		if (Object.getPrototypeOf(a) !== Object.getPrototypeOf(b)) return false;
	}
	if (typeof Map !== "undefined" && a instanceof Map && b instanceof Map) {
		if (a.size !== b.size) return false;
		var aEntries = Array.from(a.entries());
		if (strict) {
			var hasPrimitiveOnlyKeys = true;
			for (var i = 0; i < aEntries.length; i++) if (typeof aEntries[i][0] === "object" && aEntries[i][0] !== null) {
				hasPrimitiveOnlyKeys = false;
				break;
			}
			if (hasPrimitiveOnlyKeys) for (var i = 0; i < aEntries.length; i++) {
				var key = aEntries[i][0];
				if (!b.has(key)) return false;
				if (!_deepEqual(aEntries[i][1], b.get(key), aSeen, bSeen, strict)) return false;
			}
			else {
				var bEntries2 = Array.from(b.entries());
				var matched2 = new Array(bEntries2.length);
				for (var i = 0; i < aEntries.length; i++) {
					var found2 = false;
					for (var j = 0; j < bEntries2.length; j++) if (!matched2[j] && _deepEqual(aEntries[i][0], bEntries2[j][0], aSeen, bSeen, strict) && _deepEqual(aEntries[i][1], bEntries2[j][1], aSeen, bSeen, strict)) {
						matched2[j] = true;
						found2 = true;
						break;
					}
					if (!found2) return false;
				}
			}
		} else {
			var bEntries = Array.from(b.entries());
			var matched = new Array(bEntries.length);
			for (var i = 0; i < aEntries.length; i++) {
				var found = false;
				for (var j = 0; j < bEntries.length; j++) if (!matched[j] && _deepEqual(aEntries[i][0], bEntries[j][0], aSeen, bSeen, strict) && _deepEqual(aEntries[i][1], bEntries[j][1], aSeen, bSeen, strict)) {
					matched[j] = true;
					found = true;
					break;
				}
				if (!found) return false;
			}
		}
	} else if (typeof Set !== "undefined" && a instanceof Set && b instanceof Set) {
		if (a.size !== b.size) return false;
		var aArr = Array.from(a);
		var bArr = Array.from(b);
		var matched = new Array(bArr.length);
		for (var i = 0; i < aArr.length; i++) {
			var found = false;
			for (var j = 0; j < bArr.length; j++) if (!matched[j] && _deepEqual(aArr[i], bArr[j], aSeen, bSeen, strict)) {
				matched[j] = true;
				found = true;
				break;
			}
			if (!found) return false;
		}
	}
	if (Array.isArray(a)) {
		if (!Array.isArray(b) || a.length !== b.length) return false;
		var arrKeysA = Object.keys(a);
		var arrKeysB = Object.keys(b);
		if (arrKeysA.length !== arrKeysB.length) return false;
		for (var ai = 0; ai < arrKeysA.length; ai++) {
			var arrKey = arrKeysA[ai];
			if (!Object.prototype.propertyIsEnumerable.call(b, arrKey)) return false;
			if (!_deepEqual(a[arrKey], b[arrKey], aSeen, bSeen, strict)) return false;
		}
		if (strict && !_symbolKeysEqual(a, b, aSeen, bSeen)) return false;
		return true;
	}
	var keysA = Object.keys(a);
	var keysB = Object.keys(b);
	if (keysA.length !== keysB.length) return false;
	for (var i = 0; i < keysA.length; i++) {
		var key = keysA[i];
		if (!Object.prototype.propertyIsEnumerable.call(b, key)) return false;
		if (!_deepEqual(a[key], b[key], aSeen, bSeen, strict)) return false;
	}
	if (strict && !_symbolKeysEqual(a, b, aSeen, bSeen)) return false;
	return true;
}
function ok(value, message) {
	if (!value) {
		var defaultMessage = "The expression evaluated to a falsy value";
		var line = message ? "" : _getCallerLine(ok);
		if (line) defaultMessage += ":\n\n" + line + "\n";
		throw new AssertionError({
			message: message || defaultMessage,
			actual: value,
			expected: true,
			operator: "==",
			stackStartFn: ok
		});
	}
}
function equal(actual, expected, message) {
	if (actual != expected && (!Number.isNaN(actual) || !Number.isNaN(expected))) throw new AssertionError({
		message,
		actual,
		expected,
		operator: "==",
		stackStartFn: equal
	});
}
function notEqual(actual, expected, message) {
	if (actual == expected || Number.isNaN(actual) && Number.isNaN(expected)) throw new AssertionError({
		message,
		actual,
		expected,
		operator: "!=",
		stackStartFn: notEqual
	});
}
function strictEqual(actual, expected, message) {
	if (!Object.is(actual, expected)) throw new AssertionError({
		message,
		actual,
		expected,
		operator: "===",
		stackStartFn: strictEqual
	});
}
function notStrictEqual(actual, expected, message) {
	if (Object.is(actual, expected)) throw new AssertionError({
		message,
		actual,
		expected,
		operator: "!==",
		stackStartFn: notStrictEqual
	});
}
function deepEqual(actual, expected, message) {
	if (!_deepEqual(actual, expected, void 0, void 0, false)) throw new AssertionError({
		message: message || _buildDeepEqualMessage(actual, expected, false),
		actual,
		expected,
		operator: "deepEqual",
		stackStartFn: deepEqual
	});
}
function deepStrictEqual(actual, expected, message) {
	if (!_deepEqual(actual, expected, void 0, void 0, true)) throw new AssertionError({
		message: message || _buildDeepEqualMessage(actual, expected, true),
		actual,
		expected,
		operator: "deepStrictEqual",
		stackStartFn: deepStrictEqual
	});
}
function notDeepEqual(actual, expected, message) {
	if (_deepEqual(actual, expected, void 0, void 0, false)) throw new AssertionError({
		message,
		actual,
		expected,
		operator: "notDeepEqual",
		stackStartFn: notDeepEqual
	});
}
function notDeepStrictEqual(actual, expected, message) {
	if (_deepEqual(actual, expected, void 0, void 0, true)) throw new AssertionError({
		message,
		actual,
		expected,
		operator: "notDeepStrictEqual",
		stackStartFn: notDeepStrictEqual
	});
}
function _isDeepStrictEqual(a, b) {
	return _deepEqual(a, b, void 0, void 0, true);
}
function _callTrackerTypeLabel(value) {
	if (value === null) return "null";
	if (value === void 0) return "undefined";
	if (typeof value === "function" && value.name) return "[Function: " + value.name + "]";
	if (typeof value === "function") return "[Function (anonymous)]";
	return _typeof(value);
}
var __callTrackerExiting = false;
if (typeof process === "object" && process !== null && typeof process.on === "function" && !process.__exactCallTrackerExitHook) {
	process.__exactCallTrackerExitHook = true;
	process.on("exit", function() {
		__callTrackerExiting = true;
	});
}
function _invalidExpectedType(expected) {
	var actualType = expected === null ? "null" : _typeof(expected);
	var text = "The \"expected\" argument must be of type number. Received";
	if (actualType === "string") text += " type \"string\" ('" + expected + "')";
	else if (actualType === "object" && expected !== null) {
		var ctor = expected.constructor && expected.constructor.name ? expected.constructor.name : "Object";
		text += " an instance of " + ctor;
	} else if (actualType === "boolean" || actualType === "number" || actualType === "undefined") text += " type \"" + actualType + "\" (" + String(expected) + ")";
	else text += " type \"" + actualType + "\"";
	var typeErr = new TypeError(text);
	typeErr.code = "ERR_INVALID_ARG_TYPE";
	return typeErr;
}
function _cloneArguments(args) {
	var cloned = new Array(args.length);
	for (var i = 0; i < args.length; i++) cloned[i] = args[i];
	return cloned;
}
function _freeze(obj) {
	return Object.freeze(obj);
}
function _safePropertyDescriptor(descriptor) {
	if (!descriptor) return descriptor;
	var safe = Object.create(null);
	if (Object.prototype.hasOwnProperty.call(descriptor, "value")) safe.value = descriptor.value;
	if (Object.prototype.hasOwnProperty.call(descriptor, "writable")) safe.writable = descriptor.writable;
	if (Object.prototype.hasOwnProperty.call(descriptor, "get")) safe.get = descriptor.get;
	if (Object.prototype.hasOwnProperty.call(descriptor, "set")) safe.set = descriptor.set;
	if (Object.prototype.hasOwnProperty.call(descriptor, "configurable")) safe.configurable = descriptor.configurable;
	if (Object.prototype.hasOwnProperty.call(descriptor, "enumerable")) safe.enumerable = descriptor.enumerable;
	return safe;
}
function _validateExpectedCalls(expected) {
	if (typeof expected === "undefined") return 1;
	if (typeof expected !== "number" || !isFinite(expected)) throw _invalidExpectedType(expected);
	if (Math.floor(expected) !== expected) {
		var rangeErr = /* @__PURE__ */ new RangeError("The value of \"expected\" is out of range. It must be an integer. Received " + expected);
		rangeErr.code = "ERR_OUT_OF_RANGE";
		throw rangeErr;
	}
	if (expected < 1 || expected > 4294967295) {
		var rangeErr2 = /* @__PURE__ */ new RangeError("The value of \"expected\" is out of range. It must be >= 1 && <= 4294967295. Received " + expected);
		rangeErr2.code = "ERR_OUT_OF_RANGE";
		throw rangeErr2;
	}
	return expected;
}
function CallTrackerContext(expected, name, stackTrace) {
	this._calls = [];
	this._expected = expected;
	this._stackTrace = stackTrace;
	this._name = name;
}
CallTrackerContext.prototype.track = function(thisArg, args) {
	_freeze(args);
	this._calls.push(_freeze({
		thisArg,
		arguments: args
	}));
};
CallTrackerContext.prototype.getDelta = function() {
	return this._calls.length - this._expected;
};
CallTrackerContext.prototype.getCalls = function() {
	return _freeze(this._calls.slice());
};
CallTrackerContext.prototype.reset = function() {
	this._calls = [];
};
CallTrackerContext.prototype.report = function() {
	if (this.getDelta() !== 0) return {
		message: "Expected the " + this._name + " function to be executed " + this._expected + " time(s) but was executed " + this._calls.length + " time(s).",
		actual: this._calls.length,
		expected: this._expected,
		operator: this._name,
		stack: this._stackTrace
	};
};
function _getContextName(fn) {
	return fn && fn.name ? fn.name : "calls";
}
function CallTracker() {
	this._trackedFunctions = [];
	this._contexts = /* @__PURE__ */ new WeakMap();
}
CallTracker.prototype._getContext = function(tracked) {
	var context = this._contexts.get(tracked);
	if (!context) {
		var invalidError = /* @__PURE__ */ new TypeError("The argument 'tracked' is not a tracked function. Received " + _callTrackerTypeLabel(tracked));
		invalidError.code = "ERR_INVALID_ARG_VALUE";
		throw invalidError;
	}
	return context;
};
CallTracker.prototype.calls = function(fn, expected) {
	if (__callTrackerExiting) {
		var unavailable = /* @__PURE__ */ new Error("assert.CallTracker is not available during process exit");
		unavailable.code = "ERR_UNAVAILABLE_DURING_EXIT";
		throw unavailable;
	}
	if (typeof fn === "number") {
		expected = fn;
		fn = function() {};
	} else if (fn === void 0) fn = function() {};
	else if (typeof fn !== "function" && arguments.length > 1) {
		expected = _validateExpectedCalls(expected);
		return new Proxy(fn, {});
	} else if (typeof fn !== "function") {
		var nonFnErr = _invalidExpectedType(fn);
		nonFnErr.message = "The first argument must be of type function. Received type \"" + _callTrackerTypeLabel(fn) + "\"";
		nonFnErr.code = "ERR_INVALID_ARG_TYPE";
		throw nonFnErr;
	}
	expected = _validateExpectedCalls(expected);
	var context = new CallTrackerContext(expected, _getContextName(fn), /* @__PURE__ */ new Error());
	var wrapped = fn;
	var originalLengthDescriptor = _safePropertyDescriptor(Object.getOwnPropertyDescriptor(fn, "length"));
	var originalLength = originalLengthDescriptor && Object.prototype.hasOwnProperty.call(originalLengthDescriptor, "value") && typeof originalLengthDescriptor.value === "number" ? originalLengthDescriptor.value : 0;
	var tracked = (function() {
		var body = function() {
			context.track(this, _cloneArguments(arguments));
			return wrapped.apply(this, arguments);
		};
		switch (originalLength) {
			case 0:
				tracked = function() {
					return body.apply(this, arguments);
				};
				break;
			case 1:
				tracked = function(arg1) {
					return body.apply(this, arguments);
				};
				break;
			case 2:
				tracked = function(arg1, arg2) {
					return body.apply(this, arguments);
				};
				break;
			case 3:
				tracked = function(arg1, arg2, arg3) {
					return body.apply(this, arguments);
				};
				break;
			case 4:
				tracked = function(arg1, arg2, arg3, arg4) {
					return body.apply(this, arguments);
				};
				break;
			default: tracked = function() {
				return body.apply(this, arguments);
			};
		}
		return tracked;
	})();
	if (originalLengthDescriptor) try {
		Object.defineProperty(tracked, "length", originalLengthDescriptor);
	} catch (e) {}
	else try {
		delete tracked.length;
	} catch (e) {}
	var properties = Object.getOwnPropertyNames(fn);
	for (var p = 0; p < properties.length; p++) {
		var key = properties[p];
		if (key === "length") continue;
		if (key === "prototype" && typeof fn === "function") continue;
		try {
			Object.defineProperty(tracked, key, _safePropertyDescriptor(Object.getOwnPropertyDescriptor(fn, key)));
		} catch (e) {}
	}
	try {
		Object.defineProperty(tracked, "name", _safePropertyDescriptor(Object.getOwnPropertyDescriptor(fn, "name")));
	} catch (e) {}
	this._trackedFunctions.push(tracked);
	this._contexts.set(tracked, context);
	return tracked;
};
CallTracker.prototype.getCalls = function(tracked) {
	return this._getContext(tracked).getCalls();
};
CallTracker.prototype.report = function() {
	var errors = [];
	for (var i = 0; i < this._trackedFunctions.length; i++) {
		var item = this._getContext(this._trackedFunctions[i]).report();
		if (item) errors.push(item);
	}
	return _freeze(errors);
};
CallTracker.prototype.reset = function(tracked) {
	if (tracked === void 0) {
		for (var i = 0; i < this._trackedFunctions.length; i++) this._getContext(this._trackedFunctions[i]).reset();
		return;
	}
	this._getContext(tracked).reset();
};
CallTracker.prototype.verify = function() {
	var errors = this.report();
	if (errors.length > 0) throw new AssertionError({
		message: errors.length === 1 ? errors[0].message : "Functions were not called the expected number of times",
		details: errors,
		actual: void 0,
		expected: void 0,
		operator: "verify"
	});
};
function throws(fn, expected, message) {
	var threw = false;
	var caught;
	try {
		fn();
	} catch (e) {
		threw = true;
		caught = e;
	}
	if (!threw) throw new AssertionError({
		message: message || "Missing expected exception.",
		operator: "throws",
		stackStartFn: throws
	});
	if (expected) {
		if (_isErrorConstructor(expected)) {
			if (caught instanceof expected) return;
			throw new AssertionError({
				message: "The error is expected to be an instance of \"" + (expected.name || "Error") + "\". Received \"" + _errorTypeName(caught) + "\"\n\nError message:\n\n" + _inspect(caught),
				actual: caught,
				expected,
				operator: "throws",
				stackStartFn: throws
			});
		}
		if (typeof expected === "function") {
			if (expected(caught) === true) return;
			throw new AssertionError({
				message: message || "Unexpected exception",
				actual: caught,
				expected,
				operator: "throws",
				stackStartFn: throws
			});
		}
		if (expected instanceof RegExp) {
			if (expected.test(String(caught))) return;
			throw new AssertionError({
				message: message || "Unexpected exception",
				actual: caught,
				expected,
				operator: "throws",
				stackStartFn: throws
			});
		}
		if (typeof expected === "object" && expected !== null) {
			if (caught == null) throw new AssertionError({
				message: message || "Missing expected exception.",
				operator: "throws",
				stackStartFn: throws
			});
			var keys = Object.keys(expected);
			for (var i = 0; i < keys.length; i++) {
				var key = keys[i];
				if (expected[key] instanceof RegExp) {
					if (!expected[key].test(String(caught[key]))) throw new AssertionError({
						message: message || "The error property \"" + key + "\" (\"" + caught[key] + "\") does not match " + expected[key],
						actual: caught,
						expected,
						operator: "throws",
						stackStartFn: throws
					});
				} else if (!_deepEqual(caught[key], expected[key], void 0, void 0, true)) throw new AssertionError({
					message: message || "Expected error property \"" + key + "\" to be " + _inspect(expected[key]) + ", got " + _inspect(caught[key]),
					actual: caught,
					expected,
					operator: "throws",
					stackStartFn: throws
				});
			}
			return;
		}
	}
}
function doesNotThrow(fn, expected, message) {
	try {
		fn();
	} catch (e) {
		throw new AssertionError({
			message: message || "Got unwanted exception",
			actual: e,
			operator: "doesNotThrow",
			stackStartFn: doesNotThrow
		});
	}
}
function ifError(err) {
	if (err !== null && err !== void 0) throw new AssertionError({
		message: "ifError got unwanted exception: " + _ifErrorValue(err),
		actual: err,
		expected: null,
		operator: "ifError",
		stackStartFn: ifError
	});
}
function fail(message) {
	if (typeof process !== "undefined" && arguments.length > 1) {
		if (!__assertFailDeprecationWarned) {
			__assertFailDeprecationWarned = true;
			var warning = /* @__PURE__ */ new Error("assert.fail() with more than one argument is deprecated. Please use assert.strictEqual() instead or only pass a message.");
			warning.name = "DeprecationWarning";
			warning.code = "DEP0094";
			try {
				if (typeof process.emitWarning === "function") process.emitWarning(warning);
				else if (typeof process.emit === "function") process.emit("warning", warning);
			} catch (e) {}
		}
	}
	if (message === void 0 && arguments.length === 0) throw new AssertionError({
		message: "Failed",
		operator: "fail",
		generatedMessage: true,
		stackStartFn: _isFunction(arguments[4]) ? arguments[4] : null
	});
	if (message instanceof Error) throw message;
	if (arguments.length === 1) {
		var failMessage = typeof message === "string" ? message : _formatFailValue(message);
		throw new AssertionError({
			actual: void 0,
			expected: void 0,
			operator: "fail",
			message: failMessage,
			generatedMessage: false,
			stackStartFn: _isFunction(arguments[4]) ? arguments[4] : null
		});
	}
	if (arguments.length === 2) throw new AssertionError({
		actual: arguments[0],
		expected: arguments[1],
		operator: "!=",
		message: _formatFailValue(arguments[0]) + " != " + _formatFailValue(arguments[1]),
		generatedMessage: true,
		stackStartFn: _isFunction(arguments[4]) ? arguments[4] : null
	});
	if (arguments[3] === void 0 && arguments[2] instanceof Error) throw arguments[2];
	var operator = arguments[3] || "fail";
	var failMessage = arguments[2];
	var generated = true;
	if (failMessage !== void 0) generated = false;
	else failMessage = _formatFailValue(arguments[0]) + " " + operator + " " + _formatFailValue(arguments[1]);
	throw new AssertionError({
		actual: arguments[0],
		expected: arguments[1],
		operator,
		message: failMessage,
		generatedMessage: generated,
		stackStartFn: _isFunction(arguments[4]) ? arguments[4] : null
	});
}
function match(string, regexp, message) {
	if (!regexp.test(string)) throw new AssertionError({
		message,
		actual: string,
		expected: regexp,
		operator: "match",
		stackStartFn: match
	});
}
function doesNotMatch(string, regexp, message) {
	if (regexp.test(string)) throw new AssertionError({
		message,
		actual: string,
		expected: regexp,
		operator: "doesNotMatch",
		stackStartFn: doesNotMatch
	});
}
async function rejects(asyncFn, expected, message) {
	if (typeof asyncFn !== "function" && !(asyncFn instanceof Promise) && !(asyncFn && typeof asyncFn === "object" && typeof asyncFn.then === "function" && typeof asyncFn.catch === "function")) {
		var argTypeErr = /* @__PURE__ */ new TypeError("The \"promiseFn\" argument must be of type function or an instance of Promise. Received type " + _typeof(asyncFn) + " (" + _inspect(asyncFn) + ")");
		argTypeErr.code = "ERR_INVALID_ARG_TYPE";
		throw argTypeErr;
	}
	var threw = false;
	var caught;
	var promise;
	if (typeof asyncFn === "function") {
		var result = asyncFn();
		if (result instanceof Promise) promise = result;
		else if (result && typeof result === "object" && typeof result.then === "function" && typeof result.catch === "function") promise = Promise.resolve(result);
		else {
			var invalidReturn = /* @__PURE__ */ new TypeError("Expected instance of Promise to be returned from the \"promiseFn\" function but got " + (result === void 0 ? "undefined" : _formatPromiseExpectation(result)) + ".");
			invalidReturn.code = "ERR_INVALID_RETURN_VALUE";
			throw invalidReturn;
		}
	} else if (asyncFn instanceof Promise) promise = asyncFn;
	else if (asyncFn && typeof asyncFn === "object" && typeof asyncFn.then === "function" && typeof asyncFn.catch === "function") promise = Promise.resolve(asyncFn);
	else if (asyncFn && typeof asyncFn === "object" && typeof asyncFn.then === "function") {
		var argTypeErr2 = /* @__PURE__ */ new TypeError("The \"promiseFn\" argument must be of type function or an instance of Promise. Received an instance of Object");
		argTypeErr2.code = "ERR_INVALID_ARG_TYPE";
		throw argTypeErr2;
	}
	try {
		await promise;
	} catch (e) {
		threw = true;
		caught = e;
	}
	if (!threw) {
		var missingFnName = typeof asyncFn === "function" ? asyncFn.name || "anonymous" : "";
		throw new AssertionError({
			message: message || "Missing expected rejection" + (missingFnName ? " (" + missingFnName + ")" : "") + ".",
			actual: void 0,
			expected,
			operator: "rejects",
			generatedMessage: !message,
			stackStartFn: rejects
		});
	}
	if (expected !== void 0 && expected !== null) {
		if (_isErrorConstructor(expected)) {
			if (caught instanceof expected) return;
			throw new AssertionError({
				message: "The error is expected to be an instance of \"" + (expected.name || "Error") + "\". Received \"" + _errorTypeName(caught) + "\"",
				actual: caught,
				expected,
				operator: "rejects",
				stackStartFn: rejects
			});
		}
		if (typeof expected === "function") {
			var validationResult = expected(caught);
			if (validationResult === true) return;
			throw new AssertionError({
				message: "The \"validate\" validation function is expected to return \"true\". Received " + _inspect(validationResult) + "\n\nCaught error:\n\n" + (caught instanceof Error ? caught.constructor.name + ": " + caught.message : _inspect(caught)),
				actual: caught,
				expected,
				operator: "rejects",
				code: "ERR_ASSERTION",
				stackStartFn: rejects
			});
		}
		if (expected instanceof RegExp) {
			if (expected.test(String(caught))) return;
			throw new AssertionError({
				message: message || "Unexpected rejection",
				actual: caught,
				expected,
				operator: "rejects",
				stackStartFn: rejects
			});
		}
		if (typeof expected === "object") {
			var keys = Object.keys(expected);
			for (var i = 0; i < keys.length; i++) {
				var key = keys[i];
				if (key === "message" && expected.message instanceof RegExp) {
					if (!expected.message.test(caught.message)) throw new AssertionError({
						message: message || "Error message mismatch",
						actual: caught[key],
						expected: expected[key],
						operator: "rejects",
						stackStartFn: rejects
					});
				} else if (!_deepEqual(caught[key], expected[key], void 0, void 0, true)) throw new AssertionError({
					message: message || "Expected the " + key + " property on the thrown error to be " + _inspect(expected[key]) + ", got " + _inspect(caught[key]),
					actual: caught,
					expected,
					operator: "rejects",
					generatedMessage: !message,
					stackStartFn: rejects
				});
			}
			return;
		}
	}
}
async function doesNotReject(asyncFn, expected, message) {
	if (typeof expected === "string") {
		message = expected;
		expected = void 0;
	}
	var promise;
	if (_isFunction(asyncFn)) {
		var result = asyncFn();
		if (result instanceof Promise) promise = result;
		else if (result && typeof result === "object" && typeof result.then === "function" && typeof result.catch === "function") promise = Promise.resolve(result);
		else {
			var expectedReturn = "Expected instance of Promise to be returned from the \"promiseFn\" function but got " + _formatPromiseExpectation(result) + ".";
			var fnErr = new TypeError(expectedReturn);
			fnErr.code = "ERR_INVALID_RETURN_VALUE";
			throw fnErr;
		}
	} else if (asyncFn instanceof Promise) promise = asyncFn;
	else if (asyncFn && typeof asyncFn === "object" && typeof asyncFn.then === "function" && typeof asyncFn.catch === "function") promise = Promise.resolve(asyncFn);
	else if (asyncFn && typeof asyncFn === "object" && typeof asyncFn.then === "function") _throwInvalidArgType(asyncFn);
	else _throwInvalidArgType(asyncFn, "The \"promiseFn\" argument must be of type function or an instance of Promise. Received type " + _typeof(asyncFn) + " (" + _inspect(asyncFn) + ")");
	try {
		await promise;
	} catch (e) {
		if (typeof expected === "function") expected(e);
		throw new AssertionError({
			message: message || "Got unwanted rejection.\nActual message: \"" + _ifErrorValue(e) + "\"",
			actual: e,
			operator: "doesNotReject",
			stackStartFn: doesNotReject
		});
	}
}
function assert(value, message) {
	if (value) return;
	var defaultMessage = _formatValue(value) + " == " + _formatValue(true);
	var generatedMessage = true;
	if (message === void 0) message = defaultMessage;
	else generatedMessage = false;
	throw new AssertionError({
		message,
		actual: value,
		expected: true,
		operator: "==",
		generatedMessage,
		stackStartFn: assert
	});
}
assert.ok = ok;
assert.equal = equal;
assert.notEqual = notEqual;
assert.strictEqual = strictEqual;
assert.notStrictEqual = notStrictEqual;
assert.deepEqual = deepEqual;
assert.deepStrictEqual = deepStrictEqual;
assert.notDeepEqual = notDeepEqual;
assert.notDeepStrictEqual = notDeepStrictEqual;
assert.throws = throws;
assert.doesNotThrow = doesNotThrow;
assert.rejects = rejects;
assert.doesNotReject = doesNotReject;
assert.ifError = ifError;
assert.fail = fail;
assert.match = match;
assert.doesNotMatch = doesNotMatch;
assert.partialDeepStrictEqual = partialDeepStrictEqual;
assert.AssertionError = AssertionError;
assert.CallTracker = CallTracker;
assert._isDeepStrictEqual = _isDeepStrictEqual;
var strict = function strict(value, message) {
	if (!value) {
		var defaultMessage = "The expression evaluated to a falsy value";
		var line = message ? "" : _getCallerLine(strict);
		if (line) defaultMessage += ":\n\n" + line + "\n";
		throw new AssertionError({
			message: message || defaultMessage,
			actual: value,
			expected: true,
			operator: "==",
			stackStartFn: strict
		});
	}
};
strict.ok = ok;
strict.equal = strictEqual;
strict.notEqual = notStrictEqual;
strict.deepEqual = deepStrictEqual;
strict.notDeepEqual = notDeepStrictEqual;
strict.strictEqual = strictEqual;
strict.notStrictEqual = notStrictEqual;
strict.deepStrictEqual = deepStrictEqual;
strict.notDeepStrictEqual = notDeepStrictEqual;
strict.throws = throws;
strict.doesNotThrow = doesNotThrow;
strict.rejects = rejects;
strict.doesNotReject = doesNotReject;
strict.ifError = ifError;
strict.fail = fail;
strict.match = match;
strict.doesNotMatch = doesNotMatch;
strict.partialDeepStrictEqual = partialDeepStrictEqual;
strict.AssertionError = AssertionError;
strict.CallTracker = CallTracker;
strict.strict = strict;
assert.strict = strict;
module.exports = assert;
module.exports.ok = ok;
module.exports.equal = equal;
module.exports.notEqual = notEqual;
module.exports.strictEqual = strictEqual;
module.exports.notStrictEqual = notStrictEqual;
module.exports.deepEqual = deepEqual;
module.exports.deepStrictEqual = deepStrictEqual;
module.exports.notDeepEqual = notDeepEqual;
module.exports.notDeepStrictEqual = notDeepStrictEqual;
module.exports.throws = throws;
module.exports.doesNotThrow = doesNotThrow;
module.exports.rejects = rejects;
module.exports.doesNotReject = doesNotReject;
module.exports.ifError = ifError;
module.exports.fail = fail;
module.exports.match = match;
module.exports.doesNotMatch = doesNotMatch;
module.exports.partialDeepStrictEqual = partialDeepStrictEqual;
module.exports.AssertionError = AssertionError;
module.exports.CallTracker = CallTracker;
module.exports.strict = strict;
module.exports._isDeepStrictEqual = _isDeepStrictEqual;
//#endregion
