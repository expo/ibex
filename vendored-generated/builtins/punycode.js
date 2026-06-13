//#region src/builtins/punycode.js
var punycode = {};
var base = 36;
var tMin = 1;
var tMax = 26;
var skew = 38;
var damp = 700;
var initialBias = 72;
var initialN = 128;
var delimiter = "-";
var maxInt = 2147483647;
function error(type) {
	throw new RangeError("punycode: " + type);
}
function digitToBasic(digit, flag) {
	return digit + 22 + 75 * (digit < 26 ? 1 : 0) - ((flag !== 0 ? 1 : 0) << 5);
}
function basicToDigit(cp) {
	if (cp - 48 < 10) return cp - 22;
	if (cp - 65 < 26) return cp - 65;
	if (cp - 97 < 26) return cp - 97;
	return base;
}
function adapt(delta, numPoints, firstTime) {
	var k = 0;
	delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
	delta += Math.floor(delta / numPoints);
	while (delta > (base - tMin) * tMax >> 1) {
		delta = Math.floor(delta / (base - tMin));
		k += base;
	}
	return Math.floor(k + (base - tMin + 1) * delta / (delta + skew));
}
function ucs2decode(string) {
	var output = [];
	var counter = 0;
	var length = string.length;
	while (counter < length) {
		var value = string.charCodeAt(counter++);
		if (value >= 55296 && value <= 56319 && counter < length) {
			var extra = string.charCodeAt(counter++);
			if ((extra & 64512) === 56320) output.push(((value & 1023) << 10) + (extra & 1023) + 65536);
			else {
				output.push(value);
				counter--;
			}
		} else output.push(value);
	}
	return output;
}
function ucs2encode(array) {
	var output = "";
	for (var i = 0; i < array.length; i++) {
		var value = array[i];
		if (value > 65535) {
			value -= 65536;
			output += String.fromCharCode(value >>> 10 & 1023 | 55296);
			value = 56320 | value & 1023;
		}
		output += String.fromCharCode(value);
	}
	return output;
}
function decode(input) {
	var output = [];
	var inputLength = input.length;
	var i = 0;
	var n = initialN;
	var bias = initialBias;
	var basic = input.lastIndexOf(delimiter);
	if (basic < 0) basic = 0;
	for (var j = 0; j < basic; j++) {
		if (input.charCodeAt(j) >= 128) error("not-basic");
		output.push(input.charCodeAt(j));
	}
	var index = basic > 0 ? basic + 1 : 0;
	while (index < inputLength) {
		var oldi = i;
		var w = 1;
		for (var k = base;; k += base) {
			if (index >= inputLength) error("invalid-input");
			var digit = basicToDigit(input.charCodeAt(index++));
			if (digit >= base || digit > Math.floor((maxInt - i) / w)) error("overflow");
			i += digit * w;
			var t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
			if (digit < t) break;
			var baseMinusT = base - t;
			if (w > Math.floor(maxInt / baseMinusT)) error("overflow");
			w *= baseMinusT;
		}
		var out = output.length + 1;
		bias = adapt(i - oldi, out, oldi === 0);
		if (Math.floor(i / out) > maxInt - n) error("overflow");
		n += Math.floor(i / out);
		i %= out;
		output.splice(i++, 0, n);
	}
	return ucs2encode(output);
}
function encode(input) {
	var output = [];
	var inputArray = ucs2decode(input);
	var inputLength = inputArray.length;
	var n = initialN;
	var delta = 0;
	var bias = initialBias;
	for (var j = 0; j < inputLength; j++) if (inputArray[j] < 128) output.push(String.fromCharCode(inputArray[j]));
	var basicLength = output.length;
	var handledCPCount = basicLength;
	if (basicLength > 0) output.push(delimiter);
	while (handledCPCount < inputLength) {
		var m = maxInt;
		for (var j2 = 0; j2 < inputLength; j2++) if (inputArray[j2] >= n && inputArray[j2] < m) m = inputArray[j2];
		if (m - n > Math.floor((maxInt - delta) / (handledCPCount + 1))) error("overflow");
		delta += (m - n) * (handledCPCount + 1);
		n = m;
		for (var j3 = 0; j3 < inputLength; j3++) {
			if (inputArray[j3] < n) {
				if (++delta > maxInt) error("overflow");
			}
			if (inputArray[j3] === n) {
				var q = delta;
				for (var k = base;; k += base) {
					var t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
					if (q < t) break;
					var qMinusT = q - t;
					var baseMinusT = base - t;
					output.push(String.fromCharCode(digitToBasic(t + qMinusT % baseMinusT, 0)));
					q = Math.floor(qMinusT / baseMinusT);
				}
				output.push(String.fromCharCode(digitToBasic(q, 0)));
				bias = adapt(delta, handledCPCount + 1, handledCPCount === basicLength);
				delta = 0;
				handledCPCount++;
			}
		}
		delta++;
		n++;
	}
	return output.join("");
}
function toASCII(domain) {
	var parts = domain.split(".");
	var result = [];
	for (var i = 0; i < parts.length; i++) {
		var part = parts[i];
		var hasNonASCII = false;
		for (var j = 0; j < part.length; j++) if (part.charCodeAt(j) >= 128) {
			hasNonASCII = true;
			break;
		}
		if (hasNonASCII) result.push("xn--" + encode(part));
		else result.push(part);
	}
	return result.join(".");
}
function toUnicode(domain) {
	var parts = domain.split(".");
	var result = [];
	for (var i = 0; i < parts.length; i++) {
		var part = parts[i];
		if (part.indexOf("xn--") === 0) try {
			result.push(decode(part.substring(4)));
		} catch (e) {
			result.push(part);
		}
		else result.push(part);
	}
	return result.join(".");
}
punycode.version = "2.3.1";
punycode.ucs2 = {
	decode: ucs2decode,
	encode: ucs2encode
};
punycode.decode = decode;
punycode.encode = encode;
punycode.toASCII = toASCII;
punycode.toUnicode = toUnicode;
module.exports = punycode;
//#endregion
