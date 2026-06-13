//#region src/builtins/path.js
var SLASH = 47;
var BSLASH = 92;
var DOT = 46;
var COLON = 58;
function isWS(c) {
	return c === SLASH || c === BSLASH;
}
function isPS(c) {
	return c === SLASH;
}
function isDR(c) {
	return c >= 65 && c <= 90 || c >= 97 && c <= 122;
}
function _cwd() {
	return typeof process !== "undefined" && process.cwd ? process.cwd() : "/";
}
function _invalidArgType(name, expected, actual) {
	var received;
	if (actual === null) received = "null";
	else if (actual === void 0) received = "undefined";
	else if (Array.isArray(actual)) received = "an instance of Array";
	else if (typeof actual === "string") received = "type string (" + actual + ")";
	else if (typeof actual === "number") received = "type number (" + actual + ")";
	else if (typeof actual === "boolean") received = "type boolean (" + actual + ")";
	else received = "type " + typeof actual;
	var err = /* @__PURE__ */ new TypeError("The \"" + name + "\" argument must be of type " + expected + ". Received " + received);
	err.code = "ERR_INVALID_ARG_TYPE";
	return err;
}
function nStr(path, allowAboveRoot, sep, isSep) {
	var res = "", lsl = 0, ls = -1, dots = 0, code = 0;
	for (var i = 0; i <= path.length; ++i) {
		if (i < path.length) code = path.charCodeAt(i);
		else if (isSep(code)) break;
		else code = SLASH;
		if (isSep(code)) {
			if (ls === i - 1 || dots === 1) {} else if (dots === 2) {
				if (res.length < 2 || lsl !== 2 || res.charCodeAt(res.length - 1) !== DOT || res.charCodeAt(res.length - 2) !== DOT) {
					if (res.length > 2) {
						var j = res.lastIndexOf(sep);
						if (j === -1) {
							res = "";
							lsl = 0;
						} else {
							res = res.slice(0, j);
							lsl = res.length - 1 - res.lastIndexOf(sep);
						}
						ls = i;
						dots = 0;
						continue;
					} else if (res.length !== 0) {
						res = "";
						lsl = 0;
						ls = i;
						dots = 0;
						continue;
					}
				}
				if (allowAboveRoot) {
					res += res.length > 0 ? sep + ".." : "..";
					lsl = 2;
				}
			} else {
				if (res.length > 0) res += sep + path.slice(ls + 1, i);
				else res = path.slice(ls + 1, i);
				lsl = i - ls - 1;
			}
			ls = i;
			dots = 0;
		} else if (code === DOT && dots !== -1) ++dots;
		else dots = -1;
	}
	return res;
}
var posix = {
	sep: "/",
	delimiter: ":",
	resolve: function resolve() {
		var rp = "", ra = false;
		for (var i = arguments.length - 1; i >= -1 && !ra; i--) {
			var p = i >= 0 ? arguments[i] : _cwd();
			if (typeof p !== "string") throw _invalidArgType("path", "string", p);
			if (p.length === 0) continue;
			rp = p + "/" + rp;
			ra = p.charCodeAt(0) === SLASH;
		}
		rp = nStr(rp, !ra, "/", isPS);
		if (ra) return "/" + rp;
		return rp.length > 0 ? rp : ".";
	},
	normalize: function normalize(p) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		if (p.length === 0) return ".";
		var isAbs = p.charCodeAt(0) === SLASH;
		var trail = p.charCodeAt(p.length - 1) === SLASH;
		p = nStr(p, !isAbs, "/", isPS);
		if (p.length === 0) {
			if (isAbs) return "/";
			return trail ? "./" : ".";
		}
		if (trail) p += "/";
		return isAbs ? "/" + p : p;
	},
	isAbsolute: function isAbsolute(p) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		return p.length > 0 && p.charCodeAt(0) === SLASH;
	},
	join: function join() {
		if (arguments.length === 0) return ".";
		var joined;
		for (var i = 0; i < arguments.length; ++i) {
			var a = arguments[i];
			if (typeof a !== "string") throw _invalidArgType("path", "string", a);
			if (a.length > 0) if (joined === void 0) joined = a;
			else joined += "/" + a;
		}
		if (joined === void 0) return ".";
		return posix.normalize(joined);
	},
	relative: function relative(from, to) {
		if (typeof from !== "string") throw _invalidArgType("from", "string", from);
		if (typeof to !== "string") throw _invalidArgType("to", "string", to);
		if (from === to) return "";
		from = posix.resolve(from);
		to = posix.resolve(to);
		if (from === to) return "";
		var fi = 1, fe = from.length, fl = fe - fi;
		var ti = 1, tl = to.length - ti;
		var len = fl < tl ? fl : tl, lcs = -1, i = 0;
		for (; i < len; i++) {
			var fc = from.charCodeAt(fi + i);
			if (fc !== to.charCodeAt(ti + i)) break;
			else if (fc === SLASH) lcs = i;
		}
		if (i === len) {
			if (tl > len) {
				if (to.charCodeAt(ti + i) === SLASH) return to.slice(ti + i + 1);
				if (i === 0) return to.slice(ti + i);
			} else if (fl > len) {
				if (from.charCodeAt(fi + i) === SLASH) lcs = i;
				else if (i === 0) lcs = 0;
			}
		}
		var out = "";
		for (i = fi + lcs + 1; i <= fe; ++i) if (i === fe || from.charCodeAt(i) === SLASH) out += out.length === 0 ? ".." : "/..";
		return out + to.slice(ti + lcs);
	},
	dirname: function dirname(p) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		if (p.length === 0) return ".";
		var hr = p.charCodeAt(0) === SLASH, end = -1, ms = true;
		for (var i = p.length - 1; i >= 1; --i) if (p.charCodeAt(i) === SLASH) {
			if (!ms) {
				end = i;
				break;
			}
		} else ms = false;
		if (end === -1) return hr ? "/" : ".";
		if (hr && end === 1) return "//";
		return p.slice(0, end);
	},
	basename: function basename(p, ext) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		if (ext !== void 0 && typeof ext !== "string") throw _invalidArgType("ext", "string", ext);
		var s = 0, end = -1, ms = true, i;
		if (ext !== void 0 && ext.length > 0 && ext.length <= p.length) {
			if (ext === p) return "";
			var ei = ext.length - 1, fnse = -1;
			for (i = p.length - 1; i >= 0; --i) {
				var c = p.charCodeAt(i);
				if (c === SLASH) {
					if (!ms) {
						s = i + 1;
						break;
					}
				} else {
					if (fnse === -1) {
						ms = false;
						fnse = i + 1;
					}
					if (ei >= 0) if (c === ext.charCodeAt(ei)) {
						if (--ei === -1) end = i;
					} else {
						ei = -1;
						end = fnse;
					}
				}
			}
			if (s === end) end = fnse;
			else if (end === -1) end = p.length;
			return p.slice(s, end);
		}
		for (i = p.length - 1; i >= 0; --i) if (p.charCodeAt(i) === SLASH) {
			if (!ms) {
				s = i + 1;
				break;
			}
		} else if (end === -1) {
			ms = false;
			end = i + 1;
		}
		if (end === -1) return "";
		return p.slice(s, end);
	},
	extname: function extname(p) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		var sd = -1, sp = 0, end = -1, ms = true, pds = 0;
		for (var i = p.length - 1; i >= 0; --i) {
			var c = p.charCodeAt(i);
			if (c === SLASH) {
				if (!ms) {
					sp = i + 1;
					break;
				}
				continue;
			}
			if (end === -1) {
				ms = false;
				end = i + 1;
			}
			if (c === DOT) {
				if (sd === -1) sd = i;
				else if (pds !== 1) pds = 1;
			} else if (sd !== -1) pds = -1;
		}
		if (sd === -1 || end === -1 || pds === 0 || pds === 1 && sd === end - 1 && sd === sp + 1) return "";
		return p.slice(sd, end);
	},
	parse: function parse(p) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		var ret = {
			root: "",
			dir: "",
			base: "",
			ext: "",
			name: ""
		};
		if (p.length === 0) return ret;
		var isAbs = p.charCodeAt(0) === SLASH, start;
		if (isAbs) {
			ret.root = "/";
			start = 1;
		} else start = 0;
		var sd = -1, sp = 0, end = -1, ms = true, pds = 0;
		for (var i = p.length - 1; i >= start; --i) {
			var c = p.charCodeAt(i);
			if (c === SLASH) {
				if (!ms) {
					sp = i + 1;
					break;
				}
				continue;
			}
			if (end === -1) {
				ms = false;
				end = i + 1;
			}
			if (c === DOT) {
				if (sd === -1) sd = i;
				else if (pds !== 1) pds = 1;
			} else if (sd !== -1) pds = -1;
		}
		if (end !== -1) {
			var s = sp === 0 && isAbs ? 1 : sp;
			if (sd === -1 || pds === 0 || pds === 1 && sd === end - 1 && sd === sp + 1) ret.base = ret.name = p.slice(s, end);
			else {
				ret.name = p.slice(s, sd);
				ret.base = p.slice(s, end);
				ret.ext = p.slice(sd, end);
			}
		}
		if (sp > 0) ret.dir = p.slice(0, sp - 1);
		else if (isAbs) ret.dir = "/";
		return ret;
	},
	format: function format(obj) {
		if (obj === null || typeof obj !== "object") throw _invalidArgType("pathObject", "object", obj);
		var dir = obj.dir || obj.root;
		var base = obj.base || (obj.name || "") + (obj.ext ? (obj.ext.charCodeAt(0) === DOT ? "" : ".") + obj.ext : "");
		if (!dir) return base;
		return dir === obj.root ? dir + base : dir + "/" + base;
	},
	toNamespacedPath: function toNamespacedPath(p) {
		return p;
	}
};
posix._makeLong = posix.toNamespacedPath;
var win32 = {
	sep: "\\",
	delimiter: ";",
	resolve: function resolve() {
		var rd = "", rt = "", ra = false;
		for (var i = arguments.length - 1; i >= -1; i--) {
			var p;
			if (i >= 0) {
				p = arguments[i];
				if (typeof p !== "string") throw _invalidArgType("path", "string", p);
				if (p.length === 0) continue;
			} else if (rd.length === 0) p = _cwd();
			else p = _cwd();
			var len = p.length, re = 0, dev = "", ia = false, code = p.charCodeAt(0);
			if (len === 1) {
				if (isWS(code)) {
					re = 1;
					ia = true;
				}
			} else if (isWS(code)) {
				ia = true;
				if (isWS(p.charCodeAt(1))) {
					var j = 2, last = j;
					while (j < len && !isWS(p.charCodeAt(j))) j++;
					if (j < len && j !== last) {
						var fp = p.slice(last, j);
						last = j;
						while (j < len && isWS(p.charCodeAt(j))) j++;
						if (j < len && j !== last) {
							last = j;
							while (j < len && !isWS(p.charCodeAt(j))) j++;
							if (j === len || j !== last) {
								dev = "\\\\" + fp + "\\" + p.slice(last, j);
								re = j;
							}
						}
					}
				} else re = 1;
			} else if (isDR(code) && p.charCodeAt(1) === COLON) {
				dev = p.slice(0, 2);
				re = 2;
				if (len > 2 && isWS(p.charCodeAt(2))) {
					ia = true;
					re = 3;
				}
			}
			if (dev.length > 0) if (rd.length > 0) {
				if (dev.toLowerCase() !== rd.toLowerCase()) continue;
			} else rd = dev;
			if (ra) {
				if (rd.length > 0) break;
			} else {
				rt = p.slice(re) + "\\" + rt;
				ra = ia;
				if (ia && rd.length > 0) break;
			}
		}
		rt = nStr(rt, !ra, "\\", isWS);
		return rd + (ra ? "\\" : "") + rt || ".";
	},
	normalize: function normalize(p) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		var len = p.length;
		if (len === 0) return ".";
		var re = 0, dev, ia = false, code = p.charCodeAt(0);
		if (len === 1) return isPS(code) ? "\\" : p;
		if (isWS(code)) {
			ia = true;
			if (isWS(p.charCodeAt(1))) {
				var j = 2, last = j;
				while (j < len && !isWS(p.charCodeAt(j))) j++;
				if (j < len && j !== last) {
					var fp = p.slice(last, j);
					last = j;
					while (j < len && isWS(p.charCodeAt(j))) j++;
					if (j < len && j !== last) {
						last = j;
						while (j < len && !isWS(p.charCodeAt(j))) j++;
						if (j === len) return "\\\\" + fp + "\\" + p.slice(last) + "\\";
						if (j !== last) {
							dev = "\\\\" + fp + "\\" + p.slice(last, j);
							re = j;
						}
					}
				}
			} else re = 1;
		} else if (isDR(code) && p.charCodeAt(1) === COLON) {
			dev = p.slice(0, 2);
			re = 2;
			if (len > 2 && isWS(p.charCodeAt(2))) {
				ia = true;
				re = 3;
			}
		}
		var tail = re < len ? nStr(p.slice(re), !ia, "\\", isWS) : "";
		if (tail.length === 0 && !ia) tail = ".";
		if (tail.length > 0 && isWS(p.charCodeAt(len - 1))) tail += "\\";
		if (dev === void 0) return ia ? "\\" + tail : tail;
		return ia ? dev + "\\" + tail : dev + tail;
	},
	isAbsolute: function isAbsolute(p) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		var len = p.length;
		if (len === 0) return false;
		var c = p.charCodeAt(0);
		if (isWS(c)) return true;
		if (isDR(c) && len > 2 && p.charCodeAt(1) === COLON && isWS(p.charCodeAt(2))) return true;
		return false;
	},
	join: function join() {
		if (arguments.length === 0) return ".";
		var joined, fp;
		for (var i = 0; i < arguments.length; ++i) {
			var a = arguments[i];
			if (typeof a !== "string") throw _invalidArgType("path", "string", a);
			if (a.length > 0) if (joined === void 0) joined = fp = a;
			else joined += "\\" + a;
		}
		if (joined === void 0) return ".";
		var nr = true, sc = 0;
		if (isWS(fp.charCodeAt(0))) {
			++sc;
			var fl = fp.length;
			if (fl > 1 && isWS(fp.charCodeAt(1))) {
				++sc;
				if (fl > 2) if (isWS(fp.charCodeAt(2))) ++sc;
				else nr = false;
			}
		}
		if (nr) {
			while (sc < joined.length && isWS(joined.charCodeAt(sc))) sc++;
			if (sc >= 2) joined = "\\" + joined.slice(sc);
		}
		return win32.normalize(joined);
	},
	relative: function relative(from, to) {
		if (typeof from !== "string") throw _invalidArgType("from", "string", from);
		if (typeof to !== "string") throw _invalidArgType("to", "string", to);
		if (from === to) return "";
		var fO = win32.resolve(from), tO = win32.resolve(to);
		if (fO === tO) return "";
		from = fO.toLowerCase();
		to = tO.toLowerCase();
		if (from === to) return "";
		var fi = 0;
		while (fi < from.length && from.charCodeAt(fi) === BSLASH) fi++;
		var fe = from.length;
		while (fe - 1 > fi && from.charCodeAt(fe - 1) === BSLASH) fe--;
		var fl = fe - fi;
		var ti = 0;
		while (ti < to.length && to.charCodeAt(ti) === BSLASH) ti++;
		var te = to.length;
		while (te - 1 > ti && to.charCodeAt(te - 1) === BSLASH) te--;
		var tl = te - ti;
		var len = fl < tl ? fl : tl, lcs = -1, i = 0;
		for (; i < len; i++) {
			var fc = from.charCodeAt(fi + i);
			if (fc !== to.charCodeAt(ti + i)) break;
			else if (fc === BSLASH) lcs = i;
		}
		if (i !== len) {
			if (lcs === -1) return tO;
		} else {
			if (tl > len) {
				if (to.charCodeAt(ti + i) === BSLASH) return tO.slice(ti + i + 1);
				if (i === 2) return tO.slice(ti + i);
			}
			if (fl > len) {
				if (from.charCodeAt(fi + i) === BSLASH) lcs = i;
				else if (i === 2) lcs = 3;
			}
			if (lcs === -1) lcs = 0;
		}
		var out = "";
		for (i = fi + lcs + 1; i <= fe; ++i) if (i === fe || from.charCodeAt(i) === BSLASH) out += out.length === 0 ? ".." : "\\..";
		ti += lcs;
		if (out.length > 0) return out + tO.slice(ti, te);
		if (tO.charCodeAt(ti) === BSLASH) ++ti;
		return tO.slice(ti, te);
	},
	dirname: function dirname(p) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		var len = p.length;
		if (len === 0) return ".";
		var re = -1, off = 0, code = p.charCodeAt(0);
		if (len === 1) return isWS(code) ? p : ".";
		if (isWS(code)) {
			re = off = 1;
			if (isWS(p.charCodeAt(1))) {
				var j = 2, last = j;
				while (j < len && !isWS(p.charCodeAt(j))) j++;
				if (j < len && j !== last) {
					last = j;
					while (j < len && isWS(p.charCodeAt(j))) j++;
					if (j < len && j !== last) {
						last = j;
						while (j < len && !isWS(p.charCodeAt(j))) j++;
						if (j === len) return p;
						if (j !== last) re = off = j + 1;
					}
				}
			}
		} else if (isDR(code) && p.charCodeAt(1) === COLON) {
			re = len > 2 && isWS(p.charCodeAt(2)) ? 3 : 2;
			off = re;
		}
		var end = -1, ms = true;
		for (var i = len - 1; i >= off; --i) if (isWS(p.charCodeAt(i))) {
			if (!ms) {
				end = i;
				break;
			}
		} else ms = false;
		if (end === -1) {
			if (re === -1) return ".";
			end = re;
		}
		return p.slice(0, end);
	},
	basename: function basename(p, ext) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		if (ext !== void 0 && typeof ext !== "string") throw _invalidArgType("ext", "string", ext);
		var s = 0;
		if (p.length >= 2 && isDR(p.charCodeAt(0)) && p.charCodeAt(1) === COLON) s = 2;
		var end = -1, ms = true, i;
		if (ext !== void 0 && ext.length > 0 && ext.length <= p.length) {
			if (ext === p) return "";
			var ei = ext.length - 1, fnse = -1;
			for (i = p.length - 1; i >= s; --i) {
				var c = p.charCodeAt(i);
				if (isWS(c)) {
					if (!ms) {
						s = i + 1;
						break;
					}
				} else {
					if (fnse === -1) {
						ms = false;
						fnse = i + 1;
					}
					if (ei >= 0) if (c === ext.charCodeAt(ei)) {
						if (--ei === -1) end = i;
					} else {
						ei = -1;
						end = fnse;
					}
				}
			}
			if (s === end) end = fnse;
			else if (end === -1) end = p.length;
			return p.slice(s, end);
		}
		for (i = p.length - 1; i >= s; --i) if (isWS(p.charCodeAt(i))) {
			if (!ms) {
				s = i + 1;
				break;
			}
		} else if (end === -1) {
			ms = false;
			end = i + 1;
		}
		if (end === -1) return "";
		return p.slice(s, end);
	},
	extname: function extname(p) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		var s = 0, sd = -1, sp = 0, end = -1, ms = true, pds = 0;
		if (p.length >= 2 && p.charCodeAt(1) === COLON && isDR(p.charCodeAt(0))) s = sp = 2;
		for (var i = p.length - 1; i >= s; --i) {
			var c = p.charCodeAt(i);
			if (isWS(c)) {
				if (!ms) {
					sp = i + 1;
					break;
				}
				continue;
			}
			if (end === -1) {
				ms = false;
				end = i + 1;
			}
			if (c === DOT) {
				if (sd === -1) sd = i;
				else if (pds !== 1) pds = 1;
			} else if (sd !== -1) pds = -1;
		}
		if (sd === -1 || end === -1 || pds === 0 || pds === 1 && sd === end - 1 && sd === sp + 1) return "";
		return p.slice(sd, end);
	},
	parse: function parse(p) {
		if (typeof p !== "string") throw _invalidArgType("path", "string", p);
		var ret = {
			root: "",
			dir: "",
			base: "",
			ext: "",
			name: ""
		};
		if (p.length === 0) return ret;
		var len = p.length, re = 0, code = p.charCodeAt(0);
		if (len === 1) {
			if (isWS(code)) {
				ret.root = ret.dir = p;
				return ret;
			}
			ret.base = ret.name = p;
			return ret;
		}
		if (isWS(code)) {
			re = 1;
			if (isWS(p.charCodeAt(1))) {
				var j = 2, last = j;
				while (j < len && !isWS(p.charCodeAt(j))) j++;
				if (j < len && j !== last) {
					last = j;
					while (j < len && isWS(p.charCodeAt(j))) j++;
					if (j < len && j !== last) {
						last = j;
						while (j < len && !isWS(p.charCodeAt(j))) j++;
						re = j < len ? j + 1 : j;
					}
				}
			}
		} else if (isDR(code) && p.charCodeAt(1) === COLON) {
			if (len <= 2) {
				ret.root = ret.dir = p;
				return ret;
			}
			re = 2;
			if (isWS(p.charCodeAt(2))) {
				if (len === 3) {
					ret.root = ret.dir = p;
					return ret;
				}
				re = 3;
			}
		}
		if (re > 0) ret.root = p.slice(0, re);
		var sd = -1, sp = re, end = -1, ms = true, pds = 0;
		for (var i = len - 1; i >= re; --i) {
			code = p.charCodeAt(i);
			if (isWS(code)) {
				if (!ms) {
					sp = i + 1;
					break;
				}
				continue;
			}
			if (end === -1) {
				ms = false;
				end = i + 1;
			}
			if (code === DOT) {
				if (sd === -1) sd = i;
				else if (pds !== 1) pds = 1;
			} else if (sd !== -1) pds = -1;
		}
		if (end !== -1) if (sd === -1 || pds === 0 || pds === 1 && sd === end - 1 && sd === sp + 1) ret.base = ret.name = p.slice(sp, end);
		else {
			ret.name = p.slice(sp, sd);
			ret.base = p.slice(sp, end);
			ret.ext = p.slice(sd, end);
		}
		if (sp > 0 && sp !== re) ret.dir = p.slice(0, sp - 1);
		else ret.dir = ret.root;
		return ret;
	},
	format: function format(obj) {
		if (obj === null || typeof obj !== "object") throw _invalidArgType("pathObject", "object", obj);
		var dir = obj.dir || obj.root;
		var base = obj.base || (obj.name || "") + (obj.ext ? (obj.ext.charCodeAt(0) === DOT ? "" : ".") + obj.ext : "");
		if (!dir) return base;
		return dir === obj.root ? dir + base : dir + "\\" + base;
	},
	toNamespacedPath: function toNamespacedPath(p) {
		if (typeof p !== "string" || p.length === 0) return p;
		var rp = win32.resolve(p);
		if (rp.length <= 2) return p;
		if (rp.charCodeAt(0) === BSLASH) {
			if (rp.charCodeAt(1) === BSLASH) {
				var c = rp.charCodeAt(2);
				if (c !== 63 && c !== DOT) return "\\\\?\\UNC\\" + rp.slice(2);
			}
		} else if (isDR(rp.charCodeAt(0)) && rp.charCodeAt(1) === COLON && rp.charCodeAt(2) === BSLASH) return "\\\\?\\" + rp;
		return p;
	}
};
win32._makeLong = win32.toNamespacedPath;
posix.posix = posix;
posix.win32 = win32;
win32.posix = posix;
win32.win32 = win32;
module.exports = posix;
//#endregion
