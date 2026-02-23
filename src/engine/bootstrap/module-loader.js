(function() {
  if (globalThis.__exactRequire) {
    return;
  }
  var g = globalThis;
  const cache = Object.create(null);
  var mainModule = null;
  function normalizeSpecifier(specifier) {
    if (typeof specifier !== 'string') {
      return String(specifier || '');
    }
    var out = specifier.replace(/\\/g, '/');
    if (out.indexOf('node:') === 0) {
      out = out.slice(5);
    }
    if (out.slice(-3) === '.js') {
      out = out.slice(0, -3);
    }
    return out;
  }
  function formatTime(ms) {
    var t = typeof ms === 'number' ? ms : Number(ms);
    if (!isFinite(t) || t < 0) {
      return String(t) + 'ms';
    }
    if (t < 1000) {
      return t.toFixed(3).replace(/\.?0+$/, '') + 'ms';
    }
    if (t < 60000) {
      return (t / 1000).toFixed(3) + 's';
    }
    var totalSeconds = Math.floor(t / 1000);
    var hours = Math.floor(totalSeconds / 3600);
    var remainingSeconds = totalSeconds % 3600;
    var minutes = Math.floor(remainingSeconds / 60);
    var seconds = remainingSeconds % 60;
    var millis = Math.floor(t % 1000);
    var secondPart = String(seconds).padStart(2, '0') + '.' + String(millis).padStart(3, '0');
    if (hours > 0) {
      return hours + ':' + String(minutes).padStart(2, '0') + ':' + secondPart;
    }
    return minutes + ':' + secondPart;
  }
  var internalModules = {
    'internal/util/debuglog': {
      formatTime: formatTime,
      debuglog: function() { return function() {}; }
    },
    'internal/crypto/util': {
      getOpenSSLSecLevel: function() { return 0; }
    },
    'internal/crypto/x509': {
      isX509Certificate: function(value) {
        return !!(value && value.constructor && value.constructor.name === 'X509Certificate');
      }
    },
    'internal/test/binding': {
      internalBinding: function(name) {
        if (name === 'crypto') {
          return {
            testFipsCrypto: function() {
              return 0;
            }
          };
        }
        if (name === 'test' && this && this.test) {
          return this.test;
        }
        return {};
      }
    }
  };
  function loadInternal(specifier) {
    var normalized = normalizeSpecifier(specifier);
    if (normalized.indexOf('internal/util/debuglog') !== -1) {
      normalized = 'internal/util/debuglog';
    }
    var internal = internalModules[normalized];
    if (!internal) return null;
    if (!cache[normalized]) {
      cache[normalized] = {
        exports: internal,
        loaded: true,
        id: normalized,
        filename: normalized,
        path: '',
        __exactId: idToModuleId(normalized),
        parent: null,
        children: []
      };
    }
    return cache[normalized].exports;
  }
  function isSameModule(a, b) {
    if (!a || !b) return false;
    return a === b;
  }
  function addChild(parent, child) {
    if (!parent || !child) {
      return;
    }
    if (!parent.children) {
      parent.children = [];
    }
    for (var i = 0; i < parent.children.length; i++) {
      if (isSameModule(parent.children[i], child)) {
        return;
      }
    }
    parent.children.push(child);
  }
  function dirname(path) {
    if (!path) {
      return "";
    }
    const normalized = path.replace(/\\/g, "/");
    const idx = normalized.lastIndexOf("/");
    if (idx <= 0) {
      return "";
    }
    return normalized.slice(0, idx);
  }
  function resolveModulePath(basePath, relativePath) {
    if (!relativePath) {
      return "";
    }
    if (/^([A-Za-z]:\\|[A-Za-z]:\/|\/|\\\\|\\)/.test(relativePath)) {
      return relativePath.replace(/\\/g, "/");
    }
    if (relativePath.indexOf("./") === 0 || relativePath.indexOf("../") === 0) {
      const normalizedBase = dirname(basePath).replace(/\\/g, "/");
      const normalizedRelative = relativePath.replace(/\\/g, "/");
      const stack = normalizedBase ? normalizedBase.split("/") : [];
      const segments = normalizedRelative.split("/");
      for (var i = 0; i < segments.length; i++) {
        var part = segments[i];
        if (!part || part === ".") {
          continue;
        }
        if (part === "..") {
          if (stack.length) {
            stack.pop();
          }
          continue;
        }
        stack.push(part);
      }
      return stack.join("/");
    }
    return relativePath.replace(/\\/g, "/");
  }
  function applyRolldownCjsDirnameBindings(source, bundlePath) {
    return source;
  }
  function fixEsmCjsInterop(source) {
    // Patch rolldown's __toCommonJS to return .default with named exports
    // merged, so require('esm-pkg') returns the default export directly.
    if (!source || source.indexOf("__toCommonJS") === -1) return source;
    var marker = "var __toCommonJS = (mod) =>";
    var idx = source.indexOf(marker);
    if (idx === -1) return source;
    var end = source.indexOf(";", idx);
    if (end === -1) return source;
    var replacement = marker + " {\n" +
      "  if (__hasOwnProp.call(mod, 'module.exports')) return mod['module.exports'];\n" +
      "  var __ns = __copyProps(__defProp({}, '__esModule', { value: true }), mod);\n" +
      "  if (__ns.default !== undefined) {\n" +
      "    var __def = __ns.default;\n" +
      "    if (__def && (typeof __def === 'function' || typeof __def === 'object')) {\n" +
      "      var __ks = Object.keys(__ns);\n" +
      "      for (var __ki = 0; __ki < __ks.length; __ki++) {\n" +
      "        if (__ks[__ki] !== 'default' && __ks[__ki] !== '__esModule' && !(__ks[__ki] in __def)) {\n" +
      "          try { __def[__ks[__ki]] = __ns[__ks[__ki]]; } catch(e) {}\n" +
      "        }\n" +
      "      }\n" +
      "    }\n" +
      "    return __def;\n" +
      "  }\n" +
      "  return __ns;\n" +
      "}";
    return source.slice(0, idx) + replacement + source.slice(end + 1);
  }
  function __exactPinProcessStreams() {
    if (typeof process !== 'object' || process === null) {
      return;
    }
    if (process.__exactStreamPinned) {
      return;
    }
    function createWritableProxy(stream) {
      if (!stream) return stream;
      var writeFn = stream.write;
      var proxy = Object.create(stream);
      Object.defineProperty(proxy, "write", {
        configurable: true,
        enumerable: true,
        get: function() { return writeFn; },
        set: function(value) {
          writeFn = value;
        },
      });
      return proxy;
    }
    try {
      if (typeof process.stdout !== 'object' || process.stdout === null) {
        return;
      }
      var stdout = process.stdout;
      var stderr = process.stderr;
      if (stdout && stdout.writable === undefined) {
        stdout = createWritableProxy(stdout);
        if (stdout.writable === undefined) {
          stdout.writable = true;
        }
      }
      Object.defineProperty(process, 'stdout', {
        value: stdout,
        writable: true,
        configurable: true,
        enumerable: true,
      });
      if (stderr) {
        if (stderr.writable === undefined) {
          stderr = createWritableProxy(stderr);
          if (stderr.writable === undefined) {
            stderr.writable = true;
          }
        }
        Object.defineProperty(process, 'stderr', {
          value: stderr,
          writable: true,
          configurable: true,
          enumerable: true,
        });
      }
      if (process.stdin) {
        Object.defineProperty(process, 'stdin', {
          value: process.stdin,
          writable: true,
          configurable: true,
          enumerable: true,
        });
      }
      process.__exactStreamPinned = true;
    } catch (_) {
      // Keep module loading resilient if process stream patching is not possible.
    }
  }
  function fixForOfScoping(source) {
    if (!source || !/\bfor\s*\(\s*(?:const|let)\b[^)]*\bof\b/.test(source)) {
      return source;
    }
    var lines = source.split("\n");
    var out = [];
    var i = 0;
    while (i < lines.length) {
      var line = lines[i];
      // Match: for (const/let BINDING of EXPR) {
      // Use precise parsing instead of regex to handle nested parens correctly
      var trimmed = line.replace(/^\s*/, "");
      var indent = line.slice(0, line.length - trimmed.length);
      if (!/^for\s*\(/.test(trimmed)) {
        out.push(line);
        i++;
        continue;
      }
      // Find the balanced closing paren for the for(...)
      var forStart = trimmed.indexOf("(");
      if (forStart === -1) { out.push(line); i++; continue; }
      var parenDepth = 0;
      var forEnd = -1;
      var inStr2 = false;
      var strCh2 = 0;
      for (var fi = forStart; fi < trimmed.length; fi++) {
        var fc = trimmed.charCodeAt(fi);
        if (inStr2) {
          if (fc === strCh2 && (fi === 0 || trimmed.charCodeAt(fi-1) !== 92)) inStr2 = false;
        } else {
          if (fc === 34 || fc === 39 || fc === 96) { inStr2 = true; strCh2 = fc; }
          else if (fc === 40) parenDepth++;
          else if (fc === 41) { parenDepth--; if (parenDepth === 0) { forEnd = fi; break; } }
        }
      }
      if (forEnd === -1) { out.push(line); i++; continue; }
      var inner = trimmed.slice(forStart + 1, forEnd).replace(/^\s+|\s+$/g, "");
      // Check if it's const/let ... of ...
      var ofMatch = inner.match(/^(?:const|let)\s+(\S+)\s+of\s+([\s\S]+)$/);
      if (!ofMatch) { out.push(line); i++; continue; }
      var binding = ofMatch[1];
      var expr = ofMatch[2];
      // Rest of line after for(...) must be just "{"
      var afterFor = trimmed.slice(forEnd + 1).replace(/^\s+|\s+$/g, "");
      if (afterFor !== "{") { out.push(line); i++; continue; }
      // Now find the matching closing brace
      var depth = 1;
      var bodyLines = [];
      var j = i + 1;
      var hasBreakContinue = false;
      while (j < lines.length && depth > 0) {
        var bl = lines[j];
        var inStr = false;
        var strCh = 0;
        for (var k = 0; k < bl.length; k++) {
          var ch = bl.charCodeAt(k);
          if (inStr) {
            if (ch === strCh && (k === 0 || bl.charCodeAt(k - 1) !== 92)) inStr = false;
          } else {
            if (ch === 34 || ch === 39 || ch === 96) { inStr = true; strCh = ch; }
            else if (ch === 123) depth++;
            else if (ch === 125) depth--;
          }
          if (depth <= 0) break;
        }
        if (depth > 0) {
          bodyLines.push(bl);
          if (/\b(break|continue)\s*[;\n}]/.test(bl) || /\byield\b/.test(bl) || /\bawait\b/.test(bl) || /\breturn\b/.test(bl)) hasBreakContinue = true;
        }
        j++;
      }
      if (hasBreakContinue || depth !== 0) {
        out.push(line);
        i++;
        continue;
      }
      out.push(indent + "Array.from(" + expr + ").forEach(function(" + binding + ") {");
      for (var b = 0; b < bodyLines.length; b++) {
        out.push(bodyLines[b]);
      }
      out.push(indent + "});");
      i = j;
    }
    return out.join("\n");
  }
  function aliasNodePathGlobals(source) {
    if (!source || (source.indexOf("__dirname") === -1 && source.indexOf("__filename") === -1)) {
      return source;
    }
    return source.replace(/\b__dirname\b/g, "globalThis.__dirname").replace(/\b__filename\b/g, "globalThis.__filename");
  }
  function transformImportMeta(source) {
    if (!source || source.indexOf("import.meta") === -1) {
      return source;
    }
    return source
      .replace(/import\.meta\.url/g, "__filename")
      .replace(/import\.meta\.path/g, "__filename")
      .replace(/import\.meta\.filename/g, "__filename")
      .replace(/import\.meta\.file(?!name)/g, "(typeof __filename !== 'undefined' ? __filename.split('/').pop() : '')")
      .replace(/import\.meta\.dir/g, "__dirname")
      .replace(/import\.meta\.main/g, "(typeof __filename !== 'undefined' && __filename === (globalThis.process && globalThis.process.argv && globalThis.process.argv[1]))")
      .replace(/import\.meta\.require/g, "require");
  }
  function transformDynamicImport(source) {
    if (!source || source.indexOf("import(") === -1) {
      return source;
    }
    // Replace dynamic import() calls with globalThis["import"]() polyfill.
    // Be careful not to match:
    //   - Static import declarations (import ... from, import "...")
    //   - import.meta (already handled by transformImportMeta)
    // The pattern matches: word-boundary "import" followed by "(" but not ".meta"
    return source.replace(/\bimport\s*\(/g, 'globalThis["import"](');
  }
  function transformEsmToCjs(source) {
    if (!source) {
      return "";
    }
    var lines = String(source).split("\n");
    var out = [];
    var importCounter = 0;
    var isIdent = /^[A-Za-z_$][\w$]*$/;
    var isExportName = function(value) {
      return value === "default" || isIdent.test(value);
    };
    var quote = function(value) {
      return JSON.stringify(value);
    };
    var emitNamedBindings = function(spec, modName) {
      var parts = spec ? spec.split(",") : [];
      for (var i = 0; i < parts.length; i++) {
        var item = parts[i].trim();
        if (!item) {
          continue;
        }
        var asMatch = item.match(/^(.+?)\s+as\s+(.+)$/);
        if (asMatch) {
          var sourceName = asMatch[1].trim();
          var localName = asMatch[2].trim();
          if (!isExportName(sourceName) || !isIdent.test(localName) || localName === "default") {
            continue;
          }
          if (sourceName === "default") {
            out.push("var " + localName + " = " + modName + " && " + modName + ".default;");
          } else {
            out.push("var " + localName + " = " + modName + "." + sourceName + ";");
          }
        } else if (isIdent.test(item)) {
          out.push("var " + item + " = " + modName + "." + item + ";");
        }
      }
    };
    var emitExportBindings = function(spec, sourceExpr, allowBareDefault, useLocals) {
      var entries = spec ? spec.split(",") : [];
      for (var i = 0; i < entries.length; i++) {
        var item = entries[i].trim();
        if (!item) {
          continue;
        }
        var asMatch = item.match(/^(.+?)\s+as\s+(.+)$/);
        if (asMatch) {
          var sourceName = asMatch[1].trim();
          var exportName = asMatch[2].trim();
          if (!isExportName(sourceName) || !isExportName(exportName)) {
            continue;
          }
          if (useLocals) {
            out.push("module.exports." + exportName + " = " + sourceName + ";");
          } else {
            out.push("module.exports." + exportName + " = " + sourceExpr + "." + sourceName + ";");
          }
          continue;
        }
        if (!allowBareDefault && item === "default") {
          continue;
        }
        if (isExportName(item)) {
          if (useLocals) {
            out.push("module.exports." + item + " = " + item + ";");
          } else {
            out.push("module.exports." + item + " = " + sourceExpr + "." + item + ";");
          }
        }
      }
    };
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var trimmed = line.trim();
      var statement = line;
      if (/^\s*(import|export)\b/.test(trimmed) && trimmed.indexOf(";") === -1) {
        for (var j = i + 1; j < lines.length; j++) {
          statement = statement + "\n" + lines[j];
          if (statement.indexOf(";") !== -1) {
            i = j;
            break;
          }
        }
      }
      if (line.indexOf("import.meta") !== -1) {
        statement = transformImportMeta(statement);
      }
      var transformed = statement;
      trimmed = transformed.trim();
      var m;

      if (!trimmed) {
        out.push("");
        continue;
      }

      m = trimmed.match(/^\s*import\s+(["'])([^'"]+)\1\s*;?\s*$/);
      if (m) {
        out.push("require(" + quote(m[2]) + ");");
        continue;
      }

      m = trimmed.match(/^\s*import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        out.push("var " + m[1] + " = require(" + quote(m[3]) + ");");
        continue;
      }

      m = trimmed.match(
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\{([\s\S]*?)\}\s+from\s+(["'])([^'"]+)\3\s*;?\s*$/
      );
      if (m) {
        var namedImport = "__exmod" + (importCounter++);
        out.push("var " + namedImport + " = require(" + quote(m[4]) + ");");
        out.push(
          "var " +
            m[1] +
            " = " +
            namedImport +
            " && " +
            namedImport +
            ".__esModule ? " +
            namedImport +
            ".default : " +
            namedImport +
            ";"
        );
        emitNamedBindings(m[2], namedImport);
        continue;
      }

      m = trimmed.match(
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\3\s*;?\s*$/
      );
      if (m) {
        var nsImport = "__exmod" + (importCounter++);
        out.push("var " + nsImport + " = require(" + quote(m[4]) + ");");
        out.push(
          "var " +
            m[1] +
            " = " +
            nsImport +
            " && " +
            nsImport +
            ".__esModule ? " +
            nsImport +
            ".default : " +
            nsImport +
            ";"
        );
        out.push("var " + m[2] + " = " + nsImport + ";");
        continue;
      }

      m = trimmed.match(/^\s*import\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        out.push(
          "var " +
            m[1] +
            " = require(" +
            quote(m[3]) +
            ").default || require(" +
            quote(m[3]) +
            ");"
        );
        continue;
      }

      m = trimmed.match(/^\s*import\s+\{([\s\S]*?)\}\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        var named = "__exmod" + (importCounter++);
        out.push("var " + named + " = require(" + quote(m[3]) + ");");
        emitNamedBindings(m[1], named);
        continue;
      }

      m = trimmed.match(/^\s*export\s+\*\s+from\s+(["'])([^'"]+)\1\s*;?\s*$/);
      if (m) {
        var exportFrom = "__exmod" + (importCounter++);
        out.push("var " + exportFrom + " = require(" + quote(m[2]) + ");");
        out.push("for (var __exk in " + exportFrom + ") {");
        out.push("  if (Object.prototype.hasOwnProperty.call(" + exportFrom + ", __exk)) {");
        out.push("    module.exports[__exk] = " + exportFrom + "[__exk];");
        out.push("  }");
        out.push("}");
        continue;
      }

      m = trimmed.match(/^\s*export\s+\{([\s\S]*?)\}\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        var exportFrom = "__exmod" + (importCounter++);
        out.push("var " + exportFrom + " = require(" + quote(m[3]) + ");");
        emitExportBindings(m[1], exportFrom, true, false);
        continue;
      }

      m = trimmed.match(
        /^\s*export\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/
      );
      if (m) {
        var nsExport = "__exmod" + (importCounter++);
        out.push("var " + nsExport + " = require(" + quote(m[3]) + ");");
        out.push("module.exports." + m[1] + " = " + nsExport + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+(function|class)\s+([A-Za-z_$][\w$]*)/);
      if (m) {
        out.push(transformed.replace(/\bexport\s+/, ""));
        out.push("module.exports." + m[2] + " = " + m[2] + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+default\s+(.+)\s*$/);
      if (m) {
        out.push("module.exports.default = " + m[1] + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+(const|let|var)\s+([A-Za-z_$][\w$]*)/);
      if (m) {
        out.push(transformed.replace(/\bexport\s+/, ""));
        out.push("module.exports." + m[2] + " = " + m[2] + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+\{([^}]*)\}\s*;?\s*$/);
      if (m) {
        emitExportBindings(m[1], null, false, true);
        continue;
      }

      out.push(transformed);
    }
    return out.join("\n");
  }
  function load(specifier, referrer, parent) {
    __exactPinProcessStreams();

    // Lazy-load triggers: ensure non-essential bootstrap blocks are loaded
    // when their corresponding modules are first required.
    if (typeof __exactEnsureStreamEnhance === 'function') {
      if (specifier === 'stream' || specifier === 'stream/web' ||
          specifier === 'node:stream' || specifier === 'node:stream/web') {
        __exactEnsureStreamEnhance();
      }
    }
    if (typeof __exactEnsureWebCrypto === 'function') {
      if (specifier === 'crypto' || specifier === 'node:crypto') {
        __exactEnsureWebCrypto();
      }
    }
    if (typeof __exactEnsureDns === 'function') {
      if (specifier === 'dns' || specifier === 'node:dns' ||
          specifier === 'dns/promises' || specifier === 'node:dns/promises') {
        __exactEnsureDns();
      }
    }
    if (typeof __exactEnsureFs === 'function') {
      if (specifier === 'fs' || specifier === 'node:fs' ||
          specifier === 'fs/promises' || specifier === 'node:fs/promises' ||
          specifier === 'path' || specifier === 'node:path' ||
          specifier === 'path/posix' || specifier === 'node:path/posix' ||
          specifier === 'path/win32' || specifier === 'node:path/win32') {
        __exactEnsureFs();
      }
    }
    if (typeof __exactEnsureChildProcess === 'function') {
      if (specifier === 'child_process' || specifier === 'node:child_process') {
        __exactEnsureChildProcess();
      }
    }
    if (typeof __exactEnsureNet === 'function') {
      if (specifier === 'net' || specifier === 'node:net' ||
          specifier === 'tls' || specifier === 'node:tls' ||
          specifier === 'dgram' || specifier === 'node:dgram') {
        __exactEnsureNet();
      }
    }
    if (typeof __exactEnsureSqlite === 'function') {
      if (specifier === 'bun:sqlite' || specifier === 'better-sqlite3') {
        __exactEnsureSqlite();
      }
    }
    if (typeof __exactEnsureHttp === 'function') {
      if (specifier === 'http' || specifier === 'node:http' ||
          specifier === 'https' || specifier === 'node:https' ||
          specifier === 'http2' || specifier === 'node:http2') {
        __exactEnsureHttp();
      }
    }
    var normalized = normalizeSpecifier(specifier);
    if (internalModules[normalized]) {
      if (!cache[normalized]) {
        cache[normalized] = { exports: internalModules[normalized], loaded: true };
      }
      return cache[normalized].exports;
    }
    const json = __exactModuleResolve(specifier, referrer || "");
    if (!json) {
      throw new Error("Module not found: " + specifier);
    }
    let record;
    try {
      record = JSON.parse(json);
    } catch (err) {
      throw new Error("Module resolve failed: " + err.message);
    }
    if (record.error) {
      throw new Error(record.error);
    }
    const id = record.id || specifier;
    var moduleId = idToModuleId(id);
    if (cache[id]) {
      return cache[id].exports;
    }
    const kind = record.kind || "cjs";
    const source = record.source || "";
    var filename = record.path || id;
    // For the entry module, use the original source path so that
    // __dirname/__filename and require.resolve work relative to
    // the source dir, not the bundle cache dir.
    if (g.__exactEntryFile && !g.__exactEntryFileConsumed && filename.indexOf('/Caches/') !== -1) {
      filename = g.__exactEntryFile;
      g.__exactEntryFileConsumed = true;
    }
    const modulePath = filename.indexOf('/') === -1 ? filename : dirname(filename);
    // Compute node_modules search paths for this module
    var modulePaths = [];
    var pathParts = modulePath.split('/');
    for (var pi = pathParts.length - 1; pi >= 0; pi--) {
      if (pathParts[pi] === 'node_modules') continue;
      modulePaths.push(pathParts.slice(0, pi + 1).join('/') + '/node_modules');
    }
    const module = {
      id: id,
      __exactId: moduleId,
      filename: filename,
      path: modulePath,
      exports: {},
      loaded: false,
      parent: parent || null,
      children: [],
      paths: modulePaths,
    };
    cache[id] = module;
    if (!parent && !mainModule) {
      mainModule = module;
    }
    addChild(parent, module);

    module.require = function(next, options) {
      grantCapabilities(next, options, module.__exactId);
      return localRequire(next);
    };

    if (kind === "json") {
      try {
        module.exports = JSON.parse(source || "null");
      } catch (err) {
        delete cache[id];
        throw err;
      }
      module.loaded = true;
      return module.exports;
    }
    const dir = dirname(filename);
    const looksLikeModuleSyntax = function(text) {
      return /\n?\s*(?:import|export)\b/m.test(text || "");
    };
    var localRequire = function(next) {
      var internal = loadInternal(next);
      if (internal) return internal;
      var exports = load(next, filename, module);
      // Skip interop for ESM-shimmed modules — the shim's generated
      // import bindings already handle default/named/namespace access.
      if (exports && exports.__esmShimmed) {
        return exports;
      }
      // ESM/CJS interop: when a bundled ESM module is loaded via require(),
      // rolldown wraps it with __esModule:true. Return .default so that
      // require('pkg') returns the default export directly, with named
      // exports merged onto it so destructuring still works.
      if (exports && exports.__esModule && exports.default !== undefined) {
        var def = exports.default;
        if (def && (typeof def === "function" || typeof def === "object")) {
          var keys = Object.keys(exports);
          for (var ki = 0; ki < keys.length; ki++) {
            var k = keys[ki];
            if (k !== "default" && k !== "__esModule" && !(k in def)) {
              try { def[k] = exports[k]; } catch (e) {}
            }
          }
        }
        return def;
      }
      return exports;
    };
    localRequire.resolve = function(specifier) {
      var json = __exactModuleResolve(specifier, filename || "");
      if (!json) {
        throw new Error("Cannot find module '" + specifier + "'");
      }
      var rec = JSON.parse(json);
      if (rec.error) {
        throw new Error("Cannot find module '" + specifier + "'");
      }
      return rec.path || rec.id || specifier;
    };
    localRequire.resolve.paths = function(specifier) {
      return null;
    };
    localRequire.cache = cache;
    localRequire.main = mainModule;
    const restoreModuleId = function(previousId) {
      if (typeof g.__exactSetActiveModuleId === "function") {
        g.__exactSetActiveModuleId(previousId || 0);
      }
    };
    const previousModuleId = typeof g.__exactSetActiveModuleId === "function"
      ? g.__exactSetActiveModuleId(module.__exactId)
      : 0;
    const previousNodeFilename = g.__filename;
    const previousNodeDirname = g.__dirname;
    try {
      const directSource =
        transformDynamicImport(transformImportMeta(applyRolldownCjsDirnameBindings(fixForOfScoping(fixEsmCjsInterop(source || "")), filename))) +
        "\n//# sourceURL=" + filename;
      g.__exactDebugModuleSources = (g.__exactDebugModuleSources || []);
      if (Array.isArray(g.__exactDebugModuleSources)) {
        g.__exactDebugModuleSources.push({ id: id, filename: filename, source: directSource.slice(0, 2000) });
      }
      g.__exactDebugModuleSource = directSource;
      try {
        g.__filename = filename;
        g.__dirname = dir;
        const directFn = new Function(
          "require",
          "module",
          "exports",
          "__filename",
          "__dirname",
          directSource
        );
        directFn(localRequire, module, module.exports, filename, dir);
      } catch (err) {
        const shouldFallback = (kind === "esm" || looksLikeModuleSyntax(directSource));
        const canFallback = shouldFallback &&
          err &&
          err.name === "SyntaxError" &&
          directSource.length > 0;
        if (!canFallback) {
          throw err;
        }
        const runtimeSource =
          transformDynamicImport(applyRolldownCjsDirnameBindings(fixForOfScoping(transformEsmToCjs(directSource)), filename)) +
            "\n//# sourceURL=" + filename;
        if (Array.isArray(g.__exactDebugModuleSources)) {
          g.__exactDebugModuleSources.push({ id: id, filename: filename, source: runtimeSource.slice(0, 2000), fallback: true });
        }
        g.__exactDebugModuleSource = runtimeSource;
        const fallbackFn = new Function(
          "require",
          "module",
          "exports",
          "__filename",
          "__dirname",
          runtimeSource
        );
        g.__filename = filename;
        g.__dirname = dir;
        fallbackFn(localRequire, module, module.exports, filename, dir);
        if (module.exports && typeof module.exports === "object") {
          module.exports.__esModule = true;
          Object.defineProperty(module.exports, '__esmShimmed', { value: true });
        }
      }
    } catch (err) {
      delete cache[id];
      throw err;
    } finally {
      if (typeof previousNodeFilename === "undefined") {
        delete g.__filename;
      } else {
        g.__filename = previousNodeFilename;
      }
      if (typeof previousNodeDirname === "undefined") {
        delete g.__dirname;
      } else {
        g.__dirname = previousNodeDirname;
      }
      restoreModuleId(previousModuleId);
    }
    module.loaded = true;
    return module.exports;
  }
  // Convert a module specifier or id to a numeric module identifier used
  // by runtime capability checks.
  var idToModuleId = function(specifier) {
    var id = typeof specifier === "string" ? specifier : String(specifier || "");
    var moduleId = 0;
    for (var i = 0; i < id.length; i++) {
      moduleId = ((moduleId << 5) - moduleId) + id.charCodeAt(i);
      moduleId = moduleId & moduleId;
    }
    return moduleId < 0 ? -moduleId : moduleId;
  };

  // Helper to grant capabilities from options parameter
  var grantCapabilities = function(specifier, options, moduleId) {
    if (!options || typeof options !== 'object') return;
    var needs = options.needs;
    if (!needs) return;

    var numericModuleId = typeof moduleId === 'number' && isFinite(moduleId) ? moduleId : idToModuleId(specifier);
    if (numericModuleId < 0) {
      numericModuleId = -numericModuleId;
    }

    // Grant capabilities using Exact.setModuleCapabilities
    if (typeof globalThis.Exact === 'object' &&
        typeof globalThis.Exact.setModuleCapabilities === 'function') {
      var caps = Array.isArray(needs) ? needs : [needs];
      globalThis.Exact.setModuleCapabilities(numericModuleId, caps);
    }
  };

  globalThis.require = function(specifier, options) {
    // Grant capabilities if provided
    grantCapabilities(specifier, options, 0);
    var internal = loadInternal(specifier);
    if (internal) return internal;
    return load(specifier, "");
  };
  globalThis.require.cache = cache;
  globalThis.require.resolve = function(specifier) {
    var json = __exactModuleResolve(specifier, "");
    if (!json) {
      throw new Error("Cannot find module '" + specifier + "'");
    }
    var record = JSON.parse(json);
    if (record.error) {
      throw new Error("Cannot find module '" + specifier + "'");
    }
    return record.path || record.id || specifier;
  };
  globalThis.require.resolve.paths = function(specifier) {
    return null;
  };
  Object.defineProperty(globalThis.require, 'main', {
    get: function() { return mainModule; },
    configurable: true,
    enumerable: true
  });
  globalThis.__exactRequire = load;

  // Polyfill dynamic import() using require()
  // import() returns a Promise that resolves to the module
  // ESM default export becomes { default: ... }, named exports are direct properties
  var importImpl = function(specifier, options) {
    return Promise.resolve().then(function() {
      // Grant capabilities if provided
      grantCapabilities(specifier, options);

      var module = load(specifier, "");
      // Wrap CommonJS modules to look like ESM: { default: module, ...module }
      // This allows: const mod = await import('foo'); mod.default or mod.something
      if (module && !module.__esModule) {
        var moduleType = typeof module;
        // Wrap objects and functions
        if (moduleType === 'object' || moduleType === 'function') {
          var wrapped = { default: module };
          // For objects, copy properties to wrapped
          if (moduleType === 'object') {
            for (var key in module) {
              if (module.hasOwnProperty(key)) {
                wrapped[key] = module[key];
              }
            }
          }
          return wrapped;
        }
      }
      return module;
    });
  };

  // Set as globalThis.import (use globalThis.import('foo') or globalThis['import']('foo'))
  if (typeof globalThis.import === 'undefined') {
    Object.defineProperty(globalThis, 'import', {
      value: importImpl,
      writable: false,
      enumerable: false,
      configurable: true
    });
  }

  // Also provide as importModule() for convenience (since import(...) triggers parser)
  globalThis.importModule = importImpl;
})();
