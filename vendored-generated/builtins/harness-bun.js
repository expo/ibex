"use strict";

const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const processMod = require("node:process");
const util = require("node:util");
const zlib = require("node:zlib");

function detectCompatRuntimeVersion() {
  if (processMod.versions) {
    if (typeof processMod.versions.bun === "string" && processMod.versions.bun) {
      return processMod.versions.bun;
    }
    if (typeof processMod.versions.exact === "string" && processMod.versions.exact) {
      return processMod.versions.exact;
    }
  }

  const runtimePath = processMod.argv0 || processMod.execPath;
  if (typeof runtimePath === "string" && runtimePath) {
    try {
      const result = childProcess.spawnSync(runtimePath, ["--version"], { encoding: "utf8" });
      if (typeof result.stdout === "string") {
        const trimmed = result.stdout.trim();
        if (trimmed) {
          return trimmed;
        }
      }
    } catch (_err) {}
  }

  return "0.0.0";
}

const compatRuntimeVersion = detectCompatRuntimeVersion();

function concatArrayBuffers(buffers) {
  if (!Array.isArray(buffers)) {
    throw new TypeError("First argument must be an array of ArrayBuffer-like values");
  }
  if (buffers.length === 0) {
    return new Uint8Array(0).buffer;
  }

  var views = new Array(buffers.length);
  var totalLength = 0;
  var i;
  var buffer;

  for (i = 0; i < buffers.length; i++) {
    var value = buffers[i];
    if (value instanceof ArrayBuffer) {
      views[i] = new Uint8Array(value);
    } else if (value && typeof value === "object" && ArrayBuffer.isView(value)) {
      views[i] = new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength || value.length);
    } else if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(value)) {
      views[i] = new Uint8Array(value.buffer || value, value.byteOffset || 0, value.byteLength || value.length);
    } else {
      throw new TypeError("Bun.concatArrayBuffers expects an array of ArrayBuffers or typed arrays");
    }
    totalLength += views[i].length;
    if (totalLength > 0x7fffffff) {
      throw new Error("Failed to allocate ArrayBuffer");
    }
  }

  try {
    buffer = new Uint8Array(totalLength);
  } catch (e) {
    throw new Error("Failed to allocate ArrayBuffer");
  }

  var offset = 0;
  for (i = 0; i < views.length; i++) {
    buffer.set(views[i], offset);
    offset += views[i].length;
  }

  return buffer.buffer;
}

function toCompressionBuffer(value) {
  if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return Buffer.from(new Uint8Array(value));
  }
  if (value && typeof value === "object" && ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset || 0, value.byteLength || value.length || 0);
  }
  if (typeof value === "string") {
    return Buffer.from(value);
  }
  return Buffer.from(String(value == null ? "" : value));
}

function normalizeCompressionOptions(options) {
  if (!options || typeof options !== "object") {
    return undefined;
  }

  var normalized = {};
  var keys = Object.keys(options);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i] === "library") {
      continue;
    }
    normalized[keys[i]] = options[keys[i]];
  }
  return normalized;
}

function runCompressionSync(method, input, options) {
  var fn = zlib && zlib[method];
  if (typeof fn !== "function") {
    throw new TypeError(method + " is not available");
  }
  return Buffer.from(fn.call(zlib, toCompressionBuffer(input), normalizeCompressionOptions(options)));
}

function normalizeReadableStreamChunk(chunk) {
  if (typeof chunk === "string") {
    return new TextEncoder().encode(chunk);
  }
  if (chunk instanceof Uint8Array) {
    return chunk;
  }
  if (chunk instanceof ArrayBuffer) {
    return new Uint8Array(chunk.slice(0));
  }
  if (chunk && typeof chunk === "object" && ArrayBuffer.isView(chunk)) {
    return new Uint8Array(chunk.buffer, chunk.byteOffset || 0, chunk.byteLength || chunk.length || 0);
  }
  throw new TypeError("ReadableStream chunk must be a string, Buffer, or ArrayBufferView");
}

function cloneUint8Array(bytes) {
  var clone = new Uint8Array(bytes.byteLength || bytes.length || 0);
  clone.set(bytes);
  return clone;
}

function toHashBuffer(data) {
  if (typeof data === "string") {
    return data;
  }
  if (data instanceof ArrayBuffer) {
    return Buffer.from(data);
  }
  if (data && typeof data === "object" && ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset || 0, data.byteLength || 0);
  }
  return Buffer.from(data);
}

function decodeBase64ToBytes(value) {
  if (!value) {
    return new Uint8Array(0);
  }

  if (typeof Buffer !== "undefined" && Buffer.from) {
    return new Uint8Array(Buffer.from(String(value), "base64"));
  }

  var binary = atob(String(value));
  var bytes = new Uint8Array(binary.length);
  for (var i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function defineCompatProperty(target, key, value) {
  if (!target || (typeof target !== "object" && typeof target !== "function")) {
    return;
  }
  try {
    Object.defineProperty(target, key, {
      value: value,
      configurable: true,
      enumerable: false,
      writable: true,
    });
  } catch (_err) {}
}

function createMarkedResolvedPromise(value) {
  var promise = Promise.resolve(value);
  defineCompatProperty(promise, "__exactPeekStatus", "fulfilled");
  defineCompatProperty(promise, "__exactPeekValue", value);
  return promise;
}

function trackPromiseState(promise) {
  if (!promise || typeof promise.then !== "function") {
    return promise;
  }

  if (promise.__exactPeekStatus) {
    return promise;
  }

  defineCompatProperty(promise, "__exactPeekStatus", "pending");
  promise.then(
    function(value) {
      promise.__exactPeekStatus = "fulfilled";
      promise.__exactPeekValue = value;
    },
    function(error) {
      promise.__exactPeekStatus = "rejected";
      promise.__exactPeekReason = error;
    },
  );
  return promise;
}

function getBlobBackedStreamBytes(stream) {
  if (!stream || typeof stream !== "object") {
    return null;
  }

  if (stream.__exactBlobBytes && typeof stream.__exactBlobBytes === "object" && ArrayBuffer.isView(stream.__exactBlobBytes)) {
    return new Uint8Array(
      stream.__exactBlobBytes.buffer,
      stream.__exactBlobBytes.byteOffset || 0,
      stream.__exactBlobBytes.byteLength || stream.__exactBlobBytes.length || 0,
    );
  }

  return null;
}

function getBlobBackedStreamType(stream) {
  if (!stream || typeof stream !== "object" || typeof stream.__exactBlobType !== "string") {
    return "";
  }

  return stream.__exactBlobType;
}

function createReadableRequestBody(serverId, requestId) {
  return new ReadableStream({
    pull: function(controller) {
      return new Promise(function(resolve, reject) {
        function poll() {
          if (typeof globalThis.__exactHttpReadBody !== "function") {
            reject(new Error("Request body streaming unavailable"));
            return;
          }

          var resultJson = globalThis.__exactHttpReadBody(serverId, requestId);
          if (!resultJson) {
            resolve();
            return;
          }

          var result;
          try {
            result = JSON.parse(resultJson);
          } catch (error) {
            reject(error);
            return;
          }

          if (result.error) {
            reject(new Error(String(result.error)));
            return;
          }

          if (result.done) {
            controller.close();
            resolve();
            return;
          }

          if (result.chunk) {
            controller.enqueue(decodeBase64ToBytes(result.chunk));
            resolve();
            return;
          }

          setTimeout(poll, 0);
        }

        poll();
      });
    },
  });
}

function installBlobCompatFastPaths() {
  var BlobCtor = globalThis.Blob;
  if (!BlobCtor || !BlobCtor.prototype) {
    return;
  }

  function wrapMethod(name, wrapper) {
    var original = BlobCtor.prototype[name];
    if (typeof original !== "function" || original.__exactCompatWrapped) {
      return;
    }

    var wrapped = function() {
      return wrapper.call(this, original, arguments);
    };
    defineCompatProperty(wrapped, "__exactCompatWrapped", true);
    BlobCtor.prototype[name] = wrapped;
  }

  wrapMethod("stream", function(original, argsLike) {
    var stream = original.apply(this, argsLike);
    if (stream && typeof this._getBytes === "function") {
      defineCompatProperty(stream, "__exactBlobBytes", cloneUint8Array(this._getBytes()));
      defineCompatProperty(stream, "__exactBlobType", typeof this.type === "string" ? this.type : "");
    }
    return stream;
  });

  wrapMethod("arrayBuffer", function(_original, _argsLike) {
    if (typeof this._getBytes === "function") {
      return createMarkedResolvedPromise(cloneUint8Array(this._getBytes()).buffer);
    }
    return trackPromiseState(_original.apply(this, _argsLike));
  });

  wrapMethod("bytes", function(_original, _argsLike) {
    if (typeof this._getBytes === "function") {
      return createMarkedResolvedPromise(cloneUint8Array(this._getBytes()));
    }
    return trackPromiseState(_original.apply(this, _argsLike));
  });

  wrapMethod("text", function(_original, _argsLike) {
    if (typeof this._getBytes === "function") {
      var bytes = this._getBytes();
      var text = typeof TextDecoder !== "undefined"
        ? new TextDecoder().decode(bytes)
        : Buffer.from(bytes).toString("utf8");
      return createMarkedResolvedPromise(text);
    }
    return trackPromiseState(_original.apply(this, _argsLike));
  });
}

function which(command) {
  if (!command) {
    return null;
  }

  if (path.isAbsolute(command)) {
    return fs.existsSync(command) ? command : null;
  }

  const envPath = processMod.env.PATH || "";
  const suffixes = processMod.platform === "win32" ? [".exe", ".cmd", ".bat", ".com", ""] : [""];
  const parts = envPath.split(path.delimiter).filter(Boolean);

  for (const dir of parts) {
    for (const suffix of suffixes) {
      const candidate = path.join(dir, `${command}${suffix}`);
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        return candidate;
      }
    }
  }

  return null;
}

function inspect(value) {
  return util
    .inspect(value, {
      breakLength: 80,
      compact: false,
      depth: null,
      sorted: false,
    })
    .replace(/'/g, "\"");
}

function normalizeSpawnCommand(input) {
  if (typeof input === "string") {
    return { command: input, args: [] };
  }

  if (Array.isArray(input)) {
    const [command, ...args] = input;
    return { command, args };
  }

  if (input && typeof input === "object" && "cmd" in input) {
    const { command, args } = Array.isArray(input.cmd)
      ? { command: input.cmd[0], args: input.cmd.slice(1) }
      : { command: input.cmd, args: input.args || [] };
    return { command, args };
  }

  throw new TypeError("Invalid Bun spawn command.");
}

function normalizeSpawnOptions(input) {
  if (!input || typeof input !== "object") {
    return {};
  }

  var env = input.env;
  if (typeof env === "function") {
    env = env();
  }

  var stdio = input.stdio;
  if (!stdio && (input.stdin !== undefined || input.stdout !== undefined || input.stderr !== undefined)) {
    stdio = [
      input.stdin === undefined ? "pipe" : input.stdin,
      input.stdout === undefined ? "pipe" : input.stdout,
      input.stderr === undefined ? "pipe" : input.stderr,
    ];
  }

  const opts = {
    cwd: input.cwd,
    env: env,
    detached: input.detached || false,
  };

  if (stdio !== undefined) {
    opts.stdio = stdio;
  }

  if (input.shell) {
    opts.shell = true;
  }

  return opts;
}

function normalizeSpawnInput(input, options) {
  if (input && typeof input === "object" && "cmd" in input) {
    return {
      command: normalizeSpawnCommand(input).command,
      args: normalizeSpawnCommand(input).args,
      options: options && typeof options === "object" && Object.keys(options).length > 0
        ? { ...input, ...options }
        : input,
    };
  }

  return {
    command: normalizeSpawnCommand(input).command,
    args: normalizeSpawnCommand(input).args,
    options: options,
  };
}

function defineDisposable(target, syncDispose, asyncDispose) {
  if (!target || typeof target !== "object" || typeof Symbol !== "function") {
    return target;
  }

  if (Symbol.dispose && typeof target[Symbol.dispose] !== "function") {
    Object.defineProperty(target, Symbol.dispose, {
      value: function() {
        return syncDispose();
      },
      configurable: true,
      enumerable: false,
      writable: true,
    });
  }

  if (Symbol.asyncDispose && typeof target[Symbol.asyncDispose] !== "function") {
    Object.defineProperty(target, Symbol.asyncDispose, {
      value: function() {
        if (typeof asyncDispose === "function") {
          return asyncDispose();
        }
        syncDispose();
        return Promise.resolve();
      },
      configurable: true,
      enumerable: false,
      writable: true,
    });
  }

  return target;
}

function destroyStream(stream) {
  if (!stream || typeof stream !== "object") {
    return;
  }
  try {
    if (typeof stream.end === "function") {
      stream.end();
    }
  } catch (_err) {}
  try {
    if (typeof stream.destroy === "function") {
      stream.destroy();
    }
  } catch (_err) {}
}

function disposeSubprocessSync(child) {
  if (!child || typeof child !== "object") {
    return;
  }

  destroyStream(child.stdin);
  destroyStream(child.stdout);
  destroyStream(child.stderr);

  if (child.exitCode == null && child.signalCode == null && !child.killed && typeof child.kill === "function") {
    try {
      child.kill();
    } catch (_err) {}
  }
}

function disposeSubprocessAsync(child) {
  disposeSubprocessSync(child);
  if (child && child.exited && typeof child.exited.then === "function") {
    return child.exited.catch(function() {});
  }
  return Promise.resolve();
}

const BUN_FILE_MIME_TYPES = {
  ".txt": "text/plain;charset=utf-8",
  ".html": "text/html;charset=utf-8",
  ".htm": "text/html;charset=utf-8",
  ".js": "text/javascript;charset=utf-8",
  ".mjs": "text/javascript;charset=utf-8",
  ".cjs": "text/javascript;charset=utf-8",
  ".ts": "text/typescript;charset=utf-8",
  ".tsx": "text/typescript;charset=utf-8",
  ".jsx": "text/javascript;charset=utf-8",
  ".json": "application/json;charset=utf-8",
  ".css": "text/css;charset=utf-8",
  ".svg": "image/svg+xml",
  ".xml": "application/xml;charset=utf-8",
  ".wasm": "application/wasm",
  ".gz": "application/gzip",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
};

function getBunCompatMimeType(filePath) {
  var ext = path.extname(String(filePath || "")).toLowerCase();
  return BUN_FILE_MIME_TYPES[ext] || "";
}

class BunFile {
  constructor(filePath) {
    // Handle URL objects (e.g. new URL("./file", import.meta.url))
    if (filePath && typeof filePath === 'object' && filePath.pathname) {
      filePath = decodeURIComponent(filePath.pathname);
    } else if (filePath && typeof filePath === 'object' && typeof filePath.href === 'string' && filePath.href.startsWith('file:')) {
      filePath = decodeURIComponent(filePath.href.replace(/^file:\/\//, ''));
    }
    this.path = path.resolve(String(filePath));
    this.name = path.basename(this.path);
    this.type = getBunCompatMimeType(this.path);
  }

  get size() {
    try {
      return fs.statSync(this.path).size;
    } catch (_err) {
      return 0;
    }
  }

  get lastModified() {
    try {
      return fs.statSync(this.path).mtimeMs;
    } catch (_err) {
      return 0;
    }
  }

  arrayBuffer() {
    return fs.promises.readFile(this.path).then((b) => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
  }

  bytes() {
    return fs.promises.readFile(this.path);
  }

  _getBytes() {
    var bytes = fs.readFileSync(this.path);
    return new Uint8Array(bytes.buffer, bytes.byteOffset || 0, bytes.byteLength || bytes.length || 0);
  }

  text() {
    return fs.promises.readFile(this.path, "utf8");
  }

  stream() {
    var bytes = this._getBytes();
    return new ReadableStream({
      start: function(controller) {
        controller.enqueue(cloneUint8Array(bytes));
        controller.close();
      },
    });
  }

  slice(begin, end, type) {
    var bytes = this._getBytes();
    return new Blob([bytes.slice(begin || 0, end === undefined ? bytes.length : end)], {
      type: type || this.type,
    });
  }

  exists() {
    return fs.promises.access(this.path).then(
      function() { return true; },
      function() { return false; },
    );
  }

  stat() {
    return fs.promises.stat(this.path).then(
      function(stats) {
        return {
          size: stats.size,
          mtime_ms: stats.mtimeMs,
          is_dir: stats.isDirectory(),
          is_file: stats.isFile(),
          mode: stats.mode,
        };
      },
      function() { return null; },
    );
  }

  unlink() {
    return fs.promises.unlink(this.path).then(function() {});
  }

  delete() {
    return this.unlink();
  }

  writer() {
    return fs.createWriteStream(this.path);
  }
}

let Bun = {
  inspect,
  version: compatRuntimeVersion,
  concatArrayBuffers,
  platform: processMod.platform,
  arch: processMod.arch,
  argv: processMod.argv,
  env: processMod.env,
  execPath: processMod.execPath,
  pid: processMod.pid,
  stdin: processMod.stdin,
  stdout: processMod.stdout,
  stderr: processMod.stderr,
  gc() {
    if (typeof global.gc === "function") {
      global.gc();
    }
  },
  gcSync: global.gc,
  which,
  file(filePath) {
    return new BunFile(filePath);
  },
  write(target, data) {
    const toPath = target && target.path ? target.path : String(target);
    return fs.promises.writeFile(toPath, data);
  },
  pathToFileURL(filePath) {
    return new URL(`file://${path.resolve(filePath)}`);
  },
  hash(input) {
    return crypto.createHash("sha256").update(toHashBuffer(input)).digest("hex");
  },
  fileURLToPath(input) {
    return path.fileURLToPath(input);
  },
  sleep(ms = 0) {
    return new Promise((resolve) => setTimeout(resolve, Number(ms)));
  },
  sleepSync(ms = 0) {
    const start = Date.now();
    while (Date.now() - start < Number(ms)) {
      // Busy spin fallback.
    }
  },
  gzipSync(input, options) {
    return runCompressionSync("gzipSync", input, options);
  },
  deflateSync(input, options) {
    return runCompressionSync("deflateSync", input, options);
  },
  deflateRawSync(input, options) {
    return runCompressionSync("deflateRawSync", input, options);
  },
  gunzipSync(input, options) {
    return runCompressionSync("gunzipSync", input, options);
  },
  inflateSync(input, options) {
    return runCompressionSync("inflateSync", input, options);
  },
  inflateRawSync(input, options) {
    return runCompressionSync("inflateRawSync", input, options);
  },
  spawn(input, options = {}) {
    const normalized = normalizeSpawnInput(input, options);
    const child = childProcess.spawn(
      normalized.command,
      normalized.args,
      normalizeSpawnOptions(normalized.options),
    );

    child.exited = new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => {
        child.exitCode = code;
        child.signalCode = signal;
        resolve(code);
      });
    });

    return defineDisposable(child, function() {
      disposeSubprocessSync(child);
    }, function() {
      return disposeSubprocessAsync(child);
    });
  },
  spawnSync(input, options = {}) {
    const normalized = normalizeSpawnInput(input, options);
    const result = childProcess.spawnSync(normalized.command, normalized.args, {
      encoding: "utf8",
      ...normalizeSpawnOptions(normalized.options),
    });
    return defineDisposable({
      stdout: result.stdout,
      stderr: result.stderr,
      status: result.status,
      signal: result.signal,
      pid: undefined,
      output: result.output,
      error: result.error || null,
      success: result.status === 0 && !result.error,
      exitCode: result.status,
      ...result,
    }, function() {});
  },
  ["$"](strings, ...values) {
    if (!Array.isArray(strings)) {
      return "";
    }
    let out = "";
    for (let i = 0; i < strings.length; i++) {
      out += strings[i];
      if (i < values.length) {
        out += String(values[i]);
      }
    }
    return Bun.spawnSync(out).stdout;
  },
  envVars() {
    return processMod.env;
  },
  unixify(value) {
    return typeof value === "string" ? value.replace(/\\/g, "/") : value;
  },
  isatty(stream) {
    return Boolean(stream && stream.isTTY);
  },
  cwd: processMod.cwd(),
  peek: function peek(promise) {
    // Bun.peek returns the value if fulfilled, the error if rejected, or the promise if pending
    if (promise && typeof promise === "object") {
      if (promise.__exactPeekStatus === "fulfilled") {
        return promise.__exactPeekValue;
      }
      if (promise.__exactPeekStatus === "rejected") {
        return promise.__exactPeekReason;
      }
    }
    return promise;
  },
  nanoseconds: function nanoseconds() {
    return Math.floor(performance.now() * 1e6);
  },
};

// Bun.unsafe - stub for internal APIs
Bun.unsafe = {
  gcAggressionLevel: function (level) { return level !== undefined ? level : 0; },
  arrayBufferToString: function (buf) {
    return new TextDecoder().decode(buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf);
  },
  segfault: function () { throw new Error("Bun.unsafe.segfault is not implemented"); },
};

// Bun.peek.status - returns 'fulfilled', 'rejected', or 'pending'
Bun.peek.status = function peekStatus(promise) {
  if (promise && typeof promise === "object" && typeof promise.__exactPeekStatus === "string") {
    return promise.__exactPeekStatus;
  }
  return 'pending';
};

// ReadableStream helpers (exported as top-level from "bun")
function readableStreamToArrayBuffer(stream) {
  var blobBytes = getBlobBackedStreamBytes(stream);
  if (blobBytes) {
    return createMarkedResolvedPromise(cloneUint8Array(blobBytes).buffer);
  }
  if (stream && typeof stream.arrayBuffer === "function") {
    return trackPromiseState(stream.arrayBuffer());
  }

  return trackPromiseState((async function() {
    var reader = stream.getReader();
    var chunks = [];
    var totalLen = 0;
    while (true) {
      var result = await reader.read();
      if (result.done) break;
      var chunk = normalizeReadableStreamChunk(result.value);
      chunks.push(chunk);
      totalLen += chunk.byteLength;
    }
    var buf = new Uint8Array(totalLen);
    var offset = 0;
    for (var i = 0; i < chunks.length; i++) {
      buf.set(chunks[i], offset);
      offset += chunks[i].byteLength;
    }
    return buf.buffer;
  })());
}

function readableStreamToBytes(stream) {
  var blobBytes = getBlobBackedStreamBytes(stream);
  if (blobBytes) {
    return createMarkedResolvedPromise(cloneUint8Array(blobBytes));
  }
  if (stream && typeof stream.bytes === "function") {
    return trackPromiseState(stream.bytes());
  }
  return trackPromiseState(readableStreamToArrayBuffer(stream).then(function(ab) {
    return new Uint8Array(ab);
  }));
}

function readableStreamToText(stream) {
  var blobBytes = getBlobBackedStreamBytes(stream);
  if (blobBytes) {
    return createMarkedResolvedPromise(
      typeof TextDecoder !== "undefined"
        ? new TextDecoder().decode(blobBytes)
        : Buffer.from(blobBytes).toString("utf8")
    );
  }
  if (stream && typeof stream.text === "function") {
    return trackPromiseState(stream.text());
  }
  return trackPromiseState(readableStreamToBytes(stream).then(function(bytes) {
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder().decode(bytes);
    }
    var result = '';
    for (var i = 0; i < bytes.length; i++) {
      result += String.fromCharCode(bytes[i]);
    }
    return result;
  }));
}

function readableStreamToFormData(stream) {
  if (stream && typeof stream.formData === "function") {
    return trackPromiseState(stream.formData());
  }
  return trackPromiseState(readableStreamToText(stream).then(function(text) {
    var params = new URLSearchParams(text);
    var form = new FormData();
    if (typeof params.forEach === "function") {
      params.forEach(function(value, key) {
        form.append(key, value);
      });
    }
    return form;
  }));
}

function readableStreamToJSON(stream) {
  if (stream && typeof stream.json === "function") {
    return trackPromiseState(stream.json());
  }
  return trackPromiseState(readableStreamToText(stream).then(function(text) {
    return JSON.parse(text);
  }));
}

function readableStreamToBlob(stream) {
  var blobBytes = getBlobBackedStreamBytes(stream);
  if (blobBytes) {
    var blobType = getBlobBackedStreamType(stream);
    return createMarkedResolvedPromise(blobType ? new Blob([cloneUint8Array(blobBytes)], { type: blobType }) : new Blob([cloneUint8Array(blobBytes)]));
  }
  return trackPromiseState(readableStreamToBytes(stream).then(function(bytes) {
    return new Blob([bytes]);
  }));
}

async function readableStreamToArray(stream) {
  var reader = stream.getReader();
  var arr = [];
  while (true) {
    var result = await reader.read();
    if (result.done) break;
    arr.push(result.value);
  }
  return arr;
}

function shellTemplate(strings) {
  var cmd = "";
  for (var i = 0; i < strings.length; i++) {
    cmd += strings[i];
    if (i < arguments.length - 1) {
      cmd += String(arguments[i + 1]);
    }
  }

  function createShellResult(stdoutBuffer, stderrBuffer, exitCode) {
    var stdout = Buffer.from(stdoutBuffer || []);
    var stderr = Buffer.from(stderrBuffer || []);
    return {
      stdout: stdout,
      stderr: stderr,
      exitCode: exitCode,
      text: function() {
        return stdout.toString();
      },
      toString: function() {
        return stdout.toString();
      },
    };
  }

  var shellPromise = new Promise(function(resolve) {
    var child = childProcess.spawn(cmd.trim(), { shell: true });
    var stdoutChunks = [];
    var stderrChunks = [];

    if (child.stdout && typeof child.stdout.on === "function") {
      child.stdout.on("data", function(chunk) {
        stdoutChunks.push(Buffer.from(chunk));
      });
    }
    if (child.stderr && typeof child.stderr.on === "function") {
      child.stderr.on("data", function(chunk) {
        stderrChunks.push(Buffer.from(chunk));
      });
    }
    child.on("error", function(error) {
      stderrChunks.push(Buffer.from(String(error && error.message ? error.message : error)));
    });
    child.on("close", function(code) {
      resolve(createShellResult(Buffer.concat(stdoutChunks), Buffer.concat(stderrChunks), typeof code === "number" ? code : 0));
    });
  });

  shellPromise.quiet = function() {
    return shellPromise;
  };
  shellPromise.text = function() {
    return shellPromise.then(function(result) {
      return result.text();
    });
  };
  shellPromise.toString = function() {
    return cmd.trim();
  };
  shellPromise.exitCode = 0;
  return shellPromise;
}

Bun.readableStreamToArrayBuffer = readableStreamToArrayBuffer;
Bun.readableStreamToBlob = readableStreamToBlob;
Bun.readableStreamToBytes = readableStreamToBytes;
Bun.readableStreamToText = readableStreamToText;
if (typeof Bun.$ !== "function") {
  Bun.$ = shellTemplate;
}
Bun.readableStreamToFormData = readableStreamToFormData;
Bun.readableStreamToJSON = readableStreamToJSON;
Bun.readableStreamToArray = readableStreamToArray;

if (typeof Bun.serve !== "function") {
  Bun.serve = function serve(options) {
    if (!options || typeof options !== "object") {
      throw new TypeError("Bun.serve() expects an options object");
    }

    var fetchHandler = options.fetch;
    if (typeof fetchHandler !== "function") {
      throw new TypeError("Bun.serve() requires a fetch handler function");
    }

    var errorHandler = options.error || function(err) {
      return new Response("Internal Server Error: " + (err && err.message ? err.message : String(err)), {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      });
    };

    function formatUrlHost(host) {
      host = String(host);
      if (host.indexOf(":") !== -1 && host.charAt(0) !== "[") {
        return "[" + host + "]";
      }
      return host;
    }

    var scheme = options.tls ? "https" : "http";
    var unixPath = options.unix != null ? String(options.unix) : "";
    var port = options.port !== undefined ? options.port : 3000;
    var hostnameProvided = options.hostname !== undefined;
    var hostname = hostnameProvided ? options.hostname : "127.0.0.1";
    var requestHost = !hostnameProvided || hostname === "0.0.0.0" ? "localhost" : hostname;

    function restoreRequestHeaders(request, rawHeaders) {
      if (!request || !request.headers || !rawHeaders) {
        return request;
      }

      request.headers._guard = "none";
      request.headers.forEach(function(_value, key) {
        request.headers.delete(key);
      });
      if (Array.isArray(rawHeaders)) {
        for (var i = 0; i < rawHeaders.length; i++) {
          var entry = rawHeaders[i];
          if (Array.isArray(entry) && entry.length >= 2) {
            request.headers.append(entry[0], entry[1]);
          }
        }
      } else {
        var keys = Object.keys(rawHeaders);
        for (var j = 0; j < keys.length; j++) {
          var key = keys[j];
          var value = rawHeaders[key];
          if (Array.isArray(value)) {
            for (var k = 0; k < value.length; k++) {
              request.headers.append(key, value[k]);
            }
          } else if (value !== undefined && value !== null) {
            request.headers.append(key, value);
          }
        }
      }
      request.headers._guard = "request";
      return request;
    }

    function normalizeNodeRequestHeaders(req) {
      if (Array.isArray(req && req.rawHeaders) && req.rawHeaders.length > 0) {
        var pairs = [];
        for (var i = 0; i + 1 < req.rawHeaders.length; i += 2) {
          pairs.push([req.rawHeaders[i], req.rawHeaders[i + 1]]);
        }
        return pairs;
      }
      return req && req.headers ? req.headers : undefined;
    }

    function createReadableRequestBodyFromNode(req) {
      return new ReadableStream({
        start(controller) {
          req.on("data", function(chunk) {
            controller.enqueue(
              chunk instanceof Uint8Array ? chunk : new Uint8Array(Buffer.from(chunk))
            );
          });
          req.on("end", function() {
            controller.close();
          });
          req.on("error", function(error) {
            controller.error(error);
          });
        },
        cancel(reason) {
          if (typeof req.destroy === "function") {
            req.destroy(reason);
          }
        },
      });
    }

    function buildNodeRequest(req, baseUrl) {
      var url = req && req.url ? String(req.url) : "/";
      var fullUrl =
        url.indexOf("http://") === 0 || url.indexOf("https://") === 0
          ? url
          : baseUrl + url;
      var method = req && req.method ? req.method : "GET";
      var init = { method: method };
      if (method !== "GET" && method !== "HEAD") {
        init.body = createReadableRequestBodyFromNode(req);
      }
      return restoreRequestHeaders(new Request(fullUrl, init), normalizeNodeRequestHeaders(req));
    }

    function buildResponseHeaders(response, requestUrl) {
      var headers = [];
      response.headers.forEach(function(value, key) {
        if (key.toLowerCase() === "location" && typeof value === "string" && value.indexOf("://") === 0) {
          var schemeMatch = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.exec(String(requestUrl || ""));
          if (schemeMatch) {
            value = schemeMatch[0] + value.slice(1);
          }
        }
        headers.push([key, value]);
      });
      return headers;
    }

    function shouldPreserveStreamContentLength(response, request) {
      if (
        !response ||
        !response.headers ||
        !request ||
        !request.headers ||
        typeof response.headers.get !== "function" ||
        typeof request.headers.get !== "function"
      ) {
        return false;
      }

      var responseContentLength = response.headers.get("content-length");
      if (!responseContentLength) {
        return false;
      }

      if (response.headers.get("content-encoding")) {
        return false;
      }

      return responseContentLength === request.headers.get("content-length");
    }

    function validateUnixSocketPath(pathValue) {
      if (!pathValue) {
        return;
      }

      var limit = {
        darwin: 104,
        linux: 108,
        win32: 260,
        sunos: 104,
        aix: 104,
        freebsd: 104,
        openbsd: 104,
        netbsd: 104,
        plan9: 104,
        android: 104,
        haiku: 104,
        cygwin: 260,
      }[processMod.platform] || 104;
      if (pathValue.length >= limit) {
        throw new Error("too long");
      }

      if (pathValue.charAt(0) === "\0") {
        return;
      }

      var directory = path.dirname(pathValue);
      if (directory && directory !== "." && !fs.existsSync(directory)) {
        throw new Error("no such file or directory");
      }
    }

    if (options.tls || unixPath) {
      if (unixPath) {
        validateUnixSocketPath(unixPath);
      }

      var nodeHttp = require("node:http");
      var nodeHttps = options.tls ? require("node:https") : null;
      var listenTarget = unixPath || { port: port, host: hostname };
      var baseUrl = unixPath
        ? scheme + "://localhost"
        : scheme + "://" + formatUrlHost(requestHost) + ":" + port;
      var nodeServer = (options.tls ? nodeHttps : nodeHttp).createServer(
        options.tls ? {
          key: options.tls.key,
          cert: options.tls.cert,
          ca: options.tls.ca,
          passphrase: options.tls.passphrase,
        } : undefined,
        function(req, res) {
          var request;
          try {
            request = buildNodeRequest(req, baseUrl);
          } catch (_err) {
            res.statusCode = 400;
            res.end("Bad Request");
            return;
          }

          Promise.resolve()
            .then(function() {
              return fetchHandler(request, server);
            })
            .then(function(response) {
              if (!(response instanceof Response)) {
                response = new Response(response == null ? "" : String(response));
              }
              var headerPairs = buildResponseHeaders(response, request.url);
              var streamBody = response.body && typeof response.body.getReader === "function";
              var preserveStreamContentLength = streamBody && shouldPreserveStreamContentLength(response, request);
              var headerObject = {};
              for (var i = 0; i < headerPairs.length; i++) {
                if (
                  streamBody &&
                  !preserveStreamContentLength &&
                  String(headerPairs[i][0]).toLowerCase() === "content-length"
                ) {
                  continue;
                }
                headerObject[headerPairs[i][0]] = headerPairs[i][1];
              }
              if (streamBody) {
                var reader = response.body.getReader();
                res.writeHead(response.status || 200, headerObject);
                function writeBody() {
                  return reader.read().then(function(result) {
                    if (result.done) {
                      res.end();
                      return;
                    }
                    var chunk = normalizeReadableStreamChunk(result.value);
                    if (!chunk || chunk.byteLength === 0) {
                      return writeBody();
                    }
                    res.write(Buffer.from(chunk));
                    return writeBody();
                  }).catch(function() {
                    try { res.end(); } catch (_endErr) {}
                  });
                }
                writeBody();
                return;
              }
              response.arrayBuffer().then(function(buffer) {
                res.writeHead(response.status || 200, headerObject);
                res.end(Buffer.from(buffer));
              }).catch(function() {
                res.writeHead(500, { "Content-Type": "text/plain" });
                res.end("Internal Server Error");
              });
            })
            .catch(function(err) {
              try {
                var handled = errorHandler(err);
                if (!(handled instanceof Response)) {
                  handled = new Response(handled == null ? "" : String(handled));
                }
                var handledPairs = buildResponseHeaders(handled, request.url);
                handled.arrayBuffer().then(function(buffer) {
                  var handledHeaders = {};
                  for (var i = 0; i < handledPairs.length; i++) {
                    handledHeaders[handledPairs[i][0]] = handledPairs[i][1];
                  }
                  res.writeHead(handled.status || 500, handledHeaders);
                  res.end(Buffer.from(buffer));
                }).catch(function() {
                  res.writeHead(500, { "Content-Type": "text/plain" });
                  res.end("Internal Server Error");
                });
              } catch (_handlerErr) {
                res.writeHead(500, { "Content-Type": "text/plain" });
                res.end("Internal Server Error");
              }
            });
        }
      );

      nodeServer.listen(listenTarget);
      var address = typeof nodeServer.address === "function" ? nodeServer.address() : null;
      var actualPort = address && typeof address === "object" && address.port ? address.port : port;
      var serverUrl = unixPath
        ? new URL(
            unixPath.charAt(0) === "\0"
              ? "abstract://" + unixPath.slice(1) + "/"
              : "unix://" + (unixPath.charAt(0) === "/" ? "" : "/") + unixPath
          )
        : new URL(scheme + "://" + formatUrlHost(requestHost) + ":" + actualPort + "/");
      var closed = false;
      var server = {
        port: unixPath ? undefined : actualPort,
        hostname: unixPath ? undefined : requestHost,
        url: serverUrl,
        development: options.development !== undefined ? !!options.development : false,
        id: "",
        pendingRequests: 0,
        stop: function(force) {
          if (closed) {
            return;
          }
          closed = true;
          if (force && typeof nodeServer.closeAllConnections === "function") {
            try { nodeServer.closeAllConnections(); } catch (_closeAllErr) {}
          }
          nodeServer.close(function() {
            if (unixPath && unixPath.charAt(0) !== "\0") {
              try { fs.unlinkSync(unixPath); } catch (_unlinkErr) {}
            }
          });
        },
        reload: function(nextOptions) {
          if (nextOptions && typeof nextOptions.fetch === "function") {
            fetchHandler = nextOptions.fetch;
          }
          if (nextOptions && typeof nextOptions.error === "function") {
            errorHandler = nextOptions.error;
          }
        },
        ref: function() {
          if (typeof nodeServer.ref === "function") {
            nodeServer.ref();
          }
        },
        unref: function() {
          if (typeof nodeServer.unref === "function") {
            nodeServer.unref();
          }
        },
        requestIP: function() {
          return null;
        },
        upgrade: function() {
          return false;
        },
        publish: function() {},
        fetch: fetchHandler,
      };

      return defineDisposable(server, function() {
        server.stop(true);
      }, function() {
        server.stop(true);
        return Promise.resolve();
      });
    }

    if (typeof globalThis.__exactHttpServe !== "function" && typeof globalThis.__exactEnsureHttp === "function") {
      globalThis.__exactEnsureHttp();
    }
    if (typeof globalThis.__exactHttpServe !== "function") {
      throw new Error("HTTP server not available in this environment");
    }

    var resultJson = globalThis.__exactHttpServe(port, hostname);
    var result;
    try {
      result = JSON.parse(resultJson);
    } catch (_err) {
      throw new Error("Failed to start HTTP server");
    }
    if (result.error) {
      throw new Error(result.error);
    }

    var serverId = result.id;
    var actualPort = result.port || port;
    var closing = false;
    var serverUrl = new URL(scheme + "://" + formatUrlHost(requestHost) + ":" + actualPort + "/");

    function buildRequest(data) {
      var url = data && data.url ? String(data.url) : "/";
      var fullUrl =
        url.indexOf("http://") === 0 || url.indexOf("https://") === 0
          ? url
          : scheme + "://" + formatUrlHost(requestHost) + ":" + actualPort + url;
      var rawHeaders = data && data.headers ? data.headers : undefined;
      var init = {
        method: data && data.method ? data.method : "GET",
      };
      if (init.method !== "GET" && init.method !== "HEAD" && data && data.hasBody) {
        if (typeof data.body === "string") {
          init.body = decodeBase64ToBytes(data.body);
        } else {
          init.body = createReadableRequestBody(serverId, data.id);
        }
      }
      return restoreRequestHeaders(new Request(fullUrl, init), rawHeaders);
    }

    function sendResponse(requestId, response, requestUrl, request) {
      if (!(response instanceof Response)) {
        response = new Response(response == null ? "" : String(response));
      }

      var headers = [];
      var streamBody = response.body && typeof response.body.getReader === "function";
      var preserveStreamContentLength = streamBody && shouldPreserveStreamContentLength(response, request);
      response.headers.forEach(function(value, key) {
        if (key.toLowerCase() === "location" && typeof value === "string" && value.indexOf("://") === 0) {
          var schemeMatch = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.exec(String(requestUrl || ""));
          if (schemeMatch) {
            value = schemeMatch[0] + value.slice(1);
          }
        }
        if (streamBody && !preserveStreamContentLength && key.toLowerCase() === "content-length") {
          return;
        }
        headers.push([key, value]);
      });
      var headersJson = JSON.stringify(headers);

      function responseBodyPayload(bytes) {
        if (!bytes) {
          return null;
        }
        return {
          buffer: bytes.buffer,
          byteOffset: bytes.byteOffset || 0,
          byteLength: bytes.byteLength || bytes.length || 0,
        };
      }

      if (
        streamBody &&
        typeof globalThis.__exactHttpRespondStream === "function" &&
        typeof globalThis.__exactHttpRespondChunk === "function" &&
        typeof globalThis.__exactHttpRespondEnd === "function"
      ) {
        var started = globalThis.__exactHttpRespondStream(serverId, requestId, response.status || 200, headersJson);
        if (started !== 0) {
          if (typeof globalThis.__exactHttpRespondString === "function") {
            globalThis.__exactHttpRespondString(serverId, requestId, 500, "[]", "Internal Server Error");
          }
          return;
        }

        var reader = response.body.getReader();
        function writeBody() {
          return reader.read().then(function(result) {
            if (result.done) {
              globalThis.__exactHttpRespondEnd(serverId, requestId);
              return;
            }
            var chunk = normalizeReadableStreamChunk(result.value || new Uint8Array(0));
            if (!chunk || chunk.byteLength === 0) {
              return writeBody();
            }
            var writeResult = globalThis.__exactHttpRespondChunk(
              serverId,
              requestId,
              responseBodyPayload(chunk)
            );
            if (writeResult !== 0) {
              if (typeof reader.cancel === "function") {
                try { reader.cancel("stream aborted"); } catch (_cancelErr) {}
              }
              globalThis.__exactHttpRespondEnd(serverId, requestId);
              return;
            }
            return writeBody();
          }).catch(function() {
            globalThis.__exactHttpRespondEnd(serverId, requestId);
          });
        }

        writeBody();
        return;
      }

      response.arrayBuffer().then(function(buffer) {
        if (typeof globalThis.__exactHttpRespond === "function") {
          globalThis.__exactHttpRespond(serverId, requestId, response.status || 200, headersJson, {
            buffer: buffer,
            byteOffset: 0,
            byteLength: buffer.byteLength || 0,
          });
          return;
        }
        var bodyText = new TextDecoder().decode(new Uint8Array(buffer));
        if (typeof globalThis.__exactHttpRespondString === "function") {
          globalThis.__exactHttpRespondString(serverId, requestId, response.status || 200, headersJson, bodyText);
        }
      }).catch(function() {
        if (typeof globalThis.__exactHttpRespondString === "function") {
          globalThis.__exactHttpRespondString(serverId, requestId, 500, "[]", "Internal Server Error");
        }
      });
    }

    function handleRequest(rawJson) {
      var data;
      try {
        data = JSON.parse(rawJson);
      } catch (_err) {
        return;
      }

      var requestId = data && data.id ? data.id : 0;
      var request;
      try {
        request = buildRequest(data);
      } catch (_err) {
        sendResponse(requestId, new Response("Bad Request", { status: 400 }), undefined, request);
        return;
      }

      Promise.resolve()
        .then(function() {
          return fetchHandler(request, server);
        })
        .then(function(response) {
          sendResponse(requestId, response, request.url, request);
        })
        .catch(function(err) {
          try {
            sendResponse(requestId, errorHandler(err), request.url, request);
          } catch (_handlerErr) {
            sendResponse(requestId, new Response("Internal Server Error", { status: 500 }), request.url, request);
          }
        });
    }

    function poll() {
      if (closing) {
        return;
      }

      var reqJson = typeof globalThis.__exactHttpPoll === "function"
        ? globalThis.__exactHttpPoll(serverId)
        : null;
      if (reqJson) {
        handleRequest(reqJson);
        setTimeout(poll, 0);
        return;
      }

      if (typeof globalThis.__exactHttpWait === "function") {
        Promise.resolve(globalThis.__exactHttpWait(serverId, 1000)).then(
          function(nextReqJson) {
            if (nextReqJson) {
              handleRequest(nextReqJson);
            }
            if (!closing) {
              setTimeout(poll, 0);
            }
          },
          function() {
            if (!closing) {
              setTimeout(poll, 50);
            }
          }
        );
        return;
      }

      setTimeout(poll, 50);
    }

    poll();

    var server = {
      port: actualPort,
      hostname: requestHost,
      url: serverUrl,
      development: options.development !== undefined ? !!options.development : false,
      id: "",
      pendingRequests: 0,
      stop: function(force) {
        closing = true;
        if (typeof globalThis.__exactHttpClose === "function") {
          globalThis.__exactHttpClose(serverId, force ? 1 : 0);
        }
      },
      reload: function(nextOptions) {
        if (nextOptions && typeof nextOptions.fetch === "function") {
          fetchHandler = nextOptions.fetch;
        }
        if (nextOptions && typeof nextOptions.error === "function") {
          errorHandler = nextOptions.error;
        }
      },
      ref: function() {
        if (typeof globalThis.__exactHttpSetRef === "function") {
          globalThis.__exactHttpSetRef(serverId, 1);
        }
      },
      unref: function() {
        if (typeof globalThis.__exactHttpSetRef === "function") {
          globalThis.__exactHttpSetRef(serverId, 0);
        }
      },
      requestIP: function() {
        return null;
      },
      upgrade: function() {
        return false;
      },
      publish: function() {},
      fetch: fetchHandler,
    };

    return defineDisposable(server, function() {
      server.stop(true);
    }, function() {
      server.stop(true);
      return Promise.resolve();
    });
  };
}

if (typeof Bun.listen !== "function") {
  Bun.listen = function listen(options) {
    if (!options || typeof options !== "object") {
      throw new TypeError("Bun.listen() expects an options object");
    }

    var handlers = options.socket;
    if (!handlers || typeof handlers !== "object") {
      throw new TypeError("Bun.listen() requires a socket handlers object");
    }

    if (typeof globalThis.__exactTcpListen !== "function" && typeof globalThis.__exactEnsureNet === "function") {
      globalThis.__exactEnsureNet();
    }
    if (typeof globalThis.__exactTcpListen !== "function") {
      throw new Error("TCP server not available in this environment");
    }

    var hostname = options.hostname || "0.0.0.0";
    var hostnameProvided = Object.prototype.hasOwnProperty.call(options, "hostname");
    var requestHost = (!hostnameProvided || hostname === "0.0.0.0" || hostname === "::") ? "127.0.0.1" : hostname;
    var port = options.port || 0;
    var serverHandle = globalThis.__exactTcpListen(hostname, port, 128);
    var actualPort = port;

    try {
      var info = JSON.parse(globalThis.__exactTcpLocalAddr(serverHandle));
      actualPort = info.port;
      if ((!hostnameProvided || hostname === "0.0.0.0" || hostname === "::") && info.address && info.address !== "0.0.0.0" && info.address !== "::") {
        hostname = info.address;
        requestHost = info.address;
      }
    } catch (_err) {}

    var closing = false;
    var activeSockets = [];
    var acceptTimer = null;

    function BunSocket(handle) {
      this._handle = handle;
      this._destroyed = false;
      this._pollTimer = null;
      this.data = options.data !== undefined ? options.data : undefined;
      this.remoteAddress = "127.0.0.1";
      try {
        var remote = JSON.parse(globalThis.__exactTcpRemoteAddr(handle));
        this.remoteAddress = remote.address || this.remoteAddress;
      } catch (_err) {}
    }

    BunSocket.prototype.write = function(data) {
      if (this._destroyed) {
        return 0;
      }
      try {
        var output = typeof data === "string" ? data : normalizeReadableStreamChunk(data);
        return globalThis.__exactTcpWrite(this._handle, output);
      } catch (_err) {
        return 0;
      }
    };
    BunSocket.prototype.flush = function() {
      return this;
    };
    BunSocket.prototype.end = function(data) {
      if (data !== undefined) {
        this.write(data);
      }
      this.terminate();
    };
    BunSocket.prototype.terminate = function() {
      this._cleanup();
    };
    BunSocket.prototype._cleanup = function() {
      if (this._destroyed) {
        return;
      }
      this._destroyed = true;
      if (this._pollTimer != null) {
        clearTimeout(this._pollTimer);
        this._pollTimer = null;
      }
      try {
        globalThis.__exactTcpClose(this._handle);
      } catch (_err) {}
      var index = activeSockets.indexOf(this);
      if (index !== -1) {
        activeSockets.splice(index, 1);
      }
      if (typeof handlers.close === "function") {
        try {
          handlers.close(this);
        } catch (_err) {}
      }
    };
    BunSocket.prototype._startPolling = function() {
      var self = this;
      function poll() {
        if (self._destroyed) {
          return;
        }
        try {
          var data = globalThis.__exactTcpRead(self._handle, 65536);
          if (data === null) {
            self._cleanup();
            return;
          }
          if (data.length > 0 && typeof handlers.data === "function") {
            var chunk = data;
            if (typeof Buffer !== "undefined" && Buffer.from) {
              if (typeof data === "string") {
                chunk = Buffer.from(data);
              } else if (data instanceof Uint8Array || (Buffer.isBuffer && Buffer.isBuffer(data))) {
                chunk = Buffer.from(data.buffer || data, data.byteOffset || 0, data.byteLength || data.length);
              }
            }
            handlers.data(self, chunk);
          }
        } catch (err) {
          if (typeof handlers.error === "function") {
            try {
              handlers.error(self, err);
            } catch (_handlerErr) {}
          }
          self._cleanup();
          return;
        }
        self._pollTimer = setTimeout(poll, 5);
      }
      self._pollTimer = setTimeout(poll, 0);
    };

    function acceptLoop() {
      if (closing) {
        return;
      }
      try {
        var clientHandle = globalThis.__exactTcpAccept(serverHandle);
        if (clientHandle !== -1) {
          var socket = new BunSocket(clientHandle);
          activeSockets.push(socket);
          if (typeof handlers.open === "function") {
            try {
              handlers.open(socket);
            } catch (err) {
              if (typeof handlers.error === "function") {
                try {
                  handlers.error(socket, err);
                } catch (_handlerErr) {}
              }
            }
          }
          socket._startPolling();
        }
      } catch (_err) {}
      acceptTimer = setTimeout(acceptLoop, 10);
    }

    acceptTimer = setTimeout(acceptLoop, 0);

    var listener = {
      port: actualPort,
      hostname: requestHost,
      stop: function(closeActive) {
        closing = true;
        if (acceptTimer != null) {
          clearTimeout(acceptTimer);
          acceptTimer = null;
        }
        if (closeActive) {
          var sockets = activeSockets.slice();
          for (var i = 0; i < sockets.length; i++) {
            sockets[i]._cleanup();
          }
        }
        try {
          globalThis.__exactTcpClose(serverHandle);
        } catch (_err) {}
      },
      ref: function() {
        return this;
      },
      unref: function() {
        return this;
      },
      reload: function(nextOptions) {
        if (nextOptions && nextOptions.socket && typeof nextOptions.socket === "object") {
          handlers = nextOptions.socket;
        }
      },
    };

    return defineDisposable(listener, function() {
      listener.stop(true);
    }, function() {
      listener.stop(true);
      return Promise.resolve();
    });
  };
}

// Glob - basic file glob matching using node:fs and simple pattern matching
class Glob {
  constructor(pattern) {
    this._pattern = String(pattern);
  }

  *scanSync(options) {
    var dir = path.dirname(this._pattern);
    var globPart = path.basename(this._pattern);
    var re = new RegExp("^" + globPart.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$");
    try {
      var entries = fs.readdirSync(dir);
      for (var i = 0; i < entries.length; i++) {
        if (re.test(entries[i])) {
          yield path.join(dir, entries[i]);
        }
      }
    } catch (e) {
      // Directory doesn't exist or not readable
    }
  }

  scan(options) {
    var results = [];
    for (var f of this.scanSync(options)) {
      results.push(f);
    }
    return results;
  }
}

// CryptoHasher - basic crypto hasher stub
class CryptoHasher {
  constructor(algorithm) {
    this._algorithm = (algorithm || "sha256").toLowerCase();
    this._hasher = crypto.createHash(this._algorithm);
  }

  update(data) {
    this._hasher.update(toHashBuffer(data));
    return this;
  }

  digest(encoding) {
    return this._hasher.digest(encoding || "hex");
  }

  static hash(algorithm, data, encoding) {
    return crypto.createHash(algorithm).update(toHashBuffer(data)).digest(encoding || "hex");
  }

  static get algorithms() {
    return ["sha256", "sha512", "sha1", "md5", "sha384", "sha224"];
  }
}

// Named hash classes - convenience wrappers around CryptoHasher for specific algorithms
function createHashClass(algorithm) {
  function HashClass() {
    this._hasher = crypto.createHash(algorithm);
  }
  Object.defineProperty(HashClass, 'name', { value: algorithm.toUpperCase().replace('-', ''), configurable: true });
  HashClass.prototype.update = function(data) {
    this._hasher.update(toHashBuffer(data));
    return this;
  };
  HashClass.prototype.digest = function(encoding) {
    var digest = this._hasher.digest();
    if (encoding instanceof Uint8Array || (encoding && typeof encoding === 'object' && encoding.buffer)) {
      var buf = encoding instanceof Uint8Array ? encoding : new Uint8Array(encoding.buffer, encoding.byteOffset, encoding.byteLength);
      buf.set(new Uint8Array(digest.buffer, digest.byteOffset, digest.byteLength));
      return buf;
    }
    return digest.toString(encoding || 'hex');
  };
  HashClass.hash = function(input, encoding) {
    var h = crypto.createHash(algorithm);
    h.update(toHashBuffer(input));
    var digest = h.digest();
    if (encoding instanceof Uint8Array || (encoding && typeof encoding === 'object' && encoding.buffer)) {
      var buf = encoding instanceof Uint8Array ? encoding : new Uint8Array(encoding.buffer, encoding.byteOffset, encoding.byteLength);
      buf.set(new Uint8Array(digest.buffer, digest.byteOffset, digest.byteLength));
      return buf;
    }
    return digest.toString(encoding || 'hex');
  };
  return HashClass;
}

var MD4 = createHashClass('md4');
var MD5 = createHashClass('md5');
var SHA1 = createHashClass('sha1');
var SHA224 = createHashClass('sha224');
var SHA256 = createHashClass('sha256');
var SHA384 = createHashClass('sha384');
var SHA512 = createHashClass('sha512');
var SHA512_256 = createHashClass('sha512-256');

Bun.MD4 = MD4;
Bun.MD5 = MD5;
Bun.SHA1 = SHA1;
Bun.SHA224 = SHA224;
Bun.SHA256 = SHA256;
Bun.SHA384 = SHA384;
Bun.SHA512 = SHA512;
Bun.SHA512_256 = SHA512_256;

installBlobCompatFastPaths();

// Merge our properties onto the existing global Bun object (set by the runtime)
// rather than replacing it, to preserve runtime-provided APIs (fetch, serve, etc.)
if (globalThis.Bun && typeof globalThis.Bun === "object") {
  var existingBun = globalThis.Bun;
  var keys = Object.keys(Bun);
  for (var i = 0; i < keys.length; i++) {
    if (!(keys[i] in existingBun)) {
      existingBun[keys[i]] = Bun[keys[i]];
    }
  }
  // Always overwrite these specific additions from our shim
  existingBun.unsafe = Bun.unsafe;
  existingBun.peek = Bun.peek;
  existingBun.peek.status = Bun.peek.status;
  existingBun.readableStreamToArrayBuffer = readableStreamToArrayBuffer;
  existingBun.readableStreamToBlob = readableStreamToBlob;
  existingBun.readableStreamToBytes = readableStreamToBytes;
  existingBun.readableStreamToText = readableStreamToText;
  existingBun.readableStreamToFormData = readableStreamToFormData;
  existingBun.readableStreamToJSON = readableStreamToJSON;
  existingBun.readableStreamToArray = readableStreamToArray;
  existingBun.gzipSync = Bun.gzipSync;
  existingBun.deflateSync = Bun.deflateSync;
  existingBun.deflateRawSync = Bun.deflateRawSync;
  existingBun.gunzipSync = Bun.gunzipSync;
  existingBun.inflateSync = Bun.inflateSync;
  existingBun.inflateRawSync = Bun.inflateRawSync;
  existingBun.MD4 = MD4;
  existingBun.MD5 = MD5;
  existingBun.SHA1 = SHA1;
  existingBun.SHA224 = SHA224;
  existingBun.SHA256 = SHA256;
  existingBun.SHA384 = SHA384;
  existingBun.SHA512 = SHA512;
  existingBun.SHA512_256 = SHA512_256;
  defineCompatProperty(existingBun, "file", Bun.file);
  defineCompatProperty(existingBun, "write", Bun.write);
  defineCompatProperty(existingBun, "version", Bun.version);
  existingBun.$ = shellTemplate;
  Bun = existingBun;
} else {
  globalThis.Bun = Bun;
}
Bun.stdout = Bun.stdout || globalThis.process.stdout;
Bun.stderr = Bun.stderr || globalThis.process.stderr;
Bun.stdin = Bun.stdin || globalThis.process.stdin;

module.exports = Bun;
module.exports["Bun"] = Bun;
module.exports.Glob = Glob;
module.exports.CryptoHasher = CryptoHasher;
module.exports.serve = Bun.serve;
module.exports.Socket = Bun.Socket;
module.exports.TCPSocketListener = Bun.TCPSocketListener;
module.exports.ArrayBufferSink = Bun.ArrayBufferSink;
module.exports.Server = Bun.Server;
module.exports.Serve = Bun.Serve;
module.exports.ServeOptions = Bun.ServeOptions;
module.exports.AnyFunction = Bun.AnyFunction;
module.exports.randomUUIDv7 = Bun.randomUUIDv7;
module.exports.SQL = Bun.SQL;
module.exports.plugin = Bun.plugin;
module.exports.semver = Bun.semver;
module.exports.deflateSync = Bun.deflateSync;
module.exports.gzipSync = Bun.gzipSync;
module.exports.gunzipSync = Bun.gunzipSync;
module.exports.inflateSync = Bun.inflateSync;
module.exports.readableStreamToArrayBuffer = readableStreamToArrayBuffer;
module.exports.readableStreamToBlob = readableStreamToBlob;
module.exports.readableStreamToBytes = readableStreamToBytes;
module.exports.readableStreamToText = readableStreamToText;
module.exports.readableStreamToFormData = readableStreamToFormData;
module.exports.readableStreamToJSON = readableStreamToJSON;
module.exports.readableStreamToArray = readableStreamToArray;
module.exports.$ = shellTemplate;
module.exports.MD4 = MD4;
module.exports.MD5 = MD5;
module.exports.SHA1 = SHA1;
module.exports.SHA224 = SHA224;
module.exports.SHA256 = SHA256;
module.exports.SHA384 = SHA384;
module.exports.SHA512 = SHA512;
module.exports.SHA512_256 = SHA512_256;
