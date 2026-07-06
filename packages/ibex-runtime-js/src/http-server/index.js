var g = globalThis;

// Hoisted once at module load: rebuilding this 64-entry table on every request
// body decode was pure per-call waste. @ref https://linear.app/expo/issue/ENG-23027
var B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var B64_LOOKUP = (function () {
  var lookup = {};
  for (var i = 0; i < B64_CHARS.length; i++) lookup[B64_CHARS[i]] = i;
  return lookup;
})();

function b64ToBytes(b64) {
  if (!b64) return new Uint8Array(0);
  var lookup = B64_LOOKUP;
  var raw = b64.replace(/[^A-Za-z0-9+/]/g, "");
  var len = raw.length;
  var bytes = new Uint8Array(Math.ceil(len * 3 / 4));
  var j = 0;
  for (var i = 0; i < len; i += 4) {
    var a = lookup[raw[i]] || 0;
    var b = lookup[raw[i+1]] || 0;
    var c = lookup[raw[i+2]] || 0;
    var d = lookup[raw[i+3]] || 0;
    bytes[j++] = (a << 2) | (b >> 4);
    if (i + 2 < len) bytes[j++] = ((b & 15) << 4) | (c >> 2);
    if (i + 3 < len) bytes[j++] = ((c & 3) << 6) | d;
  }
  return bytes.slice(0, j);
}

function toBytes(data) {
  if (!data) return new Uint8Array(0);
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (typeof data === "string") {
    if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(data);
    var buf = new Uint8Array(data.length * 3), o = 0;
    for (var i = 0; i < data.length; i++) {
      var c = data.charCodeAt(i);
      if (c < 0x80) buf[o++] = c;
      else if (c < 0x800) { buf[o++] = 0xc0|(c>>6); buf[o++] = 0x80|(c&0x3f); }
      else { buf[o++] = 0xe0|(c>>12); buf[o++] = 0x80|((c>>6)&0x3f); buf[o++] = 0x80|(c&0x3f); }
    }
    return buf.slice(0, o);
  }
  return new Uint8Array(0);
}

function responseBodyPayload(data) {
  if (!data) return null;
  if (data instanceof Uint8Array) {
    return {
      buffer: data.buffer,
      byteOffset: data.byteOffset || 0,
      byteLength: data.byteLength || data.length || 0,
    };
  }
  if (data instanceof ArrayBuffer) {
    return {
      buffer: data,
      byteOffset: 0,
      byteLength: data.byteLength || 0,
    };
  }
  return data;
}

function createReadableRequestBody(streamId, requestId) {
  return new ReadableStream({
    pull: function(controller) {
      return new Promise(function(resolve, reject) {
        function poll() {
          if (typeof g.__exactHttpReadBody !== "function") {
            reject(new Error("Request body streaming unavailable"));
            return;
          }

          var resultJson = g.__exactHttpReadBody(streamId, requestId);
          if (!resultJson) {
            resolve();
            return;
          }

          var result = JSON.parse(resultJson);
          if (result.error) {
            reject(new Error(result.error));
            return;
          }

          if (result.done) {
            controller.close();
            resolve();
            return;
          }

          if (result.chunk) {
            controller.enqueue(b64ToBytes(result.chunk));
            resolve();
            return;
          }

          setTimeout(poll, 0);
        }

        poll();
      });
    }
  });
}

var MAX_REQUEST_HEADERS = 128;
var MAX_REQUEST_HEADER_BYTES = 16 * 1024;
var MAX_REQUEST_BODY_BYTES = 1024 * 1024;
var MAX_RESPONSE_BODY_BYTES = 4 * 1024 * 1024;
var HTTP_OK = 200;
var HTTP_BAD_REQUEST = 400;
var HTTP_REQUEST_TIMEOUT = 408;
var HTTP_REQUEST_ENTITY_TOO_LARGE = 413;
var HTTP_INTERNAL_SERVER_ERROR = 500;

// Fast-path response functions available
var hasRespondText = typeof g.__exactHttpRespondText === "function";
var hasRespondJson = typeof g.__exactHttpRespondJson === "function";
var hasRespondString = typeof g.__exactHttpRespondString === "function";
var hasPoll = typeof g.__exactHttpPoll === "function";
var hasDrain = typeof g.__exactHttpDrain === "function";

function ensureHttpHostFunctions() {
  if (typeof g.__exactHttpServe === "function") {
    return;
  }
  if (typeof g.__exactEnsureHttp === "function") {
    g.__exactEnsureHttp();
  }
  hasRespondText = typeof g.__exactHttpRespondText === "function";
  hasRespondJson = typeof g.__exactHttpRespondJson === "function";
  hasRespondString = typeof g.__exactHttpRespondString === "function";
  hasPoll = typeof g.__exactHttpPoll === "function";
  hasDrain = typeof g.__exactHttpDrain === "function";
}

// Item 9: Cache common HTTP method strings to reduce allocations
var METHOD_GET = "GET";
var METHOD_POST = "POST";
var METHOD_PUT = "PUT";
var METHOD_DELETE = "DELETE";
var METHOD_PATCH = "PATCH";
var METHOD_HEAD = "HEAD";
var METHOD_OPTIONS = "OPTIONS";

// Item 9: Method string interning cache
var methodCache = {};
methodCache[METHOD_GET] = METHOD_GET;
methodCache[METHOD_POST] = METHOD_POST;
methodCache[METHOD_PUT] = METHOD_PUT;
methodCache[METHOD_DELETE] = METHOD_DELETE;
methodCache[METHOD_PATCH] = METHOD_PATCH;
methodCache[METHOD_HEAD] = METHOD_HEAD;
methodCache[METHOD_OPTIONS] = METHOD_OPTIONS;

function internMethod(m) {
  return methodCache[m] || m;
}

function clampStatus(status) {
  var n = Number(status);
  if (!isFinite(n) || n < 100 || n > 999) {
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  return Math.floor(n);
}

function stringifyError(error) {
  if (!error) {
    return "";
  }
  if (typeof error.message === "string") {
    return error.message;
  }
  if (typeof error === "string") {
    return error;
  }
  return String(error);
}

function mapRequestErrorStatus(message) {
  var lower = (message || "").toLowerCase();
  if (lower.indexOf("payload too large") !== -1) {
    return HTTP_REQUEST_ENTITY_TOO_LARGE;
  }
  if (lower.indexOf("request timeout") !== -1 || lower.indexOf("timeout") !== -1) {
    return HTTP_REQUEST_TIMEOUT;
  }
  if (lower.indexOf("bad request") !== -1 || lower.indexOf("malformed") !== -1) {
    return HTTP_BAD_REQUEST;
  }
  return HTTP_INTERNAL_SERVER_ERROR;
}

function normalizeHeaders(list) {
  if (!list || !list.length) return {pairs: [], bytes: 0, ok: true};
  var totalBytes = 0;
  var pairs = [];
  for (var i = 0; i < list.length; i++) {
    if (pairs.length >= MAX_REQUEST_HEADERS) {
      return {pairs: pairs, bytes: totalBytes, ok: false};
    }
    var item = list[i];
    if (!item || !item.length || item.length < 2 || item.length > 2) {
      return {pairs: pairs, bytes: totalBytes, ok: false};
    }
    var key = item[0];
    var value = item[1];
    if (typeof key !== "string" || typeof value !== "string") {
      return {pairs: pairs, bytes: totalBytes, ok: false};
    }
    totalBytes += key.length + value.length;
    if (totalBytes > MAX_REQUEST_HEADER_BYTES) {
      return {pairs: pairs, bytes: totalBytes, ok: false};
    }
    pairs.push([key, value]);
  }
  return {pairs: pairs, bytes: totalBytes, ok: true};
}

function serve(options) {
  if (!options || typeof options.fetch !== "function") {
    throw new TypeError("serve() requires a fetch function");
  }
  ensureHttpHostFunctions();
  if (typeof g.__exactHttpServe !== "function") {
    throw new Error("Exact HTTP server bridge is unavailable in this runtime");
  }
  var port = options.port || 0;
  var hostnameProvided = Object.prototype.hasOwnProperty.call(options, "hostname");
  var hostname = hostnameProvided ? options.hostname : "127.0.0.1";
  var fetchFn = options.fetch;

  var resultJson = g.__exactHttpServe(port, hostname);
  var result = JSON.parse(resultJson);
  if (result.error) {
    throw new Error(result.error);
  }

  var serverId = result.id;
  var boundPort = result.port;
  var closed = false;

  // Re-check fast-path availability after serve() init
  hasRespondText = typeof g.__exactHttpRespondText === "function";
  hasRespondJson = typeof g.__exactHttpRespondJson === "function";
  hasRespondString = typeof g.__exactHttpRespondString === "function";
  hasPoll = typeof g.__exactHttpPoll === "function";
  hasDrain = typeof g.__exactHttpDrain === "function";

  // Pre-compute URL prefix once (avoid per-request string concat)
  var requestHost = !hostnameProvided || hostname === "0.0.0.0" ? "localhost" : hostname;
  var urlPrefix = "http://" + requestHost + ":" + boundPort;

  function failResponse(requestId, status, message) {
    var body = responseBodyPayload(toBytes(message || ""));
    g.__exactHttpRespond(serverId, requestId, status, null, body);
  }

  // Concurrent request dispatch
  var waitCount = 0;
  var MAX_CONCURRENT_WAITS = 4;

  function waitForNextRequest() {
    if (closed) return;
    if (waitCount >= MAX_CONCURRENT_WAITS) return;

    // Item 6: Synchronous poll fast-path
    // Try to dequeue a request synchronously before falling back to async wait.
    if (hasPoll) {
      var syncJson = g.__exactHttpPoll(serverId);
      if (syncJson) {
        // Got a request synchronously - handle it and keep polling
        handleRequest(syncJson);
        // Use setTimeout(0) to yield back to event loop before next sync poll
        // This prevents starving timers/callbacks during high load
        if (!closed) {
          setTimeout(waitForNextRequest, 0);
        }
        return;
      }
    }

    // Item 8: Try batch drain before falling back to single async wait
    if (hasDrain) {
      var batchJson = g.__exactHttpDrain(serverId, 16);
      if (batchJson) {
        var batch;
        try {
          batch = JSON.parse(batchJson);
        } catch(e) {
          batch = null;
        }
        if (batch && batch.length > 0) {
          for (var i = 0; i < batch.length; i++) {
            handleRequestObj(batch[i]);
          }
          if (!closed) {
            setTimeout(waitForNextRequest, 0);
          }
          return;
        }
      }
    }

    if (typeof g.__exactHttpWait !== "function") {
      closed = true;
      throw new Error("Exact HTTP dispatcher unavailable: __exactHttpWait is not defined");
    }

    waitCount++;
    var waitPromise = g.__exactHttpWait(serverId, 0);
    if (!waitPromise || typeof waitPromise.then !== "function") {
      waitCount--;
      if (!closed) {
        waitForNextRequest();
      }
      return;
    }

    waitPromise.then(function(reqJson) {
      waitCount--;
      if (closed) return;

      if (reqJson) {
        handleRequest(reqJson);
      }

      if (!closed) {
        waitForNextRequest();
      }
    }).catch(function() {
      waitCount--;
      if (!closed) {
        waitForNextRequest();
      }
    });
  }

  // Item 9: Process a pre-parsed request object (from batch drain)
  function handleRequestObj(req) {
    if (!req || typeof req.method !== "string" || !req.url || typeof req.id !== "number") {
      return;
    }

    if (req.url.charAt(0) !== "/") {
      failResponse(req.id, HTTP_BAD_REQUEST, "Bad Request: malformed URL");
      return;
    }

    processRequest(req);
  }

  function handleRequest(jsonStr) {
    var req;
    try {
      req = JSON.parse(jsonStr);
    } catch(e) {
      return;
    }

    if (!req || typeof req.method !== "string" || !req.url || typeof req.id !== "number") {
      return;
    }

    if (req.url.charAt(0) !== "/") {
      failResponse(req.id, HTTP_BAD_REQUEST, "Bad Request: malformed URL");
      return;
    }

    processRequest(req);
  }

  // Item 9: Shared request processing logic to avoid duplication
  function processRequest(req) {
    var headerState = normalizeHeaders(req.headers || []);
    if (!headerState.ok) {
      failResponse(req.id, HTTP_BAD_REQUEST, "Bad Request: malformed headers");
      return;
    }

    // Item 9: Use interned method strings
    var method = internMethod(req.method);

    var init = {
      method: method,
      headers: headerState.pairs
    };

    // Item 9: Fast path for GET/HEAD - skip body processing entirely
    if (req.hasBody && method !== METHOD_GET && method !== METHOD_HEAD) {
      if (req.body) {
        init.body = b64ToBytes(req.body);
      } else {
        init.body = createReadableRequestBody(serverId, req.id);
      }
    }

    var request;
    // Use pre-computed URL prefix
    var url = urlPrefix + req.url;
    try {
      request = new Request(url, init);
    } catch(e) {
      failResponse(req.id, HTTP_BAD_REQUEST, "Bad Request: " + (e && e.message || e));
      return;
    }

    try {
      var p = fetchFn(request);
      if (p && typeof p.then === "function") {
        p.then(function(response) {
          sendResponse(req.id, response);
        }).catch(function(err) {
          var message = stringifyError(err);
          var status = mapRequestErrorStatus(message);
          if (status === HTTP_INTERNAL_SERVER_ERROR) {
            failResponse(req.id, status, "Internal Server Error: " + message);
          } else {
            failResponse(req.id, status, "Request Error: " + message);
          }
        });
      } else {
        sendResponse(req.id, p);
      }
    } catch(err) {
      var message = stringifyError(err);
      var status = mapRequestErrorStatus(message);
      if (status === HTTP_INTERNAL_SERVER_ERROR) {
        failResponse(req.id, status, "Internal Server Error: " + message);
      } else {
        failResponse(req.id, status, "Request Error: " + message);
      }
    }
  }

  function sendResponse(requestId, response) {
    if (!response || typeof response !== "object") {
      failResponse(requestId, HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error: malformed response");
      return;
    }

    var status = HTTP_OK;
    if (response.status !== undefined) {
      status = clampStatus(response.status);
    }

    // Fast-path for simple text/json responses
    var body = response.body;
    var hasBodyStream = !!(body && typeof body.getReader === "function");

    if (!hasBodyStream && typeof response.arrayBuffer === "function") {
      var contentType = null;
      var headerCount = 0;
      var hasContentLength = false;
      if (response.headers && typeof response.headers.get === "function") {
        contentType = response.headers.get("content-type");
        if (typeof response.headers.forEach === "function") {
          response.headers.forEach(function(v, k) {
            headerCount++;
            if (k === "content-length") hasContentLength = true;
          });
        }
      }

      // Use fast text/json path ONLY when the sole headers are content-type and
      // (optionally) content-length. The fast host calls send just those two, so
      // any other header (cache-control, etag, set-cookie, ...) would be silently
      // dropped. When two headers are present, the second must be content-length.
      if (contentType && headerCount <= 2 && (headerCount < 2 || hasContentLength)) {
        var isText = hasRespondText && contentType.indexOf("text/plain") === 0;
        var isJson = hasRespondJson && (contentType.indexOf("application/json") === 0);

        if (isText || isJson) {
          response.arrayBuffer().then(function(ab) {
            var bytes = new Uint8Array(ab);
            if (bytes.length > MAX_RESPONSE_BODY_BYTES) {
              failResponse(requestId, HTTP_REQUEST_ENTITY_TOO_LARGE, "Response Too Large");
              return;
            }
            var payload = responseBodyPayload(bytes);
            if (isText) {
              g.__exactHttpRespondText(serverId, requestId, status, payload);
            } else {
              g.__exactHttpRespondJson(serverId, requestId, status, payload);
            }
          }).catch(function(err) {
            failResponse(requestId, HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error: " + (err && err.message || err));
          });
          return;
        }
      }
    }

    // Item 10: Zero-copy string response path
    // If the response body is a string and we have __exactHttpRespondString,
    // pass it directly without converting to Uint8Array first
    if (hasRespondString && !hasBodyStream && typeof response.text === "function") {
      var ct = null;
      if (response.headers && typeof response.headers.get === "function") {
        ct = response.headers.get("content-type");
      }
      // Use string path for text-based content types
      if (ct && (ct.indexOf("text/") === 0 || ct.indexOf("application/json") === 0 || ct.indexOf("application/xml") === 0)) {
        // Serialize headers once
        var strHeaderPairs = [];
        var strTotalBytes = 0;
        var strHeadersOk = true;
        if (response.headers && typeof response.headers.forEach === "function") {
          try {
            response.headers.forEach(function(value, key) {
              key = String(key);
              value = String(value);
              strHeaderPairs.push([key, value]);
              strTotalBytes += key.length + value.length;
            });
          } catch(e) {
            strHeadersOk = false;
          }
        }
        if (strHeadersOk && strHeaderPairs.length <= MAX_REQUEST_HEADERS && strTotalBytes <= MAX_REQUEST_HEADER_BYTES) {
          var strHeadersJson = JSON.stringify(strHeaderPairs);
          response.text().then(function(text) {
            if (text.length > MAX_RESPONSE_BODY_BYTES) {
              failResponse(requestId, HTTP_REQUEST_ENTITY_TOO_LARGE, "Response Too Large");
              return;
            }
            g.__exactHttpRespondString(serverId, requestId, status, strHeadersJson, text);
          }).catch(function(err) {
            failResponse(requestId, HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error: " + (err && err.message || err));
          });
          return;
        }
      }
    }

    // Standard path: serialize all headers
    var headerPairs = [];
    if (response.headers) {
      if (typeof response.headers.forEach !== "function") {
        failResponse(requestId, HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error: malformed response headers");
        return;
      }

      var totalHeaderBytes = 0;
      try {
        response.headers.forEach(function(value, key) {
          key = String(key);
          value = String(value);
          headerPairs.push([key, value]);
          totalHeaderBytes += key.length + value.length;
        });
      } catch (err) {
        failResponse(requestId, HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error: malformed response headers");
        return;
      }

      if (headerPairs.length > MAX_REQUEST_HEADERS || totalHeaderBytes > MAX_REQUEST_HEADER_BYTES) {
        failResponse(requestId, HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error: response headers too large");
        return;
      }
    }
    var headersJson = JSON.stringify(headerPairs);

    if (!hasBodyStream && (typeof response.body === "undefined" || response.body === null)) {
      g.__exactHttpRespond(serverId, requestId, status, headersJson, null);
      return;
    }

    function respondWithBytes(bytes) {
      if (!bytes) {
        g.__exactHttpRespond(serverId, requestId, status, headersJson, null);
        return;
      }
      if (bytes.length > MAX_RESPONSE_BODY_BYTES) {
        failResponse(requestId, HTTP_REQUEST_ENTITY_TOO_LARGE, "Response Too Large");
        return;
      }
      g.__exactHttpRespond(serverId, requestId, status, headersJson, responseBodyPayload(bytes));
    }

    // Prefer the non-blocking streaming host calls: __exactHttpRespondChunkTry /
    // __exactHttpRespondEndTry return a "would-block" code (2) when the bounded
    // body channel is full, and __exactHttpAwaitWritable resolves once a slot
    // frees. This keeps a slow/stalled client from freezing the whole JS event
    // loop. Fall back to the legacy blocking calls if the async surface is
    // absent. @ref https://linear.app/expo/issue/ENG-23027
    var hasAsyncStream = typeof g.__exactHttpRespondChunkTry === "function" &&
      typeof g.__exactHttpRespondEndTry === "function" &&
      typeof g.__exactHttpAwaitWritable === "function";
    if (hasBodyStream && typeof g.__exactHttpRespondStream === "function" &&
      ((hasAsyncStream) ||
       (typeof g.__exactHttpRespondChunk === "function" &&
        typeof g.__exactHttpRespondEnd === "function"))) {
      var respondStarted = g.__exactHttpRespondStream(serverId, requestId, status, headersJson);
      if (respondStarted !== 0) {
        failResponse(requestId, HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error: failed to start response");
        return;
      }

      var HTTP_RESPOND_WOULD_BLOCK = 2;
      var streamReader = body.getReader();
      var streamFinished = false;

      function abortStream() {
        if (streamReader.cancel) {
          try { streamReader.cancel("stream aborted"); } catch (e) {}
        }
        if (!streamFinished) {
          streamFinished = true;
          if (hasAsyncStream) {
            g.__exactHttpRespondEndTry(serverId, requestId);
          } else {
            g.__exactHttpRespondEnd(serverId, requestId);
          }
        }
      }

      // Issue `action` (a host call returning 0 / 2 / -1), awaiting a drained
      // slot off the event loop whenever it reports would-block. Resolves true
      // once the byte lands, false on a fatal/gone peer.
      function issue(action) {
        var code = action();
        if (code === 0) {
          return Promise.resolve(true);
        }
        if (code === HTTP_RESPOND_WOULD_BLOCK && hasAsyncStream) {
          return g.__exactHttpAwaitWritable(serverId, requestId, 0).then(function (ready) {
            if (ready === 0) {
              return issue(action);
            }
            // Peer gone or wedged; the host already cleared/ended the stream.
            streamFinished = true;
            return false;
          });
        }
        // Fatal (-1), or would-block without async support: give up.
        return Promise.resolve(false);
      }

      function writeBody() {
        return streamReader.read().then(function (result) {
          if (result.done) {
            return issue(function () {
              return hasAsyncStream
                ? g.__exactHttpRespondEndTry(serverId, requestId)
                : g.__exactHttpRespondEnd(serverId, requestId);
            }).then(function () {
              streamFinished = true;
            });
          }

          var chunk = result.value || new Uint8Array(0);
          return issue(function () {
            return hasAsyncStream
              ? g.__exactHttpRespondChunkTry(serverId, requestId, responseBodyPayload(chunk))
              : g.__exactHttpRespondChunk(serverId, requestId, responseBodyPayload(chunk));
          }).then(function (ok) {
            if (!ok) {
              abortStream();
              return;
            }
            return writeBody();
          });
        }).catch(function () {
          abortStream();
        });
      }

      writeBody();
      return;
    }

    if (typeof response.arrayBuffer === "function" && !hasBodyStream) {
      response.arrayBuffer().then(function(ab) {
        respondWithBytes(new Uint8Array(ab));
      }).catch(function(err) {
        failResponse(requestId, HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error: " + (err && err.message || err));
      });
      return;
    }

    if (!hasBodyStream) {
      g.__exactHttpRespond(serverId, requestId, status, headersJson, null);
      return;
    }

    {
      var chunks = [];
      var totalSize = 0;
      var reader = body.getReader();
      function readBody() {
        return reader.read().then(function(result) {
          if (result.done) {
            var combined = new Uint8Array(totalSize);
            var offset = 0;
            for (var i = 0; i < chunks.length; i++) {
              var chunk = chunks[i];
              combined.set(chunk, offset);
              offset += chunk.length;
            }
            respondWithBytes(combined);
            return;
          }
          var chunk = result.value || new Uint8Array(0);
          totalSize += chunk.length;
          if (totalSize > MAX_RESPONSE_BODY_BYTES) {
            reader.cancel("response too large");
            throw new Error("Response Too Large");
          }
          chunks.push(chunk);
          return readBody();
        });
      }

      readBody().catch(function(err) {
        failResponse(requestId, HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error: " + (err && err.message || err));
      });
      return;
    }
  }

  // Start multiple concurrent waiters for better throughput
  waitForNextRequest();
  waitForNextRequest();
  waitForNextRequest();
  waitForNextRequest();

  var handle = {
    close: function(opts) {
      if (closed) return Promise.resolve();
      closed = true;
      waitCount = 0;
      var force = false;
      if (opts && opts.force) {
        force = !!opts.force;
      }
      g.__exactHttpClose(serverId, force ? 1 : 0);
      return Promise.resolve();
    },
    ref: function() {
      g.__exactHttpSetRef(serverId, 1);
    },
    unref: function() {
      g.__exactHttpSetRef(serverId, 0);
    },
    address: function() {
      var json = g.__exactHttpAddress(serverId);
      if (!json) return null;
      return JSON.parse(json);
    }
  };

  return Promise.resolve(handle);
}

export { serve };
