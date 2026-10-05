// Fixture adapted from Snapback 2 at cec3ffda794b47d00afdd9f27e1c41efa07c1e75.
// The implementation is unchanged; only its private accessor source is the
// opt-in object instead of temporary __ibex2_* globals.
// Adapted from expo/ibex at revision 9cbf9e62d6434b4e3f4d49eddacb337218d256a3:
// crates/ibex2/src/bindings/fetch.js. Snapback follows redirects through the
// grant-bound raw binding one hop at a time so a denial retains the attempted
// hop's origin instead of being mislabeled with the initial request, and it
// reads a body to its end in one go: effects get text, json, and arrayBuffer,
// not the upstream reader surface.
// fetch and Response.
//
// A response crosses the boundary as an integer handle into a runtime-wide
// table. The accessors are captured from the opt-in primitive object; trusted
// bootstrap deletes that object's temporary global before hardening. The
// handle lives in a WeakMap behind a Response object, and the only way to get
// a Response is the fetch a module was handed. The handle is never observable
// and cannot be forged.
//
// This script's VALUE is the fetch factory. It defines no global: the engine
// side stores the completion value and calls it once per grant set, so a
// module never sees a function that would wrap an integer of its choosing.
(function (primitives, global) {
  "use strict";

  var field = primitives.responseField;
  var readBody = primitives.responseRead;
  var control = primitives.fetchControl;
  var decode = primitives.textDecode;
  var Headers = global.Headers;
  var freeHeaders = primitives.headersFree;
  // Pure helpers nothing outside the bindings needs: the engine provides
  // TextEncoder and TextDecoder itself.

  var handles = new WeakMap(); // Response -> { handle, used, empty, released, track, status, ok, url, redirected, headers }

  function own(response) {
    var r = handles.get(response);
    if (!r) throw new TypeError("not a Response");
    return r;
  }

  function Response() {
    throw new TypeError("Response is not constructible; it comes from fetch");
  }

  // Forget the record on the Rust side, aborting its native request if the
  // body is still open. Every record is released exactly once — after its
  // body is read, when it has no body, or when a redirect hop is left behind
  // — and a bodiless hop meets two of those, so the record remembers.
  function release(r) {
    if (r.released) return;
    r.released = true;
    field(r.handle, 8);
  }

  // The metadata is read once here, because the record is released when the
  // body has been read — and the web keeps status, url, and headers readable
  // after the body is gone. The headers become a real Headers. A HEAD, 204,
  // 205, or 304 response has no body to read, so its record goes at once.
  function response(handle, redirected, method, track, logicalUrl) {
    var r = Object.create(Response.prototype);
    var status = field(handle, 0);
    var empty = method === "HEAD" || status === 204 || status === 205 || status === 304;
    var record = {
      handle: handle,
      used: false,
      empty: empty,
      released: false,
      track: track,
      status: status,
      ok: field(handle, 1),
      url: logicalUrl === undefined ? field(handle, 2) : logicalUrl,
      redirected: redirected === undefined ? field(handle, 5) : redirected,
      headers: new Headers(JSON.parse(field(handle, 7))),
    };
    handles.set(r, record);
    if (empty) release(record);
    return r;
  }

  function define(name, get) {
    Object.defineProperty(Response.prototype, name, { get: get, enumerable: true, configurable: true });
  }
  define("status", function () { return own(this).status; });
  define("ok", function () { return own(this).ok; });
  define("url", function () { return own(this).url; });
  define("redirected", function () { return own(this).redirected; });
  define("bodyUsed", function () { return own(this).used; });
  define("headers", function () { return own(this).headers; });

  // The body streams from the engine one native read at a time until EOF
  // (null); the chunks are joined and the record released. The reads are the
  // job's in-flight network I/O, so the host counts them with its fetches.
  function consume(response) {
    var r = own(response);
    if (r.used) return Promise.reject(new TypeError("body already consumed"));
    r.used = true;
    if (r.empty) return Promise.resolve(new ArrayBuffer(0));
    var chunks = [];
    var length = 0;
    function next() {
      // A read that throws, synchronously or not, rejects here, so the count
      // below always comes back down and the record is always released.
      return new Promise(function (resolve) { resolve(readBody(r.handle)); }).then(function (bytes) {
        if (bytes !== null) {
          var chunk = new Uint8Array(bytes);
          chunks.push(chunk);
          length += chunk.byteLength;
          return next();
        }
        var joined = new Uint8Array(length);
        var offset = 0;
        for (var i = 0; i < chunks.length; i++) {
          joined.set(chunks[i], offset);
          offset += chunks[i].byteLength;
        }
        return joined.buffer;
      });
    }
    r.track(1);
    return next().then(
      function (bytes) { r.track(-1); release(r); return bytes; },
      function (error) { r.track(-1); release(r); throw error; }
    );
  }
  Response.prototype.arrayBuffer = function () { return consume(this); };
  Response.prototype.text = function () {
    return consume(this).then(function (bytes) { return decode(bytes); });
  };
  Response.prototype.json = function () {
    return this.text().then(function (text) { return JSON.parse(text); });
  };
  Object.defineProperty(Response.prototype, Symbol.toStringTag, { value: "Response", configurable: true });
  Object.freeze(Response.prototype);

  function copyInit(init) {
    // Snapshot enumerable own keys only; this is not full Web IDL dictionary conversion.
    var copy = {};
    if (init !== undefined && init !== null) {
      var names = Object.keys(Object(init));
      for (var i = 0; i < names.length; i++) copy[names[i]] = init[names[i]];
    }
    return copy;
  }

  function isRedirect(status) {
    return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
  }

  function methodOf(init) {
    return init.method === undefined ? "GET" : String(init.method).toUpperCase();
  }

  function invokeRaw(raw, url, init, redirectMode, tagRawError) {
    var headers;
    var token;
    try {
      var method = init.method !== undefined ? String(init.method) : "";
      var body = init.body;
      var target = String(url);
      headers = new Headers(init.headers);
      if (typeof body === "string") {
        if (!headers.has("content-type")) headers.set("content-type", "text/plain;charset=UTF-8");
        body = new TextEncoder().encode(body);
      }
      // Lowercase pairs survive redirects independently of the caller's record,
      // iterable, or Headers. The fifth raw argument is Ibex's validated handle;
      // the sixth is a control token, which is what lets the engine abort a
      // request still waiting for headers when the runtime is destroyed. It
      // is released once the request settles; the response record carries the
      // body's own control from there.
      init.headers = Array.from(headers);
      token = control(0);
      return raw(target, method, body, redirectMode, headers._handle, token).then(
        function (handle) { freeHeaders(headers._handle); control(2, token); return handle; },
        function (error) { freeHeaders(headers._handle); control(2, token); throw tagRawError(error, target); }
      );
    } catch (error) {
      if (headers) freeHeaders(headers._handle);
      if (token !== undefined) control(2, token);
      return Promise.reject(error);
    }
  }

  function dropHeaders(init, names) {
    init.headers = init.headers.filter(function (pair) { return names.indexOf(pair[0]) === -1; });
  }

  // The factory. `raw` is the engine's async binding for one grant set; it
  // resolves to a handle, and this is the only place a handle becomes an
  // object. `track` is the host's count of the job's in-flight network I/O.
  // Default redirect following is kept on this side of the binding so each
  // denied hop remains attributable without widening Ibex's capability.
  return function makeFetch(raw, tagRawError, track, bound) {
    function logicalUrl(input) {
      if (!bound) return undefined;
      var url = new URL(String(input));
      url.hash = "";
      return url.toString();
    }
    return function fetch(input, init) {
      var currentInit = copyInit(init);
      var redirectMode = currentInit.redirect !== undefined ? String(currentInit.redirect) : "follow";
      // Ibex treats unknown modes as follow; never let that bypass our hop rules.
      if (redirectMode !== "follow" && redirectMode !== "manual" && redirectMode !== "error") {
        return Promise.reject(new TypeError("Invalid redirect mode"));
      }
      if (redirectMode !== "follow") {
        var requestedUrl = String(input);
        return invokeRaw(raw, requestedUrl, currentInit, redirectMode, tagRawError)
          .then(function (handle) { return response(handle, undefined, methodOf(currentInit), track, logicalUrl(requestedUrl)); });
      }

      var currentUrl = String(input);
      currentInit.redirect = "manual";
      var redirects = 0;

      function next() {
        return invokeRaw(raw, currentUrl, currentInit, "manual", tagRawError).then(function (handle) {
          var method = methodOf(currentInit);
          var value = response(handle, redirects > 0, method, track, logicalUrl(currentUrl));
          if (!isRedirect(value.status)) return value;
          var location = value.headers.get("location");
          if (location === null) return value;
          // The hop's body is never read; let its record go before the next hop.
          release(own(value));
          redirects++;
          if (redirects > 20) throw new TypeError("TypeError: Failed to fetch — too many redirects");

          if ((value.status === 303 && method !== "GET" && method !== "HEAD") ||
              ((value.status === 301 || value.status === 302) && method === "POST")) {
            currentInit.method = "GET";
            delete currentInit.body;
            dropHeaders(currentInit, ["content-type", "content-length", "content-encoding", "content-language", "content-location"]);
          }
          var nextUrl = new URL(String(location), currentUrl);
          if (nextUrl.origin !== new URL(currentUrl).origin) {
            dropHeaders(currentInit, ["authorization", "proxy-authorization", "cookie"]);
          }
          currentUrl = nextUrl.toString();
          return next();
        });
      }

      return next();
    };
  };
})(globalThis.__snapback_ibex2_fetch_primitives, globalThis);
