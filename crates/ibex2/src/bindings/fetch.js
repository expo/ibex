// fetch and Response.
//
// A response crosses the boundary as an integer handle into a runtime-wide
// table, and the accessor that reads a handle's fields was a GLOBAL — so any
// module could read any other module's in-flight response by guessing small
// integers, granted or not. The accessor is captured here and removed from
// the global object; the handle lives in a WeakMap behind a Response object;
// and the only way to get a Response is the fetch a module was handed. The
// handle is never observable and cannot be forged.
//
// This script's VALUE is the fetch factory. It defines no global: the engine
// side stores the completion value and calls it once per grant set, so a
// module never sees a function that would wrap an integer of its choosing.
(function (global) {
  "use strict";

  var field = global.__ibex2_response_field;
  var decode = global.__ibex2_text_decode;
  var Headers = global.Headers;
  var freeHeaders = global.__ibex2_headers_free;
  delete global.__ibex2_headers_free;
  delete global.__ibex2_response_field;
  // Pure helpers nothing outside the bindings needs: the engine provides
  // TextEncoder and TextDecoder itself.
  delete global.__ibex2_text_encode;
  delete global.__ibex2_text_decode;
  delete global.__ibex2_text_encode_into;

  var handles = new WeakMap(); // Response -> { handle, used, status, ok, url, redirected, headers }

  function own(response) {
    var r = handles.get(response);
    if (!r) throw new TypeError("not a Response");
    return r;
  }

  function Response() {
    throw new TypeError("Response is not constructible; it comes from fetch");
  }

  // The metadata is read once here, because consuming the body releases the
  // record on the Rust side — and the web keeps status, url, and headers
  // readable after the body is gone. The headers become a real Headers.
  function response(handle) {
    var r = Object.create(Response.prototype);
    handles.set(r, {
      handle: handle,
      used: false,
      status: field(handle, 0),
      ok: field(handle, 1),
      url: field(handle, 2),
      redirected: field(handle, 5),
      headers: new Headers(JSON.parse(field(handle, 7))),
    });
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

  function consume(response) {
    var r = own(response);
    if (r.used) return Promise.reject(new TypeError("body already consumed"));
    r.used = true;
    try {
      return Promise.resolve(field(r.handle, 4));
    } catch (e) {
      return Promise.reject(e);
    }
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

  // The factory. `raw` is the engine's async binding for one grant set; it
  // resolves to a handle, and this is the only place a handle becomes an
  // object.
  return function makeFetch(raw) {
    return function fetch(input, init) {
      try {
        if (arguments.length === 0) throw new TypeError("fetch expects a URL");
        init = init || {};
        var url = String(input);
        var method = init.method === undefined ? "" : String(init.method);
        var body = init.body;
        if (typeof body === "string") body = new TextEncoder().encode(body);
        var redirect = init.redirect === undefined ? "follow" : String(init.redirect);
        // @ref LLP 0059.000#35-fetch--delegating-capability-bearing — snapshot before crossing; release our list after settlement
        var headers = new Headers(init.headers);
        return raw(url, method, body, redirect, headers._handle).then(function (handle) {
          freeHeaders(headers._handle);
          return response(handle);
        }, function (e) {
          freeHeaders(headers._handle);
          throw e;
        });
      } catch (e) {
        if (headers) freeHeaders(headers._handle);
        return Promise.reject(e);
      }
    };
  };
})(globalThis);
