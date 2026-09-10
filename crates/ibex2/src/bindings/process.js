// Installable process object shape. Rust owns every OS operation and limit.
// @ref LLP 0068#21-native-processes-and-ptys — explicit installation after first pixel
(function (raw) {
  "use strict";
  function text(value) {
    if (typeof value !== "string") throw new TypeError("process arguments must be strings");
    return value;
  }
  function shape(command, size) {
    if (!command || typeof command !== "object" || !Array.isArray(command.args) ||
        !command.env || typeof command.env !== "object" || Array.isArray(command.env))
      throw new TypeError("process needs executable, args, cwd, and env");
    var keys = Object.keys(command.env);
    if (command.args.length > 256 || keys.length > 256) throw new RangeError("process argv/env limit");
    var args = [size ? 1 : 0, size ? size.rows : 0, size ? size.cols : 0,
      text(command.executable), text(command.cwd), command.args.length];
    for (var i = 0; i < command.args.length; i++) args.push(text(command.args[i]));
    args.push(keys.length);
    for (i = 0; i < keys.length; i++) args.push(keys[i], text(command.env[keys[i]]));
    return args;
  }
  function status(value) {
    if (value === undefined) return undefined; // cancellation during launch
    return Object.freeze({ code: value >= 0 ? value : null,
      signal: value < 0 ? -value : null, success: value === 0 });
  }
  function open(command, size, signal) {
    var request, stop, release = function () {}, stopped = false;
    function invoke(method, args) {
      try { return raw[method].apply(undefined, [request].concat(args || [])); }
      catch (error) { return Promise.reject(error); }
    }
    function cancel() {
      if (!stop) {
        stopped = true;
        stop = invoke("cancel").then(status);
        // Listener hooks are caller code. Reentry must see the same cancel.
        release();
      }
      return stop;
    }
    function wait() { return invoke("wait").then(function (value) { release(); return status(value); }); }
    function reader(method) {
      return Object.freeze({ read: Object.freeze(function (size) {
        return invoke(method, [size === undefined ? 65536 : size]).then(function (bytes) {
          return bytes === null ? null : new Uint8Array(bytes);
        });
      }) });
    }
    function writer(halfClose) {
      var out = { write: Object.freeze(function (bytes) {
        if (!(bytes instanceof ArrayBuffer) && !(bytes instanceof Uint8Array))
          return Promise.reject(new TypeError("process write needs ArrayBuffer or Uint8Array"));
        return invoke("write", [bytes]);
      }) };
      if (halfClose) out.close = Object.freeze(function () { return invoke("closeInput"); });
      return Object.freeze(out);
    }
    try {
      if (signal !== undefined && (!signal || typeof signal.aborted !== "boolean" ||
          typeof signal.addEventListener !== "function" || typeof signal.removeEventListener !== "function"))
        throw new TypeError("invalid process abort signal");
      if (signal && signal.aborted) return Promise.reject(signal.reason);
      request = raw.prepare.apply(undefined, shape(command, size));
      if (signal) {
        var onabort = function () { cancel().catch(function () {}); };
        release = function () {
          release = function () {};
          try { signal.removeEventListener("abort", onabort); } catch (_) {}
        };
        signal.addEventListener("abort", onabort, { once: true });
        if (signal.aborted) onabort();
      }
    } catch (error) {
      if (!request) return Promise.reject(error);
      // Registration may retain onabort and then throw. Close the prepared
      // owner before rejecting, even when removing that callback also throws.
      return cancel().catch(function () {}).then(function () { throw error; });
    }
    return invoke("launch").then(function (pid) {
      if (stopped || (signal && signal.aborted)) {
        return cancel().then(function () { throw signal ? signal.reason : new Error("process cancelled"); });
      }
      var child = { pid: pid, wait: Object.freeze(wait), cancel: Object.freeze(cancel), close: Object.freeze(cancel) };
      if (size) {
        child.input = writer(false); child.output = reader("stdout");
        child.resize = Object.freeze(function (size) {
          if (!size || typeof size !== "object") return Promise.reject(new TypeError("PTY size required"));
          return invoke("resize", [size.rows, size.cols]);
        });
      } else {
        child.stdin = writer(true); child.stdout = reader("stdout"); child.stderr = reader("stderr");
      }
      return Object.freeze(child);
    }, function (error) {
      return cancel().catch(function () {}).then(function () { throw signal && signal.aborted ? signal.reason : error; });
    });
  }
  return Object.freeze({
    spawn: Object.freeze(function (command, signal) { return open(command, null, signal); }),
    pty: Object.freeze(function (command, size, signal) {
      if (!size || typeof size !== "object") return Promise.reject(new TypeError("PTY size required"));
      return open(command, size, signal);
    })
  });
});
