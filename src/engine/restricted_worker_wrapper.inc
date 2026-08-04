R"IBEXJS(
(function(authored, nativeEmit, settlementCodec) {
  "use strict";
  var runId = null;
  var sequence = 1;
  var nextCallId = 1;
  var nextSubscriptionId = 1;
  var nextTimerId = 1;
  var started = false;
  var terminal = false;
  var pendingCalls = Object.create(null);
  var subscriptions = Object.create(null);
  var brokerErrors = new WeakMap();
  var timers = Object.create(null);
  var timerHandles = [];
  var abortListeners = [];
  var signalState = { aborted: false, reason: void 0 };

  function canonical(value) {
    var seen = [];
    function encode(current, depth) {
      if (depth > 64) throw new TypeError("strict value exceeds depth");
      if (current === null) return "null";
      var kind = typeof current;
      if (kind === "boolean" || kind === "string") return JSON.stringify(current);
      if (kind === "number") {
        if (!Number.isFinite(current) || Object.is(current, -0)) throw new TypeError("invalid strict number");
        return JSON.stringify(current);
      }
      if (kind !== "object") throw new TypeError("unsupported strict value");
      if (seen.indexOf(current) !== -1) throw new TypeError("cyclic strict value");
      seen.push(current);
      var output;
      if (Array.isArray(current)) {
        var arrayDescriptors = Object.getOwnPropertyDescriptors(current);
        var arrayKeys = Object.keys(arrayDescriptors).filter(function(key) { return key !== "length"; });
        if (arrayKeys.length !== current.length || arrayKeys.some(function(key, index) { return key !== String(index); })) throw new TypeError("sparse or decorated strict array");
        arrayKeys.forEach(function(key) {
          var descriptor = arrayDescriptors[key];
          if (!descriptor.enumerable || !("value" in descriptor)) throw new TypeError("strict array accessor");
        });
        output = "[" + current.map(function(item) { return encode(item, depth + 1); }).join(",") + "]";
      } else {
        var prototype = Object.getPrototypeOf(current);
        if (prototype !== null && prototype !== Object.prototype) throw new TypeError("custom strict prototype");
        var descriptors = Object.getOwnPropertyDescriptors(current);
        var keys = Object.keys(descriptors).sort();
        output = "{" + keys.map(function(key) {
          var descriptor = descriptors[key];
          if (!descriptor.enumerable || !("value" in descriptor)) throw new TypeError("strict accessor");
          return JSON.stringify(key) + ":" + encode(descriptor.value, depth + 1);
        }).join(",") + "}";
      }
      seen.pop();
      return output;
    }
    return encode(value, 0);
  }

  function emit(type, body) {
    if (terminal && type !== "console") return;
    nativeEmit(canonical({ body: body, runId: runId, schema: "ibex/restricted-worker-broker/1", sequence: sequence++, type: type }));
  }

  function brokerError(error) {
    var value = new Error(error && error.code ? error.code : "SNAPBACK_APP_CLI_BROKER");
    brokerErrors.set(value, error);
    return value;
  }

  function invoke(functionId, args, timeoutMs) {
    if (terminal) return Promise.reject(new Error("worker is terminating"));
    var callId = String(nextCallId++);
    return new Promise(function(resolve, reject) {
      pendingCalls[callId] = { resolve: resolve, reject: reject };
      emit("call", { args: args, callId: callId, functionId: functionId, timeoutMs: timeoutMs });
    });
  }

  function liveInvoke(functionId, args, timeoutMs) {
    if (terminal) throw new Error("worker is terminating");
    var subscriptionId = String(nextSubscriptionId++);
    var row = { opened: false, closed: false, queued: [], waiters: [] };
    subscriptions[subscriptionId] = row;
    emit("liveOpen", { args: args === void 0 ? {} : args, functionId: functionId, subscriptionId: subscriptionId, timeoutMs: timeoutMs });
    function settleNext() {
      if (row.queued.length && row.waiters.length) row.waiters.shift().resolve({ done: false, value: row.queued.shift() });
      if (row.closed) while (row.waiters.length) row.waiters.shift().resolve({ done: true, value: void 0 });
    }
    var iterator = Object.create(null);
    Object.defineProperties(iterator, {
      next: { enumerable: true, value: function() {
        if (row.queued.length) return Promise.resolve({ done: false, value: row.queued.shift() });
        if (row.closed) return Promise.resolve({ done: true, value: void 0 });
        return new Promise(function(resolve, reject) { row.waiters.push({ resolve: resolve, reject: reject }); });
      } },
      return: { enumerable: true, value: function() {
        if (!row.closed) { row.closed = true; emit("liveClose", { subscriptionId: subscriptionId }); settleNext(); }
        return Promise.resolve({ done: true, value: void 0 });
      } },
      [Symbol.asyncIterator]: { value: function() { return iterator; } }
    });
    return Object.freeze(iterator);
  }

  function makeSurface(rows, timeoutMs) {
    var api = Object.create(null);
    var byId = Object.create(null);
    rows.forEach(function(row) {
      var call = row.kind === "live-query"
        ? function(args) { return liveInvoke(row.id, args === void 0 ? {} : args, timeoutMs); }
        : function(args) { return invoke(row.id, args === void 0 ? {} : args, timeoutMs); };
      byId[row.id] = call;
      if (row.alias !== null) Object.defineProperty(api, row.alias, { value: call, enumerable: true });
    });
    Object.freeze(api);
    var snapback = Object.create(null);
    Object.defineProperty(snapback, "function", { value: function(id) {
      if (!Object.prototype.hasOwnProperty.call(byId, id)) throw new TypeError("unknown function id");
      return byId[id];
    }, enumerable: true });
    return { api: api, snapback: Object.freeze(snapback) };
  }

  function makeConsole() {
    var value = Object.create(null);
    ["log", "info", "warn", "error", "debug"].forEach(function(level) {
      value[level] = function() { emit("console", { level: level, values: Array.prototype.slice.call(arguments) }); };
    });
    return Object.freeze(value);
  }

  function setTimer(callback, delayMs) {
    if (terminal || typeof callback !== "function" || arguments.length !== 2 || !Number.isInteger(delayMs) || delayMs < 0 || delayMs > 1800000) throw new TypeError("invalid timer");
    var timerId = String(nextTimerId++);
    var handle = Object.freeze(Object.create(null));
    timers[timerId] = { callback: callback, handle: handle };
    timerHandles.push({ handle: handle, timerId: timerId });
    emit("timerSet", { delayMs: delayMs, timerId: timerId });
    return handle;
  }

  function clearTimer(handle) {
    if (!handle || typeof handle !== "object") return;
    var index = timerHandles.findIndex(function(row) { return row.handle === handle; });
    if (index < 0) return;
    var timerId = timerHandles[index].timerId;
    timerHandles.splice(index, 1);
    delete timers[timerId];
    emit("timerClear", { timerId: timerId });
  }

  var signal = Object.freeze(Object.defineProperties(Object.create(null), {
    aborted: { enumerable: true, get: function() { return signalState.aborted; } },
    reason: { enumerable: true, get: function() { return signalState.reason; } },
    addEventListener: { enumerable: true, value: function(type, callback) {
      if (type === "abort" && typeof callback === "function" && abortListeners.indexOf(callback) === -1) abortListeners.push(callback);
    } },
    removeEventListener: { enumerable: true, value: function(type, callback) {
      if (type === "abort") abortListeners = abortListeners.filter(function(value) { return value !== callback; });
    } }
  }));

  function settle(value, present, limits) {
    if (!present) {
      emit("settlementBegin", { byteLength: 0, chunkCount: 0, digest: "", hasValue: false });
      emit("settlementEnd", {});
      terminal = true;
      return;
    }
    var encoded = canonical(value);
    var codec = settlementCodec(encoded, Math.floor((limits.frameBytes - 1024) * 3 / 4), limits.resultBytes);
    emit("settlementBegin", { byteLength: codec.byteLength, chunkCount: codec.chunks.length, digest: codec.digest, hasValue: true });
    codec.chunks.forEach(function(data, index) { emit("settlementChunk", { data: data, index: index }); });
    emit("settlementEnd", {});
    terminal = true;
  }

  function fail(error) {
    var branded = error && (typeof error === "object" || typeof error === "function") ? brokerErrors.get(error) : void 0;
    emit("failed", branded ? { error: branded, kind: "broker" } : { code: "SNAPBACK_APP_CLI_SCRIPT_ERROR", kind: "script" });
    terminal = true;
  }

  return function(frameText) {
    var frame = JSON.parse(frameText);
    if (canonical(frame) !== frameText) throw new Error("non-canonical parent frame");
    var body = frame.body;
    if (frame.type === "start") {
      if (started) throw new Error("duplicate start");
      started = true;
      runId = frame.runId;
      var surface = makeSurface(body.surface.functions, body.limits.callEstablishmentMs);
      Promise.resolve(authored(surface.api, surface.snapback, Object.freeze(body.args.slice()), signal, makeConsole(), setTimer, clearTimer))
        .then(function(result) { settle(result.value, result.present, body.limits); }, fail);
      return;
    }
    if (frame.type === "callResult") {
      var call = pendingCalls[body.callId];
      if (!call) throw new Error("unknown call result");
      delete pendingCalls[body.callId];
      if (body.ok) call.resolve(body.value); else call.reject(brokerError(body.error));
    } else if (frame.type === "liveOpened") {
      var opened = subscriptions[body.subscriptionId];
      if (!opened || opened.opened || opened.closed) throw new Error("unknown live establishment");
      if (body.ok) opened.opened = true;
      else {
        opened.closed = true;
        var openError = brokerError(body.error);
        while (opened.waiters.length) opened.waiters.shift().reject(openError);
      }
    } else if (frame.type === "liveValue") {
      var live = subscriptions[body.subscriptionId];
      if (!live || !live.opened || live.closed) throw new Error("unknown live value");
      live.queued.length = 0;
      live.queued.push(body.value);
      if (live.waiters.length) live.waiters.shift().resolve({ done: false, value: live.queued.shift() });
    } else if (frame.type === "liveTerminal") {
      var failedLive = subscriptions[body.subscriptionId];
      if (!failedLive || failedLive.closed) throw new Error("unknown live terminal");
      failedLive.closed = true;
      var liveError = brokerError(body.error);
      while (failedLive.waiters.length) failedLive.waiters.shift().reject(liveError);
    } else if (frame.type === "liveClosed") {
      var closedLive = subscriptions[body.subscriptionId];
      if (!closedLive) throw new Error("unknown live close");
      closedLive.closed = true;
      while (closedLive.waiters.length) closedLive.waiters.shift().resolve({ done: true, value: void 0 });
      delete subscriptions[body.subscriptionId];
    } else if (frame.type === "timerFired") {
      var timer = timers[body.timerId];
      if (timer) { delete timers[body.timerId]; timerHandles = timerHandles.filter(function(row) { return row.timerId !== body.timerId; }); Promise.resolve().then(timer.callback).catch(fail); }
    } else if (frame.type === "abort") {
      if (!signalState.aborted) {
        signalState.aborted = true;
        signalState.reason = body.reason;
        abortListeners.slice().forEach(function(callback) { try { callback.call(signal); } catch (error) { Promise.reject(error); } });
      }
    }
  };
})
)IBEXJS"
