(function runGlobalAccessorGet(config) {
  "use strict";

  var sourceOperationAttempted = false;
  var descriptorProof = null;
  var factoryCleanup = null;

  function valueShape(value) {
    if (value === null) return "null";
    if (Array.isArray(value)) return "array";
    return typeof value;
  }

  // Primitive output is retained exactly. Compound output is shape-only so
  // capture never invokes user getters, proxy enumeration, toJSON, or String.
  function rawReturn(value) {
    var shape = valueShape(value);
    var encoded = null;
    if (
      shape === "null" ||
      shape === "boolean" ||
      shape === "number" ||
      shape === "string"
    ) {
      encoded = value;
    } else if (shape === "bigint") {
      encoded = String(value);
    } else if (shape === "array") {
      encoded = [];
    }
    return {
      kind: "return",
      rawValueShape: shape,
      value: encoded,
      errorCode: null,
    };
  }

  function rawThrow(error) {
    var out = {
      kind: "throw",
      rawValueShape: "throw",
      value: null,
      errorCode:
        error && typeof error.code === "string" && error.code.length > 0
          ? error.code
          : null,
    };
    if (error && typeof error.name === "string" && error.name.length > 0) {
      out.errorName = error.name;
    }
    return out;
  }

  function cleanupFactoryReceiver() {
    if (typeof factoryCleanup !== "function") return;
    var cleanup = factoryCleanup;
    factoryCleanup = null;
    try { cleanup(); } catch (_) {}
  }

  function result(kind, extra) {
    var out = { kind: kind };
    if (extra) {
      for (var key in extra) {
        if (Object.prototype.hasOwnProperty.call(extra, key)) {
          out[key] = extra[key];
        }
      }
    }
    return out;
  }

  function propertyKey(component) {
    if (component === "[[Symbol.toStringTag]]") return Symbol.toStringTag;
    return component;
  }

  function memberComponents(memberName) {
    if (memberName === "[[Symbol.toStringTag]]") return [memberName];
    return memberName.split(".");
  }

  function leafRoute(receiver, memberName) {
    var components = memberComponents(memberName);
    var owner = receiver;
    for (var index = 0; index + 1 < components.length; index++) {
      owner = Reflect.get(owner, propertyKey(components[index]), owner);
      if (owner === null || owner === undefined) {
        throw new TypeError("global accessor receiver path is absent");
      }
    }
    return {
      owner: owner,
      key: propertyKey(components[components.length - 1]),
    };
  }

  function findDescriptor(receiver, key) {
    var current = receiver;
    while (current !== null && current !== undefined) {
      var descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor) {
        return {
          descriptor: descriptor,
          inherited: current !== receiver,
        };
      }
      current = Object.getPrototypeOf(current);
    }
    return null;
  }

  function factoryReceiver(factoryId) {
    var receiver;
    if (factoryId === "abort-signal") {
      return new AbortController().signal;
    }
    if (factoryId === "buffer") {
      return Buffer.from("ibex");
    }
    if (factoryId === "clipboard-item") {
      return new ClipboardItem({
        "text/plain": new Blob(["ibex"], { type: "text/plain" }),
      });
    }
    if (factoryId === "media-query-list") {
      return matchMedia("(min-width: 0px)");
    }
    if (factoryId === "intl-locale") {
      return new Intl.Locale("en-US");
    }
    if (factoryId === "inert-event-source") {
      var fetchDescriptor = Object.getOwnPropertyDescriptor(globalThis, "fetch");
      var inertFetch = function () {
        var error = new Error("output-shape EventSource transport disabled");
        error.code = "ERR_IBEX_OUTPUT_FIXTURE_TRANSPORT_DISABLED";
        return Promise.reject(error);
      };
      if (fetchDescriptor && fetchDescriptor.configurable === false) {
        if (!Object.prototype.hasOwnProperty.call(fetchDescriptor, "value") ||
            fetchDescriptor.writable !== true) {
          throw new TypeError("global fetch cannot be isolated for EventSource");
        }
        globalThis.fetch = inertFetch;
      } else {
        Object.defineProperty(globalThis, "fetch", {
          value: inertFetch,
          writable: true,
          enumerable: fetchDescriptor ? fetchDescriptor.enumerable : true,
          configurable: true,
        });
      }
      try {
        var eventSource = new EventSource("https://example.invalid/ibex");
        eventSource.close();
        return eventSource;
      } finally {
        if (fetchDescriptor) {
          Object.defineProperty(globalThis, "fetch", fetchDescriptor);
        } else {
          delete globalThis.fetch;
        }
      }
    }
    if (factoryId === "promise-rejection-event") {
      return new PromiseRejectionEvent("unhandledrejection", {
        promise: Promise.resolve(undefined),
        reason: null,
      });
    }
    if (factoryId === "readable-byte-controller") {
      new ReadableStream({
        type: "bytes",
        start: function (controller) { receiver = controller; },
      });
      return receiver;
    }
    if (factoryId === "readable-byob-reader") {
      return new ReadableStream({ type: "bytes" }).getReader({ mode: "byob" });
    }
    if (factoryId === "readable-byob-request") {
      var byteController;
      var byteStream = new ReadableStream({
        type: "bytes",
        start: function (controller) { byteController = controller; },
      });
      var byobReader = byteStream.getReader({ mode: "byob" });
      var pendingRead = byobReader.read(new Uint8Array(1));
      if (pendingRead && typeof pendingRead.catch === "function") {
        pendingRead.catch(function () {});
      }
      var byobRequest = byteController && byteController.byobRequest;
      if (!byobRequest) {
        throw new TypeError("BYOB request factory produced no request");
      }
      factoryCleanup = function () {
        try { byobRequest.respond(1); } catch (_) {}
        try { byteController.close(); } catch (_) {}
        if (pendingRead && typeof pendingRead.then === "function") {
          pendingRead.then(function () {
            try { byobReader.releaseLock(); } catch (_) {}
          }, function () {});
        }
      };
      return byobRequest;
    }
    if (factoryId === "readable-default-controller") {
      new ReadableStream({
        start: function (controller) { receiver = controller; },
      });
      return receiver;
    }
    if (factoryId === "readable-default-reader") {
      return new ReadableStream().getReader();
    }
    if (factoryId === "transform-controller") {
      new TransformStream({
        start: function (controller) { receiver = controller; },
      });
      return receiver;
    }
    if (factoryId === "writable-controller") {
      new WritableStream({
        start: function (controller) { receiver = controller; },
      });
      return receiver;
    }
    if (factoryId === "writable-writer") {
      return new WritableStream().getWriter();
    }
    if (factoryId === "aborted-websocket-stream") {
      var abortController = new AbortController();
      abortController.abort();
      var webSocketStream = new WebSocketStream(
        "wss://example.invalid/ibex",
        { signal: abortController.signal },
      );
      if (webSocketStream.opened && typeof webSocketStream.opened.catch === "function") {
        webSocketStream.opened.catch(function () {});
      }
      if (webSocketStream.closed && typeof webSocketStream.closed.catch === "function") {
        webSocketStream.closed.catch(function () {});
      }
      return webSocketStream;
    }
    throw new TypeError("unknown global accessor receiver factory");
  }

  function receiverFor(source, recipe) {
    if (recipe.kind === "existing-global") {
      return globalThis[recipe.receiverGlobalName];
    }
    if (recipe.kind === "construct-global") {
      var constructor = globalThis[source.globalName];
      if (typeof constructor !== "function") {
        throw new TypeError("global accessor constructor is unavailable");
      }
      return Reflect.construct(constructor, recipe.arguments);
    }
    if (recipe.kind === "global-prototype") {
      var prototypeConstructor = globalThis[source.globalName];
      if (
        typeof prototypeConstructor !== "function" ||
        prototypeConstructor.prototype === null ||
        prototypeConstructor.prototype === undefined
      ) {
        throw new TypeError("global accessor prototype is unavailable");
      }
      return prototypeConstructor.prototype;
    }
    if (recipe.kind === "factory") {
      return factoryReceiver(recipe.factoryId);
    }
    throw new TypeError("unsupported global accessor receiver recipe");
  }

  function receiverMemberName(source, recipe) {
    if (recipe.kind !== "factory" || recipe.factoryId !== "intl-locale") {
      return source.memberName;
    }
    if (source.memberName.indexOf("Locale.prototype.") === 0) {
      return source.memberName.slice("Locale.prototype.".length);
    }
    if (source.memberName.indexOf("Locale.") === 0) {
      return source.memberName.slice("Locale.".length);
    }
    throw new TypeError("Intl.Locale accessor route has an invalid member path");
  }

  try {
    var source = config.sourceDescriptor;
    var route;
    if (config.receiver.kind === "global-root") {
      route = { owner: globalThis, key: source.globalName };
    } else {
      var receiver = receiverFor(source, config.receiver);
      if (receiver === null || receiver === undefined) {
        return result("setup-failed", {
          sourceOperationAttempted: false,
          reasonCode: "receiver-unavailable",
        });
      }
      route = leafRoute(receiver, receiverMemberName(source, config.receiver));
    }

    var found = findDescriptor(route.owner, route.key);
    descriptorProof = found
      ? {
          presence: found.inherited ? "inherited" : "own",
          descriptorKind: Object.prototype.hasOwnProperty.call(
            found.descriptor,
            "value",
          ) ? "data" : "accessor",
        }
      : { presence: "absent", descriptorKind: "absent" };
    if (!found) {
      return result("setup-failed", {
        sourceOperationAttempted: false,
        reasonCode: "source-property-absent",
        descriptorProof: descriptorProof,
      });
    }

    sourceOperationAttempted = true;
    var value = Reflect.get(route.owner, route.key, route.owner);
    var rawOutput = rawReturn(value);
    cleanupFactoryReceiver();
    return result("return", {
      sourceOperationAttempted: true,
      descriptorProof: descriptorProof,
      rawOutput: rawOutput,
    });
  } catch (error) {
    cleanupFactoryReceiver();
    if (sourceOperationAttempted) {
      return result("throw", {
        sourceOperationAttempted: true,
        descriptorProof: descriptorProof,
        rawOutput: rawThrow(error),
      });
    }
    return result("setup-failed", {
      sourceOperationAttempted: false,
      reasonCode: "receiver-setup-threw",
    });
  }
})
