(function executeGlobalCallableInvocation(config) {
  "use strict";

  function valueShape(value) {
    if (value === null) return "null";
    if (Array.isArray(value)) return "array";
    return typeof value;
  }

  function primitiveValue(value, shape) {
    if (shape === "bigint") return String(value);
    if (
      shape === "boolean" ||
      shape === "number" ||
      shape === "string"
    ) {
      return value;
    }
    return null;
  }

  function returned(value) {
    var shape = valueShape(value);
    return {
      kind: "return",
      rawValueShape: shape,
      value: primitiveValue(value, shape),
      errorCode: null,
    };
  }

  function absent() {
    return {
      kind: "absent",
      rawValueShape: "absent",
      value: null,
      errorCode: null,
    };
  }

  function actualErrorCode(error) {
    return error && typeof error.code === "string" && error.code.length > 0
      ? error.code
      : null;
  }

  function thrown(error) {
    var out = {
      kind: "throw",
      rawValueShape: "throw",
      value: null,
      errorCode: actualErrorCode(error),
    };
    if (error && typeof error.name === "string" && error.name.length > 0) {
      out.errorName = error.name;
    }
    return out;
  }

  function exactKeys(value, expected, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new TypeError(label + " must be an object");
    }
    var actual = Object.keys(value).sort();
    var wanted = expected.slice().sort();
    if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
      throw new TypeError(
        label + " has keys [" + actual.join(",") + "] instead of [" +
          wanted.join(",") + "]",
      );
    }
  }

  function resolveGlobalPath(path) {
    if (path === "globalThis") return globalThis;
    var current = globalThis;
    var components = String(path).split(".");
    for (var index = 0; index < components.length; index++) {
      current = current[components[index]];
    }
    return current;
  }

  function symbolKey(token) {
    if (token === "[[Symbol.iterator]]") return Symbol.iterator;
    if (token === "[[Symbol.asyncIterator]]") return Symbol.asyncIterator;
    var symbolFor = /^\[\[Symbol\.for:(.*)\]\]$/.exec(token);
    if (symbolFor) return Symbol.for(symbolFor[1]);
    var symbolBinding = /^\[\[symbol-binding:(.*)\]\]$/.exec(token);
    if (symbolBinding) {
      if (symbolBinding[1] === "structuredCloneCloneSymbol") {
        return Symbol.for("exact.structuredClone.clone");
      }
      if (symbolBinding[1] === "structuredCloneTransferSymbol") {
        return Symbol.for("exact.structuredClone.transfer");
      }
    }
    throw new TypeError("unsupported source symbol token " + token);
  }

  function pathComponents(path) {
    var marker = path.indexOf("[[");
    if (marker < 0) return path.split(".");
    var prefix = path.slice(0, marker).replace(/\.$/, "");
    var token = path.slice(marker);
    return prefix ? prefix.split(".").concat([token]) : [token];
  }

  function propertyKey(component) {
    return component.indexOf("[[") === 0 ? symbolKey(component) : component;
  }

  function findDescriptor(owner, key) {
    var current = owner;
    while (current !== null && current !== undefined) {
      var descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor) {
        return { descriptor: descriptor, inherited: current !== owner };
      }
      current = Object.getPrototypeOf(current);
    }
    return null;
  }

  function descriptorProof(found) {
    if (!found) {
      return {
        presence: "absent",
        descriptorKind: "absent",
        valueType: "unread",
      };
    }
    var descriptor = found.descriptor;
    var data = Object.prototype.hasOwnProperty.call(descriptor, "value");
    return {
      presence: found.inherited ? "inherited" : "own",
      descriptorKind: data ? "data" : "accessor",
      valueType: data ? valueShape(descriptor.value) : "unread",
    };
  }

  function sourceMemberRoute(source) {
    if (source.memberName === null) {
      return {
        owner: globalThis,
        key: source.globalName,
        found: findDescriptor(globalThis, source.globalName),
      };
    }
    var current = resolveGlobalPath(source.globalName);
    var components = pathComponents(source.memberName);
    for (var index = 0; index + 1 < components.length; index++) {
      if (current === null || current === undefined) {
        return {
          owner: null,
          key: propertyKey(components[components.length - 1]),
          found: null,
        };
      }
      current = current[propertyKey(components[index])];
    }
    var key = propertyKey(components[components.length - 1]);
    return { owner: current, key: key, found: findDescriptor(current, key) };
  }

  function leafKey(memberName, globalName) {
    if (memberName === null) return globalName;
    var components = pathComponents(memberName);
    return propertyKey(components[components.length - 1]);
  }

  function materializeArgument(spec) {
    if (!spec || typeof spec !== "object" || Array.isArray(spec)) {
      throw new TypeError("argument descriptor must be an object");
    }
    var descriptorKeys = {
      "json": ["kind", "value"],
      "bigint": ["kind", "value"],
      "noop-function": ["kind"],
      "constant-function": ["kind", "value"],
      "uint8-array": ["kind", "bytes"],
      "buffer": ["kind", "bytes"],
      "buffer-array": ["kind", "values"],
      "array-buffer": ["kind", "byteLength"],
      "typed-array": ["kind", "globalName", "values"],
      "event": ["kind", "type"],
      "event-target": ["kind"],
      "abort-signal": ["kind"],
      "abort-signal-array": ["kind"],
      "blob": ["kind", "text", "type"],
      "resolved-promise": ["kind", "value"],
      "resolved-promise-record": ["kind"],
      "iterator": ["kind", "values"],
      "readable-stream": ["kind", "text"],
      "writable-stream": ["kind"],
      "transform-stream": ["kind"],
      "shared-int32-array": ["kind", "values"],
      "promise-executor": ["kind", "value"],
      "factory": ["kind", "factoryId", "options"],
      "existing-global": ["kind", "globalName"],
      "throwing-number-coercion": ["kind"],
    }[spec.kind];
    if (!descriptorKeys) {
      throw new TypeError("unsupported argument descriptor " + spec.kind);
    }
    exactKeys(spec, descriptorKeys, "argument descriptor " + spec.kind);
    switch (spec.kind) {
      case "json":
        return spec.value;
      case "bigint":
        return BigInt(spec.value);
      case "noop-function":
        return function () {};
      case "constant-function":
        return function () {
          return spec.value;
        };
      case "uint8-array":
        return new Uint8Array(spec.bytes);
      case "buffer":
        return Buffer.from(spec.bytes);
      case "buffer-array":
        return spec.values.map(function (bytes) {
          return Buffer.from(bytes);
        });
      case "array-buffer":
        return new ArrayBuffer(spec.byteLength);
      case "typed-array": {
        var TypedArray = resolveGlobalPath(spec.globalName);
        return new TypedArray(spec.values);
      }
      case "event":
        return new Event(spec.type);
      case "event-target":
        return new EventTarget();
      case "abort-signal":
        return new AbortController().signal;
      case "abort-signal-array":
        return [new AbortController().signal];
      case "blob":
        return new Blob([spec.text], { type: spec.type });
      case "resolved-promise":
        return Promise.resolve(spec.value);
      case "resolved-promise-record":
        return {
          promise: Promise.resolve(undefined),
          state: "fulfilled",
          resolve: function () {},
          reject: function () {},
        };
      case "iterator":
        return spec.values[Symbol.iterator]();
      case "readable-stream":
        return makeReadableStream({ format: "text", text: spec.text });
      case "writable-stream":
        return new WritableStream({
          write: function () {},
          close: function () {},
          abort: function () {},
        });
      case "transform-stream":
        return new TransformStream();
      case "shared-int32-array": {
        var storage = new SharedArrayBuffer(spec.values.length * 4);
        var view = new Int32Array(storage);
        view.set(spec.values);
        return view;
      }
      case "promise-executor":
        return function (resolve) {
          resolve(spec.value);
        };
      case "factory":
        return makeFactory(spec);
      case "existing-global":
        return resolveGlobalPath(spec.globalName);
      case "throwing-number-coercion":
        return {
          valueOf: function () {
            throw new TypeError("intentional numeric coercion refusal");
          },
          toString: function () {
            throw new TypeError("intentional numeric coercion refusal");
          },
        };
      default:
        throw new TypeError("unsupported argument descriptor " + spec.kind);
    }
  }

  function makeEventInstance(options) {
    var Constructor = resolveGlobalPath(options.globalName);
    var type = options.type;
    if (options.globalName === "PromiseRejectionEvent") {
      return new Constructor(type, {
        promise: Promise.resolve("ibex"),
        reason: null,
      });
    }
    if (options.globalName === "CustomEvent") {
      return new Constructor(type, { detail: "ibex" });
    }
    if (options.globalName === "MessageEvent") {
      return new Constructor(type, { data: "ibex" });
    }
    return new Constructor(type);
  }

  function makeBlobLike(options) {
    var text = "ibex";
    var type = "text/plain";
    if (options.format === "json") {
      text = '{"ibex":true}';
      type = "application/json";
    } else if (options.format === "form") {
      text = "field=value";
      type = "application/x-www-form-urlencoded";
    }
    if (options.globalName === "File") {
      return new File([text], "fixture.txt", { type: type, lastModified: 0 });
    }
    return new Blob([text], { type: type });
  }

  function makeBodyMessage(options) {
    var text = "ibex";
    var type = "text/plain";
    if (options.format === "json") {
      text = '{"ibex":true}';
      type = "application/json";
    } else if (options.format === "form") {
      text = "field=value";
      type = "application/x-www-form-urlencoded";
    }
    var init = { headers: { "content-type": type } };
    if (options.globalName === "Request") {
      init.method = "POST";
      // Keep the receiver body-backed without consulting string-body
      // compatibility settings. Typed-array bodies have no derived MIME type,
      // so the explicit owned header is the complete content-type source.
      init.body = new TextEncoder().encode(text);
      return new Request("https://example.com/ibex", init);
    }
    return new Response(text, init);
  }

  function makeReadableStream(options) {
    if (options.format === "empty") return new ReadableStream();
    var text = options.format === "json" ? '{"ibex":true}' : options.text || "ibex";
    return new ReadableStream({
      start: function (controller) {
        controller.enqueue(new TextEncoder().encode(text));
        controller.close();
      },
    });
  }

  function makeFactory(spec) {
    var options = spec.options || {};
    switch (spec.factoryId) {
      case "abort-signal":
        return new AbortController().signal;
      case "blob-like":
        return makeBlobLike(options);
      case "body-message":
        return makeBodyMessage(options);
      case "broadcast-channel":
        return new BroadcastChannel(options.name);
      case "buffer":
        return Buffer.from(options.bytes);
      case "clipboard-item":
        return new ClipboardItem({ "text/plain": new Blob(["ibex"], { type: "text/plain" }) });
      case "event-instance":
        return makeEventInstance(options);
      case "exact-crypto-hasher": {
        var ExactObject = resolveGlobalPath(options.globalName);
        var hasher = new ExactObject.CryptoHasher("sha256");
        if (options.update !== undefined) hasher.update(options.update);
        return hasher;
      }
      case "form-data": {
        var form = new FormData();
        options.entries.forEach(function (entry) {
          form.append(entry[0], entry[1]);
        });
        return form;
      }
      case "headers":
        return new Headers(options.entries);
      case "idb-key-range":
        return IDBKeyRange.only(1);
      case "iterator-helper":
        return Iterator.from(options.values[Symbol.iterator]());
      case "isolated-prototype": {
        var isolatedSource = resolveGlobalPath(options.globalName);
        var isolatedPrototype = typeof isolatedSource === "function"
          ? isolatedSource.prototype
          : Object.getPrototypeOf(isolatedSource);
        if (!isolatedPrototype ||
            (typeof isolatedPrototype !== "object" && typeof isolatedPrototype !== "function")) {
          throw new TypeError("isolated receiver source has no object prototype");
        }
        return Object.create(isolatedPrototype);
      }
      case "storage-prototype": {
        // The public storage globals are lazy proxies whose methods are bound
        // to singleton state. Construct an ephemeral session Storage only to
        // recover its public prototype, then omit the private fields so every
        // exact method reaches its deterministic brand refusal before a
        // capability check or storage operation.
        var StorageConstructor = resolveGlobalPath("sessionStorage").constructor;
        var storageSample = Reflect.construct(StorageConstructor, [false]);
        return Object.create(Object.getPrototypeOf(storageSample));
      }
      case "media-query-list":
        return matchMedia(options.query);
      case "message-port": {
        var channel = new MessageChannel();
        Object.defineProperty(channel.port1, "__ibexCompanionPort", {
          value: channel.port2,
          configurable: true,
        });
        return channel.port1;
      }
      case "performance-mark":
        return performance.mark(options.name);
      case "performance-measure":
        return performance.measure(options.name, { start: 0, end: 1 });
      case "performance-observer":
        return new PerformanceObserver(function () {});
      case "readable-byob-reader": {
        var byobStream = new ReadableStream({
          type: "bytes",
          start: function (controller) {
            if (options.closed) controller.close();
          },
        });
        return byobStream.getReader({ mode: "byob" });
      }
      case "readable-byte-controller": {
        var byteController;
        new ReadableStream({
          type: "bytes",
          start: function (controller) {
            byteController = controller;
          },
        });
        return byteController;
      }
      case "readable-default-controller": {
        var readableController;
        new ReadableStream({
          start: function (controller) {
            readableController = controller;
          },
        });
        return readableController;
      }
      case "readable-default-reader": {
        var defaultStream = new ReadableStream({
          start: function (controller) {
            if (options.closed) controller.close();
          },
        });
        return defaultStream.getReader();
      }
      case "readable-stream":
        return makeReadableStream(options);
      case "resolved-promise":
        return Promise.resolve(options.value);
      case "transform-controller": {
        var transformController;
        new TransformStream({
          start: function (controller) {
            transformController = controller;
          },
        });
        return transformController;
      }
      case "transform-stream-backpressure": {
        var transform = new TransformStream();
        // Enter the production writable-side backpressure path synchronously.
        // Its exact sink closure installs _backpressureResolve before returning
        // the pending promise, without consuming any external resource.
        var setup = transform._writable._writeAlgorithm(
          "ibex-capsec",
          transform._writable._controller,
        );
        if (setup && typeof setup.catch === "function") {
          setup.catch(function () {});
        }
        return transform;
      }
      case "typed-array": {
        var TypedArray = resolveGlobalPath(options.globalName);
        return new TypedArray(options.length);
      }
      case "url":
        return new URL(options.value);
      case "url-search-params":
        return new URLSearchParams(options.value);
      case "writable-controller": {
        var writableController;
        new WritableStream({
          start: function (controller) {
            writableController = controller;
          },
        });
        return writableController;
      }
      case "writable-stream":
        return new WritableStream({
          write: function () {},
          close: function () {},
          abort: function () {},
        });
      case "writable-writer":
        var writer = new WritableStream({
          write: function () {},
          close: function () {},
          abort: function () {},
        }).getWriter();
        writer.closed.catch(function () {});
        writer.ready.catch(function () {});
        return writer;
      default:
        throw new TypeError("unsupported receiver factory " + spec.factoryId);
    }
  }

  function makeReceiver(spec) {
    if (!spec || typeof spec !== "object" || Array.isArray(spec)) {
      throw new TypeError("receiver descriptor must be an object");
    }
    var receiverKeys = {
      "source-member-owner": ["kind"],
      "existing-global": ["kind", "globalName"],
      "construct-global": ["kind", "globalName", "arguments"],
      "factory": ["kind", "factoryId", "options"],
    }[spec.kind];
    if (!receiverKeys) {
      throw new TypeError("unsupported receiver descriptor " + spec.kind);
    }
    exactKeys(spec, receiverKeys, "receiver descriptor " + spec.kind);
    switch (spec.kind) {
      case "source-member-owner":
        return null;
      case "existing-global":
        return resolveGlobalPath(spec.globalName);
      case "construct-global": {
        var Constructor = resolveGlobalPath(spec.globalName);
        return Reflect.construct(
          Constructor,
          spec.arguments.map(materializeArgument),
        );
      }
      case "factory":
        return makeFactory(spec);
      default:
        throw new TypeError("unsupported receiver descriptor " + spec.kind);
    }
  }

  function targetRoute(source, route, receiver) {
    if (route.receiver.kind === "source-member-owner") {
      return sourceMemberRoute(source);
    }
    var key = leafKey(source.memberName, source.globalName);
    return { owner: receiver, key: key, found: findDescriptor(receiver, key) };
  }

  function prepareCleanup(route) {
    if (!route.cleanup) return null;
    if (route.cleanup.kind === "restore-memory-debug-sources") {
      return {
        debugSourcesDescriptor: Object.getOwnPropertyDescriptor(
          globalThis,
          "__exactDebugModuleSources",
        ),
        debugSources: Array.isArray(globalThis.__exactDebugModuleSources)
          ? globalThis.__exactDebugModuleSources.slice()
          : null,
        debugSourceDescriptor: Object.getOwnPropertyDescriptor(
          globalThis,
          "__exactDebugModuleSource",
        ),
      };
    }
    return null;
  }

  function restoreProperty(name, descriptor) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete globalThis[name];
  }

  function cleanup(route, receiver, arguments_, result, state) {
    if (!route.cleanup) return { performed: true, error: null };
    try {
      switch (route.cleanup.kind) {
        case "invoke-returned-function":
          if (typeof result !== "function") {
            throw new TypeError("source call did not return its cleanup function");
          }
          result();
          break;
        case "remove-global-event-listener":
          globalThis.removeEventListener(
            route.cleanup.type,
            arguments_[route.cleanup.listenerArgument],
          );
          break;
        case "revoke-returned-object-url":
          URL.revokeObjectURL(result);
          break;
        case "clear-performance-mark":
          performance.clearMarks(route.cleanup.name);
          break;
        case "clear-performance-measure":
          performance.clearMeasures(route.cleanup.name);
          break;
        case "disconnect-receiver":
          receiver.disconnect();
          break;
        case "close-receiver":
          receiver.close();
          break;
        case "close-message-port-pair":
          receiver.close();
          receiver.__ibexCompanionPort.close();
          break;
        case "remove-receiver-listener":
          receiver.removeListener(
            route.cleanup.type,
            arguments_[route.cleanup.listenerArgument],
          );
          break;
        case "stop-memory-debug":
          globalThis.__exactMemoryDebug.stop();
          break;
        case "restore-memory-debug-sources":
          restoreProperty(
            "__exactDebugModuleSources",
            state.debugSourcesDescriptor,
          );
          if (state.debugSources && Array.isArray(globalThis.__exactDebugModuleSources)) {
            globalThis.__exactDebugModuleSources.length = 0;
            Array.prototype.push.apply(
              globalThis.__exactDebugModuleSources,
              state.debugSources,
            );
          }
          restoreProperty(
            "__exactDebugModuleSource",
            state.debugSourceDescriptor,
          );
          break;
        default:
          throw new TypeError("unsupported cleanup descriptor " + route.cleanup.kind);
      }
      return { performed: true, error: null };
    } catch (error) {
      return { performed: false, error: actualErrorCode(error) };
    }
  }

  var sourceOperationAttempted = false;
  var proof = {
    presence: "absent",
    descriptorKind: "absent",
    valueType: "unread",
  };
  var receiver = null;
  var arguments_ = [];
  var result;
  var raw;
  var cleanupResult = { performed: false, error: null };
  var cleanupState = null;

  try {
    exactKeys(
      config,
      [
        "completion",
        "coverageClassification",
        "coverageEdgeId",
        "invocationSchema",
        "kind",
        "route",
        "sourceDescriptor",
        "sourceDescriptorDigest",
      ],
      "global callable invocation",
    );
    if (config.invocationSchema !== "ibex/capsec-global-callable-invocation/1") {
      throw new TypeError("unsupported global callable invocation schema");
    }
    if (config.kind !== "global-callable-invocation") {
      throw new TypeError("unsupported global callable invocation kind");
    }
    if (config.route.operation === "unexercisable") {
      return {
        kind: "unexercisable",
        reasonCode: config.route.reasonCode,
        sourceOperationAttempted: false,
        descriptorProof: proof,
        cleanupPerformed: false,
        cleanupError: null,
        rawOutput: null,
      };
    }
    receiver = makeReceiver(config.route.receiver);
    arguments_ = config.route.arguments.map(materializeArgument);
    cleanupState = prepareCleanup(config.route);
    var target = targetRoute(config.sourceDescriptor, config.route, receiver);
    proof = descriptorProof(target.found);
    if (config.route.operation === "get") {
      sourceOperationAttempted = true;
      if (!target.found) {
        raw = absent();
      } else {
        result = target.owner[target.key];
        raw = returned(result);
      }
      return {
        kind: raw.kind,
        sourceOperationAttempted: sourceOperationAttempted,
        descriptorProof: proof,
        cleanupPerformed: true,
        cleanupError: null,
        rawOutput: raw,
      };
    }
    if (!target.found) throw new TypeError("loaded source callable is absent");
    var callable = target.owner[target.key];
    if (typeof callable !== "function") {
      throw new TypeError("loaded source member is not callable");
    }
    sourceOperationAttempted = true;
    if (config.route.operation === "construct") {
      result = Reflect.construct(callable, arguments_);
    } else if (config.route.operation === "call") {
      var thisValue =
        config.route.receiver.kind === "source-member-owner"
          ? target.owner
          : receiver;
      result = Reflect.apply(callable, thisValue, arguments_);
    } else {
      throw new TypeError("unsupported callable operation " + config.route.operation);
    }
    raw = returned(result);
    if (
      config.route.suppressRejection === true &&
      result &&
      typeof result.catch === "function"
    ) {
      result.catch(function () {});
    }
  } catch (error) {
    raw = thrown(error);
  } finally {
    cleanupResult = cleanup(
      config.route || {},
      receiver,
      arguments_,
      result,
      cleanupState,
    );
  }

  return {
    kind: raw.kind,
    sourceOperationAttempted: sourceOperationAttempted,
    descriptorProof: proof,
    cleanupPerformed: cleanupResult.performed,
    cleanupError: cleanupResult.error,
    rawOutput: raw,
  };
})
