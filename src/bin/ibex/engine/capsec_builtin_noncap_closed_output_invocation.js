(function runBuiltinNoncapClosedOutputInvocation(config, inheritedHarness) {
  "use strict";

  var own = Object.prototype.hasOwnProperty;
  var sourceOperationAttempted = false;
  var cleanupPerformed = false;
  var cleanupContext = { callbacks: [] };
  var completionToken = null;

  function rawReturn(value) {
    var shape =
      value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
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

  function rawAbsent() {
    return {
      kind: "absent",
      rawValueShape: "absent",
      value: null,
      errorCode: null,
    };
  }

  function rawThrow(error) {
    var code = error && error.code;
    return {
      kind: "throw",
      rawValueShape: "throw",
      value: null,
      errorCode: typeof code === "string" ? code : null,
      errorName: String((error && error.name) || "Error"),
    };
  }

  function failure(kind, extra) {
    var result = {
      kind: kind,
      moduleSpecifier: config.moduleSpecifier,
      surfaceObservedKey: config.surfaceObservedKey,
      sourceOperationAttempted: sourceOperationAttempted,
      cleanupPerformed: cleanupPerformed,
    };
    if (extra) {
      var keys = Object.keys(extra);
      for (var index = 0; index < keys.length; index++) {
        result[keys[index]] = extra[keys[index]];
      }
    }
    return result;
  }

  function inheritedInvocation() {
    var route = config.route;
    var operation = route.operation;
    var legacy = {
      kind:
        operation === "get" ? "builtin-export-read" : "builtin-export-call",
      moduleSpecifier: config.moduleSpecifier,
      exportName: config.sourceDescriptor.exportName,
      sourceDescriptor: config.sourceDescriptor,
      sourceDescriptorDigest: config.sourceDescriptorDigest,
      arguments: route.arguments,
      setup:
        operation === "construct"
          ? { kind: "construct-target" }
          : operation === "get"
            ? { kind: "none" }
            : route.receiver,
      captureRawOutput: true,
    };
    var inherited = inheritedHarness(legacy);
    if (
      inherited.sourceOperationAttempted === true &&
      inherited.rawOutput &&
      inherited.rawOutput.kind === "return" &&
      (route.cleanup.kind === "none" ||
        route.cleanup.kind === "receiver-default")
    ) {
      inherited.cleanupPerformed = true;
    }
    return inherited;
  }

  function descriptorAt(moduleValue, descriptor) {
    var access = descriptor.access;
    if (access.kind === "module-value") {
      return {
        holder: null,
        propertyDescriptor: {
          value: moduleValue,
          writable: null,
          enumerable: null,
          configurable: null,
        },
        value: moduleValue,
        descriptorKind: "module-value",
      };
    }

    var value = moduleValue;
    for (var index = 0; index < access.path.length; index++) {
      var key = access.path[index];
      var last = index === access.path.length - 1;

      // string_decoder is itself the default constructor. The source
      // inventory deliberately names that module-value owner `default`.
      if (
        index === 0 &&
        key === "default" &&
        (descriptor.sourceKey === "node_string_decoder" ||
          descriptor.sourceKey === "node_stream") &&
        typeof value === "function" &&
        !own.call(value, key)
      ) {
        continue;
      }
      if (
        value === null ||
        (typeof value !== "object" && typeof value !== "function")
      ) {
        throw new TypeError("source descriptor crossed a non-object segment");
      }
      var holder = value;
      if (last && access.kind === "inherited-prototype-property") {
        if (own.call(holder, key)) {
          throw new TypeError("source descriptor expected an inherited member");
        }
        holder = Object.getPrototypeOf(holder);
        while (holder && !own.call(holder, key)) {
          holder = Object.getPrototypeOf(holder);
        }
        if (!holder) throw new TypeError("source inherited member is absent");
      } else if (!own.call(holder, key)) {
        throw new TypeError("source own member is absent");
      }
      var propertyDescriptor = Object.getOwnPropertyDescriptor(holder, key);
      if (!propertyDescriptor) throw new TypeError("source descriptor is absent");
      if (last) {
        if (
          descriptor.valueShape === "accessor" &&
          typeof propertyDescriptor.get !== "function"
        ) {
          throw new TypeError("source member is not the inventoried accessor");
        }
        if (
          descriptor.valueShape === "callable" &&
          (typeof propertyDescriptor.value !== "function" ||
            propertyDescriptor.get !== undefined)
        ) {
          throw new TypeError("source member is not the inventoried callable");
        }
        return {
          holder: holder,
          propertyDescriptor: propertyDescriptor,
          value: propertyDescriptor.value,
          descriptorKind:
            typeof propertyDescriptor.get === "function" ? "accessor" : "data",
        };
      }
      value = propertyDescriptor.value;
    }
    throw new TypeError("source descriptor has an empty access path");
  }

  function addCleanup(callback) {
    cleanupContext.callbacks.push(callback);
  }

  function beginCompletion() {
    if (completionToken !== null) {
      throw new TypeError("one invocation cannot own two completion records");
    }
    completionToken = "builtin-output:" + config.coverageEdgeId;
    if (
      !globalThis.__ibexBuiltinOutputAsyncCompletions ||
      typeof globalThis.__ibexBuiltinOutputAsyncCompletions !== "object"
    ) {
      globalThis.__ibexBuiltinOutputAsyncCompletions = Object.create(null);
    }
    delete globalThis.__ibexBuiltinOutputAsyncCompletions[completionToken];
  }

  function cleanupCompletionReceivers(bindings) {
    var receivers = [];
    if (bindings.completionCleanupReceiver) {
      receivers.push(bindings.completionCleanupReceiver);
    }
    if (Array.isArray(bindings.completionCleanupReceivers)) {
      for (var index = 0; index < bindings.completionCleanupReceivers.length; index++) {
        receivers.push(bindings.completionCleanupReceivers[index]);
      }
    }
    for (var receiverIndex = 0; receiverIndex < receivers.length; receiverIndex++) {
      var receiver = receivers[receiverIndex];
      if (receiver && typeof receiver.destroy === "function") receiver.destroy();
      if (receiver && typeof receiver._closeNativeStream === "function") {
        receiver._closeNativeStream();
      }
      if (receiver && typeof receiver.removeAllListeners === "function") {
        receiver.removeAllListeners();
      }
    }
    return receivers.length > 0;
  }

  function trackReturnedPromise(result, bindings) {
    if (!result || typeof result.then !== "function") {
      throw new TypeError("awaited stream route did not return a promise");
    }
    beginCompletion();
    Promise.resolve(result).then(
      function () {
        globalThis.__ibexBuiltinOutputAsyncCompletions[completionToken] = {
          calls: 1,
          error: false,
          cleanupPerformed: cleanupCompletionReceivers(bindings),
        };
      },
      function () {
        globalThis.__ibexBuiltinOutputAsyncCompletions[completionToken] = {
          calls: 1,
          error: true,
          cleanupPerformed: cleanupCompletionReceivers(bindings),
        };
      },
    );
  }

  function diagnosticsHandlers() {
    return {
      start: function () {},
      end: function () {},
      asyncStart: function () {},
      asyncEnd: function () {},
      error: function () {},
    };
  }

  function diagnosticsChannelMap(moduleValue) {
    return {
      start: Reflect.construct(moduleValue.Channel, ["ibex:start"]),
      end: Reflect.construct(moduleValue.Channel, ["ibex:end"]),
      asyncStart: Reflect.construct(moduleValue.Channel, ["ibex:asyncStart"]),
      asyncEnd: Reflect.construct(moduleValue.Channel, ["ibex:asyncEnd"]),
      error: Reflect.construct(moduleValue.Channel, ["ibex:error"]),
    };
  }

  function clearDiagnosticsOwner(value) {
    if (!value) return;
    var channels = value.start
      ? [value.start, value.end, value.asyncStart, value.asyncEnd, value.error]
      : [value];
    for (var index = 0; index < channels.length; index++) {
      var channel = channels[index];
      if (!channel) continue;
      channel._subscribers = [];
      channel._hasSubscribers = false;
    }
  }

  function disposeDomain(domain) {
    if (!domain) return;
    var members = Array.isArray(domain.members) ? domain.members.slice() : [];
    for (var index = 0; index < members.length; index++) {
      if (members[index] && members[index].domain === domain) {
        members[index].domain = null;
      }
    }
    if (typeof domain.dispose === "function") domain.dispose();
    if (typeof domain.removeAllListeners === "function") {
      domain.removeAllListeners();
    }
  }

  function bufferOwner(moduleValue) {
    var BufferOwner = moduleValue.Buffer || globalThis.Buffer;
    if (!BufferOwner || typeof BufferOwner.from !== "function") {
      throw new TypeError("crypto fixture requires Buffer");
    }
    return BufferOwner;
  }

  function cryptoKeyPair(moduleValue, bindings, type) {
    if (!bindings.cryptoKeyPairs) bindings.cryptoKeyPairs = {};
    if (own.call(bindings.cryptoKeyPairs, type)) {
      return bindings.cryptoKeyPairs[type];
    }
    var options;
    if (type === "rsa") {
      options = {
        modulusLength: 1024,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      };
    } else if (type === "ec-key-object") {
      options = { namedCurve: "prime256v1" };
      type = "ec";
    } else if (type === "ec") {
      options = {
        namedCurve: "prime256v1",
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      };
    } else {
      options = {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      };
    }
    var pair = moduleValue.generateKeyPairSync(type, options);
    bindings.cryptoKeyPairs[type] = pair;
    return pair;
  }

  function materialize(argument, moduleValue, bindings) {
    if (!argument || typeof argument.kind !== "string") {
      throw new TypeError("invalid authored argument");
    }
    if (argument.kind === "json") return argument.value;
    if (argument.kind === "noop-function") return function () {};
    if (argument.kind === "buffer") {
      var BufferOwner = moduleValue.Buffer || globalThis.Buffer;
      return BufferOwner.from(argument.bytes);
    }
    if (argument.kind === "uint8-array") {
      return new Uint8Array(argument.bytes);
    }
    if (argument.kind === "bigint") return BigInt(argument.value);
    if (argument.kind === "blob") return new Blob([argument.text]);
    if (argument.kind === "resolved-promise") {
      return Promise.resolve(argument.value);
    }
    if (argument.kind === "rejected-promise") {
      return Promise.reject(new Error(argument.message));
    }
    if (argument.kind === "event-emitter") {
      var EventEmitter = moduleValue.EventEmitter || moduleValue;
      return Reflect.construct(EventEmitter, []);
    }
    if (argument.kind === "setup-value") {
      if (!own.call(bindings, argument.name)) {
        throw new TypeError("missing setup value");
      }
      return bindings[argument.name];
    }
    if (argument.kind === "empty-class") return function EmptyFixture() {};
    if (argument.kind === "constant-function") {
      return function () {
        return argument.value;
      };
    }
    if (argument.kind === "reducer-function") {
      return function (accumulator, value) {
        return String(accumulator) + String(value);
      };
    }
    if (argument.kind === "stream-instance") {
      return createStreamFixture(argument, moduleValue, bindings);
    }
    if (argument.kind === "web-readable-stream") {
      var readableSource = argument.bytes ? { type: "bytes" } : {};
      if (argument.closed) {
        readableSource.start = function (controller) {
          controller.close();
        };
      }
      var readableStream = Reflect.construct(moduleValue.ReadableStream, [
        readableSource,
      ]);
      bindings.webReadableStream = readableStream;
      return readableStream;
    }
    if (argument.kind === "web-writable-stream") {
      var writableStream = Reflect.construct(moduleValue.WritableStream, []);
      bindings.webWritableStream = writableStream;
      return writableStream;
    }
    if (argument.kind === "console-writable-sink") {
      return {
        write: function () {
          return true;
        },
      };
    }
    if (argument.kind === "zlib-input") {
      if (argument.ownerExportName === "Inflate") {
        return moduleValue.deflateSync("ibex-output-shape");
      }
      if (argument.ownerExportName === "Gunzip") {
        return moduleValue.gzipSync("ibex-output-shape");
      }
      if (argument.ownerExportName === "InflateRaw") {
        return moduleValue.deflateRawSync("ibex-output-shape");
      }
      if (argument.ownerExportName === "Unzip") {
        return moduleValue.gzipSync("ibex-output-shape");
      }
      if (argument.ownerExportName === "BrotliDecompress") {
        return moduleValue.brotliCompressSync("ibex-output-shape");
      }
      return "ibex-output-shape";
    }
    if (argument.kind === "diagnostics-channel-map") {
      return diagnosticsChannelMap(moduleValue);
    }
    if (argument.kind === "diagnostics-handlers") {
      return diagnosticsHandlers();
    }
    if (argument.kind === "completion-callback") {
      beginCompletion();
      return function (error) {
        var prior = globalThis.__ibexBuiltinOutputAsyncCompletions[completionToken];
        var receiverCleanupPerformed = argument.cleanupReceiver !== true;
        if (argument.cleanupReceiver === true) {
          receiverCleanupPerformed = cleanupCompletionReceivers(bindings);
        }
        globalThis.__ibexBuiltinOutputAsyncCompletions[completionToken] = {
          calls: prior && typeof prior.calls === "number" ? prior.calls + 1 : 1,
          error:
            argument.errorFirst === true &&
            error !== null &&
            error !== undefined,
          cleanupPerformed: receiverCleanupPerformed,
        };
      };
    }
    if (argument.kind === "crypto-secret-key") {
      return moduleValue.createSecretKey(
        bufferOwner(moduleValue).from(argument.bytes),
      );
    }
    if (argument.kind === "crypto-x509-certificate") {
      return Reflect.construct(moduleValue.X509Certificate, [
        "ibex-output-shape-certificate",
      ]);
    }
    if (argument.kind === "legacy-timer-record") {
      var legacyTimerRecord = {
        _idleTimeout: -1,
        _onTimeout: function () {},
      };
      addCleanup(function () {
        if (typeof moduleValue.unenroll === "function") {
          moduleValue.unenroll(legacyTimerRecord);
        }
      });
      return legacyTimerRecord;
    }
    if (argument.kind === "crypto-key-pair-member") {
      var pair = cryptoKeyPair(moduleValue, bindings, argument.type);
      return argument.role === "private" ? pair.privateKey : pair.publicKey;
    }
    if (argument.kind === "crypto-rsa-ciphertext") {
      var rsaPair = cryptoKeyPair(moduleValue, bindings, "rsa");
      return moduleValue.publicEncrypt(
        rsaPair.publicKey,
        bufferOwner(moduleValue).from(argument.bytes),
      );
    }
    if (argument.kind === "crypto-hmac-signature") {
      return moduleValue.sign(
        "sha256",
        bufferOwner(moduleValue).from(argument.data),
        argument.key,
      );
    }
    if (argument.kind === "crypto-peer-public-key") {
      if (!own.call(bindings, "cryptoPeerPublicKey")) {
        throw new TypeError("crypto receiver did not create a peer key");
      }
      return bindings.cryptoPeerPublicKey;
    }
    if (argument.kind === "crypto-diffie-hellman-options") {
      var ecPair = cryptoKeyPair(moduleValue, bindings, "ec-key-object");
      return { privateKey: ecPair.privateKey, publicKey: ecPair.publicKey };
    }
    throw new TypeError("unknown authored argument kind " + argument.kind);
  }

  function materializeList(arguments_, moduleValue, bindings) {
    var values = [];
    for (var index = 0; index < arguments_.length; index++) {
      values.push(materialize(arguments_[index], moduleValue, bindings));
    }
    return values;
  }

  function ownerFromModule(moduleValue, ownerExportName) {
    if (ownerExportName === "default") return moduleValue.default || moduleValue;
    return moduleValue[ownerExportName];
  }

  function createStreamFixture(recipe, moduleValue, bindings) {
    var streamModule = moduleValue;
    var owner =
      recipe.ownerExportName === "default"
        ? streamModule
        : streamModule[recipe.ownerExportName];
    if (typeof owner !== "function") {
      streamModule = require("node:stream");
      owner =
        recipe.ownerExportName === "default"
          ? streamModule
          : streamModule[recipe.ownerExportName];
    }
    if (typeof owner !== "function") {
      throw new TypeError("missing authored stream owner");
    }
    var options = {};
    if (recipe.ownerExportName === "Readable" || recipe.ownerExportName === "Duplex") {
      options.read = function () {};
    }
    if (recipe.ownerExportName === "Writable" || recipe.ownerExportName === "Duplex") {
      options.write = function (chunk, encoding, callback) {
        callback();
      };
    }
    if (recipe.ownerExportName === "Transform") {
      options.transform = function (chunk, encoding, callback) {
        callback(null, chunk);
      };
    }
    var constructorArguments =
      recipe.ownerExportName === "Stream" || recipe.ownerExportName === "default"
        ? []
        : [options];
    var instance = Reflect.construct(owner, constructorArguments);
    if (recipe.swallowError && typeof instance.on === "function") {
      instance.on("error", function () {});
    }
    if (recipe.ended && typeof instance.push === "function") {
      instance.push(
        recipe.content === undefined ? "ibex-output-shape" : recipe.content,
      );
      instance.push(null);
    }
    if (recipe.endAfterOperation && typeof instance.push === "function") {
      if (!Array.isArray(bindings.postOperationCallbacks)) {
        bindings.postOperationCallbacks = [];
      }
      bindings.postOperationCallbacks.push(function () {
        instance.push(
          recipe.content === undefined ? "ibex-output-shape" : recipe.content,
        );
        instance.push(null);
        if (typeof instance.resume === "function") instance.resume();
      });
    }
    if (recipe.deferredCleanup) {
      if (!Array.isArray(bindings.completionCleanupReceivers)) {
        bindings.completionCleanupReceivers = [];
      }
      bindings.completionCleanupReceivers.push(instance);
    } else {
      addCleanup(function () {
        if (typeof instance.destroy === "function") instance.destroy();
        if (typeof instance.removeAllListeners === "function") {
          instance.removeAllListeners();
        }
      });
    }
    return instance;
  }

  function createReceiver(recipe, moduleValue, bindings) {
    if (recipe.kind === "module-value") return moduleValue;
    if (recipe.kind === "plain-object") return {};
    if (recipe.kind === "stream-module-watermark") {
      var priorByteWatermark = moduleValue.getDefaultHighWaterMark(false);
      var priorObjectWatermark = moduleValue.getDefaultHighWaterMark(true);
      addCleanup(function () {
        moduleValue.setDefaultHighWaterMark(false, priorByteWatermark);
        moduleValue.setDefaultHighWaterMark(true, priorObjectWatermark);
      });
      return moduleValue;
    }
    if (recipe.kind === "stream-owner") {
      return createStreamFixture(recipe, moduleValue, bindings);
    }
    if (recipe.kind === "fs-stream-owner") {
      var FsStreamOwner = moduleValue[recipe.ownerExportName];
      if (typeof FsStreamOwner !== "function") {
        throw new TypeError("missing authored filesystem stream owner");
      }
      var fakeFs = {
        open: function (_path, _flags, _mode, callback) {
          callback(null, recipe.ownerExportName === "ReadStream" ? 0 : 1);
        },
        close: function (_fd, callback) {
          callback(null);
        },
        read: function (_fd, buffer, _offset, _length, _position, callback) {
          callback(null, 0, buffer);
        },
        write: function (
          _fd,
          buffer,
          _offset,
          length,
          _position,
          callback,
        ) {
          callback(null, length, buffer);
        },
        writev: function (_fd, buffers, _position, callback) {
          callback(null, 0, buffers);
        },
      };
      var fsStream = Reflect.construct(FsStreamOwner, [
        null,
        {
          fd: recipe.ownerExportName === "ReadStream" ? 0 : 1,
          autoClose: false,
          emitClose: false,
          fs: fakeFs,
        },
      ]);
      addCleanup(function () {
        if (typeof fsStream.destroy === "function") fsStream.destroy();
        if (typeof fsStream.removeAllListeners === "function") {
          fsStream.removeAllListeners();
        }
      });
      return fsStream;
    }
    if (recipe.kind === "fs-file-handle") {
      var fileHandle = Reflect.construct(moduleValue.FileHandle, [
        null,
        "/project/ibex-output-shape",
        "r",
      ]);
      addCleanup(function () {
        if (typeof fileHandle.close === "function") {
          Promise.resolve(fileHandle.close()).catch(function () {});
        }
      });
      return fileHandle;
    }
    if (recipe.kind === "fs-dir") {
      var dir = Object.create(moduleValue.Dir.prototype);
      dir._path = "/project/ibex-output-shape";
      dir._entries = [];
      dir._index = 0;
      dir._closed = false;
      dir._closing = false;
      dir._asyncReads = 0;
      dir._closeCallbacks = [];
      if (!recipe.sourceCloses) {
        addCleanup(function () {
          if (!dir._closed && typeof dir.closeSync === "function") {
            dir.closeSync();
          }
        });
      }
      return dir;
    }
    if (recipe.kind === "zlib-output-owner") {
      var ZlibOwner = moduleValue[recipe.ownerExportName];
      if (typeof ZlibOwner !== "function") {
        throw new TypeError("missing authored zlib owner");
      }
      var zlibReceiver = Reflect.construct(ZlibOwner, []);
      if (recipe.deferredCleanup) {
        if (!Array.isArray(bindings.completionCleanupReceivers)) {
          bindings.completionCleanupReceivers = [];
        }
        bindings.completionCleanupReceivers.push(zlibReceiver);
      } else {
        addCleanup(function () {
          if (typeof zlibReceiver.destroy === "function") zlibReceiver.destroy();
          if (typeof zlibReceiver._closeNativeStream === "function") {
            zlibReceiver._closeNativeStream();
          }
          if (typeof zlibReceiver.removeAllListeners === "function") {
            zlibReceiver.removeAllListeners();
          }
        });
      }
      return zlibReceiver;
    }
    if (recipe.kind === "async-local-storage") {
      var asyncStorage = Reflect.construct(moduleValue.AsyncLocalStorage, []);
      addCleanup(function () {
        asyncStorage.disable();
      });
      return asyncStorage;
    }
    if (recipe.kind === "async-resource") {
      var resource = Reflect.construct(moduleValue.AsyncResource, [
        "ibex-output-shape",
      ]);
      addCleanup(function () {
        resource.emitDestroy();
      });
      return resource;
    }
    if (recipe.kind === "diagnostics-channel") {
      var channel = Reflect.construct(moduleValue.Channel, [
        "ibex-output-shape",
      ]);
      if (recipe.withListener) {
        var diagnosticsListener = function () {};
        channel.subscribe(diagnosticsListener);
        bindings.diagnosticsListener = diagnosticsListener;
      }
      addCleanup(function () {
        clearDiagnosticsOwner(channel);
      });
      return channel;
    }
    if (recipe.kind === "diagnostics-tracing-channel") {
      var tracing = Reflect.construct(moduleValue.TracingChannel, [
        diagnosticsChannelMap(moduleValue),
      ]);
      if (recipe.withHandlers) {
        var handlers = diagnosticsHandlers();
        tracing.subscribe(handlers);
        bindings.diagnosticsHandlers = handlers;
      }
      addCleanup(function () {
        clearDiagnosticsOwner(tracing);
      });
      return tracing;
    }
    if (recipe.kind === "domain-owner") {
      var domain = Reflect.construct(moduleValue.Domain, []);
      var domainMember = {};
      bindings.domainMember = domainMember;
      if (recipe.withMember) domain.add(domainMember);
      addCleanup(function () {
        disposeDomain(domain);
        if (domainMember.domain === domain) domainMember.domain = null;
      });
      return domain;
    }
    if (recipe.kind === "crypto-module-fips") {
      var priorFips = moduleValue.getFips();
      addCleanup(function () {
        moduleValue.setFips(priorFips);
      });
      return moduleValue;
    }
    if (recipe.kind === "buffer-owner") {
      var BufferOwner = moduleValue.Buffer || globalThis.Buffer;
      var receiver = BufferOwner.from(recipe.bytes);
      var expectedOwner = moduleValue[recipe.ownerExportName];
      if (typeof expectedOwner !== "function" || !(receiver instanceof expectedOwner)) {
        throw new TypeError("buffer receiver does not match source owner");
      }
      return receiver;
    }
    if (recipe.kind === "event-emitter") {
      var EventEmitter = moduleValue.EventEmitter || moduleValue;
      var emitter = Reflect.construct(EventEmitter, []);
      addCleanup(function () {
        emitter.removeAllListeners();
      });
      return emitter;
    }
    if (recipe.kind === "event-emitter-async-resource") {
      var AsyncEmitter = moduleValue.EventEmitterAsyncResource;
      var asyncEmitter = Reflect.construct(AsyncEmitter, [
        "ibex-output-shape",
      ]);
      var listener = function () {};
      asyncEmitter.on("ibex-output-shape", listener);
      bindings.listener = listener;
      addCleanup(function () {
        asyncEmitter.removeAllListeners();
        if (
          asyncEmitter.asyncResource &&
          typeof asyncEmitter.asyncResource.emitDestroy === "function"
        ) {
          asyncEmitter.asyncResource.emitDestroy();
        }
      });
      return asyncEmitter;
    }
    if (recipe.kind === "sqlite-database") {
      var Database = ownerFromModule(moduleValue, recipe.ownerExportName);
      var database = Reflect.construct(Database, [":memory:"]);
      addCleanup(function () {
        database.close(true);
      });
      return database;
    }
    if (recipe.kind === "sqlite-statement") {
      var DatabaseOwner = moduleValue.Database || moduleValue;
      var db = Reflect.construct(DatabaseOwner, [":memory:"]);
      var statement = db.query("SELECT 1 AS value");
      if (recipe.executeBeforeGet) statement.get();
      bindings.sqliteDatabase = db;
      bindings.sqliteStatement = statement;
      addCleanup(function () {
        try {
          statement.finalize();
        } finally {
          db.close(true);
        }
      });
      return statement;
    }
    if (recipe.kind === "fs-dirent") {
      return Reflect.construct(moduleValue.Dirent, ["entry.txt", 1]);
    }
    if (recipe.kind === "fs-stats") {
      return Reflect.construct(moduleValue.Stats, [{}, false]);
    }
    if (recipe.kind === "string-decoder") {
      var Decoder = moduleValue.StringDecoder || moduleValue;
      return Reflect.construct(Decoder, ["utf8"]);
    }
    if (recipe.kind === "performance-mark") {
      return Reflect.construct(moduleValue.PerformanceMark, [
        "ibex-output-shape-mark",
        { startTime: 1, detail: { fixture: true } },
      ]);
    }
    if (recipe.kind === "performance-measure") {
      var performance = moduleValue.performance;
      performance.mark("ibex-output-shape-start", { startTime: 1 });
      performance.mark("ibex-output-shape-end", { startTime: 2 });
      var measure = performance.measure("ibex-output-shape-measure", {
        start: "ibex-output-shape-start",
        end: "ibex-output-shape-end",
        detail: { fixture: true },
      });
      addCleanup(function () {
        performance.clearMeasures("ibex-output-shape-measure");
        performance.clearMarks("ibex-output-shape-start");
        performance.clearMarks("ibex-output-shape-end");
      });
      return measure;
    }
    if (recipe.kind === "performance-observer") {
      var observer = Reflect.construct(moduleValue.PerformanceObserver, [
        function () {},
      ]);
      addCleanup(function () {
        observer.disconnect();
      });
      return observer;
    }
    if (recipe.kind === "crypto-secret-key") {
      return moduleValue.createSecretKey(
        (moduleValue.Buffer || globalThis.Buffer).from("ibex-secret-key"),
      );
    }
    if (recipe.kind === "crypto-certificate") {
      return Reflect.construct(moduleValue.Certificate, []);
    }
    if (recipe.kind === "crypto-x509-certificate") {
      return Reflect.construct(moduleValue.X509Certificate, [
        "ibex-output-shape-certificate",
      ]);
    }
    if (recipe.kind === "crypto-cipher") {
      var CryptoBuffer = bufferOwner(moduleValue);
      var key = CryptoBuffer.alloc(16, 7);
      var iv = CryptoBuffer.alloc(16, 9);
      var CipherOwner = moduleValue[recipe.ownerExportName];
      if (typeof CipherOwner !== "function") {
        throw new TypeError("missing authored cipher owner");
      }
      var cryptoReceiver = Reflect.construct(CipherOwner, [
        recipe.algorithm,
        key,
        iv,
      ]);
      if (recipe.preload) {
        var sourceCipher = moduleValue.createCipheriv(
          recipe.algorithm,
          key,
          iv,
        );
        var ciphertext = CryptoBuffer.concat([
          sourceCipher.update(CryptoBuffer.from("ibex-output-shape")),
          sourceCipher.final(),
        ]);
        cryptoReceiver.update(ciphertext);
      }
      if (recipe.finalized) {
        cryptoReceiver.update(CryptoBuffer.from("ibex-output-shape"));
        cryptoReceiver.final();
      }
      if (recipe.deferredCleanup) {
        bindings.completionCleanupReceiver = cryptoReceiver;
      } else {
        addCleanup(function () {
          if (typeof cryptoReceiver.destroy === "function") {
            cryptoReceiver.destroy();
          }
        });
      }
      return cryptoReceiver;
    }
    if (recipe.kind === "crypto-diffie-hellman") {
      var DhBuffer = bufferOwner(moduleValue);
      var dh = moduleValue.createDiffieHellman(DhBuffer.from([23]), 5);
      if (recipe.generated) dh.generateKeys();
      if (recipe.peer) {
        var dhPeer = moduleValue.createDiffieHellman(DhBuffer.from([23]), 5);
        bindings.cryptoPeerPublicKey = dhPeer.generateKeys();
      }
      return dh;
    }
    if (recipe.kind === "crypto-diffie-hellman-group") {
      var dhGroup = moduleValue.getDiffieHellman("modp1");
      if (recipe.generated) dhGroup.generateKeys();
      if (recipe.peer) {
        var dhGroupPeer = moduleValue.getDiffieHellman("modp1");
        bindings.cryptoPeerPublicKey = dhGroupPeer.generateKeys();
      }
      return dhGroup;
    }
    if (recipe.kind === "crypto-ecdh") {
      var ecdh = moduleValue.createECDH("prime256v1");
      if (recipe.generated) ecdh.generateKeys();
      if (recipe.peer) {
        // computeSecret accepts public key bytes, including the PEM produced
        // by the public key-pair API. Use that public result rather than
        // reaching through either ECDH fixture's private compatibility state.
        bindings.cryptoPeerPublicKey = cryptoKeyPair(
          moduleValue,
          bindings,
          "ec",
        ).publicKey;
      }
      return ecdh;
    }
    if (recipe.kind === "crypto-hash-stream") {
      var HashOwner = moduleValue[recipe.ownerExportName];
      var hashReceiver =
        recipe.ownerExportName === "Hmac"
          ? Reflect.construct(HashOwner, ["sha256", "ibex-output-shape-key"])
          : Reflect.construct(HashOwner, ["sha256"]);
      if (recipe.deferredCleanup) {
        bindings.completionCleanupReceiver = hashReceiver;
      } else {
        addCleanup(function () {
          if (typeof hashReceiver.destroy === "function") hashReceiver.destroy();
        });
      }
      return hashReceiver;
    }
    if (recipe.kind === "crypto-sign-verify") {
      var SignVerifyOwner = moduleValue[recipe.ownerExportName];
      var signVerifyReceiver = Reflect.construct(SignVerifyOwner, ["sha256"]);
      signVerifyReceiver.update("ibex-output-shape");
      addCleanup(function () {
        if (typeof signVerifyReceiver.destroy === "function") {
          signVerifyReceiver.destroy();
        }
      });
      return signVerifyReceiver;
    }
    if (recipe.kind === "timer-handle") {
      var handle =
        recipe.timerKind === "immediate"
          ? moduleValue.setImmediate(function () {})
          : moduleValue.setTimeout(function () {}, 60000);
      addCleanup(function () {
        if (recipe.timerKind === "immediate") moduleValue.clearImmediate(handle);
        else moduleValue.clearTimeout(handle);
      });
      return handle;
    }
    if (recipe.kind === "unscheduled-timeout") {
      var timeout = Object.create(moduleValue.Timeout.prototype);
      timeout._callback = function () {};
      timeout._delay = 60_000;
      timeout._args = [];
      timeout._isRepeat = false;
      timeout._repeat = null;
      timeout._refed = true;
      timeout._destroyed = false;
      timeout._closed = false;
      timeout._idleTimeout = timeout._delay;
      timeout._idleStart = Date.now();
      timeout._id = -1;
      timeout._onTimeout = timeout._callback;
      addCleanup(function () {
        if (typeof timeout.close === "function") timeout.close();
      });
      return timeout;
    }
    throw new TypeError("unknown receiver fixture " + recipe.kind);
  }

  function performCleanup(route, moduleValue, result) {
    if (route.cleanup.kind === "returned-timer-handle") {
      if (typeof moduleValue.clearTimeout === "function") {
        moduleValue.clearTimeout(result);
      }
      if (typeof moduleValue.clearImmediate === "function") {
        moduleValue.clearImmediate(result);
      }
    } else if (
      route.cleanup.kind === "returned-stream-destroy" ||
      route.cleanup.kind === "constructed-stream-destroy" ||
      route.cleanup.kind === "returned-and-owned-stream-destroy"
    ) {
      if (result && typeof result.destroy === "function") result.destroy();
    } else if (route.cleanup.kind === "returned-object-url") {
      if (typeof moduleValue.revokeObjectURL === "function") {
        moduleValue.revokeObjectURL(result);
      }
    } else if (route.cleanup.kind === "returned-async-hook-disable") {
      if (result && typeof result.disable === "function") result.disable();
    } else if (route.cleanup.kind === "constructed-async-local-storage-disable") {
      if (result && typeof result.disable === "function") result.disable();
    } else if (route.cleanup.kind === "constructed-async-resource-destroy") {
      if (result && typeof result.emitDestroy === "function") result.emitDestroy();
    } else if (route.cleanup.kind === "constructed-web-stream-release") {
      if (result && typeof result.releaseLock === "function") {
        result.releaseLock();
      }
    } else if (route.cleanup.kind === "returned-process-listener-remove") {
      if (moduleValue && typeof moduleValue.removeAllListeners === "function") {
        moduleValue.removeAllListeners(route.cleanup.eventName);
      }
    } else if (route.cleanup.kind === "returned-async-iterator-return") {
      if (result && typeof result.return === "function") {
        Promise.resolve(result.return()).catch(function () {});
      }
    } else if (route.cleanup.kind === "returned-web-stream-cancel") {
      if (result && typeof result.cancel === "function") {
        Promise.resolve(result.cancel()).catch(function () {});
      }
    } else if (route.cleanup.kind === "returned-diagnostics-channel-clear") {
      clearDiagnosticsOwner(result);
    } else if (route.cleanup.kind === "constructed-file-handle-close") {
      if (result && typeof result.close === "function") {
        Promise.resolve(result.close()).catch(function () {});
      }
    } else if (route.cleanup.kind === "constructed-dir-close") {
      if (result && !result._closed && typeof result.closeSync === "function") {
        result.closeSync();
      }
    } else if (route.cleanup.kind === "constructed-fs-watcher-close") {
      if (result && typeof result.close === "function") result.close();
    } else if (route.cleanup.kind === "returned-performance-monitor-disable") {
      if (result && typeof result.disable === "function") result.disable();
    } else if (route.cleanup.kind === "constructed-diagnostics-channel-clear") {
      clearDiagnosticsOwner(result);
    } else if (
      route.cleanup.kind === "constructed-diagnostics-tracing-clear" ||
      route.cleanup.kind === "returned-diagnostics-tracing-clear"
    ) {
      clearDiagnosticsOwner(result);
    } else if (
      route.cleanup.kind === "constructed-domain-dispose" ||
      route.cleanup.kind === "returned-domain-dispose"
    ) {
      disposeDomain(result);
    } else if (
      !new Set([
        "none",
        "receiver-default",
        "sqlite-database-only",
        "zlib-native-stream",
        "stream-destroy",
        "stream-owned-destroy",
        "stream-watermark-restore",
        "stream-pipeline-callback-destroy",
        "returned-promise-stream-drain",
        "zlib-owned-close",
        "zlib-end-callback-close",
        "crypto-stream-destroy",
        "crypto-stream-end-callback-destroy",
        "crypto-fips-restore",
        "async-callback-quiescence",
        "returned-async-iterator-return",
        "returned-web-stream-cancel",
        "file-handle-close",
        "performance-observer-disconnect",
        "returned-diagnostics-channel-clear",
        "constructed-file-handle-close",
        "constructed-dir-close",
        "constructed-fs-watcher-close",
        "returned-performance-monitor-disable",
        "timer-record-close",
        "legacy-timer-record-cancel",
      ]).has(route.cleanup.kind)
    ) {
      throw new TypeError("unknown cleanup route " + route.cleanup.kind);
    }
    for (var index = cleanupContext.callbacks.length - 1; index >= 0; index--) {
      cleanupContext.callbacks[index]();
    }
    cleanupPerformed = true;
  }

  try {
    if (config.route.inheritedTemplateId) {
      var inherited = inheritedInvocation();
      inherited.inheritedTemplateId = config.route.inheritedTemplateId;
      return inherited;
    }

    var route = config.route;
    if (
      route.operation === "import-refusal" ||
      route.operation === "import-return"
    ) {
      sourceOperationAttempted = true;
      var unexpectedModuleValue = require(config.moduleSpecifier);
      cleanupPerformed = true;
      return failure("return", {
        descriptorProof: {
          accessKind: "module-value",
          descriptorKind: "module-value",
        },
        rawOutput: rawReturn(unexpectedModuleValue),
      });
    }

    var moduleValue = require(config.moduleSpecifier);
    var resolved;
    try {
      resolved = descriptorAt(moduleValue, config.sourceDescriptor);
    } catch (descriptorError) {
      if (
        route.outcomeCapture === "public-builtin-family" &&
        descriptorError instanceof TypeError &&
        new Set([
          "source own member is absent",
          "source inherited member is absent",
          "source descriptor is absent",
        ]).has(descriptorError.message)
      ) {
        sourceOperationAttempted = true;
        cleanupPerformed = true;
        return failure("absent", { rawOutput: rawAbsent() });
      }
      throw descriptorError;
    }
    var bindings = {};
    var receiver;
    var result;
    if (route.operation === "construct") {
      if (typeof resolved.value !== "function") {
        throw new TypeError("construct route did not resolve a callable");
      }
      sourceOperationAttempted = true;
      result = Reflect.construct(
        resolved.value,
        materializeList(route.arguments, moduleValue, bindings),
      );
    } else if (route.operation === "call") {
      if (typeof resolved.value !== "function") {
        throw new TypeError("call route did not resolve a callable");
      }
      receiver = createReceiver(route.receiver, moduleValue, bindings);
      sourceOperationAttempted = true;
      result = Reflect.apply(
        resolved.value,
        receiver,
        materializeList(route.arguments, moduleValue, bindings),
      );
    } else if (route.operation === "get") {
      receiver = createReceiver(route.receiver, moduleValue, bindings);
      sourceOperationAttempted = true;
      if (resolved.descriptorKind === "module-value") {
        result = resolved.value;
      } else if (typeof resolved.propertyDescriptor.get === "function") {
        result = Reflect.apply(resolved.propertyDescriptor.get, receiver, []);
      } else {
        result = resolved.propertyDescriptor.value;
      }
    } else {
      throw new TypeError("unsupported executable route " + route.operation);
    }
    if (Array.isArray(bindings.postOperationCallbacks)) {
      for (
        var postIndex = 0;
        postIndex < bindings.postOperationCallbacks.length;
        postIndex++
      ) {
        bindings.postOperationCallbacks[postIndex]();
      }
    }
    if (route.awaitResult === true) {
      trackReturnedPromise(result, bindings);
    }
    performCleanup(route, moduleValue, result);
    var returnEvidence = {
      descriptorProof: {
        accessKind: config.sourceDescriptor.access.kind,
        descriptorKind: resolved.descriptorKind,
      },
      rawOutput: rawReturn(result),
    };
    if (completionToken !== null) {
      returnEvidence.completionToken = completionToken;
    }
    return failure("return", returnEvidence);
  } catch (error) {
    try {
      if (!cleanupPerformed) {
        for (
          var index = cleanupContext.callbacks.length - 1;
          index >= 0;
          index--
        ) {
          cleanupContext.callbacks[index]();
        }
        cleanupPerformed = true;
      }
    } catch (cleanupError) {
      return failure("cleanup-failure", {
        errorName: String((cleanupError && cleanupError.name) || "Error"),
        errorMessage: String(cleanupError && cleanupError.message),
      });
    }
    return failure("throw", {
      errorName: String((error && error.name) || "Error"),
      errorMessage: String((error && error.message) || error),
      errorCode:
        error && typeof error.code === "string" ? error.code : null,
      rawOutput: sourceOperationAttempted ? rawThrow(error) : null,
    });
  }
})
