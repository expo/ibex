(function runBuiltinEffectsOutputInvocation(config) {
  "use strict";

  var own = Object.prototype.hasOwnProperty;
  var sourceOperationAttempted = false;
  var cleanupPerformed = false;
  var completionToken = null;
  var setupStage = "validate-config";

  function rawReturn(value) {
    var shape =
      value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
    // The catalog proves the raw shape, not machine-specific values.  Avoid
    // retaining hostnames, paths, terminal data, or other ambient material.
    return {
      kind: "return",
      rawValueShape: shape,
      value: null,
      errorCode: null,
    };
  }

  function rawThrow(error) {
    var code =
      error && typeof error.code === "string" && error.code.length > 0
        ? error.code
        : "ERR_IBEX_PUBLIC_BUILTIN_THROW";
    return {
      kind: "throw",
      rawValueShape: "throw",
      value: null,
      errorCode: code,
    };
  }

  function result(kind, extra) {
    var value = {
      kind: kind,
      moduleSpecifier: config.moduleSpecifier,
      surfaceObservedKey: config.surfaceObservedKey,
      sourceOperationAttempted: sourceOperationAttempted,
      cleanupPerformed: cleanupPerformed,
      completionToken: completionToken,
    };
    if (extra) {
      var keys = Object.keys(extra);
      for (var index = 0; index < keys.length; index++) {
        value[keys[index]] = extra[keys[index]];
      }
    }
    return value;
  }

  function childValue(value, key, descriptor) {
    // CommonJS default-constructor modules may be inventoried under the
    // synthetic `default` owner even though require() returns that owner.
    if (
      key === "default" &&
      typeof value === "function" &&
      !own.call(value, key)
    ) {
      return value;
    }
    if (
      value === null ||
      (typeof value !== "object" && typeof value !== "function")
    ) {
      throw new TypeError("source descriptor crossed a non-object segment");
    }
    var property = Object.getOwnPropertyDescriptor(value, key);
    if (!property) {
      throw new TypeError(
        "source descriptor is absent before " + descriptor.exportName,
      );
    }
    if (!own.call(property, "value")) {
      throw new TypeError("source descriptor crossed an accessor segment");
    }
    return property.value;
  }

  function descriptorAt(moduleValue, descriptor) {
    var access = descriptor.access;
    if (access.kind === "module-value") {
      return {
        holder: null,
        propertyDescriptor: { value: moduleValue },
        value: moduleValue,
        descriptorKind: "module-value",
      };
    }
    var value = moduleValue;
    for (var index = 0; index < access.path.length; index++) {
      var key = access.path[index];
      var last = index === access.path.length - 1;
      if (
        index === 0 &&
        key === "default" &&
        typeof value === "function" &&
        !own.call(value, key)
      ) {
        if (last) {
          return {
            holder: null,
            propertyDescriptor: { value: value },
            value: value,
            descriptorKind: "module-value",
          };
        }
        continue;
      }
      if (
        value === null ||
        (typeof value !== "object" && typeof value !== "function")
      ) {
        throw new TypeError("source descriptor crossed a non-object segment");
      }
      var holder = value;
      var inherited = false;
      if (last && !own.call(holder, key)) {
        var originalHolder = holder;
        holder = Object.getPrototypeOf(holder);
        while (holder && !own.call(holder, key)) {
          holder = Object.getPrototypeOf(holder);
        }
        if (!holder) throw new TypeError("source inherited member is absent");
        inherited = holder !== originalHolder;
      } else if (last && access.kind === "inherited-prototype-property") {
        if (own.call(holder, key)) {
          throw new TypeError("source descriptor expected an inherited member");
        }
      }
      var property = Object.getOwnPropertyDescriptor(holder, key);
      if (!property) throw new TypeError("source descriptor is absent");
      if (last) {
        var descriptorKind =
          typeof property.get === "function" ? "accessor" : "data";
        if (
          descriptor.valueShape === "accessor" &&
          descriptorKind !== "accessor"
        ) {
          throw new TypeError("source member is not the inventoried accessor");
        }
        var target =
          descriptorKind === "accessor" ? property.get : property.value;
        if (
          config.route.operation !== "get" &&
          typeof target !== "function"
        ) {
          throw new TypeError("source member is not callable in the loaded realm");
        }
        return {
          holder: holder,
          propertyDescriptor: property,
          value: target,
          descriptorKind: descriptorKind,
          inherited: inherited,
        };
      }
      value = childValue(value, key, descriptor);
    }
    throw new TypeError("source descriptor has an empty access path");
  }

  function valueAt(moduleValue, path) {
    var value = moduleValue;
    for (var index = 0; index < path.length; index++) {
      value = childValue(value, path[index], config.sourceDescriptor);
    }
    return value;
  }

  function inertObject() {
    var inert = {
      readable: true,
      writable: true,
      isTTY: false,
      columns: 80,
      rows: 24,
      write: function () {
        return true;
      },
      end: function () {},
      destroy: function () {},
      close: function () {},
      push: function () {
        return true;
      },
      read: function () {
        return null;
      },
      pause: function () {
        return this;
      },
      resume: function () {
        return this;
      },
      pipe: function () {
        return this;
      },
      on: function () {
        return this;
      },
      once: function () {
        return this;
      },
      off: function () {
        return this;
      },
      addListener: function () {
        return this;
      },
      removeListener: function () {
        return this;
      },
      removeAllListeners: function () {
        return this;
      },
      emit: function () {
        return false;
      },
    };
    return inert;
  }

  function completionStoreForSource() {
    completionToken = "builtin-effects-output:" + config.coverageEdgeId;
    if (
      !globalThis.__ibexBuiltinEffectsOutputCompletions ||
      typeof globalThis.__ibexBuiltinEffectsOutputCompletions !== "object"
    ) {
      globalThis.__ibexBuiltinEffectsOutputCompletions = Object.create(null);
    }
    delete globalThis.__ibexBuiltinEffectsOutputCompletions[completionToken];
    return globalThis.__ibexBuiltinEffectsOutputCompletions;
  }

  function fixtureRecord() {
    var setup = config.route && config.route.setup;
    var store = globalThis.__ibexBuiltinEffectsOutputFixtures;
    var fixture = setup && store && store[setup.fixtureKey];
    if (!fixture || fixture.kind !== setup.fixtureKind) {
      throw new TypeError("authored filesystem live fixture is absent");
    }
    return fixture;
  }

  function materialize(argument) {
    if (!argument || typeof argument.kind !== "string") {
      throw new TypeError("invalid authored argument");
    }
    if (argument.kind === "json") return argument.value;
    if (argument.kind === "noop-function") return function () {};
    if (argument.kind === "inert-object") return inertObject();
    if (argument.kind === "fixture-fd") {
      var fixture = fixtureRecord();
      if (fixture.kind !== "fd" || typeof fixture.value !== "number") {
        throw new TypeError("authored fd fixture is invalid");
      }
      return fixture.value;
    }
    if (argument.kind === "uint8-array") {
      return new Uint8Array(argument.size);
    }
    if (argument.kind === "uint8-array-list") {
      return argument.sizes.map(function (size) {
        return new Uint8Array(size);
      });
    }
    if (argument.kind === "completion-callback") {
      var completionStore = completionStoreForSource();
      return function (error) {
        completionStore[completionToken] = {
          calls: 1,
          settled: error ? "rejected" : "fulfilled",
        };
      };
    }
    throw new TypeError("unsupported authored argument kind");
  }

  function receiverFor(moduleValue, route) {
    if (route.receiver.kind === "module-value") return moduleValue;
    if (route.receiver.kind === "prototype-shell") {
      var owner = valueAt(moduleValue, route.receiver.ownerPath);
      if (typeof owner !== "function" || !owner.prototype) {
        throw new TypeError("prototype-shell owner is not a constructor");
      }
      return Object.create(owner.prototype);
    }
    if (route.receiver.kind === "fixture-value") {
      return fixtureRecord().value;
    }
    throw new TypeError("unsupported authored receiver");
  }

  function beginPromiseCompletion(promise) {
    var completionStore = completionStoreForSource();
    promise.then(
      function () {
        completionStore[completionToken] = {
          calls: 1,
          settled: "fulfilled",
        };
      },
      function () {
        completionStore[completionToken] = {
          calls: 1,
          settled: "rejected",
        };
      },
    );
  }

  function releaseOwned(value) {
    if (!value || (typeof value !== "object" && typeof value !== "function")) {
      return;
    }
    if (typeof value.then === "function" && value instanceof Promise) {
      beginPromiseCompletion(value);
      return;
    }
    if (typeof value.on === "function") {
      try {
        value.on("error", function () {});
      } catch (_) {}
    }
    var released = false;
    for (var index = 0; index < 5; index++) {
      var name = ["terminate", "destroy", "close", "stop", "unref"][index];
      if (typeof value[name] === "function") {
        try {
          if (name === "close") value[name](function () {});
          else value[name]();
          released = true;
          break;
        } catch (_) {}
      }
    }
    if (!released && typeof value.removeAllListeners === "function") {
      try {
        value.removeAllListeners();
      } catch (_) {}
    }
  }

  try {
    if (
      !config ||
      config.invocationSchema !==
        "ibex/capsec-builtin-effects-output-invocation/1" ||
      config.kind !== "builtin-effects-output"
    ) {
      throw new TypeError("invalid builtin effects invocation");
    }
    setupStage = "require-module";
    var moduleValue = require(config.moduleSpecifier);
    setupStage = "resolve-source-descriptor";
    var source = descriptorAt(moduleValue, config.sourceDescriptor);
    var route = config.route;
    setupStage = "materialize-receiver";
    var receiver = receiverFor(moduleValue, route);
    setupStage = "materialize-arguments";
    var args = route.arguments.map(materialize);
    var rawOutput;
    var returned;
    try {
      setupStage = "invoke-source";
      sourceOperationAttempted = true;
      if (route.operation === "construct") {
        returned = Reflect.construct(source.value, args);
      } else if (route.operation === "call") {
        returned = Reflect.apply(source.value, receiver, args);
      } else if (route.operation === "get") {
        returned = Reflect.apply(source.propertyDescriptor.get, receiver, []);
      } else {
        throw new TypeError("unsupported authored source operation");
      }
      rawOutput = rawReturn(returned);
    } catch (error) {
      rawOutput = rawThrow(error);
    }
    releaseOwned(returned);
    cleanupPerformed = true;
    return result("source-completion", {
      descriptorProof: {
        descriptorKind: source.descriptorKind,
        inherited: source.inherited === true,
        accessKind: config.sourceDescriptor.access.kind,
        accessPath: config.sourceDescriptor.access.path,
      },
      rawOutput: rawOutput,
    });
  } catch (error) {
    cleanupPerformed = true;
    return result("setup-failure", {
      setupStage: setupStage,
      setupErrorCode:
        error && typeof error.code === "string" && error.code.length > 0
          ? error.code
          : "ERR_IBEX_BUILTIN_EFFECTS_SETUP",
    });
  }
})
