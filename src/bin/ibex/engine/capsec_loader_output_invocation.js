(async function executeModuleLoaderOutputInvocation(config) {
  "use strict";

  // Capture the scheduling primitives before the source entrypoint can load a
  // module that rewrites their public globals. The Rust integration must still
  // enforce the same wall-clock bound and discard a timed-out realm.
  var PromiseConstructor = Promise;
  var promiseResolve = PromiseConstructor.resolve.bind(PromiseConstructor);
  var scheduleTimeout = globalThis.setTimeout;
  var cancelTimeout = globalThis.clearTimeout;

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

  function thrown(error) {
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

  function blocked(reasonCode, sourceOperationAttempted, proof) {
    return {
      kind: "unexercisable",
      reasonCode: reasonCode,
      sourceOperationAttempted: sourceOperationAttempted,
      entrypointProof: proof,
      rawOutput: null,
    };
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

  function proofFor(found) {
    if (!found) {
      return {
        presence: "absent",
        descriptorKind: "absent",
        valueType: "unread",
      };
    }
    var data = Object.prototype.hasOwnProperty.call(
      found.descriptor,
      "value",
    );
    return {
      presence: found.inherited ? "inherited" : "own",
      descriptorKind: data ? "data" : "accessor",
      valueType: data ? valueShape(found.descriptor.value) : "unread",
    };
  }

  function entryRoute(entrypoint) {
    if (entrypoint === "global-require") {
      return { owner: globalThis, key: "require" };
    }
    if (entrypoint === "exact-require") {
      return { owner: globalThis, key: "__exactRequire" };
    }
    if (entrypoint === "global-import") {
      return { owner: globalThis, key: "import" };
    }
    if (entrypoint === "import-module") {
      return { owner: globalThis, key: "importModule" };
    }
    if (entrypoint === "require-resolve") {
      return { owner: globalThis, key: "require", memberKey: "resolve" };
    }
    return null;
  }

  function result(raw, sourceOperationAttempted, proof) {
    return {
      kind: raw.kind,
      sourceOperationAttempted: sourceOperationAttempted,
      entrypointProof: proof,
      rawOutput: raw,
    };
  }

  function settleWithin(value, timeoutMilliseconds, proof) {
    return new PromiseConstructor(function (resolve) {
      var settled = false;
      var timer = Reflect.apply(scheduleTimeout, globalThis, [function () {
        if (settled) return;
        settled = true;
        resolve(blocked("event-loop-quiescence-timeout", true, proof));
      }, timeoutMilliseconds]);

      promiseResolve(value).then(
        function (resolved) {
          // Retain the source promise's actual completion, then cross one more
          // microtask boundary before declaring the bounded loader turn quiet.
          promiseResolve().then(function () {
            if (settled) return;
            settled = true;
            Reflect.apply(cancelTimeout, globalThis, [timer]);
            resolve(result(returned(resolved), true, proof));
          });
        },
        function (error) {
          promiseResolve().then(function () {
            if (settled) return;
            settled = true;
            Reflect.apply(cancelTimeout, globalThis, [timer]);
            resolve(result(thrown(error), true, proof));
          });
        },
      );
    });
  }

  var sourceOperationAttempted = false;
  var proof = {
    presence: "absent",
    descriptorKind: "absent",
    valueType: "unread",
  };

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
      "module-loader output invocation",
    );
    if (config.invocationSchema !== "ibex/capsec-loader-output-invocation/1") {
      return blocked("invalid-invocation-schema", false, proof);
    }
    if (config.kind !== "loader-output") {
      return blocked("invalid-invocation-kind", false, proof);
    }
    if (config.route.operation !== "invoke-public-loader") {
      return blocked("route-is-not-executable", false, proof);
    }
    exactKeys(
      config.route,
      config.route.authority === undefined
        ? ["entrypoint", "operation", "specifier"]
        : ["authority", "entrypoint", "operation", "specifier"],
      "module-loader output route",
    );
    if (
      typeof config.route.specifier !== "string" ||
      config.route.specifier.length === 0
    ) {
      return blocked("invalid-loader-specifier", false, proof);
    }
    var completion = config.completion;
    var asynchronous = completion.kind === "event-loop-quiescence";
    exactKeys(
      completion,
      asynchronous
        ? ["kind", "timeoutMilliseconds"]
        : ["kind"],
      "module-loader output completion",
    );
    if (
      asynchronous &&
      (!Number.isInteger(completion.timeoutMilliseconds) ||
        completion.timeoutMilliseconds < 1 ||
        completion.timeoutMilliseconds > 1_000)
    ) {
      return blocked("invalid-quiescence-bound", false, proof);
    }
    if (!asynchronous && completion.kind !== "synchronous-loaded-runtime") {
      return blocked("invalid-completion-kind", false, proof);
    }
    if (
      asynchronous &&
      (typeof scheduleTimeout !== "function" ||
        typeof cancelTimeout !== "function")
    ) {
      return blocked("trusted-timer-unavailable", false, proof);
    }
    var route = entryRoute(config.route.entrypoint);
    if (!route) {
      return blocked("private-or-unknown-entrypoint", false, proof);
    }

    try {
      var found = findDescriptor(route.owner, route.key);
      proof = proofFor(found);
      // The loaded descriptor lookup is the source operation for an absent
      // public entrypoint, just as a live Get proves an omitted global callable.
      sourceOperationAttempted = true;
      if (!found) return result(absent(), true, proof);

      var callableOwner = route.owner;
      var callableKey = route.key;
      if (route.memberKey !== undefined) {
        callableOwner = route.owner[route.key];
        callableKey = route.memberKey;
        found = findDescriptor(callableOwner, callableKey);
        proof = proofFor(found);
        if (!found) return result(absent(), true, proof);
      }
      var callable = callableOwner[callableKey];
      if (typeof callable !== "function") {
        return blocked("loaded-entrypoint-is-not-callable", true, proof);
      }
      var value;
      value = Reflect.apply(callable, callableOwner, [config.route.specifier]);
      if (asynchronous) {
        return await settleWithin(
          value,
          completion.timeoutMilliseconds,
          proof,
        );
      }
      return result(returned(value), sourceOperationAttempted, proof);
    } catch (error) {
      return result(thrown(error), sourceOperationAttempted, proof);
    }
  } catch (_validationError) {
    return blocked("invalid-invocation-shape", false, proof);
  }
})
