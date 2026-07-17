/**
 * This function is serialized with Function#toString. Keep every dependency
 * inside its closure and stay within the Hermes-compatible syntax subset.
 *
 * @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
 */
export function portableWebGpuTestWrapperFactory(plan) {
  "use strict";

  var wrapperStates = new WeakMap();
  var featureStates = new WeakMap();
  var clientStates = new WeakMap();
  var promiseStates = new WeakMap();
  var prototypes = Object.create(null);
  var routes = Object.create(null);
  var nextRealmToken = 1;

  function freezeTree(value) {
    if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
    var keys = Object.keys(value);
    for (var index = 0; index < keys.length; index += 1) freezeTree(value[keys[index]]);
    return Object.freeze(value);
  }

  freezeTree(plan);
  for (var routeIndex = 0; routeIndex < plan.routes.length; routeIndex += 1) {
    routes[plan.routes[routeIndex].operationId] = plan.routes[routeIndex];
  }

  function namedError(name, message) {
    var error = new Error(message);
    Object.defineProperty(error, "name", {
      value: name,
      writable: false,
      enumerable: false,
      configurable: true,
    });
    return error;
  }

  function typeError(message) {
    return new TypeError(message);
  }

  function requireDictionary(value, label) {
    if (value === undefined) return {};
    if (value === null || (typeof value !== "object" && typeof value !== "function")) {
      throw typeError(label + " must be a dictionary");
    }
    return value;
  }

  function snapshotValue(value, depth, seen) {
    if (depth > 8) throw typeError("descriptor nesting exceeds the test profile bound");
    if (value === null || typeof value !== "object") return value;
    if (wrapperStates.has(value)) return value;
    if (seen.has(value)) throw typeError("cyclic descriptors are not supported");
    seen.set(value, true);
    var output;
    var index;
    if (Array.isArray(value)) {
      if (value.length > 1024) throw typeError("descriptor sequence exceeds the test profile bound");
      output = [];
      for (index = 0; index < value.length; index += 1) {
        output.push(snapshotValue(value[index], depth + 1, seen));
      }
    } else {
      output = {};
      var keys = Object.keys(value);
      if (keys.length > 128) throw typeError("descriptor has too many members");
      for (index = 0; index < keys.length; index += 1) {
        output[keys[index]] = snapshotValue(value[keys[index]], depth + 1, seen);
      }
    }
    seen.delete(value);
    return output;
  }

  function snapshotDictionary(value, label) {
    return snapshotValue(requireDictionary(value, label), 0, new WeakMap());
  }

  function typedRef(state) {
    if (!state) return null;
    var client = clientStates.get(state.realm.client);
    return {
      runtimePointerNonce: client.runtimePointerNonce,
      realmToken: state.realm.token,
      realmGeneration: state.realm.generation,
      accountToken: state.realm.accountToken,
      accountGeneration: state.realm.accountGeneration,
      logicalDeviceId: state.device ? state.device.id : 0,
      logicalDeviceGeneration: state.device ? state.device.generation : 0,
      providerGeneration: state.device
        ? state.device.providerGeneration
        : state.providerGeneration || 0,
      authorityContextDigest: plan.digests.projection,
      topology: 1,
      objectKind: state.kind,
      logicalHandle: state.handle,
      lifecycleGeneration: state.generation,
    };
  }

  function logValue(value, depth) {
    if (depth > 10) return "<depth-bound>";
    if (value === null || typeof value !== "object") return value;
    var wrapperState = wrapperStates.get(value);
    if (wrapperState) return typedRef(wrapperState);
    var featureState = featureStates.get(value);
    if (featureState) return featureState.values.slice();
    if (value instanceof Error) return { name: value.name, message: value.message };
    var output;
    var keys;
    var index;
    if (Array.isArray(value)) {
      output = [];
      for (index = 0; index < value.length; index += 1) {
        output.push(logValue(value[index], depth + 1));
      }
      return output;
    }
    output = {};
    keys = Object.keys(value).sort();
    for (index = 0; index < keys.length; index += 1) {
      output[keys[index]] = logValue(value[keys[index]], depth + 1);
    }
    return output;
  }

  function defineMethod(prototype, name, implementation) {
    Object.defineProperty(prototype, name, {
      value: implementation,
      writable: false,
      enumerable: true,
      configurable: false,
    });
  }

  function defineGetter(prototype, name, implementation) {
    Object.defineProperty(prototype, name, {
      get: implementation,
      enumerable: true,
      configurable: false,
    });
  }

  function prototypeFor(kind) {
    if (!prototypes[kind]) prototypes[kind] = Object.create(null);
    return prototypes[kind];
  }

  function brandedRealm(value) {
    var wrapperState = wrapperStates.get(value);
    if (wrapperState) return wrapperState.realm;
    var featureState = featureStates.get(value);
    if (featureState) return featureState.realm;
    return null;
  }

  function realmMethod(realm, kind, implementation) {
    return function () {
      if (brandedRealm(this) !== realm) {
        throw typeError("cross-realm borrowed " + kind + " method");
      }
      return implementation.apply(this, arguments);
    };
  }

  function realmGetter(realm, kind, implementation) {
    return function () {
      if (brandedRealm(this) !== realm) {
        throw typeError("cross-realm borrowed " + kind + " getter");
      }
      return implementation.call(this);
    };
  }

  function installRealmPrototypes(realm) {
    realm.prototypes = Object.create(null);
    var kinds = Object.keys(prototypes);
    for (var kindIndex = 0; kindIndex < kinds.length; kindIndex += 1) {
      var kind = kinds[kindIndex];
      var definition = prototypes[kind];
      var installed = Object.create(null);
      var names = Object.getOwnPropertyNames(definition);
      var symbols =
        typeof Object.getOwnPropertySymbols === "function"
          ? Object.getOwnPropertySymbols(definition)
          : [];
      var keys = names.concat(symbols);
      for (var keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
        var key = keys[keyIndex];
        var descriptor = Object.getOwnPropertyDescriptor(definition, key);
        if (typeof descriptor.value === "function") {
          descriptor.value = realmMethod(realm, kind, descriptor.value);
        }
        if (typeof descriptor.get === "function") {
          descriptor.get = realmGetter(realm, kind, descriptor.get);
        }
        Object.defineProperty(installed, key, descriptor);
      }
      realm.prototypes[kind] = Object.freeze(installed);
    }
  }

  function allocateWrapper(realm, kind, device, extra) {
    var wrapper = Object.create(realm.prototypes[kind]);
    var state = extra || {};
    state.kind = kind;
    state.realm = realm;
    state.device = device || null;
    state.handle = realm.nextHandle++;
    state.generation = 1;
    state.retired = false;
    state.wrapper = wrapper;
    wrapperStates.set(wrapper, state);
    realm.wrappers.push(state);
    return wrapper;
  }

  function requireReceiver(value, kind) {
    var state = wrapperStates.get(value);
    if (!state || state.kind !== kind) throw typeError("incompatible " + kind + " receiver");
    return state;
  }

  function argumentState(value, kind) {
    var state = wrapperStates.get(value);
    if (!state || state.kind !== kind) throw typeError("value is not a branded " + kind);
    return state;
  }

  function requireFeatureSet(value) {
    var state = featureStates.get(value);
    if (!state) throw typeError("incompatible GPUSupportedFeatures receiver");
    return state;
  }

  function featureValuesIterator(state) {
    return state.values.slice()[Symbol.iterator]();
  }

  defineGetter(prototypeFor("GPUSupportedFeatures"), "size", function () {
    return requireFeatureSet(this).values.length;
  });

  defineMethod(prototypeFor("GPUSupportedFeatures"), "has", function (feature) {
    return requireFeatureSet(this).values.indexOf(String(feature)) !== -1;
  });

  defineMethod(prototypeFor("GPUSupportedFeatures"), "keys", function () {
    return featureValuesIterator(requireFeatureSet(this));
  });

  defineMethod(prototypeFor("GPUSupportedFeatures"), "values", function () {
    return featureValuesIterator(requireFeatureSet(this));
  });

  defineMethod(prototypeFor("GPUSupportedFeatures"), "entries", function () {
    var state = requireFeatureSet(this);
    var entries = state.values.map(function (value) {
      return [value, value];
    });
    return entries[Symbol.iterator]();
  });

  defineMethod(
    prototypeFor("GPUSupportedFeatures"),
    "forEach",
    function (callback, thisArg) {
      if (typeof callback !== "function") throw typeError("callback must be callable");
      var state = requireFeatureSet(this);
      for (var index = 0; index < state.values.length; index += 1) {
        callback.call(thisArg, state.values[index], state.values[index], this);
      }
    },
  );

  defineMethod(prototypeFor("GPUSupportedFeatures"), Symbol.iterator, function () {
    return featureValuesIterator(requireFeatureSet(this));
  });

  function createFeatureSet(realm, values) {
    var setlike = Object.create(realm.prototypes.GPUSupportedFeatures);
    featureStates.set(setlike, {
      realm: realm,
      values: values.slice().sort(),
    });
    return Object.freeze(setlike);
  }

  function currentScopeId(device) {
    if (!device || device.localScopes.length === 0) return 0;
    return device.localScopes[device.localScopes.length - 1];
  }

  function traceRealm(realm, kind, call, details) {
    var entry = {
      ordinal: realm.nextTraceOrdinal++,
      kind: kind,
      operationId: call ? call.route.operationId : null,
      operationInstanceId: call ? call.operationInstanceId : 0,
      promiseId: call ? call.promiseId : 0,
    };
    var names = details ? Object.keys(details) : [];
    for (var index = 0; index < names.length; index += 1) {
      entry[names[index]] = details[names[index]];
    }
    realm.orderingTrace.push(entry);
  }

  function beginPublic(realm, operationId, receiverState, targetState) {
    var route = routes[operationId];
    if (!route) throw new Error("unreviewed wrapper operation: " + operationId);
    var wireReceiverState = route.receiverHandleKind ? receiverState : null;
    var device = receiverState ? receiverState.device : null;
    if (!device && targetState) device = targetState.device;
    var carriedOperationIdentity =
      route.operationInstanceIdentity.indexOf("not-carried-wrapper-only") !== 0;
    var call = {
      route: route,
      realm: realm,
      device: device || null,
      ingressDevice: device || null,
      operationProviderGeneration: device
        ? device.providerGeneration
        : receiverState && receiverState.providerGeneration
          ? receiverState.providerGeneration
          : 0,
      operationInstanceId: carriedOperationIdentity
        ? realm.nextOperationInstance++
        : 0,
      promiseId: 0,
      adapterOperationOrdinal:
        operationId === "GPUAdapter.requestDevice" && receiverState
          ? receiverState.nextRequestDeviceOrdinal++
          : 0,
      deviceIngressOrdinal: device ? device.nextIngress++ : 0,
      queueIngressOrdinal:
        operationId === "GPUQueue.submit" && device ? device.nextQueueIngress++ : 0,
      capturedScopeId: currentScopeId(device),
      receiverState: receiverState || null,
      wireReceiverState: wireReceiverState,
      targetState: targetState || null,
      resultState: null,
      receipt: null,
      terminal: false,
    };
    if (
      targetState &&
      route.wrapperAllocatedTargetHandleKind === targetState.kind &&
      route.resultHandleKind === targetState.kind
    ) {
      call.resultState = targetState;
    }
    call.publicRecord = {
      operationId: route.operationId,
      wireId: route.wireId,
      interfaceName: route.interfaceName,
      memberName: route.memberName,
      memberKind: route.memberKind,
      dispatchClass: route.dispatchClass,
      logicalExecutionKind: route.logicalExecutionKind,
      resultTiming: route.resultTiming,
      publicArgumentCodec: route.publicArgumentCodec,
      publicResultCodec: route.publicResultCodec,
      operationInstanceIdentity: route.operationInstanceIdentity,
      promiseIdentity: route.promiseIdentity,
      operationInstanceId: call.operationInstanceId,
      expectedReceiverKind: route.receiverHandleKind,
      expectedTargetKind: route.wrapperAllocatedTargetHandleKind,
      expectedResultKind: route.resultHandleKind,
      receiverKind: wireReceiverState ? wireReceiverState.kind : null,
      targetKind: targetState ? targetState.kind : null,
      resultKind: call.resultState ? call.resultState.kind : null,
      receiverRef: typedRef(wireReceiverState),
      wrapperAllocatedTargetRef: typedRef(targetState),
      resultHandleRef: typedRef(call.resultState),
      capturedScopeId: call.capturedScopeId,
    };
    realm.publicCalls.push(call.publicRecord);
    return call;
  }

  function setCallResult(call, state) {
    call.resultState = state || null;
    call.publicRecord.resultKind = state ? state.kind : null;
    call.publicRecord.resultHandleRef = typedRef(state);
  }

  function setCallPreallocatedTarget(call, state) {
    call.targetState = state;
    call.publicRecord.targetKind = state ? state.kind : null;
    call.publicRecord.wrapperAllocatedTargetRef = typedRef(state);
    setCallResult(call, state);
  }

  function assignCallDeviceIngress(call, device) {
    if (!device || call.ingressDevice || call.deviceIngressOrdinal) {
      throw new Error("device ingress must be assigned exactly once");
    }
    call.device = device;
    call.ingressDevice = device;
    call.operationProviderGeneration = device.providerGeneration;
    call.deviceIngressOrdinal = device.nextIngress++;
    call.capturedScopeId = currentScopeId(device);
    call.publicRecord.capturedScopeId = call.capturedScopeId;
  }

  function requireClient(client) {
    var state = clientStates.get(client);
    if (!state) throw new Error("unbranded test semantic client");
    return state;
  }

  function operationCompleteEvent(call, status, completionBody) {
    var completionDevice =
      call.resultState && call.resultState.device
        ? call.resultState.device
        : call.ingressDevice;
    return {
      tag: "operation-complete-service-event-v1",
      kind: "operation-complete",
      realmToken: call.realm.token,
      realmGeneration: call.realm.generation,
      accountToken: call.realm.accountToken,
      accountGeneration: call.realm.accountGeneration,
      topology: 1,
      logicalDeviceId: completionDevice ? completionDevice.id : 0,
      logicalDeviceGeneration: completionDevice ? completionDevice.generation : 0,
      providerGeneration:
        call.operationProviderGeneration ||
        (completionDevice ? completionDevice.providerGeneration : 0),
      authorityContextDigest: plan.digests.projection,
      operationId: call.route.wireId,
      operationName: call.route.operationId,
      operationInstanceId: call.operationInstanceId,
      promiseId: call.promiseId,
      adapterOperationOrdinal: call.adapterOperationOrdinal,
      deviceIngressOrdinal: call.deviceIngressOrdinal,
      queueIngressOrdinal: call.queueIngressOrdinal,
      physicalSequence: call.receipt ? call.receipt.physicalOperationKey.physicalSequence : 0,
      receiverRef: typedRef(call.wireReceiverState),
      wrapperAllocatedTargetRef: typedRef(call.targetState),
      resultHandleRef: typedRef(call.resultState),
      capturedScopeId: call.capturedScopeId,
      completionCorrelationKey: call.realm.token + ":" + call.operationInstanceId,
      status: status,
      completionBody: logValue(completionBody, 0),
    };
  }

  function completeCall(call, status, body) {
    if (call.terminal) return;
    call.terminal = true;
    if (!call.receipt) {
      call.realm.preProviderRejections.push({
        operationName: call.route.operationId,
        operationId: call.route.wireId,
        operationInstanceId: call.operationInstanceId,
        promiseId: call.promiseId,
        providerSequence: 0,
        physicalSequence: 0,
        terminalId: call.preProviderTerminalId || null,
        failurePredicateId: call.preProviderFailurePredicateId || null,
        failurePredicateWireId: call.preProviderFailurePredicateWireId || 0,
        failureClass: call.preProviderFailureClass || null,
        failureTiming: call.preProviderFailureTiming || "promise-rejection",
        requestDeviceFacts: call.requestDeviceFacts
          ? logValue(call.requestDeviceFacts, 0)
          : null,
        status: status,
        body: logValue(body, 0),
      });
      traceRealm(call.realm, "operation-terminal", call, {
        status: status,
        providerBacked: false,
      });
      return;
    }
    if (call.publicationCredit) {
      call.receipt.publicationCreditLedger = publicationCreditSnapshot(
        call.publicationCredit,
      );
    }
    if (call.liveDeviceReservation) {
      call.receipt.liveDeviceCreditLedger = liveDeviceReservationSnapshot(
        call.liveDeviceReservation,
      );
    }
    if (call.preProviderFailurePredicateId) {
      call.receipt.failureProgram = {
        predicateId: call.preProviderFailurePredicateId,
        predicateWireId: call.preProviderFailurePredicateWireId,
        failureClass: call.preProviderFailureClass,
        failureTiming: call.preProviderFailureTiming,
      };
    }
    call.receipt.terminalStatus = status;
    call.receipt.resultHandleRef = typedRef(call.resultState);
    requireClient(call.realm.client).events.push(operationCompleteEvent(call, status, body));
    traceRealm(call.realm, "operation-terminal", call, {
      status: status,
      providerBacked: true,
    });
  }

  function errorFilterFor(name) {
    if (name === "GPUOutOfMemoryError") return "out-of-memory";
    if (name === "GPUInternalError") return "internal";
    return "validation";
  }

  function captureDeviceError(device, call, name, message) {
    var error = namedError(name, message);
    var captured = false;
    for (var index = device.serviceScopes.length - 1; index >= 0; index -= 1) {
      var scope = device.serviceScopes[index];
      if (scope.id === call.capturedScopeId && scope.filter === errorFilterFor(name)) {
        if (!scope.error) scope.error = error;
        captured = true;
        break;
      }
    }
    if (!captured) device.uncapturedErrors.push(error);
    return error;
  }

  function deliverLogicalError(device, call, name, message) {
    return captureDeviceError(device, call, name, message);
  }

  function deliverPhysicalError(device, call, errorSpec, physicalSequence) {
    if (!physicalSequence) {
      throw new Error("physical provider error lacks an admitted physical sequence");
    }
    requireClient(call.realm.client).events.push({
      tag: "physical-error-record-service-event-v1",
      kind: "physical-error-record",
      physicalOperationKey: {
        realmGeneration: call.realm.generation,
        topology: 1,
        providerGeneration: device.providerGeneration,
        logicalDeviceId: device.id,
        deviceIngressOrdinal: call.deviceIngressOrdinal,
        queueIngressOrdinal: call.queueIngressOrdinal,
        physicalSequence: physicalSequence,
        capturedScopeId: call.capturedScopeId,
        accountId: call.realm.accountToken,
        authorityContextDigest: plan.digests.projection,
        operationId: call.route.wireId,
      },
      backendClass: errorSpec.failureClass,
      terminalState: "error",
      publicErrorClass: errorSpec.name,
      redactedDiagnostic: errorSpec.message,
    });
    return captureDeviceError(device, call, errorSpec.name, errorSpec.message);
  }

  function flushLocalPrefix(device) {
    if (!device || device.pendingLocal.length === 0) return [];
    var prefix = device.pendingLocal.splice(0, device.pendingLocal.length);
    for (var index = 0; index < prefix.length; index += 1) {
      var pending = prefix[index];
      if (pending.error) {
        deliverLogicalError(
          device,
          pending.call,
          pending.error.name,
          pending.error.message,
        );
      }
    }
    return prefix.map(function (pending) {
      return {
        operationId: pending.call.route.wireId,
        operationName: pending.call.route.operationId,
        operationInstanceId: pending.call.operationInstanceId,
        deviceIngressOrdinal: pending.call.deviceIngressOrdinal,
        capturedScopeId: pending.call.capturedScopeId,
        receiverRef: typedRef(pending.call.wireReceiverState),
        wrapperAllocatedTargetRef: typedRef(pending.call.targetState),
        argumentBody: logValue(pending.payload, 0),
        logicalError: pending.error ? logValue(pending.error, 0) : null,
      };
    });
  }

  function serviceCall(client, call, argumentBody, pendingPromise, errorSpec) {
    var clientState = requireClient(client);
    var sealedLocalTimelinePrefix = flushLocalPrefix(call.device);
    var localTimelineInvalid = false;
    for (
      var localIndex = 0;
      localIndex < sealedLocalTimelinePrefix.length;
      localIndex += 1
    ) {
      if (sealedLocalTimelinePrefix[localIndex].logicalError) {
        localTimelineInvalid = true;
        break;
      }
    }
    if (
      !errorSpec &&
      call.route.operationId === "GPUQueue.submit" &&
      localTimelineInvalid
    ) {
      errorSpec = {
        name: "GPUValidationError",
        message: "sealed command program contains invalid recorded commands",
        failureClass: "validation-error",
        physical: false,
      };
    }
    if (!errorSpec && call.device && call.device.nextForcedError) {
      errorSpec = call.device.nextForcedError;
      call.device.nextForcedError = null;
    }
    if (
      call.providerAdmissionOverride === true &&
      call.route.providerSubmission === "none"
    ) {
      throw new Error("provider entry selected for an operation with no provider submission");
    }
    var providerEntrySelected =
      call.providerAdmissionOverride === true ||
      (call.providerAdmissionOverride !== false &&
        call.route.fakeProviderEntry === true);
    var providerAdmitted =
      providerEntrySelected && (!errorSpec || errorSpec.physical === true);
    var physicalSequence = providerAdmitted ? ++call.realm.nextPhysicalSequence : 0;
    var physicalDevice =
      call.resultState && call.resultState.device
        ? call.resultState.device
        : call.ingressDevice;
    var receipt = {
      operationName: call.route.operationId,
      operationId: call.route.wireId,
      semanticSha256: call.route.semanticSha256,
      dispatchClass: call.route.dispatchClass,
      logicalExecutionKind: call.route.logicalExecutionKind,
      resultTiming: call.route.resultTiming,
      publicArgumentCodec: call.route.publicArgumentCodec,
      serviceArgumentCodec: call.route.serviceArgumentCodec,
      publicResultCodec: call.route.publicResultCodec,
      serviceCompletionCodec: call.route.serviceCompletionCodec,
      operationInstanceIdentity: call.route.operationInstanceIdentity,
      promiseIdentity: call.route.promiseIdentity,
      providerSubmission: call.route.providerSubmission,
      fakeProviderEntry: call.route.fakeProviderEntry,
      providerAdmission: {
        admitted: providerAdmitted,
        providerTokenCount: providerAdmitted ? 1 : 0,
        reason: providerAdmitted
          ? "deterministic-fake-provider-entry"
          : errorSpec
            ? "semantic-rejection-before-provider"
            : call.providerAdmissionOverride === false
              ? "service-local-terminal"
              : "operation-has-no-fake-provider-entry",
      },
      requestDeviceTerminalId: call.requestDeviceTerminalId || null,
      requestDeviceTerminal: call.requestDeviceTerminal
        ? logValue(call.requestDeviceTerminal, 0)
        : null,
      publicationCreditId: call.publicationCreditId || 0,
      publicationCreditLeaseOrdinal: call.publicationCreditLeaseOrdinal || 0,
      publicationCreditDisposition: call.requestDeviceTerminal
        ? call.requestDeviceTerminal.publicationCreditDisposition
        : null,
      publicationCreditLedger: call.publicationCredit
        ? publicationCreditSnapshot(call.publicationCredit)
        : null,
      liveDeviceCreditLedger: call.liveDeviceReservation
        ? liveDeviceReservationSnapshot(call.liveDeviceReservation)
        : null,
      failureProgram: null,
      operationInstanceId: call.operationInstanceId,
      promiseId: call.promiseId,
      receiverRef: typedRef(call.wireReceiverState),
      wrapperAllocatedTargetRef: typedRef(call.targetState),
      resultHandleRef: typedRef(call.resultState),
      untrustedWrapperPayload: {
        operationId: call.route.wireId,
        serviceArgumentCodec: call.route.serviceArgumentCodec,
        operationInstanceId: call.operationInstanceId,
        promiseId: call.promiseId,
        receiverRef: typedRef(call.wireReceiverState),
        wrapperAllocatedTargetRef: typedRef(call.targetState),
        argumentBody: logValue(argumentBody, 0),
      },
      authenticatedIngressContext: {
        runtimePointerNonce: clientState.runtimePointerNonce,
        realmToken: call.realm.token,
        realmGeneration: call.realm.generation,
        accountToken: call.realm.accountToken,
        accountGeneration: call.realm.accountGeneration,
        logicalDeviceId: call.ingressDevice ? call.ingressDevice.id : 0,
        logicalDeviceGeneration: call.ingressDevice
          ? call.ingressDevice.generation
          : 0,
        providerGeneration:
          call.operationProviderGeneration ||
          (call.ingressDevice ? call.ingressDevice.providerGeneration : 0),
        authorityContextDigest: plan.digests.projection,
        topology: 1,
        operationId: call.route.wireId,
        operationInstanceId: call.operationInstanceId,
        promiseId: call.promiseId,
        adapterOperationOrdinal: call.adapterOperationOrdinal,
        deviceIngressOrdinal: call.deviceIngressOrdinal,
        queueIngressOrdinal: call.queueIngressOrdinal,
        receiverRef: typedRef(call.wireReceiverState),
        wrapperAllocatedTargetRef: typedRef(call.targetState),
        capturedScopeId: call.capturedScopeId,
      },
      physicalOperationKey: {
        realmGeneration: call.realm.generation,
        topology: 1,
        providerGeneration:
          call.operationProviderGeneration ||
          (physicalDevice ? physicalDevice.providerGeneration : 0),
        logicalDeviceId: physicalDevice ? physicalDevice.id : 0,
        deviceIngressOrdinal: call.deviceIngressOrdinal,
        queueIngressOrdinal: call.queueIngressOrdinal,
        physicalSequence: physicalSequence,
        capturedScopeId: call.capturedScopeId,
        accountId: call.realm.accountToken,
        authorityContextDigest: plan.digests.projection,
        operationId: call.route.wireId,
      },
      sealedLocalTimelinePrefix: sealedLocalTimelinePrefix,
      terminalStatus: pendingPromise ? "pending" : errorSpec ? "error" : "ok",
    };
    call.receipt = receipt;
    traceRealm(
      call.realm,
      providerAdmitted ? "provider-entry" : "no-provider-entry",
      call,
      {
        physicalSequence: physicalSequence,
        providerTokenCount: providerAdmitted ? 1 : 0,
      },
    );
    if (call.requestDeviceTerminal) {
      if (
        receipt.providerAdmission.providerTokenCount !==
          call.requestDeviceTerminal.providerTokenCount ||
        (physicalSequence ? 1 : 0) !==
          call.requestDeviceTerminal.physicalSequenceCount
      ) {
        throw new Error("fake requestDevice admission disagrees with authenticated terminal");
      }
    }
    clientState.receipts.push(receipt);
    if (errorSpec && call.device) {
      if (errorSpec.physical === true) {
        deliverPhysicalError(call.device, call, errorSpec, physicalSequence);
      } else {
        deliverLogicalError(call.device, call, errorSpec.name, errorSpec.message);
      }
    }
    if (!pendingPromise) completeCall(call, errorSpec ? "error" : "ok", errorSpec || {});
    return receipt;
  }

  function appendLocal(call, payload, errorSpec) {
    if (!call.device) throw new Error("local operation lacks a logical device");
    call.device.pendingLocal.push({
      call: call,
      payload: payload || {},
      error: errorSpec || null,
    });
  }

  function promiseOperation(call, action) {
    if (!call.promiseId) call.promiseId = allocatePromiseId(call);
    var state = { call: call, cancelled: false, closed: false };
    var promise = new Promise(function (resolve, reject) {
      Promise.resolve().then(function () {
        try {
          if (state.cancelled) throw namedError("OperationError", "operation was cancelled");
          if (state.closed) {
            throw namedError("SecurityError", "realm is closed");
          }
          var result = action();
          completeCall(call, "ok", result);
          traceRealm(call.realm, "promise-resolve", call, {});
          resolve(result);
        } catch (error) {
          completeCall(call, "rejected", {
            name: error.name || "Error",
            message: error.message || String(error),
          });
          traceRealm(call.realm, "promise-reject", call, {
            errorName: error.name || "Error",
          });
          reject(error);
        }
      });
    });
    promiseStates.set(promise, state);
    call.realm.pendingPromises.push(state);
    return promise;
  }

  function createLostInfo(reason, message, realm) {
    var info = Object.create(realm.prototypes.GPUDeviceLostInfo);
    Object.defineProperty(info, "reason", { value: reason, enumerable: true });
    Object.defineProperty(info, "message", { value: message, enumerable: true });
    return Object.freeze(info);
  }

  function loseDevice(device, reason, message, emitProviderLoss, initiatingCall) {
    if (device.lostSettled) return;
    device.lostSettled = true;
    releaseLiveDeviceCredits(device);
    device.destroyed = reason === "destroyed" || device.destroyed;
    var client = requireClient(device.realm.client);
    if (emitProviderLoss) {
      client.events.push({
        tag: "provider-loss-record-service-event-v1",
        kind: "provider-loss-record",
        realmToken: device.realm.token,
        realmGeneration: device.realm.generation,
        topology: 1,
        providerGeneration: device.providerGeneration,
        lastAcceptedPhysicalSequence: device.realm.nextPhysicalSequence,
        initiatingOperationKey: null,
        backendClass: "provider-loss",
        redactedDiagnostic: message,
      });
    }
    client.events.push({
      tag: "device-loss-service-event-v1",
      kind: "device-loss",
      realmToken: device.realm.token,
      realmGeneration: device.realm.generation,
      accountToken: device.realm.accountToken,
      accountGeneration: device.realm.accountGeneration,
      logicalDeviceId: device.id,
      logicalDeviceGeneration: device.generation,
      providerGeneration: device.providerGeneration,
      lastAcceptedPhysicalSequence: device.realm.nextPhysicalSequence,
      lossReason: reason,
      redactedDiagnostic: message,
      lostSettlementOrdinal: ++device.realm.nextLostSettlement,
    });
    traceRealm(device.realm, "device-lost-settle", initiatingCall || null, {
      logicalDeviceId: device.id,
      reason: reason,
    });
    device.resolveLost(createLostInfo(reason, message, device.realm));
  }

  function createDevice(realm, providerGeneration, serviceDetached) {
    var resolveLost;
    var lost = new Promise(function (resolve) {
      resolveLost = resolve;
    });
    var device = {
      realm: realm,
      id: realm.nextDevice++,
      generation: 1,
      providerGeneration: providerGeneration,
      serviceDetached: Boolean(serviceDetached),
      nextIngress: 1,
      nextQueueIngress: 1,
      nextScope: 1,
      localScopes: [],
      serviceScopes: [],
      pendingLocal: [],
      uncapturedErrors: [],
      nextForcedError: null,
      destroyed: false,
      lostSettled: false,
      lost: lost,
      resolveLost: resolveLost,
      liveDeviceReservation: null,
    };
    var wrapper = allocateWrapper(realm, "GPUDevice", device, {});
    var state = wrapperStates.get(wrapper);
    state.device = device;
    device.wrapper = wrapper;
    device.state = state;
    device.features = createFeatureSet(realm, plan.fakeClientData.adapterFeatures);
    var limits = {};
    var limitRows = plan.semantic.limitPolicy.limits;
    for (var index = 0; index < limitRows.length; index += 1) {
      limits[limitRows[index].name] = limitRows[index].profileBucket.core;
    }
    device.limits = Object.freeze(limits);
    device.queue = allocateWrapper(realm, "GPUQueue", device, {});
    realm.devices.push(device);
    return wrapper;
  }

  function serviceError(call, payload, name, message, failureClass) {
    serviceCall(call.realm.client, call, payload, false, {
      name: name,
      message: message,
      failureClass: failureClass,
    });
  }

  function deviceIsUnavailable(device) {
    return (
      device.destroyed ||
      device.lostSettled ||
      device.realm.closed ||
      device.realm.accountClosed
    );
  }

  function expireCurrentTexture(contextState) {
    if (!contextState.currentTexture) return;
    var textureState = wrapperStates.get(contextState.currentTexture);
    textureState.expired = true;
    contextState.currentTexture = null;
  }

  function allocatePromiseId(call) {
    var promiseId = call.realm.nextPromise++;
    if (promiseId === call.operationInstanceId) promiseId = call.realm.nextPromise++;
    return promiseId;
  }

  function assertRealmAdmission(realm) {
    if (realm.closed) throw namedError("SecurityError", "realm is closed");
    if (realm.accountClosed) throw namedError("SecurityError", "GPU account is closed");
  }

  function closeAccountState(realm, cause, initiatingCall, deferredCredit) {
    if (realm.accountClosed) return false;
    realm.accountClosed = true;
    var ordinal = realm.nextLifecycleOrdinal++;
    var reason = String(cause || "test-account-close");
    var client = requireClient(realm.client);
    client.lifecycle.push({
      kind: "accountClose",
      realmToken: realm.token,
      realmGeneration: realm.generation,
      accountToken: realm.accountToken,
      accountGeneration: realm.accountGeneration,
      closeOrdinal: ordinal,
      closeCause: reason,
    });
    client.events.push({
      tag: "account-close-service-event-v1",
      kind: "account-close",
      realmToken: realm.token,
      realmGeneration: realm.generation,
      accountToken: realm.accountToken,
      accountGeneration: realm.accountGeneration,
      closeOrdinal: ordinal,
      closeCause: reason,
      winningDiagnostic: "account closed",
    });
    traceRealm(realm, "account-close", initiatingCall || null, {
      closeOrdinal: ordinal,
    });
    for (var adapterIndex = 0; adapterIndex < realm.adapters.length; adapterIndex += 1) {
      var credit = realm.adapters[adapterIndex].publicationCredit;
      if (credit !== deferredCredit) retirePublicationCredit(credit);
    }
    for (var deviceIndex = 0; deviceIndex < realm.devices.length; deviceIndex += 1) {
      loseDevice(
        realm.devices[deviceIndex],
        "unknown",
        "account closed",
        false,
        initiatingCall || null,
      );
    }
    return true;
  }

  function publicationCreditSnapshot(credit) {
    return {
      id: credit.id,
      state: credit.state,
      ownerAdapterHandle: credit.ownerAdapterHandle,
      leaseOrdinal: credit.leaseOrdinal,
      activeOperationInstanceId: credit.activeOperationInstanceId,
      acquireCount: credit.acquireCount,
      returnCount: credit.returnCount,
      retireCount: credit.retireCount,
    };
  }

  function acquirePublicationCredit(adapter, call) {
    var credit = adapter.publicationCredit;
    if (credit.state !== "available") {
      throw new Error("publication credit is not available");
    }
    credit.state = "leased";
    credit.leaseOrdinal += 1;
    credit.activeOperationInstanceId = call.operationInstanceId;
    credit.acquireCount += 1;
    call.publicationCredit = credit;
    call.publicationCreditId = credit.id;
    call.publicationCreditLeaseOrdinal = credit.leaseOrdinal;
  }

  function returnPublicationCredit(call) {
    var credit = call.publicationCredit;
    if (!credit || credit.state !== "leased") {
      throw new Error("publication credit cannot be returned from its current state");
    }
    credit.state = "available";
    credit.activeOperationInstanceId = 0;
    credit.returnCount += 1;
  }

  function retirePublicationCredit(credit) {
    if (!credit || credit.state === "retired") return;
    if (credit.state !== "available" && credit.state !== "leased") {
      throw new Error("publication credit cannot be retired from its current state");
    }
    credit.state = "retired";
    credit.activeOperationInstanceId = 0;
    credit.retireCount += 1;
  }

  function liveDeviceReservationSnapshot(reservation) {
    return {
      id: reservation.id,
      state: reservation.state,
      ownerDeviceId: reservation.ownerDeviceId,
      operationInstanceId: reservation.operationInstanceId,
      leafCreditState: reservation.leafCreditState,
      aggregateCreditState: reservation.aggregateCreditState,
      commitCount: reservation.commitCount,
      releaseCount: reservation.releaseCount,
    };
  }

  function commitLiveDeviceCredits(device, call) {
    var ledger = device.realm.liveDeviceLedger;
    if (
      ledger.leafActive >= ledger.capacity ||
      ledger.aggregateActive >= ledger.capacity
    ) {
      throw new Error("fake live-device capacity was exhausted unexpectedly");
    }
    var reservation = {
      id: ledger.nextReservationId++,
      state: "committed",
      ownerDeviceId: device.id,
      operationInstanceId: call.operationInstanceId,
      leafCreditState: "owned-by-device",
      aggregateCreditState: "owned-by-device",
      commitCount: 1,
      releaseCount: 0,
    };
    ledger.commitCount += 1;
    ledger.leafActive += 1;
    ledger.aggregateActive += 1;
    ledger.reservations.push(reservation);
    device.liveDeviceReservation = reservation;
    call.liveDeviceReservation = reservation;
  }

  function releaseLiveDeviceCredits(device) {
    var reservation = device.liveDeviceReservation;
    if (!reservation || reservation.state === "released") return;
    if (reservation.state !== "committed") {
      throw new Error("live-device credit cannot be released from its current state");
    }
    var ledger = device.realm.liveDeviceLedger;
    reservation.state = "released";
    reservation.leafCreditState = "released";
    reservation.aggregateCreditState = "released";
    reservation.releaseCount += 1;
    ledger.releaseCount += 1;
    ledger.leafActive -= 1;
    ledger.aggregateActive -= 1;
  }

  function requestDeviceFailurePredicate(terminal, preferredPredicateId) {
    var source = terminal.errorSource;
    if (!source || source.kind !== "first-failing-predicate") {
      throw new Error(
        "requestDevice terminal has no authenticated failing predicate: " +
          terminal.terminalId,
      );
    }
    var branches = plan.semantic.requestDeviceFailureProgram.branches;
    for (var branchIndex = 0; branchIndex < branches.length; branchIndex += 1) {
      var branch = branches[branchIndex];
      if (branch.branchId !== source.branchId) continue;
      for (
        var predicateIndex = 0;
        predicateIndex < branch.orderedPredicates.length;
        predicateIndex += 1
      ) {
        var predicate = branch.orderedPredicates[predicateIndex];
        if (
          predicate.failureClass !== "none" &&
          (!preferredPredicateId || predicate.predicateId === preferredPredicateId)
        ) {
          return predicate;
        }
      }
    }
    throw new Error(
      "requestDevice terminal cannot select authenticated predicate: " +
        terminal.terminalId,
    );
  }

  function requestDeviceError(failureClass, message) {
    if (failureClass === "type-error") return typeError(message);
    if (failureClass === "operation-error") return namedError("OperationError", message);
    if (failureClass === "security-error") return namedError("SecurityError", message);
    throw new Error("unknown authenticated requestDevice failure class: " + failureClass);
  }

  function requestDeviceRejection(call, terminal, preferredPredicateId, message) {
    var predicate = requestDeviceFailurePredicate(terminal, preferredPredicateId);
    call.preProviderTerminalId = terminal.terminalId;
    call.preProviderFailurePredicateId = predicate.predicateId;
    call.preProviderFailurePredicateWireId = predicate.predicateWireId;
    call.preProviderFailureClass = predicate.failureClass;
    call.preProviderFailureTiming = predicate.failureTiming;
    return requestDeviceError(predicate.failureClass, message);
  }

  function isPowerOfTwo(value) {
    if (value <= 0 || value >= 4294967296) return false;
    var remaining = value;
    while (remaining % 2 === 0) remaining /= 2;
    return remaining === 1;
  }

  function validateDeviceDescriptor(copy) {
    var requiredFeatures = copy.requiredFeatures;
    if (requiredFeatures === undefined) requiredFeatures = [];
    if (!Array.isArray(requiredFeatures)) {
      return {
        fact: "requiredFeaturesSupported",
        predicateId: "adapter.request-device.required-features",
        message: "requiredFeatures must be a sequence",
      };
    }
    for (var featureIndex = 0; featureIndex < requiredFeatures.length; featureIndex += 1) {
      if (
        typeof requiredFeatures[featureIndex] !== "string" ||
        plan.fakeClientData.adapterFeatures.indexOf(requiredFeatures[featureIndex]) === -1
      ) {
        return {
          fact: "requiredFeaturesSupported",
          predicateId: "adapter.request-device.required-features",
          message: "unsupported required feature",
        };
      }
    }

    var requiredLimits = copy.requiredLimits;
    if (requiredLimits === undefined) requiredLimits = {};
    if (requiredLimits === null || typeof requiredLimits !== "object") {
      return {
        fact: "adapterRequestValid",
        predicateId: "adapter.request-device.limits",
        message: "requiredLimits must be a dictionary",
      };
    }
    var rows = plan.semantic.limitPolicy.limits;
    var rowByName = Object.create(null);
    for (var rowIndex = 0; rowIndex < rows.length; rowIndex += 1) {
      rowByName[rows[rowIndex].name] = rows[rowIndex];
    }
    var names = Object.keys(requiredLimits);
    for (var nameIndex = 0; nameIndex < names.length; nameIndex += 1) {
      var name = names[nameIndex];
      var requested = requiredLimits[name];
      if (requested === undefined) continue;
      var row = rowByName[name];
      if (!row || row.requestable !== true) {
        return {
          fact: "adapterRequestValid",
          predicateId: "adapter.request-device.limits",
          message: "unknown or non-requestable required limit",
        };
      }
      var number;
      try {
        number = Number(requested);
      } catch (error) {
        return {
          fact: "adapterRequestValid",
          predicateId: "adapter.request-device.limits",
          message: "required limit is not numeric",
        };
      }
      if (!Number.isFinite(number) || Math.floor(number) !== number || number < 0) {
        return {
          fact: "adapterRequestValid",
          predicateId: "adapter.request-device.limits",
          message: "required limit is not a nonnegative integer",
        };
      }
      var profileBoundary = row.profileBucket.core;
      var grantBoundary = row.capabilityGrantBoundary.core;
      if (row.class === "maximum") {
        var maximumBoundary = Math.min(profileBoundary, grantBoundary);
        if (number > maximumBoundary) {
          return {
            fact: "adapterRequestValid",
            predicateId: "adapter.request-device.limits",
            message: "required maximum is better than the boundary",
          };
        }
      } else {
        var alignmentBoundary = Math.max(profileBoundary, grantBoundary);
        if (!isPowerOfTwo(number) || number < alignmentBoundary) {
          return {
            fact: "adapterRequestValid",
            predicateId: "adapter.request-device.limits",
            message: "required alignment is better than the boundary",
          };
        }
      }
    }
    return null;
  }

  function selectRequestDeviceTerminal(adapter, directFacts) {
    var realmAdmissionLive = !adapter.realm.closed && !adapter.realm.accountClosed;
    var facts = {
      webidlValid: true,
      requiredFeaturesSupported: true,
      adapterRequestValid: true,
      deviceAdmissionValid: realmAdmissionLive,
      adapterExpired: Boolean(adapter.expired),
      deviceExpiryResultCommitLive: true,
      deviceReservationCapacityAvailable: true,
      deviceCapacityResultCommitLive: true,
      deviceReservationCommitLive: true,
      providerFulfilled: true,
      deviceAccountLiveAtProviderCompletion: true,
      deviceAccountLiveAtSettlementCommit: true,
      providerInabilityWonLossRace: false,
    };
    var overrides = adapter.nextRequestDeviceFacts || {};
    adapter.nextRequestDeviceFacts = null;
    var overrideNames = Object.keys(overrides);
    for (var overrideIndex = 0; overrideIndex < overrideNames.length; overrideIndex += 1) {
      var overrideName = overrideNames[overrideIndex];
      if (overrideName === "deviceAdmissionValid") {
        facts.deviceAdmissionValid =
          facts.deviceAdmissionValid && overrides.deviceAdmissionValid;
      } else {
        facts[overrideName] = overrides[overrideName];
      }
    }
    var directNames = directFacts ? Object.keys(directFacts) : [];
    for (var directIndex = 0; directIndex < directNames.length; directIndex += 1) {
      facts[directNames[directIndex]] = directFacts[directNames[directIndex]];
    }
    var terminals = plan.semantic.requestDeviceRouting.terminals;
    for (var terminalIndex = 0; terminalIndex < terminals.length; terminalIndex += 1) {
      var terminal = terminals[terminalIndex];
      var conditionNames = Object.keys(terminal.conditions);
      var matches = true;
      for (var conditionIndex = 0; conditionIndex < conditionNames.length; conditionIndex += 1) {
        var condition = conditionNames[conditionIndex];
        if (facts[condition] !== terminal.conditions[condition]) {
          matches = false;
          break;
        }
      }
      if (matches) {
        var admissionFailurePredicateId = null;
        if (
          terminal.errorSource &&
          terminal.errorSource.kind === "first-failing-predicate" &&
          terminal.errorSource.branchId === "live-admission"
        ) {
          admissionFailurePredicateId = adapter.realm.closed
            ? "adapter.request-device.realm"
            : adapter.realm.accountClosed
              ? "adapter.request-device.account"
              : "adapter.request-device.coverage";
        }
        return {
          terminal: terminal,
          admissionFailurePredicateId: admissionFailurePredicateId,
          facts: facts,
        };
      }
    }
    throw new Error("authenticated requestDevice precedence selected no terminal");
  }

  function lostDiagnostic(terminal) {
    var source = terminal.lostSettlement.diagnosticSource;
    if (source === "generic-expired-adapter") return "adapter is expired";
    if (source === "generic-capacity-unavailable") return "device capacity is unavailable";
    if (source === "generic-provider-inability") return "provider could not create a device";
    return "GPU account closed";
  }

  function terminalRequiresAccountClose(terminal) {
    return (
      terminal.publicationCreditDisposition.indexOf("account-close") !== -1 ||
      terminal.conditions.deviceAccountLiveAtProviderCompletion === false ||
      terminal.conditions.deviceAccountLiveAtSettlementCommit === false
    );
  }

  function traceProviderCompletion(call, facts) {
    traceRealm(call.realm, "provider-completion", call, {
      providerFulfilled: facts.providerFulfilled,
      accountLive: facts.deviceAccountLiveAtProviderCompletion,
    });
  }

  function settleTerminalPublication(call, terminal, closeAlreadyWon) {
    var disposition = terminal.publicationCreditDisposition;
    if (disposition === "account-close-retired-exactly-once") {
      if (!closeAlreadyWon) {
        closeAccountState(
          call.realm,
          "authenticated requestDevice close terminal",
          call,
          null,
        );
      }
      retirePublicationCredit(call.publicationCredit);
      return;
    }
    if (disposition === "returned-to-adapter-reusable-after-public-settlement") {
      returnPublicationCredit(call);
      return;
    }
    if (
      disposition ===
      "returned-after-public-settlement-then-account-close-retired-exactly-once"
    ) {
      returnPublicationCredit(call);
      if (!closeAlreadyWon) {
        closeAccountState(
          call.realm,
          "authenticated requestDevice close terminal",
          call,
          null,
        );
      }
      retirePublicationCredit(call.publicationCredit);
      return;
    }
    throw new Error("unknown acquired publication-credit disposition: " + disposition);
  }

  defineMethod(prototypeFor("GPU"), "getPreferredCanvasFormat", function () {
    var state = requireReceiver(this, "GPU");
    beginPublic(state.realm, "GPU.getPreferredCanvasFormat", state, null);
    return "bgra8unorm";
  });

  defineMethod(prototypeFor("GPU"), "requestAdapter", function (options) {
    var state = requireReceiver(this, "GPU");
    var call = beginPublic(state.realm, "GPU.requestAdapter", state, null);
    call.promiseId = allocatePromiseId(call);
    return promiseOperation(call, function () {
      var copy = snapshotDictionary(options, "GPURequestAdapterOptions");
      assertRealmAdmission(state.realm);
      call.operationProviderGeneration = state.realm.nextProviderGeneration++;
      serviceCall(state.realm.client, call, copy, true, null);
      if (state.realm.requestAdapterUnavailable) return null;
      var adapter = allocateWrapper(state.realm, "GPUAdapter", null, {
        expired: false,
        providerGeneration: call.operationProviderGeneration,
        nextRequestDeviceOrdinal: 1,
        publicationCredit: null,
      });
      var adapterState = wrapperStates.get(adapter);
      adapterState.publicationCredit = {
        id: state.realm.nextPublicationCredit++,
        state: "available",
        ownerAdapterHandle: adapterState.handle,
        leaseOrdinal: 0,
        activeOperationInstanceId: 0,
        acquireCount: 0,
        returnCount: 0,
        retireCount: 0,
      };
      state.realm.adapters.push(adapterState);
      setCallResult(call, wrapperStates.get(adapter));
      return adapter;
    });
  });

  defineMethod(prototypeFor("GPUAdapter"), "requestDevice", function (descriptor) {
    var adapter = requireReceiver(this, "GPUAdapter");
    var call = beginPublic(adapter.realm, "GPUAdapter.requestDevice", adapter, null);
    call.promiseId = allocatePromiseId(call);
    return promiseOperation(call, function () {
      var copy;
      var descriptorFailure = null;
      var selection;
      try {
        copy = snapshotDictionary(descriptor, "GPUDeviceDescriptor");
      } catch (error) {
        selection = selectRequestDeviceTerminal(adapter, { webidlValid: false });
        call.requestDeviceFacts = selection.facts;
        throw requestDeviceRejection(
          call,
          selection.terminal,
          "adapter.request-device.webidl",
          error.message || "GPUDeviceDescriptor conversion failed",
        );
      }
      descriptorFailure = validateDeviceDescriptor(copy);
      var descriptorFacts = {};
      if (descriptorFailure) descriptorFacts[descriptorFailure.fact] = false;
      selection = selectRequestDeviceTerminal(adapter, descriptorFacts);
      var terminal = selection.terminal;
      call.requestDeviceFacts = selection.facts;
      if (terminal.publicationCreditDisposition === "not-acquired") {
        throw requestDeviceRejection(
          call,
          terminal,
          descriptorFailure
            ? descriptorFailure.predicateId
            : selection.admissionFailurePredicateId,
          descriptorFailure
            ? descriptorFailure.message
            : "logical device admission was rejected",
        );
      }
      call.preProviderTerminalId = null;
      acquirePublicationCredit(adapter, call);
      var device;
      call.requestDeviceTerminalId = terminal.terminalId;
      call.requestDeviceTerminal = terminal;
      call.providerAdmissionOverride = terminal.providerTokenCount === 1;

      if (terminal.resultDisposition === "promise-reject") {
        serviceCall(adapter.realm.client, call, copy, true, null);
        if (terminal.adapterStateAfterSettlement === "expired") adapter.expired = true;
        settleTerminalPublication(call, terminal, false);
        throw requestDeviceRejection(
          call,
          terminal,
          null,
          "requestDevice lost a close race",
        );
      }

      if (terminal.resultDisposition === "promise-resolve-lost-object") {
        device = createDevice(
          adapter.realm,
          adapter.providerGeneration,
          true,
        );
        setCallResult(call, wrapperStates.get(device));
        if (terminal.providerTokenCount === 1) {
          commitLiveDeviceCredits(call.resultState.device, call);
        }
        serviceCall(adapter.realm.client, call, copy, true, null);
        var closeWonBeforeLoss =
          terminalRequiresAccountClose(terminal) &&
          terminal.lostSettlement.arbiterWinner === "account-close";
        if (
          terminal.providerTokenCount === 1 &&
          selection.facts.deviceAccountLiveAtProviderCompletion !== false
        ) {
          traceProviderCompletion(call, selection.facts);
        }
        if (closeWonBeforeLoss) {
          closeAccountState(
            call.realm,
            "authenticated requestDevice account-close winner",
            call,
            call.publicationCredit,
          );
        }
        if (
          terminal.providerTokenCount === 1 &&
          selection.facts.deviceAccountLiveAtProviderCompletion === false
        ) {
          traceProviderCompletion(call, selection.facts);
        }
        loseDevice(
          call.resultState.device,
          terminal.lostSettlement.reason,
          lostDiagnostic(terminal),
          false,
          call,
        );
        if (terminal.adapterStateAfterSettlement === "expired") adapter.expired = true;
        settleTerminalPublication(call, terminal, closeWonBeforeLoss);
        return device;
      }

      device = createDevice(
        adapter.realm,
        adapter.providerGeneration,
        false,
      );
      setCallResult(call, wrapperStates.get(device));
      commitLiveDeviceCredits(call.resultState.device, call);
      serviceCall(adapter.realm.client, call, copy, true, null);
      traceProviderCompletion(call, selection.facts);
      if (terminal.adapterStateAfterSettlement === "expired") adapter.expired = true;
      settleTerminalPublication(call, terminal, false);
      return device;
    });
  });

  defineMethod(prototypeFor("GPUCanvasContext"), "configure", function (configuration) {
    var context = requireReceiver(this, "GPUCanvasContext");
    var copy = snapshotDictionary(configuration, "GPUCanvasConfiguration");
    var deviceState = argumentState(copy.device, "GPUDevice");
    var call = beginPublic(context.realm, "GPUCanvasContext.configure", context, null);
    if (deviceState.realm !== context.realm) {
      serviceError(
        call,
        { configuration: copy, relationship: "cross-realm-device" },
        "GPUValidationError",
        "cross-realm device",
        "validation-error",
      );
      return;
    }
    assignCallDeviceIngress(call, deviceState.device);
    if (deviceIsUnavailable(call.device)) {
      serviceError(call, {}, "GPUValidationError", "device is unavailable", "invalid-state");
      return;
    }
    expireCurrentTexture(context);
    context.configurationGeneration += 1;
    context.configuration = copy;
    context.configuredDevice = call.device;
    serviceCall(context.realm.client, call, { configuration: copy }, false, null);
  });

  defineMethod(prototypeFor("GPUCanvasContext"), "getConfiguration", function () {
    var context = requireReceiver(this, "GPUCanvasContext");
    beginPublic(context.realm, "GPUCanvasContext.getConfiguration", context, null);
    if (!context.configuration) return null;
    return snapshotDictionary(context.configuration, "GPUCanvasConfiguration");
  });

  defineMethod(prototypeFor("GPUCanvasContext"), "getCurrentTexture", function () {
    var context = requireReceiver(this, "GPUCanvasContext");
    var call = beginPublic(context.realm, "GPUCanvasContext.getCurrentTexture", context, null);
    if (!context.configuration || !context.configuredDevice) {
      throw namedError("InvalidStateError", "canvas context is not configured");
    }
    assignCallDeviceIngress(call, context.configuredDevice);
    if (context.currentTexture) {
      setCallPreallocatedTarget(
        call,
        wrapperStates.get(context.currentTexture),
      );
      appendLocal(
        call,
        {
          sameEpoch: true,
          mintOrigin: call.targetState.currentOrigin,
        },
        null,
      );
      return context.currentTexture;
    }
    var texture = allocateWrapper(context.realm, "GPUTexture", context.configuredDevice, {
      destroyed: false,
      expired: false,
      materialized: false,
      currentOrigin: {
        contextHandle: context.handle,
        attachmentGeneration: context.attachmentGeneration,
        configurationGeneration: context.configurationGeneration,
        currentEpoch: ++context.currentEpoch,
        mintOperationInstanceId: call.operationInstanceId,
      },
    });
    context.currentTexture = texture;
    setCallPreallocatedTarget(call, wrapperStates.get(texture));
    appendLocal(call, { mintOrigin: call.targetState.currentOrigin }, null);
    return texture;
  });

  defineMethod(prototypeFor("GPUCanvasContext"), "unconfigure", function () {
    var context = requireReceiver(this, "GPUCanvasContext");
    var call = beginPublic(context.realm, "GPUCanvasContext.unconfigure", context, null);
    var wasConfigured = Boolean(context.configuration && context.configuredDevice);
    call.providerAdmissionOverride = wasConfigured;
    if (context.configuredDevice) {
      assignCallDeviceIngress(call, context.configuredDevice);
    }
    serviceCall(
      context.realm.client,
      call,
      { configurationGeneration: context.configurationGeneration },
      false,
      null,
    );
    expireCurrentTexture(context);
    context.configuration = null;
    context.configuredDevice = null;
  });

  defineMethod(prototypeFor("GPUDevice"), "createCommandEncoder", function (descriptor) {
    var state = requireReceiver(this, "GPUDevice");
    var copy = snapshotDictionary(descriptor, "GPUCommandEncoderDescriptor");
    var encoder = allocateWrapper(state.realm, "GPUCommandEncoder", state.device, {
      status: "recording",
      activePass: null,
      records: [],
      invalid: false,
    });
    var call = beginPublic(
      state.realm,
      "GPUDevice.createCommandEncoder",
      state,
      wrapperStates.get(encoder),
    );
    if (deviceIsUnavailable(state.device)) {
      serviceError(call, copy, "GPUValidationError", "device is unavailable", "invalid-state");
    } else {
      serviceCall(state.realm.client, call, copy, false, null);
    }
    return encoder;
  });

  defineMethod(prototypeFor("GPUDevice"), "createShaderModule", function (descriptor) {
    var state = requireReceiver(this, "GPUDevice");
    var copy = snapshotDictionary(descriptor, "GPUShaderModuleDescriptor");
    if (typeof copy.code !== "string") {
      throw typeError("GPUShaderModuleDescriptor.code must be a string");
    }
    var module = allocateWrapper(state.realm, "GPUShaderModule", state.device, {});
    var call = beginPublic(
      state.realm,
      "GPUDevice.createShaderModule",
      state,
      wrapperStates.get(module),
    );
    if (deviceIsUnavailable(state.device)) {
      serviceError(call, copy, "GPUValidationError", "device is unavailable", "invalid-state");
    } else {
      serviceCall(state.realm.client, call, copy, false, null);
    }
    return module;
  });

  defineMethod(prototypeFor("GPUDevice"), "createRenderPipeline", function (descriptor) {
    var state = requireReceiver(this, "GPUDevice");
    var copy = snapshotDictionary(descriptor, "GPURenderPipelineDescriptor");
    var validationMessage = "";
    if (!copy.vertex || typeof copy.vertex !== "object") {
      throw typeError("GPURenderPipelineDescriptor.vertex must be a dictionary");
    }
    var vertexModule = argumentState(copy.vertex.module, "GPUShaderModule");
    if (vertexModule.realm !== state.realm || vertexModule.device !== state.device) {
      validationMessage = "vertex shader module belongs to another realm or device";
    }
    if (copy.fragment !== undefined) {
      if (!copy.fragment || typeof copy.fragment !== "object") {
        throw typeError("GPURenderPipelineDescriptor.fragment must be a dictionary");
      }
      var fragmentModule = argumentState(copy.fragment.module, "GPUShaderModule");
      if (
        fragmentModule.realm !== state.realm ||
        fragmentModule.device !== state.device
      ) {
        validationMessage = "fragment shader module belongs to another realm or device";
      }
    }
    var pipeline = allocateWrapper(state.realm, "GPURenderPipeline", state.device, {});
    var call = beginPublic(
      state.realm,
      "GPUDevice.createRenderPipeline",
      state,
      wrapperStates.get(pipeline),
    );
    if (deviceIsUnavailable(state.device)) validationMessage = "device is unavailable";
    if (validationMessage) {
      serviceError(
        call,
        copy,
        "GPUValidationError",
        validationMessage,
        "validation-error",
      );
    } else {
      serviceCall(state.realm.client, call, copy, false, null);
    }
    return pipeline;
  });

  defineMethod(prototypeFor("GPUDevice"), "destroy", function () {
    var state = requireReceiver(this, "GPUDevice");
    var call = beginPublic(state.realm, "GPUDevice.destroy", state, null);
    var alreadyDestroyed = state.device.destroyed;
    call.providerAdmissionOverride = !alreadyDestroyed;
    serviceCall(
      state.realm.client,
      call,
      { alreadyDestroyed: alreadyDestroyed },
      false,
      null,
    );
    if (!alreadyDestroyed) {
      state.device.destroyed = true;
      loseDevice(state.device, "destroyed", "device was destroyed", false, call);
    }
  });

  defineGetter(prototypeFor("GPUDevice"), "features", function () {
    var state = requireReceiver(this, "GPUDevice");
    beginPublic(state.realm, "GPUDevice.features", state, null);
    return state.device.features;
  });

  defineGetter(prototypeFor("GPUDevice"), "limits", function () {
    var state = requireReceiver(this, "GPUDevice");
    beginPublic(state.realm, "GPUDevice.limits", state, null);
    return state.device.limits;
  });

  defineGetter(prototypeFor("GPUDevice"), "lost", function () {
    var state = requireReceiver(this, "GPUDevice");
    beginPublic(state.realm, "GPUDevice.lost", state, null);
    return state.device.lost;
  });

  defineGetter(prototypeFor("GPUDevice"), "queue", function () {
    var state = requireReceiver(this, "GPUDevice");
    var call = beginPublic(state.realm, "GPUDevice.queue", state, null);
    setCallResult(call, wrapperStates.get(state.device.queue));
    return state.device.queue;
  });

  defineMethod(prototypeFor("GPUDevice"), "pushErrorScope", function (filter) {
    var state = requireReceiver(this, "GPUDevice");
    var convertedFilter = String(filter);
    if (
      convertedFilter !== "validation" &&
      convertedFilter !== "out-of-memory" &&
      convertedFilter !== "internal"
    ) {
      throw typeError("unknown GPUErrorFilter");
    }
    var call = beginPublic(state.realm, "GPUDevice.pushErrorScope", state, null);
    var id = state.device.nextScope++;
    serviceCall(
      state.realm.client,
      call,
      { scopeId: id, filter: convertedFilter },
      false,
      null,
    );
    state.device.localScopes.push(id);
    state.device.serviceScopes.push({ id: id, filter: convertedFilter, error: null });
  });

  defineMethod(prototypeFor("GPUDevice"), "popErrorScope", function () {
    var state = requireReceiver(this, "GPUDevice");
    var call = beginPublic(state.realm, "GPUDevice.popErrorScope", state, null);
    call.promiseId = allocatePromiseId(call);
    var scopeId =
      state.device.localScopes.length > 0
        ? state.device.localScopes[state.device.localScopes.length - 1]
        : 0;
    call.providerAdmissionOverride = scopeId !== 0;
    serviceCall(
      state.realm.client,
      call,
      { scopeId: scopeId, barrier: call.deviceIngressOrdinal },
      true,
      null,
    );
    if (!scopeId) {
      return promiseOperation(call, function () {
        throw namedError("OperationError", "error scope stack is empty");
      });
    }
    state.device.localScopes.pop();
    var scope = state.device.serviceScopes.pop();
    return promiseOperation(call, function () {
      return scope.error;
    });
  });

  defineMethod(prototypeFor("GPUCommandEncoder"), "beginRenderPass", function (descriptor) {
    var encoder = requireReceiver(this, "GPUCommandEncoder");
    var copy = snapshotDictionary(descriptor, "GPURenderPassDescriptor");
    var attachments = copy.colorAttachments;
    if (attachments === undefined) attachments = [];
    if (!Array.isArray(attachments)) {
      throw typeError("colorAttachments must be a sequence");
    }
    var relationshipError = false;
    for (var index = 0; index < attachments.length; index += 1) {
      if (!attachments[index] || typeof attachments[index] !== "object") {
        throw typeError("color attachment must be a dictionary");
      }
      var view = argumentState(attachments[index].view, "GPUTextureView");
      if (view.realm !== encoder.realm || view.device !== encoder.device) {
        relationshipError = true;
      }
    }
    var canOpen =
      encoder.status === "recording" &&
      !encoder.activePass &&
      !encoder.invalid &&
      !relationshipError;
    var pass = allocateWrapper(encoder.realm, "GPURenderPassEncoder", encoder.device, {
      encoder: encoder,
      status: canOpen ? "open" : "invalid",
      records: [],
      invalid: !canOpen,
    });
    var passState = wrapperStates.get(pass);
    var call = beginPublic(
      encoder.realm,
      "GPUCommandEncoder.beginRenderPass",
      encoder,
      passState,
    );
    var errorSpec = null;
    if (encoder.status !== "recording" || encoder.activePass || encoder.invalid) {
      errorSpec = {
        name: "GPUValidationError",
        message: "command encoder cannot begin a pass",
        failureClass: "invalid-state",
      };
    }
    if (relationshipError) {
      errorSpec = {
        name: "GPUValidationError",
        message: "render attachment belongs to another realm or device",
        failureClass: "validation-error",
      };
    }
    if (canOpen) {
      encoder.activePass = passState;
    } else {
      encoder.invalid = true;
    }
    encoder.records.push({ operation: "beginRenderPass", descriptor: copy });
    appendLocal(call, copy, errorSpec);
    return pass;
  });

  defineMethod(prototypeFor("GPUCommandEncoder"), "finish", function (descriptor) {
    var encoder = requireReceiver(this, "GPUCommandEncoder");
    var copy = snapshotDictionary(descriptor, "GPUCommandBufferDescriptor");
    var errorSpec = null;
    if (encoder.status !== "recording" || encoder.activePass || encoder.invalid) {
      errorSpec = {
        name: "GPUValidationError",
        message: "command encoder cannot finish",
        failureClass: "invalid-state",
      };
    }
    encoder.status = "finished";
    encoder.records.push({ operation: "finish", descriptor: copy });
    var buffer = allocateWrapper(encoder.realm, "GPUCommandBuffer", encoder.device, {
      submitted: false,
      invalid: Boolean(errorSpec),
      program: encoder.records.slice(),
    });
    var bufferState = wrapperStates.get(buffer);
    var call = beginPublic(
      encoder.realm,
      "GPUCommandEncoder.finish",
      encoder,
      bufferState,
    );
    appendLocal(call, copy, errorSpec);
    return buffer;
  });

  function toU32(value, label, defaultValue) {
    if (value === undefined) return defaultValue;
    var number = Number(value);
    if (
      !Number.isFinite(number) ||
      Math.floor(number) !== number ||
      number < 0 ||
      number > 4294967295
    ) {
      throw typeError(label + " must be an unsigned 32-bit integer");
    }
    return number;
  }

  defineMethod(
    prototypeFor("GPURenderPassEncoder"),
    "draw",
    function (vertexCount, instanceCount, firstVertex, firstInstance) {
      var pass = requireReceiver(this, "GPURenderPassEncoder");
      if (vertexCount === undefined) {
        throw typeError("vertexCount is required");
      }
      var argumentBody = {
        vertexCount: toU32(vertexCount, "vertexCount", undefined),
        instanceCount: toU32(instanceCount, "instanceCount", 1),
        firstVertex: toU32(firstVertex, "firstVertex", 0),
        firstInstance: toU32(firstInstance, "firstInstance", 0),
      };
      var call = beginPublic(pass.realm, "GPURenderPassEncoder.draw", pass, null);
      var errorSpec =
        pass.status === "open" && !pass.invalid
          ? null
          : {
              name: "GPUValidationError",
              message: "render pass has ended",
              failureClass: "invalid-state",
            };
      pass.records.push({ operation: "draw", arguments: argumentBody });
      pass.encoder.records.push({ operation: "draw", arguments: argumentBody });
      if (errorSpec) {
        pass.invalid = true;
        pass.encoder.invalid = true;
      }
      appendLocal(call, argumentBody, errorSpec);
    },
  );

  defineMethod(prototypeFor("GPURenderPassEncoder"), "setPipeline", function (pipelineValue) {
    var pass = requireReceiver(this, "GPURenderPassEncoder");
    var pipeline = argumentState(pipelineValue, "GPURenderPipeline");
    var call = beginPublic(pass.realm, "GPURenderPassEncoder.setPipeline", pass, null);
    var errorSpec = null;
    if (pipeline.realm !== pass.realm || pipeline.device !== pass.device) {
      errorSpec = {
        name: "GPUValidationError",
        message: "pipeline belongs to another realm or device",
        failureClass: "validation-error",
      };
    } else if (pass.status !== "open" || pass.invalid) {
      errorSpec = {
        name: "GPUValidationError",
        message: "render pass has ended",
        failureClass: "invalid-state",
      };
    }
    var payload = { pipeline: pipelineValue };
    pass.records.push({ operation: "setPipeline", pipeline: pipelineValue });
    pass.encoder.records.push({ operation: "setPipeline", pipeline: pipelineValue });
    if (errorSpec) {
      pass.invalid = true;
      pass.encoder.invalid = true;
    }
    appendLocal(call, payload, errorSpec);
  });

  defineMethod(prototypeFor("GPURenderPassEncoder"), "end", function () {
    var pass = requireReceiver(this, "GPURenderPassEncoder");
    var call = beginPublic(pass.realm, "GPURenderPassEncoder.end", pass, null);
    var errorSpec =
      pass.status === "open"
        ? null
        : {
            name: "GPUValidationError",
            message: "render pass already ended",
            failureClass: "invalid-state",
          };
    pass.status = "ended";
    if (pass.encoder.activePass === pass) pass.encoder.activePass = null;
    if (errorSpec) {
      pass.invalid = true;
      pass.encoder.invalid = true;
    }
    pass.records.push({ operation: "end" });
    pass.encoder.records.push({ operation: "end" });
    appendLocal(call, {}, errorSpec);
  });

  defineMethod(prototypeFor("GPUQueue"), "submit", function (commandBuffers) {
    var queue = requireReceiver(this, "GPUQueue");
    var iteratorMethod =
      commandBuffers === null || commandBuffers === undefined
        ? null
        : commandBuffers[Symbol.iterator];
    if (typeof iteratorMethod !== "function") {
      throw typeError("commandBuffers must be an iterable sequence");
    }
    var buffers = [];
    var iterator = iteratorMethod.call(commandBuffers);
    var step;
    while (!(step = iterator.next()).done) {
      if (buffers.length >= 1024) throw typeError("too many command buffers");
      buffers.push(argumentState(step.value, "GPUCommandBuffer"));
    }
    var call = beginPublic(queue.realm, "GPUQueue.submit", queue, null);
    var errorSpec = null;
    var sealedPrograms = [];
    for (var index = 0; index < buffers.length; index += 1) {
      var buffer = buffers[index];
      if (buffer.realm !== queue.realm || buffer.device !== queue.device) {
        errorSpec = {
          name: "GPUValidationError",
          message: "command buffer belongs to another realm or device",
          failureClass: "validation-error",
        };
      } else if (buffer.submitted) {
        errorSpec = {
          name: "GPUValidationError",
          message: "command buffer is single-use",
          failureClass: "invalid-state",
        };
      } else if (buffer.invalid) {
        errorSpec = {
          name: "GPUValidationError",
          message: "command buffer contains invalid recorded commands",
          failureClass: "validation-error",
        };
      }
      sealedPrograms.push({
        commandBufferRef: typedRef(buffer),
        invalid: Boolean(buffer.invalid),
        program: buffer.invalid ? [] : logValue(buffer.program, 0),
      });
    }
    if (!errorSpec && deviceIsUnavailable(queue.device)) {
      errorSpec = {
        name: "GPUValidationError",
        message: "device is unavailable",
        failureClass: "invalid-state",
      };
    }
    if (JSON.stringify(sealedPrograms).length > plan.maxPayloadBytes) {
      errorSpec = {
        name: "GPUValidationError",
        message: "sealed command program exceeds payload bound",
        failureClass: "validation-error",
      };
    }
    if (!errorSpec) {
      for (index = 0; index < buffers.length; index += 1) buffers[index].submitted = true;
    }
    if (errorSpec) {
      serviceError(
        call,
        { commandBufferRecords: sealedPrograms },
        errorSpec.name,
        errorSpec.message,
        errorSpec.failureClass,
      );
    } else {
      serviceCall(
        queue.realm.client,
        call,
        { commandBufferRecords: sealedPrograms },
        false,
        null,
      );
    }
  });

  defineMethod(prototypeFor("GPUTexture"), "createView", function (descriptor) {
    var texture = requireReceiver(this, "GPUTexture");
    var copy = snapshotDictionary(descriptor, "GPUTextureViewDescriptor");
    var view = allocateWrapper(texture.realm, "GPUTextureView", texture.device, {
      texture: texture,
    });
    var call = beginPublic(
      texture.realm,
      "GPUTexture.createView",
      texture,
      wrapperStates.get(view),
    );
    var invalid =
      texture.destroyed || texture.expired || deviceIsUnavailable(texture.device);
    var payload = {
      descriptor: copy,
      mintOrigin: texture.currentOrigin || null,
    };
    if (invalid) {
      serviceError(call, payload, "GPUValidationError", "texture is not live", "invalid-state");
    } else {
      texture.materialized = true;
      serviceCall(texture.realm.client, call, payload, false, null);
    }
    return view;
  });

  defineMethod(prototypeFor("GPUTexture"), "destroy", function () {
    var texture = requireReceiver(this, "GPUTexture");
    var call = beginPublic(texture.realm, "GPUTexture.destroy", texture, null);
    var payload = {
      mintOrigin: texture.currentOrigin || null,
      materializedBeforeDestroy: Boolean(texture.materialized),
      alreadyDestroyed: Boolean(texture.destroyed),
    };
    call.providerAdmissionOverride = !texture.destroyed;
    serviceCall(texture.realm.client, call, payload, false, null);
    texture.destroyed = true;
  });

  Object.freeze(prototypeFor("GPU"));
  Object.freeze(prototypeFor("GPUAdapter"));
  Object.freeze(prototypeFor("GPUCanvasContext"));
  Object.freeze(prototypeFor("GPUCommandBuffer"));
  Object.freeze(prototypeFor("GPUCommandEncoder"));
  Object.freeze(prototypeFor("GPUDevice"));
  Object.freeze(prototypeFor("GPUDeviceLostInfo"));
  Object.freeze(prototypeFor("GPUSupportedFeatures"));
  Object.freeze(prototypeFor("GPUQueue"));
  Object.freeze(prototypeFor("GPURenderPassEncoder"));
  Object.freeze(prototypeFor("GPURenderPipeline"));
  Object.freeze(prototypeFor("GPUShaderModule"));
  Object.freeze(prototypeFor("GPUTexture"));
  Object.freeze(prototypeFor("GPUTextureView"));

  function createHarness(options) {
    var configuration = options && typeof options === "object" ? options : {};
    var client = Object.create(null);
    clientStates.set(client, {
      runtimePointerNonce: "test-runtime-" + nextRealmToken,
      receipts: [],
      events: [],
      lifecycle: [],
    });
    var realm = {
      token: nextRealmToken++,
      generation: 1,
      accountToken: configuration.accountToken || "test-account",
      accountGeneration: 1,
      accountClosed: false,
      closed: false,
      client: client,
      nextHandle: 1,
      nextDevice: 1,
      nextOperationInstance: 1,
      nextPromise: 1,
      nextPhysicalSequence: 0,
      nextLostSettlement: 0,
      nextProviderGeneration: 1,
      nextPublicationCredit: 1,
      nextLifecycleOrdinal: 1,
      nextTraceOrdinal: 1,
      wrappers: [],
      adapters: [],
      devices: [],
      pendingPromises: [],
      publicCalls: [],
      orderingTrace: [],
      preProviderRejections: [],
      requestAdapterUnavailable: Boolean(configuration.requestAdapterUnavailable),
      liveDeviceLedger: {
        capacity: 64,
        nextReservationId: 1,
        leafActive: 0,
        aggregateActive: 0,
        commitCount: 0,
        releaseCount: 0,
        reservations: [],
      },
    };
    installRealmPrototypes(realm);
    var gpu = allocateWrapper(realm, "GPU", null, {});

    function createCanvasContext() {
      return allocateWrapper(realm, "GPUCanvasContext", null, {
        attachmentGeneration: 1,
        configurationGeneration: 0,
        currentEpoch: 0,
        configuration: null,
        configuredDevice: null,
        currentTexture: null,
      });
    }

    function inspect() {
      var clientState = requireClient(client);
      return logValue(
        {
          schema: "ibex/webgpu-test-wrapper-observation/1",
          profileId: plan.profileId,
          projectionDigest: plan.digests.projection,
          fixtureDisposition: "test-only-no-runtime-install-no-support-claim",
          lifecycleState: {
            accountClosed: realm.accountClosed,
            realmClosed: realm.closed,
          },
          routeIdentityMatrix: plan.routes.map(function (route) {
            return {
              operationId: route.operationId,
              interfaceName: route.interfaceName,
              memberName: route.memberName,
              memberKind: route.memberKind,
              receiverHandleKind: route.receiverHandleKind,
              wrapperAllocatedTargetHandleKind:
                route.wrapperAllocatedTargetHandleKind,
              resultHandleKind: route.resultHandleKind,
            };
          }),
          requestDeviceTerminals:
            plan.semantic.requestDeviceRouting.terminals,
          requestDeviceFailureProgram:
            plan.semantic.requestDeviceFailureProgram,
          publicCalls: realm.publicCalls,
          serviceReceipts: clientState.receipts,
          events: clientState.events,
          lifecycleRequests: clientState.lifecycle,
          preProviderRejections: realm.preProviderRejections,
          orderingTrace: realm.orderingTrace,
          publicationCredits: realm.adapters.map(function (adapter) {
            return publicationCreditSnapshot(adapter.publicationCredit);
          }),
          liveDeviceLedger: {
            capacity: realm.liveDeviceLedger.capacity,
            leafActive: realm.liveDeviceLedger.leafActive,
            aggregateActive: realm.liveDeviceLedger.aggregateActive,
            commitCount: realm.liveDeviceLedger.commitCount,
            releaseCount: realm.liveDeviceLedger.releaseCount,
            reservations: realm.liveDeviceLedger.reservations.map(function (reservation) {
              return liveDeviceReservationSnapshot(reservation);
            }),
          },
          uncapturedErrors: realm.devices.map(function (device) {
            return device.uncapturedErrors;
          }),
        },
        0,
      );
    }

    function present(contextValue) {
      var context = argumentState(contextValue, "GPUCanvasContext");
      if (context.realm !== realm) {
        throw namedError("SecurityError", "cross-realm canvas context");
      }
      expireCurrentTexture(context);
    }

    function injectError(deviceValue, errorClass, message) {
      var state = argumentState(deviceValue, "GPUDevice");
      if (state.realm !== realm) throw namedError("SecurityError", "cross-realm device");
      var name =
        errorClass === "out-of-memory"
          ? "GPUOutOfMemoryError"
          : errorClass === "internal"
            ? "GPUInternalError"
            : "GPUValidationError";
      state.device.nextForcedError = {
        name: name,
        message: String(message || "injected service error"),
        failureClass: String(errorClass || "validation-error"),
        physical: true,
      };
    }

    function providerLoss(deviceValue, message) {
      var state = argumentState(deviceValue, "GPUDevice");
      if (state.realm !== realm) throw namedError("SecurityError", "cross-realm device");
      loseDevice(state.device, "unknown", String(message || "provider lost"), true);
    }

    function setRequestDeviceFacts(adapterValue, factsValue) {
      var adapter = argumentState(adapterValue, "GPUAdapter");
      if (adapter.realm !== realm) throw namedError("SecurityError", "cross-realm adapter");
      var facts = snapshotDictionary(factsValue, "requestDevice test facts");
      var allowed = {
        deviceAdmissionValid: true,
        deviceExpiryResultCommitLive: true,
        deviceReservationCapacityAvailable: true,
        deviceCapacityResultCommitLive: true,
        deviceReservationCommitLive: true,
        providerFulfilled: true,
        deviceAccountLiveAtProviderCompletion: true,
        deviceAccountLiveAtSettlementCommit: true,
        providerInabilityWonLossRace: true,
      };
      var names = Object.keys(facts);
      for (var index = 0; index < names.length; index += 1) {
        if (!allowed[names[index]] || typeof facts[names[index]] !== "boolean") {
          throw typeError("unknown or non-boolean requestDevice fact: " + names[index]);
        }
      }
      adapter.nextRequestDeviceFacts = facts;
    }

    function retire(value) {
      var state = wrapperStates.get(value);
      if (!state || state.realm !== realm) {
        throw typeError("retire requires an owned branded wrapper");
      }
      if (state.retired) return;
      state.retired = true;
      requireClient(client).lifecycle.push({
        kind: "retire",
        realmToken: realm.token,
        realmGeneration: realm.generation,
        accountToken: realm.accountToken,
        accountGeneration: realm.accountGeneration,
        retireOrdinal: realm.nextLifecycleOrdinal++,
        typedReferences: [typedRef(state)],
      });
    }

    function cancel(promise) {
      var state = promiseStates.get(promise);
      if (!state || state.call.realm !== realm) {
        throw typeError("cancel requires an owned pending promise");
      }
      if (state.cancelled || state.call.terminal) return;
      state.cancelled = true;
      var call = state.call;
      requireClient(client).lifecycle.push({
        kind: "cancel",
        realmToken: realm.token,
        realmGeneration: realm.generation,
        operationId: call.route.wireId,
        operationInstanceId: call.operationInstanceId,
        promiseId: call.promiseId,
        receiverRef: typedRef(call.wireReceiverState),
        wrapperAllocatedTargetRef: typedRef(call.targetState),
        cancelOrdinal: realm.nextLifecycleOrdinal++,
      });
    }

    function closeAccount(cause) {
      closeAccountState(realm, cause, null);
    }

    function closeRealm(cause) {
      if (realm.closed) return;
      realm.closed = true;
      var ordinal = realm.nextLifecycleOrdinal++;
      var reason = String(cause || "test-realm-close");
      requireClient(client).lifecycle.push({
        kind: "realmClose",
        realmToken: realm.token,
        realmGeneration: realm.generation,
        closeOrdinal: ordinal,
        closeCause: reason,
      });
      requireClient(client).events.push({
        tag: "realm-close-service-event-v1",
        kind: "realm-close",
        realmToken: realm.token,
        realmGeneration: realm.generation,
        closeOrdinal: ordinal,
        closeCause: reason,
        pendingSettlementPolicy: "reject-or-retire",
      });
      traceRealm(realm, "realm-close", null, { closeOrdinal: ordinal });
      for (var index = 0; index < realm.pendingPromises.length; index += 1) {
        realm.pendingPromises[index].closed = true;
      }
      for (var adapterIndex = 0; adapterIndex < realm.adapters.length; adapterIndex += 1) {
        retirePublicationCredit(realm.adapters[adapterIndex].publicationCredit);
      }
      for (index = 0; index < realm.devices.length; index += 1) {
        loseDevice(realm.devices[index], "unknown", "realm closed", false);
      }
    }

    function describe(value) {
      var state = wrapperStates.get(value);
      if (!state) return null;
      return Object.freeze({
        reference: Object.freeze(typedRef(state)),
        kind: state.kind,
        ownedRealm: state.realm === realm,
        deviceId: state.device ? state.device.id : 0,
        providerGeneration: state.device
          ? state.device.providerGeneration
          : state.providerGeneration || 0,
        serviceDetached: Boolean(state.device && state.device.serviceDetached),
        lostSettled: Boolean(state.device && state.device.lostSettled),
        destroyed: Boolean(state.destroyed || (state.device && state.device.destroyed)),
        expired: Boolean(state.expired),
        materialized: Boolean(state.materialized),
        publicationCredit: state.publicationCredit
          ? Object.freeze(publicationCreditSnapshot(state.publicationCredit))
          : null,
        liveDeviceCredit: state.device && state.device.liveDeviceReservation
          ? Object.freeze(
              liveDeviceReservationSnapshot(state.device.liveDeviceReservation),
            )
          : null,
      });
    }

    return Object.freeze({
      gpu: gpu,
      createCanvasContext: createCanvasContext,
      present: present,
      injectError: injectError,
      providerLoss: providerLoss,
      setRequestDeviceFacts: setRequestDeviceFacts,
      retire: retire,
      cancel: cancel,
      closeAccount: closeAccount,
      closeRealm: closeRealm,
      describe: describe,
      inspect: inspect,
    });
  }

  return createHarness;
}
