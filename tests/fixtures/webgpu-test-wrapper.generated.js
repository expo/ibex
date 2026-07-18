(function portableWebGpuTestWrapperFactory(plan) {
  var wrapperStates = new WeakMap, featureStates = new WeakMap, clientStates = new WeakMap, promiseStates = new WeakMap, prototypes = Object.create(null), routes = Object.create(null), providerRoutingPrograms = Object.create(null), nextRealmToken = 1;
  function planInvariant(condition, message) {
    if (!condition)
      throw Error("webgpu test-wrapper capability plan: " + message);
  }
  function isPowerOfTwoBelowU32(value) {
    if (!Number.isSafeInteger(value) || value <= 0 || value >= 4294967296)
      return !1;
    var remaining = value;
    while (remaining % 2 === 0)
      remaining /= 2;
    return remaining === 1;
  }
  function addFeature(values, feature) {
    if (values.indexOf(feature) === -1)
      values.push(feature);
  }
  function applyFeatureImplications(values, implications) {
    for (var index = 0;index < implications.length; index += 1) {
      var implication = implications[index];
      if (values.indexOf(implication.feature) !== -1)
        addFeature(values, implication.implies);
    }
  }
  function projectedFakeAdapterFeatures() {
    return plan.fakeClientData.adapterFeatures.slice();
  }
  function validateCapabilityPlan() {
    var featurePolicy = plan.semantic && plan.semantic.featurePolicy, limitPolicy = plan.semantic && plan.semantic.limitPolicy;
    planInvariant(featurePolicy && limitPolicy, "policy is missing");
    planInvariant(featurePolicy.requiredFeatureValidation === "webidl-known-then-subset-of-adapter-profile-and-capability-grant" && featurePolicy.deviceProjection === "requested-plus-pinned-default-and-implied-features", "feature algorithms drifted");
    planInvariant(Array.isArray(featurePolicy.features) && Array.isArray(featurePolicy.adapterFeatureImplications) && Array.isArray(featurePolicy.newDeviceFeatureImplications) && Array.isArray(featurePolicy.adapterRequiredFeatureAlternatives), "feature rules are malformed");
    var admittedFeatures = Object.create(null);
    for (var featureIndex = 0;featureIndex < featurePolicy.features.length; featureIndex += 1) {
      var featureRow = featurePolicy.features[featureIndex];
      planInvariant(typeof featureRow.name === "string" && admittedFeatures[featureRow.name] === void 0, "feature vocabulary is malformed");
      admittedFeatures[featureRow.name] = featureRow.profileAdmission === "admitted";
    }
    var implicationTables = [
      featurePolicy.adapterFeatureImplications,
      featurePolicy.newDeviceFeatureImplications
    ];
    for (var tableIndex = 0;tableIndex < implicationTables.length; tableIndex += 1) {
      var implicationTable = implicationTables[tableIndex];
      for (var implicationIndex = 0;implicationIndex < implicationTable.length; implicationIndex += 1) {
        var implication = implicationTable[implicationIndex];
        planInvariant(admittedFeatures[implication.feature] === !0 && admittedFeatures[implication.implies] === !0 && implication.feature !== implication.implies, "feature implication is outside the admitted vocabulary");
      }
    }
    planInvariant(plan.fakeClientData && Array.isArray(plan.fakeClientData.adapterFeatures) && plan.fakeClientData.adapterLimits && typeof plan.fakeClientData.adapterLimits === "object", "fake adapter data is missing");
    var fakeFeatureNames = Object.create(null);
    for (featureIndex = 0;featureIndex < plan.fakeClientData.adapterFeatures.length; featureIndex += 1) {
      var fakeFeature = plan.fakeClientData.adapterFeatures[featureIndex];
      planInvariant(admittedFeatures[fakeFeature] === !0 && fakeFeatureNames[fakeFeature] === void 0, "fake adapter feature data is inconsistent");
      fakeFeatureNames[fakeFeature] = !0;
    }
    var projectedFeatures = projectedFakeAdapterFeatures();
    for (implicationIndex = 0;implicationIndex < featurePolicy.adapterFeatureImplications.length; implicationIndex += 1) {
      implication = featurePolicy.adapterFeatureImplications[implicationIndex];
      planInvariant(projectedFeatures.indexOf(implication.feature) === -1 || projectedFeatures.indexOf(implication.implies) !== -1, "fake adapter omits an adapter-implied feature");
    }
    for (implicationIndex = 0;implicationIndex < featurePolicy.newDeviceFeatureImplications.length; implicationIndex += 1) {
      implication = featurePolicy.newDeviceFeatureImplications[implicationIndex];
      planInvariant(projectedFeatures.indexOf(implication.feature) === -1 || projectedFeatures.indexOf(implication.implies) !== -1, "fake adapter cannot support an ordered new-device feature addition");
    }
    for (var levelIndex = 0;levelIndex < 2; levelIndex += 1) {
      var level = levelIndex === 0 ? "core" : "compatibility", defaults = featurePolicy.defaultFeatures[level];
      planInvariant(Array.isArray(defaults), level + " defaults are missing");
      for (featureIndex = 0;featureIndex < defaults.length; featureIndex += 1)
        planInvariant(projectedFeatures.indexOf(defaults[featureIndex]) !== -1, "fake adapter does not support the " + level + " feature defaults");
    }
    var alternativeSatisfied = !1;
    for (var alternativeIndex = 0;alternativeIndex < featurePolicy.adapterRequiredFeatureAlternatives.length; alternativeIndex += 1) {
      var alternative = featurePolicy.adapterRequiredFeatureAlternatives[alternativeIndex], satisfiesAlternative = Array.isArray(alternative) && alternative.length > 0;
      for (featureIndex = 0;satisfiesAlternative && featureIndex < alternative.length; featureIndex += 1)
        satisfiesAlternative = projectedFeatures.indexOf(alternative[featureIndex]) !== -1;
      if (satisfiesAlternative)
        alternativeSatisfied = !0;
    }
    planInvariant(alternativeSatisfied, "fake adapter satisfies no required feature alternative");
    planInvariant(Array.isArray(limitPolicy.limits) && limitPolicy.limits.length === 36, "limit inventory is malformed");
    var limitNames = Object.create(null);
    for (var limitIndex = 0;limitIndex < limitPolicy.limits.length; limitIndex += 1) {
      var row = limitPolicy.limits[limitIndex];
      planInvariant(typeof row.name === "string" && limitNames[row.name] === void 0, "limit vocabulary is malformed");
      limitNames[row.name] = !0;
      var fakeLimit = plan.fakeClientData.adapterLimits[row.name];
      planInvariant(Number.isSafeInteger(row.coreDefault) && row.coreDefault >= 0 && Number.isSafeInteger(row.compatibilityDefault) && row.compatibilityDefault >= 0 && Number.isSafeInteger(row.profileBucket.core) && row.profileBucket.core >= 0 && Number.isSafeInteger(row.profileBucket.compatibility) && row.profileBucket.compatibility >= 0 && Number.isSafeInteger(row.capabilityGrantBoundary.core) && row.capabilityGrantBoundary.core >= 0 && Number.isSafeInteger(row.capabilityGrantBoundary.compatibility) && row.capabilityGrantBoundary.compatibility >= 0 && Number.isSafeInteger(fakeLimit) && fakeLimit >= 0, "limit metadata is inconsistent for " + row.name);
      if (row.class === "maximum")
        planInvariant(fakeLimit >= row.coreDefault && fakeLimit >= row.compatibilityDefault, "fake adapter maximum is worse than a device default for " + row.name);
      else
        planInvariant(row.class === "alignment" && isPowerOfTwoBelowU32(fakeLimit) && fakeLimit <= row.coreDefault && fakeLimit <= row.compatibilityDefault, "fake adapter alignment is worse than a device default for " + row.name);
    }
    var fakeLimitNames = Object.keys(plan.fakeClientData.adapterLimits);
    planInvariant(fakeLimitNames.length === limitPolicy.limits.length, "fake adapter limit data is not a complete closed record");
    for (limitIndex = 0;limitIndex < fakeLimitNames.length; limitIndex += 1)
      planInvariant(limitNames[fakeLimitNames[limitIndex]] === !0, "fake adapter limit data contains an unknown member");
  }
  function freezeTree(value) {
    if (!value || typeof value !== "object" || Object.isFrozen(value))
      return value;
    var keys = Object.keys(value);
    for (var index = 0;index < keys.length; index += 1)
      freezeTree(value[keys[index]]);
    return Object.freeze(value);
  }
  validateCapabilityPlan();
  freezeTree(plan);
  for (var routeIndex = 0;routeIndex < plan.routes.length; routeIndex += 1)
    routes[plan.routes[routeIndex].operationId] = plan.routes[routeIndex];
  for (var providerRouteIndex = 0;providerRouteIndex < plan.semantic.providerRoutingPrograms.length; providerRouteIndex += 1) {
    var providerRoutingProgram = plan.semantic.providerRoutingPrograms[providerRouteIndex];
    providerRoutingPrograms[providerRoutingProgram.operationId] = providerRoutingProgram;
  }
  function namedError(name, message) {
    var error = Error(message);
    Object.defineProperty(error, "name", {
      value: name,
      writable: !1,
      enumerable: !1,
      configurable: !0
    });
    return error;
  }
  function typeError(message) {
    return TypeError(message);
  }
  function requireDictionary(value, label) {
    if (value === void 0)
      return {};
    if (value === null || typeof value !== "object" && typeof value !== "function")
      throw typeError(label + " must be a dictionary");
    return value;
  }
  function snapshotValue(value, depth, seen) {
    if (depth > 8)
      throw typeError("descriptor nesting exceeds the test profile bound");
    if (value === null || typeof value !== "object")
      return value;
    if (wrapperStates.has(value))
      return value;
    if (seen.has(value))
      throw typeError("cyclic descriptors are not supported");
    seen.set(value, !0);
    var output, index;
    if (Array.isArray(value)) {
      if (value.length > 1024)
        throw typeError("descriptor sequence exceeds the test profile bound");
      output = [];
      for (index = 0;index < value.length; index += 1)
        output.push(snapshotValue(value[index], depth + 1, seen));
    } else {
      output = {};
      var keys = Object.keys(value);
      if (keys.length > 128)
        throw typeError("descriptor has too many members");
      for (index = 0;index < keys.length; index += 1)
        output[keys[index]] = snapshotValue(value[keys[index]], depth + 1, seen);
    }
    seen.delete(value);
    return output;
  }
  function snapshotDictionary(value, label) {
    return snapshotValue(requireDictionary(value, label), 0, new WeakMap);
  }
  function typedRef(state) {
    if (!state)
      return null;
    var client = clientStates.get(state.realm.client);
    return {
      runtimePointerNonce: client.runtimePointerNonce,
      realmToken: state.realm.token,
      realmGeneration: state.realm.generation,
      accountToken: state.realm.accountToken,
      accountGeneration: state.realm.accountGeneration,
      logicalDeviceId: state.device ? state.device.id : 0,
      logicalDeviceGeneration: state.device ? state.device.generation : 0,
      providerGeneration: state.device ? state.device.providerGeneration : state.providerGeneration || 0,
      authorityContextDigest: plan.digests.projection,
      topology: 1,
      objectKind: state.kind,
      logicalHandle: state.handle,
      lifecycleGeneration: state.generation
    };
  }
  function logValue(value, depth) {
    if (depth > 10)
      return "<depth-bound>";
    if (value === null || typeof value !== "object")
      return value;
    var wrapperState = wrapperStates.get(value);
    if (wrapperState)
      return typedRef(wrapperState);
    var featureState = featureStates.get(value);
    if (featureState)
      return featureState.values.slice();
    if (value instanceof Error)
      return { name: value.name, message: value.message };
    var output, keys, index;
    if (Array.isArray(value)) {
      output = [];
      for (index = 0;index < value.length; index += 1)
        output.push(logValue(value[index], depth + 1));
      return output;
    }
    output = {};
    keys = Object.keys(value).sort();
    for (index = 0;index < keys.length; index += 1)
      output[keys[index]] = logValue(value[keys[index]], depth + 1);
    return output;
  }
  function defineMethod(prototype, name, implementation) {
    Object.defineProperty(prototype, name, {
      value: implementation,
      writable: !1,
      enumerable: !0,
      configurable: !1
    });
  }
  function defineGetter(prototype, name, implementation) {
    Object.defineProperty(prototype, name, {
      get: implementation,
      enumerable: !0,
      configurable: !1
    });
  }
  function prototypeFor(kind) {
    if (!prototypes[kind])
      prototypes[kind] = Object.create(null);
    return prototypes[kind];
  }
  function brandedRealm(value) {
    var wrapperState = wrapperStates.get(value);
    if (wrapperState)
      return wrapperState.realm;
    var featureState = featureStates.get(value);
    if (featureState)
      return featureState.realm;
    return null;
  }
  function realmMethod(realm, kind, implementation) {
    return function() {
      if (brandedRealm(this) !== realm)
        throw typeError("cross-realm borrowed " + kind + " method");
      return implementation.apply(this, arguments);
    };
  }
  function realmGetter(realm, kind, implementation) {
    return function() {
      if (brandedRealm(this) !== realm)
        throw typeError("cross-realm borrowed " + kind + " getter");
      return implementation.call(this);
    };
  }
  function installRealmPrototypes(realm) {
    realm.prototypes = Object.create(null);
    var kinds = Object.keys(prototypes);
    for (var kindIndex = 0;kindIndex < kinds.length; kindIndex += 1) {
      var kind = kinds[kindIndex], definition = prototypes[kind], installed = Object.create(null), names = Object.getOwnPropertyNames(definition), symbols = typeof Object.getOwnPropertySymbols === "function" ? Object.getOwnPropertySymbols(definition) : [], keys = names.concat(symbols);
      for (var keyIndex = 0;keyIndex < keys.length; keyIndex += 1) {
        var key = keys[keyIndex], descriptor = Object.getOwnPropertyDescriptor(definition, key);
        if (typeof descriptor.value === "function")
          descriptor.value = realmMethod(realm, kind, descriptor.value);
        if (typeof descriptor.get === "function")
          descriptor.get = realmGetter(realm, kind, descriptor.get);
        Object.defineProperty(installed, key, descriptor);
      }
      realm.prototypes[kind] = Object.freeze(installed);
    }
  }
  function allocateWrapper(realm, kind, device, extra) {
    var wrapper = Object.create(realm.prototypes[kind]), state = extra || {};
    state.kind = kind;
    state.realm = realm;
    state.device = device || null;
    state.handle = realm.nextHandle++;
    state.generation = 1;
    state.retired = !1;
    state.wrapper = wrapper;
    wrapperStates.set(wrapper, state);
    realm.wrappers.push(state);
    return wrapper;
  }
  function requireReceiver(value, kind) {
    var state = wrapperStates.get(value);
    if (!state || state.kind !== kind)
      throw typeError("incompatible " + kind + " receiver");
    return state;
  }
  function argumentState(value, kind) {
    var state = wrapperStates.get(value);
    if (!state || state.kind !== kind)
      throw typeError("value is not a branded " + kind);
    return state;
  }
  function requireFeatureSet(value) {
    var state = featureStates.get(value);
    if (!state)
      throw typeError("incompatible GPUSupportedFeatures receiver");
    return state;
  }
  function featureValuesIterator(state) {
    return state.values.slice()[Symbol.iterator]();
  }
  defineGetter(prototypeFor("GPUSupportedFeatures"), "size", function() {
    return requireFeatureSet(this).values.length;
  });
  defineMethod(prototypeFor("GPUSupportedFeatures"), "has", function(feature) {
    return requireFeatureSet(this).values.indexOf(String(feature)) !== -1;
  });
  defineMethod(prototypeFor("GPUSupportedFeatures"), "keys", function() {
    return featureValuesIterator(requireFeatureSet(this));
  });
  defineMethod(prototypeFor("GPUSupportedFeatures"), "values", function() {
    return featureValuesIterator(requireFeatureSet(this));
  });
  defineMethod(prototypeFor("GPUSupportedFeatures"), "entries", function() {
    var state = requireFeatureSet(this), entries = state.values.map(function(value) {
      return [value, value];
    });
    return entries[Symbol.iterator]();
  });
  defineMethod(prototypeFor("GPUSupportedFeatures"), "forEach", function(callback, thisArg) {
    if (typeof callback !== "function")
      throw typeError("callback must be callable");
    var state = requireFeatureSet(this);
    for (var index = 0;index < state.values.length; index += 1)
      callback.call(thisArg, state.values[index], state.values[index], this);
  });
  defineMethod(prototypeFor("GPUSupportedFeatures"), Symbol.iterator, function() {
    return featureValuesIterator(requireFeatureSet(this));
  });
  function createFeatureSet(realm, values) {
    var setlike = Object.create(realm.prototypes.GPUSupportedFeatures);
    featureStates.set(setlike, {
      realm,
      values: values.slice().sort()
    });
    return Object.freeze(setlike);
  }
  function currentScopeId(device) {
    if (!device || device.localScopes.length === 0)
      return 0;
    return device.localScopes[device.localScopes.length - 1];
  }
  function traceRealm(realm, kind, call, details) {
    var entry = {
      ordinal: realm.nextTraceOrdinal++,
      kind,
      operationId: call ? call.route.operationId : null,
      operationInstanceId: call ? call.operationInstanceId : 0,
      promiseId: call ? call.promiseId : 0
    }, names = details ? Object.keys(details) : [];
    for (var index = 0;index < names.length; index += 1)
      entry[names[index]] = details[names[index]];
    realm.orderingTrace.push(entry);
  }
  function beginPublic(realm, operationId, receiverState, targetState) {
    var route = routes[operationId];
    if (!route)
      throw Error("unreviewed wrapper operation: " + operationId);
    var wireReceiverState = route.receiverHandleKind ? receiverState : null, device = receiverState ? receiverState.device : null;
    if (!device && targetState)
      device = targetState.device;
    var carriedOperationIdentity = route.operationInstanceIdentity.indexOf("not-carried-wrapper-only") !== 0, call = {
      route,
      realm,
      device: device || null,
      ingressDevice: device || null,
      operationProviderGeneration: device ? device.providerGeneration : receiverState && receiverState.providerGeneration ? receiverState.providerGeneration : 0,
      operationInstanceId: carriedOperationIdentity ? realm.nextOperationInstance++ : 0,
      promiseId: 0,
      adapterOperationOrdinal: operationId === "GPUAdapter.requestDevice" && receiverState ? receiverState.nextRequestDeviceOrdinal++ : 0,
      deviceIngressOrdinal: device ? device.nextIngress++ : 0,
      queueIngressOrdinal: operationId === "GPUQueue.submit" && device ? device.nextQueueIngress++ : 0,
      capturedScopeId: currentScopeId(device),
      receiverState: receiverState || null,
      wireReceiverState,
      targetState: targetState || null,
      resultState: null,
      receipt: null,
      terminal: !1
    };
    if (targetState && route.wrapperAllocatedTargetHandleKind === targetState.kind && route.resultHandleKind === targetState.kind)
      call.resultState = targetState;
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
      capturedScopeId: call.capturedScopeId
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
    if (!device || call.ingressDevice || call.deviceIngressOrdinal)
      throw Error("device ingress must be assigned exactly once");
    call.device = device;
    call.ingressDevice = device;
    call.operationProviderGeneration = device.providerGeneration;
    call.deviceIngressOrdinal = device.nextIngress++;
    call.capturedScopeId = currentScopeId(device);
    call.publicRecord.capturedScopeId = call.capturedScopeId;
  }
  function requireClient(client) {
    var state = clientStates.get(client);
    if (!state)
      throw Error("unbranded test semantic client");
    return state;
  }
  function operationCompleteEvent(call, status, completionBody) {
    var completionDevice = call.resultState && call.resultState.device ? call.resultState.device : call.ingressDevice;
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
      providerGeneration: call.operationProviderGeneration || (completionDevice ? completionDevice.providerGeneration : 0),
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
      status,
      completionBody: logValue(completionBody, 0)
    };
  }
  function completeCall(call, status, body) {
    if (call.terminal)
      return;
    call.terminal = !0;
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
        requestDeviceFacts: call.requestDeviceFacts ? logValue(call.requestDeviceFacts, 0) : null,
        status,
        body: logValue(body, 0)
      });
      traceRealm(call.realm, "operation-terminal", call, {
        status,
        providerBacked: !1
      });
      return;
    }
    if (call.publicationCredit)
      call.receipt.publicationCreditLedger = publicationCreditSnapshot(call.publicationCredit);
    if (call.liveDeviceReservation)
      call.receipt.liveDeviceCreditLedger = liveDeviceReservationSnapshot(call.liveDeviceReservation);
    if (call.preProviderFailurePredicateId)
      call.receipt.failureProgram = {
        predicateId: call.preProviderFailurePredicateId,
        predicateWireId: call.preProviderFailurePredicateWireId,
        failureClass: call.preProviderFailureClass,
        failureTiming: call.preProviderFailureTiming
      };
    call.receipt.terminalStatus = status;
    call.receipt.resultHandleRef = typedRef(call.resultState);
    requireClient(call.realm.client).events.push(operationCompleteEvent(call, status, body));
    traceRealm(call.realm, "operation-terminal", call, {
      status,
      providerBacked: !0
    });
  }
  function errorFilterFor(name) {
    if (name === "GPUOutOfMemoryError")
      return "out-of-memory";
    if (name === "GPUInternalError")
      return "internal";
    return "validation";
  }
  function captureDeviceError(device, call, name, message) {
    var error = namedError(name, message), captured = !1;
    for (var index = device.serviceScopes.length - 1;index >= 0; index -= 1) {
      var scope = device.serviceScopes[index];
      if (scope.id === call.capturedScopeId && scope.filter === errorFilterFor(name)) {
        if (!scope.error)
          scope.error = error;
        captured = !0;
        break;
      }
    }
    if (!captured)
      device.uncapturedErrors.push(error);
    return error;
  }
  function deliverLogicalError(device, call, name, message) {
    return captureDeviceError(device, call, name, message);
  }
  function deliverPhysicalError(device, call, errorSpec, physicalSequence) {
    if (!physicalSequence)
      throw Error("physical provider error lacks an admitted physical sequence");
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
        physicalSequence,
        capturedScopeId: call.capturedScopeId,
        accountId: call.realm.accountToken,
        authorityContextDigest: plan.digests.projection,
        operationId: call.route.wireId
      },
      backendClass: errorSpec.failureClass,
      terminalState: "error",
      publicErrorClass: errorSpec.name,
      redactedDiagnostic: errorSpec.message
    });
    return captureDeviceError(device, call, errorSpec.name, errorSpec.message);
  }
  function flushLocalPrefix(device) {
    if (!device || device.pendingLocal.length === 0)
      return [];
    var prefix = device.pendingLocal.splice(0, device.pendingLocal.length);
    for (var index = 0;index < prefix.length; index += 1) {
      var pending = prefix[index];
      if (pending.error)
        deliverLogicalError(device, pending.call, pending.error.name, pending.error.message);
    }
    return prefix.map(function(pending) {
      return {
        operationId: pending.call.route.wireId,
        operationName: pending.call.route.operationId,
        operationInstanceId: pending.call.operationInstanceId,
        deviceIngressOrdinal: pending.call.deviceIngressOrdinal,
        capturedScopeId: pending.call.capturedScopeId,
        receiverRef: typedRef(pending.call.wireReceiverState),
        wrapperAllocatedTargetRef: typedRef(pending.call.targetState),
        argumentBody: logValue(pending.payload, 0),
        logicalError: pending.error ? logValue(pending.error, 0) : null
      };
    });
  }
  function selectProviderRoutingTerminal(call, facts) {
    var program = providerRoutingPrograms[call.route.operationId];
    if (!program)
      throw Error("operation has no authenticated conditional provider routing: " + call.route.operationId);
    for (var terminalIndex = 0;terminalIndex < program.terminals.length; terminalIndex += 1) {
      var terminal = program.terminals[terminalIndex], names = Object.keys(terminal.conditions), matches = !0;
      for (var nameIndex = 0;nameIndex < names.length; nameIndex += 1)
        if (facts[names[nameIndex]] !== terminal.conditions[names[nameIndex]]) {
          matches = !1;
          break;
        }
      if (matches) {
        call.providerRoutingTerminalId = terminal.terminalId;
        call.providerRoutingFacts = facts;
        call.providerAdmissionOverride = terminal.providerTokenCount === 1;
        return terminal;
      }
    }
    throw Error("authenticated conditional provider routing selected no terminal: " + call.route.operationId);
  }
  function serviceCall(client, call, argumentBody, pendingPromise, errorSpec, providerArgumentBody) {
    var clientState = requireClient(client), providerPayloadSource = arguments.length >= 6 ? providerArgumentBody : argumentBody, sealedLocalTimelinePrefix = call.skipLocalPrefixFlush ? [] : flushLocalPrefix(call.device), localTimelineInvalid = !1;
    for (var localIndex = 0;localIndex < sealedLocalTimelinePrefix.length; localIndex += 1)
      if (sealedLocalTimelinePrefix[localIndex].logicalError) {
        localTimelineInvalid = !0;
        break;
      }
    if (!errorSpec && call.route.operationId === "GPUQueue.submit" && localTimelineInvalid)
      errorSpec = {
        name: "GPUValidationError",
        message: "sealed command program contains invalid recorded commands",
        failureClass: "validation-error",
        physical: !1
      };
    if (!errorSpec && call.device && call.device.nextForcedError) {
      errorSpec = call.device.nextForcedError;
      call.device.nextForcedError = null;
    }
    if (call.providerAdmissionOverride === !0 && call.route.providerSubmission === "none")
      throw Error("provider entry selected for an operation with no provider submission");
    var providerEntrySelected = call.providerAdmissionOverride === !0 || call.providerAdmissionOverride !== !1 && call.route.fakeProviderEntry === !0, providerAdmitted = providerEntrySelected && (!errorSpec || errorSpec.physical === !0), physicalSequence = providerAdmitted ? ++call.realm.nextPhysicalSequence : 0, physicalDevice = call.resultState && call.resultState.device ? call.resultState.device : call.ingressDevice, receipt = {
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
      providerRoutingTerminalId: call.providerRoutingTerminalId || null,
      providerRoutingFacts: call.providerRoutingFacts ? logValue(call.providerRoutingFacts, 0) : null,
      providerAdmission: {
        admitted: providerAdmitted,
        providerTokenCount: providerAdmitted ? 1 : 0,
        reason: providerAdmitted ? "deterministic-fake-provider-entry" : errorSpec ? "semantic-rejection-before-provider" : call.providerAdmissionOverride === !1 ? "service-local-terminal" : "operation-has-no-fake-provider-entry"
      },
      requestDeviceTerminalId: call.requestDeviceTerminalId || null,
      requestDeviceTerminal: call.requestDeviceTerminal ? logValue(call.requestDeviceTerminal, 0) : null,
      publicationCreditId: call.publicationCreditId || 0,
      publicationCreditLeaseOrdinal: call.publicationCreditLeaseOrdinal || 0,
      publicationCreditDisposition: call.requestDeviceTerminal ? call.requestDeviceTerminal.publicationCreditDisposition : null,
      publicationCreditLedger: call.publicationCredit ? publicationCreditSnapshot(call.publicationCredit) : null,
      liveDeviceCreditLedger: call.liveDeviceReservation ? liveDeviceReservationSnapshot(call.liveDeviceReservation) : null,
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
        argumentBody: logValue(argumentBody, 0)
      },
      providerPayload: providerAdmitted ? logValue(providerPayloadSource, 0) : null,
      authenticatedIngressContext: {
        runtimePointerNonce: clientState.runtimePointerNonce,
        realmToken: call.realm.token,
        realmGeneration: call.realm.generation,
        accountToken: call.realm.accountToken,
        accountGeneration: call.realm.accountGeneration,
        logicalDeviceId: call.ingressDevice ? call.ingressDevice.id : 0,
        logicalDeviceGeneration: call.ingressDevice ? call.ingressDevice.generation : 0,
        providerGeneration: call.operationProviderGeneration || (call.ingressDevice ? call.ingressDevice.providerGeneration : 0),
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
        capturedScopeId: call.capturedScopeId
      },
      physicalOperationKey: {
        realmGeneration: call.realm.generation,
        topology: 1,
        providerGeneration: call.operationProviderGeneration || (physicalDevice ? physicalDevice.providerGeneration : 0),
        logicalDeviceId: physicalDevice ? physicalDevice.id : 0,
        deviceIngressOrdinal: call.deviceIngressOrdinal,
        queueIngressOrdinal: call.queueIngressOrdinal,
        physicalSequence,
        capturedScopeId: call.capturedScopeId,
        accountId: call.realm.accountToken,
        authorityContextDigest: plan.digests.projection,
        operationId: call.route.wireId
      },
      sealedLocalTimelinePrefix,
      terminalStatus: pendingPromise ? "pending" : errorSpec ? "error" : "ok"
    };
    call.receipt = receipt;
    traceRealm(call.realm, providerAdmitted ? "provider-entry" : "no-provider-entry", call, {
      physicalSequence,
      providerTokenCount: providerAdmitted ? 1 : 0
    });
    if (call.requestDeviceTerminal) {
      if (receipt.providerAdmission.providerTokenCount !== call.requestDeviceTerminal.providerTokenCount || (physicalSequence ? 1 : 0) !== call.requestDeviceTerminal.physicalSequenceCount)
        throw Error("fake requestDevice admission disagrees with authenticated terminal");
    }
    clientState.receipts.push(receipt);
    if (errorSpec && call.device)
      if (errorSpec.physical === !0)
        deliverPhysicalError(call.device, call, errorSpec, physicalSequence);
      else
        deliverLogicalError(call.device, call, errorSpec.name, errorSpec.message);
    if (!pendingPromise)
      completeCall(call, errorSpec ? "error" : "ok", errorSpec || {});
    return receipt;
  }
  function appendLocal(call, payload, errorSpec) {
    if (!call.device)
      throw Error("local operation lacks a logical device");
    call.device.pendingLocal.push({
      call,
      payload: payload || {},
      error: errorSpec || null
    });
  }
  function promiseOperation(call, action) {
    if (!call.promiseId)
      call.promiseId = allocatePromiseId(call);
    var state = { call, cancelled: !1, closed: !1 }, promise = new Promise(function(resolve, reject) {
      Promise.resolve().then(function() {
        try {
          if (state.cancelled)
            throw namedError("OperationError", "operation was cancelled");
          if (state.closed)
            throw namedError("SecurityError", "realm is closed");
          var result = action();
          completeCall(call, "ok", result);
          traceRealm(call.realm, "promise-resolve", call, {});
          resolve(result);
        } catch (error) {
          completeCall(call, "rejected", {
            name: error.name || "Error",
            message: error.message || String(error)
          });
          traceRealm(call.realm, "promise-reject", call, {
            errorName: error.name || "Error"
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
    Object.defineProperty(info, "reason", { value: reason, enumerable: !0 });
    Object.defineProperty(info, "message", { value: message, enumerable: !0 });
    return Object.freeze(info);
  }
  function loseDevice(device, reason, message, emitProviderLoss, initiatingCall) {
    if (device.lostSettled)
      return;
    device.lostSettled = !0;
    releaseLiveDeviceCredits(device);
    device.destroyed = reason === "destroyed" || device.destroyed;
    var client = requireClient(device.realm.client);
    if (emitProviderLoss)
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
        redactedDiagnostic: message
      });
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
      lostSettlementOrdinal: ++device.realm.nextLostSettlement
    });
    traceRealm(device.realm, "device-lost-settle", initiatingCall || null, {
      logicalDeviceId: device.id,
      reason
    });
    device.resolveLost(createLostInfo(reason, message, device.realm));
  }
  function createDevice(realm, providerGeneration, serviceDetached, logicalProviderDescriptor) {
    if (!logicalProviderDescriptor)
      throw Error("logical device creation requires a normalized provider descriptor");
    var resolveLost, lost = new Promise(function(resolve) {
      resolveLost = resolve;
    }), device = {
      realm,
      id: realm.nextDevice++,
      generation: 1,
      providerGeneration,
      serviceDetached: Boolean(serviceDetached),
      nextIngress: 1,
      nextQueueIngress: 1,
      nextScope: 1,
      localScopes: [],
      serviceScopes: [],
      pendingLocal: [],
      uncapturedErrors: [],
      nextForcedError: null,
      destroyed: !1,
      lostSettled: !1,
      lost,
      resolveLost,
      liveDeviceReservation: null
    }, wrapper = allocateWrapper(realm, "GPUDevice", device, {}), state = wrapperStates.get(wrapper);
    state.device = device;
    device.wrapper = wrapper;
    device.state = state;
    device.features = createFeatureSet(realm, logicalProviderDescriptor.logicalFeatures);
    var limits = {}, limitRows = plan.semantic.limitPolicy.limits;
    for (var index = 0;index < limitRows.length; index += 1)
      limits[limitRows[index].name] = logicalProviderDescriptor.logicalLimits[limitRows[index].name];
    device.limits = Object.freeze(limits);
    device.queue = allocateWrapper(realm, "GPUQueue", device, {});
    realm.devices.push(device);
    return wrapper;
  }
  function serviceError(call, payload, name, message, failureClass) {
    serviceCall(call.realm.client, call, payload, !1, {
      name,
      message,
      failureClass
    });
  }
  function deviceIsUnavailable(device) {
    return device.destroyed || device.lostSettled || device.realm.closed || device.realm.accountClosed;
  }
  function expireCurrentTexture(contextState) {
    if (!contextState.currentTexture)
      return;
    var textureState = wrapperStates.get(contextState.currentTexture);
    textureState.expired = !0;
    contextState.currentTexture = null;
  }
  function allocatePromiseId(call) {
    var promiseId = call.realm.nextPromise++;
    if (promiseId === call.operationInstanceId)
      promiseId = call.realm.nextPromise++;
    return promiseId;
  }
  function assertRealmAdmission(realm) {
    if (realm.closed)
      throw namedError("SecurityError", "realm is closed");
    if (realm.accountClosed)
      throw namedError("SecurityError", "GPU account is closed");
  }
  function closeAccountState(realm, cause, initiatingCall, deferredCredit) {
    if (realm.accountClosed)
      return !1;
    realm.accountClosed = !0;
    var ordinal = realm.nextLifecycleOrdinal++, reason = String(cause || "test-account-close"), client = requireClient(realm.client);
    client.lifecycle.push({
      kind: "accountClose",
      realmToken: realm.token,
      realmGeneration: realm.generation,
      accountToken: realm.accountToken,
      accountGeneration: realm.accountGeneration,
      closeOrdinal: ordinal,
      closeCause: reason
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
      winningDiagnostic: "account closed"
    });
    traceRealm(realm, "account-close", initiatingCall || null, {
      closeOrdinal: ordinal
    });
    for (var adapterIndex = 0;adapterIndex < realm.adapters.length; adapterIndex += 1) {
      var credit = realm.adapters[adapterIndex].publicationCredit;
      if (credit !== deferredCredit)
        retirePublicationCredit(credit);
    }
    for (var deviceIndex = 0;deviceIndex < realm.devices.length; deviceIndex += 1)
      loseDevice(realm.devices[deviceIndex], "unknown", "account closed", !1, initiatingCall || null);
    return !0;
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
      retireCount: credit.retireCount
    };
  }
  function acquirePublicationCredit(adapter, call) {
    var credit = adapter.publicationCredit;
    if (credit.state !== "available")
      throw Error("publication credit is not available");
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
    if (!credit || credit.state !== "leased")
      throw Error("publication credit cannot be returned from its current state");
    credit.state = "available";
    credit.activeOperationInstanceId = 0;
    credit.returnCount += 1;
  }
  function retirePublicationCredit(credit) {
    if (!credit || credit.state === "retired")
      return;
    if (credit.state !== "available" && credit.state !== "leased")
      throw Error("publication credit cannot be retired from its current state");
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
      releaseCount: reservation.releaseCount
    };
  }
  function commitLiveDeviceCredits(device, call) {
    var ledger = device.realm.liveDeviceLedger;
    if (ledger.leafActive >= ledger.capacity || ledger.aggregateActive >= ledger.capacity)
      throw Error("fake live-device capacity was exhausted unexpectedly");
    var reservation = {
      id: ledger.nextReservationId++,
      state: "committed",
      ownerDeviceId: device.id,
      operationInstanceId: call.operationInstanceId,
      leafCreditState: "owned-by-device",
      aggregateCreditState: "owned-by-device",
      commitCount: 1,
      releaseCount: 0
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
    if (!reservation || reservation.state === "released")
      return;
    if (reservation.state !== "committed")
      throw Error("live-device credit cannot be released from its current state");
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
    if (!source || source.kind !== "first-failing-predicate")
      throw Error("requestDevice terminal has no authenticated failing predicate: " + terminal.terminalId);
    var branches = plan.semantic.requestDeviceFailureProgram.branches;
    for (var branchIndex = 0;branchIndex < branches.length; branchIndex += 1) {
      var branch = branches[branchIndex];
      if (branch.branchId !== source.branchId)
        continue;
      for (var predicateIndex = 0;predicateIndex < branch.orderedPredicates.length; predicateIndex += 1) {
        var predicate = branch.orderedPredicates[predicateIndex];
        if (predicate.failureClass !== "none" && (!preferredPredicateId || predicate.predicateId === preferredPredicateId))
          return predicate;
      }
    }
    throw Error("requestDevice terminal cannot select authenticated predicate: " + terminal.terminalId);
  }
  function requestDeviceError(failureClass, message) {
    if (failureClass === "type-error")
      return typeError(message);
    if (failureClass === "operation-error")
      return namedError("OperationError", message);
    if (failureClass === "security-error")
      return namedError("SecurityError", message);
    throw Error("unknown authenticated requestDevice failure class: " + failureClass);
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
  function validateDeviceDescriptor(adapter, copy) {
    var requiredFeatures = copy.requiredFeatures;
    if (requiredFeatures === void 0)
      requiredFeatures = [];
    if (!Array.isArray(requiredFeatures))
      return {
        fact: "requiredFeaturesSupported",
        predicateId: "adapter.request-device.required-features",
        message: "requiredFeatures must be a sequence"
      };
    for (var featureIndex = 0;featureIndex < requiredFeatures.length; featureIndex += 1)
      if (typeof requiredFeatures[featureIndex] !== "string" || adapter.features.indexOf(requiredFeatures[featureIndex]) === -1)
        return {
          fact: "requiredFeaturesSupported",
          predicateId: "adapter.request-device.required-features",
          message: "unsupported required feature"
        };
    var requiredLimits = copy.requiredLimits;
    if (requiredLimits === void 0)
      requiredLimits = {};
    if (requiredLimits === null || typeof requiredLimits !== "object")
      return {
        fact: "adapterRequestValid",
        predicateId: "adapter.request-device.limits",
        message: "requiredLimits must be a dictionary"
      };
    var rows = plan.semantic.limitPolicy.limits, rowByName = Object.create(null);
    for (var rowIndex = 0;rowIndex < rows.length; rowIndex += 1)
      rowByName[rows[rowIndex].name] = rows[rowIndex];
    var names = Object.keys(requiredLimits);
    for (var nameIndex = 0;nameIndex < names.length; nameIndex += 1) {
      var name = names[nameIndex], requested = requiredLimits[name];
      if (requested === void 0)
        continue;
      var row = rowByName[name];
      if (!row || row.requestable !== !0)
        return {
          fact: "adapterRequestValid",
          predicateId: "adapter.request-device.limits",
          message: "unknown or non-requestable required limit"
        };
      var number;
      try {
        number = Number(requested);
      } catch (error) {
        return {
          fact: "adapterRequestValid",
          predicateId: "adapter.request-device.limits",
          message: "required limit is not numeric"
        };
      }
      if (!Number.isFinite(number) || Math.floor(number) !== number || number < 0)
        return {
          fact: "adapterRequestValid",
          predicateId: "adapter.request-device.limits",
          message: "required limit is not a nonnegative integer"
        };
      var adapterBoundary = adapter.limits[name], profileBoundary = row.profileBucket[adapter.featureLevel], grantBoundary = row.capabilityGrantBoundary[adapter.featureLevel];
      if (row.class === "maximum") {
        var maximumBoundary = Math.min(adapterBoundary, profileBoundary, grantBoundary);
        if (number > maximumBoundary)
          return {
            fact: "adapterRequestValid",
            predicateId: "adapter.request-device.limits",
            message: "required maximum is better than the boundary"
          };
      } else {
        var alignmentBoundary = Math.max(adapterBoundary, profileBoundary, grantBoundary);
        if (!isPowerOfTwoBelowU32(number) || number < alignmentBoundary)
          return {
            fact: "adapterRequestValid",
            predicateId: "adapter.request-device.limits",
            message: "required alignment is better than the boundary"
          };
      }
    }
    return null;
  }
  function buildRequestDeviceProviderDescriptor(adapter, copy) {
    var logicalFeatures = [], requestedFeatures = copy.requiredFeatures;
    if (requestedFeatures === void 0)
      requestedFeatures = [];
    for (var featureIndex = 0;featureIndex < requestedFeatures.length; featureIndex += 1) {
      var feature = requestedFeatures[featureIndex];
      if (adapter.features.indexOf(feature) !== -1 && logicalFeatures.indexOf(feature) === -1)
        logicalFeatures.push(feature);
    }
    applyFeatureImplications(logicalFeatures, plan.semantic.featurePolicy.newDeviceFeatureImplications);
    var defaultFeatures = plan.semantic.featurePolicy.defaultFeatures[adapter.featureLevel];
    for (featureIndex = 0;featureIndex < defaultFeatures.length; featureIndex += 1)
      addFeature(logicalFeatures, defaultFeatures[featureIndex]);
    logicalFeatures.sort();
    var logicalLimits = {}, requiredLimits = copy.requiredLimits;
    if (requiredLimits === void 0)
      requiredLimits = {};
    var rows = plan.semantic.limitPolicy.limits;
    for (var rowIndex = 0;rowIndex < rows.length; rowIndex += 1) {
      var row = rows[rowIndex], logicalValue = adapter.featureLevel === "core" ? row.coreDefault : row.compatibilityDefault, requested = requiredLimits[row.name];
      if (requested !== void 0) {
        var converted = Number(requested), isBetter = row.class === "maximum" ? converted > logicalValue : converted < logicalValue;
        if (isBetter)
          logicalValue = converted;
      }
      logicalLimits[row.name] = logicalValue;
    }
    logicalLimits.maxStorageBuffersPerShaderStage = Math.max(logicalLimits.maxStorageBuffersPerShaderStage, logicalLimits.maxStorageBuffersInVertexStage, logicalLimits.maxStorageBuffersInFragmentStage);
    logicalLimits.maxStorageTexturesPerShaderStage = Math.max(logicalLimits.maxStorageTexturesPerShaderStage, logicalLimits.maxStorageTexturesInVertexStage, logicalLimits.maxStorageTexturesInFragmentStage);
    if (logicalFeatures.indexOf("core-features-and-limits") !== -1) {
      logicalLimits.maxStorageBuffersInVertexStage = logicalLimits.maxStorageBuffersPerShaderStage;
      logicalLimits.maxStorageBuffersInFragmentStage = logicalLimits.maxStorageBuffersPerShaderStage;
      logicalLimits.maxStorageTexturesInVertexStage = logicalLimits.maxStorageTexturesPerShaderStage;
      logicalLimits.maxStorageTexturesInFragmentStage = logicalLimits.maxStorageTexturesPerShaderStage;
    }
    return {
      logicalFeatures,
      logicalLimits,
      serviceInternalRequirements: {
        schema: "exact/webgpu-service-internal-requirements/1",
        requiredFeatures: [],
        requiredLimits: {}
      }
    };
  }
  function selectRequestDeviceTerminal(adapter, directFacts) {
    var realmAdmissionLive = !adapter.realm.closed && !adapter.realm.accountClosed, facts = {
      webidlValid: !0,
      requiredFeaturesSupported: !0,
      adapterRequestValid: !0,
      deviceAdmissionValid: realmAdmissionLive,
      adapterExpired: Boolean(adapter.expired),
      deviceExpiryResultCommitLive: !0,
      deviceReservationCapacityAvailable: !0,
      deviceCapacityResultCommitLive: !0,
      deviceReservationCommitLive: !0,
      providerFulfilled: !0,
      deviceAccountLiveAtProviderCompletion: !0,
      deviceAccountLiveAtSettlementCommit: !0,
      providerInabilityWonLossRace: !1
    }, overrides = adapter.nextRequestDeviceFacts || {};
    adapter.nextRequestDeviceFacts = null;
    var overrideNames = Object.keys(overrides);
    for (var overrideIndex = 0;overrideIndex < overrideNames.length; overrideIndex += 1) {
      var overrideName = overrideNames[overrideIndex];
      if (overrideName === "deviceAdmissionValid")
        facts.deviceAdmissionValid = facts.deviceAdmissionValid && overrides.deviceAdmissionValid;
      else
        facts[overrideName] = overrides[overrideName];
    }
    var directNames = directFacts ? Object.keys(directFacts) : [];
    for (var directIndex = 0;directIndex < directNames.length; directIndex += 1)
      facts[directNames[directIndex]] = directFacts[directNames[directIndex]];
    var terminals = plan.semantic.requestDeviceRouting.terminals;
    for (var terminalIndex = 0;terminalIndex < terminals.length; terminalIndex += 1) {
      var terminal = terminals[terminalIndex], conditionNames = Object.keys(terminal.conditions), matches = !0;
      for (var conditionIndex = 0;conditionIndex < conditionNames.length; conditionIndex += 1) {
        var condition = conditionNames[conditionIndex];
        if (facts[condition] !== terminal.conditions[condition]) {
          matches = !1;
          break;
        }
      }
      if (matches) {
        var admissionFailurePredicateId = null;
        if (terminal.errorSource && terminal.errorSource.kind === "first-failing-predicate" && terminal.errorSource.branchId === "live-admission")
          admissionFailurePredicateId = adapter.realm.closed ? "adapter.request-device.realm" : adapter.realm.accountClosed ? "adapter.request-device.account" : "adapter.request-device.coverage";
        return {
          terminal,
          admissionFailurePredicateId,
          facts
        };
      }
    }
    throw Error("authenticated requestDevice precedence selected no terminal");
  }
  function lostDiagnostic(terminal) {
    var source = terminal.lostSettlement.diagnosticSource;
    if (source === "generic-expired-adapter")
      return "adapter is expired";
    if (source === "generic-capacity-unavailable")
      return "device capacity is unavailable";
    if (source === "generic-provider-inability")
      return "provider could not create a device";
    return "GPU account closed";
  }
  function terminalRequiresAccountClose(terminal) {
    return terminal.publicationCreditDisposition.indexOf("account-close") !== -1 || terminal.conditions.deviceAccountLiveAtProviderCompletion === !1 || terminal.conditions.deviceAccountLiveAtSettlementCommit === !1;
  }
  function traceProviderCompletion(call, facts) {
    traceRealm(call.realm, "provider-completion", call, {
      providerFulfilled: facts.providerFulfilled,
      accountLive: facts.deviceAccountLiveAtProviderCompletion
    });
  }
  function settleTerminalPublication(call, terminal, closeAlreadyWon) {
    var disposition = terminal.publicationCreditDisposition;
    if (disposition === "account-close-retired-exactly-once") {
      if (!closeAlreadyWon)
        closeAccountState(call.realm, "authenticated requestDevice close terminal", call, null);
      retirePublicationCredit(call.publicationCredit);
      return;
    }
    if (disposition === "returned-to-adapter-reusable-after-public-settlement") {
      returnPublicationCredit(call);
      return;
    }
    if (disposition === "returned-after-public-settlement-then-account-close-retired-exactly-once") {
      returnPublicationCredit(call);
      if (!closeAlreadyWon)
        closeAccountState(call.realm, "authenticated requestDevice close terminal", call, null);
      retirePublicationCredit(call.publicationCredit);
      return;
    }
    throw Error("unknown acquired publication-credit disposition: " + disposition);
  }
  defineMethod(prototypeFor("GPU"), "getPreferredCanvasFormat", function() {
    var state = requireReceiver(this, "GPU");
    beginPublic(state.realm, "GPU.getPreferredCanvasFormat", state, null);
    return "bgra8unorm";
  });
  defineMethod(prototypeFor("GPU"), "requestAdapter", function(options) {
    var state = requireReceiver(this, "GPU"), call = beginPublic(state.realm, "GPU.requestAdapter", state, null);
    call.promiseId = allocatePromiseId(call);
    return promiseOperation(call, function() {
      var copy = snapshotDictionary(options, "GPURequestAdapterOptions");
      copy.featureLevel = copy.featureLevel === void 0 ? "core" : String(copy.featureLevel);
      if (copy.featureLevel !== "core" && copy.featureLevel !== "compatibility")
        return null;
      assertRealmAdmission(state.realm);
      call.operationProviderGeneration = state.realm.nextProviderGeneration++;
      serviceCall(state.realm.client, call, copy, !0, null);
      if (state.realm.requestAdapterUnavailable)
        return null;
      var adapter = allocateWrapper(state.realm, "GPUAdapter", null, {
        expired: !1,
        providerGeneration: call.operationProviderGeneration,
        featureLevel: copy.featureLevel,
        features: projectedFakeAdapterFeatures(),
        limits: Object.assign({}, plan.fakeClientData.adapterLimits),
        nextRequestDeviceOrdinal: 1,
        publicationCredit: null
      }), adapterState = wrapperStates.get(adapter);
      adapterState.publicationCredit = {
        id: state.realm.nextPublicationCredit++,
        state: "available",
        ownerAdapterHandle: adapterState.handle,
        leaseOrdinal: 0,
        activeOperationInstanceId: 0,
        acquireCount: 0,
        returnCount: 0,
        retireCount: 0
      };
      state.realm.adapters.push(adapterState);
      setCallResult(call, wrapperStates.get(adapter));
      return adapter;
    });
  });
  defineMethod(prototypeFor("GPUAdapter"), "requestDevice", function(descriptor) {
    var adapter = requireReceiver(this, "GPUAdapter"), call = beginPublic(adapter.realm, "GPUAdapter.requestDevice", adapter, null);
    call.promiseId = allocatePromiseId(call);
    return promiseOperation(call, function() {
      var copy, descriptorFailure = null, selection;
      try {
        copy = snapshotDictionary(descriptor, "GPUDeviceDescriptor");
      } catch (error) {
        selection = selectRequestDeviceTerminal(adapter, { webidlValid: !1 });
        call.requestDeviceFacts = selection.facts;
        throw requestDeviceRejection(call, selection.terminal, "adapter.request-device.webidl", error.message || "GPUDeviceDescriptor conversion failed");
      }
      descriptorFailure = validateDeviceDescriptor(adapter, copy);
      var logicalProviderDescriptor = descriptorFailure ? null : buildRequestDeviceProviderDescriptor(adapter, copy), descriptorFacts = {};
      if (descriptorFailure)
        descriptorFacts[descriptorFailure.fact] = !1;
      selection = selectRequestDeviceTerminal(adapter, descriptorFacts);
      var terminal = selection.terminal;
      call.requestDeviceFacts = selection.facts;
      if (terminal.publicationCreditDisposition === "not-acquired")
        throw requestDeviceRejection(call, terminal, descriptorFailure ? descriptorFailure.predicateId : selection.admissionFailurePredicateId, descriptorFailure ? descriptorFailure.message : "logical device admission was rejected");
      call.preProviderTerminalId = null;
      acquirePublicationCredit(adapter, call);
      var device;
      call.requestDeviceTerminalId = terminal.terminalId;
      call.requestDeviceTerminal = terminal;
      var providerRoutingTerminal = selectProviderRoutingTerminal(call, selection.facts);
      if (providerRoutingTerminal.terminalId !== terminal.terminalId)
        throw Error("requestDevice provider routing selected a different terminal");
      if (terminal.resultDisposition === "promise-reject") {
        serviceCall(adapter.realm.client, call, copy, !0, null, logicalProviderDescriptor);
        if (terminal.adapterStateAfterSettlement === "expired")
          adapter.expired = !0;
        settleTerminalPublication(call, terminal, !1);
        throw requestDeviceRejection(call, terminal, null, "requestDevice lost a close race");
      }
      if (terminal.resultDisposition === "promise-resolve-lost-object") {
        device = createDevice(adapter.realm, adapter.providerGeneration, !0, logicalProviderDescriptor);
        setCallResult(call, wrapperStates.get(device));
        if (terminal.providerTokenCount === 1)
          commitLiveDeviceCredits(call.resultState.device, call);
        serviceCall(adapter.realm.client, call, copy, !0, null, logicalProviderDescriptor);
        var closeWonBeforeLoss = terminalRequiresAccountClose(terminal) && terminal.lostSettlement.arbiterWinner === "account-close";
        if (terminal.providerTokenCount === 1 && selection.facts.deviceAccountLiveAtProviderCompletion !== !1)
          traceProviderCompletion(call, selection.facts);
        if (closeWonBeforeLoss)
          closeAccountState(call.realm, "authenticated requestDevice account-close winner", call, call.publicationCredit);
        if (terminal.providerTokenCount === 1 && selection.facts.deviceAccountLiveAtProviderCompletion === !1)
          traceProviderCompletion(call, selection.facts);
        loseDevice(call.resultState.device, terminal.lostSettlement.reason, lostDiagnostic(terminal), !1, call);
        if (terminal.adapterStateAfterSettlement === "expired")
          adapter.expired = !0;
        settleTerminalPublication(call, terminal, closeWonBeforeLoss);
        return device;
      }
      device = createDevice(adapter.realm, adapter.providerGeneration, !1, logicalProviderDescriptor);
      setCallResult(call, wrapperStates.get(device));
      commitLiveDeviceCredits(call.resultState.device, call);
      serviceCall(adapter.realm.client, call, copy, !0, null, logicalProviderDescriptor);
      traceProviderCompletion(call, selection.facts);
      if (terminal.adapterStateAfterSettlement === "expired")
        adapter.expired = !0;
      settleTerminalPublication(call, terminal, !1);
      return device;
    });
  });
  defineMethod(prototypeFor("GPUCanvasContext"), "configure", function(configuration) {
    var context = requireReceiver(this, "GPUCanvasContext"), copy = snapshotDictionary(configuration, "GPUCanvasConfiguration"), deviceState = argumentState(copy.device, "GPUDevice"), call = beginPublic(context.realm, "GPUCanvasContext.configure", context, null);
    if (deviceState.realm !== context.realm) {
      serviceError(call, { configuration: copy, relationship: "cross-realm-device" }, "GPUValidationError", "cross-realm device", "validation-error");
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
    serviceCall(context.realm.client, call, { configuration: copy }, !1, null);
  });
  defineMethod(prototypeFor("GPUCanvasContext"), "getConfiguration", function() {
    var context = requireReceiver(this, "GPUCanvasContext");
    beginPublic(context.realm, "GPUCanvasContext.getConfiguration", context, null);
    if (!context.configuration)
      return null;
    return snapshotDictionary(context.configuration, "GPUCanvasConfiguration");
  });
  defineMethod(prototypeFor("GPUCanvasContext"), "getCurrentTexture", function() {
    var context = requireReceiver(this, "GPUCanvasContext"), call = beginPublic(context.realm, "GPUCanvasContext.getCurrentTexture", context, null);
    if (!context.configuration || !context.configuredDevice)
      throw namedError("InvalidStateError", "canvas context is not configured");
    assignCallDeviceIngress(call, context.configuredDevice);
    if (context.currentTexture) {
      setCallPreallocatedTarget(call, wrapperStates.get(context.currentTexture));
      appendLocal(call, {
        sameEpoch: !0,
        mintOrigin: call.targetState.currentOrigin
      }, null);
      return context.currentTexture;
    }
    var texture = allocateWrapper(context.realm, "GPUTexture", context.configuredDevice, {
      destroyed: !1,
      expired: !1,
      materialized: !1,
      currentOrigin: {
        contextHandle: context.handle,
        attachmentGeneration: context.attachmentGeneration,
        configurationGeneration: context.configurationGeneration,
        currentEpoch: ++context.currentEpoch,
        mintOperationInstanceId: call.operationInstanceId
      }
    });
    context.currentTexture = texture;
    setCallPreallocatedTarget(call, wrapperStates.get(texture));
    appendLocal(call, { mintOrigin: call.targetState.currentOrigin }, null);
    return texture;
  });
  defineMethod(prototypeFor("GPUCanvasContext"), "unconfigure", function() {
    var context = requireReceiver(this, "GPUCanvasContext"), call = beginPublic(context.realm, "GPUCanvasContext.unconfigure", context, null), wasConfigured = Boolean(context.configuration && context.configuredDevice);
    selectProviderRoutingTerminal(call, {
      alreadyTerminal: !wasConfigured,
      cleanupPredicatesValid: !0
    });
    if (context.configuredDevice)
      assignCallDeviceIngress(call, context.configuredDevice);
    serviceCall(context.realm.client, call, { configurationGeneration: context.configurationGeneration }, !1, null);
    expireCurrentTexture(context);
    context.configuration = null;
    context.configuredDevice = null;
  });
  defineMethod(prototypeFor("GPUDevice"), "createBindGroupLayout", function(descriptor) {
    var state = requireReceiver(this, "GPUDevice"), copy = snapshotDictionary(descriptor, "GPUBindGroupLayoutDescriptor"), layout = allocateWrapper(state.realm, "GPUBindGroupLayout", state.device, {}), call = beginPublic(state.realm, "GPUDevice.createBindGroupLayout", state, wrapperStates.get(layout));
    if (deviceIsUnavailable(state.device))
      serviceError(call, copy, "GPUValidationError", "device is unavailable", "invalid-state");
    else
      serviceCall(state.realm.client, call, copy, !1, null);
    return layout;
  });
  defineMethod(prototypeFor("GPUDevice"), "createCommandEncoder", function(descriptor) {
    var state = requireReceiver(this, "GPUDevice"), copy = snapshotDictionary(descriptor, "GPUCommandEncoderDescriptor"), encoder = allocateWrapper(state.realm, "GPUCommandEncoder", state.device, {
      status: "recording",
      activePass: null,
      records: [],
      invalid: !1
    }), call = beginPublic(state.realm, "GPUDevice.createCommandEncoder", state, wrapperStates.get(encoder));
    if (deviceIsUnavailable(state.device))
      serviceError(call, copy, "GPUValidationError", "device is unavailable", "invalid-state");
    else
      serviceCall(state.realm.client, call, copy, !1, null);
    return encoder;
  });
  defineMethod(prototypeFor("GPUDevice"), "createShaderModule", function(descriptor) {
    var state = requireReceiver(this, "GPUDevice"), copy = snapshotDictionary(descriptor, "GPUShaderModuleDescriptor");
    if (typeof copy.code !== "string")
      throw typeError("GPUShaderModuleDescriptor.code must be a string");
    var module = allocateWrapper(state.realm, "GPUShaderModule", state.device, {}), call = beginPublic(state.realm, "GPUDevice.createShaderModule", state, wrapperStates.get(module));
    if (deviceIsUnavailable(state.device))
      serviceError(call, copy, "GPUValidationError", "device is unavailable", "invalid-state");
    else
      serviceCall(state.realm.client, call, copy, !1, null);
    return module;
  });
  defineMethod(prototypeFor("GPUDevice"), "createRenderPipeline", function(descriptor) {
    var state = requireReceiver(this, "GPUDevice"), copy = snapshotDictionary(descriptor, "GPURenderPipelineDescriptor"), validationMessage = "";
    if (!copy.vertex || typeof copy.vertex !== "object")
      throw typeError("GPURenderPipelineDescriptor.vertex must be a dictionary");
    var vertexModule = argumentState(copy.vertex.module, "GPUShaderModule");
    if (vertexModule.realm !== state.realm || vertexModule.device !== state.device)
      validationMessage = "vertex shader module belongs to another realm or device";
    if (copy.fragment !== void 0) {
      if (!copy.fragment || typeof copy.fragment !== "object")
        throw typeError("GPURenderPipelineDescriptor.fragment must be a dictionary");
      var fragmentModule = argumentState(copy.fragment.module, "GPUShaderModule");
      if (fragmentModule.realm !== state.realm || fragmentModule.device !== state.device)
        validationMessage = "fragment shader module belongs to another realm or device";
    }
    var pipeline = allocateWrapper(state.realm, "GPURenderPipeline", state.device, {}), call = beginPublic(state.realm, "GPUDevice.createRenderPipeline", state, wrapperStates.get(pipeline));
    if (deviceIsUnavailable(state.device))
      validationMessage = "device is unavailable";
    if (validationMessage)
      serviceError(call, copy, "GPUValidationError", validationMessage, "validation-error");
    else
      serviceCall(state.realm.client, call, copy, !1, null);
    return pipeline;
  });
  defineMethod(prototypeFor("GPUDevice"), "destroy", function() {
    var state = requireReceiver(this, "GPUDevice"), call = beginPublic(state.realm, "GPUDevice.destroy", state, null), alreadyDestroyed = state.device.destroyed, alreadyLost = state.device.lostSettled;
    selectProviderRoutingTerminal(call, {
      alreadyTerminal: alreadyDestroyed || alreadyLost,
      cleanupPredicatesValid: !0
    });
    serviceCall(state.realm.client, call, {
      alreadyDestroyed,
      alreadyLost
    }, !1, null);
    if (!alreadyDestroyed) {
      state.device.destroyed = !0;
      loseDevice(state.device, "destroyed", "device was destroyed", !1, call);
    }
  });
  defineGetter(prototypeFor("GPUDevice"), "features", function() {
    var state = requireReceiver(this, "GPUDevice");
    beginPublic(state.realm, "GPUDevice.features", state, null);
    return state.device.features;
  });
  defineGetter(prototypeFor("GPUDevice"), "limits", function() {
    var state = requireReceiver(this, "GPUDevice");
    beginPublic(state.realm, "GPUDevice.limits", state, null);
    return state.device.limits;
  });
  defineGetter(prototypeFor("GPUDevice"), "lost", function() {
    var state = requireReceiver(this, "GPUDevice");
    beginPublic(state.realm, "GPUDevice.lost", state, null);
    return state.device.lost;
  });
  defineGetter(prototypeFor("GPUDevice"), "queue", function() {
    var state = requireReceiver(this, "GPUDevice"), call = beginPublic(state.realm, "GPUDevice.queue", state, null);
    setCallResult(call, wrapperStates.get(state.device.queue));
    return state.device.queue;
  });
  defineMethod(prototypeFor("GPUDevice"), "pushErrorScope", function(filter) {
    var state = requireReceiver(this, "GPUDevice"), convertedFilter = String(filter);
    if (convertedFilter !== "validation" && convertedFilter !== "out-of-memory" && convertedFilter !== "internal")
      throw typeError("unknown GPUErrorFilter");
    var call = beginPublic(state.realm, "GPUDevice.pushErrorScope", state, null), id = state.device.nextScope++;
    serviceCall(state.realm.client, call, { scopeId: id, filter: convertedFilter }, !1, null);
    state.device.localScopes.push(id);
    state.device.serviceScopes.push({ id, filter: convertedFilter, error: null });
  });
  defineMethod(prototypeFor("GPUDevice"), "popErrorScope", function() {
    var state = requireReceiver(this, "GPUDevice"), call = beginPublic(state.realm, "GPUDevice.popErrorScope", state, null);
    call.promiseId = allocatePromiseId(call);
    var lost = state.device.lostSettled, scopeId = lost ? 0 : state.device.localScopes.length > 0 ? state.device.localScopes[state.device.localScopes.length - 1] : 0;
    selectProviderRoutingTerminal(call, {
      deviceLost: lost,
      scopeNonempty: scopeId !== 0
    });
    call.skipLocalPrefixFlush = lost;
    serviceCall(state.realm.client, call, {
      scopeId,
      barrier: call.deviceIngressOrdinal,
      deviceLost: lost
    }, !0, null);
    if (lost)
      return promiseOperation(call, function() {
        return null;
      });
    if (!scopeId)
      return promiseOperation(call, function() {
        throw namedError("OperationError", "error scope stack is empty");
      });
    state.device.localScopes.pop();
    var scope = state.device.serviceScopes.pop();
    return promiseOperation(call, function() {
      return scope.error;
    });
  });
  defineMethod(prototypeFor("GPUCommandEncoder"), "beginRenderPass", function(descriptor) {
    var encoder = requireReceiver(this, "GPUCommandEncoder"), copy = snapshotDictionary(descriptor, "GPURenderPassDescriptor"), attachments = copy.colorAttachments;
    if (attachments === void 0)
      attachments = [];
    if (!Array.isArray(attachments))
      throw typeError("colorAttachments must be a sequence");
    var relationshipError = !1;
    for (var index = 0;index < attachments.length; index += 1) {
      if (!attachments[index] || typeof attachments[index] !== "object")
        throw typeError("color attachment must be a dictionary");
      var view = argumentState(attachments[index].view, "GPUTextureView");
      if (view.realm !== encoder.realm || view.device !== encoder.device)
        relationshipError = !0;
    }
    var canOpen = encoder.status === "recording" && !encoder.activePass && !encoder.invalid && !relationshipError, pass = allocateWrapper(encoder.realm, "GPURenderPassEncoder", encoder.device, {
      encoder,
      status: canOpen ? "open" : "invalid",
      records: [],
      invalid: !canOpen
    }), passState = wrapperStates.get(pass), call = beginPublic(encoder.realm, "GPUCommandEncoder.beginRenderPass", encoder, passState), errorSpec = null;
    if (encoder.status !== "recording" || encoder.activePass || encoder.invalid)
      errorSpec = {
        name: "GPUValidationError",
        message: "command encoder cannot begin a pass",
        failureClass: "invalid-state"
      };
    if (relationshipError)
      errorSpec = {
        name: "GPUValidationError",
        message: "render attachment belongs to another realm or device",
        failureClass: "validation-error"
      };
    if (canOpen)
      encoder.activePass = passState;
    else
      encoder.invalid = !0;
    encoder.records.push({ operation: "beginRenderPass", descriptor: copy });
    appendLocal(call, copy, errorSpec);
    return pass;
  });
  defineMethod(prototypeFor("GPUCommandEncoder"), "finish", function(descriptor) {
    var encoder = requireReceiver(this, "GPUCommandEncoder"), copy = snapshotDictionary(descriptor, "GPUCommandBufferDescriptor"), errorSpec = null;
    if (encoder.status !== "recording" || encoder.activePass || encoder.invalid)
      errorSpec = {
        name: "GPUValidationError",
        message: "command encoder cannot finish",
        failureClass: "invalid-state"
      };
    encoder.status = "finished";
    encoder.records.push({ operation: "finish", descriptor: copy });
    var buffer = allocateWrapper(encoder.realm, "GPUCommandBuffer", encoder.device, {
      submitted: !1,
      invalid: Boolean(errorSpec),
      program: encoder.records.slice()
    }), bufferState = wrapperStates.get(buffer), call = beginPublic(encoder.realm, "GPUCommandEncoder.finish", encoder, bufferState);
    appendLocal(call, copy, errorSpec);
    return buffer;
  });
  function toU32(value, label, defaultValue) {
    if (value === void 0)
      return defaultValue;
    var number = Number(value);
    if (!Number.isFinite(number) || Math.floor(number) !== number || number < 0 || number > 4294967295)
      throw typeError(label + " must be an unsigned 32-bit integer");
    return number;
  }
  defineMethod(prototypeFor("GPURenderPassEncoder"), "draw", function(vertexCount, instanceCount, firstVertex, firstInstance) {
    var pass = requireReceiver(this, "GPURenderPassEncoder");
    if (vertexCount === void 0)
      throw typeError("vertexCount is required");
    var argumentBody = {
      vertexCount: toU32(vertexCount, "vertexCount", void 0),
      instanceCount: toU32(instanceCount, "instanceCount", 1),
      firstVertex: toU32(firstVertex, "firstVertex", 0),
      firstInstance: toU32(firstInstance, "firstInstance", 0)
    }, call = beginPublic(pass.realm, "GPURenderPassEncoder.draw", pass, null), errorSpec = pass.status === "open" && !pass.invalid ? null : {
      name: "GPUValidationError",
      message: "render pass has ended",
      failureClass: "invalid-state"
    };
    pass.records.push({ operation: "draw", arguments: argumentBody });
    pass.encoder.records.push({ operation: "draw", arguments: argumentBody });
    if (errorSpec) {
      pass.invalid = !0;
      pass.encoder.invalid = !0;
    }
    appendLocal(call, argumentBody, errorSpec);
  });
  defineMethod(prototypeFor("GPURenderPassEncoder"), "setPipeline", function(pipelineValue) {
    var pass = requireReceiver(this, "GPURenderPassEncoder"), pipeline = argumentState(pipelineValue, "GPURenderPipeline"), call = beginPublic(pass.realm, "GPURenderPassEncoder.setPipeline", pass, null), errorSpec = null;
    if (pipeline.realm !== pass.realm || pipeline.device !== pass.device)
      errorSpec = {
        name: "GPUValidationError",
        message: "pipeline belongs to another realm or device",
        failureClass: "validation-error"
      };
    else if (pass.status !== "open" || pass.invalid)
      errorSpec = {
        name: "GPUValidationError",
        message: "render pass has ended",
        failureClass: "invalid-state"
      };
    var payload = { pipeline: pipelineValue };
    pass.records.push({ operation: "setPipeline", pipeline: pipelineValue });
    pass.encoder.records.push({ operation: "setPipeline", pipeline: pipelineValue });
    if (errorSpec) {
      pass.invalid = !0;
      pass.encoder.invalid = !0;
    }
    appendLocal(call, payload, errorSpec);
  });
  defineMethod(prototypeFor("GPURenderPassEncoder"), "end", function() {
    var pass = requireReceiver(this, "GPURenderPassEncoder"), call = beginPublic(pass.realm, "GPURenderPassEncoder.end", pass, null), errorSpec = pass.status === "open" ? null : {
      name: "GPUValidationError",
      message: "render pass already ended",
      failureClass: "invalid-state"
    };
    pass.status = "ended";
    if (pass.encoder.activePass === pass)
      pass.encoder.activePass = null;
    if (errorSpec) {
      pass.invalid = !0;
      pass.encoder.invalid = !0;
    }
    pass.records.push({ operation: "end" });
    pass.encoder.records.push({ operation: "end" });
    appendLocal(call, {}, errorSpec);
  });
  defineMethod(prototypeFor("GPUQueue"), "submit", function(commandBuffers) {
    var queue = requireReceiver(this, "GPUQueue"), iteratorMethod = commandBuffers === null || commandBuffers === void 0 ? null : commandBuffers[Symbol.iterator];
    if (typeof iteratorMethod !== "function")
      throw typeError("commandBuffers must be an iterable sequence");
    var buffers = [], iterator = iteratorMethod.call(commandBuffers), step;
    while (!(step = iterator.next()).done) {
      if (buffers.length >= 1024)
        throw typeError("too many command buffers");
      buffers.push(argumentState(step.value, "GPUCommandBuffer"));
    }
    var call = beginPublic(queue.realm, "GPUQueue.submit", queue, null), errorSpec = null, sealedPrograms = [];
    for (var index = 0;index < buffers.length; index += 1) {
      var buffer = buffers[index];
      if (buffer.realm !== queue.realm || buffer.device !== queue.device)
        errorSpec = {
          name: "GPUValidationError",
          message: "command buffer belongs to another realm or device",
          failureClass: "validation-error"
        };
      else if (buffer.submitted)
        errorSpec = {
          name: "GPUValidationError",
          message: "command buffer is single-use",
          failureClass: "invalid-state"
        };
      else if (buffer.invalid)
        errorSpec = {
          name: "GPUValidationError",
          message: "command buffer contains invalid recorded commands",
          failureClass: "validation-error"
        };
      sealedPrograms.push({
        commandBufferRef: typedRef(buffer),
        invalid: Boolean(buffer.invalid),
        program: buffer.invalid ? [] : logValue(buffer.program, 0)
      });
    }
    if (!errorSpec && deviceIsUnavailable(queue.device))
      errorSpec = {
        name: "GPUValidationError",
        message: "device is unavailable",
        failureClass: "invalid-state"
      };
    if (JSON.stringify(sealedPrograms).length > plan.maxPayloadBytes)
      errorSpec = {
        name: "GPUValidationError",
        message: "sealed command program exceeds payload bound",
        failureClass: "validation-error"
      };
    if (!errorSpec)
      for (index = 0;index < buffers.length; index += 1)
        buffers[index].submitted = !0;
    if (errorSpec)
      serviceError(call, { commandBufferRecords: sealedPrograms }, errorSpec.name, errorSpec.message, errorSpec.failureClass);
    else
      serviceCall(queue.realm.client, call, { commandBufferRecords: sealedPrograms }, !1, null);
  });
  defineMethod(prototypeFor("GPUTexture"), "createView", function(descriptor) {
    var texture = requireReceiver(this, "GPUTexture"), copy = snapshotDictionary(descriptor, "GPUTextureViewDescriptor"), view = allocateWrapper(texture.realm, "GPUTextureView", texture.device, {
      texture
    }), call = beginPublic(texture.realm, "GPUTexture.createView", texture, wrapperStates.get(view)), invalid = texture.destroyed || texture.expired || deviceIsUnavailable(texture.device), payload = {
      descriptor: copy,
      mintOrigin: texture.currentOrigin || null
    };
    if (invalid)
      serviceError(call, payload, "GPUValidationError", "texture is not live", "invalid-state");
    else {
      texture.materialized = !0;
      serviceCall(texture.realm.client, call, payload, !1, null);
    }
    return view;
  });
  defineMethod(prototypeFor("GPUTexture"), "destroy", function() {
    var texture = requireReceiver(this, "GPUTexture"), call = beginPublic(texture.realm, "GPUTexture.destroy", texture, null), deviceUnavailable = deviceIsUnavailable(texture.device), payload = {
      mintOrigin: texture.currentOrigin || null,
      materializedBeforeDestroy: Boolean(texture.materialized),
      alreadyDestroyed: Boolean(texture.destroyed),
      expired: Boolean(texture.expired),
      deviceUnavailable
    };
    selectProviderRoutingTerminal(call, {
      alreadyTerminal: texture.destroyed || texture.expired || deviceUnavailable,
      cleanupPredicatesValid: !0
    });
    serviceCall(texture.realm.client, call, payload, !1, null);
    texture.destroyed = !0;
  });
  Object.freeze(prototypeFor("GPU"));
  Object.freeze(prototypeFor("GPUAdapter"));
  Object.freeze(prototypeFor("GPUBindGroupLayout"));
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
    var configuration = options && typeof options === "object" ? options : {}, client = Object.create(null);
    clientStates.set(client, {
      runtimePointerNonce: "test-runtime-" + nextRealmToken,
      receipts: [],
      events: [],
      lifecycle: []
    });
    var realm = {
      token: nextRealmToken++,
      generation: 1,
      accountToken: configuration.accountToken || "test-account",
      accountGeneration: 1,
      accountClosed: !1,
      closed: !1,
      client,
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
        reservations: []
      }
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
        currentTexture: null
      });
    }
    function inspect() {
      var clientState = requireClient(client);
      return logValue({
        schema: "ibex/webgpu-test-wrapper-observation/1",
        profileId: plan.profileId,
        projectionDigest: plan.digests.projection,
        fixtureDisposition: "test-only-no-runtime-install-no-support-claim",
        lifecycleState: {
          accountClosed: realm.accountClosed,
          realmClosed: realm.closed
        },
        routeIdentityMatrix: plan.routes.map(function(route) {
          return {
            operationId: route.operationId,
            interfaceName: route.interfaceName,
            memberName: route.memberName,
            memberKind: route.memberKind,
            receiverHandleKind: route.receiverHandleKind,
            wrapperAllocatedTargetHandleKind: route.wrapperAllocatedTargetHandleKind,
            resultHandleKind: route.resultHandleKind
          };
        }),
        requestDeviceTerminals: plan.semantic.requestDeviceRouting.terminals,
        requestDeviceFailureProgram: plan.semantic.requestDeviceFailureProgram,
        requestDeviceProviderDescriptor: plan.semantic.requestDeviceProviderDescriptor,
        providerRoutingPrograms: plan.semantic.providerRoutingPrograms,
        publicCalls: realm.publicCalls,
        serviceReceipts: clientState.receipts,
        events: clientState.events,
        lifecycleRequests: clientState.lifecycle,
        preProviderRejections: realm.preProviderRejections,
        orderingTrace: realm.orderingTrace,
        publicationCredits: realm.adapters.map(function(adapter) {
          return publicationCreditSnapshot(adapter.publicationCredit);
        }),
        liveDeviceLedger: {
          capacity: realm.liveDeviceLedger.capacity,
          leafActive: realm.liveDeviceLedger.leafActive,
          aggregateActive: realm.liveDeviceLedger.aggregateActive,
          commitCount: realm.liveDeviceLedger.commitCount,
          releaseCount: realm.liveDeviceLedger.releaseCount,
          reservations: realm.liveDeviceLedger.reservations.map(function(reservation) {
            return liveDeviceReservationSnapshot(reservation);
          })
        },
        uncapturedErrors: realm.devices.map(function(device) {
          return device.uncapturedErrors;
        })
      }, 0);
    }
    function present(contextValue) {
      var context = argumentState(contextValue, "GPUCanvasContext");
      if (context.realm !== realm)
        throw namedError("SecurityError", "cross-realm canvas context");
      expireCurrentTexture(context);
    }
    function injectError(deviceValue, errorClass, message) {
      var state = argumentState(deviceValue, "GPUDevice");
      if (state.realm !== realm)
        throw namedError("SecurityError", "cross-realm device");
      var name = errorClass === "out-of-memory" ? "GPUOutOfMemoryError" : errorClass === "internal" ? "GPUInternalError" : "GPUValidationError";
      state.device.nextForcedError = {
        name,
        message: String(message || "injected service error"),
        failureClass: String(errorClass || "validation-error"),
        physical: !0
      };
    }
    function providerLoss(deviceValue, message) {
      var state = argumentState(deviceValue, "GPUDevice");
      if (state.realm !== realm)
        throw namedError("SecurityError", "cross-realm device");
      loseDevice(state.device, "unknown", String(message || "provider lost"), !0);
    }
    function setRequestDeviceFacts(adapterValue, factsValue) {
      var adapter = argumentState(adapterValue, "GPUAdapter");
      if (adapter.realm !== realm)
        throw namedError("SecurityError", "cross-realm adapter");
      var facts = snapshotDictionary(factsValue, "requestDevice test facts"), allowed = {
        deviceAdmissionValid: !0,
        deviceExpiryResultCommitLive: !0,
        deviceReservationCapacityAvailable: !0,
        deviceCapacityResultCommitLive: !0,
        deviceReservationCommitLive: !0,
        providerFulfilled: !0,
        deviceAccountLiveAtProviderCompletion: !0,
        deviceAccountLiveAtSettlementCommit: !0,
        providerInabilityWonLossRace: !0
      }, names = Object.keys(facts);
      for (var index = 0;index < names.length; index += 1)
        if (!allowed[names[index]] || typeof facts[names[index]] !== "boolean")
          throw typeError("unknown or non-boolean requestDevice fact: " + names[index]);
      adapter.nextRequestDeviceFacts = facts;
    }
    function retire(value) {
      var state = wrapperStates.get(value);
      if (!state || state.realm !== realm)
        throw typeError("retire requires an owned branded wrapper");
      if (state.retired)
        return;
      state.retired = !0;
      requireClient(client).lifecycle.push({
        kind: "retire",
        realmToken: realm.token,
        realmGeneration: realm.generation,
        accountToken: realm.accountToken,
        accountGeneration: realm.accountGeneration,
        retireOrdinal: realm.nextLifecycleOrdinal++,
        typedReferences: [typedRef(state)]
      });
    }
    function cancel(promise) {
      var state = promiseStates.get(promise);
      if (!state || state.call.realm !== realm)
        throw typeError("cancel requires an owned pending promise");
      if (state.cancelled || state.call.terminal)
        return;
      state.cancelled = !0;
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
        cancelOrdinal: realm.nextLifecycleOrdinal++
      });
    }
    function closeAccount(cause) {
      closeAccountState(realm, cause, null);
    }
    function closeRealm(cause) {
      if (realm.closed)
        return;
      realm.closed = !0;
      var ordinal = realm.nextLifecycleOrdinal++, reason = String(cause || "test-realm-close");
      requireClient(client).lifecycle.push({
        kind: "realmClose",
        realmToken: realm.token,
        realmGeneration: realm.generation,
        closeOrdinal: ordinal,
        closeCause: reason
      });
      requireClient(client).events.push({
        tag: "realm-close-service-event-v1",
        kind: "realm-close",
        realmToken: realm.token,
        realmGeneration: realm.generation,
        closeOrdinal: ordinal,
        closeCause: reason,
        pendingSettlementPolicy: "reject-or-retire"
      });
      traceRealm(realm, "realm-close", null, { closeOrdinal: ordinal });
      for (var index = 0;index < realm.pendingPromises.length; index += 1)
        realm.pendingPromises[index].closed = !0;
      for (var adapterIndex = 0;adapterIndex < realm.adapters.length; adapterIndex += 1)
        retirePublicationCredit(realm.adapters[adapterIndex].publicationCredit);
      for (index = 0;index < realm.devices.length; index += 1)
        loseDevice(realm.devices[index], "unknown", "realm closed", !1);
    }
    function describe(value) {
      var state = wrapperStates.get(value);
      if (!state)
        return null;
      return Object.freeze({
        reference: Object.freeze(typedRef(state)),
        kind: state.kind,
        ownedRealm: state.realm === realm,
        deviceId: state.device ? state.device.id : 0,
        providerGeneration: state.device ? state.device.providerGeneration : state.providerGeneration || 0,
        featureLevel: state.kind === "GPUAdapter" ? state.featureLevel : null,
        serviceDetached: Boolean(state.device && state.device.serviceDetached),
        lostSettled: Boolean(state.device && state.device.lostSettled),
        destroyed: Boolean(state.destroyed || state.device && state.device.destroyed),
        expired: Boolean(state.expired),
        materialized: Boolean(state.materialized),
        publicationCredit: state.publicationCredit ? Object.freeze(publicationCreditSnapshot(state.publicationCredit)) : null,
        liveDeviceCredit: state.device && state.device.liveDeviceReservation ? Object.freeze(liveDeviceReservationSnapshot(state.device.liveDeviceReservation)) : null
      });
    }
    return Object.freeze({
      gpu,
      createCanvasContext,
      present,
      injectError,
      providerLoss,
      setRequestDeviceFacts,
      retire,
      cancel,
      closeAccount,
      closeRealm,
      describe,
      inspect
    });
  }
  return createHarness;
})({"schema":"ibex/webgpu-test-wrapper-plan/1","profileId":"exact-webgpu-v1-draft","scopeId":"native-triangle-plus-typegpu-graduates-v1","digests":{"operationSet":"b0190dfee00d4c7b3f29147a37bee8304f69d2cd82ae72df949fc5af42c6b66f","semanticProgramSet":"9ceb5fb5d9a1e8fb91715d2bb2ca64313efdd47c80d65eb80df337931e1c8030","runtimeRouting":"9af920f47b8ba28bcc66d10d85c88355ff3176fd8c199cafd0c605340e789dad","webgpuCVocabulary":"f627ed658ccab48eeb24008364ad23f09913b449a840e0c54d84801dcd857211","projection":"846ab45a6d4dc89ec410c8c85c9df8d457cbb8a3ba8017f3a8adeb92a68a4384"},"maxPayloadBytes":16777216,"semantic":{"digest":"4bb7d6eeabf900640e55b1bf4afdff91881eafb0a93b7a502191e4ae972e8932","featurePolicy":{"requiredFeatureValidation":"webidl-known-then-subset-of-adapter-profile-and-capability-grant","deviceProjection":"requested-plus-pinned-default-and-implied-features","defaultFeatures":{"core":["core-features-and-limits"],"compatibility":[]},"adapterFeatureImplications":[{"feature":"texture-compression-bc-sliced-3d","implies":"texture-compression-bc"},{"feature":"texture-compression-astc-sliced-3d","implies":"texture-compression-astc"}],"newDeviceFeatureImplications":[{"feature":"texture-formats-tier2","implies":"texture-formats-tier1"},{"feature":"texture-formats-tier1","implies":"rg11b10ufloat-renderable"}],"adapterRequiredFeatureAlternatives":[["texture-compression-bc"],["texture-compression-etc2","texture-compression-astc"]],"features":[{"name":"core-features-and-limits","classification":"standard","profileAdmission":"admitted"},{"name":"depth-clip-control","classification":"standard","profileAdmission":"admitted"},{"name":"depth32float-stencil8","classification":"standard","profileAdmission":"admitted"},{"name":"texture-compression-bc","classification":"standard","profileAdmission":"admitted"},{"name":"texture-compression-bc-sliced-3d","classification":"standard","profileAdmission":"admitted"},{"name":"texture-compression-etc2","classification":"standard","profileAdmission":"admitted"},{"name":"texture-compression-astc","classification":"standard","profileAdmission":"admitted"},{"name":"texture-compression-astc-sliced-3d","classification":"standard","profileAdmission":"admitted"},{"name":"timestamp-query","classification":"standard","profileAdmission":"admitted"},{"name":"indirect-first-instance","classification":"standard","profileAdmission":"admitted"},{"name":"shader-f16","classification":"standard","profileAdmission":"admitted"},{"name":"rg11b10ufloat-renderable","classification":"standard","profileAdmission":"admitted"},{"name":"bgra8unorm-storage","classification":"standard","profileAdmission":"admitted"},{"name":"float32-filterable","classification":"standard","profileAdmission":"admitted"},{"name":"float32-blendable","classification":"standard","profileAdmission":"admitted"},{"name":"clip-distances","classification":"standard","profileAdmission":"admitted"},{"name":"dual-source-blending","classification":"standard","profileAdmission":"admitted"},{"name":"subgroups","classification":"standard","profileAdmission":"admitted"},{"name":"texture-formats-tier1","classification":"standard","profileAdmission":"admitted"},{"name":"texture-formats-tier2","classification":"standard","profileAdmission":"admitted"},{"name":"primitive-index","classification":"standard","profileAdmission":"admitted"},{"name":"texture-component-swizzle","classification":"standard","profileAdmission":"admitted"},{"name":"subgroup-size-control","classification":"disabled-extension","profileAdmission":"denied"}]},"limitPolicy":{"requestValidation":{"undefinedValue":"skip-key-validation-and-projection","unknownNonUndefined":"operation-error-promise-rejection","maximum":"nonnegative-integer-no-better-than-adapter-profile-bucket-and-capability-grant","alignment":"power-of-two-less-than-2^32-and-no-better-than-adapter-profile-bucket-and-capability-grant"},"projectionRule":"start-from-feature-level-defaults-apply-only-better-nonundefined-requests-then-run-pinned-storage-limit-normalization","limits":[{"name":"maxTextureDimension1D","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":8192,"compatibilityDefault":4096,"profileBucket":{"core":8192,"compatibility":8192},"capabilityGrantBoundary":{"core":8192,"compatibility":8192}},{"name":"maxTextureDimension2D","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":8192,"compatibilityDefault":4096,"profileBucket":{"core":8192,"compatibility":8192},"capabilityGrantBoundary":{"core":8192,"compatibility":8192}},{"name":"maxTextureDimension3D","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":2048,"compatibilityDefault":2048,"profileBucket":{"core":2048,"compatibility":2048},"capabilityGrantBoundary":{"core":2048,"compatibility":2048}},{"name":"maxTextureArrayLayers","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":256,"compatibilityDefault":256,"profileBucket":{"core":256,"compatibility":256},"capabilityGrantBoundary":{"core":256,"compatibility":256}},{"name":"maxBindGroups","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":4,"compatibilityDefault":4,"profileBucket":{"core":4,"compatibility":4},"capabilityGrantBoundary":{"core":4,"compatibility":4}},{"name":"maxBindGroupsPlusVertexBuffers","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":24,"compatibilityDefault":24,"profileBucket":{"core":24,"compatibility":24},"capabilityGrantBoundary":{"core":24,"compatibility":24}},{"name":"maxBindingsPerBindGroup","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":1000,"compatibilityDefault":1000,"profileBucket":{"core":1000,"compatibility":1000},"capabilityGrantBoundary":{"core":1000,"compatibility":1000}},{"name":"maxDynamicUniformBuffersPerPipelineLayout","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":8,"compatibilityDefault":8,"profileBucket":{"core":8,"compatibility":8},"capabilityGrantBoundary":{"core":8,"compatibility":8}},{"name":"maxDynamicStorageBuffersPerPipelineLayout","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":4,"compatibilityDefault":4,"profileBucket":{"core":4,"compatibility":4},"capabilityGrantBoundary":{"core":4,"compatibility":4}},{"name":"maxSampledTexturesPerShaderStage","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":16,"compatibilityDefault":16,"profileBucket":{"core":16,"compatibility":16},"capabilityGrantBoundary":{"core":16,"compatibility":16}},{"name":"maxSamplersPerShaderStage","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":16,"compatibilityDefault":16,"profileBucket":{"core":16,"compatibility":16},"capabilityGrantBoundary":{"core":16,"compatibility":16}},{"name":"maxStorageBuffersPerShaderStage","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":8,"compatibilityDefault":8,"profileBucket":{"core":8,"compatibility":8},"capabilityGrantBoundary":{"core":8,"compatibility":8}},{"name":"maxStorageBuffersInVertexStage","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":8,"compatibilityDefault":0,"profileBucket":{"core":8,"compatibility":8},"capabilityGrantBoundary":{"core":8,"compatibility":8}},{"name":"maxStorageBuffersInFragmentStage","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":8,"compatibilityDefault":4,"profileBucket":{"core":8,"compatibility":8},"capabilityGrantBoundary":{"core":8,"compatibility":8}},{"name":"maxStorageTexturesPerShaderStage","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":4,"compatibilityDefault":4,"profileBucket":{"core":4,"compatibility":4},"capabilityGrantBoundary":{"core":4,"compatibility":4}},{"name":"maxStorageTexturesInVertexStage","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":4,"compatibilityDefault":0,"profileBucket":{"core":4,"compatibility":4},"capabilityGrantBoundary":{"core":4,"compatibility":4}},{"name":"maxStorageTexturesInFragmentStage","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":4,"compatibilityDefault":4,"profileBucket":{"core":4,"compatibility":4},"capabilityGrantBoundary":{"core":4,"compatibility":4}},{"name":"maxUniformBuffersPerShaderStage","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":12,"compatibilityDefault":12,"profileBucket":{"core":12,"compatibility":12},"capabilityGrantBoundary":{"core":12,"compatibility":12}},{"name":"maxUniformBufferBindingSize","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":65536,"compatibilityDefault":16384,"profileBucket":{"core":65536,"compatibility":65536},"capabilityGrantBoundary":{"core":65536,"compatibility":65536}},{"name":"maxStorageBufferBindingSize","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":134217728,"compatibilityDefault":134217728,"profileBucket":{"core":134217728,"compatibility":134217728},"capabilityGrantBoundary":{"core":134217728,"compatibility":134217728}},{"name":"minUniformBufferOffsetAlignment","requestable":true,"class":"alignment","betterDirection":"lower","coreDefault":256,"compatibilityDefault":256,"profileBucket":{"core":256,"compatibility":256},"capabilityGrantBoundary":{"core":256,"compatibility":256}},{"name":"minStorageBufferOffsetAlignment","requestable":true,"class":"alignment","betterDirection":"lower","coreDefault":256,"compatibilityDefault":256,"profileBucket":{"core":256,"compatibility":256},"capabilityGrantBoundary":{"core":256,"compatibility":256}},{"name":"maxVertexBuffers","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":8,"compatibilityDefault":8,"profileBucket":{"core":8,"compatibility":8},"capabilityGrantBoundary":{"core":8,"compatibility":8}},{"name":"maxBufferSize","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":268435456,"compatibilityDefault":268435456,"profileBucket":{"core":268435456,"compatibility":268435456},"capabilityGrantBoundary":{"core":268435456,"compatibility":268435456}},{"name":"maxVertexAttributes","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":16,"compatibilityDefault":16,"profileBucket":{"core":16,"compatibility":16},"capabilityGrantBoundary":{"core":16,"compatibility":16}},{"name":"maxVertexBufferArrayStride","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":2048,"compatibilityDefault":2048,"profileBucket":{"core":2048,"compatibility":2048},"capabilityGrantBoundary":{"core":2048,"compatibility":2048}},{"name":"maxInterStageShaderVariables","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":16,"compatibilityDefault":15,"profileBucket":{"core":16,"compatibility":16},"capabilityGrantBoundary":{"core":16,"compatibility":16}},{"name":"maxColorAttachments","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":8,"compatibilityDefault":4,"profileBucket":{"core":8,"compatibility":8},"capabilityGrantBoundary":{"core":8,"compatibility":8}},{"name":"maxColorAttachmentBytesPerSample","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":32,"compatibilityDefault":32,"profileBucket":{"core":32,"compatibility":32},"capabilityGrantBoundary":{"core":32,"compatibility":32}},{"name":"maxComputeWorkgroupStorageSize","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":16384,"compatibilityDefault":16384,"profileBucket":{"core":16384,"compatibility":16384},"capabilityGrantBoundary":{"core":16384,"compatibility":16384}},{"name":"maxComputeInvocationsPerWorkgroup","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":256,"compatibilityDefault":128,"profileBucket":{"core":256,"compatibility":256},"capabilityGrantBoundary":{"core":256,"compatibility":256}},{"name":"maxComputeWorkgroupSizeX","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":256,"compatibilityDefault":128,"profileBucket":{"core":256,"compatibility":256},"capabilityGrantBoundary":{"core":256,"compatibility":256}},{"name":"maxComputeWorkgroupSizeY","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":256,"compatibilityDefault":128,"profileBucket":{"core":256,"compatibility":256},"capabilityGrantBoundary":{"core":256,"compatibility":256}},{"name":"maxComputeWorkgroupSizeZ","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":64,"compatibilityDefault":64,"profileBucket":{"core":64,"compatibility":64},"capabilityGrantBoundary":{"core":64,"compatibility":64}},{"name":"maxComputeWorkgroupsPerDimension","requestable":true,"class":"maximum","betterDirection":"higher","coreDefault":65535,"compatibilityDefault":65535,"profileBucket":{"core":65535,"compatibility":65535},"capabilityGrantBoundary":{"core":65535,"compatibility":65535}},{"name":"maxImmediateSize","requestable":false,"class":"maximum","betterDirection":"higher","coreDefault":0,"compatibilityDefault":0,"profileBucket":{"core":0,"compatibility":0},"capabilityGrantBoundary":{"core":0,"compatibility":0}}]},"requestDeviceFailureProgram":{"operationId":"GPUAdapter.requestDevice","operationWireId":194635792,"branches":[{"branchId":"webidl","branchWireId":1147199790,"orderedPredicates":[{"predicateId":"adapter.request-device.webidl","predicateIndex":1,"predicateWireId":3946597711,"failureClass":"type-error","failureTiming":"promise-rejection"}]},{"branchId":"required-features-check","branchWireId":3315985549,"orderedPredicates":[{"predicateId":"adapter.request-device.timeline-head","predicateIndex":1,"predicateWireId":3461969651,"failureClass":"none","failureTiming":"none"},{"predicateId":"adapter.request-device.required-features","predicateIndex":2,"predicateWireId":2178036204,"failureClass":"type-error","failureTiming":"promise-rejection"}]},{"branchId":"adapter-validation","branchWireId":1526693743,"orderedPredicates":[{"predicateId":"adapter.request-device.limits","predicateIndex":1,"predicateWireId":2685413736,"failureClass":"operation-error","failureTiming":"promise-rejection"},{"predicateId":"adapter.request-device.capability-projection","predicateIndex":2,"predicateWireId":1496584302,"failureClass":"none","failureTiming":"none"}]},{"branchId":"live-admission","branchWireId":448486537,"orderedPredicates":[{"predicateId":"adapter.request-device.realm","predicateIndex":1,"predicateWireId":4256511629,"failureClass":"operation-error","failureTiming":"promise-rejection"},{"predicateId":"adapter.request-device.coverage","predicateIndex":2,"predicateWireId":2724553625,"failureClass":"security-error","failureTiming":"promise-rejection"},{"predicateId":"adapter.request-device.account","predicateIndex":3,"predicateWireId":1329779304,"failureClass":"security-error","failureTiming":"promise-rejection"},{"predicateId":"adapter.request-device.publication-credit","predicateIndex":4,"predicateWireId":1488720883,"failureClass":"none","failureTiming":"none"}]},{"branchId":"expiry-result-selection-commit","branchWireId":1586510580,"orderedPredicates":[{"predicateId":"adapter.request-device.expiry-result-commit","predicateIndex":1,"predicateWireId":2648522098,"failureClass":"operation-error","failureTiming":"promise-rejection"}]},{"branchId":"live-device-capacity","branchWireId":3360345703,"orderedPredicates":[{"predicateId":"adapter.request-device.capacity-live","predicateIndex":1,"predicateWireId":397073956,"failureClass":"none","failureTiming":"none"}]},{"branchId":"capacity-result-selection-commit","branchWireId":1962640843,"orderedPredicates":[{"predicateId":"adapter.request-device.capacity-result-commit","predicateIndex":1,"predicateWireId":404503266,"failureClass":"operation-error","failureTiming":"promise-rejection"}]},{"branchId":"live-device-commit","branchWireId":1982586618,"orderedPredicates":[{"predicateId":"adapter.request-device.commit-live","predicateIndex":1,"predicateWireId":2108884785,"failureClass":"operation-error","failureTiming":"promise-rejection"}]},{"branchId":"provider-request","branchWireId":533406880,"orderedPredicates":[{"predicateId":"adapter.request-device.provider-ready","predicateIndex":1,"predicateWireId":1494113071,"failureClass":"none","failureTiming":"none"}]},{"branchId":"provider-settlement","branchWireId":2109554215,"orderedPredicates":[{"predicateId":"adapter.request-device.settle-committed","predicateIndex":1,"predicateWireId":1486871225,"failureClass":"none","failureTiming":"none"}]}]},"requestDeviceRouting":{"operationId":"GPUAdapter.requestDevice","facts":["webidlValid","requiredFeaturesSupported","adapterRequestValid","deviceAdmissionValid","adapterExpired","deviceExpiryResultCommitLive","deviceReservationCapacityAvailable","deviceCapacityResultCommitLive","deviceReservationCommitLive","providerFulfilled","deviceAccountLiveAtProviderCompletion","deviceAccountLiveAtSettlementCommit","providerInabilityWonLossRace"],"precedence":["webidlValid","requiredFeaturesSupported","adapterRequestValid","deviceAdmissionValid","adapterExpired","deviceExpiryResultCommitLive","deviceReservationCapacityAvailable","deviceCapacityResultCommitLive","deviceReservationCommitLive","providerFulfilled","deviceAccountLiveAtProviderCompletion","deviceAccountLiveAtSettlementCommit","providerInabilityWonLossRace"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"webidl-rejection","conditions":{"webidlValid":false},"branchPath":["webidl"],"terminalOutcome":"reject the returned promise during Web IDL conversion","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"not-acquired","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"webidl"}},{"terminalId":"unsupported-required-features","conditions":{"webidlValid":true,"requiredFeaturesSupported":false},"branchPath":["webidl","required-features-check"],"terminalOutcome":"reject the promise with TypeError for unsupported requiredFeatures","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"not-acquired","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"required-features-check"}},{"terminalId":"invalid-adapter-request","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":false},"branchPath":["webidl","required-features-check","adapter-validation"],"terminalOutcome":"reject the promise with OperationError for invalid requiredLimits; expired adapters do not reject here","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"not-acquired","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"adapter-validation"}},{"terminalId":"live-admission-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission"],"terminalOutcome":"reject the promise during realm/coverage/account LIVE admission before observing expiry or publishing a result","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"not-acquired","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"live-admission"}},{"terminalId":"expiry-lost-selection-close-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":true,"deviceExpiryResultCommitLive":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit"],"terminalOutcome":"reject when close wins after observing adapter expiry but before lost-result selection; publish nothing and retire the publication-credit lease exactly once without provider work","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"account-close-retired-exactly-once","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"expiry-result-selection-commit"}},{"terminalId":"expired-adapter-lost-device","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":true,"deviceExpiryResultCommitLive":true},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit"],"terminalOutcome":"resolve a fresh distinct service-detached already-lost GPUDevice after its stable lost promise settles with reason unknown and the generic expired-adapter diagnostic; return the reusable publication credit and perform no provider request","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-to-adapter-reusable-after-public-settlement","liveDeviceCreditDisposition":"not-acquired","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"generic-expired-adapter","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"expired-adapter"},"providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"pre-capacity-close-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit"],"terminalOutcome":"reject when close wins after the non-expired observation but before capacity observation; publish nothing and retire the publication-credit lease exactly once without provider work","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"account-close-retired-exactly-once","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"expiry-result-selection-commit"}},{"terminalId":"capacity-lost-selection-close-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":false,"deviceCapacityResultCommitLive":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit"],"terminalOutcome":"reject when close wins after capacity-unavailable observation but before lost-result selection; publish nothing and retire the publication-credit lease exactly once without provider work","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"account-close-retired-exactly-once","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"capacity-result-selection-commit"}},{"terminalId":"live-device-capacity-unavailable","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":false,"deviceCapacityResultCommitLive":true},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice after its stable lost promise settles with reason unknown and the generic capacity-unavailable diagnostic; return the reusable publication credit without live-device ledger mutation or provider work","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-to-adapter-reusable-after-public-settlement","liveDeviceCreditDisposition":"not-acquired","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"generic-capacity-unavailable","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"capacity-unavailable"},"providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"post-capacity-close-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit"],"terminalOutcome":"reject when close wins after positive capacity observation but before reservation commit; publish nothing and retire the publication-credit lease exactly once without provider work","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"account-close-retired-exactly-once","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"capacity-result-selection-commit"}},{"terminalId":"live-device-commit-close-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit"],"terminalOutcome":"reject after close wins the atomic LIVE/authority reservation commit without result publication or provider work; retire the publication-credit lease exactly once","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"account-close-retired-exactly-once","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"live-device-commit"}},{"terminalId":"provider-unfulfilled-provider-inability-won","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":false,"deviceAccountLiveAtProviderCompletion":true,"deviceAccountLiveAtSettlementCommit":true,"providerInabilityWonLossRace":true},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice after provider inability wins the stamped terminal race; settle its stable lost promise first with reason unknown and the generic provider-inability diagnostic, return the reusable publication credit, and release both committed live-device credits exactly once","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-to-adapter-reusable-after-public-settlement","liveDeviceCreditDisposition":"released-exactly-once","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"generic-provider-inability","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"provider-inability"},"providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"provider-unfulfilled-provider-inability-won-before-close","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":false,"deviceAccountLiveAtProviderCompletion":true,"deviceAccountLiveAtSettlementCommit":false,"providerInabilityWonLossRace":true},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice after provider inability wins before a later-stamped account close; settle its stable lost promise first with reason unknown and the generic provider-inability diagnostic, return then retire the publication credit without changing the winner, and release both committed live-device credits exactly once","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-after-public-settlement-then-account-close-retired-exactly-once","liveDeviceCreditDisposition":"released-exactly-once","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"generic-provider-inability","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"provider-inability"},"providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"provider-unfulfilled-account-close-won","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":false,"deviceAccountLiveAtProviderCompletion":false,"deviceAccountLiveAtSettlementCommit":false,"providerInabilityWonLossRace":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice after account close wins the stamped terminal race ahead of provider inability; settle its stable lost promise first with reason unknown and the stable redacted winning close-cause diagnostic, return then retire the publication credit, and release both committed live-device credits exactly once","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-after-public-settlement-then-account-close-retired-exactly-once","liveDeviceCreditDisposition":"released-exactly-once","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"winning-account-close-cause-redacted","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"account-close"},"providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"lost-device-returned-close-before-provider-completion","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":true,"deviceAccountLiveAtProviderCompletion":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice when account close wins after positive commit but before provider completion; retain one provider token and physical sequence, settle the stable lost promise first with reason unknown and the stable redacted winning close-cause diagnostic, return then retire the publication credit, and release both live-device credits exactly once","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-after-public-settlement-then-account-close-retired-exactly-once","liveDeviceCreditDisposition":"released-exactly-once","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"winning-account-close-cause-redacted","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"account-close"},"providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"lost-device-returned-close-after-provider-completion","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":true,"deviceAccountLiveAtProviderCompletion":true,"deviceAccountLiveAtSettlementCommit":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice when account close wins after provider completion but before settlement commit; retain one provider token and physical sequence, settle the stable lost promise first with reason unknown and the stable redacted winning close-cause diagnostic, return then retire the publication credit, and release both live-device credits exactly once","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-after-public-settlement-then-account-close-retired-exactly-once","liveDeviceCreditDisposition":"released-exactly-once","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"winning-account-close-cause-redacted","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"account-close"},"providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"live-device-returned","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":true,"deviceAccountLiveAtProviderCompletion":true,"deviceAccountLiveAtSettlementCommit":true},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"perform the first valid-to-expired adapter transition, resolve with one fresh live isolated GPUDevice retaining only its committed live-device leaf and aggregate credits, and return the reusable adapter publication credit after public settlement","errorTiming":"none","resultDisposition":"promise-resolve-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-to-adapter-reusable-after-public-settlement","liveDeviceCreditDisposition":"retained-by-live-device","providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"none"}}],"factBindings":[{"fact":"webidlValid","kind":"branch-predicates","branchId":"webidl","passWhen":true},{"fact":"requiredFeaturesSupported","kind":"branch-predicates","branchId":"required-features-check","passWhen":true},{"fact":"adapterRequestValid","kind":"branch-predicates","branchId":"adapter-validation","passWhen":true},{"fact":"deviceAdmissionValid","kind":"branch-predicates","branchId":"live-admission","passWhen":true},{"fact":"adapterExpired","kind":"external-outcome","source":"adapter-expiry-state","requiredBranchId":"live-admission"},{"fact":"deviceExpiryResultCommitLive","kind":"branch-predicates","branchId":"expiry-result-selection-commit","passWhen":true},{"fact":"deviceReservationCapacityAvailable","kind":"external-outcome","source":"live-device-capacity-result","requiredBranchId":"live-device-capacity"},{"fact":"deviceCapacityResultCommitLive","kind":"branch-predicates","branchId":"capacity-result-selection-commit","passWhen":true},{"fact":"deviceReservationCommitLive","kind":"branch-predicates","branchId":"live-device-commit","passWhen":true},{"fact":"providerFulfilled","kind":"external-outcome","source":"provider-device-result","providerResult":true},{"fact":"deviceAccountLiveAtProviderCompletion","kind":"external-outcome","source":"committed-device-account-state-at-provider-completion","requiredBranchId":"provider-settlement"},{"fact":"deviceAccountLiveAtSettlementCommit","kind":"external-outcome","source":"committed-device-account-state-at-settlement-commit","requiredBranchId":"provider-settlement"},{"fact":"providerInabilityWonLossRace","kind":"external-outcome","source":"terminal-arbiter-provider-inability-versus-account-close-winner-after-both-account-observations","requiredBranchId":"provider-settlement"}]},"requestDeviceProviderDescriptor":{"policy":"generated-logical-limits-plus-versioned-service-internal-requirements-only","projectionRule":"start-from-feature-level-defaults-apply-only-better-nonundefined-requests-then-run-pinned-storage-limit-normalization","capabilityProjectionPredicate":{"predicateId":"adapter.request-device.capability-projection","predicateType":"profile-feature-limit","inputs":["requiredFeatures","requiredLimits","featureLevel","profileFeaturePolicy","profileLimitTable","capabilityGrant","serviceInternalRequirements"],"relation":"infallibly derive the exact logical feature set and limit projection with the pinned new-device algorithm, including default/implied features, feature-level device defaults, better-only non-undefined limit updates, and storage-limit normalization; emit a generated logical provider descriptor containing only that logical set plus versioned service-internal requirements","failureClass":"none","failureTiming":"none","predicateIndex":2,"predicateWireId":1496584302},"providerReadyPredicate":{"predicateId":"adapter.request-device.provider-ready","predicateType":"provider-request-readiness","inputs":["liveDeviceReservationId","generatedLogicalProviderDescriptor"],"relation":"all local terminal predicates have passed and the generated logical descriptor contains only the exact logical feature/limit projection plus versioned service-internal requirements; the raw request descriptor is unavailable at this boundary; mint one provider token and physical sequence immediately after this predicate","failureClass":"none","failureTiming":"none","predicateIndex":1,"predicateWireId":1494113071}},"providerRoutingPrograms":[{"operationId":"GPU.requestAdapter","facts":["webidlValid","featureLevelValid","adapterAdmissionValid","adapterReservationCapacityAvailable","adapterCapacityResultCommitLive","adapterReservationCommitLive","compatibleAdapterAvailable","adapterAccountLiveAtProviderCompletion","adapterAccountLiveAtSettlementCommit"],"precedence":["webidlValid","featureLevelValid","adapterAdmissionValid","adapterReservationCapacityAvailable","adapterCapacityResultCommitLive","adapterReservationCommitLive","compatibleAdapterAvailable","adapterAccountLiveAtProviderCompletion","adapterAccountLiveAtSettlementCommit"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"webidl-rejection","conditions":{"webidlValid":false},"branchPath":["webidl"],"terminalOutcome":"reject the returned promise during options conversion","errorTiming":"promise-rejection","adapterCreditDisposition":"not-acquired","publicationCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"promise-reject","errorSource":{"kind":"first-failing-predicate","branchId":"webidl"}},{"terminalId":"invalid-feature-level-null","conditions":{"webidlValid":true,"featureLevelValid":false},"branchPath":["webidl","feature-level-check"],"terminalOutcome":"settle the promise with null for invalid post-Web-IDL featureLevel without provider work","errorTiming":"promise-settlement-null","resultDisposition":"promise-resolve-null","adapterCreditDisposition":"not-acquired","publicationCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"standard-local-null-result"}},{"terminalId":"local-admission-rejection","conditions":{"webidlValid":true,"featureLevelValid":true,"adapterAdmissionValid":false},"branchPath":["webidl","feature-level-check","local-admission"],"terminalOutcome":"reject the request promise during local LIVE admission before reservation or provider work","errorTiming":"promise-rejection","adapterCreditDisposition":"not-acquired","publicationCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"promise-reject","errorSource":{"kind":"first-failing-predicate","branchId":"local-admission"}},{"terminalId":"capacity-null-selection-close-rejection","conditions":{"webidlValid":true,"featureLevelValid":true,"adapterAdmissionValid":true,"adapterReservationCapacityAvailable":false,"adapterCapacityResultCommitLive":false},"branchPath":["webidl","feature-level-check","local-admission","local-capacity-check","local-capacity-result-commit"],"terminalOutcome":"reject when close wins after capacity-unavailable observation but before the account arbiter can select null; publish nothing and do no provider work","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterCreditDisposition":"not-acquired","publicationCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"local-capacity-result-commit"}},{"terminalId":"local-capacity-unavailable-null","conditions":{"webidlValid":true,"featureLevelValid":true,"adapterAdmissionValid":true,"adapterReservationCapacityAvailable":false,"adapterCapacityResultCommitLive":true},"branchPath":["webidl","feature-level-check","local-admission","local-capacity-check","local-capacity-result-commit"],"terminalOutcome":"settle the promise with null only after the LIVE account arbiter selects the bounded capacity-unavailable result, without ledger mutation or provider work","errorTiming":"promise-settlement-null","resultDisposition":"promise-resolve-null","adapterCreditDisposition":"not-acquired","publicationCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"standard-local-null-result"}},{"terminalId":"post-capacity-close-rejection","conditions":{"webidlValid":true,"featureLevelValid":true,"adapterAdmissionValid":true,"adapterReservationCapacityAvailable":true,"adapterCapacityResultCommitLive":false},"branchPath":["webidl","feature-level-check","local-admission","local-capacity-check","local-capacity-result-commit"],"terminalOutcome":"reject when close wins after positive capacity observation but before reservation commit; publish nothing and do no provider work","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterCreditDisposition":"not-acquired","publicationCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"local-capacity-result-commit"}},{"terminalId":"local-reservation-commit-close-rejection","conditions":{"webidlValid":true,"featureLevelValid":true,"adapterAdmissionValid":true,"adapterReservationCapacityAvailable":true,"adapterCapacityResultCommitLive":true,"adapterReservationCommitLive":false},"branchPath":["webidl","feature-level-check","local-admission","local-capacity-check","local-capacity-result-commit","local-reservation-commit"],"terminalOutcome":"reject after close wins the atomic LIVE/authority reservation commit without adapter/publication-credit installation or provider work","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterCreditDisposition":"not-acquired","publicationCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"local-reservation-commit"}},{"terminalId":"no-compatible-adapter","conditions":{"webidlValid":true,"featureLevelValid":true,"adapterAdmissionValid":true,"adapterReservationCapacityAvailable":true,"adapterCapacityResultCommitLive":true,"adapterReservationCommitLive":true,"compatibleAdapterAvailable":false},"branchPath":["webidl","feature-level-check","local-admission","local-capacity-check","local-capacity-result-commit","local-reservation-commit","provider-request","provider-settlement"],"terminalOutcome":"settle the promise with null and roll back the committed adapter and reusable publication credits exactly once after one admitted provider request; later close cannot change the selected null result","errorTiming":"promise-settlement-null","resultDisposition":"promise-resolve-null","adapterCreditDisposition":"rolled-back-exactly-once","publicationCreditDisposition":"rolled-back-exactly-once","providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"provider-null-result"}},{"terminalId":"expired-adapter-returned-close-before-provider-completion","conditions":{"webidlValid":true,"featureLevelValid":true,"adapterAdmissionValid":true,"adapterReservationCapacityAvailable":true,"adapterCapacityResultCommitLive":true,"adapterReservationCommitLive":true,"compatibleAdapterAvailable":true,"adapterAccountLiveAtProviderCompletion":false},"branchPath":["webidl","feature-level-check","local-admission","local-capacity-check","local-capacity-result-commit","local-reservation-commit","provider-request","provider-settlement"],"terminalOutcome":"settle with a fresh service-detached expired logical adapter when close wins after positive commit but before provider completion; retain one provider token and physical sequence, release the committed adapter leaf/aggregate credit exactly once, and retire the reusable publication leaf/aggregate credit exactly once","errorTiming":"none","resultDisposition":"promise-resolve-object","adapterCreditDisposition":"account-close-released-exactly-once","publicationCreditDisposition":"account-close-retired-exactly-once","providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"none"}},{"terminalId":"expired-adapter-returned-close-after-provider-completion","conditions":{"webidlValid":true,"featureLevelValid":true,"adapterAdmissionValid":true,"adapterReservationCapacityAvailable":true,"adapterCapacityResultCommitLive":true,"adapterReservationCommitLive":true,"compatibleAdapterAvailable":true,"adapterAccountLiveAtProviderCompletion":true,"adapterAccountLiveAtSettlementCommit":false},"branchPath":["webidl","feature-level-check","local-admission","local-capacity-check","local-capacity-result-commit","local-reservation-commit","provider-request","provider-settlement"],"terminalOutcome":"settle with a fresh service-detached expired logical adapter when close wins after provider completion but before settlement commit; retain one provider token and physical sequence, release the committed adapter leaf/aggregate credit exactly once, and retire the reusable publication leaf/aggregate credit exactly once","errorTiming":"none","resultDisposition":"promise-resolve-object","adapterCreditDisposition":"account-close-released-exactly-once","publicationCreditDisposition":"account-close-retired-exactly-once","providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"none"}},{"terminalId":"adapter-returned","conditions":{"webidlValid":true,"featureLevelValid":true,"adapterAdmissionValid":true,"adapterReservationCapacityAvailable":true,"adapterCapacityResultCommitLive":true,"adapterReservationCommitLive":true,"compatibleAdapterAvailable":true,"adapterAccountLiveAtProviderCompletion":true,"adapterAccountLiveAtSettlementCommit":true},"branchPath":["webidl","feature-level-check","local-admission","local-capacity-check","local-capacity-result-commit","local-reservation-commit","provider-request","provider-settlement"],"terminalOutcome":"settle the promise with a fresh live logical adapter and retain its adapter credit plus reusable non-transferable device-result-publication credit","errorTiming":"none","resultDisposition":"promise-resolve-object","adapterCreditDisposition":"retained-by-live-adapter","publicationCreditDisposition":"retained-by-live-adapter-reusable","providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"none"}}],"factBindings":[{"fact":"webidlValid","kind":"branch-predicates","branchId":"webidl","passWhen":true},{"fact":"featureLevelValid","kind":"external-outcome","source":"post-webidl-feature-level-valid-usage","requiredBranchId":"feature-level-check"},{"fact":"adapterAdmissionValid","kind":"branch-predicates","branchId":"local-admission","passWhen":true},{"fact":"adapterReservationCapacityAvailable","kind":"external-outcome","source":"adapter-result-credit-capacity-result","requiredBranchId":"local-capacity-check"},{"fact":"adapterCapacityResultCommitLive","kind":"branch-predicates","branchId":"local-capacity-result-commit","passWhen":true},{"fact":"adapterReservationCommitLive","kind":"branch-predicates","branchId":"local-reservation-commit","passWhen":true},{"fact":"compatibleAdapterAvailable","kind":"external-outcome","source":"provider-compatible-adapter-result","providerResult":true},{"fact":"adapterAccountLiveAtProviderCompletion","kind":"external-outcome","source":"committed-adapter-account-state-at-provider-completion","requiredBranchId":"provider-settlement"},{"fact":"adapterAccountLiveAtSettlementCommit","kind":"external-outcome","source":"committed-adapter-account-state-at-settlement-commit","requiredBranchId":"provider-settlement"}]},{"operationId":"GPUAdapter.requestDevice","facts":["webidlValid","requiredFeaturesSupported","adapterRequestValid","deviceAdmissionValid","adapterExpired","deviceExpiryResultCommitLive","deviceReservationCapacityAvailable","deviceCapacityResultCommitLive","deviceReservationCommitLive","providerFulfilled","deviceAccountLiveAtProviderCompletion","deviceAccountLiveAtSettlementCommit","providerInabilityWonLossRace"],"precedence":["webidlValid","requiredFeaturesSupported","adapterRequestValid","deviceAdmissionValid","adapterExpired","deviceExpiryResultCommitLive","deviceReservationCapacityAvailable","deviceCapacityResultCommitLive","deviceReservationCommitLive","providerFulfilled","deviceAccountLiveAtProviderCompletion","deviceAccountLiveAtSettlementCommit","providerInabilityWonLossRace"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"webidl-rejection","conditions":{"webidlValid":false},"branchPath":["webidl"],"terminalOutcome":"reject the returned promise during Web IDL conversion","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"not-acquired","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"webidl"}},{"terminalId":"unsupported-required-features","conditions":{"webidlValid":true,"requiredFeaturesSupported":false},"branchPath":["webidl","required-features-check"],"terminalOutcome":"reject the promise with TypeError for unsupported requiredFeatures","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"not-acquired","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"required-features-check"}},{"terminalId":"invalid-adapter-request","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":false},"branchPath":["webidl","required-features-check","adapter-validation"],"terminalOutcome":"reject the promise with OperationError for invalid requiredLimits; expired adapters do not reject here","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"not-acquired","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"adapter-validation"}},{"terminalId":"live-admission-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission"],"terminalOutcome":"reject the promise during realm/coverage/account LIVE admission before observing expiry or publishing a result","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"not-acquired","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"live-admission"}},{"terminalId":"expiry-lost-selection-close-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":true,"deviceExpiryResultCommitLive":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit"],"terminalOutcome":"reject when close wins after observing adapter expiry but before lost-result selection; publish nothing and retire the publication-credit lease exactly once without provider work","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"account-close-retired-exactly-once","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"expiry-result-selection-commit"}},{"terminalId":"expired-adapter-lost-device","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":true,"deviceExpiryResultCommitLive":true},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit"],"terminalOutcome":"resolve a fresh distinct service-detached already-lost GPUDevice after its stable lost promise settles with reason unknown and the generic expired-adapter diagnostic; return the reusable publication credit and perform no provider request","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-to-adapter-reusable-after-public-settlement","liveDeviceCreditDisposition":"not-acquired","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"generic-expired-adapter","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"expired-adapter"},"providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"pre-capacity-close-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit"],"terminalOutcome":"reject when close wins after the non-expired observation but before capacity observation; publish nothing and retire the publication-credit lease exactly once without provider work","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"account-close-retired-exactly-once","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"expiry-result-selection-commit"}},{"terminalId":"capacity-lost-selection-close-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":false,"deviceCapacityResultCommitLive":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit"],"terminalOutcome":"reject when close wins after capacity-unavailable observation but before lost-result selection; publish nothing and retire the publication-credit lease exactly once without provider work","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"account-close-retired-exactly-once","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"capacity-result-selection-commit"}},{"terminalId":"live-device-capacity-unavailable","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":false,"deviceCapacityResultCommitLive":true},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice after its stable lost promise settles with reason unknown and the generic capacity-unavailable diagnostic; return the reusable publication credit without live-device ledger mutation or provider work","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-to-adapter-reusable-after-public-settlement","liveDeviceCreditDisposition":"not-acquired","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"generic-capacity-unavailable","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"capacity-unavailable"},"providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"post-capacity-close-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit"],"terminalOutcome":"reject when close wins after positive capacity observation but before reservation commit; publish nothing and retire the publication-credit lease exactly once without provider work","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"account-close-retired-exactly-once","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"capacity-result-selection-commit"}},{"terminalId":"live-device-commit-close-rejection","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit"],"terminalOutcome":"reject after close wins the atomic LIVE/authority reservation commit without result publication or provider work; retire the publication-credit lease exactly once","errorTiming":"promise-rejection","resultDisposition":"promise-reject","adapterStateAfterSettlement":"unchanged","publicationCreditDisposition":"account-close-retired-exactly-once","liveDeviceCreditDisposition":"not-acquired","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"first-failing-predicate","branchId":"live-device-commit"}},{"terminalId":"provider-unfulfilled-provider-inability-won","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":false,"deviceAccountLiveAtProviderCompletion":true,"deviceAccountLiveAtSettlementCommit":true,"providerInabilityWonLossRace":true},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice after provider inability wins the stamped terminal race; settle its stable lost promise first with reason unknown and the generic provider-inability diagnostic, return the reusable publication credit, and release both committed live-device credits exactly once","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-to-adapter-reusable-after-public-settlement","liveDeviceCreditDisposition":"released-exactly-once","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"generic-provider-inability","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"provider-inability"},"providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"provider-unfulfilled-provider-inability-won-before-close","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":false,"deviceAccountLiveAtProviderCompletion":true,"deviceAccountLiveAtSettlementCommit":false,"providerInabilityWonLossRace":true},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice after provider inability wins before a later-stamped account close; settle its stable lost promise first with reason unknown and the generic provider-inability diagnostic, return then retire the publication credit without changing the winner, and release both committed live-device credits exactly once","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-after-public-settlement-then-account-close-retired-exactly-once","liveDeviceCreditDisposition":"released-exactly-once","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"generic-provider-inability","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"provider-inability"},"providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"provider-unfulfilled-account-close-won","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":false,"deviceAccountLiveAtProviderCompletion":false,"deviceAccountLiveAtSettlementCommit":false,"providerInabilityWonLossRace":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice after account close wins the stamped terminal race ahead of provider inability; settle its stable lost promise first with reason unknown and the stable redacted winning close-cause diagnostic, return then retire the publication credit, and release both committed live-device credits exactly once","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-after-public-settlement-then-account-close-retired-exactly-once","liveDeviceCreditDisposition":"released-exactly-once","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"winning-account-close-cause-redacted","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"account-close"},"providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"lost-device-returned-close-before-provider-completion","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":true,"deviceAccountLiveAtProviderCompletion":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice when account close wins after positive commit but before provider completion; retain one provider token and physical sequence, settle the stable lost promise first with reason unknown and the stable redacted winning close-cause diagnostic, return then retire the publication credit, and release both live-device credits exactly once","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-after-public-settlement-then-account-close-retired-exactly-once","liveDeviceCreditDisposition":"released-exactly-once","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"winning-account-close-cause-redacted","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"account-close"},"providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"lost-device-returned-close-after-provider-completion","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":true,"deviceAccountLiveAtProviderCompletion":true,"deviceAccountLiveAtSettlementCommit":false},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"expire the adapter and resolve a fresh distinct service-detached already-lost GPUDevice when account close wins after provider completion but before settlement commit; retain one provider token and physical sequence, settle the stable lost promise first with reason unknown and the stable redacted winning close-cause diagnostic, return then retire the publication credit, and release both live-device credits exactly once","errorTiming":"none","resultDisposition":"promise-resolve-lost-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-after-public-settlement-then-account-close-retired-exactly-once","liveDeviceCreditDisposition":"released-exactly-once","lostSettlement":{"objectIdentity":"fresh-distinct-gpu-device","lostPromiseIdentity":"stable-per-object","reason":"unknown","diagnosticSource":"winning-account-close-cause-redacted","diagnosticStability":"stable-per-object","settlementOrder":"device-lost-before-request-device-promise","serviceAttachment":"service-detached","retainedServiceCredits":"none","arbiterWinner":"account-close"},"providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"lost-device-result"}},{"terminalId":"live-device-returned","conditions":{"webidlValid":true,"requiredFeaturesSupported":true,"adapterRequestValid":true,"deviceAdmissionValid":true,"adapterExpired":false,"deviceExpiryResultCommitLive":true,"deviceReservationCapacityAvailable":true,"deviceCapacityResultCommitLive":true,"deviceReservationCommitLive":true,"providerFulfilled":true,"deviceAccountLiveAtProviderCompletion":true,"deviceAccountLiveAtSettlementCommit":true},"branchPath":["webidl","required-features-check","adapter-validation","live-admission","expiry-result-selection-commit","live-device-capacity","capacity-result-selection-commit","live-device-commit","provider-request","provider-settlement"],"terminalOutcome":"perform the first valid-to-expired adapter transition, resolve with one fresh live isolated GPUDevice retaining only its committed live-device leaf and aggregate credits, and return the reusable adapter publication credit after public settlement","errorTiming":"none","resultDisposition":"promise-resolve-object","adapterStateAfterSettlement":"expired","publicationCreditDisposition":"returned-to-adapter-reusable-after-public-settlement","liveDeviceCreditDisposition":"retained-by-live-device","providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"none"}}],"factBindings":[{"fact":"webidlValid","kind":"branch-predicates","branchId":"webidl","passWhen":true},{"fact":"requiredFeaturesSupported","kind":"branch-predicates","branchId":"required-features-check","passWhen":true},{"fact":"adapterRequestValid","kind":"branch-predicates","branchId":"adapter-validation","passWhen":true},{"fact":"deviceAdmissionValid","kind":"branch-predicates","branchId":"live-admission","passWhen":true},{"fact":"adapterExpired","kind":"external-outcome","source":"adapter-expiry-state","requiredBranchId":"live-admission"},{"fact":"deviceExpiryResultCommitLive","kind":"branch-predicates","branchId":"expiry-result-selection-commit","passWhen":true},{"fact":"deviceReservationCapacityAvailable","kind":"external-outcome","source":"live-device-capacity-result","requiredBranchId":"live-device-capacity"},{"fact":"deviceCapacityResultCommitLive","kind":"branch-predicates","branchId":"capacity-result-selection-commit","passWhen":true},{"fact":"deviceReservationCommitLive","kind":"branch-predicates","branchId":"live-device-commit","passWhen":true},{"fact":"providerFulfilled","kind":"external-outcome","source":"provider-device-result","providerResult":true},{"fact":"deviceAccountLiveAtProviderCompletion","kind":"external-outcome","source":"committed-device-account-state-at-provider-completion","requiredBranchId":"provider-settlement"},{"fact":"deviceAccountLiveAtSettlementCommit","kind":"external-outcome","source":"committed-device-account-state-at-settlement-commit","requiredBranchId":"provider-settlement"},{"fact":"providerInabilityWonLossRace","kind":"external-outcome","source":"terminal-arbiter-provider-inability-versus-account-close-winner-after-both-account-observations","requiredBranchId":"provider-settlement"}]},{"operationId":"GPUCanvasContext.configure","facts":["webidlValid","providerPredicatesValid"],"precedence":["webidlValid","providerPredicatesValid"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"webidl-rejection","conditions":{"webidlValid":false},"branchPath":["webidl"],"terminalOutcome":"throw during synchronous Web IDL conversion","errorTiming":"synchronous-webidl","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"throw","errorSource":{"kind":"first-failing-predicate","branchId":"webidl"}},{"terminalId":"later-predicate-rejection","conditions":{"webidlValid":true,"providerPredicatesValid":false},"branchPath":["webidl","service-provider"],"terminalOutcome":"reject before the terminal operation outcome","errorTiming":"device-timeline","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-undefined-and-report-error","errorSource":{"kind":"first-failing-predicate","branchId":"service-provider"}},{"terminalId":"operation-success","conditions":{"webidlValid":true,"providerPredicatesValid":true},"branchPath":["webidl","service-provider"],"terminalOutcome":"enqueue configuration on the surface account device timeline","errorTiming":"none","providerTokenCount":1,"physicalSequenceCount":1,"resultDisposition":"return-undefined","errorSource":{"kind":"none"}}],"factBindings":[{"fact":"webidlValid","kind":"branch-predicates","branchId":"webidl","passWhen":true},{"fact":"providerPredicatesValid","kind":"branch-predicates","branchId":"service-provider","passWhen":true}]},{"operationId":"GPUCanvasContext.unconfigure","facts":["alreadyTerminal","cleanupPredicatesValid"],"precedence":["alreadyTerminal","cleanupPredicatesValid"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"repeat-cleanup-noop","conditions":{"alreadyTerminal":true},"branchPath":["already-unconfigured"],"terminalOutcome":"return without provider work","errorTiming":"none","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-undefined","errorSource":{"kind":"none"}},{"terminalId":"first-cleanup-rejection","conditions":{"alreadyTerminal":false,"cleanupPredicatesValid":false},"branchPath":["provider-cleanup"],"terminalOutcome":"reject invalid cleanup ownership without a provider token","errorTiming":"device-timeline","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-undefined-and-report-error","errorSource":{"kind":"first-failing-predicate","branchId":"provider-cleanup"}},{"terminalId":"first-cleanup-provider","conditions":{"alreadyTerminal":false,"cleanupPredicatesValid":true},"branchPath":["provider-cleanup"],"terminalOutcome":"enqueue one idempotent configuration cleanup","errorTiming":"none","providerTokenCount":1,"physicalSequenceCount":1,"resultDisposition":"return-undefined","errorSource":{"kind":"none"}}],"factBindings":[{"fact":"alreadyTerminal","kind":"branch-selector","branchId":"already-unconfigured","selectedWhen":true},{"fact":"cleanupPredicatesValid","kind":"branch-predicates","branchId":"provider-cleanup","passWhen":true}]},{"operationId":"GPUDevice.createBindGroupLayout","facts":["webidlValid","providerPredicatesValid"],"precedence":["webidlValid","providerPredicatesValid"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"webidl-rejection","conditions":{"webidlValid":false},"branchPath":["webidl"],"terminalOutcome":"throw during synchronous Web IDL conversion","errorTiming":"synchronous-webidl","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"throw","errorSource":{"kind":"first-failing-predicate","branchId":"webidl"}},{"terminalId":"later-predicate-rejection","conditions":{"webidlValid":true,"providerPredicatesValid":false},"branchPath":["webidl","service-provider"],"terminalOutcome":"reject before the terminal operation outcome","errorTiming":"device-timeline","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-invalid-object-and-report-error","errorSource":{"kind":"first-failing-predicate","branchId":"service-provider"}},{"terminalId":"operation-success","conditions":{"webidlValid":true,"providerPredicatesValid":true},"branchPath":["webidl","service-provider"],"terminalOutcome":"enqueue one logically validated bind group layout creation","errorTiming":"none","providerTokenCount":1,"physicalSequenceCount":1,"resultDisposition":"return-object","errorSource":{"kind":"none"}}],"factBindings":[{"fact":"webidlValid","kind":"branch-predicates","branchId":"webidl","passWhen":true},{"fact":"providerPredicatesValid","kind":"branch-predicates","branchId":"service-provider","passWhen":true}]},{"operationId":"GPUDevice.createCommandEncoder","facts":["webidlValid","providerPredicatesValid"],"precedence":["webidlValid","providerPredicatesValid"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"webidl-rejection","conditions":{"webidlValid":false},"branchPath":["webidl"],"terminalOutcome":"throw during synchronous Web IDL conversion","errorTiming":"synchronous-webidl","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"throw","errorSource":{"kind":"first-failing-predicate","branchId":"webidl"}},{"terminalId":"later-predicate-rejection","conditions":{"webidlValid":true,"providerPredicatesValid":false},"branchPath":["webidl","service-provider"],"terminalOutcome":"reject before the terminal operation outcome","errorTiming":"device-timeline","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-invalid-object-and-report-error","errorSource":{"kind":"first-failing-predicate","branchId":"service-provider"}},{"terminalId":"operation-success","conditions":{"webidlValid":true,"providerPredicatesValid":true},"branchPath":["webidl","service-provider"],"terminalOutcome":"enqueue one logical encoder creation","errorTiming":"none","providerTokenCount":1,"physicalSequenceCount":1,"resultDisposition":"return-object","errorSource":{"kind":"none"}}],"factBindings":[{"fact":"webidlValid","kind":"branch-predicates","branchId":"webidl","passWhen":true},{"fact":"providerPredicatesValid","kind":"branch-predicates","branchId":"service-provider","passWhen":true}]},{"operationId":"GPUDevice.createPipelineLayout","facts":["webidlValid","providerPredicatesValid"],"precedence":["webidlValid","providerPredicatesValid"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"webidl-rejection","conditions":{"webidlValid":false},"branchPath":["webidl"],"terminalOutcome":"throw during synchronous Web IDL conversion","errorTiming":"synchronous-webidl","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"throw","errorSource":{"kind":"first-failing-predicate","branchId":"webidl"}},{"terminalId":"later-predicate-rejection","conditions":{"webidlValid":true,"providerPredicatesValid":false},"branchPath":["webidl","service-provider"],"terminalOutcome":"reject before the terminal operation outcome","errorTiming":"device-timeline","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-invalid-object-and-report-error","errorSource":{"kind":"first-failing-predicate","branchId":"service-provider"}},{"terminalId":"operation-success","conditions":{"webidlValid":true,"providerPredicatesValid":true},"branchPath":["webidl","service-provider"],"terminalOutcome":"enqueue one logically validated pipeline layout creation","errorTiming":"none","providerTokenCount":1,"physicalSequenceCount":1,"resultDisposition":"return-object","errorSource":{"kind":"none"}}],"factBindings":[{"fact":"webidlValid","kind":"branch-predicates","branchId":"webidl","passWhen":true},{"fact":"providerPredicatesValid","kind":"branch-predicates","branchId":"service-provider","passWhen":true}]},{"operationId":"GPUDevice.createRenderPipeline","facts":["webidlValid","providerPredicatesValid"],"precedence":["webidlValid","providerPredicatesValid"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"webidl-rejection","conditions":{"webidlValid":false},"branchPath":["webidl"],"terminalOutcome":"throw during synchronous Web IDL conversion","errorTiming":"synchronous-webidl","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"throw","errorSource":{"kind":"first-failing-predicate","branchId":"webidl"}},{"terminalId":"later-predicate-rejection","conditions":{"webidlValid":true,"providerPredicatesValid":false},"branchPath":["webidl","service-provider"],"terminalOutcome":"reject before the terminal operation outcome","errorTiming":"device-timeline","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-invalid-object-and-report-error","errorSource":{"kind":"first-failing-predicate","branchId":"service-provider"}},{"terminalId":"operation-success","conditions":{"webidlValid":true,"providerPredicatesValid":true},"branchPath":["webidl","service-provider"],"terminalOutcome":"enqueue one logically validated pipeline creation","errorTiming":"none","providerTokenCount":1,"physicalSequenceCount":1,"resultDisposition":"return-object","errorSource":{"kind":"none"}}],"factBindings":[{"fact":"webidlValid","kind":"branch-predicates","branchId":"webidl","passWhen":true},{"fact":"providerPredicatesValid","kind":"branch-predicates","branchId":"service-provider","passWhen":true}]},{"operationId":"GPUDevice.createShaderModule","facts":["webidlValid","providerPredicatesValid"],"precedence":["webidlValid","providerPredicatesValid"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"webidl-rejection","conditions":{"webidlValid":false},"branchPath":["webidl"],"terminalOutcome":"throw during synchronous Web IDL conversion","errorTiming":"synchronous-webidl","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"throw","errorSource":{"kind":"first-failing-predicate","branchId":"webidl"}},{"terminalId":"later-predicate-rejection","conditions":{"webidlValid":true,"providerPredicatesValid":false},"branchPath":["webidl","service-provider"],"terminalOutcome":"reject before the terminal operation outcome","errorTiming":"device-timeline","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-invalid-object-and-report-error","errorSource":{"kind":"first-failing-predicate","branchId":"service-provider"}},{"terminalId":"operation-success","conditions":{"webidlValid":true,"providerPredicatesValid":true},"branchPath":["webidl","service-provider"],"terminalOutcome":"enqueue one logically validated shader module creation","errorTiming":"none","providerTokenCount":1,"physicalSequenceCount":1,"resultDisposition":"return-object","errorSource":{"kind":"none"}}],"factBindings":[{"fact":"webidlValid","kind":"branch-predicates","branchId":"webidl","passWhen":true},{"fact":"providerPredicatesValid","kind":"branch-predicates","branchId":"service-provider","passWhen":true}]},{"operationId":"GPUDevice.destroy","facts":["alreadyTerminal","cleanupPredicatesValid"],"precedence":["alreadyTerminal","cleanupPredicatesValid"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"repeat-cleanup-noop","conditions":{"alreadyTerminal":true},"branchPath":["already-destroyed"],"terminalOutcome":"return without provider work","errorTiming":"none","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-undefined","errorSource":{"kind":"none"}},{"terminalId":"first-cleanup-rejection","conditions":{"alreadyTerminal":false,"cleanupPredicatesValid":false},"branchPath":["provider-cleanup"],"terminalOutcome":"reject invalid cleanup ownership without a provider token","errorTiming":"device-timeline","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-undefined-and-report-error","errorSource":{"kind":"first-failing-predicate","branchId":"provider-cleanup"}},{"terminalId":"first-cleanup-provider","conditions":{"alreadyTerminal":false,"cleanupPredicatesValid":true},"branchPath":["provider-cleanup"],"terminalOutcome":"enqueue one idempotent provider cleanup","errorTiming":"none","providerTokenCount":1,"physicalSequenceCount":1,"resultDisposition":"return-undefined","errorSource":{"kind":"none"}}],"factBindings":[{"fact":"alreadyTerminal","kind":"branch-selector","branchId":"already-destroyed","selectedWhen":true},{"fact":"cleanupPredicatesValid","kind":"branch-predicates","branchId":"provider-cleanup","passWhen":true}]},{"operationId":"GPUDevice.popErrorScope","facts":["deviceLost","scopeNonempty"],"precedence":["deviceLost","scopeNonempty"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"lost-device-null","conditions":{"deviceLost":true},"branchPath":["lost-device-null"],"terminalOutcome":"resolve null before inspecting the error-scope stack","errorTiming":"none","resultDisposition":"promise-resolve-null","providerTokenCount":0,"physicalSequenceCount":0,"errorSource":{"kind":"none"}},{"terminalId":"empty-scope-rejection","conditions":{"deviceLost":false,"scopeNonempty":false},"branchPath":["scope-check"],"terminalOutcome":"reject with OperationError without provider work","errorTiming":"promise-rejection","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"promise-reject","errorSource":{"kind":"first-failing-predicate","branchId":"scope-check"}},{"terminalId":"provider-barrier","conditions":{"deviceLost":false,"scopeNonempty":true},"branchPath":["scope-check","provider-barrier"],"terminalOutcome":"settle the captured nonempty scope after one provider barrier","errorTiming":"none","resultDisposition":"promise-resolve-scope-result","providerTokenCount":1,"physicalSequenceCount":1,"errorSource":{"kind":"none"}}],"factBindings":[{"fact":"deviceLost","kind":"branch-selector","branchId":"lost-device-null","selectedWhen":true},{"fact":"scopeNonempty","kind":"branch-predicates","branchId":"scope-check","passWhen":true}]},{"operationId":"GPUQueue.submit","facts":["webidlValid","providerPredicatesValid"],"precedence":["webidlValid","providerPredicatesValid"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"webidl-rejection","conditions":{"webidlValid":false},"branchPath":["webidl"],"terminalOutcome":"throw during synchronous Web IDL conversion","errorTiming":"synchronous-webidl","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"throw","errorSource":{"kind":"first-failing-predicate","branchId":"webidl"}},{"terminalId":"later-predicate-rejection","conditions":{"webidlValid":true,"providerPredicatesValid":false},"branchPath":["webidl","service-provider"],"terminalOutcome":"reject before the terminal operation outcome","errorTiming":"device-timeline","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-undefined-and-report-error","errorSource":{"kind":"first-failing-predicate","branchId":"service-provider"}},{"terminalId":"operation-success","conditions":{"webidlValid":true,"providerPredicatesValid":true},"branchPath":["webidl","service-provider"],"terminalOutcome":"enqueue one ordered provider submission","errorTiming":"none","providerTokenCount":1,"physicalSequenceCount":1,"resultDisposition":"return-undefined","errorSource":{"kind":"none"}}],"factBindings":[{"fact":"webidlValid","kind":"branch-predicates","branchId":"webidl","passWhen":true},{"fact":"providerPredicatesValid","kind":"branch-predicates","branchId":"service-provider","passWhen":true}]},{"operationId":"GPUTexture.createView","facts":["webidlValid","providerPredicatesValid"],"precedence":["webidlValid","providerPredicatesValid"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"webidl-rejection","conditions":{"webidlValid":false},"branchPath":["webidl"],"terminalOutcome":"throw during synchronous Web IDL conversion","errorTiming":"synchronous-webidl","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"throw","errorSource":{"kind":"first-failing-predicate","branchId":"webidl"}},{"terminalId":"later-predicate-rejection","conditions":{"webidlValid":true,"providerPredicatesValid":false},"branchPath":["webidl","service-provider"],"terminalOutcome":"reject before the terminal operation outcome","errorTiming":"device-timeline","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-invalid-object-and-report-error","errorSource":{"kind":"first-failing-predicate","branchId":"service-provider"}},{"terminalId":"operation-success","conditions":{"webidlValid":true,"providerPredicatesValid":true},"branchPath":["webidl","service-provider"],"terminalOutcome":"enqueue one logical view creation","errorTiming":"none","providerTokenCount":1,"physicalSequenceCount":1,"resultDisposition":"return-object","errorSource":{"kind":"none"}}],"factBindings":[{"fact":"webidlValid","kind":"branch-predicates","branchId":"webidl","passWhen":true},{"fact":"providerPredicatesValid","kind":"branch-predicates","branchId":"service-provider","passWhen":true}]},{"operationId":"GPUTexture.destroy","facts":["alreadyTerminal","cleanupPredicatesValid"],"precedence":["alreadyTerminal","cleanupPredicatesValid"],"exhaustive":true,"disjoint":true,"terminals":[{"terminalId":"repeat-cleanup-noop","conditions":{"alreadyTerminal":true},"branchPath":["already-destroyed"],"terminalOutcome":"return without provider work","errorTiming":"none","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-undefined","errorSource":{"kind":"none"}},{"terminalId":"first-cleanup-rejection","conditions":{"alreadyTerminal":false,"cleanupPredicatesValid":false},"branchPath":["provider-cleanup"],"terminalOutcome":"reject invalid cleanup ownership without a provider token","errorTiming":"device-timeline","providerTokenCount":0,"physicalSequenceCount":0,"resultDisposition":"return-undefined-and-report-error","errorSource":{"kind":"first-failing-predicate","branchId":"provider-cleanup"}},{"terminalId":"first-cleanup-provider","conditions":{"alreadyTerminal":false,"cleanupPredicatesValid":true},"branchPath":["provider-cleanup"],"terminalOutcome":"enqueue one idempotent provider cleanup","errorTiming":"none","providerTokenCount":1,"physicalSequenceCount":1,"resultDisposition":"return-undefined","errorSource":{"kind":"none"}}],"factBindings":[{"fact":"alreadyTerminal","kind":"branch-selector","branchId":"already-destroyed","selectedWhen":true},{"fact":"cleanupPredicatesValid","kind":"branch-predicates","branchId":"provider-cleanup","passWhen":true}]}]},"fakeClientData":{"disposition":"deterministic-test-data-not-exact-profile-authority","adapterFeatures":["core-features-and-limits","texture-compression-bc","texture-compression-bc-sliced-3d","timestamp-query","rg11b10ufloat-renderable","texture-formats-tier1","texture-formats-tier2"],"providerEntryOperationIds":["GPU.requestAdapter","GPUAdapter.requestDevice","GPUCanvasContext.configure","GPUDevice.createBindGroupLayout","GPUDevice.createCommandEncoder","GPUDevice.createRenderPipeline","GPUDevice.createShaderModule","GPUQueue.submit","GPUTexture.createView"],"adapterLimits":{"maxTextureDimension1D":8192,"maxTextureDimension2D":8192,"maxTextureDimension3D":2048,"maxTextureArrayLayers":256,"maxBindGroups":4,"maxBindGroupsPlusVertexBuffers":24,"maxBindingsPerBindGroup":1000,"maxDynamicUniformBuffersPerPipelineLayout":8,"maxDynamicStorageBuffersPerPipelineLayout":4,"maxSampledTexturesPerShaderStage":16,"maxSamplersPerShaderStage":16,"maxStorageBuffersPerShaderStage":8,"maxStorageBuffersInVertexStage":8,"maxStorageBuffersInFragmentStage":8,"maxStorageTexturesPerShaderStage":4,"maxStorageTexturesInVertexStage":4,"maxStorageTexturesInFragmentStage":4,"maxUniformBuffersPerShaderStage":12,"maxUniformBufferBindingSize":65536,"maxStorageBufferBindingSize":134217728,"minUniformBufferOffsetAlignment":256,"minStorageBufferOffsetAlignment":256,"maxVertexBuffers":8,"maxBufferSize":268435456,"maxVertexAttributes":16,"maxVertexBufferArrayStride":2048,"maxInterStageShaderVariables":16,"maxColorAttachments":8,"maxColorAttachmentBytesPerSample":32,"maxComputeWorkgroupStorageSize":16384,"maxComputeInvocationsPerWorkgroup":256,"maxComputeWorkgroupSizeX":256,"maxComputeWorkgroupSizeY":256,"maxComputeWorkgroupSizeZ":64,"maxComputeWorkgroupsPerDimension":65535,"maxImmediateSize":0}},"routes":[{"operationId":"GPU.getPreferredCanvasFormat","wireId":1287763171,"semanticSha256":"cbb84da43565d0d917f99c4a3cab526a945d248580284c3ffc658db2401d2020","memberKind":"method","dispatchClass":"wrapper-local","logicalExecutionKind":"wrapper-local","publicArgumentCodec":"none-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"gpu-texture-format-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"synchronous-return","errors":[],"receiverHandleKind":null,"serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"not-carried-wrapper-only","promiseIdentity":"not-carried-wrapper-only","providerSubmission":"none","interfaceName":"GPU","memberName":"getPreferredCanvasFormat","fakeProviderEntry":false},{"operationId":"GPU.requestAdapter","wireId":1660448199,"semanticSha256":"068bb9e413b8c08eacd4ad7989bd9bd8713ba4ff7cec5eba53fe796fce139350","memberKind":"method","dispatchClass":"provider-promise","logicalExecutionKind":"provider-async","publicArgumentCodec":"gpu-request-adapter-options-v1","serviceArgumentCodec":"gpu-request-adapter-service-request-v1","publicResultCodec":"nullable-gpu-adapter-handle-promise-v1","serviceCompletionCodec":"nullable-gpu-adapter-service-completion-v2","resultTiming":"promise-settlement","errors":["operation-error-promise-rejection-v1","security-error-promise-rejection-v1","type-error-promise-rejection-v1"],"receiverHandleKind":null,"serviceReceiverProjection":{"source":"realm-gpu-singleton","kind":"GPU","flags":0,"objectIdSource":"realmIdentity.realmId","objectGenerationSource":"realmIdentity.realmGeneration"},"resultHandleKind":"GPUAdapter","wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"required-nonzero-distinct-from-operation-instance","providerSubmission":"semantic-call-promise-completion","interfaceName":"GPU","memberName":"requestAdapter","fakeProviderEntry":true},{"operationId":"GPUAdapter.requestDevice","wireId":194635792,"semanticSha256":"0404a2d0cb6d490e4492fa3c9cdc4ae9a3a89af0756882861e457688649f1c0d","memberKind":"method","dispatchClass":"provider-promise","logicalExecutionKind":"provider-async","publicArgumentCodec":"gpu-device-descriptor-v1","serviceArgumentCodec":"gpu-request-device-service-request-v1","publicResultCodec":"gpu-device-handle-promise-v1","serviceCompletionCodec":"gpu-device-service-completion-v1","resultTiming":"promise-settlement","errors":["device-lost-stable-promise-v1","operation-error-promise-rejection-v1","security-error-promise-rejection-v1","type-error-promise-rejection-v1"],"receiverHandleKind":"GPUAdapter","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUAdapter","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":"GPUDevice","wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"required-nonzero-distinct-from-operation-instance","providerSubmission":"semantic-call-promise-completion","interfaceName":"GPUAdapter","memberName":"requestDevice","fakeProviderEntry":true},{"operationId":"GPUCanvasContext.configure","wireId":3865035710,"semanticSha256":"8965fb28ce2c571a2c0dbc5f6483111fc8ea5b1e91f8eb4557857535344e0340","memberKind":"method","dispatchClass":"wrapper-local-service-enqueue","logicalExecutionKind":"wrapper-local-service-enqueue","publicArgumentCodec":"gpu-canvas-configuration-v1","serviceArgumentCodec":"gpu-canvas-configure-service-request-v1","publicResultCodec":"undefined-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-return-service-enqueued","errors":["internal-error-device-timeline-v1","invalid-state-device-timeline-v1","operation-error-device-timeline-v1","out-of-memory-device-timeline-v1","security-error-device-timeline-v1","type-error-synchronous-webidl-v1","validation-error-device-timeline-v1"],"receiverHandleKind":"GPUCanvasContext","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUCanvasContext","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-call-device-timeline","interfaceName":"GPUCanvasContext","memberName":"configure","fakeProviderEntry":true},{"operationId":"GPUCanvasContext.getConfiguration","wireId":3293775739,"semanticSha256":"d3c865e1cd8247045f447518ef463ddbe8465515bd8859cd54b037c6955a47d0","memberKind":"method","dispatchClass":"wrapper-local","logicalExecutionKind":"wrapper-local","publicArgumentCodec":"none-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"nullable-gpu-canvas-configuration-snapshot-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"synchronous-return","errors":[],"receiverHandleKind":"GPUCanvasContext","serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"not-carried-wrapper-only","promiseIdentity":"not-carried-wrapper-only","providerSubmission":"none","interfaceName":"GPUCanvasContext","memberName":"getConfiguration","fakeProviderEntry":false},{"operationId":"GPUCanvasContext.getCurrentTexture","wireId":3157634281,"semanticSha256":"037955d1bd740fb0d6b6807e1a1b593082e61d5b1be46741ff0d1d6052bc0716","memberKind":"method","dispatchClass":"wrapper-local-deferred-service","logicalExecutionKind":"wrapper-local-deferred-service","publicArgumentCodec":"none-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"gpu-texture-handle-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"synchronous-logical-identity-deferred-service","errors":["invalid-state-device-timeline-v1","invalid-state-synchronous-operation-v1","out-of-memory-device-timeline-v1","security-error-device-timeline-v1"],"receiverHandleKind":"GPUCanvasContext","serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":"GPUTexture","wrapperAllocatedTargetHandleKind":"GPUTexture","operationInstanceIdentity":"wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record","promiseIdentity":"zero-non-applicable-sealed-local-timeline-record","providerSubmission":"none","interfaceName":"GPUCanvasContext","memberName":"getCurrentTexture","fakeProviderEntry":false},{"operationId":"GPUCanvasContext.unconfigure","wireId":935342475,"semanticSha256":"a3c68bb5e4537c61e58fbe056d56b176609d55dc88417a4bfe708a718002ec0f","memberKind":"method","dispatchClass":"authority-reducing-service","logicalExecutionKind":"cleanup-service","publicArgumentCodec":"none-v1","serviceArgumentCodec":"gpu-canvas-unconfigure-service-request-v1","publicResultCodec":"undefined-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-return-cleanup-enqueued","errors":["operation-error-device-timeline-v1","security-error-device-timeline-v1"],"receiverHandleKind":"GPUCanvasContext","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUCanvasContext","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-call-authority-reducing","interfaceName":"GPUCanvasContext","memberName":"unconfigure","fakeProviderEntry":false},{"operationId":"GPUCommandEncoder.beginRenderPass","wireId":1908549907,"semanticSha256":"f824db690583244b8d836b447a85a55d3eabd2b63b765ddf6069b746cd4f90a7","memberKind":"method","dispatchClass":"wrapper-recording","logicalExecutionKind":"wrapper-recording","publicArgumentCodec":"gpu-render-pass-descriptor-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"gpu-render-pass-encoder-handle-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"synchronous-recording","errors":["invalid-state-device-timeline-v1","type-error-synchronous-webidl-v1","validation-error-device-timeline-v1"],"receiverHandleKind":"GPUCommandEncoder","serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":"GPURenderPassEncoder","wrapperAllocatedTargetHandleKind":"GPURenderPassEncoder","operationInstanceIdentity":"wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record","promiseIdentity":"zero-non-applicable-sealed-local-timeline-record","providerSubmission":"none","interfaceName":"GPUCommandEncoder","memberName":"beginRenderPass","fakeProviderEntry":false},{"operationId":"GPUCommandEncoder.finish","wireId":2481184390,"semanticSha256":"6a8b0d4ee72d155b30598b947b4fe228e99a81079544623c559d823cd61d4f30","memberKind":"method","dispatchClass":"wrapper-recording","logicalExecutionKind":"wrapper-recording","publicArgumentCodec":"gpu-command-buffer-descriptor-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"gpu-command-buffer-handle-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"synchronous-recording","errors":["invalid-state-device-timeline-v1","out-of-memory-device-timeline-v1","type-error-synchronous-webidl-v1"],"receiverHandleKind":"GPUCommandEncoder","serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":"GPUCommandBuffer","wrapperAllocatedTargetHandleKind":"GPUCommandBuffer","operationInstanceIdentity":"wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record","promiseIdentity":"zero-non-applicable-sealed-local-timeline-record","providerSubmission":"none","interfaceName":"GPUCommandEncoder","memberName":"finish","fakeProviderEntry":false},{"operationId":"GPUDevice.createBindGroupLayout","wireId":2544948076,"semanticSha256":"f40a4bba243801e87098776ea5dc50625c74d497d1eb294eebb077404cce269c","memberKind":"method","dispatchClass":"service-submit","logicalExecutionKind":"service-enqueue","publicArgumentCodec":"gpu-bind-group-layout-descriptor-v1","serviceArgumentCodec":"gpu-create-bind-group-layout-service-request-v1","publicResultCodec":"gpu-bind-group-layout-handle-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-logical-identity-service-enqueued","errors":["internal-error-device-timeline-v1","invalid-state-device-timeline-v1","out-of-memory-device-timeline-v1","security-error-device-timeline-v1","type-error-synchronous-webidl-v1","validation-error-device-timeline-v1"],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUDevice","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":"GPUBindGroupLayout","wrapperAllocatedTargetHandleKind":"GPUBindGroupLayout","operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-call-device-timeline","interfaceName":"GPUDevice","memberName":"createBindGroupLayout","fakeProviderEntry":true},{"operationId":"GPUDevice.createPipelineLayout","wireId":3373402978,"semanticSha256":"cca327299a920e4c8e543942591eaf3c75fe1af4b6603a4f85075d1d7d7cf6d4","memberKind":"method","dispatchClass":"service-submit","logicalExecutionKind":"service-enqueue","publicArgumentCodec":"gpu-pipeline-layout-descriptor-v1","serviceArgumentCodec":"gpu-create-pipeline-layout-service-request-v1","publicResultCodec":"gpu-pipeline-layout-handle-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-logical-identity-service-enqueued","errors":["internal-error-device-timeline-v1","invalid-state-device-timeline-v1","out-of-memory-device-timeline-v1","security-error-device-timeline-v1","type-error-synchronous-webidl-v1","validation-error-device-timeline-v1"],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUDevice","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":"GPUPipelineLayout","wrapperAllocatedTargetHandleKind":"GPUPipelineLayout","operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-call-device-timeline","interfaceName":"GPUDevice","memberName":"createPipelineLayout","fakeProviderEntry":false},{"operationId":"GPUDevice.createCommandEncoder","wireId":4055478657,"semanticSha256":"9f3b09e7e7da817aaa2e67374f590cb54b150b2e8d89d7a387ad7d35b37f114f","memberKind":"method","dispatchClass":"service-submit","logicalExecutionKind":"service-enqueue","publicArgumentCodec":"gpu-command-encoder-descriptor-v1","serviceArgumentCodec":"gpu-create-command-encoder-service-request-v1","publicResultCodec":"gpu-command-encoder-handle-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-logical-identity-service-enqueued","errors":["internal-error-device-timeline-v1","invalid-state-device-timeline-v1","out-of-memory-device-timeline-v1","security-error-device-timeline-v1","type-error-synchronous-webidl-v1"],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUDevice","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":"GPUCommandEncoder","wrapperAllocatedTargetHandleKind":"GPUCommandEncoder","operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-call-device-timeline","interfaceName":"GPUDevice","memberName":"createCommandEncoder","fakeProviderEntry":true},{"operationId":"GPUDevice.createRenderPipeline","wireId":2407151159,"semanticSha256":"e00998b41d03ea895864e7e116fdfa4cf31416ca112e18957919e19c6541b6dc","memberKind":"method","dispatchClass":"service-submit","logicalExecutionKind":"service-enqueue","publicArgumentCodec":"gpu-render-pipeline-descriptor-v1","serviceArgumentCodec":"gpu-create-render-pipeline-service-request-v1","publicResultCodec":"gpu-render-pipeline-handle-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-logical-identity-service-enqueued","errors":["internal-error-device-timeline-v1","invalid-state-device-timeline-v1","out-of-memory-device-timeline-v1","security-error-device-timeline-v1","type-error-synchronous-webidl-v1","validation-error-device-timeline-v1"],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUDevice","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":"GPURenderPipeline","wrapperAllocatedTargetHandleKind":"GPURenderPipeline","operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-call-device-timeline","interfaceName":"GPUDevice","memberName":"createRenderPipeline","fakeProviderEntry":true},{"operationId":"GPUDevice.createShaderModule","wireId":599085487,"semanticSha256":"2b8cb02541b94bde51ea323a655a79ef54c408c2e6f4b688952b27ea8cc4fd41","memberKind":"method","dispatchClass":"service-submit","logicalExecutionKind":"service-enqueue","publicArgumentCodec":"gpu-shader-module-descriptor-v1","serviceArgumentCodec":"gpu-create-shader-module-service-request-v1","publicResultCodec":"gpu-shader-module-handle-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-logical-identity-service-enqueued","errors":["internal-error-device-timeline-v1","invalid-state-device-timeline-v1","out-of-memory-device-timeline-v1","security-error-device-timeline-v1","type-error-synchronous-webidl-v1","validation-error-device-timeline-v1"],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUDevice","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":"GPUShaderModule","wrapperAllocatedTargetHandleKind":"GPUShaderModule","operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-call-device-timeline","interfaceName":"GPUDevice","memberName":"createShaderModule","fakeProviderEntry":true},{"operationId":"GPUDevice.destroy","wireId":206890944,"semanticSha256":"8decad4dff41a9cc94704f664b520cd302e1aa2c4d1b8caec5f0b337e3787d2a","memberKind":"method","dispatchClass":"authority-reducing-service","logicalExecutionKind":"cleanup-service","publicArgumentCodec":"none-v1","serviceArgumentCodec":"gpu-device-cleanup-service-request-v1","publicResultCodec":"undefined-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-return-cleanup-enqueued","errors":["device-lost-stable-promise-v1","operation-error-device-timeline-v1","security-error-device-timeline-v1"],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUDevice","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-call-authority-reducing","interfaceName":"GPUDevice","memberName":"destroy","fakeProviderEntry":false},{"operationId":"GPUDevice.features","wireId":3810427763,"semanticSha256":"9898b2aa27dd941e2299bfdcda8ed06d5559f23d36094f8c8e1bb568d78b8629","memberKind":"property","dispatchClass":"wrapper-property-read","logicalExecutionKind":"wrapper-local","publicArgumentCodec":"none-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"gpu-supported-features-snapshot-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"synchronous-stable-property","errors":[],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"not-carried-wrapper-only","promiseIdentity":"not-carried-wrapper-only","providerSubmission":"none","interfaceName":"GPUDevice","memberName":"features","fakeProviderEntry":false},{"operationId":"GPUDevice.limits","wireId":1914447212,"semanticSha256":"b83516a88049f122bf9df0ef51f173c6b5780f3077875442514c718a8cfbf26e","memberKind":"property","dispatchClass":"wrapper-property-read","logicalExecutionKind":"wrapper-local","publicArgumentCodec":"none-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"gpu-supported-limits-snapshot-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"synchronous-stable-property","errors":[],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"not-carried-wrapper-only","promiseIdentity":"not-carried-wrapper-only","providerSubmission":"none","interfaceName":"GPUDevice","memberName":"limits","fakeProviderEntry":false},{"operationId":"GPUDevice.lost","wireId":892795326,"semanticSha256":"1449237ed70769ebb61939816e0725c9341db6367b88219d2396e4b777a0709e","memberKind":"property","dispatchClass":"wrapper-property-read","logicalExecutionKind":"wrapper-local","publicArgumentCodec":"none-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"gpu-device-lost-stable-promise-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"stable-promise-property","errors":["device-lost-stable-promise-v1"],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"not-carried-wrapper-only","promiseIdentity":"not-carried-wrapper-only","providerSubmission":"none","interfaceName":"GPUDevice","memberName":"lost","fakeProviderEntry":false},{"operationId":"GPUDevice.popErrorScope","wireId":2687703037,"semanticSha256":"cbe45cde70a2777a812cfc7e5c0e8113acdf52dd4a7afbb5f0bf6cf796923717","memberKind":"method","dispatchClass":"provider-promise","logicalExecutionKind":"provider-async","publicArgumentCodec":"none-v1","serviceArgumentCodec":"gpu-pop-error-scope-service-request-v1","publicResultCodec":"nullable-gpu-error-promise-v1","serviceCompletionCodec":"nullable-gpu-error-service-completion-v1","resultTiming":"promise-settlement-after-scope-barrier","errors":["operation-error-promise-rejection-v1"],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUDevice","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"required-nonzero-distinct-from-operation-instance","providerSubmission":"semantic-call-promise-completion","interfaceName":"GPUDevice","memberName":"popErrorScope","fakeProviderEntry":false},{"operationId":"GPUDevice.pushErrorScope","wireId":1311136574,"semanticSha256":"e3e797642bf8cc3fb7ff366c8d5f01940ffc6bfd45436dec968146080dd6f1f8","memberKind":"method","dispatchClass":"wrapper-local-service-enqueue","logicalExecutionKind":"wrapper-local-service-enqueue","publicArgumentCodec":"gpu-error-filter-v1","serviceArgumentCodec":"gpu-push-error-scope-service-request-v1","publicResultCodec":"undefined-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-return-service-enqueued","errors":["type-error-synchronous-webidl-v1"],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUDevice","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-service-timeline","interfaceName":"GPUDevice","memberName":"pushErrorScope","fakeProviderEntry":false},{"operationId":"GPUDevice.queue","wireId":1949537636,"semanticSha256":"e6781e179fe1654367f17bb330e869c0d2a3f244989c9cc1cfc4e016c3f65a8f","memberKind":"property","dispatchClass":"wrapper-property-read","logicalExecutionKind":"wrapper-local","publicArgumentCodec":"none-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"gpu-queue-handle-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"synchronous-stable-property","errors":[],"receiverHandleKind":"GPUDevice","serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":"GPUQueue","wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"not-carried-wrapper-only","promiseIdentity":"not-carried-wrapper-only","providerSubmission":"none","interfaceName":"GPUDevice","memberName":"queue","fakeProviderEntry":false},{"operationId":"GPUQueue.submit","wireId":308839175,"semanticSha256":"e0cfb9442892144f0f6f4232465c2cef4d9e66896f346e209e6db9cbc2c830ed","memberKind":"method","dispatchClass":"service-submit","logicalExecutionKind":"service-enqueue","publicArgumentCodec":"gpu-command-buffer-handle-sequence-v1","serviceArgumentCodec":"gpu-sealed-command-program-sequence-service-request-v1","publicResultCodec":"undefined-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-return-service-enqueued","errors":["internal-error-device-timeline-v1","invalid-state-device-timeline-v1","out-of-memory-device-timeline-v1","security-error-device-timeline-v1","type-error-synchronous-webidl-v1","validation-error-device-timeline-v1"],"receiverHandleKind":"GPUQueue","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUQueue","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-call-device-timeline","interfaceName":"GPUQueue","memberName":"submit","fakeProviderEntry":true},{"operationId":"GPURenderPassEncoder.draw","wireId":3054695767,"semanticSha256":"8cf617b4697f8ade79b3ec17b18d463d66abf6b912f3df2b4a2f7aa8ba31b027","memberKind":"method","dispatchClass":"wrapper-recording","logicalExecutionKind":"wrapper-recording","publicArgumentCodec":"gpu-draw-arguments-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"undefined-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"synchronous-recording","errors":["invalid-state-device-timeline-v1","type-error-synchronous-webidl-v1","validation-error-device-timeline-v1"],"receiverHandleKind":"GPURenderPassEncoder","serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record","promiseIdentity":"zero-non-applicable-sealed-local-timeline-record","providerSubmission":"none","interfaceName":"GPURenderPassEncoder","memberName":"draw","fakeProviderEntry":false},{"operationId":"GPURenderPassEncoder.end","wireId":1724778411,"semanticSha256":"ab787e0a9d212f15d3e0347189a95c8f3621287572a40d3d6fe33b3059b50f7f","memberKind":"method","dispatchClass":"wrapper-recording","logicalExecutionKind":"wrapper-recording","publicArgumentCodec":"none-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"undefined-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"synchronous-recording","errors":["invalid-state-device-timeline-v1"],"receiverHandleKind":"GPURenderPassEncoder","serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record","promiseIdentity":"zero-non-applicable-sealed-local-timeline-record","providerSubmission":"none","interfaceName":"GPURenderPassEncoder","memberName":"end","fakeProviderEntry":false},{"operationId":"GPURenderPassEncoder.setPipeline","wireId":551383281,"semanticSha256":"307d3da4a79e9462706a907e320c1a43cc8cd44026d7c6dd7880e48c83bf7323","memberKind":"method","dispatchClass":"wrapper-recording","logicalExecutionKind":"wrapper-recording","publicArgumentCodec":"gpu-render-pipeline-handle-v1","serviceArgumentCodec":"none-service-request-v1","publicResultCodec":"undefined-v1","serviceCompletionCodec":"none-service-completion-v1","resultTiming":"synchronous-recording","errors":["invalid-state-device-timeline-v1","validation-error-device-timeline-v1"],"receiverHandleKind":"GPURenderPassEncoder","serviceReceiverProjection":{"source":"not-carried","kind":null,"flags":0,"objectIdSource":null,"objectGenerationSource":null},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record","promiseIdentity":"zero-non-applicable-sealed-local-timeline-record","providerSubmission":"none","interfaceName":"GPURenderPassEncoder","memberName":"setPipeline","fakeProviderEntry":false},{"operationId":"GPUTexture.createView","wireId":1846872529,"semanticSha256":"a81db85dd6322f2d7a801a414983b2eee2d2b960d67131c73b46ec8304aaedeb","memberKind":"method","dispatchClass":"service-submit","logicalExecutionKind":"service-enqueue","publicArgumentCodec":"gpu-texture-view-descriptor-v1","serviceArgumentCodec":"gpu-create-texture-view-service-request-v1","publicResultCodec":"gpu-texture-view-handle-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-logical-identity-service-enqueued","errors":["internal-error-device-timeline-v1","invalid-state-device-timeline-v1","out-of-memory-device-timeline-v1","security-error-device-timeline-v1","type-error-synchronous-webidl-v1","validation-error-device-timeline-v1"],"receiverHandleKind":"GPUTexture","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUTexture","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":"GPUTextureView","wrapperAllocatedTargetHandleKind":"GPUTextureView","operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-call-device-timeline","interfaceName":"GPUTexture","memberName":"createView","fakeProviderEntry":true},{"operationId":"GPUTexture.destroy","wireId":2933046788,"semanticSha256":"30b910b5b8a392a68ff331e9840c73c0ee1f3d66c5cca4070d02801c16d3ee75","memberKind":"method","dispatchClass":"authority-reducing-service","logicalExecutionKind":"cleanup-service","publicArgumentCodec":"none-v1","serviceArgumentCodec":"gpu-texture-cleanup-service-request-v1","publicResultCodec":"undefined-v1","serviceCompletionCodec":"terminal-receipt-service-completion-v1","resultTiming":"synchronous-return-cleanup-enqueued","errors":["operation-error-device-timeline-v1","security-error-device-timeline-v1"],"receiverHandleKind":"GPUTexture","serviceReceiverProjection":{"source":"wrapper-full-reference","kind":"GPUTexture","flags":0,"objectIdSource":"wrapperReceiver.logicalHandle","objectGenerationSource":"wrapperReceiver.lifecycleGeneration"},"resultHandleKind":null,"wrapperAllocatedTargetHandleKind":null,"operationInstanceIdentity":"required-nonzero-monotonic-per-realm","promiseIdentity":"zero-non-applicable","providerSubmission":"semantic-call-authority-reducing","interfaceName":"GPUTexture","memberName":"destroy","fakeProviderEntry":false}]})
