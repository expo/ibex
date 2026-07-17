/**
 * Engine-neutral behavioral corpus for the generated test-only WebGPU wrapper.
 * The function is serialized into a standalone script and run byte-for-byte on
 * Node 24.13.1 and the real built Ibex/Hermes evaluator.
 *
 * @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
 * @ref LLP 0019#the-enforced-conformance-seam
 * @ref LLP 0026#compatibility-contract-and-conformance-corpus
 */

export const webGpuTestWrapperMarker = "IBEX_WEBGPU_TEST_WRAPPER_RESULT:";

export async function webGpuTestWrapperCorpus(createHarness) {
  "use strict";

  var assertionCount = 0;

  function assert(condition, message) {
    assertionCount += 1;
    if (!condition) throw new Error("webgpu wrapper corpus: " + message);
  }

  function same(left, right, message) {
    assert(JSON.stringify(left) === JSON.stringify(right), message);
  }

  function last(array) {
    return array[array.length - 1];
  }

  function operationReceipt(observation, operationName) {
    for (var index = observation.serviceReceipts.length - 1; index >= 0; index -= 1) {
      if (observation.serviceReceipts[index].operationName === operationName) {
        return observation.serviceReceipts[index];
      }
    }
    return null;
  }

  function operationReceipts(observation, operationName) {
    var receipts = [];
    for (var index = 0; index < observation.serviceReceipts.length; index += 1) {
      if (observation.serviceReceipts[index].operationName === operationName) {
        receipts.push(observation.serviceReceipts[index]);
      }
    }
    return receipts;
  }

  function publicCall(observation, operationName) {
    for (var index = 0; index < observation.publicCalls.length; index += 1) {
      if (observation.publicCalls[index].operationId === operationName) {
        return observation.publicCalls[index];
      }
    }
    return null;
  }

  function expectTypeError(action, message) {
    var error = null;
    try {
      action();
    } catch (caught) {
      error = caught;
    }
    assert(error !== null, message + " throws");
    assert(error.name === "TypeError", message + " has TypeError name");
    assert(error instanceof TypeError, message + " is a real TypeError instance");
  }

  function indexOfTrace(trace, kind) {
    for (var index = 0; index < trace.length; index += 1) {
      if (trace[index].kind === kind) return index;
    }
    return -1;
  }

  function assertTerminalFacts(facts, terminal, message) {
    var names = Object.keys(terminal.conditions);
    for (var index = 0; index < names.length; index += 1) {
      assert(
        facts[names[index]] === terminal.conditions[names[index]],
        message + " condition " + names[index],
      );
    }
  }

  var expectedOperations = [
    "GPU.getPreferredCanvasFormat",
    "GPU.requestAdapter",
    "GPUAdapter.requestDevice",
    "GPUCanvasContext.configure",
    "GPUCanvasContext.getConfiguration",
    "GPUCanvasContext.getCurrentTexture",
    "GPUCanvasContext.unconfigure",
    "GPUCommandEncoder.beginRenderPass",
    "GPUCommandEncoder.finish",
    "GPUDevice.createCommandEncoder",
    "GPUDevice.createRenderPipeline",
    "GPUDevice.createShaderModule",
    "GPUDevice.destroy",
    "GPUDevice.features",
    "GPUDevice.limits",
    "GPUDevice.lost",
    "GPUDevice.popErrorScope",
    "GPUDevice.pushErrorScope",
    "GPUDevice.queue",
    "GPUQueue.submit",
    "GPURenderPassEncoder.draw",
    "GPURenderPassEncoder.end",
    "GPURenderPassEncoder.setPipeline",
    "GPUTexture.createView",
    "GPUTexture.destroy",
  ];

  async function exerciseAllOperations() {
    var harness = createHarness();
    assert(harness.gpu.getPreferredCanvasFormat() === "bgra8unorm", "preferred format");
    var adapter = await harness.gpu.requestAdapter();
    var device = await adapter.requestDevice({
      label: "raw-public-device-label",
      defaultQueue: { label: "raw-public-queue-label" },
      requiredFeatures: ["timestamp-query", "timestamp-query"],
      requiredLimits: {
        unknownUndefinedLimit: undefined,
        maxTextureDimension1D: undefined,
        minUniformBufferOffsetAlignment: 256,
      },
    });

    var featuresOne = device.features;
    var featuresTwo = device.features;
    assert(featuresOne === featuresTwo, "features identity is stable");
    assert(Object.isFrozen(featuresOne), "features is frozen");
    assert(featuresOne.size === 1, "feature size");
    assert(featuresOne.has("timestamp-query"), "feature membership");
    assert(!("add" in featuresOne) && !("delete" in featuresOne), "feature set has no mutators");
    assert(featuresOne.keys().next().value === "timestamp-query", "feature keys");
    assert(featuresOne.values().next().value === "timestamp-query", "feature values");
    var entry = featuresOne.entries().next().value;
    same(entry, ["timestamp-query", "timestamp-query"], "feature entries");
    assert(featuresOne[Symbol.iterator]().next().value === "timestamp-query", "feature iterator");
    var visited = [];
    featuresOne.forEach(function (value, key, receiver) {
      visited.push([value, key, receiver === featuresOne]);
    });
    same(visited, [["timestamp-query", "timestamp-query", true]], "feature forEach");

    var limitsOne = device.limits;
    var limitsTwo = device.limits;
    assert(limitsOne === limitsTwo && Object.isFrozen(limitsOne), "limits identity is stable");
    assert(Object.keys(limitsOne).length === 36, "complete 36-member limits");
    var queueOne = device.queue;
    var queueTwo = device.queue;
    assert(queueOne === queueTwo, "queue identity is stable");
    var lostOne = device.lost;
    var lostTwo = device.lost;
    assert(lostOne === lostTwo, "lost promise identity is stable");

    device.pushErrorScope("validation");
    var context = harness.createCanvasContext();
    var contextReference = JSON.stringify(harness.describe(context).reference);
    context.configure({ device: device, format: "bgra8unorm" });
    assert(JSON.stringify(harness.describe(context).reference) === contextReference, "configure preserves context ref");
    assert(context.getConfiguration().device === device, "configuration snapshot preserves device wrapper");
    var texture = context.getCurrentTexture();
    assert(texture === context.getCurrentTexture(), "current texture is stable in one epoch");
    var view = texture.createView({});
    var module = device.createShaderModule({ code: "@vertex fn v() {}" });
    var pipeline = device.createRenderPipeline({
      vertex: { module: module },
      fragment: { module: module },
    });
    var encoder = device.createCommandEncoder({});
    var pass = encoder.beginRenderPass({ colorAttachments: [{ view: view }] });
    pass.setPipeline(pipeline);
    pass.draw(3);
    pass.end();
    var buffer = encoder.finish({});
    queueOne.submit([buffer]);
    assert((await device.popErrorScope()) === null, "valid program has no scoped error");
    texture.destroy();
    context.unconfigure();
    assert(JSON.stringify(harness.describe(context).reference) === contextReference, "unconfigure preserves context ref");
    device.destroy();
    var lostInfo = await lostOne;
    assert(lostInfo.reason === "destroyed", "destroy settles stable lost promise");

    var observation = harness.inspect();
    var observed = {};
    for (var index = 0; index < observation.publicCalls.length; index += 1) {
      observed[observation.publicCalls[index].operationId] = true;
    }
    var observedNames = Object.keys(observed).sort();
    same(observedNames, expectedOperations.slice().sort(), "all 25 operation identities are exercised");
    assert(observedNames.length === 25, "operation inventory count");

    var adapterReceipt = operationReceipt(observation, "GPU.requestAdapter");
    var deviceReceipt = operationReceipt(observation, "GPUAdapter.requestDevice");
    assert(adapterReceipt.wrapperAllocatedTargetRef === null, "requestAdapter has no wrapper target");
    assert(adapterReceipt.resultHandleRef.objectKind === "GPUAdapter", "requestAdapter service result");
    assert(adapterReceipt.receiverRef === null, "GPU singleton request receiver is null");
    assert(adapterReceipt.untrustedWrapperPayload.receiverRef === null, "GPU singleton untrusted receiver is null");
    assert(adapterReceipt.authenticatedIngressContext.receiverRef === null, "GPU singleton authenticated receiver is null");
    var adapterEvent = observation.events.find(function (event) {
      return event.kind === "operation-complete" && event.operationName === "GPU.requestAdapter";
    });
    assert(adapterEvent.receiverRef === null, "GPU singleton completion receiver is null");
    assert(deviceReceipt.authenticatedIngressContext.logicalDeviceId === 0, "requestDevice ingress device absent");
    assert(deviceReceipt.wrapperAllocatedTargetRef === null, "requestDevice has no wrapper target");
    assert(deviceReceipt.resultHandleRef.objectKind === "GPUDevice", "requestDevice result device");
    assert(deviceReceipt.physicalOperationKey.logicalDeviceId === harness.describe(device).deviceId, "physical result device identity");
    var providerPayload = deviceReceipt.providerPayload;
    same(
      Object.keys(providerPayload).sort(),
      ["logicalFeatures", "logicalLimits", "serviceInternalRequirements"],
      "requestDevice provider payload has only normalized logical capabilities and internal requirements",
    );
    same(providerPayload.logicalFeatures, ["timestamp-query"], "provider features are sorted and deduplicated");
    assert(Object.keys(providerPayload.logicalLimits).length === 36, "provider carries complete normalized logical limits");
    assert(providerPayload.logicalLimits.maxTextureDimension1D === 8192, "undefined required limit keeps the core profile default");
    assert(providerPayload.logicalLimits.minUniformBufferOffsetAlignment === 256, "explicit alignment is normalized to a number");
    assert(!Object.prototype.hasOwnProperty.call(providerPayload.logicalLimits, "unknownUndefinedLimit"), "unknown undefined limit is absent from provider projection");
    assert(
      providerPayload.logicalLimits.maxStorageBuffersPerShaderStage ===
        Math.max(
          providerPayload.logicalLimits.maxStorageBuffersPerShaderStage,
          providerPayload.logicalLimits.maxStorageBuffersInVertexStage,
          providerPayload.logicalLimits.maxStorageBuffersInFragmentStage,
        ),
      "storage-buffer aggregate normalization ran",
    );
    assert(
      providerPayload.logicalLimits.maxStorageTexturesPerShaderStage ===
        Math.max(
          providerPayload.logicalLimits.maxStorageTexturesPerShaderStage,
          providerPayload.logicalLimits.maxStorageTexturesInVertexStage,
          providerPayload.logicalLimits.maxStorageTexturesInFragmentStage,
        ),
      "storage-texture aggregate normalization ran",
    );
    same(
      providerPayload.serviceInternalRequirements,
      {
        requiredFeatures: [],
        requiredLimits: {},
        schema: "exact/webgpu-service-internal-requirements/1",
      },
      "provider internal requirements are separately versioned",
    );
    assert(
      deviceReceipt.untrustedWrapperPayload.argumentBody.label ===
        "raw-public-device-label",
      "raw public label remains only in semantic-request observation",
    );
    assert(
      deviceReceipt.untrustedWrapperPayload.argumentBody.defaultQueue.label ===
        "raw-public-queue-label",
      "raw nested public descriptor remains observable before provider projection",
    );
    assert(
      Object.prototype.hasOwnProperty.call(
        deviceReceipt.untrustedWrapperPayload.argumentBody.requiredLimits,
        "unknownUndefinedLimit",
      ),
      "untrusted semantic request preserves the skipped undefined key",
    );
    assert(
      !Object.prototype.hasOwnProperty.call(providerPayload, "label") &&
        !Object.prototype.hasOwnProperty.call(providerPayload, "defaultQueue") &&
        !Object.prototype.hasOwnProperty.call(providerPayload, "requiredFeatures") &&
        !Object.prototype.hasOwnProperty.call(providerPayload, "requiredLimits"),
      "raw public descriptor fields are unavailable at provider-ready",
    );

    var targetKinds = {
      "GPUDevice.createCommandEncoder": "GPUCommandEncoder",
      "GPUDevice.createShaderModule": "GPUShaderModule",
      "GPUDevice.createRenderPipeline": "GPURenderPipeline",
      "GPUTexture.createView": "GPUTextureView",
    };
    var targetNames = Object.keys(targetKinds);
    for (index = 0; index < targetNames.length; index += 1) {
      var receipt = operationReceipt(observation, targetNames[index]);
      assert(receipt.wrapperAllocatedTargetRef.objectKind === targetKinds[targetNames[index]], targetNames[index] + " target kind");
      same(receipt.wrapperAllocatedTargetRef, receipt.resultHandleRef, targetNames[index] + " target equals result");
    }

    var representativeReceivers = {
      GPU: harness.gpu,
      GPUAdapter: adapter,
      GPUCanvasContext: context,
      GPUCommandEncoder: encoder,
      GPUDevice: device,
      GPUQueue: queueOne,
      GPURenderPassEncoder: pass,
      GPUTexture: texture,
    };
    assert(observation.routeIdentityMatrix.length === 25, "route identity matrix has 25 rows");
    for (index = 0; index < observation.routeIdentityMatrix.length; index += 1) {
      var matrix = observation.routeIdentityMatrix[index];
      var call = publicCall(observation, matrix.operationId);
      assert(Boolean(call), matrix.operationId + " has a public identity record");
      assert(call.expectedReceiverKind === matrix.receiverHandleKind, matrix.operationId + " expected receiver is route-derived");
      assert(call.expectedTargetKind === matrix.wrapperAllocatedTargetHandleKind, matrix.operationId + " expected target is route-derived");
      assert(call.expectedResultKind === matrix.resultHandleKind, matrix.operationId + " expected result is route-derived");
      if (matrix.receiverHandleKind === null) {
        assert(call.receiverRef === null && call.receiverKind === null, matrix.operationId + " null singleton receiver");
      } else {
        assert(call.receiverRef.objectKind === matrix.receiverHandleKind, matrix.operationId + " receiver kind");
      }
      if (matrix.wrapperAllocatedTargetHandleKind === null) {
        assert(call.wrapperAllocatedTargetRef === null && call.targetKind === null, matrix.operationId + " no target identity");
      } else {
        assert(call.wrapperAllocatedTargetRef.objectKind === matrix.wrapperAllocatedTargetHandleKind, matrix.operationId + " target identity");
      }
      if (matrix.resultHandleKind === null) {
        assert(call.resultHandleRef === null && call.resultKind === null, matrix.operationId + " no result handle identity");
      } else {
        assert(call.resultHandleRef.objectKind === matrix.resultHandleKind, matrix.operationId + " result identity");
      }
      if (
        matrix.wrapperAllocatedTargetHandleKind !== null &&
        matrix.wrapperAllocatedTargetHandleKind === matrix.resultHandleKind
      ) {
        same(call.wrapperAllocatedTargetRef, call.resultHandleRef, matrix.operationId + " target and result are one identity");
      }

      var routeReceipts = operationReceipts(observation, matrix.operationId);
      for (var receiptIndex = 0; receiptIndex < routeReceipts.length; receiptIndex += 1) {
        var matrixReceipt = routeReceipts[receiptIndex];
        if (matrix.receiverHandleKind === null) {
          assert(matrixReceipt.receiverRef === null, matrix.operationId + " receipt singleton receiver null");
          assert(matrixReceipt.authenticatedIngressContext.receiverRef === null, matrix.operationId + " authenticated singleton receiver null");
        } else {
          assert(matrixReceipt.receiverRef.objectKind === matrix.receiverHandleKind, matrix.operationId + " receipt receiver kind");
        }
        if (matrix.wrapperAllocatedTargetHandleKind === null) {
          assert(matrixReceipt.wrapperAllocatedTargetRef === null, matrix.operationId + " receipt target absent");
        } else {
          assert(matrixReceipt.wrapperAllocatedTargetRef.objectKind === matrix.wrapperAllocatedTargetHandleKind, matrix.operationId + " receipt target kind");
        }
        if (
          matrix.wrapperAllocatedTargetHandleKind !== null &&
          matrix.wrapperAllocatedTargetHandleKind === matrix.resultHandleKind
        ) {
          same(matrixReceipt.wrapperAllocatedTargetRef, matrixReceipt.resultHandleRef, matrix.operationId + " receipt target and result identity");
        }
      }

      var validReceiver = representativeReceivers[matrix.interfaceName];
      assert(Boolean(validReceiver), matrix.operationId + " has a representative receiver");
      var descriptor = Object.getOwnPropertyDescriptor(
        Object.getPrototypeOf(validReceiver),
        matrix.memberName,
      );
      assert(Boolean(descriptor), matrix.operationId + " member descriptor exists");
      var beforeFailure = harness.inspect().publicCalls.length;
      expectTypeError(function () {
        if (matrix.memberKind === "property") descriptor.get.call({});
        else descriptor.value.call({});
      }, matrix.operationId + " unbranded receiver");
      assert(harness.inspect().publicCalls.length === beforeFailure, matrix.operationId + " unbranded receiver fails before operation allocation");
      var wrongBrandedReceiver = matrix.interfaceName === "GPU" ? adapter : harness.gpu;
      expectTypeError(function () {
        if (matrix.memberKind === "property") descriptor.get.call(wrongBrandedReceiver);
        else descriptor.value.call(wrongBrandedReceiver);
      }, matrix.operationId + " wrong branded receiver");
      assert(harness.inspect().publicCalls.length === beforeFailure, matrix.operationId + " wrong branded receiver fails before operation allocation");
    }
    return {
      operationCount: observedNames.length,
      publicCallCount: observation.publicCalls.length,
      serviceReceiptCount: observation.serviceReceipts.length,
      eventCount: observation.events.length,
    };
  }

  function requestDeviceErrorName(terminal, failureProgram, realmClosed, accountClosed) {
    if (!terminal.errorSource || terminal.errorSource.kind !== "first-failing-predicate") {
      return "";
    }
    var selected = null;
    for (var branchIndex = 0; branchIndex < failureProgram.branches.length; branchIndex += 1) {
      var branch = failureProgram.branches[branchIndex];
      if (branch.branchId !== terminal.errorSource.branchId) continue;
      for (var predicateIndex = 0; predicateIndex < branch.orderedPredicates.length; predicateIndex += 1) {
        var predicate = branch.orderedPredicates[predicateIndex];
        if (predicate.failureClass === "none") continue;
        if (branch.branchId === "live-admission") {
          if (realmClosed && predicate.predicateId !== "adapter.request-device.realm") continue;
          if (accountClosed && predicate.predicateId !== "adapter.request-device.account") continue;
          if (!realmClosed && !accountClosed && predicate.predicateId !== "adapter.request-device.coverage") continue;
        }
        selected = predicate;
        break;
      }
    }
    assert(Boolean(selected), terminal.terminalId + " has an authenticated failure predicate");
    if (selected.failureClass === "type-error") return "TypeError";
    if (selected.failureClass === "operation-error") return "OperationError";
    if (selected.failureClass === "security-error") return "SecurityError";
    throw new Error("unknown requestDevice failure class: " + selected.failureClass);
  }

  function terminalCaseFromFacts(terminal, failureProgram) {
    var facts = {};
    var names = Object.keys(terminal.conditions);
    var allowedFacts = {
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
    for (var index = 0; index < names.length; index += 1) {
      if (allowedFacts[names[index]]) facts[names[index]] = terminal.conditions[names[index]];
    }
    var mode = "valid";
    if (terminal.conditions.webidlValid === false) mode = "cyclic";
    else if (terminal.conditions.requiredFeaturesSupported === false) mode = "unsupported";
    else if (terminal.conditions.adapterRequestValid === false) mode = "limit";
    var result =
      terminal.resultDisposition === "promise-reject"
        ? "reject"
        : terminal.resultDisposition === "promise-resolve-lost-object"
          ? "lost"
          : "live";
    return {
      terminal: terminal,
      id: terminal.terminalId,
      mode: mode,
      expired: terminal.conditions.adapterExpired === true,
      facts: facts,
      error: requestDeviceErrorName(terminal, failureProgram, false, false),
      provider: terminal.providerTokenCount,
      result: result,
      closesAccount:
        terminal.publicationCreditDisposition.indexOf("account-close") !== -1 ||
        terminal.conditions.deviceAccountLiveAtProviderCompletion === false ||
        terminal.conditions.deviceAccountLiveAtSettlementCommit === false,
    };
  }

  async function exerciseTerminal(testCase) {
    var harness = createHarness();
    var adapter = await harness.gpu.requestAdapter();
    if (testCase.expired) {
      var prime = await adapter.requestDevice();
      prime.destroy();
      assert(harness.describe(adapter).expired, testCase.id + " primed expired adapter");
    }
    if (testCase.facts) harness.setRequestDeviceFacts(adapter, testCase.facts);

    var descriptor = {};
    if (testCase.mode === "cyclic") descriptor.self = descriptor;
    if (testCase.mode === "unsupported") descriptor.requiredFeatures = ["not-supported"];
    if (testCase.mode === "limit") {
      descriptor.requiredLimits = { maxTextureDimension1D: 999999 };
    }

    var result = null;
    var errorName = "";
    var errorIsTypeError = false;
    var reactionTrace = [];
    var requestPromise = adapter.requestDevice(descriptor);
    requestPromise.then(
      function () { reactionTrace.push("request-fulfilled"); },
      function () { reactionTrace.push("request-rejected"); },
    );
    try {
      result = await requestPromise;
    } catch (error) {
      errorName = error.name;
      errorIsTypeError = error instanceof TypeError;
    }
    if (testCase.result === "reject") {
      assert(result === null, testCase.id + " rejects without result");
      assert(
        errorName === testCase.error,
        testCase.id + " rejection class expected " + testCase.error + " got " + errorName,
      );
      if (testCase.error === "TypeError") {
        assert(errorIsTypeError, testCase.id + " rejection is a real TypeError instance");
      }
      same(reactionTrace, ["request-rejected"], testCase.id + " rejection reaction trace");
    } else {
      assert(errorName === "" && result !== null, testCase.id + " resolves a device");
      var lostPromiseOne = result.lost;
      var lostPromiseTwo = result.lost;
      assert(lostPromiseOne === lostPromiseTwo, testCase.id + " stable lost promise");
      var description = harness.describe(result);
      if (testCase.result === "lost") {
        assert(description.lostSettled && description.serviceDetached, testCase.id + " already-lost detached result");
        lostPromiseOne.then(function () { reactionTrace.push("lost-fulfilled"); });
        var lostInfo = await lostPromiseOne;
        assert(lostInfo.reason === "unknown", testCase.id + " lost reason");
        same(reactionTrace, ["request-fulfilled", "lost-fulfilled"], testCase.id + " public reaction trace");
      } else {
        assert(!description.lostSettled && !description.serviceDetached, testCase.id + " live result");
        same(reactionTrace, ["request-fulfilled"], testCase.id + " live reaction trace");
      }
    }

    var observation = harness.inspect();
    var receipt = operationReceipt(observation, "GPUAdapter.requestDevice");
    var rejection = last(observation.preProviderRejections);
    var terminalId = receipt ? receipt.requestDeviceTerminalId : rejection.terminalId;
    assert(terminalId === testCase.id, testCase.id + " authenticated terminal selected");
    var providerCount = receipt ? receipt.providerAdmission.providerTokenCount : 0;
    var physicalCount = receipt && receipt.physicalOperationKey.physicalSequence ? 1 : 0;
    assert(providerCount === testCase.provider, testCase.id + " provider token count");
    assert(physicalCount === testCase.provider, testCase.id + " physical sequence count");
    if (receipt) {
      same(receipt.requestDeviceTerminal.conditions, testCase.terminal.conditions, testCase.id + " selected from authenticated facts");
      assert(receipt.wrapperAllocatedTargetRef === null, testCase.id + " target remains null");
      if (testCase.result === "reject") {
        assert(receipt.resultHandleRef === null, testCase.id + " rejected result absent");
        assert(Boolean(receipt.failureProgram), testCase.id + " authenticated failure predicate recorded");
        assert(receipt.failureProgram.failureTiming === "promise-rejection", testCase.id + " authenticated receipt failure timing");
      } else {
        assert(receipt.resultHandleRef.objectKind === "GPUDevice", testCase.id + " result handle present");
      }
    } else {
      assertTerminalFacts(rejection.requestDeviceFacts, testCase.terminal, testCase.id + " selected from authenticated facts");
      assert(rejection.operationInstanceId > 0, testCase.id + " promise rejection keeps operation identity");
      assert(rejection.physicalSequence === 0, testCase.id + " pre-provider physical sequence zero");
      assert(rejection.failureTiming === "promise-rejection", testCase.id + " authenticated failure timing");
      assert(Boolean(rejection.failurePredicateId), testCase.id + " authenticated failure predicate");
    }

    var credit = harness.describe(adapter).publicationCredit;
    assert(credit.state !== "leased", testCase.id + " publication lease is terminal");
    assert(credit.retireCount <= 1, testCase.id + " publication credit retires at most once");
    if (credit.state === "available") {
      assert(credit.acquireCount === credit.returnCount, testCase.id + " publication returns balance");
    } else if (credit.acquireCount > 0) {
      assert(credit.acquireCount === credit.returnCount + 1 || credit.acquireCount === credit.returnCount, testCase.id + " retired publication balance");
    }
    if (receipt && receipt.liveDeviceCreditLedger) {
      if (testCase.result === "live") {
        assert(receipt.liveDeviceCreditLedger.state === "committed", testCase.id + " live credits retained");
      } else {
        assert(receipt.liveDeviceCreditLedger.state === "released", testCase.id + " lost credits released");
        assert(receipt.liveDeviceCreditLedger.releaseCount === 1, testCase.id + " lost credits released once");
      }
    }

    var operationInstanceId = receipt
      ? receipt.operationInstanceId
      : rejection.operationInstanceId;
    var ordering = [];
    for (var traceIndex = 0; traceIndex < observation.orderingTrace.length; traceIndex += 1) {
      if (observation.orderingTrace[traceIndex].operationInstanceId === operationInstanceId) {
        ordering.push(observation.orderingTrace[traceIndex]);
      }
    }
    var terminalTraceIndex = indexOfTrace(ordering, "operation-terminal");
    assert(terminalTraceIndex >= 0, testCase.id + " has an operation terminal trace");
    if (testCase.result === "reject") {
      var rejectTraceIndex = indexOfTrace(ordering, "promise-reject");
      assert(rejectTraceIndex > terminalTraceIndex, testCase.id + " raw rejection precedes Promise rejection");
      assert(indexOfTrace(ordering, "device-lost-settle") === -1, testCase.id + " rejection publishes no result loss");
    } else {
      var resolveTraceIndex = indexOfTrace(ordering, "promise-resolve");
      assert(resolveTraceIndex > terminalTraceIndex, testCase.id + " raw completion precedes Promise resolution");
      if (testCase.result === "lost") {
        var lostTraceIndex = indexOfTrace(ordering, "device-lost-settle");
        assert(lostTraceIndex >= 0 && lostTraceIndex < terminalTraceIndex, testCase.id + " device loss settles before requestDevice result");
      } else {
        assert(indexOfTrace(ordering, "device-lost-settle") === -1, testCase.id + " live result has no loss settlement");
      }
    }

    var closeTraceIndex = indexOfTrace(ordering, "account-close");
    if (testCase.closesAccount) {
      assert(observation.lifecycleState.accountClosed, testCase.id + " closes account state");
      assert(closeTraceIndex >= 0 && closeTraceIndex < terminalTraceIndex, testCase.id + " close event precedes public terminal");
      var accountEvents = observation.events.filter(function (event) { return event.kind === "account-close"; });
      var accountRequests = observation.lifecycleRequests.filter(function (request) { return request.kind === "accountClose"; });
      assert(accountEvents.length === 1, testCase.id + " emits one account-close event");
      assert(accountRequests.length === 1, testCase.id + " emits one account-close lifecycle request");
      if (testCase.result === "lost") {
        var lossIndex = indexOfTrace(ordering, "device-lost-settle");
        if (testCase.terminal.lostSettlement.arbiterWinner === "account-close") {
          assert(closeTraceIndex < lossIndex, testCase.id + " account close wins before loss");
        } else if (testCase.terminal.lostSettlement.arbiterWinner === "provider-inability") {
          assert(lossIndex < closeTraceIndex, testCase.id + " provider inability wins before later close");
        }
      }
      harness.closeAccount("duplicate-terminal-close");
      var afterDuplicate = harness.inspect();
      assert(afterDuplicate.events.filter(function (event) { return event.kind === "account-close"; }).length === 1, testCase.id + " duplicate close event is idempotent");
      var futureError = null;
      try {
        await harness.gpu.requestAdapter();
      } catch (error) {
        futureError = error;
      }
      assert(futureError && futureError.name === "SecurityError", testCase.id + " future GPU work rejects SecurityError");
      var futureDeviceError = null;
      try {
        await adapter.requestDevice();
      } catch (error) {
        futureDeviceError = error;
      }
      assert(futureDeviceError && futureDeviceError.name === "SecurityError", testCase.id + " future adapter work rejects SecurityError");
    } else {
      assert(!observation.lifecycleState.accountClosed, testCase.id + " does not synthesize account close");
      assert(closeTraceIndex === -1, testCase.id + " has no account-close trace");
    }

    if (testCase.provider === 1) {
      var providerEntryIndex = indexOfTrace(ordering, "provider-entry");
      var providerCompletionIndex = indexOfTrace(ordering, "provider-completion");
      assert(providerEntryIndex >= 0 && providerEntryIndex < providerCompletionIndex, testCase.id + " provider entry precedes completion");
      assert(providerCompletionIndex >= 0, testCase.id + " has a provider completion trace");
      if (testCase.closesAccount) {
        if (testCase.terminal.conditions.deviceAccountLiveAtProviderCompletion === false) {
          assert(closeTraceIndex < providerCompletionIndex, testCase.id + " close precedes provider completion");
        } else {
          assert(providerCompletionIndex < closeTraceIndex, testCase.id + " provider completion precedes later close");
        }
      }
    } else {
      assert(indexOfTrace(ordering, "provider-entry") === -1, testCase.id + " has no provider-entry trace");
      assert(indexOfTrace(ordering, "provider-completion") === -1, testCase.id + " no-provider terminal has no provider completion");
      var noProviderEntryIndex = indexOfTrace(ordering, "no-provider-entry");
      if (receipt) {
        assert(noProviderEntryIndex >= 0 && noProviderEntryIndex < terminalTraceIndex, testCase.id + " service-local terminal records no-provider branch");
      } else {
        assert(noProviderEntryIndex === -1, testCase.id + " pre-service rejection has no service entry trace");
      }
    }
    return {
      id: testCase.id,
      result: testCase.result,
      errorName: errorName,
      providerTokenCount: providerCount,
      physicalSequenceCount: physicalCount,
      creditState: credit.state,
      creditAcquireCount: credit.acquireCount,
      creditReturnCount: credit.returnCount,
      creditRetireCount: credit.retireCount,
      liveCreditState: receipt && receipt.liveDeviceCreditLedger
        ? receipt.liveDeviceCreditLedger.state
        : "none",
      closesAccount: testCase.closesAccount,
      ordering: ordering.map(function (entry) { return entry.kind; }),
    };
  }

  async function exerciseCanvasOrdinals() {
    var harness = createHarness();
    var adapterOne = await harness.gpu.requestAdapter();
    var adapterTwo = await harness.gpu.requestAdapter();
    var deviceOne = await adapterOne.requestDevice();
    var deviceTwo = await adapterTwo.requestDevice();
    assert(harness.describe(adapterOne).providerGeneration !== harness.describe(adapterTwo).providerGeneration, "fresh adapters have distinct provider generations");
    assert(harness.describe(adapterOne).providerGeneration === harness.describe(deviceOne).providerGeneration, "first device preserves adapter provider generation");
    assert(harness.describe(adapterTwo).providerGeneration === harness.describe(deviceTwo).providerGeneration, "second device preserves adapter provider generation");
    var repeated = await adapterOne.requestDevice();
    assert(harness.describe(repeated).providerGeneration === harness.describe(adapterOne).providerGeneration, "repeat lost device preserves adapter provider generation");

    var context = harness.createCanvasContext();
    var stableReference = JSON.stringify(harness.describe(context).reference);
    context.configure({ device: deviceOne, format: "bgra8unorm" });
    var firstTexture = context.getCurrentTexture();
    assert(firstTexture === context.getCurrentTexture(), "same epoch identity on ordinal path");
    context.configure({ device: deviceTwo, format: "bgra8unorm" });
    context.unconfigure();
    assert(JSON.stringify(harness.describe(context).reference) === stableReference, "canvas ref stable across configure/reconfigure/unconfigure");
    deviceOne.createCommandEncoder({});

    var observation = harness.inspect();
    var adapterReceipts = operationReceipts(observation, "GPU.requestAdapter");
    var requestDeviceReceipts = operationReceipts(observation, "GPUAdapter.requestDevice");
    assert(adapterReceipts.length === 2, "two requestAdapter receipts");
    assert(adapterReceipts[0].authenticatedIngressContext.adapterOperationOrdinal === 0, "first requestAdapter ordinal is zero");
    assert(adapterReceipts[1].authenticatedIngressContext.adapterOperationOrdinal === 0, "second requestAdapter ordinal is zero");
    assert(requestDeviceReceipts.length === 3, "three requestDevice receipts");
    assert(requestDeviceReceipts[0].receiverRef.logicalHandle === harness.describe(adapterOne).reference.logicalHandle, "first requestDevice belongs to adapter one");
    assert(requestDeviceReceipts[0].authenticatedIngressContext.adapterOperationOrdinal === 1, "adapter one first requestDevice ordinal one");
    assert(requestDeviceReceipts[1].receiverRef.logicalHandle === harness.describe(adapterTwo).reference.logicalHandle, "second requestDevice belongs to adapter two");
    assert(requestDeviceReceipts[1].authenticatedIngressContext.adapterOperationOrdinal === 1, "adapter two first requestDevice ordinal one");
    assert(requestDeviceReceipts[2].receiverRef.logicalHandle === harness.describe(adapterOne).reference.logicalHandle, "third requestDevice returns to adapter one");
    assert(requestDeviceReceipts[2].authenticatedIngressContext.adapterOperationOrdinal === 2, "adapter one second requestDevice ordinal two");
    var configureReceipts = [];
    var unconfigureReceipt = null;
    var flushReceipt = null;
    for (var index = 0; index < observation.serviceReceipts.length; index += 1) {
      var receipt = observation.serviceReceipts[index];
      if (receipt.operationName === "GPUCanvasContext.configure") configureReceipts.push(receipt);
      if (receipt.operationName === "GPUCanvasContext.unconfigure") unconfigureReceipt = receipt;
      if (receipt.operationName === "GPUDevice.createCommandEncoder" && receipt.authenticatedIngressContext.logicalDeviceId === harness.describe(deviceOne).deviceId) flushReceipt = receipt;
    }
    assert(configureReceipts.length === 2, "two configure receipts");
    assert(configureReceipts[0].authenticatedIngressContext.deviceIngressOrdinal === 1, "first configure ingress one");
    assert(configureReceipts[1].authenticatedIngressContext.deviceIngressOrdinal === 1, "reconfigure touches only new device ingress one");
    assert(unconfigureReceipt.authenticatedIngressContext.deviceIngressOrdinal === 2, "unconfigure consumes new device ingress two");
    var textureOrdinals = [];
    for (index = 0; index < flushReceipt.sealedLocalTimelinePrefix.length; index += 1) {
      if (flushReceipt.sealedLocalTimelinePrefix[index].operationName === "GPUCanvasContext.getCurrentTexture") {
        textureOrdinals.push(flushReceipt.sealedLocalTimelinePrefix[index].deviceIngressOrdinal);
      }
    }
    same(textureOrdinals, [2, 3], "same-epoch texture calls consume exactly old-device ingress two and three");
    assert(flushReceipt.authenticatedIngressContext.deviceIngressOrdinal === 4, "old device next operation ingress four");
    return {
      firstProviderGeneration: harness.describe(adapterOne).providerGeneration,
      secondProviderGeneration: harness.describe(adapterTwo).providerGeneration,
      oldDeviceTextureOrdinals: textureOrdinals,
      newDeviceOrdinals: [
        configureReceipts[1].authenticatedIngressContext.deviceIngressOrdinal,
        unconfigureReceipt.authenticatedIngressContext.deviceIngressOrdinal,
      ],
      adapterOperationOrdinals: [
        requestDeviceReceipts[0].authenticatedIngressContext.adapterOperationOrdinal,
        requestDeviceReceipts[1].authenticatedIngressContext.adapterOperationOrdinal,
        requestDeviceReceipts[2].authenticatedIngressContext.adapterOperationOrdinal,
      ],
    };
  }

  async function exerciseWebIdlAndInvalidRecording() {
    var harness = createHarness();
    var adapterOne = await harness.gpu.requestAdapter();
    var adapterTwo = await harness.gpu.requestAdapter();
    var deviceOne = await adapterOne.requestDevice();
    var deviceTwo = await adapterTwo.requestDevice();
    var contextOne = harness.createCanvasContext();
    var contextTwo = harness.createCanvasContext();
    contextOne.configure({ device: deviceOne, format: "bgra8unorm" });
    contextTwo.configure({ device: deviceTwo, format: "bgra8unorm" });
    var viewOne = contextOne.getCurrentTexture().createView({});
    var viewTwo = contextTwo.getCurrentTexture().createView({});
    var moduleOne = deviceOne.createShaderModule({ code: "shader" });
    var pipelineOne = deviceOne.createRenderPipeline({ vertex: { module: moduleOne } });
    var encoder = deviceOne.createCommandEncoder({});

    var before = harness.inspect().publicCalls.length;
    expectTypeError(function () {
      encoder.beginRenderPass({ colorAttachments: [{ view: {} }] });
    }, "unbranded attachment WebIDL conversion");
    assert(harness.inspect().publicCalls.length === before, "unbranded attachment allocates no operation");
    var pass = encoder.beginRenderPass({ colorAttachments: [{ view: viewOne }] });

    before = harness.inspect().publicCalls.length;
    expectTypeError(function () { pass.setPipeline({}); }, "unbranded pipeline WebIDL conversion");
    assert(harness.inspect().publicCalls.length === before, "unbranded pipeline allocates no operation");
    pass.setPipeline(pipelineOne);
    pass.draw(3);
    pass.end();
    var validBuffer = encoder.finish({});
    var queue = deviceOne.queue;

    before = harness.inspect().publicCalls.length;
    expectTypeError(function () { queue.submit({}); }, "noniterable submit WebIDL conversion");
    assert(harness.inspect().publicCalls.length === before, "noniterable submit allocates no operation");
    expectTypeError(function () { queue.submit([{}]); }, "unbranded command-buffer WebIDL conversion");
    assert(harness.inspect().publicCalls.length === before, "unbranded command buffer allocates no operation");
    queue.submit([validBuffer]);

    before = harness.inspect().publicCalls.length;
    expectTypeError(function () { deviceOne.pushErrorScope("bogus"); }, "bad error-scope enum WebIDL conversion");
    assert(harness.inspect().publicCalls.length === before, "bad error-scope enum allocates no operation");

    var pipelineBefore = deviceOne.createRenderPipeline({ vertex: { module: moduleOne } });
    before = harness.inspect().publicCalls.length;
    expectTypeError(function () {
      deviceOne.createRenderPipeline({ vertex: { module: moduleOne }, fragment: { module: {} } });
    }, "unbranded fragment-module WebIDL conversion");
    assert(harness.inspect().publicCalls.length === before, "unbranded fragment module allocates no operation");
    var pipelineAfter = deviceOne.createRenderPipeline({ vertex: { module: moduleOne } });
    assert(harness.describe(pipelineAfter).reference.logicalHandle === harness.describe(pipelineBefore).reference.logicalHandle + 1, "unbranded fragment allocates no wrapper");

    var invalidEncoder = deviceOne.createCommandEncoder({});
    before = harness.inspect().publicCalls.length;
    var invalidPass = invalidEncoder.beginRenderPass({ colorAttachments: [{ view: viewTwo }] });
    assert(harness.inspect().publicCalls.length === before + 1, "branded cross-device attachment allocates semantic operation");
    invalidPass.draw(3);
    invalidPass.end();
    var invalidBuffer = invalidEncoder.finish({});
    queue.submit([invalidBuffer]);
    var submitReceipt = operationReceipt(harness.inspect(), "GPUQueue.submit");
    assert(!submitReceipt.providerAdmission.admitted, "invalid recording never reaches provider");
    assert(submitReceipt.physicalOperationKey.physicalSequence === 0, "invalid recording has no physical sequence");
    assert(submitReceipt.untrustedWrapperPayload.argumentBody.commandBufferRecords[0].program.length === 0, "invalid physical program is empty");
    assert(submitReceipt.sealedLocalTimelinePrefix.some(function (record) { return Boolean(record.logicalError); }), "invalid local prefix is sealed before admission");
    return {
      noAllocationChecks: 10,
      invalidProviderTokens: submitReceipt.providerAdmission.providerTokenCount,
      invalidPhysicalSequence: submitReceipt.physicalOperationKey.physicalSequence,
    };
  }

  async function exerciseConditionalProviderBranches() {
    var harness = createHarness();
    var adapter = await harness.gpu.requestAdapter();
    var device = await adapter.requestDevice();
    var context = harness.createCanvasContext();

    context.configure({ device: device, format: "bgra8unorm" });
    context.unconfigure();
    context.unconfigure();

    context.configure({ device: device, format: "bgra8unorm" });
    var texture = context.getCurrentTexture();
    texture.createView({});
    texture.destroy();
    texture.destroy();

    device.pushErrorScope("validation");
    await device.popErrorScope();
    var emptyPopError = null;
    try {
      await device.popErrorScope();
    } catch (error) {
      emptyPopError = error;
    }
    assert(emptyPopError && emptyPopError.name === "OperationError", "empty pop rejects OperationError");

    device.destroy();
    device.destroy();

    var observation = harness.inspect();
    function assertBranch(operationName, index, expectedProvider, label) {
      var receipts = operationReceipts(observation, operationName);
      assert(receipts.length === 2, operationName + " has provider/no-provider pair");
      var receipt = receipts[index];
      assert(receipt.providerAdmission.admitted === expectedProvider, label + " admission branch");
      assert(receipt.providerAdmission.providerTokenCount === (expectedProvider ? 1 : 0), label + " provider token count");
      assert(Boolean(receipt.physicalOperationKey.physicalSequence) === expectedProvider, label + " physical sequence branch");
      return receipt;
    }

    var configuredUnconfigure = assertBranch("GPUCanvasContext.unconfigure", 0, true, "configured unconfigure");
    var unconfiguredUnconfigure = assertBranch("GPUCanvasContext.unconfigure", 1, false, "unconfigured unconfigure");
    var firstTextureDestroy = assertBranch("GPUTexture.destroy", 0, true, "first texture destroy");
    var repeatedTextureDestroy = assertBranch("GPUTexture.destroy", 1, false, "repeated texture destroy");
    var nonemptyPop = assertBranch("GPUDevice.popErrorScope", 0, true, "nonempty popErrorScope");
    var emptyPop = assertBranch("GPUDevice.popErrorScope", 1, false, "empty popErrorScope");
    var firstDeviceDestroy = assertBranch("GPUDevice.destroy", 0, true, "first device destroy");
    var repeatedDeviceDestroy = assertBranch("GPUDevice.destroy", 1, false, "repeated device destroy");
    assert(configuredUnconfigure.authenticatedIngressContext.logicalDeviceId !== 0, "configured unconfigure carries device ingress");
    assert(unconfiguredUnconfigure.authenticatedIngressContext.logicalDeviceId === 0, "unconfigured unconfigure has no device ingress");
    assert(firstTextureDestroy.untrustedWrapperPayload.argumentBody.alreadyDestroyed === false, "first texture destroy branch fact");
    assert(repeatedTextureDestroy.untrustedWrapperPayload.argumentBody.alreadyDestroyed === true, "repeated texture destroy branch fact");
    assert(nonemptyPop.untrustedWrapperPayload.argumentBody.scopeId !== 0, "nonempty pop carries scope");
    assert(emptyPop.untrustedWrapperPayload.argumentBody.scopeId === 0, "empty pop carries zero scope");
    assert(firstDeviceDestroy.untrustedWrapperPayload.argumentBody.alreadyDestroyed === false, "first device destroy branch fact");
    assert(repeatedDeviceDestroy.untrustedWrapperPayload.argumentBody.alreadyDestroyed === true, "repeated device destroy branch fact");

    var lostHarness = createHarness();
    var lostAdapter = await lostHarness.gpu.requestAdapter();
    var lostDevice = await lostAdapter.requestDevice();
    lostDevice.pushErrorScope("validation");
    lostHarness.providerLoss(lostDevice, "conditional provider loss");
    assert((await lostDevice.popErrorScope()) === null, "lost nonempty popErrorScope resolves null");
    assert((await lostDevice.popErrorScope()) === null, "lost empty popErrorScope resolves null");
    lostDevice.destroy();
    var lostObservation = lostHarness.inspect();
    var lostPopReceipts = operationReceipts(
      lostObservation,
      "GPUDevice.popErrorScope",
    );
    assert(lostPopReceipts.length === 2, "lost device has nonempty and empty pop receipts");
    for (var lostPopIndex = 0; lostPopIndex < lostPopReceipts.length; lostPopIndex += 1) {
      assert(!lostPopReceipts[lostPopIndex].providerAdmission.admitted, "lost popErrorScope never admits provider work");
      assert(lostPopReceipts[lostPopIndex].providerAdmission.providerTokenCount === 0, "lost popErrorScope mints no provider token");
      assert(lostPopReceipts[lostPopIndex].physicalOperationKey.physicalSequence === 0, "lost popErrorScope mints no physical sequence");
      assert(lostPopReceipts[lostPopIndex].providerPayload === null, "lost popErrorScope exposes no provider payload");
      assert(lostPopReceipts[lostPopIndex].providerRoutingTerminalId === "lost-device-null", "lost popErrorScope selects authenticated lost terminal");
      assert(lostPopReceipts[lostPopIndex].untrustedWrapperPayload.argumentBody.scopeId === 0, "lost popErrorScope does not inspect the scope stack");
      assert(lostPopReceipts[lostPopIndex].sealedLocalTimelinePrefix.length === 0, "lost popErrorScope does not flush or inspect the device timeline");
    }
    var lostDestroy = operationReceipt(lostObservation, "GPUDevice.destroy");
    assert(!lostDestroy.providerAdmission.admitted, "first destroy after provider loss is no-provider");
    assert(lostDestroy.providerAdmission.providerTokenCount === 0, "destroy after loss mints no provider token");
    assert(lostDestroy.physicalOperationKey.physicalSequence === 0, "destroy after loss mints no physical sequence");
    assert(lostDestroy.providerPayload === null, "destroy after loss exposes no provider payload");
    assert(lostDestroy.providerRoutingTerminalId === "repeat-cleanup-noop", "destroy after loss selects authenticated terminal cleanup no-op");
    assert(lostDestroy.untrustedWrapperPayload.argumentBody.alreadyDestroyed === false, "destroy after provider loss is the first public destroy");
    assert(lostDestroy.untrustedWrapperPayload.argumentBody.alreadyLost === true, "destroy after provider loss carries terminal-loss fact");

    var expiredHarness = createHarness();
    var expiredAdapter = await expiredHarness.gpu.requestAdapter();
    var expiredDevice = await expiredAdapter.requestDevice();
    var expiredContext = expiredHarness.createCanvasContext();
    expiredContext.configure({ device: expiredDevice, format: "bgra8unorm" });
    var expiredTexture = expiredContext.getCurrentTexture();
    expiredTexture.createView({});
    expiredContext.unconfigure();
    expiredTexture.destroy();
    var expiredDestroy = operationReceipt(
      expiredHarness.inspect(),
      "GPUTexture.destroy",
    );
    assert(!expiredDestroy.providerAdmission.admitted, "destroy after unconfigure expiry is no-provider");
    assert(expiredDestroy.providerAdmission.providerTokenCount === 0, "expired texture destroy mints no provider token");
    assert(expiredDestroy.physicalOperationKey.physicalSequence === 0, "expired texture destroy mints no physical sequence");
    assert(expiredDestroy.providerPayload === null, "expired texture destroy exposes no provider payload");
    assert(expiredDestroy.providerRoutingTerminalId === "repeat-cleanup-noop", "expired texture destroy selects authenticated terminal cleanup no-op");
    assert(expiredDestroy.untrustedWrapperPayload.argumentBody.alreadyDestroyed === false, "expired texture destroy is the first public destroy");
    assert(expiredDestroy.untrustedWrapperPayload.argumentBody.expired === true, "expired texture destroy carries expiry fact");
    return {
      providerBranches: 4,
      noProviderBranches: 8,
      postLossNoProviderBranches: 3,
      expiredTextureNoProviderBranches: 1,
      firstProviderSequences: [
        configuredUnconfigure.physicalOperationKey.physicalSequence,
        firstTextureDestroy.physicalOperationKey.physicalSequence,
        nonemptyPop.physicalOperationKey.physicalSequence,
        firstDeviceDestroy.physicalOperationKey.physicalSequence,
      ],
    };
  }

  async function exerciseCrossRealmNoninterference() {
    var first = createHarness({ accountToken: "account-a" });
    var second = createHarness({ accountToken: "account-b" });
    var adapterA = await first.gpu.requestAdapter();
    var adapterB = await second.gpu.requestAdapter();
    var deviceA = await adapterA.requestDevice();
    var deviceB = await adapterB.requestDevice();
    deviceB.pushErrorScope("validation");
    var contextA = first.createCanvasContext();
    var contextB = second.createCanvasContext();
    var referenceA = JSON.stringify(first.describe(contextA).reference);
    var referenceB = JSON.stringify(second.describe(contextB).reference);

    contextA.configure({ device: deviceB, format: "bgra8unorm" });
    var crossA = operationReceipt(first.inspect(), "GPUCanvasContext.configure");
    assert(crossA.operationInstanceId > 0, "cross-realm configure has semantic operation identity");
    assert(crossA.authenticatedIngressContext.logicalDeviceId === 0, "foreign device is not authenticated ingress");
    assert(crossA.authenticatedIngressContext.deviceIngressOrdinal === 0, "foreign ingress ordinal untouched");
    assert(crossA.authenticatedIngressContext.capturedScopeId === 0, "foreign scope is not captured");
    assert(crossA.physicalOperationKey.physicalSequence === 0, "cross-realm configure is not physical");
    contextB.configure({ device: deviceB, format: "bgra8unorm" });
    var ownB = operationReceipt(second.inspect(), "GPUCanvasContext.configure");
    assert(ownB.authenticatedIngressContext.deviceIngressOrdinal === 2, "foreign attempt did not consume device-B ingress");
    assert(ownB.authenticatedIngressContext.capturedScopeId === 1, "device-B own scope remains intact");

    contextB.configure({ device: deviceA, format: "bgra8unorm" });
    var crossB = operationReceipt(second.inspect(), "GPUCanvasContext.configure");
    assert(crossB.authenticatedIngressContext.logicalDeviceId === 0, "reverse foreign ingress absent");
    contextA.configure({ device: deviceA, format: "bgra8unorm" });
    var ownA = operationReceipt(first.inspect(), "GPUCanvasContext.configure");
    assert(ownA.authenticatedIngressContext.deviceIngressOrdinal === 1, "reverse foreign attempt did not consume device-A ingress");

    var borrowed = Object.getPrototypeOf(contextA).configure;
    var beforeSecond = second.inspect().publicCalls.length;
    expectTypeError(function () {
      borrowed.call(contextB, { device: deviceB, format: "bgra8unorm" });
    }, "cross-realm borrowed method");
    assert(second.inspect().publicCalls.length === beforeSecond, "borrowed method has no foreign side effect");
    assert(JSON.stringify(first.describe(contextA).reference) === referenceA, "context-A ref stable");
    assert(JSON.stringify(second.describe(contextB).reference) === referenceB, "context-B ref stable");
    return {
      forwardIngress: ownB.authenticatedIngressContext.deviceIngressOrdinal,
      reverseIngress: ownA.authenticatedIngressContext.deviceIngressOrdinal,
      crossPhysicalSequences: [
        crossA.physicalOperationKey.physicalSequence,
        crossB.physicalOperationKey.physicalSequence,
      ],
    };
  }

  async function exerciseNullableAdapter() {
    var harness = createHarness({ requestAdapterUnavailable: true });
    var result = await harness.gpu.requestAdapter({ powerPreference: "low-power" });
    assert(result === null, "requestAdapter nullable branch");
    var receipt = operationReceipt(harness.inspect(), "GPU.requestAdapter");
    assert(receipt.resultHandleRef === null, "nullable adapter result handle absent");
    assert(receipt.receiverRef === null, "nullable adapter singleton receiver absent");
    assert(receipt.authenticatedIngressContext.adapterOperationOrdinal === 0, "requestAdapter ordinal remains zero");
    assert(receipt.authenticatedIngressContext.providerGeneration === 1, "nullable adapter reserves provider generation");
    assert(receipt.physicalOperationKey.physicalSequence > 0, "nullable adapter still completes provider request");
    return {
      providerGeneration: receipt.authenticatedIngressContext.providerGeneration,
      physicalSequence: receipt.physicalOperationKey.physicalSequence,
    };
  }

  var allOperations = await exerciseAllOperations();
  var catalog = createHarness().inspect();
  assert(catalog.fixtureDisposition === "test-only-no-runtime-install-no-support-claim", "fixture remains explicitly test-only with no support claim");
  assert(catalog.requestDeviceTerminals.length === 17, "authenticated terminal catalog has 17 rows");
  same(
    Object.keys(catalog.requestDeviceProviderDescriptor).sort(),
    [
      "capabilityProjectionPredicate",
      "policy",
      "projectionRule",
      "providerReadyPredicate",
    ],
    "requestDevice provider descriptor remains exactly outer-derivable",
  );
  assert(
    catalog.requestDeviceProviderDescriptor.policy ===
      "generated-logical-limits-plus-versioned-service-internal-requirements-only",
    "requestDevice provider descriptor excludes raw public fields by policy",
  );
  assert(
    catalog.requestDeviceProviderDescriptor.providerReadyPredicate.relation.indexOf(
      "raw request descriptor is unavailable at this boundary",
    ) !== -1,
    "provider-ready predicate authenticates raw descriptor exclusion",
  );
  assert(catalog.providerRoutingPrograms.length === 12, "authenticated conditional provider-routing catalog has 12 rows");
  same(
    catalog.providerRoutingPrograms.map(function (program) {
      return program.operationId;
    }),
    [
      "GPU.requestAdapter",
      "GPUAdapter.requestDevice",
      "GPUCanvasContext.configure",
      "GPUCanvasContext.unconfigure",
      "GPUDevice.createCommandEncoder",
      "GPUDevice.createRenderPipeline",
      "GPUDevice.createShaderModule",
      "GPUDevice.destroy",
      "GPUDevice.popErrorScope",
      "GPUQueue.submit",
      "GPUTexture.createView",
      "GPUTexture.destroy",
    ],
    "conditional provider-routing catalog preserves outer authority order",
  );
  var terminalCases = [];
  for (var catalogIndex = 0; catalogIndex < catalog.requestDeviceTerminals.length; catalogIndex += 1) {
    terminalCases.push(
      terminalCaseFromFacts(
        catalog.requestDeviceTerminals[catalogIndex],
        catalog.requestDeviceFailureProgram,
      ),
    );
  }
  var terminals = [];
  for (var terminalIndex = 0; terminalIndex < terminalCases.length; terminalIndex += 1) {
    terminals.push(await exerciseTerminal(terminalCases[terminalIndex]));
  }
  assert(terminals.length === 17, "all requestDevice terminals covered");
  var canvas = await exerciseCanvasOrdinals();
  var webIdl = await exerciseWebIdlAndInvalidRecording();
  var conditionalProviderBranches = await exerciseConditionalProviderBranches();
  var crossRealm = await exerciseCrossRealmNoninterference();
  var nullableAdapter = await exerciseNullableAdapter();

  return {
    schema: "ibex/webgpu-test-wrapper-corpus-result/1",
    assertionCount: assertionCount,
    operationCount: allOperations.operationCount,
    terminalCount: terminals.length,
    allOperations: allOperations,
    terminals: terminals,
    canvas: canvas,
    webIdl: webIdl,
    conditionalProviderBranches: conditionalProviderBranches,
    crossRealm: crossRealm,
    nullableAdapter: nullableAdapter,
  };
}
