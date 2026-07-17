/**
 * Engine-neutral behavioral corpus for the generated test-only WebGPU wrapper.
 * The function is serialized into a standalone script and run byte-for-byte on
 * Node 24.13.1 and the real built Ibex/Hermes evaluator.
 *
 * @ref LLP 0002#gpu-bridge-seam
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
      requiredFeatures: ["timestamp-query"],
      requiredLimits: {
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
    assert(deviceReceipt.authenticatedIngressContext.logicalDeviceId === 0, "requestDevice ingress device absent");
    assert(deviceReceipt.wrapperAllocatedTargetRef === null, "requestDevice has no wrapper target");
    assert(deviceReceipt.resultHandleRef.objectKind === "GPUDevice", "requestDevice result device");
    assert(deviceReceipt.physicalOperationKey.logicalDeviceId === harness.describe(device).deviceId, "physical result device identity");

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
    return {
      operationCount: observedNames.length,
      publicCallCount: observation.publicCalls.length,
      serviceReceiptCount: observation.serviceReceipts.length,
      eventCount: observation.events.length,
    };
  }

  var terminalCases = [
    { id: "webidl-rejection", mode: "cyclic", error: "TypeError", provider: 0, result: "reject" },
    { id: "unsupported-required-features", mode: "unsupported", error: "TypeError", provider: 0, result: "reject" },
    { id: "invalid-adapter-request", mode: "limit", error: "OperationError", provider: 0, result: "reject" },
    { id: "live-admission-rejection", closeBefore: true, error: "SecurityError", provider: 0, result: "reject" },
    { id: "expiry-lost-selection-close-rejection", expired: true, facts: { deviceExpiryResultCommitLive: false }, error: "OperationError", provider: 0, result: "reject" },
    { id: "expired-adapter-lost-device", expired: true, facts: {}, provider: 0, result: "lost" },
    { id: "pre-capacity-close-rejection", facts: { deviceExpiryResultCommitLive: false }, error: "OperationError", provider: 0, result: "reject" },
    { id: "capacity-lost-selection-close-rejection", facts: { deviceReservationCapacityAvailable: false, deviceCapacityResultCommitLive: false }, error: "OperationError", provider: 0, result: "reject" },
    { id: "live-device-capacity-unavailable", facts: { deviceReservationCapacityAvailable: false, deviceCapacityResultCommitLive: true }, provider: 0, result: "lost" },
    { id: "post-capacity-close-rejection", facts: { deviceReservationCapacityAvailable: true, deviceCapacityResultCommitLive: false }, error: "OperationError", provider: 0, result: "reject" },
    { id: "live-device-commit-close-rejection", facts: { deviceReservationCapacityAvailable: true, deviceCapacityResultCommitLive: true, deviceReservationCommitLive: false }, error: "OperationError", provider: 0, result: "reject" },
    { id: "provider-unfulfilled-provider-inability-won", facts: { providerFulfilled: false, deviceAccountLiveAtProviderCompletion: true, deviceAccountLiveAtSettlementCommit: true, providerInabilityWonLossRace: true }, provider: 1, result: "lost" },
    { id: "provider-unfulfilled-provider-inability-won-before-close", facts: { providerFulfilled: false, deviceAccountLiveAtProviderCompletion: true, deviceAccountLiveAtSettlementCommit: false, providerInabilityWonLossRace: true }, provider: 1, result: "lost" },
    { id: "provider-unfulfilled-account-close-won", facts: { providerFulfilled: false, deviceAccountLiveAtProviderCompletion: false, deviceAccountLiveAtSettlementCommit: false, providerInabilityWonLossRace: false }, provider: 1, result: "lost" },
    { id: "lost-device-returned-close-before-provider-completion", facts: { providerFulfilled: true, deviceAccountLiveAtProviderCompletion: false }, provider: 1, result: "lost" },
    { id: "lost-device-returned-close-after-provider-completion", facts: { providerFulfilled: true, deviceAccountLiveAtProviderCompletion: true, deviceAccountLiveAtSettlementCommit: false }, provider: 1, result: "lost" },
    { id: "live-device-returned", facts: {}, provider: 1, result: "live" },
  ];

  async function exerciseTerminal(testCase) {
    var harness = createHarness();
    var adapter = await harness.gpu.requestAdapter();
    if (testCase.expired) {
      var prime = await adapter.requestDevice();
      prime.destroy();
      assert(harness.describe(adapter).expired, testCase.id + " primed expired adapter");
    }
    if (testCase.closeBefore) {
      harness.closeAccount("terminal-admission-close");
      harness.closeAccount("duplicate-close-must-be-idempotent");
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
    try {
      result = await adapter.requestDevice(descriptor);
    } catch (error) {
      errorName = error.name;
    }
    if (testCase.result === "reject") {
      assert(result === null, testCase.id + " rejects without result");
      assert(
        errorName === testCase.error,
        testCase.id + " rejection class expected " + testCase.error + " got " + errorName,
      );
    } else {
      assert(errorName === "" && result !== null, testCase.id + " resolves a device");
      var lostPromiseOne = result.lost;
      var lostPromiseTwo = result.lost;
      assert(lostPromiseOne === lostPromiseTwo, testCase.id + " stable lost promise");
      var description = harness.describe(result);
      if (testCase.result === "lost") {
        assert(description.lostSettled && description.serviceDetached, testCase.id + " already-lost detached result");
        var lostInfo = await lostPromiseOne;
        assert(lostInfo.reason === "unknown", testCase.id + " lost reason");
      } else {
        assert(!description.lostSettled && !description.serviceDetached, testCase.id + " live result");
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
      assert(receipt.wrapperAllocatedTargetRef === null, testCase.id + " target remains null");
      if (testCase.result === "reject") {
        assert(receipt.resultHandleRef === null, testCase.id + " rejected result absent");
        assert(Boolean(receipt.failureProgram), testCase.id + " authenticated failure predicate recorded");
        assert(receipt.failureProgram.failureTiming === "promise-rejection", testCase.id + " authenticated receipt failure timing");
      } else {
        assert(receipt.resultHandleRef.objectKind === "GPUDevice", testCase.id + " result handle present");
      }
    } else {
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
    var errorName = "";
    try { encoder.beginRenderPass({ colorAttachments: [{ view: {} }] }); } catch (error) { errorName = error.name; }
    assert(errorName === "TypeError", "unbranded attachment is WebIDL TypeError");
    assert(harness.inspect().publicCalls.length === before, "unbranded attachment allocates no operation");
    var pass = encoder.beginRenderPass({ colorAttachments: [{ view: viewOne }] });

    before = harness.inspect().publicCalls.length;
    errorName = "";
    try { pass.setPipeline({}); } catch (error) { errorName = error.name; }
    assert(errorName === "TypeError", "unbranded pipeline is WebIDL TypeError");
    assert(harness.inspect().publicCalls.length === before, "unbranded pipeline allocates no operation");
    pass.setPipeline(pipelineOne);
    pass.draw(3);
    pass.end();
    var validBuffer = encoder.finish({});
    var queue = deviceOne.queue;

    before = harness.inspect().publicCalls.length;
    errorName = "";
    try { queue.submit({}); } catch (error) { errorName = error.name; }
    assert(errorName === "TypeError", "noniterable submit is WebIDL TypeError");
    assert(harness.inspect().publicCalls.length === before, "noniterable submit allocates no operation");
    errorName = "";
    try { queue.submit([{}]); } catch (error) { errorName = error.name; }
    assert(errorName === "TypeError", "unbranded command buffer is WebIDL TypeError");
    assert(harness.inspect().publicCalls.length === before, "unbranded command buffer allocates no operation");
    queue.submit([validBuffer]);

    before = harness.inspect().publicCalls.length;
    errorName = "";
    try { deviceOne.pushErrorScope("bogus"); } catch (error) { errorName = error.name; }
    assert(errorName === "TypeError", "bad error-scope enum is WebIDL TypeError");
    assert(harness.inspect().publicCalls.length === before, "bad error-scope enum allocates no operation");

    var pipelineBefore = deviceOne.createRenderPipeline({ vertex: { module: moduleOne } });
    before = harness.inspect().publicCalls.length;
    errorName = "";
    try {
      deviceOne.createRenderPipeline({ vertex: { module: moduleOne }, fragment: { module: {} } });
    } catch (error) { errorName = error.name; }
    assert(errorName === "TypeError", "unbranded fragment module is WebIDL TypeError");
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
    var errorName = "";
    try { borrowed.call(contextB, { device: deviceB, format: "bgra8unorm" }); } catch (error) { errorName = error.name; }
    assert(errorName === "TypeError", "cross-realm borrowed method rejects");
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
    assert(receipt.authenticatedIngressContext.providerGeneration === 1, "nullable adapter reserves provider generation");
    assert(receipt.physicalOperationKey.physicalSequence > 0, "nullable adapter still completes provider request");
    return {
      providerGeneration: receipt.authenticatedIngressContext.providerGeneration,
      physicalSequence: receipt.physicalOperationKey.physicalSequence,
    };
  }

  var allOperations = await exerciseAllOperations();
  var terminals = [];
  for (var terminalIndex = 0; terminalIndex < terminalCases.length; terminalIndex += 1) {
    terminals.push(await exerciseTerminal(terminalCases[terminalIndex]));
  }
  assert(terminals.length === 17, "all requestDevice terminals covered");
  var canvas = await exerciseCanvasOrdinals();
  var webIdl = await exerciseWebIdlAndInvalidRecording();
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
    crossRealm: crossRealm,
    nullableAdapter: nullableAdapter,
  };
}
