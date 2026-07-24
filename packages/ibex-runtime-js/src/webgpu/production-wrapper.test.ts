import { describe, expect, test } from 'bun:test';

import { AbortController } from '../abort';
import {
  isDetachedArrayBuffer,
  markDetachedArrayBuffer,
} from '../arraybuffer-detach';
import { structuredClone as ibexStructuredClone } from '../clone/structuredClone';
import { Blob } from '../blob/Blob';
import { Event } from '../events/Event';
import { EventTarget } from '../events/EventTarget';
import type {
  NativeGpuBridgeV2,
  NativeGpuCallMetadataV2,
  NativeGpuEventV2,
  NativeGpuPresentationAuthorityMetadataV2,
  NativeGpuPresentationAuthorityV2,
} from './native-bridge';
import type { ProductionGpuDecodedImageRequestV1 } from './private-image-bitmap';
import type {
  ExecutableWebGpuCodecBundle,
  ProductionGpuBufferLifecycleEncoding,
  ProductionGpuCanvasServiceEncoding,
  ProductionGpuServiceEncodingInput,
  ProductionGpuWrapperKind,
} from './production-codecs';
import {
  WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION,
  WEBGPU_EXECUTABLE_CODEC_MANIFEST,
  WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT,
} from './production-codecs.generated';
import { WEBGPU_PRODUCTION_PLAN } from './production-plan.generated';
import {
  createProductionWebGpuPrivateBinding,
  describeProductionWebGpuWorkloadStaging,
  incrementCanonicalU64Decimal,
  installProductionWebGpu,
} from './production-wrapper';

const CANVAS_AUTHORITY = Object.freeze({
  attachmentGeneration: '31',
  contextGeneration: '37',
  targetAuthorityDigest: 'ab'.repeat(32),
  surfaceAccountToken: '41',
  surfaceAccountGeneration: '43',
});
const U64_MAX = '18446744073709551615';
const U64_MAX_MINUS_ONE = '18446744073709551614';
const U64_MAX_MINUS_TWO = '18446744073709551613';

const EXPECTED_STAGED_LOCAL_RECORD_IDENTITIES = Object.freeze({
  'GPUCommandEncoder.beginComputePass': Object.freeze({
    localRecordId: 1059087543,
    recordIdentitySha256:
      'b764203ffd4b4acc806bb6345f8be90aced91d4ea1cf076657f84e18fcc209dd',
  }),
  'GPUCommandEncoder.clearBuffer': Object.freeze({
    localRecordId: 2252941047,
    recordIdentitySha256:
      'f72649863586f7b6e8a9e05d96f7f1ac9af3a78cdd4ff75f005f0f8246d9db41',
  }),
  'GPUCommandEncoder.copyBufferToBuffer': Object.freeze({
    localRecordId: 140509420,
    recordIdentitySha256:
      'ec0060085c40946da4d8252a859b048c59eb9803013f1ec825e5bcbe87d0d5df',
  }),
  'GPUCommandEncoder.copyTextureToTexture': Object.freeze({
    localRecordId: 921211603,
    recordIdentitySha256:
      'd392e836c6e02ea2eea66cc84e8ccf3b2394f2020e441d1bf263928aadb0a5fb',
  }),
  'GPUCommandEncoder.resolveQuerySet': Object.freeze({
    localRecordId: 3627060274,
    recordIdentitySha256:
      '328c30d8f31272fcb2bbc3b0322f6fafa2b9ba7b790a764e2f19a12524a85006',
  }),
  'GPUComputePassEncoder.dispatchWorkgroups': Object.freeze({
    localRecordId: 1258425661,
    recordIdentitySha256:
      '3d0d024b3eace3d62076d1e26e9a2db303f2efdf6731a91d2792620df102a4e1',
  }),
  'GPUComputePassEncoder.end': Object.freeze({
    localRecordId: 458012391,
    recordIdentitySha256:
      'e7b64c1bebc3da3fa8df936f74a73ccfdc45d81c8c56681882a7352b107145a8',
  }),
  'GPUComputePassEncoder.setBindGroup': Object.freeze({
    localRecordId: 292725259,
    recordIdentitySha256:
      '0ba27211e9da9207afa1d5d597b223076372056cbad2e360e50d737e8ca98977',
  }),
  'GPUComputePassEncoder.setPipeline': Object.freeze({
    localRecordId: 1263398999,
    recordIdentitySha256:
      '57f04d4bf6dcdddfb654c0847f204a0032ee60d21ac1365a6cc1633c0602152b',
  }),
  'GPURenderPassEncoder.drawIndexed': Object.freeze({
    localRecordId: 503426110,
    recordIdentitySha256:
      '3eac011e17196ecf71481d542fa15245d5656ed02e434ead8dc578ca9f7255f0',
  }),
  'GPURenderPassEncoder.drawIndirect': Object.freeze({
    localRecordId: 403203469,
    recordIdentitySha256:
      '8d650818bd0c8412c5c61028aa3f562e2acf2016dea3bf238168c3e64e6a91ee',
  }),
  'GPURenderPassEncoder.setBindGroup': Object.freeze({
    localRecordId: 1289149290,
    recordIdentitySha256:
      '6adbd64cfdd954e7c505494c6f21f4c003ec0d483c629e618792bc94135497a5',
  }),
  'GPURenderPassEncoder.setIndexBuffer': Object.freeze({
    localRecordId: 1097249753,
    recordIdentitySha256:
      'd9b36641df046d8eb15d188f10af8b4cd93164d961252f5d057d7d704c2223ac',
  }),
  'GPURenderPassEncoder.setVertexBuffer': Object.freeze({
    localRecordId: 3247535054,
    recordIdentitySha256:
      'ce7391c12a7841f14f9d56c0ffe0e7c5a942b023d71644c19842acd7fbc50183',
  }),
});
const PROMOTED_LOCAL_RECORD_OPERATION_NAMES = new Set(
  Object.keys(EXPECTED_STAGED_LOCAL_RECORD_IDENTITIES),
);

type OperationResultEvent = Extract<NativeGpuEventV2, { kind: 1 }>;

interface RecordedSubmission {
  readonly operationId: number;
  readonly wantsPromise: boolean;
  readonly metadata: NativeGpuCallMetadataV2;
  readonly payload: ArrayBuffer | ArrayBufferView;
}

interface FakeMappedRangeAliasMint {
  readonly source: ArrayBuffer;
  readonly byteOffset: number;
  readonly byteLength: number;
  readonly alias: ArrayBuffer;
}

interface RecordedPresentationAuthorityCall {
  readonly operationId: number;
  readonly metadata: NativeGpuPresentationAuthorityMetadataV2;
}

interface RecordedPresentationAuthorityRecheck
  extends RecordedPresentationAuthorityCall {
  readonly retained: NativeGpuPresentationAuthorityV2;
}

type PromiseResultHook = (
  event: OperationResultEvent,
) => NativeGpuEventV2 | Promise<NativeGpuEventV2>;

function createFakeBridge(): NativeGpuBridgeV2 & {
  readonly submissions: RecordedSubmission[];
  readonly cancellations: ReadonlyArray<Readonly<{
    operationInstanceId: string;
    promiseId: string;
  }>>;
  readonly mappedRangeAliasMints: FakeMappedRangeAliasMint[];
  readonly mappedRangeDetachAttempts: ArrayBuffer[];
  readonly presentationAuthorityCaptures: RecordedPresentationAuthorityCall[];
  readonly presentationAuthorityRechecks: RecordedPresentationAuthorityRecheck[];
  readonly presentationAuthorityRetirements: NativeGpuPresentationAuthorityV2[];
  emit(event: NativeGpuEventV2): void;
  setSubmitHook(
    hook: ((operationId: number, metadata: NativeGpuCallMetadataV2) => number | void) |
      undefined,
  ): void;
  setPromiseResultHook(hook: PromiseResultHook | undefined): void;
  setDetachMappedRangeHook(
    hook: ((buffer: ArrayBuffer) => boolean | void) | undefined,
  ): void;
  setCapturePresentationAuthorityHook(
    hook: ((
      operationId: number,
      metadata: NativeGpuPresentationAuthorityMetadataV2,
    ) => NativeGpuPresentationAuthorityV2 | null | undefined) | undefined,
  ): void;
  setRecheckPresentationAuthorityHook(
    hook: ((
      operationId: number,
      metadata: NativeGpuPresentationAuthorityMetadataV2,
      retained: NativeGpuPresentationAuthorityV2,
    ) => boolean | undefined) | undefined,
  ): void;
  setRetirePresentationAuthorityHook(
    hook: ((
      retained: NativeGpuPresentationAuthorityV2,
    ) => 1 | 0 | -1 | -2 | undefined) | undefined,
  ): void;
} {
  let sink: ((event: NativeGpuEventV2) => void) | undefined;
  let submitHook:
    ((operationId: number, metadata: NativeGpuCallMetadataV2) => number | void) |
    undefined;
  let promiseResultHook: PromiseResultHook | undefined;
  let detachMappedRangeHook:
    ((buffer: ArrayBuffer) => boolean | void) | undefined;
  let capturePresentationAuthorityHook:
    | ((
      operationId: number,
      metadata: NativeGpuPresentationAuthorityMetadataV2,
    ) => NativeGpuPresentationAuthorityV2 | null | undefined)
    | undefined;
  let recheckPresentationAuthorityHook:
    | ((
      operationId: number,
      metadata: NativeGpuPresentationAuthorityMetadataV2,
      retained: NativeGpuPresentationAuthorityV2,
    ) => boolean | undefined)
    | undefined;
  let retirePresentationAuthorityHook:
    | ((
      retained: NativeGpuPresentationAuthorityV2,
    ) => 1 | 0 | -1 | -2 | undefined)
    | undefined;
  let nextOperation = 1;
  let nextPromise = 1;
  let nextPresentationSession = 1_001;
  const submissions: RecordedSubmission[] = [];
  const cancellations: Array<Readonly<{
    operationInstanceId: string;
    promiseId: string;
  }>> = [];
  const mappedRangeAliasMints: FakeMappedRangeAliasMint[] = [];
  const mappedRangeDetachAttempts: ArrayBuffer[] = [];
  const presentationAuthorityCaptures: RecordedPresentationAuthorityCall[] = [];
  const presentationAuthorityRechecks: RecordedPresentationAuthorityRecheck[] = [];
  const presentationAuthorityRetirements: NativeGpuPresentationAuthorityV2[] = [];
  const defaultAuthorityContextDigest = new Uint8Array(32).fill(9);
  const mappedRangeAliases = new Map<ArrayBuffer, Readonly<{
    source: ArrayBuffer;
    byteOffset: number;
    initial: Uint8Array;
  }>>();
  const bridge: NativeGpuBridgeV2 & {
    readonly submissions: RecordedSubmission[];
    readonly cancellations: typeof cancellations;
    readonly mappedRangeAliasMints: FakeMappedRangeAliasMint[];
    readonly mappedRangeDetachAttempts: ArrayBuffer[];
    readonly presentationAuthorityCaptures: RecordedPresentationAuthorityCall[];
    readonly presentationAuthorityRechecks: RecordedPresentationAuthorityRecheck[];
    readonly presentationAuthorityRetirements: NativeGpuPresentationAuthorityV2[];
    emit(event: NativeGpuEventV2): void;
    setSubmitHook(
      hook: ((operationId: number, metadata: NativeGpuCallMetadataV2) => number | void) |
        undefined,
    ): void;
    setPromiseResultHook(hook: PromiseResultHook | undefined): void;
    setDetachMappedRangeHook(
      hook: ((buffer: ArrayBuffer) => boolean | void) | undefined,
    ): void;
    setCapturePresentationAuthorityHook(
      hook: ((
        operationId: number,
        metadata: NativeGpuPresentationAuthorityMetadataV2,
      ) => NativeGpuPresentationAuthorityV2 | null | undefined) | undefined,
    ): void;
    setRecheckPresentationAuthorityHook(
      hook: ((
        operationId: number,
        metadata: NativeGpuPresentationAuthorityMetadataV2,
        retained: NativeGpuPresentationAuthorityV2,
      ) => boolean | undefined) | undefined,
    ): void;
    setRetirePresentationAuthorityHook(
      hook: ((
        retained: NativeGpuPresentationAuthorityV2,
      ) => 1 | 0 | -1 | -2 | undefined) | undefined,
    ): void;
  } = {
    abiVersion: 0x0002_0000,
    runtimeAddress: '11',
    runtimeNonce: '13',
    realmId: '17',
    realmGeneration: '19',
    rootAccountId: '23',
    rootAccountGeneration: '29',
    rootAuthorityDigest: new Uint8Array(32).fill(7),
    submissions,
    cancellations,
    mappedRangeAliasMints,
    mappedRangeDetachAttempts,
    presentationAuthorityCaptures,
    presentationAuthorityRechecks,
    presentationAuthorityRetirements,
    submit(operationId, wantsPromise, metadata, payload) {
      submissions.push({ operationId, wantsPromise, metadata, payload });
      const submissionStatus = submitHook?.(operationId, metadata) ?? 0;
      const operationInstanceId = String(nextOperation++);
      const promiseId = wantsPromise ? String(nextPromise++) : '0';
      const emitDefaultSealedTerminals = () => {
        for (const authority of metadata.sealedOperations) {
          sink?.({
            kind: 1,
            runtimeAddress: bridge.runtimeAddress,
            runtimeNonce: bridge.runtimeNonce,
            topologyId: 1,
            operationId: authority.operationId,
            operationInstanceId: authority.operationInstanceId,
            promiseId: '0',
            providerAdmission: 0,
            physicalSequence: '0',
            capturedScopeId: authority.capturedScopeId,
            realmId: bridge.realmId,
            realmGeneration: bridge.realmGeneration,
            accountId: bridge.rootAccountId,
            accountGeneration: bridge.rootAccountGeneration,
            accountAuthorityDigest: bridge.rootAuthorityDigest,
            logicalDeviceId: metadata.logicalDeviceId,
            logicalDeviceGeneration: metadata.logicalDeviceGeneration,
            providerGeneration: metadata.providerGeneration,
            ingressLogicalDeviceId: metadata.logicalDeviceId,
            ingressLogicalDeviceGeneration: metadata.logicalDeviceGeneration,
            ingressProviderGeneration: metadata.providerGeneration,
            deviceTransition: 0,
            operationProviderGeneration: metadata.operationProviderGeneration,
            authorityContextDigest:
              authority.authorityContextDigest ??
                defaultAuthorityContextDigest,
            adapterOrdinal: '0',
            deviceIngressOrdinal: authority.deviceIngressOrdinal,
            queueIngressOrdinal: '0',
            receiverKind: authority.receiver.kind,
            receiverFlags: 0,
            receiverId: authority.receiver.id,
            receiverGeneration: authority.receiver.generation,
            targetKind: authority.target?.kind ?? 0,
            targetFlags: 0,
            targetId: authority.target?.id ?? '0',
            targetGeneration: authority.target?.generation ?? '0',
            resultKind: 0,
            status: 0,
            detachedAlreadyLost: false,
            payload: new Uint8Array(),
          });
        }
      };
      const receipt = wantsPromise && submissionStatus === 0
        ? Promise.resolve().then(async () => {
          emitDefaultSealedTerminals();
          const defaultEvent: OperationResultEvent = {
            kind: 1,
            runtimeAddress: bridge.runtimeAddress,
            runtimeNonce: bridge.runtimeNonce,
            topologyId: 1,
            operationId,
            operationInstanceId,
            promiseId,
            providerAdmission: 1,
            physicalSequence: operationInstanceId,
            capturedScopeId: metadata.capturedScopeId,
            realmId: bridge.realmId,
            realmGeneration: bridge.realmGeneration,
            accountId: bridge.rootAccountId,
            accountGeneration: bridge.rootAccountGeneration,
            accountAuthorityDigest: bridge.rootAuthorityDigest,
            logicalDeviceId: metadata.logicalDeviceId,
            logicalDeviceGeneration: metadata.logicalDeviceGeneration,
            providerGeneration: metadata.providerGeneration,
            ingressLogicalDeviceId: metadata.logicalDeviceId,
            ingressLogicalDeviceGeneration: metadata.logicalDeviceGeneration,
            ingressProviderGeneration: metadata.providerGeneration,
            deviceTransition: 0,
            operationProviderGeneration: metadata.operationProviderGeneration,
            authorityContextDigest: defaultAuthorityContextDigest,
            adapterOrdinal: metadata.adapterOrdinal,
            deviceIngressOrdinal: metadata.deviceIngressOrdinal,
            queueIngressOrdinal: metadata.queueIngressOrdinal,
            receiverKind: metadata.receiverKind,
            receiverFlags: 0,
            receiverId: metadata.receiverId,
            receiverGeneration: metadata.receiverGeneration,
            targetKind: metadata.targetKind,
            targetFlags: 0,
            targetId: metadata.targetId,
            targetGeneration: metadata.targetGeneration,
            resultKind: 1,
            status: 0,
            detachedAlreadyLost: false,
            payload: new Uint8Array([1]),
          };
          const event = promiseResultHook
            ? await promiseResultHook(defaultEvent)
            : defaultEvent;
          sink?.(event);
          return Object.freeze({ operationInstanceId, promiseId });
        })
        : wantsPromise
        ? Promise.reject(new Error('fake semantic-service submission rejection'))
        : undefined;
      if (!wantsPromise && submissionStatus === 0) {
        Promise.resolve().then(() => {
          emitDefaultSealedTerminals();
          sink?.({
            kind: 1,
            runtimeAddress: bridge.runtimeAddress,
            runtimeNonce: bridge.runtimeNonce,
            topologyId: 1,
            operationId,
            operationInstanceId,
            promiseId: '0',
            providerAdmission: 1,
            physicalSequence: operationInstanceId,
            capturedScopeId: metadata.capturedScopeId,
            realmId: bridge.realmId,
            realmGeneration: bridge.realmGeneration,
            accountId: bridge.rootAccountId,
            accountGeneration: bridge.rootAccountGeneration,
            accountAuthorityDigest: bridge.rootAuthorityDigest,
            logicalDeviceId: metadata.logicalDeviceId,
            logicalDeviceGeneration: metadata.logicalDeviceGeneration,
            providerGeneration: metadata.providerGeneration,
            ingressLogicalDeviceId: metadata.logicalDeviceId,
            ingressLogicalDeviceGeneration: metadata.logicalDeviceGeneration,
            ingressProviderGeneration: metadata.providerGeneration,
            deviceTransition: 0,
            operationProviderGeneration: metadata.operationProviderGeneration,
            authorityContextDigest: defaultAuthorityContextDigest,
            adapterOrdinal: metadata.adapterOrdinal,
            deviceIngressOrdinal: metadata.deviceIngressOrdinal,
            queueIngressOrdinal: metadata.queueIngressOrdinal,
            receiverKind: metadata.receiverKind,
            receiverFlags: 0,
            receiverId: metadata.receiverId,
            receiverGeneration: metadata.receiverGeneration,
            targetKind: metadata.targetKind,
            targetFlags: 0,
            targetId: metadata.targetId,
            targetGeneration: metadata.targetGeneration,
            resultKind: 0,
            status: 0,
            detachedAlreadyLost: false,
            payload: new Uint8Array(),
          });
        });
      }
      return {
        operationInstanceId,
        promiseId,
        submissionStatus,
        receipt,
      };
    },
    cancel(operationInstanceId, promiseId) {
      cancellations.push(Object.freeze({ operationInstanceId, promiseId }));
      return 0;
    },
    retire: () => 0,
    capturePresentationAuthority(operationId, metadata) {
      presentationAuthorityCaptures.push(Object.freeze({ operationId, metadata }));
      const hooked = capturePresentationAuthorityHook?.(operationId, metadata);
      if (hooked !== undefined) return hooked;
      const acquireSessionId = String(nextPresentationSession);
      nextPresentationSession += 2;
      return Object.freeze({
        acquireSessionId,
        presentSessionId: String(Number(acquireSessionId) + 1),
        authorityContextDigest: new Uint8Array(32).fill(0x5a),
      });
    },
    recheckPresentationAuthority(operationId, metadata, retained) {
      presentationAuthorityRechecks.push(
        Object.freeze({ operationId, metadata, retained }),
      );
      return recheckPresentationAuthorityHook?.(
        operationId,
        metadata,
        retained,
      ) ?? true;
    },
    retirePresentationAuthority(retained) {
      presentationAuthorityRetirements.push(retained);
      return retirePresentationAuthorityHook?.(retained) ?? 1;
    },
    createMappedRangeAlias(source, offset, length) {
      const alias = source.slice(offset, offset + length);
      mappedRangeAliases.set(alias, Object.freeze({
        source,
        byteOffset: offset,
        initial: Uint8Array.from(new Uint8Array(alias)),
      }));
      mappedRangeAliasMints.push(Object.freeze({
        source,
        byteOffset: offset,
        byteLength: length,
        alias,
      }));
      return alias;
    },
    detachMappedRange(buffer) {
      mappedRangeDetachAttempts.push(buffer);
      if (detachMappedRangeHook?.(buffer) === false) return false;
      const record = mappedRangeAliases.get(buffer);
      if (!record || isDetachedArrayBuffer(buffer)) return false;
      const aliasBytes = new Uint8Array(buffer);
      const sourceBytes = new Uint8Array(record.source);
      // JavaScript cannot mint independently detachable ArrayBuffers over one
      // backing store. Reconcile only bytes changed through this fake alias so
      // overlapping leases emulate native shared write-through at cleanup.
      for (let index = 0; index < aliasBytes.length; index += 1) {
        if (aliasBytes[index] !== record.initial[index]) {
          sourceBytes[record.byteOffset + index] = aliasBytes[index]!;
        }
      }
      mappedRangeAliases.delete(buffer);
      markDetachedArrayBuffer(buffer);
      return true;
    },
    setEventSink(nextSink) {
      if (sink) throw new TypeError('event sink is one-shot');
      sink = nextSink;
    },
    emit(event) {
      sink?.(event);
    },
    setSubmitHook(hook) {
      submitHook = hook;
    },
    setPromiseResultHook(hook) {
      promiseResultHook = hook;
    },
    setDetachMappedRangeHook(hook) {
      detachMappedRangeHook = hook;
    },
    setCapturePresentationAuthorityHook(hook) {
      capturePresentationAuthorityHook = hook;
    },
    setRecheckPresentationAuthorityHook(hook) {
      recheckPresentationAuthorityHook = hook;
    },
    setRetirePresentationAuthorityHook(hook) {
      retirePresentationAuthorityHook = hook;
    },
  };
  return bridge;
}

function createFakeCodecs(
  log: string[] = [],
  options: Readonly<{
    detachedAdapters?: boolean;
    detachedDevices?: boolean;
    distinctLiveDevices?: boolean;
    omitAdapterDetachedState?: boolean;
    omitAdapterFeatures?: boolean;
    omitDeviceFeatures?: boolean;
  }> = {},
): ExecutableWebGpuCodecBundle & {
  readonly encodings: ProductionGpuServiceEncodingInput[];
} {
  const encodings: ProductionGpuServiceEncodingInput[] = [];
  let nextDetachedIdentity = 1_000;
  let nextLiveDeviceOffset = 0;
  return {
    schema: 'ibex/webgpu-executable-codecs/1',
    operationSetDigest: WEBGPU_PRODUCTION_PLAN.digests.operationSet,
    semanticProgramDigest: WEBGPU_PRODUCTION_PLAN.digests.semanticProgramSet,
    runtimeRoutingDigest: WEBGPU_PRODUCTION_PLAN.digests.runtimeRouting,
    webgpuCVocabularyDigest: WEBGPU_PRODUCTION_PLAN.digests.webgpuCVocabulary,
    operationIds: WEBGPU_PRODUCTION_PLAN.routes.map((route) => route.operationId),
    encodings,
    deriveTextureOriginDigest(input) {
      return WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
        .deriveTextureOriginDigest(input);
    },
    convertPublicArguments(operationId, args, wrappers) {
      log.push(`convert:${operationId}`);
      if (
        operationId === 'GPUDevice.createTexture' ||
        operationId === 'GPUDevice.createBindGroup' ||
        operationId === 'GPUDevice.createBindGroupLayout' ||
        operationId === 'GPUDevice.createComputePipeline' ||
        operationId === 'GPUDevice.createQuerySet' ||
        operationId === 'GPUDevice.createRenderPipeline' ||
        operationId === 'GPUDevice.popErrorScope' ||
        operationId === 'GPUDevice.pushErrorScope' ||
        operationId === 'GPUBuffer.destroy' ||
        operationId === 'GPUBuffer.getMappedRange' ||
        operationId === 'GPUBuffer.mapAsync' ||
        operationId === 'GPUBuffer.unmap' ||
        operationId === 'GPUQueue.writeBuffer' ||
        operationId === 'GPUQueue.writeTexture' ||
        operationId === 'GPUQueue.copyExternalImageToTexture' ||
        operationId === 'GPUTexture.createView' ||
        operationId === 'GPUTexture.destroy' ||
        operationId === 'GPUCanvasContext.configure' ||
        operationId === 'GPUCanvasContext.unconfigure' ||
        operationId === 'GPUCommandEncoder.beginRenderPass' ||
        operationId === 'GPUCommandEncoder.resolveQuerySet' ||
        operationId === 'GPURenderPassEncoder.drawIndexed' ||
        operationId === 'GPURenderPassEncoder.drawIndirect' ||
        operationId === 'GPURenderPassEncoder.setIndexBuffer' ||
        operationId === 'GPURenderPassEncoder.setPipeline'
      ) {
        return WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
          operationId,
          args,
          wrappers,
        );
      }
      if (operationId === 'GPU.requestAdapter') {
        const source = (args[0] ?? {}) as Record<string, unknown>;
        return Object.freeze({
          forceFallbackAdapter: Boolean(source.forceFallbackAdapter),
          featureLevel: source.featureLevel === undefined
            ? 'core'
            : String(source.featureLevel),
          xrCompatible: Boolean(source.xrCompatible),
          ...(source.powerPreference === undefined
            ? {}
            : { powerPreference: String(source.powerPreference) }),
        });
      }
      if (operationId === 'GPUQueue.submit') {
        return Array.from(args[0] as Iterable<unknown>);
      }
      if (operationId === 'GPURenderPassEncoder.draw') {
        if (args[0] === undefined) throw new TypeError('vertexCount is required');
        return Object.freeze({
          vertexCount: Number(args[0]),
          instanceCount: args[1] === undefined ? 1 : Number(args[1]),
          firstVertex: args[2] === undefined ? 0 : Number(args[2]),
          firstInstance: args[3] === undefined ? 0 : Number(args[3]),
        });
      }
      if (args.length === 0 || args[0] === undefined) return Object.freeze({});
      return args[0];
    },
    encodeServiceRequest(input) {
      log.push(`encode:${input.operationId}`);
      encodings.push(input);
      if (
        input.operationId === 'GPUDevice.createComputePipeline' ||
        input.operationId === 'GPUDevice.createQuerySet' ||
        input.operationId === 'GPUDevice.pushErrorScope' ||
        input.operationId === 'GPUDevice.popErrorScope' ||
        input.operationId === 'GPUBuffer.destroy' ||
        input.operationId === 'GPUBuffer.mapAsync' ||
        input.operationId === 'GPUBuffer.unmap' ||
        input.operationId === 'GPUQueue.writeBuffer' ||
        input.operationId === 'GPUTexture.createView' ||
        input.operationId === 'GPUQueue.writeTexture' ||
        input.operationId === 'GPUQueue.copyExternalImageToTexture'
      ) {
        return WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
          .encodeServiceRequest(input);
      }
      return new Uint8Array([input.wireId & 0xff]);
    },
    encodeServiceRequestWithSealedOperations(input) {
      if (input.sealedLocalTimeline.length > 0) {
        log.push(`encode:${input.operationId}`);
        encodings.push(input);
        const programDigests = new Map<object, string>();
        const programs = (input.convertedArguments as {
          readonly commandBuffers?: readonly {
            readonly records?: readonly object[];
          }[];
        })?.commandBuffers ?? [];
        programs.forEach((program, index) => {
          for (const record of program.records ?? []) {
            programDigests.set(
              record,
              (index % 255 + 1).toString(16).padStart(2, '0').repeat(32),
            );
          }
        });
        const sealedOperations = input.sealedLocalTimeline.map((value) => {
          const record = value as Readonly<Record<string, unknown>>;
          const receiver = record.receiverRef as Readonly<Record<string, string>>;
          const target = record.wrapperAllocatedTargetRef as
            | Readonly<Record<string, string>>
            | null;
          const staged = record.recordIdentityClass === 'staged-local';
          const programDigest = programDigests.get(value as object);
          return Object.freeze({
            identityClass: staged ? 'staged-local' as const : 'active-route' as const,
            authorityContextSource: staged
              ? 'staged-record' as const
              : programDigest === undefined
                ? 'enclosing-carrier' as const
                : 'command-program' as const,
            operationId: record.operationId as number,
            operationInstanceId: record.operationInstanceId as string,
            deviceIngressOrdinal: record.deviceIngressOrdinal as string,
            capturedScopeId: record.capturedScopeId as string,
            receiver: Object.freeze({
              kind: receiver.kind as ProductionGpuWrapperKind,
              id: receiver.objectId,
              generation: receiver.objectGeneration,
            }),
            ...(target === null
              ? {}
              : {
                target: Object.freeze({
                  kind: target.kind as ProductionGpuWrapperKind,
                  id: target.objectId,
                  generation: target.objectGeneration,
                }),
              }),
            ...(staged
              ? {
                authorityContextDigest:
                  record.operationIdentitySha256 as string,
              }
              : programDigest === undefined
                ? {}
                : { authorityContextDigest: programDigest }),
          });
        });
        return Object.freeze({
          payload:
            input.operationId === 'GPUDevice.popErrorScope' ||
            input.operationId === 'GPUTexture.createView' ||
            input.operationId === 'GPUTexture.destroy'
              ? WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
                .encodeServiceRequest(input)
              : new Uint8Array([input.wireId & 0xff]),
          sealedOperations: Object.freeze(sealedOperations),
        });
      }
      return Object.freeze({
        payload: this.encodeServiceRequest(input),
        sealedOperations: Object.freeze([]),
      });
    },
    decodeServiceResult(operationId, event) {
      log.push(`decode:${operationId}`);
      if (operationId === 'GPUBuffer.mapAsync') {
        return WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
          operationId,
          event,
        );
      }
      if (operationId === 'GPU.requestAdapter') {
        return {
          kind: 'object',
          object: {
            kind: 'GPUAdapter',
            objectId: '101',
            objectGeneration: '1',
            providerGeneration: '7',
            ...(options.omitAdapterDetachedState
              ? {}
              : {
                serviceDetachedExpired: Boolean(options.detachedAdapters),
              }),
            ...(options.omitAdapterFeatures
              ? {}
              : { features: ['timestamp-query'] }),
          },
        };
      }
      if (operationId === 'GPUAdapter.requestDevice') {
        const liveOffset = options.distinctLiveDevices
          ? nextLiveDeviceOffset++ * 10
          : 0;
        const objectId = options.detachedDevices
          ? String(nextDetachedIdentity++)
          : String(201 + liveOffset);
        const logicalDeviceId = options.detachedDevices
          ? String(nextDetachedIdentity++)
          : String(301 + liveOffset);
        const queueObjectId = options.detachedDevices
          ? String(nextDetachedIdentity++)
          : String(202 + liveOffset);
        return {
          kind: 'object',
          object: {
            kind: 'GPUDevice',
            objectId,
            objectGeneration: '1',
            logicalDeviceId,
            logicalDeviceGeneration: '1',
            providerGeneration: '7',
            features: options.omitDeviceFeatures ? [] : ['timestamp-query'],
            limits: { maxBindGroups: 4 },
            queue: {
              objectId: queueObjectId,
              objectGeneration: '1',
            },
            alreadyLost: options.detachedDevices
              ? {
                reason: 'unknown' as const,
                message: 'The adapter is expired',
              }
              : undefined,
          },
        };
      }
      return { kind: 'value', value: null };
    },
    decodeDeviceLoss(event) {
      return {
        reason: event.kind === 4 && event.lossReason === 2 ? 'destroyed' : 'unknown',
        message: `loss-${event.kind}`,
      };
    },
  };
}

function isolatedGlobal(): typeof globalThis {
  return { navigator: Object.create(null) } as unknown as typeof globalThis;
}

function emitDeviceLoss(
  bridge: ReturnType<typeof createFakeBridge>,
  logicalDeviceId: string,
  logicalLossOrdinal: string,
): void {
  bridge.emit({
    kind: 4,
    runtimeAddress: bridge.runtimeAddress,
    runtimeNonce: bridge.runtimeNonce,
    topologyId: 1,
    realmId: bridge.realmId,
    realmGeneration: bridge.realmGeneration,
    accountId: bridge.rootAccountId,
    accountGeneration: bridge.rootAccountGeneration,
    accountAuthorityDigest: bridge.rootAuthorityDigest,
    logicalDeviceId,
    logicalDeviceGeneration: '1',
    providerGeneration: '7',
    logicalLossOrdinal,
    lastAcceptedPhysicalSequence: '9',
    backendClass: 1,
    lossReason: 1,
    hasInitiatingOperation: false,
    payload: new Uint8Array(),
  });
}

function emitProviderLoss(
  bridge: ReturnType<typeof createFakeBridge>,
): void {
  bridge.emit({
    kind: 3,
    runtimeAddress: bridge.runtimeAddress,
    runtimeNonce: bridge.runtimeNonce,
    topologyId: 1,
    realmId: bridge.realmId,
    realmGeneration: bridge.realmGeneration,
    logicalDeviceId: '301',
    logicalDeviceGeneration: '1',
    providerGeneration: '7',
    lastAcceptedPhysicalSequence: '9',
    backendClass: 1,
    lossReason: 1,
    hasInitiatingOperation: false,
    payload: new Uint8Array(),
  });
}

function inspectBinding(
  binding: ReturnType<typeof createProductionWebGpuPrivateBinding>,
) {
  if (!binding.inspectForTest) throw new Error('state inspection was not enabled');
  return binding.inspectForTest();
}

function latestCanvasTextureOrigin(
  bridge: ReturnType<typeof createFakeBridge>,
): Readonly<Record<string, unknown>> {
  const createViewWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
    (route) => route.operationId === 'GPUTexture.createView',
  )?.wireId;
  if (createViewWireId === undefined) throw new Error('missing createView route');
  const submission = bridge.submissions.findLast(
    (candidate) => candidate.operationId === createViewWireId,
  );
  if (!submission) throw new Error('missing createView submission');
  const request = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
    .inspectServiceRequest(submission.payload) as Readonly<{
      convertedArguments: Readonly<{
        currentOrigin: Readonly<Record<string, unknown>>;
      }>;
    }>;
  return request.convertedArguments.currentOrigin;
}

interface TestGpuDevice {
  readonly lost: Promise<unknown>;
  destroy(): void;
}

interface TestBuffer {
  readonly size: number;
  readonly usage: number;
  readonly mapState: 'mapped' | 'pending' | 'unmapped';
  destroy(): void;
  getMappedRange(offset?: number, size?: number): ArrayBuffer;
  mapAsync(mode: number, offset?: number, size?: number): Promise<undefined>;
  unmap(): void;
}

interface TestRenderPassEncoder {
  drawIndexed(
    indexCount: number,
    instanceCount?: number,
    firstIndex?: number,
    baseVertex?: number,
    firstInstance?: number,
  ): void;
  drawIndirect(buffer: unknown, offset: number): void;
  setBindGroup(
    index: number,
    bindGroup: unknown,
    dynamicOffsets?: Iterable<number>,
  ): void;
  setBindGroup(
    index: number,
    bindGroup: unknown,
    dynamicOffsetsData: Uint32Array,
    dynamicOffsetsDataStart: number,
    dynamicOffsetsDataLength: number,
  ): void;
  setIndexBuffer(
    buffer: unknown,
    indexFormat: 'uint16' | 'uint32',
    offset?: number,
    size?: number,
  ): void;
  setPipeline(pipeline: unknown): void;
  setVertexBuffer(
    slot: number,
    buffer: unknown,
    offset?: number,
    size?: number,
  ): void;
  end(): void;
}

interface TestComputePassEncoder {
  setBindGroup(
    index: number,
    bindGroup: unknown,
    dynamicOffsets?: Iterable<number>,
  ): void;
  setBindGroup(
    index: number,
    bindGroup: unknown,
    dynamicOffsetsData: Uint32Array,
    dynamicOffsetsDataStart: number,
    dynamicOffsetsDataLength: number,
  ): void;
  setPipeline(pipeline: unknown): void;
  dispatchWorkgroups(x: number, y?: number, z?: number): void;
  end(): void;
}

interface TestCommandEncoder {
  beginComputePass(descriptor?: unknown): TestComputePassEncoder;
  beginRenderPass(descriptor: unknown): TestRenderPassEncoder;
  clearBuffer(buffer: unknown, offset?: number, size?: number): void;
  copyBufferToBuffer(source: unknown, destination: unknown, size?: number): void;
  copyBufferToBuffer(
    source: unknown,
    sourceOffset: number,
    destination: unknown,
    destinationOffset: number,
    size?: number,
  ): void;
  copyTextureToTexture(
    source: unknown,
    destination: unknown,
    copySize: unknown,
  ): void;
  resolveQuerySet(
    querySet: unknown,
    firstQuery: number,
    queryCount: number,
    destination: unknown,
    destinationOffset: number,
  ): void;
  finish(descriptor?: unknown): object;
}

interface TestRecordingDevice extends TestGpuDevice {
  readonly queue: {
    submit(commandBuffers: Iterable<unknown>): void;
    writeBuffer(
      buffer: unknown,
      bufferOffset: number,
      data: ArrayBufferView,
      dataOffset?: number,
      size?: number,
    ): void;
    writeTexture(
      destination: unknown,
      data: ArrayBufferView,
      dataLayout: unknown,
      size: unknown,
    ): void;
  };
  createBindGroupLayout(descriptor: unknown): object;
  createBindGroup(descriptor: unknown): object;
  createBuffer(descriptor: unknown): TestBuffer;
  createCommandEncoder(descriptor?: unknown): TestCommandEncoder;
  createPipelineLayout(descriptor: unknown): object;
  createComputePipeline(descriptor: unknown): object;
  createRenderPipeline(descriptor: unknown): object;
  createQuerySet(descriptor: unknown): object;
  createShaderModule(descriptor: unknown): object;
  createTexture(descriptor: unknown): object;
  pushErrorScope(filter: 'validation' | 'out-of-memory' | 'internal'): void;
  popErrorScope(): Promise<unknown>;
}

interface TestSealedLocalRecord {
  readonly recordIdentityClass: 'active-route' | 'staged-local';
  readonly operationId: number;
  readonly operationName: string;
  readonly operationIdentitySha256: string | null;
  readonly operationInstanceId: string;
  readonly deviceIngressOrdinal: string;
  readonly capturedScopeId: string;
  readonly receiverRef: Readonly<Record<string, unknown>>;
  readonly commandEncoderRef: Readonly<Record<string, unknown>> | null;
  readonly passRef: Readonly<Record<string, unknown>> | null;
  readonly wrapperAllocatedTargetRef: Readonly<Record<string, unknown>> | null;
  readonly argumentBody: Readonly<Record<string, unknown>>;
  readonly logicalError: Readonly<{ name: string; message: string }> | null;
}

interface TestSealedCommandProgram {
  readonly commandBuffer: Readonly<Record<string, unknown>>;
  readonly invalid: boolean;
  readonly records: readonly TestSealedLocalRecord[];
}

function localRecords(
  encoding: ProductionGpuServiceEncodingInput,
): readonly TestSealedLocalRecord[] {
  return encoding.sealedLocalTimeline as readonly TestSealedLocalRecord[];
}

function commandPrograms(
  encoding: ProductionGpuServiceEncodingInput,
): readonly TestSealedCommandProgram[] {
  return (encoding.convertedArguments as Readonly<{
    commandBuffers: readonly TestSealedCommandProgram[];
  }>).commandBuffers;
}

interface TestCanvasTexture {
  createView(): object;
  destroy(): void;
}

interface TestCanvasContext {
  configure(configuration: unknown): void;
  getConfiguration(): Record<string, unknown> | null;
  getCurrentTexture(): TestCanvasTexture;
  unconfigure(): void;
}

async function requestTestDevice(
  binding: ReturnType<typeof createProductionWebGpuPrivateBinding>,
): Promise<TestGpuDevice> {
  const adapter = (await (binding.gpu as {
    requestAdapter(): Promise<unknown>;
  }).requestAdapter()) as {
    requestDevice(): Promise<unknown>;
  };
  return await adapter.requestDevice() as TestGpuDevice;
}

async function requestTestRecordingDevice(
  binding: ReturnType<typeof createProductionWebGpuPrivateBinding>,
): Promise<TestRecordingDevice> {
  return await requestTestDevice(binding) as TestRecordingDevice;
}

interface TestLifecycleDevice extends TestGpuDevice {
  createBuffer(descriptor: unknown): TestBuffer;
}

type BufferMapResultSpec = Readonly<{
  variant:
    | 'mapped-bytes'
    | 'provider-operation-error'
    | 'allocation-range-error'
    | 'late-cancelled-cleanup';
  pendingMapGeneration: string;
  mode: 1 | 2;
  offset: string;
  size: string;
  ownedBytes: Uint8Array;
}>;

function bufferMapResultEvent(
  event: OperationResultEvent,
  result: BufferMapResultSpec,
): OperationResultEvent {
  return {
    ...event,
    resultKind: 4,
    payload: WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUBuffer.mapAsync',
      { kind: 'buffer-map', ...result },
    ),
  };
}

function bufferLifecycleEncodings(
  codecs: ReturnType<typeof createFakeCodecs>,
  operationId?: 'GPUBuffer.destroy' | 'GPUBuffer.mapAsync' | 'GPUBuffer.unmap',
): ProductionGpuBufferLifecycleEncoding[] {
  return codecs.encodings
    .filter((encoding) =>
      encoding.bufferLifecycle !== undefined &&
      (operationId === undefined || encoding.operationId === operationId)
    )
    .map((encoding) => encoding.bufferLifecycle!);
}

async function requestTestLifecycleDevice(
  binding: ReturnType<typeof createProductionWebGpuPrivateBinding>,
): Promise<TestLifecycleDevice> {
  return await requestTestDevice(binding) as TestLifecycleDevice;
}

function mintTestCanvasContext(
  binding: ReturnType<typeof createProductionWebGpuPrivateBinding>,
  objectGeneration = '1',
): TestCanvasContext {
  return binding.mintCanvasContext({
    objectId: '401',
    objectGeneration,
    drawingBufferWidth: 640,
    drawingBufferHeight: 480,
    authority: CANVAS_AUTHORITY,
  }) as TestCanvasContext;
}

function mintSecondTestCanvasContext(
  binding: ReturnType<typeof createProductionWebGpuPrivateBinding>,
): TestCanvasContext {
  return binding.mintCanvasContext({
    objectId: '402',
    objectGeneration: '1',
    drawingBufferWidth: 800,
    drawingBufferHeight: 600,
    authority: Object.freeze({
      attachmentGeneration: '32',
      contextGeneration: '38',
      targetAuthorityDigest: 'cd'.repeat(32),
      surfaceAccountToken: '42',
      surfaceAccountGeneration: '44',
    }),
  }) as TestCanvasContext;
}

describe('production-private WebGPU wrapper gate', () => {
  test('publishes and revokes the exact authenticated provider root set', () => {
    const providerRoots = [
      'GPU',
      'GPUAdapter',
      'GPUBindGroupLayout',
      'GPUBuffer',
      'GPUBufferUsage',
      'GPUCanvasContext',
      'GPUColorWrite',
      'GPUCommandBuffer',
      'GPUCommandEncoder',
      'GPUComputePassEncoder',
      'GPUComputePipeline',
      'GPUDevice',
      'GPUDeviceLostInfo',
      'GPUError',
      'GPUInternalError',
      'GPUMapMode',
      'GPUOutOfMemoryError',
      'GPUPipelineLayout',
      'GPUQuerySet',
      'GPUQueue',
      'GPURenderPassEncoder',
      'GPURenderPipeline',
      'GPUSampler',
      'GPUShaderModule',
      'GPUShaderStage',
      'GPUSupportedFeatures',
      'GPUSupportedLimits',
      'GPUTexture',
      'GPUTextureUsage',
      'GPUTextureView',
      'GPUUncapturedErrorEvent',
      'GPUValidationError',
    ].sort();
    const globalObject = isolatedGlobal();
    const installation = installProductionWebGpu(
      globalObject,
      createFakeBridge(),
      createFakeCodecs(),
    );
    expect(installation.status).toBe('installed');
    expect(Reflect.ownKeys(globalObject).sort()).toEqual(
      ['navigator', ...providerRoots].sort(),
    );
    expect(Reflect.ownKeys(globalObject.navigator)).toEqual(['gpu']);
    expect('createImageBitmap' in globalObject).toBe(false);

    installation.status === 'installed' && installation.revoke();
    expect(Reflect.ownKeys(globalObject)).toEqual(['navigator']);
    expect(Reflect.ownKeys(globalObject.navigator)).toEqual([]);
  });

  test('publishes createImageBitmap only with decoded-image authority', () => {
    const bridge = Object.assign(createFakeBridge(), {
      decodedImageAuthority: Object.freeze({
        async decodePng(): Promise<never> {
          throw new Error('not exercised by installation');
        },
      }),
    });
    const globalObject = isolatedGlobal();
    const installation = installProductionWebGpu(
      globalObject,
      bridge,
      createFakeCodecs(),
    );
    expect(installation.status).toBe('installed');
    expect(typeof globalObject.createImageBitmap).toBe('function');
    installation.status === 'installed' && installation.revoke();
    expect('createImageBitmap' in globalObject).toBe(false);
  });

  test('returns only a frozen construction-private Canvas minter', () => {
    const globalObject = isolatedGlobal();
    const installation = installProductionWebGpu(
      globalObject,
      createFakeBridge(),
      createFakeCodecs(),
    );
    if (installation.status !== 'installed') throw new Error('installation failed');

    expect(Object.isFrozen(installation)).toBe(true);
    expect(Object.isFrozen(installation.canvasContextMinter)).toBe(true);
    expect(Reflect.ownKeys(installation.canvasContextMinter)).toEqual([
      'mintCanvasContext',
    ]);
    const context = installation.canvasContextMinter.mintCanvasContext({
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: CANVAS_AUTHORITY,
    });
    expect(Object.getPrototypeOf(context)).toBe(
      (globalObject.GPUCanvasContext as { prototype: object }).prototype,
    );
    expect(Reflect.ownKeys(globalObject)).not.toContain('canvasContextMinter');

    installation.revoke();
    expect(() => installation.canvasContextMinter.mintCanvasContext({
      objectId: '402',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: Object.freeze({
        ...CANVAS_AUTHORITY,
        surfaceAccountToken: '42',
      }),
    })).toThrow('WebGPU realm is revoked');
  });

  test('increments private u64 counters exactly and rejects overflow before wrap', () => {
    expect(incrementCanonicalU64Decimal('18446744073709551614')).toBe(
      '18446744073709551615',
    );
    const state = { counter: '18446744073709551615' };
    expect(() => {
      state.counter = incrementCanonicalU64Decimal(state.counter);
    }).toThrow(RangeError);
    expect(state.counter).toBe('18446744073709551615');
    expect(() => incrementCanonicalU64Decimal('018')).toThrow(TypeError);
    expect(() => incrementCanonicalU64Decimal('18446744073709551616'))
      .toThrow(TypeError);
  });

  test('keeps the generic embedded default absent from host-selected injection', () => {
    expect(WEBGPU_PRODUCTION_PLAN.codecReadiness).toBe(
      'selected-build-authenticated-explicit-injection-default-ambient-undefined',
    );
  });
  test('fails closed without a V2 provider and executable codec authority', () => {
    const globalObject = isolatedGlobal();
    expect(installProductionWebGpu(globalObject, undefined)).toEqual({
      status: 'not-installed',
      reason: 'provider-absent',
    });
    const bridge = createFakeBridge();
    expect(installProductionWebGpu(globalObject, bridge)).toEqual({
      status: 'not-installed',
      reason: 'executable-codecs-unavailable',
    });
    expect('gpu' in globalObject.navigator).toBe(false);
    expect('GPUDevice' in globalObject).toBe(false);
    expect('createImageBitmap' in globalObject).toBe(false);
    expect(bridge.submissions).toHaveLength(0);

    const mismatchedCodecs = {
      ...createFakeCodecs(),
      runtimeRoutingDigest: '0'.repeat(64),
    } as ExecutableWebGpuCodecBundle;
    expect(installProductionWebGpu(globalObject, bridge, mismatchedCodecs)).toEqual({
      status: 'not-installed',
      reason: 'executable-codecs-unavailable',
    });
    expect('gpu' in globalObject.navigator).toBe(false);
  });

  test('installs and revokes a bridge-carried decoded-image global atomically', async () => {
    const globalObject = isolatedGlobal();
    const bridge = Object.assign(createFakeBridge(), {
      decodedImageAuthority: Object.freeze({
        async decodePng(request: ProductionGpuDecodedImageRequestV1) {
          return Object.freeze({
            runtimeAddress: request.runtimeAddress,
            runtimeNonce: request.runtimeNonce,
            sourceId: request.sourceId,
            sourceGeneration: request.sourceGeneration,
            width: 1,
            height: 1,
            bytesPerRow: 4,
            encodedBytes: request.encodedBytes,
            decodedPremultipliedRgba8: new Uint8Array([4, 3, 2, 1]),
            encodedContentSha256: '12'.repeat(32),
            decodedContentSha256: '34'.repeat(32),
            originClean: true as const,
            colorSpace: 'srgb' as const,
            alphaMode: 'premultiplied' as const,
            orientation: 'top-left' as const,
          });
        },
      }),
    });
    const installation = installProductionWebGpu(
      globalObject,
      bridge,
      createFakeCodecs(),
    );
    expect(installation.status).toBe('installed');
    if (installation.status !== 'installed') throw new Error('installation failed');

    const createImageBitmap = Object.getOwnPropertyDescriptor(
      globalObject,
      'createImageBitmap',
    )?.value as ((source: Blob) => Promise<{
      readonly width: number;
      readonly height: number;
      close(): void;
    }>) | undefined;
    expect(createImageBitmap).toBeFunction();
    const bitmap = await createImageBitmap!(
      new Blob([new Uint8Array([137, 80, 78, 71])], { type: 'image/png' }),
    );
    expect({ width: bitmap.width, height: bitmap.height }).toEqual({
      width: 1,
      height: 1,
    });
    bitmap.close();

    installation.revoke();
    expect('gpu' in globalObject.navigator).toBe(false);
    expect('GPUDevice' in globalObject).toBe(false);
    expect('createImageBitmap' in globalObject).toBe(false);
  });

  test('refuses worker installation and public-surface replacement', () => {
    const codecs = createFakeCodecs();
    const workerGlobal = isolatedGlobal();
    expect(
      installProductionWebGpu(workerGlobal, createFakeBridge(), codecs, 'worker'),
    ).toEqual({ status: 'not-installed', reason: 'not-app-realm' });
    expect('gpu' in workerGlobal.navigator).toBe(false);

    const occupied = isolatedGlobal();
    Object.defineProperty(occupied.navigator, 'gpu', { value: Object.freeze({}) });
    expect(
      installProductionWebGpu(occupied, createFakeBridge(), codecs),
    ).toEqual({ status: 'not-installed', reason: 'public-surface-conflict' });

    const occupiedDecodedFunction = isolatedGlobal();
    Object.defineProperty(occupiedDecodedFunction, 'createImageBitmap', {
      value() {},
    });
    expect(
      installProductionWebGpu(
        occupiedDecodedFunction,
        createFakeBridge(),
        codecs,
      ),
    ).toEqual({ status: 'not-installed', reason: 'public-surface-conflict' });
    expect('gpu' in occupiedDecodedFunction.navigator).toBe(false);
    expect('GPU' in occupiedDecodedFunction).toBe(false);
  });

  test('rolls back a partially installed public provider set', () => {
    const target = isolatedGlobal();
    const throwingGlobal = new Proxy(target, {
      defineProperty(inner, key, descriptor) {
        if (key === 'GPUAdapter') throw new Error('injected publication failure');
        return Reflect.defineProperty(inner, key, descriptor);
      },
    });
    expect(() =>
      installProductionWebGpu(
        throwingGlobal,
        createFakeBridge(),
        createFakeCodecs(),
      ),
    ).toThrow('injected publication failure');
    expect(Reflect.ownKeys(target)).toEqual(['navigator']);
    expect(Reflect.ownKeys(target.navigator)).toEqual([]);
  });
});

describe('production-private WebGPU wrapper factory', () => {
  test('admits decoded-image authority only through private construction', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      {},
      {
        decodedImageAuthority: Object.freeze({
          async decodePng(request) {
            return Object.freeze({
              runtimeAddress: request.runtimeAddress,
              runtimeNonce: request.runtimeNonce,
              sourceId: request.sourceId,
              sourceGeneration: request.sourceGeneration,
              width: 1,
              height: 1,
              bytesPerRow: 4,
              encodedBytes: request.encodedBytes,
              decodedPremultipliedRgba8: new Uint8Array([1, 2, 3, 4]),
              encodedContentSha256: 'ab'.repeat(32),
              decodedContentSha256: 'cd'.repeat(32),
              originClean: true as const,
              colorSpace: 'srgb' as const,
              alphaMode: 'premultiplied' as const,
              orientation: 'top-left' as const,
            });
          },
        }),
      },
    );
    expect(typeof binding.createImageBitmap).toBe('function');
    expect(typeof binding.snapshotImageBitmapForCopy).toBe('function');

    const bitmap = await binding.createImageBitmap!(
      new Blob([new Uint8Array([137, 80, 78, 71])], { type: 'image/png' }),
    );
    const snapshot = binding.snapshotImageBitmapForCopy!(bitmap);
    expect(snapshot).toMatchObject({
      runtimeAddress: bridge.runtimeAddress,
      runtimeNonce: bridge.runtimeNonce,
      sourceId: '1',
      sourceGeneration: '1',
      width: 1,
      height: 1,
      bytesPerRow: 4,
      originClean: true,
    });
    expect([...snapshot.decodedPremultipliedRgba8]).toEqual([1, 2, 3, 4]);

    binding.revoke();
    expect(() => binding.snapshotImageBitmapForCopy!(bitmap))
      .toThrow('Decoded-image realm is revoked');

    const withoutAuthority = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    expect(withoutAuthority.createImageBitmap).toBeUndefined();
    expect(withoutAuthority.snapshotImageBitmapForCopy).toBeUndefined();
    withoutAuthority.revoke();

    let extensionGetterRuns = 0;
    const accessorExtension = Object.defineProperty(
      {},
      'decodedImageAuthority',
      {
        enumerable: true,
        get() {
          extensionGetterRuns += 1;
          return Object.freeze({ decodePng: async () => Promise.reject() });
        },
      },
    );
    expect(() =>
      createProductionWebGpuPrivateBinding(
        createFakeBridge(),
        createFakeCodecs(),
        {},
        accessorExtension,
      ),
    ).toThrow('Invalid private WebGPU binding extensions');
    expect(extensionGetterRuns).toBe(0);
  });

  test('consumes a bridge-carried decoder without installing a global ImageBitmap API', async () => {
    let decodeCalls = 0;
    const bridge = Object.assign(createFakeBridge(), {
      decodedImageAuthority: Object.freeze({
        async decodePng(request: ProductionGpuDecodedImageRequestV1) {
          decodeCalls += 1;
          return Object.freeze({
            runtimeAddress: request.runtimeAddress,
            runtimeNonce: request.runtimeNonce,
            sourceId: request.sourceId,
            sourceGeneration: request.sourceGeneration,
            width: 1,
            height: 1,
            bytesPerRow: 4,
            encodedBytes: request.encodedBytes,
            decodedPremultipliedRgba8: new Uint8Array([9, 8, 7, 6]),
            encodedContentSha256: '12'.repeat(32),
            decodedContentSha256: '34'.repeat(32),
            originClean: true as const,
            colorSpace: 'srgb' as const,
            alphaMode: 'premultiplied' as const,
            orientation: 'top-left' as const,
          });
        },
      }),
    });
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const bitmap = await binding.createImageBitmap!(
      new Blob([new Uint8Array([137, 80, 78, 71])], { type: 'image/png' }),
    );
    expect(binding.snapshotImageBitmapForCopy!(bitmap)
      .decodedPremultipliedRgba8).toEqual(new Uint8Array([9, 8, 7, 6]));
    expect(decodeCalls).toBe(1);
    expect('createImageBitmap' in globalThis).toBe(false);
    binding.revoke();
  });

  test('snapshots only an attenuating mapped allocation guard data option', () => {
    const options = {
      privateMappedAllocationGuardLimitBytes: 4,
      enableStateInspection: true,
    };
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
      options,
    );
    options.privateMappedAllocationGuardLimitBytes = 8;
    expect(inspectBinding(binding).current.privateMappedAllocationGuardLimitBytes)
      .toBe(4);
    binding.revoke();

    for (const invalidLimit of [3, -4, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => createProductionWebGpuPrivateBinding(
        createFakeBridge(),
        createFakeCodecs(),
        { privateMappedAllocationGuardLimitBytes: invalidLimit },
      )).toThrow('Invalid private WebGPU mapped allocation guard limit');
    }
    let accessorRuns = 0;
    const accessorOptions = Object.defineProperty(
      {},
      'privateMappedAllocationGuardLimitBytes',
      {
        enumerable: true,
        get() {
          accessorRuns += 1;
          return 4;
        },
      },
    );
    expect(() => createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
      accessorOptions,
    )).toThrow('Invalid private WebGPU test options');
    expect(accessorRuns).toBe(0);
  });

  test('bounds private mapped allocation without claiming service-ledger admission', async () => {
    expect(
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.types
        .bufferDescriptorV1.fields[2]?.value.constraints,
    ).toContain('maximum-268435456');
    const defaultBinding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    expect(inspectBinding(defaultBinding).current)
      .toMatchObject({
        privateMappedAllocationGuardLimitBytes: 268_435_456,
        privateMappedAllocationGuardBytes: 0,
      });
    defaultBinding.revoke();
    expect(() => createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
      { privateMappedAllocationGuardLimitBytes: 268_435_460 },
    )).toThrow('Invalid private WebGPU mapped allocation guard limit');

    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      {
        privateMappedAllocationGuardLimitBytes: 12,
        enableStateInspection: true,
      },
    );
    const device = await requestTestDevice(binding) as TestGpuDevice & {
      createBuffer(descriptor: unknown): object;
    };
    const beforeBuffers = inspectBinding(binding).current;

    expect(() => device.createBuffer({
      mappedAtCreation: true,
      size: 2,
      usage: 9,
    })).toThrow('must be a multiple of 4');
    expect(inspectBinding(binding).current.privateMappedAllocationGuardBytes)
      .toBe(0);

    device.createBuffer({ mappedAtCreation: true, size: 4, usage: 9 });
    device.createBuffer({ mappedAtCreation: true, size: 8, usage: 9 });
    expect(inspectBinding(binding).current).toMatchObject({
      privateMappedAllocationGuardLimitBytes: 12,
      privateMappedAllocationGuardBytes: 12,
    });

    const beforeGuardFailure = inspectBinding(binding).current;
    const encodingsBeforeGuardFailure = codecs.encodings.length;
    const submissionsBeforeGuardFailure = bridge.submissions.length;
    expect(() => device.createBuffer({
      mappedAtCreation: true,
      size: 4,
      usage: 9,
    })).toThrow('private allocation guard is exhausted');
    expect(codecs.encodings).toHaveLength(encodingsBeforeGuardFailure);
    expect(bridge.submissions).toHaveLength(submissionsBeforeGuardFailure);
    expect(inspectBinding(binding).current).toMatchObject({
      allocatedWrapperCount: beforeGuardFailure.allocatedWrapperCount,
      privateMappedAllocationGuardBytes: 12,
    });

    device.createBuffer({ mappedAtCreation: false, size: 72, usage: 76 });
    expect(inspectBinding(binding).current.privateMappedAllocationGuardBytes)
      .toBe(12);
    expect(inspectBinding(binding).current.allocatedWrapperCount)
      .toBe(beforeBuffers.allocatedWrapperCount + 3);

    binding.revoke();
    expect(inspectBinding(binding).lastClose).toMatchObject({
      privateMappedAllocationGuardLimitBytes: 12,
      privateMappedAllocationGuardBytes: 12,
    });
  });

  test('uses captured mapped-byte intrinsics after app globals are replaced', async () => {
    const bridge = createFakeBridge();
    const nativeArrayBuffer = globalThis.ArrayBuffer;
    const baseCodecs = createFakeCodecs();
    const arrayBufferPayloadCodecs: ExecutableWebGpuCodecBundle = {
      ...baseCodecs,
      encodeServiceRequest() {
        return new nativeArrayBuffer(1);
      },
    };
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      arrayBufferPayloadCodecs,
      {
        privateMappedAllocationGuardLimitBytes: 4,
        enableStateInspection: true,
      },
    );
    const device = await requestTestDevice(binding) as TestGpuDevice & {
      createBuffer(descriptor: unknown): object;
    };
    const arrayBufferDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      'ArrayBuffer',
    );
    const reflectDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      'Reflect',
    );
    const uint8ArrayDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      'Uint8Array',
    );
    let hostileArrayBufferCalls = 0;
    let hostileReflectCalls = 0;
    let hostileUint8ArrayCalls = 0;
    const HostileArrayBuffer = function (): never {
      hostileArrayBufferCalls += 1;
      throw new Error('hostile ArrayBuffer binding ran');
    };
    const hostileReflect = new Proxy(Object.create(null) as object, {
      get(): never {
        hostileReflectCalls += 1;
        throw new Error('hostile Reflect binding ran');
      },
    });
    const HostileUint8Array = function (): never {
      hostileUint8ArrayCalls += 1;
      throw new Error('hostile Uint8Array binding ran');
    };
    let created: object | undefined;
    try {
      Object.defineProperty(globalThis, 'ArrayBuffer', {
        value: HostileArrayBuffer,
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis, 'Reflect', {
        value: hostileReflect,
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis, 'Uint8Array', {
        value: HostileUint8Array,
        writable: true,
        configurable: true,
      });
      created = device.createBuffer({
        mappedAtCreation: true,
        size: 4,
        usage: 9,
      });
    } finally {
      if (arrayBufferDescriptor) {
        Object.defineProperty(globalThis, 'ArrayBuffer', arrayBufferDescriptor);
      }
      if (reflectDescriptor) {
        Object.defineProperty(globalThis, 'Reflect', reflectDescriptor);
      }
      if (uint8ArrayDescriptor) {
        Object.defineProperty(globalThis, 'Uint8Array', uint8ArrayDescriptor);
      }
    }
    expect(created).toBeObject();
    expect(hostileArrayBufferCalls).toBe(0);
    expect(hostileReflectCalls).toBe(0);
    expect(hostileUint8ArrayCalls).toBe(0);
    expect(inspectBinding(binding).current.privateMappedAllocationGuardBytes)
      .toBe(4);
    binding.revoke();
  });

  test('keeps the private mapped allocation guard isolated per realm', async () => {
    const bindings = [0, 1].map(() => createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
      {
        privateMappedAllocationGuardLimitBytes: 4,
        enableStateInspection: true,
      },
    ));
    for (const binding of bindings) {
      const device = await requestTestDevice(binding) as TestGpuDevice & {
        createBuffer(descriptor: unknown): object;
      };
      device.createBuffer({ mappedAtCreation: true, size: 4, usage: 9 });
      expect(inspectBinding(binding).current.privateMappedAllocationGuardBytes)
        .toBe(4);
    }
    bindings.forEach((binding) => binding.revoke());
  });

  test('retains the private mapped allocation debit after submission rejection', async () => {
    const createBufferWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUDevice.createBuffer',
    )?.wireId;
    if (createBufferWireId === undefined) throw new Error('missing createBuffer route');
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      {
        privateMappedAllocationGuardLimitBytes: 4,
        enableStateInspection: true,
      },
    );
    const device = await requestTestDevice(binding) as TestGpuDevice & {
      createBuffer(descriptor: unknown): object;
    };
    const before = inspectBinding(binding).current;
    const encodingsBefore = codecs.encodings.length;
    const submissionsBefore = bridge.submissions.length;
    bridge.setSubmitHook((operationId) =>
      operationId === createBufferWireId ? 7 : 0
    );
    expect(() => device.createBuffer({
      mappedAtCreation: true,
      size: 4,
      usage: 9,
    })).toThrow('semantic service rejected GPUDevice.createBuffer');
    expect(codecs.encodings).toHaveLength(encodingsBefore + 1);
    expect(bridge.submissions).toHaveLength(submissionsBefore + 1);
    expect(inspectBinding(binding).current).toMatchObject({
      allocatedWrapperCount: before.allocatedWrapperCount + 1,
      privateMappedAllocationGuardBytes: 4,
    });
    const submissionsAfterRejection = bridge.submissions.length;
    expect(() => device.createBuffer({
      mappedAtCreation: true,
      size: 4,
      usage: 9,
    })).toThrow('private allocation guard is exhausted');
    expect(bridge.submissions).toHaveLength(submissionsAfterRejection);
    binding.revoke();
  });

  test('settles an unknown post-WebIDL feature level to null without provider work', async () => {
    const log: string[] = [];
    const bridge = createFakeBridge();
    const globalObject = isolatedGlobal();
    const installation = installProductionWebGpu(
      globalObject,
      bridge,
      createFakeCodecs(log),
    );
    expect(installation.status).toBe('installed');
    const result = await (globalObject.navigator.gpu as {
      requestAdapter(options?: unknown): Promise<unknown>;
    }).requestAdapter({ featureLevel: 'future-profile' });
    expect(result).toBeNull();
    expect(log).toContain('convert:GPU.requestAdapter');
    expect(log).not.toContain('encode:GPU.requestAdapter');
    expect(bridge.submissions).toHaveLength(0);
    installation.status === 'installed' && installation.revoke();
  });

  test('runs Promise-operation conversion effects during the call and rejects conversion errors', async () => {
    const bridge = createFakeBridge();
    const globalObject = isolatedGlobal();
    const installation = installProductionWebGpu(
      globalObject,
      bridge,
      createFakeCodecs(),
    );
    expect(installation.status).toBe('installed');
    let getterObserved = false;
    const options = Object.defineProperty({}, 'forceFallbackAdapter', {
      enumerable: true,
      get() {
        getterObserved = true;
        throw new TypeError('conversion exploded');
      },
    });
    const pending = (globalObject.navigator.gpu as {
      requestAdapter(options?: unknown): Promise<unknown>;
    }).requestAdapter(options);
    expect(getterObserved).toBe(true);
    expect(pending).toBeInstanceOf(Promise);
    await expect(pending).rejects.toThrow('conversion exploded');
    expect(bridge.submissions).toHaveLength(0);
    installation.status === 'installed' && installation.revoke();
  });

  test('requires authenticated adapter attachment state without defaulting live', async () => {
    const log: string[] = [];
    const detached = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(log, { detachedAdapters: true }),
    );
    const adapter = await (detached.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter() as { requestDevice(): Promise<unknown> };
    await expect(adapter.requestDevice()).resolves.toBeObject();
    expect(log).toContain('convert:GPUAdapter.requestDevice');
    expect(log).toContain('encode:GPUAdapter.requestDevice');
    detached.revoke();

    const missing = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs([], { omitAdapterDetachedState: true }),
    );
    await expect((missing.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter()).rejects.toThrow(
      'GPUAdapter result lacks authenticated detached state',
    );
    missing.revoke();

    const missingFeatures = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs([], { omitAdapterFeatures: true }),
    );
    await expect((missingFeatures.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter()).rejects.toThrow(
      'GPUAdapter result lacks authenticated exposed features',
    );
    missingFeatures.revoke();
  });

  test('does not allocate or enqueue a texture view after an intermediate descriptor conversion throws', async () => {
    const log: string[] = [];
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs(log);
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      enableStateInspection: true,
    });
    const adapter = await (binding.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter() as { requestDevice(): Promise<unknown> };
    const device = await adapter.requestDevice() as {
      createTexture(descriptor: unknown): {
        createView(descriptor?: unknown): object;
      };
    };
    const texture = device.createTexture({
      format: 'rgba8unorm',
      size: [4, 4],
      usage: 4,
    });
    const before = texture.createView();
    const beforeTarget = codecs.encodings.at(-1)?.target;
    expect(beforeTarget).toMatchObject({ kind: 'GPUTextureView' });

    let laterGetterCount = 0;
    const hostile = Object.create({
      get label() {
        laterGetterCount += 1;
        return 'unseen';
      },
    }) as Record<string, unknown>;
    Object.defineProperty(hostile, 'arrayLayerCount', {
      enumerable: true,
      get() {
        return {
          valueOf() {
            throw new TypeError('array layer conversion exploded');
          },
        };
      },
    });
    Object.defineProperty(hostile, 'aspect', {
      enumerable: true,
      get() {
        laterGetterCount += 1;
        return 'all';
      },
    });
    const encodingCount = codecs.encodings.length;
    const submissionCount = bridge.submissions.length;
    expect(() => texture.createView(hostile)).toThrow(
      'array layer conversion exploded',
    );
    expect(laterGetterCount).toBe(0);
    expect(codecs.encodings).toHaveLength(encodingCount);
    expect(bridge.submissions).toHaveLength(submissionCount);

    const after = texture.createView();
    const afterTarget = codecs.encodings.at(-1)?.target;
    expect(after).not.toBe(before);
    expect(afterTarget).toMatchObject({ kind: 'GPUTextureView' });
    expect(
      BigInt((afterTarget as { objectId: string }).objectId),
    ).toBe(BigInt((beforeTarget as { objectId: string }).objectId) + 1n);
    binding.revoke();
  });

  test('defers texture extent shape and format-feature rejection until complete conversion without allocating', async () => {
    const log: string[] = [];
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs(log);
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding) as TestGpuDevice & {
      createTexture(descriptor: unknown): object;
    };
    const first = device.createTexture({
      format: 'rgba8unorm',
      size: [4, 4],
      usage: 4,
    });
    expect(first).toBeObject();
    const firstTarget = codecs.encodings.at(-1)?.target as { objectId: string };

    const observations: string[] = [];
    const extent = {
      [Symbol.iterator]: function* () {
        observations.push('extent-iterator');
        for (let index = 0; index < 4; index += 1) {
          yield {
            valueOf() {
              observations.push(`extent-${index}`);
              return index + 1;
            },
          };
        }
      },
    };
    const viewFormats = {
      [Symbol.iterator]: function* () {
        observations.push('view-formats-iterator');
        yield 'rgba8unorm';
      },
    };
    const hostile = Object.create(null) as Record<string, unknown>;
    for (const [name, value] of [
      ['dimension', '2d'],
      ['format', 'rgba8unorm'],
      ['label', 'hostile'],
      ['mipLevelCount', 1],
      ['sampleCount', 1],
      ['size', extent],
      ['textureBindingViewDimension', '2d'],
      ['usage', 4],
      ['viewFormats', viewFormats],
    ] as const) {
      Object.defineProperty(hostile, name, {
        enumerable: true,
        get() {
          observations.push(`get-${name}`);
          return value;
        },
      });
    }
    const encodingCount = codecs.encodings.length;
    const submissionCount = bridge.submissions.length;
    const wrapperCount = inspectBinding(binding).current.allocatedWrapperCount;
    expect(() => device.createTexture(hostile)).toThrow(
      'GPUTextureDescriptor.size sequence must contain one to three members',
    );
    expect(observations).toEqual([
      'get-dimension',
      'get-format',
      'get-label',
      'get-mipLevelCount',
      'get-sampleCount',
      'get-size',
      'extent-iterator',
      'extent-0',
      'extent-1',
      'extent-2',
      'extent-3',
      'get-textureBindingViewDimension',
      'get-usage',
      'get-viewFormats',
      'view-formats-iterator',
    ]);
    expect(codecs.encodings).toHaveLength(encodingCount);
    expect(bridge.submissions).toHaveLength(submissionCount);
    expect(inspectBinding(binding).current.allocatedWrapperCount)
      .toBe(wrapperCount);

    for (const descriptor of [
      { format: 'rgba8unorm', size: [], usage: 4 },
      { format: 'r16unorm', size: [4, 4], usage: 4 },
      {
        format: 'rgba8unorm',
        size: [4, 4],
        usage: 4,
        viewFormats: ['bc1-rgba-unorm'],
      },
    ]) {
      expect(() => device.createTexture(descriptor)).toThrow(TypeError);
      expect(codecs.encodings).toHaveLength(encodingCount);
      expect(bridge.submissions).toHaveLength(submissionCount);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(wrapperCount);
    }

    device.createTexture({ format: 'rgba8unorm', size: [8, 8], usage: 4 });
    const finalTarget = codecs.encodings.at(-1)?.target as { objectId: string };
    expect(BigInt(finalTarget.objectId)).toBe(BigInt(firstTarget.objectId) + 1n);
    binding.revoke();
  });

  test('reports selected-build TypeGPU execution without widening support', () => {
    const staging = describeProductionWebGpuWorkloadStaging();
    expect(staging.status).toBe(
      'conditional-selected-build-routable-active-default-runtime-absent',
    );
    expect(staging.supportClaim).toBe('none');
    expect(staging.nativeExecutionEvidence).toBe(
      'source-activated-no-platform-or-cts-evidence',
    );
    expect(staging.conditionalExecutionLane).toMatchObject({
      classification: 'experimental-selected-build-only',
      defaultRuntimeInstallation: 'absent',
      workerInstallation: 'absent',
      ctsEvidence: 'absent',
      platformQualificationEvidence: 'absent',
      supportClaim: 'none',
    });
    expect(staging.typegpuVersion).toBe('0.11.9');
    expect(staging.activeRouteOperationCount).toBe(
      WEBGPU_PRODUCTION_PLAN.routes.length,
    );
    expect(staging.activeRouteOperationCount).toBeGreaterThanOrEqual(41);
    expect(staging.workloadOperationCount).toBe(51);
    expect(staging.additionalOperationCount).toBe(
      staging.additionalOperations.length,
    );
    expect(staging.additionalOperationCount).toBe(0);
    expect(staging.claimBoundaryAbsences).toEqual([
      'default-runtime-installation',
      'canonical-public-support-surface',
      'worker-runtime-installation',
      'webgpu-cts-evidence',
      'platform-qualification-evidence',
    ]);
    expect(staging.embeddedCodecRule).toBe(
      'EMBEDDED_EXECUTABLE_WEBGPU_CODECS-remains-undefined-selected-build-uses-authenticated-explicit-injection',
    );
    expect(Object.isFrozen(staging)).toBe(true);
    expect(Object.isFrozen(staging.additionalOperations)).toBe(true);
    expect(Object.isFrozen(staging.localRecordingSubset)).toBe(true);
    expect(Object.isFrozen(staging.localRecordingSubset.operations)).toBe(true);
    expect(Object.isFrozen(staging.claimBoundaryAbsences)).toBe(true);
    expect(Object.fromEntries(
      staging.localRecordingSubset.operations.map((operation) => [
        operation.operationId,
        {
          localRecordId: operation.localRecordId,
          recordIdentitySha256: operation.recordIdentitySha256,
        },
      ]),
    )).toEqual(EXPECTED_STAGED_LOCAL_RECORD_IDENTITIES);

    expect(staging.additionalOperations).toEqual([]);
  });

  test('materializes only routes whose native and CapSec installation gates are closed', () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    expect(WEBGPU_PRODUCTION_PLAN.routes.length).toBeGreaterThanOrEqual(41);
    expect(Object.keys(binding.interfaceObjects)).toHaveLength(27);
    expect(Object.keys(binding.constantObjects)).toHaveLength(5);
    for (const selected of WEBGPU_PRODUCTION_PLAN.routes) {
      const interfaceObject = binding.interfaceObjects[selected.interfaceName] as {
        readonly prototype: object;
      };
      expect(interfaceObject).toBeDefined();
      const descriptor = Object.getOwnPropertyDescriptor(
        interfaceObject.prototype,
        selected.memberName,
      );
      expect(descriptor).toBeDefined();
      if (selected.memberKind === 'method') {
        expect(descriptor?.value).toBeFunction();
      } else {
        expect(descriptor?.get).toBeFunction();
      }
    }
    binding.revoke();
  });

  test('routes writeTexture only after a synchronous immutable source snapshot', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs([], { distinctLiveDevices: true });
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestRecordingDevice(binding);
    const texture = device.createTexture({
      format: 'rgba8unorm',
      size: { width: 1, height: 1, depthOrArrayLayers: 1 },
      usage: 2,
    });
    const source = Uint8Array.from([1, 2, 3, 4]);
    device.queue.writeTexture(
      { texture, origin: [0, 0, 0] },
      source,
      { bytesPerRow: 256, rowsPerImage: 1 },
      [1, 1, 1],
    );
    source.fill(99);
    const wireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUQueue.writeTexture',
    )?.wireId;
    const submission = bridge.submissions.findLast(
      (candidate) => candidate.operationId === wireId,
    );
    expect(submission).toBeDefined();
    expect(submission?.wantsPromise).toBe(false);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      submission!.payload,
    )).toMatchObject({
      operationId: 'GPUQueue.writeTexture',
      convertedArguments: {
        destination: {
          texture: { kind: 'GPUTexture' },
          origin: { x: 0, y: 0, z: 0, iterableLength: 3 },
        },
        dataLayout: { offset: '0', bytesPerRow: 256, rowsPerImage: 1 },
        size: {
          width: 1,
          height: 1,
          depthOrArrayLayers: 1,
          iterableLength: 3,
        },
        bytes: [1, 2, 3, 4],
      },
    });

    const foreignDevice = await requestTestRecordingDevice(binding);
    const foreignTexture = foreignDevice.createTexture({
      format: 'rgba8unorm',
      size: { width: 1, height: 1, depthOrArrayLayers: 1 },
      usage: 2,
    });
    expect(() => device.queue.writeTexture(
      { texture: foreignTexture },
      new Uint8Array(4),
      { bytesPerRow: 256, rowsPerImage: 1 },
      { width: 1, height: 1, depthOrArrayLayers: 1 },
    )).not.toThrow();
    const foreignSubmission = bridge.submissions.findLast(
      (candidate) => candidate.operationId === wireId,
    );
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      foreignSubmission!.payload,
    )).toMatchObject({
      receiver: { logicalDeviceId: '301' },
      convertedArguments: {
        destination: {
          texture: {
            kind: 'GPUTexture',
            logicalDeviceId: '311',
            logicalDeviceGeneration: '1',
            providerGeneration: '7',
          },
        },
      },
    });
    binding.revoke();
  });

  test('routes copyExternalImageToTexture with one authenticated decoded-plane snapshot', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs([], { distinctLiveDevices: true }),
      {},
      {
        decodedImageAuthority: Object.freeze({
          async decodePng(request) {
            return Object.freeze({
              runtimeAddress: request.runtimeAddress,
              runtimeNonce: request.runtimeNonce,
              sourceId: request.sourceId,
              sourceGeneration: request.sourceGeneration,
              width: 1,
              height: 1,
              bytesPerRow: 4,
              encodedBytes: request.encodedBytes,
              decodedPremultipliedRgba8: new Uint8Array([1, 2, 3, 4]),
              encodedContentSha256: 'ab'.repeat(32),
              decodedContentSha256: 'cd'.repeat(32),
              originClean: true as const,
              colorSpace: 'srgb' as const,
              alphaMode: 'premultiplied' as const,
              orientation: 'top-left' as const,
            });
          },
        }),
      },
    );
    const device = await requestTestRecordingDevice(binding) as TestGpuDevice & {
      queue: TestGpuDevice['queue'] & {
        copyExternalImageToTexture(
          source: unknown,
          destination: unknown,
          size: unknown,
        ): void;
      };
    };
    const texture = device.createTexture({
      format: 'rgba8unorm',
      size: { width: 1, height: 1, depthOrArrayLayers: 1 },
      usage: 18,
    });
    const bitmap = await binding.createImageBitmap!(
      new Blob([new Uint8Array([137, 80, 78, 71])], { type: 'image/png' }),
    );
    device.queue.copyExternalImageToTexture(
      { source: bitmap, origin: [0, 0], flipY: true },
      {
        texture,
        origin: [0, 0, 0],
        colorSpace: 'srgb',
        premultipliedAlpha: false,
      },
      [1, 1, 1],
    );
    const wireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUQueue.copyExternalImageToTexture',
    )?.wireId;
    const submission = bridge.submissions.findLast(
      (candidate) => candidate.operationId === wireId,
    );
    expect(submission).toBeDefined();
    expect(submission?.wantsPromise).toBe(false);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      submission!.payload,
    )).toMatchObject({
      operationId: 'GPUQueue.copyExternalImageToTexture',
      convertedArguments: {
        source: {
          origin: { x: 0, y: 0, iterableLength: 2 },
          flipY: true,
          snapshot: {
            runtimeAddress: bridge.runtimeAddress,
            runtimeNonce: bridge.runtimeNonce,
            sourceId: '1',
            sourceGeneration: '1',
            width: 1,
            height: 1,
            bytesPerRow: 4,
            encodedBytes: [137, 80, 78, 71],
            decodedPremultipliedRgba8: [1, 2, 3, 4],
            originClean: true,
            usability: 'good',
          },
        },
        destination: {
          texture: { kind: 'GPUTexture' },
          origin: { x: 0, y: 0, z: 0, iterableLength: 3 },
          colorSpace: 'srgb',
          premultipliedAlpha: false,
        },
        copySize: {
          width: 1,
          height: 1,
          depthOrArrayLayers: 1,
          iterableLength: 3,
        },
      },
    });

    (bitmap as { close(): void }).close();
    const submissionCount = bridge.submissions.length;
    expect(() => device.queue.copyExternalImageToTexture(
      { source: bitmap, origin: [1, 0] },
      { texture },
      [1, 1, 1],
    )).toThrowError(expect.objectContaining({ name: 'OperationError' }));
    expect(() => device.queue.copyExternalImageToTexture(
      { source: bitmap },
      { texture },
      [1, 1, 1],
    )).toThrowError(expect.objectContaining({ name: 'InvalidStateError' }));
    expect(bridge.submissions).toHaveLength(submissionCount);
    binding.revoke();
  });

  test('routes the app realm through V2 and preserves local recording semantics', async () => {
    const log: string[] = [];
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs(log);
    const globalObject = isolatedGlobal();
    const installation = installProductionWebGpu(globalObject, bridge, codecs);
    expect(installation.status).toBe('installed');
    const gpu = globalObject.navigator.gpu as {
      requestAdapter(options?: unknown): Promise<unknown>;
      getPreferredCanvasFormat(): string;
    };
    expect(gpu.getPreferredCanvasFormat()).toBe('bgra8unorm');
    expect('createBuffer' in gpu).toBe(false);

    const pendingAdapter = gpu.requestAdapter({ powerPreference: 'high-performance' });
    expect(log).toContain('convert:GPU.requestAdapter');
    const adapter = (await pendingAdapter) as {
      readonly features: {
        readonly size: number;
        has(value: string): boolean;
      };
      requestDevice(descriptor?: unknown): Promise<unknown>;
    };
    const adapterFeatures = adapter.features;
    const logBeforeAdapterMetadata = log.slice();
    const submissionsBeforeAdapterMetadata = bridge.submissions.length;
    expect(adapterFeatures).toBe(adapter.features);
    expect(adapterFeatures.size).toBe(1);
    expect(adapterFeatures.has('timestamp-query')).toBe(true);
    expect(log).toEqual(logBeforeAdapterMetadata);
    expect(bridge.submissions).toHaveLength(submissionsBeforeAdapterMetadata);
    expect(() => {
      (adapter as { features: object }).features = {};
    }).toThrow();
    const pendingDevice = adapter.requestDevice({});
    expect(log).toContain('convert:GPUAdapter.requestDevice');
    const device = (await pendingDevice) as {
      readonly queue: {
        submit(buffers: Iterable<unknown>): void;
        writeBuffer(
          buffer: unknown,
          bufferOffset: number,
          data: ArrayBufferView,
          dataOffset?: number,
          size?: number,
        ): void;
      };
      readonly features: { has(value: string): boolean };
      readonly limits: Readonly<Record<string, number>>;
      readonly lost: Promise<unknown>;
      pushErrorScope(filter: unknown): void;
      popErrorScope(): Promise<unknown>;
      createBindGroupLayout(descriptor: unknown): object;
      createBuffer(descriptor: unknown): {
        readonly size: number;
        readonly usage: number;
        readonly mapState: 'mapped' | 'pending' | 'unmapped';
      };
      createPipelineLayout(descriptor: unknown): object;
      createSampler(descriptor?: unknown): object;
      createShaderModule(descriptor: unknown): object;
      createTexture(descriptor: unknown): {
        readonly dimension: '1d' | '2d' | '3d';
        readonly format: string;
        readonly height: number;
        readonly depthOrArrayLayers: number;
        readonly width: number;
      };
      createComputePipeline(descriptor: unknown): object;
      createRenderPipeline(descriptor: unknown): object;
      createCommandEncoder(descriptor?: unknown): {
        beginRenderPass(descriptor: unknown): {
          setPipeline(pipeline: unknown): void;
          draw(vertexCount: number): void;
          end(): void;
        };
        finish(descriptor?: unknown): object;
      };
    };
    expect(device.features.has('timestamp-query')).toBe(true);
    expect(device.limits.maxBindGroups).toBe(4);
    expect(device.queue).toBe(device.queue);
    expect(device.lost).toBe(device.lost);
    expect(globalObject.GPUComputePassEncoder).toBeFunction();
    device.pushErrorScope('validation');
    const poppedScope = device.popErrorScope();
    expect(poppedScope).toBeInstanceOf(Promise);
    expect(await poppedScope).toBeNull();

    const bindGroupLayout = device.createBindGroupLayout({
      entries: [{ binding: 0, visibility: 7, buffer: {} }],
    });
    expect(bindGroupLayout).toBeObject();
    expect(log).toContain('convert:GPUDevice.createBindGroupLayout');
    expect(log).toContain('encode:GPUDevice.createBindGroupLayout');
    const bindGroupLayoutEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUDevice.createBindGroupLayout',
    )!;
    expect(bindGroupLayoutEncoding.target).toMatchObject({
      kind: 'GPUBindGroupLayout',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    const submissionsBeforeMappedAlignmentFailure = bridge.submissions.length;
    const encodingsBeforeMappedAlignmentFailure = codecs.encodings.length;
    expect(() => device.createBuffer({
      label: 'misaligned-mapped-buffer',
      mappedAtCreation: true,
      size: 6,
      usage: 9,
    })).toThrow(RangeError);
    expect(bridge.submissions).toHaveLength(
      submissionsBeforeMappedAlignmentFailure,
    );
    expect(codecs.encodings).toHaveLength(encodingsBeforeMappedAlignmentFailure);
    const mappedBufferDescriptor = {
      label: 'mapped-buffer',
      mappedAtCreation: true,
      size: 128,
      usage: 9,
    };
    const mappedBuffer = device.createBuffer(mappedBufferDescriptor);
    mappedBufferDescriptor.size = 256;
    const logBeforeMappedBufferMetadata = log.slice();
    const submissionsBeforeMappedBufferMetadata = bridge.submissions.length;
    expect(mappedBuffer.size).toBe(128);
    expect(mappedBuffer.usage).toBe(9);
    expect(mappedBuffer.mapState).toBe('mapped');
    expect(log).toEqual(logBeforeMappedBufferMetadata);
    expect(bridge.submissions).toHaveLength(submissionsBeforeMappedBufferMetadata);
    const unmappedBufferDescriptor = {
      label: 'unmapped-buffer',
      size: 72,
      usage: 76,
    };
    const unmappedBuffer = device.createBuffer(unmappedBufferDescriptor);
    unmappedBufferDescriptor.size = 144;
    const logBeforeUnmappedBufferMetadata = log.slice();
    const submissionsBeforeUnmappedBufferMetadata = bridge.submissions.length;
    expect(unmappedBuffer.size).toBe(72);
    expect(unmappedBuffer.usage).toBe(76);
    expect(unmappedBuffer.mapState).toBe('unmapped');
    expect(log).toEqual(logBeforeUnmappedBufferMetadata);
    expect(bridge.submissions).toHaveLength(submissionsBeforeUnmappedBufferMetadata);
    expect(() => {
      (unmappedBuffer as { usage: number }).usage = 1;
    }).toThrow();
    expect(() => {
      (unmappedBuffer as { size: number }).size = 1;
    }).toThrow();
    expect(log.filter((entry) => entry === 'convert:GPUDevice.createBuffer')).toHaveLength(3);
    expect(log.filter((entry) => entry === 'encode:GPUDevice.createBuffer')).toHaveLength(2);
    const bufferEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUDevice.createBuffer',
    )!;
    expect(bufferEncoding.target).toEqual({
      kind: 'GPUBuffer',
      objectId: expect.any(String),
      objectGeneration: '1',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    expect(BigInt((bufferEncoding.target as { objectId: string }).objectId)).toBe(
      BigInt((bindGroupLayoutEncoding.target as { objectId: string }).objectId) +
        1n,
    );
    const pipelineLayout = device.createPipelineLayout({
      bindGroupLayouts: [bindGroupLayout],
      immediateSize: 0,
    });
    expect(pipelineLayout).toBeObject();
    expect(log).toContain('convert:GPUDevice.createPipelineLayout');
    expect(log).toContain('encode:GPUDevice.createPipelineLayout');
    const pipelineLayoutEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUDevice.createPipelineLayout',
    )!;
    expect(pipelineLayoutEncoding.target).toMatchObject({
      kind: 'GPUPipelineLayout',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });

    const shaderForCompute = device.createShaderModule({
      code: '@compute @workgroup_size(1) fn main() {}',
    });
    const computePipeline = device.createComputePipeline({
      label: 'compute-pipeline',
      layout: pipelineLayout,
      compute: { module: shaderForCompute },
    });
    expect(Object.getPrototypeOf(computePipeline)).toBe(
      (globalObject.GPUComputePipeline as { prototype: object }).prototype,
    );
    const computeEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUDevice.createComputePipeline',
    )!;
    expect(computeEncoding.target).toMatchObject({
      kind: 'GPUComputePipeline',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });

    const sampler = device.createSampler({
      label: 'sampler',
      magFilter: 'linear',
      minFilter: 'linear',
    });
    expect(Object.getPrototypeOf(sampler)).toBe(
      (globalObject.GPUSampler as { prototype: object }).prototype,
    );
    const samplerEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUDevice.createSampler',
    )!;
    expect(samplerEncoding.receiver).toMatchObject({
      kind: 'GPUDevice',
      objectId: '201',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    expect(samplerEncoding.target).toMatchObject({
      kind: 'GPUSampler',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });

    const textureDescriptor = {
      dimension: '2d',
      format: 'rgba8unorm',
      label: 'texture',
      size: { width: 32, height: 16, depthOrArrayLayers: 1 },
      usage: 23,
    };
    const texture = device.createTexture(textureDescriptor);
    textureDescriptor.size.depthOrArrayLayers = 4;
    const logBeforeTextureMetadata = log.slice();
    const submissionsBeforeTextureMetadata = bridge.submissions.length;
    expect(texture.dimension).toBe('2d');
    expect(texture.format).toBe('rgba8unorm');
    expect(texture.height).toBe(16);
    expect(texture.depthOrArrayLayers).toBe(1);
    expect(texture.width).toBe(32);
    expect(log).toEqual(logBeforeTextureMetadata);
    expect(bridge.submissions).toHaveLength(submissionsBeforeTextureMetadata);
    expect(() => {
      (texture as { width: number }).width = 1;
    }).toThrow();
    expect(() => {
      (texture as { depthOrArrayLayers: number }).depthOrArrayLayers = 2;
    }).toThrow();
    const textureEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUDevice.createTexture',
    )!;
    expect(textureEncoding.receiver).toMatchObject({
      kind: 'GPUDevice',
      objectId: '201',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    expect(textureEncoding.target).toMatchObject({
      kind: 'GPUTexture',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });

    const shader = device.createShaderModule({ code: '@vertex fn main() {}' });
    const pipeline = device.createRenderPipeline({
      layout: 'auto',
      vertex: { module: shader },
    });
    const encoder = device.createCommandEncoder();
    const pass = encoder.beginRenderPass({ colorAttachments: [] });
    pass.setPipeline(pipeline);
    pass.draw(3);
    pass.end();
    const commandBuffer = encoder.finish();
    const uploadSource = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    device.queue.writeBuffer(unmappedBuffer, 4, uploadSource, 1, 4);
    uploadSource.fill(0);
    const writeBufferEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUQueue.writeBuffer',
    )!;
    expect(writeBufferEncoding.receiver).toMatchObject({
      kind: 'GPUQueue',
      objectId: '202',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    expect(writeBufferEncoding.convertedArguments).toMatchObject({
      bufferOffset: 4,
      bytes: new Uint8Array([2, 3, 4, 5]),
    });
    expect(writeBufferEncoding.deviceIngressOrdinal).not.toBe('0');
    expect(writeBufferEncoding.queueIngressOrdinal).not.toBe('0');
    expect(writeBufferEncoding.sealedLocalTimeline).toEqual([]);
    const submissionsBeforeQueue = bridge.submissions.length;
    device.queue.submit([commandBuffer]);
    expect(bridge.submissions).toHaveLength(submissionsBeforeQueue + 1);

    const requestAdapterWire = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPU.requestAdapter',
    )!.wireId;
    const requestDeviceWire = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUAdapter.requestDevice',
    )!.wireId;
    const adapterSubmission = bridge.submissions.find(
      (submission) => submission.operationId === requestAdapterWire,
    )!;
    const deviceSubmission = bridge.submissions.find(
      (submission) => submission.operationId === requestDeviceWire,
    )!;
    expect(adapterSubmission.metadata).toMatchObject({
      receiverKind: 1,
      receiverId: bridge.realmId,
      receiverGeneration: bridge.realmGeneration,
    });
    expect(deviceSubmission.metadata).toMatchObject({
      receiverKind: 2,
      receiverId: '101',
      receiverGeneration: '1',
    });
    const submitEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    )!;
    expect(submitEncoding.sealedLocalTimeline.length).toBeGreaterThanOrEqual(5);
    const drawRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPURenderPassEncoder.draw',
    )!;
    const drawRecord = (submitEncoding.sealedLocalTimeline as ReadonlyArray<
      Readonly<Record<string, unknown>>
    >).find((record) => record.operationId === drawRoute.wireId)!;
    expect(drawRecord).toMatchObject({
      operationId: drawRoute.wireId,
      operationName: 'GPURenderPassEncoder.draw',
      deviceIngressOrdinal: expect.any(String),
      capturedScopeId: '0',
      receiverRef: { kind: 'GPURenderPassEncoder' },
      wrapperAllocatedTargetRef: null,
      argumentBody: {
        vertexCount: 3,
        instanceCount: 1,
        firstVertex: 0,
        firstInstance: 0,
      },
      logicalError: null,
    });
    expect(typeof drawRecord.operationInstanceId).toBe('string');
    expect(BigInt(drawRecord.operationInstanceId as string) >= (1n << 63n)).toBe(true);
    expect(drawRecord).not.toHaveProperty('wireId');
    expect(drawRecord).not.toHaveProperty('receiver');
    expect(drawRecord).not.toHaveProperty('convertedArguments');
    expect(submitEncoding.receiver).toMatchObject({
      kind: 'GPUQueue',
      objectId: '202',
      logicalDeviceId: '301',
    });

    installation.status === 'installed' && installation.revoke();
    expect('gpu' in globalObject.navigator).toBe(false);
    expect('GPUDevice' in globalObject).toBe(false);
  });

  test('preserves cross-device render lineage and rejects foreign brands', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs([], { distinctLiveDevices: true });
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const firstDevice = await requestTestRecordingDevice(binding);
    const secondDevice = await requestTestRecordingDevice(binding);
    const firstBuffer = firstDevice.createBuffer({ size: 16, usage: 8 });
    const secondBuffer = secondDevice.createBuffer({ size: 16, usage: 8 });
    const submissionsBeforeForeignWrite = bridge.submissions.length;
    expect(() => firstDevice.queue.writeBuffer(
      secondBuffer,
      0,
      new Uint8Array([1, 2, 3, 4]),
    )).toThrow(TypeError);
    expect(bridge.submissions).toHaveLength(submissionsBeforeForeignWrite);
    firstDevice.queue.writeBuffer(
      firstBuffer,
      0,
      new Uint8Array([5, 6, 7, 8]),
    );
    const firstValidWrite = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUQueue.writeBuffer',
    );
    expect(firstValidWrite?.queueIngressOrdinal).toBe('1');
    expect(bridge.submissions).toHaveLength(submissionsBeforeForeignWrite + 1);
    const firstShader = firstDevice.createShaderModule({
      code: '@vertex fn main() {}',
    });
    const secondLayout = secondDevice.createPipelineLayout({
      bindGroupLayouts: [],
    });

    let ordinaryLayoutStringCalls = 0;
    firstDevice.createRenderPipeline({
      layout: {
        toString() {
          ordinaryLayoutStringCalls += 1;
          return 'auto';
        },
      },
      vertex: { module: firstShader },
    });
    expect(ordinaryLayoutStringCalls).toBe(1);

    firstDevice.createRenderPipeline({
      layout: secondLayout,
      vertex: { module: firstShader },
    });
    const crossDeviceEncoding = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUDevice.createRenderPipeline',
    );
    if (!crossDeviceEncoding) throw new Error('missing render pipeline encoding');
    expect(crossDeviceEncoding.receiver).toMatchObject({
      kind: 'GPUDevice',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    expect(crossDeviceEncoding.convertedArguments).toMatchObject({
      layout: {
        kind: 'GPUPipelineLayout',
        logicalDeviceId: '311',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      vertex: {
        module: {
          kind: 'GPUShaderModule',
          logicalDeviceId: '301',
          logicalDeviceGeneration: '1',
          providerGeneration: '7',
        },
      },
    });

    let wrongBrandStringCalls = 0;
    Object.defineProperty(firstShader, 'toString', {
      configurable: true,
      value() {
        wrongBrandStringCalls += 1;
        return 'auto';
      },
    });
    expect(() => firstDevice.createRenderPipeline({
      layout: firstShader,
      vertex: { module: firstShader },
    })).toThrow(TypeError);
    expect(wrongBrandStringCalls).toBe(0);

    const foreignBridge = createFakeBridge();
    const foreignCodecs = createFakeCodecs();
    const foreignBinding = createProductionWebGpuPrivateBinding(
      foreignBridge,
      foreignCodecs,
      { enableStateInspection: true },
    );
    const foreignDevice = await requestTestRecordingDevice(foreignBinding);
    const foreignLayout = foreignDevice.createPipelineLayout({
      bindGroupLayouts: [],
    });
    let foreignLayoutStringCalls = 0;
    Object.defineProperty(foreignLayout, 'toString', {
      configurable: true,
      value() {
        foreignLayoutStringCalls += 1;
        return 'auto';
      },
    });
    const beforeForeign = inspectBinding(binding).current;
    const encodingsBeforeForeign = codecs.encodings.length;
    const submissionsBeforeForeign = bridge.submissions.length;
    expect(() => firstDevice.createRenderPipeline({
      layout: foreignLayout,
      vertex: { module: firstShader },
    })).toThrow(TypeError);
    expect(foreignLayoutStringCalls).toBe(0);
    expect(codecs.encodings).toHaveLength(encodingsBeforeForeign);
    expect(bridge.submissions).toHaveLength(submissionsBeforeForeign);
    expect(inspectBinding(binding).current.allocatedWrapperCount).toBe(
      beforeForeign.allocatedWrapperCount,
    );

    foreignBinding.revoke();
    binding.revoke();
  });

  test('seals the promoted command program with active identities, copied overloads, and full lineage without provider dispatch', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    const layout = device.createBindGroupLayout({
      entries: [{
        binding: 0,
        visibility: 7,
        buffer: { hasDynamicOffset: true, minBindingSize: 16 },
      }],
    });
    const uniformBuffer = device.createBuffer({ size: 64, usage: 64 });
    const bindGroup = device.createBindGroup({
      layout,
      entries: [{
        binding: 0,
        resource: { buffer: uniformBuffer, offset: 8, size: 4 },
      }],
    });
    const copySource = device.createBuffer({ size: 64, usage: 4 });
    const copyDestination = device.createBuffer({ size: 64, usage: 40 });
    const sourceTexture = device.createTexture({
      format: 'rgba8unorm',
      size: [16, 16, 1],
      usage: 1,
    });
    const destinationTexture = device.createTexture({
      format: 'rgba8unorm',
      size: [16, 16, 1],
      usage: 2,
    });
    const querySet = device.createQuerySet({
      count: 4,
      type: 'occlusion',
    });
    const queryResolveBuffer = device.createBuffer({
      size: 2_048,
      usage: 512,
    });
    const indexIndirectBuffer = device.createBuffer({
      size: 2_048,
      usage: 16 | 256,
    });
    const shader = device.createShaderModule({ code: '@vertex fn main() {}' });
    const renderPipeline = device.createRenderPipeline({
      layout: 'auto',
      vertex: { module: shader },
    });
    const encoder = device.createCommandEncoder({ label: 'staged-program' });
    const submissionsBeforeRecording = bridge.submissions.length;

    encoder.clearBuffer(copyDestination, 0, 4);
    encoder.copyBufferToBuffer(copySource, copyDestination, 8);
    encoder.copyBufferToBuffer(copySource, 4, copyDestination, 8, 4);
    const sourceOrigin = [1, 2, 0];
    const copyExtent = [4, 5, 1];
    encoder.copyTextureToTexture(
      { texture: sourceTexture, origin: sourceOrigin },
      { texture: destinationTexture, origin: { x: 2, y: 1, z: 0 } },
      copyExtent,
    );
    encoder.resolveQuerySet(querySet, 0, 1, queryResolveBuffer, 0);
    sourceOrigin[0] = 9;
    copyExtent[0] = 10;

    const renderPass = encoder.beginRenderPass({ colorAttachments: [] });
    const renderOffsets = new Uint32Array([99, 40, 99]);
    renderPass.setBindGroup(0, bindGroup, renderOffsets, 1, 1);
    renderOffsets[1] = 41;
    renderPass.setVertexBuffer(0, copyDestination, 0, 8);
    renderPass.setPipeline(renderPipeline);
    renderPass.setIndexBuffer(indexIndirectBuffer, 'uint16', 0);
    renderPass.drawIndexed(3);
    renderPass.drawIndirect(indexIndirectBuffer, 0);
    renderPass.end();

    const computePass = encoder.beginComputePass({ label: 'dormant-\ud800-compute' });
    const computeOffsets = [40];
    computePass.setBindGroup(0, bindGroup, computeOffsets);
    computeOffsets[0] = 41;
    // No compute-pipeline wrapper is mintable in this staged milestone. A
    // branded render pipeline is captured but fails closed as a logical error.
    computePass.setPipeline(renderPipeline);
    computePass.dispatchWorkgroups(2, 3, 4);
    computePass.end();
    const commandBuffer = encoder.finish();

    expect(bridge.submissions).toHaveLength(submissionsBeforeRecording);
    expect(inspectBinding(binding).current.activePassCount).toBe(0);
    device.queue.submit([commandBuffer]);
    expect(bridge.submissions).toHaveLength(submissionsBeforeRecording + 1);

    const submitEncoding = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    );
    if (!submitEncoding) throw new Error('missing queue submit encoding');
    const timeline = localRecords(submitEncoding);
    const programs = commandPrograms(submitEncoding);
    expect(Object.isFrozen(timeline)).toBe(true);
    expect(Object.isFrozen(programs)).toBe(true);
    expect(programs).toHaveLength(1);
    const program = programs[0];
    expect(Object.isFrozen(program)).toBe(true);
    expect(Object.isFrozen(program.commandBuffer)).toBe(true);
    expect(Object.isFrozen(program.records)).toBe(true);
    expect(program.invalid).toBe(true);
    expect(program.records).toHaveLength(timeline.length);
    for (let index = 0; index < timeline.length; index += 1) {
      expect(program.records[index]).toBe(timeline[index]);
    }

    const promotedRecords = timeline.filter(
      (record) => PROMOTED_LOCAL_RECORD_OPERATION_NAMES.has(record.operationName),
    );
    expect(new Set(promotedRecords.map((record) => record.operationName))).toEqual(
      new Set(Object.keys(EXPECTED_STAGED_LOCAL_RECORD_IDENTITIES)),
    );
    for (const record of promotedRecords) {
      const stagedIdentity = EXPECTED_STAGED_LOCAL_RECORD_IDENTITIES[
        record.operationName as keyof typeof EXPECTED_STAGED_LOCAL_RECORD_IDENTITIES
      ];
      const route = WEBGPU_PRODUCTION_PLAN.routes.find(
        (candidate) => candidate.operationId === record.operationName,
      );
      expect(record.recordIdentityClass).toBe('active-route');
      expect(record.operationId).toBe(route?.wireId);
      expect(record.operationId).not.toBe(stagedIdentity.localRecordId);
      expect(record.operationIdentitySha256).toBeNull();
      expect(record.operationInstanceId).toMatch(/^[1-9][0-9]*$/);
      expect(record.deviceIngressOrdinal).toMatch(/^[1-9][0-9]*$/);
      expect(record.capturedScopeId).toBe('0');
      expect(Object.isFrozen(record)).toBe(true);
      expect(Object.isFrozen(record.argumentBody)).toBe(true);
      expect(record.receiverRef).toEqual({
        kind: expect.any(String),
        objectId: expect.any(String),
        objectGeneration: expect.any(String),
        logicalDeviceId: '301',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      });
      expect(route).toBeDefined();
    }

    const beginCompute = promotedRecords.find(
      (record) => record.operationName === 'GPUCommandEncoder.beginComputePass',
    );
    if (!beginCompute) throw new Error('missing beginComputePass record');
    expect(beginCompute.argumentBody.label).toBe('dormant-\ufffd-compute');
    expect(beginCompute.commandEncoderRef).toEqual(beginCompute.receiverRef);
    expect(beginCompute.passRef).toEqual(beginCompute.wrapperAllocatedTargetRef);
    expect(beginCompute.passRef).toMatchObject({
      kind: 'GPUComputePassEncoder',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    for (const record of promotedRecords.filter(
      (candidate) => candidate.operationName.startsWith('GPUComputePassEncoder.'),
    )) {
      expect(record.commandEncoderRef).toEqual(beginCompute.commandEncoderRef);
      expect(record.passRef).toEqual(beginCompute.passRef);
    }

    const bufferCopies = promotedRecords.filter(
      (record) => record.operationName === 'GPUCommandEncoder.copyBufferToBuffer',
    );
    expect(bufferCopies.map((record) => record.argumentBody.overload)).toEqual([
      'short',
      'full',
    ]);
    const textureCopy = promotedRecords.find(
      (record) => record.operationName === 'GPUCommandEncoder.copyTextureToTexture',
    );
    expect(textureCopy?.argumentBody).toMatchObject({
      source: { origin: { x: 1, y: 2, z: 0 } },
      copySize: { width: 4, height: 5, depthOrArrayLayers: 1 },
    });
    const renderBind = promotedRecords.find(
      (record) => record.operationName === 'GPURenderPassEncoder.setBindGroup',
    );
    expect(renderBind?.argumentBody).toMatchObject({
      dynamicOffsets: [40],
      overload: 'uint32-range',
    });
    // The backing-buffer predicate succeeds exactly at 8 + 40 + 16 = 64;
    // the GPUBindingResource.size of 4 is intentionally irrelevant here.
    expect(renderBind?.logicalError).toBeNull();
    const computeBind = promotedRecords.find(
      (record) => record.operationName === 'GPUComputePassEncoder.setBindGroup',
    );
    expect(computeBind?.argumentBody).toMatchObject({
      dynamicOffsets: [40],
      overload: 'iterable',
    });
    const computeEnd = promotedRecords.find(
      (record) => record.operationName === 'GPUComputePassEncoder.end',
    );
    expect(computeEnd?.logicalError).toMatchObject({ name: 'GPUValidationError' });
    expect(computeEnd?.argumentBody.usedBindGroups).toContainEqual(
      computeBind?.argumentBody.bindGroup,
    );
    expect(promotedRecords.find(
      (record) => record.operationName === 'GPUComputePassEncoder.setPipeline',
    )?.logicalError).toMatchObject({ name: 'GPUValidationError' });
    expect(promotedRecords.find(
      (record) => record.operationName === 'GPUComputePassEncoder.dispatchWorkgroups',
    )?.logicalError).toMatchObject({ name: 'GPUValidationError' });

    const submitRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUQueue.submit',
    );
    if (!submitRoute) throw new Error('missing queue submit route');
    const serviceSubmission = bridge.submissions.findLast(
      (submission) => submission.operationId === submitRoute.wireId,
    );
    if (!serviceSubmission) throw new Error('missing queue service submission');
    expect(serviceSubmission.metadata).toMatchObject({
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
      deviceIngressOrdinal: submitEncoding.deviceIngressOrdinal,
      queueIngressOrdinal: submitEncoding.queueIngressOrdinal,
      receiverId: '202',
      receiverGeneration: '1',
    });
    expect(promotedRecords.every(
      (record) => record.operationId !== serviceSubmission.operationId,
    )).toBe(true);
    binding.revoke();
  });

  test('locks before compute timestamp validation and unlocks before invalid and second-end checks', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    const encoder = device.createCommandEncoder();
    const querySet = device.createQuerySet({
      type: 'occlusion',
      count: 1,
    });
    const submissionsBeforeRecording = bridge.submissions.length;
    const pass = encoder.beginComputePass({
      timestampWrites: {
        querySet,
        beginningOfPassWriteIndex: 0,
      },
    });
    expect(inspectBinding(binding).current.activePassCount).toBe(1);
    expect(bridge.submissions).toHaveLength(submissionsBeforeRecording);
    pass.end();
    expect(inspectBinding(binding).current.activePassCount).toBe(0);
    pass.end();
    expect(inspectBinding(binding).current.activePassCount).toBe(0);
    const commandBuffer = encoder.finish();
    device.queue.submit([commandBuffer]);

    const submitEncoding = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    );
    if (!submitEncoding) throw new Error('missing queue submit encoding');
    const computeRecords = localRecords(submitEncoding).filter(
      (record) =>
        record.operationName === 'GPUCommandEncoder.beginComputePass' ||
        record.operationName === 'GPUComputePassEncoder.end',
    );
    expect(computeRecords.map((record) => record.operationName)).toEqual([
      'GPUCommandEncoder.beginComputePass',
      'GPUComputePassEncoder.end',
      'GPUComputePassEncoder.end',
    ]);
    expect(computeRecords[0].logicalError).toMatchObject({
      name: 'GPUValidationError',
      message: expect.stringContaining('timestamp'),
    });
    expect(computeRecords[1].logicalError).toMatchObject({
      name: 'GPUValidationError',
      message: 'Compute pass is invalid',
    });
    expect(computeRecords[2].logicalError).toMatchObject({
      name: 'GPUValidationError',
      message: 'Compute pass already ended',
    });
    expect(computeRecords[1].passRef).toEqual(computeRecords[0].passRef);
    expect(computeRecords[2].passRef).toEqual(computeRecords[0].passRef);
    binding.revoke();
  });

  test('converts pass timestamp dictionaries exactly once before wrong-brand rejection and leaves encoders unlocked', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    const encoder = device.createCommandEncoder();
    const wrongBrandedQuerySet = device.createBuffer({ size: 16, usage: 8 });
    const baseline = inspectBinding(binding).current;
    const submissionCount = bridge.submissions.length;
    const encodingCount = codecs.encodings.length;

    const timestampDescriptor = (
      prefix: string,
      candidate: unknown,
      reads: string[],
    ) => {
      const descriptor = Object.create(null);
      for (const [name, value] of [
        ['beginningOfPassWriteIndex', 0],
        ['endOfPassWriteIndex', 1],
        ['querySet', candidate],
      ] as const) {
        Object.defineProperty(descriptor, name, {
          get() {
            reads.push(`${prefix}.timestampWrites.${name}`);
            return value;
          },
        });
      }
      return descriptor;
    };
    const computeDescriptor = (candidate: unknown, reads: string[]) => {
      const descriptor = Object.create(null);
      for (const [name, value] of [
        ['label', 'compute-brand-rejection'],
        ['timestampWrites', timestampDescriptor('compute', candidate, reads)],
      ] as const) {
        Object.defineProperty(descriptor, name, {
          get() {
            reads.push(`compute.${name}`);
            return value;
          },
        });
      }
      return descriptor;
    };
    const renderDescriptor = (candidate: unknown, reads: string[]) => {
      const descriptor = Object.create(null);
      for (const [name, value] of [
        ['label', 'render-brand-rejection'],
        ['colorAttachments', []],
        ['timestampWrites', timestampDescriptor('render', candidate, reads)],
      ] as const) {
        Object.defineProperty(descriptor, name, {
          get() {
            reads.push(`render.${name}`);
            return value;
          },
        });
      }
      return descriptor;
    };

    for (const candidate of [{}, wrongBrandedQuerySet]) {
      const computeReads: string[] = [];
      expect(() =>
        encoder.beginComputePass(
          computeDescriptor(candidate, computeReads),
        )).toThrow(TypeError);
      expect(computeReads).toEqual([
        'compute.label',
        'compute.timestampWrites',
        'compute.timestampWrites.beginningOfPassWriteIndex',
        'compute.timestampWrites.endOfPassWriteIndex',
        'compute.timestampWrites.querySet',
      ]);

      const renderReads: string[] = [];
      expect(() =>
        encoder.beginRenderPass(
          renderDescriptor(candidate, renderReads),
        )).toThrow(TypeError);
      expect(renderReads).toEqual([
        'render.label',
        'render.colorAttachments',
        'render.timestampWrites',
        'render.timestampWrites.beginningOfPassWriteIndex',
        'render.timestampWrites.endOfPassWriteIndex',
        'render.timestampWrites.querySet',
      ]);
    }
    const after = inspectBinding(binding).current;
    expect(after.activePassCount).toBe(0);
    expect(after.allocatedWrapperCount).toBe(baseline.allocatedWrapperCount);
    expect(after.pendingLocalRecordCount).toBe(baseline.pendingLocalRecordCount);
    expect(bridge.submissions).toHaveLength(submissionCount);
    expect(codecs.encodings).toHaveLength(encodingCount);
    binding.revoke();
  });

  test('retains exact Bone Tide render and compute timestamp references and indices', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    const querySet = device.createQuerySet({
      count: 2,
      label: 'bone-tide-timestamps',
      type: 'timestamp',
    });
    const querySetEncoding = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUDevice.createQuerySet',
    );
    if (!querySetEncoding?.target) {
      throw new Error('missing Bone Tide query-set target');
    }
    const querySetReference = querySetEncoding.target;
    expect(Object.keys(querySetReference).sort()).toEqual([
      'kind',
      'logicalDeviceGeneration',
      'logicalDeviceId',
      'objectGeneration',
      'objectId',
      'providerGeneration',
    ]);

    const encoder = device.createCommandEncoder({ label: 'bone-tide-encoder' });
    const frameBegin = encoder.beginRenderPass({
      label: 'bone-tide-frame-begin',
      colorAttachments: [],
      timestampWrites: {
        querySet,
        beginningOfPassWriteIndex: 0,
      },
    });
    frameBegin.end();
    const frameEnd = encoder.beginRenderPass({
      label: 'bone-tide-frame-end',
      colorAttachments: [],
      timestampWrites: {
        querySet,
        endOfPassWriteIndex: 1,
      },
    });
    frameEnd.end();
    const compute = encoder.beginComputePass({
      label: 'bone-tide-compute',
      timestampWrites: {
        querySet,
        beginningOfPassWriteIndex: 0,
        endOfPassWriteIndex: 1,
      },
    });
    compute.end();
    device.queue.submit([encoder.finish()]);

    const submitEncoding = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    );
    if (!submitEncoding) throw new Error('missing Bone Tide queue submission');
    const beginRecords = localRecords(submitEncoding).filter(
      (record) =>
        record.operationName === 'GPUCommandEncoder.beginRenderPass' ||
        record.operationName === 'GPUCommandEncoder.beginComputePass',
    );
    expect(beginRecords).toHaveLength(3);
    expect(beginRecords.every((record) => record.logicalError === null)).toBe(
      true,
    );
    expect(beginRecords.map((record) => record.argumentBody)).toEqual([
      {
        label: 'bone-tide-frame-begin',
        colorAttachments: [],
        timestampWrites: {
          beginningOfPassWriteIndex: 0,
          endOfPassWriteIndex: null,
          querySet: querySetReference,
        },
      },
      {
        label: 'bone-tide-frame-end',
        colorAttachments: [],
        timestampWrites: {
          beginningOfPassWriteIndex: null,
          endOfPassWriteIndex: 1,
          querySet: querySetReference,
        },
      },
      {
        label: 'bone-tide-compute',
        timestampWrites: {
          beginningOfPassWriteIndex: 0,
          endOfPassWriteIndex: 1,
          querySet: querySetReference,
        },
      },
    ]);
    binding.revoke();
  });

  test('applies every timestamp-write semantic gate after locking render and compute passes', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs([], { distinctLiveDevices: true });
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const firstDevice = await requestTestRecordingDevice(binding);
    const secondDevice = await requestTestRecordingDevice(binding);
    const firstTimestamp = firstDevice.createQuerySet({
      count: 2,
      label: 'first-timestamp',
      type: 'timestamp',
    });
    const firstOcclusion = firstDevice.createQuerySet({
      count: 2,
      label: 'first-occlusion',
      type: 'occlusion',
    });
    const foreignTimestamp = secondDevice.createQuerySet({
      count: 2,
      label: 'foreign-timestamp',
      type: 'timestamp',
    });
    const queryReferences = new Map(
      codecs.encodings
        .filter((encoding) => encoding.operationId === 'GPUDevice.createQuerySet')
        .map((encoding) => [
          (encoding.convertedArguments as { label: string }).label,
          encoding.target,
        ]),
    );
    const cases = [
      {
        name: 'wrong-type',
        querySet: firstOcclusion,
        queryLabel: 'first-occlusion',
        beginningOfPassWriteIndex: 0,
        endOfPassWriteIndex: undefined,
      },
      {
        name: 'missing-indices',
        querySet: firstTimestamp,
        queryLabel: 'first-timestamp',
        beginningOfPassWriteIndex: undefined,
        endOfPassWriteIndex: undefined,
      },
      {
        name: 'out-of-range',
        querySet: firstTimestamp,
        queryLabel: 'first-timestamp',
        beginningOfPassWriteIndex: 2,
        endOfPassWriteIndex: undefined,
      },
      {
        name: 'duplicate-indices',
        querySet: firstTimestamp,
        queryLabel: 'first-timestamp',
        beginningOfPassWriteIndex: 0,
        endOfPassWriteIndex: 0,
      },
      {
        name: 'foreign-device',
        querySet: foreignTimestamp,
        queryLabel: 'foreign-timestamp',
        beginningOfPassWriteIndex: 0,
        endOfPassWriteIndex: undefined,
      },
    ] as const;
    const commandBuffers: object[] = [];
    for (const passKind of ['render', 'compute'] as const) {
      for (const row of cases) {
        const encoder = firstDevice.createCommandEncoder();
        const timestampWrites = {
          querySet: row.querySet,
          beginningOfPassWriteIndex: row.beginningOfPassWriteIndex,
          endOfPassWriteIndex: row.endOfPassWriteIndex,
        };
        const pass = passKind === 'render'
          ? encoder.beginRenderPass({
            label: `${passKind}-${row.name}`,
            colorAttachments: [],
            timestampWrites,
          })
          : encoder.beginComputePass({
            label: `${passKind}-${row.name}`,
            timestampWrites,
          });
        expect(inspectBinding(binding).current.activePassCount).toBe(1);
        pass.end();
        expect(inspectBinding(binding).current.activePassCount).toBe(0);
        commandBuffers.push(encoder.finish());
      }
    }
    firstDevice.queue.submit(commandBuffers);

    const submitEncoding = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    );
    if (!submitEncoding) throw new Error('missing timestamp-gate submission');
    const beginRecords = localRecords(submitEncoding).filter(
      (record) =>
        record.operationName === 'GPUCommandEncoder.beginRenderPass' ||
        record.operationName === 'GPUCommandEncoder.beginComputePass',
    );
    expect(beginRecords).toHaveLength(cases.length * 2);
    for (const passKind of ['render', 'compute'] as const) {
      for (const row of cases) {
        const record = beginRecords.find(
          (candidate) =>
            (candidate.argumentBody as { label: string }).label ===
              `${passKind}-${row.name}`,
        );
        if (!record) throw new Error(`missing ${passKind}-${row.name} record`);
        expect(record.logicalError).toMatchObject({
          name: 'GPUValidationError',
          message: expect.stringContaining('timestamp'),
        });
        expect(record.argumentBody).toMatchObject({
          timestampWrites: {
            beginningOfPassWriteIndex:
              row.beginningOfPassWriteIndex ?? null,
            endOfPassWriteIndex: row.endOfPassWriteIndex ?? null,
            querySet: queryReferences.get(row.queryLabel),
          },
        });
      }
    }
    binding.revoke();
  });

  test('preserves the exact sealed prefix and command program across bridge rejection', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    const buffer = device.createBuffer({ size: 64, usage: 8 });
    const encoder = device.createCommandEncoder();
    const suffixEncoder = device.createCommandEncoder();
    encoder.clearBuffer(buffer, 0, 4);
    const commandBuffer = encoder.finish();
    const pendingPrefixLength = inspectBinding(binding).current.pendingLocalRecordCount;
    expect(pendingPrefixLength).toBe(2);
    const submitRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUQueue.submit',
    );
    if (!submitRoute) throw new Error('missing queue submit route');
    bridge.setSubmitHook((operationId) =>
      operationId === submitRoute.wireId ? 7 : undefined
    );
    expect(() => device.queue.submit([commandBuffer])).toThrow(
      'semantic service rejected GPUQueue.submit (7)',
    );
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(
      pendingPrefixLength,
    );
    const rejected = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    );
    if (!rejected) throw new Error('missing rejected queue encoding');

    let appendedDuringAcceptedSubmit = false;
    bridge.setSubmitHook((operationId) => {
      if (
        operationId === submitRoute.wireId &&
        !appendedDuringAcceptedSubmit
      ) {
        appendedDuringAcceptedSubmit = true;
        suffixEncoder.clearBuffer(buffer, 0, 4);
      }
      return undefined;
    });
    device.queue.submit([commandBuffer]);
    const accepted = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    );
    if (!accepted || accepted === rejected) {
      throw new Error('missing accepted queue encoding');
    }
    expect(appendedDuringAcceptedSubmit).toBe(true);
    // Acceptance removes exactly the immutable prefix captured for that
    // submission. A record appended synchronously after capture survives.
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(1);
    expect(accepted.deviceIngressOrdinal).not.toBe(rejected.deviceIngressOrdinal);
    expect(accepted.queueIngressOrdinal).not.toBe(rejected.queueIngressOrdinal);
    expect(localRecords(accepted)).toEqual(localRecords(rejected));
    expect(commandPrograms(accepted)).toEqual(commandPrograms(rejected));
    for (let index = 0; index < localRecords(rejected).length; index += 1) {
      expect(localRecords(accepted)[index]).toBe(localRecords(rejected)[index]);
      expect(commandPrograms(accepted)[0].records[index]).toBe(
        commandPrograms(rejected)[0].records[index],
      );
    }
    const queueSubmissions = bridge.submissions.filter(
      (submission) => submission.operationId === submitRoute.wireId,
    );
    expect(queueSubmissions).toHaveLength(2);
    expect(queueSubmissions[0].metadata).toMatchObject({
      deviceIngressOrdinal: rejected.deviceIngressOrdinal,
      queueIngressOrdinal: rejected.queueIngressOrdinal,
      receiverId: '202',
    });
    expect(queueSubmissions[1].metadata).toMatchObject({
      deviceIngressOrdinal: accepted.deviceIngressOrdinal,
      queueIngressOrdinal: accepted.queueIngressOrdinal,
      receiverId: '202',
    });
    bridge.setSubmitHook(undefined);
    device.queue.submit([]);
    const suffixFlush = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    );
    if (!suffixFlush || suffixFlush === accepted) {
      throw new Error('missing suffix flush');
    }
    expect(localRecords(suffixFlush)).toHaveLength(1);
    expect(localRecords(suffixFlush)[0].operationName).toBe(
      'GPUCommandEncoder.clearBuffer',
    );
    expect(localRecords(suffixFlush)[0]).not.toBe(localRecords(accepted)[0]);
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
    binding.revoke();
  });

  test('records the TypeGPU query and indexed-draw path with full references, signed base vertex, and omitted index size', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    const querySet = device.createQuerySet({
      count: 4,
      label: 'typegpu-query-set',
      type: 'occlusion',
    });
    const sharedBuffer = device.createBuffer({
      label: 'typegpu-index-indirect-query-buffer',
      size: 2_048,
      usage: 16 | 256 | 512,
    });
    const shader = device.createShaderModule({
      code: '@vertex fn main() {}',
    });
    const pipeline = device.createRenderPipeline({
      layout: 'auto',
      vertex: { module: shader },
    });
    const encoder = device.createCommandEncoder({ label: 'typegpu-encoder' });
    encoder.resolveQuerySet(querySet, 1, 2, sharedBuffer, 256);
    const pass = encoder.beginRenderPass({ colorAttachments: [] });
    pass.setPipeline(pipeline);
    pass.setIndexBuffer(sharedBuffer, 'uint16', 0);
    pass.drawIndexed(3, 2, 1, -7, 4);
    pass.drawIndirect(sharedBuffer, 512);
    pass.end();
    const commandBuffer = encoder.finish();

    const submissionCount = bridge.submissions.length;
    device.queue.submit([commandBuffer]);
    expect(bridge.submissions).toHaveLength(submissionCount + 1);
    const submitEncoding = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    );
    if (!submitEncoding) throw new Error('missing TypeGPU queue submission');
    const records = localRecords(submitEncoding);
    const byName = new Map(
      records.map((record) => [record.operationName, record]),
    );
    for (const operationName of [
      'GPUCommandEncoder.resolveQuerySet',
      'GPURenderPassEncoder.drawIndexed',
      'GPURenderPassEncoder.drawIndirect',
      'GPURenderPassEncoder.setIndexBuffer',
    ]) {
      const record = byName.get(operationName);
      expect(record).toBeDefined();
      expect(record?.recordIdentityClass).toBe('active-route');
      expect(record?.operationId).toBe(
        WEBGPU_PRODUCTION_PLAN.routes.find(
          (route) => route.operationId === operationName,
        )?.wireId,
      );
      expect(record?.logicalError).toBeNull();
    }
    expect(byName.get('GPUCommandEncoder.resolveQuerySet')?.argumentBody)
      .toMatchObject({
        querySet: {
          kind: 'GPUQuerySet',
          logicalDeviceId: '301',
          logicalDeviceGeneration: '1',
          providerGeneration: '7',
        },
        firstQuery: 1,
        queryCount: 2,
        destination: {
          kind: 'GPUBuffer',
          logicalDeviceId: '301',
          logicalDeviceGeneration: '1',
          providerGeneration: '7',
        },
        destinationOffset: 256,
      });
    expect(byName.get('GPURenderPassEncoder.setIndexBuffer')?.argumentBody)
      .toMatchObject({
        buffer: {
          kind: 'GPUBuffer',
          logicalDeviceId: '301',
          logicalDeviceGeneration: '1',
          providerGeneration: '7',
        },
        indexFormat: 'uint16',
        offset: 0,
        sizePresent: false,
        size: 0,
      });
    expect(byName.get('GPURenderPassEncoder.drawIndexed')?.argumentBody)
      .toEqual({
        indexCount: 3,
        instanceCount: 2,
        firstIndex: 1,
        baseVertex: -7,
        firstInstance: 4,
      });
    expect(byName.get('GPURenderPassEncoder.drawIndirect')?.argumentBody)
      .toMatchObject({
        indirectBuffer: {
          kind: 'GPUBuffer',
          logicalDeviceId: '301',
          logicalDeviceGeneration: '1',
          providerGeneration: '7',
        },
        indirectOffset: 512,
      });
    binding.revoke();
  });

  test('gates timestamp query sets before target allocation, ingress consumption, or service submission', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs([], { omitDeviceFeatures: true });
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    const before = inspectBinding(binding).current;
    const submissionCount = bridge.submissions.length;
    const encodingCount = codecs.encodings.length;
    expect(() => device.createQuerySet({
      count: 2,
      label: 'unsupported-timestamp-query',
      type: 'timestamp',
    })).toThrow('requires feature timestamp-query');
    expect(inspectBinding(binding).current.allocatedWrapperCount).toBe(
      before.allocatedWrapperCount,
    );
    expect(bridge.submissions).toHaveLength(submissionCount);
    expect(codecs.encodings).toHaveLength(encodingCount);

    device.createQuerySet({
      count: 2,
      label: 'supported-occlusion-query',
      type: 'occlusion',
    });
    const submitted = bridge.submissions.findLast(
      (submission) =>
        submission.operationId === WEBGPU_PRODUCTION_PLAN.routes.find(
          (route) => route.operationId === 'GPUDevice.createQuerySet',
        )?.wireId,
    );
    expect(submitted?.metadata.deviceIngressOrdinal).toBe('1');
    const encoded = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUDevice.createQuerySet',
    );
    expect(encoded).toMatchObject({
      convertedArguments: {
        count: 2,
        label: 'supported-occlusion-query',
        type: 'occlusion',
      },
      target: {
        kind: 'GPUQuerySet',
        logicalDeviceId: '301',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
    });
    binding.revoke();
  });

  test('transports source-affine error-scope transitions and seals the pop timeline', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    device.pushErrorScope('validation');
    const pushed = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUDevice.pushErrorScope',
    );
    if (!pushed) throw new Error('missing pushErrorScope encoding');
    expect(pushed).toMatchObject({
      convertedArguments: 'validation',
      capturedScopeId: '0',
      errorScopeService: {
        kind: 'push-error-scope-v1',
        scopeId: '1',
        filter: 'validation',
        scopeStackGeneration: '1',
        precedingScopeId: '0',
      },
    });
    expect(pushed.sealedLocalTimeline).toEqual([]);
    expect(
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        bridge.submissions.findLast(
          (submission) =>
            submission.operationId === WEBGPU_PRODUCTION_PLAN.routes.find(
              (route) => route.operationId === 'GPUDevice.pushErrorScope',
            )?.wireId,
        )!.payload,
      ),
    ).toMatchObject({
      convertedArguments: 'validation',
      capturedScopeId: '0',
      errorScopeService: {
        kind: 'push-error-scope-v1',
        scopeId: '1',
        filter: 'validation',
        scopeStackGeneration: '1',
        precedingScopeId: '0',
      },
      sealedLocalTimeline: [],
    });

    const destination = device.createBuffer({ size: 16, usage: 8 });
    const encoder = device.createCommandEncoder();
    encoder.clearBuffer(destination, 0, 4);
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(1);
    expect(await device.popErrorScope()).toBeNull();
    const popped = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUDevice.popErrorScope',
    );
    if (!popped) throw new Error('missing popErrorScope encoding');
    expect(popped).toMatchObject({
      convertedArguments: null,
      capturedScopeId: '1',
      errorScopeService: {
        kind: 'pop-error-scope-v1',
        scopeId: '1',
        scopeStackGeneration: '2',
      },
    });
    expect(localRecords(popped)).toHaveLength(1);
    expect(localRecords(popped)[0]).toMatchObject({
      operationName: 'GPUCommandEncoder.clearBuffer',
      capturedScopeId: '1',
      logicalError: null,
    });
    const popSubmission = bridge.submissions.findLast(
      (submission) =>
        submission.operationId === WEBGPU_PRODUCTION_PLAN.routes.find(
          (route) => route.operationId === 'GPUDevice.popErrorScope',
        )?.wireId,
    );
    if (!popSubmission) throw new Error('missing popErrorScope submission');
    expect(
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        popSubmission.payload,
      ),
    ).toMatchObject({
      convertedArguments: null,
      capturedScopeId: '1',
      errorScopeService: {
        kind: 'pop-error-scope-v1',
        scopeId: '1',
        scopeStackGeneration: '2',
      },
      sealedLocalTimeline: [{
        operationName: 'GPUCommandEncoder.clearBuffer',
        capturedScopeId: '1',
      }],
    });
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
    binding.revoke();
  });

  test('captures and removes the popped scope before a same-job push', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);

    device.pushErrorScope('validation');
    const popped = device.popErrorScope();
    device.pushErrorScope('internal');

    const transitions = codecs.encodings.filter(
      (encoding) =>
        encoding.operationId === 'GPUDevice.pushErrorScope' ||
        encoding.operationId === 'GPUDevice.popErrorScope',
    );
    expect(transitions).toHaveLength(3);
    expect(transitions[1]).toMatchObject({
      operationId: 'GPUDevice.popErrorScope',
      capturedScopeId: '1',
      errorScopeService: {
        kind: 'pop-error-scope-v1',
        scopeId: '1',
        scopeStackGeneration: '2',
      },
    });
    expect(transitions[2]).toMatchObject({
      operationId: 'GPUDevice.pushErrorScope',
      convertedArguments: 'internal',
      capturedScopeId: '0',
      errorScopeService: {
        kind: 'push-error-scope-v1',
        scopeId: '2',
        filter: 'internal',
        scopeStackGeneration: '3',
        precedingScopeId: '0',
      },
    });
    expect(await popped).toBeNull();
    binding.revoke();
  });

  test('rejects a live empty pop without submitting or consuming service ingress', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    const submissionCount = bridge.submissions.length;
    const encodingCount = codecs.encodings.length;

    const emptyPop = device.popErrorScope();
    const emptyRejection = expect(emptyPop).rejects.toMatchObject({
      name: 'OperationError',
    });
    expect(bridge.submissions).toHaveLength(submissionCount);
    expect(codecs.encodings).toHaveLength(encodingCount);
    await emptyRejection;

    device.pushErrorScope('validation');
    expect(bridge.submissions.at(-1)?.metadata.deviceIngressOrdinal).toBe('1');
    expect(codecs.encodings.at(-1)).toMatchObject({
      operationId: 'GPUDevice.pushErrorScope',
      errorScopeService: {
        scopeId: '1',
        scopeStackGeneration: '1',
        precedingScopeId: '0',
      },
    });
    binding.revoke();
  });

  test('resolves a lost-device pop without submission and still mirrors lost pushes', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    device.pushErrorScope('validation');
    emitProviderLoss(bridge);
    await device.lost;
    const submissionCount = bridge.submissions.length;
    const encodingCount = codecs.encodings.length;

    const lostPop = device.popErrorScope();
    expect(bridge.submissions).toHaveLength(submissionCount);
    expect(codecs.encodings).toHaveLength(encodingCount);
    expect(await lostPop).toBeNull();

    device.pushErrorScope('internal');
    expect(bridge.submissions.at(-1)?.metadata.deviceIngressOrdinal).toBe('2');
    expect(codecs.encodings.at(-1)).toMatchObject({
      operationId: 'GPUDevice.pushErrorScope',
      convertedArguments: 'internal',
      capturedScopeId: '0',
      errorScopeService: {
        kind: 'push-error-scope-v1',
        scopeId: '2',
        filter: 'internal',
        scopeStackGeneration: '3',
        precedingScopeId: '0',
      },
    });

    device.pushErrorScope('out-of-memory');
    expect(bridge.submissions.at(-1)?.metadata.deviceIngressOrdinal).toBe('3');
    expect(codecs.encodings.at(-1)).toMatchObject({
      operationId: 'GPUDevice.pushErrorScope',
      convertedArguments: 'out-of-memory',
      capturedScopeId: '2',
      errorScopeService: {
        kind: 'push-error-scope-v1',
        scopeId: '3',
        filter: 'out-of-memory',
        scopeStackGeneration: '4',
        precedingScopeId: '2',
      },
    });
    binding.revoke();
  });

  test('records cross-device and expired references as logical errors while rejecting foreign brands and bad ranges before counters', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs([], { distinctLiveDevices: true });
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const firstDevice = await requestTestRecordingDevice(binding);
    const secondDevice = await requestTestRecordingDevice(binding);
    const firstLayout = firstDevice.createBindGroupLayout({
      entries: [{
        binding: 0,
        visibility: 7,
        buffer: { hasDynamicOffset: true, minBindingSize: 16 },
      }],
    });
    const firstUniform = firstDevice.createBuffer({ size: 64, usage: 64 });
    const firstGroup = firstDevice.createBindGroup({
      layout: firstLayout,
      entries: [{ binding: 0, resource: { buffer: firstUniform, offset: 8 } }],
    });
    const secondLayout = secondDevice.createBindGroupLayout({
      entries: [{
        binding: 0,
        visibility: 7,
        buffer: { hasDynamicOffset: true, minBindingSize: 16 },
      }],
    });
    const secondBuffer = secondDevice.createBuffer({ size: 64, usage: 96 });
    const secondGroup = secondDevice.createBindGroup({
      layout: secondLayout,
      entries: [{ binding: 0, resource: { buffer: secondBuffer, offset: 8 } }],
    });
    const encoder = firstDevice.createCommandEncoder();
    const pass = encoder.beginRenderPass({ colorAttachments: [] });
    const badRange = new Uint32Array([40]);
    const beforeBadRange = inspectBinding(binding).current.pendingLocalRecordCount;
    expect(() => pass.setBindGroup(0, firstGroup, badRange, 1, 1)).toThrow(
      RangeError,
    );
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(
      beforeBadRange,
    );
    pass.setBindGroup(0, firstGroup, [41]);
    pass.setBindGroup(1, secondGroup, [40]);
    pass.setVertexBuffer(0, secondBuffer, 0, 8);

    const foreignBinding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const foreignDevice = await requestTestRecordingDevice(foreignBinding);
    const foreignBuffer = foreignDevice.createBuffer({ size: 64, usage: 32 });
    const beforeForeignBrand = inspectBinding(binding).current.pendingLocalRecordCount;
    expect(() => pass.setVertexBuffer(0, foreignBuffer, 0, 8)).toThrow(TypeError);
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(
      beforeForeignBrand,
    );
    pass.end();
    const commandBuffer = encoder.finish();
    firstDevice.queue.submit([commandBuffer]);
    const crossDeviceEncoding = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    );
    if (!crossDeviceEncoding) throw new Error('missing cross-device submit');
    const renderRecords = localRecords(crossDeviceEncoding).filter(
      (record) => PROMOTED_LOCAL_RECORD_OPERATION_NAMES.has(record.operationName),
    );
    const bindRecords = renderRecords.filter(
      (record) => record.operationName === 'GPURenderPassEncoder.setBindGroup',
    );
    expect(bindRecords).toHaveLength(2);
    expect(bindRecords[0].logicalError).toMatchObject({ name: 'GPUValidationError' });
    expect(bindRecords[0].argumentBody).toMatchObject({ dynamicOffsets: [41] });
    expect(bindRecords[1].logicalError).toMatchObject({ name: 'GPUValidationError' });
    expect(bindRecords[1].argumentBody.bindGroup).toMatchObject({
      kind: 'GPUBindGroup',
      logicalDeviceId: '311',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    const crossVertex = renderRecords.find(
      (record) => record.operationName === 'GPURenderPassEncoder.setVertexBuffer',
    );
    expect(crossVertex?.logicalError).toMatchObject({ name: 'GPUValidationError' });
    expect(crossVertex?.argumentBody.buffer).toMatchObject({
      kind: 'GPUBuffer',
      logicalDeviceId: '311',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });

    const context = mintTestCanvasContext(binding);
    context.configure({
      device: firstDevice,
      format: 'bgra8unorm',
      usage: 17,
    });
    const expiredTexture = context.getCurrentTexture();
    context.configure({
      device: firstDevice,
      format: 'bgra8unorm',
      usage: 17,
    });
    const copyDestination = firstDevice.createTexture({
      format: 'rgba8unorm',
      size: [8, 8, 1],
      usage: 2,
    });
    const staleEncoder = firstDevice.createCommandEncoder();
    staleEncoder.copyTextureToTexture(
      { texture: expiredTexture },
      { texture: copyDestination },
      [1, 1, 1],
    );
    const staleCommandBuffer = staleEncoder.finish();
    firstDevice.queue.submit([staleCommandBuffer]);
    const staleEncoding = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    );
    if (!staleEncoding || staleEncoding === crossDeviceEncoding) {
      throw new Error('missing stale-reference submit');
    }
    const staleCopy = localRecords(staleEncoding).find(
      (record) => record.operationName === 'GPUCommandEncoder.copyTextureToTexture',
    );
    expect(staleCopy?.logicalError).toMatchObject({ name: 'GPUValidationError' });
    expect(staleCopy?.argumentBody.source).toMatchObject({
      texture: {
        kind: 'GPUTexture',
        logicalDeviceId: '301',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
    });
    foreignBinding.revoke();
    binding.revoke();
  });

  test('enforces the authenticated 1,024-record bound before counter mutation or provider work', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    const buffer = device.createBuffer({ size: 4, usage: 8 });
    const encoder = device.createCommandEncoder();
    const submissionsBeforeRecording = bridge.submissions.length;
    for (let index = 0; index < 1_024; index += 1) {
      encoder.clearBuffer(buffer, 0, 4);
    }
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(1_024);
    expect(() => encoder.clearBuffer(buffer, 0, 4)).toThrow(RangeError);
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(1_024);
    expect(bridge.submissions).toHaveLength(submissionsBeforeRecording);
    binding.revoke();
  });

  test('uses the final local-record identity once and closes before a second record', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      {
        counterSeeds: { nextLocalOperationInstanceId: U64_MAX },
        enableStateInspection: true,
      },
    );
    const device = await requestTestRecordingDevice(binding);
    const buffer = device.createBuffer({ size: 4, usage: 8 });
    const encoder = device.createCommandEncoder();
    const submissionsBeforeRecording = bridge.submissions.length;
    encoder.clearBuffer(buffer, 0, 4);
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(1);
    expect(() => encoder.clearBuffer(buffer, 0, 4)).toThrow(RangeError);
    expect(bridge.submissions).toHaveLength(submissionsBeforeRecording);
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
    expect(inspectBinding(binding).lastClose).toMatchObject({
      closeReason: 'counter-exhausted:local operation identity',
      pendingLocalRecordCount: 1,
    });
    binding.revoke();
  });

  test('fails closed on a re-entrant local counter-plan conflict', async () => {
    const bridge = createFakeBridge();
    const baseCodecs = createFakeCodecs();
    let encoder: TestCommandEncoder | undefined;
    let buffer: TestBuffer | undefined;
    let armed = false;
    let reentered = false;
    const codecs: ExecutableWebGpuCodecBundle & {
      readonly encodings: ProductionGpuServiceEncodingInput[];
    } = {
      ...baseCodecs,
      convertPublicArguments(operationId, args, wrappers) {
        if (operationId !== 'GPUCommandEncoder.finish' || !armed) {
          return baseCodecs.convertPublicArguments(operationId, args, wrappers);
        }
        const target = { label: 'outer-finish' };
        return new Proxy(target, {
          ownKeys(value) {
            if (!reentered) {
              reentered = true;
              if (!encoder || !buffer) throw new Error('missing reentry fixtures');
              encoder.clearBuffer(buffer, 0, 4);
            }
            return Reflect.ownKeys(value);
          },
          getOwnPropertyDescriptor(value, property) {
            return Reflect.getOwnPropertyDescriptor(value, property);
          },
        });
      },
    };
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    buffer = device.createBuffer({ size: 4, usage: 8 });
    encoder = device.createCommandEncoder();
    const submissionsBeforeRecording = bridge.submissions.length;
    armed = true;
    expect(() => encoder?.finish()).toThrow(
      'WebGPU local counter plan is stale',
    );
    expect(reentered).toBe(true);
    expect(bridge.submissions).toHaveLength(submissionsBeforeRecording);
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
    expect(inspectBinding(binding).lastClose).toMatchObject({
      closeReason: 'counter-plan-conflict',
      pendingLocalRecordCount: 1,
    });
    binding.revoke();
  });

  test('inherits a route-free EventTarget surface on GPUDevice', async () => {
    const sharedPrototypeFrozenBefore = Object.isFrozen(EventTarget.prototype);
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    const adapter = await (binding.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter() as { requestDevice(): Promise<unknown> };
    const device = await adapter.requestDevice() as EventTarget;
    const gpuDevicePrototype = binding.interfaceObjects.GPUDevice.prototype;
    const eventTargetPrototype = Object.getPrototypeOf(gpuDevicePrototype);
    expect(device).toBeInstanceOf(EventTarget);
    expect(eventTargetPrototype).toBe(EventTarget.prototype);
    expect(Object.hasOwn(gpuDevicePrototype, 'addEventListener')).toBe(false);
    expect(Object.hasOwn(gpuDevicePrototype, 'removeEventListener')).toBe(false);
    expect(Object.hasOwn(gpuDevicePrototype, 'dispatchEvent')).toBe(false);
    expect(Object.getOwnPropertyDescriptor(
      eventTargetPrototype,
      'addEventListener',
    )?.value).toBeFunction();
    expect(Object.isFrozen(EventTarget.prototype)).toBe(
      sharedPrototypeFrozenBefore,
    );
    expect(WEBGPU_PRODUCTION_PLAN.routes.some(
      (route) => route.memberName === 'addEventListener' ||
        route.memberName === 'removeEventListener' ||
        route.memberName === 'dispatchEvent',
    )).toBe(false);

    const calls: string[] = [];
    const listener = function (this: unknown, event: Event): void {
      expect(this).toBe(device);
      expect(event).toBeInstanceOf(Event);
      expect(event.target).toBe(device);
      expect(event.currentTarget).toBe(device);
      calls.push(`function:${event.type}`);
    };
    const onceListener = {
      handleEvent(event: Event): void {
        calls.push(`object:${event.type}`);
      },
    };
    device.addEventListener('uncapturederror', listener);
    device.addEventListener('uncapturederror', listener);
    device.addEventListener('uncapturederror', onceListener, { once: true });
    const firstEvent = new Event('uncapturederror', { cancelable: true });
    expect(device.dispatchEvent(firstEvent)).toBe(true);
    expect(firstEvent.target).toBe(device);
    expect(firstEvent.currentTarget).toBeNull();
    expect(calls).toEqual([
      'function:uncapturederror',
      'object:uncapturederror',
    ]);
    expect(device.dispatchEvent(new Event('uncapturederror'))).toBe(true);
    expect(calls).toEqual([
      'function:uncapturederror',
      'object:uncapturederror',
      'function:uncapturederror',
    ]);
    device.removeEventListener('uncapturederror', listener);
    expect(device.dispatchEvent(new Event('uncapturederror'))).toBe(true);
    expect(calls).toHaveLength(3);

    let signalCalls = 0;
    const controller = new AbortController();
    const signalListener = (): void => {
      signalCalls += 1;
    };
    device.addEventListener('uncapturederror', signalListener, {
      signal: controller.signal,
    });
    controller.abort();
    device.dispatchEvent(new Event('uncapturederror'));
    expect(signalCalls).toBe(0);

    const propagationCalls: string[] = [];
    const stopper = (event: Event): void => {
      propagationCalls.push('stopper');
      event.stopImmediatePropagation();
    };
    const skipped = (): void => {
      propagationCalls.push('skipped');
    };
    device.addEventListener('uncapturederror', stopper);
    device.addEventListener('uncapturederror', skipped);
    expect(device.dispatchEvent(new Event('uncapturederror'))).toBe(true);
    expect(propagationCalls).toEqual(['stopper']);
    device.removeEventListener('uncapturederror', stopper);
    device.removeEventListener('uncapturederror', skipped);

    let redispatchError: unknown;
    const redispatchListener = (event: Event): void => {
      try {
        device.dispatchEvent(event);
      } catch (error) {
        redispatchError = error;
      }
    };
    device.addEventListener('uncapturederror', redispatchListener, { once: true });
    const redispatchEvent = new Event('uncapturederror');
    expect(device.dispatchEvent(redispatchEvent)).toBe(true);
    expect(redispatchError).toMatchObject({ name: 'InvalidStateError' });
    expect(device.dispatchEvent(redispatchEvent)).toBe(true);

    const cancelListener = (event: Event): void => {
      event.preventDefault();
    };
    device.addEventListener('uncapturederror', cancelListener);
    const cancelEvent = new Event('uncapturederror', { cancelable: true });
    expect(device.dispatchEvent(cancelEvent)).toBe(false);
    expect(cancelEvent.defaultPrevented).toBe(true);
    device.removeEventListener('uncapturederror', cancelListener);
    binding.revoke();
  });

  test('keeps canvas epochs stable and settles device loss exactly once', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const gpu = binding.gpu as { requestAdapter(): Promise<unknown> };
    const adapter = (await gpu.requestAdapter()) as {
      requestDevice(): Promise<unknown>;
    };
    const device = (await adapter.requestDevice()) as {
      readonly lost: Promise<unknown>;
    };
    const context = binding.mintCanvasContext({
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: CANVAS_AUTHORITY,
    }) as {
      configure(configuration: unknown): void;
      getConfiguration(): Record<string, unknown> | null;
      getCurrentTexture(): {
        readonly dimension: '2d';
        readonly format: string;
        readonly height: number;
        readonly depthOrArrayLayers: number;
        readonly width: number;
        createView(): object;
        destroy(): void;
      };
      unconfigure(): void;
    };
    context.configure({ device, format: 'bgra8unorm' });
    const firstConfigure = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUCanvasContext.configure',
    );
    expect(firstConfigure?.canvasService).toMatchObject({
      kind: 'canvas-configure-v1',
      receiverContextRef: {
        kind: 'GPUCanvasContext',
        objectId: '401',
        objectGeneration: '1',
        logicalDeviceId: '301',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      attachmentGeneration: '31',
      contextGeneration: '37',
      configurationGeneration: '1',
      configuredDeviceRef: {
        kind: 'GPUDevice',
        objectId: '201',
        objectGeneration: '1',
        logicalDeviceId: '301',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      format: 'bgra8unorm',
      usage: 16,
      viewFormats: [],
      alphaMode: 'opaque',
      colorSpace: 'srgb',
      toneMappingMode: 'standard',
      targetAuthorityDigest: CANVAS_AUTHORITY.targetAuthorityDigest,
      surfaceAccountToken: '41',
      surfaceAccountGeneration: '43',
    });
    const first = context.getCurrentTexture();
    expect(context.getCurrentTexture()).toBe(first);
    expect(first.dimension).toBe('2d');
    expect(first.format).toBe('bgra8unorm');
    expect(first.height).toBe(480);
    expect(first.depthOrArrayLayers).toBe(1);
    expect(first.width).toBe(640);
    expect(first.createView()).toBeObject();
    const createViewWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUTexture.createView',
    )?.wireId;
    if (createViewWireId === undefined) throw new Error('missing createView route');
    const firstSubmission = bridge.submissions.findLast(
      (submission) => submission.operationId === createViewWireId,
    );
    if (!firstSubmission) throw new Error('missing createView submission');
    const firstRequest = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(firstSubmission.payload) as Readonly<{
        receiver: Readonly<Record<string, unknown>>;
        convertedArguments: Readonly<{
          currentOrigin: Readonly<Record<string, unknown>>;
        }>;
      }>;
    const firstOrigin = firstRequest.convertedArguments.currentOrigin;
    expect(firstOrigin).toMatchObject({
      originClass: 'canvas-current',
      contextRef: {
        kind: 'GPUCanvasContext',
        objectId: '401',
        objectGeneration: '1',
        logicalDeviceId: '301',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      attachmentGeneration: '31',
      contextGeneration: '37',
      configurationGeneration: '1',
      currentEpoch: '1',
      mintOperationProvenance: {
        operationInstanceId: '9223372036854775808',
        deviceIngressOrdinal: '2',
      },
      configuredDeviceRef: {
        kind: 'GPUDevice',
        objectId: '201',
        objectGeneration: '1',
        logicalDeviceId: '301',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      format: 'bgra8unorm',
      usage: 16,
      alphaMode: 'opaque',
      colorSpace: 'srgb',
      targetAuthorityDigest: CANVAS_AUTHORITY.targetAuthorityDigest,
      surfaceAccountToken: '41',
      surfaceAccountGeneration: '43',
    });
    expect(firstOrigin.textureOriginDigest).toMatch(/^[0-9a-f]{64}$/u);
    expect(firstOrigin).not.toHaveProperty('receiverTextureRef');
    expect(firstRequest.receiver).toMatchObject({
      kind: 'GPUTexture',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    const snapshot = context.getConfiguration();
    expect(snapshot?.format).toBe('bgra8unorm');
    expect(snapshot).not.toBe(context.getConfiguration());
    context.configure({ device, format: 'bgra8unorm' });
    expect(codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUCanvasContext.configure',
    )?.canvasService).toMatchObject({
      kind: 'canvas-configure-v1',
      configurationGeneration: '2',
    });
    const second = context.getCurrentTexture();
    expect(second).not.toBe(first);
    expect(second.createView()).toBeObject();
    const secondSubmission = bridge.submissions.findLast(
      (submission) => submission.operationId === createViewWireId,
    );
    if (!secondSubmission) throw new Error('missing second createView submission');
    const secondRequest = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(secondSubmission.payload) as Readonly<{
        convertedArguments: Readonly<{
          currentOrigin: Readonly<Record<string, unknown>>;
        }>;
      }>;
    const secondOrigin = secondRequest.convertedArguments.currentOrigin;
    expect(secondOrigin.configurationGeneration).toBe('2');
    expect(secondOrigin.currentEpoch).toBe('2');
    expect(secondOrigin.mintOperationProvenance).not.toEqual(
      firstOrigin.mintOperationProvenance,
    );
    expect(secondOrigin.textureOriginDigest).not.toBe(
      firstOrigin.textureOriginDigest,
    );
    // The private codec may structurally encode an old canvas texture. It
    // must preserve the immutable origin so the eventual semantic executor,
    // rather than a silent wrapper rebind, rejects the stale generation.
    expect(first.createView()).toBeObject();
    const staleSubmission = bridge.submissions.findLast(
      (submission) => submission.operationId === createViewWireId,
    );
    if (!staleSubmission) throw new Error('missing stale createView submission');
    const staleRequest = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(staleSubmission.payload) as Readonly<{
        convertedArguments: Readonly<{
          currentOrigin: Readonly<Record<string, unknown>>;
        }>;
      }>;
    expect(staleRequest.convertedArguments.currentOrigin).toEqual(firstOrigin);
    expect(staleRequest.convertedArguments.currentOrigin).toMatchObject({
      configurationGeneration: '1',
      currentEpoch: '1',
    });
    context.unconfigure();
    const unconfigureEncodings = codecs.encodings.filter(
      (encoding) => encoding.operationId === 'GPUCanvasContext.unconfigure',
    );
    expect(unconfigureEncodings).toHaveLength(1);
    expect(unconfigureEncodings[0]?.convertedArguments).toBeNull();
    expect(unconfigureEncodings[0]?.canvasService).toMatchObject({
      kind: 'canvas-unconfigure-v1',
      receiverContextRef: {
        kind: 'GPUCanvasContext',
        objectId: '401',
        objectGeneration: '1',
      },
      attachmentGeneration: '31',
      contextGeneration: '37',
      configurationGeneration: '2',
      terminalIntent: 'first-cleanup',
      targetAuthorityDigest: CANVAS_AUTHORITY.targetAuthorityDigest,
      surfaceAccountToken: '41',
      surfaceAccountGeneration: '43',
    });
    context.unconfigure();
    expect(codecs.encodings.filter(
      (encoding) => encoding.operationId === 'GPUCanvasContext.unconfigure',
    )).toHaveLength(1);
    expect(() => context.getCurrentTexture()).toThrow('not configured');
    first.destroy();
    first.destroy();
    const firstDestroyEncodings = codecs.encodings.filter(
      (encoding) =>
        encoding.operationId === 'GPUTexture.destroy' &&
        encoding.receiver.objectId === firstRequest.receiver.objectId,
    );
    expect(firstDestroyEncodings).toHaveLength(3);
    expect(firstDestroyEncodings.map((encoding) =>
      encoding.canvasService)).toMatchObject([
      {
        kind: 'texture-expire-v1',
        expiryIntent: 'host-task-expiry',
        materializationState: 'materialized',
      },
      {
        kind: 'texture-destroy-v1',
        terminalIntent: 'repeat-cleanup-noop',
        materializationState: 'materialized',
      },
      {
        kind: 'texture-destroy-v1',
        terminalIntent: 'repeat-cleanup-noop',
        materializationState: 'materialized',
      },
    ]);
    expect(firstDestroyEncodings[0]?.convertedArguments).toBeNull();
    expect(firstDestroyEncodings[0]?.canvasService).toMatchObject({
      kind: 'texture-expire-v1',
      materializationState: 'materialized',
      origin: {
        kind: 'canvas-current-v1',
        contextRef: firstOrigin.contextRef,
        configurationGeneration: '1',
        currentEpoch: '1',
      },
    });
    expect(firstDestroyEncodings[1]?.canvasService).toMatchObject({
      kind: 'texture-destroy-v1',
      materializationState: 'materialized',
      origin: {
        kind: 'canvas-current-v1',
        contextRef: firstOrigin.contextRef,
        attachmentGeneration: '31',
        contextGeneration: '37',
        configurationGeneration: '1',
        currentEpoch: '1',
        mintOperationProvenance: firstOrigin.mintOperationProvenance,
        textureOriginDigest: firstOrigin.textureOriginDigest,
      },
    });

    const lost = device.lost;
    bridge.emit({
      kind: 4,
      runtimeAddress: bridge.runtimeAddress,
      runtimeNonce: bridge.runtimeNonce,
      topologyId: 1,
      realmId: bridge.realmId,
      realmGeneration: bridge.realmGeneration,
      accountId: bridge.rootAccountId,
      accountGeneration: bridge.rootAccountGeneration,
      accountAuthorityDigest: bridge.rootAuthorityDigest,
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
      logicalLossOrdinal: '1',
      lastAcceptedPhysicalSequence: '9',
      backendClass: 1,
      lossReason: 1,
      hasInitiatingOperation: false,
      payload: new Uint8Array(),
    });
    expect(await lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    binding.revoke();
  });

  test('does not publish or consume counters when first presentation capture is denied', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    bridge.setCapturePresentationAuthorityHook(() => null);

    expect(() => context.getCurrentTexture()).toThrow('authority was denied');
    expect(bridge.presentationAuthorityCaptures).toHaveLength(1);
    expect(bridge.presentationAuthorityRetirements).toEqual([]);
    const deniedMetadata = bridge.presentationAuthorityCaptures[0]!.metadata;
    const afterDenied = inspectBinding(binding).current;

    bridge.setCapturePresentationAuthorityHook(undefined);
    const texture = context.getCurrentTexture();
    expect(texture).toBeObject();
    expect(bridge.presentationAuthorityCaptures).toHaveLength(2);
    expect(bridge.presentationAuthorityCaptures[1]!.metadata)
      .toEqual(deniedMetadata);
    expect(inspectBinding(binding).current.allocatedWrapperCount)
      .toBe(afterDenied.allocatedWrapperCount + 1);
    binding.revoke();
  });

  test('retires first presentation capture and closes after a partial wrapper commit', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    bridge.setCapturePresentationAuthorityHook(() => {
      device.createBuffer({ size: 4, usage: 1 });
      return undefined;
    });

    expect(() => context.getCurrentTexture()).toThrow(
      'wrapper allocation plan is stale',
    );
    expect(bridge.presentationAuthorityCaptures).toHaveLength(1);
    expect(bridge.presentationAuthorityRetirements).toHaveLength(1);
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      closeReason: 'wrapper-allocation-plan-conflict',
    });
    binding.revoke();
    expect(bridge.presentationAuthorityRetirements).toHaveLength(1);
  });

  test('does not commit a denied same-epoch recheck and retries the same counters', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    const texture = context.getCurrentTexture();
    bridge.setRecheckPresentationAuthorityHook(() => false);

    expect(() => context.getCurrentTexture()).toThrow('authority was denied');
    expect(bridge.presentationAuthorityRechecks).toHaveLength(1);
    const deniedMetadata = bridge.presentationAuthorityRechecks[0]!.metadata;

    bridge.setRecheckPresentationAuthorityHook(undefined);
    expect(context.getCurrentTexture()).toBe(texture);
    expect(bridge.presentationAuthorityRechecks).toHaveLength(2);
    expect(bridge.presentationAuthorityRechecks[1]!.metadata)
      .toEqual(deniedMetadata);
    texture.createView();
    const createView = codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUTexture.createView',
    );
    if (!createView) throw new Error('missing createView carrier');
    expect(localRecords(createView)).toHaveLength(2);
    binding.revoke();
  });

  test('closes on structurally invalid recheck and retires the live pair once', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    context.getCurrentTexture();
    bridge.setRecheckPresentationAuthorityHook(() => {
      throw new Error('malformed Host output');
    });

    expect(() => context.getCurrentTexture()).toThrow(
      'presentation authority recheck failed',
    );
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      closeReason: 'canvas-presentation-recheck-invalid',
    });
    expect(bridge.presentationAuthorityRetirements).toHaveLength(1);
  });

  test('realm revoke expires every retained presentation pair through source-affine controls', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const firstContext = mintTestCanvasContext(binding);
    const secondContext = mintSecondTestCanvasContext(binding);
    firstContext.configure({ device, format: 'bgra8unorm' });
    secondContext.configure({ device, format: 'rgba8unorm' });
    firstContext.getCurrentTexture();
    secondContext.getCurrentTexture().createView();
    expect(bridge.presentationAuthorityCaptures).toHaveLength(2);

    binding.revoke();
    expect(bridge.presentationAuthorityRetirements).toHaveLength(0);
    const expiryEncodings = codecs.encodings.filter(
      (encoding) => encoding.operationId === 'GPUTexture.destroy',
    );
    expect(expiryEncodings.map((encoding) => encoding.canvasService)).toMatchObject([
      {
        kind: 'texture-destroy-v1',
        terminalIntent: 'first-cleanup',
        materializationState: 'unmaterialized',
      },
      {
        kind: 'texture-expire-v1',
        materializationState: 'materialized',
      },
      {
        kind: 'texture-expire-v1',
        materializationState: 'materialized',
      },
    ]);
    binding.revoke();
    expect(bridge.presentationAuthorityRetirements).toHaveLength(0);
    expect(codecs.encodings.filter(
      (encoding) => encoding.operationId === 'GPUTexture.destroy',
    )).toHaveLength(expiryEncodings.length);
  });

  test('converts canvas configuration once in Web IDL dictionary order', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const observations: string[] = [];
    const toneMapping = new Proxy({ mode: 'standard' }, {
      get(target, key, receiver) {
        observations.push(`toneMapping.${String(key)}`);
        return Reflect.get(target, key, receiver);
      },
    });
    const values: Record<string, unknown> = {
      alphaMode: 'premultiplied',
      colorSpace: 'display-p3',
      device,
      format: 'rgba8unorm',
      toneMapping,
      usage: 16,
      viewFormats: ['bgra8unorm'],
    };
    const configuration = new Proxy(values, {
      get(target, key, receiver) {
        observations.push(`configuration.${String(key)}`);
        return Reflect.get(target, key, receiver);
      },
    });

    context.configure(configuration);
    expect(observations).toEqual([
      'configuration.alphaMode',
      'configuration.colorSpace',
      'configuration.device',
      'configuration.format',
      'configuration.toneMapping',
      'toneMapping.mode',
      'configuration.usage',
      'configuration.viewFormats',
    ]);
    expect(codecs.encodings.findLast(
      (encoding) => encoding.operationId === 'GPUCanvasContext.configure',
    )).toMatchObject({
      convertedArguments: {
        alphaMode: 'premultiplied',
        colorSpace: 'display-p3',
        device,
        format: 'rgba8unorm',
        toneMapping: { mode: 'standard' },
        usage: 16,
        viewFormats: ['bgra8unorm'],
      },
      canvasService: {
        configuredDeviceRef: { kind: 'GPUDevice', objectId: '201' },
        viewFormats: ['bgra8unorm'],
        toneMappingMode: 'standard',
      },
    });

    const earlyObservations: string[] = [];
    const hostile = new Proxy({ device }, {
      get(target, key, receiver) {
        earlyObservations.push(String(key));
        if (key === 'format') throw new TypeError('format getter exploded');
        return Reflect.get(target, key, receiver);
      },
    });
    const submissionCount = bridge.submissions.length;
    expect(() => context.configure(hostile)).toThrow('format getter exploded');
    expect(earlyObservations).toEqual([
      'alphaMode',
      'colorSpace',
      'device',
      'format',
    ]);
    expect(bridge.submissions).toHaveLength(submissionCount);
    expect(context.getConfiguration()?.format).toBe('rgba8unorm');
    binding.revoke();
  });

  test('rejects canvas content predicates only after complete conversion', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');

    for (const [configuration, message] of [
      [
        { device, format: 'bgra8unorm', viewFormats: ['bc1-rgba-unorm'] },
        'requires feature texture-compression-bc',
      ],
      [
        { device, format: 'r8unorm' },
        'is not a supported canvas context format',
      ],
      [
        { device, format: 'bgra8unorm', usage: 0x30 },
        'may not include TRANSIENT_ATTACHMENT',
      ],
      [
        {
          device,
          format: 'bgra8unorm',
          toneMapping: { mode: 'extended' },
        },
        'toneMapping.mode must be standard in this profile',
      ],
    ] as const) {
      expect(() => context.configure(configuration)).toThrow(message);
      expect(context.getConfiguration()).toBeNull();
    }
    expect(bridge.submissions.filter(
      (submission) => submission.operationId === configureWireId,
    )).toHaveLength(0);
    expect(codecs.encodings.filter(
      (encoding) => encoding.operationId === 'GPUCanvasContext.configure',
    )).toHaveLength(0);

    context.configure({ device, format: 'bgra8unorm' });
    context.getCurrentTexture().createView();
    expect(latestCanvasTextureOrigin(bridge).configurationGeneration).toBe('1');
    binding.revoke();
  });

  test('returns detached deep canvas configuration snapshots', async () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const viewFormats = ['rgba8unorm'];
    const toneMapping = { mode: 'standard' };
    context.configure({
      device,
      format: 'bgra8unorm',
      viewFormats,
      toneMapping,
    });
    viewFormats[0] = 'rgba16float';
    toneMapping.mode = 'extended';

    const first = context.getConfiguration()!;
    expect(first).toMatchObject({
      format: 'bgra8unorm',
      viewFormats: ['rgba8unorm'],
      toneMapping: { mode: 'standard' },
    });
    (first.viewFormats as string[])[0] = 'rgba16float';
    (first.toneMapping as { mode: string }).mode = 'extended';
    const second = context.getConfiguration()!;
    expect(second).toMatchObject({
      format: 'bgra8unorm',
      viewFormats: ['rgba8unorm'],
      toneMapping: { mode: 'standard' },
    });
    expect(second).not.toBe(first);
    expect(second.viewFormats).not.toBe(first.viewFormats);
    expect(second.toneMapping).not.toBe(first.toneMapping);
    binding.revoke();
  });

  test('keeps the published reconfiguration when codec preflight fails', async () => {
    const bridge = createFakeBridge();
    const baseCodecs = createFakeCodecs();
    let failConfigureEncoding = false;
    const codecs: ExecutableWebGpuCodecBundle = {
      ...baseCodecs,
      encodeServiceRequest(input) {
        if (
          failConfigureEncoding &&
          input.operationId === 'GPUCanvasContext.configure'
        ) {
          throw new TypeError('configure codec preflight exploded');
        }
        return baseCodecs.encodeServiceRequest(input);
      },
    };
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    const oldTexture = context.getCurrentTexture();
    oldTexture.createView();
    const oldOrigin = latestCanvasTextureOrigin(bridge);
    const configureSubmissionCount = bridge.submissions.filter(
      (submission) => submission.operationId === WEBGPU_PRODUCTION_PLAN.routes.find(
        (route) => route.operationId === 'GPUCanvasContext.configure',
      )?.wireId,
    ).length;

    failConfigureEncoding = true;
    expect(() => context.configure({ device, format: 'rgba8unorm' }))
      .toThrow('configure codec preflight exploded');
    expect(context.getConfiguration()?.format).toBe('rgba8unorm');
    expect(bridge.submissions.filter(
      (submission) => submission.operationId === WEBGPU_PRODUCTION_PLAN.routes.find(
        (route) => route.operationId === 'GPUCanvasContext.configure',
      )?.wireId,
    )).toHaveLength(configureSubmissionCount);
    failConfigureEncoding = false;
    const newTexture = context.getCurrentTexture();
    expect(newTexture).not.toBe(oldTexture);
    newTexture.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '2',
      currentEpoch: '2',
      format: 'rgba8unorm',
    });
    oldTexture.createView();
    expect(latestCanvasTextureOrigin(bridge)).toEqual(oldOrigin);
    binding.revoke();
  });

  test('settles only the exact canvas origin for direct carriers in either order', async () => {
    for (const order of [
      ['first', 'second'],
      ['second', 'first'],
    ] as const) {
      const bridge = createFakeBridge();
      const codecs = createFakeCodecs();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        codecs,
        { enableStateInspection: true },
      );
      const device = await requestTestDevice(binding);
      const firstContext = mintTestCanvasContext(binding);
      const secondContext = mintSecondTestCanvasContext(binding);
      firstContext.configure({ device, format: 'bgra8unorm' });
      secondContext.configure({ device, format: 'rgba8unorm' });
      const textures = {
        first: firstContext.getCurrentTexture(),
        second: secondContext.getCurrentTexture(),
      };
      const contextIds = { first: '401', second: '402' } as const;
      expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(2);

      for (const [index, name] of order.entries()) {
        textures[name].createView();
        const encoding = codecs.encodings.findLast(
          (candidate) => candidate.operationId === 'GPUTexture.createView',
        );
        if (!encoding) throw new Error('missing direct canvas carrier');
        const records = localRecords(encoding);
        expect(records).toHaveLength(1);
        expect(records[0]).toMatchObject({
          operationName: 'GPUCanvasContext.getCurrentTexture',
          argumentBody: {
            currentOrigin: {
              contextRef: { objectId: contextIds[name] },
            },
          },
        });
        expect(inspectBinding(binding).current.pendingLocalRecordCount)
          .toBe(1 - index);
      }
      binding.revoke();
    }
  });

  test('preserves a second canvas origin through unrelated work and materializes it on queue submit', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    const firstContext = mintTestCanvasContext(binding);
    const secondContext = mintSecondTestCanvasContext(binding);
    firstContext.configure({ device, format: 'bgra8unorm' });
    secondContext.configure({ device, format: 'rgba8unorm' });
    const firstTexture = firstContext.getCurrentTexture();
    const secondTexture = secondContext.getCurrentTexture();
    device.createBuffer({ size: 16, usage: 1 });
    const unrelatedEncoding = codecs.encodings.findLast(
      (candidate) => candidate.operationId === 'GPUDevice.createBuffer',
    );
    if (!unrelatedEncoding) throw new Error('missing unrelated service call');
    expect(localRecords(unrelatedEncoding)).toEqual([]);
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(2);

    firstTexture.createView();
    const firstCarrier = codecs.encodings.findLast(
      (candidate) => candidate.operationId === 'GPUTexture.createView',
    );
    if (!firstCarrier) throw new Error('missing first direct carrier');
    expect(localRecords(firstCarrier)).toMatchObject([{
      argumentBody: {
        currentOrigin: { contextRef: { objectId: '401' } },
      },
    }]);
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(1);

    device.queue.submit([]);
    const queueCarrier = codecs.encodings.findLast(
      (candidate) => candidate.operationId === 'GPUQueue.submit',
    );
    if (!queueCarrier) throw new Error('missing queue canvas carrier');
    expect(localRecords(queueCarrier)).toMatchObject([{
      argumentBody: {
        currentOrigin: { contextRef: { objectId: '402' } },
      },
    }]);
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);

    secondTexture.destroy();
    const secondDestroy = codecs.encodings.findLast(
      (candidate) => candidate.operationId === 'GPUTexture.destroy',
    );
    expect(secondDestroy?.canvasService).toMatchObject({
      kind: 'texture-destroy-v1',
      materializationState: 'materialized',
      origin: { kind: 'canvas-current-v1' },
    });
    binding.revoke();
  });

  test('expires every current texture in canonical texture order without conflating manual destroy', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      codecs,
      { enableStateInspection: true },
    );
    const device = await requestTestRecordingDevice(binding);
    const firstContext = mintTestCanvasContext(binding);
    const secondContext = mintSecondTestCanvasContext(binding);
    firstContext.configure({ device, format: 'bgra8unorm' });
    secondContext.configure({ device, format: 'rgba8unorm' });
    const secondTexture = secondContext.getCurrentTexture();
    const firstTexture = firstContext.getCurrentTexture();

    // Manual destroy ends app write access but cannot retire the immutable
    // drawing buffer before the host-task expiry control arrives.
    secondTexture.destroy();
    binding.checkpointHostTask();

    const lifecycle = codecs.encodings.filter(
      (encoding) => encoding.operationId === 'GPUTexture.destroy',
    );
    expect(lifecycle).toHaveLength(4);
    const lifecycleAuthorities = lifecycle.map((encoding) =>
      encoding.canvasService as ProductionGpuCanvasServiceEncoding);
    expect(lifecycleAuthorities).toMatchObject([
      {
        kind: 'texture-destroy-v1',
        terminalIntent: 'first-cleanup',
        materializationState: 'unmaterialized',
        origin: { contextRef: { objectId: '402' } },
      },
      {
        kind: 'texture-expire-v1',
        expiryIntent: 'host-task-expiry',
        materializationState: 'materialized',
        origin: { contextRef: { objectId: '402' } },
      },
      {
        kind: 'texture-destroy-v1',
        terminalIntent: 'first-cleanup',
        materializationState: 'unmaterialized',
        origin: { contextRef: { objectId: '401' } },
      },
      {
        kind: 'texture-expire-v1',
        expiryIntent: 'host-task-expiry',
        materializationState: 'materialized',
        origin: { contextRef: { objectId: '401' } },
      },
    ]);
    expect(localRecords(lifecycle[0]!)).toHaveLength(1);
    expect(localRecords(lifecycle[1]!)).toEqual([]);
    expect(localRecords(lifecycle[2]!)).toHaveLength(1);
    expect(localRecords(lifecycle[3]!)).toEqual([]);
    expect(lifecycleAuthorities[1]).toMatchObject({
      origin: (lifecycleAuthorities[0] as Extract<
        ProductionGpuCanvasServiceEncoding,
        { kind: 'texture-destroy-v1' }
      >).origin,
    });
    expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);

    expect(firstContext.getCurrentTexture()).not.toBe(firstTexture);
    expect(secondContext.getCurrentTexture()).not.toBe(secondTexture);
    firstTexture.destroy();
    secondTexture.destroy();
    expect(codecs.encodings.slice(-2).map((encoding) =>
      (encoding.canvasService as Extract<
        ProductionGpuCanvasServiceEncoding,
        { kind: 'texture-destroy-v1' }
      >).terminalIntent)).toEqual([
      'repeat-cleanup-noop',
      'repeat-cleanup-noop',
    ]);
    binding.revoke();
  });

  test('commits no local texture expiry when a later checkpoint control is rejected', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestRecordingDevice(binding);
    const firstContext = mintTestCanvasContext(binding);
    const secondContext = mintSecondTestCanvasContext(binding);
    firstContext.configure({ device, format: 'bgra8unorm' });
    secondContext.configure({ device, format: 'rgba8unorm' });
    const secondTexture = secondContext.getCurrentTexture();
    const firstTexture = firstContext.getCurrentTexture();
    const destroyWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUTexture.destroy',
    )?.wireId;
    if (destroyWireId === undefined) throw new Error('missing texture destroy route');

    let expiryAttempt = 0;
    bridge.setSubmitHook((operationId) => {
      if (operationId !== destroyWireId) return undefined;
      expiryAttempt += 1;
      return expiryAttempt === 2 ? 83 : undefined;
    });
    expect(() => binding.checkpointHostTask()).toThrow(
      'WebGPU semantic service rejected GPUTexture.destroy (83)',
    );
    expect(expiryAttempt).toBe(2);
    expect(firstContext.getCurrentTexture()).toBe(firstTexture);
    expect(secondContext.getCurrentTexture()).toBe(secondTexture);
    expect(codecs.encodings.slice(-2).map((encoding) =>
      encoding.canvasService)).toMatchObject([
      {
        kind: 'texture-destroy-v1',
        terminalIntent: 'first-cleanup',
        materializationState: 'unmaterialized',
        origin: { contextRef: { objectId: '402' } },
      },
      {
        kind: 'texture-expire-v1',
        expiryIntent: 'host-task-expiry',
        materializationState: 'materialized',
        origin: { contextRef: { objectId: '402' } },
      },
    ]);
    binding.revoke();
  });

  test('does not clear a current texture when host-task expiry is rejected', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestRecordingDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    const current = context.getCurrentTexture();
    const destroyWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUTexture.destroy',
    )?.wireId;
    if (destroyWireId === undefined) throw new Error('missing texture destroy route');
    bridge.setSubmitHook((operationId) =>
      operationId === destroyWireId ? 79 : undefined);
    expect(() => binding.checkpointHostTask()).toThrow(
      'WebGPU semantic service rejected GPUTexture.destroy (79)',
    );
    expect(context.getCurrentTexture()).toBe(current);
    bridge.setSubmitHook(undefined);
    binding.checkpointHostTask();
    expect(context.getCurrentTexture()).not.toBe(current);
    binding.revoke();
  });

  test('keeps texture destroy retryable after bridge rejection and authenticates each terminal intent', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestRecordingDevice(binding);
    const texture = device.createTexture({
      format: 'rgba8unorm',
      size: [8, 8],
      usage: 4,
    }) as TestCanvasTexture;
    const destroyWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUTexture.destroy',
    )?.wireId;
    if (destroyWireId === undefined) throw new Error('missing texture destroy route');

    bridge.setSubmitHook((operationId) =>
      operationId === destroyWireId ? 71 : undefined);
    expect(() => texture.destroy()).toThrow(
      'WebGPU semantic service rejected GPUTexture.destroy (71)',
    );
    bridge.setSubmitHook(undefined);
    texture.destroy();
    texture.destroy();

    const destroyEncodings = codecs.encodings.filter(
      (encoding) => encoding.operationId === 'GPUTexture.destroy',
    );
    expect(destroyEncodings).toHaveLength(3);
    expect(destroyEncodings.map((encoding) =>
      (encoding.canvasService as ProductionGpuCanvasServiceEncoding & {
        readonly terminalIntent: string;
      }).terminalIntent)).toEqual([
      'first-cleanup',
      'first-cleanup',
      'repeat-cleanup-noop',
    ]);
    for (const encoding of destroyEncodings) {
      expect(encoding.convertedArguments).toBeNull();
      expect(encoding.canvasService).toMatchObject({
        kind: 'texture-destroy-v1',
        materializationState: 'unmaterialized',
        origin: { kind: 'device-created-v1' },
      });
    }
    expect(bridge.submissions.filter(
      (submission) => submission.operationId === destroyWireId,
    )).toHaveLength(3);
    binding.revoke();
  });

  test('keeps canvas unconfigure retryable after explicit service rejection', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    const unconfigureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUCanvasContext.unconfigure',
    )?.wireId;
    if (unconfigureWireId === undefined) {
      throw new Error('missing canvas unconfigure route');
    }
    bridge.setSubmitHook((operationId) =>
      operationId === unconfigureWireId ? 73 : undefined);

    expect(() => context.unconfigure()).toThrow(
      'WebGPU semantic service rejected GPUCanvasContext.unconfigure (73)',
    );
    expect(context.getConfiguration()?.format).toBe('bgra8unorm');
    bridge.setSubmitHook(undefined);
    context.unconfigure();
    expect(context.getConfiguration()).toBeNull();
    expect(codecs.encodings.filter(
      (encoding) => encoding.operationId === 'GPUCanvasContext.unconfigure',
    ).map((encoding) => encoding.canvasService)).toMatchObject([
      { terminalIntent: 'first-cleanup', configurationGeneration: '1' },
      { terminalIntent: 'first-cleanup', configurationGeneration: '1' },
    ]);
    binding.revoke();
  });

  test('closes the realm on ambiguous canvas cleanup bridge throws', async () => {
    {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        { enableStateInspection: true },
      );
      const device = await requestTestDevice(binding);
      const context = mintTestCanvasContext(binding);
      context.configure({ device, format: 'bgra8unorm' });
      const unconfigureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
        (route) => route.operationId === 'GPUCanvasContext.unconfigure',
      )?.wireId;
      if (unconfigureWireId === undefined) {
        throw new Error('missing canvas unconfigure route');
      }
      bridge.setSubmitHook((operationId) => {
        if (operationId === unconfigureWireId) {
          throw new Error('unconfigure submit exploded');
        }
      });
      expect(() => context.unconfigure()).toThrow('unconfigure submit exploded');
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      expect(inspectBinding(binding).current).toMatchObject({
        active: false,
        closeReason: 'canvas-unconfigure-submit-threw',
      });
      expect(() => context.unconfigure()).toThrow('realm is revoked');
      binding.revoke();
    }

    {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        { enableStateInspection: true },
      );
      const device = await requestTestRecordingDevice(binding);
      const texture = device.createTexture({
        format: 'rgba8unorm',
        size: [8, 8],
        usage: 4,
      }) as TestCanvasTexture;
      const destroyWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
        (route) => route.operationId === 'GPUTexture.destroy',
      )?.wireId;
      if (destroyWireId === undefined) throw new Error('missing texture destroy route');
      bridge.setSubmitHook((operationId) => {
        if (operationId === destroyWireId) throw new Error('destroy submit exploded');
      });
      expect(() => texture.destroy()).toThrow('destroy submit exploded');
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      expect(inspectBinding(binding).current).toMatchObject({
        active: false,
        closeReason: 'texture-destroy-submit-threw',
      });
      expect(() => texture.destroy()).toThrow('realm is revoked');
      binding.revoke();
    }
  });

  test('interns only exact unchanged host canvas identities and fences stale generations', async () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    const identity = {
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: CANVAS_AUTHORITY,
    } as const;
    const first = binding.mintCanvasContext(identity) as TestCanvasContext;
    expect(binding.mintCanvasContext({
      ...identity,
      authority: { ...CANVAS_AUTHORITY },
    })).toBe(first);
    expect(() => binding.mintCanvasContext({
      ...identity,
      drawingBufferWidth: 641,
    })).toThrow('conflicts with existing host authority or extent');
    expect(() => binding.mintCanvasContext({
      ...identity,
      authority: {
        ...CANVAS_AUTHORITY,
        surfaceAccountGeneration: '44',
      },
    })).toThrow('conflicts with existing host authority or extent');

    // Provider-result wrappers deliberately remain allocation-local. The two
    // fake adapter results carry the same service identity but are not drawn
    // into the host-only Canvas identity index.
    const gpu = binding.gpu as { requestAdapter(): Promise<unknown> };
    expect(await gpu.requestAdapter()).not.toBe(await gpu.requestAdapter());

    const successor = binding.mintCanvasContext({
      ...identity,
      objectGeneration: '2',
      authority: {
        ...CANVAS_AUTHORITY,
        attachmentGeneration: '32',
        contextGeneration: '38',
      },
    }) as TestCanvasContext;
    expect(successor).not.toBe(first);
    expect(() => first.getConfiguration()).toThrow('identity is stale');
    expect(() => binding.mintCanvasContext(identity)).toThrow('identity is stale');

    binding.revoke();
    expect(() => successor.getConfiguration()).toThrow('realm is revoked');
    expect(() => binding.mintCanvasContext({
      ...identity,
      objectGeneration: '2',
    })).toThrow('realm is revoked');
  });

  test('fences canvas authority lineage across object IDs with bounded live indexes', () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const firstIdentity = {
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: CANVAS_AUTHORITY,
    } as const;
    const first = binding.mintCanvasContext(firstIdentity) as TestCanvasContext;

    expect(() => binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
    })).toThrow('authority aliases an existing live identity');
    expect(() => binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
      authority: { ...CANVAS_AUTHORITY, contextGeneration: '38' },
    })).toThrow('lineage is stale or conflicting');
    expect(() => binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
      authority: { ...CANVAS_AUTHORITY, attachmentGeneration: '32' },
    })).toThrow('lineage is stale or conflicting');
    expect(() => binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
      authority: {
        ...CANVAS_AUTHORITY,
        attachmentGeneration: '32',
        contextGeneration: '36',
      },
    })).toThrow('lineage is stale or conflicting');
    expect(first.getConfiguration()).toBeNull();

    const resizedAuthority = Object.freeze({
      ...CANVAS_AUTHORITY,
      attachmentGeneration: '32',
      contextGeneration: '38',
      targetAuthorityDigest: 'cd'.repeat(32),
    });
    const resized = binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
      drawingBufferWidth: 800,
      drawingBufferHeight: 600,
      authority: resizedAuthority,
    }) as TestCanvasContext;
    expect(() => first.getConfiguration()).toThrow('identity is stale');
    expect(binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
      drawingBufferWidth: 800,
      drawingBufferHeight: 600,
      authority: { ...resizedAuthority },
    })).toBe(resized);
    expect(() => binding.mintCanvasContext(firstIdentity))
      .toThrow('lineage is stale or conflicting');

    const resetChildAuthority = Object.freeze({
      ...resizedAuthority,
      surfaceAccountGeneration: '44',
      attachmentGeneration: '1',
      contextGeneration: '1',
      targetAuthorityDigest: 'ef'.repeat(32),
    });
    const resetChild = binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '403',
      objectGeneration: '1',
      drawingBufferWidth: 1024,
      drawingBufferHeight: 768,
      authority: resetChildAuthority,
    }) as TestCanvasContext;
    expect(() => resized.getConfiguration()).toThrow('identity is stale');

    const distinct = binding.mintCanvasContext({
      objectId: '501',
      objectGeneration: '1',
      drawingBufferWidth: 320,
      drawingBufferHeight: 240,
      authority: {
        ...CANVAS_AUTHORITY,
        surfaceAccountToken: '99',
        surfaceAccountGeneration: '1',
      },
    }) as TestCanvasContext;
    expect(resetChild.getConfiguration()).toBeNull();
    expect(distinct.getConfiguration()).toBeNull();
    expect(inspectBinding(binding).current).toMatchObject({
      indexedCanvasContextCount: 2,
      indexedCanvasObjectCount: 2,
      indexedCanvasSurfaceTokenCount: 2,
    });
    binding.revoke();
    expect(inspectBinding(binding).lastClose).toMatchObject({
      indexedCanvasContextCount: 2,
      indexedCanvasObjectCount: 2,
      indexedCanvasSurfaceTokenCount: 2,
    });
  });

  test('device destroy synchronously enters canvas LOST exactly once and preserves stale origin', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    const beforeLoss = context.getCurrentTexture();
    beforeLoss.createView();
    const beforeLossOrigin = latestCanvasTextureOrigin(bridge);

    device.destroy();
    expect(context.getConfiguration()?.format).toBe('bgra8unorm');
    const afterLoss = context.getCurrentTexture();
    expect(afterLoss).not.toBe(beforeLoss);
    expect(context.getCurrentTexture()).toBe(afterLoss);
    afterLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '2',
      currentEpoch: '2',
    });

    beforeLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toEqual(beforeLossOrigin);
    context.configure({ device, format: 'bgra8unorm' });
    const replacementInvalidTexture = context.getCurrentTexture();
    expect(replacementInvalidTexture).not.toBe(afterLoss);
    replacementInvalidTexture.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '3',
      currentEpoch: '3',
    });

    // A later duplicate native loss input cannot re-expire the post-loss
    // invalid-device identity or advance configuration generation again.
    emitDeviceLoss(bridge, '301', '2');
    expect(context.getCurrentTexture()).toBe(replacementInvalidTexture);
    expect(await device.lost).toEqual({
      reason: 'destroyed',
      message: 'The device was destroyed',
    });
    binding.revoke();
  });

  test('asynchronous device loss expires a configured canvas without unconfigure', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs([], { distinctLiveDevices: true }),
    );
    const device = await requestTestDevice(binding);
    const recoveryDevice = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    const beforeLoss = context.getCurrentTexture();
    beforeLoss.createView();
    const beforeLossOrigin = latestCanvasTextureOrigin(bridge);

    emitDeviceLoss(bridge, '301', '1');
    const afterLoss = context.getCurrentTexture();
    expect(afterLoss).not.toBe(beforeLoss);
    afterLoss.createView();
    const afterLossOrigin = latestCanvasTextureOrigin(bridge);
    expect(afterLossOrigin).toMatchObject({
      configurationGeneration: '2',
      currentEpoch: '2',
      configuredDeviceRef: { logicalDeviceId: '301' },
    });
    emitDeviceLoss(bridge, '301', '2');
    expect(context.getCurrentTexture()).toBe(afterLoss);

    beforeLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toEqual(beforeLossOrigin);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });

    context.configure({ device: recoveryDevice, format: 'bgra8unorm' });
    const recovered = context.getCurrentTexture();
    expect(recovered).not.toBe(afterLoss);
    recovered.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '3',
      currentEpoch: '3',
      configuredDeviceRef: { logicalDeviceId: '311' },
    });
    emitDeviceLoss(bridge, '301', '3');
    expect(context.getCurrentTexture()).toBe(recovered);
    afterLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toEqual(afterLossOrigin);
    expect(context.getCurrentTexture()).toBe(recovered);
    binding.revoke();
  });

  test('reconfigure and unconfigure unlink prior device loss registries', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs([], { distinctLiveDevices: true }),
    );
    const firstDevice = await requestTestDevice(binding);
    const secondDevice = await requestTestDevice(binding);
    const thirdDevice = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);

    context.configure({ device: firstDevice, format: 'bgra8unorm' });
    context.configure({ device: secondDevice, format: 'bgra8unorm' });
    const secondTexture = context.getCurrentTexture();
    emitDeviceLoss(bridge, '301', '1');
    expect(context.getCurrentTexture()).toBe(secondTexture);
    expect(await firstDevice.lost).toEqual({ reason: 'unknown', message: 'loss-4' });

    context.unconfigure();
    emitDeviceLoss(bridge, '311', '1');
    expect(() => context.getCurrentTexture()).toThrow('not configured');
    context.configure({ device: thirdDevice, format: 'bgra8unorm' });
    context.getCurrentTexture().createView();
    // configure A, configure B, unconfigure, configure C. Loss of the two
    // unlinked devices contributes no extra generation transition.
    expect(latestCanvasTextureOrigin(bridge).configurationGeneration).toBe('4');
    binding.revoke();
  });

  test('keeps an initially rejected configure installed without reusing ingress', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    bridge.setSubmitHook((operationId) =>
      operationId === configureWireId ? 17 : undefined
    );

    expect(() => context.configure({ device, format: 'rgba8unorm' }))
      .toThrow('semantic service rejected GPUCanvasContext.configure (17)');
    expect(context.getConfiguration()?.format).toBe('rgba8unorm');
    const rejectedConfigurationTexture = context.getCurrentTexture();
    rejectedConfigurationTexture.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '1',
      currentEpoch: '1',
      format: 'rgba8unorm',
    });
    expect(inspectBinding(binding).current).toMatchObject({
      active: true,
      routedDeviceCount: 1,
      indexedCanvasContextCount: 1,
      indexedCanvasObjectCount: 1,
      indexedCanvasSurfaceTokenCount: 1,
      invalidCurrentTextureCount: 0,
      canvasLossTransitionCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });
    expect(bridge.submissions.filter(
      (submission) => submission.operationId === configureWireId,
    ).map((submission) => submission.metadata.deviceIngressOrdinal)).toEqual(['1']);

    bridge.setSubmitHook(undefined);
    context.configure({ device, format: 'bgra8unorm' });
    expect(bridge.submissions.filter(
      (submission) => submission.operationId === configureWireId,
    ).map((submission) => submission.metadata.deviceIngressOrdinal)).toEqual([
      '1',
      '5',
    ]);
    const configuredTexture = context.getCurrentTexture();
    expect(configuredTexture).not.toBe(rejectedConfigurationTexture);
    configuredTexture.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '2',
      currentEpoch: '2',
      format: 'bgra8unorm',
    });

    emitDeviceLoss(bridge, '301', '1');
    const invalidTexture = context.getCurrentTexture();
    expect(invalidTexture).not.toBe(configuredTexture);
    invalidTexture.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '3',
      currentEpoch: '3',
      format: 'bgra8unorm',
    });
    emitDeviceLoss(bridge, '301', '2');
    emitProviderLoss(bridge);
    expect(context.getCurrentTexture()).toBe(invalidTexture);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    binding.revoke();
  });

  test('keeps a rejected reconfigure installed while expiring the prior texture', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    context.configure({ device, format: 'bgra8unorm' });
    const beforeRejectedConfigure = context.getCurrentTexture();
    beforeRejectedConfigure.createView();
    const beforeOrigin = latestCanvasTextureOrigin(bridge);
    bridge.setSubmitHook((operationId) =>
      operationId === configureWireId ? 23 : undefined
    );

    expect(() => context.configure({ device, format: 'rgba8unorm' }))
      .toThrow('semantic service rejected GPUCanvasContext.configure (23)');
    expect(context.getConfiguration()?.format).toBe('rgba8unorm');
    const afterRejectedConfigure = context.getCurrentTexture();
    expect(afterRejectedConfigure).not.toBe(beforeRejectedConfigure);
    afterRejectedConfigure.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '2',
      currentEpoch: '2',
      format: 'rgba8unorm',
    });
    expect(bridge.submissions.at(-1)?.metadata.deviceIngressOrdinal).toBe('7');
    beforeRejectedConfigure.createView();
    expect(latestCanvasTextureOrigin(bridge)).toEqual(beforeOrigin);
    expect(bridge.submissions.filter(
      (submission) => submission.operationId === configureWireId,
    ).map((submission) => submission.metadata.deviceIngressOrdinal)).toEqual([
      '1',
      '5',
    ]);
    expect(inspectBinding(binding).current).toMatchObject({
      active: true,
      routedDeviceCount: 1,
      indexedCanvasContextCount: 1,
      indexedCanvasObjectCount: 1,
      indexedCanvasSurfaceTokenCount: 1,
      invalidCurrentTextureCount: 0,
      canvasLossTransitionCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });

    emitDeviceLoss(bridge, '301', '1');
    const invalidTexture = context.getCurrentTexture();
    expect(invalidTexture).not.toBe(afterRejectedConfigure);
    invalidTexture.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '3',
      currentEpoch: '3',
      format: 'rgba8unorm',
    });
    expect(inspectBinding(binding).current).toMatchObject({
      routedDeviceCount: 0,
      canvasLossTransitionCount: 1,
      invalidCurrentTextureCount: 1,
    });
    emitDeviceLoss(bridge, '301', '2');
    emitProviderLoss(bridge);
    expect(context.getCurrentTexture()).toBe(invalidTexture);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    binding.revoke();
  });

  test('closes the realm when an initial configure submit throws', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    bridge.setSubmitHook((operationId) => {
      if (operationId === configureWireId) throw new Error('configure submit exploded');
    });

    expect(() => context.configure({ device, format: 'bgra8unorm' }))
      .toThrow('configure submit exploded');
    expect(await device.lost).toEqual({
      reason: 'unknown',
      message: 'The WebGPU realm closed because canvas configure submission threw',
    });
    expect(() => context.getConfiguration()).toThrow('realm is revoked');
    expect(() => context.getCurrentTexture()).toThrow('realm is revoked');
    expect(bridge.submissions.filter(
      (submission) => submission.operationId === configureWireId,
    ).map((submission) => submission.metadata.deviceIngressOrdinal)).toEqual(['1']);
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      closeReason: 'canvas-configure-submit-threw',
      routedDeviceCount: 0,
      indexedCanvasContextCount: 0,
      indexedCanvasObjectCount: 0,
      indexedCanvasSurfaceTokenCount: 0,
      invalidCurrentTextureCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });
    expect(inspectBinding(binding).lastClose).toMatchObject({
      routedDeviceCount: 1,
      indexedCanvasContextCount: 1,
      indexedCanvasObjectCount: 1,
      indexedCanvasSurfaceTokenCount: 1,
      canvasLossTransitionCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });
    emitDeviceLoss(bridge, '301', '1');
    emitProviderLoss(bridge);
    expect(await device.lost).toMatchObject({ reason: 'unknown' });
    binding.revoke();
  });

  test('closes the realm when reconfigure submit throws after expiring current', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    context.configure({ device, format: 'bgra8unorm' });
    const beforeThrownConfigure = context.getCurrentTexture();
    beforeThrownConfigure.createView();
    const beforeOrigin = latestCanvasTextureOrigin(bridge);
    bridge.setSubmitHook((operationId) => {
      if (operationId === configureWireId) throw new Error('reconfigure submit exploded');
    });

    expect(() => context.configure({ device, format: 'rgba8unorm' }))
      .toThrow('reconfigure submit exploded');
    expect(await device.lost).toEqual({
      reason: 'unknown',
      message: 'The WebGPU realm closed because canvas configure submission threw',
    });
    expect(() => context.getConfiguration()).toThrow('realm is revoked');
    expect(() => context.getCurrentTexture()).toThrow('realm is revoked');
    expect(() => beforeThrownConfigure.createView()).toThrow('realm is revoked');
    expect(beforeOrigin).toMatchObject({
      configurationGeneration: '1',
      currentEpoch: '1',
      format: 'bgra8unorm',
    });
    expect(bridge.submissions.filter(
      (submission) => submission.operationId === configureWireId,
    ).map((submission) => submission.metadata.deviceIngressOrdinal)).toEqual([
      '1',
      '5',
    ]);
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      routedDeviceCount: 0,
      indexedCanvasContextCount: 0,
      indexedCanvasObjectCount: 0,
      indexedCanvasSurfaceTokenCount: 0,
      invalidCurrentTextureCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });
    expect(inspectBinding(binding).lastClose).toMatchObject({
      closeReason: 'canvas-configure-submit-threw',
      routedDeviceCount: 1,
      indexedCanvasContextCount: 1,
      indexedCanvasObjectCount: 1,
      indexedCanvasSurfaceTokenCount: 1,
      canvasLossTransitionCount: 0,
      invalidCurrentTextureCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });
    emitDeviceLoss(bridge, '301', '1');
    emitProviderLoss(bridge);
    expect(await device.lost).toMatchObject({ reason: 'unknown' });
    binding.revoke();
  });

  test('keeps provider-wide inline loss terminal when configure is rejected', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    bridge.setSubmitHook((operationId) => {
      if (operationId !== configureWireId) return;
      emitProviderLoss(bridge);
      return 29;
    });

    expect(() => context.configure({ device, format: 'bgra8unorm' }))
      .toThrow('semantic service rejected GPUCanvasContext.configure (29)');
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-3' });
    expect(context.getConfiguration()?.format).toBe('bgra8unorm');
    const invalidTexture = context.getCurrentTexture();
    expect(context.getCurrentTexture()).toBe(invalidTexture);
    invalidTexture.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '2',
      currentEpoch: '1',
      format: 'bgra8unorm',
    });
    expect(inspectBinding(binding).current).toMatchObject({
      active: true,
      routedDeviceCount: 0,
      indexedCanvasContextCount: 1,
      indexedCanvasObjectCount: 1,
      indexedCanvasSurfaceTokenCount: 1,
      invalidCurrentTextureCount: 1,
      canvasLossTransitionCount: 1,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });
    emitProviderLoss(bridge);
    emitDeviceLoss(bridge, '301', '1');
    expect(context.getCurrentTexture()).toBe(invalidTexture);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-3' });
    binding.revoke();
  });

  test('keeps targeted inline loss terminal when configure submit then throws', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    bridge.setSubmitHook((operationId) => {
      if (operationId !== configureWireId) return;
      emitDeviceLoss(bridge, '301', '1');
      throw new Error('configure threw after inline loss');
    });

    expect(() => context.configure({ device, format: 'bgra8unorm' }))
      .toThrow('configure threw after inline loss');
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(context.getConfiguration()?.format).toBe('bgra8unorm');
    const invalidTexture = context.getCurrentTexture();
    invalidTexture.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '2',
      currentEpoch: '1',
      format: 'bgra8unorm',
    });
    expect(inspectBinding(binding).current).toMatchObject({
      active: true,
      routedDeviceCount: 0,
      indexedCanvasContextCount: 1,
      indexedCanvasObjectCount: 1,
      indexedCanvasSurfaceTokenCount: 1,
      invalidCurrentTextureCount: 1,
      canvasLossTransitionCount: 1,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });
    emitDeviceLoss(bridge, '301', '2');
    emitProviderLoss(bridge);
    expect(context.getCurrentTexture()).toBe(invalidTexture);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    binding.revoke();
  });

  test('keeps an initial configure LOST when device loss is delivered inside submit', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    let inlineLossCount = 0;
    bridge.setSubmitHook((operationId) => {
      if (operationId !== configureWireId) return;
      inlineLossCount += 1;
      emitDeviceLoss(bridge, '301', String(inlineLossCount));
    });

    context.configure({ device, format: 'bgra8unorm' });
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(context.getConfiguration()?.format).toBe('bgra8unorm');
    const invalidTexture = context.getCurrentTexture();
    expect(context.getCurrentTexture()).toBe(invalidTexture);
    expect(inspectBinding(binding).current).toMatchObject({
      routedDeviceCount: 0,
      indexedCanvasContextCount: 1,
      indexedCanvasObjectCount: 1,
      indexedCanvasSurfaceTokenCount: 1,
      invalidCurrentTextureCount: 1,
    });
    invalidTexture.createView();
    expect(latestCanvasTextureOrigin(bridge).configurationGeneration).toBe('2');

    emitDeviceLoss(bridge, '301', '2');
    emitProviderLoss(bridge);
    expect(context.getCurrentTexture()).toBe(invalidTexture);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    context.configure({ device, format: 'rgba8unorm' });
    expect(context.getConfiguration()?.format).toBe('rgba8unorm');
    const replacementInvalidTexture = context.getCurrentTexture();
    expect(replacementInvalidTexture).not.toBe(invalidTexture);
    replacementInvalidTexture.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '3',
      currentEpoch: '2',
      format: 'rgba8unorm',
    });
    expect(inlineLossCount).toBe(2);
    binding.revoke();
  });

  test('does not let inline loss resurrect a reconfigured context', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    const beforeLoss = context.getCurrentTexture();
    beforeLoss.createView();
    const beforeLossOrigin = latestCanvasTextureOrigin(bridge);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    bridge.setSubmitHook((operationId) => {
      if (operationId === configureWireId) emitDeviceLoss(bridge, '301', '1');
    });

    context.configure({ device, format: 'rgba8unorm' });
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(context.getConfiguration()?.format).toBe('rgba8unorm');
    const afterLoss = context.getCurrentTexture();
    expect(afterLoss).not.toBe(beforeLoss);
    expect(context.getCurrentTexture()).toBe(afterLoss);
    afterLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '3',
      currentEpoch: '2',
      format: 'rgba8unorm',
    });
    expect(inspectBinding(binding).current.invalidCurrentTextureCount).toBe(1);

    beforeLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toEqual(beforeLossOrigin);
    emitDeviceLoss(bridge, '301', '2');
    emitProviderLoss(bridge);
    expect(context.getCurrentTexture()).toBe(afterLoss);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    binding.revoke();
  });

  test('fails closed when inline configure loss cannot advance its installed generation', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      {
        counterSeeds: { canvasConfigurationGeneration: U64_MAX_MINUS_ONE },
        enableStateInspection: true,
      },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    bridge.setSubmitHook((operationId) => {
      if (operationId === configureWireId) emitDeviceLoss(bridge, '301', '1');
    });

    expect(() => context.configure({ device, format: 'bgra8unorm' }))
      .toThrow('realm closed during GPUCanvasContext.configure');
    expect(await device.lost).toEqual({
      reason: 'unknown',
      message:
        'The WebGPU realm closed because canvas configuration generation was exhausted',
    });
    expect(() => context.getCurrentTexture()).toThrow('realm is revoked');
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      routedDeviceCount: 0,
      indexedCanvasContextCount: 0,
      indexedCanvasObjectCount: 0,
      indexedCanvasSurfaceTokenCount: 0,
      invalidCurrentTextureCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });
    expect(inspectBinding(binding).lastClose).toMatchObject({
      routedDeviceCount: 1,
      indexedCanvasContextCount: 1,
      indexedCanvasObjectCount: 1,
      indexedCanvasSurfaceTokenCount: 1,
      canvasLossTransitionCount: 0,
    });
    emitDeviceLoss(bridge, '301', '2');
    emitProviderLoss(bridge);
    expect(await device.lost).toMatchObject({ reason: 'unknown' });
    binding.revoke();
  });

  test('routes only unsettled live devices and forgets 1,100 destroyed terminals', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs([], { distinctLiveDevices: true }),
      { enableStateInspection: true },
    );
    let firstLost: Promise<unknown> | undefined;
    for (let index = 0; index < 1_100; index += 1) {
      const device = await requestTestDevice(binding);
      firstLost ??= device.lost;
      device.destroy();
      expect(await device.lost).toEqual({
        reason: 'destroyed',
        message: 'The device was destroyed',
      });
    }
    expect(inspectBinding(binding).current.routedDeviceCount).toBe(0);
    binding.revoke();
    binding.revoke();
    const inspection = inspectBinding(binding);
    expect(inspection.lastClose).toMatchObject({
      closeReason: 'realm-revoked',
      routedDeviceCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });
    expect(await firstLost!).toEqual({
      reason: 'destroyed',
      message: 'The device was destroyed',
    });
  });

  test('snapshots targeted and provider-wide loss routing with stable duplicate settlement', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs([], { distinctLiveDevices: true }),
      { enableStateInspection: true },
    );
    const first = await requestTestDevice(binding);
    const second = await requestTestDevice(binding);
    const third = await requestTestDevice(binding);

    emitDeviceLoss(bridge, '301', '1');
    expect(await first.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(inspectBinding(binding).current.routedDeviceCount).toBe(2);
    emitDeviceLoss(bridge, '301', '2');
    expect(inspectBinding(binding).current.routedDeviceCount).toBe(2);

    emitProviderLoss(bridge);
    expect(await second.lost).toEqual({ reason: 'unknown', message: 'loss-3' });
    expect(await third.lost).toEqual({ reason: 'unknown', message: 'loss-3' });
    expect(inspectBinding(binding).current.routedDeviceCount).toBe(0);

    emitDeviceLoss(bridge, '311', '3');
    emitProviderLoss(bridge);
    binding.revoke();
    expect(await first.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(await second.lost).toEqual({ reason: 'unknown', message: 'loss-3' });
    expect(inspectBinding(binding).lastClose?.routedDeviceCount).toBe(0);
  });

  test('makes local destroy win over a synchronous native loss callback', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestDevice(binding);
    const destroyWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUDevice.destroy',
    )?.wireId;
    if (destroyWireId === undefined) throw new Error('missing destroy route');
    let inlineLossCount = 0;
    bridge.setSubmitHook((operationId) => {
      if (operationId !== destroyWireId) return;
      inlineLossCount += 1;
      emitDeviceLoss(bridge, '301', String(inlineLossCount));
    });

    device.destroy();
    expect(await device.lost).toEqual({
      reason: 'destroyed',
      message: 'The device was destroyed',
    });
    const submissionCount = bridge.submissions.length;
    device.destroy();
    expect(bridge.submissions).toHaveLength(submissionCount);
    expect(inlineLossCount).toBe(1);
    binding.revoke();
  });

  test('submits destroy cleanup once after unknown loss without replacing the winner', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestDevice(binding);
    const stableLost = device.lost;
    emitDeviceLoss(bridge, '301', '1');
    expect(await stableLost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(device.lost).toBe(stableLost);

    const beforeDestroy = bridge.submissions.length;
    device.destroy();
    expect(bridge.submissions).toHaveLength(beforeDestroy + 1);
    expect(device.lost).toBe(stableLost);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    device.destroy();
    expect(bridge.submissions).toHaveLength(beforeDestroy + 1);
    binding.revoke();
  });

  test('does not repopulate Promise bookkeeping after synchronous realm close in submit', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const requestAdapterWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPU.requestAdapter',
    )?.wireId;
    if (requestAdapterWireId === undefined) {
      throw new Error('missing requestAdapter route');
    }
    bridge.setSubmitHook((operationId) => {
      if (operationId !== requestAdapterWireId) return;
      bridge.emit({
        kind: 6,
        runtimeAddress: bridge.runtimeAddress,
        runtimeNonce: bridge.runtimeNonce,
        realmId: bridge.realmId,
        realmGeneration: bridge.realmGeneration,
        closeOrdinal: '1',
        closeReason: 1,
        payload: new Uint8Array(),
      });
    });
    await expect((binding.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter()).rejects.toThrow('realm closed during GPU.requestAdapter');
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      pendingPromiseCount: 0,
      pendingLocalRecordCount: 0,
      routedDeviceCount: 0,
    });
    binding.revoke();
  });

  test('rejects missing or malformed host canvas authority synchronously', () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    const base = {
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
    };
    expect(() => binding.mintCanvasContext(base as never))
      .toThrow('identity is incomplete or malformed');
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: {
        ...CANVAS_AUTHORITY,
        targetAuthorityDigest: 'not-a-digest',
      },
    })).toThrow('authority is incomplete or malformed');
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: {
        ...CANVAS_AUTHORITY,
        attachmentGeneration: '18446744073709551616',
      },
    })).toThrow('authority is incomplete or malformed');
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: {
        ...CANVAS_AUTHORITY,
        unexpected: 'ambient-data-must-not-be-carried',
      },
    } as never)).toThrow('authority is incomplete or malformed');
    const symbolAuthority = { ...CANVAS_AUTHORITY } as Record<PropertyKey, unknown>;
    symbolAuthority[Symbol('ambient')] = 'ambient-data-must-not-be-carried';
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: symbolAuthority,
    } as never)).toThrow('authority is incomplete or malformed');
    const nonEnumerableExtraAuthority = { ...CANVAS_AUTHORITY };
    Object.defineProperty(nonEnumerableExtraAuthority, 'ambient', {
      value: 'ambient-data-must-not-be-carried',
      enumerable: false,
    });
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: nonEnumerableExtraAuthority,
    } as never)).toThrow('authority is incomplete or malformed');
    const nonEnumerableMemberAuthority = { ...CANVAS_AUTHORITY };
    Object.defineProperty(nonEnumerableMemberAuthority, 'attachmentGeneration', {
      value: CANVAS_AUTHORITY.attachmentGeneration,
      enumerable: false,
    });
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: nonEnumerableMemberAuthority,
    })).toThrow('authority is incomplete or malformed');
    binding.revoke();
  });

  test('captures canvas envelopes and nested authority exactly once without getters', () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    let outerOwnKeys = 0;
    let outerDescriptors = 0;
    let outerGets = 0;
    let authorityOwnKeys = 0;
    let authorityDescriptors = 0;
    let authorityGets = 0;
    const authorityTarget = { ...CANVAS_AUTHORITY };
    let outerTarget: Record<string, unknown>;
    const authority = new Proxy(authorityTarget, {
      ownKeys(target) {
        authorityOwnKeys += 1;
        outerTarget.objectId = '999';
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, key) {
        authorityDescriptors += 1;
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
      get() {
        authorityGets += 1;
        throw new Error('authority getter trap must not run');
      },
    });
    outerTarget = {
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority,
    };
    const envelope = new Proxy(outerTarget, {
      ownKeys(target) {
        outerOwnKeys += 1;
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, key) {
        outerDescriptors += 1;
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
      get() {
        outerGets += 1;
        throw new Error('outer getter trap must not run');
      },
    });
    const context = binding.mintCanvasContext(envelope as never);
    expect(outerOwnKeys).toBe(1);
    expect(outerDescriptors).toBe(5);
    expect(outerGets).toBe(0);
    expect(authorityOwnKeys).toBe(1);
    expect(authorityDescriptors).toBe(5);
    expect(authorityGets).toBe(0);

    authorityTarget.contextGeneration = '999';
    expect(binding.mintCanvasContext({
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: { ...CANVAS_AUTHORITY },
    })).toBe(context);

    let outerAccessorRuns = 0;
    const outerAccessor = {
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: CANVAS_AUTHORITY,
    } as Record<string, unknown>;
    Object.defineProperty(outerAccessor, 'objectId', {
      enumerable: true,
      get() {
        outerAccessorRuns += 1;
        return '402';
      },
    });
    expect(() => binding.mintCanvasContext(outerAccessor as never))
      .toThrow('identity is incomplete or malformed');
    expect(outerAccessorRuns).toBe(0);

    let authorityAccessorRuns = 0;
    const authorityAccessor = { ...CANVAS_AUTHORITY } as Record<string, unknown>;
    Object.defineProperty(authorityAccessor, 'contextGeneration', {
      enumerable: true,
      get() {
        authorityAccessorRuns += 1;
        return '38';
      },
    });
    expect(() => binding.mintCanvasContext({
      objectId: '402',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: authorityAccessor,
    } as never)).toThrow('authority is incomplete or malformed');
    expect(authorityAccessorRuns).toBe(0);

    const outerSymbol = {
      objectId: '402',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: CANVAS_AUTHORITY,
      [Symbol('ambient')]: true,
    };
    expect(() => binding.mintCanvasContext(outerSymbol as never))
      .toThrow('identity is incomplete or malformed');
    const outerExtra = { ...outerSymbol } as Record<PropertyKey, unknown>;
    delete outerExtra[Reflect.ownKeys(outerExtra).find(
      (key) => typeof key === 'symbol',
    )!];
    outerExtra.ambient = true;
    expect(() => binding.mintCanvasContext(outerExtra as never))
      .toThrow('identity is incomplete or malformed');
    const inherited = Object.assign(
      Object.create({ authority: CANVAS_AUTHORITY }) as Record<string, unknown>,
      {
        objectId: '402',
        objectGeneration: '1',
        drawingBufferWidth: 640,
        drawingBufferHeight: 480,
      },
    );
    expect(() => binding.mintCanvasContext(inherited as never))
      .toThrow('identity is incomplete or malformed');
    binding.revoke();
  });

  test('uses the final local object identity exactly once and closes before orphan allocation', async () => {
    const createBufferWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUDevice.createBuffer',
    )?.wireId;
    if (createBufferWireId === undefined) throw new Error('missing createBuffer route');
    for (const [seed, successCount] of [
      [U64_MAX_MINUS_ONE, 2],
      [U64_MAX, 1],
    ] as const) {
      const bridge = createFakeBridge();
      const counterSeeds = { nextLocalObjectId: seed as string };
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        { counterSeeds, enableStateInspection: true },
      );
      // Construction snapshots the seed; later caller mutation is irrelevant.
      counterSeeds.nextLocalObjectId = '1';
      const device = await requestTestDevice(binding) as TestGpuDevice & {
        createBuffer(descriptor: unknown): object;
      };
      for (let index = 0; index < successCount; index += 1) {
        expect(device.createBuffer({ mappedAtCreation: false, usage: 1 }))
          .toBeObject();
      }
      const targets = bridge.submissions
        .filter((submission) => submission.operationId === createBufferWireId)
        .map((submission) => submission.metadata.targetId);
      expect(targets).toEqual(
        successCount === 2 ? [U64_MAX_MINUS_ONE, U64_MAX] : [U64_MAX],
      );
      const beforeFailure = inspectBinding(binding).current;
      const submissionCount = bridge.submissions.length;
      expect(() => device.createBuffer({ mappedAtCreation: false, usage: 1 }))
        .toThrow(RangeError);
      expect(bridge.submissions).toHaveLength(submissionCount);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(beforeFailure.allocatedWrapperCount);
      expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      expect(inspectBinding(binding).lastClose?.closeReason)
        .toBe('counter-exhausted:local object identity');
      binding.revoke();
      binding.revoke();
    }
  });

  test('uses the final adapter request ordinal exactly once before fail-closed exhaustion', async () => {
    const requestDeviceWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUAdapter.requestDevice',
    )?.wireId;
    if (requestDeviceWireId === undefined) {
      throw new Error('missing requestDevice route');
    }
    for (const [seed, successCount] of [
      [U64_MAX_MINUS_ONE, 2],
      [U64_MAX, 1],
    ] as const) {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs([], { distinctLiveDevices: true }),
        {
          counterSeeds: { nextAdapterOrdinal: seed },
          enableStateInspection: true,
        },
      );
      const adapter = await (binding.gpu as {
        requestAdapter(): Promise<unknown>;
      }).requestAdapter() as {
        requestDevice(): Promise<unknown>;
      };
      const attempts = Array.from(
        { length: successCount + 1 },
        () => adapter.requestDevice(),
      );
      const outcomes = await Promise.allSettled(attempts);
      expect(outcomes.at(-1)?.status).toBe('rejected');
      expect((outcomes.at(-1) as PromiseRejectedResult).reason).toBeInstanceOf(
        RangeError,
      );
      expect(
        bridge.submissions
          .filter((submission) => submission.operationId === requestDeviceWireId)
          .map((submission) => submission.metadata.adapterOrdinal),
      ).toEqual(successCount === 2 ? [U64_MAX_MINUS_ONE, U64_MAX] : [U64_MAX]);
      expect(inspectBinding(binding).current).toMatchObject({
        active: false,
        routedDeviceCount: 0,
        pendingPromiseCount: 0,
      });
      expect(inspectBinding(binding).lastClose?.closeReason)
        .toBe('counter-exhausted:adapter request ordinal');
      binding.revoke();
    }
  });

  test('uses the final error scope identity exactly once before fail-closed exhaustion', async () => {
    for (const [seed, successCount] of [
      [U64_MAX_MINUS_ONE, 2],
      [U64_MAX, 1],
    ] as const) {
      const bridge = createFakeBridge();
      const codecs = createFakeCodecs();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        codecs,
        {
          counterSeeds: { nextScopeId: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding) as TestGpuDevice & {
        pushErrorScope(filter: string): void;
      };
      for (let index = 0; index < successCount; index += 1) {
        device.pushErrorScope('validation');
      }
      expect(
        codecs.encodings
          .filter((encoding) =>
            encoding.operationId === 'GPUDevice.pushErrorScope'
          )
          .map((encoding) =>
            encoding.errorScopeService?.scopeId
          ),
      ).toEqual(successCount === 2 ? [U64_MAX_MINUS_ONE, U64_MAX] : [U64_MAX]);
      const submissionCount = bridge.submissions.length;
      expect(() => device.pushErrorScope('validation')).toThrow(RangeError);
      expect(bridge.submissions).toHaveLength(submissionCount);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      expect(inspectBinding(binding).current).toMatchObject({
        active: false,
        routedDeviceCount: 0,
        pendingLocalRecordCount: 0,
        pendingPromiseCount: 0,
      });
      expect(inspectBinding(binding).lastClose?.closeReason)
        .toBe('counter-exhausted:error scope identity');
      binding.revoke();
    }
  });

  test('fails canvas generation and epoch exhaustion closed before submission or texture allocation', async () => {
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    for (const [seed, successfulConfigures] of [
      [U64_MAX_MINUS_ONE, 1],
      [U64_MAX, 0],
    ] as const) {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        {
          counterSeeds: { canvasConfigurationGeneration: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding);
      const context = mintTestCanvasContext(binding);
      for (let index = 0; index < successfulConfigures; index += 1) {
        context.configure({ device, format: 'bgra8unorm' });
      }
      const beforeFailure = inspectBinding(binding).current;
      const submissionCount = bridge.submissions.length;
      expect(() => context.configure({ device, format: 'bgra8unorm' }))
        .toThrow(RangeError);
      expect(bridge.submissions).toHaveLength(submissionCount);
      expect(
        bridge.submissions.filter(
          (submission) => submission.operationId === configureWireId,
        ),
      ).toHaveLength(successfulConfigures);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(beforeFailure.allocatedWrapperCount);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      binding.revoke();
    }

    for (const [seed, hasFirstTexture] of [
      [U64_MAX_MINUS_ONE, true],
      [U64_MAX, false],
    ] as const) {
      const binding = createProductionWebGpuPrivateBinding(
        createFakeBridge(),
        createFakeCodecs(),
        {
          counterSeeds: { canvasCurrentEpoch: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding);
      const context = mintTestCanvasContext(binding);
      context.configure({ device, format: 'bgra8unorm' });
      if (hasFirstTexture) {
        expect(context.getCurrentTexture()).toBeObject();
        context.configure({ device, format: 'bgra8unorm' });
      }
      const beforeFailure = inspectBinding(binding).current;
      expect(() => context.getCurrentTexture()).toThrow(RangeError);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(beforeFailure.allocatedWrapperCount);
      expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      binding.revoke();
    }
  });

  test('preflights every configured context before applying a batch loss transition', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      {
        counterSeeds: {
          canvasConfigurationGeneration: U64_MAX_MINUS_TWO,
        },
        enableStateInspection: true,
      },
    );
    const device = await requestTestDevice(binding);
    const first = mintTestCanvasContext(binding);
    const second = binding.mintCanvasContext({
      objectId: '402',
      objectGeneration: '1',
      drawingBufferWidth: 800,
      drawingBufferHeight: 600,
      authority: {
        ...CANVAS_AUTHORITY,
        surfaceAccountToken: '99',
        surfaceAccountGeneration: '1',
      },
    }) as TestCanvasContext;
    first.configure({ device, format: 'bgra8unorm' });
    second.configure({ device, format: 'bgra8unorm' });
    second.configure({ device, format: 'bgra8unorm' });
    expect(inspectBinding(binding).current.canvasLossTransitionCount).toBe(0);

    emitProviderLoss(bridge);
    expect(await device.lost).toEqual({
      reason: 'unknown',
      message:
        'The WebGPU realm closed because canvas configuration generation was exhausted',
    });
    expect(() => first.getConfiguration()).toThrow('realm is revoked');
    expect(() => second.getConfiguration()).toThrow('realm is revoked');
    const inspection = inspectBinding(binding);
    expect(inspection.current).toMatchObject({
      active: false,
      routedDeviceCount: 0,
      indexedCanvasContextCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
      canvasLossTransitionCount: 0,
    });
    expect(inspection.lastClose).toMatchObject({
      routedDeviceCount: 1,
      indexedCanvasContextCount: 2,
      indexedCanvasObjectCount: 2,
      indexedCanvasSurfaceTokenCount: 2,
      canvasLossTransitionCount: 0,
    });
    emitProviderLoss(bridge);
    expect(await device.lost).toEqual({
      reason: 'unknown',
      message:
        'The WebGPU realm closed because canvas configuration generation was exhausted',
    });
    binding.revoke();
  });

  test('uses MAX once for local operation and device ingress identities, then clears timelines', async () => {
    for (const [seed, successfulRecords] of [
      [U64_MAX_MINUS_ONE, 2],
      [U64_MAX, 1],
    ] as const) {
      const binding = createProductionWebGpuPrivateBinding(
        createFakeBridge(),
        createFakeCodecs(),
        {
          counterSeeds: { nextLocalOperationInstanceId: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding);
      const context = mintTestCanvasContext(binding);
      context.configure({ device, format: 'bgra8unorm' });
      let texture: TestCanvasTexture | undefined;
      for (let index = 0; index < successfulRecords; index += 1) {
        texture = context.getCurrentTexture();
      }
      expect(texture).toBeObject();
      expect(inspectBinding(binding).current.pendingLocalRecordCount)
        .toBe(successfulRecords);
      const beforeFailure = inspectBinding(binding).current;
      expect(() => context.getCurrentTexture()).toThrow(RangeError);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(beforeFailure.allocatedWrapperCount);
      expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      binding.revoke();
    }

    for (const [seed, successfulLocalRecords] of [
      [U64_MAX_MINUS_ONE, 1],
      [U64_MAX, 0],
    ] as const) {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        {
          counterSeeds: { nextDeviceIngressOrdinal: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding);
      const context = mintTestCanvasContext(binding);
      context.configure({ device, format: 'bgra8unorm' });
      if (successfulLocalRecords === 1) context.getCurrentTexture();
      const beforeFailure = inspectBinding(binding).current;
      expect(() => context.getCurrentTexture()).toThrow(RangeError);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(beforeFailure.allocatedWrapperCount);
      expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      binding.revoke();
    }
  });

  test('uses MAX once for queue ingress and closes before a further service submission', async () => {
    const submitWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUQueue.submit',
    )?.wireId;
    if (submitWireId === undefined) throw new Error('missing queue submit route');
    for (const [seed, successCount] of [
      [U64_MAX_MINUS_ONE, 2],
      [U64_MAX, 1],
    ] as const) {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        {
          counterSeeds: { nextQueueIngressOrdinal: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding) as TestGpuDevice & {
        readonly queue: { submit(commandBuffers: readonly unknown[]): void };
      };
      for (let index = 0; index < successCount; index += 1) {
        device.queue.submit([]);
      }
      expect(
        bridge.submissions
          .filter((submission) => submission.operationId === submitWireId)
          .map((submission) => submission.metadata.queueIngressOrdinal),
      ).toEqual(successCount === 2 ? [U64_MAX_MINUS_ONE, U64_MAX] : [U64_MAX]);
      const submissionCount = bridge.submissions.length;
      const allocationCount = inspectBinding(binding).current.allocatedWrapperCount;
      expect(() => device.queue.submit([])).toThrow(RangeError);
      expect(bridge.submissions).toHaveLength(submissionCount);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(allocationCount);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      binding.revoke();
    }
  });

  test('preflights canvas queue exhaustion before configuration or current-texture mutation', async () => {
    for (const operation of ['reconfigure', 'unconfigure'] as const) {
      const bridge = createFakeBridge();
      const codecs = createFakeCodecs();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        codecs,
        {
          counterSeeds: { nextQueueIngressOrdinal: U64_MAX },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding);
      const context = mintTestCanvasContext(binding);
      context.configure({ device, format: 'bgra8unorm' });
      context.getCurrentTexture();

      const configureEncodings = codecs.encodings.filter(
        (encoding) => encoding.operationId === 'GPUCanvasContext.configure',
      );
      expect(configureEncodings).toHaveLength(1);
      expect(configureEncodings[0]?.queueIngressOrdinal).toBe(U64_MAX);

      const beforeFailure = inspectBinding(binding).current;
      expect(beforeFailure.pendingLocalRecordCount).toBe(1);
      const encodingCount = codecs.encodings.length;
      const submissionCount = bridge.submissions.length;
      const invoke = operation === 'reconfigure'
        ? () => context.configure({ device, format: 'rgba8unorm' })
        : () => context.unconfigure();

      expect(invoke).toThrow(RangeError);
      expect(codecs.encodings).toHaveLength(encodingCount);
      expect(bridge.submissions).toHaveLength(submissionCount);
      expect(inspectBinding(binding).lastClose).toMatchObject({
        closeReason: 'counter-exhausted:queue ingress ordinal',
        allocatedWrapperCount: beforeFailure.allocatedWrapperCount,
        indexedCanvasContextCount: beforeFailure.indexedCanvasContextCount,
        indexedCanvasObjectCount: beforeFailure.indexedCanvasObjectCount,
        indexedCanvasSurfaceTokenCount:
          beforeFailure.indexedCanvasSurfaceTokenCount,
        invalidCurrentTextureCount: beforeFailure.invalidCurrentTextureCount,
        pendingLocalRecordCount: beforeFailure.pendingLocalRecordCount,
      });
      expect(await device.lost).toEqual({
        reason: 'unknown',
        message:
          'The WebGPU realm closed because queue ingress ordinal was exhausted',
      });
      binding.revoke();
    }
  });

  test('does not retain an unbounded series of service-detached lost devices', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs([], { detachedDevices: true });
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const adapter = (await (binding.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter()) as {
      requestDevice(): Promise<unknown>;
    };
    let firstLost: Promise<unknown> | undefined;
    for (let index = 0; index < 1_100; index += 1) {
      const device = (await adapter.requestDevice()) as {
        readonly lost: Promise<unknown>;
      };
      if (!firstLost) {
        firstLost = device.lost;
        expect(
          await Promise.race([
            device.lost,
            Promise.resolve('request-device-resolved-first'),
          ]),
        ).toEqual({
          reason: 'unknown',
          message: 'The adapter is expired',
        });
      }
      expect(await device.lost).toEqual({
        reason: 'unknown',
        message: 'The adapter is expired',
      });
    }
    binding.revoke();
    expect(firstLost).toBeDefined();
    expect(await firstLost!).toEqual({
      reason: 'unknown',
      message: 'The adapter is expired',
    });
  });
});

describe('production-private GPUBuffer lifecycle', () => {
  test('aliases the mapped-at-creation root and writes back one exact full extent', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      enableStateInspection: true,
    });
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({
      mappedAtCreation: true,
      size: 16,
      usage: 9,
    });

    expect(buffer.mapState).toBe('mapped');
    expect(inspectBinding(binding).current.trackedBufferLifecycleCount).toBe(1);
    const first = buffer.getMappedRange(0, 4);
    const second = buffer.getMappedRange(8, 8);
    expect(() => buffer.getMappedRange(0, 4)).toThrow('unavailable');
    expect(bridge.mappedRangeAliasMints).toHaveLength(2);
    expect(bridge.mappedRangeAliasMints.map((mint) => ({
      byteOffset: mint.byteOffset,
      byteLength: mint.byteLength,
      alias: mint.alias,
    }))).toEqual([
      { byteOffset: 0, byteLength: 4, alias: first },
      { byteOffset: 8, byteLength: 8, alias: second },
    ]);
    expect(bridge.mappedRangeAliasMints[1]!.source)
      .toBe(bridge.mappedRangeAliasMints[0]!.source);
    new Uint8Array(first).set([1, 2, 3, 4]);
    new Uint8Array(second).set([9, 10, 11, 12, 13, 14, 15, 16]);

    const beforeUnmap = bridge.submissions.length;
    expect(buffer.unmap()).toBeUndefined();
    expect(bridge.submissions).toHaveLength(beforeUnmap + 1);
    expect(buffer.mapState).toBe('unmapped');
    expect(inspectBinding(binding).current.trackedBufferLifecycleCount).toBe(0);
    expect(isDetachedArrayBuffer(first)).toBe(true);
    expect(isDetachedArrayBuffer(second)).toBe(true);
    expect(bridge.mappedRangeDetachAttempts).toEqual([first, second]);

    const unmapBody = bufferLifecycleEncodings(codecs, 'GPUBuffer.unmap').at(-1);
    expect(unmapBody).toMatchObject({
      kind: 'cleanup-v1',
      cleanupAction: 1,
      cleanupGeneration: '1',
      cancelledMapGeneration: '0',
      activeMapGeneration: '1',
      activeMapMode: 2,
      mappedOffset: '0',
      mappedSize: '16',
    });
    if (!unmapBody || unmapBody.kind !== 'cleanup-v1') {
      throw new Error('missing unmap cleanup body');
    }
    expect(Array.from(new Uint8Array(
      unmapBody.writeback.buffer,
      unmapBody.writeback.byteOffset,
      unmapBody.writeback.byteLength,
    ))).toEqual([
      1,
      2,
      3,
      4,
      0,
      0,
      0,
      0,
      9,
      10,
      11,
      12,
      13,
      14,
      15,
      16,
    ]);

    const afterUnmap = bridge.submissions.length;
    expect(buffer.unmap()).toBeUndefined();
    expect(bridge.submissions).toHaveLength(afterUnmap);
    expect(buffer.destroy()).toBeUndefined();
    const destroyBody = bufferLifecycleEncodings(codecs, 'GPUBuffer.destroy').at(-1);
    expect(destroyBody).toMatchObject({
      kind: 'cleanup-v1',
      cleanupAction: 2,
      cleanupGeneration: '2',
      activeMapGeneration: '0',
      activeMapMode: 0,
    });
    const afterDestroy = bridge.submissions.length;
    expect(buffer.destroy()).toBeUndefined();
    expect(bridge.submissions).toHaveLength(afterDestroy);
    binding.revoke();
    expect(bridge.mappedRangeDetachAttempts).toEqual([first, second]);
  });

  test('rejects overlapping wrapper leases before minting a second engine alias', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({
      mappedAtCreation: true,
      size: 24,
      usage: 9,
    });
    const first = buffer.getMappedRange(0, 12);

    expect(() => buffer.getMappedRange(8, 8)).toThrow('unavailable');
    expect(bridge.mappedRangeAliasMints.map((mint) => mint.alias)).toEqual([first]);
    buffer.destroy();
    expect(bridge.mappedRangeDetachAttempts).toEqual([first]);
    binding.revoke();
  });

  test('tracks a malformed minted alias before validation and offers one detach', async () => {
    const bridge = createFakeBridge();
    const malformedAlias = new ArrayBuffer(3);
    Object.defineProperty(bridge, 'createMappedRangeAlias', {
      configurable: true,
      value: () => malformedAlias,
    });
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({
      mappedAtCreation: true,
      size: 8,
      usage: 9,
    });

    expect(() => buffer.getMappedRange(0, 4)).toThrow('wrong extent');
    expect(bridge.mappedRangeDetachAttempts).toEqual([malformedAlias]);
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      closeReason: 'buffer-mapped-range-mint-contradiction',
      trackedBufferLifecycleCount: 0,
    });

    binding.revoke();
    expect(bridge.mappedRangeDetachAttempts).toEqual([malformedAlias]);
  });

  test('detaches mapped aliases exactly once on device destroy', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({
      mappedAtCreation: true,
      size: 8,
      usage: 9,
    });
    const range = buffer.getMappedRange();

    expect(device.destroy()).toBeUndefined();
    expect(buffer.mapState).toBe('unmapped');
    expect(isDetachedArrayBuffer(range)).toBe(true);
    expect(bridge.mappedRangeDetachAttempts).toEqual([range]);
    expect(device.destroy()).toBeUndefined();
    binding.revoke();
    expect(bridge.mappedRangeDetachAttempts).toEqual([range]);
  });

  test('retains the typed MAP_READ completion view without copying and discards mutations', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    let decodedOwnedBytes: Uint8Array | undefined;
    const decode = codecs.decodeServiceResult.bind(codecs);
    Object.defineProperty(codecs, 'decodeServiceResult', {
      value(operationId: string, event: OperationResultEvent) {
        const result = decode(operationId, event);
        if (operationId === 'GPUBuffer.mapAsync' && result.kind === 'value') {
          decodedOwnedBytes = (
            result.value as Readonly<{ ownedBytes: Uint8Array }>
          ).ownedBytes;
        }
        return result;
      },
    });
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      enableStateInspection: true,
    });
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({ size: 8, usage: 1 });
    bridge.setPromiseResultHook((event) => bufferMapResultEvent(event, {
      variant: 'mapped-bytes',
      pendingMapGeneration: '1',
      mode: 1,
      offset: '0',
      size: '8',
      ownedBytes: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]),
    }));

    const mapping = buffer.mapAsync(1, 0, 8);
    expect(buffer.mapState).toBe('pending');
    await expect(mapping).resolves.toBeUndefined();
    expect(buffer.mapState).toBe('mapped');
    expect(decodedOwnedBytes).toBeDefined();
    decodedOwnedBytes!.fill(99);
    const range = buffer.getMappedRange();
    expect(Array.from(new Uint8Array(range))).toEqual(new Array(8).fill(99));
    expect(bridge.mappedRangeAliasMints).toHaveLength(1);
    expect(bridge.mappedRangeAliasMints[0]).toMatchObject({
      source: decodedOwnedBytes!.buffer,
      byteOffset: decodedOwnedBytes!.byteOffset,
      byteLength: decodedOwnedBytes!.byteLength,
      alias: range,
    });
    new Uint8Array(range).fill(42);
    buffer.unmap();
    expect(isDetachedArrayBuffer(range)).toBe(true);
    const cleanup = bufferLifecycleEncodings(codecs, 'GPUBuffer.unmap').at(-1);
    expect(cleanup).toMatchObject({
      kind: 'cleanup-v1',
      activeMapGeneration: '1',
      activeMapMode: 1,
      mappedOffset: '0',
      mappedSize: '8',
    });
    if (!cleanup || cleanup.kind !== 'cleanup-v1') {
      throw new Error('missing MAP_READ cleanup');
    }
    expect(cleanup.writeback.byteLength).toBe(0);
    binding.revoke();
  });

  test('shares MAP_WRITE aliases with the retained codec view without shadow writeback', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    let decodedOwnedBytes: Uint8Array | undefined;
    const decode = codecs.decodeServiceResult.bind(codecs);
    Object.defineProperty(codecs, 'decodeServiceResult', {
      value(operationId: string, event: OperationResultEvent) {
        const result = decode(operationId, event);
        if (operationId === 'GPUBuffer.mapAsync' && result.kind === 'value') {
          decodedOwnedBytes = (
            result.value as Readonly<{ ownedBytes: Uint8Array }>
          ).ownedBytes;
        }
        return result;
      },
    });
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({ size: 8, usage: 2 });
    bridge.setPromiseResultHook((event) => bufferMapResultEvent(event, {
      variant: 'mapped-bytes',
      pendingMapGeneration: '1',
      mode: 2,
      offset: '0',
      size: '8',
      ownedBytes: new Uint8Array(8),
    }));

    await expect(buffer.mapAsync(2, 0, 8)).resolves.toBeUndefined();
    const range = buffer.getMappedRange();
    new Uint8Array(range).set([8, 7, 6, 5, 4, 3, 2, 1]);
    buffer.unmap();

    const cleanup = bufferLifecycleEncodings(codecs, 'GPUBuffer.unmap').at(-1);
    if (!cleanup || cleanup.kind !== 'cleanup-v1' || !decodedOwnedBytes) {
      throw new Error('missing MAP_WRITE cleanup or retained codec view');
    }
    expect(cleanup.writeback).toBe(decodedOwnedBytes);
    expect(Array.from(cleanup.writeback)).toEqual([8, 7, 6, 5, 4, 3, 2, 1]);
    expect(bridge.mappedRangeDetachAttempts).toEqual([range]);
    binding.revoke();
  });

  test('reclaims a native mapping when its wrapper allocation cannot be admitted', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const unmapWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUBuffer.unmap',
    )?.wireId;
    if (unmapWireId === undefined) throw new Error('missing GPUBuffer.unmap route');
    let rejectCleanup = true;
    bridge.setSubmitHook((operationId) =>
      operationId === unmapWireId && rejectCleanup ? 17 : 0);
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      enableStateInspection: true,
      privateMappedAllocationGuardLimitBytes: 4,
    });
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({ size: 8, usage: 2 });
    bridge.setPromiseResultHook((event) => bufferMapResultEvent(event, {
      variant: 'mapped-bytes',
      pendingMapGeneration: '1',
      mode: 2,
      offset: '0',
      size: '8',
      ownedBytes: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]),
    }));

    await expect(buffer.mapAsync(2, 0, 8)).rejects.toBeInstanceOf(RangeError);
    expect(buffer.mapState).toBe('unmapped');
    expect(inspectBinding(binding).current).toMatchObject({
      active: true,
      privateMappedAllocationGuardBytes: 0,
      trackedBufferLifecycleCount: 1,
    });

    rejectCleanup = false;
    expect(buffer.unmap()).toBeUndefined();
    expect(inspectBinding(binding).current.trackedBufferLifecycleCount).toBe(0);
    const cleanupRequests = bufferLifecycleEncodings(codecs, 'GPUBuffer.unmap');
    expect(cleanupRequests).toHaveLength(2);
    for (const cleanup of cleanupRequests) {
      expect(cleanup).toMatchObject({
        kind: 'cleanup-v1',
        cleanupAction: 1,
        cleanupGeneration: '1',
        cancelledMapGeneration: '0',
        activeMapGeneration: '1',
        activeMapMode: 2,
        mappedOffset: '0',
        mappedSize: '8',
      });
      if (cleanup.kind !== 'cleanup-v1') {
        throw new Error('missing failed-map reclamation body');
      }
      expect(Array.from(cleanup.writeback)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    }
    binding.revoke();
  });

  test('settles every typed failure variant and rejects mismatched generations', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      enableStateInspection: true,
    });
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({ size: 4, usage: 1 });
    const outcomes = [
      ['provider-operation-error', 'OperationError'],
      ['allocation-range-error', 'RangeError'],
      ['late-cancelled-cleanup', 'AbortError'],
    ] as const;
    let outcomeIndex = 0;
    bridge.setPromiseResultHook((event) => {
      const body = bufferLifecycleEncodings(codecs, 'GPUBuffer.mapAsync').at(-1);
      if (!body || body.kind !== 'map-async-v1') {
        throw new Error('missing map lifecycle body');
      }
      const outcome = outcomes[outcomeIndex++]!;
      return bufferMapResultEvent(event, {
        variant: outcome[0],
        pendingMapGeneration: body.pendingMapGeneration,
        mode: 1,
        offset: '0',
        size: '4',
        ownedBytes: new Uint8Array(0),
      });
    });

    for (const [, errorName] of outcomes) {
      const pending = buffer.mapAsync(1, 0, 4);
      expect(buffer.mapState).toBe('pending');
      await expect(pending).rejects.toMatchObject({ name: errorName });
      expect(buffer.mapState).toBe('unmapped');
    }
    bridge.setPromiseResultHook((event) => bufferMapResultEvent(event, {
      variant: 'mapped-bytes',
      pendingMapGeneration: '999',
      mode: 1,
      offset: '0',
      size: '4',
      ownedBytes: Uint8Array.from([1, 2, 3, 4]),
    }));
    await expect(buffer.mapAsync(1, 0, 4)).rejects.toMatchObject({
      name: 'OperationError',
    });
    expect(buffer.mapState).toBe('unmapped');
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      closeReason: 'buffer-map-terminal-mismatch',
      trackedBufferLifecycleCount: 0,
    });
    expect(
      bufferLifecycleEncodings(codecs, 'GPUBuffer.mapAsync')
        .map((body) => body.kind === 'map-async-v1'
          ? body.pendingMapGeneration
          : 'cleanup'),
    ).toEqual(['1', '2', '3', '4']);
    binding.revoke();
  });

  test('cancels pending maps once and ignores a generation-matched late success', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({ size: 8, usage: 1 });
    let release: (() => void) | undefined;
    bridge.setPromiseResultHook((event) => new Promise((resolve) => {
      release = () => resolve(bufferMapResultEvent(event, {
        variant: 'mapped-bytes',
        pendingMapGeneration: '1',
        mode: 1,
        offset: '0',
        size: '8',
        ownedBytes: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]),
      }));
    }));

    const pending = buffer.mapAsync(1, 0, 8);
    await Promise.resolve();
    expect(buffer.mapState).toBe('pending');
    expect(buffer.unmap()).toBeUndefined();
    expect(buffer.mapState).toBe('unmapped');
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(bridge.cancellations).toHaveLength(1);
    expect(bufferLifecycleEncodings(codecs, 'GPUBuffer.unmap').at(-1))
      .toMatchObject({
        kind: 'cleanup-v1',
        cleanupGeneration: '1',
        cancelledMapGeneration: '1',
        activeMapGeneration: '0',
      });
    expect(release).toBeFunction();
    release!();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    expect(buffer.mapState).toBe('unmapped');
    expect(() => buffer.getMappedRange()).toThrow('no active mapping');
    binding.revoke();
  });

  test('refuses duplicate pending and active maps before generation or service ingress', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestLifecycleDevice(binding);

    const activeBuffer = device.createBuffer({
      mappedAtCreation: true,
      size: 8,
      usage: 9,
    });
    const beforeActiveAttempt = bridge.submissions.length;
    const activeMapBodiesBefore = bufferLifecycleEncodings(
      codecs,
      'GPUBuffer.mapAsync',
    ).length;
    let activeAttempt!: Promise<undefined>;
    expect(() => {
      activeAttempt = activeBuffer.mapAsync(2, 0, 8);
    }).not.toThrow();
    await expect(activeAttempt).rejects.toMatchObject({ name: 'OperationError' });
    expect(bridge.submissions).toHaveLength(beforeActiveAttempt);
    expect(bufferLifecycleEncodings(codecs, 'GPUBuffer.mapAsync'))
      .toHaveLength(activeMapBodiesBefore);
    activeBuffer.unmap();

    const buffer = device.createBuffer({ size: 8, usage: 1 });
    let release: (() => void) | undefined;
    bridge.setPromiseResultHook((event) => new Promise((resolve) => {
      release = () => resolve(bufferMapResultEvent(event, {
        variant: 'mapped-bytes',
        pendingMapGeneration: '1',
        mode: 1,
        offset: '0',
        size: '8',
        ownedBytes: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]),
      }));
    }));
    const first = buffer.mapAsync(1, 0, 8);
    expect(buffer.mapState).toBe('pending');
    const beforePendingAttempt = bridge.submissions.length;
    const pendingMapBodiesBefore = bufferLifecycleEncodings(
      codecs,
      'GPUBuffer.mapAsync',
    ).length;
    let duplicate!: Promise<undefined>;
    expect(() => {
      duplicate = buffer.mapAsync(1, 0, 8);
    }).not.toThrow();
    await expect(duplicate).rejects.toMatchObject({ name: 'OperationError' });
    expect(bridge.submissions).toHaveLength(beforePendingAttempt);
    expect(bufferLifecycleEncodings(codecs, 'GPUBuffer.mapAsync'))
      .toHaveLength(pendingMapBodiesBefore);

    buffer.unmap();
    await expect(first).rejects.toMatchObject({ name: 'AbortError' });
    expect(release).toBeFunction();
    release!();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    bridge.setPromiseResultHook((event) => bufferMapResultEvent(event, {
      variant: 'mapped-bytes',
      pendingMapGeneration: '2',
      mode: 1,
      offset: '0',
      size: '8',
      ownedBytes: Uint8Array.from([8, 7, 6, 5, 4, 3, 2, 1]),
    }));
    await expect(buffer.mapAsync(1, 0, 8)).resolves.toBeUndefined();
    expect(bufferLifecycleEncodings(codecs, 'GPUBuffer.mapAsync').map((body) =>
      body.kind === 'map-async-v1' ? body.pendingMapGeneration : 'cleanup'
    )).toEqual(['1', '2']);
    buffer.unmap();
    binding.revoke();
  });

  test('retries synchronous map and cleanup rejection with stable local generations', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestLifecycleDevice(binding);
    const mapWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUBuffer.mapAsync',
    )?.wireId;
    const unmapWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUBuffer.unmap',
    )?.wireId;
    if (mapWireId === undefined || unmapWireId === undefined) {
      throw new Error('missing GPUBuffer lifecycle routes');
    }
    let rejectMap = true;
    let rejectCleanup = false;
    bridge.setSubmitHook((operationId) =>
      (operationId === mapWireId && rejectMap) ||
        (operationId === unmapWireId && rejectCleanup)
        ? 17
        : 0);
    const buffer = device.createBuffer({ size: 8, usage: 2 });
    await expect(buffer.mapAsync(2, 0, 8)).rejects.toMatchObject({
      name: 'OperationError',
    });
    expect(buffer.mapState).toBe('unmapped');
    rejectMap = false;
    bridge.setPromiseResultHook((event) => bufferMapResultEvent(event, {
      variant: 'mapped-bytes',
      pendingMapGeneration: '1',
      mode: 2,
      offset: '0',
      size: '8',
      ownedBytes: new Uint8Array(8),
    }));
    await expect(buffer.mapAsync(2, 0, 8)).resolves.toBeUndefined();
    const mapRequests = codecs.encodings.filter(
      (encoding) => encoding.operationId === 'GPUBuffer.mapAsync',
    );
    expect(mapRequests.map((encoding) =>
      encoding.bufferLifecycle?.kind === 'map-async-v1'
        ? encoding.bufferLifecycle.pendingMapGeneration
        : undefined)).toEqual(['1', '1']);
    expect(mapRequests.map((encoding) => encoding.deviceIngressOrdinal))
      .toEqual(['2', '3']);
    buffer.unmap();

    const retryBuffer = device.createBuffer({
      mappedAtCreation: true,
      size: 8,
      usage: 9,
    });
    const retryRange = retryBuffer.getMappedRange();
    new Uint8Array(retryRange).set([8, 7, 6, 5, 4, 3, 2, 1]);
    rejectCleanup = true;
    expect(retryBuffer.unmap()).toBeUndefined();
    expect(retryBuffer.mapState).toBe('unmapped');
    expect(isDetachedArrayBuffer(retryRange)).toBe(true);
    rejectCleanup = false;
    expect(retryBuffer.unmap()).toBeUndefined();
    const cleanupRequests = codecs.encodings
      .filter((encoding) => encoding.operationId === 'GPUBuffer.unmap')
      .slice(-2);
    expect(cleanupRequests.map((encoding) =>
      encoding.bufferLifecycle?.kind === 'cleanup-v1'
        ? encoding.bufferLifecycle.cleanupGeneration
        : undefined)).toEqual(['1', '1']);
    expect(cleanupRequests.map((encoding) => encoding.deviceIngressOrdinal))
      .toEqual(['6', '7']);
    const retryBodies = cleanupRequests.map((encoding) => encoding.bufferLifecycle);
    for (const body of retryBodies) {
      expect(body).toMatchObject({
        kind: 'cleanup-v1',
        cleanupGeneration: '1',
        activeMapGeneration: '1',
        activeMapMode: 2,
      });
      if (!body || body.kind !== 'cleanup-v1') {
        throw new Error('missing cleanup retry body');
      }
      expect(Array.from(new Uint8Array(
        body.writeback.buffer,
        body.writeback.byteOffset,
        body.writeback.byteLength,
      ))).toEqual([8, 7, 6, 5, 4, 3, 2, 1]);
    }
    binding.revoke();
  });

  test('treats kind-2 receipt rejection as validation without an uncaptured event', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestLifecycleDevice(binding) as
      TestLifecycleDevice & EventTarget;
    const buffer = device.createBuffer({ size: 4, usage: 1 });
    let uncapturedCount = 0;
    device.addEventListener('uncapturederror', () => {
      uncapturedCount += 1;
    });
    bridge.setPromiseResultHook((event) => {
      bridge.emit({
        ...event,
        kind: 2,
        uncapturedError: false,
        errorKind: 1,
        backendClass: 0,
        status: 1,
        payload: new Uint8Array(0),
      } as NativeGpuEventV2);
      const error = new Error('captured validation rejection');
      error.name = 'GPUValidationError';
      throw error;
    });

    await expect(buffer.mapAsync(1, 0, 4)).rejects.toMatchObject({
      name: 'OperationError',
    });
    expect(buffer.mapState).toBe('unmapped');
    expect(uncapturedCount).toBe(0);
    binding.revoke();
  });

  test('queues an authenticated uncaptured error without replacing its operation terminal', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestLifecycleDevice(binding) as
      TestLifecycleDevice & EventTarget;
    const buffer = device.createBuffer({ size: 4, usage: 1 });
    const uncaptured = new Promise<Event>((resolve) => {
      device.addEventListener('uncapturederror', resolve, { once: true });
    });
    bridge.setPromiseResultHook((event) => {
      bridge.emit({
        ...event,
        kind: 2,
        uncapturedError: true,
        errorKind: 1,
        backendClass: 1,
        status: -1,
        payload: new Uint8Array([
          0x63, 0x6f, 0x72, 0x70, 0x75, 0x73, 0x20, 0x76,
          0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f,
          0x6e,
        ]),
      } as NativeGpuEventV2);
      return bufferMapResultEvent(event, {
        variant: 'mapped-bytes',
        pendingMapGeneration: '1',
        mode: 1,
        offset: '0',
        size: '4',
        ownedBytes: new Uint8Array([1, 2, 3, 4]),
      });
    });

    await expect(buffer.mapAsync(1, 0, 4)).resolves.toBeUndefined();
    const dispatched = await uncaptured;
    const error = (
      dispatched as Event & {
        readonly error: { readonly name: string; readonly message: string };
      }
    ).error;
    expect(dispatched.type).toBe('uncapturederror');
    expect(dispatched.bubbles).toBe(false);
    expect(dispatched.cancelable).toBe(false);
    expect(error.name).toBe('GPUValidationError');
    expect(error.message).toBe('corpus validation');
    expect(Object.getPrototypeOf(dispatched)).toBe(
      (
        binding.interfaceObjects.GPUUncapturedErrorEvent as {
          readonly prototype: object;
        }
      ).prototype,
    );
    expect(Object.getPrototypeOf(error)).toBe(
      (
        binding.interfaceObjects.GPUValidationError as {
          readonly prototype: object;
        }
      ).prototype,
    );
    binding.revoke();
  });

  test('runs rejection reactions before a typed exact-device uncaptured-error task', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestLifecycleDevice(binding) as
      TestLifecycleDevice & EventTarget;
    const buffer = device.createBuffer({ size: 4, usage: 1 });
    const order: string[] = [];
    let observedEvent: Event & { readonly error: object } | undefined;
    device.addEventListener('uncapturederror', (event) => {
      order.push('event');
      observedEvent = event as Event & { readonly error: object };
    });
    bridge.setPromiseResultHook((event) => {
      bridge.emit({
        ...event,
        kind: 2,
        uncapturedError: true,
        errorKind: 1,
        backendClass: 1,
        status: -7,
        payload: Uint8Array.from([
          0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e,
          0x09, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x0a,
        ]),
      });
      throw new Error('mandatory operation terminal rejected');
    });

    const intrinsicGlobalThis = globalThis;
    const originalSetTimeout = intrinsicGlobalThis.setTimeout;
    const originalGlobalThisDescriptor =
      Object.getOwnPropertyDescriptor(intrinsicGlobalThis, 'globalThis');
    if (!originalGlobalThisDescriptor) {
      throw new Error('test realm lacks its globalThis descriptor');
    }
    let replacedTimerCalls = 0;
    const replacedTimer = (() => {
      replacedTimerCalls += 1;
      throw new Error('app timer replacement must not schedule WebGPU tasks');
    }) as unknown as typeof setTimeout;
    intrinsicGlobalThis.setTimeout = replacedTimer;
    Object.defineProperty(intrinsicGlobalThis, 'globalThis', {
      value: { setTimeout: replacedTimer },
      writable: true,
      enumerable: false,
      configurable: true,
    });
    try {
      const completion = buffer.mapAsync(1, 0, 4).catch((error) => {
        order.push('rejection');
        throw error;
      });
      await expect(completion).rejects.toMatchObject({ name: 'OperationError' });
      expect(order).toEqual(['rejection']);
      await new Promise<void>((resolve) => {
        originalSetTimeout(resolve, 5);
      });
    } finally {
      intrinsicGlobalThis.setTimeout = originalSetTimeout;
      Object.defineProperty(
        intrinsicGlobalThis,
        'globalThis',
        originalGlobalThisDescriptor,
      );
    }

    expect(replacedTimerCalls).toBe(0);
    expect(order).toEqual(['rejection', 'event']);
    expect(observedEvent).toBeDefined();
    const dispatched = observedEvent!;
    const eventConstructor =
      binding.interfaceObjects.GPUUncapturedErrorEvent as Function & {
        readonly prototype: object;
      };
    const validationConstructor =
      binding.interfaceObjects.GPUValidationError as Function;
    const gpuErrorConstructor = binding.interfaceObjects.GPUError as Function;
    expect(Object.getPrototypeOf(eventConstructor.prototype)).toBe(Event.prototype);
    expect(dispatched).toBeInstanceOf(Event);
    expect(dispatched).toBeInstanceOf(eventConstructor);
    expect(dispatched.type).toBe('uncapturederror');
    expect(dispatched.target).toBe(device);
    expect(dispatched.bubbles).toBe(false);
    expect(dispatched.cancelable).toBe(false);
    expect(dispatched.composed).toBe(false);
    dispatched.preventDefault();
    expect(dispatched.defaultPrevented).toBe(false);
    expect(dispatched.error).toBeInstanceOf(validationConstructor);
    expect(dispatched.error).toBeInstanceOf(gpuErrorConstructor);
    expect(dispatched.error).toMatchObject({
      name: 'GPUValidationError',
      message: 'validation\tfailed\n',
    });
    const errorGetter = Object.getOwnPropertyDescriptor(
      eventConstructor.prototype,
      'error',
    )?.get;
    expect(errorGetter).toBeFunction();
    expect(() => Reflect.apply(errorGetter!, {}, [])).toThrow(
      'Incompatible GPUUncapturedErrorEvent receiver',
    );
    expect(() => Reflect.construct(eventConstructor, [])).toThrow(
      'Illegal constructor: GPUUncapturedErrorEvent',
    );
    binding.revoke();
  });

  test('dispatches uncaptured-error ingress FIFO with one item per task', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestLifecycleDevice(binding) as
      TestLifecycleDevice & EventTarget;
    const first = device.createBuffer({ size: 4, usage: 1 });
    const second = device.createBuffer({ size: 4, usage: 1 });
    const order: string[] = [];
    device.addEventListener('uncapturederror', (event) => {
      const error = (event as Event & {
        readonly error: { readonly message: string };
      }).error;
      order.push(error.message);
      Promise.resolve().then(() => {
        order.push(`microtask:${error.message}`);
      });
    });
    let sequence = 0;
    bridge.setPromiseResultHook((event) => {
      sequence += 1;
      bridge.emit({
        ...event,
        kind: 2,
        uncapturedError: true,
        errorKind: sequence === 1 ? 2 : 3,
        backendClass: 1,
        status: -1,
        payload: Uint8Array.from([0x30 + sequence]),
      });
      throw new Error(`terminal-${sequence}`);
    });

    await Promise.allSettled([
      first.mapAsync(1, 0, 4),
      second.mapAsync(1, 0, 4),
    ]);
    await new Promise<void>((resolve) => {
      setTimeout(resolve, 10);
    });
    expect(order).toEqual([
      '1',
      'microtask:1',
      '2',
      'microtask:2',
    ]);
    binding.revoke();
  });

  test('fails closed on malformed diagnostic, stale, and cross-device uncaptured ingress', async () => {
    const diagnosticCases = [
      Uint8Array.from([0xc0, 0x80]),
      Uint8Array.from([0xed, 0xa0, 0x80]),
      Uint8Array.from([0xf4, 0x90, 0x80, 0x80]),
      Uint8Array.from([0x00]),
      Uint8Array.from([0xc2, 0x80]),
      new Uint8Array(4_097),
    ];
    for (const payload of diagnosticCases) {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        { enableStateInspection: true },
      );
      const device = await requestTestLifecycleDevice(binding);
      const buffer = device.createBuffer({ size: 4, usage: 1 });
      bridge.setPromiseResultHook((event) => {
        bridge.emit({
          ...event,
          kind: 2,
          uncapturedError: true,
          errorKind: 1,
          backendClass: 1,
          status: -1,
          payload,
        });
        throw new Error('malformed diagnostic terminal');
      });
      await expect(buffer.mapAsync(1, 0, 4)).rejects.toBeDefined();
      expect(inspectBinding(binding).lastClose?.closeReason).toBe(
        'uncaptured-error-malformed',
      );
      binding.revoke();
    }

    const staleBridge = createFakeBridge();
    const staleBinding = createProductionWebGpuPrivateBinding(
      staleBridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const staleDevice = await requestTestLifecycleDevice(staleBinding);
    const staleBuffer = staleDevice.createBuffer({ size: 4, usage: 1 });
    staleBridge.setPromiseResultHook((event) => {
      emitDeviceLoss(staleBridge, '301', '1');
      staleBridge.emit({
        ...event,
        kind: 2,
        uncapturedError: true,
        errorKind: 1,
        backendClass: 1,
        status: -1,
        payload: new Uint8Array(),
      });
      throw new Error('stale terminal');
    });
    await expect(staleBuffer.mapAsync(1, 0, 4)).rejects.toBeDefined();
    expect(inspectBinding(staleBinding).lastClose?.closeReason).toBe(
      'uncaptured-error-malformed',
    );
    staleBinding.revoke();

    const crossBridge = createFakeBridge();
    const crossBinding = createProductionWebGpuPrivateBinding(
      crossBridge,
      createFakeCodecs([], { distinctLiveDevices: true }),
      { enableStateInspection: true },
    );
    const firstDevice = await requestTestLifecycleDevice(crossBinding);
    await requestTestLifecycleDevice(crossBinding);
    const crossBuffer = firstDevice.createBuffer({ size: 4, usage: 1 });
    crossBridge.setPromiseResultHook((event) => {
      crossBridge.emit({
        ...event,
        kind: 2,
        uncapturedError: true,
        errorKind: 1,
        backendClass: 1,
        status: -1,
        logicalDeviceId: '311',
        ingressLogicalDeviceId: '311',
        payload: new Uint8Array(),
      });
      throw new Error('cross-device terminal');
    });
    await expect(crossBuffer.mapAsync(1, 0, 4)).rejects.toBeDefined();
    expect(inspectBinding(crossBinding).lastClose?.closeReason).toBe(
      'uncaptured-error-malformed',
    );
    crossBinding.revoke();
  });

  test('bounds retained uncaptured-error notifications and closes before dispatch', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestLifecycleDevice(binding) as
      TestLifecycleDevice & EventTarget;
    const buffer = device.createBuffer({ size: 4, usage: 1 });
    let dispatchCount = 0;
    device.addEventListener('uncapturederror', () => {
      dispatchCount += 1;
    });
    bridge.setPromiseResultHook((event) => {
      const uncaptured = {
        ...event,
        kind: 2,
        uncapturedError: true,
        errorKind: 1,
        backendClass: 1,
        status: -1,
        payload: new Uint8Array(),
      } as const;
      for (let index = 0; index <= 1_024; index += 1) {
        bridge.emit(uncaptured);
      }
      throw new Error('queue overflow terminal');
    });
    await expect(buffer.mapAsync(1, 0, 4)).rejects.toBeDefined();
    expect(inspectBinding(binding).lastClose?.closeReason).toBe(
      'uncaptured-error-queue-overflow',
    );
    await new Promise<void>((resolve) => {
      setTimeout(resolve, 5);
    });
    expect(dispatchCount).toBe(0);
    binding.revoke();
  });

  test('drops queued uncaptured errors when their realm closes before the task', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestLifecycleDevice(binding) as
      TestLifecycleDevice & EventTarget;
    const buffer = device.createBuffer({ size: 4, usage: 1 });
    let dispatchCount = 0;
    device.addEventListener('uncapturederror', () => {
      dispatchCount += 1;
    });
    bridge.setPromiseResultHook((event) => {
      bridge.emit({
        ...event,
        kind: 2,
        uncapturedError: true,
        errorKind: 1,
        backendClass: 1,
        status: -1,
        payload: new Uint8Array(),
      });
      bridge.emit({
        kind: 6,
        runtimeAddress: bridge.runtimeAddress,
        runtimeNonce: bridge.runtimeNonce,
        realmId: bridge.realmId,
        realmGeneration: bridge.realmGeneration,
        closeOrdinal: '1',
        closeReason: 1,
        payload: new Uint8Array(),
      });
      throw new Error('realm terminal followed the error terminal');
    });
    await expect(buffer.mapAsync(1, 0, 4)).rejects.toBeDefined();
    await new Promise<void>((resolve) => {
      setTimeout(resolve, 5);
    });
    expect(dispatchCount).toBe(0);
    expect(inspectBinding(binding).lastClose?.closeReason).toBe('realm-retired');
    binding.revoke();
  });

  test('rejects foreign brands and Web IDL failures before counters or bridge work', async () => {
    const firstBridge = createFakeBridge();
    const firstCodecs = createFakeCodecs();
    const firstBinding = createProductionWebGpuPrivateBinding(
      firstBridge,
      firstCodecs,
    );
    const secondBridge = createFakeBridge();
    const secondBinding = createProductionWebGpuPrivateBinding(
      secondBridge,
      createFakeCodecs(),
    );
    const firstDevice = await requestTestLifecycleDevice(firstBinding);
    const secondDevice = await requestTestLifecycleDevice(secondBinding);
    const firstBuffer = firstDevice.createBuffer({ size: 4, usage: 1 });
    const foreignBuffer = secondDevice.createBuffer({ size: 4, usage: 1 });
    const bufferPrototype = (
      firstBinding.interfaceObjects.GPUBuffer as { readonly prototype: object }
    ).prototype as {
      mapAsync: (mode: unknown, offset?: unknown, size?: unknown) => Promise<unknown>;
      destroy: () => void;
    };
    const firstBefore = firstBridge.submissions.length;
    const secondBefore = secondBridge.submissions.length;
    expect(() => Reflect.apply(bufferPrototype.mapAsync, foreignBuffer, [1]))
      .toThrow(TypeError);
    expect(() => Reflect.apply(bufferPrototype.destroy, foreignBuffer, []))
      .toThrow(TypeError);
    expect(firstBridge.submissions).toHaveLength(firstBefore);
    expect(secondBridge.submissions).toHaveLength(secondBefore);

    const conversionFailure = new Error('mode conversion failed');
    const mode = Object.freeze({
      [Symbol.toPrimitive]() {
        throw conversionFailure;
      },
    });
    await expect(firstBuffer.mapAsync(mode as unknown as number))
      .rejects.toBe(conversionFailure);
    expect(firstBridge.submissions).toHaveLength(firstBefore);
    firstBridge.setPromiseResultHook((event) => bufferMapResultEvent(event, {
      variant: 'provider-operation-error',
      pendingMapGeneration: '1',
      mode: 1,
      offset: '0',
      size: '4',
      ownedBytes: new Uint8Array(0),
    }));
    await expect(firstBuffer.mapAsync(1, 0, 4)).rejects.toMatchObject({
      name: 'OperationError',
    });
    expect(bufferLifecycleEncodings(firstCodecs, 'GPUBuffer.mapAsync').at(-1))
      .toMatchObject({ kind: 'map-async-v1', pendingMapGeneration: '1' });
    firstBinding.revoke();
    secondBinding.revoke();
  });

  test('enforces the 4,096 nonoverlapping lease cap and detaches every issued range', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({
      mappedAtCreation: true,
      size: 4_097 * 8,
      usage: 9,
    });
    const submissionsBeforeRanges = bridge.submissions.length;
    const ranges: ArrayBuffer[] = [];
    for (let index = 0; index < 4_096; index += 1) {
      ranges.push(buffer.getMappedRange(index * 8, 4));
    }
    expect(bridge.submissions).toHaveLength(submissionsBeforeRanges);
    expect(() => buffer.getMappedRange(4_096 * 8, 4)).toThrow('unavailable');
    expect(buffer.destroy()).toBeUndefined();
    expect(ranges.every(isDetachedArrayBuffer)).toBe(true);
    expect(buffer.mapState).toBe('unmapped');
    expect(bufferLifecycleEncodings(codecs, 'GPUBuffer.destroy').at(-1))
      .toMatchObject({
        kind: 'cleanup-v1',
        cleanupAction: 2,
        cleanupGeneration: '1',
        activeMapGeneration: '1',
      });
    binding.revoke();
  });

  test('rejects mapAsync without service work while destroy cleanup is retained', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const destroyWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUBuffer.destroy',
    )?.wireId;
    if (destroyWireId === undefined) throw new Error('missing GPUBuffer.destroy route');
    let rejectDestroy = true;
    bridge.setSubmitHook((operationId) =>
      operationId === destroyWireId && rejectDestroy ? 17 : 0);
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      enableStateInspection: true,
    });
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({ size: 8, usage: 2 });

    expect(buffer.destroy()).toBeUndefined();
    expect(inspectBinding(binding).current.trackedBufferLifecycleCount).toBe(1);
    const submissionsBeforeMap = bridge.submissions.length;
    const mapBodiesBefore = bufferLifecycleEncodings(
      codecs,
      'GPUBuffer.mapAsync',
    ).length;
    let rejectedMap!: Promise<undefined>;
    expect(() => {
      rejectedMap = buffer.mapAsync(2, 0, 8);
    }).not.toThrow();
    await expect(rejectedMap).rejects.toMatchObject({ name: 'OperationError' });
    expect(bridge.submissions).toHaveLength(submissionsBeforeMap);
    expect(bufferLifecycleEncodings(codecs, 'GPUBuffer.mapAsync'))
      .toHaveLength(mapBodiesBefore);
    expect(buffer.mapState).toBe('unmapped');

    rejectDestroy = false;
    expect(buffer.destroy()).toBeUndefined();
    const destroyBodies = bufferLifecycleEncodings(codecs, 'GPUBuffer.destroy');
    expect(destroyBodies).toHaveLength(2);
    expect(destroyBodies[1]).toBe(destroyBodies[0]);
    expect(destroyBodies[1]).toMatchObject({
      kind: 'cleanup-v1',
      cleanupAction: 2,
      cleanupGeneration: '1',
    });
    expect(inspectBinding(binding).current.trackedBufferLifecycleCount).toBe(0);
    const submissionsAfterDestroy = bridge.submissions.length;
    await expect(buffer.mapAsync(2, 0, 8)).rejects.toMatchObject({
      name: 'OperationError',
    });
    expect(bridge.submissions).toHaveLength(submissionsAfterDestroy);
    binding.revoke();
  });

  test('fences maps across rejected unmap cleanup and its destroy upgrade', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const unmapWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUBuffer.unmap',
    )?.wireId;
    const destroyWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUBuffer.destroy',
    )?.wireId;
    if (unmapWireId === undefined || destroyWireId === undefined) {
      throw new Error('missing GPUBuffer cleanup routes');
    }
    let rejectCleanup = true;
    bridge.setSubmitHook((operationId) =>
      rejectCleanup && (operationId === unmapWireId || operationId === destroyWireId)
        ? 17
        : 0);
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      enableStateInspection: true,
    });
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({
      mappedAtCreation: true,
      size: 8,
      usage: 9,
    });
    const range = buffer.getMappedRange();
    new Uint8Array(range).set([1, 2, 3, 4, 5, 6, 7, 8]);

    expect(buffer.unmap()).toBeUndefined();
    expect(isDetachedArrayBuffer(range)).toBe(true);
    const beforeFirstFencedMap = bridge.submissions.length;
    await expect(buffer.mapAsync(2, 0, 8)).rejects.toMatchObject({
      name: 'OperationError',
    });
    expect(bridge.submissions).toHaveLength(beforeFirstFencedMap);

    expect(buffer.destroy()).toBeUndefined();
    const beforeSecondFencedMap = bridge.submissions.length;
    await expect(buffer.mapAsync(2, 0, 8)).rejects.toMatchObject({
      name: 'OperationError',
    });
    expect(bridge.submissions).toHaveLength(beforeSecondFencedMap);
    expect(buffer.mapState).toBe('unmapped');

    rejectCleanup = false;
    expect(buffer.destroy()).toBeUndefined();
    const unmapBody = bufferLifecycleEncodings(codecs, 'GPUBuffer.unmap')[0];
    const destroyBodies = bufferLifecycleEncodings(codecs, 'GPUBuffer.destroy');
    expect(unmapBody).toMatchObject({ cleanupAction: 1, cleanupGeneration: '1' });
    expect(destroyBodies).toHaveLength(2);
    expect(destroyBodies[1]).toBe(destroyBodies[0]);
    expect(destroyBodies[1]).toMatchObject({
      cleanupAction: 2,
      cleanupGeneration: '1',
      activeMapGeneration: '1',
      activeMapMode: 2,
    });
    if (
      !unmapBody || unmapBody.kind !== 'cleanup-v1' ||
      !destroyBodies[0] || destroyBodies[0].kind !== 'cleanup-v1'
    ) {
      throw new Error('missing upgraded cleanup bodies');
    }
    expect(destroyBodies[0].writeback).toBe(unmapBody.writeback);
    expect(Array.from(destroyBodies[0].writeback))
      .toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(inspectBinding(binding).current.trackedBufferLifecycleCount).toBe(0);
    binding.revoke();
  });

  test('keeps map counter exhaustion on the Promise rejection path', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      counterSeeds: { nextBufferMapGeneration: U64_MAX },
      enableStateInspection: true,
    });
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({ size: 4, usage: 1 });
    bridge.setPromiseResultHook((event) => bufferMapResultEvent(event, {
      variant: 'provider-operation-error',
      pendingMapGeneration: U64_MAX,
      mode: 1,
      offset: '0',
      size: '4',
      ownedBytes: new Uint8Array(0),
    }));

    await expect(buffer.mapAsync(1, 0, 4)).rejects.toMatchObject({
      name: 'OperationError',
    });
    const submissionsBeforeExhaustion = bridge.submissions.length;
    let exhausted!: Promise<undefined>;
    expect(() => {
      exhausted = buffer.mapAsync(1, 0, 4);
    }).not.toThrow();
    await expect(exhausted).rejects.toBeInstanceOf(RangeError);
    expect(bridge.submissions).toHaveLength(submissionsBeforeExhaustion);
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      closeReason: 'counter-exhausted:buffer map generation',
    });
    binding.revoke();
  });

  test('settles rejected maps before cleanup generation exhaustion closes the realm', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      counterSeeds: { nextBufferCleanupGeneration: U64_MAX },
      enableStateInspection: true,
      privateMappedAllocationGuardLimitBytes: 0,
    });
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({ size: 4, usage: 2 });
    bridge.setPromiseResultHook((event) => {
      const body = bufferLifecycleEncodings(codecs, 'GPUBuffer.mapAsync').at(-1);
      if (!body || body.kind !== 'map-async-v1') {
        throw new Error('missing map request body');
      }
      return bufferMapResultEvent(event, {
        variant: 'mapped-bytes',
        pendingMapGeneration: body.pendingMapGeneration,
        mode: 2,
        offset: '0',
        size: '4',
        ownedBytes: Uint8Array.from([1, 2, 3, 4]),
      });
    });

    await expect(buffer.mapAsync(2, 0, 4)).rejects.toBeInstanceOf(RangeError);
    expect(bufferLifecycleEncodings(codecs, 'GPUBuffer.unmap')).toHaveLength(1);
    expect(inspectBinding(binding).current.active).toBe(true);

    let second!: Promise<undefined>;
    expect(() => {
      second = buffer.mapAsync(2, 0, 4);
    }).not.toThrow();
    await expect(second).rejects.toBeInstanceOf(RangeError);
    await Promise.resolve();
    expect(bufferLifecycleEncodings(codecs, 'GPUBuffer.unmap')).toHaveLength(1);
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      closeReason: 'counter-exhausted:buffer cleanup generation',
    });
    binding.revoke();
  });

  test('keeps void cleanup silent and authority-reducing at cleanup counter exhaustion', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      counterSeeds: { nextBufferCleanupGeneration: U64_MAX },
      enableStateInspection: true,
    });
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({
      mappedAtCreation: true,
      size: 4,
      usage: 9,
    });
    expect(buffer.unmap()).toBeUndefined();
    bridge.setPromiseResultHook((event) => bufferMapResultEvent(event, {
      variant: 'mapped-bytes',
      pendingMapGeneration: '2',
      mode: 2,
      offset: '0',
      size: '4',
      ownedBytes: Uint8Array.from([1, 2, 3, 4]),
    }));
    await expect(buffer.mapAsync(2, 0, 4)).resolves.toBeUndefined();
    const range = buffer.getMappedRange();
    const submissionsBeforeExhaustion = bridge.submissions.length;

    expect(buffer.unmap()).toBeUndefined();
    expect(bridge.submissions).toHaveLength(submissionsBeforeExhaustion);
    expect(buffer.mapState).toBe('unmapped');
    expect(isDetachedArrayBuffer(range)).toBe(true);
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      closeReason: 'counter-exhausted:buffer cleanup generation',
      trackedBufferLifecycleCount: 0,
    });
    binding.revoke();
  });

  test('closes on ambiguous cleanup submission without throwing from void methods', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const unmapWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUBuffer.unmap',
    )?.wireId;
    if (unmapWireId === undefined) throw new Error('missing GPUBuffer.unmap route');
    bridge.setSubmitHook((operationId) => {
      if (operationId === unmapWireId) throw new Error('ambiguous bridge failure');
      return 0;
    });
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      enableStateInspection: true,
    });
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({
      mappedAtCreation: true,
      size: 4,
      usage: 9,
    });
    const range = buffer.getMappedRange();

    expect(buffer.unmap()).toBeUndefined();
    expect(isDetachedArrayBuffer(range)).toBe(true);
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      closeReason: 'buffer-cleanup-bridge-threw',
      trackedBufferLifecycleCount: 0,
    });
    binding.revoke();
  });

  test('fails closed without duplicate detach when the engine returns false or throws', async () => {
    for (const behavior of ['false', 'throw'] as const) {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        { enableStateInspection: true },
      );
      const device = await requestTestLifecycleDevice(binding);
      const buffer = device.createBuffer({
        mappedAtCreation: true,
        size: 8,
        usage: 9,
      });
      const first = buffer.getMappedRange(0, 4);
      const second = buffer.getMappedRange(8, 0);
      bridge.setDetachMappedRangeHook(() => {
        if (behavior === 'throw') throw new Error('engine detach contradiction');
        return false;
      });

      expect(buffer.unmap()).toBeUndefined();
      expect(buffer.mapState).toBe('unmapped');
      expect(inspectBinding(binding).current).toMatchObject({
        active: false,
        closeReason: 'buffer-mapped-range-detach-contradiction',
        trackedBufferLifecycleCount: 0,
      });
      expect(bridge.mappedRangeDetachAttempts).toEqual([first, second]);
      binding.revoke();
      expect(bridge.mappedRangeDetachAttempts).toEqual([first, second]);
    }
  });

  test('drops retained cleanup on loss and keeps later unmap or destroy local-only', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const unmapWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUBuffer.unmap',
    )?.wireId;
    if (unmapWireId === undefined) throw new Error('missing GPUBuffer.unmap route');
    bridge.setSubmitHook((operationId) =>
      operationId === unmapWireId ? 17 : 0);
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      enableStateInspection: true,
    });
    const device = await requestTestLifecycleDevice(binding);
    const retained = device.createBuffer({
      mappedAtCreation: true,
      size: 4,
      usage: 9,
    });
    const active = device.createBuffer({
      mappedAtCreation: true,
      size: 4,
      usage: 9,
    });
    const activeRange = active.getMappedRange();
    const destroyedAfterLoss = device.createBuffer({
      mappedAtCreation: true,
      size: 4,
      usage: 9,
    });
    const destroyedRange = destroyedAfterLoss.getMappedRange();
    expect(retained.unmap()).toBeUndefined();
    expect(inspectBinding(binding).current.trackedBufferLifecycleCount).toBe(3);

    emitDeviceLoss(bridge, '301', '1');
    await expect(device.lost).resolves.toMatchObject({ reason: 'unknown' });
    expect(inspectBinding(binding).current.trackedBufferLifecycleCount).toBe(2);
    expect(active.mapState).toBe('mapped');
    expect(isDetachedArrayBuffer(activeRange)).toBe(false);
    expect(isDetachedArrayBuffer(destroyedRange)).toBe(false);
    expect(bridge.mappedRangeDetachAttempts).toHaveLength(0);

    const submissionsAfterLoss = bridge.submissions.length;
    const cleanupEncodingsAfterLoss =
      bufferLifecycleEncodings(codecs, 'GPUBuffer.unmap').length +
      bufferLifecycleEncodings(codecs, 'GPUBuffer.destroy').length;
    const realmGlobal = globalThis;
    const detachedRegistryKey = Symbol.for('exact.detachedArrayBuffers');
    const previousDetachedRegistry = Object.getOwnPropertyDescriptor(
      realmGlobal,
      detachedRegistryKey,
    );
    const previousWeakSet = Object.getOwnPropertyDescriptor(
      realmGlobal,
      'WeakSet',
    );
    const previousGlobalThis = Object.getOwnPropertyDescriptor(
      realmGlobal,
      'globalThis',
    );
    let detachedRegistryAccessorCalls = 0;
    Object.defineProperty(realmGlobal, detachedRegistryKey, {
      get: () => {
        detachedRegistryAccessorCalls += 1;
        throw new Error('hostile detached registry getter');
      },
      set: () => {
        detachedRegistryAccessorCalls += 1;
        throw new Error('hostile detached registry setter');
      },
      configurable: true,
    });
    try {
      expect(active.unmap()).toBeUndefined();
      expect(detachedRegistryAccessorCalls).toBe(0);
      Reflect.deleteProperty(realmGlobal, detachedRegistryKey);
      Object.defineProperty(realmGlobal, 'WeakSet', {
        value: function HostileWeakSet(): never {
          throw new Error('hostile WeakSet constructor');
        },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(realmGlobal, 'globalThis', {
        get: () => {
          throw new Error('hostile globalThis getter');
        },
        configurable: true,
      });
      let destroyError: unknown;
      try {
        destroyedAfterLoss.destroy();
      } catch (error) {
        destroyError = error;
      } finally {
        if (previousGlobalThis) {
          Object.defineProperty(realmGlobal, 'globalThis', previousGlobalThis);
        } else {
          Reflect.deleteProperty(realmGlobal, 'globalThis');
        }
        if (previousWeakSet) {
          Object.defineProperty(realmGlobal, 'WeakSet', previousWeakSet);
        } else {
          Reflect.deleteProperty(realmGlobal, 'WeakSet');
        }
      }
      expect(destroyError).toBeUndefined();
      expect(retained.destroy()).toBeUndefined();
      expect(bridge.submissions).toHaveLength(submissionsAfterLoss);
      expect(
        bufferLifecycleEncodings(codecs, 'GPUBuffer.unmap').length +
        bufferLifecycleEncodings(codecs, 'GPUBuffer.destroy').length,
      ).toBe(cleanupEncodingsAfterLoss);
      expect(active.mapState).toBe('unmapped');
      expect(destroyedAfterLoss.mapState).toBe('unmapped');
      expect(isDetachedArrayBuffer(activeRange)).toBe(true);
      expect(isDetachedArrayBuffer(destroyedRange)).toBe(true);
      expect(bridge.mappedRangeDetachAttempts).toEqual([
        activeRange,
        destroyedRange,
      ]);
      expect(inspectBinding(binding).current.trackedBufferLifecycleCount).toBe(0);
    } finally {
      if (previousGlobalThis) {
        Object.defineProperty(realmGlobal, 'globalThis', previousGlobalThis);
      } else {
        Reflect.deleteProperty(realmGlobal, 'globalThis');
      }
      if (previousWeakSet) {
        Object.defineProperty(realmGlobal, 'WeakSet', previousWeakSet);
      } else {
        Reflect.deleteProperty(realmGlobal, 'WeakSet');
      }
      if (previousDetachedRegistry) {
        Object.defineProperty(
          realmGlobal,
          detachedRegistryKey,
          previousDetachedRegistry,
        );
      } else {
        Reflect.deleteProperty(realmGlobal, detachedRegistryKey);
      }
    }

    const beforeDestroyedMap = bridge.submissions.length;
    await expect(destroyedAfterLoss.mapAsync(2, 0, 4)).rejects.toMatchObject({
      name: 'OperationError',
    });
    expect(bridge.submissions).toHaveLength(beforeDestroyedMap);
    binding.revoke();
    expect(bridge.mappedRangeDetachAttempts).toEqual([
      activeRange,
      destroyedRange,
    ]);
  });

  test('marks mapped range leases non-transferable for Ibex structuredClone', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({
      mappedAtCreation: true,
      size: 4,
      usage: 9,
    });
    const range = buffer.getMappedRange();
    new Uint8Array(range).set([4, 3, 2, 1]);

    expect(() => ibexStructuredClone(range, { transfer: [range] }))
      .toThrow(expect.objectContaining({ name: 'DataCloneError' }));
    expect(isDetachedArrayBuffer(range)).toBe(false);
    expect(Array.from(new Uint8Array(range))).toEqual([4, 3, 2, 1]);
    buffer.unmap();
    binding.revoke();
  });

  test('does not strongly retain accepted-destroy or rejected-create buffer churn', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs, {
      enableStateInspection: true,
    });
    const device = await requestTestLifecycleDevice(binding);
    for (let index = 0; index < 1_100; index += 1) {
      const buffer = device.createBuffer({ size: 4, usage: 8 });
      buffer.destroy();
    }
    expect(inspectBinding(binding).current.trackedBufferLifecycleCount).toBe(0);

    const createBufferWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUDevice.createBuffer',
    )?.wireId;
    if (createBufferWireId === undefined) {
      throw new Error('missing GPUDevice.createBuffer route');
    }
    bridge.setSubmitHook((operationId) =>
      operationId === createBufferWireId ? 23 : 0);
    for (let index = 0; index < 1_100; index += 1) {
      expect(() => device.createBuffer({
        mappedAtCreation: true,
        size: 0,
        usage: 9,
      })).toThrow('rejected GPUDevice.createBuffer');
    }
    expect(inspectBinding(binding).current.trackedBufferLifecycleCount).toBe(0);
    binding.revoke();
  });

  test('preserves active views across spontaneous loss and detaches them on realm close', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestLifecycleDevice(binding);
    const buffer = device.createBuffer({
      mappedAtCreation: true,
      size: 8,
      usage: 9,
    });
    const range = buffer.getMappedRange();
    emitDeviceLoss(bridge, '301', '1');
    await expect(device.lost).resolves.toMatchObject({ reason: 'unknown' });
    expect(buffer.mapState).toBe('mapped');
    expect(isDetachedArrayBuffer(range)).toBe(false);
    expect(bridge.mappedRangeDetachAttempts).toHaveLength(0);
    binding.revoke();
    expect(isDetachedArrayBuffer(range)).toBe(true);
    expect(bridge.mappedRangeDetachAttempts).toEqual([range]);
  });
});
