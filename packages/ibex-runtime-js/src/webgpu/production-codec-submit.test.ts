import { describe, expect, test } from 'bun:test';

import corpus from '../../../../tests/fixtures/webgpu-production-codec-corpus-v1.generated.json';

import {
  WEBGPU_EXECUTABLE_CODEC_MANIFEST,
  WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT,
} from './production-codecs.generated';
import type { ProductionGpuServiceEncodingInput } from './production-codecs';

function bytesFromHex(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(value)) {
    throw new TypeError('Corpus bytes must be lowercase even-length hex');
  }
  return Uint8Array.from(
    { length: value.length / 2 },
    (_, index) => Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}

interface SubmitCorpusVector {
  readonly id: string;
  readonly operationId: string;
  readonly kind: string;
  readonly bytesHex: string;
  readonly mutation?: string;
}

interface InspectedSubmitRecord {
  readonly operationName: string;
  readonly argumentBody: unknown;
  readonly logicalError: Readonly<{ name: string }> | null;
}

interface InspectedSubmitProgram {
  readonly commandBuffer: unknown;
  readonly invalid: boolean;
  readonly records: readonly InspectedSubmitRecord[];
  readonly commandProgramDigest: string;
}

interface InspectedSubmitRequest {
  readonly recordTable: readonly InspectedSubmitRecord[];
  readonly sealedLocalTimeline: readonly InspectedSubmitRecord[];
  readonly convertedArguments: Readonly<{
    commandBuffers: readonly InspectedSubmitProgram[];
    wrapperValidationError?: Readonly<{ name: string }>;
  }>;
}

describe('GPUQueue.submit construction-private codec corpus', () => {
  const submitVectors = corpus.vectors.filter(
    (vector) => vector.operationId === 'GPUQueue.submit',
  ) as readonly SubmitCorpusVector[];
  const requests = submitVectors.filter((vector) => vector.kind === 'request');
  const binaryRejections = submitVectors.filter(
    (vector) => vector.kind === 'binary-rejection',
  );

  test('pins tag 11, the private native route, and no support publication', () => {
    const serviceCodec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (codec) =>
        codec.tag === 'gpu-sealed-command-program-sequence-service-request-v1',
    );
    const nativeRoute = WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes
      .find((route) => route.operationId === 'GPUQueue.submit');

    expect(serviceCodec).toMatchObject({
      wireTag: 11,
      nativeProgramPrerequisitesRepresented: true,
      executableFromCurrentAuthenticatedInputs: true,
      unavailableSemanticFields: [],
    });
    expect(nativeRoute).toMatchObject({
      operationId: 'GPUQueue.submit',
      wireId: 308839175,
      request: {
        catalog: { wireTag: 11 },
        noTrailingBytes: true,
      },
      completion: { catalog: { wireTag: 2 }, noTrailingBytes: true },
    });
    expect(corpus.supportClaim).toBe('none');
  });

  test('round-trips every sealed command kind, timeline-only state, and errors', () => {
    expect(requests).toHaveLength(5);
    const inspected = new Map(requests.map((vector) => [
      vector.id,
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        bytesFromHex(vector.bytesHex),
      ) as InspectedSubmitRequest,
    ]));
    const complete = inspected.get('queue-submit-all-record-kinds-request')!;
    expect(complete.recordTable).toHaveLength(16);
    expect(complete.convertedArguments.commandBuffers).toHaveLength(1);
    expect(complete.convertedArguments.commandBuffers[0].records).toHaveLength(15);
    expect(complete.convertedArguments.commandBuffers[0].commandProgramDigest)
      .toMatch(/^[0-9a-f]{64}$/);
    expect(new Set(
      complete.convertedArguments.commandBuffers[0].records.map(
        (record) => record.operationName,
      ),
    ).size).toBe(15);
    const beginRender = complete.recordTable.find(
      (record) => record.operationName === 'GPUCommandEncoder.beginRenderPass',
    )!;
    const beginRenderBody = beginRender.argumentBody as Readonly<{
      colorAttachments: readonly (Readonly<{ depthSlice?: number }> | null)[];
    }>;
    expect(beginRenderBody.colorAttachments[0]).toBeNull();
    expect(beginRenderBody.colorAttachments[1]?.depthSlice).toBe(2);

    const absent = inspected.get(
      'queue-submit-null-slot-depth-slice-absent-request',
    )!;
    const absentBeginRender = absent.recordTable.find(
      (record) => record.operationName === 'GPUCommandEncoder.beginRenderPass',
    )!;
    const absentBeginRenderBody = absentBeginRender.argumentBody as Readonly<{
      colorAttachments: readonly (Readonly<Record<string, unknown>> | null)[];
    }>;
    expect(absentBeginRenderBody.colorAttachments[0]).toBeNull();
    expect(Object.hasOwn(
      absentBeginRenderBody.colorAttachments[1]!,
      'depthSlice',
    )).toBe(false);

    const empty = inspected.get('queue-submit-empty-program-timeline-only-request')!;
    expect(empty.recordTable).toHaveLength(1);
    expect(empty.sealedLocalTimeline[0].operationName).toBe(
      'GPUCanvasContext.getCurrentTexture',
    );
    expect(empty.convertedArguments.commandBuffers).toEqual([]);

    const trulyEmpty = inspected.get('queue-submit-empty-request')!;
    expect(trulyEmpty.recordTable).toEqual([]);
    expect(trulyEmpty.sealedLocalTimeline).toEqual([]);
    expect(trulyEmpty.convertedArguments.commandBuffers).toEqual([]);

    const invalid = inspected.get('queue-submit-logical-error-program-request')!;
    expect(invalid.convertedArguments.commandBuffers[0].invalid).toBe(true);
    expect(invalid.convertedArguments.wrapperValidationError).toMatchObject({
      name: 'GPUValidationError',
    });
    expect(invalid.recordTable.some(
      (record) =>
        record.logicalError?.name === 'GPUValidationError',
    )).toBe(true);
    const invalidComputePipeline = invalid.recordTable.find(
      (record) => record.operationName === 'GPUComputePassEncoder.setPipeline',
    )!;
    expect(invalidComputePipeline.argumentBody).toMatchObject({
      pipeline: {
        kind: 'GPUAdapter',
        logicalDeviceId: '0',
        logicalDeviceGeneration: '0',
      },
    });

    const completeInput = complete as unknown as ProductionGpuServiceEncodingInput;
    const sourceProgram = complete.convertedArguments.commandBuffers[0];
    const aggregatePrograms = Object.freeze(Array.from({ length: 69 }, () =>
      Object.freeze({
        commandBuffer: sourceProgram.commandBuffer,
        invalid: sourceProgram.invalid,
        records: sourceProgram.records,
      })));
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest({
      ...completeInput,
      wireId: 308839175,
      target: undefined,
      convertedArguments: Object.freeze({ commandBuffers: aggregatePrograms }),
    })).toThrow('aggregate command records exceed their bound');
  });

  test('rejects every authenticated mutation vector before exposure', () => {
    expect(binaryRejections.length).toBeGreaterThanOrEqual(31);
    for (const vector of binaryRejections) {
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        bytesFromHex(vector.bytesHex),
      )).toThrow();
    }
    const kindMutations = binaryRejections.filter((vector) =>
      vector.mutation?.startsWith('unknown-record-kind-'));
    expect(kindMutations).toHaveLength(16);
    expect(binaryRejections.some((vector) =>
      vector.mutation === 'depthSlice-two-to-three-without-digest-rewrite'))
      .toBe(true);
    expect(binaryRejections.some((vector) =>
      vector.mutation === 'record-table-row-removed-from-exact-index-union'))
      .toBe(true);
    expect(binaryRejections.some((vector) =>
      vector.mutation ===
        'sixty-nine-fifteen-record-programs-exceed-aggregate-bound'))
      .toBe(true);
    expect(binaryRejections.filter((vector) =>
      vector.mutation?.startsWith('zero-receiver-'))).toHaveLength(5);
  });
});
