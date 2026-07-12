import { describe, expect, test } from "bun:test";
import {
  authoredNonCapabilityBuiltinProbe,
  nonCapabilityBuiltinProbeResidualReason,
} from "./capsec-builtin-public-probe-templates.mjs";

const plan = {
  classification: "non-capability",
  actionIds: [],
};

function probeFor({
  sourceKey = "node_constants",
  exportName = "ENOENT",
  exportIdioms = ["object-binding", "object-source"],
  importReachability = "public",
  moduleSpecifiers = ["constants", "node:constants"],
  publicModuleSpecifiers = moduleSpecifiers,
  platformAvailability,
  target = "aarch64-apple-darwin",
  valueShape = "data",
} = {}) {
  const observedKey = `builtin:export:${sourceKey}:${exportName}`;
  return authoredNonCapabilityBuiltinProbe({
    plan,
    scenario: "non-capability",
    target,
    route: {
      surfaceObservedKeys: [observedKey],
      alternatives: [
        { terminalObservedKey: observedKey, proofPaths: [observedKey] },
      ],
      ambiguousCallees: [],
    },
    liveByObservedKey: new Map([
      [
        observedKey,
        {
          observedKey,
          sourceRefs: [`src/builtins/${sourceKey}.js#exports:${exportName}`],
          metadata: {
            sourceKey,
            exportName,
            exportIdioms,
            importReachability,
            moduleSpecifiers,
            publicModuleSpecifiers,
            platformAvailability,
            surfaceType: "export",
            valueShape,
          },
        },
      ],
    ]),
  });
}

describe("source-bound builtin public probes", () => {
  test("imports exact manifest and bootstrap module aliases", () => {
    for (const [moduleSpecifier, importReachability, resolutionKind] of [
      ["node:path", "public", "manifest"],
      ["internal/fs/utils", "bootstrap-internal", "bootstrap-internal"],
    ]) {
      const observedKey = `builtin:${moduleSpecifier}`;
      expect(
        authoredNonCapabilityBuiltinProbe({
          plan,
          scenario: "non-capability",
          route: {
            surfaceObservedKeys: [observedKey],
            alternatives: [
              {
                terminalObservedKey: observedKey,
                proofPaths: [observedKey],
              },
            ],
            ambiguousCallees: [],
          },
          liveByObservedKey: new Map([
            [
              observedKey,
              {
                kind: "builtin",
                name: moduleSpecifier,
                observedKey,
                sourceRefs: ["modules.ts#specifiers:synthetic"],
                metadata: {
                  importReachability,
                  sourceKey: "synthetic",
                },
              },
            ],
          ]),
        }),
      ).toMatchObject({
        surfaceObservedKey: observedKey,
        invocation: {
          invocationSchema:
            "ibex/capsec-builtin-module-import-invocation/1",
          kind: "builtin-module-import",
          moduleSpecifier,
          sourceDescriptor: {
            kind: "builtin-module-alias",
            moduleSpecifier,
            resolutionKind,
            sourceKey: "synthetic",
          },
          expectedTypedDecisionCount: 0,
        },
      });
    }
  });

  test("reads an own export through the canonical public alias", () => {
    const probe = probeFor();
    expect(probe).toMatchObject({
      kind: "public-surface-invocation",
      surfaceObservedKey: "builtin:export:node_constants:ENOENT",
      invocation: {
        kind: "builtin-export-read",
        moduleSpecifier: "node:constants",
        exportName: "ENOENT",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
        sourceDescriptor: {
          access: { kind: "export-property", path: ["ENOENT"] },
          valueShape: "data",
        },
      },
    });
  });

  test("triggers source-proven root accessors", () => {
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "Z_OK",
        exportIdioms: ["define-property"],
        moduleSpecifiers: ["node:zlib", "zlib"],
        valueShape: "accessor",
      }).invocation.sourceDescriptor,
    ).toEqual({
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "Z_OK",
      exportIdioms: ["define-property"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/node_zlib.js#exports:Z_OK",
      valueShape: "accessor",
      access: { kind: "export-property", path: ["Z_OK"] },
    });
  });

  test("calls only source-authored root functions with bounded arguments", () => {
    expect(
      probeFor({
        sourceKey: "node_path",
        exportName: "basename",
        moduleSpecifiers: ["node:path", "path"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        invocationSchema: "ibex/capsec-builtin-call-invocation/1",
        kind: "builtin-export-call",
        templateId: "node-path-pure-v1",
        arguments: [{ kind: "json", value: "/ibex/file.txt" }],
        setup: { kind: "root-call" },
        bodyEntryProof: {
          kind: "normal-return-from-source-call",
          resultType: "string",
        },
        expectedResult: "normal-return",
      },
    });
  });

  test("constructs explicit receivers for authored prototype methods", () => {
    expect(
      probeFor({
        sourceKey: "node_buffer",
        exportName: "Buffer.readUInt32LE",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["buffer", "node:buffer"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-buffer-bounded-v1",
        arguments: [{ kind: "json", value: 0 }],
        setup: {
          kind: "buffer-owner",
          ownerExportName: "Buffer",
          bytes: [0, 1, 2, 3, 4, 5, 6, 7],
        },
        sourceDescriptor: {
          access: {
            kind: "prototype-property",
            path: ["Buffer", "prototype", "readUInt32LE"],
          },
        },
        bodyEntryProof: { resultType: "number" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_buffer",
        exportName: "SlowBuffer.writeBigUint64BE",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["buffer", "node:buffer"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        arguments: [
          { kind: "bigint", value: "1" },
          { kind: "json", value: 0 },
        ],
        setup: {
          kind: "buffer-owner",
          ownerExportName: "SlowBuffer",
        },
        bodyEntryProof: { resultType: "number" },
      },
    });
  });

  test("authors format-correct zlib roots and inherited transform receivers", () => {
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "gzipSync",
        moduleSpecifiers: ["node:zlib", "zlib"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-zlib-bounded-v1",
        arguments: [
          { kind: "zlib-input", ownerExportName: "Gzip" },
        ],
        setup: { kind: "root-call" },
        bodyEntryProof: { resultType: "object" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "Gunzip._processChunk",
        exportIdioms: ["exported-constructor-inherited-prototype"],
        moduleSpecifiers: ["node:zlib", "zlib"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        arguments: [
          { kind: "zlib-input", ownerExportName: "Gunzip" },
          { kind: "json", value: 4 },
        ],
        setup: {
          kind: "zlib-owner",
          ownerExportName: "Gunzip",
          ensureNativeStream: false,
        },
        sourceDescriptor: {
          access: { kind: "inherited-prototype-property" },
        },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "ZstdDecompress._processChunk",
        exportIdioms: ["exported-constructor-inherited-prototype"],
        moduleSpecifiers: ["node:zlib", "zlib"],
        valueShape: "callable",
      }),
    ).toBeNull();
  });

  test("authors configured stream receivers but leaves throwing base methods residual", () => {
    expect(
      probeFor({
        sourceKey: "node_stream",
        exportName: "Readable.read",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:stream", "stream"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-stream-bounded-v1",
        arguments: [{ kind: "json", value: 0 }],
        setup: {
          kind: "stream-owner",
          ownerExportName: "Readable",
          endedInput: false,
        },
        bodyEntryProof: { resultType: "null" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_stream",
        exportName: "compose",
        exportIdioms: ["member-assignment"],
        moduleSpecifiers: ["node:stream", "stream"],
        valueShape: "callable",
      }),
    ).toBeNull();
    expect(
      probeFor({
        sourceKey: "node_stream",
        exportName: "destroy",
        exportIdioms: ["member-assignment"],
        moduleSpecifiers: ["node:stream", "stream"],
        valueShape: "callable",
      })?.invocation.arguments,
    ).toEqual([
      {
        kind: "stream-instance",
        ownerExportName: "Readable",
        ended: false,
      },
      { kind: "json", value: null },
    ]);
    expect(
      probeFor({
        sourceKey: "node_stream",
        exportName: "default.destroy",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:stream", "stream"],
        valueShape: "callable",
      }),
    ).toBeNull();
    expect(
      probeFor({
        sourceKey: "node_stream",
        exportName: "Writable._write",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:stream", "stream"],
        valueShape: "callable",
      }),
    ).toBeNull();
  });

  test("authors bounded string decoder, URL, and util calls", () => {
    expect(
      probeFor({
        sourceKey: "node_string_decoder",
        exportName: "StringDecoder.write",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:string_decoder", "string_decoder"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-string-decoder-bounded-v1",
        arguments: [{ kind: "buffer", bytes: [0x69, 0x62, 0x65, 0x78] }],
        setup: {
          kind: "constructed-owner",
          ownerExportName: "StringDecoder",
          constructorArguments: [{ kind: "json", value: "utf8" }],
        },
        bodyEntryProof: { resultType: "string" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_url",
        exportName: "resolve",
        exportIdioms: ["module-exports-object"],
        moduleSpecifiers: ["node:url", "url"],
        valueShape: "callable",
      })?.invocation.bodyEntryProof.resultType,
    ).toBe("string");
    expect(
      probeFor({
        sourceKey: "node_util",
        exportName: "parseArgs",
        exportIdioms: ["member-assignment"],
        moduleSpecifiers: ["node:util", "util"],
        valueShape: "callable",
      })?.invocation.arguments,
    ).toEqual([
      {
        kind: "json",
        value: {
          args: ["--probe", "ibex"],
          options: { probe: { type: "string" } },
        },
      },
    ]);
    expect(
      probeFor({
        sourceKey: "node_string_decoder",
        exportName: "default.write",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:string_decoder", "string_decoder"],
        valueShape: "callable",
      }),
    ).toBeNull();
  });

  test("authors bounded performance receivers without retaining observers", () => {
    expect(
      probeFor({
        sourceKey: "node_perf_hooks",
        exportName: "Performance.measure",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:perf_hooks", "perf_hooks"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-perf-hooks-bounded-v1",
        arguments: [
          { kind: "json", value: "ibex-measure" },
          { kind: "json", value: { start: 0, duration: 1 } },
        ],
        setup: {
          kind: "constructed-owner",
          ownerExportName: "Performance",
          constructorArguments: [],
        },
        bodyEntryProof: { resultType: "object" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_perf_hooks",
        exportName: "PerformanceObserver.takeRecords",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:perf_hooks", "perf_hooks"],
        valueShape: "callable",
      })?.invocation.setup.constructorArguments,
    ).toEqual([{ kind: "noop-function" }]);
    expect(
      probeFor({
        sourceKey: "node_perf_hooks",
        exportName: "PerformanceObserver.observe",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:perf_hooks", "perf_hooks"],
        valueShape: "callable",
      }),
    ).toBeNull();
    expect(
      probeFor({
        sourceKey: "node_perf_hooks",
        exportName: "PerformanceMeasure",
        exportIdioms: ["module-exports-object"],
        moduleSpecifiers: ["node:perf_hooks", "perf_hooks"],
        valueShape: "callable",
      }),
    ).toBeNull();
  });

  test("leaves un-authored callable families and throwing-only calls residual", () => {
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "Hash.update",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "data",
      }),
    ).toBeNull();
    expect(
      probeFor({
        sourceKey: "node_assert",
        exportName: "fail",
        exportIdioms: ["member-assignment"],
        moduleSpecifiers: ["assert", "node:assert"],
        valueShape: "callable",
      }),
    ).toBeNull();
    expect(
      probeFor({
        sourceKey: "node_path",
        exportName: "__proto__",
        moduleSpecifiers: ["node:path", "path"],
        valueShape: "callable",
      }),
    ).toBeNull();
  });

  test("leaves dynamic tables and non-self routes residual", () => {
    expect(
      probeFor({
        sourceKey: "node_constants",
        exportName: "[[dynamic-table:signal-number-overlay]]",
        exportIdioms: [
          "closed-dynamic-table:signal-number-overlay",
          "table-copy",
        ],
        moduleSpecifiers: ["node:constants"],
      }),
    ).toBeNull();

    const observedKey = "builtin:export:node_path:basename";
    expect(
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario: "non-capability",
        route: {
          surfaceObservedKeys: [observedKey],
          alternatives: [
            {
              terminalObservedKey: "native-op:__unexpected",
              proofPaths: ["basename -> __unexpected"],
            },
          ],
          ambiguousCallees: [],
        },
        liveByObservedKey: new Map(),
      }),
    ).toBeNull();
  });

  test("keeps non-public manifest sources as explicit residuals", () => {
    const surfaceObservedKey =
      "builtin:export:internal_fs_utils:toPathIfFileURL";
    const route = {
      surfaceObservedKeys: [surfaceObservedKey],
      alternatives: [
        {
          terminalObservedKey: surfaceObservedKey,
          proofPaths: [surfaceObservedKey],
        },
      ],
      ambiguousCallees: [],
    };
    const liveByObservedKey = new Map([
      [
        surfaceObservedKey,
        {
          observedKey: surfaceObservedKey,
          sourceRefs: [
            "modules.ts#sources:internal_fs_utils:exports:toPathIfFileURL",
          ],
          metadata: {
            bootstrapInternalModuleSpecifiers: ["internal/fs/utils"],
            exportName: "toPathIfFileURL",
            exportIdioms: ["module-exports-object"],
            importReachability: "bootstrap-internal",
            moduleSpecifiers: ["internal/fs/utils"],
            publicModuleSpecifiers: [],
            sourceKey: "internal_fs_utils",
            surfaceType: "export",
            valueShape: "callable",
          },
        },
      ],
    ]);

    expect(
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario: "non-capability",
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toBeNull();
    expect(
      nonCapabilityBuiltinProbeResidualReason({
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toBe("builtin-export-resolves-to-bootstrap-internal");

    const metadata = liveByObservedKey.get(surfaceObservedKey).metadata;
    metadata.bootstrapInternalModuleSpecifiers = [];
    metadata.importReachability = "private-manifest";
    metadata.moduleSpecifiers = [];
    expect(
      nonCapabilityBuiltinProbeResidualReason({
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toBe("builtin-export-not-publicly-importable");
  });

  test("keeps source-proven target-absent constants explicitly residual", () => {
    const surfaceObservedKey = "builtin:export:node_constants:EDQUOT";
    const liveByObservedKey = new Map([
      [
        surfaceObservedKey,
        {
          observedKey: surfaceObservedKey,
          sourceRefs: ["src/builtins/constants.js#exports:EDQUOT"],
          metadata: {
            sourceKey: "node_constants",
            exportName: "EDQUOT",
            exportIdioms: ["object-binding", "object-source", "table-copy"],
            importReachability: "public",
            moduleSpecifiers: ["constants", "node:constants"],
            publicModuleSpecifiers: ["constants", "node:constants"],
            platformAvailability: ["android", "linux"],
            surfaceType: "export",
            valueShape: "data",
          },
        },
      ],
    ]);
    const route = {
      surfaceObservedKeys: [surfaceObservedKey],
      alternatives: [
        {
          terminalObservedKey: surfaceObservedKey,
          proofPaths: [surfaceObservedKey],
        },
      ],
      ambiguousCallees: [],
    };
    expect(
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario: "non-capability",
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toBeNull();
    expect(
      nonCapabilityBuiltinProbeResidualReason({
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toBe("builtin-export-not-available-on-target");
    expect(
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario: "non-capability",
        route,
        liveByObservedKey,
        target: "aarch64-linux-android",
      })?.invocation.sourceDescriptor.platformAvailability,
    ).toEqual(["android", "linux"]);
  });
});
