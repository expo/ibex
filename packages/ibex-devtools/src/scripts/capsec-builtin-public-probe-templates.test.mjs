import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import {
  authoredNonCapabilityBuiltinProbe,
  authoredNonCapabilityBuiltinOutputInvocation,
  nonCapabilityBuiltinProbeResidualReason,
} from "./capsec-builtin-public-probe-templates.mjs";

const plan = {
  classification: "non-capability",
  actionIds: [],
};
const REVIEWED_MODULE_IMPORTS = [
  ["buffer", "node_buffer", true, "object"],
  ["bun:sqlite", "exact_sqlite", false, "function"],
  ["console", "node_console", true, "object"],
  ["dns", "node_dns", true, "object"],
  ["dns/promises", "node_dns_promises", true, "object"],
  ["exact:clipboard", "exact_clipboard", false, "object"],
  ["exact:http", "exact_http", false, "object"],
  ["exact:sqlite", "exact_sqlite", false, "function"],
  ["module", "node_module", true, "object"],
  ["node:buffer", "node_buffer", true, "object"],
  ["node:console", "node_console", true, "object"],
  ["node:dns", "node_dns", true, "object"],
  ["node:dns/promises", "node_dns_promises", true, "object"],
  ["node:module", "node_module", true, "object"],
  ["node:path", "node_path", true, "object"],
  ["node:path/posix", "path_posix_alias", true, "object"],
  ["node:path/win32", "path_win32_alias", true, "object"],
  ["node:punycode", "node_punycode", true, "object"],
  ["node:querystring", "node_querystring", true, "object"],
  ["node:string_decoder", "node_string_decoder", true, "function"],
  ["node:timers", "node_timers", true, "object"],
  ["node:timers/promises", "node_timers_promises", true, "object"],
  ["node:trace_events", "node_trace_events", true, "object"],
  ["node:v8", "node_v8", true, "object"],
  ["path", "node_path", true, "object"],
  ["path/posix", "path_posix_alias", true, "object"],
  ["path/win32", "path_win32_alias", true, "object"],
  ["punycode", "node_punycode", true, "object"],
  ["querystring", "node_querystring", true, "object"],
  ["string_decoder", "node_string_decoder", true, "function"],
  ["timers", "node_timers", true, "object"],
  ["timers/promises", "node_timers_promises", true, "object"],
  ["trace_events", "node_trace_events", true, "object"],
  ["v8", "node_v8", true, "object"],
];
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const builtinInvocationHarness = new Function(
  "require",
  `return ${fs.readFileSync(
    path.join(
      __dirname,
      "../../../../src/bin/ibex/engine/capsec_public_noncap_builtin_invocation.js",
    ),
    "utf8",
  )};`,
)(createRequire(import.meta.url));

function probeFor({
  constructorInstanceProjection,
  crossSourceExportProjection,
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
            ...(crossSourceExportProjection === undefined
              ? {}
              : { crossSourceExportProjection }),
            ...(constructorInstanceProjection === undefined
              ? {}
              : { constructorInstanceProjection }),
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
  test("keeps cross-source export projections residual even with one source ref", () => {
    const input = {
      sourceKey: "node_dns_promises",
      exportName: "getDefaultResultOrder",
      exportIdioms: ["cross-source-required-member-object-property"],
      moduleSpecifiers: ["dns/promises", "node:dns/promises"],
      valueShape: "data",
    };
    expect(probeFor(input)).not.toBeNull();
    expect(
      probeFor({
        ...input,
        crossSourceExportProjection: {
          carrierSourceKey: "node_dns_promises",
          kind: "immutable-commonjs-member-object",
          providerSourceKey: "node_dns",
        },
      }),
    ).toBeNull();
  });

  test("keeps constructor-instance projections residual even with one source ref", () => {
    const input = {};
    expect(probeFor(input)).not.toBeNull();
    expect(
      probeFor({
        ...input,
        constructorInstanceProjection: {
          constructorExport: "Resolver",
          instancePath: "_handle.cancel",
          kind: "constructor-installed-nested-object",
        },
      }),
    ).toBeNull();
  });

  test("rejects incomplete, bootstrap-owned, and source-shadowed aliases", () => {
    for (const [moduleSpecifier, sourceKey, importReachability] of [
      ["node:path", "node_path", "public"],
      ["internal/fs/utils", "internal_fs_utils", "bootstrap-internal"],
      ["buffer", "node_buffer", "public"],
      ["bun:sqlite", "exact_sqlite", "public"],
      ["stream/consumers", "node_stream_consumers", "bootstrap-internal"],
      [
        "node:stream/consumers",
        "node_stream_consumers",
        "bootstrap-internal",
      ],
    ]) {
      const observedKey = `builtin:${moduleSpecifier}`;
      expect(
        authoredNonCapabilityBuiltinProbe({
          plan,
          scenario: "non-capability",
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
                kind: "builtin",
                name: moduleSpecifier,
                observedKey,
                sourceRefs: [`modules.ts#specifiers:${sourceKey}`],
                metadata: { importReachability, sourceKey },
              },
            ],
          ]),
        }),
      ).toBeNull();
    }
  });

  test("authors fresh-engine zero-decision probes for the exact reviewed aliases", () => {
    expect(REVIEWED_MODULE_IMPORTS).toHaveLength(34);
    for (const [
      moduleSpecifier,
      sourceKey,
      moduleBuiltin,
      expectedRootType,
    ] of REVIEWED_MODULE_IMPORTS) {
      const edgeId = `edge.${moduleSpecifier}`;
      const observedKey = `builtin:${moduleSpecifier}`;
      const probe = authoredNonCapabilityBuiltinProbe({
        plan: { ...plan, edgeIds: [edgeId] },
        scenario: "non-capability",
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
              kind: "builtin",
              name: moduleSpecifier,
              observedKey,
              sourceRefs: [`modules.ts#specifiers:${sourceKey}`],
              metadata: {
                sourceKey,
                bundleExternal: true,
                importReachability: "public",
                moduleBuiltin,
              },
            },
          ],
        ]),
      });
      expect(probe).toMatchObject({
        kind: "public-surface-invocation",
        surfaceObservedKey: observedKey,
        invocation: {
          invocationSchema:
            "ibex/capsec-builtin-module-import-no-effect-invocation/1",
          kind: "builtin-module-import",
          moduleSpecifier,
          arguments: [],
          setup: { kind: "none" },
          completion: {
            kind: "event-loop-quiescence",
            timeoutMilliseconds: 1_000,
          },
          requiredAuthority: [],
          expectedResult: "return",
          expectedTypedDecisionCount: 0,
          expectedTypedStages: [],
          allowedCoverageEdgeIds: [],
          expectedActionIds: [],
          sourceDescriptor: {
            kind: "builtin-module-alias",
            moduleSpecifier,
            sourceKey,
            sourceRef: `modules.ts#specifiers:${sourceKey}`,
            sourceMetadata: {
              sourceKey,
              bundleExternal: true,
              importReachability: "public",
              moduleBuiltin,
            },
            expectedRootType,
            carrierEdgeId: edgeId,
          },
        },
      });
      expect(probe.invocation).not.toHaveProperty("exportName");
    }
  });

  test("rejects near-miss reviewed import carriers and export-call conflation", () => {
    const invoke = ({
      moduleSpecifier = "node:dns",
      sourceKey = "node_dns",
      sourceRef = `modules.ts#specifiers:${sourceKey}`,
      metadata = {
        sourceKey,
        bundleExternal: true,
        importReachability: "public",
        moduleBuiltin: true,
      },
      proofPaths,
    } = {}) => {
      const observedKey = `builtin:${moduleSpecifier}`;
      return authoredNonCapabilityBuiltinProbe({
        plan: { ...plan, edgeIds: ["edge.node-dns"] },
        scenario: "non-capability",
        route: {
          surfaceObservedKeys: [observedKey],
          alternatives: [
            {
              terminalObservedKey: observedKey,
              proofPaths: proofPaths ?? [observedKey],
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
              sourceRefs: [sourceRef],
              metadata,
            },
          ],
        ]),
      });
    };

    expect(
      invoke({
        moduleSpecifier: "node:stream/consumers",
        sourceKey: "node_stream_consumers",
      }),
    ).toBeNull();
    expect(invoke({ sourceKey: "node_dns_promises" })).toBeNull();
    expect(invoke({ sourceRef: "src/builtins/dns.js#exports:getServers" })).toBeNull();
    expect(
      invoke({
        metadata: {
          sourceKey: "node_dns",
          bundleExternal: true,
          importReachability: "public",
          moduleBuiltin: true,
          exportName: "getServers",
        },
      }),
    ).toBeNull();
    expect(
      invoke({
        proofPaths: [
          "builtin:node:dns",
          "builtin:export:node_dns:getServers",
        ],
      }),
    ).toBeNull();
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
        completion: {
          kind: "event-loop-quiescence",
          timeoutMilliseconds: 1_000,
        },
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
        completion: {
          kind: "event-loop-quiescence",
          timeoutMilliseconds: 1_000,
        },
        expectedResult: "normal-return",
      },
    });
  });

  test("constructs zero-effect node:fs values and their pure predicates", () => {
    expect(
      probeFor({
        sourceKey: "node_fs",
        exportName: "_toUnixTimestamp",
        moduleSpecifiers: ["fs", "node:fs"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-fs-pure-v1",
        arguments: [{ kind: "json", value: 1 }],
        setup: { kind: "root-call" },
        bodyEntryProof: { resultType: "number" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_fs",
        exportName: "Stats",
        moduleSpecifiers: ["fs", "node:fs"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-fs-pure-v1",
        arguments: [
          { kind: "json", value: { is_file: true } },
          { kind: "json", value: false },
        ],
        setup: { kind: "construct-target" },
        bodyEntryProof: { resultType: "object" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_fs",
        exportName: "Dirent.isFile",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["fs", "node:fs"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-fs-pure-v1",
        arguments: [],
        setup: {
          kind: "constructed-owner",
          ownerExportName: "Dirent",
          constructorArguments: [
            { kind: "json", value: "entry.txt" },
            { kind: "json", value: 1 },
          ],
        },
        bodyEntryProof: { resultType: "boolean" },
      },
    });
  });

  test("exports expectation-free output invocations from the same authored recipes", () => {
    const invocation = authoredNonCapabilityBuiltinOutputInvocation({
      target: "aarch64-apple-darwin",
      surface: {
        observedKey: "builtin:export:node_path:basename",
        sourceRefs: ["src/builtins/path.js#exports:basename"],
        metadata: {
          sourceKey: "node_path",
          exportName: "basename",
          exportIdioms: ["object-binding", "object-source"],
          importReachability: "public",
          moduleSpecifiers: ["node:path", "path"],
          publicModuleSpecifiers: ["node:path", "path"],
          surfaceType: "export",
          valueShape: "callable",
        },
      },
    });
    expect(invocation).toMatchObject({
      invocationSchema: "ibex/capsec-builtin-call-invocation/1",
      kind: "builtin-export-call",
      moduleSpecifier: "node:path",
      exportName: "basename",
      templateId: "node-path-pure-v1",
      arguments: [{ kind: "json", value: "/ibex/file.txt" }],
      setup: { kind: "root-call" },
      completion: {
        kind: "event-loop-quiescence",
        timeoutMilliseconds: 1_000,
      },
    });
    expect(Object.keys(invocation).sort()).toEqual([
      "arguments",
      "completion",
      "exportName",
      "invocationSchema",
      "kind",
      "moduleSpecifier",
      "setup",
      "sourceDescriptor",
      "sourceDescriptorDigest",
      "templateId",
    ]);
    expect(JSON.stringify(invocation)).not.toContain("expectedResult");
    expect(JSON.stringify(invocation)).not.toContain("bodyEntryProof");

    const returned = builtinInvocationHarness({
      ...invocation,
      captureRawOutput: true,
    });
    expect(returned).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      bodyEntryProof: "normal-return-from-source-call",
      rawOutput: {
        kind: "return",
        rawValueShape: "string",
        value: "file.txt",
        errorCode: null,
      },
    });

    const thrown = builtinInvocationHarness({
      ...invocation,
      arguments: [{ kind: "json", value: {} }],
      captureRawOutput: true,
    });
    expect(thrown).toMatchObject({
      kind: "throw",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "throw",
        rawValueShape: "throw",
        value: null,
        errorCode: "ERR_INVALID_ARG_TYPE",
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

  test("authors non-native zlib setup and keeps native work residual", () => {
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "createGzip",
        moduleSpecifiers: ["node:zlib", "zlib"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-zlib-bounded-v1",
        arguments: [],
        setup: { kind: "root-call" },
        bodyEntryProof: { resultType: "object" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "Gunzip._ensureNativeStream",
        exportIdioms: ["exported-constructor-inherited-prototype"],
        moduleSpecifiers: ["node:zlib", "zlib"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        arguments: [],
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
    for (const exportName of [
      "gzipSync",
      "Gunzip._processChunk",
      "ZstdDecompress._processChunk",
    ]) {
      expect(
        probeFor({
          sourceKey: "node_zlib",
          exportName,
          exportIdioms: exportName.includes(".")
            ? ["exported-constructor-inherited-prototype"]
            : ["object-binding", "object-source"],
          moduleSpecifiers: ["node:zlib", "zlib"],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
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
    for (const exportName of ["pipeline", "Readable.every", "Readable.wrap"]) {
      expect(
        probeFor({
          sourceKey: "node_stream",
          exportName,
          exportIdioms: exportName.includes(".")
            ? ["exported-constructor-prototype"]
            : ["member-assignment"],
          moduleSpecifiers: ["node:stream", "stream"],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
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

  test("authors bounded crypto operations and keeps native crashes residual", () => {
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "Hash.digest",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "exact-crypto-bounded-v1",
        arguments: [{ kind: "json", value: "hex" }],
        setup: {
          kind: "constructed-owner",
          ownerExportName: "Hash",
          constructorArguments: [{ kind: "json", value: "sha256" }],
        },
        bodyEntryProof: { resultType: "string" },
      },
    });
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "Sign.update",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      })?.invocation.setup,
    ).toEqual({
      kind: "constructed-owner",
      ownerExportName: "Sign",
      constructorArguments: [{ kind: "json", value: "sha256" }],
    });
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "DiffieHellmanGroup.getPrime",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      })?.invocation.setup.constructorArguments,
    ).toEqual([{ kind: "json", value: "modp14" }]);
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "privateDecrypt",
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      }),
    ).toBeNull();
    for (const exportName of [
      "generateKeySync",
      "generatePrimeSync",
      "hkdfSync",
      "Hmac.digest",
      "pbkdf2Sync",
      "scryptSync",
    ]) {
      expect(
        probeFor({
          sourceKey: "exact_crypto",
          exportName,
          exportIdioms: exportName.includes(".")
            ? ["exported-constructor-prototype"]
            : ["object-binding", "object-source"],
          moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
    for (const exportName of ["Hash._flush", "Hash.end", "randomUUID"]) {
      expect(
        probeFor({
          sourceKey: "exact_crypto",
          exportName,
          exportIdioms: exportName.includes(".")
            ? ["exported-constructor-prototype"]
            : ["object-binding", "object-source"],
          moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
  });

  test("binds shared Windows crypto probes but leaves native KDFs residual", () => {
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "createHash",
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        target: "x86_64-pc-windows-msvc",
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "exact-crypto-bounded-v1",
      },
    });

    for (const exportName of ["hkdfSync", "pbkdf2Sync", "scryptSync"]) {
      expect(
        probeFor({
          sourceKey: "exact_crypto",
          exportName,
          moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
          target: "x86_64-pc-windows-msvc",
          valueShape: "callable",
        }),
      ).toBeNull();
    }
  });

  test("does not schedule Brotli calls without the Windows native codec", () => {
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "BrotliCompress._processChunk",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:zlib", "zlib"],
        target: "x86_64-pc-windows-msvc",
        valueShape: "callable",
      }),
    ).toBeNull();
  });

  test("authors pure IP, module, clock, URL, and version helpers", () => {
    expect(
      probeFor({
        sourceKey: "node_net",
        exportName: "BlockList.addRange",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["net", "node:net"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-net-bounded-v1",
        setup: {
          kind: "constructed-owner",
          ownerExportName: "BlockList",
          constructorArguments: [],
        },
        bodyEntryProof: { resultType: "undefined" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_net",
        exportName: "Server.close",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["net", "node:net"],
        valueShape: "callable",
      }),
    ).toBeNull();
    for (const [sourceKey, exportName, moduleSpecifiers, templateId] of [
      ["node_module", "isBuiltin", ["module", "node:module"], "node-module-pure-v1"],
      ["node_url", "canParse", ["node:url", "url"], "node-url-pure-v1"],
      ["node_v8", "cachedDataVersionTag", ["node:v8", "v8"], "node-v8-pure-v1"],
    ]) {
      expect(
        probeFor({
          sourceKey,
          exportName,
          moduleSpecifiers,
          valueShape: "callable",
        })?.invocation.templateId,
      ).toBe(templateId);
    }
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
    for (const sourceKey of ["node_cluster", "node_http"]) {
      expect(
        probeFor({
          sourceKey,
          exportName: "scalar",
          moduleSpecifiers: [`node:${sourceKey.slice(5)}`],
          valueShape: "data",
        }),
      ).toBeNull();
    }
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

  test("proves source-bound target-absent constants through the public module", () => {
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
    ).toMatchObject({
      surfaceObservedKey,
      invocation: {
        invocationSchema: "ibex/capsec-builtin-export-invocation/1",
        kind: "builtin-export-read",
        expectedResult: "absent",
        expectedTypedDecisionCount: 0,
        sourceDescriptor: {
          exportName: "EDQUOT",
          platformAvailability: ["android", "linux"],
        },
      },
    });
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
