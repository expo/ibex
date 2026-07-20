import { beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  discoverRepositorySurfaces,
  HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
} from "./capsec-surface-inventory.mjs";
import {
  authoredHostAbiOutputProbe,
  buildHostAbiOutputProbePartition,
  HOST_ABI_OUTPUT_INVOCATION_SCHEMA,
  HOST_ABI_OUTPUT_PARTITION_SCHEMA,
  HOST_ABI_OUTPUT_SOURCE_DESCRIPTOR_KIND,
} from "./capsec-host-abi-output-templates.mjs";
import { canonicalOutputDispositionKey } from "./capsec-output-dispositions.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const read = (relative) =>
  JSON.parse(fs.readFileSync(path.join(repoRoot, relative), "utf8"));

let catalog;
let coverage;
let surfaces;
let authored;
let pathOutputCases;
let legacyOutputCases;

beforeAll(async () => {
  catalog = read("capsec/generated/output-shape-catalog.json");
  coverage = read("capsec/registry/coverage-edges.json");
  surfaces = (await discoverRepositorySurfaces(repoRoot)).surfaces;
  const byEdge = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  const byObserved = new Map(surfaces.map((surface) => [surface.observedKey, surface]));
  authored = catalog.rows.flatMap((catalogRow) => {
    if (catalogRow.key.sourceKind !== "host-abi") return [];
    const edge = byEdge.get(catalogRow.key.surfaceId);
    const surface = byObserved.get(`host-abi:${edge.surface.name}`);
    const probe = authoredHostAbiOutputProbe({ catalogRow, surface, coverageEdge: edge });
    return probe ? [{ catalogRow, edge, surface, probe }] : [];
  });
  pathOutputCases = [
    ["ex_hermes_engine_binary_path", "out:out"],
    ["ex_host_vfs_chdir", "out:virtual"],
    ["ex_host_vfs_get_cwd", "out:virtual"],
    ["ex_host_vfs_resolve_path", "out:virtual"],
    ["ex_host_vfs_resolve_path", "out:backing"],
  ].map(([functionName, output]) => {
    const edge = [...byEdge.values()].find(
      (candidate) => candidate.surface.name === functionName,
    );
    const surface = byObserved.get(`host-abi:${functionName}`);
    const catalogRow = {
      key: {
        surfaceId: edge.id,
        output,
        alias: functionName,
        mode: "all",
        sourceKind: "host-abi",
        returnVariant: "default",
        contextId: "host.private-native-call-initialized",
      },
      discovery: {
        kind: "source-inventory-surface",
        observedKeys: [surface.observedKey],
        sourceRefs: [...surface.sourceRefs],
      },
    };
    return {
      catalogRow,
      edge,
      surface,
      probe: authoredHostAbiOutputProbe({
        catalogRow,
        surface,
        coverageEdge: edge,
      }),
    };
  });
  legacyOutputCases = [
    ...[
      "ex_host_fs_mkdir_recursive_result",
      "ex_host_fs_mkdtemp",
      "ex_host_fs_realpath",
    ].flatMap((functionName) => [
      [functionName, "[[return]]", functionName, "unarmed", "success"],
      [functionName, "[[return]]", functionName, "unarmed", "error"],
      [functionName, "[[return]]", functionName, "armed", "refused"],
    ]),
    [
      "ex_host_fs_readdir",
      "array-items",
      "ex_host_fs_readdir[]",
      "all",
      "success",
    ],
  ].map(([functionName, output, alias, mode, returnVariant]) => {
    const edge = [...byEdge.values()].find(
      (candidate) => candidate.surface.name === functionName,
    );
    const surface = byObserved.get(`host-abi:${functionName}`);
    const catalogRow = {
      key: {
        surfaceId: edge.id,
        output,
        alias,
        mode,
        sourceKind: "host-abi",
        returnVariant,
        contextId: "host.private-native-call-initialized",
      },
      discovery: {
        kind: "source-inventory-surface",
        observedKeys: [surface.observedKey],
        sourceRefs: [...surface.sourceRefs],
      },
    };
    return {
      catalogRow,
      edge,
      surface,
      probe: authoredHostAbiOutputProbe({
        catalogRow,
        surface,
        coverageEdge: edge,
      }),
    };
  });
}, 60_000);

describe("source-bound Host ABI output templates", () => {
  test("authors exact bounded native tranches without promoting platform or registrar presence", () => {
    const scalarAuthored = authored.filter(
      ({ catalogRow }) => catalogRow.key.output === "[[return]]",
    );
    const legacyNames = new Set([
      "ex_host_fs_mkdir_recursive_result",
      "ex_host_fs_mkdtemp",
      "ex_host_fs_realpath",
    ]);
    const ordinaryScalarAuthored = scalarAuthored.filter(
      ({ edge }) => !legacyNames.has(edge.surface.name),
    );
    const legacyScalarAuthored = scalarAuthored.filter(({ edge }) =>
      legacyNames.has(edge.surface.name),
    );
    expect(ordinaryScalarAuthored).toHaveLength(227);
    expect(
      new Set(ordinaryScalarAuthored.map(({ edge }) => edge.surface.name)).size,
    ).toBe(222);
    expect(legacyScalarAuthored.length).toBe(
      catalog.rows.filter(
        (row) =>
          row.key.sourceKind === "host-abi" &&
          legacyNames.has(row.key.alias) &&
          new Set(["success", "error", "refused"]).has(
            row.key.returnVariant,
          ),
      ).length,
    );
    expect(
      Object.fromEntries(
        [
          ...Map.groupBy(
            ordinaryScalarAuthored,
            ({ probe }) => probe.sourceDescriptor.operation.kind,
          ),
        ]
          .map(([kind, rows]) => [kind, rows.length])
          .sort(),
      ),
    ).toEqual({
      "native-hermes-authenticated-armed-create": 1,
      "native-hermes-authenticated-session-runtime": 10,
      "rust-host-bounded-basic": 26,
      "rust-host-authenticated-typed-authority": 17,
      "rust-host-authenticated-stateful-output": 13,
      "rust-host-fs-sandbox": 25,
      "rust-host-authenticated-vfs-output": 5,
      "rust-host-authenticated-javascript-absence": 5,
      "rust-host-http-live-server": 24,
      "rust-host-sqlite-memory": 13,
      "rust-host-terminal-inert": 8,
      "native-hermes-diagnostic-runtime": 24,
      "native-hermes-bounded-dispatch-runtime": 3,
      "native-hermes-module-runner-runtime": 27,
      "native-hermes-owned-runtime-teardown": 1,
      "native-hermes-owned-value-runtime": 5,
      "native-hermes-stateless-current-target": 8,
      "native-hermes-worklet-runtime": 12,
    });
    if (legacyScalarAuthored.length > 0) {
      expect(legacyScalarAuthored).toHaveLength(9);
      expect(
        legacyScalarAuthored.every(
          ({ probe }) =>
            probe.sourceDescriptor.operation.kind ===
            "rust-host-legacy-path-output",
        ),
      ).toBe(true);
    }
    expect(
      scalarAuthored.every(({ probe }) =>
        probe.sourceDescriptor.selectedDefinitions.every(
          (definition) => definition.targetVariant === "default",
        ),
      ),
    ).toBe(true);
  });

  test("authors the exact merged module, compiled-environment, and sealing routes", () => {
    const names = new Set([
      "ex_hermes_commonjs_record_link_computed_dynamic_import",
      "ex_hermes_module_preflight_bytecode",
      "ex_hermes_module_record_link_computed_dynamic_import",
      "ex_host_env_compiled_key_at",
      "ex_host_env_compiled_key_count",
      "ex_host_seal_bootstrap_phase",
    ]);
    expect(
      authored
        .filter(({ edge }) => names.has(edge.surface.name))
        .map(({ catalogRow, edge, probe }) => [
          edge.surface.name,
          catalogRow.key.output,
          probe.sourceDescriptor.operation.kind,
        ])
        .sort(([leftName, leftOutput], [rightName, rightOutput]) =>
          `${leftName}\0${leftOutput}`.localeCompare(
            `${rightName}\0${rightOutput}`,
          ),
        ),
    ).toEqual([
      [
        "ex_hermes_commonjs_record_link_computed_dynamic_import",
        "[[return]]",
        "native-hermes-module-runner-runtime",
      ],
      [
        "ex_hermes_module_preflight_bytecode",
        "[[return]]",
        "native-hermes-stateless-current-target",
      ],
      [
        "ex_hermes_module_preflight_bytecode",
        "out:error",
        "native-hermes-stateless-current-target",
      ],
      [
        "ex_hermes_module_record_link_computed_dynamic_import",
        "[[return]]",
        "native-hermes-module-runner-runtime",
      ],
      [
        "ex_host_env_compiled_key_at",
        "[[return]]",
        "rust-host-authenticated-stateful-output",
      ],
      [
        "ex_host_env_compiled_key_at",
        "out:buf",
        "rust-host-authenticated-stateful-output",
      ],
      [
        "ex_host_env_compiled_key_count",
        "[[return]]",
        "rust-host-authenticated-stateful-output",
      ],
      [
        "ex_host_seal_bootstrap_phase",
        "[[return]]",
        "rust-host-authenticated-stateful-output",
      ],
    ]);
  });

  test("authors only the five exact source-bound path buffer selectors", () => {
    expect(pathOutputCases.map(({ probe }) => probe).every(Boolean)).toBe(true);
    expect(
      pathOutputCases.map(({ catalogRow, probe }) => ({
        functionName: probe.sourceDescriptor.functionName,
        operation: probe.sourceDescriptor.operation.kind,
        output: catalogRow.key.output,
        recordPath: probe.recordPath,
        selectedOutput: probe.sourceDescriptor.selectedOutput,
      })),
    ).toEqual([
      {
        functionName: "ex_hermes_engine_binary_path",
        operation: "native-hermes-stateless-path-output",
        output: "out:out",
        recordPath: ["out:out"],
        selectedOutput: {
          kind: "buffer",
          lengthParameter: "out_len",
          ownership: { kind: "caller-storage" },
          parameter: "out",
          role: "output",
          selector: "out:out",
        },
      },
      ...[
        ["ex_host_vfs_chdir", "out:virtual", "out_virtual", "out_virtual_len"],
        ["ex_host_vfs_get_cwd", "out:virtual", "out_virtual", "out_virtual_len"],
        [
          "ex_host_vfs_resolve_path",
          "out:virtual",
          "out_virtual",
          "out_virtual_len",
        ],
        [
          "ex_host_vfs_resolve_path",
          "out:backing",
          "out_backing",
          "out_backing_len",
        ],
      ].map(([functionName, output, parameter, lengthParameter]) => ({
        functionName,
        operation: "rust-host-authenticated-vfs-path-output",
        output,
        recordPath: [output],
        selectedOutput: {
          kind: "buffer",
          lengthParameter,
          ownership: {
            kind: "caller-owned",
            releaseFunction: "ex_host_free_buffer",
          },
          parameter,
          role: "output",
          selector: output,
        },
      })),
    ]);
  });

  test("authors the ten exact legacy path and directory output variants", () => {
    expect(legacyOutputCases.map(({ probe }) => probe).every(Boolean)).toBe(
      true,
    );
    expect(
      legacyOutputCases.map(({ catalogRow, probe }) => ({
        alias: catalogRow.key.alias,
        catalogOutput: probe.sourceDescriptor.catalogOutput,
        mode: probe.sourceDescriptor.catalogMode,
        operation: probe.sourceDescriptor.operation.kind,
        projection: probe.sourceDescriptor.selectedOutput.projection,
        recordPath: probe.recordPath,
        returnVariant: probe.sourceDescriptor.returnVariant,
        sourceSelector: probe.sourceDescriptor.selectedOutput.selector,
      })),
    ).toEqual([
      ...[
        "ex_host_fs_mkdir_recursive_result",
        "ex_host_fs_mkdtemp",
        "ex_host_fs_realpath",
      ].flatMap((functionName) =>
        [
          ["unarmed", "success"],
          ["unarmed", "error"],
          ["armed", "refused"],
        ].map(([mode, returnVariant]) => ({
          alias: functionName,
          catalogOutput: "[[return]]",
          mode,
          operation: "rust-host-legacy-path-output",
          projection: {
            catalogSelector: "[[return]]",
            kind: "whole-return",
          },
          recordPath: ["[[return]]"],
          returnVariant,
          sourceSelector: "[[return]]",
        })),
      ),
      {
        alias: "ex_host_fs_readdir[]",
        catalogOutput: "array-items",
        mode: "all",
        operation: "rust-host-legacy-directory-output",
        projection: {
          catalogSelector: "array-items",
          kind: "json-array-items",
        },
        recordPath: ["array-items"],
        returnVariant: "success",
        sourceSelector: "[[return]]",
      },
    ]);
    for (const { probe } of legacyOutputCases) {
      expect(probe.sourceDescriptor.selectedOutput).toMatchObject({
        kind: "pointer",
        ownership: {
          kind: "caller-owned",
          releaseFunction: "ex_host_free_string",
        },
        role: "return",
        selector: "[[return]]",
      });
      expect(probe.sourceDescriptor.sourceSafetyBinding).toMatchObject({
        path: "src/host/abi.rs",
        returnOwnership: {
          kind: "caller-owned",
          releaseFunction: "ex_host_free_string",
          sourceToken: "ex_host_free_string",
        },
      });
    }

    const drifted = structuredClone(legacyOutputCases[0]);
    drifted.surface.metadata.definitions[0].outputContract.return.ownership = {
      kind: "unknown",
    };
    expect(() =>
      authoredHostAbiOutputProbe({
        catalogRow: drifted.catalogRow,
        surface: drifted.surface,
        coverageEdge: drifted.edge,
      }),
    ).toThrow("legacy Host pointer return contract drifted");
  });

  test("fails closed when a bounded path selector loses its source ownership contract", () => {
    const original = pathOutputCases.find(
      ({ catalogRow }) => catalogRow.key.output === "out:backing",
    );
    const surface = structuredClone(original.surface);
    const channel = surface.metadata.definitions[0].outputContract.outputChannels.find(
      (candidate) => candidate.selector === "out:backing",
    );
    channel.ownership = { kind: "caller-storage" };
    expect(() =>
      authoredHostAbiOutputProbe({
        catalogRow: original.catalogRow,
        surface,
        coverageEdge: original.edge,
      }),
    ).toThrow("lost its exact source ownership contract");

    const unownedSelector = structuredClone(original.catalogRow);
    unownedSelector.key.output = "out:unreviewed";
    expect(
      authoredHostAbiOutputProbe({
        catalogRow: unownedSelector,
        surface: original.surface,
        coverageEdge: original.edge,
      }),
    ).toBeNull();
  });

  test("binds every probe to exact symbols, source refs, and current raw file digests", () => {
    for (const { catalogRow, edge, probe } of authored) {
      expect(probe.kind).toBe("loaded-engine-return-record");
      expect(probe.recordPath).toEqual([catalogRow.key.output]);
      expect(probe.sourceDescriptor.kind).toBe(HOST_ABI_OUTPUT_SOURCE_DESCRIPTOR_KIND);
      expect(probe.sourceDescriptor.invocationSchema).toBe(
        HOST_ABI_OUTPUT_INVOCATION_SCHEMA,
      );
      expect(probe.sourceDescriptor.functionName).toBe(edge.surface.name);
      expect(probe.sourceDescriptor.catalogOutput).toBe(catalogRow.key.output);
      expect(probe.sourceDescriptor.outputContractSchema).toBe(
        HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
      );
      if (
        catalogRow.key.output === "[[return]]" &&
        probe.sourceDescriptor.selectedOutput.kind === "scalar"
      ) {
        expect(probe.sourceDescriptor.selectedOutput).toEqual({
          kind: "scalar",
          ownership: "not-applicable",
          selector: "[[return]]",
        });
      } else if (catalogRow.key.output !== "[[return]]") {
        expect(probe.sourceDescriptor.selectedOutput.selector).toBe(
          probe.sourceDescriptor.selectedOutput.projection
            ? "[[return]]"
            : catalogRow.key.output,
        );
        expect(
          new Set(["aggregate", "buffer", "pointer", "scalar"]).has(
            probe.sourceDescriptor.selectedOutput.kind,
          ),
        ).toBe(true);
      } else {
        expect(probe.sourceDescriptor.selectedOutput).toMatchObject({
          kind: "pointer",
          ownership: {
            kind: "caller-owned",
            releaseFunction: expect.any(String),
          },
          role: "return",
          selector: "[[return]]",
        });
      }
      expect(probe.sourceDescriptor.outputContracts.length).toBeGreaterThan(0);
      expect(
        probe.sourceDescriptor.outputContracts.every((contract) => {
          if (
            contract.schema !== HOST_ABI_OUTPUT_CONTRACT_SCHEMA ||
            contract.functionName !== edge.surface.name
          ) {
            return false;
          }
          if (
            catalogRow.key.output !== "[[return]]" &&
            !probe.sourceDescriptor.selectedOutput.projection
          ) {
            return contract.outputChannels.some(
              (channel) =>
                channel.selector === catalogRow.key.output &&
                JSON.stringify(channel) ===
                  JSON.stringify(probe.sourceDescriptor.selectedOutput),
            );
          }
          if (contract.return.role !== "value") return false;
          return probe.sourceDescriptor.selectedOutput.kind === "pointer"
            ? contract.return.kind === "pointer" &&
                contract.return.ownership.kind === "caller-owned" &&
                typeof contract.return.ownership.releaseFunction === "string"
            : contract.return.kind === "scalar" &&
                contract.return.ownership.kind === "not-applicable";
        }),
      ).toBe(true);
      expect(probe.sourceDescriptor.sourceFiles.length).toBeGreaterThan(0);
      for (const binding of probe.sourceDescriptor.sourceFiles) {
        expect(binding.rawContentDigest).toMatch(/^sha256-[A-Za-z0-9_-]{43}$/);
        expect(
          fs.readFileSync(path.join(repoRoot, binding.path), "utf8"),
        ).toContain(edge.surface.name);
      }
    }
  });

  test("promotes bounded stateful routes while leaving platform-only routes residual", () => {
    const names = new Set(authored.map(({ edge }) => edge.surface.name));
    for (const executable of [
      "ex_host_http_serve",
      "ex_hermes_create_armed",
      "ex_hermes_eval_structured_session",
      "ex_hermes_module_compile_factory",
    ]) {
      expect(names.has(executable), executable).toBe(true);
    }
    expect(names.has("java:dev.ibex.runtime.IbexNetworking.fetch")).toBe(false);
    for (const nonPromotable of [
      "ex_host_free_string",
      "ex_host_fs_realpath",
    ]) {
      expect(
        authored.some(
          ({ edge, catalogRow }) =>
            edge.surface.name === nonPromotable &&
            catalogRow.key.returnVariant === "default",
        ),
        nonPromotable,
      ).toBe(false);
    }
    for (const ownedPointer of [
      "ex_hermes_create_diagnostic",
      "ex_host_fs_open",
      "ex_host_fs_read_file",
      "ex_worklet_drain_logs",
    ]) {
      expect(
        authored.some(
          ({ edge, catalogRow }) =>
            edge.surface.name === ownedPointer &&
            catalogRow.key.returnVariant === "default",
        ),
        ownedPointer,
      ).toBe(true);
    }
  });

  test("an exact target-absence binding always preempts this author", () => {
    const row = authored[0];
    expect(
      authoredHostAbiOutputProbe({
        catalogRow: row.catalogRow,
        surface: row.surface,
        coverageEdge: row.edge,
        targetAbsenceBinding: { fixtureId: "exact-target-absence" },
      }),
    ).toBeNull();
  });

  test("partitions the Host ABI catalog bidirectionally by exact seven-part keys", () => {
    const partition = buildHostAbiOutputProbePartition({
      catalog,
      coverage,
      surfaces,
    });
    expect(partition.hostAbiOutputPartitionSchema).toBe(
      HOST_ABI_OUTPUT_PARTITION_SCHEMA,
    );
    expect(partition.targetAbsenceBindings).toEqual([]);
    expect(partition.rows).toHaveLength(authored.length);
    expect(partition.residuals).toHaveLength(
      catalog.rows.filter((row) => row.key.sourceKind === "host-abi").length -
        authored.length,
    );
    expect(
      partition.residuals.filter((row) =>
        new Set([
          "pointer-return-ownership-is-not-source-bound",
          "void-abi-has-no-syntactic-return-slot",
        ]).has(row.reason),
      ),
    ).toEqual([]);
    const catalogKeys = catalog.rows
      .filter((row) => row.key.sourceKind === "host-abi")
      .map((row) => canonicalOutputDispositionKey(row.key))
      .sort();
    const partitionKeys = [...partition.rows, ...partition.residuals]
      .map((row) => canonicalOutputDispositionKey(row.key))
      .sort();
    expect(partitionKeys).toEqual(catalogKeys);

    const exactAbsence = {
      key: structuredClone(authored[0].catalogRow.key),
      fixtureId: "exact-target-absence",
    };
    const withAbsence = buildHostAbiOutputProbePartition({
      catalog,
      coverage,
      surfaces,
      targetAbsenceBindings: [exactAbsence],
    });
    expect(withAbsence.targetAbsenceBindings).toEqual([exactAbsence]);
    expect(withAbsence.rows).toHaveLength(authored.length - 1);
    expect(withAbsence.residuals).toHaveLength(partition.residuals.length);
    expect(() =>
      buildHostAbiOutputProbePartition({
        catalog,
        coverage,
        surfaces,
        targetAbsenceBindings: [exactAbsence, exactAbsence],
      }),
    ).toThrow("duplicate Host ABI target-absence binding");
  });
});
