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
});

describe("source-bound Host ABI output templates", () => {
  test("authors exact bounded native tranches without promoting platform or registrar presence", () => {
    expect(authored).toHaveLength(77);
    expect(new Set(authored.map(({ edge }) => edge.surface.name)).size).toBe(77);
    expect(
      Object.fromEntries(
        [...Map.groupBy(authored, ({ probe }) => probe.sourceDescriptor.operation.kind)]
          .map(([kind, rows]) => [kind, rows.length])
          .sort(),
      ),
    ).toEqual({
      "rust-host-bounded-basic": 23,
      "rust-host-fs-sandbox": 18,
      "rust-host-sqlite-memory": 6,
      "rust-host-terminal-inert": 8,
      "native-hermes-diagnostic-runtime": 12,
      "native-hermes-stateless-current-target": 6,
      "native-hermes-worklet-runtime": 4,
    });
    expect(
      authored.every(({ probe }) =>
        probe.sourceDescriptor.selectedDefinitions.every(
          (definition) => definition.targetVariant === "default",
        ),
      ),
    ).toBe(true);
  });

  test("binds every probe to exact symbols, source refs, and current raw file digests", () => {
    for (const { catalogRow, edge, probe } of authored) {
      expect(probe.kind).toBe("loaded-engine-return-record");
      expect(probe.recordPath).toEqual(["[[return]]"]);
      expect(probe.sourceDescriptor.kind).toBe(HOST_ABI_OUTPUT_SOURCE_DESCRIPTOR_KIND);
      expect(probe.sourceDescriptor.invocationSchema).toBe(
        HOST_ABI_OUTPUT_INVOCATION_SCHEMA,
      );
      expect(probe.sourceDescriptor.functionName).toBe(edge.surface.name);
      expect(probe.sourceDescriptor.catalogOutput).toBe(catalogRow.key.output);
      expect(probe.sourceDescriptor.outputContractSchema).toBe(
        HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
      );
      expect(probe.sourceDescriptor.selectedOutput).toEqual({
        kind: "scalar",
        ownership: "not-applicable",
        selector: "[[return]]",
      });
      expect(probe.sourceDescriptor.outputContracts.length).toBeGreaterThan(0);
      expect(
        probe.sourceDescriptor.outputContracts.every(
          (contract) =>
            contract.schema === HOST_ABI_OUTPUT_CONTRACT_SCHEMA &&
            contract.functionName === edge.surface.name &&
            contract.return.role === "value" &&
            contract.return.kind === "scalar" &&
            contract.return.ownership.kind === "not-applicable",
        ),
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

  test("leaves unbounded armed/session, stateful, private-VFS, and platform routes residual", () => {
    const names = new Set(authored.map(({ edge }) => edge.surface.name));
    for (const residual of [
      "ex_hermes_create_armed",
      "ex_host_authorize_typed_fs_stack",
      "ex_host_http_serve",
      "ex_host_install_armed",
      "ex_host_vfs_get_cwd",
      "java:dev.ibex.runtime.IbexNetworking.fetch",
    ]) {
      expect(names.has(residual), residual).toBe(false);
    }
    for (const nonPromotable of [
      "ex_host_free_string",
      "ex_host_fs_realpath",
      "ex_hermes_create_diagnostic",
      "ex_worklet_drain_logs",
    ]) {
      expect(names.has(nonPromotable), nonPromotable).toBe(false);
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

  test("partitions the Host ABI catalog bidirectionally by exact six-part keys", () => {
    const partition = buildHostAbiOutputProbePartition({
      catalog,
      coverage,
      surfaces,
    });
    expect(partition.hostAbiOutputPartitionSchema).toBe(
      HOST_ABI_OUTPUT_PARTITION_SCHEMA,
    );
    expect(partition.targetAbsenceBindings).toEqual([]);
    expect(partition.rows).toHaveLength(77);
    expect(partition.residuals).toHaveLength(196);
    expect(
      Object.fromEntries(
        [...Map.groupBy(partition.residuals, (row) => row.reason)]
          .map(([reason, rows]) => [reason, rows.length])
          .filter(([reason]) =>
            new Set([
              "pointer-return-ownership-is-not-source-bound",
              "void-abi-has-no-syntactic-return-slot",
            ]).has(reason),
          )
          .sort(),
      ),
    ).toEqual({
      "pointer-return-ownership-is-not-source-bound": 28,
      "void-abi-has-no-syntactic-return-slot": 26,
    });
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
    expect(withAbsence.rows).toHaveLength(76);
    expect(withAbsence.residuals).toHaveLength(196);
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
