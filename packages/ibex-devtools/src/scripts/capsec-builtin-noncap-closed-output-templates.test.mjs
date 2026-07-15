// @ref LLP 0023#6-path-bearing-observables — the output recipe universe is
// source-derived and contains no reviewed disposition or expected value.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import { outputShapeProbeKindForCatalogRow } from "./capsec-output-shape-sweep.mjs";
import {
  BUILTIN_NONCAP_CLOSED_OUTPUT_INVOCATION_SCHEMA,
  authoredBuiltinNoncapClosedOutputInvocation,
  builtinNoncapClosedOutputRouteManifest,
  hasBuiltinNoncapClosedDescriptorResidualRoute,
} from "./capsec-builtin-noncap-closed-output-templates.mjs";
import { canonicalOutputDispositionKey } from "./capsec-output-dispositions.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const outputDispositionPolicy = JSON.parse(
  fs.readFileSync(
    path.join(repoRoot, "capsec/registry/output-disposition-policy.json"),
    "utf8",
  ),
);
const ASYNC_HOOKS_IMPORT_REFUSAL_ALIASES = [
  "export:node_async_hooks:AsyncLocalStorage",
  "export:node_async_hooks:AsyncLocalStorage.disable",
  "export:node_async_hooks:AsyncLocalStorage.enable",
  "export:node_async_hooks:AsyncLocalStorage.enterWith",
  "export:node_async_hooks:AsyncLocalStorage.exit",
  "export:node_async_hooks:AsyncLocalStorage.getStore",
  "export:node_async_hooks:AsyncLocalStorage.run",
  "export:node_async_hooks:AsyncLocalStorage.snapshot",
  "export:node_async_hooks:AsyncResource",
  "export:node_async_hooks:AsyncResource.asyncId",
  "export:node_async_hooks:AsyncResource.bind",
  "export:node_async_hooks:AsyncResource.emitAfter",
  "export:node_async_hooks:AsyncResource.emitBefore",
  "export:node_async_hooks:AsyncResource.emitDestroy",
  "export:node_async_hooks:AsyncResource.runInAsyncScope",
  "export:node_async_hooks:AsyncResource.triggerAsyncId",
  "export:node_async_hooks:__emitInit",
  "export:node_async_hooks:__getHooksEnabled",
  "export:node_async_hooks:__nextAsyncId",
  "export:node_async_hooks:createHook",
  "export:node_async_hooks:executionAsyncId",
  "export:node_async_hooks:triggerAsyncId",
];

async function residualInvocations() {
  const catalog = JSON.parse(
    fs.readFileSync(
      path.join(repoRoot, "capsec/generated/output-shape-catalog.json"),
      "utf8",
    ),
  );
  const coverage = JSON.parse(
    fs.readFileSync(
      path.join(repoRoot, "capsec/registry/coverage-edges.json"),
      "utf8",
    ),
  );
  const rules = JSON.parse(
    fs.readFileSync(
      path.join(repoRoot, "capsec/registry/policy-rules.json"),
      "utf8",
    ),
  );
  const target = rules.initialProfile.candidateTargets[0];
  const inventory = await discoverRepositorySurfaces(repoRoot);
  const surfaces = new Map(
    inventory.surfaces.map((surface) => [
      `${surface.kind}:${surface.name}`,
      surface,
    ]),
  );
  const edges = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  return catalog.rows.flatMap((row) => {
    const coverageEdge = edges.get(row.key.surfaceId);
    const surface = coverageEdge
      ? surfaces.get(
          `${coverageEdge.surface.kind}:${coverageEdge.surface.name}`,
        )
      : null;
    const genericKind = outputShapeProbeKindForCatalogRow(row, surface, {
      coverageEdge,
      target,
    });
    if (
      row.key.sourceKind !== "builtin" ||
      !new Set(["non-capability", "closed"]).has(
        coverageEdge?.classification,
      ) ||
      !new Set(["compiled-registrar", "loaded-engine-descriptor"]).has(
        genericKind,
      )
    ) {
      return [];
    }
    if (
      genericKind === "loaded-engine-descriptor" &&
      !hasBuiltinNoncapClosedDescriptorResidualRoute({
        catalogKey: row.key,
        surface,
        target,
      })
    ) {
      return [];
    }
    const invocation = authoredBuiltinNoncapClosedOutputInvocation({
      catalogKey: row.key,
      coverageEdge,
      surface,
      target,
    });
    if (!invocation) {
      if (genericKind === "loaded-engine-descriptor") return [];
      throw new Error(
        `missing builtin output recipe for ${surface.observedKey}`,
      );
    }
    return [{ row, coverageEdge, surface, invocation }];
  });
}

const loaded = residualInvocations();

describe("builtin non-capability/closed output recipes", () => {
  test("accounts for the exact callable/accessor and descriptor residual universe", async () => {
    const rows = await loaded;
    expect(rows).toHaveLength(716);
    expect(
      Object.fromEntries(
        ["non-capability", "closed"].map((classification) => [
          classification,
          rows.filter(
            (row) => row.coverageEdge.classification === classification,
          ).length,
        ]),
      ),
    ).toEqual({ "non-capability": 487, closed: 229 });
    expect(
      builtinNoncapClosedOutputRouteManifest(rows.map((row) => row.invocation)),
    ).toMatchObject({
      total: 716,
      operations: {
        call: 355,
        construct: 52,
        get: 86,
        "import-refusal": 22,
        "import-return": 18,
        unexercisable: 183,
      },
    });
    // Duplex now owns an explicit `_undestroy` descriptor, so its invocation
    // is exercised by the public-probe family rather than this inherited
    // descriptor-residual family.
    expect(
      rows.some(
        ({ surface }) =>
          surface.name === "export:node_stream:Duplex._undestroy",
      ),
    ).toBe(false);
  }, 30_000);

  test("binds every operation to the exact source descriptor without expectations", async () => {
    const rows = await loaded;
    for (const { row, coverageEdge, surface, invocation } of rows) {
      expect(invocation.invocationSchema).toBe(
        BUILTIN_NONCAP_CLOSED_OUTPUT_INVOCATION_SCHEMA,
      );
      expect(invocation.coverageEdgeId).toBe(row.key.surfaceId);
      expect(invocation.coverageClassification).toBe(
        coverageEdge.classification,
      );
      expect(invocation.surfaceObservedKey).toBe(surface.observedKey);
      expect(invocation.sourceDescriptor.sourceKey).toBe(
        surface.metadata.sourceKey,
      );
      if (surface.metadata.surfaceType === "export") {
        expect(invocation.sourceDescriptor.exportName).toBe(
          surface.metadata.exportName,
        );
      } else {
        expect(invocation.sourceDescriptor).toMatchObject({
          kind: "builtin-root",
          exportName: "[[module]]",
          moduleSpecifiers: [surface.name],
          access: { kind: "module-value", path: [] },
        });
      }
      expect(invocation.completion).toEqual({
        kind: "event-loop-quiescence",
        timeoutMilliseconds: 1_000,
      });
      expect(coverageEdge.surface.name).toBe(surface.name);
      if (invocation.route.operation === "unexercisable") {
        expect(invocation.route.reasonCode.length).toBeGreaterThan(0);
        expect(invocation.route.reason.length).toBeGreaterThan(15);
      } else {
        expect(
          new Set([
            "call",
            "construct",
            "get",
            "import-refusal",
            "import-return",
          ]).has(invocation.route.operation),
        ).toBe(true);
        expect(invocation.route.cleanup.kind.length).toBeGreaterThan(0);
      }
      const encoded = JSON.stringify(invocation);
      expect(encoded).not.toContain("normalizedValue");
      expect(encoded).not.toContain("expectation");
      expect(encoded).not.toContain("disposition");
      expect(encoded).not.toContain("expectedResult");
    }
  }, 30_000);

  test("binds every terminal async-hooks import refusal to an exact closed disposition", async () => {
    const refusals = (await loaded).filter(
      ({ invocation }) => invocation.route.operation === "import-refusal",
    );
    expect(
      refusals.map(({ row }) => row.key.alias).sort(),
    ).toEqual(ASYNC_HOOKS_IMPORT_REFUSAL_ALIASES);
    for (const { coverageEdge, invocation } of refusals) {
      expect(coverageEdge.classification).toBe("closed");
      expect(invocation).toMatchObject({
        moduleSpecifier: "node:async_hooks",
        sourceDescriptor: {
          sourceKey: "node_async_hooks",
          importReachability: "public",
        },
        route: {
          operation: "import-refusal",
          cleanup: { kind: "none" },
        },
      });
    }

    const refusalKeys = refusals
      .map(({ row }) => canonicalOutputDispositionKey(row.key))
      .sort();
    const overrides = outputDispositionPolicy.overrides.filter(({ key }) =>
      key.alias.startsWith("export:node_async_hooks:"),
    );
    expect(
      overrides.map(({ key }) => canonicalOutputDispositionKey(key)).sort(),
    ).toEqual(refusalKeys);
    for (const override of overrides) {
      expect(override).toMatchObject({
        disposition: "closed",
        expectation: {
          outcome: "throw",
          normalizedValue: "ERR_IBEX_IMPORT_DENIED",
        },
      });
    }
  }, 30_000);

  test("uses bounded in-memory fixtures and preserves honest residuals", async () => {
    const byExport = new Map(
      (await loaded).map((row) => [
        `${row.invocation.sourceDescriptor.sourceKey}:${row.invocation.sourceDescriptor.exportName}`,
        row.invocation,
      ]),
    );
    expect(byExport.get("node_buffer:Buffer.offset").route).toMatchObject({
      operation: "get",
      receiver: { kind: "buffer-owner", ownerExportName: "Buffer" },
    });
    expect(byExport.get("node_fs:Dirent.isFile").route).toMatchObject({
      operation: "call",
      receiver: { kind: "fs-dirent" },
    });
    expect(
      byExport.get("node_fs:ReadStream.destroy").sourceDescriptor.access,
    ).toMatchObject({ kind: "inherited-prototype-property" });
    expect(
      byExport.get("node_fs:WriteStream._emitClose").sourceDescriptor.access,
    ).toMatchObject({ kind: "inherited-prototype-property" });
    expect(byExport.get("node_console:Console").route).toMatchObject({
      operation: "construct",
      arguments: [{ kind: "console-writable-sink" }],
    });
    expect(byExport.get("exact_sqlite:Database._closed").route).toMatchObject({
      operation: "get",
      receiver: { kind: "sqlite-database" },
    });
    expect(byExport.get("node_timers:setTimeout").route).toMatchObject({
      operation: "call",
      cleanup: { kind: "returned-timer-handle" },
    });
    expect(byExport.get("node_http:validateHeaderValue").route).toMatchObject({
      operation: "call",
      arguments: [
        { kind: "json", value: "x-ibex-output-shape" },
        { kind: "json", value: "ibex-output-shape" },
      ],
    });
    expect(byExport.get("node_http2:getUnpackedSettings").route).toMatchObject({
      operation: "call",
      arguments: [{ kind: "uint8-array", bytes: [0, 2, 0, 0, 0, 1] }],
    });
    expect(byExport.get("node_tls:checkServerIdentity").route).toMatchObject({
      operation: "call",
      arguments: [
        { kind: "json", value: "localhost" },
        {
          kind: "json",
          value: { subjectaltname: "DNS:localhost" },
        },
      ],
    });
    expect(byExport.get("node_zlib:ZstdCompress.end").route).toMatchObject({
      operation: "call",
      outcomeCapture: "public-builtin-family",
    });
    expect(
      byExport.get("node_async_hooks:AsyncLocalStorage").route,
    ).toMatchObject({
      operation: "import-refusal",
      cleanup: { kind: "none" },
    });
    const bootstrapInternal = (await loaded).find(
      (row) =>
        row.invocation.sourceDescriptor.importReachability ===
        "bootstrap-internal",
    );
    expect(bootstrapInternal).toBeDefined();
    expect(bootstrapInternal.invocation.route).toMatchObject({
      operation: "unexercisable",
      reasonCode: "bootstrap-shadowed-manifest-export",
    });
  }, 30_000);
});
