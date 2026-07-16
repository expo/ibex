import { beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  auditNativeGlobalMarkerAliasClosure,
  authoredNativeGlobalMarkerStructuralAccount,
  CAPSEC_CONTEXT_OBSERVER_SURFACE,
  capsecContextObserverOutputCatalogBinding,
  NATIVE_GLOBAL_MARKER_OUTPUT_CATALOG_BINDINGS,
  NATIVE_GLOBAL_MARKER_STRUCTURAL_ACCOUNT_SCHEMA,
  NATIVE_GLOBAL_MARKER_STRUCTURAL_REASON_CODE,
  NATIVE_GLOBAL_MARKER_SURFACE,
  nativeGlobalMarkerStructuralAccountBindings,
  validateNativeGlobalMarkerAliasCatalog,
} from "./capsec-native-global-marker-alias-accounts.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const ENGINE_PATH = "src/engine/hermes_runtime.cc";
const SECOND_ENGINE_PATH = "src/engine/hermes_runtime_utils.cc";
const HERMES_RUST_PATH = "src/bin/ibex/engine/hermes.rs";
const FIXTURE_RUST_PATH =
  "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs";
const BUILD_PATH = "build.rs";

const readText = (relativePath) =>
  fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
const readJson = (relativePath) => JSON.parse(readText(relativePath));

function replaceExact(source, before, after, label) {
  const start = source.indexOf(before);
  if (start === -1 || source.indexOf(before, start + before.length) !== -1) {
    throw new Error(`${label}: expected one mutation target`);
  }
  return source.slice(0, start) + after + source.slice(start + before.length);
}

function replaceFirst(source, before, after, label) {
  const start = source.indexOf(before);
  if (start === -1) throw new Error(`${label}: missing mutation target`);
  return source.slice(0, start) + after + source.slice(start + before.length);
}

function auditWithOverrides(overrides = {}, options = {}) {
  return auditNativeGlobalMarkerAliasClosure({
    repoRoot,
    surfaces: options.surfaces ?? surfaces,
    coverage: options.coverage ?? coverage,
    readSource: (_absolutePath, relativePath) =>
      Object.hasOwn(overrides, relativePath)
        ? overrides[relativePath]
        : readText(relativePath),
  });
}

function syntheticCatalog(audit) {
  return {
    surfaceAccounts: [
      {
        surfaceId: audit.marker.surfaceId,
        status: "structural-only",
        reasonCode: NATIVE_GLOBAL_MARKER_STRUCTURAL_REASON_CODE,
        sourceRefs: [...audit.marker.sourceRefs],
        outputKinds: [],
      },
      structuredClone(audit.observer.catalogAccount),
    ],
    rows: structuredClone(audit.observer.catalogRows),
  };
}

let surfaces;
let coverage;
let sourceAudit;

beforeAll(async () => {
  surfaces = (await discoverRepositorySurfaces(repoRoot)).surfaces;
  coverage = readJson("capsec/registry/coverage-edges.json");
  sourceAudit = auditWithOverrides();
}, 30_000);

describe("native dynamic-global structural alias account", () => {
  test("proves the sole recursive writer and its bounded observer lifecycle", () => {
    expect(sourceAudit.structuralAccountSchema).toBe(
      NATIVE_GLOBAL_MARKER_STRUCTURAL_ACCOUNT_SCHEMA,
    );
    expect(sourceAudit.proof).toMatchObject({
      dynamicWriterPath: ENGINE_PATH,
      buildFeature: "capsec-conformance-observer",
      armedOnly: true,
      restrictedRuntimeRefused: true,
      unpredictableNamePrefix: "__ibexCapsecContextObserver_",
      unpredictableSuffixBits: 128,
      oneShot: true,
      captureDeletePairs: 5,
    });
    expect(sourceAudit.proof.engineCppFiles).toBeGreaterThan(25);
    expect(sourceAudit.proof.engineCppPathsDigest).toMatch(/^sha256-/u);
    expect(sourceAudit.marker.observedKey).toBe(
      `native-op:${NATIVE_GLOBAL_MARKER_SURFACE}`,
    );
    expect(sourceAudit.observer.observedKey).toBe(
      `native-op:${CAPSEC_CONTEXT_OBSERVER_SURFACE}`,
    );
  });

  test("keeps the marker rowless and the observer output-bearing with three exact rows", () => {
    expect(NATIVE_GLOBAL_MARKER_OUTPUT_CATALOG_BINDINGS).toEqual([]);
    expect(nativeGlobalMarkerStructuralAccountBindings(sourceAudit)).toEqual([
      expect.objectContaining({
        surfaceName: NATIVE_GLOBAL_MARKER_SURFACE,
        status: "structural-only",
        outputKinds: [],
        outputDependencies: [
          {
            surfaceObservedKey: `native-op:${CAPSEC_CONTEXT_OBSERVER_SURFACE}`,
            selector: "[[return]]",
          },
          {
            surfaceObservedKey: `native-op:${CAPSEC_CONTEXT_OBSERVER_SURFACE}`,
            selector: "field:principalId",
          },
          {
            surfaceObservedKey: `native-op:${CAPSEC_CONTEXT_OBSERVER_SURFACE}`,
            selector: "field:runtimeNonce",
          },
        ],
      }),
    ]);

    const observer = capsecContextObserverOutputCatalogBinding(sourceAudit);
    expect(observer.surfaceName).toBe(CAPSEC_CONTEXT_OBSERVER_SURFACE);
    expect(observer.account).toMatchObject({
      status: "output-bearing",
      outputKinds: ["structured-output"],
    });
    expect(observer.rows.map((row) => row.key)).toEqual([
      {
        surfaceId: sourceAudit.observer.surfaceId,
        output: "[[return]]",
        alias: "__ibexCapsecContextObserver_.context",
        mode: "ephemeral-one-shot",
        sourceKind: "native-op",
        returnVariant: "context-record",
        contextId: "javascript.package-call-loaded",
      },
      {
        surfaceId: sourceAudit.observer.surfaceId,
        output: "field:principalId",
        alias: "__ibexCapsecContextObserver_.principalId",
        mode: "ephemeral-one-shot",
        sourceKind: "native-op",
        returnVariant: "u64-tagged-string",
        contextId: "javascript.package-call-loaded",
      },
      {
        surfaceId: sourceAudit.observer.surfaceId,
        output: "field:runtimeNonce",
        alias: "__ibexCapsecContextObserver_.runtimeNonce",
        mode: "ephemeral-one-shot",
        sourceKind: "native-op",
        returnVariant: "u64-tagged-string",
        contextId: "javascript.package-call-loaded",
      },
    ]);
  });

  test("authors the structural account and validates only the exact catalog pair", () => {
    const surfaceByObservedKey = new Map(
      surfaces.map((surface) => [surface.observedKey, surface]),
    );
    const edgeByObservedKey = new Map(
      coverage.edges.map((edge) => [
        `${edge.surface.kind}:${edge.surface.name}`,
        edge,
      ]),
    );
    const markerKey = `native-op:${NATIVE_GLOBAL_MARKER_SURFACE}`;
    const account = authoredNativeGlobalMarkerStructuralAccount({
      surface: surfaceByObservedKey.get(markerKey),
      coverageEdge: edgeByObservedKey.get(markerKey),
      sourceAudit,
    });
    expect(account).toMatchObject({
      structuralAccountSchema: NATIVE_GLOBAL_MARKER_STRUCTURAL_ACCOUNT_SCHEMA,
      status: "structural-only",
      reasonCode: NATIVE_GLOBAL_MARKER_STRUCTURAL_REASON_CODE,
      outputKinds: [],
    });

    const catalog = syntheticCatalog(sourceAudit);
    expect(
      validateNativeGlobalMarkerAliasCatalog({
        catalog,
        coverage,
        sourceAudit,
      }),
    ).toBe(true);

    const markerRow = structuredClone(catalog);
    markerRow.rows.push({
      ...structuredClone(markerRow.rows[0]),
      key: {
        ...structuredClone(markerRow.rows[0].key),
        surfaceId: sourceAudit.marker.surfaceId,
      },
    });
    expect(() =>
      validateNativeGlobalMarkerAliasCatalog({
        catalog: markerRow,
        coverage,
        sourceAudit,
      }),
    ).toThrow(/rowless/u);

    const missingObserverRow = structuredClone(catalog);
    missingObserverRow.rows.pop();
    expect(() =>
      validateNativeGlobalMarkerAliasCatalog({
        catalog: missingObserverRow,
        coverage,
        sourceAudit,
      }),
    ).toThrow(/exactly three structured output rows/u);

    const unresolvedObserver = structuredClone(catalog);
    unresolvedObserver.surfaceAccounts[1].status = "unresolved";
    expect(() =>
      validateNativeGlobalMarkerAliasCatalog({
        catalog: unresolvedObserver,
        coverage,
        sourceAudit,
      }),
    ).toThrow(/output-bearing catalog account/u);
  });

  test("rejects a second recursively discovered native dynamic-global writer", () => {
    const secondWriter = `${readText(SECOND_ENGINE_PATH)}
void ibex_test_dynamic_writer_drift(
    facebook::jsi::Runtime& rt,
    facebook::jsi::PropNameID property,
    facebook::jsi::Value value) {
  rt.global().setProperty(rt, property, std::move(value));
}
`;
    expect(() =>
      auditWithOverrides({ [SECOND_ENGINE_PATH]: secondWriter }),
    ).toThrow(/expected one native dynamic-global writer/u);
  });

  test("rejects weakened C++, build, or Rust lifecycle evidence", () => {
    expect(() =>
      auditWithOverrides({
        [ENGINE_PATH]: replaceExact(
          readText(ENGINE_PATH),
          "called->exchange(true)",
          "called->load()",
          "one-shot gate",
        ),
      }),
    ).toThrow(/one-shot|missing source token/u);

    expect(() =>
      auditWithOverrides({
        [BUILD_PATH]: replaceExact(
          readText(BUILD_PATH),
          'CARGO_FEATURE_CAPSEC_CONFORMANCE_OBSERVER")',
          'CARGO_FEATURE_CAPSEC_CONFORMANCE_OBSERVER_DISABLED")',
          "build feature",
        ),
      }),
    ).toThrow(/build feature binding/u);

    expect(() =>
      auditWithOverrides({
        [HERMES_RUST_PATH]: replaceExact(
          readText(HERMES_RUST_PATH),
          "getrandom::getrandom(&mut nonce)",
          "nonce.fill(0)",
          "Rust entropy source",
        ),
      }),
    ).toThrow(/name proof/u);

    expect(() =>
      auditWithOverrides({
        [FIXTURE_RUST_PATH]: replaceFirst(
          readText(FIXTURE_RUST_PATH),
          "var removed = delete globalThis[{0}];",
          "var removed = true;",
          "capture-delete lifecycle",
        ),
      }),
    ).toThrow(/captured and deleted before use/u);
  });

  test("rejects inventory or coverage identity drift", () => {
    const missingObserver = surfaces.filter(
      (surface) =>
        surface.observedKey !== `native-op:${CAPSEC_CONTEXT_OBSERVER_SURFACE}`,
    );
    expect(() => auditWithOverrides({}, { surfaces: missingObserver })).toThrow(
      /inventory or coverage drifted/u,
    );

    const driftedCoverage = structuredClone(coverage);
    const markerEdge = driftedCoverage.edges.find(
      (edge) =>
        `${edge.surface.kind}:${edge.surface.name}` ===
        `native-op:${NATIVE_GLOBAL_MARKER_SURFACE}`,
    );
    markerEdge.cap = "runtime:mutate";
    expect(() => auditWithOverrides({}, { coverage: driftedCoverage })).toThrow(
      /inventory or coverage drifted/u,
    );
  });
});
