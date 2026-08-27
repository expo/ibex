// @ref LLP 0023#6-path-bearing-observables — the output catalog and reviewed
// dataset join bidirectionally on one canonical seven-part key, every coverage
// surface is accounted exactly once, and live values must agree before
// evidence becomes promotable.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import {
  OUTPUT_DISPOSITIONS,
  OUTPUT_DISPOSITION_EVIDENCE_EXECUTOR,
  buildOutputDispositionDataset,
  buildOutputShapeCatalog,
  canonicalOutputDispositionKey,
  defaultContextIdForCatalogRow,
  legacyHostPathOutputShapes,
  modulePackageRootShapes,
  outputExecutionContextsForRows,
  outputParameterizedBindingDigest,
  outputShapeCatalogKeyDigest,
  renderOutputDispositionMarkdown,
  resolverRecordShapes,
  validateOutputDispositionEvidence,
  validateOutputDispositionJoin,
  validateOutputShapeCatalogAccounts,
  validateOutputValueProofKind,
  validateTrackedOutputDispositionEvidenceSentinel,
  vfsHostAbiShapes,
} from "./capsec-output-dispositions.mjs";
import {
  CALLBACK_OUTPUT_CONTRACT_SCHEMA,
  deriveHostAbiOutputCatalogAccount,
  discoverRepositorySurfaces,
} from "./capsec-surface-inventory.mjs";
import {
  classifyObservedSurface,
  prepareCoverageContext,
} from "./capsec-coverage-model.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

function readRepoJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));
}

function countsBy(rows, select) {
  return Object.fromEntries(
    [...Map.groupBy(rows, select)]
      .map(([name, values]) => [name, values.length])
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

function key(index) {
  const privateNative = OUTPUT_DISPOSITIONS[index] === "private-native-path";
  return {
    surfaceId: `surface.test.output.${index}`,
    output: index % 2 === 0 ? "[[return]]" : `field:value${index}`,
    alias: `test.alias.${index}`,
    mode: index % 3 === 0 ? "file" : "all",
    sourceKind: privateNative
      ? "host-abi"
      : index % 2 === 0
        ? "builtin"
        : "native-op",
    returnVariant: "default",
    contextId: privateNative
      ? "host.private-native-call-initialized"
      : "javascript.package-call-loaded",
  };
}

function catalogRow(index) {
  return {
    key: key(index),
    discovery: {
      kind: "source-inventory-surface",
      observedKeys: [`test:${index}`],
      sourceRefs: [`test.js#${index}`],
    },
    requiredValueProof: "live-value-observation",
  };
}

function expectation(disposition) {
  if (disposition === "absent") {
    return { outcome: "absent", normalizedValue: "absent" };
  }
  if (disposition === "closed" || disposition === "refused") {
    return {
      outcome: "throw",
      normalizedValue:
        disposition === "closed" ? "ERR_IBEX_CLOSED_SURFACE" : "EACCES",
    };
  }
  if (disposition === "typed-logical") {
    return { outcome: "typed-return", normalizedValue: "ibex/logical-path/1" };
  }
  return { outcome: "return", normalizedValue: disposition };
}

function fixture() {
  const rows = OUTPUT_DISPOSITIONS.map((_, index) => catalogRow(index));
  const surfaceAccounts = rows.map((row, index) => ({
    surfaceId: row.key.surfaceId,
    status: "output-bearing",
    reasonCode: "test-output",
    sourceRefs: [`test.js#${index}`],
    outputKinds: ["test-output"],
  }));
  const catalog = {
    outputShapeCatalogSchema: "ibex/capsec-output-shape-catalog/2",
    profile: "ibex/capsec/1",
    discovery: {
      status: "unpromotable",
      method:
        "source-inventory-surface-accounting-plus-source-asserted-structured-outputs",
      requiredExecutor: OUTPUT_DISPOSITION_EVIDENCE_EXECUTOR,
      reason: "test evidence is intentionally absent",
    },
    contexts: outputExecutionContextsForRows(rows),
    surfaceAccounts,
    parameterizedOutputBindings: [],
    parameterizedBindingDigest: outputParameterizedBindingDigest([]),
    catalogKeyDigest: outputShapeCatalogKeyDigest(rows),
    counts: {
      coverageSurfaces: rows.length,
      outputBearingSurfaces: rows.length,
      structuralOnlySurfaces: 0,
      unresolvedSurfaces: 0,
      catalogRows: rows.length,
      parameterizedBindings: 0,
      sourceInventoryRows: rows.length,
      structuredRows: 0,
    },
    rows,
  };
  const policy = {
    outputDispositionPolicySchema: "ibex/capsec-output-disposition-policy/2",
    profile: "ibex/capsec/1",
    catalogKeyDigest: catalog.catalogKeyDigest,
    defaultDisposition: "non-path",
    defaultRationale: "reviewed exact test catalog",
    overrides: OUTPUT_DISPOSITIONS.map((disposition, index) => ({
      key: key(index),
      disposition,
      expectation: expectation(disposition),
      rationale: `test decision ${disposition}`,
    })),
  };
  const evidence = {
    outputDispositionEvidenceSchema:
      "ibex/capsec-output-disposition-evidence/3",
    profile: "ibex/capsec/1",
    status: "unpromotable",
    requiredExecutor: OUTPUT_DISPOSITION_EVIDENCE_EXECUTOR,
    reason: "test evidence is intentionally absent",
    observations: [],
  };
  return { catalog, policy, evidence };
}

let repositoryCatalogPromise;
async function repositoryCatalogFixture() {
  repositoryCatalogPromise ??= (async () => {
    const coverage = JSON.parse(
      fs.readFileSync(
        path.join(repoRoot, "capsec/registry/coverage-edges.json"),
        "utf8",
      ),
    );
    const inventory = await discoverRepositorySurfaces(repoRoot);
    const sourceByObservedKey = new Map(
      inventory.surfaces.map((surface) => [surface.observedKey, surface]),
    );
    const implementationRows = coverage.edges.map((edge) => {
      const observedKey = `${edge.surface.kind}:${edge.surface.name}`;
      const surface = sourceByObservedKey.get(observedKey);
      if (!surface) throw new Error(`test inventory lacks ${observedKey}`);
      return {
        edgeId: edge.id,
        observedKey,
        sourceRefs: [...surface.sourceRefs],
      };
    });
    const liveEvidence = readRepoJson(
      "capsec/registry/output-disposition-evidence.json",
    );
    const catalog = buildOutputShapeCatalog({
      coverage,
      implementationRows,
      surfaces: inventory.surfaces,
      repoRoot,
      liveEvidence,
    });
    return {
      catalog,
      coverage,
      implementationRows,
      surfaces: inventory.surfaces,
      liveEvidence,
    };
  })();
  return repositoryCatalogPromise;
}

const CLOCK_I_CANDIDATE_NEW_SURFACE_IDS = new Set([
  "surface.host.abi.ex.hermes.dispatch.event.attested.v1.1ba2uy1",
  "surface.native.op.ibexregisterexactdispatchevent.1i6csy6",
]);

function isClockICandidateAddedRow(row) {
  if (CLOCK_I_CANDIDATE_NEW_SURFACE_IDS.has(row.key.surfaceId)) return true;
  return (
    row.key.surfaceId === "surface.native.op.exactdispatchevent.1158ilx" &&
    row.key.output === "callback:dispatch/2" &&
    row.key.alias === "__exactDispatchEvent.attestClockICarrier" &&
    row.key.mode === "attested" &&
    row.key.sourceKind === "native-op" &&
    row.key.returnVariant === "call-scoped-host-function" &&
    row.key.contextId === "javascript.package-callback-loaded"
  );
}

function stageClockIOnlyCatalogDelta(discoveredCatalog, coverage) {
  const trackedCatalog = readRepoJson(
    "capsec/generated/output-shape-catalog.json",
  );
  const trackedKeys = new Set(
    trackedCatalog.rows.map((row) =>
      canonicalOutputDispositionKey(row.key),
    ),
  );
  const clockIAddedRows = discoveredCatalog.rows.filter(
    (row) =>
      !trackedKeys.has(canonicalOutputDispositionKey(row.key)) &&
      isClockICandidateAddedRow(row),
  );
  if (clockIAddedRows.length !== 4) {
    throw new Error(
      `Clock I candidate expected four source-derived output rows, found ${clockIAddedRows.length}`,
    );
  }

  const rows = [...trackedCatalog.rows, ...clockIAddedRows].sort(
    (left, right) => {
      const leftKey = canonicalOutputDispositionKey(left.key);
      const rightKey = canonicalOutputDispositionKey(right.key);
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    },
  );
  const trackedAccountIds = new Set(
    trackedCatalog.surfaceAccounts.map((account) => account.surfaceId),
  );
  const clockIAddedAccounts = discoveredCatalog.surfaceAccounts.filter(
    (account) =>
      !trackedAccountIds.has(account.surfaceId) &&
      CLOCK_I_CANDIDATE_NEW_SURFACE_IDS.has(account.surfaceId),
  );
  if (clockIAddedAccounts.length !== 2) {
    throw new Error(
      `Clock I candidate expected two source-derived surface accounts, found ${clockIAddedAccounts.length}`,
    );
  }
  const surfaceAccounts = [
    ...trackedCatalog.surfaceAccounts,
    ...clockIAddedAccounts,
  ].sort((left, right) => left.surfaceId.localeCompare(right.surfaceId));
  const accountCounts = validateOutputShapeCatalogAccounts({
    coverage,
    surfaceAccounts,
    rows,
    parameterizedOutputBindings:
      discoveredCatalog.parameterizedOutputBindings,
    promotionStatus: discoveredCatalog.discovery.status,
  });
  return {
    ...discoveredCatalog,
    contexts: outputExecutionContextsForRows(rows),
    surfaceAccounts,
    catalogKeyDigest: outputShapeCatalogKeyDigest(rows),
    counts: {
      coverageSurfaces: surfaceAccounts.length,
      outputBearingSurfaces: accountCounts["output-bearing"],
      structuralOnlySurfaces: accountCounts["structural-only"],
      unresolvedSurfaces: accountCounts.unresolved,
      catalogRows: rows.length,
      parameterizedBindings:
        discoveredCatalog.parameterizedOutputBindings.length,
      sourceInventoryRows: rows.filter(
        (row) => row.discovery.kind === "source-inventory-surface",
      ).length,
      structuredRows: rows.filter(
        (row) => row.discovery.kind === "source-asserted-structured-output",
      ).length,
    },
    rows,
  };
}

async function clockICandidateCatalogFixture() {
  const fixture = await repositoryCatalogFixture();
  const coverage = structuredClone(fixture.coverage);
  const implementationRows = structuredClone(fixture.implementationRows);
  const sourceByObservedKey = new Map(
    fixture.surfaces.map((surface) => [surface.observedKey, surface]),
  );
  const context = prepareCoverageContext({
    definitions: readRepoJson("capsec/registry/capability-definitions.json"),
    rules: readRepoJson("capsec/registry/policy-rules.json"),
  });
  for (const observedKey of [
    "host-abi:ex_hermes_dispatch_event_attested_v1",
    "native-op:__ibexRegisterExactDispatchEvent",
  ]) {
    const surface = sourceByObservedKey.get(observedKey);
    if (!surface) throw new Error(`Clock I candidate lacks ${observedKey}`);
    const classified = classifyObservedSurface(surface, context);
    coverage.edges.push(classified.edge);
    implementationRows.push(...classified.implementationRows);
  }
  coverage.edges.sort((left, right) => left.id.localeCompare(right.id));
  implementationRows.sort((left, right) =>
    `${left.edgeId}\u0000${left.branchId}`.localeCompare(
      `${right.edgeId}\u0000${right.branchId}`,
    ),
  );
  const discoveredCatalog = buildOutputShapeCatalog({
    coverage,
    implementationRows,
    surfaces: fixture.surfaces,
    repoRoot,
    liveEvidence: fixture.liveEvidence,
  });
  const catalog = stageClockIOnlyCatalogDelta(discoveredCatalog, coverage);
  return { catalog, coverage };
}

function verifiedEvidence(dataset) {
  const target = {
    triple: "aarch64-apple-darwin",
    features: ["native-lockdown"],
  };
  return {
    outputDispositionEvidenceSchema:
      "ibex/capsec-output-disposition-evidence/3",
    profile: "ibex/capsec/1",
    status: "verified",
    requiredExecutor: OUTPUT_DISPOSITION_EVIDENCE_EXECUTOR,
    sourceRevision: "a".repeat(40),
    sourceTreeDigest: `sha256-${"A".repeat(43)}`,
    conformanceRunner: {
      sourceRevision: "a".repeat(40),
      sourceTreeDigest: `sha256-${"A".repeat(43)}`,
      artifactId: `sha256-${"Y".repeat(43)}`,
      buildConsumptionDigest: `sha256-${"M".repeat(43)}`,
      postLinkSetDigest: `sha256-${"Q".repeat(43)}`,
      verificationDigest: `sha256-${"U".repeat(43)}`,
      testExecutableDigest: `sha256-${"e".repeat(64)}`,
    },
    target,
    engine: {
      engineArtifactPath: "/exact/hermes",
      kind: "hermes",
      binaryDigest: `sha256-${"A".repeat(43)}`,
      object: { platform: "apple", volume: "dev:1", file: "ino:2" },
      targetArchitecture: "aarch64",
      structuralFeatures: [...target.features],
    },
    sweepPlan: {},
    sweepArtifact: {},
    observations: dataset.rows.map((row) => ({
      key: structuredClone(row.key),
      disposition: row.disposition,
      proofKind: "loaded-engine-return-record",
      observation: structuredClone(row.expectation),
    })),
  };
}

describe("LLP 0023 output-disposition dataset", () => {
  test("catalogs every serialized resolver record and typed path field", () => {
    const full = resolverRecordShapes("__exactModuleResolve");
    const metadata = resolverRecordShapes("__exactModuleResolveMeta");
    const fullOutputs = new Set(full.map((row) => row.output));
    const metadataOutputs = new Set(metadata.map((row) => row.output));

    for (const output of [
      "[[return]]",
      "field:schema",
      "field:id",
      "field:kind",
      "field:error",
      "field:errorCode",
      "field:path",
      "field:pkgName",
      "field:pkgRoot",
      "field:pkgVersion",
      "field:pkgIntegrity",
      "field:sourceId",
      "field:sourceLabel",
      "field:virtualPath",
    ]) {
      expect(fullOutputs.has(output), output).toBe(true);
      expect(metadataOutputs.has(output), output).toBe(true);
    }
    expect(fullOutputs.has("field:source")).toBe(true);
    expect(metadataOutputs.has("field:source")).toBe(false);

    for (const prefix of ["field:path", "field:pkgRoot"]) {
      for (const suffix of [
        "schema",
        "sessionHandle",
        "virtualPath",
        "logicalPath",
        "logicalPath.root",
        "logicalPath.components",
        "logicalPath.components[]",
        "logicalPath.components[].encoding",
        "logicalPath.components[].value",
        "logicalPath.hostBound",
        "bindingOwner",
        "bindingOwner.kind",
        "bindingOwner.name",
        "bindingOwner.integrity",
        "bindingOwner.locator",
      ]) {
        expect(
          fullOutputs.has(`${prefix}.${suffix}`),
          `${prefix}.${suffix}`,
        ).toBe(true);
      }
      for (const suffix of [
        "",
        ".schema",
        ".sessionHandle",
        ".handle",
        ".virtualPath",
      ]) {
        expect(
          full.some(
            (row) =>
              row.output === `${prefix}${suffix}` &&
              row.returnVariant === "private-compat",
          ),
          `${prefix}${suffix}:private-compat`,
        ).toBe(true);
      }
    }
  });

  test("catalogs module package-root leaves and private VFS JavaScript absence", () => {
    const packageRootOutputs = new Set(
      modulePackageRootShapes().map((row) => row.output),
    );
    for (const suffix of [
      "",
      ".schema",
      ".sessionHandle",
      ".virtualPath",
      ".logicalPath",
      ".logicalPath.root",
      ".logicalPath.components",
      ".logicalPath.components[]",
      ".logicalPath.components[].encoding",
      ".logicalPath.components[].value",
      ".logicalPath.hostBound",
      ".bindingOwner",
      ".bindingOwner.kind",
      ".bindingOwner.name",
      ".bindingOwner.integrity",
      ".bindingOwner.locator",
    ]) {
      expect(
        packageRootOutputs.has(`field:__exactPackageRoot${suffix}`),
        suffix,
      ).toBe(true);
    }

    for (const name of [
      "ex_host_vfs_bind_runtime",
      "ex_host_vfs_chdir",
      "ex_host_vfs_get_cwd",
      "ex_host_vfs_resolve_path",
      "ex_host_vfs_unbind_runtime",
    ]) {
      expect(vfsHostAbiShapes(name)[0], name).toEqual({
        output: "[[return]]",
        alias: name,
        mode: "javascript",
        sourceKind: "host-abi",
        returnVariant: "absent",
      });
    }
    expect(vfsHostAbiShapes("ex_host_vfs_resolve_path")).toContainEqual({
      output: "out:backing",
      alias: "ex_host_vfs_resolve_path.out_backing",
      mode: "javascript",
      sourceKind: "host-abi",
      returnVariant: "absent",
    });
    for (const name of [
      "ex_host_vfs_chdir",
      "ex_host_vfs_get_cwd",
      "ex_host_vfs_resolve_path",
    ]) {
      expect(vfsHostAbiShapes(name), name).toContainEqual({
        output: "out:virtual",
        alias: `${name}.out_virtual`,
        mode: "private-native",
        sourceKind: "host-abi",
        returnVariant: "success",
      });
    }
  });

  test("splits legacy physical-path ABI returns by armed state and catalogs readdir items", async () => {
    for (const surfaceName of [
      "ex_host_fs_mkdir_recursive_result",
      "ex_host_fs_mkdtemp",
      "ex_host_fs_realpath",
    ]) {
      expect(legacyHostPathOutputShapes(surfaceName)).toEqual([
        expect.objectContaining({
          output: "[[return]]",
          alias: surfaceName,
          mode: "unarmed",
          sourceKind: "host-abi",
          returnVariant: "success",
        }),
        expect.objectContaining({
          output: "[[return]]",
          alias: surfaceName,
          mode: "unarmed",
          sourceKind: "host-abi",
          returnVariant: "error",
        }),
        expect.objectContaining({
          output: "[[return]]",
          alias: surfaceName,
          mode: "armed",
          sourceKind: "host-abi",
          returnVariant: "refused",
        }),
      ]);
    }
    expect(() => legacyHostPathOutputShapes("ex_host_fs_open")).toThrow(
      /unknown legacy Host path output/,
    );
    const { catalog } = await repositoryCatalogFixture();
    for (const surfaceName of [
      "ex_host_fs_mkdir_recursive_result",
      "ex_host_fs_mkdtemp",
      "ex_host_fs_realpath",
    ]) {
      const rows = catalog.rows.filter((row) => row.key.alias === surfaceName);
      expect(rows).toHaveLength(3);
      expect(
        rows.some(
          (row) =>
            row.key.mode === "all" && row.key.returnVariant === "default",
        ),
      ).toBe(false);
    }
    expect(
      catalog.rows.some(
        (row) =>
          row.key.alias === "ex_host_fs_readdir[]" &&
          row.key.output === "array-items" &&
          row.key.returnVariant === "success",
      ),
    ).toBe(true);
  }, 120_000);

  test("uses exactly the canonical seven-part key", () => {
    expect(JSON.parse(canonicalOutputDispositionKey(key(0)))).toEqual([
      key(0).surfaceId,
      key(0).output,
      key(0).alias,
      key(0).mode,
      key(0).sourceKind,
      key(0).returnVariant,
      key(0).contextId,
    ]);
    expect(() =>
      canonicalOutputDispositionKey({ ...key(0), surprise: true }),
    ).toThrow(/expected exact keys/);
    const missing = key(0);
    delete missing.alias;
    expect(() => canonicalOutputDispositionKey(missing)).toThrow(
      /expected exact keys/,
    );
  });

  test("accounts for every covered surface and context-bound output row", async () => {
    const { catalog, coverage } = await repositoryCatalogFixture();
    expect(catalog.outputShapeCatalogSchema).toBe(
      "ibex/capsec-output-shape-catalog/2",
    );
    expect(catalog.counts).toEqual({
      coverageSurfaces: 7_580,
      outputBearingSurfaces: 5_821,
      structuralOnlySurfaces: 1_752,
      unresolvedSurfaces: 7,
      catalogRows: 6_523,
      parameterizedBindings: 1,
      sourceInventoryRows: 6_115,
      structuredRows: 408,
    });
    expect(catalog.surfaceAccounts).toHaveLength(coverage.edges.length);
    expect(
      new Set(catalog.surfaceAccounts.map((row) => row.surfaceId)),
    ).toEqual(new Set(coverage.edges.map((edge) => edge.id)));
    expect(
      validateOutputShapeCatalogAccounts({
        coverage,
        surfaceAccounts: catalog.surfaceAccounts,
        rows: catalog.rows,
        parameterizedOutputBindings: catalog.parameterizedOutputBindings,
      }),
    ).toEqual({
      "output-bearing": 5_821,
      "structural-only": 1_752,
      unresolved: 7,
    });
    expect(
      catalog.rows.filter(
        (row) => row.discovery.kind === "source-asserted-structured-output",
      ),
    ).toHaveLength(408);
    expect(
      catalog.rows.every(
        (row) =>
          row.requiredValueProof === "live-value-observation" &&
          typeof row.key.contextId === "string",
      ),
    ).toBe(true);
    const schema = JSON.parse(
      fs.readFileSync(
        path.join(repoRoot, "capsec/schema/output-shape-catalog.schema.json"),
        "utf8",
      ),
    );
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(
      schema,
    );
    expect(validate(catalog), JSON.stringify(validate.errors)).toBe(true);
  }, 120_000);

  test("accounts source-shaped globals and source-bound callback outputs", async () => {
    const fixture = await repositoryCatalogFixture();
    const edgeByObservedKey = new Map(
      fixture.coverage.edges.map((edge) => [
        `${edge.surface.kind}:${edge.surface.name}`,
        edge,
      ]),
    );
    const accountById = new Map(
      fixture.catalog.surfaceAccounts.map((account) => [
        account.surfaceId,
        account,
      ]),
    );
    const rowsById = Map.groupBy(
      fixture.catalog.rows,
      (row) => row.key.surfaceId,
    );
    const sourceShapedGlobals = fixture.surfaces.filter(
      (surface) =>
        surface.kind === "native-op" &&
        surface.metadata?.surfaceType === "global-api" &&
        surface.metadata?.sourceKey === "shared_runtime" &&
        surface.metadata?.publicReadAccessSourceProven !== true &&
        new Set(["accessor", "callable", "data"]).has(
          surface.metadata?.valueShape,
        ),
    );
    expect(sourceShapedGlobals).toHaveLength(66);
    expect(
      countsBy(sourceShapedGlobals, (surface) => surface.metadata.valueShape),
    ).toEqual({ accessor: 44, callable: 17, data: 5 });
    for (const surface of sourceShapedGlobals) {
      const edge = edgeByObservedKey.get(surface.observedKey);
      const account = accountById.get(edge.id);
      expect(account.status, surface.observedKey).toBe("output-bearing");
      expect(account.reasonCode, surface.observedKey).toBe(
        "source-derived-public-output",
      );
      const rows = (rowsById.get(edge.id) ?? []).filter(
        (row) => row.discovery.kind === "source-inventory-surface",
      );
      expect(rows, surface.observedKey).toHaveLength(1);
      expect(rows[0].key.output, surface.observedKey).toBe(
        surface.metadata.valueShape === "callable" ? "[[return]]" : "[[value]]",
      );
    }

    for (const [surfaceName, reasonCode] of [
      [
        "__exactGeneratedImportGrantKeys.[[dynamic-table:call-result-354b628423c4-properties]]",
        "private-root-dynamic-descendant",
      ],
      [
        "global:localStorage.persistence",
        "semantic-effect-marker-no-value-slot",
      ],
    ]) {
      const edge = edgeByObservedKey.get(`native-op:${surfaceName}`);
      expect(accountById.get(edge.id), surfaceName).toMatchObject({
        status: "structural-only",
        reasonCode,
        outputKinds: [],
      });
      expect(rowsById.get(edge.id) ?? [], surfaceName).toHaveLength(0);
    }

    const callbacks = fixture.surfaces.filter(
      (surface) => surface.kind === "callback",
    );
    const producerCallbacks = callbacks.filter(
      (surface) =>
        surface.metadata?.evidenceType === "push-runtime-callback-producer",
    );
    const controlCallbacks = callbacks.filter(
      (surface) => surface.metadata?.callbackOutputBoundary === "none",
    );
    const outputCallbacks = callbacks.filter(
      (surface) =>
        surface.metadata?.callbackOutputContractSchema ===
        CALLBACK_OUTPUT_CONTRACT_SCHEMA,
    );
    expect(producerCallbacks).toHaveLength(15);
    expect(controlCallbacks).toHaveLength(9);
    expect(outputCallbacks).toHaveLength(21);
    expect(
      countsBy(callbacks, (surface) => {
        const edge = edgeByObservedKey.get(surface.observedKey);
        return accountById.get(edge.id).status;
      }),
    ).toEqual({
      "output-bearing": 21,
      "structural-only": 24,
    });
    for (const [surfaces, reasonCode] of [
      [producerCallbacks, "callback-producer-provenance"],
      [controlCallbacks, "callback-control-plane"],
    ]) {
      for (const surface of surfaces) {
        const edge = edgeByObservedKey.get(surface.observedKey);
        expect(accountById.get(edge.id)).toMatchObject({
          status: "structural-only",
          reasonCode,
          outputKinds: [],
        });
      }
    }
    for (const surface of outputCallbacks) {
      const edge = edgeByObservedKey.get(surface.observedKey);
      const account = accountById.get(edge.id);
      expect(account, surface.observedKey).toMatchObject({
        status: "output-bearing",
        reasonCode: "source-derived-callback-output",
      });
      const contracts = surface.metadata.callbackOutputContracts;
      const rows = rowsById.get(edge.id) ?? [];
      expect(rows, surface.observedKey).toHaveLength(contracts.length);
      expect(account.outputKinds, surface.observedKey).toEqual(
        [
          ...new Set(contracts.map((contract) => `callback-${contract.role}`)),
        ].sort(),
      );
      for (const contract of contracts) {
        expect(
          rows,
          `${surface.observedKey}:${contract.selector}`,
        ).toContainEqual({
          key: {
            surfaceId: edge.id,
            output: contract.selector,
            alias: surface.name,
            mode: "all",
            sourceKind: "callback",
            returnVariant: contract.returnVariant,
            contextId: "javascript.package-callback-loaded",
          },
          discovery: {
            kind: "source-inventory-surface",
            observedKeys: [surface.observedKey],
            sourceRefs: contract.sourceRefs,
          },
          requiredValueProof: "live-value-observation",
        });
      }
    }
    expect(
      outputCallbacks.flatMap(
        (surface) => surface.metadata.callbackOutputContracts,
      ),
    ).toHaveLength(74);

    const mutatedSurfaces = structuredClone(fixture.surfaces);
    const dataVictim = mutatedSurfaces.find(
      (surface) =>
        sourceShapedGlobals.some(
          (candidate) => candidate.observedKey === surface.observedKey,
        ) && surface.metadata?.valueShape === "data",
    );
    expect(dataVictim).toBeDefined();
    delete dataVictim.metadata.valueShape;
    for (const surface of mutatedSurfaces) {
      if (surface.kind !== "callback") continue;
      delete surface.metadata?.evidenceType;
      delete surface.metadata?.callbackOutputBoundary;
    }
    const mutated = buildOutputShapeCatalog({
      coverage: fixture.coverage,
      implementationRows: fixture.implementationRows,
      surfaces: mutatedSurfaces,
      repoRoot,
      liveEvidence: fixture.liveEvidence,
    });
    expect(mutated.counts).toEqual({
      ...fixture.catalog.counts,
      outputBearingSurfaces: fixture.catalog.counts.outputBearingSurfaces - 1,
      structuralOnlySurfaces:
        fixture.catalog.counts.structuralOnlySurfaces - 24,
      unresolvedSurfaces: fixture.catalog.counts.unresolvedSurfaces + 25,
      catalogRows: fixture.catalog.counts.catalogRows - 1,
      sourceInventoryRows: fixture.catalog.counts.sourceInventoryRows - 1,
    });
    const mutatedAccountById = new Map(
      mutated.surfaceAccounts.map((account) => [account.surfaceId, account]),
    );
    expect(
      mutatedAccountById.get(edgeByObservedKey.get(dataVictim.observedKey).id),
    ).toMatchObject({
      status: "unresolved",
      reasonCode: "native-global-reachability-contract-missing",
    });
    for (const surface of [...producerCallbacks, ...controlCallbacks]) {
      expect(
        mutatedAccountById.get(edgeByObservedKey.get(surface.observedKey).id),
      ).toMatchObject({
        status: "unresolved",
        reasonCode: "callback-payload-contract-missing",
      });
    }

    const missingOutputContracts = structuredClone(fixture.surfaces);
    for (const surface of missingOutputContracts) {
      if (
        surface.metadata?.callbackOutputContractSchema !==
        CALLBACK_OUTPUT_CONTRACT_SCHEMA
      ) {
        continue;
      }
      delete surface.metadata.callbackOutputContractSchema;
      delete surface.metadata.callbackOutputContracts;
    }
    const missingOutputCatalog = buildOutputShapeCatalog({
      coverage: fixture.coverage,
      implementationRows: fixture.implementationRows,
      surfaces: missingOutputContracts,
      repoRoot,
      liveEvidence: fixture.liveEvidence,
    });
    expect(missingOutputCatalog.counts).toEqual({
      ...fixture.catalog.counts,
      outputBearingSurfaces: fixture.catalog.counts.outputBearingSurfaces - 21,
      unresolvedSurfaces: fixture.catalog.counts.unresolvedSurfaces + 21,
      catalogRows: fixture.catalog.counts.catalogRows - 74,
      sourceInventoryRows: fixture.catalog.counts.sourceInventoryRows - 74,
    });
    const missingAccountById = new Map(
      missingOutputCatalog.surfaceAccounts.map((account) => [
        account.surfaceId,
        account,
      ]),
    );
    for (const surface of outputCallbacks) {
      expect(
        missingAccountById.get(edgeByObservedKey.get(surface.observedKey).id),
      ).toMatchObject({
        status: "unresolved",
        reasonCode: "callback-payload-contract-missing",
      });
    }

    for (const mutate of [
      (surface) => {
        surface.metadata.callbackOutputContractSchema = "unknown";
      },
      (surface) => {
        surface.metadata.callbackOutputContracts[0].sourceRefs = [
          "missing.cc#callback",
        ];
      },
      (surface) => {
        surface.metadata.callbackOutputContracts[0].valueShape = "no-arguments";
      },
    ]) {
      const malformedSurfaces = structuredClone(fixture.surfaces);
      const victim = malformedSurfaces.find(
        (surface) =>
          surface.metadata?.callbackOutputContractSchema ===
          CALLBACK_OUTPUT_CONTRACT_SCHEMA,
      );
      mutate(victim);
      expect(() =>
        buildOutputShapeCatalog({
          coverage: fixture.coverage,
          implementationRows: fixture.implementationRows,
          surfaces: malformedSurfaces,
          repoRoot,
          liveEvidence: fixture.liveEvidence,
        }),
      ).toThrow(/callback output contract/);
    }
  }, 120_000);

  test("source-asserts native control tokens and identity-bearing freeze outputs", async () => {
    const fixture = await repositoryCatalogFixture();
    const edgeByName = new Map(
      fixture.coverage.edges.map((edge) => [edge.surface.name, edge]),
    );
    const accountById = new Map(
      fixture.catalog.surfaceAccounts.map((account) => [
        account.surfaceId,
        account,
      ]),
    );
    const rowsById = Map.groupBy(
      fixture.catalog.rows,
      (row) => row.key.surfaceId,
    );
    const accountFor = (surfaceName) =>
      accountById.get(edgeByName.get(surfaceName).id);
    const rowsFor = (surfaceName) =>
      rowsById.get(edgeByName.get(surfaceName).id) ?? [];

    for (const [surfaceName, reasonCode] of [
      ["__exact", "reserved-native-prefix-literal"],
      ["__ibex", "reserved-native-prefix-literal"],
      ["__exactHttpWaitExecutor", "promise-executor-control"],
      ["__exactHttpAwaitWritableExecutor", "promise-executor-control"],
      ["inspector.debugger-pause", "debugger-void-control"],
      ["inspector.debugger-remove-breakpoint", "debugger-void-control"],
      ["inspector.debugger-resume", "debugger-void-control"],
    ]) {
      const account = accountFor(surfaceName);
      expect(account, surfaceName).toMatchObject({
        status: "structural-only",
        reasonCode,
        outputKinds: [],
      });
      expect(
        account.sourceRefs.some((sourceRef) => sourceRef.includes("#tokens:")),
        surfaceName,
      ).toBe(true);
      expect(rowsFor(surfaceName), surfaceName).toHaveLength(0);
    }

    expect(accountFor("inspector.cdp-listener")).toMatchObject({
      status: "structural-only",
      reasonCode: "closed-before-inspector-dispatch",
      outputKinds: [],
    });
    expect(accountFor("inspector.cdp-listener").sourceRefs).toContain(
      "src/bin/ibex/runtime.rs#Runtime::start_inspector:armed-sink-guard",
    );
    expect(rowsFor("inspector.cdp-listener")).toHaveLength(0);

    for (const symbol of [
      "ex_hermes_debugger_pause",
      "ex_hermes_debugger_remove_breakpoint",
      "ex_hermes_debugger_resume",
    ]) {
      const surfaceName =
        symbol === "ex_hermes_debugger_remove_breakpoint"
          ? "inspector.debugger-remove-breakpoint"
          : `inspector.debugger-${symbol.replace("ex_hermes_debugger_", "")}`;
      const tokenRefs = accountFor(surfaceName).sourceRefs.filter((sourceRef) =>
        sourceRef.includes(`#tokens:extern \"C\" void ${symbol}(`),
      );
      expect(tokenRefs, surfaceName).toHaveLength(2);
      expect(
        tokenRefs.some((sourceRef) =>
          sourceRef.startsWith("src/engine/hermes_runtime_debugger.cc#"),
        ),
      ).toBe(true);
      expect(
        tokenRefs.some((sourceRef) =>
          sourceRef.startsWith(
            "src/engine/hermes_runtime_platform_windows.cc#",
          ),
        ),
      ).toBe(true);
    }

    expect(accountFor("__exactCancel")).toMatchObject({
      status: "output-bearing",
      reasonCode: "source-asserted-structured-output",
      outputKinds: ["structured-output"],
    });
    expect(rowsFor("__exactCancel").map((row) => row.key)).toEqual([
      {
        surfaceId: edgeByName.get("__exactCancel").id,
        output: "[[return]]",
        alias: "nativeFetchPromise.__exactCancel",
        mode: "all",
        sourceKind: "native-op",
        returnVariant: "undefined",
        contextId: "javascript.package-call-loaded",
      },
    ]);

    expect(accountFor("__exactSetCompartmentFor")).toMatchObject({
      status: "output-bearing",
      reasonCode: "source-asserted-structured-output",
      outputKinds: ["structured-output"],
    });
    expect(rowsFor("__exactSetCompartmentFor").map((row) => row.key)).toEqual([
      {
        surfaceId: edgeByName.get("__exactSetCompartmentFor").id,
        output: "[[return]]",
        alias: "__privSetCompartmentFor",
        mode: "all",
        sourceKind: "native-op",
        returnVariant: "boolean",
        contextId: "runtime.bootstrap-native-call-loaded",
      },
    ]);

    expect(accountFor("__ibexLockedDown")).toMatchObject({
      status: "output-bearing",
      reasonCode: "source-asserted-structured-output",
    });
    expect(rowsFor("__ibexLockedDown").map((row) => row.key)).toEqual([
      expect.objectContaining({
        output: "[[value]]",
        alias: "globalThis.__ibexLockedDown",
        mode: "lockdown",
        sourceKind: "native-op",
        returnVariant: "true",
        contextId: "javascript.package-property-read-loaded",
      }),
      expect.objectContaining({
        output: "[[value]]",
        alias: "globalThis.__ibexLockedDown",
        mode: "no-lockdown",
        sourceKind: "native-op",
        returnVariant: "absent",
        contextId: "javascript.package-property-read-loaded",
      }),
    ]);

    const tamedAliases = [
      "globalThis.Function.__ibexTamed",
      "globalThis.eval.__ibexTamed",
      "Object.getPrototypeOf(function*(){}).constructor.__ibexTamed",
      "Object.getPrototypeOf(async function(){}).constructor.__ibexTamed",
    ];
    const tamedKeys = rowsFor("__ibexTamed").map((row) => row.key);
    expect(tamedKeys).toHaveLength(8);
    for (const alias of tamedAliases) {
      expect(tamedKeys).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            output: "[[value]]",
            alias,
            mode: "lockdown",
            returnVariant: "true",
          }),
          expect.objectContaining({
            output: "[[value]]",
            alias,
            mode: "no-lockdown",
            returnVariant: "absent",
          }),
        ]),
      );
    }

    for (const [surfaceName, patchPath] of [
      [
        "__exactDeepFreeze",
        "patches/hermes/0006-eval-binding-and-native-deep-freeze.patch",
      ],
      [
        "__exactNativeFreeze",
        "patches/hermes/0005-native-compartment-refinements.patch",
      ],
    ]) {
      expect(accountFor(surfaceName), surfaceName).toMatchObject({
        status: "output-bearing",
        reasonCode: "source-asserted-structured-output",
        outputKinds: ["structured-output"],
      });
      const rows = rowsFor(surfaceName);
      expect(rows, surfaceName).toHaveLength(2);
      expect(
        rows.map((row) => row.key),
        surfaceName,
      ).toEqual(
        expect.arrayContaining(
          ["primitive-sentinel", "object-sentinel"].map((mode) => ({
            surfaceId: edgeByName.get(surfaceName).id,
            output: "[[return]]",
            alias: surfaceName,
            mode,
            sourceKind: "native-op",
            returnVariant: "same-as-argument-0",
            contextId: "runtime.bootstrap-native-call-loaded",
          })),
        ),
      );
      for (const row of rows) {
        expect(row.discovery.kind).toBe("source-asserted-structured-output");
        expect(row.discovery.sourceRefs).toHaveLength(2);
        expect(
          row.discovery.sourceRefs.every((sourceRef) =>
            sourceRef.startsWith(`${patchPath}#region:`),
          ),
        ).toBe(true);
        expect(
          row.discovery.sourceRefs.some((sourceRef) =>
            sourceRef.includes("return args.getArg(0);"),
          ),
        ).toBe(true);
      }
    }

    // These private identifier spellings are source-bound to Android-only
    // process property reads. The catalog names the public property value;
    // the current target proves its absence through the separate target route.
    for (const [surfaceName, alias] of [
      ["__exactOSRelease", "process.__exactOSRelease"],
      ["__exactOSVersion", "process.__exactOSVersion"],
    ]) {
      expect(accountFor(surfaceName), surfaceName).toMatchObject({
        status: "output-bearing",
        reasonCode: "source-derived-public-output",
        outputKinds: ["public-property-read"],
      });
      expect(rowsFor(surfaceName), surfaceName).toEqual([
        {
          key: {
            surfaceId: edgeByName.get(surfaceName).id,
            output: "[[value]]",
            alias,
            mode: "all",
            sourceKind: "native-op",
            returnVariant: "default",
            contextId: "javascript.package-property-read-loaded",
          },
          discovery: {
            kind: "source-inventory-surface",
            observedKeys: [`native-op:${surfaceName}`],
            sourceRefs: expect.arrayContaining([
              `src/engine/hermes_runtime_android.cc#jsi-global-property:${alias}`,
            ]),
          },
          requiredValueProof: "live-value-observation",
        },
      ]);
    }
    expect(
      fs.readFileSync(
        path.join(
          repoRoot,
          "patches/hermes/0005-native-compartment-refinements.patch",
        ),
        "utf8",
      ),
    ).toContain("return args.getArg(0);");
    expect(
      fs.readFileSync(
        path.join(
          repoRoot,
          "patches/hermes/0006-eval-binding-and-native-deep-freeze.patch",
        ),
        "utf8",
      ),
    ).toContain("return args.getArg(0);");
    const androidRuntime = fs.readFileSync(
      path.join(repoRoot, "src/engine/hermes_runtime_android.cc"),
      "utf8",
    );
    expect(androidRuntime).toContain('"__exactOSRelease"');
    expect(androidRuntime).toContain('"__exactOSVersion"');
    expect(androidRuntime).toContain("process.setProperty(");
  }, 120_000);

  test("catalogs fixed native callback deliveries separately from ignored callback returns", async () => {
    const { catalog, coverage } = await repositoryCatalogFixture();
    const edgeByName = new Map(
      coverage.edges.map((edge) => [edge.surface.name, edge]),
    );
    const accountById = new Map(
      catalog.surfaceAccounts.map((account) => [account.surfaceId, account]),
    );
    const rowsById = Map.groupBy(catalog.rows, (row) => row.key.surfaceId);
    const rowsFor = (surfaceName) =>
      rowsById.get(edgeByName.get(surfaceName).id) ?? [];

    const deliveryCounts = new Map([
      ["__exactDispatchEvent", 4],
      ["__exactModuleEvent", 14],
      ["__exactMotionRatedPublish", 8],
      ["__exactRunOnJS", 6],
      ["__exactScheduleOnAppRuntime", 4],
    ]);
    for (const [surfaceName, count] of deliveryCounts) {
      const edge = edgeByName.get(surfaceName);
      expect(accountById.get(edge.id), surfaceName).toMatchObject({
        status: "output-bearing",
        reasonCode: "source-asserted-structured-output",
        outputKinds: ["structured-output"],
      });
      const rows = rowsFor(surfaceName);
      expect(rows, surfaceName).toHaveLength(count);
      expect(
        rows.every(
          (row) =>
            row.key.output.startsWith("callback:") &&
            row.key.sourceKind === "native-op" &&
            row.key.contextId === "javascript.package-callback-loaded" &&
            row.discovery.kind === "source-asserted-structured-output" &&
            row.requiredValueProof === "live-value-observation",
        ),
        surfaceName,
      ).toBe(true);
      expect(
        rows.some((row) => row.key.output === "[[return]]"),
        `${surfaceName} ignored callback return`,
      ).toBe(false);
      expect(
        rows.every((row) =>
          row.discovery.sourceRefs.some((sourceRef) =>
            sourceRef.includes("#tokens:"),
          ),
        ),
        surfaceName,
      ).toBe(true);
    }

    expect(rowsFor("__exactDispatchEvent").map((row) => row.key)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          output: "callback:dispatch/0",
          alias: "__exactDispatchEvent.handlerId",
          mode: "json-payload",
          returnVariant: "number",
        }),
        expect.objectContaining({
          output: "callback:dispatch/1",
          alias: "__exactDispatchEvent.payload",
          mode: "json-payload",
          returnVariant: "json-value",
        }),
        expect.objectContaining({
          output: "callback:dispatch/1",
          alias: "__exactDispatchEvent.payload",
          mode: "empty-payload",
          returnVariant: "undefined",
        }),
        expect.objectContaining({
          output: "callback:dispatch/2",
          alias: "__exactDispatchEvent.attestClockICarrier",
          mode: "attested",
          returnVariant: "call-scoped-host-function",
        }),
      ]),
    );
    expect(
      rowsFor("__exactModuleEvent").filter(
        (row) => row.key.returnVariant === "absent",
      ),
    ).toHaveLength(2);
    expect(rowsFor("__exactRunOnJS").map((row) => row.key.output)).toEqual(
      expect.arrayContaining([
        "callback:run-on-js/0",
        "callback:run-on-js/1.sourceIdentity",
        "callback:run-on-js/1.sourceSequence",
        "callback:run-on-js/1.generation",
        "callback:run-on-js/arguments[]",
      ]),
    );
    expect(
      rowsFor("__exactMotionRatedPublish").map((row) => row.key.output),
    ).toEqual(
      expect.arrayContaining([
        "callback:motion-rated-publish/0",
        "callback:motion-rated-publish/1[]",
        "callback:motion-rated-publish/2.dirtyGeneration",
        "callback:motion-rated-publish/2.sampleTimeNs",
        "callback:motion-rated-publish/2.heartbeat",
        "callback:motion-rated-publish/2.programmatic",
      ]),
    );

    const observerName = "__ibexCapsecContextObserver_";
    const observerEdge = edgeByName.get(observerName);
    expect(accountById.get(observerEdge.id)).toMatchObject({
      status: "output-bearing",
      reasonCode: "source-asserted-structured-output",
      outputKinds: ["structured-output"],
    });
    const observerSourceRefs = [
      "build.rs#IBEX_CAPSEC_CONFORMANCE_OBSERVER",
      "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#context-observer:capture-delete-before-use",
      "src/bin/ibex/engine/hermes.rs#install_capsec_context_test_observer",
      "src/engine/hermes_runtime.cc#__ibexCapsecContextObserver_",
      "src/engine/hermes_runtime.cc#ibex_test_install_capsec_context_observer",
    ];
    expect(accountById.get(observerEdge.id).sourceRefs).toEqual(
      observerSourceRefs,
    );
    expect(rowsFor(observerName).map((row) => row.key)).toEqual([
      expect.objectContaining({
        output: "[[return]]",
        alias: "__ibexCapsecContextObserver_.context",
        mode: "ephemeral-one-shot",
        returnVariant: "context-record",
        contextId: "javascript.package-call-loaded",
      }),
      expect.objectContaining({
        output: "field:principalId",
        alias: "__ibexCapsecContextObserver_.principalId",
        returnVariant: "u64-tagged-string",
      }),
      expect.objectContaining({
        output: "field:runtimeNonce",
        alias: "__ibexCapsecContextObserver_.runtimeNonce",
        returnVariant: "u64-tagged-string",
      }),
    ]);
    expect(
      rowsFor(observerName).every(
        (row) =>
          row.discovery.kind === "source-asserted-structured-output" &&
          JSON.stringify(row.discovery.sourceRefs) ===
            JSON.stringify(observerSourceRefs),
      ),
    ).toBe(true);
  }, 120_000);

  test("stages the Clock I catalog delta without self-approving reviewed policy", async () => {
    const { catalog } = await clockICandidateCatalogFixture();
    expect(catalog.catalogKeyDigest).toBe(
      "sha256-AqO2vBjPjBsgIJ3CxCj5NwyvrmZ9GEPd5JUw91teNd4",
    );
    expect(catalog.counts).toEqual({
      coverageSurfaces: 7_582,
      outputBearingSurfaces: 5_823,
      structuralOnlySurfaces: 1_752,
      unresolvedSurfaces: 7,
      catalogRows: 6_526,
      parameterizedBindings: 1,
      sourceInventoryRows: 6_118,
      structuredRows: 408,
    });

    const trackedCatalog = readRepoJson(
      "capsec/generated/output-shape-catalog.json",
    );
    const trackedKeys = new Set(
      trackedCatalog.rows.map((row) =>
        canonicalOutputDispositionKey(row.key),
      ),
    );
    const candidateKeys = new Set(
      catalog.rows.map((row) => canonicalOutputDispositionKey(row.key)),
    );
    const addedKeys = catalog.rows
      .filter(
        (row) => !trackedKeys.has(canonicalOutputDispositionKey(row.key)),
      )
      .map((row) => row.key);
    const removedKeys = trackedCatalog.rows
      .filter(
        (row) => !candidateKeys.has(canonicalOutputDispositionKey(row.key)),
      )
      .map((row) => row.key);
    expect(addedKeys).toHaveLength(4);
    expect(addedKeys).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          surfaceId:
            "surface.host.abi.ex.hermes.dispatch.event.attested.v1.1ba2uy1",
          output: "[[return]]",
        }),
        expect.objectContaining({
          surfaceId:
            "surface.host.abi.ex.hermes.dispatch.event.attested.v1.1ba2uy1",
          output: "out:receipt_json",
        }),
        expect.objectContaining({
          surfaceId: "surface.native.op.exactdispatchevent.1158ilx",
          output: "callback:dispatch/2",
        }),
        expect.objectContaining({
          surfaceId:
            "surface.native.op.ibexregisterexactdispatchevent.1i6csy6",
          output: "[[return]]",
        }),
      ]),
    );
    expect(removedKeys).toEqual([]);

    const rowsBySurfaceId = Map.groupBy(
      catalog.rows,
      (row) => row.key.surfaceId,
    );
    expect(
      rowsBySurfaceId
        .get(
          "surface.host.abi.ex.hermes.dispatch.event.attested.v1.1ba2uy1",
        )
        .map((row) => row.key),
    ).toEqual([
      {
        surfaceId:
          "surface.host.abi.ex.hermes.dispatch.event.attested.v1.1ba2uy1",
        output: "[[return]]",
        alias: "ex_hermes_dispatch_event_attested_v1",
        mode: "all",
        sourceKind: "host-abi",
        returnVariant: "default",
        contextId: "host.private-native-call-initialized",
      },
      {
        surfaceId:
          "surface.host.abi.ex.hermes.dispatch.event.attested.v1.1ba2uy1",
        output: "out:receipt_json",
        alias: "ex_hermes_dispatch_event_attested_v1",
        mode: "all",
        sourceKind: "host-abi",
        returnVariant: "default",
        contextId: "host.private-native-call-initialized",
      },
    ]);
    expect(
      rowsBySurfaceId
        .get("surface.native.op.exactdispatchevent.1158ilx")
        .map((row) => row.key),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          output: "callback:dispatch/2",
          alias: "__exactDispatchEvent.attestClockICarrier",
          mode: "attested",
          returnVariant: "call-scoped-host-function",
        }),
      ]),
    );
    expect(
      rowsBySurfaceId.get(
        "surface.native.op.ibexregisterexactdispatchevent.1i6csy6",
      ),
    ).toEqual([
      expect.objectContaining({
        key: {
          surfaceId:
            "surface.native.op.ibexregisterexactdispatchevent.1i6csy6",
          output: "[[return]]",
          alias: "__ibexRegisterExactDispatchEvent",
          mode: "all",
          sourceKind: "native-op",
          returnVariant: "default",
          contextId: "runtime.bootstrap-native-call-loaded",
        },
      }),
    ]);
    expect(
      rowsBySurfaceId
        .get("surface.native.op.global.exact.invokehostasync.0b92itq")
        .map((row) => row.key),
    ).toEqual([
      {
        surfaceId: "surface.native.op.global.exact.invokehostasync.0b92itq",
        output: "[[return]]",
        alias: "global:exact.invokeHostAsync",
        mode: "all",
        sourceKind: "native-op",
        returnVariant: "default",
        contextId: "runtime.bootstrap-native-call-loaded",
      },
    ]);

    const policy = readRepoJson(
      "capsec/registry/output-disposition-policy.json",
    );
    const evidence = readRepoJson(
      "capsec/registry/output-disposition-evidence.json",
    );
    expect(() =>
      buildOutputDispositionDataset({ catalog, policy, evidence }),
    ).toThrow(
      "output disposition policy has unreviewed catalog fields: expected sha256-jAtRyrk5Ntw_ls-C58L7X0Gi9e0iPg2TY_Ru31ypldU, discovered sha256-AqO2vBjPjBsgIJ3CxCj5NwyvrmZ9GEPd5JUw91teNd4",
    );
  }, 120_000);

  test("derives every host ABI account and output row only from its signature contract", async () => {
    const { catalog, coverage, surfaces } = await repositoryCatalogFixture();
    const sourceByObservedKey = new Map(
      surfaces.map((surface) => [surface.observedKey, surface]),
    );
    const accountBySurfaceId = new Map(
      catalog.surfaceAccounts.map((account) => [account.surfaceId, account]),
    );
    const rowsBySurfaceId = Map.groupBy(
      catalog.rows,
      (row) => row.key.surfaceId,
    );
    const hostEdges = coverage.edges.filter(
      (edge) => edge.surface.kind === "host-abi",
    );
    const derivedAccounts = hostEdges.map((edge) => {
      const surface = sourceByObservedKey.get(`host-abi:${edge.surface.name}`);
      const derived = deriveHostAbiOutputCatalogAccount(surface);
      const membershipComplete =
        derived.status === "output-bearing" &&
        derived.membershipUnresolved.length === 0;
      const sourceRefs = [
        ...new Set(
          surface.metadata.outputContracts.map(
            (contract) => contract.sourceRef,
          ),
        ),
      ].sort();
      const outputKinds = membershipComplete
        ? derived.outputChannels.map((channel) => channel.selector)
        : [];
      const account = accountBySurfaceId.get(edge.id);
      expect(Object.keys(account).sort()).toEqual([
        "outputKinds",
        "reasonCode",
        "sourceRefs",
        "status",
        "surfaceId",
      ]);
      expect(account).toEqual({
        surfaceId: edge.id,
        status: derived.status,
        reasonCode: derived.reasonCode,
        sourceRefs,
        outputKinds,
      });

      const allRows = rowsBySurfaceId.get(edge.id) ?? [];
      const rows = allRows.filter(
        (row) => row.discovery.kind === "source-inventory-surface",
      );
      const hasReplacementRecipe = [
        "ex_host_fs_mkdir_recursive_result",
        "ex_host_fs_mkdtemp",
        "ex_host_fs_realpath",
      ].includes(edge.surface.name);
      const expectedChannels =
        membershipComplete && !hasReplacementRecipe
          ? derived.outputChannels
          : [];
      expect(rows).toHaveLength(expectedChannels.length);
      if (!membershipComplete) expect(allRows).toHaveLength(0);
      for (const channel of expectedChannels) {
        expect(rows).toContainEqual({
          key: {
            surfaceId: edge.id,
            output: channel.selector,
            alias: edge.surface.name,
            mode: "all",
            sourceKind: "host-abi",
            returnVariant: "default",
            contextId: "host.private-native-call-initialized",
          },
          discovery: {
            kind: "source-inventory-surface",
            observedKeys: [surface.observedKey],
            sourceRefs: channel.sourceRefs,
          },
          requiredValueProof: "live-value-observation",
        });
      }
      return derived;
    });

    expect(hostEdges).toHaveLength(365);
    expect(countsBy(derivedAccounts, (account) => account.status)).toEqual({
      "output-bearing": 313,
      "structural-only": 52,
    });
    expect(
      derivedAccounts
        .filter((account) => account.status === "output-bearing")
        .flatMap((account) => account.outputChannels),
    ).toHaveLength(591);
    expect(
      derivedAccounts.some(
        (account) =>
          account.status === "unresolved" && account.outputChannels.length > 0,
      ),
    ).toBe(false);

    const vfsResolveEdge = hostEdges.find(
      (edge) => edge.surface.name === "ex_host_vfs_resolve_path",
    );
    expect(
      rowsBySurfaceId.get(vfsResolveEdge.id).map((row) => row.key),
    ).toContainEqual({
      surfaceId: vfsResolveEdge.id,
      output: "out:backing",
      alias: "ex_host_vfs_resolve_path",
      mode: "all",
      sourceKind: "host-abi",
      returnVariant: "default",
      contextId: "host.private-native-call-initialized",
    });
  }, 120_000);

  test("derives output membership independently of classification, capability, and rationale", async () => {
    const fixture = await repositoryCatalogFixture();
    const mutatedCoverage = structuredClone(fixture.coverage);
    for (const edge of mutatedCoverage.edges) {
      edge.classification = "test-policy-mutation";
      edge.cap = "test:mutated";
      edge.rationale = "test-only policy mutation";
      delete edge.effects;
    }
    const mutated = buildOutputShapeCatalog({
      coverage: mutatedCoverage,
      implementationRows: fixture.implementationRows,
      surfaces: fixture.surfaces,
      repoRoot,
      liveEvidence: fixture.liveEvidence,
    });
    expect(mutated.surfaceAccounts).toEqual(fixture.catalog.surfaceAccounts);
    expect(mutated.rows).toEqual(fixture.catalog.rows);
    expect(mutated.contexts).toEqual(fixture.catalog.contexts);
    expect(mutated.catalogKeyDigest).toBe(fixture.catalog.catalogKeyDigest);
    expect(mutated.counts).toEqual(fixture.catalog.counts);
  }, 120_000);

  test("blocks verified promotion while any source surface is unresolved", async () => {
    const fixture = await repositoryCatalogFixture();
    expect(() =>
      buildOutputShapeCatalog({
        coverage: fixture.coverage,
        implementationRows: fixture.implementationRows,
        surfaces: fixture.surfaces,
        repoRoot,
        liveEvidence: {
          status: "verified",
          requiredExecutor: OUTPUT_DISPOSITION_EVIDENCE_EXECUTOR,
          sourceRevision: "a".repeat(40),
          sourceTreeDigest: `sha256-${"B".repeat(43)}`,
          target: {
            triple: "aarch64-apple-darwin",
            features: ["native-lockdown"],
          },
          engine: {
            engineArtifactPath: "/exact/hermes",
            kind: "hermes",
            binaryDigest: `sha256-${"A".repeat(43)}`,
            object: { platform: "apple", volume: "dev:1", file: "ino:2" },
            targetArchitecture: "aarch64",
            structuralFeatures: ["native-lockdown"],
          },
        },
      }),
    ).toThrow(/verified output catalog has 7 unresolved surface accounts/);
  }, 120_000);

  test("rejects incomplete accounts and registrar-only value evidence", async () => {
    const { catalog, coverage } = await repositoryCatalogFixture();
    expect(() =>
      validateOutputShapeCatalogAccounts({
        coverage,
        surfaceAccounts: catalog.surfaceAccounts.slice(1),
        rows: catalog.rows,
      }),
    ).toThrow(/not set-equal to coverage/);
    expect(() => validateOutputValueProofKind("compiled-registrar")).toThrow(
      /registrar presence cannot satisfy a value observation/,
    );
    expect(validateOutputValueProofKind("loaded-engine-descriptor")).toBe(
      "loaded-engine-descriptor",
    );
  });

  test("selects context from source reachability instead of policy", () => {
    expect(
      defaultContextIdForCatalogRow(
        { mode: "all", sourceKind: "builtin", output: "[[binding]]" },
        { kind: "builtin", metadata: { importReachability: "public" } },
      ),
    ).toBe("javascript.package-import-fresh");
    expect(
      defaultContextIdForCatalogRow(
        { mode: "private-native", sourceKind: "host-abi", output: "out:value" },
        { kind: "host-abi", metadata: {} },
      ),
    ).toBe("host.private-native-call-initialized");
    expect(
      defaultContextIdForCatalogRow(
        {
          mode: "all",
          sourceKind: "native-op",
          output: "[[return]]",
        },
        {
          kind: "native-op",
          name: "global:process.umask",
          metadata: {
            publicReadAccessSourceProven: true,
            valueShape: "callable",
          },
        },
      ),
    ).toBe("javascript.package-call-loaded");
    expect(
      defaultContextIdForCatalogRow(
        {
          mode: "all",
          sourceKind: "native-op",
          output: "[[return]]",
        },
        {
          kind: "native-op",
          name: "__exactAccess",
          metadata: {
            memberKinds: ["native-root"],
            publicInvocation: { kind: "native-global-function" },
          },
        },
      ),
    ).toBe("runtime.bootstrap-native-call-loaded");
  });

  test("keeps the reviewed policy pinned while source catalog review is pending", async () => {
    const { catalog: discoveredCatalog } = await repositoryCatalogFixture();
    const catalog = readRepoJson("capsec/generated/output-shape-catalog.json");
    const policy = readRepoJson(
      "capsec/registry/output-disposition-policy.json",
    );
    const evidence = readRepoJson(
      "capsec/registry/output-disposition-evidence.json",
    );
    expect(discoveredCatalog.catalogKeyDigest).toBe(
      "sha256-2kQloHOzzRZdyFN40Erf8696yjEf6AiM97JMXZ6fCKQ",
    );
    expect(() =>
      buildOutputDispositionDataset({
        catalog: discoveredCatalog,
        policy,
        evidence,
      }),
    ).toThrow(
      "output disposition policy has unreviewed catalog fields: expected sha256-jAtRyrk5Ntw_ls-C58L7X0Gi9e0iPg2TY_Ru31ypldU, discovered sha256-2kQloHOzzRZdyFN40Erf8696yjEf6AiM97JMXZ6fCKQ",
    );
    const dataset = buildOutputDispositionDataset({
      catalog,
      policy,
      evidence,
    });

    expect(policy.outputDispositionPolicySchema).toBe(
      "ibex/capsec-output-disposition-policy/2",
    );
    expect(policy.catalogKeyDigest).toBe(
      "sha256-jAtRyrk5Ntw_ls-C58L7X0Gi9e0iPg2TY_Ru31ypldU",
    );
    expect(policy.catalogKeyDigest).toBe(catalog.catalogKeyDigest);
    expect(policy.overrides).toHaveLength(370);
    expect(
      new Set(
        policy.overrides.map((row) => canonicalOutputDispositionKey(row.key)),
      ).size,
    ).toBe(policy.overrides.length);
    const catalogKeys = new Set(
      catalog.rows.map((row) => canonicalOutputDispositionKey(row.key)),
    );
    expect(
      policy.overrides.every((row) =>
        catalogKeys.has(canonicalOutputDispositionKey(row.key)),
      ),
    ).toBe(true);
    expect(countsBy(policy.overrides, (row) => row.disposition)).toEqual({
      absent: 153,
      closed: 28,
      "non-path": 41,
      "private-native-path": 5,
      refused: 12,
      "reserved-constant": 1,
      "synthetic-source-id": 21,
      "typed-logical": 23,
      "virtual-absolute": 74,
      "virtual-basename": 4,
      "virtual-relative": 8,
    });
    expect(dataset.outputDispositionDatasetSchema).toBe(
      "ibex/capsec-output-dispositions/2",
    );
    expect(dataset.counts).toEqual({
      catalogRows: 6_522,
      dispositionRows: 6_522,
      byDisposition: {
        absent: 153,
        closed: 28,
        "non-path": 6_193,
        "private-native-path": 5,
        refused: 12,
        "reserved-constant": 1,
        "synthetic-source-id": 21,
        "typed-logical": 23,
        "virtual-absolute": 74,
        "virtual-basename": 4,
        "virtual-relative": 8,
      },
    });

    // The legacy v1 policy had 494 explicit overrides. The exact-key join
    // retained 227; 143 source-reviewed v2 corrections remain after removing
    // four overrides for the now-private original-Promise carrier.
    expect({
      legacyExplicitOverrides: 494,
      exactKeyRetained: 227,
      exactKeyDropped: 267,
      reviewedV2Corrections: 143,
      currentOverrides: policy.overrides.length,
      droppedByCatalogAccount: {
        "output-bearing-key-changed": 14,
        "structural-only": 137,
        unresolved: 116,
      },
      droppedBySourceKind: {
        builtin: 5,
        cli: 114,
        "host-abi": 66,
        loader: 2,
        "native-op": 59,
        startup: 21,
      },
    }).toEqual({
      legacyExplicitOverrides: 494,
      exactKeyRetained: 227,
      exactKeyDropped: 267,
      reviewedV2Corrections: 143,
      currentOverrides: 370,
      droppedByCatalogAccount: {
        "output-bearing-key-changed": 14,
        "structural-only": 137,
        unresolved: 116,
      },
      droppedBySourceKind: {
        builtin: 5,
        cli: 114,
        "host-abi": 66,
        loader: 2,
        "native-op": 59,
        startup: 21,
      },
    });

    for (const [schemaPath, document] of [
      ["capsec/schema/output-disposition-policy.schema.json", policy],
      ["capsec/schema/output-disposition-evidence.schema.json", evidence],
      ["capsec/schema/output-dispositions.schema.json", dataset],
    ]) {
      const validate = new Ajv2020({ allErrors: true, strict: true }).compile(
        readRepoJson(schemaPath),
      );
      expect(
        validate(document),
        `${schemaPath}: ${JSON.stringify(validate.errors)}`,
      ).toBe(true);
    }
  }, 120_000);

  test("pins the reviewed umask closure and devNull property-read migration", async () => {
    const { catalog } = await repositoryCatalogFixture();
    const policy = readRepoJson(
      "capsec/registry/output-disposition-policy.json",
    );
    const bySurfaceId = new Map(
      policy.overrides.map((row) => [row.key.surfaceId, row]),
    );
    for (const surfaceId of [
      "surface.builtin.export.exact.process.umask.02n7ymy",
      "surface.native.op.global.process.umask.1axcurx",
    ]) {
      expect(bySurfaceId.get(surfaceId)).toMatchObject({
        key: {
          output: "[[return]]",
          contextId: "javascript.package-call-loaded",
        },
        disposition: "closed",
        expectation: {
          outcome: "throw",
          normalizedValue: "ERR_ACCESS_DENIED",
        },
      });
    }
    for (const surfaceId of [
      "surface.builtin.export.exact.process.umask.10xxy9j",
      "surface.native.op.global.process.umask.1lvkowq",
    ]) {
      expect(bySurfaceId.get(surfaceId)).toMatchObject({
        key: {
          output: "[[value]]",
          contextId: "javascript.package-property-read-loaded",
        },
        disposition: "absent",
        expectation: { outcome: "absent", normalizedValue: "absent" },
      });
    }

    const devNull = bySurfaceId.get(
      "surface.builtin.export.node.os.devnull.1evbi49",
    );
    expect(devNull).toMatchObject({
      key: {
        output: "[[value]]",
        contextId: "javascript.package-property-read-loaded",
      },
      disposition: "reserved-constant",
      expectation: { outcome: "return", normalizedValue: "/dev/null" },
      rationale:
        "The universal constant names no machine-specific host path and is not a mounted node.",
    });
    const devNullCatalogRow = catalog.rows.find(
      (row) => row.key.surfaceId === devNull.key.surfaceId,
    );
    expect(devNullCatalogRow).toMatchObject({
      key: devNull.key,
      discovery: { kind: "source-inventory-surface" },
      requiredValueProof: "live-value-observation",
    });
  });

  test("binds the sealed __exactCompatModes root to an exact absent value override", async () => {
    const { catalog } = await repositoryCatalogFixture();
    const policy = readRepoJson(
      "capsec/registry/output-disposition-policy.json",
    );
    const rootManifest = readRepoJson(
      "capsec/generated/root-global-disposition-manifest.json",
    );
    const manifestRow = rootManifest.rows.find(
      (row) => row.observedKey === "native-op:__exactCompatModes",
    );
    expect(manifestRow).toMatchObject({
      installId: "root-global.exactcompatmodes.d1e1fe28017b1402",
      registryEdgeId: "surface.native.op.exactcompatmodes.0hzhmrx",
      branch: {
        sourceRefs: [
          "src/engine/hermes_runtime.cc#jsi-global:__exactCompatModes",
        ],
      },
      disposition: "sealed",
      liveExpectation: "absent",
      nativeImplementation: true,
    });

    const override = policy.overrides.find(
      (row) => row.key.surfaceId === manifestRow.registryEdgeId,
    );
    expect(override).toEqual({
      key: {
        surfaceId: "surface.native.op.exactcompatmodes.0hzhmrx",
        output: "[[value]]",
        alias: "__exactCompatModes",
        mode: "all",
        sourceKind: "native-op",
        returnVariant: "default",
        contextId: "javascript.package-property-read-loaded",
      },
      disposition: "absent",
      expectation: { outcome: "absent", normalizedValue: "absent" },
      rationale:
        "The generated sealed-root manifest row root-global.exactcompatmodes.d1e1fe28017b1402 binds native-op:__exactCompatModes to src/engine/hermes_runtime.cc#jsi-global:__exactCompatModes with disposition sealed and liveExpectation absent; the loaded package-property read must observe this exact value key absent.",
    });
    expect(
      catalog.rows.find(
        (row) =>
          canonicalOutputDispositionKey(row.key) ===
          canonicalOutputDispositionKey(override.key),
      ),
    ).toMatchObject({ requiredValueProof: "live-value-observation" });
  });

  test("binds the sealed process IPC bootstrap carrier to exact absent value overrides", async () => {
    const { catalog } = await repositoryCatalogFixture();
    const rootManifest = readRepoJson(
      "capsec/generated/root-global-disposition-manifest.json",
    );
    const policy = readRepoJson(
      "capsec/registry/output-disposition-policy.json",
    );
    const expectedRows = [
      {
        observedKey: "native-op:__exactProcessIpcBootstrap",
        installId: "root-global.exactprocessipcbootstrap.f5ef7efbc7e86864",
        surfaceId: "surface.native.op.exactprocessipcbootstrap.1f8twb6",
        sourceRef:
          "src/engine/hermes_runtime.cc#jsi-global:__exactProcessIpcBootstrap",
      },
      {
        observedKey: "native-op:__exactProcessIpcBootstrap.close",
        installId:
          "root-global.exactprocessipcbootstrap.close.8979e0d4ab05815a",
        surfaceId:
          "surface.native.op.exactprocessipcbootstrap.close.1ap2eh4",
        sourceRef:
          "src/engine/hermes_runtime.cc#jsi-global:__exactProcessIpcBootstrap.close",
        output: "[[return]]",
        contextId: "runtime.bootstrap-native-call-loaded",
        rationale:
          "The generated sealed-root manifest row root-global.exactprocessipcbootstrap.close.8979e0d4ab05815a binds native-op:__exactProcessIpcBootstrap.close to src/engine/hermes_runtime.cc#jsi-global:__exactProcessIpcBootstrap.close with disposition sealed and liveExpectation absent; the loaded bootstrap lookup must observe this exact callable absent before any invocation.",
      },
      {
        observedKey: "native-op:__exactProcessIpcBootstrap.fd",
        installId:
          "root-global.exactprocessipcbootstrap.fd.f0572c00634b3d42",
        surfaceId: "surface.native.op.exactprocessipcbootstrap.fd.1yvjieu",
        sourceRef:
          "src/engine/hermes_runtime.cc#jsi-global:__exactProcessIpcBootstrap.fd",
      },
      {
        observedKey: "native-op:__exactProcessIpcBootstrap.serialization",
        installId:
          "root-global.exactprocessipcbootstrap.serialization.efa6a07e051d0374",
        surfaceId:
          "surface.native.op.exactprocessipcbootstrap.serialization.1vtmt9s",
        sourceRef:
          "src/engine/hermes_runtime.cc#jsi-global:__exactProcessIpcBootstrap.serialization",
      },
    ];

    expect(
      rootManifest.rows.filter((row) =>
        row.observedKey.startsWith("native-op:__exactProcessIpcBootstrap"),
      ),
    ).toHaveLength(expectedRows.length);
    for (const expected of expectedRows) {
      const manifestRow = rootManifest.rows.find(
        (row) => row.observedKey === expected.observedKey,
      );
      expect(manifestRow).toMatchObject({
        installId: expected.installId,
        registryEdgeId: expected.surfaceId,
        branch: { sourceRefs: [expected.sourceRef] },
        disposition: "sealed",
        liveExpectation: "absent",
        nativeImplementation: true,
      });

      const matchingOverrides = policy.overrides.filter(
        (row) => row.key.surfaceId === manifestRow.registryEdgeId,
      );
      expect(matchingOverrides).toHaveLength(1);
      const alias = expected.observedKey.slice("native-op:".length);
      const override = matchingOverrides[0];
      expect(override).toEqual({
        key: {
          surfaceId: expected.surfaceId,
          output: expected.output ?? "[[value]]",
          alias,
          mode: "all",
          sourceKind: "native-op",
          returnVariant: "default",
          contextId:
            expected.contextId ?? "javascript.package-property-read-loaded",
        },
        disposition: "absent",
        expectation: { outcome: "absent", normalizedValue: "absent" },
        rationale:
          expected.rationale ??
          `The generated sealed-root manifest row ${expected.installId} binds ${expected.observedKey} to ${expected.sourceRef} with disposition sealed and liveExpectation absent; the loaded package-property read must observe this exact value key absent.`,
      });
      expect(
        catalog.rows.find(
          (row) =>
            canonicalOutputDispositionKey(row.key) ===
            canonicalOutputDispositionKey(override.key),
        ),
      ).toMatchObject({ requiredValueProof: "live-value-observation" });
    }
  }, 120_000);

  test("rejects every v1 policy/evidence compatibility shape", () => {
    const { catalog, policy, evidence } = fixture();
    const legacyPolicy = structuredClone(policy);
    legacyPolicy.outputDispositionPolicySchema =
      "ibex/capsec-output-disposition-policy/1";
    expect(() =>
      buildOutputDispositionDataset({
        catalog,
        policy: legacyPolicy,
        evidence,
      }),
    ).toThrow(/policy is not a complete v2 document/);

    const legacyEvidence = structuredClone(evidence);
    legacyEvidence.outputDispositionEvidenceSchema =
      "ibex/capsec-output-disposition-evidence/1";
    expect(() =>
      buildOutputDispositionDataset({
        catalog,
        policy,
        evidence: legacyEvidence,
      }),
    ).toThrow(/evidence is not a complete v3 document/);
  });

  test("generates all eleven dispositions and an explicit unpromotable state", () => {
    const { catalog, policy, evidence } = fixture();
    const dataset = buildOutputDispositionDataset({
      catalog,
      policy,
      evidence,
    });
    expect(dataset.dispositions).toEqual(OUTPUT_DISPOSITIONS);
    expect(Object.values(dataset.counts.byDisposition)).toEqual(
      Array(OUTPUT_DISPOSITIONS.length).fill(1),
    );
    expect(dataset.evidence).toEqual({
      status: "unpromotable",
      reason: evidence.reason,
    });
    expect(renderOutputDispositionMarkdown(dataset)).toContain(
      "Evidence status: **unpromotable**",
    );
    expect(renderOutputDispositionMarkdown(dataset)).toContain(evidence.reason);
  });

  test("confines private native path markers to authenticated Host-ABI rows", () => {
    const input = fixture();
    const privateIndex = OUTPUT_DISPOSITIONS.indexOf("private-native-path");
    const privateOverride = input.policy.overrides[privateIndex];
    expect(privateOverride).toMatchObject({
      disposition: "private-native-path",
      expectation: {
        outcome: "return",
        normalizedValue: "private-native-path",
      },
      key: {
        sourceKind: "host-abi",
        contextId: "host.private-native-call-initialized",
      },
    });
    expect(() => buildOutputDispositionDataset(input)).not.toThrow();

    for (const mutation of [
      (row) => {
        row.key.sourceKind = "native-op";
      },
      (row) => {
        row.key.contextId = "javascript.package-call-loaded";
      },
      (row) => {
        row.expectation.normalizedValue = "non-path";
      },
    ]) {
      const changed = fixture();
      mutation(changed.policy.overrides[privateIndex]);
      expect(() => buildOutputDispositionDataset(changed)).toThrow(
        /private-native-path requires an authenticated Host-ABI return marker/,
      );
    }

    const mismatched = fixture();
    mismatched.policy.overrides[privateIndex].disposition = "non-path";
    expect(() => buildOutputDispositionDataset(mismatched)).toThrow(
      /private-native-path marker requires the matching disposition/,
    );
  });

  test("binds catalog discovery to the exact evidence state and engine identity", () => {
    const { catalog, policy, evidence } = fixture();

    const wrongExecutor = structuredClone(evidence);
    wrongExecutor.requiredExecutor = "different-runner";
    expect(() =>
      buildOutputDispositionDataset({
        catalog,
        policy,
        evidence: wrongExecutor,
      }),
    ).toThrow(/does not bind the loaded-engine evidence state/);

    const wrongReason = structuredClone(evidence);
    wrongReason.reason = "different unpromotable reason";
    expect(() =>
      buildOutputDispositionDataset({ catalog, policy, evidence: wrongReason }),
    ).toThrow(/does not bind the unpromotable evidence reason/);

    const unpromotable = buildOutputDispositionDataset({
      catalog,
      policy,
      evidence,
    });
    const verified = verifiedEvidence(unpromotable);
    catalog.discovery = {
      status: "verified",
      method:
        "source-inventory-surface-accounting-plus-source-asserted-structured-outputs",
      requiredExecutor: verified.requiredExecutor,
      sourceRevision: verified.sourceRevision,
      sourceTreeDigest: verified.sourceTreeDigest,
      target: structuredClone(verified.target),
      engine: structuredClone(verified.engine),
    };
    const verifiedDataset = buildOutputDispositionDataset({
      catalog,
      policy,
      evidence: verified,
    });
    expect(verifiedDataset.evidence).toEqual({
      status: "verified",
      sourceRevision: verified.sourceRevision,
      sourceTreeDigest: verified.sourceTreeDigest,
      conformanceRunner: verified.conformanceRunner,
      target: verified.target,
      engine: verified.engine,
    });
    for (const [schemaPath, document] of [
      ["capsec/schema/output-shape-catalog.schema.json", catalog],
      ["capsec/schema/output-dispositions.schema.json", verifiedDataset],
    ]) {
      const validate = new Ajv2020({ allErrors: true, strict: true }).compile(
        readRepoJson(schemaPath),
      );
      expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
    }

    const wrongRevision = structuredClone(verified);
    wrongRevision.sourceRevision = "b".repeat(40);
    expect(() =>
      buildOutputDispositionDataset({
        catalog,
        policy,
        evidence: wrongRevision,
      }),
    ).toThrow(/does not bind the verified engine identity/);

    const wrongDigest = structuredClone(verified);
    wrongDigest.engine.binaryDigest = `sha256-${"C".repeat(43)}`;
    expect(() =>
      buildOutputDispositionDataset({
        catalog,
        policy,
        evidence: wrongDigest,
      }),
    ).toThrow(/does not bind the verified engine identity/);
  });

  test("pins source-discovered catalog membership before applying defaults", () => {
    const { catalog, policy, evidence } = fixture();
    catalog.rows.push(catalogRow(20));
    catalog.surfaceAccounts.push({
      surfaceId: key(20).surfaceId,
      status: "output-bearing",
      reasonCode: "test-output",
      sourceRefs: ["test.js#20"],
      outputKinds: ["test-output"],
    });
    catalog.counts.coverageSurfaces += 1;
    catalog.counts.outputBearingSurfaces += 1;
    catalog.counts.catalogRows += 1;
    catalog.counts.sourceInventoryRows += 1;
    catalog.catalogKeyDigest = outputShapeCatalogKeyDigest(catalog.rows);
    expect(() =>
      buildOutputDispositionDataset({ catalog, policy, evidence }),
    ).toThrow(/unreviewed catalog fields/);
  });

  test("rejects duplicate, uncovered, and unknown rows bidirectionally", () => {
    const { catalog, policy, evidence } = fixture();
    const dataset = buildOutputDispositionDataset({
      catalog,
      policy,
      evidence,
    });
    expect(() =>
      validateOutputDispositionJoin(catalog.rows, [
        ...dataset.rows,
        structuredClone(dataset.rows[0]),
      ]),
    ).toThrow(/duplicate canonical output key/);
    expect(() =>
      validateOutputDispositionJoin(catalog.rows, dataset.rows.slice(1)),
    ).toThrow(/uncovered=/);
    expect(() =>
      validateOutputDispositionJoin(catalog.rows.slice(1), dataset.rows),
    ).toThrow(/unknown=/);
  });

  test("requires exact loaded-engine membership and values", () => {
    const { catalog, policy, evidence } = fixture();
    const dataset = buildOutputDispositionDataset({
      catalog,
      policy,
      evidence,
    });
    const verified = verifiedEvidence(dataset);
    const validateEvidenceSchema = new Ajv2020({
      allErrors: true,
      strict: true,
    }).compile(
      readRepoJson("capsec/schema/output-disposition-evidence.schema.json"),
    );
    expect(
      validateEvidenceSchema(verified),
      JSON.stringify(validateEvidenceSchema.errors),
    ).toBe(true);
    expect(validateOutputDispositionEvidence(dataset.rows, verified)).toEqual({
      status: "verified",
      sourceRevision: verified.sourceRevision,
      sourceTreeDigest: verified.sourceTreeDigest,
      target: verified.target,
      engine: verified.engine,
      conformanceRunner: verified.conformanceRunner,
    });

    const wrongExecutor = structuredClone(verified);
    wrongExecutor.requiredExecutor =
      "ibex-public-surface-harness/output-shape-sweep-v2";
    expect(validateEvidenceSchema(wrongExecutor)).toBe(false);
    expect(() =>
      validateOutputDispositionEvidence(dataset.rows, wrongExecutor),
    ).toThrow(/evidence is not a complete v3 document/);

    const missing = structuredClone(verified);
    missing.observations.pop();
    expect(() =>
      validateOutputDispositionEvidence(dataset.rows, missing),
    ).toThrow(/evidence is incomplete/);

    const mismatch = structuredClone(verified);
    mismatch.observations[0].observation.normalizedValue = "host-path";
    expect(() =>
      validateOutputDispositionEvidence(dataset.rows, mismatch),
    ).toThrow(/value mismatch/);

    const duplicate = structuredClone(verified);
    duplicate.observations.push(structuredClone(duplicate.observations[0]));
    expect(() =>
      validateOutputDispositionEvidence(dataset.rows, duplicate),
    ).toThrow(/duplicate canonical output key/);

    const unidentified = structuredClone(verified);
    delete unidentified.engine;
    expect(() =>
      validateOutputDispositionEvidence(dataset.rows, unidentified),
    ).toThrow(/expected exact keys/);

    const registrarOnly = structuredClone(verified);
    registrarOnly.observations[0].proofKind = "compiled-registrar";
    expect(() =>
      validateOutputDispositionEvidence(dataset.rows, registrarOnly),
    ).toThrow(/registrar presence cannot satisfy a value observation/);

    const missingProof = structuredClone(verified);
    delete missingProof.observations[0].proofKind;
    expect(() =>
      validateOutputDispositionEvidence(dataset.rows, missingProof),
    ).toThrow(/unsupported live value proof kind/);

    const missingExecutor = structuredClone(verified);
    delete missingExecutor.requiredExecutor;
    expect(() =>
      validateOutputDispositionEvidence(dataset.rows, missingExecutor),
    ).toThrow(/evidence is not a complete v3 document/);
  });

  test("does not allow observations to hide inside unpromotable evidence", () => {
    const { catalog, policy, evidence } = fixture();
    const dataset = buildOutputDispositionDataset({
      catalog,
      policy,
      evidence,
    });
    evidence.observations.push({
      key: structuredClone(dataset.rows[0].key),
      disposition: dataset.rows[0].disposition,
      proofKind: "loaded-engine-return-record",
      observation: structuredClone(dataset.rows[0].expectation),
    });
    expect(() =>
      validateOutputDispositionEvidence(dataset.rows, evidence),
    ).toThrow(/must not carry observations/);
    evidence.observations = [];
    evidence.sourceRevision = "a".repeat(40);
    expect(() =>
      validateOutputDispositionEvidence(dataset.rows, evidence),
    ).toThrow(/expected exact keys/);
  });

  test("keeps the tracked evidence document permanently unpromotable", () => {
    const { catalog, policy, evidence } = fixture();
    expect(
      validateTrackedOutputDispositionEvidenceSentinel(evidence),
    ).toEqual({
      status: "unpromotable",
      reason: evidence.reason,
    });
    const dataset = buildOutputDispositionDataset({
      catalog,
      policy,
      evidence,
    });
    expect(() =>
      validateTrackedOutputDispositionEvidenceSentinel(
        verifiedEvidence(dataset),
      ),
    ).toThrow();
  });
});
