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
  buildOutputDispositionDataset,
  buildOutputShapeCatalog,
  canonicalOutputDispositionKey,
  defaultContextIdForCatalogRow,
  modulePackageRootShapes,
  outputExecutionContextsForRows,
  outputShapeCatalogKeyDigest,
  renderOutputDispositionMarkdown,
  resolverRecordShapes,
  validateOutputDispositionEvidence,
  validateOutputDispositionJoin,
  validateOutputShapeCatalogAccounts,
  validateOutputValueProofKind,
  vfsHostAbiShapes,
} from "./capsec-output-dispositions.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";

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
  return {
    surfaceId: `surface.test.output.${index}`,
    output: index % 2 === 0 ? "[[return]]" : `field:value${index}`,
    alias: `test.alias.${index}`,
    mode: index % 3 === 0 ? "file" : "all",
    sourceKind: index % 2 === 0 ? "builtin" : "native-op",
    returnVariant: "default",
    contextId: "javascript.package-call-loaded",
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
      requiredExecutor: "test-runner",
      reason: "test evidence is intentionally absent",
    },
    contexts: outputExecutionContextsForRows(rows),
    surfaceAccounts,
    catalogKeyDigest: outputShapeCatalogKeyDigest(rows),
    counts: {
      coverageSurfaces: rows.length,
      outputBearingSurfaces: rows.length,
      structuralOnlySurfaces: 0,
      unresolvedSurfaces: 0,
      catalogRows: rows.length,
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
      "ibex/capsec-output-disposition-evidence/2",
    profile: "ibex/capsec/1",
    status: "unpromotable",
    requiredExecutor: "test-runner",
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

function verifiedEvidence(dataset) {
  return {
    outputDispositionEvidenceSchema:
      "ibex/capsec-output-disposition-evidence/2",
    profile: "ibex/capsec/1",
    status: "verified",
    requiredExecutor: "test-runner",
    sourceRevision: "a".repeat(40),
    engineBinaryDigest: `sha256-${"A".repeat(43)}`,
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

  test("accounts for all 7,177 source surfaces and emits only 5,231 actual output rows", async () => {
    const { catalog, coverage } = await repositoryCatalogFixture();
    expect(catalog.outputShapeCatalogSchema).toBe(
      "ibex/capsec-output-shape-catalog/2",
    );
    expect(catalog.counts).toEqual({
      coverageSurfaces: 7_177,
      outputBearingSurfaces: 4_916,
      structuralOnlySurfaces: 1_352,
      unresolvedSurfaces: 909,
      catalogRows: 5_231,
      sourceInventoryRows: 4_888,
      structuredRows: 343,
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
      }),
    ).toEqual({
      "output-bearing": 4_916,
      "structural-only": 1_352,
      unresolved: 909,
    });
    expect(
      catalog.rows.filter(
        (row) => row.discovery.kind === "source-asserted-structured-output",
      ),
    ).toHaveLength(343);
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
  }, 30_000);

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
  }, 30_000);

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
          requiredExecutor: "test-runner",
          sourceRevision: "a".repeat(40),
          engineBinaryDigest: `sha256-${"A".repeat(43)}`,
        },
      }),
    ).toThrow(/verified output catalog has 909 unresolved surface accounts/);
  }, 30_000);

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

  test("migrates the reviewed policy to exact v2 keys with deterministic accounting", async () => {
    const { catalog } = await repositoryCatalogFixture();
    const policy = readRepoJson(
      "capsec/registry/output-disposition-policy.json",
    );
    const evidence = readRepoJson(
      "capsec/registry/output-disposition-evidence.json",
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
      "sha256-ycYwUGDv598Zq4FEHapGAe1DeT-kq-bSezmbkMBcAdY",
    );
    expect(policy.catalogKeyDigest).toBe(catalog.catalogKeyDigest);
    expect(policy.overrides).toHaveLength(232);
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
      absent: 34,
      closed: 28,
      "non-path": 34,
      refused: 9,
      "reserved-constant": 1,
      "synthetic-source-id": 21,
      "typed-logical": 23,
      "virtual-absolute": 71,
      "virtual-basename": 3,
      "virtual-relative": 8,
    });
    expect(dataset.outputDispositionDatasetSchema).toBe(
      "ibex/capsec-output-dispositions/2",
    );
    expect(dataset.counts).toEqual({
      catalogRows: 5_231,
      dispositionRows: 5_231,
      byDisposition: {
        absent: 34,
        closed: 28,
        "non-path": 5_033,
        refused: 9,
        "reserved-constant": 1,
        "synthetic-source-id": 21,
        "typed-logical": 23,
        "virtual-absolute": 71,
        "virtual-basename": 3,
        "virtual-relative": 8,
      },
    });

    // The legacy v1 policy had 494 explicit overrides. The exact-key join
    // retained 227; five source-reviewed v2 corrections were then added.
    expect({
      legacyExplicitOverrides: 494,
      exactKeyRetained: 227,
      exactKeyDropped: 267,
      reviewedV2Corrections: 5,
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
      reviewedV2Corrections: 5,
      currentOverrides: 232,
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
  }, 30_000);

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
    ).toThrow(/evidence is not a complete v2 document/);
  });

  test("generates all ten dispositions and an explicit unpromotable state", () => {
    const { catalog, policy, evidence } = fixture();
    const dataset = buildOutputDispositionDataset({
      catalog,
      policy,
      evidence,
    });
    expect(dataset.dispositions).toEqual(OUTPUT_DISPOSITIONS);
    expect(Object.values(dataset.counts.byDisposition)).toEqual(
      Array(10).fill(1),
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
      engineBinaryDigest: verified.engineBinaryDigest,
    };
    expect(
      buildOutputDispositionDataset({ catalog, policy, evidence: verified })
        .evidence,
    ).toEqual({
      status: "verified",
      sourceRevision: verified.sourceRevision,
      engineBinaryDigest: verified.engineBinaryDigest,
    });

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
    wrongDigest.engineBinaryDigest = `sha256-${"B".repeat(43)}`;
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
    expect(validateOutputDispositionEvidence(dataset.rows, verified)).toEqual({
      status: "verified",
      sourceRevision: verified.sourceRevision,
      engineBinaryDigest: verified.engineBinaryDigest,
    });

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
    delete unidentified.engineBinaryDigest;
    expect(() =>
      validateOutputDispositionEvidence(dataset.rows, unidentified),
    ).toThrow(/lacks exact source and engine identity/);

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
    ).toThrow(/evidence is not a complete v2 document/);
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
    ).toThrow(/cannot claim engine identity/);
  });
});
