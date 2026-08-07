// @ref LLP 0021#wp0-semantic-contract — the frozen contract must fail closed on
// wildcard/untyped/unknown authority, duplicate JSON keys, or an unreconciled
// legacy capability bit.
// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — WP1
// promotes the generated production inventory into the checked contract.

import { afterAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
  armedTargetPathEntries,
  assertCanonicalKeyedSets,
  assertCanonicalSets,
  assertDigestProjectionContract,
  assertDigestVectorBindings,
  assertLegacyReconciliationCoverage,
  assertLegacyReconciliationDestinations,
  assertOccurrencePrincipalContext,
  assertNoDuplicateJsonKeys,
  capsecRoot,
  canonicalSetOrder,
  canonicalIpAddress,
  canonicalJson,
  compareAuthorityContainment,
  computeDomainDigest,
  invalidFixtureNames,
  loadAndValidateContract as loadAndValidateContractUncached,
  parseJsonStrict,
  portableDiagnosticPath,
  readArtifactSourceFoundationDocuments,
  renderLegacyReconciliation,
  runContractCheck,
  validateArmedSnapshotSemantics,
  validateImplementationManifestSemantics,
  validateInvalidFixture,
  validateOccurrenceSemantics,
  validateTargetLogicalPaths,
} from "./capsec-contract.mjs";
import { parseCapabilityBitDefinitions } from "./generate-capability-bits.mjs";

function validateImplementationMutation(
  contract,
  implementation,
  targetCells = contract.targetCells,
) {
  return validateImplementationManifestSemantics(implementation, {
    coverage: contract.coverage,
    targetCells,
    definitions: contract.definitions,
    rules: contract.rules,
  });
}

function git(repositoryRoot, ...args) {
  return execFileSync("/usr/bin/git", args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      PATH: "/usr/bin:/bin",
      LC_ALL: "C",
      LANG: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
    },
  }).trim();
}

function writeJson(filePath, value, { canonical = false } = {}) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(
    filePath,
    canonical
      ? `${canonicalJson(value)}\n`
      : `${JSON.stringify(value, null, 2)}\n`,
  );
}

let invalidFixtureContract;
let validatedContract;

// The production corpus now embeds thousands of source-derived rows and two
// digest bundles. Validate that immutable baseline once; every mutation test
// clones the specific value it changes.
function loadAndValidateContract() {
  validatedContract ??= loadAndValidateContractUncached();
  return validatedContract;
}

afterAll(() => {
  invalidFixtureContract = undefined;
  validatedContract = undefined;
});

describe("LLP 0021 capsec contract", () => {
  test("report v3 schemas require one scope binding and explicit uncertified accounting", () => {
    const schemas = [
      fs.readFileSync(
        path.join(capsecRoot, "schema/conformance-report.schema.json"),
      ),
      fs.readFileSync(
        path.join(capsecRoot, "../schemas/capsec-conformance-report-v2.schema.json"),
      ),
    ].map((bytes, index) => parseJsonStrict(bytes, `report schema ${index}`));
    for (const schema of schemas) {
      expect(schema.properties.conformanceSchema.const).toBe(
        "ibex/capsec-conformance/3",
      );
      expect(schema.properties.bindings.required).toContain("scopeDigest");
      expect(schema.properties.bindings.properties.scopeDigest).toBeDefined();
      expect(schema.properties.bindings.additionalProperties).toBe(false);
      const summary = schema.properties.summary.$ref
        ? schema.$defs.summary
        : schema.properties.summary;
      expect(summary.required).toContain("uncertifiedCells");
      expect(summary.properties.uncertifiedCells).toEqual({
        type: "integer",
        minimum: 0,
      });
      const cell = schema.properties.cells.items.$ref
        ? schema.$defs.cell
        : schema.properties.cells.items;
      expect(cell.properties.status.enum).toContain("uncertified");
    }
  });

  test("reads both foundation documents from one authenticated artifact-source revision", () => {
    const repositoryRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "ibex-capsec-foundation-"),
    );
    try {
      git(repositoryRoot, "init", "-b", "main");
      git(repositoryRoot, "config", "user.name", "CapSec Test");
      git(repositoryRoot, "config", "user.email", "capsec@example.invalid");

      const catalogPath = path.join(
        repositoryRoot,
        "schemas/portable-engine-promotion-admission-catalog-v1.json",
      );
      const advertisementsPath = path.join(
        repositoryRoot,
        "capsec/generated/target-advertisements.json",
      );
      const attestationsPath = path.join(
        repositoryRoot,
        "capsec/conformance/target-attestations.json",
      );
      const disabledCatalog = {
        admissionPath:
          "schemas/portable-engine-promotion-admission-catalog-v1.json",
        admissions: [],
        enabled: false,
        schema: "ibex/portable-engine-promotion-admission-catalog/2",
      };
      const sourceAdvertisements = {
        targetAdvertisementSchema: "ibex/capsec-target-advertisements/1",
        profile: "ibex/capsec/1",
        targetCellsRawContentDigest: `sha256-${"A".repeat(43)}`,
        advertisements: [],
      };
      const sourceAttestations = {
        targetAttestationSchema: "ibex/capsec-target-attestations/1",
        profile: "ibex/capsec/1",
        attestations: [],
      };
      writeJson(catalogPath, disabledCatalog, { canonical: true });
      writeJson(advertisementsPath, sourceAdvertisements);
      writeJson(attestationsPath, sourceAttestations);
      git(repositoryRoot, "add", ".");
      git(repositoryRoot, "commit", "-m", "artifact source");
      const sourceRevision = git(repositoryRoot, "rev-parse", "HEAD");
      const sourceTreeObjectId = git(
        repositoryRoot,
        "rev-parse",
        "HEAD^{tree}",
      );

      const admission = {
        schema: "ibex/portable-engine-promotion-admission/2",
        sourceRevision,
        sourceTreeObjectId,
        topology: "github-pull-request-merge/direct-single-commit-topic/1",
        target: {
          triple: "aarch64-apple-darwin",
          features: ["native-lockdown"],
        },
        portableArtifactId: computeDomainDigest("test:artifact", {
          id: "portable",
        }),
        admittedScopeDigest: computeDomainDigest("test:scope", {
          id: "scope",
        }),
        artifacts: [],
        admissionDigest: "",
      };
      admission.admissionDigest = computeDomainDigest(
        "ibex.portable-engine-promotion-admission.v2",
        admission,
        ["admissionDigest"],
      );
      writeJson(
        catalogPath,
        {
          ...disabledCatalog,
          admissions: [admission],
          enabled: true,
        },
        { canonical: true },
      );
      writeJson(advertisementsPath, {
        targetAdvertisementSchema: "ibex/capsec-target-advertisements/3",
        profile: "ibex/capsec/1",
        advertisements: [{ scopeDigest: admission.admittedScopeDigest }],
      });
      writeJson(attestationsPath, {
        targetAttestationSchema: "ibex/capsec-target-attestations/3",
        profile: "ibex/capsec/1",
        attestations: [{ scopeDigest: admission.admittedScopeDigest }],
      });
      git(repositoryRoot, "add", ".");
      git(repositoryRoot, "commit", "-m", "publish scoped documents");

      expect(readArtifactSourceFoundationDocuments(repositoryRoot)).toEqual({
        sourceRevision,
        targetAdvertisements: sourceAdvertisements,
        targetAttestations: sourceAttestations,
      });

      admission.admissionDigest = computeDomainDigest("test:tampered", {
        id: "admission",
      });
      writeJson(
        catalogPath,
        {
          ...disabledCatalog,
          admissions: [admission],
          enabled: true,
        },
        { canonical: true },
      );
      git(repositoryRoot, "add", catalogPath);
      git(repositoryRoot, "commit", "-m", "tamper admission digest");
      expect(() =>
        readArtifactSourceFoundationDocuments(repositoryRoot),
      ).toThrow(/admission digest does not bind/);
    } finally {
      fs.rmSync(repositoryRoot, { recursive: true, force: true });
    }
  });

  test("all schemas, registries, examples, and generated output validate", () => {
    const contract = loadAndValidateContract();
    const counts = runContractCheck();
    expect(counts.capabilityDefinitions).toBe(41);
    expect(counts.legacyCapabilities).toBe(57);
    expect(counts.schemas).toBe(contract.manifest.schemas.length);
    expect(counts.selectorExamples).toBe(19);
    expect(counts.occurrenceExamples).toBe(19);
    expect(counts.decisionSets).toBe(1);
    expect(counts.containmentVectors).toBe(23);
    expect(counts.digestVectors).toBe(5);
    expect(counts.invalidFixtures).toBe(30);
    expect(counts.coverageEdges).toBeGreaterThan(500);
    expect(counts.targetCells).toBeGreaterThanOrEqual(counts.coverageEdges);
    expect(renderLegacyReconciliation(contract)).toContain(
      "This table covers all 57 entries in `src/host/capability_bits.rs`.",
    );
  }, 30_000);

  for (const fixture of invalidFixtureNames()) {
    test(`rejects ${fixture}`, () => {
      invalidFixtureContract ??= loadAndValidateContract();
      expect(() =>
        validateInvalidFixture(fixture, invalidFixtureContract),
      ).toThrow();
    });
  }

  test("duplicate detection compares decoded JSON keys", () => {
    expect(() =>
      assertNoDuplicateJsonKeys('{"a":1,"\\u0061":2}', "inline"),
    ).toThrow(/duplicate JSON object key "a"/);
  });

  test("strict byte parsing rejects duplicate decoded JSON keys", () => {
    expect(() =>
      parseJsonStrict(Buffer.from('{"a":1,"\\u0061":2}', "utf8"), "inline"),
    ).toThrow(/inline: duplicate JSON object key "a"/);
    expect(parseJsonStrict(Buffer.from('{"a":1}', "utf8"), "inline")).toEqual({
      a: 1,
    });
  });

  test("invalid fixture errors use manifest-relative canonical paths", () => {
    const contract = loadAndValidateContract();
    expect(() => validateInvalidFixture("duplicate-key.json", contract)).toThrow(
      /^testdata\/invalid\/duplicate-key\.json: duplicate JSON object key "cap"/,
    );
  }, 30_000);

  test("strict JSON diagnostics use portable repository paths", () => {
    expect(
      portableDiagnosticPath("capsec\\testdata\\invalid\\duplicate-key.json"),
    ).toBe("capsec/testdata/invalid/duplicate-key.json");
  });

  test("schema-declared sets must use canonical order", () => {
    const contract = loadAndValidateContract();
    const value = structuredClone(
      contract.containment.vectors.find((row) => row.id === "fetch.narrow-sets")
        .parent,
    );
    value.resource.peerClasses.reverse();
    expect(() =>
      assertCanonicalSets(
        value,
        new Set(contract.rules.digestContract.setKeys),
        "mutated",
      ),
    ).toThrow(/canonical lexical order/);
  });

  test("semantic set order compares canonical UTF-8 bytes, not UTF-16 units", () => {
    const setKeys = new Set(["examples"]);
    expect(() =>
      assertCanonicalSets({ examples: ["\uE000", "𐀀"] }, setKeys),
    ).not.toThrow();
    expect(() =>
      assertCanonicalSets({ examples: ["𐀀", "\uE000"] }, setKeys),
    ).toThrow(/canonical lexical order/);
    expect(canonicalSetOrder(["pkg@𐀀", "pkg@\uE000"])).toEqual([
      "pkg@\uE000",
      "pkg@𐀀",
    ]);
  });

  test("IPv4-mapped IPv6 has one embedded-IPv4 canonical form", () => {
    expect(() => canonicalIpAddress("::ffff:169.254.169.254")).toThrow(
      /expected 169\.254\.169\.254/,
    );
    expect(() => canonicalIpAddress("::ffff:a9fe:a9fe")).toThrow(
      /expected 169\.254\.169\.254/,
    );
    expect(canonicalIpAddress("169.254.169.254")).toBe(4);
    expect(canonicalIpAddress("::ffff:0:7f00:1")).toBe(6);
  });

  test("shared non-integer JCS vectors match ECMAScript bytes", () => {
    const vectors = fs.readFileSync(
      path.join(
        capsecRoot,
        "../crates/capsec-semantics/tests/fixtures/jcs-number-vectors.tsv",
      ),
      "utf8",
    );
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    for (const line of vectors.split("\n")) {
      if (!line || line.startsWith("#")) continue;
      const [bits, expected] = line.split("\t");
      view.setBigUint64(0, BigInt(`0x${bits}`), false);
      expect(canonicalJson(view.getFloat64(0, false))).toBe(expected);
    }
  });

  test("keyed sets must use their declared composite order", () => {
    const contract = loadAndValidateContract();
    const mutated = structuredClone(contract.targetCells);
    mutated.cells.reverse();
    const documents = new Map([["ibex/capsec-target-cells/1", mutated]]);
    const specification = contract.rules.digestContract.keyedSets.filter(
      (row) => row.schema === "ibex/capsec-target-cells/1",
    );
    expect(() => assertCanonicalKeyedSets(documents, specification)).toThrow(
      /canonical lexical order/,
    );
  });

  test("implementation observed keys exactly join coverage surface identities", () => {
    const contract = loadAndValidateContract();
    const mutated = structuredClone(contract.implementation);
    mutated.surfaces[0].observedKey = "builtin:not-the-covered-surface";
    expect(() => validateImplementationMutation(contract, mutated)).toThrow(
      /observedKey .* does not match coverage surface/,
    );
  });

  test("definition coverage is derived exactly from effects, closed edges, and lifecycle", () => {
    const contract = loadAndValidateContract();
    const covered = contract.implementation.definitionCoverage.find(
      (row) => row.disposition === "covered" && row.edgeIds.length > 0,
    );
    const closed = contract.implementation.definitionCoverage.find(
      (row) => row.disposition === "closed" && row.edgeIds.length > 0,
    );

    const wrongEdges = structuredClone(contract.implementation);
    wrongEdges.definitionCoverage.find(
      (row) => row.definitionId === covered.definitionId,
    ).edgeIds = [];
    expect(() => validateImplementationMutation(contract, wrongEdges)).toThrow(
      /edgeIds disagree with production coverage/,
    );

    const wrongDisposition = structuredClone(contract.implementation);
    wrongDisposition.definitionCoverage.find(
      (row) => row.definitionId === covered.definitionId,
    ).disposition = "unsupported";
    expect(() =>
      validateImplementationMutation(contract, wrongDisposition),
    ).toThrow(/disposition unsupported disagrees with expected covered/);

    const wrongClosedEdges = structuredClone(contract.implementation);
    wrongClosedEdges.definitionCoverage.find(
      (row) => row.definitionId === closed.definitionId,
    ).edgeIds = [];
    expect(() =>
      validateImplementationMutation(contract, wrongClosedEdges),
    ).toThrow(/edgeIds disagree with production coverage/);

    const wrongAbsentDisposition = structuredClone(contract.implementation);
    wrongAbsentDisposition.definitionCoverage.find(
      (row) => row.disposition === "absent",
    ).disposition = "unsupported";
    expect(() =>
      validateImplementationMutation(contract, wrongAbsentDisposition),
    ).toThrow(/disposition unsupported disagrees with expected absent/);
  });

  test("every implementation count is recomputed from authoritative manifest data", () => {
    const contract = loadAndValidateContract();
    for (const count of [
      "observedReferences",
      "logicalSurfaces",
      "enforcementBranches",
      "coverageEdges",
      "targetCells",
    ]) {
      const mutated = structuredClone(contract.implementation);
      mutated.counts[count] += 1;
      expect(() => validateImplementationMutation(contract, mutated)).toThrow(
        /implementation counts disagree with manifest data/,
      );
    }
  });

  test("production registry contains no conditional-unrefined edges", () => {
    const contract = loadAndValidateContract();
    expect(
      contract.coverage.edges.filter(
        (edge) => edge.effectMode === "conditional-unrefined",
      ),
    ).toEqual([]);
  });

  test("target cells reject unknown and wrong-target implementation branches", () => {
    const contract = loadAndValidateContract();
    const sourceCell = contract.targetCells.cells.find(
      (cell) => cell.implementationBranchIds.length > 0,
    );
    expect(sourceCell).toBeDefined();

    const unknownBranch = structuredClone(contract.targetCells);
    unknownBranch.cells.find(
      (cell) => cell.edgeId === sourceCell.edgeId,
    ).implementationBranchIds = ["invented.implementation.branch"];
    expect(() =>
      validateImplementationMutation(
        contract,
        contract.implementation,
        unknownBranch,
      ),
    ).toThrow(/unknown implementation branch/);

    const wrongTargetCase = contract.targetCells.cells
      .map((cell) => {
        const selected = new Set(cell.implementationBranchIds);
        const wrongBranch = contract.implementation.surfaces.find(
          (row) => row.edgeId === cell.edgeId && !selected.has(row.branchId),
        );
        return wrongBranch ? { cell, wrongBranch } : null;
      })
      .find(Boolean);
    expect(wrongTargetCase).toBeDefined();
    const wrongTarget = structuredClone(contract.targetCells);
    wrongTarget.cells.find(
      (cell) => cell.edgeId === wrongTargetCase.cell.edgeId,
    ).implementationBranchIds = [wrongTargetCase.wrongBranch.branchId];
    expect(() =>
      validateImplementationMutation(
        contract,
        contract.implementation,
        wrongTarget,
      ),
    ).toThrow(
      /implementation branches do not match source-derived target selection/,
    );
  });

  test("target promotion requires every selected branch fixture obligation", () => {
    const contract = loadAndValidateContract();
    const sourceCell = contract.targetCells.cells.find((cell) => {
      const edge = contract.coverage.edges.find(
        (row) => row.id === cell.edgeId,
      );
      return (
        cell.implementationBranchIds.length > 0 &&
        edge.effectMode !== "conditional-unrefined"
      );
    });
    expect(sourceCell).toBeDefined();
    const edge = contract.coverage.edges.find(
      (row) => row.id === sourceCell.edgeId,
    );
    const expectedDisposition =
      edge.classification === "effects"
        ? "enforced"
        : edge.classification === "closed"
          ? "closed"
          : "non-capability";
    const obligations = [
      ...new Set(
        sourceCell.implementationBranchIds.flatMap(
          (branchId) =>
            contract.implementation.surfaces.find(
              (row) => row.branchId === branchId,
            ).fixtureObligations,
        ),
      ),
    ].sort();
    expect(obligations.length).toBeGreaterThan(0);

    const missingObligation = structuredClone(contract.targetCells);
    const promoted = missingObligation.cells.find(
      (cell) => cell.edgeId === sourceCell.edgeId,
    );
    promoted.disposition = expectedDisposition;
    promoted.fixtures = obligations.slice(0, -1);
    expect(() =>
      validateImplementationMutation(
        contract,
        contract.implementation,
        missingObligation,
      ),
    ).toThrow(
      /fixtures do not exactly cover selected implementation branch obligations/,
    );
  });

  test("implementation manifests cannot co-author weaker fixture obligations", () => {
    const contract = loadAndValidateContract();
    const sourceCell = contract.targetCells.cells.find((cell) => {
      const edge = contract.coverage.edges.find(
        (row) => row.id === cell.edgeId,
      );
      return (
        cell.implementationBranchIds.length > 0 &&
        edge.effectMode !== "conditional-unrefined"
      );
    });
    expect(sourceCell).toBeDefined();
    const edge = contract.coverage.edges.find(
      (row) => row.id === sourceCell.edgeId,
    );
    const mutatedImplementation = structuredClone(contract.implementation);
    const mutatedCells = structuredClone(contract.targetCells);
    const branchId = sourceCell.implementationBranchIds[0];
    mutatedImplementation.surfaces.find(
      (row) => row.branchId === branchId,
    ).fixtureObligations = [`${branchId}.invented`];
    const promoted = mutatedCells.cells.find(
      (cell) => cell.edgeId === sourceCell.edgeId,
    );
    promoted.disposition =
      edge.classification === "effects"
        ? "enforced"
        : edge.classification === "closed"
          ? "closed"
          : "non-capability";
    promoted.fixtures = [`${branchId}.invented`];
    expect(() =>
      validateImplementationMutation(
        contract,
        mutatedImplementation,
        mutatedCells,
      ),
    ).toThrow(
      /fixture obligations disagree with semantic edge and branch identity/,
    );
  });

  test("unsupported stubs and invented absence evidence cannot promote", () => {
    const contract = loadAndValidateContract();
    const sourceCell = contract.targetCells.cells.find((cell) => {
      const edge = contract.coverage.edges.find(
        (row) => row.id === cell.edgeId,
      );
      return (
        cell.implementationBranchIds.length > 0 &&
        edge.effectMode !== "conditional-unrefined"
      );
    });
    expect(sourceCell).toBeDefined();
    const edge = contract.coverage.edges.find(
      (row) => row.id === sourceCell.edgeId,
    );
    const unsupportedImplementation = structuredClone(contract.implementation);
    const unsupportedCells = structuredClone(contract.targetCells);
    unsupportedImplementation.surfaces.find(
      (row) => row.branchId === sourceCell.implementationBranchIds[0],
    ).implementationDisposition = "unsupported-stub";
    const promoted = unsupportedCells.cells.find(
      (cell) => cell.edgeId === sourceCell.edgeId,
    );
    promoted.disposition =
      edge.classification === "effects"
        ? "enforced"
        : edge.classification === "closed"
          ? "closed"
          : "non-capability";
    promoted.fixtures = [
      ...new Set(
        sourceCell.implementationBranchIds.flatMap(
          (branchId) =>
            contract.implementation.surfaces.find(
              (row) => row.branchId === branchId,
            ).fixtureObligations,
        ),
      ),
    ].sort();
    expect(() =>
      validateImplementationMutation(
        contract,
        unsupportedImplementation,
        unsupportedCells,
      ),
    ).toThrow(/unsupported implementation branches cannot be promoted/);

    const branchless = contract.targetCells.cells.find(
      (cell) => cell.implementationBranchIds.length === 0,
    );
    expect(branchless).toBeDefined();
    const inventedAbsence = structuredClone(contract.targetCells);
    const absent = inventedAbsence.cells.find(
      (cell) => cell.edgeId === branchless.edgeId,
    );
    absent.disposition = "absent";
    absent.fixtures = ["invented.absence.evidence"];
    expect(() =>
      validateImplementationMutation(
        contract,
        contract.implementation,
        inventedAbsence,
      ),
    ).toThrow(/requires exact target-bound absence evidence/);
  });

  test("implementation source, fixture, and output sets require canonical order", () => {
    const contract = loadAndValidateContract();

    const reversedSources = structuredClone(contract.implementation);
    reversedSources.surfaces
      .find((row) => row.sourceRefs.length > 1)
      .sourceRefs.reverse();
    expect(() =>
      validateImplementationMutation(contract, reversedSources),
    ).toThrow(/sourceRefs: expected canonical lexical order/);

    const reversedFixtures = structuredClone(contract.implementation);
    reversedFixtures.surfaces
      .find((row) => row.fixtureObligations.length > 1)
      .fixtureObligations.reverse();
    expect(() =>
      validateImplementationMutation(contract, reversedFixtures),
    ).toThrow(/fixtureObligations: expected canonical lexical order/);

    const reversedOutputs = structuredClone(contract.implementation);
    reversedOutputs.outputs.reverse();
    expect(() =>
      validateImplementationMutation(contract, reversedOutputs),
    ).toThrow(/implementation outputs: expected canonical lexical order/);

    const duplicateOutput = structuredClone(contract.implementation);
    duplicateOutput.outputs[1].path = duplicateOutput.outputs[0].path;
    expect(() =>
      validateImplementationMutation(contract, duplicateOutput),
    ).toThrow(/implementation outputs: duplicate/);

    const missingOutput = structuredClone(contract.implementation);
    missingOutput.outputs.pop();
    expect(() =>
      validateImplementationMutation(contract, missingOutput),
    ).toThrow(/exact digest-bound output catalog/);

    const wrongKind = structuredClone(contract.implementation);
    wrongKind.outputs[0].kind = "markdown";
    expect(() => validateImplementationMutation(contract, wrongKind)).toThrow(
      /exact digest-bound output catalog/,
    );
  });

  test("the aggregate registry bundle binds the self-excluded implementation manifest", () => {
    const contract = loadAndValidateContract();
    expect(
      contract.implementation.outputs.some(
        (row) => row.path === "capsec/generated/implementation-manifest.json",
      ),
    ).toBe(false);
    expect(
      contract.registryDigestBundle.members.find(
        (row) => row.logicalName === "implementation-manifest",
      )?.document,
    ).toEqual(contract.implementation);
    expect(
      contract.ajv.getSchema(
        "https://ibex.dev/capsec/generated/capsec-registry-ids.schema.json",
      ),
    ).toBeDefined();
  });

  test("implementation output paths are schema-safe and runtime-contained", () => {
    const contract = loadAndValidateContract();
    const validate = contract.ajv.getSchema(
      "https://ibex.dev/capsec/schema/implementation-manifest.schema.json",
    );
    for (const unsafePath of [
      "/tmp/ibex-output",
      "../outside.json",
      "capsec/../outside.json",
      "C:\\outside.json",
    ]) {
      const mutated = structuredClone(contract.implementation);
      mutated.outputs[0].path = unsafePath;
      expect(validate(mutated)).toBe(false);
    }

    for (const unsafePath of ["/tmp/ibex-output", "../outside.json"]) {
      const mutated = structuredClone(contract.implementation);
      mutated.outputs[0].path = unsafePath;
      expect(() => validateImplementationMutation(contract, mutated)).toThrow(
        /repository-relative without traversal/,
      );
    }
  });

  test("conformance fixture plans accept capability action IDs", () => {
    const contract = loadAndValidateContract();
    const validate = contract.ajv.getSchema(
      "https://ibex.dev/capsec/schema/conformance-report.schema.json#/$defs/fixturePlan",
    );
    const plan = {
      fixtureId: "surface.test.main.allow",
      edgeIds: ["surface.test"],
      implementationBranchIds: ["surface.test.main"],
      enforcementBranchIds: ["surface.test.main"],
      terminalObservedKey: "native-op:test",
      classification: "effects",
      actionIds: ["fs:read", "fs:write"],
      expectedObservation: {
        kind: "enforcement-branch",
        branchId: "surface.test.main",
      },
    };
    expect(validate(plan)).toBe(true);
    expect(validate({ ...plan, actionIds: ["fs-read"] })).toBe(false);
  });

  test("armed graph and protected-object joins fail closed", () => {
    const contract = loadAndValidateContract();
    const missingGuard = structuredClone(contract.armed);
    missingGuard.protectedObjects.pop();
    expect(() =>
      validateArmedSnapshotSemantics(missingGuard, "mutated armed"),
    ).toThrow(/protected object roles are incomplete/);

    const badOwner = structuredClone(contract.armed);
    badOwner.rootBindings[0].owner.name = "other-package";
    expect(() =>
      validateArmedSnapshotSemantics(badOwner, "mutated armed"),
    ).toThrow(/package owner is not a graph node/);
  });

  test("armed entry kind identity and mode are one closed authenticated tuple", () => {
    const contract = loadAndValidateContract();
    const invalidEntries = [
      { kind: "repl", identity: "ibex:stdin", mode: "interactive" },
      { kind: "repl", identity: "ibex:repl", mode: "program" },
      { kind: "stdin", identity: "ibex:stdin", mode: "transcript" },
      { kind: "eval", identity: "ibex:eval", mode: "program" },
      {
        kind: "file",
        identity: "file:///project/../private.js",
        mode: "program",
      },
      {
        kind: "file",
        identity: "file:///project/%2Fetc/passwd",
        mode: "program",
      },
    ];
    for (const entry of invalidEntries) {
      const mutated = structuredClone(contract.armed);
      mutated.entry = entry;
      expect(() =>
        validateArmedSnapshotSemantics(mutated, "mutated armed"),
      ).toThrow(/entry.*inconsistent/);
    }

    for (const entry of [
      { kind: "stdin", identity: "ibex:stdin", mode: "program" },
      { kind: "repl", identity: "ibex:repl", mode: "interactive" },
      { kind: "eval", identity: "ibex:eval", mode: "one-shot" },
      {
        kind: "file",
        identity: "file:///project/a%20b.js",
        mode: "program",
      },
    ]) {
      const mutated = structuredClone(contract.armed);
      mutated.entry = entry;
      expect(() =>
        validateArmedSnapshotSemantics(mutated, "mutated armed"),
      ).not.toThrow();
    }
  });

  test("decision-set context cannot be contradicted by one effect", () => {
    const contract = loadAndValidateContract();
    const value = structuredClone(contract.effectSet);
    value.effects[0].stage = "requested";
    const validate = contract.ajv.getSchema(
      "https://ibex.dev/capsec/schema/effect.schema.json",
    );
    expect(validate(value)).toBe(false);
  });

  test("actor and effect owner cannot escape the constrained principal intersection", () => {
    const contract = loadAndValidateContract();
    const occurrence = structuredClone(
      contract.occurrenceExamples.occurrences[0],
    );
    const duplicated = structuredClone(occurrence);
    duplicated.constrainedPrincipals.push(
      structuredClone(duplicated.constrainedPrincipals[0]),
    );
    expect(() =>
      assertOccurrencePrincipalContext(
        duplicated,
        contract.rules,
        "mutated occurrence",
      ),
    ).toThrow(/duplicate/);

    const omittedActor = structuredClone(occurrence);
    omittedActor.actor = {
      kind: "package",
      name: "other-lib",
      integrity: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      locator: "other-lib@1.0.0",
    };
    expect(() =>
      assertOccurrencePrincipalContext(
        omittedActor,
        contract.rules,
        "mutated occurrence",
      ),
    ).toThrow(/actor.*absent/);

    omittedActor.actor = structuredClone(
      contract.rules.principalSemantics.transparentFramePrincipal,
    );
    expect(() =>
      assertOccurrencePrincipalContext(
        omittedActor,
        contract.rules,
        "mutated occurrence",
      ),
    ).not.toThrow();
  });

  test("later-stage occurrence facts cannot appear speculatively", () => {
    const contract = loadAndValidateContract();
    const candidate = structuredClone(
      contract.occurrenceExamples.occurrences.find(
        (occurrence) =>
          occurrence.resource.kind === "network-occurrence" &&
          occurrence.stage === "candidate",
      ),
    );
    candidate.stage = "requested";
    expect(() =>
      validateOccurrenceSemantics(
        candidate,
        contract.definitionsById,
        contract.rules,
        "mutated occurrence",
      ),
    ).toThrow(/speculative candidates|speculative selectedCandidate/);

    const pathDiscovery = structuredClone(
      contract.occurrenceExamples.occurrences.find(
        (occurrence) => occurrence.resource.kind === "path-occurrence",
      ),
    );
    pathDiscovery.stage = "discovery";
    pathDiscovery.resource.objectState = "existing";
    delete pathDiscovery.resource.finalObject;
    delete pathDiscovery.resource.retainedHandle;
    expect(() =>
      validateOccurrenceSemantics(
        pathDiscovery,
        contract.definitionsById,
        contract.rules,
        "mutated occurrence",
      ),
    ).toThrow(/discovery stage lacks finalObject/);

    const unixDiscovery = structuredClone(
      contract.occurrenceExamples.occurrences.find(
        (occurrence) => occurrence.resource.kind === "unix-connect-occurrence",
      ),
    );
    unixDiscovery.stage = "discovery";
    delete unixDiscovery.resource.socketObject;
    delete unixDiscovery.resource.connectionId;
    expect(() =>
      validateOccurrenceSemantics(
        unixDiscovery,
        contract.definitionsById,
        contract.rules,
        "mutated occurrence",
      ),
    ).toThrow(/discovery stage lacks socketObject/);

    const sessionState = contract.occurrenceExamples.occurrences.find(
      (occurrence) => occurrence.resource.kind === "session-state-occurrence",
    );
    for (const stage of ["requested", "commit"]) {
      const allowed = structuredClone(sessionState);
      allowed.stage = stage;
      expect(() =>
        validateOccurrenceSemantics(
          allowed,
          contract.definitionsById,
          contract.rules,
          `session-state occurrence at ${stage}`,
        ),
      ).not.toThrow();
    }

    const delivery = structuredClone(sessionState);
    delivery.stage = "delivery";
    expect(() =>
      validateOccurrenceSemantics(
        delivery,
        contract.definitionsById,
        contract.rules,
        "session-state occurrence at delivery",
      ),
    ).toThrow(
      /session-state occurrence supports only requested and commit stages/,
    );
  });

  test("digest projections omit self-digest fields and retain every other field", () => {
    const contract = loadAndValidateContract();
    const vector = contract.digestVectors.vectors.find(
      (row) => row.id === "armed",
    );
    const changedSelfDigest = structuredClone(contract.armed);
    changedSelfDigest.armedSnapshotDigest = "different-but-omitted";
    expect(
      computeDomainDigest(vector.domain, changedSelfDigest, vector.omitFields),
    ).toBe(vector.expectedDigest);
    changedSelfDigest.channelEpoch = "2";
    expect(
      computeDomainDigest(vector.domain, changedSelfDigest, vector.omitFields),
    ).not.toBe(vector.expectedDigest);
    const changedDiscovery = structuredClone(contract.armed);
    changedDiscovery.projectRootDiscovery.markerSetVersion =
      "ibex/project-root-markers/2";
    expect(
      computeDomainDigest(vector.domain, changedDiscovery, vector.omitFields),
    ).not.toBe(vector.expectedDigest);
  });

  test("armed project-root discovery is total and agrees with its project binding", () => {
    const contract = loadAndValidateContract();
    expect(() =>
      validateArmedSnapshotSemantics(contract.armed, "armed fixture"),
    ).not.toThrow();

    const mismatchedRoot = structuredClone(contract.armed);
    mismatchedRoot.projectRootDiscovery.selectedRoot.components.push({
      encoding: "utf8",
      value: "other",
    });
    expect(() =>
      validateArmedSnapshotSemantics(mismatchedRoot, "mutated"),
    ).toThrow(/selected root differs from the project binding/);

    const mismatchedMarker = structuredClone(contract.armed);
    mismatchedMarker.projectRootDiscovery.markerKind = "lockfile";
    expect(() =>
      validateArmedSnapshotSemantics(mismatchedMarker, "mutated"),
    ).toThrow(/discovery record is internally inconsistent/);
  });

  test("digest projections and domain payloads cannot redefine their own oracle", () => {
    const contract = loadAndValidateContract();
    const changedProjection = structuredClone(contract.rules);
    changedProjection.digestContract.projections.policy.omitFields.push(
      "purpose",
    );
    expect(() => assertDigestProjectionContract(changedProjection)).toThrow(
      /frozen/,
    );

    const changedBinding = structuredClone(contract.digestVectors);
    changedBinding.vectors.find((row) => row.id === "vocabulary").payloadRef =
      "examples/armed-snapshot.canonical.json";
    expect(() => assertDigestVectorBindings(changedBinding)).toThrow(
      /not canonical/,
    );
  });

  test("real vocabulary, registry, policy, and armed digests detect one-field tampering", () => {
    const contract = loadAndValidateContract();
    const cases = [
      {
        name: "vocabulary",
        payload: contract.digestBundle,
        mutate: (payload) => {
          payload.profile = "ibex/capsec/tampered";
        },
      },
      {
        name: "registry",
        payload: contract.registryDigestBundle,
        mutate: (payload) => {
          payload.profile = "ibex/capsec/tampered";
        },
      },
      {
        name: "policy",
        payload: contract.policy,
        mutate: (payload) => {
          payload.capsVocab = "ibex/capsec/tampered";
        },
      },
      {
        name: "armedSnapshot",
        payload: contract.armed,
        mutate: (payload) => {
          payload.channelEpoch = "2";
        },
      },
    ];
    for (const row of cases) {
      const domain = contract.rules.digestContract.domains[row.name];
      const projection = contract.rules.digestContract.projections[row.name];
      const original = computeDomainDigest(
        domain,
        row.payload,
        projection.omitFields,
      );
      const tampered = structuredClone(row.payload);
      row.mutate(tampered);
      expect(
        computeDomainDigest(domain, tampered, projection.omitFields),
      ).not.toBe(original);
    }
  });

  test("authority containment never crosses action identity", () => {
    const contract = loadAndValidateContract();
    const vector = contract.containment.vectors.find(
      (row) => row.id === "cross-action",
    );
    expect(
      compareAuthorityContainment(vector.parent, vector.child, {
        sameSnapshot: true,
        samePackageRootOwner: true,
      }),
    ).toBe("incomparable");
  });

  test("resolved package principal identity includes locator and integrity", () => {
    const contract = loadAndValidateContract();
    const armedPrincipal = contract.armed.packageGraph.nodes[0].principal;
    const samePrincipal = structuredClone(armedPrincipal);
    expect(canonicalJson(samePrincipal)).toBe(canonicalJson(armedPrincipal));
    samePrincipal.locator = "image-lib@2.4.2";
    expect(canonicalJson(samePrincipal)).not.toBe(
      canonicalJson(armedPrincipal),
    );

    const policy = structuredClone(contract.policy);
    policy.principals[0].imports.packages = ["image-lib"];
    const validatePolicy = contract.ajv.getSchema(
      "https://ibex.dev/capsec/schema/canonical-policy.schema.json",
    );
    expect(validatePolicy(policy)).toBe(false);
  });

  test("target-neutral paths defer platform aliases until arming", () => {
    const unixOnlyName = {
      root: "project",
      components: [{ encoding: "utf8", value: "CON" }],
    };
    expect(() =>
      validateTargetLogicalPaths(
        [unixOnlyName],
        "x86_64-unknown-linux-gnu",
        "paths",
      ),
    ).not.toThrow();
    expect(() =>
      validateTargetLogicalPaths(
        [unixOnlyName],
        "x86_64-pc-windows-msvc",
        "paths",
        { aliasKey: (logicalPath) => canonicalJson(logicalPath).toLowerCase() },
      ),
    ).toThrow(/Windows-invalid or reserved/);

    const appleAliases = [
      { root: "project", components: [{ encoding: "utf8", value: "Readme" }] },
      { root: "project", components: [{ encoding: "utf8", value: "README" }] },
    ];
    expect(() =>
      validateTargetLogicalPaths(
        appleAliases,
        "aarch64-apple-darwin",
        "paths",
        {
          aliasKey: (logicalPath) =>
            `${logicalPath.root}/${logicalPath.components
              .map((row) => row.value)
              .join("/")
              .toLowerCase()}`,
        },
      ),
    ).toThrow(/alias collision/);

    const contract = loadAndValidateContract();
    const twoPackages = structuredClone(contract.armed);
    const firstRow = twoPackages.principals.find(
      (row) => row.principal.kind === "package",
    );
    firstRow.floor[0].resource.path = {
      root: "package",
      components: [{ encoding: "utf8", value: "Readme" }],
    };
    const secondPrincipal = {
      kind: "package",
      name: "other-lib",
      integrity: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      locator: "other-lib@1.0.0",
    };
    const secondRow = structuredClone(firstRow);
    secondRow.principal = secondPrincipal;
    secondRow.floor[0].resource.path.components[0].value = "README";
    twoPackages.principals.push(secondRow);
    twoPackages.packageGraph.nodes.push({ principal: secondPrincipal });
    const packageBinding = structuredClone(
      twoPackages.rootBindings.find(
        (binding) => binding.logicalRoot === "package",
      ),
    );
    packageBinding.owner = secondPrincipal;
    packageBinding.hostPath.components.at(-1).value = "other-lib";
    packageBinding.object.file = "file-201";
    twoPackages.rootBindings.push(packageBinding);

    const entries = armedTargetPathEntries(twoPackages).filter(
      (entry) => entry.logicalPath.root === "package",
    );
    const aliasAdapter = {
      aliasKey: (logicalPath) =>
        logicalPath.components
          .map((row) => row.value)
          .join("/")
          .toLowerCase(),
    };
    expect(() =>
      validateTargetLogicalPaths(
        entries,
        "aarch64-apple-darwin",
        "package paths",
        aliasAdapter,
      ),
    ).not.toThrow();
    expect(() =>
      validateTargetLogicalPaths(
        entries.map((entry) => ({ ...entry, namespace: "same-binding" })),
        "aarch64-apple-darwin",
        "package paths",
        aliasAdapter,
      ),
    ).toThrow(/alias collision/);
  });

  test("production snapshots require an advertised complete exact target", () => {
    const contract = loadAndValidateContract();
    const production = structuredClone(contract.armed);
    production.workflow = "production";
    production.engine.target = "aarch64-apple-darwin";
    expect(() =>
      validateArmedSnapshotSemantics(production, "mutated armed", {
        rules: contract.rules,
        coverage: contract.coverage,
        targetCells: contract.targetCells,
      }),
    ).toThrow(/not advertised/);

    const advertisedRules = structuredClone(contract.rules);
    advertisedRules.initialProfile.advertisedTargets = [
      {
        triple: production.engine.target,
        features: production.engine.features,
      },
    ];
    expect(() =>
      validateArmedSnapshotSemantics(production, "mutated armed", {
        rules: advertisedRules,
        coverage: contract.coverage,
        targetCells: contract.targetCells,
      }),
    ).toThrow(/no complete cell/);

    const unsupportedCells = {
      cells: contract.coverage.edges.map((edge) => ({
        edgeId: edge.id,
        target: structuredClone(
          advertisedRules.initialProfile.advertisedTargets[0],
        ),
        disposition: "enforced",
      })),
    };
    unsupportedCells.cells[0].disposition = "unsupported";
    expect(() =>
      validateArmedSnapshotSemantics(production, "mutated armed", {
        rules: advertisedRules,
        coverage: contract.coverage,
        targetCells: unsupportedCells,
      }),
    ).toThrow(
      new RegExp(
        `no complete cell for coverage edge ${contract.coverage.edges[0].id}`,
      ),
    );
  });

  test("a missing legacy row fails reconciliation even if schemas still parse", () => {
    const source = fs.readFileSync(
      path.join(capsecRoot, "..", "src", "host", "capability_bits.rs"),
      "utf8",
    );
    const bits = parseCapabilityBitDefinitions(source);
    const reconciliation = JSON.parse(
      fs.readFileSync(
        path.join(
          capsecRoot,
          "registry",
          "legacy-capability-reconciliation.json",
        ),
        "utf8",
      ),
    );
    expect(() =>
      assertLegacyReconciliationCoverage(
        bits,
        reconciliation.entries.slice(0, -1),
      ),
    ).toThrow(/missing=network:resolve/);
  });

  test("virtual cwd actions replace the legacy shared-process definition", () => {
    const definitions = JSON.parse(
      fs.readFileSync(
        path.join(capsecRoot, "registry", "capability-definitions.json"),
        "utf8",
      ),
    ).definitions;
    const byId = new Map(definitions.map((definition) => [definition.id, definition]));

    expect(byId.has("process:cwd")).toBe(false);
    expect(byId.get("path:cwd-observe")).toMatchObject({
      lifecycle: "authorable",
      globality: "session-scoped",
      resourceKinds: ["session-state"],
      staticOnly: true,
      channels: { dynamic: false, handle: false, synthesis: false },
    });
    expect(byId.get("path:cwd-mutate")).toMatchObject({
      lifecycle: "authorable",
      globality: "session-scoped",
      resourceKinds: ["path-exact"],
      staticOnly: true,
      principalConstraint: "root-only",
      channels: { dynamic: false, handle: false, synthesis: false },
    });

    const reconciliation = JSON.parse(
      fs.readFileSync(
        path.join(
          capsecRoot,
          "registry",
          "legacy-capability-reconciliation.json",
        ),
        "utf8",
      ),
    ).entries.find((entry) => entry.legacyCapability === "process:cwd");
    expect(reconciliation).toMatchObject({
      destinationDisposition: "authorable",
      migrationKind: "decompose",
      replacementActions: ["path:cwd-mutate", "path:cwd-observe"],
      currentStatus: "enforced",
    });
  });

  test("closed legacy rows can map only to deny-only definitions", () => {
    const contract = loadAndValidateContract();
    const entries = structuredClone(contract.reconciliation.entries);
    entries.find(
      (entry) => entry.destinationDisposition === "closed",
    ).replacementActions = ["fs:read"];
    expect(() =>
      assertLegacyReconciliationDestinations(entries, contract.definitionsById),
    ).toThrow(/non-deny-only/);
  });

  test("only live rows inside the Rust capability table are authoritative", () => {
    const source = `
CapabilityBitDefinition { capability: "fake:outside", bit: 6 }
const GHOST: &str = "pub const CAPABILITY_BIT_DEFINITIONS: = &[fake]";
pub const CAPABILITY_BIT_DEFINITIONS: &[CapabilityBitDefinition] = &[
  // CapabilityBitDefinition { capability: "fake:line", bit: 7 }
  /* CapabilityBitDefinition { capability: "fake:block", bit: 8 } */
  CapabilityBitDefinition { capability: "real:entry", bit: 0 }
];`;
    expect(parseCapabilityBitDefinitions(source)).toEqual([
      { capability: "real:entry", bit: 0 },
    ]);
  });
});
