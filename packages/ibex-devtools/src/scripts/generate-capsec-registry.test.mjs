// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — the
// production inventory, bindings, and report-derived target matrix are
// generated from one fail-closed discovery/classification path.

import { afterAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  assertOutputDispositionEvidenceMatchesReport,
  buildTargetCells,
  generatedRegistryPaths,
  generatedRegistryOutputCatalog,
  readImmutablePromotionArtifact,
  renderCapsecRegistry,
  runCapsecRegistryGenerator,
} from "./generate-capsec-registry.mjs";
import {
  OUTPUT_DISPOSITIONS,
  OUTPUT_KEY_FIELDS,
  canonicalOutputDispositionKey,
} from "./capsec-output-dispositions.mjs";

function renderedEntries(result) {
  return [...result.rendered.entries()].map(([filePath, content]) => [
    filePath,
    content,
  ]);
}

// Repository-wide source discovery takes several seconds and the
// reproducibility case intentionally performs a second complete render. Share
// the immutable baseline across assertions while keeping a finite per-test
// bound instead of inheriting Bun's 5 s unit-test default.
const SOURCE_RENDER_TIMEOUT_MS = 90_000;
let baselineRender;

function renderBaseline() {
  baselineRender ??= renderCapsecRegistry();
  return baselineRender;
}

afterAll(() => {
  baselineRender = undefined;
});

describe("LLP 0021 WP1 capsec registry generator", () => {
  test("keeps per-target publication artifacts outside the source-derived output identity", () => {
    expect(
      generatedRegistryOutputCatalog.some((row) =>
        row.path.startsWith("capsec/conformance/"),
      ),
    ).toBe(false);
    for (const publicationPath of [
      "capsec/generated/target-advertisements.json",
      "capsec/generated/target-matrix.md",
      "capsec/registry/target-cells.json",
    ]) {
      expect(
        generatedRegistryOutputCatalog.find(
          (row) => row.path === publicationPath,
        )?.digestBound,
      ).toBe(false);
    }
  });

  test("binds each promoted report to its own output evidence bytes and exact execution identity", () => {
    const target = {
      triple: "aarch64-apple-darwin",
      features: ["native-lockdown"],
    };
    const engine = {
      engineArtifactPath: "/exact/hermes",
      kind: "hermes",
      binaryDigest: `sha256-${"A".repeat(43)}`,
      object: { platform: "apple", volume: "dev:1", file: "ino:2" },
      targetArchitecture: "aarch64",
      structuralFeatures: [...target.features],
    };
    const evidence = {
      status: "verified",
      sourceRevision: "a".repeat(40),
      sourceTreeDigest: `sha256-${"B".repeat(43)}`,
      target,
      engine,
    };
    const rawContentDigest = `sha256-${"C".repeat(43)}`;
    const report = {
      bindings: {
        sourceRevision: evidence.sourceRevision,
        sourceTreeDigest: evidence.sourceTreeDigest,
        target: structuredClone(target),
        engine: structuredClone(engine),
        outputDispositionEvidenceRawContentDigest: rawContentDigest,
      },
    };
    expect(() =>
      assertOutputDispositionEvidenceMatchesReport(
        evidence,
        report,
        rawContentDigest,
      ),
    ).not.toThrow();
    expect(() =>
      assertOutputDispositionEvidenceMatchesReport(
        { status: "unpromotable" },
        report,
        rawContentDigest,
      ),
    ).toThrow(/raw digest or exact source, target, and loaded-engine binding/);

    const substitutions = [
      (value) => {
        value.sourceRevision = "b".repeat(40);
      },
      (value) => {
        value.sourceTreeDigest = `sha256-${"C".repeat(43)}`;
      },
      (value) => {
        value.target.triple = "x86_64-apple-darwin";
      },
      (value) => {
        value.target.features = ["native-compartments"];
      },
      (value) => {
        value.engine.engineArtifactPath = "/other/hermes";
      },
      (value) => {
        value.engine.binaryDigest = `sha256-${"D".repeat(43)}`;
      },
      (value) => {
        value.engine.object.file = "ino:3";
      },
      (value) => {
        value.engine.structuralFeatures = ["native-compartments"];
      },
    ];
    for (const substitute of substitutions) {
      const changed = structuredClone(evidence);
      substitute(changed);
      expect(() =>
        assertOutputDispositionEvidenceMatchesReport(
          changed,
          report,
          rawContentDigest,
        ),
      ).toThrow(/raw digest or exact source, target, and loaded-engine binding/);
    }
    expect(() =>
      assertOutputDispositionEvidenceMatchesReport(
        evidence,
        report,
        `sha256-${"D".repeat(43)}`,
      ),
    ).toThrow(/raw digest/);

    const otherTarget = {
      triple: "x86_64-pc-windows-msvc",
      features: ["native-lockdown"],
    };
    const otherEvidence = structuredClone(evidence);
    otherEvidence.target = otherTarget;
    otherEvidence.engine.targetArchitecture = "x86_64";
    otherEvidence.engine.structuralFeatures = [...otherTarget.features];
    const otherDigest = `sha256-${"E".repeat(43)}`;
    const otherReport = {
      bindings: {
        sourceRevision: otherEvidence.sourceRevision,
        sourceTreeDigest: otherEvidence.sourceTreeDigest,
        target: structuredClone(otherTarget),
        engine: structuredClone(otherEvidence.engine),
        outputDispositionEvidenceRawContentDigest: otherDigest,
      },
    };
    expect(() =>
      assertOutputDispositionEvidenceMatchesReport(
        otherEvidence,
        otherReport,
        otherDigest,
      ),
    ).not.toThrow();
    expect(() =>
      assertOutputDispositionEvidenceMatchesReport(
        evidence,
        otherReport,
        rawContentDigest,
      ),
    ).toThrow(/raw digest or exact source, target, and loaded-engine binding/);
    expect(() =>
      assertOutputDispositionEvidenceMatchesReport(
        otherEvidence,
        report,
        rawContentDigest,
      ),
    ).toThrow(/raw digest or exact source, target, and loaded-engine binding/);
  });

  test("reopens promotion evidence only as digest-addressed regular files", () => {
    const root = fs.mkdtempSync(
      path.join(os.tmpdir(), "ibex-capsec-promotion-"),
    );
    try {
      const directory = path.join(
        root,
        "conformance",
        "output-disposition-evidence",
      );
      fs.mkdirSync(directory, { recursive: true });
      const text = '{"profile":"ibex/capsec/1"}\n';
      const digest = `sha256-${crypto
        .createHash("sha256")
        .update(text)
        .digest("base64url")}`;
      const artifactPath = path.join(directory, `${digest}.json`);
      fs.writeFileSync(artifactPath, text);
      expect(
        readImmutablePromotionArtifact(
          "output-disposition-evidence",
          digest,
          "test output-disposition evidence",
          root,
        ),
      ).toEqual({ profile: "ibex/capsec/1" });

      fs.writeFileSync(artifactPath, '{"profile":"tampered"}\n');
      expect(() =>
        readImmutablePromotionArtifact(
          "output-disposition-evidence",
          digest,
          "test output-disposition evidence",
          root,
        ),
      ).toThrow(/raw content digest differs/);

      fs.unlinkSync(artifactPath);
      const targetPath = path.join(root, "target.json");
      fs.writeFileSync(targetPath, text);
      fs.symlinkSync(targetPath, artifactPath);
      expect(() =>
        readImmutablePromotionArtifact(
          "output-disposition-evidence",
          digest,
          "test output-disposition evidence",
          root,
        ),
      ).toThrow(/not an immutable regular file/);

      fs.unlinkSync(artifactPath);
      fs.linkSync(targetPath, artifactPath);
      expect(() =>
        readImmutablePromotionArtifact(
          "output-disposition-evidence",
          digest,
          "test output-disposition evidence",
          root,
        ),
      ).toThrow(/not an immutable regular file/);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("derives promoted dispositions only from conformant report cells", () => {
    const target = {
      triple: "aarch64-apple-darwin",
      features: ["native-lockdown"],
    };
    const coverage = {
      edges: [
        {
          id: "edge.effects",
          classification: "effects",
          effectMode: "conjunctive",
        },
        { id: "edge.closed", classification: "closed" },
        { id: "edge.absent", classification: "closed" },
      ],
    };
    const implementationRows = [
      {
        edgeId: "edge.effects",
        branchId: "edge.effects.main",
        targetVariant: "all",
        targetApplicability: { kind: "all" },
      },
      {
        edgeId: "edge.closed",
        branchId: "edge.closed.main",
        targetVariant: "all",
        targetApplicability: { kind: "all" },
      },
      {
        edgeId: "edge.absent",
        branchId: "edge.absent.windows",
        targetVariant: "windows",
        targetApplicability: { kind: "operating-system", value: "windows" },
      },
    ];
    const reportCells = [
      ["edge.effects", ["edge.effects.main"], ["fixture.effects"]],
      ["edge.closed", ["edge.closed.main"], ["fixture.closed"]],
      ["edge.absent", [], ["fixture.absent"]],
    ].map(([edgeId, implementationBranchIds, requiredFixtures]) => ({
      edgeId,
      implementationBranchIds,
      requiredFixtures,
      status: "conformant",
    }));
    const cells = buildTargetCells(coverage, [target], implementationRows, [
      {
        attestation: { reportRawContentDigest: "sha256-report" },
        report: {
          bindings: { target },
          conformanceDigest: "sha256-conformance",
          cells: reportCells,
        },
      },
    ]).cells;
    expect(
      cells.map(({ edgeId, disposition, fixtures }) => ({
        edgeId,
        disposition,
        fixtures,
      })),
    ).toEqual([
      {
        edgeId: "edge.absent",
        disposition: "absent",
        fixtures: ["fixture.absent"],
      },
      {
        edgeId: "edge.closed",
        disposition: "closed",
        fixtures: ["fixture.closed"],
      },
      {
        edgeId: "edge.effects",
        disposition: "enforced",
        fixtures: ["fixture.effects"],
      },
    ]);
  });

  test(
    "renders byte-identically",
    async () => {
      const first = await renderBaseline();
      const second = await renderCapsecRegistry();

      expect(renderedEntries(second)).toEqual(renderedEntries(first));
    },
    SOURCE_RENDER_TIMEOUT_MS,
  );

  test(
    "keeps every committed output current",
    async () => {
      const first = await renderBaseline();
      expect(await runCapsecRegistryGenerator()).toEqual({
        coverageEdges: first.coverage.edges.length,
        targetCells: first.targetCells.cells.length,
        enforcementBranches:
          first.implementationManifest.counts.enforcementBranches,
        observedReferences:
          first.implementationManifest.counts.observedReferences,
        outputs: first.rendered.size,
        ingressObligations: first.ingressObligationCounts.obligations,
        outputDispositionEvidence:
          first.outputDispositionDataset.evidence.status,
      });
    },
    SOURCE_RENDER_TIMEOUT_MS,
  );

  test(
    "joins every observed edge and makes no unattested conformance claim",
    async () => {
      const result = await renderBaseline();
      const edgeIds = result.coverage.edges.map((edge) => edge.id);
      const implementedEdgeIds = [
        ...new Set(
          result.implementationManifest.surfaces.map((row) => row.edgeId),
        ),
      ].sort();

      expect(implementedEdgeIds).toEqual(edgeIds);
      expect(result.targetCells.cells).toHaveLength(
        edgeIds.length * result.implementationManifest.candidateTargets.length,
      );
      expect(
        result.targetCells.cells.every(
          (cell) =>
            cell.disposition === "unsupported" && cell.fixtures.length === 0,
        ),
      ).toBe(true);
      expect(result.targetAdvertisements.advertisements).toEqual([]);
      const implementationById = new Map(
        result.implementationManifest.surfaces.map((row) => [
          row.branchId,
          row,
        ]),
      );
      expect(
        result.targetCells.cells.every((cell) =>
          cell.implementationBranchIds.every(
            (branchId) =>
              implementationById.get(branchId)?.edgeId === cell.edgeId,
          ),
        ),
      ).toBe(true);
      expect(
        result.targetCells.cells.some(
          (cell) => cell.implementationBranchIds.length > 0,
        ),
      ).toBe(true);
      expect(
        result.implementationManifest.surfaces.every((row) =>
          row.fixtureObligations.every((fixtureId) =>
            fixtureId.startsWith(`${row.enforcementBranchId}.`),
          ),
        ),
      ).toBe(true);
    },
    SOURCE_RENDER_TIMEOUT_MS,
  );

  test(
    "renders the exact closed output family with one documented self exclusion",
    async () => {
      const result = await renderBaseline();
      const renderedPaths = [...result.rendered.keys()]
        .map((filePath) => filePath.replaceAll("\\", "/"))
        .sort();
      const catalogSuffixes = generatedRegistryOutputCatalog
        .map((row) => row.path)
        .sort();
      expect(renderedPaths).toHaveLength(generatedRegistryOutputCatalog.length);
      expect(
        renderedPaths.map((filePath) =>
          catalogSuffixes.find((suffix) => filePath.endsWith(`/${suffix}`)),
        ),
      ).toEqual(catalogSuffixes);

      expect(
        result.implementationManifest.outputs.map(({ path, kind }) => ({
          path,
          kind,
        })),
      ).toEqual(
        generatedRegistryOutputCatalog
          .filter((row) => row.digestBound)
          .map(({ path, kind }) => ({ path, kind }))
          .sort((left, right) => left.path.localeCompare(right.path)),
      );
      expect(
        result.implementationManifest.outputs.some(
          (row) => row.path === "capsec/generated/implementation-manifest.json",
        ),
      ).toBe(false);
      expect(
        result.implementationManifest.outputs.some((row) =>
          row.path.startsWith("capsec/conformance/"),
        ),
      ).toBe(false);
      expect(
        result.implementationManifest.sourceDatasets.some((source) =>
          source.startsWith("conformance/"),
        ),
      ).toBe(false);
      expect(result.implementationManifest.sourceDatasets).toContain(
        "registry/output-disposition-evidence.json",
      );
      for (const outputPath of [
        generatedRegistryPaths.surfaceDocs,
        generatedRegistryPaths.targetDocs,
      ]) {
        const content = result.rendered.get(outputPath);
        expect(content.endsWith("\n")).toBe(true);
        expect(content.endsWith("\n\n")).toBe(false);
      }
    },
    SOURCE_RENDER_TIMEOUT_MS,
  );

  test(
    "generates a total seven-part output dataset without claiming absent live evidence",
    async () => {
      const result = await renderBaseline();
      const catalog = result.outputShapeCatalog;
      const dataset = result.outputDispositionDataset;
      expect(catalog.counts).toEqual({
        coverageSurfaces: 7_328,
        outputBearingSurfaces: 5_761,
        structuralOnlySurfaces: 1_563,
        unresolvedSurfaces: 4,
        catalogRows: 6_429,
        parameterizedBindings: 1,
        sourceInventoryRows: 6_022,
        structuredRows: 407,
      });
      expect(catalog.surfaceAccounts).toHaveLength(
        result.coverage.edges.length,
      );
      expect(
        new Set(catalog.surfaceAccounts.map((account) => account.surfaceId)),
      ).toEqual(new Set(result.coverage.edges.map((edge) => edge.id)));
      expect(dataset.rows).toHaveLength(catalog.rows.length);
      expect(dataset.dispositions).toEqual(OUTPUT_DISPOSITIONS);
      expect(dataset.evidence.status).toBe("unpromotable");
      expect(catalog.discovery.status).toBe("unpromotable");
      expect(catalog.catalogKeyDigest).toBe(dataset.catalogKeyDigest);
      expect(
        catalog.rows.map((row) => canonicalOutputDispositionKey(row.key)),
      ).toEqual(
        dataset.rows.map((row) => canonicalOutputDispositionKey(row.key)),
      );
      expect(
        dataset.rows.every(
          (row) =>
            JSON.stringify(Object.keys(row.key).sort()) ===
            JSON.stringify([...OUTPUT_KEY_FIELDS].sort()),
        ),
      ).toBe(true);
      expect(new Set(dataset.rows.map((row) => row.disposition))).toEqual(
        new Set(OUTPUT_DISPOSITIONS),
      );
      for (const alias of [
        "process.argv[0]",
        "process.execArgv[]",
        "import.meta.url",
        "import.meta.dirname",
        "module.__exactPackageRoot",
        "module.paths[]",
        "resolver.path",
        "error.path",
        "source-map.sources[]",
        "Error.stack frame source",
        "Dirent.parentPath",
        "FileHandle.path",
        "ExactFile.name",
        "Bun.main",
      ]) {
        expect(dataset.rows.some((row) => row.key.alias === alias)).toBe(true);
      }
      expect(
        dataset.rows.some(
          (row) =>
            row.key.alias === "import.meta.dirname" &&
            row.key.sourceKind === "synthetic" &&
            row.disposition === "absent",
        ),
      ).toBe(true);
      expect(
        dataset.rows.some(
          (row) =>
            row.key.alias === "error.dest" &&
            row.disposition === "virtual-absolute",
        ),
      ).toBe(true);
      expect(
        dataset.rows.some(
          (row) =>
            row.key.alias === "sourceURL" &&
            row.key.sourceKind === "synthetic" &&
            row.disposition === "synthetic-source-id",
        ),
      ).toBe(true);
      expect(
        JSON.parse(
          result.rendered.get(generatedRegistryPaths.outputShapeCatalog),
        ),
      ).toEqual(catalog);
      expect(
        JSON.parse(
          result.rendered.get(generatedRegistryPaths.outputDispositions),
        ),
      ).toEqual(dataset);
    },
    SOURCE_RENDER_TIMEOUT_MS,
  );

  test(
    "uses printable canonical target keys in every language binding",
    async () => {
      const result = await renderBaseline();
      expect(result.binding.implementationBranchIds).toEqual(
        result.implementationManifest.surfaces
          .map((row) => row.branchId)
          .sort(),
      );
      expect(result.binding.enforcementBranchIds).toEqual(
        [
          ...new Set(
            result.implementationManifest.surfaces.map(
              (row) => row.enforcementBranchId,
            ),
          ),
        ].sort(),
      );
      expect(
        result.binding.implementationBranchIds.every(
          (branchId) => !branchId.includes("\u0000"),
        ),
      ).toBe(true);
      for (const targetKey of result.binding.targetKeys) {
        expect(targetKey).not.toContain("\u0000");
        const [edgeId, triple, features] = JSON.parse(targetKey);
        expect(typeof edgeId).toBe("string");
        expect(typeof triple).toBe("string");
        expect(Array.isArray(features)).toBe(true);
      }

      for (const outputPath of [
        generatedRegistryPaths.rust,
        generatedRegistryPaths.cxx,
        generatedRegistryPaths.javascript,
        generatedRegistryPaths.typescript,
      ]) {
        expect(result.rendered.get(outputPath)).not.toContain("\\u0000");
      }
    },
    SOURCE_RENDER_TIMEOUT_MS,
  );

  test(
    "deep-freezes both scripting-language bindings",
    async () => {
      const result = await renderBaseline();
      const temporaryRoot = fs.mkdtempSync(
        path.join(os.tmpdir(), "ibex-capsec-bindings-"),
      );
      try {
        const commonJsPath = path.join(temporaryRoot, "registry.cjs");
        const typeScriptPath = path.join(temporaryRoot, "registry.ts");
        fs.writeFileSync(
          commonJsPath,
          result.rendered.get(generatedRegistryPaths.javascript),
        );
        fs.writeFileSync(
          typeScriptPath,
          result.rendered.get(generatedRegistryPaths.typescript),
        );

        const commonJsModule = await import(pathToFileURL(commonJsPath).href);
        const typeScriptModule = await import(
          pathToFileURL(typeScriptPath).href
        );
        for (const registry of [
          commonJsModule.default.CAPSEC_REGISTRY,
          typeScriptModule.CAPSEC_REGISTRY,
        ]) {
          expect(Object.isFrozen(registry)).toBe(true);
          expect(Object.isFrozen(registry.actionIds)).toBe(true);
          expect(Object.isFrozen(registry.edgeIds)).toBe(true);
          expect(Object.isFrozen(registry.implementationBranchIds)).toBe(true);
          expect(Object.isFrozen(registry.enforcementBranchIds)).toBe(true);
          expect(Object.isFrozen(registry.targetKeys)).toBe(true);
          expect(() => registry.actionIds.push("future:action")).toThrow();
        }
      } finally {
        fs.rmSync(temporaryRoot, { force: true, recursive: true });
      }
    },
    SOURCE_RENDER_TIMEOUT_MS,
  );
});
