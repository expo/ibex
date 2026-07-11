// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — the
// production inventory, bindings, and unsupported target matrix are generated
// from one fail-closed discovery/classification path.

import { afterAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  generatedRegistryPaths,
  generatedRegistryOutputCatalog,
  renderCapsecRegistry,
  runCapsecRegistryGenerator,
} from "./generate-capsec-registry.mjs";

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
        observedReferences:
          first.implementationManifest.counts.observedReferences,
        outputs: first.rendered.size,
      });
    },
    SOURCE_RENDER_TIMEOUT_MS,
  );

  test(
    "joins every observed edge and makes no WP1 conformance claim",
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
            fixtureId.startsWith(`${row.branchId}.`),
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
      expect(renderedPaths).toHaveLength(10);
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
    "uses printable canonical target keys in every language binding",
    async () => {
      const result = await renderBaseline();
      expect(result.binding.implementationBranchIds).toEqual(
        result.implementationManifest.surfaces
          .map((row) => row.branchId)
          .sort(),
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
