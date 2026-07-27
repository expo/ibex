import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  authoredModuleLoaderOutputInvocation,
  moduleLoaderPublicEntrypoints,
} from "./capsec-loader-output-templates.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const moduleLoaderSource = fs.readFileSync(
  path.join(repoRoot, "src/engine/bootstrap/module-loader.js"),
  "utf8",
);

async function currentInvocations() {
  const inventory = await discoverRepositorySurfaces(repoRoot);
  const coverage = JSON.parse(
    fs.readFileSync(
      path.join(repoRoot, "capsec/registry/coverage-edges.json"),
      "utf8",
    ),
  );
  const coverageBySurface = new Map(
    coverage.edges.map((edge) => [
      `${edge.surface.kind}:${edge.surface.name}`,
      edge,
    ]),
  );
  return inventory.surfaces.flatMap((surface) => {
    if (
      surface.kind !== "loader" ||
      !surface.sourceRefs.some((sourceRef) =>
        sourceRef.startsWith("src/engine/bootstrap/module-loader.js"),
      )
    ) {
      return [];
    }
    const coverageEdge = coverageBySurface.get(`loader:${surface.name}`);
    const invocation = authoredModuleLoaderOutputInvocation({
      surface,
      coverageEdge,
    });
    return invocation ? [{ surface, invocation }] : [];
  });
}

describe("source-bound module-loader output recipes", () => {
  test("partitions the exact catalogued module-loader family", async () => {
    const rows = await currentInvocations();
    const byEvidence = Object.groupBy(
      rows,
      ({ invocation }) => invocation.sourceDescriptor.evidenceType ?? "base",
    );
    const counts = Object.fromEntries(
      Object.entries(byEvidence).map(([evidenceType, entries]) => {
        const operations = Object.groupBy(
          entries,
          ({ invocation }) => invocation.route.operation,
        );
        return [
          evidenceType,
          {
            authored: operations["invoke-public-loader"]?.length ?? 0,
            residual: operations.unexercisable?.length ?? 0,
          },
        ];
      }),
    );
    // The authenticated dev-served loader seam and construction-only runtime
    // extension registrar add reviewed residuals. Neither has a bounded public
    // invocation, so the authored partition is unchanged.
    expect(rows).toHaveLength(169);
    expect(counts).toEqual({
      base: { authored: 8, residual: 4 },
      "internal-loader-route": { authored: 47, residual: 0 },
      "lazy-loader-installer-route": { authored: 39, residual: 0 },
      "loader-entry-route": { authored: 9, residual: 3 },
      "loader-function": { authored: 14, residual: 43 },
      "loader-kind-branch": { authored: 1, residual: 1 },
    });
    const authored = rows.filter(
      ({ invocation }) => invocation.route.operation === "invoke-public-loader",
    );
    const residual = rows.filter(
      ({ invocation }) => invocation.route.operation === "unexercisable",
    );
    expect(authored).toHaveLength(118);
    expect(residual).toHaveLength(51);
    expect(
      residual
        .filter(({ surface }) =>
          new Set([
            "function:javascript:__exactResolveSessionPath",
            "function:javascript:__sessionStaticImport",
            "function:javascript:moduleResolutionError",
            "function:javascript:stableModuleResolutionErrorCode",
          ]).has(surface.name),
        )
        .map(({ surface }) => surface.name),
    ).toEqual([
      "function:javascript:__exactResolveSessionPath",
      "function:javascript:__sessionStaticImport",
      "function:javascript:moduleResolutionError",
      "function:javascript:stableModuleResolutionErrorCode",
    ]);
    expect(
      residual
        .filter(({ surface }) =>
          new Set([
            "entry:module-dynamic-import",
            "function:javascript:moduleDynamicImport",
            "function:javascript:wrapDynamicImportValue",
          ]).has(surface.name),
        )
        .map(({ surface, invocation }) => ({
          name: surface.name,
          reasonCode: invocation.route.reasonCode,
        })),
    ).toEqual([
      {
        name: "entry:module-dynamic-import",
        reasonCode: "module-local-entry-not-public",
      },
      {
        name: "function:javascript:moduleDynamicImport",
        reasonCode: "project-module-body-required",
      },
      {
        name: "function:javascript:wrapDynamicImportValue",
        reasonCode: "no-bounded-public-loader-route",
      },
    ]);
  }, 30_000);

  test("uses only existing public or legacy loader entrypoints", async () => {
    const rows = await currentInvocations();
    const allowed = new Set(moduleLoaderPublicEntrypoints);
    for (const { invocation } of rows) {
      if (invocation.route.operation !== "invoke-public-loader") continue;
      expect(allowed.has(invocation.route.entrypoint)).toBe(true);
      expect(invocation.route.specifier).toBeString();
      expect(invocation.route.specifier.length).toBeGreaterThan(0);
      expect(invocation.sourceDescriptor.sourceRefs.length).toBeGreaterThan(0);
    }
    expect(moduleLoaderPublicEntrypoints).toEqual([
      "exact-require",
      "global-import",
      "global-require",
      "import-module",
      "require-resolve",
    ]);
  }, 30_000);

  test("binds every recipe entrypoint to an existing production surface", () => {
    for (const sourceFragment of [
      "globalThis.require = function(specifier)",
      "globalThis.require.resolve = function(specifier)",
      "globalThis.__exactRequire = exactRequire",
      "Object.defineProperty(globalThis, 'import'",
      "globalThis.importModule = publicImport",
    ]) {
      expect(moduleLoaderSource).toContain(sourceFragment);
    }
  });

  test("keeps require/import recipes behind the production import gate", () => {
    expect(moduleLoaderSource).toMatch(
      /globalThis\.require = function\(specifier\)[\s\S]*?checkImportGate\(specifier\)[\s\S]*?loadInternal\(specifier\)/,
    );
    expect(moduleLoaderSource).toMatch(
      /var exactRequire = function\(specifier\)[\s\S]*?checkImportGate\(specifier\)[\s\S]*?return load\(specifier, ""\)/,
    );
    expect(moduleLoaderSource).toMatch(
      /var importImpl = function\(specifier, options, referrer, parent\)[\s\S]*?checkImportGate\(\s*devServedImportGateSpecifier\(specifier, referrer\)\s*\)/,
    );
  });

  test("routes internal aliases and lazy installers through their real specifiers", async () => {
    const rows = await currentInvocations();
    expect(
      rows.some(({ surface }) => surface.name === "internal-route:dns/promises"),
    ).toBe(false);
    expect(
      rows.some(
        ({ surface }) =>
          surface.name === "lazy-installer:__exactEnsureDns:dns/promises",
      ),
    ).toBe(true);
    for (const { surface, invocation } of rows) {
      if (surface.metadata?.evidenceType === "internal-loader-route") {
        expect(invocation.route).toMatchObject({
          operation: "invoke-public-loader",
          entrypoint: "global-require",
          specifier: surface.metadata.specifier,
        });
      }
      if (surface.metadata?.evidenceType === "lazy-loader-installer-route") {
        expect(invocation.route).toMatchObject({
          operation: "invoke-public-loader",
          entrypoint: "exact-require",
          specifier: surface.metadata.specifier,
        });
      }
    }
  }, 30_000);

  test("grants only the exact project package read for the JSON branch", async () => {
    const rows = await currentInvocations();
    const json = rows.find(({ surface }) => surface.name === "json-module");
    expect(json.invocation.route).toEqual({
      operation: "invoke-public-loader",
      entrypoint: "exact-require",
      specifier: "./package.json",
      authority: [
        {
          kind: "typed-effect",
          cap: "fs:read",
          resourceKind: "path-occurrence",
          requested: { root: "project", components: ["package.json"] },
        },
      ],
    });
  }, 30_000);

  test("keeps expectations and private call targets out of every recipe", async () => {
    const rows = await currentInvocations();
    const encoded = JSON.stringify(rows);
    expect(encoded).not.toContain("expectedValue");
    expect(encoded).not.toContain("normalizedValue");
    expect(encoded).not.toContain("outputDisposition");
    for (const { invocation } of rows) {
      expect(invocation.route.targetFunction).toBeUndefined();
      expect(invocation.route.privateEntrypoint).toBeUndefined();
      if (invocation.route.operation === "unexercisable") {
        expect(invocation.route.reasonCode).toBeString();
        expect(invocation.route.reason).toBeString();
      }
    }
  }, 30_000);

  test("rejects non-loader and non-module-loader discovery rows", () => {
    const coverageEdge = {
      id: "surface.loader.test.0000001",
      classification: "non-capability",
    };
    expect(
      authoredModuleLoaderOutputInvocation({
        surface: {
          kind: "loader",
          name: "test",
          observedKey: "loader:test",
          sourceRefs: ["src/other-loader.js#test"],
        },
        coverageEdge,
      }),
    ).toBeNull();
    expect(
      authoredModuleLoaderOutputInvocation({
        surface: {
          kind: "startup",
          name: "test",
          observedKey: "startup:test",
          sourceRefs: ["src/engine/bootstrap/module-loader.js#test"],
        },
        coverageEdge,
      }),
    ).toBeNull();
  });
});
