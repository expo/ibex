import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "bun:test";
import {
  MODULE_LOADER_CAPTURED_BATCH_COMMAND,
  authoredModuleLoaderCapturedInvocation,
} from "./capsec-loader-public-probe-templates.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

describe("source-bound module-loader public probes", () => {
  let loaderSurfaces;
  let coverageByObservedKey;

  beforeAll(async () => {
    const inventory = await discoverRepositorySurfaces(repoRoot);
    loaderSurfaces = inventory.surfaces.filter(
      (surface) => surface.kind === "loader",
    );
    const coverage = JSON.parse(
      fs.readFileSync(
        path.join(repoRoot, "capsec/registry/coverage-edges.json"),
        "utf8",
      ),
    );
    coverageByObservedKey = new Map(
      coverage.edges.map((edge) => [
        `${edge.surface.kind}:${edge.surface.name}`,
        edge,
      ]),
    );
  }, 60_000);

  const authoredForTarget = (triple) =>
    loaderSurfaces.flatMap((surface) => {
      const invocation = authoredModuleLoaderCapturedInvocation({
        surface,
        coverageEdge: coverageByObservedKey.get(surface.observedKey),
        target: { triple },
      });
      return invocation ? [{ surface, invocation }] : [];
    });

  test("authors the reviewed zero-effect boundary on Apple and Windows", () => {
    const apple = authoredForTarget("aarch64-apple-darwin");
    const windows = authoredForTarget("x86_64-pc-windows-msvc");
    expect(apple).toHaveLength(13);
    expect(windows).toHaveLength(13);

    const counts = (rows) =>
      Object.fromEntries(
        Object.entries(
          Object.groupBy(
            rows,
            ({ surface }) => surface.metadata?.evidenceType ?? "base",
          ),
        ).map(([kind, members]) => [kind, members.length]),
      );
    expect(counts(apple)).toEqual({
      base: 2,
      "loader-function": 8,
      "internal-loader-route": 2,
      "loader-kind-branch": 1,
    });
    expect(counts(windows)).toEqual(counts(apple));

    for (const { surface, invocation } of [...apple, ...windows]) {
      expect(invocation.requiredAuthority).toEqual([]);
      expect(invocation.expectedTypedDecisionCount).toBe(0);
      expect(invocation.sourceDescriptor.surfaceName).toBe(surface.name);
      expect(invocation.sourceDescriptor.executionPoint).toBeString();
      expect(invocation.capturedOutputInvocation.route.operation).toBe(
        "invoke-public-loader",
      );
      expect(invocation.capturedOutputInvocation.route).not.toHaveProperty(
        "authority",
      );
    }
  });

  test("does not promote typed, bypassed, or unavailable target routes", () => {
    const surface = (name) =>
      loaderSurfaces.find((candidate) => candidate.name === name);
    const author = (name, triple = "aarch64-apple-darwin") =>
      authoredModuleLoaderCapturedInvocation({
        surface: surface(name),
        coverageEdge: coverageByObservedKey.get(`loader:${name}`),
        target: { triple },
      });

    expect(author("json-module")).toBeNull();
    expect(author("function:javascript:builtinCacheKeyFor")).toBeNull();
    expect(
      author(
        "lazy-installer:__exactEnsureWebCrypto:crypto",
        "x86_64-pc-windows-msvc",
      ),
    ).toBeNull();
    expect(author("lazy-installer:__exactEnsureWebCrypto:crypto")).toBeNull();
    expect(author("entry:load-internal")).toBeNull();
  });

  test("pins the secure isolated batch command and exact source points", () => {
    expect(MODULE_LOADER_CAPTURED_BATCH_COMMAND).toContain(
      "capsec_public_loader_recipe_batch",
    );
    expect(MODULE_LOADER_CAPTURED_BATCH_COMMAND).toContain(
      "standard,capsec-conformance-observer,openssl-crypto",
    );
    const rows = authoredForTarget("aarch64-apple-darwin");
    const byName = new Map(rows.map((row) => [row.surface.name, row.invocation]));
    expect(
      byName.get("import-needs").sourceDescriptor.executionPoint,
    ).toBe("function:javascript:rejectRuntimeLoaderOptions");
    expect(
      byName.get("internal-route:internal/fs/utils").sourceDescriptor
        .executionPoint,
    ).toBe("internal-route:internal/fs/utils");
  });
});
