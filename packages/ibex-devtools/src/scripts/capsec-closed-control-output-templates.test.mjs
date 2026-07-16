import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "bun:test";
import {
  canonicalJson,
  repoRoot,
} from "./capsec-contract.mjs";
import {
  authoredClosedControlOutputInvocation,
  CLOSED_CONTROL_OUTPUT_INVOCATION_SCHEMA,
  CLOSED_CONTROL_OUTPUT_TIMEOUT_MILLISECONDS,
} from "./capsec-closed-control-output-templates.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";

const CLOSED_CONTROL_POLICY_RATIONALES = Object.freeze({
  "cli-control":
    "The source-inventoried CLI control is classified closed, and production entry returns its stable refusal before artifact or project execution.",
  "startup-environment":
    "The source-inventoried startup-environment control is classified closed, and production entry returns its stable refusal before artifact or project execution.",
  "loader-executable-file":
    "The source-inventoried executable-loader control is classified closed, and the authenticated module loader throws its stable resolution refusal before payload evaluation.",
});

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

function forbiddenResultKeys(value, pathPrefix = "invocation") {
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value)) {
    return value.flatMap((item, index) =>
      forbiddenResultKeys(item, `${pathPrefix}[${index}]`),
    );
  }
  const forbidden = new Set([
    "disposition",
    "expectation",
    "normalizedValue",
    "observation",
    "outcome",
    "resultKind",
  ]);
  return Object.entries(value).flatMap(([key, child]) => [
    ...(forbidden.has(key) ? [`${pathPrefix}.${key}`] : []),
    ...forbiddenResultKeys(child, `${pathPrefix}.${key}`),
  ]);
}

describe("closed-control output templates", () => {
  test("authors the exact 136 closed output routes without result expectations", async () => {
    const inventory = await discoverRepositorySurfaces(repoRoot);
    const coverage = JSON.parse(
      fs.readFileSync(
        path.join(repoRoot, "capsec/registry/coverage-edges.json"),
        "utf8",
      ),
    );
    const live = new Map(
      inventory.surfaces.map((surface) => [surface.observedKey, surface]),
    );
    const invocations = coverage.edges.flatMap((coverageEdge) => {
      const surface = live.get(
        `${coverageEdge.surface.kind}:${coverageEdge.surface.name}`,
      );
      if (!surface) return [];
      const invocation = authoredClosedControlOutputInvocation({
        surface,
        surfaces: inventory,
        coverageEdge,
        coverage,
      });
      return invocation ? [invocation] : [];
    });

    const counts = Object.fromEntries(
      ["cli-control", "startup-environment", "loader-executable-file"].map(
        (kind) => [
          kind,
          invocations.filter((invocation) => invocation.operation.kind === kind)
            .length,
        ],
      ),
    );
    expect(counts).toEqual({
      "cli-control": 114,
      "startup-environment": 20,
      "loader-executable-file": 2,
    });
    expect(new Set(invocations.map((row) => row.coverageEdgeId)).size).toBe(
      136,
    );
    for (const invocation of invocations) {
      expect(invocation.invocationSchema).toBe(
        CLOSED_CONTROL_OUTPUT_INVOCATION_SCHEMA,
      );
      expect(invocation.sourceDescriptorDigest).toBe(
        taggedDigest(invocation.sourceDescriptor),
      );
      expect(invocation.completion).toEqual({
        kind: "bounded-production-boundary",
        timeoutMilliseconds: CLOSED_CONTROL_OUTPUT_TIMEOUT_MILLISECONDS,
      });
      expect(forbiddenResultKeys(invocation)).toEqual([]);
      expect(Object.hasOwn(invocation.operation, "expectedRejectionFragments"))
        .toBe(false);
      expect(Object.hasOwn(invocation.operation, "rejectionFragment")).toBe(
        false,
      );
    }
  }, 60_000);

  test("rejects a mismatched or non-closed coverage edge", () => {
    const surface = {
      kind: "startup",
      name: "env:IBEX_EXAMPLE",
      observedKey: "startup:env:IBEX_EXAMPLE",
      sourceRefs: ["fixture#env"],
      metadata: {
        evidenceType: "static-runtime-environment-control",
        authoredNames: ["IBEX_EXAMPLE"],
      },
    };
    const edge = {
      id: "surface.startup.example",
      classification: "effects",
      surface: { kind: surface.kind, name: surface.name },
    };
    expect(
      authoredClosedControlOutputInvocation({
        surface,
        surfaces: [surface],
        coverageEdge: edge,
        coverage: { edges: [edge] },
      }),
    ).toBeNull();
  });

  test("keeps source-derived closed controls as exact structural-only accounts", async () => {
    const inventory = await discoverRepositorySurfaces(repoRoot);
    const coverage = JSON.parse(
      fs.readFileSync(
        path.join(repoRoot, "capsec/registry/coverage-edges.json"),
        "utf8",
      ),
    );
    const catalog = JSON.parse(
      fs.readFileSync(
        path.join(repoRoot, "capsec/generated/output-shape-catalog.json"),
        "utf8",
      ),
    );
    const policy = JSON.parse(
      fs.readFileSync(
        path.join(repoRoot, "capsec/registry/output-disposition-policy.json"),
        "utf8",
      ),
    );
    const live = new Map(
      inventory.surfaces.map((surface) => [surface.observedKey, surface]),
    );
    const accounts = new Map(
      catalog.surfaceAccounts.map((account) => [account.surfaceId, account]),
    );
    const expectedSurfaceIds = new Set();
    for (const coverageEdge of coverage.edges) {
      const surface = live.get(
        `${coverageEdge.surface.kind}:${coverageEdge.surface.name}`,
      );
      if (!surface) continue;
      const invocation = authoredClosedControlOutputInvocation({
        surface,
        surfaces: inventory,
        coverageEdge,
        coverage,
      });
      if (!invocation) continue;
      expect(coverageEdge.classification).toBe("closed");
      const catalogRows = catalog.rows.filter(
        (row) =>
          row.key.surfaceId === invocation.coverageEdgeId &&
          row.key.output === "[[return]]" &&
          row.key.sourceKind === surface.kind,
      );
      expect(catalogRows).toHaveLength(0);
      expect(accounts.get(invocation.coverageEdgeId)).toMatchObject({
        surfaceId: invocation.coverageEdgeId,
        status: "structural-only",
        outputKinds: [],
      });
      expectedSurfaceIds.add(invocation.coverageEdgeId);
    }

    const rationales = new Set(Object.values(CLOSED_CONTROL_POLICY_RATIONALES));
    const staleValueOverrides = policy.overrides.filter((row) =>
      rationales.has(row.rationale),
    );
    expect(expectedSurfaceIds.size).toBe(136);
    expect(staleValueOverrides).toEqual([]);
  }, 60_000);
});
