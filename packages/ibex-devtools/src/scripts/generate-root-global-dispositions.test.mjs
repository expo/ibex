// @ref LLP 0022#7-capabilities-principals-and-affordance-parity — one
// generated JSON manifest drives the native registrar/verifier projection.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import {
  ARMED_NATIVE_SEALED_ROOTS,
  ARMED_SHARED_RUNTIME_SEALED_PATH_PREFIXES,
  ARMED_SHARED_RUNTIME_SEALED_ROOTS,
  reviewedArmedRootGlobalSealedSurface,
} from "./capsec-armed-root-closures.mjs";
import {
  checkRootGlobalDispositionArtifacts,
  generatedRootGlobalDispositionPaths,
  renderRootGlobalDispositionArtifacts,
  renderRootGlobalDispositionHeader,
  rootGlobalInstallSurfaces,
} from "./generate-root-global-dispositions.mjs";

const renderedArtifacts = renderRootGlobalDispositionArtifacts();

describe("generated root-global disposition artifacts", () => {
  test("reviewed evaluated-script roots require discovered source evidence", () => {
    const source = {
      kind: "native-op",
      name: "__ibexLockedDown",
      observedKey: "native-op:__ibexLockedDown",
      sourceRefs: ["src/engine/hermes_runtime.cc#__ibexLockedDown"],
      metadata: { occurrenceCount: 2 },
    };
    const projected = rootGlobalInstallSurfaces({
      globals: [],
      surfaces: [source],
    });
    expect(projected).toHaveLength(1);
    expect(projected[0]).toMatchObject({
      observedKey: "native-op:__ibexLockedDown",
      metadata: {
        globalName: "__ibexLockedDown",
        surfaceType: "global-api",
        installationBranches: [
          {
            route: "evaluated-native-script",
            targetVariant: "default",
          },
        ],
      },
    });
    expect(() =>
      rootGlobalInstallSurfaces({
        globals: [],
        surfaces: [{ ...source, sourceRefs: ["different.cc#marker"] }],
      }),
    ).toThrow(/evaluated-script root evidence is absent/u);
  });

  test("the native table is a projection of the manifest", async () => {
    const rendered = await renderedArtifacts;
    expect(rendered.manifest.counts.logicalGlobals).toBeGreaterThan(2_000);
    expect(rendered.manifest.counts.sealedOrPrivate).toBeGreaterThan(20);
    expect(rendered.cxx).toContain("kRootExpectations");
    expect(rendered.cxx).toContain("kAbsentExpectations");
    expect(rendered.cxx).toContain("kConditionalLiveSweepExpectations[1]");
    expect(rendered.cxx).toContain("kNativeKeyExpectations");
    expect(rendered.cxx).toContain("kPermittedKeyExpectations");
    expect(rendered.cxx).toContain("__exactExit");
    expect(rendered.cxx).toContain("Ibex.permissions");
    expect(rendered.cxx).toContain(
      '"exact", "invokeHostAsync", "default", "authenticated-exact-host-ingress"',
    );
    expect(
      renderRootGlobalDispositionHeader(rendered.manifest, rendered.json),
    ).toBe(rendered.cxx);
  }, 30_000);

  test("all reviewed armed closures project to sealed absence", async () => {
    const { manifest } = await renderedArtifacts;
    const reviewedRows = manifest.rows.filter((row) =>
      reviewedArmedRootGlobalSealedSurface(
        row.observedKey.replace(/^native-op:/u, ""),
      ),
    );
    expect(reviewedRows).toHaveLength(297);
    expect(
      reviewedRows.every(
        (row) =>
          row.disposition === "sealed" &&
          row.liveExpectation === "absent" &&
          row.privateConsumer === null,
      ),
    ).toBe(true);
    for (const root of [
      ...ARMED_NATIVE_SEALED_ROOTS,
      ...ARMED_SHARED_RUNTIME_SEALED_ROOTS,
    ]) {
      expect(
        reviewedRows.some((row) => row.property.root.value === root),
      ).toBe(true);
    }
    for (const prefix of ARMED_SHARED_RUNTIME_SEALED_PATH_PREFIXES) {
      expect(
        reviewedRows.some((row) =>
          row.observedKey.startsWith(`native-op:${prefix}`),
        ),
      ).toBe(true);
    }
    expect(manifest.counts).toMatchObject({
      installBranches: 2_807,
      sealedOrPrivate: 351,
      permittedReachable: 2_456,
    });
  }, 30_000);

  test("committed generated artifacts are current", async () => {
    const rendered = await renderedArtifacts;
    expect(checkRootGlobalDispositionArtifacts(rendered)).toEqual([]);
    for (const filePath of Object.values(generatedRootGlobalDispositionPaths)) {
      expect(fs.existsSync(filePath)).toBe(true);
    }
  }, 30_000);
});
