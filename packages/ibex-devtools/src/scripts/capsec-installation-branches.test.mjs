import { describe, expect, test } from "bun:test";
import { normalizeComposedInstallationBranches } from "./capsec-installation-branches.mjs";

describe("composed installation branches", () => {
  test("composes shared and native layers per target", () => {
    const branches = normalizeComposedInstallationBranches([
      {
        route: "shared-runtime",
        targetVariant: "all",
        sourceRefs: ["runtime.ts#process"],
      },
      {
        route: "native-jsi-global",
        targetVariant: "default",
        sourceRefs: ["runtime.cc#process"],
      },
      {
        route: "windows-native-shim",
        targetVariant: "windows",
        sourceRefs: ["windows.cc#process"],
      },
    ]);
    expect(branches).toHaveLength(2);
    expect(branches.map((branch) => branch.targetVariant)).toEqual([
      "default",
      "windows",
    ]);
    expect(branches[0]).toMatchObject({
      branchKind: "alternative",
      routes: ["native-jsi-global", "shared-runtime"],
      sourceRefs: ["runtime.cc#process", "runtime.ts#process"],
    });
    expect(branches[1]).toMatchObject({
      branchKind: "alternative",
      routes: ["shared-runtime", "windows-native-shim"],
      sourceRefs: ["runtime.ts#process", "windows.cc#process"],
    });
  });

  test("retains a common fallback beside a target overlay", () => {
    const branches = normalizeComposedInstallationBranches([
      {
        route: "shared-runtime",
        targetVariant: "all",
        sourceRefs: ["runtime.ts#Headers"],
      },
      {
        route: "windows-native-shim",
        targetVariant: "windows",
        sourceRefs: ["windows.cc#Headers"],
      },
    ]);
    expect(
      branches.map((branch) => [branch.targetVariant, branch.sourceRefs]),
    ).toEqual([
      ["default", ["runtime.ts#Headers"]],
      ["windows", ["runtime.ts#Headers", "windows.cc#Headers"]],
    ]);
  });

  test("merges multiple same-target layers into one implementation", () => {
    const [branch] = normalizeComposedInstallationBranches([
      {
        route: "bootstrap-a",
        targetVariant: "default",
        sourceRefs: ["a.js#global"],
      },
      {
        route: "bootstrap-b",
        targetVariant: "default",
        sourceRefs: ["b.js#global"],
      },
    ]);
    expect(branch).toMatchObject({
      branchKind: "single",
      routes: ["bootstrap-a", "bootstrap-b"],
      sourceRefs: ["a.js#global", "b.js#global"],
      targetVariant: "default",
    });
  });

  test("is idempotent after evidence views are merged repeatedly", () => {
    const once = normalizeComposedInstallationBranches([
      {
        route: "shared-runtime",
        targetVariant: "all",
        sourceRefs: ["runtime.ts#process"],
      },
      {
        route: "native-jsi-global",
        targetVariant: "default",
        sourceRefs: ["runtime.cc#process"],
      },
    ]);
    expect(normalizeComposedInstallationBranches(once)).toEqual(once);
  });

  test("retains source uncertainty when installation layers compose", () => {
    const [uncertain] = normalizeComposedInstallationBranches([
      {
        route: "shared-runtime",
        targetVariant: "all",
        sourceRefs: ["runtime.ts#eval"],
      },
      {
        route: "external-engine",
        targetVariant: "default",
        sourceRefs: ["build.rs#HERMES_LIB_DIR"],
        stubDisposition: "not-structurally-proven",
      },
    ]);
    expect(uncertain.stubDisposition).toBe("not-structurally-proven");

    const [mixedWeak] = normalizeComposedInstallationBranches([
      {
        route: "concrete",
        targetVariant: "default",
        sourceRefs: ["runtime.cc#strong"],
      },
      {
        route: "weak",
        targetVariant: "default",
        sourceRefs: ["runtime.cc#weak"],
        stubDisposition: "weak-fallback",
      },
    ]);
    expect(mixedWeak.stubDisposition).toBe("contains-weak-fallback");
  });

  test("rejects evidence-free layers", () => {
    expect(() =>
      normalizeComposedInstallationBranches([
        { route: "broken", targetVariant: "default", sourceRefs: [] },
      ]),
    ).toThrow(/no source refs/u);
    expect(() =>
      normalizeComposedInstallationBranches([
        {
          route: "broken",
          targetVariant: "default",
          sourceRefs: ["runtime.cc#broken"],
          stubDisposition: "unreviewed",
        },
      ]),
    ).toThrow(/unreviewed stub disposition/u);
  });
});
