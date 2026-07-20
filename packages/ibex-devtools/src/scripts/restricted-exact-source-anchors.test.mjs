import { describe, expect, test } from "vitest";

import { resolveRestrictedExactSourceAnchor } from "./restricted-exact-source-anchors.mjs";

describe("restricted Exact source anchors", () => {
  test.each([
    [
      "build.rs#backend-selection:linux:native_fetch_linux.cc",
      "build.rs",
    ],
    [
      "packages/ibex-runtime-js/src/bootstrap.ts#<module>:globals:ExactBundle.detectEngine",
      "packages/ibex-runtime-js/src/bootstrap.ts",
    ],
    [
      "packages/ibex-runtime-js/src/bootstrap.ts#defineLazyGlobal:globals:ReadableStream",
      "packages/ibex-runtime-js/src/bootstrap.ts",
    ],
    [
      "src/engine/hermes_runtime.cc#probeRootGlobalLogicalPath",
      "src/engine/hermes_runtime.cc",
    ],
  ])("resolves %s to a nonempty exact range", (sourceRef, expectedPath) => {
    const anchor = resolveRestrictedExactSourceAnchor(sourceRef);
    expect(anchor.path).toBe(expectedPath);
    expect(anchor.startByte).toBeLessThan(anchor.endByte);
    expect(anchor.startLine).toBeLessThanOrEqual(anchor.endLine);
    expect(anchor.rawContentDigest).toMatch(/^sha256-[A-Za-z0-9_-]{43}$/u);
  });

  test("refuses an ambiguous legacy export instead of choosing a platform branch", () => {
    expect(() =>
      resolveRestrictedExactSourceAnchor(
        "src/builtins/constants.js#exports:E2BIG",
      )
    ).toThrow(/missing, ambiguous, or unsupported/u);
  });
});
