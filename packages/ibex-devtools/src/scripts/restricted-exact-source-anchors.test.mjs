import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test } from "vitest";

import {
  resolveRestrictedExactSourceAnchor,
  resolveRestrictedExactSourceBinding,
  resolveRestrictedExactBranchSourceBinding,
} from "./restricted-exact-source-anchors.mjs";

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

  test("models platform-conditioned errno producers and their shared publication path", () => {
    const binding = resolveRestrictedExactSourceBinding(
      "src/builtins/constants.js#exports:E2BIG",
    );
    expect(binding.resolutionPolicy).toBe("conditioned-alternatives");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "value-producer",
      "selector",
      "dispatch",
      "publication",
    ]);
    expect(binding.producerPaths).toHaveLength(2);
    expect(binding.producerPaths.map((route) => route.conditionId)).toEqual([
      "runtime-platform:not-linux-or-android",
      "runtime-platform:linux-or-android",
    ]);
    expect(() =>
      resolveRestrictedExactSourceAnchor("src/builtins/constants.js#exports:E2BIG")
    ).toThrow(/requires an anchor set/u);
  });

  test("models process.cwd construction and both publication sites as one path", () => {
    const binding = resolveRestrictedExactSourceBinding(
      "src/engine/hermes_runtime_process_setup.cc#jsi-global:process.cwd",
    );
    expect(binding.resolutionPolicy).toBe("composite-path");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "publication",
      "publication",
    ]);
    expect(binding.producerPaths[0].requiredSiteIds).toEqual(
      binding.sites.map((site) => site.siteId),
    );
  });

  test("resolves a reused module source key against the branch's exact builtin identity", () => {
    const branch = {
      branchId: "surface.builtin.assert.strict.main",
      observedKey: "builtin:assert/strict",
      targetVariant: "all",
    };
    const binding = resolveRestrictedExactBranchSourceBinding(
      branch,
      "modules.ts#specifiers:node_assert",
    );
    expect(binding.locatorKind).toBe("builtin-specifier-registration");
    expect(binding.resolutionPolicy).toBe("composite-path");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "registration",
      "publication",
    ]);
    const publication = binding.sites[1];
    const modules = fs.readFileSync("modules.ts");
    expect(modules.subarray(publication.startByte, publication.endByte).toString()).toContain(
      "'assert/strict'",
    );
  });

  test("binds a CommonJS member terminal through producer, export alias, and publication", () => {
    const branch = {
      branchId: "surface.builtin.export.crypto.cipheriv.update.main",
      observedKey: "builtin:export:exact_crypto:Cipheriv.update",
      targetVariant: "all",
    };
    const binding = resolveRestrictedExactBranchSourceBinding(
      branch,
      "src/builtins/crypto.js#exports:Cipheriv.update",
    );
    expect(binding.locatorKind).toBe("commonjs-export-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "alias",
      "publication",
    ]);
    const bytes = fs.readFileSync("src/builtins/crypto.js");
    expect(
      bytes.subarray(binding.sites[0].startByte, binding.sites[0].endByte).toString(),
    ).toMatch(/Cipher\.prototype\.update|update\s*\(/u);
  });

  test("uses UTF-8 byte offsets and isolates alternate-root caches", () => {
    const firstRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-anchor-a-"));
    const secondRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-anchor-b-"));
    try {
      const first = "// café\nfunction target() { return 1; }\n";
      const second = "// café and more text\nfunction target() { return 2; }\n";
      fs.writeFileSync(path.join(firstRoot, "sample.js"), first);
      fs.writeFileSync(path.join(secondRoot, "sample.js"), second);
      const firstAnchor = resolveRestrictedExactSourceAnchor("sample.js#target", firstRoot);
      const secondAnchor = resolveRestrictedExactSourceAnchor("sample.js#target", secondRoot);
      expect(firstAnchor.startByte).toBe(Buffer.byteLength("// café\n"));
      expect(secondAnchor.startByte).toBe(Buffer.byteLength("// café and more text\n"));
      expect(firstAnchor.startByte).not.toBe(secondAnchor.startByte);
    } finally {
      fs.rmSync(firstRoot, { recursive: true, force: true });
      fs.rmSync(secondRoot, { recursive: true, force: true });
    }
  });

  test("never promotes a whole module to an executable source anchor", () => {
    expect(() =>
      resolveRestrictedExactSourceBinding(
        "packages/ibex-runtime-js/src/runtime-entry.ts#<module>",
      )
    ).toThrow(/missing, ambiguous, or unsupported/u);
  });
});
