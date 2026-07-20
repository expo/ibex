import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test } from "vitest";

import {
  buildRestrictedExactBranchSourceRoute,
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

  test("binds JSI globals through HostFunction construction and exact publication", () => {
    const branch = {
      branchId: "surface.native.op.exactaccess.default",
      observedKey: "native-op:__exactAccess",
      targetVariant: "default",
    };
    const binding = resolveRestrictedExactBranchSourceBinding(
      branch,
      "src/engine/hermes_runtime_fs.cc#jsi-global:__exactAccess",
    );
    expect(binding.locatorKind).toBe("jsi-root-global-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "publication",
    ]);
    const bytes = fs.readFileSync("src/engine/hermes_runtime_fs.cc");
    expect(bytes.subarray(binding.sites[0].startByte, binding.sites[0].endByte).toString()).toContain(
      "createFromHostFunction",
    );
    expect(bytes.subarray(binding.sites[1].startByte, binding.sites[1].endByte).toString()).toContain(
      'setProperty(rt, "__exactAccess"',
    );
  });

  test("rejects an unclassified second JSI publication", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-jsi-branch-"));
    try {
      fs.writeFileSync(path.join(root, "fixture.cc"), `
void install(Runtime& rt) {
  auto first = createHostFunction();
  rt.global().setProperty(rt, "danger", std::move(first));
  auto second = createHostFunction();
  rt.global().setProperty(rt, "danger", std::move(second));
}
`);
      expect(() => resolveRestrictedExactBranchSourceBinding(
        { branchId: "danger.default", observedKey: "native-op:danger", targetVariant: "default" },
        "fixture.cc#jsi-global:danger",
        root,
      )).toThrow(/missing, ambiguous, or unsupported/u);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("binds a TypeScript member without crediting the entire class", () => {
    const sourceRef = "packages/ibex-runtime-js/src/node/Buffer.ts#Buffer.prototype.copy";
    const binding = resolveRestrictedExactBranchSourceBinding(
      { branchId: "buffer.copy.all", observedKey: "native-op:global:Buffer.copy", targetVariant: "all" },
      sourceRef,
    );
    expect(binding.locatorKind).toBe("typescript-class-member");
    expect(binding.resolutionPolicy).toBe("provenance-only");
    const source = fs.readFileSync("packages/ibex-runtime-js/src/node/Buffer.ts");
    const slice = source.subarray(binding.sites[0].startByte, binding.sites[0].endByte).toString();
    expect(slice).toMatch(/^\s*copy\(/u);
    expect(slice).not.toContain("class Buffer");
  });

  test("composes a global member route and excludes a nonterminal prototype homonym", () => {
    const branch = {
      branchId: "surface.native.op.global.buffer.compare.all",
      edgeId: "surface.native.op.global.buffer.compare",
      observedKey: "native-op:global:Buffer.compare",
      targetVariant: "all",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:Buffer",
      "packages/ibex-runtime-js/src/node/Buffer.ts#Buffer.compare",
      "packages/ibex-runtime-js/src/node/Buffer.ts#Buffer.prototype.compare",
    ]);
    expect(route.status).toBe("executable");
    expect(route.producerPaths).toHaveLength(1);
    expect(route.bindingDispositions).toContainEqual({
      sourceRef: "packages/ibex-runtime-js/src/node/Buffer.ts#Buffer.prototype.compare",
      disposition: "supporting-provenance",
      locatorKind: "typescript-class-member",
    });
    expect(route.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "publication",
    ]);
  });

  test("composes runtime-bundle and legacy-bootstrap lazy alternatives", () => {
    const branch = {
      branchId: "surface.native.op.global.abortcontroller.abort.default",
      edgeId: "surface.native.op.global.abortcontroller.abort",
      observedKey: "native-op:global:AbortController.abort",
      targetVariant: "default",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "packages/ibex-runtime-js/src/abort/AbortController.ts#AbortController.prototype.abort",
      "packages/ibex-runtime-js/src/bootstrap.ts#defineLazyGlobal:globals:AbortController",
      "src/engine/bootstrap/bootstrap-globals.js#AbortController.abort",
    ]);
    expect(route.status).toBe("executable");
    expect(route.resolutionPolicy).toBe("conditioned-alternatives");
    expect(route.producerPaths.map((producerPath) => producerPath.conditionId).sort()).toEqual([
      "legacy-bootstrap:global-missing",
      "runtime-bundle:global-missing",
    ]);
  });

  test("binds inherited CommonJS terminals through capture, guard, and prototype alias", () => {
    const dynamic = "Cipher.[[dynamic-table:inherited-09c5428f83a8-properties]]";
    const binding = resolveRestrictedExactBranchSourceBinding(
      { branchId: "cipher.inherited", observedKey: `builtin:export:exact_crypto:${dynamic}`, targetVariant: "all" },
      `src/builtins/crypto.js#exports:${dynamic}`,
    );
    expect(binding.locatorKind).toBe("commonjs-inherited-export-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "retention",
      "guard",
      "alias",
      "alias",
      "publication",
    ]);
    expect(binding.producerPaths[0].conditionId).toBe(
      "runtime-dependency:stream-transform-present",
    );
  });

  test("binds an exported host ABI symbol through its exact definition and export", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.host.abi.ex.android.initialize.1c4cnq6.android",
        observedKey: "host-abi:ex_android_initialize",
        targetVariant: "android",
      },
      "src/engine/native_android_networking.cc#ex_android_initialize",
    );
    expect(binding.locatorKind).toBe("exported-host-abi");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "publication",
    ]);
    expect(binding.producerPaths[0].conditionId).toBe("target-branch:android");
  });

  test("keeps strong and weak host ABI definitions as build-conditioned alternatives", () => {
    const branch = {
      branchId: "surface.host.abi.ex.host.http.address.15trli0.default",
      edgeId: "surface.host.abi.ex.host.http.address.15trli0",
      observedKey: "host-abi:ex_host_http_address",
      targetVariant: "default",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "src/engine/hermes_runtime.cc#ex_host_http_address",
      "src/host/http_server.rs#ex_host_http_address",
    ]);
    expect(route.status).toBe("executable");
    expect(route.resolutionPolicy).toBe("conditioned-alternatives");
    expect(route.producerPaths.map((producerPath) => producerPath.conditionId).sort()).toEqual([
      "linkage:strong-rust-export",
      "linkage:weak-fallback-without-strong-export",
    ]);
  });

  test("binds a visible CLI command through manifest, clap enum, and dispatch", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.cli.run.1adr0ba.main",
        observedKey: "cli:run",
        targetVariant: "all",
      },
      "runtime-surface.json#visibleCommands",
    );
    expect(binding.locatorKind).toBe("cli-command-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "registration",
      "publication",
      "dispatch",
    ]);
    expect(binding.producerPaths).toHaveLength(1);
    expect(binding.refusalPaths).toEqual([]);
  });

  test("binds a forbidden CLI namespace to the compiled refusal dispatcher", () => {
    const branch = {
      branchId: "surface.cli.agent.18yerxe.main",
      edgeId: "surface.cli.agent.18yerxe",
      observedKey: "cli:agent",
      targetVariant: "all",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "runtime-surface.json#legacyProjectCommands",
    ]);
    expect(route.status).toBe("executable");
    expect(route.producerPaths).toEqual([]);
    expect(route.refusalPaths).toHaveLength(1);
    expect(route.sites.map((site) => site.role)).toEqual([
      "registration",
      "guard",
      "guard",
    ]);
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
