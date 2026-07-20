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

  test("binds prototype members published through direct CommonJS root assignments", () => {
    const sourceRef = "src/builtins/assert.js#exports:CallTracker.calls";
    const route = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.builtin.assert.call-tracker.calls",
        observedKey: "builtin:export:node_assert:CallTracker.calls",
        targetVariant: "main",
      },
      [sourceRef],
    );
    expect(route.status).toBe("executable");
    expect(route.producerPaths).toHaveLength(1);
    expect(route.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "registration",
      "publication",
    ]);
    const source = fs.readFileSync("src/builtins/assert.js");
    expect(source.subarray(route.sites[0].startByte, route.sites[0].endByte).toString())
      .toContain("CallTracker.prototype.calls");
    expect(source.subarray(route.sites[2].startByte, route.sites[2].endByte).toString())
      .toContain("module.exports.CallTracker");
  });

  test("keeps conditioned CommonJS module publications as distinct export paths", () => {
    const route = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.builtin.process.argv",
        observedKey: "builtin:export:exact_process:argv",
        targetVariant: "main",
      },
      ["src/builtins/process.js#exports:argv"],
    );
    expect(route.status).toBe("executable");
    expect(route.producerPaths).toHaveLength(2);
    expect(new Set(route.producerPaths.map((path) => path.conditionId)).size).toBe(2);
    const source = fs.readFileSync("src/builtins/process.js");
    const publications = route.sites.filter((site) => site.role === "publication")
      .map((site) => source.subarray(site.startByte, site.endByte).toString());
    expect(publications.some((value) => value.includes("module.exports = proc"))).toBe(true);
    expect(publications.some((value) => value.includes("module.exports = {"))).toBe(true);
  });

  test("binds computed prototype copies and their public publication", () => {
    const route = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.builtin.buffer.ascii-slice",
        observedKey: "builtin:export:node_buffer:Buffer.asciiSlice",
        targetVariant: "all",
      },
      ["src/builtins/buffer.js#exports:Buffer.asciiSlice"],
    );
    expect(route.status).toBe("executable");
    const source = fs.readFileSync("src/builtins/buffer.js");
    expect(route.sites.some((site) =>
      source.subarray(site.startByte, site.endByte).toString().includes("BufferProto.asciiSlice"),
    )).toBe(true);
    expect(route.sites.map((site) => site.role)).toContain("alias");
  });

  test("binds constructor-installed instance methods through their initializer", () => {
    const route = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.builtin.readline.interface-on-data",
        observedKey: "builtin:export:node_readline:Interface._onData",
        targetVariant: "all",
      },
      ["src/builtins/readline.js#exports:Interface._onData"],
    );
    expect(route.status).toBe("executable");
    expect(route.sites.map((site) => site.role)).toEqual(
      expect.arrayContaining(["value-producer", "registration", "publication"]),
    );
    const source = fs.readFileSync("src/builtins/readline.js");
    expect(source.subarray(route.sites[0].startByte, route.sites[0].endByte).toString())
      .toContain("this._onData");
  });

  test("uses a legacy getter, not its setter, for a public property-read route", () => {
    const route = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.builtin.net.socket-bytes-written",
        observedKey: "builtin:export:node_net:Socket.bytesWritten",
        targetVariant: "all",
      },
      ["src/builtins/net.js#exports:Socket.bytesWritten"],
    );
    expect(route.status).toBe("executable");
    expect(route.producerPaths).toHaveLength(1);
    const source = fs.readFileSync("src/builtins/net.js");
    const producer = route.sites.find((site) => site.role === "value-producer");
    expect(source.subarray(producer.startByte, producer.endByte).toString())
      .toContain("__defineGetter__");
  });

  test("binds inherited dynamic tables through their exact prototype chain", () => {
    const sourceRef = "src/builtins/zlib.js#exports:BrotliCompress.[[dynamic-table:inherited-4a42ce205a0e-properties]]";
    const route = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.builtin.zlib.brotli-inherited",
        observedKey: "builtin:export:node_zlib:BrotliCompress.[[dynamic-table:inherited-4a42ce205a0e-properties]]",
        targetVariant: "all",
      },
      [sourceRef],
    );
    expect(route.status).toBe("executable");
    expect(route.sites.map((site) => site.role)).toContain("alias");
  });

  test("binds inline module exports to embedded code and both registrations", () => {
    const route = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.builtin.internal-fs-utils.bigint-stats",
        observedKey: "builtin:export:internal_fs_utils:BigIntStats.isBlockDevice",
        targetVariant: "all",
      },
      ["modules.ts#sources:internal_fs_utils:exports:BigIntStats.isBlockDevice"],
    );
    expect(route.status).toBe("executable");
    expect(route.sites.map((site) => site.role)).toEqual(
      expect.arrayContaining(["value-producer", "registration", "publication"]),
    );
  });

  test("binds getOwnPropertyNames prototype copies without inventing member literals", () => {
    const route = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.builtin.stream.duplex-write.corrected",
        observedKey: "builtin:export:node_stream:Duplex.write",
        targetVariant: "all",
      },
      ["src/builtins/stream.js#exports:Duplex.write"],
    );
    expect(route.status).toBe("executable");
    const source = fs.readFileSync("src/builtins/stream.js");
    expect(route.sites.some((site) =>
      source.subarray(site.startByte, site.endByte).toString()
        .includes("Object.getOwnPropertyNames(Writable.prototype)"),
    )).toBe(true);
  });

  test("rejects a prototype copy that discards the source descriptor", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-prototype-copy-"));
    try {
      fs.writeFileSync(path.join(root, "fixture.js"), `
function Base() {}
Base.prototype.write = function() {};
function Public() {}
Object.getOwnPropertyNames(Base.prototype).forEach(function(key) {
  var descriptor = Object.getOwnPropertyDescriptor(Base.prototype, key);
  Object.defineProperty(Public.prototype, key, { value: function unrelated() {} });
});
module.exports = { Public: Public };
`);
      const route = buildRestrictedExactBranchSourceRoute(
        {
          branchId: "surface.builtin.fixture.public-write",
          observedKey: "builtin:export:fixture:Public.write",
          targetVariant: "all",
        },
        ["fixture.js#exports:Public.write"],
        root,
      );
      expect(route.status).toBe("incomplete");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test.each([
    [
      "reassigned",
      "descriptor = { value: function unrelated() {} };",
    ],
    [
      "shadowed",
      "{ let descriptor = { value: function unrelated() {} }; Object.defineProperty(Public.prototype, key, descriptor); }",
    ],
  ])("rejects a prototype descriptor binding that is %s", (_label, mutation) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-prototype-binding-"));
    try {
      const define = mutation.startsWith("{")
        ? mutation
        : `${mutation}\n  Object.defineProperty(Public.prototype, key, descriptor);`;
      fs.writeFileSync(path.join(root, "fixture.js"), `
function Base() {}
Base.prototype.write = function() {};
function Public() {}
Object.getOwnPropertyNames(Base.prototype).forEach(function(key) {
  var descriptor = Object.getOwnPropertyDescriptor(Base.prototype, key);
  ${define}
});
module.exports = { Public: Public };
`);
      const route = buildRestrictedExactBranchSourceRoute(
        {
          branchId: `surface.builtin.fixture.public-write.${_label}`,
          observedKey: "builtin:export:fixture:Public.write",
          targetVariant: "all",
        },
        ["fixture.js#exports:Public.write"],
        root,
      );
      expect(route.status).toBe("incomplete");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test.each([
    ["reassigned", "key = 'unrelated';"],
    [
      "shadowed",
      "{ let key = 'unrelated'; Object.defineProperty(Public.prototype, key, Object.getOwnPropertyDescriptor(Base.prototype, key)); }",
    ],
  ])("rejects a prototype-copy key parameter that is %s", (_label, mutation) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-prototype-key-"));
    try {
      const define = mutation.startsWith("{")
        ? mutation
        : `${mutation}\n  Object.defineProperty(Public.prototype, key, Object.getOwnPropertyDescriptor(Base.prototype, key));`;
      fs.writeFileSync(path.join(root, "fixture.js"), `
function Base() {}
Base.prototype.write = function() {};
function Public() {}
Object.getOwnPropertyNames(Base.prototype).forEach(function(key) {
  ${define}
});
module.exports = { Public: Public };
`);
      const route = buildRestrictedExactBranchSourceRoute(
        {
          branchId: `surface.builtin.fixture.public-write.key-${_label}`,
          observedKey: "builtin:export:fixture:Public.write",
          targetVariant: "all",
        },
        ["fixture.js#exports:Public.write"],
        root,
      );
      expect(route.status).toBe("incomplete");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects a constructor helper that does not install its named property", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-constructor-helper-"));
    try {
      fs.writeFileSync(path.join(root, "fixture.js"), `
function observe(target, name) { return target && name; }
function Public() { observe(this, 'secret'); }
module.exports = { Public: Public };
`);
      const route = buildRestrictedExactBranchSourceRoute(
        {
          branchId: "surface.builtin.fixture.public-secret",
          observedKey: "builtin:export:fixture:Public.secret",
          targetVariant: "all",
        },
        ["fixture.js#exports:Public.secret"],
        root,
      );
      expect(route.status).toBe("incomplete");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test.each([
    ["reassigned", "target = {}; Object.defineProperty(target, name, { value: true });"],
    ["shadowed", "{ let target = {}; Object.defineProperty(target, name, { value: true }); }"],
  ])("rejects a constructor helper whose target parameter is %s", (_label, body) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-helper-binding-"));
    try {
      fs.writeFileSync(path.join(root, "fixture.js"), `
function install(target, name) { ${body} }
function Public() { install(this, 'secret'); }
module.exports = { Public: Public };
`);
      const route = buildRestrictedExactBranchSourceRoute(
        {
          branchId: `surface.builtin.fixture.public-secret.${_label}`,
          observedKey: "builtin:export:fixture:Public.secret",
          targetVariant: "all",
        },
        ["fixture.js#exports:Public.secret"],
        root,
      );
      expect(route.status).toBe("incomplete");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("binds the signal-number overlay through producer, assignment, and publication", () => {
    const route = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.builtin.constants.signal-number-overlay",
        observedKey: "builtin:export:node_constants:[[dynamic-table:signal-number-overlay]]",
        targetVariant: "all",
      },
      ["src/builtins/constants.js#exports:[[dynamic-table:signal-number-overlay]]"],
    );
    expect(route.status).toBe("executable");
    expect(route.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "dispatch",
      "publication",
    ]);
  });

  test("binds every builtin implementation branch to an executable source route", () => {
    const implementation = JSON.parse(
      fs.readFileSync("capsec/generated/implementation-manifest.json", "utf8"),
    );
    const incomplete = [];
    for (const branch of implementation.surfaces.filter(
      (surface) => surface.observedKey.startsWith("builtin:"),
    )) {
      const refs = [...new Set([
        ...branch.sourceRefs,
        ...branch.enforcementRoute.sourceRefs,
        ...branch.enforcementRoute.proofSourceRefs,
      ])];
      const route = buildRestrictedExactBranchSourceRoute(branch, refs);
      if (route.status !== "executable") {
        incomplete.push({ branchId: branch.branchId, unresolved: route.unresolved });
      }
    }
    expect(incomplete).toEqual([]);
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

  test("binds nested JSI object publications without borrowing a later root write", () => {
    for (const [observedKey, sourceRef, siteCount] of [
      [
        "native-op:global:exact.callModuleSync",
        "src/engine/hermes_runtime_ios.cc#jsi-global:exact.callModuleSync",
        3,
      ],
      [
        "native-op:global:process.release.name",
        "src/engine/hermes_runtime_process_setup.cc#jsi-global:process.release.name",
        4,
      ],
      [
        "native-op:global:process.stderr.write",
        "src/engine/hermes_runtime_process_setup.cc#jsi-global:process.stderr.write",
        4,
      ],
      [
        "native-op:global:process.stderr.columns",
        "src/engine/hermes_runtime_process_setup.cc#jsi-global:process.stderr.columns",
        4,
      ],
    ]) {
      const binding = resolveRestrictedExactBranchSourceBinding({
        branchId: `surface.${observedKey}`,
        observedKey,
        targetVariant: "default",
      }, sourceRef);
      expect(binding.locatorKind).toBe("jsi-root-global-route");
      expect(binding.producerPaths).toHaveLength(1);
      expect(binding.sites).toHaveLength(siteCount);
      expect(binding.sites[0].role).toBe("value-producer");
      expect(binding.sites.slice(1).every((site) => site.role === "publication")).toBe(true);
    }
  });

  test("binds preprocessor-selected JSI members as conditioned alternatives", () => {
    for (const [member, pathCount] of [["platform", 5], ["arch", 3]]) {
      const branch = {
        branchId: `surface.process.${member}.default`,
        observedKey: `native-op:global:process.${member}`,
        targetVariant: "default",
      };
      const sourceRef = `src/engine/hermes_runtime_process_setup.cc#jsi-global:process.${member}`;
      const binding = resolveRestrictedExactBranchSourceBinding(branch, sourceRef);
      expect(binding.locatorKind).toBe("jsi-conditional-root-member-route");
      expect(binding.producerPaths).toHaveLength(pathCount);
      expect(new Set(binding.producerPaths.map((entry) => entry.conditionId)).size).toBe(pathCount);
      expect(buildRestrictedExactBranchSourceRoute(branch, [sourceRef]).status).toBe("executable");
    }
    const envBranch = {
      branchId: "surface.process.env.default",
      observedKey: "native-op:global:process.env",
      targetVariant: "default",
    };
    const envRef = "src/engine/hermes_runtime_process_setup.cc#jsi-global:process.env";
    const env = resolveRestrictedExactBranchSourceBinding(envBranch, envRef);
    expect(env.locatorKind).toBe("jsi-process-env-route");
    expect(env.producerPaths).toHaveLength(2);
    expect(env.refusalPaths).toHaveLength(1);
    expect(buildRestrictedExactBranchSourceRoute(envBranch, [envRef]).status).toBe("executable");
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

  test("upgrades a plain native locator through the same exact JSI publication proof", () => {
    const branch = {
      branchId: "surface.native.op.exactaccess.windows",
      observedKey: "native-op:__exactAccess",
      targetVariant: "windows",
    };
    const binding = resolveRestrictedExactBranchSourceBinding(
      branch,
      "src/engine/hermes_runtime_fs_windows.cc#__exactAccess",
    );
    expect(binding.locatorKind).toBe("jsi-root-global-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "publication",
    ]);
  });

  test("prefers an explicit JSI locator over its duplicate plain locator", () => {
    const branch = {
      branchId: "surface.native.op.ex.p.default",
      observedKey: "native-op:__ex_p",
      targetVariant: "default",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "src/engine/hermes_runtime.cc#__ex_p",
      "src/engine/hermes_runtime.cc#jsi-global:__ex_p",
    ]);
    expect(route.status).toBe("executable");
    expect(route.producerPaths).toHaveLength(1);
    expect(route.bindingDispositions).toContainEqual({
      sourceRef: "src/engine/hermes_runtime.cc#__ex_p",
      disposition: "excluded-nonterminal-route",
      locatorKind: "jsi-root-global-route",
    });
  });

  test("binds script and patch identities to exact authority ranges", () => {
    const script = resolveRestrictedExactSourceBinding(
      "scripts/hermes-version.sh#IBEX_HERMES_ANDROID_VERSION",
    );
    expect(script.locatorKind).toBe("script-identity-authority");
    expect(script.sites).toHaveLength(1);
    const patch = resolveRestrictedExactSourceBinding(
      "patches/hermes/0001-domain-package-principal.patch#patch-content",
    );
    expect(patch.locatorKind).toBe("patch-payload-identity");
    expect(patch.sites).toHaveLength(1);
  });

  test("recomputes Hermes evaluator and lockdown identity authorities", () => {
    const evaluator = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.native.op.async-function.android",
      observedKey: "native-op:global:AsyncFunction",
      targetVariant: "android",
    }, "scripts/hermes-version.sh#evaluator-identity:sha256-a633ad80de5caf51ccd5642dcaee15b1d47cc907c34d2b2f30bfae5dccaf152a");
    expect(evaluator.locatorKind).toBe("hermes-evaluator-identity-authority");
    expect(evaluator.sites.every((site) => site.role === "identity-authority")).toBe(true);
    const lockdown = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.native.op.async-function.default",
      observedKey: "native-op:global:AsyncFunction",
      targetVariant: "default",
    }, "src/engine/hermes_runtime.cc#lockdown-taming:sha256-84bc50a29f721c540d8cf37b74f395d4afef63f0174df05bd40ec9b0e4486e8c");
    expect(lockdown.locatorKind).toBe("lockdown-taming-identity-authority");
    expect(() => resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.native.op.async-function.default",
      observedKey: "native-op:global:AsyncFunction",
      targetVariant: "default",
    }, "src/engine/hermes_runtime.cc#lockdown-taming:sha256-0000000000000000000000000000000000000000000000000000000000000000"))
      .toThrow(/missing, ambiguous, or unsupported/u);
  });

  test("binds legacy evaluator runners and typed global getters", () => {
    const legacy = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.native.op.date-constructor.default",
      observedKey: "native-op:global:Date.constructor",
      targetVariant: "default",
    }, "src/engine/hermes_bootstrap.cc#legacy-runner:runLegacyCompatPolyfills:sha256-85e5f64997c896a0b0fed5d1fdbb4903a17334b0e9a0bbe32c412ee13316e1ea");
    expect(legacy.locatorKind).toBe("legacy-native-evaluator-route");
    expect(legacy.sites.map((site) => site.role)).toEqual(["definition", "dispatch"]);
    for (const [observedKey, locator] of [
      ["native-op:global:crypto", "get:globals:crypto"],
      ["native-op:global:Bun.inspect", "get:globals:Exact.inspect"],
    ]) {
      const getter = resolveRestrictedExactBranchSourceBinding({
        branchId: `surface.${locator}`,
        observedKey,
        targetVariant: "all",
      }, `packages/ibex-runtime-js/src/bootstrap.ts#${locator}`);
      expect(getter.locatorKind).toBe("typescript-global-installer-route");
      expect(getter.sites.map((site) => site.role)).toEqual(["value-producer", "publication"]);
    }
    const lazy = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.readable-stream.default",
      observedKey: "native-op:global:ReadableStream",
      targetVariant: "default",
    }, "packages/ibex-runtime-js/src/bootstrap.ts#get:globals:ReadableStream");
    expect(lazy.locatorKind).toBe("typescript-global-installer-route");
    const staticNameBranch = {
      branchId: "surface.request-name.all",
      observedKey: "native-op:global:Request.name",
      targetVariant: "all",
    };
    const staticNameRef = "packages/ibex-runtime-js/src/fetch/Request.ts#Request.name";
    const staticName = resolveRestrictedExactBranchSourceBinding(staticNameBranch, staticNameRef);
    expect(staticName.locatorKind).toBe("typescript-static-descriptor-route");
    expect(buildRestrictedExactBranchSourceRoute(staticNameBranch, [staticNameRef]).status)
      .toBe("executable");
  });

  test("keeps legacy JavaScript symbols as exact supporting provenance", () => {
    const binding = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.native.op.dirname.default",
      observedKey: "native-op:__dirname",
      targetVariant: "default",
    }, "src/engine/bootstrap/module-loader.js#__dirname");
    expect(binding.locatorKind).toBe("javascript-symbol-provenance");
    expect(binding.sites.length).toBeGreaterThan(0);
    expect(binding.sites.every((site) => site.role === "symbol-provenance")).toBe(true);
  });

  test("models guarded legacy global assignments as distinct executable paths", () => {
    const branch = {
      branchId: "surface.native.op.global.badly.default",
      observedKey: "native-op:global:badly",
      targetVariant: "default",
    };
    const sourceRef = "src/engine/bootstrap/compat-polyfills.js#badly";
    const binding = resolveRestrictedExactBranchSourceBinding(branch, sourceRef);
    expect(binding.locatorKind).toBe("javascript-global-assignment-route");
    expect(binding.producerPaths).toHaveLength(2);
    expect(buildRestrictedExactBranchSourceRoute(branch, [sourceRef]).status).toBe("executable");
  });

  test("binds an object-literal global member without crediting its installer", () => {
    const branch = {
      branchId: "surface.native.op.global.atomics.add.all",
      observedKey: "native-op:global:Atomics.add",
      targetVariant: "all",
    };
    const binding = resolveRestrictedExactBranchSourceBinding(
      branch,
      "packages/ibex-runtime-js/src/bootstrap.ts#add.add",
    );
    expect(binding.locatorKind).toBe("typescript-object-member");
    expect(binding.sites).toHaveLength(1);
  });

  test("traces Exact and Bun members through factory and root alias publication", () => {
    for (const key of ["Exact.CryptoHasher.prototype.copy", "Bun.MD5.update", "Bun.password.hash"]) {
      const branch = {
        branchId: `surface.native.op.global.${key}.default`,
        observedKey: `native-op:global:${key}`,
        targetVariant: "default",
      };
      const sourceRef = `src/engine/bootstrap/exact-global.js#${key}`;
      const binding = resolveRestrictedExactBranchSourceBinding(branch, sourceRef);
      expect(binding.locatorKind).toBe("exact-global-alias-route");
      expect(binding.sites.at(-1).role).toBe("publication");
      expect(buildRestrictedExactBranchSourceRoute(branch, [sourceRef]).status).toBe("executable");
    }
  });

  test("composes an aliased producer leaf with the published global root", () => {
    const branch = {
      branchId: "surface.native.op.global.bun.accessibility.colorScheme.all",
      observedKey: "native-op:global:Bun.accessibility.colorScheme",
      targetVariant: "all",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:Bun",
      "packages/ibex-runtime-js/src/core/accessibility.ts#createAccessibilityNamespace.colorScheme",
      "packages/ibex-runtime-js/src/core/accessibility.ts#installExactAccessibilityGlobal:globals:Exact.accessibility",
    ]);
    expect(route.status).toBe("executable");
  });

  test("binds evaluated C++ JavaScript through member, publication, and dispatch", () => {
    const fixtures = [
      ["fetch", "src/engine/hermes_runtime_fetch.cc#embedded:windowsFetchShim:fetch", "windows"],
      ["WebSocket.send", "src/engine/hermes_runtime_websocket.cc#embedded:windowsWebSocketShim:WebSocket.send", "windows"],
      ["process.__exactStreamStabilityPatched", "src/engine/hermes_runtime_process_setup.cc#embedded:streamStabilityPatchJS:process.__exactStreamStabilityPatched", "default"],
      ["worklet", "src/engine/hermes_runtime_worklet.cc#embedded:kPrelude:worklet", "worklet"],
    ];
    for (const [key, sourceRef, targetVariant] of fixtures) {
      const branch = {
        branchId: `surface.native.op.global.${key}.${targetVariant}`,
        observedKey: `native-op:global:${key}`,
        targetVariant,
      };
      const binding = resolveRestrictedExactBranchSourceBinding(branch, sourceRef);
      expect(binding.locatorKind).toBe("evaluated-cpp-global-route");
      expect(binding.sites.map((site) => site.role)).toEqual([
        "value-producer",
        "publication",
        "dispatch",
      ]);
      expect(buildRestrictedExactBranchSourceRoute(branch, [sourceRef]).status).toBe("executable");
    }
  });

  test("binds platform native definitions and Android dispatch as one route", () => {
    const definition = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.native.op.native.fetch.cancel.android",
      observedKey: "native-op:native_fetch_cancel",
      targetVariant: "android",
    }, "src/engine/native_android_networking.cc#definition:native_fetch_cancel");
    expect(definition.locatorKind).toBe("native-operation-definition");
    expect(definition.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "publication",
    ]);

    const route = buildRestrictedExactBranchSourceRoute({
      branchId: "surface.native.op.native.fetch.perform.android",
      observedKey: "native-op:native_fetch_perform",
      targetVariant: "android",
    }, [
      "src/engine/native_android_networking.cc#definition:native_fetch_perform",
      "src/engine/native_android_networking.cc#java-call:fetch:fetch",
      "src/engine/native_android_networking.cc#jni-callback:nativeFetchDidComplete:android_fetch_did_complete",
    ]);
    expect(route.status).toBe("executable");
    expect(route.producerPaths).toHaveLength(1);
    expect(route.producerPaths[0].conditionId).toBe("target-platform:android");
  });

  test("keeps multiple exact JSI publications as conditioned alternatives", () => {
    const binding = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.native.op.exactarch.windows",
      observedKey: "native-op:__exactArch",
      targetVariant: "windows",
    }, "src/engine/hermes_runtime_platform_windows.cc#jsi-global:__exactArch");
    expect(binding.locatorKind).toBe("jsi-root-global-route");
    expect(binding.producerPaths).toHaveLength(2);
    expect(new Set(binding.producerPaths.map((pathEntry) => pathEntry.conditionId)).size).toBe(2);
  });

  test("classifies runtime if/else JSI publications as paired alternatives", () => {
    const binding = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.native.op.initial-url.android",
      observedKey: "native-op:__exactInitialURL",
      targetVariant: "android",
    }, "src/engine/hermes_runtime_android.cc#jsi-global:__exactInitialURL");
    expect(binding.locatorKind).toBe("jsi-root-global-route");
    expect(binding.producerPaths).toHaveLength(2);
    expect(binding.producerPaths.map((pathEntry) => pathEntry.conditionId)).toEqual([
      expect.stringMatching(/^runtime-if:/u),
      expect.stringMatching(/^runtime-else:/u),
    ]);
  });

  test("binds generated defineProperty globals through their installer invocation", () => {
    for (const locator of [
      "__exactGeneratedImportGrantKeys",
      "__exactGeneratedImportGrantKeys.[[dynamic]]",
    ]) {
      const binding = resolveRestrictedExactBranchSourceBinding({
        branchId: "surface.native.op.generated-import-grants.all",
        observedKey: "native-op:__exactGeneratedImportGrantKeys",
        targetVariant: "all",
      }, `src/engine/bootstrap/import-grant-keys.generated.js#${locator}`);
      expect(binding.locatorKind).toBe("generated-javascript-global-route");
      expect(binding.sites.map((site) => site.role)).toEqual([
        "value-producer",
        "publication",
        "dispatch",
      ]);
    }
  });

  test("binds module runtime metadata members through their global object publication", () => {
    for (const [observedKey, locator] of [
      ["native-op:__exactRuntime.engine", "<module>.engine"],
      ["native-op:global:exact.runtime.detectEngine", "<module>.detectEngine"],
      ["native-op:global:exact.runtime.info.engine", "<module>.info"],
    ]) {
      const binding = resolveRestrictedExactBranchSourceBinding({
        branchId: `surface.${locator}.${observedKey}`,
        observedKey,
        targetVariant: "all",
      }, `packages/ibex-runtime-js/src/runtime-entry.ts#${locator}`);
      expect(binding.locatorKind).toBe("typescript-module-global-member-route");
      expect(binding.sites.map((site) => site.role)).toEqual([
        "value-producer",
        "publication",
      ]);
    }
  });

  test("traces ExactBundle members through module object declarations", () => {
    for (const pathValue of [
      "ExactBundle.installGlobals",
      "ExactBundle.runtimeInfo",
      "ExactBundle.runtimeInfo.engine",
    ]) {
      const leaf = pathValue.split(".").at(-1);
      const sourceRef = `packages/ibex-runtime-js/src/bootstrap.ts#<module>.${leaf}`;
      const branch = {
        branchId: `surface.${pathValue}`,
        observedKey: `native-op:global:${pathValue}`,
        targetVariant: "all",
      };
      const binding = resolveRestrictedExactBranchSourceBinding(branch, sourceRef);
      expect(binding.locatorKind).toBe("typescript-bundle-member-route");
      expect(binding.targetGlobalPath).toBe(pathValue);
      expect(binding.sites.map((site) => site.role)).toEqual(["value-producer", "publication"]);
      expect(buildRestrictedExactBranchSourceRoute(branch, [sourceRef]).status).toBe("executable");
    }
    const supporting = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.exact.runtime.info.engine",
      observedKey: "native-op:global:exact.runtime.info.engine",
      targetVariant: "all",
    }, "packages/ibex-runtime-js/src/bootstrap.ts#<module>.engine");
    expect(supporting.locatorKind).toBe("typescript-module-object-member-provenance");
    expect(supporting.producerPaths).toEqual([]);
  });

  test("resolves installer-local aliases for nested Intl publications", () => {
    const sourceRef = "packages/ibex-runtime-js/src/polyfills/intl.ts#installIntlPolyfills:globals:Intl.DateTimeFormat.prototype.formatToParts";
    const memberBranch = {
      branchId: "surface.native.op.intl.datetime-format-parts.all",
      observedKey: "native-op:global:Intl.DateTimeFormat.prototype.formatToParts",
      targetVariant: "all",
    };
    const binding = resolveRestrictedExactBranchSourceBinding(memberBranch, sourceRef);
    expect(binding.locatorKind).toBe("typescript-global-installer-route");
    expect(binding.sites.map((site) => site.role)).toEqual(["value-producer", "publication"]);
    expect(buildRestrictedExactBranchSourceRoute(memberBranch, [sourceRef]).status).toBe("executable");
    const ancestor = buildRestrictedExactBranchSourceRoute({
      ...memberBranch,
      branchId: "surface.native.op.intl.datetime-format.all",
      observedKey: "native-op:global:Intl.DateTimeFormat",
    }, [sourceRef]);
    expect(ancestor.status).toBe("executable");
    expect(ancestor.bindingDispositions[0].disposition).toBe("selected-route");
  });

  test("binds module-level global assignments and C++ supporting symbols", () => {
    const moduleBinding = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.native.op.android.dispatch.all",
      observedKey: "native-op:__exactAndroidDispatchPlatformEvent",
      targetVariant: "all",
    }, "packages/ibex-runtime-js/src/window/index.ts#<module>:globals:__exactAndroidDispatchPlatformEvent");
    expect(moduleBinding.locatorKind).toBe("typescript-global-installer-route");
    const cppBinding = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.native.op.compartments.default",
      observedKey: "native-op:__compartments",
      targetVariant: "default",
    }, "src/engine/hermes_module_runner.cc#__compartments");
    expect(cppBinding.locatorKind).toBe("cpp-symbol-provenance");
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
      "value-producer",
      "publication",
    ]);
  });

  test("composes an inherited global member with its lazy publication", () => {
    const route = buildRestrictedExactBranchSourceRoute({
      branchId: "surface.native.op.global.broadcastchannel.addeventlistener.all",
      observedKey: "native-op:global:BroadcastChannel.addEventListener",
      targetVariant: "all",
    }, [
      "packages/ibex-runtime-js/src/bootstrap.ts#defineLazyGlobal:globals:BroadcastChannel",
      "packages/ibex-runtime-js/src/events/EventTarget.ts#EventTarget.prototype.addEventListener",
    ]);
    expect(route.status).toBe("executable");
    expect(route.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "lazy-trigger",
    ]);
  });

  test("composes a root global from its exact lazy factory publication", () => {
    const route = buildRestrictedExactBranchSourceRoute({
      branchId: "surface.native.op.global.broadcastchannel.all",
      observedKey: "native-op:global:BroadcastChannel",
      targetVariant: "all",
    }, [
      "packages/ibex-runtime-js/src/bootstrap.ts#defineLazyGlobal:globals:BroadcastChannel",
    ]);
    expect(route.status).toBe("executable");
    expect(route.producerPaths).toHaveLength(1);
  });

  test("retains a direct JSI global route while composing the global family", () => {
    const route = buildRestrictedExactBranchSourceRoute({
      branchId: "surface.native.op.global.console.debug.default",
      observedKey: "native-op:global:console.debug",
      targetVariant: "default",
    }, ["src/engine/hermes_runtime_console.cc#jsi-global:console.debug"]);
    expect(route.status).toBe("executable");
    expect(route.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "publication",
      "publication",
    ]);
  });

  test("binds a TypeScript installer to the exact global value and publication", () => {
    const branch = {
      branchId: "surface.native.op.accessibility.changed.all",
      observedKey: "native-op:__exactAccessibilityChanged",
      targetVariant: "all",
    };
    const sourceRef = "packages/ibex-runtime-js/src/core/accessibility.ts#installExactAccessibilityGlobal:globals:__exactAccessibilityChanged";
    const binding = resolveRestrictedExactBranchSourceBinding(branch, sourceRef);
    expect(binding.locatorKind).toBe("typescript-global-installer-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "publication",
    ]);
    expect(buildRestrictedExactBranchSourceRoute(branch, [sourceRef]).status).toBe("executable");
  });

  test("does not let a root installer route stand in for a nested global member", () => {
    const route = buildRestrictedExactBranchSourceRoute({
      branchId: "surface.native.op.global.intl.locale.all",
      observedKey: "native-op:global:Intl.Locale",
      targetVariant: "all",
    }, ["packages/ibex-runtime-js/src/polyfills/intl.ts#installIntlPolyfills:globals:Intl"]);
    expect(route.status).toBe("incomplete");
  });

  test("binds a public accessor pair without confusing a private homonym", () => {
    const binding = resolveRestrictedExactBranchSourceBinding({
      branchId: "surface.native.op.global.url.hash.all",
      observedKey: "native-op:global:URL.hash",
      targetVariant: "all",
    }, "packages/ibex-runtime-js/src/url/URL.ts#URL.prototype.hash");
    expect(binding.locatorKind).toBe("typescript-class-member");
    expect(binding.sites).toHaveLength(2);
    expect(binding.sites.every((site) => site.role === "value-producer")).toBe(true);
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

  test("binds exported ABI functions whose signatures contain nested callback syntax", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.host.abi.ex.hermes.destroy.0m27uxn.default",
        observedKey: "host-abi:ex_hermes_destroy",
        targetVariant: "default",
      },
      "src/engine/hermes_runtime.cc#ex_hermes_destroy",
    );
    expect(binding.locatorKind).toBe("exported-host-abi");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "publication",
    ]);
  });

  test("binds the outer Android Java method without selecting its nested provider homonym", () => {
    const branch = {
      branchId: "surface.host.abi.java.camera-host-call",
      observedKey: "host-abi:java:dev.ibex.runtime.IbexNetworking.cameraHostCall",
      targetVariant: "main",
    };
    const binding = resolveRestrictedExactBranchSourceBinding(
      branch,
      "platform/android/java/dev/ibex/runtime/IbexNetworking.java#java:dev.ibex.runtime.IbexNetworking.cameraHostCall",
    );
    expect(binding.locatorKind).toBe("android-java-method-route");
    const source = fs.readFileSync("platform/android/java/dev/ibex/runtime/IbexNetworking.java");
    const declaration = source.subarray(binding.sites[0].startByte, binding.sites[0].endByte).toString();
    expect(declaration).toContain("public static String cameraHostCall");
    expect(declaration).toContain("CameraHostProvider provider");
  });

  test("binds a nested Android Java provider interface method exactly", () => {
    const branch = {
      branchId: "surface.host.abi.java.camera-provider-call",
      observedKey: "host-abi:java:dev.ibex.runtime.IbexNetworking.CameraHostProvider.cameraHostCall",
      targetVariant: "main",
    };
    const binding = resolveRestrictedExactBranchSourceBinding(
      branch,
      "platform/android/java/dev/ibex/runtime/IbexNetworking.java#java:dev.ibex.runtime.IbexNetworking.CameraHostProvider.cameraHostCall",
    );
    const source = fs.readFileSync("platform/android/java/dev/ibex/runtime/IbexNetworking.java");
    const declaration = source.subarray(binding.sites[0].startByte, binding.sites[0].endByte).toString();
    expect(declaration).toMatch(/^String cameraHostCall/u);
    expect(declaration).toMatch(/throws Exception;$/u);
    expect(declaration).not.toContain("CameraHostProvider provider");
  });

  test("composes Android Java publication, method retention, and JNI dispatch", () => {
    const branch = {
      branchId: "surface.host.abi.java.accessibility-flags",
      observedKey: "host-abi:java:dev.ibex.runtime.IbexNetworking.accessibilityFlags",
      targetVariant: "main",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "platform/android/java/dev/ibex/runtime/IbexNetworking.java#java:dev.ibex.runtime.IbexNetworking.accessibilityFlags",
      "src/engine/native_android_networking.cc#java-call:accessibilityFlags:accessibilityFlags",
    ]);
    expect(route.status).toBe("executable");
    expect(route.producerPaths).toHaveLength(1);
    expect(route.sites.map((site) => site.role)).toEqual([
      "definition",
      "publication",
      "registration",
      "retention",
      "dispatch",
    ]);
  });

  test("keeps Android storage-path initialization and runtime calls as exact alternatives", () => {
    const branch = {
      branchId: "surface.host.abi.java.storage-paths",
      observedKey: "host-abi:java:dev.ibex.runtime.IbexNetworking.storagePaths",
      targetVariant: "main",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "platform/android/java/dev/ibex/runtime/IbexNetworking.java#java:dev.ibex.runtime.IbexNetworking.storagePaths",
      "src/engine/native_android_networking.cc#java-call:storagePaths:storagePaths",
    ]);
    expect(route.status).toBe("executable");
    expect(route.producerPaths.map((producerPath) => producerPath.conditionId)).toEqual([
      "android-java-call:direct-cache",
      "android-java-call:retained-method",
    ]);
  });

  test("composes a registered JNI callback through Java declaration, table entry, and target", () => {
    const branch = {
      branchId: "surface.host.abi.jni.fetch-complete",
      observedKey: "host-abi:jni:dev.ibex.runtime.IbexNetworking.nativeFetchDidComplete",
      targetVariant: "main",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "platform/android/java/dev/ibex/runtime/IbexNetworking.java#jni:dev.ibex.runtime.IbexNetworking.nativeFetchDidComplete",
      "src/engine/native_android_networking.cc#jni-callback:nativeFetchDidComplete:android_fetch_did_complete",
    ]);
    expect(route.status).toBe("executable");
    expect(route.sites.map((site) => site.role)).toEqual([
      "definition",
      "publication",
      "value-producer",
      "registration",
      "publication",
    ]);
    const source = fs.readFileSync("src/engine/native_android_networking.cc");
    expect(source.subarray(route.sites[3].startByte, route.sites[3].endByte).toString()).toContain(
      "nativeFetchDidComplete",
    );
    expect(source.subarray(route.sites[4].startByte, route.sites[4].endByte).toString()).toContain(
      "env->RegisterNatives",
    );
  });

  test("composes a direct exported JNI callback", () => {
    const branch = {
      branchId: "surface.host.abi.jni.animation-frame",
      observedKey: "host-abi:jni:dev.ibex.runtime.IbexNetworking.nativeAnimationFrame",
      targetVariant: "main",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "platform/android/java/dev/ibex/runtime/IbexNetworking.java#jni:dev.ibex.runtime.IbexNetworking.nativeAnimationFrame",
      "src/engine/native_android_networking.cc#jni-callback:nativeAnimationFrame:Java_dev_ibex_runtime_IbexNetworking_nativeAnimationFrame",
    ]);
    expect(route.status).toBe("executable");
    expect(route.bindingDispositions.every(({ disposition }) => disposition === "selected-route")).toBe(true);
  });

  test("binds every host ABI implementation branch to an executable source route", () => {
    const implementation = JSON.parse(
      fs.readFileSync("capsec/generated/implementation-manifest.json", "utf8"),
    );
    const incomplete = [];
    for (const branch of implementation.surfaces.filter(
      (surface) => surface.observedKey.startsWith("host-abi:"),
    )) {
      const refs = [...new Set([
        ...branch.sourceRefs,
        ...branch.enforcementRoute.sourceRefs,
        ...branch.enforcementRoute.proofSourceRefs,
      ])];
      const route = buildRestrictedExactBranchSourceRoute(branch, refs);
      if (route.status !== "executable") {
        incomplete.push({ branchId: branch.branchId, unresolved: route.unresolved });
      }
    }
    expect(incomplete).toEqual([]);
  });

  test("binds a callback producer to its exact runtime-queue publication call", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.callback.producer.android-animation-frame",
        observedKey: "callback:producer:src/engine/hermes_runtime_android.cc:android_animation_frame_callback:pushRuntimeCallback",
        targetVariant: "android",
      },
      "src/engine/hermes_runtime_android.cc#android_animation_frame_callback:pushRuntimeCallback",
    );
    expect(binding.locatorKind).toBe("callback-producer-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "publication",
    ]);
    const source = fs.readFileSync("src/engine/hermes_runtime_android.cc");
    expect(
      source.subarray(binding.sites[1].startByte, binding.sites[1].endByte).toString(),
    ).toMatch(/^pushRuntimeCallback\(/u);
  });

  test("binds every WebSocket callback producer call without crediting comments", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.callback.producer.websocket",
        observedKey: "callback:producer:src/engine/hermes_runtime_websocket.cc:installWebSocketGlobals:pushRuntimeCallback",
        targetVariant: "main",
      },
      "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals:pushRuntimeCallback",
    );
    expect(binding.sites).toHaveLength(7);
    expect(binding.sites.slice(1).every((site) => site.role === "publication")).toBe(true);
    const source = fs.readFileSync("src/engine/hermes_runtime_websocket.cc");
    for (const site of binding.sites.slice(1)) {
      expect(source.subarray(site.startByte, site.endByte).toString()).toMatch(
        /^pushRuntimeCallback\(/u,
      );
    }
  });

  test("binds callback delivery through exact producer, retention, and queue dispatch", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.callback.dns.async.delivery.0t5h1ll.main",
        observedKey: "callback:dns-async-delivery",
        targetVariant: "main",
      },
      "src/engine/hermes_runtime_dns.cc#startDnsAsync",
    );
    expect(binding.locatorKind).toBe("callback-delivery-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "value-producer",
      "publication",
      "definition",
      "retention",
      "definition",
      "dispatch",
    ]);
    expect(binding.sites.slice(-4).map((site) => site.path)).toEqual([
      "src/engine/hermes_runtime.cc",
      "src/engine/hermes_runtime.cc",
      "src/engine/hermes_runtime.cc",
      "src/engine/hermes_runtime.cc",
    ]);
  });

  test("keeps POSIX and Windows filesystem callback deliveries target-conditioned", () => {
    const branch = {
      branchId: "surface.callback.filesystem.async.delivery.1ia1gd5.main",
      edgeId: "surface.callback.filesystem.async.delivery.1ia1gd5",
      observedKey: "callback:filesystem-async-delivery",
      targetVariant: "main",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "src/engine/hermes_runtime_fs.cc#startFsAsync",
      "src/engine/hermes_runtime_fs_windows.cc#startFsAsync",
    ]);
    expect(route.status).toBe("executable");
    expect(route.resolutionPolicy).toBe("conditioned-alternatives");
    expect(route.producerPaths.map((producerPath) => producerPath.conditionId).sort()).toEqual([
      "target-platform:not-windows",
      "target-platform:windows",
    ]);
  });

  test("binds callback setters through exact ABI registration and retained slots", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.callback.ios.dispatch.main",
        observedKey: "callback:ios-dispatch",
        targetVariant: "main",
      },
      "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_callback",
    );
    expect(binding.locatorKind).toBe("callback-setter-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "registration",
      "publication",
      "retention",
    ]);
  });

  test("keeps platform-specific microtask dispatches as distinct source paths", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.callback.microtask.drain",
        observedKey: "callback:microtask-drain",
        targetVariant: "all",
      },
      "src/engine/hermes_runtime.cc#drainMicrotasks",
    );
    expect(binding.locatorKind).toBe("callback-direct-dispatch-route");
    expect(binding.producerPaths.map((producerPath) => producerPath.conditionId)).toEqual([
      "target-platform:windows",
      "target-platform:not-windows",
    ]);
    expect(binding.sites.map((site) => site.role)).toEqual([
      "registration",
      "dispatch",
      "dispatch",
    ]);
  });

  test("binds callback queue drain through retention transfer and exact invocation", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.callback.queue.drain",
        observedKey: "callback:queue-drain",
        targetVariant: "all",
      },
      "src/engine/hermes_runtime.cc#drainCallbackQueue",
    );
    expect(binding.locatorKind).toBe("callback-direct-dispatch-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "registration",
      "retention",
      "dispatch",
    ]);
  });

  test("binds timer callback alternatives through the public poll entry", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.callback.timer.invoke",
        observedKey: "callback:timer-invoke",
        targetVariant: "all",
      },
      "src/engine/hermes_runtime.cc#ex_hermes_poll",
    );
    expect(binding.locatorKind).toBe("callback-timer-dispatch-route");
    expect(binding.producerPaths.map((producerPath) => producerPath.conditionId)).toEqual([
      "timer-callback:without-arguments",
      "timer-callback:with-arguments",
    ]);
  });

  test("binds native-principal restoration to the exact RAII destructor write", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.callback.native.principal.restore",
        observedKey: "callback:native-principal-restore",
        targetVariant: "all",
      },
      "src/engine/hermes_runtime_internal.h#ScopedNativePrincipal",
    );
    expect(binding.locatorKind).toBe("callback-native-principal-restore-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "registration",
      "publication",
      "dispatch",
    ]);
  });

  test("keeps direct and owner-thread WebSocket context releases distinct", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.callback.websocket.context.release",
        observedKey: "callback:websocket-context-release",
        targetVariant: "all",
      },
      "src/engine/hermes_runtime.cc#native_ws_release_context",
    );
    expect(binding.locatorKind).toBe("callback-context-release-route");
    expect(binding.producerPaths.map((producerPath) => producerPath.conditionId)).toEqual([
      "callback-release:on-runtime-thread",
      "callback-release:off-runtime-thread",
    ]);
  });

  test("composes signal watcher, callback queue, and JS delivery outcomes", () => {
    const branch = {
      branchId: "surface.callback.signal.delivery",
      edgeId: "surface.callback.signal.delivery",
      observedKey: "callback:signal-delivery",
      targetVariant: "main",
    };
    const route = buildRestrictedExactBranchSourceRoute(branch, [
      "src/engine/bootstrap/stream-enhance.js#__exactDispatchPendingSignals",
      "src/engine/hermes_runtime_crypto.cc#signalWatcherThreadMain",
    ]);
    expect(route.status).toBe("executable");
    expect(route.producerPaths.map((producerPath) => producerPath.conditionId)).toEqual([
      "signal-listener:present",
      "signal-listener:absent",
    ]);
    expect(route.sites.map((site) => site.path)).toContain(
      "src/engine/bootstrap/stream-enhance.js",
    );
    expect(route.sites.map((site) => site.path)).toContain(
      "src/engine/hermes_runtime_crypto.cc",
    );
  });

  test("binds every callback implementation branch to an executable source route", () => {
    const implementation = JSON.parse(
      fs.readFileSync("capsec/generated/implementation-manifest.json", "utf8"),
    );
    const incomplete = [];
    for (const branch of implementation.surfaces.filter(
      (surface) => surface.observedKey.startsWith("callback:"),
    )) {
      const refs = [...new Set([
        ...branch.sourceRefs,
        ...branch.enforcementRoute.sourceRefs,
        ...branch.enforcementRoute.proofSourceRefs,
      ])];
      const route = buildRestrictedExactBranchSourceRoute(branch, refs);
      if (route.status !== "executable") {
        incomplete.push({ branchId: branch.branchId, unresolved: route.unresolved });
      }
    }
    expect(incomplete).toEqual([]);
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

  test("binds a generated CLI option to its exact command-local object", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.cli.option.run.inspect-port",
        observedKey: "cli:option:ibex%20run:inspect_port",
        targetVariant: "all",
      },
      "runtime-surface.json#clapSurface.command:ibex run:option:inspect_port",
    );
    expect(binding.locatorKind).toBe("cli-generated-surface-route");
    const source = fs.readFileSync("runtime-surface.json");
    const row = source.subarray(binding.sites[0].startByte, binding.sites[0].endByte).toString();
    expect(row).toContain('"id": "inspect_port"');
    expect(row).toContain('"valueNames"');
    expect(row).not.toContain('"path": "ibex compat"');
  });

  test("binds a CLI parser relation to its exact generated semantic row", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.cli.parser.run.inspect-port",
        observedKey: "cli:argument-parser:ibex%20run:inspect_port:unsigned-integer-u16",
        targetVariant: "all",
      },
      "runtime-surface.json#clapSurface.semanticRelations:parser:ibex run:inspect_port:unsigned-integer-u16",
    );
    const source = fs.readFileSync("runtime-surface.json");
    const row = source.subarray(binding.sites[0].startByte, binding.sites[0].endByte).toString();
    expect(row).toContain('"commandPath": "ibex run"');
    expect(row).toContain('"argumentId": "inspect_port"');
    expect(row).toContain('"parserKind": "unsigned-integer-u16"');
  });

  test("binds the default REPL load refusal without crediting an extension row", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.cli.repl.load.default",
        observedKey: "cli:repl-load-extension:default",
        targetVariant: "all",
      },
      "runtime-surface.json#replSurface.loadExtension:default",
    );
    const source = fs.readFileSync("runtime-surface.json");
    const row = source.subarray(binding.sites[0].startByte, binding.sites[0].endByte).toString();
    expect(row).toContain('"defaultDisposition": "refuse-unknown-or-extensionless"');
  });

  test("binds implicit input selection to authenticated program and REPL dispatches", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.cli.implicit-no-file-dispatch",
        observedKey: "cli:implicit-no-file-dispatch",
        targetVariant: "all",
      },
      "src/bin/ibex/main.rs#run",
    );
    expect(binding.locatorKind).toBe("cli-authenticated-ingress-route");
    expect(binding.producerPaths.map((producerPath) => producerPath.conditionId)).toEqual([
      "implicit-input:program-stdin",
      "implicit-input:interactive-repl",
    ]);
    expect(binding.sites.map((site) => site.role)).toEqual([
      "definition",
      "guard",
      "dispatch",
      "dispatch",
    ]);
  });

  test("binds every CLI implementation branch to an executable source route", () => {
    const implementation = JSON.parse(
      fs.readFileSync("capsec/generated/implementation-manifest.json", "utf8"),
    );
    const incomplete = [];
    for (const branch of implementation.surfaces.filter(
      (surface) => surface.observedKey.startsWith("cli:"),
    )) {
      const refs = [...new Set([
        ...branch.sourceRefs,
        ...branch.enforcementRoute.sourceRefs,
        ...branch.enforcementRoute.proofSourceRefs,
      ])];
      const route = buildRestrictedExactBranchSourceRoute(branch, refs);
      if (route.status !== "executable") {
        incomplete.push({ branchId: branch.branchId, unresolved: route.unresolved });
      }
    }
    expect(incomplete).toEqual([]);
  });

  test("binds variable-assigned loader functions to their exact bodies", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.loader.function.javascript.module-syntax",
        observedKey: "loader:function:javascript:looksLikeModuleSyntax",
        targetVariant: "all",
      },
      "src/engine/bootstrap/module-loader.js#looksLikeModuleSyntax",
    );
    expect(binding.locatorKind).toBe("loader-javascript-function");
    const source = fs.readFileSync("src/engine/bootstrap/module-loader.js");
    const definition = source.subarray(binding.sites[0].startByte, binding.sites[0].endByte).toString();
    expect(definition).toMatch(/^const looksLikeModuleSyntax = function/u);
  });

  test("binds global loader entry publication through its exact producer", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.loader.entry.exact-require",
        observedKey: "loader:entry:exact-require",
        targetVariant: "all",
      },
      "src/engine/bootstrap/module-loader.js#globalThis.__exactRequire",
    );
    expect(binding.locatorKind).toBe("loader-global-entry-route");
    const source = fs.readFileSync("src/engine/bootstrap/module-loader.js");
    expect(source.subarray(binding.sites[1].startByte, binding.sites[1].endByte).toString()).toContain(
      "globalThis.__exactRequire = exactRequire",
    );
  });

  test("binds loader internal routes through exact registration and dispatch", () => {
    for (const specifier of ["bun:internal-for-testing", "internal/util/debuglog"]) {
      const binding = resolveRestrictedExactBranchSourceBinding(
        {
          branchId: `surface.loader.internal.${specifier}`,
          observedKey: `loader:internal-route:${specifier}`,
          targetVariant: "all",
        },
        `src/engine/bootstrap/module-loader.js#internal-route:${specifier}`,
      );
      expect(binding.locatorKind).toBe("loader-internal-route");
      expect(binding.sites.some((site) => site.role === "registration")).toBe(true);
      expect(binding.sites.some((site) => site.role === "dispatch")).toBe(true);
    }
  });

  test("binds a lazy loader installer to its exact specifier selector and trigger", () => {
    const binding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.loader.lazy.fs-promises",
        observedKey: "loader:lazy-installer:__exactEnsureFs:node:fs/promises",
        targetVariant: "all",
      },
      "src/engine/bootstrap/module-loader.js#__exactEnsureFs:node:fs/promises",
    );
    expect(binding.locatorKind).toBe("loader-lazy-installer-route");
    expect(binding.sites.map((site) => site.role)).toEqual([
      "definition",
      "selector",
      "dispatch",
    ]);
  });

  test("binds nested and owner-ambiguous Rust loader operations exactly", () => {
    const someBinding = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.loader.external.resolution",
        observedKey: "loader:external-calls:resolution",
        targetVariant: "all",
      },
      "src/module_loader/mod.rs#resolve_package_import:external:call:Some:count-3",
    );
    expect(someBinding.locatorKind).toBe("loader-rust-external-call-route");
    expect(someBinding.producerPaths).toHaveLength(3);
    const ownedFd = resolveRestrictedExactBranchSourceBinding(
      {
        branchId: "surface.loader.operation.from-owned-fd",
        observedKey: "loader:operation:resolution:from-owned-fd",
        targetVariant: "all",
      },
      "src/module_loader/mod.rs#new:operation:qualified:std::fs::File::from",
    );
    expect(ownedFd.locatorKind).toBe("loader-rust-operation-route");
    expect(ownedFd.producerPaths).toHaveLength(1);
  });

  test("composes loader kind producers and keeps closed kinds as refusals", () => {
    const builtin = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.loader.kind.builtin",
        observedKey: "loader:kind:builtin",
        targetVariant: "all",
      },
      [
        "src/engine/bootstrap/module-loader.js#kind:builtin",
        "src/module_loader/mod.rs#kind:builtin",
      ],
    );
    expect(builtin.status).toBe("executable");
    expect(builtin.producerPaths.length).toBeGreaterThan(1);
    const wasm = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.loader.kind.wasm",
        observedKey: "loader:kind:wasm",
        targetVariant: "all",
      },
      ["src/module_loader/mod.rs#kind:wasm"],
    );
    expect(wasm.status).toBe("executable");
    expect(wasm.producerPaths).toEqual([]);
    expect(wasm.refusalPaths.length).toBeGreaterThan(0);
  });

  test("binds every loader implementation branch to an executable source route", () => {
    const implementation = JSON.parse(
      fs.readFileSync("capsec/generated/implementation-manifest.json", "utf8"),
    );
    const incomplete = [];
    for (const branch of implementation.surfaces.filter(
      (surface) => surface.observedKey.startsWith("loader:"),
    )) {
      const refs = [...new Set([
        ...branch.sourceRefs,
        ...branch.enforcementRoute.sourceRefs,
        ...branch.enforcementRoute.proofSourceRefs,
      ])];
      const route = buildRestrictedExactBranchSourceRoute(branch, refs);
      if (route.status !== "executable") {
        incomplete.push({ branchId: branch.branchId, unresolved: route.unresolved });
      }
    }
    expect(incomplete).toEqual([]);
  });

  test("binds startup environment access to an exact executable source range", () => {
    const branch = {
      branchId: "surface.startup.env.path.test",
      observedKey: "startup:env:PATH:rust:env::var_os",
      targetVariant: "main",
    };
    const sourceRef = "src/bin/ibex/runtime.rs#env::var_os:PATH:read";
    const route = buildRestrictedExactBranchSourceRoute(branch, [sourceRef]);
    expect(route.status).toBe("executable");
    expect(route.producerPaths).toHaveLength(1);
    expect(route.sites.map((site) => site.role)).toEqual(["value-producer", "dispatch"]);
    const source = fs.readFileSync("src/bin/ibex/runtime.rs");
    const selected = source.subarray(route.sites[0].startByte, route.sites[0].endByte).toString();
    expect(selected).toContain("PATH");
    expect(selected.length).toBeLessThan(source.length);
  });

  test("binds startup install calls and evaluated scripts to exact executable ranges", () => {
    const install = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.startup.install.test",
        observedKey: "startup:install-route:installGlobals:installFetchGlobals",
        targetVariant: "main",
      },
      ["src/engine/hermes_runtime.cc#installGlobals:installFetchGlobals"],
    );
    const evaluation = buildRestrictedExactBranchSourceRoute(
      {
        branchId: "surface.startup.evaluation.test",
        observedKey: "startup:evaluation:installGlobals:capability-hardening",
        targetVariant: "main",
      },
      ["src/engine/hermes_runtime.cc#installGlobals:evaluateJavaScript:<capability-hardening>"],
    );
    expect(install.status).toBe("executable");
    expect(evaluation.status).toBe("executable");
    const source = fs.readFileSync("src/engine/hermes_runtime.cc");
    expect(source.subarray(install.sites[0].startByte, install.sites[0].endByte).toString())
      .toContain("installFetchGlobals");
    expect(source.subarray(evaluation.sites[0].startByte, evaluation.sites[0].endByte).toString())
      .toContain("capability-hardening");
    expect(install.sites[0].endByte - install.sites[0].startByte).toBeLessThan(1_000);
    expect(evaluation.sites[0].endByte - evaluation.sites[0].startByte).toBeLessThan(1_000);
  });

  test("binds every startup implementation branch to an executable source route", () => {
    const implementation = JSON.parse(
      fs.readFileSync("capsec/generated/implementation-manifest.json", "utf8"),
    );
    const incomplete = [];
    for (const branch of implementation.surfaces.filter(
      (surface) => surface.observedKey.startsWith("startup:"),
    )) {
      const refs = [...new Set([
        ...branch.sourceRefs,
        ...branch.enforcementRoute.sourceRefs,
        ...branch.enforcementRoute.proofSourceRefs,
      ])];
      const route = buildRestrictedExactBranchSourceRoute(branch, refs);
      if (route.status !== "executable") {
        incomplete.push({ branchId: branch.branchId, unresolved: route.unresolved });
      }
    }
    expect(incomplete).toEqual([]);
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
