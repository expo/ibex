// @ref LLP 0022#7-capabilities-principals-and-affordance-parity — the
// generated install/registry/live-sweep join is exact and getter-free.

import { describe, expect, test } from "bun:test";
import {
  assertExactRootGlobalDispositionJoin,
  buildRootGlobalDispositionManifest,
  sweepReachableOwnDescriptors,
} from "./capsec-root-global-dispositions.mjs";

function surface(
  name,
  {
    globalName = name.replace(/^global:/u, "").split(".")[0],
    memberName = null,
    sourceRefs = [`native.cc#${name}`],
    targetVariant = "default",
    metadata = {},
  } = {},
) {
  const observedKey = `native-op:${name}`;
  return {
    kind: "native-op",
    name,
    observedKey,
    sourceRefs,
    metadata: {
      globalName,
      memberName,
      surfaceType: "global-api",
      sourceKey: "native_jsi_global",
      installationBranches: [
        {
          id: targetVariant,
          route: "native-jsi-global",
          routes: ["native-jsi-global"],
          sourceRefs,
          targetVariant,
        },
      ],
      ...metadata,
    },
  };
}

function edge(row, classification = "non-capability") {
  const edgeName = row.name
    .replace(/[^A-Za-z0-9]+/gu, ".")
    .replace(/^\.|\.$/gu, "")
    .toLowerCase();
  return {
    id: `edge.${edgeName}`,
    classification,
    surface: { kind: row.kind, name: row.name },
    ...(classification === "non-capability"
      ? { rationaleId: "test", rationale: "test row" }
      : classification === "closed"
        ? { cap: "closed:test" }
        : { effects: [{ cap: "test:effect" }] }),
  };
}

function coverage(rows) {
  return {
    coverageSchema: "ibex/capsec-coverage/1",
    profile: "ibex/capsec/1",
    edges: rows.map((row) => edge(row)),
  };
}

describe("root-global disposition manifest", () => {
  test("records stable branches, aliases, private consumers, and registry ids", () => {
    const rows = [
      surface("__exactExit"),
      surface("__exactFsMutationGuard"),
      surface("__exactGetCwd"),
      surface("__exactOnRejectionHandled"),
      surface("__exactOnUnhandledRejection"),
      surface("__exactSetCwd"),
      surface("global:process", { globalName: "process" }),
      surface("global:window", { globalName: "window" }),
    ];
    const manifest = buildRootGlobalDispositionManifest({
      globals: rows,
      coverage: coverage(rows),
    });
    const privateExit = manifest.rows.find(
      (row) => row.observedKey === "native-op:__exactExit",
    );
    expect(privateExit).toMatchObject({
      disposition: "private",
      privateConsumer: "runtime-process-lifecycle-adapter",
      installPhase: "native-install",
      liveExpectation: "absent",
      branch: { activation: "always" },
    });
    expect(privateExit.registryEdgeId).toBe("edge.exactexit");
    expect(privateExit.installId).toMatch(/^root-global\.exactexit\./u);
    expect(
      manifest.rows.find(
        (row) => row.observedKey === "native-op:__exactFsMutationGuard",
      ),
    ).toMatchObject({
      disposition: "private",
      privateConsumer: "trusted-fs-builtin",
      liveExpectation: "absent",
    });
    for (const observedKey of [
      "native-op:__exactGetCwd",
      "native-op:__exactOnRejectionHandled",
      "native-op:__exactOnUnhandledRejection",
      "native-op:__exactSetCwd",
    ]) {
      expect(
        manifest.rows.find((row) => row.observedKey === observedKey),
      ).toMatchObject({
        disposition: "private",
        privateConsumer: observedKey.includes("OnRejection") ||
          observedKey.includes("OnUnhandledRejection")
          ? "native-promise-rejection-checkpoint"
          : "trusted-path-process-builtins",
        liveExpectation: "absent",
      });
    }
    const window = manifest.rows.find(
      (row) => row.observedKey === "native-op:global:window",
    );
    expect(window.aliases.map((alias) => alias.root.value)).toEqual([
      "global",
      "globalThis",
      "self",
    ]);
    expect(assertExactRootGlobalDispositionJoin(manifest, rows, coverage(rows))).toBe(
      true,
    );
  });

  test("stable install ids do not depend on evidence path spelling", () => {
    const first = surface("global:process", {
      globalName: "process",
      sourceRefs: ["old.cc#process"],
    });
    const moved = surface("global:process", {
      globalName: "process",
      sourceRefs: ["new.cc#process"],
    });
    const id = (row) =>
      buildRootGlobalDispositionManifest({
        globals: [row],
        coverage: coverage([row]),
      }).rows[0].installId;
    expect(id(first)).toBe(id(moved));
  });

  test("native implementation evidence is scoped to its concrete branch", () => {
    const exact = surface("global:exact", {
      globalName: "exact",
      metadata: {
        sourceKey: "shared_runtime",
        installationBranches: [
          {
            id: "shared",
            routes: ["shared-runtime"],
            sourceRefs: ["runtime-entry.ts#exact"],
            targetVariant: "default",
          },
          {
            id: "ios",
            routes: ["native-jsi-global", "shared-runtime"],
            sourceRefs: ["hermes_runtime_ios.cc#exact"],
            targetVariant: "ios",
          },
        ],
      },
    });
    const manifest = buildRootGlobalDispositionManifest({
      globals: [exact],
      coverage: coverage([exact]),
    });
    expect(
      manifest.rows.find((row) => row.branch.targetVariant === "default")
        .nativeImplementation,
    ).toBe(false);
    expect(
      manifest.rows.find((row) => row.branch.targetVariant === "default")
        .branch.activation,
    ).toBe("shared-runtime-bundle");
    expect(
      manifest.rows.find((row) => row.branch.targetVariant === "ios")
        .nativeImplementation,
    ).toBe(true);
    expect(
      manifest.rows.find((row) => row.branch.targetVariant === "ios").branch
        .activation,
    ).toBe("always");
  });

  test("legacy bootstrap rows record fallback-only activation", () => {
    const performance = surface("global:Performance", {
      globalName: "Performance",
      sourceRefs: ["src/engine/bootstrap/bootstrap-globals.js#Performance"],
      metadata: {
        sourceKey: "global_static_api",
        installationBranches: [
          {
            id: "legacy",
            routes: ["legacy-bootstrap"],
            sourceRefs: [
              "src/engine/bootstrap/bootstrap-globals.js#Performance",
            ],
            targetVariant: "default",
          },
        ],
      },
    });
    const manifest = buildRootGlobalDispositionManifest({
      globals: [performance],
      coverage: coverage([performance]),
    });
    expect(manifest.rows[0].branch.activation).toBe(
      "legacy-runtime-fallback",
    );
  });

  test("records source-grounded conditional and non-bootstrap activations", () => {
    const conditional = [
      surface("global:Bun", {
        globalName: "Bun",
        metadata: {
          installationBranches: [
            {
              id: "shared",
              routes: ["shared-runtime"],
              sourceRefs: ["packages/ibex-runtime-js/src/bootstrap.ts#Bun"],
              targetVariant: "default",
            },
          ],
        },
      }),
      surface("__exactEcdsaSign"),
      surface("__nativeFetchSync"),
      surface("global:AsyncFunction", {
        globalName: "AsyncFunction",
        metadata: {
          installationBranches: [
            {
              id: "intrinsic",
              routes: ["hermes-intrinsic-source"],
              sourceRefs: ["src/engine/hermes_runtime.cc#AsyncFunction"],
              targetVariant: "default",
            },
          ],
        },
      }),
      surface("__exactNativeWrapState", {
        metadata: {
          installationBranches: [
            {
              id: "lazy",
              routes: ["legacy-bootstrap"],
              sourceRefs: ["src/engine/bootstrap/module-loader.js#__exactNativeWrapState"],
              targetVariant: "default",
            },
          ],
        },
      }),
      surface("__OriginalPromise", {
        metadata: {
          sourceKey: "shared_runtime",
          installationBranches: [
            {
              id: "fallback",
              routes: ["shared-runtime"],
              sourceRefs: [
                "packages/ibex-runtime-js/src/promise-rejection-tracking.ts#installPromiseRejectionTracking:globals:__OriginalPromise",
              ],
              targetVariant: "all",
            },
          ],
        },
      }),
      surface("__OriginalPromise.prototype.then", {
        globalName: "__OriginalPromise",
        memberName: "prototype.then",
        metadata: {
          sourceKey: "shared_runtime",
          installationBranches: [
            {
              id: "fallback",
              routes: ["shared-runtime"],
              sourceRefs: [
                "packages/ibex-runtime-js/src/promise-rejection-tracking.ts#installPromiseRejectionTracking:globals:__OriginalPromise",
              ],
              targetVariant: "all",
            },
          ],
        },
      }),
      surface("global:process.stdout.write", {
        globalName: "process",
        memberName: "stdout.write",
      }),
    ];
    const manifest = buildRootGlobalDispositionManifest({
      globals: conditional,
      coverage: coverage(conditional),
    });
    const activation = (root) =>
      manifest.rows.find((row) => row.property.root.value === root).branch
        .activation;
    expect(activation("Bun")).toBe("bun-compat-shared-runtime");
    expect(activation("__exactEcdsaSign")).toBe("openssl-crypto");
    expect(activation("__nativeFetchSync")).toBe("windows-native");
    expect(activation("AsyncFunction")).toBe("intrinsic-reference-only");
    expect(activation("__exactNativeWrapState")).toBe(
      "post-bootstrap-lazy",
    );
    expect(activation("__OriginalPromise")).toBe(
      "diagnostic-unarmed-promise-fallback",
    );
    expect(
      manifest.rows.find(
        (row) =>
          row.observedKey ===
          "native-op:__OriginalPromise.prototype.then",
      ).branch.activation,
    ).toBe("diagnostic-unarmed-promise-fallback");
    expect(
      manifest.rows.find(
        (row) => row.observedKey === "native-op:global:process.stdout.write",
      ).branch.activation,
    ).toBe("legacy-runtime-fallback");
    expect(manifest.status).toBe("enforced-by-armed-live-sweep");
  });

  test("missing, extra, and unresolved reachable rows fail closed", () => {
    const process = surface("global:process", { globalName: "process" });
    expect(() =>
      buildRootGlobalDispositionManifest({
        globals: [process],
        coverage: { ...coverage([]), edges: [] },
      }),
    ).toThrow(/missing CapSec registry classification/u);

    const extra = surface("global:Extra", { globalName: "Extra" });
    expect(() =>
      buildRootGlobalDispositionManifest({
        globals: [process],
        coverage: coverage([process, extra]),
      }),
    ).toThrow(/extra root-global rows/u);

    const unresolved = surface(
      "global:Bridge.[[dynamic-table:opaque-properties]]",
      {
        globalName: "Bridge",
        memberName: "[[dynamic-table:opaque-properties]]",
      },
    );
    expect(() =>
      buildRootGlobalDispositionManifest({
        globals: [unresolved],
        coverage: coverage([unresolved]),
      }),
    ).toThrow(/unresolved dynamic sentinel is root-reachable/u);
  });
});

describe("descriptor-only root-global live sweep", () => {
  test("covers symbols, aliases, prototypes, cycles, and never invokes a getter", () => {
    let getterCalls = 0;
    const symbol = Symbol("secret");
    const prototype = Object.create(null);
    Object.defineProperty(prototype, "nativeLike", {
      value() {},
      enumerable: false,
    });
    const root = Object.create(prototype);
    Object.defineProperty(root, "danger", {
      get() {
        getterCalls += 1;
        throw new Error("getter must not execute");
      },
      enumerable: false,
    });
    Object.defineProperty(root, symbol, { value: root, enumerable: false });
    root.alias = root;

    const swept = sweepReachableOwnDescriptors({ globalThis: root });
    expect(getterCalls).toBe(0);
    expect(swept.descriptors.some((row) => row.path.includes("danger"))).toBe(
      true,
    );
    expect(
      swept.descriptors.some((row) => row.path.includes("Symbol(secret)")),
    ).toBe(true);
    expect(
      swept.descriptors.some((row) => row.path.includes("[[Prototype]].nativeLike")),
    ).toBe(true);
    expect(swept.objectCount).toBeGreaterThan(1);
  });

  test("all traversal budgets are fail-closed", () => {
    const root = { child: { leaf: true } };
    expect(() =>
      sweepReachableOwnDescriptors({ globalThis: root }, { maxObjects: 1 }),
    ).toThrow(/object budget exceeded/u);
    expect(() =>
      sweepReachableOwnDescriptors(
        { globalThis: root },
        { maxDescriptors: 1 },
      ),
    ).toThrow(/descriptor budget exceeded/u);
    expect(() =>
      sweepReachableOwnDescriptors({ globalThis: root }, { maxDepth: 0 }),
    ).toThrow(/depth budget exceeded/u);
  });

  test("explicit descriptor leaves never execute Proxy reflection traps", () => {
    let ownKeyCalls = 0;
    const storage = new Proxy(
      {},
      {
        ownKeys() {
          ownKeyCalls += 1;
          throw new Error("effectful ownKeys must not execute");
        },
      },
    );
    const root = { localStorage: storage };
    const swept = sweepReachableOwnDescriptors(
      { globalThis: root },
      { descriptorLeafPaths: new Set(["globalThis.localStorage"]) },
    );
    expect(ownKeyCalls).toBe(0);
    expect(
      swept.descriptors.some(
        (descriptor) => descriptor.path === "globalThis.localStorage",
      ),
    ).toBe(true);
  });
});
