import { beforeAll, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import {
  auditInheritedIntrinsicAliasSources,
  buildInheritedIntrinsicAliasValidatorAccountSet,
  inheritedIntrinsicAliasProbe,
  inheritedIntrinsicAliasValidatorBindings,
  INHERITED_INTRINSIC_ALIAS_VALIDATOR_ACCOUNT_SCHEMA,
  INHERITED_INTRINSIC_ALIAS_FAMILIES,
  INHERITED_INTRINSIC_ALIAS_OBSERVATION_SCHEMA,
  INHERITED_INTRINSIC_ALIAS_OUTPUT_CATALOG_BINDINGS,
  INHERITED_INTRINSIC_ALIAS_REASON_CODE,
  INHERITED_INTRINSIC_ALIAS_RUNTIME_EXECUTION_REQUIRED,
  INHERITED_INTRINSIC_ALIAS_SOURCE_REVIEW_SCHEMA,
} from "./capsec-inherited-intrinsic-alias-accounts.mjs";
import {
  auditInheritedIntrinsicAliasBatchEvidence,
  auditInheritedIntrinsicAliasExecutionLedger,
  auditInheritedIntrinsicAliasTargetRecord,
  inheritedIntrinsicAliasExecutionPlan,
  INHERITED_INTRINSIC_ALIAS_BATCH_EVIDENCE_SCHEMA,
  INHERITED_INTRINSIC_ALIAS_EXECUTION_LEDGER_SCHEMA,
  INHERITED_INTRINSIC_ALIAS_EXECUTION_PLAN_SCHEMA,
  INHERITED_INTRINSIC_ALIAS_EXECUTOR_CONTRACT_DIGEST,
  INHERITED_INTRINSIC_ALIAS_LINUX_PROFILE_RECEIPT_CODE,
  INHERITED_INTRINSIC_ALIAS_MISSING_EXECUTION_CODE,
  INHERITED_INTRINSIC_ALIAS_LINKED_DEPENDENCY_CODE,
  INHERITED_INTRINSIC_ALIAS_PROFILE_PROVENANCE_CODE,
  INHERITED_INTRINSIC_ALIAS_SOURCE_CACHE_AUTHORITY_CODE,
  INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_ATTESTATION_CODE,
  INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_SCHEMA,
  INHERITED_INTRINSIC_ALIAS_WINDOWS_BUILD_AUTHORITY_CODE,
  INHERITED_INTRINSIC_ALIAS_WINDOWS_LOADED_IMAGE_CODE,
  HERMES_PROFILE_PROVENANCE_RECEIPT_SCHEMA,
} from "./capsec-inherited-intrinsic-alias-conformance.mjs";
import { discoverHermesEvaluatorIdentityProfiles } from "./capsec-surface-inventory.mjs";
import { canonicalJson } from "./capsec-contract.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const BUFFER_PATH = "packages/ibex-runtime-js/src/node/Buffer.ts";
const RUNTIME_BOOTSTRAP_PATH = "packages/ibex-runtime-js/src/bootstrap.ts";
const COMPAT_BOOTSTRAP_PATH = "src/engine/bootstrap/compat-polyfills.js";
const REQUIRED_PATHS = [
  BUFFER_PATH,
  RUNTIME_BOOTSTRAP_PATH,
  COMPAT_BOOTSTRAP_PATH,
];

const readText = (relativePath) =>
  fs.readFileSync(path.join(repoRoot, relativePath), "utf8");

function replaceExact(source, before, after, label) {
  const start = source.indexOf(before);
  if (start === -1 || source.indexOf(before, start + before.length) !== -1) {
    throw new Error(`${label}: expected one mutation target`);
  }
  return source.slice(0, start) + after + source.slice(start + before.length);
}

function syntheticRealm(profileId = "android-maven") {
  const context = vm.createContext({});
  const installCompatSharedArrayBuffer = profileId === "android-maven";
  const emulateHermesNativeSharedArrayBuffer = profileId === "source-patched";
  vm.runInContext(
    `
      (() => {
        const NativeUint8Array = globalThis.Uint8Array;
        class TranspilerBufferBase extends NativeUint8Array {}
        class ExactBuffer extends TranspilerBufferBase {
          static implementationFixture() { return 1; }
          bufferPrototypeFixture() { return 2; }
        }
        function Buffer(value) {
          return new ExactBuffer(value === undefined ? 0 : value);
        }
        Object.setPrototypeOf(Buffer, ExactBuffer);
        Object.defineProperty(Buffer, "prototype", {
          value: ExactBuffer.prototype,
          writable: false,
          configurable: false,
        });
        Object.defineProperty(Buffer, "wrapperFixture", {
          value: true,
          writable: false,
          configurable: true,
        });
        Object.defineProperty(globalThis, "Buffer", {
          value: Buffer,
          writable: true,
          configurable: true,
          enumerable: true,
        });

        function WrappedUint8Array(...args) {
          return Reflect.construct(NativeUint8Array, args, new.target);
        }
        WrappedUint8Array.prototype = NativeUint8Array.prototype;
        Object.setPrototypeOf(WrappedUint8Array, NativeUint8Array);
        Object.defineProperty(WrappedUint8Array, "__exactSharedArrayBufferWrapped", {
          value: true,
          configurable: true,
        });
        Object.defineProperty(globalThis, "Uint8Array", {
          value: WrappedUint8Array,
          writable: true,
          configurable: true,
        });

        Object.defineProperty(NativeUint8Array.prototype, "throwingFixture", {
          configurable: true,
          get() { throw new Error("descriptor probe invoked an intrinsic getter"); },
        });

        class Float16Array extends globalThis.Uint16Array {
          static get BYTES_PER_ELEMENT() { return 2; }
          static floatConstructorFixture() { return 3; }
          get [Symbol.toStringTag]() { return "Float16Array"; }
          floatPrototypeFixture() { return 4; }
        }
        Object.defineProperty(globalThis, "Float16Array", {
          value: Float16Array,
          writable: true,
          configurable: true,
          enumerable: true,
        });

        if (${JSON.stringify(installCompatSharedArrayBuffer)}) {
          const NativeArrayBuffer = globalThis.ArrayBuffer;
          function SharedArrayBuffer(byteLength) {
            const buffer = new NativeArrayBuffer(byteLength);
            Object.setPrototypeOf(buffer, SharedArrayBuffer.prototype);
            return buffer;
          }
          SharedArrayBuffer.prototype = Object.create(NativeArrayBuffer.prototype);
          Object.defineProperty(SharedArrayBuffer.prototype, "constructor", {
            value: SharedArrayBuffer,
            writable: true,
            configurable: true,
          });
          Object.defineProperty(SharedArrayBuffer.prototype, Symbol.toStringTag, {
            value: "SharedArrayBuffer",
            configurable: true,
          });
          Object.defineProperty(SharedArrayBuffer.prototype, "compatFixture", {
            value: true,
            configurable: true,
          });
          Object.setPrototypeOf(SharedArrayBuffer, globalThis.Function.prototype);
          Object.defineProperty(globalThis, "SharedArrayBuffer", {
            value: SharedArrayBuffer,
            writable: true,
            configurable: true,
            enumerable: true,
          });
        } else if (${JSON.stringify(emulateHermesNativeSharedArrayBuffer)}) {
          function RetainedNativeSharedArrayBuffer() {}
          RetainedNativeSharedArrayBuffer.prototype = Object.create(Object.prototype);
          Object.defineProperty(
            RetainedNativeSharedArrayBuffer.prototype,
            "constructor",
            {
              value: RetainedNativeSharedArrayBuffer,
              writable: true,
              configurable: true,
            },
          );
          Object.setPrototypeOf(RetainedNativeSharedArrayBuffer, Object.prototype);
          Object.defineProperty(globalThis, "SharedArrayBuffer", {
            value: RetainedNativeSharedArrayBuffer,
            writable: true,
            configurable: true,
          });
        }
      })();
    `,
    context,
  );
  return context;
}

const TARGETS = Object.freeze({
  "android-maven": {
    triple: "aarch64-linux-android",
    features: ["hermes-frame-attribution", "native-lockdown"],
  },
  "source-patched": {
    triple: "aarch64-apple-darwin",
    features: ["hermes-frame-attribution", "native-lockdown"],
  },
  "windows-source-patched": {
    triple: "x86_64-pc-windows-msvc",
    features: ["hermes-frame-attribution", "native-lockdown"],
  },
});

function syntheticBinaryDigest(profileId) {
  return `sha256-${crypto
    .createHash("sha256")
    .update(`synthetic Hermes ${profileId}`)
    .digest("base64url")}`;
}

function syntheticExecution(
  sourceAudit,
  context,
  profileId,
  targetFixture = TARGETS[profileId],
) {
  const profile = sourceAudit.profiles.find((entry) => entry.id === profileId);
  const target = structuredClone(targetFixture);
  const probe = inheritedIntrinsicAliasProbe({
    sourceAudit,
    profileId,
    target,
  });
  const observation = vm.runInContext(probe.source, context);
  const canonicalArtifactPath = `/synthetic/hermes/${profileId}/libhermes`;
  const binaryDigest = syntheticBinaryDigest(profileId);
  const expectedObject = {
    platform: target.triple.includes("android")
      ? "android"
      : target.triple.includes("windows")
        ? "windows"
        : target.triple.includes("apple")
          ? "apple"
          : "unix",
    volume: `fixture-volume:${profileId}`,
    file: `fixture-file:${profileId}`,
  };
  return {
    profileId,
    targetVariant: profile.targetVariant,
    target,
    probeSourceDigest: probe.sourceDigest,
    observation,
    engine: {
      canonicalArtifactPath,
      binaryDigest,
      expectedObject,
      identity: {
        binaryDigest,
        engineArtifactPath: canonicalArtifactPath,
        kind: "hermes",
        object: expectedObject,
        structuralFeatures: [...target.features],
        targetArchitecture: target.triple.split("-")[0],
      },
    },
  };
}

function syntheticProfileReceipt(sourceAudit, execution) {
  const profile = sourceAudit.profiles.find(
    (entry) => entry.id === execution.profileId,
  );
  const binaryHex = Buffer.from(
    execution.engine.identity.binaryDigest.slice(7),
    "base64url",
  ).toString("hex");
  let origin;
  if (profile.id === "source-patched") {
    const authorityKey =
      `p${profile.identity.patchStackDigest.slice(7, 19)}` +
      `-ba${profile.identity.sourceBuildAuthorityDigests["scripts/build-hermes.sh"].slice(7, 19)}` +
      `-bl${profile.identity.sourceBuildAuthorityDigests["scripts/build-hermes-linux.sh"].slice(7, 19)}` +
      `-a${profile.identity.patchApplicationAuthorityDigest.slice(7, 19)}` +
      `-i${profile.identity.patchIdentityAuthorityDigest.slice(7, 19)}`;
    origin = {
      kind: "source-patched-cache",
      cacheKey: `${profile.identity.sourceCommit.slice(0, 12)}-debug-${authorityKey}-oapple`,
      reviewedProfileIdentity: structuredClone(profile.identity),
    };
  } else if (profile.id === "android-maven") {
    const linkedDigest = crypto
      .createHash("sha256")
      .update(`synthetic linked dependency ${profile.id}`)
      .digest("hex");
    origin = {
      kind: "maven-aar",
      packageCoordinate: `${profile.identity.artifact}:${profile.identity.version}:${profile.identity.variant}`,
      packageDigest: profile.identity.packageDigest,
      packageRepository: "https://repo1.maven.org/maven2",
      linkedDependency: {
        artifact: {
          binaryDigest: `sha256-${linkedDigest}`,
          fileName: "libjsi.so",
          targetArchitecture: execution.engine.identity.targetArchitecture,
        },
        packageCoordinate: `${profile.identity.linkedDependency.artifact}:${profile.identity.linkedDependency.version}:${profile.identity.linkedDependency.variant}`,
        packageDigest: profile.identity.linkedDependency.packageDigest,
        packageRepository: "https://repo1.maven.org/maven2",
      },
      reviewedProfileIdentity: structuredClone(profile.identity),
    };
  } else if (profile.id === "windows-source-patched") {
    origin = {
      configuration: "Release",
      debugger: false,
      kind: "source-patched-build",
      reviewedProfileIdentity: structuredClone(profile.identity),
    };
  } else {
    throw new Error(`unsupported synthetic Hermes profile ${profile.id}`);
  }
  const receipt = {
    schema: HERMES_PROFILE_PROVENANCE_RECEIPT_SCHEMA,
    profileId: profile.id,
    targetVariant: profile.targetVariant,
    artifact: {
      binaryDigest: `sha256-${binaryHex}`,
      fileName: path.basename(execution.engine.identity.engineArtifactPath),
      targetArchitecture: execution.engine.identity.targetArchitecture,
    },
    origin,
  };
  if (profile.id === "windows-source-patched") {
    receipt.linkArtifact = {
      binaryDigest: `sha256-${crypto
        .createHash("sha256")
        .update(`synthetic Hermes import library ${profile.id}`)
        .digest("hex")}`,
      fileName: "hermes.lib",
      targetArchitecture: execution.engine.identity.targetArchitecture,
    };
  }
  return receipt;
}

function syntheticBatchEvidence(
  sourceAudit,
  execution,
  { withProvenance = true } = {},
) {
  const plan = inheritedIntrinsicAliasExecutionPlan({
    sourceAudit,
    profileId: execution.profileId,
    target: execution.target,
  });
  return {
    schema: INHERITED_INTRINSIC_ALIAS_BATCH_EVIDENCE_SCHEMA,
    executorContractDigest: plan.executorContractDigest,
    planDigest: plan.planDigest,
    profileId: execution.profileId,
    targetVariant: execution.targetVariant,
    target: structuredClone(execution.target),
    probeSourceDigest: execution.probeSourceDigest,
    observation: structuredClone(execution.observation),
    loadedEngineIdentity: structuredClone(execution.engine.identity),
    loadedEngineProfileProvenance: withProvenance
      ? syntheticProfileReceipt(sourceAudit, execution)
      : null,
  };
}

function syntheticCommandStream(text) {
  return {
    bytes: Buffer.byteLength(text),
    digest: `sha256-${crypto.createHash("sha256").update(text).digest("base64url")}`,
    tail: text,
    truncated: false,
  };
}

function syntheticTargetRecord(sourceAudit, execution, options) {
  const evidence = syntheticBatchEvidence(sourceAudit, execution, options);
  return {
    schema: INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_SCHEMA,
    sourceRevision: "1".repeat(40),
    sourceTree: "2".repeat(40),
    evidenceDigest: `sha256-${crypto
      .createHash("sha256")
      .update(canonicalJson(evidence))
      .digest("hex")}`,
    evidence,
    executionCommand: {
      schema: "ibex/capsec-inherited-intrinsic-alias-command/1",
      evidenceEnvironment: [
        "IBEX_CAPSEC_INTRINSIC_ALIAS_EVIDENCE_OUTPUT",
        "IBEX_CAPSEC_INTRINSIC_ALIAS_PLAN",
        "IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE",
      ],
      commandEvidence: {
        id: "loaded-intrinsic-alias-execution",
        command: [
          "cargo",
          "test",
          "--bin",
          "ibex",
          "--no-default-features",
          "--features",
          "standard,capsec-conformance-observer,openssl-crypto",
          "capsec_inherited_intrinsic_alias_loaded_execution",
          "--",
          "--test-threads=1",
          "--nocapture",
        ],
        exitCode: 0,
        signal: null,
        stdout: syntheticCommandStream("validator fixture passed\n"),
        stderr: syntheticCommandStream(""),
      },
    },
  };
}

function descriptorKeys(layer) {
  return layer.ownDescriptors.map(
    (descriptor) => `${descriptor.key.kind}:${descriptor.key.value}`,
  );
}

let sourceFiles;
let engineProfiles;
let sourceAudit;
let executions;
let accountSet;

beforeAll(() => {
  sourceFiles = Object.fromEntries(
    REQUIRED_PATHS.map((relativePath) => [relativePath, readText(relativePath)]),
  );
  engineProfiles = discoverHermesEvaluatorIdentityProfiles(repoRoot);
  sourceAudit = auditInheritedIntrinsicAliasSources({
    sourceFiles,
    engineProfiles,
  });
  // This VM realm exercises the strict validator and account projection only.
  // It is not target evidence. The Rust loaded-engine batch emits candidate
  // records, and the ledger still refuses promotion without an independent
  // origin/record trust attestation.
  executions = sourceAudit.profiles.map((profile) =>
    syntheticExecution(sourceAudit, syntheticRealm(profile.id), profile.id),
  );
  accountSet = buildInheritedIntrinsicAliasValidatorAccountSet({
    sourceAudit,
    executions,
  });
});

describe("source-bound inherited intrinsic alias review", () => {
  test("binds the exact source mechanisms and all three pinned Hermes profiles", () => {
    expect(sourceAudit.schema).toBe(
      INHERITED_INTRINSIC_ALIAS_SOURCE_REVIEW_SCHEMA,
    );
    expect(sourceAudit.runtimeExecutionRequired).toBe(true);
    expect(sourceAudit.profiles.map((profile) => profile.id)).toEqual([
      "android-maven",
      "source-patched",
      "windows-source-patched",
    ]);
    expect(sourceAudit.profiles.map((profile) => profile.targetVariant)).toEqual(
      ["android", "default", "windows"],
    );
    expect(Object.keys(sourceAudit.sourceProofs).sort()).toEqual(
      [
        "bufferImplementation",
        "bufferInstall",
        "bufferWrapperFactory",
        "float16Install",
        "sharedArrayBufferCompat",
        "sharedArrayBufferInvocation",
        "uint8ArrayCompatibilityWrapper",
      ].sort(),
    );
    expect(sourceAudit.profileReviewDigest).toMatch(/^sha256-[a-f0-9]{64}$/);
    expect(sourceAudit.sourceReviewDigest).toMatch(/^sha256-[a-f0-9]{64}$/);
  });

  test.each([
    [
      "Buffer base class",
      BUFFER_PATH,
      "export class Buffer extends Uint8Array {",
      "export class Buffer extends Uint16Array {",
    ],
    [
      "Buffer wrapper identity edge",
      RUNTIME_BOOTSTRAP_PATH,
      "Object.setPrototypeOf(Buffer, BufferCtor);",
      "Object.setPrototypeOf(Buffer, Function.prototype);",
    ],
    [
      "Float16Array base class",
      RUNTIME_BOOTSTRAP_PATH,
      "g.Float16Array = class Float16Array extends Uint16Array {",
      "g.Float16Array = class Float16Array extends Uint8Array {",
    ],
    [
      "Uint8Array compatibility wrapper identity edge",
      RUNTIME_BOOTSTRAP_PATH,
      "Object.setPrototypeOf(WrappedUint8Array, NativeUint8Array);",
      "Object.setPrototypeOf(WrappedUint8Array, Function.prototype);",
    ],
    [
      "compat SharedArrayBuffer prototype edge",
      COMPAT_BOOTSTRAP_PATH,
      "SharedArrayBuffer.prototype = Object.create(NativeArrayBuffer.prototype);",
      "SharedArrayBuffer.prototype = Object.create(Object.prototype);",
    ],
  ])("fails closed when the reviewed %s drifts", (_, sourcePath, before, after) => {
    const mutated = {
      ...sourceFiles,
      [sourcePath]: replaceExact(
        sourceFiles[sourcePath],
        before,
        after,
        sourcePath,
      ),
    };
    expect(() =>
      auditInheritedIntrinsicAliasSources({
        sourceFiles: mutated,
        engineProfiles,
      }),
    ).toThrow(/reviewed source AST|reviewed AST node/);
  });

  test("fails closed on a pin, target-variant, or profile-set change", () => {
    const pinDrift = structuredClone(engineProfiles);
    pinDrift.find((profile) => profile.id === "android-maven").identity.version =
      "250829098.0.15";
    expect(() =>
      auditInheritedIntrinsicAliasSources({
        sourceFiles,
        engineProfiles: pinDrift,
      }),
    ).toThrow(/identity or authority drifted/);

    const targetDrift = structuredClone(engineProfiles);
    targetDrift.find(
      (profile) => profile.id === "windows-source-patched",
    ).targetVariant = "default";
    expect(() =>
      auditInheritedIntrinsicAliasSources({
        sourceFiles,
        engineProfiles: targetDrift,
      }),
    ).toThrow(/identity or authority drifted/);

    expect(() =>
      auditInheritedIntrinsicAliasSources({
        sourceFiles,
        engineProfiles: engineProfiles.slice(0, 2),
      }),
    ).toThrow(/profile set drifted/);
  });

  test("does not accept a caller-forged source-review object", () => {
    const forged = structuredClone(sourceAudit);
    forged.sourceProofs.bufferImplementation.astDigest =
      `sha256-${"0".repeat(64)}`;
    expect(() =>
      inheritedIntrinsicAliasProbe({
        sourceAudit: forged,
        profileId: "source-patched",
        target: TARGETS["source-patched"],
      }),
    ).toThrow(/source audit proof drifted/);
  });

  test("binds observed/account profile scope and branch contracts into the review", () => {
    const shared =
      sourceAudit.families[
        "compat-sharedarraybuffer-arraybuffer-prototype"
      ];
    expect(shared.accountProfileIds).toEqual(["android-maven"]);
    expect(
      shared.profileContracts.map(({ profileId, branch }) => ({
        profileId,
        branch,
      })),
    ).toEqual([
      { profileId: "android-maven", branch: "compat-installed" },
      { profileId: "source-patched", branch: "retained-native" },
    ]);

    const forged = structuredClone(sourceAudit);
    forged.families[
      "compat-sharedarraybuffer-arraybuffer-prototype"
    ].profileContracts[1].branch = "compat-installed";
    expect(() =>
      inheritedIntrinsicAliasProbe({
        sourceAudit: forged,
        profileId: "source-patched",
        target: TARGETS["source-patched"],
      }),
    ).toThrow(/source audit is absent or unreviewed/);
  });
});

describe("descriptor-only loaded-Hermes probe contract", () => {
  test("emits a profile/target/source-bound, content-addressed evaluator", () => {
    const probe = inheritedIntrinsicAliasProbe({
      sourceAudit,
      profileId: "android-maven",
      target: TARGETS["android-maven"],
    });
    expect(probe.schema).toBe(INHERITED_INTRINSIC_ALIAS_OBSERVATION_SCHEMA);
    expect(probe.binding.familyIds).toEqual(INHERITED_INTRINSIC_ALIAS_FAMILIES);
    expect(probe.binding.sourceReviewDigest).toBe(
      sourceAudit.sourceReviewDigest,
    );
    expect(probe.sourceDigest).toMatch(/^sha256-[a-f0-9]{64}$/);
    expect(probe.source).toContain("Reflect.ownKeys");
    expect(probe.source).toContain("Object.getOwnPropertyDescriptor");
  });

  test("enumerates exact own descriptors without invoking getters", () => {
    const android = accountSet.executions.find(
      (execution) => execution.profileId === "android-maven",
    );
    const buffer = android.observation.families.find(
      (family) => family.familyId === "buffer-uint8array",
    );
    const basePrototype = buffer.chains
      .find((chain) => chain.role === "prototype-chain")
      .layers.find((layer) => layer.role === "base-prototype");
    const throwing = basePrototype.ownDescriptors.find(
      (descriptor) => descriptor.key.value === "throwingFixture",
    );
    expect(throwing).toEqual({
      key: { kind: "string", value: "throwingFixture" },
      configurable: true,
      enumerable: false,
      kind: "accessor",
      get: true,
      set: false,
    });
  });

  test("rejects prototype accessors without invoking them", () => {
    const context = syntheticRealm("android-maven");
    vm.runInContext(
      `
        (() => {
          globalThis.__intrinsicPrototypeGetterCalls = 0;
          const implementation = Object.getPrototypeOf(globalThis.Buffer);
          const maliciousImplementation = (function () {}).bind(null);
          Object.setPrototypeOf(maliciousImplementation, Object.getPrototypeOf(implementation));
          Object.defineProperty(maliciousImplementation, "prototype", {
            configurable: true,
            get() {
              globalThis.__intrinsicPrototypeGetterCalls += 1;
              return Object.getOwnPropertyDescriptor(implementation, "prototype").value;
            },
          });
          Object.setPrototypeOf(globalThis.Buffer, maliciousImplementation);
        })();
      `,
      context,
    );
    const probe = inheritedIntrinsicAliasProbe({
      sourceAudit,
      profileId: "android-maven",
      target: TARGETS["android-maven"],
    });
    expect(() => vm.runInContext(probe.source, context)).toThrow(
      /not an own data property: Buffer implementation\.prototype/,
    );
    expect(
      vm.runInContext("globalThis.__intrinsicPrototypeGetterCalls", context),
    ).toBe(0);
  });

  test("rejects non-function constructor-shaped globals", () => {
    const context = syntheticRealm("android-maven");
    vm.runInContext(
      `Object.defineProperty(globalThis, "Buffer", {
        value: { prototype: {} },
        writable: true,
        configurable: true,
      });`,
      context,
    );
    const probe = inheritedIntrinsicAliasProbe({
      sourceAudit,
      profileId: "android-maven",
      target: TARGETS["android-maven"],
    });
    expect(() => vm.runInContext(probe.source, context)).toThrow(
      /constructor is not a function: global Buffer/,
    );
  });

  test("observes source-patched retained-native SharedArrayBuffer explicitly", () => {
    const source = accountSet.executions.find(
      (execution) => execution.profileId === "source-patched",
    );
    const shared = source.observation.families.find(
      (family) =>
        family.familyId ===
        "compat-sharedarraybuffer-arraybuffer-prototype",
    );
    expect(shared.branch).toBe("retained-native");
    expect(shared.aliases.prototypeInheritsBasePrototype).toBe(false);
    expect(shared.aliases.constructorInheritsFunctionPrototype).toBe(false);
    expect(shared.aliases.compatToStringTag).toBe(false);
    expect(shared.chains[0].layers[0].role).toBe("native-constructor");
    expect(shared.chains[1].layers[0].role).toBe("native-prototype");
    expect(
      accountSet.accounts[
        "compat-sharedarraybuffer-arraybuffer-prototype"
      ].profileProofs.map((proof) => proof.profileId),
    ).toEqual(["android-maven"]);
  });

  test("rejects a target/profile mismatch before it can name evidence", () => {
    expect(() =>
      inheritedIntrinsicAliasProbe({
        sourceAudit,
        profileId: "android-maven",
        target: TARGETS["windows-source-patched"],
      }),
    ).toThrow(/does not match profile/);
  });
});

describe("loaded inherited intrinsic structural accounts", () => {
  test("validates all-family closure shape and complete member layers", () => {
    expect(Object.keys(accountSet.accounts)).toEqual(
      INHERITED_INTRINSIC_ALIAS_FAMILIES,
    );
    expect(accountSet.runtimeExecutionRequired).toBe(true);
    expect(accountSet.validatorOnly).toBe(true);
    expect(accountSet.eligibleForStructuralAccounts).toBe(false);
    expect(INHERITED_INTRINSIC_ALIAS_RUNTIME_EXECUTION_REQUIRED).toBe(true);
    expect(INHERITED_INTRINSIC_ALIAS_OUTPUT_CATALOG_BINDINGS).toEqual([]);

    const buffer = accountSet.accounts["buffer-uint8array"];
    const float16 = accountSet.accounts["float16array-uint16array"];
    const shared =
      accountSet.accounts[
        "compat-sharedarraybuffer-arraybuffer-prototype"
      ];
    for (const account of [buffer, float16, shared]) {
      expect(account.schema).toBe(
        INHERITED_INTRINSIC_ALIAS_VALIDATOR_ACCOUNT_SCHEMA,
      );
      expect(account.status).toBe("validator-only-loaded-structural-alias");
      expect(account.reasonCode).toBe(INHERITED_INTRINSIC_ALIAS_REASON_CODE);
      expect(account.accountDigest).toMatch(/^sha256-[a-f0-9]{64}$/);
    }
    expect(buffer.profileProofs.map((proof) => proof.profileId)).toEqual([
      "android-maven",
      "source-patched",
      "windows-source-patched",
    ]);
    expect(float16.profileProofs.map((proof) => proof.profileId)).toEqual([
      "android-maven",
      "source-patched",
      "windows-source-patched",
    ]);
    expect(shared.profileProofs.map((proof) => proof.profileId)).toEqual([
      "android-maven",
    ]);

    const bufferChains = buffer.profileProofs[0].memberUniverse;
    expect(bufferChains.map((chain) => chain.role)).toEqual([
      "constructor-chain",
      "prototype-chain",
    ]);
    expect(bufferChains.every((chain) => chain.terminatedAtNull)).toBe(true);
    expect(bufferChains[0].layers.slice(0, 4).map((layer) => layer.role)).toEqual([
      "wrapper-constructor",
      "implementation-constructor",
      "inherited-constructor-layer",
      "base-implementation-constructor",
    ]);
    expect(bufferChains[1].layers.slice(0, 3).map((layer) => layer.role)).toEqual([
      "implementation-prototype",
      "inherited-prototype-layer",
      "base-prototype",
    ]);
    expect(bufferChains[0].layers.length).toBeGreaterThan(4);
    expect(bufferChains[1].layers.length).toBeGreaterThan(3);
    expect(descriptorKeys(bufferChains[0].layers[0])).toContain(
      "string:wrapperFixture",
    );
    expect(descriptorKeys(bufferChains[0].layers[1])).toContain(
      "string:implementationFixture",
    );
    expect(descriptorKeys(bufferChains[1].layers[0])).toContain(
      "string:bufferPrototypeFixture",
    );
    expect(
      bufferChains[0].layers
        .slice(4)
        .flatMap(descriptorKeys),
    ).toContain("string:from");
    expect(
      bufferChains[1].layers
        .slice(3)
        .flatMap(descriptorKeys),
    ).toContain("string:map");

    const floatChains = float16.profileProofs[0].memberUniverse;
    expect(descriptorKeys(floatChains[0].layers[0])).toContain(
      "string:floatConstructorFixture",
    );
    expect(descriptorKeys(floatChains[1].layers[0])).toContain(
      "string:floatPrototypeFixture",
    );

    const sharedChains = shared.profileProofs[0].memberUniverse;
    expect(descriptorKeys(sharedChains[1].layers[0])).toContain(
      "string:compatFixture",
    );
    expect(sharedChains[1].layers.at(-1).role).toBe(
      "inherited-prototype-layer",
    );
    expect(descriptorKeys(sharedChains[1].layers.at(-1))).toContain(
      "string:toString",
    );
    expect(shared.profileProofs[0].identityAliases).toEqual({
      constructorInheritsFunctionPrototype: true,
      prototypeDistinctFromBasePrototype: true,
      prototypeInheritsBasePrototype: true,
      prototypeConstructorBackReference: true,
      compatToStringTag: true,
    });

    expect(buffer.profileProofs[0].identityAliases).toEqual({
      constructorDistinctFromImplementation: true,
      wrapperPrototypeIsImplementationPrototype: true,
      baseConstructorBindingIsDirectOrReviewedWrapper: true,
      implementationConstructorTransitivelyInheritsBaseImplementation: true,
      implementationPrototypeTransitivelyInheritsBasePrototype: true,
    });
  });

  test("exposes structural bindings but no premature catalog binding", () => {
    const bindings =
      inheritedIntrinsicAliasValidatorBindings(accountSet);
    expect(bindings.map((binding) => binding.familyId)).toEqual(
      INHERITED_INTRINSIC_ALIAS_FAMILIES,
    );
    expect(bindings.every((binding) => binding.profileProofs.length > 0)).toBe(
      true,
    );
    expect(
      bindings.every(
        (binding) =>
          binding.status === "validator-only-loaded-structural-alias",
      ),
    )
      .toBe(true);
  });

  test("revalidates account content before exposing structural bindings", () => {
    const forged = structuredClone(accountSet);
    forged.accounts["buffer-uint8array"].profileProofs[0].memberUniverse[0]
      .layers[0].ownDescriptors[0].configurable =
      !forged.accounts["buffer-uint8array"].profileProofs[0].memberUniverse[0]
        .layers[0].ownDescriptors[0].configurable;
    expect(() =>
      inheritedIntrinsicAliasValidatorBindings(forged),
    ).toThrow(/membership digest|account digest|account-set digest/);
  });

  test("requires one loaded, correctly mapped execution for every profile", () => {
    expect(() =>
      buildInheritedIntrinsicAliasValidatorAccountSet({
        sourceAudit,
        executions: executions.slice(0, 2),
      }),
    ).toThrow(/every Hermes profile/);

    const duplicate = structuredClone(executions);
    duplicate[2].profileId = "source-patched";
    duplicate[2].targetVariant = "default";
    expect(() =>
      buildInheritedIntrinsicAliasValidatorAccountSet({
        sourceAudit,
        executions: duplicate,
      }),
    ).toThrow();
  });

  test("fails on executed source, mapped-image, or target drift", () => {
    const probeDrift = structuredClone(executions);
    probeDrift[0].probeSourceDigest = `sha256-${"0".repeat(64)}`;
    expect(() =>
      buildInheritedIntrinsicAliasValidatorAccountSet({
        sourceAudit,
        executions: probeDrift,
      }),
    ).toThrow(/probe source digest drifted/);

    const imageDrift = structuredClone(executions);
    imageDrift[0].engine.identity.binaryDigest = syntheticBinaryDigest(
      "different-image",
    );
    expect(() =>
      buildInheritedIntrinsicAliasValidatorAccountSet({
        sourceAudit,
        executions: imageDrift,
      }),
    ).toThrow(/loaded engine identity/);

    const targetDrift = structuredClone(executions);
    targetDrift[0].target.triple = "aarch64-apple-darwin";
    expect(() =>
      buildInheritedIntrinsicAliasValidatorAccountSet({
        sourceAudit,
        executions: targetDrift,
      }),
    ).toThrow(/target\/profile mismatch/);
  });

  test("fails closed when an identity alias or conditional compat branch is absent", () => {
    const aliasDrift = structuredClone(executions);
    aliasDrift[0].observation.families[0].aliases[
      "implementationConstructorTransitivelyInheritsBaseImplementation"
    ] = false;
    expect(() =>
      buildInheritedIntrinsicAliasValidatorAccountSet({
        sourceAudit,
        executions: aliasDrift,
      }),
    ).toThrow(/identity alias/);

    const retainedNative = structuredClone(executions);
    const shared = retainedNative[0].observation.families.find(
      (family) =>
        family.familyId ===
        "compat-sharedarraybuffer-arraybuffer-prototype",
    );
    shared.branch = "retained-native";
    shared.aliases.prototypeInheritsBasePrototype = false;
    expect(() =>
      buildInheritedIntrinsicAliasValidatorAccountSet({
        sourceAudit,
        executions: retainedNative,
      }),
    ).toThrow(/family branch or shape drifted/);
  });

  test("rejects non-canonical, duplicate, or unreviewed own-key membership", () => {
    const unterminated = structuredClone(executions);
    unterminated[0].observation.families[0].chains[0].terminatedAtNull = false;
    expect(() =>
      buildInheritedIntrinsicAliasValidatorAccountSet({
        sourceAudit,
        executions: unterminated,
      }),
    ).toThrow(/exhaustive prototype chain drifted/);

    const unsorted = structuredClone(executions);
    const descriptors = unsorted[0].observation.families[0].chains[0].layers[0]
      .ownDescriptors;
    descriptors.reverse();
    expect(() =>
      buildInheritedIntrinsicAliasValidatorAccountSet({
        sourceAudit,
        executions: unsorted,
      }),
    ).toThrow(/duplicate or not canonical/);

    const unknownSymbol = structuredClone(executions);
    const descriptor =
      unknownSymbol[0].observation.families[0].chains[0].layers[0]
        .ownDescriptors[0];
    descriptor.key = { kind: "well-known-symbol", value: "dispose" };
    expect(() =>
      buildInheritedIntrinsicAliasValidatorAccountSet({
        sourceAudit,
        executions: unknownSymbol,
      }),
    ).toThrow(/malformed exact property key/);
  });
});

describe("exact-target inherited intrinsic conformance ledger", () => {
  test("authors a source/profile/target-bound execution plan", () => {
    expect(HERMES_PROFILE_PROVENANCE_RECEIPT_SCHEMA).toBe(
      "ibex/hermes-profile-provenance-receipt/2",
    );
    const plan = inheritedIntrinsicAliasExecutionPlan({
      sourceAudit,
      profileId: "source-patched",
      target: TARGETS["source-patched"],
    });
    expect(plan.schema).toBe(INHERITED_INTRINSIC_ALIAS_EXECUTION_PLAN_SCHEMA);
    expect(plan.reviewedProfileIdentity).toEqual(
      sourceAudit.profiles.find((profile) => profile.id === "source-patched")
        .identity,
    );
    expect(plan.probe.sourceDigest).toMatch(/^sha256-[a-f0-9]{64}$/);
    expect(plan.executorContractDigest).toBe(
      INHERITED_INTRINSIC_ALIAS_EXECUTOR_CONTRACT_DIGEST,
    );
    expect(plan.planDigest).toMatch(/^sha256-[a-f0-9]{64}$/);
  });

  test("accepts universal artifacts only for source-patched macOS", () => {
    const sourceEvidence = syntheticBatchEvidence(sourceAudit, executions[1]);
    sourceEvidence.loadedEngineProfileProvenance.artifact.targetArchitecture =
      "universal";
    expect(
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: sourceEvidence,
      }).profileProvenance.mechanicallyBound,
    ).toBe(true);

    for (const execution of [executions[0], executions[2]]) {
      const evidence = syntheticBatchEvidence(sourceAudit, execution);
      evidence.loadedEngineProfileProvenance.artifact.targetArchitecture =
        "universal";
      expect(() =>
        auditInheritedIntrinsicAliasBatchEvidence({ sourceAudit, evidence }),
      ).toThrow(/does not bind the loaded artifact bytes/u);
    }

    const linuxExecution = syntheticExecution(
      sourceAudit,
      syntheticRealm("source-patched"),
      "source-patched",
      {
        triple: "aarch64-unknown-linux-gnu",
        features: ["hermes-frame-attribution", "native-lockdown"],
      },
    );
    const linuxEvidence = syntheticBatchEvidence(sourceAudit, linuxExecution);
    linuxEvidence.loadedEngineProfileProvenance.artifact.targetArchitecture =
      "universal";
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: linuxEvidence,
      }),
    ).toThrow(/does not bind the loaded artifact bytes/u);

    const androidLinked = syntheticBatchEvidence(sourceAudit, executions[0]);
    androidLinked.loadedEngineProfileProvenance.origin.linkedDependency.artifact.targetArchitecture =
      "universal";
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: androidLinked,
      }),
    ).toThrow(/reviewed linked JSI package/u);
  });

  test("rejects missing, malformed, or substituted Windows link artifacts", () => {
    const legacySchema = syntheticBatchEvidence(sourceAudit, executions[2]);
    legacySchema.loadedEngineProfileProvenance.schema =
      "ibex/hermes-profile-provenance-receipt/1";
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: legacySchema,
      }),
    ).toThrow(/malformed exact Hermes profile receipt/u);

    const missing = syntheticBatchEvidence(sourceAudit, executions[2]);
    delete missing.loadedEngineProfileProvenance.linkArtifact;
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: missing,
      }),
    ).toThrow(/malformed exact Hermes profile receipt/u);

    const malformed = syntheticBatchEvidence(sourceAudit, executions[2]);
    malformed.loadedEngineProfileProvenance.linkArtifact.binaryDigest =
      `sha256-${"0".repeat(63)}`;
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: malformed,
      }),
    ).toThrow(/exact reviewed Hermes import library/u);

    const extraField = syntheticBatchEvidence(sourceAudit, executions[2]);
    extraField.loadedEngineProfileProvenance.linkArtifact.unreviewedOverride =
      true;
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: extraField,
      }),
    ).toThrow(/exact reviewed Hermes import library/u);

    for (const [field, value] of [
      ["fileName", "substituted.lib"],
      ["targetArchitecture", "aarch64"],
      ["targetArchitecture", "universal"],
    ]) {
      const substituted = syntheticBatchEvidence(sourceAudit, executions[2]);
      substituted.loadedEngineProfileProvenance.linkArtifact[field] = value;
      expect(() =>
        auditInheritedIntrinsicAliasBatchEvidence({
          sourceAudit,
          evidence: substituted,
        }),
      ).toThrow(/exact reviewed Hermes import library/u);
    }

    const androidExtra = syntheticBatchEvidence(sourceAudit, executions[0]);
    androidExtra.loadedEngineProfileProvenance.linkArtifact = structuredClone(
      syntheticBatchEvidence(sourceAudit, executions[2])
        .loadedEngineProfileProvenance.linkArtifact,
    );
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: androidExtra,
      }),
    ).toThrow(/malformed exact Hermes profile receipt/u);
  });

  test("retains one structurally valid candidate without claiming authenticated closure", () => {
    // This is a validator fixture only. Production records are emitted by the
    // Rust loaded-engine batch; the ledger never upgrades this one record into
    // accounts for profiles that did not run.
    const evidence = syntheticBatchEvidence(sourceAudit, executions[1]);
    const accepted = auditInheritedIntrinsicAliasBatchEvidence({
      sourceAudit,
      evidence,
    });
    expect(accepted.execution.profileId).toBe("source-patched");

    const targetRecord = syntheticTargetRecord(sourceAudit, executions[1]);
    expect(
      auditInheritedIntrinsicAliasTargetRecord({
        sourceAudit,
        targetRecord,
      }).execution.profileId,
    ).toBe("source-patched");

    const ledger = auditInheritedIntrinsicAliasExecutionLedger({
      sourceAudit,
      targetRecords: [targetRecord],
    });
    expect(ledger.schema).toBe(
      INHERITED_INTRINSIC_ALIAS_EXECUTION_LEDGER_SCHEMA,
    );
    expect(ledger.status).toBe("incomplete");
    expect(ledger.acceptedProfileIds).toEqual(["source-patched"]);
    expect(ledger.missingProfileIds).toEqual([
      "android-maven",
      "windows-source-patched",
    ]);
    expect(ledger.blockers.map((blocker) => blocker.code)).toEqual([
      INHERITED_INTRINSIC_ALIAS_MISSING_EXECUTION_CODE,
      INHERITED_INTRINSIC_ALIAS_MISSING_EXECUTION_CODE,
      INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_ATTESTATION_CODE,
      INHERITED_INTRINSIC_ALIAS_SOURCE_CACHE_AUTHORITY_CODE,
      INHERITED_INTRINSIC_ALIAS_LINKED_DEPENDENCY_CODE,
      INHERITED_INTRINSIC_ALIAS_LINUX_PROFILE_RECEIPT_CODE,
      INHERITED_INTRINSIC_ALIAS_WINDOWS_BUILD_AUTHORITY_CODE,
      INHERITED_INTRINSIC_ALIAS_WINDOWS_LOADED_IMAGE_CODE,
    ]);
    expect(ledger.eligibleForStructuralAccounts).toBe(false);
    expect(ledger.accountSet).toBeNull();
  });

  test("keeps account closure blocked when loaded executions lack reviewed artifact provenance", () => {
    const ledger = auditInheritedIntrinsicAliasExecutionLedger({
      sourceAudit,
      targetRecords: executions.map((execution) =>
        syntheticTargetRecord(sourceAudit, execution, {
          withProvenance: false,
        }),
      ),
    });
    expect(ledger.status).toBe("incomplete");
    expect(ledger.runtimeExecutionRecordsComplete).toBe(true);
    expect(ledger.runtimeExecutionsComplete).toBe(false);
    expect(ledger.linkedProfileBindingsComplete).toBe(false);
    expect(ledger.reviewedProfileProvenanceComplete).toBe(false);
    expect(ledger.targetRecordAuthenticityComplete).toBe(false);
    expect(ledger.missingProfileIds).toEqual([]);
    expect(ledger.blockers.map((blocker) => blocker.code)).toEqual([
      ...Array(3).fill(INHERITED_INTRINSIC_ALIAS_PROFILE_PROVENANCE_CODE),
      ...Array(3).fill(INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_ATTESTATION_CODE),
      INHERITED_INTRINSIC_ALIAS_SOURCE_CACHE_AUTHORITY_CODE,
      INHERITED_INTRINSIC_ALIAS_LINKED_DEPENDENCY_CODE,
      INHERITED_INTRINSIC_ALIAS_LINUX_PROFILE_RECEIPT_CODE,
      INHERITED_INTRINSIC_ALIAS_WINDOWS_BUILD_AUTHORITY_CODE,
      INHERITED_INTRINSIC_ALIAS_WINDOWS_LOADED_IMAGE_CODE,
    ]);
    const provenanceReasons = Object.fromEntries(
      ledger.blockers.map((blocker) => [blocker.code, blocker.reason]),
    );
    expect(
      provenanceReasons[INHERITED_INTRINSIC_ALIAS_SOURCE_CACHE_AUTHORITY_CODE],
    ).toMatch(/no independent build attestation/);
    expect(
      provenanceReasons[INHERITED_INTRINSIC_ALIAS_LINKED_DEPENDENCY_CODE],
    ).toMatch(/link-selected libjsi\.so bytes/);
    expect(
      provenanceReasons[INHERITED_INTRINSIC_ALIAS_LINUX_PROFILE_RECEIPT_CODE],
    ).toMatch(/emits a reviewed receipt for dynamic libhermesvm\.so/);
    expect(
      provenanceReasons[INHERITED_INTRINSIC_ALIAS_WINDOWS_BUILD_AUTHORITY_CODE],
    ).toMatch(/without an independent build attestation/);
    expect(
      provenanceReasons[INHERITED_INTRINSIC_ALIAS_WINDOWS_LOADED_IMAGE_CODE],
    ).toMatch(/loader-reported DLL pathname.*without authenticating/);
    expect(ledger.accountSet).toBeNull();
  });

  test("does not let synthetic receipt-bound JSON close accounts", () => {
    const ledger = auditInheritedIntrinsicAliasExecutionLedger({
      sourceAudit,
      targetRecords: executions.map((execution) =>
        syntheticTargetRecord(sourceAudit, execution),
      ),
    });
    expect(ledger.status).toBe("incomplete");
    expect(ledger.runtimeExecutionRecordsComplete).toBe(true);
    expect(ledger.runtimeExecutionsComplete).toBe(false);
    expect(ledger.linkedProfileBindingsComplete).toBe(false);
    expect(ledger.reviewedProfileProvenanceComplete).toBe(false);
    expect(ledger.targetRecordAuthenticityComplete).toBe(false);
    expect(ledger.eligibleForStructuralAccounts).toBe(false);
    expect(ledger.blockers.map((blocker) => blocker.code)).toEqual([
      ...Array(3).fill(
        INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_ATTESTATION_CODE,
      ),
      INHERITED_INTRINSIC_ALIAS_SOURCE_CACHE_AUTHORITY_CODE,
      INHERITED_INTRINSIC_ALIAS_LINKED_DEPENDENCY_CODE,
      INHERITED_INTRINSIC_ALIAS_LINUX_PROFILE_RECEIPT_CODE,
      INHERITED_INTRINSIC_ALIAS_WINDOWS_BUILD_AUTHORITY_CODE,
      INHERITED_INTRINSIC_ALIAS_WINDOWS_LOADED_IMAGE_CODE,
    ]);
    expect(ledger.accountSet).toBeNull();
  });

  test("rejects duplicate profiles and evidence detached from the authored plan", () => {
    const targetRecord = syntheticTargetRecord(sourceAudit, executions[0]);
    expect(() =>
      auditInheritedIntrinsicAliasExecutionLedger({
        sourceAudit,
        targetRecords: [targetRecord, structuredClone(targetRecord)],
      }),
    ).toThrow(/duplicate/);

    const evidence = targetRecord.evidence;
    const detached = structuredClone(evidence);
    detached.planDigest = `sha256-${"0".repeat(64)}`;
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: detached,
      }),
    ).toThrow(/not bound to its plan/);

    const provenanceForgery = structuredClone(targetRecord.evidence);
    provenanceForgery.loadedEngineProfileProvenance.artifact.binaryDigest =
      `sha256-${"0".repeat(64)}`;
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: provenanceForgery,
      }),
    ).toThrow(/does not bind the loaded artifact bytes/);

    const androidPackageForgery = structuredClone(targetRecord.evidence);
    androidPackageForgery.loadedEngineProfileProvenance.origin.packageDigest =
      `sha256-${"0".repeat(64)}`;
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: androidPackageForgery,
      }),
    ).toThrow(/reviewed package provenance/);

    const androidJsiForgery = structuredClone(targetRecord.evidence);
    androidJsiForgery.loadedEngineProfileProvenance.origin.linkedDependency.packageDigest =
      `sha256-${"0".repeat(64)}`;
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: androidJsiForgery,
      }),
    ).toThrow(/reviewed linked JSI package/);

    const windowsEvidence = syntheticBatchEvidence(sourceAudit, executions[2]);
    windowsEvidence.loadedEngineProfileProvenance.origin.debugger = true;
    expect(() =>
      auditInheritedIntrinsicAliasBatchEvidence({
        sourceAudit,
        evidence: windowsEvidence,
      }),
    ).toThrow(/reviewed source-build provenance/);

    const commandForgery = structuredClone(targetRecord);
    commandForgery.executionCommand.commandEvidence.exitCode = 1;
    expect(() =>
      auditInheritedIntrinsicAliasTargetRecord({
        sourceAudit,
        targetRecord: commandForgery,
      }),
    ).toThrow(/did not pass exactly/);
  });
});
