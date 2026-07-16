/**
 * Exhaustive-output review ledger for unresolved dynamic-global families.
 *
 * A successful member read or call does not close a dynamic-table sentinel.
 * Closure requires a source-bound finite membership proof plus one output
 * account for every output-bearing member. None of the reviewed families has
 * both yet, so this module deliberately authors no executable invocation or
 * catalog binding. It records the exact residual and the proof needed next.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * sample success is not exhaustive value evidence for a dynamic family.
 * @ref LLP 0023#6-path-bearing-observables — sentinels and owner-key markers
 * are not values, and ambient domains cannot be enumerated into completeness.
 */

export const DYNAMIC_GLOBAL_OUTPUT_INVOCATION_SCHEMA =
  "ibex/capsec-dynamic-global-output-invocation/1";
export const DYNAMIC_GLOBAL_OUTPUT_SOURCE_DESCRIPTOR_KIND =
  "source-bound-dynamic-global-family";

const residual = ({
  dynamicNamespaceEvidence,
  dynamicNamespaceRoot,
  expectedClassification = "closed",
  familyKind,
  globalName,
  inheritedBase,
  memberName,
  name,
  reason,
  reasonCode,
  requiredIntegration,
  requiredMemberKinds,
  sourceKey,
  sourceRefs,
}) =>
  Object.freeze({
    ...(dynamicNamespaceEvidence
      ? { dynamicNamespaceEvidence, dynamicNamespaceRoot }
      : {}),
    expectedClassification,
    familyKind,
    globalName,
    ...(inheritedBase ? { inheritedBase } : {}),
    memberName,
    name,
    reason,
    reasonCode,
    requiredIntegration: Object.freeze(requiredIntegration),
    requiredMemberKinds: Object.freeze(requiredMemberKinds),
    sourceKey,
    sourceRefs: Object.freeze(sourceRefs),
    status: "residual",
  });

const FAMILY_CONTRACTS = Object.freeze({
  "__exactHostNavigator.[[dynamic-table:host-navigator-properties]]": residual({
    familyKind: "host-object-overlay",
    globalName: "__exactHostNavigator",
    memberName: "[[dynamic-table:host-navigator-properties]]",
    name: "__exactHostNavigator.[[dynamic-table:host-navigator-properties]]",
    reasonCode: "ambient-host-overlay-membership-unclosed",
    reason:
      "The family row does not bind a finite navigator member universe; enumerating the ambient host object cannot prove exhaustive output membership.",
    requiredIntegration: [
      "split each supported navigator member into an exact source-derived row",
      "account for every output-bearing member with a targeted loaded operation",
      "prove the supported member set has no unaccounted remainder without ambient ownKeys enumeration",
    ],
    requiredMemberKinds: ["dynamic-table"],
    sourceKey: "shared_runtime",
    sourceRefs: [
      "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:__exactHostNavigator",
    ],
  }),
  "global:Buffer.[[dynamic-table:inherited-uint8-array-6128693053-properties]]":
    residual({
      familyKind: "inherited-constructor-shape",
      globalName: "Buffer",
      inheritedBase: "Uint8Array",
      memberName:
        "[[dynamic-table:inherited-uint8-array-6128693053-properties]]",
      name: "global:Buffer.[[dynamic-table:inherited-uint8-array-6128693053-properties]]",
      reasonCode: "inherited-base-membership-unclosed",
      reason:
        "The extends clause proves Buffer inherits from Uint8Array, but a prototype-lineage boolean does not close or account for the inherited Uint8Array member universe.",
      requiredIntegration: [
        "source-bind a finite Uint8Array constructor and prototype membership contract for every loaded target variant",
        "expand every inherited output-bearing member into a concrete output account",
        "prove the loaded Buffer chain contains no unaccounted inherited member",
      ],
      requiredMemberKinds: ["dynamic-table", "inherited-shape"],
      sourceKey: "shared_runtime",
      sourceRefs: [
        "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:Buffer",
        "packages/ibex-runtime-js/src/node/Buffer.ts#Buffer:extends:Uint8Array",
      ],
    }),
  "global:Bun.CryptoHasher.[[dynamic-table:call-result-3eca66b45491-properties]]":
    residual({
      dynamicNamespaceEvidence:
        "sha256-3eca66b4549187abbc77e2e4738d8b15a607efaa95c594fe7f987d36cc525136",
      dynamicNamespaceRoot: "Bun.CryptoHasher",
      familyKind: "iife-constructor-properties",
      globalName: "Bun",
      memberName:
        "CryptoHasher.[[dynamic-table:call-result-3eca66b45491-properties]]",
      name: "global:Bun.CryptoHasher.[[dynamic-table:call-result-3eca66b45491-properties]]",
      reasonCode: "iife-result-membership-unclosed",
      reason:
        "The IIFE digest binds the returned CH constructor source, but one successful static hash call neither enumerates nor accounts for its complete constructor, static, and prototype output shape.",
      requiredIntegration: [
        "derive the complete CH constructor-own, source-static, and CH.prototype member sets from the digested IIFE",
        "expand every output-bearing member into a concrete output account, including ordinary-function members that remain observable on the loaded engine",
        "execute a loaded exhaustive membership comparison and prove no unaccounted constructor or prototype key remains",
      ],
      requiredMemberKinds: ["dynamic-table", "namespace-alias"],
      sourceKey: "global_exact_global",
      sourceRefs: [
        "src/engine/bootstrap/exact-global.js#Bun.CryptoHasher.[[dynamic-table:call-result-3eca66b45491-properties]]",
      ],
    }),
  "global:Bun.env.[[dynamic-table:call-result-83f13e6eeaf2-properties]]":
    residual({
      familyKind: "environment-proxy",
      globalName: "Bun",
      memberName: "env.[[dynamic-table:call-result-83f13e6eeaf2-properties]]",
      name: "global:Bun.env.[[dynamic-table:call-result-83f13e6eeaf2-properties]]",
      reasonCode: "ambient-environment-proxy-open-domain",
      reason:
        "Bun.env is an open environment proxy; no finite family membership proof may enumerate or select unauthored ambient environment names.",
      requiredIntegration: [
        "split each authorized environment name into an exact typed occurrence",
        "execute only its targeted Get with matching env:read authority",
        "treat the remaining open proxy domain as structural rather than output-complete",
      ],
      requiredMemberKinds: ["dynamic-table", "namespace-alias"],
      sourceKey: "global_exact_global",
      sourceRefs: [
        "src/engine/bootstrap/exact-global.js#Bun.env.[[dynamic-table:call-result-83f13e6eeaf2-properties]]",
      ],
    }),
  "global:[[dynamic-table:native-global-name]]": residual({
    familyKind: "native-global-writer-marker",
    globalName: "[[dynamic-table:native-global-name]]",
    memberName: null,
    name: "global:[[dynamic-table:native-global-name]]",
    reasonCode: "dynamic-registrar-name-marker-not-value",
    reason:
      "The row marks an unresolved registrar name; the sentinel is structural inventory evidence, not a readable global or output value.",
    requiredIntegration: [
      "resolve every registrar call to a concrete global name in source inventory",
      "create output accounts only for the resulting concrete globals and members",
      "classify the marker itself as structural and never probe or serialize its spelling",
    ],
    requiredMemberKinds: ["dynamic-table"],
    sourceKey: "native_jsi_global",
    sourceRefs: [
      "src/engine/hermes_runtime.cc#jsi-global:[[dynamic-table:native-global-name]]",
      "src/engine/hermes_runtime_fs_windows.cc#jsi-global:[[dynamic-table:native-global-name]]",
      "src/engine/hermes_runtime_platform_windows.cc#jsi-global:[[dynamic-table:native-global-name]]",
      "src/engine/hermes_runtime_process.cc#jsi-global:[[dynamic-table:native-global-name]]",
    ],
  }),
  "global:Exact.CryptoHasher.[[dynamic-table:call-result-3eca66b45491-properties]]":
    residual({
      dynamicNamespaceEvidence:
        "sha256-3eca66b4549187abbc77e2e4738d8b15a607efaa95c594fe7f987d36cc525136",
      dynamicNamespaceRoot: "Exact.CryptoHasher",
      familyKind: "iife-constructor-properties",
      globalName: "Exact",
      memberName:
        "CryptoHasher.[[dynamic-table:call-result-3eca66b45491-properties]]",
      name: "global:Exact.CryptoHasher.[[dynamic-table:call-result-3eca66b45491-properties]]",
      reasonCode: "iife-result-membership-unclosed",
      reason:
        "The IIFE digest binds the returned CH constructor source, but one successful static hash call neither enumerates nor accounts for its complete constructor, static, and prototype output shape.",
      requiredIntegration: [
        "derive the complete CH constructor-own, source-static, and CH.prototype member sets from the digested IIFE",
        "expand every output-bearing member into a concrete output account, including ordinary-function members that remain observable on the loaded engine",
        "execute a loaded exhaustive membership comparison and prove no unaccounted constructor or prototype key remains",
      ],
      requiredMemberKinds: ["dynamic-table", "namespace-alias"],
      sourceKey: "global_exact_global",
      sourceRefs: [
        "src/engine/bootstrap/exact-global.js#Exact.CryptoHasher.[[dynamic-table:call-result-3eca66b45491-properties]]",
      ],
    }),
  "global:Exact.env.[[dynamic-table:call-result-83f13e6eeaf2-properties]]":
    residual({
      familyKind: "environment-proxy",
      globalName: "Exact",
      memberName: "env.[[dynamic-table:call-result-83f13e6eeaf2-properties]]",
      name: "global:Exact.env.[[dynamic-table:call-result-83f13e6eeaf2-properties]]",
      reasonCode: "ambient-environment-proxy-open-domain",
      reason:
        "Exact.env is an open environment proxy; no finite family membership proof may enumerate or select unauthored ambient environment names.",
      requiredIntegration: [
        "split each authorized environment name into an exact typed occurrence",
        "execute only its targeted Get with matching env:read authority",
        "treat the remaining open proxy domain as structural rather than output-complete",
      ],
      requiredMemberKinds: ["dynamic-table", "namespace-alias"],
      sourceKey: "global_exact_global",
      sourceRefs: [
        "src/engine/bootstrap/exact-global.js#Exact.env.[[dynamic-table:call-result-83f13e6eeaf2-properties]]",
      ],
    }),
  "global:Float16Array.[[dynamic-table:inherited-uint16-array-90265aa4ff-properties]]":
    residual({
      familyKind: "inherited-constructor-shape",
      globalName: "Float16Array",
      inheritedBase: "Uint16Array",
      memberName:
        "[[dynamic-table:inherited-uint16-array-90265aa4ff-properties]]",
      name: "global:Float16Array.[[dynamic-table:inherited-uint16-array-90265aa4ff-properties]]",
      reasonCode: "inherited-base-membership-unclosed",
      reason:
        "The extends clause proves Float16Array inherits from Uint16Array, but a prototype-lineage boolean does not close or account for the inherited Uint16Array member universe.",
      requiredIntegration: [
        "source-bind a finite Uint16Array constructor and prototype membership contract for every native/polyfill variant",
        "expand every inherited output-bearing member into a concrete output account",
        "prove each loaded Float16Array chain contains no unaccounted inherited member",
      ],
      requiredMemberKinds: ["dynamic-table", "inherited-shape"],
      sourceKey: "shared_runtime",
      sourceRefs: [
        "packages/ibex-runtime-js/src/bootstrap.ts#Float16Array:extends:Uint16Array",
        "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:Float16Array",
      ],
    }),
  "global:Intl.[[dynamic-table:host-intl-properties]]": residual({
    familyKind: "intl-proxy",
    globalName: "Intl",
    memberName: "[[dynamic-table:host-intl-properties]]",
    name: "global:Intl.[[dynamic-table:host-intl-properties]]",
    reasonCode: "ambient-intl-proxy-open-domain",
    reason:
      "The lazy Intl proxy exposes a host-dependent open domain; enumerating it cannot establish a stable exhaustive member universe.",
    requiredIntegration: [
      "split every supported Intl member into a concrete source-derived row",
      "account for each concrete member with a member-specific construction or property-read recipe",
      "leave the remaining host proxy domain structural rather than output-complete",
    ],
    requiredMemberKinds: ["dynamic-table", "proxy-overlay"],
    sourceKey: "shared_runtime",
    sourceRefs: [
      "packages/ibex-runtime-js/src/polyfills/index.ts#installPolyfills:globals:Intl",
    ],
  }),
  "global:process.[[dynamic-table:channel-handle-key]]": residual({
    familyKind: "ipc-owner-key-marker",
    globalName: "process",
    memberName: "[[dynamic-table:channel-handle-key]]",
    name: "global:process.[[dynamic-table:channel-handle-key]]",
    reasonCode: "dynamic-owner-key-marker-not-value",
    reason:
      "The sentinel denotes a mutable process owner key; only resolved concrete descendants can have output accounts, never the marker spelling itself.",
    requiredIntegration: [
      "retain the owner-key sentinel as structural inventory evidence",
      "resolve and account for every concrete descendant under each activation branch",
      "never read or serialize the sentinel spelling as a process property value",
    ],
    requiredMemberKinds: ["member-assignment"],
    sourceKey: "global_ipc_listener",
    sourceRefs: [
      "src/engine/bootstrap/ipc-listener.js#process.[[dynamic-table:channel-handle-key]]",
    ],
  }),
  "global:process.[[dynamic-table:exact-channel-handle-key]]": residual({
    familyKind: "ipc-owner-key-marker",
    globalName: "process",
    memberName: "[[dynamic-table:exact-channel-handle-key]]",
    name: "global:process.[[dynamic-table:exact-channel-handle-key]]",
    reasonCode: "dynamic-owner-key-marker-not-value",
    reason:
      "The conditional sentinel denotes a mutable process owner key whose installed value can be null; it is not an exact output-value contract.",
    requiredIntegration: [
      "retain the owner-key sentinel as structural evidence with its EXACT_IPC_FD activation",
      "resolve and account for every concrete descendant in each activation branch",
      "never read or serialize the sentinel spelling as a process property value",
    ],
    requiredMemberKinds: ["member-assignment"],
    sourceKey: "global_compat_polyfills",
    sourceRefs: [
      "src/engine/bootstrap/compat-polyfills.js#process.[[dynamic-table:exact-channel-handle-key]]",
    ],
  }),
  "global:process.[[dynamic-table:host-process-own-properties]]": residual({
    familyKind: "process-host-own-overlay",
    globalName: "process",
    memberName: "[[dynamic-table:host-process-own-properties]]",
    name: "global:process.[[dynamic-table:host-process-own-properties]]",
    reasonCode: "ambient-process-proxy-open-domain",
    reason:
      "Host process own properties are an open ambient domain; enumeration cannot prove a stable exhaustive output-member universe.",
    requiredIntegration: [
      "split every supported process own member into a concrete source-derived row",
      "account for each concrete member with a member-specific read or bounded call",
      "leave the remaining host overlay structural rather than output-complete",
    ],
    requiredMemberKinds: ["assignment", "dynamic-table"],
    sourceKey: "shared_runtime",
    sourceRefs: [
      "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:process.[[dynamic-table:host-process-own-properties]]",
    ],
  }),
  "global:process.[[dynamic-table:host-process-prototype-properties]]":
    residual({
      familyKind: "process-host-prototype-overlay",
      globalName: "process",
      memberName: "[[dynamic-table:host-process-prototype-properties]]",
      name: "global:process.[[dynamic-table:host-process-prototype-properties]]",
      reasonCode: "ambient-process-proxy-open-domain",
      reason:
        "Host process prototype properties are an open ambient domain; enumeration cannot prove a stable exhaustive output-member universe.",
      requiredIntegration: [
        "split every supported process prototype member into a concrete source-derived row",
        "account for each concrete member with a member-specific read or bounded call",
        "leave the remaining host overlay structural rather than output-complete",
      ],
      requiredMemberKinds: ["assignment", "dynamic-table"],
      sourceKey: "shared_runtime",
      sourceRefs: [
        "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:process.[[dynamic-table:host-process-prototype-properties]]",
      ],
    }),
  "global:process.[[dynamic-table:k-channel-handle]]": residual({
    familyKind: "ipc-owner-key-marker",
    globalName: "process",
    memberName: "[[dynamic-table:k-channel-handle]]",
    name: "global:process.[[dynamic-table:k-channel-handle]]",
    reasonCode: "dynamic-owner-key-marker-not-value",
    reason:
      "The conditional sentinel denotes a mutable process owner key; only resolved concrete descendants can have output accounts, never the marker spelling itself.",
    requiredIntegration: [
      "retain the owner-key sentinel as structural evidence with its EXACT_IPC_FD activation",
      "resolve and account for every concrete descendant in each activation branch",
      "never read or serialize the sentinel spelling as a process property value",
    ],
    requiredMemberKinds: ["member-assignment"],
    sourceKey: "global_compat_polyfills",
    sourceRefs: [
      "src/engine/bootstrap/compat-polyfills.js#process.[[dynamic-table:k-channel-handle]]",
    ],
  }),
  "global:process.env.[[dynamic-table:env-obj-properties]]": residual({
    expectedClassification: "effects",
    familyKind: "process-environment-object",
    globalName: "process",
    memberName: "env.[[dynamic-table:env-obj-properties]]",
    name: "global:process.env.[[dynamic-table:env-obj-properties]]",
    reasonCode: "ambient-environment-object-open-domain",
    reason:
      "process.env is an open environment object; enumerating it or choosing an unauthored key would disclose ambient host state, not prove output closure.",
    requiredIntegration: [
      "split each authorized environment name into an exact typed occurrence",
      "execute only its targeted Get with matching env:read authority",
      "treat the remaining environment object domain as structural rather than output-complete",
    ],
    requiredMemberKinds: ["dynamic-table"],
    sourceKey: "native_jsi_global",
    sourceRefs: [
      "src/engine/hermes_runtime_process_setup.cc#jsi-global:process.env.[[dynamic-table:env-obj-properties]]",
    ],
  }),
  "global:process.once.[[dynamic-table:call-result-621e9ebb69c5-properties]]":
    residual({
      dynamicNamespaceEvidence:
        "sha256-621e9ebb69c57ef4f2f25f6f1f639a6d4fb7faee4b9721f73582905622449f97",
      dynamicNamespaceRoot: "process.once",
      familyKind: "returned-wrapper-properties",
      globalName: "process",
      memberName: "once.[[dynamic-table:call-result-621e9ebb69c5-properties]]",
      name: "global:process.once.[[dynamic-table:call-result-621e9ebb69c5-properties]]",
      reasonCode: "returned-wrapper-membership-unclosed",
      reason:
        "The call-result digest binds wrapSingleUseListener's returned function, but reading only length does not close or account for the wrapper's complete own and inherited function shape.",
      requiredIntegration: [
        "derive a finite returned-wrapper own and prototype membership contract from the digested function expression and loaded Function intrinsics",
        "expand every output-bearing wrapper member into a concrete output account",
        "execute a loaded exhaustive membership comparison and prove no unaccounted wrapper key remains",
      ],
      requiredMemberKinds: ["dynamic-table"],
      sourceKey: "global_ipc_listener",
      sourceRefs: [
        "src/engine/bootstrap/ipc-listener.js#process.once.[[dynamic-table:call-result-621e9ebb69c5-properties]]",
      ],
    }),
  "global:process.prependOnceListener.[[dynamic-table:call-result-f0b2d7f38e0a-properties]]":
    residual({
      dynamicNamespaceEvidence:
        "sha256-f0b2d7f38e0a9e69373c435410db1eac4fbc5e2ea5a903ab8367aca9a0fbec98",
      dynamicNamespaceRoot: "process.prependOnceListener",
      familyKind: "returned-wrapper-properties",
      globalName: "process",
      memberName:
        "prependOnceListener.[[dynamic-table:call-result-f0b2d7f38e0a-properties]]",
      name: "global:process.prependOnceListener.[[dynamic-table:call-result-f0b2d7f38e0a-properties]]",
      reasonCode: "returned-wrapper-membership-unclosed",
      reason:
        "The call-result digest binds wrapSingleUseListener's returned function, but reading only length does not close or account for the wrapper's complete own and inherited function shape.",
      requiredIntegration: [
        "derive a finite returned-wrapper own and prototype membership contract from the digested function expression and loaded Function intrinsics",
        "expand every output-bearing wrapper member into a concrete output account",
        "execute a loaded exhaustive membership comparison and prove no unaccounted wrapper key remains",
      ],
      requiredMemberKinds: ["dynamic-table"],
      sourceKey: "global_ipc_listener",
      sourceRefs: [
        "src/engine/bootstrap/ipc-listener.js#process.prependOnceListener.[[dynamic-table:call-result-f0b2d7f38e0a-properties]]",
      ],
    }),
  "global:SharedArrayBuffer.prototype.[[dynamic-table:call-result-6409897f6685-properties]]":
    residual({
      dynamicNamespaceEvidence:
        "sha256-6409897f66853c6d91d6361cdfd919d7c8276d306e73b33aabe87a8e6bd4e48e",
      dynamicNamespaceRoot: "SharedArrayBuffer.prototype",
      familyKind: "prototype-call-result-properties",
      globalName: "SharedArrayBuffer",
      memberName:
        "prototype.[[dynamic-table:call-result-6409897f6685-properties]]",
      name: "global:SharedArrayBuffer.prototype.[[dynamic-table:call-result-6409897f6685-properties]]",
      reasonCode: "prototype-base-membership-unclosed",
      reason:
        "Object.create proves the compat prototype's lineage, but a lineage boolean does not close NativeArrayBuffer.prototype membership and does not cover the retained-native branch.",
      requiredIntegration: [
        "source-bind finite branch-specific SharedArrayBuffer and ArrayBuffer prototype membership contracts",
        "expand every own and inherited output-bearing member into a concrete output account",
        "prove both retained-native and compat-installed loaded branches contain no unaccounted prototype member",
      ],
      requiredMemberKinds: ["dynamic-table", "namespace-alias"],
      sourceKey: "global_compat_polyfills",
      sourceRefs: [
        "src/engine/bootstrap/compat-polyfills.js#SharedArrayBuffer.prototype.[[dynamic-table:call-result-6409897f6685-properties]]",
      ],
    }),
});

const FAMILY_NAMES = Object.freeze(Object.keys(FAMILY_CONTRACTS).sort());

// No reviewed family currently has an exhaustive membership proof.
export const DYNAMIC_GLOBAL_OUTPUT_COVERED_FAMILIES = Object.freeze([]);
export const DYNAMIC_GLOBAL_OUTPUT_RESIDUAL_FAMILIES = FAMILY_NAMES;

function validateSurfaceBinding(surface, coverageEdge) {
  const specification = FAMILY_CONTRACTS[surface?.name];
  if (!specification) return null;
  const metadata = surface?.metadata;
  if (
    surface.kind !== "native-op" ||
    surface.observedKey !== `native-op:${surface.name}` ||
    metadata?.surfaceType !== "global-api" ||
    metadata.globalName !== specification.globalName ||
    (metadata.memberName ?? null) !== specification.memberName ||
    metadata.sourceKey !== specification.sourceKey ||
    !Array.isArray(metadata.memberKinds) ||
    !specification.requiredMemberKinds.every((kind) =>
      metadata.memberKinds.includes(kind),
    ) ||
    JSON.stringify(surface.sourceRefs) !==
      JSON.stringify(specification.sourceRefs)
  ) {
    throw new Error(`${surface?.name}: dynamic-global source binding drift`);
  }
  if (
    specification.dynamicNamespaceEvidence &&
    (metadata.dynamicNamespaceEvidence !==
      specification.dynamicNamespaceEvidence ||
      metadata.dynamicNamespaceRoot !== specification.dynamicNamespaceRoot)
  ) {
    throw new Error(`${surface.name}: dynamic-global evidence drift`);
  }
  if (
    specification.inheritedBase &&
    (metadata.inheritedShape !== true ||
      !surface.sourceRefs.some((sourceRef) =>
        sourceRef.endsWith(`:extends:${specification.inheritedBase}`),
      ))
  ) {
    throw new Error(`${surface.name}: inherited source binding drift`);
  }
  if (
    !coverageEdge ||
    typeof coverageEdge.id !== "string" ||
    coverageEdge.id.length === 0 ||
    coverageEdge.classification !== specification.expectedClassification ||
    coverageEdge.surface?.kind !== "native-op" ||
    coverageEdge.surface.name !== surface.name
  ) {
    throw new Error(`${surface.name}: dynamic-global coverage binding drift`);
  }
  return specification;
}

export function reviewedDynamicGlobalOutputFamilies() {
  return FAMILY_NAMES.map((name) => {
    const specification = FAMILY_CONTRACTS[name];
    return structuredClone({
      familyName: name,
      status: "residual",
      familyKind: specification.familyKind,
      sourceRefs: specification.sourceRefs,
      reasonCode: specification.reasonCode,
      reason: specification.reason,
      requiredIntegration: specification.requiredIntegration,
    });
  });
}

export function dynamicGlobalOutputCatalogBindings() {
  return [];
}

export function dynamicGlobalOutputResidual({ surface, coverageEdge }) {
  const specification = validateSurfaceBinding(surface, coverageEdge);
  if (!specification) return null;
  return structuredClone({
    familyName: specification.name,
    status: "residual",
    reasonCode: specification.reasonCode,
    reason: specification.reason,
    requiredIntegration: specification.requiredIntegration,
  });
}

export function validateDynamicGlobalOutputInvocation(
  _invocation,
  { surface, coverageEdge },
) {
  const specification = validateSurfaceBinding(surface, coverageEdge);
  if (!specification) {
    throw new Error(`${surface?.name}: no reviewed dynamic-global family`);
  }
  throw new Error(
    `${surface.name}: no exhaustive dynamic-global output invocation; ${specification.reasonCode}`,
  );
}

export function authoredDynamicGlobalOutputInvocation({
  surface,
  coverageEdge,
}) {
  validateSurfaceBinding(surface, coverageEdge);
  return null;
}
