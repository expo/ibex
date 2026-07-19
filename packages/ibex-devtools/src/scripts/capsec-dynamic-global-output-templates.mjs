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
