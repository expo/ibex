/**
 * Loaded-Hermes structural accounts for inherited intrinsic sentinels.
 *
 * These accounts do not infer inherited members from TypeScript inheritance or
 * from an engine release number.  The source review below fixes the three
 * installation mechanisms and the checked-in Hermes artifact profiles.  A
 * descriptor-only probe must then run in each loaded profile and prove both the
 * complete own-key layers and the relevant object-identity aliases.
 *
 * This module intentionally has no output-catalog integration.  Its result is
 * an independently discovered, target-bound member universe for the remaining
 * Buffer, Float16Array, and compat SharedArrayBuffer sentinels.
 *
 * @ref LLP 0013#mechanism-1-lockdown — shared intrinsic
 * identity is part of the security boundary, not merely a matching key list.
 * @ref LLP 0013#upstream-tracking-and-re-derivation — every Hermes pin is a
 * reviewed fork identity and must be re-derived when its authority changes.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — an
 * accepted observation binds one mapped Hermes image and its exact target.
 * @ref LLP 0023#6-path-bearing-observables — output membership is an
 * independently generated universe, not evidence inferred from registration.
 */

import crypto from "node:crypto";
import path from "node:path";
import { parseSync } from "@babel/core";
import { canonicalJson } from "./capsec-contract.mjs";
import { validateLoadedEngineIdentity } from "./capsec-engine-identity.mjs";

export const INHERITED_INTRINSIC_ALIAS_SOURCE_REVIEW_SCHEMA =
  "ibex/capsec-inherited-intrinsic-alias-source-review/1";
export const INHERITED_INTRINSIC_ALIAS_OBSERVATION_SCHEMA =
  "ibex/capsec-inherited-intrinsic-alias-observation/1";
export const INHERITED_INTRINSIC_ALIAS_ACCOUNT_SCHEMA =
  "ibex/capsec-inherited-intrinsic-alias-structural-account/1";
export const INHERITED_INTRINSIC_ALIAS_ACCOUNT_SET_SCHEMA =
  "ibex/capsec-inherited-intrinsic-alias-account-set/1";
export const INHERITED_INTRINSIC_ALIAS_REASON_CODE =
  "loaded-hermes-intrinsic-inheritance-alias";
export const INHERITED_INTRINSIC_ALIAS_RUNTIME_EXECUTION_REQUIRED = true;
export const INHERITED_INTRINSIC_ALIAS_OUTPUT_CATALOG_BINDINGS = Object.freeze(
  [],
);

const BUFFER_PATH = "packages/ibex-runtime-js/src/node/Buffer.ts";
const RUNTIME_BOOTSTRAP_PATH = "packages/ibex-runtime-js/src/bootstrap.ts";
const COMPAT_BOOTSTRAP_PATH = "src/engine/bootstrap/compat-polyfills.js";

const REVIEWED_PROFILE_DIGEST =
  "sha256-b8edf4dd0c4fbbb3ca381938e652a6e7d5e674b896078687c558122f6108e4d6";
const REVIEWED_SOURCE_REVIEW_DIGEST =
  "sha256-b93cb6bd2ddf0564e79803eebcadd3253fe660b2a1050173381fa3cae7d333bb";

const REVIEWED_SOURCE_NODE_DIGESTS = Object.freeze({
  bufferImplementation:
    "sha256-221e6baed97d591f1cefa3d15b13b18550d077a2620dab1393218c315eecf705",
  bufferInstall:
    "sha256-c6735ca83c967944f49473eb9bcfff4d2b625c3527db4d3bf4374f2aeb8e8f55",
  bufferWrapperFactory:
    "sha256-3ab655925d1a8303f926e2d3d7d18a6c42413f0e705457bf73d03ddd6775dfec",
  float16Install:
    "sha256-36e06a36a57b9fbe58fedcd98fa0ba58efa119b897f62419926bce2b014b2fd3",
  sharedArrayBufferCompat:
    "sha256-576fc02da10258d0915f373704bafefea6a391d022558a902de6a864b554068d",
  sharedArrayBufferInvocation:
    "sha256-46d9a1c37ecbfc0d83519da1da01c8008d0815b9ca3b093e224460f75e4d6cc2",
});

const PROFILE_IDS = Object.freeze([
  "android-maven",
  "source-patched",
  "windows-nuget",
]);
const PROFILE_TARGET_VARIANTS = Object.freeze({
  "android-maven": "android",
  "source-patched": "default",
  "windows-nuget": "windows",
});

const FAMILY_SPECS = Object.freeze([
  deepFreeze({
    familyId: "buffer-uint8array",
    branch: "ibex-wrapper-installed",
    dynamicSelectors: [
      "global:Buffer.[[dynamic-table:inherited-uint8-array-6128693053-properties]]",
    ],
    profileIds: PROFILE_IDS,
    sourceProofKeys: [
      "bufferImplementation",
      "bufferWrapperFactory",
      "bufferInstall",
    ],
    sourceRefs: [
      `${BUFFER_PATH}#Buffer:extends:Uint8Array`,
      `${RUNTIME_BOOTSTRAP_PATH}#createGlobalBufferConstructor`,
      `${RUNTIME_BOOTSTRAP_PATH}#installGlobals:globals:Buffer`,
    ],
    chainSpecs: [
      {
        role: "constructor-chain",
        prefixLayerRoles: [
          "wrapper-constructor",
          "implementation-constructor",
          "base-constructor",
        ],
      },
      {
        role: "prototype-chain",
        prefixLayerRoles: [
          "implementation-prototype",
          "base-prototype",
        ],
      },
    ],
    aliasNames: [
      "constructorDistinctFromImplementation",
      "wrapperPrototypeIsImplementationPrototype",
      "implementationConstructorInheritsBase",
      "implementationPrototypeInheritsBasePrototype",
    ],
  }),
  deepFreeze({
    familyId: "float16array-uint16array",
    branch: "ibex-polyfill-installed",
    dynamicSelectors: [
      "global:Float16Array.[[dynamic-table:inherited-uint16-array-90265aa4ff-properties]]",
    ],
    profileIds: PROFILE_IDS,
    sourceProofKeys: ["float16Install"],
    sourceRefs: [
      `${RUNTIME_BOOTSTRAP_PATH}#installGlobals:globals:Float16Array`,
    ],
    chainSpecs: [
      {
        role: "constructor-chain",
        prefixLayerRoles: ["polyfill-constructor", "base-constructor"],
      },
      {
        role: "prototype-chain",
        prefixLayerRoles: ["polyfill-prototype", "base-prototype"],
      },
    ],
    aliasNames: [
      "constructorDistinctFromBase",
      "constructorInheritsBase",
      "prototypeInheritsBasePrototype",
      "polyfillBytesPerElementAccessor",
      "polyfillToStringTagAccessor",
    ],
  }),
  deepFreeze({
    familyId: "compat-sharedarraybuffer-arraybuffer-prototype",
    branch: "compat-installed",
    dynamicSelectors: [
      "global:SharedArrayBuffer.prototype.[[dynamic-table:call-result-6409897f6685-properties]]",
    ],
    profileIds: ["android-maven", "source-patched"],
    sourceProofKeys: [
      "sharedArrayBufferCompat",
      "sharedArrayBufferInvocation",
    ],
    sourceRefs: [
      `${COMPAT_BOOTSTRAP_PATH}#__exactPatchBrokenSharedArrayBuffer`,
    ],
    chainSpecs: [
      {
        role: "constructor-chain",
        prefixLayerRoles: ["compat-constructor", "function-prototype"],
      },
      {
        role: "prototype-chain",
        prefixLayerRoles: ["compat-prototype", "base-prototype"],
      },
    ],
    aliasNames: [
      "constructorInheritsFunctionPrototype",
      "prototypeDistinctFromBasePrototype",
      "prototypeInheritsBasePrototype",
      "prototypeConstructorBackReference",
      "compatToStringTag",
    ],
  }),
]);

export const INHERITED_INTRINSIC_ALIAS_FAMILIES = Object.freeze(
  FAMILY_SPECS.map((spec) => spec.familyId),
);

const AST_IGNORED_FIELDS = new Set([
  "comments",
  "end",
  "errors",
  "extra",
  "innerComments",
  "leadingComments",
  "loc",
  "start",
  "trailingComments",
]);

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256Hex(value) {
  return `sha256-${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function taggedDigest(domain, value) {
  return sha256Hex(`${domain}\0${canonicalJson(value)}`);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function exactFields(value, fields) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalJson(Object.keys(value).sort(compareText)) ===
      canonicalJson([...fields].sort(compareText))
  );
}

function uniqueSortedStrings(values, label) {
  if (
    !Array.isArray(values) ||
    values.some((value) => typeof value !== "string" || value.length === 0)
  ) {
    throw new Error(`${label}: expected non-empty string members`);
  }
  const sorted = [...values].sort(compareText);
  if (new Set(sorted).size !== sorted.length) {
    throw new Error(`${label}: members must be unique`);
  }
  return sorted;
}

function assertJsonValue(value, label) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((child, index) => assertJsonValue(child, `${label}[${index}]`));
    return;
  }
  if (
    !value ||
    typeof value !== "object" ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(`${label}: expected a plain JSON value`);
  }
  for (const [key, child] of Object.entries(value)) {
    if (child === undefined) throw new Error(`${label}.${key}: undefined value`);
    assertJsonValue(child, `${label}.${key}`);
  }
}

function canonicalAst(value) {
  if (Array.isArray(value)) return value.map(canonicalAst);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .filter((key) => !AST_IGNORED_FIELDS.has(key))
      .sort(compareText)
      .map((key) => [key, canonicalAst(value[key])]),
  );
}

function astDigest(node) {
  return sha256Hex(canonicalJson(canonicalAst(node)));
}

function parseProgram(text, sourcePath) {
  if (typeof text !== "string") {
    throw new Error(`${sourcePath}: source text is absent`);
  }
  const plugins = sourcePath.endsWith(".ts") ? ["typescript"] : [];
  try {
    return parseSync(text, {
      ast: true,
      babelrc: false,
      code: false,
      configFile: false,
      parserOpts: { plugins },
      sourceType: "unambiguous",
    }).program;
  } catch (error) {
    throw new Error(`${sourcePath}: unable to parse exact source: ${error.message}`);
  }
}

function walkAst(root) {
  const nodes = [];
  const stack = [root];
  while (stack.length > 0) {
    const node = stack.pop();
    if (!node || typeof node !== "object") continue;
    if (typeof node.type === "string") nodes.push(node);
    for (const [key, value] of Object.entries(node)) {
      if (AST_IGNORED_FIELDS.has(key)) continue;
      if (Array.isArray(value)) {
        for (let index = value.length - 1; index >= 0; index -= 1) {
          stack.push(value[index]);
        }
      } else if (value && typeof value === "object") {
        stack.push(value);
      }
    }
  }
  return nodes;
}

function oneAstNode(nodes, predicate, label) {
  const matches = nodes.filter(predicate);
  if (matches.length !== 1) {
    throw new Error(`${label}: expected exactly one reviewed AST node`);
  }
  return matches[0];
}

function isDirectMember(node, objectName, propertyName) {
  return (
    node?.type === "MemberExpression" &&
    !node.computed &&
    node.object?.type === "Identifier" &&
    node.object.name === objectName &&
    node.property?.type === "Identifier" &&
    node.property.name === propertyName
  );
}

function isUndefinedGlobalBranch(node, objectName, propertyName) {
  return (
    node?.type === "IfStatement" &&
    node.test?.type === "BinaryExpression" &&
    node.test.operator === "===" &&
    node.test.left?.type === "UnaryExpression" &&
    node.test.left.operator === "typeof" &&
    isDirectMember(node.test.left.argument, objectName, propertyName) &&
    node.test.right?.type === "StringLiteral" &&
    node.test.right.value === "undefined"
  );
}

function reviewedSourceNodes(sourceFiles) {
  const bufferNodes = walkAst(parseProgram(sourceFiles[BUFFER_PATH], BUFFER_PATH));
  const bootstrapNodes = walkAst(
    parseProgram(sourceFiles[RUNTIME_BOOTSTRAP_PATH], RUNTIME_BOOTSTRAP_PATH),
  );
  const compatNodes = walkAst(
    parseProgram(sourceFiles[COMPAT_BOOTSTRAP_PATH], COMPAT_BOOTSTRAP_PATH),
  );
  return {
    bufferImplementation: oneAstNode(
      bufferNodes,
      (node) =>
        node.type === "ClassDeclaration" &&
        node.id?.name === "Buffer" &&
        node.superClass?.type === "Identifier" &&
        node.superClass.name === "Uint8Array",
      `${BUFFER_PATH}#Buffer`,
    ),
    bufferWrapperFactory: oneAstNode(
      bootstrapNodes,
      (node) =>
        node.type === "FunctionDeclaration" &&
        node.id?.name === "createGlobalBufferConstructor",
      `${RUNTIME_BOOTSTRAP_PATH}#createGlobalBufferConstructor`,
    ),
    bufferInstall: oneAstNode(
      bootstrapNodes,
      (node) => isUndefinedGlobalBranch(node, "g", "Buffer"),
      `${RUNTIME_BOOTSTRAP_PATH}#globals:Buffer`,
    ),
    float16Install: oneAstNode(
      bootstrapNodes,
      (node) => isUndefinedGlobalBranch(node, "g", "Float16Array"),
      `${RUNTIME_BOOTSTRAP_PATH}#globals:Float16Array`,
    ),
    sharedArrayBufferCompat: oneAstNode(
      compatNodes,
      (node) =>
        node.type === "FunctionDeclaration" &&
        node.id?.name === "__exactPatchBrokenSharedArrayBuffer",
      `${COMPAT_BOOTSTRAP_PATH}#__exactPatchBrokenSharedArrayBuffer`,
    ),
    sharedArrayBufferInvocation: oneAstNode(
      compatNodes,
      (node) =>
        node.type === "ExpressionStatement" &&
        node.expression?.type === "CallExpression" &&
        node.expression.callee?.type === "Identifier" &&
        node.expression.callee.name === "__exactPatchBrokenSharedArrayBuffer",
      `${COMPAT_BOOTSTRAP_PATH}#__exactPatchBrokenSharedArrayBuffer:call`,
    ),
  };
}

function normalizeProfiles(engineProfiles) {
  if (!Array.isArray(engineProfiles)) {
    throw new Error("Hermes profiles are absent");
  }
  const normalized = engineProfiles.map((profile) => {
    if (
      !exactFields(profile, [
        "id",
        "identity",
        "reachableEvaluators",
        "sourceRefs",
        "targetVariant",
      ]) ||
      typeof profile.id !== "string" ||
      typeof profile.targetVariant !== "string" ||
      !profile.identity ||
      typeof profile.identity !== "object" ||
      Array.isArray(profile.identity)
    ) {
      throw new Error("Hermes profile has malformed exact fields");
    }
    assertJsonValue(profile.identity, `Hermes profile ${profile.id} identity`);
    return {
      id: profile.id,
      targetVariant: profile.targetVariant,
      identity: JSON.parse(canonicalJson(profile.identity)),
      reachableEvaluators: uniqueSortedStrings(
        profile.reachableEvaluators,
        `Hermes profile ${profile.id} evaluators`,
      ),
      sourceRefs: uniqueSortedStrings(
        profile.sourceRefs,
        `Hermes profile ${profile.id} source refs`,
      ),
    };
  });
  normalized.sort((left, right) => compareText(left.id, right.id));
  if (
    canonicalJson(normalized.map((profile) => profile.id)) !==
    canonicalJson(PROFILE_IDS)
  ) {
    throw new Error("Hermes profile set drifted from the reviewed profiles");
  }
  const digest = sha256Hex(canonicalJson(normalized));
  if (digest !== REVIEWED_PROFILE_DIGEST) {
    throw new Error("Hermes profile identity or authority drifted from review");
  }
  return { profiles: normalized, profileReviewDigest: digest };
}

function sourceFamilyReview() {
  return Object.fromEntries(
    FAMILY_SPECS.map((spec) => [
      spec.familyId,
      {
        dynamicSelectors: spec.dynamicSelectors,
        profileIds: spec.profileIds,
        sourceProofKeys: spec.sourceProofKeys,
        sourceRefs: spec.sourceRefs,
      },
    ]),
  );
}

export function auditInheritedIntrinsicAliasSources({
  sourceFiles,
  engineProfiles,
}) {
  if (!sourceFiles || typeof sourceFiles !== "object") {
    throw new Error("inherited intrinsic source files are absent");
  }
  const nodes = reviewedSourceNodes(sourceFiles);
  const sourceProofs = Object.fromEntries(
    Object.entries(nodes).map(([proofKey, node]) => {
      const digest = astDigest(node);
      if (digest !== REVIEWED_SOURCE_NODE_DIGESTS[proofKey]) {
        throw new Error(`${proofKey}: reviewed source AST drifted`);
      }
      return [proofKey, { astDigest: digest }];
    }),
  );
  const { profiles, profileReviewDigest } = normalizeProfiles(engineProfiles);
  const sourceReviewDigest = taggedDigest(
    "ibex.capsec.inherited-intrinsic-alias.source-review.v1",
    {
      schema: INHERITED_INTRINSIC_ALIAS_SOURCE_REVIEW_SCHEMA,
      profileReviewDigest,
      sourceProofs,
    },
  );
  if (sourceReviewDigest !== REVIEWED_SOURCE_REVIEW_DIGEST) {
    throw new Error("inherited intrinsic source-review contract drifted");
  }
  return deepFreeze({
    schema: INHERITED_INTRINSIC_ALIAS_SOURCE_REVIEW_SCHEMA,
    sourceReviewDigest,
    profileReviewDigest,
    profiles,
    sourceProofs,
    families: sourceFamilyReview(),
    runtimeExecutionRequired: true,
  });
}

function validateSourceAudit(sourceAudit) {
  if (
    !exactFields(sourceAudit, [
      "families",
      "profileReviewDigest",
      "profiles",
      "runtimeExecutionRequired",
      "schema",
      "sourceProofs",
      "sourceReviewDigest",
    ]) ||
    sourceAudit.schema !== INHERITED_INTRINSIC_ALIAS_SOURCE_REVIEW_SCHEMA ||
    sourceAudit.runtimeExecutionRequired !== true ||
    sourceAudit.profileReviewDigest !== REVIEWED_PROFILE_DIGEST ||
    sourceAudit.sourceReviewDigest !== REVIEWED_SOURCE_REVIEW_DIGEST ||
    !exactFields(sourceAudit.sourceProofs, Object.keys(REVIEWED_SOURCE_NODE_DIGESTS)) ||
    canonicalJson(sourceAudit.families) !== canonicalJson(sourceFamilyReview())
  ) {
    throw new Error("inherited intrinsic source audit is absent or unreviewed");
  }
  for (const [proofKey, digest] of Object.entries(
    REVIEWED_SOURCE_NODE_DIGESTS,
  )) {
    const proof = sourceAudit.sourceProofs[proofKey];
    if (!exactFields(proof, ["astDigest"]) || proof.astDigest !== digest) {
      throw new Error(`${proofKey}: source audit proof drifted from review`);
    }
  }
  const normalized = normalizeProfiles(sourceAudit.profiles);
  if (
    canonicalJson(normalized.profiles) !== canonicalJson(sourceAudit.profiles)
  ) {
    throw new Error("inherited intrinsic source audit profiles are not canonical");
  }
  const expectedReviewDigest = taggedDigest(
    "ibex.capsec.inherited-intrinsic-alias.source-review.v1",
    {
      schema: sourceAudit.schema,
      profileReviewDigest: sourceAudit.profileReviewDigest,
      sourceProofs: sourceAudit.sourceProofs,
    },
  );
  if (sourceAudit.sourceReviewDigest !== expectedReviewDigest) {
    throw new Error("inherited intrinsic source review digest drifted");
  }
  return normalized.profiles;
}

function targetVariantForTriple(triple) {
  if (triple.includes("android")) return "android";
  if (triple.includes("windows")) return "windows";
  return "default";
}

function normalizeTarget(target, label = "target") {
  if (
    !exactFields(target, ["features", "triple"]) ||
    typeof target.triple !== "string" ||
    !/^[A-Za-z0-9_.+]+(?:-[A-Za-z0-9_.+]+)+$/u.test(target.triple)
  ) {
    throw new Error(`${label}: malformed exact target`);
  }
  return {
    triple: target.triple,
    features: uniqueSortedStrings(target.features, `${label} features`),
  };
}

function profileFromAudit(sourceAudit, profileId) {
  const profiles = validateSourceAudit(sourceAudit);
  const profile = profiles.find((entry) => entry.id === profileId);
  if (!profile) throw new Error(`unknown reviewed Hermes profile ${profileId}`);
  return profile;
}

function familySpecsForProfile(profileId) {
  return FAMILY_SPECS.filter((spec) => spec.profileIds.includes(profileId));
}

/**
 * Self-contained runtime body.  The string form of this function is the exact
 * code sent to Hermes, so it must not close over module helpers.
 */
function loadedIntrinsicAliasProbe(binding) {
  var globalObject = globalThis;
  var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  var getPrototypeOf = Object.getPrototypeOf;
  var hasOwnProperty = Object.prototype.hasOwnProperty;
  var reflectApply = Reflect.apply;
  var reflectOwnKeys = Reflect.ownKeys;
  var symbolKeyFor = Symbol.keyFor;
  var symbolConstructor = Symbol;
  var wellKnownSymbolNames = [
    "asyncIterator",
    "hasInstance",
    "isConcatSpreadable",
    "iterator",
    "match",
    "matchAll",
    "replace",
    "search",
    "species",
    "split",
    "toPrimitive",
    "toStringTag",
    "unscopables",
  ];

  function compare(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
  }

  function insertionSort(values, key) {
    for (var index = 1; index < values.length; index += 1) {
      var current = values[index];
      var cursor = index - 1;
      while (cursor >= 0 && compare(key(values[cursor]), key(current)) > 0) {
        values[cursor + 1] = values[cursor];
        cursor -= 1;
      }
      values[cursor + 1] = current;
    }
    return values;
  }

  function globalData(name) {
    var descriptor = getOwnPropertyDescriptor(globalObject, name);
    if (
      !descriptor ||
      !reflectApply(hasOwnProperty, descriptor, ["value"])
    ) {
      throw new Error("intrinsic global is not an own data property: " + name);
    }
    return descriptor.value;
  }

  function keyToken(key) {
    if (typeof key === "string") return { kind: "string", value: key };
    for (var index = 0; index < wellKnownSymbolNames.length; index += 1) {
      var name = wellKnownSymbolNames[index];
      var descriptor = getOwnPropertyDescriptor(symbolConstructor, name);
      if (descriptor && descriptor.value === key) {
        return { kind: "well-known-symbol", value: name };
      }
    }
    var registryKey = reflectApply(symbolKeyFor, symbolConstructor, [key]);
    if (registryKey !== undefined) {
      return { kind: "global-symbol", value: registryKey };
    }
    throw new Error("unreviewed non-global symbol key in intrinsic membership");
  }

  function keySortValue(token) {
    return token.kind + ":" + token.value;
  }

  function ownLayer(role, value, depth) {
    if (
      value === null ||
      (typeof value !== "object" && typeof value !== "function")
    ) {
      throw new Error("intrinsic layer is not an object: " + role);
    }
    var keys = reflectOwnKeys(value);
    var descriptors = [];
    for (var index = 0; index < keys.length; index += 1) {
      var key = keys[index];
      var descriptor = getOwnPropertyDescriptor(value, key);
      if (!descriptor) throw new Error("own key has no descriptor: " + role);
      var member = {
        key: keyToken(key),
        configurable: descriptor.configurable === true,
        enumerable: descriptor.enumerable === true,
      };
      if (reflectApply(hasOwnProperty, descriptor, ["value"])) {
        member.kind = "data";
        member.writable = descriptor.writable === true;
      } else {
        member.kind = "accessor";
        member.get = typeof descriptor.get === "function";
        member.set = typeof descriptor.set === "function";
      }
      descriptors.push(member);
    }
    insertionSort(descriptors, function (entry) {
      return keySortValue(entry.key);
    });
    return { depth: depth, role: role, ownDescriptors: descriptors };
  }

  function completeChain(role, value, prefixLayerRoles, inheritedLayerRole) {
    var layers = [];
    var seen = [];
    var current = value;
    while (current !== null) {
      if (layers.length >= 32) {
        throw new Error("intrinsic prototype chain exceeds reviewed budget: " + role);
      }
      for (var seenIndex = 0; seenIndex < seen.length; seenIndex += 1) {
        if (seen[seenIndex] === current) {
          throw new Error("intrinsic prototype chain contains a cycle: " + role);
        }
      }
      seen.push(current);
      var layerRole =
        layers.length < prefixLayerRoles.length
          ? prefixLayerRoles[layers.length]
          : inheritedLayerRole;
      layers.push(ownLayer(layerRole, current, layers.length));
      current = getPrototypeOf(current);
    }
    return { role: role, layers: layers, terminatedAtNull: true };
  }

  function bufferFamily() {
    var wrapper = globalData("Buffer");
    var base = globalData("Uint8Array");
    var implementation = getPrototypeOf(wrapper);
    var wrapperPrototype = wrapper.prototype;
    var aliases = {
      constructorDistinctFromImplementation: wrapper !== implementation,
      wrapperPrototypeIsImplementationPrototype:
        wrapperPrototype === implementation.prototype,
      implementationConstructorInheritsBase:
        getPrototypeOf(implementation) === base,
      implementationPrototypeInheritsBasePrototype:
        getPrototypeOf(wrapperPrototype) === base.prototype,
    };
    var installed =
      aliases.constructorDistinctFromImplementation &&
      aliases.wrapperPrototypeIsImplementationPrototype &&
      aliases.implementationConstructorInheritsBase &&
      aliases.implementationPrototypeInheritsBasePrototype;
    return {
      familyId: "buffer-uint8array",
      branch: installed ? "ibex-wrapper-installed" : "unreviewed",
      chains: [
        completeChain(
          "constructor-chain",
          wrapper,
          [
            "wrapper-constructor",
            "implementation-constructor",
            "base-constructor",
          ],
          "inherited-constructor-layer",
        ),
        completeChain(
          "prototype-chain",
          wrapperPrototype,
          ["implementation-prototype", "base-prototype"],
          "inherited-prototype-layer",
        ),
      ],
      aliases: aliases,
    };
  }

  function float16Family() {
    var polyfill = globalData("Float16Array");
    var base = globalData("Uint16Array");
    var bytesDescriptor = getOwnPropertyDescriptor(
      polyfill,
      "BYTES_PER_ELEMENT",
    );
    var tagDescriptor = getOwnPropertyDescriptor(
      polyfill.prototype,
      symbolConstructor.toStringTag,
    );
    var aliases = {
      constructorDistinctFromBase: polyfill !== base,
      constructorInheritsBase: getPrototypeOf(polyfill) === base,
      prototypeInheritsBasePrototype:
        getPrototypeOf(polyfill.prototype) === base.prototype,
      polyfillBytesPerElementAccessor:
        !!bytesDescriptor && typeof bytesDescriptor.get === "function",
      polyfillToStringTagAccessor:
        !!tagDescriptor && typeof tagDescriptor.get === "function",
    };
    var installed =
      aliases.constructorDistinctFromBase &&
      aliases.constructorInheritsBase &&
      aliases.prototypeInheritsBasePrototype &&
      aliases.polyfillBytesPerElementAccessor &&
      aliases.polyfillToStringTagAccessor;
    return {
      familyId: "float16array-uint16array",
      branch: installed ? "ibex-polyfill-installed" : "unreviewed",
      chains: [
        completeChain(
          "constructor-chain",
          polyfill,
          ["polyfill-constructor", "base-constructor"],
          "inherited-constructor-layer",
        ),
        completeChain(
          "prototype-chain",
          polyfill.prototype,
          ["polyfill-prototype", "base-prototype"],
          "inherited-prototype-layer",
        ),
      ],
      aliases: aliases,
    };
  }

  function sharedArrayBufferFamily() {
    var compat = globalData("SharedArrayBuffer");
    var base = globalData("ArrayBuffer");
    var functionConstructor = globalData("Function");
    var prototype = compat.prototype;
    var constructorDescriptor = getOwnPropertyDescriptor(
      prototype,
      "constructor",
    );
    var tagDescriptor = getOwnPropertyDescriptor(
      prototype,
      symbolConstructor.toStringTag,
    );
    var aliases = {
      constructorInheritsFunctionPrototype:
        getPrototypeOf(compat) === functionConstructor.prototype,
      prototypeDistinctFromBasePrototype: prototype !== base.prototype,
      prototypeInheritsBasePrototype:
        getPrototypeOf(prototype) === base.prototype,
      prototypeConstructorBackReference:
        !!constructorDescriptor && constructorDescriptor.value === compat,
      compatToStringTag:
        !!tagDescriptor && tagDescriptor.value === "SharedArrayBuffer",
    };
    var installed =
      aliases.constructorInheritsFunctionPrototype &&
      aliases.prototypeDistinctFromBasePrototype &&
      aliases.prototypeInheritsBasePrototype &&
      aliases.prototypeConstructorBackReference &&
      aliases.compatToStringTag;
    return {
      familyId: "compat-sharedarraybuffer-arraybuffer-prototype",
      branch: installed ? "compat-installed" : "retained-native",
      chains: [
        completeChain(
          "constructor-chain",
          compat,
          ["compat-constructor", "function-prototype"],
          "inherited-constructor-layer",
        ),
        completeChain(
          "prototype-chain",
          prototype,
          ["compat-prototype", "base-prototype"],
          "inherited-prototype-layer",
        ),
      ],
      aliases: aliases,
    };
  }

  var families = [];
  for (var index = 0; index < binding.familyIds.length; index += 1) {
    var familyId = binding.familyIds[index];
    if (familyId === "buffer-uint8array") families.push(bufferFamily());
    else if (familyId === "float16array-uint16array") {
      families.push(float16Family());
    } else if (
      familyId === "compat-sharedarraybuffer-arraybuffer-prototype"
    ) {
      families.push(sharedArrayBufferFamily());
    } else {
      throw new Error("unreviewed inherited intrinsic family: " + familyId);
    }
  }
  return {
    schema: binding.schema,
    profileId: binding.profileId,
    targetVariant: binding.targetVariant,
    targetTriple: binding.targetTriple,
    structuralFeatures: binding.structuralFeatures,
    sourceReviewDigest: binding.sourceReviewDigest,
    profileReviewDigest: binding.profileReviewDigest,
    probeContractDigest: binding.probeContractDigest,
    families: families,
  };
}

const PROBE_RUNTIME_SOURCE = loadedIntrinsicAliasProbe.toString();
const PROBE_CONTRACT_DIGEST = sha256Hex(PROBE_RUNTIME_SOURCE);

function probeBinding({ sourceAudit, profileId, target }) {
  const profile = profileFromAudit(sourceAudit, profileId);
  const normalizedTarget = normalizeTarget(target);
  if (
    profile.targetVariant !== targetVariantForTriple(normalizedTarget.triple)
  ) {
    throw new Error(
      `target ${normalizedTarget.triple} does not match profile ${profile.id}`,
    );
  }
  return {
    schema: INHERITED_INTRINSIC_ALIAS_OBSERVATION_SCHEMA,
    profileId: profile.id,
    targetVariant: profile.targetVariant,
    targetTriple: normalizedTarget.triple,
    structuralFeatures: normalizedTarget.features,
    sourceReviewDigest: sourceAudit.sourceReviewDigest,
    profileReviewDigest: sourceAudit.profileReviewDigest,
    probeContractDigest: PROBE_CONTRACT_DIGEST,
    familyIds: familySpecsForProfile(profile.id).map((spec) => spec.familyId),
  };
}

export function inheritedIntrinsicAliasProbe({
  sourceAudit,
  profileId,
  target,
}) {
  const binding = probeBinding({ sourceAudit, profileId, target });
  const source = `(${PROBE_RUNTIME_SOURCE})(${canonicalJson(binding)})`;
  return deepFreeze({
    schema: INHERITED_INTRINSIC_ALIAS_OBSERVATION_SCHEMA,
    binding,
    source,
    sourceDigest: sha256Hex(source),
  });
}

const WELL_KNOWN_SYMBOL_NAMES = new Set([
  "asyncIterator",
  "hasInstance",
  "isConcatSpreadable",
  "iterator",
  "match",
  "matchAll",
  "replace",
  "search",
  "species",
  "split",
  "toPrimitive",
  "toStringTag",
  "unscopables",
]);

function normalizeKeyToken(key, label) {
  if (
    !exactFields(key, ["kind", "value"]) ||
    typeof key.value !== "string" ||
    !new Set(["global-symbol", "string", "well-known-symbol"]).has(key.kind) ||
    (key.kind === "well-known-symbol" &&
      !WELL_KNOWN_SYMBOL_NAMES.has(key.value))
  ) {
    throw new Error(`${label}: malformed exact property key`);
  }
  return { kind: key.kind, value: key.value };
}

function descriptorSortValue(descriptor) {
  return `${descriptor.key.kind}:${descriptor.key.value}`;
}

function normalizeDescriptor(descriptor, label) {
  const commonFields = ["configurable", "enumerable", "key", "kind"];
  if (
    !descriptor ||
    typeof descriptor !== "object" ||
    !new Set(["accessor", "data"]).has(descriptor.kind) ||
    typeof descriptor.configurable !== "boolean" ||
    typeof descriptor.enumerable !== "boolean"
  ) {
    throw new Error(`${label}: malformed own descriptor`);
  }
  const fields =
    descriptor.kind === "data"
      ? [...commonFields, "writable"]
      : [...commonFields, "get", "set"];
  if (!exactFields(descriptor, fields)) {
    throw new Error(`${label}: descriptor fields drifted`);
  }
  const normalized = {
    key: normalizeKeyToken(descriptor.key, `${label} key`),
    configurable: descriptor.configurable,
    enumerable: descriptor.enumerable,
    kind: descriptor.kind,
  };
  if (descriptor.kind === "data") {
    if (typeof descriptor.writable !== "boolean") {
      throw new Error(`${label}: malformed data descriptor`);
    }
    normalized.writable = descriptor.writable;
  } else {
    if (typeof descriptor.get !== "boolean" || typeof descriptor.set !== "boolean") {
      throw new Error(`${label}: malformed accessor descriptor`);
    }
    normalized.get = descriptor.get;
    normalized.set = descriptor.set;
  }
  return normalized;
}

function normalizeLayer(layer, expectedRole, expectedDepth, label) {
  if (
    !exactFields(layer, ["depth", "ownDescriptors", "role"]) ||
    layer.role !== expectedRole ||
    layer.depth !== expectedDepth ||
    !Array.isArray(layer.ownDescriptors)
  ) {
    throw new Error(`${label}: intrinsic membership layer drifted`);
  }
  const ownDescriptors = layer.ownDescriptors.map((descriptor, index) =>
    normalizeDescriptor(descriptor, `${label} descriptor ${index}`),
  );
  const sortValues = ownDescriptors.map(descriptorSortValue);
  const sorted = [...sortValues].sort(compareText);
  if (
    new Set(sortValues).size !== sortValues.length ||
    canonicalJson(sortValues) !== canonicalJson(sorted)
  ) {
    throw new Error(`${label}: own keys are duplicate or not canonical`);
  }
  return { depth: layer.depth, role: layer.role, ownDescriptors };
}

function normalizeChain(chain, chainSpec, label) {
  if (
    !exactFields(chain, ["layers", "role", "terminatedAtNull"]) ||
    chain.role !== chainSpec.role ||
    chain.terminatedAtNull !== true ||
    !Array.isArray(chain.layers) ||
    chain.layers.length < chainSpec.prefixLayerRoles.length ||
    chain.layers.length > 32
  ) {
    throw new Error(`${label}: exhaustive prototype chain drifted`);
  }
  const inheritedRole =
    chainSpec.role === "constructor-chain"
      ? "inherited-constructor-layer"
      : "inherited-prototype-layer";
  return {
    role: chain.role,
    layers: chain.layers.map((layer, index) =>
      normalizeLayer(
        layer,
        chainSpec.prefixLayerRoles[index] ?? inheritedRole,
        index,
        `${label} depth ${index}`,
      ),
    ),
    terminatedAtNull: true,
  };
}

function normalizeFamilyObservation(family, spec, label) {
  if (
    !exactFields(family, ["aliases", "branch", "chains", "familyId"]) ||
    family.familyId !== spec.familyId ||
    family.branch !== spec.branch ||
    !Array.isArray(family.chains) ||
    family.chains.length !== spec.chainSpecs.length ||
    !exactFields(family.aliases, spec.aliasNames)
  ) {
    throw new Error(`${label}: family branch or shape drifted`);
  }
  for (const aliasName of spec.aliasNames) {
    if (family.aliases[aliasName] !== true) {
      throw new Error(`${label}: identity alias ${aliasName} is not proven`);
    }
  }
  return {
    familyId: family.familyId,
    branch: family.branch,
    chains: family.chains.map((chain, index) =>
      normalizeChain(chain, spec.chainSpecs[index], `${label} ${spec.chainSpecs[index].role}`),
    ),
    aliases: Object.fromEntries(
      spec.aliasNames.map((aliasName) => [aliasName, true]),
    ),
  };
}

function normalizeObservation(observation, binding) {
  if (
    !exactFields(observation, [
      "families",
      "probeContractDigest",
      "profileId",
      "profileReviewDigest",
      "schema",
      "sourceReviewDigest",
      "structuralFeatures",
      "targetTriple",
      "targetVariant",
    ]) ||
    observation.schema !== binding.schema ||
    observation.profileId !== binding.profileId ||
    observation.targetVariant !== binding.targetVariant ||
    observation.targetTriple !== binding.targetTriple ||
    canonicalJson(observation.structuralFeatures) !==
      canonicalJson(binding.structuralFeatures) ||
    observation.sourceReviewDigest !== binding.sourceReviewDigest ||
    observation.profileReviewDigest !== binding.profileReviewDigest ||
    observation.probeContractDigest !== binding.probeContractDigest ||
    !Array.isArray(observation.families)
  ) {
    throw new Error("loaded intrinsic observation is not bound to its probe");
  }
  const specs = familySpecsForProfile(binding.profileId);
  if (observation.families.length !== specs.length) {
    throw new Error("loaded intrinsic observation has a profile-family drift");
  }
  return {
    schema: observation.schema,
    profileId: observation.profileId,
    targetVariant: observation.targetVariant,
    targetTriple: observation.targetTriple,
    structuralFeatures: [...observation.structuralFeatures],
    sourceReviewDigest: observation.sourceReviewDigest,
    profileReviewDigest: observation.profileReviewDigest,
    probeContractDigest: observation.probeContractDigest,
    families: specs.map((spec, index) =>
      normalizeFamilyObservation(
        observation.families[index],
        spec,
        `${binding.profileId} ${spec.familyId}`,
      ),
    ),
  };
}

function normalizeExecution(execution, sourceAudit) {
  if (
    !exactFields(execution, [
      "engine",
      "observation",
      "probeSourceDigest",
      "profileId",
      "target",
      "targetVariant",
    ]) ||
    typeof execution.profileId !== "string" ||
    typeof execution.targetVariant !== "string"
  ) {
    throw new Error("loaded intrinsic execution has malformed exact fields");
  }
  const profile = profileFromAudit(sourceAudit, execution.profileId);
  const target = normalizeTarget(execution.target, `${profile.id} target`);
  if (
    execution.targetVariant !== profile.targetVariant ||
    targetVariantForTriple(target.triple) !== profile.targetVariant
  ) {
    throw new Error(`${profile.id}: execution target/profile mismatch`);
  }
  const probe = inheritedIntrinsicAliasProbe({
    sourceAudit,
    profileId: profile.id,
    target,
  });
  if (execution.probeSourceDigest !== probe.sourceDigest) {
    throw new Error(`${profile.id}: executed probe source digest drifted`);
  }
  const engine = execution.engine;
  if (
    !exactFields(engine, [
      "binaryDigest",
      "canonicalArtifactPath",
      "expectedObject",
      "identity",
    ]) ||
    typeof engine.canonicalArtifactPath !== "string" ||
    !path.isAbsolute(engine.canonicalArtifactPath) ||
    typeof engine.binaryDigest !== "string"
  ) {
    throw new Error(`${profile.id}: malformed loaded engine binding`);
  }
  const loadedEngineIdentity = validateLoadedEngineIdentity({
    identity: engine.identity,
    canonicalArtifactPath: engine.canonicalArtifactPath,
    binaryDigest: engine.binaryDigest,
    target,
    expectedObject: engine.expectedObject,
  });
  const observation = normalizeObservation(execution.observation, probe.binding);
  const engineBindingDigest = taggedDigest(
    "ibex.capsec.inherited-intrinsic-alias.engine-binding.v1",
    {
      profile,
      target,
      loadedEngineIdentity,
    },
  );
  const membershipDigest = taggedDigest(
    "ibex.capsec.inherited-intrinsic-alias.membership.v1",
    observation.families,
  );
  return {
    profileId: profile.id,
    targetVariant: profile.targetVariant,
    target,
    loadedEngineIdentity,
    probeSourceDigest: probe.sourceDigest,
    engineBindingDigest,
    membershipDigest,
    observation,
  };
}

/**
 * Authenticate one loaded-profile observation without weakening the
 * all-profile closure rule used by auditLoadedInheritedIntrinsicAliasAccounts.
 *
 * Target runners use this to retain a valid execution while other reviewed
 * profiles are still unavailable.  A single execution is evidence for only
 * its own profile; it never creates a structural account by itself.
 */
export function auditLoadedInheritedIntrinsicAliasExecution({
  sourceAudit,
  execution,
}) {
  return deepFreeze(normalizeExecution(execution, sourceAudit));
}

export function auditLoadedInheritedIntrinsicAliasAccounts({
  sourceAudit,
  executions,
}) {
  if (!Array.isArray(executions) || executions.length !== PROFILE_IDS.length) {
    throw new Error("one loaded execution is required for every Hermes profile");
  }
  const normalizedExecutions = executions
    .map((execution) => normalizeExecution(execution, sourceAudit))
    .sort((left, right) => compareText(left.profileId, right.profileId));
  if (
    canonicalJson(normalizedExecutions.map((entry) => entry.profileId)) !==
    canonicalJson(PROFILE_IDS)
  ) {
    throw new Error("loaded execution profile set drifted from review");
  }

  const accounts = Object.fromEntries(
    FAMILY_SPECS.map((spec) => {
      const profileProofs = normalizedExecutions
        .filter((execution) => spec.profileIds.includes(execution.profileId))
        .map((execution) => {
          const family = execution.observation.families.find(
            (entry) => entry.familyId === spec.familyId,
          );
          return {
            profileId: execution.profileId,
            targetVariant: execution.targetVariant,
            target: execution.target,
            engineBindingDigest: execution.engineBindingDigest,
            probeSourceDigest: execution.probeSourceDigest,
            membershipDigest: taggedDigest(
              "ibex.capsec.inherited-intrinsic-alias.family-membership.v1",
              family,
            ),
            memberUniverse: family.chains,
            identityAliases: family.aliases,
          };
        });
      if (profileProofs.length !== spec.profileIds.length) {
        throw new Error(`${spec.familyId}: loaded profile proof set is incomplete`);
      }
      const account = {
        schema: INHERITED_INTRINSIC_ALIAS_ACCOUNT_SCHEMA,
        familyId: spec.familyId,
        status: "loaded-structural-alias",
        reasonCode: INHERITED_INTRINSIC_ALIAS_REASON_CODE,
        dynamicSelectors: spec.dynamicSelectors,
        sourceRefs: spec.sourceRefs,
        sourceProofs: Object.fromEntries(
          spec.sourceProofKeys.map((proofKey) => [
            proofKey,
            sourceAudit.sourceProofs[proofKey],
          ]),
        ),
        sourceReviewDigest: sourceAudit.sourceReviewDigest,
        profileReviewDigest: sourceAudit.profileReviewDigest,
        profileProofs,
      };
      return [
        spec.familyId,
        {
          ...account,
          accountDigest: taggedDigest(
            "ibex.capsec.inherited-intrinsic-alias.account.v1",
            account,
          ),
        },
      ];
    }),
  );
  const result = {
    schema: INHERITED_INTRINSIC_ALIAS_ACCOUNT_SET_SCHEMA,
    runtimeExecutionRequired: true,
    sourceReviewDigest: sourceAudit.sourceReviewDigest,
    profileReviewDigest: sourceAudit.profileReviewDigest,
    executions: normalizedExecutions,
    accounts,
  };
  return deepFreeze({
    ...result,
    closureDigest: taggedDigest(
      "ibex.capsec.inherited-intrinsic-alias.account-set.v1",
      result,
    ),
  });
}

function validateStructuralAccount(account, spec) {
  if (
    !exactFields(account, [
      "accountDigest",
      "dynamicSelectors",
      "familyId",
      "profileProofs",
      "profileReviewDigest",
      "reasonCode",
      "schema",
      "sourceProofs",
      "sourceRefs",
      "sourceReviewDigest",
      "status",
    ]) ||
    account.schema !== INHERITED_INTRINSIC_ALIAS_ACCOUNT_SCHEMA ||
    account.familyId !== spec.familyId ||
    account.status !== "loaded-structural-alias" ||
    account.reasonCode !== INHERITED_INTRINSIC_ALIAS_REASON_CODE ||
    account.profileReviewDigest !== REVIEWED_PROFILE_DIGEST ||
    account.sourceReviewDigest !== REVIEWED_SOURCE_REVIEW_DIGEST ||
    canonicalJson(account.dynamicSelectors) !==
      canonicalJson(spec.dynamicSelectors) ||
    canonicalJson(account.sourceRefs) !== canonicalJson(spec.sourceRefs) ||
    !exactFields(account.sourceProofs, spec.sourceProofKeys) ||
    !Array.isArray(account.profileProofs) ||
    account.profileProofs.length !== spec.profileIds.length
  ) {
    throw new Error(`${spec.familyId}: structural account shape drifted`);
  }
  for (const proofKey of spec.sourceProofKeys) {
    const proof = account.sourceProofs[proofKey];
    if (
      !exactFields(proof, ["astDigest"]) ||
      proof.astDigest !== REVIEWED_SOURCE_NODE_DIGESTS[proofKey]
    ) {
      throw new Error(`${spec.familyId}: structural source proof drifted`);
    }
  }
  for (let index = 0; index < spec.profileIds.length; index += 1) {
    const proof = account.profileProofs[index];
    if (
      !exactFields(proof, [
        "engineBindingDigest",
        "identityAliases",
        "memberUniverse",
        "membershipDigest",
        "probeSourceDigest",
        "profileId",
        "target",
        "targetVariant",
      ]) ||
      proof.profileId !== spec.profileIds[index] ||
      proof.targetVariant !== PROFILE_TARGET_VARIANTS[proof.profileId] ||
      !/^sha256-[a-f0-9]{64}$/u.test(proof.engineBindingDigest ?? "") ||
      !/^sha256-[a-f0-9]{64}$/u.test(proof.membershipDigest ?? "") ||
      !/^sha256-[a-f0-9]{64}$/u.test(proof.probeSourceDigest ?? "") ||
      !exactFields(proof.identityAliases, spec.aliasNames) ||
      spec.aliasNames.some(
        (aliasName) => proof.identityAliases[aliasName] !== true,
      ) ||
      !Array.isArray(proof.memberUniverse) ||
      proof.memberUniverse.length !== spec.chainSpecs.length
    ) {
      throw new Error(`${spec.familyId}: structural profile proof drifted`);
    }
    normalizeTarget(proof.target, `${spec.familyId} ${proof.profileId} target`);
    proof.memberUniverse.forEach((chain, chainIndex) =>
      normalizeChain(
        chain,
        spec.chainSpecs[chainIndex],
        `${spec.familyId} ${proof.profileId} ${spec.chainSpecs[chainIndex].role}`,
      ),
    );
    const expectedMembershipDigest = taggedDigest(
      "ibex.capsec.inherited-intrinsic-alias.family-membership.v1",
      {
        familyId: spec.familyId,
        branch: spec.branch,
        chains: proof.memberUniverse,
        aliases: proof.identityAliases,
      },
    );
    if (proof.membershipDigest !== expectedMembershipDigest) {
      throw new Error(`${spec.familyId}: family membership digest drifted`);
    }
    const binding = {
      schema: INHERITED_INTRINSIC_ALIAS_OBSERVATION_SCHEMA,
      profileId: proof.profileId,
      targetVariant: proof.targetVariant,
      targetTriple: proof.target.triple,
      structuralFeatures: [...proof.target.features].sort(compareText),
      sourceReviewDigest: REVIEWED_SOURCE_REVIEW_DIGEST,
      profileReviewDigest: REVIEWED_PROFILE_DIGEST,
      probeContractDigest: PROBE_CONTRACT_DIGEST,
      familyIds: familySpecsForProfile(proof.profileId).map(
        (profileSpec) => profileSpec.familyId,
      ),
    };
    const expectedProbeSource = `(${PROBE_RUNTIME_SOURCE})(${canonicalJson(binding)})`;
    if (proof.probeSourceDigest !== sha256Hex(expectedProbeSource)) {
      throw new Error(`${spec.familyId}: profile probe source digest drifted`);
    }
  }
  const { accountDigest, ...unsignedAccount } = account;
  if (
    accountDigest !==
    taggedDigest(
      "ibex.capsec.inherited-intrinsic-alias.account.v1",
      unsignedAccount,
    )
  ) {
    throw new Error(`${spec.familyId}: structural account digest drifted`);
  }
}

function validateAccountSet(accountSet) {
  if (
    !exactFields(accountSet, [
      "accounts",
      "closureDigest",
      "executions",
      "profileReviewDigest",
      "runtimeExecutionRequired",
      "schema",
      "sourceReviewDigest",
    ]) ||
    accountSet.schema !== INHERITED_INTRINSIC_ALIAS_ACCOUNT_SET_SCHEMA ||
    accountSet.runtimeExecutionRequired !== true ||
    accountSet.profileReviewDigest !== REVIEWED_PROFILE_DIGEST ||
    accountSet.sourceReviewDigest !== REVIEWED_SOURCE_REVIEW_DIGEST ||
    !Array.isArray(accountSet.executions) ||
    accountSet.executions.length !== PROFILE_IDS.length ||
    !exactFields(accountSet.accounts, INHERITED_INTRINSIC_ALIAS_FAMILIES)
  ) {
    throw new Error("loaded inherited intrinsic account set is absent");
  }
  FAMILY_SPECS.forEach((spec) =>
    validateStructuralAccount(accountSet.accounts[spec.familyId], spec),
  );
  const executionProfileIds = accountSet.executions.map(
    (execution) => execution?.profileId,
  );
  if (canonicalJson(executionProfileIds) !== canonicalJson(PROFILE_IDS)) {
    throw new Error("loaded inherited intrinsic execution order drifted");
  }
  for (const spec of FAMILY_SPECS) {
    for (const proof of accountSet.accounts[spec.familyId].profileProofs) {
      const execution = accountSet.executions.find(
        (candidate) => candidate.profileId === proof.profileId,
      );
      if (
        !execution ||
        proof.engineBindingDigest !== execution.engineBindingDigest ||
        proof.probeSourceDigest !== execution.probeSourceDigest ||
        canonicalJson(proof.target) !== canonicalJson(execution.target)
      ) {
        throw new Error(`${spec.familyId}: account/execution binding drifted`);
      }
    }
  }
  const { closureDigest, ...unsignedSet } = accountSet;
  if (
    closureDigest !==
    taggedDigest(
      "ibex.capsec.inherited-intrinsic-alias.account-set.v1",
      unsignedSet,
    )
  ) {
    throw new Error("loaded inherited intrinsic account-set digest drifted");
  }
}

export function inheritedIntrinsicAliasStructuralAccountBindings(accountSet) {
  validateAccountSet(accountSet);
  return INHERITED_INTRINSIC_ALIAS_FAMILIES.map((familyId) =>
    structuredClone(accountSet.accounts[familyId]),
  );
}
