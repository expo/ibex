/**
 * Bind LLP 0023 output-disposition evidence to one clean source revision and
 * one exact loaded engine without putting the reviewed expected values in the
 * executor's sweep plan.
 *
 * The plan describes only how to reach an output. The raw artifact records
 * only what the loaded-engine executor observed. The reviewed disposition
 * dataset is joined later, in `buildVerifiedOutputDispositionEvidence`, so an
 * executor cannot pass by reflecting expected values from the policy input.
 *
 * @ref LLP 0023#6-path-bearing-observables — the live descriptor sweep and
 * compiled registrar IDs must cover the independent output catalog in both
 * directions before output-disposition evidence is promotable.
 * @ref LLP 0023#72-the-structured-result-and-its-error-classes — structured
 * resolver and VFS records are observed at their exact return-record paths.
 */

import crypto from "node:crypto";
import {
  canonicalOutputDispositionKey,
  OUTPUT_DISPOSITION_EVIDENCE_EXECUTOR,
  buildOutputDispositionDataset,
  buildOutputShapeCatalog,
  outputExecutionContextsForRows,
  outputParameterizedBindingDigest,
  outputShapeCatalogKeyDigest,
  validateOutputDispositionEvidence,
  validateOutputDispositionJoin,
  validateOutputShapeCatalogAccounts,
  validateOutputValueProofKind,
} from "./capsec-output-dispositions.mjs";
import {
  ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD,
  buildEnvironmentOutputSweepBindings,
  buildEnvironmentOutputSweepObservations,
  validateEnvironmentOutputSweepBindings,
  validateEnvironmentOutputSweepObservations,
} from "./capsec-environment-output-templates.mjs";
import { CALLBACK_OUTPUT_CONTRACT_SCHEMA } from "./capsec-surface-inventory.mjs";
import { authoredNonCapabilityBuiltinOutputInvocation } from "./capsec-builtin-public-probe-templates.mjs";
import {
  authoredBuiltinNoncapClosedOutputProbe,
  BUILTIN_NONCAP_CLOSED_OUTPUT_INVOCATION_SCHEMA,
  BUILTIN_NONCAP_CLOSED_OUTPUT_SOURCE_DESCRIPTOR_KIND,
} from "./capsec-builtin-noncap-closed-output-templates.mjs";
import {
  authoredBuiltinEffectsOutputProbe,
  BUILTIN_EFFECTS_OUTPUT_INVOCATION_SCHEMA,
  BUILTIN_EFFECTS_OUTPUT_SOURCE_DESCRIPTOR_KIND,
  isBuiltinEffectsOutputTargetSurface,
} from "./capsec-builtin-effects-output-templates.mjs";
import {
  authoredGlobalAccessorOutputInvocation,
  globalAccessorReceiverRecipeIds,
} from "./capsec-global-accessor-probe-templates.mjs";
import {
  authoredGlobalCallableOutputInvocation,
  globalCallableFactoryRecipeIds,
} from "./capsec-global-callable-probe-templates.mjs";
import { authoredClosedControlOutputInvocation } from "./capsec-closed-control-output-templates.mjs";
import {
  authoredCliOutputInvocation,
  compiledCliEvidenceTypes,
} from "./capsec-cli-output-templates.mjs";
import {
  authoredNativeFreezeOutputInvocation,
  NATIVE_FREEZE_OUTPUT_SOURCE_DESCRIPTOR_KIND,
  validateNativeFreezeOutputInvocation,
} from "./capsec-native-freeze-output-templates.mjs";
import {
  HOST_ABI_OUTPUT_SOURCE_DESCRIPTOR_KIND,
  buildHostAbiOutputProbePartition,
} from "./capsec-host-abi-output-templates.mjs";
import { validatePublicSurfaceExecutionArtifact } from "./capsec-public-surface-evidence.mjs";

export const OUTPUT_SHAPE_SWEEP_EXECUTOR = OUTPUT_DISPOSITION_EVIDENCE_EXECUTOR;

const PROFILE = "ibex/capsec/1";
const CATALOG_SCHEMA = "ibex/capsec-output-shape-catalog/2";
const PLAN_SCHEMA = "ibex/capsec-output-shape-sweep-plan/3";
const ARTIFACT_SCHEMA = "ibex/capsec-output-shape-sweep-artifact/3";
const EXECUTOR_BATCH_SCHEMA = "ibex/capsec-output-shape-executor-batch/3";
const PLAN_DIGEST_DOMAIN = "ibex:capsec:output-shape-sweep-plan:3";
const ARTIFACT_DIGEST_DOMAIN = "ibex:capsec:output-shape-sweep-artifact:3";
const EXECUTION_PARTITION_SCHEMA =
  "ibex/capsec-output-shape-execution-partition/1";
const HOST_ABI_EXECUTOR_BATCH_SCHEMA =
  "ibex/capsec-host-abi-output-executor-batch/2";
const TARGET_ABSENCE_OUTPUT_SOURCE_DESCRIPTOR_KIND =
  "source-bound-target-absence-output";
const TARGET_ABSENCE_RECORD_PATH = Object.freeze([
  "runtimeObservation",
  "invocation",
  "result",
]);
const DIGEST_PATTERN = /^sha256-[A-Za-z0-9_-]{43}$/u;
const REVISION_PATTERN = /^[0-9a-f]{40}$/u;
const TARGET_FIELDS = Object.freeze(["triple", "features"]);
const ENGINE_FIELDS = Object.freeze([
  "binaryDigest",
  "engineArtifactPath",
  "kind",
  "object",
  "structuralFeatures",
  "targetArchitecture",
]);
const ENGINE_OBJECT_FIELDS = Object.freeze(["file", "platform", "volume"]);
const ENGINE_OBJECT_PLATFORMS = new Set([
  "android",
  "apple",
  "unix",
  "windows",
]);
const OUTCOMES = new Set(["absent", "return", "throw", "typed-return"]);
const VALUE_TYPES = new Set([
  "bigint",
  "boolean",
  "function",
  "null",
  "number",
  "object",
  "string",
  "symbol",
  "undefined",
]);
const RAW_VALUE_SHAPES = new Set([
  ...VALUE_TYPES,
  "absent",
  "throw",
  "array",
  "argument-identity",
]);
const DESCRIPTOR_SOURCE_KINDS = new Set(["builtin", "native-op"]);
const CALLBACK_OUTPUT_DIRECTIONS = new Set([
  "javascript-to-native",
  "native-to-javascript",
]);
const CALLBACK_OUTPUT_ROLES = new Set(["error", "payload", "return"]);
const CALLBACK_OUTPUT_VALUE_SHAPES = new Set([
  "array-buffer",
  "boolean",
  "bytes",
  "error",
  "float32x4",
  "json-string",
  "json-value",
  "null",
  "number",
  "object",
  "string",
  "uint8-array",
  "undefined",
]);
const STRUCTURED_DISCOVERY_KIND = "source-asserted-structured-output";
const SAFE_THROW_METADATA_ALIAS = "ex_hermes_value_safe_throw_metadata";
const FORBIDDEN_PLAN_FIELDS = new Set([
  "disposition",
  "expectation",
  "normalizedValue",
  "observation",
  "outcome",
]);

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort(compareText)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

/**
 * Re-derive the generated output catalog and reviewed disposition dataset from
 * the current source inventory and coverage registry. A self-consistent stale
 * subset is not current-source evidence merely because its plan IDs remain a
 * subset of the compiled registrar set.
 */
export function validateCurrentSourceOutputDispositionArtifacts({
  catalog,
  dispositionDataset,
  coverage,
  surfaces,
  repoRoot,
  policy,
  trackedEvidence,
}) {
  const sourceSurfaces = Array.isArray(surfaces)
    ? surfaces
    : surfaces?.surfaces;
  if (
    !Array.isArray(coverage?.edges) ||
    !Array.isArray(sourceSurfaces) ||
    typeof repoRoot !== "string" ||
    repoRoot.length === 0
  ) {
    throw new Error(
      "current-source output validation requires coverage, source surfaces, and the repository root",
    );
  }
  const sourceByObservedKey = new Map();
  for (const [index, surface] of sourceSurfaces.entries()) {
    if (
      typeof surface?.observedKey !== "string" ||
      !Array.isArray(surface.sourceRefs) ||
      sourceByObservedKey.has(surface.observedKey)
    ) {
      throw new Error(
        `current-source output surface ${index} is malformed or duplicated`,
      );
    }
    sourceByObservedKey.set(surface.observedKey, surface);
  }
  const implementationRows = coverage.edges.map((edge) => {
    const observedKey = `${edge?.surface?.kind}:${edge?.surface?.name}`;
    const surface = sourceByObservedKey.get(observedKey);
    if (!surface) {
      throw new Error(
        `${edge?.id ?? "unknown coverage edge"}: current source inventory lacks ${observedKey}`,
      );
    }
    return {
      edgeId: edge.id,
      observedKey,
      sourceRefs: [...surface.sourceRefs],
    };
  });
  const derivedCatalog = buildOutputShapeCatalog({
    coverage,
    implementationRows,
    surfaces: sourceSurfaces,
    repoRoot,
    liveEvidence: trackedEvidence,
  });
  if (canonicalJson(catalog) !== canonicalJson(derivedCatalog)) {
    throw new Error(
      "generated output-shape catalog differs from the current source-derived catalog",
    );
  }
  const derivedDispositionDataset = buildOutputDispositionDataset({
    catalog: derivedCatalog,
    policy,
    evidence: trackedEvidence,
  });
  if (
    canonicalJson(dispositionDataset) !==
    canonicalJson(derivedDispositionDataset)
  ) {
    throw new Error(
      "generated output dispositions differ from the current source-derived reviewed dataset",
    );
  }
  return { catalog, dispositionDataset };
}

function computeDomainDigest(domain, payload, omitFields) {
  const projected = structuredClone(payload);
  for (const field of omitFields) delete projected[field];
  const hash = crypto.createHash("sha256");
  hash.update(domain, "utf8");
  hash.update(Buffer.from([0]));
  hash.update(canonicalJson(projected), "utf8");
  return `sha256-${hash.digest("base64url")}`;
}

export function outputShapeSourceDescriptorDigest(sourceDescriptor) {
  const hash = crypto.createHash("sha256");
  hash.update(canonicalJson(sourceDescriptor), "utf8");
  return `sha256-${hash.digest("base64url")}`;
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label}: expected object`);
  }
  const actual = Object.keys(value).sort(compareText);
  const wanted = [...expected].sort(compareText);
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    throw new Error(
      `${label}: expected exact keys [${wanted.join(", ")}], got [${actual.join(", ")}]`,
    );
  }
}

function nonEmptyString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label}: expected non-empty string`);
  }
  return value;
}

function digest(value, label) {
  if (!DIGEST_PATTERN.test(value ?? "")) {
    throw new Error(`${label}: expected tagged SHA-256 digest`);
  }
  return value;
}

function revision(value, label) {
  if (!REVISION_PATTERN.test(value ?? "")) {
    throw new Error(`${label}: expected exact 40-hex source revision`);
  }
  return value;
}

function canonicalStableIdSet(value, label) {
  if (
    !Array.isArray(value) ||
    value.some(
      (item) => typeof item !== "string" || !/^[a-z][a-z0-9.-]*$/u.test(item),
    ) ||
    canonicalJson(value) !==
      canonicalJson([...new Set(value)].sort(compareText))
  ) {
    throw new Error(`${label}: expected a canonical stable-id set`);
  }
  return value;
}

function exactTarget(target, label) {
  exactKeys(target, TARGET_FIELDS, label);
  if (!/^[a-z0-9_]+(?:-[a-z0-9_]+){2,}$/u.test(target.triple ?? "")) {
    throw new Error(`${label}.triple: expected an exact target triple`);
  }
  canonicalStableIdSet(target.features, `${label}.features`);
  return target;
}

function exactEngine(engine, target, label) {
  exactKeys(engine, ENGINE_FIELDS, label);
  exactKeys(engine.object, ENGINE_OBJECT_FIELDS, `${label}.object`);
  canonicalStableIdSet(
    engine.structuralFeatures,
    `${label}.structuralFeatures`,
  );
  const expectedObjectPlatform = target.triple.includes("-windows-")
    ? "windows"
    : target.triple.includes("-android")
      ? "android"
      : target.triple.includes("-apple-")
        ? "apple"
        : "unix";
  if (
    engine.kind !== "hermes" ||
    typeof engine.engineArtifactPath !== "string" ||
    engine.engineArtifactPath.length === 0 ||
    !DIGEST_PATTERN.test(engine.binaryDigest ?? "") ||
    !ENGINE_OBJECT_PLATFORMS.has(engine.object.platform) ||
    engine.object.platform !== expectedObjectPlatform ||
    typeof engine.object.volume !== "string" ||
    engine.object.volume.length === 0 ||
    typeof engine.object.file !== "string" ||
    engine.object.file.length === 0 ||
    !/^[a-z0-9_]+$/u.test(engine.targetArchitecture ?? "") ||
    engine.targetArchitecture !== target.triple.split("-")[0] ||
    canonicalJson(engine.structuralFeatures) !== canonicalJson(target.features)
  ) {
    throw new Error(`${label}: expected the exact target-bound Hermes image`);
  }
  return engine;
}

function assertBindingInputs(
  { sourceRevision, sourceTreeDigest, target, engine },
  label,
) {
  revision(sourceRevision, `${label}.sourceRevision`);
  digest(sourceTreeDigest, `${label}.sourceTreeDigest`);
  exactTarget(target, `${label}.target`);
  exactEngine(engine, target, `${label}.engine`);
}

function assertNoExpectedValueEcho(value, label) {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      assertNoExpectedValueEcho(item, `${label}[${index}]`),
    );
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_PLAN_FIELDS.has(key)) {
      throw new Error(
        `${label}.${key}: sweep plans must not carry reviewed expected values`,
      );
    }
    assertNoExpectedValueEcho(child, `${label}.${key}`);
  }
}

function catalogSurfaceAccountIds(catalog) {
  return catalog.surfaceAccounts
    .map((account) => account.surfaceId)
    .sort(compareText);
}

function validateSweepCatalog(catalog, label = "output-shape catalog") {
  exactKeys(
    catalog,
    [
      "outputShapeCatalogSchema",
      "profile",
      "discovery",
      "contexts",
      "surfaceAccounts",
      "parameterizedOutputBindings",
      "parameterizedBindingDigest",
      "catalogKeyDigest",
      "counts",
      "rows",
    ],
    label,
  );
  if (
    catalog.outputShapeCatalogSchema !== CATALOG_SCHEMA ||
    catalog.profile !== PROFILE ||
    !Array.isArray(catalog.rows) ||
    !Array.isArray(catalog.contexts) ||
    !Array.isArray(catalog.surfaceAccounts) ||
    !Array.isArray(catalog.parameterizedOutputBindings) ||
    catalog.parameterizedBindingDigest !==
      outputParameterizedBindingDigest(catalog.parameterizedOutputBindings) ||
    catalog.catalogKeyDigest !== outputShapeCatalogKeyDigest(catalog.rows)
  ) {
    throw new Error(`${label}: expected an intact v2 catalog`);
  }
  const discovery = catalog.discovery;
  const verified = discovery?.status === "verified";
  exactKeys(
    discovery,
    verified
      ? [
          "status",
          "method",
          "requiredExecutor",
          "sourceRevision",
          "sourceTreeDigest",
          "target",
          "engine",
        ]
      : ["status", "method", "requiredExecutor", "reason"],
    `${label}.discovery`,
  );
  if (
    !new Set(["unpromotable", "verified"]).has(discovery.status) ||
    typeof discovery.method !== "string" ||
    discovery.method.length === 0 ||
    discovery.requiredExecutor !== OUTPUT_SHAPE_SWEEP_EXECUTOR ||
    (!verified &&
      (typeof discovery.reason !== "string" ||
        discovery.reason.length === 0)) ||
    (verified &&
      (!REVISION_PATTERN.test(discovery.sourceRevision ?? "") ||
        !DIGEST_PATTERN.test(discovery.sourceTreeDigest ?? "")))
  ) {
    throw new Error(`${label}.discovery: malformed live-evidence binding`);
  }
  if (verified) {
    exactTarget(discovery.target, `${label}.discovery.target`);
    exactEngine(
      discovery.engine,
      discovery.target,
      `${label}.discovery.engine`,
    );
  }
  const expectedContexts = outputExecutionContextsForRows(catalog.rows);
  if (canonicalJson(catalog.contexts) !== canonicalJson(expectedContexts)) {
    throw new Error(
      `${label}: execution contexts do not exactly cover value rows`,
    );
  }
  const accountCounts = validateOutputShapeCatalogAccounts({
    surfaceAccounts: catalog.surfaceAccounts,
    rows: catalog.rows,
    parameterizedOutputBindings: catalog.parameterizedOutputBindings,
    promotionStatus: discovery.status,
  });
  const expectedCounts = {
    coverageSurfaces: catalog.surfaceAccounts.length,
    outputBearingSurfaces: accountCounts["output-bearing"],
    structuralOnlySurfaces: accountCounts["structural-only"],
    unresolvedSurfaces: accountCounts.unresolved,
    catalogRows: catalog.rows.length,
    parameterizedBindings: catalog.parameterizedOutputBindings.length,
    sourceInventoryRows: catalog.rows.filter(
      (row) => row.discovery?.kind === "source-inventory-surface",
    ).length,
    structuredRows: catalog.rows.filter(
      (row) => row.discovery?.kind === STRUCTURED_DISCOVERY_KIND,
    ).length,
  };
  if (canonicalJson(catalog.counts) !== canonicalJson(expectedCounts)) {
    throw new Error(`${label}: counts do not match accounts and value rows`);
  }
  for (const [index, row] of catalog.rows.entries()) {
    exactKeys(
      row,
      ["key", "discovery", "requiredValueProof"],
      `${label}.rows[${index}]`,
    );
    if (row.requiredValueProof !== "live-value-observation") {
      throw new Error(`${label}.rows[${index}]: value proof is not live`);
    }
  }
  return catalog;
}

function validateTargetAbsenceOutputProbe(probe, key, label) {
  const descriptor = probe?.sourceDescriptor;
  if (descriptor?.kind !== TARGET_ABSENCE_OUTPUT_SOURCE_DESCRIPTOR_KIND) {
    return false;
  }
  exactKeys(
    descriptor,
    [
      "kind",
      "recipeCatalogDigest",
      "fixtureId",
      "recipePlanDigest",
      "terminalObservedKey",
      "invocationSchema",
      "targetSourceDescriptorDigest",
      "publicSurfaceProbe",
    ],
    `${label}.sourceDescriptor`,
  );
  const publicProbe = descriptor.publicSurfaceProbe;
  exactKeys(
    publicProbe,
    ["kind", "surfaceObservedKey", "command", "invocation"],
    `${label}.sourceDescriptor.publicSurfaceProbe`,
  );
  const invocation = publicProbe.invocation;
  if (
    !DIGEST_PATTERN.test(descriptor.recipeCatalogDigest ?? "") ||
    !DIGEST_PATTERN.test(descriptor.recipePlanDigest ?? "") ||
    !DIGEST_PATTERN.test(descriptor.targetSourceDescriptorDigest ?? "") ||
    descriptor.fixtureId !== probe.fixtureId ||
    descriptor.invocationSchema !==
      "ibex/capsec-target-absence-invocation/1" ||
    publicProbe.kind !== "target-absence-probe" ||
    !Array.isArray(publicProbe.command) ||
    publicProbe.command.length === 0 ||
    publicProbe.command.some(
      (component) => typeof component !== "string" || component.length === 0,
    ) ||
    publicProbe.surfaceObservedKey !== descriptor.terminalObservedKey ||
    invocation?.invocationSchema !== descriptor.invocationSchema ||
    invocation.kind !== "target-absence" ||
    invocation.surfaceKind !== key.sourceKind ||
    invocation.surfaceName !== key.alias ||
    invocation.sourceDescriptorDigest !==
      descriptor.targetSourceDescriptorDigest ||
    canonicalJson(probe.recordPath) !== canonicalJson(TARGET_ABSENCE_RECORD_PATH)
  ) {
    throw new Error(`${label}: invalid source-bound target-absence route`);
  }
  return true;
}

function validateProbe(probe, key, label) {
  assertNoExpectedValueEcho(probe, label);
  validateOutputValueProofKind(probe?.kind, `${label}.kind`);
  switch (probe?.kind) {
    case "loaded-engine-descriptor":
      exactKeys(
        probe,
        ["kind", "sourceDescriptor", "sourceDescriptorDigest"],
        label,
      );
      if (
        !probe.sourceDescriptor ||
        typeof probe.sourceDescriptor !== "object" ||
        Array.isArray(probe.sourceDescriptor)
      ) {
        throw new Error(
          `${label}.sourceDescriptor: expected a source-bound access route`,
        );
      }
      if (Object.keys(probe.sourceDescriptor).length === 0) {
        throw new Error(
          `${label}.sourceDescriptor: expected a non-empty access route`,
        );
      }
      if (
        key.output === "[[return]]" &&
        probe.sourceDescriptor.exercise?.kind === "descriptor" &&
        new Set(["callable", "accessor"]).has(probe.sourceDescriptor.valueShape)
      ) {
        throw new Error(
          `${label}: a default descriptor cannot observe a callable or accessor output`,
        );
      }
      if (
        digest(
          probe.sourceDescriptorDigest,
          `${label}.sourceDescriptorDigest`,
        ) !== outputShapeSourceDescriptorDigest(probe.sourceDescriptor)
      ) {
        throw new Error(
          `${label}: source descriptor digest does not match route`,
        );
      }
      return;
    case "compiled-runtime-return-record": {
      exactKeys(
        probe,
        [
          "kind",
          "fixtureId",
          "sourceDescriptor",
          "sourceDescriptorDigest",
          "recordPath",
        ],
        label,
      );
      nonEmptyString(probe.fixtureId, `${label}.fixtureId`);
      if (
        !probe.sourceDescriptor ||
        typeof probe.sourceDescriptor !== "object" ||
        Array.isArray(probe.sourceDescriptor) ||
        probe.sourceDescriptor.kind !== "authored-cli-output"
      ) {
        throw new Error(`${label}: unsupported compiled-runtime source route`);
      }
      if (
        digest(
          probe.sourceDescriptorDigest,
          `${label}.sourceDescriptorDigest`,
        ) !== outputShapeSourceDescriptorDigest(probe.sourceDescriptor)
      ) {
        throw new Error(
          `${label}: source descriptor digest does not match route`,
        );
      }
      exactKeys(
        probe.sourceDescriptor,
        ["kind", "surfaceObservedKey", "invocation"],
        `${label}.sourceDescriptor`,
      );
      const invocation = probe.sourceDescriptor.invocation;
      exactKeys(
        invocation,
        [
          "invocationSchema",
          "kind",
          "coverageEdgeId",
          "coverageClassification",
          "sourceDescriptor",
          "sourceDescriptorDigest",
          "operation",
          "completion",
        ],
        `${label}.sourceDescriptor.invocation`,
      );
      exactKeys(
        invocation.sourceDescriptor,
        ["kind", "surfaceName", "evidenceType", "sourceRefs"],
        `${label}.sourceDescriptor.invocation.sourceDescriptor`,
      );
      exactKeys(
        invocation.operation,
        ["kind"],
        `${label}.sourceDescriptor.invocation.operation`,
      );
      exactKeys(
        invocation.completion,
        ["kind"],
        `${label}.sourceDescriptor.invocation.completion`,
      );
      const evidenceType = invocation.sourceDescriptor.evidenceType;
      const manifestCommandRef = invocation.sourceDescriptor.sourceRefs.find(
        (sourceRef) =>
          new Set([
            "runtime-surface.json#hiddenHarnessCommands",
            "runtime-surface.json#legacyProjectCommands",
            "runtime-surface.json#reservedCommands",
            "runtime-surface.json#visibleCommands",
          ]).has(sourceRef),
      );
      const expectedOperation =
        evidenceType === "cli-product-ingress"
          ? "product-ingress-route-read"
          : evidenceType === "cli-manifest-command" &&
              new Set([
                "runtime-surface.json#hiddenHarnessCommands",
                "runtime-surface.json#visibleCommands",
              ]).has(manifestCommandRef)
            ? "clap-command-name-read"
            : evidenceType === "cli-manifest-command" && manifestCommandRef
              ? "namespace-command-name-read"
              : typeof evidenceType === "string" &&
                  evidenceType.startsWith("repl-")
                ? "repl-surface-read"
                : "clap-surface-read";
      if (
        invocation.invocationSchema !== "ibex/capsec-cli-output-invocation/1" ||
        invocation.kind !== "cli-output" ||
        invocation.coverageEdgeId !== key.surfaceId ||
        !new Set(["non-capability", "effects", "closed"]).has(
          invocation.coverageClassification,
        ) ||
        probe.sourceDescriptor.surfaceObservedKey !== `cli:${key.alias}` ||
        invocation.sourceDescriptor.kind !== "compiled-cli-surface" ||
        invocation.sourceDescriptor.surfaceName !== key.alias ||
        !compiledCliEvidenceTypes.includes(evidenceType) ||
        !Array.isArray(invocation.sourceDescriptor.sourceRefs) ||
        invocation.sourceDescriptor.sourceRefs.length === 0 ||
        !invocation.sourceDescriptor.sourceRefs.every(
          (sourceRef) => typeof sourceRef === "string" && sourceRef.length > 0,
        ) ||
        outputShapeSourceDescriptorDigest(invocation.sourceDescriptor) !==
          invocation.sourceDescriptorDigest ||
        invocation.operation.kind !== expectedOperation ||
        invocation.completion.kind !== "synchronous-compiled-runtime" ||
        canonicalJson(probe.recordPath) !== canonicalJson(["[[return]]"])
      ) {
        throw new Error(`${label}: invalid authored compiled CLI route`);
      }
      return;
    }
    case "compiled-runtime-return-record":
    case "loaded-engine-return-record":
      exactKeys(
        probe,
        [
          "kind",
          "fixtureId",
          "sourceDescriptor",
          "sourceDescriptorDigest",
          "recordPath",
        ],
        label,
      );
      nonEmptyString(probe.fixtureId, `${label}.fixtureId`);
      if (
        !probe.sourceDescriptor ||
        typeof probe.sourceDescriptor !== "object" ||
        Array.isArray(probe.sourceDescriptor) ||
        Object.keys(probe.sourceDescriptor).length === 0
      ) {
        throw new Error(
          `${label}.sourceDescriptor: expected a source-bound fixture route`,
        );
      }
      if (
        digest(
          probe.sourceDescriptorDigest,
          `${label}.sourceDescriptorDigest`,
        ) !== outputShapeSourceDescriptorDigest(probe.sourceDescriptor)
      ) {
        throw new Error(
          `${label}: source descriptor digest does not match route`,
        );
      }
      if (validateTargetAbsenceOutputProbe(probe, key, label)) return;
      if (
        probe.sourceDescriptor.kind ===
        NATIVE_FREEZE_OUTPUT_SOURCE_DESCRIPTOR_KIND
      ) {
        if (probe.kind !== "loaded-engine-return-record") {
          throw new Error(`${label}: native freeze requires loaded Hermes`);
        }
        exactKeys(
          probe.sourceDescriptor,
          ["kind", "surfaceObservedKey", "invocation"],
          `${label}.sourceDescriptor`,
        );
        validateNativeFreezeOutputInvocation(
          probe.sourceDescriptor.invocation,
          {
            catalogKey: key,
            surfaceObservedKey: probe.sourceDescriptor.surfaceObservedKey,
          },
        );
        if (canonicalJson(probe.recordPath) !== canonicalJson(["[[return]]"])) {
          throw new Error(`${label}: native freeze requires its return record`);
        }
      }
      if (
        probe.sourceDescriptor.kind ===
        BUILTIN_EFFECTS_OUTPUT_SOURCE_DESCRIPTOR_KIND
      ) {
        exactKeys(
          probe.sourceDescriptor,
          ["kind", "surfaceObservedKey", "invocation"],
          `${label}.sourceDescriptor`,
        );
        const invocation = probe.sourceDescriptor.invocation;
        exactKeys(
          invocation,
          [
            "invocationSchema",
            "kind",
            "cohort",
            "coverageEdgeId",
            "coverageClassification",
            "surfaceObservedKey",
            "moduleSpecifier",
            "sourceDescriptor",
            "sourceDescriptorDigest",
            "route",
            "decisionEvidence",
            "positiveControl",
            "completion",
          ],
          `${label}.sourceDescriptor.invocation`,
        );
        const builtinDescriptor = invocation.sourceDescriptor;
        exactKeys(
          builtinDescriptor,
          [
            "kind",
            "sourceKey",
            "exportName",
            "exportIdioms",
            "moduleSpecifiers",
            "sourceRef",
            "valueShape",
            "importReachability",
            "access",
            ...(Object.hasOwn(builtinDescriptor ?? {}, "platformAvailability")
              ? ["platformAvailability"]
              : []),
          ],
          `${label}.sourceDescriptor.invocation.sourceDescriptor`,
        );
        exactKeys(
          builtinDescriptor.access,
          ["kind", "path"],
          `${label}.sourceDescriptor.invocation.sourceDescriptor.access`,
        );
        const route = invocation.route;
        exactKeys(
          route,
          [
            "operation",
            "receiver",
            "arguments",
            "cleanup",
            "authorityBounds",
            "setup",
            "fixture",
          ],
          `${label}.sourceDescriptor.invocation.route`,
        );
        exactKeys(
          route.receiver,
          route.receiver?.kind === "module-value"
            ? ["kind"]
            : route.receiver?.kind === "fixture-value"
              ? ["kind"]
              : ["kind", "ownerPath"],
          `${label}.sourceDescriptor.invocation.route.receiver`,
        );
        exactKeys(
          route.cleanup,
          ["kind"],
          `${label}.sourceDescriptor.invocation.route.cleanup`,
        );
        exactKeys(
          route.fixture,
          ["kind", "family", "network", "filesystem", "process"],
          `${label}.sourceDescriptor.invocation.route.fixture`,
        );
        if (!Array.isArray(route.arguments)) {
          throw new Error(
            `${label}: builtin effects arguments must be an array`,
          );
        }
        route.arguments.forEach((argument, argumentIndex) => {
          const argumentLabel = `${label}.sourceDescriptor.invocation.route.arguments[${argumentIndex}]`;
          const keys = {
            json: ["kind", "value"],
            "noop-function": ["kind"],
            "inert-object": ["kind"],
            "fixture-fd": ["kind"],
            "completion-callback": ["kind"],
            "uint8-array": ["kind", "size"],
            "uint8-array-list": ["kind", "sizes"],
          }[argument?.kind];
          if (!keys) {
            throw new Error(`${argumentLabel}: unsupported authored argument`);
          }
          exactKeys(argument, keys, argumentLabel);
          if (
            (argument.kind === "uint8-array" &&
              (!Number.isInteger(argument.size) || argument.size <= 0)) ||
            (argument.kind === "uint8-array-list" &&
              (!Array.isArray(argument.sizes) ||
                argument.sizes.length === 0 ||
                argument.sizes.some(
                  (size) => !Number.isInteger(size) || size <= 0,
                )))
          ) {
            throw new Error(`${argumentLabel}: invalid typed-array fixture`);
          }
        });
        if (
          !Array.isArray(route.authorityBounds) ||
          route.authorityBounds.length === 0
        ) {
          throw new Error(
            `${label}: builtin effects route has no authority bounds`,
          );
        }
        for (const [boundIndex, bound] of route.authorityBounds.entries()) {
          const boundLabel = `${label}.sourceDescriptor.invocation.route.authorityBounds[${boundIndex}]`;
          exactKeys(
            bound,
            bound?.kind === "typed-effect"
              ? ["kind", "cap", "resourceKind", "requested"]
              : ["kind", "cap"],
            boundLabel,
          );
          if (
            !new Set(["capability-family", "typed-effect"]).has(bound.kind) ||
            typeof bound.cap !== "string" ||
            bound.cap.length === 0 ||
            (bound.kind === "typed-effect" &&
              (typeof bound.resourceKind !== "string" ||
                bound.resourceKind.length === 0 ||
                !bound.requested ||
                typeof bound.requested !== "object" ||
                Array.isArray(bound.requested)))
          ) {
            throw new Error(
              `${boundLabel}: invalid builtin effects authority bound`,
            );
          }
        }
        const setup = route.setup;
        if (setup !== null) {
          exactKeys(
            setup,
            [
              "kind",
              "fixtureKind",
              "fixtureKey",
              "moduleSpecifier",
              "operation",
              "path",
              "flags",
              "decisionEvidence",
              "cleanup",
              "setupDigest",
            ],
            `${label}.sourceDescriptor.invocation.route.setup`,
          );
          exactKeys(
            setup.cleanup,
            ["kind"],
            `${label}.sourceDescriptor.invocation.route.setup.cleanup`,
          );
          exactKeys(
            setup.decisionEvidence,
            [
              "kind",
              "carrierEdgeId",
              "typedRoutes",
              "requiredDecisionEdgeIds",
              "selectedNoEffectBranch",
            ],
            `${label}.sourceDescriptor.invocation.route.setup.decisionEvidence`,
          );
          const setupSource = {
            kind: setup.kind,
            fixtureKind: setup.fixtureKind,
            fixtureKey: setup.fixtureKey,
            moduleSpecifier: setup.moduleSpecifier,
            operation: setup.operation,
            path: setup.path,
            flags: setup.flags,
            decisionEvidence: setup.decisionEvidence,
            cleanup: setup.cleanup,
          };
          if (
            setup.kind !== "source-authored-filesystem-live-fixture" ||
            !new Set(["fd", "file-handle"]).has(setup.fixtureKind) ||
            typeof setup.fixtureKey !== "string" ||
            setup.fixtureKey !== invocation.coverageEdgeId ||
            !new Set(["node:fs", "bun:fs/promises"]).has(
              setup.moduleSpecifier,
            ) ||
            !new Set(["open-sync", "open-promise"]).has(setup.operation) ||
            (setup.fixtureKind === "fd" && setup.operation !== "open-sync") ||
            (setup.fixtureKind === "file-handle" &&
              setup.operation !== "open-promise") ||
            typeof setup.path !== "string" ||
            !setup.path.startsWith(`/project/fixtures/${setup.fixtureKey}/`) ||
            !new Set(["r", "r+"]).has(setup.flags) ||
            setup.decisionEvidence.kind !==
              "coverage-bound-fixture-setup-effects" ||
            setup.decisionEvidence.carrierEdgeId !==
              invocation.coverageEdgeId ||
            !Array.isArray(setup.decisionEvidence.typedRoutes) ||
            setup.decisionEvidence.typedRoutes.length === 0 ||
            !Array.isArray(setup.decisionEvidence.requiredDecisionEdgeIds) ||
            setup.decisionEvidence.requiredDecisionEdgeIds.length === 0 ||
            setup.decisionEvidence.selectedNoEffectBranch !== null ||
            setup.cleanup.kind !== "close-filesystem-live-fixture" ||
            setup.setupDigest !== outputShapeSourceDescriptorDigest(setupSource)
          ) {
            throw new Error(`${label}: invalid filesystem live fixture setup`);
          }
          const setupRouteIds = [];
          for (const [
            setupRouteIndex,
            setupRoute,
          ] of setup.decisionEvidence.typedRoutes.entries()) {
            const setupRouteLabel = `${label}.sourceDescriptor.invocation.route.setup.decisionEvidence.typedRoutes[${setupRouteIndex}]`;
            exactKeys(
              setupRoute,
              [
                "coverageEdgeId",
                "actionStages",
                "internalObserverActionStages",
                "sourceBinding",
              ],
              setupRouteLabel,
            );
            nonEmptyString(
              setupRoute.coverageEdgeId,
              `${setupRouteLabel}.coverageEdgeId`,
            );
            setupRouteIds.push(setupRoute.coverageEdgeId);
            for (const [field, allowEmpty] of [
              ["actionStages", false],
              ["internalObserverActionStages", true],
            ]) {
              const actions = setupRoute[field];
              if (
                !Array.isArray(actions) ||
                (!allowEmpty && actions.length === 0)
              ) {
                throw new Error(`${setupRouteLabel}.${field}: invalid actions`);
              }
              const actionIds = [];
              for (const [actionIndex, action] of actions.entries()) {
                const actionLabel = `${setupRouteLabel}.${field}[${actionIndex}]`;
                exactKeys(action, ["actionId", "stages"], actionLabel);
                nonEmptyString(action.actionId, `${actionLabel}.actionId`);
                if (
                  !Array.isArray(action.stages) ||
                  action.stages.length === 0 ||
                  canonicalJson(action.stages) !==
                    canonicalJson([...new Set(action.stages)].sort(compareText))
                ) {
                  throw new Error(`${actionLabel}: invalid exact stages`);
                }
                actionIds.push(action.actionId);
              }
              if (
                canonicalJson(actionIds) !==
                canonicalJson([...new Set(actionIds)].sort(compareText))
              ) {
                throw new Error(
                  `${setupRouteLabel}.${field}: noncanonical actions`,
                );
              }
            }
            const sourceBinding = setupRoute.sourceBinding;
            if (sourceBinding === null) {
              throw new Error(
                `${setupRouteLabel}: setup route has no source binding`,
              );
            }
            exactKeys(
              sourceBinding,
              [
                "kind",
                "nativeTerminal",
                "nativeSourceRef",
                "hostAuthorizationRef",
                "bindingDigest",
              ],
              `${setupRouteLabel}.sourceBinding`,
            );
            const boundSource = {
              kind: sourceBinding.kind,
              nativeTerminal: sourceBinding.nativeTerminal,
              nativeSourceRef: sourceBinding.nativeSourceRef,
              hostAuthorizationRef: sourceBinding.hostAuthorizationRef,
            };
            if (
              sourceBinding.kind !==
                "source-authored-native-filesystem-terminal" ||
              sourceBinding.nativeSourceRef !==
                `src/engine/hermes_runtime_fs.cc#${sourceBinding.nativeTerminal}` ||
              sourceBinding.hostAuthorizationRef !==
                "src/host/abi.rs#ex_host_authorize_typed_fs_stack" ||
              sourceBinding.bindingDigest !==
                outputShapeSourceDescriptorDigest(boundSource)
            ) {
              throw new Error(
                `${setupRouteLabel}: invalid setup source binding`,
              );
            }
          }
          if (
            canonicalJson(setupRouteIds) !==
              canonicalJson([...new Set(setupRouteIds)].sort(compareText)) ||
            canonicalJson(setup.decisionEvidence.requiredDecisionEdgeIds) !==
              canonicalJson(
                [
                  ...new Set(setup.decisionEvidence.requiredDecisionEdgeIds),
                ].sort(compareText),
              ) ||
            !setup.decisionEvidence.requiredDecisionEdgeIds.every((edgeId) =>
              setupRouteIds.includes(edgeId),
            )
          ) {
            throw new Error(`${label}: setup typed routes are not canonical`);
          }
        }
        const decisionEvidence = invocation.decisionEvidence;
        exactKeys(
          decisionEvidence,
          [
            "kind",
            "carrierEdgeId",
            "typedRoutes",
            "requiredDecisionEdgeIds",
            "selectedNoEffectBranch",
          ],
          `${label}.sourceDescriptor.invocation.decisionEvidence`,
        );
        if (
          decisionEvidence.kind !== "coverage-bound-typed-effects" ||
          decisionEvidence.carrierEdgeId !== invocation.coverageEdgeId ||
          !Array.isArray(decisionEvidence.typedRoutes) ||
          decisionEvidence.typedRoutes.length === 0 ||
          !Array.isArray(decisionEvidence.requiredDecisionEdgeIds)
        ) {
          throw new Error(`${label}: invalid builtin effects decision binding`);
        }
        const typedRouteIds = [];
        for (const [
          routeIndex,
          typedRoute,
        ] of decisionEvidence.typedRoutes.entries()) {
          const routeLabel = `${label}.sourceDescriptor.invocation.decisionEvidence.typedRoutes[${routeIndex}]`;
          exactKeys(
            typedRoute,
            [
              "coverageEdgeId",
              "actionStages",
              "internalObserverActionStages",
              "sourceBinding",
            ],
            routeLabel,
          );
          nonEmptyString(
            typedRoute.coverageEdgeId,
            `${routeLabel}.coverageEdgeId`,
          );
          if (
            !Array.isArray(typedRoute.actionStages) ||
            typedRoute.actionStages.length === 0
          ) {
            throw new Error(`${routeLabel}: typed route must carry actions`);
          }
          if (!Array.isArray(typedRoute.internalObserverActionStages)) {
            throw new Error(
              `${routeLabel}: internal observer action stages must be an array`,
            );
          }
          typedRouteIds.push(typedRoute.coverageEdgeId);
          const validateActionStages = (actions, field, allowEmpty) => {
            if (!allowEmpty && actions.length === 0) {
              throw new Error(
                `${routeLabel}.${field}: typed route must carry actions`,
              );
            }
            const actionIds = [];
            for (const [actionIndex, action] of actions.entries()) {
              const actionLabel = `${routeLabel}.${field}[${actionIndex}]`;
              exactKeys(action, ["actionId", "stages"], actionLabel);
              nonEmptyString(action.actionId, `${actionLabel}.actionId`);
              if (
                !Array.isArray(action.stages) ||
                action.stages.length === 0 ||
                action.stages.some(
                  (stage) => typeof stage !== "string" || stage.length === 0,
                )
              ) {
                throw new Error(
                  `${actionLabel}: typed action has no exact stages`,
                );
              }
              actionIds.push(action.actionId);
              if (
                canonicalJson(action.stages) !==
                canonicalJson([...new Set(action.stages)].sort(compareText))
              ) {
                throw new Error(
                  `${actionLabel}: typed stages are not canonical`,
                );
              }
            }
            if (
              canonicalJson(actionIds) !==
              canonicalJson([...new Set(actionIds)].sort(compareText))
            ) {
              throw new Error(
                `${routeLabel}.${field}: typed actions are not canonical`,
              );
            }
          };
          validateActionStages(typedRoute.actionStages, "actionStages", false);
          validateActionStages(
            typedRoute.internalObserverActionStages,
            "internalObserverActionStages",
            true,
          );
          const sourceBinding = typedRoute.sourceBinding;
          if (sourceBinding === null) {
            if (typedRoute.internalObserverActionStages.length !== 0) {
              throw new Error(
                `${routeLabel}: internal observer stages have no native source binding`,
              );
            }
          } else {
            exactKeys(
              sourceBinding,
              [
                "kind",
                "nativeTerminal",
                "nativeSourceRef",
                "hostAuthorizationRef",
                "bindingDigest",
              ],
              `${routeLabel}.sourceBinding`,
            );
            const source = {
              kind: sourceBinding.kind,
              nativeTerminal: sourceBinding.nativeTerminal,
              nativeSourceRef: sourceBinding.nativeSourceRef,
              hostAuthorizationRef: sourceBinding.hostAuthorizationRef,
            };
            if (
              sourceBinding.kind !==
                "source-authored-native-filesystem-terminal" ||
              !sourceBinding.nativeTerminal.startsWith("__exact") ||
              sourceBinding.nativeSourceRef !==
                `src/engine/hermes_runtime_fs.cc#${sourceBinding.nativeTerminal}` ||
              sourceBinding.hostAuthorizationRef !==
                "src/host/abi.rs#ex_host_authorize_typed_fs_stack" ||
              sourceBinding.bindingDigest !==
                outputShapeSourceDescriptorDigest(source)
            ) {
              throw new Error(`${routeLabel}: invalid native source binding`);
            }
          }
        }
        if (
          canonicalJson(typedRouteIds) !==
            canonicalJson([...new Set(typedRouteIds)].sort(compareText)) ||
          !typedRouteIds.includes(invocation.coverageEdgeId) ||
          canonicalJson(decisionEvidence.requiredDecisionEdgeIds) !==
            canonicalJson(
              [...new Set(decisionEvidence.requiredDecisionEdgeIds)].sort(
                compareText,
              ),
            ) ||
          !decisionEvidence.requiredDecisionEdgeIds.every((edgeId) =>
            typedRouteIds.includes(edgeId),
          ) ||
          (route.setup !== null &&
            decisionEvidence.requiredDecisionEdgeIds.length === 0)
        ) {
          throw new Error(
            `${label}: builtin effects typed routes are not canonical`,
          );
        }
        const noEffectBranch = decisionEvidence.selectedNoEffectBranch;
        if (noEffectBranch !== null) {
          exactKeys(
            noEffectBranch,
            ["carrierEdgeId", "branchId", "conditions", "branchDigest"],
            `${label}.sourceDescriptor.invocation.decisionEvidence.selectedNoEffectBranch`,
          );
          if (Array.isArray(noEffectBranch.conditions)) {
            noEffectBranch.conditions.forEach((condition, conditionIndex) =>
              exactKeys(
                condition,
                ["fact", "equals"],
                `${label}.sourceDescriptor.invocation.decisionEvidence.selectedNoEffectBranch.conditions[${conditionIndex}]`,
              ),
            );
          }
          if (
            noEffectBranch.carrierEdgeId !== invocation.coverageEdgeId ||
            typeof noEffectBranch.branchId !== "string" ||
            noEffectBranch.branchId.length === 0 ||
            !Array.isArray(noEffectBranch.conditions) ||
            noEffectBranch.conditions.length === 0 ||
            !noEffectBranch.conditions.every(
              (condition) =>
                condition &&
                typeof condition === "object" &&
                !Array.isArray(condition) &&
                typeof condition.fact === "string" &&
                condition.fact.length > 0 &&
                typeof condition.equals === "string" &&
                condition.equals.length > 0,
            )
          ) {
            throw new Error(`${label}: invalid source-bound no-effect branch`);
          }
          digest(
            noEffectBranch.branchDigest,
            `${label}.noEffectBranch.branchDigest`,
          );
        }
        exactKeys(
          invocation.positiveControl,
          ["kind", "family"],
          `${label}.sourceDescriptor.invocation.positiveControl`,
        );
        exactKeys(
          invocation.completion,
          ["kind", "timeoutMilliseconds"],
          `${label}.sourceDescriptor.invocation.completion`,
        );
        if (
          invocation.invocationSchema !==
            BUILTIN_EFFECTS_OUTPUT_INVOCATION_SCHEMA ||
          invocation.kind !== "builtin-effects-output" ||
          !new Set(["registrar", "descriptor-residual"]).has(
            invocation.cohort,
          ) ||
          invocation.coverageEdgeId !== key.surfaceId ||
          invocation.coverageClassification !== "effects" ||
          invocation.surfaceObservedKey !==
            probe.sourceDescriptor.surfaceObservedKey ||
          probe.sourceDescriptor.surfaceObservedKey !==
            `builtin:${key.alias}` ||
          typeof invocation.moduleSpecifier !== "string" ||
          invocation.moduleSpecifier.length === 0 ||
          builtinDescriptor.kind !== "builtin-export" ||
          typeof builtinDescriptor.sourceKey !== "string" ||
          builtinDescriptor.sourceKey.length === 0 ||
          typeof builtinDescriptor.exportName !== "string" ||
          builtinDescriptor.exportName.length === 0 ||
          !Array.isArray(builtinDescriptor.exportIdioms) ||
          builtinDescriptor.exportIdioms.length === 0 ||
          !Array.isArray(builtinDescriptor.moduleSpecifiers) ||
          !builtinDescriptor.moduleSpecifiers.includes(
            invocation.moduleSpecifier,
          ) ||
          typeof builtinDescriptor.sourceRef !== "string" ||
          builtinDescriptor.sourceRef.length === 0 ||
          !new Set(["callable", "accessor", "unknown"]).has(
            builtinDescriptor.valueShape,
          ) ||
          builtinDescriptor.importReachability !== "public" ||
          !new Set([
            "export-property",
            "prototype-property",
            "inherited-prototype-property",
            "module-value",
          ]).has(builtinDescriptor.access.kind) ||
          !Array.isArray(builtinDescriptor.access.path) ||
          !builtinDescriptor.access.path.every(
            (component) =>
              typeof component === "string" && component.length > 0,
          ) ||
          (builtinDescriptor.platformAvailability !== undefined &&
            (!Array.isArray(builtinDescriptor.platformAvailability) ||
              builtinDescriptor.platformAvailability.length === 0 ||
              !builtinDescriptor.platformAvailability.every((platform) =>
                new Set(["android", "darwin", "linux"]).has(platform),
              ))) ||
          outputShapeSourceDescriptorDigest(builtinDescriptor) !==
            invocation.sourceDescriptorDigest ||
          !new Set(["call", "construct", "get"]).has(route.operation) ||
          !Array.isArray(route.arguments) ||
          !new Set(["module-value", "prototype-shell", "fixture-value"]).has(
            route.receiver.kind,
          ) ||
          (route.receiver.kind === "prototype-shell" &&
            (!Array.isArray(route.receiver.ownerPath) ||
              route.receiver.ownerPath.length === 0)) ||
          (route.receiver.kind === "fixture-value" && setup === null) ||
          route.cleanup.kind !== "fixture-owned-resource-release" ||
          route.fixture.kind !== "isolated-family-fixture" ||
          route.fixture.family !== builtinDescriptor.sourceKey ||
          route.fixture.network !== "private-loopback-only" ||
          route.fixture.filesystem !== "private-project-tree-only" ||
          route.fixture.process !== "controlled-helper-only" ||
          invocation.positiveControl.kind !==
            "public-family-positive-control" ||
          invocation.positiveControl.family !== builtinDescriptor.sourceKey ||
          invocation.completion.kind !== "event-loop-quiescence" ||
          invocation.completion.timeoutMilliseconds !== 1_000 ||
          canonicalJson(probe.recordPath) !== canonicalJson(["[[return]]"])
        ) {
          throw new Error(
            `${label}: invalid authored builtin effects output route`,
          );
        }
      }
      if (
        probe.sourceDescriptor.kind ===
        BUILTIN_NONCAP_CLOSED_OUTPUT_SOURCE_DESCRIPTOR_KIND
      ) {
        exactKeys(
          probe.sourceDescriptor,
          ["kind", "surfaceObservedKey", "invocation"],
          `${label}.sourceDescriptor`,
        );
        const invocation = probe.sourceDescriptor.invocation;
        exactKeys(
          invocation,
          [
            "invocationSchema",
            "kind",
            "coverageEdgeId",
            "coverageClassification",
            "surfaceObservedKey",
            "moduleSpecifier",
            "sourceDescriptor",
            "sourceDescriptorDigest",
            "route",
            "completion",
          ],
          `${label}.sourceDescriptor.invocation`,
        );
        const builtinDescriptor = invocation.sourceDescriptor;
        exactKeys(
          builtinDescriptor,
          [
            "kind",
            "sourceKey",
            "exportName",
            "exportIdioms",
            "moduleSpecifiers",
            "sourceRef",
            "valueShape",
            "importReachability",
            "access",
            ...(Object.hasOwn(builtinDescriptor ?? {}, "platformAvailability")
              ? ["platformAvailability"]
              : []),
          ],
          `${label}.sourceDescriptor.invocation.sourceDescriptor`,
        );
        exactKeys(
          builtinDescriptor.access,
          ["kind", "path"],
          `${label}.sourceDescriptor.invocation.sourceDescriptor.access`,
        );
        const route = invocation.route;
        if (!route || typeof route !== "object" || Array.isArray(route)) {
          throw new Error(`${label}: builtin output route must be an object`);
        }
        const allowedRouteFields = new Set([
          "operation",
          "reasonCode",
          "reason",
          "receiver",
          "arguments",
          "cleanup",
          "awaitResult",
          "inheritedTemplateId",
          "outcomeCapture",
          "dependencyModuleSpecifiers",
        ]);
        for (const field of Object.keys(route)) {
          if (!allowedRouteFields.has(field)) {
            throw new Error(
              `${label}: unsupported builtin output route field ${field}`,
            );
          }
        }
        const operation = route.operation;
        const operations = new Set([
          "call",
          "construct",
          "get",
          "import-refusal",
          "import-return",
          "unexercisable",
        ]);
        if (!operations.has(operation)) {
          throw new Error(`${label}: unsupported builtin output operation`);
        }
        if (operation === "unexercisable") {
          exactKeys(
            route,
            ["operation", "reasonCode", "reason"],
            `${label}.sourceDescriptor.invocation.route`,
          );
          nonEmptyString(route.reasonCode, `${label}.route.reasonCode`);
          nonEmptyString(route.reason, `${label}.route.reason`);
        } else if (
          operation === "import-refusal" ||
          operation === "import-return"
        ) {
          exactKeys(
            route,
            ["operation", "cleanup"],
            `${label}.sourceDescriptor.invocation.route`,
          );
        } else {
          if (!Array.isArray(route.arguments)) {
            throw new Error(
              `${label}: builtin operation arguments must be an array`,
            );
          }
          if (!route.cleanup || typeof route.cleanup !== "object") {
            throw new Error(`${label}: builtin operation must own cleanup`);
          }
          if (
            Object.hasOwn(route, "receiver") &&
            (!route.receiver ||
              typeof route.receiver !== "object" ||
              Array.isArray(route.receiver) ||
              typeof route.receiver.kind !== "string" ||
              route.receiver.kind.length === 0)
          ) {
            throw new Error(`${label}: invalid builtin operation receiver`);
          }
          if (
            Object.hasOwn(route, "awaitResult") &&
            route.awaitResult !== true
          ) {
            throw new Error(`${label}: invalid builtin await-result marker`);
          }
          if (Object.hasOwn(route, "inheritedTemplateId")) {
            nonEmptyString(
              route.inheritedTemplateId,
              `${label}.route.inheritedTemplateId`,
            );
          }
          if (
            Object.hasOwn(route, "outcomeCapture") &&
            (route.outcomeCapture !== "public-builtin-family" ||
              builtinDescriptor.importReachability !== "public")
          ) {
            throw new Error(`${label}: invalid public builtin outcome capture`);
          }
          if (Object.hasOwn(route, "dependencyModuleSpecifiers")) {
            if (
              !Array.isArray(route.dependencyModuleSpecifiers) ||
              route.dependencyModuleSpecifiers.length === 0 ||
              !route.dependencyModuleSpecifiers.every(
                (specifier) =>
                  typeof specifier === "string" && specifier.length > 0,
              )
            ) {
              throw new Error(`${label}: invalid builtin dependency modules`);
            }
          }
        }
        if (
          operation !== "unexercisable" &&
          (!route.cleanup ||
            typeof route.cleanup !== "object" ||
            Array.isArray(route.cleanup) ||
            typeof route.cleanup.kind !== "string" ||
            route.cleanup.kind.length === 0)
        ) {
          throw new Error(`${label}: invalid builtin cleanup route`);
        }
        if (
          invocation.invocationSchema !==
            BUILTIN_NONCAP_CLOSED_OUTPUT_INVOCATION_SCHEMA ||
          invocation.kind !== "builtin-noncap-closed-output" ||
          invocation.coverageEdgeId !== key.surfaceId ||
          !new Set(["non-capability", "closed"]).has(
            invocation.coverageClassification,
          ) ||
          invocation.surfaceObservedKey !==
            probe.sourceDescriptor.surfaceObservedKey ||
          probe.sourceDescriptor.surfaceObservedKey !==
            `builtin:${key.alias}` ||
          (invocation.moduleSpecifier !== null &&
            (typeof invocation.moduleSpecifier !== "string" ||
              invocation.moduleSpecifier.length === 0)) ||
          !new Set(["builtin-export", "builtin-root"]).has(
            builtinDescriptor.kind,
          ) ||
          typeof builtinDescriptor.sourceKey !== "string" ||
          builtinDescriptor.sourceKey.length === 0 ||
          typeof builtinDescriptor.exportName !== "string" ||
          builtinDescriptor.exportName.length === 0 ||
          !Array.isArray(builtinDescriptor.exportIdioms) ||
          builtinDescriptor.exportIdioms.length === 0 ||
          !Array.isArray(builtinDescriptor.moduleSpecifiers) ||
          typeof builtinDescriptor.sourceRef !== "string" ||
          builtinDescriptor.sourceRef.length === 0 ||
          typeof builtinDescriptor.valueShape !== "string" ||
          builtinDescriptor.valueShape.length === 0 ||
          !new Set(["public", "bootstrap-internal"]).has(
            builtinDescriptor.importReachability,
          ) ||
          !new Set([
            "export-property",
            "prototype-property",
            "inherited-prototype-property",
            "module-value",
          ]).has(builtinDescriptor.access.kind) ||
          !Array.isArray(builtinDescriptor.access.path) ||
          !builtinDescriptor.access.path.every(
            (component) =>
              typeof component === "string" && component.length > 0,
          ) ||
          (invocation.moduleSpecifier !== null &&
            !builtinDescriptor.moduleSpecifiers.includes(
              invocation.moduleSpecifier,
            )) ||
          outputShapeSourceDescriptorDigest(builtinDescriptor) !==
            invocation.sourceDescriptorDigest ||
          (builtinDescriptor.platformAvailability !== undefined &&
            (!Array.isArray(builtinDescriptor.platformAvailability) ||
              builtinDescriptor.platformAvailability.length === 0 ||
              !builtinDescriptor.platformAvailability.every((platform) =>
                new Set(["android", "darwin", "linux"]).has(platform),
              )))
        ) {
          throw new Error(`${label}: invalid authored builtin output route`);
        }
        exactKeys(
          invocation.completion,
          ["kind", "timeoutMilliseconds"],
          `${label}.sourceDescriptor.invocation.completion`,
        );
        if (
          invocation.completion.kind !== "event-loop-quiescence" ||
          invocation.completion.timeoutMilliseconds !== 1_000
        ) {
          throw new Error(`${label}: unbounded builtin output completion`);
        }
      }
      if (
        probe.sourceDescriptor.kind === "authored-public-builtin-invocation"
      ) {
        exactKeys(
          probe.sourceDescriptor,
          ["kind", "surfaceObservedKey", "invocation"],
          `${label}.sourceDescriptor`,
        );
        const invocation = probe.sourceDescriptor.invocation;
        const call = invocation?.kind === "builtin-export-call";
        const read = invocation?.kind === "builtin-export-read";
        exactKeys(
          invocation,
          [
            "invocationSchema",
            "kind",
            "moduleSpecifier",
            "exportName",
            "sourceDescriptor",
            "sourceDescriptorDigest",
            ...(call ? ["templateId"] : []),
            "arguments",
            "setup",
            "completion",
          ],
          `${label}.sourceDescriptor.invocation`,
        );
        if (
          (!call && !read) ||
          invocation.invocationSchema !==
            (call
              ? "ibex/capsec-builtin-call-invocation/1"
              : "ibex/capsec-builtin-export-invocation/1") ||
          typeof probe.sourceDescriptor.surfaceObservedKey !== "string" ||
          !probe.sourceDescriptor.surfaceObservedKey.startsWith(
            "builtin:export:",
          ) ||
          outputShapeSourceDescriptorDigest(invocation.sourceDescriptor) !==
            invocation.sourceDescriptorDigest
        ) {
          throw new Error(`${label}: invalid authored public builtin route`);
        }
        exactKeys(
          invocation.completion,
          ["kind", "timeoutMilliseconds"],
          `${label}.sourceDescriptor.invocation.completion`,
        );
        if (
          invocation.completion.kind !== "event-loop-quiescence" ||
          invocation.completion.timeoutMilliseconds !== 1_000
        ) {
          throw new Error(`${label}: unbounded public builtin completion`);
        }
      }
      if (probe.sourceDescriptor.kind === "authored-global-accessor-get") {
        exactKeys(
          probe.sourceDescriptor,
          ["kind", "surfaceObservedKey", "invocation"],
          `${label}.sourceDescriptor`,
        );
        const invocation = probe.sourceDescriptor.invocation;
        exactKeys(
          invocation,
          [
            "invocationSchema",
            "kind",
            "coverageEdgeId",
            "coverageClassification",
            "sourceDescriptor",
            "sourceDescriptorDigest",
            "receiver",
            ...(invocation?.authority === undefined ? [] : ["authority"]),
            "completion",
          ],
          `${label}.sourceDescriptor.invocation`,
        );
        exactKeys(
          invocation.sourceDescriptor,
          ["kind", "globalName", "memberName", "memberKinds", "sourceRefs"],
          `${label}.sourceDescriptor.invocation.sourceDescriptor`,
        );
        const receiver = invocation.receiver;
        const receiverKeys = {
          "global-root": ["kind"],
          "existing-global": ["kind", "receiverGlobalName"],
          "construct-global": ["kind", "arguments"],
          "global-prototype": ["kind"],
          factory: ["kind", "factoryId"],
          unexercisable: ["kind", "reasonCode", "reason"],
        }[receiver?.kind];
        if (!receiverKeys) {
          throw new Error(`${label}: unsupported global accessor receiver`);
        }
        exactKeys(
          receiver,
          receiverKeys,
          `${label}.sourceDescriptor.invocation.receiver`,
        );
        if (invocation.authority !== undefined) {
          if (
            !Array.isArray(invocation.authority) ||
            invocation.authority.length === 0
          ) {
            throw new Error(`${label}: accessor authority must be non-empty`);
          }
          for (const [grantIndex, grant] of invocation.authority.entries()) {
            const grantLabel = `${label}.sourceDescriptor.invocation.authority[${grantIndex}]`;
            exactKeys(
              grant,
              ["kind", "cap", "resourceKind", "requested"],
              grantLabel,
            );
            if (
              grant.kind !== "typed-effect" ||
              typeof grant.cap !== "string" ||
              grant.cap.length === 0 ||
              typeof grant.resourceKind !== "string" ||
              grant.resourceKind.length === 0 ||
              !grant.requested ||
              typeof grant.requested !== "object" ||
              Array.isArray(grant.requested)
            ) {
              throw new Error(`${grantLabel}: invalid typed effect authority`);
            }
          }
        }
        if (
          invocation.invocationSchema !==
            "ibex/capsec-global-accessor-get-invocation/1" ||
          invocation.kind !== "global-accessor-get" ||
          invocation.coverageEdgeId !== key.surfaceId ||
          !new Set(["non-capability", "effects", "closed"]).has(
            invocation.coverageClassification,
          ) ||
          probe.sourceDescriptor.surfaceObservedKey !==
            `native-op:${key.alias}` ||
          invocation.sourceDescriptor.kind !== "global-api-accessor" ||
          typeof invocation.sourceDescriptor.globalName !== "string" ||
          invocation.sourceDescriptor.globalName.length === 0 ||
          (invocation.sourceDescriptor.memberName !== null &&
            (typeof invocation.sourceDescriptor.memberName !== "string" ||
              invocation.sourceDescriptor.memberName.length === 0)) ||
          !Array.isArray(invocation.sourceDescriptor.memberKinds) ||
          !Array.isArray(invocation.sourceDescriptor.sourceRefs) ||
          invocation.sourceDescriptor.sourceRefs.length === 0 ||
          outputShapeSourceDescriptorDigest(invocation.sourceDescriptor) !==
            invocation.sourceDescriptorDigest ||
          (invocation.coverageClassification === "closed" &&
            receiver.kind !== "unexercisable") ||
          (receiver.kind === "existing-global" &&
            (typeof receiver.receiverGlobalName !== "string" ||
              receiver.receiverGlobalName.length === 0)) ||
          (receiver.kind === "construct-global" &&
            !Array.isArray(receiver.arguments)) ||
          (receiver.kind === "factory" &&
            !globalAccessorReceiverRecipeIds.includes(receiver.factoryId)) ||
          (receiver.kind === "unexercisable" &&
            (typeof receiver.reasonCode !== "string" ||
              receiver.reasonCode.length === 0 ||
              typeof receiver.reason !== "string" ||
              receiver.reason.length === 0))
        ) {
          throw new Error(
            `${label}: invalid authored global accessor Get route`,
          );
        }
        exactKeys(
          invocation.completion,
          ["kind", "timeoutMilliseconds"],
          `${label}.sourceDescriptor.invocation.completion`,
        );
        if (
          invocation.completion.kind !== "event-loop-quiescence" ||
          invocation.completion.timeoutMilliseconds !== 1_000
        ) {
          throw new Error(`${label}: unbounded global accessor Get completion`);
        }
      }
      if (
        probe.sourceDescriptor.kind === "authored-global-callable-invocation"
      ) {
        exactKeys(
          probe.sourceDescriptor,
          ["kind", "surfaceObservedKey", "invocation"],
          `${label}.sourceDescriptor`,
        );
        const invocation = probe.sourceDescriptor.invocation;
        exactKeys(
          invocation,
          [
            "invocationSchema",
            "kind",
            "coverageEdgeId",
            "coverageClassification",
            "sourceDescriptor",
            "sourceDescriptorDigest",
            "route",
            "completion",
          ],
          `${label}.sourceDescriptor.invocation`,
        );
        exactKeys(
          invocation.sourceDescriptor,
          ["kind", "globalName", "memberName", "memberKinds", "sourceRefs"],
          `${label}.sourceDescriptor.invocation.sourceDescriptor`,
        );
        const route = invocation.route;
        if (route?.operation === "unexercisable") {
          exactKeys(
            route,
            ["operation", "reasonCode", "reason"],
            `${label}.sourceDescriptor.invocation.route`,
          );
        } else {
          exactKeys(
            route,
            [
              "operation",
              "receiver",
              "arguments",
              ...(route?.cleanup ? ["cleanup"] : []),
              ...(Object.hasOwn(route ?? {}, "suppressRejection")
                ? ["suppressRejection"]
                : []),
              ...(Object.hasOwn(route ?? {}, "authority") ? ["authority"] : []),
            ],
            `${label}.sourceDescriptor.invocation.route`,
          );
          const receiverKeys = {
            "source-member-owner": ["kind"],
            "existing-global": ["kind", "globalName"],
            "construct-global": ["kind", "globalName", "arguments"],
            factory: ["kind", "factoryId", "options"],
          }[route.receiver?.kind];
          if (!receiverKeys) {
            throw new Error(`${label}: unsupported global callable receiver`);
          }
          exactKeys(
            route.receiver,
            receiverKeys,
            `${label}.sourceDescriptor.invocation.route.receiver`,
          );
          if (Object.hasOwn(route, "authority")) {
            if (
              !Array.isArray(route.authority) ||
              route.authority.length === 0
            ) {
              throw new Error(`${label}: callable authority must be non-empty`);
            }
            route.authority.forEach((grant, grantIndex) => {
              const grantLabel = `${label}.sourceDescriptor.invocation.route.authority[${grantIndex}]`;
              exactKeys(
                grant,
                ["kind", "cap", "resourceKind", "requested"],
                grantLabel,
              );
              if (
                grant.kind !== "typed-effect" ||
                typeof grant.cap !== "string" ||
                grant.cap.length === 0 ||
                typeof grant.resourceKind !== "string" ||
                grant.resourceKind.length === 0 ||
                !grant.requested ||
                typeof grant.requested !== "object" ||
                Array.isArray(grant.requested)
              ) {
                throw new Error(`${grantLabel}: invalid typed-effect grant`);
              }
            });
          }
        }
        if (
          invocation.invocationSchema !==
            "ibex/capsec-global-callable-invocation/1" ||
          invocation.kind !== "global-callable-invocation" ||
          invocation.coverageEdgeId !== key.surfaceId ||
          !new Set(["non-capability", "effects", "closed"]).has(
            invocation.coverageClassification,
          ) ||
          probe.sourceDescriptor.surfaceObservedKey !==
            `native-op:${key.alias}` ||
          invocation.sourceDescriptor.kind !== "global-api-callable" ||
          typeof invocation.sourceDescriptor.globalName !== "string" ||
          invocation.sourceDescriptor.globalName.length === 0 ||
          (invocation.sourceDescriptor.memberName !== null &&
            (typeof invocation.sourceDescriptor.memberName !== "string" ||
              invocation.sourceDescriptor.memberName.length === 0)) ||
          !Array.isArray(invocation.sourceDescriptor.memberKinds) ||
          !Array.isArray(invocation.sourceDescriptor.sourceRefs) ||
          invocation.sourceDescriptor.sourceRefs.length === 0 ||
          outputShapeSourceDescriptorDigest(invocation.sourceDescriptor) !==
            invocation.sourceDescriptorDigest ||
          (route.operation === "unexercisable" &&
            (typeof route.reasonCode !== "string" ||
              route.reasonCode.length === 0 ||
              typeof route.reason !== "string" ||
              route.reason.length === 0)) ||
          (route.operation !== "unexercisable" &&
            (!new Set(["call", "construct", "get"]).has(route.operation) ||
              !Array.isArray(route.arguments) ||
              (route.receiver.kind === "existing-global" &&
                (typeof route.receiver.globalName !== "string" ||
                  route.receiver.globalName.length === 0)) ||
              (route.receiver.kind === "construct-global" &&
                (typeof route.receiver.globalName !== "string" ||
                  route.receiver.globalName.length === 0 ||
                  !Array.isArray(route.receiver.arguments))) ||
              (route.receiver.kind === "factory" &&
                !globalCallableFactoryRecipeIds.includes(
                  route.receiver.factoryId,
                ))))
        ) {
          throw new Error(`${label}: invalid authored global callable route`);
        }
        exactKeys(
          invocation.completion,
          ["kind", "timeoutMilliseconds"],
          `${label}.sourceDescriptor.invocation.completion`,
        );
        if (
          invocation.completion.kind !== "event-loop-quiescence" ||
          invocation.completion.timeoutMilliseconds !== 1_000
        ) {
          throw new Error(`${label}: unbounded global callable completion`);
        }
      }
      if (probe.sourceDescriptor.kind === "authored-closed-control-output") {
        exactKeys(
          probe.sourceDescriptor,
          ["kind", "surfaceObservedKey", "invocation"],
          `${label}.sourceDescriptor`,
        );
        const invocation = probe.sourceDescriptor.invocation;
        exactKeys(
          invocation,
          [
            "invocationSchema",
            "kind",
            "coverageEdgeId",
            "surfaceObservedKey",
            "sourceDescriptor",
            "sourceDescriptorDigest",
            "operation",
            "completion",
          ],
          `${label}.sourceDescriptor.invocation`,
        );
        const operationKeys = {
          "cli-control": ["kind", "argumentVectors", "projectCodePlaceholder"],
          "startup-environment": ["kind", "environmentName"],
          "loader-executable-file": ["kind", "loaderKind", "extension"],
        }[invocation.operation?.kind];
        if (!operationKeys) {
          throw new Error(`${label}: unsupported closed-control operation`);
        }
        exactKeys(
          invocation.operation,
          operationKeys,
          `${label}.sourceDescriptor.invocation.operation`,
        );
        const expectedSourceKind = {
          "cli-control": "cli",
          "startup-environment": "startup",
          "loader-executable-file": "loader",
        }[invocation.operation.kind];
        const expectedDescriptorKind = {
          "cli-control": "closed-cli-control",
          "startup-environment": "closed-startup-environment",
          "loader-executable-file": "closed-loader-executable-kind",
        }[invocation.operation.kind];
        if (
          invocation.invocationSchema !==
            "ibex/capsec-closed-control-output-invocation/1" ||
          invocation.kind !== "closed-control-output" ||
          invocation.coverageEdgeId !== key.surfaceId ||
          probe.sourceDescriptor.surfaceObservedKey !==
            `${key.sourceKind}:${key.alias}` ||
          invocation.surfaceObservedKey !==
            probe.sourceDescriptor.surfaceObservedKey ||
          key.sourceKind !== expectedSourceKind ||
          !invocation.sourceDescriptor ||
          typeof invocation.sourceDescriptor !== "object" ||
          Array.isArray(invocation.sourceDescriptor) ||
          invocation.sourceDescriptor.kind !== expectedDescriptorKind ||
          outputShapeSourceDescriptorDigest(invocation.sourceDescriptor) !==
            invocation.sourceDescriptorDigest ||
          (invocation.operation.kind === "cli-control" &&
            (!Array.isArray(invocation.operation.argumentVectors) ||
              invocation.operation.argumentVectors.length === 0 ||
              typeof invocation.operation.projectCodePlaceholder !== "string" ||
              invocation.operation.projectCodePlaceholder.length === 0)) ||
          (invocation.operation.kind === "startup-environment" &&
            (typeof invocation.operation.environmentName !== "string" ||
              invocation.operation.environmentName.length === 0 ||
              invocation.sourceDescriptor.environmentName !==
                invocation.operation.environmentName)) ||
          (invocation.operation.kind === "loader-executable-file" &&
            !new Set(["native-addon", "wasm"]).has(
              invocation.operation.loaderKind,
            )) ||
          (invocation.operation.kind === "loader-executable-file" &&
            ((invocation.operation.loaderKind === "native-addon" &&
              invocation.operation.extension !== ".node") ||
              (invocation.operation.loaderKind === "wasm" &&
                invocation.operation.extension !== ".wasm") ||
              invocation.sourceDescriptor.loaderKind !==
                invocation.operation.loaderKind ||
              invocation.sourceDescriptor.extension !==
                invocation.operation.extension))
        ) {
          throw new Error(`${label}: invalid authored closed-control route`);
        }
        exactKeys(
          invocation.completion,
          ["kind", "timeoutMilliseconds"],
          `${label}.sourceDescriptor.invocation.completion`,
        );
        if (
          invocation.completion.kind !== "bounded-production-boundary" ||
          invocation.completion.timeoutMilliseconds !== 1_000
        ) {
          throw new Error(`${label}: unbounded closed-control completion`);
        }
      }
      if (
        !Array.isArray(probe.recordPath) ||
        probe.recordPath.length === 0 ||
        probe.recordPath.some(
          (component) =>
            typeof component !== "string" || component.length === 0,
        )
      ) {
        throw new Error(
          `${label}.recordPath: expected non-empty string components`,
        );
      }
      return;
    default:
      throw new Error(
        `${label}.kind: unsupported output-shape probe mechanism`,
      );
  }
}

function validateCatalogProbeMechanism(catalogRow, probe, label) {
  if (catalogRow.requiredValueProof !== "live-value-observation") {
    throw new Error(`${label}: catalog row does not require live value proof`);
  }
  validateOutputValueProofKind(probe.kind, `${label}.kind`);
  if (
    new Set(["__exactDeepFreeze", "__exactNativeFreeze"]).has(
      catalogRow.key.alias,
    ) &&
    probe.sourceDescriptor?.kind !== NATIVE_FREEZE_OUTPUT_SOURCE_DESCRIPTOR_KIND
  ) {
    throw new Error(
      `${label}: native freeze identity requires its exact authored route`,
    );
  }
  if (
    catalogRow.discovery?.kind === "source-asserted-structured-output" &&
    probe.kind !== "loaded-engine-return-record"
  ) {
    throw new Error(
      `${label}: structured output rows require a loaded-engine return-record probe`,
    );
  }
  const contextId = catalogRow.key.contextId;
  const exercise = probe.sourceDescriptor?.exercise?.kind;
  if (
    probe.kind === "loaded-engine-descriptor" &&
    contextId === "javascript.package-call-loaded" &&
    !new Set(["call", "construct", "fixture", "unexercisable"]).has(exercise)
  ) {
    throw new Error(
      `${label}: package-call context requires an exercised live invocation`,
    );
  }
  if (
    probe.kind === "loaded-engine-descriptor" &&
    contextId === "javascript.package-property-read-loaded" &&
    !new Set(["descriptor", "fixture", "read"]).has(exercise)
  ) {
    throw new Error(
      `${label}: property-read context cannot be satisfied by a call fixture`,
    );
  }
  if (
    new Set([
      "host.private-native-call-initialized",
      "javascript.package-callback-loaded",
      "javascript.package-module-load",
      "runtime.bootstrap-native-call-loaded",
    ]).has(contextId) &&
    !new Set([
      "compiled-runtime-return-record",
      "loaded-engine-return-record",
    ]).has(probe.kind) &&
    !(probe.kind === "loaded-engine-descriptor" && exercise === "unexercisable")
  ) {
    throw new Error(`${label}: ${contextId} requires an exact return record`);
  }
}

/**
 * Select the independently executable proof family for a catalog row. Runtime
 * builtin/global values are inspected in the loaded realm and structured
 * rows are exercised through authored fixtures. Compiled registrar presence
 * is surface-account provenance only and is never selected for a value row.
 */
export function outputShapeProbeKindForCatalogRow(
  catalogRow,
  sourceSurface,
  {
    coverageEdge,
    target,
    closedControlInvocation,
    compiledRuntimeInvocation,
    rootGlobalClosed,
  } = {},
) {
  if (
    catalogRow?.discovery?.kind === "source-inventory-surface" &&
    catalogRow?.key?.sourceKind === "callback"
  ) {
    return "loaded-engine-descriptor";
  }
  if (catalogRow?.key?.alias === SAFE_THROW_METADATA_ALIAS) {
    return "loaded-engine-return-record";
  }
  if (
    coverageEdge?.classification === "effects" &&
    catalogRow?.discovery?.kind === "source-inventory-surface" &&
    catalogRow?.key?.sourceKind === "builtin" &&
    catalogRow?.key?.output === "[[return]]" &&
    isBuiltinEffectsOutputTargetSurface(sourceSurface)
  ) {
    return "loaded-engine-return-record";
  }
  if (closedControlInvocation) {
    return "loaded-engine-return-record";
  }
  if (compiledRuntimeInvocation) {
    return "compiled-runtime-return-record";
  }
  if (
    catalogRow?.discovery?.kind === "source-inventory-surface" &&
    catalogRow?.key?.sourceKind === "native-op" &&
    catalogRow?.key?.output === "[[return]]" &&
    !Object.hasOwn(DESCRIPTOR_EXERCISES, catalogRow.key.alias) &&
    authoredGlobalCallableOutputInvocation({
      surface: sourceSurface,
      coverageEdge,
    })
  ) {
    return "loaded-engine-return-record";
  }
  if (catalogRow?.discovery?.kind === STRUCTURED_DISCOVERY_KIND) {
    return "loaded-engine-return-record";
  }
  if (
    coverageEdge?.classification === "non-capability" &&
    catalogRow?.discovery?.kind === "source-inventory-surface" &&
    catalogRow?.key?.sourceKind === "builtin" &&
    catalogRow?.key?.output === "[[return]]" &&
    authoredNonCapabilityBuiltinOutputInvocation({
      surface: sourceSurface,
      target,
    })
  ) {
    return "loaded-engine-return-record";
  }
  // A closed accessor must be proved through the public loaded realm, not
  // declared unexercisable from its reviewed classification. A descriptor
  // route with an actual read records the target's real absent/return/throw
  // outcome without constructing an otherwise unreachable branded receiver.
  if (
    (coverageEdge?.classification === "closed" || rootGlobalClosed === true) &&
    catalogRow?.discovery?.kind === "source-inventory-surface" &&
    catalogRow?.key?.sourceKind === "native-op" &&
    catalogRow?.key?.output === "[[value]]" &&
    sourceSurface?.metadata?.surfaceType === "global-api" &&
    sourceSurface?.metadata?.valueShape === "accessor"
  ) {
    return "loaded-engine-descriptor";
  }
  if (
    catalogRow?.discovery?.kind === "source-inventory-surface" &&
    catalogRow?.key?.sourceKind === "native-op" &&
    catalogRow?.key?.output === "[[value]]" &&
    sourceSurface?.metadata?.sourceKey === "shared_runtime" &&
    sourceSurface?.metadata?.publicReadAccessSourceProven !== true &&
    !Object.hasOwn(DESCRIPTOR_EXERCISES, catalogRow.key.alias) &&
    authoredGlobalAccessorOutputInvocation({
      surface: sourceSurface,
      coverageEdge,
    })
  ) {
    return "loaded-engine-return-record";
  }
  if (
    catalogRow?.discovery?.kind === "source-inventory-surface" &&
    (catalogRow.key?.sourceKind === "builtin" ||
      (catalogRow.key?.sourceKind === "native-op" &&
        (catalogRow.key?.alias?.startsWith("global:") ||
          sourceSurface?.metadata?.surfaceType === "global-api")))
  ) {
    const exercise = DESCRIPTOR_EXERCISES[catalogRow.key?.alias] ?? {
      kind: "descriptor",
    };
    if (
      catalogRow.key.output === "[[return]]" &&
      exercise.kind === "descriptor" &&
      new Set(["callable", "accessor"]).has(sourceSurface?.metadata?.valueShape)
    ) {
      return "loaded-engine-descriptor";
    }
    return "loaded-engine-descriptor";
  }
  if (
    catalogRow?.discovery?.kind === "source-inventory-surface" &&
    catalogRow?.key?.output === "[[value]]" &&
    new Set(["builtin", "native-op"]).has(catalogRow.key.sourceKind)
  ) {
    return "loaded-engine-descriptor";
  }
  throw new Error(
    `${catalogRow?.key?.surfaceId ?? "unknown surface"}: retained value row has no live proof route`,
  );
}

// These are execution inputs, not expected outputs. Each entry names the
// smallest deterministic call/fixture needed to observe a path-bearing value
// rather than merely observing that the callable is installed.
const DESCRIPTOR_EXERCISES = Object.freeze({
  "export:exact_process:cwd": Object.freeze({ kind: "call", arguments: [] }),
  "export:node_fs:Dir.path": Object.freeze({
    kind: "fixture",
    fixture: "open-project-directory-path",
  }),
  "export:node_fs_promises:realpath": Object.freeze({
    kind: "call",
    arguments: ["/project"],
  }),
  "export:node_fs:realpath": Object.freeze({
    kind: "call",
    arguments: ["/project"],
  }),
  "export:node_fs:realpathSync": Object.freeze({
    kind: "call",
    arguments: ["/project"],
  }),
  "export:node_os:homedir": Object.freeze({ kind: "call", arguments: [] }),
  "export:node_os:devNull": Object.freeze({ kind: "read" }),
  "export:node_os:tmpdir": Object.freeze({ kind: "call", arguments: [] }),
  "export:node_path:relative": Object.freeze({
    kind: "call",
    arguments: ["/project/a", "/project/b"],
  }),
  "export:node_path:resolve": Object.freeze({
    kind: "call",
    arguments: ["output-shape"],
  }),
  "export:node_url:fileURLToPath": Object.freeze({
    kind: "call",
    arguments: ["file:///project/output-shape.js"],
  }),
  "export:node_url:pathToFileURL": Object.freeze({
    kind: "call",
    arguments: ["/project/output-shape.js"],
  }),
  "global:AsyncFunction": Object.freeze({
    kind: "construct",
    arguments: ["return 1"],
  }),
  "global:Bun.fileURLToPath": Object.freeze({
    kind: "call",
    arguments: ["file:///project/output-shape.js"],
  }),
  "global:Bun.pathToFileURL": Object.freeze({
    kind: "call",
    arguments: ["/project/output-shape.js"],
  }),
  "global:Bun.resolve": Object.freeze({
    kind: "call",
    arguments: ["./output-shape.js", "/project/entry.js"],
  }),
  "global:Bun.resolveSync": Object.freeze({
    kind: "call",
    arguments: ["./output-shape.js", "/project/entry.js"],
  }),
  "global:Bun.which": Object.freeze({
    kind: "call",
    arguments: ["ibex-output-shape-nonexistent"],
  }),
  "global:Exact.fileURLToPath": Object.freeze({
    kind: "call",
    arguments: ["file:///project/output-shape.js"],
  }),
  "global:Exact.pathToFileURL": Object.freeze({
    kind: "call",
    arguments: ["/project/output-shape.js"],
  }),
  "global:Exact.resolve": Object.freeze({
    kind: "call",
    arguments: ["./output-shape.js", "/project/entry.js"],
  }),
  "global:Exact.resolveSync": Object.freeze({
    kind: "call",
    arguments: ["./output-shape.js", "/project/entry.js"],
  }),
  "global:Exact.which": Object.freeze({
    kind: "call",
    arguments: ["ibex-output-shape-nonexistent"],
  }),
  "global:process.cwd": Object.freeze({ kind: "call", arguments: [] }),
  "global:process.argv0": Object.freeze({ kind: "read" }),
  "global:process.execPath": Object.freeze({ kind: "read" }),
});

function stableFixtureId(parts) {
  const hash = crypto.createHash("sha256");
  hash.update("ibex:capsec:output-shape-fixture:1", "utf8");
  hash.update(Buffer.from([0]));
  hash.update(canonicalJson(parts), "utf8");
  return `output-shape-${hash.digest("base64url").slice(0, 22)}`;
}

function sourceSurfaceMap(surfaces) {
  const rows = Array.isArray(surfaces) ? surfaces : surfaces?.surfaces;
  if (!Array.isArray(rows)) {
    throw new Error("output-shape probes require the live source inventory");
  }
  const byKindAndName = new Map();
  for (const row of rows) {
    const key = `${row.kind}:${row.name}`;
    if (byKindAndName.has(key)) {
      throw new Error(`live source inventory duplicates ${key}`);
    }
    byKindAndName.set(key, row);
  }
  return byKindAndName;
}

function coverageEdgeMap(coverage) {
  if (!Array.isArray(coverage?.edges)) {
    throw new Error(
      "output-shape probes require source-derived coverage edges",
    );
  }
  const byId = new Map();
  for (const edge of coverage.edges) {
    if (byId.has(edge.id)) throw new Error(`coverage duplicates ${edge.id}`);
    byId.set(edge.id, edge);
  }
  return byId;
}

function descriptorSourceRoute(
  row,
  surface,
  coverageEdge,
  rootGlobalClosed = false,
) {
  if (row.key.sourceKind === "callback") {
    if (
      surface.kind !== "callback" ||
      surface.metadata?.callbackOutputContractSchema !==
        CALLBACK_OUTPUT_CONTRACT_SCHEMA ||
      !Array.isArray(surface.metadata?.callbackOutputContracts)
    ) {
      throw new Error(
        `${row.key.surfaceId}: callback output has no source-bound contract`,
      );
    }
    const matching = surface.metadata.callbackOutputContracts.filter(
      (contract) =>
        contract?.selector === row.key.output &&
        contract?.returnVariant === row.key.returnVariant,
    );
    if (matching.length !== 1) {
      throw new Error(
        `${row.key.surfaceId}: callback output contract selection is not exact`,
      );
    }
    const selectedOutput = matching[0];
    exactKeys(
      selectedOutput,
      [
        "direction",
        "returnVariant",
        "role",
        "selector",
        "sourceRefs",
        "valueShape",
      ],
      `${row.key.surfaceId}.callbackOutputContract`,
    );
    if (
      !Array.isArray(selectedOutput.sourceRefs) ||
      selectedOutput.sourceRefs.length === 0 ||
      typeof selectedOutput.selector !== "string" ||
      !/^callback:[A-Za-z_$][A-Za-z0-9_$-]*\/(?:[0-9]+|return)$/u.test(
        selectedOutput.selector,
      ) ||
      typeof selectedOutput.returnVariant !== "string" ||
      !/^[a-z][a-z0-9-]*$/u.test(selectedOutput.returnVariant) ||
      !CALLBACK_OUTPUT_DIRECTIONS.has(selectedOutput.direction) ||
      !CALLBACK_OUTPUT_ROLES.has(selectedOutput.role) ||
      !CALLBACK_OUTPUT_VALUE_SHAPES.has(selectedOutput.valueShape) ||
      canonicalJson(selectedOutput.sourceRefs) !==
        canonicalJson(
          [...new Set(selectedOutput.sourceRefs)].sort(compareText),
        ) ||
      !selectedOutput.sourceRefs.every((sourceRef) =>
        surface.sourceRefs?.includes(sourceRef),
      ) ||
      canonicalJson(selectedOutput.sourceRefs) !==
        canonicalJson(row.discovery.sourceRefs)
    ) {
      throw new Error(
        `${row.key.surfaceId}: callback output contract does not match catalog discovery`,
      );
    }
    const platformSurface =
      surface.name.startsWith("ios-") ||
      surface.name.startsWith("android-") ||
      surface.name.startsWith("worklet-");
    const reasonCode =
      surface.name === "exact-host-call-async-resolve"
        ? "exact-host-callback-probe-not-output-sweep-adapted"
        : platformSurface
          ? "platform-callback-output-has-no-bound-live-fixture"
          : "callback-output-has-no-bound-live-fixture";
    return {
      kind: "callback-output",
      surfaceName: surface.name,
      callbackOutputContractSchema: CALLBACK_OUTPUT_CONTRACT_SCHEMA,
      selectedOutput: structuredClone(selectedOutput),
      contextId: row.key.contextId,
      observedKeys: structuredClone(row.discovery.observedKeys),
      sourceRefs: structuredClone(row.discovery.sourceRefs),
      exercise: {
        kind: "unexercisable",
        reasonCode,
      },
    };
  }
  const authoredExercise = DESCRIPTOR_EXERCISES[row.key.alias];
  const invocationContext = new Set([
    "host.private-native-call-initialized",
    "javascript.package-call-loaded",
    "javascript.package-callback-loaded",
    "javascript.package-module-load",
    "runtime.bootstrap-native-call-loaded",
  ]).has(row.key.contextId);
  const exercise =
    (coverageEdge?.classification === "closed" || rootGlobalClosed) &&
    surface.metadata?.valueShape === "accessor"
      ? { kind: "read" }
      : ((row.key.output === "[[value]]" && authoredExercise?.kind === "call"
          ? { kind: "descriptor" }
          : authoredExercise) ??
        (row.key.output === "[[return]]" && invocationContext
          ? {
              kind: "unexercisable",
              reasonCode: "missing-authored-live-invocation",
            }
          : { kind: "descriptor" }));
  const common = {
    contextId: row.key.contextId,
    observedKeys: structuredClone(row.discovery.observedKeys),
    sourceRefs: structuredClone(row.discovery.sourceRefs),
    exercise: structuredClone(exercise),
  };
  if (row.key.sourceKind === "builtin") {
    if (surface.metadata?.surfaceType !== "export") {
      return {
        kind: "builtin-root",
        moduleSpecifiers: [surface.name],
        valueShape: surface.metadata?.valueShape ?? "unknown",
        ...common,
      };
    }
    const publicModuleSpecifiers = surface.metadata?.publicModuleSpecifiers;
    const moduleSpecifiers =
      Array.isArray(publicModuleSpecifiers) && publicModuleSpecifiers.length > 0
        ? publicModuleSpecifiers
        : surface.metadata?.moduleSpecifiers;
    if (!Array.isArray(moduleSpecifiers) || moduleSpecifiers.length === 0) {
      throw new Error(
        `${row.key.surfaceId}: builtin export has no source-proven module specifier`,
      );
    }
    return {
      kind: "builtin-export",
      moduleSpecifiers: [...moduleSpecifiers],
      exportName: nonEmptyString(
        surface.metadata.exportName,
        `${row.key.surfaceId}.exportName`,
      ),
      exportIdioms: [...(surface.metadata.exportIdioms ?? [])],
      inheritedShape: surface.metadata.inheritedShape === true,
      valueShape: surface.metadata.valueShape ?? "unknown",
      ...common,
    };
  }
  if (row.key.sourceKind === "native-op") {
    if (
      surface.metadata?.surfaceType !== "global-api" ||
      typeof surface.metadata?.globalName !== "string"
    ) {
      throw new Error(
        `${row.key.surfaceId}: native global has no live global-api descriptor`,
      );
    }
    return {
      kind: "global-api",
      globalName: surface.metadata.globalName,
      memberName: surface.metadata.memberName ?? null,
      memberKinds: [...(surface.metadata.memberKinds ?? [])],
      valueShape: surface.metadata.valueShape ?? "unknown",
      ...common,
    };
  }
  throw new Error(`${row.key.surfaceId}: unsupported descriptor source kind`);
}

function structuredSourceRoute(row, surface) {
  return {
    kind: "structured-output",
    surfaceName: surface.name,
    output: row.key.output,
    alias: row.key.alias,
    mode: row.key.mode,
    sourceKind: row.key.sourceKind,
    returnVariant: row.key.returnVariant,
    contextId: row.key.contextId,
    sourceRefs: structuredClone(row.discovery.sourceRefs),
  };
}

/**
 * Author the executor routes from the live source inventory and coverage ids.
 * No disposition policy or reviewed expected value is accepted by this API.
 */
export function buildOutputShapeSweepProbes({
  catalog,
  surfaces,
  coverage,
  target,
}) {
  validateSweepCatalog(catalog, "output-shape probe catalog");
  const sources = sourceSurfaceMap(surfaces);
  const coverageById = coverageEdgeMap(coverage);
  const closedGlobalSurfaces = new Set(
    coverage.edges
      .filter(
        (edge) =>
          edge.classification === "closed" &&
          edge.surface?.kind === "native-op" &&
          typeof edge.surface?.name === "string",
      )
      .map((edge) => edge.surface.name),
  );
  return sortedRows(
    catalog.rows.map((row) => {
      const coverageEdge = coverageById.get(row.key.surfaceId);
      if (!coverageEdge) {
        throw new Error(
          `${row.key.surfaceId}: output row has no coverage surface`,
        );
      }
      const coverageSurface = coverageEdge.surface;
      const sourceSurface = sources.get(
        `${coverageSurface.kind}:${coverageSurface.name}`,
      );
      if (!sourceSurface) {
        throw new Error(
          `${row.key.surfaceId}: output row has no live source-inventory surface`,
        );
      }
      const rootGlobalClosed =
        sourceSurface.metadata?.surfaceType === "global-api" &&
        typeof sourceSurface.metadata?.globalName === "string" &&
        closedGlobalSurfaces.has(`global:${sourceSurface.metadata.globalName}`);
      const authoredBuiltinInvocation =
        coverageEdge.classification === "non-capability" &&
        row.discovery.kind === "source-inventory-surface" &&
        row.key.sourceKind === "builtin" &&
        row.key.output === "[[return]]"
          ? authoredNonCapabilityBuiltinOutputInvocation({
              surface: sourceSurface,
              target,
            })
          : null;
      const builtinEffectsCandidate =
        coverageEdge.classification === "effects" &&
        row.discovery.kind === "source-inventory-surface" &&
        row.key.sourceKind === "builtin" &&
        row.key.output === "[[return]]" &&
        isBuiltinEffectsOutputTargetSurface(sourceSurface);
      const authoredBuiltinEffectsProbe = builtinEffectsCandidate
        ? authoredBuiltinEffectsOutputProbe({
            catalogKey: row.key,
            coverage,
            coverageEdge,
            surface: sourceSurface,
            target,
          })
        : null;
      if (builtinEffectsCandidate && !authoredBuiltinEffectsProbe) {
        throw new Error(
          `${sourceSurface.observedKey}: missing exact builtin effects output route`,
        );
      }
      if (authoredBuiltinEffectsProbe) {
        return {
          key: structuredClone(row.key),
          probe: authoredBuiltinEffectsProbe,
        };
      }
      const authoredClosedControlInvocation =
        coverageEdge.classification === "closed" &&
        row.discovery.kind === "source-inventory-surface" &&
        row.key.output === "[[return]]" &&
        new Set(["cli", "startup", "loader"]).has(row.key.sourceKind)
          ? authoredClosedControlOutputInvocation({
              surface: sourceSurface,
              surfaces,
              coverageEdge,
              coverage,
            })
          : null;
      const authoredCompiledCliInvocation =
        authoredClosedControlInvocation === null &&
        row.discovery.kind === "source-inventory-surface" &&
        row.key.sourceKind === "cli" &&
        row.key.output === "[[return]]"
          ? authoredCliOutputInvocation({
              surface: sourceSurface,
              coverageEdge,
            })
          : null;
      const authoredNativeFreezeInvocation =
        row.discovery.kind === STRUCTURED_DISCOVERY_KIND &&
        row.key.sourceKind === "native-op" &&
        row.key.output === "[[return]]" &&
        new Set(["__exactDeepFreeze", "__exactNativeFreeze"]).has(row.key.alias)
          ? authoredNativeFreezeOutputInvocation({
              catalogRow: row,
              surface: sourceSurface,
              coverageEdge,
            })
          : null;
      const authoredGlobalAccessorInvocation =
        row.discovery.kind === "source-inventory-surface" &&
        row.key.sourceKind === "native-op" &&
        row.key.output === "[[value]]" &&
        sourceSurface.metadata?.sourceKey === "shared_runtime" &&
        sourceSurface.metadata?.publicReadAccessSourceProven !== true &&
        coverageEdge.classification !== "closed" &&
        !rootGlobalClosed &&
        !Object.hasOwn(DESCRIPTOR_EXERCISES, row.key.alias)
          ? authoredGlobalAccessorOutputInvocation({
              surface: sourceSurface,
              coverageEdge,
            })
          : null;
      const authoredGlobalCallableInvocation =
        row.discovery.kind === "source-inventory-surface" &&
        row.key.sourceKind === "native-op" &&
        row.key.output === "[[return]]" &&
        !Object.hasOwn(DESCRIPTOR_EXERCISES, row.key.alias)
          ? authoredGlobalCallableOutputInvocation({
              surface: sourceSurface,
              coverageEdge,
            })
          : null;
      const genericKind = outputShapeProbeKindForCatalogRow(
        row,
        sourceSurface,
        {
          coverageEdge,
          target,
          closedControlInvocation: authoredClosedControlInvocation,
          compiledRuntimeInvocation: authoredCompiledCliInvocation,
          rootGlobalClosed,
        },
      );
      const builtinNoncapClosedCandidate =
        row.discovery.kind === "source-inventory-surface" &&
        row.key.sourceKind === "builtin" &&
        row.key.output === "[[return]]" &&
        new Set(["non-capability", "closed"]).has(
          coverageEdge.classification,
        ) &&
        genericKind === "loaded-engine-descriptor";
      const authoredBuiltinNoncapClosedProbe = builtinNoncapClosedCandidate
        ? authoredBuiltinNoncapClosedOutputProbe({
            catalogKey: row.key,
            coverageEdge,
            surface: sourceSurface,
            target,
          })
        : null;
      if (authoredBuiltinNoncapClosedProbe) {
        return {
          key: structuredClone(row.key),
          probe: authoredBuiltinNoncapClosedProbe,
        };
      }
      const kind = genericKind;
      const sourceDescriptor =
        row.key.alias === SAFE_THROW_METADATA_ALIAS
          ? {
              kind: "native-abi-fixture",
              symbol: SAFE_THROW_METADATA_ALIAS,
              variant: "rooted-error",
            }
          : authoredNativeFreezeInvocation
            ? {
                kind: NATIVE_FREEZE_OUTPUT_SOURCE_DESCRIPTOR_KIND,
                surfaceObservedKey: sourceSurface.observedKey,
                invocation: authoredNativeFreezeInvocation,
              }
            : authoredBuiltinInvocation
              ? {
                  kind: "authored-public-builtin-invocation",
                  surfaceObservedKey: sourceSurface.observedKey,
                  invocation: authoredBuiltinInvocation,
                }
              : authoredClosedControlInvocation
                ? {
                    kind: "authored-closed-control-output",
                    surfaceObservedKey: sourceSurface.observedKey,
                    invocation: authoredClosedControlInvocation,
                  }
                : authoredCompiledCliInvocation
                  ? {
                      kind: "authored-cli-output",
                      surfaceObservedKey: sourceSurface.observedKey,
                      invocation: authoredCompiledCliInvocation,
                    }
                  : authoredGlobalAccessorInvocation
                    ? {
                        kind: "authored-global-accessor-get",
                        surfaceObservedKey: sourceSurface.observedKey,
                        invocation: authoredGlobalAccessorInvocation,
                      }
                    : authoredGlobalCallableInvocation
                      ? {
                          kind: "authored-global-callable-invocation",
                          surfaceObservedKey: sourceSurface.observedKey,
                          invocation: authoredGlobalCallableInvocation,
                        }
                      : kind === "loaded-engine-descriptor"
                        ? descriptorSourceRoute(
                            row,
                            sourceSurface,
                            coverageEdge,
                            rootGlobalClosed,
                          )
                        : structuredSourceRoute(row, sourceSurface);
      const sourceDescriptorDigest =
        outputShapeSourceDescriptorDigest(sourceDescriptor);
      if (kind === "loaded-engine-descriptor") {
        return {
          key: structuredClone(row.key),
          probe: { kind, sourceDescriptor, sourceDescriptorDigest },
        };
      }
      return {
        key: structuredClone(row.key),
        probe: {
          kind,
          fixtureId:
            row.key.alias === SAFE_THROW_METADATA_ALIAS
              ? "safe-throw-metadata"
              : stableFixtureId([
                  row.key.surfaceId,
                  row.key.mode,
                  row.key.sourceKind,
                  row.key.returnVariant,
                  row.key.contextId,
                  sourceDescriptorDigest,
                ]),
          sourceDescriptor,
          sourceDescriptorDigest,
          recordPath:
            row.key.alias === SAFE_THROW_METADATA_ALIAS ||
            authoredNativeFreezeInvocation ||
            authoredBuiltinInvocation ||
            authoredClosedControlInvocation ||
            authoredCompiledCliInvocation ||
            authoredGlobalAccessorInvocation ||
            authoredGlobalCallableInvocation
              ? ["[[return]]"]
              : ["outputs", canonicalOutputDispositionKey(row.key)],
        },
      };
    }),
  );
}

function projectGenericOutputShapeCatalog(catalog, coverage) {
  validateSweepCatalog(catalog, "complete output-shape execution catalog");
  const coverageById = coverageEdgeMap(coverage);
  const hostAbiSurfaceIds = new Set();
  for (const edge of coverageById.values()) {
    if (edge.surface?.kind === "host-abi") hostAbiSurfaceIds.add(edge.id);
  }

  for (const row of catalog.rows) {
    const edge = coverageById.get(row.key.surfaceId);
    if (!edge) {
      throw new Error(
        `${row.key.surfaceId}: output row has no coverage surface during execution partitioning`,
      );
    }
    if (
      (row.key.sourceKind === "host-abi") !==
      (edge.surface?.kind === "host-abi")
    ) {
      throw new Error(
        `${row.key.surfaceId}: Host ABI source kind and coverage kind disagree`,
      );
    }
  }

  const rows = catalog.rows.filter((row) => row.key.sourceKind !== "host-abi");
  const surfaceAccounts = catalog.surfaceAccounts.filter((account) => {
    if (!coverageById.has(account.surfaceId)) {
      throw new Error(
        `${account.surfaceId}: output account has no coverage surface during execution partitioning`,
      );
    }
    return !hostAbiSurfaceIds.has(account.surfaceId);
  });
  const parameterizedOutputBindings =
    catalog.parameterizedOutputBindings.filter(
      (binding) => !hostAbiSurfaceIds.has(binding.surfaceId),
    );
  const accountCounts = validateOutputShapeCatalogAccounts({
    surfaceAccounts,
    rows,
    parameterizedOutputBindings,
    promotionStatus: catalog.discovery.status,
  });
  const projected = {
    outputShapeCatalogSchema: catalog.outputShapeCatalogSchema,
    profile: catalog.profile,
    discovery: structuredClone(catalog.discovery),
    contexts: outputExecutionContextsForRows(rows),
    surfaceAccounts: structuredClone(surfaceAccounts),
    parameterizedOutputBindings: structuredClone(parameterizedOutputBindings),
    parameterizedBindingDigest: outputParameterizedBindingDigest(
      parameterizedOutputBindings,
    ),
    catalogKeyDigest: outputShapeCatalogKeyDigest(rows),
    counts: {
      coverageSurfaces: surfaceAccounts.length,
      outputBearingSurfaces: accountCounts["output-bearing"],
      structuralOnlySurfaces: accountCounts["structural-only"],
      unresolvedSurfaces: accountCounts.unresolved,
      catalogRows: rows.length,
      parameterizedBindings: parameterizedOutputBindings.length,
      sourceInventoryRows: rows.filter(
        (row) => row.discovery?.kind === "source-inventory-surface",
      ).length,
      structuredRows: rows.filter(
        (row) => row.discovery?.kind === STRUCTURED_DISCOVERY_KIND,
      ).length,
    },
    rows: structuredClone(rows),
  };
  return validateSweepCatalog(
    projected,
    "generic output-shape execution catalog",
  );
}

/**
 * Split the complete output catalog at the production executor boundary.
 * Host-ABI rows retain their dedicated native author (including exact
 * target-absence preemption); only the remaining rows enter the loaded-JS
 * sweep. The returned key sets are checked bidirectionally against the full
 * catalog so delegation cannot silently drop or duplicate a value row.
 */
export function buildOutputShapeSweepExecutionPartition({
  catalog,
  coverage,
  surfaces,
  target,
  targetAbsenceBindings = [],
}) {
  if (
    !Array.isArray(targetAbsenceBindings) ||
    targetAbsenceBindings.some(
      (binding) => binding?.key?.sourceKind !== "host-abi",
    )
  ) {
    throw new Error(
      "output-shape execution partition requires only exact Host ABI target-absence bindings",
    );
  }
  const hostAbi = buildHostAbiOutputProbePartition({
    catalog,
    coverage,
    surfaces,
    targetAbsenceBindings,
  });
  const genericCatalog = projectGenericOutputShapeCatalog(catalog, coverage);
  const genericProbes = buildOutputShapeSweepProbes({
    catalog: genericCatalog,
    coverage,
    surfaces,
    target,
  });
  assertBidirectionalKeys(
    catalog.rows,
    [
      ...genericCatalog.rows,
      ...hostAbi.targetAbsenceBindings,
      ...hostAbi.rows,
      ...hostAbi.residuals,
    ],
    "output-shape production execution partition",
  );
  return {
    outputShapeExecutionPartitionSchema: EXECUTION_PARTITION_SCHEMA,
    completeCatalogKeyDigest: catalog.catalogKeyDigest,
    genericCatalog,
    genericProbes,
    hostAbi,
  };
}

/**
 * Turn exact Host-ABI target-absence recipe bindings into ordinary sweep
 * probes. The plan retains the complete authored public probe, but never the
 * reviewed output expectation or a claimed runtime result.
 */
export function buildTargetAbsenceOutputShapeProbes({
  targetAbsenceBindings,
  recipeCatalog,
  target,
}) {
  if (
    !Array.isArray(targetAbsenceBindings) ||
    !Array.isArray(recipeCatalog?.recipes) ||
    !DIGEST_PATTERN.test(recipeCatalog?.recipeCatalogDigest ?? "")
  ) {
    throw new Error(
      "target-absence output probes require exact bindings and a digested recipe catalog",
    );
  }
  exactTarget(target, "target-absence output target");
  if (canonicalJson(recipeCatalog.target) !== canonicalJson(target)) {
    throw new Error(
      "target-absence output recipe catalog targets another candidate cell",
    );
  }
  const recipes = new Map();
  for (const recipe of recipeCatalog.recipes) {
    if (
      typeof recipe?.fixtureId !== "string" ||
      recipe.fixtureId.length === 0 ||
      recipes.has(recipe.fixtureId)
    ) {
      throw new Error("target-absence recipe fixture IDs are not unique");
    }
    recipes.set(recipe.fixtureId, recipe);
  }
  const probes = targetAbsenceBindings.map((binding, index) => {
    exactKeys(
      binding,
      [
        "key",
        "fixtureId",
        "planDigest",
        "terminalObservedKey",
        "invocationSchema",
        "sourceDescriptorDigest",
      ],
      `target-absence output binding ${index}`,
    );
    canonicalOutputDispositionKey(
      binding.key,
      `target-absence output binding ${index}.key`,
    );
    const recipe = recipes.get(binding.fixtureId);
    const publicProbe = recipe?.publicSurfaceProbe;
    const invocation = publicProbe?.invocation;
    if (
      binding.key.sourceKind !== "host-abi" ||
      !recipe ||
      recipe.status !== "fully-executable" ||
      recipe.scenario !== "absent" ||
      recipe.planDigest !== binding.planDigest ||
      recipe.terminalObservedKey !== binding.terminalObservedKey ||
      !DIGEST_PATTERN.test(binding.planDigest ?? "") ||
      !DIGEST_PATTERN.test(binding.sourceDescriptorDigest ?? "") ||
      publicProbe?.kind !== "target-absence-probe" ||
      publicProbe.surfaceObservedKey !== binding.terminalObservedKey ||
      invocation?.invocationSchema !== binding.invocationSchema ||
      invocation.kind !== "target-absence" ||
      invocation.surfaceKind !== "host-abi" ||
      invocation.surfaceName !== binding.key.alias ||
      invocation.targetTriple !== target.triple ||
      invocation.sourceDescriptorDigest !== binding.sourceDescriptorDigest
    ) {
      throw new Error(
        `${binding.fixtureId}: target-absence output binding differs from its authored recipe`,
      );
    }
    const sourceDescriptor = {
      kind: TARGET_ABSENCE_OUTPUT_SOURCE_DESCRIPTOR_KIND,
      recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
      fixtureId: binding.fixtureId,
      recipePlanDigest: binding.planDigest,
      terminalObservedKey: binding.terminalObservedKey,
      invocationSchema: binding.invocationSchema,
      targetSourceDescriptorDigest: binding.sourceDescriptorDigest,
      publicSurfaceProbe: structuredClone(publicProbe),
    };
    const probe = {
      kind: "loaded-engine-return-record",
      fixtureId: binding.fixtureId,
      sourceDescriptor,
      sourceDescriptorDigest: outputShapeSourceDescriptorDigest(sourceDescriptor),
      recordPath: [...TARGET_ABSENCE_RECORD_PATH],
    };
    validateProbe(
      probe,
      binding.key,
      `target-absence output probe ${binding.fixtureId}`,
    );
    return { key: structuredClone(binding.key), probe };
  });
  uniqueKeyMap(probes, "target-absence output probes");
  return sortedRows(probes);
}

function sortedRows(rows) {
  return [...rows].sort((left, right) =>
    compareText(
      canonicalOutputDispositionKey(left.key),
      canonicalOutputDispositionKey(right.key),
    ),
  );
}

function uniqueKeyMap(rows, label) {
  if (!Array.isArray(rows)) throw new Error(`${label}: expected array`);
  const byKey = new Map();
  for (const [index, row] of rows.entries()) {
    if (!row || typeof row !== "object" || Array.isArray(row)) {
      throw new Error(`${label}[${index}]: expected object`);
    }
    const key = canonicalOutputDispositionKey(
      row.key,
      `${label}[${index}].key`,
    );
    if (byKey.has(key))
      throw new Error(`${label}: duplicate canonical output key ${key}`);
    byKey.set(key, row);
  }
  return byKey;
}

function assertBidirectionalKeys(expectedRows, actualRows, label) {
  const expected = uniqueKeyMap(expectedRows, `${label} expected rows`);
  const actual = uniqueKeyMap(actualRows, `${label} actual rows`);
  const missing = [...expected.keys()].filter((key) => !actual.has(key));
  const unknown = [...actual.keys()].filter((key) => !expected.has(key));
  if (missing.length || unknown.length) {
    throw new Error(
      `${label} is not bidirectional; missing=[${missing.slice(0, 8).join(", ")}] unknown=[${unknown.slice(0, 8).join(", ")}]`,
    );
  }
  return { expected, actual };
}

function assertCanonicalRowOrder(rows, label) {
  const actual = rows.map((row) => canonicalOutputDispositionKey(row.key));
  const expected = [...actual].sort(compareText);
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new Error(`${label}: rows are not in canonical output-key order`);
  }
}

function planDigest(plan) {
  return computeDomainDigest(PLAN_DIGEST_DOMAIN, plan, ["sweepPlanDigest"]);
}

function artifactDigest(artifact) {
  return computeDomainDigest(ARTIFACT_DIGEST_DOMAIN, artifact, [
    "sweepArtifactDigest",
  ]);
}

function validateSurfaceAccountIds(surfaceAccountIds, label) {
  if (
    !Array.isArray(surfaceAccountIds) ||
    surfaceAccountIds.some(
      (surfaceId) =>
        typeof surfaceId !== "string" ||
        !/^surface\.[a-z0-9.]+$/u.test(surfaceId),
    ) ||
    canonicalJson(surfaceAccountIds) !==
      canonicalJson([...new Set(surfaceAccountIds)].sort(compareText))
  ) {
    throw new Error(`${label}: expected canonical stable surface-account IDs`);
  }
  return surfaceAccountIds;
}

function validatePlanSelf(plan) {
  exactKeys(
    plan,
    [
      "outputShapeSweepPlanSchema",
      "profile",
      "executor",
      "sourceRevision",
      "sourceTreeDigest",
      "target",
      "engine",
      "catalogKeyDigest",
      "parameterizedBindingDigest",
      "parameterizedEnvironment",
      "surfaceAccountIds",
      "rows",
      "sweepPlanDigest",
    ],
    "output-shape sweep plan",
  );
  assertBindingInputs(plan, "output-shape sweep plan");
  if (
    plan.outputShapeSweepPlanSchema !== PLAN_SCHEMA ||
    plan.profile !== PROFILE ||
    plan.executor !== OUTPUT_SHAPE_SWEEP_EXECUTOR ||
    !Array.isArray(plan.rows) ||
    plan.catalogKeyDigest !== outputShapeCatalogKeyDigest(plan.rows) ||
    plan.parameterizedBindingDigest !==
      outputParameterizedBindingDigest(
        plan.parameterizedEnvironment.map(
          ({ catalogBinding }) => catalogBinding,
        ),
      ) ||
    plan.sweepPlanDigest !== planDigest(plan)
  ) {
    throw new Error("output-shape sweep plan has stale or mismatched bindings");
  }
  validateSurfaceAccountIds(
    plan.surfaceAccountIds,
    "output-shape sweep plan.surfaceAccountIds",
  );
  if (!Array.isArray(plan.parameterizedEnvironment)) {
    throw new Error(
      "output-shape sweep plan.parameterizedEnvironment must be an array",
    );
  }
  for (const [index, entry] of plan.parameterizedEnvironment.entries()) {
    exactKeys(
      entry,
      ["catalogBinding", "sweepBinding"],
      `output-shape sweep plan.parameterizedEnvironment[${index}]`,
    );
  }
  validateEnvironmentOutputSweepBindings(
    plan.parameterizedEnvironment.map(({ sweepBinding }) => sweepBinding),
    plan.parameterizedEnvironment.map(({ catalogBinding }) => catalogBinding),
  );
  const rowsByKey = uniqueKeyMap(plan.rows, "output-shape sweep plan rows");
  assertCanonicalRowOrder(plan.rows, "output-shape sweep plan");
  for (const [canonicalKey, row] of rowsByKey) {
    exactKeys(row, ["key", "probe"], `plan row ${canonicalKey}`);
    validateProbe(row.probe, row.key, `plan row ${canonicalKey}.probe`);
  }
  return plan;
}

/**
 * Construct a source/engine-bound plan from independently-authored probe
 * routes. `probes` must contain exactly one route for every catalog key.
 */
export function buildOutputShapeSweepPlan({
  catalog,
  sourceRevision,
  sourceTreeDigest,
  target,
  engine,
  probes,
}) {
  assertBindingInputs(
    { sourceRevision, sourceTreeDigest, target, engine },
    "sweep plan",
  );
  validateSweepCatalog(catalog, "output-shape sweep plan catalog");
  const { actual: probesByKey } = assertBidirectionalKeys(
    catalog.rows,
    probes,
    "output-shape sweep probes",
  );
  const rows = sortedRows(
    catalog.rows.map((catalogRow) => {
      const canonicalKey = canonicalOutputDispositionKey(catalogRow.key);
      const route = probesByKey.get(canonicalKey);
      exactKeys(route, ["key", "probe"], `probe ${canonicalKey}`);
      validateProbe(route.probe, catalogRow.key, `probe ${canonicalKey}.probe`);
      validateCatalogProbeMechanism(
        catalogRow,
        route.probe,
        `probe ${canonicalKey}.probe`,
      );
      return {
        key: structuredClone(catalogRow.key),
        probe: structuredClone(route.probe),
      };
    }),
  );
  const environmentSweepBindings = buildEnvironmentOutputSweepBindings(
    catalog.parameterizedOutputBindings,
  );
  const plan = {
    outputShapeSweepPlanSchema: PLAN_SCHEMA,
    profile: PROFILE,
    executor: OUTPUT_SHAPE_SWEEP_EXECUTOR,
    sourceRevision,
    sourceTreeDigest,
    target: structuredClone(target),
    engine: structuredClone(engine),
    catalogKeyDigest: catalog.catalogKeyDigest,
    parameterizedBindingDigest: catalog.parameterizedBindingDigest,
    parameterizedEnvironment: catalog.parameterizedOutputBindings.map(
      (catalogBinding, index) => ({
        catalogBinding: structuredClone(catalogBinding),
        sweepBinding: structuredClone(environmentSweepBindings[index]),
      }),
    ),
    surfaceAccountIds: catalogSurfaceAccountIds(catalog),
    rows,
  };
  plan.sweepPlanDigest = planDigest(plan);
  return plan;
}

export function validateOutputShapeSweepPlan(
  plan,
  { catalog, sourceRevision, sourceTreeDigest, target, engine },
) {
  validatePlanSelf(plan);
  validateSweepCatalog(catalog, "output-shape sweep validation catalog");
  if (
    plan.sourceRevision !== sourceRevision ||
    plan.sourceTreeDigest !== sourceTreeDigest ||
    canonicalJson(plan.target) !== canonicalJson(target) ||
    canonicalJson(plan.engine) !== canonicalJson(engine) ||
    plan.catalogKeyDigest !== catalog.catalogKeyDigest ||
    plan.parameterizedBindingDigest !== catalog.parameterizedBindingDigest ||
    canonicalJson(
      plan.parameterizedEnvironment.map(({ catalogBinding }) => catalogBinding),
    ) !== canonicalJson(catalog.parameterizedOutputBindings) ||
    plan.catalogKeyDigest !== outputShapeCatalogKeyDigest(catalog.rows) ||
    canonicalJson(plan.surfaceAccountIds) !==
      canonicalJson(catalogSurfaceAccountIds(catalog))
  ) {
    throw new Error("output-shape sweep plan has stale or mismatched bindings");
  }
  const { expected: catalogByKey, actual: planByKey } = assertBidirectionalKeys(
    catalog.rows,
    plan.rows,
    "output-shape sweep plan rows",
  );
  for (const [canonicalKey, row] of planByKey) {
    validateCatalogProbeMechanism(
      catalogByKey.get(canonicalKey),
      row.probe,
      `plan row ${canonicalKey}.probe`,
    );
  }
  return plan;
}

function validateNormalizedObservation(observation, label) {
  exactKeys(observation, ["outcome", "normalizedValue"], label);
  if (!OUTCOMES.has(observation.outcome)) {
    throw new Error(`${label}.outcome: unsupported normalized outcome`);
  }
  nonEmptyString(observation.normalizedValue, `${label}.normalizedValue`);
}

function validateDescriptorObservation(descriptor, label) {
  exactKeys(
    descriptor,
    [
      "presence",
      "descriptorKind",
      "valueType",
      "enumerable",
      "configurable",
      "writable",
      "hasGetter",
      "hasSetter",
    ],
    label,
  );
  if (!["absent", "own", "inherited"].includes(descriptor.presence)) {
    throw new Error(`${label}.presence: unsupported descriptor presence`);
  }
  if (!["absent", "data", "accessor"].includes(descriptor.descriptorKind)) {
    throw new Error(`${label}.descriptorKind: unsupported descriptor kind`);
  }
  if (![...VALUE_TYPES, "unread"].includes(descriptor.valueType)) {
    throw new Error(`${label}.valueType: unsupported JavaScript value type`);
  }
  for (const field of [
    "enumerable",
    "configurable",
    "writable",
    "hasGetter",
    "hasSetter",
  ]) {
    if (descriptor[field] !== null && typeof descriptor[field] !== "boolean") {
      throw new Error(`${label}.${field}: expected boolean or null`);
    }
  }
  if (
    descriptor.presence === "absent" &&
    (descriptor.descriptorKind !== "absent" ||
      descriptor.valueType !== "unread")
  ) {
    throw new Error(`${label}: absent descriptors cannot claim a value shape`);
  }
}

function validateProof(proof, probe, key, label) {
  switch (probe.kind) {
    case "compiled-registrar":
      throw new Error(
        `${label}: compiled registrar presence is structural coverage, not a loaded-engine output observation`,
      );
    case "loaded-engine-descriptor":
      exactKeys(proof, ["kind", "sourceDescriptorDigest", "descriptor"], label);
      if (
        proof.kind !== probe.kind ||
        proof.sourceDescriptorDigest !== probe.sourceDescriptorDigest
      ) {
        throw new Error(
          `${label}: descriptor proof selected another source route`,
        );
      }
      validateDescriptorObservation(proof.descriptor, `${label}.descriptor`);
      if (
        key.output === "[[return]]" &&
        probe.sourceDescriptor.exercise?.kind === "descriptor" &&
        (proof.descriptor.valueType === "function" ||
          proof.descriptor.descriptorKind === "accessor")
      ) {
        throw new Error(
          `${label}: a default descriptor substituted property shape for an uninvoked output`,
        );
      }
      return;
    case "compiled-runtime-return-record":
    case "loaded-engine-return-record": {
      const builtinEffects =
        probe.sourceDescriptor?.kind ===
        BUILTIN_EFFECTS_OUTPUT_SOURCE_DESCRIPTOR_KIND;
      exactKeys(
        proof,
        [
          "kind",
          "fixtureId",
          "sourceDescriptorDigest",
          "recordPath",
          "rawValueShape",
          ...(builtinEffects
            ? ["effectEvidence", "fixtureSetupEvidence", "fixtureCleanup"]
            : []),
        ],
        label,
      );
      if (
        proof.kind !== probe.kind ||
        proof.fixtureId !== probe.fixtureId ||
        proof.sourceDescriptorDigest !== probe.sourceDescriptorDigest ||
        canonicalJson(proof.recordPath) !== canonicalJson(probe.recordPath) ||
        !RAW_VALUE_SHAPES.has(proof.rawValueShape)
      ) {
        throw new Error(
          `${label}: return-record proof selected another fixture or path`,
        );
      }
      if (builtinEffects) {
        const invocation = probe.sourceDescriptor.invocation;
        const binding = invocation.decisionEvidence;
        const evidence = proof.effectEvidence;
        exactKeys(
          evidence,
          ["kind", "carrierEdgeId", "branchId", "decisions", "noEffectBranch"],
          `${label}.effectEvidence`,
        );
        if (
          evidence.kind !== "coverage-bound-typed-effects" ||
          evidence.carrierEdgeId !== invocation.coverageEdgeId ||
          evidence.branchId !== `output-shape:${probe.fixtureId}` ||
          !Array.isArray(evidence.decisions)
        ) {
          throw new Error(
            `${label}: effect evidence lost its exact carrier or branch`,
          );
        }
        const routeByEdge = new Map(
          binding.typedRoutes.map((route) => [route.coverageEdgeId, route]),
        );
        for (const [decisionIndex, decision] of evidence.decisions.entries()) {
          const decisionLabel = `${label}.effectEvidence.decisions[${decisionIndex}]`;
          exactKeys(
            decision,
            ["coverageEdgeId", "actionIds", "stage"],
            decisionLabel,
          );
          const route = routeByEdge.get(decision.coverageEdgeId);
          const actionIds = Array.isArray(decision.actionIds)
            ? decision.actionIds
            : [];
          const allowedActions = [
            ...(route?.actionStages ?? []),
            ...(route?.internalObserverActionStages ?? []),
          ]
            .filter((action) => action.stages.includes(decision.stage))
            .map((action) => action.actionId)
            .filter(
              (actionId, index, values) => values.indexOf(actionId) === index,
            )
            .sort(compareText);
          if (
            !route ||
            typeof decision.stage !== "string" ||
            decision.stage.length === 0 ||
            actionIds.length === 0 ||
            !actionIds.every(
              (actionId) => typeof actionId === "string" && actionId.length > 0,
            ) ||
            canonicalJson(actionIds) !==
              canonicalJson([...new Set(actionIds)].sort(compareText)) ||
            !actionIds.every((actionId) => allowedActions.includes(actionId))
          ) {
            throw new Error(
              `${decisionLabel}: typed edge/action/stage drifted`,
            );
          }
        }
        const observedDecisionEdgeIds = new Set(
          evidence.decisions.map((decision) => decision.coverageEdgeId),
        );
        for (const requiredEdgeId of binding.requiredDecisionEdgeIds) {
          if (!observedDecisionEdgeIds.has(requiredEdgeId)) {
            throw new Error(
              `${label}: source operation omitted required typed edge ${requiredEdgeId}`,
            );
          }
        }
        if (binding.selectedNoEffectBranch === null) {
          if (
            evidence.decisions.length === 0 ||
            evidence.noEffectBranch !== null
          ) {
            throw new Error(
              `${label}: effect-classified output has no typed evidence`,
            );
          }
        } else if (
          evidence.decisions.length !== 0 ||
          canonicalJson(evidence.noEffectBranch) !==
            canonicalJson(binding.selectedNoEffectBranch)
        ) {
          throw new Error(
            `${label}: zero-decision output is not source-branch bound`,
          );
        }
        const setup = invocation.route.setup;
        const setupEvidence = proof.fixtureSetupEvidence;
        const fixtureCleanup = proof.fixtureCleanup;
        if (setup === null) {
          if (setupEvidence !== null || fixtureCleanup !== null) {
            throw new Error(
              `${label}: unconfigured route retained fixture proof`,
            );
          }
        } else {
          exactKeys(
            setupEvidence,
            [
              "kind",
              "carrierEdgeId",
              "branchId",
              "decisions",
              "noEffectBranch",
            ],
            `${label}.fixtureSetupEvidence`,
          );
          if (
            setupEvidence.kind !== "coverage-bound-fixture-setup-effects" ||
            setupEvidence.carrierEdgeId !== invocation.coverageEdgeId ||
            setupEvidence.branchId !==
              `output-shape:${probe.fixtureId}:fixture-setup` ||
            !Array.isArray(setupEvidence.decisions) ||
            setupEvidence.decisions.length === 0 ||
            setupEvidence.noEffectBranch !== null
          ) {
            throw new Error(`${label}: fixture setup evidence is not exact`);
          }
          const setupRouteByEdge = new Map(
            setup.decisionEvidence.typedRoutes.map((route) => [
              route.coverageEdgeId,
              route,
            ]),
          );
          for (const [
            decisionIndex,
            decision,
          ] of setupEvidence.decisions.entries()) {
            const decisionLabel = `${label}.fixtureSetupEvidence.decisions[${decisionIndex}]`;
            exactKeys(
              decision,
              ["coverageEdgeId", "actionIds", "stage"],
              decisionLabel,
            );
            const route = setupRouteByEdge.get(decision.coverageEdgeId);
            const actionIds = Array.isArray(decision.actionIds)
              ? decision.actionIds
              : [];
            const allowedActions = [
              ...(route?.actionStages ?? []),
              ...(route?.internalObserverActionStages ?? []),
            ]
              .filter((action) => action.stages.includes(decision.stage))
              .map((action) => action.actionId)
              .filter(
                (actionId, index, values) => values.indexOf(actionId) === index,
              )
              .sort(compareText);
            if (
              !route ||
              typeof decision.stage !== "string" ||
              decision.stage.length === 0 ||
              actionIds.length === 0 ||
              canonicalJson(actionIds) !==
                canonicalJson([...new Set(actionIds)].sort(compareText)) ||
              !actionIds.every((actionId) => allowedActions.includes(actionId))
            ) {
              throw new Error(
                `${decisionLabel}: fixture edge/action/stage drifted`,
              );
            }
          }
          const observedSetupEdgeIds = new Set(
            setupEvidence.decisions.map((decision) => decision.coverageEdgeId),
          );
          for (const requiredEdgeId of setup.decisionEvidence
            .requiredDecisionEdgeIds) {
            if (!observedSetupEdgeIds.has(requiredEdgeId)) {
              throw new Error(
                `${label}: fixture setup omitted required typed edge ${requiredEdgeId}`,
              );
            }
          }
          exactKeys(
            fixtureCleanup,
            ["kind", "completionToken", "errorCode"],
            `${label}.fixtureCleanup`,
          );
          if (
            fixtureCleanup.kind !== "fixture-cleanup-completion" ||
            fixtureCleanup.errorCode !== null ||
            (fixtureCleanup.completionToken !== null &&
              (typeof fixtureCleanup.completionToken !== "string" ||
                fixtureCleanup.completionToken.length === 0))
          ) {
            throw new Error(`${label}: filesystem fixture cleanup is unproven`);
          }
        }
      }
      return;
    }
    default:
      throw new Error(`${label}: unsupported proof mechanism`);
  }
}

function validateRawExecutorObservation(raw, label) {
  const hasErrorName = Object.hasOwn(raw ?? {}, "errorName");
  exactKeys(
    raw,
    [
      "kind",
      "rawValueShape",
      "value",
      "errorCode",
      ...(hasErrorName ? ["errorName"] : []),
    ],
    label,
  );
  if (!new Set(["absent", "return", "throw"]).has(raw.kind)) {
    throw new Error(`${label}.kind: unsupported raw executor result`);
  }
  if (!RAW_VALUE_SHAPES.has(raw.rawValueShape)) {
    throw new Error(`${label}.rawValueShape: unsupported raw value shape`);
  }
  if (raw.rawValueShape === "argument-identity") {
    if (
      raw.kind !== "return" ||
      raw.value !== "same-as-argument-0" ||
      raw.errorCode !== null ||
      hasErrorName
    ) {
      throw new Error(
        `${label}: argument identity must be an exact successful return class`,
      );
    }
    return;
  }
  if (raw.kind === "absent") {
    if (
      raw.rawValueShape !== "absent" ||
      raw.value !== null ||
      raw.errorCode !== null ||
      hasErrorName
    ) {
      throw new Error(
        `${label}: absent results must carry only the absent tag`,
      );
    }
    return;
  }
  const validateValueShape = () => {
    const valid =
      (raw.rawValueShape === "null" && raw.value === null) ||
      (raw.rawValueShape === "boolean" && typeof raw.value === "boolean") ||
      (raw.rawValueShape === "number" &&
        typeof raw.value === "number" &&
        Number.isFinite(raw.value)) ||
      (raw.rawValueShape === "string" && typeof raw.value === "string") ||
      (raw.rawValueShape === "bigint" &&
        typeof raw.value === "string" &&
        /^(?:0|-?[1-9][0-9]*)$/u.test(raw.value)) ||
      (raw.rawValueShape === "array" && Array.isArray(raw.value)) ||
      (raw.rawValueShape === "object" &&
        (raw.value === null ||
          (typeof raw.value === "object" && !Array.isArray(raw.value)))) ||
      (new Set(["function", "symbol", "undefined"]).has(raw.rawValueShape) &&
        raw.value === null);
    if (!valid) {
      throw new Error(`${label}: raw value contradicts its value-shape tag`);
    }
  };
  if (raw.kind === "throw") {
    if (
      raw.errorCode !== null &&
      (typeof raw.errorCode !== "string" || raw.errorCode.length === 0)
    ) {
      throw new Error(`${label}: thrown error codes must be non-empty or null`);
    }
    if (
      hasErrorName &&
      (typeof raw.errorName !== "string" || raw.errorName.length === 0)
    ) {
      throw new Error(`${label}: thrown error names must be non-empty`);
    }
    if (raw.rawValueShape === "throw") {
      if (raw.value !== null) {
        throw new Error(`${label}: an unprojected throw cannot carry a value`);
      }
      return;
    }
    // A return-record route such as `throw-field:path` observes a value on the
    // thrown object while retaining the fact that the operation threw.  Do
    // not erase that field: its path class is precisely what the sweep proves.
    // @ref LLP 0023#72-the-structured-result-and-its-error-classes
    if (raw.rawValueShape === "absent") {
      throw new Error(
        `${label}: a projected throw field cannot use the absent tag`,
      );
    }
    validateValueShape();
    return;
  }
  if (
    raw.rawValueShape === "absent" ||
    raw.rawValueShape === "throw" ||
    raw.errorCode !== null ||
    hasErrorName
  ) {
    throw new Error(`${label}: returned results have contradictory raw tags`);
  }
  validateValueShape();
}

function isForeignAbsolute(value) {
  return /^[A-Za-z]:[\\/]/u.test(value) || /^\\\\/u.test(value);
}

function isVirtualAbsolute(value) {
  return value === "/project" || value.startsWith("/project/");
}

function normalizedStringValue(key, value) {
  const alias = key.alias;
  if (value === "private-native-path") {
    if (
      key.sourceKind !== "host-abi" ||
      key.contextId !== "host.private-native-call-initialized"
    ) {
      throw new Error(
        `loaded-engine output used a private native path marker outside authenticated Host-ABI context for ${alias}`,
      );
    }
    return "private-native-path";
  }
  if (alias === "process.execArgv[]" || alias === "exact:process.execArgv[]") {
    return "non-path:runtime-flags-with-no-runtime-originated-host-path";
  }
  if (key.sourceKind === "foreign-dialect") {
    return "non-path:foreign-dialect";
  }
  if (alias === "resolver.error") return "stable-resolver-error-message";
  if (alias === "resolver.errorCode") return "stable-resolver-error-code";
  if (alias.endsWith(".sessionHandle")) {
    return "opaque-resolver-session-handle";
  }
  if (
    (alias === "resolver.id" && key.returnVariant === "builtin") ||
    (alias === "require.resolve" && key.returnVariant === "builtin")
  ) {
    return "builtin-source-id";
  }
  if (alias === "Error.stack frame source") {
    return "ibex:runtime-or-builtin-source-id";
  }
  if (key.output.startsWith("source-map:") && key.sourceKind === "synthetic") {
    return "ibex-or-repl-source-id";
  }
  if (value === "") return "empty-string";
  if (key.returnVariant === "argument-or-absent") {
    return "user-argument-or-absent";
  }
  if (key.returnVariant === "argument-or-empty") {
    return "user-argument-or-empty";
  }
  if (value === "/dev/null") return "/dev/null";
  if (value === "ibex:runtime") return "ibex:runtime";
  if (value === "ibex:stdin") return "ibex:stdin";
  if (value === "ibex:eval") return "ibex:eval";
  if (/^repl:\d+$/u.test(value)) return "repl:<ordinal>";
  if (value.startsWith("file:///project")) {
    return key.output.startsWith("source-map:")
      ? "canonical-virtual-file-url"
      : "virtual-file-url";
  }
  if (isVirtualAbsolute(value)) {
    if (
      (alias === "process.cwd" || alias === "exact:process.cwd") &&
      value === "/project"
    ) {
      return "/project";
    }
    if (
      (alias === "process.argv[1]" ||
        alias === "Exact.argv[1]" ||
        alias === "Bun.argv[1]") &&
      key.mode === "file"
    ) {
      return "virtual-entry-path";
    }
    return "virtual-absolute";
  }
  if (
    alias === "Dirent.name" ||
    alias === "import.meta.file" ||
    alias === "ex_host_fs_readdir[]"
  ) {
    return "virtual-basename";
  }
  if (alias === "fs.watch event path") {
    return key.returnVariant === "recursive"
      ? "virtual-relative"
      : "virtual-basename";
  }
  if (
    alias === "fs.readlink" ||
    alias === "fs.readlinkSync" ||
    alias === "fs.promises.readlink" ||
    alias === "path.posix.relative" ||
    alias === "export:node_path:relative"
  ) {
    return "virtual-relative";
  }
  if (isForeignAbsolute(value)) {
    throw new Error(
      `loaded-engine output exposed a foreign absolute path for ${alias}`,
    );
  }
  if (value.startsWith("/") || /^file:\/\//u.test(value)) {
    throw new Error(
      `loaded-engine output exposed a host-backed path for ${alias}`,
    );
  }
  return "non-path";
}

export function normalizeExecutorObservation(key, raw) {
  if (raw.kind === "absent") {
    return { outcome: "absent", normalizedValue: "absent" };
  }
  if (raw.kind === "throw") {
    if (raw.rawValueShape === "string") {
      return {
        outcome: "throw",
        normalizedValue: normalizedStringValue(key, String(raw.value)),
      };
    }
    if (
      raw.rawValueShape === "object" &&
      raw.value &&
      typeof raw.value === "object" &&
      typeof raw.value.schema === "string" &&
      /^ibex\/[a-z0-9-]+\/\d+$/u.test(raw.value.schema)
    ) {
      return { outcome: "throw", normalizedValue: raw.value.schema };
    }
    return {
      outcome: "throw",
      normalizedValue:
        raw.errorCode ??
        (raw.errorName ? `error-name:${raw.errorName}` : "throw-without-code"),
    };
  }
  if (raw.rawValueShape === "argument-identity") {
    if (
      raw.kind !== "return" ||
      raw.value !== "same-as-argument-0" ||
      key.output !== "[[return]]" ||
      !new Set(["__exactDeepFreeze", "__exactNativeFreeze"]).has(key.alias) ||
      !new Set(["primitive-sentinel", "object-sentinel"]).has(key.mode) ||
      key.sourceKind !== "native-op" ||
      key.returnVariant !== "same-as-argument-0" ||
      key.contextId !== "runtime.bootstrap-native-call-loaded"
    ) {
      throw new Error(
        `${key.alias}: argument identity is not bound to an exact native freeze route`,
      );
    }
    return {
      outcome: "return",
      normalizedValue: "same-as-argument-0",
    };
  }
  const value = raw.value;
  if (
    raw.rawValueShape === "object" &&
    value &&
    typeof value === "object" &&
    typeof value.schema === "string" &&
    /^ibex\/[a-z0-9-]+\/\d+$/u.test(value.schema)
  ) {
    return { outcome: "typed-return", normalizedValue: value.schema };
  }
  if (raw.rawValueShape === "string") {
    return {
      outcome: "return",
      normalizedValue: normalizedStringValue(key, String(value)),
    };
  }
  if (raw.rawValueShape === "array") {
    if (
      key.alias === "process.execArgv[]" ||
      key.alias === "exact:process.execArgv[]"
    ) {
      return {
        outcome: "return",
        normalizedValue:
          "non-path:runtime-flags-with-no-runtime-originated-host-path",
      };
    }
    const pathBearingArray =
      key.alias === "source-map.sources[]" ||
      key.alias === "ex_host_fs_readdir[]" ||
      key.alias === "fs.glob" ||
      key.alias === "fs.globSync" ||
      key.alias === "module.paths[]";
    const strings = pathBearingArray
      ? value.map((item) => {
          if (typeof item !== "string") {
            throw new Error(
              `${key.alias}: path-bearing array contains a non-string`,
            );
          }
          return item;
        })
      : null;
    if (key.alias === "source-map.sources[]") {
      if (strings.length === 0) {
        throw new Error(`${key.alias}: source-map observation is empty`);
      }
      const normalized = strings.map((item) =>
        normalizedStringValue(key, item),
      );
      if (new Set(normalized).size !== 1) {
        throw new Error(
          `${key.alias}: source-map observations mix path classes`,
        );
      }
      return { outcome: "return", normalizedValue: normalized[0] };
    }
    if (key.alias === "ex_host_fs_readdir[]") {
      if (strings.length === 0) {
        throw new Error(
          `${key.alias}: an empty directory cannot prove item shape`,
        );
      }
      if (
        strings.some(
          (item) =>
            item.length === 0 ||
            item === "." ||
            item === ".." ||
            item.includes("/") ||
            item.includes("\\"),
        )
      ) {
        throw new Error(`${key.alias}: directory items are not basenames`);
      }
      const normalized = strings.map((item) =>
        normalizedStringValue(key, item),
      );
      if (normalized.some((item) => item !== "virtual-basename")) {
        throw new Error(`${key.alias}: directory items are not basenames`);
      }
      return {
        outcome: "return",
        normalizedValue: "array:virtual-basename",
      };
    }
    if (
      key.alias === "fs.glob" ||
      key.alias === "fs.globSync" ||
      key.alias === "module.paths[]"
    ) {
      if (strings.length === 0) {
        throw new Error(`${key.alias}: path-array observation is empty`);
      }
      const expected =
        key.returnVariant === "relative-pattern"
          ? "virtual-relative"
          : "virtual-absolute";
      const normalized = strings.map((item) =>
        normalizedStringValue(key, item),
      );
      if (normalized.some((item) => item !== expected)) {
        throw new Error(
          `${key.alias}: path-array observation has the wrong shape`,
        );
      }
      return { outcome: "return", normalizedValue: `array:${expected}` };
    }
    const assertNestedNonPath = (item) => {
      if (typeof item === "string") {
        const normalized = normalizedStringValue(key, item);
        if (normalized !== "non-path" && normalized !== "empty-string") {
          throw new Error(
            `${key.alias}: structured array unexpectedly contains ${normalized}`,
          );
        }
      } else if (Array.isArray(item)) {
        item.forEach(assertNestedNonPath);
      } else if (item && typeof item === "object") {
        Object.values(item).forEach(assertNestedNonPath);
      }
    };
    value.forEach(assertNestedNonPath);
    return { outcome: "return", normalizedValue: "non-path" };
  }
  return { outcome: "return", normalizedValue: "non-path" };
}

/**
 * Convert executor-owned raw values into the sealed artifact. The executor
 * batch is source/plan/engine bound and contains no disposition policy; this is
 * the only normalization step before the later independent policy join.
 */
export function buildOutputShapeSweepArtifactFromExecutorBatch({
  plan,
  batch,
}) {
  validatePlanSelf(plan);
  exactKeys(
    batch,
    [
      "outputShapeExecutorBatchSchema",
      "profile",
      "executor",
      "sourceRevision",
      "sourceTreeDigest",
      "target",
      "catalogKeyDigest",
      "sweepPlanDigest",
      "loadedEngineIdentity",
      "compiledRegistrarIds",
      "results",
      "parameterizedResults",
      "unexercisable",
    ],
    "output-shape executor batch",
  );
  if (
    batch.outputShapeExecutorBatchSchema !== EXECUTOR_BATCH_SCHEMA ||
    batch.profile !== PROFILE ||
    batch.executor !== OUTPUT_SHAPE_SWEEP_EXECUTOR ||
    batch.sourceRevision !== plan.sourceRevision ||
    batch.sourceTreeDigest !== plan.sourceTreeDigest ||
    canonicalJson(batch.target) !== canonicalJson(plan.target) ||
    batch.catalogKeyDigest !== plan.catalogKeyDigest ||
    batch.sweepPlanDigest !== plan.sweepPlanDigest ||
    canonicalJson(batch.loadedEngineIdentity) !== canonicalJson(plan.engine)
  ) {
    throw new Error(
      "output-shape executor batch has stale or mismatched bindings",
    );
  }
  if (!Array.isArray(batch.unexercisable)) {
    throw new Error(
      "output-shape executor batch unexercisable rows must be an array",
    );
  }
  const planByKey = uniqueKeyMap(plan.rows, "output-shape sweep plan rows");
  const unsupported = new Map();
  for (const [index, row] of batch.unexercisable.entries()) {
    exactKeys(row, ["key", "reason"], `unexercisable row ${index}`);
    const key = canonicalOutputDispositionKey(row.key);
    nonEmptyString(row.reason, `unexercisable row ${index}.reason`);
    if (!planByKey.has(key)) {
      throw new Error(`executor reported an unknown unexercisable key ${key}`);
    }
    if (unsupported.has(key)) {
      throw new Error(`executor duplicated unexercisable key ${key}`);
    }
    unsupported.set(key, row.reason);
  }
  if (unsupported.size) {
    const sample = [...unsupported.entries()]
      .slice(0, 8)
      .map(([key, reason]) => `${key}: ${reason}`)
      .join("; ");
    throw new Error(
      `output-shape executor could not honestly exercise ${unsupported.size} rows: ${sample}`,
    );
  }

  const { actual: resultsByKey } = assertBidirectionalKeys(
    plan.rows,
    batch.results,
    "output-shape executor results",
  );
  assertCanonicalRowOrder(batch.results, "output-shape executor batch");
  const observations = [];
  for (const [canonicalKey, result] of resultsByKey) {
    const planRow = planByKey.get(canonicalKey);
    const focusedBuiltinResult =
      planRow.probe.sourceDescriptor?.kind ===
      BUILTIN_NONCAP_CLOSED_OUTPUT_SOURCE_DESCRIPTOR_KIND;
    const hasDiagnostic = Object.hasOwn(result, "diagnostic");
    const hasRefusal = Object.hasOwn(result, "refusal");
    if ((hasDiagnostic || hasRefusal) && !focusedBuiltinResult) {
      throw new Error(
        `executor result ${canonicalKey}: diagnostics are not bound to the authored builtin probe`,
      );
    }
    exactKeys(
      result,
      [
        "key",
        "proof",
        "raw",
        ...(hasDiagnostic ? ["diagnostic"] : []),
        ...(hasRefusal ? ["refusal"] : []),
      ],
      `executor result ${canonicalKey}`,
    );
    if (hasDiagnostic) {
      exactKeys(
        result.diagnostic,
        [
          "legacyObservationCount",
          "typedObservationCount",
          "legacyObservations",
          "typedObservations",
        ],
        `executor result ${canonicalKey}.diagnostic`,
      );
      if (
        !Array.isArray(result.diagnostic.legacyObservations) ||
        !Array.isArray(result.diagnostic.typedObservations) ||
        result.diagnostic.legacyObservationCount !==
          result.diagnostic.legacyObservations.length ||
        result.diagnostic.typedObservationCount !==
          result.diagnostic.typedObservations.length
      ) {
        throw new Error(
          `executor result ${canonicalKey}: builtin diagnostics contradict their raw counts`,
        );
      }
    }
    if (hasRefusal) {
      exactKeys(
        result.refusal,
        [
          "operation",
          "moduleSpecifier",
          "errorName",
          "errorMessage",
          "errorCode",
        ],
        `executor result ${canonicalKey}.refusal`,
      );
      if (
        result.refusal.operation !== "require" ||
        typeof result.refusal.moduleSpecifier !== "string" ||
        result.refusal.moduleSpecifier.length === 0 ||
        typeof result.refusal.errorName !== "string" ||
        result.refusal.errorName.length === 0 ||
        typeof result.refusal.errorMessage !== "string" ||
        result.refusal.errorMessage.length === 0 ||
        typeof result.refusal.errorCode !== "string" ||
        result.refusal.errorCode.length === 0 ||
        result.refusal.errorCode !== result.raw.errorCode
      ) {
        throw new Error(
          `executor result ${canonicalKey}: invalid actual builtin import refusal`,
        );
      }
    }
    validateProof(
      result.proof,
      planRow.probe,
      result.key,
      `executor result ${canonicalKey}.proof`,
    );
    validateRawExecutorObservation(
      result.raw,
      `executor result ${canonicalKey}.raw`,
    );
    if (
      planRow.probe.sourceDescriptor?.kind ===
        BUILTIN_EFFECTS_OUTPUT_SOURCE_DESCRIPTOR_KIND &&
      result.raw.kind !== "return"
    ) {
      throw new Error(
        `executor result ${canonicalKey}: builtin effects source did not return normally`,
      );
    }
    if (
      new Set([
        "compiled-runtime-return-record",
        "loaded-engine-return-record",
      ]).has(result.proof.kind) &&
      result.proof.rawValueShape !== result.raw.rawValueShape
    ) {
      throw new Error(
        `executor result ${canonicalKey}: return-record proof disagrees with raw value shape`,
      );
    }
    observations.push({
      key: structuredClone(result.key),
      observation: normalizeExecutorObservation(result.key, result.raw),
      proof: structuredClone(result.proof),
    });
  }
  const parameterizedObservations = buildEnvironmentOutputSweepObservations(
    plan.parameterizedEnvironment.map(({ sweepBinding }) => sweepBinding),
    batch.parameterizedResults,
    {
      executor: batch.executor,
      loadedEngineBinaryDigest: batch.loadedEngineIdentity.binaryDigest,
    },
  );
  const artifact = sealOutputShapeSweepArtifact({
    plan,
    loadedEngineIdentity: batch.loadedEngineIdentity,
    compiledRegistrarIds: batch.compiledRegistrarIds,
    observations,
    parameterizedObservations,
  });
  validateOutputShapeSweepArtifact(artifact, plan);
  return artifact;
}

function validateBoundHostAbiExecutorBatch({ batch, plan, expectedRows }) {
  exactKeys(
    batch,
    [
      "hostAbiOutputExecutorBatchSchema",
      "profile",
      "executor",
      "sourceRevision",
      "sourceTreeDigest",
      "target",
      "catalogKeyDigest",
      "sweepPlanDigest",
      "loadedEngineIdentity",
      "compiledRegistrarIds",
      "results",
      "unexercisable",
    ],
    "Host ABI output executor batch",
  );
  if (
    batch.hostAbiOutputExecutorBatchSchema !== HOST_ABI_EXECUTOR_BATCH_SCHEMA ||
    batch.profile !== PROFILE ||
    batch.executor !== OUTPUT_SHAPE_SWEEP_EXECUTOR ||
    batch.sourceRevision !== plan.sourceRevision ||
    batch.sourceTreeDigest !== plan.sourceTreeDigest ||
    canonicalJson(batch.target) !== canonicalJson(plan.target) ||
    batch.catalogKeyDigest !== plan.catalogKeyDigest ||
    batch.sweepPlanDigest !== plan.sweepPlanDigest ||
    canonicalJson(batch.loadedEngineIdentity) !== canonicalJson(plan.engine) ||
    !Array.isArray(batch.results) ||
    !Array.isArray(batch.unexercisable) ||
    !Array.isArray(batch.compiledRegistrarIds)
  ) {
    throw new Error("Host ABI output executor batch has stale bindings");
  }
  if (batch.unexercisable.length !== 0) {
    const sample = batch.unexercisable
      .slice(0, 8)
      .map((row) => `${canonicalOutputDispositionKey(row.key)}: ${row.reason}`)
      .join("; ");
    throw new Error(
      `Host ABI output executor could not honestly exercise ${batch.unexercisable.length} rows: ${sample}`,
    );
  }
  assertBidirectionalKeys(
    expectedRows,
    batch.results,
    "Host ABI output executor results",
  );
  assertCanonicalRowOrder(batch.results, "Host ABI output executor batch");
  return batch;
}

function targetAbsenceExecutorResult({ planRow, execution }) {
  const descriptor = planRow.probe.sourceDescriptor;
  const evidence = execution?.evidence;
  const runtime = evidence?.runtimeObservation;
  const invocation = runtime?.invocation;
  const result = invocation?.result;
  if (
    execution?.fixtureId !== descriptor.fixtureId ||
    execution.outcome !== "passed" ||
    evidence?.fixtureId !== descriptor.fixtureId ||
    evidence.planDigest !== descriptor.recipePlanDigest ||
    evidence.engineBinaryDigest === undefined ||
    canonicalJson(evidence.probe) !==
      canonicalJson(descriptor.publicSurfaceProbe) ||
    evidence.terminalObservedKey !== descriptor.terminalObservedKey ||
    runtime?.observationSchema !== "ibex/capsec-runtime-public-observation/1" ||
    runtime.legacyObservationCount !== 0 ||
    !Array.isArray(runtime.typedDecisions) ||
    runtime.typedDecisions.length !== 0 ||
    invocation?.invocationSchema !== descriptor.invocationSchema ||
    invocation.kind !== "target-absence" ||
    invocation.surfaceObservedKey !== descriptor.terminalObservedKey ||
    invocation.surfaceKind !== planRow.key.sourceKind ||
    invocation.surfaceName !== planRow.key.alias ||
    invocation.sourceDescriptorDigest !==
      descriptor.targetSourceDescriptorDigest ||
    result?.kind !== "absent" ||
    result.surfaceKind !== planRow.key.sourceKind ||
    result.surfaceName !== planRow.key.alias ||
    result.targetTriple !==
      descriptor.publicSurfaceProbe.invocation.targetTriple
  ) {
    throw new Error(
      `${descriptor.fixtureId}: public execution did not prove the exact target-absent output row`,
    );
  }
  return {
    key: structuredClone(planRow.key),
    proof: {
      kind: "loaded-engine-return-record",
      fixtureId: planRow.probe.fixtureId,
      sourceDescriptorDigest: planRow.probe.sourceDescriptorDigest,
      recordPath: structuredClone(planRow.probe.recordPath),
      rawValueShape: "absent",
    },
    raw: {
      kind: "absent",
      rawValueShape: "absent",
      value: null,
      errorCode: null,
    },
  };
}

/**
 * Validate the independently executed generic, Host-ABI, and target-absence
 * partitions, then lift them into the one complete executor batch required by
 * the v3 plan/artifact contract.
 */
export function composeOutputShapeSweepArtifactFromDelegatedBatches({
  catalog,
  plan,
  genericCatalog,
  genericPlan,
  genericBatch,
  hostAbiBatch,
  targetAbsenceProbes,
  targetAbsenceExecutionArtifact = null,
  recipeCatalog = null,
  coverage,
}) {
  const bindings = {
    sourceRevision: plan.sourceRevision,
    sourceTreeDigest: plan.sourceTreeDigest,
    target: plan.target,
    engine: plan.engine,
  };
  validateOutputShapeSweepPlan(plan, { catalog, ...bindings });
  validateOutputShapeSweepPlan(genericPlan, {
    catalog: genericCatalog,
    ...bindings,
  });
  const genericArtifact = buildOutputShapeSweepArtifactFromExecutorBatch({
    plan: genericPlan,
    batch: genericBatch,
  });

  const hostRows = [];
  const targetAbsenceRows = [];
  const genericRows = [];
  for (const row of plan.rows) {
    const descriptorKind = row.probe?.sourceDescriptor?.kind;
    if (descriptorKind === HOST_ABI_OUTPUT_SOURCE_DESCRIPTOR_KIND) {
      hostRows.push(row);
    } else if (descriptorKind === TARGET_ABSENCE_OUTPUT_SOURCE_DESCRIPTOR_KIND) {
      targetAbsenceRows.push(row);
    } else {
      genericRows.push(row);
    }
  }
  const { expected: genericByKey, actual: projectedGenericByKey } =
    assertBidirectionalKeys(
      genericPlan.rows,
      genericRows,
      "generic/full output-shape plan projection",
    );
  for (const [key, row] of genericByKey) {
    if (canonicalJson(row) !== canonicalJson(projectedGenericByKey.get(key))) {
      throw new Error(`generic output-shape probe drift for ${key}`);
    }
  }
  const { expected: absenceByKey, actual: authoredAbsenceByKey } =
    assertBidirectionalKeys(
      targetAbsenceRows,
      targetAbsenceProbes,
      "target-absence/full output-shape plan projection",
    );
  for (const [key, row] of absenceByKey) {
    if (canonicalJson(row) !== canonicalJson(authoredAbsenceByKey.get(key))) {
      throw new Error(`target-absence output-shape probe drift for ${key}`);
    }
  }
  assertBidirectionalKeys(
    plan.rows,
    [...genericRows, ...hostRows, ...targetAbsenceRows],
    "complete delegated output-shape plan",
  );

  validateBoundHostAbiExecutorBatch({
    batch: hostAbiBatch,
    plan,
    expectedRows: hostRows,
  });
  if (!Array.isArray(coverage?.edges)) {
    throw new Error("delegated output-shape composition requires coverage edges");
  }
  const hostSurfaceAccountIds = coverage.edges
    .filter((edge) => edge.surface?.kind === "host-abi")
    .map((edge) => edge.id)
    .sort(compareText);
  if (
    canonicalJson(hostAbiBatch.compiledRegistrarIds) !==
    canonicalJson(hostSurfaceAccountIds)
  ) {
    throw new Error(
      "Host ABI compiled registrar IDs do not cover the exact Host catalog accounts",
    );
  }

  let targetAbsenceResults = [];
  if (targetAbsenceRows.length > 0) {
    if (!recipeCatalog || !targetAbsenceExecutionArtifact) {
      throw new Error(
        "target-absence output rows require their validated public execution artifact",
      );
    }
    validatePublicSurfaceExecutionArtifact(targetAbsenceExecutionArtifact, {
      recipeCatalog,
      target: plan.target,
      sourceRevision: plan.sourceRevision,
      sourceTreeDigest: plan.sourceTreeDigest,
      engine: plan.engine,
      coverage,
    });
    const executions = new Map(
      targetAbsenceExecutionArtifact.executions.map((execution) => [
        execution.fixtureId,
        execution,
      ]),
    );
    targetAbsenceResults = targetAbsenceRows.map((row) => {
      if (
        row.probe.sourceDescriptor.recipeCatalogDigest !==
        recipeCatalog.recipeCatalogDigest
      ) {
        throw new Error(
          `${row.probe.fixtureId}: target-absence plan selected another recipe catalog`,
        );
      }
      const execution = executions.get(row.probe.fixtureId);
      if (!execution) {
        throw new Error(
          `${row.probe.fixtureId}: target-absence public execution is missing`,
        );
      }
      if (execution.evidence?.engineBinaryDigest !== plan.engine.binaryDigest) {
        throw new Error(
          `${row.probe.fixtureId}: target-absence execution used another engine`,
        );
      }
      return targetAbsenceExecutorResult({ planRow: row, execution });
    });
  } else if (
    targetAbsenceExecutionArtifact !== null ||
    (Array.isArray(targetAbsenceProbes) && targetAbsenceProbes.length !== 0)
  ) {
    throw new Error("empty target-absence partition carried delegated evidence");
  }

  const compiledRegistrarIds = [
    ...new Set([
      ...genericArtifact.compiledRegistrarIds,
      ...hostAbiBatch.compiledRegistrarIds,
    ]),
  ].sort(compareText);
  const composedBatch = {
    outputShapeExecutorBatchSchema: EXECUTOR_BATCH_SCHEMA,
    profile: PROFILE,
    executor: OUTPUT_SHAPE_SWEEP_EXECUTOR,
    sourceRevision: plan.sourceRevision,
    sourceTreeDigest: plan.sourceTreeDigest,
    target: structuredClone(plan.target),
    catalogKeyDigest: plan.catalogKeyDigest,
    sweepPlanDigest: plan.sweepPlanDigest,
    loadedEngineIdentity: structuredClone(plan.engine),
    compiledRegistrarIds,
    results: sortedRows([
      ...genericBatch.results,
      ...hostAbiBatch.results,
      ...targetAbsenceResults,
    ]),
    parameterizedResults: structuredClone(genericBatch.parameterizedResults),
    unexercisable: [],
  };
  const artifact = buildOutputShapeSweepArtifactFromExecutorBatch({
    plan,
    batch: composedBatch,
  });
  return { artifact, batch: composedBatch };
}

/** Seal executor-owned raw observations without consulting disposition policy. */
export function sealOutputShapeSweepArtifact({
  plan,
  loadedEngineIdentity,
  compiledRegistrarIds,
  observations,
  parameterizedObservations = [],
}) {
  const artifact = {
    outputShapeSweepArtifactSchema: ARTIFACT_SCHEMA,
    profile: PROFILE,
    executor: OUTPUT_SHAPE_SWEEP_EXECUTOR,
    sourceRevision: plan.sourceRevision,
    sourceTreeDigest: plan.sourceTreeDigest,
    target: structuredClone(plan.target),
    catalogKeyDigest: plan.catalogKeyDigest,
    sweepPlanDigest: plan.sweepPlanDigest,
    loadedEngineIdentity: structuredClone(loadedEngineIdentity),
    compiledRegistrarIds: [...compiledRegistrarIds],
    observations: structuredClone(observations),
    parameterizedObservations: structuredClone(parameterizedObservations),
  };
  artifact.sweepArtifactDigest = artifactDigest(artifact);
  return artifact;
}

export function validateOutputShapeSweepArtifact(artifact, plan) {
  validatePlanSelf(plan);
  exactKeys(
    artifact,
    [
      "outputShapeSweepArtifactSchema",
      "profile",
      "executor",
      "sourceRevision",
      "sourceTreeDigest",
      "target",
      "catalogKeyDigest",
      "sweepPlanDigest",
      "loadedEngineIdentity",
      "compiledRegistrarIds",
      "observations",
      "parameterizedObservations",
      "sweepArtifactDigest",
    ],
    "output-shape sweep artifact",
  );
  if (
    artifact.outputShapeSweepArtifactSchema !== ARTIFACT_SCHEMA ||
    artifact.profile !== PROFILE ||
    artifact.executor !== OUTPUT_SHAPE_SWEEP_EXECUTOR ||
    artifact.sourceRevision !== plan.sourceRevision ||
    artifact.sourceTreeDigest !== plan.sourceTreeDigest ||
    canonicalJson(artifact.target) !== canonicalJson(plan.target) ||
    artifact.catalogKeyDigest !== plan.catalogKeyDigest ||
    artifact.sweepPlanDigest !== plan.sweepPlanDigest ||
    canonicalJson(artifact.loadedEngineIdentity) !==
      canonicalJson(plan.engine) ||
    artifact.loadedEngineIdentity?.binaryDigest !== plan.engine?.binaryDigest ||
    artifact.sweepArtifactDigest !== artifactDigest(artifact)
  ) {
    throw new Error(
      "output-shape sweep artifact has stale or mismatched bindings",
    );
  }

  if (
    !Array.isArray(artifact.compiledRegistrarIds) ||
    artifact.compiledRegistrarIds.some(
      (surfaceId) =>
        typeof surfaceId !== "string" ||
        !/^surface\.[a-z0-9.]+$/u.test(surfaceId),
    )
  ) {
    throw new Error("compiled registrar IDs must be stable surface IDs");
  }
  const expectedRegistrarIds = plan.surfaceAccountIds;
  const actualRegistrarIds = [...new Set(artifact.compiledRegistrarIds)].sort(
    compareText,
  );
  if (
    actualRegistrarIds.length !== artifact.compiledRegistrarIds.length ||
    canonicalJson(artifact.compiledRegistrarIds) !==
      canonicalJson(actualRegistrarIds) ||
    canonicalJson(actualRegistrarIds) !== canonicalJson(expectedRegistrarIds)
  ) {
    throw new Error(
      "compiled registrar IDs do not join the catalog surface accounts bidirectionally",
    );
  }

  const { expected: planByKey, actual: observationsByKey } =
    assertBidirectionalKeys(
      plan.rows,
      artifact.observations,
      "loaded-engine output observations",
    );
  assertCanonicalRowOrder(artifact.observations, "output-shape sweep artifact");
  for (const [canonicalKey, observation] of observationsByKey) {
    exactKeys(
      observation,
      ["key", "observation", "proof"],
      `sweep observation ${canonicalKey}`,
    );
    validateNormalizedObservation(
      observation.observation,
      `sweep observation ${canonicalKey}.observation`,
    );
    validateProof(
      observation.proof,
      planByKey.get(canonicalKey).probe,
      observation.key,
      `sweep observation ${canonicalKey}.proof`,
    );
  }
  validateEnvironmentOutputSweepObservations(
    plan.parameterizedEnvironment.map(({ sweepBinding }) => sweepBinding),
    artifact.parameterizedObservations,
    {
      executor: artifact.executor,
      loadedEngineBinaryDigest: artifact.loadedEngineIdentity.binaryDigest,
    },
  );
  return artifact;
}

/**
 * Perform the only expected-value join. Raw observations come from the loaded
 * engine artifact; dispositions and expectations come from the reviewed data.
 */
export function buildVerifiedOutputDispositionEvidence({
  catalog,
  dispositionRows,
  plan,
  artifact,
  sourceRevision,
  sourceTreeDigest,
  target,
  engine,
}) {
  validateOutputShapeSweepPlan(plan, {
    catalog,
    sourceRevision,
    sourceTreeDigest,
    target,
    engine,
  });
  if (plan.catalogKeyDigest !== outputShapeCatalogKeyDigest(dispositionRows)) {
    throw new Error(
      "output-shape sweep plan targets another disposition catalog",
    );
  }
  validateOutputShapeSweepArtifact(artifact, plan);
  const dispositionsByKey = uniqueKeyMap(
    dispositionRows,
    "reviewed output dispositions",
  );
  const evidence = {
    outputDispositionEvidenceSchema:
      "ibex/capsec-output-disposition-evidence/3",
    profile: PROFILE,
    status: "verified",
    requiredExecutor: OUTPUT_SHAPE_SWEEP_EXECUTOR,
    sourceRevision: plan.sourceRevision,
    sourceTreeDigest: plan.sourceTreeDigest,
    target: structuredClone(plan.target),
    engine: structuredClone(plan.engine),
    sweepPlan: structuredClone(plan),
    sweepArtifact: structuredClone(artifact),
    observations: artifact.observations.map((actual) => {
      const canonicalKey = canonicalOutputDispositionKey(actual.key);
      const reviewed = dispositionsByKey.get(canonicalKey);
      if (!reviewed) {
        throw new Error(
          `loaded-engine output observation has unknown key ${canonicalKey}`,
        );
      }
      return {
        key: structuredClone(actual.key),
        disposition: reviewed.disposition,
        proofKind: validateOutputValueProofKind(
          actual.proof.kind,
          `loaded-engine output observation ${canonicalKey}.proofKind`,
        ),
        observation: structuredClone(actual.observation),
      };
    }),
  };
  validateOutputDispositionEvidence(dispositionRows, evidence);
  return evidence;
}

/**
 * Validate the complete executor proof bundle before any target promotion.
 * The projected observations alone are deliberately insufficient: promotion
 * replays the sealed plan/artifact validation and reconstructs the projection
 * byte-for-byte from their full per-row proof records.
 */
export function validatePromotableOutputDispositionEvidence({
  catalog,
  dispositionRows,
  evidence,
}) {
  const state = validateOutputDispositionEvidence(dispositionRows, evidence);
  if (state.status !== "verified") {
    throw new Error(
      "target promotion requires verified loaded-engine output-disposition evidence",
    );
  }
  validateOutputShapeSweepPlan(evidence.sweepPlan, {
    catalog,
    sourceRevision: state.sourceRevision,
    sourceTreeDigest: state.sourceTreeDigest,
    target: state.target,
    engine: state.engine,
  });
  validateOutputShapeSweepArtifact(evidence.sweepArtifact, evidence.sweepPlan);
  const reconstructed = buildVerifiedOutputDispositionEvidence({
    catalog,
    dispositionRows,
    plan: evidence.sweepPlan,
    artifact: evidence.sweepArtifact,
    sourceRevision: state.sourceRevision,
    sourceTreeDigest: state.sourceTreeDigest,
    target: state.target,
    engine: state.engine,
  });
  if (canonicalJson(reconstructed) !== canonicalJson(evidence)) {
    throw new Error(
      "output-disposition evidence projection differs from its sealed sweep proof",
    );
  }
  validateOutputDispositionJoin(catalog.rows, dispositionRows);
  validateOutputShapeCatalogAccounts({
    surfaceAccounts: catalog.surfaceAccounts,
    rows: catalog.rows,
    parameterizedOutputBindings:
      catalog[ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD],
    parameterizedOutputEvidence:
      evidence.sweepArtifact.parameterizedObservations,
    promotionStatus: "verified",
  });
  return state;
}
