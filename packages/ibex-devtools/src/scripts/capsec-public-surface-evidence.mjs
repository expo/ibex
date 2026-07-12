/**
 * Validate content-addressed evidence that every exact-target recipe invoked
 * its authored public surface and observed the selected enforcement terminal.
 * Typed-adapter probes are deliberately a different schema and are never
 * accepted here.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * target promotion requires executed public obligations, not adapter checks.
 */

import crypto from "node:crypto";
import {
  assertRecipeCatalogComplete,
  validateRecipeCatalog,
} from "./capsec-conformance-recipes.mjs";
import { canonicalJson } from "./capsec-contract.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : canonicalJson(value), "utf8")
    .digest("base64url")}`;

function exactKeys(value, keys, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    canonicalJson(Object.keys(value).sort(compareText)) !==
      canonicalJson([...keys].sort(compareText))
  ) {
    throw new Error(`${label} has unknown or missing fields`);
  }
}

function evidenceDigest(evidence) {
  const { evidenceDigest: _digest, ...payload } = evidence;
  return taggedDigest(payload);
}

export function computePublicSurfaceExecutionDigest(artifact) {
  const { publicSurfaceExecutionDigest: _digest, ...payload } = artifact;
  return taggedDigest(payload);
}

export function mergePublicBatchExecutions({
  batches,
  recipeCatalog,
  loadedEngineIdentity,
}) {
  if (!Array.isArray(batches)) {
    throw new Error("public fixture batches must be an array");
  }
  const knownFixtures = new Set(
    recipeCatalog.recipes.map((recipe) => recipe.fixtureId),
  );
  const seen = new Set();
  const executions = [];
  for (const [index, entry] of batches.entries()) {
    exactKeys(
      entry,
      ["batch", "expectedFixtureIds"],
      `public fixture batch binding ${index}`,
    );
    const { batch, expectedFixtureIds } = entry;
    exactKeys(
      batch,
      [
        "publicBatchEvidenceSchema",
        "recipeCatalogDigest",
        "loadedEngineIdentity",
        "executions",
      ],
      `public fixture batch ${index}`,
    );
    if (
      batch.publicBatchEvidenceSchema !==
        "ibex/capsec-public-batch-evidence/1" ||
      batch.recipeCatalogDigest !== recipeCatalog.recipeCatalogDigest ||
      canonicalJson(batch.loadedEngineIdentity) !==
        canonicalJson(loadedEngineIdentity) ||
      !Array.isArray(batch.executions) ||
      !Array.isArray(expectedFixtureIds) ||
      new Set(expectedFixtureIds).size !== expectedFixtureIds.length ||
      expectedFixtureIds.some((fixtureId) => !knownFixtures.has(fixtureId))
    ) {
      throw new Error(`public fixture batch ${index} is stale or malformed`);
    }
    const observedFixtureIds = batch.executions.map(
      (execution) => execution?.fixtureId,
    );
    if (
      observedFixtureIds.some((fixtureId) => typeof fixtureId !== "string") ||
      new Set(observedFixtureIds).size !== observedFixtureIds.length ||
      canonicalJson([...observedFixtureIds].sort(compareText)) !==
        canonicalJson([...expectedFixtureIds].sort(compareText))
    ) {
      throw new Error(
        `public fixture batch ${index} is missing, duplicates, or adds fixtures`,
      );
    }
    for (const execution of batch.executions) {
      if (seen.has(execution.fixtureId)) {
        throw new Error(
          `${execution.fixtureId}: duplicate public execution across batch commands`,
        );
      }
      seen.add(execution.fixtureId);
      executions.push(structuredClone(execution));
    }
  }
  return executions.sort((left, right) =>
    compareText(left.fixtureId, right.fixtureId),
  );
}

function executionSummary(recipeCatalog, executions) {
  return {
    requiredFixtures: recipeCatalog.summary.requiredFixtures,
    executableFixtures: recipeCatalog.summary.fullyExecutableFixtures,
    residualFixtures: recipeCatalog.summary.unresolvedFixtures,
    executedFixtures: executions.length,
    passedFixtures: executions.filter(
      (execution) => execution.outcome === "passed",
    ).length,
    failedFixtures: executions.filter(
      (execution) => execution.outcome === "failed",
    ).length,
    missingFixtures: recipeCatalog.summary.requiredFixtures - executions.length,
  };
}

export function buildPublicSurfaceExecutionArtifact({
  recipeCatalog,
  sourceRevision,
  sourceTreeDigest,
  target,
  engine,
  coverage = null,
  executions = [],
}) {
  validateRecipeCatalog(recipeCatalog, { target });
  const sortedExecutions = [...executions].sort((left, right) =>
    compareText(left.fixtureId, right.fixtureId),
  );
  const artifact = {
    publicSurfaceExecutionSchema: "ibex/capsec-public-surface-executions/1",
    profile: "ibex/capsec/1",
    sourceRevision,
    sourceTreeDigest,
    target: structuredClone(target),
    engine: structuredClone(engine),
    recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
    summary: executionSummary(recipeCatalog, sortedExecutions),
    executions: sortedExecutions,
  };
  artifact.publicSurfaceExecutionDigest =
    computePublicSurfaceExecutionDigest(artifact);
  return validatePublicSurfaceExecutionArtifact(artifact, {
    recipeCatalog,
    target,
    sourceRevision,
    sourceTreeDigest,
    engine,
    coverage,
  });
}

function coverageTerminalMap(coverage) {
  if (!Array.isArray(coverage?.edges)) {
    throw new Error(
      "runtime public evidence requires the bound coverage registry",
    );
  }
  const terminals = new Map();
  for (const edge of coverage.edges) {
    const kind = edge?.surface?.kind;
    const name = edge?.surface?.name;
    if (
      typeof edge?.id !== "string" ||
      typeof kind !== "string" ||
      typeof name !== "string" ||
      terminals.has(edge.id)
    ) {
      throw new Error(
        "bound coverage registry has malformed or duplicate edges",
      );
    }
    terminals.set(edge.id, `${kind}:${name}`);
  }
  return terminals;
}

function validateRuntimeInvocation(observation, recipe) {
  const invocation = observation.invocation;
  const authored = recipe.publicSurfaceProbe?.invocation;
  if (!authored || typeof authored.invocationSchema !== "string") {
    throw new Error(
      `${recipe.fixtureId}: public probe has no typed invocation descriptor`,
    );
  }
  const commonKeys = [
    "invocationSchema",
    "kind",
    "surfaceObservedKey",
    "sourceDescriptorDigest",
    "result",
  ];
  if (
    invocation?.invocationSchema === "ibex/capsec-native-global-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "globalName", "executionProof"],
      `${recipe.fixtureId}: native runtime invocation`,
    );
    if (
      invocation.kind !== "native-global-function" ||
      invocation.globalName !== authored.globalName
    ) {
      throw new Error(
        `${recipe.fixtureId}: native runtime invocation descriptor drift`,
      );
    }
  } else if (
    ["ibex/capsec-builtin-export-invocation/1"].includes(
      invocation?.invocationSchema,
    )
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "moduleSpecifier", "exportName"],
      `${recipe.fixtureId}: builtin runtime invocation`,
    );
    if (
      !["builtin-export-call", "builtin-export-read"].includes(
        invocation.kind,
      ) ||
      invocation.moduleSpecifier !== authored.moduleSpecifier ||
      invocation.exportName !== authored.exportName
    ) {
      throw new Error(
        `${recipe.fixtureId}: builtin runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema === "ibex/capsec-target-absence-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName", "targetTriple"],
      `${recipe.fixtureId}: target-absence runtime invocation`,
    );
    if (
      invocation.kind !== "target-absence" ||
      invocation.surfaceKind !== authored.surfaceKind ||
      invocation.surfaceName !== authored.surfaceName ||
      invocation.targetTriple !== authored.targetTriple
    ) {
      throw new Error(
        `${recipe.fixtureId}: target-absence runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema === "ibex/capsec-closed-surface-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName"],
      `${recipe.fixtureId}: closed-surface runtime invocation`,
    );
    if (
      invocation.kind !== "closed-surface" ||
      invocation.surfaceKind !== authored.surfaceKind ||
      invocation.surfaceName !== authored.surfaceName
    ) {
      throw new Error(
        `${recipe.fixtureId}: closed-surface runtime invocation descriptor drift`,
      );
    }
  } else {
    throw new Error(
      `${recipe.fixtureId}: unsupported runtime invocation schema`,
    );
  }
  if (
    invocation.invocationSchema !== authored.invocationSchema ||
    invocation.kind !== authored.kind ||
    invocation.surfaceObservedKey !==
      recipe.publicSurfaceProbe.surfaceObservedKey ||
    invocation.sourceDescriptorDigest !== authored.sourceDescriptorDigest ||
    authored.sourceDescriptorDigest !== taggedDigest(authored.sourceDescriptor)
  ) {
    throw new Error(
      `${recipe.fixtureId}: runtime invocation is not source-descriptor bound`,
    );
  }
  if (
    !Number.isSafeInteger(authored.expectedTypedDecisionCount) ||
    authored.expectedTypedDecisionCount < 0 ||
    !Array.isArray(authored.expectedTypedStages) ||
    authored.expectedTypedDecisionCount !==
      authored.expectedTypedStages.length ||
    !Array.isArray(authored.allowedCoverageEdgeIds) ||
    !Array.isArray(authored.expectedActionIds) ||
    !authored.expectedTypedStages.every(
      (stage) => typeof stage === "string" && stage.length > 0,
    ) ||
    !authored.allowedCoverageEdgeIds.every(
      (edgeId) => typeof edgeId === "string" && edgeId.length > 0,
    ) ||
    !authored.expectedActionIds.every(
      (actionId) => typeof actionId === "string" && actionId.length > 0,
    ) ||
    canonicalJson(authored.allowedCoverageEdgeIds) !==
      canonicalJson(canonicalSet(authored.allowedCoverageEdgeIds)) ||
    canonicalJson(authored.expectedActionIds) !==
      canonicalJson(canonicalSet(authored.expectedActionIds))
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed authored runtime expectations`,
    );
  }
  if (!invocation.result || typeof invocation.result !== "object") {
    throw new Error(`${recipe.fixtureId}: runtime invocation has no result`);
  }
  if (authored.expectedResult === "return") {
    if (invocation.result.kind !== "return") {
      throw new Error(`${recipe.fixtureId}: public invocation did not return`);
    }
  } else if (authored.expectedResult === "permission-denied") {
    if (
      invocation.result.kind !== "throw" ||
      typeof invocation.result.errorMessage !== "string" ||
      !invocation.result.errorMessage.includes("Permission denied")
    ) {
      throw new Error(`${recipe.fixtureId}: public invocation did not deny`);
    }
  } else if (authored.expectedResult === "absent") {
    if (
      invocation.invocationSchema === "ibex/capsec-native-global-invocation/1"
    ) {
      if (invocation.result.kind !== "missing") {
        throw new Error(
          `${recipe.fixtureId}: public native global was not absent`,
        );
      }
    } else {
      const probeMode = authored.sourceDescriptor?.probeMode;
      if (
        invocation.result.kind !== "absent" ||
        invocation.result.surfaceKind !== authored.surfaceKind ||
        invocation.result.surfaceName !== authored.surfaceName ||
        invocation.result.targetTriple !== authored.targetTriple ||
        invocation.result.compiledTargetOs !== "macos" ||
        invocation.result.compiledTargetArch !== "aarch64" ||
        invocation.result.probeMode !== probeMode?.kind
      ) {
        throw new Error(
          `${recipe.fixtureId}: target-absence probe did not prove absence`,
        );
      }
      if (probeMode?.kind === "runtime-global-property") {
        exactKeys(
          invocation.result,
          [
            "kind",
            "surfaceKind",
            "surfaceName",
            "targetTriple",
            "compiledTargetOs",
            "compiledTargetArch",
            "probeMode",
            "globalName",
            "memberName",
            "surfacePresent",
          ],
          `${recipe.fixtureId}: native-global target-absence runtime result`,
        );
        if (
          invocation.result.globalName !== probeMode.globalName ||
          invocation.result.memberName !== probeMode.memberName ||
          invocation.result.surfacePresent !== false
        ) {
          throw new Error(
            `${recipe.fixtureId}: runtime-global probe did not prove absence`,
          );
        }
      } else {
        exactKeys(
          invocation.result,
          [
            "kind",
            "surfaceKind",
            "surfaceName",
            "targetTriple",
            "compiledTargetOs",
            "compiledTargetArch",
            "probeMode",
            "symbolName",
            "symbolPresent",
          ],
          `${recipe.fixtureId}: symbol target-absence runtime result`,
        );
        if (
          !["dynamic-symbol", "platform-bridge"].includes(probeMode?.kind) ||
          invocation.result.symbolName !== probeMode.symbolName ||
          invocation.result.symbolPresent !== false
        ) {
          throw new Error(
            `${recipe.fixtureId}: symbol probe did not prove absence`,
          );
        }
      }
    }
  } else if (authored.expectedResult === "closed") {
    exactKeys(
      invocation.result,
      [
        "kind",
        "surfaceKind",
        "surfaceName",
        "mechanism",
        "errorName",
        "errorMessage",
        "engineExecuted",
        "projectCodeExecuted",
      ],
      `${recipe.fixtureId}: closed-surface runtime result`,
    );
    if (
      invocation.result.kind !== "closed" ||
      invocation.result.surfaceKind !== authored.surfaceKind ||
      invocation.result.surfaceName !== authored.surfaceName ||
      invocation.result.mechanism !== authored.operation?.kind ||
      invocation.result.errorName !== "ClosedSurface" ||
      typeof invocation.result.errorMessage !== "string" ||
      invocation.result.errorMessage.length === 0 ||
      typeof invocation.result.engineExecuted !== "boolean" ||
      invocation.result.projectCodeExecuted !== false
    ) {
      throw new Error(
        `${recipe.fixtureId}: public closed surface did not fail closed`,
      );
    }
    if (
      authored.operation?.kind === "startup-environment" &&
      (invocation.result.engineExecuted !== false ||
        !invocation.result.errorMessage.includes(
          "rejects closed environment controls",
        ) ||
        !invocation.result.errorMessage.includes(
          authored.operation.environmentName,
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: closed startup control reached engine execution or the wrong rejection`,
      );
    }
    if (
      authored.operation?.kind === "cli-control" &&
      (invocation.result.engineExecuted !== false ||
        !Array.isArray(authored.operation.expectedRejectionFragments) ||
        authored.operation.expectedRejectionFragments.length === 0 ||
        !authored.operation.expectedRejectionFragments.every(
          (fragment) =>
            typeof fragment === "string" &&
            fragment.length > 0 &&
            invocation.result.errorMessage.includes(fragment),
        ) ||
        !Array.isArray(authored.operation.argumentVectors) ||
        authored.operation.argumentVectors.length === 0)
    ) {
      throw new Error(
        `${recipe.fixtureId}: closed CLI control reached execution or the wrong rejection`,
      );
    }
  } else {
    throw new Error(`${recipe.fixtureId}: unsupported expected public result`);
  }
  if (
    invocation.invocationSchema === "ibex/capsec-native-global-invocation/1"
  ) {
    exactKeys(
      invocation.executionProof,
      ["kind", "bodyEntered"],
      `${recipe.fixtureId}: native execution proof`,
    );
    const expectedProof =
      authored.expectedResult === "return"
        ? ["native-return", true]
        : authored.expectedResult === "permission-denied"
          ? ["typed-permission-denial", true]
          : ["exact-global-absence", false];
    if (
      invocation.executionProof.kind !== expectedProof[0] ||
      invocation.executionProof.bodyEntered !== expectedProof[1]
    ) {
      throw new Error(
        `${recipe.fixtureId}: native execution proof disagrees with result`,
      );
    }
  }
}

function validateRuntimeObservation(observation, recipe, coverage) {
  exactKeys(
    observation,
    [
      "observationSchema",
      "invocation",
      "legacyObservationCount",
      "typedDecisions",
    ],
    `${recipe.fixtureId}: runtime public observation`,
  );
  validateRuntimeInvocation(observation, recipe);
  const authored = recipe.publicSurfaceProbe.invocation;
  if (
    observation.observationSchema !==
      "ibex/capsec-runtime-public-observation/1" ||
    observation.legacyObservationCount !== 0 ||
    !Array.isArray(observation.typedDecisions) ||
    observation.typedDecisions.length !== authored?.expectedTypedDecisionCount
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed runtime public observation`,
    );
  }
  const stages = [];
  const actions = new Set();
  const edgeIds = new Set();
  const terminals = new Set();
  const terminalByEdge =
    observation.typedDecisions.length === 0
      ? null
      : coverageTerminalMap(coverage);
  for (const decision of observation.typedDecisions) {
    exactKeys(
      decision,
      ["decisionSet", "gates", "evidence"],
      `${recipe.fixtureId}: observed typed decision`,
    );
    const set = decision.decisionSet;
    if (
      !set?.context ||
      typeof set.context.stage !== "string" ||
      !Array.isArray(set.effects) ||
      !Array.isArray(decision.gates) ||
      decision.gates.length !== set.effects.length
    ) {
      throw new Error(`${recipe.fixtureId}: malformed observed typed decision`);
    }
    stages.push(set.context.stage);
    for (const effect of set.effects) {
      if (typeof effect?.cap !== "string") {
        throw new Error(`${recipe.fixtureId}: observed effect has no action`);
      }
      actions.add(effect.cap);
    }
    for (const gate of decision.gates) {
      const edgeId = gate?.coverageEdgeId;
      if (
        typeof edgeId !== "string" ||
        gate.targetCell !== "complete" ||
        gate.definitionAndEdgePredicatesSatisfied !== true ||
        set.atomicityGroup !== `${edgeId}.decision` ||
        !authored.allowedCoverageEdgeIds.includes(edgeId)
      ) {
        throw new Error(
          `${recipe.fixtureId}: observed an unbound or incomplete typed gate`,
        );
      }
      edgeIds.add(edgeId);
      const terminal = terminalByEdge.get(edgeId);
      if (!terminal) {
        throw new Error(
          `${recipe.fixtureId}: observed an unknown coverage edge`,
        );
      }
      terminals.add(terminal);
    }
    const expectedOutcome =
      authored.expectedResult === "permission-denied" ? "deny" : "allow";
    if (decision.evidence?.outcome !== expectedOutcome) {
      throw new Error(
        `${recipe.fixtureId}: observed typed outcome disagrees with invocation`,
      );
    }
  }
  if (
    canonicalJson(stages) !== canonicalJson(authored.expectedTypedStages) ||
    canonicalJson([...actions].sort(compareText)) !==
      canonicalJson(
        [
          ...(authored.expectedResult === "absent"
            ? []
            : authored.expectedActionIds),
        ].sort(compareText),
      ) ||
    (observation.typedDecisions.length > 0 && edgeIds.size === 0)
  ) {
    throw new Error(
      `${recipe.fixtureId}: observed typed stages, actions, or gates drifted`,
    );
  }

  let terminalObservedKey;
  if (observation.typedDecisions.length === 0) {
    const validZeroDecisionScenario =
      (recipe.classification === "non-capability" &&
        recipe.scenario === "non-capability") ||
      (recipe.classification === "closed" && recipe.scenario === "closed") ||
      recipe.scenario === "absent";
    if (
      !validZeroDecisionScenario ||
      authored.expectedTypedStages.length !== 0 ||
      (authored.expectedResult !== "absent" &&
        authored.expectedActionIds.length !== 0)
    ) {
      throw new Error(
        `${recipe.fixtureId}: absence of a typed decision is not evidence here`,
      );
    }
    const nativeExactAbsence =
      authored.expectedResult === "absent" &&
      observation.invocation.invocationSchema ===
        "ibex/capsec-native-global-invocation/1";
    if (
      nativeExactAbsence &&
      observation.invocation.surfaceObservedKey !== recipe.terminalObservedKey
    ) {
      throw new Error(`${recipe.fixtureId}: malformed exact-absence evidence`);
    }
    const sourceVariantAbsence =
      authored.expectedResult === "absent" &&
      observation.invocation.invocationSchema !==
        "ibex/capsec-native-global-invocation/1";
    terminalObservedKey = sourceVariantAbsence
      ? `${observation.invocation.result.surfaceKind}:${observation.invocation.result.surfaceName}`
      : observation.invocation.surfaceObservedKey;
  } else {
    if (terminals.size !== 1) {
      throw new Error(
        `${recipe.fixtureId}: typed gates selected multiple terminals`,
      );
    }
    terminalObservedKey = [...terminals][0];
  }
  const allowed = recipe.route?.alternatives?.map(
    (alternative) => alternative.terminalObservedKey,
  );
  const exactTargetAbsence =
    authored.expectedResult === "absent" &&
    recipe.expectedObservation?.kind === "target-absence";
  if (
    exactTargetAbsence
      ? allowed?.length !== 0 ||
        terminalObservedKey !== recipe.terminalObservedKey
      : !allowed?.includes(terminalObservedKey)
  ) {
    throw new Error(
      `${recipe.fixtureId}: runtime-derived terminal is outside the bound route`,
    );
  }
  return terminalObservedKey;
}

function validateExecution(execution, recipe, engineBinaryDigest, coverage) {
  exactKeys(
    execution,
    ["fixtureId", "outcome", "executor", "evidence"],
    `${recipe.fixtureId}: public execution`,
  );
  exactKeys(
    execution.evidence,
    [
      "evidenceSchema",
      "fixtureId",
      "planDigest",
      "engineBinaryDigest",
      "probe",
      "terminalObservedKey",
      "exitCode",
      "resultMarker",
      "observation",
      "runtimeObservation",
      "evidenceDigest",
    ],
    `${recipe.fixtureId}: public execution evidence`,
  );
  const evidence = execution.evidence;
  if (
    execution.fixtureId !== recipe.fixtureId ||
    evidence.evidenceSchema !==
      "ibex/capsec-public-surface-fixture-evidence/2" ||
    evidence.fixtureId !== recipe.fixtureId ||
    typeof execution.executor !== "string" ||
    execution.executor.length === 0 ||
    /adapter/iu.test(execution.executor) ||
    evidence.planDigest !== recipe.planDigest ||
    evidence.engineBinaryDigest !== engineBinaryDigest ||
    canonicalJson(evidence.probe) !==
      canonicalJson(recipe.publicSurfaceProbe) ||
    evidence.evidenceDigest !== evidenceDigest(evidence)
  ) {
    throw new Error(
      `${recipe.fixtureId}: adapter-only, stale, or malformed public-surface evidence`,
    );
  }
  const runtimeTerminal = validateRuntimeObservation(
    evidence.runtimeObservation,
    recipe,
    coverage,
  );
  const passedMarker = `ibex-capsec-public-fixture:${recipe.fixtureId}:passed`;
  const failedMarker = `ibex-capsec-public-fixture:${recipe.fixtureId}:failed`;
  const derivedOutcome =
    evidence.exitCode === 0 && evidence.resultMarker === passedMarker
      ? "passed"
      : evidence.exitCode !== 0 || evidence.resultMarker === failedMarker
        ? "failed"
        : null;
  if (!derivedOutcome || derivedOutcome !== execution.outcome) {
    throw new Error(
      `${recipe.fixtureId}: public result marker disagrees with outcome`,
    );
  }
  const expectedObservation = {
    ...recipe.expectedObservation,
    result: derivedOutcome,
  };
  if (
    canonicalJson(evidence.observation) !== canonicalJson(expectedObservation)
  ) {
    throw new Error(
      `${recipe.fixtureId}: public observation selected the wrong branch`,
    );
  }
  if (runtimeTerminal !== evidence.terminalObservedKey) {
    throw new Error(
      `${recipe.fixtureId}: claimed terminal differs from runtime typed gates`,
    );
  }
}

export function validatePublicSurfaceExecutionArtifact(
  artifact,
  {
    recipeCatalog,
    target = null,
    sourceRevision = null,
    sourceTreeDigest = null,
    engine = null,
    coverage = null,
  },
) {
  if (artifact?.adapterEvidenceSchema) {
    throw new Error("adapter-only evidence cannot advertise a target");
  }
  exactKeys(
    artifact,
    [
      "publicSurfaceExecutionSchema",
      "profile",
      "sourceRevision",
      "sourceTreeDigest",
      "target",
      "engine",
      "recipeCatalogDigest",
      "summary",
      "executions",
      "publicSurfaceExecutionDigest",
    ],
    "public-surface execution artifact",
  );
  if (
    artifact.publicSurfaceExecutionSchema !==
      "ibex/capsec-public-surface-executions/1" ||
    artifact.profile !== "ibex/capsec/1" ||
    !Array.isArray(artifact.executions) ||
    artifact.recipeCatalogDigest !== recipeCatalog.recipeCatalogDigest ||
    artifact.publicSurfaceExecutionDigest !==
      computePublicSurfaceExecutionDigest(artifact) ||
    (target && canonicalJson(artifact.target) !== canonicalJson(target)) ||
    (sourceRevision && artifact.sourceRevision !== sourceRevision) ||
    (sourceTreeDigest && artifact.sourceTreeDigest !== sourceTreeDigest) ||
    (engine && canonicalJson(artifact.engine) !== canonicalJson(engine))
  ) {
    throw new Error(
      "public-surface execution artifact has stale or mismatched bindings",
    );
  }
  validateRecipeCatalog(recipeCatalog, { target: artifact.target });
  const recipes = new Map(
    recipeCatalog.recipes.map((recipe) => [recipe.fixtureId, recipe]),
  );
  const seen = new Set();
  for (const execution of artifact.executions) {
    const recipe = recipes.get(execution?.fixtureId);
    if (!recipe || seen.has(execution.fixtureId)) {
      throw new Error(
        "public-surface executions contain an unknown or duplicate fixture",
      );
    }
    seen.add(execution.fixtureId);
    validateExecution(
      execution,
      recipe,
      artifact.engine?.binaryDigest,
      coverage,
    );
  }
  if (
    canonicalJson(artifact.executions.map((row) => row.fixtureId)) !==
    canonicalJson([...seen].sort(compareText))
  ) {
    throw new Error(
      "public-surface executions are not in canonical fixture order",
    );
  }
  if (
    canonicalJson(artifact.summary) !==
    canonicalJson(executionSummary(recipeCatalog, artifact.executions))
  ) {
    throw new Error(
      "public-surface execution summary disagrees with its evidence",
    );
  }
  return artifact;
}

export function assertPublicSurfaceExecutionComplete(
  artifact,
  recipeCatalog,
  options = {},
) {
  assertRecipeCatalogComplete(recipeCatalog, {
    target: options.target ?? artifact.target,
    expectedFixtureIds: options.expectedFixtureIds ?? null,
  });
  validatePublicSurfaceExecutionArtifact(artifact, {
    ...options,
    recipeCatalog,
  });
  if (
    artifact.summary.residualFixtures !== 0 ||
    artifact.summary.missingFixtures !== 0 ||
    artifact.summary.failedFixtures !== 0 ||
    artifact.summary.executedFixtures !== artifact.summary.requiredFixtures ||
    artifact.summary.passedFixtures !== artifact.summary.requiredFixtures
  ) {
    throw new Error(
      "public-surface execution artifact cannot advertise with residual, missing, or failed obligations",
    );
  }
}

export function buildPublicFixtureEvidence({
  recipe,
  engineBinaryDigest,
  runtimeObservation,
  coverage,
  outcome = "passed",
  executor = "ibex-public-surface-harness",
}) {
  const terminalObservedKey = validateRuntimeObservation(
    runtimeObservation,
    recipe,
    coverage,
  );
  const evidence = {
    evidenceSchema: "ibex/capsec-public-surface-fixture-evidence/2",
    fixtureId: recipe.fixtureId,
    planDigest: recipe.planDigest,
    engineBinaryDigest,
    probe: structuredClone(recipe.publicSurfaceProbe),
    terminalObservedKey,
    exitCode: outcome === "passed" ? 0 : 1,
    resultMarker: `ibex-capsec-public-fixture:${recipe.fixtureId}:${outcome}`,
    observation: { ...recipe.expectedObservation, result: outcome },
    runtimeObservation: structuredClone(runtimeObservation),
  };
  evidence.evidenceDigest = evidenceDigest(evidence);
  return {
    fixtureId: recipe.fixtureId,
    outcome,
    executor,
    evidence,
  };
}
