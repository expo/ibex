/**
 * Derive executable CapSec recipe inputs without confusing an adapter check
 * with proof that a public surface reached that adapter.
 *
 * Every required fixture receives exactly one recipe row. A row may contain a
 * decision-adapter probe, but it remains unresolved until an invocation of the
 * selected public surface observes the expected enforcement branch. This is
 * deliberate: static call-graph reachability and a manually selected branch
 * marker are useful diagnostics, not conformance evidence.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — only
 * exact-target executions of every selected branch obligation may promote a
 * target.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";
import { fixtureExecutionPlans } from "./capsec-conformance.mjs";
import { authoredNonCapabilityBuiltinProbe } from "./capsec-builtin-public-probe-templates.mjs";
import { authoredBuiltinPublicProbe } from "./capsec-public-probe-templates.mjs";
import { authoredTargetAbsenceProbe } from "./capsec-target-absence-probe-templates.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : canonicalJson(value), "utf8")
    .digest("base64url")}`;

const FIXTURE_SCENARIOS = [
  "attribution-missing-deny",
  "malformed-branch-facts",
  "snapshot-mismatch-deny",
  "cannot-widen-authority",
  "post-lockdown-invariant",
  "conditional-refinement",
  "missing-attribution",
  "generation-recheck",
  "principal-restore",
  "wrong-principal",
  "branch-selection",
  "non-capability",
  "malformed",
  "no-effect",
  "closed",
  "absent",
  "allow",
  "deny",
].sort((left, right) => right.length - left.length || compareText(left, right));

const ADAPTER_SCENARIOS = new Set([
  "allow",
  "deny",
  "malformed",
  "missing-attribution",
  "wrong-principal",
]);

const ROOT_PRINCIPAL = Object.freeze({
  kind: "root",
  identity: "project-root",
});
const UNPRIVILEGED_PRINCIPAL = Object.freeze({
  kind: "package",
  name: "image-lib",
  integrity: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
  locator: "image-lib@2.4.1",
});

const DERIVED_ACTION_SOURCE = new Map([
  ["clipboard:write", "clipboard:read"],
  ["env:write", "env:read"],
  ["fs:list", "fs:read"],
  ["fs:watch", "fs:read"],
  ["fs:write", "fs:read"],
  ["stdio:query", "stdio:read"],
  ["stdio:raw", "stdio:read"],
  ["stdio:write", "stdio:read"],
]);

function clone(value) {
  return structuredClone(value);
}

export function fixtureScenario(fixtureId) {
  const scenario = FIXTURE_SCENARIOS.find((candidate) =>
    fixtureId.endsWith(`.${candidate}`),
  );
  if (!scenario) {
    throw new Error(`${fixtureId}: unknown fixture scenario`);
  }
  return scenario;
}

function requestedResourceKind(resource) {
  return resource?.requested?.kind ?? resource?.kind ?? null;
}

function exampleForAction(examples, action, resourceKind = null) {
  const sourceAction = DERIVED_ACTION_SOURCE.get(action) ?? action;
  const candidates = examples.filter((row) => row.cap === sourceAction);
  const selected =
    candidates.find(
      (row) => requestedResourceKind(row.resource) === resourceKind,
    ) ?? candidates[0];
  if (!selected) return null;
  const result = clone(selected);
  result.cap = action;
  return result;
}

function actionTemplate(action, occurrences, selectors) {
  const selectorCandidates = selectors.filter(
    (row) => row.cap === (DERIVED_ACTION_SOURCE.get(action) ?? action),
  );
  let occurrence = null;
  let selector = null;
  for (const candidateSelector of selectorCandidates) {
    const candidateOccurrence = exampleForAction(
      occurrences,
      action,
      candidateSelector.resource.kind,
    );
    if (candidateOccurrence) {
      occurrence = candidateOccurrence;
      selector = clone(candidateSelector);
      break;
    }
  }
  occurrence ??= exampleForAction(occurrences, action);
  selector ??= exampleForAction(selectors, action);
  if (!occurrence || !selector) return null;
  selector.cap = action;
  return { occurrence, selector };
}

const COMMIT_OR_LATER = new Set(["commit", "delivery", "repeat", "cleanup"]);
const DISCOVERY_OR_LATER = new Set([
  "discovery",
  "candidate",
  "commit",
  "delivery",
  "repeat",
  "cleanup",
]);

function occurrenceResourceAtStage(input, stage) {
  const resource = clone(input);
  const commitOrLater = COMMIT_OR_LATER.has(stage);
  const discoveryOrLater = DISCOVERY_OR_LATER.has(stage);
  if (resource.kind === "path-occurrence") {
    if (!discoveryOrLater) {
      delete resource.parentObject;
      delete resource.finalObject;
    }
    if (!commitOrLater) delete resource.retainedHandle;
  } else if (resource.kind === "network-occurrence") {
    const publicAddress = "93.184.216.34";
    if (stage === "requested") {
      resource.candidates = [];
      delete resource.selectedCandidate;
      delete resource.verifiedPeer;
      delete resource.connectionId;
    } else if (stage === "candidate") {
      resource.candidates = [publicAddress];
      resource.selectedCandidate = publicAddress;
      delete resource.verifiedPeer;
      delete resource.connectionId;
    } else if (commitOrLater) {
      resource.candidates = [publicAddress];
      resource.selectedCandidate = publicAddress;
      resource.verifiedPeer = {
        address: publicAddress,
        port: resource.requested.port,
      };
      resource.connectionId ??= "connection:conformance:1";
    }
  } else if (resource.kind === "unix-connect-occurrence") {
    if (!discoveryOrLater) delete resource.socketObject;
    if (!commitOrLater) delete resource.connectionId;
  } else if (resource.kind === "listen-occurrence") {
    if (!commitOrLater) {
      delete resource.boundEndpoints;
      delete resource.boundUnixObject;
      delete resource.listenerId;
    }
    if (stage === "delivery" || stage === "repeat") {
      if (resource.requested.kind === "listen-inet") {
        resource.acceptedPeer = {
          address: "127.0.0.1",
          port: resource.boundEndpoints[0].port,
        };
      }
    } else {
      delete resource.acceptedPeer;
      delete resource.acceptedUnixPeer;
    }
  } else if (resource.kind === "dns-occurrence" && stage === "requested") {
    resource.answers = [];
  } else if (resource.kind === "executable-occurrence" && !discoveryOrLater) {
    delete resource.executableObject;
    delete resource.interpreterObject;
  } else if (resource.kind === "device-occurrence" && !commitOrLater) {
    delete resource.deviceIdentity;
  }
  return resource;
}

function effectsForPlan(plan, coverageByEdge) {
  const rows = [];
  for (const edgeId of plan.edgeIds) {
    const edge = coverageByEdge.get(edgeId);
    if (!edge)
      throw new Error(`${plan.fixtureId}: unknown coverage edge ${edgeId}`);
    const logicalBranch = edge.logicalBranches?.find((branch) =>
      plan.fixtureId.includes(`.logical.${branch.id}.`),
    );
    for (const effect of logicalBranch?.effects ?? edge.effects ?? []) {
      if (plan.actionIds.includes(effect.cap)) rows.push(effect);
    }
  }
  const unique = new Map();
  for (const effect of rows) {
    const prior = unique.get(effect.cap);
    if (prior && canonicalJson(prior) !== canonicalJson(effect)) {
      throw new Error(
        `${plan.fixtureId}: action ${effect.cap} has conflicting stage plans`,
      );
    }
    unique.set(effect.cap, effect);
  }
  return [...unique.values()].sort((left, right) =>
    compareText(left.cap, right.cap),
  );
}

function adapterProbeForPlan(
  plan,
  scenario,
  occurrences,
  selectors,
  coverageByEdge,
) {
  if (plan.classification !== "effects" || !ADAPTER_SCENARIOS.has(scenario)) {
    return { probe: null, unavailableReason: null };
  }
  if (plan.actionIds.length === 0) {
    return { probe: null, unavailableReason: "decision-set-has-no-effects" };
  }
  const templates = plan.actionIds.map((action) =>
    actionTemplate(action, occurrences, selectors),
  );
  const missingActions = plan.actionIds.filter(
    (_action, index) => templates[index] === null,
  );
  if (missingActions.length > 0) {
    return {
      probe: null,
      unavailableReason: `missing-action-template:${missingActions.join("+")}`,
    };
  }
  const semanticEffects = effectsForPlan(plan, coverageByEdge);
  if (
    canonicalJson(semanticEffects.map((effect) => effect.cap)) !==
    canonicalJson(plan.actionIds)
  ) {
    return {
      probe: null,
      unavailableReason: "coverage-effect-stage-plan-unavailable",
    };
  }

  const actor = scenario === "deny" ? UNPRIVILEGED_PRINCIPAL : ROOT_PRINCIPAL;
  const constrainedPrincipals =
    scenario === "missing-attribution" ? [] : [actor];
  const effectOwner =
    scenario === "wrong-principal" ? UNPRIVILEGED_PRINCIPAL : actor;
  const templateByAction = new Map(
    plan.actionIds.map((action, index) => [action, templates[index]]),
  );
  const stages = canonicalSet(
    semanticEffects.flatMap((effect) => effect.stages),
  );
  const malformed = scenario === "malformed";
  const probeCases = stages.map((stage, stageIndex) => {
    const activeEffects = semanticEffects.filter((effect) =>
      effect.stages.includes(stage),
    );
    const decisionSet = {
      decisionSetSchema: "ibex/capsec-decision-set/1",
      operationId: `conformance:${taggedDigest(plan).slice(7)}:${stage}`,
      atomicityGroup: `${plan.edgeIds[0]}.decision`,
      combination: "conjunction",
      context: {
        stage,
        actor,
        constrainedPrincipals,
        presentedHandleIds: [],
      },
      effects: activeEffects.map((effect) => ({
        cap: effect.cap,
        effectOwner,
        resource: occurrenceResourceAtStage(
          templateByAction.get(effect.cap).occurrence.resource,
          stage,
        ),
      })),
    };
    const gates = activeEffects.map(() => ({
      coverageEdgeId: plan.edgeIds[0],
      targetCell: "complete",
      definitionAndEdgePredicatesSatisfied: true,
    }));
    return {
      stage,
      actionIds: activeEffects.map((effect) => effect.cap),
      decisionSetJson:
        malformed && stageIndex === 0
          ? '{"decisionSetSchema":'
          : JSON.stringify(decisionSet),
      gatesJson: JSON.stringify(gates),
      expected:
        malformed && stageIndex === 0
          ? { adapter: "error", legacyObservations: 0, typedObservations: 0 }
          : {
              adapter: scenario === "allow" && !malformed ? "allow" : "deny",
              legacyObservations: 0,
              typedObservations: 1,
            },
    };
  });
  // Malformed JSON is rejected before a stage can be decoded. Repeating the
  // same parser obligation for every declared stage would add executions but
  // no semantic coverage.
  if (malformed) probeCases.splice(1);
  return {
    unavailableReason: null,
    probe: {
      kind: "hermes-public-typed-adapter",
      operation: "capsec.conformance.evaluate",
      terminalBranchId: plan.expectedObservation.branchId,
      cases: probeCases,
      requiredFloor:
        scenario === "allow" ? templates.map(({ selector }) => selector) : [],
    },
  };
}

function selectedRows(plan, rowsByBranch) {
  return plan.implementationBranchIds.map((branchId) => {
    const row = rowsByBranch.get(branchId);
    if (!row) throw new Error(`${plan.fixtureId}: unknown branch ${branchId}`);
    return row;
  });
}

function routeForPlan(plan, implementationRows, liveByObservedKey) {
  const alternatives = new Map();
  const ambiguousCallees = new Set();
  const surfaceObservedKeys = new Set();
  for (const row of implementationRows) {
    surfaceObservedKeys.add(row.observedKey);
    const live = liveByObservedKey.get(row.observedKey);
    const routeEvidence = live?.metadata?.enforcementRouteEvidence;
    if (routeEvidence?.kind === "static-builtin-call-graph") {
      if (plan.classification === "non-capability") {
        const route = row.enforcementRoute;
        if (
          route?.kind === "surface-branch" &&
          route.terminalObservedKey === row.observedKey
        ) {
          const accumulated = alternatives.get(row.observedKey) ?? new Set();
          for (const proofPath of route.proofPaths) accumulated.add(proofPath);
          alternatives.set(row.observedKey, accumulated);
        }
        continue;
      }
      for (const callee of routeEvidence.ambiguousCallees ?? []) {
        ambiguousCallees.add(callee);
      }
      for (const terminal of routeEvidence.terminals ?? []) {
        const terminalObservedKey = `native-op:${terminal}`;
        const paths = (routeEvidence.paths ?? []).filter((routePath) =>
          routePath.endsWith(` -> ${terminal}`),
        );
        const accumulated = alternatives.get(terminalObservedKey) ?? new Set();
        for (const routePath of paths) accumulated.add(routePath);
        alternatives.set(terminalObservedKey, accumulated);
      }
      continue;
    }
    const route = row.enforcementRoute;
    const accumulated =
      alternatives.get(route.terminalObservedKey) ?? new Set();
    for (const proofPath of route.proofPaths) accumulated.add(proofPath);
    alternatives.set(route.terminalObservedKey, accumulated);
  }
  return {
    surfaceObservedKeys: canonicalSet(surfaceObservedKeys),
    alternatives: [...alternatives]
      .sort(([left], [right]) => compareText(left, right))
      .map(([terminalObservedKey, proofPaths]) => ({
        terminalObservedKey,
        proofPaths: canonicalSet(proofPaths),
      })),
    ambiguousCallees: canonicalSet(ambiguousCallees),
  };
}

// Public native probes are intentionally opt-in. Source discovery proves the
// installed global and declared JSI arity; this registry supplies only bounded
// arguments/setup whose effects the harness can own and reproduce.
const literalArgument = (value) => ({ kind: "json-literal", value });
const nativeNoEffectTemplate = (
  requiredSourceArity,
  argumentsList = [],
  setup = [],
) =>
  Object.freeze({
    actionIds: [],
    arguments: argumentsList,
    expectedDecisionCounts: { "non-capability": 0 },
    expectedResults: { "non-capability": "return" },
    expectedStages: { "non-capability": [] },
    requiredSourceArity,
    setup,
  });

// Structural lockdown eagerly invokes these installers and then deletes the
// globals before user code can run. Their source registrations are real, but a
// post-load public harness must report them as unavailable rather than claiming
// that a pre-lockdown implementation detail remains callable.
const NATIVE_PUBLIC_POST_LOCKDOWN_ABSENT = new Set([
  "__exactEnsureChildProcess",
  "__exactEnsureDns",
  "__exactEnsureFormData",
  "__exactEnsureFs",
  "__exactEnsureHttp",
  "__exactEnsureNet",
  "__exactEnsureSqlite",
  "__exactEnsureStreamEnhance",
  "__exactEnsureWebCrypto",
  "__exactEnsureWebStorage",
]);

export const NATIVE_PUBLIC_PROBE_TEMPLATES = new Map([
  [
    "__exactTcpConnect",
    Object.freeze({
      actionIds: ["network:connect"],
      arguments: [
        { kind: "harness-loopback-address", family: "ipv4" },
        { kind: "harness-loopback-listener-port" },
      ],
      expectedStages: {
        allow: ["requested", "candidate", "commit", "repeat"],
        deny: ["requested"],
      },
      expectedDecisionCounts: { allow: 4, deny: 1 },
      expectedResults: { allow: "return", deny: "permission-denied" },
      requiredSourceArity: 4,
      setup: [{ kind: "tcp-loopback-listener" }],
    }),
  ],
  ["__exactPerformanceNow", nativeNoEffectTemplate(0)],
  ["__exactPerformanceTimeOrigin", nativeNoEffectTemplate(0)],
  ["__exactSignalNumbers", nativeNoEffectTemplate(0)],
  [
    "__exactAesCbcEncrypt",
    nativeNoEffectTemplate(3, [
      literalArgument("0123456789abcdef"),
      literalArgument("fedcba9876543210"),
      literalArgument("ibex"),
    ]),
  ],
  [
    "__exactAesCtrEncrypt",
    nativeNoEffectTemplate(3, [
      literalArgument("0123456789abcdef"),
      literalArgument("fedcba9876543210"),
      literalArgument("ibex"),
    ]),
  ],
  [
    "__exactAesGcmEncrypt",
    nativeNoEffectTemplate(5, [
      literalArgument("0123456789abcdef"),
      literalArgument("fixture-iv12"),
      literalArgument("ibex"),
      literalArgument("fixture-aad"),
      literalArgument(128),
    ]),
  ],
  [
    "__exactBrotliCompressSync",
    nativeNoEffectTemplate(2, [literalArgument("ibex"), literalArgument(4)]),
  ],
  [
    "__exactBytesToUtf8String",
    nativeNoEffectTemplate(1, [literalArgument("ibex")]),
  ],
  [
    "__exactDeflateSync",
    nativeNoEffectTemplate(4, [
      literalArgument("ibex"),
      literalArgument(6),
      literalArgument(0),
      literalArgument(null),
    ]),
  ],
  [
    "__exactHashSync",
    nativeNoEffectTemplate(2, [
      literalArgument("sha256"),
      literalArgument("ibex"),
    ]),
  ],
  [
    "__exactHashRaw",
    nativeNoEffectTemplate(2, [
      literalArgument("sha256"),
      literalArgument("ibex"),
    ]),
  ],
  [
    "__exactHmacSync",
    nativeNoEffectTemplate(3, [
      literalArgument("sha256"),
      literalArgument("fixture-key"),
      literalArgument("ibex"),
    ]),
  ],
  [
    "__exactHkdf",
    nativeNoEffectTemplate(5, [
      literalArgument("sha256"),
      literalArgument("fixture-ikm"),
      literalArgument("fixture-salt"),
      literalArgument("fixture-info"),
      literalArgument(16),
    ]),
  ],
  [
    "__exactPbkdf2",
    nativeNoEffectTemplate(5, [
      literalArgument("fixture-password"),
      literalArgument("fixture-salt"),
      literalArgument(2),
      literalArgument(16),
      literalArgument("sha256"),
    ]),
  ],
  [
    "__exactScryptSync",
    nativeNoEffectTemplate(6, [
      literalArgument("fixture-password"),
      literalArgument("fixture-salt"),
      literalArgument(16),
      literalArgument(1),
      literalArgument(1),
      literalArgument(16),
    ]),
  ],
  [
    "__exactStringToUtf8Bytes",
    nativeNoEffectTemplate(1, [literalArgument("ibex")]),
  ],
]);

function nativePublicProbeForPlan({
  plan,
  scenario,
  route,
  liveByObservedKey,
}) {
  if (plan.expectedObservation.kind === "target-absence") {
    return { probe: null, unavailableReason: null };
  }
  if (
    route.surfaceObservedKeys.length !== 1 ||
    !route.surfaceObservedKeys[0].startsWith("native-op:")
  ) {
    return { probe: null, unavailableReason: null };
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const live = liveByObservedKey.get(surfaceObservedKey);
  const invocation = live?.metadata?.publicInvocation;
  if (!invocation) {
    return {
      probe: null,
      unavailableReason: "native-public-source-invocation-unavailable",
    };
  }
  if (NATIVE_PUBLIC_POST_LOCKDOWN_ABSENT.has(invocation.globalName)) {
    return {
      probe: null,
      unavailableReason: "native-public-global-removed-by-structural-lockdown",
    };
  }
  const template = NATIVE_PUBLIC_PROBE_TEMPLATES.get(invocation.globalName);
  if (!template) {
    return {
      probe: null,
      unavailableReason: "native-public-arguments-not-authored",
    };
  }
  if (
    !Object.hasOwn(template.expectedStages, scenario) ||
    !Object.hasOwn(template.expectedDecisionCounts, scenario) ||
    !Object.hasOwn(template.expectedResults, scenario)
  ) {
    return {
      probe: null,
      unavailableReason: `native-public-${scenario}-scenario-not-authored`,
    };
  }
  if (
    invocation.arity !== template.requiredSourceArity ||
    canonicalJson(plan.actionIds) !== canonicalJson(template.actionIds)
  ) {
    return {
      probe: null,
      unavailableReason: "native-public-source-descriptor-drift",
    };
  }
  if (
    route.alternatives.length !== 1 ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey ||
    route.ambiguousCallees.length !== 0
  ) {
    return {
      probe: null,
      unavailableReason: "native-public-terminal-route-is-not-exact",
    };
  }
  const sourceDescriptor = clone(invocation);
  return {
    unavailableReason: null,
    probe: {
      kind: "public-surface-invocation",
      surfaceObservedKey,
      command: [
        "cargo",
        "test",
        "--bin",
        "ibex",
        "--features",
        "capsec-conformance-observer",
        "capsec_public_native_recipe_batch",
        "--",
        "--test-threads=1",
      ],
      invocation: {
        invocationSchema: "ibex/capsec-native-global-invocation/1",
        kind: "native-global-function",
        globalName: invocation.globalName,
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        arguments: clone(template.arguments),
        setup: clone(template.setup),
        expectedResult: template.expectedResults[scenario],
        expectedTypedStages: clone(template.expectedStages[scenario]),
        expectedTypedDecisionCount: template.expectedDecisionCounts[scenario],
        allowedCoverageEdgeIds: clone(plan.edgeIds),
        expectedActionIds: clone(plan.actionIds),
      },
    },
  };
}

function residualReasons({
  plan,
  scenario,
  adapterProbe,
  adapterUnavailableReason,
  publicSurfaceProbe,
  publicSurfaceUnavailableReason,
  route,
}) {
  const reasons = [];
  if (plan.expectedObservation.kind === "target-absence") {
    if (!publicSurfaceProbe) reasons.push("target-absence-probe-not-authored");
    return reasons;
  } else if (!publicSurfaceProbe) {
    reasons.push("public-surface-invocation-not-authored");
    if (publicSurfaceUnavailableReason) {
      reasons.push(publicSurfaceUnavailableReason);
    }
  }
  if (plan.classification === "closed" && !publicSurfaceProbe) {
    reasons.push("closed-surface-denial-probe-not-authored");
  } else if (plan.classification === "non-capability" && !publicSurfaceProbe) {
    if (scenario === "non-capability") {
      reasons.push("non-capability-no-decision-probe-not-authored");
    } else {
      reasons.push(`callback-invariant-${scenario}-probe-not-authored`);
    }
  } else if (plan.classification === "effects" && !adapterProbe) {
    if (plan.actionIds.length === 0) {
      reasons.push(`conditional-${scenario}-probe-not-authored`);
    } else if (
      scenario === "branch-selection" ||
      scenario === "malformed-branch-facts"
    ) {
      reasons.push(`conditional-${scenario}-probe-not-authored`);
    } else if (scenario === "conditional-refinement") {
      reasons.push("conditional-refinement-probe-not-authored");
    } else {
      reasons.push(
        adapterUnavailableReason ?? "typed-decision-template-unavailable",
      );
    }
  }
  if (
    route.alternatives.length === 0 &&
    plan.expectedObservation.kind !== "target-absence"
  ) {
    reasons.push("no-static-enforcement-terminal");
  }
  if (route.alternatives.length > 1 && !publicSurfaceProbe) {
    reasons.push("argument-selected-terminal-alternatives-not-authored");
  }
  if (route.ambiguousCallees.length > 0) {
    reasons.push("ambiguous-static-enforcement-route");
  }
  return canonicalSet(reasons);
}

function summarize(recipes) {
  const byScenario = {};
  const residualReasons = {};
  for (const recipe of recipes) {
    byScenario[recipe.scenario] = (byScenario[recipe.scenario] ?? 0) + 1;
    for (const reason of recipe.residualReasons) {
      residualReasons[reason] = (residualReasons[reason] ?? 0) + 1;
    }
  }
  return {
    requiredFixtures: recipes.length,
    fullyExecutableFixtures: recipes.filter(
      (recipe) => recipe.status === "fully-executable",
    ).length,
    adapterExecutableFixtures: recipes.filter(
      (recipe) => recipe.adapterProbe !== null,
    ).length,
    unresolvedFixtures: recipes.filter(
      (recipe) => recipe.status !== "fully-executable",
    ).length,
    byScenario: Object.fromEntries(
      Object.entries(byScenario).sort(([left], [right]) =>
        compareText(left, right),
      ),
    ),
    residualReasons: Object.fromEntries(
      Object.entries(residualReasons).sort(([left], [right]) =>
        compareText(left, right),
      ),
    ),
  };
}

export function buildConformanceRecipeCatalog({
  catalog,
  coverage,
  implementation,
  inventory,
  occurrenceExamples,
  selectorExamples,
  target,
}) {
  const rowsByBranch = new Map(
    implementation.surfaces.map((row) => [row.branchId, row]),
  );
  const coverageByEdge = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  const coverageByObservedKey = new Map(
    coverage.edges.map((edge) => [
      `${edge.surface.kind}:${edge.surface.name}`,
      edge,
    ]),
  );
  const liveSurfaces = inventory.surfaces ?? inventory;
  const liveByObservedKey = new Map(
    liveSurfaces.map((surface) => [surface.observedKey, surface]),
  );
  const occurrences = occurrenceExamples.occurrences ?? [];
  const selectors = selectorExamples.selectors ?? [];
  const recipes = fixtureExecutionPlans(catalog).map((plan) => {
    const scenario = fixtureScenario(plan.fixtureId);
    const rows = selectedRows(plan, rowsByBranch);
    const route = routeForPlan(plan, rows, liveByObservedKey);
    const adapter = adapterProbeForPlan(
      plan,
      scenario,
      occurrences,
      selectors,
      coverageByEdge,
    );
    const adapterProbe = adapter.probe;
    const targetAbsenceProbe = authoredTargetAbsenceProbe({
      plan,
      scenario,
      target,
      coverageByEdge,
      liveByObservedKey,
    });
    const effectBuiltinPublicSurfaceProbe = authoredBuiltinPublicProbe({
      plan,
      scenario,
      route,
      liveByObservedKey,
      coverageByObservedKey,
    });
    const nonCapabilityBuiltinPublicSurfaceProbe =
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario,
        route,
        liveByObservedKey,
      });
    const nativePublicSurface = nativePublicProbeForPlan({
      plan,
      scenario,
      route,
      liveByObservedKey,
    });
    const authoredPublicSurfaceProbes = [
      targetAbsenceProbe,
      effectBuiltinPublicSurfaceProbe,
      nonCapabilityBuiltinPublicSurfaceProbe,
      nativePublicSurface.probe,
    ].filter((probe) => probe !== null);
    if (authoredPublicSurfaceProbes.length > 1) {
      throw new Error(
        `${plan.fixtureId}: multiple public probe authors claimed one fixture`,
      );
    }
    const publicSurfaceProbe = authoredPublicSurfaceProbes[0] ?? null;
    const residual = residualReasons({
      plan,
      scenario,
      adapterProbe,
      adapterUnavailableReason: adapter.unavailableReason,
      publicSurfaceProbe,
      publicSurfaceUnavailableReason:
        effectBuiltinPublicSurfaceProbe === null &&
        nonCapabilityBuiltinPublicSurfaceProbe === null
          ? nativePublicSurface.unavailableReason
          : null,
      route,
    });
    return {
      fixtureId: plan.fixtureId,
      planDigest: taggedDigest(plan),
      classification: plan.classification,
      scenario,
      edgeIds: plan.edgeIds,
      implementationBranchIds: plan.implementationBranchIds,
      enforcementBranchIds: plan.enforcementBranchIds,
      actionIds: plan.actionIds,
      terminalObservedKey: plan.terminalObservedKey,
      expectedObservation: plan.expectedObservation,
      route,
      adapterProbe,
      publicSurfaceProbe,
      status: residual.length === 0 ? "fully-executable" : "unresolved",
      residualReasons: residual,
    };
  });
  recipes.sort((left, right) => compareText(left.fixtureId, right.fixtureId));
  const duplicate = recipes.find(
    (recipe, index) =>
      index > 0 && recipe.fixtureId === recipes[index - 1].fixtureId,
  );
  if (duplicate) throw new Error(`duplicate recipe ${duplicate.fixtureId}`);
  const result = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes,
    summary: summarize(recipes),
  };
  result.recipeCatalogDigest = taggedDigest(result);
  return result;
}

export function computeRecipeCatalogDigest(recipeCatalog) {
  const { recipeCatalogDigest: _digest, ...payload } = recipeCatalog;
  return taggedDigest(payload);
}

function validatePublicSurfaceProbe(recipe) {
  const probe = recipe.publicSurfaceProbe;
  const expectedKind =
    recipe.expectedObservation?.kind === "target-absence"
      ? "target-absence-probe"
      : "public-surface-invocation";
  const allowedSurfaces =
    expectedKind === "target-absence-probe"
      ? [recipe.terminalObservedKey]
      : recipe.route?.surfaceObservedKeys;
  if (
    probe?.kind !== expectedKind ||
    typeof probe.surfaceObservedKey !== "string" ||
    !Array.isArray(allowedSurfaces) ||
    !allowedSurfaces.includes(probe.surfaceObservedKey) ||
    !Array.isArray(probe.command) ||
    probe.command.length === 0 ||
    !probe.command.every((part) => typeof part === "string" && part.length > 0)
  ) {
    throw new Error(
      `${recipe.fixtureId}: complete recipe lacks an exact authored public-surface probe`,
    );
  }
}

export function validateRecipeCatalog(
  recipeCatalog,
  { expectedFixtureIds = null, target = null } = {},
) {
  if (
    recipeCatalog?.recipeCatalogSchema !== "ibex/capsec-executable-recipes/1" ||
    recipeCatalog.profile !== "ibex/capsec/1" ||
    !Array.isArray(recipeCatalog.recipes) ||
    !recipeCatalog.summary ||
    recipeCatalog.recipeCatalogDigest !==
      computeRecipeCatalogDigest(recipeCatalog)
  ) {
    throw new Error("malformed or digest-mismatched executable recipe catalog");
  }
  if (target && canonicalJson(recipeCatalog.target) !== canonicalJson(target)) {
    throw new Error("recipe catalog target differs from the attested target");
  }
  const fixtureIds = recipeCatalog.recipes.map((recipe) => recipe.fixtureId);
  if (
    fixtureIds.some((fixtureId) => typeof fixtureId !== "string") ||
    new Set(fixtureIds).size !== fixtureIds.length ||
    canonicalJson(fixtureIds) !==
      canonicalJson([...fixtureIds].sort(compareText))
  ) {
    throw new Error(
      "recipe catalog fixture ids are missing, duplicate, or noncanonical",
    );
  }
  if (
    expectedFixtureIds &&
    canonicalJson(fixtureIds) !==
      canonicalJson(canonicalSet(expectedFixtureIds))
  ) {
    throw new Error(
      "recipe catalog does not cover the exact required fixture set",
    );
  }
  if (
    canonicalJson(recipeCatalog.summary) !==
    canonicalJson(summarize(recipeCatalog.recipes))
  ) {
    throw new Error("recipe catalog summary disagrees with its recipe rows");
  }
  return recipeCatalog;
}

export function assertRecipeCatalogComplete(recipeCatalog, options = {}) {
  validateRecipeCatalog(recipeCatalog, options);
  if (
    recipeCatalog.summary.fullyExecutableFixtures !==
      recipeCatalog.summary.requiredFixtures ||
    recipeCatalog.summary.unresolvedFixtures !== 0
  ) {
    const residual = Object.entries(recipeCatalog.summary.residualReasons)
      .map(([reason, count]) => `${reason}=${count}`)
      .join(", ");
    throw new Error(
      `CapSec executable recipe catalog is incomplete: ${recipeCatalog.summary.unresolvedFixtures}/${recipeCatalog.summary.requiredFixtures} unresolved (${residual})`,
    );
  }
  for (const recipe of recipeCatalog.recipes) {
    if (
      recipe.status !== "fully-executable" ||
      !Array.isArray(recipe.residualReasons) ||
      recipe.residualReasons.length !== 0
    ) {
      throw new Error(
        `${recipe.fixtureId}: complete catalog retains a residual`,
      );
    }
    validatePublicSurfaceProbe(recipe);
  }
}
