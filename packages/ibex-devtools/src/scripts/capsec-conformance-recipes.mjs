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
import {
  authoredNonCapabilityBuiltinProbe,
  nonCapabilityBuiltinProbeResidualReason,
} from "./capsec-builtin-public-probe-templates.mjs";
import { authoredBuiltinPublicProbe } from "./capsec-public-probe-templates.mjs";
import { authoredCallbackInvariantProbe } from "./capsec-callback-invariant-probe-templates.mjs";
import { authoredClosedPublicProbe } from "./capsec-closed-probe-templates.mjs";
import { authoredStartupPublicProbe } from "./capsec-startup-probe-templates.mjs";
import { authoredStartupEnvironmentProbe } from "./capsec-startup-environment-probe-templates.mjs";
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

function definitionMap(capabilityDefinitions) {
  const definitions = capabilityDefinitions?.definitions;
  if (!Array.isArray(definitions) || definitions.length === 0) {
    throw new Error(
      "recipe generation requires checked capability definitions",
    );
  }
  const byAction = new Map(
    definitions.map((definition) => [definition.id, definition]),
  );
  if (byAction.size !== definitions.length) {
    throw new Error("capability definitions contain duplicate action ids");
  }
  return byAction;
}

function constrainedValue(action, field, current, allowed, preferred = []) {
  if (!Array.isArray(allowed)) return current;
  if (allowed.includes(current)) return current;
  const replacement =
    preferred.find((candidate) => allowed.includes(candidate)) ?? allowed[0];
  if (typeof replacement !== "string") {
    throw new Error(`${action}: ${field} has no registry-valid value`);
  }
  return replacement;
}

// @ref LLP 0021#typed-resources-and-initial-vocabulary — derived adapter
// templates must preserve the target action's exact resource constraints;
// cloning a related action's example cannot invent authority for that action.
function constrainExampleForAction(example, action, definitionByAction) {
  const definition = definitionByAction.get(action);
  if (!definition) throw new Error(`${action}: no capability definition`);
  const resource = example.resource;
  const requested = resource?.requested ?? resource;
  const resourceKind =
    resource?.kind === "path-occurrence"
      ? "path-exact"
      : requestedResourceKind(resource);
  if (!definition.resourceKinds.includes(resourceKind)) {
    throw new Error(
      `${action}: derived ${resourceKind} resource violates its capability definition`,
    );
  }

  const constraints = definition.selectorConstraints ?? {};
  if (constraints.environmentTargets) {
    requested.target = constrainedValue(
      action,
      "environmentTargets",
      requested.target,
      constraints.environmentTargets,
      ["principal-overlay"],
    );
    if (resource.kind === "environment-occurrence") {
      resource.valueOrigin = ["broker-base", "principal-overlay"].includes(
        requested.target,
      )
        ? requested.target
        : "literal";
    }
  }
  if (constraints.stdioStreams) {
    const previousStream = requested.stream;
    requested.stream = constrainedValue(
      action,
      "stdioStreams",
      requested.stream,
      constraints.stdioStreams,
    );
    if (requested.stream !== previousStream) {
      requested.source.identity = `conformance:${requested.source.kind}:${requested.stream}`;
    }
  }
  if (constraints.stdioSourceKinds) {
    const previousSourceKind = requested.source.kind;
    requested.source.kind = constrainedValue(
      action,
      "stdioSourceKinds",
      requested.source.kind,
      constraints.stdioSourceKinds,
    );
    if (requested.source.kind !== previousSourceKind) {
      requested.source.identity = `conformance:${requested.source.kind}:${requested.stream}`;
    }
  }
  if (constraints.closedSurfaceClasses) {
    requested.surfaceClass = constrainedValue(
      action,
      "closedSurfaceClasses",
      requested.surfaceClass,
      constraints.closedSurfaceClasses,
    );
  }
  if (constraints.storageStores) {
    requested.store = constrainedValue(
      action,
      "storageStores",
      requested.store,
      constraints.storageStores,
    );
  }
  return example;
}

function exampleForAction(
  examples,
  action,
  resourceKind = null,
  definitionByAction,
) {
  const sourceAction = DERIVED_ACTION_SOURCE.get(action) ?? action;
  const candidates = examples.filter((row) => row.cap === sourceAction);
  const selected =
    candidates.find(
      (row) => requestedResourceKind(row.resource) === resourceKind,
    ) ?? candidates[0];
  if (!selected) return null;
  const result = clone(selected);
  result.cap = action;
  return constrainExampleForAction(result, action, definitionByAction);
}

function actionTemplate(action, occurrences, selectors, definitionByAction) {
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
      definitionByAction,
    );
    if (candidateOccurrence) {
      occurrence = candidateOccurrence;
      selector = clone(candidateSelector);
      selector.cap = action;
      constrainExampleForAction(selector, action, definitionByAction);
      break;
    }
  }
  occurrence ??= exampleForAction(
    occurrences,
    action,
    null,
    definitionByAction,
  );
  selector ??= exampleForAction(selectors, action, null, definitionByAction);
  if (!occurrence || !selector) return null;
  selector.cap = action;
  return { occurrence, selector };
}

export function deriveAdapterActionTemplate({
  action,
  occurrenceExamples,
  selectorExamples,
  capabilityDefinitions,
}) {
  return actionTemplate(
    action,
    occurrenceExamples.occurrences ?? [],
    selectorExamples.selectors ?? [],
    definitionMap(capabilityDefinitions),
  );
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
  definitionByAction,
) {
  if (plan.classification !== "effects" || !ADAPTER_SCENARIOS.has(scenario)) {
    return { probe: null, unavailableReason: null };
  }
  if (plan.actionIds.length === 0) {
    return { probe: null, unavailableReason: "decision-set-has-no-effects" };
  }
  const templates = plan.actionIds.map((action) =>
    actionTemplate(action, occurrences, selectors, definitionByAction),
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
const harnessNoopCallbackArgument = () => ({ kind: "harness-noop-callback" });
const harnessLoopbackClientHandleArgument = () => ({
  kind: "harness-loopback-client-handle",
});
const harnessFsFileDescriptorArgument = () => ({
  kind: "harness-fs-file-descriptor",
});
const harnessSqliteDatabaseHandleArgument = () => ({
  kind: "harness-sqlite-database-handle",
});
const harnessSqliteStatementHandleArgument = () => ({
  kind: "harness-sqlite-statement-handle",
});
const tcpLoopbackClientSetup = () => [
  { kind: "tcp-loopback-listener" },
  {
    kind: "tcp-loopback-client",
    globalName: "__exactTcpConnect",
    requiredSourceArity: 4,
  },
];
const sqliteMemorySetup = (withStatement = false) => [
  {
    kind: "sqlite-memory-database",
    globalName: "__exactSqliteOpen",
    requiredSourceArity: 2,
  },
  ...(withStatement
    ? [
        {
          kind: "sqlite-memory-statement",
          globalName: "__exactSqlitePrepare",
          requiredSourceArity: 2,
        },
      ]
    : []),
];
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
// retained filesystem controls receive a source-bound descriptor created by
// the harness before the zero-decision invocation is observed.
const fsReadFileSetup = () => [
  {
    kind: "fs-read-file",
    globalName: "__exactFsOpen",
    requiredSourceArity: 4,
  },
];
const nativeResultArgument = (
  globalName,
  requiredSourceArity,
  argumentsList = [],
) => ({
  kind: "native-global-result",
  globalName,
  requiredSourceArity,
  arguments: argumentsList,
});
const tlsEngineArgument = () =>
  nativeResultArgument("__exactTlsEngineNew", 1, [
    literalArgument('{"host":"localhost"}'),
  ]);
const nativeResultPropertyArgument = (
  property,
  globalName,
  requiredSourceArity,
  argumentsList = [],
) => ({
  kind: "native-global-result-property",
  property,
  globalName,
  requiredSourceArity,
  arguments: argumentsList,
});
const generatedKeyArgument = (keyType, property, options = null) =>
  nativeResultPropertyArgument(property, "__exactGenerateKeyPairSync", 3, [
    literalArgument(keyType),
    literalArgument(options),
    literalArgument(null),
  ]);
const nativeNoEffectTemplate = (
  requiredSourceArity,
  argumentsList = [],
  setup = [],
  expectedCleanup = null,
) =>
  Object.freeze({
    actionIds: [],
    arguments: argumentsList,
    ...(expectedCleanup ? { expectedCleanup } : {}),
    expectedDecisionCounts: { "non-capability": 0 },
    expectedResults: { "non-capability": "return" },
    expectedStages: { "non-capability": [] },
    requiredSourceArity,
    setup,
  });
const nativeConditionalNoEffectTemplate = (
  requiredSourceArity,
  argumentsList = [],
  setup = [],
) =>
  Object.freeze({
    actionIds: [],
    arguments: argumentsList,
    expectedDecisionCounts: { "branch-selection": 0, "no-effect": 0 },
    expectedResults: { "branch-selection": "return", "no-effect": "return" },
    expectedStages: { "branch-selection": [], "no-effect": [] },
    requiredSourceArity,
    setup,
  });
const nativeSystemInfoTemplate = (name) =>
  Object.freeze({
    actionIds: ["sys:read"],
    arguments: [],
    expectedDecisionCounts: {
      allow: 2,
      deny: 1,
      malformed: 2,
      "missing-attribution": 2,
      "wrong-principal": 2,
    },
    expectedResults: {
      allow: "return",
      deny: "permission-denied",
      malformed: "return",
      "missing-attribution": "return",
      "wrong-principal": "return",
    },
    expectedStages: {
      allow: ["requested", "commit"],
      deny: ["requested"],
      malformed: ["requested", "commit"],
      "missing-attribution": ["requested", "commit"],
      "wrong-principal": ["requested", "commit"],
    },
    requiredFloor: [
      {
        cap: "sys:read",
        resource: { kind: "system-info", name },
      },
    ],
    requiredSourceArity: 0,
    setup: [],
  });
const nativeCachedSystemInfoTemplate = (name, numericName) =>
  Object.freeze({
    actionIds: ["sys:read"],
    arguments: [literalArgument(numericName)],
    expectedDecisionCounts: {
      allow: 2,
      deny: 1,
      malformed: 2,
      "missing-attribution": 2,
      "wrong-principal": 2,
    },
    expectedResults: {
      allow: "return",
      deny: "permission-denied",
      malformed: "return",
      "missing-attribution": "return",
      "wrong-principal": "return",
    },
    expectedStages: {
      allow: ["requested", "commit"],
      deny: ["requested"],
      malformed: ["requested", "commit"],
      "missing-attribution": ["requested", "commit"],
      "wrong-principal": ["requested", "commit"],
    },
    requiredFloor: [
      {
        cap: "sys:read",
        resource: { kind: "system-info", name },
      },
    ],
    requiredSourceArity: 1,
    setup: [],
  });
const nativeEnvironmentReadTemplate = (name) =>
  Object.freeze({
    actionIds: ["env:read"],
    arguments: [literalArgument(name)],
    expectedDecisionCounts: {
      allow: 2,
      deny: 1,
      malformed: 2,
      "missing-attribution": 2,
      "wrong-principal": 2,
    },
    expectedResults: {
      allow: "return",
      deny: "permission-denied",
      malformed: "return",
      "missing-attribution": "return",
      "wrong-principal": "return",
    },
    expectedStages: {
      allow: ["requested", "commit"],
      deny: ["requested"],
      malformed: ["requested", "commit"],
      "missing-attribution": ["requested", "commit"],
      "wrong-principal": ["requested", "commit"],
    },
    requiredFloor: [
      {
        cap: "env:read",
        resource: {
          kind: "environment-name",
          target: "broker-base",
          name,
        },
      },
    ],
    requiredSourceArity: 1,
    setup: [],
  });
const nativePrintTemplate = () =>
  Object.freeze({
    actionIds: ["stdio:write"],
    arguments: [literalArgument("ibex-capsec-print")],
    expectedDecisionCounts: {
      allow: 3,
      deny: 1,
      malformed: 3,
      "missing-attribution": 3,
      "wrong-principal": 3,
    },
    expectedResults: {
      allow: "return",
      deny: "permission-denied",
      malformed: "return",
      "missing-attribution": "return",
      "wrong-principal": "return",
    },
    expectedStages: {
      allow: ["requested", "commit", "repeat"],
      deny: ["requested"],
      malformed: ["requested", "commit", "repeat"],
      "missing-attribution": ["requested", "commit", "repeat"],
      "wrong-principal": ["requested", "commit", "repeat"],
    },
    requiredFloor: [
      {
        cap: "stdio:write",
        resource: {
          kind: "stdio",
          stream: "stdout",
          source: { kind: "broker", identity: "ibex:console:stdout" },
        },
      },
    ],
    requiredSourceArity: 1,
    setup: [],
  });
const projectPathExactResource = (...components) => ({
  kind: "path-exact",
  path: {
    root: "project",
    components: components.map((value) => ({ encoding: "utf8", value })),
  },
});
const projectPathTreeResource = (...components) => ({
  kind: "path-tree",
  path: {
    root: "project",
    components: components.map((value) => ({ encoding: "utf8", value })),
  },
});
const nativeProjectMetadataTemplate = () =>
  Object.freeze({
    actionIds: ["fs:list"],
    arguments: [literalArgument("Cargo.toml"), literalArgument(null)],
    expectedDecisionCounts: {
      allow: 3,
      deny: 1,
      malformed: 3,
      "missing-attribution": 3,
      "wrong-principal": 3,
    },
    expectedResults: {
      allow: "return",
      deny: "permission-denied",
      malformed: "return",
      "missing-attribution": "return",
      "wrong-principal": "return",
    },
    expectedStages: {
      allow: ["requested", "discovery", "repeat"],
      deny: ["requested"],
      malformed: ["requested", "discovery", "repeat"],
      "missing-attribution": ["requested", "discovery", "repeat"],
      "wrong-principal": ["requested", "discovery", "repeat"],
    },
    requiredFloor: [
      {
        cap: "fs:list",
        resource: projectPathExactResource("Cargo.toml"),
      },
    ],
    requiredSourceArity: 2,
    setup: [],
  });
const nativeProjectStatfsTemplate = () =>
  Object.freeze({
    actionIds: ["fs:list"],
    arguments: [literalArgument("Cargo.toml")],
    expectedDecisionCounts: {
      allow: 3,
      deny: 1,
      malformed: 3,
      "missing-attribution": 3,
      "wrong-principal": 3,
    },
    expectedResults: {
      allow: "return",
      deny: "permission-denied",
      malformed: "return",
      "missing-attribution": "return",
      "wrong-principal": "return",
    },
    expectedStages: {
      allow: ["requested", "discovery", "repeat"],
      deny: ["requested"],
      malformed: ["requested", "discovery", "repeat"],
      "missing-attribution": ["requested", "discovery", "repeat"],
      "wrong-principal": ["requested", "discovery", "repeat"],
    },
    requiredFloor: [
      {
        cap: "fs:list",
        resource: projectPathExactResource("Cargo.toml"),
      },
    ],
    requiredSourceArity: 1,
    setup: [],
  });
const nativeProjectReadFileTemplate = () =>
  Object.freeze({
    actionIds: ["fs:list", "fs:read"],
    arguments: [literalArgument("Cargo.toml"), literalArgument(null)],
    expectedDecisionCounts: {
      allow: 4,
      deny: 1,
      malformed: 4,
      "missing-attribution": 4,
      "wrong-principal": 4,
    },
    expectedResults: {
      allow: "return",
      deny: "permission-denied",
      malformed: "return",
      "missing-attribution": "return",
      "wrong-principal": "return",
    },
    expectedObservedActionIds: {
      malformed: ["fs:list", "fs:read"],
    },
    expectedStages: {
      allow: ["requested", "discovery", "commit", "repeat"],
      deny: ["requested"],
      malformed: ["requested", "discovery", "commit", "repeat"],
      "missing-attribution": ["requested", "discovery", "commit", "repeat"],
      "wrong-principal": ["requested", "discovery", "commit", "repeat"],
    },
    requiredFloor: [
      {
        cap: "fs:list",
        resource: projectPathExactResource("Cargo.toml"),
      },
      {
        cap: "fs:read",
        resource: projectPathExactResource("Cargo.toml"),
      },
    ],
    requiredSourceArity: 2,
    setup: [],
  });
// Structural lockdown eagerly invokes these installers and then deletes the
// globals before user code can run. Their source registrations are real, but a
// post-load public harness must report them as unavailable rather than claiming
// that a pre-lockdown implementation detail remains callable.
const NATIVE_PUBLIC_POST_LOCKDOWN_ABSENT = new Map([
  ["__exactCheckImport", 2],
  ["__exactEnsureChildProcess", 0],
  ["__exactEnsureDns", 0],
  ["__exactEnsureFormData", 0],
  ["__exactEnsureFs", 0],
  ["__exactEnsureHttp", 0],
  ["__exactEnsureNet", 0],
  ["__exactEnsureSqlite", 0],
  ["__exactEnsureStreamEnhance", 0],
  ["__exactEnsureWebCrypto", 0],
  ["__exactEnsureWebStorage", 0],
  ["__exactGrantCapability", 2],
  ["__exactRegisterPackage", 4],
  ["__exactResolveManifestBuiltinInternal", 1],
  ["__exactSetActiveModuleId", 1],
  ["__exactSetPendingPackageId", 1],
  ["__hostCall", 2],
  ["__hostCallAsync", 2],
  ["__ibexBarePackageName", 1],
]);

export const NATIVE_PUBLIC_PROBE_TEMPLATES = new Map([
  ["print", nativePrintTemplate()],
  ["__exactStatfs", nativeProjectStatfsTemplate()],
  [
    "__exactAuthorizeSystemInfo",
    nativeCachedSystemInfoTemplate("platform", 11),
  ],
  [
    "queueMicrotask",
    nativeNoEffectTemplate(1, [harnessNoopCallbackArgument()]),
  ],
  [
    "setInterval",
    nativeNoEffectTemplate(2, [
      harnessNoopCallbackArgument(),
      literalArgument(60_000),
    ]),
  ],
  [
    "setTimeout",
    nativeNoEffectTemplate(2, [
      harnessNoopCallbackArgument(),
      literalArgument(60_000),
    ]),
  ],
  [
    "clearTimeout",
    nativeNoEffectTemplate(1, [
      nativeResultArgument("setTimeout", 2, [
        harnessNoopCallbackArgument(),
        literalArgument(60_000),
      ]),
    ]),
  ],
  [
    "clearInterval",
    nativeNoEffectTemplate(1, [
      nativeResultArgument("setInterval", 2, [
        harnessNoopCallbackArgument(),
        literalArgument(60_000),
      ]),
    ]),
  ],
  [
    "__exactTimerRef",
    nativeNoEffectTemplate(1, [
      nativeResultArgument("setTimeout", 2, [
        harnessNoopCallbackArgument(),
        literalArgument(60_000),
      ]),
    ]),
  ],
  [
    "__exactTimerUnref",
    nativeNoEffectTemplate(1, [
      nativeResultArgument("setTimeout", 2, [
        harnessNoopCallbackArgument(),
        literalArgument(60_000),
      ]),
    ]),
  ],
  [
    "__exactHandleScoped",
    nativeNoEffectTemplate(2, [literalArgument(0), literalArgument("fs:read")]),
  ],
  ["__exactRevokeHandle", nativeNoEffectTemplate(1, [literalArgument(0)])],
  [
    "__exactPermissionRequest",
    nativeNoEffectTemplate(1, [literalArgument("capsec:unknown")]),
  ],
  [
    "__exactPermissionRevoke",
    nativeNoEffectTemplate(1, [literalArgument("capsec:unknown")]),
  ],
  [
    "__exactPermissionStatus",
    nativeNoEffectTemplate(1, [literalArgument("capsec:unknown")]),
  ],
  [
    "__exactTypedPermissionRequest",
    nativeNoEffectTemplate(1, [literalArgument({})]),
  ],
  [
    "__exactTypedPermissionRevoke",
    nativeNoEffectTemplate(1, [literalArgument("unknown-grant")]),
  ],
  [
    "__exactTypedHandleMint",
    nativeNoEffectTemplate(1, [literalArgument({})]),
  ],
  [
    "__exactTypedHandleRevoke",
    nativeNoEffectTemplate(1, [literalArgument("unknown-handle")]),
  ],
  ["__exactHttpOwner", nativeNoEffectTemplate(1, [literalArgument(0)])],
  [
    "__exactHttpRespondAbort",
    nativeNoEffectTemplate(2, [literalArgument(0), literalArgument(0)]),
  ],
  [
    "__exactHttpClose",
    nativeNoEffectTemplate(2, [literalArgument(0), literalArgument(0)]),
  ],
  [
    "__exactHttpSetRef",
    nativeNoEffectTemplate(2, [literalArgument(0), literalArgument(0)]),
  ],
  [
    "__exactSpawnCloseStdin",
    nativeNoEffectTemplate(2, [literalArgument(0), literalArgument("stdin")]),
  ],
  ["__exactSpawnDispose", nativeNoEffectTemplate(1, [literalArgument(0)])],
  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // authority helpers must prove their exact refusal branches without
  // fabricating a capability or retained process handle.
  ["__exactCapabilityCheck", nativeNoEffectTemplate(1)],
  ["__exactCreateHandle", nativeNoEffectTemplate(1)],
  [
    "__exactSpawnSetReferenced",
    Object.freeze({
      actionIds: [],
      arguments: [literalArgument(0), literalArgument(false)],
      expectedDecisionCounts: { "non-capability": 0 },
      expectedResults: { "non-capability": "invalid-handle" },
      expectedStages: { "non-capability": [] },
      requiredSourceArity: 2,
      setup: [],
    }),
  ],
  [
    "__exactFsClose",
    Object.freeze({
      ...nativeNoEffectTemplate(
        1,
        [harnessFsFileDescriptorArgument()],
        fsReadFileSetup(),
        "consumed-fs-file-descriptor",
      ),
      requiredFloor: [
        {
          cap: "fs:list",
          resource: projectPathExactResource("Cargo.toml"),
        },
        {
          cap: "fs:read",
          resource: projectPathExactResource("Cargo.toml"),
        },
      ],
    }),
  ],
  [
    "__exactFsCloseAsync",
    Object.freeze({
      ...nativeNoEffectTemplate(
        1,
        [harnessFsFileDescriptorArgument()],
        fsReadFileSetup(),
        "consumed-fs-file-descriptor",
      ),
      completion: {
        kind: "event-loop-quiescence",
        timeoutMilliseconds: 1_000,
      },
      requiredFloor: [
        {
          cap: "fs:list",
          resource: projectPathExactResource("Cargo.toml"),
        },
        {
          cap: "fs:read",
          resource: projectPathExactResource("Cargo.toml"),
        },
      ],
    }),
  ],
  [
    "__exactTcpConnect",
    Object.freeze({
      actionIds: ["network:connect"],
      arguments: [
        { kind: "harness-loopback-address", family: "ipv4" },
        { kind: "harness-loopback-listener-port" },
      ],
      expectedStages: {
        allow: ["requested", "candidate", "commit"],
        deny: ["requested"],
        malformed: ["requested", "candidate", "commit"],
        "missing-attribution": ["requested", "candidate", "commit"],
        "wrong-principal": ["requested", "candidate", "commit"],
      },
      expectedDecisionCounts: {
        allow: 3,
        deny: 1,
        malformed: 3,
        "missing-attribution": 3,
        "wrong-principal": 3,
      },
      expectedResults: {
        allow: "return",
        deny: "permission-denied",
        malformed: "return",
        "missing-attribution": "return",
        "wrong-principal": "return",
      },
      requiredSourceArity: 4,
      setup: [{ kind: "tcp-loopback-listener" }],
    }),
  ],
  [
    "__exactTcpClose",
    nativeNoEffectTemplate(
      1,
      [harnessLoopbackClientHandleArgument()],
      tcpLoopbackClientSetup(),
    ),
  ],
  [
    "__exactTcpReset",
    nativeNoEffectTemplate(
      1,
      [harnessLoopbackClientHandleArgument()],
      tcpLoopbackClientSetup(),
    ),
  ],
  [
    "__exactTcpShutdown",
    nativeNoEffectTemplate(
      2,
      [harnessLoopbackClientHandleArgument(), literalArgument(1)],
      tcpLoopbackClientSetup(),
    ),
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
    "__exactAesCbcDecrypt",
    nativeNoEffectTemplate(3, [
      literalArgument("0123456789abcdef"),
      literalArgument("fedcba9876543210"),
      nativeResultArgument("__exactAesCbcEncrypt", 3, [
        literalArgument("0123456789abcdef"),
        literalArgument("fedcba9876543210"),
        literalArgument("ibex"),
      ]),
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
    "__exactAesGcmDecrypt",
    nativeNoEffectTemplate(5, [
      literalArgument("0123456789abcdef"),
      literalArgument("fixture-iv12"),
      nativeResultArgument("__exactAesGcmEncrypt", 5, [
        literalArgument("0123456789abcdef"),
        literalArgument("fixture-iv12"),
        literalArgument("ibex"),
        literalArgument("fixture-aad"),
        literalArgument(128),
      ]),
      literalArgument("fixture-aad"),
      literalArgument(128),
    ]),
  ],
  [
    "__exactEcdhDeriveBits",
    nativeNoEffectTemplate(3, [
      literalArgument("P-256"),
      generatedKeyArgument("ec", "privateKey", { namedCurve: "P-256" }),
      generatedKeyArgument("ec", "publicKey", { namedCurve: "P-256" }),
    ]),
  ],
  [
    "__exactEcdsaSign",
    nativeNoEffectTemplate(4, [
      literalArgument("P-256"),
      literalArgument("SHA-256"),
      generatedKeyArgument("ec", "privateKey", { namedCurve: "P-256" }),
      literalArgument("ibex"),
    ]),
  ],
  [
    "__exactEcdsaVerify",
    nativeNoEffectTemplate(5, [
      literalArgument("P-256"),
      literalArgument("SHA-256"),
      generatedKeyArgument("ec", "publicKey", { namedCurve: "P-256" }),
      nativeResultArgument("__exactEcdsaSign", 4, [
        literalArgument("P-256"),
        literalArgument("SHA-256"),
        generatedKeyArgument("ec", "privateKey", { namedCurve: "P-256" }),
        literalArgument("ibex"),
      ]),
      literalArgument("ibex"),
    ]),
  ],
  [
    "__exactEd25519Sign",
    nativeNoEffectTemplate(2, [
      generatedKeyArgument("ed25519", "privateKey"),
      literalArgument("ibex"),
    ]),
  ],
  [
    "__exactEd25519Verify",
    nativeNoEffectTemplate(3, [
      generatedKeyArgument("ed25519", "publicKey"),
      nativeResultArgument("__exactEd25519Sign", 2, [
        generatedKeyArgument("ed25519", "privateKey"),
        literalArgument("ibex"),
      ]),
      literalArgument("ibex"),
    ]),
  ],
  [
    "__exactEvpCipherEncrypt",
    nativeNoEffectTemplate(4, [
      literalArgument("aes-128-cbc"),
      literalArgument("0123456789abcdef"),
      literalArgument("fedcba9876543210"),
      literalArgument("ibex"),
    ]),
  ],
  [
    "__exactEvpCipherDecrypt",
    nativeNoEffectTemplate(5, [
      literalArgument("aes-128-cbc"),
      literalArgument("0123456789abcdef"),
      literalArgument("fedcba9876543210"),
      nativeResultArgument("__exactEvpCipherEncrypt", 4, [
        literalArgument("aes-128-cbc"),
        literalArgument("0123456789abcdef"),
        literalArgument("fedcba9876543210"),
        literalArgument("ibex"),
      ]),
      literalArgument(null),
    ]),
  ],
  [
    "__exactExportKeyPkcs8",
    nativeNoEffectTemplate(2, [
      literalArgument("rsa"),
      generatedKeyArgument("rsa", "privateKey", { modulusLength: 1024 }),
    ]),
  ],
  [
    "__exactExportKeySpki",
    nativeNoEffectTemplate(2, [
      literalArgument("rsa"),
      generatedKeyArgument("rsa", "publicKey", { modulusLength: 1024 }),
    ]),
  ],
  [
    "__exactImportKeyPkcs8",
    nativeNoEffectTemplate(1, [
      nativeResultArgument("__exactExportKeyPkcs8", 2, [
        literalArgument("rsa"),
        generatedKeyArgument("rsa", "privateKey", { modulusLength: 1024 }),
      ]),
    ]),
  ],
  [
    "__exactImportKeySpki",
    nativeNoEffectTemplate(1, [
      nativeResultArgument("__exactExportKeySpki", 2, [
        literalArgument("rsa"),
        generatedKeyArgument("rsa", "publicKey", { modulusLength: 1024 }),
      ]),
    ]),
  ],
  [
    "__exactRsaOaepEncrypt",
    nativeNoEffectTemplate(4, [
      generatedKeyArgument("rsa", "publicKey", { modulusLength: 1024 }),
      literalArgument("SHA-256"),
      literalArgument(""),
      literalArgument("ibex"),
    ]),
  ],
  [
    "__exactRsaOaepDecrypt",
    nativeNoEffectTemplate(4, [
      generatedKeyArgument("rsa", "privateKey", { modulusLength: 1024 }),
      literalArgument("SHA-256"),
      literalArgument(""),
      nativeResultArgument("__exactRsaOaepEncrypt", 4, [
        generatedKeyArgument("rsa", "publicKey", { modulusLength: 1024 }),
        literalArgument("SHA-256"),
        literalArgument(""),
        literalArgument("ibex"),
      ]),
    ]),
  ],
  [
    "__exactX25519DeriveBits",
    nativeNoEffectTemplate(2, [
      generatedKeyArgument("x25519", "privateKey"),
      generatedKeyArgument("x25519", "publicKey"),
    ]),
  ],
  [
    "__exactBrotliCompressSync",
    nativeNoEffectTemplate(2, [literalArgument("ibex"), literalArgument(4)]),
  ],
  [
    "__exactBrotliDecompressSync",
    nativeNoEffectTemplate(4, [
      nativeResultArgument("__exactBrotliCompressSync", 2, [
        literalArgument("ibex"),
        literalArgument(4),
      ]),
      literalArgument(true),
      literalArgument(0),
      literalArgument(1024),
    ]),
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
    "__exactInflateSync",
    nativeNoEffectTemplate(6, [
      nativeResultArgument("__exactDeflateSync", 4, [
        literalArgument("ibex"),
        literalArgument(6),
        literalArgument(0),
        literalArgument(null),
      ]),
      literalArgument(0),
      literalArgument(true),
      literalArgument(0),
      literalArgument(null),
      literalArgument(1024),
    ]),
  ],
  [
    "__exactGenerateKeyPairSync",
    nativeNoEffectTemplate(3, [
      literalArgument("ec"),
      literalArgument({ namedCurve: "P-256" }),
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
  ["__exactGetCpuCount", nativeSystemInfoTemplate("cpus")],
  ["__exactGetCwd", nativeSystemInfoTemplate("cwd")],
  ["__exactGetEnv", nativeEnvironmentReadTemplate("PATH")],
  ["__exactGetFreeMem", nativeSystemInfoTemplate("memory")],
  ["__exactGetHostname", nativeSystemInfoTemplate("hostname")],
  ["__exactGetLoadAvg", nativeSystemInfoTemplate("load-average")],
  [
    "__exactGetNetworkInterfaces",
    nativeSystemInfoTemplate("network-interfaces"),
  ],
  ["__exactGetProcessRSS", nativeSystemInfoTemplate("memory")],
  ["__exactGetTotalMem", nativeSystemInfoTemplate("memory")],
  ["__exactGetUptime", nativeSystemInfoTemplate("uptime")],
  ["__exactGetUserInfo", nativeSystemInfoTemplate("user")],
  ["__exactLstat", nativeProjectMetadataTemplate()],
  ["__exactReadFile", nativeProjectReadFileTemplate()],
  ["__exactRealpath", nativeProjectMetadataTemplate()],
  ["__exactStat", nativeProjectMetadataTemplate()],
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
  ["__exactRandomBytes", nativeNoEffectTemplate(1, [literalArgument(16)])],
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
    "__exactSignSync",
    nativeNoEffectTemplate(5, [
      literalArgument("SHA256"),
      literalArgument("ibex"),
      generatedKeyArgument("rsa", "privateKey", { modulusLength: 1024 }),
      literalArgument(null),
      literalArgument(null),
    ]),
  ],
  [
    "__exactSqliteClose",
    nativeNoEffectTemplate(
      1,
      [harnessSqliteDatabaseHandleArgument()],
      sqliteMemorySetup(),
    ),
  ],
  [
    "__exactSqliteExpandedSql",
    nativeNoEffectTemplate(
      1,
      [harnessSqliteStatementHandleArgument()],
      sqliteMemorySetup(true),
    ),
  ],
  [
    "__exactSqliteFinalize",
    nativeNoEffectTemplate(
      1,
      [harnessSqliteStatementHandleArgument()],
      sqliteMemorySetup(true),
    ),
  ],
  [
    "__exactSqliteInTransaction",
    nativeNoEffectTemplate(
      1,
      [harnessSqliteDatabaseHandleArgument()],
      sqliteMemorySetup(),
    ),
  ],
  [
    "__exactStringToUtf8Bytes",
    nativeNoEffectTemplate(1, [literalArgument("ibex")]),
  ],
  [
    "__exactZlibCreate",
    nativeNoEffectTemplate(
      5,
      [
        literalArgument(0),
        literalArgument(0),
        literalArgument(-1),
        literalArgument(0),
        literalArgument(null),
      ],
      [],
      "closed-zlib-stream",
    ),
  ],
  [
    "__exactZlibCheckOwner",
    nativeNoEffectTemplate(
      1,
      [
        nativeResultArgument("__exactZlibCreate", 5, [
          literalArgument(0),
          literalArgument(0),
          literalArgument(-1),
          literalArgument(0),
          literalArgument(null),
        ]),
      ],
      [],
      "closed-zlib-stream",
    ),
  ],
  [
    "__exactZlibClose",
    nativeNoEffectTemplate(
      1,
      [
        nativeResultArgument("__exactZlibCreate", 5, [
          literalArgument(0),
          literalArgument(0),
          literalArgument(-1),
          literalArgument(0),
          literalArgument(null),
        ]),
      ],
      [],
      "consumed-zlib-stream",
    ),
  ],
  [
    "__exactZlibParams",
    nativeNoEffectTemplate(
      3,
      [
        nativeResultArgument("__exactZlibCreate", 5, [
          literalArgument(0),
          literalArgument(0),
          literalArgument(-1),
          literalArgument(0),
          literalArgument(null),
        ]),
        literalArgument(6),
        literalArgument(0),
      ],
      [],
      "closed-zlib-stream",
    ),
  ],
  [
    "__exactZlibWrite",
    nativeNoEffectTemplate(
      6,
      [
        nativeResultArgument("__exactZlibCreate", 5, [
          literalArgument(0),
          literalArgument(0),
          literalArgument(-1),
          literalArgument(0),
          literalArgument(null),
        ]),
        literalArgument("ibex"),
        literalArgument(0),
        literalArgument(true),
        literalArgument(false),
        literalArgument(1024),
      ],
      [],
      "closed-zlib-stream",
    ),
  ],
  [
    "__exactTlsOwnerToken",
    nativeNoEffectTemplate(
      2,
      [literalArgument("new")],
      [],
      "closed-tls-owner-token",
    ),
  ],
  [
    "__exactNetOwner",
    nativeNoEffectTemplate(3, [literalArgument("new")], [], "none"),
  ],
  [
    "__exactTlsEngineNew",
    nativeNoEffectTemplate(
      1,
      [literalArgument('{"host":"localhost"}')],
      [],
      "closed-tls-engine",
    ),
  ],
  [
    "__exactTlsEngineClose",
    nativeNoEffectTemplate(1, [tlsEngineArgument()], [], "consumed-tls-engine"),
  ],
  [
    "__exactTlsEnginePeerCerts",
    nativeNoEffectTemplate(1, [tlsEngineArgument()], [], "closed-tls-engine"),
  ],
  [
    "__exactTlsEngineReadPlain",
    nativeNoEffectTemplate(
      2,
      [tlsEngineArgument(), literalArgument(1024)],
      [],
      "closed-tls-engine",
    ),
  ],
  [
    "__exactTlsEngineReadTls",
    nativeNoEffectTemplate(
      2,
      [tlsEngineArgument(), literalArgument(1024)],
      [],
      "closed-tls-engine",
    ),
  ],
  [
    "__exactTlsEngineShutdown",
    nativeNoEffectTemplate(1, [tlsEngineArgument()], [], "closed-tls-engine"),
  ],
  [
    "__exactTlsEngineStatus",
    nativeNoEffectTemplate(1, [tlsEngineArgument()], [], "closed-tls-engine"),
  ],
  [
    "__exactTlsEngineTransportEof",
    nativeNoEffectTemplate(1, [tlsEngineArgument()], [], "closed-tls-engine"),
  ],
  [
    "__exactTlsEngineWritePlain",
    nativeNoEffectTemplate(
      2,
      [
        tlsEngineArgument(),
        nativeResultArgument("__exactStringToUtf8Bytes", 1, [
          literalArgument("ibex"),
        ]),
      ],
      [],
      "closed-tls-engine",
    ),
  ],
  [
    "__exactTlsEngineWriteTls",
    nativeNoEffectTemplate(
      2,
      [
        tlsEngineArgument(),
        nativeResultArgument("__exactStringToUtf8Bytes", 1, [
          literalArgument(""),
        ]),
      ],
      [],
      "closed-tls-engine",
    ),
  ],
  [
    "__exactUdpClose",
    nativeNoEffectTemplate(1, [
      nativeResultArgument("__exactUdpSocket", 1, [literalArgument("udp4")]),
    ]),
  ],
  ["__exactUdpSocket", nativeNoEffectTemplate(1, [literalArgument("udp4")])],
  [
    "__exactVerifySync",
    nativeNoEffectTemplate(6, [
      literalArgument("SHA256"),
      nativeResultArgument("__exactSignSync", 5, [
        literalArgument("SHA256"),
        literalArgument("ibex"),
        generatedKeyArgument("rsa", "privateKey", { modulusLength: 1024 }),
        literalArgument(null),
        literalArgument(null),
      ]),
      literalArgument("ibex"),
      generatedKeyArgument("rsa", "publicKey", { modulusLength: 1024 }),
      literalArgument(null),
      literalArgument(null),
    ]),
  ],
]);

const NATIVE_PUBLIC_LOGICAL_BRANCH_PROBE_TEMPLATES = new Map([
  [
    "__exactFsPathAsync",
    new Map([
      [
        "mkdir",
        Object.freeze({
          actionIds: ["fs:list", "fs:write"],
          arguments: [
            literalArgument("mkdir"),
            literalArgument("target/ibex-capsec-fspathasync-mkdir"),
            literalArgument(null),
            literalArgument(0),
            literalArgument(0),
            literalArgument(0),
          ],
          completion: {
            kind: "event-loop-quiescence",
            timeoutMilliseconds: 1_000,
          },
          additionalAllowedCoverageObservedKeys: ["native-op:__exactMkdir"],
          expectedCleanup: "removed-created-directory",
          expectedDecisionCounts: {
            allow: 4,
            "branch-selection": 4,
            deny: 1,
            malformed: 4,
            "missing-attribution": 4,
            "wrong-principal": 4,
          },
          expectedObservedActionIds: {
            malformed: ["fs:list", "fs:write"],
          },
          expectedResults: {
            allow: "return",
            "branch-selection": "return",
            deny: "permission-denied",
            malformed: "return",
            "missing-attribution": "return",
            "wrong-principal": "return",
          },
          expectedStages: {
            allow: ["requested", "discovery", "discovery", "commit"],
            "branch-selection": [
              "requested",
              "discovery",
              "discovery",
              "commit",
            ],
            deny: ["requested"],
            malformed: ["requested", "discovery", "discovery", "commit"],
            "missing-attribution": [
              "requested",
              "discovery",
              "discovery",
              "commit",
            ],
            "wrong-principal": [
              "requested",
              "discovery",
              "discovery",
              "commit",
            ],
          },
          requiredFloor: [
            {
              cap: "fs:list",
              resource: projectPathExactResource(
                "target",
                "ibex-capsec-fspathasync-mkdir",
              ),
            },
            {
              cap: "fs:write",
              resource: projectPathExactResource(
                "target",
                "ibex-capsec-fspathasync-mkdir",
              ),
            },
          ],
          requiredSourceArity: 6,
          setup: [],
        }),
      ],
      [
        "mkdtemp",
        Object.freeze({
          actionIds: ["fs:list", "fs:write"],
          arguments: [
            literalArgument("mkdtemp"),
            literalArgument("target/ibex-capsec-fspathasync-mkdtemp/"),
            literalArgument(null),
            literalArgument(0),
            literalArgument(0),
            literalArgument(0),
          ],
          completion: {
            kind: "event-loop-quiescence",
            timeoutMilliseconds: 1_000,
          },
          additionalAllowedCoverageObservedKeys: ["native-op:__exactMkdir"],
          expectedCleanup: "removed-created-directory",
          expectedDecisionCounts: {
            allow: 4,
            "branch-selection": 4,
            deny: 1,
            malformed: 4,
            "missing-attribution": 4,
            "wrong-principal": 4,
          },
          expectedObservedActionIds: {
            malformed: ["fs:list", "fs:write"],
          },
          expectedResults: {
            allow: "return",
            "branch-selection": "return",
            deny: "permission-denied",
            malformed: "return",
            "missing-attribution": "return",
            "wrong-principal": "return",
          },
          expectedStages: {
            allow: ["requested", "discovery", "discovery", "commit"],
            "branch-selection": [
              "requested",
              "discovery",
              "discovery",
              "commit",
            ],
            deny: ["requested"],
            malformed: ["requested", "discovery", "discovery", "commit"],
            "missing-attribution": [
              "requested",
              "discovery",
              "discovery",
              "commit",
            ],
            "wrong-principal": [
              "requested",
              "discovery",
              "discovery",
              "commit",
            ],
          },
          requiredFloor: [
            {
              cap: "fs:list",
              resource: projectPathTreeResource(
                "target",
                "ibex-capsec-fspathasync-mkdtemp",
              ),
            },
            {
              cap: "fs:write",
              resource: projectPathTreeResource(
                "target",
                "ibex-capsec-fspathasync-mkdtemp",
              ),
            },
          ],
          requiredSourceArity: 6,
          setup: [],
        }),
      ],
      [
        "readdir",
        Object.freeze({
          actionIds: ["fs:list"],
          arguments: [
            literalArgument("readdir"),
            literalArgument("capsec"),
            literalArgument(null),
            literalArgument(0),
            literalArgument(0),
            literalArgument(0),
          ],
          completion: {
            kind: "event-loop-quiescence",
            timeoutMilliseconds: 1_000,
          },
          additionalAllowedCoverageObservedKeys: ["native-op:__exactReaddir"],
          expectedDecisionCounts: {
            allow: 4,
            "branch-selection": 4,
            deny: 1,
            malformed: 4,
            "missing-attribution": 4,
            "wrong-principal": 4,
          },
          expectedResults: {
            allow: "return",
            "branch-selection": "return",
            deny: "permission-denied",
            malformed: "return",
            "missing-attribution": "return",
            "wrong-principal": "return",
          },
          expectedStages: {
            allow: ["requested", "discovery", "repeat", "repeat"],
            "branch-selection": ["requested", "discovery", "repeat", "repeat"],
            deny: ["requested"],
            malformed: ["requested", "discovery", "repeat", "repeat"],
            "missing-attribution": [
              "requested",
              "discovery",
              "repeat",
              "repeat",
            ],
            "wrong-principal": ["requested", "discovery", "repeat", "repeat"],
          },
          requiredFloor: [
            {
              cap: "fs:list",
              resource: projectPathExactResource("capsec"),
            },
          ],
          requiredSourceArity: 6,
          setup: [],
        }),
      ],
      [
        "realpath",
        Object.freeze({
          actionIds: ["fs:list"],
          arguments: [
            literalArgument("realpath"),
            literalArgument("Cargo.toml"),
            literalArgument(null),
            literalArgument(0),
            literalArgument(0),
            literalArgument(0),
          ],
          completion: {
            kind: "event-loop-quiescence",
            timeoutMilliseconds: 1_000,
          },
          additionalAllowedCoverageObservedKeys: ["native-op:__exactRealpath"],
          expectedDecisionCounts: {
            allow: 4,
            "branch-selection": 4,
            deny: 1,
            malformed: 4,
            "missing-attribution": 4,
            "wrong-principal": 4,
          },
          expectedResults: {
            allow: "return",
            "branch-selection": "return",
            deny: "permission-denied",
            malformed: "return",
            "missing-attribution": "return",
            "wrong-principal": "return",
          },
          expectedStages: {
            allow: ["requested", "discovery", "repeat", "repeat"],
            "branch-selection": ["requested", "discovery", "repeat", "repeat"],
            deny: ["requested"],
            malformed: ["requested", "discovery", "repeat", "repeat"],
            "missing-attribution": [
              "requested",
              "discovery",
              "repeat",
              "repeat",
            ],
            "wrong-principal": ["requested", "discovery", "repeat", "repeat"],
          },
          requiredFloor: [
            {
              cap: "fs:list",
              resource: projectPathExactResource("Cargo.toml"),
            },
          ],
          requiredSourceArity: 6,
          setup: [],
        }),
      ],
      [
        "statfs",
        Object.freeze({
          actionIds: ["fs:list"],
          arguments: [
            literalArgument("statfs"),
            literalArgument("Cargo.toml"),
            literalArgument(null),
            literalArgument(0),
            literalArgument(0),
            literalArgument(0),
          ],
          completion: {
            kind: "event-loop-quiescence",
            timeoutMilliseconds: 1_000,
          },
          expectedDecisionCounts: {
            allow: 4,
            "branch-selection": 4,
            deny: 1,
            malformed: 4,
            "missing-attribution": 4,
            "wrong-principal": 4,
          },
          expectedResults: {
            allow: "return",
            "branch-selection": "return",
            deny: "permission-denied",
            malformed: "return",
            "missing-attribution": "return",
            "wrong-principal": "return",
          },
          expectedStages: {
            allow: ["requested", "discovery", "repeat", "repeat"],
            "branch-selection": ["requested", "discovery", "repeat", "repeat"],
            deny: ["requested"],
            malformed: ["requested", "discovery", "repeat", "repeat"],
            "missing-attribution": [
              "requested",
              "discovery",
              "repeat",
              "repeat",
            ],
            "wrong-principal": ["requested", "discovery", "repeat", "repeat"],
          },
          requiredFloor: [
            {
              cap: "fs:list",
              resource: projectPathExactResource("Cargo.toml"),
            },
          ],
          requiredSourceArity: 6,
          setup: [],
        }),
      ],
      [
        "truncate",
        Object.freeze({
          actionIds: ["fs:list", "fs:write"],
          arguments: [
            literalArgument("truncate"),
            literalArgument("target/ibex-capsec-fspathasync-truncate"),
            literalArgument(null),
            literalArgument(2),
            literalArgument(0),
            literalArgument(0),
          ],
          completion: {
            kind: "event-loop-quiescence",
            timeoutMilliseconds: 1_000,
          },
          expectedCleanup: "removed-owned-file",
          expectedDecisionCounts: {
            allow: 5,
            "branch-selection": 5,
            deny: 1,
            malformed: 5,
            "missing-attribution": 5,
            "wrong-principal": 5,
          },
          expectedObservedActionIds: {
            malformed: ["fs:list", "fs:write"],
          },
          expectedResults: {
            allow: "return",
            "branch-selection": "return",
            deny: "permission-denied",
            malformed: "return",
            "missing-attribution": "return",
            "wrong-principal": "return",
          },
          expectedStages: {
            allow: ["requested", "discovery", "discovery", "commit", "repeat"],
            "branch-selection": [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
            deny: ["requested"],
            malformed: [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
            "missing-attribution": [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
            "wrong-principal": [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
          },
          requiredFloor: [
            {
              cap: "fs:list",
              resource: projectPathExactResource(
                "target",
                "ibex-capsec-fspathasync-truncate",
              ),
            },
            {
              cap: "fs:write",
              resource: projectPathExactResource(
                "target",
                "ibex-capsec-fspathasync-truncate",
              ),
            },
          ],
          requiredSourceArity: 6,
          setup: [],
        }),
      ],
      [
        "chmod",
        Object.freeze({
          actionIds: ["fs:list", "fs:write"],
          arguments: [
            literalArgument("chmod"),
            literalArgument("target/ibex-capsec-fspathasync-chmod"),
            literalArgument(null),
            literalArgument(0o600),
            literalArgument(0),
            literalArgument(0),
          ],
          completion: {
            kind: "event-loop-quiescence",
            timeoutMilliseconds: 1_000,
          },
          expectedCleanup: "removed-owned-file",
          expectedDecisionCounts: {
            allow: 5,
            "branch-selection": 5,
            deny: 1,
            malformed: 5,
            "missing-attribution": 5,
            "wrong-principal": 5,
          },
          expectedObservedActionIds: {
            malformed: ["fs:list", "fs:write"],
          },
          expectedResults: {
            allow: "return",
            "branch-selection": "return",
            deny: "permission-denied",
            malformed: "return",
            "missing-attribution": "return",
            "wrong-principal": "return",
          },
          expectedStages: {
            allow: ["requested", "discovery", "discovery", "commit", "repeat"],
            "branch-selection": [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
            deny: ["requested"],
            malformed: [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
            "missing-attribution": [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
            "wrong-principal": [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
          },
          requiredFloor: [
            {
              cap: "fs:list",
              resource: projectPathExactResource(
                "target",
                "ibex-capsec-fspathasync-chmod",
              ),
            },
            {
              cap: "fs:write",
              resource: projectPathExactResource(
                "target",
                "ibex-capsec-fspathasync-chmod",
              ),
            },
          ],
          requiredSourceArity: 6,
          setup: [],
        }),
      ],
      [
        "utime",
        Object.freeze({
          actionIds: ["fs:list", "fs:write"],
          arguments: [
            literalArgument("utime"),
            literalArgument("target/ibex-capsec-fspathasync-utime"),
            literalArgument(null),
            literalArgument(1),
            literalArgument(2),
            literalArgument(0),
          ],
          completion: {
            kind: "event-loop-quiescence",
            timeoutMilliseconds: 1_000,
          },
          expectedCleanup: "removed-owned-file",
          expectedDecisionCounts: {
            allow: 5,
            "branch-selection": 5,
            deny: 1,
            malformed: 5,
            "missing-attribution": 5,
            "wrong-principal": 5,
          },
          expectedObservedActionIds: {
            malformed: ["fs:list", "fs:write"],
          },
          expectedResults: {
            allow: "return",
            "branch-selection": "return",
            deny: "permission-denied",
            malformed: "return",
            "missing-attribution": "return",
            "wrong-principal": "return",
          },
          expectedStages: {
            allow: ["requested", "discovery", "discovery", "commit", "repeat"],
            "branch-selection": [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
            deny: ["requested"],
            malformed: [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
            "missing-attribution": [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
            "wrong-principal": [
              "requested",
              "discovery",
              "discovery",
              "commit",
              "repeat",
            ],
          },
          requiredFloor: [
            {
              cap: "fs:list",
              resource: projectPathExactResource(
                "target",
                "ibex-capsec-fspathasync-utime",
              ),
            },
            {
              cap: "fs:write",
              resource: projectPathExactResource(
                "target",
                "ibex-capsec-fspathasync-utime",
              ),
            },
          ],
          requiredSourceArity: 6,
          setup: [],
        }),
      ],
    ]),
  ],
]);

function logicalBranchIdForPlan(plan, scenario) {
  const marker = ".logical.";
  const markerIndex = plan.fixtureId.lastIndexOf(marker);
  const suffix = `.${scenario}`;
  if (markerIndex === -1 || !plan.fixtureId.endsWith(suffix)) return null;
  const branchId = plan.fixtureId.slice(
    markerIndex + marker.length,
    -suffix.length,
  );
  return branchId || null;
}

const NATIVE_PUBLIC_CONDITIONAL_PROBE_TEMPLATES = new Map([
  [
    "__exactSqliteOpen",
    nativeConditionalNoEffectTemplate(2, [
      literalArgument(":memory:"),
      literalArgument(null),
    ]),
  ],
  [
    "__exactSqlitePrepare",
    nativeConditionalNoEffectTemplate(
      2,
      [
        harnessSqliteDatabaseHandleArgument(),
        literalArgument("SELECT 1 AS value"),
      ],
      sqliteMemorySetup(),
    ),
  ],
  ...["All", "Get", "Run", "Values"].map((suffix) => [
    `__exactSqlite${suffix}`,
    nativeConditionalNoEffectTemplate(
      2,
      [harnessSqliteStatementHandleArgument(), literalArgument(null)],
      sqliteMemorySetup(true),
    ),
  ]),
  [
    "__exactSqliteExec",
    nativeConditionalNoEffectTemplate(
      3,
      [
        harnessSqliteDatabaseHandleArgument(),
        literalArgument("SELECT 1"),
        literalArgument(null),
      ],
      sqliteMemorySetup(),
    ),
  ],
]);

const GLOBAL_READ_INACCESSIBLE_MEMBER_KINDS = new Set([
  "dynamic-table",
  "inherited-shape",
  "instance-property",
  "namespace-alias",
  "namespace-prefix",
  "prototype-accessor",
  "prototype-assignment",
  "prototype-method",
]);

function nativePublicReadDescriptor(surface) {
  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
  // readable inventory fact becomes a recipe only with an exact source path.
  const metadata = surface?.metadata;
  if (
    metadata?.surfaceType !== "global-api" ||
    metadata.sourceKey !== "shared_runtime" ||
    metadata.publicReadAccessSourceProven !== true ||
    !new Set(["accessor", "data"]).has(metadata.valueShape) ||
    typeof metadata.exportName !== "string" ||
    metadata.exportName.length === 0 ||
    typeof metadata.globalName !== "string" ||
    metadata.globalName.length === 0 ||
    !Array.isArray(metadata.memberKinds) ||
    metadata.memberKinds.length === 0 ||
    canonicalJson(metadata.memberKinds) !==
      canonicalJson(canonicalSet(metadata.memberKinds)) ||
    metadata.memberKinds.some((kind) =>
      GLOBAL_READ_INACCESSIBLE_MEMBER_KINDS.has(kind),
    ) ||
    (metadata.memberKinds.includes("inherited") &&
      (metadata.valueShape !== "data" ||
        !metadata.memberKinds.includes("static"))) ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length === 0 ||
    !surface.sourceRefs.every((sourceRef) =>
      sourceRef.startsWith("packages/ibex-runtime-js/src/"),
    ) ||
    canonicalJson(surface.sourceRefs) !==
      canonicalJson(canonicalSet(surface.sourceRefs))
  ) {
    return null;
  }
  const path = metadata.exportName.split(".");
  if (
    path[0] !== metadata.globalName ||
    path.some(
      (segment) =>
        !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(segment) ||
        segment.includes("[[") ||
        segment.includes("]]"),
    )
  ) {
    return null;
  }
  if (
    metadata.valueShape === "accessor" &&
    path.length === 1 &&
    surface.sourceRefs.some((sourceRef) =>
      sourceRef.includes("#defineLazyGlobal:"),
    )
  ) {
    // `defineLazyGlobal` self-replaces with its result. If startup has already
    // materialized a callable, a later property read no longer executes the
    // getter and cannot be counted as public-surface execution.
    return null;
  }
  const expectedObservedKey = metadata.exportName.startsWith("_")
    ? `native-op:${metadata.exportName}`
    : `native-op:global:${metadata.exportName}`;
  if (surface.observedKey !== expectedObservedKey) return null;
  return {
    kind: "global-property-read",
    sourceKey: metadata.sourceKey,
    exportName: metadata.exportName,
    globalName: metadata.globalName,
    memberKinds: [...metadata.memberKinds],
    sourceRefs: [...surface.sourceRefs],
    valueShape: metadata.valueShape,
    access: { kind: "source-proven-property-path", path },
  };
}

function bindNativeArgumentSources(argument, liveByObservedKey) {
  if (
    argument.kind !== "native-global-result" &&
    argument.kind !== "native-global-result-property"
  ) {
    return clone(argument);
  }
  const producer = (
    liveByObservedKey.get(`native-op:${argument.globalName}`) ??
    liveByObservedKey.get(`native-op:global:${argument.globalName}`)
  )?.metadata?.publicInvocation;
  if (
    !producer ||
    producer.kind !== "native-global-function" ||
    producer.arity !== argument.requiredSourceArity
  ) {
    throw new Error(
      `native public argument producer descriptor drift: ${argument.globalName}`,
    );
  }
  const sourceDescriptor = clone(producer);
  return {
    kind: argument.kind,
    ...(argument.kind === "native-global-result-property"
      ? { property: argument.property }
      : {}),
    globalName: argument.globalName,
    arguments: argument.arguments.map((nested) =>
      bindNativeArgumentSources(nested, liveByObservedKey),
    ),
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
  };
}

function bindNativeSetupSources(setup, liveByObservedKey) {
  if (
    !new Set([
      "fs-read-file",
      "sqlite-memory-database",
      "sqlite-memory-statement",
      "tcp-loopback-client",
    ]).has(setup.kind)
  ) {
    return clone(setup);
  }
  const producer = liveByObservedKey.get(`native-op:${setup.globalName}`)
    ?.metadata?.publicInvocation;
  if (
    !producer ||
    producer.kind !== "native-global-function" ||
    producer.arity !== setup.requiredSourceArity
  ) {
    throw new Error(
      `native public setup producer descriptor drift: ${setup.globalName}`,
    );
  }
  const sourceDescriptor = clone(producer);
  return {
    kind: setup.kind,
    globalName: setup.globalName,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
  };
}

function nativePublicProbeForPlan({
  plan,
  scenario,
  route,
  liveByObservedKey,
  coverageByObservedKey,
  adapterProbe,
}) {
  const targetAbsence = plan.expectedObservation.kind === "target-absence";
  const surfaceObservedKey = targetAbsence
    ? plan.terminalObservedKey
    : route.surfaceObservedKeys.length === 1
      ? route.surfaceObservedKeys[0]
      : null;
  if (!surfaceObservedKey?.startsWith("native-op:")) {
    return { probe: null, unavailableReason: null };
  }
  const live = liveByObservedKey.get(surfaceObservedKey);
  const invocation = live?.metadata?.publicInvocation;
  const readDescriptor = targetAbsence
    ? null
    : nativePublicReadDescriptor(live);
  if (!invocation && !readDescriptor) {
    return {
      probe: null,
      unavailableReason: targetAbsence
        ? "native-public-target-absence-source-invocation-unavailable"
        : "native-public-source-invocation-unavailable",
    };
  }
  if (readDescriptor) {
    if (
      plan.classification !== "non-capability" ||
      scenario !== "non-capability" ||
      plan.actionIds.length !== 0
    ) {
      return {
        probe: null,
        unavailableReason: `native-public-${scenario}-scenario-not-authored`,
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
          "capsec-conformance-observer,openssl-crypto",
          "capsec_public_native_recipe_batch",
          "--",
          "--test-threads=1",
        ],
        invocation: {
          invocationSchema: "ibex/capsec-native-global-invocation/1",
          kind: "global-property-read",
          globalName: readDescriptor.globalName,
          sourceDescriptor: readDescriptor,
          sourceDescriptorDigest: taggedDigest(readDescriptor),
          arguments: [],
          requiredFloor: [],
          setup: [],
          expectedResult: "return",
          expectedTypedStages: [],
          expectedTypedDecisionCount: 0,
          allowedCoverageEdgeIds: clone(plan.edgeIds),
          expectedActionIds: [],
        },
      },
    };
  }
  const structuralAbsenceArity = NATIVE_PUBLIC_POST_LOCKDOWN_ABSENT.get(
    invocation.globalName,
  );
  const structuralAbsence = structuralAbsenceArity !== undefined;
  if (structuralAbsence && invocation.arity !== structuralAbsenceArity) {
    return {
      probe: null,
      unavailableReason: "native-public-source-descriptor-drift",
    };
  }
  const template =
    targetAbsence || structuralAbsence
      ? {
          actionIds: plan.actionIds,
          arguments: [],
          expectedDecisionCounts: { [scenario]: 0 },
          expectedResults: { [scenario]: "absent" },
          expectedStages: { [scenario]: [] },
          requiredSourceArity: invocation.arity,
          setup: [],
        }
      : (NATIVE_PUBLIC_PROBE_TEMPLATES.get(invocation.globalName) ??
        NATIVE_PUBLIC_LOGICAL_BRANCH_PROBE_TEMPLATES.get(
          invocation.globalName,
        )?.get(logicalBranchIdForPlan(plan, scenario)) ??
        (plan.actionIds.length === 0 &&
        new Set(["branch-selection", "no-effect"]).has(scenario)
          ? NATIVE_PUBLIC_CONDITIONAL_PROBE_TEMPLATES.get(invocation.globalName)
          : null));
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
    !targetAbsence &&
    (route.alternatives.length !== 1 ||
      route.alternatives[0].terminalObservedKey !== surfaceObservedKey ||
      route.ambiguousCallees.length !== 0)
  ) {
    return {
      probe: null,
      unavailableReason: "native-public-terminal-route-is-not-exact",
    };
  }
  const sourceDescriptor = clone(invocation);
  const expectedStages = template.expectedStages[scenario];
  const additionalAllowedCoverageEdgeIds = [];
  for (const observedKey of template.additionalAllowedCoverageObservedKeys ??
    []) {
    const additionalEdge = coverageByObservedKey.get(observedKey);
    if (!additionalEdge?.id) {
      return {
        probe: null,
        unavailableReason: "native-public-auxiliary-coverage-edge-unavailable",
      };
    }
    additionalAllowedCoverageEdgeIds.push(additionalEdge.id);
  }
  const expectedActionIds = template.expectedObservedActionIds?.[scenario]
    ? clone(template.expectedObservedActionIds[scenario])
    : adapterProbe
      ? canonicalSet(
          adapterProbe.cases
            .filter((adapterCase) => expectedStages.includes(adapterCase.stage))
            .flatMap((adapterCase) => adapterCase.actionIds),
        )
      : clone(plan.actionIds);
  return {
    unavailableReason: null,
    probe: {
      kind: targetAbsence
        ? "target-absence-probe"
        : "public-surface-invocation",
      surfaceObservedKey,
      command: [
        "cargo",
        "test",
        "--bin",
        "ibex",
        "--features",
        "capsec-conformance-observer,openssl-crypto",
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
        arguments: template.arguments.map((argument) =>
          bindNativeArgumentSources(argument, liveByObservedKey),
        ),
        ...(template.completion
          ? { completion: clone(template.completion) }
          : {}),
        requiredFloor: clone(template.requiredFloor ?? []),
        setup: template.setup.map((setup) =>
          bindNativeSetupSources(setup, liveByObservedKey),
        ),
        expectedResult: template.expectedResults[scenario],
        ...(template.expectedCleanup
          ? { expectedCleanup: template.expectedCleanup }
          : {}),
        expectedTypedStages: clone(expectedStages),
        expectedTypedDecisionCount: template.expectedDecisionCounts[scenario],
        allowedCoverageEdgeIds: canonicalSet([
          ...plan.edgeIds,
          ...additionalAllowedCoverageEdgeIds,
        ]),
        expectedActionIds,
      },
    },
  };
}

const CONDITIONAL_SQLITE_HOST_ABIS = new Set([
  "ex_host_sqlite_all",
  "ex_host_sqlite_exec",
  "ex_host_sqlite_get",
  "ex_host_sqlite_open",
  "ex_host_sqlite_prepare",
  "ex_host_sqlite_run",
  "ex_host_sqlite_values",
]);

function conditionalHostAbiProbeForPlan({
  plan,
  scenario,
  route,
  liveByObservedKey,
  coverageByEdge,
}) {
  if (
    plan.classification !== "effects" ||
    !new Set(["branch-selection", "no-effect"]).has(scenario) ||
    plan.actionIds.length !== 0 ||
    plan.edgeIds.length !== 1 ||
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "host-abi:";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const functionName = surfaceObservedKey.slice(prefix.length);
  if (!CONDITIONAL_SQLITE_HOST_ABIS.has(functionName)) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByEdge.get(plan.edgeIds[0]);
  const logicalBranch = edge?.logicalBranches?.find((branch) =>
    plan.fixtureId.includes(`.logical.${branch.id}.`),
  );
  const definitions = live?.metadata?.definitions;
  if (
    live?.kind !== "host-abi" ||
    live.name !== functionName ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length !== 1 ||
    !Array.isArray(definitions) ||
    definitions.length !== 1 ||
    definitions[0].language !== "rust" ||
    definitions[0].targetVariant !== "default" ||
    definitions[0].sourceRef !== live.sourceRefs[0] ||
    edge?.surface?.kind !== "host-abi" ||
    edge.surface.name !== functionName ||
    logicalBranch?.id !== "memory" ||
    logicalBranch.effects.length !== 0 ||
    canonicalJson(logicalBranch.when) !==
      canonicalJson([
        {
          fact:
            functionName === "ex_host_sqlite_open"
              ? "sqlite.open.mode"
              : new Set(["ex_host_sqlite_exec", "ex_host_sqlite_run"]).has(
                    functionName,
                  )
                ? "sqlite.statement.effect"
                : "sqlite.storage.kind",
          equals: "memory",
        },
      ]) ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "host-abi-function",
    functionName,
    sourceRefs: clone(live.sourceRefs),
    sourceMetadata: clone(live.metadata),
    selectedBranch: {
      id: logicalBranch.id,
      when: clone(logicalBranch.when),
    },
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [
      "cargo",
      "test",
      "--bin",
      "ibex",
      "--features",
      "capsec-conformance-observer,openssl-crypto",
      "capsec_public_native_recipe_batch",
      "--",
      "--test-threads=1",
    ],
    invocation: {
      invocationSchema: "ibex/capsec-host-abi-invocation/1",
      kind: "host-abi-function",
      functionName,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "sqlite-memory",
        selectedBranch: clone(sourceDescriptor.selectedBranch),
      },
      expectedResult: "return",
      expectedTypedStages: [],
      expectedTypedDecisionCount: 0,
      allowedCoverageEdgeIds: clone(plan.edgeIds),
      expectedActionIds: [],
    },
  };
}

// @ref LLP 0021#module-initialization-and-trusted-source-acquisition — loader
// admission and source/cache/carrier reads are control-plane operations, so
// their public proof must execute with zero host-effect decisions.
const MODULE_RUNNER_LOADER_OPERATIONS = new Map([
  ["module-runner-edge-authorization", "authorize-edge"],
  ["module-runner-trusted-source-acquisition", "source-acquisition"],
  ["module-runner-cache-access", "cache-read"],
  ["module-runner-prepared-carrier-access", "prepared-carrier-read"],
]);

const MODULE_RUNNER_SOURCE_GRAPH_HOST_ABIS = new Set([
  "ex_hermes_commonjs_create_record",
  "ex_hermes_commonjs_record_create_esm_adapter",
  "ex_hermes_commonjs_record_declare_export",
  "ex_hermes_commonjs_record_evaluate",
  "ex_hermes_commonjs_record_link_dynamic_import",
  "ex_hermes_commonjs_record_link_require",
  "ex_hermes_commonjs_record_link_require_esm",
  "ex_hermes_graph_context_create",
  "ex_hermes_graph_context_retain",
  "ex_hermes_module_compile_factory",
  "ex_hermes_module_create_record",
  "ex_hermes_module_load_carrier_factory",
  "ex_hermes_module_pin_generation",
  "ex_hermes_module_record_declare_export",
  "ex_hermes_module_record_instantiate",
  "ex_hermes_module_record_link_dependency",
  "ex_hermes_module_record_link_dynamic_import",
  "ex_hermes_module_record_link_export",
  "ex_hermes_module_record_link_import",
  "ex_hermes_module_record_poll_evaluation",
  "ex_hermes_module_record_run_declare",
  "ex_hermes_module_record_run_execute",
  "ex_hermes_module_release_handle",
  "ex_hermes_module_unpin_generation",
]);

function moduleRunnerLoaderProbeForPlan({
  plan,
  scenario,
  route,
  liveByObservedKey,
}) {
  if (
    plan.classification !== "non-capability" ||
    scenario !== "non-capability" ||
    plan.actionIds.length !== 0 ||
    plan.edgeIds.length !== 1 ||
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "loader:";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const surfaceName = surfaceObservedKey.slice(prefix.length);
  const operation = MODULE_RUNNER_LOADER_OPERATIONS.get(surfaceName);
  if (!operation) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  if (
    live?.kind !== "loader" ||
    live.name !== surfaceName ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length !== 1 ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "module-loader-function",
    surfaceName,
    sourceRefs: clone(live.sourceRefs),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [
      "cargo",
      "test",
      "--bin",
      "ibex",
      "--features",
      "capsec-conformance-observer,openssl-crypto",
      "capsec_public_native_recipe_batch",
      "--",
      "--test-threads=1",
    ],
    invocation: {
      invocationSchema: "ibex/capsec-module-loader-invocation/1",
      kind: "module-loader-authority",
      surfaceName,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: { kind: operation },
      expectedResult: "return",
      expectedTypedStages: [],
      expectedTypedDecisionCount: 0,
      allowedCoverageEdgeIds: clone(plan.edgeIds),
      expectedActionIds: [],
    },
  };
}

function moduleRunnerHostAbiProbeForPlan({
  plan,
  scenario,
  route,
  liveByObservedKey,
}) {
  if (
    plan.classification !== "non-capability" ||
    scenario !== "non-capability" ||
    plan.actionIds.length !== 0 ||
    plan.edgeIds.length !== 1 ||
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "host-abi:";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const functionName = surfaceObservedKey.slice(prefix.length);
  if (!MODULE_RUNNER_SOURCE_GRAPH_HOST_ABIS.has(functionName)) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  if (
    live?.kind !== "host-abi" ||
    live.name !== functionName ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length !== 1 ||
    !Array.isArray(live.metadata?.definitions) ||
    live.metadata.definitions.length !== 1 ||
    live.metadata.definitions[0].language !== "c++" ||
    live.metadata.definitions[0].sourceRef !== live.sourceRefs[0] ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "host-abi-function",
    functionName,
    sourceRefs: clone(live.sourceRefs),
    sourceMetadata: clone(live.metadata),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [
      "cargo",
      "test",
      "--bin",
      "ibex",
      "--features",
      "capsec-conformance-observer,openssl-crypto",
      "capsec_public_native_recipe_batch",
      "--",
      "--test-threads=1",
    ],
    invocation: {
      invocationSchema: "ibex/capsec-host-abi-invocation/1",
      kind: "host-abi-function",
      functionName,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: { kind: "module-runner-source-graph" },
      expectedResult: "return",
      expectedTypedStages: [],
      expectedTypedDecisionCount: 0,
      allowedCoverageEdgeIds: clone(plan.edgeIds),
      expectedActionIds: [],
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
  const callbackInvariantProbe =
    publicSurfaceProbe?.invocation?.invocationSchema ===
    "ibex/capsec-callback-invariant-invocation/1";
  const effectBuiltinProbe =
    plan.classification === "effects" &&
    publicSurfaceProbe?.invocation?.invocationSchema ===
      "ibex/capsec-builtin-export-invocation/1" &&
    Number.isSafeInteger(
      publicSurfaceProbe.invocation.expectedTypedDecisionCount,
    ) &&
    publicSurfaceProbe.invocation.expectedTypedDecisionCount > 0 &&
    Array.isArray(publicSurfaceProbe.invocation.allowedCoverageEdgeIds) &&
    publicSurfaceProbe.invocation.allowedCoverageEdgeIds.length > 0;
  const terminalBuiltinClosureProbe =
    publicSurfaceProbe?.invocation?.invocationSchema ===
      "ibex/capsec-closed-surface-invocation/1" &&
    publicSurfaceProbe?.invocation?.operation?.kind ===
      "terminal-builtin-import";
  if (plan.expectedObservation.kind === "target-absence") {
    if (!publicSurfaceProbe) {
      reasons.push("target-absence-probe-not-authored");
      if (publicSurfaceUnavailableReason) {
        reasons.push(publicSurfaceUnavailableReason);
      }
    }
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
      if (!publicSurfaceUnavailableReason) {
        reasons.push("non-capability-no-decision-probe-not-authored");
      }
    } else {
      reasons.push(`callback-invariant-${scenario}-probe-not-authored`);
    }
  } else if (plan.classification === "effects" && !adapterProbe) {
    // A conditional branch is selected by the real public invocation, not by
    // the diagnostic typed evaluator. When that invocation is source-bound
    // and observes the branch's exact decisions (or deliberately observes no
    // decisions for a zero-effect branch), it is the stronger witness. The
    // malformed-branch-facts obligation remains adapter-specific because a
    // valid public API cannot inject malformed internal facts.
    if (
      (scenario === "branch-selection" || scenario === "no-effect") &&
      publicSurfaceProbe
    ) {
      // Resolved by loaded-engine public evidence.
    } else if (plan.actionIds.length === 0) {
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
    plan.expectedObservation.kind !== "target-absence" &&
    !callbackInvariantProbe &&
    !terminalBuiltinClosureProbe
  ) {
    reasons.push("no-static-enforcement-terminal");
  }
  if (route.alternatives.length > 1 && !publicSurfaceProbe) {
    reasons.push("argument-selected-terminal-alternatives-not-authored");
  }
  // An exact effect-builtin probe resolves its authored setup/arguments at
  // runtime and must observe a typed gate from the source-derived terminal
  // allow-list. Static ambiguity remains a residual without that witness.
  if (
    route.ambiguousCallees.length > 0 &&
    !callbackInvariantProbe &&
    !effectBuiltinProbe &&
    !terminalBuiltinClosureProbe
  ) {
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
  capabilityDefinitions,
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
  const definitionByAction = definitionMap(capabilityDefinitions);
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
      definitionByAction,
    );
    const adapterProbe = adapter.probe;
    const targetAbsenceProbe = authoredTargetAbsenceProbe({
      plan,
      scenario,
      target,
      coverageByEdge,
      liveByObservedKey,
    });
    const closedPublicSurfaceProbe = authoredClosedPublicProbe({
      plan,
      scenario,
      route,
      liveByObservedKey,
      coverageByObservedKey,
      target,
    });
    const startupPublicSurfaceProbe = authoredStartupPublicProbe({
      plan,
      scenario,
      route,
      liveByObservedKey,
      coverageByObservedKey,
    });
    const startupEnvironmentPublicSurfaceProbe =
      authoredStartupEnvironmentProbe({
        plan,
        scenario,
        route,
        liveByObservedKey,
        coverageByObservedKey,
      });
    const callbackInvariantProbe = authoredCallbackInvariantProbe({
      plan,
      scenario,
      rows,
      route,
      liveByObservedKey,
      coverageByEdge,
      coverageByObservedKey,
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
        target,
      });
    const nativePublicSurface = nativePublicProbeForPlan({
      plan,
      scenario,
      route,
      liveByObservedKey,
      coverageByObservedKey,
      adapterProbe,
    });
    const conditionalHostAbiProbe = conditionalHostAbiProbeForPlan({
      plan,
      scenario,
      route,
      liveByObservedKey,
      coverageByEdge,
    });
    const moduleRunnerLoaderProbe = moduleRunnerLoaderProbeForPlan({
      plan,
      scenario,
      route,
      liveByObservedKey,
    });
    const moduleRunnerHostAbiProbe = moduleRunnerHostAbiProbeForPlan({
      plan,
      scenario,
      route,
      liveByObservedKey,
    });
    const authoredPublicSurfaceProbes = callbackInvariantProbe
      ? [callbackInvariantProbe]
      : [
          nativePublicSurface.probe ? null : targetAbsenceProbe,
          closedPublicSurfaceProbe,
          startupPublicSurfaceProbe,
          startupEnvironmentPublicSurfaceProbe,
          effectBuiltinPublicSurfaceProbe,
          nonCapabilityBuiltinPublicSurfaceProbe,
          conditionalHostAbiProbe,
          moduleRunnerLoaderProbe,
          moduleRunnerHostAbiProbe,
          nativePublicSurface.probe,
        ].filter((probe) => probe !== null);
    if (authoredPublicSurfaceProbes.length > 1) {
      throw new Error(
        `${plan.fixtureId}: multiple public probe authors claimed one fixture`,
      );
    }
    const publicSurfaceProbe = authoredPublicSurfaceProbes[0] ?? null;
    const publicSurfaceUnavailableReason = publicSurfaceProbe
      ? null
      : (nonCapabilityBuiltinProbeResidualReason({
          route,
          liveByObservedKey,
          target,
        }) ?? nativePublicSurface.unavailableReason);
    const residual = residualReasons({
      plan,
      scenario,
      adapterProbe,
      adapterUnavailableReason: adapter.unavailableReason,
      publicSurfaceProbe,
      publicSurfaceUnavailableReason,
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
