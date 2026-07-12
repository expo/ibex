/**
 * Source-bound public probes for deny-only surfaces. Closed surfaces do not
 * enter the typed authority evaluator: the production boundary must reject
 * them before project code and report zero typed and legacy decisions.
 *
 * @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces —
 * deny-only startup controls must fail at the authenticated entry boundary.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const CLOSED_BATCH_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer",
  "capsec_public_closed_recipe_batch",
  "--",
  "--test-threads=1",
]);

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const PROJECT_CODE_PLACEHOLDER = "{ibex-capsec-closed-project-code}";
const EVALUATION_MARKER =
  "globalThis.__IBEX_CAPSEC_CLOSED_CLI_EVALUATED__ = true";

const CLI_OPTION_TEMPLATES = new Map([
  ["ibex\0allow_all", { value: null, rejection: "legacy" }],
  ["ibex\0allow_env_endowments", { value: null, rejection: "legacy" }],
  ["ibex\0capsec", { value: null, rejection: "legacy" }],
  ["ibex\0capsec_allow_advisory", { value: null, rejection: "legacy" }],
  ["ibex\0eval_code", { value: EVALUATION_MARKER, rejection: "evaluation" }],
  ["ibex\0expose_internals", { value: null, rejection: "inspector" }],
  ["ibex\0inspect", { value: null, rejection: "inspector" }],
  ["ibex\0inspect_host", { value: "127.0.0.1", rejection: "inspector" }],
  ["ibex\0inspect_open", { value: null, rejection: "inspector" }],
  ["ibex\0inspect_pause", { value: null, rejection: "inspector" }],
  ["ibex\0inspect_port", { value: "9230", rejection: "inspector" }],
  ["ibex\0inspect_wait", { value: null, rejection: "inspector" }],
  ["ibex\0print_eval", { value: EVALUATION_MARKER, rejection: "evaluation" }],
  ["ibex run\0inspect", { value: null, rejection: "inspector" }],
  ["ibex run\0inspect_host", { value: "127.0.0.1", rejection: "inspector" }],
  ["ibex run\0inspect_open", { value: null, rejection: "inspector" }],
  ["ibex run\0inspect_pause", { value: null, rejection: "inspector" }],
  ["ibex run\0inspect_port", { value: "9230", rejection: "inspector" }],
  ["ibex run\0inspect_wait", { value: null, rejection: "inspector" }],
]);

const CLI_COMMAND_TEMPLATES = new Map([
  ["ibex debug", { args: ["debug", "modules"], rejection: "evaluation" }],
  ["ibex debug modules", { args: ["debug", "modules"], rejection: "evaluation" }],
  ["ibex eval", { args: ["eval", EVALUATION_MARKER], rejection: "evaluation" }],
  ["ibex repl", { args: ["repl"], rejection: "evaluation" }],
]);

const REJECTION_FRAGMENTS = Object.freeze({
  evaluation: [
    "closes ad-hoc evaluation, REPL, and debug commands",
  ],
  inspector: [
    "closes compatibility, inspector",
    "runtime-fidelity overrides",
  ],
  legacy: [
    "rejects legacy allow/deny",
    "environment endowment widening",
  ],
});

const TAMED_EVALUATOR_ACCESS = new Map([
  ["global:eval", "global-eval"],
  ["global:Function", "global-function"],
  ["global:AsyncFunction", "async-function-constructor"],
  ["global:GeneratorFunction", "generator-function-constructor"],
]);

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalStrings(values) {
  return [...new Set(values)].sort(compareText);
}

function liveRows(liveByObservedKey) {
  return [...liveByObservedKey.values()];
}

function optionControlDescriptor(live, liveByObservedKey) {
  const metadata = live.metadata ?? {};
  let commandPath = metadata.commandPath;
  let argumentId = metadata.argumentId;
  const rows = liveRows(liveByObservedKey);
  let route = null;
  if (commandPath && argumentId) {
    route = rows.find(
      (row) =>
        row.kind === "cli" &&
        row.metadata?.evidenceType === "cli-option-route" &&
        row.metadata.commandPath === commandPath &&
        row.metadata.id === argumentId,
    );
  } else {
    route = rows.find(
      (row) =>
        row.kind === "cli" &&
        row.metadata?.evidenceType === "cli-option-route" &&
        row.sourceRefs.some((sourceRef) => live.sourceRefs.includes(sourceRef)),
    );
    commandPath = route?.metadata?.commandPath;
    argumentId = route?.metadata?.id;
  }
  if (!route || !commandPath || !argumentId) return null;
  const template = CLI_OPTION_TEMPLATES.get(`${commandPath}\0${argumentId}`);
  const evidenceType = metadata.evidenceType;
  if (!template) return null;
  if (
    evidenceType === "cli-default-value" &&
    !route.metadata.valueShape?.defaultValues?.includes(metadata.value)
  ) {
    return null;
  }

  let value = template.value;
  if (evidenceType === "cli-enum-value") {
    if (
      commandPath !== "ibex" ||
      argumentId !== "capsec" ||
      !["audit", "permissive"].includes(metadata.value)
    ) {
      return null;
    }
    value = metadata.value;
  }
  if (argumentId === "capsec") {
    if (evidenceType !== "cli-enum-value") return null;
  }

  const optionNameRows = rows.filter(
    (row) =>
      row.kind === "cli" &&
      row.metadata?.evidenceType === "cli-option-name" &&
      row.sourceRefs.some((sourceRef) => route.sourceRefs.includes(sourceRef)),
  );
  const optionSpellings = canonicalStrings(
    optionNameRows.map((row) => row.metadata.name),
  );
  if (optionSpellings.length === 0) return null;
  const selectedSpellings =
    evidenceType === "cli-option-name" ? [metadata.name] : optionSpellings;
  if (selectedSpellings.some((spelling) => !optionSpellings.includes(spelling))) {
    return null;
  }
  const parser = rows.find(
    (row) =>
      row.kind === "cli" &&
      row.metadata?.evidenceType === "cli-non-enumerated-parser" &&
      row.metadata.commandPath === commandPath &&
      row.metadata.argumentId === argumentId,
  );
  const argumentVectors = selectedSpellings.map((spelling) => {
    const option = value === null ? [spelling] : [spelling, value];
    const prefix = commandPath.split(" ").slice(1);
    return {
      spelling,
      args:
        commandPath === "ibex run"
          ? [...prefix, ...option, PROJECT_CODE_PLACEHOLDER]
          : [...option, PROJECT_CODE_PLACEHOLDER],
    };
  });
  return {
    controlDescriptor: {
      kind: "clap-option",
      commandPath,
      argumentId,
      optionSpellings,
      valueShape: structuredClone(route.metadata.valueShape),
      hidden: route.metadata.hidden === true,
      parserKind: parser?.metadata?.parserKind ?? null,
    },
    argumentVectors,
    rejection: template.rejection,
  };
}

function tamedEvaluatorProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "native-op:";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const surfaceName = surfaceObservedKey.slice(prefix.length);
  const accessMode = TAMED_EVALUATOR_ACCESS.get(surfaceName);
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  if (
    !accessMode ||
    live?.kind !== "native-op" ||
    live.name !== surfaceName ||
    metadata?.evidenceType !== "hermes-evaluator-reachability" ||
    metadata?.exportName !== surfaceName.slice("global:".length) ||
    typeof metadata.engineIdentityReviewId !== "string" ||
    typeof metadata.lockdownTamingDigest !== "string" ||
    metadata.tamingEvidence !== "lockdownJS" ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-tamed-evaluator",
    surfaceObservedKey,
    globalName: metadata.exportName,
    accessMode,
    engineIdentityReviewId: metadata.engineIdentityReviewId,
    lockdownTamingDigest: metadata.lockdownTamingDigest,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(metadata),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "native-op",
      surfaceName,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "tamed-evaluator",
        globalName: metadata.exportName,
        accessMode,
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function commandControlDescriptor(live, liveByObservedKey) {
  const rows = liveRows(liveByObservedKey);
  const evidenceType = live.metadata?.evidenceType;
  let commandPath = evidenceType === "cli-command-route"
    ? live.metadata.path
    : null;
  if (!commandPath && live.variant === "visible") {
    commandPath = `ibex ${live.name}`;
  }
  if (!commandPath && evidenceType === "cli-positional-route") {
    commandPath = live.metadata.commandPath;
  }
  if (!commandPath) {
    const route = rows.find(
      (row) =>
        row.kind === "cli" &&
        row.metadata?.evidenceType === "cli-positional-route" &&
        row.sourceRefs.some((sourceRef) => live.sourceRefs.includes(sourceRef)),
    );
    commandPath = route?.metadata?.commandPath;
  }
  const template = CLI_COMMAND_TEMPLATES.get(commandPath);
  if (!template) return null;
  const commandRoute = rows.find(
    (row) =>
      row.kind === "cli" &&
      row.metadata?.evidenceType === "cli-command-route" &&
      row.metadata.path === commandPath,
  );
  const positionalRoute = rows.find(
    (row) =>
      row.kind === "cli" &&
      row.metadata?.evidenceType === "cli-positional-route" &&
      row.metadata.commandPath === commandPath,
  );
  return {
    controlDescriptor: {
      kind: positionalRoute && live.sourceRefs.some((sourceRef) =>
        positionalRoute.sourceRefs.includes(sourceRef))
        ? "clap-positional"
        : "clap-command",
      commandPath,
      commandMetadata: structuredClone(commandRoute?.metadata ?? null),
      positionalMetadata: structuredClone(positionalRoute?.metadata ?? null),
    },
    argumentVectors: [{ spelling: commandPath, args: [...template.args] }],
    rejection: template.rejection,
  };
}

function cliControlProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  if (!surfaceObservedKey.startsWith("cli:")) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  if (
    live?.kind !== "cli" ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const selected =
    optionControlDescriptor(live, liveByObservedKey) ??
    commandControlDescriptor(live, liveByObservedKey);
  if (!selected) return null;
  const sourceDescriptor = {
    kind: "closed-cli-control",
    surfaceObservedKey,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(live.metadata),
    controlDescriptor: selected.controlDescriptor,
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "cli",
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "cli-control",
        argumentVectors: selected.argumentVectors,
        expectedRejectionFragments: REJECTION_FRAGMENTS[selected.rejection],
        projectCodePlaceholder: PROJECT_CODE_PLACEHOLDER,
        evaluationMarker: EVALUATION_MARKER,
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function startupEnvironmentProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "startup:env:";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const environmentName = surfaceObservedKey.slice(prefix.length);
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  if (
    !environmentName ||
    live?.kind !== "startup" ||
    live.name !== `env:${environmentName}` ||
    live.metadata?.evidenceType !== "static-runtime-environment-control" ||
    canonicalJson(live.metadata.authoredNames) !==
      canonicalJson([environmentName]) ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-startup-environment",
    environmentName,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(live.metadata),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "startup",
      surfaceName: `env:${environmentName}`,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: { kind: "startup-environment", environmentName },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function loaderExecutableKindProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  if (!surfaceObservedKey.startsWith("loader:")) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  // The filename guard returns before ModuleType::Addon/Wasm is inspected.
  // Only the resolve_with_oxc facet is public-source executable; the later
  // kind branches remain honest residuals.
  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
  const fixedKind = live?.name?.endsWith("-module")
    ? live.name.slice(0, -"-module".length)
    : null;
  const loaderKind = fixedKind;
  if (
    !new Set(["native-addon", "wasm"]).has(loaderKind) ||
    live?.kind !== "loader" ||
    live.metadata != null ||
    !Array.isArray(live.sourceRefs) ||
    canonicalJson(live.sourceRefs) !==
      canonicalJson(["src/module_loader/mod.rs#resolve_with_oxc"]) ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const extension = loaderKind === "native-addon" ? ".node" : ".wasm";
  const rejectionFragment =
    loaderKind === "native-addon"
      ? "Native addons are closed"
      : "WebAssembly modules are closed";
  const sourceDescriptor = {
    kind: "closed-loader-executable-kind",
    loaderKind,
    extension,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(live.metadata ?? null),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "loader",
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "loader-executable-file",
        loaderKind,
        extension,
        rejectionFragment,
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

export function authoredClosedPublicProbe(options) {
  const { plan, scenario } = options;
  if (
    plan.classification !== "closed" ||
    scenario !== "closed" ||
    plan.expectedObservation?.kind !== "enforcement-branch" ||
    plan.edgeIds.length !== 1 ||
    plan.actionIds.length !== 0
  ) {
    return null;
  }
  return (
    startupEnvironmentProbe(options) ??
    cliControlProbe(options) ??
    tamedEvaluatorProbe(options) ??
    loaderExecutableKindProbe(options)
  );
}

export const closedBatchCommand = CLOSED_BATCH_COMMAND;
