import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalJson,
  computeDomainDigest,
  parseJsonStrict,
} from "./capsec-contract.mjs";

// @ref LLP 0032#deadline-policy — Stage 1 uses one reviewed, versioned plan
// whose complete per-target critical path fits the workflow containment bound.

export const SUITE_PLAN_SCHEMA = "ibex/capsec-suite-plan/1";
export const SUITE_PLAN_DIGEST_DOMAIN = "ibex/capsec-suite-plan-binding/1";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
export const defaultSuitePlanPath = path.join(
  repoRoot,
  "capsec/conformance/suite-plan.json",
);

const exactKeys = (value, expected, label) => {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    throw new Error(
      `${label}: expected exact fields ${wanted.join(", ")}; got ${actual.join(", ")}`,
    );
  }
};

const positiveInteger = (value, label) => {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label}: expected a positive safe integer`);
  }
};

function validatePolicy(policy, label) {
  exactKeys(policy, ["deadlineMs", "gracePeriodMs", "phase"], label);
  if (!/^[a-z0-9][a-z0-9-]*$/u.test(policy.phase)) {
    throw new Error(`${label}.phase: invalid phase identifier`);
  }
  positiveInteger(policy.deadlineMs, `${label}.deadlineMs`);
  positiveInteger(policy.gracePeriodMs, `${label}.gracePeriodMs`);
}

export function validateConformanceSuitePlan(plan) {
  if (!plan || typeof plan !== "object" || Array.isArray(plan)) {
    throw new Error("suite plan must be an object");
  }
  exactKeys(
    plan,
    [
      "commands",
      "dynamicCommands",
      "heartbeatIntervalMs",
      "helperClasses",
      "planId",
      "schema",
      "targets",
      "timeoutPolicyVersion",
    ],
    "suite plan",
  );
  if (plan.schema !== SUITE_PLAN_SCHEMA) {
    throw new Error(`unsupported suite plan schema ${plan.schema}`);
  }
  if (!/^[a-z0-9][a-z0-9-]*$/u.test(plan.planId)) {
    throw new Error("suite plan planId is invalid");
  }
  positiveInteger(plan.timeoutPolicyVersion, "timeoutPolicyVersion");
  positiveInteger(plan.heartbeatIntervalMs, "heartbeatIntervalMs");
  for (const [id, policy] of Object.entries(plan.commands)) {
    if (!/^[a-z0-9][a-z0-9-]*$/u.test(id)) {
      throw new Error(`invalid command policy id ${id}`);
    }
    validatePolicy(policy, `commands.${id}`);
  }
  for (const [prefix, policy] of Object.entries(plan.dynamicCommands)) {
    if (!/^[a-z0-9][a-z0-9-]*-$/u.test(prefix)) {
      throw new Error(`invalid dynamic command prefix ${prefix}`);
    }
    validatePolicy(policy, `dynamicCommands.${prefix}`);
  }
  for (const [name, helper] of Object.entries(plan.helperClasses)) {
    exactKeys(helper, ["commands", "producesEvidence"], `helperClasses.${name}`);
    if (
      !Array.isArray(helper.commands) ||
      helper.commands.length === 0 ||
      helper.commands.some((command) => typeof command !== "string") ||
      helper.producesEvidence !== false
    ) {
      throw new Error(`helperClasses.${name}: invalid helper declaration`);
    }
  }
  for (const [target, budget] of Object.entries(plan.targets)) {
    exactKeys(
      budget,
      [
        "aliasDiagnosticCommands",
        "cleanupUploadReserveMs",
        "deadlineOverrides",
        "maxPublicFixtureBatches",
        "outerTimeoutMs",
        "setupReserveMs",
      ],
      `targets.${target}`,
    );
    positiveInteger(budget.outerTimeoutMs, `${target}.outerTimeoutMs`);
    positiveInteger(budget.setupReserveMs, `${target}.setupReserveMs`);
    positiveInteger(
      budget.cleanupUploadReserveMs,
      `${target}.cleanupUploadReserveMs`,
    );
    positiveInteger(
      budget.maxPublicFixtureBatches,
      `${target}.maxPublicFixtureBatches`,
    );
    if (!Array.isArray(budget.aliasDiagnosticCommands)) {
      throw new Error(`${target}.aliasDiagnosticCommands must be an array`);
    }
    for (const id of budget.aliasDiagnosticCommands) {
      if (!plan.commands[id]) {
        throw new Error(`${target}: unknown alias diagnostic command ${id}`);
      }
    }
    for (const [id, deadline] of Object.entries(budget.deadlineOverrides)) {
      if (!plan.commands[id]) {
        throw new Error(`${target}: deadline override names unknown command ${id}`);
      }
      positiveInteger(deadline, `${target}.deadlineOverrides.${id}`);
    }
    const critical = criticalPathBudget(plan, target);
    if (critical.totalMs > budget.outerTimeoutMs) {
      throw new Error(
        `${target}: critical path ${critical.totalMs}ms exceeds outer timeout ${budget.outerTimeoutMs}ms`,
      );
    }
  }
  return plan;
}

export function readConformanceSuitePlan(filePath = defaultSuitePlanPath) {
  return validateConformanceSuitePlan(
    parseJsonStrict(fs.readFileSync(filePath), "CapSec suite plan"),
  );
}

export function commandPolicyFor(plan, target, id) {
  const targetPlan = plan.targets[target];
  if (!targetPlan) throw new Error(`suite plan does not support target ${target}`);
  const base =
    plan.commands[id] ??
    Object.entries(plan.dynamicCommands).find(([prefix]) =>
      id.startsWith(prefix),
    )?.[1];
  if (!base) throw new Error(`suite plan has no command policy for ${id}`);
  return {
    ...base,
    deadlineMs: targetPlan.deadlineOverrides[id] ?? base.deadlineMs,
  };
}

export function criticalPathBudget(plan, target) {
  const targetPlan = plan.targets[target];
  if (!targetPlan) throw new Error(`suite plan does not support target ${target}`);
  const aliasIds = new Set(targetPlan.aliasDiagnosticCommands);
  const aliasUniverse = new Set(
    Object.values(plan.targets).flatMap(
      (candidate) => candidate.aliasDiagnosticCommands,
    ),
  );
  let commandDeadlinesMs = 0;
  let maximumGracePeriodMs = 0;
  for (const id of Object.keys(plan.commands)) {
    if (aliasUniverse.has(id) && !aliasIds.has(id)) continue;
    const policy = commandPolicyFor(plan, target, id);
    commandDeadlinesMs += policy.deadlineMs;
    maximumGracePeriodMs = Math.max(
      maximumGracePeriodMs,
      policy.gracePeriodMs,
    );
  }
  const publicPolicy = Object.entries(plan.dynamicCommands).find(([prefix]) =>
    "public-fixtures-000-placeholder".startsWith(prefix),
  )?.[1];
  if (!publicPolicy) throw new Error("suite plan lacks public fixture policy");
  commandDeadlinesMs +=
    targetPlan.maxPublicFixtureBatches * publicPolicy.deadlineMs;
  maximumGracePeriodMs = Math.max(
    maximumGracePeriodMs,
    publicPolicy.gracePeriodMs,
  );
  return {
    commandDeadlinesMs,
    maximumGracePeriodMs,
    setupReserveMs: targetPlan.setupReserveMs,
    cleanupUploadReserveMs: targetPlan.cleanupUploadReserveMs,
    totalMs:
      commandDeadlinesMs +
      maximumGracePeriodMs +
      targetPlan.setupReserveMs +
      targetPlan.cleanupUploadReserveMs,
  };
}

export function bindConformanceSuitePlan({
  plan,
  sourceRevision,
  sourceTreeDigest,
  target,
  engineArtifactDigest,
}) {
  validateConformanceSuitePlan(plan);
  if (!plan.targets[target]) {
    throw new Error(`suite plan does not support target ${target}`);
  }
  const binding = {
    schema: "ibex/capsec-suite-plan-binding/1",
    plan,
    sourceRevision,
    sourceTreeDigest,
    target,
    engineArtifactDigest,
  };
  return {
    ...binding,
    suitePlanDigest: computeDomainDigest(SUITE_PLAN_DIGEST_DOMAIN, binding),
  };
}
