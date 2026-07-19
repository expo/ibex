/**
 * Generate and model-check LLP 0025's terminal interrupt machine.
 *
 * The transition relation is owned by session/interrupt-machine.v1.json.
 * This file is the deterministic interpreter/generator: it rejects ambiguous
 * or unreachable rows, explores every reachable abstract state, and proves the
 * two temporal properties against arbitrary non-editor interleavings.
 *
 * @ref LLP 0025#6-interruption-and-cancellation — the interrupt relation is
 * owner-authored data, with typed promise, escape-credit, and cause precedence.
 * @ref LLP 0025#acceptance-criteria — AC 7 requires generated dispatch and
 * trajectories plus adversarial reachability checks for schedules (a)-(n).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const repoRoot = path.resolve(__dirname, "..", "..", "..", "..");
export const machineSourcePath = path.join(
  repoRoot,
  "session",
  "interrupt-machine.v1.json",
);
export const machineSchemaPath = path.join(
  repoRoot,
  "session",
  "interrupt-machine.schema.json",
);
export const generatorPath = __filename;
export const generatedInterruptPaths = Object.freeze({
  rust: path.join(
    repoRoot,
    "vendored-generated",
    "interrupt_machine.generated.rs",
  ),
  table: path.join(
    repoRoot,
    "vendored-generated",
    "interrupt_machine_table.generated.md",
  ),
  trajectories: path.join(
    repoRoot,
    "vendored-generated",
    "interrupt_trajectories.generated.json",
  ),
  manifest: path.join(
    repoRoot,
    "vendored-generated",
    "interrupt_machine_manifest.generated.json",
  ),
});

const EXACT_ESCAPE_PROPERTY = "interrupts_without_editor_input <= 3";
const EXACT_PROMISE_PROPERTY =
  "(promised && no editor input since) => next interrupt terminal";
const EXACT_STATUS_RULE =
  "promised status retained unless a cause already latched";
const MAX_REACHABLE_STATES = 100_000;
const KNOWN_OPERATIONS = new Set([
  "accept-editor-input",
  "record-typed-ahead",
  "drain-typed-ahead",
  "submit",
  "dispatch",
  "unit-begin",
  "unit-end",
  "suspend",
  "settle",
  "due",
  "undue",
  "completion-queue",
  "completion-begin",
  "quiescence",
  "cancellation-resolve",
  "exit-code-set",
  "cause-latch",
  "session-end",
]);
const GUARD_KEYS = new Set([
  "phase",
  "pendingSubmission",
  "hasExecuting",
  "hasSuspendedOrDue",
  "executingCompletion",
  "hasCompletionQueued",
]);

function digest(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function prettyJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function relative(filePath) {
  return path.relative(repoRoot, filePath).split(path.sep).join("/");
}

function unique(values) {
  return [...new Set(values)];
}

function assertUnique(values, label) {
  if (values.length !== new Set(values).size) {
    throw new Error(`${label} contains a duplicate`);
  }
}

function assertExactKeys(value, required, optional, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const allowed = new Set([...required, ...optional]);
  const missing = required.filter((key) => !Object.hasOwn(value, key));
  const extra = Object.keys(value).filter((key) => !allowed.has(key));
  if (missing.length > 0 || extra.length > 0) {
    throw new Error(
      `${label} keys mismatch; missing=[${missing.join(",")}] extra=[${extra.join(",")}]`,
    );
  }
}

function deepClone(value) {
  return structuredClone(value);
}

function sorted(values) {
  return [...values].sort();
}

function normalizeState(state) {
  const normalized = deepClone(state);
  normalized.suspended = sorted(unique(normalized.suspended));
  normalized.due = sorted(unique(normalized.due));
  normalized.completionQueued = sorted(unique(normalized.completionQueued));
  normalized.pendingCancellations = sorted(
    unique(normalized.pendingCancellations),
  );
  return normalized;
}

function stateKey(state) {
  const normalized = normalizeState(state);
  return JSON.stringify({
    phase: normalized.phase,
    bufferGeneration: normalized.bufferGeneration,
    typedAhead: normalized.typedAhead,
    pendingSubmission: normalized.pendingSubmission,
    executing: normalized.executing,
    suspended: normalized.suspended,
    due: normalized.due,
    completionQueued: normalized.completionQueued,
    pendingCancellations: normalized.pendingCancellations,
    escapeCredit: normalized.escapeCredit,
    promise: normalized.promise,
    cause: normalized.cause,
    exitCode: normalized.exitCode,
    ended: normalized.ended,
  });
}

function sameState(left, right) {
  return stateKey(left) === stateKey(right);
}

function assertMember(value, values, label) {
  if (!values.includes(value)) {
    throw new Error(`${label}: unknown value ${JSON.stringify(value)}`);
  }
}

function validateState(machine, input, label = "state") {
  const state = normalizeState(input);
  const phases = ["idle", "editing", "continuation", "evaluating", "shutdown"];
  const pending = ["none", "undispatched", "dispatched", "discarded"];
  const promises = ["none", "orderly", "interrupt-130"];
  assertMember(state.phase, phases, `${label}.phase`);
  assertMember(state.pendingSubmission, pending, `${label}.pendingSubmission`);
  assertMember(state.promise, promises, `${label}.promise`);
  if (![0, 1].includes(state.bufferGeneration)) {
    throw new Error(`${label}.bufferGeneration must be the finite parity abstraction`);
  }
  if (!Number.isInteger(state.escapeCredit) || state.escapeCredit < 0 || state.escapeCredit > 3) {
    throw new Error(`${label}.escapeCredit is outside 0..3`);
  }
  if (state.phase === "evaluating" && state.pendingSubmission === "none") {
    throw new Error(`${label}: evaluating requires a pending/discarded submission`);
  }
  if (state.phase !== "evaluating" && state.pendingSubmission !== "none") {
    throw new Error(`${label}: only evaluating may carry a submission`);
  }
  if (state.cause === null && state.phase === "shutdown") {
    throw new Error(`${label}: shutdown requires a latched cause`);
  }
  if (state.cause !== null && state.phase !== "shutdown") {
    throw new Error(`${label}: a latched cause requires shutdown`);
  }
  if (state.ended && state.cause === null) {
    throw new Error(`${label}: an ended session requires a cause`);
  }
  if (state.promise !== "none" && state.escapeCredit === 0) {
    throw new Error(`${label}: a promise requires a prior interrupt credit`);
  }
  if (state.cause === null && state.promise === "none" && state.escapeCredit >= 2) {
    throw new Error(`${label}: an unpromised credit >=2 is unreachable`);
  }
  for (const target of [
    ...state.suspended,
    ...state.pendingCancellations,
  ]) {
    assertMember(target, machine.identityDomains.targets, `${label}.target`);
  }
  for (const sched of state.due) {
    assertMember(sched, machine.identityDomains.schedules, `${label}.due`);
  }
  for (const request of state.completionQueued) {
    assertMember(
      request,
      machine.identityDomains.completionRequests,
      `${label}.completionQueued`,
    );
  }
  if (state.executing !== null) {
    assertMember(
      state.executing.target,
      machine.identityDomains.targets,
      `${label}.executing.target`,
    );
    assertMember(
      state.executing.role,
      ["evaluation", "callback", "completion"],
      `${label}.executing.role`,
    );
    if (state.suspended.includes(state.executing.target)) {
      throw new Error(`${label}: one target cannot be executing and suspended`);
    }
  }
  if (state.cause !== null) {
    if (
      typeof state.cause.kind !== "string" ||
      !Number.isInteger(state.cause.status)
    ) {
      throw new Error(`${label}: malformed cause`);
    }
  }
  return state;
}

function derived(state) {
  return {
    hasExecuting: state.executing !== null,
    hasSuspendedOrDue: state.suspended.length > 0 || state.due.length > 0,
    executingCompletion: state.executing?.role === "completion",
    hasCompletionQueued: state.completionQueued.length > 0,
  };
}

function guardMatches(state, guard) {
  const facts = { ...state, ...derived(state) };
  return Object.entries(guard).every(([key, expected]) => {
    const actual = facts[key];
    return Array.isArray(expected)
      ? expected.includes(actual)
      : actual === expected;
  });
}

function matchingInterruptRows(machine, state) {
  return machine.interruptRows.filter((row) => guardMatches(state, row.when));
}

function selectInterruptRow(machine, state) {
  const matches = matchingInterruptRows(machine, state);
  if (matches.length !== 1) {
    throw new Error(
      `interrupt transition is ${matches.length === 0 ? "missing" : "ambiguous"} for ${stateKey(state)}; rows=[${matches.map((row) => row.id).join(", ")}]`,
    );
  }
  return matches[0];
}

function bumpGeneration(state) {
  state.bufferGeneration = (state.bufferGeneration + 1) % 2;
}

function latchCause(state, kind, status) {
  if (state.cause !== null) return;
  state.cause = { kind, status };
  state.phase = "shutdown";
  state.pendingSubmission = "none";
  // Once precedence is cause-owned, target-selection fields are observationally
  // irrelevant to the interrupt machine. Collapse them so exhaustive search
  // does not manufacture a second copy of the shutdown state for every worker
  // arrangement that cleanup may still be dismantling.
  state.typedAhead = false;
  state.executing = null;
  state.suspended = [];
  state.due = [];
  state.completionQueued = [];
  state.pendingCancellations = [];
}

function promisedStatus(state, promise) {
  if (promise === "orderly") {
    return { status: state.exitCode, statusClass: "orderly", causeKind: "orderly" };
  }
  return { status: 130, statusClass: "interrupt-130", causeKind: "interrupt" };
}

export function applyInterrupt(machine, input) {
  const previous = validateState(machine, input, "interrupt input");
  if (previous.ended) return null;
  const state = deepClone(previous);
  state.escapeCredit = Math.min(3, state.escapeCredit + 1);
  const result = {
    event: "interrupt",
    branch: null,
    row: null,
    terminal: false,
    expedited: false,
    status: null,
    statusClass: null,
    notice: "none",
    promiseSet: "none",
    promiseCleared: false,
    cancelTarget: null,
    abandonedCompletionRequests: [],
    buffer: "unchanged",
    submission: "unchanged",
  };

  // Termination and status precedence are independent of the current target.
  if (previous.cause !== null) {
    result.branch = "latched-cause";
    result.terminal = true;
    result.expedited = true;
    result.status = previous.cause.status;
    result.statusClass = "cause";
    return { state: validateState(machine, state), result };
  }
  if (previous.promise !== "none") {
    const promised = promisedStatus(previous, previous.promise);
    result.branch = "prior-promise";
    result.terminal = true;
    result.status = promised.status;
    result.statusClass = promised.statusClass;
    latchCause(state, promised.causeKind, promised.status);
    return { state: validateState(machine, state), result };
  }
  if (state.escapeCredit >= 3) {
    // Defensive safe default. The model proves this branch unreachable.
    result.branch = "credit-three";
    result.terminal = true;
    result.status = 130;
    result.statusClass = "interrupt-130";
    latchCause(state, "interrupt", 130);
    return { state: validateState(machine, state), result };
  }

  const row = selectInterruptRow(machine, previous);
  const decision = row.decision;
  result.branch = "target-row";
  result.row = row.id;
  result.notice = decision.notice;
  result.buffer = decision.buffer;
  result.submission = decision.submission;

  let invalidateBuffer =
    decision.buffer === "preserve-invalidate" ||
    decision.buffer === "discard-invalidate";
  if (decision.abandonCompletion && state.completionQueued.length > 0) {
    result.abandonedCompletionRequests = [...state.completionQueued];
    state.completionQueued = [];
    invalidateBuffer = true;
  }
  if (decision.raiseCancellation === "executing") {
    if (previous.executing === null) {
      throw new Error(`${row.id}: requested cancellation without Executing{id}`);
    }
    result.cancelTarget = previous.executing.target;
    state.pendingCancellations = sorted(
      unique([...state.pendingCancellations, previous.executing.target]),
    );
  }
  if (invalidateBuffer) bumpGeneration(state);
  if (decision.buffer === "discard-invalidate") state.phase = "idle";
  if (decision.submission === "discard") {
    state.pendingSubmission = "discarded";
    state.typedAhead = false;
  } else if (decision.submission === "discard-and-idle") {
    state.pendingSubmission = "none";
    state.typedAhead = false;
    state.phase = "idle";
  }
  if (decision.promise !== "none") {
    state.promise = decision.promise;
    result.promiseSet = decision.promise;
  }
  return { state: validateState(machine, state), result };
}

function eventRule(machine, eventName) {
  const matches = machine.eventRules.filter((row) => row.event === eventName);
  if (matches.length !== 1) {
    throw new Error(
      `event ${eventName} has ${matches.length} rules; exactly one is required`,
    );
  }
  return matches[0];
}

function transitionResult(event, extra = {}) {
  return {
    event: event.event,
    branch: "event-rule",
    row: null,
    terminal: false,
    expedited: false,
    status: null,
    statusClass: null,
    notice: "none",
    promiseSet: "none",
    promiseCleared: false,
    cancelTarget: null,
    abandonedCompletionRequests: [],
    buffer: "unchanged",
    submission: "unchanged",
    ...extra,
  };
}

function applyEventRule(machine, input, event, rule) {
  const previous = validateState(machine, input, `${event.event} input`);
  if (previous.ended) return null;
  if (previous.cause !== null && rule.operation !== "session-end") return null;
  const state = deepClone(previous);
  const result = transitionResult(event, { rule: rule.id });
  const targets = machine.identityDomains.targets;
  const schedules = machine.identityDomains.schedules;
  const requests = machine.identityDomains.completionRequests;

  switch (rule.operation) {
    case "accept-editor-input": {
      if (!["idle", "editing", "continuation"].includes(state.phase)) return null;
      if (!["idle", "editing", "continuation"].includes(event.nextPhase)) return null;
      result.promiseCleared = state.promise !== "none";
      state.promise = "none";
      state.escapeCredit = 0;
      state.phase = event.nextPhase;
      break;
    }
    case "record-typed-ahead": {
      if (state.phase !== "evaluating") return null;
      state.typedAhead = true;
      break;
    }
    case "drain-typed-ahead": {
      if (!state.typedAhead || !["idle", "editing", "continuation"].includes(state.phase)) {
        return null;
      }
      state.typedAhead = false;
      break;
    }
    case "submit": {
      if (!["editing", "continuation"].includes(state.phase)) return null;
      state.phase = "evaluating";
      state.pendingSubmission = "undispatched";
      state.typedAhead = false;
      break;
    }
    case "dispatch": {
      if (state.phase !== "evaluating" || state.pendingSubmission !== "undispatched") {
        return null;
      }
      state.pendingSubmission = "dispatched";
      break;
    }
    case "due": {
      if (!schedules.includes(event.sched) || state.due.includes(event.sched)) return null;
      state.due.push(event.sched);
      break;
    }
    case "undue": {
      if (!schedules.includes(event.sched) || !state.due.includes(event.sched)) return null;
      state.due = state.due.filter((value) => value !== event.sched);
      break;
    }
    case "unit-begin": {
      if (state.executing !== null || !targets.includes(event.target)) return null;
      if (!["evaluation", "callback"].includes(event.role)) return null;
      if (state.suspended.includes(event.target)) return null;
      if (event.role === "evaluation") {
        if (
          event.target !== "evaluation-1" ||
          state.phase !== "evaluating" ||
          state.pendingSubmission !== "dispatched" ||
          event.sched !== undefined
        ) {
          return null;
        }
      } else {
        if (!schedules.includes(event.sched) || !state.due.includes(event.sched)) {
          return null;
        }
        state.due = state.due.filter((value) => value !== event.sched);
      }
      state.executing = { target: event.target, role: event.role };
      break;
    }
    case "unit-end": {
      if (state.executing?.target !== event.target) return null;
      const role = state.executing.role;
      state.executing = null;
      if (role === "evaluation" && state.suspended.length === 0) {
        state.pendingSubmission = "none";
        state.phase = "idle";
      }
      break;
    }
    case "suspend": {
      if (
        state.executing?.target !== event.target ||
        state.executing.role !== "evaluation"
      ) {
        return null;
      }
      state.executing = null;
      state.suspended.push(event.target);
      break;
    }
    case "settle": {
      if (!state.suspended.includes(event.target)) return null;
      state.suspended = state.suspended.filter((value) => value !== event.target);
      if (state.suspended.length === 0 && state.executing === null) {
        state.pendingSubmission = "none";
        state.phase = "idle";
      }
      break;
    }
    case "completion-queue": {
      if (
        !requests.includes(event.request) ||
        state.completionQueued.includes(event.request) ||
        state.executing?.role === "completion" ||
        !["idle", "editing", "continuation"].includes(state.phase)
      ) {
        return null;
      }
      state.completionQueued.push(event.request);
      break;
    }
    case "completion-begin": {
      if (
        state.executing !== null ||
        !requests.includes(event.request) ||
        !state.completionQueued.includes(event.request) ||
        event.target !== "completion-1"
      ) {
        return null;
      }
      state.completionQueued = state.completionQueued.filter(
        (value) => value !== event.request,
      );
      state.executing = { target: event.target, role: "completion" };
      break;
    }
    case "quiescence": {
      if (
        state.executing !== null ||
        state.suspended.length > 0 ||
        state.due.length > 0
      ) {
        return null;
      }
      if (state.phase === "evaluating" && state.pendingSubmission === "discarded") {
        state.pendingSubmission = "none";
        state.phase = "idle";
      }
      break;
    }
    case "cancellation-resolve": {
      if (
        !targets.includes(event.target) ||
        !state.pendingCancellations.includes(event.target) ||
        !["accepted", "unavailable", "failed", "defeated"].includes(event.outcome)
      ) {
        return null;
      }
      state.pendingCancellations = state.pendingCancellations.filter(
        (value) => value !== event.target,
      );
      if (event.outcome === "failed") latchCause(state, "fault", 70);
      break;
    }
    case "exit-code-set": {
      if (!Number.isInteger(event.status) || ![0, 7].includes(event.status)) return null;
      if (state.cause !== null) return null;
      state.exitCode = event.status;
      break;
    }
    case "cause-latch": {
      if (
        state.cause !== null ||
        ![
          ["orderly", 0],
          ["cooperative", 7],
          ["sigterm", 143],
          ["fault", 70],
        ].some(([kind, status]) => kind === event.kind && status === event.status)
      ) {
        return null;
      }
      latchCause(state, event.kind, event.status);
      break;
    }
    case "session-end": {
      if (state.cause === null) return null;
      result.promiseCleared = state.promise !== "none";
      state.promise = "none";
      state.escapeCredit = 0;
      state.ended = true;
      break;
    }
    default:
      throw new Error(`unknown event operation ${rule.operation}`);
  }

  return { state: validateState(machine, normalizeState(state)), result };
}

export function applyEvent(machine, state, event) {
  if (!event || typeof event.event !== "string") {
    throw new Error("event must carry an event name");
  }
  if (event.event === "interrupt") return applyInterrupt(machine, state);
  const alphabetEntry = machine.eventAlphabet.find((row) => row.id === event.event);
  if (!alphabetEntry) throw new Error(`unknown event ${event.event}`);
  if (alphabetEntry.kind === "derived-atomic") {
    throw new Error(`${event.event} is an atomic derived event, not scheduler input`);
  }
  return applyEventRule(machine, state, event, eventRule(machine, event.event));
}

export function enumerateSchedulerEvents(machine) {
  const events = [
    { event: "interrupt" },
    ...["idle", "editing", "continuation"].map((nextPhase) => ({
      event: "editor-input-at-prompt",
      nextPhase,
    })),
    { event: "typed-ahead-byte" },
    { event: "drain-typed-ahead" },
    { event: "submit" },
    { event: "dispatch" },
    { event: "quiescence" },
    { event: "session-end" },
    { event: "suspend", target: "evaluation-1" },
    { event: "settle", target: "evaluation-1" },
    { event: "unit-begin", target: "evaluation-1", role: "evaluation" },
    ...machine.identityDomains.schedules.flatMap((sched) => [
      { event: "due", sched },
      { event: "undue", sched },
      ...["callback-1"].map((target) => ({
        event: "unit-begin",
        target,
        role: "callback",
        sched,
      })),
    ]),
    ...machine.identityDomains.targets.map((target) => ({
      event: "unit-end",
      target,
    })),
    ...machine.identityDomains.completionRequests.flatMap((request) => [
      { event: "completion-queue", request },
      {
        event: "completion-begin",
        request,
        target: "completion-1",
      },
    ]),
    // Cancellation resolution and additional identity values are exercised by
    // generated named trajectories. They do not alter credit/promise except
    // `failed`, whose cause-latch behavior is represented directly below.
    { event: "exit-code-set", status: 0 },
    { event: "cause-latch", kind: "cooperative", status: 7 },
  ];
  return events;
}

function validateStaticMachine(machine) {
  // Keep validation dependency-free so this security gate runs in a minimal
  // checkout. The checked-in JSON Schema is the external contract; these
  // fail-closed structural checks are its executable counterpart.
  JSON.parse(fs.readFileSync(machineSchemaPath, "utf8"));
  if (
    machine === null ||
    typeof machine !== "object" ||
    machine.version !== 1 ||
    machine.id !== "ibex-terminal-interrupt-machine" ||
    machine.sourceRef !== "LLP 0025#6-interruption-and-cancellation" ||
    !machine.identityDomains ||
    !machine.initialState ||
    !Array.isArray(machine.properties) ||
    !Array.isArray(machine.eventAlphabet) ||
    !Array.isArray(machine.interruptRows) ||
    !Array.isArray(machine.eventRules) ||
    !Array.isArray(machine.namedSchedules)
  ) {
    throw new Error("interrupt machine failed structural schema validation");
  }
  assertExactKeys(
    machine,
    [
      "$schema",
      "version",
      "id",
      "sourceRef",
      "identityDomains",
      "initialState",
      "properties",
      "eventAlphabet",
      "dispatchPrecedence",
      "interruptRows",
      "eventRules",
      "namedSchedules",
    ],
    [],
    "interrupt machine",
  );
  assertExactKeys(
    machine.identityDomains,
    ["targets", "schedules", "completionRequests"],
    [],
    "identityDomains",
  );
  for (const [index, property] of machine.properties.entries()) {
    assertExactKeys(
      property,
      ["id", "expression"],
      ["statusRule"],
      `properties[${index}]`,
    );
  }
  for (const [index, event] of machine.eventAlphabet.entries()) {
    assertExactKeys(
      event,
      ["id", "kind"],
      ["description"],
      `eventAlphabet[${index}]`,
    );
  }
  for (const [index, row] of machine.interruptRows.entries()) {
    assertExactKeys(
      row,
      ["id", "label", "when", "decision"],
      [],
      `interruptRows[${index}]`,
    );
    assertExactKeys(
      row.decision,
      [
        "notice",
        "promise",
        "abandonCompletion",
        "raiseCancellation",
        "buffer",
        "submission",
      ],
      [],
      `interruptRows[${index}].decision`,
    );
  }
  for (const [index, rule] of machine.eventRules.entries()) {
    assertExactKeys(
      rule,
      ["id", "event", "operation"],
      [],
      `eventRules[${index}]`,
    );
  }
  for (const [index, schedule] of machine.namedSchedules.entries()) {
    assertExactKeys(
      schedule,
      ["id", "llpSchedule", "title", "steps", "expect"],
      [],
      `namedSchedules[${index}]`,
    );
    for (const [stepIndex, step] of schedule.steps.entries()) {
      assertExactKeys(
        step,
        ["event"],
        ["expect"],
        `namedSchedules[${index}].steps[${stepIndex}]`,
      );
    }
  }
  assertUnique(machine.identityDomains.targets, "target identities");
  assertUnique(machine.identityDomains.schedules, "schedule identities");
  assertUnique(
    machine.identityDomains.completionRequests,
    "completion request identities",
  );
  assertUnique(machine.eventAlphabet.map((row) => row.id), "event alphabet ids");
  assertUnique(machine.eventRules.map((row) => row.id), "event rule ids");
  assertUnique(machine.eventRules.map((row) => row.event), "event rule events");
  assertUnique(machine.interruptRows.map((row) => row.id), "interrupt row ids");
  assertUnique(machine.namedSchedules.map((row) => row.id), "schedule fixture ids");
  for (const row of machine.eventRules) {
    if (!KNOWN_OPERATIONS.has(row.operation)) {
      throw new Error(`${row.id}: unknown operation ${row.operation}`);
    }
  }
  const externalEvents = machine.eventAlphabet
    .filter((row) => row.kind === "external" && row.id !== "interrupt")
    .map((row) => row.id)
    .sort();
  const ruledEvents = machine.eventRules.map((row) => row.event).sort();
  if (JSON.stringify(externalEvents) !== JSON.stringify(ruledEvents)) {
    throw new Error(
      `event rules do not exactly cover external alphabet; external=${externalEvents.join(",")} rules=${ruledEvents.join(",")}`,
    );
  }
  for (const row of machine.interruptRows) {
    for (const key of Object.keys(row.when)) {
      if (!GUARD_KEYS.has(key)) throw new Error(`${row.id}: unknown guard key ${key}`);
    }
  }
  const propertyById = new Map(
    machine.properties.map((property) => [property.id, property]),
  );
  if (propertyById.get("escape-bound")?.expression !== EXACT_ESCAPE_PROPERTY) {
    throw new Error(`escape-bound must be textually exact: ${EXACT_ESCAPE_PROPERTY}`);
  }
  const promise = propertyById.get("notice-promise");
  if (
    promise?.expression !== EXACT_PROMISE_PROPERTY ||
    promise?.statusRule !== EXACT_STATUS_RULE
  ) {
    throw new Error(
      `notice-promise must be textually exact and retain promised status unless cause-latched`,
    );
  }
  const letters = new Set(machine.namedSchedules.map((row) => row.llpSchedule));
  for (const letter of "abcdefghijklmn") {
    if (!letters.has(letter)) throw new Error(`missing LLP 0025 schedule (${letter})`);
  }
  validateState(machine, machine.initialState, "initialState");
}

export function loadInterruptMachine(
  sourcePath = machineSourcePath,
  { validateModel = true } = {},
) {
  const source = fs.readFileSync(sourcePath, "utf8");
  const machine = JSON.parse(source);
  validateStaticMachine(machine);
  if (validateModel) modelCheck(machine);
  return { machine, source };
}

export function exploreReachableStates(machine) {
  const events = enumerateSchedulerEvents(machine);
  const initial = validateState(machine, machine.initialState, "initialState");
  const initialKey = stateKey(initial);
  const states = new Map([[initialKey, initial]]);
  const queue = [initialKey];
  const edges = new Map();
  const rowHits = new Map(machine.interruptRows.map((row) => [row.id, 0]));
  const branchHits = new Map(
    machine.dispatchPrecedence.termination.map((branch) => [branch, 0]),
  );
  let transitionCount = 0;

  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const fromKey = queue[cursor];
    const state = states.get(fromKey);
    const outgoing = [];
    for (const event of events) {
      const transition = applyEvent(machine, state, event);
      if (transition === null) continue;
      const to = normalizeState(transition.state);
      const toKey = stateKey(to);
      transitionCount += 1;
      outgoing.push({ event, toKey, result: transition.result });
      if (event.event === "interrupt") {
        branchHits.set(
          transition.result.branch,
          (branchHits.get(transition.result.branch) ?? 0) + 1,
        );
        if (transition.result.row !== null) {
          rowHits.set(
            transition.result.row,
            (rowHits.get(transition.result.row) ?? 0) + 1,
          );
        }
      }
      if (!states.has(toKey)) {
        states.set(toKey, to);
        queue.push(toKey);
        if (states.size > MAX_REACHABLE_STATES) {
          throw new Error(`model exceeded ${MAX_REACHABLE_STATES} reachable states`);
        }
      }
    }
    edges.set(fromKey, outgoing);
  }

  for (const [row, hits] of rowHits) {
    if (hits === 0) throw new Error(`unreachable interrupt transition row: ${row}`);
  }
  if ((branchHits.get("credit-three") ?? 0) !== 0) {
    throw new Error("unpromised credit-three fallback became reachable");
  }
  return { states, edges, rowHits, branchHits, transitionCount };
}

function promisedExpectedStatus(state) {
  if (state.cause !== null) {
    return { status: state.cause.status, statusClass: "cause" };
  }
  const promised = promisedStatus(state, state.promise);
  return { status: promised.status, statusClass: promised.statusClass };
}

function checkLocalTemporalProperties(machine, graph) {
  for (const [key, state] of graph.states) {
    if (state.escapeCredit > 3) {
      throw new Error(`${EXACT_ESCAPE_PROPERTY} failed at ${key}`);
    }
    const outgoing = graph.edges.get(key) ?? [];
    for (const edge of outgoing) {
      const next = graph.states.get(edge.toKey);
      if (
        edge.event.event !== "interrupt" &&
        edge.event.event !== "editor-input-at-prompt" &&
        edge.event.event !== "session-end"
      ) {
        if (next.escapeCredit !== state.escapeCredit) {
          throw new Error(`non-editor event ${edge.event.event} reset escape credit`);
        }
        if (next.promise !== state.promise) {
          throw new Error(`non-editor event ${edge.event.event} changed promise`);
        }
      }
      if (edge.event.event === "interrupt" && state.promise !== "none") {
        const expected = promisedExpectedStatus(state);
        if (
          !edge.result.terminal ||
          edge.result.status !== expected.status ||
          edge.result.statusClass !== expected.statusClass
        ) {
          throw new Error(
            `${EXACT_PROMISE_PROPERTY} failed at ${key}; expected ${JSON.stringify(expected)}, got ${JSON.stringify(edge.result)}`,
          );
        }
      }
      if (
        edge.event.event === "interrupt" &&
        edge.result.promiseSet !== "none" &&
        edge.result.terminal
      ) {
        throw new Error("a first-row promise was not reserved for the next interrupt");
      }
    }
  }
}

function checkAdversarialEscapeBound(graph) {
  // Start a fresh adversarial run at every reachable state. The scheduler may
  // take any number of non-editor transitions between interrupts. Editor input
  // and session end deliberately terminate the consecutive-interrupt run.
  const queue = [];
  const visited = new Set();
  for (const key of graph.states.keys()) {
    const token = `${key}\u00000`;
    visited.add(token);
    queue.push({ key, interrupts: 0 });
  }
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const current = queue[cursor];
    for (const edge of graph.edges.get(current.key) ?? []) {
      if (
        edge.event.event === "editor-input-at-prompt" ||
        edge.event.event === "session-end"
      ) {
        continue;
      }
      if (edge.event.event === "interrupt") {
        const interrupts = current.interrupts + 1;
        if (edge.result.terminal) continue;
        if (interrupts >= 3) {
          throw new Error(
            `${EXACT_ESCAPE_PROPERTY} failed after adversarial interleaving at ${current.key}`,
          );
        }
        const token = `${edge.toKey}\u0000${interrupts}`;
        if (!visited.has(token)) {
          visited.add(token);
          queue.push({ key: edge.toKey, interrupts });
        }
      } else {
        const token = `${edge.toKey}\u0000${current.interrupts}`;
        if (!visited.has(token)) {
          visited.add(token);
          queue.push({ key: edge.toKey, interrupts: current.interrupts });
        }
      }
    }
  }
  return visited.size;
}

export function modelCheck(machine) {
  validateStaticMachine(machine);
  const graph = exploreReachableStates(machine);
  checkLocalTemporalProperties(machine, graph);
  const adversarialProductStates = checkAdversarialEscapeBound(graph);
  return {
    reachableStates: graph.states.size,
    transitions: graph.transitionCount,
    adversarialProductStates,
    rowHits: Object.fromEntries(graph.rowHits),
    branchHits: Object.fromEntries(graph.branchHits),
    properties: [EXACT_ESCAPE_PROPERTY, EXACT_PROMISE_PROPERTY],
    statusRule: EXACT_STATUS_RULE,
    graph,
  };
}

function actualExpectationValue(state, result, key) {
  switch (key) {
    case "row":
      return result.row;
    case "terminal":
      return result.terminal;
    case "status":
    case "finalStatus":
      return result.status;
    case "statusClass":
      return result.statusClass;
    case "notice":
      return result.notice;
    case "cancelTarget":
      return result.cancelTarget;
    case "expedited":
      return result.expedited;
    case "promise":
      return state.promise;
    case "causeKind":
      return state.cause?.kind ?? null;
    case "phase":
      return state.phase;
    case "bufferGeneration":
      return state.bufferGeneration;
    case "typedAhead":
      return state.typedAhead;
    case "pendingSubmission":
      return state.pendingSubmission;
    case "escapeCredit":
      return state.escapeCredit;
    case "completionQueued":
      return state.completionQueued;
    case "due":
      return state.due;
    case "pendingCancellations":
      return state.pendingCancellations;
    case "executingTarget":
      return state.executing?.target ?? null;
    default:
      throw new Error(`unknown fixture expectation ${key}`);
  }
}

function assertExpectations(scheduleId, label, state, result, expectations) {
  for (const [key, expected] of Object.entries(expectations ?? {})) {
    if (["interrupts"].includes(key)) continue;
    const actual = actualExpectationValue(state, result, key);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error(
        `${scheduleId} ${label}: expected ${key}=${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
      );
    }
  }
}

function traceState(state) {
  return {
    phase: state.phase,
    bufferGeneration: state.bufferGeneration,
    typedAhead: state.typedAhead,
    pendingSubmission: state.pendingSubmission,
    executing: state.executing,
    suspended: state.suspended,
    due: state.due,
    completionQueued: state.completionQueued,
    pendingCancellations: state.pendingCancellations,
    escapeCredit: state.escapeCredit,
    promise: state.promise,
    cause: state.cause,
    exitCode: state.exitCode,
    ended: state.ended,
  };
}

export function simulateNamedSchedules(machine) {
  return machine.namedSchedules.map((schedule) => {
    let state = validateState(machine, machine.initialState);
    let interrupts = 0;
    let lastResult = transitionResult({ event: "initial" });
    const trace = [{ index: 0, event: { event: "initial" }, state: traceState(state), result: null }];
    schedule.steps.forEach((step, index) => {
      const transition = applyEvent(machine, state, step.event);
      if (transition === null) {
        throw new Error(
          `${schedule.id} step ${index + 1}: event is not enabled: ${JSON.stringify(step.event)}`,
        );
      }
      state = transition.state;
      lastResult = transition.result;
      if (step.event.event === "interrupt") interrupts += 1;
      assertExpectations(
        schedule.id,
        `step ${index + 1}`,
        state,
        lastResult,
        step.expect,
      );
      trace.push({
        index: index + 1,
        event: step.event,
        state: traceState(state),
        result: lastResult,
      });
    });
    if (schedule.expect.interrupts !== interrupts) {
      throw new Error(
        `${schedule.id}: expected ${schedule.expect.interrupts} interrupts, got ${interrupts}`,
      );
    }
    assertExpectations(
      schedule.id,
      "final",
      state,
      lastResult,
      schedule.expect,
    );
    return {
      id: schedule.id,
      llpSchedule: schedule.llpSchedule,
      title: schedule.title,
      interruptCount: interrupts,
      trace,
    };
  });
}

function pascal(value) {
  return value
    .split("-")
    .map((part) => `${part[0].toUpperCase()}${part.slice(1)}`)
    .join("");
}

function rustPhase(value) {
  return `EditorPhase::${pascal(value)}`;
}

function rustGuard(guard) {
  return Object.entries(guard)
    .map(([key, expected]) => {
      const equals = (value) => {
        switch (key) {
          case "phase":
            return `state.phase == ${rustPhase(value)}`;
          case "pendingSubmission":
            return `state.pending_submission == PendingSubmission::${pascal(value)}`;
          case "hasExecuting":
            return value ? "state.executing.is_some()" : "state.executing.is_none()";
          case "hasSuspendedOrDue":
            return value
              ? "!state.suspended_ids.is_empty() || !state.due_schedules.is_empty()"
              : "state.suspended_ids.is_empty() && state.due_schedules.is_empty()";
          case "executingCompletion":
            return value
              ? "matches!(state.executing, Some(unit) if unit.kind == WorkKind::Completion)"
              : "!matches!(state.executing, Some(unit) if unit.kind == WorkKind::Completion)";
          case "hasCompletionQueued":
            return value
              ? "state.completion_queued.is_some()"
              : "state.completion_queued.is_none()";
          default:
            throw new Error(`cannot render Rust guard ${key}`);
        }
      };
      return Array.isArray(expected)
        ? `(${expected.map(equals).join(" || ")})`
        : `(${equals(expected)})`;
    })
    .join(" && ");
}

function rustDecision(row) {
  const decision = row.decision;
  const notice = `Notice::${pascal(decision.notice)}`;
  const promise = `PromiseClass::${pascal(decision.promise)}`;
  const buffer = `BufferAction::${pascal(decision.buffer)}`;
  const submission = `SubmissionAction::${pascal(decision.submission)}`;
  const cancel =
    decision.raiseCancellation === "executing"
      ? "state.executing.map(|unit| unit.id)"
      : "None";
  return `InterruptDecision {
            branch: DispatchBranch::TargetRow,
            row: Some(InterruptRow::${pascal(row.id)}),
            terminal: false,
            expedited: false,
            next_credit,
            status: None,
            status_class: None,
            notice: ${notice},
            promise_to_set: ${promise},
            abandon_completion: ${decision.abandonCompletion},
            cancel_target: ${cancel},
            buffer: ${buffer},
            submission: ${submission},
        }`;
}

function renderRust(machine, binding) {
  const rowVariants = machine.interruptRows
    .map((row) => `    ${pascal(row.id)},`)
    .join("\n");
  const rowBranches = machine.interruptRows
    .map(
      (row) => `    if ${rustGuard(row.when)} {
        matches += 1;
        selected = Some(${rustDecision(row)});
    }`,
    )
    .join("\n");
  return `// @generated by packages/ibex-devtools/src/scripts/generate-interrupt-machine.mjs
// Source: session/interrupt-machine.v1.json
// Source SHA-256: ${binding.sourceDigest}
// Generator SHA-256: ${binding.generatorDigest}
// Do not edit by hand.
// @ref LLP 0025#6-interruption-and-cancellation

#![allow(dead_code)]

pub const INTERRUPT_MACHINE_SOURCE_SHA256: &str = "${binding.sourceDigest}";
pub const INTERRUPT_MACHINE_GENERATOR_SHA256: &str = "${binding.generatorDigest}";
pub const ESCAPE_TEMPORAL_PROPERTY: &str = "${EXACT_ESCAPE_PROPERTY}";
pub const PROMISE_TEMPORAL_PROPERTY: &str = "${EXACT_PROMISE_PROPERTY}";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditorPhase { Idle, Editing, Continuation, Evaluating, Shutdown }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingSubmission { None, Undispatched, Dispatched, Discarded }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkKind { Evaluation, Callback, Completion }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutingUnit { pub id: u64, pub kind: WorkKind }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromiseClass { None, Orderly, Interrupt130 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminationCause { pub status: i32 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptState<'a> {
    pub phase: EditorPhase,
    pub pending_submission: PendingSubmission,
    pub executing: Option<ExecutingUnit>,
    pub suspended_ids: &'a [u64],
    /// Scheduling identities are distinct from cancellation target ids.
    pub due_schedules: &'a [u64],
    pub completion_queued: Option<u64>,
    pub escape_credit: u8,
    pub promise: PromiseClass,
    pub cause: Option<TerminationCause>,
    pub exit_code: i32,
    pub ended: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchBranch { LatchedCause, PriorPromise, CreditThree, TargetRow }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptRow {
${rowVariants}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusClass { Cause, Orderly, Interrupt130 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Notice { None, OrderlyPromise, CancellingWork, WorkInFlight, CancellingCompletion, InputDiscarded }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferAction { Unchanged, PreserveInvalidate, DiscardInvalidate }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionAction { Unchanged, Discard, DiscardAndIdle }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptDecision {
    pub branch: DispatchBranch,
    pub row: Option<InterruptRow>,
    pub terminal: bool,
    pub expedited: bool,
    pub next_credit: u8,
    pub status: Option<i32>,
    pub status_class: Option<StatusClass>,
    pub notice: Notice,
    pub promise_to_set: PromiseClass,
    pub abandon_completion: bool,
    pub cancel_target: Option<u64>,
    pub buffer: BufferAction,
    pub submission: SubmissionAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidInterruptState { SessionEnded, MissingOrAmbiguousRow }

pub fn dispatch_interrupt(state: InterruptState<'_>) -> Result<InterruptDecision, InvalidInterruptState> {
    if state.ended { return Err(InvalidInterruptState::SessionEnded); }
    let next_credit = state.escape_credit.saturating_add(1).min(3);
    if let Some(cause) = state.cause {
        return Ok(InterruptDecision {
            branch: DispatchBranch::LatchedCause, row: None, terminal: true,
            expedited: true, next_credit, status: Some(cause.status),
            status_class: Some(StatusClass::Cause), notice: Notice::None,
            promise_to_set: PromiseClass::None, abandon_completion: false,
            cancel_target: None, buffer: BufferAction::Unchanged,
            submission: SubmissionAction::Unchanged,
        });
    }
    if state.promise != PromiseClass::None {
        let (status, status_class) = match state.promise {
            PromiseClass::Orderly => (state.exit_code, StatusClass::Orderly),
            PromiseClass::Interrupt130 => (130, StatusClass::Interrupt130),
            PromiseClass::None => unreachable!(),
        };
        return Ok(InterruptDecision {
            branch: DispatchBranch::PriorPromise, row: None, terminal: true,
            expedited: false, next_credit, status: Some(status),
            status_class: Some(status_class), notice: Notice::None,
            promise_to_set: PromiseClass::None, abandon_completion: false,
            cancel_target: None, buffer: BufferAction::Unchanged,
            submission: SubmissionAction::Unchanged,
        });
    }
    if next_credit >= 3 {
        return Ok(InterruptDecision {
            branch: DispatchBranch::CreditThree, row: None, terminal: true,
            expedited: false, next_credit, status: Some(130),
            status_class: Some(StatusClass::Interrupt130), notice: Notice::None,
            promise_to_set: PromiseClass::None, abandon_completion: false,
            cancel_target: None, buffer: BufferAction::Unchanged,
            submission: SubmissionAction::Unchanged,
        });
    }

    let mut selected = None;
    let mut matches = 0_u8;
${rowBranches}
    if matches != 1 { return Err(InvalidInterruptState::MissingOrAmbiguousRow); }
    Ok(selected.expect("one generated row matched"))
}
`;
}

function renderTable(machine, binding, summary) {
  const rows = machine.interruptRows
    .map((row) => {
      const guard = Object.entries(row.when)
        .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
        .join(", ");
      const decision = row.decision;
      return `| \`${row.id}\` | ${row.label} | ${guard} | ${decision.notice} | ${decision.promise} | ${decision.raiseCancellation} | ${decision.buffer} | ${decision.submission} |`;
    })
    .join("\n");
  const events = machine.eventAlphabet
    .map((event) => `- \`${event.id}\` (${event.kind})${event.description ? ` — ${event.description}` : ""}`)
    .join("\n");
  return `<!-- @generated by packages/ibex-devtools/src/scripts/generate-interrupt-machine.mjs -->
<!-- Source SHA-256: ${binding.sourceDigest}; generator SHA-256: ${binding.generatorDigest} -->

# LLP 0025 interrupt machine, generated table

- Source: \`session/interrupt-machine.v1.json\`
- Reachable states: ${summary.reachableStates}
- Reachable transitions: ${summary.transitions}
- Adversarial product states checked: ${summary.adversarialProductStates}
- Termination precedence: ${machine.dispatchPrecedence.termination.map((value) => `\`${value}\``).join(" → ")}
- Status precedence: ${machine.dispatchPrecedence.status.map((value) => `\`${value}\``).join(" → ")}
- Property: \`${EXACT_ESCAPE_PROPERTY}\`
- Property: \`${EXACT_PROMISE_PROPERTY}\`; ${EXACT_STATUS_RULE}.

## First-interrupt rows

| id | row | guard | notice | promise | cancellation | buffer | submission |
| --- | --- | --- | --- | --- | --- | --- | --- |
${rows}

The generated dispatch applies latched-cause, prior-promise, and credit-three
precedence before these rows. A lone \`CompletionQueued\` is abandoned before
the idle-prompt row is selected; only \`Executing{id}\` can raise a request.

## Event alphabet

${events}
`;
}

function renderTrajectories(machine, binding, summary, schedules) {
  return prettyJson({
    generated: true,
    version: 1,
    source: {
      path: relative(machineSourcePath),
      sha256: binding.sourceDigest,
    },
    generator: {
      path: relative(generatorPath),
      sha256: binding.generatorDigest,
    },
    modelCheck: {
      reachableStates: summary.reachableStates,
      transitions: summary.transitions,
      adversarialProductStates: summary.adversarialProductStates,
      rowHits: summary.rowHits,
      branchHits: summary.branchHits,
      properties: summary.properties,
      statusRule: summary.statusRule,
    },
    schedules,
  });
}

export function renderInterruptArtifacts(
  machine,
  {
    source = prettyJson(machine),
    generatorSource = fs.readFileSync(generatorPath, "utf8"),
  } = {},
) {
  validateStaticMachine(machine);
  const summary = modelCheck(machine);
  const schedules = simulateNamedSchedules(machine);
  const binding = {
    sourceDigest: digest(source),
    generatorDigest: digest(generatorSource),
  };
  const artifacts = {
    rust: renderRust(machine, binding),
    table: renderTable(machine, binding, summary),
    trajectories: renderTrajectories(machine, binding, summary, schedules),
  };
  const manifest = prettyJson({
    generated: true,
    version: 1,
    source: { path: relative(machineSourcePath), sha256: binding.sourceDigest },
    generator: { path: relative(generatorPath), sha256: binding.generatorDigest },
    outputs: Object.entries(artifacts).map(([name, content]) => ({
      name,
      path: relative(generatedInterruptPaths[name]),
      sha256: digest(content),
    })),
  });
  return { ...artifacts, manifest, summary, schedules, binding };
}

function outputEntries(rendered) {
  return Object.entries(generatedInterruptPaths).map(([name, filePath]) => ({
    path: filePath,
    content: rendered[name],
    label: `interrupt machine ${name}`,
  }));
}

export function checkInterruptArtifacts(rendered) {
  const stale = [];
  for (const [name, filePath] of Object.entries(generatedInterruptPaths)) {
    try {
      assertConfinedGeneratedFile(repoRoot, filePath, `interrupt machine ${name}`);
    } catch {
      stale.push(relative(filePath));
      continue;
    }
    if (fs.readFileSync(filePath, "utf8") !== rendered[name]) {
      stale.push(relative(filePath));
    }
  }
  return stale;
}

export function writeInterruptArtifacts(rendered) {
  writeGeneratedFilesTransactionally(repoRoot, outputEntries(rendered), () => {
    const stale = checkInterruptArtifacts(rendered);
    if (stale.length > 0) {
      throw new Error(`generated interrupt artifacts failed validation: ${stale.join(", ")}`);
    }
  });
}

function main(argv) {
  const write = argv.includes("--write");
  const check = argv.includes("--check");
  const unknown = argv.filter((arg) => !["--write", "--check"].includes(arg));
  if (unknown.length > 0 || write === check) {
    throw new Error(
      "usage: bun packages/ibex-devtools/src/scripts/generate-interrupt-machine.mjs (--write|--check)",
    );
  }
  const { machine, source } = loadInterruptMachine(machineSourcePath, {
    validateModel: false,
  });
  const rendered = renderInterruptArtifacts(machine, { source });
  if (write) {
    writeInterruptArtifacts(rendered);
    for (const filePath of Object.values(generatedInterruptPaths)) {
      console.log(`wrote ${relative(filePath)}`);
    }
    console.log(
      `model checked ${rendered.summary.reachableStates} states / ${rendered.summary.transitions} transitions`,
    );
    return;
  }
  const stale = checkInterruptArtifacts(rendered);
  if (stale.length > 0) {
    console.error(`interrupt machine generated artifacts are stale: ${stale.join(", ")}`);
    process.exitCode = 1;
  } else {
    console.log(
      `interrupt machine checked: ${rendered.summary.reachableStates} states / ${rendered.summary.transitions} transitions`,
    );
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.stack : String(error));
    process.exitCode = 1;
  }
}
