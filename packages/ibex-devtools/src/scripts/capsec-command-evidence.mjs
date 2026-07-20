import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { computeDomainDigest } from "./capsec-contract.mjs";
import { commandPolicyFor } from "./capsec-conformance-plan.mjs";

// @ref LLP 0032#command-envelope — every conformance child is supervised by
// one deadline-, identity-, status-, and cleanup-aware envelope.

const DEFAULT_TAIL_BYTES = 64 * 1024;
const COMMAND_DESCRIPTOR_DOMAIN = "ibex/capsec-command-descriptor/1";
const ATTEMPT_RECORD_DOMAIN = "ibex/capsec-command-attempt/1";
const OUTCOME_RECORD_DOMAIN = "ibex/capsec-execution-outcome/1";
const STATUS_RECORD_DOMAIN = "ibex/capsec-live-status/1";
const OUTER_BUDGET_DOMAIN = "ibex/capsec-outer-budget/1";
export const SUPERVISOR_COMMAND_IDENTITY_ENV =
  "IBEX_CAPSEC_SUPERVISOR_COMMAND_IDENTITY_DIGEST";
const DEFAULT_ENVIRONMENT_KEYS = Object.freeze([
  "PATH",
  "PATHEXT",
  "SystemRoot",
]);
const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const windowsJobWrapperPath = path.join(
  repoRoot,
  "scripts/capsec-windows-job-wrapper.ps1",
);

let atomicWriteSequence = 0;

export function commandEvidenceIdSuffix(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

const ownedByCurrentUser = (metadata) =>
  typeof process.getuid !== "function" || metadata.uid === process.getuid();

export const commandEvidenceDirectoryModeIsPrivate = (
  metadata,
  platform = process.platform,
) => platform === "win32" || (metadata.mode & 0o077) === 0;

function assertEvidenceDirectory(evidenceDirectory, platform) {
  const directory = fs.lstatSync(evidenceDirectory);
  if (
    directory.isSymbolicLink() ||
    !directory.isDirectory() ||
    !ownedByCurrentUser(directory) ||
    !commandEvidenceDirectoryModeIsPrivate(directory, platform)
  ) {
    throw new Error(
      "command evidence directory must be an owned real directory",
    );
  }
}

function assertOwnedRegularPath(filePath, opened) {
  const current = fs.lstatSync(filePath);
  if (
    current.isSymbolicLink() ||
    !current.isFile() ||
    current.nlink !== 1 ||
    !ownedByCurrentUser(current) ||
    current.dev !== opened.dev ||
    current.ino !== opened.ino
  ) {
    throw new Error(`${filePath}: command log identity changed during execution`);
  }
}

function openOwnedLog(filePath) {
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_CREAT |
      fs.constants.O_EXCL |
      fs.constants.O_RDWR |
      (fs.constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  const stat = fs.fstatSync(descriptor);
  if (!stat.isFile() || stat.nlink !== 1 || !ownedByCurrentUser(stat)) {
    fs.closeSync(descriptor);
    throw new Error(`${filePath}: command log is not a new regular file`);
  }
  return { descriptor, stat };
}

function digestAndTail(filePath, descriptor, opened, tailBytes) {
  assertOwnedRegularPath(filePath, opened);
  const current = fs.fstatSync(descriptor);
  if (
    !current.isFile() ||
    current.nlink !== 1 ||
    current.dev !== opened.dev ||
    current.ino !== opened.ino
  ) {
    throw new Error(`${filePath}: opened command log identity changed`);
  }
  const size = current.size;
  try {
    const hash = crypto.createHash("sha256");
    const chunk = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    while (offset < size) {
      const read = fs.readSync(
        descriptor,
        chunk,
        0,
        Math.min(chunk.length, size - offset),
        offset,
      );
      if (read === 0) break;
      hash.update(chunk.subarray(0, read));
      offset += read;
    }
    const tailLength = Math.min(size, tailBytes);
    const tail = Buffer.alloc(tailLength);
    if (tailLength > 0) {
      fs.readSync(descriptor, tail, 0, tailLength, size - tailLength);
    }
    return {
      bytes: size,
      digest: `sha256-${hash.digest("base64url")}`,
      tail: tail.toString("utf8"),
      truncated: size > tailLength,
    };
  } finally {
    assertOwnedRegularPath(filePath, opened);
  }
}

function atomicWriteJson(filePath, value) {
  atomicWriteSequence += 1;
  const temporaryPath = `${filePath}.${process.pid}.${atomicWriteSequence}.tmp`;
  const descriptor = fs.openSync(temporaryPath, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporaryPath, filePath);
}

function environmentProjection(environment, keys) {
  return [...new Set([...DEFAULT_ENVIRONMENT_KEYS, ...keys])]
    .sort()
    .map((name) => ({
      name,
      present: Object.hasOwn(environment, name),
      valueDigest: Object.hasOwn(environment, name)
        ? computeDomainDigest("ibex/capsec-command-environment-value/1", {
            name,
            value: String(environment[name]),
          })
        : null,
    }));
}

function declaredOutputRecord(filePath) {
  const metadata = fs.lstatSync(filePath);
  if (
    metadata.isSymbolicLink() ||
    !metadata.isFile() ||
    metadata.nlink !== 1 ||
    !ownedByCurrentUser(metadata)
  ) {
    throw new Error(`${filePath}: declared output is not an owned regular file`);
  }
  const bytes = fs.readFileSync(filePath);
  const current = fs.lstatSync(filePath);
  if (current.dev !== metadata.dev || current.ino !== metadata.ino) {
    throw new Error(`${filePath}: declared output identity changed while reading`);
  }
  return {
    path: filePath,
    bytes: bytes.length,
    digest: `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`,
  };
}

function processExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

function processGroupExists(processGroupId) {
  try {
    process.kill(-processGroupId, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

function listPosixProcesses() {
  const result = spawnSync(
    "ps",
    ["-axo", "pid=,ppid=,pgid=,comm="],
    { encoding: "utf8", timeout: 5000 },
  );
  if (result.status !== 0 || result.error) return [];
  return result.stdout
    .split("\n")
    .map((line) => line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/u))
    .filter(Boolean)
    .map((match) => ({
      pid: Number(match[1]),
      ppid: Number(match[2]),
      pgid: Number(match[3]),
      command: match[4],
    }));
}

function descendantsOf(rootPid, processes) {
  const descendants = new Map();
  let frontier = [rootPid];
  while (frontier.length > 0) {
    const parents = new Set(frontier);
    frontier = [];
    for (const item of processes) {
      if (parents.has(item.ppid) && !descendants.has(item.pid)) {
        descendants.set(item.pid, item);
        frontier.push(item.pid);
      }
    }
  }
  return descendants;
}

const delay = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

async function waitForExit(child) {
  return new Promise((resolve) => {
    child.once("error", (error) => resolve({ error, code: null, signal: null }));
    child.once("close", (code, signal) => resolve({ error: null, code, signal }));
  });
}

function killWindowsTree(pid) {
  const result = spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], {
    encoding: "utf8",
    timeout: 30000,
  });
  return {
    mechanism: "taskkill-tree",
    exitCode: result.status ?? -1,
    signal: result.signal ?? null,
    error: result.error?.message ?? null,
  };
}

async function terminateProcessTree({
  child,
  platform,
  gracePeriodMs,
  escapedDescendants,
}) {
  const actions = [];
  if (platform === "win32") {
    const graceful = child.kill();
    actions.push({
      mechanism: "windows-job-object-wrapper",
      signal: "terminate",
      result: graceful ? "sent" : "not-running",
    });
    await delay(gracePeriodMs);
    if (processExists(child.pid)) actions.push(killWindowsTree(child.pid));
    await delay(100);
    return {
      actions,
      cleanupProven: !processExists(child.pid),
      escapedDescendants: [],
    };
  }
  try {
    process.kill(-child.pid, "SIGTERM");
    actions.push({ mechanism: "process-group", signal: "SIGTERM", result: "sent" });
  } catch (error) {
    actions.push({
      mechanism: "process-group",
      signal: "SIGTERM",
      result: error.code === "ESRCH" ? "already-exited" : `error:${error.code}`,
    });
  }
  await delay(gracePeriodMs);
  if (processGroupExists(child.pid)) {
    try {
      process.kill(-child.pid, "SIGKILL");
      actions.push({ mechanism: "process-group", signal: "SIGKILL", result: "sent" });
    } catch (error) {
      actions.push({
        mechanism: "process-group",
        signal: "SIGKILL",
        result: error.code === "ESRCH" ? "already-exited" : `error:${error.code}`,
      });
    }
  }
  for (const pid of escapedDescendants.keys()) {
    try {
      process.kill(pid, "SIGKILL");
      actions.push({ mechanism: "escaped-descendant", pid, signal: "SIGKILL", result: "sent" });
    } catch (error) {
      actions.push({
        mechanism: "escaped-descendant",
        pid,
        signal: "SIGKILL",
        result: error.code === "ESRCH" ? "already-exited" : `error:${error.code}`,
      });
    }
  }
  await delay(100);
  return {
    actions,
    cleanupProven:
      !processGroupExists(child.pid) &&
      [...escapedDescendants.keys()].every((pid) => !processExists(pid)),
    escapedDescendants: [...escapedDescendants.values()],
  };
}

export class CapsecCommandSupervisor {
  constructor({
    evidenceDirectory,
    suitePlanBinding,
    executionShard,
    jobStartedAtMs,
    platform = process.platform,
    tailBytes = DEFAULT_TAIL_BYTES,
    heartbeatIntervalMs,
    outcomePath,
    liveStatusPath,
    contaminationMarkerPath,
    outerBudgetPath,
    abortSignal,
  }) {
    assertEvidenceDirectory(evidenceDirectory, platform);
    this.evidenceDirectory = evidenceDirectory;
    this.suitePlanBinding = suitePlanBinding;
    this.plan = suitePlanBinding.plan;
    this.target = suitePlanBinding.target;
    if (!/^[a-z0-9][a-z0-9-]*$/u.test(executionShard)) {
      throw new Error("command supervisor requires an execution shard identifier");
    }
    this.executionShard = executionShard;
    this.platform = platform;
    this.tailBytes = tailBytes;
    this.heartbeatIntervalMs =
      heartbeatIntervalMs ?? this.plan.heartbeatIntervalMs;
    if (!Number.isFinite(jobStartedAtMs)) {
      throw new Error("command supervisor requires a finite jobStartedAtMs");
    }
    this.jobStartedAtMs = jobStartedAtMs;
    this.abortSignal = abortSignal;
    this.outcomePath =
      outcomePath ?? path.join(evidenceDirectory, "execution-outcome.json");
    this.liveStatusPath =
      liveStatusPath ?? path.join(evidenceDirectory, "live-status.json");
    this.contaminationMarkerPath =
      contaminationMarkerPath ?? path.join(evidenceDirectory, "contaminated.json");
    this.outerBudgetPath =
      outerBudgetPath ?? path.join(evidenceDirectory, "outer-budget.json");
    this.attempts = [];
    this.nextAttempt = 1;
    this.startedAt = new Date().toISOString();
    this.finishedAt = null;
    this.status = "running";
    const targetBudget = this.plan.targets[this.target];
    const outerBudget = {
      schema: "ibex/capsec-outer-budget/1",
      suitePlanDigest: this.suitePlanBinding.suitePlanDigest,
      target: this.target,
      executionShard: this.executionShard,
      jobStartedAt: new Date(this.jobStartedAtMs).toISOString(),
      outerTimeoutMs: targetBudget.outerTimeoutMs,
      outerDeadline: new Date(
        this.jobStartedAtMs + targetBudget.outerTimeoutMs,
      ).toISOString(),
      cleanupUploadReserveMs: targetBudget.cleanupUploadReserveMs,
    };
    atomicWriteJson(this.outerBudgetPath, {
      ...outerBudget,
      outerBudgetDigest: computeDomainDigest(OUTER_BUDGET_DOMAIN, outerBudget),
    });
    this.writeOutcome();
  }

  writeOutcome() {
    const outcome = {
      schema: "ibex/capsec-execution-outcome/1",
      suitePlanDigest: this.suitePlanBinding.suitePlanDigest,
      target: this.target,
      executionShard: this.executionShard,
      startedAt: this.startedAt,
      finishedAt: this.finishedAt,
      status: this.status,
      contaminationMarkerPresent: fs.existsSync(this.contaminationMarkerPath),
      attempts: this.attempts,
    };
    atomicWriteJson(this.outcomePath, {
      ...outcome,
      outcomeDigest: computeDomainDigest(OUTCOME_RECORD_DOMAIN, outcome),
    });
  }

  finish(status = "success") {
    if (!new Set(["success", "failed"]).has(status)) {
      throw new Error(`invalid command supervisor status ${status}`);
    }
    if (this.status !== "failed") this.status = status;
    this.finishedAt = new Date().toISOString();
    this.writeOutcome();
  }

  markContaminated(reason, attemptId) {
    const marker = {
      schema: "ibex/capsec-runner-contamination/1",
      suitePlanDigest: this.suitePlanBinding.suitePlanDigest,
      attemptId,
      reason,
      recordedAt: new Date().toISOString(),
    };
    if (!fs.existsSync(this.contaminationMarkerPath)) {
      atomicWriteJson(this.contaminationMarkerPath, marker);
    }
  }

  recordAttempt(attempt) {
    const record = {
      ...attempt,
      attemptDigest: computeDomainDigest(ATTEMPT_RECORD_DOMAIN, attempt),
    };
    this.attempts.push(record);
    if (record.classification !== "success") {
      this.status = "failed";
      this.finishedAt = record.finishedAt;
    }
    this.writeOutcome();
    return record;
  }

  async run({
    id,
    command,
    args = [],
    cwd,
    env = process.env,
    environmentKeys = [],
    declaredInputs = [],
    expectedOutputs = [],
    redactedArgs = args,
    abortSignal = this.abortSignal,
    injectCommandIdentity = false,
  }) {
    if (!/^[a-z0-9][a-z0-9-]*$/u.test(id)) {
      throw new Error(`invalid command evidence id ${JSON.stringify(id)}`);
    }
    if (fs.existsSync(this.contaminationMarkerPath)) {
      throw new Error("authoritative command refused: runner is contaminated");
    }
    if (this.status !== "running") {
      throw new Error("command supervisor no longer accepts attempts");
    }
    if (typeof injectCommandIdentity !== "boolean") {
      throw new Error("injectCommandIdentity must be a boolean");
    }
    if (
      Object.hasOwn(env, SUPERVISOR_COMMAND_IDENTITY_ENV) ||
      environmentKeys.includes(SUPERVISOR_COMMAND_IDENTITY_ENV)
    ) {
      throw new Error(
        `${SUPERVISOR_COMMAND_IDENTITY_ENV} is reserved for supervisor injection`,
      );
    }
    const policy = commandPolicyFor(this.plan, this.target, id);
    const attemptId = `attempt-${String(this.nextAttempt).padStart(6, "0")}`;
    this.nextAttempt += 1;
    const descriptor = {
      schema: "ibex/capsec-command-descriptor/1",
      suitePlanDigest: this.suitePlanBinding.suitePlanDigest,
      commandId: id,
      phase: policy.phase,
      executionShard: this.executionShard,
      executable: command,
      arguments: args,
      workingDirectory: cwd,
      environment: environmentProjection(env, environmentKeys),
      declaredInputs,
      deadlineMs: policy.deadlineMs,
      gracePeriodMs: policy.gracePeriodMs,
      expectedOutputs,
    };
    const commandIdentity = computeDomainDigest(
      COMMAND_DESCRIPTOR_DOMAIN,
      descriptor,
    );
    // The child needs the already-fixed pre-command identity in order to emit
    // acyclic mapped-engine evidence. It cannot supply or project this value:
    // doing so would either let the child self-assert authority or make the
    // descriptor digest recursively depend on itself.
    // @ref LLP 0035#reports-and-advertisements — mapped evidence names the
    // pre-command descriptor; the finalized attempt names the evidence output.
    const spawnedEnvironment = injectCommandIdentity
      ? { ...env, [SUPERVISOR_COMMAND_IDENTITY_ENV]: commandIdentity }
      : env;
    const displayedInvocation = [command, ...redactedArgs];
    const now = Date.now();
    const budget = this.plan.targets[this.target];
    const outerDeadlineMs = this.jobStartedAtMs + budget.outerTimeoutMs;
    if (
      now + policy.deadlineMs + policy.gracePeriodMs +
        budget.cleanupUploadReserveMs >
      outerDeadlineMs
    ) {
      const record = this.recordAttempt({
        schema: "ibex/capsec-command-attempt/1",
        attemptId,
        commandId: id,
        commandIdentity,
        phase: policy.phase,
        displayedInvocation,
        startedAt: null,
        finishedAt: new Date().toISOString(),
        elapsedMs: 0,
        deadlineMs: policy.deadlineMs,
        gracePeriodMs: policy.gracePeriodMs,
        classification: "refused-launch",
        exitCode: null,
        signal: null,
        cleanup: { actions: [], cleanupProven: true, escapedDescendants: [] },
        stdout: null,
        stderr: null,
        outputs: [],
      });
      const error = new Error(`${id} refused: insufficient outer job budget`);
      error.commandEvidence = record;
      throw error;
    }
    if (abortSignal?.aborted) {
      const record = this.recordAttempt({
        schema: "ibex/capsec-command-attempt/1",
        attemptId,
        commandId: id,
        commandIdentity,
        phase: policy.phase,
        displayedInvocation,
        startedAt: null,
        finishedAt: new Date().toISOString(),
        elapsedMs: 0,
        deadlineMs: policy.deadlineMs,
        gracePeriodMs: policy.gracePeriodMs,
        classification: "cancellation",
        exitCode: null,
        signal: null,
        cleanup: { actions: [], cleanupProven: true, escapedDescendants: [] },
        stdout: null,
        stderr: null,
        outputs: [],
      });
      const error = new Error(`${id} canceled before launch`);
      error.commandEvidence = record;
      throw error;
    }

    const stdoutPath = path.join(this.evidenceDirectory, `${id}.stdout.log`);
    const stderrPath = path.join(this.evidenceDirectory, `${id}.stderr.log`);
    const stdout = openOwnedLog(stdoutPath);
    let stderr;
    let child;
    const escapedDescendants = new Map();
    const startMonotonic = performance.now();
    const startedAt = new Date().toISOString();
    let timedOut = false;
    let canceled = false;
    let timeoutHandle;
    let heartbeatHandle;
    let processInspectionHandle;
    let stopExecution;
    let statusWriteError = null;
    const stopPromise = new Promise((resolve) => {
      stopExecution = resolve;
    });
    const updateStatus = () => {
      const status = {
        schema: "ibex/capsec-live-status/1",
        suitePlanDigest: this.suitePlanBinding.suitePlanDigest,
        target: this.target,
        executionShard: this.executionShard,
        attemptId,
        commandId: id,
        commandIdentity,
        phase: policy.phase,
        startedAt,
        observedAt: new Date().toISOString(),
        elapsedMs: Math.round(performance.now() - startMonotonic),
        deadlineMs: policy.deadlineMs,
        state: "running",
        terminalClassification: null,
      };
      try {
        atomicWriteJson(this.liveStatusPath, {
          ...status,
          statusDigest: computeDomainDigest(STATUS_RECORD_DOMAIN, status),
        });
        process.stdout.write(
          `[capsec-status] ${id} ${status.elapsedMs}ms/${policy.deadlineMs}ms\n`,
        );
      } catch (error) {
        statusWriteError ??= error;
        stopExecution("status-failure");
      }
    };

    try {
      stderr = openOwnedLog(stderrPath);
      const spawnedCommand = this.platform === "win32" ? "pwsh" : command;
      const spawnedArgs =
        this.platform === "win32"
          ? [
              "-NoLogo",
              "-NoProfile",
              "-NonInteractive",
              "-ExecutionPolicy",
              "Bypass",
              "-File",
              windowsJobWrapperPath,
              "-CommandBase64",
              Buffer.from(command, "utf8").toString("base64"),
              "-ArgumentsBase64",
              Buffer.from(JSON.stringify(args), "utf8").toString("base64"),
              "-WorkingDirectoryBase64",
              Buffer.from(cwd, "utf8").toString("base64"),
            ]
          : args;
      child = spawn(spawnedCommand, spawnedArgs, {
        cwd,
        env: spawnedEnvironment,
        detached: this.platform !== "win32",
        stdio: ["ignore", stdout.descriptor, stderr.descriptor],
        windowsHide: true,
      });
      updateStatus();
      heartbeatHandle = setInterval(updateStatus, this.heartbeatIntervalMs);
      const inspectDescendants = () => {
        const descendants = descendantsOf(child.pid, listPosixProcesses());
        for (const [pid, item] of descendants) {
          if (item.pgid !== child.pid) {
            escapedDescendants.set(pid, item);
          }
        }
      };
      if (this.platform !== "win32") {
        processInspectionHandle = setInterval(
          inspectDescendants,
          Math.min(this.heartbeatIntervalMs, 1000),
        );
      }
      timeoutHandle = setTimeout(() => stopExecution("timeout"), policy.deadlineMs);
      const abort = () => stopExecution("cancellation");
      abortSignal?.addEventListener("abort", abort, { once: true });
      if (abortSignal?.aborted) abort();
      const exitPromise = waitForExit(child);
      const first = await Promise.race([
        exitPromise.then((result) => ({ kind: "exit", result })),
        stopPromise.then((kind) => ({ kind, result: null })),
      ]);
      if (this.platform !== "win32") inspectDescendants();
      abortSignal?.removeEventListener("abort", abort);
      clearTimeout(timeoutHandle);
      clearInterval(heartbeatHandle);
      clearInterval(processInspectionHandle);
      timedOut = first.kind === "timeout";
      canceled = first.kind === "cancellation";
      const statusFailed = first.kind === "status-failure";
      let cleanup = { actions: [], cleanupProven: true, escapedDescendants: [] };
      if (timedOut || canceled || statusFailed) {
        cleanup = await terminateProcessTree({
          child,
          platform: this.platform,
          gracePeriodMs: policy.gracePeriodMs,
          escapedDescendants,
        });
      }
      const result =
        first.kind === "exit"
          ? first.result
          : await Promise.race([
              exitPromise,
              delay(5000).then(() => ({
                error: new Error("process did not report exit after cleanup"),
                code: null,
                signal: null,
              })),
            ]);
      fs.fsyncSync(stdout.descriptor);
      fs.fsyncSync(stderr.descriptor);

      const lingeringTree =
        this.platform === "win32"
          ? processExists(child.pid)
          : processGroupExists(child.pid) || escapedDescendants.size > 0;
      const unexpectedLingeringTree =
        !timedOut && !canceled && !statusFailed && lingeringTree;
      if (!timedOut && !canceled && lingeringTree) {
        cleanup = await terminateProcessTree({
          child,
          platform: this.platform,
          gracePeriodMs: policy.gracePeriodMs,
          escapedDescendants,
        });
      }
      let classification = "success";
      if (timedOut) classification = "timeout";
      else if (canceled) classification = "cancellation";
      else if (statusFailed) classification = "failure";
      else if (
        unexpectedLingeringTree ||
        escapedDescendants.size > 0 ||
        !cleanup.cleanupProven
      ) {
        classification = "cleanup-failure";
      } else if (result.error || result.code !== 0) classification = "failure";
      if (escapedDescendants.size > 0 || !cleanup.cleanupProven) {
        this.markContaminated(
          escapedDescendants.size > 0
            ? "descendant escaped the command process group or session"
            : "process-tree cleanup could not be proven",
          attemptId,
        );
      }
      let outputs = [];
      let outputValidationError = null;
      if (classification === "success") {
        try {
          outputs = expectedOutputs.map(declaredOutputRecord);
        } catch (error) {
          outputValidationError = error;
          classification = "failure";
        }
      }
      const attempt = this.recordAttempt({
        schema: "ibex/capsec-command-attempt/1",
        attemptId,
        commandId: id,
        commandIdentity,
        phase: policy.phase,
        displayedInvocation,
        startedAt,
        finishedAt: new Date().toISOString(),
        elapsedMs: Math.round(performance.now() - startMonotonic),
        deadlineMs: policy.deadlineMs,
        gracePeriodMs: policy.gracePeriodMs,
        classification,
        exitCode: result.code ?? -1,
        signal: result.signal ?? null,
        cleanup,
        stdout: digestAndTail(
          stdoutPath,
          stdout.descriptor,
          stdout.stat,
          this.tailBytes,
        ),
        stderr: digestAndTail(
          stderrPath,
          stderr.descriptor,
          stderr.stat,
          this.tailBytes,
        ),
        outputs,
      });
      const terminalStatus = {
        schema: "ibex/capsec-live-status/1",
        suitePlanDigest: this.suitePlanBinding.suitePlanDigest,
        target: this.target,
        executionShard: this.executionShard,
        attemptId,
        commandId: id,
        commandIdentity,
        phase: policy.phase,
        startedAt,
        observedAt: attempt.finishedAt,
        elapsedMs: attempt.elapsedMs,
        deadlineMs: policy.deadlineMs,
        state: "finished",
        terminalClassification: classification,
      };
      atomicWriteJson(this.liveStatusPath, {
        ...terminalStatus,
        statusDigest: computeDomainDigest(STATUS_RECORD_DOMAIN, terminalStatus),
      });
      if (classification !== "success") {
        const detail =
          statusWriteError?.message ??
          outputValidationError?.message ??
          result.error?.message ??
          attempt.stderr.tail ??
          attempt.stdout.tail;
        const error = new Error(
          `${id} ${classification} (${attempt.exitCode}): ${detail}`,
        );
        error.commandEvidence = attempt;
        throw error;
      }
      return attempt;
    } finally {
      clearTimeout(timeoutHandle);
      clearInterval(heartbeatHandle);
      clearInterval(processInspectionHandle);
      fs.closeSync(stdout.descriptor);
      if (stderr) fs.closeSync(stderr.descriptor);
    }
  }
}

export function createCapsecCommandSupervisor(options) {
  return new CapsecCommandSupervisor(options);
}

export function runObservedCommand({ supervisor, ...options }) {
  if (!(supervisor instanceof CapsecCommandSupervisor)) {
    throw new Error("runObservedCommand requires a CapsecCommandSupervisor");
  }
  return supervisor.run(options);
}

export function legacyCommandEvidence(attempt) {
  return {
    id: attempt.commandId,
    command: attempt.displayedInvocation,
    exitCode: attempt.exitCode,
    signal: attempt.signal,
    stdout: attempt.stdout,
    stderr: attempt.stderr,
  };
}
