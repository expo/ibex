import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, test } from "bun:test";
import {
  commandEvidenceDirectoryModeIsPrivate,
  commandEvidenceIdSuffix,
  createCapsecCommandSupervisor,
  runObservedCommand,
  SUPERVISOR_COMMAND_IDENTITY_ENV,
} from "./capsec-command-evidence.mjs";
import {
  bindConformanceSuitePlan,
  readConformanceSuitePlan,
} from "./capsec-conformance-plan.mjs";

const roots = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function fixture({
  commandId = "capsec-registry-drift",
  deadlineMs = process.platform === "win32" ? 20_000 : 5000,
  gracePeriodMs = 100,
  jobStartedAtMs = Date.now(),
} = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-capsec-command-"));
  roots.push(root);
  const evidenceDirectory = path.join(root, "evidence");
  fs.mkdirSync(evidenceDirectory, { mode: 0o700 });
  const plan = structuredClone(readConformanceSuitePlan());
  plan.commands[commandId] = {
    phase: "test-phase",
    deadlineMs,
    gracePeriodMs,
  };
  const suitePlanBinding = bindConformanceSuitePlan({
    plan,
    sourceRevision: "test-revision",
    sourceTreeDigest: "sha256-test-tree",
    target: "aarch64-apple-darwin",
    engineArtifactDigest: "sha256-test-engine",
  });
  const supervisor = createCapsecCommandSupervisor({
    evidenceDirectory,
    suitePlanBinding,
    executionShard: "test-sequential",
    jobStartedAtMs,
    heartbeatIntervalMs: process.platform === "win32" ? 100 : 25,
  });
  return { root, evidenceDirectory, supervisor };
}

function pidExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

test("command evidence ID suffixes are canonical and collision-resistant", () => {
  const first = commandEvidenceIdSuffix(Buffer.from("cargo test --bin ibex"));
  expect(first).toMatch(/^[a-f0-9]{64}$/u);
  expect(commandEvidenceIdSuffix(Buffer.from("cargo test --bin ibex"))).toBe(
    first,
  );
  expect(commandEvidenceIdSuffix(Buffer.from("cargo test --lib"))).not.toBe(
    first,
  );
});

test("command evidence enforces real POSIX modes without trusting Windows synthetic bits", () => {
  expect(commandEvidenceDirectoryModeIsPrivate({ mode: 0o700 }, "linux")).toBe(
    true,
  );
  expect(commandEvidenceDirectoryModeIsPrivate({ mode: 0o755 }, "darwin")).toBe(
    false,
  );
  expect(commandEvidenceDirectoryModeIsPrivate({ mode: 0o777 }, "win32")).toBe(
    true,
  );
});

test(
  "command evidence streams large output, binds identity, and retains duration",
  async () => {
    const { root, evidenceDirectory, supervisor } = fixture({
      deadlineMs: process.platform === "win32" ? 60_000 : 5000,
    });
    const declaredInputs = [
      {
        name: "conformanceRunner",
        digest: `sha256-${"A".repeat(43)}`,
      },
    ];
    const evidencePromise = runObservedCommand({
      supervisor,
      id: "capsec-registry-drift",
      command: process.execPath,
      args: [
        "-e",
        "process.stdout.write('x'.repeat(3 * 1024 * 1024) + 'MARKER\\n')",
      ],
      cwd: root,
      declaredInputs,
    });
    declaredInputs[0].digest = `sha256-${"B".repeat(43)}`;
    const evidence = await evidencePromise;
    supervisor.finish();
    expect(evidence.classification).toBe("success");
    expect(evidence.commandIdentity).toMatch(/^sha256-[A-Za-z0-9_-]{43}$/u);
    expect(evidence.elapsedMs).toBeGreaterThanOrEqual(0);
    expect(evidence.stdout.bytes).toBeGreaterThan(3 * 1024 * 1024);
    expect(evidence.stdout.truncated).toBe(true);
    expect(evidence.stdout.tail).toEndWith("MARKER\n");
    expect(evidence.declaredInputs).toEqual([
      {
        name: "conformanceRunner",
        digest: `sha256-${"A".repeat(43)}`,
      },
    ]);
    const outcome = JSON.parse(
      fs.readFileSync(path.join(evidenceDirectory, "execution-outcome.json")),
    );
    expect(outcome.status).toBe("success");
    expect(outcome.attempts).toHaveLength(1);
  },
  process.platform === "win32" ? 90_000 : 30_000,
);

test("the supervisor injects the fixed pre-command identity out of band", async () => {
  const { root, supervisor } = fixture();
  const outputPath = path.join(root, "observed-command-identity.txt");
  const attempt = await runObservedCommand({
    supervisor,
    id: "capsec-registry-drift",
    command: process.execPath,
    args: [
      "-e",
      `require('fs').writeFileSync(${JSON.stringify(outputPath)}, process.env[${JSON.stringify(SUPERVISOR_COMMAND_IDENTITY_ENV)}])`,
    ],
    cwd: root,
    expectedOutputs: [outputPath],
    injectCommandIdentity: true,
  });
  expect(fs.readFileSync(outputPath, "utf8")).toBe(attempt.commandIdentity);
  expect(
    attempt.outputs.find((output) => output.path === outputPath),
  ).toBeDefined();
});

test("a child cannot supply or project the reserved command identity", async () => {
  for (const ownership of ["environment", "projection"]) {
    const { root, supervisor } = fixture();
    const environment = { ...process.env };
    const environmentKeys = [];
    if (ownership === "environment") {
      environment[SUPERVISOR_COMMAND_IDENTITY_ENV] = "sha256-spoofed";
    } else {
      environmentKeys.push(SUPERVISOR_COMMAND_IDENTITY_ENV);
    }
    await expect(
      runObservedCommand({
        supervisor,
        id: "capsec-registry-drift",
        command: process.execPath,
        cwd: root,
        env: environment,
        environmentKeys,
        injectCommandIdentity: true,
      }),
    ).rejects.toThrow(/reserved for supervisor injection/u);
  }
});

test("command evidence preserves a nonzero child exit code", async () => {
  const { root, supervisor } = fixture();
  let error;
  try {
    await runObservedCommand({
      supervisor,
      id: "capsec-registry-drift",
      command: process.execPath,
      args: ["-e", "process.exit(23)"],
      cwd: root,
    });
  } catch (caught) {
    error = caught;
  }
  expect(error?.commandEvidence?.classification).toBe("failure");
  expect(error?.commandEvidence?.exitCode).toBe(23);
});

test("command failures report both stderr and stdout diagnostic tails", async () => {
  const { root, supervisor } = fixture();
  let error;
  try {
    await runObservedCommand({
      supervisor,
      id: "capsec-registry-drift",
      command: process.execPath,
      args: [
        "-e",
        "process.stdout.write('stdout-diagnostic\\n'); process.stderr.write('stderr-summary\\n'); process.exit(23)",
      ],
      cwd: root,
    });
  } catch (caught) {
    error = caught;
  }
  expect(error?.message).toContain("stderr:\nstderr-summary");
  expect(error?.message).toContain("stdout:\nstdout-diagnostic");
});

test("command evidence refuses reused logs and symlink directories", async () => {
  const { root, evidenceDirectory, supervisor } = fixture();
  const victim = path.join(root, "victim");
  fs.writeFileSync(victim, "unchanged");
  fs.symlinkSync(
    victim,
    path.join(evidenceDirectory, "capsec-registry-drift.stdout.log"),
  );
  await expect(
    runObservedCommand({
      supervisor,
      id: "capsec-registry-drift",
      command: process.execPath,
      args: ["-e", "console.log('must not run')"],
      cwd: root,
    }),
  ).rejects.toThrow();
  expect(fs.readFileSync(victim, "utf8")).toBe("unchanged");

  const linkedDirectory = path.join(root, "linked-evidence");
  fs.symlinkSync(evidenceDirectory, linkedDirectory);
  expect(() =>
    createCapsecCommandSupervisor({
      evidenceDirectory: linkedDirectory,
      suitePlanBinding: supervisor.suitePlanBinding,
      executionShard: "test-sequential",
      jobStartedAtMs: Date.now(),
    }),
  ).toThrow(/owned real directory/u);
});

test("a deadline kills a hanging parent and grandchild and records timeout", async () => {
  const { root, evidenceDirectory, supervisor } = fixture({
    commandId: "hang-tree",
    deadlineMs: process.platform === "win32" ? 3000 : 300,
    gracePeriodMs: process.platform === "win32" ? 1000 : 100,
  });
  const childPidPath = path.join(root, "child.pid");
  let error;
  try {
    await runObservedCommand({
      supervisor,
      id: "hang-tree",
      command: process.execPath,
      args: [
        "-e",
        `const fs=require('fs');const {spawn}=require('child_process');const c=spawn(process.execPath,['-e','setInterval(()=>{},1000)']);fs.writeFileSync(${JSON.stringify(childPidPath)},String(c.pid));setInterval(()=>{},1000);`,
      ],
      cwd: root,
    });
  } catch (caught) {
    error = caught;
  }
  expect(error?.commandEvidence?.classification).toBe("timeout");
  const childPid = Number(fs.readFileSync(childPidPath, "utf8"));
  expect(pidExists(childPid)).toBe(false);
  const outcome = JSON.parse(
    fs.readFileSync(path.join(evidenceDirectory, "execution-outcome.json")),
  );
  expect(outcome.attempts[0].classification).toBe("timeout");
}, 15_000);

test.skipIf(process.platform === "win32")(
  "a zero-exit command cannot leave a same-group background child",
  async () => {
    const { root, evidenceDirectory, supervisor } = fixture({
      commandId: "leak-tree",
      deadlineMs: 5000,
      gracePeriodMs: 100,
    });
    const childPidPath = path.join(root, "leaked.pid");
    let error;
    try {
      await runObservedCommand({
        supervisor,
        id: "leak-tree",
        command: process.execPath,
        args: [
          "-e",
          `const fs=require('fs');const {spawn}=require('child_process');const c=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});c.unref();fs.writeFileSync(${JSON.stringify(childPidPath)},String(c.pid));`,
        ],
        cwd: root,
      });
    } catch (caught) {
      error = caught;
    }
    expect(error?.commandEvidence?.classification).toBe("cleanup-failure");
    const childPid = Number(fs.readFileSync(childPidPath, "utf8"));
    expect(pidExists(childPid)).toBe(false);
    expect(
      fs.existsSync(path.join(evidenceDirectory, "contaminated.json")),
    ).toBe(false);
  },
);

test.skipIf(process.platform === "win32")(
  "a session-escaping descendant contaminates the runner and blocks later work",
  async () => {
    const { root, evidenceDirectory, supervisor } = fixture({
      commandId: "escape-tree",
      deadlineMs: 400,
      gracePeriodMs: 100,
    });
    const childPidPath = path.join(root, "escaped.pid");
    await expect(
      runObservedCommand({
        supervisor,
        id: "escape-tree",
        command: process.execPath,
        args: [
          "-e",
          `const fs=require('fs');const {spawn}=require('child_process');const c=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});fs.writeFileSync(${JSON.stringify(childPidPath)},String(c.pid));setInterval(()=>{},1000);`,
        ],
        cwd: root,
      }),
    ).rejects.toThrow();
    expect(
      fs.existsSync(path.join(evidenceDirectory, "contaminated.json")),
    ).toBe(true);
    const escapedPid = Number(fs.readFileSync(childPidPath, "utf8"));
    expect(pidExists(escapedPid)).toBe(false);
    await expect(
      runObservedCommand({
        supervisor,
        id: "escape-tree",
        command: process.execPath,
        cwd: root,
      }),
    ).rejects.toThrow(/runner is contaminated/u);
  },
);

test("launch admission refuses a command that cannot fit the remaining job budget", async () => {
  const { root, supervisor } = fixture({
    jobStartedAtMs: Date.now() - 21_600_000,
  });
  let error;
  try {
    await runObservedCommand({
      supervisor,
      id: "capsec-registry-drift",
      command: process.execPath,
      cwd: root,
    });
  } catch (caught) {
    error = caught;
  }
  expect(error?.commandEvidence?.classification).toBe("refused-launch");
});

test("cancellation terminates the command tree and remains distinct from timeout", async () => {
  const { root, supervisor } = fixture({
    commandId: "cancel-tree",
    deadlineMs: 5000,
    gracePeriodMs: 100,
  });
  const controller = new AbortController();
  setTimeout(() => controller.abort("test cancellation"), 100);
  let error;
  try {
    await runObservedCommand({
      supervisor,
      id: "cancel-tree",
      command: process.execPath,
      args: ["-e", "setInterval(()=>{},1000)"],
      cwd: root,
      abortSignal: controller.signal,
    });
  } catch (caught) {
    error = caught;
  }
  expect(error?.commandEvidence?.classification).toBe("cancellation");
});

test("an already-canceled command is recorded without launching", async () => {
  const { root, evidenceDirectory, supervisor } = fixture();
  const markerPath = path.join(root, "must-not-exist");
  const controller = new AbortController();
  controller.abort("test cancellation before launch");
  let error;
  try {
    await runObservedCommand({
      supervisor,
      id: "capsec-registry-drift",
      command: process.execPath,
      args: [
        "-e",
        `require('fs').writeFileSync(${JSON.stringify(markerPath)}, 'bad')`,
      ],
      cwd: root,
      abortSignal: controller.signal,
    });
  } catch (caught) {
    error = caught;
  }
  expect(error?.commandEvidence?.classification).toBe("cancellation");
  expect(error?.commandEvidence?.startedAt).toBeNull();
  expect(fs.existsSync(markerPath)).toBe(false);
  const outcome = JSON.parse(
    fs.readFileSync(path.join(evidenceDirectory, "execution-outcome.json")),
  );
  expect(outcome.status).toBe("failed");
  expect(outcome.finishedAt).not.toBeNull();
});

test("missing declared outputs fail the command after a zero exit", async () => {
  const { root, supervisor } = fixture();
  let error;
  try {
    await runObservedCommand({
      supervisor,
      id: "capsec-registry-drift",
      command: process.execPath,
      args: ["-e", "process.exit(0)"],
      cwd: root,
      expectedOutputs: [path.join(root, "missing.json")],
    });
  } catch (caught) {
    error = caught;
  }
  expect(error?.commandEvidence?.classification).toBe("failure");
  expect(error?.message).toMatch(/missing\.json/u);
});
