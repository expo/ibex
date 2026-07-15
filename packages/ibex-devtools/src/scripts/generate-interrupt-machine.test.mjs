// @ref LLP 0025#6-interruption-and-cancellation — generated transition data
// must prove credit, promise, cause, identity, and target-selection invariants.
// @ref LLP 0025#acceptance-criteria — schedules (a)-(n) are executable
// trajectories, not frozen expected tuples.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  applyEvent,
  checkInterruptArtifacts,
  generatedInterruptPaths,
  loadInterruptMachine,
  machineSourcePath,
  modelCheck,
  renderInterruptArtifacts,
  simulateNamedSchedules,
} from "./generate-interrupt-machine.mjs";

let machine;
let source;
let rendered;
let temporaryDirectory;

beforeAll(() => {
  ({ machine, source } = loadInterruptMachine(machineSourcePath, {
    validateModel: false,
  }));
  rendered = renderInterruptArtifacts(machine, { source });
  temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "ibex-interrupt-machine-"),
  );
});

afterAll(() => {
  if (temporaryDirectory) {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

function step(state, event) {
  const transition = applyEvent(machine, state, event);
  expect(transition).not.toBeNull();
  return transition;
}

describe("LLP 0025 generated interrupt machine", () => {
  test("binds the exact temporal properties and every named schedule", () => {
    expect(rendered.summary.properties).toEqual([
      "interrupts_without_editor_input <= 3",
      "(promised && no editor input since) => next interrupt terminal",
    ]);
    expect(rendered.summary.statusRule).toBe(
      "promised status retained unless a cause already latched",
    );
    expect(new Set(rendered.schedules.map((row) => row.llpSchedule))).toEqual(
      new Set("abcdefghijklmn"),
    );
    expect(rendered.summary.branchHits["credit-three"]).toBe(0);
    expect(rendered.summary.reachableStates).toBeGreaterThan(10_000);
    expect(rendered.summary.adversarialProductStates).toBeGreaterThan(
      rendered.summary.reachableStates,
    );
    for (const hits of Object.values(rendered.summary.rowHits)) {
      expect(hits).toBeGreaterThan(0);
    }
  });

  test("executes queued and executing completion trajectories differently", () => {
    const schedules = new Map(
      simulateNamedSchedules(machine).map((row) => [row.id, row]),
    );
    const queued = schedules.get("k-completion-queued").trace.at(-1);
    const executing = schedules.get("k-completion-executing").trace.at(-1);
    expect(queued.result.row).toBe("editor-completion-queued");
    expect(queued.result.cancelTarget).toBeNull();
    expect(queued.result.notice).toBe("work-in-flight");
    expect(executing.result.row).toBe("editor-completion-executing");
    expect(executing.result.cancelTarget).toBe("completion-1");
    expect(executing.result.notice).toBe("cancelling-completion");
  });

  test("keeps due scheduling identities distinct", () => {
    const trajectory = rendered.schedules.find(
      (row) => row.id === "n-distinct-due-identities",
    );
    const afterBothDue = trajectory.trace[2].state;
    const afterOneBegins = trajectory.trace[3].state;
    expect(afterBothDue.due).toEqual(["timer-1", "timer-2"]);
    expect(afterOneBegins.due).toEqual(["timer-2"]);
    expect(afterOneBegins.executing.target).toBe("callback-1");
  });

  test("never retargets a stale cancellation id to a successor", () => {
    let state = structuredClone(machine.initialState);
    ({ state } = step(state, { event: "due", sched: "timer-1" }));
    ({ state } = step(state, {
      event: "unit-begin",
      target: "callback-1",
      role: "callback",
      sched: "timer-1",
    }));
    ({ state } = step(state, { event: "interrupt" }));
    expect(state.pendingCancellations).toEqual(["callback-1"]);
    ({ state } = step(state, { event: "unit-end", target: "callback-1" }));
    ({ state } = step(state, {
      event: "editor-input-at-prompt",
      nextPhase: "idle",
    }));
    ({ state } = step(state, { event: "due", sched: "timer-2" }));
    ({ state } = step(state, {
      event: "unit-begin",
      target: "callback-2",
      role: "callback",
      sched: "timer-2",
    }));
    expect(state.executing.target).toBe("callback-2");
    expect(state.pendingCancellations).toEqual(["callback-1"]);
  });

  test("editor input clears a promise while typed-ahead and drain preserve it", () => {
    let state = structuredClone(machine.initialState);
    ({ state } = step(state, { event: "interrupt" }));
    expect(state.promise).toBe("orderly");
    expect(state.escapeCredit).toBe(1);
    ({ state } = step(state, {
      event: "editor-input-at-prompt",
      nextPhase: "editing",
    }));
    expect(state.promise).toBe("none");
    expect(state.escapeCredit).toBe(0);

    ({ state } = step(state, { event: "submit" }));
    ({ state } = step(state, { event: "dispatch" }));
    ({ state } = step(state, {
      event: "unit-begin",
      target: "evaluation-1",
      role: "evaluation",
    }));
    ({ state } = step(state, { event: "interrupt" }));
    ({ state } = step(state, { event: "typed-ahead-byte" }));
    ({ state } = step(state, { event: "unit-end", target: "evaluation-1" }));
    ({ state } = step(state, { event: "drain-typed-ahead" }));
    expect(state.promise).toBe("interrupt-130");
    expect(state.escapeCredit).toBe(1);
  });

  test("rejects an ambiguous owner-authored row", () => {
    const invalid = structuredClone(machine);
    const duplicate = structuredClone(
      invalid.interruptRows.find((row) => row.id === "idle-prompt"),
    );
    duplicate.id = "idle-prompt-duplicate";
    invalid.interruptRows.push(duplicate);
    expect(() => modelCheck(invalid)).toThrow(/ambiguous/);
  });

  test("rejects an unreachable owner-authored row", () => {
    const invalid = structuredClone(machine);
    invalid.interruptRows.push({
      id: "shutdown-impossible-executing",
      label: "impossible shutdown row",
      when: { phase: "shutdown", hasExecuting: true },
      decision: {
        notice: "none",
        promise: "none",
        abandonCompletion: false,
        raiseCancellation: "none",
        buffer: "unchanged",
        submission: "unchanged",
      },
    });
    expect(() => modelCheck(invalid)).toThrow(/unreachable interrupt transition row/);
  }, 15_000);

  test("generated outputs are deterministic, digest-bound, and current", () => {
    expect(checkInterruptArtifacts(rendered)).toEqual([]);
    const manifest = JSON.parse(rendered.manifest);
    const sourceDigest = crypto
      .createHash("sha256")
      .update(source)
      .digest("hex");
    expect(manifest.source.sha256).toBe(sourceDigest);
    for (const output of manifest.outputs) {
      const content = rendered[output.name];
      expect(
        crypto.createHash("sha256").update(content).digest("hex"),
      ).toBe(output.sha256);
      expect(fs.readFileSync(generatedInterruptPaths[output.name], "utf8")).toBe(
        content,
      );
    }
  });

  test("generated Rust dispatch compiles standalone", () => {
    const output = path.join(temporaryDirectory, "libibex_interrupt_model.rlib");
    const result = spawnSync(
      "rustc",
      [
        "--edition=2021",
        "--crate-name",
        "ibex_interrupt_model",
        "--crate-type",
        "lib",
        generatedInterruptPaths.rust,
        "-o",
        output,
      ],
      { encoding: "utf8" },
    );
    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(fs.existsSync(output)).toBe(true);
  });
});
