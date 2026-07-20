// @ref LLP 0025#12-constants — the canonical annex, its strict schema, and
// generated Rust consumer must move as one digest-bound contract.
// @ref LLP 0025#6-interruption-and-cancellation — interrupt status and exact
// notice vocabulary may not diverge between the model and supervisor.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  checkSessionConstantsArtifact,
  generatedSessionConstantsPath,
  loadSessionConstants,
  renderSessionConstants,
  terminalSessionSourcePath,
  validateInterruptStatusBinding,
  validateTerminalBinding,
} from "./generate-session-constants.mjs";

let annex;
let source;
let schemaSource;
let rendered;
let temporaryDirectory;

beforeAll(() => {
  ({ annex, source, schemaSource } = loadSessionConstants());
  rendered = renderSessionConstants(annex, { source, schemaSource });
  temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "ibex-session-constants-"),
  );
});

afterAll(() => {
  if (temporaryDirectory) {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

function writeFixture(name, value, { canonical = true } = {}) {
  const filePath = path.join(temporaryDirectory, name);
  fs.writeFileSync(
    filePath,
    canonical ? `${JSON.stringify(value, null, 2)}\n` : JSON.stringify(value),
  );
  return filePath;
}

describe("LLP 0025 session constants annex", () => {
  test("pins every operator-visible constants family", () => {
    expect(annex.promptTokens).toEqual({
      defaultText: "➤ ",
      interruptByte: 3,
      editorErase: "\r\x1b[2K",
      transcriptBoundary: "\n",
    });
    expect(annex.notices).toEqual({
      orderlyPromise:
        "press Ctrl+C again to end the session, or Ctrl+D to exit",
      cancellingWork:
        "cancelling work — press Ctrl+C again to end the session",
      workInFlight:
        "work is in flight — press Ctrl+C again to end the session",
      cancellingCompletion:
        "cancelling completion — press Ctrl+C again to end the session",
      inputDiscarded: "input discarded",
    });
    expect(annex.exitStatuses).toEqual({
      orderlyDefault: 0,
      nonInteractiveFailure: 1,
      workerCommitUnacknowledged: 69,
      cancellationOrEngineFault: 70,
      startupFailure: 78,
      sighup: 129,
      interrupt: 130,
      sigquit: 131,
      brokenPipe: 141,
      sigterm: 143,
      posixStatusMask: 255,
    });
    expect(
      Object.fromEntries(
        Object.entries(annex.limits).map(([name, limit]) => [
          name,
          limit.value,
        ]),
      ),
    ).toEqual({
      rendererDepth: 4,
      rendererBreadth: 128,
      rendererPayload: 10_000,
      historyEntries: 10_000,
      historyBytes: 8 * 1024 * 1024,
      historyRecordBytes: 1024 * 1024,
      brokerQueueBytes: 8 * 1024 * 1024,
      displayTreeSerializedBytes: 16 * 1024 * 1024,
      liveRelays: 64,
      inputBytes: 1024 * 1024,
    });
  });

  test("distinguishes pinned lifecycle timings from open engine budgets", () => {
    expect(annex.timings.brokerFlush.milliseconds).toBe(500);
    expect(annex.timings.historyLockAcquisition.milliseconds).toBe(250);
    expect(annex.timings.lifecycleCommitAck.milliseconds).toBe(2_000);
    for (const name of [
      "shutdownDrain",
      "cancellation",
      "completion",
      "asyncStormCoalescingWindow",
    ]) {
      expect(annex.timings[name]).toEqual({
        milliseconds: null,
        onExpiry: "unbound-engine-dependent",
      });
    }
  });

  test("pins the complete IBDX v1 grammar and tag vocabulary", () => {
    expect(annex.displayTreeWire).toEqual({
      magic: "IBDX",
      version: 1,
      endianness: "little",
      rootDepth: 1,
      headerOrder: ["magic", "version"],
      nodeOrder: [
        "kind",
        "payloadLength",
        "payload",
        "childCount",
        "children",
      ],
      fieldWidthsBits: {
        magic: 32,
        version: 16,
        kind: 16,
        payloadLength: 32,
        childCount: 32,
      },
      nodeTags: {
        text: 1,
        string: 2,
        number: 3,
        boolean: 4,
        null: 5,
        undefined: 6,
        error: 7,
        key: 8,
        typeTag: 9,
        cycle: 10,
        truncation: 11,
      },
    });
    expect(annex.renderText.truncationTemplate).toBe("… +{omitted} more");
    expect(annex.renderText.fallbackTemplate).toBe(
      "[display unavailable: {reason}]",
    );
    expect(annex.renderText.unknownNodeTemplate).toBe(
      "[Unknown display node {tag}]",
    );
  });

  test("rejects noncanonical and schema-invalid annexes", () => {
    const noncanonical = writeFixture("noncanonical.json", annex, {
      canonical: false,
    });
    expect(() => loadSessionConstants(noncanonical)).toThrow(/not canonical/);

    const withExtraKey = structuredClone(annex);
    withExtraKey.promptTokens.unowned = "drift";
    const invalid = writeFixture("invalid.json", withExtraKey);
    expect(() => loadSessionConstants(invalid)).toThrow(/schema validation failed/);
  });

  test("renders deterministically and the checked-in artifact is current", () => {
    const second = renderSessionConstants(annex, { source, schemaSource });
    expect(second).toEqual(rendered);
    expect(checkSessionConstantsArtifact(rendered)).toEqual([]);
    expect(fs.readFileSync(generatedSessionConstantsPath, "utf8")).toBe(
      rendered.rust,
    );
    expect(rendered.rust).toContain(
      `SESSION_CONSTANTS_SOURCE_SHA256: &str =\n    "${rendered.binding.sourceDigest}"`,
    );
  });

  test("emits a standalone Rust constants module", () => {
    const output = path.join(temporaryDirectory, "session_constants.rlib");
    const compilation = spawnSync(
      "rustc",
      [
        "--edition=2021",
        "--crate-type=lib",
        "--crate-name=session_constants_generated",
        "-Dwarnings",
        generatedSessionConstantsPath,
        "-o",
        output,
      ],
      { encoding: "utf8" },
    );
    expect(compilation.status, compilation.stderr).toBe(0);
    expect(fs.existsSync(output)).toBe(true);
  });

  test("fails closed when the Rust consumer restores a handwritten copy", () => {
    const terminalSource = fs.readFileSync(terminalSessionSourcePath, "utf8");
    expect(() => validateTerminalBinding(annex, terminalSource)).not.toThrow();

    const numericDrift = terminalSource.replaceAll(
      "EXIT_STATUS_ENGINE_FAULT",
      "70",
    );
    expect(() => validateTerminalBinding(annex, numericDrift)).toThrow(
      /missing generated constant bindings/,
    );

    const noticeDrift = terminalSource.replace(
      "generated::Notice::CancellingWork => NOTICE_CANCELLING_WORK",
      'generated::Notice::CancellingWork => "cancelling work — press Ctrl+C again to end the session"',
    );
    expect(() => validateTerminalBinding(annex, noticeDrift)).toThrow(
      /annex-owned literal/,
    );

    const wireDrift = terminalSource.replace(
      "let child_count = cursor.u32()?;",
      "let child_count = cursor.u16()?;",
    );
    expect(() => validateTerminalBinding(annex, wireDrift)).toThrow(
      /annex-bound IBDX node field order/,
    );
  });

  test("fails closed when the interrupt model changes status vocabulary", () => {
    expect(() => validateInterruptStatusBinding(annex)).not.toThrow();
    expect(() =>
      validateInterruptStatusBinding(
        annex,
        '{"promise":"interrupt-131"}\n',
      ),
    ).toThrow(/diverges from annex/);
  });
});
