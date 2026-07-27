// @ref LLP 0025#2-startup-configuration-is-captured-before-arming — every
// production environment occurrence needs an exact, reviewed phase identity.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  checkRuntimeEnvironmentInventory,
  loadRuntimeEnvironmentInventory,
  repoRoot,
  reconcileRuntimeEnvironmentRows,
  runtimeEnvironmentInventorySchemaPath,
} from "./generate-runtime-environment-inventory.mjs";

function occurrence(overrides = {}) {
  return {
    accessor: "env::var",
    context: "startup-input",
    direction: "read",
    language: "rust",
    scope: "capture",
    sourceOffset: 10,
    sourcePath: "src/example.rs",
    sourceRef: "src/example.rs#env::var:EXAMPLE:read",
    ...overrides,
  };
}

function surface(name, occurrences, overrides = {}) {
  const dynamic = name.includes("<dynamic>");
  return {
    kind: "startup",
    name,
    metadata: {
      authoredNames: dynamic ? [] : [name.slice("env:".length)],
      dynamic,
      dynamicKey: dynamic ? "rust:env::var" : null,
      occurrences,
      ...overrides,
    },
  };
}

function reviewedOccurrence(source, stage, overrides = {}) {
  return {
    accessor: source.accessor,
    context: source.context,
    direction: source.direction,
    language: source.language,
    occurrenceIndex: overrides.occurrenceIndex ?? 0,
    scope: source.scope,
    sourceOffset: overrides.sourceOffset ?? source.sourceOffset,
    sourcePath: source.sourcePath,
    sourceRef: source.sourceRef,
    stage,
    ...overrides,
  };
}

function reviewedRow(discovered, occurrences) {
  return {
    surfaceName: discovered.name,
    dynamic: discovered.metadata.dynamic,
    dynamicKey: discovered.metadata.dynamicKey,
    authoredNames: discovered.metadata.authoredNames,
    allowedStages: [...new Set(occurrences.map((item) => item.stage))].sort(),
    occurrences,
  };
}

function artifact(...rows) {
  return { rows };
}

const POST_ARM_EVIDENCE = {
  postArmDisposition: "effect-gated-host-read",
  postArmEvidence: {
    sourceRefs: ["src/example.rs#effectGate"],
    summary: "The exact typed effect gate precedes this host read.",
  },
};

describe("runtime environment stage inventory", () => {
  test("retains reviewed stages while refreshing offset evidence", () => {
    const source = occurrence({ sourceOffset: 200 });
    const discovered = surface("env:EXAMPLE", [source]);
    const reviewed = reviewedOccurrence(source, "post-arm-host-read", {
      ...POST_ARM_EVIDENCE,
      sourceOffset: 12,
    });
    const [row] = reconcileRuntimeEnvironmentRows(
      [discovered],
      artifact(reviewedRow(discovered, [reviewed])),
    );
    expect(row.occurrences[0]).toMatchObject({
      sourceOffset: 200,
      stage: "post-arm-host-read",
      postArmDisposition: "effect-gated-host-read",
      postArmEvidence: POST_ARM_EVIDENCE.postArmEvidence,
    });
  });

  test("fails when an occurrence moves to another lexical scope", () => {
    const prior = occurrence({ scope: "capture" });
    const moved = occurrence({ scope: "evaluate", sourceOffset: 500 });
    const discovered = surface("env:EXAMPLE", [moved]);
    expect(() =>
      reconcileRuntimeEnvironmentRows(
        [discovered],
        artifact(
          reviewedRow(discovered, [
            reviewedOccurrence(prior, "armed-bootstrap-host-read"),
          ]),
        ),
      ),
    ).toThrow(/un-dispositioned environment occurrence/u);
  });

  test("fails for new static, dynamic, and duplicate-scope occurrences", () => {
    const staticSurface = surface("env:NEW_STATIC", [occurrence()]);
    expect(() =>
      reconcileRuntimeEnvironmentRows([staticSurface], artifact()),
    ).toThrow(/un-dispositioned runtime environment surface/u);

    const first = occurrence({
      sourceRef: "src/example.rs#env::var:dynamic:read",
      sourceOffset: 10,
    });
    const second = occurrence({
      sourceRef: "src/example.rs#env::var:dynamic:read",
      sourceOffset: 20,
    });
    const dynamic = surface("env:<dynamic>:rust:env::var", [first, second]);
    expect(() =>
      reconcileRuntimeEnvironmentRows(
        [dynamic],
        artifact(
          reviewedRow(dynamic, [
            reviewedOccurrence(first, "launcher-pre-arm-read"),
          ]),
        ),
      ),
    ).toThrow(/un-dispositioned environment occurrence/u);
  });

  test("fails prohibited and post-arm fixed controls", () => {
    for (const name of [
      "EX_DISABLE_BYTECODE_SANITY_CHECK",
      "IBEX_AWAIT_UNWRAP_TIMEOUT_MS",
    ]) {
      expect(() =>
        reconcileRuntimeEnvironmentRows(
          [surface(`env:${name}`, [occurrence()])],
          artifact(),
        ),
      ).toThrow(/prohibited post-arm fixed environment control/u);
    }

    const compat = surface("env:EXACT_COMPAT_BUN", [occurrence()]);
    const reviewed = reviewedOccurrence(
      compat.metadata.occurrences[0],
      "post-arm-host-read",
      POST_ARM_EVIDENCE,
    );
    expect(() =>
      reconcileRuntimeEnvironmentRows(
        [compat],
        artifact(reviewedRow(compat, [reviewed])),
      ),
    ).toThrow(/fixed compatibility control has a post-arm host read/u);
  });

  test("requires explicit, valid evidence for every post-arm host read", () => {
    const discovered = surface("env:EXAMPLE", [occurrence()]);
    const missing = reviewedOccurrence(
      discovered.metadata.occurrences[0],
      "post-arm-host-read",
    );
    expect(() =>
      reconcileRuntimeEnvironmentRows(
        [discovered],
        artifact(reviewedRow(discovered, [missing])),
      ),
    ).toThrow(/no reviewed disposition/u);

    const invalidTestHook = {
      ...missing,
      postArmDisposition: "test-only-effect-hook",
      postArmEvidence: POST_ARM_EVIDENCE.postArmEvidence,
    };
    expect(() =>
      reconcileRuntimeEnvironmentRows(
        [discovered],
        artifact(reviewedRow(discovered, [invalidTestHook])),
      ),
    ).toThrow(/only an IBEX_TEST_ control/u);
  });

  test("keeps JavaScript reads on the principal overlay", () => {
    const source = occurrence({
      accessor: "process.env",
      language: "javascript",
      scope: null,
      sourceOffset: null,
      sourcePath: "src/runtime.js",
      sourceRef: "src/runtime.js#process.env:EXAMPLE:read",
    });
    const discovered = surface("env:EXAMPLE", [source]);
    const wrong = reviewedOccurrence(source, "launcher-pre-arm-read");
    expect(() =>
      reconcileRuntimeEnvironmentRows(
        [discovered],
        artifact(reviewedRow(discovered, [wrong])),
      ),
    ).toThrow(/must use the principal overlay/u);

    const right = reviewedOccurrence(source, "principal-overlay-read");
    const [row] = reconcileRuntimeEnvironmentRows(
      [discovered],
      artifact(reviewedRow(discovered, [right])),
    );
    expect(row.occurrences[0]).toMatchObject({
      hostEnvironment: false,
      postArmDisposition: null,
      postArmEvidence: null,
      stage: "principal-overlay-read",
    });
  });

  test("rejects an undispositioned runtime host mutation", () => {
    const source = occurrence({
      context: "runtime-input",
      direction: "write",
    });
    const discovered = surface("env:EXAMPLE", [source]);
    const reviewed = reviewedOccurrence(source, "trusted-bootstrap-host-write");
    expect(() =>
      reconcileRuntimeEnvironmentRows(
        [discovered],
        artifact(reviewedRow(discovered, [reviewed])),
      ),
    ).toThrow(/runtime host-environment mutation is prohibited/u);
  });

  test("rejects noncanonical and schema-invalid reviewed artifacts", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-env-artifact-"));
    const artifactPath = path.join(root, "inventory.json");
    fs.writeFileSync(artifactPath, '{"rows": []}\n');
    expect(() =>
      loadRuntimeEnvironmentInventory(
        artifactPath,
        runtimeEnvironmentInventorySchemaPath,
      ),
    ).toThrow(/not canonical JSON/u);
    fs.writeFileSync(artifactPath, '{\n  "rows": []\n}\n');
    expect(() =>
      loadRuntimeEnvironmentInventory(
        artifactPath,
        runtimeEnvironmentInventorySchemaPath,
      ),
    ).toThrow(/schema validation failed/u);
  });

  test("pins immutable startup captures and the effect-gated child fallback", () => {
    const { artifact: reviewed } = loadRuntimeEnvironmentInventory();
    const row = (name) =>
      reviewed.rows.find((candidate) => candidate.surfaceName === `env:${name}`);

    for (const name of ["IBEX_LOOP_TRACE", "EXACT_LOOP_TRACE"]) {
      expect(row(name).occurrences).toEqual([
        expect.objectContaining({
          scope: "new_with_armed_snapshot",
          stage: "armed-bootstrap-host-read",
        }),
      ]);
    }
    for (const name of [
      "EXACT_WINHTTP_ENABLE_HTTP2",
      "EXACT_WPT_FIXTURE_CLOSE_SEMANTICS",
      "EXACT_WPT_TRUST_LOOPBACK_TLS",
    ]) {
      expect(
        row(name).occurrences.every(
          (item) =>
            item.scope === "<top-level>" &&
            item.stage === "launcher-pre-arm-read",
        ),
      ).toBe(true);
    }
    expect(row("IBEX_STARTUP_TRACE").occurrences).toEqual([
      expect.objectContaining({
        scope: "new_with_armed_snapshot",
        stage: "armed-bootstrap-host-read",
      }),
      expect.objectContaining({
        scope: "trace_startup",
        stage: "launcher-pre-arm-read",
      }),
      expect.objectContaining({
        scope: "begin",
        stage: "armed-bootstrap-host-read",
      }),
    ]);
    expect(row("EX_STARTUP_TRACE").occurrences).toEqual([
      expect.objectContaining({
        scope: "new_with_armed_snapshot",
        stage: "armed-bootstrap-host-read",
      }),
      expect.objectContaining({
        scope: "trace_startup",
        stage: "launcher-pre-arm-read",
      }),
      expect.objectContaining({
        scope: "startup_trace_enabled",
        stage: "armed-bootstrap-host-read",
      }),
    ]);
    for (const name of ["IBEX_CDP_LOG", "EXACT_CDP_LOG"]) {
      expect(row(name).occurrences).toEqual([
        expect.objectContaining({
          scope: "cdp_log_enabled",
          stage: "post-arm-host-read",
          postArmDisposition: "armed-unreachable-host-read",
        }),
      ]);
    }
    expect(
      row("COMSPEC").occurrences.find(
        (item) => item.sourcePath === "src/engine/hermes_runtime_platform_windows.cc",
      ),
    ).toMatchObject({
      scope: "windowsSpawnLaunchFile",
      stage: "post-arm-host-read",
      postArmDisposition: "effect-gated-host-read",
    });
    expect(row("<dynamic>:cpp:environ").occurrences).toEqual([
      expect.objectContaining({
        scope: "s_processEnvironment",
        sourcePath: "src/engine/hermes_runtime_process.cc",
        stage: "post-arm-host-read",
        postArmDisposition: "effect-gated-host-read",
      }),
    ]);
    expect(row("<dynamic>:cpp:_dupenv_s").occurrences).toEqual([
      expect.objectContaining({
        scope: "getenvString",
        sourcePath: "src/engine/hermes_runtime_platform_windows.cc",
        stage: "post-arm-host-read",
        postArmDisposition: "effect-gated-host-read",
      }),
    ]);
    expect(row("IBEX_TEST_ARMED_DENY_OPEN_COMMIT").occurrences).toEqual([
      expect.objectContaining({
        accessor: "getenv",
        scope: "denyArmedOpenCommitForTest",
        stage: "post-arm-host-read",
        postArmDisposition: "test-only-effect-hook",
      }),
    ]);
    expect(row("IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS").occurrences).toEqual([
      expect.objectContaining({
        scope: "exactTestDelayRuntimeProducer",
        sourcePath: "src/engine/hermes_runtime_internal.h",
        stage: "post-arm-host-read",
        postArmDisposition: "test-only-effect-hook",
      }),
    ]);
  });

  test("authenticated compiler children use closed environments and captured runners", () => {
    const runtime = fs.readFileSync(
      path.join(repoRoot, "src/bin/ibex/runtime.rs"),
      "utf8",
    );
    const moduleLoader = fs.readFileSync(
      path.join(repoRoot, "src/module_loader/mod.rs"),
      "utf8",
    );
    const main = fs.readFileSync(
      path.join(repoRoot, "src/bin/ibex/main.rs"),
      "utf8",
    );
    const freshEnvironment = runtime.slice(
      runtime.indexOf("fn configure_js_tool_environment"),
      runtime.indexOf("async fn run_bundler_with_source_provenance_mode"),
    );
    const transpileEnvironment = moduleLoader.slice(
      moduleLoader.indexOf("fn configure_transpile_subprocess_environment"),
      moduleLoader.indexOf("fn find_js_runner"),
    );
    const transpileRun = moduleLoader.slice(
      moduleLoader.indexOf("fn run_transpile_subprocess"),
      moduleLoader.indexOf("fn configure_transpile_subprocess_environment"),
    );
    for (const [label, source] of [
      ["fresh bundler", freshEnvironment],
      ["transpile override", transpileEnvironment],
    ]) {
      expect(source, label).toContain(".env_clear()");
      expect(source, label).not.toMatch(/\.env\(\s*"PATH"/u);
    }
    expect(main.indexOf("capture_bundler_runner_selection()"))
      .toBeGreaterThan(-1);
    expect(main.indexOf("capture_bundler_runner_selection()"))
      .toBeLessThan(main.indexOf("pre_clap_worker_bootstrap"));
    expect(transpileRun).toContain("command.current_dir(&private_environment)");
    expect(transpileRun).toContain('command.arg("--no-env-file")');
    expect(transpileRun).toContain('"--config={}"');
    const policyRun = runtime.slice(
      runtime.indexOf("pub async fn run_policy_command"),
      runtime.indexOf("fn bundler_working_dir"),
    );
    expect(policyRun).toContain("configure_js_tool_environment");
    expect(policyRun).toContain('cmd.arg("--no-env-file")');
    expect(policyRun).toContain('"--config={}"');
  });

  test(
    "checked-in inventory is current",
    async () => {
      expect(await checkRuntimeEnvironmentInventory()).toEqual([]);
    },
    30_000,
  );
});
