// @ref LLP 0024#7-the-session-record — independently asserted model cases pin
// provenance, cross-kind replacement, per-cell rollback, and display ACK state.
// @ref LLP 0024#77-deviations-and-the-four-gates-that-prove-them — the focused
// suite exercises every self-contained part of all four gate harness classes.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import {
  EMPTY,
  GATE_CATALOG,
  GATE_3_DIRECT_ORACLE_EXCLUSIONS,
  GATE_3_LOWERING_CASES,
  GATE_3_LOWERING_OBLIGATIONS,
  MATRIX_ROWS,
  MODEL_FIXTURES,
  RESTRICTED_CLASS_CASES,
  RESTRICTED_CLASS_EXCLUSION_IDS,
  RESTRICTED_GLOBAL_ROWS,
  STANDARDS_PROBES,
  UNDEFINED,
  SessionSemanticsModel,
  accessorDescriptor,
  checkGeneratedArtifacts,
  compareGateObservations,
  executeFixture,
  generatedPaths,
  hasRestrictedGlobalProperty,
  isRestrictedClassCase,
  modelSourceDigest,
  repoRoot,
  restrictedClassExclusions,
  runModelStandardsProbe,
  runStandardsProbe,
} from "./session-semantics-model.mjs";

const fixtures = new Map(MODEL_FIXTURES.map((fixture) => [fixture.id, fixture]));

function run(id) {
  const fixture = fixtures.get(id);
  if (!fixture) throw new Error(`missing fixture ${id}`);
  return executeFixture(fixture);
}

function lastEvent(result, type) {
  return [...result.events].reverse().find((event) => event.type === type);
}

describe("LLP 0024 executable session-semantics model", () => {
  test("checked generated artifacts are exact and bind the model source digest", () => {
    const result = checkGeneratedArtifacts();
    expect(result.fixtures).toBe(MODEL_FIXTURES.length);
    expect(result.matrixRows).toBe(MATRIX_ROWS.length);
    expect(result.standardsProbes).toBe(STANDARDS_PROBES.length);
    expect(result.sourceDigest).toBe(modelSourceDigest());

    const manifest = JSON.parse(fs.readFileSync(generatedPaths.manifest, "utf8"));
    expect(manifest.modelSource.digest).toBe(modelSourceDigest());
    expect(manifest.outputs).toHaveLength(2);
    expect(manifest.artifactSetDigest).toMatch(/^sha256-[A-Za-z0-9_-]{43}$/);
  });

  test("bare var Object adopts while function Object clobbers", () => {
    const bareVar = run("bare-var-object-adopts-without-clobber").final;
    expect(bareVar.objectRecord.own.Object).toEqual({
      type: "data",
      value: { $sessionValue: "builtin", name: "Object" },
      writable: true,
      enumerable: false,
      configurable: true,
    });
    expect(bareVar.varDeclaredNames).toContain("Object");
    expect(bareVar.sessionCreatedVars).not.toContain("Object");

    const declaredFunction = run(
      "function-object-clobbers-without-creation-provenance",
    ).final;
    expect(declaredFunction.objectRecord.own.Object).toEqual({
      type: "data",
      value: { $sessionValue: "function", name: "Object", revision: 2 },
      writable: true,
      enumerable: true,
      configurable: false,
    });
    expect(declaredFunction.sessionCreatedVars).not.toContain("Object");
  });

  test("restricted-global provenance cannot be laundered by var or function", () => {
    const adopted = run("var-undefined-cannot-launder-restricted-global");
    expect(adopted.events[0].result.outcome).toBe("success");
    expect(adopted.events[1].result).toMatchObject({
      outcome: "throw",
      phase: 3,
      error: {
        type: "SyntaxError",
        name: "undefined",
        predicate: "ModifiedHasRestrictedGlobalProperty",
      },
    });
    expect(adopted.final.varDeclaredNames).toContain("undefined");
    expect(adopted.final.sessionCreatedVars).not.toContain("undefined");

    const overwritten = run("function-overwrite-does-not-launder-provenance");
    expect(overwritten.events[0].result.outcome).toBe("success");
    expect(overwritten.events[1].result).toMatchObject({
      outcome: "throw",
      phase: 3,
      error: { predicate: "ModifiedHasRestrictedGlobalProperty" },
    });
    expect(overwritten.final.sessionCreatedVars).not.toContain("p");

    for (const row of RESTRICTED_GLOBAL_ROWS) {
      const session = new SessionSemanticsModel(
        row.ownProperty
          ? {
              ownProperties: {
                p: {
                  type: "data",
                  value: 1,
                  writable: true,
                  enumerable: true,
                  configurable: row.configurable,
                },
              },
            }
          : undefined,
      );
      if (row.sessionCreated) session.sessionCreatedVars.add("p");
      expect(hasRestrictedGlobalProperty(session, "p"), row.id).toBe(
        row.restricted,
      );
    }
  });

  test("rollback commits iff each cell reached InitializeBinding", () => {
    const restored = run("uninitialized-lexical-restores-displaced-cell");
    expect(restored.events[1].result.journal[0].fate).toBe("rolled-back");
    expect(restored.final.declarativeRecord.x).toMatchObject({
      kind: "const",
      initialized: true,
      value: 1,
    });
    expect(lastEvent(restored, "read").value).toBe(1);

    const committed = run("initialized-lexical-commits-on-throw");
    expect(committed.events[0].result.outcome).toBe("throw");
    expect(committed.events[0].result.journal[0].fate).toBe("committed");
    expect(committed.final.declarativeRecord.x).toMatchObject({
      kind: "let",
      initialized: true,
      value: 1,
    });

    const partial = run("destructuring-commits-per-initialized-cell");
    expect(partial.final.declarativeRecord.a).toMatchObject({
      initialized: true,
      value: 1,
    });
    expect(partial.final.declarativeRecord.b).toBeUndefined();
    expect(partial.events.at(-1).value).toBe("undefined");
    expect(partial.events[0].result.journal.map(({ fate }) => fate).sort()).toEqual(
      ["committed", "rolled-back"],
    );
  });

  test("object bindings commit on phase-six failure and imports precede mutation", () => {
    const displaced = run("var-commits-and-displaces-lexical-on-throw");
    expect(displaced.final.declarativeRecord.x).toBeUndefined();
    expect(displaced.final.objectRecord.own.x.value).toBe(2);
    expect(displaced.final.sessionCreatedVars).toContain("x");
    expect(displaced.events[1].result.journal[0].fate).toBe("committed");

    const importFailure = run("throwing-import-publishes-no-declarations");
    expect(importFailure.events[0].result).toMatchObject({
      outcome: "throw",
      phase: 4,
      journal: [],
    });
    expect(importFailure.final.declarativeRecord.imported).toBeUndefined();
    expect(importFailure.final.objectRecord.own.w).toBeUndefined();
    expect(importFailure.final.objectRecord.own.moduleSideEffect.value).toBe(1);

    const recheck = run("phase-five-recheck-prevents-partial-instantiation");
    expect(recheck.events[0].result).toMatchObject({
      outcome: "throw",
      phase: 5,
      journal: [],
    });
    expect(recheck.final.objectRecord.extensible).toBe(false);
    expect(recheck.final.objectRecord.own.x).toBeUndefined();
    expect(recheck.final.objectRecord.own.y).toBeUndefined();
    expect(recheck.final.declarativeRecord.imported).toBeUndefined();
  });

  test("const and import cells remain read-only", () => {
    const constant = run("const-assignment-throws-without-changing-value");
    expect(constant.events[1].result).toMatchObject({
      outcome: "throw",
      phase: 6,
      error: { type: "TypeError" },
    });
    expect(lastEvent(constant, "read").value).toBe(9);

    const imported = run("import-cell-is-initialized-and-read-only");
    expect(imported.events[0].result.journal[0]).toMatchObject({
      declarationKind: "import",
      initializedAtInstantiation: true,
      fate: "committed",
    });
    expect(imported.events[1].result.error.type).toBe("TypeError");
    expect(lastEvent(imported, "read").value).toBe(42);

    const classCell = run("class-cell-initializes-and-remains-mutable");
    expect(classCell.events[1].result.outcome).toBe("success");
    expect(lastEvent(classCell, "read").value).toBe("replacement");
  });

  test("$_ updates only after a displayed ACK and disables with trigger fate", () => {
    const acknowledgements = run("last-value-updates-only-on-displayed-ack");
    expect(acknowledgements.events[0].result.updated).toBe(true);
    expect(acknowledgements.events[1].result).toEqual({
      updated: false,
      reason: "display-fallback",
    });
    expect(lastEvent(acknowledgements, "read").value).toBe(1);

    const mutation = run("last-value-user-mutation-disables-auto-update");
    expect(mutation.final.lastValue).toMatchObject({
      value: 7,
      autoUpdateEnabled: false,
      disableReason: "mutation:setter-fired",
      mutationGeneration: 1,
    });
    expect(lastEvent(mutation, "read").value).toBe(7);

    const rolledBack = run(
      "last-value-uninitialized-lexical-disable-rolls-back",
    );
    expect(rolledBack.events[0].result.journal[0].fate).toBe("rolled-back");
    expect(rolledBack.final.lastValue.autoUpdateEnabled).toBe(true);
    expect(lastEvent(rolledBack, "read").value).toBe(5);

    const committed = run("last-value-initialized-lexical-disable-commits");
    expect(committed.events[0].result.journal[0].fate).toBe("committed");
    expect(committed.final.lastValue.autoUpdateEnabled).toBe(false);
    expect(lastEvent(committed, "read").value).toBe(5);
  });

  test("$_ descriptor checks catch persistent replacement but not exact ABA", () => {
    const replaced = new SessionSemanticsModel();
    replaced.defineGlobalProperty(
      "$_",
      accessorDescriptor("attacker-getter", "attacker-setter"),
    );
    expect(replaced.lastValue.autoUpdateEnabled).toBe(true);
    expect(replaced.acknowledgeDisplay(1, "displayed")).toEqual({
      updated: false,
      reason: "accessor-identity-mismatch",
    });
    expect(replaced.lastValue.autoUpdateEnabled).toBe(false);

    const exactAba = new SessionSemanticsModel();
    const savedDescriptor = structuredClone(exactAba.ownDescriptor("$_"));
    expect(exactAba.deleteGlobalProperty("$_")).toBe(true);
    exactAba.defineGlobalProperty("$_", savedDescriptor);
    expect(exactAba.acknowledgeDisplay(2, "displayed")).toEqual({
      updated: true,
      reason: "displayed",
    });
    expect(exactAba.resolve("$_")).toBe(2);
  });

  test("same-input collisions are atomic while duplicate var/function is legal", () => {
    const collision = run("same-input-lexical-var-collision-is-atomic");
    expect(collision.events[0].result).toMatchObject({
      outcome: "throw",
      phase: 2,
      error: { type: "SyntaxError" },
      journal: [],
    });
    expect(collision.final.declarativeRecord.x).toBeUndefined();
    expect(collision.final.objectRecord.own.x).toBeUndefined();

    const functionWins = run("same-input-var-function-function-wins");
    expect(lastEvent(functionWins, "read").value).toEqual({
      $sessionValue: "function",
      name: "f",
      revision: 1,
    });
  });

  test("every generated cross-kind row is reached by a checked fixture", () => {
    const reached = new Set();
    for (const fixture of MODEL_FIXTURES) {
      for (const event of executeFixture(fixture).events) {
        for (const entry of event.result?.journal ?? []) {
          for (const row of entry.matrixRows) reached.add(row);
        }
      }
    }
    expect([...reached].sort()).toEqual(MATRIX_ROWS.map(({ id }) => id).sort());
  });

  test("gate 1 and gate 3 comparator detects an observation mismatch", () => {
    const cases = [fixtures.get("bare-var-object-adopts-without-clobber")];
    expect(
      compareGateObservations(cases, executeFixture, executeFixture),
    ).toEqual([]);
    const mismatches = compareGateObservations(
      cases,
      executeFixture,
      (fixture) => {
        const result = executeFixture(fixture);
        result.final.sessionCreatedVars.push("Object");
        return result;
      },
    );
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0].id).toBe(cases[0].id);
  });

  test("external gates identify their exact implemented Rust harness", () => {
    const expected = new Map([
      [
        "gate-1-model-conformance",
        "session_semantics_conformance::implementation_matches_reference_model_gate",
      ],
      [
        "gate-2-model-validation",
        "session_semantics_conformance::reference_model_matches_same_engine_growing_script_gate",
      ],
      [
        "gate-3-lowering-fidelity",
        "session_semantics_conformance::single_input_lowering_fidelity_gate",
      ],
    ]);
    const sourcePath = "src/bin/ibex/session_semantics_conformance.rs";
    const rustHarness = fs.readFileSync(`${repoRoot}/${sourcePath}`, "utf8");
    const rustMain = fs.readFileSync(`${repoRoot}/src/bin/ibex/main.rs`, "utf8");
    expect(rustMain).toContain(
      '#[cfg(all(test, feature = "capsec-conformance-observer"))]\nmod session_semantics_conformance;',
    );

    for (const [id, testName] of expected) {
      const gate = GATE_CATALOG.find((candidate) => candidate.id === id);
      expect(gate?.status).toBe("external-harness-implemented");
      expect(gate?.harness).toEqual({
        kind: "external-rust-test",
        cargoTarget: "bin:ibex",
        requiredFeatures: ["capsec-conformance-observer"],
        sourcePath,
        testName,
        cargoArgs: [
          "test",
          "--bin",
          "ibex",
          "--features",
          "capsec-conformance-observer",
          testName,
          "--",
          "--test-threads=1",
        ],
      });
      expect(rustHarness).toContain(
        `#[tokio::test(flavor = "current_thread")]\nasync fn ${testName.split("::").at(-1)}()`,
      );
    }
  });

  test("gate 3 executes every named lowering obligation without hiding exclusions", () => {
    const obligationIds = [...GATE_3_LOWERING_OBLIGATIONS];
    expect(new Set(obligationIds).size).toBe(obligationIds.length);

    const caseIds = GATE_3_LOWERING_CASES.map(({ id }) => id);
    expect(new Set(caseIds).size).toBe(caseIds.length);
    const declared = new Set(obligationIds);
    const observed = new Set();
    for (const testCase of GATE_3_LOWERING_CASES) {
      expect(testCase.source.length, testCase.id).toBeGreaterThan(0);
      expect(testCase.covers.length, testCase.id).toBeGreaterThan(0);
      for (const obligation of testCase.covers) {
        expect(declared.has(obligation), `${testCase.id}: ${obligation}`).toBe(
          true,
        );
        observed.add(obligation);
      }
      expect(
        [
          "equal-completion",
          "expected-difference",
          "matching-refusal",
          "matching-throw",
        ],
        testCase.id,
      ).toContain(testCase.oracle.kind);
      if (testCase.oracle.kind !== "equal-completion") {
        expect(testCase.oracle.rationale.length, testCase.id).toBeGreaterThan(0);
        expect(testCase.oracle.direct, testCase.id).toBeDefined();
        expect(testCase.oracle.lowered, testCase.id).toBeDefined();
      }
    }
    expect([...observed].sort()).toEqual([...obligationIds].sort());

    expect(
      GATE_3_LOWERING_CASES.filter(
        ({ oracle }) => oracle.kind === "expected-difference",
      ).map(({ oracle }) => oracle.rationale),
    ).toEqual([
      "safe-display-quotes-string-completions",
      "hermes-finally-does-not-apply-update-empty",
      "hermes-finally-does-not-apply-update-empty",
      "hermes-finally-does-not-apply-update-empty",
      "legacy-seam-collapses-undefined-and-empty",
      "legacy-seam-collapses-undefined-and-empty",
      "hermes-has-no-session-lexical-tdz",
      "hermes-rejects-const-assignment-before-runtime",
    ]);
    expect(
      GATE_3_DIRECT_ORACLE_EXCLUSIONS.map(({ id, owner }) => ({ id, owner })),
    ).toEqual([
      { id: "script-static-import", owner: "OBL-PARSER-GOAL" },
      { id: "dynamic-import-expression", owner: "OBL-PARSER-GOAL" },
      { id: "script-top-level-await", owner: "OBL-PARSER-GOAL" },
      {
        id: "script-plus-extensions-parser-goal",
        owner: "OBL-PARSER-GOAL",
      },
    ]);

    const gate = GATE_CATALOG.find(
      ({ id }) => id === "gate-3-lowering-fidelity",
    );
    expect(gate?.status).toBe("external-harness-implemented");
    expect(gate?.selfContainedCoverage).toContain(
      `${GATE_3_LOWERING_OBLIGATIONS.length} lowering obligations`,
    );
    expect(gate?.selfContainedCoverage).toContain(
      `${GATE_3_LOWERING_CASES.length} owner-authored cases`,
    );
  });

  test("gate 2 restricted-class predicate enforces every exclusion", () => {
    const observedExclusionIds = new Set();
    for (const testCase of RESTRICTED_CLASS_CASES) {
      const observed = restrictedClassExclusions(testCase);
      expect(observed, testCase.id).toEqual(
        [...testCase.expectedExclusions].sort(),
      );
      expect(isRestrictedClassCase(testCase), testCase.id).toBe(
        testCase.expectedExclusions.length === 0,
      );
      for (const exclusion of observed) observedExclusionIds.add(exclusion);
    }
    expect([...observedExclusionIds].sort()).toEqual(
      [...RESTRICTED_CLASS_EXCLUSION_IDS].sort(),
    );
  });

  test("gate 2b probes real Script semantics in a fresh subprocess", () => {
    for (const probe of STANDARDS_PROBES) {
      const standardsObservation = runStandardsProbe(probe);
      const modelObservation = runModelStandardsProbe(probe);
      expect(standardsObservation, probe.id).toEqual(probe.expected);
      if (probe.relation === "matches-model") {
        expect(modelObservation, probe.id).toEqual(standardsObservation);
      }
      if (probe.relation === "expected-deviation") {
        expect(probe.deviation).toBe("a-cross-input-redeclaration");
        expect(modelObservation, probe.id).not.toEqual(standardsObservation);
        expect(modelObservation).toEqual({ secondOutcome: "success" });
      }
    }
    expect(
      GATE_CATALOG.find(({ id }) => id.startsWith("gate-2b"))?.status,
    ).toBe("self-contained-probes-runnable");
  });

  test("symbolic undefined and empty completion remain distinct", () => {
    expect(UNDEFINED).not.toEqual(EMPTY);
    const session = new SessionSemanticsModel();
    expect(session.resolve("$_")).toEqual(UNDEFINED);
    const result = session.evaluateInput({
      steps: [
        { op: "complete", value: 1 },
        { op: "empty" },
      ],
    });
    expect(result.completion).toBe(1);
  });
});
