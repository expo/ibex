#!/usr/bin/env node

/**
 * Executable, non-circular adapters for LLP 0024 Gates 2 and 2b.
 *
 * Gate 2 data pairs concrete source with the small reference-model IR. The
 * native Rust harness consumes the emitted observations and runs the source as
 * one growing Script through the production lowering and Hermes engine.
 * Gate 2b keeps the standards arm in a fresh Node process for every row and
 * applies only an optional owner-authored quirk file; expected deviations stay
 * in the model's separate relation field.
 *
 * @ref LLP 0024#77-deviations-and-the-four-gates-that-prove-them
 */

import fs from "node:fs";
import path from "node:path";
import {
  EMPTY,
  STANDARDS_PROBES,
  SessionSemanticsModel,
  functionValue,
  repoRoot,
  restrictedClassExclusions,
  runModelStandardsProbe,
  runStandardsProbe,
} from "./session-semantics-model.mjs";

const QUIRK_PATH = path.join(
  repoRoot,
  "session",
  "session-semantics-engine-quirks.v1.json",
);

export const ENGINE_RESTRICTED_CASES = Object.freeze([
  Object.freeze({
    id: "var-update-empty-fold",
    sources: ["var gate2a = 1;", "gate2a += 2;", "gate2a;"],
    classifierInputs: [
      { declarations: [{ kind: "var", name: "gate2a" }] },
      { analysis: { referencedNames: ["gate2a"] } },
      { analysis: { referencedNames: ["gate2a"] } },
    ],
    modelInputs: [
      {
        declarations: [{ kind: "var", name: "gate2a" }],
        steps: [{ op: "assign", name: "gate2a", value: 1, completion: EMPTY }],
      },
      { steps: [{ op: "assign", name: "gate2a", value: 3 }] },
      { steps: [{ op: "read", name: "gate2a" }] },
    ],
  }),
  Object.freeze({
    id: "function-call-and-var",
    sources: [
      "function gate2f() { return 4; }",
      "var gate2y = gate2f();",
      "gate2y;",
    ],
    classifierInputs: [
      { declarations: [{ kind: "function", name: "gate2f" }] },
      {
        declarations: [{ kind: "var", name: "gate2y" }],
        analysis: { referencedNames: ["gate2f"] },
      },
      { analysis: { referencedNames: ["gate2y"] } },
    ],
    modelInputs: [
      {
        declarations: [
          { kind: "function", name: "gate2f", value: functionValue("gate2f") },
        ],
      },
      {
        declarations: [{ kind: "var", name: "gate2y" }],
        steps: [{ op: "assign", name: "gate2y", value: 4, completion: EMPTY }],
      },
      { steps: [{ op: "read", name: "gate2y" }] },
    ],
  }),
  Object.freeze({
    id: "lexical-and-class-mutation",
    sources: [
      "let gate2l = 5;",
      "gate2l += 3;",
      "class Gate2K {}",
      'Gate2K = "done";',
      'gate2l + ":" + Gate2K;',
    ],
    classifierInputs: [
      { declarations: [{ kind: "let", name: "gate2l" }] },
      { analysis: { referencedNames: ["gate2l"] } },
      { declarations: [{ kind: "class", name: "Gate2K" }] },
      { analysis: { referencedNames: ["Gate2K"] } },
      { analysis: { referencedNames: ["gate2l", "Gate2K"] } },
    ],
    modelInputs: [
      {
        declarations: [{ kind: "let", name: "gate2l" }],
        steps: [{ op: "initialize", name: "gate2l", value: 5 }],
      },
      { steps: [{ op: "assign", name: "gate2l", value: 8 }] },
      {
        declarations: [{ kind: "class", name: "Gate2K" }],
        steps: [
          {
            op: "initialize",
            name: "Gate2K",
            value: { $sessionValue: "class", name: "Gate2K" },
          },
        ],
      },
      { steps: [{ op: "assign", name: "Gate2K", value: "done" }] },
      { steps: [{ op: "complete", value: "8:done" }] },
    ],
  }),
  Object.freeze({
    id: "successful-destructuring",
    sources: [
      "let [gate2d1, gate2d2] = [1, 2];",
      "gate2d1 + gate2d2;",
    ],
    classifierInputs: [
      {
        declarations: [
          { kind: "let", name: "gate2d1" },
          { kind: "let", name: "gate2d2" },
        ],
      },
      { analysis: { referencedNames: ["gate2d1", "gate2d2"] } },
    ],
    modelInputs: [
      {
        declarations: [
          { kind: "let", name: "gate2d1" },
          { kind: "let", name: "gate2d2" },
        ],
        steps: [
          { op: "initialize", name: "gate2d1", value: 1 },
          { op: "initialize", name: "gate2d2", value: 2 },
        ],
      },
      { steps: [{ op: "complete", value: 3 }] },
    ],
  }),
]);

function metadataObservation(observation, names) {
  const declarativeRecord = Object.fromEntries(
    Object.entries(observation.declarativeRecord).map(([name, cell]) => [
      name,
      { kind: cell.kind, initialized: cell.initialized },
    ]),
  );
  const own = Object.fromEntries(
    Object.entries(observation.objectRecord.own)
      .filter(([name]) => names.includes(name))
      .map(([name, descriptor]) => [
        name,
        descriptor.type === "data"
          ? {
              type: "data",
              writable: descriptor.writable,
              enumerable: descriptor.enumerable,
              configurable: descriptor.configurable,
            }
          : {
              type: "accessor",
              hasGetter: descriptor.getter !== undefined,
              hasSetter: descriptor.setter !== undefined,
              enumerable: descriptor.enumerable,
              configurable: descriptor.configurable,
            },
      ]),
  );
  return {
    declarativeRecord,
    varDeclaredNames: observation.varDeclaredNames,
    sessionCreatedVars: observation.sessionCreatedVars,
    own,
  };
}

function modelValue(value) {
  if (value && value.$sessionValue === "empty") return { outcome: "empty" };
  if (value && value.$sessionValue) {
    return { outcome: "value", symbolic: value.$sessionValue };
  }
  return { outcome: "value", value };
}

export function restrictedEngineObservations() {
  return ENGINE_RESTRICTED_CASES.map((testCase) => {
    const exclusions = restrictedClassExclusions({ inputs: testCase.classifierInputs });
    if (exclusions.length !== 0) {
      throw new Error(`${testCase.id}: restricted-class exclusions: ${exclusions.join(", ")}`);
    }
    const model = new SessionSemanticsModel();
    let completion = EMPTY;
    for (const input of testCase.modelInputs) {
      const result = model.evaluateInput(input);
      if (result.outcome !== "success") {
        throw new Error(`${testCase.id}: model input failed: ${JSON.stringify(result)}`);
      }
      if (!(result.completion && result.completion.$sessionValue === "empty")) {
        completion = result.completion;
      }
    }
    const names = [
      "$_",
      ...new Set(
        testCase.modelInputs.flatMap((input) =>
          (input.declarations ?? []).map(({ name }) => name),
        ),
      ),
    ].sort();
    return {
      id: testCase.id,
      sources: testCase.sources,
      growingSource: testCase.sources.join("\n"),
      requestedOwnNames: names,
      expectedMetadata: metadataObservation(model.observe(), names),
      expectedCompletion: modelValue(completion),
    };
  });
}

function loadOwnerQuirks() {
  if (!fs.existsSync(QUIRK_PATH)) return new Map();
  const document = JSON.parse(fs.readFileSync(QUIRK_PATH, "utf8"));
  if (document.schema !== "ibex/session-semantics-engine-quirks/1") {
    throw new Error(`unrecognized quirk schema in ${path.relative(repoRoot, QUIRK_PATH)}`);
  }
  const rows = new Map();
  for (const row of document.quirks ?? []) {
    if (!row.id || rows.has(row.id) || row.standards === undefined || row.model === undefined) {
      throw new Error(`invalid or duplicate owner-authored quirk row ${JSON.stringify(row)}`);
    }
    rows.set(row.id, row);
  }
  return rows;
}

export function runStandardsCorrectnessGate() {
  const quirks = loadOwnerQuirks();
  const observed = [];
  for (const probe of STANDARDS_PROBES) {
    const standards = runStandardsProbe(probe);
    const model = runModelStandardsProbe(probe);
    if (JSON.stringify(standards) !== JSON.stringify(probe.expected)) {
      throw new Error(`${probe.id}: standards output drifted: ${JSON.stringify(standards)}`);
    }
    const matches = JSON.stringify(standards) === JSON.stringify(model);
    const quirk = quirks.get(probe.id);
    if (probe.relation === "matches-model" && !matches) {
      if (!quirk || JSON.stringify(quirk.standards) !== JSON.stringify(standards) ||
          JSON.stringify(quirk.model) !== JSON.stringify(model)) {
        throw new Error(`${probe.id}: unfiltered standards/model divergence`);
      }
      quirks.delete(probe.id);
    } else if (probe.relation === "expected-deviation") {
      if (!probe.deviation || matches) {
        throw new Error(`${probe.id}: malformed or no-longer-observed expected deviation`);
      }
      if (quirk) {
        throw new Error(`${probe.id}: expected deviations must not be duplicated as quirks`);
      }
    } else if (quirk) {
      throw new Error(`${probe.id}: stale quirk now matches the standards engine`);
    }
    observed.push({ id: probe.id, relation: probe.relation, standards, model });
  }
  if (quirks.size !== 0) {
    throw new Error(`quirk file contains unknown/stale rows: ${[...quirks.keys()].join(", ")}`);
  }
  return { freshRealm: "node-subprocess-per-probe", quirkFilePresent: fs.existsSync(QUIRK_PATH), observed };
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  if (process.argv.includes("--emit-restricted")) {
    process.stdout.write(`${JSON.stringify(restrictedEngineObservations())}\n`);
  } else if (process.argv.includes("--run-standards")) {
    process.stdout.write(`${JSON.stringify(runStandardsCorrectnessGate())}\n`);
  } else {
    throw new Error("expected --emit-restricted or --run-standards");
  }
}
