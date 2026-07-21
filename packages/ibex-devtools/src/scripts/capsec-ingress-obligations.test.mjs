// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry — the
// authenticated session-submit edge has checked mechanism obligations rather
// than relying on its non-capability rationale string.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import {
  REQUIRED_AUTHENTICATED_INGRESS_ROUTES,
  REQUIRED_INGRESS_OBLIGATIONS,
  REQUIRED_INGRESS_ROW_PROFILES,
  validateIngressObligationDataset,
} from "./capsec-ingress-obligations.mjs";
import { capsecRoot, readJsonStrict, repoRoot } from "./capsec-contract.mjs";

function loadDataset() {
  return readJsonStrict(
    path.join(capsecRoot, "registry", "ingress-obligations.json"),
  );
}

function coverageFor(dataset) {
  const supportingEdges = dataset.supportingSurfaces.map(
    ({ role: _role, edgeId, ...row }) => ({
      id: edgeId,
      ...row,
      rationale: "test supporting-surface rationale",
    }),
  );
  const ingressEdges = dataset.rows.map((row) => ({
    id: row.edgeId,
    classification: "non-capability",
    surface: structuredClone(row.surface),
    rationaleId: dataset.rationaleId,
    rationale: "test authenticated-code-ingress rationale",
  }));
  return { edges: [...supportingEdges, ...ingressEdges] };
}

function copyEvidenceTree(dataset) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-ingress-evidence-"));
  const sourcePaths = new Set(
    dataset.obligations.flatMap((obligation) =>
      obligation.sourceEvidence.map((evidence) => evidence.path),
    ),
  );
  for (const relativePath of sourcePaths) {
    const destination = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(repoRoot, relativePath), destination);
  }
  return root;
}

describe("LLP 0022 authenticated ingress obligations", () => {
  test("the source dataset validates against its strict schema", () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    ajv.addSchema(
      readJsonStrict(path.join(capsecRoot, "schema", "common.schema.json")),
    );
    const validate = ajv.compile(
      readJsonStrict(
        path.join(capsecRoot, "schema", "ingress-obligations.schema.json"),
      ),
    );
    const dataset = loadDataset();
    expect(validate(dataset)).toBe(true);
    expect(validate({ ...dataset, unexpected: true })).toBe(false);
  });

  test("joins every authenticated route to its exact source-backed profile", () => {
    const dataset = loadDataset();
    expect(
      validateIngressObligationDataset({
        coverage: coverageFor(dataset),
        dataset,
        repoRoot,
      }),
    ).toEqual({
      ingressEdges: 10,
      obligations: REQUIRED_INGRESS_OBLIGATIONS.length,
      sourceAssertions: 41,
      supportingSurfaces: 6,
    });
    expect(Object.keys(REQUIRED_INGRESS_ROW_PROFILES).sort()).toEqual([
      "cli:authenticated-direct-file-ingress",
      "cli:authenticated-one-shot-ingress",
      "cli:authenticated-program-stdin-ingress",
      "cli:authenticated-repl-ingress",
      "cli:implicit-no-file-dispatch",
      "cli:repl-command:load",
      "cli:repl-command:time",
      "host-abi:ex_hermes_eval_lowered_session",
      "host-abi:ex_hermes_eval_structured_session",
      "host-abi:ex_hermes_structured_module_graph_begin",
    ]);
    expect(REQUIRED_AUTHENTICATED_INGRESS_ROUTES).toEqual(
      Object.keys(REQUIRED_INGRESS_ROW_PROFILES).sort(),
    );
    expect(
      REQUIRED_INGRESS_ROW_PROFILES["cli:authenticated-direct-file-ingress"],
    ).toEqual(
      expect.arrayContaining([
        "checked-native-module-graph",
        "checked-session-lowering",
        "file-argv-bound",
        "file-program-adapter-bound",
        "file-vfs-source-bound",
      ]),
    );
    expect(
      REQUIRED_INGRESS_ROW_PROFILES[
        "cli:authenticated-direct-file-ingress"
      ],
    ).not.toContain("synthetic-source-label-derived");
  });

  test("rejects a required route omitted from both coverage and the dataset", () => {
    const dataset = loadDataset();
    dataset.rows = dataset.rows.filter(
      (row) => row.surface.name !== "authenticated-direct-file-ingress",
    );
    expect(() =>
      validateIngressObligationDataset({
        coverage: coverageFor(dataset),
        dataset,
        repoRoot,
      }),
    ).toThrow(/required authenticated ingress routes/);
  });

  test("load evidence pins the positive canonical route match", () => {
    const dataset = loadDataset();
    const load = dataset.obligations.find(
      (obligation) => obligation.id === "load-vfs-source-bound",
    );
    const host = load.sourceEvidence.find(
      (evidence) => evidence.path === "src/host/mod.rs",
    );
    expect(host.tokens).toContain(
      "submission.is_canonical_load_for(namespace.virtual_path())",
    );
    expect(host.tokens).not.toContain(
      "if !submission.is_canonical_load_for(namespace.virtual_path()) {",
    );
    expect(() =>
      validateIngressObligationDataset({
        coverage: coverageFor(dataset),
        dataset,
        repoRoot,
      }),
    ).not.toThrow();
  });

  test("rejects an uncovered authenticated-code-ingress edge", () => {
    const dataset = loadDataset();
    const coverage = coverageFor(dataset);
    coverage.edges.push({
      id: "surface.cli.future.dispatch.0000000",
      classification: "non-capability",
      surface: { kind: "host-abi", name: "future_dispatch" },
      rationaleId: dataset.rationaleId,
      rationale: "not yet implemented",
    });
    expect(() =>
      validateIngressObligationDataset({ coverage, dataset, repoRoot }),
    ).toThrow(/required authenticated ingress routes/);
  });

  test("rejects an obligation omitted from the session-submit row", () => {
    const dataset = loadDataset();
    dataset.rows[0].obligationIds.pop();
    expect(() =>
      validateIngressObligationDataset({
        coverage: coverageFor(dataset),
        dataset,
        repoRoot,
      }),
    ).toThrow(/obligation coverage/);
  });

  test("rejects a route claiming an obligation outside its exact profile", () => {
    const dataset = loadDataset();
    const raw = dataset.rows.find(
      (row) => row.surface.name === "ex_hermes_eval_structured_session",
    );
    raw.obligationIds.splice(2, 0, "checked-session-lowering");
    expect(() =>
      validateIngressObligationDataset({
        coverage: coverageFor(dataset),
        dataset,
        repoRoot,
      }),
    ).toThrow(/obligation coverage/);
  });

  test("rejects a coverage-joined authenticated route without a reviewed profile", () => {
    const dataset = loadDataset();
    dataset.rows[0].surface = {
      kind: "cli",
      name: "repl-command:future-ingress",
    };
    expect(() =>
      validateIngressObligationDataset({
        coverage: coverageFor(dataset),
        dataset,
        repoRoot,
      }),
    ).toThrow(/required authenticated ingress routes/);
  });

  test("rejects a supporting surface whose classification drifts", () => {
    const dataset = loadDataset();
    const coverage = coverageFor(dataset);
    const binding = coverage.edges.find(
      (edge) => edge.surface.name === "ex_hermes_structured_session_bind",
    );
    binding.classification = "closed";
    binding.cap = "vm:evaluate";
    delete binding.rationaleId;
    expect(() =>
      validateIngressObligationDataset({ coverage, dataset, repoRoot }),
    ).toThrow(/expected classification non-capability, got closed/);
  });

  test("rejects source drift under a reviewed evidence token", () => {
    const dataset = loadDataset();
    const evidenceRoot = copyEvidenceTree(dataset);
    try {
      const runtimePath = path.join(evidenceRoot, "src/engine/hermes_runtime.cc");
      const source = fs.readFileSync(runtimePath, "utf8");
      fs.writeFileSync(
        runtimePath,
        source.replaceAll(
          "EX_HERMES_EVAL_FAULT_SUBMISSION_REPLAY",
          "EX_HERMES_EVAL_FAULT_REPLAY_REMOVED",
        ),
      );
      expect(() =>
        validateIngressObligationDataset({
          coverage: coverageFor(dataset),
          dataset,
          repoRoot: evidenceRoot,
        }),
      ).toThrow(/reviewed source range .* digest/);
    } finally {
      fs.rmSync(evidenceRoot, { recursive: true, force: true });
    }
  });

  test("accepts CRLF source checkouts without weakening reviewed bytes", () => {
    const dataset = loadDataset();
    const evidenceRoot = copyEvidenceTree(dataset);
    try {
      const sourcePaths = new Set(
        dataset.obligations.flatMap((obligation) =>
          obligation.sourceEvidence.map((evidence) => evidence.path),
        ),
      );
      for (const relativePath of sourcePaths) {
        const sourcePath = path.join(evidenceRoot, relativePath);
        const source = fs.readFileSync(sourcePath, "utf8");
        fs.writeFileSync(sourcePath, source.replace(/(?<!\r)\n/gu, "\r\n"));
      }

      expect(() =>
        validateIngressObligationDataset({
          coverage: coverageFor(dataset),
          dataset,
          repoRoot: evidenceRoot,
        }),
      ).not.toThrow();
    } finally {
      fs.rmSync(evidenceRoot, { recursive: true, force: true });
    }
  });

  test("rejects a token-preserving dead-code mutation in reviewed enforcement", () => {
    const dataset = loadDataset();
    const evidenceRoot = copyEvidenceTree(dataset);
    try {
      const runtimePath = path.join(evidenceRoot, "src/engine/hermes_runtime.cc");
      const source = fs.readFileSync(runtimePath, "utf8");
      const replayBranch = [
        "  if (credential->ordinal < expected_ordinal) {",
        "    structuredFault(result, EX_HERMES_EVAL_FAULT_SUBMISSION_REPLAY);",
        "    return 0;",
        "  }",
      ].join("\n");
      const deadReplayBranch = [
        "  if (false) {",
        "    if (credential->ordinal < expected_ordinal) {",
        "      structuredFault(result, EX_HERMES_EVAL_FAULT_SUBMISSION_REPLAY);",
        "      return 0;",
        "    }",
        "  }",
      ].join("\n");
      expect(source).toContain(replayBranch);
      const mutated = source.replace(replayBranch, deadReplayBranch);
      const replayEvidence = dataset.obligations
        .find((obligation) => obligation.id === "replay-refused")
        .sourceEvidence.find(
          (evidence) => evidence.path === "src/engine/hermes_runtime.cc",
        );
      for (const token of replayEvidence.tokens) {
        expect(mutated).toContain(token);
      }
      fs.writeFileSync(runtimePath, mutated);

      expect(() =>
        validateIngressObligationDataset({
          coverage: coverageFor(dataset),
          dataset,
          repoRoot: evidenceRoot,
        }),
      ).toThrow(/reviewed source range .*structured-session-ingress.* digest/);
    } finally {
      fs.rmSync(evidenceRoot, { recursive: true, force: true });
    }
  });
});
