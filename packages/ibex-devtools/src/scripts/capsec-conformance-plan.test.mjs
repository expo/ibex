import fs from "node:fs";
import path from "node:path";
import { expect, test } from "bun:test";
import {
  bindConformanceSuitePlan,
  commandPolicyFor,
  criticalPathBudget,
  readConformanceSuitePlan,
  validateConformanceSuitePlan,
} from "./capsec-conformance-plan.mjs";
import { commandEvidenceIdSuffix } from "./capsec-command-evidence.mjs";
import {
  CONFORMANCE_PREFLIGHT_COMMANDS,
  CONFORMANCE_PRODUCT_COMMANDS,
} from "./capsec-conformance-matrix.mjs";
import { canonicalJson } from "./capsec-contract.mjs";
import { PUBLIC_SURFACE_EXECUTOR_DESCRIPTORS } from "./capsec-public-executors.mjs";

test("the authored target budgets fit their outer job timeouts", () => {
  const plan = readConformanceSuitePlan();
  expect(plan.timeoutPolicyVersion).toBe(5);
  for (const target of Object.keys(plan.targets)) {
    const budget = criticalPathBudget(plan, target);
    expect(budget.totalMs).toBe(22_440_000);
    expect(budget.totalMs).toBeLessThanOrEqual(
      plan.targets[target].outerTimeoutMs,
    );
  }
  expect(
    commandPolicyFor(
      plan,
      "x86_64-pc-windows-msvc",
      "all-generated-drift",
    ).deadlineMs,
  ).toBe(300_000);
  expect(
    commandPolicyFor(
      plan,
      "aarch64-apple-darwin",
      "public-fixtures-002-deadbeef",
    ).deadlineMs,
  ).toBe(300_000);
  const noncapCommand = PUBLIC_SURFACE_EXECUTOR_DESCRIPTORS.find(
    ({ testName }) => testName === "capsec_public_noncap_builtin_recipe_batch",
  ).command;
  const windowsNoncapBatchId = `public-fixtures-005-${commandEvidenceIdSuffix(
    Buffer.from(canonicalJson(noncapCommand), "utf8"),
  )}`;
  expect(windowsNoncapBatchId).toBe(
    "public-fixtures-005-d0b17e51064234a80cd89dc1c8f4a2f2fbedab33b08f7d065b33f5926cfe3d5f",
  );
  expect(
    commandPolicyFor(
      plan,
      "x86_64-pc-windows-msvc",
      windowsNoncapBatchId,
    ).deadlineMs,
  ).toBe(420_000);
  expect(
    commandPolicyFor(
      plan,
      "x86_64-pc-windows-msvc",
      "public-fixtures-004-deadbeef",
    ).deadlineMs,
  ).toBe(300_000);
  expect(
    commandPolicyFor(
      plan,
      "x86_64-pc-windows-msvc",
      "exact-loaded-engine-attestation",
    ).deadlineMs,
  ).toBe(2_700_000);
  expect(
    commandPolicyFor(
      plan,
      "x86_64-pc-windows-msvc",
      "rust-default-full",
    ).deadlineMs,
  ).toBe(2_700_000);
  expect(
    commandPolicyFor(
      plan,
      "aarch64-apple-darwin",
      "portable-public-fixtures-000-deadbeef",
    ),
  ).toEqual({
    phase: "fixture-evidence",
    deadlineMs: 90_000,
    gracePeriodMs: 30_000,
  });
  expect(
    plan.targets["aarch64-apple-darwin"].maxPublicFixtureBatches,
  ).toBe(11);
  expect(
    plan.targets["aarch64-apple-darwin"].setupReserveMs,
  ).toBe(3_480_000);
  expect(
    plan.targets["x86_64-pc-windows-msvc"].maxPublicFixtureBatches,
  ).toBe(10);
  expect(
    plan.targets["x86_64-pc-windows-msvc"]
      .maxPortablePublicFixtureBatches,
  ).toBe(0);
});

test("suite-plan bindings distinguish source, target, and engine identity", () => {
  const plan = readConformanceSuitePlan();
  const bind = (overrides = {}) =>
    bindConformanceSuitePlan({
      plan,
      sourceRevision: "revision-a",
      sourceTreeDigest: "tree-a",
      target: "aarch64-apple-darwin",
      engineArtifactDigest: "engine-a",
      ...overrides,
    }).suitePlanDigest;
  const baseline = bind();
  expect(bind()).toBe(baseline);
  expect(bind({ sourceRevision: "revision-b" })).not.toBe(baseline);
  expect(bind({ engineArtifactDigest: "engine-b" })).not.toBe(baseline);
  expect(bind({ target: "x86_64-pc-windows-msvc" })).not.toBe(baseline);
});

test("the plan covers every fixed command emitted by both suite entry points", () => {
  const plan = readConformanceSuitePlan();
  const expectedIds = new Set([
    ...CONFORMANCE_PREFLIGHT_COMMANDS.map(([id]) => id),
    ...CONFORMANCE_PRODUCT_COMMANDS.map(([id]) => id),
    "exact-loaded-engine-attestation",
    "generate-executable-recipes",
    "exact-hermes-typed-adapter-recipes",
    "exact-fixture-evidence-pilot",
    "exact-fixture-evidence-portable-pilot",
    "exact-loaded-engine-attestation-after-evidence",
    "generate-conformance-report",
    "loaded-engine-preflight",
    "loaded-intrinsic-alias-execution",
  ]);
  expect(new Set(Object.keys(plan.commands))).toEqual(expectedIds);
});

test("suite-plan validation is exact-field and fail-closed", () => {
  const plan = structuredClone(readConformanceSuitePlan());
  plan.unreviewed = true;
  expect(() => validateConformanceSuitePlan(plan)).toThrow(/exact fields/u);
});

test("suite-plan deadline overrides name fixed or exact dynamic commands", () => {
  const plan = structuredClone(readConformanceSuitePlan());
  plan.targets["x86_64-pc-windows-msvc"].deadlineOverrides[
    "unreviewed-dynamic-command"
  ] = 420_000;
  expect(() => validateConformanceSuitePlan(plan)).toThrow(
    /deadline override names unknown command/u,
  );
});

test("suite entry points spawn evidence commands only through the envelope", () => {
  const repoRoot = path.resolve(import.meta.dir, "../../../..");
  for (const relativePath of [
    "packages/ibex-devtools/src/scripts/run-capsec-conformance.mjs",
    "packages/ibex-devtools/src/scripts/run-capsec-inherited-intrinsic-alias-conformance.mjs",
  ]) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
    expect(source).not.toMatch(/execFileSync\(process\.execPath/u);
    expect(source).not.toMatch(/\bspawnSync\(/u);
    expect(source).not.toMatch(/\bspawn\(/u);
  }
});
