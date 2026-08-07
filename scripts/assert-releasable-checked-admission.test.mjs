import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  auditReleaseGateCallers,
  RAW_RELEASE_EXCLUSION,
  RELEASE_GATE_EXCLUSIONS,
  validateReleasableCheckedAdmission,
} from "./assert-releasable-checked-admission.mjs";
import { canonicalJson, semanticDigest } from "./portable-engine-contract.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vectorPath = path.join(repoRoot, "schemas/vectors/portable-engine-promotion-admission-v2.valid.json");
const vectors = JSON.parse(fs.readFileSync(vectorPath, "utf8"));
const temporaryRoots = new Set();

afterEach(async () => {
  for (const root of temporaryRoots) await fsp.rm(root, { recursive: true, force: true });
  temporaryRoots.clear();
});

function bytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function rebound(value) {
  const copy = structuredClone(value);
  copy.verificationDigest = semanticDigest(
    "ibex.portable-engine-checked-promotion-admission.v2",
    copy,
    ["verificationDigest"],
  );
  return copy;
}

async function callerAuditFixture() {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "ibex-release-gate-"));
  temporaryRoots.add(root);
  await fsp.mkdir(path.join(root, ".github/workflows"), { recursive: true });
  for (const exclusion of RELEASE_GATE_EXCLUSIONS) {
    const destination = path.join(root, exclusion.path);
    await fsp.mkdir(path.dirname(destination), { recursive: true });
    await fsp.copyFile(path.join(repoRoot, exclusion.path), destination);
  }
  await fsp.writeFile(path.join(root, "package.json"), "{\"scripts\":{}}\n");
  await fsp.writeFile(path.join(root, "Cargo.toml"), "[package]\nname = \"ibex-runtime\"\nversion = \"0.0.0\"\n");
  return root;
}

test("M33 accepts only a digest-valid authorized /2 admission with an admitted scope", () => {
  const accepted = validateReleasableCheckedAdmission(bytes(vectors.checkedAuthorized));
  assert.equal(accepted.authorized, true);
  assert.equal(accepted.admittedScopeDigest, vectors.checkedAuthorized.admittedScopeDigest);

  assert.throws(
    () => validateReleasableCheckedAdmission(bytes(vectors.checkedDiagnostic)),
    /not authorized/u,
  );
  const nullScope = rebound({ ...vectors.checkedAuthorized, admittedScopeDigest: null });
  assert.throws(
    () => validateReleasableCheckedAdmission(bytes(nullScope)),
    /admittedScopeDigest is null or malformed/u,
  );
  const badDigest = { ...vectors.checkedAuthorized, verificationDigest: vectors.checkedDiagnostic.verificationDigest };
  assert.throws(
    () => validateReleasableCheckedAdmission(bytes(badDigest)),
    /verification digest mismatch/u,
  );
  assert.throws(
    () => validateReleasableCheckedAdmission(Buffer.from(`${JSON.stringify(vectors.checkedAuthorized, null, 2)}\n`, "utf8")),
    /canonical JSON plus one LF/u,
  );
});

test("F6h-a the command refuses a reset admission rather than merely producing an unarmed binary", async () => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "ibex-release-admission-"));
  temporaryRoots.add(root);
  const admissionPath = path.join(root, "portable_engine_promotion_admission.json");
  await fsp.writeFile(admissionPath, bytes(vectors.checkedDiagnostic));
  const result = spawnSync(process.execPath, [
    path.join(repoRoot, "scripts/assert-releasable-checked-admission.mjs"),
    "--admission",
    admissionPath,
  ], { cwd: repoRoot, encoding: "utf8" });
  assert.notEqual(result.status, 0, result.stdout);
  assert.match(result.stderr, /product release refused/u);
});

test("F6h-b both artifact-source ceremonies remain explicitly outside the product gate", () => {
  const audit = auditReleaseGateCallers(repoRoot);
  assert.deepEqual(audit.excludedCeremonies, [
    ".github/workflows/hermes-artifacts.yml",
    ".github/workflows/portable-engine-physical-promotion.yml",
  ]);
  for (const relativePath of audit.excludedCeremonies) {
    const text = fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
    assert.doesNotMatch(text, /assert-releasable-checked-admission\.mjs --admission/u);
  }
});

test("F6h-c the shared command audit rejects every newly added ungated product publisher", async () => {
  const root = await callerAuditFixture();
  await fsp.writeFile(path.join(root, ".github/workflows/product-release.yml"), [
    "name: Product release",
    "on: workflow_dispatch",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - run: cargo publish",
    "",
  ].join("\n"));
  assert.throws(
    () => auditReleaseGateCallers(root),
    /does not invoke the shared checked-admission gate/u,
  );

  await fsp.writeFile(path.join(root, ".github/workflows/product-release.yml"), [
    "name: Product release",
    "on: workflow_dispatch",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - run: node scripts/assert-releasable-checked-admission.mjs --admission target/release/build/ibex/out/portable_engine_promotion_admission.json",
    "      - run: cargo publish",
    "",
  ].join("\n"));
  const audit = auditReleaseGateCallers(root);
  assert.deepEqual(audit.gated, [".github/workflows/product-release.yml"]);
  assert.equal(audit.gateCommand, "node scripts/assert-releasable-checked-admission.mjs --admission");

  await fsp.mkdir(path.join(root, "scripts"));
  await fsp.writeFile(path.join(root, "scripts/publish.sh"), "#!/bin/sh\ncargo publish\n");
  assert.throws(
    () => auditReleaseGateCallers(root),
    /publisher script.*does not invoke the shared checked-admission gate/u,
  );
  await fsp.writeFile(
    path.join(root, "scripts/publish.sh"),
    "#!/bin/sh\nnode scripts/assert-releasable-checked-admission.mjs --admission target/release/build/ibex/out/portable_engine_promotion_admission.json\ncargo publish\n",
  );
  assert.deepEqual(auditReleaseGateCallers(root).gated, [
    ".github/workflows/product-release.yml",
    "scripts/publish.sh",
  ]);
});

test("raw product tags and direct cargo publication are explicit fail-closed exclusions", () => {
  assert.match(RAW_RELEASE_EXCLUSION.productTags, /forbidden.*enumerated gated workflow/u);
  assert.match(RAW_RELEASE_EXCLUSION.packageRegistries, /forbidden.*enumerated gated workflow/u);
  assert.match(RAW_RELEASE_EXCLUSION.nonProductTags, /explicitly excluded ceremony workflow/u);
});
