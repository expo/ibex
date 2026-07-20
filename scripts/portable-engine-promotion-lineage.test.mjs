import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { deflateSync } from "node:zlib";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

import {
  canonicalJson,
  parseJsonStrict,
  rawDigest,
  semanticDigest,
} from "./portable-engine-contract.mjs";
import { portableEnginePromotionLineagePlatformSupported } from "./portable-engine-promotion-lineage.mjs";

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoots = new Set();
const catalogPath = "schemas/portable-engine-promotion-admission-catalog-v1.json";
const schemaPath = "schemas/portable-engine-promotion-admission-catalog-v1.schema.json";
const checkedAdmissionSchemaPath = "schemas/portable-engine-checked-promotion-admission-v1.schema.json";
const targetAttestationPath = "capsec/conformance/target-attestations.json";
const targetAdvertisementPath = "capsec/generated/target-advertisements.json";
const targetTriple = "aarch64-apple-darwin";
const artifactId = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const admissionDomain = "ibex.portable-engine-promotion-admission.v1";
const checkedAdmissionDomain = "ibex.portable-engine-checked-promotion-admission.v1";
const gitEnvironment = Object.freeze({
  PATH: "/usr/bin:/bin",
  HOME: "/var/empty",
  XDG_CONFIG_HOME: "/var/empty",
  LC_ALL: "C",
  LANG: "C",
  GIT_CONFIG_COUNT: "0",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_NO_LAZY_FETCH: "1",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_TERMINAL_PROMPT: "0",
});

afterEach(async () => {
  for (const root of temporaryRoots) await fsp.rm(root, { recursive: true, force: true });
  temporaryRoots.clear();
});

function git(repoRoot, args, options = {}) {
  return execFileSync("/usr/bin/git", args, {
    cwd: repoRoot,
    env: gitEnvironment,
    encoding: options.encoding ?? "utf8",
    maxBuffer: 80 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function writeFile(repoRoot, relativePath, bytes) {
  const absolute = path.join(repoRoot, relativePath);
  await fsp.mkdir(path.dirname(absolute), { recursive: true });
  await fsp.writeFile(absolute, bytes, { mode: 0o644 });
}

async function copyAuthority(repoRoot, relativePath) {
  await writeFile(repoRoot, relativePath, await fsp.readFile(path.join(sourceRoot, relativePath)));
}

function indexEntry(repoRoot, relativePath) {
  const output = git(repoRoot, ["ls-files", "-s", "--", relativePath]).trim();
  const match = /^(100644|100755|120000|160000) ([0-9a-f]{40}) 0\t(.+)$/u.exec(output);
  assert(match, `missing exact index entry for ${relativePath}: ${output}`);
  assert.equal(match[3], relativePath);
  return { mode: match[1], objectId: match[2] };
}

function readIndexBytes(repoRoot, entry) {
  if (entry.mode === "160000") return null;
  return Buffer.from(git(repoRoot, ["cat-file", "blob", entry.objectId], { encoding: "buffer" }));
}

function artifactRow(repoRoot, role, relativePath, { advertisedMode = "100644" } = {}) {
  const entry = indexEntry(repoRoot, relativePath);
  const bytes = readIndexBytes(repoRoot, entry);
  return {
    role,
    path: relativePath,
    mode: advertisedMode,
    blobObjectId: entry.objectId,
    size: bytes?.length ?? 1,
    digest: bytes ? rawDigest(bytes) : `sha256-${"0".repeat(64)}`,
  };
}

async function initializeSourceRepository() {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "ibex-promotion-lineage-"));
  temporaryRoots.add(root);
  const repoRoot = path.join(root, "checkout");
  await fsp.mkdir(repoRoot);
  git(repoRoot, ["init", "--quiet", "--initial-branch=main"]);
  git(repoRoot, ["config", "user.name", "Ibex promotion test"]);
  git(repoRoot, ["config", "user.email", "ibex-promotion@example.invalid"]);
  git(repoRoot, ["config", "advice.addEmbeddedRepo", "false"]);

  for (const relativePath of [
    "scripts/portable-engine-promotion-lineage.mjs",
    "scripts/portable-engine-contract.mjs",
    "scripts/portable-engine-installer.mjs",
    "scripts/portable-engine-installer-core.mjs",
    schemaPath,
    checkedAdmissionSchemaPath,
    catalogPath,
    "schemas/portable-engine-provenance-trust-policy-v1.json",
  ]) {
    await copyAuthority(repoRoot, relativePath);
  }
  await writeFile(repoRoot, targetAttestationPath, `${JSON.stringify({
    targetAttestationSchema: "ibex/capsec-target-attestations/1",
    profile: "ibex/capsec/1",
    attestations: [],
  }, null, 2)}\n`);
  await writeFile(repoRoot, targetAdvertisementPath, `${JSON.stringify({
    targetAdvertisementSchema: "ibex/capsec-target-advertisements/1",
    profile: "ibex/capsec/1",
    targetCellsRawContentDigest: "sha256-bj5xdO8TVjq3Dkm-ZS4u9P8cLQrKwcnZg8UgrsXV6nU",
    advertisements: [],
  }, null, 2)}\n`);
  await writeFile(repoRoot, "src/source-authority.json", canonicalJson({ source: "closed" }));
  git(repoRoot, ["add", "--all"]);
  git(repoRoot, ["commit", "--quiet", "-m", "artifact source"]);
  return {
    root,
    repoRoot,
    sourceRevision: git(repoRoot, ["rev-parse", "HEAD"]).trim(),
    sourceTreeObjectId: git(repoRoot, ["show", "-s", "--format=%T", "HEAD"]).trim(),
  };
}

async function createNestedSubmodule(repoRoot, relativePath) {
  const nested = path.join(repoRoot, relativePath);
  await fsp.mkdir(nested, { recursive: true });
  git(nested, ["init", "--quiet", "--initial-branch=main"]);
  git(nested, ["config", "user.name", "Ibex promotion test"]);
  git(nested, ["config", "user.email", "ibex-promotion@example.invalid"]);
  await fsp.writeFile(path.join(nested, "payload.json"), canonicalJson({ nested: true }));
  git(nested, ["add", "payload.json"]);
  git(nested, ["commit", "--quiet", "-m", "nested"]);
  git(repoRoot, ["add", "--", relativePath]);
}

async function createPromotionRepository(options = {}) {
  const fixture = await initializeSourceRepository();
  const { repoRoot, sourceRevision, sourceTreeObjectId } = fixture;
  git(repoRoot, ["switch", "--quiet", "-c", "promotion"]);
  if (options.topicHasTwoCommits) git(repoRoot, ["commit", "--quiet", "--allow-empty", "-m", "promotion prelude"]);

  const evidenceRoot = `capsec/conformance/portable-promotions/${sourceRevision}/${targetTriple}/${artifactId}`;
  const evidencePath = `${evidenceRoot}/conformance-report.json`;
  const evidenceBytes = options.copySourceBlob
    ? await fsp.readFile(path.join(repoRoot, "src/source-authority.json"))
    : Buffer.from(canonicalJson({ conformant: true, sourceRevision }), "utf8");

  if (options.symlinkEvidence) {
    await fsp.mkdir(path.dirname(path.join(repoRoot, evidencePath)), { recursive: true });
    await fsp.symlink("conformance-report-target.json", path.join(repoRoot, evidencePath));
  } else if (options.submoduleEvidence) {
    await createNestedSubmodule(repoRoot, evidencePath);
  } else {
    await writeFile(repoRoot, evidencePath, evidenceBytes);
    if (options.executableEvidence) await fsp.chmod(path.join(repoRoot, evidencePath), 0o755);
  }
  await writeFile(repoRoot, targetAttestationPath, canonicalJson({
    targetAttestationSchema: "ibex/capsec-target-attestations/2",
    profile: "ibex/capsec/1",
    attestations: [{ sourceRevision, portableArtifactId: artifactId }],
  }));
  await writeFile(repoRoot, targetAdvertisementPath, canonicalJson({
    targetAdvertisementSchema: "ibex/capsec-target-advertisements/2",
    profile: "ibex/capsec/1",
    advertisements: [{ sourceRevision, portableArtifactId: artifactId }],
  }));

  let codeDriftPath = null;
  if (options.codeDrift || options.listedCodeDrift) {
    codeDriftPath = "src/source-authority.json";
    await writeFile(repoRoot, codeDriftPath, canonicalJson({ source: "drifted" }));
  }
  let renamedEvidencePath = null;
  if (options.renameSourceBlob) {
    renamedEvidencePath = `${evidenceRoot}/renamed-source.json`;
    await fsp.rename(path.join(repoRoot, "src/source-authority.json"), path.join(repoRoot, renamedEvidencePath));
  }
  if (options.unlistedEquivalent) {
    await writeFile(repoRoot, `${evidenceRoot}/unlisted-equivalent.json`, evidenceBytes);
  }
  const duplicateEvidencePath = `${evidenceRoot}/duplicate-evidence.json`;
  if (options.duplicateEvidence) await writeFile(repoRoot, duplicateEvidencePath, evidenceBytes);
  if (options.authorityDriftPath) {
    const absoluteAuthority = path.join(repoRoot, options.authorityDriftPath);
    await fsp.appendFile(absoluteAuthority, "\n// promotion-time authority drift\n");
  }
  git(repoRoot, ["add", "--all"]);

  const evidenceRowPath = renamedEvidencePath ?? evidencePath;
  const artifacts = [
    artifactRow(repoRoot, "conformance-evidence", evidenceRowPath),
    artifactRow(repoRoot, "target-attestation", targetAttestationPath),
    artifactRow(repoRoot, "target-advertisement", targetAdvertisementPath),
  ];
  if (options.listedCodeDrift) {
    artifacts.push(artifactRow(repoRoot, "conformance-evidence", codeDriftPath));
  }
  if (options.duplicateEvidence) {
    artifacts.push(artifactRow(repoRoot, "conformance-evidence", duplicateEvidencePath));
  }
  if (options.duplicateArtifactRow) artifacts.push({ ...artifacts[0] });
  artifacts.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));

  const admission = {
    schema: "ibex/portable-engine-promotion-admission/1",
    sourceRevision,
    sourceTreeObjectId,
    topology: "github-pull-request-merge/direct-single-commit-topic/1",
    targetTriple,
    portableArtifactId: artifactId,
    artifacts,
    admissionDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
  options.mutateAdmission?.(admission);
  admission.admissionDigest = semanticDigest(admissionDomain, admission, ["admissionDigest"]);
  if (options.corruptAdmissionDigest) admission.admissionDigest = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
  const catalog = {
    admissionPath: catalogPath,
    admissions: [admission],
    enabled: true,
    schema: "ibex/portable-engine-promotion-admission-catalog/1",
  };
  options.mutateCatalog?.(catalog);
  const catalogBytes = `${canonicalJson(catalog)}\n`;
  if (options.catalogSymlink) {
    const target = "promotion-catalog-symlink-target.json";
    await writeFile(repoRoot, `schemas/${target}`, catalogBytes);
    await fsp.unlink(path.join(repoRoot, catalogPath));
    await fsp.symlink(target, path.join(repoRoot, catalogPath));
  } else if (options.catalogSubmodule) {
    await fsp.unlink(path.join(repoRoot, catalogPath));
    await createNestedSubmodule(repoRoot, catalogPath);
  } else {
    await writeFile(repoRoot, catalogPath, catalogBytes);
  }
  git(repoRoot, ["add", "--all"]);
  git(repoRoot, ["commit", "--quiet", "-m", "review portable promotion"]);
  const promotionTopicRevision = git(repoRoot, ["rev-parse", "HEAD"]).trim();

  if (options.fastForward) {
    git(repoRoot, ["switch", "--quiet", "main"]);
    git(repoRoot, ["merge", "--quiet", "--ff-only", "promotion"]);
  } else {
    git(repoRoot, ["switch", "--quiet", "main"]);
    if (options.firstParentDrift) git(repoRoot, ["commit", "--quiet", "--allow-empty", "-m", "main moved"]);
    if (options.mergeTreeDrift) {
      git(repoRoot, ["merge", "--quiet", "--no-ff", "--no-commit", "promotion"]);
      await writeFile(repoRoot, "merge-only.json", canonicalJson({ forbidden: "merge drift" }));
      git(repoRoot, ["add", "merge-only.json"]);
      git(repoRoot, ["commit", "--quiet", "-m", "merge promotion with drift"]);
    } else {
      git(repoRoot, ["merge", "--quiet", "--no-ff", "-m", "merge promotion", "promotion"]);
    }
  }
  const promotionMergeRevision = git(repoRoot, ["rev-parse", "HEAD"]).trim();
  if (options.laterDescendant) {
    git(repoRoot, ["commit", "--quiet", "--allow-empty", "-m", "later descendant"]);
  }
  return {
    ...fixture,
    evidencePath,
    evidenceObjectId: indexEntry(repoRoot, evidencePath).objectId,
    promotionTopicRevision,
    promotionMergeRevision,
  };
}

function runVerifier(repoRoot) {
  const script = path.join(repoRoot, "scripts/portable-engine-promotion-lineage.mjs");
  const result = spawnSync(process.execPath, [script], {
    cwd: repoRoot,
    env: Object.fromEntries(Object.entries(process.env).filter(([name]) => !["NODE_OPTIONS", "NODE_PATH"].includes(name))),
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 30_000,
  });
  return result;
}

function verifiedResult(repoRoot) {
  const result = runVerifier(repoRoot);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function assertVerifierRefuses(repoRoot, pattern) {
  const result = runVerifier(repoRoot);
  assert.notEqual(result.status, 0, `verifier unexpectedly accepted: ${result.stdout}`);
  assert.match(result.stderr, pattern);
}

function runCheckedAdmission(repoRoot, selection) {
  const program = [
    "import { verifyPortableEngineCheckoutAdmission } from './scripts/portable-engine-installer.mjs';",
    "const selection = JSON.parse(process.env.IBEX_TEST_PROMOTION_SELECTION);",
    "process.stdout.write(`${JSON.stringify(verifyPortableEngineCheckoutAdmission(selection))}\\n`);",
  ].join("\n");
  return spawnSync(process.execPath, ["--input-type=module", "--eval", program], {
    cwd: repoRoot,
    env: {
      ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !["NODE_OPTIONS", "NODE_PATH"].includes(name))),
      IBEX_TEST_PROMOTION_SELECTION: JSON.stringify({ repoRoot, ...selection }),
    },
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 30_000,
  });
}

function checkedAdmissionResult(repoRoot, selection = {}) {
  const result = runCheckedAdmission(repoRoot, {
    expectedSourceRevision: selection.expectedSourceRevision,
    artifactId: selection.artifactId ?? artifactId,
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function assertCheckedAdmissionRefuses(repoRoot, selection, pattern) {
  const result = runCheckedAdmission(repoRoot, selection);
  assert.notEqual(result.status, 0, `checked admission unexpectedly accepted: ${result.stdout}`);
  assert.match(result.stderr, pattern);
}

describe("portable engine promotion admission schema and foundation", () => {
  test("the production trust adapter is explicitly Darwin-only", () => {
    assert.equal(portableEnginePromotionLineagePlatformSupported("darwin"), true);
    assert.equal(portableEnginePromotionLineagePlatformSupported("linux"), false);
    assert.equal(portableEnginePromotionLineagePlatformSupported("win32"), false);
  });

  test("disabled checked catalog grants no authority and active vectors are schema-valid mechanics only", () => {
    const schema = JSON.parse(fs.readFileSync(path.join(sourceRoot, schemaPath), "utf8"));
    const vectors = JSON.parse(fs.readFileSync(path.join(sourceRoot, "schemas/vectors/portable-engine-promotion-admission-v1.valid.json"), "utf8"));
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    assert.equal(validate(vectors.disabledCatalog), true, JSON.stringify(validate.errors));
    assert.equal(validate(vectors.activeCatalog), true, JSON.stringify(validate.errors));
    assert.equal(
      semanticDigest(admissionDomain, vectors.activeCatalog.admissions[0], ["admissionDigest"]),
      vectors.activeCatalog.admissions[0].admissionDigest,
    );

    const foundationBytes = fs.readFileSync(path.join(sourceRoot, catalogPath));
    const foundation = parseJsonStrict(foundationBytes, "checked promotion foundation");
    assert.equal(foundationBytes.toString("utf8"), `${canonicalJson(foundation)}\n`);
    assert.deepEqual(foundation, vectors.disabledCatalog);
    assert.equal(foundation.enabled, false);
    assert.deepEqual(foundation.admissions, []);

    const policy = JSON.parse(fs.readFileSync(path.join(sourceRoot, "schemas/portable-engine-provenance-trust-policy-v1.json"), "utf8"));
    const attestations = JSON.parse(fs.readFileSync(path.join(sourceRoot, targetAttestationPath), "utf8"));
    const advertisements = JSON.parse(fs.readFileSync(path.join(sourceRoot, targetAdvertisementPath), "utf8"));
    assert.equal(policy.portableArtifactAcceptanceEnabled, false);
    assert.deepEqual(attestations.attestations, []);
    assert.deepEqual(advertisements.advertisements, []);
  });

  test("schema rejects a disabled nonempty catalog and an active empty catalog", () => {
    const schema = JSON.parse(fs.readFileSync(path.join(sourceRoot, schemaPath), "utf8"));
    const vectors = JSON.parse(fs.readFileSync(path.join(sourceRoot, "schemas/vectors/portable-engine-promotion-admission-v1.valid.json"), "utf8"));
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    assert.equal(validate({ ...vectors.activeCatalog, enabled: false }), false);
    assert.equal(validate({ ...vectors.disabledCatalog, enabled: true }), false);
  });

  test("checked admission schema freezes one common A/C result shape", () => {
    const schema = JSON.parse(fs.readFileSync(path.join(sourceRoot, checkedAdmissionSchemaPath), "utf8"));
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    const diagnostic = {
      schema: "ibex/portable-engine-checked-promotion-admission/1",
      authorized: false,
      currentRevision: "a".repeat(40),
      sourceRevision: "a".repeat(40),
      promotionTopicRevision: null,
      sourceTreeObjectId: null,
      targetTriple,
      portableArtifactId: artifactId,
      admissionDigest: null,
      verificationDigest: artifactId,
    };
    assert.equal(validate(diagnostic), true, JSON.stringify(validate.errors));
    assert.equal(validate({ ...diagnostic, authorized: true }), false);
    assert.equal(validate({ ...diagnostic, note: "open field" }), false);
  });
});

describe("portable engine checked Git promotion lineage", { skip: process.platform !== "darwin" }, () => {
  test("source A stays disabled while its exact one-commit PR merge C verifies", async () => {
    const fixture = await createPromotionRepository();
    const result = verifiedResult(fixture.repoRoot);
    assert.equal(result.authorized, true);
    assert.equal(result.sourceRevision, fixture.sourceRevision);
    assert.equal(result.promotionTopicRevision, fixture.promotionTopicRevision);
    assert.equal(result.currentRevision, fixture.promotionMergeRevision);
    assert.equal(result.portableArtifactId, artifactId);

    git(fixture.repoRoot, ["switch", "--quiet", "--detach", fixture.sourceRevision]);
    const sourceResult = verifiedResult(fixture.repoRoot);
    assert.equal(sourceResult.authorized, false);
    assert.equal(sourceResult.admission, null);
  });

  test("the production checked selection binds source A and exact merge C separately", async () => {
    const fixture = await createPromotionRepository();
    const promoted = checkedAdmissionResult(fixture.repoRoot, { expectedSourceRevision: fixture.sourceRevision });
    assert.deepEqual(Object.keys(promoted).sort(), [
      "schema",
      "authorized",
      "currentRevision",
      "sourceRevision",
      "promotionTopicRevision",
      "sourceTreeObjectId",
      "targetTriple",
      "portableArtifactId",
      "admissionDigest",
      "verificationDigest",
    ].sort());
    assert.equal(promoted.authorized, true);
    assert.equal(promoted.currentRevision, fixture.promotionMergeRevision);
    assert.equal(promoted.sourceRevision, fixture.sourceRevision);
    assert.equal(promoted.promotionTopicRevision, fixture.promotionTopicRevision);
    assert.equal(promoted.sourceTreeObjectId, fixture.sourceTreeObjectId);
    assert.equal(promoted.targetTriple, targetTriple);
    assert.equal(promoted.portableArtifactId, artifactId);
    assert.equal(
      promoted.verificationDigest,
      semanticDigest(checkedAdmissionDomain, promoted, ["verificationDigest"]),
    );
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(
      JSON.parse(fs.readFileSync(path.join(sourceRoot, checkedAdmissionSchemaPath), "utf8")),
    );
    assert.equal(validate(promoted), true, JSON.stringify(validate.errors));

    git(fixture.repoRoot, ["switch", "--quiet", "--detach", fixture.sourceRevision]);
    const diagnostic = checkedAdmissionResult(fixture.repoRoot, { expectedSourceRevision: fixture.sourceRevision });
    assert.equal(diagnostic.authorized, false);
    assert.equal(diagnostic.currentRevision, fixture.sourceRevision);
    assert.equal(diagnostic.sourceRevision, fixture.sourceRevision);
    assert.equal(diagnostic.promotionTopicRevision, null);
    assert.equal(diagnostic.sourceTreeObjectId, null);
    assert.equal(diagnostic.admissionDigest, null);
    assert.equal(
      diagnostic.verificationDigest,
      semanticDigest(checkedAdmissionDomain, diagnostic, ["verificationDigest"]),
    );
    assert.equal(validate(diagnostic), true, JSON.stringify(validate.errors));
  });

  test("checked selection refuses source, target, and artifact substitution", async () => {
    const fixture = await createPromotionRepository();
    const selection = {
      expectedSourceRevision: fixture.sourceRevision,
      artifactId,
    };
    assertCheckedAdmissionRefuses(
      fixture.repoRoot,
      { ...selection, expectedSourceRevision: "f".repeat(40) },
      /source revision differs/u,
    );
    assertCheckedAdmissionRefuses(
      fixture.repoRoot,
      { ...selection, targetTriple: "x86_64-apple-darwin" },
      /unknown option targetTriple/u,
    );
    assertCheckedAdmissionRefuses(
      fixture.repoRoot,
      { ...selection, artifactId: "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" },
      /artifact ID differs/u,
    );
  });

  test("a canonical linked worktree gitfile and packed symbolic ref both verify", async () => {
    const linkedFixture = await createPromotionRepository();
    const linkedRoot = path.join(linkedFixture.root, "linked-checkout");
    git(linkedFixture.repoRoot, ["worktree", "add", "--quiet", "--detach", linkedRoot, "HEAD"]);
    const linkedResult = verifiedResult(linkedRoot);
    assert.equal(linkedResult.authorized, true);
    assert.equal(linkedResult.currentRevision, linkedFixture.promotionMergeRevision);

    const packedFixture = await createPromotionRepository();
    git(packedFixture.repoRoot, ["pack-refs", "--all"]);
    const packedResult = verifiedResult(packedFixture.repoRoot);
    assert.equal(packedResult.authorized, true);
  });

  test("gitfile, symbolic-ref, and HTTP-alternate selector substitution is refused", async () => {
    const linkedFixture = await createPromotionRepository();
    const linkedRoot = path.join(linkedFixture.root, "linked-checkout");
    git(linkedFixture.repoRoot, ["worktree", "add", "--quiet", "--detach", linkedRoot, "HEAD"]);
    await fsp.link(path.join(linkedRoot, ".git"), path.join(linkedFixture.root, "gitfile-hardlink"));
    assertVerifierRefuses(linkedRoot, /trusted regular files must have one filesystem link/u);

    const refFixture = await createPromotionRepository();
    const refPath = path.join(refFixture.repoRoot, ".git", "refs", "heads", "main");
    const refTarget = path.join(refFixture.repoRoot, ".git", "refs", "heads", "main-target");
    await fsp.rename(refPath, refTarget);
    await fsp.symlink("main-target", refPath);
    assertVerifierRefuses(refFixture.repoRoot, /trusted file path must be canonical and symlink-free|checked Git .*failed/u);

    const alternateFixture = await createPromotionRepository();
    const infoRoot = path.join(alternateFixture.repoRoot, ".git", "objects", "info");
    await fsp.mkdir(infoRoot, { recursive: true });
    await fsp.writeFile(path.join(infoRoot, "http-alternates"), "https://example.invalid/objects\n");
    assertVerifierRefuses(alternateFixture.repoRoot, /Git HTTP object alternates: forbidden control path exists/u);
  });

  test("an unchanged later descendant cannot inherit an admission", async () => {
    const fixture = await createPromotionRepository({ laterDescendant: true });
    assertVerifierRefuses(fixture.repoRoot, /exact two-parent promotion merge/u);
    assertCheckedAdmissionRefuses(fixture.repoRoot, {
      expectedSourceRevision: fixture.sourceRevision,
      artifactId,
    }, /exact two-parent promotion merge/u);
  });

  test("fast-forward and squash-shaped single-parent promotion commits are refused", async () => {
    const fixture = await createPromotionRepository({ fastForward: true });
    assertVerifierRefuses(fixture.repoRoot, /exact two-parent promotion merge/u);
  });

  test("the promotion topic must be one direct commit from source A", async () => {
    const fixture = await createPromotionRepository({ topicHasTwoCommits: true });
    assertVerifierRefuses(fixture.repoRoot, /one direct commit whose sole parent/u);
  });

  test("source A must be the merge first parent and C must have P's exact tree", async () => {
    const wrongParent = await createPromotionRepository({ firstParentDrift: true });
    assertVerifierRefuses(wrongParent.repoRoot, /first parent must equal/u);
    const wrongTree = await createPromotionRepository({ mergeTreeDrift: true });
    assertVerifierRefuses(wrongTree.repoRoot, /merge tree must equal/u);
  });

  test("code drift fails even when the active catalog attempts to list it", async () => {
    const unlisted = await createPromotionRepository({ codeDrift: true });
    assertVerifierRefuses(unlisted.repoRoot, /changed-path set mismatch/u);
    const listed = await createPromotionRepository({ listedCodeDrift: true });
    assertVerifierRefuses(listed.repoRoot, /outside the source\/target\/artifact-scoped promotion namespace/u);
  });

  test("equivalent but unlisted files and renames fail the exact changed-path set", async () => {
    const extra = await createPromotionRepository({ unlistedEquivalent: true });
    assertVerifierRefuses(extra.repoRoot, /changed-path set mismatch/u);
    const renamed = await createPromotionRepository({ renameSourceBlob: true });
    assertVerifierRefuses(renamed.repoRoot, /exactly one conformance report/u);
  });

  test("copies of source blobs are refused even at an admitted evidence path", async () => {
    const fixture = await createPromotionRepository({ copySourceBlob: true });
    assertVerifierRefuses(fixture.repoRoot, /copied source blob is forbidden/u);
  });

  test("duplicate catalog rows and duplicate promoted blob objects are refused", async () => {
    const duplicateRow = await createPromotionRepository({ duplicateArtifactRow: true });
    assertVerifierRefuses(duplicateRow.repoRoot, /duplicate artifact path/u);
    const duplicateBlob = await createPromotionRepository({ duplicateEvidence: true });
    assertVerifierRefuses(duplicateBlob.repoRoot, /copied promotion blobs are forbidden/u);
  });

  test("executable, symlink, and submodule promotion artifacts are refused", async () => {
    const executable = await createPromotionRepository({ executableEvidence: true });
    assertVerifierRefuses(executable.repoRoot, /symlinks, submodules, executables/u);
    const symlink = await createPromotionRepository({ symlinkEvidence: true });
    assertVerifierRefuses(symlink.repoRoot, /symlinks, submodules, executables/u);
    const submodule = await createPromotionRepository({ submoduleEvidence: true });
    assertVerifierRefuses(submodule.repoRoot, /symlinks, submodules, executables/u);
  });

  test("the checked catalog itself cannot be a symlink or submodule", async () => {
    const symlink = await createPromotionRepository({ catalogSymlink: true });
    assertVerifierRefuses(symlink.repoRoot, /running authority .*catalog.*not a checked non-executable blob/u);
    const submodule = await createPromotionRepository({ catalogSubmodule: true });
    assertVerifierRefuses(submodule.repoRoot, /running authority .*catalog.*not a checked non-executable blob/u);
  });

  test("promotion-time verifier or schema drift is outside the exact path set", async () => {
    const moduleDrift = await createPromotionRepository({
      authorityDriftPath: "scripts/portable-engine-promotion-lineage.mjs",
    });
    assertVerifierRefuses(moduleDrift.repoRoot, /changed-path set mismatch/u);
    const schemaDrift = await createPromotionRepository({ authorityDriftPath: schemaPath });
    assertVerifierRefuses(schemaDrift.repoRoot, /changed-path set mismatch/u);
    const checkedSchemaDrift = await createPromotionRepository({ authorityDriftPath: checkedAdmissionSchemaPath });
    assertVerifierRefuses(checkedSchemaDrift.repoRoot, /changed-path set mismatch/u);
  });

  test("blob object, size, digest, and admission-digest substitutions fail", async () => {
    const wrongObject = await createPromotionRepository({
      mutateAdmission(admission) {
        admission.artifacts[0].blobObjectId = "f".repeat(40);
      },
    });
    assertVerifierRefuses(wrongObject.repoRoot, /checked blob object ID mismatch/u);
    const wrongSize = await createPromotionRepository({
      mutateAdmission(admission) {
        admission.artifacts[0].size += 1;
      },
    });
    assertVerifierRefuses(wrongSize.repoRoot, /checked blob size mismatch/u);
    const wrongDigest = await createPromotionRepository({
      mutateAdmission(admission) {
        admission.artifacts[0].digest = `sha256-${"f".repeat(64)}`;
      },
    });
    assertVerifierRefuses(wrongDigest.repoRoot, /checked blob raw digest mismatch/u);
    const wrongAdmissionDigest = await createPromotionRepository({ corruptAdmissionDigest: true });
    assertVerifierRefuses(wrongAdmissionDigest.repoRoot, /admissionDigest mismatch/u);
  });

  test("the admission path is fixed and unknown catalog fields fail closed", async () => {
    const wrongPath = await createPromotionRepository({
      mutateCatalog(catalog) {
        catalog.admissionPath = "capsec/conformance/portable-promotions/catalog.json";
      },
    });
    assertVerifierRefuses(wrongPath.repoRoot, /admissionPath must name the exact checked catalog path/u);
    const unknown = await createPromotionRepository({
      mutateCatalog(catalog) {
        catalog.note = "not-authority";
      },
    });
    assertVerifierRefuses(unknown.repoRoot, /expected exact fields/u);
  });

  test("dirty tracked or untracked state is refused", async () => {
    const fixture = await createPromotionRepository();
    await writeFile(fixture.repoRoot, "untracked.json", canonicalJson({ dirty: true }));
    assertVerifierRefuses(fixture.repoRoot, /exactly clean tracked and untracked worktree/u);
  });

  test("raw loose-object substitution is caught by independent Git object hashing", async () => {
    const fixture = await createPromotionRepository();
    const hostile = Buffer.from("hostile-but-same-object-name", "utf8");
    const loosePath = path.join(
      fixture.repoRoot,
      ".git",
      "objects",
      fixture.evidenceObjectId.slice(0, 2),
      fixture.evidenceObjectId.slice(2),
    );
    await fsp.chmod(loosePath, 0o600);
    await fsp.writeFile(
      loosePath,
      deflateSync(Buffer.concat([Buffer.from(`blob ${hostile.length}\0`, "ascii"), hostile])),
    );
    assertVerifierRefuses(fixture.repoRoot, /failed independent content hashing|checked Git cat-file failed/u);
  });
});
