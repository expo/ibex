// Adversarial phase-1 installer tests. Provenance verification is injected:
// the production path remains fail-closed until verifier expectations v2 is
// integrated with the checked publisher policy.

import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { deflateSync, gzipSync } from "node:zlib";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildDeterministicUstarGzip,
  canonicalJson,
  compareUtf8,
  gitObjectId,
  rawDigest,
  semanticDigest,
} from "./portable-engine-contract.mjs";
import { deriveReviewedSourceAuthorities } from "./package-portable-hermes-macos.mjs";
import {
  buildFixedVerifierExpectations,
  detectMacOsExtendedAcl,
  installPortableEngine,
  installPortableEngineWithPromotionLineage,
  listCheckedRevisionFiles,
  readCheckedRevisionFile,
  resolveGitControlPaths,
  validateGitControlPlane,
  verifyPortableEngineStore,
} from "./portable-engine-installer-test-harness.mjs";
import {
  installPortableEngine as installPortableEngineProduction,
  verifyPortableEngineStore as verifyPortableEngineStoreProduction,
} from "./portable-engine-installer.mjs";
import {
  loadProductionCargoTargetMap,
  requireProductionCleanCheckout,
  runPortableHermesCargoCore,
  validateCheckedPromotionAdmission,
} from "./portable-engine-build-preflight-core.mjs";
import { runPortableHermesCargo as runPortableHermesCargoProduction } from "./run-portable-hermes-cargo.mjs";

const sourceRepo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoots = new Set();

function checkedPromotionAdmission({
  sourceRevision,
  currentRevision = sourceRevision,
  authorized = false,
  artifactId = `sha256-${"A".repeat(43)}`,
  targetTriple = "aarch64-apple-darwin",
  promotionTopicRevision = ["0", "1", "2"]
    .map((digit) => digit.repeat(40))
    .find((revision) => revision !== sourceRevision && revision !== currentRevision),
}) {
  const record = {
    schema: "ibex/portable-engine-checked-promotion-admission/1",
    authorized,
    currentRevision,
    sourceRevision,
    promotionTopicRevision: authorized ? promotionTopicRevision : null,
    sourceTreeObjectId: authorized ? "b".repeat(40) : null,
    targetTriple,
    portableArtifactId: artifactId,
    admissionDigest: authorized ? semanticDigest("fixture.promotion-admission.v1", { sourceRevision, currentRevision }) : null,
    verificationDigest: "",
  };
  record.verificationDigest = semanticDigest(
    "ibex.portable-engine-checked-promotion-admission.v1",
    record,
    ["verificationDigest"],
  );
  return record;
}

async function makeWritable(root) {
  let status;
  try {
    status = await fsp.lstat(root);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (status.isSymbolicLink()) return;
  if (status.isDirectory()) {
    await fsp.chmod(root, 0o700);
    for (const child of await fsp.readdir(root)) await makeWritable(path.join(root, child));
  } else if (status.isFile()) {
    await fsp.chmod(root, 0o600);
  }
}

afterEach(async () => {
  for (const root of temporaryRoots) {
    await makeWritable(root);
    await fsp.rm(root, { recursive: true, force: true });
  }
  temporaryRoots.clear();
});

function gitBytes(args) {
  return Buffer.from(execFileSync("git", args, { cwd: sourceRepo, encoding: "buffer", maxBuffer: 64 * 1024 * 1024 }));
}

function systemGitBytes(repoRoot, args) {
  return Buffer.from(execFileSync("/usr/bin/git", args, {
    cwd: repoRoot,
    encoding: "buffer",
    env: { PATH: "/usr/bin:/bin", LC_ALL: "C", LANG: "C" },
    maxBuffer: 64 * 1024 * 1024,
  }));
}

async function writeLooseObjectAtId(repoRoot, objectId, type, bytes) {
  const body = Buffer.from(bytes);
  const encoded = deflateSync(Buffer.concat([Buffer.from(`${type} ${body.length}\0`, "ascii"), body]));
  const objectPath = path.join(repoRoot, ".git", "objects", objectId.slice(0, 2), objectId.slice(2));
  await fsp.mkdir(path.dirname(objectPath), { recursive: true });
  await fsp.unlink(objectPath).catch((error) => {
    if (error.code !== "ENOENT") throw error;
  });
  await fsp.writeFile(objectPath, encoded, { mode: 0o444 });
}

async function createLooseObjectRepository() {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "ibex-portable-git-authority-"));
  temporaryRoots.add(root);
  const repoRoot = path.join(root, "checkout");
  await fsp.mkdir(path.join(repoRoot, "authority"), { recursive: true });
  systemGitBytes(root, ["init", "--quiet", repoRoot]);
  systemGitBytes(repoRoot, ["config", "user.name", "Ibex test"]);
  systemGitBytes(repoRoot, ["config", "user.email", "ibex@example.invalid"]);
  await fsp.writeFile(path.join(repoRoot, "authority", "policy.json"), "{\"trusted\":true}\n");
  systemGitBytes(repoRoot, ["add", "authority/policy.json"]);
  systemGitBytes(repoRoot, ["commit", "--quiet", "-m", "fixture"]);
  const revision = systemGitBytes(repoRoot, ["rev-parse", "HEAD"]).toString("ascii").trim();
  return { root, repoRoot, revision };
}

function revisionFile(_repoRoot, revision, relativePath) {
  return gitBytes(["show", `${revision}:${relativePath}`]);
}

function revisionFiles(_repoRoot, revision, directory) {
  return gitBytes(["ls-tree", "-r", "-z", "--name-only", revision, "--", directory])
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
}

function gitObject(_repoRoot, type, objectId) {
  return gitBytes(["cat-file", type, objectId]);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function digestPrefix(value) {
  return value.slice("sha256-".length, "sha256-".length + 12);
}

function addDirectory(payload, pathname, role) {
  payload.set(pathname, { kind: "directory", role, path: pathname });
}

function addRegular(payload, pathname, role, bytes, executable = false) {
  const captured = Buffer.from(bytes);
  payload.set(pathname, {
    kind: "regular",
    role,
    path: pathname,
    digest: rawDigest(captured),
    size: captured.length,
    executable,
    bytes: captured,
  });
}

function addSymlink(payload, pathname, role, target) {
  payload.set(pathname, { kind: "symlink", role, path: pathname, target });
}

function addAuthority(payload, pathname, document) {
  addRegular(payload, pathname, "metadata", Buffer.from(canonicalJson(document), "utf8"));
}

function manifestEntries(payload) {
  return [...payload.values()]
    .map(({ bytes: _bytes, ...entry }) => entry)
    .sort((left, right) => compareUtf8(left.path, right.path));
}

function archiveMembers(payload, manifestBytes) {
  return [
    { path: "META-INF", kind: "directory" },
    { path: "META-INF/portable-engine-manifest.json", kind: "regular", bytes: manifestBytes, executable: false },
    { path: "payload", kind: "directory" },
    ...[...payload.values()].map((entry) => {
      const memberPath = `payload/${entry.path}`;
      if (entry.kind === "regular") return { path: memberPath, kind: "regular", bytes: entry.bytes, executable: entry.executable };
      if (entry.kind === "symlink") return { path: memberPath, kind: "symlink", target: entry.target };
      return { path: memberPath, kind: "directory" };
    }),
  ];
}

function writeTarText(header, offset, length, value) {
  const bytes = Buffer.from(value, "utf8");
  assert(bytes.length <= length);
  bytes.copy(header, offset);
}

function writeTarOctal(header, offset, length, value) {
  const digits = value.toString(8).padStart(length - 1, "0");
  assert(digits.length === length - 1);
  header.write(`${digits}\0`, offset, length, "ascii");
}

function rawTarHeader(member) {
  const header = Buffer.alloc(512);
  const tarPath = member.kind === "directory" && !member.path.endsWith("/") ? `${member.path}/` : member.path;
  if (Buffer.byteLength(tarPath) <= 100) {
    writeTarText(header, 0, 100, tarPath);
  } else {
    const segments = tarPath.split("/");
    let split = segments.length - 1;
    for (; split > 0; split -= 1) {
      const prefix = segments.slice(0, split).join("/");
      const name = segments.slice(split).join("/");
      if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100) {
        writeTarText(header, 0, 100, name);
        writeTarText(header, 345, 155, prefix);
        break;
      }
    }
    assert(split > 0, `${tarPath}: does not fit test ustar header`);
  }
  const type = member.typeOverride ?? (member.kind === "regular" ? "0" : member.kind === "directory" ? "5" : "2");
  const mode = member.modeOverride ?? (member.kind === "regular" ? (member.executable ? 0o755 : 0o644) : member.kind === "directory" ? 0o755 : 0o777);
  const bodySize = member.sizeOverride ?? (member.kind === "regular" ? member.bytes.length : 0);
  writeTarOctal(header, 100, 8, mode);
  writeTarOctal(header, 108, 8, 0);
  writeTarOctal(header, 116, 8, 0);
  writeTarOctal(header, 124, 12, bodySize);
  writeTarOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  if (member.kind === "symlink" || member.linkTargetOverride !== undefined) {
    writeTarText(header, 157, 100, member.linkTargetOverride ?? member.target);
  }
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  const checksum = header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, "0");
  header.write(`${checksum}\0 `, 148, 8, "ascii");
  return header;
}

function rawUstarGzip(members) {
  const chunks = [];
  for (const member of members) {
    chunks.push(rawTarHeader(member));
    if (member.kind === "regular") {
      const declared = member.sizeOverride ?? member.bytes.length;
      const body = member.bytes.subarray(0, declared);
      chunks.push(body);
      if (body.length < declared) chunks.push(Buffer.alloc(declared - body.length));
      const padding = (512 - (declared % 512)) % 512;
      if (padding) chunks.push(Buffer.alloc(padding));
    }
  }
  chunks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(chunks), { level: 1, mtime: 0 });
}

function replaceManifest(fixture, mutate, additionalMembers = []) {
  const manifest = deepClone(fixture.manifest);
  mutate(manifest);
  manifest.entries.sort((left, right) => compareUtf8(left.path, right.path));
  manifest.artifactId = semanticDigest("ibex.portable-engine-manifest.v1", manifest, ["artifactId"]);
  const manifestBytes = Buffer.from(canonicalJson(manifest), "utf8");
  const members = fixture.members
    .filter((member) => member.path !== "META-INF/portable-engine-manifest.json")
    .concat({ path: "META-INF/portable-engine-manifest.json", kind: "regular", bytes: manifestBytes, executable: false }, additionalMembers)
    .sort((left, right) => compareUtf8(left.path, right.path));
  return { ...fixture, manifest, manifestBytes, members, archive: rawUstarGzip(members) };
}

function replacePayloadRegular(fixture, payloadPath, bytes) {
  const manifest = deepClone(fixture.manifest);
  const entry = manifest.entries.find((candidate) => candidate.path === payloadPath);
  assert(entry?.kind === "regular");
  entry.digest = rawDigest(bytes);
  entry.size = bytes.length;
  manifest.artifactId = semanticDigest("ibex.portable-engine-manifest.v1", manifest, ["artifactId"]);
  const manifestBytes = Buffer.from(canonicalJson(manifest), "utf8");
  const members = fixture.members.map((member) => {
    if (member.path === "META-INF/portable-engine-manifest.json") return { ...member, bytes: manifestBytes };
    if (member.path === `payload/${payloadPath}`) return { ...member, bytes: Buffer.from(bytes) };
    return member;
  });
  return { ...fixture, manifest, manifestBytes, members, archive: rawUstarGzip(members) };
}

function buildSourceTree(revision) {
  const commitBytes = gitObject(sourceRepo, "commit", revision);
  const treeId = gitBytes(["show", "-s", "--format=%T", revision]).toString("utf8").trim();
  const treeBytes = gitObject(sourceRepo, "tree", treeId);
  return {
    commitBytes,
    treeBytes,
    document: {
      schema: "ibex/portable-engine-source-tree-identity/1",
      repository: "ccheever/ibex",
      sourceRevision: revision,
      sourceRef: "refs/heads/main",
      gitObjectFormat: "sha1",
      sourceRevisionObjectType: "commit",
      sourceRevisionObjectContent: {
        path: "META-INF/authority/source-tree/commit.content",
        digest: rawDigest(commitBytes),
        size: commitBytes.length,
        encoding: "raw-uncompressed-git-object-content",
      },
      treeObjectId: treeId,
      treeObjectType: "tree",
      treeObjectContent: {
        path: "META-INF/authority/source-tree/tree.content",
        digest: rawDigest(treeBytes),
        size: treeBytes.length,
        encoding: "raw-uncompressed-git-object-content",
      },
    },
  };
}

function buildFixture() {
  const revision = gitBytes(["rev-parse", "HEAD"]).toString("utf8").trim();
  const policy = JSON.parse(revisionFile(sourceRepo, revision, "schemas/portable-engine-provenance-trust-policy-v1.json").toString("utf8"));
  const targetPolicy = policy.admittedTargets.find((target) => target.triple === "aarch64-apple-darwin");
  const authorityRows = targetPolicy.buildAuthorityPaths
    .map((relativePath) => ({ path: relativePath, digest: rawDigest(revisionFile(sourceRepo, revision, relativePath)) }))
    .sort((left, right) => compareUtf8(left.path, right.path));
  const authorityBytes = new Map(targetPolicy.buildAuthorityPaths.map((relativePath) => [relativePath, revisionFile(sourceRepo, revision, relativePath)]));
  const sourceAuthorities = deriveReviewedSourceAuthorities(sourceRepo, revision, { rows: authorityRows, bytesByPath: authorityBytes });
  const sourceTree = buildSourceTree(revision);
  const payload = new Map();

  for (const [pathname, role] of [
    ["lib", "runtime"],
    ["lib/hermesvm.framework", "framework-resource"],
    ["lib/hermesvm.framework/Versions", "framework-resource"],
    ["lib/hermesvm.framework/Versions/1", "framework-resource"],
    ["include", "header"],
    ["include/jsi", "header"],
    ["bin", "host-tool"],
    ["share", "profile-receipt"],
    ["share/hermes", "profile-receipt"],
    ["share/compatibility", "compatibility-fixture"],
    ["share/compatibility/host-tools", "compatibility-fixture"],
    ["share/compatibility/host-tools/input", "compatibility-fixture"],
  ]) addDirectory(payload, pathname, role);
  const runtimePath = "lib/hermesvm.framework/Versions/1/hermesvm";
  const runtimeBytes = Buffer.from("fixture Hermes runtime bytes\n", "utf8");
  const toolBytes = Buffer.from("fixture hermesc bytes\n", "utf8");
  const headerBytes = Buffer.from("#pragma once\n", "utf8");
  const smokeBytes = Buffer.from("globalThis.answer = 42;\n", "utf8");
  addRegular(payload, runtimePath, "runtime", runtimeBytes, true);
  addSymlink(payload, "lib/hermesvm.framework/Versions/Current", "framework-resource", "1");
  addSymlink(payload, "lib/hermesvm.framework/hermesvm", "framework-resource", "Versions/Current/hermesvm");
  addRegular(payload, "include/jsi/jsi.h", "header", headerBytes);
  addRegular(payload, "bin/hermesc", "host-tool", toolBytes, true);
  addRegular(payload, "share/compatibility/host-tools/input/smoke.js", "compatibility-fixture", smokeBytes);

  const reviewedIdentity = {
    artifact: "facebook/hermes",
    patchApplicationAuthorityDigest: sourceAuthorities.patchApplicationAuthorityDigest,
    patchIdentityAuthorityDigest: sourceAuthorities.patchIdentityAuthorityDigest,
    patchStackDigest: sourceAuthorities.patchStackDigest,
    sourceBuildAuthorityDigests: sourceAuthorities.sourceBuildAuthorityDigests,
    sourceCommit: sourceAuthorities.pinnedHermesSource.sourceCommit,
    sourceRef: sourceAuthorities.pinnedHermesSource.sourceRef,
    sourceVersion: sourceAuthorities.pinnedHermesSource.sourceVersion,
  };
  const cacheKey = `${reviewedIdentity.sourceCommit.slice(0, 12)}-p${digestPrefix(reviewedIdentity.patchStackDigest)}-ba${digestPrefix(reviewedIdentity.sourceBuildAuthorityDigests["scripts/build-hermes.sh"])}-bl${digestPrefix(reviewedIdentity.sourceBuildAuthorityDigests["scripts/build-hermes-linux.sh"])}-a${digestPrefix(reviewedIdentity.patchApplicationAuthorityDigest)}-i${digestPrefix(reviewedIdentity.patchIdentityAuthorityDigest)}-oapple`;
  const receipt = {
    schema: "ibex/hermes-profile-provenance-receipt/2",
    profileId: targetPolicy.profile.id,
    targetVariant: targetPolicy.profile.targetVariant,
    artifact: { binaryDigest: rawDigest(runtimeBytes), fileName: "hermesvm", targetArchitecture: "aarch64" },
    origin: { kind: targetPolicy.reviewedProfileOriginKind, cacheKey, reviewedProfileIdentity: reviewedIdentity },
  };
  const receiptBytes = Buffer.from(canonicalJson(receipt), "utf8");
  addRegular(payload, "share/hermes/profile-provenance.json", "profile-receipt", receiptBytes);

  const reviewedProfile = {
    schema: "ibex/portable-engine-reviewed-profile-identity/1",
    profileId: receipt.profileId,
    targetVariant: receipt.targetVariant,
    targetTriple: "aarch64-apple-darwin",
    originKind: receipt.origin.kind,
    receiptPath: "share/hermes/profile-provenance.json",
    receiptDigest: rawDigest(receiptBytes),
    reviewedProfileIdentity: reviewedIdentity,
  };
  const component = { path: runtimePath, digest: rawDigest(runtimeBytes) };
  const requiredExports = {
    schema: "ibex/portable-engine-export-set/1",
    mode: "required",
    targetTriple: "aarch64-apple-darwin",
    extractor: targetPolicy.exportExtractor,
    components: [component],
    symbolNameSemantics: "utf8-bytes-no-normalization",
    matchers: targetPolicy.exportPolicy.requiredMatchers,
  };
  const forbiddenExports = {
    ...requiredExports,
    mode: "forbidden",
    matchers: targetPolicy.exportPolicy.forbiddenMatchers,
  };
  const headerSet = {
    schema: "ibex/portable-engine-header-set/1",
    targetTriple: "aarch64-apple-darwin",
    includeRoots: ["include"],
    headers: [{ path: "include/jsi/jsi.h", digest: rawDigest(headerBytes), size: headerBytes.length }],
  };
  const requiredExportsDigest = semanticDigest("ibex.portable-engine-required-exports.v1", requiredExports);
  const forbiddenExportsDigest = semanticDigest("ibex.portable-engine-forbidden-exports.v1", forbiddenExports);
  const headerSetDigest = semanticDigest("ibex.portable-engine-header-set.v1", headerSet);
  const abiContract = {
    schema: "ibex/portable-engine-abi-contract/1",
    target: { triple: "aarch64-apple-darwin", structuralFeatures: targetPolicy.structuralFeatures },
    ...targetPolicy.directJsiAbi,
    headerSetDigest,
    requiredExportsDigest,
    forbiddenExportsDigest,
  };
  const hostTool = {
    schema: "ibex/portable-engine-host-tool-compatibility/1",
    toolRole: "bytecode-compiler",
    toolPath: "bin/hermesc",
    toolDigest: rawDigest(toolBytes),
    actualHostTriple: "aarch64-apple-darwin",
    binaryMachine: targetPolicy.hostTool.binaryMachine,
    ...targetPolicy.hostTool.executionContract,
    dependencyClosure: {
      extractor: {
        format: "mach-o",
        tables: ["LC_LAZY_LOAD_DYLIB", "LC_LOAD_DYLIB", "LC_LOAD_UPWARD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB"],
        transitive: true,
      },
      nonSystemDependencies: [],
      systemDependencies: ["/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"],
    },
    inputFixtures: [{ fixturePayloadPath: "share/compatibility/host-tools/input/smoke.js", workspacePath: "input/smoke.js", digest: rawDigest(smokeBytes), size: smokeBytes.length, executable: false }],
    invocations: [{
      id: "compile-smoke",
      argv: ["-emit-binary", "-out", "output/smoke.hbc", "input/smoke.js"],
      expectedExitCode: 0,
      stdoutDigest: rawDigest(Buffer.alloc(0)),
      stdoutSize: 0,
      stderrDigest: rawDigest(Buffer.alloc(0)),
      stderrSize: 0,
      outputFiles: [{ path: "output/smoke.hbc", digest: rawDigest(Buffer.from("hbc")), size: 3, executable: false }],
      bytecodeOutputs: [{ path: "output/smoke.hbc", bytecodeVersion: targetPolicy.profile.hermesBytecodeVersion, sourcePath: "input/smoke.js", sourceDigest: rawDigest(smokeBytes) }],
    }],
  };
  const hostToolDigest = semanticDigest("ibex.portable-engine-host-tool-compatibility.v1", hostTool);

  for (const pathname of ["META-INF", "META-INF/authority", "META-INF/authority/host-tools", "META-INF/authority/source-tree"]) addDirectory(payload, pathname, "metadata");
  addAuthority(payload, "META-INF/authority/abi-contract.json", abiContract);
  addAuthority(payload, "META-INF/authority/forbidden-exports.json", forbiddenExports);
  addAuthority(payload, "META-INF/authority/header-set.json", headerSet);
  addAuthority(payload, `META-INF/authority/host-tools/${hostToolDigest}.json`, hostTool);
  addAuthority(payload, "META-INF/authority/required-exports.json", requiredExports);
  addAuthority(payload, "META-INF/authority/reviewed-profile-identity.json", reviewedProfile);
  addAuthority(payload, "META-INF/authority/source-tree-identity.json", sourceTree.document);
  addRegular(payload, sourceTree.document.sourceRevisionObjectContent.path, "metadata", sourceTree.commitBytes);
  addRegular(payload, sourceTree.document.treeObjectContent.path, "metadata", sourceTree.treeBytes);

  const manifest = {
    schema: "ibex/portable-engine-manifest/1",
    artifactId: "",
    artifactKind: "hermes",
    target: { triple: "aarch64-apple-darwin", structuralFeatures: targetPolicy.structuralFeatures },
    profile: { ...targetPolicy.profile, reviewedProfileIdentityDigest: semanticDigest("ibex.portable-engine-reviewed-profile-identity.v1", reviewedProfile) },
    source: {
      artifact: reviewedIdentity.artifact,
      sourceCommit: reviewedIdentity.sourceCommit,
      sourceRef: reviewedIdentity.sourceRef,
      sourceVersion: reviewedIdentity.sourceVersion,
      patchStackDigest: reviewedIdentity.patchStackDigest,
    },
    build: {
      repository: policy.enginePublisher.repository,
      sourceRevision: revision,
      sourceTreeDigest: semanticDigest("ibex.portable-engine-source-tree-identity.v1", sourceTree.document),
      sourceRef: policy.enginePublisher.sourceRef,
      publisherWorkflow: policy.enginePublisher.workflowPath,
      authorityDigests: authorityRows,
    },
    interface: {
      abiContractDigest: semanticDigest("ibex.portable-engine-abi-contract.v1", abiContract),
      requiredExportsDigest,
      forbiddenExportsDigest,
      headerSetDigest,
      hostTools: [{ role: "host-tool", path: "bin/hermesc", digest: rawDigest(toolBytes), compatibilityDigest: hostToolDigest }],
      loadableComponents: [
        { role: "runtime", path: runtimePath, digest: rawDigest(runtimeBytes), system: false },
        ...policy.platformSystemDependencies.apple.map((name) => ({ role: "runtime-dependency", name, system: true })),
      ],
    },
    entries: manifestEntries(payload),
    runtimeComponent: runtimePath,
  };
  manifest.artifactId = semanticDigest("ibex.portable-engine-manifest.v1", manifest, ["artifactId"]);
  const manifestBytes = Buffer.from(canonicalJson(manifest), "utf8");
  const members = archiveMembers(payload, manifestBytes).sort((left, right) => compareUtf8(left.path, right.path));
  return { revision, policy, targetPolicy, payload, manifest, manifestBytes, members, archive: buildDeterministicUstarGzip(members) };
}

async function createCase(fixture = buildFixture()) {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "ibex-portable-installer-"));
  temporaryRoots.add(root);
  const archivePath = path.join(root, "fixture-portable-hermes.tar.gz");
  const bundlePath = path.join(root, "fixture.sigstore.json");
  await fsp.writeFile(archivePath, fixture.archive);
  await fsp.writeFile(bundlePath, Buffer.from(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","fixture":true}\n`, "utf8"));
  const repoRoot = path.join(root, "checkout");
  await fsp.mkdir(repoRoot);
  return { root, repoRoot, archivePath, bundlePath, fixture };
}

async function lstatKind(filePath) {
  const status = await fsp.lstat(filePath);
  if (status.isSymbolicLink()) return "symlink";
  if (status.isDirectory()) return "directory";
  if (status.isFile()) return "regular";
  return "special";
}

function mockVerificationResult({ archivePath, bundlePath, expectations, expectationsBytes }) {
  const archive = fs.readFileSync(archivePath);
  const bundle = fs.readFileSync(bundlePath);
  const san = `https://github.com/${expectations.repository}/${expectations.workflowPath}@${expectations.sourceRef}`;
  return Buffer.from(`${canonicalJson({
    schema: "ibex/github-private-artifact-attestation-verification/2",
    trustRoot: expectations.trustedRoot,
    expectationsDigest: sha256(expectationsBytes),
    bundle: { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", sha256: sha256(bundle), size: bundle.length },
    subject: { name: expectations.subjectName, sha256: sha256(archive), size: archive.length },
    signer: {
      issuer: expectations.certificateIssuer,
      san,
      repository: expectations.repository,
      repositoryId: expectations.repositoryId,
      repositoryOwnerId: expectations.repositoryOwnerId,
      workflowPath: expectations.workflowPath,
      workflowName: expectations.workflowName,
      sourceRef: expectations.sourceRef,
      sourceRevision: expectations.sourceRevision,
      trigger: "push",
      runnerEnvironment: expectations.runnerEnvironment,
      repositoryVisibility: expectations.repositoryVisibility,
      runId: "123456789",
      runAttempt: "1",
    },
    provenance: {
      statementType: "https://in-toto.io/Statement/v1",
      predicateType: "https://slsa.dev/provenance/v1",
      buildType: expectations.buildType,
      builderId: san,
      invocationId: `https://github.com/${expectations.repository}/actions/runs/123456789/attempts/1`,
    },
    timestamp: { type: "TimestampAuthority", uri: "timestamp.githubapp.com", value: "2026-07-20T00:00:00Z" },
  })}\n`, "utf8");
}

function dependencies(overrides = {}) {
  return {
    readRevisionFile: revisionFile,
    listRevisionFiles: revisionFiles,
    readGitObject: gitObject,
    resolveCheckoutRevision: () => gitBytes(["rev-parse", "HEAD"]).toString("utf8").trim(),
    verifyAttestation: async (input) => mockVerificationResult(input),
    ...overrides,
  };
}

async function installCase(testCase, overrides = {}) {
  return installPortableEngine({
    repoRoot: testCase.repoRoot,
    archivePath: testCase.archivePath,
    bundlePath: testCase.bundlePath,
    expectedSourceRevision: testCase.fixture.revision,
  }, dependencies(overrides));
}

async function expectRejected(testCase, pattern, overrides = {}) {
  await assert.rejects(() => installCase(testCase, overrides), pattern);
}

describe("portable engine installer core", () => {
  test("authenticates, streams, atomically publishes, and fully reverifies a checkout-local store", async () => {
    const testCase = await createCase();
    const result = await installCase(testCase);
    assert.equal(result.installed, true);
    assert.equal(result.diagnosticOnly, true);
    assert.equal(result.manifest.artifactId, testCase.fixture.manifest.artifactId);
    assert.equal(result.artifactRoot, path.join(await fsp.realpath(testCase.repoRoot), "target", "hermes-artifacts-test-only", result.manifest.artifactId));
    assert.equal(result.transport.receipt.schema, "ibex/test-only-portable-engine-installation-receipt/1");
    await assert.rejects(() => fsp.lstat(path.join(testCase.repoRoot, "target", "hermes-artifacts")), { code: "ENOENT" });
    const repeated = await installCase(testCase);
    assert.equal(repeated.installed, false);
    const verified = await verifyPortableEngineStore({
      repoRoot: testCase.repoRoot,
      expectedSourceRevision: testCase.fixture.revision,
      artifactId: result.manifest.artifactId,
      archiveDigest: rawDigest(testCase.fixture.archive),
    }, dependencies());
    assert.equal(verified.manifest.artifactId, result.manifest.artifactId);
  });

  test("atomically adds and selects another authenticated transport for the same portable identity", async () => {
    const testCase = await createCase();
    const first = await installCase(testCase);
    const alternateArchive = rawUstarGzip(testCase.fixture.members);
    assert.notEqual(rawDigest(alternateArchive), rawDigest(testCase.fixture.archive));
    const alternatePath = path.join(testCase.root, "alternate-encoding.tar.gz");
    const alternateBundle = path.join(testCase.root, "alternate.sigstore.json");
    await fsp.writeFile(alternatePath, alternateArchive);
    await fsp.writeFile(alternateBundle, "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",\"alternate\":true}\n");
    const second = await installPortableEngine({
      repoRoot: testCase.repoRoot,
      archivePath: alternatePath,
      bundlePath: alternateBundle,
      expectedSourceRevision: testCase.fixture.revision,
    }, dependencies());
    assert.equal(second.installed, false);
    assert.equal(second.manifest.artifactId, first.manifest.artifactId);
    assert.equal(second.transport.receipt.archiveDigest, rawDigest(alternateArchive));
    const transportRoot = path.join(first.artifactRoot, "LOCAL", "transport");
    assert.deepEqual((await fsp.readdir(transportRoot)).sort(compareUtf8), [rawDigest(testCase.fixture.archive), rawDigest(alternateArchive)].sort(compareUtf8));
  });

  test("rejects a valid attested transport for an unrelated valid installed artifact", async () => {
    const firstCase = await createCase();
    const first = await installCase(firstCase);
    const unrelatedBytes = Buffer.from("unrelated but schema-valid metadata\n", "utf8");
    const unrelatedFixture = replaceManifest(buildFixture(), (manifest) => {
      manifest.entries.push({
        kind: "regular",
        role: "metadata",
        path: "share/unrelated-metadata.txt",
        digest: rawDigest(unrelatedBytes),
        size: unrelatedBytes.length,
        executable: false,
      });
    }, [{ path: "payload/share/unrelated-metadata.txt", kind: "regular", bytes: unrelatedBytes, executable: false }]);
    const unrelatedCase = await createCase(unrelatedFixture);
    const unrelated = await installPortableEngine({
      repoRoot: firstCase.repoRoot,
      archivePath: unrelatedCase.archivePath,
      bundlePath: unrelatedCase.bundlePath,
      expectedSourceRevision: unrelatedFixture.revision,
    }, dependencies());
    assert.notEqual(unrelated.manifest.artifactId, first.manifest.artifactId);

    const unrelatedDigest = rawDigest(unrelatedFixture.archive);
    const sourceTransport = path.join(unrelated.artifactRoot, "LOCAL", "transport", unrelatedDigest);
    const firstTransportRoot = path.join(first.artifactRoot, "LOCAL", "transport");
    const forgedTransport = path.join(firstTransportRoot, unrelatedDigest);
    await fsp.chmod(firstTransportRoot, 0o755);
    await fsp.cp(sourceTransport, forgedTransport, { recursive: true, preserveTimestamps: true });
    const unrelatedReceiptPath = path.join(forgedTransport, "installation-receipt.json");
    const receipt = JSON.parse(await fsp.readFile(unrelatedReceiptPath, "utf8"));
    receipt.artifactId = first.manifest.artifactId;
    receipt.manifestDigest = semanticDigest("ibex.portable-engine-manifest-digest.v1", first.manifest);
    await fsp.chmod(unrelatedReceiptPath, 0o600);
    await fsp.writeFile(unrelatedReceiptPath, canonicalJson(receipt));
    await fsp.chmod(unrelatedReceiptPath, 0o444);
    const completionPath = path.join(forgedTransport, "COMPLETE");
    const completion = JSON.parse(await fsp.readFile(completionPath, "utf8"));
    completion.artifactId = first.manifest.artifactId;
    await fsp.chmod(completionPath, 0o600);
    await fsp.writeFile(completionPath, canonicalJson(completion));
    await fsp.chmod(completionPath, 0o444);
    await fsp.chmod(forgedTransport, 0o555);
    await fsp.chmod(firstTransportRoot, 0o555);

    await assert.rejects(() => verifyPortableEngineStore({
      repoRoot: firstCase.repoRoot,
      expectedSourceRevision: firstCase.fixture.revision,
      artifactId: first.manifest.artifactId,
      archiveDigest: unrelatedDigest,
    }, dependencies()), /retained archive manifest bytes differ from installed canonical manifest/u);
  });

  test("constructs authority expectations only from checked policy, revision, and subject facts", () => {
    const fixture = buildFixture();
    const expectations = buildFixedVerifierExpectations(fixture.policy, fixture.revision, "artifact.tar.gz");
    assert.deepEqual(expectations, {
      schema: "ibex/github-private-artifact-attestation-expectations/2",
      subjectName: "artifact.tar.gz",
      repository: "ccheever/ibex",
      repositoryId: "1268046138",
      repositoryOwnerId: "56719",
      workflowPath: ".github/workflows/hermes-artifacts.yml",
      workflowName: "Hermes artifact cache",
      sourceRef: "refs/heads/main",
      sourceRevision: fixture.revision,
      allowedTriggers: ["push", "workflow_dispatch"],
      runnerEnvironment: "github-hosted",
      repositoryVisibility: "private",
      certificateIssuer: "https://token.actions.githubusercontent.com",
      buildType: "https://actions.github.io/buildtypes/workflow/v1",
      trustedRoot: {
        profile: "github-private-signed-timestamp-v1",
        sha256: "484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7",
        size: 31645,
      },
    });
    assert.equal("runId" in expectations, false);
    assert.equal("runAttempt" in expectations, false);
  });

  test("refuses a selected revision that is not the current checkout HEAD", async () => {
    const testCase = await createCase();
    await assert.rejects(() => installPortableEngine({
      repoRoot: testCase.repoRoot,
      archivePath: testCase.archivePath,
      bundlePath: testCase.bundlePath,
      expectedSourceRevision: "0".repeat(40),
    }, dependencies()), /is not current checkout HEAD/u);
  });

  test("an admitted artifact mismatch fails before any final store publication", async () => {
    const testCase = await createCase();
    const promotionLineage = {
      schema: "ibex/portable-engine-promotion-lineage-verification/1",
      authorized: true,
      currentRevision: "c".repeat(40),
      promotionTopicRevision: "b".repeat(40),
      sourceRevision: testCase.fixture.revision,
      sourceTreeObjectId: "d".repeat(40),
      targetTriple: "aarch64-apple-darwin",
      portableArtifactId: semanticDigest("ibex.test.wrong-promoted-artifact.v1", {}),
      admissionDigest: semanticDigest("ibex.test.promotion-admission.v1", {}),
    };
    await assert.rejects(() => installPortableEngineWithPromotionLineage({
      repoRoot: testCase.repoRoot,
      archivePath: testCase.archivePath,
      bundlePath: testCase.bundlePath,
      expectedSourceRevision: testCase.fixture.revision,
    }, promotionLineage, dependencies({
      resolveCheckoutRevision: () => promotionLineage.currentRevision,
    })), /promoted artifact ID differs/u);
    await assert.rejects(
      () => fsp.lstat(path.join(
        testCase.repoRoot,
        "target",
        "hermes-artifacts-test-only",
        testCase.fixture.manifest.artifactId,
      )),
      { code: "ENOENT" },
    );
  });

  test("refuses an unauthenticated transport before any gzip, tar, or member parsing", async () => {
    const testCase = await createCase({ ...buildFixture(), archive: Buffer.from("attacker-controlled archive bytes") });
    let parsingStarted = false;
    await expectRejected(testCase, /signature verification refused fixture/u, {
      verifyAttestation: async () => { throw new Error("signature verification refused fixture"); },
      onArchiveParseStart: () => { parsingStarted = true; },
    });
    assert.equal(parsingStarted, false);
  });

  test("production wrappers reject dependency and context overrides", async () => {
    const testCase = await createCase();
    const installOptions = {
      repoRoot: testCase.repoRoot,
      archivePath: testCase.archivePath,
      bundlePath: testCase.bundlePath,
      expectedSourceRevision: testCase.fixture.revision,
    };
    await assert.rejects(() => installPortableEngineProduction(installOptions, dependencies()), /exactly one production options object/u);
    await assert.rejects(() => installPortableEngineProduction({ ...installOptions, context: {} }), /unknown option context/u);
    await assert.rejects(() => installPortableEngineProduction({ ...installOptions, promotionVerifier: () => ({ authorized: true }) }), /unknown option promotionVerifier/u);
    await assert.rejects(() => verifyPortableEngineStoreProduction({
      repoRoot: testCase.repoRoot,
      expectedSourceRevision: testCase.fixture.revision,
      artifactId: testCase.fixture.manifest.artifactId,
    }, dependencies()), /exactly one production options object/u);
    await assert.rejects(() => verifyPortableEngineStoreProduction({
      repoRoot: testCase.repoRoot,
      expectedSourceRevision: testCase.fixture.revision,
      artifactId: testCase.fixture.manifest.artifactId,
      promotionVerifier: () => ({ authorized: true }),
    }), /unknown option promotionVerifier/u);
  });

  test("production build runner refuses a synthetic store before resolving Cargo", async () => {
    const testCase = await createCase();
    const installed = await installCase(testCase);
    const markerRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "ibex-fake-cargo-"));
    temporaryRoots.add(markerRoot);
    const marker = path.join(markerRoot, "cargo-ran");
    const fakeCargo = path.join(markerRoot, "cargo");
    await fsp.writeFile(fakeCargo, `#!/bin/sh\n/usr/bin/touch ${JSON.stringify(marker)}\nexit 91\n`, { mode: 0o700 });
    const priorPath = process.env.PATH;
    process.env.PATH = markerRoot;
    try {
      await assert.rejects(() => runPortableHermesCargoProduction({
        repoRoot: testCase.repoRoot,
        expectedSourceRevision: testCase.fixture.revision,
        artifactId: installed.manifest.artifactId,
        archiveDigest: rawDigest(testCase.fixture.archive),
        cargoArgs: ["build"],
      }), /ENOENT|portable artifact store entry|test-only|receipt|schema|checked Git|not a git repository/u);
    } finally {
      if (priorPath === undefined) delete process.env.PATH;
      else process.env.PATH = priorPath;
    }
    await assert.rejects(() => fsp.lstat(marker), { code: "ENOENT" });
  });

  test("fresh build preflight rejects every mutated attestation claim before Cargo", async (t) => {
    for (const [name, mutate, pattern] of [
      ["subject", (result) => { result.subject.name = "attacker.tar.gz"; }, /subject/u],
      ["repository", (result) => { result.signer.repository = "attacker/ibex"; }, /repository/u],
      ["workflow", (result) => { result.signer.workflowPath = ".github/workflows/attacker.yml"; }, /workflow|SAN/u],
      ["ref", (result) => { result.signer.sourceRef = "refs/heads/attacker"; }, /sourceRef|SAN/u],
      ["revision", (result) => { result.signer.sourceRevision = "0".repeat(40); }, /sourceRevision/u],
      ["runner", (result) => { result.signer.runnerEnvironment = "self-hosted"; }, /runnerEnvironment/u],
      ["trusted root", (result) => { result.trustRoot.sha256 = "0".repeat(64); }, /trust root|trustRoot/u],
    ]) {
      await t.test(name, async () => {
        const testCase = await createCase();
        const installed = await installCase(testCase);
        let cargoSpawned = false;
        await assert.rejects(() => runPortableHermesCargoCore({
          repoRoot: testCase.repoRoot,
          expectedSourceRevision: testCase.fixture.revision,
          artifactId: installed.manifest.artifactId,
          archiveDigest: rawDigest(testCase.fixture.archive),
          cargoArgs: ["build"],
        }, {
          verifyStore: (selection) => verifyPortableEngineStore(selection, dependencies({
            verifyAttestation: async (input) => {
              const result = JSON.parse(mockVerificationResult(input).toString("utf8"));
              mutate(result);
              return Buffer.from(`${canonicalJson(result)}\n`, "utf8");
            },
          })),
          loadCargoTargetMap: async () => { throw new Error("target-map marker ran before refusal"); },
          requireCleanCheckout: async () => { throw new Error("clean-check marker ran before refusal"); },
          spawnCargo: () => {
            cargoSpawned = true;
            throw new Error("Cargo marker ran before refusal");
          },
        }), pattern);
        assert.equal(cargoSpawned, false);
      });
    }
  });

  test("diagnostic A mints one live capability and an exact LF-terminated admission marker", {
    skip: process.platform !== "darwin",
  }, async () => {
    const temporaryRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "ibex-portable-build-live-"));
    temporaryRoots.add(temporaryRoot);
    const root = await fsp.realpath(temporaryRoot);
    await fsp.mkdir(path.join(root, "src"));
    await fsp.mkdir(path.join(root, "scripts"));
    await fsp.writeFile(path.join(root, ".gitignore"), "/target\n");
    await fsp.writeFile(path.join(root, "Cargo.toml"), `[package]\nname = "live-probe"\nversion = "0.1.0"\nedition = "2021"\n`);
    await fsp.writeFile(path.join(root, "src/main.rs"), "fn main() {}\n");
    await fsp.copyFile(
      path.join(sourceRepo, "scripts/portable-engine-rustc-wrapper.mjs"),
      path.join(root, "scripts/portable-engine-rustc-wrapper.mjs"),
    );
    execFileSync("/usr/bin/git", ["init", "-q"], { cwd: root });
    execFileSync("/usr/bin/git", ["config", "user.name", "Portable Build Test"], { cwd: root });
    execFileSync("/usr/bin/git", ["config", "user.email", "portable-build@example.invalid"], { cwd: root });
    execFileSync("/usr/bin/git", ["add", ".gitignore", "Cargo.toml", "src/main.rs", "scripts/portable-engine-rustc-wrapper.mjs"], { cwd: root });
    execFileSync("/usr/bin/git", ["commit", "-qm", "fixture A"], { cwd: root });
    const sourceRevision = execFileSync("/usr/bin/git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
    const artifactId = `sha256-${"A".repeat(43)}`;
    const archiveDigest = `sha256-${"a".repeat(64)}`;
    const artifactRoot = path.join(root, "target/hermes-artifacts", artifactId);
    const transportRoot = path.join(artifactRoot, "LOCAL/transport", archiveDigest);
    await fsp.mkdir(transportRoot, { recursive: true });
    await fsp.chmod(path.join(root, "target/hermes-artifacts"), 0o700);
    await fsp.writeFile(path.join(transportRoot, "attestation-verification.json"), "{}\n");
    const promotionAdmission = checkedPromotionAdmission({ sourceRevision, artifactId });
    const verified = {
      authorized: false,
      promotionAdmission,
      artifactRoot,
      manifest: { target: { triple: "aarch64-apple-darwin" } },
      transport: {
        receipt: {
          manifestDigest: `sha256-${"B".repeat(43)}`,
          verificationPolicyDigest: `sha256-${"C".repeat(43)}`,
          provenanceBundleDigest: `sha256-${"b".repeat(64)}`,
        },
      },
    };
    let capturedAdmission;
    let capturedReceipt;
    const outcome = await runPortableHermesCargoCore({
      repoRoot: root,
      expectedSourceRevision: sourceRevision,
      artifactId,
      archiveDigest,
      cargoArgs: ["build"],
    }, {
      verifyStore: async () => verified,
      loadCargoTargetMap: loadProductionCargoTargetMap,
      requireCleanCheckout: requireProductionCleanCheckout,
      spawnCargo: (_arguments, options) => {
        capturedAdmission = fs.readFileSync(options.env.IBEX_PORTABLE_HERMES_PROMOTION_ADMISSION);
        capturedReceipt = JSON.parse(fs.readFileSync(options.env.IBEX_PORTABLE_HERMES_PREFLIGHT_RECEIPT, "utf8"));
        return spawn(process.execPath, ["-e", `
          const fs = require("node:fs");
          const net = require("node:net");
          const path = require("node:path");
          const receipt = JSON.parse(fs.readFileSync(process.env.IBEX_PORTABLE_HERMES_PREFLIGHT_RECEIPT, "utf8"));
          process.chdir(path.dirname(process.env.IBEX_PORTABLE_HERMES_PREFLIGHT_RECEIPT));
          const socket = net.createConnection("claim.sock");
          let response = "";
          socket.on("connect", () => socket.end(JSON.stringify({ nonce: receipt.nonce, runnerPid: receipt.runnerPid, schema: "ibex/portable-engine-build-preflight-claim/1" }) + "\\n"));
          socket.on("data", (chunk) => { response += chunk; });
          socket.on("end", () => process.exit(response === "authorized:" + receipt.nonce + "\\n" ? 0 : 91));
          socket.on("error", () => process.exit(92));
        `], { ...options, stdio: "ignore" });
      },
    });
    assert.deepEqual(outcome, { code: 0, signal: null });
    assert.deepEqual(capturedAdmission, Buffer.from(`${canonicalJson(promotionAdmission)}\n`, "utf8"));
    assert.equal(capturedAdmission.at(-1), 0x0a);
    assert.equal(capturedReceipt.currentRevision, sourceRevision);
    assert.equal(capturedReceipt.promotionAdmissionDigest, rawDigest(capturedAdmission));
    assert.equal(
      capturedReceipt.promotionAdmissionVerificationDigest,
      promotionAdmission.verificationDigest,
    );
    await assert.rejects(
      () => fsp.lstat(capturedReceipt.promotionAdmissionPath),
      { code: "ENOENT" },
    );
  });

  test("production build checkout and Cargo target discovery distinguish diagnostic A, admitted C, and refused D", async () => {
    const temporaryRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "ibex-portable-build-checkout-"));
    temporaryRoots.add(temporaryRoot);
    const root = await fsp.realpath(temporaryRoot);
    await fsp.mkdir(path.join(root, "src"));
    await fsp.writeFile(path.join(root, "Cargo.toml"), `[package]\nname = "clean-probe"\nversion = "0.1.0"\nedition = "2021"\n`);
    await fsp.writeFile(path.join(root, "src/lib.rs"), "pub fn clean() {}\n");
    execFileSync("/usr/bin/git", ["init", "-q"], { cwd: root });
    execFileSync("/usr/bin/git", ["config", "user.name", "Portable Build Test"], { cwd: root });
    execFileSync("/usr/bin/git", ["config", "user.email", "portable-build@example.invalid"], { cwd: root });
    execFileSync("/usr/bin/git", ["add", "Cargo.toml", "src/lib.rs"], { cwd: root });
    execFileSync("/usr/bin/git", ["commit", "-qm", "fixture"], { cwd: root });
    await fsp.mkdir(path.join(root, "target"));
    const sourceRevision = execFileSync("/usr/bin/git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
    const artifactId = `sha256-${"A".repeat(43)}`;
    const diagnostic = checkedPromotionAdmission({ sourceRevision, artifactId });
    assert.equal(validateCheckedPromotionAdmission({
      verified: {
        authorized: false,
        manifest: { target: { triple: "aarch64-apple-darwin" } },
        promotionAdmission: diagnostic,
      },
      expectedSourceRevision: sourceRevision,
      artifactId,
    }).authorized, false);
    await requireProductionCleanCheckout({
      repoRoot: root,
      expectedCurrentRevision: sourceRevision,
    });

    await fsp.writeFile(path.join(root, "promotion-only.md"), "checked promotion\n");
    execFileSync("/usr/bin/git", ["add", "promotion-only.md"], { cwd: root });
    execFileSync("/usr/bin/git", ["commit", "-qm", "promotion"], { cwd: root });
    const currentRevision = execFileSync("/usr/bin/git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
    const admitted = checkedPromotionAdmission({
      sourceRevision,
      currentRevision,
      authorized: true,
      artifactId,
    });
    assert.equal(new Set([
      admitted.sourceRevision,
      admitted.promotionTopicRevision,
      admitted.currentRevision,
    ]).size, 3, "real A/P/C fixture must keep all lineage revisions distinct");
    assert.equal(validateCheckedPromotionAdmission({
      verified: {
        authorized: true,
        manifest: { target: { triple: "aarch64-apple-darwin" } },
        promotionAdmission: admitted,
      },
      expectedSourceRevision: sourceRevision,
      artifactId,
    }).authorized, true);
    await requireProductionCleanCheckout({
      repoRoot: root,
      expectedCurrentRevision: currentRevision,
    });
    const targetMap = await loadProductionCargoTargetMap({
      repoRoot: root,
      expectedSourceRevision: sourceRevision,
    });
    assert.deepEqual(targetMap.targets, [{
      kind: "lib",
      name: "clean_probe",
      crateName: "clean_probe",
      source: "src/lib.rs",
    }]);
    for (const [name, mutate, pattern] of [
      ["source", (record) => { record.sourceRevision = "c".repeat(40); }, /source revision/u],
      ["artifact", (record) => { record.portableArtifactId = `sha256-${"B".repeat(43)}`; }, /portable artifact/u],
      ["target", (record) => { record.targetTriple = "x86_64-apple-darwin"; }, /verified target/u],
      ["authorization", (_record, verified) => { verified.authorized = false; }, /authorization differs/u],
      ["digest", (record) => { record.verificationDigest = `sha256-${"Z".repeat(43)}`; }, /does not bind/u],
    ]) {
      const record = structuredClone(admitted);
      const verified = {
        authorized: true,
        manifest: { target: { triple: "aarch64-apple-darwin" } },
        promotionAdmission: record,
      };
      mutate(record, verified);
      assert.throws(
        () => validateCheckedPromotionAdmission({
          verified,
          expectedSourceRevision: sourceRevision,
          artifactId,
        }),
        pattern,
        `${name} mismatch was admitted`,
      );
    }

    await fsp.writeFile(path.join(root, "unrelated-d.txt"), "D must not degrade to A\n");
    execFileSync("/usr/bin/git", ["add", "unrelated-d.txt"], { cwd: root });
    execFileSync("/usr/bin/git", ["commit", "-qm", "unrelated D"], { cwd: root });
    await assert.rejects(
      () => requireProductionCleanCheckout({
        repoRoot: root,
        expectedCurrentRevision: currentRevision,
      }),
      /differs from checked promotion current revision/u,
    );

    const dRevision = execFileSync("/usr/bin/git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
    await fsp.writeFile(path.join(root, "untracked.rs"), "attacker\n");
    await assert.rejects(
      () => requireProductionCleanCheckout({
        repoRoot: root,
        expectedCurrentRevision: dRevision,
      }),
      /clean tracked and untracked/u,
    );
    await fsp.unlink(path.join(root, "untracked.rs"));
    const manifest = path.join(root, "Cargo.toml");
    const external = path.join(root, "external-Cargo.toml");
    await fsp.rename(manifest, external);
    await fsp.symlink(external, manifest);
    await assert.rejects(
      () => loadProductionCargoTargetMap({ repoRoot: root, expectedSourceRevision: sourceRevision }),
      /Cargo manifest is redirected/u,
    );
  });

  test("portable build runner rejects ambient Cargo and Rust selector surfaces", async () => {
    const options = (cargoArgs) => ({
      repoRoot: sourceRepo,
      expectedSourceRevision: "0".repeat(40),
      artifactId: `sha256-${"A".repeat(43)}`,
      archiveDigest: `sha256-${"0".repeat(64)}`,
      cargoArgs,
    });
    const dependencies = (onVerify) => ({
      verifyStore: async () => { onVerify(); },
      loadCargoTargetMap: async () => ({}),
      requireCleanCheckout: async () => {},
      spawnCargo: () => { throw new Error("Cargo must not spawn"); },
    });
    const previous = process.env.RUSTFLAGS;
    process.env.RUSTFLAGS = "-C link-arg=-Wl,-rpath,/attacker";
    let verifierCalled = false;
    try {
      await assert.rejects(
        () => runPortableHermesCargoCore(options(["build"]), dependencies(() => { verifierCalled = true; })),
        /ambient Cargo\/Rust selector variables are forbidden.*RUSTFLAGS/u,
      );
    } finally {
      if (previous === undefined) delete process.env.RUSTFLAGS;
      else process.env.RUSTFLAGS = previous;
    }
    assert.equal(verifierCalled, false);
    for (const [cargoArgs, pattern] of [
      [["build", "--manifest-path", "attacker/Cargo.toml"], /manifest-path/u],
      [["build", "--workspace"], /workspace\/package-set/u],
      [["build", "-pattacker"], /package overrides/u],
    ]) {
      verifierCalled = false;
      await assert.rejects(
        () => runPortableHermesCargoCore(options(cargoArgs), dependencies(() => { verifierCalled = true; })),
        pattern,
      );
      assert.equal(verifierCalled, false);
    }
  });

  test("source-level caller guard confines the injectable core to the production wrapper and test-only harness", async () => {
    const scriptsRoot = path.join(sourceRepo, "scripts");
    const coreBasename = "portable-engine-installer-core.mjs";
    const harnessBasename = "portable-engine-installer-test-harness.mjs";
    const buildCoreBasename = "portable-engine-build-preflight-core.mjs";
    const buildHarnessBasename = "portable-engine-build-preflight-test-harness.mjs";
    const classifyCallers = (sources) => {
      const productionSources = sources.filter(([name]) => /\.(?:[cm]?[jt]s|[jt]sx|rs|sh)$/u.test(name) && !/(?:^|\/)tests?(?:\/|$)|\.test\.[^.]+$/u.test(name));
      return {
        core: productionSources.filter(([name, source]) => name !== `scripts/${coreBasename}` && source.includes(coreBasename)).map(([name]) => name).sort(compareUtf8),
        harness: productionSources.filter(([name, source]) => name !== `scripts/${harnessBasename}` && source.includes(harnessBasename)).map(([name]) => name).sort(compareUtf8),
        buildCore: productionSources.filter(([name, source]) => name !== `scripts/${buildCoreBasename}` && source.includes(buildCoreBasename)).map(([name]) => name).sort(compareUtf8),
        buildHarness: productionSources.filter(([name, source]) => name !== `scripts/${buildHarnessBasename}` && source.includes(buildHarnessBasename)).map(([name]) => name).sort(compareUtf8),
      };
    };
    const repositorySources = [];
    const repositoryFiles = gitBytes(["ls-files", "-co", "--exclude-standard", "-z"]).toString("utf8").split("\0").filter(Boolean);
    for (const name of repositoryFiles) {
      if (!/\.(?:[cm]?[jt]s|[jt]sx|rs|sh)$/u.test(name)) continue;
      repositorySources.push([name, await fsp.readFile(path.join(sourceRepo, name), "utf8")]);
    }
    assert.deepEqual(classifyCallers(repositorySources), {
      core: ["scripts/portable-engine-installer-test-harness.mjs", "scripts/portable-engine-installer.mjs"],
      harness: ["scripts/portable-engine-build-preflight-test-harness.mjs"],
      buildCore: ["scripts/portable-engine-build-preflight-test-harness.mjs", "scripts/run-portable-hermes-cargo.mjs"],
      buildHarness: [],
    });
    assert.deepEqual(classifyCallers([
      ["src/nested/rogue.mjs", "await import('../../scripts/portable-engine-installer-core.mjs');"],
      ["src/nested/rogue-single-quotes.mjs", "import '../../scripts/portable-engine-installer-test-harness.mjs';"],
    ]), {
      core: ["src/nested/rogue.mjs"],
      harness: ["src/nested/rogue-single-quotes.mjs"],
      buildCore: [],
      buildHarness: [],
    });
    const cli = await fsp.readFile(path.join(scriptsRoot, "install-portable-hermes.mjs"), "utf8");
    assert.match(cli, /from "\.\/portable-engine-installer\.mjs"/u);
    assert.doesNotMatch(cli, /portable-engine-installer-(?:core|test-harness)/u);
    assert.match(cli, /installPortableEngine\(options\)/u);
    assert.doesNotMatch(cli, /installPortableEngine\(options\s*,/u);
    const core = await fsp.readFile(path.join(scriptsRoot, "portable-engine-installer-core.mjs"), "utf8");
    assert.doesNotMatch(core, /\boptions\.context\b/u);
    assert.match(core, /const SYSTEM_GIT = "\/usr\/bin\/git"/u);
    assert.doesNotMatch(core, /process\.env\.PATH/u);
    assert.match(core, /GIT_NO_LAZY_FETCH: "1"/u);
    assert.match(core, /GIT_NO_REPLACE_OBJECTS: "1"/u);
    const packageDocument = JSON.parse(await fsp.readFile(path.join(sourceRepo, "package.json"), "utf8"));
    assert.equal(packageDocument.scripts["install:portable-hermes"], "node scripts/install-portable-hermes.mjs");
  });

  test("checked revision reads independently traverse and hash the selected commit graph", async () => {
    const revision = systemGitBytes(sourceRepo, ["rev-parse", "HEAD"]).toString("ascii").trim();
    assert.deepEqual(
      readCheckedRevisionFile(sourceRepo, revision, "schemas/portable-engine-provenance-trust-policy-v1.json"),
      systemGitBytes(sourceRepo, ["show", `${revision}:schemas/portable-engine-provenance-trust-policy-v1.json`]),
    );
    const patches = listCheckedRevisionFiles(sourceRepo, revision, "patches/hermes");
    assert(patches.length > 0);
    assert(patches.every((pathname, index) => pathname.startsWith("patches/hermes/") && (index === 0 || patches[index - 1] < pathname)));
    const control = resolveGitControlPaths(sourceRepo);
    assert.deepEqual(Object.keys(control).sort(), ["commonDir", "gitDir", "objectDir"]);
    assert(path.isAbsolute(control.gitDir) && path.isAbsolute(control.commonDir) && path.isAbsolute(control.objectDir));
    await validateGitControlPlane(sourceRepo);
  });

  test("checked revision reads reject a different blob stored under the selected object ID", async () => {
    const fixture = await createLooseObjectRepository();
    const blobId = systemGitBytes(fixture.repoRoot, ["rev-parse", `${fixture.revision}:authority/policy.json`]).toString("ascii").trim();
    await writeLooseObjectAtId(fixture.repoRoot, blobId, "blob", Buffer.from("{\"trusted\":false}\n"));
    assert.throws(
      () => readCheckedRevisionFile(fixture.repoRoot, fixture.revision, "authority/policy.json"),
      /failed independent content hashing|cannot read checked Git blob/u,
    );
  });

  test("checked revision reads reject a different commit stored under the selected object ID", async () => {
    const fixture = await createLooseObjectRepository();
    const commitBytes = systemGitBytes(fixture.repoRoot, ["cat-file", "commit", fixture.revision]);
    await writeLooseObjectAtId(fixture.repoRoot, fixture.revision, "commit", Buffer.concat([commitBytes, Buffer.from("substituted\n")]));
    assert.throws(
      () => readCheckedRevisionFile(fixture.repoRoot, fixture.revision, "authority/policy.json"),
      /failed independent content hashing|cannot read checked Git commit/u,
    );
  });

  test("checked revision reads reject a substituted nested tree object", async () => {
    const fixture = await createLooseObjectRepository();
    const treeId = systemGitBytes(fixture.repoRoot, ["rev-parse", `${fixture.revision}:authority`]).toString("ascii").trim();
    const attackerBytes = Buffer.from("{\"trusted\":false}\n");
    const attackerBlobId = gitObjectId("sha1", "blob", attackerBytes);
    await writeLooseObjectAtId(fixture.repoRoot, attackerBlobId, "blob", attackerBytes);
    const substitutedTree = Buffer.concat([
      Buffer.from("100644 policy.json\0", "ascii"),
      Buffer.from(attackerBlobId, "hex"),
    ]);
    await writeLooseObjectAtId(fixture.repoRoot, treeId, "tree", substitutedTree);
    assert.throws(
      () => readCheckedRevisionFile(fixture.repoRoot, fixture.revision, "authority/policy.json"),
      /failed independent content hashing|cannot read checked Git tree/u,
    );
  });

  test("external Git control paths must satisfy the checkout ownership premise", async (t) => {
    async function gitControlCase() {
      const testCase = await createCase();
      const commonDir = path.join(testCase.root, "git-common");
      const objectDir = path.join(commonDir, "objects");
      await fsp.mkdir(objectDir, { recursive: true, mode: 0o700 });
      await fsp.writeFile(path.join(testCase.repoRoot, ".git"), "gitdir: external\n", { mode: 0o600 });
      return {
        testCase,
        commonDir,
        objectDir,
        resolveGitControlPaths: () => ({ gitDir: commonDir, commonDir, objectDir }),
      };
    }

    await t.test("writable external object directory", async () => {
      const fixture = await gitControlCase();
      await fsp.chmod(fixture.objectDir, 0o777);
      await expectRejected(fixture.testCase, /Git object directory.*group\/world-writable/u, {
        resolveGitControlPaths: fixture.resolveGitControlPaths,
      });
    });

    await t.test("HTTP object alternate", async () => {
      const fixture = await gitControlCase();
      const infoDir = path.join(fixture.objectDir, "info");
      await fsp.mkdir(infoDir, { mode: 0o700 });
      await fsp.writeFile(path.join(infoDir, "http-alternates"), "https://example.invalid/objects\n", { mode: 0o600 });
      await expectRejected(fixture.testCase, /Git HTTP object alternates are forbidden/u, {
        resolveGitControlPaths: fixture.resolveGitControlPaths,
      });
    });

    await t.test("writable local object alternate", async () => {
      const fixture = await gitControlCase();
      const infoDir = path.join(fixture.objectDir, "info");
      const alternate = path.join(fixture.testCase.root, "alternate-objects");
      await fsp.mkdir(infoDir, { mode: 0o700 });
      await fsp.mkdir(alternate, { mode: 0o777 });
      await fsp.chmod(alternate, 0o777);
      await fsp.writeFile(path.join(infoDir, "alternates"), `${alternate}\n`, { mode: 0o600 });
      await expectRejected(fixture.testCase, /Git object directory.*group\/world-writable/u, {
        resolveGitControlPaths: fixture.resolveGitControlPaths,
      });
    });
  });

  test("requires owned, non-shared, ACL-free checkout and store control nodes", async (t) => {
    await t.test("effective UID owns the checkout", async () => {
      const testCase = await createCase();
      const differentUid = (typeof process.geteuid === "function" ? process.geteuid() : 0) + 1;
      await expectRejected(testCase, /effective-UID ownership/u, { effectiveUid: differentUid });
    });
    await t.test("checkout is not group writable", async () => {
      const testCase = await createCase();
      await fsp.chmod(testCase.repoRoot, 0o770);
      await expectRejected(testCase, /group\/world-writable/u);
    });
    await t.test("checkout parent does not grant alternate-principal rename authority", async () => {
      const testCase = await createCase();
      await fsp.chmod(testCase.root, 0o777);
      await expectRejected(testCase, /checkout ancestor .*group\/world-writable/u);
    });
    await t.test("write-enabling ancestor ACLs are rejected", async () => {
      const testCase = await createCase();
      const unsafeAncestor = await fsp.realpath(testCase.root);
      await expectRejected(testCase, /write-enabling macOS extended ACLs/u, {
        hasWriteEnablingExtendedAcl: async (filePath) => filePath === unsafeAncestor,
      });
    });
    await t.test("checkout ancestry rename and substitution is detected", async () => {
      const testCase = await createCase();
      let substituted = false;
      await expectRejected(testCase, /checkout ancestry changed during validation/u, {
        onCheckoutAncestryValidated: async () => {
          assert.equal(substituted, false);
          substituted = true;
          await fsp.rename(testCase.repoRoot, `${testCase.repoRoot}.original`);
          await fsp.mkdir(testCase.repoRoot, { mode: 0o700 });
        },
      });
      assert.equal(substituted, true);
    });
    await t.test("checkout special mode bits are rejected", async () => {
      const testCase = await createCase();
      await fsp.chmod(testCase.repoRoot, 0o1700);
      await expectRejected(testCase, /setuid, setgid, and sticky mode bits/u);
    });
    await t.test("target ancestry is not world writable", async () => {
      const testCase = await createCase();
      await fsp.mkdir(path.join(testCase.repoRoot, "target"), { mode: 0o700 });
      await fsp.chmod(path.join(testCase.repoRoot, "target"), 0o707);
      await expectRejected(testCase, /group\/world-writable/u);
    });
    await t.test("private store mode 0700 excludes special mode bits", async () => {
      const testCase = await createCase();
      const storeRoot = path.join(testCase.repoRoot, "target", "hermes-artifacts-test-only");
      await fsp.mkdir(storeRoot, { recursive: true, mode: 0o700 });
      await fsp.chmod(path.join(testCase.repoRoot, "target"), 0o700);
      await fsp.chmod(storeRoot, 0o1700);
      await expectRejected(testCase, /setuid, setgid, and sticky mode bits/u);
    });
    await t.test("store root remains private mode 0700", async () => {
      const testCase = await createCase();
      const installed = await installCase(testCase);
      const storeRoot = path.dirname(installed.artifactRoot);
      await fsp.chmod(storeRoot, 0o755);
      await assert.rejects(() => verifyPortableEngineStore({
        repoRoot: testCase.repoRoot,
        expectedSourceRevision: testCase.fixture.revision,
        artifactId: installed.manifest.artifactId,
      }, dependencies()), /expected mode 700/u);
    });
    await t.test("macOS extended ACLs are outside the trusted-store premise", async () => {
      const testCase = await createCase();
      const checkout = await fsp.realpath(testCase.repoRoot);
      if (process.platform === "darwin") {
        execFileSync("/bin/chmod", ["+a", "everyone deny write", checkout]);
        try {
          assert.equal(detectMacOsExtendedAcl(checkout), true);
          await expectRejected(testCase, /extended ACLs are forbidden/u, { hasExtendedAcl: detectMacOsExtendedAcl });
        } finally {
          execFileSync("/bin/chmod", ["-N", checkout]);
        }
      } else {
        await expectRejected(testCase, /extended ACLs are forbidden/u, {
          hasExtendedAcl: async (filePath) => filePath === checkout,
        });
      }
    });
  });

  test("strict-validates the canonical verifier result before archive parsing", async () => {
    const testCase = await createCase();
    let parsingStarted = false;
    await expectRejected(testCase, /attacker/u, {
      verifyAttestation: async (input) => {
        const result = JSON.parse(mockVerificationResult(input).toString("utf8"));
        result.attacker = true;
        return Buffer.from(`${canonicalJson(result)}\n`, "utf8");
      },
      onArchiveParseStart: () => { parsingStarted = true; },
    });
    assert.equal(parsingStarted, false);
  });

  test("rejects traversal, absolute, ADS, reserved-name, hardlink, and special members", async (t) => {
    const attacks = [
      ["traversal", { path: "payload/../escape", kind: "regular", bytes: Buffer.from("x"), executable: false }, /pseudo path segment/u],
      ["absolute", { path: "/payload/escape", kind: "regular", bytes: Buffer.from("x"), executable: false }, /absolute\/UNC\/device/u],
      ["ADS", { path: "payload/share/name:stream", kind: "regular", bytes: Buffer.from("x"), executable: false }, /ADS, drive, and backslash/u],
      ["reserved", { path: "payload/share/CON.txt", kind: "regular", bytes: Buffer.from("x"), executable: false }, /reserved device/u],
      ["trailing dot", { path: "payload/share/name.", kind: "regular", bytes: Buffer.from("x"), executable: false }, /trailing dot\/space/u],
      ["non-ASCII equivalence", { path: "payload/share/\u00e9", kind: "regular", bytes: Buffer.from("x"), executable: false }, /printable ASCII/u],
      ["hardlink", { path: "payload/share/hard", kind: "regular", bytes: Buffer.alloc(0), executable: false, typeOverride: "1" }, /hardlink, special/u],
      ["character device", { path: "payload/share/device", kind: "regular", bytes: Buffer.alloc(0), executable: false, typeOverride: "3" }, /hardlink, special/u],
    ];
    for (const [name, member, pattern] of attacks) {
      await t.test(name, async () => {
        const fixture = buildFixture();
        fixture.archive = rawUstarGzip([...fixture.members, member].sort((left, right) => compareUtf8(left.path, right.path)));
        await expectRejected(await createCase(fixture), pattern);
      });
    }
  });

  test("rejects target-filesystem collisions and escaping or cyclic symlinks", async (t) => {
    const cases = [
      ["case-fold collision", (manifest) => manifest.entries.push(
        { kind: "directory", role: "metadata", path: "Case" },
        { kind: "directory", role: "metadata", path: "case" },
      ), [
        { path: "payload/Case", kind: "directory" },
        { path: "payload/case", kind: "directory" },
      ], /target-filesystem collision/u],
      ["symlink escape", (manifest) => manifest.entries.push(
        { kind: "directory", role: "metadata", path: "links" },
        { kind: "symlink", role: "metadata", path: "links/escape", target: "../../outside" },
      ), [
        { path: "payload/links", kind: "directory" },
        { path: "payload/links/escape", kind: "symlink", target: "../../outside" },
      ], /escapes payload/u],
      ["symlink cycle", (manifest) => manifest.entries.push(
        { kind: "directory", role: "metadata", path: "cycle" },
        { kind: "symlink", role: "metadata", path: "cycle/a", target: "b" },
        { kind: "symlink", role: "metadata", path: "cycle/b", target: "a" },
      ), [
        { path: "payload/cycle", kind: "directory" },
        { path: "payload/cycle/a", kind: "symlink", target: "b" },
        { path: "payload/cycle/b", kind: "symlink", target: "a" },
      ], /symlink cycle/u],
      ["symlink depth", (manifest) => {
        manifest.entries.push({ kind: "directory", role: "metadata", path: "deep" });
        for (let index = 0; index < 34; index += 1) {
          manifest.entries.push({
            kind: "symlink",
            role: "metadata",
            path: `deep/link-${String(index).padStart(2, "0")}`,
            target: index === 33 ? "target" : `link-${String(index + 1).padStart(2, "0")}`,
          });
        }
        manifest.entries.push({ kind: "regular", role: "metadata", path: "deep/target", digest: rawDigest(Buffer.from("x")), size: 1, executable: false });
      }, [], /symlink resolution exceeds/u],
    ];
    for (const [name, mutate, members, pattern] of cases) {
      await t.test(name, async () => {
        const fixture = replaceManifest(buildFixture(), mutate, members);
        await expectRejected(await createCase(fixture), pattern);
      });
    }
  });

  test("rejects undeclared, missing, duplicate, digest-drifted, and size-drifted members", async (t) => {
    const base = buildFixture();
    const runtimePath = `payload/${base.manifest.runtimeComponent}`;
    const cases = [
      ["undeclared", () => [...base.members, { path: "payload/share/unexpected", kind: "regular", bytes: Buffer.from("x"), executable: false }], /undeclared archive member/u],
      ["missing", () => base.members.filter((member) => member.path !== runtimePath), /archive exact membership/u],
      ["duplicate", () => {
        const original = base.members.find((member) => member.path === "payload/include/jsi/jsi.h");
        return [...base.members, { ...original, bytes: Buffer.from(original.bytes) }];
      }, /strict canonical order|collision/u],
      ["digest drift", () => base.members.map((member) => member.path === runtimePath ? { ...member, bytes: Buffer.from("tampered runtime bytes") } : member), /archive size differs|extracted digest differs/u],
      ["size drift", () => base.members.map((member) => member.path === runtimePath ? { ...member, bytes: Buffer.concat([member.bytes, Buffer.from("x")]) } : member), /archive size differs/u],
    ];
    for (const [name, mutate, pattern] of cases) {
      await t.test(name, async () => {
        const fixture = { ...base, archive: rawUstarGzip(mutate().sort((left, right) => compareUtf8(left.path, right.path))) };
        await expectRejected(await createCase(fixture), pattern);
      });
    }
  });

  test("enforces member-count and per-file resource limits before allocation", async (t) => {
    await t.test("member count", async () => {
      const fixture = replaceManifest(buildFixture(), (manifest) => {
        for (let index = 0; index < 4094; index += 1) {
          manifest.entries.push({ kind: "directory", role: "metadata", path: `limit-${String(index).padStart(4, "0")}` });
        }
      });
      await expectRejected(await createCase(fixture), /member count|exact membership/u);
    });
    await t.test("declared regular size", async () => {
      const fixture = replaceManifest(buildFixture(), (manifest) => {
        manifest.entries.push({
          kind: "regular",
          role: "metadata",
          path: "oversized",
          digest: `sha256-${"0".repeat(64)}`,
          size: 536_870_913,
          executable: false,
        });
      });
      await expectRejected(await createCase(fixture), /declared size exceeds policy/u);
    });
    await t.test("declared cumulative expansion", async () => {
      const fixture = replaceManifest(buildFixture(), (manifest) => {
        for (let index = 0; index < 5; index += 1) {
          manifest.entries.push({
            kind: "regular",
            role: "metadata",
            path: `expanded-${index}`,
            digest: `sha256-${String(index).repeat(64)}`,
            size: 500_000_000,
            executable: false,
          });
        }
      });
      await expectRejected(await createCase(fixture), /expanded bytes exceed policy/u);
    });
    await t.test("JSON nesting", async () => {
      const fixture = buildFixture();
      const nested = Buffer.from(`${"[".repeat(65)}0${"]".repeat(65)}`, "utf8");
      fixture.archive = rawUstarGzip([
        { path: "META-INF", kind: "directory" },
        { path: "META-INF/portable-engine-manifest.json", kind: "regular", bytes: nested, executable: false },
        { path: "payload", kind: "directory" },
      ]);
      await expectRejected(await createCase(fixture), /JSON nesting exceeds/u);
    });
  });

  test("repeated truncated members close extractor output handles and both streams", async () => {
    const base = buildFixture();
    const partialManifest = base.manifestBytes.subarray(0, Math.max(1, Math.floor(base.manifestBytes.length / 3)));
    const truncatedTar = Buffer.concat([
      rawTarHeader({ path: "META-INF", kind: "directory" }),
      rawTarHeader({ path: "META-INF/portable-engine-manifest.json", kind: "regular", bytes: base.manifestBytes, executable: false }),
      partialManifest,
    ]);
    const fixture = { ...base, archive: gzipSync(truncatedTar, { level: 1, mtime: 0 }) };
    const descriptorDirectory = process.platform === "linux" ? "/proc/self/fd" : "/dev/fd";
    const before = (await fsp.readdir(descriptorDirectory)).length;
    for (let attempt = 0; attempt < 24; attempt += 1) {
      await expectRejected(await createCase(fixture), /ustar stream is truncated/u);
    }
    const after = (await fsp.readdir(descriptorDirectory)).length;
    assert(after <= before + 2, `file descriptors grew from ${before} to ${after}`);
  });

  test("repeated extracted-file sync failures close the output handle and both streams", async () => {
    const descriptorDirectory = process.platform === "linux" ? "/proc/self/fd" : "/dev/fd";
    const before = (await fsp.readdir(descriptorDirectory)).length;
    let syncAttempts = 0;
    for (let attempt = 0; attempt < 24; attempt += 1) {
      await expectRejected(await createCase(), /fixture extracted-file sync failure/u, {
        syncExtractedFile: async () => {
          syncAttempts += 1;
          throw new Error("fixture extracted-file sync failure");
        },
      });
    }
    const after = (await fsp.readdir(descriptorDirectory)).length;
    assert.equal(syncAttempts, 24);
    assert(after <= before + 2, `file descriptors grew from ${before} to ${after}`);
  });

  test("rejects partial and mutated existing stores instead of trusting artifactId names", async (t) => {
    await t.test("missing completion marker", async () => {
      const testCase = await createCase();
      const installed = await installCase(testCase);
      const local = path.join(installed.artifactRoot, "LOCAL");
      await fsp.chmod(local, 0o755);
      await fsp.unlink(path.join(local, "COMPLETE"));
      await fsp.chmod(local, 0o555);
      await assert.rejects(() => verifyPortableEngineStore({
        repoRoot: testCase.repoRoot,
        expectedSourceRevision: testCase.fixture.revision,
        artifactId: installed.manifest.artifactId,
      }, dependencies()), /COMPLETE|completion/u);
    });
    await t.test("payload mutation", async () => {
      const testCase = await createCase();
      const installed = await installCase(testCase);
      const runtime = path.join(installed.artifactRoot, "payload", ...installed.manifest.runtimeComponent.split("/"));
      await fsp.chmod(runtime, 0o600);
      await fsp.writeFile(runtime, "mutated");
      await assert.rejects(() => verifyPortableEngineStore({
        repoRoot: testCase.repoRoot,
        expectedSourceRevision: testCase.fixture.revision,
        artifactId: installed.manifest.artifactId,
      }, dependencies()), /mode class|size\/digest drift/u);
    });
    await t.test("payload hardlink substitution", async () => {
      const testCase = await createCase();
      const installed = await installCase(testCase);
      const tool = path.join(installed.artifactRoot, "payload", "bin", "hermesc");
      const runtime = path.join(installed.artifactRoot, "payload", ...installed.manifest.runtimeComponent.split("/"));
      const runtimeParent = path.dirname(runtime);
      await fsp.chmod(runtimeParent, 0o755);
      await fsp.unlink(runtime);
      await fsp.link(tool, runtime);
      await fsp.chmod(runtimeParent, 0o555);
      await assert.rejects(() => verifyPortableEngineStore({
        repoRoot: testCase.repoRoot,
        expectedSourceRevision: testCase.fixture.revision,
        artifactId: installed.manifest.artifactId,
      }, dependencies()), /hard-linked|aliases/u);
    });
    await t.test("retained transport hardlink alias", async () => {
      const testCase = await createCase();
      const installed = await installCase(testCase);
      const archive = path.join(
        installed.artifactRoot,
        "LOCAL",
        "transport",
        rawDigest(testCase.fixture.archive),
        "archive.tar.gz",
      );
      await fsp.link(archive, path.join(testCase.root, "retained-archive-alias.tar.gz"));
      await assert.rejects(() => verifyPortableEngineStore({
        repoRoot: testCase.repoRoot,
        expectedSourceRevision: testCase.fixture.revision,
        artifactId: installed.manifest.artifactId,
      }, dependencies()), /retained transport member is hard-linked/u);
    });
    await t.test("writable store", async () => {
      const testCase = await createCase();
      const installed = await installCase(testCase);
      await fsp.chmod(installed.artifactRoot, 0o755);
      await assert.rejects(() => verifyPortableEngineStore({
        repoRoot: testCase.repoRoot,
        expectedSourceRevision: testCase.fixture.revision,
        artifactId: installed.manifest.artifactId,
      }, dependencies()), /store entry is writable/u);
    });
    await t.test("partial unselected transport", async () => {
      const testCase = await createCase();
      const installed = await installCase(testCase);
      const transportRoot = path.join(installed.artifactRoot, "LOCAL", "transport");
      await fsp.chmod(path.join(installed.artifactRoot, "LOCAL"), 0o755);
      await fsp.chmod(transportRoot, 0o755);
      await fsp.mkdir(path.join(transportRoot, `sha256-${"0".repeat(64)}`), { mode: 0o555 });
      await fsp.chmod(transportRoot, 0o555);
      await fsp.chmod(path.join(installed.artifactRoot, "LOCAL"), 0o555);
      await assert.rejects(() => verifyPortableEngineStore({
        repoRoot: testCase.repoRoot,
        expectedSourceRevision: testCase.fixture.revision,
        artifactId: installed.manifest.artifactId,
        archiveDigest: rawDigest(testCase.fixture.archive),
      }, dependencies()), /retained transport exact membership/u);
    });
    await t.test("redirected store root", async () => {
      const testCase = await createCase();
      const target = path.join(await fsp.realpath(testCase.repoRoot), "target");
      const elsewhere = path.join(testCase.root, "elsewhere");
      await fsp.mkdir(elsewhere);
      await fsp.symlink(elsewhere, target);
      await expectRejected(testCase, /redirected or not a directory/u);
    });
  });

  test("serializes publication and quarantines invalid exact destinations for restart", async (t) => {
    await t.test("two concurrent installs serialize per portable artifact", async () => {
      const testCase = await createCase();
      let criticalEntries = 0;
      let releaseFirst;
      let firstEntered;
      const entered = new Promise((resolve) => { firstEntered = resolve; });
      const gate = new Promise((resolve) => { releaseFirst = resolve; });
      const failpoint = async (name) => {
        if (name !== "after-artifact-lock") return;
        criticalEntries += 1;
        if (criticalEntries === 1) {
          firstEntered();
          await gate;
        }
      };
      const firstPromise = installCase(testCase, { failpoint });
      await entered;
      const secondPromise = installCase(testCase, { failpoint });
      await new Promise((resolve) => setTimeout(resolve, 75));
      assert.equal(criticalEntries, 1);
      releaseFirst();
      const results = await Promise.all([firstPromise, secondPromise]);
      assert.deepEqual(results.map((result) => result.installed).sort(), [false, true]);
      assert.equal(criticalEntries, 2);
    });

    await t.test("a dead-owner lock is recovered on restart", async () => {
      const testCase = await createCase();
      const storeRoot = path.join(testCase.repoRoot, "target", "hermes-artifacts-test-only");
      const locksRoot = path.join(storeRoot, ".locks");
      await fsp.mkdir(locksRoot, { recursive: true, mode: 0o700 });
      await fsp.chmod(path.join(testCase.repoRoot, "target"), 0o700);
      await fsp.chmod(storeRoot, 0o700);
      await fsp.chmod(locksRoot, 0o700);
      const lockPath = path.join(locksRoot, `${testCase.fixture.manifest.artifactId}.lock`);
      await fsp.mkdir(lockPath, { mode: 0o700 });
      await fsp.writeFile(path.join(lockPath, "OWNER"), canonicalJson({
        schema: "ibex/test-only-portable-engine-local-install-lock/1",
        pid: 999999,
        token: "0".repeat(32),
      }), { mode: 0o600 });
      const installed = await installCase(testCase, { isProcessAlive: () => false });
      assert.equal(installed.installed, true);
      await assert.rejects(() => fsp.lstat(lockPath), { code: "ENOENT" });
    });

    for (const [name, failpointName, expectedMembers] of [
      ["restart recovers a complete release tombstone", "after-lock-release-tombstone-fsync", ["OWNER"]],
      ["restart recovers an empty release tombstone", "after-lock-release-tombstone-owner-unlink", []],
    ]) {
      await t.test(name, async () => {
        const testCase = await createCase();
        const artifactId = testCase.fixture.manifest.artifactId;
        const storeRoot = path.join(testCase.repoRoot, "target", "hermes-artifacts-test-only");
        const locksRoot = path.join(storeRoot, ".locks");
        let fired = false;
        let tombstonePath;
        await assert.rejects(() => installCase(testCase, {
          failpoint: async (observedName, details) => {
            if (fired || observedName !== failpointName) return;
            fired = true;
            tombstonePath = details.tombstonePath;
            throw new Error(`fixture crash at ${failpointName}`);
          },
        }), new RegExp(`fixture crash at ${failpointName}`, "u"));
        assert.equal(fired, true);
        assert.match(path.basename(tombstonePath), new RegExp(`^\\.released-${artifactId}\\.[0-9a-f]{32}$`, "u"));
        assert.deepEqual((await fsp.readdir(tombstonePath)).sort(compareUtf8), expectedMembers);
        await assert.rejects(() => fsp.lstat(path.join(locksRoot, `${artifactId}.lock`)), { code: "ENOENT" });
        const restarted = await installCase(testCase);
        assert.equal(restarted.installed, false);
        await assert.rejects(() => fsp.lstat(tombstonePath), { code: "ENOENT" });
        assert.equal((await fsp.readdir(locksRoot)).some((entry) => entry.startsWith(`.released-${artifactId}.`)), false);
      });
    }

    await t.test("invalid partial store is retained in quarantine and replaced", async () => {
      const testCase = await createCase();
      const first = await installCase(testCase);
      const local = path.join(first.artifactRoot, "LOCAL");
      await fsp.chmod(local, 0o755);
      await fsp.unlink(path.join(local, "COMPLETE"));
      await fsp.chmod(local, 0o555);
      const restarted = await installCase(testCase);
      assert.equal(restarted.installed, true);
      assert.equal(restarted.replacedInvalid, true);
      assert.equal(restarted.quarantines.length, 1);
      assert.equal(await lstatKind(restarted.quarantines[0]), "directory");
      await assert.rejects(() => fsp.lstat(path.join(restarted.quarantines[0], "LOCAL", "COMPLETE")), { code: "ENOENT" });
    });

    await t.test("redirected exact destination is quarantined without following it", async () => {
      const testCase = await createCase();
      const artifactId = testCase.fixture.manifest.artifactId;
      const storeRoot = path.join(testCase.repoRoot, "target", "hermes-artifacts-test-only");
      await fsp.mkdir(storeRoot, { recursive: true, mode: 0o700 });
      await fsp.chmod(path.join(testCase.repoRoot, "target"), 0o700);
      await fsp.chmod(storeRoot, 0o700);
      const sentinel = path.join(testCase.root, "outside-sentinel");
      await fsp.mkdir(sentinel);
      await fsp.writeFile(path.join(sentinel, "preserved"), "still here");
      await fsp.symlink(sentinel, path.join(storeRoot, artifactId));
      const installed = await installCase(testCase);
      assert.equal(installed.replacedInvalid, true);
      assert.equal(await fsp.readFile(path.join(sentinel, "preserved"), "utf8"), "still here");
      assert.equal(await lstatKind(installed.quarantines[0]), "symlink");
      assert.equal(await fsp.readlink(installed.quarantines[0]), sentinel);
    });

    await t.test("restart after quarantine-before-publish retains evidence and completes", async () => {
      const testCase = await createCase();
      const first = await installCase(testCase);
      await fsp.chmod(first.artifactRoot, 0o755);
      let fired = false;
      await assert.rejects(() => installCase(testCase, {
        failpoint: async (name) => {
          if (!fired && name === "after-invalid-destination-quarantine") {
            fired = true;
            throw new Error("fixture crash after quarantine");
          }
        },
      }), /fixture crash after quarantine/u);
      await assert.rejects(() => fsp.lstat(first.artifactRoot), { code: "ENOENT" });
      const restarted = await installCase(testCase);
      assert.equal(restarted.installed, true);
      assert.equal(restarted.quarantines.length, 1);
    });

    await t.test("restart after candidate rename quarantines the writable remnant", async () => {
      const testCase = await createCase();
      let fired = false;
      await assert.rejects(() => installCase(testCase, {
        failpoint: async (name) => {
          if (!fired && name === "after-candidate-rename") {
            fired = true;
            throw new Error("fixture crash after candidate rename");
          }
        },
      }), /fixture crash after candidate rename/u);
      const finalRoot = path.join(testCase.repoRoot, "target", "hermes-artifacts-test-only", testCase.fixture.manifest.artifactId);
      assert.equal(Number((await fsp.lstat(finalRoot, { bigint: true })).mode & 0o777n), 0o700);
      const restarted = await installCase(testCase);
      assert.equal(restarted.replacedInvalid, true);
      assert.equal(restarted.quarantines.length, 1);
    });

    await t.test("restart after root narrowing treats the durable store as idempotent", async () => {
      const testCase = await createCase();
      let fired = false;
      await assert.rejects(() => installCase(testCase, {
        failpoint: async (name) => {
          if (!fired && name === "after-published-root-narrow") {
            fired = true;
            throw new Error("fixture crash after root narrowing");
          }
        },
      }), /fixture crash after root narrowing/u);
      const restarted = await installCase(testCase);
      assert.equal(restarted.installed, false);
      assert.equal(restarted.quarantines.length, 0);
    });
  });

  test("pins the source archive and detects mutation of the authenticated copy", async (t) => {
    await t.test("source mutation cannot change parsed bytes", async () => {
      const testCase = await createCase();
      const result = await installCase(testCase, {
        onAuthenticated: () => fs.writeFileSync(testCase.archivePath, "substituted after authentication"),
      });
      assert.equal(result.manifest.artifactId, testCase.fixture.manifest.artifactId);
    });
    await t.test("pinned-copy mutation is fatal before parsing", async () => {
      const testCase = await createCase();
      let parsingStarted = false;
      await expectRejected(testCase, /mutated before parsing/u, {
        verifyAttestation: async (input) => {
          const result = mockVerificationResult(input);
          fs.appendFileSync(input.archivePath, "mutation");
          return result;
        },
        onArchiveParseStart: () => { parsingStarted = true; },
      });
      assert.equal(parsingStarted, false);
    });
    await t.test("pinned bundle mutation is fatal before parsing", async () => {
      const testCase = await createCase();
      let parsingStarted = false;
      await expectRejected(testCase, /provenance bundle mutated before archive parsing/u, {
        verifyAttestation: async (input) => {
          const result = mockVerificationResult(input);
          fs.appendFileSync(input.bundlePath, "mutation");
          return result;
        },
        onArchiveParseStart: () => { parsingStarted = true; },
      });
      assert.equal(parsingStarted, false);
    });
    await t.test("retained archive mutation during reconstructive verification is fatal", async () => {
      const testCase = await createCase();
      const installed = await installCase(testCase);
      await assert.rejects(() => verifyPortableEngineStore({
        repoRoot: testCase.repoRoot,
        expectedSourceRevision: testCase.fixture.revision,
        artifactId: installed.manifest.artifactId,
      }, dependencies({
        failpoint: async (name, details) => {
          if (name !== "after-retained-reconstruction-extraction") return;
          await fsp.chmod(details.archivePath, 0o600);
          await fsp.appendFile(details.archivePath, "mutation");
        },
      })), /retained archive mutated during reconstructive extraction/u);
    });
    await t.test("retained bundle mutation during reconstructive verification is fatal", async () => {
      const testCase = await createCase();
      const installed = await installCase(testCase);
      await assert.rejects(() => verifyPortableEngineStore({
        repoRoot: testCase.repoRoot,
        expectedSourceRevision: testCase.fixture.revision,
        artifactId: installed.manifest.artifactId,
      }, dependencies({
        failpoint: async (name, details) => {
          if (name !== "after-retained-reconstruction-extraction") return;
          await fsp.chmod(details.bundlePath, 0o600);
          await fsp.appendFile(details.bundlePath, "mutation");
        },
      })), /retained bundle mutated during reconstructive extraction/u);
    });
  });

  test("joins manifest publisher/source authority to policy instead of bundle or caller claims", async (t) => {
    for (const [name, mutate, pattern] of [
      ["repository", (manifest) => { manifest.build.repository = "attacker/ibex"; }, /repository differs/u],
      ["workflow", (manifest) => { manifest.build.publisherWorkflow = ".github/workflows/attacker.yml"; }, /workflow differs/u],
      ["revision", (manifest) => { manifest.build.sourceRevision = "0".repeat(40); }, /externally selected checkout revision/u],
      ["authority bytes", (manifest) => { manifest.build.authorityDigests[0].digest = `sha256-${"0".repeat(64)}`; }, /checked build authorities/u],
    ]) {
      await t.test(name, async () => {
        const fixture = replaceManifest(buildFixture(), mutate);
        await expectRejected(await createCase(fixture), pattern);
      });
    }
  });

  test("strict-validates canonical authority documents and their semantic joins", async (t) => {
    await t.test("unknown authority field", async () => {
      const base = buildFixture();
      const pathname = "META-INF/authority/abi-contract.json";
      const member = base.members.find((candidate) => candidate.path === `payload/${pathname}`);
      const document = JSON.parse(member.bytes.toString("utf8"));
      document.unknown = true;
      const fixture = replacePayloadRegular(base, pathname, Buffer.from(canonicalJson(document), "utf8"));
      await expectRejected(await createCase(fixture), /unknown field unknown|variant, got 0/u);
    });
    await t.test("semantic digest substitution", async () => {
      const base = buildFixture();
      const pathname = "META-INF/authority/required-exports.json";
      const member = base.members.find((candidate) => candidate.path === `payload/${pathname}`);
      const document = JSON.parse(member.bytes.toString("utf8"));
      document.matchers[0].value = "differentRequiredSymbol";
      const fixture = replacePayloadRegular(base, pathname, Buffer.from(canonicalJson(document), "utf8"));
      await expectRejected(await createCase(fixture), /required-export semantic digest/u);
    });
  });
});
