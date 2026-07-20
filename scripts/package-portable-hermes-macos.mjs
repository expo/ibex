#!/usr/bin/env node

// Producer-only diagnostic portable Hermes package. This command deliberately
// does not install, select, link, load, run Ibex, or advertise a target.
//
// @ref LLP 0035#portable-package-contract — the reviewed publisher constructs
// the closed payload, authority documents, manifest, and deterministic archive.
// @ref LLP 0035#implementation-program — Phase 1 begins with a diagnostic
// macOS package while portable artifact acceptance remains disabled.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  assertCanonicalJsonBytes,
  assertExactKeys,
  assertNormalizedPayloadPath,
  assertSafeRelativeSymlink,
  assertUniquePortablePaths,
  buildDeterministicUstarGzip,
  canonicalJson,
  compareUtf8,
  deterministicUstarGzipSize,
  deterministicUstarSize,
  gitObjectId,
  inspectUstarGzip,
  parseHermesBytecode,
  parseJsonStrict,
  parseMachO,
  rawDigest,
  semanticDigest,
} from "./portable-engine-contract.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const defaultRepoRoot = path.resolve(path.dirname(scriptPath), "..");
const TARGET_TRIPLE = "aarch64-apple-darwin";
const RUNTIME_COMPONENT = "lib/hermesvm.framework/Versions/1/hermesvm";
const RECEIPT_PAYLOAD_PATH = "share/hermes/profile-provenance.json";
const TOOL_PAYLOAD_PATH = "bin/hermesc";
const FIXTURE_PAYLOAD_PATH = "share/compatibility/host-tools/input/smoke.js";
const FIXTURE_WORKSPACE_PATH = "input/smoke.js";
const HBC_OUTPUT_PATH = "output/smoke.hbc";
const MACHO_FILETYPE_EXECUTE = 2;
const MACHO_FILETYPE_DYLIB = 6;
const HERMES_FRAMEWORK_INSTALL_NAME = "@rpath/hermesvm.framework/Versions/1/hermesvm";
const MACOS_DYNAMIC_LINKER = "/usr/lib/dyld";
const FROZEN_MACOS_DIRECT_JSI_ABI = Object.freeze({
  languageBoundary: "cxx-jsi-direct",
  cxxStandard: "c++17",
  compilerAbi: "itanium",
  standardLibraryAbi: "libc++",
  exceptions: "enabled",
  rtti: "enabled",
  pointerWidth: 64,
  endianness: "little",
  allocationBoundary: "cxx-allocator-compatible",
  contractFeatures: ["direct-jsi-objects", "hermes-bytecode-v99"],
});
const RUNTIME_HBC_PROBE_SOURCE = Buffer.from(
  `#include <hermes/hermes.h>
#include <cstdio>
#include <dlfcn.h>
int main(int argc, char **argv) {
  if (argc != 2) return 10;
  void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (handle == nullptr) { std::fprintf(stderr, "%s\\n", dlerror()); return 11; }
  using Factory = facebook::jsi::ICast *(*)();
  auto factory = reinterpret_cast<Factory>(dlsym(handle, "_ZN8facebook6hermes17makeHermesRootAPIEv"));
  if (factory == nullptr) { std::fprintf(stderr, "%s\\n", dlerror()); return 12; }
  auto *root = facebook::jsi::castInterface<facebook::hermes::IHermesRootAPI>(factory());
  if (root == nullptr) return 13;
  std::printf("%u\\n", root->getBytecodeVersion());
  return dlclose(handle) == 0 ? 0 : 14;
}
`,
  "utf8",
);

// These files are the complete checkout-local authority read by the diagnostic
// producer. Node built-ins are the only code dependency; no package lock is an
// output input. Keep this exact sorted set joined to the checked trust policy.
export const REQUIRED_BUILD_AUTHORITY_PATHS = Object.freeze(
  [
    ".gitattributes",
    ".github/workflows/hermes-artifacts.yml",
    "schemas/portable-engine-abi-contract-v1.schema.json",
    "schemas/portable-engine-common-v1.schema.json",
    "schemas/portable-engine-export-set-v1.schema.json",
    "schemas/portable-engine-header-set-v1.schema.json",
    "schemas/portable-engine-host-tool-compatibility-v1.schema.json",
    "schemas/portable-engine-manifest-v1.schema.json",
    "schemas/portable-engine-provenance-trust-policy-v1.json",
    "schemas/portable-engine-provenance-trust-policy-v1.schema.json",
    "schemas/portable-engine-reviewed-profile-identity-v1.schema.json",
    "schemas/portable-engine-source-tree-identity-v1.schema.json",
    "scripts/apply-hermes-patches.sh",
    "scripts/build-hermes-linux.sh",
    "scripts/build-hermes.sh",
    "scripts/hermes-version.sh",
    "scripts/package-portable-hermes-macos.mjs",
    "scripts/portable-engine-contract.mjs",
    "tests/fixtures/portable-engine/host-tools/smoke.js",
  ].sort(compareUtf8),
);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertString(value, label) {
  assert(typeof value === "string" && value.length > 0, `${label}: expected a non-empty string`);
  return value;
}

function assertRawDigest(value, label) {
  assert(/^sha256-[0-9a-f]{64}$/u.test(value), `${label}: expected lowercase raw SHA-256`);
  return value;
}

function assertSame(left, right, label) {
  assert(canonicalJson(left) === canonicalJson(right), `${label}: mismatch`);
}

function readRegularFile(filePath, label, maximumBytes = Number.MAX_SAFE_INTEGER) {
  const before = fs.lstatSync(filePath);
  assert(before.isFile() && !before.isSymbolicLink(), `${label}: expected a no-follow regular file at ${filePath}`);
  assert(before.nlink === 1, `${label}: hard-linked input files are forbidden`);
  assert(Number.isSafeInteger(before.size) && before.size >= 0, `${label}: file size is not a safe integer`);
  assert(before.size <= maximumBytes, `${label}: ${before.size} bytes exceeds limit ${maximumBytes}`);
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  try {
    const opened = fs.fstatSync(descriptor);
    assert(opened.isFile(), `${label}: opened object is not a regular file`);
    assert(opened.dev === before.dev && opened.ino === before.ino, `${label}: file object changed before read`);
    assert(opened.nlink === 1, `${label}: opened input became hard-linked`);
    assert(Number.isSafeInteger(opened.size) && opened.size >= 0, `${label}: opened size is not a safe integer`);
    assert(opened.size <= maximumBytes, `${label}: ${opened.size} bytes exceeds limit ${maximumBytes}`);
    const bytes = Buffer.allocUnsafe(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      assert(count > 0, `${label}: file became shorter during bounded read`);
      offset += count;
    }
    const overflow = Buffer.alloc(1);
    assert(
      fs.readSync(descriptor, overflow, 0, 1, bytes.length) === 0,
      `${label}: file grew beyond its bounded size during read`,
    );
    const after = fs.fstatSync(descriptor);
    assert(
      after.dev === opened.dev &&
        after.ino === opened.ino &&
        after.nlink === 1 &&
        after.size === bytes.length,
      `${label}: file object or size changed during read`,
    );
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    encoding: null,
    input: options.input ?? Buffer.alloc(0),
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
    timeout: options.timeout,
    argv0: options.argv0,
    windowsHide: true,
  });
  if (result.error) throw new Error(`${options.label ?? command}: ${result.error.message}`);
  if (result.signal) throw new Error(`${options.label ?? command}: terminated by ${result.signal}`);
  return {
    status: result.status,
    stdout: Buffer.from(result.stdout ?? Buffer.alloc(0)),
    stderr: Buffer.from(result.stderr ?? Buffer.alloc(0)),
  };
}

function runGit(repoRoot, args, { allowFailure = false } = {}) {
  const result = runCommand("git", ["-C", repoRoot, ...args], {
    env: { ...process.env, LC_ALL: "C", GIT_NO_REPLACE_OBJECTS: "1" },
    maxBuffer: 64 * 1024 * 1024,
    label: `git ${args.join(" ")}`,
  });
  if (!allowFailure && result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed (${result.status}): ${result.stderr.toString("utf8")}`);
  }
  return result;
}

function requireCleanGitCheckout(repoRoot) {
  const status = runGit(repoRoot, ["status", "--porcelain=v1", "--untracked-files=all"]);
  assert(status.status === 0, "git status failed");
  assert(status.stdout.length === 0, "portable package production requires a clean Git checkout");
}

function readGitObject(repoRoot, type, objectId) {
  const result = runGit(repoRoot, ["cat-file", type, objectId]);
  assert(result.status === 0, `Git ${type} object ${objectId} is absent`);
  return result.stdout;
}

function parseCommitTree(commitBytes, objectWidth) {
  const headerEnd = commitBytes.indexOf(Buffer.from("\n\n", "ascii"));
  assert(headerEnd >= 0, "Git commit object has no header terminator");
  const header = commitBytes.subarray(0, headerEnd).toString("latin1");
  const trees = header.split("\n").filter((line) => line.startsWith("tree "));
  assert(trees.length === 1, "Git commit object must carry exactly one tree header");
  const treeId = trees[0].slice("tree ".length);
  assert(new RegExp(`^[0-9a-f]{${objectWidth}}$`, "u").test(treeId), "Git commit tree ID has the wrong object width");
  return treeId;
}

function deriveSourceTreeIdentity(repoRoot, sourceRef, expectedSourceRevision) {
  const formatResult = runGit(repoRoot, ["rev-parse", "--show-object-format"]);
  const gitObjectFormat = formatResult.stdout.toString("ascii").trim();
  assert(gitObjectFormat === "sha1", `only the admitted sha1 Git object format is supported; got ${gitObjectFormat}`);
  const revisionResult = runGit(repoRoot, ["rev-parse", "HEAD"]);
  const sourceRevision = revisionResult.stdout.toString("ascii").trim();
  assert(/^[0-9a-f]{40}$/u.test(sourceRevision), "HEAD is not one lowercase SHA-1 commit ID");
  assert(
    /^[0-9a-f]{40}$/u.test(expectedSourceRevision),
    "expected publisher source revision is not one lowercase SHA-1 commit ID",
  );
  assert(
    sourceRevision === expectedSourceRevision,
    `checked-out HEAD ${sourceRevision} differs from expected publisher revision ${expectedSourceRevision}`,
  );
  const commitBytes = readGitObject(repoRoot, "commit", sourceRevision);
  assert(gitObjectId("sha1", "commit", commitBytes) === sourceRevision, "raw Git commit content does not hash to HEAD");
  const treeObjectId = parseCommitTree(commitBytes, 40);
  const treeBytes = readGitObject(repoRoot, "tree", treeObjectId);
  assert(gitObjectId("sha1", "tree", treeBytes) === treeObjectId, "raw Git tree content does not hash to the commit tree edge");
  return {
    sourceRevision,
    commitBytes,
    treeBytes,
    document: {
      schema: "ibex/portable-engine-source-tree-identity/1",
      repository: "ccheever/ibex",
      sourceRevision,
      sourceRef,
      gitObjectFormat,
      sourceRevisionObjectType: "commit",
      sourceRevisionObjectContent: {
        path: "META-INF/authority/source-tree/commit.content",
        digest: rawDigest(commitBytes),
        size: commitBytes.length,
        encoding: "raw-uncompressed-git-object-content",
      },
      treeObjectId,
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

function validateTrustPolicy(policy, sourceRef) {
  assertExactKeys(
    policy,
    [
      "schema",
      "portableArtifactAcceptanceEnabled",
      "admittedTargets",
      "enginePublisher",
      "provenanceBundleBytes",
      "authoritativeConformance",
      "crossRunnerConformance",
      "archiveLimits",
      "payloadPathPolicy",
      "platformSystemDependencies",
    ],
    "portable engine trust policy",
  );
  assert(policy.schema === "ibex/portable-engine-provenance-trust-policy/1", "unexpected trust-policy schema");
  assert(policy.portableArtifactAcceptanceEnabled === false, "diagnostic producer refuses while acceptance is not explicitly false");
  assertExactKeys(
    policy.enginePublisher,
    [
      "allowedTriggers",
      "buildType",
      "certificateIssuer",
      "enabled",
      "offlineVerifier",
      "repository",
      "repositoryId",
      "repositoryOwnerId",
      "repositoryVisibility",
      "workflowPath",
      "workflowName",
      "sourceRef",
      "runnerClass",
      "provenanceRoot",
      "trustedRoot",
    ],
    "enginePublisher",
  );
  assert(
    policy.enginePublisher.enabled === true &&
      canonicalJson(policy.enginePublisher.offlineVerifier) === canonicalJson({
        binaryDigest: "sha256-f69505f54caad78b6012519ac866eea23c19ade9d274bd61044c791a1e30f594",
        binarySize: 25130562,
        goVersion: "go1.26.5",
        targetTriple: "aarch64-apple-darwin",
      }) &&
      policy.enginePublisher.repository === "ccheever/ibex" &&
      policy.enginePublisher.repositoryId === "1268046138" &&
      policy.enginePublisher.repositoryOwnerId === "56719" &&
      policy.enginePublisher.repositoryVisibility === "private" &&
      policy.enginePublisher.workflowPath === ".github/workflows/hermes-artifacts.yml" &&
      policy.enginePublisher.workflowName === "Hermes artifact cache" &&
      policy.enginePublisher.sourceRef === "refs/heads/main" &&
      policy.enginePublisher.runnerClass === "github-hosted" &&
      policy.enginePublisher.provenanceRoot === "github-oidc-artifact-attestations" &&
      policy.enginePublisher.buildType === "https://actions.github.io/buildtypes/workflow/v1" &&
      policy.enginePublisher.certificateIssuer === "https://token.actions.githubusercontent.com" &&
      canonicalJson(policy.enginePublisher.allowedTriggers) === canonicalJson(["push", "workflow_dispatch"]) &&
      canonicalJson(policy.enginePublisher.trustedRoot) === canonicalJson({
        profile: "github-private-signed-timestamp-v1",
        sha256: "484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7",
        size: 31645,
      }),
    "checked publisher policy is not the diagnostic v1 authority",
  );
  assert(sourceRef === policy.enginePublisher.sourceRef, `source ref ${sourceRef} is not admitted`);
  assert(Array.isArray(policy.admittedTargets), "admittedTargets must be an array");
  const matches = policy.admittedTargets.filter((target) => target.triple === TARGET_TRIPLE);
  assert(matches.length === 1, `trust policy must contain exactly one ${TARGET_TRIPLE} target`);
  const target = matches[0];
  assertExactKeys(
    target,
    [
      "triple",
      "targetFamily",
      "structuralFeatures",
      "nonSystemLoadableComponentPolicy",
      "profile",
      "sourceTreeGitObjectFormat",
      "reviewedProfileOriginKind",
      "exportExtractor",
      "exportPolicy",
      "requiredHostTools",
      "buildAuthorityPaths",
      "mappingProof",
      "receiptTargetArchitectures",
      "hostTool",
      "systemDependencyPolicyKey",
      "directJsiAbi",
    ],
    "admitted macOS target",
  );
  assert(target.targetFamily === "apple", "target family must be apple");
  assertSame(target.structuralFeatures, ["dynamic-library", "framework"], "target structural features");
  assert(target.nonSystemLoadableComponentPolicy === "runtime-only", "non-system component policy must be runtime-only");
  assert(target.sourceTreeGitObjectFormat === "sha1", "target Git object format must be sha1");
  assert(target.reviewedProfileOriginKind === "source-patched-cache", "target profile origin must be source-patched-cache");
  assert(target.exportExtractor === "macho-nlist-external-defined", "target export extractor must parse Mach-O nlist");
  assertSame(target.requiredHostTools, [{ toolRole: "bytecode-compiler", toolPath: TOOL_PAYLOAD_PATH }], "required host tools");
  assertSame(target.buildAuthorityPaths, REQUIRED_BUILD_AUTHORITY_PATHS, "complete producer build-authority paths");
  assert(target.systemDependencyPolicyKey === "apple", "target system dependency policy must be apple");
  assertSame(target.receiptTargetArchitectures, ["aarch64", "universal"], "admitted receipt architectures");
  assertExactKeys(
    target.hostTool,
    [
      "actualHostTriple",
      "binaryMachine",
      "dependencyExtractorFormat",
      "systemDependencyPolicyKey",
      "executionContract",
    ],
    "host-tool target policy",
  );
  assert(target.hostTool.actualHostTriple === TARGET_TRIPLE, "host-tool target policy has the wrong host triple");
  assertSame(target.hostTool.binaryMachine, { format: "mach-o", architecture: "arm64" }, "host-tool binary machine");
  assert(target.hostTool.dependencyExtractorFormat === "mach-o", "host-tool dependency extractor must be Mach-O");
  assert(target.hostTool.systemDependencyPolicyKey === "apple", "host-tool dependency policy must be Apple");
  assertExactKeys(target.exportPolicy, ["requiredMatchers", "forbiddenMatchers"], "target export policy");
  const matcherKey = (matcher) => `${matcher.kind}\0${matcher.value}`;
  for (const [mode, matchers] of Object.entries({
    required: target.exportPolicy.requiredMatchers,
    forbidden: target.exportPolicy.forbiddenMatchers,
  })) {
    assert(Array.isArray(matchers) && matchers.length > 0, `${mode} export policy must be non-empty`);
    const keys = matchers.map((matcher) => {
      assertExactKeys(matcher, ["kind", "value"], `${mode} export matcher`);
      assert(matcher.kind === "contains" || matcher.kind === "exact", `${mode} export matcher kind is unsupported`);
      assertString(matcher.value, `${mode} export matcher value`);
      return matcherKey(matcher);
    });
    assert(new Set(keys).size === keys.length, `${mode} export policy has duplicate matchers`);
    assertSame(keys, [...keys].sort(compareUtf8), `${mode} export matcher order`);
  }
  assertSame(
    target.profile,
    {
      id: "source-patched",
      targetVariant: "default",
      configuration: "Release",
      debugger: false,
      hermesBytecodeVersion: 99,
    },
    "admitted Release profile",
  );
  assertSame(target.mappingProof, { class: "macos-proc-pid-region-path-info", platform: "macos" }, "macOS mapping proof");
  assertSame(target.directJsiAbi, FROZEN_MACOS_DIRECT_JSI_ABI, "frozen macOS direct JSI ABI");
  assertExactKeys(policy.archiveLimits, ["maxArchiveBytes", "maxMemberCount", "maxRegularFileBytes", "maxExpandedBytes", "maxSymlinkDepth"], "archive limits");
  for (const [name, value] of Object.entries(policy.archiveLimits)) {
    assert(Number.isSafeInteger(value) && value > 0, `archiveLimits.${name} must be a positive safe integer`);
  }
  return target;
}

function assertTrackedBytes(repoRoot, revision, relativePath, bytes) {
  assertNormalizedPayloadPath(relativePath, "build authority path");
  const result = runGit(repoRoot, ["show", `${revision}:${relativePath}`]);
  assert(result.status === 0, `build authority is not tracked at ${revision}: ${relativePath}`);
  assert(result.stdout.equals(bytes), `working-tree bytes differ from ${revision}: ${relativePath}`);
}

function hashAuthorityPaths(repoRoot, sourceRevision, authorityPaths) {
  const rows = [];
  const bytesByPath = new Map();
  for (const relativePath of authorityPaths) {
    const bytes = readRegularFile(path.join(repoRoot, relativePath), `build authority ${relativePath}`);
    assertTrackedBytes(repoRoot, sourceRevision, relativePath, bytes);
    bytesByPath.set(relativePath, bytes);
    rows.push({ path: relativePath, digest: rawDigest(bytes) });
  }
  rows.sort((left, right) => compareUtf8(left.path, right.path));
  return { rows, bytesByPath };
}

function derivePatchStackDigest(repoRoot, sourceRevision) {
  const patchRoot = path.join(repoRoot, "patches/hermes");
  const workingNames = fs
    .readdirSync(patchRoot, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".patch"))
    .map((entry) => entry.name)
    .sort(compareUtf8);
  const trackedResult = runGit(repoRoot, ["ls-tree", "-r", "-z", "--name-only", sourceRevision, "--", "patches/hermes"]);
  const trackedNames = trackedResult.stdout
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .filter((relativePath) => /^patches\/hermes\/[^/]+\.patch$/u.test(relativePath))
    .map((relativePath) => relativePath.slice("patches/hermes/".length))
    .sort(compareUtf8);
  assertSame(workingNames, trackedNames, "tracked Hermes patch-stack membership");
  assert(trackedNames.length > 0, "reviewed Hermes patch stack is empty");
  const lines = [];
  for (const name of trackedNames) {
    const relativePath = `patches/hermes/${name}`;
    const bytes = readRegularFile(path.join(repoRoot, relativePath), `Hermes patch ${relativePath}`);
    assertTrackedBytes(repoRoot, sourceRevision, relativePath, bytes);
    lines.push(`${rawDigest(bytes).slice("sha256-".length)}  ${relativePath}\n`);
  }
  return rawDigest(Buffer.from(lines.join(""), "utf8"));
}

function derivePatchIdentityAuthorityDigest(versionScriptBytes) {
  const marker = Buffer.from("ibex_sha256() {", "utf8");
  const offset = versionScriptBytes.indexOf(marker);
  assert(offset >= 0 && (offset === 0 || versionScriptBytes[offset - 1] === 0x0a), "hermes-version identity-authority marker is absent");
  return rawDigest(versionScriptBytes.subarray(offset));
}

export function deriveReviewedSourceAuthorities(repoRoot, sourceRevision, authority) {
  const digestByPath = new Map(authority.rows.map((row) => [row.path, row.digest]));
  const patchApplicationAuthorityDigest = digestByPath.get("scripts/apply-hermes-patches.sh");
  const appleBuildAuthorityDigest = digestByPath.get("scripts/build-hermes.sh");
  const linuxBuildAuthorityDigest = digestByPath.get("scripts/build-hermes-linux.sh");
  const versionBytes = authority.bytesByPath.get("scripts/hermes-version.sh");
  assert(patchApplicationAuthorityDigest && appleBuildAuthorityDigest && linuxBuildAuthorityDigest && versionBytes, "core source-build authorities are incomplete");
  return {
    patchApplicationAuthorityDigest,
    patchIdentityAuthorityDigest: derivePatchIdentityAuthorityDigest(versionBytes),
    patchStackDigest: derivePatchStackDigest(repoRoot, sourceRevision),
    sourceBuildAuthorityDigests: {
      "scripts/build-hermes-linux.sh": linuxBuildAuthorityDigest,
      "scripts/build-hermes.sh": appleBuildAuthorityDigest,
    },
    pinnedHermesSource: derivePinnedHermesSource(versionBytes),
    sourceRevision,
  };
}

export function derivePinnedHermesSource(versionScriptBytes) {
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(versionScriptBytes);
  } catch (error) {
    throw new Error(`hermes-version.sh is not UTF-8: ${error.message}`);
  }
  const exactlyOne = (pattern, label) => {
    const matches = [...source.matchAll(pattern)];
    assert(matches.length === 1, `hermes-version.sh must contain exactly one canonical ${label} assignment`);
    return matches[0][1];
  };
  const sourceVersion = exactlyOne(
    /^IBEX_HERMES_VERSION="\$\{IBEX_HERMES_VERSION:-([0-9]+(?:\.[0-9]+){2})\}"$/gmu,
    "source version",
  );
  const sourceCommit = exactlyOne(
    /^IBEX_HERMES_SOURCE_COMMIT="\$\{IBEX_HERMES_SOURCE_COMMIT:-([0-9a-f]{40})\}"$/gmu,
    "source commit",
  );
  const sourceRefAssignments = [
    ...source.matchAll(
      /^IBEX_HERMES_SOURCE_REF="\$\{IBEX_HERMES_SOURCE_REF:-\$\{IBEX_HERMES_VERSION\}-stable\}"$/gmu,
    ),
  ];
  assert(
    sourceRefAssignments.length === 1,
    "hermes-version.sh must contain exactly one canonical source-ref derivation",
  );
  return { sourceVersion, sourceRef: `${sourceVersion}-stable`, sourceCommit };
}

function digestPrefix(value, label) {
  assertRawDigest(value, label);
  return value.slice("sha256-".length, "sha256-".length + 12);
}

function validateProfileReceipt(receiptBytes, runtimeDigest, targetPolicy, sourceAuthorities) {
  const receipt = parseJsonStrict(receiptBytes, "Hermes profile receipt");
  assertExactKeys(receipt, ["schema", "profileId", "targetVariant", "artifact", "origin"], "Hermes profile receipt");
  assert(receipt.schema === "ibex/hermes-profile-provenance-receipt/2", "profile receipt is not schema 2");
  assert(receipt.profileId === targetPolicy.profile.id, "profile receipt ID differs from admitted profile");
  assert(receipt.targetVariant === targetPolicy.profile.targetVariant, "profile receipt target variant differs from admitted profile");
  assertExactKeys(receipt.artifact, ["binaryDigest", "fileName", "targetArchitecture"], "profile receipt artifact");
  assertRawDigest(receipt.artifact.binaryDigest, "profile receipt runtime digest");
  assert(receipt.artifact.binaryDigest === runtimeDigest, "profile receipt does not bind the packaged runtime bytes");
  assert(receipt.artifact.fileName === "hermesvm", "profile receipt does not name hermesvm");
  assert(targetPolicy.receiptTargetArchitectures.includes(receipt.artifact.targetArchitecture), "profile receipt target architecture is not admitted");
  assertExactKeys(receipt.origin, ["kind", "cacheKey", "reviewedProfileIdentity"], "profile receipt origin");
  assert(receipt.origin.kind === targetPolicy.reviewedProfileOriginKind, "profile receipt origin kind is not admitted");
  const identity = receipt.origin.reviewedProfileIdentity;
  assertExactKeys(
    identity,
    [
      "artifact",
      "patchApplicationAuthorityDigest",
      "patchIdentityAuthorityDigest",
      "patchStackDigest",
      "sourceBuildAuthorityDigests",
      "sourceCommit",
      "sourceRef",
      "sourceVersion",
    ],
    "reviewed source profile identity",
  );
  assert(identity.artifact === "facebook/hermes", "reviewed source artifact is not facebook/hermes");
  for (const field of ["patchApplicationAuthorityDigest", "patchIdentityAuthorityDigest", "patchStackDigest"]) {
    assertRawDigest(identity[field], `reviewed source ${field}`);
  }
  assertExactKeys(identity.sourceBuildAuthorityDigests, ["scripts/build-hermes-linux.sh", "scripts/build-hermes.sh"], "source build authority digests");
  assert(/^[0-9a-f]{40}$/u.test(identity.sourceCommit), "reviewed Hermes source commit is not lowercase SHA-1");
  assertString(identity.sourceVersion, "reviewed Hermes source version");
  assert(identity.sourceRef === `${identity.sourceVersion}-stable`, "reviewed Hermes source ref is not derived from sourceVersion");
  assertSame(
    {
      sourceVersion: identity.sourceVersion,
      sourceRef: identity.sourceRef,
      sourceCommit: identity.sourceCommit,
    },
    sourceAuthorities.pinnedHermesSource,
    "receipt Hermes source pin",
  );
  assert(identity.patchApplicationAuthorityDigest === sourceAuthorities.patchApplicationAuthorityDigest, "receipt patch-application authority differs from reviewed bytes");
  assert(identity.patchIdentityAuthorityDigest === sourceAuthorities.patchIdentityAuthorityDigest, "receipt identity authority differs from reviewed hermes-version suffix");
  assert(identity.patchStackDigest === sourceAuthorities.patchStackDigest, "receipt patch stack differs from reviewed patch bytes and names");
  assertSame(identity.sourceBuildAuthorityDigests, sourceAuthorities.sourceBuildAuthorityDigests, "receipt platform build authorities");
  const expectedCacheKey =
    `${identity.sourceCommit.slice(0, 12)}` +
    `-p${digestPrefix(identity.patchStackDigest, "patch stack")}` +
    `-ba${digestPrefix(identity.sourceBuildAuthorityDigests["scripts/build-hermes.sh"], "Apple builder")}` +
    `-bl${digestPrefix(identity.sourceBuildAuthorityDigests["scripts/build-hermes-linux.sh"], "Linux builder")}` +
    `-a${digestPrefix(identity.patchApplicationAuthorityDigest, "patch application")}` +
    `-i${digestPrefix(identity.patchIdentityAuthorityDigest, "identity authority")}` +
    "-oapple";
  assert(receipt.origin.cacheKey === expectedCacheKey, `profile receipt cache key is not the exact Release key: expected ${expectedCacheKey}`);
  return {
    receipt,
    reviewedProfileIdentity: {
      schema: "ibex/portable-engine-reviewed-profile-identity/1",
      profileId: receipt.profileId,
      targetVariant: receipt.targetVariant,
      targetTriple: TARGET_TRIPLE,
      originKind: receipt.origin.kind,
      receiptPath: RECEIPT_PAYLOAD_PATH,
      receiptDigest: rawDigest(receiptBytes),
      reviewedProfileIdentity: structuredClone(identity),
    },
    source: {
      artifact: identity.artifact,
      sourceCommit: identity.sourceCommit,
      sourceRef: identity.sourceRef,
      sourceVersion: identity.sourceVersion,
      patchStackDigest: identity.patchStackDigest,
    },
  };
}

class Payload {
  constructor(limits) {
    this.limits = limits;
    this.members = new Map();
    this.expandedBytes = 0;
  }

  addDirectory(pathname, role) {
    assertNormalizedPayloadPath(pathname);
    this.#insert(pathname, { kind: "directory", role, path: pathname });
  }

  addRegular(pathname, role, bytes, executable = false) {
    assertNormalizedPayloadPath(pathname);
    assert(
      bytes && Number.isSafeInteger(bytes.length),
      `${pathname}: regular input has no safe byte length`,
    );
    assert(
      bytes.length <= this.limits.maxRegularFileBytes,
      `${pathname}: ${bytes.length} bytes exceeds regular-file limit ${this.limits.maxRegularFileBytes}`,
    );
    assert(
      this.expandedBytes + bytes.length <= this.limits.maxExpandedBytes,
      `${pathname}: payload would exceed expanded-byte limit ${this.limits.maxExpandedBytes}`,
    );
    const captured = Buffer.from(bytes);
    this.#insert(pathname, {
      kind: "regular",
      role,
      path: pathname,
      digest: rawDigest(captured),
      size: captured.length,
      executable,
      bytes: captured,
    });
    this.expandedBytes += captured.length;
  }

  addRegularFile(pathname, role, sourcePath, executable = false, maximumBytes = Number.MAX_SAFE_INTEGER) {
    this.#assertInsert(pathname);
    const remaining = this.limits.maxExpandedBytes - this.expandedBytes;
    const effectiveLimit = Math.min(maximumBytes, this.limits.maxRegularFileBytes, remaining);
    const status = fs.lstatSync(sourcePath);
    assert(status.isFile() && !status.isSymbolicLink(), `${pathname}: expected a no-follow regular file`);
    assert(
      status.size <= effectiveLimit,
      `${pathname}: ${status.size} bytes exceeds remaining regular/expanded limit ${effectiveLimit}`,
    );
    this.addRegular(pathname, role, readRegularFile(sourcePath, pathname, effectiveLimit), executable);
  }

  addSymlink(pathname, role, target) {
    assertSafeRelativeSymlink(pathname, target);
    this.#insert(pathname, { kind: "symlink", role, path: pathname, target });
  }

  #insert(pathname, member) {
    this.#assertInsert(pathname);
    this.members.set(pathname, member);
  }

  #assertInsert(pathname) {
    assert(!this.members.has(pathname), `duplicate payload member: ${pathname}`);
    assert(
      this.members.size + 1 + 3 <= this.limits.maxMemberCount,
      `${pathname}: archive member count exceeds policy limit ${this.limits.maxMemberCount}`,
    );
  }

  manifestEntries() {
    return [...this.members.values()]
      .map(({ bytes: _bytes, ...entry }) => entry)
      .sort((left, right) => compareUtf8(left.path, right.path));
  }

  archiveMembers() {
    return [...this.members.values()].map((member) => {
      const archivePath = `payload/${member.path}`;
      if (member.kind === "regular") {
        return { path: archivePath, kind: "regular", bytes: member.bytes, executable: member.executable };
      }
      if (member.kind === "symlink") return { path: archivePath, kind: "symlink", target: member.target };
      return { path: archivePath, kind: "directory" };
    });
  }
}

function collectDirectory(sourceRoot, payloadRoot, payload, classify) {
  const rootStatus = fs.lstatSync(sourceRoot);
  assert(rootStatus.isDirectory() && !rootStatus.isSymbolicLink(), `${sourceRoot}: source root must be a no-follow directory`);
  const visit = (sourcePath, payloadPath, isRoot = false) => {
    const status = fs.lstatSync(sourcePath);
    const classification = classify(payloadPath, status, isRoot);
    if (status.isDirectory()) {
      payload.addDirectory(payloadPath, classification.role);
      const children = fs.readdirSync(sourcePath).sort(compareUtf8);
      for (const child of children) {
        assert(child !== ".DS_Store", `${sourcePath}: platform metadata sidecar is forbidden`);
        visit(path.join(sourcePath, child), `${payloadPath}/${child}`);
      }
      return;
    }
    if (status.isFile()) {
      payload.addRegularFile(
        payloadPath,
        classification.role,
        sourcePath,
        classification.executable ?? false,
      );
      return;
    }
    if (status.isSymbolicLink()) {
      assert(classification.allowSymlink === true, `${payloadPath}: symlink is not admitted in this source tree`);
      payload.addSymlink(payloadPath, classification.role, fs.readlinkSync(sourcePath, "utf8"));
      return;
    }
    throw new Error(`${payloadPath}: sockets, devices, FIFOs, and hard-link aliases are not package inputs`);
  };
  visit(sourceRoot, payloadRoot, true);
}

function matcherMatches(nameBytes, matcher) {
  const needle = Buffer.from(matcher.value, "utf8");
  return matcher.kind === "exact" ? nameBytes.equals(needle) : matcher.kind === "contains" ? nameBytes.indexOf(needle) >= 0 : false;
}

function hasMachOMagic(bytes) {
  if (bytes.length < 4) return false;
  const magicLe = bytes.readUInt32LE(0);
  const magicBe = bytes.readUInt32BE(0);
  return (
    magicLe === 0xfeedfacf ||
    magicLe === 0xcffaedfe ||
    magicBe === 0xcafebabe ||
    magicBe === 0xcafebabf ||
    magicBe === 0xbebafeca ||
    magicBe === 0xbfbafeca
  );
}

function validateExportPolicy(symbols, exportPolicy) {
  assertExactKeys(exportPolicy, ["requiredMatchers", "forbiddenMatchers"], "target export policy");
  for (const [mode, matchers] of [
    ["required", exportPolicy.requiredMatchers],
    ["forbidden", exportPolicy.forbiddenMatchers],
  ]) {
    assert(Array.isArray(matchers), `${mode} export matchers must be an array`);
    for (const matcher of matchers) {
      assertExactKeys(matcher, ["kind", "value"], `${mode} export matcher`);
      assert(matcher.kind === "exact" || matcher.kind === "contains", `${mode} export matcher has unsupported kind`);
      assertString(matcher.value, `${mode} export matcher value`);
      const matched = symbols.some((name) => matcherMatches(name, matcher));
      if (mode === "required") assert(matched, `required export matcher did not match: ${matcher.kind}:${matcher.value}`);
      else assert(!matched, `forbidden export matcher matched: ${matcher.kind}:${matcher.value}`);
    }
  }
}

function defaultHostToolRunner({ toolPath, args, cwd, environment, timeoutMs, maxStdoutBytes, maxStderrBytes }) {
  const result = runCommand(toolPath, args, {
    cwd,
    env: Object.fromEntries(environment.map(({ name, value }) => [name, value])),
    input: Buffer.alloc(0),
    timeout: timeoutMs,
    maxBuffer: Math.max(maxStdoutBytes, maxStderrBytes) + 1,
    argv0: toolPath,
    label: `${toolPath} ${args.join(" ")}`,
  });
  assert(result.stdout.length <= maxStdoutBytes, "host tool stdout exceeded its bound");
  assert(result.stderr.length <= maxStderrBytes, "host tool stderr exceeded its bound");
  return result;
}

function observeRuntimeHbcVersion({
  includePath,
  runtimePath,
  runtimeDigest,
  runtimeSize,
  allowedSystemDependencies,
}) {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-portable-hermes-runtime-probe-"));
  fs.chmodSync(workspace, 0o700);
  try {
    const exactEnvironment = { LC_ALL: "C", TZ: "UTC" };
    const compilerLookup = runCommand("/usr/bin/xcrun", ["--find", "clang++"], {
      cwd: workspace,
      env: exactEnvironment,
      input: Buffer.alloc(0),
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
      argv0: "/usr/bin/xcrun",
      label: "resolve Apple clang++",
    });
    assert(compilerLookup.status === 0 && compilerLookup.stderr.length === 0, "xcrun could not resolve clang++ cleanly");
    const compilerPath = compilerLookup.stdout.toString("utf8").trim();
    assert(path.isAbsolute(compilerPath) && !compilerPath.includes("\n"), "xcrun returned an invalid clang++ path");
    const sdkLookup = runCommand("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"], {
      cwd: workspace,
      env: exactEnvironment,
      input: Buffer.alloc(0),
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
      argv0: "/usr/bin/xcrun",
      label: "resolve macOS SDK",
    });
    assert(sdkLookup.status === 0 && sdkLookup.stderr.length === 0, "xcrun could not resolve the macOS SDK cleanly");
    const sdkPath = sdkLookup.stdout.toString("utf8").trim();
    assert(path.isAbsolute(sdkPath) && !sdkPath.includes("\n"), "xcrun returned an invalid macOS SDK path");
    const probePath = path.join(workspace, "hbc-probe");
    const compilation = runCommand(compilerPath, [
      "-x",
      "c++",
      "-",
      "-std=c++17",
      "-arch",
      "arm64",
      "-isysroot",
      sdkPath,
      "-I",
      includePath,
      "-ldl",
      "-o",
      probePath,
    ], {
      cwd: workspace,
      env: { ...exactEnvironment, SDKROOT: sdkPath },
      input: RUNTIME_HBC_PROBE_SOURCE,
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
      argv0: compilerPath,
      label: "compile runtime HBC probe",
    });
    assert(compilation.status === 0, `runtime HBC probe compilation failed: ${compilation.stderr.toString("utf8")}`);
    assert(compilation.stdout.length === 0 && compilation.stderr.length === 0, "runtime HBC probe compilation produced unexpected output");
    const probeBytes = readRegularFile(probePath, "runtime HBC probe", 16 * 1024 * 1024);
    const probeMachO = parseMachO(probeBytes, { architecture: "arm64" });
    assert(probeMachO.fileType === MACHO_FILETYPE_EXECUTE, "runtime HBC probe is not an MH_EXECUTE image");
    assert(
      probeMachO.dylibId === null && probeMachO.dylinker === MACOS_DYNAMIC_LINKER,
      "runtime HBC probe has the wrong Mach-O image role or dynamic linker",
    );
    for (const dependency of probeMachO.dependencies) {
      assert(allowedSystemDependencies.includes(dependency), `runtime HBC probe has non-admitted dependency: ${dependency}`);
    }
    assert(
      probeMachO.dependencies.every((dependency) => !dependency.toLowerCase().includes("hermes")),
      "runtime HBC probe has a pre-main Hermes dependency",
    );
    assert(
      rawDigest(readRegularFile(runtimePath, "runtime before HBC probe", runtimeSize)) === runtimeDigest,
      "runtime bytes changed before HBC probe",
    );
    const execution = runCommand(probePath, [runtimePath], {
      cwd: workspace,
      env: exactEnvironment,
      input: Buffer.alloc(0),
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
      argv0: probePath,
      label: "runtime HBC probe",
    });
    assert(execution.status === 0, `runtime HBC probe failed: ${execution.stderr.toString("utf8")}`);
    assert(execution.stderr.length === 0, "runtime HBC probe produced stderr");
    const output = execution.stdout.toString("utf8");
    assert(/^[0-9]+\n$/u.test(output), "runtime HBC probe output is not one canonical version line");
    const version = Number(output.trim());
    assert(Number.isSafeInteger(version), "runtime HBC probe version is not a safe integer");
    assert(
      rawDigest(readRegularFile(runtimePath, "runtime after HBC probe", runtimeSize)) === runtimeDigest,
      "runtime bytes changed during HBC probe",
    );
    return { version };
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
}

function inspectWorkspace(workspace, expectedPaths) {
  const observed = [];
  const visit = (relativePath) => {
    const absolute = path.join(workspace, relativePath);
    for (const name of fs.readdirSync(absolute).sort(compareUtf8)) {
      const child = relativePath ? `${relativePath}/${name}` : name;
      const status = fs.lstatSync(path.join(workspace, child));
      assert(status.isDirectory() || status.isFile(), `host-tool workspace contains unsupported object: ${child}`);
      observed.push(child);
      if (status.isDirectory()) visit(child);
    }
  };
  visit("");
  assertSame(observed.sort(compareUtf8), [...expectedPaths].sort(compareUtf8), "host-tool workspace exact membership");
}

function runHostToolInvocation({ id, args, toolPath, fixtureBytes, contract, runner, expectsHbc }) {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-portable-hermes-tool-"));
  fs.chmodSync(workspace, 0o700);
  try {
    const inputPath = path.join(workspace, FIXTURE_WORKSPACE_PATH);
    fs.mkdirSync(path.dirname(inputPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(inputPath, fixtureBytes, { mode: 0o600, flag: "wx" });
    if (expectsHbc) fs.mkdirSync(path.join(workspace, "output"), { mode: 0o700 });
    const result = runner({
      toolPath,
      args,
      cwd: workspace,
      environment: contract.environment,
      timeoutMs: contract.timeoutMs,
      maxStdoutBytes: contract.maxStdoutBytes,
      maxStderrBytes: contract.maxStderrBytes,
    });
    assertExactKeys(result, ["status", "stdout", "stderr"], `${id} runner result`);
    const stdout = Buffer.from(result.stdout);
    const stderr = Buffer.from(result.stderr);
    assert(Number.isInteger(result.status) && result.status >= 0 && result.status <= 255, `${id}: invalid exit status`);
    assert(result.status === 0, `${id}: hermesc exited ${result.status}`);
    assert(stdout.length <= contract.maxStdoutBytes, `${id}: stdout exceeds limit`);
    assert(stderr.length <= contract.maxStderrBytes, `${id}: stderr exceeds limit`);
    const outputFiles = [];
    const bytecodeOutputs = [];
    if (expectsHbc) {
      inspectWorkspace(workspace, ["input", FIXTURE_WORKSPACE_PATH, "output", HBC_OUTPUT_PATH]);
      const outputBytes = readRegularFile(path.join(workspace, HBC_OUTPUT_PATH), "compiled smoke HBC", contract.maxOutputBytes);
      assert(
        (fs.lstatSync(path.join(workspace, HBC_OUTPUT_PATH)).mode & 0o111) === 0,
        "compiled smoke HBC must not be executable",
      );
      const hbc = parseHermesBytecode(outputBytes);
      assert(hbc.version === 99, `compiled smoke HBC has bytecode version ${hbc.version}, not 99`);
      outputFiles.push({ path: HBC_OUTPUT_PATH, digest: rawDigest(outputBytes), size: outputBytes.length, executable: false });
      bytecodeOutputs.push({
        path: HBC_OUTPUT_PATH,
        bytecodeVersion: hbc.version,
        sourcePath: FIXTURE_WORKSPACE_PATH,
        sourceDigest: rawDigest(fixtureBytes),
      });
    } else {
      inspectWorkspace(workspace, ["input", FIXTURE_WORKSPACE_PATH]);
    }
    let retainedFixture;
    try {
      retainedFixture = readRegularFile(inputPath, `${id} input fixture`, fixtureBytes.length);
    } catch {
      throw new Error(`${id}: host tool changed its exact input fixture`);
    }
    assert(retainedFixture.equals(fixtureBytes), `${id}: host tool changed its exact input fixture`);
    return {
      evidence: {
        id,
        argv: [...args],
        expectedExitCode: result.status,
        stdoutDigest: rawDigest(stdout),
        stdoutSize: stdout.length,
        stderrDigest: rawDigest(stderr),
        stderrSize: stderr.length,
        outputFiles,
        bytecodeOutputs,
      },
      stdout,
      stderr,
    };
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
}

function parseReportedHbcVersion(stdout, stderr) {
  const combined = Buffer.concat([stdout, Buffer.from("\n"), stderr]);
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(combined);
  } catch (error) {
    throw new Error(`hermesc --version output is not UTF-8: ${error.message}`);
  }
  const matches = [...text.matchAll(/^\s*HBC bytecode version:\s*([0-9]+)\s*$/gmu)];
  assert(matches.length === 1, `hermesc --version must report exactly one HBC bytecode version; found ${matches.length}`);
  const version = Number(matches[0][1]);
  assert(Number.isSafeInteger(version), "hermesc HBC bytecode version is unsafe");
  return version;
}

function buildHostToolCompatibility({
  toolPath,
  toolBytes,
  toolMachO,
  fixtureBytes,
  targetPolicy,
  physicalHostTriple,
  runner,
}) {
  const execution = targetPolicy.hostTool.executionContract;
  assertExactKeys(
    execution,
    [
      "environmentMode",
      "environment",
      "stdin",
      "workingDirectoryLifetime",
      "argv0",
      "timeoutMs",
      "maxStdoutBytes",
      "maxStderrBytes",
      "maxOutputBytes",
    ],
    "host-tool execution contract",
  );
  assert(execution.environmentMode === "replace-exactly", "host-tool environment must replace inherited values");
  assert(execution.stdin === "empty", "host-tool stdin must be empty");
  assert(execution.workingDirectoryLifetime === "fresh-private-per-invocation", "host-tool workspace must be fresh per invocation");
  assert(execution.argv0 === "exact-tool-path", "host-tool argv0 must be exact tool path");
  assertSame(
    execution.environment,
    [
      { name: "LC_ALL", value: "C" },
      { name: "TZ", value: "UTC" },
    ],
    "host-tool exact environment",
  );
  const version = runHostToolInvocation({
    id: "version",
    args: ["--version"],
    toolPath,
    fixtureBytes,
    contract: execution,
    runner,
    expectsHbc: false,
  });
  const reportedVersion = parseReportedHbcVersion(version.stdout, version.stderr);
  assert(reportedVersion === targetPolicy.profile.hermesBytecodeVersion, `hermesc reports HBC ${reportedVersion}, expected ${targetPolicy.profile.hermesBytecodeVersion}`);
  const compile = runHostToolInvocation({
    id: "compile-smoke",
    args: ["-emit-binary", "-out", HBC_OUTPUT_PATH, FIXTURE_WORKSPACE_PATH],
    toolPath,
    fixtureBytes,
    contract: execution,
    runner,
    expectsHbc: true,
  });
  const systemPolicy = targetPolicy.systemDependencyPolicyKey;
  assert(systemPolicy === "apple", "host tool must use Apple system-dependency policy");
  return {
    schema: "ibex/portable-engine-host-tool-compatibility/1",
    toolRole: "bytecode-compiler",
    toolPath: TOOL_PAYLOAD_PATH,
    toolDigest: rawDigest(toolBytes),
    actualHostTriple: physicalHostTriple,
    binaryMachine: structuredClone(targetPolicy.hostTool.binaryMachine),
    environmentMode: execution.environmentMode,
    environment: structuredClone(execution.environment),
    stdin: execution.stdin,
    workingDirectoryLifetime: execution.workingDirectoryLifetime,
    argv0: execution.argv0,
    timeoutMs: execution.timeoutMs,
    maxStdoutBytes: execution.maxStdoutBytes,
    maxStderrBytes: execution.maxStderrBytes,
    maxOutputBytes: execution.maxOutputBytes,
    dependencyClosure: {
      // Every direct dependency is already a closed platform-system leaf, so
      // the complete transitive non-system closure is empty.
      extractor: {
        format: "mach-o",
        tables: [
          "LC_LAZY_LOAD_DYLIB",
          "LC_LOAD_DYLIB",
          "LC_LOAD_UPWARD_DYLIB",
          "LC_LOAD_WEAK_DYLIB",
          "LC_REEXPORT_DYLIB",
        ],
        transitive: true,
      },
      nonSystemDependencies: [],
      systemDependencies: [...toolMachO.dependencies],
    },
    inputFixtures: [
      {
        fixturePayloadPath: FIXTURE_PAYLOAD_PATH,
        workspacePath: FIXTURE_WORKSPACE_PATH,
        digest: rawDigest(fixtureBytes),
        size: fixtureBytes.length,
        executable: false,
      },
    ],
    invocations: [compile.evidence, version.evidence].sort((left, right) => compareUtf8(left.id, right.id)),
  };
}

function addAuthorityDocument(payload, pathname, document) {
  const bytes = Buffer.from(canonicalJson(document), "utf8");
  assertCanonicalJsonBytes(bytes, document, pathname);
  payload.addRegular(pathname, "metadata", bytes, false);
}

function validateManifestConstruction(manifest, payload, limits) {
  assert(manifest.schema === "ibex/portable-engine-manifest/1", "manifest schema mismatch");
  assert(manifest.artifactKind === "hermes", "manifest artifact kind mismatch");
  assert(manifest.target.triple === TARGET_TRIPLE, "manifest target mismatch");
  assert(manifest.runtimeComponent === RUNTIME_COMPONENT, "manifest runtime component mismatch");
  const entries = payload.manifestEntries();
  assertSame(manifest.entries, entries, "manifest exact payload membership");
  assertUniquePortablePaths(entries.map((entry) => entry.path));
  assert(entries.every((entry, index) => index === 0 || compareUtf8(entries[index - 1].path, entry.path) < 0), "manifest entries are not strictly sorted");
  const regular = new Map(entries.filter((entry) => entry.kind === "regular").map((entry) => [entry.path, entry]));
  const runtimeRows = manifest.interface.loadableComponents.filter((row) => row.system === false);
  assert(runtimeRows.length === 1 && runtimeRows[0].role === "runtime" && runtimeRows[0].path === RUNTIME_COMPONENT, "manifest does not have runtime-only non-system topology");
  assert(regular.get(RUNTIME_COMPONENT)?.digest === runtimeRows[0].digest, "runtime component does not join its regular entry");
  assert(manifest.interface.hostTools.length === 1, "manifest must have one required host tool");
  assert(regular.get(TOOL_PAYLOAD_PATH)?.digest === manifest.interface.hostTools[0].digest, "host tool does not join its regular entry");
  assert(entries.length + 3 <= limits.maxMemberCount, "archive member count exceeds policy");
  let expanded = 0;
  for (const entry of entries) {
    if (entry.kind === "regular") {
      assert(entry.size <= limits.maxRegularFileBytes, `${entry.path}: regular file exceeds policy`);
      expanded += entry.size;
    }
  }
  assert(expanded <= limits.maxExpandedBytes, "payload expanded bytes exceed policy");
}

export function buildPortableHermesMacosPackage(options, dependencies = {}) {
  const repoRoot = path.resolve(options.repoRoot ?? defaultRepoRoot);
  const sourceRef = options.sourceRef ?? process.env.GITHUB_REF;
  const expectedSourceRevision = options.expectedSourceRevision ?? process.env.GITHUB_SHA;
  assertString(sourceRef, "publisher source ref");
  assertString(expectedSourceRevision, "expected publisher source revision");
  const physicalHost = dependencies.physicalHost ?? {
    platform: process.platform,
    architecture: process.arch,
  };
  assertExactKeys(physicalHost, ["platform", "architecture"], "physical producer host");
  assert(
    physicalHost.platform === "darwin" && physicalHost.architecture === "arm64",
    `portable macOS arm64 production requires darwin/arm64; observed ${physicalHost.platform}/${physicalHost.architecture}`,
  );
  const physicalHostTriple = "aarch64-apple-darwin";
  requireCleanGitCheckout(repoRoot);

  const policyPath = path.join(repoRoot, "schemas/portable-engine-provenance-trust-policy-v1.json");
  const policyBytes = readRegularFile(policyPath, "portable engine trust policy");
  const trustPolicy = parseJsonStrict(policyBytes, "portable engine trust policy");
  const targetPolicy = validateTrustPolicy(trustPolicy, sourceRef);
  assert(
    targetPolicy.hostTool.actualHostTriple === physicalHostTriple,
    "physical host triple differs from the admitted host-tool triple",
  );
  const sourceTree = deriveSourceTreeIdentity(repoRoot, sourceRef, expectedSourceRevision);
  const authority = hashAuthorityPaths(repoRoot, sourceTree.sourceRevision, targetPolicy.buildAuthorityPaths);
  const sourceAuthorities = deriveReviewedSourceAuthorities(repoRoot, sourceTree.sourceRevision, authority);

  const frameworkPath = path.resolve(options.frameworkPath);
  const includePath = path.resolve(options.includePath);
  const hermescPath = path.resolve(options.hermescPath);
  const receiptPath = path.resolve(options.receiptPath);
  const fixturePath = path.join(repoRoot, "tests/fixtures/portable-engine/host-tools/smoke.js");

  const payload = new Payload(trustPolicy.archiveLimits);
  payload.addDirectory("lib", "runtime");
  collectDirectory(frameworkPath, "lib/hermesvm.framework", payload, (payloadPath, status) => ({
    role: payloadPath === RUNTIME_COMPONENT ? "runtime" : "framework-resource",
    executable: payloadPath === RUNTIME_COMPONENT,
    allowSymlink: status.isSymbolicLink(),
  }));
  collectDirectory(includePath, "include", payload, (_payloadPath, status) => ({
    role: "header",
    executable: false,
    allowSymlink: status.isSymbolicLink(),
  }));
  payload.addDirectory("bin", "host-tool");
  const toolBytes = readRegularFile(
    hermescPath,
    "hermesc",
    Math.min(
      targetPolicy.hostTool.executionContract.maxOutputBytes * 512,
      trustPolicy.archiveLimits.maxRegularFileBytes,
      trustPolicy.archiveLimits.maxExpandedBytes - payload.expandedBytes,
    ),
  );
  assert((fs.lstatSync(hermescPath).mode & 0o111) !== 0, "hermesc input is not executable");
  payload.addRegular(TOOL_PAYLOAD_PATH, "host-tool", toolBytes, true);
  payload.addDirectory("share", "profile-receipt");
  payload.addDirectory("share/hermes", "profile-receipt");
  const receiptBytes = readRegularFile(receiptPath, "Hermes profile receipt", 1024 * 1024);
  payload.addRegular(RECEIPT_PAYLOAD_PATH, "profile-receipt", receiptBytes, false);
  payload.addDirectory("share/compatibility", "compatibility-fixture");
  payload.addDirectory("share/compatibility/host-tools", "compatibility-fixture");
  payload.addDirectory("share/compatibility/host-tools/input", "compatibility-fixture");
  const fixtureBytes = readRegularFile(fixturePath, "checked host-tool smoke fixture", 64 * 1024);
  payload.addRegular(FIXTURE_PAYLOAD_PATH, "compatibility-fixture", fixtureBytes, false);

  const runtimeMember = payload.members.get(RUNTIME_COMPONENT);
  assert(runtimeMember?.kind === "regular", "framework runtime component is missing or not regular");
  for (const member of payload.members.values()) {
    if (
      member.kind === "regular" &&
      member.path.startsWith("lib/") &&
      member.path !== RUNTIME_COMPONENT
    ) {
      assert(!hasMachOMagic(member.bytes), `undeclared framework Mach-O component: ${member.path}`);
    }
  }
  const runtimeSourcePath = path.join(frameworkPath, "Versions/1/hermesvm");
  assert((fs.lstatSync(runtimeSourcePath).mode & 0o111) !== 0, "framework runtime input is not executable");
  assert(
    rawDigest(readRegularFile(runtimeSourcePath, "framework runtime source", runtimeMember.size)) ===
      runtimeMember.digest,
    "runtime payload snapshot differs from the exact framework component",
  );
  const runtimeMachO = parseMachO(runtimeMember.bytes, { architecture: "arm64" });
  const toolMachO = parseMachO(toolBytes, { architecture: "arm64" });
  assert(runtimeMachO.fileType === MACHO_FILETYPE_DYLIB, "arm64 Hermes runtime slice is not MH_DYLIB");
  assert(
    runtimeMachO.dylibId === HERMES_FRAMEWORK_INSTALL_NAME && runtimeMachO.dylinker === null,
    "arm64 Hermes runtime has the wrong framework install name or dynamic-linker command",
  );
  assert(
    toolMachO.container === "thin" &&
      toolMachO.fileType === MACHO_FILETYPE_EXECUTE &&
      toolMachO.dylibId === null &&
      toolMachO.dylinker === MACOS_DYNAMIC_LINKER &&
      toolMachO.sliceOffset === 0 &&
      toolMachO.sliceSize === toolBytes.length &&
      canonicalJson(toolMachO.containerArchitectures) === canonicalJson(["arm64"]),
    "hermesc must be a thin arm64 Mach-O executable",
  );
  const allowedSystemDependencies = trustPolicy.platformSystemDependencies[targetPolicy.systemDependencyPolicyKey];
  assertExactKeys(trustPolicy.platformSystemDependencies, ["apple", "linux", "windows"], "platform system dependencies");
  assert(Array.isArray(allowedSystemDependencies), "Apple system dependency allowlist is absent");
  assert(allowedSystemDependencies.length > 0, "Apple system dependency allowlist is empty");
  assert(new Set(allowedSystemDependencies).size === allowedSystemDependencies.length, "Apple system dependency allowlist has duplicates");
  assertSame(allowedSystemDependencies, [...allowedSystemDependencies].sort(compareUtf8), "Apple system dependency order");
  assertSame(runtimeMachO.dependencies, [...allowedSystemDependencies].sort(compareUtf8), "runtime complete system dependency topology");
  for (const dependency of toolMachO.dependencies) {
    assert(allowedSystemDependencies.includes(dependency), `hermesc has non-admitted dependency: ${dependency}`);
  }
  validateExportPolicy(runtimeMachO.externalDefinedSymbolNames, targetPolicy.exportPolicy);
  const profile = validateProfileReceipt(receiptBytes, runtimeMember.digest, targetPolicy, sourceAuthorities);
  if (profile.receipt.artifact.targetArchitecture === "universal") {
    assert(
      runtimeMachO.container === "fat" &&
        canonicalJson(runtimeMachO.containerArchitectures) === canonicalJson(["arm64", "x86_64"]),
      "universal receipt must describe exactly arm64 and x86_64 runtime slices",
    );
    const x86Runtime = parseMachO(runtimeMember.bytes, { architecture: "x86_64" });
    assert(x86Runtime.fileType === MACHO_FILETYPE_DYLIB, "x86_64 Hermes runtime slice is not MH_DYLIB");
    assert(
      x86Runtime.dylibId === HERMES_FRAMEWORK_INSTALL_NAME && x86Runtime.dylinker === null,
      "x86_64 Hermes runtime has the wrong framework install name or dynamic-linker command",
    );
    assertSame(
      x86Runtime.dependencies,
      [...allowedSystemDependencies].sort(compareUtf8),
      "universal x86_64 runtime system dependency topology",
    );
    validateExportPolicy(x86Runtime.externalDefinedSymbolNames, targetPolicy.exportPolicy);
  } else {
    assert(
      runtimeMachO.container === "thin" &&
        runtimeMachO.sliceOffset === 0 &&
        runtimeMachO.sliceSize === runtimeMember.bytes.length &&
        canonicalJson(runtimeMachO.containerArchitectures) === canonicalJson(["arm64"]),
      "aarch64-only receipt cannot describe a fat runtime",
    );
  }
  const runtimeHbcObservation = (
    dependencies.runRuntimeHbcProbe ?? observeRuntimeHbcVersion
  )({
    includePath,
    runtimePath: runtimeSourcePath,
    runtimeDigest: runtimeMember.digest,
    runtimeSize: runtimeMember.size,
    allowedSystemDependencies,
  });
  assertExactKeys(runtimeHbcObservation, ["version"], "runtime HBC observation");
  assert(
    runtimeHbcObservation.version === targetPolicy.profile.hermesBytecodeVersion,
    `runtime reports HBC ${runtimeHbcObservation.version}, expected ${targetPolicy.profile.hermesBytecodeVersion}`,
  );

  const hostToolCompatibility = buildHostToolCompatibility({
    toolPath: hermescPath,
    toolBytes,
    toolMachO,
    fixtureBytes,
    targetPolicy,
    physicalHostTriple,
    runner: dependencies.runHostTool ?? defaultHostToolRunner,
  });
  let retainedToolBytes;
  try {
    retainedToolBytes = readRegularFile(
      hermescPath,
      "hermesc after compatibility execution",
      toolBytes.length,
    );
  } catch {
    throw new Error("hermesc bytes changed during compatibility execution");
  }
  assert(
    rawDigest(retainedToolBytes) === rawDigest(toolBytes),
    "hermesc bytes changed during compatibility execution",
  );
  const hbcEvidence = hostToolCompatibility.invocations
    .flatMap((invocation) => invocation.bytecodeOutputs)
    .map((output) => output.bytecodeVersion);
  assertSame(hbcEvidence, [targetPolicy.profile.hermesBytecodeVersion], "complete host-tool HBC output versions");

  const component = { path: RUNTIME_COMPONENT, digest: runtimeMember.digest };
  const requiredExports = {
    schema: "ibex/portable-engine-export-set/1",
    mode: "required",
    targetTriple: TARGET_TRIPLE,
    extractor: targetPolicy.exportExtractor,
    components: [component],
    symbolNameSemantics: "utf8-bytes-no-normalization",
    matchers: structuredClone(targetPolicy.exportPolicy.requiredMatchers),
  };
  const forbiddenExports = {
    schema: "ibex/portable-engine-export-set/1",
    mode: "forbidden",
    targetTriple: TARGET_TRIPLE,
    extractor: targetPolicy.exportExtractor,
    components: [component],
    symbolNameSemantics: "utf8-bytes-no-normalization",
    matchers: structuredClone(targetPolicy.exportPolicy.forbiddenMatchers),
  };
  const headerSet = {
    schema: "ibex/portable-engine-header-set/1",
    targetTriple: TARGET_TRIPLE,
    includeRoots: ["include"],
    headers: payload
      .manifestEntries()
      .filter((entry) => entry.kind === "regular" && entry.role === "header")
      .map(({ path: pathname, digest, size }) => ({ path: pathname, digest, size })),
  };
  assert(headerSet.headers.length > 0, "portable package contains no headers");
  const requiredExportsDigest = semanticDigest("ibex.portable-engine-required-exports.v1", requiredExports);
  const forbiddenExportsDigest = semanticDigest("ibex.portable-engine-forbidden-exports.v1", forbiddenExports);
  const headerSetDigest = semanticDigest("ibex.portable-engine-header-set.v1", headerSet);
  const abiContract = {
    schema: "ibex/portable-engine-abi-contract/1",
    target: { triple: TARGET_TRIPLE, structuralFeatures: structuredClone(targetPolicy.structuralFeatures) },
    ...structuredClone(targetPolicy.directJsiAbi),
    headerSetDigest,
    requiredExportsDigest,
    forbiddenExportsDigest,
  };
  // The schema orders no fields, but the exact policy contract has no unknown
  // dimensions. The spread above is safe only after this exact-key assertion.
  assertExactKeys(
    targetPolicy.directJsiAbi,
    [
      "languageBoundary",
      "cxxStandard",
      "compilerAbi",
      "standardLibraryAbi",
      "exceptions",
      "rtti",
      "pointerWidth",
      "endianness",
      "allocationBoundary",
      "contractFeatures",
    ],
    "direct JSI ABI policy",
  );
  const reviewedProfileIdentityDigest = semanticDigest(
    "ibex.portable-engine-reviewed-profile-identity.v1",
    profile.reviewedProfileIdentity,
  );
  const sourceTreeDigest = semanticDigest("ibex.portable-engine-source-tree-identity.v1", sourceTree.document);
  const abiContractDigest = semanticDigest("ibex.portable-engine-abi-contract.v1", abiContract);
  const hostToolCompatibilityDigest = semanticDigest(
    "ibex.portable-engine-host-tool-compatibility.v1",
    hostToolCompatibility,
  );

  payload.addDirectory("META-INF", "metadata");
  payload.addDirectory("META-INF/authority", "metadata");
  payload.addDirectory("META-INF/authority/host-tools", "metadata");
  payload.addDirectory("META-INF/authority/source-tree", "metadata");
  addAuthorityDocument(payload, "META-INF/authority/abi-contract.json", abiContract);
  addAuthorityDocument(payload, "META-INF/authority/forbidden-exports.json", forbiddenExports);
  addAuthorityDocument(payload, "META-INF/authority/header-set.json", headerSet);
  addAuthorityDocument(
    payload,
    `META-INF/authority/host-tools/${hostToolCompatibilityDigest}.json`,
    hostToolCompatibility,
  );
  addAuthorityDocument(payload, "META-INF/authority/required-exports.json", requiredExports);
  addAuthorityDocument(payload, "META-INF/authority/reviewed-profile-identity.json", profile.reviewedProfileIdentity);
  addAuthorityDocument(payload, "META-INF/authority/source-tree-identity.json", sourceTree.document);
  payload.addRegular(sourceTree.document.sourceRevisionObjectContent.path, "metadata", sourceTree.commitBytes, false);
  payload.addRegular(sourceTree.document.treeObjectContent.path, "metadata", sourceTree.treeBytes, false);

  const loadableComponents = [
    { role: "runtime", path: RUNTIME_COMPONENT, digest: runtimeMember.digest, system: false },
    ...runtimeMachO.dependencies.map((name) => ({ role: "runtime-dependency", name, system: true })),
  ];
  const manifest = {
    schema: "ibex/portable-engine-manifest/1",
    artifactId: "",
    artifactKind: "hermes",
    target: { triple: TARGET_TRIPLE, structuralFeatures: structuredClone(targetPolicy.structuralFeatures) },
    profile: {
      ...structuredClone(targetPolicy.profile),
      reviewedProfileIdentityDigest,
    },
    source: profile.source,
    build: {
      repository: trustPolicy.enginePublisher.repository,
      sourceRevision: sourceTree.sourceRevision,
      sourceTreeDigest,
      sourceRef,
      publisherWorkflow: trustPolicy.enginePublisher.workflowPath,
      authorityDigests: authority.rows,
    },
    interface: {
      abiContractDigest,
      requiredExportsDigest,
      forbiddenExportsDigest,
      headerSetDigest,
      hostTools: [
        {
          role: "host-tool",
          path: TOOL_PAYLOAD_PATH,
          digest: rawDigest(toolBytes),
          compatibilityDigest: hostToolCompatibilityDigest,
        },
      ],
      loadableComponents,
    },
    entries: payload.manifestEntries(),
    runtimeComponent: RUNTIME_COMPONENT,
  };
  manifest.artifactId = semanticDigest("ibex.portable-engine-manifest.v1", manifest, ["artifactId"]);
  validateManifestConstruction(manifest, payload, trustPolicy.archiveLimits);
  const manifestBytes = Buffer.from(canonicalJson(manifest), "utf8");
  assertCanonicalJsonBytes(manifestBytes, manifest, "portable engine manifest");
  assert(
    manifestBytes.length <= trustPolicy.archiveLimits.maxRegularFileBytes,
    "portable engine manifest exceeds the regular-file limit",
  );
  const payloadExpandedBytes = manifest.entries
    .filter((entry) => entry.kind === "regular")
    .reduce((total, entry) => total + entry.size, 0);
  assert(
    payloadExpandedBytes + manifestBytes.length <=
      trustPolicy.archiveLimits.maxExpandedBytes,
    "portable package expanded bytes exceed policy",
  );

  const archiveMembers = [
    { path: "META-INF", kind: "directory" },
    {
      path: "META-INF/portable-engine-manifest.json",
      kind: "regular",
      bytes: manifestBytes,
      executable: false,
    },
    { path: "payload", kind: "directory" },
    ...payload.archiveMembers(),
  ];
  const expectedTarSize = deterministicUstarSize(archiveMembers);
  const expectedArchiveSize = deterministicUstarGzipSize(archiveMembers);
  assert(
    expectedArchiveSize <= trustPolicy.archiveLimits.maxArchiveBytes,
    "deterministic archive would exceed policy byte limit",
  );
  const archiveBytes = buildDeterministicUstarGzip(archiveMembers);
  assert(
    archiveBytes.length === expectedArchiveSize,
    "deterministic archive size differs from its checked pre-allocation projection",
  );
  const inspected = inspectUstarGzip(archiveBytes, {
    maxArchiveBytes: trustPolicy.archiveLimits.maxArchiveBytes,
    maxOutputBytes: expectedTarSize,
    maxMemberCount: trustPolicy.archiveLimits.maxMemberCount,
    maxRegularFileBytes: trustPolicy.archiveLimits.maxRegularFileBytes,
    maxExpandedBytes: trustPolicy.archiveLimits.maxExpandedBytes,
    maxSymlinkDepth: trustPolicy.archiveLimits.maxSymlinkDepth,
  });
  assertSame(
    inspected.map(({ path: pathname, kind }) => ({ path: pathname, kind })),
    archiveMembers
      .map(({ path: pathname, kind }) => ({ path: pathname, kind }))
      .sort((left, right) => compareUtf8(left.path, right.path)),
    "archive exact membership",
  );
  const archivedManifest = inspected.find((member) => member.path === "META-INF/portable-engine-manifest.json");
  assert(archivedManifest?.kind === "regular" && archivedManifest.bytes.equals(manifestBytes), "archive manifest bytes changed");

  return {
    archiveBytes,
    archiveDigest: rawDigest(archiveBytes),
    manifest,
    manifestBytes,
    documents: {
      trustPolicy,
      sourceTreeIdentity: sourceTree.document,
      reviewedProfileIdentity: profile.reviewedProfileIdentity,
      requiredExports,
      forbiddenExports,
      headerSet,
      abiContract,
      hostToolCompatibility,
    },
    observations: {
      runtimeHbcVersion: runtimeHbcObservation.version,
      runtimeSymbolsBase64: runtimeMachO.externalDefinedSymbolNames.map((name) => name.toString("base64")),
      runtimeDependencies: runtimeMachO.dependencies,
      hostToolDependencies: toolMachO.dependencies,
    },
  };
}

function writeArchiveAtomically(outputPath, archiveBytes) {
  const absolute = path.resolve(outputPath);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  assert(!fs.existsSync(absolute), `refusing to replace existing output: ${absolute}`);
  const temporary = `${absolute}.tmp-${process.pid}-${Date.now()}`;
  try {
    fs.writeFileSync(temporary, archiveBytes, { flag: "wx", mode: 0o644 });
    fs.linkSync(temporary, absolute);
    fs.unlinkSync(temporary);
  } catch (error) {
    try {
      fs.unlinkSync(temporary);
    } catch (cleanupError) {
      if (cleanupError.code !== "ENOENT") throw cleanupError;
    }
    throw error;
  }
  return absolute;
}

function parseArguments(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (!option.startsWith("--")) throw new Error(`unexpected positional argument: ${option}`);
    const name = option.slice(2);
    if (![
      "repo-root",
      "cache-root",
      "framework",
      "include",
      "hermesc",
      "receipt",
      "source-ref",
      "expected-source-revision",
      "output",
    ].includes(name)) {
      throw new Error(`unknown option: ${option}`);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`${option} requires a value`);
    if (name in values) throw new Error(`duplicate option: ${option}`);
    values[name] = value;
    index += 1;
  }
  const cache = values["cache-root"] ? path.resolve(values["cache-root"]) : null;
  const options = {
    repoRoot: values["repo-root"] ?? defaultRepoRoot,
    frameworkPath: values.framework ?? (cache && path.join(cache, "hermesvm.framework")),
    includePath: values.include ?? (cache && path.join(cache, "include")),
    hermescPath: values.hermesc ?? (cache && path.join(cache, "bin/hermesc")),
    receiptPath: values.receipt ?? (cache && path.join(cache, "hermes-profile-provenance.json")),
    sourceRef: values["source-ref"] ?? process.env.GITHUB_REF,
    expectedSourceRevision: values["expected-source-revision"] ?? process.env.GITHUB_SHA,
  };
  for (const [name, value] of Object.entries({
    framework: options.frameworkPath,
    include: options.includePath,
    hermesc: options.hermescPath,
    receipt: options.receiptPath,
    "expected-source-revision": options.expectedSourceRevision,
    output: values.output,
  })) {
    if (!value) throw new Error(`--${name} is required (or supply --cache-root where applicable)`);
  }
  return { options, outputPath: values.output };
}

export function main(argv = process.argv.slice(2)) {
  const { options, outputPath } = parseArguments(argv);
  assert(!fs.existsSync(path.resolve(outputPath)), `refusing to replace existing output: ${path.resolve(outputPath)}`);
  const result = buildPortableHermesMacosPackage(options);
  const written = writeArchiveAtomically(outputPath, result.archiveBytes);
  process.stdout.write(
    `${canonicalJson({
      authority: "diagnostic-only",
      portableArtifactAcceptanceEnabled: false,
      artifactId: result.manifest.artifactId,
      archiveDigest: result.archiveDigest,
      archivePath: written,
    })}\n`,
  );
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`package-portable-hermes-macos: ${error.message}\n`);
    process.exitCode = 1;
  }
}
