// Verify that a portable-engine admission is the only authority-bearing change
// in one exact, non-fast-forward promotion merge.
//
// Production installation and store verification consume this fixed verifier.
// A disabled catalog returns a checked diagnostic result; an active catalog is
// useful only after this verifier reconstructs and hashes the complete Git
// lineage and exact changed-blob set. Runtime and Host startup remain closed.
//
// @ref LLP 0035#promotion-lineage-and-admission — source artifacts are built at
// a closed commit, then admitted only by a current, non-inheriting merge whose
// tree contains the exact reviewed evidence and no code drift.
// @ref LLP 0035#content-addressed-installation — checked repository authority
// is read through an OS-trusted Git under a closed environment and every raw
// commit, tree, and authority blob is independently object-hashed.
// @ref LLP 0021#a9-appendix--the-scope-digest-join-matrix — M19/M27 bind each
// admitted scope to a content-hashed promotion hop and the full target tuple.

import * as fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
  assertExactKeys,
  canonicalJson,
  compareUtf8,
  gitObjectId,
  parseJsonStrict,
  rawDigest,
  semanticDigest,
} from "./portable-engine-contract.mjs";
import {
  validatePortablePromotionBundleGraph,
} from "../packages/ibex-devtools/src/scripts/verify-capsec-portable-promotion-bundle.mjs";
import {
  SCOPE_SCHEMA,
  computeScopeDigest,
} from "../packages/ibex-devtools/src/scripts/capsec-scope-artifact.mjs";

const CATALOG_SCHEMA_V1 = "ibex/portable-engine-promotion-admission-catalog/1";
const CATALOG_SCHEMA = "ibex/portable-engine-promotion-admission-catalog/2";
const ADMISSION_SCHEMA = "ibex/portable-engine-promotion-admission/2";
const VERIFICATION_SCHEMA = "ibex/portable-engine-promotion-lineage-verification/1";
const CHECKED_ADMISSION_SCHEMA = "ibex/portable-engine-checked-promotion-admission/2";
const ADMISSION_DOMAIN = "ibex.portable-engine-promotion-admission.v2";
const CHECKED_ADMISSION_DOMAIN = "ibex.portable-engine-checked-promotion-admission.v2";
const MERGE_TOPOLOGY = "github-pull-request-merge/direct-single-commit-topic/1";
const CATALOG_PATH = "schemas/portable-engine-promotion-admission-catalog-v1.json";
const CATALOG_SCHEMA_PATH = "schemas/portable-engine-promotion-admission-catalog-v2.schema.json";
const CHECKED_ADMISSION_SCHEMA_PATH = "schemas/portable-engine-checked-promotion-admission-v2.schema.json";
const TRUST_POLICY_PATH = "schemas/portable-engine-provenance-trust-policy-v1.json";
const CAPSEC_POLICY_RULES_PATH = "capsec/registry/policy-rules.json";
const TARGET_ATTESTATION_PATH = "capsec/conformance/target-attestations.json";
const TARGET_ADVERTISEMENT_PATH = "capsec/generated/target-advertisements.json";
const MODULE_PATH = "scripts/portable-engine-promotion-lineage.mjs";
const CONTRACT_PATH = "scripts/portable-engine-contract.mjs";
const BUNDLE_VERIFIER_PATH =
  "packages/ibex-devtools/src/scripts/verify-capsec-portable-promotion-bundle.mjs";
const PORTABLE_EVIDENCE_CONTRACT_PATH =
  "packages/ibex-devtools/src/scripts/capsec-portable-engine-evidence-contract.mjs";
const CAPSEC_SCOPE_ARTIFACT_PATH =
  "packages/ibex-devtools/src/scripts/capsec-scope-artifact.mjs";
const PORTABLE_EVIDENCE_SCHEMA_PATHS = Object.freeze([
  "capsec/schema/common.schema.json",
  "capsec/schema/target-cell.schema.json",
  "schemas/portable-engine-common-v1.schema.json",
  "schemas/portable-engine-artifact-identity-v1.schema.json",
  "schemas/mapped-engine-instance-identity-v1.schema.json",
  "schemas/capsec-portable-engine-evidence-common-v1.schema.json",
  "schemas/capsec-command-attempt-v1.schema.json",
  "schemas/capsec-executable-recipes-v2.schema.json",
  "schemas/capsec-public-surface-executions-v2.schema.json",
  "schemas/capsec-output-disposition-evidence-v4.schema.json",
  "schemas/capsec-portable-fixture-evidence-v1.schema.json",
  "schemas/capsec-mapped-engine-execution-evidence-v1.schema.json",
  "schemas/capsec-conformance-report-v2.schema.json",
  "schemas/capsec-target-attestations-v2.schema.json",
  "schemas/capsec-target-advertisements-v3.schema.json",
  "schemas/capsec-portable-promotion-authority-v1.schema.json",
]);
const SCOPE_ROLE = "scope-artifact";
const SCOPE_PATH_BASENAME = "capsec-scope.json";
const SCOPE_GENESIS_MARKER = "genesis";
const LINEAGE_FLOOR = "afad4af9f4257eb8262cf8348e5fbb0a3c082ecf";
// Historical recomputation is deliberately version-dispatched. Retaining this
// table is part of the published lineage contract; removing an old row would
// make an otherwise valid historical hop unverifiable.
const SCOPE_DIGEST_FORMATS = Object.freeze({
  [SCOPE_SCHEMA]: Object.freeze({ computeDigest: computeScopeDigest }),
});
const SYSTEM_GIT = "/usr/bin/git";
const MAX_GIT_OBJECT_BYTES = 72 * 1024 * 1024;
const MAX_CHANGED_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_TREE_ENTRIES = 250_000;
const MAX_TREE_DEPTH = 64;
// One verified bundle admits at most MAX_MEMBERS bundle members, its manifest,
// and the two byte-identical top-level target publications.
const MIN_CHANGED_ARTIFACTS = 15;
const MAX_CHANGED_ARTIFACTS = 100_003;
const fatalUtf8 = new TextDecoder("utf-8", { fatal: true });
const moduleFilePath = fileURLToPath(import.meta.url);
const CHECKED_GIT_ENV = Object.freeze({
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

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

export function portableEnginePromotionLineagePlatformSupported(platform = process.platform) {
  return platform === "darwin";
}

function assertSha1ObjectId(value, label) {
  assert(typeof value === "string" && /^[0-9a-f]{40}$/u.test(value), `${label}: expected one lowercase SHA-1 object ID`);
  return value;
}

function assertSemanticDigest(value, label) {
  assert(typeof value === "string" && /^sha256-[A-Za-z0-9_-]{43}$/u.test(value), `${label}: expected one semantic SHA-256 digest`);
  return value;
}

function assertRawDigest(value, label) {
  assert(typeof value === "string" && /^sha256-[0-9a-f]{64}$/u.test(value), `${label}: expected one raw SHA-256 digest`);
  return value;
}

function assertRepositoryPath(value, label) {
  assert(typeof value === "string" && value.length > 0 && value.length <= 1024, `${label}: expected a bounded path`);
  assert(/^[\x21-\x7e]+$/u.test(value), `${label}: only printable ASCII is admitted`);
  assert(!value.startsWith("/") && !value.includes("\\") && !value.includes(":"), `${label}: absolute, backslash, and colon syntax is forbidden`);
  const segments = value.split("/");
  assert(segments.every((segment) => segment !== "" && segment !== "." && segment !== ".."), `${label}: path is not normalized`);
  return value;
}

function runCheckedGit(
  repoRoot,
  args,
  { encoding = null, maxBuffer = MAX_GIT_OBJECT_BYTES, allowedStatuses = [0] } = {},
) {
  const result = spawnSync(
    SYSTEM_GIT,
    [
      "--no-replace-objects",
      "--literal-pathspecs",
      "-c",
      "core.fsmonitor=false",
      "-c",
      "core.untrackedCache=false",
      ...args,
    ],
    {
      cwd: repoRoot,
      env: CHECKED_GIT_ENV,
      encoding,
      maxBuffer,
      timeout: 30_000,
      windowsHide: true,
    },
  );
  if (result.error || !allowedStatuses.includes(result.status)) {
    const detail = result.error?.message ?? Buffer.from(result.stderr ?? "").toString("utf8").trim();
    fail(`checked Git ${args[0] ?? "command"} failed${detail ? `: ${detail}` : ""}`);
  }
  return result.stdout;
}

function sameObject(left, right, {
  includeLinks = true,
  includeSize = false,
  includeTimes = false,
} = {}) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.uid === right.uid
    && (!includeLinks || left.nlink === right.nlink)
    && (!includeSize || left.size === right.size)
    && (!includeTimes || (left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs));
}

function assertTrustedOwnershipAndMode(status, label, { directory = false, requireSingleLink = false } = {}) {
  const effectiveUid = typeof process.geteuid === "function" ? BigInt(process.geteuid()) : null;
  assert(status.uid === 0n || (effectiveUid !== null && status.uid === effectiveUid), `${label}: must be root- or effective-UID-owned`);
  assert((status.mode & 0o7022n) === 0n, `${label}: special and group/world-writable mode bits are forbidden`);
  if (directory) assert(status.isDirectory() && !status.isSymbolicLink(), `${label}: expected a no-follow directory`);
  else assert(status.isFile() && !status.isSymbolicLink(), `${label}: expected a no-follow regular file`);
  if (requireSingleLink) assert(status.nlink === 1n, `${label}: trusted regular files must have one filesystem link`);
}

function hasWriteEnablingAcl(filePath) {
  const result = spawnSync("/bin/ls", ["-lde", filePath], {
    env: { PATH: "/usr/bin:/bin", LC_ALL: "C", LANG: "C" },
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    timeout: 10_000,
  });
  assert(!result.error && result.status === 0, `${filePath}: cannot inspect macOS ACL state`);
  const mutation = /\b(?:write|append|add_file|add_subdirectory|delete|delete_child|writeattr|writeextattr|writesecurity|chown)\b/u;
  return result.stdout
    .split("\n")
    .some((line) => /^\s+\d+:/u.test(line) && /\ballow\b/u.test(line) && mutation.test(line));
}

function absoluteDirectoryChain(directoryPath) {
  const absolute = path.resolve(directoryPath);
  const parsed = path.parse(absolute);
  const relative = absolute.slice(parsed.root.length);
  const output = [parsed.root];
  let cursor = parsed.root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    output.push(cursor);
  }
  return output;
}

function readDescriptorBytes(descriptor, expectedSize, label) {
  assert(expectedSize >= 0n && expectedSize <= BigInt(MAX_GIT_OBJECT_BYTES), `${label}: trusted file exceeds the authority byte limit`);
  const size = Number(expectedSize);
  const output = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const bytesRead = fs.readSync(descriptor, output, offset, size - offset, offset);
    assert(bytesRead > 0, `${label}: trusted file truncated during descriptor read`);
    offset += bytesRead;
  }
  return output;
}

function lstatMaybe(filePath) {
  try {
    return fs.lstatSync(filePath, { bigint: true });
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function createAuthorityPlane(repoRoot) {
  const directories = new Map();
  const files = new Map();
  const absentPaths = new Map();
  let selectedHeadObjectId = null;

  function pinDirectory(directoryPath, { strictMetadata = false } = {}) {
    const absolute = path.resolve(directoryPath);
    const existing = directories.get(absolute);
    if (existing) {
      if (strictMetadata) existing.strictMetadata = true;
      return existing;
    }
    const lexical = fs.lstatSync(absolute, { bigint: true });
    assertTrustedOwnershipAndMode(lexical, `trusted ancestor ${absolute}`, { directory: true });
    assert(!hasWriteEnablingAcl(absolute), `trusted ancestor ${absolute}: write-enabling ACL is forbidden`);
    const descriptor = fs.openSync(
      absolute,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_DIRECTORY ?? 0),
    );
    const pinned = fs.fstatSync(descriptor, { bigint: true });
    // Directory link counts change when an unrelated sibling directory is
    // created or removed. The pinned descriptor plus dev/inode/mode/owner
    // comparison detects ancestry replacement without treating that ambient
    // namespace churn as mutation of the selected authority path.
    assert(
      sameObject(lexical, pinned, { includeLinks: false }),
      `trusted ancestor ${absolute}: path changed while pinning`,
    );
    const record = { absolute, descriptor, status: pinned, strictMetadata };
    directories.set(absolute, record);
    return record;
  }

  function pinDirectoryChain(directoryPath) {
    const absolute = path.resolve(directoryPath);
    assert(fs.realpathSync(absolute) === absolute, `${absolute}: trusted ancestry must be canonical and symlink-free`);
    for (const component of absoluteDirectoryChain(absolute)) pinDirectory(component);
  }

  function pinFile(filePath, label, { expectedBytes = null, strictMetadata = false, rootOwned = false } = {}) {
    const absolute = path.resolve(filePath);
    const existing = files.get(absolute);
    if (existing) {
      if (strictMetadata) existing.strictMetadata = true;
      if (expectedBytes !== null) {
        const expected = Buffer.from(expectedBytes);
        assert(existing.expectedBytes === null || existing.expectedBytes.equals(expected), `${label}: conflicting checked byte expectations`);
        const current = readDescriptorBytes(existing.descriptor, existing.status.size, label);
        assert(current.equals(expected), `${label}: descriptor bytes differ from checked Git authority`);
        existing.expectedBytes = expected;
      }
      return existing;
    }
    pinDirectoryChain(path.dirname(absolute));
    assert(fs.realpathSync(absolute) === absolute, `${label}: trusted file path must be canonical and symlink-free`);
    const lexical = fs.lstatSync(absolute, { bigint: true });
    assertTrustedOwnershipAndMode(lexical, label, { requireSingleLink: !rootOwned });
    if (rootOwned) assert(lexical.uid === 0n, `${label}: OS-trusted executable must be root-owned`);
    assert(!hasWriteEnablingAcl(absolute), `${label}: write-enabling ACL is forbidden`);
    const descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const pinned = fs.fstatSync(descriptor, { bigint: true });
    assert(sameObject(lexical, pinned, { includeSize: true }), `${label}: path changed while pinning`);
    const bytes = readDescriptorBytes(descriptor, pinned.size, label);
    if (expectedBytes !== null) assert(Buffer.from(expectedBytes).equals(bytes), `${label}: descriptor bytes differ from checked Git authority`);
    const record = {
      absolute,
      descriptor,
      status: pinned,
      digest: rawDigest(bytes),
      expectedBytes: expectedBytes === null ? null : Buffer.from(expectedBytes),
      strictMetadata,
      label,
    };
    files.set(absolute, record);
    return record;
  }

  function pinAbsent(filePath, label) {
    const absolute = path.resolve(filePath);
    assert(lstatMaybe(absolute) === null, `${label}: forbidden control path exists`);
    absentPaths.set(absolute, label);
  }

  function checkedGitPath(args, label, { file = false } = {}) {
    const output = runCheckedGit(repoRoot, args, { encoding: "utf8", maxBuffer: 1024 * 1024 });
    const value = output.endsWith("\n") ? output.slice(0, -1) : output;
    assert(value.length > 0 && !value.includes("\n") && !value.includes("\0"), `${label}: checked Git returned an invalid path`);
    const absolute = path.resolve(repoRoot, value);
    assert(fs.realpathSync(absolute) === absolute, `${label}: Git control path must be canonical and symlink-free`);
    if (file) pinFile(absolute, label, { strictMetadata: true });
    else {
      pinDirectoryChain(absolute);
      pinDirectory(absolute, { strictMetadata: true });
    }
    return absolute;
  }

  function parsePinnedText(record, label, maximumBytes = 64 * 1024) {
    assert(record.status.size > 0n && record.status.size <= BigInt(maximumBytes), `${label}: invalid bounded control-file size`);
    return fatalUtf8.decode(readDescriptorBytes(record.descriptor, record.status.size, label));
  }

  function pinGitObjectDatabase(objectDirectory, seen = new Set(), depth = 0) {
    assert(depth <= 16 && seen.size <= 32, "Git alternate object-database limit exceeded");
    const selectedObjectDir = path.resolve(objectDirectory);
    const objectDir = fs.realpathSync(selectedObjectDir);
    assert(objectDir === selectedObjectDir, "Git object database ancestry must be canonical and symlink-free");
    if (seen.has(objectDir)) return;
    seen.add(objectDir);
    pinDirectoryChain(objectDir);
    pinDirectory(objectDir, { strictMetadata: true });
    const infoDir = path.join(objectDir, "info");
    const infoStatus = lstatMaybe(infoDir);
    if (infoStatus === null) {
      pinAbsent(path.join(infoDir, "alternates"), "Git alternates control");
      pinAbsent(path.join(infoDir, "http-alternates"), "Git HTTP alternates control");
      return;
    }
    assertTrustedOwnershipAndMode(infoStatus, `Git object info directory ${infoDir}`, { directory: true });
    pinDirectoryChain(infoDir);
    pinDirectory(infoDir, { strictMetadata: true });
    const httpAlternates = path.join(infoDir, "http-alternates");
    pinAbsent(httpAlternates, "Git HTTP object alternates");
    const alternatesPath = path.join(infoDir, "alternates");
    const alternatesStatus = lstatMaybe(alternatesPath);
    if (alternatesStatus === null) {
      pinAbsent(alternatesPath, "Git alternates control");
      return;
    }
    const alternates = pinFile(alternatesPath, "Git alternates control", { strictMetadata: true });
    const text = parsePinnedText(alternates, "Git alternates control");
    assert(text.endsWith("\n") && !text.includes("\r"), "Git alternates control must be LF-delimited");
    const rows = text.split("\n").slice(0, -1);
    assert(rows.length > 0 && rows.length <= 16 && rows.every((row) => row.length > 0), "Git alternates control has invalid cardinality");
    for (const row of rows) {
      assert(row.length <= 4096 && !/[\x00-\x1f\x7f]/u.test(row), "Git alternates control contains an unsafe path");
      const selected = path.isAbsolute(row) ? row : path.resolve(objectDir, row);
      pinGitObjectDatabase(selected, seen, depth + 1);
    }
  }

  function pinHeadAuthority(gitDir, commonDir) {
    const headPath = path.join(gitDir, "HEAD");
    const head = pinFile(headPath, "Git HEAD control file", { strictMetadata: true });
    const text = parsePinnedText(head, "Git HEAD control file", 4096);
    const detached = /^([0-9a-f]{40})\n$/u.exec(text);
    if (detached) {
      selectedHeadObjectId = detached[1];
      return;
    }
    const symbolic = /^ref: (refs\/heads\/[A-Za-z0-9][A-Za-z0-9._\/-]{0,1023})\n$/u.exec(text);
    assert(symbolic, "Git HEAD must be detached or name one bounded refs/heads symbolic ref");
    const refName = symbolic[1];
    assertRepositoryPath(refName, "Git symbolic HEAD ref");
    assert(
      refName.split("/").slice(2).every((segment) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(segment)
        && !segment.includes("..") && !segment.endsWith(".lock")),
      "Git symbolic HEAD ref is outside the closed branch-name grammar",
    );
    const looseRefPath = path.join(commonDir, ...refName.split("/"));
    const looseStatus = lstatMaybe(looseRefPath);
    if (looseStatus !== null) {
      const loose = pinFile(looseRefPath, `Git symbolic HEAD ref ${refName}`, { strictMetadata: true });
      const match = /^([0-9a-f]{40})\n$/u.exec(parsePinnedText(loose, `Git symbolic HEAD ref ${refName}`, 4096));
      assert(match, `Git symbolic HEAD ref ${refName} must contain one direct object ID`);
      selectedHeadObjectId = match[1];
      return;
    }
    pinAbsent(looseRefPath, `Git loose symbolic HEAD ref ${refName}`);
    const packedPath = path.join(commonDir, "packed-refs");
    const packed = pinFile(packedPath, "Git packed refs", { strictMetadata: true });
    const packedText = parsePinnedText(packed, "Git packed refs", 16 * 1024 * 1024);
    assert(packedText.endsWith("\n") && !packedText.includes("\r") && !packedText.includes("\0"), "Git packed refs must be bounded LF text");
    const matches = [];
    for (const line of packedText.split("\n")) {
      if (line === "" || line.startsWith("#") || line.startsWith("^")) continue;
      const match = /^([0-9a-f]{40}) (refs\/[!-~]+)$/u.exec(line);
      assert(match, "Git packed refs contains a malformed row");
      if (match[2] === refName) matches.push(match[1]);
    }
    assert(matches.length === 1, `Git packed refs must resolve ${refName} exactly once`);
    selectedHeadObjectId = matches[0];
  }

  const plane = {
    pinAbsentControl(absolutePath, label) {
      pinAbsent(absolutePath, label);
    },
    pinCheckedFile(relativePath, expectedBytes) {
      return pinFile(path.join(repoRoot, relativePath), `running authority ${relativePath}`, { expectedBytes, strictMetadata: true });
    },
    assertResolvedHead(objectId) {
      assert(selectedHeadObjectId !== null && selectedHeadObjectId === objectId, `pinned Git HEAD selector names ${selectedHeadObjectId}, not ${objectId}`);
    },
    recheck() {
      for (const record of directories.values()) {
        const descriptorStatus = fs.fstatSync(record.descriptor, { bigint: true });
        const pathStatus = fs.lstatSync(record.absolute, { bigint: true });
        assert(
          sameObject(record.status, descriptorStatus, {
            includeLinks: false,
            includeTimes: record.strictMetadata,
          })
            && sameObject(record.status, pathStatus, {
              includeLinks: false,
              includeTimes: record.strictMetadata,
            }),
          `trusted directory ${record.absolute} changed during promotion verification`,
        );
      }
      for (const record of files.values()) {
        const descriptorStatus = fs.fstatSync(record.descriptor, { bigint: true });
        const pathStatus = fs.lstatSync(record.absolute, { bigint: true });
        assert(
          sameObject(record.status, descriptorStatus, { includeSize: true, includeTimes: record.strictMetadata })
            && sameObject(record.status, pathStatus, { includeSize: true, includeTimes: record.strictMetadata }),
          `${record.label}: file object changed during promotion verification`,
        );
        const bytes = readDescriptorBytes(record.descriptor, descriptorStatus.size, record.label);
        assert(rawDigest(bytes) === record.digest, `${record.label}: descriptor bytes changed during promotion verification`);
        if (record.expectedBytes !== null) assert(bytes.equals(record.expectedBytes), `${record.label}: descriptor no longer rejoins checked Git bytes`);
      }
      for (const [absolute, label] of absentPaths) {
        assert(lstatMaybe(absolute) === null, `${label}: forbidden control path appeared during promotion verification`);
      }
    },
    close() {
      for (const record of files.values()) fs.closeSync(record.descriptor);
      for (const record of [...directories.values()].reverse()) fs.closeSync(record.descriptor);
    },
  };
  try {
    pinDirectoryChain(repoRoot);
    pinFile(SYSTEM_GIT, "OS-trusted Git executable", { strictMetadata: true, rootOwned: true });
    const dotGitPath = path.join(repoRoot, ".git");
    const dotGitStatus = lstatMaybe(dotGitPath);
    assert(dotGitStatus !== null && !dotGitStatus.isSymbolicLink(), "checkout .git control is missing or redirected");
    let gitfileTarget = null;
    if (dotGitStatus.isDirectory()) {
      pinDirectory(dotGitPath, { strictMetadata: true });
    } else {
      assert(dotGitStatus.isFile(), "checkout .git control has the wrong type");
      const gitfile = pinFile(dotGitPath, "checkout .git gitfile", { strictMetadata: true });
      const match = /^gitdir: ([^\x00-\x1f\x7f]+)\n$/u.exec(parsePinnedText(gitfile, "checkout .git gitfile"));
      assert(match && match[1].length <= 4096, "checkout .git gitfile has invalid exact syntax");
      gitfileTarget = fs.realpathSync(path.resolve(repoRoot, match[1]));
    }
    const gitDir = checkedGitPath(["rev-parse", "--absolute-git-dir"], "Git worktree control directory");
    const commonDir = checkedGitPath(["rev-parse", "--path-format=absolute", "--git-common-dir"], "Git common directory");
    const objectDir = checkedGitPath(["rev-parse", "--path-format=absolute", "--git-path", "objects"], "Git object directory");
    if (gitfileTarget === null) assert(gitDir === dotGitPath, "main-worktree .git directory does not equal checked Git control directory");
    else assert(gitDir === gitfileTarget, "checkout .git gitfile does not equal checked Git control directory");
    assert(objectDir === path.join(commonDir, "objects"), "checked Git object directory must be the common directory's exact objects child");
    const commonDirControl = path.join(gitDir, "commondir");
    const gitDirBacklink = path.join(gitDir, "gitdir");
    if (gitDir === commonDir) {
      pinAbsent(commonDirControl, "main-worktree commondir selector");
      pinAbsent(gitDirBacklink, "main-worktree gitdir backlink");
    } else {
      const commonSelector = pinFile(commonDirControl, "linked-worktree commondir selector", { strictMetadata: true });
      const commonText = parsePinnedText(commonSelector, "linked-worktree commondir selector", 4096);
      assert(commonText.endsWith("\n") && !commonText.slice(0, -1).includes("\n"), "linked-worktree commondir selector must contain one LF-terminated path");
      assert(fs.realpathSync(path.resolve(gitDir, commonText.slice(0, -1))) === commonDir, "linked-worktree commondir selector does not equal checked Git common directory");
      const backlink = pinFile(gitDirBacklink, "linked-worktree gitdir backlink", { strictMetadata: true });
      const backlinkText = parsePinnedText(backlink, "linked-worktree gitdir backlink", 4096);
      assert(backlinkText.endsWith("\n") && !backlinkText.slice(0, -1).includes("\n"), "linked-worktree gitdir backlink must contain one LF-terminated path");
      assert(path.resolve(backlinkText.slice(0, -1)) === dotGitPath, "linked-worktree gitdir backlink does not equal the checkout gitfile");
    }
    pinFile(path.join(commonDir, "config"), "Git repository config", { strictMetadata: true });
    const localIncludes = runCheckedGit(
      repoRoot,
      ["config", "--local", "--includes", "--get-regexp", "^include"],
      { encoding: "utf8", maxBuffer: 1024 * 1024, allowedStatuses: [0, 1] },
    );
    assert(localIncludes.length === 0, "Git repository config includes are forbidden in checked authority");
    const worktreeConfigPath = path.join(gitDir, "config.worktree");
    const worktreeConfigStatus = lstatMaybe(worktreeConfigPath);
    if (worktreeConfigStatus === null) pinAbsent(worktreeConfigPath, "Git worktree config");
    else {
      pinFile(worktreeConfigPath, "Git worktree config", { strictMetadata: true });
      const worktreeIncludes = runCheckedGit(
        repoRoot,
        ["config", "--worktree", "--includes", "--get-regexp", "^include"],
        { encoding: "utf8", maxBuffer: 1024 * 1024, allowedStatuses: [0, 1] },
      );
      assert(worktreeIncludes.length === 0, "Git worktree config includes are forbidden in checked authority");
    }
    pinGitObjectDatabase(objectDir);
    pinHeadAuthority(gitDir, commonDir);
    checkedGitPath(["rev-parse", "--path-format=absolute", "--git-path", "index"], "Git index control file", { file: true });
    return plane;
  } catch (error) {
    plane.close();
    throw error;
  }
}

function resolveRepositoryRoot(candidate) {
  assert(typeof candidate === "string" && candidate.length > 0 && !candidate.includes("\0"), "repository root must be one path string");
  const selected = fs.realpathSync(path.resolve(candidate));
  assert(fs.statSync(selected).isDirectory(), "repository root is not a directory");
  const observedRaw = runCheckedGit(selected, ["rev-parse", "--path-format=absolute", "--show-toplevel"], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  const observed = observedRaw.endsWith("\n") ? observedRaw.slice(0, -1) : observedRaw;
  assert(observed.length > 0 && !observed.includes("\n") && !observed.includes("\0"), "checked Git returned an invalid worktree root");
  assert(fs.realpathSync(observed) === selected, "selected repository root is not the canonical Git worktree root");
  const objectFormat = runCheckedGit(selected, ["rev-parse", "--show-object-format"], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  }).trim();
  assert(objectFormat === "sha1", `promotion lineage requires the checked SHA-1 repository, got ${objectFormat}`);
  return selected;
}

function resolveHead(repoRoot) {
  const value = runCheckedGit(repoRoot, ["rev-parse", "--verify", "HEAD^{commit}"], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  }).trim();
  return assertSha1ObjectId(value, "current checkout revision");
}

function assertCleanWorktree(repoRoot) {
  const status = Buffer.from(runCheckedGit(
    repoRoot,
    ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"],
    { maxBuffer: 16 * 1024 * 1024 },
  ));
  assert(status.length === 0, "promotion admission requires an exactly clean tracked and untracked worktree");
}

function readGitObject(repoRoot, type, objectId) {
  assert(["blob", "commit", "tree"].includes(type), `unsupported Git object type ${type}`);
  assertSha1ObjectId(objectId, `Git ${type} object ID`);
  const bytes = Buffer.from(runCheckedGit(repoRoot, ["cat-file", type, objectId]));
  assert(bytes.length <= MAX_GIT_OBJECT_BYTES, `Git ${type} object ${objectId} exceeds the object limit`);
  assert(gitObjectId("sha1", type, bytes) === objectId, `Git ${type} object ${objectId} failed independent content hashing`);
  return bytes;
}

function parseCommit(bytes, label) {
  const input = Buffer.from(bytes);
  assert(!input.includes(0), `${label}: NUL is forbidden in a commit object`);
  const boundary = input.indexOf(Buffer.from("\n\n", "ascii"));
  assert(boundary >= 0, `${label}: missing commit header terminator`);
  const header = input.subarray(0, boundary);
  assert(!header.includes(0x0d), `${label}: CR is forbidden in commit headers`);
  const lines = fatalUtf8.decode(header).split("\n");
  let tree = null;
  const parents = [];
  let previousHeader = false;
  for (const line of lines) {
    if (line.startsWith(" ")) {
      assert(previousHeader, `${label}: orphaned continuation header`);
      continue;
    }
    const separator = line.indexOf(" ");
    assert(separator > 0, `${label}: malformed commit header`);
    const name = line.slice(0, separator);
    const value = line.slice(separator + 1);
    assert(/^[a-z][a-z0-9-]*$/u.test(name), `${label}: malformed commit header name`);
    previousHeader = true;
    if (name === "tree") {
      assert(tree === null, `${label}: duplicate tree header`);
      tree = assertSha1ObjectId(value, `${label} tree`);
    } else if (name === "parent") {
      parents.push(assertSha1ObjectId(value, `${label} parent`));
      assert(parents.length <= 64, `${label}: commit parent count exceeds the parser limit`);
    }
  }
  assert(tree !== null, `${label}: missing tree header`);
  return { tree, parents };
}

function parseTree(bytes, label) {
  const input = Buffer.from(bytes);
  const rows = [];
  const names = new Set();
  let offset = 0;
  while (offset < input.length) {
    assert(rows.length < MAX_TREE_ENTRIES, `${label}: tree entry limit exceeded`);
    const space = input.indexOf(0x20, offset);
    const nul = space < 0 ? -1 : input.indexOf(0x00, space + 1);
    assert(space > offset && nul > space + 1 && nul + 21 <= input.length, `${label}: malformed raw tree entry`);
    const mode = input.subarray(offset, space).toString("ascii");
    assert(["40000", "100644", "100755", "120000", "160000"].includes(mode), `${label}: unsupported Git mode ${mode}`);
    const name = fatalUtf8.decode(input.subarray(space + 1, nul));
    assert(name !== "" && name !== "." && name !== ".." && !name.includes("/") && !name.includes("\0"), `${label}: unsafe Git entry name`);
    assert(!names.has(name), `${label}: duplicate Git entry name ${name}`);
    names.add(name);
    rows.push({
      mode,
      name,
      objectId: input.subarray(nul + 1, nul + 21).toString("hex"),
      kind: mode === "40000" ? "tree" : mode === "160000" ? "submodule" : mode === "120000" ? "symlink" : "blob",
    });
    offset = nul + 21;
  }
  return rows;
}

function collectTreeLeaves(repoRoot, rootTreeId) {
  const leaves = new Map();
  let visitedEntries = 0;
  const activeTrees = new Set();
  function walk(treeId, prefix, depth) {
    assert(depth <= MAX_TREE_DEPTH, "checked Git tree depth limit exceeded");
    assert(!activeTrees.has(treeId), `checked Git tree cycle at ${treeId}`);
    activeTrees.add(treeId);
    const rows = parseTree(readGitObject(repoRoot, "tree", treeId), `Git tree ${treeId}`);
    for (const row of rows) {
      visitedEntries += 1;
      assert(visitedEntries <= MAX_TREE_ENTRIES, "checked Git tree corpus exceeds the entry limit");
      const pathname = prefix === "" ? row.name : `${prefix}/${row.name}`;
      assertRepositoryPath(pathname, "checked Git path");
      if (row.kind === "tree") walk(row.objectId, pathname, depth + 1);
      else {
        assert(!leaves.has(pathname), `duplicate checked Git leaf ${pathname}`);
        leaves.set(pathname, row);
      }
    }
    activeTrees.delete(treeId);
  }
  walk(assertSha1ObjectId(rootTreeId, "root tree object ID"), "", 0);
  return leaves;
}

function readTrackedBlob(repoRoot, leaves, relativePath, label) {
  const entry = leaves.get(relativePath);
  assert(entry?.kind === "blob" && entry.mode === "100644", `${label}: expected one non-executable regular tracked blob at ${relativePath}`);
  return { entry, bytes: readGitObject(repoRoot, "blob", entry.objectId) };
}

function parseCatalog(bytes, label) {
  const catalog = parseJsonStrict(bytes, label);
  const expectedBytes = Buffer.from(`${canonicalJson(catalog)}\n`, "utf8");
  assert(Buffer.from(bytes).equals(expectedBytes), `${label}: bytes are not the canonical encoding plus one LF`);
  assertExactKeys(catalog, ["schema", "enabled", "admissionPath", "admissions"], label);
  assert([CATALOG_SCHEMA_V1, CATALOG_SCHEMA].includes(catalog.schema), `${label}: unsupported schema`);
  assert(typeof catalog.enabled === "boolean", `${label}: enabled must be boolean`);
  assert(catalog.admissionPath === CATALOG_PATH, `${label}: admissionPath must name the exact checked catalog path`);
  assert(Array.isArray(catalog.admissions), `${label}: admissions must be an array`);
  if (!catalog.enabled) {
    assert(catalog.admissions.length === 0, `${label}: a disabled catalog must be empty`);
    return catalog;
  }
  assert(catalog.schema === CATALOG_SCHEMA, `${label}: an enabled v1 catalog cannot anchor scoped lineage`);
  assert(catalog.admissions.length === 1, `${label}: an active catalog must carry exactly one admission`);
  validateAdmissionShape(catalog.admissions[0], `${label}.admissions[0]`);
  return catalog;
}

function validateCanonicalTarget(target, label) {
  assertExactKeys(target, ["triple", "features"], label);
  assert(
    typeof target.triple === "string"
      && /^[a-z0-9_]+(?:-[a-z0-9_]+)+$/u.test(target.triple)
      && target.triple.length <= 128,
    `${label}.triple: invalid target triple`,
  );
  assert(Array.isArray(target.features) && target.features.length > 0, `${label}.features: expected a non-empty array`);
  for (const [index, feature] of target.features.entries()) {
    assert(
      typeof feature === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(feature),
      `${label}.features[${index}]: invalid target feature`,
    );
    assert(
      index === 0 || compareUtf8(target.features[index - 1], feature) < 0,
      `${label}.features: features must be strictly sorted by UTF-8 bytes`,
    );
  }
  return target;
}

function sameTarget(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function validateAdmissionShape(admission, label) {
  assertExactKeys(
    admission,
    [
      "schema",
      "sourceRevision",
      "sourceTreeObjectId",
      "topology",
      "target",
      "admittedScopeDigest",
      "portableArtifactId",
      "artifacts",
      "admissionDigest",
    ],
    label,
  );
  assert(admission.schema === ADMISSION_SCHEMA, `${label}: unsupported admission schema`);
  assertSha1ObjectId(admission.sourceRevision, `${label}.sourceRevision`);
  assertSha1ObjectId(admission.sourceTreeObjectId, `${label}.sourceTreeObjectId`);
  assert(admission.topology === MERGE_TOPOLOGY, `${label}: unsupported merge topology`);
  validateCanonicalTarget(admission.target, `${label}.target`);
  assertSemanticDigest(admission.admittedScopeDigest, `${label}.admittedScopeDigest`);
  assertSemanticDigest(admission.portableArtifactId, `${label}.portableArtifactId`);
  assert(Array.isArray(admission.artifacts), `${label}.artifacts: expected an array`);
  assert(
    admission.artifacts.length >= MIN_CHANGED_ARTIFACTS &&
      admission.artifacts.length <= MAX_CHANGED_ARTIFACTS,
    `${label}.artifacts: expected ${MIN_CHANGED_ARTIFACTS}..${MAX_CHANGED_ARTIFACTS} rows`,
  );
  const paths = new Set();
  let previousPath = null;
  const roleCounts = new Map();
  for (const [index, artifact] of admission.artifacts.entries()) {
    const artifactLabel = `${label}.artifacts[${index}]`;
    assertExactKeys(artifact, ["role", "path", "mode", "blobObjectId", "size", "digest"], artifactLabel);
    assert(["conformance-evidence", SCOPE_ROLE, "target-attestation", "target-advertisement"].includes(artifact.role), `${artifactLabel}.role: unsupported role`);
    assertRepositoryPath(artifact.path, `${artifactLabel}.path`);
    assert(artifact.mode === "100644", `${artifactLabel}.mode: promotion blobs must be non-executable regular files`);
    assertSha1ObjectId(artifact.blobObjectId, `${artifactLabel}.blobObjectId`);
    assert(Number.isSafeInteger(artifact.size) && artifact.size > 0 && artifact.size <= MAX_CHANGED_ARTIFACT_BYTES, `${artifactLabel}.size: invalid bounded size`);
    assertRawDigest(artifact.digest, `${artifactLabel}.digest`);
    assert(!paths.has(artifact.path), `${artifactLabel}.path: duplicate artifact path`);
    assert(previousPath === null || compareUtf8(previousPath, artifact.path) < 0, `${label}.artifacts: rows must be strictly sorted by UTF-8 path bytes`);
    previousPath = artifact.path;
    paths.add(artifact.path);
    roleCounts.set(artifact.role, (roleCounts.get(artifact.role) ?? 0) + 1);
  }
  assert(roleCounts.get("conformance-evidence") >= 1, `${label}: at least one conformance-evidence blob is required`);
  assert(roleCounts.get(SCOPE_ROLE) === 1, `${label}: exactly one scope-artifact blob is required`);
  assert(roleCounts.get("target-attestation") === 1, `${label}: exactly one target-attestation blob is required`);
  assert(roleCounts.get("target-advertisement") === 1, `${label}: exactly one target-advertisement blob is required`);
  const reportPath = `capsec/conformance/portable-promotions/${admission.sourceRevision}/${admission.target.triple}/${admission.portableArtifactId}/conformance-report.json`;
  const bundleManifestPath = `capsec/conformance/portable-promotions/${admission.sourceRevision}/${admission.target.triple}/${admission.portableArtifactId}/promotion-bundle-manifest.json`;
  assert(
    admission.artifacts.filter(
      (artifact) =>
        artifact.role === "conformance-evidence" &&
        artifact.path === reportPath,
    ).length === 1,
    `${label}: exactly one conformance report must use the fixed source/target/artifact-scoped path`,
  );
  assert(
    admission.artifacts.filter(
      (artifact) =>
        artifact.role === "conformance-evidence" &&
        artifact.path === bundleManifestPath,
    ).length === 1,
    `${label}: exactly one verified promotion bundle manifest must use the fixed source/target/artifact-scoped path`,
  );
  assertSemanticDigest(admission.admissionDigest, `${label}.admissionDigest`);
  assert(semanticDigest(ADMISSION_DOMAIN, admission, ["admissionDigest"]) === admission.admissionDigest, `${label}: admissionDigest mismatch`);
}

function evidencePrefix(admission) {
  return `capsec/conformance/portable-promotions/${admission.sourceRevision}/${admission.target.triple}/${admission.portableArtifactId}/`;
}

function promotionBundleMemberPath(admission, logicalName) {
  assert(
    typeof logicalName === "string" &&
      /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/u.test(logicalName),
    "portable bundle logical member name is malformed",
  );
  const prefix = evidencePrefix(admission);
  if (logicalName === "scope-artifact") {
    return `${prefix}${SCOPE_PATH_BASENAME}`;
  }
  const basename =
    logicalName === "portable-conformance-report"
      ? "conformance-report"
      : logicalName;
  return `${prefix}${basename}.json`;
}

function promotionSourceTreeDigest(sourceTreeObjectId) {
  return `sha256-${createHash("sha256")
    .update(Buffer.from(`${sourceTreeObjectId}\n`, "utf8"))
    .digest("base64url")}`;
}

function assertArtifactRolePath(admission, artifact, label) {
  if (artifact.role === "target-attestation") {
    assert(artifact.path === TARGET_ATTESTATION_PATH, `${label}: target-attestation must use the exact checked path`);
    return;
  }
  if (artifact.role === "target-advertisement") {
    assert(artifact.path === TARGET_ADVERTISEMENT_PATH, `${label}: target-advertisement must use the exact checked path`);
    return;
  }
  const prefix = evidencePrefix(admission);
  if (artifact.role === SCOPE_ROLE) {
    assert(
      artifact.path === `${prefix}${SCOPE_PATH_BASENAME}`,
      `${label}: scope-artifact must use the reserved evidence-prefix path`,
    );
    return;
  }
  assert(artifact.path.startsWith(prefix), `${label}: conformance evidence is outside the source/target/artifact-scoped promotion namespace`);
  const suffix = artifact.path.slice(prefix.length);
  assert(suffix.length > 0 && suffix.endsWith(".json"), `${label}: conformance evidence must be a named JSON blob`);
  const segments = suffix.split("/");
  assert(
    segments.every((segment) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(segment) && segment !== "." && segment !== ".."),
    `${label}: conformance evidence path has an unsafe segment`,
  );
}

function assertSourceAuthorityClosed(repoRoot, sourceLeaves, admission) {
  const sourceCatalogRecord = readTrackedBlob(repoRoot, sourceLeaves, CATALOG_PATH, "source promotion catalog");
  const sourceCatalog = parseCatalog(sourceCatalogRecord.bytes, "source promotion catalog");
  assert(sourceCatalog.enabled === false && sourceCatalog.admissions.length === 0, "artifact-source revision must contain the disabled, empty admission foundation");

  const policyRecord = readTrackedBlob(repoRoot, sourceLeaves, TRUST_POLICY_PATH, "source portable trust policy");
  const policy = parseJsonStrict(policyRecord.bytes, "source portable trust policy");
  assert(policy && typeof policy === "object" && !Array.isArray(policy), "source portable trust policy must be an object");
  assert(policy.portableArtifactAcceptanceEnabled === false, "artifact-source revision must keep portableArtifactAcceptanceEnabled false");
  assert(Array.isArray(policy.admittedTargets), "source portable trust policy must carry admittedTargets");
  assert(policy.admittedTargets.some((target) => target && target.triple === admission.target.triple), `source portable trust policy has no closed target row for ${admission.target.triple}`);

  const attestationRecord = readTrackedBlob(repoRoot, sourceLeaves, TARGET_ATTESTATION_PATH, "source target attestations");
  const attestations = parseJsonStrict(attestationRecord.bytes, "source target attestations");
  assertExactKeys(attestations, ["targetAttestationSchema", "profile", "attestations"], "source target attestations");
  assert(attestations.targetAttestationSchema === "ibex/capsec-target-attestations/1", "artifact-source target attestations must remain on the closed v1 schema");
  assert(Array.isArray(attestations.attestations) && attestations.attestations.length === 0, "artifact-source target attestations must be empty");

  const advertisementRecord = readTrackedBlob(repoRoot, sourceLeaves, TARGET_ADVERTISEMENT_PATH, "source target advertisements");
  const advertisements = parseJsonStrict(advertisementRecord.bytes, "source target advertisements");
  assertExactKeys(advertisements, ["targetAdvertisementSchema", "profile", "targetCellsRawContentDigest", "advertisements"], "source target advertisements");
  assert(advertisements.targetAdvertisementSchema === "ibex/capsec-target-advertisements/1", "artifact-source target advertisements must remain on the closed v1 schema");
  assert(Array.isArray(advertisements.advertisements) && advertisements.advertisements.length === 0, "artifact-source target advertisements must be empty");

  const rulesRecord = readTrackedBlob(
    repoRoot,
    sourceLeaves,
    CAPSEC_POLICY_RULES_PATH,
    "source CapSec policy rules",
  );
  const rules = parseJsonStrict(rulesRecord.bytes, "source CapSec policy rules");
  const targetMatches = rules?.initialProfile?.candidateTargets?.filter(
    (target) => target?.triple === admission.target.triple,
  );
  assert(
    Array.isArray(targetMatches) && targetMatches.length === 1,
    `source CapSec policy rules must name exactly one candidate target for ${admission.target.triple}`,
  );
  const target = targetMatches[0];
  assertExactKeys(target, ["triple", "features"], "source CapSec candidate target");
  assert(
    Array.isArray(target.features) &&
      target.features.length > 0 &&
      target.features.every(
        (feature, index) =>
          typeof feature === "string" &&
          /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(feature) &&
          (index === 0 || compareUtf8(target.features[index - 1], feature) < 0),
      ),
    "source CapSec candidate target features are malformed or noncanonical",
  );
  assert(sameTarget(target, admission.target), "source CapSec candidate target differs from the tracked admission target");
  return target;
}

function changedLeaves(sourceLeaves, currentLeaves) {
  const paths = [...new Set([...sourceLeaves.keys(), ...currentLeaves.keys()])].sort(compareUtf8);
  return paths.filter((pathname) => {
    const source = sourceLeaves.get(pathname);
    const current = currentLeaves.get(pathname);
    return !source || !current || source.mode !== current.mode || source.kind !== current.kind || source.objectId !== current.objectId;
  });
}

function parseScopeArtifact(bytes, label) {
  const scope = parseJsonStrict(bytes, label);
  const expectedBytes = Buffer.from(canonicalJson(scope), "utf8");
  assert(Buffer.from(bytes).equals(expectedBytes), `${label}: bytes are not the canonical JCS encoding`);
  assert(scope && typeof scope === "object" && !Array.isArray(scope), `${label}: expected an object`);
  const format = SCOPE_DIGEST_FORMATS[scope.scopeSchema];
  assert(format, `${label}: unsupported scope schema`);
  validateCanonicalTarget(scope.target, `${label}.target`);
  assertSemanticDigest(scope.scopeDigest, `${label}.scopeDigest`);
  assert(
    format.computeDigest(scope) === scope.scopeDigest,
    `${label}: scopeDigest mismatch`,
  );
  assert(scope.predecessor && typeof scope.predecessor === "object" && !Array.isArray(scope.predecessor), `${label}.predecessor: expected an object`);
  let predecessor;
  if (scope.predecessor.kind === "genesis") {
    assertExactKeys(scope.predecessor, ["kind"], `${label}.predecessor`);
    predecessor = SCOPE_GENESIS_MARKER;
  } else {
    assertExactKeys(scope.predecessor, ["kind", "scopeDigest"], `${label}.predecessor`);
    assert(scope.predecessor.kind === "scope", `${label}.predecessor: unsupported kind`);
    predecessor = assertSemanticDigest(
      scope.predecessor.scopeDigest,
      `${label}.predecessor.scopeDigest`,
    );
  }
  return { scope, predecessor };
}

function matchingAdvertisementScopeDigest(bytes, admission, label) {
  const catalog = parseJsonStrict(bytes, label);
  assert(catalog && typeof catalog === "object" && !Array.isArray(catalog), `${label}: expected an object`);
  assert(Array.isArray(catalog.advertisements), `${label}.advertisements: expected an array`);
  const matches = catalog.advertisements.filter(
    (advertisement) => advertisement?.target && sameTarget(advertisement.target, admission.target),
  );
  assert(matches.length === 1, `${label}: expected exactly one advertisement for the tracked admission target`);
  assertSemanticDigest(matches[0].scopeDigest, `${label}.advertisements[].scopeDigest`);
  return matches[0].scopeDigest;
}

function promotionTopology(repoRoot, revision, commit, admission) {
  if (commit.parents.length !== 2 || commit.parents[0] !== admission.sourceRevision) return null;
  const sourceCommit = parseCommit(
    readGitObject(repoRoot, "commit", admission.sourceRevision),
    `source commit ${admission.sourceRevision}`,
  );
  const topicRevision = commit.parents[1];
  const topicCommit = parseCommit(
    readGitObject(repoRoot, "commit", topicRevision),
    `promotion topic commit ${topicRevision}`,
  );
  if (
    topicCommit.parents.length !== 1
      || topicCommit.parents[0] !== admission.sourceRevision
      || commit.tree !== topicCommit.tree
      || sourceCommit.tree !== admission.sourceTreeObjectId
      || sourceCommit.tree === commit.tree
  ) return null;
  return { revision, sourceCommit, topicRevision };
}

function verifyScopeCriticalPromotionRevision(
  repoRoot,
  revision,
  commit,
  currentLeaves,
  admission,
) {
  const topology = promotionTopology(repoRoot, revision, commit, admission);
  if (topology === null) return null;
  const sourceLeaves = collectTreeLeaves(repoRoot, topology.sourceCommit.tree);
  const expectedPaths = [CATALOG_PATH, ...admission.artifacts.map((artifact) => artifact.path)]
    .sort(compareUtf8);
  const observedPaths = changedLeaves(sourceLeaves, currentLeaves);
  assert(
    canonicalJson(observedPaths) === canonicalJson(expectedPaths),
    `historical promotion ${revision}: changed-path set mismatch`,
  );

  const promotedBytes = new Map();
  for (const [index, artifact] of admission.artifacts.entries()) {
    const label = `historical promotion ${revision} artifact ${index} (${artifact.path})`;
    assertArtifactRolePath(admission, artifact, label);
    const current = currentLeaves.get(artifact.path);
    assert(current?.kind === "blob" && current.mode === "100644", `${label}: expected one checked regular blob`);
    assert(current.objectId === artifact.blobObjectId, `${label}: checked blob object ID mismatch`);
    const bytes = readGitObject(repoRoot, "blob", current.objectId);
    assert(bytes.length === artifact.size, `${label}: checked blob size mismatch`);
    assert(rawDigest(bytes) === artifact.digest, `${label}: checked blob raw digest mismatch`);
    promotedBytes.set(artifact.path, bytes);
    const source = sourceLeaves.get(artifact.path);
    if (artifact.role === "conformance-evidence" || artifact.role === SCOPE_ROLE) {
      assert(source === undefined, `${label}: evidence-prefix artifacts must be newly added at promotion`);
    } else {
      assert(source?.kind === "blob" && source.mode === "100644", `${label}: target publication path must replace the closed source blob in place`);
    }
  }

  const scopePath = `${evidencePrefix(admission)}${SCOPE_PATH_BASENAME}`;
  const scopeBytes = promotedBytes.get(scopePath);
  assert(scopeBytes, `historical promotion ${revision}: missing reserved scope artifact`);
  const { scope, predecessor } = parseScopeArtifact(
    scopeBytes,
    `historical promotion ${revision} scope artifact`,
  );
  assert(scope.scopeDigest === admission.admittedScopeDigest, `historical promotion ${revision}: admittedScopeDigest is not backed by the scope artifact`);
  assert(sameTarget(scope.target, admission.target), `historical promotion ${revision}: scope target differs from the tracked admission target`);
  const advertisementDigest = matchingAdvertisementScopeDigest(
    promotedBytes.get(TARGET_ADVERTISEMENT_PATH),
    admission,
    `historical promotion ${revision} target advertisements`,
  );
  assert(advertisementDigest === admission.admittedScopeDigest, `historical promotion ${revision}: advertisement scopeDigest differs from admittedScopeDigest`);
  return Object.freeze({
    admittedScopeDigest: admission.admittedScopeDigest,
    predecessorScopeDigest: predecessor,
    target: structuredClone(admission.target),
  });
}

function checkedGitControlPath(repoRoot, relativePath, label) {
  const output = runCheckedGit(
    repoRoot,
    ["rev-parse", "--path-format=absolute", "--git-path", relativePath],
    { encoding: "utf8", maxBuffer: 1024 * 1024 },
  ).trim();
  assert(path.isAbsolute(output) && !output.includes("\0") && !output.includes("\n"), `${label}: checked Git returned an invalid control path`);
  return path.resolve(output);
}

function assertCompleteLineageHistory(repoRoot, authorityPlane = null) {
  const shallow = runCheckedGit(
    repoRoot,
    ["rev-parse", "--is-shallow-repository"],
    { encoding: "utf8", maxBuffer: 1024 * 1024 },
  ).trim();
  assert(shallow === "false", "promotion lineage refuses a shallow repository");
  for (const [relativePath, label] of [
    ["shallow", "Git shallow-history control"],
    ["info/grafts", "Git grafts control"],
  ]) {
    const controlPath = checkedGitControlPath(repoRoot, relativePath, label);
    assert(lstatMaybe(controlPath) === null, `${label}: forbidden control path exists`);
    authorityPlane?.pinAbsentControl(controlPath, label);
  }
  const replacements = runCheckedGit(
    repoRoot,
    ["for-each-ref", "--format=%(refname)", "refs/replace"],
    { encoding: "utf8", maxBuffer: 1024 * 1024 },
  );
  assert(replacements.length === 0, "promotion lineage refuses configured replace refs");
}

// This object-history helper intentionally does not establish checkout or OS
// authority by itself. The fixed production verifier below supplies those
// premises; tests use this export to exercise the content-hashed walk on Linux.
export function resolvePortableEnginePromotionPredecessor(options) {
  assert(options && typeof options === "object" && !Array.isArray(options), "promotion history resolver expects one options object");
  assertExactKeys(options, ["repoRoot", "startRevision", "target"], "promotion history resolver options");
  const repoRoot = resolveRepositoryRoot(options.repoRoot);
  const startRevision = assertSha1ObjectId(options.startRevision, "promotion history start revision");
  const target = validateCanonicalTarget(structuredClone(options.target), "promotion history target");
  assertCompleteLineageHistory(repoRoot);

  let revision = startRevision;
  for (let depth = 0; depth < 100_000; depth += 1) {
    const commit = parseCommit(readGitObject(repoRoot, "commit", revision), `lineage commit ${revision}`);
    const leaves = collectTreeLeaves(repoRoot, commit.tree);
    if (revision === LINEAGE_FLOOR) {
      const floorCatalog = parseCatalog(
        readTrackedBlob(repoRoot, leaves, CATALOG_PATH, "lineage-floor promotion catalog").bytes,
        "lineage-floor promotion catalog",
      );
      assert(floorCatalog.schema === CATALOG_SCHEMA_V1 && floorCatalog.enabled === false && floorCatalog.admissions.length === 0, "lineage floor must carry the disabled empty v1 catalog foundation");
      assert(commit.parents.length >= 1, "lineage floor has no first parent");
      const firstParent = parseCommit(
        readGitObject(repoRoot, "commit", commit.parents[0]),
        `lineage-floor first parent ${commit.parents[0]}`,
      );
      const parentLeaves = collectTreeLeaves(repoRoot, firstParent.tree);
      assert(!parentLeaves.has(CATALOG_PATH), "lineage-floor first parent must lack the promotion catalog path");
      return null;
    }

    assert(leaves.has(CATALOG_PATH), `lineage revision ${revision} above the pinned floor lacks the promotion catalog`);
    const catalog = parseCatalog(
      readTrackedBlob(repoRoot, leaves, CATALOG_PATH, `lineage promotion catalog at ${revision}`).bytes,
      `lineage promotion catalog at ${revision}`,
    );
    if (catalog.enabled) {
      const admission = catalog.admissions[0];
      const hop = verifyScopeCriticalPromotionRevision(
        repoRoot,
        revision,
        commit,
        leaves,
        admission,
      );
      if (hop !== null && sameTarget(admission.target, target)) {
        // The scope-critical subset above remains the version-dispatched
        // historical floor. While a hop's complete portable graph uses the
        // schemas understood by HEAD, also run the stronger full ceremony
        // checks; future schema revisions may fall back to the floor.
        // @ref LLP 0021#a9-appendix--the-scope-digest-join-matrix — M27(iii)
        // makes the reduced historical predicate a floor, not a ceiling.
        if (
          historicalPromotionUsesHeadPortableGraphSchemas(
            repoRoot,
            leaves,
            admission,
          )
        ) {
          const sourceCommit = parseCommit(
            readGitObject(repoRoot, "commit", admission.sourceRevision),
            `historical source commit ${admission.sourceRevision}`,
          );
          const sourceLeaves = collectTreeLeaves(repoRoot, sourceCommit.tree);
          const expectedTarget = assertSourceAuthorityClosed(
            repoRoot,
            sourceLeaves,
            admission,
          );
          verifyChangedArtifacts(
            repoRoot,
            sourceLeaves,
            leaves,
            admission,
            expectedTarget,
          );
        }
        return hop;
      }
    }
    assert(commit.parents.length >= 1, `promotion lineage ended before the pinned floor ${LINEAGE_FLOOR}`);
    revision = commit.parents[0];
  }
  fail("promotion lineage exceeds the first-parent walk limit");
}

export function verifyPortableEngineScopePredecessor(options) {
  assert(options && typeof options === "object" && !Array.isArray(options), "scope predecessor verifier expects one options object");
  assertExactKeys(
    options,
    ["repoRoot", "startRevision", "target", "predecessorScopeDigest"],
    "scope predecessor verifier options",
  );
  const priorScope = resolvePortableEnginePromotionPredecessor({
    repoRoot: options.repoRoot,
    startRevision: options.startRevision,
    target: options.target,
  });
  if (priorScope === null) {
    assert(options.predecessorScopeDigest === SCOPE_GENESIS_MARKER, "genesis scope must carry the explicit genesis predecessor marker");
  } else {
    assert(
      options.predecessorScopeDigest === priorScope.admittedScopeDigest,
      "scope predecessor does not equal the latest admitted scope for the canonical target tuple",
    );
  }
  return priorScope;
}

function verifyPromotionBundleGraph(admission, promotedBytes, expectedTarget) {
  const prefix = evidencePrefix(admission);
  const manifestPath = `${prefix}promotion-bundle-manifest.json`;
  const manifestBytes = promotedBytes.get(manifestPath);
  assert(manifestBytes, "promotion omits the verified portable bundle manifest");
  const manifest = parseJsonStrict(
    manifestBytes,
    "promoted portable bundle manifest",
  );
  assert(
    Array.isArray(manifest?.files),
    "promoted portable bundle manifest has malformed membership",
  );
  const members = manifest.files.map((file) => {
    const pathname = promotionBundleMemberPath(admission, file?.logicalName);
    const bytes = promotedBytes.get(pathname);
    assert(
      bytes,
      `promotion omits portable bundle member ${String(file?.logicalName)}`,
    );
    return { logicalName: file.logicalName, bytes };
  });
  const expectedArtifactPaths = [
    manifestPath,
    ...members.map((member) =>
      promotionBundleMemberPath(admission, member.logicalName),
    ),
    `${prefix}${SCOPE_PATH_BASENAME}`,
    TARGET_ATTESTATION_PATH,
    TARGET_ADVERTISEMENT_PATH,
  ].filter((pathname, index, paths) => paths.indexOf(pathname) === index).sort(compareUtf8);
  const actualArtifactPaths = admission.artifacts
    .map((artifact) => artifact.path)
    .sort(compareUtf8);
  assert(
    canonicalJson(actualArtifactPaths) === canonicalJson(expectedArtifactPaths),
    "promotion admission does not name the exact complete portable bundle graph",
  );
  validatePortablePromotionBundleGraph({
    manifestBytes,
    members,
    expectedSourceRevision: admission.sourceRevision,
    expectedSourceTreeDigest: promotionSourceTreeDigest(
      admission.sourceTreeObjectId,
    ),
    expectedTarget,
    expectedPortableArtifactId: admission.portableArtifactId,
  });
  const scopedAttestations = promotedBytes.get(
    promotionBundleMemberPath(admission, "target-attestations"),
  );
  const scopedAdvertisements = promotedBytes.get(
    promotionBundleMemberPath(admission, "target-advertisements"),
  );
  assert(
    scopedAttestations?.equals(promotedBytes.get(TARGET_ATTESTATION_PATH)),
    "published target attestations differ from the verified portable bundle graph",
  );
  assert(
    scopedAdvertisements?.equals(promotedBytes.get(TARGET_ADVERTISEMENT_PATH)),
    "published target advertisements differ from the verified portable bundle graph",
  );
}

const HEAD_PORTABLE_GRAPH_SCHEMAS = Object.freeze({
  "portable-promotion-authority": Object.freeze([
    "portablePromotionAuthoritySchema",
    "ibex/capsec-portable-promotion-authority/1",
  ]),
  "scope-artifact": Object.freeze(["scopeSchema", SCOPE_SCHEMA]),
  "scope-expansion-diff": Object.freeze([
    "scopeExpansionDiffSchema",
    "ibex/capsec-scope-expansion-diff/1",
  ]),
  "scope-cell-mapping": Object.freeze([
    "scopeCellMappingSchema",
    "ibex/capsec-scope-cell-mapping/1",
  ]),
  "portable-conformance-report": Object.freeze([
    "conformanceSchema",
    "ibex/capsec-conformance/3",
  ]),
  "target-attestations": Object.freeze([
    "targetAttestationSchema",
    "ibex/capsec-target-attestations/3",
  ]),
  "target-advertisements": Object.freeze([
    "targetAdvertisementSchema",
    "ibex/capsec-target-advertisements/3",
  ]),
  "target-cells": Object.freeze([
    "targetCellSchema",
    "ibex/capsec-target-cells/1",
  ]),
  recipes: Object.freeze([
    "recipeCatalogSchema",
    "ibex/capsec-executable-recipes/2",
  ]),
  "public-surface": Object.freeze([
    "publicSurfaceExecutionSchema",
    "ibex/capsec-public-surface-executions/2",
  ]),
  "output-dispositions": Object.freeze([
    "outputDispositionEvidenceSchema",
    "ibex/capsec-output-disposition-evidence/4",
  ]),
});

function historicalPromotionUsesHeadPortableGraphSchemas(
  repoRoot,
  currentLeaves,
  admission,
) {
  const manifestPath = `${evidencePrefix(admission)}promotion-bundle-manifest.json`;
  const manifest = parseJsonStrict(
    readTrackedBlob(
      repoRoot,
      currentLeaves,
      manifestPath,
      "historical portable bundle manifest",
    ).bytes,
    "historical portable bundle manifest",
  );
  if (
    manifest?.portablePromotionBundleSchema !==
      "ibex/capsec-portable-promotion-bundle/1" ||
    !Array.isArray(manifest.files)
  ) {
    return false;
  }
  for (const [logicalName, [field, schema]] of Object.entries(
    HEAD_PORTABLE_GRAPH_SCHEMAS,
  )) {
    if (!manifest.files.some((file) => file?.logicalName === logicalName)) {
      return false;
    }
    const document = parseJsonStrict(
      readTrackedBlob(
        repoRoot,
        currentLeaves,
        promotionBundleMemberPath(admission, logicalName),
        `historical portable bundle member ${logicalName}`,
      ).bytes,
      `historical portable bundle member ${logicalName}`,
    );
    if (document?.[field] !== schema) return false;
  }
  for (const file of manifest.files) {
    const processSchema =
      /^process-[0-9]{4}\.mapped-evidence$/u.test(file?.logicalName)
        ? [
            "mappedEngineExecutionEvidenceSchema",
            "ibex/capsec-mapped-engine-execution-evidence/1",
          ]
        : /^process-[0-9]{4}\.command-attempt$/u.test(file?.logicalName)
          ? ["schema", "ibex/capsec-command-attempt/1"]
          : /^process-[0-9]{4}\.fixture-[0-9]{6}$/u.test(file?.logicalName)
            ? [
                "fixtureEvidenceSchema",
                "ibex/capsec-portable-fixture-evidence/1",
              ]
            : null;
    if (processSchema === null) continue;
    const document = parseJsonStrict(
      readTrackedBlob(
        repoRoot,
        currentLeaves,
        promotionBundleMemberPath(admission, file.logicalName),
        `historical portable bundle member ${file.logicalName}`,
      ).bytes,
      `historical portable bundle member ${file.logicalName}`,
    );
    if (document?.[processSchema[0]] !== processSchema[1]) return false;
  }
  return true;
}

function verifyChangedArtifacts(
  repoRoot,
  sourceLeaves,
  currentLeaves,
  admission,
  expectedTarget,
) {
  const rows = new Map(admission.artifacts.map((artifact) => [artifact.path, artifact]));
  const expectedPaths = [CATALOG_PATH, ...rows.keys()].sort(compareUtf8);
  const observedPaths = changedLeaves(sourceLeaves, currentLeaves);
  assert(
    canonicalJson(observedPaths) === canonicalJson(expectedPaths),
    `promotion changed-path set mismatch: expected ${canonicalJson(expectedPaths)}, got ${canonicalJson(observedPaths)}`,
  );

  const sourceBlobPaths = new Map();
  for (const [pathname, entry] of sourceLeaves) {
    if (entry.kind !== "blob") continue;
    const paths = sourceBlobPaths.get(entry.objectId) ?? [];
    paths.push(pathname);
    sourceBlobPaths.set(entry.objectId, paths);
  }
  const promotedBlobPaths = new Map();
  const promotedBytes = new Map();
  for (const [index, artifact] of admission.artifacts.entries()) {
    const label = `promotion artifact ${index} (${artifact.path})`;
    assertArtifactRolePath(admission, artifact, label);
    const current = currentLeaves.get(artifact.path);
    assert(current?.kind === "blob" && current.mode === "100644", `${label}: symlinks, submodules, executables, and non-regular entries are forbidden`);
    assert(current.objectId === artifact.blobObjectId, `${label}: checked blob object ID mismatch`);
    const duplicatePaths = promotedBlobPaths.get(current.objectId) ?? [];
    duplicatePaths.push(artifact.path);
    promotedBlobPaths.set(current.objectId, duplicatePaths);
    const priorPaths = sourceBlobPaths.get(current.objectId) ?? [];
    assert(priorPaths.length === 0, `${label}: copied source blob is forbidden (matches ${priorPaths.join(", ")})`);
    const bytes = readGitObject(repoRoot, "blob", current.objectId);
    promotedBytes.set(artifact.path, bytes);
    assert(bytes.length === artifact.size, `${label}: checked blob size mismatch`);
    assert(rawDigest(bytes) === artifact.digest, `${label}: checked blob raw digest mismatch`);

    const source = sourceLeaves.get(artifact.path);
    if (artifact.role === "conformance-evidence" || artifact.role === SCOPE_ROLE) {
      assert(source === undefined, `${label}: evidence-prefix artifacts must be newly added at promotion`);
    } else {
      assert(source?.kind === "blob" && source.mode === "100644", `${label}: target publication path must replace the closed source blob in place`);
    }
  }
  const permittedCopies = [
    [
      promotionBundleMemberPath(admission, "target-attestations"),
      TARGET_ATTESTATION_PATH,
    ].sort(compareUtf8),
    [
      promotionBundleMemberPath(admission, "target-advertisements"),
      TARGET_ADVERTISEMENT_PATH,
    ].sort(compareUtf8),
  ].map((paths) => canonicalJson(paths));
  for (const paths of promotedBlobPaths.values()) {
    if (paths.length === 1) continue;
    assert(
      paths.length === 2 &&
        permittedCopies.includes(canonicalJson([...paths].sort(compareUtf8))),
      `copied promotion blobs are forbidden outside exact bundle publication joins: ${paths.join(", ")}`,
    );
  }
  verifyPromotionBundleGraph(admission, promotedBytes, expectedTarget);
  const sourceCatalog = sourceLeaves.get(CATALOG_PATH);
  const currentCatalog = currentLeaves.get(CATALOG_PATH);
  assert(sourceCatalog?.kind === "blob" && sourceCatalog.mode === "100644", "source admission catalog must be a regular non-executable blob");
  assert(currentCatalog?.kind === "blob" && currentCatalog.mode === "100644", "current admission catalog must be a regular non-executable blob");
  assert(sourceCatalog.objectId !== currentCatalog.objectId, "active admission catalog must replace the disabled source catalog");
}

function pinWorkingAuthorityFile(repoRoot, currentLeaves, relativePath, authorityPlane) {
  const expected = currentLeaves.get(relativePath);
  assert(expected?.kind === "blob" && expected.mode === "100644", `running authority ${relativePath} is not a checked non-executable blob`);
  const checkedBytes = readGitObject(repoRoot, "blob", expected.objectId);
  authorityPlane.pinCheckedFile(relativePath, checkedBytes);
}

function pinRunningAuthority(repoRoot, currentLeaves, authorityPlane) {
  const expectedModule = path.join(repoRoot, MODULE_PATH);
  assert(fs.realpathSync(moduleFilePath) === fs.realpathSync(expectedModule), "promotion verifier is not running from the selected checkout's exact checked path");
  for (const relativePath of [
    MODULE_PATH,
    CONTRACT_PATH,
    BUNDLE_VERIFIER_PATH,
    PORTABLE_EVIDENCE_CONTRACT_PATH,
    CAPSEC_SCOPE_ARTIFACT_PATH,
    ...PORTABLE_EVIDENCE_SCHEMA_PATHS,
    CATALOG_SCHEMA_PATH,
    CHECKED_ADMISSION_SCHEMA_PATH,
    CATALOG_PATH,
  ]) {
    pinWorkingAuthorityFile(repoRoot, currentLeaves, relativePath, authorityPlane);
  }
}

function exactOptions(options) {
  assert(options && typeof options === "object" && !Array.isArray(options), "promotion verifier expects one options object");
  const keys = Object.keys(options).sort();
  assert(keys.every((key) => key === "repoRoot"), `promotion verifier received unknown option ${keys.find((key) => key !== "repoRoot")}`);
  return { repoRoot: options.repoRoot ?? process.cwd() };
}

export function verifyPortableEnginePromotionAdmission(options = {}) {
  if (arguments.length > 1) fail("promotion verifier accepts at most one production options object");
  assert(portableEnginePromotionLineagePlatformSupported(), `portable-engine promotion lineage is Darwin-only; ${process.platform} has no admitted OS/Git/ACL trust adapter`);
  const selected = exactOptions(options);
  const repoRoot = resolveRepositoryRoot(selected.repoRoot);
  const authorityPlane = createAuthorityPlane(repoRoot);
  try {
    const currentRevision = resolveHead(repoRoot);
    authorityPlane.assertResolvedHead(currentRevision);
    assertCleanWorktree(repoRoot);
    assertCompleteLineageHistory(repoRoot, authorityPlane);

    const currentCommit = parseCommit(readGitObject(repoRoot, "commit", currentRevision), `current commit ${currentRevision}`);
    const currentLeaves = collectTreeLeaves(repoRoot, currentCommit.tree);
    pinRunningAuthority(repoRoot, currentLeaves, authorityPlane);
    const currentCatalogRecord = readTrackedBlob(repoRoot, currentLeaves, CATALOG_PATH, "current promotion catalog");
    const currentCatalog = parseCatalog(currentCatalogRecord.bytes, "current promotion catalog");

    if (!currentCatalog.enabled) {
      assert(resolveHead(repoRoot) === currentRevision, "checkout HEAD changed during disabled-catalog verification");
      authorityPlane.assertResolvedHead(currentRevision);
      assertCleanWorktree(repoRoot);
      authorityPlane.recheck();
      return Object.freeze({
        schema: VERIFICATION_SCHEMA,
        authorized: false,
        currentRevision,
        admission: null,
      });
    }

    const admission = currentCatalog.admissions[0];
    assert(currentCommit.parents.length === 2, "active admission requires the current checkout to be the exact two-parent promotion merge");
    assert(currentCommit.parents[0] === admission.sourceRevision, "promotion merge first parent must equal the admitted artifact-source revision");
    const promotionTopicRevision = currentCommit.parents[1];
    const sourceCommit = parseCommit(readGitObject(repoRoot, "commit", admission.sourceRevision), `source commit ${admission.sourceRevision}`);
    const topicCommit = parseCommit(readGitObject(repoRoot, "commit", promotionTopicRevision), `promotion topic commit ${promotionTopicRevision}`);
    assert(topicCommit.parents.length === 1 && topicCommit.parents[0] === admission.sourceRevision, "promotion topic must be one direct commit whose sole parent is the artifact-source revision");
    assert(currentCommit.tree === topicCommit.tree, "promotion merge tree must equal the reviewed promotion topic tree exactly");
    assert(sourceCommit.tree === admission.sourceTreeObjectId, "admission sourceTreeObjectId does not equal the independently hashed source commit tree");
    assert(sourceCommit.tree !== currentCommit.tree, "promotion merge must change the disabled source tree");

    const sourceLeaves = collectTreeLeaves(repoRoot, sourceCommit.tree);
    const currentScope = verifyScopeCriticalPromotionRevision(
      repoRoot,
      currentRevision,
      currentCommit,
      currentLeaves,
      admission,
    );
    assert(currentScope !== null, "current active admission is not the exact promotion revision it declares");
    verifyPortableEngineScopePredecessor({
      repoRoot,
      startRevision: admission.sourceRevision,
      target: admission.target,
      predecessorScopeDigest: currentScope.predecessorScopeDigest,
    });
    const expectedTarget = assertSourceAuthorityClosed(
      repoRoot,
      sourceLeaves,
      admission,
    );
    verifyChangedArtifacts(
      repoRoot,
      sourceLeaves,
      currentLeaves,
      admission,
      expectedTarget,
    );

    assert(resolveHead(repoRoot) === currentRevision, "checkout HEAD changed during promotion verification");
    authorityPlane.assertResolvedHead(currentRevision);
    assertCleanWorktree(repoRoot);
    authorityPlane.recheck();
    return Object.freeze({
      schema: VERIFICATION_SCHEMA,
      authorized: true,
      currentRevision,
      promotionTopicRevision,
      sourceRevision: admission.sourceRevision,
      sourceTreeObjectId: admission.sourceTreeObjectId,
      target: structuredClone(admission.target),
      portableArtifactId: admission.portableArtifactId,
      admissionDigest: admission.admissionDigest,
      admittedScopeDigest: currentScope.admittedScopeDigest,
      predecessorScopeDigest: currentScope.predecessorScopeDigest,
    });
  } finally {
    authorityPlane.close();
  }
}

function exactCheckedSelectionOptions(options) {
  assert(options && typeof options === "object" && !Array.isArray(options), "checked promotion admission expects one options object");
  const keys = Object.keys(options).sort();
  const allowed = ["expectedSourceRevision", "portableArtifactId", "repoRoot", "targetTriple"];
  assert(keys.every((key) => allowed.includes(key)), `checked promotion admission received unknown option ${keys.find((key) => !allowed.includes(key))}`);
  for (const required of ["expectedSourceRevision", "portableArtifactId", "targetTriple"]) {
    assert(Object.prototype.hasOwnProperty.call(options, required), `checked promotion admission is missing ${required}`);
  }
  assertSha1ObjectId(options.expectedSourceRevision, "selected artifact source revision");
  assertSemanticDigest(options.portableArtifactId, "selected portable artifact ID");
  assert(
    typeof options.targetTriple === "string"
      && /^[a-z0-9_]+(?:-[a-z0-9_]+)+$/u.test(options.targetTriple)
      && options.targetTriple.length <= 128,
    "selected portable target triple is invalid",
  );
  return {
    repoRoot: options.repoRoot ?? process.cwd(),
    expectedSourceRevision: options.expectedSourceRevision,
    targetTriple: options.targetTriple,
    portableArtifactId: options.portableArtifactId,
  };
}

function validateLineageVerificationResult(lineage) {
  assert(lineage && typeof lineage === "object" && !Array.isArray(lineage), "promotion lineage verification result must be an object");
  assert(lineage.schema === VERIFICATION_SCHEMA, "promotion lineage verification result has an unsupported schema");
  assert(typeof lineage.authorized === "boolean", "promotion lineage verification result has no closed authorization outcome");
  assertSha1ObjectId(lineage.currentRevision, "promotion lineage current revision");
  if (!lineage.authorized) {
    assertExactKeys(lineage, ["schema", "authorized", "currentRevision", "admission"], "disabled promotion lineage verification result");
    assert(lineage.admission === null, "disabled promotion lineage verification result must carry a null admission");
    return;
  }
  assertExactKeys(
    lineage,
    [
      "schema",
      "authorized",
      "currentRevision",
      "promotionTopicRevision",
      "sourceRevision",
      "sourceTreeObjectId",
      "target",
      "portableArtifactId",
      "admissionDigest",
      "admittedScopeDigest",
      "predecessorScopeDigest",
    ],
    "active promotion lineage verification result",
  );
  assertSha1ObjectId(lineage.promotionTopicRevision, "promotion lineage topic revision");
  assertSha1ObjectId(lineage.sourceRevision, "promotion lineage source revision");
  assertSha1ObjectId(lineage.sourceTreeObjectId, "promotion lineage source tree object ID");
  validateCanonicalTarget(lineage.target, "promotion lineage target");
  assertSemanticDigest(lineage.portableArtifactId, "promotion lineage portable artifact ID");
  assertSemanticDigest(lineage.admissionDigest, "promotion lineage admission digest");
  assertSemanticDigest(lineage.admittedScopeDigest, "promotion lineage admitted scope digest");
  assert(
    lineage.predecessorScopeDigest === SCOPE_GENESIS_MARKER
      || (typeof lineage.predecessorScopeDigest === "string" && /^sha256-[A-Za-z0-9_-]{43}$/u.test(lineage.predecessorScopeDigest)),
    "promotion lineage predecessor scope digest is invalid",
  );
}

// This formatter does not establish Git authority by itself. Production calls
// it only with the result returned by the fixed verifier above; the separately
// exported checked entry point performs that composition for other consumers.
export function bindVerifiedPortableEnginePromotionAdmission(lineage, selection) {
  if (arguments.length !== 2) fail("checked promotion admission binding expects one verified lineage result and one selection");
  validateLineageVerificationResult(lineage);
  const selected = exactCheckedSelectionOptions(selection);
  if (lineage.authorized) {
    assert(lineage.sourceRevision === selected.expectedSourceRevision, "promoted artifact source revision differs from the selected manifest/store source revision");
    assert(lineage.target.triple === selected.targetTriple, "promoted target triple differs from the selected manifest/store target");
    assert(lineage.portableArtifactId === selected.portableArtifactId, "promoted artifact ID differs from the selected manifest/store artifact ID");
  } else {
    assert(lineage.currentRevision === selected.expectedSourceRevision, "a disabled promotion catalog is diagnostic only at its exact artifact-source checkout");
  }
  const checked = {
    schema: CHECKED_ADMISSION_SCHEMA,
    authorized: lineage.authorized,
    currentRevision: lineage.currentRevision,
    sourceRevision: selected.expectedSourceRevision,
    promotionTopicRevision: lineage.authorized ? lineage.promotionTopicRevision : null,
    sourceTreeObjectId: lineage.authorized ? lineage.sourceTreeObjectId : null,
    target: lineage.authorized
      ? structuredClone(lineage.target)
      : { triple: selected.targetTriple, features: [] },
    portableArtifactId: selected.portableArtifactId,
    admissionDigest: lineage.authorized ? lineage.admissionDigest : null,
    admittedScopeDigest: lineage.authorized ? lineage.admittedScopeDigest : null,
    predecessorScopeDigest: lineage.authorized ? lineage.predecessorScopeDigest : null,
  };
  return Object.freeze({
    ...checked,
    verificationDigest: semanticDigest(CHECKED_ADMISSION_DOMAIN, checked),
  });
}

export function verifyPortableEngineCheckedPromotionAdmission(options) {
  if (arguments.length !== 1) fail("checked promotion admission accepts exactly one production options object");
  const selected = exactCheckedSelectionOptions(options);
  const lineage = verifyPortableEnginePromotionAdmission({ repoRoot: selected.repoRoot });
  return bindVerifiedPortableEnginePromotionAdmission(lineage, selected);
}

function isDirectInvocation() {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync(process.argv[1]) === fs.realpathSync(moduleFilePath);
  } catch {
    return false;
  }
}

if (isDirectInvocation()) {
  try {
    assert(process.argv.length === 2, "portable-engine-promotion-lineage accepts no command-line arguments");
    process.stdout.write(`${canonicalJson(verifyPortableEnginePromotionAdmission({ repoRoot: process.cwd() }))}\n`);
  } catch (error) {
    process.stderr.write(`portable-engine-promotion-lineage: ${error.message}\n`);
    process.exitCode = 1;
  }
}
