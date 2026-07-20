// Shared mechanics for the production portable-build runner and its named
// test-only harness. Production authority is supplied only by
// run-portable-hermes-cargo.mjs, which fixes the merged production store
// verifier and Cargo launcher.
//
// @ref LLP 0035#build-consumption-and-post-link-contracts — build inputs and
// host tools are unavailable until a fresh checkout-local provenance pass has
// minted one process-bound build capability.

import fs from "node:fs";
import * as fsp from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";

import { canonicalJson, rawDigest, semanticDigest } from "./portable-engine-contract.mjs";

const RECEIPT_SCHEMA = "ibex/portable-engine-build-preflight/1";
const CLAIM_SCHEMA = "ibex/portable-engine-build-preflight-claim/1";
const CAPABILITY_PREFIX = ".portable-engine-build-capability-";
const WRAPPER_SOURCE = "scripts/portable-engine-rustc-wrapper.mjs";
const MAX_WRAPPER_BYTES = 1024 * 1024;
const TARGET_MAP_SCHEMA = "ibex/portable-engine-cargo-target-map/1";
const PROMOTION_ADMISSION_SCHEMA = "ibex/portable-engine-checked-promotion-admission/1";
const PROMOTION_ADMISSION_DOMAIN = "ibex.portable-engine-checked-promotion-admission.v1";
const semanticDigestPattern = /^sha256-[A-Za-z0-9_-]{43}$/u;
const revisionPattern = /^[a-f0-9]{40}$/u;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label}: expected object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  assert(canonicalJson(actual) === canonicalJson(wanted), `${label}: malformed exact fields`);
}

export function validateCheckedPromotionAdmission({
  verified,
  expectedSourceRevision,
  artifactId,
}) {
  const admission = verified?.promotionAdmission;
  exactKeys(admission, [
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
  ], "checked promotion admission");
  assert(admission.schema === PROMOTION_ADMISSION_SCHEMA, "checked promotion admission has the wrong schema");
  assert(typeof admission.authorized === "boolean", "checked promotion admission authorization is not boolean");
  assert(revisionPattern.test(admission.currentRevision) && revisionPattern.test(admission.sourceRevision), "checked promotion admission revisions are malformed");
  assert(admission.sourceRevision === expectedSourceRevision, "checked promotion admission names a different artifact source revision");
  assert(admission.portableArtifactId === artifactId, "checked promotion admission names a different portable artifact");
  assert(admission.targetTriple === verified?.manifest?.target?.triple, "checked promotion admission names a different verified target");
  assert(verified.authorized === admission.authorized, "production verifier authorization differs from its checked promotion admission");
  assert(semanticDigestPattern.test(admission.verificationDigest), "checked promotion admission verification digest is malformed");
  assert(
    semanticDigest(PROMOTION_ADMISSION_DOMAIN, admission, ["verificationDigest"]) === admission.verificationDigest,
    "checked promotion admission verification digest does not bind its exact fields",
  );
  if (admission.authorized) {
    assert(admission.currentRevision !== admission.sourceRevision, "authorized promotion admission does not advance beyond the artifact source revision");
    assert(revisionPattern.test(admission.promotionTopicRevision), "authorized promotion admission topic revision is malformed");
    assert(admission.promotionTopicRevision !== admission.currentRevision && admission.promotionTopicRevision !== admission.sourceRevision, "authorized promotion admission does not distinguish A/P/C revisions");
    assert(revisionPattern.test(admission.sourceTreeObjectId), "authorized promotion admission source-tree object ID is malformed");
    assert(semanticDigestPattern.test(admission.admissionDigest), "authorized promotion admission digest is malformed");
  } else {
    assert(admission.currentRevision === admission.sourceRevision, "diagnostic promotion admission is not pinned to its artifact source revision");
    assert(admission.promotionTopicRevision === null && admission.sourceTreeObjectId === null && admission.admissionDigest === null, "diagnostic promotion admission carries unauthorized lineage authority");
  }
  return structuredClone(admission);
}

function identity(status) {
  return {
    device: status.dev.toString(10),
    inode: status.ino.toString(10),
    uid: status.uid.toString(10),
    mode: Number(status.mode & 0o7777n).toString(8).padStart(4, "0"),
  };
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.mode === right.mode;
}

function effectiveUid() {
  assert(typeof process.geteuid === "function", "portable build preflight requires an effective-UID check");
  return BigInt(process.geteuid());
}

function hasExtendedAcl(filePath) {
  assert(process.platform === "darwin", "production portable build preflight requires Darwin ACL inspection");
  const result = spawnSync("/bin/ls", ["-lde", filePath], {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin", LC_ALL: "C", LANG: "C" },
    maxBuffer: 1024 * 1024,
  });
  assert(result.status === 0, `${filePath}: cannot inspect macOS ACL state`);
  const firstToken = result.stdout.trimStart().split(/\s+/u, 1)[0] ?? "";
  return firstToken.endsWith("+") || /^\s+\d+:/mu.test(result.stdout);
}

async function requireOwnedNode(filePath, kind, exactMode, label, { nlinkOne = false } = {}) {
  const before = await fsp.lstat(filePath, { bigint: true });
  assert(!before.isSymbolicLink(), `${label}: symlinks are forbidden`);
  assert(kind === "directory" ? before.isDirectory() : kind === "regular" ? before.isFile() : before.isSocket(), `${label}: wrong node kind`);
  assert(before.uid === effectiveUid(), `${label}: expected effective-UID ownership`);
  const mode = Number(before.mode & 0o7777n);
  assert(mode === exactMode, `${label}: expected mode ${exactMode.toString(8)}, got ${mode.toString(8)}`);
  if (nlinkOne) assert(before.nlink === 1n, `${label}: hard links are forbidden`);
  assert(!hasExtendedAcl(filePath), `${label}: macOS extended ACLs are forbidden`);
  const after = await fsp.lstat(filePath, { bigint: true });
  assert(sameIdentity(before, after) && before.size === after.size && before.nlink === after.nlink, `${label}: node changed during validation`);
  return before;
}

async function readRegularNoFollow(filePath, maximum, label) {
  const handle = await fsp.open(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat({ bigint: true });
    assert(before.isFile() && !before.isSymbolicLink(), `${label}: expected no-follow regular file`);
    assert(before.size > 0n && before.size <= BigInt(maximum), `${label}: invalid byte size`);
    assert(before.nlink === 1n, `${label}: hard links are forbidden`);
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    assert(sameIdentity(before, after) && before.size === after.size && bytes.length === Number(before.size), `${label}: file changed while read`);
    return bytes;
  } finally {
    await handle.close();
  }
}

function checkedRevisionBytes(repoRoot, revision, relativePath) {
  const result = spawnSync("/usr/bin/git", [
    "-c", "core.hooksPath=/dev/null",
    "-c", "extensions.objectFormat=sha1",
    "show", `${revision}:${relativePath}`,
  ], {
    cwd: repoRoot,
    encoding: null,
    env: {
      PATH: "/usr/bin:/bin",
      LC_ALL: "C",
      LANG: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
      GIT_NO_REPLACE_OBJECTS: "1",
    },
    maxBuffer: MAX_WRAPPER_BYTES,
  });
  assert(result.status === 0 && result.signal === null, `cannot read ${relativePath} from checked revision ${revision}`);
  return Buffer.from(result.stdout);
}

function checkedGit(repoRoot, arguments_, maximum = 4 * 1024 * 1024) {
  const result = spawnSync("/usr/bin/git", [
    "-c", "core.hooksPath=/dev/null",
    ...arguments_,
  ], {
    cwd: repoRoot,
    encoding: null,
    env: {
      PATH: "/usr/bin:/bin",
      LC_ALL: "C",
      LANG: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_LFS_SKIP_SMUDGE: "1",
    },
    maxBuffer: maximum,
  });
  assert(result.error === undefined && result.status === 0 && result.signal === null, `checked Git command failed: git ${arguments_.join(" ")}`);
  return Buffer.from(result.stdout ?? Buffer.alloc(0));
}

export async function requireProductionCleanCheckout({ repoRoot, expectedCurrentRevision }) {
  const root = checkedGit(repoRoot, ["rev-parse", "--show-toplevel"]).toString("utf8").trim();
  assert(await fsp.realpath(root) === repoRoot, "checked Git worktree root is redirected or differs from the authenticated checkout");
  const revision = checkedGit(repoRoot, ["rev-parse", "--verify", "HEAD^{commit}"]).toString("utf8").trim();
  assert(revision === expectedCurrentRevision, `checked worktree HEAD ${revision} differs from checked promotion current revision ${expectedCurrentRevision}`);
  const dirty = checkedGit(repoRoot, ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"], 16 * 1024 * 1024);
  assert(dirty.length === 0, "authoritative portable build requires a clean tracked and untracked Git worktree");
}

async function writeExclusive(filePath, bytes, mode) {
  const handle = await fsp.open(filePath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), mode);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fsp.chmod(filePath, mode);
}

function listen(server, socketPath) {
  return new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once("error", onError);
    server.listen(socketPath, () => {
      server.off("error", onError);
      resolve();
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

function waitForChild(child) {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
}

function rejectAmbientCargoSelectors(environment, cargoArgs) {
  const forbiddenExact = new Set([
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_TARGET_DIR",
  ]);
  const forbiddenPattern = /^CARGO_TARGET_.+_(?:RUSTFLAGS|LINKER|RUNNER)$/u;
  const selected = Object.keys(environment).filter((name) => forbiddenExact.has(name) || forbiddenPattern.test(name));
  assert(selected.length === 0, `ambient Cargo/Rust selector variables are forbidden: ${selected.sort().join(", ")}`);
  assert(!cargoArgs.includes("--config") && !cargoArgs.some((argument) => argument.startsWith("--config=")), "Cargo --config overrides are forbidden");
  assert(!cargoArgs.includes("--target-dir") && !cargoArgs.some((argument) => argument.startsWith("--target-dir=")), "Cargo target-dir overrides are forbidden");
  assert(!cargoArgs.includes("--target") && !cargoArgs.some((argument) => argument.startsWith("--target=")), "Cargo target overrides are forbidden in portable macOS v1");
  assert(!cargoArgs.includes("--manifest-path") && !cargoArgs.some((argument) => argument.startsWith("--manifest-path=")), "Cargo manifest-path overrides are forbidden");
  assert(!cargoArgs.includes("--workspace") && !cargoArgs.includes("--all") && !cargoArgs.includes("--exclude") && !cargoArgs.some((argument) => argument.startsWith("--exclude=")), "Cargo workspace/package-set overrides are forbidden");
  assert(!cargoArgs.includes("--package") && !cargoArgs.some((argument) => argument.startsWith("--package=") || /^-p.+/u.test(argument)), "Cargo package overrides are forbidden");
  assert(["build", "test", "bench", "run"].includes(cargoArgs[0]), "portable build runner admits only build, test, bench, or run Cargo commands");
}

async function rejectAmbientCargoConfig(repoRoot, environment) {
  const candidates = [];
  let current = repoRoot;
  while (true) {
    candidates.push(path.join(current, ".cargo", "config"), path.join(current, ".cargo", "config.toml"));
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  const cargoHome = environment.CARGO_HOME ? path.resolve(environment.CARGO_HOME) :
    environment.HOME ? path.join(path.resolve(environment.HOME), ".cargo") : null;
  if (cargoHome) candidates.push(path.join(cargoHome, "config"), path.join(cargoHome, "config.toml"));
  for (const candidate of new Set(candidates)) {
    try {
      await fsp.lstat(candidate);
      throw new Error(`ambient Cargo config is forbidden for authoritative builds: ${candidate}`);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
}

function normalizedRepoRelative(repoRoot, absolutePath, label) {
  assert(path.isAbsolute(absolutePath), `${label} is not absolute`);
  const relative = path.relative(repoRoot, absolutePath).split(path.sep).join("/");
  assert(relative.length > 0 && relative !== ".." && !relative.startsWith("../") && !path.isAbsolute(relative), `${label} escapes the authenticated checkout`);
  assert(!relative.split("/").some((segment) => segment === "" || segment === "." || segment === ".."), `${label} is not normalized`);
  return relative;
}

export async function loadProductionCargoTargetMap({ repoRoot, expectedSourceRevision }) {
  const manifestPath = path.join(repoRoot, "Cargo.toml");
  const manifestStatus = await fsp.lstat(manifestPath, { bigint: true });
  assert(manifestStatus.isFile() && !manifestStatus.isSymbolicLink() && manifestStatus.nlink === 1n, "Cargo manifest is redirected, hard-linked, or not regular");
  assert(manifestStatus.uid === effectiveUid() && (Number(manifestStatus.mode & 0o7777n) & 0o7022) === 0, "Cargo manifest violates the ownership/mode premise");
  assert(!hasExtendedAcl(manifestPath), "Cargo manifest has an extended ACL");
  const manifestBytes = await readRegularNoFollow(manifestPath, 4 * 1024 * 1024, "checked Cargo manifest");
  assert(manifestBytes.equals(checkedRevisionBytes(repoRoot, expectedSourceRevision, "Cargo.toml")), "Cargo manifest differs from the checked revision");

  const metadataEnvironment = { ...process.env, CARGO_TARGET_DIR: path.join(repoRoot, "target") };
  for (const name of ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"]) delete metadataEnvironment[name];
  const result = spawnSync("cargo", ["metadata", "--format-version=1", "--no-deps"], {
    cwd: repoRoot,
    env: metadataEnvironment,
    encoding: null,
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  assert(result.error === undefined && result.status === 0 && result.signal === null, `Cargo metadata refused the checked workspace: ${Buffer.from(result.stderr ?? Buffer.alloc(0)).toString("utf8").trim()}`);
  const metadata = JSON.parse(Buffer.from(result.stdout).toString("utf8"));
  assert(await fsp.realpath(metadata.workspace_root) === repoRoot, "Cargo metadata workspace root is redirected or differs from the authenticated checkout");
  assert(await fsp.realpath(metadata.target_directory) === await fsp.realpath(path.join(repoRoot, "target")), "Cargo metadata target directory is redirected or not checkout-local");
  const packages = metadata.packages.filter((candidate) => path.resolve(candidate.manifest_path) === manifestPath);
  assert(packages.length === 1, "Cargo metadata did not return exactly one root package for the checked manifest");
  const package_ = packages[0];
  const admittedKinds = new Set(["bin", "example", "test", "bench", "custom-build"]);
  const libraryKinds = new Set(["lib", "rlib", "dylib", "staticlib", "cdylib", "proc-macro"]);
  const targets = package_.targets.map((target) => {
    assert(Array.isArray(target.kind) && target.kind.length > 0, `Cargo target ${target.name} has no kind`);
    const kind = target.kind.every((candidate) => libraryKinds.has(candidate)) ? "lib" :
      target.kind.length === 1 && admittedKinds.has(target.kind[0]) ? target.kind[0] : null;
    assert(kind !== null, `Cargo target ${target.name} has an unclassified kind`);
    assert(typeof target.name === "string" && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u.test(target.name), "Cargo target name is outside the closed executable grammar");
    const source = normalizedRepoRelative(repoRoot, path.resolve(target.src_path), `Cargo target ${target.name} source`);
    return {
      kind,
      name: target.name,
      crateName: target.name.replaceAll("-", "_"),
      source,
    };
  }).sort((left, right) => Buffer.compare(Buffer.from(`${left.kind}\0${left.name}\0${left.source}`), Buffer.from(`${right.kind}\0${right.name}\0${right.source}`)));
  assert(targets.length > 0 && new Set(targets.map((target) => `${target.kind}\0${target.name}\0${target.source}`)).size === targets.length, "Cargo target map is empty or ambiguous");
  for (const target of targets) {
    const sourcePath = path.join(repoRoot, ...target.source.split("/"));
    const status = await fsp.lstat(sourcePath, { bigint: true });
    assert(status.isFile() && !status.isSymbolicLink() && status.nlink === 1n && status.uid === effectiveUid(), `${target.kind}/${target.name}: Cargo target source is redirected, hard-linked, or not owned`);
    assert((Number(status.mode & 0o7777n) & 0o7022) === 0, `${target.kind}/${target.name}: Cargo target source has unsafe mode bits`);
    assert(!hasExtendedAcl(sourcePath), `${target.kind}/${target.name}: Cargo target source has an extended ACL`);
  }
  for (const source of new Set(targets.map((target) => target.source))) {
    const sourcePath = path.join(repoRoot, ...source.split("/"));
    const sourceBytes = await readRegularNoFollow(sourcePath, 16 * 1024 * 1024, `checked Cargo target source ${source}`);
    assert(sourceBytes.equals(checkedRevisionBytes(repoRoot, expectedSourceRevision, source)), `Cargo target source ${source} differs from the checked revision`);
  }
  return {
    schema: TARGET_MAP_SCHEMA,
    packageName: package_.name,
    manifestDigest: rawDigest(manifestBytes),
    targets,
  };
}

async function createCapability({ repoRoot, artifactId, archiveDigest, expectedSourceRevision, verified, cargoTargetMap, promotionAdmission }) {
  const targetRoot = path.join(repoRoot, "target");
  const storeRoot = path.join(targetRoot, "hermes-artifacts");
  const checkoutStatus = await fsp.lstat(repoRoot, { bigint: true });
  const targetStatus = await fsp.lstat(targetRoot, { bigint: true });
  const storeStatus = await fsp.lstat(storeRoot, { bigint: true });
  assert(checkoutStatus.isDirectory() && !checkoutStatus.isSymbolicLink(), "authenticated checkout root became redirected");
  assert(targetStatus.isDirectory() && !targetStatus.isSymbolicLink(), "authenticated target root became redirected");
  assert(storeStatus.isDirectory() && !storeStatus.isSymbolicLink(), "authenticated portable store became redirected");

  const nonce = randomBytes(32).toString("hex");
  const capabilityDirectory = path.join(targetRoot, `${CAPABILITY_PREFIX}${nonce}`);
  await fsp.mkdir(capabilityDirectory, { mode: 0o700 });
  await fsp.chmod(capabilityDirectory, 0o700);
  const capabilityStatus = await requireOwnedNode(capabilityDirectory, "directory", 0o700, "portable build capability directory");

  const wrapperSourcePath = path.join(repoRoot, WRAPPER_SOURCE);
  const wrapperSourceStatus = await fsp.lstat(wrapperSourcePath, { bigint: true });
  assert(wrapperSourceStatus.isFile() && !wrapperSourceStatus.isSymbolicLink(), "portable rustc-wrapper source is redirected or not regular");
  assert(wrapperSourceStatus.uid === effectiveUid() && wrapperSourceStatus.nlink === 1n, "portable rustc-wrapper source violates ownership/link premise");
  assert((Number(wrapperSourceStatus.mode & 0o7777n) & 0o7022) === 0, "portable rustc-wrapper source has unsafe mode bits");
  assert(!hasExtendedAcl(wrapperSourcePath), "portable rustc-wrapper source has an extended ACL");
  const wrapperSource = await readRegularNoFollow(wrapperSourcePath, MAX_WRAPPER_BYTES, "portable rustc-wrapper source");
  const committedWrapperSource = checkedRevisionBytes(repoRoot, expectedSourceRevision, WRAPPER_SOURCE);
  assert(wrapperSource.equals(committedWrapperSource), "portable rustc-wrapper source differs from the checked revision");

  const nodeExecutable = await fsp.realpath(process.execPath);
  assert(path.isAbsolute(nodeExecutable) && !/[\r\n]/u.test(nodeExecutable), "Node executable path cannot form a launcher shebang");
  const launcherPath = path.join(capabilityDirectory, "rustc-wrapper");
  const launcherBytes = Buffer.concat([
    Buffer.from(`#!${nodeExecutable}\n`, "utf8"),
    wrapperSource,
  ]);
  await writeExclusive(launcherPath, launcherBytes, 0o500);
  const launcherStatus = await requireOwnedNode(launcherPath, "regular", 0o500, "portable rustc-wrapper launcher", { nlinkOne: true });

  const targetMapPath = path.join(capabilityDirectory, "cargo-target-map.json");
  const targetMapBytes = Buffer.from(canonicalJson(cargoTargetMap), "utf8");
  await writeExclusive(targetMapPath, targetMapBytes, 0o400);
  const targetMapStatus = await requireOwnedNode(targetMapPath, "regular", 0o400, "portable Cargo target map", { nlinkOne: true });

  const promotionAdmissionPath = path.join(capabilityDirectory, "promotion-admission.json");
  const promotionAdmissionBytes = Buffer.from(`${canonicalJson(promotionAdmission)}\n`, "utf8");
  await writeExclusive(promotionAdmissionPath, promotionAdmissionBytes, 0o400);
  const promotionAdmissionStatus = await requireOwnedNode(
    promotionAdmissionPath,
    "regular",
    0o400,
    "checked promotion admission",
    { nlinkOne: true },
  );

  let claimed = false;
  const socketPath = path.join(capabilityDirectory, "claim.sock");
  const expectedClaim = `${canonicalJson({ schema: CLAIM_SCHEMA, nonce, runnerPid: process.pid.toString(10) })}\n`;
  const authorizedResponse = `authorized:${nonce}\n`;
  const server = net.createServer((socket) => {
    let bytes = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length > 4096) socket.destroy();
    });
    socket.on("end", () => {
      if (!claimed && bytes.toString("utf8") === expectedClaim) {
        claimed = true;
        socket.end(authorizedResponse);
      } else {
        socket.destroy();
      }
    });
  });
  // Darwin's pathname-socket ABI has a short `sun_path`. Resolve the socket
  // relative to the already-validated private capability directory so a long
  // checkout path cannot truncate or redirect it.
  const priorCwd = process.cwd();
  try {
    process.chdir(capabilityDirectory);
    await listen(server, "claim.sock");
  } finally {
    process.chdir(priorCwd);
  }
  await fsp.chmod(socketPath, 0o600);
  const socketStatus = await requireOwnedNode(socketPath, "socket", 0o600, "portable build claim socket", { nlinkOne: true });

  const transportRoot = path.join(verified.artifactRoot, "LOCAL", "transport", archiveDigest);
  const verificationBytes = await readRegularNoFollow(
    path.join(transportRoot, "attestation-verification.json"),
    1024 * 1024,
    "freshly reverified attestation result",
  );
  const receipt = {
    schema: RECEIPT_SCHEMA,
    nonce,
    runnerPid: process.pid.toString(10),
    checkoutRoot: repoRoot,
    sourceRevision: expectedSourceRevision,
    currentRevision: promotionAdmission.currentRevision,
    artifactId,
    archiveDigest,
    manifestDigest: verified.transport.receipt.manifestDigest,
    installationReceiptDigest: semanticDigest("ibex.portable-engine-installation-receipt.v1", verified.transport.receipt),
    verificationPolicyDigest: verified.transport.receipt.verificationPolicyDigest,
    attestationVerificationDigest: rawDigest(verificationBytes),
    provenanceBundleDigest: verified.transport.receipt.provenanceBundleDigest,
    checkoutIdentity: identity(checkoutStatus),
    targetIdentity: identity(targetStatus),
    storeIdentity: identity(storeStatus),
    capabilityDirectoryIdentity: identity(capabilityStatus),
    claimSocketIdentity: identity(socketStatus),
    rustcWrapperPath: launcherPath,
    rustcWrapperDigest: rawDigest(launcherBytes),
    rustcWrapperSourceDigest: rawDigest(wrapperSource),
    rustcWrapperIdentity: identity(launcherStatus),
    cargoTargetMapPath: targetMapPath,
    cargoTargetMapDigest: rawDigest(targetMapBytes),
    cargoTargetMapIdentity: identity(targetMapStatus),
    promotionAdmissionPath,
    promotionAdmissionDigest: rawDigest(promotionAdmissionBytes),
    promotionAdmissionVerificationDigest: promotionAdmission.verificationDigest,
    promotionAdmissionIdentity: identity(promotionAdmissionStatus),
  };
  exactKeys(receipt, [
    "schema", "nonce", "runnerPid", "checkoutRoot", "sourceRevision", "currentRevision", "artifactId", "archiveDigest",
    "manifestDigest", "installationReceiptDigest", "verificationPolicyDigest", "attestationVerificationDigest",
    "provenanceBundleDigest", "checkoutIdentity", "targetIdentity", "storeIdentity", "capabilityDirectoryIdentity",
    "claimSocketIdentity", "rustcWrapperPath", "rustcWrapperDigest", "rustcWrapperSourceDigest", "rustcWrapperIdentity",
    "cargoTargetMapPath", "cargoTargetMapDigest", "cargoTargetMapIdentity",
    "promotionAdmissionPath", "promotionAdmissionDigest", "promotionAdmissionVerificationDigest", "promotionAdmissionIdentity",
  ], "portable build preflight receipt");
  const receiptPath = path.join(capabilityDirectory, "receipt.json");
  await writeExclusive(receiptPath, Buffer.from(canonicalJson(receipt), "utf8"), 0o400);
  await requireOwnedNode(receiptPath, "regular", 0o400, "portable build preflight receipt", { nlinkOne: true });
  return {
    nonce,
    receiptPath,
    launcherPath,
    targetMapPath,
    targetMapDigest: rawDigest(targetMapBytes),
    promotionAdmissionPath,
    promotionAdmissionDigest: rawDigest(promotionAdmissionBytes),
    server,
    claimed: () => claimed,
    async cleanup() {
      if (server.listening) await closeServer(server);
      const observed = await fsp.lstat(capabilityDirectory, { bigint: true }).catch((error) => error.code === "ENOENT" ? null : Promise.reject(error));
      if (observed) {
        assert(observed.isDirectory() && !observed.isSymbolicLink() && sameIdentity(observed, capabilityStatus), "portable build capability directory changed before cleanup");
        await fsp.rm(capabilityDirectory, { recursive: true, force: false });
      }
    },
  };
}

export async function runPortableHermesCargoCore(options, dependencies) {
  exactKeys(options, ["repoRoot", "artifactId", "archiveDigest", "expectedSourceRevision", "cargoArgs"], "portable build runner options");
  assert(Array.isArray(options.cargoArgs) && options.cargoArgs.length > 0 && options.cargoArgs.every((value) => typeof value === "string"), "portable build runner requires nonempty string Cargo arguments");
  assert(typeof dependencies?.verifyStore === "function" && typeof dependencies?.spawnCargo === "function" && typeof dependencies?.loadCargoTargetMap === "function" && typeof dependencies?.requireCleanCheckout === "function", "portable build runner dependencies are incomplete");
  rejectAmbientCargoSelectors(process.env, options.cargoArgs);

  // This call is deliberately first: no capability, wrapper, Cargo process,
  // or host-tool marker exists until the merged verifier has freshly checked
  // the exact checkout/store/transport selection.
  const verified = await dependencies.verifyStore({
    repoRoot: options.repoRoot,
    artifactId: options.artifactId,
    archiveDigest: options.archiveDigest,
    expectedSourceRevision: options.expectedSourceRevision,
  });
  const promotionAdmission = validateCheckedPromotionAdmission({
    verified,
    expectedSourceRevision: options.expectedSourceRevision,
    artifactId: options.artifactId,
  });
  const repoRoot = await fsp.realpath(options.repoRoot);
  await rejectAmbientCargoConfig(repoRoot, process.env);
  await dependencies.requireCleanCheckout({
    repoRoot,
    expectedCurrentRevision: promotionAdmission.currentRevision,
  });
  const cargoTargetMap = await dependencies.loadCargoTargetMap({ repoRoot, expectedSourceRevision: options.expectedSourceRevision });
  const capability = await createCapability({
    ...options,
    repoRoot,
    verified,
    cargoTargetMap,
    promotionAdmission,
  });
  try {
    const environment = { ...process.env };
    delete environment.RUSTC_WORKSPACE_WRAPPER;
    environment.CARGO_TARGET_DIR = path.join(repoRoot, "target");
    environment.RUSTC_WRAPPER = capability.launcherPath;
    environment.IBEX_PORTABLE_HERMES_CHECKOUT_ROOT = repoRoot;
    environment.IBEX_PORTABLE_HERMES_ARTIFACT_ID = options.artifactId;
    environment.IBEX_PORTABLE_HERMES_ARCHIVE_DIGEST = options.archiveDigest;
    environment.IBEX_PORTABLE_HERMES_SOURCE_REVISION = options.expectedSourceRevision;
    environment.IBEX_PORTABLE_HERMES_CURRENT_REVISION = promotionAdmission.currentRevision;
    environment.IBEX_PORTABLE_HERMES_PREFLIGHT_RECEIPT = capability.receiptPath;
    environment.IBEX_PORTABLE_HERMES_PREFLIGHT_NONCE = capability.nonce;
    environment.IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP = capability.targetMapPath;
    environment.IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP_DIGEST = capability.targetMapDigest;
    environment.IBEX_PORTABLE_HERMES_PROMOTION_ADMISSION = capability.promotionAdmissionPath;
    environment.IBEX_PORTABLE_HERMES_PROMOTION_ADMISSION_DIGEST = capability.promotionAdmissionDigest;
    const child = dependencies.spawnCargo(options.cargoArgs, { cwd: repoRoot, env: environment });
    const outcome = await waitForChild(child);
    await dependencies.requireCleanCheckout({
      repoRoot,
      expectedCurrentRevision: promotionAdmission.currentRevision,
    });
    if (outcome.code === 0 && outcome.signal === null && !capability.claimed()) {
      throw new Error("Cargo succeeded without consuming the one-use portable build capability");
    }
    return outcome;
  } finally {
    await capability.cleanup();
  }
}

export function spawnProductionCargo(arguments_, options) {
  return spawn("cargo", arguments_, { ...options, stdio: "inherit", windowsHide: true });
}

export const portableBuildPreflightSchemasTestOnly = Object.freeze({ receipt: RECEIPT_SCHEMA, claim: CLAIM_SCHEMA });
