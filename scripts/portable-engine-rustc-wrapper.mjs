// Output-aware rustc seam for authenticated portable Hermes builds.
//
// Cargo applies `rustc-link-arg-bin` to both the promoted ordinary binary and
// that bin's unit-test harness, even though the former loads from the profile
// directory and the latter loads from `deps`. The preflight runner materializes
// this checked source behind an absolute-node launcher and selects it as
// RUSTC_WRAPPER. It observes Cargo's actual rustc invocation and injects one,
// and only one, loader-relative rpath for final package executables.
//
// @ref LLP 0035#build-consumption-and-post-link-contracts — every final Mach-O
// receives one target-placement-specific loader-relative engine rpath.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";

const ARTIFACT_ENV = "IBEX_PORTABLE_HERMES_ARTIFACT_ID";
const REPO_ENV = "IBEX_PORTABLE_HERMES_CHECKOUT_ROOT";
const TARGET_MAP_ENV = "IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP";
const TARGET_MAP_DIGEST_ENV = "IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP_DIGEST";
const semanticDigestPattern = /^sha256-[A-Za-z0-9_-]{43}$/u;
const rawDigestPattern = /^sha256-[a-f0-9]{64}$/u;

function fail(message) {
  process.stderr.write(`portable Hermes rustc wrapper refused: ${message}\n`);
  process.exit(86);
}

function oneOption(arguments_, name) {
  const values = [];
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === name) {
      if (index + 1 >= arguments_.length) fail(`${name} has no value`);
      values.push(arguments_[index + 1]);
    } else if (argument.startsWith(`${name}=`)) {
      values.push(argument.slice(name.length + 1));
    }
  }
  if (values.length !== 1) fail(`expected exactly one ${name} option, observed ${values.length}`);
  return values[0];
}

function emitsLinkedArtifact(arguments_) {
  const emit = oneOption(arguments_, "--emit");
  return emit.split(",").includes("link");
}

function isExecutableInvocation(arguments_) {
  if (arguments_.includes("--test")) return true;
  const crateTypes = [];
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--crate-type") {
      if (index + 1 >= arguments_.length) fail("--crate-type has no value");
      crateTypes.push(arguments_[index + 1]);
      index += 1;
    } else if (argument.startsWith("--crate-type=")) {
      crateTypes.push(argument.slice("--crate-type=".length));
    }
  }
  return crateTypes.some((value) => value.split(",").includes("bin"));
}

function rejectCallerSelectedLinkage(arguments_) {
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    const codegen = argument === "-C" ? arguments_[index + 1] ?? "" :
      argument.startsWith("-C") ? argument.slice(2) : "";
    if (argument === "-C") index += 1;
    if (/^(?:rpath(?:=|$)|link-args?=|linker(?:=|$)|linker-flavor(?:=|$)|link-self-contained(?:=|$))/u.test(codegen) || /(?:^|,)\s*-rpath(?:,|=|\s|$)/u.test(argument)) {
      fail(`caller supplied an alternate linker/rpath option: ${argument}${codegen && argument === "-C" ? ` ${codegen}` : ""}`);
    }
  }
}

function loadTargetMap(repoRoot) {
  const targetMapPath = process.env[TARGET_MAP_ENV];
  const expectedDigest = process.env[TARGET_MAP_DIGEST_ENV];
  if (!targetMapPath || !path.isAbsolute(targetMapPath) || !rawDigestPattern.test(expectedDigest ?? "")) fail("Cargo target-map selectors are absent or malformed");
  const descriptor = fs.openSync(targetMapPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  let bytes;
  try {
    const status = fs.fstatSync(descriptor, { bigint: true });
    if (!status.isFile() || status.nlink !== 1n || status.uid !== BigInt(process.geteuid()) || Number(status.mode & 0o7777n) !== 0o400 || status.size <= 0n || status.size > 1024n * 1024n) fail("Cargo target map violates its private regular-file contract");
    bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (status.dev !== after.dev || status.ino !== after.ino || status.size !== after.size || status.mode !== after.mode) fail("Cargo target map changed while read");
  } finally {
    fs.closeSync(descriptor);
  }
  const digest = `sha256-${createHash("sha256").update(bytes).digest("hex")}`;
  if (digest !== expectedDigest) fail("Cargo target map bytes differ from the preflight receipt");
  const value = JSON.parse(bytes.toString("utf8"));
  if (!value || value.schema !== "ibex/portable-engine-cargo-target-map/1" || !Array.isArray(value.targets)) fail("Cargo target map has the wrong schema");
  const targets = value.targets.map((target) => {
    if (!target || typeof target !== "object" || !["lib", "bin", "example", "test", "bench", "custom-build"].includes(target.kind) || typeof target.name !== "string" || typeof target.crateName !== "string" || typeof target.source !== "string") fail("Cargo target map has a malformed row");
    const absoluteSource = path.join(repoRoot, ...target.source.split("/"));
    return { ...target, absoluteSource };
  });
  return targets;
}

function classifyPlacement(arguments_, targets, repoRoot) {
  const candidates = targets.filter((target) => arguments_.some((argument) => !argument.startsWith("-") && path.resolve(process.cwd(), argument) === target.absoluteSource));
  if (candidates.length === 0) {
    const unknownRepoSources = arguments_
      .filter((argument) => !argument.startsWith("-") && argument.endsWith(".rs"))
      .map((argument) => path.resolve(process.cwd(), argument))
      .filter((source) => source.startsWith(`${repoRoot}${path.sep}`));
    if (process.env.CARGO_PRIMARY_PACKAGE === "1" && unknownRepoSources.length > 0 && isExecutableInvocation(arguments_) && emitsLinkedArtifact(arguments_)) {
      fail(`unknown root-package executable target source: ${unknownRepoSources.join(", ")}`);
    }
    return null;
  }
  if (candidates.length !== 1) fail("rustc invocation ambiguously matches multiple checked Cargo targets");
  const target = candidates[0];
  if (oneOption(arguments_, "--crate-name") !== target.crateName) fail(`${target.kind}/${target.name}: rustc crate name differs from checked Cargo metadata`);
  if (!emitsLinkedArtifact(arguments_)) return null;
  if (target.kind === "custom-build") return null;
  const outDir = path.resolve(oneOption(arguments_, "--out-dir"));
  const testHarness = arguments_.includes("--test");
  let placement;
  if (target.kind === "bin") {
    if (path.basename(outDir) !== "deps") fail("Cargo bin rustc output is not in the expected deps staging directory");
    placement = testHarness ? "nested" : "direct";
  } else if (target.kind === "lib") {
    if (!testHarness) return null;
    if (!testHarness || path.basename(outDir) !== "deps") fail("library executable is not the expected unit-test harness in deps");
    placement = "nested";
  } else if (target.kind === "example") {
    if (path.basename(outDir) !== "examples") fail("Cargo example rustc output is not in examples");
    placement = "nested";
  } else if (target.kind === "test" || target.kind === "bench") {
    if (path.basename(outDir) !== "deps") fail("Cargo test/bench rustc output is not in deps");
    placement = "nested";
  } else {
    fail(`${target.kind}/${target.name}: checked Cargo target cannot be assigned an executable placement`);
  }
  return { placement, target };
}

const [rustc, ...rustcArguments] = process.argv.slice(2);
if (!rustc || rustcArguments.length === 0) fail("Cargo did not supply rustc and its arguments");
const repoInput = process.env[REPO_ENV];
const artifactId = process.env[ARTIFACT_ENV];
if (!repoInput || !path.isAbsolute(repoInput)) fail(`${REPO_ENV} must be one absolute path`);
if (!semanticDigestPattern.test(artifactId ?? "")) fail(`${ARTIFACT_ENV} is not a semantic SHA-256 digest`);
const repoRoot = fs.realpathSync(repoInput);
if (repoRoot !== repoInput) fail(`${REPO_ENV} is redirected or non-canonical`);
if (fs.realpathSync(process.cwd()) !== repoRoot) fail("rustc wrapper cwd is not the authenticated checkout root");
const cargoTargets = loadTargetMap(repoRoot);

const classified = classifyPlacement(rustcArguments, cargoTargets, repoRoot);
const finalArguments = [...rustcArguments];
if (classified !== null) {
  rejectCallerSelectedLinkage(rustcArguments);
  const depth = classified.placement === "direct" ? ".." : "../..";
  const rpath = `@loader_path/${depth}/hermes-artifacts/${artifactId}/payload/lib`;
  finalArguments.push("-C", `link-arg=-Wl,-rpath,${rpath}`);
}

const result = spawnSync(rustc, finalArguments, {
  stdio: "inherit",
  env: process.env,
  windowsHide: true,
});
if (result.error) fail(`could not execute Cargo-selected rustc: ${result.error.message}`);
if (result.signal) {
  process.kill(process.pid, result.signal);
  fail(`rustc ended under signal ${result.signal}`);
}
process.exit(result.status ?? 1);
