import assert from "node:assert/strict";
import fs from "node:fs";
import * as fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalJson, parseMachO, rawDigest } from "./portable-engine-contract.mjs";

const sourceRepo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoots = [];

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
  } else {
    await fsp.chmod(root, 0o600);
  }
}

after(async () => {
  for (const root of temporaryRoots) {
    await makeWritable(root);
    await fsp.rm(root, { recursive: true, force: true });
  }
});

function command(executable, arguments_, options = {}) {
  const result = spawnSync(executable, arguments_, {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    ...options,
  });
  assert.equal(result.error, undefined, `${executable} could not run: ${result.error?.message ?? "unknown"}`);
  assert.equal(result.signal, null, `${executable} ended under ${result.signal}`);
  assert.equal(result.status, 0, `${executable} ${arguments_.join(" ")} failed:\n${result.stdout}\n${result.stderr}`);
  return result;
}

async function write(filePath, contents, mode = 0o600) {
  await fsp.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  await fsp.writeFile(filePath, contents, { mode });
  await fsp.chmod(filePath, mode);
}

function cargoArtifact(root, environment, arguments_, predicate) {
  const result = command("cargo", [...arguments_, "--message-format=json-render-diagnostics"], {
    cwd: root,
    env: environment,
  });
  const artifacts = result.stdout
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line))
    .filter((message) => message.reason === "compiler-artifact" && message.executable);
  const selected = artifacts.filter(predicate);
  assert.equal(selected.length, 1, `expected one Cargo executable for ${arguments_.join(" ")}, saw ${selected.map((item) => item.executable).join(", ")}`);
  return selected[0].executable;
}

test("actual Cargo target kinds receive one depth-correct Mach-O rpath and reject wrong-depth decoys", {
  skip: process.platform !== "darwin" || process.arch !== "arm64",
  timeout: 180_000,
}, async () => {
  const temporary = await fsp.mkdtemp(path.join(os.tmpdir(), "ibex-rustc-wrapper-"));
  temporaryRoots.push(temporary);
  const root = await fsp.realpath(temporary);
  const artifactId = `sha256-${"A".repeat(43)}`;
  const realLibraryDirectory = path.join(root, "target", "hermes-artifacts", artifactId, "payload", "lib");
  const directWrongDirectory = path.join(root, "target", "debug", "hermes-artifacts", artifactId, "payload", "lib");
  const releaseWrongDirectory = path.join(root, "target", "release", "hermes-artifacts", artifactId, "payload", "lib");
  const nestedWrongDirectory = path.join(root, "hermes-artifacts", artifactId, "payload", "lib");
  await write(path.join(root, "real.c"), "int fixture_value(void) { return 7; }\n");
  await write(path.join(root, "decoy.c"), "int fixture_value(void) { return 99; }\n");
  await fsp.mkdir(realLibraryDirectory, { recursive: true });
  for (const directory of [directWrongDirectory, releaseWrongDirectory, nestedWrongDirectory]) await fsp.mkdir(directory, { recursive: true });
  command("/usr/bin/clang", ["-dynamiclib", "-Wl,-install_name,@rpath/libfixture.dylib", "-o", path.join(realLibraryDirectory, "libfixture.dylib"), path.join(root, "real.c")]);
  const decoy = path.join(root, "libfixture-decoy.dylib");
  command("/usr/bin/clang", ["-dynamiclib", "-Wl,-install_name,@rpath/libfixture.dylib", "-o", decoy, path.join(root, "decoy.c")]);
  for (const directory of [directWrongDirectory, releaseWrongDirectory, nestedWrongDirectory]) {
    await fsp.copyFile(decoy, path.join(directory, "libfixture.dylib"));
  }

  await write(path.join(root, "Cargo.toml"), `[package]\nname = "probe"\nversion = "0.1.0"\nedition = "2021"\nbuild = "build.rs"\n\n[[bin]]\nname = "probe"\npath = "src/bin/probe/main.rs"\n\n[[example]]\nname = "probe_example"\npath = "examples/probe_example.rs"\n\n[[bench]]\nname = "probe_bench"\npath = "benches/probe_bench.rs"\nharness = false\n`);
  await write(path.join(root, "build.rs"), `fn main() { println!("cargo:rustc-link-search=native=${realLibraryDirectory}"); println!("cargo:rustc-link-lib=dylib=fixture"); }\n`);
  await write(path.join(root, "src/lib.rs"), `unsafe extern "C" { fn fixture_value() -> i32; }\npub fn value() -> i32 { unsafe { fixture_value() } }\n#[cfg(test)] mod tests { #[test] fn real_library() { assert_eq!(super::value(), 7); } }\n`);
  await write(path.join(root, "src/bin/probe/main.rs"), `fn main() { assert_eq!(probe::value(), 7); println!("7"); }\n#[cfg(test)] mod tests { #[test] fn real_library() { assert_eq!(probe::value(), 7); } }\n`);
  await write(path.join(root, "tests/probe_integration.rs"), `#[test] fn real_library() { assert_eq!(probe::value(), 7); }\n`);
  await write(path.join(root, "examples/probe_example.rs"), `fn main() { assert_eq!(probe::value(), 7); println!("7"); }\n`);
  await write(path.join(root, "benches/probe_bench.rs"), `fn main() { assert_eq!(probe::value(), 7); println!("7"); }\n`);

  const targetMap = {
    schema: "ibex/portable-engine-cargo-target-map/1",
    packageName: "probe",
    manifestDigest: rawDigest(await fsp.readFile(path.join(root, "Cargo.toml"))),
    targets: [
      { kind: "bench", name: "probe_bench", crateName: "probe_bench", source: "benches/probe_bench.rs" },
      { kind: "bin", name: "probe", crateName: "probe", source: "src/bin/probe/main.rs" },
      { kind: "custom-build", name: "build-script-build", crateName: "build_script_build", source: "build.rs" },
      { kind: "example", name: "probe_example", crateName: "probe_example", source: "examples/probe_example.rs" },
      { kind: "lib", name: "probe", crateName: "probe", source: "src/lib.rs" },
      { kind: "test", name: "probe_integration", crateName: "probe_integration", source: "tests/probe_integration.rs" },
    ],
  };
  const targetMapPath = path.join(root, ".capability", "cargo-target-map.json");
  const targetMapBytes = Buffer.from(canonicalJson(targetMap), "utf8");
  await write(targetMapPath, targetMapBytes, 0o400);
  const wrapperSource = await fsp.readFile(path.join(sourceRepo, "scripts/portable-engine-rustc-wrapper.mjs"));
  const wrapperPath = path.join(root, ".capability", "rustc-wrapper.mjs");
  await write(wrapperPath, Buffer.concat([Buffer.from(`#!${process.execPath}\n`), wrapperSource]), 0o500);
  const environment = { ...process.env };
  for (const name of Object.keys(environment)) {
    if (["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"].includes(name) || /^CARGO_TARGET_.+_(?:RUSTFLAGS|LINKER|RUNNER)$/u.test(name)) delete environment[name];
  }
  environment.CARGO_TARGET_DIR = path.join(root, "target");
  environment.RUSTC_WRAPPER = wrapperPath;
  environment.IBEX_PORTABLE_HERMES_CHECKOUT_ROOT = root;
  environment.IBEX_PORTABLE_HERMES_ARTIFACT_ID = artifactId;
  environment.IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP = targetMapPath;
  environment.IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP_DIGEST = rawDigest(targetMapBytes);

  const directWrapper = (arguments_, overrides = {}) => spawnSync(wrapperPath, ["/usr/bin/true", ...arguments_], {
    cwd: root,
    env: { ...environment, ...overrides },
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  const knownExecutableArguments = [
    path.join(root, "src/bin/probe/main.rs"),
    "--crate-name", "probe",
    "--emit", "link",
    "--crate-type", "bin",
    "--out-dir", path.join(root, "target/debug/deps"),
  ];
  const linkerOverride = directWrapper([...knownExecutableArguments, "-C", "linker=/tmp/attacker"]);
  assert.equal(linkerOverride.status, 86);
  assert.match(linkerOverride.stderr, /alternate linker\/rpath option/u);
  const unknownSource = path.join(root, "src/bin/unmapped.rs");
  await write(unknownSource, "fn main() {}\n");
  const unknownTarget = directWrapper([
    unknownSource,
    "--crate-name", "unmapped",
    "--emit", "link",
    "--crate-type", "bin",
    "--out-dir", path.join(root, "target/debug/deps"),
  ], { CARGO_PRIMARY_PACKAGE: "1" });
  assert.equal(unknownTarget.status, 86);
  assert.match(unknownTarget.stderr, /unknown root-package executable target source/u);
  await fsp.unlink(unknownSource);

  const observed = [
    ["bin", cargoArtifact(root, environment, ["build", "--bin", "probe"], (item) => item.target.name === "probe" && item.target.kind.includes("bin") && !item.profile.test), "@loader_path/../"],
    ["bin-test", cargoArtifact(root, environment, ["test", "--bin", "probe", "--no-run"], (item) => item.target.name === "probe" && item.target.kind.includes("bin") && item.profile.test), "@loader_path/../../"],
    ["lib-test", cargoArtifact(root, environment, ["test", "--lib", "--no-run"], (item) => item.target.name === "probe" && item.target.kind.some((kind) => ["lib", "rlib", "staticlib"].includes(kind)) && item.profile.test), "@loader_path/../../"],
    ["integration", cargoArtifact(root, environment, ["test", "--test", "probe_integration", "--no-run"], (item) => item.target.name === "probe_integration"), "@loader_path/../../"],
    ["example", cargoArtifact(root, environment, ["build", "--example", "probe_example"], (item) => item.target.name === "probe_example"), "@loader_path/../../"],
    ["bench", cargoArtifact(root, environment, ["bench", "--bench", "probe_bench", "--no-run"], (item) => item.target.name === "probe_bench"), "@loader_path/../../"],
  ];
  for (const [label, executable, prefix] of observed) {
    const expected = `${prefix}hermes-artifacts/${artifactId}/payload/lib`;
    const alternatePrefix = prefix === "@loader_path/../" ? "@loader_path/../../" : "@loader_path/../";
    const alternate = `${alternatePrefix}hermes-artifacts/${artifactId}/payload/lib`;
    const macho = parseMachO(await fsp.readFile(executable), { architecture: "arm64", requireExternalDefinedSymbols: false });
    assert.deepEqual(macho.rpaths, [expected], `${label} did not receive exactly its one placement-correct rpath`);
    assert(!macho.rpaths.includes(alternate), `${label} retained the wrong-depth decoy rpath`);
    const execution = command(executable, [], { cwd: root, env: { PATH: "/usr/bin:/bin" } });
    if (["bin", "example", "bench"].includes(label)) assert.match(execution.stdout, /7/u);
  }
});
