#!/usr/bin/env node

// Regenerate the checked expected artifact set for the one authoritative
// portable macOS Cargo invocation. This command runs metadata only; it never
// builds or executes repository code.
//
// @ref LLP 0035#build-consumption-and-post-link-contracts — checked source
// authority, rather than a caller-selected target subset, closes post-link
// executable enumeration.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  canonicalJson,
  compareUtf8,
  parseJsonStrict,
} from "./portable-engine-contract.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const outputPath = path.join(
  repoRoot,
  "config/portable-engine-cargo-executables-authenticated-v1.json",
);
const requestedFeatures = Object.freeze([
  "capsec-conformance-observer",
  "cli-notify",
  "default",
  "host-http-server",
  "openssl-crypto",
]);

function fail(message) {
  throw new Error(message);
}

function runMetadata() {
  const result = spawnSync(
    "cargo",
    [
      "metadata",
      "--locked",
      "--no-deps",
      "--format-version=1",
      "--features",
      requestedFeatures.join(","),
    ],
    {
      cwd: repoRoot,
      encoding: null,
      env: { ...process.env, LC_ALL: "C", LANG: "C" },
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  if (result.status !== 0 || result.signal !== null) {
    fail(
      `cargo metadata failed: ${Buffer.from(result.stderr ?? [])
        .toString("utf8")
        .trim()}`,
    );
  }
  return parseJsonStrict(Buffer.from(result.stdout), "cargo metadata");
}

function row(target, cargoTargetKind, profileTest, targetKind) {
  const kinds = [...target.kind].sort(compareUtf8);
  return {
    cargoTargetKind,
    cargoTargetKinds: kinds,
    cargoTargetName: target.name,
    profileTest,
    targetKind,
    logicalName: `${targetKind}/${target.name}`,
  };
}

function activeRootFeatures(packageFeatures) {
  const active = new Set(requestedFeatures);
  const pending = [...requestedFeatures];
  while (pending.length > 0) {
    const feature = pending.pop();
    const members = packageFeatures[feature];
    if (!Array.isArray(members))
      fail(
        `requested Cargo feature ${feature} is not declared by the root package`,
      );
    for (const member of members) {
      if (!Object.prototype.hasOwnProperty.call(packageFeatures, member))
        continue;
      if (active.has(member)) continue;
      active.add(member);
      pending.push(member);
    }
  }
  return [...active].sort(compareUtf8);
}

function rowsForTarget(target, features) {
  if (
    !(target["required-features"] ?? []).every((feature) =>
      features.includes(feature),
    )
  )
    return [];
  const kinds = new Set(target.kind);
  if (kinds.has("custom-build")) return [];
  if (kinds.has("bin")) {
    return [
      row(target, "bin", false, "bin"),
      ...(target.test ? [row(target, "bin", true, "test")] : []),
    ];
  }
  if (kinds.has("test")) return [row(target, "test", true, "test")];
  if (kinds.has("example")) {
    return [row(target, "example", true, "example")];
  }
  if (kinds.has("bench")) return [row(target, "bench", true, "bench")];
  if (
    ["cdylib", "dylib", "lib", "rlib", "staticlib"].some((kind) =>
      kinds.has(kind),
    )
  ) {
    return target.test ? [row(target, "lib", true, "test")] : [];
  }
  fail(
    `${target.name}: unsupported Cargo target kinds ${JSON.stringify(target.kind)}`,
  );
}

export function generatePortableEngineCargoExecutableSet() {
  const metadata = runMetadata();
  const manifestPath = path.join(repoRoot, "Cargo.toml");
  const packages = metadata.packages.filter(
    (candidate) => path.resolve(candidate.manifest_path) === manifestPath,
  );
  if (packages.length !== 1)
    fail(`expected one root Cargo package; found ${packages.length}`);
  const selectedPackage = packages[0];
  if (selectedPackage.name !== "ibex-runtime")
    fail("root Cargo package is not ibex-runtime");
  const features = activeRootFeatures(selectedPackage.features);
  const cargoArguments = [
    "test",
    "--locked",
    "--no-run",
    "--all-targets",
    "--features",
    features.join(","),
    "--message-format=json",
  ];
  const targets = selectedPackage.targets
    .flatMap((target) => rowsForTarget(target, features))
    .sort((left, right) => {
      const logical = compareUtf8(left.logicalName, right.logicalName);
      if (logical !== 0) return logical;
      const kind = compareUtf8(left.cargoTargetKind, right.cargoTargetKind);
      if (kind !== 0) return kind;
      return Number(left.profileTest) - Number(right.profileTest);
    });
  for (let index = 1; index < targets.length; index += 1) {
    if (targets[index - 1].logicalName === targets[index].logicalName) {
      fail(
        `Cargo targets collapse to duplicate evidence identity ${targets[index].logicalName}`,
      );
    }
  }
  return {
    schema: "ibex/portable-engine-cargo-executable-set/1",
    mode: "cargo-test-no-run-all-targets",
    package: {
      name: selectedPackage.name,
      version: selectedPackage.version,
      manifestPath: "Cargo.toml",
    },
    targetTriple: "aarch64-apple-darwin",
    ibexFeatures: [...features],
    cargoArguments: [...cargoArguments],
    targets,
  };
}

function main(argv) {
  if (argv.length !== 1 || !["--check", "--write"].includes(argv[0])) {
    fail(
      "usage: node scripts/generate-portable-engine-cargo-executable-set.mjs --check|--write",
    );
  }
  const bytes = Buffer.from(
    canonicalJson(generatePortableEngineCargoExecutableSet()),
    "utf8",
  );
  if (argv[0] === "--write") {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, bytes);
    return;
  }
  const checked = fs.readFileSync(outputPath);
  if (!checked.equals(bytes))
    fail(`${path.relative(repoRoot, outputPath)} is stale; rerun with --write`);
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(
      `generate-portable-engine-cargo-executable-set: ${error.message}\n`,
    );
    process.exitCode = 1;
  }
}
