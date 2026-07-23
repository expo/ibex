// @ref LLP 0035#build-consumption-and-post-link-contracts — adversarial tests
// cover complete Cargo enumeration, final-byte mutation, loader resolution,
// exact artifact binding, and all-or-nothing evidence publication.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, test } from "bun:test";
import { fileURLToPath } from "node:url";

import {
  assertCanonicalJsonBytes,
  canonicalJson,
  parseJsonStrict,
  rawDigest,
  semanticDigest,
} from "./portable-engine-contract.mjs";
import {
  cargoExecutableEnumerationContractTestOnly,
  verifyPortableEnginePostLinkTestOnly,
} from "./portable-engine-post-link-core.mjs";
import { generatePortableEngineCargoExecutableSet } from "./generate-portable-engine-cargo-executable-set.mjs";

const sourceRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const temporaryRoots = [];
const sourceRevision = "a".repeat(40);
const runtimeComponent = "lib/hermesvm.framework/Versions/1/hermesvm";
const runtimeInstallName = "@rpath/hermesvm.framework/Versions/1/hermesvm";
const systemDependency = "/usr/lib/libSystem.B.dylib";

function makeTreeOwnerWritable(root) {
  if (!fs.existsSync(root)) return;
  const status = fs.lstatSync(root);
  if (!status.isDirectory() || status.isSymbolicLink()) return;
  fs.chmodSync(root, 0o700);
  for (const name of fs.readdirSync(root))
    makeTreeOwnerWritable(path.join(root, name));
}

afterEach(() => {
  while (temporaryRoots.length > 0) {
    const root = temporaryRoots.pop();
    makeTreeOwnerWritable(root);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function align(value, multiple) {
  return Math.ceil(value / multiple) * multiple;
}

function makeThinMachO({
  fileType,
  dylibId = null,
  dylinker = null,
  dependencies = [],
  rpaths = [],
} = {}) {
  const stringCommand = (commandId, stringOffset, value) => {
    const string = Buffer.from(`${value}\0`, "utf8");
    const command = Buffer.alloc(align(stringOffset + string.length, 8));
    command.writeUInt32LE(commandId, 0);
    command.writeUInt32LE(command.length, 4);
    command.writeUInt32LE(stringOffset, 8);
    string.copy(command, stringOffset);
    return command;
  };
  const commands = [];
  const loadCommands = new Map([
    ["LC_LOAD_DYLIB", 0x0c],
    ["LC_LOAD_WEAK_DYLIB", 0x80000018],
  ]);
  for (const dependency of dependencies) {
    const row =
      typeof dependency === "string"
        ? { command: "LC_LOAD_DYLIB", installName: dependency }
        : dependency;
    commands.push(
      stringCommand(loadCommands.get(row.command), 24, row.installName),
    );
  }
  if (dylibId !== null) commands.push(stringCommand(0x0d, 24, dylibId));
  if (dylinker !== null) commands.push(stringCommand(0x0e, 12, dylinker));
  for (const rpath of rpaths)
    commands.push(stringCommand(0x8000001c, 12, rpath));
  const commandBytes = commands.reduce(
    (sum, command) => sum + command.length,
    0,
  );
  const output = Buffer.alloc(32 + commandBytes);
  output.writeUInt32LE(0xfeedfacf, 0);
  output.writeUInt32LE(0x0100000c, 4);
  output.writeUInt32LE(0, 8);
  output.writeUInt32LE(fileType, 12);
  output.writeUInt32LE(commands.length, 16);
  output.writeUInt32LE(commandBytes, 20);
  let cursor = 32;
  for (const command of commands) {
    command.copy(output, cursor);
    cursor += command.length;
  }
  return output;
}

function writeCanonical(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, canonicalJson(value));
}

function policyFixture() {
  return parseJsonStrict(
    fs.readFileSync(
      path.join(
        sourceRoot,
        "schemas/portable-engine-provenance-trust-policy-v1.json",
      ),
    ),
    "portable trust policy",
  );
}

function manifestFixture(runtimeBytes) {
  const runtimeDigest = rawDigest(runtimeBytes);
  const headerBytes = Buffer.from("header", "utf8");
  const hermesHeaderBytes = Buffer.from("hermes header", "utf8");
  const toolBytes = Buffer.from("tool", "utf8");
  const headerSet = {
    schema: "ibex/portable-engine-header-set/1",
    targetTriple: "aarch64-apple-darwin",
    includeRoots: ["include"],
    headers: [
      {
        path: "include/hermes/hermes.h",
        digest: rawDigest(hermesHeaderBytes),
        size: hermesHeaderBytes.length,
      },
      {
        path: "include/jsi/jsi.h",
        digest: rawDigest(headerBytes),
        size: headerBytes.length,
      },
    ],
  };
  const headerSetBytes = Buffer.from(canonicalJson(headerSet), "utf8");
  const manifest = {
    schema: "ibex/portable-engine-manifest/1",
    artifactId: "",
    artifactKind: "hermes",
    target: {
      triple: "aarch64-apple-darwin",
      structuralFeatures: ["dynamic-library", "framework"],
    },
    profile: {
      id: "source-patched",
      targetVariant: "default",
      configuration: "Release",
      debugger: false,
      hermesBytecodeVersion: 99,
      reviewedProfileIdentityDigest: semanticDigest(
        "fixture.reviewed-profile.v1",
        { fixture: true },
      ),
    },
    source: {
      artifact: "facebook/hermes",
      sourceCommit: "b".repeat(40),
      sourceRef: "0.13.0-stable",
      sourceVersion: "0.13.0",
      patchStackDigest: rawDigest(Buffer.from("patches", "utf8")),
    },
    build: {
      repository: "expo/ibex",
      sourceRevision,
      sourceTreeDigest: semanticDigest("fixture.source-tree.v1", {
        fixture: true,
      }),
      sourceRef: "refs/heads/main",
      publisherWorkflow: ".github/workflows/hermes-artifacts.yml",
      authorityDigests: [
        {
          path: "scripts/portable-engine-contract.mjs",
          digest: rawDigest(Buffer.from("authority", "utf8")),
        },
      ],
    },
    interface: {
      abiContractDigest: semanticDigest("fixture.abi.v1", { fixture: true }),
      requiredExportsDigest: semanticDigest("fixture.required.v1", {
        fixture: true,
      }),
      forbiddenExportsDigest: semanticDigest("fixture.forbidden.v1", {
        fixture: true,
      }),
      headerSetDigest: semanticDigest(
        "ibex.portable-engine-header-set.v1",
        headerSet,
      ),
      hostTools: [
        {
          role: "host-tool",
          path: "bin/hermesc",
          digest: rawDigest(toolBytes),
          compatibilityDigest: semanticDigest("fixture.compatibility.v1", {
            fixture: true,
          }),
        },
      ],
      loadableComponents: [
        {
          role: "runtime",
          path: runtimeComponent,
          digest: runtimeDigest,
          system: false,
        },
        { role: "runtime-dependency", name: systemDependency, system: true },
      ],
    },
    entries: [
      { kind: "directory", role: "metadata", path: "META-INF" },
      {
        kind: "directory",
        role: "metadata",
        path: "META-INF/authority",
      },
      {
        kind: "regular",
        role: "metadata",
        path: "META-INF/authority/header-set.json",
        digest: rawDigest(headerSetBytes),
        size: headerSetBytes.length,
        executable: false,
      },
      { kind: "directory", role: "host-tool", path: "bin" },
      {
        kind: "regular",
        role: "host-tool",
        path: "bin/hermesc",
        digest: rawDigest(toolBytes),
        size: toolBytes.length,
        executable: true,
      },
      { kind: "directory", role: "header", path: "include" },
      { kind: "directory", role: "header", path: "include/hermes" },
      {
        kind: "regular",
        role: "header",
        path: "include/hermes/hermes.h",
        digest: rawDigest(hermesHeaderBytes),
        size: hermesHeaderBytes.length,
        executable: false,
      },
      { kind: "directory", role: "header", path: "include/jsi" },
      {
        kind: "regular",
        role: "header",
        path: "include/jsi/jsi.h",
        digest: rawDigest(headerBytes),
        size: headerBytes.length,
        executable: false,
      },
      { kind: "directory", role: "runtime", path: "lib" },
      { kind: "directory", role: "runtime", path: "lib/hermesvm.framework" },
      {
        kind: "directory",
        role: "runtime",
        path: "lib/hermesvm.framework/Versions",
      },
      {
        kind: "directory",
        role: "runtime",
        path: "lib/hermesvm.framework/Versions/1",
      },
      {
        kind: "regular",
        role: "runtime",
        path: runtimeComponent,
        digest: runtimeDigest,
        size: runtimeBytes.length,
        executable: true,
      },
    ],
    runtimeComponent,
  };
  manifest.artifactId = semanticDigest(
    "ibex.portable-engine-manifest.v1",
    manifest,
    ["artifactId"],
  );
  return { headerSet, manifest };
}

function portableIdentity(manifest) {
  return {
    schema: "ibex/portable-engine-artifact-identity/1",
    artifactId: manifest.artifactId,
    artifactKind: "hermes",
    target: structuredClone(manifest.target),
    profile: {
      id: manifest.profile.id,
      targetVariant: manifest.profile.targetVariant,
      configuration: manifest.profile.configuration,
      debugger: manifest.profile.debugger,
      hermesBytecodeVersion: manifest.profile.hermesBytecodeVersion,
    },
    runtimeComponentDigest: manifest.interface.loadableComponents[0].digest,
    reviewedProfileIdentityDigest:
      manifest.profile.reviewedProfileIdentityDigest,
    interfaceContractDigest: semanticDigest(
      "ibex.portable-engine-interface.v1",
      manifest.interface,
    ),
  };
}

function fixture({
  rpaths,
  dependencies,
  targetRows,
  cargoRows,
  writeExecutable = true,
  executableRelativePath = "debug/ibex",
  evidenceTargetKind = "bin",
} = {}) {
  const root = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "ibex-post-link-test-")),
  );
  temporaryRoots.push(root);
  const repoRoot = path.join(root, "repo");
  fs.mkdirSync(path.join(repoRoot, "target", "debug"), { recursive: true });
  const runtimeBytes = makeThinMachO({
    fileType: 6,
    dylibId: runtimeInstallName,
    dependencies: [systemDependency],
  });
  const { headerSet, manifest } = manifestFixture(runtimeBytes);
  const artifactRoot = path.join(
    repoRoot,
    "target",
    "hermes-artifacts",
    manifest.artifactId,
  );
  const runtimePath = path.join(
    artifactRoot,
    "payload",
    ...runtimeComponent.split("/"),
  );
  writeCanonical(
    path.join(
      artifactRoot,
      "payload",
      "META-INF",
      "authority",
      "header-set.json",
    ),
    headerSet,
  );
  fs.mkdirSync(path.dirname(runtimePath), { recursive: true });
  fs.writeFileSync(runtimePath, runtimeBytes);
  const executablePath = path.join(
    repoRoot,
    "target",
    ...executableRelativePath.split("/"),
  );
  fs.mkdirSync(path.dirname(executablePath), { recursive: true });
  const defaultRpath = `@loader_path/${path
    .relative(
      path.dirname(executablePath),
      path.join(artifactRoot, "payload", "lib"),
    )
    .split(path.sep)
    .join("/")}`;
  const executableBytes = makeThinMachO({
    fileType: 2,
    dylinker: "/usr/lib/dyld",
    dependencies: dependencies ?? [runtimeInstallName, systemDependency],
    rpaths: rpaths ?? [defaultRpath],
  });
  if (writeExecutable)
    fs.writeFileSync(executablePath, executableBytes, { mode: 0o755 });
  const policy = policyFixture();
  const targetPolicy = policy.admittedTargets.find(
    (row) => row.triple === "aarch64-apple-darwin",
  );
  const policyDigest = semanticDigest(
    "ibex.portable-engine-provenance-trust-policy.v1",
    policy,
  );
  const manifestDigest = semanticDigest(
    "ibex.portable-engine-manifest-digest.v1",
    manifest,
  );
  const receipt = {
    schema: "ibex/portable-engine-installation-receipt/1",
    artifactId: manifest.artifactId,
    manifestDigest,
    archiveDigest: rawDigest(Buffer.from("archive", "utf8")),
    provenanceBundleDigest: rawDigest(Buffer.from("bundle", "utf8")),
    verificationPolicyDigest: policyDigest,
    repository: policy.enginePublisher.repository,
    publisherWorkflow: policy.enginePublisher.workflowPath,
    sourceRef: policy.enginePublisher.sourceRef,
    sourceRevision,
    runnerClass: policy.enginePublisher.runnerClass,
  };
  const receiptDigest = semanticDigest(
    "ibex.portable-engine-installation-receipt.v1",
    receipt,
  );
  const toolEntry = manifest.entries.find(
    (entry) => entry.path === "bin/hermesc",
  );
  const runtimeEntry = manifest.entries.find(
    (entry) => entry.path === runtimeComponent,
  );
  const tool = manifest.interface.hostTools[0];
  const build = {
    schema: "ibex/portable-engine-build-consumption/1",
    portable: portableIdentity(manifest),
    manifestDigest,
    installationReceiptDigest: receiptDigest,
    verificationPolicyDigest: policyDigest,
    target: structuredClone(manifest.target),
    ibexFeatures: [
      "capsec-conformance-observer",
      "cli-notify",
      "default",
      "host-http-server",
      "module-runner",
    ],
    headers: {
      headerSetDigest: manifest.interface.headerSetDigest,
      includeRoots: ["include"],
      files: structuredClone(headerSet.headers),
    },
    runtimeComponent: {
      path: runtimeEntry.path,
      digest: runtimeEntry.digest,
      size: runtimeEntry.size,
    },
    linkInputs: [
      {
        role: "runtime",
        path: runtimeEntry.path,
        digest: runtimeEntry.digest,
        size: runtimeEntry.size,
      },
    ],
    hostTools: [{ ...tool, size: toolEntry.size }],
    nonSystemLoadableDependencies: [],
    consumptionDigest: "",
  };
  build.consumptionDigest = semanticDigest(
    "ibex.portable-engine-build-consumption.v1",
    build,
    ["consumptionDigest"],
  );
  const defaultTargetRows = [
    {
      cargoTargetKind: evidenceTargetKind,
      cargoTargetKinds: [evidenceTargetKind],
      cargoTargetName: "ibex",
      logicalName: `${evidenceTargetKind}/ibex`,
      profileTest: evidenceTargetKind !== "bin",
      targetKind: evidenceTargetKind,
    },
  ];
  const enumeration = {
    schema: cargoExecutableEnumerationContractTestOnly.schema,
    mode: cargoExecutableEnumerationContractTestOnly.mode,
    package: {
      name: "ibex-runtime",
      version: "0.1.0",
      manifestPath: "Cargo.toml",
    },
    targetTriple: "aarch64-apple-darwin",
    ibexFeatures: [...build.ibexFeatures],
    cargoArguments: [
      "test",
      "--locked",
      "--no-run",
      "--all-targets",
      "--features",
      build.ibexFeatures.join(","),
      "--message-format=json",
    ],
    targets: targetRows ?? defaultTargetRows,
  };
  const packageId = "path+file:///fixture#ibex-runtime@0.1.0";
  const defaultCargoRows = [
    {
      reason: "compiler-artifact",
      package_id: packageId,
      manifest_path: path.join(repoRoot, "Cargo.toml"),
      target: { name: "ibex", kind: [evidenceTargetKind] },
      profile: { test: evidenceTargetKind !== "bin" },
      executable: executablePath,
    },
  ];
  const selectedCargoRows =
    typeof cargoRows === "function"
      ? cargoRows({ executablePath, repoRoot })
      : (cargoRows ?? defaultCargoRows);
  const cargoMessages = [
    ...selectedCargoRows,
    { reason: "build-finished", success: true },
  ];
  const inputs = {
    buildConsumptionPath: path.join(
      repoRoot,
      "target",
      "fixture",
      "build.json",
    ),
    cargoMessagesPath: path.join(repoRoot, "target", "fixture", "cargo.jsonl"),
  };
  writeCanonical(inputs.buildConsumptionPath, build);
  const enumerationPath = path.join(
    repoRoot,
    ...cargoExecutableEnumerationContractTestOnly.path.split("/"),
  );
  writeCanonical(enumerationPath, enumeration);
  fs.writeFileSync(
    inputs.cargoMessagesPath,
    `${cargoMessages.map((row) => JSON.stringify(row)).join("\n")}\n`,
  );
  const outputDirectory = path.join(
    repoRoot,
    "target",
    "portable-engine-post-link",
    build.consumptionDigest,
  );
  const options = {
    archiveDigest: receipt.archiveDigest,
    ...inputs,
    expectedSourceRevision: sourceRevision,
    repoRoot,
  };
  const verifyStore = async (observed) => {
    assert.equal(observed.artifactId, manifest.artifactId);
    assert.equal(observed.expectedSourceRevision, sourceRevision);
    assert.equal(observed.archiveDigest, receipt.archiveDigest);
    assert.equal(observed.repoRoot, repoRoot);
    return {
      artifactRoot,
      manifest,
      context: {
        policy,
        targetPolicy,
        readRevisionFile(relativePath) {
          if (
            relativePath === cargoExecutableEnumerationContractTestOnly.path
          ) {
            return fs.readFileSync(enumerationPath);
          }
          return fs.readFileSync(path.join(sourceRoot, relativePath));
        },
      },
      transport: {
        archive: { digest: receipt.archiveDigest },
        receipt,
      },
    };
  };
  return {
    artifactRoot,
    build,
    cargoMessages,
    defaultRpath,
    enumeration,
    enumerationPath,
    executableBytes,
    executablePath,
    manifest,
    options,
    outputDirectory,
    repoRoot,
    runtimeBytes,
    runtimePath,
    verifyStore,
  };
}

async function verify(subject, dependencies = {}) {
  return await verifyPortableEnginePostLinkTestOnly(subject.options, {
    verifyStore: dependencies.verifyStore ?? subject.verifyStore,
    afterExecutableRead: dependencies.afterExecutableRead,
  });
}

async function rejectsWithoutOutput(subject, pattern, dependencies = {}) {
  await assert.rejects(verify(subject, dependencies), pattern);
  assert.equal(fs.existsSync(subject.outputDirectory), false);
}

function rewriteCargoMessages(subject, rows) {
  subject.cargoMessages = rows;
  fs.writeFileSync(
    subject.options.cargoMessagesPath,
    `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`,
  );
}

describe("portable macOS post-link evidence", () => {
  test("checked Cargo executable authority matches current metadata", () => {
    const checkedPath = path.join(
      sourceRoot,
      ...cargoExecutableEnumerationContractTestOnly.path.split("/"),
    );
    const checked = fs.readFileSync(checkedPath);
    const generated = generatePortableEngineCargoExecutableSet();
    assert.equal(checked.toString("utf8"), canonicalJson(generated));
    assert.deepEqual(
      generated.targets.filter(
        (row) =>
          row.cargoTargetKind === "example" &&
          ["module_runner_spike", "module_runner_test262_spike"].includes(
            row.cargoTargetName,
          ),
      ),
      [],
      "inactive Cargo metadata required-features must omit gated examples",
    );
  });

  test("emits one canonical schema-checked result after exact Cargo and loader resolution", async () => {
    const subject = fixture();
    const result = await verify(subject);
    assert.equal(result.records.length, 1);
    assert.deepEqual(fs.readdirSync(subject.outputDirectory).sort(), [
      "0000.json",
      "COMPLETE.json",
    ]);
    const bytes = fs.readFileSync(
      path.join(subject.outputDirectory, "0000.json"),
    );
    const evidence = parseJsonStrict(bytes, "post-link evidence");
    assertCanonicalJsonBytes(bytes, evidence, "post-link evidence");
    assert.equal(evidence.executable.logicalName, "bin/ibex");
    assert.equal(
      evidence.executable.digest,
      rawDigest(subject.executableBytes),
    );
    assert.equal(
      evidence.audit.dependencies[0].resolution.class,
      "platform-system",
    );
    assert.equal(
      evidence.audit.dependencies[1].resolution.class,
      "portable-component",
    );
    assert.equal(
      evidence.payloadRevalidation.transportProvenanceReverified,
      true,
    );
    assert.equal(canonicalJson(evidence).includes(subject.repoRoot), false);
    assert.equal(
      evidence.verificationDigest,
      semanticDigest(
        "ibex.portable-engine-post-link-verification.v1",
        evidence,
        ["verificationDigest"],
      ),
    );
    const completionBytes = fs.readFileSync(
      path.join(subject.outputDirectory, "COMPLETE.json"),
    );
    const completion = parseJsonStrict(completionBytes, "post-link completion");
    assertCanonicalJsonBytes(
      completionBytes,
      completion,
      "post-link completion",
    );
    assert.equal(completion.results.length, 1);
    assert.equal(completion.results[0].evidenceDigest, rawDigest(bytes));
    assert.equal(result.completion.setDigest, completion.setDigest);
    assert.equal(canonicalJson(completion).includes(subject.repoRoot), false);
    assert.equal(fs.statSync(subject.outputDirectory).mode & 0o777, 0o555);
    assert.equal(
      fs.statSync(path.join(subject.outputDirectory, "0000.json")).mode & 0o777,
      0o444,
    );
    assert.equal(
      fs.statSync(path.join(subject.outputDirectory, "COMPLETE.json")).mode &
        0o777,
      0o444,
    );
  });

  test("rejects a missing final executable before publishing evidence", async () => {
    const subject = fixture({ writeExecutable: false });
    await rejectsWithoutOutput(subject, /Cargo executable is missing/u);
  });

  test("rejects mutation of the open executable object", async () => {
    const subject = fixture();
    await rejectsWithoutOutput(subject, /changed while it was being read/u, {
      afterExecutableRead({ filePath }) {
        fs.appendFileSync(filePath, Buffer.from([0]));
      },
    });
  });

  test("rejects atomic path replacement while an executable is pinned", async () => {
    const subject = fixture();
    await rejectsWithoutOutput(
      subject,
      /file object changed|path no longer names the opened file/u,
      {
        afterExecutableRead({ filePath }) {
          const replacement = `${filePath}.replacement`;
          fs.writeFileSync(replacement, subject.executableBytes, {
            mode: 0o755,
          });
          fs.renameSync(replacement, filePath);
        },
      },
    );
  });

  test("rejects absolute RPATHs", async () => {
    const subject = fixture({ rpaths: ["/tmp/hermes"] });
    await rejectsWithoutOutput(subject, /non-loader-relative RPATH/u);
  });

  test("rejects a wrong existing Hermes resolution", async () => {
    const subject = fixture({ rpaths: ["@loader_path/../wrong/payload/lib"] });
    const wrongRuntime = path.join(
      subject.repoRoot,
      "target",
      "wrong",
      "payload",
      "lib",
      "hermesvm.framework",
      "Versions",
      "1",
      "hermesvm",
    );
    fs.mkdirSync(path.dirname(wrongRuntime), { recursive: true });
    fs.writeFileSync(wrongRuntime, subject.runtimeBytes);
    await rejectsWithoutOutput(
      subject,
      /resolves outside the selected artifact payload/u,
    );
  });

  test("rejects an ambiguous correct-plus-local Hermes resolution", async () => {
    const baseline = fixture();
    const subject = fixture({
      rpaths: [baseline.defaultRpath, "@loader_path/../decoy/payload/lib"],
    });
    const decoyRuntime = path.join(
      subject.repoRoot,
      "target",
      "decoy",
      "payload",
      "lib",
      "hermesvm.framework",
      "Versions",
      "1",
      "hermesvm",
    );
    fs.mkdirSync(path.dirname(decoyRuntime), { recursive: true });
    fs.writeFileSync(decoyRuntime, subject.runtimeBytes);
    await rejectsWithoutOutput(
      subject,
      /resolves outside the selected artifact payload/u,
    );
  });

  test("rejects the wrong-depth target/debug RPATH and decoy for a deps executable", async () => {
    const subject = fixture({
      executableRelativePath: "debug/deps/ibex-fixture",
      evidenceTargetKind: "test",
    });
    const wrongDepthRpath = `@loader_path/../hermes-artifacts/${subject.manifest.artifactId}/payload/lib`;
    subject.executableBytes = makeThinMachO({
      fileType: 2,
      dylinker: "/usr/lib/dyld",
      dependencies: [runtimeInstallName, systemDependency],
      rpaths: [subject.defaultRpath, wrongDepthRpath],
    });
    fs.writeFileSync(subject.executablePath, subject.executableBytes, {
      mode: 0o755,
    });
    const wrongRuntime = path.join(
      subject.repoRoot,
      "target",
      "debug",
      "hermes-artifacts",
      subject.manifest.artifactId,
      "payload",
      ...runtimeComponent.split("/"),
    );
    fs.mkdirSync(path.dirname(wrongRuntime), { recursive: true });
    fs.writeFileSync(wrongRuntime, subject.runtimeBytes);
    await rejectsWithoutOutput(
      subject,
      /resolves outside the selected artifact payload/u,
    );
  });

  test("rejects duplicate loader spellings that both resolve to selected Hermes", async () => {
    const subject = fixture();
    const duplicate = subject.defaultRpath.replace(
      "@loader_path",
      "@executable_path",
    );
    const duplicateSubject = fixture({
      rpaths: [subject.defaultRpath, duplicate],
    });
    await rejectsWithoutOutput(
      duplicateSubject,
      /exactly one existing RPATH resolution; found 2/u,
    );
  });

  test("rejects a build record bound to the wrong artifact", async () => {
    const subject = fixture();
    subject.build.portable.artifactId = semanticDigest(
      "fixture.wrong-artifact.v1",
      { wrong: true },
    );
    subject.build.consumptionDigest = semanticDigest(
      "ibex.portable-engine-build-consumption.v1",
      subject.build,
      ["consumptionDigest"],
    );
    writeCanonical(subject.options.buildConsumptionPath, subject.build);
    await rejectsWithoutOutput(
      subject,
      /Expected values to be strictly equal|artifact IDs differ|wrong checkout-local artifact root/u,
      {
        verifyStore: async () => ({
          ...(await subject.verifyStore({
            artifactId: subject.manifest.artifactId,
            expectedSourceRevision: sourceRevision,
            archiveDigest: subject.options.archiveDigest,
            repoRoot: subject.repoRoot,
          })),
        }),
      },
    );
  });

  test("rejects a changed authenticated header-set authority", async () => {
    const subject = fixture();
    const headerSetPath = path.join(
      subject.artifactRoot,
      "payload",
      "META-INF",
      "authority",
      "header-set.json",
    );
    const changed = parseJsonStrict(
      fs.readFileSync(headerSetPath),
      "fixture header set",
    );
    changed.includeRoots = ["include/jsi"];
    writeCanonical(headerSetPath, changed);
    await rejectsWithoutOutput(
      subject,
      /header-set authority bytes do not join the portable manifest/u,
    );
  });

  test("rejects an incomplete bounded Cargo executable set", async () => {
    const subject = fixture();
    subject.enumeration.targets.push({
      cargoTargetKind: "test",
      cargoTargetKinds: ["test"],
      cargoTargetName: "integration",
      logicalName: "test/integration",
      profileTest: true,
      targetKind: "test",
    });
    writeCanonical(subject.enumerationPath, subject.enumeration);
    await rejectsWithoutOutput(
      subject,
      /missing final executables: test\/integration/u,
    );
  });

  test("rejects an extra root-package final target", async () => {
    const subject = fixture();
    const expected = subject.cargoMessages[0];
    rewriteCargoMessages(subject, [
      expected,
      {
        ...expected,
        target: { name: "undeclared", kind: ["test"] },
        profile: { test: true },
      },
      { reason: "build-finished", success: true },
    ]);
    await rejectsWithoutOutput(
      subject,
      /unexpected final executable test\/undeclared\/true/u,
    );
  });

  test("rejects a duplicate root-package final target", async () => {
    const subject = fixture();
    const expected = subject.cargoMessages[0];
    rewriteCargoMessages(subject, [
      expected,
      structuredClone(expected),
      { reason: "build-finished", success: true },
    ]);
    await rejectsWithoutOutput(
      subject,
      /duplicate final executable bin\/ibex/u,
    );
  });

  test("rejects distinct Cargo identities sharing one executable path", async () => {
    const targetRows = ["alpha", "beta"].map((name) => ({
      cargoTargetKind: "test",
      cargoTargetKinds: ["test"],
      cargoTargetName: name,
      logicalName: `test/${name}`,
      profileTest: true,
      targetKind: "test",
    }));
    const subject = fixture({
      evidenceTargetKind: "test",
      executableRelativePath: "debug/deps/alpha-fixture",
      targetRows,
      cargoRows: ({ executablePath, repoRoot }) =>
        targetRows.map((row) => ({
          reason: "compiler-artifact",
          package_id: "path+file:///fixture#ibex-runtime@0.1.0",
          manifest_path: path.join(repoRoot, "Cargo.toml"),
          target: { name: row.cargoTargetName, kind: ["test"] },
          profile: { test: true },
          executable: executablePath,
        })),
    });
    await rejectsWithoutOutput(subject, /path is shared/u);
  });

  test("rejects distinct Cargo paths aliasing one executable file object", async () => {
    const targetRows = ["alpha", "beta"].map((name) => ({
      cargoTargetKind: "test",
      cargoTargetKinds: ["test"],
      cargoTargetName: name,
      logicalName: `test/${name}`,
      profileTest: true,
      targetKind: "test",
    }));
    let aliasPath;
    const subject = fixture({
      evidenceTargetKind: "test",
      executableRelativePath: "debug/deps/alpha-fixture",
      targetRows,
      cargoRows: ({ executablePath, repoRoot }) => {
        aliasPath = path.join(path.dirname(executablePath), "beta-fixture");
        return targetRows.map((row, index) => ({
          reason: "compiler-artifact",
          package_id: "path+file:///fixture#ibex-runtime@0.1.0",
          manifest_path: path.join(repoRoot, "Cargo.toml"),
          target: { name: row.cargoTargetName, kind: ["test"] },
          profile: { test: true },
          executable: index === 0 ? executablePath : aliasPath,
        }));
      },
    });
    fs.linkSync(subject.executablePath, aliasPath);
    await rejectsWithoutOutput(subject, /file object is shared/u);
  });

  test("rejects an ambiguous Cargo target-kind identity", async () => {
    const subject = fixture();
    const expected = subject.cargoMessages[0];
    rewriteCargoMessages(subject, [
      { ...expected, target: { name: "ibex", kind: ["bin", "test"] } },
      { reason: "build-finished", success: true },
    ]);
    await rejectsWithoutOutput(subject, /ambiguous final target kind/u);
  });

  test("rejects an unmatched root-package executable message", async () => {
    const subject = fixture();
    const expected = subject.cargoMessages[0];
    rewriteCargoMessages(subject, [
      {
        ...expected,
        target: { name: "unmatched", kind: ["custom-build"] },
      },
      { reason: "build-finished", success: true },
    ]);
    await rejectsWithoutOutput(subject, /unmatched root-package executable/u);
  });

  test("rejects unexpected and duplicate Hermes load commands", async () => {
    const subject = fixture({
      dependencies: [runtimeInstallName, runtimeInstallName, systemDependency],
    });
    await rejectsWithoutOutput(
      subject,
      /duplicate load-dylib dependency commands|exactly one selected Hermes runtime/u,
    );
  });
});
