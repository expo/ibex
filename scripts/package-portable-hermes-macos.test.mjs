import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  assertIJson,
  buildDeterministicUstarGzip,
  canonicalJson,
  deterministicUstarGzipSize,
  deterministicUstarSize,
  inspectUstarGzip,
  parseHermesBytecode,
  parseJsonStrict,
  parseMachO,
  rawDigest,
} from "./portable-engine-contract.mjs";
import {
  REQUIRED_BUILD_AUTHORITY_PATHS,
  buildPortableHermesMacosPackage,
  derivePinnedHermesSource,
  deriveReviewedSourceAuthorities,
} from "./package-portable-hermes-macos.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoots = [];
after(() => {
  for (const root of temporaryRoots) fs.rmSync(root, { recursive: true, force: true });
});

function makeTemporaryRoot(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  temporaryRoots.push(root);
  return root;
}

function align(value, multiple) {
  return Math.ceil(value / multiple) * multiple;
}

function makeThinMachO({
  architecture = "arm64",
  cpuSubtype = architecture === "arm64" ? 0 : 3,
  fileType = 6,
  dylibId = fileType === 6 ? "@rpath/hermesvm.framework/Versions/1/hermesvm" : null,
  dylinker = fileType === 2 ? "/usr/lib/dyld" : null,
  dependencies = [],
  symbols = ["_symbol"],
} = {}) {
  const cpu = architecture === "arm64" ? 0x0100000c : 0x01000007;
  const makeStringCommand = (commandId, nameOffset, value) => {
    const name = Buffer.from(`${value}\0`, "utf8");
    const command = Buffer.alloc(align(nameOffset + name.length, 8));
    command.writeUInt32LE(commandId, 0);
    command.writeUInt32LE(command.length, 4);
    command.writeUInt32LE(nameOffset, 8);
    name.copy(command, nameOffset);
    return command;
  };
  const dependencyCommands = dependencies.map((dependency) =>
    makeStringCommand(0x0c, 24, dependency),
  );
  const roleCommands = [];
  if (dylibId !== null) roleCommands.push(makeStringCommand(0x0d, 24, dylibId));
  if (dylinker !== null) roleCommands.push(makeStringCommand(0x0e, 12, dylinker));
  const symtabCommand = Buffer.alloc(24);
  const commands = [...dependencyCommands, ...roleCommands, symtabCommand];
  const commandBytes = commands.reduce((sum, command) => sum + command.length, 0);
  const symbolOffset = 32 + commandBytes;
  const stringParts = [Buffer.from([0])];
  const stringIndexes = [];
  let stringSize = 1;
  for (const symbol of symbols) {
    const bytes = Buffer.from(`${symbol}\0`, "utf8");
    stringIndexes.push(stringSize);
    stringParts.push(bytes);
    stringSize += bytes.length;
  }
  const stringTable = Buffer.concat(stringParts);
  const stringOffset = symbolOffset + symbols.length * 16;
  symtabCommand.writeUInt32LE(0x02, 0);
  symtabCommand.writeUInt32LE(24, 4);
  symtabCommand.writeUInt32LE(symbolOffset, 8);
  symtabCommand.writeUInt32LE(symbols.length, 12);
  symtabCommand.writeUInt32LE(stringOffset, 16);
  symtabCommand.writeUInt32LE(stringTable.length, 20);
  const output = Buffer.alloc(stringOffset + stringTable.length);
  output.writeUInt32LE(0xfeedfacf, 0);
  output.writeUInt32LE(cpu, 4);
  output.writeUInt32LE(cpuSubtype, 8);
  output.writeUInt32LE(fileType, 12);
  output.writeUInt32LE(commands.length, 16);
  output.writeUInt32LE(commandBytes, 20);
  let cursor = 32;
  for (const command of commands) {
    command.copy(output, cursor);
    cursor += command.length;
  }
  for (let index = 0; index < symbols.length; index += 1) {
    const row = symbolOffset + index * 16;
    output.writeUInt32LE(stringIndexes[index], row);
    output[row + 4] = 0x0f; // N_EXT | N_SECT
    output[row + 5] = 1;
    output.writeBigUInt64LE(BigInt(index + 1), row + 8);
  }
  stringTable.copy(output, stringOffset);
  return output;
}

function makeFatMachO(x86, arm64) {
  const tableEnd = 8 + 2 * 20;
  const x86Offset = align(tableEnd, 64);
  const armOffset = align(x86Offset + x86.length, 64);
  const output = Buffer.alloc(armOffset + arm64.length);
  output.writeUInt32BE(0xcafebabe, 0);
  output.writeUInt32BE(2, 4);
  output.writeUInt32BE(0x01000007, 8);
  output.writeUInt32BE(x86.readUInt32LE(8), 12);
  output.writeUInt32BE(x86Offset, 16);
  output.writeUInt32BE(x86.length, 20);
  output.writeUInt32BE(6, 24);
  output.writeUInt32BE(0x0100000c, 28);
  output.writeUInt32BE(arm64.readUInt32LE(8), 32);
  output.writeUInt32BE(armOffset, 36);
  output.writeUInt32BE(arm64.length, 40);
  output.writeUInt32BE(6, 44);
  x86.copy(output, x86Offset);
  arm64.copy(output, armOffset);
  return output;
}

function makeHbc(version = 99, size = 64) {
  const output = Buffer.alloc(size);
  output.writeBigUInt64LE(0x1f1903c103bc1fc6n, 0);
  output.writeUInt32LE(version, 8);
  output.writeUInt32LE(size, 32);
  return output;
}

function copyFile(sourceRoot, destinationRoot, relativePath) {
  const source = path.join(sourceRoot, relativePath);
  const destination = path.join(destinationRoot, relativePath);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
  fs.chmodSync(destination, fs.statSync(source).mode & 0o777);
}

function runGit(root, args) {
  const result = spawnSync("git", ["-C", root, ...args], {
    env: {
      ...process.env,
      LC_ALL: "C",
      GIT_AUTHOR_NAME: "Portable Engine Test",
      GIT_AUTHOR_EMAIL: "portable-engine@example.invalid",
      GIT_COMMITTER_NAME: "Portable Engine Test",
      GIT_COMMITTER_EMAIL: "portable-engine@example.invalid",
    },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function sourceAuthorityFixture(testRepo) {
  const rows = [];
  const bytesByPath = new Map();
  for (const relativePath of REQUIRED_BUILD_AUTHORITY_PATHS) {
    const bytes = fs.readFileSync(path.join(testRepo, relativePath));
    rows.push({ path: relativePath, digest: rawDigest(bytes) });
    bytesByPath.set(relativePath, bytes);
  }
  return deriveReviewedSourceAuthorities(testRepo, runGit(testRepo, ["rev-parse", "HEAD"]), {
    rows,
    bytesByPath,
  });
}

function setupProducerFixture() {
  const root = makeTemporaryRoot("ibex-portable-producer-test-");
  const testRepo = path.join(root, "repo");
  const cache = path.join(root, "cache");
  fs.mkdirSync(testRepo);
  for (const relativePath of REQUIRED_BUILD_AUTHORITY_PATHS) copyFile(repoRoot, testRepo, relativePath);
  for (const name of fs.readdirSync(path.join(repoRoot, "patches/hermes"))) {
    if (name.endsWith(".patch")) copyFile(repoRoot, testRepo, `patches/hermes/${name}`);
  }
  runGit(testRepo, ["init", "-b", "main"]);
  runGit(testRepo, ["add", "."]);
  runGit(testRepo, ["commit", "-m", "portable producer fixture"]);

  const policy = JSON.parse(
    fs.readFileSync(path.join(testRepo, "schemas/portable-engine-provenance-trust-policy-v1.json"), "utf8"),
  );
  const appleDependencies = policy.platformSystemDependencies.apple;
  const runtimeArm = makeThinMachO({
    dependencies: appleDependencies,
    symbols: ["_makeHermesRuntime", "_ex_hermes_vm_current_package_id", "_safe_export"],
  });
  const runtimeX86 = makeThinMachO({
    architecture: "x86_64",
    dependencies: appleDependencies,
    symbols: ["_makeHermesRuntime", "_ex_hermes_vm_current_package_id"],
  });
  const runtime = makeFatMachO(runtimeX86, runtimeArm);
  const framework = path.join(cache, "hermesvm.framework");
  fs.mkdirSync(path.join(framework, "Versions/1/Resources"), { recursive: true });
  fs.writeFileSync(path.join(framework, "Versions/1/hermesvm"), runtime, { mode: 0o755 });
  fs.writeFileSync(path.join(framework, "Versions/1/Resources/Info.plist"), "<plist/>\n");
  fs.symlinkSync("1", path.join(framework, "Versions/Current"));
  fs.symlinkSync("Versions/Current/hermesvm", path.join(framework, "hermesvm"));
  fs.symlinkSync("Versions/Current/Resources", path.join(framework, "Resources"));
  fs.mkdirSync(path.join(cache, "include/jsi"), { recursive: true });
  fs.writeFileSync(path.join(cache, "include/jsi/jsi.h"), "#pragma once\n");
  fs.mkdirSync(path.join(cache, "bin"), { recursive: true });
  const hermesc = makeThinMachO({
    fileType: 2,
    dependencies: [
      "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
      "/usr/lib/libSystem.B.dylib",
      "/usr/lib/libc++.1.dylib",
    ],
    symbols: ["_main"],
  });
  fs.writeFileSync(path.join(cache, "bin/hermesc"), hermesc, { mode: 0o755 });

  const authorities = sourceAuthorityFixture(testRepo);
  const pinnedSource = derivePinnedHermesSource(
    fs.readFileSync(path.join(testRepo, "scripts/hermes-version.sh")),
  );
  const identity = {
    artifact: "facebook/hermes",
    patchApplicationAuthorityDigest: authorities.patchApplicationAuthorityDigest,
    patchIdentityAuthorityDigest: authorities.patchIdentityAuthorityDigest,
    patchStackDigest: authorities.patchStackDigest,
    sourceBuildAuthorityDigests: authorities.sourceBuildAuthorityDigests,
    sourceCommit: pinnedSource.sourceCommit,
    sourceRef: pinnedSource.sourceRef,
    sourceVersion: pinnedSource.sourceVersion,
  };
  const prefix = (digest) => digest.slice("sha256-".length, "sha256-".length + 12);
  const cacheKey =
    `${identity.sourceCommit.slice(0, 12)}` +
    `-p${prefix(identity.patchStackDigest)}` +
    `-ba${prefix(identity.sourceBuildAuthorityDigests["scripts/build-hermes.sh"])}` +
    `-bl${prefix(identity.sourceBuildAuthorityDigests["scripts/build-hermes-linux.sh"])}` +
    `-a${prefix(identity.patchApplicationAuthorityDigest)}` +
    `-i${prefix(identity.patchIdentityAuthorityDigest)}` +
    "-oapple";
  const receipt = {
    schema: "ibex/hermes-profile-provenance-receipt/2",
    profileId: "source-patched",
    targetVariant: "default",
    artifact: {
      binaryDigest: rawDigest(runtime),
      fileName: "hermesvm",
      targetArchitecture: "universal",
    },
    origin: {
      kind: "source-patched-cache",
      cacheKey,
      reviewedProfileIdentity: identity,
    },
  };
  fs.writeFileSync(path.join(cache, "hermes-profile-provenance.json"), `${JSON.stringify(receipt, null, 2)}\n`);
  return {
    root,
    testRepo,
    cache,
    options: {
      repoRoot: testRepo,
      frameworkPath: framework,
      includePath: path.join(cache, "include"),
      hermescPath: path.join(cache, "bin/hermesc"),
      receiptPath: path.join(cache, "hermes-profile-provenance.json"),
      sourceRef: "refs/heads/main",
      expectedSourceRevision: runGit(testRepo, ["rev-parse", "HEAD"]),
    },
  };
}

function fixtureRunner({ args, cwd }) {
  if (args.length === 1 && args[0] === "--version") {
    return {
      status: 0,
      stdout: Buffer.from("Hermes JavaScript compiler.\n  HBC bytecode version: 99\n", "utf8"),
      stderr: Buffer.alloc(0),
    };
  }
  assert.deepEqual(args, ["-emit-binary", "-out", "output/smoke.hbc", "input/smoke.js"]);
  fs.writeFileSync(path.join(cwd, "output/smoke.hbc"), makeHbc());
  return { status: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
}

function fixtureDependencies(runHostTool = fixtureRunner) {
  return {
    physicalHost: { platform: "darwin", architecture: "arm64" },
    runHostTool,
    runRuntimeHbcProbe: () => ({ version: 99 }),
  };
}

describe("portable engine production contract", () => {
  test("strict JSON and JCS reject ambiguous or non-JSON values", () => {
    assert.throws(() => parseJsonStrict(Buffer.from('{"a":1,"a":2}')), /duplicate JSON object key/u);
    assert.throws(() => parseJsonStrict(Buffer.from('{"a":1} trailing')), /trailing|invalid JSON token/u);
    assert.equal(canonicalJson({ z: 0, a: [true, "x"] }), '{"a":[true,"x"],"z":0}');
    assert.throws(() => assertIJson(undefined), /not representable/u);
    assert.throws(() => assertIJson(1n), /not representable/u);
    assert.throws(() => assertIJson(new Date()), /non-plain/u);
    const cyclic = {};
    cyclic.self = cyclic;
    assert.throws(() => assertIJson(cyclic), /cyclic/u);
    const sparse = [];
    sparse.length = 1;
    assert.throws(() => assertIJson(sparse), /sparse/u);
  });

  test("Mach-O parsing selects arm64 and reads bytes, not rendered tool output", () => {
    const arm = makeThinMachO({
      dependencies: ["/usr/lib/libSystem.B.dylib"],
      symbols: ["_makeHermesRuntime", "_ex_hermes_vm_current_package_id"],
    });
    const fat = makeFatMachO(makeThinMachO({ architecture: "x86_64" }), arm);
    const parsed = parseMachO(fat, { architecture: "arm64" });
    assert.equal(parsed.container, "fat");
    assert.equal(parsed.cpuSubtype, 0);
    assert.equal(parsed.fileType, 6);
    assert.equal(parsed.dylibId, "@rpath/hermesvm.framework/Versions/1/hermesvm");
    assert.equal(parsed.dylinker, null);
    assert.deepEqual(parsed.containerArchitectures, ["arm64", "x86_64"]);
    assert.deepEqual(parsed.dependencies, ["/usr/lib/libSystem.B.dylib"]);
    assert.deepEqual(
      parsed.externalDefinedSymbolNames.map((value) => value.toString("utf8")),
      ["_ex_hermes_vm_current_package_id", "_makeHermesRuntime"],
    );
    const corrupted = Buffer.from(fat);
    corrupted.writeUInt32BE(0xfffffff0, 40);
    assert.throws(() => parseMachO(corrupted), /outside|range|slice/u);

    const mismatchedSubtype = Buffer.from(fat);
    mismatchedSubtype.writeUInt32BE(1, 32);
    assert.throws(() => parseMachO(mismatchedSubtype), /subtype/u);

    const unsupportedSubtype = Buffer.from(arm);
    unsupportedSubtype.writeUInt32LE(2, 8);
    assert.throws(() => parseMachO(unsupportedSubtype), /unsupported CPU subtype/u);

    const misaligned = Buffer.from(fat);
    misaligned.writeUInt32BE(30, 44);
    assert.throws(() => parseMachO(misaligned), /not aligned/u);

    const paddedDependency = makeThinMachO({ dependencies: ["/usr/lib/libSystem.B.dylib"] });
    paddedDependency[32 + 24 + Buffer.byteLength("/usr/lib/libSystem.B.dylib") + 1] = 1;
    assert.throws(() => parseMachO(paddedDependency), /non-zero string padding/u);
  });

  test("Hermes bytecode binds magic, version, and declared file length", () => {
    assert.deepEqual(parseHermesBytecode(makeHbc()), { version: 99, fileLength: 64 });
    const wrongMagic = makeHbc();
    wrongMagic[0] ^= 1;
    assert.throws(() => parseHermesBytecode(wrongMagic), /magic/u);
    const wrongLength = makeHbc();
    wrongLength.writeUInt32LE(65, 32);
    assert.throws(() => parseHermesBytecode(wrongLength), /length/u);
  });

  test("deterministic ustar+gzip has exact members and a closed symlink graph", () => {
    const members = [
      { path: "META-INF", kind: "directory" },
      {
        path: "META-INF/portable-engine-manifest.json",
        kind: "regular",
        bytes: Buffer.from("{}"),
        executable: false,
      },
      { path: "payload", kind: "directory" },
      { path: "payload/lib", kind: "directory" },
      { path: "payload/lib/runtime", kind: "regular", bytes: Buffer.from("runtime"), executable: true },
      { path: "payload/lib/current", kind: "symlink", target: "runtime" },
    ];
    const first = buildDeterministicUstarGzip(members);
    const second = buildDeterministicUstarGzip(members);
    assert(first.equals(second));
    assert.equal(first.length, deterministicUstarGzipSize(members));
    assert(deterministicUstarSize(members) > 0);
    assert.deepEqual(
      inspectUstarGzip(first).map(({ path: pathname, kind }) => [pathname, kind]),
      [
        ["META-INF", "directory"],
        ["META-INF/portable-engine-manifest.json", "regular"],
        ["payload", "directory"],
        ["payload/lib", "directory"],
        ["payload/lib/current", "symlink"],
        ["payload/lib/runtime", "regular"],
      ],
    );
    const cyclic = members.concat({ path: "payload/loop", kind: "symlink", target: "loop" });
    assert.throws(() => inspectUstarGzip(buildDeterministicUstarGzip(cyclic)), /cycle/u);

    const deep = members.concat(
      { path: "payload/depth-a", kind: "symlink", target: "depth-b" },
      { path: "payload/depth-b", kind: "symlink", target: "lib/runtime" },
    );
    assert.throws(
      () => inspectUstarGzip(buildDeterministicUstarGzip(deep), { maxSymlinkDepth: 1 }),
      /symlink resolution exceeds 1/u,
    );
  });
});

describe("diagnostic macOS portable package", () => {
  test("produces one deterministic closed package and omits CLI/iOS inputs", () => {
    const fixture = setupProducerFixture();
    const first = buildPortableHermesMacosPackage(fixture.options, fixtureDependencies());
    const second = buildPortableHermesMacosPackage(fixture.options, fixtureDependencies());
    assert(first.archiveBytes.equals(second.archiveBytes));
    assert.equal(first.manifest.artifactId, second.manifest.artifactId);
    const paths = first.manifest.entries.map((entry) => entry.path);
    assert(paths.includes("lib/hermesvm.framework/Versions/1/hermesvm"));
    assert(paths.includes("bin/hermesc"));
    assert(paths.includes("share/hermes/profile-provenance.json"));
    assert(paths.includes("share/compatibility/host-tools/input/smoke.js"));
    assert(!paths.some((pathname) => pathname.includes("xcframework")));
    assert(!paths.includes("bin/hermes"));
    assert.deepEqual(
      first.manifest.build.authorityDigests.map(({ path: pathname }) => pathname),
      REQUIRED_BUILD_AUTHORITY_PATHS,
    );
    assert(paths.includes("META-INF/authority/source-tree/commit.content"));
    assert(paths.includes("META-INF/authority/source-tree/tree.content"));
    const archivePaths = inspectUstarGzip(first.archiveBytes).map(({ path: pathname }) => pathname);
    assert(
      archivePaths.every(
        (pathname) =>
          pathname === "payload" ||
          pathname.startsWith("payload/") ||
          pathname === "META-INF" ||
          pathname === "META-INF/portable-engine-manifest.json",
      ),
    );
    assert.equal(first.documents.trustPolicy.portableArtifactAcceptanceEnabled, false);
    assert.deepEqual(
      first.documents.hostToolCompatibility.invocations.map((invocation) => invocation.id),
      ["compile-smoke", "version"],
    );
    assert.equal(first.documents.hostToolCompatibility.invocations[0].bytecodeOutputs[0].bytecodeVersion, 99);
  });

  test("rejects receipt and host-tool version or bytecode tampering", () => {
    const receiptFixture = setupProducerFixture();
    const receiptPath = receiptFixture.options.receiptPath;
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    receipt.artifact.binaryDigest = `sha256-${"0".repeat(64)}`;
    fs.writeFileSync(receiptPath, JSON.stringify(receipt));
    assert.throws(
      () => buildPortableHermesMacosPackage(receiptFixture.options, fixtureDependencies()),
      /does not bind the packaged runtime/u,
    );

    const versionFixture = setupProducerFixture();
    const wrongVersion = (invocation) => {
      const result = fixtureRunner(invocation);
      if (invocation.args[0] === "--version") result.stdout = Buffer.from("HBC bytecode version: 98\n");
      return result;
    };
    assert.throws(
      () => buildPortableHermesMacosPackage(versionFixture.options, fixtureDependencies(wrongVersion)),
      /reports HBC 98/u,
    );

    const byteFixture = setupProducerFixture();
    const wrongBytecode = (invocation) => {
      if (invocation.args[0] === "--version") return fixtureRunner(invocation);
      fs.writeFileSync(path.join(invocation.cwd, "output/smoke.hbc"), makeHbc(98));
      return { status: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
    };
    assert.throws(
      () => buildPortableHermesMacosPackage(byteFixture.options, fixtureDependencies(wrongBytecode)),
      /bytecode version 98/u,
    );

    const runtimeFixture = setupProducerFixture();
    const runtimeDependencies = fixtureDependencies();
    runtimeDependencies.runRuntimeHbcProbe = () => ({ version: 98 });
    assert.throws(
      () => buildPortableHermesMacosPackage(runtimeFixture.options, runtimeDependencies),
      /runtime reports HBC 98/u,
    );
  });

  test("rejects a host tool changed during compatibility execution", () => {
    const fixture = setupProducerFixture();
    let mutated = false;
    const mutatingRunner = (invocation) => {
      const result = fixtureRunner(invocation);
      if (!mutated) {
        fs.appendFileSync(invocation.toolPath, Buffer.from([0]));
        mutated = true;
      }
      return result;
    };
    assert.throws(
      () => buildPortableHermesMacosPackage(fixture.options, fixtureDependencies(mutatingRunner)),
      /changed during compatibility execution/u,
    );

    const inputFixture = setupProducerFixture();
    const inputMutatingRunner = (invocation) => {
      const result = fixtureRunner(invocation);
      fs.appendFileSync(path.join(invocation.cwd, "input/smoke.js"), "// changed\n");
      return result;
    };
    assert.throws(
      () => buildPortableHermesMacosPackage(inputFixture.options, fixtureDependencies(inputMutatingRunner)),
      /host tool changed its exact input fixture/u,
    );
  });

  test("rejects Mach-O role, source-pin, and publisher-revision confusion", { timeout: 15_000 }, () => {
    const runtimeFixture = setupProducerFixture();
    const runtimePath = path.join(runtimeFixture.options.frameworkPath, "Versions/1/hermesvm");
    const runtimeBytes = fs.readFileSync(runtimePath);
    const armSlice = parseMachO(runtimeBytes, { architecture: "arm64" });
    runtimeBytes.writeUInt32LE(2, armSlice.sliceOffset + 12);
    fs.writeFileSync(runtimePath, runtimeBytes, { mode: 0o755 });
    assert.throws(
      () => buildPortableHermesMacosPackage(runtimeFixture.options, fixtureDependencies()),
      /runtime slice is not MH_DYLIB/u,
    );

    const toolFixture = setupProducerFixture();
    const toolBytes = fs.readFileSync(toolFixture.options.hermescPath);
    toolBytes.writeUInt32LE(6, 12);
    fs.writeFileSync(toolFixture.options.hermescPath, toolBytes, { mode: 0o755 });
    assert.throws(
      () => buildPortableHermesMacosPackage(toolFixture.options, fixtureDependencies()),
      /hermesc must be a thin arm64 Mach-O executable/u,
    );

    const installNameFixture = setupProducerFixture();
    const installNamePath = path.join(
      installNameFixture.options.frameworkPath,
      "Versions/1/hermesvm",
    );
    const installNameBytes = fs.readFileSync(installNamePath);
    const installName = Buffer.from("@rpath/hermesvm.framework/Versions/1/hermesvm", "utf8");
    const installNameArmSlice = parseMachO(installNameBytes, { architecture: "arm64" });
    const installNameOffset = installNameBytes.indexOf(
      installName,
      installNameArmSlice.sliceOffset,
    );
    assert(
      installNameOffset >= installNameArmSlice.sliceOffset &&
        installNameOffset < installNameArmSlice.sliceOffset + installNameArmSlice.sliceSize,
    );
    installNameBytes[installNameOffset] = "x".charCodeAt(0);
    fs.writeFileSync(installNamePath, installNameBytes, { mode: 0o755 });
    assert.throws(
      () => buildPortableHermesMacosPackage(installNameFixture.options, fixtureDependencies()),
      /wrong framework install name/u,
    );

    const linkerFixture = setupProducerFixture();
    const linkerBytes = fs.readFileSync(linkerFixture.options.hermescPath);
    const linkerName = Buffer.from("/usr/lib/dyld", "utf8");
    const linkerOffset = linkerBytes.indexOf(linkerName);
    assert(linkerOffset >= 0);
    linkerBytes[linkerOffset + linkerName.length - 4] = "n".charCodeAt(0);
    fs.writeFileSync(linkerFixture.options.hermescPath, linkerBytes, { mode: 0o755 });
    assert.throws(
      () => buildPortableHermesMacosPackage(linkerFixture.options, fixtureDependencies()),
      /hermesc must be a thin arm64 Mach-O executable/u,
    );

    const pinFixture = setupProducerFixture();
    const pinReceipt = JSON.parse(fs.readFileSync(pinFixture.options.receiptPath, "utf8"));
    pinReceipt.origin.reviewedProfileIdentity.sourceCommit = "b".repeat(40);
    fs.writeFileSync(pinFixture.options.receiptPath, JSON.stringify(pinReceipt));
    assert.throws(
      () => buildPortableHermesMacosPackage(pinFixture.options, fixtureDependencies()),
      /receipt Hermes source pin/u,
    );

    const revisionFixture = setupProducerFixture();
    revisionFixture.options.expectedSourceRevision = "f".repeat(40);
    assert.throws(
      () => buildPortableHermesMacosPackage(revisionFixture.options, fixtureDependencies()),
      /differs from expected publisher revision/u,
    );
  });

  test("rejects manufactured ABI claims, ignored patches, and oversized inputs", () => {
    const abiFixture = setupProducerFixture();
    const policyPath = path.join(
      abiFixture.testRepo,
      "schemas/portable-engine-provenance-trust-policy-v1.json",
    );
    const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    policy.admittedTargets[0].directJsiAbi.pointerWidth = 32;
    fs.writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
    runGit(abiFixture.testRepo, ["add", policyPath]);
    runGit(abiFixture.testRepo, ["commit", "-m", "mutate ABI policy"]);
    abiFixture.options.expectedSourceRevision = runGit(abiFixture.testRepo, ["rev-parse", "HEAD"]);
    assert.throws(
      () => buildPortableHermesMacosPackage(abiFixture.options, fixtureDependencies()),
      /frozen macOS direct JSI ABI/u,
    );

    const patchFixture = setupProducerFixture();
    fs.appendFileSync(
      path.join(patchFixture.testRepo, ".git/info/exclude"),
      "patches/hermes/ignored-injection.patch\n",
    );
    fs.writeFileSync(
      path.join(patchFixture.testRepo, "patches/hermes/ignored-injection.patch"),
      "ignored patch bytes\n",
    );
    assert.throws(
      () => buildPortableHermesMacosPackage(patchFixture.options, fixtureDependencies()),
      /tracked Hermes patch-stack membership/u,
    );

    const limitFixture = setupProducerFixture();
    const runtimeSize = fs.statSync(
      path.join(limitFixture.options.frameworkPath, "Versions/1/hermesvm"),
    ).size;
    const oversizedPath = path.join(
      limitFixture.options.frameworkPath,
      "Versions/1/Resources/oversized.bin",
    );
    fs.writeFileSync(oversizedPath, Buffer.alloc(runtimeSize + 1));
    const limitPolicyPath = path.join(
      limitFixture.testRepo,
      "schemas/portable-engine-provenance-trust-policy-v1.json",
    );
    const limitPolicy = JSON.parse(fs.readFileSync(limitPolicyPath, "utf8"));
    limitPolicy.archiveLimits.maxRegularFileBytes = runtimeSize;
    fs.writeFileSync(limitPolicyPath, `${JSON.stringify(limitPolicy, null, 2)}\n`);
    runGit(limitFixture.testRepo, ["add", limitPolicyPath]);
    runGit(limitFixture.testRepo, ["commit", "-m", "tighten archive limit"]);
    limitFixture.options.expectedSourceRevision = runGit(limitFixture.testRepo, ["rev-parse", "HEAD"]);
    assert.throws(
      () => buildPortableHermesMacosPackage(limitFixture.options, fixtureDependencies()),
      /oversized\.bin: .* exceeds remaining regular\/expanded limit/u,
    );
  });

  test("does not enable portable acceptance or target advertisements", () => {
    const policy = JSON.parse(
      fs.readFileSync(path.join(repoRoot, "schemas/portable-engine-provenance-trust-policy-v1.json"), "utf8"),
    );
    const advertisements = JSON.parse(
      fs.readFileSync(path.join(repoRoot, "capsec/generated/target-advertisements.json"), "utf8"),
    );
    assert.equal(policy.portableArtifactAcceptanceEnabled, false);
    assert.deepEqual(advertisements.advertisements, []);
  });
});
