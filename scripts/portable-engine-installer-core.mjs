// Safe, checkout-local materialization for an authenticated portable engine.
// This phase-1 foundation deliberately does not make the resulting store an
// accepted build/runtime authority; build.rs and target advertisement remain
// disconnected until LLP 0035's remaining gates are complete.
//
// @ref LLP 0035#transport-and-distribution-provenance — authenticate the
// detached publisher statement and exact archive bytes before parsing gzip or
// ustar metadata.
// @ref LLP 0035#content-addressed-installation — publish an exact, reverified
// payload and selected transport record atomically in the checkout-local store.

import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { finished } from "node:stream/promises";
import { createGunzip } from "node:zlib";

import {
  assertCanonicalJsonBytes,
  assertExactKeys,
  canonicalJson,
  compareUtf8,
  gitObjectId,
  parseJsonStrict,
  rawDigest,
  semanticDigest,
} from "./portable-engine-contract.mjs";

const TARGET_TRIPLE = "aarch64-apple-darwin";
const POLICY_PATH = "schemas/portable-engine-provenance-trust-policy-v1.json";
const POLICY_SCHEMA_PATH = "schemas/portable-engine-provenance-trust-policy-v1.schema.json";
const MANIFEST_PATH = "META-INF/portable-engine-manifest.json";
const RECEIPT_PATH = "share/hermes/profile-provenance.json";
const EXPECTATIONS_SCHEMA = "ibex/github-private-artifact-attestation-expectations/2";
const VERIFICATION_SCHEMA = "ibex/github-private-artifact-attestation-verification/2";
const RECEIPT_SCHEMA = "ibex/portable-engine-installation-receipt/1";
const COMPLETION_SCHEMA = "ibex/portable-engine-local-completion/1";
const TRANSPORT_COMPLETION_SCHEMA = "ibex/portable-engine-local-transport-completion/1";
const TEST_RECEIPT_SCHEMA = "ibex/test-only-portable-engine-installation-receipt/1";
const TEST_COMPLETION_SCHEMA = "ibex/test-only-portable-engine-local-completion/1";
const TEST_TRANSPORT_COMPLETION_SCHEMA = "ibex/test-only-portable-engine-local-transport-completion/1";
const BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json";
const MAX_SCHEMA_BYTES = 2 * 1024 * 1024;
const MAX_AUTHORITY_JSON_BYTES = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const OPEN_READ_NOFOLLOW = fs.constants.O_RDONLY | NOFOLLOW;
const OPEN_CREATE_EXCLUSIVE = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW;
const fatalUtf8 = new TextDecoder("utf-8", { fatal: true });

const PRODUCTION_STORE_CONTRACT = Object.freeze({
  kind: "production",
  storeDirectory: "hermes-artifacts",
  receiptSchema: RECEIPT_SCHEMA,
  completionSchema: COMPLETION_SCHEMA,
  transportCompletionSchema: TRANSPORT_COMPLETION_SCHEMA,
  lockSchema: "ibex/portable-engine-local-install-lock/1",
});

const TEST_STORE_CONTRACT = Object.freeze({
  kind: "test-only",
  storeDirectory: "hermes-artifacts-test-only",
  receiptSchema: TEST_RECEIPT_SCHEMA,
  completionSchema: TEST_COMPLETION_SCHEMA,
  transportCompletionSchema: TEST_TRANSPORT_COMPLETION_SCHEMA,
  lockSchema: "ibex/test-only-portable-engine-local-install-lock/1",
});

const AUTHORITY_SCHEMAS = Object.freeze({
  manifest: "schemas/portable-engine-manifest-v1.schema.json",
  sourceTree: "schemas/portable-engine-source-tree-identity-v1.schema.json",
  reviewedProfile: "schemas/portable-engine-reviewed-profile-identity-v1.schema.json",
  exportSet: "schemas/portable-engine-export-set-v1.schema.json",
  headerSet: "schemas/portable-engine-header-set-v1.schema.json",
  abiContract: "schemas/portable-engine-abi-contract-v1.schema.json",
  hostTool: "schemas/portable-engine-host-tool-compatibility-v1.schema.json",
  receipt: "schemas/portable-engine-installation-receipt-v1.schema.json",
});

const ALL_SCHEMA_PATHS = Object.freeze([
  "schemas/portable-engine-common-v1.schema.json",
  POLICY_SCHEMA_PATH,
  ...Object.values(AUTHORITY_SCHEMAS),
]);

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function equalJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function assertSame(left, right, label) {
  assert(equalJson(left, right), `${label}: expected ${canonicalJson(right)}, got ${canonicalJson(left)}`);
}

function assertRawDigest(value, label) {
  assert(typeof value === "string" && /^sha256-[0-9a-f]{64}$/u.test(value), `${label}: expected a raw SHA-256 digest`);
}

function assertSemanticDigest(value, label) {
  assert(typeof value === "string" && /^sha256-[A-Za-z0-9_-]{43}$/u.test(value), `${label}: expected a semantic SHA-256 digest`);
}

function assertSourceRevision(value, label = "source revision") {
  assert(typeof value === "string" && /^[0-9a-f]{40}$/u.test(value), `${label}: expected exactly 40 lowercase hexadecimal digits`);
}

function assertPositiveDecimal(value, label) {
  assert(typeof value === "string" && /^[1-9][0-9]*$/u.test(value), `${label}: expected one canonical positive decimal string`);
  assert(BigInt(value) <= BigInt(Number.MAX_SAFE_INTEGER), `${label}: exceeds the I-JSON safe integer range`);
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseBoundedJson(bytes, label, { maximumDepth = 64, maximumPunctuation = 1_000_000 } = {}) {
  const input = Buffer.from(bytes);
  let depth = 0;
  let punctuation = 0;
  let inString = false;
  let escaped = false;
  for (const byte of input) {
    if (inString) {
      if (escaped) escaped = false;
      else if (byte === 0x5c) escaped = true;
      else if (byte === 0x22) inString = false;
      continue;
    }
    if (byte === 0x22) {
      inString = true;
      continue;
    }
    if (byte === 0x7b || byte === 0x5b) {
      depth += 1;
      punctuation += 1;
      assert(depth <= maximumDepth, `${label}: JSON nesting exceeds ${maximumDepth}`);
    } else if (byte === 0x7d || byte === 0x5d) {
      depth -= 1;
      punctuation += 1;
      assert(depth >= 0, `${label}: JSON containers are unbalanced`);
    } else if (byte === 0x2c || byte === 0x3a) {
      punctuation += 1;
    }
    assert(punctuation <= maximumPunctuation, `${label}: JSON structural cardinality exceeds ${maximumPunctuation}`);
  }
  assert(!inString && !escaped && depth === 0, `${label}: JSON lexical structure is incomplete`);
  return parseJsonStrict(input, label);
}

function fileObjectEqual(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mode === right.mode;
}

function requireRegularStat(status, label, maximumBytes) {
  assert(status.isFile() && !status.isSymbolicLink(), `${label}: expected one no-follow regular file`);
  assert(status.size > 0n, `${label}: empty files are forbidden`);
  assert(status.size <= BigInt(maximumBytes), `${label}: exceeds ${maximumBytes} bytes`);
}

async function readBoundedRegular(filePath, label, maximumBytes) {
  const handle = await fsp.open(filePath, OPEN_READ_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    requireRegularStat(before, label, maximumBytes);
    const size = Number(before.size);
    const output = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(output, offset, size - offset, offset);
      assert(bytesRead > 0, `${label}: file truncated during read`);
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    assert(fileObjectEqual(before, after), `${label}: file object changed during read`);
    return output;
  } finally {
    await handle.close();
  }
}

async function digestRegularFile(filePath, label, maximumBytes) {
  const handle = await fsp.open(filePath, OPEN_READ_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    requireRegularStat(before, label, maximumBytes);
    const hash = createHash("sha256");
    let seen = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      seen += chunk.length;
      assert(seen <= maximumBytes, `${label}: exceeds ${maximumBytes} bytes while hashing`);
      hash.update(chunk);
    }
    const after = await handle.stat({ bigint: true });
    assert(fileObjectEqual(before, after) && BigInt(seen) === before.size, `${label}: file object changed while hashing`);
    return { digest: `sha256-${hash.digest("hex")}`, size: seen, stat: before };
  } finally {
    await handle.close();
  }
}

async function copyPinnedRegular(sourcePath, destinationPath, label, maximumBytes) {
  const source = await fsp.open(sourcePath, OPEN_READ_NOFOLLOW);
  let destination;
  try {
    const before = await source.stat({ bigint: true });
    requireRegularStat(before, label, maximumBytes);
    destination = await fsp.open(destinationPath, OPEN_CREATE_EXCLUSIVE, 0o600);
    const hash = createHash("sha256");
    let seen = 0;
    for await (const chunk of source.createReadStream({ autoClose: false })) {
      seen += chunk.length;
      assert(seen <= maximumBytes, `${label}: exceeds ${maximumBytes} bytes while copying`);
      let offset = 0;
      while (offset < chunk.length) {
        const { bytesWritten } = await destination.write(chunk, offset, chunk.length - offset);
        assert(bytesWritten > 0, `${label}: short write while pinning transport`);
        offset += bytesWritten;
      }
      hash.update(chunk);
    }
    await destination.sync();
    const pinned = await destination.stat({ bigint: true });
    const after = await source.stat({ bigint: true });
    assert(fileObjectEqual(before, after) && BigInt(seen) === before.size, `${label}: source changed while pinning transport`);
    assert(pinned.isFile() && pinned.size === BigInt(seen), `${label}: pinned transport size drift`);
    return { digest: `sha256-${hash.digest("hex")}`, size: seen, stat: pinned };
  } finally {
    if (destination) await destination.close();
    await source.close();
  }
}

function defaultReadRevisionFile(repoRoot, revision, relativePath) {
  assertPortablePath(relativePath, `revision path ${relativePath}`);
  const result = spawnSync("git", ["show", `${revision}:${relativePath}`], {
    cwd: repoRoot,
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
    env: { PATH: process.env.PATH ?? "" },
  });
  assert(result.status === 0, `checked authority is not a regular tracked blob at ${revision}:${relativePath}`);
  return Buffer.from(result.stdout);
}

function defaultListRevisionFiles(repoRoot, revision, relativeDirectory) {
  assertPortablePath(relativeDirectory, "revision directory");
  const result = spawnSync("git", ["ls-tree", "-r", "-z", "--name-only", revision, "--", relativeDirectory], {
    cwd: repoRoot,
    encoding: null,
    maxBuffer: 16 * 1024 * 1024,
    env: { PATH: process.env.PATH ?? "" },
  });
  assert(result.status === 0, `cannot enumerate checked files at ${revision}:${relativeDirectory}`);
  return result.stdout.toString("utf8").split("\0").filter(Boolean);
}

function defaultReadGitObject(repoRoot, type, objectId) {
  assert(type === "commit" || type === "tree", `unsupported Git object type ${type}`);
  const result = spawnSync("git", ["cat-file", type, objectId], {
    cwd: repoRoot,
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
    env: { PATH: process.env.PATH ?? "" },
  });
  assert(result.status === 0, `cannot read checked Git ${type} object ${objectId}`);
  return Buffer.from(result.stdout);
}

function defaultResolveCheckoutRevision(repoRoot) {
  const result = spawnSync("git", ["rev-parse", "--verify", "HEAD^{commit}"], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    env: { PATH: process.env.PATH ?? "" },
  });
  assert(result.status === 0, "cannot resolve the current checkout revision");
  const revision = result.stdout.trim();
  assertSourceRevision(revision, "current checkout revision");
  return revision;
}

function defaultEffectiveUid() {
  assert(typeof process.geteuid === "function", "portable macOS installation requires an effective-UID ownership check");
  return process.geteuid();
}

function defaultHasExtendedAcl(filePath) {
  assert(process.platform === "darwin", "production portable macOS installation requires Darwin ACL inspection");
  const result = spawnSync("/bin/ls", ["-lde", filePath], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    env: { PATH: "/usr/bin:/bin", LC_ALL: "C", LANG: "C" },
  });
  assert(result.status === 0, `${filePath}: cannot inspect macOS ACL state`);
  const firstToken = result.stdout.trimStart().split(/\s+/u, 1)[0] ?? "";
  return firstToken.endsWith("+") || /^\s+\d+:/mu.test(result.stdout);
}

function createRuntime(contract, dependencies) {
  return {
    contract,
    dependencies,
    effectiveUid: dependencies.effectiveUid ?? defaultEffectiveUid(),
    hasExtendedAcl: dependencies.hasExtendedAcl ?? defaultHasExtendedAcl,
  };
}

// @ref LLP 0035#threat-model-and-trust-roots — ACL-free effective-UID
// ownership closes alternate-principal write paths without claiming safety
// from a malicious process already running as that UID.
async function assertOwnedTrustedNode(filePath, status, runtime, label, { exactMode, rejectGroupWorldWrite = true } = {}) {
  assert(status.uid === BigInt(runtime.effectiveUid), `${label}: expected effective-UID ownership`);
  const mode = Number(status.mode & 0o777n);
  if (exactMode !== undefined) assert(mode === exactMode, `${label}: expected mode ${exactMode.toString(8)}, got ${mode.toString(8)}`);
  if (rejectGroupWorldWrite && !status.isSymbolicLink()) assert((mode & 0o022) === 0, `${label}: group/world-writable mode is forbidden`);
  assert(!(await runtime.hasExtendedAcl(filePath)), `${label}: macOS extended ACLs are forbidden on trusted installer nodes`);
}

function assertCurrentCheckoutRevision(repoRoot, expected, dependencies) {
  const resolveCheckoutRevision = dependencies.resolveCheckoutRevision ?? defaultResolveCheckoutRevision;
  const observed = resolveCheckoutRevision(repoRoot);
  assert(observed === expected, `externally selected revision ${expected} is not current checkout HEAD ${observed}`);
}

function jsonPointer(value, fragment, label) {
  if (fragment === "" || fragment === "#") return value;
  assert(fragment.startsWith("#/"), `${label}: unsupported JSON Schema fragment ${fragment}`);
  let current = value;
  for (const encoded of fragment.slice(2).split("/")) {
    const key = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    assert(current && typeof current === "object" && key in current, `${label}: unresolved JSON Schema pointer ${fragment}`);
    current = current[key];
  }
  return current;
}

function jsonTypeMatches(value, type) {
  if (type === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
  if (type === "array") return Array.isArray(value);
  if (type === "integer") return Number.isSafeInteger(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  if (type === "string" || type === "boolean") return typeof value === type;
  if (type === "null") return value === null;
  return false;
}

function validateJsonSchema(schema, value, registry, location = "$") {
  assert(schema && typeof schema === "object" && !Array.isArray(schema), `${location}: invalid checked JSON Schema node`);
  if (schema.$ref) {
    const [documentName, rawFragment = ""] = schema.$ref.split("#", 2);
    const document = documentName === "" ? registry.current : registry.byName.get(documentName);
    assert(document, `${location}: unresolved checked JSON Schema ${documentName}`);
    validateJsonSchema(jsonPointer(document, `#${rawFragment}`, location), value, { ...registry, current: document }, location);
  }
  if (schema.allOf) for (const item of schema.allOf) validateJsonSchema(item, value, registry, location);
  if (schema.oneOf) {
    let matches = 0;
    for (const item of schema.oneOf) {
      try {
        validateJsonSchema(item, value, registry, location);
        matches += 1;
      } catch {
        // Only the exact one-of cardinality is authoritative here.
      }
    }
    assert(matches === 1, `${location}: expected exactly one checked JSON Schema variant, got ${matches}`);
  }
  if (schema.if) {
    let matched = false;
    try {
      validateJsonSchema(schema.if, value, registry, location);
      matched = true;
    } catch {
      matched = false;
    }
    if (matched && schema.then) validateJsonSchema(schema.then, value, registry, location);
    if (!matched && schema.else) validateJsonSchema(schema.else, value, registry, location);
  }
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    assert(types.some((type) => jsonTypeMatches(value, type)), `${location}: value has the wrong JSON Schema type`);
  }
  if (Object.prototype.hasOwnProperty.call(schema, "const")) {
    assert(equalJson(value, schema.const), `${location}: value differs from checked const`);
  }
  if (schema.enum) assert(schema.enum.some((item) => equalJson(value, item)), `${location}: value is outside checked enum`);
  if (typeof value === "string") {
    if (schema.minLength !== undefined) assert([...value].length >= schema.minLength, `${location}: string is too short`);
    if (schema.maxLength !== undefined) assert([...value].length <= schema.maxLength, `${location}: string is too long`);
    if (schema.pattern !== undefined) assert(new RegExp(schema.pattern, "u").test(value), `${location}: string fails checked pattern`);
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined) assert(value >= schema.minimum, `${location}: number is below checked minimum`);
    if (schema.maximum !== undefined) assert(value <= schema.maximum, `${location}: number is above checked maximum`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined) assert(value.length >= schema.minItems, `${location}: array is too short`);
    if (schema.maxItems !== undefined) assert(value.length <= schema.maxItems, `${location}: array is too long`);
    if (schema.uniqueItems) {
      const keys = value.map((item) => canonicalJson(item));
      assert(new Set(keys).size === keys.length, `${location}: array items are not unique`);
    }
    if (schema.items) value.forEach((item, index) => validateJsonSchema(schema.items, item, registry, `${location}[${index}]`));
    if (schema.contains) {
      let count = 0;
      for (let index = 0; index < value.length; index += 1) {
        try {
          validateJsonSchema(schema.contains, value[index], registry, `${location}[${index}]`);
          count += 1;
        } catch {
          // Count only matching items.
        }
      }
      const minimum = schema.minContains ?? 1;
      const maximum = schema.maxContains ?? Number.MAX_SAFE_INTEGER;
      assert(count >= minimum && count <= maximum, `${location}: contains cardinality ${count} is outside ${minimum}..${maximum}`);
    }
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    if (schema.required) {
      for (const field of schema.required) assert(Object.prototype.hasOwnProperty.call(value, field), `${location}: missing required field ${field}`);
    }
    if (schema.properties) {
      for (const [field, childSchema] of Object.entries(schema.properties)) {
        if (Object.prototype.hasOwnProperty.call(value, field)) {
          validateJsonSchema(childSchema, value[field], registry, `${location}.${field}`);
        }
      }
    }
    if (schema.additionalProperties === false) {
      const allowed = new Set(Object.keys(schema.properties ?? {}));
      for (const field of Object.keys(value)) assert(allowed.has(field), `${location}: unknown field ${field}`);
    }
  }
}

async function loadCheckedContext(repoRoot, sourceRevision, dependencies) {
  const readRevisionFile = dependencies.readRevisionFile ?? defaultReadRevisionFile;
  const read = (relativePath) => Promise.resolve(readRevisionFile(repoRoot, sourceRevision, relativePath));
  const schemaByName = new Map();
  for (const schemaPath of ALL_SCHEMA_PATHS) {
    const bytes = Buffer.from(await read(schemaPath));
    assert(bytes.length > 0 && bytes.length <= MAX_SCHEMA_BYTES, `${schemaPath}: checked schema size is outside policy`);
    schemaByName.set(path.posix.basename(schemaPath), parseBoundedJson(bytes, schemaPath));
  }
  const policyBytes = Buffer.from(await read(POLICY_PATH));
  const policy = parseBoundedJson(policyBytes, POLICY_PATH);
  const policySchema = schemaByName.get(path.posix.basename(POLICY_SCHEMA_PATH));
  validateJsonSchema(policySchema, policy, { byName: schemaByName, current: policySchema }, "$ policy");
  assert(policy.portableArtifactAcceptanceEnabled === false, "installer foundation requires portable acceptance to remain false");
  const matches = policy.admittedTargets.filter((target) => target.triple === TARGET_TRIPLE);
  assert(matches.length === 1, `checked policy must contain exactly one ${TARGET_TRIPLE} row`);
  const targetPolicy = matches[0];
  const authorityBytes = new Map();
  const authorityRows = [];
  for (const relativePath of targetPolicy.buildAuthorityPaths) {
    const bytes = Buffer.from(await read(relativePath));
    authorityBytes.set(relativePath, bytes);
    authorityRows.push({ path: relativePath, digest: rawDigest(bytes) });
  }
  authorityRows.sort((left, right) => compareUtf8(left.path, right.path));
  return {
    policy,
    policyBytes,
    targetPolicy,
    authorityBytes,
    authorityRows,
    schemaByName,
    validate(schemaPath, value, label) {
      const schema = schemaByName.get(path.posix.basename(schemaPath));
      assert(schema, `${label}: checked schema is unavailable`);
      validateJsonSchema(schema, value, { byName: schemaByName, current: schema }, label);
    },
    readRevisionFile: read,
  };
}

function assertPortableSegment(segment, label) {
  assert(segment !== "" && segment !== "." && segment !== "..", `${label}: empty or pseudo path segment`);
  assert(/^[\x20-\x7e]+$/u.test(segment), `${label}: v1 accepts printable ASCII path segments only`);
  assert(!segment.endsWith(".") && !segment.endsWith(" "), `${label}: trailing dot/space is forbidden`);
  assert(!segment.includes(":") && !segment.includes("\\"), `${label}: ADS, drive, and backslash syntax is forbidden`);
  const stem = segment.split(".", 1)[0].toLowerCase();
  assert(!new Set(["aux", "clock$", "con", "nul", "prn", ...Array.from({ length: 9 }, (_, index) => `com${index + 1}`), ...Array.from({ length: 9 }, (_, index) => `lpt${index + 1}`)]).has(stem), `${label}: Windows reserved device name is forbidden`);
}

function assertPortablePath(value, label = "portable path") {
  assert(typeof value === "string" && value.length > 0, `${label}: expected a non-empty string`);
  assert(!value.startsWith("/") && !value.startsWith("\\") && !/^[A-Za-z]:/u.test(value), `${label}: absolute/UNC/device path is forbidden`);
  const segments = value.split("/");
  for (const segment of segments) assertPortableSegment(segment, label);
  return value;
}

function portableEquivalenceKey(value) {
  assertPortablePath(value);
  return value.toLowerCase();
}

function assertUniquePortablePaths(paths, label) {
  const raw = new Set();
  const equivalent = new Map();
  for (const pathname of paths) {
    assertPortablePath(pathname, `${label} path`);
    assert(!raw.has(pathname), `${label}: duplicate path ${pathname}`);
    raw.add(pathname);
    const key = portableEquivalenceKey(pathname);
    assert(!equivalent.has(key), `${label}: target-filesystem collision between ${equivalent.get(key)} and ${pathname}`);
    equivalent.set(key, pathname);
  }
}

function resolveRelativeSymlink(pathname, target) {
  assert(typeof target === "string" && target.length > 0, `${pathname}: empty symlink target`);
  assert(!target.startsWith("/") && !target.startsWith("\\") && !target.includes(":") && !target.includes("\\"), `${pathname}: absolute/drive/UNC symlink target is forbidden`);
  const output = pathname.split("/").slice(0, -1);
  for (const segment of target.split("/")) {
    assert(segment !== "" && segment !== ".", `${pathname}: symlink target is not normalized`);
    if (segment === "..") {
      assert(output.length > 0, `${pathname}: symlink target escapes payload`);
      output.pop();
    } else {
      assertPortableSegment(segment, `${pathname} symlink target`);
      output.push(segment);
    }
  }
  assert(output.length > 0, `${pathname}: symlink target names the payload root`);
  return output.join("/");
}

function validateEntryGraph(entries, maximumDepth) {
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  for (const entry of entries) {
    const segments = entry.path.split("/");
    for (let length = 1; length < segments.length; length += 1) {
      const parent = segments.slice(0, length).join("/");
      assert(byPath.get(parent)?.kind === "directory", `${entry.path}: parent ${parent} is not a declared directory`);
    }
  }
  const resolve = (pathname, stack = new Set(), depth = 0) => {
    assert(depth <= maximumDepth, `${pathname}: symlink resolution exceeds ${maximumDepth}`);
    const segments = pathname.split("/");
    for (let index = 0; index < segments.length; index += 1) {
      const candidate = segments.slice(0, index + 1).join("/");
      const entry = byPath.get(candidate);
      assert(entry, `${pathname}: traversal reaches undeclared ${candidate}`);
      if (entry.kind === "symlink") {
        assert(!stack.has(candidate), `${candidate}: symlink cycle`);
        const next = new Set(stack);
        next.add(candidate);
        const target = resolveRelativeSymlink(candidate, entry.target);
        const remainder = segments.slice(index + 1);
        return resolve(remainder.length ? `${target}/${remainder.join("/")}` : target, next, depth + 1);
      }
      assert(index === segments.length - 1 || entry.kind === "directory", `${pathname}: traversal crosses non-directory ${candidate}`);
    }
    return pathname;
  };
  for (const entry of entries) if (entry.kind === "symlink") resolve(entry.path);
}

function validateManifestShape(manifestBytes, context, expectedSourceRevision) {
  const manifest = parseBoundedJson(manifestBytes, "portable engine manifest");
  assertCanonicalJsonBytes(manifestBytes, manifest, "portable engine manifest");
  context.validate(AUTHORITY_SCHEMAS.manifest, manifest, "$ manifest");
  assert(manifest.artifactId === semanticDigest("ibex.portable-engine-manifest.v1", manifest, ["artifactId"]), "manifest artifactId self-digest mismatch");
  assert(manifest.artifactKind === "hermes", "manifest artifact kind is not Hermes");
  assertSame(manifest.target, { triple: TARGET_TRIPLE, structuralFeatures: context.targetPolicy.structuralFeatures }, "manifest target");
  assertSame(
    manifest.profile,
    { ...context.targetPolicy.profile, reviewedProfileIdentityDigest: manifest.profile.reviewedProfileIdentityDigest },
    "manifest profile",
  );
  assert(manifest.build.repository === context.policy.enginePublisher.repository, "manifest repository differs from checked publisher policy");
  assert(manifest.build.publisherWorkflow === context.policy.enginePublisher.workflowPath, "manifest workflow differs from checked publisher policy");
  assert(manifest.build.sourceRef === context.policy.enginePublisher.sourceRef, "manifest source ref differs from checked publisher policy");
  assert(manifest.build.sourceRevision === expectedSourceRevision, "manifest source revision differs from the externally selected checkout revision");
  assertSame(manifest.build.authorityDigests, context.authorityRows, "manifest checked build authorities");
  assertSemanticDigest(manifest.profile.reviewedProfileIdentityDigest, "reviewed profile identity digest");
  assertSemanticDigest(manifest.build.sourceTreeDigest, "source tree digest");
  const paths = manifest.entries.map((entry) => entry.path);
  assert(manifest.entries.length + 3 <= context.policy.archiveLimits.maxMemberCount, "manifest plus envelope exceeds checked archive member count");
  assertUniquePortablePaths(paths, "manifest entries");
  const sorted = [...paths].sort(compareUtf8);
  assertSame(paths, sorted, "manifest entry order");
  let expanded = 0;
  for (const entry of manifest.entries) {
    if (entry.kind === "regular") {
      assertRawDigest(entry.digest, `${entry.path} digest`);
      assert(entry.size <= context.policy.archiveLimits.maxRegularFileBytes, `${entry.path}: declared size exceeds policy`);
      expanded += entry.size;
      assert(Number.isSafeInteger(expanded) && expanded <= context.policy.archiveLimits.maxExpandedBytes, "manifest expanded bytes exceed policy");
    } else if (entry.kind === "symlink") {
      resolveRelativeSymlink(entry.path, entry.target);
    }
  }
  assert(expanded + manifestBytes.length <= context.policy.archiveLimits.maxExpandedBytes, "manifest plus payload expanded bytes exceed policy");
  validateEntryGraph(manifest.entries, context.policy.archiveLimits.maxSymlinkDepth);
  const regular = new Map(manifest.entries.filter((entry) => entry.kind === "regular").map((entry) => [entry.path, entry]));
  const runtime = regular.get(manifest.runtimeComponent);
  assert(runtime && runtime.role === "runtime" && runtime.executable === true, "runtimeComponent does not name one executable runtime payload member");
  const nonSystem = manifest.interface.loadableComponents.filter((entry) => entry.system === false);
  assert(nonSystem.length === 1 && nonSystem[0].role === "runtime", "v1 macOS package must have runtime-only non-system topology");
  assert(nonSystem[0].path === manifest.runtimeComponent && nonSystem[0].digest === runtime.digest, "runtime component does not join its interface row");
  const expectedComponents = [
    { role: "runtime", path: manifest.runtimeComponent, digest: runtime.digest, system: false },
    ...context.policy.platformSystemDependencies[context.targetPolicy.systemDependencyPolicyKey]
      .map((name) => ({ role: "runtime-dependency", name, system: true })),
  ];
  assertSame(manifest.interface.loadableComponents, expectedComponents, "complete runtime dependency topology");
  assertSame(
    manifest.interface.hostTools.map((tool) => ({ toolRole: context.targetPolicy.requiredHostTools.find((row) => row.toolPath === tool.path)?.toolRole, toolPath: tool.path })),
    context.targetPolicy.requiredHostTools,
    "complete required host-tool membership",
  );
  for (const tool of manifest.interface.hostTools) {
    assert(regular.get(tool.path)?.digest === tool.digest && regular.get(tool.path)?.role === "host-tool" && regular.get(tool.path)?.executable === true, `${tool.path}: host tool does not join an executable host-tool entry`);
  }
  return manifest;
}

function decodeTarString(field, label, { allowEmpty = false } = {}) {
  const nul = field.indexOf(0);
  const end = nul === -1 ? field.length : nul;
  if (nul !== -1) assert(field.subarray(nul).every((byte) => byte === 0), `${label}: non-zero bytes after NUL`);
  let value;
  try {
    value = fatalUtf8.decode(field.subarray(0, end));
  } catch (error) {
    fail(`${label}: invalid UTF-8: ${error.message}`);
  }
  assert(allowEmpty || value.length > 0, `${label}: empty ustar string`);
  return value;
}

function parseTarOctal(field, label) {
  const text = field.toString("ascii");
  assert(/^[0-7]+(?:\0[\0 ]*| +)$/u.test(text), `${label}: non-canonical or base-256 ustar integer`);
  const digits = text.match(/^[0-7]+/u)[0];
  const value = Number.parseInt(digits, 8);
  assert(Number.isSafeInteger(value), `${label}: ustar integer is unsafe`);
  return value;
}

function parseTarHeader(header) {
  assert(header.length === 512, "internal ustar header size mismatch");
  assert(header.toString("ascii", 257, 263) === "ustar\0", "archive member is not POSIX ustar");
  assert(header.toString("ascii", 263, 265) === "00", "archive member has an unsupported ustar version");
  const checksumHeader = Buffer.from(header);
  checksumHeader.fill(0x20, 148, 156);
  const computed = checksumHeader.reduce((sum, byte) => sum + byte, 0);
  assert(parseTarOctal(header.subarray(148, 156), "ustar checksum") === computed, "ustar header checksum mismatch");
  assert(header.subarray(265, 345).every((byte) => byte === 0), "ustar user/group fields are forbidden");
  assert(header.subarray(329, 345).every((byte) => byte === 0), "ustar device fields are forbidden");
  assert(header.subarray(500, 512).every((byte) => byte === 0), "ustar extension padding is forbidden");
  const name = decodeTarString(header.subarray(0, 100), "ustar name");
  const prefix = decodeTarString(header.subarray(345, 500), "ustar prefix", { allowEmpty: true });
  let pathname = prefix ? `${prefix}/${name}` : name;
  const typeByte = header[156];
  const kind = typeByte === 0 || typeByte === 0x30 ? "regular" : typeByte === 0x35 ? "directory" : typeByte === 0x32 ? "symlink" : null;
  assert(kind, `${pathname}: hardlink, special, sparse, pax, and unknown ustar types are forbidden`);
  if (kind === "directory" && pathname.endsWith("/")) pathname = pathname.slice(0, -1);
  assertPortablePath(pathname, "ustar member path");
  const mode = parseTarOctal(header.subarray(100, 108), `${pathname} mode`);
  const uid = parseTarOctal(header.subarray(108, 116), `${pathname} uid`);
  const gid = parseTarOctal(header.subarray(116, 124), `${pathname} gid`);
  const size = parseTarOctal(header.subarray(124, 136), `${pathname} size`);
  const mtime = parseTarOctal(header.subarray(136, 148), `${pathname} mtime`);
  assert(uid === 0 && gid === 0 && mtime === 0, `${pathname}: ustar ownership/time metadata is not normalized`);
  const linkTarget = decodeTarString(header.subarray(157, 257), `${pathname} link target`, { allowEmpty: true });
  if (kind === "symlink") {
    assert(size === 0 && mode === 0o777 && linkTarget.length > 0, `${pathname}: malformed ustar symlink`);
  } else {
    assert(linkTarget === "", `${pathname}: non-symlink carries a link target`);
  }
  if (kind === "directory") assert(size === 0 && mode === 0o755, `${pathname}: malformed ustar directory`);
  if (kind === "regular") assert(mode === 0o644 || mode === 0o755, `${pathname}: regular ustar mode is not portable`);
  return { path: pathname, kind, size, mode, target: linkTarget };
}

class StreamingUstarExtractor {
  constructor({ candidateRoot, context, expectedSourceRevision, onArchiveMember }) {
    this.candidateRoot = candidateRoot;
    this.context = context;
    this.expectedSourceRevision = expectedSourceRevision;
    this.onArchiveMember = onArchiveMember;
    this.pending = Buffer.alloc(0);
    this.state = "header";
    this.zeroBlocks = 0;
    this.members = [];
    this.equivalence = new Map();
    this.manifest = null;
    this.manifestBytes = null;
    this.current = null;
    this.expanded = 0;
    this.symlinks = [];
  }

  async feed(chunk) {
    assert(this.state !== "done" || chunk.length === 0, "decompressed bytes follow the two ustar end blocks");
    this.pending = this.pending.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.pending, chunk]);
    while (true) {
      if (this.state === "header") {
        if (this.pending.length < 512) return;
        const header = this.take(512);
        if (header.every((byte) => byte === 0)) {
          this.zeroBlocks += 1;
          if (this.zeroBlocks === 2) {
            this.state = "done";
            assert(this.pending.length === 0, "decompressed bytes follow the two ustar end blocks");
            return;
          }
          continue;
        }
        assert(this.zeroBlocks === 0, "non-zero ustar member follows an end block");
        const member = parseTarHeader(header);
        assert(this.members.length < this.context.policy.archiveLimits.maxMemberCount, "ustar member count exceeds checked policy");
        const prior = this.members.at(-1)?.path;
        assert(prior === undefined || compareUtf8(prior, member.path) < 0, `${member.path}: ustar paths are not strict canonical order`);
        const key = portableEquivalenceKey(member.path);
        assert(!this.equivalence.has(key), `ustar target-filesystem collision between ${this.equivalence.get(key)} and ${member.path}`);
        this.equivalence.set(key, member.path);
        this.members.push(member);
        this.onArchiveMember?.(member.path);
        await this.beginMember(member);
        continue;
      }
      if (this.state === "body") {
        if (this.pending.length === 0) return;
        const amount = Math.min(this.current.remaining, this.pending.length);
        const bytes = this.take(amount);
        await this.writeCurrent(bytes);
        this.current.remaining -= amount;
        if (this.current.remaining === 0) await this.finishBody();
        continue;
      }
      if (this.state === "padding") {
        if (this.pending.length < this.current.padding) return;
        const padding = this.take(this.current.padding);
        assert(padding.every((byte) => byte === 0), `${this.current.member.path}: non-zero ustar body padding`);
        this.current = null;
        this.state = "header";
        continue;
      }
      return;
    }
  }

  take(size) {
    const output = this.pending.subarray(0, size);
    this.pending = this.pending.subarray(size);
    return output;
  }

  expectedEntry(memberPath) {
    if (!this.manifest || !memberPath.startsWith("payload/")) return null;
    const payloadPath = memberPath.slice("payload/".length);
    return this.manifest.entries.find((entry) => entry.path === payloadPath) ?? null;
  }

  async beginMember(member) {
    const allowedEnvelope = member.path === "META-INF" || member.path === MANIFEST_PATH || member.path === "payload" || member.path.startsWith("payload/");
    assert(allowedEnvelope, `${member.path}: member is outside the closed portable-engine envelope`);
    if (member.path === "META-INF" || member.path === "payload") {
      assert(member.kind === "directory", `${member.path}: envelope root is not a directory`);
      await fsp.mkdir(path.join(this.candidateRoot, member.path), { mode: 0o700 });
      this.state = "header";
      return;
    }
    if (member.path === MANIFEST_PATH) {
      assert(member.kind === "regular" && member.mode === 0o644, "portable manifest member is not a non-executable regular file");
      assert(member.size <= Math.min(this.context.policy.archiveLimits.maxRegularFileBytes, MAX_MANIFEST_BYTES), "portable manifest exceeds its bounded regular-file limit");
      const outputPath = path.join(this.candidateRoot, MANIFEST_PATH);
      const handle = await fsp.open(outputPath, OPEN_CREATE_EXCLUSIVE, 0o600);
      this.current = { member, remaining: member.size, padding: (512 - (member.size % 512)) % 512, handle, hash: createHash("sha256"), chunks: [], seen: 0, expected: null };
      this.state = "body";
      if (member.size === 0) await this.finishBody();
      return;
    }
    assert(this.manifest, `${member.path}: payload member precedes the authenticated manifest member`);
    const expected = this.expectedEntry(member.path);
    assert(expected, `${member.path}: undeclared archive member`);
    assert(expected.kind === member.kind, `${member.path}: archive kind differs from manifest`);
    const payloadRelative = member.path.slice("payload/".length);
    const outputPath = path.join(this.candidateRoot, "payload", ...payloadRelative.split("/"));
    if (member.kind === "directory") {
      await fsp.mkdir(outputPath, { mode: 0o700 });
      this.state = "header";
      return;
    }
    if (member.kind === "symlink") {
      assert(member.target === expected.target, `${member.path}: symlink target differs from manifest`);
      resolveRelativeSymlink(expected.path, expected.target);
      this.symlinks.push({ outputPath, target: expected.target, path: expected.path });
      this.state = "header";
      return;
    }
    assert(member.size === expected.size, `${member.path}: archive size differs from manifest`);
    assert(member.mode === (expected.executable ? 0o755 : 0o644), `${member.path}: archive mode differs from manifest`);
    assert(member.size <= this.context.policy.archiveLimits.maxRegularFileBytes, `${member.path}: regular file exceeds policy`);
    this.expanded += member.size;
    assert(Number.isSafeInteger(this.expanded) && this.expanded <= this.context.policy.archiveLimits.maxExpandedBytes, "archive expanded bytes exceed checked policy");
    const handle = await fsp.open(outputPath, OPEN_CREATE_EXCLUSIVE, 0o600);
    this.current = { member, remaining: member.size, padding: (512 - (member.size % 512)) % 512, handle, hash: createHash("sha256"), chunks: null, seen: 0, expected };
    this.state = "body";
    if (member.size === 0) await this.finishBody();
  }

  async writeCurrent(bytes) {
    if (bytes.length === 0) return;
    assert(this.current?.handle, "internal extractor error: output handle is closed");
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesWritten } = await this.current.handle.write(bytes, offset, bytes.length - offset);
      assert(bytesWritten > 0, `${this.current.member.path}: short extraction write`);
      offset += bytesWritten;
    }
    this.current.hash.update(bytes);
    this.current.seen += bytes.length;
    if (this.current.chunks) this.current.chunks.push(Buffer.from(bytes));
  }

  async finishBody() {
    const handle = this.current.handle;
    assert(handle, "internal extractor error: output handle is absent");
    this.current.handle = null;
    await handle.sync();
    await handle.close();
    const digest = `sha256-${this.current.hash.digest("hex")}`;
    assert(this.current.seen === this.current.member.size, `${this.current.member.path}: extracted size drift`);
    if (this.current.member.path === MANIFEST_PATH) {
      this.manifestBytes = Buffer.concat(this.current.chunks);
      this.manifest = validateManifestShape(this.manifestBytes, this.context, this.expectedSourceRevision);
    } else {
      assert(digest === this.current.expected.digest, `${this.current.member.path}: extracted digest differs from manifest`);
    }
    this.state = this.current.padding === 0 ? "header" : "padding";
    if (this.current.padding === 0) this.current = null;
  }

  async abort() {
    const handle = this.current?.handle;
    if (handle) {
      this.current.handle = null;
      await handle.close().catch(() => {});
    }
    this.pending = Buffer.alloc(0);
  }

  async finish() {
    assert(this.state === "done" && this.pending.length === 0, "ustar stream is truncated or missing exactly two end blocks");
    assert(this.manifest && this.manifestBytes, "ustar stream has no portable manifest");
    const expected = ["META-INF", MANIFEST_PATH, "payload", ...this.manifest.entries.map((entry) => `payload/${entry.path}`)];
    assertSame(this.members.map((member) => member.path), expected, "archive exact membership and order");
    for (const symlink of this.symlinks) await fsp.symlink(symlink.target, symlink.outputPath);
    return { manifest: this.manifest, manifestBytes: this.manifestBytes };
  }
}

async function extractAuthenticatedArchive(archivePath, candidateRoot, context, expectedSourceRevision, hooks = {}) {
  hooks.onArchiveParseStart?.();
  const extractor = new StreamingUstarExtractor({
    candidateRoot,
    context,
    expectedSourceRevision,
    onArchiveMember: hooks.onArchiveMember,
  });
  const handle = await fsp.open(archivePath, OPEN_READ_NOFOLLOW);
  const gunzip = createGunzip();
  const input = handle.createReadStream({ autoClose: false });
  input.on("error", (error) => gunzip.destroy(error));
  input.pipe(gunzip);
  const maximumTarBytes = context.policy.archiveLimits.maxExpandedBytes + context.policy.archiveLimits.maxMemberCount * 1024 + 4096;
  let outputBytes = 0;
  try {
    for await (const chunk of gunzip) {
      outputBytes += chunk.length;
      assert(Number.isSafeInteger(outputBytes) && outputBytes <= maximumTarBytes, "gzip expansion exceeds bounded ustar envelope limit");
      await extractor.feed(chunk);
    }
    return await extractor.finish();
  } finally {
    await extractor.abort();
    input.unpipe(gunzip);
    input.destroy();
    gunzip.destroy();
    await Promise.allSettled([finished(input), finished(gunzip)]);
    await handle.close();
  }
}

function buildFixedVerifierExpectations(policy, sourceRevision, subjectName) {
  assertSourceRevision(sourceRevision);
  assertPortableSegment(subjectName, "attestation subject basename");
  const publisher = policy.enginePublisher;
  return {
    schema: EXPECTATIONS_SCHEMA,
    subjectName,
    repository: publisher.repository,
    repositoryId: publisher.repositoryId,
    repositoryOwnerId: publisher.repositoryOwnerId,
    workflowPath: publisher.workflowPath,
    workflowName: publisher.workflowName,
    sourceRef: publisher.sourceRef,
    sourceRevision,
    allowedTriggers: [...publisher.allowedTriggers],
    runnerEnvironment: publisher.runnerClass,
    repositoryVisibility: publisher.repositoryVisibility,
    certificateIssuer: publisher.certificateIssuer,
    buildType: publisher.buildType,
    trustedRoot: { ...publisher.trustedRoot },
  };
}

function validateCanonicalVerificationResult(resultBytes, { expectationsBytes, expectations, archive, bundle }) {
  assert(Buffer.isBuffer(resultBytes) || resultBytes instanceof Uint8Array, "offline verifier returned no canonical result bytes");
  const rawBytes = Buffer.from(resultBytes);
  assert(rawBytes.length > 1 && rawBytes.at(-1) === 0x0a && rawBytes.at(-2) !== 0x0a, "offline verifier result must be one JCS document followed by exactly one LF");
  const bytes = rawBytes.subarray(0, -1);
  const result = parseBoundedJson(bytes, "offline attestation verification result");
  assertCanonicalJsonBytes(bytes, result, "offline attestation verification result");
  assertExactKeys(result, ["schema", "trustRoot", "expectationsDigest", "bundle", "subject", "signer", "provenance", "timestamp"], "verification result");
  assert(result.schema === VERIFICATION_SCHEMA, "offline verifier returned an unexpected result schema");
  assertExactKeys(result.trustRoot, ["profile", "sha256", "size"], "verification trust root");
  assertSame(result.trustRoot, expectations.trustedRoot, "verification trust root");
  assert(result.expectationsDigest === sha256Hex(expectationsBytes), "verification result does not bind the fixed expectations bytes");
  assertExactKeys(result.bundle, ["mediaType", "sha256", "size"], "verification bundle");
  assertSame(result.bundle, { mediaType: BUNDLE_MEDIA_TYPE, sha256: bundle.digest.slice("sha256-".length), size: bundle.size }, "verified bundle bytes");
  assertExactKeys(result.subject, ["name", "sha256", "size"], "verification subject");
  assertSame(result.subject, { name: expectations.subjectName, sha256: archive.digest.slice("sha256-".length), size: archive.size }, "verified archive subject");
  assertExactKeys(result.signer, ["issuer", "san", "repository", "repositoryId", "repositoryOwnerId", "workflowPath", "workflowName", "sourceRef", "sourceRevision", "trigger", "runnerEnvironment", "repositoryVisibility", "runId", "runAttempt"], "verification signer");
  assert(result.signer.issuer === expectations.certificateIssuer, "verified signer issuer differs from fixed policy");
  const san = `https://github.com/${expectations.repository}/${expectations.workflowPath}@${expectations.sourceRef}`;
  assert(result.signer.san === san, "verified signer SAN does not join policy repository/workflow/ref");
  for (const field of ["repository", "repositoryId", "repositoryOwnerId", "workflowPath", "workflowName", "sourceRef", "sourceRevision", "runnerEnvironment", "repositoryVisibility"]) {
    assert(result.signer[field] === expectations[field], `verified signer ${field} differs from fixed expectations`);
  }
  assert(expectations.allowedTriggers.includes(result.signer.trigger), "verified trigger is outside the checked allowed set");
  assertPositiveDecimal(result.signer.runId, "verified run ID");
  assertPositiveDecimal(result.signer.runAttempt, "verified run attempt");
  assertExactKeys(result.provenance, ["statementType", "predicateType", "buildType", "builderId", "invocationId"], "verification provenance");
  assert(result.provenance.statementType === "https://in-toto.io/Statement/v1" && result.provenance.predicateType === "https://slsa.dev/provenance/v1", "verified statement has the wrong in-toto/SLSA types");
  const invocation = `https://github.com/${expectations.repository}/actions/runs/${result.signer.runId}/attempts/${result.signer.runAttempt}`;
  assert(result.provenance.invocationId === invocation, "verified invocation does not join signer run/attempt");
  assert(result.provenance.buildType === expectations.buildType && result.provenance.builderId === san, "verified build type/builder differs from fixed current workflow policy");
  assertExactKeys(result.timestamp, ["type", "uri", "value"], "verification timestamp");
  assert(result.timestamp.type === "TimestampAuthority" && typeof result.timestamp.uri === "string" && result.timestamp.uri.length > 0, "verification result lacks one timestamp-authority observation");
  assert(typeof result.timestamp.value === "string" && Number.isFinite(Date.parse(result.timestamp.value)), "verification timestamp is not RFC3339-like");
  return result;
}

async function unavailableRealVerifier() {
  fail(
    "portable engine installation remains fail-closed: production offline-verifier invocation is deliberately not wired into this foundation; dependency injection is test-only until the reviewed verifier and checked publisher-expectation policy are integrated",
  );
}

function parseCommitTree(commitBytes) {
  const text = fatalUtf8.decode(commitBytes);
  const lines = text.split("\n").filter((line) => line.startsWith("tree "));
  assert(lines.length === 1 && /^tree [0-9a-f]{40}$/u.test(lines[0]), "source commit object does not carry one canonical SHA-1 tree header");
  return lines[0].slice(5);
}

function deriveVersionAuthorities(context, dependencies, repoRoot, sourceRevision) {
  const versionBytes = context.authorityBytes.get("scripts/hermes-version.sh");
  assert(versionBytes, "checked hermes-version.sh authority is missing");
  const source = fatalUtf8.decode(versionBytes);
  const exactlyOne = (pattern, label) => {
    const matches = [...source.matchAll(pattern)];
    assert(matches.length === 1, `hermes-version.sh must contain one canonical ${label}`);
    return matches[0][1];
  };
  const sourceVersion = exactlyOne(/^IBEX_HERMES_VERSION="\$\{IBEX_HERMES_VERSION:-([0-9]+(?:\.[0-9]+){2})\}"$/gmu, "source version");
  const sourceCommit = exactlyOne(/^IBEX_HERMES_SOURCE_COMMIT="\$\{IBEX_HERMES_SOURCE_COMMIT:-([0-9a-f]{40})\}"$/gmu, "source commit");
  assert([...source.matchAll(/^IBEX_HERMES_SOURCE_REF="\$\{IBEX_HERMES_SOURCE_REF:-\$\{IBEX_HERMES_VERSION\}-stable\}"$/gmu)].length === 1, "hermes-version.sh lacks one canonical source-ref derivation");
  const marker = Buffer.from("ibex_sha256() {", "utf8");
  const markerOffset = versionBytes.indexOf(marker);
  assert(markerOffset >= 0 && (markerOffset === 0 || versionBytes[markerOffset - 1] === 0x0a), "Hermes identity-authority marker is absent");
  const listRevisionFiles = dependencies.listRevisionFiles ?? defaultListRevisionFiles;
  const readRevisionFile = dependencies.readRevisionFile ?? defaultReadRevisionFile;
  const patches = listRevisionFiles(repoRoot, sourceRevision, "patches/hermes")
    .filter((entry) => /^patches\/hermes\/[^/]+\.patch$/u.test(entry))
    .sort(compareUtf8);
  assert(patches.length > 0, "checked Hermes patch stack is empty");
  const patchProjection = patches.map((relativePath) => {
    const bytes = Buffer.from(readRevisionFile(repoRoot, sourceRevision, relativePath));
    return `${sha256Hex(bytes)}  ${relativePath}\n`;
  }).join("");
  const digestByPath = new Map(context.authorityRows.map((row) => [row.path, row.digest]));
  return {
    pinned: { sourceVersion, sourceRef: `${sourceVersion}-stable`, sourceCommit },
    patchStackDigest: rawDigest(Buffer.from(patchProjection, "utf8")),
    patchApplicationAuthorityDigest: digestByPath.get("scripts/apply-hermes-patches.sh"),
    patchIdentityAuthorityDigest: rawDigest(versionBytes.subarray(markerOffset)),
    sourceBuildAuthorityDigests: {
      "scripts/build-hermes-linux.sh": digestByPath.get("scripts/build-hermes-linux.sh"),
      "scripts/build-hermes.sh": digestByPath.get("scripts/build-hermes.sh"),
    },
  };
}

async function readPayloadEntry(artifactRoot, entry, maximumBytes = MAX_AUTHORITY_JSON_BYTES) {
  assert(entry?.kind === "regular", `${entry?.path ?? "payload member"}: expected a regular manifest entry`);
  const filePath = path.join(artifactRoot, "payload", ...entry.path.split("/"));
  const bytes = await readBoundedRegular(filePath, entry.path, Math.min(maximumBytes, entry.size));
  assert(bytes.length === entry.size && rawDigest(bytes) === entry.digest, `${entry.path}: installed bytes differ from manifest`);
  return bytes;
}

async function readAuthorityDocument(artifactRoot, manifest, pathname, schemaPath, context) {
  const entry = manifest.entries.find((candidate) => candidate.path === pathname);
  assert(entry?.role === "metadata", `${pathname}: authority document does not have metadata role`);
  const bytes = await readPayloadEntry(artifactRoot, entry);
  const document = parseBoundedJson(bytes, pathname);
  assertCanonicalJsonBytes(bytes, document, pathname);
  context.validate(schemaPath, document, `$ ${pathname}`);
  return { bytes, document, entry };
}

function digestPrefix(value, label) {
  assertRawDigest(value, label);
  return value.slice(7, 19);
}

async function validateManifestAuthorities(artifactRoot, manifest, context, sourceRevision, dependencies) {
  const repoRoot = dependencies.repoRoot;
  assert(typeof repoRoot === "string", "internal installer error: checkout root is absent during authority validation");
  const regular = new Map(manifest.entries.filter((entry) => entry.kind === "regular").map((entry) => [entry.path, entry]));
  const [sourceTree, reviewed, required, forbidden, headers, abi] = await Promise.all([
    readAuthorityDocument(artifactRoot, manifest, "META-INF/authority/source-tree-identity.json", AUTHORITY_SCHEMAS.sourceTree, context),
    readAuthorityDocument(artifactRoot, manifest, "META-INF/authority/reviewed-profile-identity.json", AUTHORITY_SCHEMAS.reviewedProfile, context),
    readAuthorityDocument(artifactRoot, manifest, "META-INF/authority/required-exports.json", AUTHORITY_SCHEMAS.exportSet, context),
    readAuthorityDocument(artifactRoot, manifest, "META-INF/authority/forbidden-exports.json", AUTHORITY_SCHEMAS.exportSet, context),
    readAuthorityDocument(artifactRoot, manifest, "META-INF/authority/header-set.json", AUTHORITY_SCHEMAS.headerSet, context),
    readAuthorityDocument(artifactRoot, manifest, "META-INF/authority/abi-contract.json", AUTHORITY_SCHEMAS.abiContract, context),
  ]);
  assert(manifest.build.sourceTreeDigest === semanticDigest("ibex.portable-engine-source-tree-identity.v1", sourceTree.document), "source-tree semantic digest does not join manifest");
  assert(manifest.profile.reviewedProfileIdentityDigest === semanticDigest("ibex.portable-engine-reviewed-profile-identity.v1", reviewed.document), "reviewed-profile semantic digest does not join manifest");
  assert(manifest.interface.requiredExportsDigest === semanticDigest("ibex.portable-engine-required-exports.v1", required.document), "required-export semantic digest does not join manifest");
  assert(manifest.interface.forbiddenExportsDigest === semanticDigest("ibex.portable-engine-forbidden-exports.v1", forbidden.document), "forbidden-export semantic digest does not join manifest");
  assert(manifest.interface.headerSetDigest === semanticDigest("ibex.portable-engine-header-set.v1", headers.document), "header-set semantic digest does not join manifest");
  assert(manifest.interface.abiContractDigest === semanticDigest("ibex.portable-engine-abi-contract.v1", abi.document), "ABI semantic digest does not join manifest");

  assertSame(sourceTree.document.repository, manifest.build.repository, "source-tree repository");
  assert(sourceTree.document.sourceRevision === sourceRevision && sourceTree.document.sourceRef === manifest.build.sourceRef, "source-tree revision/ref does not join manifest");
  assert(sourceTree.document.gitObjectFormat === context.targetPolicy.sourceTreeGitObjectFormat, "source-tree object format is not policy admitted");
  const commitEntry = regular.get(sourceTree.document.sourceRevisionObjectContent.path);
  const treeEntry = regular.get(sourceTree.document.treeObjectContent.path);
  assert(commitEntry?.role === "metadata" && treeEntry?.role === "metadata", "source-tree raw objects do not have metadata role");
  const commitBytes = await readPayloadEntry(artifactRoot, commitEntry);
  const treeBytes = await readPayloadEntry(artifactRoot, treeEntry);
  for (const [object, entry, bytes] of [[sourceTree.document.sourceRevisionObjectContent, commitEntry, commitBytes], [sourceTree.document.treeObjectContent, treeEntry, treeBytes]]) {
    assert(object.digest === entry.digest && object.size === entry.size && object.encoding === "raw-uncompressed-git-object-content", "source-tree object content does not join its payload entry");
  }
  assert(gitObjectId("sha1", "commit", commitBytes) === sourceRevision, "payload commit bytes do not hash to selected source revision");
  const treeId = parseCommitTree(commitBytes);
  assert(treeId === sourceTree.document.treeObjectId && gitObjectId("sha1", "tree", treeBytes) === treeId, "payload tree bytes do not join the selected commit");
  const readGitObject = dependencies.readGitObject ?? defaultReadGitObject;
  assert(Buffer.from(readGitObject(repoRoot, "commit", sourceRevision)).equals(commitBytes), "payload commit bytes differ from the current checkout object");
  assert(Buffer.from(readGitObject(repoRoot, "tree", treeId)).equals(treeBytes), "payload tree bytes differ from the current checkout object");

  const runtimeEntry = regular.get(manifest.runtimeComponent);
  const receiptEntry = regular.get(reviewed.document.receiptPath);
  assert(reviewed.document.receiptPath === RECEIPT_PATH && reviewed.document.receiptDigest === receiptEntry?.digest && receiptEntry?.role === "profile-receipt", "reviewed profile receipt member does not join its exact profile-receipt bytes");
  const receiptBytes = await readPayloadEntry(artifactRoot, receiptEntry, 1024 * 1024);
  const receipt = parseBoundedJson(receiptBytes, "Hermes profile receipt");
  assertExactKeys(receipt, ["schema", "profileId", "targetVariant", "artifact", "origin"], "Hermes profile receipt");
  assert(receipt.schema === "ibex/hermes-profile-provenance-receipt/2", "Hermes profile receipt has the wrong schema");
  assertExactKeys(receipt.artifact, ["binaryDigest", "fileName", "targetArchitecture"], "Hermes profile receipt artifact");
  assertExactKeys(receipt.origin, ["kind", "cacheKey", "reviewedProfileIdentity"], "Hermes profile receipt origin");
  assert(receipt.profileId === context.targetPolicy.profile.id && receipt.targetVariant === context.targetPolicy.profile.targetVariant, "Hermes profile receipt differs from admitted profile");
  assert(receipt.artifact.binaryDigest === runtimeEntry.digest && receipt.artifact.fileName === "hermesvm", "Hermes profile receipt does not bind runtime component");
  assert(context.targetPolicy.receiptTargetArchitectures.includes(receipt.artifact.targetArchitecture), "Hermes receipt architecture is not policy admitted");
  assert(receipt.origin.kind === context.targetPolicy.reviewedProfileOriginKind, "Hermes receipt origin is not policy admitted");
  assertSame(reviewed.document, {
    schema: "ibex/portable-engine-reviewed-profile-identity/1",
    profileId: receipt.profileId,
    targetVariant: receipt.targetVariant,
    targetTriple: TARGET_TRIPLE,
    originKind: receipt.origin.kind,
    receiptPath: RECEIPT_PATH,
    receiptDigest: rawDigest(receiptBytes),
    reviewedProfileIdentity: receipt.origin.reviewedProfileIdentity,
  }, "reviewed profile projection");
  const sourceAuthorities = deriveVersionAuthorities(context, dependencies, repoRoot, sourceRevision);
  const identity = receipt.origin.reviewedProfileIdentity;
  assertSame(identity, {
    artifact: "facebook/hermes",
    patchApplicationAuthorityDigest: sourceAuthorities.patchApplicationAuthorityDigest,
    patchIdentityAuthorityDigest: sourceAuthorities.patchIdentityAuthorityDigest,
    patchStackDigest: sourceAuthorities.patchStackDigest,
    sourceBuildAuthorityDigests: sourceAuthorities.sourceBuildAuthorityDigests,
    sourceCommit: sourceAuthorities.pinned.sourceCommit,
    sourceRef: sourceAuthorities.pinned.sourceRef,
    sourceVersion: sourceAuthorities.pinned.sourceVersion,
  }, "reviewed profile source/build authority");
  const expectedCacheKey = `${identity.sourceCommit.slice(0, 12)}-p${digestPrefix(identity.patchStackDigest, "patch stack")}-ba${digestPrefix(identity.sourceBuildAuthorityDigests["scripts/build-hermes.sh"], "Apple builder")}-bl${digestPrefix(identity.sourceBuildAuthorityDigests["scripts/build-hermes-linux.sh"], "Linux builder")}-a${digestPrefix(identity.patchApplicationAuthorityDigest, "patch application")}-i${digestPrefix(identity.patchIdentityAuthorityDigest, "identity authority")}-oapple`;
  assert(receipt.origin.cacheKey === expectedCacheKey, "Hermes receipt cache key is not reconstructed from checked authorities");
  assertSame(manifest.source, {
    artifact: identity.artifact,
    sourceCommit: identity.sourceCommit,
    sourceRef: identity.sourceRef,
    sourceVersion: identity.sourceVersion,
    patchStackDigest: identity.patchStackDigest,
  }, "manifest source projection");

  const componentRows = manifest.interface.loadableComponents.filter((row) => row.system === false).map(({ path: pathname, digest }) => ({ path: pathname, digest }));
  assert(required.document.mode === "required" && forbidden.document.mode === "forbidden", "export authority modes are confused");
  for (const document of [required.document, forbidden.document]) {
    assert(document.targetTriple === TARGET_TRIPLE && document.extractor === context.targetPolicy.exportExtractor, "export authority target/extractor differs from policy");
    assertSame(document.components, componentRows, "export authority components");
  }
  assertSame(required.document.matchers, context.targetPolicy.exportPolicy.requiredMatchers, "required export policy");
  assertSame(forbidden.document.matchers, context.targetPolicy.exportPolicy.forbiddenMatchers, "forbidden export policy");
  const headerRows = manifest.entries.filter((entry) => entry.kind === "regular" && entry.role === "header").map(({ path: pathname, digest, size }) => ({ path: pathname, digest, size }));
  assert(headers.document.targetTriple === TARGET_TRIPLE && headers.document.includeRoots.length > 0, "header-set target/include roots are invalid");
  assertSame(headers.document.headers, headerRows, "header-set exact membership");
  assertSame(abi.document, {
    schema: "ibex/portable-engine-abi-contract/1",
    target: manifest.target,
    ...context.targetPolicy.directJsiAbi,
    headerSetDigest: manifest.interface.headerSetDigest,
    requiredExportsDigest: manifest.interface.requiredExportsDigest,
    forbiddenExportsDigest: manifest.interface.forbiddenExportsDigest,
  }, "direct-JSI ABI authority");

  const hostDocumentPaths = [];
  for (const tool of manifest.interface.hostTools) {
    const pathname = `META-INF/authority/host-tools/${tool.compatibilityDigest}.json`;
    hostDocumentPaths.push(pathname);
    const authority = await readAuthorityDocument(artifactRoot, manifest, pathname, AUTHORITY_SCHEMAS.hostTool, context);
    assert(tool.compatibilityDigest === semanticDigest("ibex.portable-engine-host-tool-compatibility.v1", authority.document), `${pathname}: compatibility semantic digest mismatch`);
    assert(authority.document.toolPath === tool.path && authority.document.toolDigest === tool.digest, `${pathname}: host tool bytes do not join manifest`);
    assert(authority.document.toolRole === context.targetPolicy.requiredHostTools.find((row) => row.toolPath === tool.path)?.toolRole, `${pathname}: host tool role is not required by policy`);
    assert(authority.document.actualHostTriple === context.targetPolicy.hostTool.actualHostTriple, `${pathname}: host tool target differs from policy`);
    assertSame(authority.document.binaryMachine, context.targetPolicy.hostTool.binaryMachine, `${pathname} binary machine`);
    const contract = context.targetPolicy.hostTool.executionContract;
    for (const field of ["environmentMode", "environment", "stdin", "workingDirectoryLifetime", "argv0", "timeoutMs", "maxStdoutBytes", "maxStderrBytes", "maxOutputBytes"]) {
      assertSame(authority.document[field], contract[field], `${pathname} ${field}`);
    }
    for (const fixture of authority.document.inputFixtures) {
      const fixtureEntry = regular.get(fixture.fixturePayloadPath);
      assert(fixtureEntry?.digest === fixture.digest && fixtureEntry.size === fixture.size && fixtureEntry.role === "compatibility-fixture" && fixtureEntry.executable === fixture.executable, `${pathname}: input fixture does not join compatibility-fixture payload`);
    }
    const fixtureByWorkspacePath = new Map(authority.document.inputFixtures.map((fixture) => [fixture.workspacePath, fixture]));
    for (const invocation of authority.document.invocations) {
      for (const output of invocation.bytecodeOutputs) {
        const fixture = fixtureByWorkspacePath.get(output.sourcePath);
        assert(fixture?.digest === output.sourceDigest, `${pathname}: bytecode source does not join one declared fixture`);
        assert(output.bytecodeVersion === manifest.profile.hermesBytecodeVersion, `${pathname}: bytecode version differs from admitted profile`);
        assert(invocation.outputFiles.some((file) => file.path === output.path), `${pathname}: bytecode output is absent from complete output membership`);
      }
    }
    const allowedSystem = context.policy.platformSystemDependencies[context.targetPolicy.hostTool.systemDependencyPolicyKey];
    assert(authority.document.dependencyClosure.nonSystemDependencies.length === 0, `${pathname}: host tool has a non-system dependency`);
    for (const dependency of authority.document.dependencyClosure.systemDependencies) assert(allowedSystem.includes(dependency), `${pathname}: host dependency is outside policy`);
  }
  const declaredHostDocs = manifest.entries.filter((entry) => entry.kind === "regular" && entry.path.startsWith("META-INF/authority/host-tools/")).map((entry) => entry.path);
  assertSame(declaredHostDocs, hostDocumentPaths.sort(compareUtf8), "host-tool authority exact membership");
  const expectedAuthorityNamespace = [
    "META-INF",
    "META-INF/authority",
    "META-INF/authority/abi-contract.json",
    "META-INF/authority/forbidden-exports.json",
    "META-INF/authority/header-set.json",
    "META-INF/authority/host-tools",
    ...hostDocumentPaths,
    "META-INF/authority/required-exports.json",
    "META-INF/authority/reviewed-profile-identity.json",
    "META-INF/authority/source-tree",
    "META-INF/authority/source-tree-identity.json",
    sourceTree.document.sourceRevisionObjectContent.path,
    sourceTree.document.treeObjectContent.path,
  ].sort(compareUtf8);
  const actualAuthorityNamespace = manifest.entries
    .filter((entry) => entry.path === "META-INF" || entry.path.startsWith("META-INF/"))
    .map((entry) => entry.path);
  assertSame(actualAuthorityNamespace, expectedAuthorityNamespace, "reserved authority namespace exact membership");
}

async function walkNoFollow(root, inspect = async () => {}) {
  const output = [];
  const visit = async (absolute, relative) => {
    const status = await fsp.lstat(absolute, { bigint: true });
    const kind = status.isSymbolicLink() ? "symlink" : status.isDirectory() ? "directory" : status.isFile() ? "regular" : "special";
    const entry = { absolute, relative, status, kind };
    await inspect(entry);
    output.push(entry);
    if (kind === "directory") {
      const children = (await fsp.readdir(absolute)).sort(compareUtf8);
      for (const child of children) await visit(path.join(absolute, child), relative ? `${relative}/${child}` : child);
    }
  };
  await visit(root, "");
  return output;
}

async function makePrivateTreeRemovable(root) {
  const entries = await walkNoFollow(root);
  for (const entry of entries) {
    if (entry.kind === "directory") await fsp.chmod(entry.absolute, 0o700);
    else if (entry.kind === "regular") await fsp.chmod(entry.absolute, 0o600);
  }
}

async function validateInstalledPayload(artifactRoot, manifest, context, runtime) {
  const payloadRoot = path.join(artifactRoot, "payload");
  const actual = (await walkNoFollow(payloadRoot, async (entry) => {
    await assertOwnedTrustedNode(entry.absolute, entry.status, runtime, `${entry.relative || "payload"}: installed payload node`);
  }))
    .filter((entry) => entry.relative !== "")
    .sort((left, right) => compareUtf8(left.relative, right.relative));
  assertSame(actual.map((entry) => entry.relative), manifest.entries.map((entry) => entry.path), "installed payload exact membership");
  const byPath = new Map(actual.map((entry) => [entry.relative, entry]));
  const regularObjects = new Map();
  const graph = [];
  for (const expected of manifest.entries) {
    const observed = byPath.get(expected.path);
    assert(observed?.kind === expected.kind, `${expected.path}: installed kind differs from manifest`);
    const mode = Number(observed.status.mode & 0o777n);
    if (expected.kind === "directory") {
      assert((mode & 0o222) === 0, `${expected.path}: installed directory is writable`);
      graph.push({ kind: "directory", path: expected.path, mode });
    } else if (expected.kind === "symlink") {
      const target = await fsp.readlink(observed.absolute);
      assert(target === expected.target, `${expected.path}: installed symlink target drift`);
      graph.push({ kind: "symlink", path: expected.path, target });
    } else {
      assert(observed.status.nlink === 1n, `${expected.path}: installed regular file is hard-linked`);
      const objectKey = `${observed.status.dev}:${observed.status.ino}`;
      assert(!regularObjects.has(objectKey), `${expected.path}: installed file object aliases ${regularObjects.get(objectKey)}`);
      regularObjects.set(objectKey, expected.path);
      assert((mode & 0o222) === 0 && ((mode & 0o111) !== 0) === expected.executable, `${expected.path}: installed mode class differs from manifest`);
      const digest = await digestRegularFile(observed.absolute, expected.path, Math.min(expected.size, context.policy.archiveLimits.maxRegularFileBytes));
      assert(digest.size === expected.size && digest.digest === expected.digest, `${expected.path}: installed size/digest drift`);
      graph.push({ kind: "regular", path: expected.path, digest: digest.digest, size: digest.size, mode });
    }
  }
  return graph;
}

async function applyNarrowModes(artifactRoot, manifest) {
  for (const entry of manifest.entries) {
    if (entry.kind !== "regular") continue;
    await fsp.chmod(path.join(artifactRoot, "payload", ...entry.path.split("/")), entry.executable ? 0o555 : 0o444);
  }
  const directories = manifest.entries.filter((entry) => entry.kind === "directory").sort((left, right) => right.path.split("/").length - left.path.split("/").length);
  for (const entry of directories) await fsp.chmod(path.join(artifactRoot, "payload", ...entry.path.split("/")), 0o555);
  await fsp.chmod(path.join(artifactRoot, MANIFEST_PATH), 0o444);
  await fsp.chmod(path.join(artifactRoot, "payload"), 0o555);
  await fsp.chmod(path.join(artifactRoot, "META-INF"), 0o555);
}

async function writeCanonicalExclusive(filePath, value, mode = 0o600) {
  const bytes = Buffer.from(canonicalJson(value), "utf8");
  const handle = await fsp.open(filePath, OPEN_CREATE_EXCLUSIVE, mode);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  return bytes;
}

async function fsyncDirectory(directory) {
  const handle = await fsp.open(directory, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function fsyncRegularFile(filePath) {
  const handle = await fsp.open(filePath, OPEN_READ_NOFOLLOW);
  try {
    const status = await handle.stat({ bigint: true });
    assert(status.isFile() && !status.isSymbolicLink(), `${filePath}: durability target is not a no-follow regular file`);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function fsyncTreeBottomUp(root, runtime) {
  const entries = await walkNoFollow(root, async (entry) => {
    await assertOwnedTrustedNode(entry.absolute, entry.status, runtime, `${entry.relative || "artifact root"}: durability node`);
  });
  for (const entry of entries) if (entry.kind === "regular") await fsyncRegularFile(entry.absolute);
  const directories = entries
    .filter((entry) => entry.kind === "directory")
    .sort((left, right) => right.relative.split("/").length - left.relative.split("/").length);
  for (const entry of directories) await fsyncDirectory(entry.absolute);
}

function buildReceipt({ manifest, archive, bundle, context, sourceRevision, contract }) {
  return {
    schema: contract.receiptSchema,
    artifactId: manifest.artifactId,
    manifestDigest: semanticDigest("ibex.portable-engine-manifest-digest.v1", manifest),
    archiveDigest: archive.digest,
    provenanceBundleDigest: bundle.digest,
    verificationPolicyDigest: semanticDigest("ibex.portable-engine-provenance-trust-policy.v1", context.policy),
    repository: context.policy.enginePublisher.repository,
    publisherWorkflow: context.policy.enginePublisher.workflowPath,
    sourceRef: context.policy.enginePublisher.sourceRef,
    sourceRevision,
    runnerClass: context.policy.enginePublisher.runnerClass,
  };
}

function validateReceiptSchema(context, receipt, label) {
  context.validate(AUTHORITY_SCHEMAS.receipt, { ...receipt, schema: RECEIPT_SCHEMA }, label);
}

async function createTransportRecord({ artifactRoot, archivePath, bundlePath, verificationBytes, receipt, context, contract }) {
  const transportRoot = path.join(artifactRoot, "LOCAL", "transport", receipt.archiveDigest);
  await fsp.mkdir(transportRoot, { recursive: true, mode: 0o700 });
  await fsp.rename(archivePath, path.join(transportRoot, "archive.tar.gz"));
  await fsp.rename(bundlePath, path.join(transportRoot, "provenance.sigstore.json"));
  const verificationPath = path.join(transportRoot, "attestation-verification.json");
  const verificationHandle = await fsp.open(verificationPath, OPEN_CREATE_EXCLUSIVE, 0o600);
  try {
    await verificationHandle.writeFile(verificationBytes);
    await verificationHandle.sync();
  } finally {
    await verificationHandle.close();
  }
  await writeCanonicalExclusive(path.join(transportRoot, "installation-receipt.json"), receipt);
  const completion = {
    schema: contract.transportCompletionSchema,
    artifactId: receipt.artifactId,
    archiveDigest: receipt.archiveDigest,
    provenanceBundleDigest: receipt.provenanceBundleDigest,
    verificationPolicyDigest: receipt.verificationPolicyDigest,
  };
  await writeCanonicalExclusive(path.join(transportRoot, "COMPLETE"), completion);
  for (const name of ["archive.tar.gz", "provenance.sigstore.json", "attestation-verification.json", "installation-receipt.json", "COMPLETE"]) {
    await fsp.chmod(path.join(transportRoot, name), 0o444);
  }
  await fsyncDirectory(transportRoot);
  await fsp.chmod(transportRoot, 0o555);
  return transportRoot;
}

async function validateTransportRecord({ artifactRoot, archiveDigest, manifest, context, sourceRevision, verifyAttestation, runtime }) {
  assertRawDigest(archiveDigest, "selected transport archive digest");
  const transportRoot = path.join(artifactRoot, "LOCAL", "transport", archiveDigest);
  const status = await fsp.lstat(transportRoot, { bigint: true });
  assert(status.isDirectory() && !status.isSymbolicLink(), "selected transport record is not one no-follow directory");
  const names = (await fsp.readdir(transportRoot)).sort(compareUtf8);
  assertSame(names, ["COMPLETE", "archive.tar.gz", "attestation-verification.json", "installation-receipt.json", "provenance.sigstore.json"], "selected transport exact membership");
  const archivePath = path.join(transportRoot, "archive.tar.gz");
  const bundlePath = path.join(transportRoot, "provenance.sigstore.json");
  const archive = await digestRegularFile(archivePath, "retained transport archive", context.policy.archiveLimits.maxArchiveBytes);
  const bundle = await digestRegularFile(bundlePath, "retained provenance bundle", context.policy.provenanceBundleBytes.maxBundleBytes);
  assert(archive.digest === archiveDigest, "retained transport archive digest differs from selected directory");
  const expectations = buildFixedVerifierExpectations(context.policy, sourceRevision, path.basename(archivePath));
  // Stored basename differs from the signed release subject. Preserve the
  // original verified subject in the retained canonical verification result.
  const priorVerificationBytes = await readBoundedRegular(path.join(transportRoot, "attestation-verification.json"), "retained verification result", 1024 * 1024);
  const observedPrior = parseBoundedJson(priorVerificationBytes, "retained verification result");
  expectations.subjectName = observedPrior.subject?.name;
  assertPortableSegment(expectations.subjectName, "retained attestation subject");
  const expectationsBytes = Buffer.from(canonicalJson(expectations), "utf8");
  const priorVerification = validateCanonicalVerificationResult(priorVerificationBytes, { expectationsBytes, expectations, archive, bundle });
  const freshBytes = Buffer.from(await verifyAttestation({ archivePath, bundlePath, expectations, expectationsBytes, context }));
  const fresh = validateCanonicalVerificationResult(freshBytes, { expectationsBytes, expectations, archive, bundle });
  assertSame(fresh, priorVerification, "retained versus fresh offline attestation result");
  const receiptBytes = await readBoundedRegular(path.join(transportRoot, "installation-receipt.json"), "installation receipt", 1024 * 1024);
  const receipt = parseBoundedJson(receiptBytes, "installation receipt");
  assertCanonicalJsonBytes(receiptBytes, receipt, "installation receipt");
  validateReceiptSchema(context, receipt, "$ installation receipt");
  assertSame(receipt, buildReceipt({ manifest, archive, bundle, context, sourceRevision, contract: runtime.contract }), "installation receipt binding");
  const completionBytes = await readBoundedRegular(path.join(transportRoot, "COMPLETE"), "transport completion marker", 64 * 1024);
  const completion = parseBoundedJson(completionBytes, "transport completion marker");
  assertCanonicalJsonBytes(completionBytes, completion, "transport completion marker");
  assertSame(completion, {
    schema: runtime.contract.transportCompletionSchema,
    artifactId: receipt.artifactId,
    archiveDigest: receipt.archiveDigest,
    provenanceBundleDigest: receipt.provenanceBundleDigest,
    verificationPolicyDigest: receipt.verificationPolicyDigest,
  }, "transport completion marker");
  return { receipt, verification: fresh, archive, bundle };
}

async function validateTransportRecordShape(artifactRoot, archiveDigest, runtime) {
  const transportRoot = path.join(artifactRoot, "LOCAL", "transport", archiveDigest);
  const status = await fsp.lstat(transportRoot, { bigint: true });
  assert(status.isDirectory() && !status.isSymbolicLink(), `${archiveDigest}: retained transport is redirected or not a directory`);
  await assertOwnedTrustedNode(transportRoot, status, runtime, `${archiveDigest}: retained transport directory`);
  assert((Number(status.mode & 0o777n) & 0o222) === 0, `${archiveDigest}: retained transport directory is writable`);
  const names = (await fsp.readdir(transportRoot)).sort(compareUtf8);
  assertSame(names, ["COMPLETE", "archive.tar.gz", "attestation-verification.json", "installation-receipt.json", "provenance.sigstore.json"], `${archiveDigest} retained transport exact membership`);
  for (const name of names) {
    const member = await fsp.lstat(path.join(transportRoot, name), { bigint: true });
    assert(member.isFile() && !member.isSymbolicLink(), `${archiveDigest}/${name}: retained transport member is redirected or not regular`);
    await assertOwnedTrustedNode(path.join(transportRoot, name), member, runtime, `${archiveDigest}/${name}: retained transport member`);
    assert(member.nlink === 1n, `${archiveDigest}/${name}: retained transport member is hard-linked`);
    assert((Number(member.mode & 0o777n) & 0o222) === 0, `${archiveDigest}/${name}: retained transport member is writable`);
  }
}

async function removePrivateWorkspace(workspace) {
  try {
    const status = await fsp.lstat(workspace);
    if (status.isDirectory() && !status.isSymbolicLink()) {
      await makePrivateTreeRemovable(workspace);
      await fsp.rm(workspace, { recursive: true, force: false });
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

async function verifyRetainedArchiveMaterialization({ repoRoot, storeRoot, artifactRoot, manifest, manifestBytes, installedGraph, context, sourceRevision, transport, runtime }) {
  const archivePath = path.join(artifactRoot, "LOCAL", "transport", transport.archive.digest, "archive.tar.gz");
  const bundlePath = path.join(artifactRoot, "LOCAL", "transport", transport.archive.digest, "provenance.sigstore.json");
  const workspace = await fsp.mkdtemp(path.join(storeRoot, ".reverify-"));
  await fsp.chmod(workspace, 0o700);
  try {
    const workspaceStatus = await fsp.lstat(workspace, { bigint: true });
    await assertOwnedTrustedNode(workspace, workspaceStatus, runtime, "retained-archive verification workspace", { exactMode: 0o700 });
    const beforeArchive = await digestRegularFile(archivePath, "retained archive before reconstructive extraction", context.policy.archiveLimits.maxArchiveBytes);
    const beforeBundle = await digestRegularFile(bundlePath, "retained bundle before reconstructive extraction", context.policy.provenanceBundleBytes.maxBundleBytes);
    assert(beforeArchive.digest === transport.archive.digest && beforeArchive.size === transport.archive.size && fileObjectEqual(beforeArchive.stat, transport.archive.stat), "retained archive changed after fresh provenance verification");
    assert(beforeBundle.digest === transport.bundle.digest && beforeBundle.size === transport.bundle.size && fileObjectEqual(beforeBundle.stat, transport.bundle.stat), "retained bundle changed after fresh provenance verification");

    const candidateRoot = path.join(workspace, "candidate");
    await fsp.mkdir(candidateRoot, { mode: 0o700 });
    const extracted = await extractAuthenticatedArchive(archivePath, candidateRoot, context, sourceRevision);
    await invokeFailpoint(runtime, "after-retained-reconstruction-extraction", { archivePath, bundlePath });
    const afterArchive = await digestRegularFile(archivePath, "retained archive after reconstructive extraction", context.policy.archiveLimits.maxArchiveBytes);
    const afterBundle = await digestRegularFile(bundlePath, "retained bundle after reconstructive extraction", context.policy.provenanceBundleBytes.maxBundleBytes);
    assert(afterArchive.digest === beforeArchive.digest && afterArchive.size === beforeArchive.size && fileObjectEqual(afterArchive.stat, beforeArchive.stat), "retained archive mutated during reconstructive extraction");
    assert(afterBundle.digest === beforeBundle.digest && afterBundle.size === beforeBundle.size && fileObjectEqual(afterBundle.stat, beforeBundle.stat), "retained bundle mutated during reconstructive extraction");

    assert(Buffer.from(extracted.manifestBytes).equals(manifestBytes), "retained archive manifest bytes differ from installed canonical manifest");
    assertSame(extracted.manifest, manifest, "retained archive versus installed manifest");
    await applyNarrowModes(candidateRoot, extracted.manifest);
    const extractedGraph = await validateInstalledPayload(candidateRoot, extracted.manifest, context, runtime);
    await validateManifestAuthorities(candidateRoot, extracted.manifest, context, sourceRevision, { ...runtime.dependencies, repoRoot });
    assertSame(extractedGraph, installedGraph, "retained archive versus installed full payload graph");
  } finally {
    await removePrivateWorkspace(workspace);
  }
}

async function verifyPortableEngineStoreCore(options, runtime, checkedContext = null) {
  const dependencies = runtime.dependencies;
  const repoRoot = await requireCheckoutRoot(options.repoRoot, runtime);
  const sourceRevision = options.expectedSourceRevision;
  assertSourceRevision(sourceRevision, "externally selected checkout revision");
  assertCurrentCheckoutRevision(repoRoot, sourceRevision, dependencies);
  const context = checkedContext ?? await loadCheckedContext(repoRoot, sourceRevision, dependencies);
  const artifactId = options.artifactId;
  assertSemanticDigest(artifactId, "portable artifact ID");
  const storeRoot = await requireStoreRoot(repoRoot, runtime);
  const artifactRoot = path.join(storeRoot, artifactId);
  const rootStatus = await fsp.lstat(artifactRoot, { bigint: true });
  assert(rootStatus.isDirectory() && !rootStatus.isSymbolicLink(), "portable artifact store entry is redirected or not a directory");
  await assertOwnedTrustedNode(artifactRoot, rootStatus, runtime, "portable artifact store entry");
  assert((Number(rootStatus.mode & 0o777n) & 0o222) === 0, "portable artifact store entry is writable");
  const rootNames = (await fsp.readdir(artifactRoot)).sort(compareUtf8);
  assertSame(rootNames, ["LOCAL", "META-INF", "payload"], "portable artifact store root membership");
  for (const relativePath of ["META-INF", "LOCAL", "LOCAL/transport"]) {
    const status = await fsp.lstat(path.join(artifactRoot, ...relativePath.split("/")), { bigint: true });
    assert(status.isDirectory() && !status.isSymbolicLink(), `${relativePath}: installed store directory is redirected`);
    await assertOwnedTrustedNode(path.join(artifactRoot, ...relativePath.split("/")), status, runtime, `${relativePath}: installed store directory`);
    assert((Number(status.mode & 0o777n) & 0o222) === 0, `${relativePath}: installed store directory is writable`);
  }
  for (const relativePath of [MANIFEST_PATH, "LOCAL/COMPLETE"]) {
    const status = await fsp.lstat(path.join(artifactRoot, ...relativePath.split("/")), { bigint: true });
    assert(status.isFile() && !status.isSymbolicLink(), `${relativePath}: installed store member is redirected or not regular`);
    await assertOwnedTrustedNode(path.join(artifactRoot, ...relativePath.split("/")), status, runtime, `${relativePath}: installed store member`);
    assert(status.nlink === 1n, `${relativePath}: installed store member is hard-linked`);
    assert((Number(status.mode & 0o777n) & 0o222) === 0, `${relativePath}: installed store member is writable`);
  }
  const manifestBytes = await readBoundedRegular(path.join(artifactRoot, MANIFEST_PATH), "installed portable manifest", context.policy.archiveLimits.maxRegularFileBytes);
  const manifest = validateManifestShape(manifestBytes, context, sourceRevision);
  assert(manifest.artifactId === artifactId, "store directory and manifest artifact IDs differ");
  const installedGraph = await validateInstalledPayload(artifactRoot, manifest, context, runtime);
  await validateManifestAuthorities(artifactRoot, manifest, context, sourceRevision, { ...dependencies, repoRoot });
  const localNames = (await fsp.readdir(path.join(artifactRoot, "LOCAL"))).sort(compareUtf8);
  assertSame(localNames, ["COMPLETE", "transport"], "portable artifact LOCAL membership");
  const completionBytes = await readBoundedRegular(path.join(artifactRoot, "LOCAL", "COMPLETE"), "store completion marker", 64 * 1024);
  const completion = parseBoundedJson(completionBytes, "store completion marker");
  assertCanonicalJsonBytes(completionBytes, completion, "store completion marker");
  assertSame(completion, {
    schema: runtime.contract.completionSchema,
    artifactId,
    manifestDigest: semanticDigest("ibex.portable-engine-manifest-digest.v1", manifest),
  }, "store completion marker");
  const transportNames = (await fsp.readdir(path.join(artifactRoot, "LOCAL", "transport"))).sort(compareUtf8);
  assert(transportNames.length > 0, "portable artifact store has no retained transport record");
  for (const name of transportNames) {
    assertRawDigest(name, "retained transport directory");
    await validateTransportRecordShape(artifactRoot, name, runtime);
  }
  const selectedArchiveDigest = options.archiveDigest ?? transportNames[0];
  assert(transportNames.includes(selectedArchiveDigest), "selected transport record is absent");
  const verifyAttestation = dependencies.verifyAttestation ?? unavailableRealVerifier;
  const transport = await validateTransportRecord({ artifactRoot, archiveDigest: selectedArchiveDigest, manifest, context, sourceRevision, verifyAttestation, runtime });
  await verifyRetainedArchiveMaterialization({ repoRoot, storeRoot, artifactRoot, manifest, manifestBytes, installedGraph, context, sourceRevision, transport, runtime });
  return { artifactRoot, manifest, context, transport };
}

async function requireCheckoutRoot(input, runtime) {
  const resolved = path.resolve(input ?? process.cwd());
  const real = await fsp.realpath(resolved);
  // macOS exposes /var through /private/var. Canonicalize pre-existing host
  // ancestors, then enforce no-follow semantics on every store component we
  // create below; an ambient alias to the checkout is not an artifact selector.
  const status = await fsp.lstat(real, { bigint: true });
  assert(status.isDirectory() && !status.isSymbolicLink(), "checkout root is not one no-follow directory");
  await assertOwnedTrustedNode(real, status, runtime, "checkout root");
  return real;
}

async function ensureDirectoryNoFollow(directory, mode, runtime, label, { exactMode } = {}) {
  try {
    await fsp.mkdir(directory, { mode });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  const status = await fsp.lstat(directory, { bigint: true });
  assert(status.isDirectory() && !status.isSymbolicLink(), `${directory}: store path component is redirected or not a directory`);
  await assertOwnedTrustedNode(directory, status, runtime, label, { exactMode });
}

async function requireStoreRoot(repoRoot, runtime) {
  const target = path.join(repoRoot, "target");
  const store = path.join(target, runtime.contract.storeDirectory);
  await ensureDirectoryNoFollow(target, 0o700, runtime, "checkout target directory");
  await ensureDirectoryNoFollow(store, 0o700, runtime, "portable engine store root", { exactMode: 0o700 });
  await fsyncDirectory(store);
  await fsyncDirectory(target);
  await fsyncDirectory(repoRoot);
  return store;
}

async function lstatMaybe(filePath) {
  try {
    return await fsp.lstat(filePath, { bigint: true });
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function defaultProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") return false;
    if (error.code === "EPERM") return true;
    throw error;
  }
}

async function pause(milliseconds) {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function nextNonce(runtime) {
  const value = runtime.dependencies.randomNonce?.() ?? randomBytes(16).toString("hex");
  assert(typeof value === "string" && /^[0-9a-f]{32}$/u.test(value), "installer nonce must be 32 lowercase hexadecimal digits");
  return value;
}

async function invokeFailpoint(runtime, name, details = {}) {
  await runtime.dependencies.failpoint?.(name, details);
}

async function requirePrivateControlDirectory(directory, runtime, label) {
  await ensureDirectoryNoFollow(directory, 0o700, runtime, label, { exactMode: 0o700 });
  await fsyncDirectory(directory);
  await fsyncDirectory(path.dirname(directory));
}

async function acquireArtifactLock(storeRoot, artifactId, runtime) {
  const locksRoot = path.join(storeRoot, ".locks");
  await requirePrivateControlDirectory(locksRoot, runtime, "portable engine lock directory");
  const lockPath = path.join(locksRoot, `${artifactId}.lock`);
  const token = nextNonce(runtime);
  const owner = {
    schema: runtime.contract.lockSchema,
    pid: runtime.dependencies.processId ?? process.pid,
    token,
  };
  assert(Number.isSafeInteger(owner.pid) && owner.pid > 0, "installer lock PID is invalid");
  const claimPath = path.join(locksRoot, `.claim-${artifactId}.${token}`);
  const ownerName = "OWNER";
  await fsp.mkdir(claimPath, { mode: 0o700 });
  await writeCanonicalExclusive(path.join(claimPath, ownerName), owner, 0o600);
  await fsyncDirectory(claimPath);
  await fsyncDirectory(locksRoot);
  let claimed = false;
  try {
    for (let attempt = 0; attempt < 400; attempt += 1) {
      try {
        await fsp.rename(claimPath, lockPath);
        claimed = true;
        await fsyncDirectory(locksRoot);
        return { lockPath, locksRoot, owner, ownerName };
      } catch (error) {
        const existingStatus = await lstatMaybe(lockPath);
        if (!existingStatus || !["EACCES", "EEXIST", "ENOTEMPTY"].includes(error.code)) throw error;
        assert(existingStatus.isDirectory() && !existingStatus.isSymbolicLink(), "existing portable engine install lock is redirected or not a directory");
        await assertOwnedTrustedNode(lockPath, existingStatus, runtime, "existing portable engine install lock", { exactMode: 0o700 });
        assertSame((await fsp.readdir(lockPath)).sort(compareUtf8), [ownerName], "existing portable engine install lock membership");
        const ownerPath = path.join(lockPath, ownerName);
        const ownerStatus = await fsp.lstat(ownerPath, { bigint: true });
        requireRegularStat(ownerStatus, "existing portable engine install lock owner", 64 * 1024);
        await assertOwnedTrustedNode(ownerPath, ownerStatus, runtime, "existing portable engine install lock owner", { exactMode: 0o600 });
        assert(ownerStatus.nlink === 1n, "existing portable engine install lock owner is hard-linked");
        const bytes = await readBoundedRegular(ownerPath, "existing portable engine install lock owner", 64 * 1024);
        const observed = parseBoundedJson(bytes, "existing portable engine install lock owner");
        assertCanonicalJsonBytes(bytes, observed, "existing portable engine install lock owner");
        assertExactKeys(observed, ["schema", "pid", "token"], "existing portable engine install lock owner");
        assert(observed.schema === runtime.contract.lockSchema && Number.isSafeInteger(observed.pid) && observed.pid > 0 && /^[0-9a-f]{32}$/u.test(observed.token), "existing portable engine install lock metadata is invalid");
        const alive = await Promise.resolve((runtime.dependencies.isProcessAlive ?? defaultProcessAlive)(observed.pid));
        if (!alive) {
          const stalePath = path.join(locksRoot, `.stale-${artifactId}.${nextNonce(runtime)}`);
          await fsp.rename(lockPath, stalePath);
          await fsyncDirectory(locksRoot);
          await fsp.unlink(path.join(stalePath, ownerName));
          await fsp.rmdir(stalePath);
          await fsyncDirectory(locksRoot);
          continue;
        }
        await (runtime.dependencies.sleep ?? pause)(25);
      }
    }
    fail(`${artifactId}: timed out waiting for the per-artifact installation lock`);
  } finally {
    if (!claimed) {
      await fsp.unlink(path.join(claimPath, ownerName)).catch(() => {});
      await fsp.rmdir(claimPath).catch(() => {});
      await fsyncDirectory(locksRoot).catch(() => {});
    }
  }
}

async function releaseArtifactLock(lock, runtime) {
  const ownerPath = path.join(lock.lockPath, lock.ownerName);
  const bytes = await readBoundedRegular(ownerPath, "owned portable engine install lock", 64 * 1024);
  const observed = parseBoundedJson(bytes, "owned portable engine install lock");
  assertSame(observed, lock.owner, "owned portable engine install lock token");
  await fsp.unlink(ownerPath);
  await fsp.rmdir(lock.lockPath);
  await fsyncDirectory(lock.locksRoot);
}

async function withArtifactLock(storeRoot, artifactId, runtime, action) {
  const lock = await acquireArtifactLock(storeRoot, artifactId, runtime);
  try {
    await invokeFailpoint(runtime, "after-artifact-lock", { artifactId });
    return await action();
  } finally {
    await releaseArtifactLock(lock, runtime);
  }
}

async function requireQuarantineRoot(storeRoot, runtime) {
  const quarantineRoot = path.join(storeRoot, ".quarantine");
  await requirePrivateControlDirectory(quarantineRoot, runtime, "portable engine quarantine directory");
  return quarantineRoot;
}

// @ref LLP 0035#content-addressed-installation — invalid exact destinations
// are moved as opaque entries into durable quarantine, never followed or
// recursively deleted in place.
async function quarantineExactDestination(storeRoot, finalRoot, artifactId, runtime, reason) {
  const quarantineRoot = await requireQuarantineRoot(storeRoot, runtime);
  const quarantinePath = path.join(quarantineRoot, `${artifactId}.${nextNonce(runtime)}`);
  const original = await lstatMaybe(finalRoot);
  assert(original, "invalid exact destination disappeared before quarantine");
  let directoryHandle;
  try {
    await fsp.rename(finalRoot, quarantinePath);
  } catch (error) {
    if (error.code !== "EACCES" || !original.isDirectory() || original.isSymbolicLink() || original.uid !== BigInt(runtime.effectiveUid)) throw error;
    directoryHandle = await fsp.open(finalRoot, fs.constants.O_RDONLY | NOFOLLOW);
    const pinned = await directoryHandle.stat({ bigint: true });
    assert(pinned.dev === original.dev && pinned.ino === original.ino && pinned.isDirectory(), "invalid destination changed before no-follow quarantine widening");
    const originalMode = Number(original.mode & 0o777n);
    await directoryHandle.chmod(originalMode | 0o200);
    await directoryHandle.sync();
    try {
      await fsp.rename(finalRoot, quarantinePath);
    } finally {
      await directoryHandle.chmod(originalMode).catch(() => {});
      await directoryHandle.sync().catch(() => {});
      await directoryHandle.close();
      directoryHandle = null;
    }
  } finally {
    if (directoryHandle) await directoryHandle.close().catch(() => {});
  }
  await fsyncDirectory(storeRoot);
  await fsyncDirectory(quarantineRoot);
  await invokeFailpoint(runtime, "after-invalid-destination-quarantine", { artifactId, quarantinePath });
  return { path: quarantinePath, reason: reason instanceof Error ? reason.message : String(reason) };
}

async function listArtifactQuarantines(storeRoot, artifactId, runtime) {
  const quarantineRoot = path.join(storeRoot, ".quarantine");
  if (!(await lstatMaybe(quarantineRoot))) return [];
  const rootStatus = await fsp.lstat(quarantineRoot, { bigint: true });
  assert(rootStatus.isDirectory() && !rootStatus.isSymbolicLink(), "portable engine quarantine root is redirected");
  await assertOwnedTrustedNode(quarantineRoot, rootStatus, runtime, "portable engine quarantine directory", { exactMode: 0o700 });
  const prefix = `${artifactId}.`;
  const output = [];
  for (const name of (await fsp.readdir(quarantineRoot)).sort(compareUtf8)) {
    if (!name.startsWith(prefix)) continue;
    assert(/^[A-Za-z0-9_-]+\.[0-9a-f]{32}$/u.test(name), "portable engine quarantine entry has an invalid name");
    const quarantinePath = path.join(quarantineRoot, name);
    await fsp.lstat(quarantinePath, { bigint: true });
    output.push(quarantinePath);
  }
  return output;
}

async function finalizeFreshStore({ candidateRoot, manifest, archivePath, bundlePath, verificationBytes, receipt, context, runtime }) {
  await applyNarrowModes(candidateRoot, manifest);
  await fsp.mkdir(path.join(candidateRoot, "LOCAL", "transport"), { recursive: true, mode: 0o700 });
  await createTransportRecord({ artifactRoot: candidateRoot, archivePath, bundlePath, verificationBytes, receipt, context, contract: runtime.contract });
  const completion = {
    schema: runtime.contract.completionSchema,
    artifactId: manifest.artifactId,
    manifestDigest: receipt.manifestDigest,
  };
  await writeCanonicalExclusive(path.join(candidateRoot, "LOCAL", "COMPLETE"), completion);
  await fsp.chmod(path.join(candidateRoot, "LOCAL", "COMPLETE"), 0o444);
  await fsp.chmod(path.join(candidateRoot, "LOCAL", "transport"), 0o555);
  await fsyncDirectory(path.join(candidateRoot, "LOCAL"));
  await fsp.chmod(path.join(candidateRoot, "LOCAL"), 0o555);
  await fsyncDirectory(candidateRoot);
  // macOS refuses to rename a directory whose owner-write bit is absent.
  // Keep only this private candidate root writable until the atomic rename;
  // identity-bearing descendants and completion markers are already narrow.
  await fsp.chmod(candidateRoot, 0o700);
  await fsyncTreeBottomUp(candidateRoot, runtime);
}

async function publishAdditionalTransport(candidateRoot, existingRoot, archiveDigest, runtime) {
  const sourceParent = path.join(candidateRoot, "LOCAL", "transport");
  const source = path.join(sourceParent, archiveDigest);
  const destinationParent = path.join(existingRoot, "LOCAL", "transport");
  const destination = path.join(destinationParent, archiveDigest);
  await fsp.chmod(sourceParent, 0o755);
  await fsp.chmod(source, 0o700);
  await fsp.chmod(destinationParent, 0o755);
  let moved = false;
  try {
    await fsp.rename(source, destination);
    moved = true;
    await invokeFailpoint(runtime, "after-additional-transport-rename", { archiveDigest, destination });
    await fsp.chmod(destination, 0o555);
    await fsyncDirectory(destination);
    await fsyncDirectory(sourceParent);
    await fsyncDirectory(destinationParent);
  } finally {
    if (moved) await fsp.chmod(destination, 0o555).catch(() => {});
    await fsp.chmod(sourceParent, 0o555).catch(() => {});
    await fsp.chmod(destinationParent, 0o555).catch(() => {});
    await fsyncDirectory(sourceParent).catch(() => {});
    if (moved) await fsyncDirectory(destination).catch(() => {});
    await fsyncDirectory(destinationParent).catch(() => {});
  }
}

async function publishFreshCandidate(candidateRoot, finalRoot, storeRoot, runtime) {
  assert(!(await lstatMaybe(finalRoot)), "portable artifact destination appeared while holding its installation lock");
  const sourceParent = path.dirname(candidateRoot);
  await fsp.rename(candidateRoot, finalRoot);
  await invokeFailpoint(runtime, "after-candidate-rename", { finalRoot });
  await fsp.chmod(finalRoot, 0o555);
  await fsyncDirectory(finalRoot);
  await invokeFailpoint(runtime, "after-published-root-narrow", { finalRoot });
  await fsyncDirectory(sourceParent);
  await fsyncDirectory(storeRoot);
  await invokeFailpoint(runtime, "after-published-parent-fsync", { finalRoot });
}

async function installPortableEngineCore(options, runtime) {
  const dependencies = runtime.dependencies;
  const repoRoot = await requireCheckoutRoot(options.repoRoot, runtime);
  const sourceRevision = options.expectedSourceRevision;
  assertSourceRevision(sourceRevision, "externally selected checkout revision");
  assertCurrentCheckoutRevision(repoRoot, sourceRevision, dependencies);
  const context = await loadCheckedContext(repoRoot, sourceRevision, dependencies);
  const storeRoot = await requireStoreRoot(repoRoot, runtime);
  const workspace = await fsp.mkdtemp(path.join(storeRoot, ".install-"));
  await fsp.chmod(workspace, 0o700);
  await assertOwnedTrustedNode(workspace, await fsp.lstat(workspace, { bigint: true }), runtime, "portable engine installation workspace", { exactMode: 0o700 });
  const pinnedArchive = path.join(workspace, "transport.archive");
  const pinnedBundle = path.join(workspace, "transport.bundle");
  try {
    const archive = await copyPinnedRegular(options.archivePath, pinnedArchive, "portable engine archive", context.policy.archiveLimits.maxArchiveBytes);
    const bundle = await copyPinnedRegular(options.bundlePath, pinnedBundle, "portable engine provenance bundle", context.policy.provenanceBundleBytes.maxBundleBytes);
    const expectations = buildFixedVerifierExpectations(context.policy, sourceRevision, path.basename(options.archivePath));
    const expectationsBytes = Buffer.from(canonicalJson(expectations), "utf8");
    const verifyAttestation = dependencies.verifyAttestation ?? unavailableRealVerifier;
    const verificationBytes = Buffer.from(await verifyAttestation({
      archivePath: pinnedArchive,
      bundlePath: pinnedBundle,
      expectations,
      expectationsBytes,
      context,
    }));
    const verification = validateCanonicalVerificationResult(verificationBytes, { expectationsBytes, expectations, archive, bundle });
    dependencies.onAuthenticated?.({ archive, bundle, verification });
    const afterAuthentication = await digestRegularFile(pinnedArchive, "authenticated pinned archive", context.policy.archiveLimits.maxArchiveBytes);
    assert(afterAuthentication.digest === archive.digest && afterAuthentication.size === archive.size && fileObjectEqual(afterAuthentication.stat, archive.stat), "authenticated archive mutated before parsing");
    const bundleAfterAuthentication = await digestRegularFile(pinnedBundle, "authenticated pinned provenance bundle", context.policy.provenanceBundleBytes.maxBundleBytes);
    assert(bundleAfterAuthentication.digest === bundle.digest && bundleAfterAuthentication.size === bundle.size && fileObjectEqual(bundleAfterAuthentication.stat, bundle.stat), "authenticated provenance bundle mutated before archive parsing");

    const candidateRoot = path.join(workspace, "candidate");
    await fsp.mkdir(candidateRoot, { mode: 0o700 });
    const extracted = await extractAuthenticatedArchive(pinnedArchive, candidateRoot, context, sourceRevision, dependencies);
    const afterExtraction = await digestRegularFile(pinnedArchive, "authenticated pinned archive after extraction", context.policy.archiveLimits.maxArchiveBytes);
    assert(afterExtraction.digest === archive.digest && afterExtraction.size === archive.size && fileObjectEqual(afterExtraction.stat, archive.stat), "authenticated archive mutated during extraction");
    const bundleAfterExtraction = await digestRegularFile(pinnedBundle, "authenticated pinned provenance bundle after extraction", context.policy.provenanceBundleBytes.maxBundleBytes);
    assert(bundleAfterExtraction.digest === bundle.digest && bundleAfterExtraction.size === bundle.size && fileObjectEqual(bundleAfterExtraction.stat, bundle.stat), "authenticated provenance bundle mutated during extraction");
    await applyNarrowModes(candidateRoot, extracted.manifest);
    const candidateGraph = await validateInstalledPayload(candidateRoot, extracted.manifest, context, runtime);
    await validateManifestAuthorities(candidateRoot, extracted.manifest, context, sourceRevision, { ...dependencies, repoRoot });
    const receipt = buildReceipt({ manifest: extracted.manifest, archive, bundle, context, sourceRevision, contract: runtime.contract });
    validateReceiptSchema(context, receipt, "$ installation receipt");
    await finalizeFreshStore({ candidateRoot, manifest: extracted.manifest, archivePath: pinnedArchive, bundlePath: pinnedBundle, verificationBytes, receipt, context, runtime });
    const candidateTransport = await validateTransportRecord({
      artifactRoot: candidateRoot,
      archiveDigest: archive.digest,
      manifest: extracted.manifest,
      context,
      sourceRevision,
      verifyAttestation,
      runtime,
    });
    await verifyRetainedArchiveMaterialization({ repoRoot, storeRoot, artifactRoot: candidateRoot, manifest: extracted.manifest, manifestBytes: extracted.manifestBytes, installedGraph: candidateGraph, context, sourceRevision, transport: candidateTransport, runtime });

    const finalRoot = path.join(storeRoot, extracted.manifest.artifactId);
    return await withArtifactLock(storeRoot, extracted.manifest.artifactId, runtime, async () => {
      let installed = false;
      let replacedInvalid = false;
      let currentQuarantine = null;
      const destinationStatus = await lstatMaybe(finalRoot);
      if (!destinationStatus) {
        await publishFreshCandidate(candidateRoot, finalRoot, storeRoot, runtime);
        installed = true;
      } else {
        const destinationTransport = path.join(finalRoot, "LOCAL", "transport", archive.digest);
        const destinationTransportExists = Boolean(await lstatMaybe(destinationTransport));
        let existing;
        try {
          existing = await verifyPortableEngineStoreCore({
            repoRoot,
            expectedSourceRevision: sourceRevision,
            artifactId: extracted.manifest.artifactId,
            archiveDigest: destinationTransportExists ? archive.digest : undefined,
          }, runtime, context);
          assertSame(existing.manifest, extracted.manifest, "existing store portable identity");
        } catch (error) {
          currentQuarantine = await quarantineExactDestination(storeRoot, finalRoot, extracted.manifest.artifactId, runtime, error);
          await publishFreshCandidate(candidateRoot, finalRoot, storeRoot, runtime);
          installed = true;
          replacedInvalid = true;
        }
        if (existing && !destinationTransportExists) {
          await publishAdditionalTransport(candidateRoot, finalRoot, archive.digest, runtime);
        }
      }
      const selected = await verifyPortableEngineStoreCore({
        repoRoot,
        expectedSourceRevision: sourceRevision,
        artifactId: extracted.manifest.artifactId,
        archiveDigest: archive.digest,
      }, runtime, context);
      const quarantines = await listArtifactQuarantines(storeRoot, extracted.manifest.artifactId, runtime);
      return { ...selected, installed, replacedInvalid, quarantine: currentQuarantine, quarantines, diagnosticOnly: true };
    });
  } finally {
    // Never follow or recursively delete a caller-selected path: workspace is
    // the exact mkdtemp result beneath the validated checkout-local store.
    await removePrivateWorkspace(workspace);
  }
}

async function verifyWithArtifactLock(options, runtime) {
  assertSemanticDigest(options.artifactId, "portable artifact ID");
  const repoRoot = await requireCheckoutRoot(options.repoRoot, runtime);
  const storeRoot = await requireStoreRoot(repoRoot, runtime);
  return await withArtifactLock(storeRoot, options.artifactId, runtime, async () => verifyPortableEngineStoreCore(options, runtime));
}

export async function installPortableEngineProductionCore(options) {
  return await installPortableEngineCore(options, createRuntime(PRODUCTION_STORE_CONTRACT, {}));
}

export async function verifyPortableEngineStoreProductionCore(options) {
  return await verifyWithArtifactLock(options, createRuntime(PRODUCTION_STORE_CONTRACT, {}));
}

function testRuntime(dependencies = {}) {
  return createRuntime(TEST_STORE_CONTRACT, {
    effectiveUid: typeof process.geteuid === "function" ? process.geteuid() : 0,
    hasExtendedAcl: async () => false,
    ...dependencies,
  });
}

export async function installPortableEngineTestOnly(options, dependencies = {}) {
  return await installPortableEngineCore(options, testRuntime(dependencies));
}

export async function verifyPortableEngineStoreTestOnly(options, dependencies = {}) {
  return await verifyWithArtifactLock(options, testRuntime(dependencies));
}

export const buildFixedVerifierExpectationsTestOnly = buildFixedVerifierExpectations;
export const detectMacOsExtendedAclTestOnly = defaultHasExtendedAcl;
