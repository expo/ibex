// Local selection is path-bearing; promotion authority retains only the
// exact post-link provenance and executable-byte identity projected here.
//
// @ref LLP 0035#reports-and-advertisements — publication authority must be
// locality-free while retaining the exact authenticated executable lineage.

import fs from "node:fs";
import path from "node:path";
import {
  canonicalJson,
  parseJsonStrict,
  semanticDigest,
} from "../../../../scripts/portable-engine-contract.mjs";

const SELECTION_SCHEMA =
  "ibex/portable-engine-physical-promotion-conformance-runner/1";
const BINDING_DOMAIN = "ibex:capsec:conformance-runner-binding:1";
const SOURCE_REVISION_PATTERN = /^[0-9a-f]{40}$/u;
const SEMANTIC_DIGEST_PATTERN =
  /^sha256-[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u;
const RAW_DIGEST_PATTERN = /^sha256-[0-9a-f]{64}$/u;
const MAX_SELECTION_BYTES = 1024 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function exactKeys(value, keys, label) {
  invariant(
    value && typeof value === "object" && !Array.isArray(value),
    `${label} must be an object`,
  );
  invariant(
    same(Object.keys(value).sort(), [...keys].sort()),
    `${label} has unknown or missing fields`,
  );
}

function ownedByEffectiveUser(metadata) {
  const effectiveUid =
    typeof process.geteuid === "function"
      ? process.geteuid()
      : typeof process.getuid === "function"
        ? process.getuid()
        : null;
  return effectiveUid === null || metadata.uid === BigInt(effectiveUid);
}

function readPinnedCanonicalJson(filePath, label) {
  const absolute = path.resolve(filePath);
  const before = fs.lstatSync(absolute, { bigint: true });
  invariant(
    before.isFile() &&
      !before.isSymbolicLink() &&
      before.nlink === 1n &&
      ownedByEffectiveUser(before) &&
      before.size > 0n &&
      before.size <= BigInt(MAX_SELECTION_BYTES),
    `${label} is not one bounded, effective-UID-owned regular file`,
  );
  const descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    invariant(
      opened.isFile() &&
        opened.nlink === 1n &&
        ownedByEffectiveUser(opened) &&
        opened.dev === before.dev &&
        opened.ino === before.ino &&
        opened.size === before.size,
      `${label} changed while opening`,
    );
    const bytes = fs.readFileSync(descriptor);
    const finalized = fs.fstatSync(descriptor, { bigint: true });
    const after = fs.lstatSync(absolute, { bigint: true });
    for (const observed of [finalized, after]) {
      invariant(
        observed.isFile() &&
          !observed.isSymbolicLink() &&
          observed.nlink === 1n &&
          ownedByEffectiveUser(observed) &&
          observed.dev === opened.dev &&
          observed.ino === opened.ino &&
          observed.size === opened.size &&
          observed.mtimeNs === opened.mtimeNs &&
          observed.ctimeNs === opened.ctimeNs,
        `${label} changed while reading`,
      );
    }
    const value = parseJsonStrict(bytes, label);
    invariant(
      bytes.equals(Buffer.from(canonicalJson(value), "utf8")),
      `${label} is not exact canonical JSON`,
    );
    return value;
  } finally {
    fs.closeSync(descriptor);
  }
}

export function validateConformanceRunnerBinding(
  binding,
  { sourceRevision, sourceTreeDigest } = {},
) {
  exactKeys(
    binding,
    [
      "sourceRevision",
      "sourceTreeDigest",
      "artifactId",
      "buildConsumptionDigest",
      "postLinkSetDigest",
      "verificationDigest",
      "testExecutableDigest",
    ],
    "conformance-runner binding",
  );
  invariant(
    SOURCE_REVISION_PATTERN.test(binding.sourceRevision) &&
      SEMANTIC_DIGEST_PATTERN.test(binding.sourceTreeDigest) &&
      SEMANTIC_DIGEST_PATTERN.test(binding.artifactId) &&
      SEMANTIC_DIGEST_PATTERN.test(binding.buildConsumptionDigest) &&
      SEMANTIC_DIGEST_PATTERN.test(binding.postLinkSetDigest) &&
      SEMANTIC_DIGEST_PATTERN.test(binding.verificationDigest) &&
      RAW_DIGEST_PATTERN.test(binding.testExecutableDigest),
    "conformance-runner binding is malformed",
  );
  invariant(
    (sourceRevision === undefined ||
      binding.sourceRevision === sourceRevision) &&
      (sourceTreeDigest === undefined ||
        binding.sourceTreeDigest === sourceTreeDigest),
    "conformance-runner binding names another source revision or tree",
  );
  return binding;
}

export function conformanceRunnerBindingDigest(binding) {
  validateConformanceRunnerBinding(binding);
  return semanticDigest(BINDING_DOMAIN, binding);
}

export function readCanonicalConformanceRunnerSelection({
  selectionPath,
  repoRoot,
  sourceRevision,
  sourceTreeDigest,
}) {
  invariant(
    SOURCE_REVISION_PATTERN.test(sourceRevision) &&
      SEMANTIC_DIGEST_PATTERN.test(sourceTreeDigest),
    "current conformance-runner source binding is malformed",
  );
  const root = fs.realpathSync(path.resolve(repoRoot));
  const selection = readPinnedCanonicalJson(
    selectionPath,
    "canonical conformance-runner selection",
  );
  exactKeys(
    selection,
    [
      "schema",
      "sourceRevision",
      "artifactId",
      "cargoMessagesDigest",
      "buildConsumptionDigest",
      "postLinkSetDigest",
      "postLinkCompletionRawDigest",
      "executablePath",
      "executableDigest",
      "executableSize",
      "verificationDigest",
    ],
    "canonical conformance-runner selection",
  );
  invariant(
    selection.schema === SELECTION_SCHEMA &&
      selection.sourceRevision === sourceRevision &&
      SEMANTIC_DIGEST_PATTERN.test(selection.artifactId) &&
      RAW_DIGEST_PATTERN.test(selection.cargoMessagesDigest) &&
      SEMANTIC_DIGEST_PATTERN.test(selection.buildConsumptionDigest) &&
      SEMANTIC_DIGEST_PATTERN.test(selection.postLinkSetDigest) &&
      RAW_DIGEST_PATTERN.test(selection.postLinkCompletionRawDigest) &&
      RAW_DIGEST_PATTERN.test(selection.executableDigest) &&
      Number.isSafeInteger(selection.executableSize) &&
      selection.executableSize > 0 &&
      SEMANTIC_DIGEST_PATTERN.test(selection.verificationDigest),
    "canonical conformance-runner selection is malformed or names another source",
  );
  invariant(
    typeof selection.executablePath === "string" &&
      selection.executablePath.startsWith("target/") &&
      path.posix.normalize(selection.executablePath) ===
        selection.executablePath &&
      !selection.executablePath.includes("\\") &&
      !/[\u0000-\u001f\u007f]/u.test(selection.executablePath),
    "canonical conformance-runner selection has an unsafe executable path",
  );
  const executablePath = path.resolve(root, selection.executablePath);
  const targetRoot = fs.realpathSync(path.join(root, "target"));
  const relative = path.relative(targetRoot, executablePath);
  invariant(
    relative !== "" &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    "canonical conformance-runner selection escaped target/",
  );
  const binding = validateConformanceRunnerBinding(
    {
      sourceRevision: selection.sourceRevision,
      sourceTreeDigest,
      artifactId: selection.artifactId,
      buildConsumptionDigest: selection.buildConsumptionDigest,
      postLinkSetDigest: selection.postLinkSetDigest,
      verificationDigest: selection.verificationDigest,
      testExecutableDigest: selection.executableDigest,
    },
    { sourceRevision, sourceTreeDigest },
  );
  return {
    binding,
    bindingDigest: conformanceRunnerBindingDigest(binding),
    executablePath,
    selection,
  };
}
