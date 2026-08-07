// Refuse product release, product tag, and package publication unless the
// build-carried checked promotion admission authorizes one scoped target.
//
// @ref LLP 0021#a9-appendix--the-scope-digest-join-matrix — M33 closes the
// reset/depublication window while leaving both source-A ceremonies runnable.

import * as fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertExactKeys,
  canonicalJson,
  compareUtf8,
  parseJsonStrict,
  semanticDigest,
} from "./portable-engine-contract.mjs";

const CHECKED_ADMISSION_SCHEMA = "ibex/portable-engine-checked-promotion-admission/2";
const CHECKED_ADMISSION_DOMAIN = "ibex.portable-engine-checked-promotion-admission.v2";
const EMBEDDED_ADMISSION_BASENAME = "portable_engine_promotion_admission.json";
const GATE_INVOCATION = "node scripts/assert-releasable-checked-admission.mjs --admission";
const semanticDigestPattern = /^sha256-[A-Za-z0-9_-]{43}$/u;
const revisionPattern = /^[0-9a-f]{40}$/u;
const moduleFilePath = fileURLToPath(import.meta.url);

// These paths produce inputs for promotion n+1 at the reset revision. Gating
// either one would be circular: the artifacts needed to authorize the next
// admission could not be produced until that admission already existed.
export const RELEASE_GATE_EXCLUSIONS = Object.freeze([
  Object.freeze({
    path: ".github/workflows/hermes-artifacts.yml",
    kind: "artifact-source-ceremony",
    requiredText: Object.freeze([
      "ARTIFACT CACHES, not product releases",
      "This is an artifact cache, not a product release.",
    ]),
  }),
  Object.freeze({
    path: ".github/workflows/portable-engine-physical-promotion.yml",
    kind: "artifact-source-ceremony",
    requiredText: Object.freeze([
      "A successful run may upload candidate bytes",
      "separate reviewed one-commit promotion topic",
    ]),
  }),
]);

// Raw pushes and direct registry commands have no build-carried admission
// input to validate. They are therefore outside the product-release interface,
// not alternate release paths: product tags and `cargo publish` must be issued
// only by an enumerated gated workflow. Repository tag protection is the
// external enforcement half of this declaration.
export const RAW_RELEASE_EXCLUSION = Object.freeze({
  productTags: "direct product-tag pushes are forbidden; product tags are created only by an enumerated gated workflow",
  packageRegistries: "direct cargo/npm package publication is forbidden; package publication is performed only by an enumerated gated workflow",
  nonProductTags: "non-product diagnostic/cache tags are permitted only in an explicitly excluded ceremony workflow",
});

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function validateTarget(target, label) {
  assertExactKeys(target, ["triple", "features"], label);
  assert(
    typeof target.triple === "string"
      && /^[a-z0-9_]+(?:-[a-z0-9_]+)+$/u.test(target.triple)
      && target.triple.length <= 128,
    `${label}.triple is malformed`,
  );
  assert(Array.isArray(target.features) && target.features.length > 0, `${label}.features must be a non-empty array`);
  for (const [index, feature] of target.features.entries()) {
    assert(typeof feature === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(feature), `${label}.features[${index}] is malformed`);
    assert(index === 0 || compareUtf8(target.features[index - 1], feature) < 0, `${label}.features must be strictly sorted and unique`);
  }
}

export function validateReleasableCheckedAdmission(bytes) {
  const input = Buffer.from(bytes);
  const admission = parseJsonStrict(input, "build-embedded checked promotion admission");
  assert(
    input.equals(Buffer.from(`${canonicalJson(admission)}\n`, "utf8")),
    "build-embedded checked promotion admission must be canonical JSON plus one LF",
  );
  assertExactKeys(admission, [
    "schema",
    "authorized",
    "currentRevision",
    "sourceRevision",
    "promotionTopicRevision",
    "sourceTreeObjectId",
    "target",
    "portableArtifactId",
    "admissionDigest",
    "admittedScopeDigest",
    "predecessorScopeDigest",
    "verificationDigest",
  ], "build-embedded checked promotion admission");
  assert(admission.schema === CHECKED_ADMISSION_SCHEMA, "build-embedded checked promotion admission has the wrong schema");
  assert(typeof admission.authorized === "boolean", "build-embedded checked promotion admission has no closed authorization outcome");
  assert(revisionPattern.test(admission.currentRevision) && revisionPattern.test(admission.sourceRevision), "build-embedded checked promotion admission revisions are malformed");
  validateTarget(admission.target, "build-embedded checked promotion admission target");
  assert(semanticDigestPattern.test(admission.portableArtifactId), "build-embedded checked promotion admission portable artifact ID is malformed");
  assert(semanticDigestPattern.test(admission.verificationDigest), "build-embedded checked promotion admission verification digest is malformed");
  assert(
    semanticDigest(CHECKED_ADMISSION_DOMAIN, admission, ["verificationDigest"])
      === admission.verificationDigest,
    "build-embedded checked promotion admission verification digest mismatch",
  );
  assert(admission.authorized === true, "product release refused: checked promotion admission is not authorized");
  assert(revisionPattern.test(admission.promotionTopicRevision), "authorized checked promotion admission topic revision is malformed");
  assert(revisionPattern.test(admission.sourceTreeObjectId), "authorized checked promotion admission source tree is malformed");
  assert(admission.currentRevision !== admission.sourceRevision, "authorized checked promotion admission does not advance beyond its source revision");
  assert(admission.promotionTopicRevision !== admission.currentRevision && admission.promotionTopicRevision !== admission.sourceRevision, "authorized checked promotion admission does not distinguish A/P/C revisions");
  assert(semanticDigestPattern.test(admission.admissionDigest), "authorized checked promotion admission digest is malformed");
  assert(semanticDigestPattern.test(admission.admittedScopeDigest), "product release refused: admittedScopeDigest is null or malformed");
  assert(
    admission.predecessorScopeDigest === "genesis"
      || semanticDigestPattern.test(admission.predecessorScopeDigest),
    "authorized checked promotion admission predecessor scope is malformed",
  );
  return Object.freeze(structuredClone(admission));
}

export function assertReleasableCheckedAdmissionFile(filePath) {
  assert(typeof filePath === "string" && filePath.length > 0 && !filePath.includes("\0"), "checked promotion admission path must be one path string");
  const requested = path.resolve(filePath);
  const requestedStatus = fs.lstatSync(requested);
  assert(requestedStatus.isFile() && !requestedStatus.isSymbolicLink(), "build-embedded checked promotion admission path must be a regular non-symlink file");
  const selected = fs.realpathSync(requested);
  assert(selected === requested, "build-embedded checked promotion admission path must be canonical and symlink-free");
  assert(path.basename(selected) === EMBEDDED_ADMISSION_BASENAME, `checked promotion admission must be the build-embedded ${EMBEDDED_ADMISSION_BASENAME}`);
  const status = fs.lstatSync(selected);
  assert(status.isFile() && !status.isSymbolicLink(), "build-embedded checked promotion admission must be a regular file");
  assert(status.size > 0 && status.size <= 1024 * 1024, "build-embedded checked promotion admission has an invalid bounded size");
  return validateReleasableCheckedAdmission(fs.readFileSync(selected));
}

function workflowFiles(repoRoot) {
  const workflowRoot = path.join(repoRoot, ".github", "workflows");
  return fs.readdirSync(workflowRoot, { withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.ya?ml$/u.test(entry.name))
    .map((entry) => `.github/workflows/${entry.name}`)
    .sort(compareUtf8);
}

function productReleaseSignals(text) {
  const signals = [];
  for (const [name, pattern] of [
    ["cargo-publish", /(?:^|[;&|\s])cargo\s+publish(?:\s|$)/mu],
    ["javascript-publish", /(?:^|[;&|\s])(?:npm|bun|pnpm|yarn)\s+publish(?:\s|$)/mu],
    ["github-release-create", /(?:^|[;&|\s])gh\s+release\s+create(?:\s|$)/mu],
    ["git-tag-create", /(?:^|[;&|\s])git\s+tag(?:\s|$)/mu],
    ["product-tag-trigger", /^\s*tags:\s*(?:\[|$)/mu],
    ["release-action", /^\s*uses:\s*[^\s#]*(?:publish|release)[^\s#]*@/mu],
  ]) {
    if (pattern.test(text)) signals.push(name);
  }
  return signals;
}

function scriptEntryPointFiles(repoRoot) {
  const files = [];
  const visit = (absolute, relative) => {
    const entries = fs.readdirSync(absolute, { withFileTypes: true });
    for (const entry of entries) {
      if ([".git", "node_modules", "target", "fixtures"].includes(entry.name)) continue;
      const childAbsolute = path.join(absolute, entry.name);
      const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) visit(childAbsolute, childRelative);
      else if (
        entry.isFile()
          && /\.(?:c?js|mjs|sh|ts)$/u.test(entry.name)
          && !/\.test\.(?:c?js|mjs|ts)$/u.test(entry.name)
      ) files.push(childRelative);
    }
  };
  for (const rootName of ["scripts", "packages"]) {
    const absolute = path.join(repoRoot, rootName);
    if (fs.existsSync(absolute)) visit(absolute, rootName);
  }
  return files.sort(compareUtf8);
}

function packageManifestFiles(repoRoot) {
  const paths = ["package.json"];
  const packagesRoot = path.join(repoRoot, "packages");
  if (!fs.existsSync(packagesRoot)) return paths;
  const visit = (absolute, relative) => {
    for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
      if (["node_modules", "target", "fixtures"].includes(entry.name)) continue;
      const childAbsolute = path.join(absolute, entry.name);
      const childRelative = `${relative}/${entry.name}`;
      if (entry.isDirectory()) visit(childAbsolute, childRelative);
      else if (entry.isFile() && entry.name === "package.json") paths.push(childRelative);
    }
  };
  visit(packagesRoot, "packages");
  return paths.sort(compareUtf8);
}

export function auditReleaseGateCallers(candidateRoot) {
  const repoRoot = fs.realpathSync(path.resolve(candidateRoot));
  const exclusions = new Map(RELEASE_GATE_EXCLUSIONS.map((entry) => [entry.path, entry]));
  const observedExcluded = [];
  const gated = [];
  for (const relativePath of workflowFiles(repoRoot)) {
    const text = fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
    const exclusion = exclusions.get(relativePath);
    if (exclusion) {
      for (const required of exclusion.requiredText) {
        assert(text.includes(required), `${relativePath}: ceremony exclusion marker is missing ${JSON.stringify(required)}`);
      }
      assert(!text.includes(GATE_INVOCATION), `${relativePath}: artifact-source ceremony must remain outside the product-release gate`);
      observedExcluded.push(relativePath);
      continue;
    }
    const signals = productReleaseSignals(text);
    if (signals.length === 0) continue;
    assert(text.includes(GATE_INVOCATION), `${relativePath}: product release path with signals ${signals.join(", ")} does not invoke the shared checked-admission gate`);
    gated.push(relativePath);
  }
  assert(
    canonicalJson(observedExcluded.sort(compareUtf8))
      === canonicalJson([...exclusions.keys()].sort(compareUtf8)),
    "release-gate ceremony exclusion set is not exhaustive",
  );

  for (const relativePath of scriptEntryPointFiles(repoRoot)) {
    if (relativePath === "scripts/assert-releasable-checked-admission.mjs") continue;
    const text = fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
    const signals = productReleaseSignals(text);
    if (signals.length === 0) continue;
    assert(text.includes(GATE_INVOCATION), `${relativePath}: publisher script with signals ${signals.join(", ")} does not invoke the shared checked-admission gate`);
    gated.push(relativePath);
  }
  for (const relativePath of packageManifestFiles(repoRoot)) {
    const packageJson = JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));
    for (const [name, command] of Object.entries(packageJson.scripts ?? {})) {
      if (typeof command !== "string" || productReleaseSignals(command).length === 0) continue;
      assert(command.includes(GATE_INVOCATION), `${relativePath} script ${name}: publication does not invoke the shared checked-admission gate`);
      gated.push(`${relativePath}#scripts.${name}`);
    }
  }
  const cargoToml = fs.readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8");
  assert(/^name\s*=\s*"ibex-runtime"\s*$/mu.test(cargoToml), "release-gate audit cannot identify the repository package");
  assert(!/^publish\s*=\s*false\s*$/mu.test(cargoToml), "release-gate audit expected the explicitly publishable root crate");
  assert(RAW_RELEASE_EXCLUSION.productTags.includes("forbidden") && RAW_RELEASE_EXCLUSION.packageRegistries.includes("forbidden"), "raw release exclusions must fail closed");
  return Object.freeze({
    schema: "ibex/checked-admission-release-callers/1",
    gateCommand: GATE_INVOCATION,
    gated: Object.freeze(gated.sort(compareUtf8)),
    excludedCeremonies: Object.freeze(observedExcluded.sort(compareUtf8)),
    rawReleaseExclusion: RAW_RELEASE_EXCLUSION,
  });
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
    if (process.argv[2] === "--admission" && process.argv.length === 4) {
      const admission = assertReleasableCheckedAdmissionFile(process.argv[3]);
      process.stdout.write(`${canonicalJson({ authorized: true, admittedScopeDigest: admission.admittedScopeDigest })}\n`);
    } else if (process.argv[2] === "--audit-callers" && process.argv.length >= 3 && process.argv.length <= 4) {
      process.stdout.write(`${canonicalJson(auditReleaseGateCallers(process.argv[3] ?? process.cwd()))}\n`);
    } else {
      fail("usage: assert-releasable-checked-admission (--admission <portable_engine_promotion_admission.json> | --audit-callers [repo-root])");
    }
  } catch (error) {
    process.stderr.write(`assert-releasable-checked-admission: ${error.message}\n`);
    process.exitCode = 1;
  }
}
