#!/usr/bin/env node

// Derive the untracked target-cell candidate consumed by the portable v2
// promotion bundle. The checked source-A target-cell catalog is intentionally
// unsupported and is never rewritten here. A candidate is emitted only after
// the independently regenerated rich recipe catalog has exact, executable
// coverage for every required fixture.
//
// @ref LLP 0035#reports-and-advertisements — promotion target/security facts
// come from reviewed source closure, not a caller-authored locality heuristic.
// @ref LLP 0035#phase-2--split-runtime-and-publication-identity — source A
// remains unchanged; this is an untracked candidate input to the sole v2
// promotion validator, not an advertisement or admission switch.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  fixtureCatalogForTarget,
  selectCandidateTarget,
} from "./capsec-conformance.mjs";
import {
  assertRecipeCatalogComplete,
  validateCurrentSourceRecipeCatalog,
} from "./capsec-conformance-recipes.mjs";
import { canonicalJson, readJsonStrict } from "./capsec-contract.mjs";
import { portablePromotionJsonBytes } from "./capsec-portable-promotion-bundle.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";

const PROFILE = "ibex/capsec/1";
const TARGET_CELL_SCHEMA = "ibex/capsec-target-cells/1";
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const compareUtf8 = (left, right) =>
  Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));

function refuse(message) {
  throw new Error(message);
}

function invariant(condition, message) {
  if (!condition) refuse(message);
}

function canonicalSet(values) {
  return [...new Set(values)].sort(compareUtf8);
}

function dispositionFor(edge, catalogRow) {
  if (catalogRow.implementationBranchIds.length === 0) return "absent";
  if (edge.effectMode === "conditional-unrefined") return null;
  if (edge.classification === "effects") return "enforced";
  if (edge.classification === "closed") return "closed";
  if (edge.classification === "non-capability") return "non-capability";
  return null;
}

export function derivePortablePromotionTargetCells({
  coverage,
  fixtureCatalog,
  target,
}) {
  invariant(
    Array.isArray(coverage?.edges) &&
      Array.isArray(fixtureCatalog) &&
      target &&
      typeof target === "object" &&
      !Array.isArray(target),
    "portable target-cell derivation inputs are malformed",
  );
  const coverageById = new Map(
    coverage.edges.map((edge) => [edge.id, edge]),
  );
  const catalogById = new Map(
    fixtureCatalog.map((row) => [row.edgeId, row]),
  );
  invariant(
    coverageById.size === coverage.edges.length &&
      catalogById.size === fixtureCatalog.length &&
      coverageById.size === catalogById.size,
    "portable target-cell derivation has duplicate or incomplete edge membership",
  );
  const edgeIds = [...coverageById.keys()].sort(compareUtf8);
  invariant(
    edgeIds.every((edgeId) => catalogById.has(edgeId)),
    "portable target-cell fixture catalog differs from coverage membership",
  );
  const cells = edgeIds.map((edgeId) => {
    const edge = coverageById.get(edgeId);
    const catalogRow = catalogById.get(edgeId);
    const disposition = dispositionFor(edge, catalogRow);
    invariant(
      disposition !== null,
      `${edgeId}: reviewed source closure has no promotable target disposition`,
    );
    const implementationBranchIds = canonicalSet(
      catalogRow.implementationBranchIds,
    );
    const fixtures = canonicalSet(catalogRow.requiredFixtures);
    invariant(
      fixtures.length > 0,
      `${edgeId}: promotable target cell has no required fixture`,
    );
    invariant(
      disposition === "absent"
        ? implementationBranchIds.length === 0
        : implementationBranchIds.length > 0,
      `${edgeId}: target disposition and implementation membership disagree`,
    );
    return {
      edgeId,
      target: structuredClone(target),
      disposition,
      implementationBranchIds,
      fixtures,
      rationale:
        "Source-derived physical-promotion candidate; authority requires complete v2 execution evidence.",
    };
  });
  return {
    targetCellSchema: TARGET_CELL_SCHEMA,
    profile: PROFILE,
    cells,
  };
}

function parseArguments(argv) {
  const allowed = new Set(["--target", "--recipe-catalog", "--output"]);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    invariant(allowed.has(name), `unknown option ${name ?? "<missing>"}`);
    invariant(
      typeof value === "string" && !value.startsWith("--"),
      `${name}: expected one value`,
    );
    invariant(!values.has(name), `duplicate option ${name}`);
    values.set(name, value);
  }
  for (const name of allowed) invariant(values.has(name), `missing option ${name}`);
  return values;
}

function git(...arguments_) {
  return execFileSync("/usr/bin/git", arguments_, {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 16 * 1024 * 1024,
    env: {
      PATH: "/usr/bin:/bin",
      LC_ALL: "C",
      LANG: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_OPTIONAL_LOCKS: "0",
    },
  }).trim();
}

function sourceState() {
  return {
    revision: git("rev-parse", "--verify", "HEAD^{commit}"),
    tree: git("rev-parse", "--verify", "HEAD^{tree}"),
    dirty: git(
      "status",
      "--porcelain=v1",
      "--untracked-files=all",
      "--ignore-submodules=none",
    ),
  };
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function writeExclusive(filePath, value) {
  const absolute = path.resolve(filePath);
  const targetRoot = fs.realpathSync(path.join(repoRoot, "target"));
  const parent = fs.realpathSync(path.dirname(absolute));
  const relative = path.relative(targetRoot, absolute);
  invariant(
    relative !== "" &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    "portable target-cell output must remain beneath checkout target/",
  );
  invariant(
    parent === path.dirname(absolute),
    "portable target-cell output parent is redirected",
  );
  const descriptor = fs.openSync(
    absolute,
    fs.constants.O_WRONLY |
      fs.constants.O_CREAT |
      fs.constants.O_EXCL |
      NOFOLLOW,
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, portablePromotionJsonBytes(value));
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

async function main(argv) {
  const options = parseArguments(argv);
  const initial = sourceState();
  invariant(initial.dirty === "", "portable target-cell derivation requires a clean checkout");
  const capsecRoot = path.join(repoRoot, "capsec");
  const target = selectCandidateTarget(
    readJsonStrict(path.join(capsecRoot, "registry/policy-rules.json")),
    options.get("--target"),
  );
  const coverage = readJsonStrict(
    path.join(capsecRoot, "registry/coverage-edges.json"),
  );
  const implementation = readJsonStrict(
    path.join(capsecRoot, "generated/implementation-manifest.json"),
  );
  const fixtureCatalog = fixtureCatalogForTarget({
    coverage,
    implementation,
    target,
  });
  const recipeCatalog = readJsonStrict(
    path.resolve(repoRoot, options.get("--recipe-catalog")),
  );
  const inventory = await discoverRepositorySurfaces(repoRoot);
  validateCurrentSourceRecipeCatalog(recipeCatalog, {
    coverage,
    implementation,
    inventory,
    occurrenceExamples: readJsonStrict(
      path.join(capsecRoot, "examples/effect-occurrences.canonical.json"),
    ),
    selectorExamples: readJsonStrict(
      path.join(capsecRoot, "examples/authority-selectors.canonical.json"),
    ),
    capabilityDefinitions: readJsonStrict(
      path.join(capsecRoot, "registry/capability-definitions.json"),
    ),
    target,
  });
  const requiredFixtureIds = canonicalSet(
    fixtureCatalog.flatMap((row) => row.requiredFixtures),
  );
  assertRecipeCatalogComplete(recipeCatalog, {
    expectedFixtureIds: requiredFixtureIds,
    target,
  });
  const candidate = derivePortablePromotionTargetCells({
    coverage,
    fixtureCatalog,
    target,
  });
  const final = sourceState();
  invariant(
    same(final, initial),
    "portable target-cell derivation changed the checked source tree",
  );
  writeExclusive(options.get("--output"), candidate);
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(
      `generate-capsec-portable-promotion-target-cells: ${error.message}\n`,
    );
    process.exitCode = 1;
  });
}
