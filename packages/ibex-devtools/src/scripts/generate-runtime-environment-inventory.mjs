/**
 * Reconcile the source-derived production environment inventory with its
 * reviewed stage dispositions.
 *
 * The checked-in artifact is intentionally not an inferred allowlist. Every
 * newly discovered static name or dynamic accessor is missing until a reviewer
 * adds its allowed stages, and stage drift on an existing row fails too.
 *
 * @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — source
 * discovery is the completeness authority.
 * @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
 * — fixed compatibility inputs become a digest-bound projection.
 * @ref LLP 0025#2-startup-configuration-is-captured-before-arming — source
 * reads, snapshot capture, bootstrap use, and principal overlays are distinct.
 */

import Ajv2020 from "ajv/dist/2020.js";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const repoRoot = path.resolve(__dirname, "..", "..", "..", "..");
export const runtimeEnvironmentInventoryPath = path.join(
  repoRoot,
  "capsec",
  "registry",
  "runtime-environment-inventory.json",
);
export const runtimeEnvironmentInventorySchemaPath = path.join(
  repoRoot,
  "capsec",
  "schema",
  "runtime-environment-inventory.schema.json",
);

export const RUNTIME_ENVIRONMENT_INVENTORY_SCHEMA =
  "ibex/runtime-environment-inventory/1";

export const FIXED_COMPATIBILITY_ENVIRONMENT_NAMES = Object.freeze([
  "EXACT_COMPAT_BUN",
  "EXACT_COMPAT_TEST",
  "EXACT_TEST_SECTION",
]);

const PROHIBITED_POST_ARM_FIXED_CONTROLS = new Set([
  "EX_DISABLE_BYTECODE_SANITY_CHECK",
  "IBEX_AWAIT_UNWRAP_TIMEOUT_MS",
]);

const POST_ARM_DISPOSITIONS = new Set([
  "armed-unreachable-host-read",
  "effect-gated-host-read",
  "production-unreachable-host-read",
  "test-only-effect-hook",
]);

const FIXED_COMPATIBILITY_PROJECTION = Object.freeze({
  names: FIXED_COMPATIBILITY_ENVIRONMENT_NAMES,
  sourceReadStage: "launcher-pre-arm-read",
  snapshotCaptureStage: "snapshot-finalization",
  bootstrapUseStage: "authenticated-projection-use",
  armedPrincipalOverlayFallback: false,
  sourceRefs: Object.freeze({
    launcherRead:
      "src/bin/ibex/runtime.rs#requested_bootstrap_compatibility_modes",
    snapshotField: "src/bin/ibex/runtime.rs#bootstrapCompatibilityModes",
    hostProjection:
      "src/host/abi.rs#ex_host_armed_bootstrap_compatibility_flags",
    nativeBootstrapUse:
      "src/engine/hermes_runtime.cc#installBootstrapCompatibilityModes",
    javascriptBootstrapUse:
      "packages/ibex-runtime-js/src/core/host-inputs.ts#readBootstrapCompatibilityControl",
  }),
});

function compareText(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256(value) {
  return `sha256-${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function relative(filePath) {
  return path.relative(repoRoot, filePath).split(path.sep).join("/");
}

function canonicalSet(values) {
  return [...new Set(values)].sort(compareText);
}

function normalizeOccurrences(surface) {
  const occurrences = surface.metadata?.occurrences;
  if (!Array.isArray(occurrences) || occurrences.length === 0) {
    throw new Error(`${surface.name}: environment surface has no occurrences`);
  }
  const environmentName = surface.metadata.dynamic
    ? null
    : surface.name.slice("env:".length);
  const normalized = occurrences
    .map((occurrence) => {
      return {
        accessor: occurrence.accessor,
        context: occurrence.context,
        direction: occurrence.direction,
        language: occurrence.language,
        scope: occurrence.scope,
        sourcePath: occurrence.sourcePath,
        sourceRef: occurrence.sourceRef,
        sourceOffset: occurrence.sourceOffset,
        environmentName,
      };
    })
    .sort((left, right) =>
      compareText(
        `${left.sourceRef}\0${left.scope ?? ""}\0${left.sourceOffset ?? ""}`,
        `${right.sourceRef}\0${right.scope ?? ""}\0${right.sourceOffset ?? ""}`,
      ),
    );
  const indices = new Map();
  return normalized.map((occurrence) => {
    const key = occurrenceDispositionBaseKey(occurrence);
    const occurrenceIndex = indices.get(key) ?? 0;
    indices.set(key, occurrenceIndex + 1);
    return { ...occurrence, occurrenceIndex };
  });
}

function occurrenceDispositionBaseKey(occurrence) {
  return JSON.stringify([
    occurrence.accessor,
    occurrence.context,
    occurrence.direction,
    occurrence.language,
    occurrence.scope,
    occurrence.sourcePath,
  ]);
}

function occurrenceDispositionKey(occurrence) {
  return JSON.stringify([
    ...JSON.parse(occurrenceDispositionBaseKey(occurrence)),
    occurrence.occurrenceIndex,
  ]);
}

function assertProjectionSources(root) {
  for (const sourceRef of Object.values(FIXED_COMPATIBILITY_PROJECTION.sourceRefs)) {
    const separator = sourceRef.lastIndexOf("#");
    const sourcePath = sourceRef.slice(0, separator);
    const symbol = sourceRef.slice(separator + 1);
    const source = fs.readFileSync(path.join(root, sourcePath), "utf8");
    if (!source.includes(symbol)) {
      throw new Error(`fixed compatibility projection source is missing ${sourceRef}`);
    }
  }
}

function assertSourceAnchor(root, sourceRef, label) {
  const separator = sourceRef.lastIndexOf("#");
  if (separator <= 0 || separator === sourceRef.length - 1) {
    throw new Error(`${label}: malformed evidence source ref ${sourceRef}`);
  }
  const sourcePath = sourceRef.slice(0, separator);
  const anchor = sourceRef.slice(separator + 1);
  const source = fs.readFileSync(path.join(root, sourcePath), "utf8");
  if (!source.includes(anchor)) {
    throw new Error(`${label}: evidence source anchor is missing ${sourceRef}`);
  }
}

function assertPostArmEvidenceSources(artifact, root) {
  for (const row of artifact.rows) {
    for (const occurrence of row.occurrences) {
      if (occurrence.stage !== "post-arm-host-read") continue;
      for (const sourceRef of occurrence.postArmEvidence.sourceRefs) {
        assertSourceAnchor(root, sourceRef, row.surfaceName);
      }
    }
  }
}

function reviewedRowsBySurface(reviewedArtifact) {
  const rows = new Map();
  for (const row of reviewedArtifact?.rows ?? []) {
    if (rows.has(row.surfaceName)) {
      throw new Error(`duplicate environment disposition ${row.surfaceName}`);
    }
    rows.set(row.surfaceName, row);
  }
  return rows;
}

export function reconcileRuntimeEnvironmentRows(
  discoveredRows,
  reviewedArtifact,
) {
  const reviewedBySurface = reviewedRowsBySurface(reviewedArtifact);
  const discoveredNames = new Set();
  const rows = discoveredRows
    .map((surface) => {
      if (
        surface.kind !== "startup" ||
        !surface.name.startsWith("env:")
      ) {
        throw new Error(`non-environment surface entered inventory: ${surface.name}`);
      }
      if (discoveredNames.has(surface.name)) {
        throw new Error(`duplicate discovered environment surface ${surface.name}`);
      }
      discoveredNames.add(surface.name);
      const environmentName = surface.metadata.dynamic
        ? null
        : surface.name.slice("env:".length);
      if (PROHIBITED_POST_ARM_FIXED_CONTROLS.has(environmentName)) {
        throw new Error(
          `${surface.name}: prohibited post-arm fixed environment control remains in production source`,
        );
      }
      const occurrences = normalizeOccurrences(surface);
      const reviewed = reviewedBySurface.get(surface.name);
      if (!reviewed) {
        throw new Error(
          `${surface.name}: un-dispositioned runtime environment surface`,
        );
      }
      const reviewedOccurrences = new Map();
      for (const occurrence of reviewed.occurrences) {
        const key = occurrenceDispositionKey(occurrence);
        if (reviewedOccurrences.has(key)) {
          throw new Error(
            `${surface.name}: duplicate reviewed environment occurrence ${key}`,
          );
        }
        reviewedOccurrences.set(key, occurrence);
      }
      const seenReviewedOccurrences = new Set();
      const dispositionedOccurrences = occurrences.map((occurrence) => {
        const key = occurrenceDispositionKey(occurrence);
        const reviewedOccurrence = reviewedOccurrences.get(key);
        if (!reviewedOccurrence) {
          throw new Error(
            `${surface.name}: un-dispositioned environment occurrence ${key}`,
          );
        }
        seenReviewedOccurrences.add(key);
        const stage = reviewedOccurrence.stage;
        if (
          occurrence.direction === "read" &&
          occurrence.language === "javascript" &&
          stage !== "principal-overlay-read"
        ) {
          throw new Error(
            `${surface.name}: JavaScript environment reads must use the principal overlay`,
          );
        }
        if (
          occurrence.direction === "read" &&
          occurrence.language !== "javascript" &&
          !new Set([
            "armed-bootstrap-host-read",
            "launcher-pre-arm-read",
            "post-arm-host-read",
          ]).has(stage)
        ) {
          throw new Error(
            `${surface.name}: native host environment read has invalid stage ${stage}`,
          );
        }
        if (
          occurrence.direction !== "read" &&
          !(
            (occurrence.context === "trusted-bootstrap-output" &&
              stage === "trusted-bootstrap-host-write") ||
            (occurrence.context === "spawn-child-env" &&
              stage === "child-environment-construction")
          )
        ) {
          throw new Error(
            `${surface.name}: runtime host-environment mutation is prohibited`,
          );
        }
        const postArmDisposition =
          reviewedOccurrence.postArmDisposition ?? null;
        const postArmEvidence = reviewedOccurrence.postArmEvidence ?? null;
        if (stage === "post-arm-host-read") {
          if (!POST_ARM_DISPOSITIONS.has(postArmDisposition)) {
            throw new Error(
              `${surface.name}: post-arm host read has no reviewed disposition`,
            );
          }
          if (
            !postArmEvidence ||
            typeof postArmEvidence.summary !== "string" ||
            postArmEvidence.summary.length === 0 ||
            !Array.isArray(postArmEvidence.sourceRefs) ||
            postArmEvidence.sourceRefs.length === 0 ||
            JSON.stringify(postArmEvidence.sourceRefs) !==
              JSON.stringify(canonicalSet(postArmEvidence.sourceRefs))
          ) {
            throw new Error(
              `${surface.name}: post-arm host read has invalid reviewed evidence`,
            );
          }
          if (
            postArmDisposition === "test-only-effect-hook" &&
            !environmentName?.startsWith("IBEX_TEST_")
          ) {
            throw new Error(
              `${surface.name}: only an IBEX_TEST_ control may use the test-hook disposition`,
            );
          }
        } else if (postArmDisposition !== null || postArmEvidence !== null) {
          throw new Error(
            `${surface.name}: non-post-arm occurrence carries post-arm evidence`,
          );
        }
        return {
          accessor: occurrence.accessor,
          context: occurrence.context,
          direction: occurrence.direction,
          hostEnvironment: !new Set([
            "child-environment-construction",
            "principal-overlay-read",
          ]).has(stage),
          language: occurrence.language,
          occurrenceIndex: occurrence.occurrenceIndex,
          postArmDisposition,
          postArmEvidence,
          scope: occurrence.scope,
          sourceOffset: occurrence.sourceOffset,
          sourcePath: occurrence.sourcePath,
          sourceRef: occurrence.sourceRef,
          stage,
        };
      });
      const staleOccurrences = [...reviewedOccurrences.keys()].filter(
        (key) => !seenReviewedOccurrences.has(key),
      );
      if (staleOccurrences.length > 0) {
        throw new Error(
          `${surface.name}: stale environment occurrence dispositions ${staleOccurrences.join(", ")}`,
        );
      }
      const allowedStages = canonicalSet(
        dispositionedOccurrences.map((occurrence) => occurrence.stage),
      );
      if (JSON.stringify(reviewed.allowedStages) !== JSON.stringify(allowedStages)) {
        throw new Error(
          `${surface.name}: reviewed allowedStages do not exactly match occurrence dispositions`,
        );
      }
      if (
        FIXED_COMPATIBILITY_ENVIRONMENT_NAMES.includes(environmentName) &&
        dispositionedOccurrences.some(
          (occurrence) =>
            occurrence.hostEnvironment &&
            occurrence.stage !== "launcher-pre-arm-read",
        )
      ) {
        throw new Error(
          `${surface.name}: fixed compatibility control has a post-arm host read`,
        );
      }
      return {
        surfaceName: surface.name,
        dynamic: surface.metadata.dynamic,
        dynamicKey: surface.metadata.dynamicKey,
        authoredNames: [...surface.metadata.authoredNames],
        allowedStages: [...allowedStages],
        occurrences: dispositionedOccurrences,
      };
    })
    .sort((left, right) => compareText(left.surfaceName, right.surfaceName));

  const stale = [...reviewedBySurface.keys()].filter(
    (surfaceName) => !discoveredNames.has(surfaceName),
  );
  if (stale.length > 0) {
    throw new Error(
      `stale runtime environment dispositions: ${stale.sort(compareText).join(", ")}`,
    );
  }
  return rows;
}

function validateCanonicalArtifact(source, schemaSource, label) {
  let value;
  try {
    value = JSON.parse(source);
  } catch (error) {
    throw new Error(`${label}: invalid JSON: ${error.message}`);
  }
  if (canonicalJson(value) !== source) {
    throw new Error(`${label}: artifact is not canonical JSON`);
  }
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const schema = JSON.parse(schemaSource);
  const validate = ajv.compile(schema);
  if (!validate(value)) {
    throw new Error(
      `${label}: schema validation failed: ${ajv.errorsText(validate.errors)}`,
    );
  }
  return value;
}

export function loadRuntimeEnvironmentInventory(
  artifactPath = runtimeEnvironmentInventoryPath,
  schemaPath = runtimeEnvironmentInventorySchemaPath,
) {
  const source = fs.readFileSync(artifactPath, "utf8");
  const schemaSource = fs.readFileSync(schemaPath, "utf8");
  return {
    artifact: validateCanonicalArtifact(
      source,
      schemaSource,
      relative(artifactPath),
    ),
    schemaSource,
    source,
  };
}

export function renderRuntimeEnvironmentInventory(
  discoveredRows,
  reviewedArtifact,
  { generatorSource, schemaSource } = {},
) {
  const rows = reconcileRuntimeEnvironmentRows(discoveredRows, reviewedArtifact);
  const artifact = {
    inventorySchema: RUNTIME_ENVIRONMENT_INVENTORY_SCHEMA,
    generatorSha256: sha256(
      generatorSource ?? fs.readFileSync(__filename, "utf8"),
    ),
    schemaSha256: sha256(
      schemaSource ??
        fs.readFileSync(runtimeEnvironmentInventorySchemaPath, "utf8"),
    ),
    fixedCompatibilityProjection: structuredClone(
      FIXED_COMPATIBILITY_PROJECTION,
    ),
    rows,
  };
  return canonicalJson(artifact);
}

async function discoveredEnvironmentRows(root = repoRoot) {
  const inventory = await discoverRepositorySurfaces(root);
  return inventory.surfaces.filter(
    (surface) =>
      surface.kind === "startup" && surface.name.startsWith("env:"),
  );
}

export async function checkRuntimeEnvironmentInventory() {
  assertProjectionSources(repoRoot);
  const { artifact, schemaSource, source } = loadRuntimeEnvironmentInventory();
  const rendered = renderRuntimeEnvironmentInventory(
    await discoveredEnvironmentRows(),
    artifact,
    { schemaSource },
  );
  assertPostArmEvidenceSources(JSON.parse(rendered), repoRoot);
  return source === rendered ? [] : [relative(runtimeEnvironmentInventoryPath)];
}

export async function writeRuntimeEnvironmentInventory() {
  assertProjectionSources(repoRoot);
  const schemaSource = fs.readFileSync(
    runtimeEnvironmentInventorySchemaPath,
    "utf8",
  );
  const reviewedArtifact = loadRuntimeEnvironmentInventory().artifact;
  const rendered = renderRuntimeEnvironmentInventory(
    await discoveredEnvironmentRows(),
    reviewedArtifact,
    { schemaSource },
  );
  validateCanonicalArtifact(
    rendered,
    schemaSource,
    relative(runtimeEnvironmentInventoryPath),
  );
  assertPostArmEvidenceSources(JSON.parse(rendered), repoRoot);
  writeGeneratedFilesTransactionally(
    repoRoot,
    [
      {
        path: runtimeEnvironmentInventoryPath,
        content: rendered,
        label: "runtime environment inventory",
      },
    ],
    () => {
      assertConfinedGeneratedFile(
        repoRoot,
        runtimeEnvironmentInventoryPath,
        "runtime environment inventory",
      );
    },
  );
}

async function main(argv) {
  const write = argv.includes("--write");
  const check = argv.includes("--check");
  const unknown = argv.filter(
    (argument) => !new Set(["--write", "--check"]).has(argument),
  );
  if (
    unknown.length > 0 ||
    Number(write) + Number(check) !== 1
  ) {
    throw new Error(
      "usage: generate-runtime-environment-inventory.mjs (--write|--check)",
    );
  }
  if (write) {
    await writeRuntimeEnvironmentInventory();
    console.log(`wrote ${relative(runtimeEnvironmentInventoryPath)}`);
    return;
  }
  const stale = await checkRuntimeEnvironmentInventory();
  if (stale.length > 0) {
    throw new Error(
      `runtime environment inventory is stale: ${stale.join(", ")}\nRun: bun run generate:runtime-environment-inventory`,
    );
  }
  const { artifact } = loadRuntimeEnvironmentInventory();
  console.log(
    `runtime environment inventory checked: ${artifact.rows.length} source-derived rows`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  try {
    await main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.stack : String(error));
    process.exitCode = 1;
  }
}
