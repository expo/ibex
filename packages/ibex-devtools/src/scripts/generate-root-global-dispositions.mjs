/**
 * Generate the LLP 0022 root-global disposition manifest and its native
 * verifier table from source discovery joined exactly to the CapSec registry.
 *
 * @ref LLP 0022#7-capabilities-principals-and-affordance-parity — reachability
 * is a generated contract independent from, but exactly joined to, effects.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import {
  assertReviewedSurfaceInventory,
  buildCoverageModel,
} from "./capsec-coverage-model.mjs";
import { canonicalJson, readJsonStrict } from "./capsec-contract.mjs";
import {
  buildRootGlobalDispositionManifest,
  ROOT_GLOBAL_DISPOSITION_SCHEMA,
} from "./capsec-root-global-dispositions.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const repoRoot = path.resolve(__dirname, "..", "..", "..", "..");
const capsecRoot = path.join(repoRoot, "capsec");

export const generatedRootGlobalDispositionPaths = Object.freeze({
  json: path.join(
    capsecRoot,
    "generated",
    "root-global-disposition-manifest.json",
  ),
  cxx: path.join(
    repoRoot,
    "src",
    "engine",
    "root_global_disposition.generated.h",
  ),
});

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256Base64Url(value) {
  return `sha256-${crypto.createHash("sha256").update(value, "utf8").digest("base64url")}`;
}

function prettyJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function relative(filePath) {
  return path.relative(repoRoot, filePath).split(path.sep).join("/");
}

function quoteCxx(value) {
  return JSON.stringify(value)
    .replaceAll("\\u2028", "\\u2028")
    .replaceAll("\\u2029", "\\u2029");
}

function keyText(key) {
  if (key.kind === "string") return key.value;
  if (key.kind === "well-known-symbol") return `[[Symbol.${key.value}]]`;
  if (key.kind === "dynamic-table") return `[[dynamic-table:${key.value}]]`;
  if (key.kind === "return-value") return "[[return]]";
  throw new Error(`unknown root-global key kind ${key.kind}`);
}

function logicalPathText(property) {
  return [property.root, ...property.path].map(keyText).join(".");
}

const CONDITIONAL_LIVE_SWEEP_ACTIVATIONS = new Set([
  "authenticated-exact-host-ingress",
]);

const EVALUATED_NATIVE_SCRIPT_ROOTS = Object.freeze([
  Object.freeze({
    observedKey: "native-op:__ibexLockedDown",
    globalName: "__ibexLockedDown",
    sourceRef: "src/engine/hermes_runtime.cc#__ibexLockedDown",
    branchId: "native-lockdown-script",
  }),
]);

/**
 * Native source scanning records string literals in evaluated script bodies as
 * private native operations because it cannot prove that a literal is a root
 * property install. Keep that conservative inventory intact, then promote the
 * reviewed, finite install sites here for the reachability contract. Every
 * promotion still requires matching discovered evidence and joins to the same
 * observed CapSec edge.
 */
export function rootGlobalInstallSurfaces(inventory) {
  const globals = [...inventory.globals];
  const byObservedKey = new Map(
    inventory.surfaces.map((surface) => [surface.observedKey, surface]),
  );
  for (const projection of EVALUATED_NATIVE_SCRIPT_ROOTS) {
    if (globals.some((surface) => surface.observedKey === projection.observedKey)) {
      continue;
    }
    const source = byObservedKey.get(projection.observedKey);
    if (!source || !source.sourceRefs?.includes(projection.sourceRef)) {
      throw new Error(
        `${projection.observedKey}: reviewed evaluated-script root evidence is absent`,
      );
    }
    globals.push({
      ...source,
      sourceRefs: [projection.sourceRef],
      metadata: {
        exportName: projection.globalName,
        globalName: projection.globalName,
        memberName: null,
        sourceKey: "evaluated_native_script",
        surfaceType: "global-api",
        installationBranches: [
          {
            branchKind: "single",
            id: projection.branchId,
            kind: "single",
            route: "evaluated-native-script",
            routes: ["evaluated-native-script"],
            sourceRefs: [projection.sourceRef],
            targetVariant: "default",
          },
        ],
      },
    });
  }
  return globals.sort((left, right) =>
    compareText(left.observedKey, right.observedKey),
  );
}

function renderRootEntries(manifest) {
  return manifest.rows
    .filter((row) => row.property.path.length === 0)
    .map(
      (row) =>
        `    {${quoteCxx(row.installId)}, ${quoteCxx(keyText(row.property.root))}, ${quoteCxx(row.disposition)}, ${quoteCxx(row.traversal)}, ${quoteCxx(row.liveExpectation)}, ${quoteCxx(row.branch.targetVariant)}, ${quoteCxx(row.branch.activation)}},`,
    )
    .join("\n");
}

function renderAbsentEntries(manifest) {
  return manifest.rows
    .filter((row) => row.liveExpectation === "absent")
    .filter((row) =>
      [row.property.root, ...row.property.path].every((key) =>
        new Set(["string", "well-known-symbol"]).has(key.kind),
      ),
    )
    .map(
      (row) =>
        `    {${quoteCxx(row.installId)}, ${quoteCxx(logicalPathText(row.property))}, ${quoteCxx(row.privateConsumer ?? "")}, ${quoteCxx(row.branch.targetVariant)}, ${quoteCxx(row.branch.activation)}},`,
    )
    .join("\n");
}

function conditionalLiveSweepRows(manifest) {
  return manifest.rows
    .filter(
      (row) =>
        row.liveExpectation === "reachable" &&
        CONDITIONAL_LIVE_SWEEP_ACTIVATIONS.has(row.branch.activation) &&
        [row.property.root, ...row.property.path].every((key) =>
          new Set(["string", "well-known-symbol"]).has(key.kind),
        ),
    )
    .map((row) => ({
      installId: row.installId,
      logicalPath: logicalPathText(row.property),
      targetVariant: row.branch.targetVariant,
      activation: row.branch.activation,
    }))
    .sort(
      (left, right) =>
        compareText(left.logicalPath, right.logicalPath) ||
        compareText(left.targetVariant, right.targetVariant) ||
        compareText(left.activation, right.activation) ||
        compareText(left.installId, right.installId),
    );
}

function renderConditionalLiveSweepEntries(manifest) {
  return conditionalLiveSweepRows(manifest)
    .map(
      (row) =>
        `    {${quoteCxx(row.installId)}, ${quoteCxx(row.logicalPath)}, ${quoteCxx(row.targetVariant)}, ${quoteCxx(row.activation)}},`,
    )
    .join("\n");
}

function renderNativeKeys(manifest) {
  const rows = manifest.rows
    .filter(
      (row) =>
        row.nativeImplementation &&
        row.liveExpectation === "reachable" &&
        row.property.root.kind === "string" &&
        row.property.path.every((key) =>
          new Set(["string", "well-known-symbol"]).has(key.kind),
        ),
    )
    .map((row) => ({
      root: row.property.root.value,
      key:
        row.property.path.length === 0
          ? row.property.root.value
          : keyText(row.property.path.at(-1)),
      targetVariant: row.branch.targetVariant,
      activation: row.branch.activation,
    }));
  const unique = new Map();
  for (const row of rows) {
    unique.set(
      `${row.root}\0${row.key}\0${row.targetVariant}\0${row.activation}`,
      row,
    );
  }
  return [...unique.values()]
    .sort(
      (left, right) =>
        compareText(left.root, right.root) ||
        compareText(left.key, right.key) ||
        compareText(left.targetVariant, right.targetVariant) ||
        compareText(left.activation, right.activation),
    )
    .map(
      (row) =>
        `    {${quoteCxx(row.root)}, ${quoteCxx(row.key)}, ${quoteCxx(row.targetVariant)}, ${quoteCxx(row.activation)}},`,
    )
    .join("\n");
}

function renderPermittedKeys(manifest) {
  const rows = manifest.rows
    .filter(
      (row) =>
        row.liveExpectation === "reachable" &&
        row.property.root.kind === "string" &&
        row.property.path.every((key) =>
          new Set(["string", "well-known-symbol"]).has(key.kind),
        ),
    )
    .map((row) => ({
      root: row.property.root.value,
      key:
        row.property.path.length === 0
          ? row.property.root.value
          : keyText(row.property.path.at(-1)),
      targetVariant: row.branch.targetVariant,
      activation: row.branch.activation,
    }));
  const unique = new Map();
  for (const row of rows) {
    unique.set(
      `${row.root}\0${row.key}\0${row.targetVariant}\0${row.activation}`,
      row,
    );
  }
  return [...unique.values()]
    .sort(
      (left, right) =>
        compareText(left.root, right.root) ||
        compareText(left.key, right.key) ||
        compareText(left.targetVariant, right.targetVariant) ||
        compareText(left.activation, right.activation),
    )
    .map(
      (row) =>
        `    {${quoteCxx(row.root)}, ${quoteCxx(row.key)}, ${quoteCxx(row.targetVariant)}, ${quoteCxx(row.activation)}},`,
    )
    .join("\n");
}

export function renderRootGlobalDispositionHeader(manifest, jsonSource) {
  const manifestDigest = sha256Base64Url(jsonSource);
  const rootCount = manifest.rows.filter(
    (row) => row.property.path.length === 0,
  ).length;
  const absentCount = manifest.rows.filter(
    (row) =>
      row.liveExpectation === "absent" &&
      [row.property.root, ...row.property.path].every((key) =>
        new Set(["string", "well-known-symbol"]).has(key.kind),
      ),
  ).length;
  const conditionalLiveSweepCount = conditionalLiveSweepRows(manifest).length;
  const nativeRows = manifest.rows.filter(
    (row) =>
      row.nativeImplementation &&
      row.liveExpectation === "reachable" &&
      row.property.root.kind === "string" &&
      row.property.path.every((key) =>
        new Set(["string", "well-known-symbol"]).has(key.kind),
      ),
  );
  const nativeCount = new Set(
    nativeRows.map((row) =>
      [
        row.property.root.value,
        row.property.path.length === 0
          ? row.property.root.value
          : keyText(row.property.path.at(-1)),
        row.branch.targetVariant,
        row.branch.activation,
      ].join("\0"),
    ),
  ).size;
  const permittedCount = new Set(
    manifest.rows
      .filter(
        (row) =>
          row.liveExpectation === "reachable" &&
          row.property.root.kind === "string" &&
          row.property.path.every((key) =>
            new Set(["string", "well-known-symbol"]).has(key.kind),
          ),
      )
      .map((row) =>
        [
          row.property.root.value,
          row.property.path.length === 0
            ? row.property.root.value
            : keyText(row.property.path.at(-1)),
          row.branch.targetVariant,
          row.branch.activation,
        ].join("\0"),
      ),
  ).size;
  return [
    "// @generated by packages/ibex-devtools/src/scripts/generate-root-global-dispositions.mjs",
    `// Manifest digest: ${manifestDigest}`,
    "// Do not edit by hand.",
    `// ${"@ref"} LLP 0022#7-capabilities-principals-and-affordance-parity`,
    "#pragma once",
    "",
    "#include <cstddef>",
    "",
    "namespace exact::root_global_disposition {",
    "struct RootExpectation {",
    "  const char* install_id;",
    "  const char* root_key;",
    "  const char* disposition;",
    "  const char* traversal;",
    "  const char* live_expectation;",
    "  const char* target_variant;",
    "  const char* activation;",
    "};",
    "struct AbsentExpectation {",
    "  const char* install_id;",
    "  const char* logical_path;",
    "  const char* private_consumer;",
    "  const char* target_variant;",
    "  const char* activation;",
    "};",
    "struct NativeKeyExpectation {",
    "  const char* root_key;",
    "  const char* property_key;",
    "  const char* target_variant;",
    "  const char* activation;",
    "};",
    "struct ConditionalLiveSweepExpectation {",
    "  const char* install_id;",
    "  const char* logical_path;",
    "  const char* target_variant;",
    "  const char* activation;",
    "};",
    "using PermittedKeyExpectation = NativeKeyExpectation;",
    "",
    `inline constexpr std::size_t kMaxDepth = ${manifest.sweep.maxDepth};`,
    `inline constexpr std::size_t kMaxDescriptors = ${manifest.sweep.maxDescriptors};`,
    `inline constexpr std::size_t kMaxObjects = ${manifest.sweep.maxObjects};`,
    `inline constexpr const char* kManifestDigest = ${quoteCxx(manifestDigest)};`,
    `inline constexpr RootExpectation kRootExpectations[${rootCount}] = {`,
    renderRootEntries(manifest),
    "};",
    `inline constexpr AbsentExpectation kAbsentExpectations[${absentCount}] = {`,
    renderAbsentEntries(manifest),
    "};",
    `inline constexpr ConditionalLiveSweepExpectation kConditionalLiveSweepExpectations[${conditionalLiveSweepCount}] = {`,
    renderConditionalLiveSweepEntries(manifest),
    "};",
    `inline constexpr NativeKeyExpectation kNativeKeyExpectations[${nativeCount}] = {`,
    renderNativeKeys(manifest),
    "};",
    `inline constexpr PermittedKeyExpectation kPermittedKeyExpectations[${permittedCount}] = {`,
    renderPermittedKeys(manifest),
    "};",
    "}  // namespace exact::root_global_disposition",
    "",
  ].join("\n");
}

function validateManifestSchema(manifest) {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const common = readJsonStrict(
    path.join(capsecRoot, "schema", "common.schema.json"),
  );
  const schema = readJsonStrict(
    path.join(
      capsecRoot,
      "schema",
      "root-global-disposition-manifest.schema.json",
    ),
  );
  ajv.addSchema(common);
  ajv.addSchema(schema);
  const validate = ajv.getSchema(
    "https://ibex.dev/capsec/schema/root-global-disposition-manifest.schema.json",
  );
  if (!validate(manifest)) {
    throw new Error(
      `root-global disposition schema validation failed: ${ajv.errorsText(validate.errors, { separator: "; " })}`,
    );
  }
}

export async function renderRootGlobalDispositionArtifacts() {
  const inventory = await discoverRepositorySurfaces(repoRoot);
  assertReviewedSurfaceInventory(inventory.surfaces);
  const globals = rootGlobalInstallSurfaces(inventory);
  const definitions = readJsonStrict(
    path.join(capsecRoot, "registry", "capability-definitions.json"),
  );
  const rules = readJsonStrict(
    path.join(capsecRoot, "registry", "policy-rules.json"),
  );
  const coverage = buildCoverageModel(inventory.surfaces, {
    definitions,
    rules,
  }).coverage;
  const sourceDigest = sha256Base64Url(
    canonicalJson({ globals, coverage }),
  );
  const manifest = buildRootGlobalDispositionManifest({
    globals,
    coverage,
    sourceDigest,
  });
  validateManifestSchema(manifest);
  const json = prettyJson(manifest);
  const cxx = renderRootGlobalDispositionHeader(manifest, json);
  return { manifest, json, cxx };
}

export function checkRootGlobalDispositionArtifacts(rendered) {
  const stale = [];
  for (const [kind, filePath] of Object.entries(
    generatedRootGlobalDispositionPaths,
  )) {
    try {
      assertConfinedGeneratedFile(
        repoRoot,
        filePath,
        `${kind} root-global disposition artifact`,
      );
      if (fs.readFileSync(filePath, "utf8") !== rendered[kind]) {
        stale.push(relative(filePath));
      }
    } catch {
      stale.push(relative(filePath));
    }
  }
  return stale;
}

export function writeRootGlobalDispositionArtifacts(rendered) {
  writeGeneratedFilesTransactionally(
    repoRoot,
    [
      {
        path: generatedRootGlobalDispositionPaths.json,
        content: rendered.json,
        label: "root-global disposition JSON",
      },
      {
        path: generatedRootGlobalDispositionPaths.cxx,
        content: rendered.cxx,
        label: "root-global disposition C++ header",
      },
    ],
    () => {
      const stale = checkRootGlobalDispositionArtifacts(rendered);
      if (stale.length > 0) {
        throw new Error(
          `root-global disposition artifacts failed validation: ${stale.join(", ")}`,
        );
      }
    },
  );
}

async function main(argv) {
  const write = argv.includes("--write");
  const check = argv.includes("--check");
  const unknown = argv.filter(
    (argument) => !new Set(["--write", "--check"]).has(argument),
  );
  if (unknown.length > 0 || write === check) {
    throw new Error(
      "usage: bun packages/ibex-devtools/src/scripts/generate-root-global-dispositions.mjs (--write|--check)",
    );
  }
  const rendered = await renderRootGlobalDispositionArtifacts();
  if (write) {
    writeRootGlobalDispositionArtifacts(rendered);
    console.log(
      `wrote ${Object.values(generatedRootGlobalDispositionPaths).map(relative).join(", ")}`,
    );
    return;
  }
  const stale = checkRootGlobalDispositionArtifacts(rendered);
  if (stale.length > 0) {
    console.error(`root-global disposition artifacts are stale: ${stale.join(", ")}`);
    process.exitCode = 1;
  } else {
    console.log(
      `root-global disposition manifest checked: ${rendered.manifest.counts.installBranches} install branches`,
    );
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  try {
    await main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.stack : String(error));
    process.exitCode = 1;
  }
}

export { ROOT_GLOBAL_DISPOSITION_SCHEMA };
