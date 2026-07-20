/**
 * Render the compiled-mode environment consumer profile from the source-derived
 * CapSec implementation manifest and a small reviewed classification authority.
 *
 * @ref LLP 0029#4-compiled-mode-authority — every runtime environment consumer is classified while the real environment remains default-deny
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalJson,
  computeDomainDigest,
  parseJsonStrict,
} from "./capsec-contract.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../../..");
const schema = "ibex/compiled-environment-profile/1";
const domain = "ibex:compiled-environment-profile:1";
const configPath = path.join(repoRoot, "config/compiled-environment-profile.json");
const implementationManifestPath = path.join(
  repoRoot,
  "capsec/generated/implementation-manifest.json",
);
const canonicalOutPath = path.join(
  repoRoot,
  "vendored-generated/compiled-environment-profile.canonical.json",
);
const rustOutPath = path.join(repoRoot, "src/compiled_environment_profile_generated.rs");
const tsOutPath = path.join(
  repoRoot,
  "packages/ibex-runtime-js/src/security/compiled-environment-profile.generated.ts",
);

const exactPrefix = "startup:env:";
const dynamicPrefix = "startup:env:<dynamic>:";
const allowedDynamicDispositions = new Set([
  "application-broker",
  "capture-primitive",
  "typed-internal-dispatch",
]);

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requireSortedUniqueStrings(value, label) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new Error(`${label} must be an array of non-empty strings`);
  }
  const sorted = [...value].sort(compareStrings);
  if (new Set(value).size !== value.length || value.some((item, index) => item !== sorted[index])) {
    throw new Error(`${label} must be sorted and duplicate-free`);
  }
  return value;
}

function exactName(observedKey) {
  if (!observedKey.startsWith(exactPrefix) || observedKey.startsWith(dynamicPrefix)) return null;
  const name = observedKey.slice(exactPrefix.length);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) {
    throw new Error(`environment inventory has a non-canonical exact name ${name}`);
  }
  return name;
}

export function buildCompiledEnvironmentProfile(config, manifest) {
  requireObject(config, "compiled environment config");
  requireObject(manifest, "CapSec implementation manifest");
  if (config.schema !== "ibex/compiled-environment-profile-config/1") {
    throw new Error("compiled environment config schema is unsupported");
  }
  if (manifest.implementationManifestSchema !== "ibex/capsec-implementation/1") {
    throw new Error("CapSec implementation manifest schema is unsupported");
  }
  const allowlistDecision = requireObject(config.allowlistDecision, "allowlist decision");
  if (![
    "blocked-on-author-decision-2",
    "decided",
  ].includes(allowlistDecision.status)) {
    throw new Error("compiled environment allowlist decision status is invalid");
  }
  const allowlist = requireSortedUniqueStrings(
    allowlistDecision.names,
    "compiled environment allowlist",
  );
  const applicationNames = requireSortedUniqueStrings(
    config.intentionalApplicationBehaviorNames,
    "intentional application behavior names",
  );
  const applicationSet = new Set(applicationNames);
  const dynamicDispositions = requireObject(
    config.dynamicConsumerDispositions,
    "dynamic consumer dispositions",
  );
  for (const [key, disposition] of Object.entries(dynamicDispositions)) {
    if (!key.startsWith(dynamicPrefix) || !allowedDynamicDispositions.has(disposition)) {
      throw new Error(`invalid dynamic environment disposition ${key} -> ${disposition}`);
    }
  }
  if (!Array.isArray(manifest.surfaces)) {
    throw new Error("CapSec implementation manifest omits surfaces");
  }
  const grouped = new Map();
  for (const surface of manifest.surfaces) {
    const observedKey = surface?.observedKey;
    if (typeof observedKey !== "string" || !observedKey.startsWith(exactPrefix)) continue;
    const row = grouped.get(observedKey) ?? { sourceRefs: new Set(), branchIds: new Set() };
    for (const sourceRef of surface.sourceRefs ?? []) row.sourceRefs.add(sourceRef);
    if (typeof surface.branchId === "string") row.branchIds.add(surface.branchId);
    grouped.set(observedKey, row);
  }
  if (grouped.size === 0) throw new Error("CapSec manifest has no environment consumers");
  const observedDynamic = [...grouped.keys()].filter((key) => key.startsWith(dynamicPrefix));
  const configuredDynamic = Object.keys(dynamicDispositions);
  const missingDynamic = observedDynamic.filter((key) => !Object.hasOwn(dynamicDispositions, key));
  const staleDynamic = configuredDynamic.filter((key) => !grouped.has(key));
  if (missingDynamic.length || staleDynamic.length) {
    throw new Error(
      `dynamic environment classification drift; missing=${missingDynamic.join(",") || "none"}; stale=${staleDynamic.join(",") || "none"}`,
    );
  }

  const consumers = [...grouped.entries()]
    .sort(([left], [right]) => compareStrings(left, right))
    .map(([observedKey, evidence]) => {
      const name = exactName(observedKey);
      const disposition = name
        ? applicationSet.has(name)
          ? "application-behavior"
          : "privileged-control"
        : dynamicDispositions[observedKey];
      return {
        observedKey,
        ...(name ? { name } : {}),
        disposition,
        sourceRefs: [...evidence.sourceRefs].sort(compareStrings),
        branchIds: [...evidence.branchIds].sort(compareStrings),
      };
    });
  const observedExact = new Set(consumers.flatMap((row) => (row.name ? [row.name] : [])));
  const staleApplicationNames = applicationNames.filter((name) => !observedExact.has(name));
  if (staleApplicationNames.length) {
    throw new Error(
      `intentional application behavior names are not source-observed: ${staleApplicationNames.join(", ")}`,
    );
  }
  if (allowlistDecision.status !== "decided" && allowlist.length !== 0) {
    throw new Error("an undecided real-environment allowlist must be empty");
  }

  return {
    schema,
    sourceManifestSchema: manifest.implementationManifestSchema,
    sourceManifestStatus: manifest.status,
    allowlistDecision: {
      status: allowlistDecision.status,
      names: allowlist,
    },
    releaseEligible: allowlistDecision.status === "decided",
    realEnvironment: {
      posture: "capture-then-clear-default-deny",
      restore: "allowlist-only",
    },
    applicationEnvironment: {
      reads: "exact-name-capsec-gated-base-plus-principal-overlay",
      writes: "principal-overlay-only",
      childInheritance: "exact-overlay-state",
      privilegedControls: "typed-internal-config-process-env-and-host-side-channel-inert",
    },
    nameAlgebra: {
      unix: "byte-preserving-canonical-environment-name-or-record-and-reject",
      duplicateInput: "first-wins-and-record",
      windows: "case-insensitive-uppercase-canonicalization-deferred-with-target",
    },
    consumers,
  };
}

function renderRust(digest, releaseEligible) {
  return `// @generated by bun run generate:compiled-environment-profile; do not edit.\n` +
    `// @ref LLP 0029#4-compiled-mode-authority — the stub pins the reviewed environment consumer taxonomy\n` +
    `pub const COMPILED_ENVIRONMENT_PROFILE_SCHEMA: &str = ${JSON.stringify(schema)};\n` +
    `pub const COMPILED_ENVIRONMENT_PROFILE_DOMAIN: &str = ${JSON.stringify(domain)};\n` +
    `pub const COMPILED_ENVIRONMENT_PROFILE_DIGEST: &str =\n` +
    `    ${JSON.stringify(digest)};\n` +
    `pub const COMPILED_ENVIRONMENT_PROFILE_RELEASE_ELIGIBLE: bool = ${releaseEligible};\n` +
    `\n#[cfg(test)]\nmod tests {\n` +
    `    #[test]\n` +
    `    fn generated_compiled_environment_profile_digest_matches_bytes() {\n` +
    `        let bytes = include_bytes!(concat!(\n` +
    `            env!("CARGO_MANIFEST_DIR"),\n` +
    `            "/vendored-generated/compiled-environment-profile.canonical.json"\n` +
    `        ));\n` +
    `        let text = std::str::from_utf8(bytes).unwrap();\n` +
    `        let value = capsec_semantics::strict_json::parse_strict(text).unwrap();\n` +
    `        assert_eq!(\n` +
    `            capsec_semantics::canonical::to_jcs_bytes(&value).unwrap(),\n` +
    `            bytes\n` +
    `        );\n` +
    `        assert_eq!(value["schema"], super::COMPILED_ENVIRONMENT_PROFILE_SCHEMA);\n` +
    `        assert_eq!(\n` +
    `            capsec_semantics::digest::compute_domain_digest(\n` +
    `                super::COMPILED_ENVIRONMENT_PROFILE_DOMAIN,\n` +
    `                &value,\n` +
    `                &[],\n` +
    `            )\n` +
    `            .unwrap(),\n` +
    `            super::COMPILED_ENVIRONMENT_PROFILE_DIGEST,\n` +
    `        );\n` +
    `    }\n` +
    `}\n`;
}

function renderTypeScript(digest, releaseEligible) {
  return `// GENERATED FILE - DO NOT EDIT.\n` +
    `// Source: config/compiled-environment-profile.json + CapSec implementation manifest\n` +
    `// Generator: bun packages/ibex-devtools/src/scripts/generate-compiled-environment-profile.mjs\n\n` +
    `export const COMPILED_ENVIRONMENT_PROFILE_SCHEMA = ${JSON.stringify(schema)};\n` +
    `export const COMPILED_ENVIRONMENT_PROFILE_DOMAIN = ${JSON.stringify(domain)};\n` +
    `export const COMPILED_ENVIRONMENT_PROFILE_DIGEST = ${JSON.stringify(digest)};\n` +
    `export const COMPILED_ENVIRONMENT_PROFILE_RELEASE_ELIGIBLE = ${releaseEligible};\n`;
}

export function renderCompiledEnvironmentProfile(config, manifest) {
  const profile = buildCompiledEnvironmentProfile(config, manifest);
  const canonical = canonicalJson(profile);
  const digest = computeDomainDigest(domain, profile);
  return {
    profile,
    digest,
    outputs: [
      [canonicalOutPath, canonical],
      [rustOutPath, renderRust(digest, profile.releaseEligible)],
      [tsOutPath, renderTypeScript(digest, profile.releaseEligible)],
    ],
  };
}

function readStrict(filePath) {
  return parseJsonStrict(fs.readFileSync(filePath), path.relative(repoRoot, filePath));
}

export function run({ check }) {
  const rendered = renderCompiledEnvironmentProfile(
    readStrict(configPath),
    readStrict(implementationManifestPath),
  );
  const stale = [];
  for (const [outPath, content] of rendered.outputs) {
    if (fs.existsSync(outPath) && fs.readFileSync(outPath, "utf8") === content) continue;
    if (check) stale.push(path.relative(repoRoot, outPath));
    else {
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, content);
      console.log(`wrote ${path.relative(repoRoot, outPath)}`);
    }
  }
  if (stale.length) {
    throw new Error(
      `compiled environment profile is stale: ${stale.join(", ")}; run bun run generate:compiled-environment-profile`,
    );
  }
  if (check) console.log("compiled environment profile is fresh");
  return rendered;
}

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  try {
    run({ check: process.argv.includes("--check") });
  } catch (error) {
    console.error(`error: ${error.message}`);
    process.exit(1);
  }
}
