// Generate language bindings from the runtime identity authority
// (runtime-identity.json — LLP 0012).
//
// Usage: bun packages/ibex-devtools/src/scripts/generate-runtime-identity.ts [--check]
//
// Outputs (provenance-headered per CLAUDE.md §10):
//   packages/ibex-runtime-js/src/identity.generated.ts
//   src/identity_generated.rs
//
// --check verifies the outputs are current without writing (the
// runtime-identity-bindings-fresh registered check).

import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseJsonStrict } from './capsec-contract.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../../..');
const authorityPath = path.join(repoRoot, 'runtime-identity.json');
const tsOutPath = path.join(repoRoot, 'packages/ibex-runtime-js/src/identity.generated.ts');
const rsOutPath = path.join(repoRoot, 'src/identity_generated.rs');
const projectionOutPath = path.join(
  repoRoot,
  'vendored-generated/runtime-identity-projection.canonical.json'
);
const runtimeIdentitySchema = 'ibex/runtime-identity/1';
const runtimeIdentityDomain = 'ibex:runtime-identity:1';

interface Identity {
  version: number;
  name: string;
  processTitle: string;
  userAgent: string;
  release: { name: string };
  versions: Record<string, string>;
  compat: { bun: { versionWhenEnabled: string } };
}

const identity = parseJsonStrict(
  fs.readFileSync(authorityPath),
  'runtime-identity.json'
) as Identity & Record<string, unknown>;

function requireExactKeys(
  value: unknown,
  expected: readonly string[],
  label: string
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} keys must be exactly ${wanted.join(', ')}`);
  }
}

function requireNonEmptyString(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
}

requireExactKeys(
  identity,
  ['$comment', 'compat', 'llp', 'name', 'processTitle', 'release', 'userAgent', 'version', 'versions'],
  'runtime identity authority'
);
if (!Number.isSafeInteger(identity.version) || identity.version < 1) {
  throw new Error('runtime identity version must be a positive safe integer');
}
for (const [label, value] of [
  ['name', identity.name],
  ['processTitle', identity.processTitle],
  ['userAgent', identity.userAgent],
] as const) {
  requireNonEmptyString(value, `runtime identity ${label}`);
}
requireExactKeys(identity.release, ['name'], 'runtime identity release');
requireNonEmptyString(identity.release.name, 'runtime identity release.name');
if (!identity.versions || typeof identity.versions !== 'object' || Array.isArray(identity.versions)) {
  throw new Error('runtime identity versions must be an object');
}
if (Object.keys(identity.versions).length === 0) {
  throw new Error('runtime identity versions must not be empty');
}
for (const [key, value] of Object.entries(identity.versions)) {
  requireNonEmptyString(key, 'runtime identity version key');
  requireNonEmptyString(value, `runtime identity versions.${key}`);
}
requireNonEmptyString(identity.versions.node, 'runtime identity versions.node');
requireNonEmptyString(identity.versions.ibex, 'runtime identity versions.ibex');
requireExactKeys(identity.compat, ['bun'], 'runtime identity compat');
requireExactKeys(identity.compat.bun, ['versionWhenEnabled'], 'runtime identity compat.bun');
requireNonEmptyString(
  identity.compat.bun.versionWhenEnabled,
  'runtime identity compat.bun.versionWhenEnabled'
);

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
}

const projection = {
  schema: runtimeIdentitySchema,
  version: identity.version,
  name: identity.name,
  processTitle: identity.processTitle,
  userAgent: identity.userAgent,
  release: identity.release,
  versions: identity.versions,
  compat: identity.compat,
};
const projectionBytes = canonicalJson(projection);
const runtimeIdentityDigest = `sha256-${crypto
  .createHash('sha256')
  .update(runtimeIdentityDomain, 'utf8')
  .update(Buffer.from([0]))
  .update(projectionBytes, 'utf8')
  .digest('base64url')}`;

const provenance = (comment: string) =>
  `${comment} GENERATED FILE - DO NOT EDIT.\n` +
  `${comment} Source authority: runtime-identity.json (LLP 0012)\n` +
  `${comment} Generator: bun packages/ibex-devtools/src/scripts/generate-runtime-identity.ts\n`;

const versionEntries = Object.entries(identity.versions);

const tsOut =
  provenance('//') +
  `\nexport const RUNTIME_NAME = ${JSON.stringify(identity.name)};\n` +
  `export const PROCESS_TITLE = ${JSON.stringify(identity.processTitle)};\n` +
  `export const USER_AGENT = ${JSON.stringify(identity.userAgent)};\n` +
  `export const RELEASE_NAME = ${JSON.stringify(identity.release.name)};\n` +
  `export const RUNTIME_VERSIONS: ReadonlyArray<readonly [string, string]> = [\n` +
  versionEntries.map(([k, v]) => `  [${JSON.stringify(k)}, ${JSON.stringify(v)}],`).join('\n') +
  `\n] as const;\n` +
  `export const BUN_COMPAT_VERSION = ${JSON.stringify(identity.compat.bun.versionWhenEnabled)};\n` +
  `export const RUNTIME_IDENTITY_SCHEMA = ${JSON.stringify(runtimeIdentitySchema)};\n` +
  `export const RUNTIME_IDENTITY_DOMAIN = ${JSON.stringify(runtimeIdentityDomain)};\n` +
  `export const RUNTIME_IDENTITY_DIGEST = ${JSON.stringify(runtimeIdentityDigest)};\n`;

const versionsJsObject =
  '{ ' + versionEntries.map(([k, v]) => `${k}: '${v}'`).join(', ') + ' }';

const rsOut =
  provenance('//') +
  `\n/// Runtime identity constants (LLP 0012).\n` +
  `pub const RUNTIME_NAME: &str = ${JSON.stringify(identity.name)};\n` +
  `pub const PROCESS_TITLE: &str = ${JSON.stringify(identity.processTitle)};\n` +
  `pub const USER_AGENT: &str = ${JSON.stringify(identity.userAgent)};\n` +
  `pub const RELEASE_NAME: &str = ${JSON.stringify(identity.release.name)};\n` +
  `pub const NODE_VERSION: &str = ${JSON.stringify(identity.versions.node)};\n` +
  `pub const IBEX_VERSION: &str = ${JSON.stringify(identity.versions.ibex)};\n` +
  `/// The full versions table as a JS object literal, for host bootstrap\n` +
  `/// snippets that seed process.versions before the runtime bundle loads.\n` +
  `pub const VERSIONS_JS_OBJECT: &str = ${JSON.stringify(versionsJsObject)};\n` +
  `pub const RUNTIME_IDENTITY_SCHEMA: &str = ${JSON.stringify(runtimeIdentitySchema)};\n` +
  `pub const RUNTIME_IDENTITY_DOMAIN: &str = ${JSON.stringify(runtimeIdentityDomain)};\n` +
  `pub const RUNTIME_IDENTITY_DIGEST: &str = ${JSON.stringify(runtimeIdentityDigest)};\n` +
  `\n#[cfg(test)]\nmod tests {\n` +
  `    #[test]\n` +
  `    fn generated_runtime_identity_digest_matches_projection() {\n` +
  `        let bytes = include_bytes!(concat!(\n` +
  `            env!("CARGO_MANIFEST_DIR"),\n` +
  `            "/vendored-generated/runtime-identity-projection.canonical.json"\n` +
  `        ));\n` +
  `        let text = std::str::from_utf8(bytes).unwrap();\n` +
  `        let value = capsec_semantics::strict_json::parse_strict(text).unwrap();\n` +
  `        assert_eq!(\n` +
  `            capsec_semantics::canonical::to_jcs_bytes(&value).unwrap(),\n` +
  `            bytes\n` +
  `        );\n` +
  `        assert_eq!(value["schema"], super::RUNTIME_IDENTITY_SCHEMA);\n` +
  `        assert_eq!(\n` +
  `            capsec_semantics::digest::compute_domain_digest(\n` +
  `                super::RUNTIME_IDENTITY_DOMAIN,\n` +
  `                &value,\n` +
  `                &[],\n` +
  `            )\n` +
  `            .unwrap(),\n` +
  `            super::RUNTIME_IDENTITY_DIGEST,\n` +
  `        );\n` +
  `    }\n` +
  `}\n`;

const check = process.argv.includes('--check');
let stale: string[] = [];
for (const [outPath, content] of [
  [tsOutPath, tsOut],
  [rsOutPath, rsOut],
  [projectionOutPath, projectionBytes],
] as const) {
  const current = fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf8') : null;
  if (current === content) continue;
  if (check) {
    stale.push(path.relative(repoRoot, outPath));
  } else {
    fs.writeFileSync(outPath, content);
    console.log(`wrote ${path.relative(repoRoot, outPath)}`);
  }
}

if (check) {
  if (stale.length > 0) {
    console.error(
      `runtime identity bindings are stale: ${stale.join(', ')}\n` +
        `Regenerate with: bun packages/ibex-devtools/src/scripts/generate-runtime-identity.ts`
    );
    process.exit(1);
  }
  console.log('runtime identity bindings are fresh');
}
