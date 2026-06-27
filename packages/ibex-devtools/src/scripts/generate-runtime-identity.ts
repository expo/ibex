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
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../../..');
const authorityPath = path.join(repoRoot, 'runtime-identity.json');
const tsOutPath = path.join(repoRoot, 'packages/ibex-runtime-js/src/identity.generated.ts');
const rsOutPath = path.join(repoRoot, 'src/identity_generated.rs');

interface Identity {
  version: number;
  name: string;
  processTitle: string;
  userAgent: string;
  release: { name: string };
  versions: Record<string, string>;
  compat: { bun: { versionWhenEnabled: string } };
}

const identity: Identity = JSON.parse(fs.readFileSync(authorityPath, 'utf8'));

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
  `export const BUN_COMPAT_VERSION = ${JSON.stringify(identity.compat.bun.versionWhenEnabled)};\n`;

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
  `pub const VERSIONS_JS_OBJECT: &str = ${JSON.stringify(versionsJsObject)};\n`;

const check = process.argv.includes('--check');
let stale: string[] = [];
for (const [outPath, content] of [
  [tsOutPath, tsOut],
  [rsOutPath, rsOut],
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
