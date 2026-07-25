import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import {
  bootstrapInternalModules,
  meta,
  publicBuiltins,
  sources,
  specifiers,
  type Source,
} from '../../../../modules.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..', '..');
const SCRIPT_PATH = 'packages/ibex-devtools/src/scripts/generate-module-manifest.ts';

export const runtimeManifestOutputPath = path.join(
  repoRoot,
  'src',
  'builtins',
  'helpers',
  'runtime-module-manifest.cjs',
);

export const rustManifestFileName = 'builtin_manifest.generated.rs';

interface RegistryEntry {
  specifier: string;
  sourceKey: string;
  moduleBuiltin: boolean;
  bundleExternal: boolean;
}

interface DebugEntry extends RegistryEntry {
  sourceKind: Source['kind'];
  sourcePath: string | null;
  platformAvailability: string;
}

interface NormalizedManifest {
  registryEntries: RegistryEntry[];
  debugEntries: DebugEntry[];
  bundlerExternalModules: string[];
  moduleBuiltinList: string[];
  moduleBuiltinRuntimeSpecifiers: string[];
  nodeBuiltins: string[];
  nodeOnlyBuiltinModules: string[];
  publicBuiltins: { name: string; nodeOnly: boolean }[];
  reservedNodeOnlyBuiltins: string[];
  runtimeGatedNodeBuiltins: string[];
  staticBootstrapInternalModules: string[];
}

function assertUnique(values: readonly string[], label: string): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) {
      throw new Error(`Duplicate ${label}: ${value}`);
    }
    seen.add(value);
  }
}

function normalizeManifest(): NormalizedManifest {
  const sourceEntries = Object.entries(sources);
  assertUnique(sourceEntries.map(([key]) => key), 'module source key');

  for (const [key, source] of sourceEntries) {
    if (source.kind === 'inline') {
      if (!source.code) {
        throw new Error(`Inline source ${key} is missing code`);
      }
      continue;
    }

    if (!source.path) {
      throw new Error(`Source ${key} is missing a path`);
    }
  }

  const normalizedPublicBuiltins = publicBuiltins.map((entry) => ({
    name: entry.name,
    nodeOnly: entry.nodeOnly ?? meta.defaults.nodeOnly,
  }));
  assertUnique(
    normalizedPublicBuiltins.map((entry) => entry.name),
    'public builtin name',
  );

  const registryEntries: RegistryEntry[] = [];
  const debugEntries: DebugEntry[] = [];
  const seenSpecifiers = new Set<string>();

  for (const group of specifiers) {
    const source = sources[group.source];
    if (!source) {
      throw new Error(`Unknown source key in specifiers: ${group.source}`);
    }

    const moduleBuiltin = group.moduleBuiltin ?? meta.defaults.moduleBuiltin;
    const bundleExternal = group.bundleExternal ?? meta.defaults.bundleExternal;

    for (const name of group.names) {
      if (seenSpecifiers.has(name)) {
        throw new Error(`Duplicate registry specifier: ${name}`);
      }
      seenSpecifiers.add(name);

      registryEntries.push({
        specifier: name,
        sourceKey: group.source,
        moduleBuiltin,
        bundleExternal,
      });

      debugEntries.push({
        specifier: name,
        sourceKey: group.source,
        sourceKind: source.kind,
        sourcePath: source.path ?? null,
        platformAvailability: 'all',
        moduleBuiltin,
        bundleExternal,
      });
    }
  }

  const normalizedBootstrapInternalModules = [...bootstrapInternalModules];
  assertUnique(normalizedBootstrapInternalModules, 'bootstrap internal module');

  const reservedNodeOnlyBuiltins = [...meta.reservedNodeOnly];
  const nodeBuiltins = normalizedPublicBuiltins.map((entry) => entry.name);
  const runtimeGatedNodeBuiltins = [
    ...new Set([
      ...nodeBuiltins.map((name) => name.split('/')[0]),
      ...(meta.runtimeGatedNodeBuiltinRoots ?? []),
    ]),
  ].sort();
  // `moduleBuiltinList` feeds `module.builtinModules` and must only advertise
  // names that are actually requirable, so it agrees with `Module.isBuiltin`
  // (which is registry-backed via `moduleBuiltinRuntimeSpecifiers`). The
  // `reservedNodeOnly` names (`sqlite`, `sea`) have no registry entry — bare
  // `require('node:sqlite')` throws "Unsupported node builtin" — so advertising
  // them made bundlers leave those specifiers external and crash at runtime.
  // Reserved names are still exported via `nodeOnlyBuiltinModules`. (ENG-22981)
  const moduleBuiltinList = [...nodeBuiltins];
  const nodeOnlyBuiltinModules = [
    ...normalizedPublicBuiltins
      .filter((entry) => entry.nodeOnly)
      .map((entry) => entry.name),
    ...reservedNodeOnlyBuiltins,
  ];
  const moduleBuiltinRuntimeSpecifiers = registryEntries
    .filter((entry) => entry.moduleBuiltin)
    .map((entry) => entry.specifier);
  const bundlerExternalModules = registryEntries
    .filter((entry) => entry.bundleExternal)
    .map((entry) => entry.specifier);

  return {
    registryEntries,
    debugEntries,
    bundlerExternalModules,
    moduleBuiltinList,
    moduleBuiltinRuntimeSpecifiers,
    nodeBuiltins,
    nodeOnlyBuiltinModules,
    publicBuiltins: normalizedPublicBuiltins,
    reservedNodeOnlyBuiltins,
    runtimeGatedNodeBuiltins,
    staticBootstrapInternalModules: normalizedBootstrapInternalModules,
  };
}

function renderJsValue(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export function renderRuntimeModuleManifest(): string {
  const manifest = normalizeManifest();

  return `// @generated by ${SCRIPT_PATH}
// Do not edit by hand.
const publicBuiltins = Object.freeze(${renderJsValue(manifest.publicBuiltins)});

const reservedNodeOnlyBuiltins = Object.freeze(${renderJsValue(manifest.reservedNodeOnlyBuiltins)});

const registryEntries = Object.freeze(${renderJsValue(manifest.registryEntries)});

const staticBootstrapInternalModules = Object.freeze(${renderJsValue(manifest.staticBootstrapInternalModules)});

const nodeBuiltins = Object.freeze(publicBuiltins.map((entry) => entry.name));
const runtimeGatedNodeBuiltins = Object.freeze(${renderJsValue(manifest.runtimeGatedNodeBuiltins)});
// Only requirable builtins are advertised via module.builtinModules so it agrees
// with Module.isBuiltin; reservedNodeOnly names stay in nodeOnlyBuiltinModules. (ENG-22981)
const moduleBuiltinList = Object.freeze([...nodeBuiltins]);
const nodeOnlyBuiltinModules = Object.freeze(
  [
    ...publicBuiltins.filter((entry) => entry.nodeOnly).map((entry) => entry.name),
    ...reservedNodeOnlyBuiltins,
  ],
);
const moduleBuiltinRuntimeSpecifiers = Object.freeze(
  registryEntries.filter((entry) => entry.moduleBuiltin).map((entry) => entry.specifier),
);
const bundlerExternalModules = Object.freeze(
  registryEntries.filter((entry) => entry.bundleExternal).map((entry) => entry.specifier),
);

module.exports = Object.freeze({
  bundlerExternalModules,
  moduleBuiltinList,
  moduleBuiltinRuntimeSpecifiers,
  nodeBuiltins,
  nodeOnlyBuiltinModules,
  publicBuiltins,
  registryEntries,
  reservedNodeOnlyBuiltins,
  runtimeGatedNodeBuiltins,
  staticBootstrapInternalModules,
});
`;
}

function rustStringLiteral(value: string): string {
  for (let hashCount = 0; hashCount < 16; hashCount += 1) {
    const hashes = '#'.repeat(hashCount);
    const closing = `"${hashes}`;
    if (!value.includes(closing)) {
      return `r${hashes}"${value}"${hashes}`;
    }
  }

  return JSON.stringify(value);
}

function renderRustSourceExpression(source: Source): string {
  if (source.kind === 'generated') {
    return `include_str!(concat!(env!("OUT_DIR"), ${rustStringLiteral(`/${source.path}`)}))`;
  }

  if (source.kind === 'repo') {
    return `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), ${rustStringLiteral(`/${source.path}`)}))`;
  }

  return rustStringLiteral(source.code ?? '');
}

function renderRustOptionString(value: string | null): string {
  if (value === null) {
    return 'None';
  }
  return `Some(${rustStringLiteral(value)})`;
}

export function renderRustBuiltinManifest(): string {
  const manifest = normalizeManifest();
  const registrationLines = manifest.registryEntries.map(
    (entry) =>
      `    BuiltinManifestRegistration { specifier: ${rustStringLiteral(entry.specifier)}, source_key: ${rustStringLiteral(entry.sourceKey)} },`,
  );
  const debugLines = manifest.debugEntries.map(
    (entry) =>
      `    BuiltinManifestDebugEntry { specifier: ${rustStringLiteral(entry.specifier)}, source_key: ${rustStringLiteral(entry.sourceKey)}, source_kind: ${rustStringLiteral(entry.sourceKind)}, source_path: ${renderRustOptionString(entry.sourcePath)}, platform_availability: ${rustStringLiteral(entry.platformAvailability)}, module_builtin: ${entry.moduleBuiltin}, bundle_external: ${entry.bundleExternal} },`,
  );
  const gatedBuiltinLines = manifest.runtimeGatedNodeBuiltins.map(
    (name) => `    ${rustStringLiteral(name)},`,
  );
  const bootstrapInternalLines = manifest.staticBootstrapInternalModules.map(
    (name) => `    ${rustStringLiteral(name)},`,
  );
  const sourceLines = Object.entries(sources).map(
    ([sourceKey, source]) =>
      `        ${rustStringLiteral(sourceKey)} => ${renderRustSourceExpression(source)},`,
  );

  return `// @generated by ${SCRIPT_PATH}
// Do not edit by hand.

#[rustfmt::skip]
pub(crate) const BUILTIN_MANIFEST_REGISTRATIONS: &[BuiltinManifestRegistration] = &[
${registrationLines.join('\n')}
];

#[rustfmt::skip]
pub const RUNTIME_GATED_NODE_BUILTINS: &[&str] = &[
${gatedBuiltinLines.join('\n')}
];

#[rustfmt::skip]
pub(crate) const BOOTSTRAP_INTERNAL_MODULE_SPECIFIERS: &[&str] = &[
${bootstrapInternalLines.join('\n')}
];

#[rustfmt::skip]
pub(crate) const BUILTIN_MANIFEST_DEBUG_ENTRIES: &[BuiltinManifestDebugEntry] = &[
${debugLines.join('\n')}
];

fn generated_builtin_source(source_key: &str) -> Option<&'static str> {
    Some(match source_key {
${sourceLines.join('\n')}
        _ => return None,
    })
}
`;
}

function ensureFileContents(
  outputPath: string,
  contents: string,
  check: boolean,
): void {
  const existing = fs.existsSync(outputPath)
    ? fs.readFileSync(outputPath, 'utf8')
    : null;

  if (existing === contents) {
    return;
  }

  if (check) {
    throw new Error(`${path.relative(repoRoot, outputPath)} is out of date`);
  }

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, contents, 'utf8');
}

export function writeRuntimeModuleManifest(
  outputPath = runtimeManifestOutputPath,
  check = false,
): void {
  ensureFileContents(outputPath, renderRuntimeModuleManifest(), check);
}

export function writeRustBuiltinManifest(
  outDir: string,
  check = false,
): string {
  const outputPath = path.join(outDir, rustManifestFileName);
  ensureFileContents(outputPath, renderRustBuiltinManifest(), check);
  return outputPath;
}

interface CliOptions {
  check: boolean;
  jsOut?: string;
  rustOutDir?: string;
  skipJs: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    check: false,
    skipJs: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    switch (arg) {
      case '--check':
        options.check = true;
        break;
      case '--skip-js':
        options.skipJs = true;
        break;
      case '--js-out':
        index += 1;
        if (index >= argv.length) {
          throw new Error('--js-out requires a path');
        }
        options.jsOut = argv[index];
        break;
      case '--rust-out-dir':
        index += 1;
        if (index >= argv.length) {
          throw new Error('--rust-out-dir requires a path');
        }
        options.rustOutDir = argv[index];
        break;
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return options;
}

function main(): void {
  const options = parseArgs(process.argv.slice(2));

  if (!options.skipJs) {
    writeRuntimeModuleManifest(options.jsOut, options.check);
  }

  if (options.rustOutDir) {
    writeRustBuiltinManifest(options.rustOutDir, options.check);
  }
}

if (process.argv[1] === __filename) {
  main();
}
