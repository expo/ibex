#!/usr/bin/env node
// @ref LLP 0057.000#l1--the-bindings-door — hermes-lean-sys owns the exact
// engine/compiler identity shared by bindings and runtimes.
/**
 * Produce the canonical v2 Hermes input receipt for one release bundle.
 *
 * The bundle root contains the target's ordered static link closure, public
 * headers, and (for the build host) hermesc. The receipt binds every one of
 * those inputs without a build-date field, so identical inputs produce
 * identical receipt bytes.
 *
 *   node scripts/hermes-input-receipt.mjs <bundle-dir> \
 *     --target aarch64-apple-darwin --profile release \
 *     --engine-archive lib/libhermesvm_a.a \
 *     --lean-engine-archive lib/libhermesvmlean_a.a \
 *     --build-flag=-DHERMES_ENABLE_DEBUGGER=false \
 *     --link-directive=rustc-link-lib=static=hermesvm_a
 */

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCHEMA = 'ibex/hermes-upstream-pinned-receipt/2';
const CANONICAL_EMPTY_PATCH_SET = createHash('sha256').update('').digest('hex');
const PATCHED_SYMBOLS = [
  'ex_hermes_vm_current_package_id',
  'ex_hermes_vm_collect_package_ids',
  'ex_hermes_vm_disable_eval',
  'ex_hermes_vm_set_pending_package_id',
];

function die(message) {
  console.error(`hermes-input-receipt: ${message}`);
  process.exit(1);
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function isFile(path) {
  return existsSync(path) && lstatSync(path).isFile();
}

function parseArguments(argv) {
  const options = new Map();
  const positionals = [];
  const repeatable = new Set(['--archive', '--build-flag', '--link-directive']);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument.startsWith('--')) {
      positionals.push(argument);
      continue;
    }
    const equals = argument.indexOf('=');
    const name = equals === -1 ? argument : argument.slice(0, equals);
    const value = equals === -1 ? argv[index += 1] : argument.slice(equals + 1);
    if (!value || value.startsWith('--')) die(`${name} requires a value`);
    if (!repeatable.has(name) && options.has(name)) die(`${name} may appear only once`);
    options.set(name, [...(options.get(name) ?? []), value]);
  }
  if (positionals.length !== 1) {
    die('usage: hermes-input-receipt.mjs <bundle-dir> --target <triple> --profile <name> --engine-archive <path> --link-directive <directive> [...]');
  }
  const known = new Set([
    '--archive', '--build-flag', '--bytecode-version', '--commit', '--compiler',
    '--engine-archive', '--headers', '--lean-engine-archive', '--link-directive', '--out',
    '--profile', '--target',
  ]);
  for (const name of options.keys()) {
    if (!known.has(name)) die(`unknown option ${name}`);
  }
  const one = (name) => options.get(name)?.[0];
  const many = (name) => options.get(name) ?? [];
  return { bundle: positionals[0], one, many };
}

function inside(root, requested, label) {
  const path = resolve(root, requested);
  const rel = relative(root, path);
  if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    die(`${label} escapes the bundle root: ${requested}`);
  }
  return path;
}

function canonicalRelative(root, path) {
  return relative(root, path).split(sep).join('/');
}

function walkFiles(root) {
  if (!existsSync(root)) return [];
  const files = [];
  const visit = (directory) => {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name);
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) die(`bundle manifests may not contain symlinks: ${path}`);
      if (stat.isDirectory()) visit(path);
      else if (stat.isFile()) files.push(path);
      else die(`bundle manifests support only regular files and directories: ${path}`);
    }
  };
  visit(root);
  return files;
}

function sourceIdentity(repoRoot, commitOverride) {
  let sourceCommit = commitOverride;
  let sourceRef = '';
  let sourceVersion = '';
  try {
    if (process.platform === 'win32') {
      const pins = readFileSync(join(repoRoot, 'scripts/hermes-version.sh'), 'utf8');
      const literal = (name) => process.env[name]
        || pins.match(new RegExp(`${name}="\\$\\{${name}:-([^}]+)\\}"`))?.[1];
      sourceCommit ||= literal('IBEX_HERMES_VANILLA_SOURCE_COMMIT');
      sourceVersion = literal('IBEX_HERMES_VERSION');
      sourceRef = process.env.IBEX_HERMES_SOURCE_REF || `hermes-v${sourceVersion}`;
    } else {
      const pin = execFileSync('bash', [
        '-c',
        'source "$1" && printf "%s\\t%s\\t%s" "$IBEX_HERMES_VANILLA_SOURCE_COMMIT" "$IBEX_HERMES_SOURCE_REF" "$IBEX_HERMES_VERSION"',
        'hermes-input-receipt',
        join(repoRoot, 'scripts/hermes-version.sh').replaceAll('\\', '/'),
      ], { encoding: 'utf8' }).trim();
      const [commit, ref, version] = pin.split('\t');
      sourceCommit ||= commit;
      sourceRef = ref;
      sourceVersion = version;
    }
  } catch (error) {
    die(`cannot read vanilla Hermes pin: ${error.message}`);
  }
  if (!/^[0-9a-f]{40}$/.test(sourceCommit ?? '')) {
    die(`vanilla Hermes pin is not a 40-hex commit: ${sourceCommit}`);
  }
  if (!sourceRef || !sourceVersion) die('vanilla Hermes source ref/version pin is absent');
  return { sourceCommit, sourceRef, sourceVersion };
}

function exportedSymbols(engineBinary) {
  let output;
  try {
    if (process.platform === 'win32') {
      output = execFileSync('dumpbin', ['/symbols', engineBinary], {
        encoding: 'utf8',
        maxBuffer: 128 * 1024 * 1024,
      });
    } else {
      const args = process.platform === 'darwin'
        ? ['-gU', engineBinary]
        : ['-g', '--defined-only', engineBinary];
      output = execFileSync('nm', args, { encoding: 'utf8', maxBuffer: 128 * 1024 * 1024 });
    }
  } catch (error) {
    die(`cannot read symbols from ${engineBinary}: ${error.message}`);
  }
  return output
    .split('\n')
    .map((line) => process.platform === 'win32'
      ? (/\bUNDEF\b/.test(line) ? undefined : line.match(/\bExternal\s+\|\s+(\S+)/)?.[1])
      : line.trim().match(/^(?:[0-9a-fA-F]+\s+)?[A-Za-z]\s+(\S+)$/)?.[1])
    .filter(Boolean);
}

function bytecodeVersion(compiler, override) {
  if (override !== undefined) {
    if (!/^[1-9][0-9]*$/.test(override)) die(`invalid HBC bytecode version: ${override}`);
    return Number(override);
  }
  let versionOutput;
  try {
    versionOutput = execFileSync(compiler, ['-version'], { encoding: 'utf8' });
  } catch (error) {
    die(`cannot read the HBC bytecode version from ${compiler}: ${error.message}`);
  }
  const match = versionOutput.match(/HBC bytecode version:\s*([1-9][0-9]*)/);
  if (!match) die(`hermesc did not report an HBC bytecode version: ${compiler}`);
  return Number(match[1]);
}

const { bundle, one, many } = parseArguments(process.argv.slice(2));
const requestedBundleDir = resolve(bundle);
if (!existsSync(requestedBundleDir) || !statSync(requestedBundleDir).isDirectory()) {
  die(`bundle directory does not exist: ${requestedBundleDir}`);
}
// The repository's local engine installs are intentionally symlinked. Resolve
// only the bundle root; links inside the published tree remain forbidden.
const bundleDir = realpathSync(requestedBundleDir);
const target = one('--target');
const profile = one('--profile') ?? 'release';
if (!target || !/^[A-Za-z0-9_.-]+$/.test(target)) die('--target must name one release target');
if (!/^[A-Za-z0-9_.-]+$/.test(profile)) die('--profile contains unsupported characters');
const requestedEngineArchive = one('--engine-archive');
if (!requestedEngineArchive) die('--engine-archive must name the full VM archive linked for this target');
const requestedLeanEngineArchive = one('--lean-engine-archive');
const linkDirectives = many('--link-directive');
if (linkDirectives.length === 0 || linkDirectives.some((item) => !item.trim() || /[\r\n]/.test(item))) {
  die('at least one non-empty --link-directive is required');
}
const buildFlags = many('--build-flag');
if (buildFlags.some((item) => !item.trim() || /[\r\n]/.test(item))) die('build flags must be non-empty single lines');

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const { sourceCommit, sourceRef, sourceVersion } = sourceIdentity(repoRoot, one('--commit'));
const outPath = one('--out') ? resolve(one('--out')) : join(bundleDir, 'hermes-input-receipt.json');

const configuredCompiler = one('--compiler') || process.env.IBEX2_HERMESC;
const hostPlatform = process.platform === 'darwin' ? 'macos' : process.platform;
const toolArch = process.arch === 'x64' ? 'x64' : process.arch === 'arm64' ? 'arm64' : process.arch;
const compilerCandidates = configuredCompiler
  ? [resolve(configuredCompiler)]
  : [
      join(bundleDir, 'bin', `hermesc${process.platform === 'win32' ? '.exe' : ''}`),
      join(repoRoot, 'tools/hermes-vanilla', `hermesc-${hostPlatform}-${toolArch}${process.platform === 'win32' ? '.exe' : ''}`),
    ];
const compiler = compilerCandidates.find(isFile);
if (!compiler) die(`no hermesc at ${compilerCandidates.join(' or ')}`);

const requestedArchives = many('--archive');
let archivePaths;
if (requestedArchives.length > 0) {
  archivePaths = requestedArchives.map((path) => inside(bundleDir, path, 'archive'));
} else {
  const roots = ['lib', 'macos-static', 'linux-static', 'windows-static']
    .map((path) => join(bundleDir, path));
  archivePaths = roots.flatMap(walkFiles).filter((path) => /\.(?:a|lib)$/.test(path));
}
archivePaths = [...new Set(archivePaths)].sort((a, b) => {
  const left = canonicalRelative(bundleDir, a);
  const right = canonicalRelative(bundleDir, b);
  return left < right ? -1 : left > right ? 1 : 0;
});
if (archivePaths.length === 0) die('bundle has no static archives');
for (const path of archivePaths) if (!isFile(path)) die(`archive is not a regular file: ${path}`);

const engineBinary = inside(bundleDir, requestedEngineArchive, 'engine archive');
const expectedEngineName = target.endsWith('-pc-windows-msvc')
  ? 'hermesvm_a.lib'
  : 'libhermesvm_a.a';
if (basename(engineBinary) !== expectedEngineName) {
  die(`engine archive must be the target's full VM archive ${expectedEngineName}`);
}
if (!isFile(engineBinary)) die(`engine archive is not a regular file: ${engineBinary}`);
if (!archivePaths.includes(engineBinary)) {
  die('engine archive is not present in the archive manifest');
}

let leanEngineBinary;
if (requestedLeanEngineArchive) {
  leanEngineBinary = inside(bundleDir, requestedLeanEngineArchive, 'lean engine archive');
  const expectedLeanEngineName = target.endsWith('-pc-windows-msvc')
    ? 'hermesvmlean_a.lib'
    : 'libhermesvmlean_a.a';
  if (basename(leanEngineBinary) !== expectedLeanEngineName) {
    die(`lean engine archive must be the target's lean VM archive ${expectedLeanEngineName}`);
  }
  if (!isFile(leanEngineBinary)) {
    die(`lean engine archive is not a regular file: ${leanEngineBinary}`);
  }
  if (!archivePaths.includes(leanEngineBinary)) {
    die('lean engine archive is not present in the archive manifest');
  }
}

const symbols = exportedSymbols(engineBinary);
const inspectedSymbols = [symbols];
if (leanEngineBinary) inspectedSymbols.push(exportedSymbols(leanEngineBinary));
const foundPatched = PATCHED_SYMBOLS.filter((patched) => inspectedSymbols.some((archiveSymbols) =>
  archiveSymbols.some((symbol) => symbol === patched || symbol === `_${patched}`)
));
if (foundPatched.length > 0) {
  die(`refusing an empty-patch-set receipt for a patched engine; it exports ${foundPatched.join(', ')}`);
}

const headersRoot = one('--headers')
  ? inside(bundleDir, one('--headers'), 'headers directory')
  : [join(bundleDir, 'include'), join(bundleDir, 'hermes-headers')]
      .find((path) => existsSync(path));
if (!headersRoot || !lstatSync(headersRoot).isDirectory()) die('bundle has no headers directory');
const headerFiles = walkFiles(headersRoot);
if (headerFiles.length === 0) die(`headers directory is empty: ${headersRoot}`);

const archives = archivePaths.map((path) => ({
  path: canonicalRelative(bundleDir, path),
  digest: `sha256-${sha256File(path)}`,
}));
const enginePath = canonicalRelative(bundleDir, engineBinary);
const engineArchive = archives.find((archive) => archive.path === enginePath);
const compilerPath = relative(bundleDir, compiler);
const compilerName = compilerPath !== '..' && !compilerPath.startsWith(`..${sep}`) && !isAbsolute(compilerPath)
  ? canonicalRelative(bundleDir, compiler)
  : basename(compiler);
const receipt = {
  schema: SCHEMA,
  upstream: {
    artifact: 'facebook/hermes',
    sourceCommit,
    sourceRef,
    sourceVersion,
  },
  patchSet: {
    digest: `sha256-${CANONICAL_EMPTY_PATCH_SET}`,
    applied: [],
    verifiedAbsentSymbols: PATCHED_SYMBOLS,
  },
  target,
  profile,
  build: { flags: buildFlags },
  bytecode: { version: bytecodeVersion(compiler, one('--bytecode-version')) },
  compiler: {
    binary: compilerName,
    digest: `sha256-${sha256File(compiler)}`,
  },
  engine: {
    binary: enginePath,
    binaryDigest: engineArchive.digest,
    variant: symbols.some((symbol) =>
      /16AsyncDebuggerAPI(?:[0-9]|C[123]|D[012])/.test(symbol) || /\?[^@]+@AsyncDebuggerAPI@/.test(symbol)
    ) ? 'debugger' : 'release',
  },
  archives,
  headers: headerFiles.map((path) => ({
    path: canonicalRelative(bundleDir, path),
    digest: `sha256-${sha256File(path)}`,
  })),
  linkDirectives,
};

writeFileSync(outPath, `${JSON.stringify(receipt, null, 2)}\n`);
console.log(`wrote ${outPath}`);
console.log(`  upstream      ${sourceCommit}`);
console.log(`  target        ${target}`);
console.log(`  profile       ${profile}`);
console.log(`  HBC version   ${receipt.bytecode.version}`);
console.log(`  archives      ${archives.length}`);
console.log(`  headers       ${receipt.headers.length}`);
