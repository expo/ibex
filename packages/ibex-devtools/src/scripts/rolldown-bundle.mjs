#!/usr/bin/env node
import fs from 'fs/promises';
import path from 'path';
import { createHash } from 'crypto';
import {
  createRolldownConfig,
  runtimeImportMetaDefine,
  packageOfModuleId,
  packageIdentityOfModuleId,
} from './transforms.mjs';

// @ref LLP 0013#mechanism-3 — encode a package name into a chunk name reversibly
// (filesystem-safe), so the runtime loader can recover the package a chunk
// belongs to and stamp its Domain principal. Only `/` needs escaping for scopes.
const PKG_CHUNK_PREFIX = '__ibexpkg__';
function encodePackageChunkName(pkg) {
  return PKG_CHUNK_PREFIX + String(pkg).replace(/\//g, '__SLASH__');
}

let rolldown;
try {
  ({ rolldown } = await import('rolldown'));
} catch (err) {
  console.error('Failed to load rolldown. Run `bun install` at the repo root to install JS dependencies.');
  console.error(err?.message || err);
  process.exit(1);
}

const args = process.argv.slice(2);
const opts = {};
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--entry') {
    opts.entry = args[++i];
  } else if (arg === '--out') {
    opts.out = args[++i];
  } else if (arg === '--sourcemap') {
    opts.sourcemap = true;
  } else if (arg === '--format') {
    opts.format = args[++i];
  } else if (arg === '--name') {
    opts.name = args[++i];
  } else if (arg === '--lower-classes') {
    opts.lowerClasses = true;
  } else if (arg === '--compartments') {
    // @ref LLP 0013#mechanism-2 — per-package free-global rewrite.
    opts.compartments = true;
  } else if (arg === '--per-package-chunks') {
    // @ref LLP 0013#mechanism-3 — emit one chunk per npm package so each
    // compiles into its own Domain at load time, giving bundled apps
    // per-package frame attribution (not just the unbundled path).
    opts.perPackageChunks = true;
  } else if (arg === '--cache-manifest') {
    // Runtime generated-code cache: bind graph inputs and outputs by digest.
    // Build-time vendoring does not need or commit this sidecar.
    opts.cacheManifest = true;
  }
}

if (!opts.entry || !opts.out) {
  console.error('Usage: rolldown-bundle.mjs --entry <file> --out <file> [--sourcemap]');
  process.exit(2);
}

const entry = path.resolve(process.cwd(), opts.entry);
const out = path.resolve(process.cwd(), opts.out);
const utf8Compare = (left, right) =>
  Buffer.compare(Buffer.from(String(left), 'utf8'), Buffer.from(String(right), 'utf8'));
const digestFile = async (file) =>
  createHash('sha256').update(await fs.readFile(file)).digest('hex');
const missingDigest = createHash('sha256').update('missing').digest('hex');
const metadataNames = [
  'package.json', 'bun.lock', 'bun.lockb', 'package-lock.json',
  'pnpm-lock.yaml', 'yarn.lock', 'tsconfig.json', 'jsconfig.json',
];
const directoryDigest = async (directory) => {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const rows = [];
  for (const item of entries) {
    const kind = item.isSymbolicLink() ? 'l' : item.isDirectory() ? 'd' : item.isFile() ? 'f' : 'o';
    let target = '';
    if (kind === 'l') target = await fs.readlink(path.join(directory, item.name));
    rows.push({ name: item.name, row: `${kind}\0${item.name}\0${target}\n` });
  }
  rows.sort((a, b) => utf8Compare(a.name, b.name));
  return createHash('sha256').update(rows.map((item) => item.row).join('')).digest('hex');
};

const resolutionInputMap = new Map();
const resolutionInputTasks = new Map();
const rememberResolutionInput = (record) => {
  // First observation wins: later hooks run after a resolver decision and
  // must never bless a mutation that changed that decision's precedence.
  if (!resolutionInputMap.has(record.path)) resolutionInputMap.set(record.path, record);
};
const snapshotPathState = async (candidate) => {
  const absolute = path.resolve(candidate);
  // Rolldown may resolve thousands of imports from the same directory. The
  // first pre-resolution observation is the security witness; recomputing its
  // full directory/file digest for every import is both redundant and O(graph
  // size × directory size). Reserve the path before awaiting so concurrent
  // resolve hooks cannot duplicate that work or replace the first witness.
  if (resolutionInputMap.has(absolute)) return;
  const inFlight = resolutionInputTasks.get(absolute);
  if (inFlight) return inFlight;
  const capture = (async () => {
    let record;
    try {
      const stat = await fs.lstat(absolute);
      if (stat.isSymbolicLink()) {
        record = {
          kind: 'symlink',
          path: absolute,
          sha256: createHash('sha256').update(await fs.readlink(absolute)).digest('hex'),
        };
      } else if (stat.isDirectory()) {
        record = { kind: 'directory', path: absolute, sha256: await directoryDigest(absolute) };
      } else if (stat.isFile()) {
        record = { kind: 'file', path: absolute, sha256: await digestFile(absolute) };
      } else {
        record = { kind: 'missing', path: absolute, sha256: missingDigest };
      }
    } catch {
      record = { kind: 'missing', path: absolute, sha256: missingDigest };
    }
    resolutionInputMap.set(absolute, record);
  })();
  resolutionInputTasks.set(absolute, capture);
  try {
    await capture;
  } finally {
    resolutionInputTasks.delete(absolute);
  }
};
const checkedSymlinkComponents = new Set();
const symlinkComponentTasks = new Map();
const addSymlinkComponents = async (file) => {
  const absolute = path.resolve(file);
  const parsed = path.parse(absolute);
  let current = parsed.root;
  for (const component of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    if (checkedSymlinkComponents.has(current)) continue;
    const existing = symlinkComponentTasks.get(current);
    if (existing) {
      await existing;
      continue;
    }
    const componentPath = current;
    const capture = (async () => {
      try {
        const stat = await fs.lstat(componentPath);
        if (stat.isSymbolicLink()) {
          rememberResolutionInput({
            kind: 'symlink',
            path: componentPath,
            sha256: createHash('sha256').update(await fs.readlink(componentPath)).digest('hex'),
          });
        }
        return true;
      } catch {
        return false;
      }
    })();
    symlinkComponentTasks.set(componentPath, capture);
    const exists = await capture;
    symlinkComponentTasks.delete(componentPath);
    checkedSymlinkComponents.add(componentPath);
    if (!exists) break;
  }
};
const extensionCandidates = ['', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json'];
const snapshotResolutionRequest = async (source, importer) => {
  if (typeof source !== 'string' || source.startsWith('\0')) return;
  const importerPath = importer && !importer.startsWith('\0') ? importer : entry;
  const base = path.dirname(importerPath);
  await addSymlinkComponents(importerPath);

  // Resolver configuration can live above a nested VCS/project boundary (for
  // example a workspace package with a hoisted package.json/tsconfig). Record
  // each exact metadata candidate through the filesystem root. Do not hash
  // whole ancestor directories: unrelated files in $HOME or / must not churn
  // an otherwise valid bundle cache.
  for (let current = base, depth = 0; depth < 64; depth++) {
    for (const name of metadataNames) await snapshotPathState(path.join(current, name));
    if (path.dirname(current) === current) break;
    current = path.dirname(current);
  }

  if (source.startsWith('.') || path.isAbsolute(source)) {
    const candidate = path.isAbsolute(source) ? source : path.resolve(base, source);
    await snapshotPathState(path.dirname(candidate));
    for (const extension of extensionCandidates) {
      await snapshotPathState(`${candidate}${extension}`);
      if (extension) await snapshotPathState(path.join(candidate, `index${extension}`));
    }
    await addSymlinkComponents(candidate);
    return;
  }

  const parts = source.split('/');
  const packageName = source.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  // Node package lookup does not stop at `.git` or the nearest package
  // metadata boundary. Witness every ancestor node_modules candidate so a
  // newly-created, closer hoisted package cannot make an old bundle resolve to
  // different code while all of its previous positive dependencies remain.
  for (let current = base, depth = 0; depth < 64; depth++) {
    const nodeModules = path.join(current, 'node_modules');
    const packageRoot = path.join(nodeModules, packageName);
    await snapshotPathState(nodeModules);
    await snapshotPathState(packageRoot);
    await snapshotPathState(path.join(packageRoot, 'package.json'));
    if (path.dirname(current) === current) break;
    current = path.dirname(current);
  }
};

const digestResolutionInput = async (record) => {
  try {
    const stat = await fs.lstat(record.path);
    if (record.kind === 'missing') return null;
    if (record.kind === 'symlink' && stat.isSymbolicLink()) {
      return createHash('sha256').update(await fs.readlink(record.path)).digest('hex');
    }
    if (record.kind === 'directory' && stat.isDirectory()) return directoryDigest(record.path);
    if (record.kind === 'file' && stat.isFile()) return digestFile(record.path);
    return null;
  } catch {
    return record.kind === 'missing' ? missingDigest : null;
  }
};

// Capture the exact pre-transform source text Rolldown hands to its plugin
// pipeline. The cache manifest is built from these bytes, not a post-build
// reread that could authenticate old output against a concurrently edited file.
const capturedModules = new Map();
let captureBarrierUsed = false;
const sourceCapturePlugin = {
  name: 'ibex-cache-source-capture',
  async resolveId(source, importer) {
    if (opts.cacheManifest) await snapshotResolutionRequest(source, importer);
    return null;
  },
  async transform(code, id) {
    if (!id.startsWith('\0') && path.isAbsolute(id)) {
      const real = await fs.realpath(id);
      capturedModules.set(real, {
        id,
        code,
        sha256: createHash('sha256').update(code).digest('hex'),
      });
      const barrierEntry = process.env.IBEX_TEST_BUNDLE_BARRIER_ENTRY;
      const barrierDir = process.env.IBEX_TEST_BUNDLE_BARRIER_DIR;
      if (!captureBarrierUsed && barrierEntry && barrierDir &&
          real === await fs.realpath(barrierEntry)) {
        captureBarrierUsed = true;
        await fs.mkdir(barrierDir, { recursive: true });
        await fs.writeFile(path.join(barrierDir, 'captured'), '');
        const deadline = Date.now() + 10000;
        while (!(await (async () => {
          try { await fs.stat(path.join(barrierDir, 'release')); return true; }
          catch { return false; }
        })())) {
          if (Date.now() >= deadline) throw new Error('bundle capture test barrier timed out');
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
      }
    }
    return null;
  },
};
if (opts.cacheManifest) await snapshotResolutionRequest(entry, undefined);
const rolldownConfig = createRolldownConfig({
  input: entry,
  // Disable tree-shaking so that calls with observable side effects
  // (e.g. URL.canParse() throwing on missing args, assert.throws callbacks)
  // are not silently removed during bundling.
  treeshake: false,
  // Keep relative .cjs files external so they go through runtime require().
  // This preserves require.cache, require.resolve, __dirname/__filename semantics.
  keepRelativeCjsExternal: true,
  define: runtimeImportMetaDefine,
  compartments: opts.compartments || false,
});
rolldownConfig.plugins.unshift(sourceCapturePlugin);
const bundle = await rolldown(rolldownConfig);

// @ref LLP 0013#mechanism-3 — per-package chunking. Group each npm package's
// modules into a chunk named after the package; the entry chunk requires them,
// and the runtime loader compiles each chunk into its own Domain stamped with
// the package principal. Off by default (one flat chunk); iife can't split.
const perPackageChunks = opts.perPackageChunks && (opts.format || 'cjs') !== 'iife';
const outDir = path.dirname(out);
const outBase = path.basename(out);
const writeResult = await bundle.write({
  format: opts.format || 'cjs',
  ...(opts.format === 'iife' ? { name: opts.name || 'ExactRuntimeBundle' } : {}),
  sourcemap: opts.sourcemap ? true : false,
  exports: 'auto',
  ...(perPackageChunks
    ? {
        // Multi-chunk output must use `dir` (+ names), not `file`.
        dir: outDir,
        entryFileNames: outBase,
        chunkFileNames: '[name].js',
        advancedChunks: {
          groups: [
            {
              name: (id) => {
                // Group by the version-qualified identity (`name@version`) so two
                // installed versions of one package become separate chunks (hence
                // separate Domains/principals), matching the runtime loader's
                // identity. @ref LLP 0013#resolved-questions — (ENG-22621)
                const pkg = packageIdentityOfModuleId(id);
                return pkg ? encodePackageChunkName(pkg) : null;
              },
              // Detect package modules via packageOfModuleId, which normalizes
              // path separators — a POSIX-only `/node_modules/` regex would miss
              // Windows ids using backslashes (`C:\app\node_modules\evil\...`),
              // silently leaving those packages in the root bundle and disabling
              // per-package attribution on Windows. (ENG-22698)
              test: (id) => packageOfModuleId(id) !== null,
            },
          ],
        },
      }
    : { file: out, codeSplitting: false }),
});

if (typeof bundle.close === 'function') {
  await bundle.close();
}

// Emit a content-addressed dependency/output manifest next to the output.
// Cache identity never trusts mtime or length: both every source in the graph
// and every published output are SHA-256 bound. Real file paths only — virtual
// modules (\0-prefixed) and externals are skipped.
if (opts.cacheManifest) {
  const moduleIds = new Set([await fs.realpath(entry)]);
  for (const item of writeResult?.output ?? []) {
    if (item?.type === 'chunk' && item.modules) {
      for (const id of Object.keys(item.modules)) {
        if (!id.startsWith('\0') && path.isAbsolute(id)) {
          moduleIds.add(await fs.realpath(id));
        }
      }
    }
  }
  const deps = [];
  for (const modulePath of [...moduleIds].sort(utf8Compare)) {
    const captured = capturedModules.get(modulePath);
    if (!captured) {
      throw new Error(`cache source capture missed ${modulePath}`);
    }
    const currentCode = await fs.readFile(modulePath, 'utf8');
    const currentDigest = createHash('sha256').update(currentCode).digest('hex');
    if (currentDigest !== captured.sha256) {
      throw new Error(`source changed while bundling: ${modulePath}`);
    }
    deps.push({ path: modulePath, sha256: captured.sha256 });
  }

  for (const record of resolutionInputMap.values()) {
    const currentDigest = await digestResolutionInput(record);
    if (currentDigest !== record.sha256) {
      throw new Error(`module resolution input changed while bundling: ${record.path}`);
    }
  }
  const resolutionInputs = [...resolutionInputMap.values()].sort((a, b) => {
    const byPath = utf8Compare(a.path, b.path);
    return byPath || utf8Compare(a.kind, b.kind);
  });
  const resolutionDigest = createHash('sha256')
    .update(JSON.stringify(resolutionInputs))
    .digest('hex');
  const outputs = [];
  const outputNames = new Set([path.basename(out)]);
  for (const item of writeResult?.output ?? []) {
    if (typeof item?.fileName === 'string') outputNames.add(item.fileName);
  }
  for (const outputName of outputNames) {
    const outputPath = path.join(outDir, outputName);
    outputs.push({ path: outputName, sha256: await digestFile(outputPath) });
  }
  outputs.sort((a, b) => utf8Compare(a.path, b.path));
  const graphDigest = createHash('sha256')
    .update(JSON.stringify(deps))
    .digest('hex');
  const manifestPath = `${out}.deps.json`;
  const manifestTmp = `${manifestPath}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(
    manifestTmp,
    JSON.stringify({
      version: 3,
      entry: await fs.realpath(entry),
      resolutionDigest,
      graphDigest,
      deps,
      resolutionInputs,
      outputs,
    })
  );
  await fs.rename(manifestTmp, manifestPath);
}

if (opts.lowerClasses) {
  let babel;
  try {
    babel = await import('@babel/core');
  } catch (err) {
    console.error('Failed to load @babel/core for --lower-classes. Run `bun install` at the repo root.');
    console.error(err?.message || err);
    process.exit(1);
  }

  const code = await fs.readFile(out, 'utf8');
  let inputSourceMap;
  const mapPath = `${out}.map`;
  if (opts.sourcemap) {
    try {
      inputSourceMap = JSON.parse(await fs.readFile(mapPath, 'utf8'));
    } catch {
      inputSourceMap = undefined;
    }
  }

  const result = await babel.transformAsync(code, {
    babelrc: false,
    configFile: false,
    filename: out,
    inputSourceMap,
    sourceMaps: opts.sourcemap ? true : false,
    plugins: [
      ['@babel/plugin-transform-classes', { loose: true }],
    ],
  });

  if (!result?.code) {
    console.error('Babel --lower-classes transform produced no output.');
    process.exit(1);
  }

  await fs.writeFile(out, result.code);
  if (opts.sourcemap && result.map) {
    await fs.writeFile(mapPath, JSON.stringify(result.map));
  }
}
