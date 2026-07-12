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

// Capture the exact pre-transform source text Rolldown hands to its plugin
// pipeline. The cache manifest is built from these bytes, not a post-build
// reread that could authenticate old output against a concurrently edited file.
const capturedModules = new Map();
let captureBarrierUsed = false;
const sourceCapturePlugin = {
  name: 'ibex-cache-source-capture',
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
  const originalModuleIds = new Set([entry]);
  for (const item of writeResult?.output ?? []) {
    if (item?.type === 'chunk' && item.modules) {
      for (const id of Object.keys(item.modules)) {
        if (!id.startsWith('\0') && path.isAbsolute(id)) {
          moduleIds.add(await fs.realpath(id));
          originalModuleIds.add(id);
        }
      }
    }
  }
  const digestFile = async (file) =>
    createHash('sha256').update(await fs.readFile(file)).digest('hex');
  const deps = [];
  for (const modulePath of [...moduleIds].sort()) {
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

  const resolutionInputMap = new Map();
  const rememberResolutionInput = (record) => {
    resolutionInputMap.set(`${record.kind}\0${record.path}`, record);
  };
  const exists = async (candidate) => {
    try { await fs.lstat(candidate); return true; } catch { return false; }
  };
  const directoryDigest = async (directory) => {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    const rows = [];
    for (const item of entries) {
      let kind = item.isSymbolicLink() ? 'l' : item.isDirectory() ? 'd' : item.isFile() ? 'f' : 'o';
      let target = '';
      if (kind === 'l') target = await fs.readlink(path.join(directory, item.name));
      rows.push({ name: item.name, row: `${kind}\0${item.name}\0${target}\n` });
    }
    rows.sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)));
    return createHash('sha256').update(rows.map((item) => item.row).join('')).digest('hex');
  };
  const addDirectory = async (directory) => {
    const absolute = path.resolve(directory);
    try {
      const stat = await fs.stat(absolute);
      if (!stat.isDirectory()) return;
      rememberResolutionInput({
        kind: 'directory',
        path: absolute,
        sha256: await directoryDigest(absolute),
      });
    } catch {}
  };
  const addFile = async (file) => {
    const absolute = path.resolve(file);
    try {
      const stat = await fs.stat(absolute);
      if (!stat.isFile()) return;
      rememberResolutionInput({ kind: 'file', path: absolute, sha256: await digestFile(absolute) });
    } catch {}
  };
  const addSymlinkComponents = async (file) => {
    const absolute = path.resolve(file);
    const parsed = path.parse(absolute);
    let current = parsed.root;
    for (const component of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, component);
      try {
        const stat = await fs.lstat(current);
        if (stat.isSymbolicLink()) {
          const target = await fs.readlink(current);
          rememberResolutionInput({
            kind: 'symlink',
            path: current,
            sha256: createHash('sha256').update(target).digest('hex'),
          });
        }
      } catch { break; }
    }
  };
  const metadataNames = [
    'package.json', 'bun.lock', 'bun.lockb', 'package-lock.json',
    'pnpm-lock.yaml', 'yarn.lock', 'tsconfig.json', 'jsconfig.json',
  ];
  let projectRoot = path.dirname(entry);
  for (let current = projectRoot;; current = path.dirname(current)) {
    const hasMetadata = (await Promise.all(
      metadataNames.map((name) => exists(path.join(current, name)))
    )).some(Boolean);
    if (hasMetadata) {
      projectRoot = current;
    }
    if (await exists(path.join(current, '.git')) || path.dirname(current) === current) {
      if (await exists(path.join(current, '.git'))) projectRoot = current;
      break;
    }
  }
  for (const moduleId of originalModuleIds) {
    await addSymlinkComponents(moduleId);
    let current = path.dirname(moduleId);
    for (let depth = 0; depth < 64; depth++) {
      await addDirectory(current);
      for (const name of metadataNames) await addFile(path.join(current, name));
      if (current === projectRoot || path.dirname(current) === current) break;
      // An external symlink target only needs its package boundary; source
      // project ancestors are covered by the original symlinked module id.
      if (!path.resolve(current).startsWith(path.resolve(projectRoot)) &&
          await exists(path.join(current, 'package.json'))) break;
      current = path.dirname(current);
    }
  }
  const resolutionInputs = [...resolutionInputMap.values()].sort((a, b) => {
    const byPath = Buffer.compare(Buffer.from(a.path), Buffer.from(b.path));
    return byPath || a.kind.localeCompare(b.kind);
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
  outputs.sort((a, b) => a.path.localeCompare(b.path));
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
