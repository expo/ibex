#!/usr/bin/env node
import fs from 'fs/promises';
import path from 'path';
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
  }
}

if (!opts.entry || !opts.out) {
  console.error('Usage: rolldown-bundle.mjs --entry <file> --out <file> [--sourcemap]');
  process.exit(2);
}

const entry = path.resolve(process.cwd(), opts.entry);
const out = path.resolve(process.cwd(), opts.out);

const bundle = await rolldown(createRolldownConfig({
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
}));

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
                // identity. @ref LLP 0013#resolved-questions (ENG-22621)
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

// Emit a dependency manifest next to the output so the runtime's bundle
// cache can invalidate when any module in the graph changes, not just the
// entry file. Real file paths only —
// virtual modules (\0-prefixed) and externals are skipped.
try {
  const moduleIds = new Set([entry]);
  for (const item of writeResult?.output ?? []) {
    if (item?.type === 'chunk' && item.modules) {
      for (const id of Object.keys(item.modules)) {
        if (!id.startsWith('\0') && path.isAbsolute(id)) {
          moduleIds.add(id);
        }
      }
    }
  }
  await fs.writeFile(
    `${out}.deps.json`,
    JSON.stringify({ version: 1, entry, deps: [...moduleIds].sort() })
  );
} catch (err) {
  console.error(`warning: failed to write bundle deps manifest: ${err?.message || err}`);
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
