#!/usr/bin/env node
/**
 * Build script for compiling builtin module source files via rolldown.
 *
 * Usage:
 *   bun packages/ibex-devtools/src/scripts/build-builtins.mjs --src-dir src/builtins --out-dir $OUT_DIR/builtins
 *
 * Discovers all .js/.ts files in --src-dir, compiles them as individual CJS
 * modules with Hermes-compatible transforms, and writes one output file per
 * module to --out-dir.
 */
import path from 'path';
import fs from 'fs';
import { createRolldownConfig } from './transforms.mjs';

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
  if (arg === '--src-dir') {
    opts.srcDir = args[++i];
  } else if (arg === '--out-dir') {
    opts.outDir = args[++i];
  }
}

if (!opts.srcDir || !opts.outDir) {
  console.error('Usage: build-builtins.mjs --src-dir <dir> --out-dir <dir>');
  process.exit(2);
}

const srcDir = path.resolve(process.cwd(), opts.srcDir);
const outDir = path.resolve(process.cwd(), opts.outDir);

// Discover entry files
const entries = fs.readdirSync(srcDir)
  .filter(f => /\.(js|ts)$/.test(f) && !f.endsWith('.d.ts'))
  .sort();

if (entries.length === 0) {
  console.error(`No .js/.ts files found in ${srcDir}`);
  process.exit(1);
}

// Build input map: { moduleName: absolutePath }
const input = {};
for (const entry of entries) {
  const name = entry.replace(/\.(js|ts)$/, '');
  input[name] = path.join(srcDir, entry);
}

const bundle = await rolldown(createRolldownConfig({
  input,
  extraExternalModules: ['bun:test'],
}));

fs.mkdirSync(outDir, { recursive: true });

await bundle.write({
  dir: outDir,
  format: 'cjs',
  exports: 'auto',
  entryFileNames: '[name].js',
});

if (typeof bundle.close === 'function') {
  await bundle.close();
}

console.log(`Built ${entries.length} builtin modules → ${outDir}`);
