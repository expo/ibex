#!/usr/bin/env bun
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../../..');
const outputPath = path.join(
  repoRoot,
  'vendored-generated',
  'source-fingerprint.generated.txt',
);
const roots = [
  path.join(repoRoot, 'src', 'builtins'),
  path.join(repoRoot, 'packages', 'ibex-runtime-js', 'src'),
  path.join(repoRoot, 'modules.ts'),
];

function collectFiles(input, files) {
  const metadata = fs.lstatSync(input);
  if (metadata.isDirectory()) {
    for (const entry of fs.readdirSync(input).sort()) {
      if (entry === 'node_modules') continue;
      collectFiles(path.join(input, entry), files);
    }
  } else if (metadata.isFile()) {
    files.push(input);
  }
}

function updateFnv1a(hash, bytes) {
  const prime = 1_099_511_628_211n;
  for (const byte of bytes) {
    hash = BigInt.asUintN(64, (hash ^ BigInt(byte)) * prime);
  }
  return hash;
}

const files = [];
for (const root of roots) collectFiles(root, files);
files.sort((left, right) => {
  const a = path.relative(repoRoot, left).split(path.sep).join('/');
  const b = path.relative(repoRoot, right).split(path.sep).join('/');
  return a < b ? -1 : a > b ? 1 : 0;
});

let hash = 14_695_981_039_346_656_037n;
for (const file of files) {
  const relative = path.relative(repoRoot, file).split(path.sep).join('/');
  hash = updateFnv1a(hash, Buffer.from(relative));
  hash = updateFnv1a(hash, Buffer.from([0]));
  hash = updateFnv1a(hash, fs.readFileSync(file));
  hash = updateFnv1a(hash, Buffer.from([0xff]));
}

const fingerprint = hash.toString(16).padStart(16, '0');
const rendered =
  '# GENERATED FILE - DO NOT EDIT.\n' +
  '# Source authority: src/builtins, packages/ibex-runtime-js/src, modules.ts (LLP 0018)\n' +
  '# Generator: bun run generate:vendored-fingerprint\n' +
  `${fingerprint}\n`;
const check = process.argv.includes('--check');

if (check) {
  if (!fs.existsSync(outputPath) || fs.readFileSync(outputPath, 'utf8') !== rendered) {
    console.error('Vendored source fingerprint is stale.');
    process.exit(1);
  }
} else {
  fs.writeFileSync(outputPath, rendered, 'utf8');
  console.log(`Wrote ${path.relative(repoRoot, outputPath)}`);
}
