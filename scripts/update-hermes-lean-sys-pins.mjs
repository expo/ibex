#!/usr/bin/env node
/**
 * Rewrite hermes-lean-sys's target pin table from a verified SHA256SUMS.
 *
 * Before running this script, the maintainer must run `gh attestation verify`
 * for every archive exactly as documented in docs/hermes-vanilla-release.md.
 * SHA256SUMS alone does not authenticate the publisher or source revision.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function die(message) {
  console.error(`update-hermes-lean-sys-pins: ${message}`);
  process.exit(1);
}

if (process.argv.length !== 3) {
  die('usage: scripts/update-hermes-lean-sys-pins.mjs <verified-SHA256SUMS>');
}

const checksumsPath = resolve(process.argv[2]);
const checksums = new Map();
for (const [index, line] of readFileSync(checksumsPath, 'utf8').split(/\r?\n/).entries()) {
  if (!line.trim()) continue;
  const match = line.match(/^([0-9a-fA-F]{64})\s+\*?([A-Za-z0-9_.-]+)$/);
  if (!match) die(`${checksumsPath}:${index + 1}: malformed checksum line`);
  const [, digest, asset] = match;
  if (!asset.endsWith('.tar.gz')) continue;
  if (!asset.startsWith('hermes-vanilla-')) {
    die(`${checksumsPath}:${index + 1}: unexpected archive ${asset}`);
  }
  if (checksums.has(asset)) die(`${checksumsPath}:${index + 1}: duplicate checksum for ${asset}`);
  checksums.set(asset, digest.toLowerCase());
}

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const pinsPath = resolve(repoRoot, 'crates/hermes-lean-sys/build_support.rs');
const source = readFileSync(pinsPath, 'utf8');
const tableStart = source.indexOf('pub(crate) const PINNED_BUNDLES:');
const tableEnd = source.indexOf('\n];', tableStart);
if (tableStart === -1 || tableEnd === -1) die(`cannot find PINNED_BUNDLES in ${pinsPath}`);

const assets = new Set();
const table = source.slice(tableStart, tableEnd + 3).replace(
  /(asset:\s*"([^"]+)",\s*sha256:\s*")([^"]+)(")/g,
  (whole, prefix, asset, _oldDigest, suffix) => {
    const digest = checksums.get(asset);
    if (!digest) die(`${checksumsPath} has no checksum for ${asset}`);
    assets.add(asset);
    return `${prefix}${digest}${suffix}`;
  },
);

if (assets.size !== 9) die(`pin table names ${assets.size} unique assets; expected 9`);
for (const asset of checksums.keys()) {
  if (!assets.has(asset)) die(`${checksumsPath} contains unexpected archive ${asset}`);
}

const updated = `${source.slice(0, tableStart)}${table}${source.slice(tableEnd + 3)}`;
writeFileSync(pinsPath, updated);
console.log(`updated ${pinsPath} from ${checksumsPath}`);
