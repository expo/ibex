#!/usr/bin/env node
/**
 * Replace hermes-lean-sys's release tag and complete target pin table from a
 * verified immutable release's SHA256SUMS.
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

if (process.argv.length !== 4) {
  die('usage: scripts/update-hermes-lean-sys-pins.mjs <verified-SHA256SUMS> <verified-release-tag>');
}

const pins = [
  ['aarch64-apple-darwin', 'hermes-vanilla-aarch64-apple-darwin.tar.gz'],
  ['x86_64-apple-darwin', 'hermes-vanilla-x86_64-apple-darwin.tar.gz'],
  ['aarch64-apple-ios', 'hermes-vanilla-aarch64-apple-ios.tar.gz'],
  ['aarch64-apple-ios-sim', 'hermes-vanilla-universal-apple-ios-simulator.tar.gz'],
  ['x86_64-apple-ios', 'hermes-vanilla-universal-apple-ios-simulator.tar.gz'],
  ['aarch64-apple-tvos', 'hermes-vanilla-aarch64-apple-tvos.tar.gz'],
  ['aarch64-apple-tvos-sim', 'hermes-vanilla-aarch64-apple-tvos-simulator.tar.gz'],
  ['x86_64-unknown-linux-gnu', 'hermes-vanilla-x86_64-unknown-linux-gnu.tar.gz'],
  ['aarch64-unknown-linux-gnu', 'hermes-vanilla-aarch64-unknown-linux-gnu.tar.gz'],
  ['aarch64-linux-android', 'hermes-vanilla-aarch64-linux-android.tar.gz'],
  ['x86_64-pc-windows-msvc', 'hermes-vanilla-x86_64-pc-windows-msvc.tar.gz'],
];
const archiveAssets = new Set(pins.map(([, asset]) => asset));
const releaseAssets = new Set(
  [...archiveAssets].flatMap((asset) => [asset, `${asset}.sigstore.json`]),
);

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const publisherPath = resolve(repoRoot, '.github/workflows/hermes-vanilla-publish.yml');
const publisher = readFileSync(publisherPath, 'utf8');
const expectedReleaseTag = publisher.match(/^  RELEASE_TAG: (hermes-vanilla-[a-f0-9]{12}-v[1-9][0-9]*)$/m)?.[1];
if (!expectedReleaseTag) die(`cannot find the staged release tag in ${publisherPath}`);

const releaseTag = process.argv[3];
if (releaseTag !== expectedReleaseTag) {
  die(`release tag ${releaseTag} does not equal staged publisher tag ${expectedReleaseTag}`);
}

const checksumsPath = resolve(process.argv[2]);
const checksums = new Map();
for (const [index, line] of readFileSync(checksumsPath, 'utf8').split(/\r?\n/).entries()) {
  if (!line.trim()) continue;
  const match = line.match(/^([0-9a-fA-F]{64})\s+\*?([A-Za-z0-9_.-]+)$/);
  if (!match) die(`${checksumsPath}:${index + 1}: malformed checksum line`);
  const [, digest, asset] = match;
  if (checksums.has(asset)) die(`${checksumsPath}:${index + 1}: duplicate checksum for ${asset}`);
  checksums.set(asset, digest.toLowerCase());
}

if (checksums.size !== releaseAssets.size) {
  die(`${checksumsPath} names ${checksums.size} assets; expected ${releaseAssets.size}`);
}
for (const asset of releaseAssets) {
  if (!checksums.has(asset)) die(`${checksumsPath} has no checksum for ${asset}`);
}
for (const asset of checksums.keys()) {
  if (!releaseAssets.has(asset)) die(`${checksumsPath} contains unexpected release asset ${asset}`);
}

const pinsPath = resolve(repoRoot, 'crates/hermes-lean-sys/build_support.rs');
const source = readFileSync(pinsPath, 'utf8');
const releasePattern = /pub\(crate\) const RELEASE_TAG: &str = "[^"]+";/;
if (!releasePattern.test(source)) die(`cannot find RELEASE_TAG in ${pinsPath}`);
const tableStart = source.indexOf('pub(crate) const PINNED_BUNDLES:');
const tableEnd = source.indexOf('\n];', tableStart);
if (tableStart === -1 || tableEnd === -1) die(`cannot find PINNED_BUNDLES in ${pinsPath}`);

const table = [
  'pub(crate) const PINNED_BUNDLES: &[BundlePin] = &[',
  ...pins.flatMap(([target, asset]) => [
    '    BundlePin {',
    `        target: "${target}",`,
    `        asset: "${asset}",`,
    `        sha256: "${checksums.get(asset)}",`,
    '    },',
  ]),
  '];',
].join('\n');

const withRelease = source.replace(
  releasePattern,
  `pub(crate) const RELEASE_TAG: &str = "${releaseTag}";`,
);
const adjustedTableStart = withRelease.indexOf('pub(crate) const PINNED_BUNDLES:');
const adjustedTableEnd = withRelease.indexOf('\n];', adjustedTableStart);
const updated = `${withRelease.slice(0, adjustedTableStart)}${table}${withRelease.slice(adjustedTableEnd + 3)}`;
writeFileSync(pinsPath, updated);
console.log(`updated ${pinsPath} to ${releaseTag} from ${checksumsPath}`);
