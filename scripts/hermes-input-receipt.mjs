#!/usr/bin/env node
// @ref LLP 0058.000.001#5-build-artifact-and-dependency-isolation — HermesInputReceipt (G0)
/**
 * Produce a HermesInputReceipt for an installed Hermes engine.
 *
 * A distinct producer, deliberately: LLP 0058.000.001 §5 requires the four
 * receipt schemas to have distinct producers and no self-hash, and keeping this
 * out of build-hermes.sh also means the reviewed engine's cache identity does
 * not move every time the receipt format does.
 *
 * The claim the receipt makes is narrow and checkable: THIS engine was built
 * from THIS upstream commit with an EMPTY Ibex patch set. "Vanilla" stops being
 * a build flag someone remembered to pass and becomes a property of an artifact.
 *
 *   node scripts/hermes-input-receipt.mjs <engine-dir> [--out <path>] [--commit <sha>]
 *
 * Exits non-zero if the engine carries patched symbols, which is the one thing
 * a receipt claiming an empty patch set must never be written over.
 */

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

const SCHEMA = 'ibex/hermes-upstream-pinned-receipt/1';

/** The digest of an empty patch set — what "vanilla" has to hash to. */
const CANONICAL_EMPTY_PATCH_SET = createHash('sha256').update('').digest('hex');

/** Symbols the carried patch series exports. Their absence is the evidence. */
const PATCHED_SYMBOLS = [
  'ex_hermes_vm_current_package_id',
  'ex_hermes_vm_collect_package_ids',
  'ex_hermes_vm_disable_eval',
  'ex_hermes_vm_set_pending_package_id',
];

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function die(message) {
  console.error(`hermes-input-receipt: ${message}`);
  process.exit(1);
}

function flagValue(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) {
    return undefined;
  }
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) {
    die(`${name} requires a value`);
  }
  return value;
}

const args = process.argv.slice(2);
if (args.length < 1 || args[0].startsWith('--')) {
  die('usage: hermes-input-receipt.mjs <engine-dir> [--out <path>] [--commit <sha>]');
}
const engineDir = resolve(args[0]);
const outPath = flagValue(args, '--out') ?? join(engineDir, 'hermes-input-receipt.json');
const commitOverride = flagValue(args, '--commit');

const framework = join(engineDir, 'hermesvm.framework/Versions/1/hermesvm');
if (!existsSync(framework)) {
  die(`no engine binary at ${framework}`);
}

// The negative guarantee, checked rather than asserted: an engine carrying the
// patch stack's exports is not an empty-patch-set engine, whatever produced it.
let exported = '';
try {
  exported = execFileSync('nm', ['-gU', framework], { encoding: 'utf8' });
} catch (error) {
  die(`cannot read symbols from ${framework}: ${error.message}`);
}
const found = PATCHED_SYMBOLS.filter((symbol) => exported.includes(symbol));
if (found.length > 0) {
  die(
    `refusing to write an empty-patch-set receipt for a PATCHED engine; it exports ${found.join(', ')}`
  );
}

// The receipt must not claim an empty patch set while a patch series sits in
// the tree as a build input. Recorded, so a reader can tell "no patches exist"
// from "patches exist and were not applied" — only the second needs the check
// above to mean anything.
const repoRoot = resolve(new URL('..', import.meta.url).pathname);
const patchDir = join(repoRoot, 'patches/hermes');
const patchesPresent = existsSync(patchDir)
  ? readdirSync(patchDir).filter((name) => name.endsWith('.patch')).sort()
  : [];

const hermescDir = join(repoRoot, 'tools/hermes-vanilla');
const hermesc = existsSync(hermescDir)
  ? readdirSync(hermescDir)
      .filter((name) => name.startsWith('hermesc-'))
      .map((name) => join(hermescDir, name))[0]
  : undefined;

let sourceCommit = commitOverride;
let sourceRef = '';
let sourceVersion = '';
try {
  const pin = execFileSync(
    'bash',
    [
      '-c',
      'source "$1" && printf "%s\\t%s\\t%s" "$IBEX_HERMES_VANILLA_SOURCE_COMMIT" "$IBEX_HERMES_SOURCE_REF" "$IBEX_HERMES_VERSION"',
      'hermes-input-receipt',
      join(repoRoot, 'scripts/hermes-version.sh'),
    ],
    { encoding: 'utf8' }
  ).trim();
  const [commit, ref, version] = pin.split('\t');
  sourceCommit = sourceCommit || commit;
  sourceRef = ref;
  sourceVersion = version;
} catch (error) {
  die(`cannot read vanilla Hermes pin: ${error.message}`);
}
if (!/^[0-9a-f]{40}$/.test(sourceCommit)) {
  die(`vanilla Hermes pin is not a 40-hex commit: ${sourceCommit}`);
}

const receipt = {
  schema: SCHEMA,
  producedOn: new Date().toISOString().slice(0, 10),
  upstream: {
    artifact: 'facebook/hermes',
    sourceCommit,
    sourceRef,
    sourceVersion,
  },
  engine: {
    binary: basename(framework),
    binaryDigest: `sha256-${sha256File(framework)}`,
    // Debugger-enabled builds are ~35% slower to boot (LLP 0063 §6), so which
    // variant an artifact is must be part of its identity, not folklore.
    variant: exported.includes('AsyncDebuggerAPI') ? 'debugger' : 'release',
    target: process.platform === 'darwin' ? 'apple' : process.platform,
  },
  patchSet: {
    // The claim. An empty set hashes to the digest of no input at all.
    digest: `sha256-${CANONICAL_EMPTY_PATCH_SET}`,
    applied: [],
    presentInTree: patchesPresent,
    verifiedAbsentSymbols: PATCHED_SYMBOLS,
  },
  compiler: hermesc
    ? { binary: basename(hermesc), digest: `sha256-${sha256File(hermesc)}` }
    : null,
};

writeFileSync(outPath, `${JSON.stringify(receipt, null, 2)}\n`);
console.log(`wrote ${outPath}`);
console.log(`  upstream      ${receipt.upstream.sourceCommit}`);
console.log(`  variant       ${receipt.engine.variant}`);
console.log(`  patch set     empty (${patchesPresent.length} patches present in tree, 0 applied)`);
console.log(`  hermesc       ${receipt.compiler ? receipt.compiler.binary : '(absent)'}`);
