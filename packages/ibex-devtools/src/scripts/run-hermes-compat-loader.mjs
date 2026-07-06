#!/usr/bin/env node
/**
 * Hermes-compat conformance runner for the REAL Ibex module-loader path
 * (ENG-22989, follow-up to ENG-22987's AST-path runner).
 *
 * @ref LLP 0019#the-enforced-conformance-seam — this runner is the
 * cross-implementation differential test holding the loader scanner (tier 2)
 * to the canonical AST authority's behavior (tier 1); loaderExpectations is
 * the only sanctioned place to record a tier divergence.
 *
 * Drives the shared for-of scoping corpus (hermes-compat-corpus.mjs) through
 * the actual built `ibex` binary. Each fixture is written as a module file and
 * loaded via `require()` from a generated entry, with `EXACT_COMPAT_TEST=1` so
 * the binary skips the rolldown pre-bundle (which would apply the AST
 * transform) and takes the in-process pipeline instead: SWC transpile, then
 * the embedded bootstrap loader's string-scanner `fixForOfScoping`
 * (src/engine/bootstrap/module-loader.js). That is the exact production path
 * for code the bundler never sees — NOT a unit-test copy of the scanner.
 *
 * The oracle for every fixture is the untransformed source run on V8/Node
 * (imported from run-hermes-compat-corpus.mjs so both runners share one
 * oracle). The loader path legitimately differs from the AST path on some
 * fixtures; those expected divergences are encoded EXPLICITLY and exactly in
 * `loaderExpectations` below — an unknown fixture, an unused expectation, or
 * a documented divergence that stops reproducing all fail the run (no silent
 * drift, LLP 0018).
 *
 * Usage:
 *   node run-hermes-compat-loader.mjs [--ibex /path/to/ibex]
 *   IBEX_BIN=/path/to/ibex node run-hermes-compat-loader.mjs
 * Default binary: <repo>/target/debug/ibex.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { forOfScopingCorpus } from './hermes-compat-corpus.mjs';
import { runV8 } from './run-hermes-compat-corpus.mjs';

const scriptsDir = fileURLToPath(new URL('.', import.meta.url));
const repoRoot = path.resolve(scriptsDir, '../../../..');

/**
 * Per-fixture expectations for the loader path, keyed by corpus fixture id.
 *
 *   - `matchesOracle: true`   the loader path reproduces the V8/Node oracle.
 *   - `matchesOracle: false`  documented loader-vs-oracle divergence:
 *     `stdout` is the EXACT output the loader path produces today and
 *     `reason` says why the divergence is accepted (or ticketed). When a
 *     loader change makes such a fixture match the oracle, the stale entry
 *     fails loudly (actual != stdout) and must be flipped to
 *     `matchesOracle: true` in the same change.
 *
 * The loader scanner and the AST transform legitimately disagree on WHICH
 * loops they rewrite (the scanner's line-based bails are coarser than the
 * AST walk, and it skips `for (var ...)` headers entirely where the AST path
 * rewrites them to the plain iterator shape), but rewrite-set differences
 * only matter here when they change observable behavior against the oracle.
 */
export const loaderExpectations = Object.freeze({
  'single-level-closure-capture': { matchesOracle: true },
  'nested-closure-capture': { matchesOracle: true },
  'destructured-binding-capture': { matchesOracle: true },
  'let-mutation-per-iteration': { matchesOracle: true },
  'method-this-binding': { matchesOracle: true },
  'live-iterator-semantics': {
    matchesOracle: true,
    note: 'ENG-22990: the scanner emits the explicit iterator-protocol shape, so live/lazy iteration is preserved (the old Array.from shape snapshotted)',
  },
  'arguments-preserved': {
    matchesOracle: true,
    note: 'ENG-22990: the per-iteration body is an arrow, so `arguments` resolves to the enclosing function (the old forEach callback bound its own)',
  },
  'bailed-break-continue': {
    matchesOracle: true,
    note: 'scanner bails on break/continue; the raw loop has no escaping closures, so raw Hermes output is spec-correct',
  },
  'bailed-asi-bare-break-continue': {
    matchesOracle: true,
    note: 'ENG-23137: the scanner bails on bare keyword matches now, so an ASI bare break/continue leaves the loop raw (spec-correct without escaping closures) instead of moving the body into an arrow where break is illegal',
  },
  'bailed-labeled-continue': {
    matchesOracle: true,
    note: 'ENG-23137: labeled continue bails the same bare-keyword way; both loops stay raw and raw output is spec-correct without escaping closures',
  },
  'minified-destructured-header': {
    matchesOracle: false,
    stdout: '["b:2","b:2"]',
    reason:
      'ENG-23137: the loader scanner only rewrites pretty-printed single-line `for (const ... of ...) {` ' +
      'headers by design (LLP 0019 accepted divergence — the scanner may bail where the AST authority ' +
      'rewrites, never the reverse), so a minified braceless header stays raw and its escaping closures ' +
      'keep capture-last behavior on non-block-scoping Hermes; the AST authority rewrites it',
  },
  'bailed-yield-body': {
    matchesOracle: true,
    note: 'scanner bails on yield; raw generator for-of is spec-correct without escaping closures',
  },
  'var-declared-loop-variable': {
    matchesOracle: true,
    note: 'scanner only matches const/let headers, leaving the var loop raw — and raw var capture-last IS the spec behavior',
  },
  'hazard-bailed-var-in-body': {
    matchesOracle: false,
    stdout: '["b:b","b:b"]',
    reason:
      'ENG-22990: the scanner now hazard-bails on a var declaration in the body (converged ' +
      'with the AST twin), leaving the loop raw — so escaping closures keep raw capture-last ' +
      'behavior on non-block-scoping Hermes, the same documented hole the corpus pins for the ' +
      'AST path (hermesMatchesOracle=false / rawHermesCaptureLast)',
  },
  'iterator-close-on-throw': {
    matchesOracle: true,
    note: 'ENG-22990: the emitted loop closes the iterator (iterator.return) when the body throws, matching native IteratorClose ordering',
  },
});

/**
 * Engine-premise canary. The body contains a `continue`, so the loader
 * scanner bails and the loop reaches the engine RAW. On the shipping Hermes
 * configuration (ES6BlockScoping=false) escaping closures then capture the
 * LAST value — the exact pitfall the loader rewrite exists to fix. If this
 * canary ever reports ["a","b"], the embedded engine has gained per-iteration
 * for-of bindings and the loader rewrite (and these expectations) should be
 * re-evaluated.
 */
const engineCanary = {
  id: 'engine-canary-raw-capture-last',
  expectedStdout: '["b","b"]',
  source: `
function collect(items) {
  const fns = [];
  for (const item of items) {
    if (items.length === -1) continue;
    fns.push(() => item);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect(["a", "b"])));
`,
};

export function resolveIbexBin(argv = process.argv) {
  // Resolve to an absolute path: fixtures run with a temp-dir cwd, so a
  // relative --ibex/IBEX_BIN would spawn ENOENT from inside the fixture dir.
  const flagIndex = argv.indexOf('--ibex');
  if (flagIndex !== -1 && argv[flagIndex + 1]) {
    return path.resolve(argv[flagIndex + 1]);
  }
  if (process.env.IBEX_BIN) {
    return path.resolve(process.env.IBEX_BIN);
  }
  return path.join(repoRoot, 'target', 'debug', 'ibex');
}

/**
 * Run one fixture source through the ibex binary's in-process loader path and
 * return { stdout, stderr, status }. The fixture is a separate module file
 * required from a shim entry, so the fixture source itself goes through the
 * loader's module pipeline (transpile + fixForOfScoping) verbatim.
 */
function runIbexFixture(ibexBin, id, source) {
  const dir = mkdtempSync(path.join(os.tmpdir(), `ibex-loader-conformance-${id}-`));
  try {
    writeFileSync(path.join(dir, 'fixture.js'), source);
    writeFileSync(
      path.join(dir, 'entry.js'),
      'globalThis.print = function (v) { console.log(String(v)); };\n' +
        'require("./fixture.js");\n',
    );
    const result = spawnSync(ibexBin, [path.join(dir, 'entry.js')], {
      encoding: 'utf8',
      timeout: 120000,
      cwd: dir,
      env: { ...process.env, EXACT_COMPAT_TEST: '1' },
    });
    return {
      stdout: (result.stdout ?? '').trim(),
      stderr: (result.stderr ?? '').trim(),
      status: result.status,
      error: result.error,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Run the corpus through the real ibex binary's loader path. Returns a
 * structured report; never throws on a fixture failure (failures are
 * collected per fixture). Throws only on harness misconfiguration (missing
 * binary).
 */
export function runLoaderCorpus({ ibexBin = resolveIbexBin() } = {}) {
  if (!ibexBin || !existsSync(ibexBin)) {
    throw new Error(
      `ibex binary not found at '${ibexBin}'. Build it (cargo build) or pass --ibex / IBEX_BIN.`,
    );
  }

  const results = [];

  // Expectation-table completeness, both directions (fail loud on drift).
  const corpusIds = new Set(forOfScopingCorpus.map((fixture) => fixture.id));
  for (const id of Object.keys(loaderExpectations)) {
    if (!corpusIds.has(id)) {
      results.push({
        id,
        ok: false,
        failures: [`loaderExpectations entry has no corpus fixture '${id}' — remove or fix the key`],
      });
    }
  }

  // Engine-premise canary first: it validates the environment the
  // per-fixture expectations are written against.
  {
    const failures = [];
    const run = runIbexFixture(ibexBin, engineCanary.id, engineCanary.source);
    if (run.status !== 0) {
      failures.push(
        `ibex exited ${run.status} (${run.error?.message ?? 'no spawn error'}): ${run.stderr}`,
      );
    } else if (run.stdout !== engineCanary.expectedStdout) {
      failures.push(
        `raw (scanner-bailed) for-of no longer captures-last: got ${run.stdout}, expected ` +
          `${engineCanary.expectedStdout}. The embedded Hermes appears to have per-iteration ` +
          'for-of bindings now — re-evaluate the loader rewrite and these expectations.',
      );
    }
    results.push({ id: engineCanary.id, ok: failures.length === 0, failures });
  }

  for (const fixture of forOfScopingCorpus) {
    const failures = [];
    const expectation = loaderExpectations[fixture.id];
    if (!expectation) {
      results.push({
        id: fixture.id,
        ok: false,
        failures: [
          `corpus fixture '${fixture.id}' has no loaderExpectations entry — every fixture must ` +
            'state whether the loader path matches the oracle',
        ],
      });
      continue;
    }

    let oracle;
    try {
      oracle = runV8(fixture.source);
    } catch (error) {
      failures.push(`oracle (raw on V8) threw: ${error?.message ?? error}`);
      results.push({ id: fixture.id, ok: false, failures });
      continue;
    }

    const expected = expectation.matchesOracle ? oracle : expectation.stdout;
    if (!expectation.matchesOracle && expectation.stdout === oracle) {
      failures.push(
        'documented divergence equals the oracle — the expectation entry is stale; flip it to matchesOracle: true',
      );
    }

    const run = runIbexFixture(ibexBin, fixture.id, fixture.source);
    if (run.status !== 0) {
      failures.push(
        `ibex exited ${run.status} (${run.error?.message ?? 'no spawn error'}): ${run.stderr}`,
      );
    } else if (run.stdout !== expected) {
      failures.push(
        expectation.matchesOracle
          ? `loader path != oracle: ibex=${run.stdout} oracle=${oracle}`
          : `loader path != documented divergence: ibex=${run.stdout} documented=${expected} oracle=${oracle}` +
            (run.stdout === oracle
              ? ' (the loader now matches the oracle — flip this expectation to matchesOracle: true)'
              : ''),
      );
    }

    results.push({
      id: fixture.id,
      ok: failures.length === 0,
      failures,
      divergenceDocumented: expectation.matchesOracle === false,
    });
  }

  return {
    ok: results.every((result) => result.ok),
    ibexBin,
    results,
  };
}

function main() {
  const report = runLoaderCorpus();
  const passed = report.results.filter((r) => r.ok).length;
  console.log(
    `hermes-compat loader corpus: ${passed}/${report.results.length} fixtures ok (ibex: ${report.ibexBin})`,
  );
  for (const result of report.results) {
    const tag = result.ok ? 'ok  ' : 'FAIL';
    const diverges = result.divergenceDocumented ? ' [documented divergence]' : '';
    console.log(`  ${tag} ${result.id}${diverges}`);
    for (const failure of result.failures) {
      console.log(`       - ${failure}`);
    }
  }
  process.exit(report.ok ? 0 : 1);
}

if (import.meta.main || process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
