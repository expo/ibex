#!/usr/bin/env node
/**
 * Standalone Hermes-compat conformance runner (LLP 0312, ENG-22987).
 *
 * Runs the shared for-of scoping corpus against the canonical AST transform and
 * the V8/Node spec oracle, and — when a Hermes binary is available — against the
 * shipping Hermes configuration this repo actually runs. It depends only on
 * local ibex-devtools modules and an optional Hermes binary, so it runs
 * Ibex-standalone with no Exact checkout.
 *
 * The Ibex runtime module loader has its own (string-scanner) for-of rewrite.
 * Adding that path as a second runner over this same corpus is ENG-22989 and is
 * deliberately out of scope here; this runner exercises the AST path only.
 *
 * Usage:
 *   node run-hermes-compat-corpus.mjs          # run corpus, print report
 *   IBEX_HERMES_BIN=/path/to/hermes node run-hermes-compat-corpus.mjs
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { fixForOfScoping } from './hermes-compat.mjs';
import { forOfScopingCorpus } from './hermes-compat-corpus.mjs';

const testDir = fileURLToPath(new URL('.', import.meta.url));

// Hermes binary resolution mirrors transforms.test.mjs: IBEX_HERMES_BIN wins,
// then an ibex-local tools/hermes checkout, then the exact monorepo's
// tools/hermes when ibex is vendored at <exact>/vendor/ibex.
export function resolveHermesBin() {
  return (
    [
      process.env.IBEX_HERMES_BIN,
      path.resolve(testDir, '../../../../tools/hermes/hermes'),
      path.resolve(testDir, '../../../../../../tools/hermes/hermes'),
    ].find((candidate) => candidate && existsSync(candidate)) ?? ''
  );
}

export function canRunHermes(candidate) {
  if (!candidate || !existsSync(candidate)) {
    return false;
  }
  const dir = mkdtempSync(path.join(os.tmpdir(), 'ibex-forof-hermes-probe-'));
  const file = path.join(dir, 'fixture.js');
  writeFileSync(file, 'print("ok");\n');
  const result = spawnSync(candidate, [file], { encoding: 'utf8', timeout: 30000 });
  return result.status === 0 && result.stdout.trim() === 'ok';
}

function runV8(code) {
  const lines = [];
  // eslint-disable-next-line no-new-func
  new Function('print', code)((value) => lines.push(String(value)));
  return lines.join('\n');
}

function runHermes(hermesBin, code) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'ibex-forof-hermes-'));
  const file = path.join(dir, 'fixture.js');
  writeFileSync(file, code);
  const result = spawnSync(hermesBin, [file], { encoding: 'utf8', timeout: 30000 });
  if (result.status !== 0) {
    throw new Error(
      `hermes failed: signal=${result.signal ?? 'none'} error=${result.error?.message ?? 'none'} stderr=${result.stderr}`,
    );
  }
  return result.stdout.trim();
}

/**
 * Run the corpus against the AST transform + V8 oracle, and against Hermes when
 * available. Returns a structured report; never throws on a fixture failure
 * (failures are collected per fixture).
 */
export function runCorpus({ hermesBin = resolveHermesBin() } = {}) {
  const hermesUsable = canRunHermes(hermesBin);
  const results = [];

  for (const fixture of forOfScopingCorpus) {
    const failures = [];
    let transformed;
    try {
      transformed = fixForOfScoping(fixture.source);
    } catch (error) {
      failures.push(`transform threw: ${error?.message ?? error}`);
      results.push({ id: fixture.id, ok: false, failures, hermesChecked: false });
      continue;
    }

    const didRewrite = transformed !== fixture.source;
    if (didRewrite !== fixture.rewrites) {
      failures.push(`expected rewrites=${fixture.rewrites} but transform ${didRewrite ? 'rewrote' : 'left raw'}`);
    }

    let oracle;
    try {
      oracle = runV8(fixture.source);
    } catch (error) {
      failures.push(`oracle (raw on V8) threw: ${error?.message ?? error}`);
    }

    if (oracle !== undefined) {
      let transformedOnV8;
      try {
        transformedOnV8 = runV8(transformed);
      } catch (error) {
        failures.push(`transformed on V8 threw: ${error?.message ?? error}`);
      }
      if (transformedOnV8 !== undefined && transformedOnV8 !== oracle) {
        failures.push(`transform changed V8 semantics: oracle=${oracle} transformed=${transformedOnV8}`);
      }
    }

    let hermesChecked = false;
    if (hermesUsable && oracle !== undefined) {
      hermesChecked = true;
      // Most fixtures assert the transform output yields spec semantics on the
      // shipping Hermes config. The documented hole (hermesMatchesOracle=false)
      // is a hazard-bailed loop whose raw output keeps capture-last on Hermes;
      // for it we assert the divergence via rawHermesCaptureLast instead.
      if (fixture.hermesMatchesOracle !== false) {
        try {
          const transformedOnHermes = runHermes(hermesBin, transformed);
          if (transformedOnHermes !== oracle) {
            failures.push(`transformed on Hermes != oracle: hermes=${transformedOnHermes} oracle=${oracle}`);
          }
        } catch (error) {
          failures.push(`transformed on Hermes threw: ${error?.message ?? error}`);
        }
      }
      if (fixture.rawHermesCaptureLast !== undefined) {
        try {
          const rawOnHermes = runHermes(hermesBin, fixture.source);
          if (rawOnHermes !== fixture.rawHermesCaptureLast) {
            failures.push(
              `raw on Hermes != documented capture-last: hermes=${rawOnHermes} expected=${fixture.rawHermesCaptureLast}`,
            );
          }
        } catch (error) {
          failures.push(`raw on Hermes threw: ${error?.message ?? error}`);
        }
      }
    }

    results.push({ id: fixture.id, ok: failures.length === 0, failures, hermesChecked });
  }

  return {
    ok: results.every((result) => result.ok),
    hermesUsed: hermesUsable,
    hermesBin: hermesUsable ? hermesBin : '',
    results,
  };
}

function main() {
  const report = runCorpus();
  const passed = report.results.filter((r) => r.ok).length;
  console.log(
    `hermes-compat corpus: ${passed}/${report.results.length} fixtures ok ` +
      `(${report.hermesUsed ? `Hermes: ${report.hermesBin}` : 'Hermes unavailable — V8 oracle only'})`,
  );
  for (const result of report.results) {
    const tag = result.ok ? 'ok  ' : 'FAIL';
    const hermes = result.hermesChecked ? ' [hermes]' : '';
    console.log(`  ${tag} ${result.id}${hermes}`);
    for (const failure of result.failures) {
      console.log(`       - ${failure}`);
    }
  }
  process.exit(report.ok ? 0 : 1);
}

if (import.meta.main || process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
