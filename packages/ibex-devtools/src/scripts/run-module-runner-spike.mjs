#!/usr/bin/env node
/**
 * Execute every checked-in LLP 0026 producer-spike artifact on real Hermes.
 * Shape-only or V8-only success is intentionally impossible.
 *
 * @ref LLP 0026#adoption-gate — the enumerated factory list must execute on
 * real Hermes before adoption; unavailable Hermes is a hard failure.
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { SourceMap } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../../../..');
const marker = 'MODULE_RUNNER_SPIKE|';

function parseArgs(argv) {
  const options = {
    artifacts: path.join(repoRoot, 'tests/fixtures/module-runner-spike/canonical-artifacts.json'),
    hermes: process.env.IBEX_HERMES_BIN || '',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--artifacts') options.artifacts = argv[++index] || '';
    else if (arg === '--hermes') options.hermes = argv[++index] || '';
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (!options.hermes) throw new Error('--hermes /path/to/real/hermes is required');
  return options;
}

export function runtimeSource(fixture) {
  return `
"use strict";
var __fixture = ${JSON.stringify(fixture)};
var __records = Object.create(null);
var __entryName = __fixture.entry;

function __resolve(from, specifier) {
  var parts = (from.slice(0, from.lastIndexOf("/") + 1) + specifier).split("/");
  var normalized = [];
  for (var i = 0; i < parts.length; i += 1) {
    if (!parts[i] || parts[i] === ".") continue;
    if (parts[i] === "..") normalized.pop();
    else normalized.push(parts[i]);
  }
  return normalized.join("/");
}

function __target(record, specifier) {
  var name = __resolve(record.artifact.sourceName, specifier);
  var target = __records[name];
  if (!target) throw new Error("missing spike dependency " + name);
  return target;
}

function __explicitDescriptor(record, name) {
  for (var i = 0; i < record.artifact.exportDescriptors.length; i += 1) {
    var descriptor = record.artifact.exportDescriptors[i];
    if (descriptor.kind !== "star" && descriptor.exported === name) return descriptor;
  }
  return null;
}

function __resolveCell(record, name, seen) {
  var key = record.artifact.sourceName + "::" + name;
  if (seen[key]) return null;
  var nextSeen = Object.create(seen);
  nextSeen[key] = true;
  var explicit = __explicitDescriptor(record, name);
  if (explicit) {
    if (explicit.kind === "local") return record.cells[name];
    if (explicit.kind === "indirect") {
      return __resolveCell(__target(record, explicit.specifier), explicit.imported, nextSeen);
    }
    if (explicit.kind === "namespace") {
      if (!record.cells[name].initialized) {
        record.cells[name].value = __namespace(__target(record, explicit.specifier));
        record.cells[name].initialized = true;
      }
      return record.cells[name];
    }
  }
  if (name === "default") return null;
  var found = null;
  for (var i = 0; i < record.artifact.exportDescriptors.length; i += 1) {
    var descriptor = record.artifact.exportDescriptors[i];
    if (descriptor.kind !== "star") continue;
    var candidate = __resolveCell(__target(record, descriptor.specifier), name, nextSeen);
    if (!candidate) continue;
    if (found && found !== candidate) return null;
    found = candidate;
  }
  return found;
}

function __exportNames(record, seen) {
  if (seen[record.artifact.sourceName]) return [];
  var nextSeen = Object.create(seen);
  nextSeen[record.artifact.sourceName] = true;
  var candidates = Object.create(null);
  for (var i = 0; i < record.artifact.exportDescriptors.length; i += 1) {
    var descriptor = record.artifact.exportDescriptors[i];
    if (descriptor.kind === "star") {
      var starNames = __exportNames(__target(record, descriptor.specifier), nextSeen);
      for (var j = 0; j < starNames.length; j += 1) {
        if (starNames[j] !== "default") candidates[starNames[j]] = true;
      }
    } else if (descriptor.exported) {
      candidates[descriptor.exported] = true;
    }
  }
  return Object.keys(candidates).filter(function (name) {
    return __resolveCell(record, name, Object.create(null)) !== null;
  }).sort();
}

function __namespace(record) {
  if (record.namespace) return record.namespace;
  var namespace = Object.create(null);
  var names = __exportNames(record, Object.create(null));
  for (var i = 0; i < names.length; i += 1) {
    (function (name) {
      Object.defineProperty(namespace, name, {
        enumerable: true,
        configurable: false,
        get: function () { return __read(record, name); },
      });
    })(names[i]);
  }
  Object.preventExtensions(namespace);
  record.namespace = namespace;
  return namespace;
}

function __read(record, name) {
  if (name === "*") return __namespace(record);
  var cell = __resolveCell(record, name, Object.create(null));
  if (!cell) throw new SyntaxError("ambiguous or absent export " + name);
  if (!cell.initialized) {
    throw new ReferenceError("uninitialized export " + name + " from " + record.artifact.sourceName);
  }
  return cell.value;
}

function __evaluate(record) {
  if (record.state === "evaluated") return record.promise;
  if (record.state === "evaluating") return record.promise;
  if (record.state === "errored") throw record.error;
  record.state = "evaluating";
  var dependencies = [];
  var seen = Object.create(null);
  for (var i = 0; i < record.artifact.staticEdges.length; i += 1) {
    var specifier = record.artifact.staticEdges[i].specifier;
    if (!seen[specifier]) {
      seen[specifier] = true;
      dependencies.push(__target(record, specifier));
    }
  }
  var chain = null;
  for (var j = 0; j < dependencies.length; j += 1) {
    var pending = __evaluate(dependencies[j]);
    if (pending && typeof pending.then === "function") {
      chain = chain ? chain.then((function (value) { return function () { return value; }; })(pending)) : pending;
    }
  }
  function execute() {
    try {
      var result = record.definition.execute.call(void 0);
      if (result && typeof result.then === "function") {
        return result.then(function () {
          record.state = "evaluated";
          return void 0;
        }, function (error) {
          record.state = "errored";
          record.error = error;
          throw error;
        });
      }
      record.state = "evaluated";
      return null;
    } catch (error) {
      record.state = "errored";
      record.error = error;
      throw error;
    }
  }
  if (chain) {
    record.promise = chain.then(execute);
    return record.promise;
  }
  var result = execute();
  if (result && typeof result.then === "function") record.promise = result;
  return record.promise;
}

for (var i = 0; i < __fixture.modules.length; i += 1) {
  var artifact = __fixture.modules[i];
  var cells = Object.create(null);
  for (var j = 0; j < artifact.exportDescriptors.length; j += 1) {
    var descriptor = artifact.exportDescriptors[j];
    if ((descriptor.kind === "local" || descriptor.kind === "namespace") && descriptor.exported) {
      cells[descriptor.exported] = { initialized: false, value: void 0 };
    }
  }
  __records[artifact.sourceName] = {
    artifact: artifact,
    cells: cells,
    state: "linked",
    promise: null,
    error: null,
    namespace: null,
    definition: null,
  };
}

Object.keys(__records).forEach(function (name) {
  var record = __records[name];
  var factory = (0, eval)("(" + record.artifact.factorySource + ")");
  var context = {
    meta: { url: "fixture:///" + name, main: name === __entryName },
    importValue: function (specifier, imported) {
      return __read(__target(record, specifier), imported);
    },
    dynamicImport: function () {
      // @ref LLP 0026#6-top-level-await-and-dynamic-import — execute both the current source-site ABI and pre-site spike artifacts during producer rotation.
      var siteBearing = arguments.length >= 5 &&
        typeof arguments[0] === "number" &&
        typeof arguments[1] === "number" &&
        typeof arguments[2] === "number" &&
        typeof arguments[3] === "number";
      var legacyComputed = !siteBearing && arguments.length >= 2 &&
        typeof arguments[0] === "number";
      var specifierIndex = siteBearing ? 4 : (legacyComputed ? 1 : 0);
      var specifier = arguments[specifierIndex];
      var target = __target(record, specifier);
      try {
        return Promise.resolve(__evaluate(target)).then(function () { return __namespace(target); });
      } catch (error) {
        return Promise.reject(error);
      }
    },
  };
  record.definition = factory(function (exported, value) {
    var cell = record.cells[exported];
    if (!cell) throw new Error("factory published undeclared export " + exported);
    cell.value = value;
    cell.initialized = true;
    return value;
  }, context);
});

Object.keys(__records).forEach(function (name) {
  var definition = __records[name].definition;
  if (!definition || typeof definition.declare !== "function" || typeof definition.execute !== "function") {
    throw new Error("factory did not provide declare/execute: " + name);
  }
  definition.declare.call(void 0);
});

function __complete(ok, error) {
  if (ok) {
    print(${JSON.stringify(marker)} + JSON.stringify({ ok: true }));
  } else {
    print(${JSON.stringify(marker)} + JSON.stringify({
      ok: false,
      errorName: error && error.name ? String(error.name) : "Error",
      message: error && error.message ? String(error.message) : String(error),
    }));
  }
}

try {
  var __result = __evaluate(__records[__entryName]);
  if (__result && typeof __result.then === "function") {
    __result.then(function () { __complete(true); }, function (error) { __complete(false, error); });
  } else {
    __complete(true);
  }
} catch (error) {
  __complete(false, error);
}
`;
}

function validateSourceMap(fixture) {
  const expectedLine = fixture.expected.sourceLine;
  if (expectedLine === undefined) return;
  const artifact = fixture.modules.find((module) => module.sourceName === fixture.entry);
  const generatedLine = artifact.factorySource.split('\n').findIndex((line) => line.includes('throw new Error'));
  if (generatedLine < 0) throw new Error(`${fixture.id}: generated throw site missing`);
  const entry = new SourceMap(artifact.sourceMap).findEntry(generatedLine, 0);
  if (entry.originalLine + 1 !== expectedLine) {
    throw new Error(
      `${fixture.id}: composed map resolved generated line ${generatedLine + 1} to source line ${entry.originalLine + 1}, expected ${expectedLine}`,
    );
  }
}

function runFixture(hermes, fixture) {
  validateSourceMap(fixture);
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ibex-module-runner-spike-'));
  const script = path.join(directory, `${fixture.id}.js`);
  try {
    writeFileSync(script, runtimeSource(fixture));
    const result = spawnSync(hermes, [script], { encoding: 'utf8', timeout: 30_000 });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error(`Hermes exited ${result.status}: ${result.stderr}`);
    }
    const lines = result.stdout.trimEnd().split(/\r?\n/u);
    const markerIndex = lines.findIndex((line) => line.startsWith(marker));
    if (markerIndex < 0) throw new Error(`real Hermes emitted no completion marker:\n${result.stdout}`);
    const outcome = JSON.parse(lines[markerIndex].slice(marker.length));
    const stdout = lines.slice(0, markerIndex);
    if (fixture.expected.stdout) {
      if (!outcome.ok) throw new Error(`${outcome.errorName}: ${outcome.message}`);
      if (JSON.stringify(stdout) !== JSON.stringify(fixture.expected.stdout)) {
        throw new Error(`stdout ${JSON.stringify(stdout)} != ${JSON.stringify(fixture.expected.stdout)}`);
      }
    } else {
      if (outcome.ok) throw new Error('expected fixture to fail');
      if (outcome.errorName !== fixture.expected.errorName) {
        throw new Error(`error ${outcome.errorName} != ${fixture.expected.errorName}`);
      }
      if (!outcome.message.includes(fixture.expected.messageIncludes)) {
        throw new Error(`message ${JSON.stringify(outcome.message)} lacks ${JSON.stringify(fixture.expected.messageIncludes)}`);
      }
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const bundle = JSON.parse(readFileSync(options.artifacts, 'utf8'));
  if (bundle.schema !== 'ibex/module-runner-spike-artifacts/1') {
    throw new Error(`unexpected artifact schema: ${bundle.schema}`);
  }
  let passed = 0;
  const failures = [];
  for (const fixture of bundle.fixtures) {
    try {
      runFixture(options.hermes, fixture);
      passed += 1;
      console.log(`  ok   ${fixture.id} [real Hermes]`);
    } catch (error) {
      failures.push(`${fixture.id}: ${error.message}`);
      console.log(`  FAIL ${fixture.id}: ${error.message}`);
    }
  }
  console.log(`module-runner spike: ${passed}/${bundle.fixtures.length} canonical artifacts ok (real Hermes: ${options.hermes})`);
  if (bundle.fixtures.length === 0 || failures.length) {
    for (const failure of failures) console.error(`- ${failure}`);
    process.exit(1);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
