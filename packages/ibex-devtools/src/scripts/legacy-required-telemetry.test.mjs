import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildLegacyRequiredTelemetryReport,
  legacyRequiredTelemetryReportSchema,
} from './legacy-required-telemetry.mjs';

const event = Object.freeze({
  schema: 'ibex/legacy-required-telemetry-event/1',
  category: 'computed-dynamic-import',
  code: 'IBEX_LEGACY_COMPUTED_DYNAMIC_IMPORT',
  moduleSourceId: 'ibex-source-id-v1:test',
  originalSourceSite: { byteOffset: 15, line: 1, column: 16 },
  runtimeVersion: '0.1.0',
});

test('legacy-required report binds its population, events, and static denominator', () => {
  const input = {
    populationId: 'ibex-fixtures',
    boundary: 'Only the checked Ibex fixture population; no released-user field usage.',
    modules: [
      { sourceId: 'fixture:computed-import', source: 'const x = import(name);' },
      { sourceId: 'fixture:computed-require', source: 'const x = require(name);' },
    ],
    events: [event],
    executions: 2,
  };
  const first = buildLegacyRequiredTelemetryReport(input);
  const second = buildLegacyRequiredTelemetryReport({
    ...input,
    modules: [...input.modules].reverse(),
  });
  assert.deepEqual(first, second);
  assert.equal(first.schema, legacyRequiredTelemetryReportSchema);
  assert.equal(first.population.controlledTestPopulation, true);
  assert.equal(first.population.advisoryOnly, true);
  assert.equal(first.events.byCategory['computed-dynamic-import'], 1);
  assert.equal(first.staticScan.computedDynamicImportOccurrences, 1);
  assert.equal(first.staticScan.computedCommonJsRequireOccurrences, 1);
  assert.match(first.population.authenticatedTreeDigest, /^sha256-[A-Za-z0-9_-]{43}$/u);
  assert.match(first.events.digest, /^sha256-[A-Za-z0-9_-]{43}$/u);
});

test('legacy-required report rejects malformed event and duplicate population identities', () => {
  assert.throws(() => buildLegacyRequiredTelemetryReport({
    populationId: 'ibex-fixtures',
    boundary: 'Only a controlled and named fixture population.',
    modules: [
      { sourceId: 'fixture:same', source: 'import(name)' },
      { sourceId: 'fixture:same', source: 'require(name)' },
    ],
    events: [event],
    executions: 1,
  }), /SourceIds must be unique/u);
  assert.throws(() => buildLegacyRequiredTelemetryReport({
    populationId: 'ibex-fixtures',
    boundary: 'Only a controlled and named fixture population.',
    modules: [{ sourceId: 'fixture:one', source: 'import(name)' }],
    events: [{ ...event, schema: 'wrong' }],
    executions: 1,
  }));
});
