import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { parseModuleOrScript } from './parse-js.mjs';

export const legacyRequiredTelemetryEventSchema =
  'ibex/legacy-required-telemetry-event/1';
export const legacyRequiredTelemetryReportSchema =
  'ibex/legacy-required-telemetry-report/1';

function digest(domain, value) {
  return `sha256-${createHash('sha256')
    .update(`${domain}\0`, 'utf8')
    .update(JSON.stringify(value), 'utf8')
    .digest('base64url')}`;
}

function isStringLiteral(node) {
  return node && typeof node === 'object' && (
    (node.type === 'Literal' && typeof node.value === 'string')
    || node.type === 'StringLiteral'
  );
}

function staticLegacySiteCounts(source, fileName) {
  const program = parseModuleOrScript(source, { fileName });
  assert.ok(program, 'telemetry denominator source must parse through the pinned Oxc frontend');
  let computedDynamicImport = 0;
  let computedCommonJsRequire = 0;
  const seen = new WeakSet();
  const visit = (node) => {
    if (!node || typeof node !== 'object' || seen.has(node)) return;
    seen.add(node);
    if (node.type === 'ImportExpression' && !isStringLiteral(node.source)) {
      computedDynamicImport += 1;
    }
    if (
      node.type === 'CallExpression'
      && node.callee?.type === 'Identifier'
      && node.callee.name === 'require'
      && !(node.arguments?.length === 1 && isStringLiteral(node.arguments[0]))
    ) {
      computedCommonJsRequire += 1;
    }
    for (const value of Object.values(node)) {
      if (value && typeof value === 'object') {
        if (Array.isArray(value)) {
          for (const child of value) visit(child);
        } else {
          visit(value);
        }
      }
    }
  };
  visit(program);
  return { computedDynamicImport, computedCommonJsRequire };
}

function sortedCounts(values) {
  return Object.fromEntries(
    [...values.entries()].sort(([left], [right]) => left.localeCompare(right)),
  );
}

export function buildLegacyRequiredTelemetryReport({
  populationId,
  boundary,
  modules,
  events,
  executions,
}) {
  assert.match(populationId, /^[a-z0-9][a-z0-9-]*$/u);
  assert.ok(typeof boundary === 'string' && boundary.length >= 20);
  assert.ok(Number.isInteger(executions) && executions > 0);
  const uniqueModules = [...modules]
    .map(({ sourceId, source, fileName = 'module.js' }) => {
      assert.ok(typeof sourceId === 'string' && sourceId.length > 0);
      assert.ok(typeof source === 'string');
      return {
        sourceId,
        fileName,
        sourceDigest: digest('ibex:legacy-required-population-source:1', source),
        source,
      };
    })
    .sort((left, right) => left.sourceId.localeCompare(right.sourceId));
  assert.equal(
    new Set(uniqueModules.map(({ sourceId }) => sourceId)).size,
    uniqueModules.length,
    'telemetry population SourceIds must be unique',
  );

  let computedDynamicImportOccurrences = 0;
  let computedCommonJsRequireOccurrences = 0;
  for (const module of uniqueModules) {
    const counts = staticLegacySiteCounts(module.source, module.fileName);
    computedDynamicImportOccurrences += counts.computedDynamicImport;
    computedCommonJsRequireOccurrences += counts.computedCommonJsRequire;
  }

  const normalizedEvents = events.map((event) => {
    assert.equal(event.schema, legacyRequiredTelemetryEventSchema);
    assert.match(event.code, /^IBEX_LEGACY_[A-Z0-9_]+$/u);
    assert.match(event.moduleSourceId, /^ibex-source-id-v1:/u);
    assert.ok(typeof event.runtimeVersion === 'string' && event.runtimeVersion.length > 0);
    if (event.originalSourceSite) {
      assert.ok(event.originalSourceSite.line > 0 && event.originalSourceSite.column > 0);
      assert.ok(event.originalSourceSite.byteOffset >= 0);
    }
    return event;
  }).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  const byCategory = new Map();
  const byShape = new Map();
  for (const event of normalizedEvents) {
    byCategory.set(event.category, (byCategory.get(event.category) ?? 0) + 1);
    if (event.shape) byShape.set(event.shape, (byShape.get(event.shape) ?? 0) + 1);
  }

  const treeProjection = uniqueModules.map(({ sourceId, fileName, sourceDigest }) => ({
    sourceId,
    fileName,
    sourceDigest,
  }));
  return {
    schema: legacyRequiredTelemetryReportSchema,
    population: {
      id: populationId,
      boundary,
      controlledTestPopulation: true,
      advisoryOnly: true,
      moduleCount: uniqueModules.length,
      executions,
      authenticatedTreeDigest: digest('ibex:legacy-required-population-tree:1', treeProjection),
    },
    events: {
      count: normalizedEvents.length,
      byCategory: sortedCounts(byCategory),
      byShape: sortedCounts(byShape),
      digest: digest('ibex:legacy-required-events:1', normalizedEvents),
    },
    staticScan: {
      scanner: 'pinned-rolldown-oxc-estree-syntactic-upper-bound-v1',
      computedDynamicImportOccurrences,
      computedCommonJsRequireOccurrences,
      denominatorModules: uniqueModules.length,
      note: 'Counts are an advisory syntactic upper bound; shadowed CommonJS require identifiers remain in the denominator.',
    },
  };
}
