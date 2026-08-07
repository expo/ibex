/**
 * Canonical `ibex/authenticated-graph-snapshot/1` authoring and validation.
 *
 * @ref LLP 0029#1-command-surface-and-producer-pipeline — policy, carriers,
 * and the executable envelope bind this one path-independent graph projection.
 */

import { canonicalJson, computeDomainDigest } from './capsec-contract.mjs';

export const AUTHENTICATED_GRAPH_SNAPSHOT_SCHEMA_V1 =
  'ibex/authenticated-graph-snapshot/1';
export const AUTHENTICATED_GRAPH_SNAPSHOT_DOMAIN_V1 =
  'ibex/authenticated-graph-snapshot/1';
const SOURCE_ID_PREFIX_V1 = 'ibex-source-id-v1:';
const DIGEST = /^sha256-[A-Za-z0-9_-]{43}$/u;

function assertExactKeys(value, required, optional, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new TypeError(`${label} has unknown field ${key}`);
  }
  for (const key of required) {
    if (!(key in value)) throw new TypeError(`${label} omits ${key}`);
  }
}

function assertNonEmpty(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
}

function assertDigest(value, label) {
  if (!DIGEST.test(value) || Buffer.from(value.slice(7), 'base64url').length !== 32) {
    throw new TypeError(`${label} is not a canonical SHA-256 digest`);
  }
}

function assertSortedUnique(values, key, label) {
  for (let index = 1; index < values.length; index += 1) {
    if (key(values[index - 1]) >= key(values[index])) {
      throw new TypeError(`${label} must be strictly ordered and unique`);
    }
  }
}

function validatePrincipal(principal, label, packageOnly = false) {
  assertExactKeys(
    principal,
    principal?.kind === 'package'
      ? ['kind', 'name', 'locator', 'integrity']
      : ['kind', 'identity'],
    [],
    label,
  );
  if (principal.kind === 'package') {
    assertNonEmpty(principal.name, `${label}.name`);
    assertNonEmpty(principal.locator, `${label}.locator`);
    assertDigest(principal.integrity, `${label}.integrity`);
  } else if (principal.kind !== 'root' || packageOnly) {
    throw new TypeError(`${label} is not an admitted principal kind`);
  } else {
    assertNonEmpty(principal.identity, `${label}.identity`);
  }
}

function validateSourceIdValue(source, label = 'SourceId') {
  if (source?.kind === 'file') {
    assertExactKeys(source, ['kind', 'principal', 'path'], [], label);
    validatePrincipal(source.principal, `${label}.principal`);
    if (!Array.isArray(source.path) || source.path.length === 0) {
      throw new TypeError(`${label}.path must be non-empty`);
    }
    source.path.forEach((component, index) => {
      assertExactKeys(component, ['encoding', 'value'], [], `${label}.path[${index}]`);
      if (!['utf8', 'base64url'].includes(component.encoding)) {
        throw new TypeError(`${label}.path[${index}] has an invalid encoding`);
      }
      assertNonEmpty(component.value, `${label}.path[${index}].value`);
    });
  } else if (source?.kind === 'builtin') {
    assertExactKeys(source, ['kind', 'domain', 'sourceKey'], [], label);
    assertNonEmpty(source.domain, `${label}.domain`);
    assertNonEmpty(source.sourceKey, `${label}.sourceKey`);
  } else if (source?.kind === 'synthetic') {
    assertExactKeys(
      source,
      ['kind', 'sessionIdentity', 'sourceIdentity'],
      [],
      label,
    );
    assertNonEmpty(source.sessionIdentity, `${label}.sessionIdentity`);
    assertNonEmpty(source.sourceIdentity, `${label}.sourceIdentity`);
  } else {
    throw new TypeError(`${label} has an unsupported kind`);
  }
  return source;
}

export function encodeCanonicalSourceId(source) {
  validateSourceIdValue(source);
  return `${SOURCE_ID_PREFIX_V1}${Buffer.from(canonicalJson(source), 'utf8').toString('base64url')}`;
}

export function decodeCanonicalSourceId(encoded) {
  if (typeof encoded !== 'string' || !encoded.startsWith(SOURCE_ID_PREFIX_V1)) {
    throw new TypeError('unsupported SourceId wire version');
  }
  const payload = encoded.slice(SOURCE_ID_PREFIX_V1.length);
  if (!/^[A-Za-z0-9_-]+$/u.test(payload)) {
    throw new TypeError('SourceId payload is not canonical base64url');
  }
  const bytes = Buffer.from(payload, 'base64url');
  if (bytes.toString('base64url') !== payload) {
    throw new TypeError('SourceId payload is not canonical base64url');
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const source = JSON.parse(text);
  if (canonicalJson(source) !== text) throw new TypeError('SourceId payload is not JCS');
  return validateSourceIdValue(source);
}

export function validateAuthenticatedGraphSnapshotV1(snapshot) {
  assertExactKeys(
    snapshot,
    ['schema', 'entry', 'nodes', 'packages', 'edges', 'candidateSets'],
    [],
    'snapshot',
  );
  if (snapshot.schema !== AUTHENTICATED_GRAPH_SNAPSHOT_SCHEMA_V1) {
    throw new TypeError('unsupported authenticated graph snapshot schema');
  }
  assertExactKeys(snapshot.entry, ['name', 'sourceId'], [], 'snapshot.entry');
  if (snapshot.entry.name !== 'main') throw new TypeError('v1 entry must be main');
  decodeCanonicalSourceId(snapshot.entry.sourceId);
  if (!Array.isArray(snapshot.nodes) || snapshot.nodes.length === 0) {
    throw new TypeError('snapshot.nodes must be a non-empty array');
  }
  assertSortedUnique(snapshot.nodes, (node) => node.sourceId, 'snapshot.nodes');
  const sources = new Set();
  const packagePrincipals = new Map();
  snapshot.nodes.forEach((node, index) => {
    assertExactKeys(
      node,
      ['sourceId', 'sourceIntegrity'],
      [],
      `snapshot.nodes[${index}]`,
    );
    const source = decodeCanonicalSourceId(node.sourceId);
    assertDigest(node.sourceIntegrity, `snapshot.nodes[${index}].sourceIntegrity`);
    sources.add(node.sourceId);
    if (source.kind === 'file' && source.principal.kind === 'package') {
      packagePrincipals.set(canonicalJson(source.principal), source.principal);
    }
  });
  if (!sources.has(snapshot.entry.sourceId)) {
    throw new TypeError('snapshot entry is absent from nodes');
  }

  if (!Array.isArray(snapshot.packages)) throw new TypeError('snapshot.packages must be an array');
  snapshot.packages.forEach((principal, index) =>
    validatePrincipal(principal, `snapshot.packages[${index}]`, true));
  assertSortedUnique(snapshot.packages, canonicalJson, 'snapshot.packages');
  const expectedPackages = [...packagePrincipals.values()].sort((a, b) =>
    Buffer.from(canonicalJson(a)).compare(Buffer.from(canonicalJson(b))));
  if (canonicalJson(snapshot.packages) !== canonicalJson(expectedPackages)) {
    throw new TypeError('snapshot package inventory does not equal node package principals');
  }

  if (!Array.isArray(snapshot.edges)) throw new TypeError('snapshot.edges must be an array');
  assertSortedUnique(snapshot.edges, canonicalJson, 'snapshot.edges');
  snapshot.edges.forEach((edge, index) => {
    assertExactKeys(
      edge,
      ['requester', 'specifier', 'resolutionKind', 'conditions', 'attributes', 'target'],
      [],
      `snapshot.edges[${index}]`,
    );
    if (!sources.has(edge.requester) || !sources.has(edge.target)) {
      throw new TypeError(`snapshot.edges[${index}] endpoint is absent from nodes`);
    }
    assertNonEmpty(edge.specifier, `snapshot.edges[${index}].specifier`);
    if (!['esm-static', 'dynamic-import', 'common-js-require'].includes(edge.resolutionKind)) {
      throw new TypeError(`snapshot.edges[${index}] has an invalid resolution kind`);
    }
    if (!Array.isArray(edge.conditions) || edge.conditions.length === 0) {
      throw new TypeError(`snapshot.edges[${index}].conditions must be non-empty`);
    }
    edge.conditions.forEach((condition, conditionIndex) =>
      assertNonEmpty(condition, `snapshot.edges[${index}].conditions[${conditionIndex}]`));
    assertSortedUnique(edge.conditions, String, `snapshot.edges[${index}].conditions`);
    if (edge.conditions.includes('default')) {
      throw new TypeError(`snapshot.edges[${index}] conditions contain default`);
    }
    const required = edge.resolutionKind === 'common-js-require'
      ? ['node', 'require']
      : ['import', 'node'];
    if (required.some((condition) => !edge.conditions.includes(condition))) {
      throw new TypeError(`snapshot.edges[${index}] omits required conditions`);
    }
    assertExactKeys(edge.attributes, [], ['type'], `snapshot.edges[${index}].attributes`);
    if ('type' in edge.attributes && edge.attributes.type !== 'json') {
      throw new TypeError(`snapshot.edges[${index}] has unsupported attributes`);
    }
  });

  if (!Array.isArray(snapshot.candidateSets)) {
    throw new TypeError('snapshot.candidateSets must be an array');
  }
  assertSortedUnique(snapshot.candidateSets, canonicalJson, 'snapshot.candidateSets');
  const candidateIds = new Set();
  snapshot.candidateSets.forEach((row, index) => {
    assertExactKeys(
      row,
      ['id', 'requester', 'label', 'candidates'],
      [],
      `snapshot.candidateSets[${index}]`,
    );
    assertNonEmpty(row.id, `snapshot.candidateSets[${index}].id`);
    if (candidateIds.has(row.id)) throw new TypeError(`duplicate candidate-set id ${row.id}`);
    candidateIds.add(row.id);
    if (!sources.has(row.requester)) {
      throw new TypeError(`snapshot.candidateSets[${index}] requester is absent from nodes`);
    }
    assertNonEmpty(row.label, `snapshot.candidateSets[${index}].label`);
    if (!Array.isArray(row.candidates)) {
      throw new TypeError(`snapshot.candidateSets[${index}].candidates must be an array`);
    }
    row.candidates.forEach((candidate, candidateIndex) =>
      assertNonEmpty(candidate, `snapshot.candidateSets[${index}].candidates[${candidateIndex}]`));
    assertSortedUnique(row.candidates, String, `snapshot.candidateSets[${index}].candidates`);
  });
  return snapshot;
}

export function computeAuthenticatedGraphIdentityV1(snapshot) {
  validateAuthenticatedGraphSnapshotV1(snapshot);
  return computeDomainDigest(AUTHENTICATED_GRAPH_SNAPSHOT_DOMAIN_V1, snapshot, []);
}
