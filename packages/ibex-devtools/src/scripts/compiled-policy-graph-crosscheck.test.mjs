import { describe, expect, test } from 'bun:test';
import {
  encodeCanonicalSourceId,
} from './authenticated-graph-snapshot.mjs';
import {
  assertCompiledPolicyAnalysisMatchesNativeGraph,
} from './compiled-policy-graph-crosscheck.mjs';

const rootPrincipal = { kind: 'root', identity: 'project-root' };
const sourceId = (path) => encodeCanonicalSourceId({
  kind: 'file',
  principal: rootPrincipal,
  path: path.split('/').map((value) => ({ encoding: 'utf8', value })),
});

const fixture = () => {
  const entrySourceId = sourceId('entry.mjs');
  const dependencySourceId = sourceId('dependency.mjs');
  const candidate = {
    requester: entrySourceId,
    label: 'routes',
    candidates: ['./dependency.mjs'],
  };
  const snapshot = {
    nodes: [
      { sourceId: entrySourceId, sourceIntegrity: 'sha256-entry' },
      { sourceId: dependencySourceId, sourceIntegrity: 'sha256-dependency' },
    ],
    packages: [{ name: 'dependency', locator: 'dependency@1.0.0' }],
    entry: { sourceId: entrySourceId },
    candidateSets: [candidate],
  };
  const expected = {
    snapshot,
    expectedFileNodes: new Map(snapshot.nodes.map((node) => [
      node.sourceId,
      node.sourceIntegrity,
    ])),
    expectedPackages: structuredClone(snapshot.packages),
    expectedEntrySourceId: entrySourceId,
    expectedEntryIntegrity: 'sha256-entry',
    expectedCandidateSets: [structuredClone(candidate)],
  };
  return expected;
};

describe('compiled policy/native graph divergence boundary', () => {
  test('accepts the exact analyzed/native projection', () => {
    expect(() => assertCompiledPolicyAnalysisMatchesNativeGraph(fixture())).not.toThrow();
  });

  test.each([
    ['file inventory', (value) => {
      value.snapshot.nodes[1].sourceIntegrity = 'sha256-mutated';
    }, /file identities differ/u],
    ['package inventory', (value) => {
      value.snapshot.packages[0].locator = 'dependency@2.0.0';
    }, /package inventory differs/u],
    ['entry identity', (value) => {
      value.snapshot.entry.sourceId = value.snapshot.nodes[1].sourceId;
    }, /entry differs/u],
    ['candidate materialization', (value) => {
      value.snapshot.candidateSets[0].candidates.push('./other.mjs');
    }, /candidate tables differ/u],
  ])('refuses divergent %s', (_label, mutate, expectedError) => {
    const value = fixture();
    mutate(value);
    expect(() => assertCompiledPolicyAnalysisMatchesNativeGraph(value)).toThrow(expectedError);
  });
});
