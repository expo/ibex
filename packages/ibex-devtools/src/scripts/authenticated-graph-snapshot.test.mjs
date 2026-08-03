import { describe, expect, test } from 'bun:test';
import fs from 'node:fs';

import {
  computeAuthenticatedGraphIdentityV1,
  decodeCanonicalSourceId,
  encodeCanonicalSourceId,
  validateAuthenticatedGraphSnapshotV1,
} from './authenticated-graph-snapshot.mjs';

const golden = JSON.parse(fs.readFileSync(new URL(
  '../../../../tests/fixtures/authenticated-graph-snapshot-v1.golden.json',
  import.meta.url,
), 'utf8'));

describe('authenticated graph snapshot v1', () => {
  test('matches the cross-language golden identity', () => {
    expect(computeAuthenticatedGraphIdentityV1(golden.snapshot))
      .toBe(golden.expectedIdentity);
    expect(validateAuthenticatedGraphSnapshotV1(golden.snapshot))
      .toBe(golden.snapshot);
  });

  test('round-trips builtin and synthetic SourceId variants canonically', () => {
    for (const source of [
      { kind: 'builtin', domain: 'ibex-runtime', sourceKey: 'exact:fs' },
      {
        kind: 'synthetic',
        sessionIdentity: 'fixture-session',
        sourceIdentity: 'ibex:stdin',
      },
    ]) {
      expect(decodeCanonicalSourceId(encodeCanonicalSourceId(source))).toEqual(source);
    }
  });

  test('refuses package, edge, and candidate inventory drift', () => {
    const missingPackage = structuredClone(golden.snapshot);
    missingPackage.packages = [];
    expect(() => validateAuthenticatedGraphSnapshotV1(missingPackage)).toThrow();

    const alienEdge = structuredClone(golden.snapshot);
    alienEdge.edges[0].target = encodeCanonicalSourceId({
      kind: 'synthetic',
      sessionIdentity: 'session',
      sourceIdentity: 'ibex:stdin',
    });
    expect(() => validateAuthenticatedGraphSnapshotV1(alienEdge)).toThrow();

    const unorderedCandidates = structuredClone(golden.snapshot);
    unorderedCandidates.candidateSets[0].candidates.reverse();
    expect(() => validateAuthenticatedGraphSnapshotV1(unorderedCandidates)).toThrow();
  });
});
