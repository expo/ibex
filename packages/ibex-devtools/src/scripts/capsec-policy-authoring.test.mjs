import { expect, test } from 'bun:test';
import {
  buildCanonicalPolicy,
  canonicalPolicySourcePath,
  classifyPolicyDrift,
  compareCanonicalBytes,
  intersectAuthorities,
  packageIntegrity,
  resolveTypedDelegations,
  withV1CwdObserveFloor,
} from './capsec-policy-authoring.mjs';

test('policy provenance paths are portable across host separators', () => {
  expect(
    canonicalPolicySourcePath('examples\\llp0013-supply-chain\\app.mjs'),
  ).toBe('examples/llp0013-supply-chain/app.mjs');
});

const authority = {
  cap: 'fs:read',
  resource: {
    kind: 'path-tree',
    path: { root: 'project', components: [{ encoding: 'utf8', value: 'images' }] },
  },
};

function principal(floor = []) {
  return {
    principal: {
      kind: 'package',
      name: 'image-lib',
      integrity: packageIntegrity('{"name":"image-lib","version":"1.0.0"}'),
      locator: 'image-lib@1.0.0',
    },
    floor,
    imports: { builtins: ['node:fs'], packages: [] },
    endowments: [],
  };
}

test('buildCanonicalPolicy emits deterministic typed rows and a self-digest', () => {
  const row = {
    authority,
    provenance: [{ kind: 'import-site', source: 'src/app.mjs:1' }],
  };
  const first = buildCanonicalPolicy([principal([row, row])]);
  const second = buildCanonicalPolicy([principal([row])]);
  expect(first).toEqual(second);
  expect(first.mode).toBe('enforce');
  expect(first.rootImports).toEqual([]);
  expect(first.principals[0].floor).toHaveLength(1);
  expect(first.policyDigest).toMatch(/^sha256-/);
}, 30_000);

test('root import provenance is explicit, canonical, and drift-classified', () => {
  const policy = buildCanonicalPolicy(
    [principal()],
    ['image-lib@1.0.0', 'image-lib@1.0.0'],
  );
  expect(policy.rootImports).toEqual(['image-lib@1.0.0']);
  const closed = buildCanonicalPolicy([principal()]);
  expect(classifyPolicyDrift(closed, policy).expansions)
    .toContain('rootImports image-lib@1.0.0');
  expect(classifyPolicyDrift(policy, closed).narrowings)
    .toContain('rootImports image-lib@1.0.0');
});

test('the v1 generator floor grants cwd observation to every admitted package', () => {
  const existing = {
    authority,
    provenance: [{ kind: 'import-site', source: 'src/app.mjs:1' }],
  };
  expect(withV1CwdObserveFloor([])).toEqual([
    {
      authority: {
        cap: 'path:cwd-observe',
        resource: { kind: 'session-state', name: 'cwd' },
      },
      provenance: [
        {
          kind: 'macro-expansion',
          source: 'profile:path.cwd.v1:universal-observe',
        },
      ],
    },
  ]);
  expect(withV1CwdObserveFloor([existing])).toEqual([
    existing,
    expect.objectContaining({
      authority: expect.objectContaining({ cap: 'path:cwd-observe' }),
    }),
  ]);
});

test('package policy cannot author the core-root-only cwd mutation action', () => {
  expect(() =>
    buildCanonicalPolicy([
      principal([
        {
          authority: {
            cap: 'path:cwd-mutate',
            resource: {
              kind: 'path-exact',
              path: { root: 'project', components: [] },
            },
          },
          provenance: [{ kind: 'import-site', source: 'src/app.mjs:1' }],
        },
      ]),
    ]),
  ).toThrow(/path:cwd-mutate is restricted to root principals/);
});

test('buildCanonicalPolicy rejects action/resource mismatches', () => {
  const bad = { ...authority, cap: 'network:fetch' };
  expect(() => buildCanonicalPolicy([principal([{
    authority: bad,
    provenance: [{ kind: 'import-site', source: 'src/app.mjs:1' }],
  }])])).toThrow(/does not accept resource kind "path-tree"/);
});

test('production authoring enforces action-specific selector constraints', () => {
  const rejected = [
    {
      cap: 'env:write',
      resource: { kind: 'environment-name', target: 'broker-base', name: 'PATH' },
    },
    {
      cap: 'stdio:write',
      resource: {
        kind: 'stdio',
        stream: 'stdin',
        source: { kind: 'terminal', identity: 'terminal-1' },
      },
    },
    {
      cap: 'stdio:raw',
      resource: {
        kind: 'stdio',
        stream: 'stdin',
        source: { kind: 'pipe', identity: 'pipe-1' },
      },
    },
    {
      cap: 'process:identity',
      resource: { kind: 'closed-surface', surfaceClass: 'process-cwd' },
    },
    {
      cap: 'storage:persist',
      resource: {
        kind: 'storage-namespace',
        store: 'session',
        namespace: { kind: 'principal' },
      },
    },
  ];
  for (const [index, bad] of rejected.entries()) {
    expect(() => buildCanonicalPolicy([principal([{
      authority: bad,
      provenance: [{ kind: 'import-site', source: `src/app.mjs:${index + 1}` }],
    }])])).toThrow(/rejects|deny-only action/);
  }
});

test('classifyPolicyDrift separates authority and vocabulary changes', () => {
  const empty = buildCanonicalPolicy([principal()]);
  const granted = buildCanonicalPolicy([principal([{
    authority,
    provenance: [{ kind: 'import-site', source: 'src/app.mjs:1' }],
  }])]);
  expect(classifyPolicyDrift(empty, granted).expansions).toHaveLength(1);
  expect(classifyPolicyDrift(granted, empty).narrowings).toHaveLength(1);
  expect(classifyPolicyDrift(empty, { ...empty, vocabDigest: packageIntegrity('new') }))
    .toEqual({
      classification: 'semantic-vocabulary-change',
      semanticVocabularyChange: true,
      identityChanges: [],
      expansions: [],
      narrowings: [],
    });
});

test('classifyPolicyDrift covers imports, endowments, denials, ceilings, and identity', () => {
  const row = (selected = authority) => ({
    authority: selected,
    provenance: [{ kind: 'import-site', source: 'app.mjs:1' }],
  });
  const baselineEntry = principal();
  const baseline = buildCanonicalPolicy([baselineEntry]);

  const importsAndEndowments = buildCanonicalPolicy([{
    ...baselineEntry,
    imports: { builtins: ['node:fs', 'node:http'], packages: ['dep@1.0.0'] },
    endowments: ['fetch'],
  }]);
  const importDrift = classifyPolicyDrift(baseline, importsAndEndowments);
  expect(importDrift.classification).toBe('expansion');
  expect(importDrift.expansions).toHaveLength(3);

  const denied = buildCanonicalPolicy([{
    ...baselineEntry,
    denials: [row()],
  }]);
  const denialRemoval = classifyPolicyDrift(denied, baseline);
  expect(denialRemoval.classification).toBe('expansion');
  expect(denialRemoval.expansions[0]).toContain('denials');

  const exact = {
    ...authority,
    resource: {
      kind: 'path-exact',
      path: { root: 'project', components: [{ encoding: 'utf8', value: 'images' }] },
    },
  };
  const narrowCeiling = buildCanonicalPolicy([{
    ...baselineEntry,
    escalationCeiling: [row(exact)],
  }]);
  const broadCeiling = buildCanonicalPolicy([{
    ...baselineEntry,
    escalationCeiling: [row(authority)],
  }]);
  expect(classifyPolicyDrift(narrowCeiling, broadCeiling).classification).toBe('expansion');

  const changedIdentity = buildCanonicalPolicy([{
    ...baselineEntry,
    principal: { ...baselineEntry.principal, integrity: packageIntegrity('changed') },
  }]);
  const identityDrift = classifyPolicyDrift(baseline, changedIdentity);
  expect(identityDrift.classification).toBe('identity-change');
  expect(identityDrift.identityChanges).toHaveLength(2);
});

test('canonical semantic sets use UTF-8/JCS byte order, never locale collation', () => {
  const values = ['𐀀', '\uE000', '_digest', '-digest', 'z'];
  const sorted = [...values].sort(compareCanonicalBytes);
  expect(sorted).toEqual(['-digest', '_digest', 'z', '\uE000', '𐀀']);
  const entry = principal();
  entry.imports.builtins = ['𐀀', '\uE000', '_digest', '-digest', 'z'];
  const policy = buildCanonicalPolicy([entry]);
  expect(policy.principals[0].imports.builtins).toEqual(sorted);
});

test('classifyPolicyDrift recognizes containment replacement as narrowing or expansion', () => {
  const exact = {
    ...authority,
    resource: {
      kind: 'path-exact',
      path: { root: 'project', components: [{ encoding: 'utf8', value: 'images' }] },
    },
  };
  const policyWith = (selected) => buildCanonicalPolicy([principal([{
    authority: selected,
    provenance: [{ kind: 'import-site', source: 'app.mjs:1' }],
  }])]);
  const broad = policyWith(authority);
  const narrow = policyWith(exact);
  expect(classifyPolicyDrift(broad, narrow).expansions).toEqual([]);
  expect(classifyPolicyDrift(broad, narrow).narrowings).toHaveLength(1);
  expect(classifyPolicyDrift(narrow, broad).expansions).toHaveLength(1);
  expect(classifyPolicyDrift(narrow, broad).narrowings).toEqual([]);
});

test('typed delegation intersection returns the narrower selector and drops disjoint authority', () => {
  const exact = {
    ...authority,
    resource: {
      kind: 'path-exact',
      path: { root: 'project', components: [{ encoding: 'utf8', value: 'images' }] },
    },
  };
  expect(intersectAuthorities(authority, exact)).toEqual(exact);
  expect(intersectAuthorities(exact, authority)).toEqual(exact);
  expect(intersectAuthorities(authority, { ...authority, cap: 'fs:write' })).toBeNull();
});

test('typed delegation cascades, attenuates, unions provenance, and cannot self-grant', () => {
  const exact = {
    ...authority,
    resource: {
      kind: 'path-exact',
      path: { root: 'project', components: [{ encoding: 'utf8', value: 'images' }] },
    },
  };
  const seed = new Map([['a@1', [{
    authority,
    provenance: [{ kind: 'import-site', source: 'app.mjs:1' }],
  }]]]);
  const requests = new Map([
    ['a@1', { authorities: [], delegates: { b: [exact] } }],
    ['b@1', { authorities: [authority], delegates: { c: [authority] } }],
    ['untrusted@1', { authorities: [authority], delegates: {} }],
  ]);
  const effective = resolveTypedDelegations({
    seed,
    edges: [['a@1', 'b@1'], ['b@1', 'c@1']],
    requests,
    bareOf: (identity) => identity.split('@')[0],
  });
  expect(effective.get('b@1')[0].authority).toEqual(exact);
  expect(effective.get('c@1')[0].authority).toEqual(exact);
  expect(effective.get('c@1')[0].provenance.map((entry) => entry.kind)).toEqual([
    'import-site', 'delegation', 'delegation',
  ]);
  expect(effective.has('untrusted@1')).toBe(false);
});
