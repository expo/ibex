// @ref LLP 0021#wp0-semantic-contract — the WP0 contract must fail closed on
// wildcard/untyped/unknown authority, duplicate JSON keys, or an unreconciled
// legacy capability bit.

import { describe, expect, test } from 'bun:test';
import fs from 'node:fs';
import path from 'node:path';
import {
  armedTargetPathEntries,
  assertCanonicalKeyedSets,
  assertCanonicalSets,
  assertDigestProjectionContract,
  assertDigestVectorBindings,
  assertLegacyReconciliationCoverage,
  assertLegacyReconciliationDestinations,
  assertOccurrencePrincipalContext,
  assertNoDuplicateJsonKeys,
  capsecRoot,
  canonicalSetOrder,
  canonicalJson,
  compareAuthorityContainment,
  computeDomainDigest,
  invalidFixtureNames,
  loadAndValidateContract,
  renderLegacyReconciliation,
  runContractCheck,
  validateArmedSnapshotSemantics,
  validateInvalidFixture,
  validateOccurrenceSemantics,
  validateTargetLogicalPaths,
} from './capsec-contract.mjs';
import { parseCapabilityBitDefinitions } from './generate-capability-bits.mjs';

describe('LLP 0021 WP0 capsec contract', () => {
  test('all schemas, registries, examples, and generated output validate', () => {
    const counts = runContractCheck();
    expect(counts.capabilityDefinitions).toBe(38);
    expect(counts.legacyCapabilities).toBe(57);
    expect(counts.schemas).toBe(15);
    expect(counts.selectorExamples).toBe(16);
    expect(counts.occurrenceExamples).toBe(15);
    expect(counts.decisionSets).toBe(1);
    expect(counts.containmentVectors).toBe(23);
    expect(counts.digestVectors).toBe(5);
    expect(counts.invalidFixtures).toBe(27);
    expect(renderLegacyReconciliation()).toContain(
      'This table covers all 57 entries in `src/host/capability_bits.rs`.',
    );
  });

  for (const fixture of invalidFixtureNames()) {
    test(`rejects ${fixture}`, () => {
      expect(() => validateInvalidFixture(fixture)).toThrow();
    });
  }

  test('duplicate detection compares decoded JSON keys', () => {
    expect(() => assertNoDuplicateJsonKeys('{"a":1,"\\u0061":2}', 'inline')).toThrow(
      /duplicate JSON object key "a"/,
    );
  });

  test('schema-declared sets must use canonical order', () => {
    const contract = loadAndValidateContract();
    const value = structuredClone(contract.containment.vectors.find((row) => row.id === 'fetch.narrow-sets').parent);
    value.resource.peerClasses.reverse();
    expect(() =>
      assertCanonicalSets(value, new Set(contract.rules.digestContract.setKeys), 'mutated'),
    ).toThrow(/canonical lexical order/);
  });

  test('semantic set order compares canonical UTF-8 bytes, not UTF-16 units', () => {
    const setKeys = new Set(['examples']);
    expect(() => assertCanonicalSets({ examples: ['\uE000', '𐀀'] }, setKeys)).not.toThrow();
    expect(() => assertCanonicalSets({ examples: ['𐀀', '\uE000'] }, setKeys)).toThrow(
      /canonical lexical order/,
    );
    expect(canonicalSetOrder(['pkg@𐀀', 'pkg@\uE000'])).toEqual([
      'pkg@\uE000',
      'pkg@𐀀',
    ]);
  });

  test('keyed sets must use their declared composite order', () => {
    const contract = loadAndValidateContract();
    const mutated = structuredClone(contract.targetCells);
    mutated.cells.reverse();
    const documents = new Map([
      ['ibex/capsec-target-cells/1', mutated],
    ]);
    const specification = contract.rules.digestContract.keyedSets.filter(
      (row) => row.schema === 'ibex/capsec-target-cells/1',
    );
    expect(() => assertCanonicalKeyedSets(documents, specification)).toThrow(
      /canonical lexical order/,
    );
  });

  test('armed graph and protected-object joins fail closed', () => {
    const contract = loadAndValidateContract();
    const missingGuard = structuredClone(contract.armed);
    missingGuard.protectedObjects.pop();
    expect(() => validateArmedSnapshotSemantics(missingGuard, 'mutated armed')).toThrow(
      /protected object roles are incomplete/,
    );

    const badOwner = structuredClone(contract.armed);
    badOwner.rootBindings[0].owner.name = 'other-package';
    expect(() => validateArmedSnapshotSemantics(badOwner, 'mutated armed')).toThrow(
      /package owner is not a graph node/,
    );
  });

  test('decision-set context cannot be contradicted by one effect', () => {
    const contract = loadAndValidateContract();
    const value = structuredClone(contract.effectSet);
    value.effects[0].stage = 'requested';
    const validate = contract.ajv.getSchema(
      'https://ibex.dev/capsec/schema/effect.schema.json',
    );
    expect(validate(value)).toBe(false);
  });

  test('actor and effect owner cannot escape the constrained principal intersection', () => {
    const contract = loadAndValidateContract();
    const occurrence = structuredClone(contract.occurrenceExamples.occurrences[0]);
    const duplicated = structuredClone(occurrence);
    duplicated.constrainedPrincipals.push(structuredClone(duplicated.constrainedPrincipals[0]));
    expect(() =>
      assertOccurrencePrincipalContext(duplicated, contract.rules, 'mutated occurrence'),
    ).toThrow(/duplicate/);

    const omittedActor = structuredClone(occurrence);
    omittedActor.actor = {
      kind: 'package',
      name: 'other-lib',
      integrity: 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      locator: 'other-lib@1.0.0',
    };
    expect(() =>
      assertOccurrencePrincipalContext(omittedActor, contract.rules, 'mutated occurrence'),
    ).toThrow(/actor.*absent/);

    omittedActor.actor = structuredClone(
      contract.rules.principalSemantics.transparentFramePrincipal,
    );
    expect(() =>
      assertOccurrencePrincipalContext(omittedActor, contract.rules, 'mutated occurrence'),
    ).not.toThrow();
  });

  test('later-stage occurrence facts cannot appear speculatively', () => {
    const contract = loadAndValidateContract();
    const candidate = structuredClone(
      contract.occurrenceExamples.occurrences.find(
        (occurrence) =>
          occurrence.resource.kind === 'network-occurrence' &&
          occurrence.stage === 'candidate',
      ),
    );
    candidate.stage = 'requested';
    expect(() =>
      validateOccurrenceSemantics(
        candidate,
        contract.definitionsById,
        contract.rules,
        'mutated occurrence',
      ),
    ).toThrow(/speculative candidates|speculative selectedCandidate/);

    const pathDiscovery = structuredClone(
      contract.occurrenceExamples.occurrences.find(
        (occurrence) => occurrence.resource.kind === 'path-occurrence',
      ),
    );
    pathDiscovery.stage = 'discovery';
    delete pathDiscovery.resource.finalObject;
    delete pathDiscovery.resource.retainedHandle;
    expect(() =>
      validateOccurrenceSemantics(
        pathDiscovery,
        contract.definitionsById,
        contract.rules,
        'mutated occurrence',
      ),
    ).toThrow(/discovery stage lacks finalObject/);

    const unixDiscovery = structuredClone(
      contract.occurrenceExamples.occurrences.find(
        (occurrence) => occurrence.resource.kind === 'unix-connect-occurrence',
      ),
    );
    unixDiscovery.stage = 'discovery';
    delete unixDiscovery.resource.socketObject;
    delete unixDiscovery.resource.connectionId;
    expect(() =>
      validateOccurrenceSemantics(
        unixDiscovery,
        contract.definitionsById,
        contract.rules,
        'mutated occurrence',
      ),
    ).toThrow(/discovery stage lacks socketObject/);
  });

  test('digest projections omit self-digest fields and retain every other field', () => {
    const contract = loadAndValidateContract();
    const vector = contract.digestVectors.vectors.find((row) => row.id === 'armed');
    const changedSelfDigest = structuredClone(contract.armed);
    changedSelfDigest.armedSnapshotDigest = 'different-but-omitted';
    expect(computeDomainDigest(vector.domain, changedSelfDigest, vector.omitFields)).toBe(
      vector.expectedDigest,
    );
    changedSelfDigest.channelEpoch = '2';
    expect(computeDomainDigest(vector.domain, changedSelfDigest, vector.omitFields)).not.toBe(
      vector.expectedDigest,
    );
  });

  test('digest projections and domain payloads cannot redefine their own oracle', () => {
    const contract = loadAndValidateContract();
    const changedProjection = structuredClone(contract.rules);
    changedProjection.digestContract.projections.policy.omitFields.push('purpose');
    expect(() => assertDigestProjectionContract(changedProjection)).toThrow(/frozen/);

    const changedBinding = structuredClone(contract.digestVectors);
    changedBinding.vectors.find((row) => row.id === 'vocabulary').payloadRef =
      'examples/armed-snapshot.canonical.json';
    expect(() => assertDigestVectorBindings(changedBinding)).toThrow(/not canonical/);
  });

  test('real vocabulary, registry, policy, and armed digests detect one-field tampering', () => {
    const contract = loadAndValidateContract();
    const cases = [
      {
        name: 'vocabulary',
        payload: contract.digestBundle,
        mutate: (payload) => { payload.profile = 'ibex/capsec/tampered'; },
      },
      {
        name: 'registry',
        payload: contract.registryDigestBundle,
        mutate: (payload) => { payload.profile = 'ibex/capsec/tampered'; },
      },
      {
        name: 'policy',
        payload: contract.policy,
        mutate: (payload) => { payload.capsVocab = 'ibex/capsec/tampered'; },
      },
      {
        name: 'armedSnapshot',
        payload: contract.armed,
        mutate: (payload) => { payload.channelEpoch = '2'; },
      },
    ];
    for (const row of cases) {
      const domain = contract.rules.digestContract.domains[row.name];
      const projection = contract.rules.digestContract.projections[row.name];
      const original = computeDomainDigest(domain, row.payload, projection.omitFields);
      const tampered = structuredClone(row.payload);
      row.mutate(tampered);
      expect(computeDomainDigest(domain, tampered, projection.omitFields)).not.toBe(original);
    }
  });

  test('authority containment never crosses action identity', () => {
    const contract = loadAndValidateContract();
    const vector = contract.containment.vectors.find((row) => row.id === 'cross-action');
    expect(
      compareAuthorityContainment(vector.parent, vector.child, {
        sameSnapshot: true,
        samePackageRootOwner: true,
      }),
    ).toBe('incomparable');
  });

  test('resolved package principal identity includes locator and integrity', () => {
    const contract = loadAndValidateContract();
    const armedPrincipal = contract.armed.packageGraph.nodes[0].principal;
    const samePrincipal = structuredClone(armedPrincipal);
    expect(canonicalJson(samePrincipal)).toBe(canonicalJson(armedPrincipal));
    samePrincipal.locator = 'image-lib@2.4.2';
    expect(canonicalJson(samePrincipal)).not.toBe(canonicalJson(armedPrincipal));

    const policy = structuredClone(contract.policy);
    policy.principals[0].imports.packages = ['image-lib'];
    const validatePolicy = contract.ajv.getSchema(
      'https://ibex.dev/capsec/schema/canonical-policy.schema.json',
    );
    expect(validatePolicy(policy)).toBe(false);
  });

  test('target-neutral paths defer platform aliases until arming', () => {
    const unixOnlyName = {
      root: 'project',
      components: [{ encoding: 'utf8', value: 'CON' }],
    };
    expect(() =>
      validateTargetLogicalPaths(
        [unixOnlyName],
        'x86_64-unknown-linux-gnu',
        'paths',
      ),
    ).not.toThrow();
    expect(() =>
      validateTargetLogicalPaths(
        [unixOnlyName],
        'x86_64-pc-windows-msvc',
        'paths',
        { aliasKey: (logicalPath) => canonicalJson(logicalPath).toLowerCase() },
      ),
    ).toThrow(/Windows-invalid or reserved/);

    const appleAliases = [
      { root: 'project', components: [{ encoding: 'utf8', value: 'Readme' }] },
      { root: 'project', components: [{ encoding: 'utf8', value: 'README' }] },
    ];
    expect(() =>
      validateTargetLogicalPaths(
        appleAliases,
        'aarch64-apple-darwin',
        'paths',
        {
          aliasKey: (logicalPath) =>
            `${logicalPath.root}/${logicalPath.components.map((row) => row.value).join('/').toLowerCase()}`,
        },
      ),
    ).toThrow(/alias collision/);

    const contract = loadAndValidateContract();
    const twoPackages = structuredClone(contract.armed);
    const firstRow = twoPackages.principals.find((row) => row.principal.kind === 'package');
    firstRow.floor[0].resource.path = {
      root: 'package',
      components: [{ encoding: 'utf8', value: 'Readme' }],
    };
    const secondPrincipal = {
      kind: 'package',
      name: 'other-lib',
      integrity: 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      locator: 'other-lib@1.0.0',
    };
    const secondRow = structuredClone(firstRow);
    secondRow.principal = secondPrincipal;
    secondRow.floor[0].resource.path.components[0].value = 'README';
    twoPackages.principals.push(secondRow);
    twoPackages.packageGraph.nodes.push({ principal: secondPrincipal });
    const packageBinding = structuredClone(
      twoPackages.rootBindings.find((binding) => binding.logicalRoot === 'package'),
    );
    packageBinding.owner = secondPrincipal;
    packageBinding.hostPath.components.at(-1).value = 'other-lib';
    packageBinding.object.file = 'file-201';
    twoPackages.rootBindings.push(packageBinding);

    const entries = armedTargetPathEntries(twoPackages).filter(
      (entry) => entry.logicalPath.root === 'package',
    );
    const aliasAdapter = {
      aliasKey: (logicalPath) =>
        logicalPath.components.map((row) => row.value).join('/').toLowerCase(),
    };
    expect(() =>
      validateTargetLogicalPaths(
        entries,
        'aarch64-apple-darwin',
        'package paths',
        aliasAdapter,
      ),
    ).not.toThrow();
    expect(() =>
      validateTargetLogicalPaths(
        entries.map((entry) => ({ ...entry, namespace: 'same-binding' })),
        'aarch64-apple-darwin',
        'package paths',
        aliasAdapter,
      ),
    ).toThrow(/alias collision/);
  });

  test('production snapshots require an advertised complete exact target', () => {
    const contract = loadAndValidateContract();
    const production = structuredClone(contract.armed);
    production.workflow = 'production';
    production.engine.target = 'aarch64-apple-darwin';
    expect(() =>
      validateArmedSnapshotSemantics(production, 'mutated armed', {
        rules: contract.rules,
        coverage: contract.coverage,
        targetCells: contract.targetCells,
      }),
    ).toThrow(/not advertised/);

    const advertisedRules = structuredClone(contract.rules);
    advertisedRules.initialProfile.advertisedTargets = [
      {
        triple: production.engine.target,
        features: production.engine.features,
      },
    ];
    expect(() =>
      validateArmedSnapshotSemantics(production, 'mutated armed', {
        rules: advertisedRules,
        coverage: contract.coverage,
        targetCells: contract.targetCells,
      }),
    ).toThrow(/no complete cell/);

    const unsupportedCells = {
      cells: contract.coverage.edges.map((edge) => ({
        edgeId: edge.id,
        target: structuredClone(advertisedRules.initialProfile.advertisedTargets[0]),
        disposition: 'enforced',
      })),
    };
    unsupportedCells.cells[0].disposition = 'unsupported';
    expect(() =>
      validateArmedSnapshotSemantics(production, 'mutated armed', {
        rules: advertisedRules,
        coverage: contract.coverage,
        targetCells: unsupportedCells,
      }),
    ).toThrow(new RegExp(`no complete cell for coverage edge ${contract.coverage.edges[0].id}`));
  });

  test('a missing legacy row fails reconciliation even if schemas still parse', () => {
    const source = fs.readFileSync(
      path.join(capsecRoot, '..', 'src', 'host', 'capability_bits.rs'),
      'utf8',
    );
    const bits = parseCapabilityBitDefinitions(source);
    const reconciliation = JSON.parse(
      fs.readFileSync(
        path.join(capsecRoot, 'registry', 'legacy-capability-reconciliation.json'),
        'utf8',
      ),
    );
    expect(() =>
      assertLegacyReconciliationCoverage(bits, reconciliation.entries.slice(0, -1)),
    ).toThrow(/missing=network:resolve/);
  });

  test('closed legacy rows can map only to deny-only definitions', () => {
    const contract = loadAndValidateContract();
    const entries = structuredClone(contract.reconciliation.entries);
    entries.find((entry) => entry.destinationDisposition === 'closed').replacementActions = [
      'fs:read',
    ];
    expect(() =>
      assertLegacyReconciliationDestinations(entries, contract.definitionsById),
    ).toThrow(/non-deny-only/);
  });

  test('only live rows inside the Rust capability table are authoritative', () => {
    const source = `
CapabilityBitDefinition { capability: "fake:outside", bit: 6 }
const GHOST: &str = "pub const CAPABILITY_BIT_DEFINITIONS: = &[fake]";
pub const CAPABILITY_BIT_DEFINITIONS: &[CapabilityBitDefinition] = &[
  // CapabilityBitDefinition { capability: "fake:line", bit: 7 }
  /* CapabilityBitDefinition { capability: "fake:block", bit: 8 } */
  CapabilityBitDefinition { capability: "real:entry", bit: 0 }
];`;
    expect(parseCapabilityBitDefinitions(source)).toEqual([
      { capability: 'real:entry', bit: 0 },
    ]);
  });
});
