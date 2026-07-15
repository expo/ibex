import { createHash } from 'crypto';
import {
  canonicalJson,
  compareAuthorityContainment,
  computeDomainDigest,
  loadAndValidateContract,
  validateSelectorSemantics,
} from './capsec-contract.mjs';

let cachedContract;
function contract() {
  return (cachedContract ??= loadAndValidateContract());
}
const POLICY_SCHEMA_ID = 'https://ibex.dev/capsec/schema/canonical-policy.schema.json';

export function compareCanonicalBytes(left, right) {
  const leftBytes = Buffer.from(typeof left === 'string' ? left : canonicalJson(left), 'utf8');
  const rightBytes = Buffer.from(typeof right === 'string' ? right : canonicalJson(right), 'utf8');
  return leftBytes.compare(rightBytes);
}

function canonicalStringSet(values) {
  return [...new Set(values)].sort(compareCanonicalBytes);
}

function digestBytes(value) {
  return `sha256-${createHash('sha256').update(value).digest('base64url')}`;
}

export function packageIntegrity(packageJsonText) {
  return digestBytes(Buffer.from(packageJsonText, 'utf8'));
}

// V1 intentionally exposes the authenticated virtual resolution base to every
// admitted package. Keep that choice in one generator-facing constructor so
// the row is explicit, digest-bound, and removable by a later profile.
// @ref LLP 0023#53-cwd-visibility-is-an-explicit-information-grant
export function withV1CwdObserveFloor(rows) {
  return [
    ...rows,
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
  ];
}

export function assertTypedAuthority(authority, label = 'authority', options = {}) {
  const currentContract = contract();
  const validate = currentContract.ajv.getSchema(
    'https://ibex.dev/capsec/schema/authority-selector.schema.json',
  );
  if (!validate(authority)) {
    throw new TypeError(`${label}: ${currentContract.ajv.errorsText(validate.errors)}`);
  }
  try {
    validateSelectorSemantics(
      authority,
      currentContract.definitionsById,
      label,
      options,
    );
  } catch (error) {
    throw new TypeError(error.message, { cause: error });
  }
  return authority;
}

export function canonicalAuthorityRows(
  rows,
  label = 'authority rows',
  options = {},
) {
  const byAuthority = new Map();
  for (const [index, row] of rows.entries()) {
    assertTypedAuthority(
      row.authority,
      `${label}[${index}].authority`,
      options,
    );
    if (!Array.isArray(row.provenance) || row.provenance.length === 0) {
      throw new TypeError(`${label}[${index}].provenance must be non-empty`);
    }
    const key = canonicalJson(row.authority);
    const current = byAuthority.get(key) || { authority: row.authority, provenance: [] };
    const provenance = new Map(current.provenance.map((entry) => [canonicalJson(entry), entry]));
    for (const entry of row.provenance) provenance.set(canonicalJson(entry), entry);
    current.provenance = [...provenance.values()].sort(compareCanonicalBytes);
    byAuthority.set(key, current);
  }
  return [...byAuthority.values()].sort((a, b) =>
    compareCanonicalBytes(a.authority, b.authority));
}

export function intersectAuthorities(held, delegated) {
  assertTypedAuthority(held, 'held authority');
  assertTypedAuthority(delegated, 'delegated authority');
  const context = { sameSnapshot: true, samePackageRootOwner: true };
  const heldContainsDelegated = compareAuthorityContainment(held, delegated, context);
  if (heldContainsDelegated === 'equal' || heldContainsDelegated === 'strict-subset') return delegated;
  const delegatedContainsHeld = compareAuthorityContainment(delegated, held, context);
  if (delegatedContainsHeld === 'strict-subset') return held;
  return null;
}

export function resolveTypedDelegations({ seed, edges, requests, bareOf = (value) => value }) {
  const effective = new Map([...seed].map(([identity, rows]) => [
    identity,
    rows.map((row) => ({ ...row, provenance: [...row.provenance] })),
  ]));
  let changed = true;
  while (changed) {
    changed = false;
    for (const [from, to] of edges) {
      const requested = requests.get(from)?.delegates?.[bareOf(to)];
      if (!Array.isArray(requested)) continue;
      const destination = effective.get(to) || [];
      const rowsByKey = new Map(destination.map((row) => [canonicalJson(row.authority), row]));
      for (const held of effective.get(from) || []) {
        for (const delegated of requested) {
          const authority = intersectAuthorities(held.authority, delegated);
          if (!authority) continue;
          const key = canonicalJson(authority);
          const additions = [
            ...held.provenance,
            { kind: 'delegation', source: from, rule: 'manifest.delegates' },
          ];
          const existing = rowsByKey.get(key);
          if (existing) {
            const provenanceKeys = new Set(existing.provenance.map(canonicalJson));
            for (const entry of additions) {
              if (!provenanceKeys.has(canonicalJson(entry))) {
                existing.provenance.push(entry);
                provenanceKeys.add(canonicalJson(entry));
                changed = true;
              }
            }
          } else {
            const row = { authority, provenance: additions };
            destination.push(row);
            rowsByKey.set(key, row);
            changed = true;
          }
        }
      }
      effective.set(to, destination);
    }
  }
  return effective;
}

export function buildCanonicalPolicy(principals, rootImports = []) {
  const policy = {
    policySchema: 'ibex/capsec-policy/1',
    capsVocab: 'ibex/capsec/1',
    semanticCore: 'capsec/semantics/1',
    vocabDigest: contract().policy.vocabDigest,
    registryDigest: contract().registryDigest,
    policyDigest: contract().policy.policyDigest,
    purpose: 'production',
    mode: 'enforce',
    rootImports: canonicalStringSet(rootImports),
    principals: principals.map((entry) => ({
      principal: entry.principal,
      floor: canonicalAuthorityRows(
        entry.floor || [],
        `${entry.principal.locator}.floor`,
        { positive: true, principal: entry.principal },
      ),
      denials: canonicalAuthorityRows(entry.denials || [], `${entry.principal.locator}.denials`),
      escalationCeiling: canonicalAuthorityRows(
        entry.escalationCeiling || [],
        `${entry.principal.locator}.escalationCeiling`,
        { positive: true, dynamic: true, principal: entry.principal },
      ),
      imports: {
        builtins: canonicalStringSet(entry.imports?.builtins || []),
        packages: canonicalStringSet(entry.imports?.packages || []),
      },
      endowments: canonicalStringSet(entry.endowments || []),
    })).sort((a, b) => compareCanonicalBytes(a.principal, b.principal)),
  };
  policy.policyDigest = computeDomainDigest(
    contract().rules.digestContract.domains.policy,
    policy,
    contract().rules.digestContract.projections.policy.omitFields,
  );
  const currentContract = contract();
  const validate = currentContract.ajv.getSchema(POLICY_SCHEMA_ID);
  if (!validate(policy))
    throw new TypeError(currentContract.ajv.errorsText(validate.errors));
  return policy;
}

export function classifyPolicyDrift(before, after) {
  const semanticVocabularyChange = before.vocabDigest !== after.vocabDigest ||
    before.registryDigest !== after.registryDigest ||
    before.semanticCore !== after.semanticCore || before.capsVocab !== after.capsVocab ||
    before.policySchema !== after.policySchema;
  if (semanticVocabularyChange) {
    return {
      classification: 'semantic-vocabulary-change',
      semanticVocabularyChange: true,
      identityChanges: [],
      expansions: [],
      narrowings: [],
    };
  }
  const context = { sameSnapshot: true, samePackageRootOwner: true };
  const authorityRows = (policy, field) => policy.principals.flatMap((entry) =>
    (entry[field] || []).map((row) => ({
      principal: canonicalJson(entry.principal),
      authority: row.authority,
      rendered: `${entry.principal.locator}: ${field} ${canonicalJson(row.authority)}`,
    })));
  const isContained = (parent, child) => parent.principal === child.principal &&
    ['equal', 'strict-subset'].includes(
      compareAuthorityContainment(parent.authority, child.authority, context),
    );
  const authorityDelta = (field) => {
    const oldRows = authorityRows(before, field);
    const newRows = authorityRows(after, field);
    const oldKeys = new Set(oldRows.map((row) => canonicalJson([row.principal, row.authority])));
    const newKeys = new Set(newRows.map((row) => canonicalJson([row.principal, row.authority])));
    const removed = oldRows.filter((row) =>
      !newKeys.has(canonicalJson([row.principal, row.authority])));
    const added = newRows.filter((row) =>
      !oldKeys.has(canonicalJson([row.principal, row.authority])));
    return {
      expansions: added
        .filter((row) => !removed.some((oldRow) => isContained(oldRow, row)))
        .map((row) => row.rendered),
      narrowings: removed
        .filter((row) => !added.some((newRow) => isContained(newRow, row)))
        .map((row) => row.rendered),
    };
  };
  const setRows = (policy, field) => new Set(policy.principals.flatMap((entry) => {
    const values = field === 'endowments' ? entry.endowments : entry.imports[field];
    return values.map((value) => `${entry.principal.locator}: ${field} ${value}`);
  }));
  const setDelta = (field) => {
    const oldRows = setRows(before, field);
    const newRows = setRows(after, field);
    return {
      expansions: [...newRows].filter((row) => !oldRows.has(row)),
      narrowings: [...oldRows].filter((row) => !newRows.has(row)),
    };
  };
  const floor = authorityDelta('floor');
  const ceiling = authorityDelta('escalationCeiling');
  const denials = authorityDelta('denials');
  const builtins = setDelta('builtins');
  const packages = setDelta('packages');
  const endowments = setDelta('endowments');
  const oldRootImports = new Set(before.rootImports || []);
  const newRootImports = new Set(after.rootImports || []);
  const rootImports = {
    expansions: [...newRootImports]
      .filter((locator) => !oldRootImports.has(locator))
      .map((locator) => `rootImports ${locator}`),
    narrowings: [...oldRootImports]
      .filter((locator) => !newRootImports.has(locator))
      .map((locator) => `rootImports ${locator}`),
  };
  const expansions = canonicalStringSet([
    ...floor.expansions,
    ...ceiling.expansions,
    ...denials.narrowings,
    ...builtins.expansions,
    ...packages.expansions,
    ...endowments.expansions,
    ...rootImports.expansions,
  ]);
  const narrowings = canonicalStringSet([
    ...floor.narrowings,
    ...ceiling.narrowings,
    ...denials.expansions,
    ...builtins.narrowings,
    ...packages.narrowings,
    ...endowments.narrowings,
    ...rootImports.narrowings,
  ]);
  const identitySet = (policy) => new Set(policy.principals.map((entry) =>
    canonicalJson(entry.principal)));
  const oldIdentities = identitySet(before);
  const newIdentities = identitySet(after);
  const identityChanges = canonicalStringSet([
    ...[...newIdentities].filter((identity) => !oldIdentities.has(identity))
      .map((identity) => `+ ${identity}`),
    ...[...oldIdentities].filter((identity) => !newIdentities.has(identity))
      .map((identity) => `- ${identity}`),
  ]);
  let classification = 'none';
  if (expansions.length && narrowings.length) classification = 'mixed';
  else if (expansions.length) classification = 'expansion';
  else if (narrowings.length) classification = 'narrowing';
  else if (identityChanges.length) classification = 'identity-change';
  return {
    classification,
    semanticVocabularyChange: false,
    identityChanges,
    expansions,
    narrowings,
  };
}
