import { createHash } from 'crypto';
import {
  canonicalJson,
  compareAuthorityContainment,
  computeDomainDigest,
  loadAndValidateContract,
} from './capsec-contract.mjs';

const CONTRACT = loadAndValidateContract();
const POLICY_SCHEMA_ID = 'https://ibex.dev/capsec/schema/canonical-policy.schema.json';

function digestBytes(value) {
  return `sha256-${createHash('sha256').update(value).digest('base64url')}`;
}

export function packageIntegrity(packageJsonText) {
  return digestBytes(Buffer.from(packageJsonText, 'utf8'));
}

export function assertTypedAuthority(authority, label = 'authority') {
  const validate = CONTRACT.ajv.getSchema(
    'https://ibex.dev/capsec/schema/authority-selector.schema.json',
  );
  if (!validate(authority)) {
    throw new TypeError(`${label}: ${CONTRACT.ajv.errorsText(validate.errors)}`);
  }
  const definition = CONTRACT.definitionsById.get(authority.cap);
  if (!definition || !definition.resourceKinds.includes(authority.resource.kind)) {
    throw new TypeError(`${label}: ${authority.cap} cannot select ${authority.resource.kind}`);
  }
  return authority;
}

export function canonicalAuthorityRows(rows, label = 'authority rows') {
  const byAuthority = new Map();
  for (const [index, row] of rows.entries()) {
    assertTypedAuthority(row.authority, `${label}[${index}].authority`);
    if (!Array.isArray(row.provenance) || row.provenance.length === 0) {
      throw new TypeError(`${label}[${index}].provenance must be non-empty`);
    }
    const key = canonicalJson(row.authority);
    const current = byAuthority.get(key) || { authority: row.authority, provenance: [] };
    const provenance = new Map(current.provenance.map((entry) => [canonicalJson(entry), entry]));
    for (const entry of row.provenance) provenance.set(canonicalJson(entry), entry);
    current.provenance = [...provenance.values()].sort((a, b) =>
      Buffer.from(canonicalJson(a)).compare(Buffer.from(canonicalJson(b))),
    );
    byAuthority.set(key, current);
  }
  return [...byAuthority.values()].sort((a, b) =>
    Buffer.from(canonicalJson(a.authority)).compare(Buffer.from(canonicalJson(b.authority))),
  );
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

export function buildCanonicalPolicy(principals) {
  const policy = {
    policySchema: 'ibex/capsec-policy/1',
    capsVocab: 'ibex/capsec/1',
    semanticCore: 'capsec/semantics/1',
    vocabDigest: CONTRACT.policy.vocabDigest,
    policyDigest: CONTRACT.policy.policyDigest,
    purpose: 'production',
    mode: 'enforce',
    principals: principals.map((entry) => ({
      principal: entry.principal,
      floor: canonicalAuthorityRows(entry.floor || [], `${entry.principal.locator}.floor`),
      denials: canonicalAuthorityRows(entry.denials || [], `${entry.principal.locator}.denials`),
      escalationCeiling: canonicalAuthorityRows(
        entry.escalationCeiling || [],
        `${entry.principal.locator}.escalationCeiling`,
      ),
      imports: {
        builtins: [...new Set(entry.imports?.builtins || [])].sort(),
        packages: [...new Set(entry.imports?.packages || [])].sort(),
      },
      endowments: [...new Set(entry.endowments || [])].sort(),
    })).sort((a, b) => canonicalJson(a.principal).localeCompare(canonicalJson(b.principal))),
  };
  policy.policyDigest = computeDomainDigest(
    CONTRACT.rules.digestContract.domains.policy,
    policy,
    CONTRACT.rules.digestContract.projections.policy.omitFields,
  );
  const validate = CONTRACT.ajv.getSchema(POLICY_SCHEMA_ID);
  if (!validate(policy)) throw new TypeError(CONTRACT.ajv.errorsText(validate.errors));
  return policy;
}

export function classifyPolicyDrift(before, after) {
  if (before.vocabDigest !== after.vocabDigest || before.semanticCore !== after.semanticCore) {
    return { semanticVocabularyChange: true, expansions: [], narrowings: [] };
  }
  const rows = (policy) => policy.principals.flatMap((principal) =>
    principal.floor.map((row) => ({
      principal: canonicalJson(principal.principal),
      authority: row.authority,
      rendered: canonicalJson([principal.principal, row.authority]),
    })));
  const oldRows = rows(before);
  const newRows = rows(after);
  const oldKeys = new Set(oldRows.map((row) => row.rendered));
  const newKeys = new Set(newRows.map((row) => row.rendered));
  const removed = oldRows.filter((row) => !newKeys.has(row.rendered));
  const added = newRows.filter((row) => !oldKeys.has(row.rendered));
  const context = { sameSnapshot: true, samePackageRootOwner: true };
  const isContained = (parent, child) =>
    parent.principal === child.principal &&
    ['equal', 'strict-subset'].includes(
      compareAuthorityContainment(parent.authority, child.authority, context),
    );
  return {
    semanticVocabularyChange: false,
    expansions: added
      .filter((row) => !removed.some((oldRow) => isContained(oldRow, row)))
      .map((row) => row.rendered)
      .sort(),
    narrowings: removed
      .filter((row) => !added.some((newRow) => isContained(newRow, row)))
      .map((row) => row.rendered)
      .sort(),
  };
}
