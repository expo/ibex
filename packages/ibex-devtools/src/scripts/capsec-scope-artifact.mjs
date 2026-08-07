// Canonical scope identity and complete-cell selector expansion.
//
// @ref LLP 0021#amendment-scoped-advertisement-2026-08-06 — A1 makes the
// generator the sole creator of scopeDigest and requires a closed, set-only
// selector grammar plus a dependency-closed complete-cell expansion.

import {
  canonicalJson,
  semanticDigest,
} from "../../../../scripts/portable-engine-contract.mjs";

export const SCOPE_SCHEMA = "ibex/capsec-scope/1";
export const SCOPE_DOMAIN = "ibex:capsec:scope:1";
export const SCOPE_EXPANSION_DIFF_SCHEMA =
  "ibex/capsec-scope-expansion-diff/1";
export const SCOPE_EXPANSION_DIFF_DOMAIN =
  "ibex:capsec:scope-expansion-diff:1";
export const SCOPE_CELL_MAPPING_SCHEMA =
  "ibex/capsec-scope-cell-mapping/1";
export const SCOPE_CELL_MAPPING_DOMAIN =
  "ibex:capsec:scope-cell-mapping:1";

const STABLE_ID = /^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/u;
const compareText = (left, right) =>
  left < right ? -1 : left > right ? 1 : 0;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  invariant(
    value && typeof value === "object" && !Array.isArray(value),
    `${label} must be an object`,
  );
  invariant(
    canonicalJson(Object.keys(value).sort(compareText)) ===
      canonicalJson([...expected].sort(compareText)),
    `${label} has unknown or missing fields`,
  );
}

function canonicalStringSet(values, label, { allowEmpty = false } = {}) {
  invariant(Array.isArray(values), `${label} must be an array`);
  invariant(
    values.every((value) => typeof value === "string" && STABLE_ID.test(value)),
    `${label} contains an invalid identifier`,
  );
  const canonical = [...new Set(values)].sort(compareText);
  invariant(
    allowEmpty || canonical.length > 0,
    `${label} must name at least one identifier`,
  );
  invariant(
    canonicalJson(values) === canonicalJson(canonical),
    `${label} must be a canonical sorted set`,
  );
  return canonical;
}

export function validateIntensionalDefinition(intensional) {
  exactKeys(
    intensional,
    ["capabilityFamilies", "surfaceKinds"],
    "scope intensional definition",
  );
  canonicalStringSet(
    intensional.capabilityFamilies,
    "scope capabilityFamilies",
  );
  canonicalStringSet(intensional.surfaceKinds, "scope surfaceKinds");
  return intensional;
}

function validateInventoryEntry(entry, index) {
  exactKeys(
    entry,
    ["edgeId", "surfaceKind", "capabilityFamilySets", "dependencyEdgeIds"],
    `scope inventory entry ${index}`,
  );
  invariant(STABLE_ID.test(entry.edgeId), `${entry.edgeId}: invalid edge id`);
  invariant(
    STABLE_ID.test(entry.surfaceKind),
    `${entry.edgeId}: invalid surface kind`,
  );
  invariant(
    Array.isArray(entry.capabilityFamilySets),
    `${entry.edgeId}: capabilityFamilySets must be an array`,
  );
  for (const [setIndex, families] of entry.capabilityFamilySets.entries()) {
    canonicalStringSet(
      families,
      `${entry.edgeId}: capabilityFamilySets[${setIndex}]`,
      { allowEmpty: true },
    );
  }
  canonicalStringSet(entry.dependencyEdgeIds, `${entry.edgeId}: dependencyEdgeIds`, {
    allowEmpty: true,
  });
}

/**
 * Expand a set-only selector over normalized full-inventory cells, then follow
 * every source-derived dependency transitively. A cell is selected only when
 * its surface kind is named and at least one complete fixture row has a
 * non-empty capability-family set wholly contained by the selected families.
 */
export function expandScope(intensional, inventory) {
  validateIntensionalDefinition(intensional);
  invariant(Array.isArray(inventory), "scope inventory must be an array");
  inventory.forEach(validateInventoryEntry);
  const byId = new Map();
  for (const entry of inventory) {
    invariant(!byId.has(entry.edgeId), `duplicate scope inventory edge ${entry.edgeId}`);
    byId.set(entry.edgeId, entry);
  }
  const families = new Set(intensional.capabilityFamilies);
  const surfaceKinds = new Set(intensional.surfaceKinds);
  const expanded = new Set();
  const pending = [];
  for (const entry of inventory) {
    const selected =
      surfaceKinds.has(entry.surfaceKind) &&
      entry.capabilityFamilySets.some(
        (rowFamilies) =>
          rowFamilies.length > 0 &&
          rowFamilies.every((family) => families.has(family)),
      );
    if (selected) {
      expanded.add(entry.edgeId);
      pending.push(entry.edgeId);
    }
  }
  while (pending.length > 0) {
    const edgeId = pending.shift();
    for (const dependencyEdgeId of byId.get(edgeId).dependencyEdgeIds) {
      invariant(
        byId.has(dependencyEdgeId),
        `${edgeId}: unresolved scope dependency ${dependencyEdgeId}`,
      );
      if (!expanded.has(dependencyEdgeId)) {
        expanded.add(dependencyEdgeId);
        pending.push(dependencyEdgeId);
      }
    }
  }
  invariant(expanded.size > 0, "scope selector expands to no complete cells");
  return [...expanded].sort(compareText);
}

export function computeScopeDigest(artifact) {
  invariant(
    artifact?.scopeSchema === SCOPE_SCHEMA,
    `scope artifact schema must be ${SCOPE_SCHEMA}`,
  );
  return semanticDigest(SCOPE_DOMAIN, artifact, ["scopeDigest"]);
}

export function computeScopeExpansionDiffDigest(artifact) {
  invariant(
    artifact?.scopeExpansionDiffSchema === SCOPE_EXPANSION_DIFF_SCHEMA,
    `scope expansion diff schema must be ${SCOPE_EXPANSION_DIFF_SCHEMA}`,
  );
  return semanticDigest(SCOPE_EXPANSION_DIFF_DOMAIN, artifact, [
    "scopeExpansionDiffDigest",
  ]);
}

export function computeScopeCellMappingDigest(artifact) {
  invariant(
    artifact?.scopeCellMappingSchema === SCOPE_CELL_MAPPING_SCHEMA,
    `scope cell mapping schema must be ${SCOPE_CELL_MAPPING_SCHEMA}`,
  );
  return semanticDigest(SCOPE_CELL_MAPPING_DOMAIN, artifact, [
    "scopeCellMappingDigest",
  ]);
}
