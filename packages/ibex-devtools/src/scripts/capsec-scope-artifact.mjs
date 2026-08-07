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

function asCanonicalStringSet(values) {
  return [...new Set(values)].sort(compareText);
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function capabilityFamily(actionId) {
  invariant(
    typeof actionId === "string" && actionId.includes(":"),
    `invalid capability action ${JSON.stringify(actionId)}`,
  );
  return actionId.slice(0, actionId.indexOf(":"));
}

function validateTarget(target) {
  exactKeys(target, ["triple", "features"], "scope target");
  invariant(
    typeof target.triple === "string" &&
      /^[a-z0-9_]+(?:-[a-z0-9_]+){2,}$/u.test(target.triple),
    "scope target has an invalid triple",
  );
  canonicalStringSet(target.features, "scope target features", {
    allowEmpty: true,
  });
  return target;
}

function validatePredecessor(predecessor) {
  invariant(
    predecessor && typeof predecessor === "object" && !Array.isArray(predecessor),
    "scope predecessor must be an object",
  );
  if (predecessor.kind === "genesis") {
    exactKeys(predecessor, ["kind"], "scope predecessor");
  } else {
    exactKeys(predecessor, ["kind", "scopeDigest"], "scope predecessor");
    invariant(predecessor.kind === "scope", "unknown scope predecessor kind");
    invariant(
      /^sha256-[A-Za-z0-9_-]{43}$/u.test(predecessor.scopeDigest),
      "scope predecessor has an invalid digest",
    );
  }
  return predecessor;
}

function predecessorForScope(predecessorScope, target) {
  if (predecessorScope === null || predecessorScope === undefined) {
    return { predecessor: { kind: "genesis" }, previousExpandedCellIds: [] };
  }
  invariant(
    predecessorScope.scopeSchema === SCOPE_SCHEMA &&
      predecessorScope.scopeDigest === computeScopeDigest(predecessorScope),
    "predecessor scope is malformed or digest-mismatched",
  );
  invariant(
    same(predecessorScope.target, target),
    "predecessor scope target differs from successor target",
  );
  canonicalStringSet(
    predecessorScope.expandedCellIds,
    "predecessor expandedCellIds",
  );
  return {
    predecessor: {
      kind: "scope",
      scopeDigest: predecessorScope.scopeDigest,
    },
    previousExpandedCellIds: predecessorScope.expandedCellIds,
  };
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

/**
 * Project the unchanged full fixture catalog into the normalized inventory
 * consumed by expandScope. This is intentionally a projection after
 * fixtureCatalogForTarget, never a scoped replacement for that authority.
 */
export function scopeInventoryForTarget({ catalog, coverage }) {
  invariant(Array.isArray(catalog), "scope catalog must be an array");
  invariant(Array.isArray(coverage?.edges), "scope coverage must have edges");
  const coverageById = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  invariant(
    coverageById.size === coverage.edges.length,
    "scope coverage contains duplicate edge ids",
  );
  const catalogIds = catalog.map((cell) => cell.edgeId);
  invariant(
    new Set(catalogIds).size === catalogIds.length &&
      same(asCanonicalStringSet(catalogIds), asCanonicalStringSet(coverageById.keys())),
    "scope catalog is not the exact full coverage inventory",
  );
  return catalog
    .map((cell) => {
      const edge = coverageById.get(cell.edgeId);
      invariant(
        Array.isArray(cell.fixtureBindings),
        `${cell.edgeId}: scope catalog cell lacks fixture bindings`,
      );
      const familySets = cell.fixtureBindings.map((binding) =>
        asCanonicalStringSet((binding.actionIds ?? []).map(capabilityFamily)),
      );
      const uniqueFamilySets = [
        ...new Map(
          familySets.map((families) => [canonicalJson(families), families]),
        ).values(),
      ].sort((left, right) => compareText(canonicalJson(left), canonicalJson(right)));
      return {
        edgeId: cell.edgeId,
        surfaceKind: edge.surface.kind,
        capabilityFamilySets: uniqueFamilySets,
        dependencyEdgeIds: [],
      };
    })
    .sort((left, right) => compareText(left.edgeId, right.edgeId));
}

function implementationIndexes(implementation) {
  invariant(
    Array.isArray(implementation?.surfaces),
    "scope implementation manifest has no surfaces",
  );
  const byBranch = new Map();
  const edgeByObservedKey = new Map();
  for (const row of implementation.surfaces) {
    invariant(
      typeof row?.branchId === "string" && !byBranch.has(row.branchId),
      `duplicate or malformed implementation branch ${row?.branchId}`,
    );
    byBranch.set(row.branchId, row);
    const prior = edgeByObservedKey.get(row.observedKey);
    invariant(
      prior === undefined || prior === row.edgeId,
      `${row.observedKey}: observed surface resolves to several coverage cells`,
    );
    edgeByObservedKey.set(row.observedKey, row.edgeId);
  }
  return { byBranch, edgeByObservedKey };
}

function liveSurfaceIndex(surfaceInventory) {
  const surfaces = Array.isArray(surfaceInventory)
    ? surfaceInventory
    : surfaceInventory?.surfaces;
  invariant(Array.isArray(surfaces), "source surface inventory has no surfaces");
  const byObservedKey = new Map();
  for (const surface of surfaces) {
    invariant(
      typeof surface?.observedKey === "string" &&
        !byObservedKey.has(surface.observedKey),
      `duplicate or malformed source surface ${surface?.observedKey}`,
    );
    byObservedKey.set(surface.observedKey, surface);
  }
  return byObservedKey;
}

function routeDependencies(row, live, edgeByObservedKey) {
  const routeEvidence = live?.metadata?.enforcementRouteEvidence;
  let routes;
  if (routeEvidence?.kind === "static-builtin-call-graph") {
    const ambiguousCallees = routeEvidence.ambiguousCallees ?? [];
    invariant(
      Array.isArray(ambiguousCallees) && ambiguousCallees.length === 0,
      `${row.edgeId}: source route retains ambiguous callees`,
    );
    invariant(
      Array.isArray(routeEvidence.terminals) && routeEvidence.terminals.length > 0,
      `${row.edgeId}: source route has no terminal alternatives`,
    );
    const terminals = asCanonicalStringSet(routeEvidence.terminals);
    routes = terminals.map((terminal) => {
      const terminalObservedKey = `native-op:${terminal}`;
      const proofPaths = asCanonicalStringSet(
        (routeEvidence.paths ?? []).filter((routePath) =>
          routePath.endsWith(` -> ${terminal}`),
        ),
      );
      invariant(
        proofPaths.length > 0,
        `${row.edgeId}: terminal ${terminalObservedKey} has no source proof path`,
      );
      return {
        terminalObservedKey,
        proofPaths,
        dependencyKind:
          terminals.length > 1
            ? "argument-selected-branch-alternative"
            : "source-derived-route",
      };
    });
  } else {
    const route = row.enforcementRoute;
    invariant(
      route &&
        typeof route.terminalObservedKey === "string" &&
        Array.isArray(route.proofPaths) &&
        route.proofPaths.length > 0,
      `${row.edgeId}: implementation route cannot be conservatively resolved`,
    );
    routes = [
      {
        terminalObservedKey: route.terminalObservedKey,
        proofPaths: asCanonicalStringSet(route.proofPaths),
        dependencyKind: "source-derived-route",
      },
    ];
  }
  return routes.map((route) => {
    const toEdgeId = edgeByObservedKey.get(route.terminalObservedKey);
    invariant(
      typeof toEdgeId === "string",
      `${row.edgeId}: unresolved terminal dependency ${route.terminalObservedKey}`,
    );
    const sourceRefs = asCanonicalStringSet(
      row.enforcementRoute?.sourceRefs ?? row.sourceRefs ?? [],
    );
    invariant(
      sourceRefs.length > 0,
      `${row.edgeId}: dependency has no reviewed source references`,
    );
    return {
      fromEdgeId: row.edgeId,
      toEdgeId,
      dependencyKind: route.dependencyKind,
      implementationBranchId: row.branchId,
      terminalObservedKey: route.terminalObservedKey,
      proofPaths: route.proofPaths,
      sourceRefs,
    };
  });
}

/** Derive source-route closure for only the selector-reachable cells. */
export function deriveScopeExpansion({
  intensionalDefinition,
  catalog,
  coverage,
  implementation,
  surfaceInventory,
}) {
  const inventory = scopeInventoryForTarget({ catalog, coverage });
  const catalogById = new Map(catalog.map((cell) => [cell.edgeId, cell]));
  const inventoryById = new Map(inventory.map((entry) => [entry.edgeId, entry]));
  const { byBranch, edgeByObservedKey } = implementationIndexes(implementation);
  const liveByObservedKey = liveSurfaceIndex(surfaceInventory);
  const expanded = new Set(
    expandScope(intensionalDefinition, inventory),
  );
  const pending = [...expanded];
  const visited = new Set();
  const closureEdges = new Map();
  while (pending.length > 0) {
    const edgeId = pending.shift();
    if (visited.has(edgeId)) continue;
    visited.add(edgeId);
    const cell = catalogById.get(edgeId);
    invariant(cell, `${edgeId}: closure cell is absent from the full catalog`);
    const dependencies = [];
    for (const branchId of cell.implementationBranchIds ?? []) {
      const row = byBranch.get(branchId);
      invariant(
        row?.edgeId === edgeId,
        `${edgeId}: selected implementation branch ${branchId} is unresolved`,
      );
      const live = liveByObservedKey.get(row.observedKey);
      invariant(live, `${edgeId}: source-derived surface is absent`);
      for (const closureEdge of routeDependencies(
        row,
        live,
        edgeByObservedKey,
      )) {
        const key = canonicalJson(closureEdge);
        closureEdges.set(key, closureEdge);
        dependencies.push(closureEdge.toEdgeId);
        if (!expanded.has(closureEdge.toEdgeId)) {
          expanded.add(closureEdge.toEdgeId);
          pending.push(closureEdge.toEdgeId);
        }
      }
    }
    inventoryById.get(edgeId).dependencyEdgeIds =
      asCanonicalStringSet(dependencies);
  }
  const normalizedInventory = [...inventoryById.values()].sort((left, right) =>
    compareText(left.edgeId, right.edgeId),
  );
  const expandedCellIds = expandScope(
    intensionalDefinition,
    normalizedInventory,
  );
  invariant(
    same(expandedCellIds, asCanonicalStringSet(expanded)),
    "scope closure expansion is internally inconsistent",
  );
  return {
    expandedCellIds,
    closureEdges: [...closureEdges.values()].sort((left, right) =>
      compareText(canonicalJson(left), canonicalJson(right)),
    ),
    inventory: normalizedInventory,
  };
}

export function buildScopeExpansionDiff({
  target,
  predecessorScope = null,
  currentExpandedCellIds,
  liveInventoryEdgeIds,
}) {
  validateTarget(target);
  canonicalStringSet(currentExpandedCellIds, "current expandedCellIds");
  const live = new Set(
    canonicalStringSet(liveInventoryEdgeIds, "live inventory edge ids"),
  );
  const { predecessor, previousExpandedCellIds } = predecessorForScope(
    predecessorScope,
    target,
  );
  const previous = new Set(previousExpandedCellIds);
  const current = new Set(currentExpandedCellIds);
  const addedCellIds = currentExpandedCellIds.filter((edgeId) => !previous.has(edgeId));
  const retiredCellIds = previousExpandedCellIds.filter((edgeId) => !current.has(edgeId));
  const stillLive = retiredCellIds.filter((edgeId) => live.has(edgeId));
  invariant(
    stillLive.length === 0,
    `scope expansion attempts to retire live inventory cells: ${stillLive.join(", ")}`,
  );
  const artifact = {
    scopeExpansionDiffSchema: SCOPE_EXPANSION_DIFF_SCHEMA,
    profile: "ibex/capsec/1",
    target,
    predecessor,
    previousExpandedCellIds,
    currentExpandedCellIds,
    addedCellIds,
    retiredCellIds,
  };
  artifact.scopeExpansionDiffDigest = computeScopeExpansionDiffDigest(artifact);
  return artifact;
}

function validateMappingEntry(entry, index) {
  exactKeys(
    entry,
    ["kind", "predecessorCellIds", "successorCellIds"],
    `scope cell mapping ${index}`,
  );
  canonicalStringSet(entry.predecessorCellIds, `mapping ${index} predecessorCellIds`);
  canonicalStringSet(entry.successorCellIds, `mapping ${index} successorCellIds`);
  const expected =
    entry.predecessorCellIds.length === 1 && entry.successorCellIds.length === 1
      ? "rename"
      : entry.predecessorCellIds.length === 1 && entry.successorCellIds.length > 1
        ? "split"
        : entry.predecessorCellIds.length > 1 && entry.successorCellIds.length === 1
          ? "merge"
          : null;
  invariant(
    entry.kind === expected,
    `scope cell mapping ${index} has non-partitioning ${entry.kind} cardinality`,
  );
}

export function buildScopeCellMapping({
  target,
  expansionDiff,
  inventoryHistory,
}) {
  validateTarget(target);
  invariant(
    expansionDiff?.scopeExpansionDiffDigest ===
      computeScopeExpansionDiffDigest(expansionDiff) &&
      same(expansionDiff.target, target),
    "scope cell mapping requires the exact expansion diff",
  );
  let history = inventoryHistory;
  if (history === undefined || history === null) {
    invariant(
      expansionDiff.addedCellIds.length === 0 ||
        expansionDiff.retiredCellIds.length === 0,
      "simultaneous additions and retirements require authenticated inventory history",
    );
    history = {
      additions: expansionDiff.addedCellIds,
      retirements: expansionDiff.retiredCellIds,
      mappings: [],
    };
  }
  exactKeys(
    history,
    ["additions", "retirements", "mappings"],
    "scope inventory history",
  );
  canonicalStringSet(history.additions, "scope history additions", {
    allowEmpty: true,
  });
  canonicalStringSet(history.retirements, "scope history retirements", {
    allowEmpty: true,
  });
  invariant(Array.isArray(history.mappings), "scope history mappings must be an array");
  history.mappings.forEach(validateMappingEntry);
  const mappedPredecessors = history.mappings.flatMap(
    (entry) => entry.predecessorCellIds,
  );
  const mappedSuccessors = history.mappings.flatMap(
    (entry) => entry.successorCellIds,
  );
  const predecessorPartition = [...history.retirements, ...mappedPredecessors];
  const successorPartition = [...history.additions, ...mappedSuccessors];
  invariant(
    new Set(predecessorPartition).size === predecessorPartition.length &&
      same(asCanonicalStringSet(predecessorPartition), expansionDiff.retiredCellIds),
    "cell mapping is not total exactly once on the predecessor side",
  );
  invariant(
    new Set(successorPartition).size === successorPartition.length &&
      same(asCanonicalStringSet(successorPartition), expansionDiff.addedCellIds),
    "cell mapping is not total exactly once on the successor side",
  );
  const mappings = [...history.mappings].sort((left, right) =>
    compareText(canonicalJson(left), canonicalJson(right)),
  );
  invariant(
    same(mappings, history.mappings),
    "scope history mappings must be canonically sorted",
  );
  const artifact = {
    scopeCellMappingSchema: SCOPE_CELL_MAPPING_SCHEMA,
    profile: "ibex/capsec/1",
    target,
    predecessor: expansionDiff.predecessor,
    additions: history.additions,
    retirements: history.retirements,
    mappings,
  };
  artifact.scopeCellMappingDigest = computeScopeCellMappingDigest(artifact);
  return artifact;
}

export function buildScopeArtifact({
  target,
  intensionalDefinition,
  expandedCellIds,
  closureEdges,
  predecessor,
  expansionDiff,
  cellMapping,
}) {
  validateTarget(target);
  validateIntensionalDefinition(intensionalDefinition);
  canonicalStringSet(expandedCellIds, "scope expandedCellIds");
  validatePredecessor(predecessor);
  invariant(Array.isArray(closureEdges) && closureEdges.length > 0, "scope closure is empty");
  const canonicalEdges = [...closureEdges].sort((left, right) =>
    compareText(canonicalJson(left), canonicalJson(right)),
  );
  invariant(same(canonicalEdges, closureEdges), "scope closure edges are not canonical");
  const expanded = new Set(expandedCellIds);
  for (const edge of closureEdges) {
    exactKeys(
      edge,
      [
        "fromEdgeId",
        "toEdgeId",
        "dependencyKind",
        "implementationBranchId",
        "terminalObservedKey",
        "proofPaths",
        "sourceRefs",
      ],
      "scope closure edge",
    );
    invariant(
      expanded.has(edge.fromEdgeId) && expanded.has(edge.toEdgeId),
      "scope closure edge escapes expandedCellIds",
    );
  }
  invariant(
    expansionDiff?.scopeExpansionDiffDigest ===
      computeScopeExpansionDiffDigest(expansionDiff) &&
      cellMapping?.scopeCellMappingDigest ===
        computeScopeCellMappingDigest(cellMapping) &&
      same(expansionDiff.target, target) &&
      same(cellMapping.target, target) &&
      same(expansionDiff.predecessor, predecessor) &&
      same(cellMapping.predecessor, predecessor) &&
      same(expansionDiff.currentExpandedCellIds, expandedCellIds),
    "scope companions do not bind the exact scope expansion",
  );
  const artifact = {
    scopeSchema: SCOPE_SCHEMA,
    profile: "ibex/capsec/1",
    target,
    intensionalDefinition,
    expandedCellIds,
    closureEdges,
    predecessor,
    scopeExpansionDiffDigest: expansionDiff.scopeExpansionDiffDigest,
    scopeCellMappingDigest: cellMapping.scopeCellMappingDigest,
  };
  artifact.scopeDigest = computeScopeDigest(artifact);
  return artifact;
}

export function generateScopeArtifacts({
  target,
  intensionalDefinition,
  catalog,
  coverage,
  implementation,
  surfaceInventory,
  predecessorScope = null,
  inventoryHistory = null,
}) {
  const expansion = deriveScopeExpansion({
    intensionalDefinition,
    catalog,
    coverage,
    implementation,
    surfaceInventory,
  });
  const expansionDiff = buildScopeExpansionDiff({
    target,
    predecessorScope,
    currentExpandedCellIds: expansion.expandedCellIds,
    liveInventoryEdgeIds: coverage.edges.map((edge) => edge.id).sort(compareText),
  });
  const cellMapping = buildScopeCellMapping({
    target,
    expansionDiff,
    inventoryHistory,
  });
  const scope = buildScopeArtifact({
    target,
    intensionalDefinition,
    expandedCellIds: expansion.expandedCellIds,
    closureEdges: expansion.closureEdges,
    predecessor: expansionDiff.predecessor,
    expansionDiff,
    cellMapping,
  });
  return { scope, expansionDiff, cellMapping };
}
