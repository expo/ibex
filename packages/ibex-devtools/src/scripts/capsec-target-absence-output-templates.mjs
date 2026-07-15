/**
 * Join source-bound target-absence recipes to their exact output-catalog rows.
 * The join deliberately retains the recipe fixture and named surface instead
 * of turning target availability into an inferred output.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — an
 * absent output is evidence only when an executable recipe inspects the exact
 * target and the exact source-discovered public surface.
 * @ref LLP 0023#8-registry-obligations — output policy and execution evidence
 * join through the one canonical six-part output key.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";
import { canonicalOutputDispositionKey } from "./capsec-output-dispositions.mjs";

const TARGET_ABSENCE_INVOCATION =
  "ibex/capsec-target-absence-invocation/1";
const NATIVE_GLOBAL_INVOCATION = "ibex/capsec-native-global-invocation/1";

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function exactStrings(actual, expected, label) {
  requireCondition(Array.isArray(actual), `${label}: expected an array`);
  const left = [...actual].sort(compareText);
  const right = [...expected].sort(compareText);
  requireCondition(
    canonicalJson(left) === canonicalJson(right),
    `${label}: expected [${right.join(", ")}], got [${left.join(", ")}]`,
  );
}

function validateCommonRecipe(recipe, edge, target, label) {
  const probe = recipe.publicSurfaceProbe;
  const invocation = probe.invocation;
  requireCondition(recipe.status === "fully-executable", `${label}: not executable`);
  requireCondition(recipe.scenario === "absent", `${label}: not an absent scenario`);
  exactStrings(recipe.edgeIds, [edge.id], `${label}.edgeIds`);
  requireCondition(
    recipe.expectedObservation?.kind === "target-absence" &&
      recipe.expectedObservation.edgeId === edge.id,
    `${label}: expected observation does not bind the edge`,
  );
  requireCondition(
    probe.kind === "target-absence-probe",
    `${label}: expected a target-absence public probe`,
  );
  requireCondition(
    probe.surfaceObservedKey === recipe.terminalObservedKey,
    `${label}: probe selected another terminal`,
  );
  requireCondition(
    invocation?.expectedResult === "absent" &&
      invocation.expectedTypedDecisionCount === 0 &&
      Array.isArray(invocation.expectedTypedStages) &&
      invocation.expectedTypedStages.length === 0,
    `${label}: invocation does not prove a decision-free absent result`,
  );
  const expectedSourceDescriptorDigest = taggedDigest(invocation.sourceDescriptor);
  requireCondition(
    typeof invocation.sourceDescriptorDigest === "string" &&
      invocation.sourceDescriptorDigest === expectedSourceDescriptorDigest,
    `${label}: source descriptor digest drift (${invocation.sourceDescriptorDigest} != ${expectedSourceDescriptorDigest})`,
  );
  requireCondition(
    target?.triple === "aarch64-apple-darwin",
    `${label}: target-absence output projection is pinned to macOS/aarch64`,
  );
  return invocation;
}

function validateDedicatedTargetAbsence(invocation, edge, target, label) {
  requireCondition(
    invocation.kind === "target-absence" &&
      invocation.targetTriple === target.triple &&
      invocation.surfaceKind === edge.surface.kind &&
      invocation.surfaceName === edge.surface.name,
    `${label}: dedicated absence invocation selected another target or surface`,
  );
  exactStrings(
    invocation.allowedCoverageEdgeIds,
    [],
    `${label}.allowedCoverageEdgeIds`,
  );
  exactStrings(invocation.expectedActionIds, [], `${label}.expectedActionIds`);
  const descriptor = invocation.sourceDescriptor;
  const descriptorKind =
    edge.surface.kind === "host-abi"
      ? "target-absent-host-abi"
      : "target-absent-native-operation";
  requireCondition(
    descriptor?.kind === descriptorKind &&
      descriptor.surfaceKind === edge.surface.kind &&
      descriptor.surfaceName === edge.surface.name &&
      Array.isArray(descriptor.sourceRefs) &&
      descriptor.sourceRefs.length > 0 &&
      Array.isArray(descriptor.targetVariants) &&
      descriptor.targetVariants.length > 0 &&
      descriptor.targetVariants.every((variant) =>
        new Set(["android", "ios"]).has(variant),
      ),
    `${label}: dedicated absence source binding is incomplete`,
  );
}

function validateNativeGlobalAbsence(invocation, edge, label) {
  requireCondition(
    edge.surface.kind === "native-op" &&
      invocation.kind === "native-global-function" &&
      invocation.globalName === edge.surface.name &&
      invocation.sourceDescriptor?.kind === "native-global-function" &&
      invocation.sourceDescriptor.globalName === edge.surface.name &&
      typeof invocation.sourceDescriptor.sourceRef === "string" &&
      invocation.sourceDescriptor.sourceRef.length > 0,
    `${label}: native-global absence invocation selected another surface`,
  );
  exactStrings(
    invocation.allowedCoverageEdgeIds,
    [edge.id],
    `${label}.allowedCoverageEdgeIds`,
  );
}

/**
 * Return the exact output rows for which an already-authored public recipe
 * proves target absence. Each binding preserves enough recipe identity for a
 * loaded-engine executor to reuse the observation without fabricating it.
 */
export function authoredTargetAbsenceOutputBindings({
  catalog,
  recipeCatalog,
  coverage,
  target,
}) {
  requireCondition(Array.isArray(catalog?.rows), "output catalog has no rows");
  requireCondition(
    Array.isArray(recipeCatalog?.recipes),
    "recipe catalog has no recipes",
  );
  requireCondition(Array.isArray(coverage?.edges), "coverage registry has no edges");

  const edges = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  const catalogRows = new Map();
  for (const row of catalog.rows) {
    const rows = catalogRows.get(row.key.surfaceId) ?? [];
    rows.push(row);
    catalogRows.set(row.key.surfaceId, rows);
  }

  const bindings = [];
  const seenEdges = new Set();
  for (const recipe of recipeCatalog.recipes) {
    if (recipe.publicSurfaceProbe?.kind !== "target-absence-probe") continue;
    const label = `target-absence recipe ${recipe.fixtureId}`;
    requireCondition(
      Array.isArray(recipe.edgeIds) && recipe.edgeIds.length === 1,
      `${label}: expected one edge`,
    );
    const edge = edges.get(recipe.edgeIds[0]);
    requireCondition(edge, `${label}: unknown coverage edge`);
    requireCondition(
      !seenEdges.has(edge.id),
      `${label}: duplicate target-absence output edge`,
    );
    seenEdges.add(edge.id);

    const invocation = validateCommonRecipe(recipe, edge, target, label);
    if (invocation.invocationSchema === TARGET_ABSENCE_INVOCATION) {
      validateDedicatedTargetAbsence(invocation, edge, target, label);
    } else if (invocation.invocationSchema === NATIVE_GLOBAL_INVOCATION) {
      validateNativeGlobalAbsence(invocation, edge, label);
    } else {
      throw new Error(`${label}: unsupported absence invocation schema`);
    }

    const matchingRows = catalogRows.get(edge.id) ?? [];
    requireCondition(
      matchingRows.length === 1,
      `${label}: expected exactly one output-catalog row, got ${matchingRows.length}`,
    );
    const row = matchingRows[0];
    requireCondition(
      row.key.output === "[[return]]" &&
        row.key.alias === edge.surface.name &&
        row.key.mode === "all" &&
        row.key.sourceKind === edge.surface.kind &&
        row.key.returnVariant === "default",
      `${label}: output key does not name the exact surface return`,
    );
    requireCondition(
      row.discovery?.kind === "source-inventory-surface" &&
        Array.isArray(row.discovery.observedKeys) &&
        row.discovery.observedKeys.includes(recipe.terminalObservedKey) &&
        Array.isArray(row.discovery.sourceRefs) &&
        row.discovery.sourceRefs.length > 0,
      `${label}: catalog discovery does not bind the named surface`,
    );

    bindings.push({
      key: structuredClone(row.key),
      fixtureId: recipe.fixtureId,
      planDigest: recipe.planDigest,
      terminalObservedKey: recipe.terminalObservedKey,
      invocationSchema: invocation.invocationSchema,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
    });
  }

  return bindings.sort((left, right) =>
    compareText(
      canonicalOutputDispositionKey(left.key),
      canonicalOutputDispositionKey(right.key),
    ),
  );
}
