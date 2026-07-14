/**
 * Normalize layered global installation evidence into executable target
 * branches.  A shared-runtime layer and a native layer are composed on the
 * same target; they are not mutually exclusive implementation alternatives.
 *
 * @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — the
 * implementation manifest must describe honest target branches and source
 * provenance before any target can be promoted from unsupported.
 */

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(compareText);
}

const STUB_DISPOSITIONS = new Set([
  "weak-fallback",
  "contains-weak-fallback",
  "not-structurally-proven",
]);

function normalizedInput(branch) {
  if (!branch || typeof branch !== "object") {
    throw new Error("installation branch must be an object");
  }
  if (typeof branch.route !== "string" || branch.route.length === 0) {
    throw new Error("installation branch route is absent");
  }
  if (
    typeof branch.targetVariant !== "string" ||
    branch.targetVariant.length === 0
  ) {
    throw new Error(`installation branch ${branch.route} target is absent`);
  }
  const sourceRefs = uniqueSorted(branch.sourceRefs ?? []);
  if (sourceRefs.length === 0) {
    throw new Error(`installation branch ${branch.route} has no source refs`);
  }
  if (
    branch.stubDisposition !== undefined &&
    !STUB_DISPOSITIONS.has(branch.stubDisposition)
  ) {
    throw new Error(
      `installation branch ${branch.route} has unreviewed stub disposition ${branch.stubDisposition}`,
    );
  }
  return {
    route: branch.route,
    routes: uniqueSorted(branch.routes ?? [branch.route]),
    sourceRefs,
    stubDisposition: branch.stubDisposition,
    targetVariant: branch.targetVariant,
  };
}

function composedStubDisposition(layers) {
  const dispositions = layers
    .map((layer) => layer.stubDisposition)
    .filter((value) => value !== undefined);
  if (dispositions.includes("not-structurally-proven")) {
    return "not-structurally-proven";
  }
  if (dispositions.includes("contains-weak-fallback")) {
    return "contains-weak-fallback";
  }
  if (dispositions.includes("weak-fallback")) {
    return dispositions.length === layers.length
      ? "weak-fallback"
      : "contains-weak-fallback";
  }
  return undefined;
}

function outputBranch(targetVariant, layers, branchKind) {
  const routes = uniqueSorted(layers.flatMap((layer) => layer.routes));
  const sourceRefs = uniqueSorted(layers.flatMap((layer) => layer.sourceRefs));
  const route =
    routes.length === 1 ? routes[0] : `composed:${routes.join("+")}`;
  const id = targetVariant;
  const stubDisposition = composedStubDisposition(layers);
  return {
    branchKind,
    id,
    kind: branchKind,
    route,
    routes,
    sourceRefs,
    ...(stubDisposition === undefined ? {} : { stubDisposition }),
    targetVariant,
  };
}

/**
 * `all` layers execute on every target. `default` is the fallback native
 * implementation when no more-specific target implementation is selected.
 * Every layer applicable to one target is merged into that target branch.
 */
export function normalizeComposedInstallationBranches(inputBranches) {
  if (!Array.isArray(inputBranches) || inputBranches.length === 0) return [];
  const branches = inputBranches.map(normalizedInput);
  const common = branches.filter((branch) => branch.targetVariant === "all");
  const byTarget = new Map();
  for (const branch of branches) {
    if (branch.targetVariant === "all") continue;
    const layers = byTarget.get(branch.targetVariant) ?? [];
    layers.push(branch);
    byTarget.set(branch.targetVariant, layers);
  }

  if (byTarget.size === 0) {
    return [outputBranch("all", common, "single")];
  }

  // A common-only fallback exists when target-specific layers are present but
  // no explicit default layer exists. This keeps an Android/Windows overlay
  // from pretending the shared layer vanishes on every other target.
  if (common.length > 0 && !byTarget.has("default")) {
    byTarget.set("default", []);
  }

  const targets = [...byTarget.keys()].sort(compareText);
  const branchKind = targets.length > 1 ? "alternative" : "single";
  return targets.map((targetVariant) =>
    outputBranch(
      targetVariant,
      [...common, ...(byTarget.get(targetVariant) ?? [])],
      branchKind,
    ),
  );
}
