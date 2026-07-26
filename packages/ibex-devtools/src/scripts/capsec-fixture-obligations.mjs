/**
 * Derive the complete fixture obligation set from semantic coverage and an
 * exact implementation branch identity. The implementation manifest records
 * this result but cannot author or weaken it.
 *
 * @ref LLP 0021#generated-semantic-datasets — only executed fixtures can
 * promote a target cell, and every selected branch must satisfy the semantic
 * edge's independently derived obligation set.
 */

import crypto from "node:crypto";

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalStringSet(values) {
  return [...new Set(values)].sort(compareText);
}

export function fixtureObligationsForBranch(edge, branchId) {
  if (edge.classification === "effects") {
    if (edge.effectMode === "conditional") {
      return canonicalStringSet(
        edge.logicalBranches.flatMap((logicalBranch) => {
          const prefix = `${branchId}.logical.${logicalBranch.id}`;
          if (logicalBranch.disposition === "closed") {
            return [
              `${prefix}.branch-selection`,
              `${prefix}.closed`,
            ];
          }
          if (logicalBranch.effects.length === 0) {
            // @ref LLP 0036#the-unresolved-catalog-split-into-two-provable-categories
            // — branch predicates are admitted registry metadata, not
            // per-surface runtime facts; execute selection and no-effect,
            // while malformed predicate shape remains a registry-contract
            // refusal rather than an invented public invocation.
            return [
              `${prefix}.branch-selection`,
              `${prefix}.no-effect`,
            ];
          }
          return [
            `${prefix}.allow`,
            `${prefix}.branch-selection`,
            `${prefix}.deny`,
            `${prefix}.malformed`,
            `${prefix}.missing-attribution`,
            `${prefix}.wrong-principal`,
          ];
        }),
      );
    }
    const obligations = [
      `${branchId}.allow`,
      `${branchId}.deny`,
      `${branchId}.malformed`,
      `${branchId}.missing-attribution`,
      `${branchId}.wrong-principal`,
    ];
    if (edge.effectMode === "conditional-unrefined") {
      obligations.push(`${branchId}.conditional-refinement`);
    }
    return canonicalStringSet(obligations);
  }
  if (edge.classification === "closed") {
    return canonicalStringSet([
      `${branchId}.closed`,
      ...(edge.logicalBranches ?? []).flatMap((logicalBranch) => {
        const prefix = `${branchId}.logical.${logicalBranch.id}`;
        return [
          `${prefix}.branch-selection`,
          `${prefix}.no-effect`,
        ];
      }),
    ]);
  }
  if (edge.rationaleId === "callback-attribution-carrier") {
    return canonicalStringSet([
      `${branchId}.attribution-missing-deny`,
      `${branchId}.generation-recheck`,
      `${branchId}.principal-restore`,
      `${branchId}.snapshot-mismatch-deny`,
      `${branchId}.non-capability`,
    ]);
  }
  if (edge.rationaleId === "authority-control-plane") {
    return canonicalStringSet([
      `${branchId}.cannot-widen-authority`,
      `${branchId}.non-capability`,
      `${branchId}.post-lockdown-invariant`,
    ]);
  }
  if (edge.classification === "non-capability") {
    return [`${branchId}.non-capability`];
  }
  throw new Error(
    `${branchId}: cannot derive fixtures for classification ${edge.classification}`,
  );
}

export function absenceFixtureForTarget(edgeId, target) {
  if (typeof edgeId !== "string" || edgeId.length === 0) {
    throw new Error("target absence fixture requires an edge id");
  }
  if (typeof target?.triple !== "string" || !Array.isArray(target.features)) {
    throw new Error(
      `${edgeId}: target absence fixture requires an exact target`,
    );
  }
  const canonicalTarget = JSON.stringify([
    target.triple,
    canonicalStringSet(target.features),
  ]);
  const targetDigest = crypto
    .createHash("sha256")
    .update(canonicalTarget, "utf8")
    .digest("hex");
  return `${edgeId}.target.${target.triple}.${targetDigest}.absent`;
}
