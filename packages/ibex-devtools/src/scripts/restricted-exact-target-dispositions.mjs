/**
 * Resolve the LLP 0033 surface projection for one exact target.
 *
 * The generated projection records the conservative default disposition.
 * A definition may then narrow a candidate target with an explicit,
 * identity-bound override. No caller-provided target outside the candidate
 * roster can acquire an effective projection.
 */

import { canonicalJson, parseJsonStrict } from "./capsec-contract.mjs";

function targetKey(target) {
  return canonicalJson(target);
}

export function parseRestrictedProfileDefinition(rawDefinition) {
  return parseJsonStrict(rawDefinition, "restricted profile definition");
}

export function effectiveRestrictedProjectionRows({ projection, definition, target }) {
  const key = targetKey(target);
  if (!definition.candidateTargets.some((candidate) => targetKey(candidate) === key)) {
    throw new Error("restricted effective projection target is not a candidate");
  }
  const overrides = new Map();
  for (const override of definition.targetDispositionOverrides ?? []) {
    if (targetKey(override.target) !== key) continue;
    if (overrides.has(override.edgeId)) {
      throw new Error(`duplicate restricted target disposition override ${override.edgeId}`);
    }
    overrides.set(override.edgeId, override.disposition);
  }
  const projectedIds = new Set(projection.rows.map((row) => row[0]));
  for (const edgeId of overrides.keys()) {
    if (!projectedIds.has(edgeId)) {
      throw new Error(`restricted target disposition override names unknown edge ${edgeId}`);
    }
  }
  return projection.rows.map(([edgeId, disposition, evidence]) => [
    edgeId,
    overrides.get(edgeId) ?? disposition,
    evidence,
  ]);
}
