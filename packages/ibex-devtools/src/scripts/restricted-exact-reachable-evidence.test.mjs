import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "bun:test";

import { capsecRoot } from "./capsec-contract.mjs";
import { ingestRestrictedAbsenceEvidence } from "./restricted-exact-absence-evidence.mjs";
import { ingestRestrictedControlEvidence } from "./restricted-exact-control-evidence.mjs";
import { ingestRestrictedGlobalCorporaEvidence } from "./restricted-exact-global-corpora-evidence.mjs";
import { ingestRestrictedReachableEvidence } from "./restricted-exact-reachable-evidence.mjs";

const evidenceRoot = path.join(capsecRoot, "conformance/evidence/restricted-exact");
const evidencePath = path.join(evidenceRoot, "reachable-aarch64-apple-darwin-04a08eeb.json");
const controlEvidencePath = path.join(evidenceRoot, "control-aarch64-apple-darwin-04a08eeb.json");
const absenceEvidencePath = path.join(evidenceRoot, "absence-aarch64-apple-darwin-04a08eeb.json");
const corpusEvidencePath = path.join(evidenceRoot, "global-corpora-aarch64-apple-darwin-04a08eeb.json");

describe("LLP 0033 restricted evidence invalidation", () => {
  test("invalidates every evidence family predating the per-edge probe plan", () => {
    expect(() => ingestRestrictedReachableEvidence(
      fs.readFileSync(evidencePath),
    )).toThrow("restricted authority changed after evidence");
    expect(() => ingestRestrictedControlEvidence(
      fs.readFileSync(controlEvidencePath),
    )).toThrow("restricted authority changed after evidence");
    expect(() => ingestRestrictedAbsenceEvidence(
      fs.readFileSync(absenceEvidencePath),
    )).toThrow("restricted authority changed after evidence");
    expect(() => ingestRestrictedGlobalCorporaEvidence(
      fs.readFileSync(corpusEvidencePath),
      fs.readFileSync(evidencePath),
    )).toThrow("restricted authority changed after evidence");
  });
});
