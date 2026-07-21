import { describe, expect, test } from "bun:test";
import path from "node:path";

import { capsecRoot, readJsonStrict } from "./capsec-contract.mjs";
import { effectiveRestrictedProjectionRows } from "./restricted-exact-target-dispositions.mjs";

const definition = readJsonStrict(path.join(
  capsecRoot,
  "registry/restricted-exact-profile-definition.json",
));
const projection = readJsonStrict(path.join(
  capsecRoot,
  "generated/restricted-exact-profile-projection.json",
));
const edgeId = "surface.native.op.global.intl.numberformat.prototype.formattoparts.1ogrg4u";

function dispositionFor(target) {
  return effectiveRestrictedProjectionRows({ projection, definition, target })
    .find((row) => row[0] === edgeId)[1];
}

describe("LLP 0033 target-effective restricted dispositions", () => {
  test("requires Apple absence and Linux invocation for the divergent Intl edge", () => {
    expect(dispositionFor(definition.candidateTargets[0])).toBe("structurally-absent");
    expect(dispositionFor(definition.candidateTargets[1])).toBe("reachable");
  });

  test("rejects a caller-invented target", () => {
    expect(() => dispositionFor({
      triple: "x86_64-unknown-other",
      features: definition.candidateTargets[1].features,
    })).toThrow("not a candidate");
  });
});
