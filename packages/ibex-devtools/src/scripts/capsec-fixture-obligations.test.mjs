// @ref LLP 0021#generated-semantic-datasets — implementation manifests cannot
// self-author the fixture obligations that permit target promotion.

import { describe, expect, test } from "bun:test";
import {
  absenceFixtureForTarget,
  fixtureObligationsForBranch,
} from "./capsec-fixture-obligations.mjs";

describe("capsec branch fixture obligations", () => {
  test("derives effect, conditional, and closed obligations from semantics", () => {
    expect(
      fixtureObligationsForBranch(
        { classification: "effects", effectMode: "conjunctive" },
        "edge.main",
      ),
    ).toEqual([
      "edge.main.allow",
      "edge.main.deny",
      "edge.main.malformed",
      "edge.main.missing-attribution",
      "edge.main.wrong-principal",
    ]);
    expect(
      fixtureObligationsForBranch(
        { classification: "effects", effectMode: "conditional-unrefined" },
        "edge.main",
      ),
    ).toContain("edge.main.conditional-refinement");
    expect(
      fixtureObligationsForBranch(
        {
          classification: "effects",
          effectMode: "conditional",
          logicalBranches: [
            { id: "read", effects: [{ cap: "fs:read" }] },
            { id: "none", effects: [] },
          ],
        },
        "edge.main",
      ),
    ).toEqual([
      "edge.main.logical.none.branch-selection",
      "edge.main.logical.none.malformed-branch-facts",
      "edge.main.logical.none.no-effect",
      "edge.main.logical.read.allow",
      "edge.main.logical.read.branch-selection",
      "edge.main.logical.read.deny",
      "edge.main.logical.read.malformed",
      "edge.main.logical.read.missing-attribution",
      "edge.main.logical.read.wrong-principal",
    ]);
    expect(
      fixtureObligationsForBranch({ classification: "closed" }, "edge.main"),
    ).toEqual(["edge.main.closed"]);
  });

  test("derives security-control and ordinary non-capability obligations", () => {
    expect(
      fixtureObligationsForBranch(
        {
          classification: "non-capability",
          rationaleId: "authority-control-plane",
        },
        "edge.main",
      ),
    ).toEqual([
      "edge.main.cannot-widen-authority",
      "edge.main.non-capability",
      "edge.main.post-lockdown-invariant",
    ]);
    expect(
      fixtureObligationsForBranch(
        { classification: "non-capability", rationaleId: "ordinary-time" },
        "edge.main",
      ),
    ).toEqual(["edge.main.non-capability"]);
  });

  test("binds absence evidence to the exact edge, triple, and feature set", () => {
    const fixture = absenceFixtureForTarget("edge.main", {
      triple: "aarch64-apple-darwin",
      features: ["native-lockdown", "hermes-frame-attribution"],
    });
    expect(fixture).toMatch(
      /^edge\.main\.target\.aarch64-apple-darwin\.[a-f0-9]{64}\.absent$/,
    );
    expect(fixture).toBe(
      absenceFixtureForTarget("edge.main", {
        triple: "aarch64-apple-darwin",
        features: ["hermes-frame-attribution", "native-lockdown"],
      }),
    );
    expect(
      absenceFixtureForTarget("edge.main", {
        triple: "aarch64-apple-darwin",
        features: ["a.b", "c"],
      }),
    ).not.toBe(
      absenceFixtureForTarget("edge.main", {
        triple: "aarch64-apple-darwin",
        features: ["a", "b.c"],
      }),
    );
  });
});
