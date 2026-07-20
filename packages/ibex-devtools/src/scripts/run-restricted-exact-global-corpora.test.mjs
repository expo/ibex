import { describe, expect, test } from "bun:test";

import { restrictedGlobalCorpusPlan } from "./run-restricted-exact-global-corpora.mjs";

describe("LLP 0033 restricted global corpus runner", () => {
  test("locks all five preregistered corpora to exact native fixtures", () => {
    expect(restrictedGlobalCorpusPlan.map((row) => row.id)).toEqual([
      "artifact-tamper",
      "hostile-lifecycle",
      "loader-and-bridge-absence",
      "profile-confusion",
      "teardown",
    ]);
    expect(restrictedGlobalCorpusPlan.every((row) => row.tests.length >= 2)).toBe(true);
    expect(restrictedGlobalCorpusPlan.flatMap((row) => row.tests)).toContain(
      "restricted_exact_absence_edges_close_source_and_live_routes",
    );
    expect(restrictedGlobalCorpusPlan.flatMap((row) => row.tests)).toContain(
      "restricted_exact_control_plane_edges_enforce_lifecycle_refusals",
    );
    expect(restrictedGlobalCorpusPlan.flatMap((row) => row.tests)).toContain(
      "restricted_exact_teardown_drains_admitted_completion_and_refuses_stale_generation",
    );
  });
});
