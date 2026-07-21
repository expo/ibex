import { describe, expect, test } from "bun:test";

import { restrictedGlobalCorpusPlan } from "./run-restricted-exact-global-corpora.mjs";

describe("LLP 0033 restricted global corpus runner", () => {
  test("locks all six preregistered corpora to exact native fixtures", () => {
    expect(restrictedGlobalCorpusPlan.map((row) => row.id)).toEqual([
      "artifact-tamper",
      "hostile-lifecycle",
      "loader-and-bridge-absence",
      "observer-equivalence",
      "profile-confusion",
      "teardown",
    ]);
    expect(restrictedGlobalCorpusPlan
      .filter((row) => row.id !== "observer-equivalence")
      .every((row) => row.tests.length >= 2)).toBe(true);
    expect(restrictedGlobalCorpusPlan
      .find((row) => row.id === "observer-equivalence")?.tests).toEqual([]);
    expect(restrictedGlobalCorpusPlan.find((row) => row.id === "artifact-tamper")?.tests).toEqual([
      "restricted_exact_builder_binds_one_immutable_candidate_bundle",
      "restricted_exact_builder_uses_embedder_owned_private_cache",
      "restricted_exact_builder_rejects_non_private_cache_roots",
      "restricted_exact_builder_rejects_format_and_engine_confusion",
    ]);
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
