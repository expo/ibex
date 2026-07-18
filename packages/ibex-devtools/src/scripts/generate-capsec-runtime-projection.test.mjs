import { describe, expect, test } from "bun:test";

import {
  buildRuntimeProjection,
  renderRuntimeProjection,
} from "./generate-capsec-runtime-projection.mjs";

function fixtures() {
  const definitions = {
    definitionsSchema: "ibex/capsec-definitions/1",
    profile: "ibex/capsec/1",
    semanticCore: "capsec/semantics/1",
    definitions: [
      {
        id: "fs:read",
        lifecycle: "authorable",
        stability: "stable",
        globality: "resource",
        resourceKinds: ["path-exact"],
        selectorSchema: "selector/1",
        occurrenceSchema: "occurrence/1",
        normalizationProfile: "fs.v1",
        channels: { dynamic: true, handle: true, synthesis: true },
        staticOnly: false,
        risk: { baseTier: 2 },
        description: "review prose",
      },
    ],
  };
  const rules = {
    rulesSchema: "ibex/capsec-rules/1",
    profile: "ibex/capsec/1",
    semanticCore: "capsec/semantics/1",
    coreOwnership: { repository: "fixture" },
    cacheKeyFields: ["action"],
    classifierRules: {},
    decisionPrecedence: ["arm-validity"],
    decisionStrata: [],
    digestContract: {},
    dynamicAuthority: {},
    effectSemantics: {},
    execution: {
      durableMode: "enforce",
      auditWorkflow: "ibex capsec audit",
      contractFixtureWorkflow: "schema-only",
    },
    handles: {},
    initialProfile: {},
    normalizationProfiles: {},
    principalSemantics: {},
    resourceRules: {},
  };
  return { definitions, rules };
}

describe("CapSec runtime projection", () => {
  test("excludes review prose and command spelling", () => {
    const { definitions, rules } = fixtures();
    const baseline = renderRuntimeProjection(definitions, rules).digest;
    definitions.definitions[0].description = "new prose";
    definitions.definitions[0].risk.baseTier = 4;
    rules.execution.auditWorkflow = "renamed audit command";
    rules.coreOwnership.repository = "moved repository";
    expect(renderRuntimeProjection(definitions, rules).digest).toBe(baseline);
  });

  test("rotates when runtime decision semantics change", () => {
    const { definitions, rules } = fixtures();
    const baseline = renderRuntimeProjection(definitions, rules).digest;
    rules.decisionPrecedence.push("principal-denial");
    expect(renderRuntimeProjection(definitions, rules).digest).not.toBe(baseline);
  });

  test("rejects mismatched authorities", () => {
    const { definitions, rules } = fixtures();
    rules.semanticCore = "other/1";
    expect(() => buildRuntimeProjection(definitions, rules)).toThrow("disagree");
  });
});
