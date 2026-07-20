import { describe, expect, test } from "bun:test";

import { buildCompiledEnvironmentProfile } from "./generate-compiled-environment-profile.mjs";

function fixture() {
  return {
    config: {
      schema: "ibex/compiled-environment-profile-config/1",
      allowlistDecision: { status: "blocked-on-author-decision-2", names: [] },
      intentionalApplicationBehaviorNames: ["TERM"],
      dynamicConsumerDispositions: {
        "startup:env:<dynamic>:rust:env::vars": "capture-primitive",
      },
    },
    manifest: {
      implementationManifestSchema: "ibex/capsec-implementation/1",
      status: "complete",
      surfaces: [
        {
          observedKey: "startup:env:TERM",
          branchId: "term.main",
          sourceRefs: ["tty.js#process.env:TERM:read"],
        },
        {
          observedKey: "startup:env:NODE_ENV",
          branchId: "node-env.main",
          sourceRefs: ["crypto.ts#process.env:NODE_ENV:read"],
        },
        {
          observedKey: "startup:env:<dynamic>:rust:env::vars",
          branchId: "capture.main",
          sourceRefs: ["runtime.rs#env::vars"],
        },
      ],
    },
  };
}

describe("compiled environment profile", () => {
  test("defaults exact controls closed and preserves reviewed app behavior", () => {
    const { config, manifest } = fixture();
    const profile = buildCompiledEnvironmentProfile(config, manifest);
    expect(profile.releaseEligible).toBe(false);
    expect(profile.consumers.map(({ observedKey, disposition }) => [observedKey, disposition])).toEqual([
      ["startup:env:<dynamic>:rust:env::vars", "capture-primitive"],
      ["startup:env:NODE_ENV", "privileged-control"],
      ["startup:env:TERM", "application-behavior"],
    ]);
  });

  test("fails closed on an unclassified dynamic consumer", () => {
    const { config, manifest } = fixture();
    manifest.surfaces.push({
      observedKey: "startup:env:<dynamic>:cpp:getenv",
      branchId: "getenv.main",
      sourceRefs: ["runtime.cc#getenv"],
    });
    expect(() => buildCompiledEnvironmentProfile(config, manifest)).toThrow("classification drift");
  });

  test("requires the author decision before restoring any real environment name", () => {
    const { config, manifest } = fixture();
    config.allowlistDecision.names = ["TERM"];
    expect(() => buildCompiledEnvironmentProfile(config, manifest)).toThrow("undecided");
  });
});
