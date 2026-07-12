import { describe, expect, test } from "bun:test";
import path from "node:path";
import {
  engineLoaderEnvironment,
  validateLoadedEngineIdentity,
} from "./capsec-engine-identity.mjs";

const target = {
  triple: "aarch64-apple-darwin",
  features: [
    "hermes-frame-attribution",
    "native-compartments",
    "native-lockdown",
  ],
};
const identity = {
  engineArtifactPath: "/repo/ios/Frameworks/hermesvm.framework/Versions/1/hermesvm",
  kind: "hermes",
  binaryDigest: `sha256-${"A".repeat(43)}`,
  object: { platform: "apple", volume: "dev:7", file: "ino:11" },
  targetArchitecture: "aarch64",
  structuralFeatures: [...target.features],
};
const validate = (candidate) =>
  validateLoadedEngineIdentity({
    identity: candidate,
    canonicalArtifactPath: identity.engineArtifactPath,
    binaryDigest: identity.binaryDigest,
    target,
    expectedObject: identity.object,
  });

describe("exact loaded engine identity", () => {
  test("projects the attested mapped object into a report binding", () => {
    expect(validate(identity)).toEqual({
      kind: "hermes",
      binaryDigest: identity.binaryDigest,
      object: identity.object,
      targetArchitecture: "aarch64",
      structuralFeatures: target.features,
    });
  });

  test("rejects path, object, digest, architecture, feature, and shape drift", () => {
    for (const mutation of [
      { ...identity, engineArtifactPath: "/different/hermesvm" },
      { ...identity, binaryDigest: `sha256-${"B".repeat(43)}` },
      { ...identity, object: { ...identity.object, file: "ino:12" } },
      { ...identity, targetArchitecture: "x86_64" },
      { ...identity, structuralFeatures: identity.structuralFeatures.slice(1) },
      { ...identity, invented: true },
    ]) {
      expect(() => validate(mutation)).toThrow(/does not bind/);
    }
  });

  test("derives platform loader search paths from the named artifact", () => {
    expect(
      engineLoaderEnvironment(identity.engineArtifactPath, {
        baseEnvironment: { DYLD_FRAMEWORK_PATH: "/prior" },
        platform: "darwin",
      }).DYLD_FRAMEWORK_PATH,
    ).toBe(`/repo/ios/Frameworks${path.delimiter}/prior`);
    expect(
      engineLoaderEnvironment("/opt/ibex/lib/libhermesvm.so", {
        baseEnvironment: {},
        platform: "linux",
      }).LD_LIBRARY_PATH,
    ).toBe("/opt/ibex/lib");
  });
});
