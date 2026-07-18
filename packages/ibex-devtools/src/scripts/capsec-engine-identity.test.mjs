import { describe, expect, test } from "bun:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
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
      engineArtifactPath: identity.engineArtifactPath,
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
        baseEnvironment: { ld_library_path: "/case-sensitive" },
        platform: "linux",
      }).LD_LIBRARY_PATH,
    ).toBe("/opt/ibex/lib");
    expect(
      engineLoaderEnvironment("/opt/ibex/lib/libhermesvm.so", {
        baseEnvironment: { ld_library_path: "/case-sensitive" },
        platform: "linux",
      }).ld_library_path,
    ).toBe("/case-sensitive");
    const windowsEnvironment = engineLoaderEnvironment(
      "/opt/ibex/bin/hermesvm.dll",
      {
        baseEnvironment: { Path: "/runner/bin", PATH: "/ambiguous" },
        platform: "win32",
      },
    );
    expect(windowsEnvironment.Path).toBe(
      `/opt/ibex/bin${path.delimiter}/runner/bin`,
    );
    expect(windowsEnvironment.PATH).toBeUndefined();
  });

  test("derives Windows volume and file identity from the named artifact", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-engine-"));
    try {
      const artifact = path.join(directory, "hermes.dll");
      fs.writeFileSync(artifact, "hermes");
      const canonicalArtifactPath = fs.realpathSync(artifact);
      const metadata = fs.statSync(canonicalArtifactPath, { bigint: true });
      const windowsTarget = {
        triple: "x86_64-pc-windows-msvc",
        features: [...target.features],
      };
      const windowsIdentity = {
        ...identity,
        engineArtifactPath: canonicalArtifactPath,
        object: {
          platform: "windows",
          volume: `volume:${metadata.dev}`,
          file: `file:${metadata.ino}`,
        },
        targetArchitecture: "x86_64",
      };
      expect(
        validateLoadedEngineIdentity({
          identity: windowsIdentity,
          canonicalArtifactPath,
          binaryDigest: windowsIdentity.binaryDigest,
          target: windowsTarget,
        }),
      ).toEqual(windowsIdentity);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  test("binds a Windows staged DLL replica to the selected artifact bytes", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-engine-"));
    try {
      const selectedDirectory = path.join(directory, "selected");
      const stagedDirectory = path.join(directory, "target", "debug", "deps");
      fs.mkdirSync(selectedDirectory, { recursive: true });
      fs.mkdirSync(stagedDirectory, { recursive: true });
      const selectedArtifact = path.join(selectedDirectory, "hermesvm.dll");
      const stagedArtifact = path.join(stagedDirectory, "hermesvm.dll");
      fs.writeFileSync(selectedArtifact, "exact Hermes Release bytes");
      fs.copyFileSync(selectedArtifact, stagedArtifact);
      const canonicalSelectedArtifact = fs.realpathSync(selectedArtifact);
      const canonicalStagedArtifact = fs.realpathSync(stagedArtifact);
      const metadata = fs.statSync(canonicalStagedArtifact, { bigint: true });
      const binaryDigest = `sha256-${crypto
        .createHash("sha256")
        .update(fs.readFileSync(canonicalSelectedArtifact))
        .digest("base64url")}`;
      const windowsTarget = {
        triple: "x86_64-pc-windows-msvc",
        features: [...target.features],
      };
      const stagedIdentity = {
        ...identity,
        engineArtifactPath: canonicalStagedArtifact,
        binaryDigest,
        object: {
          platform: "windows",
          volume: `volume:${metadata.dev}`,
          file: `file:${metadata.ino}`,
        },
        targetArchitecture: "x86_64",
      };
      expect(
        validateLoadedEngineIdentity({
          identity: stagedIdentity,
          canonicalArtifactPath: canonicalSelectedArtifact,
          binaryDigest,
          target: windowsTarget,
        }),
      ).toEqual(stagedIdentity);

      fs.writeFileSync(stagedArtifact, "different Hermes bytes");
      expect(() =>
        validateLoadedEngineIdentity({
          identity: stagedIdentity,
          canonicalArtifactPath: canonicalSelectedArtifact,
          binaryDigest,
          target: windowsTarget,
        }),
      ).toThrow(/does not bind/);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});
