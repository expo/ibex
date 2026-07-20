import { describe, expect, test } from "bun:test";
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

  test("rejects relative paths, object, digest, architecture, feature, and shape drift", () => {
    for (const mutation of [
      { ...identity, engineArtifactPath: "relative/hermesvm" },
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

    const windowsArtifact = path.join(
      path.parse(process.cwd()).root,
      "repo",
      "hermes.dll",
    );
    const priorPath = path.join(path.parse(process.cwd()).root, "tools", "bun");
    const windowsEnvironment = engineLoaderEnvironment(windowsArtifact, {
      baseEnvironment: { Path: priorPath, SYSTEMROOT: "C:\\Windows" },
      platform: "win32",
    });
    expect(windowsEnvironment.Path).toBe(
      `${path.dirname(windowsArtifact)}${path.delimiter}${priorPath}`,
    );
    expect(Object.hasOwn(windowsEnvironment, "PATH")).toBe(false);
    expect(windowsEnvironment.SYSTEMROOT).toBe("C:\\Windows");
  });

  test("derives Windows volume and file identity from the mapped artifact", () => {
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

  test("binds a byte-equivalent staged engine to its mapped object", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-engine-stage-"));
    try {
      const selectedArtifact = path.join(directory, "selected-hermes.dll");
      const mappedArtifact = path.join(directory, "staged-hermes.dll");
      fs.writeFileSync(selectedArtifact, "same-hermes-binary");
      fs.copyFileSync(selectedArtifact, mappedArtifact);
      const canonicalSelected = fs.realpathSync(selectedArtifact);
      const canonicalMapped = fs.realpathSync(mappedArtifact);
      const metadata = fs.statSync(canonicalMapped, { bigint: true });
      const windowsTarget = {
        triple: "x86_64-pc-windows-msvc",
        features: [...target.features],
      };
      const stagedIdentity = {
        ...identity,
        engineArtifactPath: canonicalMapped,
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
          canonicalArtifactPath: canonicalSelected,
          binaryDigest: stagedIdentity.binaryDigest,
          target: windowsTarget,
        }),
      ).toEqual(stagedIdentity);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});
