import fs from "node:fs";
import path from "node:path";
import { canonicalJson } from "./capsec-contract.mjs";

const IDENTITY_FIELDS = [
  "binaryDigest",
  "engineArtifactPath",
  "kind",
  "object",
  "structuralFeatures",
  "targetArchitecture",
];
const OBJECT_FIELDS = ["file", "platform", "volume"];
const OBJECT_PLATFORMS = new Set(["android", "apple", "unix", "windows"]);

function exactFields(value, fields) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalJson(Object.keys(value).sort()) === canonicalJson(fields)
  );
}

function artifactObjectIdentity(canonicalArtifactPath, target) {
  const triple = target?.triple ?? "";
  const metadata = fs.statSync(canonicalArtifactPath, { bigint: true });
  if (!metadata.isFile()) throw new Error("engine artifact is not a file");
  if (triple.includes("-windows-")) {
    return {
      platform: "windows",
      volume: `volume:${metadata.dev}`,
      file: `file:${metadata.ino}`,
    };
  }
  return {
    platform: triple.includes("-apple-")
      ? "apple"
      : triple.includes("-android")
        ? "android"
        : "unix",
    volume: `dev:${metadata.dev}`,
    file: `ino:${metadata.ino}`,
  };
}

export function validateLoadedEngineIdentity({
  identity,
  canonicalArtifactPath,
  binaryDigest,
  target,
  expectedObject,
}) {
  let mappedObject = expectedObject;
  try {
    if (mappedObject === undefined) {
      if (!fs.statSync(canonicalArtifactPath).isFile()) {
        throw new Error("selected engine artifact is not a file");
      }
      mappedObject = artifactObjectIdentity(identity?.engineArtifactPath, target);
    }
  } catch {
    throw new Error(
      "loaded engine identity does not bind the named artifact and exact target",
    );
  }
  const object = identity?.object;
  if (
    !exactFields(identity, IDENTITY_FIELDS) ||
    !path.isAbsolute(canonicalArtifactPath) ||
    !path.isAbsolute(identity.engineArtifactPath) ||
    identity.kind !== "hermes" ||
    identity.binaryDigest !== binaryDigest ||
    !/^sha256-[A-Za-z0-9_-]{43}$/u.test(identity.binaryDigest ?? "") ||
    identity.targetArchitecture !== target?.triple?.split("-")[0] ||
    canonicalJson(identity.structuralFeatures) !== canonicalJson(target?.features) ||
    !exactFields(object, OBJECT_FIELDS) ||
    canonicalJson(object) !== canonicalJson(mappedObject) ||
    !OBJECT_PLATFORMS.has(object.platform) ||
    typeof object.volume !== "string" ||
    object.volume.length === 0 ||
    typeof object.file !== "string" ||
    object.file.length === 0
  ) {
    throw new Error(
      "loaded engine identity does not bind the named artifact and exact target",
    );
  }
  return {
    engineArtifactPath: identity.engineArtifactPath,
    kind: identity.kind,
    binaryDigest: identity.binaryDigest,
    object: identity.object,
    targetArchitecture: identity.targetArchitecture,
    structuralFeatures: identity.structuralFeatures,
  };
}

export function engineLoaderEnvironment(
  enginePath,
  { baseEnvironment = process.env, platform = process.platform } = {},
) {
  const env = { ...baseEnvironment };
  const prepend = (name, directory) => {
    env[name] = env[name]
      ? `${directory}${path.delimiter}${env[name]}`
      : directory;
  };
  if (platform === "darwin") {
    let current = path.dirname(enginePath);
    while (current !== path.dirname(current)) {
      if (path.basename(current).endsWith(".framework")) {
        prepend("DYLD_FRAMEWORK_PATH", path.dirname(current));
        return env;
      }
      current = path.dirname(current);
    }
    throw new Error("macOS Hermes artifact is not inside a framework");
  }
  if (platform === "win32") {
    const pathNames = Object.keys(env).filter(
      (name) => name.toLowerCase() === "path",
    );
    if (pathNames.length > 1) {
      throw new Error("Windows loader environment has duplicate PATH keys");
    }
    prepend(pathNames[0] ?? "PATH", path.dirname(enginePath));
  } else prepend("LD_LIBRARY_PATH", path.dirname(enginePath));
  return env;
}
