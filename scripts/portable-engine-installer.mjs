// Production-safe portable engine installer boundary. Injectable dependencies
// and context objects are intentionally unavailable from this module.
//
// @ref LLP 0035#threat-model-and-trust-roots — production callers derive
// authority from the checked checkout and fixed offline verifier, never from
// caller-supplied implementations.

import {
  installPortableEngineProductionCore,
  verifyPortableEngineStoreProductionCore,
} from "./portable-engine-installer-core.mjs";

function exactOptions(input, allowed, required, label) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error(`${label}: expected one options object`);
  const fields = Object.keys(input).sort();
  for (const field of fields) if (!allowed.includes(field)) throw new Error(`${label}: unknown option ${field}`);
  for (const field of required) if (!Object.prototype.hasOwnProperty.call(input, field)) throw new Error(`${label}: missing option ${field}`);
  return Object.freeze(Object.fromEntries(fields.map((field) => [field, input[field]])));
}

export async function installPortableEngine(options) {
  if (arguments.length !== 1) throw new Error("installPortableEngine accepts exactly one production options object");
  return await installPortableEngineProductionCore(exactOptions(
    options,
    ["archivePath", "bundlePath", "expectedSourceRevision", "repoRoot"],
    ["archivePath", "bundlePath", "expectedSourceRevision"],
    "installPortableEngine",
  ));
}

export async function verifyPortableEngineStore(options) {
  if (arguments.length !== 1) throw new Error("verifyPortableEngineStore accepts exactly one production options object");
  return await verifyPortableEngineStoreProductionCore(exactOptions(
    options,
    ["archiveDigest", "artifactId", "expectedSourceRevision", "repoRoot"],
    ["artifactId", "expectedSourceRevision"],
    "verifyPortableEngineStore",
  ));
}
