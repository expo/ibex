import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schemaNames = [
  "app-bound-common-v1.schema.json",
  "application-binding-v1.schema.json",
  "restricted-worker-target-advertisement-v1.schema.json",
  "compile-plan-v2.schema.json",
  "package-provenance-v2.schema.json",
  "single-file-executable-v3.schema.json",
  "sfe-catalog-v2.schema.json",
  "stub-contract-v4.schema.json",
  "standalone-executable-info-v2.schema.json",
  "executable-inspection-v4.schema.json",
];
const schemaUrl = (name) => `https://ibex.dev/schemas/${name}`;
const digest = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

const loadSchemas = () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  for (const name of schemaNames) {
    const value = JSON.parse(fs.readFileSync(path.join(repoRoot, "schemas", name), "utf8"));
    ajv.addSchema(value, schemaUrl(name));
  }
  return ajv;
};

test("the complete app-bound schema profile compiles under strict draft 2020-12", () => {
  const ajv = loadSchemas();
  for (const name of schemaNames) assert.equal(typeof ajv.getSchema(schemaUrl(name)), "function", name);
});

test("application binding and target evidence objects are closed", () => {
  const ajv = loadSchemas();
  const binding = {
    schema: "ibex/app-bound-parent/1",
    origin: "https://example.test",
    appId: "example",
    engineCompatibility: [digest],
    brokerProtocols: ["ibex/restricted-worker-broker/1"],
    releaseLineage: {
      schema: "ibex/app-cli-release-lineage/1",
      publisherKeyId: "release-key-1",
      channel: "stable",
      recipeDigest: digest,
    },
  };
  const advertisement = {
    schema: "ibex/restricted-worker-target-advertisement/1",
    target: { triple: "aarch64-apple-darwin", minimumPlatform: "macos-14.0-arm64" },
    engineCompatibilityDigest: digest,
    nativeAbi: "ibex/restricted-worker-abi/1",
    languageProfile: "ibex/external-script-profile/1",
    languageProfileDigest: digest,
    workerPolicy: "ibex/restricted-external-worker-policy/1",
    workerPolicyDigest: digest,
    brokerProtocol: "ibex/restricted-worker-broker/1",
    globalInventoryDigest: digest,
    defaultsDigest: digest,
    maximaDigest: digest,
    evidence: {
      schema: "ibex/restricted-worker-target-evidence/1",
      suiteDigest: digest,
      engineArtifactDigest: digest,
      policyArtifactDigest: digest,
      brokerCorpusDigest: digest,
    },
  };
  const bindingValidator = ajv.getSchema(schemaUrl("application-binding-v1.schema.json"));
  const advertisementValidator = ajv.getSchema(schemaUrl("restricted-worker-target-advertisement-v1.schema.json"));
  assert.equal(bindingValidator(binding), true, JSON.stringify(bindingValidator.errors));
  assert.equal(advertisementValidator(advertisement), true, JSON.stringify(advertisementValidator.errors));
  assert.equal(bindingValidator({ ...binding, token: "forbidden" }), false);
  assert.equal(advertisementValidator({ ...advertisement, evidence: { ...advertisement.evidence, note: "forbidden" } }), false);
});
