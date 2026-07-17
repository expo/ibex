#!/usr/bin/env bun
/**
 * Refresh the committed portable test-wrapper expression.
 *
 * @ref LLP 0002#gpu-bridge-seam
 * @ref LLP 0017#2-add-one-regenerate-command-and-one-drift-check
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";
import {
  REVIEWED_DIGESTS,
  renderWebGpuTestWrapper,
} from "./webgpu-test-wrapper-generator.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../../../..");
const authorityPath = "tests/fixtures/webgpu-test-wrapper-authority-v1.json";
const semanticsPath = "tests/fixtures/webgpu-test-wrapper-semantics-v1.json";
const outputPath = "tests/fixtures/webgpu-test-wrapper.generated.js";

function readAuthority() {
  const confined = assertConfinedGeneratedFile(
    repositoryRoot,
    authorityPath,
    "WebGPU test-wrapper normalized authority",
  );
  return JSON.parse(fs.readFileSync(confined.path, "utf8"));
}

function readSemantics() {
  const confined = assertConfinedGeneratedFile(
    repositoryRoot,
    semanticsPath,
    "WebGPU test-wrapper semantic authority",
  );
  return JSON.parse(fs.readFileSync(confined.path, "utf8"));
}

function main() {
  const authority = readAuthority();
  const semantics = readSemantics();
  const rendered = renderWebGpuTestWrapper(authority, semantics);
  if (process.argv.includes("--check")) {
    const confined = assertConfinedGeneratedFile(
      repositoryRoot,
      outputPath,
      "WebGPU generated test wrapper",
    );
    if (fs.readFileSync(confined.path, "utf8") !== rendered) {
      throw new Error(
        "generated test wrapper is stale; run bun run generate:webgpu-test-wrapper",
      );
    }
    console.log(
      "webgpu-test-wrapper-generation: 25/25 routes fresh at normalized projection " +
        REVIEWED_DIGESTS.projection,
    );
    return;
  }
  writeGeneratedFilesTransactionally(repositoryRoot, [
    {
      path: outputPath,
      content: rendered,
      label: "WebGPU generated test wrapper",
    },
  ]);
  console.log(
    "webgpu-test-wrapper-generation: wrote " +
      outputPath +
      " from normalized projection " +
      REVIEWED_DIGESTS.projection,
  );
}

try {
  main();
} catch (error) {
  console.error(
    "webgpu-test-wrapper-generation: " +
      (error instanceof Error ? error.message : String(error)),
  );
  process.exitCode = 1;
}
