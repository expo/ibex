#!/usr/bin/env node
/**
 * Fail-loud Node 24.13.1 versus real Ibex/Hermes conformance runner for the
 * generated, test-only WebGPU wrapper expression.
 *
 * @ref LLP 0019#the-enforced-conformance-seam
 * @ref LLP 0026#compatibility-contract-and-conformance-corpus
 */

import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  webGpuTestWrapperCorpus,
  webGpuTestWrapperMarker,
} from "./webgpu-test-wrapper-corpus.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../../../..");
const generatedWrapperPath = path.join(
  repositoryRoot,
  "tests/fixtures/webgpu-test-wrapper.generated.js",
);

function parseArguments(argv) {
  let ibex = "";
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--ibex") {
      ibex = argv[++index] || "";
    } else {
      throw new Error("unknown argument: " + argv[index]);
    }
  }
  if (!ibex) throw new Error("--ibex /path/to/ibex is required");
  return { ibex: path.resolve(process.cwd(), ibex) };
}

function pinnedNodeVersion() {
  const identity = JSON.parse(
    readFileSync(path.join(repositoryRoot, "runtime-identity.json"), "utf8"),
  );
  return String(identity?.versions?.node || "");
}

function standaloneProgram() {
  const expression = readFileSync(generatedWrapperPath, "utf8").trim();
  return (
    "var createHarness = " +
    expression +
    ";\nvar runCorpus = (" +
    webGpuTestWrapperCorpus.toString() +
    ");\nrunCorpus(createHarness).then(function (result) {\n" +
    "  console.log(" +
    JSON.stringify(webGpuTestWrapperMarker) +
    " + JSON.stringify(result));\n" +
    "}, function (error) {\n" +
    "  console.error(\"webgpu-test-wrapper-corpus-error:\", error && error.stack ? error.stack : String(error));\n" +
    "  throw error;\n" +
    "});\n"
  );
}

function run(command, arguments_, cwd, environment) {
  const result = spawnSync(command, arguments_, {
    cwd,
    env: { ...process.env, ...environment },
    encoding: "utf8",
    timeout: 60_000,
  });
  if (result.error) throw result.error;
  return result;
}

function markerPayload(result, runtime) {
  if (result.status !== 0) {
    throw new Error(
      runtime +
        " exited " +
        result.status +
        " (signal " +
        (result.signal || "none") +
        ")\nstdout:\n" +
        result.stdout +
        "\nstderr:\n" +
        result.stderr,
    );
  }
  const lines = String(result.stdout || "")
    .split(/\r?\n/u)
    .filter((line) => line.startsWith(webGpuTestWrapperMarker));
  if (lines.length !== 1) {
    throw new Error(
      runtime +
        " emitted " +
        lines.length +
        " corpus markers\nstdout:\n" +
        result.stdout +
        "\nstderr:\n" +
        result.stderr,
    );
  }
  const payload = lines[0].slice(webGpuTestWrapperMarker.length);
  JSON.parse(payload);
  return payload;
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  const expectedNode = pinnedNodeVersion();
  if (process.versions.node !== expectedNode || expectedNode !== "24.13.1") {
    throw new Error(
      "wrong Node oracle: runtime-identity.json pins " +
        expectedNode +
        ", runner is " +
        process.versions.node,
    );
  }

  const temporaryDirectory = mkdtempSync(
    path.join(os.tmpdir(), "ibex-webgpu-test-wrapper-"),
  );
  try {
    const entry = path.join(temporaryDirectory, "corpus.js");
    writeFileSync(entry, standaloneProgram());
    const node = run(process.execPath, [entry], temporaryDirectory, {});
    const ibex = run(
      options.ibex,
      ["capsec", "audit", entry],
      temporaryDirectory,
      {
        EXACT_COMPAT_TEST: "1",
        IBEX_SKIP_AGENT_SKILLS_SYNC: "1",
      },
    );
    const nodePayload = markerPayload(node, "Node oracle");
    const ibexPayload = markerPayload(ibex, "Ibex/Hermes");
    if (nodePayload !== ibexPayload) {
      throw new Error(
        "Node/Ibex corpus observations differ\nNode: " +
          nodePayload +
          "\nIbex: " +
          ibexPayload,
      );
    }
    const summary = JSON.parse(nodePayload);
    if (
      summary.schema !== "ibex/webgpu-test-wrapper-corpus-result/1" ||
      summary.operationCount !== 25 ||
      summary.terminalCount !== 17 ||
      !Number.isSafeInteger(summary.assertionCount) ||
      summary.assertionCount < 1000 ||
      summary.conditionalProviderBranches?.providerBranches !== 4 ||
      summary.conditionalProviderBranches?.noProviderBranches !== 4
    ) {
      throw new Error("corpus returned an empty or malformed summary");
    }
    console.log(
      "webgpu-test-wrapper conformance: 1/1 corpus matched Node 24.13.1 and real Ibex/Hermes (" +
        summary.assertionCount +
        " assertions, 25 operations, 17 requestDevice terminals)",
    );
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(
    "webgpu-test-wrapper conformance: " +
      (error instanceof Error ? error.stack || error.message : String(error)),
  );
  process.exitCode = 1;
}
