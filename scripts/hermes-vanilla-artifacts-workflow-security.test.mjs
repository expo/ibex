// @ref LLP 0067#5-the-engine-and-the-artifacts — native builders hand inert
// bytes to a default-branch publisher; only that publisher has release/OIDC
// authority.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const builderWorkflow = readFileSync(
  join(repoRoot, ".github/workflows/hermes-vanilla-build.yml"),
  "utf8",
);
const publisherWorkflow = readFileSync(
  join(repoRoot, ".github/workflows/hermes-vanilla-publish.yml"),
  "utf8",
);

const builders = [
  "macos_arm64",
  "macos_x86_64",
  "ios_device",
  "ios_simulator",
  "linux_x86_64",
  "linux_arm64",
  "windows_x64",
];

function jobBlocks(workflow) {
  const jobsStart = workflow.indexOf("\njobs:\n");
  assert.notEqual(jobsStart, -1, "workflow must have a jobs mapping");
  const jobsText = workflow.slice(jobsStart + 1);
  const headers = [...jobsText.matchAll(/^  ([a-z][a-z0-9_]*):\n/gm)];
  return new Map(headers.map((header, index) => [
    header[1],
    jobsText.slice(header.index, headers[index + 1]?.index ?? jobsText.length),
  ]));
}

function stepBlocks(job) {
  const headers = [...job.matchAll(/^      - name: (.+)\n/gm)];
  return headers.map((header, index) => ({
    name: header[1],
    text: job.slice(header.index, headers[index + 1]?.index ?? job.length),
  }));
}

function permissions(job) {
  const match = job.match(/^    permissions:\n((?:      [a-z-]+: [a-z]+\n)+)/m);
  assert.ok(match, "job must declare explicit permissions");
  return Object.fromEntries(
    match[1].trim().split("\n").map((line) => line.trim().split(": ")),
  );
}

function blockScalar(workflow, key) {
  const marker = `      ${key}: |\n`;
  const start = workflow.indexOf(marker);
  assert.notEqual(start, -1, `missing ${key} block scalar`);
  const body = [];
  for (const line of workflow.slice(start + marker.length).split("\n")) {
    if (line !== "" && !line.startsWith("        ")) break;
    body.push(line.startsWith("        ") ? line.slice(8) : "");
  }
  return body.join("\n");
}

test("read-only builders are separated from the default-branch publisher", () => {
  assert.deepEqual([...jobBlocks(builderWorkflow).keys()], builders);
  assert.deepEqual([...jobBlocks(publisherWorkflow).keys()], ["publish"]);
  assert.match(builderWorkflow, /^permissions: \{\}$/m);
  assert.match(publisherWorkflow, /^permissions: \{\}$/m);

  const builderTrigger = builderWorkflow.slice(0, builderWorkflow.indexOf("\njobs:\n"));
  assert.match(builderTrigger, /\non:\n  workflow_dispatch:\n/);
  assert.doesNotMatch(builderTrigger, /\n  (?:pull_request_target|workflow_run):/);

  const publisherTrigger = publisherWorkflow.slice(0, publisherWorkflow.indexOf("\njobs:\n"));
  assert.match(publisherTrigger, /\non:\n  workflow_run:\n/);
  assert.match(publisherTrigger, /workflows: \[Hermes vanilla release builder\]/);
  assert.match(publisherTrigger, /types: \[completed\]/);
  assert.doesNotMatch(publisherTrigger, /\n  (?:push|pull_request|workflow_dispatch):/);

  for (const [name, builder] of jobBlocks(builderWorkflow)) {
    assert.deepEqual(permissions(builder), { contents: "read" }, `${name} is read-only`);
    assert.doesNotMatch(builder, /\$\{\{\s*secrets\.|^\s+GH_TOKEN:/m);
    assert.doesNotMatch(builder, /actions\/download-artifact|actions\/attest-build-provenance|gh release/);
    assert.doesNotMatch(builder, /^\s+(?:actions|attestations|contents|id-token): write$/m);
    const checkout = stepBlocks(builder).find((step) => step.text.includes("actions/checkout@"));
    assert.ok(checkout, `${name} checks out source`);
    assert.match(checkout.text, /\n          persist-credentials: false\n/);
    const uploads = stepBlocks(builder).filter((step) => step.text.includes("actions/upload-artifact@"));
    assert.equal(uploads.length, 1, `${name} emits one handoff`);
    assert.match(uploads[0].text, /\n          archive: false\n/);
    assert.match(uploads[0].text, /\n          if-no-files-found: error\n/);
    assert.match(uploads[0].text, /\n          overwrite: false\n/);
  }

  const publisher = jobBlocks(publisherWorkflow).get("publish");
  assert.deepEqual(permissions(publisher), {
    actions: "read",
    attestations: "write",
    contents: "write",
    "id-token": "write",
  });
  assert.match(publisher, /github\.event\.workflow_run\.conclusion == 'success'/);
  assert.match(publisher, /github\.event\.workflow_run\.head_branch == 'main'/);
  assert.match(publisher, /github\.event\.workflow_run\.event == 'workflow_dispatch'/);
  assert.match(publisher, /github\.event\.workflow_run\.head_repository\.full_name == github\.repository/);
  assert.match(publisher, /gh api "repos\/\$GITHUB_REPOSITORY\/commits\/main" --jq \.sha/);
  assert.match(publisher, /"\$SOURCE_SHA" != "\$main_sha"/);
  assert.doesNotMatch(publisher, /actions\/checkout|uses: \.\/|scripts\//);
  assert.doesNotMatch(publisher, /\b(?:unzip|Expand-Archive)\b|\btar\s+-/);

  const downloads = stepBlocks(publisher).filter((step) => step.text.includes("actions/download-artifact@"));
  assert.equal(downloads.length, builders.length);
  for (const download of downloads) {
    assert.match(download.text, /\n          run-id: \$\{\{ github\.event\.workflow_run\.id \}\}\n/);
    assert.match(download.text, /\n          github-token: \$\{\{ github\.token \}\}\n/);
    assert.match(download.text, /\n          repository: \$\{\{ github\.repository \}\}\n/);
    assert.match(download.text, /\n          skip-decompress: true\n/);
    assert.match(download.text, /\n          digest-mismatch: error\n/);
  }

  const attestations = stepBlocks(publisher).filter((step) => step.text.includes("actions/attest-build-provenance@"));
  assert.equal(attestations.length, builders.length);
  for (const attestation of attestations) {
    assert.match(attestation.text, /\n          subject-name: \$\{\{ steps\.validate_[a-z0-9_]+\.outputs\.asset_name \}\}\n/);
    assert.match(attestation.text, /\n          subject-digest: sha256:\$\{\{ steps\.validate_[a-z0-9_]+\.outputs\.asset_sha256 \}\}\n/);
    assert.doesNotMatch(attestation.text, /subject-path:/);
  }

  assert.match(publisher, /gh release create "\$RELEASE_TAG"/);
  assert.match(publisher, /--target "\$SOURCE_SHA"/);
  assert.match(publisher, /gh api "repos\/\$GITHUB_REPOSITORY\/git\/ref\/tags\/\$RELEASE_TAG"/);
  assert.match(publisher, /--draft \\/);
  assert.match(publisher, /gh release upload "\$RELEASE_TAG" "\$RELEASE_DIR"\/\*/);
  assert.match(publisher, /releases\/\$release_id\/assets\?per_page=100/);
  assert.match(publisher, /remote release asset names are not the exact local set/);
  assert.match(publisher, /remote asset digest mismatch/);
  assert.match(publisher, /gh release edit "\$RELEASE_TAG"/);
  assert.match(publisher, /--draft=false \\/);
  assert.match(publisher, /--prerelease \\/);
  assert.match(publisher, /gh api --method DELETE "repos\/\$GITHUB_REPOSITORY\/releases\/\$existing_id"/);
  assert.doesNotMatch(publisher, /gh release delete|--clobber|git\/refs\/tags.*--method DELETE/);
});

test("every action reference is an approved full commit SHA", () => {
  const approved = new Set([
    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be",
    "ilammy/msvc-dev-cmd@0b201ec74fa43914dc39ae48a89fd1d8cb592756",
  ]);
  const references = [...`${builderWorkflow}\n${publisherWorkflow}`.matchAll(/^\s+uses: ([^\s#]+)/gm)]
    .map((match) => match[1]);
  assert.ok(references.length > 0);
  for (const reference of references) {
    assert.match(reference, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/);
    assert.ok(approved.has(reference), `unapproved action reference: ${reference}`);
  }
});

test("release namespace is pinned to the sole Hermes source authority", () => {
  const version = readFileSync(join(repoRoot, "scripts/hermes-version.sh"), "utf8");
  const commit = version.match(/IBEX_HERMES_VANILLA_SOURCE_COMMIT="\$\{IBEX_HERMES_VANILLA_SOURCE_COMMIT:-([0-9a-f]{40})\}"/)?.[1];
  assert.ok(commit);
  for (const workflow of [builderWorkflow, publisherWorkflow]) {
    assert.match(workflow, new RegExp(`^  HERMES_COMMIT: ${commit}$`, "m"));
    assert.match(workflow, new RegExp(`^  RELEASE_TAG: hermes-vanilla-${commit.slice(0, 12)}-v1$`, "m"));
    assert.match(workflow, new RegExp(`^  group: hermes-vanilla-${commit.slice(0, 12)}-v1`, "m"));
  }
});

const validator = blockScalar(publisherWorkflow, "HANDOFF_VALIDATOR");

function runValidator(setup) {
  const temporary = mkdtempSync(join(tmpdir(), "hermes-vanilla-handoff-test-"));
  const handoff = join(temporary, "handoff");
  mkdirSync(handoff);
  const artifactName = "hermes-vanilla-handoff-test-target";
  const assetName = "hermes-vanilla-test-target.tar.gz";
  const bytes = Buffer.from("inert archive bytes");
  writeFileSync(join(handoff, assetName), bytes);
  const digest = createHash("sha256").update(bytes).digest("hex");
  const artifactsFile = join(temporary, "artifacts.json");
  writeFileSync(artifactsFile, JSON.stringify([{ artifacts: [{
    name: artifactName,
    digest: `sha256:${digest}`,
    size_in_bytes: bytes.length,
    expired: false,
  }] }]));
  setup?.({ temporary, handoff, artifactName, assetName, bytes, artifactsFile });
  const output = join(temporary, "output");
  const result = spawnSync("python3", ["-c", validator], {
    encoding: "utf8",
    env: {
      ...process.env,
      EXPECTED_ARTIFACT_NAME: artifactName,
      EXPECTED_ASSET_NAME: assetName,
      ARTIFACTS_FILE: artifactsFile,
      HANDOFF_DIR: handoff,
      GITHUB_OUTPUT: output,
    },
  });
  rmSync(temporary, { recursive: true, force: true });
  return result;
}

test("publisher accepts exactly one named regular archive with matching bytes", () => {
  const result = runValidator();
  assert.equal(result.status, 0, result.stderr);
});

test("publisher rejects extra entries, symlinks, and changed bytes", () => {
  const extra = runValidator(({ handoff }) => writeFileSync(join(handoff, "extra"), "x"));
  assert.notEqual(extra.status, 0);

  const linked = runValidator(({ temporary, handoff, assetName }) => {
    rmSync(join(handoff, assetName));
    const outside = join(temporary, "outside");
    writeFileSync(outside, "inert archive bytes");
    symlinkSync(outside, join(handoff, assetName));
  });
  assert.notEqual(linked.status, 0);

  const changed = runValidator(({ handoff, assetName }) => writeFileSync(join(handoff, assetName), "changed"));
  assert.notEqual(changed.status, 0);
});
