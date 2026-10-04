// @ref LLP 0067#5-the-engine-and-the-artifacts — native builders hand inert
// bytes to a checkout-free publisher; only that publisher has release/OIDC
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
const workflow = readFileSync(
  join(repoRoot, ".github/workflows/hermes-vanilla-artifacts.yml"),
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

function jobBlocks() {
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

function blockScalar(key) {
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

test("workflow isolates seven read-only builders from one checkout-free publisher", () => {
  const jobs = jobBlocks();
  assert.deepEqual([...jobs.keys()], [...builders, "publish"]);
  assert.match(workflow, /^permissions: \{\}$/m);
  const trigger = workflow.slice(0, workflow.indexOf("\njobs:\n"));
  assert.match(trigger, /\non:\n  workflow_dispatch:\n/);
  assert.doesNotMatch(trigger, /\n  (?:push|pull_request|workflow_run):/);

  for (const name of builders) {
    const builder = jobs.get(name);
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
    assert.match(builder, /artifact_id: \$\{\{ steps\.handoff\.outputs\.artifact-id \}\}/);
    assert.match(builder, /artifact_digest: \$\{\{ steps\.handoff\.outputs\.artifact-digest \}\}/);
  }

  const publisher = jobs.get("publish");
  assert.deepEqual(permissions(publisher), {
    actions: "read",
    attestations: "write",
    contents: "write",
    "id-token": "write",
  });
  assert.doesNotMatch(publisher, /actions\/checkout|uses: \.\/|scripts\//);
  assert.doesNotMatch(publisher, /\b(?:unzip|Expand-Archive)\b|\btar\s+-/);
  assert.doesNotMatch(publisher, /^    (?:container|services|environment):/m);

  const downloads = stepBlocks(publisher).filter((step) => step.text.includes("actions/download-artifact@"));
  assert.equal(downloads.length, builders.length);
  for (const download of downloads) {
    assert.match(download.text, /\n          artifact-ids: \$\{\{ needs\.[a-z0-9_]+\.outputs\.artifact_id \}\}\n/);
    assert.match(download.text, /\n          skip-decompress: true\n/);
    assert.match(download.text, /\n          digest-mismatch: error\n/);
    assert.doesNotMatch(download.text, /\n          (?:github-token|repository|run-id|name|pattern|merge-multiple):/);
  }

  const attestations = stepBlocks(publisher).filter((step) => step.text.includes("actions/attest-build-provenance@"));
  assert.equal(attestations.length, builders.length);
  for (const attestation of attestations) {
    assert.match(attestation.text, /\n          subject-name: \$\{\{ needs\.[a-z0-9_]+\.outputs\.asset_name \}\}\n/);
    assert.match(attestation.text, /\n          subject-digest: sha256:\$\{\{ needs\.[a-z0-9_]+\.outputs\.asset_sha256 \}\}\n/);
    assert.doesNotMatch(attestation.text, /subject-path:/);
  }

  assert.match(publisher, /gh release create "\$RELEASE_TAG"/);
  assert.match(publisher, /release .* already exists; immutable releases are never edited/);
  assert.doesNotMatch(publisher, /gh release (?:edit|upload|delete)|--clobber|--method DELETE/);
});

test("every action reference is an approved full commit SHA", () => {
  const approved = new Set([
    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be",
    "ilammy/msvc-dev-cmd@0b201ec74fa43914dc39ae48a89fd1d8cb592756",
  ]);
  const references = [...workflow.matchAll(/^\s+uses: ([^\s#]+)/gm)].map((match) => match[1]);
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
  assert.match(workflow, new RegExp(`^  HERMES_COMMIT: ${commit}$`, "m"));
  assert.match(workflow, new RegExp(`^  RELEASE_TAG: hermes-vanilla-${commit.slice(0, 12)}-v1$`, "m"));
  assert.match(workflow, new RegExp(`^  group: hermes-vanilla-${commit.slice(0, 12)}-v1$`, "m"));
});

const validator = blockScalar("HANDOFF_VALIDATOR");

function runValidator(setup) {
  const temporary = mkdtempSync(join(tmpdir(), "hermes-vanilla-handoff-test-"));
  const handoff = join(temporary, "handoff");
  mkdirSync(handoff);
  const name = "hermes-vanilla-test-target.tar.gz";
  const bytes = Buffer.from("inert archive bytes");
  writeFileSync(join(handoff, name), bytes);
  setup?.({ temporary, handoff, name, bytes });
  const expected = createHash("sha256").update(bytes).digest("hex");
  const result = spawnSync("python3", ["-c", validator], {
    encoding: "utf8",
    env: {
      ...process.env,
      EXPECTED_NAME: name,
      EXPECTED_SHA256: expected,
      EXPECTED_SIZE: String(bytes.length),
      HANDOFF_DIR: handoff,
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

  const linked = runValidator(({ temporary, handoff, name }) => {
    rmSync(join(handoff, name));
    const outside = join(temporary, "outside");
    writeFileSync(outside, "inert archive bytes");
    symlinkSync(outside, join(handoff, name));
  });
  assert.notEqual(linked.status, 0);

  const changed = runValidator(({ handoff, name }) => writeFileSync(join(handoff, name), "changed"));
  assert.notEqual(changed.status, 0);
});
