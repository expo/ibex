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
).replaceAll("\r\n", "\n");
const publisherWorkflow = readFileSync(
  join(repoRoot, ".github/workflows/hermes-vanilla-publish.yml"),
  "utf8",
).replaceAll("\r\n", "\n");
const receiptWriter = readFileSync(join(repoRoot, "scripts/hermes-input-receipt.mjs"), "utf8");
const localAppleBuilder = readFileSync(join(repoRoot, "scripts/build-hermes.sh"), "utf8");
const localLinuxBuilder = readFileSync(join(repoRoot, "scripts/build-hermes-linux.sh"), "utf8");
const releaseBuilder = readFileSync(
  join(repoRoot, "scripts/build-hermes-vanilla-release.sh"),
  "utf8",
);
const windowsReleaseBuilder = readFileSync(
  join(repoRoot, "scripts/build-hermes-windows-vanilla-release.ps1"),
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

function foldedJson(workflow, key) {
  const match = workflow.match(new RegExp(`^      ${key}: >-\\n((?:        .*\\n)+)`, "m"));
  assert.ok(match, `missing ${key} folded scalar`);
  return JSON.parse(match[1].split("\n").map((line) => line.trim()).join(" "));
}

function builderArchiveBasenames(workflow) {
  return [...workflow.matchAll(
    /^\s+(?:asset_name=|\$assetName = ")(hermes-vanilla-[a-z0-9_.-]+\.tar\.gz)"?$/gm,
  )].map((match) => match[1]);
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

  const archiveNames = builderArchiveBasenames(builderWorkflow);
  assert.equal(archiveNames.length, builders.length);
  assert.equal(new Set(archiveNames).size, builders.length, "builder archive basenames are unique");
  assert.deepEqual(foldedJson(publisherWorkflow, "EXPECTED_ARTIFACT_NAMES"), archiveNames);
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
    assert.doesNotMatch(uploads[0].text, /\n          name:/);
    assert.match(uploads[0].text, /\n          archive: false\n/);
    assert.match(uploads[0].text, /\n          if-no-files-found: error\n/);
    assert.match(uploads[0].text, /\n          overwrite: false\n/);
    assert.match(builder, /ARCHIVE_SHA256: \$\{\{ steps\.package\.outputs\.asset_sha256 \}\}/);
    assert.match(builder, /HANDOFF_DIGEST: \$\{\{ steps\.handoff\.outputs\.artifact-digest \}\}/);
    if (name === "windows_x64") {
      assert.match(builder, /\$env:HANDOFF_DIGEST -ne \$env:ARCHIVE_SHA256/);
    } else {
      assert.match(builder, /\[\[ "\$HANDOFF_DIGEST" == "\$ARCHIVE_SHA256" \]\]/);
    }
  }
  const windowsBuilder = jobBlocks(builderWorkflow).get("windows_x64");
  assert.match(windowsBuilder, /Microsoft Visual Studio\\Installer\\vswhere\.exe/);
  assert.match(windowsBuilder, /VC\\Auxiliary\\Build\\vcvarsall\.bat/);
  assert.match(windowsBuilder, /"`"\$vcvarsall`" x64 >nul && set"/);
  assert.doesNotMatch(windowsBuilder, /ilammy\/msvc-dev-cmd/);

  const publisher = jobBlocks(publisherWorkflow).get("publish");
  assert.deepEqual(permissions(publisher), {
    actions: "read",
    attestations: "write",
    contents: "write",
    "id-token": "write",
  });
  assert.match(publisher, /^    environment: hermes-vanilla-release$/m);
  assert.doesNotMatch(publisher, /\$\{\{\s*secrets\.|^\s+[A-Z0-9_]*SECRET[A-Z0-9_]*:/m);
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
  const downloadNames = [];
  for (const download of downloads) {
    const artifactName = download.text.match(
      /\n          name: (hermes-vanilla-[a-z0-9_.-]+\.tar\.gz)\n/,
    )?.[1];
    assert.ok(artifactName, "download names an archive basename");
    downloadNames.push(artifactName);
    assert.match(download.text, /\n          run-id: \$\{\{ github\.event\.workflow_run\.id \}\}\n/);
    assert.match(download.text, /\n          github-token: \$\{\{ github\.token \}\}\n/);
    assert.match(download.text, /\n          repository: \$\{\{ github\.repository \}\}\n/);
    assert.match(download.text, /\n          skip-decompress: true\n/);
    assert.match(download.text, /\n          digest-mismatch: error\n/);
  }
  assert.deepEqual(downloadNames, archiveNames);

  const attestations = stepBlocks(publisher).filter((step) => step.text.includes("actions/attest-build-provenance@"));
  assert.equal(attestations.length, builders.length);
  for (const attestation of attestations) {
    assert.match(attestation.text, /\n          subject-name: \$\{\{ steps\.validate_[a-z0-9_]+\.outputs\.asset_name \}\}\n/);
    assert.match(attestation.text, /\n          subject-digest: sha256:\$\{\{ steps\.validate_[a-z0-9_]+\.outputs\.asset_sha256 \}\}\n/);
    assert.doesNotMatch(attestation.text, /subject-path:/);
  }

  const validations = stepBlocks(publisher).filter((step) => step.name.startsWith("Validate "));
  assert.equal(validations.length, builders.length);
  for (const validation of validations) {
    assert.match(validation.text, /run: python3 -c "\$HANDOFF_VALIDATOR"/);
  }

  // The runner context is unavailable in workflow- and job-level env; using
  // it there makes GitHub reject the whole workflow file.
  const jobEnv = publisher.slice(publisher.indexOf("\n    env:\n"), publisher.indexOf("\n    steps:\n"));
  assert.ok(jobEnv.length > 0, "publisher has a job-level env block");
  assert.doesNotMatch(jobEnv, /runner\./);
  assert.doesNotMatch(publisherWorkflow.slice(0, publisherWorkflow.indexOf("\njobs:\n")), /runner\./);
  // The draft is created through the API and addressed by its returned id
  // from then on; listing right after a write can miss it.
  assert.match(publisher, /gh api --method POST "repos\/\$GITHUB_REPOSITORY\/releases"/);
  assert.match(publisher, /-f target_commitish="\$SOURCE_SHA"/);
  assert.match(publisher, /created draft does not carry the requested tag, target, and marker/);
  assert.doesNotMatch(publisher, /gh release (create|upload|edit)/);
  assert.match(publisher, /gh api "repos\/\$GITHUB_REPOSITORY\/git\/ref\/tags\/\$RELEASE_TAG"/);
  assert.match(publisher, /DRAFT_MARKER="\$DRAFT_MARKER_PREFIX source-sha=\$SOURCE_SHA -->"/);
  assert.match(publisher, /-F draft=true \\/);
  assert.match(publisher, /https:\/\/uploads\.github\.com\/repos\/\$GITHUB_REPOSITORY\/releases\/\$release_id\/assets/);
  assert.match(publisher, /releases\/\$release_id\/assets\?per_page=100/);
  assert.match(publisher, /remote release asset names are not the exact local set/);
  assert.match(publisher, /remote asset digest mismatch/);
  assert.match(publisher, /gh api --method PATCH "repos\/\$GITHUB_REPOSITORY\/releases\/\$release_id"/);
  assert.match(publisher, /-F draft=false \\/);
  assert.match(publisher, /-F prerelease=true \\/);
  // An existing release, draft or published, is refused and never adopted.
  assert.match(publisher, /if \[\[ "\$existing_count" != 0 \]\]; then\n\s+echo "::error::a release named/);
  assert.doesNotMatch(publisher, /releases\/assets\/\$asset_id|--method DELETE/);
  // What was published is verified again: assets, immutability, and the tag.
  const publish = publisher.indexOf("-F draft=false \\");
  const finalAssetCheck = publisher.lastIndexOf("\n          fetch_and_verify_assets\n");
  assert.ok(publish !== -1 && finalAssetCheck > publish, "assets are re-verified after publication");
  assert.equal(publisher.split("\n          fetch_and_verify_assets\n").length, 3);
  assert.match(publisher, /release\.get\("immutable"\) is not True/);
  assert.match(publisher, /tag\.get\("type"\) != "commit" or tag\.get\("sha"\) != os\.environ\["SOURCE_SHA"\]/);
  const releaseLookup = publisher.indexOf(
    '"repos/$GITHUB_REPOSITORY/releases?per_page=100" > "$releases_file"',
  );
  const absentTagCheck = publisher.search(/^\s+require_absent_tag$/m);
  assert.notEqual(releaseLookup, -1, "publisher first looks for a release by tag");
  assert.notEqual(absentTagCheck, -1, "new-draft path checks tag absence");
  assert.ok(releaseLookup < absentTagCheck, "existing releases are refused before tag absence");
  assert.doesNotMatch(
    publisher,
    /--method DELETE\s+(?:\\\n\s+)?"repos\/\$GITHUB_REPOSITORY\/releases\/\$existing_id"/,
  );
  assert.doesNotMatch(publisher, /gh release delete|--clobber|git\/refs\/tags.*--method DELETE/);
});

test("every action reference is an approved full commit SHA", () => {
  const approved = new Set([
    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be",
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
    assert.match(workflow, new RegExp(`^  RELEASE_TAG: hermes-vanilla-${commit.slice(0, 12)}-v2$`, "m"));
    assert.match(workflow, new RegExp(`^  group: hermes-vanilla-${commit.slice(0, 12)}-v2`, "m"));
  }
});

test("release receipts bind both VM archives and keep the full VM as engine.binary", () => {
  assert.match(receiptWriter, /const engineBinary = inside\(bundleDir, requestedEngineArchive/);
  assert.match(receiptWriter, /const symbols = exportedSymbols\(engineBinary\)/);
  assert.match(receiptWriter, /const enginePath = canonicalRelative\(bundleDir, engineBinary\)/);
  assert.doesNotMatch(receiptWriter, /preferredEngineNames/);

  for (const [name, producer, archive] of [
    ["local Apple", localAppleBuilder, "--engine-archive macos-static/libhermesvm_a.a"],
    ["local Linux", localLinuxBuilder, "--engine-archive linux-static/libhermesvm_a.a"],
    ["Unix release", releaseBuilder, "--engine-archive lib/libhermesvm_a.a"],
    ["Windows release", windowsReleaseBuilder, "--engine-archive=lib/hermesvm_a.lib"],
  ]) {
    assert.ok(producer.includes(archive), `${name} producer does not name its full VM archive`);
    assert.match(producer, /link-directive=rustc-link-lib=static=hermesvm_a/);
  }
  assert.match(releaseBuilder, /--target hermesvm_a hermesvmlean_a/);
  assert.match(releaseBuilder, /--lean-engine-archive lib\/libhermesvmlean_a\.a/);
  assert.match(windowsReleaseBuilder, /--target hermesvmlean_a/);
  assert.match(windowsReleaseBuilder, /--lean-engine-archive=lib\/hermesvmlean_a\.lib/);
  assert.match(receiptWriter, /lean engine archive is not present in the archive manifest/);
});

const validator = blockScalar(publisherWorkflow, "HANDOFF_VALIDATOR");

test("publisher validator cross-binds every artifact digest to its archive SHA-256", () => {
  assert.match(validator, /artifact_digest = digest\.removeprefix\("sha256:"\)/);
  assert.match(validator, /if artifact_digest != asset_sha256:/);
  assert.match(validator, /raise SystemExit\("artifact_digest does not equal asset_sha256"\)/);
});

function runValidator(setup, environment = {}) {
  const temporary = mkdtempSync(join(tmpdir(), "hermes-vanilla-handoff-test-"));
  const handoff = join(temporary, "handoff");
  mkdirSync(handoff);
  const assetName = "hermes-vanilla-test-target.tar.gz";
  const artifactName = assetName;
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
  try {
    setup?.({ temporary, handoff, artifactName, assetName, bytes, artifactsFile });
    const output = join(temporary, "output");
    const python = process.platform === "win32" ? "python" : "python3";
    const result = spawnSync(python, ["-c", validator], {
      encoding: "utf8",
      env: {
        ...process.env,
        EXPECTED_ARTIFACT_NAME: artifactName,
        EXPECTED_ASSET_NAME: assetName,
        ARTIFACTS_FILE: artifactsFile,
        HANDOFF_DIR: handoff,
        GITHUB_OUTPUT: output,
        ...environment,
      },
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, null, `${python} did not exit normally: ${result.signal}`);
    return result;
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

test("publisher accepts exactly one named regular archive with matching bytes", () => {
  const result = runValidator();
  assert.equal(result.status, 0, result.stderr);
});

test("publisher rejects traversal and newline archive names", () => {
  const traversal = runValidator(undefined, {
    EXPECTED_ASSET_NAME: "../hermes-vanilla-test-target.tar.gz",
  });
  assert.notEqual(traversal.status, 0);

  const newline = runValidator(undefined, {
    EXPECTED_ASSET_NAME: "hermes-vanilla-test\ntarget.tar.gz",
  });
  assert.notEqual(newline.status, 0);
});

test("publisher rejects empty digests, zero sizes, and digest mismatches", () => {
  function changeArtifact(field, value) {
    return ({ artifactsFile }) => {
      const pages = JSON.parse(readFileSync(artifactsFile, "utf8"));
      pages[0].artifacts[0][field] = value;
      writeFileSync(artifactsFile, JSON.stringify(pages));
    };
  }

  const emptyDigest = runValidator(changeArtifact("digest", ""));
  assert.notEqual(emptyDigest.status, 0);

  const zeroSize = runValidator(changeArtifact("size_in_bytes", 0));
  assert.notEqual(zeroSize.status, 0);

  const mismatchedDigest = runValidator(changeArtifact("digest", `sha256:${"0".repeat(64)}`));
  assert.notEqual(mismatchedDigest.status, 0);
});

test("publisher rejects extra entries and changed bytes", () => {
  const extra = runValidator(({ handoff }) => writeFileSync(join(handoff, "extra"), "x"));
  assert.notEqual(extra.status, 0);

  const changed = runValidator(({ handoff, assetName }) => writeFileSync(join(handoff, assetName), "changed"));
  assert.notEqual(changed.status, 0);
});

test("publisher rejects an actual symlink archive", (t) => {
  try {
    const linked = runValidator(({ temporary, handoff, assetName }) => {
      rmSync(join(handoff, assetName));
      const outside = join(temporary, "outside");
      writeFileSync(outside, "inert archive bytes");
      symlinkSync(outside, join(handoff, assetName));
    });
    assert.notEqual(linked.status, 0);
  } catch (error) {
    if (process.platform === "win32" && error.syscall === "symlink"
        && ["EPERM", "EACCES"].includes(error.code)) {
      t.skip(`Windows symlink creation privilege unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
});
