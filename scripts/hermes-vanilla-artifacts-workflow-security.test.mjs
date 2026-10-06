// @ref LLP 0067#5-the-engine-and-the-artifacts — native builders hand inert
// bytes to a default-branch publisher; only that publisher has release/OIDC
// authority.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
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
const icuVersion = readFileSync(join(repoRoot, "scripts/icu-version.sh"), "utf8");
const icuFilter = readFileSync(join(repoRoot, "scripts/icu74-filter-root-en.json"));
const localAppleBuilder = readFileSync(join(repoRoot, "scripts/build-hermes.sh"), "utf8");
const localLinuxBuilder = readFileSync(join(repoRoot, "scripts/build-hermes-linux.sh"), "utf8");
const localWindowsBuilder = readFileSync(
  join(repoRoot, "scripts/build-hermes-windows-vanilla.ps1"),
  "utf8",
);
const releaseBuilder = readFileSync(
  join(repoRoot, "scripts/build-hermes-vanilla-release.sh"),
  "utf8",
);
const linuxContainerBuilder = readFileSync(
  join(repoRoot, "scripts/build-hermes-vanilla-linux-container.sh"),
  "utf8",
);
const linuxContainerBody = readFileSync(
  join(repoRoot, "scripts/build-hermes-vanilla-linux-in-container.sh"),
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
  "tvos_device",
  "tvos_simulator",
  "linux_x86_64",
  "linux_arm64",
  "windows_x64",
];

test("Linux VM artifacts use pinned ICU 74 with trimmed and full data", () => {
  assert.match(localLinuxBuilder, /-DHERMES_ENABLE_INTL=false/);
  assert.match(localLinuxBuilder, /-DHERMES_UNICODE_LITE=false/);
  assert.match(localLinuxBuilder, /-DHERMES_USE_STATIC_ICU=true/);
  assert.doesNotMatch(localLinuxBuilder, /-DHERMES_ENABLE_INTL=true/);
  assert.match(releaseBuilder, /else\n  icu_filter=/);
  assert.match(releaseBuilder, /-DHERMES_ENABLE_INTL=false\n    -DHERMES_UNICODE_LITE=false\n    -DHERMES_USE_STATIC_ICU=true/);
  assert.match(releaseBuilder, /if \[\[ "\$host_os" == Darwin \]\]; then\n  build_flags\+=\(\n    -DHERMES_ENABLE_INTL=true/);
  for (const producer of [localLinuxBuilder, releaseBuilder]) {
    assert.match(producer, /libicudata-full\.a/);
    assert.match(producer, /icu74-filter-root-en\.json/);
    assert.match(producer, /--icu-trimmed-data-archive=/);
    assert.match(producer, /--icu-full-data-archive=/);
    assert.match(producer, /--icu-trimmed-filter=/);
    assert.match(producer, /ibex_verify_icu_data_variants/);
  }
  assert.match(
    linuxContainerBuilder,
    /^container_image='rust:1\.97-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97'$/m,
  );
  assert.match(linuxContainerBuilder, /--platform "\$platform"/);
  assert.match(linuxContainerBuilder, /^  "\$container_image" \\$/m);
  assert.match(linuxContainerBody, /build-hermes-vanilla-release\.sh/);
  assert.doesNotMatch(linuxContainerBody, /libicu-dev/);
  assert.doesNotMatch(linuxContainerBody, /(?:deb|security)\.debian\.org/);
  assert.match(linuxContainerBody, /snapshot_timestamp=20261005T000000Z/);
  assert.match(
    linuxContainerBody,
    /snapshot\.debian\.org\/archive\/debian\/\$\{snapshot_timestamp\}/,
  );
  assert.match(
    linuxContainerBody,
    /snapshot\.debian\.org\/archive\/debian-security\/\$\{snapshot_timestamp\}/,
  );
  assert.match(linuxContainerBody, /rm -f \/etc\/apt\/sources\.list\.d\/debian\.sources/);
  for (const pinnedPackage of [
    "build-essential=12.9",
    "ca-certificates=20250419~deb12u1",
    "cmake=3.25.1-1",
    "git=1:2.39.5-0+deb12u3",
    "libreadline-dev=8.2-1.3",
    "libtinfo-dev=6.4-4",
    "locales=2.36-9+deb12u14",
    "ninja-build=1.11.1-2~deb12u1",
    "nodejs=18.20.4+dfsg-1~deb12u3",
    "pkg-config=1.8.1-1",
    "python3=3.11.2-1+b1",
    "python3-jsonschema=4.10.3-1",
    "zlib1g-dev=1:1.2.13.dfsg-1",
  ]) {
    assert.ok(linuxContainerBody.includes(pinnedPackage), `${pinnedPackage} is pinned`);
  }
  assert.match(releaseBuilder, /\(\( jobs <= 4 \)\) \|\| jobs=4/);
  assert.match(releaseBuilder, /-DCMAKE_JOB_POOLS=link_pool=2/);
  assert.match(localLinuxBuilder, /\(\( jobs <= 4 \)\) \|\| jobs=4/);
  assert.match(localLinuxBuilder, /-DCMAKE_JOB_POOLS=link_pool=2/);
  assert.equal(
    createHash("sha256").update(icuFilter).digest("hex"),
    icuVersion.match(/IBEX_ICU_TRIMMED_FILTER_SHA256="\$\{IBEX_ICU_TRIMMED_FILTER_SHA256:-([0-9a-f]{64})\}"/)?.[1],
  );
  assert.match(icuVersion, /IBEX_ICU_SOURCE_REF="\$\{IBEX_ICU_SOURCE_REF:-release-74-2\}"/);
  assert.match(icuVersion, /IBEX_ICU_SOURCE_COMMIT="\$\{IBEX_ICU_SOURCE_COMMIT:-2d029329c82c7792b985024b2bdab5fc7278fbc8\}"/);
  for (const job of ["linux_x86_64", "linux_arm64"].map((name) => jobBlocks(builderWorkflow).get(name))) {
    assert.match(job, /build-hermes-vanilla-linux-container\.sh/);
    assert.doesNotMatch(job, /libicu-dev/);
  }
});

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

  // Every handoff must also be retained, and the assembled and uploaded set
  // sizes must move with the builder list (archive + Sigstore bundle per
  // builder, then SHA256SUMS).
  const retained = [...publisher.matchAll(/^          retain ([a-z0-9_-]+) "\$[A-Z0-9_]+_NAME" "\$[A-Z0-9_]+_BUNDLE"$/gm)].map((m) => m[1]);
  assert.deepEqual(retained, builders.map((builder) => builder.replace("_", "-")));
  const assembled = builders.length * 2;
  assert.match(publisher, new RegExp(`if len\\(files\\) != ${assembled} or`));
  assert.match(publisher, new RegExp(`wc -l \\| tr -d ' '\\)" = ${assembled + 1}\n`));
  assert.match(publisher, new RegExp(`if len\\(local\\) != ${assembled + 1}:`));

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
    assert.match(workflow, new RegExp(`^  RELEASE_TAG: hermes-vanilla-${commit.slice(0, 12)}-v4$`, "m"));
    assert.match(workflow, new RegExp(`^  group: hermes-vanilla-${commit.slice(0, 12)}-v4`, "m"));
  }
});

test("tvOS jobs mirror the iOS handoff boundary and build arm64 MinSizeRel targets", () => {
  const tvosDevice = jobBlocks(builderWorkflow).get("tvos_device");
  const tvosSimulator = jobBlocks(builderWorkflow).get("tvos_simulator");
  for (const job of [tvosDevice, tvosSimulator]) {
    assert.match(job, /^    runs-on: macos-15-xlarge$/m);
    assert.deepEqual(permissions(job), { contents: "read" });
  }
  assert.match(tvosDevice, /build-hermes-vanilla-release\.sh aarch64-apple-tvos /);
  assert.match(tvosSimulator, /build-hermes-vanilla-release\.sh aarch64-apple-tvos-simulator /);
  assert.match(releaseBuilder, /aarch64-apple-tvos\)\n(?:    .*\n)*    platform=appletvos; target_arches=arm64; deployment_target=15\.0; profile=min-size-release/);
  assert.match(releaseBuilder, /aarch64-apple-tvos-simulator\)\n(?:    .*\n)*    platform=appletvsimulator; target_arches=arm64; deployment_target=15\.0; profile=min-size-release/);
  assert.doesNotMatch(releaseBuilder, /platform=appletvsimulator; target_arches=[^;]*x86_64/);
});

test("release receipts bind both VM archives and keep the full VM as engine.binary", () => {
  assert.match(receiptWriter, /const engineBinary = inside\(bundleDir, requestedEngineArchive/);
  assert.match(receiptWriter, /const symbols = exportedSymbols\(engineBinary\)/);
  assert.match(receiptWriter, /const enginePath = canonicalRelative\(bundleDir, engineBinary\)/);
  assert.doesNotMatch(receiptWriter, /preferredEngineNames/);

  for (const [name, producer, archive] of [
    ["local Apple", localAppleBuilder, "--engine-archive macos-static/libhermesvm_a.a"],
    ["local Linux", localLinuxBuilder, "--engine-archive linux-static/libhermesvm_a.a"],
    ["local Windows", localWindowsBuilder, "--engine-archive=windows-static/hermesvm_a.lib"],
    ["Unix release", releaseBuilder, "--engine-archive lib/libhermesvm_a.a"],
    ["Windows release", windowsReleaseBuilder, "--engine-archive=lib/hermesvm_a.lib"],
  ]) {
    assert.ok(producer.includes(archive), `${name} producer does not name its full VM archive`);
    assert.match(producer, /link-directive=rustc-link-lib=static=hermesvm_a/);
  }
  assert.match(releaseBuilder, /--target hermesvm_a hermesvmlean_a/);
  assert.match(localAppleBuilder, /--lean-engine-archive macos-static\/libhermesvmlean_a\.a/);
  assert.match(releaseBuilder, /--lean-engine-archive lib\/libhermesvmlean_a\.a/);
  assert.match(windowsReleaseBuilder, /--target hermesvmlean_a/);
  assert.match(windowsReleaseBuilder, /--lean-engine-archive=lib\/hermesvmlean_a\.lib/);
  for (const producer of [localWindowsBuilder, windowsReleaseBuilder]) {
    assert.match(producer, /(?:--profile=release|"--profile=release")/);
    assert.match(producer, /-DHERMES_ENABLE_DEBUGGER=OFF/);
    assert.doesNotMatch(producer, /release-debugger|-DHERMES_ENABLE_DEBUGGER=ON/);
    assert.match(producer, /-DHERMES_ENABLE_WIN10_ICU_FALLBACK=ON/);
    assert.match(producer, /link-directive=rustc-link-lib=icuuc/);
    assert.match(producer, /link-directive=rustc-link-lib=icuin/);
  }
  assert.match(receiptWriter, /manifestedLeanEngineArchives/);
  assert.match(receiptWriter, /exportedSymbols\(leanEngineBinary\)/);
});

test("receipt writer scans a manifested lean archive without an optional argument", (t) => {
  if (process.platform === "win32") {
    t.skip("the fixture supplies a POSIX fake nm; Windows release coverage is structural");
    return;
  }
  const temporary = mkdtempSync(join(tmpdir(), "hermes-receipt-lean-scan-"));
  const bundle = join(temporary, "bundle");
  const fakeBin = join(temporary, "bin");
  mkdirSync(join(bundle, "lib"), { recursive: true });
  mkdirSync(join(bundle, "include", "hermes"), { recursive: true });
  mkdirSync(join(bundle, "bin"), { recursive: true });
  mkdirSync(fakeBin);
  writeFileSync(join(bundle, "lib", "libhermesvm_a.a"), "full VM");
  writeFileSync(join(bundle, "lib", "libhermesvmlean_a.a"), "lean VM");
  writeFileSync(join(bundle, "include", "hermes", "Hermes.h"), "// header\n");
  writeFileSync(join(bundle, "bin", "hermesc"), "compiler");
  const fakeNm = join(fakeBin, "nm");
  writeFileSync(fakeNm, `#!/bin/sh
case "$*" in
  *libhermesvmlean_a.a*) printf '00000000 T ex_hermes_vm_disable_eval\\n' ;;
  *) printf '00000000 T ordinary_vanilla_symbol\\n' ;;
esac
`);
  chmodSync(fakeNm, 0o755);
  try {
    const result = spawnSync(process.execPath, [
      join(repoRoot, "scripts/hermes-input-receipt.mjs"),
      bundle,
      "--target=aarch64-apple-darwin",
      "--profile=release",
      "--engine-archive=lib/libhermesvm_a.a",
      "--bytecode-version=99",
      "--link-directive=rustc-link-lib=static=hermesvm_a",
    ], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH ?? ""}` },
    });
    assert.notEqual(result.status, 0, result.stdout);
    assert.match(result.stderr, /refusing an empty-patch-set receipt for a patched engine/);
    assert.match(result.stderr, /ex_hermes_vm_disable_eval/);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("Linux receipt binds both ICU data archives and the pinned filter", (t) => {
  if (process.platform === "win32") {
    t.skip("the fixture supplies a POSIX fake nm; Windows release coverage is structural");
    return;
  }
  const temporary = mkdtempSync(join(tmpdir(), "hermes-receipt-icu-data-"));
  const bundle = join(temporary, "bundle");
  const fakeBin = join(temporary, "bin");
  mkdirSync(join(bundle, "lib"), { recursive: true });
  mkdirSync(join(bundle, "include", "hermes"), { recursive: true });
  mkdirSync(join(bundle, "share", "icu"), { recursive: true });
  mkdirSync(join(bundle, "bin"), { recursive: true });
  mkdirSync(fakeBin);
  for (const name of [
    "libhermesvm_a.a",
    "libhermesvmlean_a.a",
    "libicui18n.a",
    "libicuuc.a",
    "libicudata.a",
    "libicudata-full.a",
  ]) writeFileSync(join(bundle, "lib", name), name);
  writeFileSync(join(bundle, "include", "hermes", "Hermes.h"), "// header\n");
  writeFileSync(join(bundle, "bin", "hermesc"), "compiler");
  writeFileSync(join(bundle, "share", "icu", "filters-root-en.json"), icuFilter);
  const fakeNm = join(fakeBin, "nm");
  writeFileSync(fakeNm, "#!/bin/sh\nprintf '00000000 T ordinary_vanilla_symbol\\n'\n");
  chmodSync(fakeNm, 0o755);
  try {
    const result = spawnSync(process.execPath, [
      join(repoRoot, "scripts/hermes-input-receipt.mjs"),
      bundle,
      "--target=aarch64-unknown-linux-gnu",
      "--profile=release",
      "--engine-archive=lib/libhermesvm_a.a",
      "--lean-engine-archive=lib/libhermesvmlean_a.a",
      "--icu-trimmed-data-archive=lib/libicudata.a",
      "--icu-full-data-archive=lib/libicudata-full.a",
      "--icu-trimmed-filter=share/icu/filters-root-en.json",
      "--bytecode-version=99",
      "--link-directive=rustc-link-lib=static=hermesvm_a",
    ], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH ?? ""}` },
    });
    assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(readFileSync(join(bundle, "hermes-input-receipt.json"), "utf8"));
    const archives = new Set(receipt.archives.map((archive) => archive.path));
    assert.ok(archives.has("lib/libicudata.a"));
    assert.ok(archives.has("lib/libicudata-full.a"));
    assert.equal(receipt.icu.data.trimmed.archive, "lib/libicudata.a");
    assert.equal(receipt.icu.data.full.archive, "lib/libicudata-full.a");
    assert.equal(
      receipt.icu.data.trimmed.filter.digest,
      `sha256-${createHash("sha256").update(icuFilter).digest("hex")}`,
    );
    assert.equal(receipt.icu.upstream.sourceCommit, "2d029329c82c7792b985024b2bdab5fc7278fbc8");
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
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
