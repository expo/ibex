// @ref LLP 0035#transport-and-distribution-provenance — keep native build
// bytes outside the credentialed publisher until a raw, immutable handoff has
// passed the exact structural and byte-level boundary tested here.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  linkSync,
  lstatSync,
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
import {
  readArtifactSourceFoundationDocuments,
} from "../packages/ibex-devtools/src/scripts/capsec-contract.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workflowPath = join(repoRoot, ".github/workflows/hermes-artifacts.yml");
const workflow = readFileSync(workflowPath, "utf8");

function jobBlocks() {
  const jobsStart = workflow.indexOf("\njobs:\n");
  assert.notEqual(jobsStart, -1, "workflow must have a jobs mapping");
  const jobsText = workflow.slice(jobsStart + 1);
  const headers = [...jobsText.matchAll(/^  ([a-z][a-z0-9_]*):\n/gm)];
  return new Map(
    headers.map((header, index) => [
      header[1],
      jobsText.slice(header.index, headers[index + 1]?.index ?? jobsText.length),
    ]),
  );
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
    match[1]
      .trim()
      .split("\n")
      .map((line) => line.trim().split(": ")),
  );
}

function blockScalar(key) {
  const marker = `      ${key}: |\n`;
  const start = workflow.indexOf(marker);
  assert.notEqual(start, -1, `missing ${key} block scalar`);
  const lines = workflow.slice(start + marker.length).split("\n");
  const body = [];
  for (const line of lines) {
    if (line !== "" && !line.startsWith("        ")) break;
    body.push(line.startsWith("        ") ? line.slice(8) : "");
  }
  return body.join("\n");
}

test("workflow isolates unprivileged builders from the credentialed publisher", () => {
  const jobs = jobBlocks();
  assert.deepEqual(
    [...jobs.keys()],
    ["identity", "release_state", "macos", "linux", "macos_release", "windows", "publish"],
  );
  assert.match(workflow, /^permissions: \{\}$/m);
  for (const key of ["on", "concurrency", "permissions", "jobs"]) {
    assert.equal((workflow.match(new RegExp(`^${key}:`, "gm")) ?? []).length, 1, `unique top-level ${key}`);
  }
  for (const [jobName, job] of jobs) {
    for (const key of ["needs", "if", "runs-on", "timeout-minutes", "permissions", "outputs", "env", "steps"]) {
      assert.ok(
        (job.match(new RegExp(`^    ${key}:`, "gm")) ?? []).length <= 1,
        `${jobName} has no duplicate ${key} mapping`,
      );
    }
    for (const step of stepBlocks(job)) {
      for (const key of ["id", "if", "uses", "with", "env", "run", "shell"]) {
        assert.ok(
          (step.text.match(new RegExp(`^        ${key}:`, "gm")) ?? []).length <= 1,
          `${jobName}/${step.name} has no duplicate ${key} mapping`,
        );
      }
    }
  }

  const trigger = workflow.slice(0, workflow.indexOf("\njobs:\n"));
  assert.match(trigger, /\n  push:\n    branches: \[main\]\n/);
  assert.doesNotMatch(trigger, /^    paths(?:-ignore)?:/m);
  assert.match(trigger, /\n  group: hermes-artifacts-\$\{\{ github\.sha \}\}\n/);

  for (const name of ["identity", "release_state", "macos", "linux", "macos_release", "windows"]) {
    assert.deepEqual(permissions(jobs.get(name)), { contents: "read" }, `${name} is read-only`);
  }
  assert.match(jobs.get("release_state"), /gh api --paginate --slurp/);
  assert.deepEqual(permissions(jobs.get("publish")), {
    actions: "read",
    attestations: "write",
    contents: "write",
    "id-token": "write",
  });

  const approvedActions = new Set([
    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be",
    "ilammy/msvc-dev-cmd@0b201ec74fa43914dc39ae48a89fd1d8cb592756",
  ]);
  const actionReferences = [...workflow.matchAll(/^\s+uses: ([^\s#]+)/gm)].map((match) => match[1]);
  assert.ok(actionReferences.length > 0);
  for (const reference of actionReferences) {
    assert.match(reference, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/);
    assert.ok(approvedActions.has(reference), `unapproved action reference: ${reference}`);
  }

  const checkoutSteps = actionReferences.filter((reference) => reference.startsWith("actions/checkout@"));
  assert.equal(checkoutSteps.length, 5);
  for (const name of ["identity", "macos", "linux", "macos_release", "windows"]) {
    const checkout = stepBlocks(jobs.get(name)).find((step) => step.text.includes("actions/checkout@"));
    assert.ok(checkout, `${name} checks out its source revision`);
    assert.match(checkout.text, /\n          persist-credentials: false\n/);
  }

  const expectedUploads = { macos: 1, linux: 1, macos_release: 2, windows: 1 };
  for (const [name, count] of Object.entries(expectedUploads)) {
    const builder = jobs.get(name);
    assert.doesNotMatch(builder, /actions\/attest-build-provenance|actions\/download-artifact|gh release/);
    assert.doesNotMatch(builder, /^\s+GH_TOKEN:/m);
    assert.doesNotMatch(builder, /^\s+(?:attestations|actions|contents|id-token): write$/m);
    const uploadSteps = stepBlocks(builder).filter((step) =>
      step.text.includes("actions/upload-artifact@"),
    );
    const directHandoffs = uploadSteps.filter((step) =>
      step.text.includes("\n          archive: false\n"),
    );
    assert.equal(
      directHandoffs.length,
      count,
      `${name} emits the expected direct handoffs`,
    );
    for (const upload of directHandoffs) {
      assert.match(upload.text, /\n          archive: false\n/);
      assert.match(upload.text, /\n          if-no-files-found: error\n/);
      assert.match(upload.text, /\n          overwrite: false\n/);
      assert.match(upload.text, /\n          path: \$\{\{ steps\.[a-z_]+\.outputs\.asset_path \}\}\n/);
      assert.doesNotMatch(upload.text, /\n          name:/);
    }
    const auxiliaryUploads = uploadSteps.filter(
      (step) => !directHandoffs.includes(step),
    );
    if (name === "linux") {
      assert.equal(auxiliaryUploads.length, 1);
      assert.equal(auxiliaryUploads[0].name, "Upload Linux dependency audit");
      assert.match(
        auxiliaryUploads[0].text,
        /\n          name: sfe-linux-static-dependency-audit\n/,
      );
      assert.match(
        auxiliaryUploads[0].text,
        /\n          path: target\/sfe-linux-static-audit\/dependency-audit\.json\n/,
      );
      assert.match(auxiliaryUploads[0].text, /\n          if-no-files-found: error\n/);
    } else {
      assert.equal(auxiliaryUploads.length, 0);
    }
    assert.match(builder, /artifact_id: \$\{\{ steps\.[a-z_]+\.outputs\.artifact-id \}\}/);
    assert.match(builder, /artifact_digest: \$\{\{ steps\.[a-z_]+\.outputs\.artifact-digest \}\}/);
  }

  const publisher = jobs.get("publish");
  assert.doesNotMatch(publisher, /actions\/checkout|uses: \.\/|scripts\/|subject-path:/);
  assert.doesNotMatch(publisher, /\b(?:unzip|Expand-Archive)\b|\btar\s+-/);
  assert.doesNotMatch(publisher, /^    (?:container|services|environment):/m);
  for (const step of stepBlocks(publisher)) {
    const runIndex = step.text.indexOf("\n        run:");
    if (runIndex !== -1) {
      assert.doesNotMatch(step.text.slice(runIndex), /\$\{\{\s*(?:needs|inputs)\./);
    }
    if (/^\s+GH_TOKEN:/m.test(step.text)) {
      assert.match(step.name, /^(?:Validate current-run|Ensure .*prerelease|Acquire cross-revision|Upload |Release cross-revision)/);
    }
  }

  const downloads = stepBlocks(publisher).filter((step) => step.text.includes("actions/download-artifact@"));
  assert.equal(downloads.length, 5);
  for (const download of downloads) {
    assert.match(download.text, /\n          artifact-ids: \$\{\{ needs\.[a-z_]+\.outputs\.[a-z_]+ \}\}\n/);
    assert.match(download.text, /\n          skip-decompress: true\n/);
    assert.match(download.text, /\n          digest-mismatch: error\n/);
    assert.doesNotMatch(download.text, /\n          (?:github-token|repository|run-id|name|pattern|merge-multiple):/);
    assert.equal((download.text.match(/artifact-ids:/g) ?? []).length, 1);
  }

  const attestations = stepBlocks(publisher).filter((step) => step.text.includes("actions/attest-build-provenance@"));
  assert.equal(attestations.length, 5);
  for (const attestation of attestations) {
    assert.match(attestation.text, /\n          subject-name: \$\{\{ needs\.[a-z_]+\.outputs\.[a-z_]+ \}\}\n/);
    assert.match(attestation.text, /\n          subject-digest: sha256:\$\{\{ needs\.[a-z_]+\.outputs\.[a-z0-9_]+ \}\}\n/);
    assert.doesNotMatch(attestation.text, /subject-path:/);
  }

  const condition = publisher.slice(0, publisher.indexOf("\n    runs-on:"));
  for (const required of [
    "always()",
    "needs.identity.result == 'success'",
    "needs.release_state.result == 'success'",
    "needs.macos.result == 'success'",
    "needs.linux.result == 'success'",
    "needs.macos_release.result == 'success'",
    "needs.windows.result == 'success'",
  ]) {
    assert.ok(condition.includes(required), `publisher condition is missing ${required}`);
  }

  const metadata = publisher.indexOf("- name: Validate current-run artifact-service metadata");
  const portableRelease = publisher.indexOf("- name: Ensure revision-scoped portable prerelease exists");
  const legacyRelease = publisher.indexOf("- name: Ensure legacy prerelease artifact cache exists");
  const lock = publisher.indexOf("- name: Acquire cross-revision legacy publish lease");
  const unlock = publisher.indexOf("- name: Release cross-revision legacy publish lease");
  const lockStep = stepBlocks(publisher).find((step) => step.name === "Acquire cross-revision legacy publish lease");
  const unlockStep = stepBlocks(publisher).find((step) => step.name === "Release cross-revision legacy publish lease");
  assert.ok(lockStep && unlockStep);
  assert.match(lockStep.text, /gh release upload "\$TAG" "\$lock_path" --repo "\$GITHUB_REPOSITORY"/);
  assert.doesNotMatch(lockStep.text, /gh release upload[^\n]*--clobber/);
  assert.match(lockStep.text, /actions\/runs\/\$owner_run/);
  assert.match(lockStep.text, /releases\/assets\/\$asset_id/);
  assert.match(lockStep.text, /wait-starter\|wait-unknown-state/);
  assert.match(lockStep.text, /delete-stale-starter\|delete-invalid-uploaded/);
  assert.match(lockStep.text, /temporarily unavailable; waiting/);
  assert.match(unlockStep.text, /document != expected/);
  assert.match(unlockStep.text, /--method DELETE/);
  assert.ok(portableRelease < legacyRelease && legacyRelease < lock && lock < unlock);
  const roleSteps = [
    ["macOS", "macOS"],
    ["Linux", "Linux"],
    ["macOS Release", "macOS Release"],
    ["portable", "portable"],
    ["Windows", "Windows"],
  ];
  for (const [downloadLabel, laterLabel] of roleSteps) {
    const download = publisher.indexOf(`- name: Download ${downloadLabel} direct handoff`);
    const validation = publisher.indexOf(`- name: Validate ${downloadLabel} raw handoff bytes`);
    const attestation = publisher.indexOf(`- name: Attest ${laterLabel} bundle provenance`);
    const retention = publisher.indexOf(`- name: Retain exact ${laterLabel} provenance bundle`);
    const sidecars = publisher.indexOf(`- name: Upload ${laterLabel} provenance sidecars`);
    const archive = publisher.indexOf(`- name: Upload ${laterLabel} archive last`);
    for (const [name, position] of Object.entries({ download, validation, attestation, retention, sidecars, archive })) {
      assert.notEqual(position, -1, `missing ${laterLabel} ${name} step`);
    }
    assert.ok(metadata < download && download < validation);
    assert.ok(validation < attestation && attestation < retention);
    assert.ok(sidecars < archive);
    if (laterLabel === "portable") {
      assert.ok(
        retention < portableRelease && portableRelease < sidecars && archive < legacyRelease,
        "revision-scoped portable publication never waits on the legacy release or lease",
      );
    } else {
      assert.ok(retention < legacyRelease && legacyRelease < lock && lock < sidecars && archive < unlock);
    }
  }
});

test("portable sets use a bounded revision-scoped release namespace", () => {
  const jobs = jobBlocks();
  const identity = jobs.get("identity");
  const releaseState = jobs.get("release_state");
  const publisherSteps = stepBlocks(jobs.get("publish"));

  assert.match(identity, /portable_tag=hermes-portable-\$identity-\$GITHUB_SHA/);
  assert.match(releaseState, /PORTABLE_TAG: \$\{\{ needs\.identity\.outputs\.portable_tag \}\}/);
  assert.match(releaseState, /list_assets "\$TAG" "\$legacy_assets"/);
  assert.match(releaseState, /list_assets "\$PORTABLE_TAG" "\$portable_assets"/);
  assert.match(releaseState, /need_portable_macos_release="\$\(need "\$portable_assets"/);

  const portableRelease = publisherSteps.find(
    (step) => step.name === "Ensure revision-scoped portable prerelease exists",
  );
  assert.ok(portableRelease);
  assert.match(portableRelease.text, /TAG: \$\{\{ needs\.identity\.outputs\.portable_tag \}\}/);
  assert.match(portableRelease.text, /"\$TAG" == "hermes-portable-\$IDENTITY-\$SHA"/);
  const portableArchiveIndex = publisherSteps.findIndex(
    (step) => step.name === "Upload portable archive last",
  );
  const legacyReleaseIndex = publisherSteps.findIndex(
    (step) => step.name === "Ensure legacy prerelease artifact cache exists",
  );
  assert.ok(
    portableArchiveIndex >= 0 && portableArchiveIndex < legacyReleaseIndex,
    "portable publication completes before any shared legacy-release operation can fail",
  );

  for (const step of publisherSteps.filter((candidate) => candidate.name.startsWith("Upload "))) {
    if (step.name.startsWith("Upload portable")) {
      assert.match(step.text, /TAG: \$\{\{ needs\.identity\.outputs\.portable_tag \}\}/);
    } else {
      assert.match(step.text, /TAG: \$\{\{ needs\.identity\.outputs\.tag \}\}/);
      assert.doesNotMatch(step.text, /outputs\.portable_tag/);
    }
  }
});

const releaseAssetNeedValidator = blockScalar("IBEX_RELEASE_ASSET_NEED_VALIDATOR");

function runReleaseAssetNeed(assets, expectedNames) {
  const temporary = mkdtempSync(join(tmpdir(), "ibex-release-state-test-"));
  const metadataPath = join(temporary, "assets.json");
  writeFileSync(metadataPath, JSON.stringify([assets]));
  try {
    return spawnSync("python3", ["-c", releaseAssetNeedValidator, metadataPath, ...expectedNames], {
      encoding: "utf8",
      timeout: 10_000,
    });
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function completeReleaseAssetSet() {
  const archive = "hermes-portable-test.tar.gz";
  const names = [archive, `${archive}.sha256`, `${archive}.sigstore.json`, `${archive}.sigstore.json.sha256`];
  const assets = names.map((name, index) => ({
    id: 100 + index,
    name,
    size: index === 0 ? 1024 : 128,
    state: "uploaded",
  }));
  return { assets, names };
}

test("release discovery skips only one complete uploaded four-file set", () => {
  const { assets, names } = completeReleaseAssetSet();
  const result = runReleaseAssetNeed(assets, names);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "false\n");
});

test("a four-name set with a starter archive is selected for repair", () => {
  const { assets, names } = completeReleaseAssetSet();
  assets[0].state = "starter";
  assets[0].size = 0;
  const result = runReleaseAssetNeed(assets, names);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "true\n");
});

for (const [label, mutate] of [
  ["missing member", ({ assets }) => assets.pop()],
  ["duplicate name", ({ assets }) => assets.push({ ...assets[0], id: 999 })],
  ["zero size", ({ assets }) => { assets[1].size = 0; }],
  ["oversize member", ({ assets }) => { assets[2].size = 2 * 1024 * 1024 * 1024 + 1; }],
  ["nonpositive ID", ({ assets }) => { assets[3].id = 0; }],
]) {
  test(`release discovery selects a set with ${label} for repair`, () => {
    const fixture = completeReleaseAssetSet();
    mutate(fixture);
    const result = runReleaseAssetNeed(fixture.assets, fixture.names);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "true\n");
  });
}

test("portable acceptance and the artifact-source foundation remain closed", () => {
  const policy = JSON.parse(
    readFileSync(join(repoRoot, "schemas/portable-engine-provenance-trust-policy-v1.json"), "utf8"),
  );
  const { targetAdvertisements, targetAttestations } =
    readArtifactSourceFoundationDocuments(repoRoot);
  assert.equal(policy.portableArtifactAcceptanceEnabled, false);
  assert.equal(
    targetAdvertisements.targetAdvertisementSchema,
    "ibex/capsec-target-advertisements/1",
  );
  assert.deepEqual(targetAdvertisements.advertisements, []);
  assert.equal(
    targetAttestations.targetAttestationSchema,
    "ibex/capsec-target-attestations/1",
  );
  assert.deepEqual(targetAttestations.attestations, []);
});

test("one exclusive lease encloses every stable-name legacy release mutation", () => {
  const publisher = jobBlocks().get("publish");
  const steps = stepBlocks(publisher);
  const lockIndex = steps.findIndex((step) => step.name === "Acquire cross-revision legacy publish lease");
  const unlockIndex = steps.findIndex((step) => step.name === "Release cross-revision legacy publish lease");
  assert.ok(lockIndex > 0 && unlockIndex > lockIndex);
  const lock = steps[lockIndex];
  const unlock = steps[unlockIndex];
  assert.match(lock.text, /needs\.release_state\.outputs\.need_macos == 'true'/);
  assert.match(lock.text, /needs\.release_state\.outputs\.need_linux == 'true'/);
  assert.match(lock.text, /needs\.release_state\.outputs\.need_macos_release_legacy == 'true'/);
  assert.match(lock.text, /needs\.release_state\.outputs\.need_windows == 'true'/);
  assert.doesNotMatch(lock.text, /need_portable_macos_release/);
  assert.match(lock.text, /ibex-hermes-legacy-publish-\$IDENTITY\.lock/);
  assert.match(lock.text, /gh release upload "\$TAG" "\$lock_path" --repo "\$GITHUB_REPOSITORY"/);
  assert.doesNotMatch(lock.text, /gh release upload[^\n]*--clobber/);
  assert.match(lock.text, /gh api --paginate --slurp/);
  assert.match(lock.text, /actions\/runs\/\$owner_run/);
  assert.match(lock.text, /owner_status" != "completed"/);
  assert.match(lock.text, /wait-starter\|wait-unknown-state/);
  assert.match(lock.text, /delete-stale-starter\|delete-invalid-uploaded/);
  assert.match(lock.text, /deleting proven-stale or invalid/);
  assert.match(lock.text, /gh api --include/);
  assert.match(lock.text, /owner_missing=true/);
  assert.match(lock.text, /definitively absent; its lease is stale/);
  assert.match(lock.text, /"\$owner_lookup_failed" == "true" \|\| "\$owner_active" == "true"/);
  assert.match(unlock.text, /always\(\).*legacy_publish_lock\.outputs\.acquired == 'true'/);
  assert.match(unlock.text, /document != expected/);
  assert.match(unlock.text, /gh api --paginate --slurp/);
  assert.match(unlock.text, /--method DELETE/);

  for (const [index, step] of steps.entries()) {
    if (!step.name.startsWith("Upload ")) continue;
    if (step.name.startsWith("Upload portable")) {
      assert.ok(index < lockIndex, `${step.name} remains outside and before the legacy lease`);
    } else {
      assert.ok(index > lockIndex && index < unlockIndex, `${step.name} is enclosed by the legacy lease`);
    }
  }
});

const leaseAssetMetadataValidator = blockScalar("IBEX_LEASE_ASSET_METADATA_VALIDATOR");
const actionsRunResponseValidator = blockScalar("IBEX_ACTIONS_RUN_RESPONSE_VALIDATOR");

function githubTimestamp(secondsFromNow = 0) {
  return new Date(Date.now() + secondsFromNow * 1000).toISOString().replace(/\.[0-9]{3}Z$/, "Z");
}

function runLeaseAssetMetadata(pages, lockName = "ibex-hermes-legacy-publish-test.lock") {
  const temporary = mkdtempSync(join(tmpdir(), "ibex-lease-metadata-test-"));
  const metadataPath = join(temporary, "assets.json");
  writeFileSync(metadataPath, JSON.stringify(pages));
  try {
    return spawnSync("python3", ["-c", leaseAssetMetadataValidator, metadataPath], {
      encoding: "utf8",
      env: { ...process.env, LOCK_NAME: lockName },
      timeout: 10_000,
    });
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

test("the production lease metadata path identifies one bounded uploaded asset", () => {
  const result = runLeaseAssetMetadata([
    [{
      id: 41,
      name: "ibex-hermes-legacy-publish-test.lock",
      size: 127,
      state: "uploaded",
      created_at: githubTimestamp(-60),
    }],
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "41 127 uploaded download\n");
});

test("a concurrent starter lease remains untouched throughout its creation grace", () => {
  const result = runLeaseAssetMetadata([
    [{
      id: 42,
      name: "ibex-hermes-legacy-publish-test.lock",
      size: 0,
      state: "starter",
      created_at: githubTimestamp(-5),
    }],
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "42 0 starter wait-starter\n");

  const lock = stepBlocks(jobBlocks().get("publish")).find(
    (step) => step.name === "Acquire cross-revision legacy publish lease",
  ).text;
  const waitCase = lock.indexOf("wait-starter|wait-unknown-state)");
  const pollAgain = lock.indexOf("continue", waitCase);
  const staleCase = lock.indexOf("delete-stale-starter|delete-invalid-uploaded)");
  assert.ok(waitCase >= 0 && waitCase < pollAgain && pollAgain < staleCase);
});

test("an aged starter lease is deleted by exact ID before any download is attempted", () => {
  const result = runLeaseAssetMetadata([
    [{
      id: 45,
      name: "ibex-hermes-legacy-publish-test.lock",
      size: 0,
      state: "starter",
      created_at: githubTimestamp(-10 * 60),
    }],
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "45 0 starter delete-stale-starter\n");

  const lock = stepBlocks(jobBlocks().get("publish")).find(
    (step) => step.name === "Acquire cross-revision legacy publish lease",
  ).text;
  const staleCase = lock.indexOf("delete-stale-starter|delete-invalid-uploaded)");
  const exactIdDelete = lock.indexOf('"repos/$GITHUB_REPOSITORY/releases/assets/$asset_id"', staleCase);
  const skipDownload = lock.indexOf("continue", exactIdDelete);
  const binaryDownload = lock.indexOf('-H "Accept: application/octet-stream"', skipDownload);
  assert.ok(staleCase >= 0 && staleCase < exactIdDelete);
  assert.ok(exactIdDelete < skipDownload && skipDownload < binaryDownload);
});

test("an unknown lease asset state remains fail-closed", () => {
  const result = runLeaseAssetMetadata([
    [{
      id: 46,
      name: "ibex-hermes-legacy-publish-test.lock",
      size: 127,
      state: "processing",
      created_at: githubTimestamp(-60 * 60),
    }],
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "46 127 processing wait-unknown-state\n");
});

test("ambiguous lease metadata is never assigned an asset ID", () => {
  const name = "ibex-hermes-legacy-publish-test.lock";
  const result = runLeaseAssetMetadata([[
    { id: 43, name, size: 127, state: "uploaded", created_at: githubTimestamp(-60) },
    { id: 44, name, size: 0, state: "starter", created_at: githubTimestamp(-60) },
  ]], name);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
});

function runActionsResponse(raw, apiExit) {
  const temporary = mkdtempSync(join(tmpdir(), "ibex-actions-response-test-"));
  const responsePath = join(temporary, "response.txt");
  writeFileSync(responsePath, raw);
  try {
    return spawnSync("python3", ["-c", actionsRunResponseValidator, responsePath], {
      encoding: "utf8",
      env: { ...process.env, GH_API_EXIT: String(apiExit) },
      timeout: 10_000,
    });
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

test("a definitive Actions run 404 is classified as a recoverable missing owner", () => {
  const result = runActionsResponse(
    "HTTP/2.0 404 Not Found\r\ncontent-type: application/json\r\n\r\n" +
      '{"message":"Not Found","status":"404"}\n',
    1,
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "missing\n");

  const lock = stepBlocks(jobBlocks().get("publish")).find(
    (step) => step.name === "Acquire cross-revision legacy publish lease",
  ).text;
  const missing = lock.indexOf("owner_missing=true");
  const wait = lock.indexOf('"$owner_lookup_failed" == "true" || "$owner_active" == "true"');
  const deleteStale = lock.lastIndexOf("--method DELETE");
  assert.ok(missing >= 0 && missing < wait && wait < deleteStale);
});

test("ambiguous Actions API failures remain fail-closed", () => {
  for (const raw of [
    "",
    "HTTP/2.0 500 Internal Server Error\r\ncontent-type: application/json\r\n\r\n{}\n",
    "HTTP/2.0 403 Forbidden\r\ncontent-type: application/json\r\n\r\n{}\n",
  ]) {
    const result = runActionsResponse(raw, 1);
    assert.notEqual(result.status, 0, `${JSON.stringify(raw)} was not fail-closed`);
  }
});

test("the Actions response validator binds active owner metadata", () => {
  const body = JSON.stringify({
    status: "in_progress",
    run_attempt: 3,
    head_sha: "a".repeat(40),
    path: ".github/workflows/hermes-artifacts.yml",
  });
  const result = runActionsResponse(
    `HTTP/2 200 OK\ncontent-type: application/json\n\n${body}\n`,
    0,
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    result.stdout,
    `found\tin_progress\t3\t${"a".repeat(40)}\t.github/workflows/hermes-artifacts.yml\n`,
  );
});

const handoffValidator = blockScalar("IBEX_PUBLISH_HANDOFF_VALIDATOR");

function newHandoffFixture({ role = "linux", name = "hermes-linux-x64-test.tar.gz" } = {}) {
  const temporary = mkdtempSync(join(tmpdir(), "ibex-handoff-test-"));
  const root = join(temporary, "publish");
  const directory = join(root, role);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const bytes = Buffer.from("inert Hermes archive bytes\n", "utf8");
  const candidate = join(directory, name);
  writeFileSync(candidate, bytes, { mode: 0o600 });
  const env = {
    ...process.env,
    EXPECTED_NAME: name,
    EXPECTED_ROLE: role,
    EXPECTED_SHA256: createHash("sha256").update(bytes).digest("hex"),
    EXPECTED_SIZE: String(bytes.length),
    HANDOFF_DIR: directory,
    IBEX_PUBLISH_ROOT: root,
  };
  return { bytes, candidate, directory, env, name, root, temporary };
}

function runValidator(fixture) {
  return spawnSync("python3", ["-c", handoffValidator], {
    encoding: "utf8",
    env: fixture.env,
    timeout: 10_000,
  });
}

test("the exact production handoff validator accepts one bound regular file", () => {
  const fixture = newHandoffFixture();
  try {
    const result = runValidator(fixture);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /validated inert linux handoff/);
  } finally {
    rmSync(fixture.temporary, { recursive: true, force: true });
  }
});

const adversarialHandoffs = [
  ["missing archive", (fixture) => rmSync(fixture.candidate)],
  ["extra file", (fixture) => writeFileSync(join(fixture.directory, "extra"), "extra")],
  ["wrong expected basename", (fixture) => { fixture.env.EXPECTED_NAME = "hermes-linux-x64-other.tar.gz"; }],
  ["path-traversal basename", (fixture) => { fixture.env.EXPECTED_NAME = "../hermes.tar.gz"; }],
  ["control-character basename", (fixture) => { fixture.env.EXPECTED_NAME = "hermes-\n.tar.gz"; }],
  ["uppercase digest", (fixture) => { fixture.env.EXPECTED_SHA256 = fixture.env.EXPECTED_SHA256.toUpperCase(); }],
  ["wrong digest", (fixture) => { fixture.env.EXPECTED_SHA256 = "0".repeat(64); }],
  ["wrong size", (fixture) => { fixture.env.EXPECTED_SIZE = String(fixture.bytes.length + 1); }],
  ["zero size", (fixture) => { fixture.env.EXPECTED_SIZE = "0"; }],
  ["oversize declaration", (fixture) => { fixture.env.EXPECTED_SIZE = String(2 * 1024 * 1024 * 1024 + 1); }],
  ["directory in place of archive", (fixture) => {
    rmSync(fixture.candidate);
    mkdirSync(fixture.candidate);
  }],
  ["FIFO in place of archive", (fixture) => {
    rmSync(fixture.candidate);
    const result = spawnSync("mkfifo", [fixture.candidate], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
  }],
  ["symlink in place of archive", (fixture) => {
    const source = join(fixture.temporary, "outside");
    writeFileSync(source, fixture.bytes);
    rmSync(fixture.candidate);
    symlinkSync(source, fixture.candidate);
  }],
  ["hard link in place of archive", (fixture) => {
    const source = join(fixture.temporary, "outside");
    writeFileSync(source, fixture.bytes);
    rmSync(fixture.candidate);
    linkSync(source, fixture.candidate);
    assert.equal(lstatSync(fixture.candidate).nlink, 2);
  }],
  ["symlinked handoff directory", (fixture) => {
    const realDirectory = join(fixture.root, "real-linux");
    mkdirSync(realDirectory);
    writeFileSync(join(realDirectory, fixture.name), fixture.bytes);
    rmSync(fixture.directory, { recursive: true });
    symlinkSync(realDirectory, fixture.directory);
  }],
  ["expanded Windows ZIP tree", (fixture) => {
    const windowsDirectory = join(fixture.root, "windows");
    mkdirSync(join(windowsDirectory, "bin"), { recursive: true });
    writeFileSync(join(windowsDirectory, "bin", "hermes.exe"), fixture.bytes);
    fixture.env.EXPECTED_ROLE = "windows";
    fixture.env.HANDOFF_DIR = windowsDirectory;
    fixture.env.EXPECTED_NAME = "hermes-windows-x64-test.zip";
  }],
];

for (const [name, mutate] of adversarialHandoffs) {
  test(`the production handoff validator rejects ${name}`, () => {
    const fixture = newHandoffFixture();
    try {
      mutate(fixture);
      const result = runValidator(fixture);
      assert.notEqual(result.status, 0, `${name} unexpectedly passed\n${result.stdout}`);
      assert.match(result.stderr, /handoff refused:/);
    } finally {
      rmSync(fixture.temporary, { recursive: true, force: true });
    }
  });
}

const bundleValidator = blockScalar("IBEX_RETAIN_SIGSTORE_BUNDLE");

function writeAttestationBundle(fixture, overrides = {}) {
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: fixture.name, digest: { sha256: fixture.env.EXPECTED_SHA256 } }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {},
    ...overrides.statement,
  };
  const bundle = {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: {},
    dsseEnvelope: {
      payloadType: "application/vnd.in-toto+json",
      payload: Buffer.from(JSON.stringify(statement), "utf8").toString("base64"),
      signatures: [{}],
    },
    ...overrides.bundle,
  };
  const source = join(fixture.temporary, "attestation.json");
  writeFileSync(source, JSON.stringify(bundle));
  fixture.env.ATTESTATION_BUNDLE_PATH = source;
  return { bundle, source, statement };
}

function runBundleValidator(fixture) {
  return spawnSync("python3", ["-c", bundleValidator], {
    encoding: "utf8",
    env: fixture.env,
    timeout: 10_000,
  });
}

test("the exact production bundle validator retains a subject-bound DSSE bundle", () => {
  const fixture = newHandoffFixture();
  try {
    const { source } = writeAttestationBundle(fixture);
    const sourceBytes = readFileSync(source);
    const result = runBundleValidator(fixture);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.deepEqual(readFileSync(join(fixture.directory, `${fixture.name}.sigstore.json`)), sourceBytes);
    assert.equal(
      readFileSync(join(fixture.directory, `${fixture.name}.sha256`), "ascii"),
      `${fixture.env.EXPECTED_SHA256}  ${fixture.name}\n`,
    );
  } finally {
    rmSync(fixture.temporary, { recursive: true, force: true });
  }
});

const adversarialBundles = [
  ["malformed JSON", (fixture, state) => writeFileSync(state.source, "{")],
  ["trailing second JSON document", (fixture, state) => {
    writeFileSync(state.source, `${JSON.stringify(state.bundle)}\n{}`);
  }],
  ["duplicate JSON keys", (fixture, state) => {
    writeFileSync(
      state.source,
      `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","mediaType":"duplicate"}`,
    );
  }],
  ["wrong media type", (fixture, state) => {
    state.bundle.mediaType = "application/example";
    writeFileSync(state.source, JSON.stringify(state.bundle));
  }],
  ["wrong DSSE payload type", (fixture, state) => {
    state.bundle.dsseEnvelope.payloadType = "application/example";
    writeFileSync(state.source, JSON.stringify(state.bundle));
  }],
  ["malformed DSSE payload", (fixture, state) => {
    state.bundle.dsseEnvelope.payload = "***not-base64***";
    writeFileSync(state.source, JSON.stringify(state.bundle));
  }],
  ["wrong subject name", (fixture) => {
    writeAttestationBundle(fixture, {
      statement: { subject: [{ name: "other.tar.gz", digest: { sha256: fixture.env.EXPECTED_SHA256 } }] },
    });
  }],
  ["wrong subject digest", (fixture) => {
    writeAttestationBundle(fixture, {
      statement: { subject: [{ name: fixture.name, digest: { sha256: "0".repeat(64) } }] },
    });
  }],
  ["multiple subjects", (fixture) => {
    const subject = { name: fixture.name, digest: { sha256: fixture.env.EXPECTED_SHA256 } };
    writeAttestationBundle(fixture, { statement: { subject: [subject, subject] } });
  }],
  ["symlinked action output", (fixture, state) => {
    const target = join(fixture.temporary, "real-attestation.json");
    writeFileSync(target, readFileSync(state.source));
    rmSync(state.source);
    symlinkSync(target, state.source);
  }],
  ["archive mutation after attestation", (fixture) => {
    writeFileSync(fixture.candidate, "changed archive bytes");
  }],
];

for (const [name, mutate] of adversarialBundles) {
  test(`the production bundle validator rejects ${name}`, () => {
    const fixture = newHandoffFixture();
    try {
      const state = writeAttestationBundle(fixture);
      mutate(fixture, state);
      const result = runBundleValidator(fixture);
      assert.notEqual(result.status, 0, `${name} unexpectedly passed\n${result.stdout}`);
      assert.match(result.stderr, /attestation bundle refused:/);
    } finally {
      rmSync(fixture.temporary, { recursive: true, force: true });
    }
  });
}
