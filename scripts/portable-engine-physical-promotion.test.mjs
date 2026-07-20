// @ref LLP 0035#transport-and-distribution-provenance — physical-promotion
// inputs are exact revision-scoped release members and a signer-selected
// producer run, never a mutable name-only download.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson } from "./portable-engine-contract.mjs";
import {
  buildPortableReleasePlan,
  selectBuildConsumption,
  verifyPortableReleaseDownload,
  verifyProducerRun,
} from "./portable-engine-physical-promotion.mjs";

const REVISION = "a".repeat(40);
const ARTIFACT_ID = `sha256-${"A".repeat(43)}`;
const ARCHIVE_DIGEST = `sha256-${"1".repeat(64)}`;
const BUNDLE_DIGEST = `sha256-${"2".repeat(64)}`;
const TARGET = "aarch64-apple-darwin";
const RELEASE_TAG = `hermes-portable-0123456789ab-abcdef012345-${REVISION}`;
const ARCHIVE_NAME = `hermes-portable-macos-arm64-release-cache-${REVISION}.tar.gz`;
const TIMESTAMP = "2026-07-20T12:00:00Z";

const sha256 = (bytes) =>
  `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;

function releaseFixture() {
  const archive = Buffer.from("portable archive\n", "utf8");
  const bundle = Buffer.from(
    `${JSON.stringify({
      mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    })}\n`,
    "utf8",
  );
  const archiveChecksum = Buffer.from(
    `${sha256(archive).slice("sha256:".length)}  ${ARCHIVE_NAME}\n`,
    "ascii",
  );
  const bundleName = `${ARCHIVE_NAME}.sigstore.json`;
  const bundleChecksum = Buffer.from(
    `${sha256(bundle).slice("sha256:".length)}  ${bundleName}\n`,
    "ascii",
  );
  const files = new Map([
    [ARCHIVE_NAME, archive],
    [`${ARCHIVE_NAME}.sha256`, archiveChecksum],
    [bundleName, bundle],
    [`${bundleName}.sha256`, bundleChecksum],
  ]);
  const metadata = {
    id: 81,
    tag_name: RELEASE_TAG,
    target_commitish: REVISION,
    draft: false,
    prerelease: true,
    name: `Hermes portable artifact ${REVISION}`,
    created_at: TIMESTAMP,
    published_at: TIMESTAMP,
    assets: [...files].map(([name, bytes], index) => ({
      id: 100 + index,
      name,
      state: "uploaded",
      size: bytes.byteLength,
      digest: sha256(bytes),
      created_at: TIMESTAMP,
      updated_at: TIMESTAMP,
    })),
  };
  return { files, metadata };
}

function materializeDownload(files) {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "ibex-portable-promotion-")),
  );
  chmodSync(root, 0o700);
  for (const [name, bytes] of files) {
    writeFileSync(join(root, name), bytes, { mode: 0o600 });
  }
  return root;
}

function planFor(metadata) {
  return buildPortableReleasePlan({
    metadata,
    sourceRevision: REVISION,
    releaseTag: RELEASE_TAG,
    archiveName: ARCHIVE_NAME,
  });
}

test("release plan and exact four-file download join by revision, ID, size, and digest", () => {
  const fixture = releaseFixture();
  const directory = materializeDownload(fixture.files);
  try {
    const plan = planFor(fixture.metadata);
    assert.match(plan.planDigest, /^sha256-[A-Za-z0-9_-]{43}$/u);
    const selected = verifyPortableReleaseDownload({
      plan,
      metadata: structuredClone(fixture.metadata),
      directory,
    });
    assert.equal(readFileSync(selected.archivePath, "utf8"), "portable archive\n");
    assert.equal(
      selected.bundlePath,
      join(directory, `${ARCHIVE_NAME}.sigstore.json`),
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

for (const [label, mutate] of [
  ["another source revision", (fixture) => { fixture.metadata.target_commitish = "b".repeat(40); }],
  ["a missing member", (fixture) => { fixture.metadata.assets.pop(); }],
  ["an extra member", (fixture) => { fixture.metadata.assets.push({ ...fixture.metadata.assets[0], id: 999, name: "extra" }); }],
  ["a duplicate asset ID", (fixture) => { fixture.metadata.assets[1].id = fixture.metadata.assets[0].id; }],
  ["a starter asset", (fixture) => { fixture.metadata.assets[0].state = "starter"; }],
  ["an absent service digest", (fixture) => { fixture.metadata.assets[0].digest = null; }],
  ["a mutable branch target", (fixture) => { fixture.metadata.target_commitish = "main"; }],
]) {
  test(`release planning rejects ${label}`, () => {
    const fixture = releaseFixture();
    mutate(fixture);
    assert.throws(() => planFor(fixture.metadata));
  });
}

test("post-download metadata drift and local substitution fail closed", () => {
  const fixture = releaseFixture();
  const plan = planFor(fixture.metadata);
  const directory = materializeDownload(fixture.files);
  try {
    const changedMetadata = structuredClone(fixture.metadata);
    changedMetadata.assets[0].id += 1000;
    assert.throws(
      () =>
        verifyPortableReleaseDownload({
          plan,
          metadata: changedMetadata,
          directory,
        }),
      /changed across exact-ID downloads/u,
    );

    writeFileSync(join(directory, ARCHIVE_NAME), "substituted\n");
    assert.throws(
      () =>
        verifyPortableReleaseDownload({
          plan,
          metadata: fixture.metadata,
          directory,
        }),
      /size differs|digest differs/u,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("unexpected local members and sidecar substitution fail closed", () => {
  const fixture = releaseFixture();
  const plan = planFor(fixture.metadata);
  const directory = materializeDownload(fixture.files);
  try {
    writeFileSync(join(directory, "unexpected"), "x", { mode: 0o600 });
    assert.throws(
      () =>
        verifyPortableReleaseDownload({
          plan,
          metadata: fixture.metadata,
          directory,
        }),
      /exact four-file membership/u,
    );
    rmSync(join(directory, "unexpected"));
    const sidecar = join(directory, `${ARCHIVE_NAME}.sha256`);
    const original = readFileSync(sidecar);
    writeFileSync(sidecar, Buffer.from(original.toString("ascii").replace("  ", " ")));
    const changedMetadata = structuredClone(fixture.metadata);
    const changedAsset = changedMetadata.assets.find(
      (asset) => asset.name === `${ARCHIVE_NAME}.sha256`,
    );
    changedAsset.size = readFileSync(sidecar).byteLength;
    changedAsset.digest = sha256(readFileSync(sidecar));
    const changedPlan = planFor(changedMetadata);
    assert.throws(
      () =>
        verifyPortableReleaseDownload({
          plan: changedPlan,
          metadata: changedMetadata,
          directory,
        }),
      /checksum sidecar does not bind/u,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function installationFixture() {
  return {
    schema: "ibex/portable-engine-physical-promotion-installation/1",
    sourceRevision: REVISION,
    targetTriple: TARGET,
    artifactId: ARTIFACT_ID,
    archiveDigest: ARCHIVE_DIGEST,
    provenanceBundleDigest: BUNDLE_DIGEST,
    manifestDigest: `sha256-${"D".repeat(43)}`,
    installationReceiptDigest: `sha256-${"E".repeat(43)}`,
    verificationPolicyDigest: `sha256-${"F".repeat(43)}`,
    subjectName: ARCHIVE_NAME,
    producer: {
      repository: "ccheever/ibex",
      workflowPath: ".github/workflows/hermes-artifacts.yml",
      sourceRef: "refs/heads/main",
      runId: "7001",
      runAttempt: "2",
    },
    checkedAdmission: {
      schema: "ibex/portable-engine-checked-promotion-admission/1",
      authorized: false,
      currentRevision: REVISION,
      sourceRevision: REVISION,
      promotionTopicRevision: null,
      sourceTreeObjectId: null,
      targetTriple: TARGET,
      portableArtifactId: ARTIFACT_ID,
      admissionDigest: null,
      verificationDigest: `sha256-${"B".repeat(43)}`,
    },
  };
}

function runMetadataFixture() {
  return {
    id: 7001,
    run_attempt: 2,
    head_sha: REVISION,
    head_branch: "main",
    path: ".github/workflows/hermes-artifacts.yml",
    name: "Hermes artifact cache",
    event: "push",
    status: "completed",
    conclusion: "success",
    created_at: TIMESTAMP,
    updated_at: TIMESTAMP,
    run_started_at: TIMESTAMP,
    repository: {
      id: 1268046138,
      full_name: "ccheever/ibex",
      owner: { id: 56719 },
    },
  };
}

test("signed producer run and exact attempt rejoin successful Actions metadata", () => {
  assert.doesNotThrow(() =>
    verifyProducerRun({
      installation: installationFixture(),
      metadata: runMetadataFixture(),
    }),
  );
});

for (const [label, mutate] of [
  ["run ID", (metadata) => { metadata.id += 1; }],
  ["attempt", (metadata) => { metadata.run_attempt += 1; }],
  ["source revision", (metadata) => { metadata.head_sha = "b".repeat(40); }],
  ["workflow", (metadata) => { metadata.path = ".github/workflows/other.yml"; }],
  ["branch", (metadata) => { metadata.head_branch = "topic"; }],
  ["conclusion", (metadata) => { metadata.conclusion = "failure"; }],
  ["repository object", (metadata) => { metadata.repository.id += 1; }],
]) {
  test(`producer join rejects another ${label}`, () => {
    const metadata = runMetadataFixture();
    mutate(metadata);
    assert.throws(() =>
      verifyProducerRun({ installation: installationFixture(), metadata }),
    );
  });
}

test("Cargo stream selects exactly one matching canonical build-consumption record", () => {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "ibex-portable-build-selection-")),
  );
  try {
    const out = join(root, "target/debug/build/ibex-runtime-test/out");
    mkdirSync(out, { recursive: true, mode: 0o700 });
    const buildPath = join(out, "portable_engine_build_consumption.json");
    const build = {
      schema: "ibex/portable-engine-build-consumption/1",
      portable: { artifactId: ARTIFACT_ID },
      target: { triple: TARGET },
      manifestDigest: installationFixture().manifestDigest,
      installationReceiptDigest:
        installationFixture().installationReceiptDigest,
      verificationPolicyDigest:
        installationFixture().verificationPolicyDigest,
      consumptionDigest: `sha256-${"C".repeat(43)}`,
    };
    writeFileSync(buildPath, canonicalJson(build), { mode: 0o600 });
    const cargoMessagesPath = join(root, "target/cargo.jsonl");
    writeFileSync(
      cargoMessagesPath,
      `${JSON.stringify({ reason: "build-script-executed", out_dir: out })}\n`,
      { mode: 0o600 },
    );
    const selection = selectBuildConsumption({
      cargoMessagesPath,
      installation: installationFixture(),
      selectedRepoRoot: root,
    });
    assert.equal(
      selection.buildConsumptionPath,
      "target/debug/build/ibex-runtime-test/out/portable_engine_build_consumption.json",
    );
    assert.equal(selection.buildConsumptionDigest, build.consumptionDigest);
    assert.match(selection.cargoMessagesDigest, /^sha256-[0-9a-f]{64}$/u);

    const secondOut = join(root, "target/debug/build/ibex-runtime-other/out");
    mkdirSync(secondOut, { recursive: true, mode: 0o700 });
    writeFileSync(
      join(secondOut, "portable_engine_build_consumption.json"),
      canonicalJson(build),
      { mode: 0o600 },
    );
    writeFileSync(
      cargoMessagesPath,
      [out, secondOut]
        .map((out_dir) => JSON.stringify({ reason: "build-script-executed", out_dir }))
        .join("\n") + "\n",
    );
    assert.throws(
      () =>
        selectBuildConsumption({
          cargoMessagesPath,
          installation: installationFixture(),
          selectedRepoRoot: root,
        }),
      /selected 2 matching/u,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test(
  "Cargo stream refuses a build-consumption path redirected through target",
  { skip: process.platform === "win32" },
  () => {
    const root = realpathSync(
      mkdtempSync(join(tmpdir(), "ibex-portable-build-redirect-")),
    );
    const outside = realpathSync(
      mkdtempSync(join(tmpdir(), "ibex-portable-build-outside-")),
    );
    try {
      mkdirSync(join(root, "target"), { recursive: true, mode: 0o700 });
      const build = {
        schema: "ibex/portable-engine-build-consumption/1",
        portable: { artifactId: ARTIFACT_ID },
        target: { triple: TARGET },
        manifestDigest: installationFixture().manifestDigest,
        installationReceiptDigest:
          installationFixture().installationReceiptDigest,
        verificationPolicyDigest:
          installationFixture().verificationPolicyDigest,
        consumptionDigest: `sha256-${"C".repeat(43)}`,
      };
      writeFileSync(
        join(outside, "portable_engine_build_consumption.json"),
        canonicalJson(build),
        { mode: 0o600 },
      );
      const redirectedOut = join(root, "target/redirected-out");
      symlinkSync(outside, redirectedOut, "dir");
      const cargoMessagesPath = join(root, "target/cargo.jsonl");
      writeFileSync(
        cargoMessagesPath,
        `${JSON.stringify({ reason: "build-script-executed", out_dir: redirectedOut })}\n`,
        { mode: 0o600 },
      );
      assert.throws(
        () =>
          selectBuildConsumption({
            cargoMessagesPath,
            installation: installationFixture(),
            selectedRepoRoot: root,
          }),
        /redirected outside target/u,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  },
);
