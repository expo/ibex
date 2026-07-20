// @ref LLP 0035#promotion-lineage-and-admission — the physical source-A
// workflow can emit only an immutable candidate artifact. It has no repository
// write authority and contains no mechanism that can manufacture P or C.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const workflowPath = path.join(
  repoRoot,
  ".github/workflows/portable-engine-physical-promotion.yml",
);
const workflow = fs.readFileSync(workflowPath, "utf8");

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

function namedStep(name) {
  const step = stepBlocks(jobBlocks().get("physical_promotion")).find(
    (candidate) => candidate.name === name,
  );
  assert.ok(step, `missing workflow step ${name}`);
  return step.text;
}

test("ceremony is one bounded GitHub-hosted runner with no repository write authority", () => {
  const jobs = jobBlocks();
  assert.deepEqual([...jobs.keys()], ["physical_promotion"]);
  const job = jobs.get("physical_promotion");
  assert.match(workflow, /^permissions: \{\}$/m);
  assert.deepEqual(permissions(job), { actions: "read", contents: "read" });
  assert.match(job, /^    runs-on: macos-14$/m);
  assert.match(job, /^    timeout-minutes: 360$/m);
  assert.doesNotMatch(job, /^    (?:strategy|container|services|environment):/m);
  assert.doesNotMatch(
    workflow,
    /^\s+(?:actions|attestations|contents|id-token|issues|packages|pages|pull-requests|security-events): write$/m,
  );
  assert.doesNotMatch(workflow, /continue-on-error:|cancel-in-progress: true/u);
  assert.match(
    workflow.slice(0, workflow.indexOf("\njobs:\n")),
    /\non:\n  workflow_dispatch:\n/u,
  );
  assert.doesNotMatch(
    workflow.slice(0, workflow.indexOf("\njobs:\n")),
    /^  (?:push|pull_request|workflow_run|schedule):/m,
  );
  assert.match(
    workflow,
    /group: portable-engine-physical-promotion-\$\{\{ github\.sha \}\}/u,
  );
  for (const step of stepBlocks(job)) {
    assert.match(
      step.text,
      /^        timeout-minutes: (?:5|10|15|20|30|90)$/m,
      `${step.name} must have one explicit timeout`,
    );
  }
});

test("every action is commit-pinned and checkout is the exact uncredentialed source A", () => {
  const references = [...workflow.matchAll(/^\s+uses: ([^\s#]+)/gm)].map(
    (match) => match[1],
  );
  const approved = new Set([
    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6",
    "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
  ]);
  assert.equal(references.length, 5);
  for (const reference of references) {
    assert.match(
      reference,
      /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/u,
    );
    assert.ok(approved.has(reference), `unapproved action ${reference}`);
  }
  const checkout = namedStep("Check out exact source A without credentials");
  assert.match(checkout, /\n          ref: \$\{\{ github\.sha \}\}\n/u);
  assert.match(checkout, /\n          fetch-depth: 0\n/u);
  assert.match(checkout, /\n          persist-credentials: false\n/u);
  const boundary = namedStep("Assert trusted source-A and same-runner boundary");
  for (const required of [
    '"$GITHUB_REPOSITORY" == "ccheever/ibex"',
    '"$GITHUB_REF" == "refs/heads/main"',
    '"$RUNNER_ENVIRONMENT" == "github-hosted"',
    '"$WORKFLOW_SHA" == "$GITHUB_SHA"',
    "git merge-base --is-ancestor",
    "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
    "checkout left a persisted Git credential",
  ]) {
    assert.ok(boundary.includes(required), `source-A boundary omits ${required}`);
  }
});

test("release transport joins the exact four revision-scoped assets before production install", () => {
  const coordinates = namedStep(
    "Derive the exact revision-scoped release coordinates",
  );
  assert.match(
    coordinates,
    /release_tag="hermes-portable-\$\{identity\}-\$\{GITHUB_SHA\}"/u,
  );
  assert.match(
    coordinates,
    /archive_name="hermes-portable-macos-arm64-release-\$\{cache_key\}-\$\{GITHUB_SHA\}\.tar\.gz"/u,
  );
  const resolve = namedStep("Resolve one exact four-member portable release");
  assert.match(resolve, /releases\/tags\/\$RELEASE_TAG/u);
  assert.match(
    resolve,
    /portable-engine-physical-promotion\.mjs plan-release/u,
  );
  assert.match(
    resolve,
    /target\/portable-engine-physical-promotion\/release-plan\.json/u,
  );
  const download = namedStep(
    "Download and rejoin exact release assets by immutable IDs",
  );
  assert.match(download, /releases\/assets\/\$asset_id/u);
  assert.match(download, /Accept: application\/octet-stream/u);
  assert.match(download, /verify-release-download/u);
  assert.match(download, /release-after\.json/u);
  assert.doesNotMatch(workflow, /gh release download|browser_download_url/u);

  const install = namedStep("Production-install the diagnostic source-A package");
  assert.match(install, /install-source-a/u);
  assert.match(install, /checkedAdmission\.authorized !== false/u);
  assert.doesNotMatch(install, /test-harness|verifyAttestation|dependencies/u);
  const runJoin = namedStep("Rejoin the signed producer run and exact attempt");
  assert.match(
    runJoin,
    /actions\/runs\/\$PRODUCER_RUN_ID\/attempts\/\$PRODUCER_RUN_ATTEMPT/u,
  );
  assert.match(runJoin, /verify-producer-run/u);
});

test("the only Cargo build is the exact checked set and its JSON stream gates post-link", () => {
  const build = namedStep("Build the exact checked Cargo executable set");
  assert.equal(
    (workflow.match(/node scripts\/run-portable-hermes-cargo\.mjs/g) ?? [])
      .length,
    1,
  );
  assert.match(build, /\| tee "\$cargo_messages"/u);
  assert.doesNotMatch(workflow, /^\s+cargo (?:build|test|bench|run)\b/gm);
  const checked = JSON.parse(
    fs.readFileSync(
      path.join(
        repoRoot,
        "config/portable-engine-cargo-executables-authenticated-v1.json",
      ),
      "utf8",
    ),
  );
  const exactInvocation = checked.cargoArguments
    .map((argument) =>
      argument === "--features"
        ? argument
        : argument,
    )
    .join(" ");
  assert.ok(
    build.replaceAll("\\\n", " ").replaceAll(/\s+/gu, " ").includes(exactInvocation),
    `workflow Cargo invocation differs from checked arguments: ${exactInvocation}`,
  );
  const selection = namedStep(
    "Select build consumption only from the retained Cargo stream",
  );
  assert.match(selection, /select-build-consumption/u);
  assert.match(selection, /cargo-messages\.jsonl/u);
  const postLink = namedStep(
    "Verify the complete production post-link executable set",
  );
  assert.match(postLink, /scripts\/portable-engine-post-link\.mjs/u);
  assert.match(postLink, /\/COMPLETE\.json/u);
  assert.ok(
    workflow.indexOf("Verify the complete production post-link executable set") <
      workflow.indexOf("Run complete v2 conformance and promotion-bundle generation"),
    "post-link complete-set verification must precede conformance",
  );
});

test("only independently derived complete inputs can reach the v2 bundle generator", () => {
  const targetCells = namedStep("Derive complete promotion target cells or refuse");
  assert.match(
    targetCells,
    /generate-capsec-portable-promotion-target-cells\.mjs/u,
  );
  assert.doesNotMatch(
    targetCells,
    /capsec\/registry\/target-cells\.json/u,
  );
  const outputEvidence = namedStep(
    "Produce complete output-disposition evidence or refuse",
  );
  assert.match(outputEvidence, /run-capsec-output-shape-sweep\.mjs/u);
  const conformance = namedStep(
    "Run complete v2 conformance and promotion-bundle generation",
  );
  for (const required of [
    "verify:capsec-conformance",
    "--portable-promotion-target-cells",
    "--portable-promotion-output",
    "--output-disposition-evidence",
  ]) {
    assert.ok(conformance.includes(required), `v2 generator omits ${required}`);
  }
  assert.doesNotMatch(conformance, /--expect-incomplete|\|\| true|continue-on-error/u);
  assert.match(
    workflow,
    /first expected refusal at the current source A:[\s\S]*rich[\s\S]*unresolved fixtures/u,
  );
});

test("candidate publication is reverified, frozen, immutable, and distinct from diagnostics", () => {
  const verify = namedStep("Reverify and freeze locality-free publication bytes");
  assert.equal(
    (
      verify.match(
        /verify-capsec-portable-promotion-bundle\.mjs/g,
      ) ?? []
    ).length,
    2,
  );
  assert.match(verify, /find "\$directory" -type f -exec chmod 0444/u);
  assert.match(verify, /chmod 0555 "\$directory"/u);
  assert.match(verify, /"\$frozen_digest" == "\$digest"/u);

  const upload = namedStep("Upload immutable portable promotion candidate");
  assert.match(
    upload,
    /name: portable-promotion-macos-arm64-\$\{\{ github\.sha \}\}-\$\{\{ steps\.bundle\.outputs\.bundle_digest \}\}/u,
  );
  assert.match(upload, /overwrite: false/u);
  assert.match(upload, /archive: true/u);
  assert.match(upload, /compression-level: 0/u);
  assert.match(
    upload,
    /path: target\/portable-engine-physical-promotion\/promotion-bundle\/\*\*/u,
  );
  assert.doesNotMatch(upload, /if: always\(\)/u);

  const diagnostic = namedStep(
    "Retain bounded diagnostic build and refusal evidence",
  );
  assert.match(diagnostic, /if: always\(\)/u);
  assert.match(diagnostic, /cargo-messages\.jsonl/u);
  assert.match(diagnostic, /release-plan\.json/u);
  assert.doesNotMatch(diagnostic, /promotion-bundle\/\*\*/u);
  assert.match(diagnostic, /overwrite: false/u);
  assert.match(diagnostic, /archive: true/u);
});

test("workflow contains no promotion-lineage or repository mutation mechanism", () => {
  assert.doesNotMatch(
    workflow,
    /portable-engine-promotion-lineage|^\s+git (?:commit|push|merge |rebase|tag|checkout -b|switch -c)|gh pr |gh api[^\n]*--method (?:POST|PATCH|PUT|DELETE)|gh release (?:create|edit|upload|delete)/mu,
  );
  assert.doesNotMatch(
    workflow,
    /schemas\/portable-engine-promotion-admission-catalog-v1\.json[^\n]*(?:>|tee)|capsec\/generated\/target-advertisements\.json[^\n]*(?:>|tee)/u,
  );
});
