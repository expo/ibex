# Vanilla Hermes release bundles

Ibex publishes vanilla Hermes separately from every patched-Hermes channel.
The release for the current pin is the immutable prerelease
`hermes-vanilla-d412d3bd8512-v1`. It contains seven deterministic archives,
`SHA256SUMS`, and one retained Sigstore bundle beside each archive.

Each archive contains the full-VM target link closure under `lib/`, host `hermesc`
under `bin/`, public headers under `include/`, the upstream license, and a
canonical `hermes-input-receipt.json`. Receipt v2 binds the source commit,
empty patch set, target, profile and build flags, HBC version, compiler,
archive/header digests, the explicit full-VM archive linked for the target, and
ordered Cargo link directives. Patched-symbol scanning and installed-engine
verification both use that exact archive path. The receipt deliberately has no
production date.

## Required repository settings

Apply these settings after the publisher workflow is merged to `main` and
before the first builder dispatch. Run the commands as a repository
administrator. They intentionally do not create a release or run a workflow.

```sh
repo=expo/ibex
api_version=2026-03-10
```

Enable immutable releases for all releases created after this setting:

```sh
gh api --method PUT \
  -H "X-GitHub-Api-Version: $api_version" \
  "repos/$repo/immutable-releases"
gh api -H "X-GitHub-Api-Version: $api_version" \
  "repos/$repo/immutable-releases" --jq '.enabled == true'
```

Protect `refs/tags/hermes-vanilla-*` with two aggregated tag rulesets. GitHub
ruleset bypass actors are GitHub Apps rather than individual workflow files,
so the first ruleset admits the GitHub Actions App for creation and update;
the repository's only `contents: write` workflow is the protected
default-branch publisher. The second ruleset has no bypass actor, making tag
deletion unavailable even to that App.

```sh
github_actions_app_id="$(gh api -H "X-GitHub-Api-Version: $api_version" \
  /apps/github-actions --jq .id)"
test -n "$github_actions_app_id"

publication_ruleset_id="$(
  gh api --method POST \
    -H "X-GitHub-Api-Version: $api_version" \
    "repos/$repo/rulesets" --input - --jq .id <<JSON
{
  "name": "Hermes vanilla tag publication",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [
    {
      "actor_id": $github_actions_app_id,
      "actor_type": "Integration",
      "bypass_mode": "always"
    }
  ],
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/hermes-vanilla-*"],
      "exclude": []
    }
  },
  "rules": [
    {"type": "creation"},
    {
      "type": "update",
      "parameters": {"update_allows_fetch_and_merge": false}
    }
  ]
}
JSON
)"
test -n "$publication_ruleset_id"

deletion_ruleset_id="$(
  gh api --method POST \
    -H "X-GitHub-Api-Version: $api_version" \
    "repos/$repo/rulesets" --input - --jq .id <<'JSON'
{
  "name": "Hermes vanilla tag deletion ban",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/hermes-vanilla-*"],
      "exclude": []
    }
  },
  "rules": [
    {"type": "deletion"}
  ]
}
JSON
)"
test -n "$deletion_ruleset_id"

gh api -H "X-GitHub-Api-Version: $api_version" \
  "repos/$repo/rulesets/$publication_ruleset_id" --jq \
  '{name,target,enforcement,bypass_actors,conditions,rules}'
gh api -H "X-GitHub-Api-Version: $api_version" \
  "repos/$repo/rulesets/$deletion_ruleset_id" --jq \
  '{name,target,enforcement,bypass_actors,conditions,rules}'
```

Create the secret-free `hermes-vanilla-release` environment and allow
deployments only from the `main` branch:

```sh
gh api --method PUT \
  -H "X-GitHub-Api-Version: $api_version" \
  "repos/$repo/environments/hermes-vanilla-release" --input - <<'JSON'
{
  "wait_timer": 0,
  "prevent_self_review": false,
  "reviewers": [],
  "deployment_branch_policy": {
    "protected_branches": false,
    "custom_branch_policies": true
  }
}
JSON

gh api --method POST \
  -H "X-GitHub-Api-Version: $api_version" \
  "repos/$repo/environments/hermes-vanilla-release/deployment-branch-policies" \
  -f name=main -f type=branch

gh api -H "X-GitHub-Api-Version: $api_version" \
  "repos/$repo/environments/hermes-vanilla-release"
gh api -H "X-GitHub-Api-Version: $api_version" \
  "repos/$repo/environments/hermes-vanilla-release/deployment-branch-policies" \
  --jq '{total_count,branch_policies}'
test "$(gh api -H "X-GitHub-Api-Version: $api_version" \
  "repos/$repo/environments/hermes-vanilla-release/secrets" \
  --jq .total_count)" = 0
```

Protect `main`: require a pull request with one non-author approval, dismiss
stale approvals, require approval after the last push, enforce the rule for
administrators, require linear history and resolved conversations, and forbid
force pushes and deletion. This command deliberately names no bypass actor
and no status check; add required checks separately once their stable check
names are known.

```sh
gh api --method PUT \
  -H "X-GitHub-Api-Version: $api_version" \
  "repos/$repo/branches/main/protection" --input - <<'JSON'
{
  "required_status_checks": null,
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 1,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": false
}
JSON

gh api -H "X-GitHub-Api-Version: $api_version" \
  "repos/$repo/branches/main/protection"
```

## Cut the release

1. Resolve an upstream tag to its exact commit and update
   `scripts/hermes-version.sh`. Update the fixed commit/tag/concurrency values
   in `.github/workflows/hermes-vanilla-build.yml` and
   `.github/workflows/hermes-vanilla-publish.yml`; the security test fails if
   they drift. Windows reads the same commit pin and therefore moves with every
   pin bump, while retaining its supported Release+debugger, Intl-off
   configuration.
2. Run the local checks and, where the host supports them, packaging dry runs:

   ```sh
   node --check scripts/hermes-input-receipt.mjs
   node --check scripts/hermes-vanilla-artifacts-workflow-security.test.mjs
   node --test scripts/hermes-vanilla-artifacts-workflow-security.test.mjs
   cargo test -p ibex2 receipt::tests --no-default-features
   actionlint .github/workflows/hermes-vanilla-build.yml
   actionlint .github/workflows/hermes-vanilla-publish.yml
   ./ref-check

   scripts/build-hermes-vanilla-release.sh \
     aarch64-apple-darwin /tmp/hermes-vanilla-aarch64-apple-darwin.tar.gz
   scripts/build-hermes-vanilla-release.sh \
     aarch64-apple-ios /tmp/hermes-vanilla-aarch64-apple-ios.tar.gz
   ```

3. After review, push and merge the branch. The orchestrator then dispatches
   the read-only builder on `main`. Its successful completion triggers the
   checkout-free publisher definition loaded by GitHub from the default
   branch. The publisher proceeds only for a `workflow_dispatch` builder run
   whose branch is `main` and whose source commit still equals the `main` head
   fetched through the API. It downloads the exact triggering run's handoffs
   by run ID, revalidates their names, sizes, and SHA-256 digests, then attests
   them. It first looks for a release using the requested tag. With no release,
   it refuses any pre-existing tag ref and creates a commit-bound marker-owned
   draft. It uploads all 15 assets, fetches the remote asset list, and requires
   the exact names, sizes, and SHA-256 digests before publishing the draft as a
   prerelease. A published release is never edited or deleted.

   ```sh
   git push -u origin l1c-release

   repo=expo/ibex
   ref=main
   builder_workflow=hermes-vanilla-build.yml
   publisher_workflow=hermes-vanilla-publish.yml
   source_revision="$(gh api "repos/$repo/commits/$ref" --jq .sha)"
   gh workflow run "$builder_workflow" --repo "$repo" --ref "$ref"
   builder_run_id=
   attempts=0
   while test -z "$builder_run_id" && test "$attempts" -lt 30; do
     builder_run_id="$(gh run list --repo "$repo" --workflow "$builder_workflow" \
       --branch "$ref" --commit "$source_revision" --event workflow_dispatch \
       --limit 1 --json databaseId --jq '.[0].databaseId')"
     attempts=$((attempts + 1))
     test -n "$builder_run_id" || sleep 2
   done
   test -n "$builder_run_id"
   gh run watch "$builder_run_id" --repo "$repo" --exit-status

   publisher_run_id=
   attempts=0
   while test -z "$publisher_run_id" && test "$attempts" -lt 30; do
     publisher_run_id="$(gh run list --repo "$repo" --workflow "$publisher_workflow" \
       --branch "$ref" --commit "$source_revision" --event workflow_run \
       --limit 1 --json databaseId --jq '.[0].databaseId')"
     attempts=$((attempts + 1))
     test -n "$publisher_run_id" || sleep 2
   done
   test -n "$publisher_run_id"
   gh run watch "$publisher_run_id" --repo "$repo" --exit-status
   gh release view hermes-vanilla-d412d3bd8512-v1 --repo "$repo"
   ```

## Recover a stuck draft

If the publisher stops after creating its draft but before publishing it,
leave the draft and tag namespace alone. After the underlying failure is
fixed, dispatch the builder again from the unchanged current `main`. The
publisher recognizes its own draft only by the
`<!-- ibex-hermes-vanilla-publisher:v1 source-sha=<commit> -->` body marker.
It requires that recorded commit to equal the newly authorized builder source
and requires the existing tag ref to point directly and exactly at that commit.
It then deletes only the draft's assets, confirms the asset set is empty,
uploads the complete 15-file set again, and repeats the exact remote name,
size, and SHA-256 verification before publishing. It never deletes or recreates
the draft or tag.

The recovery path refuses an unmarked draft, any published release, and any
draft whose recorded commit, current authorized source, and tag target do not
all agree. When no release exists, any existing `refs/tags/hermes-vanilla-*`
ref is also refused. Investigate those cases rather than deleting them through
the workflow; if the intended bytes or authority have changed, increment the
immutable release suffix (`-v2`, `-v3`, and so on).

## Verify a published release

Verify both the ordinary checksum set and each retained Sigstore bundle. The
signer restriction prevents an attestation from another workflow in the same
repository from satisfying this check.

```sh
repo=expo/ibex
tag=hermes-vanilla-d412d3bd8512-v1
source_revision="$(gh api "repos/$repo/git/ref/tags/$tag" --jq .object.sha)"
verify_dir="$(mktemp -d)"
gh release download "$tag" --repo "$repo" --dir "$verify_dir"
(cd "$verify_dir" && shasum -a 256 -c SHA256SUMS)

for archive in "$verify_dir"/hermes-vanilla-*.tar.gz; do
  gh attestation verify "$archive" \
    --repo "$repo" \
    --bundle "$archive.sigstore.json" \
    --signer-workflow expo/ibex/.github/workflows/hermes-vanilla-publish.yml \
    --cert-identity \
      https://github.com/expo/ibex/.github/workflows/hermes-vanilla-publish.yml@refs/heads/main \
    --source-ref refs/heads/main \
    --source-digest "$source_revision" \
    --signer-digest "$source_revision"
  tar -xOzf "$archive" hermes-input-receipt.json | jq -e '
    .schema == "ibex/hermes-upstream-pinned-receipt/2" and
    .upstream.sourceCommit == "d412d3bd851278712c20cca25d094e32641a0465" and
    .patchSet.applied == [] and
    (.producedOn | not) and
    (.engine.binary == "lib/libhermesvm_a.a" or
      .engine.binary == "lib/hermesvm_a.lib") and
    (.archives | length > 0) and
    (.headers | length > 0) and
    (.linkDirectives | length > 0)'
done
```

This checks the downloaded bytes against `SHA256SUMS`; verifies the retained
Sigstore bundle for each archive; requires the attestation repository and
signer workflow to be `expo/ibex` and the publisher path above; requires the
certificate subject to bind that workflow to `refs/heads/main`; and requires
both the source and signer digests to equal the Ibex commit named by the
release tag. Separately, the receipt check binds the archive contents to the
pinned upstream Hermes commit, an empty patch set, and the closed v2
archive/header/link manifests.

## Bump consumer pins

`hermes-lean-sys` pins the release URL, each selected archive SHA-256, and its
receipt SHA-256. Download the verified release, record those digests in the
target selector, and exercise cold-cache, warm-cache, offline-cache, and local
directory override cases before landing consumer updates. Never replace an
asset: a changed build or packaging authority receives a new release revision
suffix (`-v2`, `-v3`, and so on) and new consumer digests.
