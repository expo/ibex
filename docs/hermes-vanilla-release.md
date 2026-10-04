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

Protect `refs/tags/hermes-vanilla-*` from deletion with a tag ruleset that has
no bypass actor, so no one, including the publisher, can delete a release tag.

A second ruleset restricting tag creation and update to the GitHub Actions App
was planned, but GitHub refuses that App as a bypass actor unless it is part
of the ruleset's owner organization ("Actor GitHub Actions integration must be
part of the ruleset source or owner organization", HTTP 422, 2026-10-04). The
publisher doesn't depend on it: it refuses a pre-existing tag before creating
its draft, publication creates the tag from `--target`, immutable releases then
lock the tag, and the post-publication check requires the tag to name the
authorized source commit. A planted tag can only make the publisher refuse,
which is resolved with the next suffix.

```sh
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
   it refuses any pre-existing tag ref and creates a commit-bound draft; any
   existing release with that tag is refused. It uploads all 15 assets, fetches the remote asset list, and requires
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

The publisher never adopts, edits, or deletes an existing release. If any
release named the requested tag exists, draft or published, it fails. A body
marker cannot prove a draft is the publisher's own (any writer can reproduce
it), a draft need not carry a tag yet, and an adopted draft would keep title
and notes this workflow did not write.

If a run stops after creating its draft but before publishing it:

1. Inspect the draft (`gh release view <tag> --repo expo/ibex`) and record why
   the run failed.
2. Confirm the tag does not exist (`gh api repos/expo/ibex/git/ref/tags/<tag>`
   returns 404). GitHub creates a draft's tag only when the draft is published,
   so a stuck draft normally has none.
3. Delete the draft through the web UI or
   `gh api --method DELETE repos/expo/ibex/releases/<release-id>`. Deleting a
   draft never deletes a tag, so the tag deletion ban stays as configured.
4. After the underlying failure is fixed, dispatch the builder again from the
   unchanged current `main`.

If the tag already exists, or a published release exists, don't delete either:
increment the immutable release suffix (`-v2`, `-v3`, and so on).

After publication the workflow re-reads the release. It requires it to be a
non-draft, immutable prerelease with the exact 15-asset set and digests, and
its tag to name the authorized source commit directly. GitHub's update
endpoint has no compare-and-swap, so a writer with `contents: write` could
swap an asset between the draft check and publication. This final check turns
that race into a failed run on an immutable release, which is then superseded
with the next suffix. Consumers pin the archive digests independently of the
release object.

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

## Consuming the bundles

`hermes-lean-sys` is the supported consumer. It resolves a complete
`HERMES_LEAN_SYS_DIR` first, this repository's local platform install second,
and the release bundle pinned for Cargo's exact target triple otherwise. Both
the legacy repository layout (`hermes-headers` plus the platform static-library
directory) and the published layout (`include/`, `lib/`, and `bin/hermesc`) are
accepted for local installs. A published-layout override is complete only with
its v2 receipt; a legacy repository-layout install may omit one. Unsupported
triples are refused with instructions to provide `HERMES_LEAN_SYS_DIR`;
`aarch64-apple-ios-sim` and
`x86_64-apple-ios` both select the universal iOS Simulator archive.

The downloader uses rustls with WebPKI roots and always verifies the pinned
archive SHA-256 before inspecting or extracting the tarball. Extraction
preflights the complete archive and accepts only relative regular-file and
directory entries: absolute paths, parent traversal, links, and special files
are refused. Completed installs are atomically renamed into
`$CARGO_HOME/hermes-lean-sys/<tag>/<archive-sha256>/`, with Cargo home defaulting
to `$HOME/.cargo` (or the platform home equivalent). A cache entry is reused
only when its recorded archive digest equals the pin.

`CARGO_NET_OFFLINE=true` and `HERMES_LEAN_SYS_OFFLINE=1` both prohibit a
download. In offline mode a valid warm cache entry or local override is
required. `HERMES_LEAN_SYS_MIRROR` replaces
`https://github.com/expo/ibex/releases/download` as the base URL and must serve
`<tag>/<asset>` beneath that base; mirrors do not replace digest verification.

For cross compilation, `hermesc` comes from the pinned host bundle while the
headers and archives come from the target bundle. Its reported HBC bytecode
version must match the target receipt. For every published bundle, and every
local install carrying a receipt, the receipt's engine path and digest must
name the archive `hermes-lean-sys` selected. A recorded compiler digest must
likewise equal the selected `hermesc`, preventing a receipt from describing a
different compiler than the one that produced binding bytecode.

## Bump consumer pins

Only after completing every `gh attestation verify` command in the preceding
section, update the target table from that same downloaded checksum file:

```sh
node scripts/update-hermes-lean-sys-pins.mjs "$verify_dir/SHA256SUMS"
```

The script requires all seven archive checksums and rewrites the duplicate
universal-simulator mappings consistently. Review the resulting source diff,
then exercise cold-cache, warm-cache, offline-cache, mirror, and local-directory
override cases before landing consumer updates. Never replace an asset: a
changed build or packaging authority receives a new release revision suffix
(`-v2`, `-v3`, and so on) and new consumer digests.
