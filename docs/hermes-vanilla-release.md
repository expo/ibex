# Vanilla Hermes release bundles

Ibex publishes vanilla Hermes separately from every patched-Hermes channel.
The release for the current pin is the immutable prerelease
`hermes-vanilla-d412d3bd8512-v1`. It contains seven deterministic archives,
`SHA256SUMS`, and one retained Sigstore bundle beside each archive.

Each archive contains the lean target link closure under `lib/`, host `hermesc`
under `bin/`, public headers under `include/`, the upstream license, and a
canonical `hermes-input-receipt.json`. Receipt v2 binds the source commit,
empty patch set, target, profile and build flags, HBC version, compiler,
archive/header digests, and ordered Cargo link directives. It deliberately has
no production date.

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
   them. Before creating a release it refuses any pre-existing tag ref. It
   creates a marker-owned draft, uploads all 15 assets, fetches the remote
   asset list, and requires the exact names, sizes, and SHA-256 digests before
   publishing the draft as a prerelease. A published release is never edited
   or deleted.

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
`<!-- ibex-hermes-vanilla-publisher:v1 -->` body marker, deletes that draft,
and restarts from an empty release. It will not reuse partially uploaded
assets.

The recovery path refuses an unmarked draft, any published release, and any
existing `refs/tags/hermes-vanilla-*` ref. Investigate those cases rather than
deleting them through the workflow; if the intended bytes or authority have
changed, increment the immutable release suffix (`-v2`, `-v3`, and so on).

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
