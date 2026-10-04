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
   in `.github/workflows/hermes-vanilla-artifacts.yml`; the security test fails
   if they drift. Windows reads the same commit pin and therefore moves with
   every pin bump, while retaining its supported Release+debugger, Intl-off
   configuration.
2. Run the local checks and, where the host supports them, packaging dry runs:

   ```sh
   node --check scripts/hermes-input-receipt.mjs
   node --check scripts/hermes-vanilla-artifacts-workflow-security.test.mjs
   node --test scripts/hermes-vanilla-artifacts-workflow-security.test.mjs
   cargo test -p ibex2 receipt::tests --no-default-features
   actionlint .github/workflows/hermes-vanilla-artifacts.yml
   ./ref-check

   scripts/build-hermes-vanilla-release.sh \
     aarch64-apple-darwin /tmp/hermes-vanilla-aarch64-apple-darwin.tar.gz
   scripts/build-hermes-vanilla-release.sh \
     aarch64-apple-ios /tmp/hermes-vanilla-aarch64-apple-ios.tar.gz
   ```

3. After review, push and merge the branch. The orchestrator then runs the
   manual workflow; its checkout-free publisher creates the prerelease and all
   assets in one `gh release create`. If the tag already exists, publication
   fails. The workflow never edits, replaces, or deletes an existing release.

   ```sh
   git push -u origin l1c-release

   repo=expo/ibex
   ref=main
   workflow=hermes-vanilla-artifacts.yml
   source_revision="$(gh api "repos/$repo/commits/$ref" --jq .sha)"
   gh workflow run "$workflow" --repo "$repo" --ref "$ref"
   run_id=
   attempts=0
   while test -z "$run_id" && test "$attempts" -lt 30; do
     run_id="$(gh run list --repo "$repo" --workflow "$workflow" \
       --branch "$ref" --commit "$source_revision" --event workflow_dispatch \
       --limit 1 --json databaseId --jq '.[0].databaseId')"
     attempts=$((attempts + 1))
     test -n "$run_id" || sleep 2
   done
   test -n "$run_id"
   gh run watch "$run_id" --repo "$repo" --exit-status
   gh release view hermes-vanilla-d412d3bd8512-v1 --repo "$repo"
   ```

## Verify a published release

Verify both the ordinary checksum set and each retained Sigstore bundle. The
signer restriction prevents an attestation from another workflow in the same
repository from satisfying this check.

```sh
repo=expo/ibex
tag=hermes-vanilla-d412d3bd8512-v1
verify_dir="$(mktemp -d)"
gh release download "$tag" --repo "$repo" --dir "$verify_dir"
(cd "$verify_dir" && shasum -a 256 -c SHA256SUMS)

for archive in "$verify_dir"/hermes-vanilla-*.tar.gz; do
  gh attestation verify "$archive" \
    --repo "$repo" \
    --bundle "$archive.sigstore.json" \
    --signer-workflow expo/ibex/.github/workflows/hermes-vanilla-artifacts.yml
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

## Bump consumer pins

`hermes-lean-sys` pins the release URL, each selected archive SHA-256, and its
receipt SHA-256. Download the verified release, record those digests in the
target selector, and exercise cold-cache, warm-cache, offline-cache, and local
directory override cases before landing consumer updates. Never replace an
asset: a changed build or packaging authority receives a new release revision
suffix (`-v2`, `-v3`, and so on) and new consumer digests.
