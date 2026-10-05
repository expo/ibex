# Vanilla Hermes release bundles

Ibex publishes vanilla Hermes separately from every patched-Hermes channel.
The next immutable prerelease is `hermes-vanilla-d412d3bd8512-v2`. It contains
seven deterministic archives, `SHA256SUMS`, and one retained Sigstore bundle
beside each archive. The immutable v1 release contains only the full VM and
cannot gain the lean archive, which is why this uses a new release namespace.

Each v2 archive contains both the full `hermesvm_a` and lean
`hermesvmlean_a` target archives under `lib/`, the rest of their target link
closure, host `hermesc` under `bin/`, public headers under `include/`, the
upstream license, and a canonical `hermes-input-receipt.json`. Receipt v2 binds
the source commit, empty patch set, target, profile and build flags, HBC
version, compiler, and every archive/header digest. `engine.binary` remains the
full VM for compatibility; the lean VM is bound by the same archive manifest.
Receipt generation scans both VM archives for patched exports whenever lean is
present, and lean selection verifies its distinct manifest digest. The receipt
deliberately has no production date.

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

Full branch protection on `main` is not applied, by Charlie's decision on
2026-10-04, and is not a release prerequisite. The active `Default branch
protections` ruleset targets `~DEFAULT_BRANCH` and blocks both deletion and
non-fast-forward updates (force-pushes).

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
   # Run only after the reviewed release change has been merged to main.
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
   gh release view hermes-vanilla-d412d3bd8512-v2 --repo "$repo"
   ```

### First publication (2026-10-04)

The first immutable publication used builder run
[37229325065](https://github.com/expo/ibex/actions/runs/37229325065) and
publisher run
[37230233860](https://github.com/expo/ibex/actions/runs/37230233860). Both ran
from `321cc6d2b80ced4dd22ac482fe12c180e7bac473`, and the published tag
`hermes-vanilla-d412d3bd8512-v1` resolves directly to that commit.

Post-publication verification downloaded the release, passed every
`SHA256SUMS` check, and verified all seven retained attestations. Each
attestation was checked with the publisher workflow certificate identity on
`refs/heads/main`, `--source-ref refs/heads/main`, and both `--source-digest`
and `--signer-digest` set to the full `321cc6d…` tag target above.

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
increment the immutable release suffix (`-v3`, `-v4`, and so on).

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
tag=hermes-vanilla-d412d3bd8512-v2
source_revision="$(gh api "repos/$repo/git/ref/tags/$tag" --jq .object.sha)"
verify_dir="$(mktemp -d)"
gh release download "$tag" --repo "$repo" --dir "$verify_dir"
(cd "$verify_dir" && shasum -a 256 -c SHA256SUMS)

for archive in "$verify_dir"/hermes-vanilla-*.tar.gz; do
  gh attestation verify "$archive" \
    --repo "$repo" \
    --bundle "$archive.sigstore.json" \
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
    (any(.archives[];
      .path == "lib/libhermesvmlean_a.a" or
      .path == "lib/hermesvmlean_a.lib")) and
    (.archives | length > 0) and
    (.headers | length > 0) and
    (.linkDirectives | length > 0)'
done
```

This checks the downloaded bytes against `SHA256SUMS`; verifies the retained
Sigstore bundle for each archive; and uses the certificate identity to bind
the publisher workflow path specifically to `refs/heads/main`. The source and
signer digests must both equal the Ibex commit named by the release tag.
Separately, the receipt check binds the archive contents to the pinned upstream
Hermes commit, an empty patch set, and the closed v2 archive/header/link
manifests. Do not combine `--cert-identity` with `--signer-workflow`: `gh`
rejects that pair.

## Consuming the bundles

`hermes-lean-sys` is the supported consumer. Until v2 is published and its
seven checksums are independently verified, its release table intentionally
stays on immutable v1 with the real v1 digests and full-VM-only behavior. It
resolves a complete
`HERMES_LEAN_SYS_DIR` first, this repository's local platform install second,
and the release bundle pinned for Cargo's exact target triple otherwise. Both
the legacy repository layout (`hermes-headers` plus the platform static-library
directory) and the published layout (`include/`, `lib/`, and `bin/hermesc`) are
accepted for local installs. A published-layout override is complete only with
its v2 receipt; a legacy repository-layout install may omit one. Unsupported
triples are refused with instructions to provide `HERMES_LEAN_SYS_DIR`;
`aarch64-apple-ios-sim` and
`x86_64-apple-ios` both select the universal iOS Simulator archive.

The `link` feature emits the full VM's link line; `link-lean` emits the lean
VM's link line, and the two features are mutually exclusive. Resolution still
exports both archive paths and, when present, both digests in every feature
context. Downstream build scripts receive `DEP_HERMES_LEAN_ARCHIVE` and
`DEP_HERMES_LEAN_ENGINE_DIGEST` for full, plus
`DEP_HERMES_LEAN_LEAN_ARCHIVE` and `DEP_HERMES_LEAN_LEAN_ENGINE_DIGEST` for
lean. With either link feature active, `DEP_HERMES_LEAN_LINKED_ARCHIVE` and
`DEP_HERMES_LEAN_LINKED_ENGINE_DIGEST` identify what that process links. This
is the R-e identity: a process never reports the full digest while linking
lean. Legacy local layouts may omit lean; they fail only if `link-lean` is
requested. Published v2 bundles must carry and manifest both.

The downloader uses rustls with WebPKI roots and always verifies the pinned
archive SHA-256 before inspecting or extracting the tarball. Extraction
preflights the complete archive and accepts only relative regular-file and
directory entries: absolute paths, parent traversal, links, and special files
are refused. Completed installs are atomically renamed into
`$CARGO_HOME/hermes-lean-sys/<tag>/<archive-sha256>/`, with Cargo home defaulting
to `$HOME/.cargo` (or the platform home equivalent). The verified tarball is
retained in the cache entry. Every admission rehashes it against the source
pin, rebuilds a per-file manifest from its members, and compares that manifest
with the extracted tree, including refusal of missing, changed, extra, linked,
or special entries.

`CARGO_NET_OFFLINE=true` and `HERMES_LEAN_SYS_OFFLINE=1` both prohibit a
download. In offline mode a valid warm cache entry or local override is
required. `HERMES_LEAN_SYS_MIRROR` replaces
`https://github.com/expo/ibex/releases/download` as the base URL and must serve
`<tag>/<asset>` beneath that base; mirrors do not replace digest verification.

For cross compilation, `hermesc` comes from the pinned host bundle while the
headers and archives come from the target bundle. Its reported HBC bytecode
version must match the target receipt. For every published bundle, and every
local install carrying a receipt, the receipt's engine path and digest must
name the archive `hermes-lean-sys` selected. Before `hermesc` executes, its
digest must match the compiler digest in the receipt of the host bundle that
supplied it. The target receipt authenticates the target engine and HBC
version; its compiler digest need not equal the independently built host
compiler's digest. The full and lean VMs from one source build share that HBC
version; the bindings build asserts the equality, and the lean embedding test
checks it against the runtime API.

## Bump consumer pins

Only after completing every `gh attestation verify` command in the preceding
section, update the target table from that same downloaded checksum file:

```sh
node scripts/update-hermes-lean-sys-pins.mjs "$verify_dir/SHA256SUMS"
```

The script requires all seven archive checksums and rewrites the duplicate
universal-simulator mappings consistently. Review the resulting source diff,
then exercise cold-cache, warm-cache, offline-cache, mirror, and local-directory
override cases on the follow-up lean-selection branch before landing consumer
updates. Never replace an asset: a
changed build or packaging authority receives a new release revision suffix
(`-v3`, `-v4`, and so on) and new consumer digests.
Until v2 is published and all seven attestations pass, the pin table
deliberately retains the verified v1 SHA-256 values as placeholders. They do
not authenticate v2 assets and must be replaced only by the procedure above.
