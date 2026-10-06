# Vanilla Hermes release bundles

Ibex publishes vanilla Hermes separately from every patched-Hermes channel.
The next immutable prerelease is `hermes-vanilla-d412d3bd8512-v4`. It contains
nine deterministic archives, `SHA256SUMS`, and one retained Sigstore bundle
beside each archive. The immutable v1 release contains only the full VM; v2
added the lean VM but cannot gain the new Linux ICU profile, so v3 uses a new
release namespace. The immutable v3 release cannot gain tvOS bundles or the
debugger-off Windows engine, so those changes use the v4 namespace.

Each v4 archive contains both the full `hermesvm_a` and lean
`hermesvmlean_a` target archives under `lib/`, the rest of their target link
closure, host `hermesc` under `bin/`, public headers under `include/`, the
upstream license, and a canonical `hermes-input-receipt.json`. Receipt v2 binds
the source commit, empty patch set, target, profile and build flags, HBC
version, compiler, and every archive/header digest. `engine.binary` remains the
full VM for compatibility; the lean VM is bound by the same archive manifest.
Receipt generation scans both VM archives for patched exports whenever lean is
present, and lean selection verifies its distinct manifest digest. The receipt
deliberately has no production date.

Linux v3 bundles build ICU 74.2 from tag `release-74-2`, verified at commit
`2d029329c82c7792b985024b2bdab5fc7278fbc8`. They carry shared
`libicui18n.a` and `libicuuc.a` code archives, `libicudata.a` as the default
root+en trimmed data, and `libicudata-full.a` as the opt-in full locale data.
The canonical filter is `scripts/icu74-filter-root-en.json`, SHA-256
`c5d1b182d6e92212ff4952d7a5c956f3d54611f300cb6fa1fdca39a6510f9702`;
it is copied into each Linux bundle as `share/icu/filters-root-en.json`.
Receipt `icu` metadata binds the ICU tag, commit, version, both data paths,
the shared code paths, and that filter digest. Both data archives are also in
the ordinary sorted archive manifest, so they receive the same digest and
cache-tree verification as every other static archive.

The Linux jobs run in the multi-platform `rust:1.97-bookworm` OCI image pinned
at
`sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97`,
matching the filtering spike. Both `linux/amd64` and `linux/arm64` resolve
through that index. Packages come from the Debian and Debian Security snapshots
at `20261005T000000Z`; every directly requested package has an exact version in
`build-hermes-vanilla-linux-in-container.sh`, while transitive dependencies are
bounded by that immutable snapshot. The earlier v1 and v2 Linux builds used the
GitHub runner's system packages; v3 tightens the build environment by pinning
the container, repository snapshot, and requested package versions.

To update the Linux environment, resolve the tag's current OCI index digest,
confirm that it contains both workflow platforms, choose one UTC Debian
snapshot timestamp, and query every requested package's candidate version for
both architectures. Update the two Linux container scripts, the workflow
security test, and this paragraph together, then rebuild and inspect both Linux
bundles. Do not update the tag without its digest or move the snapshot while
retaining old version pins.

ICU uses two make jobs; Hermes uses at most four Ninja jobs and a two-slot link
pool. Hermes is configured with `HERMES_ENABLE_INTL=false`,
`HERMES_UNICODE_LITE=false`, and `HERMES_USE_STATIC_ICU=true`. Apple keeps
`HERMES_ENABLE_INTL=true`. Windows v4 disables the debugger and uses the same
`release` receipt profile as Linux; as before, the receipt records
`HERMES_ENABLE_WIN10_ICU_FALLBACK=ON` plus the `icuuc` and
`icuin` import-library link directives, while pinned Hermes's CMake source
selects its `USE_WIN10_ICU` declarations (marked `dllimport`) and reports
"Using Windows 10 built-in ICU" when no separately installed ICU is found.
Thus the Windows build continues to use the OS ICU DLL for its Unicode
backend; v4 adds no packaged Windows ICU archive.

## Bundle set

| Receipt target | Archive | Runner | Profile | v4 dry-run size |
| --- | --- | --- | --- | ---: |
| `aarch64-apple-darwin` | `hermes-vanilla-aarch64-apple-darwin.tar.gz` | `macos-15-xlarge` | `min-size-release` | not rebuilt in I3 |
| `x86_64-apple-darwin` | `hermes-vanilla-x86_64-apple-darwin.tar.gz` | `macos-15-large` | `min-size-release` | not rebuilt in I3 |
| `aarch64-apple-ios` | `hermes-vanilla-aarch64-apple-ios.tar.gz` | `macos-15-xlarge` | `min-size-release` | not rebuilt in I3 |
| `universal-apple-ios-simulator` | `hermes-vanilla-universal-apple-ios-simulator.tar.gz` | `macos-15-xlarge` | `min-size-release` | not rebuilt in I3 |
| `aarch64-apple-tvos` | `hermes-vanilla-aarch64-apple-tvos.tar.gz` | `macos-15-xlarge` | `min-size-release` | 6,365,983 B |
| `aarch64-apple-tvos-simulator` | `hermes-vanilla-aarch64-apple-tvos-simulator.tar.gz` | `macos-15-xlarge` | `min-size-release` | 6,364,463 B |
| `x86_64-unknown-linux-gnu` | `hermes-vanilla-x86_64-unknown-linux-gnu.tar.gz` | `ubuntu-24.04` | `release` | not rebuilt in I3 |
| `aarch64-unknown-linux-gnu` | `hermes-vanilla-aarch64-unknown-linux-gnu.tar.gz` | `ubuntu-24.04-arm` | `release` | not rebuilt in I3 |
| `x86_64-pc-windows-msvc` | `hermes-vanilla-x86_64-pc-windows-msvc.tar.gz` | `windows-2022` | `release` | not buildable on macOS |

The simulator receipt and archive use `aarch64-apple-tvos-simulator`, following
the iOS simulator bundle's `-simulator` spelling. They deliberately omit
`universal`: only the arm64 tvOS Simulator is built. Rust does have
`x86_64-apple-tvos` (the Intel tvOS Simulator), but no bundle covers it and it
is deliberately unmapped, so a build for it needs `HERMES_LEAN_SYS_DIR`. The Rust
target `aarch64-apple-tvos-sim` maps to that receipt.

## Runners

The macOS, iOS, and tvOS builder jobs run on GitHub's larger hosted macOS runners
(`macos-15-xlarge`, Apple silicon; `macos-15-large`, Intel), which draw on the
`expo` organization's dedicated larger-runner capacity rather than the shared
standard pool. On 2026-10-05 the v3 build's standard `macos-15` jobs waited
about two hours behind an organization-wide queue and one was cancelled before
it received a runner; a probe on 2026-10-06 started both larger labels within
seconds. They use the same macOS 15 image family and Xcode as the standard
labels, so the build environment is unchanged. Linux and Windows jobs keep the
standard hosted runners.

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
   pin bump, while retaining its supported Release, debugger-off, Intl-off
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
   scripts/build-hermes-vanilla-release.sh \
     aarch64-apple-tvos /tmp/hermes-vanilla-aarch64-apple-tvos.tar.gz
   scripts/build-hermes-vanilla-release.sh \
     aarch64-apple-tvos-simulator \
     /tmp/hermes-vanilla-aarch64-apple-tvos-simulator.tar.gz
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
   existing release with that tag is refused. It uploads all 19 assets, fetches
   the remote asset list, and requires
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
   gh release view hermes-vanilla-d412d3bd8512-v4 --repo "$repo"
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
increment the immutable release suffix (`-v4`, `-v5`, and so on).

After publication the workflow re-reads the release. It requires it to be a
non-draft, immutable prerelease with the exact 19-asset set and digests, and
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
tag=hermes-vanilla-d412d3bd8512-v4
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
    (.linkDirectives | length > 0) and
    (if (.target | endswith("-unknown-linux-gnu")) then
      .icu.upstream.sourceCommit == "2d029329c82c7792b985024b2bdab5fc7278fbc8" and
      .icu.upstream.sourceRef == "release-74-2" and
      .icu.upstream.sourceVersion == "74.2" and
      .icu.codeArchives == ["lib/libicui18n.a", "lib/libicuuc.a"] and
      .icu.data.trimmed.archive == "lib/libicudata.a" and
      .icu.data.full.archive == "lib/libicudata-full.a" and
      .icu.data.trimmed.filter.path == "share/icu/filters-root-en.json" and
      .icu.data.trimmed.filter.digest == "sha256-c5d1b182d6e92212ff4952d7a5c956f3d54611f300cb6fa1fdca39a6510f9702" and
      any(.archives[]; .path == "lib/libicudata.a") and
      any(.archives[]; .path == "lib/libicudata-full.a")
    else (.icu | not) end)'
done
```

This checks the downloaded bytes against `SHA256SUMS`; verifies the retained
Sigstore bundle for each archive; and uses the certificate identity to bind
the publisher workflow path specifically to `refs/heads/main`. The source and
signer digests must both equal the Ibex commit named by the release tag.
Separately, the receipt check binds the archive contents to the pinned upstream
Hermes commit, an empty patch set, and the closed receipt-v2 archive/header/link
manifests. Do not combine `--cert-identity` with `--signer-workflow`: `gh`
rejects that pair.

## Consuming the bundles

`hermes-lean-sys` is the supported consumer. The pipeline commits remain on
independently verified immutable v3 asset digests. The separate v4 consumer
commit names v4 and rejects every `TODO_I3_V4_SHA256_*` pin until publication
and attestation; the orchestrator replaces those sentinels from the published
`SHA256SUMS`. It resolves a complete
`HERMES_LEAN_SYS_DIR` first, this repository's local platform install second,
and the release bundle pinned for Cargo's exact target triple otherwise. Both
the legacy repository layout (`hermes-headers` plus the platform static-library
directory) and the published layout (`include/`, `lib/`, and `bin/hermesc`) are
accepted for local installs. A published-layout override is complete only with
its receipt. A legacy Apple or Windows repository-layout install may omit one;
a Linux install must carry a canonical receipt because its ICU code, both data
variants, and the pinned filter are build inputs. Unsupported
triples are refused with instructions to provide `HERMES_LEAN_SYS_DIR`;
`aarch64-apple-ios-sim` and `x86_64-apple-ios` both select the universal iOS
Simulator archive. `aarch64-apple-tvos` selects the tvOS device archive and
`aarch64-apple-tvos-sim` selects the arm64 tvOS Simulator archive.

The `link` feature emits the full VM's link line; `link-lean` emits the lean
VM's link line, and the two features are mutually exclusive. On Linux either
one also selects `icu`, whose default data archive is trimmed root+en;
`icu-full-data` swaps to the full archive and is enabled by `ibex2/intl`.
Selecting it directly without `ibex2/intl` is also supported: the engine's
basic-Unicode backend then uses full data while Ibex's Intl shims remain absent.
Resolution
exports lean metadata only when the lean archive exists. If a receipt is
present, its archive manifest must authenticate that archive in every feature
context, even one that does not enable `link-lean`; a receipt that omits or
mismatches the lean entry is refused. Downstream build scripts receive
`DEP_HERMES_LEAN_ARCHIVE` and
`DEP_HERMES_LEAN_ENGINE_DIGEST` for full, plus
`DEP_HERMES_LEAN_LEAN_ARCHIVE` and `DEP_HERMES_LEAN_LEAN_ENGINE_DIGEST` for
lean when present. With either link feature active, `DEP_HERMES_LEAN_LINKED_ARCHIVE` and
`DEP_HERMES_LEAN_LINKED_ENGINE_DIGEST` identify what VM that process links.
Linux additionally exports `DEP_HERMES_LEAN_LINKED_ICU_DATA_ARCHIVE` and
`DEP_HERMES_LEAN_LINKED_ICU_DATA_DIGEST`; this separate identity names exactly
the trimmed or full data variant while shared ICU code stays archive-manifest
bound. Bindings-only contexts export both available identities and no selected
identity; only the normal dependency that emits the link lines exports these
`LINKED_ICU_DATA_*` values. This is R-e: a process never reports full while
linking lean, or reports trimmed data while linking full data. Legacy local
layouts may omit lean; they export no lean path, digest, or
HBC version and fail only if `link-lean` is requested. Published v4 bundles
must carry and manifest both. Repository discovery uses the Apple layout only
for macOS targets; iOS cross builds fall through to their pinned target bundle
or an explicit complete `HERMES_LEAN_SYS_DIR`.

Two consumption modes are supported:

1. **Automatic download during a Cargo build.** This is the default. A missing
   release bundle is downloaded, verified, and cached by
   `hermes-lean-sys`'s build script.
2. **Install once, then build offline.** Run the explicit installer while
   online, then make network access a refusing build invariant. Use the
   installer manifest from the same Ibex source revision as
   `hermes-lean-sys`. The build's recovery error prints its absolute path, so
   this works from a consumer repository whether Ibex is a Cargo Git checkout
   or a vendored/path dependency. The pins are identified by the release tag
   and the SHA-256 the build error prints.
   The installer is the explicit online step, so it ignores `HERMES_LEAN_SYS_OFFLINE`: a consumer that forces offline mode in `.cargo/config.toml` `[env]` can still run it. A vendored copy must include `crates/hermes-lean-sys-installer` beside `hermes-lean-sys` (same Ibex revision); without it, the build error says so instead of printing a command.
   Install with:

   ```sh
   # Installs the host bundle.
   cargo run --manifest-path \
     ../ibex/crates/hermes-lean-sys-installer/Cargo.toml --

   # Installs the host bundle plus every named cross target.
   cargo run --manifest-path \
     ../ibex/crates/hermes-lean-sys-installer/Cargo.toml -- \
     --target aarch64-apple-ios \
     --target aarch64-apple-ios-sim

   HERMES_LEAN_SYS_OFFLINE=1 cargo build --locked -p ibex2-runtime
   ```

   A cross-target invocation always installs the host bundle too, because the
   host's authenticated `hermesc` compiles bytecode for the target VM.

Both modes call the same acquisition and admission code. The downloader uses
rustls with WebPKI roots and verifies the compiled-in archive SHA-256 before
inspecting or extracting the tarball. Extraction preflights the complete
archive and accepts only relative regular-file and directory entries:
absolute paths, parent traversal, links, and special files are refused.
Downloads remain in a private staging directory through canonical receipt,
compiler authentication, and host/target HBC pairing checks. Only a completely
validated install is atomically renamed into
`$CARGO_HOME/hermes-lean-sys/<tag>/<archive-sha256>/`, with Cargo home defaulting
to `$HOME/.cargo` (or the platform home equivalent). The verified tarball is
retained in the cache entry. Every admission rehashes it against the source
pin, rebuilds a per-file manifest from its members, and compares that manifest
with the extracted tree, including refusal of missing, changed, extra, linked,
or special entries. Admission also validates the canonical receipt's exact
target, pinned upstream commit, empty patch set, engine path and digest,
compiler digest, positive HBC version, and non-empty archive, header, and
ordered link manifests. The installer and build resolver use that same staged
admission boundary, so a failed full validation never publishes the final
cache entry.

`CARGO_NET_OFFLINE=true` and `HERMES_LEAN_SYS_OFFLINE=1` both prohibit a
download. In offline mode a valid warm cache entry or local override is
required. `HERMES_LEAN_SYS_MIRROR` replaces
`https://github.com/expo/ibex/releases/download` as the base URL and must serve
`<tag>/<asset>` beneath that base; mirrors do not replace digest verification.
The installer uses the same variable, for example:

```sh
HERMES_LEAN_SYS_MIRROR=https://mirror.example/hermes \
  cargo run --manifest-path \
    ../ibex/crates/hermes-lean-sys-installer/Cargo.toml -- \
    --target aarch64-apple-ios
```

For exact2 and other consumers whose policy forbids build-script downloads,
install the bundles first and check this into the consumer's
`.cargo/config.toml`:

```toml
[env]
HERMES_LEAN_SYS_OFFLINE = { value = "1", force = true }
```

Before enabling that entry, run the exact manifest-path command from an
offline cache-miss error while online. It points into the Cargo Git checkout or
vendored Ibex copy that supplied `hermes-lean-sys` and reports the compiled-in
Ibex pin-set revision, release tag, asset, and SHA-256. For example, a vendored
copy at `../vendor/ibex` is installed from any consumer directory with:

```sh
cargo run --manifest-path \
  ../vendor/ibex/crates/hermes-lean-sys-installer/Cargo.toml -- \
  --target aarch64-apple-ios
```

This `[env]` entry is the recommended `hermes-lean-sys` control: it reaches
the build script and cannot be silently overridden by a caller's ambient
environment. Cargo's separate `[net] offline = true` setting controls registry
and Git dependency access but does not itself promise to export
`CARGO_NET_OFFLINE` to build scripts. A repository that wants both guarantees
should configure both.

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

The script requires all nine archive checksums and rewrites the duplicate
universal-simulator mappings consistently. Review the resulting source diff,
then exercise cold-cache, warm-cache, offline-cache, mirror, and local-directory
override cases on the follow-up lean-selection branch before landing consumer
updates. Never replace an asset: a
changed build or packaging authority receives a new release revision suffix
(`-v4`, `-v5`, and so on) and new consumer digests.
Before a future release revision is published and all attestations pass, its
pins must remain rejecting `TODO_*` sentinels. The resolver refuses those
sentinels before any download, so neither a mirror nor a pre-populated cache
can substitute bytes under an unpublished release name. Replace them only by
the procedure above.
