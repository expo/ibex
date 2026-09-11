# Linux runtime and Snapback2 publication code review — r1.grok

**Date:** 2026-09-11
**Model / effort:** grok-4.6 / xhigh (reported grok-4.6-build)
**Runtime:** grok-cli 1.0.25, session 01a090df-cdee-77a1-8250-652992c69522
**Interval:** 2026-09-11T14:29:40Z – 2026-09-11T14:47:04Z
**Ibex target:** `f9f352057a1e5a5ee361e8c634890a8285ad85b8`
**Snapback target:** `b0489fd1e02419574ebd058b49c26d0be9f18867`
**Method:** Fresh mutually blind read-only source-capsule review; one reviewer,
no subagents, clones, builds, remote commands, web access or edits. Reviewer
received no peer findings. The two projects were reviewed together because
this publication depends on the Linux engine port. This is a code review,
not author acceptance of an LLP or production qualification.

First-round findings are historical and are not silently rewritten when
fixed or declined. Dispositions and later source-bound evidence are recorded
in Snapback's `benchmarks/runs/2026-09-11-snapback2-release-0024-linux/`.

## Received review text

I'll review both candidates from the supplied local patches and capsules only: read the diffs first, then the relevant source and governing docs, with no builds, clones, or extra inspection.I'll skip the review skill and other review artifacts, and start with the two scoped patches plus their file lists.Patches are small enough to read in full. Next I’ll take both diffs, then the governing docs and the matching source.Patches are in. I’ll read the changed sources and the governing docs next, focusing on loader identity, build/receipt paths, and publisher resume/qualification.I’ll inspect Linux fetch/rustls, the remaining Ibex build scripts, and the publisher’s qualification and resume paths.## Verdicts

| Candidate | SHA | Verdict |
|---|---|---|
| Ibex2 Linux runtime | `f9f352057a1e5a5ee361e8c634890a8285ad85b8` | **READY** |
| Snapback2 multi-platform publisher | `b0489fd1e02419574ebd058b49c26d0be9f18867` | **NOT READY** |

Ibex2’s Linux vanilla lane is isolated from the patched tree, stays on unmodified Hermes `6badada762121682b5481b6124e6c3a991ae6046`, does not touch rustls `fetch`, and the loader/test-fixture corrections are sound. Snapback2’s stage/import/verify gates fail closed, but the two-host workflow this patch adds cannot mechanically keep one final shim identity.

---

## 1. Ibex2 Linux runtime — READY

No introduced product-correctness defect that should block Linux vanilla Hermes. Findings below are latent identity risk, weaker cache identity than Apple vanilla, and verification still pending.

### Finding I1 — Medium — `scripts/hermes-input-receipt.mjs:105`

**What:** Compiler identity is “first `hermesc-*` from `readdirSync`,” not the platform compiler `build.rs` / `hermesc_path` will check.

```105:110:ibex-f9f352057/scripts/hermes-input-receipt.mjs
const hermescDir = join(repoRoot, 'tools/hermes-vanilla');
const hermesc = existsSync(hermescDir)
  ? readdirSync(hermescDir)
      .filter((name) => name.startsWith('hermesc-'))
      .map((name) => join(hermescDir, name))[0]
  : undefined;
```

Linux vanilla now installs `tools/hermes-vanilla/hermesc-linux-*` next to Apple’s `hermesc-macos-*`. `Compiler::discover_for_engine` hashes the platform path and refuses a digest mismatch (`crates/ibex2/src/bytecode.rs:104-116`).

**Failure:** A tree that has both binaries (copied tools dir, shared volume, dual build) writes a receipt bound to whichever `hermesc-*` `readdir` returns. `hermesc-linux-*` often sorts first. Regenerating the receipt on Mac then fails: “the receipt describes a different hermesc than the one present.” Native Mac without a Linux hermesc is unchanged.

**Fix:** Hash `hermesc-${process.platform === 'darwin' ? 'macos' : process.platform}-*` (and fail if that file is missing). Do not pick `readdir()[0]`.

This pick is pre-existing; it becomes a Mac/Linux interaction only because this candidate writes the Linux compiler into the same directory.

### Finding I2 — Low — `scripts/build-hermes-linux.sh:88`

**What:** Vanilla cache is `hermes2-linux-vanilla/${commit}${debug}` only. Apple vanilla folds the builder-script digest into the cache key; Linux vanilla does not. `BUILD_DIR` is kept for incremental ninja.

**Failure:** A script-only change that does not alter cmake inputs or source timestamps can reuse objects from the previous script (`ninja: no work to do`). Commit/debug isolation is still correct; patched vs vanilla trees are still separate; `git archive` still re-materializes unpatched source and skips `apply-hermes-patches.sh`.

**Fix:** Put `ibex_hermes_linux_build_authority_digest` (or equivalent) in the vanilla cache path, matching Apple vanilla.

### What looks correct (not findings)

- Default vanilla pin is `IBEX_HERMES_VANILLA_SOURCE_COMMIT=6badada7…`; `--vanilla` requires a 40-hex object; patches are not applied.
- Vanilla source is `git archive` of that object from an existing repo under the shared source-build lock. Dirty patched worktrees cannot leak. Missing object fails closed.
- Link line is `linux-static` + static ICU/tinfo + system `stdc++/dl/pthread/m`. Darwin still uses `ios/Frameworks-vanilla`, `macos-static`, `libc++`, CoreFoundation/Foundation.
- rustls `fetch` is unchanged (`Cargo.toml` non-Apple deps; `src/transport/mod.rs` still `RustlsHttpTransport` off Apple).
- Case-identity: on a case-sensitive volume, `./A.ts` vs on-disk `a.ts` is now a refusal rather than a second specifier (`loader.rs:528`, `loader.rs:660`). Case-folding volumes still settle in `contain`.
- `Project::new` is unique per process+instance; the traversal fixture no longer depends on `/etc/hosts` depth.

### Inherited / pending (not introduced defects)

- `tests/resolution.rs` `case_variants_of_one_file_are_one_module` is still Mac-centric (the nearby bind test is gated on case-fold). It already could not pass on Linux; this patch did not update it.
- Vanilla build prints the receipt command and does not write the receipt (same as Apple). Shipping posture still requires `hermes-input-receipt.mjs`.
- Vanilla Linux still needs an existing Hermes git repo containing the pin; it does not fetch.
- Full hermes integration on Linux, Mac regression, and ELF `NEEDED`/glibc of the linked binaries were not run here. Author evidence is not a substitute.

---

## 2. Snapback2 publisher — NOT READY

`--stage-only` does not publish. Foreign tarballs are copied and metadata-checked, not executed. Host consumer smoke installs only host+shim. Resume selection mismatch rebuilds rather than ignoring a new platform. Those gates are right.

The candidate still cannot keep **one** immutable shim across the two-host flow it documents.

### Finding S1 — High — `snapback2/scripts/publish.mjs:778` and `:331`

**What:** Import validates the foreign receipt’s shim, then throws that shim away. `prepare` copies only the **platform** tarball and always `npm pack`s a new shim on the current host.

```778:786:snapback-b0489fd1e/snapback2/scripts/publish.mjs
  for (const requested of requestedPlatforms) {
    const target = resolve(stateDirectory, basename(requested.artifact.tarball));
    if (existsSync(target)) throw new Error(`staged platform artifact target already exists: ${target}`);
    copyFileSync(requested.artifact.tarball, target);
    platformArtifacts.push({ ...requested.artifact, tarball: target });
    platformQualifications[requested.artifact.name] = requested.qualification;
  }
  stagePlatformDependencies(shimStage, platformArtifacts);
  const shimPack = pack(shimStage, stateDirectory);
```

`verifyPublicationQualifications` then requires every platform qualification’s `shimIntegrity` to equal **that** newly packed shim (`publish.mjs:331`).

LLP 1002 §11’s flow is: A stage, B unified stage, A unified stage, B publish using A’s refreshed receipt. That only works if B publishes the **same** shim bytes A just exercised.

**Failure:** Host B packs unified shim `S_b` (esbuild + `npm pack`, fresh `dist/` mtimes). Host A imports B, rebuilds the JS package, packs `S_a`. Those tarballs are not the same object; the order test only packs a static fixture on one machine (`publish.test.mjs` “platform selection order…”). A’s qualification binds `S_a`. B then misses resume (A rebuilt darwin), packs `S_b2`, and `verifyPublicationQualifications` throws `not production-qualified with final shim`. Publication never converges. This is fail-closed, not a silent wrong publish — it still blocks the work this patch is for.

**Fix:** Treat the shim like a platform artifact.

1. If the imported receipt’s shim `optionalDependencies` already name the full selected set at this version, **copy that shim tarball** and run `hostConsumerArtifacts` against those bytes. Do not pack a new one.
2. Pack a new shim only when the selected set is a strict superset of the imported shim (first unified assembly on host B).
3. Later hosts, including the publishing host, copy that canonical shim.

No new registry or signing.

### Finding S2 — Medium — `snapback2/scripts/publish.mjs:496`

**What:** `loadResume` matches host name plus imported **platform** integrities. It does not bind the resume’s `snapback2` tarball to the imported receipt’s shim integrity.

```508:514:snapback-b0489fd1e/snapback2/scripts/publish.mjs
  const selected = resume.artifacts.filter((artifact) => artifact.name !== "snapback2");
  const expected = [{ name }, ...requestedPlatforms.map(({ artifact }) => artifact)];
  if (selected.length !== expected.length
    || expected.some((artifact) => selected.filter((candidate) => candidate.name === artifact.name).length !== 1)
    || requestedPlatforms.some(({ artifact }) => selected.find((candidate) => candidate.name === artifact.name)?.integrity !== artifact.integrity)) {
    return undefined;
  }
```

**Failure:** Darwin tarball bytes match an older resume, but A has since packed a new unified shim. B resumes the old shim, overwrites Darwin’s qualification with A’s (`shimIntegrity: S_a`), then either fail-closes at verify or writes a stage-only receipt whose quals and artifacts disagree.

**Fix:** When requested platforms carry a shim, resume only if the local `snapback2` artifact integrity equals that imported shim integrity (and still fail closed on platform selection/integrity mismatch). Combined with S1, the publishing host reuses A’s shim instead of packing another.

### What looks correct (not findings)

- `--stage-only` returns before `registryIntegrity` / `npm publish` (`publish.mjs:1124`). Mutually exclusive with `--dry-run`.
- `readQualifiedPlatformArtifact` checks identity, version, `os`/`cpu`, both tarball SRIs, `format: 1`, native `host`, and the production consumer steps. It never runs the foreign binary.
- `hostConsumerArtifacts` plus `npm install --ignore-scripts` keeps foreign packages off the consumer.
- `portableTarballPath` prefers basename beside `resume.json`, then the recorded path; integrity is checked. Intact staging-dir transfer works. Stale absolute path with a good beside copy is covered by test.
- Darwin `scripts/hermes` still uses `ios/Frameworks-vanilla` and `hermesc-macos-<arch>`.
- Production ibex pin/version integration is explicitly out of scope.

### Inherited / pending

- `SNAPBACK2_PUBLISH_WITHOUT_ENGINE` still exists (loud). Not introduced.
- Default `~/projects/ibex/...` lookup is unchanged in shape.
- Author 12/12 + self-test + opposite-order fixture packs do **not** prove two-host production shim identity or production/media/installed-consumer qualification. That remaining work cannot be inferred from these unit tests.

---

## Inspected

Both scoped patches in full. Ibex: `build.rs`, `build-hermes-linux.sh`, `hermes-input-receipt.mjs`, `hermes-version.sh`, `loader.rs` resolve/contain, `receipt.rs`, `bytecode.rs` hermesc discovery, `ibex2.rs` / test `engine_dir`, `tests/common/mod.rs`, `tests/loader.rs` traversal fixture, `tests/embedding.rs`, `tests/resolution.rs` case tests, `Cargo.toml` rustls cfg, `src/transport/mod.rs`. Snapback: `publish.mjs` (import/resume/prepare/stage/main), `publish.test.mjs` (from the patch), `consumer-smoke.mjs`, `scripts/hermes`, LLP 1002 §11 as patched, LLP 1003 engine-lookup paragraph, `snapback2/AGENTS.md`.

## Not verified

No cargo/build/test/npm, no clones, no remote, no other review artifacts. Did not execute Linux hermes integration, Mac regression, `ldd`/`readelf` on Ibex or Snapback binaries, two-host publish, or production qualification. Did not treat author-reported 423/423, 262 lib tests, 12/12 publisher tests, or 1118/1118 native complement as this review’s evidence.

Requested model: grok-4.6 / xhigh
Reported model: grok-4.6-build
Session: 01a090df-cdee-77a1-8250-652992c69522
Stop: end_turn
