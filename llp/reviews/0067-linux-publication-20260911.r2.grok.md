# Linux runtime and Snapback2 publication code review — r2.grok

**Date:** 2026-09-11
**Model / effort:** requested grok-4.6 / xhigh; reported grok-4.6-build
**Runtime:** grok-cli 1.0.25
**Interval:** 2026-09-11T15:05:06Z – 2026-09-11T15:19:16Z
**Session:** `01a09100-3e34-77e3-9128-d3ed047970f0`
**Ibex target:** `3182a9d7767ca199438d4b7ed114e74c29458944`
**Snapback target:** `2849b5cde3976301ffa3114200620495d76fd36a`
**Method:** Fresh mutually blind read-only correction-delta review in exact
Git source archives. One reviewer; no subagents, clones, builds, remote
commands, web access, edits or peer findings. This is code review, not author
acceptance of an LLP or production qualification. Final pin integration and
native artifact qualification are separate release steps.

## Received review text

I'll review only the two correction-delta capsules, starting with the r2 patches and nearby changed code—no subagents, no edits, no builds.The capsules are in place. Next I’ll read the r2 patches and the portable follow-up, then only the nearby changed code.Patches are in. I’ll now read the changed scripts and the nearby callers that actually enforce those contracts.I’ll now read the remaining staging/main paths and the Ibex hermesc/Intl callers that the patches actually change.Checking one resume-match edge around imported non-canonical shims, then I’ll close the review.## Verdicts

**Ibex `3182a9d77` — READY**

**Snapback `2849b5cde` — READY**

No introduced material defects in the r2 deltas.

---

## 1. Ibex

The two-script delta does the things this pass asked for.

- **hermesc path** is exact: `hermesc-${macos|linux}-${process.arch}`, matching `build-hermes-linux.sh` (`x86_64|amd64` → `x64`, `arm64|aarch64` → `arm64`) and `build.rs` / `bytecode.rs`.
- **`IBEX2_HERMESC`**: set and missing → hard fail; unset and missing default → `compiler: null` (run-only / engine-only).
- **Receipt variant** is taken from parsed `nm` symbol rows, not archive headers or a raw `includes('AsyncDebuggerAPI')`. The Itanium check (`16AsyncDebuggerAPI` + member length / `C1–C3` / `D0–D2`) is what drops `RuntimeTaskRunner` parameter types. Patched-symbol refusal uses the same row list.
- **Vanilla Linux Intl**: required; `true`/`True`/`on`/`On`/`yes`/`Yes`/`1` accepted after case-fold; anything else, including `false`/`False`/`Off` and `--no-intl`, rejected.
- **Shared payload**: vanilla install copies the static closure and `rm -f` leftover `libhermesvm.so` from the publication dir; non-vanilla still installs the `.so`.
- No variant flag and no new proof registry.

**Non-blocking**

- `IBEX2_HERMESC` pointing at an existing directory passes `existsSync` and then `readFileSync` throws `EISDIR` instead of `die()` (`scripts/hermes-input-receipt.mjs:117–126`, `sha256File` at `:39–41`). Nonexistent paths already fail as required.
- Case-sensitive fixture: on an empty `out`, `out.iter().all(...)` is vacuously true (`crates/ibex2/tests/resolution.rs:510–515`). The `err` `"is not a file"` check is the real gate; lockdown proof on that arm is weaker if the process exits before the lower-case fetch logs.

**Inherited / out of this delta**

- `bytecode.rs` still treats `IBEX2_HERMESC=""` as a path; the receipt script treats empty as unset.
- Vanilla `IBEX_HERMES_VANILLA` matching is still mixed-case literals, not the Intl-style fold.
- Mac Keychain roundtrip under noninteractive SSH: inherited, not claimed green.
- Implementer evidence (286 library tests, Clippy, ELF closure, HTTPS CLI) was not re-run here.

---

## 2. Snapback

The publisher delta matches the staging/custody contract.

- **`--stage-only`**: `main()` returns after host consumer qualification and resume write; no `verifyPublicationQualifications`, no `convergeArtifacts`, no `npm publish`. `prepare()` still does production build, media, package snapshot, and `npm install`.
- **Foreign natives**: `readQualifiedPlatformArtifact` checks identity / integrity / native-host consumer evidence; `hostConsumerArtifacts` installs only host + shim; `qualifyStagedMedia` runs the host helper only.
- **Full-set shim**: imported packed `optionalDependencies` must name the whole selected platform set at this version; then `stagePublicationShim` copies those bytes and re-checks SRI. A single-platform imported shim is not canonical, so the first expansion packs once.
- **Resume identity** includes that canonical shim integrity (`loadResume`).
- **Mismatch**: existing resume that does not match is refused with no mutation; `--stage-only` renames the whole directory to `.previous` / `.previous-N` then restages.
- **Dry-run**: still a sibling `.dry-*` directory; mutually exclusive with `--stage-only`.
- Version `0.0.24` is preparation only.

**Non-blocking**

- Default `prepare()` always rebuilds the host native tarball (`publish.mjs:767–824`). A’s second stage therefore usually changes A’s native integrity, so B’s matching-resume publish of the refreshed A receipt will refuse and need `--stage-only`. That restage still copies the canonical shim; it is workflow friction from non-reproducible host packs, not silent re-packing. The unit roundtrip hides this by writing deterministic `platform:${name}` bytes.
- Corrupt `resume.json` throws from `JSON.parse` (`publish.mjs:520`) rather than the “refusing to replace” error. Still no mutation.
- README states Linux x64 “is qualified” on Ubuntu 24.04. That is a publication-time claim; the still-pending production pin/same-shim consumers are a release gate, not a logic bug in this delta.

**Inherited / out of this delta**

- Pending pinned production staging and real dual-host native consumers, as specified. Not treated as an introduced defect.
- No signature / adversarial trust / evidence-registry work was in scope.

---

## Inspected / not verified

**Inspected:** `ibex-r2.patch`, `ibex-test-doc-followup.patch`, `snapback-r2.patch`; the corresponding files in `ibex-3182a9d77/` and `snapback-2849b5cde/` (`scripts/hermes-input-receipt.mjs`, `scripts/build-hermes-linux.sh`, `crates/ibex2/tests/resolution.rs`, LLP 0067/0068 notes, `snapback2/scripts/publish.mjs`, `publish.test.mjs`, `consumer-smoke.mjs` host/foreign split, nearby `build.rs` / `bytecode.rs` hermesc paths, `main()` stage-only/publish split).

**Not inspected / not verified:** `ibex-final-scope.patch` as a full-corpus review; parent directories; other reviewer or session output; git remotes; builds, tests, `nm`, Clippy, ELF, or live A→B staging. Implementer-reported evidence is taken as reported.
