# Committed-admission cost: blog-scale profile, M2 wave, and held designs

**Status:** Open (tracking held items and follow-ups; the M2 wave landed on
main — commits `e71cc491`, `ff8fd4e6`, `6616c850`, `6e314bcc` — and the
`admission-cost-profile` branch is deleted)
**Systems:** Module Loader, Prepared Publications, CapSec Semantics
**Author:** Claude Fable 5 (Claude Code)
**Date:** 2026-07-30
**Related:** Exact LLP 0413 §10 Phase 3 (admission is the dominant
prepared-startup phase), Exact
`issues/20260728-llp0413-phase3-hbc-carriers-and-cache.md` M2/M3 receipts,
LLP 0042 (committed admission algorithm), LLP 0027 (canonical encoding).

## M1 profile (measurement harness: `src/module_loader/admission_cost_profile.rs`)

Blog-scale committed admission (51 carriers / 545 records, index ~7.7 MB,
manifests ~6.9 MB, HBC carriers ~5.7 MB) measured 155.2 ms locally against
166.5 ms on-device (Exact Phase 3 M3 receipts), byte-identical between
carrier encodings — the cost is manifest/record verification, not carrier
bytes. Dominant blocks at baseline:

- per-module semantic-digest recompute, done TWICE per module
  (carrier-manifest entry + index-record artifact): ~46 ms;
- index/manifest strict-parse + JCS re-canonicalize + typed decode +
  encoding peek: ~64 ms;
- sha256 at a measured ~0.5 GB/s (portable sha2 backend; the same machine
  does ~3 GB/s with the ARMv8 crypto extensions): ~55 ms across all
  digest domains;
- authorized-set clones: 596 full BTreeSet clones (~325k Digest strings),
  ~3.3 ms;
- transform-fingerprint digest recomputed 1,090× for one distinct input:
  ~4.6 ms.

Scaling: linear in RECORD count (545→250 records: 155→67 ms); carrier
count is second-order (~0.1–0.3 ms per carrier). Warm file I/O is ~3 ms —
OQ6/OQ7 (retained-buffer zero-copy, mmap) stay LOW value at current sizes.

Run the matrix:
`cargo test --release --lib admission_cost_profile -- --ignored --nocapture`.

## M2 wave (landed on this branch; per-commit release medians, one pass,
## same machine — blog-hbc / diet-250r-24c cells)

| commit | change | blog 51c/545r | diet 24c/250r |
| --- | --- | ---: | ---: |
| harness baseline | — | 147.0 ms | 64.5 ms |
| item 1 | hardware SHA-256 (aarch64 non-Windows; MSVC keeps soft) | 100–104 ms¹ | 44–45 ms¹ |
| item 6 | `Arc<BTreeSet<Digest>>` authorized set | 93.3 ms | 42.1 ms |
| item 5 | `FingerprintDigestMemoV1` in both record loops | 92.0 ms | 41.1 ms |
| item 2 | semantic-digest dedupe via verified carrier-entry hint | **81.9 ms** | **36.8 ms** |

¹ The item-1 window of the per-commit pass caught a sibling load spike;
the quoted range is from two dedicated low-load runs (100.2/104.0 blog,
44.1/45.4 diet), consistent with the pass's later windows.

Net: **−44%** at current blog scale, **−43%** at the LLP 0128 diet point
(projected on-device from the 166.5 ms M3 receipt: ~93 ms now, ~41 ms
after the record diet). All four items are zero refusal-semantics change:
identical accept/refuse sets, identical diagnostics, identical ordering;
item 2 ships with the required mismatched-duplicate adversarial fixtures.
Note: at the tip, the harness's component-attribution sum exceeds the
end-to-end median by design — the breakdown pass times what each
verification building block costs standalone, and production now skips
the deduped/memoized share.

## Held: parallel per-carrier/per-record verification (M1 proposal 3)

Design note for a future wave (decision needed before implementation):

- **Shape:** `std::thread::scope` (no new dependency) over (a) the
  per-carrier `decode_and_admit` loop and (b) the per-record
  `verify_for_admission` loop. Both bodies are pure functions over owned
  bytes/structs; `anyhow::Error` is `Send`. Bounded chunking (e.g.
  `min(available_parallelism, 6)` workers) rather than per-item spawn.
- **Refusal-selection rule (the decision):** verification runs over ALL
  items; the surfaced refusal is the failure with the LOWEST index-order
  position, making the refusal deterministic and identical to today's
  sequential first-failure. Fail-fast short-circuiting across threads is
  permitted only if it still selects the lowest-index failure before
  reporting.
- **Constraint:** admission runs pre-evaluation on the runtime thread;
  scoped threads are joined before return, so no runtime-thread state
  escapes. Needs an explicit check against embedder threading
  expectations before landing.
- **Expected value:** ~4–6× on the ~2/3 of admission that is per-item
  work; at the LLP 0128 diet point this is what takes admission from
  ~30 ms to ~10 ms.

## Held: single manifest decode / drop the encoding peek (M1 proposal 4)

Each manifest is currently parsed twice: a full `serde_json::Value` parse
to peek `encoding.kind` (host engine expectation selection), then
`decode_and_admit`'s strict parse. Folding these into one strict parse
whose `Value` is reused changes the refusal CLASSIFICATION order on
doubly-invalid manifests: a non-strict manifest that still `Value`-parses
with `encoding.kind == "hermes-bytecode"` on a host with no loaded-engine
identity refuses `IBEX_PREPARED_ENGINE_UNAVAILABLE` today, but would
refuse as non-canonical/corrupt after the fold. The accept/refuse set is
unchanged; the observable diagnostic on that corner is not. Decision to
frame: is the engine-unavailable classification on malformed manifests
load-bearing for any host UX or fixture? If not, fold and update the
fixture expectations in the same commit.

## Future work: streaming canonical parse+digest (M1 proposal 7)

Replacing parse→Value→re-serialize→byte-compare with a streaming
canonical-form validator that hashes in the same pass addresses the
remaining ~40% (index/manifest JSON pipeline), but it rewrites the
RFC 8785 trust core. Precondition: a differential fuzzing program
(streaming validator vs `parse_strict` + `to_jcs_bytes` byte-compare over
adversarial corpora) with documented coverage, per the coordinator's
M2 decision. Do not start this without that program.

## Follow-ups (small)

- `verify_for_admission` recomputes the transform-fingerprint digest per
  record even when the caller derived the expectation from the same
  struct; a verified-fingerprint hint analogous to the semantics hint
  could remove ~2 ms at blog scale. Kept out of this wave deliberately —
  the generic artifact check stays self-contained.
- `verify_current_transform_fingerprint_v1` (production posture, LLP 0042
  step 6) recomputes BOTH the configured and the record fingerprint
  digests per record; memoization needs a decision about restating that
  trust logic vs. plumbing the memo through.
- CI evidence for `sha2`'s `asm` backend on aarch64-linux/Android builds
  (the gate excludes only Windows; the non-Apple aarch64 lanes should
  compile-verify before a release).
- x86_64 non-MSVC hosts still run the portable backend; enabling `asm`
  there is the same one-line change if profiling ever shows it matters.

## Pointer for the Exact-side diet (do NOT change in ibex)

Source-map `mappings` inside record semantics are ~37% of blog-scale
admission (155.2 → 98.4 ms with empty mappings, index 7.7 → 1.7 MB).
Whether mappings ride inside admission-time semantics is an Exact
producer choice — debug-profile material per Exact LLP 0413 §12's
debug/source-map profile dimension. Recorded here as measured input to
the Exact diet workstream; ibex admission treats semantics as opaque
producer content and must not slim them itself.
