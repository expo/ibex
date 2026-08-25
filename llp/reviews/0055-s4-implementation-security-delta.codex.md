# Review: LLP 0055 S4 implementation — security delta (codex)

**Reviewer:** codex gpt-5.6-sol, effort xhigh, `codex exec -s read-only`, security-delta commission (signature verification is an enforcement surface — delta owed).
**Date:** 2026-08-25. **Requested by:** the LLP 0055 S4 lane.
**Round 1 target:** commit a70c8cd6a on cd9a40d5c. **Verdict:** REGRESSES (3 materials: payload-semantics binding, handle/session binding, replay memory bound). All addressed in the fix round eeb07d472 (2 fixed; 1 partial + accepted-text disposition).
**Re-verdict target:** eeb07d472. **Final posture: NEUTRAL** (the S3-resolved base posture restored) — materials RESOLVED / DISPOSITION-ACCEPTED; no new findings.

---

## Round 1 (verbatim)

## Security Delta Assessment

Reviewed only commit `a70c8cd6a` against `cd9a40d5c`. Key custody and signed-envelope verification order are sound, and the product remains transport/JS-inert. However, the new public Rust enforcement API does not structurally bind authenticated bytes, consumer session, surface, and settlement together, while replay memory can escape its stated bound. These are blockers before external ingress connects.

## Verdict

REGRESSES

## Material Findings

1. **The signature does not authenticate the update semantics actually applied.** Admission verifies only the digest of a detached `payload` slice, then discards that slice; the admitted token retains no decoded payload. `begin_admitted` accepts an independently supplied invalidation vector, and staging later accepts independently supplied replacement records. Consequently, a caller can pair a valid signed payload with different invalidations/replacements, and no strict/JCS check rejects duplicate-key or non-canonical update payload JSON. The 512-module check also occurs only after the caller has already constructed the vector, not during bounded decoding (`src/module_loader/hot_update.rs:439`, `src/module_loader/hot_update.rs:461`, `src/module_loader/hot_update.rs:482`, `src/module_loader/hot_update.rs:695`, `src/module_loader/hot_revision.rs:172`). This violates LLP 0055 §6’s requirement that every authenticated payload row be verified before staging.

2. **Admission and settlement handles are not structurally bound to their originating consumer or surface.** `begin_admitted` checks consumer ownership only with `debug_assert!`, which disappears in release, and records no surface identity. An admitted token can therefore begin against a different same-state surface or consumer. Settlement handles carry only `updateId` and an `Rc`; settlement operates on whichever session receives the call, and failed row replacement is again only debug-asserted. Cross-session settlement can finalize the wrong row or suppress the origin session’s fail-closed drop while leaving its row pending. Moreover, the still-public raw `HotRevisionSurfaceV1::begin` bypasses authentication and replay entirely (`src/module_loader/hot_update.rs:469`, `src/module_loader/hot_update.rs:562`, `src/module_loader/hot_update.rs:573`, `src/module_loader/hot_update.rs:646`, `src/module_loader/hot_revision.rs:90`).

3. **The replay table is not memory-bounded by its 4096-terminal-entry capacity.** Capacity checks only `terminal_count`; an admitted reservation does not make the surface in-flight until the later `begin` call. A caller can retain arbitrarily many distinct admitted handles, creating arbitrarily many pending rows while `terminal_count` remains zero. Each `updateId` may consume nearly the entire 64 KiB signed-body allowance, and `settle_refused` clones an otherwise unbounded message into terminal storage (`src/module_loader/hot_update.rs:328`, `src/module_loader/hot_update.rs:339`, `src/module_loader/hot_update.rs:347`, `src/module_loader/hot_update.rs:588`, `src/module_loader/hot_update.rs:673`, `src/module_loader/hot_revision.rs:103`). Unauthenticated attempts create no persistent state, but authenticated pending traffic can grow the table without bound.

## Advisory Notes

1. Key custody otherwise passes: private material is confined to the non-serializable `Ed25519KeyPair`, `Debug` redacts it, and verifier construction copies only public bytes (`src/module_loader/hot_update.rs:99`, `src/module_loader/hot_update.rs:104`, `src/module_loader/hot_update.rs:130`). The public `sign` method is necessarily a signing capability, so the session object itself must remain producer-confined.

2. The signed-envelope body has the correct verification order: both byte limits precede proportional authentication/parsing work; Ed25519 covers the exact transmitted body bytes; strict JSON rejects duplicate decoded keys; JCS byte equality precedes typed deserialization; and `serde_json::from_value` consumes the same parsed `Value`, avoiding a second-parser differential (`src/module_loader/hot_update.rs:368`, `src/module_loader/hot_update.rs:374`, `src/module_loader/hot_update.rs:382`, `src/module_loader/hot_update.rs:388`, `src/module_loader/hot_update.rs:391`).

3. The S3 advisory is narrowly improved: the consumer checks the 512-module ceiling before entering the revision algebra. S4 remains unmounted—no transport or engine/JS caller was added, and `runtime-surface.json` is untouched. Production graph mutation remains structurally refused by `GenerationMode::Production` (`src/module_loader/generation.rs:1133`).

4. Same-session dropped handles and quarantine paths fail closed into rotation. The `Rc<Cell<bool>>` ownership also makes the surface, consumer session, and handles non-`Send`, enforcing the LLP 0002/0003 single-thread assumption in safe Rust (`src/module_loader/hot_update.rs:715`, `src/module_loader/hot_update.rs:739`, `src/module_loader/hot_revision.rs:18`).

5. `ring` adds no new package or feature exposure: the same vendored `0.17.14` implementation and default features were already selected through `rustls`. However, the exact commit updates `Cargo.toml` without updating the root package dependency edge in `Cargo.lock`; a clean locked build will require that one-line lockfile correction (`Cargo.toml:124`, `HEAD:Cargo.lock:1056`).
---

## Re-verdict round (verbatim, post-fix eeb07d472)

## Security Delta Assessment

Commit `eeb07d472` restores the S3-resolved posture. The admitted token retains the authenticated payload and exposes it with an explicit H2 derivation contract ([hot_update.rs:361](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:361), [hot_update.rs:476](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:476), [hot_update.rs:833](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:833)); transport remains unwired and assigned to H2 ([H1 ticket:20](/Users/ccheever/projects/ibex-wt/s4h-lane/issues/20260824-llp0055-hot-revision-h1-surface.md:20), [H1 ticket:26](/Users/ccheever/projects/ibex-wt/s4h-lane/issues/20260824-llp0055-hot-revision-h1-surface.md:26)).

Real `Rc` identity checks precede receiving-session mutation ([hot_update.rs:490](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:490), [hot_update.rs:619](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:619), [hot_update.rs:658](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:658), [hot_update.rs:679](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:679)); foreign early returns drop shadows/ready state without publication and poison only the handle’s origin through the backstops ([hot_update.rs:843](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:843), [hot_update.rs:867](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:867)).

`pending_update` blocks additional reservations, capacity blocks additional terminal identities, and successful removal/terminalization clears occupancy ([hot_update.rs:341](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:341), [hot_update.rs:352](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:352), [hot_update.rs:715](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:715), [hot_update.rs:730](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:730)). The transient `Option<Digest>` is consumed and replaced within one exclusive operation. Quarantine deliberately strands both pending markers, but the rotation gate precedes replay and busy ([hot_update.rs:292](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:292)). Commit errors explicitly poison; panics poison through settlement drop while the surface latch remains quarantined ([hot_update.rs:629](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:629), [hot_revision.rs:131](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_revision.rs:131)). The direct `ring` lock edge is present ([Cargo.lock:1093](/Users/ccheever/projects/ibex-wt/s4h-lane/Cargo.lock:1093)). Focused verification passed: 22 hot-update tests, 8 hot-revision tests, and `ref-check`.

## Verdict

NEUTRAL

## Material Findings

None.

## Resolution Check

1. Signature does not authenticate applied semantics: DISPOSITION-ACCEPTED
2. Handles not structurally bound to session/surface: RESOLVED
3. Replay table not memory-bounded: RESOLVED