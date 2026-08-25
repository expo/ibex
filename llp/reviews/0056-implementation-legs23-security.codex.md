# LLP 0056 legs 2/3 — codex security delta reviews (slice 3 + fix rounds)

**Type:** Review artifact (implementation security delta, LLP 0005 honesty rules)
**Reviewer:** codex gpt-5.6-sol xhigh, read-only sandbox, runs 2026-08-25 by the 0056 legs-2/3 lane; transcripts retained lane-side (/tmp/l23-codex-secrev3.log, /tmp/l23-codex-drev.log, /tmp/l23-codex-d1d2.log)

**Round 1 (slice-3 range 397cac57d..96935de7f): DO-NOT-LAND** — F1 (BLOCKER: C-entry input pointers dereferenced before the armed exclusion), F2 (BLOCKER: ex_hermes_module_invoke_export had no native armed exclusion and ungated wrappers), F3 (MAJOR: coverage classification over-grant), F4 (MAJOR: linked plan not bound to the step-6 authority), F5–F7 minors; F8 INFO recorded the intact invariants (phase split, atomic link, sticky executor, session recovery, alias bounds, landed lanes unchanged).

**Fix round (db62cb957) delta verdict: DO-NOT-LAND residual** — F1/F4/F5/F6/F7 verified resolved; D1 (the raw C symbol remained armed-reachable for direct C callers — the Rust wrapper assert is not the ABI boundary) and D2 (classification still claimed descriptor binding/armed exclusion as ABI properties).

**Final fix (35ee5336d): native runtime->armed refusal inside the C definition (after the drive guard, before record lookup) + a real-armed-runtime refusal test (ex_hermes_create_armed) + honest classification. Focused verification verdict: RESOLVED**, no new defect in the commit's hunks.
