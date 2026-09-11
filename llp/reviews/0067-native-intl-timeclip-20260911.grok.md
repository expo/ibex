# Native Intl TimeClip addendum — Grok code review

**Date:** 2026-09-11
**Model / effort:** grok-4.6 / xhigh
**Session:** `01a09233-e409-7fd2-a903-ff0538548fc7`
**PID:** 12131
**Interval:** 2026-09-11T20:41:09Z–2026-09-11T20:44:26Z
**Exit:** 0
**Target:** `49fa9841212cf1fc119a3f8dcd246b1f9ab71ea8`
**Base:** `12dfbf3fd20fe0986768a3a5443972d38e69566c`
**Candidate archive SHA-256:** `18b6759c5ae6472b347c5d50acce4cedc0952255f1839f15f45e723752382f56`
**Delta SHA-256:** `d7869ec07f979e840556684afb430dc6616080c81d293dd4dc3752da0c420c14`
**Method:** Mutually blind two-file addendum review, one reviewer. No peer
findings, subagents, clones, worktrees, remotes, web, edits, builds or tests.
Public response only; escaped newlines rendered for readability. The broader
correction review is separate. This is not publication authorization.

## Received review text

I'll review this TimeClip correction myself: start with `delta.patch`, then only the related callers and regression assertions in the two candidate files.The review skill uses subagents, so I'll skip it and review the delta and the two candidate files directly.Delta is a one-line `trunc()` plus tests. Next I’ll read `checked_time`, `native_result`, format callers, and the regression assertions in the two candidate files.Callers share `checked_time` → `native_result`. I’ll read `number_arg`/`range` and confirm no other format path skips the clip.**READY**

This is a one-line TimeClip correction plus targeted tests. Finite in-range values now truncate toward zero before ICU; range/type rejection still happens first; `format` and `formatToParts` share that conversion. I did not run tests and this is not publication authorization.

## What changed

`checked_time` still takes an already-numeric `HostArg`, then:

```510:518:candidate/crates/ibex2/src/stdlib/intl_datetime.rs
fn checked_time(value: Option<&HostArg<'_>>) -> Result<f64, HostError> {
    let value = value
        .and_then(number_arg)
        .ok_or_else(|| HostError::InvalidArgument("date time value expected".into()))?;
    if value.is_finite() && value.abs() <= 8_640_000_000_000_000.0 {
        Ok(value.trunc())
    } else {
        range("Invalid time value")
    }
```

- Finite and `|t| ≤ 8.64e15` is decided on the incoming value; `trunc()` runs only on the success path.
- Non-number still fails via `number_arg` (`InvalidArgument`), before any clip.
- NaN / ±Inf / out-of-range still take `range("Invalid time value")`.
- `f64::trunc` is toward zero: `(-0.1).trunc()` is `-0.0`, `(0.9).trunc()` is `0.0`. That is the UTC `format(-0.1)` → Dec 31, 1969 vs `format(0)` → Jan 1, 1970 failure.

Both native callers use that result:

```460:466:candidate/crates/ibex2/src/stdlib/intl_datetime.rs
    fn format(&self, value: Option<&HostArg<'_>>) -> Result<String, HostError> {
        native_result(&self.native, checked_time(value)?).map(|result| result.text)
    }

    fn format_parts(&self, value: Option<&HostArg<'_>>) -> Result<Vec<Part>, HostError> {
        let result = native_result(&self.native, checked_time(value)?)?;
```

`FORMAT` / `FORMAT_PARTS` still pass `args.get(1)` into those methods. `native_result` still only forwards the `f64` to ICU. No new JS coercion, option read, engine change, grant, dependency, or public surface.

Existing range assertions are unchanged and still valid after `trunc()` (the ±8.64e15 bounds are integers in f64):

```1199:1202:candidate/crates/ibex2/src/stdlib/intl_datetime.rs
        assert!(checked_time(Some(&HostArg::Number(8_640_000_000_000_000.0))).is_ok());
        assert!(checked_time(Some(&HostArg::Number(8_640_000_000_000_001.0))).is_err());
        assert!(checked_time(Some(&HostArg::Number(f64::NAN))).is_err());
```

## Material findings

None introduced by this delta.

## Tests

Negative: `checked_time(-0.1)` is bit-identical to `-0.0`; Linux `format(-0.1)` / `formatToParts(-0.1)` must match `format(0)` / `formatToParts(0)` under UTC second precision. That is the retained reproduction.

Positive: `checked_time(999.9) == 999.0` (toward zero, not round/ceil). The format-level `0.9` checks are consistent with clip, not a substitute for that numeric assertion.

## Optional suggestions (not blocking)

- `candidate/crates/ibex2/tests/intl_datetime.rs:55` — `format(0.9) === format(0)` at second precision would already hold without `trunc()`. If you want the format surface to prove positive clip, add `fractionalSecondDigits: 3` (or an equivalent millisecond field).
- Spec TimeClip is `truncate(t) + 0`, which canonicalizes `-0` to `+0`. This code returns `value.trunc()` and the unit test pins `-0.0` bits. Observable UTC format of `-0.1` vs `0` is already asserted; `value.trunc() + 0.0` is only needed if you want bit-identical `+0` into ICU.

Inherited Intl gaps (missing-argument `Date.now()`, Date.prototype clip, locale/options) were not reopened. Broader correction-delta review and package rebuild remain separate.

