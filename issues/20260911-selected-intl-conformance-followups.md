# Selected Intl conformance follow-ups after Linux publication

**Status:** Open
**Impact:** 2
**Urgency:** 2
**Ease:** 2
**Confidence:** 5
**Severity:** P3
**Systems:** Ibex 2, Hermes, Standard Library
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-09-11
**Related:** LLP 0067 §5, `issues/closed/20260911-linux-hermes-intl-numberformat-stub.md`

Snapback2 0.0.24's Linux publication proves the selected consumer-required
Intl surface, not complete ECMA-402 conformance. Keep these known boundaries
open without retroactively widening that release claim:

1. Calendar and numbering-system option processing ASCII-case-normalizes
   canonical spellings but does not perform complete UTS 35 alias
   canonicalization. For example, `islamicc` and `ethiopic-amete-alem` do not
   yet select `islamic-civil` and `ethioaa`.
2. On pinned Hermes, `Reflect.construct` with a distinct `newTarget` whose
   `prototype` is not an object falls back to `Object.prototype` for the
   replacement NumberFormat and DateTimeFormat constructors. The public JSI
   surface has no custom `[[Construct]]` hook; the expected-correct
   reproductions remain narrowly ignored rather than hidden behind a second
   observable prototype read or heuristic.
3. `String.prototype.toLocaleLowerCase` and `toLocaleUpperCase` return the
   selected native locale-sensitive results, but their Linux replacement
   functions remain constructable instead of having built-in methods'
   nonconstructable callable shape.
4. DateTimeFormat validates and reads `formatMatcher: "basic"`, but both
   accepted matcher values currently use ICU best-pattern selection.
5. `Intl.PluralRules`, `Intl.RelativeTimeFormat`, `Intl.Locale`, and
   `Intl.DisplayNames` remain absent in both qualified engine profiles. This
   ticket does not commission those constructors merely because TypeScript's
   selected library declarations include them.

These are independent follow-ups, not a request for a new conformance program,
Hermes fork, blanket latest-Intl claim, or test262 gate. Canonical option names
and the published consumer surface remain supported as recorded in LLP 0067.

**Done when:** each listed behavior is either implemented with a focused
real-runtime regression and the existing native ownership/integrity invariants,
or separately disposed by the author without broadening the published
Snapback2 0.0.24 claim.
