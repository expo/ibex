# Linux vanilla Hermes exposes a dummy `Intl.NumberFormat`

**Status:** Open
**Impact:** 5
**Urgency:** 5
**Ease:** 2
**Confidence:** 5
**Severity:** P1
**Systems:** Ibex 2, Hermes, Build, Standard Library
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-09-11
**Related:** LLP 0067 §5, LLP 0068 OQ2, Snapback LLP 1003 §1

The Linux vanilla-Hermes engine is linkable, self-contained, and passes the
Ibex engine/transport suite, but it does not yet support the standard-library
surface its consumer requires. This blocks qualification and publication of
the Linux Snapback artifact; it must not be waived by weakening the witness.

At exact pinned Hermes commit
`6badada762121682b5481b6124e6c3a991ae6046`,
`lib/Platform/Intl/PlatformIntlICU.cpp` defines `NumberFormatDummy` (lines
981–1024). It:

- ignores the requested locales and options;
- hardcodes `supportedLocalesOf` to `en-CA` and `de-DE`;
- hardcodes the resolved locale to `en-US` and returns no normal number-format
  options;
- formats with `std::to_string`; and
- returns the entire decimal as one `integer` part, with the source comment
  that this is not correct and is a stub.

The qualified Ubuntu 24.04.4 engine produced this direct evidence:

```text
plain:    7.000000
grouped:  1234567.890000
rounded:  7.126000       (requested exactly two fractional digits)
currency: 7.000000       (requested en-US USD)
percent:  0.250000       (requested percent)
parts:    [{"value":"7.000000","type":"integer"}]
```

Snapback's compile-and-execute witness requires
`new Intl.NumberFormat("en-US").format(7) === "7"`. With the release Linux
engine, its final no-fail-fast effects run passes 74 tests and fails only that
Intl witness. The preceding redirect failures were test portability defects:
Linux `ureq` writes `Content-Length: 0` for a bodyless request where Darwin
omits the header; the tests now admit only those two wire forms while still
proving the authored length and body were dropped.

There is no existing build escape in the available Hermes objects. The exact
pin, `main`, stable, staging, and `static_h` refs all contain the same dummy;
`HERMES_USE_STATIC_ICU` changes linkage but not this implementation. Android's
implementation is Java/JNI and Apple's uses Foundation. Replacing the Hermes
source or its archive would violate Ibex 2's unpatched-vanilla receipt.

Bounded viable directions need an author choice:

1. install a standards-compatible NumberFormat implementation in Ibex's
   pre-hardening standard-library tier, backed by the already-static ICU4C
   closure;
2. install a complete standards polyfill and its locale data before hardening,
   then qualify its size and packaged dependency closure; or
3. remove `Intl` from the cross-platform authored surface until upstream
   supplies it.

## Implementation disposition, 2026-09-11

The author selected direction 1. Ibex now installs a Linux-only trusted Intl
completion before hardening while leaving vanilla Hermes unchanged. Rust owns
locale negotiation, normalized options, formatter state, special-number
handling, parts, and lifetime; the already-static ICU4C closure performs the
native locale computation. Thin build-time JavaScript bytecode preserves
ECMAScript `Get`/coercion order, ordinary constructor behavior, receivers,
prototypes, and bound format functions. Opaque JSI native owners keep formatter
state alive without exposing raw handles or creating a JavaScript/native
strong-reference cycle.

The completed selected surface includes `Intl.NumberFormat`, Number and BigInt
locale formatting, String locale lower/upper case mapping, and a native-owned
`Intl.DateTimeFormat` whose `format` and `formatToParts` share one formatter;
the dependent Date locale methods use it. It does not add the Intl constructors
absent from both engine profiles or claim complete ECMA-402 conformance.
`formatMatcher: "basic"` is validated and observable in the required option
order but currently shares ICU's best-pattern selection with `"best fit"`.

One exact exotic-constructor limitation remains. On pinned Hermes,
`Reflect.construct(Intl.NumberFormat, args, NewTarget)` (and the corresponding
DateTimeFormat form) uses `Object.prototype` when `NewTarget.prototype` is not
an object; ECMA-402 requires the matching Intl prototype. Normal calls,
ordinary construction, subclasses, custom object prototypes, and the one
observable prototype read before locale coercion are covered and pass. The
engine's callable-Proxy path performs ordinary allocation and the observable
prototype read before looking up the construct trap, so a Proxy replacement
would read twice. Public JSI exposes callable host functions but no custom
`[[Construct]]` callback. After three bounded implementation rounds, the
remaining case is preserved as an ignored expected-correct regression rather
than hidden with a second read, descriptor heuristic, or Hermes patch.

The Linux focused suite passes 31 tests spanning these operations and the
narrow integrity-snapshot admission. The complete Hermes suite passes with no
failures, including deadlines, fetch/redirect/body/cancellation semantics,
the exact global surface, freeze, and the regression that mutating an admitted
Intl intrinsic after trusted installation still makes SQLite refuse. One
diagnostic run also found Hermes's canonical NaN carried a sign bit into ICU;
normalizing NaN while preserving real signed zero and infinity fixed the parts
and all four `signDisplay` modes without weakening their expected output.

The issue remains open until the unchanged Snapback real-runtime Intl witness,
complete Linux effects suite, and publication-stage artifact qualification are
green. No publication qualification is claimed by this implementation record.

**Done when:** an unpatched pinned Hermes plus the shipped Ibex standard-library
tier passes the unchanged Snapback Intl witness on Linux, representative
grouping/rounding/currency/percent/parts tests pass, the static closure remains
self-contained, and the complete Linux effects and publication qualification
runs are green.
