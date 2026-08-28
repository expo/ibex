# WPT URL: `///path` against an http base reports empty host

**Status:** Closed
**Resolution:** Accepted as a deliberate divergence: the spec resolves ///host as an origin CHANGE for special schemes, and refusing to parse it fails closed. A test in fetch.rs pins that a ///-bearing Location cannot reach another origin. LLP 0061 §3 records the reasoning; the 828 baseline stands.
**Systems:** Runtime, Standard Library
**Severity:** P3
**Author:** Charlie Cheever
**Date:** 2026-08-28

Three cases in the vendored WPT URL suite fail on the `http` scheme, which unlike the rest of the divergence list is the measured surface:

    "///test"            base http://example.org/  ->  want http://test/
    "///\\//\\//test"    base http://example.org/  ->  want http://test/
    "///example.org/path" base http://example.org/ ->  want http://example.org/path

We report `TypeError: invalid URL: empty host`. Per WHATWG, a leading `///` against a special-scheme base takes the next non-empty segment as the host.

This is the `url` crate's behaviour, so the fix is upstream, a local pre-normalization, or an accepted divergence — decide before writing code. It is scheduled rather than accepted because `http` is what applications actually use, per LLP 0061 §3.

Closing this raises the WPT URL baseline in `crates/ibex2/tests/wpt_url.rs` from 828 to 831. Raise the constant in the same commit, per LLP 0061 D2.
