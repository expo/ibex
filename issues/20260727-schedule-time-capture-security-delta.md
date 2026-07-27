# Adjudicate: schedule-time principal capture vs the compat token-auth design

**Status:** Open
**Severity:** P3
**Systems:** Security, Engine
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-27
**Related:** [20260727-upstream-snapback-compat-abi](./20260727-upstream-snapback-compat-abi.md); LLP 0040 step 4

The retired compat branch's `c791baa2` hardened async capability
continuations with registration-bound one-shot reaction tokens
(FetchAuthorizationHostObject, revised Hermes patch 0008 + a token-auth
patch 0009, promise-rejection-tracking rewrite). Main solved async
attribution differently — unconditional schedule-time principal capture
(patch 0008, still carrying the pre-`c791baa2` "(Open-Q3)" comment) with
per-fetch-entry principals rescoped at completion via
`ScopedNativePrincipal`, plus the typed `ex_host_authorize_*_stack` family.

Whether main's unauthenticated schedule-time capture is security-equivalent
to the compat token design **was never adjudicated on main**. The LLP 0040
step-1 audit dispositions the compat continuation-auth core as DROPPABLE
for the snapback pin advance (snapback neither links nor configures it),
but the analysis itself should not be silently discarded when the compat
refs retire (LLP 0040 step 4).

**Done when:** a real security review compares the two designs (can a
package-authored reaction launder a continuation onto a stronger principal
under main's capture? does the token design close anything main's typed
decision stack leaves open?) and either affirms main's design with the
"(Open-Q3)" comment resolved, or files the gap as engine work.
