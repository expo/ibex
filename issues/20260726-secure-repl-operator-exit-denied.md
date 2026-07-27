# Secure REPL rejects operator Ctrl-D after publishing its prompt

**Status:** Open
**Impact:** 3
**Urgency:** 4
**Ease:** 4
**Confidence:** 5
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Secure REPL rejects operator Ctrl-D after publishing its prompt” shows the issue materially affects reliability, verification, or developer experience; delay compounds an active rollout, reliability, or verification risk, while the implementation is localized and has concrete acceptance witnesses, with a direct reproduction or current implementation proof.
**Date:** 2026-07-26
**Related:** issues/20260724-insecure-startup-performance.md

## Problem

An Ibex secure-development build reaches and publishes the REPL prompt, but
Ctrl-D on an empty edit buffer exits with status 1:

```text
error: operator exit was denied by the typed lifecycle route
```

The same operator EOF exits successfully in the default/insecure build.

## Reproduction

```sh
cargo build --release --bin ibex --no-default-features \
  --features standard,unadvertised-dev-arming
printf '\004' | script -q /dev/null target/release/ibex repl
```

## Expected

Operator EOF after a ready prompt follows an authorized lifecycle route and
terminates the secure REPL successfully.

## Notes

This was discovered while adding the startup distribution harness. That
harness measures only process launch through truthful prompt publication and
now terminates and reaps its pseudoterminal wrapper after the measured
boundary, keeping this functional lifecycle bug independently visible here.
