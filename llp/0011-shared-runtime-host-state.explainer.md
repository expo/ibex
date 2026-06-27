# LLP 0011: Shared Runtime Host State

**Type:** Explainer
**Status:** Draft
**Systems:** Runtime, Engine, Host ABI, Android, Web APIs
**Author:** Charlie Cheever / Codex
**Date:** 2026-06-27
**Related:** LLP 0000; LLP 0003; LLP 0008

## Summary

Ibex exposes host-provided app and device state through a small set of global
snapshots and update hooks, then fans that state out to web, Exact, and
React Native compatibility APIs. This state is broader than one Android
backend, but Android is currently the most complete producer: it seeds locale,
screen, appearance, accessibility, app-state, storage-root, and platform
metadata globals during runtime initialization `[observed]`
(`src/engine/hermes_runtime_android.cc`;
`platform/android/java/dev/ibex/runtime/IbexNetworking.java`). The runtime JS
consumes those globals from `packages/ibex-runtime-js/src/core/*-state.ts`,
`window`, `navigator`, `locale`, `accessibility`, and `react-native`
compatibility modules `[observed]` (`packages/ibex-runtime-js/src`).

The key shape is: native hosts publish plain snapshot globals; state-only JS
modules normalize them and hold listeners; public API modules install user
facing namespaces and callbacks.

## State Modules

Locale and accessibility are split into state-only modules and public API
modules:

- `core/locale-state.ts` owns `__exactLocaleState`, reads
  `__exactLocaleSnapshot` / legacy locale globals, normalizes tags and
  direction, stores overrides, and emits locale listeners `[observed]`.
- `core/locale.ts` installs `Exact.locale` and wires
  `__exactLocaleChanged(snapshot)` to update the shared state `[observed]`.
- `core/accessibility-state.ts` owns `__exactAccessibilityState`, reads
  `__exactAccessibilitySnapshot` and `__exactAppearanceState`, mirrors
  appearance state, and emits accessibility / appearance-related listeners
  `[observed]`.
- `core/accessibility.ts` installs `Exact.accessibility`, exposes
  `AccessibilityInfo`, and wires `__exactAccessibilityChanged(snapshot)`
  `[observed]`.

`[inferred: the state-only split lets modules such as `navigator`, `window`,
and React Native compatibility read or subscribe to the same normalized state
without forcing every public `Exact.*` namespace or host-call helper to install
at import time.]`

## Host Snapshot Contract

The native-to-JS contract is deliberately plain data:

- Locale: `__exactLocaleSnapshot`, legacy `__exactLocale`, and
  `__exactHostNavigator` language fields.
- Accessibility and appearance: `__exactAccessibilitySnapshot` and
  `__exactAppearanceState`.
- Window / React Native compatibility: `__exactScreenInfo`,
  `__exactAppState`, `__exactAndroidStoragePaths`, platform-version globals,
  and notifier functions such as `__exactReactNativeNotifyDimensionsChange`
  and `__exactReactNativeNotifyAppState`.

The Android bridge currently seeds many of those globals from Android
Resources, DateFormat, AccessibilityManager, Activity lifecycle callbacks, and
configuration callbacks; [LLP 0008](./0008-platform-backend-parity-audit.research.md)
tracks the Android-specific backend and verification status.

## Consumers

The shared runtime state feeds several public surfaces:

- `navigator.language` / `navigator.languages` read normalized locale state.
- `window` media-query and resize/orientation behavior observe appearance,
  locale, accessibility, screen, and app-state updates.
- React Native compatibility shims expose `Dimensions`, `Appearance`,
  `AppState`, and `Linking`-style data from the same host state.
- `Exact.locale` and `Exact.accessibility` expose the normalized snapshots and
  listener APIs directly.

This keeps host state coherent across web-standard APIs, Exact-specific APIs,
and React Native compatibility APIs instead of giving each surface its own
private snapshot.

## Boundaries

- This LLP documents the shared state shape and import/notification split. It
  does not choose individual platform backends; platform backend choices and
  verification gaps live in [LLP 0008](./0008-platform-backend-parity-audit.research.md).
- State globals are not a stable public embedding ABI by themselves. The stable
  host/embedding boundary is [LLP 0002](./0002-host-embedding-abi.spec.md);
  these globals are the runtime JS layer's current host-state convention.
