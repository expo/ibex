# Ibex

**Ibex** is the JavaScript/TypeScript **runtime** used by [Exact](https://github.com/ccheever/exact)
and [Snapback](https://github.com/ccheever/valet). It embeds Hermes and exposes
a small, stable host ABI so native hosts can create runtimes, evaluate JS/HBC,
and install host calls.

Analogous in spirit to `node`, `bun`, or `deno` — a runtime, not an app
framework. The `ibex` runtime binary lives in this repo. The Exact project CLI
and app framework live in the `exact` repo.

> **Status: extracted "for now."** This repository was split out of the Exact
> monorepo as a history-preserving extraction. It will be re-homed under the
> `expo` org later.

## What's here

- The `ibex-runtime` Rust crate (Hermes bindings in `src/engine/*.cc`, the
  host ABI in `src/host`, the module loader, vendored Brotli).
- The `ibex` runtime binary (`src/bin/ibex`) for running JavaScript and
  TypeScript files.
- The Hermes build scripts (`scripts/build-hermes-*.sh`, `download-hermes.sh`).

## The contract

Consumers depend on a deliberately narrow surface (see [LLP 0002](./llp/0002-host-embedding-abi.spec.md)):

- The lifecycle/evaluation C ABI: production construction uses
  `ex_hermes_create_armed`; the historical `ex_hermes_create` symbol always
  refuses, and `ex_hermes_create_diagnostic` is explicitly non-production.
  Runtime driving continues through `ex_hermes_destroy`, `ex_hermes_eval`,
  `ex_hermes_free_string`, and the diagnostic-only
  `ex_hermes_set_host_call`. Armed runtimes silently reject the generic host
  bridge and expose only dedicated native APIs.
- The Rust host ABI: `ibex_runtime::host::{install_host, Host}`.

## Building

Ibex needs Hermes headers + a prebuilt `libhermesvm`. Install/build them with
`./scripts/download-hermes.sh`, which delegates to the platform source builder
and defaults to Hermes `260318099.0.0-stable`. The platform-specific entry
points are `./scripts/build-hermes-linux.sh` on Linux and
`./scripts/build-hermes.sh` on macOS/iOS. They install ignored native artifacts
into `linux/`, `ios/Frameworks/`, and `tools/hermes/`. Then:

```sh
# default profile
cargo build

# runtime binary
cargo build --bin ibex

# full runtime CLI profile
cargo build --bin ibex --features host-http-server,cli-notify

# full native crypto on Linux
cargo build --features openssl-crypto
```

Run the local binary with:

```sh
cargo run --bin ibex -- --version
```

`build.rs` auto-detects the standalone layout; `HERMES_INCLUDE_DIR` and
`HERMES_LIB_DIR` override the Hermes locations. `HERMES_VERSION` can override
the source ref passed to the build scripts; `scripts/hermes-version.sh` holds
the repo default.

Linux native networking requires `pkg-config` and libcurl >= 7.86 so Fetch and
WebSocket use libcurl. For constrained local builds only,
`IBEX_ALLOW_CURL_CLI_FALLBACK=1` enables a degraded fetch-only fallback that
shells out to `curl`; WebSocket remains unavailable in that fallback profile.

### Android

Android builds consume the same Maven/PREFAB artifacts Android apps already use:
`com.facebook.hermes:hermes-android` for Hermes and
`com.facebook.react:react-android` for JSI. Install/extract them, then build
through the NDK wrapper:

```sh
./scripts/install-android-hermes.sh
ANDROID_TARGET=aarch64-linux-android ./scripts/cargo-android.sh
```

Android currently requires `--features openssl-crypto`; the wrapper includes it
by default. Native Android fetch/WebSocket use OkHttp through the Android
Java/JNI bridge in `platform/android/java/dev/ibex/runtime/IbexNetworking.java`.
The same bridge provides Android clipboard, raw DNS, location, camera
permission/device metadata, locale, screen, appearance/accessibility, app
lifecycle/configuration/deep-link events, and platform-version data to the JS
runtime.
Embedding apps must include that Java source, add OkHttp to the Android
classpath (for example `implementation("com.squareup.okhttp3:okhttp:5.4.0")`),
and call `ex_android_initialize(JavaVM*, Context)` before creating a runtime
that should observe Android platform data or use networking APIs. The wrapper
also sets `EXACT_ALLOW_FALLBACK=1` unless already set, so
AAR-based builds can use bootstrap JS source when no matching host `hermesc` is
installed. `HERMES_ANDROID_VERSION`, `REACT_ANDROID_VERSION`,
`ANDROID_HERMES_VARIANT`, and `ANDROID_API` are overrideable. The default
Android artifact pair is `hermes-android:250829098.0.14` with
`react-android:0.86.0`, because Maven Central does not yet publish
`hermes-android:260318099.0.0` and the JSI PREFAB must include
`jsi/hermes-interfaces.h`.

## Crypto profiles

- **`openssl-crypto`** — full native crypto on Linux via OpenSSL, including
  hashing/HMAC, AES, PBKDF2/scrypt/HKDF, asymmetric sign/verify/key generation,
  and key import/export. Optional on macOS.
- **Android** — currently uses the `openssl-crypto` profile with vendored
  OpenSSL.
- **default (no OpenSSL)** — uses platform crypto on Apple/Windows. On Linux it
  now builds without OpenSSL and provides the reduced portable surface used by
  core runtime flows: MD5/SHA-1/SHA-2 hashing, HMAC, PBKDF2, scrypt, and HKDF.
  Linux AES and asymmetric crypto still require `openssl-crypto`.
