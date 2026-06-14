# Ibex

**Ibex** is the JavaScript/TypeScript **runtime** used by [Exact](https://github.com/ccheever/exact)
and [Snapback](https://github.com/ccheever/valet). It embeds Hermes and exposes
a small, stable host ABI so native hosts can create runtimes, evaluate JS/HBC,
and install host calls.

Analogous in spirit to `node`, `bun`, or `deno` — a runtime, not an app
framework. The Exact project CLI and app framework live in the `exact` repo;
this repo is just the runtime.

> **Status: extracted "for now."** This repository was split out of the Exact
> monorepo per **LLP 0180** (history-preserving). It will be re-homed under the
> `expo` org later. The Rust crate is still named `exact-runtime` during the
> transition to avoid churning downstream consumers; renaming to `ibex` is a
> follow-up.

## What's here

- The `exact-runtime` Rust crate (Hermes bindings in `src/engine/*.cc`, the
  host ABI in `src/host`, the module loader, vendored Brotli).
- The Hermes build scripts (`scripts/build-hermes-*.sh`, `download-hermes.sh`).

## The contract

Consumers depend on a deliberately narrow surface (see Exact LLP 0038):

- Five C ABI functions: `ex_hermes_create`, `ex_hermes_destroy`,
  `ex_hermes_eval`, `ex_hermes_free_string`, `ex_hermes_set_host_call`.
- The Rust host ABI: `exact_runtime::host::{install_host, Host}`.

## Building

Ibex needs Hermes headers + a prebuilt `libhermesvm`. Build them with
`./scripts/build-hermes-linux.sh` (Linux) or `./scripts/download-hermes.sh`
(macOS), which install into `linux/` and `tools/hermes/`. Then:

```sh
# default profile
cargo build

# full native crypto on Linux
cargo build --features openssl-crypto
```

`build.rs` auto-detects the standalone layout; `HERMES_INCLUDE_DIR` and
`HERMES_LIB_DIR` override the Hermes locations.

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
The same bridge provides Android clipboard, raw DNS, location, locale, screen,
appearance/accessibility, app lifecycle/configuration/deep-link events, and
platform-version data to the JS runtime.
Embedding apps must include that Java source, add OkHttp to the Android
classpath (for example `implementation("com.squareup.okhttp3:okhttp:5.4.0")`),
and call `ex_android_initialize(JavaVM*, Context)` before creating a runtime
that should observe Android platform data or use networking APIs. The wrapper
also sets `EXACT_ALLOW_FALLBACK=1` unless already set, so
AAR-based builds can use bootstrap JS source when no matching host `hermesc` is
installed. `HERMES_ANDROID_VERSION`, `REACT_ANDROID_VERSION`,
`ANDROID_HERMES_VARIANT`, and `ANDROID_API` are overrideable. The default
Android artifact pair is `hermes-android:250829098.0.14` with
`react-android:0.86.0-rc.3`, because that JSI PREFAB includes the
`jsi/hermes-interfaces.h` header required by current Hermes Android headers.

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
