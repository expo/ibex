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

# with real crypto (required on Linux — no platform crypto backend there)
cargo build --features openssl-crypto
```

`build.rs` auto-detects the standalone layout; `HERMES_INCLUDE_DIR` and
`HERMES_LIB_DIR` override the Hermes locations.

## Crypto profiles

- **`openssl-crypto`** — real hashing/HMAC/sign via OpenSSL. Required on Linux.
- **default (no OpenSSL)** — uses platform crypto on macOS/Windows; on Linux it
  has no backend and asymmetric sign/verify register as throwing stubs (see
  Exact LLP 0180 §5.4).
