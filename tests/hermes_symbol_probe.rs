// Compile the production build-support parser as an ordinary test module so
// its exact-symbol and fail-closed fixtures run under `cargo test`; Cargo does
// not build a separate test harness for build.rs itself.
#![allow(dead_code)]

#[path = "../build_support/hermes_symbol_probe.rs"]
mod hermes_symbol_probe;
