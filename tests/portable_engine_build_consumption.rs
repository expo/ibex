// Compile the production build-support module as an ordinary test module so
// its pure selector/refusal tests run under `cargo test`; Cargo does not build
// a separate test harness for build.rs itself.
#![cfg(unix)]
#![allow(dead_code)]

#[path = "../build_support/portable_engine_build_consumption.rs"]
mod portable_engine_build_consumption;
#[cfg(target_os = "macos")]
#[path = "../build_support/portable_engine_build_preflight.rs"]
mod portable_engine_build_preflight;
#[cfg(not(target_os = "macos"))]
#[path = "../build_support/portable_engine_build_preflight_unsupported.rs"]
mod portable_engine_build_preflight;
#[cfg(target_os = "macos")]
#[path = "../build_support/portable_engine_promotion_report.rs"]
mod portable_engine_promotion_report;
#[path = "../build_support/portable_host_tool_runner.rs"]
mod portable_host_tool_runner;
