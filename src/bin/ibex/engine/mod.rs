//! JavaScript engine abstraction layer
//!
//! This module provides a unified interface for different JS engines.
//! Hermes is the only shipped engine; the `Engine` trait and factory are
//! the seam for future engines, which require their own Accepted LLP and a
//! feature-gated build before any value re-enters the public surface.
//! @ref LLP 0010#runtime-command-surface — public engine choices must be true.

pub mod hermes;
pub use ibex_runtime::engine::sourcemap;

use anyhow::Result;
use std::sync::Arc;

/// The JavaScript engine interface
///
/// This trait defines the operations that all engines must support.
/// It's designed to be engine-agnostic while allowing engine-specific
/// features through downcast patterns.
#[async_trait::async_trait]
#[allow(dead_code)]
pub trait Engine: Send + Sync {
    /// Get the engine name
    fn name(&self) -> &str;

    /// Get the engine version
    fn version(&self) -> Result<String>;

    /// Load the Ibex runtime bundle into the engine
    async fn load_runtime(&self) -> Result<()>;

    /// Evaluate JavaScript code and return the result
    async fn eval(&self, code: &str) -> Result<Option<String>>;

    /// Evaluate JavaScript code without driving the event loop afterwards.
    /// Use this for setup code that should not trigger timer-based side effects.
    async fn eval_immediate(&self, code: &str) -> Result<Option<String>> {
        self.eval(code).await
    }

    /// Execute all currently-ready event-loop work (due timers, drained
    /// microtasks/callbacks, pending debugger interrupts) without blocking on
    /// future timers. The keep-alive/debug loop calls this on its own cadence to
    /// keep the runtime responsive to DevTools. Engines without an event loop
    /// leave this a no-op. (ENG-22958)
    async fn drive_ready_tasks(&self) -> Result<()> {
        Ok(())
    }

    /// Drive the event loop to quiescence — like `eval` does after running code,
    /// but without evaluating anything. The REPL calls this once its input
    /// stream ends (EOF) so pending timers/async callbacks scheduled during the
    /// session finish before the process exits, matching Node's REPL and
    /// `ibex <file>`. Unlike `drive_ready_tasks` this blocks until no work
    /// remains, so it is only safe after the prompt is gone. Engines without an
    /// event loop leave this a no-op. (ENG-23001)
    async fn drain_event_loop(&self) -> Result<()> {
        Ok(())
    }

    /// Run a JavaScript file
    async fn run_file(&self, path: &str) -> Result<Option<String>>;

    /// Start the Chrome DevTools Protocol inspector
    async fn start_inspector(&self, host: &str, port: u16) -> Result<()>;

    /// Stop the inspector
    async fn stop_inspector(&self) -> Result<()>;

    /// Wait for a debugger client to attach (optional)
    async fn wait_for_inspector(&self) -> Result<()> {
        Ok(())
    }

    /// Wait for the Debugger domain to be enabled (optional)
    async fn wait_for_debugger(&self) -> Result<()> {
        Ok(())
    }

    /// Check if the engine supports a specific feature
    fn supports_feature(&self, feature: EngineFeature) -> bool;
}

/// Features that may or may not be supported by different engines
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EngineFeature {
    /// Hermes bytecode compilation
    BytecodeCompilation,
    /// Chrome DevTools Protocol debugging
    CdpDebugging,
    /// Source maps
    SourceMaps,
    /// Top-level await
    TopLevelAwait,
    /// ESM modules
    EsmModules,
    /// CommonJS modules
    CommonJsModules,
}

/// Create an engine instance by name
///
/// The CLI's clap value list rejects non-Hermes names before this runs; the
/// unknown-engine arm guards internal callers.
pub fn create_engine(name: &str) -> Result<Arc<dyn Engine>> {
    match name {
        "hermes" => Ok(Arc::new(hermes::HermesEngine::new()?)),
        other => anyhow::bail!("Unknown engine: {other}. Ibex currently supports Hermes only."),
    }
}

// Re-export async_trait for the trait definition
pub use async_trait::async_trait;
