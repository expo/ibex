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

    /// Evaluate a trusted entry wrapper whose returned Promise is the entry's
    /// completion contract (for example, lowered top-level await). Engines may
    /// use this distinction to avoid treating an ordinary script's incidental
    /// Promise result as a fatal entry rejection. (ENG-24933)
    /// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
    async fn eval_awaited_entry(&self, code: &str) -> Result<Option<String>> {
        self.eval(code).await
    }

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

    /// Park until the next scheduled event-loop wakeup (the soonest due timer) or
    /// a background callback, so the idle REPL prompt can stop polling at a fixed
    /// 20 Hz cadence. Engines without an event loop just sleep a short interval.
    /// (ENG-23030 #5)
    async fn wait_for_pending_tasks(&self) {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    /// Run a JavaScript file
    async fn run_file(&self, path: &str) -> Result<Option<String>>;

    /// Evaluate an already-read bytecode buffer. Generated-code caches use
    /// this path so the exact bytes whose digest was verified are the bytes
    /// executed; reopening a cache pathname after verification is a TOCTOU.
    async fn run_bytecode_bytes(&self, _bytes: &[u8], _source_url: &str) -> Result<Option<String>> {
        anyhow::bail!(
            "{} does not support in-memory bytecode execution",
            self.name()
        )
    }

    /// Evaluate one fully authenticated source graph through the native module
    /// runner. Engines without that ABI fail closed instead of reopening or
    /// rebundling the admitted sources.
    #[cfg(feature = "module-runner")]
    async fn run_authenticated_module_graph(
        &self,
        _graph: &crate::module_loader::runner_pipeline::SourceModuleGraphV1,
    ) -> Result<Option<String>> {
        anyhow::bail!("{} has no authenticated native module runner", self.name())
    }

    /// Run a JavaScript file WITHOUT driving the event loop to quiescence, so a
    /// long-lived server/timer started by the file returns control to the caller.
    /// The REPL's `.load` uses this and lets its idle pump drive background work,
    /// instead of wedging the prompt on `drive_event_loop`. Defaults to
    /// `run_file`. (ENG-23030 #2)
    async fn run_file_immediate(&self, path: &str) -> Result<Option<String>> {
        self.run_file(path).await
    }

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
pub fn create_engine(name: &str, armed_snapshot_digest: Option<&str>) -> Result<Arc<dyn Engine>> {
    match name {
        "hermes" => Ok(Arc::new(hermes::HermesEngine::new_with_armed_snapshot(
            armed_snapshot_digest,
        )?)),
        other => anyhow::bail!("Unknown engine: {other}. Ibex currently supports Hermes only."),
    }
}

// Re-export async_trait for the trait definition
pub use async_trait::async_trait;
