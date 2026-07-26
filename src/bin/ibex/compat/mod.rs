//! Compatibility test suite runner (`ibex compat`, hidden harness command).
//!
//! Runs WPT, Node.js, Bun, and Exact-specific compatibility tests with a
//! process pool and JSON result output. The fixture tree (`test/compat/`)
//! lives in the exact repo; this command is exercised from there, both by the
//! registered `websocket-wpt-compat` / `websocket-server-compat` checks and by
//! humans (see LLP 0010#runtime-command-surface for why it is hidden).
//!
//! Ported from exact's orphaned `packages/exact-cli/src/compat/` at exact
//! commit 96a82fa1d1ea2057e86e03fa22f78763057bf62c after the LLP 0180 split
//! stranded those sources uncompiled (ENG-23081; the originals were deleted in
//! exact ENG-23079). Two deliberate deltas from the original:
//!
//!   * The ratatui live dashboard was not ported — it pulled ratatui +
//!     crossterm into the runtime-only binary for an interactive nicety CI
//!     never uses (CI is non-TTY and passes `--log`/`--json`). Interactive
//!     runs use the plain streaming runner instead.
//!   * `num_cpus` was replaced with `std::thread::available_parallelism`.

mod discovery;
mod expectations;
mod manifest;
mod probe;
mod reporter;
mod runner;
mod types;

use anyhow::Result;
use tokio::sync::mpsc;

use types::{RunnerEvent, TestStatus};

pub use types::CompatOptions;

/// Recover the inner value from poisoned mutexes so one panic does not
/// permanently take down the rest of the process. Duplicates the private
/// `ibex_runtime::sync::lock_or_recover` — the lib module is deliberately
/// not re-exported for a harness-only consumer.
pub(crate) fn lock_or_recover<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Entry point for `ibex compat`.
pub async fn run_compat(opts: CompatOptions) -> Result<()> {
    // Probe mode is a standalone measurement harness (Exact LLP 0404 N-1):
    // it needs no fixture tree, so it must run before the repo-root/fixture
    // discovery that the suite mode requires.
    if let Some(probe_expr) = &opts.probe {
        return probe::run_probe(probe_expr, opts.timeout).await;
    }

    let repo_root = find_repo_root()?;
    let compat_dir = repo_root.join("test").join("compat");

    if !compat_dir.exists() {
        anyhow::bail!(
            "Compatibility test directory not found: {}\nRun from the Exact repo root.",
            compat_dir.display()
        );
    }

    // Load manifests for requested sections
    let manifests = manifest::load_manifests(&compat_dir, &opts)?;

    if manifests.is_empty() {
        eprintln!("No test manifests found. Nothing to run.");
        return Ok(());
    }

    // Discover tests based on manifests and filters
    let test_plan = discovery::discover_tests(&compat_dir, &manifests, &opts)?;

    if test_plan.tests.is_empty() {
        eprintln!("No tests matched the given filters.");
        return Ok(());
    }

    let total_tests = test_plan.tests.len();
    eprintln!(
        "Discovered {} tests across {} sections",
        total_tests,
        test_plan.section_counts().len()
    );

    // Run tests with the process pool. The original exact-cli offered a
    // ratatui dashboard for interactive TTY runs; this port streams with
    // `--log` and otherwise uses the plain runner (see module docs).
    let results = if opts.log {
        run_with_log_output(&compat_dir, &test_plan, &opts).await?
    } else {
        runner::run_tests(&compat_dir, &test_plan, &opts).await?
    };

    // Update expectations if requested
    if opts.update_expectations {
        expectations::update_expectations(&compat_dir, &results)?;
        eprintln!("Expectations updated.");
    }

    // Output results
    if opts.json {
        let json = serde_json::to_string_pretty(&results)?;
        println!("{}", json);
    } else {
        reporter::print_summary(&results);
    }

    // Save results to history
    reporter::save_results(&compat_dir, &results)?;

    // Generate web report if requested
    if opts.report {
        reporter::serve_report(&compat_dir)?;
    }

    // Check for regressions
    let regressions = expectations::check_regressions(&compat_dir, &results)?;
    if !regressions.is_empty() {
        eprintln!("\n{} regressions detected:", regressions.len());
        for reg in &regressions {
            eprintln!(
                "  REGRESSION: {} (expected {}, got {})",
                reg.test_id, reg.expected, reg.actual
            );
        }
        // Exit with error code for CI
        std::process::exit(1);
    }

    Ok(())
}

async fn run_with_log_output(
    compat_dir: &std::path::Path,
    test_plan: &types::TestPlan,
    opts: &CompatOptions,
) -> Result<types::CompatResults> {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<RunnerEvent>();
    let compat_dir = compat_dir.to_path_buf();
    let test_plan = test_plan.clone();
    let opts = opts.clone();
    let opts_for_task = opts.clone();

    let total_tests = test_plan.tests.len();
    let run_task = tokio::spawn(async move {
        runner::run_tests_with_events(&compat_dir, &test_plan, &opts_for_task, event_tx).await
    });

    eprintln!("Streaming test results ({} total)", total_tests);
    let mut completed = 0usize;
    let mut failed_tests = 0usize;

    while let Some(event) = event_rx.recv().await {
        if let RunnerEvent::TestCompleted {
            id,
            section,
            result,
            ..
        } = event
        {
            completed += 1;
            let section_name = section.as_str();
            let duration = result.duration_ms;
            let status_label = format_status(result.status, opts.log_color);
            let is_failure = matches!(
                result.status,
                TestStatus::Fail | TestStatus::Crash | TestStatus::Timeout
            );

            match result.status {
                TestStatus::Pass => {
                    eprintln!(
                        "[{}/{}] {} {} [{}ms]",
                        completed, total_tests, status_label, id, duration
                    );
                }
                TestStatus::Flaky => {
                    eprintln!(
                        "[{}/{}] {} {} [{}ms] ({} retries)",
                        completed,
                        total_tests,
                        status_label,
                        id,
                        duration,
                        result.retries.unwrap_or_default()
                    );
                    if let Some(error) = result.error {
                        eprintln!("         {}", short_or(error, 1200));
                    }
                }
                TestStatus::Skip => {
                    if opts.log_no_skip {
                        continue;
                    }
                    eprintln!(
                        "[{}/{}] {} {} [{}ms]",
                        completed, total_tests, status_label, id, duration
                    );
                }
                _ if is_failure => {
                    failed_tests += 1;
                    eprintln!(
                        "[{}/{}] {} ({}) {} [{}ms]",
                        completed, total_tests, section_name, status_label, id, duration
                    );
                    if let Some(error) = result.error {
                        eprintln!("         {}", short_or(error, 1200));
                    } else if let Some(stack) = result.stack {
                        eprintln!("         {}", short_or(stack, 1200));
                    }
                }
                _ => {
                    eprintln!(
                        "[{}/{}] {} {} [{}ms]",
                        completed, total_tests, status_label, id, duration
                    );
                }
            }
        }
    }

    let results = run_task
        .await
        .map_err(|err| anyhow::anyhow!("compat log runner task failed: {err}"))??;

    if failed_tests > 0 {
        eprintln!(
            "Completed with {} failing test files ({} passed).",
            failed_tests,
            total_tests.saturating_sub(failed_tests)
        );
    } else {
        eprintln!("Completed with all tests passing.");
    }

    Ok(results)
}

fn format_status(status: TestStatus, color: bool) -> String {
    let raw = match status {
        TestStatus::Pass => "PASS",
        TestStatus::Fail => "FAIL",
        TestStatus::Skip => "SKIP",
        TestStatus::Timeout => "TIMEOUT",
        TestStatus::Crash => "CRASH",
        TestStatus::Flaky => "FLAKY",
    };
    if !color {
        return raw.to_string();
    }

    match status {
        TestStatus::Pass => format!("\x1b[32m{}\x1b[0m", raw),
        TestStatus::Fail | TestStatus::Timeout | TestStatus::Crash => {
            format!("\x1b[31m{}\x1b[0m", raw)
        }
        TestStatus::Flaky => format!("\x1b[33m{}\x1b[0m", raw),
        TestStatus::Skip => format!("\x1b[34m{}\x1b[0m", raw),
    }
}

fn short_or(text: String, max_len: usize) -> String {
    if text.chars().count() <= max_len {
        return text;
    }
    let end = text
        .char_indices()
        .nth(max_len)
        .map(|(idx, _)| idx)
        .unwrap_or(text.len());
    format!("{}...", &text[..end])
}

/// Locate the repo root holding the `test/compat/` fixture tree.
///
/// The fixtures live in the exact repo, where this binary is vendored at
/// `vendor/ibex` — so CARGO_MANIFEST_DIR's grandparent is the exact root in
/// registry-check runs (`cargo run -p ibex-runtime --bin ibex -- compat …`).
/// For direct invocations from a checkout, walk up from the cwd (and, as a
/// last resort, the executable path).
fn find_repo_root() -> Result<std::path::PathBuf> {
    // Try CARGO_MANIFEST_DIR first (available during cargo build/run)
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let path = std::path::PathBuf::from(manifest_dir);
        // The manifest dir itself, or (for the vendor/ibex layout) two
        // levels up, may be the repo root that carries test/compat.
        if path.join("test").join("compat").exists() {
            return Ok(path);
        }
        if let Some(root) = path.parent().and_then(|p| p.parent()) {
            if root.join("test").join("compat").exists() {
                return Ok(root.to_path_buf());
            }
        }
    }

    // Walk up from current directory looking for test/compat/
    let mut current = std::env::current_dir()?;
    loop {
        if current.join("test").join("compat").exists() {
            return Ok(current);
        }
        if !current.pop() {
            break;
        }
    }

    // Walk up from executable location
    if let Ok(exe) = std::env::current_exe() {
        let mut current = exe;
        while current.pop() {
            if current.join("test").join("compat").exists() {
                return Ok(current);
            }
        }
    }

    anyhow::bail!("Could not find Exact repo root (looking for test/compat/ directory)")
}
