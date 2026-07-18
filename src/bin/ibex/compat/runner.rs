//! Process pool test runner.
//!
//! Each test runs in its own child process. A configurable number of workers
//! execute tests in parallel. Results are streamed as JSON lines.

use anyhow::Result;
use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};
use std::io;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use super::types::*;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct WptServerConfig {
    primary_url: String,
    ports: HashMap<String, Vec<u16>>,
}

impl WptServerConfig {
    fn fallback(http_port: u16) -> Self {
        let mut ports = HashMap::new();
        ports.insert("http".to_string(), vec![http_port]);
        ports.insert("https".to_string(), vec![http_port]);
        ports.insert("ws".to_string(), vec![http_port]);
        ports.insert("wss".to_string(), vec![http_port]);
        ports.insert("h2".to_string(), vec![http_port]);
        Self {
            primary_url: format!("http://localhost:{http_port}"),
            ports,
        }
    }
}

/// Format current time as HH:MM:SS.mmm for logging.
fn fmt_time() -> String {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = dur.as_secs();
    // Local time offset: use libc on unix
    let local_secs = {
        #[cfg(unix)]
        {
            // Get local time via libc::localtime_r
            let t = total_secs as libc::time_t;
            let mut tm: libc::tm = unsafe { std::mem::zeroed() };
            unsafe { libc::localtime_r(&t, &mut tm) };
            (tm.tm_hour as u64) * 3600 + (tm.tm_min as u64) * 60 + tm.tm_sec as u64
        }
        #[cfg(not(unix))]
        {
            total_secs % 86400
        }
    };
    let h = local_secs / 3600;
    let m = (local_secs % 3600) / 60;
    let s = local_secs % 60;
    let ms = dur.subsec_millis();
    format!("{:02}:{:02}:{:02}.{:03}", h, m, s, ms)
}

/// Run all tests in the plan, returning aggregated results.
pub async fn run_tests(
    compat_dir: &Path,
    plan: &TestPlan,
    opts: &CompatOptions,
) -> Result<CompatResults> {
    let (event_tx, _event_rx) = mpsc::unbounded_channel::<RunnerEvent>();
    run_tests_with_events(compat_dir, plan, opts, event_tx).await
}

/// Run all tests, sending live events to the provided channel.
pub async fn run_tests_with_events(
    compat_dir: &Path,
    plan: &TestPlan,
    opts: &CompatOptions,
    event_tx: mpsc::UnboundedSender<RunnerEvent>,
) -> Result<CompatResults> {
    let start = Instant::now();
    let parallelism = opts.parallelism();
    let strict = opts.strict;
    let no_retry = opts.no_retry;

    let mut results = CompatResults::new();

    // Initialize section results
    for section in Section::all() {
        results.sections.insert(*section, SectionResult::new());
    }

    // Create work queue
    let (work_tx, work_rx) = async_channel::bounded::<TestEntry>(plan.tests.len());
    for test in &plan.tests {
        work_tx.send(test.clone()).await.ok();
    }
    work_tx.close();

    // Create result collector channel
    let (result_tx, mut result_rx) = mpsc::unbounded_channel::<(TestEntry, TestResult)>();

    // Find the `ibex` binary path for spawning child processes
    let ibex_binary = find_ibex_binary()?;
    let compat_dir_owned = compat_dir.to_path_buf();

    // Start the WPT servers if any tests are in the Wpt section. The harness
    // uses these for real HTTP, HTTPS, WebSocket, secure WebSocket, and H2
    // requests; without the server, URL-based WPTs produce slow false
    // regressions instead of meaningful compatibility results.
    let has_wpt_tests = plan.tests.iter().any(|t| t.section == Section::Wpt);
    let mut wpt_server_child: Option<std::process::Child> = None;
    let wpt_server_config: Option<WptServerConfig> = if has_wpt_tests {
        match start_wpt_server(&compat_dir_owned) {
            Ok((child, config)) => {
                wpt_server_child = Some(child);
                Some(config)
            }
            Err(e) => {
                anyhow::bail!("failed to start WPT server for WPT tests: {e}");
            }
        }
    } else {
        None
    };
    let wpt_server_config = std::sync::Arc::new(wpt_server_config);

    // Verbose logging: open a log file and track test counts
    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);
    TEST_COUNTER.store(0, Ordering::SeqCst);
    let total_tests = plan.tests.len();
    let log_path = std::env::temp_dir().join("exact-compat-test-log.txt");
    let log_file = std::sync::Arc::new(std::sync::Mutex::new(
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)
            .ok(),
    ));
    // Log to file only — eprintln would corrupt the ratatui dashboard
    if let Ok(mut guard) = log_file.lock() {
        if let Some(ref mut f) = *guard {
            let _ = writeln!(f, "[COMPAT] Test log: {}", log_path.display());
            let _ = writeln!(
                f,
                "[COMPAT] Running {} tests with {} workers",
                total_tests, parallelism
            );
            let _ = f.flush();
        }
    }

    // Start memory pressure monitor to throttle workers under OOM risk
    let memory_pressure = spawn_memory_pressure_monitor();

    // Spawn worker tasks
    let mut workers = Vec::new();
    for worker_id in 0..parallelism {
        let work_rx = work_rx.clone();
        let result_tx = result_tx.clone();
        let event_tx = event_tx.clone();
        let ibex_binary = ibex_binary.clone();
        let compat_dir = compat_dir_owned.clone();
        let log_file = log_file.clone();
        let memory_pressure = memory_pressure.clone();
        let wpt_server_config = wpt_server_config.clone();
        let worker = tokio::spawn(async move {
            while let Ok(test) = work_rx.recv().await {
                // If system memory is critically low, back off before spawning
                // another child process. This prevents OOM lockups on macOS
                // where RLIMIT_AS is not available.
                let mut backoff_count = 0u32;
                while memory_pressure.load(Ordering::Relaxed) {
                    if backoff_count == 0 {
                        if let Ok(mut guard) = log_file.lock() {
                            if let Some(ref mut f) = *guard {
                                let _ = writeln!(f, "[{}] THROTTLE worker={worker_id} waiting for memory pressure to subside", fmt_time());
                                let _ = f.flush();
                            }
                        }
                    }
                    backoff_count += 1;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    // Safety valve: don't wait forever (max 30s)
                    if backoff_count >= 30 {
                        break;
                    }
                }
                let test_num = TEST_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
                let now = fmt_time();
                let msg = format!(
                    "[{now}] START  #{test_num}/{total_tests} worker={worker_id} {section}/{module}/{id}",
                    section = test.section.as_str(),
                    module = test.module,
                    id = test.id,
                );
                if let Ok(mut guard) = log_file.lock() {
                    if let Some(ref mut f) = *guard {
                        let _ = writeln!(f, "{}", msg);
                        let _ = f.flush();
                    }
                }

                // Notify dashboard that test started
                event_tx
                    .send(RunnerEvent::TestStarted {
                        id: test.id.clone(),
                        section: test.section,
                        module: test.module.clone(),
                    })
                    .ok();

                // Execute the test
                let result = execute_test(
                    &ibex_binary,
                    &compat_dir,
                    &test,
                    worker_id,
                    no_retry,
                    wpt_server_config.as_ref().as_ref(),
                )
                .await;

                let now = fmt_time();
                let msg = format!(
                    "[{now}] FINISH #{test_num}/{total_tests} worker={worker_id} {section}/{module}/{id} -> {status:?} ({dur}ms)",
                    section = test.section.as_str(),
                    module = test.module,
                    id = test.id,
                    status = result.status,
                    dur = result.duration_ms,
                );
                if let Ok(mut guard) = log_file.lock() {
                    if let Some(ref mut f) = *guard {
                        let _ = writeln!(f, "{}", msg);
                        let _ = f.flush();
                    }
                }

                // Notify dashboard of completion
                event_tx
                    .send(RunnerEvent::TestCompleted {
                        id: test.id.clone(),
                        section: test.section,
                        module: test.module.clone(),
                        result: Box::new(result.clone()),
                    })
                    .ok();

                result_tx.send((test, result)).ok();
            }
        });
        workers.push(worker);
    }

    // Drop our copy of result_tx so the channel closes when all workers finish
    drop(result_tx);

    // Track how many results each module still owes so ModuleCompleted can
    // fire when the last one lands. Workers run tests out of module order, so
    // the aggregation loop (which sees every result exactly once) is the one
    // place that knows a module is done. Previously this event was never
    // emitted and the dashboard's completed-modules panel stayed permanently
    // empty (LLP 0175 ledger item 14).
    let mut module_remaining: HashMap<(Section, String), usize> = HashMap::new();
    for test in &plan.tests {
        *module_remaining
            .entry((test.section, test.module.clone()))
            .or_insert(0) += 1;
    }

    // Collect results
    while let Some((entry, mut test_result)) = result_rx.recv().await {
        // Handle flaky detection: if --strict, treat flaky as fail
        if strict && test_result.status == TestStatus::Flaky {
            test_result.status = TestStatus::Fail;
        }

        let section_result = results
            .sections
            .entry(entry.section)
            .or_insert_with(SectionResult::new);

        let module_result = section_result
            .modules
            .entry(entry.module.clone())
            .or_insert_with(ModuleResult::new);

        // Update section counters
        match test_result.status {
            TestStatus::Pass | TestStatus::Flaky => section_result.pass += 1,
            TestStatus::Fail | TestStatus::Timeout | TestStatus::Crash => section_result.fail += 1,
            TestStatus::Skip => section_result.skip += 1,
        }
        section_result.total += 1;
        section_result.duration_ms += test_result.duration_ms;

        module_result.add_result(test_result);

        let module_key = (entry.section, entry.module.clone());
        if let Some(remaining) = module_remaining.get_mut(&module_key) {
            *remaining -= 1;
            if *remaining == 0 {
                module_remaining.remove(&module_key);
                event_tx
                    .send(RunnerEvent::ModuleCompleted {
                        section: entry.section,
                        module: entry.module.clone(),
                    })
                    .ok();
            }
        }
    }

    // Wait for all workers to finish
    for worker in workers {
        worker.await.ok();
    }

    // Stop the WPT server if we started one
    if let Some(mut child) = wpt_server_child {
        let _ = child.kill();
        let _ = child.wait();
    }

    // Send completion event
    event_tx.send(RunnerEvent::AllCompleted).ok();

    results.duration_ms = start.elapsed().as_millis() as u64;

    Ok(results)
}

/// Execute a single test in a child process.
async fn execute_test(
    ibex_binary: &Path,
    compat_dir: &Path,
    test: &TestEntry,
    worker_id: usize,
    no_retry: bool,
    wpt_server_config: Option<&WptServerConfig>,
) -> TestResult {
    let start = Instant::now();

    if matches!(test.expected_status, Some(TestStatus::Skip)) {
        return TestResult {
            name: test.name.clone(),
            id: test.id.clone(),
            status: TestStatus::Skip,
            duration_ms: 0,
            retries: None,
            error: None,
            expected: Some(String::from("skip")),
            actual: Some(String::from("skipped")),
            stack: None,
            signal: None,
            upstream_url: None,
        };
    }

    let result =
        execute_test_once(ibex_binary, compat_dir, test, worker_id, wpt_server_config).await;

    let result = match result {
        Ok(r) if r.status == TestStatus::Fail && !no_retry => {
            // Retry failed tests up to 2 more times for flaky detection
            let mut retries = 0;
            let mut flaky = false;
            for _ in 0..2 {
                retries += 1;
                let retry_result =
                    execute_test_once(ibex_binary, compat_dir, test, worker_id, wpt_server_config)
                        .await;
                if let Ok(ref rr) = retry_result {
                    if rr.status == TestStatus::Pass {
                        flaky = true;
                        break;
                    }
                }
            }
            if flaky {
                TestResult {
                    name: test.name.clone(),
                    id: test.id.clone(),
                    status: TestStatus::Flaky,
                    duration_ms: start.elapsed().as_millis() as u64,
                    retries: Some(retries),
                    error: r.error.clone(),
                    expected: None,
                    actual: None,
                    stack: r.stack.clone(),
                    signal: None,
                    upstream_url: None,
                }
            } else {
                // Still failing after retries
                TestResult {
                    duration_ms: start.elapsed().as_millis() as u64,
                    retries: Some(retries),
                    ..r
                }
            }
        }
        Ok(r) => r,
        Err(e) => TestResult {
            name: test.name.clone(),
            id: test.id.clone(),
            status: TestStatus::Crash,
            duration_ms: start.elapsed().as_millis() as u64,
            retries: None,
            error: Some(format!("{:#}", e)),
            expected: None,
            actual: None,
            stack: None,
            signal: None,
            upstream_url: None,
        },
    };

    // Clean up temp file from patching (if any)
    if let Some(temp_path) = patch_temp_path(test) {
        let _ = std::fs::remove_file(temp_path);
    }

    result
}

/// Execute a test once and return the result.
async fn execute_test_once(
    ibex_binary: &Path,
    compat_dir: &Path,
    test: &TestEntry,
    worker_id: usize,
    wpt_server_config: Option<&WptServerConfig>,
) -> Result<TestResult> {
    let patched_path = apply_patches(compat_dir, test);
    let test_file = patched_path.as_deref().unwrap_or(&test.file_path);
    let compat_exec_argv = collect_fixture_exec_argv(test.section, test_file);
    let effective_timeout_ms = adjusted_timeout_ms(test, test_file);
    let timeout = Duration::from_millis(effective_timeout_ms);

    let mut args: Vec<String> = vec!["run".to_string()];
    if should_use_node_main_runner(test) {
        let node_main_runner = compat_dir.join("harness").join("node-main-runner.js");
        args.push(node_main_runner.to_string_lossy().into_owned());
    }
    if test.section == Section::Bun {
        let bun_runner = compat_dir.join("harness").join("bun-runner.js");
        args.push(bun_runner.to_string_lossy().into_owned());
    }

    if test.section == Section::Wpt {
        let runner_dir = test
            .file_path
            .ancestors()
            .find(|p| p.file_name().and_then(|n| n.to_str()) == Some("fixtures"))
            .and_then(|p| p.parent())
            .map(|p| p.join("harness").join("wpt-runner.js"));
        if let Some(ref wpt_runner) = runner_dir {
            if wpt_runner.exists() {
                args.push(wpt_runner.to_string_lossy().into_owned());
            }
        }
    }
    args.push(test_file.to_string_lossy().into_owned());
    if test.section == Section::Wpt {
        if let Some(config) = wpt_server_config {
            args.push(format!("--wpt-server-url={}", config.primary_url));
        }
    }

    let test_id = test.id.clone();
    let section = test.section.as_str().to_string();
    let module = test.module.clone();
    let start = Instant::now();
    let output: std::process::Output = {
        let mut cmd = tokio::process::Command::new(ibex_binary);
        cmd.args(args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.env("EXACT_COMPAT_TEST", "1");
        cmd.env("IBEX_COMPAT_LOADER_TEST", "1");
        if section == "bun" {
            cmd.env("EXACT_COMPAT_BUN", "1");
        }
        cmd.env("EXACT_TEST_ID", test_id);
        cmd.env("EXACT_TEST_SECTION", section);
        cmd.env("EXACT_TEST_MODULE", module);
        cmd.env("TEST_THREAD_ID", worker_id.to_string());
        cmd.env(
            "EXACT_EXECUTABLE",
            ibex_binary.to_string_lossy().to_string(),
        );
        if !compat_exec_argv.is_empty() {
            if let Ok(serialized) = serde_json::to_string(&compat_exec_argv) {
                cmd.env("EXACT_COMPAT_EXEC_ARGV", serialized);
            }
        }
        if test.section == Section::Node {
            // Node compat fixtures do not need the Bun/Exact global bootstrap,
            // and skipping it removes a large per-process startup cost.
            cmd.env("EX_SKIP_STARTUP_EXACT_GLOBAL", "1");
        }
        // Disable bytecode compilation in compat tests to avoid SIGBUS
        // from hermesc/runtime version mismatches.
        cmd.env("IBEX_NO_BYTECODE", "1");
        if let Some(config) = wpt_server_config {
            cmd.env("WPT_SERVER_URL", &config.primary_url);
            cmd.env("EXACT_WPT_TRUST_LOOPBACK_TLS", "1");
            // Opt in to the WPT close-timing fixture URL sniffing in the macOS
            // websocket engine; production runs leave it off.
            // @tactical — see LLP 0159 R5 in the exact monorepo (inherited
            // cross-repo reference; that corpus is not carried under this llp/).
            cmd.env("EXACT_WPT_FIXTURE_CLOSE_SEMANTICS", "1");
            if let Ok(serialized) = serde_json::to_string(config) {
                cmd.env("WPT_SERVER_CONFIG", serialized);
            }
        }

        #[cfg(unix)]
        unsafe {
            cmd.pre_exec(|| {
                // Put each test in its own process group so we can kill the
                // entire tree (including grandchild processes spawned by
                // child_process.spawn / cluster.fork) on timeout.
                libc::setpgid(0, 0);

                set_child_memory_limit().map_err(|error| {
                    io::Error::other(format!("failed to set child memory limit: {error}"))
                })?;
                Ok(())
            });
        }

        let spawn_result = cmd.spawn();
        let child = match spawn_result {
            Ok(child) => child,
            Err(e) => {
                return Ok(TestResult {
                    name: test.name.clone(),
                    id: test.id.clone(),
                    status: TestStatus::Crash,
                    duration_ms: 0,
                    retries: None,
                    error: Some(format!("Failed to run process: {e}")),
                    expected: None,
                    actual: None,
                    stack: None,
                    signal: None,
                    upstream_url: None,
                });
            }
        };

        let child_pid = child.id();
        let mut child_output = tokio::spawn(async move { child.wait_with_output().await });

        match tokio::time::timeout(timeout, &mut child_output).await {
            Ok(Ok(output)) => output?,
            Ok(Err(e)) => {
                return Ok(TestResult {
                    name: test.name.clone(),
                    id: test.id.clone(),
                    status: TestStatus::Crash,
                    duration_ms: 0,
                    retries: None,
                    error: Some(format!("Failed to run process: {e}")),
                    expected: None,
                    actual: None,
                    stack: None,
                    signal: None,
                    upstream_url: None,
                });
            }
            Err(_) => {
                #[cfg(unix)]
                if let Some(pid) = child_pid {
                    unsafe {
                        // Kill the entire process group (child + any
                        // grandchildren from child_process.spawn / cluster)
                        libc_killpg(pid as i32);
                    }
                }
                let _ = tokio::time::timeout(Duration::from_millis(500), &mut child_output).await;
                if !child_output.is_finished() {
                    child_output.abort();
                }

                return Ok(TestResult {
                    name: test.name.clone(),
                    id: test.id.clone(),
                    status: TestStatus::Timeout,
                    duration_ms: effective_timeout_ms,
                    retries: None,
                    error: Some(format!("Test timed out after {}ms", effective_timeout_ms)),
                    expected: None,
                    actual: None,
                    stack: None,
                    signal: None,
                    upstream_url: None,
                });
            }
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    let mut stdout = if output.stdout.len() > 8 * 1024 * 1024 {
        String::from_utf8_lossy(&output.stdout[output.stdout.len() - 8 * 1024 * 1024..])
            .into_owned()
    } else {
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let mut stderr = if output.stderr.len() > 8 * 1024 * 1024 {
        String::from_utf8_lossy(&output.stderr[output.stderr.len() - 8 * 1024 * 1024..])
            .into_owned()
    } else {
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    let exit_status = output.status;

    if output.stdout.len() > 8 * 1024 * 1024 {
        stdout.push_str("\n[stdout truncated due to harness limit]");
    }
    if output.stderr.len() > 8 * 1024 * 1024 {
        stderr.push_str("\n[stderr truncated due to harness limit]");
    }

    if let Some(json_result) = parse_json_result(&stdout, &test.id) {
        return Ok(json_result);
    }

    let status = if exit_status.success() {
        TestStatus::Pass
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = exit_status.signal() {
                let signal_name = match signal {
                    11 => "SIGSEGV",
                    6 => "SIGABRT",
                    10 => "SIGBUS",
                    8 => "SIGFPE",
                    4 => "SIGILL",
                    _ => "unknown",
                };
                return Ok(TestResult {
                    name: test.name.clone(),
                    id: test.id.clone(),
                    status: TestStatus::Crash,
                    duration_ms,
                    retries: None,
                    error: Some(format!("Process killed by signal {}", signal_name)),
                    expected: None,
                    actual: None,
                    stack: if stderr.is_empty() {
                        None
                    } else {
                        Some(stderr.to_string())
                    },
                    signal: Some(signal_name.to_string()),
                    upstream_url: None,
                });
            }
        }
        TestStatus::Fail
    };

    Ok(TestResult {
        name: test.name.clone(),
        id: test.id.clone(),
        status,
        duration_ms,
        retries: None,
        error: if status == TestStatus::Fail {
            let err = if !stderr.is_empty() {
                stderr.to_string()
            } else if !stdout.is_empty() {
                let s = stdout.to_string();
                if s.len() > 1000 {
                    format!("{}...", &s[..1000])
                } else {
                    s
                }
            } else {
                format!("Exit code: {}", exit_status.code().unwrap_or(-1))
            };
            Some(err)
        } else {
            None
        },
        expected: None,
        actual: None,
        stack: None,
        signal: None,
        upstream_url: None,
    })
}

fn collect_fixture_exec_argv(section: Section, test_file: &Path) -> Vec<String> {
    if section != Section::Node {
        return Vec::new();
    }

    let Ok(source) = std::fs::read_to_string(test_file) else {
        return Vec::new();
    };

    let mut exec_argv = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        let Some(flags) = trimmed.strip_prefix("// Flags:") else {
            continue;
        };
        exec_argv.extend(
            flags
                .split_whitespace()
                .filter(|entry| !entry.is_empty())
                .map(str::to_string),
        );
    }
    exec_argv
}
/// Compute a deterministic temp file path for a patched test.
/// The temp file is placed in the same directory as the original so that
/// relative imports (e.g. `require('../common')`) still resolve correctly.
fn patch_temp_path(test: &TestEntry) -> Option<PathBuf> {
    let section_str = test.section.as_str();
    let file_str = test.file_path.to_string_lossy();
    let marker = format!("fixtures/{}/", section_str);
    file_str.find(&marker)?;

    let parent = test.file_path.parent()?;
    let mut hasher = DefaultHasher::new();
    test.id.hash(&mut hasher);
    let hash = hasher.finish();
    let ext = test
        .file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("js");
    Some(parent.join(format!(".exact-patched-{:x}.{}", hash, ext)))
}

fn adjusted_timeout_ms(test: &TestEntry, test_file: &Path) -> u64 {
    if test.section == Section::Node {
        if let Some(file_name) = test_file.file_name().and_then(|name| name.to_str()) {
            if matches!(
                file_name,
                "test-assert-partial-deep-equal.js"
                    | "test-assert-partial-deep-equal.debug.js"
                    | "test-assert-typedarray-deepequal.js"
                    | "test-url-parse-invalid-input.js"
                    | "test-net-write-fully-async-buffer.js"
                    | "test-net-write-fully-async-hex-string.js"
                    | "test-net-bytes-written-large.js"
            ) {
                return test.timeout_ms.max(45_000);
            }
        }
        return test.timeout_ms;
    }

    if test.section == Section::Bun {
        if let Some(file_name) = test_file.file_name().and_then(|name| name.to_str()) {
            if matches!(file_name, "http-server-chunking.test.ts") {
                return test.timeout_ms.max(25_000);
            }
        }
    }

    let mut timeout_ms = test.timeout_ms;
    if let Ok(source) = std::fs::read_to_string(test_file) {
        let mut global_count = 0usize;
        let mut variant_count = 0usize;
        let mut has_long_timeout = false;

        for line in source.lines() {
            let trimmed = line.trim();
            let rest = match trimmed.strip_prefix("// META:") {
                Some(rest) => rest.trim(),
                None => continue,
            };

            if let Some(value) = rest.strip_prefix("global=") {
                let count = value
                    .split(',')
                    .map(|item| item.trim())
                    .filter(|item| !item.is_empty())
                    .count();
                global_count = global_count.max(count);
                continue;
            }

            if rest.starts_with("variant=") {
                variant_count += 1;
                continue;
            }

            if let Some(value) = rest.strip_prefix("timeout=") {
                if value.trim().eq_ignore_ascii_case("long") {
                    has_long_timeout = true;
                }
            }
        }

        if has_long_timeout {
            timeout_ms = timeout_ms.max(test.timeout_ms.saturating_mul(3));
        }

        let run_count = global_count.max(1).saturating_mul(variant_count.max(1));
        if run_count > 1 {
            timeout_ms = timeout_ms.saturating_mul(run_count as u64);
        }
    }

    timeout_ms.min(120_000)
}

fn should_use_node_main_runner(test: &TestEntry) -> bool {
    if test.section != Section::Node {
        return false;
    }

    matches!(
        test.id.as_str(),
        "node/url/parallel/test-url-parse-invalid-input.js"
    )
}

/// Apply patches to a test file if a .patch file exists.
/// Returns `Some(temp_path)` if patches were applied, `None` otherwise.
fn apply_patches(compat_dir: &Path, test: &TestEntry) -> Option<PathBuf> {
    let section_str = test.section.as_str();
    let file_str = test.file_path.to_string_lossy();

    // Compute relative path within fixtures/<section>/
    let marker = format!("fixtures/{}/", section_str);
    let idx = file_str.find(&marker)?;
    let rel = &file_str[idx + marker.len()..];

    let patch_path = compat_dir
        .join("patches")
        .join(section_str)
        .join(format!("{}.patch", rel));

    if !patch_path.exists() {
        return None;
    }

    let source = std::fs::read_to_string(&test.file_path).ok()?;
    let patch_content = std::fs::read_to_string(&patch_path).ok()?;

    let patched = apply_patch_content(&source, &patch_content, &test.id);

    // Write patched file next to the original so relative imports still work
    let parent = test.file_path.parent()?;
    let mut hasher = DefaultHasher::new();
    test.id.hash(&mut hasher);
    let hash = hasher.finish();
    let ext = test
        .file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("js");
    let temp_path = parent.join(format!(".exact-patched-{:x}.{}", hash, ext));

    std::fs::write(&temp_path, patched).ok()?;
    Some(temp_path)
}

/// Parse and apply find/replace pairs from patch content.
fn apply_patch_content(source: &str, patch: &str, _test_id: &str) -> String {
    let mut result = source.to_string();

    // Parse blocks: split on "--- find" and "--- replace" markers
    let mut lines = patch.lines().peekable();
    let mut _block_num = 0;

    while lines.peek().is_some() {
        // Skip blank lines between blocks
        while lines.peek().is_some_and(|l| l.trim().is_empty()) {
            lines.next();
        }

        // Expect "--- find"
        match lines.next() {
            Some(line) if line.trim() == "--- find" => {}
            Some(_) => continue, // skip unexpected lines
            None => break,
        }

        // Collect find lines until "--- replace"
        let mut find_lines = Vec::new();
        loop {
            match lines.peek() {
                Some(line) if line.trim() == "--- replace" => {
                    lines.next();
                    break;
                }
                Some(_) => {
                    if let Some(line) = lines.next() {
                        find_lines.push(line);
                    } else {
                        break;
                    }
                }
                None => break,
            }
        }

        // Collect replace lines until next "--- find" or end
        let mut replace_lines = Vec::new();
        loop {
            match lines.peek() {
                Some(line) if line.trim() == "--- find" => break,
                Some(line) if line.trim().is_empty() => {
                    // Could be trailing blank or separator; peek ahead
                    // to see if a "--- find" follows
                    if let Some(line) = lines.next() {
                        replace_lines.push(line);
                    } else {
                        break;
                    }
                }
                Some(_) => {
                    if let Some(line) = lines.next() {
                        replace_lines.push(line);
                    } else {
                        break;
                    }
                }
                None => break,
            }
        }

        // Trim trailing empty lines from replace block
        while replace_lines.last().is_some_and(|l| l.trim().is_empty()) {
            replace_lines.pop();
        }

        let find = find_lines.join("\n");
        let replace = replace_lines.join("\n");
        _block_num += 1;

        if find.is_empty() {
            continue;
        }

        if result.contains(&find) {
            result = result.replace(&find, &replace);
        }
        // Silently skip non-matching patches (stale patch blocks).
        // Previously this used eprintln which corrupts the ratatui dashboard.
    }

    result
}

/// Parse a JSON result line from test harness output.
fn parse_json_result(stdout: &str, test_id: &str) -> Option<TestResult> {
    let mut aggregated_tests = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if !(trimmed.starts_with('{') && trimmed.contains("\"type\"")) {
            continue;
        }

        let Ok(msg) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        let msg_type = msg.get("type").and_then(|t| t.as_str());

        if msg_type == Some("test_result") {
            if let Ok(result) = serde_json::from_value::<TestResult>(
                msg.get("test").cloned().unwrap_or(msg.clone()),
            ) {
                aggregated_tests.push(result);
            }
            continue;
        }

        // WPT tests emit wpt_results with an array of sub-tests.
        // Aggregate them into a single TestResult for this file.
        if msg_type == Some("wpt_results") {
            if let Some(tests) = msg.get("tests").and_then(|t| t.as_array()) {
                let test_id = test_id.to_string();
                let mut pass = 0u32;
                let mut fail = 0u32;
                let mut total = 0u32;
                let mut first_error: Option<String> = None;
                let mut first_stack: Option<String> = None;
                let mut total_duration = 0u64;

                for t in tests {
                    total += 1;
                    let status = t.get("status").and_then(|s| s.as_str()).unwrap_or("fail");
                    let duration = t.get("duration_ms").and_then(|d| d.as_u64()).unwrap_or(0);
                    total_duration += duration;
                    match status {
                        "pass" => pass += 1,
                        "skip" => {}
                        _ => {
                            fail += 1;
                            if first_error.is_none() {
                                let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("");
                                let message =
                                    t.get("message").and_then(|m| m.as_str()).unwrap_or("");
                                first_error = Some(format!("{}: {}", name, message));
                                first_stack = t
                                    .get("stack")
                                    .and_then(|s| s.as_str())
                                    .map(|s| s.to_string());
                            }
                        }
                    }
                }

                let status = if fail > 0 {
                    TestStatus::Fail
                } else {
                    TestStatus::Pass
                };

                return Some(TestResult {
                    name: format!("{} ({}/{} passed)", test_id, pass, total),
                    id: test_id,
                    status,
                    duration_ms: total_duration,
                    retries: None,
                    error: first_error,
                    expected: None,
                    actual: None,
                    stack: first_stack,
                    signal: None,
                    upstream_url: None,
                });
            }
        }
    }

    if !aggregated_tests.is_empty() {
        let mut pass = 0u32;
        let mut skip = 0u32;
        let mut fail = 0u32;
        let mut total_duration = 0u64;
        let mut first_error: Option<String> = None;
        let mut first_stack: Option<String> = None;

        for result in &aggregated_tests {
            total_duration += result.duration_ms;
            match result.status {
                TestStatus::Pass => pass += 1,
                TestStatus::Skip => skip += 1,
                _ => {
                    fail += 1;
                    if first_error.is_none() {
                        first_error = result.error.clone();
                        first_stack = result.stack.clone();
                    }
                }
            }
        }

        let status = if fail > 0 {
            TestStatus::Fail
        } else if pass > 0 {
            TestStatus::Pass
        } else {
            TestStatus::Skip
        };

        return Some(TestResult {
            name: format!(
                "{} ({}/{} passed, {} skipped)",
                test_id,
                pass,
                aggregated_tests.len(),
                skip
            ),
            id: test_id.to_string(),
            status,
            duration_ms: total_duration,
            retries: None,
            error: first_error,
            expected: None,
            actual: None,
            stack: first_stack,
            signal: None,
            upstream_url: None,
        });
    }

    None
}

/// How long to wait for wpt-server.py to announce its port before giving up.
///
/// GitHub-hosted macOS can spend more than ten seconds importing the freshly
/// installed WPT server stack before stdout is flushed. Keep this bounded, but
/// long enough that CI startup slowness does not become a fake WebSocket
/// compatibility regression.
const WPT_SERVER_STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
/// Trailing stderr lines retained for the startup failure message.
const WPT_SERVER_STDERR_TAIL_LINES: usize = 20;

/// Startup lines parsed off wpt-server.py stdout by the reader thread.
enum WptStartupEvent {
    Port(u16),
    Config(WptServerConfig),
}

/// Start the WPT HTTP/HTTPS/WebSocket/H2 servers (wptserve) for WPT tests.
///
/// Returns the child process and the structured server config.
/// The caller is responsible for killing the child when tests are done.
fn start_wpt_server(compat_dir: &Path) -> Result<(std::process::Child, WptServerConfig)> {
    use std::io::BufRead as _;

    let harness_dir = compat_dir.join("harness");
    let venv_python = harness_dir.join(".wpt-venv").join("bin").join("python");
    let server_script = harness_dir.join("wpt-server.py");

    if !venv_python.exists() {
        // Run setup script to create venv + install wptserve. Output goes to
        // null, not a pipe: `.status()` never reads pipes, so a chatty script
        // would block once the pipe buffer fills (LLP 0175 ledger item 12).
        let setup_script = harness_dir.join("setup-wpt-server.sh");
        if setup_script.exists() {
            let status = std::process::Command::new("bash")
                .arg(&setup_script)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()?;
            if !status.success() {
                anyhow::bail!("setup-wpt-server.sh failed");
            }
        }
    }

    if !venv_python.exists() {
        anyhow::bail!("WPT venv python not found at {}", venv_python.display());
    }
    if !server_script.exists() {
        anyhow::bail!("wpt-server.py not found at {}", server_script.display());
    }

    let mut child = std::process::Command::new(&venv_python)
        .arg(&server_script)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stdout from wpt-server.py"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stderr from wpt-server.py"))?;

    // Drain stderr for the server's whole lifetime on a background thread —
    // an unread pipe deadlocks a chatty server once the OS buffer fills
    // (LLP 0175 ledger item 12). Keep a short tail for startup diagnostics.
    // The thread exits when the pipe closes (server killed at end of run).
    let stderr_tail: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
    {
        let stderr_tail = stderr_tail.clone();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                let mut tail = crate::compat::lock_or_recover(&stderr_tail);
                if tail.len() >= WPT_SERVER_STDERR_TAIL_LINES {
                    tail.pop_front();
                }
                tail.push_back(line);
            }
        });
    }

    // Read `WPT_SERVER_PORT=<port>` / `WPT_SERVER_CONFIG=<json>` off stdout on
    // a thread and wait with a real deadline. The previous implementation only
    // checked the deadline *between* blocking line reads, so a started-but-
    // silent server hung the entire run forever (LLP 0175 ledger item 12).
    // After startup the thread keeps draining stdout to EOF so later server
    // output can neither fill the pipe nor hit a closed descriptor.
    let (startup_tx, startup_rx) = std::sync::mpsc::channel::<WptStartupEvent>();
    std::thread::spawn(move || {
        let mut startup_tx = Some(startup_tx);
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let Some(tx) = startup_tx.as_ref() else {
                continue;
            };
            let event = if let Some(rest) = line.strip_prefix("WPT_SERVER_PORT=") {
                rest.trim().parse::<u16>().ok().map(WptStartupEvent::Port)
            } else if let Some(rest) = line.strip_prefix("WPT_SERVER_CONFIG=") {
                serde_json::from_str::<WptServerConfig>(rest.trim())
                    .ok()
                    .map(WptStartupEvent::Config)
            } else {
                None
            };
            if let Some(event) = event {
                if tx.send(event).is_err() {
                    // Startup finished (receiver dropped); drain only from here.
                    startup_tx = None;
                }
            }
        }
    });

    let deadline = Instant::now() + WPT_SERVER_STARTUP_TIMEOUT;
    let mut port: Option<u16> = None;
    let mut config: Option<WptServerConfig> = None;
    while port.is_none() || config.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match startup_rx.recv_timeout(remaining) {
            Ok(WptStartupEvent::Port(p)) => port = Some(p),
            Ok(WptStartupEvent::Config(c)) => config = Some(c),
            // Timed out, or the server exited / closed stdout — either way no
            // more startup lines are coming.
            Err(_) => break,
        }
    }

    let Some(port) = port else {
        let _ = child.kill();
        let _ = child.wait();
        let tail = crate::compat::lock_or_recover(&stderr_tail)
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        if tail.is_empty() {
            anyhow::bail!(
                "WPT server did not report its port within {}s (no stderr output); killed it",
                WPT_SERVER_STARTUP_TIMEOUT.as_secs()
            );
        }
        anyhow::bail!(
            "WPT server did not report its port within {}s; killed it. Recent stderr:\n{}",
            WPT_SERVER_STARTUP_TIMEOUT.as_secs(),
            tail
        );
    };

    let config = config.unwrap_or_else(|| {
        let tail = crate::compat::lock_or_recover(&stderr_tail)
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        if tail.is_empty() {
            eprintln!(
                "[wpt-server] Warning: wpt-server.py reported port {port} but no WPT_SERVER_CONFIG; using fallback config"
            );
        } else {
            eprintln!(
                "[wpt-server] Warning: wpt-server.py reported port {port} but no WPT_SERVER_CONFIG; using fallback config. Recent stderr:\n{tail}"
            );
        }
        WptServerConfig::fallback(port)
    });
    if config.primary_url.is_empty() {
        eprintln!(
            "[wpt-server] Warning: wpt-server.py reported an empty primary_url; using fallback config for port {port}"
        );
        return Ok((child, WptServerConfig::fallback(port)));
    }

    Ok((child, config))
}

/// Find the `ibex` binary to use for spawning child processes.
fn find_ibex_binary() -> Result<std::path::PathBuf> {
    let resolve_candidate = |candidate: &str| -> Option<PathBuf> {
        let path = if Path::new(candidate).is_absolute() {
            PathBuf::from(candidate)
        } else {
            std::env::current_dir()
                .ok()?
                .join(candidate)
                .canonicalize()
                .ok()
                .filter(|p| p.is_file())?
        };

        if path.exists() && path.is_file() {
            return Some(path);
        }
        None
    };

    if let Some(exe) = std::env::current_exe()
        .ok()
        .filter(|exe| exe.exists() && exe.is_file())
    {
        return Ok(exe);
    }

    if let Some(arg) = std::env::args()
        .next()
        .and_then(|arg| resolve_candidate(&arg))
    {
        return Ok(arg);
    }

    // Common local binary locations when the parent executable path is unavailable
    for name in [
        ".cargo-targets/main/debug/ibex",
        ".cargo-targets/main/release/ibex",
        "target/debug/ibex",
        "target/release/ibex",
        // Legacy `ex` build artifacts (LLP 0165): remove after one checkpoint cycle
        "target/debug/ex",
        "target/release/ex",
    ] {
        if let Some(path) = resolve_candidate(name) {
            return Ok(path);
        }
    }

    for fallback in ["ibex"] {
        if let Some(path) = resolve_candidate(fallback) {
            return Ok(path);
        }
    }

    Err(anyhow::anyhow!("Cannot find ibex binary"))
}

/// Kill an entire process group by PGID (Unix only).
/// Each test child is placed in its own process group via setpgid(0,0) in
/// pre_exec, so this kills the test *and* any grandchild processes it spawned
/// (e.g. via child_process.spawn or cluster.fork).
#[cfg(unix)]
unsafe fn libc_killpg(pid: i32) {
    // Try killpg first (kills the whole group), fall back to kill if it fails.
    let rc = libc::killpg(pid, libc::SIGKILL);
    if rc != 0 {
        libc::kill(pid, libc::SIGKILL);
    }
}

/// Set a virtual memory limit on the current process (called in child after fork).
/// Prevents pathological tests from exhausting system memory and triggering the
/// OOM killer, which would take down the parent runner process.
#[cfg(unix)]
fn set_child_memory_limit() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        // macOS rejects finite RLIMIT_* values in current environments.
        // Keep test execution working and avoid OOM guard false positives.
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        use libc::{
            __rlimit_resource_t, rlim_t, rlimit, setrlimit, EINVAL, ENOSYS, ENOTSUP, ENXIO,
            RLIMIT_AS, RLIMIT_DATA, RLIMIT_RSS,
        };

        // Guard both virtual address space and heap/data growth.
        const RESOURCES: &[__rlimit_resource_t] = &[RLIMIT_AS, RLIMIT_DATA, RLIMIT_RSS];
        const LIMIT_BYTES: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB

        let rlim = rlimit {
            rlim_cur: LIMIT_BYTES as rlim_t,
            rlim_max: LIMIT_BYTES as rlim_t,
        };

        let mut last_error = None;
        for resource in RESOURCES {
            // Safety: setrlimit is safe to call here in `pre_exec`.
            let rc = unsafe { setrlimit(*resource, &rlim) };
            if rc == 0 {
                return Ok(());
            }

            let error = io::Error::last_os_error();
            if let Some(code) = error.raw_os_error() {
                if code == EINVAL || code == ENOTSUP || code == ENOSYS || code == ENXIO {
                    // Resource limit not supported on this platform/version; skip it.
                    continue;
                }
            }

            last_error = Some(error);
        }

        if let Some(error) = last_error {
            // Any non-unsupported failure is treated as a hard error.
            // Supported-but-failing limits (EINVAL/ENOTSUP/ENOSYS) are non-fatal
            // and let the run proceed with suite-level mitigations only.
            match error.raw_os_error() {
                Some(EINVAL) | Some(ENOTSUP) | Some(ENOSYS) | Some(ENXIO) => Ok(()),
                _ => Err(error),
            }
        } else {
            Ok(())
        }
    }
}

/// Check if the system is under memory pressure (macOS only).
/// Returns `true` if memory pressure is critical and tests should be throttled.
#[cfg(target_os = "macos")]
fn system_memory_pressure_critical() -> bool {
    // Use vm_stat to get free page count. If free pages < ~256MB worth
    // (65536 pages × 4KB = 256MB), consider it critical.
    use std::process::Command;
    let output = Command::new("vm_stat").output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            // Parse "Pages free:" line
            for line in text.lines() {
                if line.starts_with("Pages free:") {
                    let pages: u64 = line
                        .trim_start_matches("Pages free:")
                        .trim()
                        .trim_end_matches('.')
                        .parse()
                        .unwrap_or(u64::MAX);
                    // 65536 pages * 16KB (Apple Silicon) ≈ 1GB threshold
                    // Use conservative threshold since each ibex process can use 100MB+
                    return pages < 65536;
                }
            }
            false
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "macos"))]
fn system_memory_pressure_critical() -> bool {
    false
}

/// Spawn a background task that periodically checks memory pressure and
/// sets a flag when the system is under critical memory pressure.
/// Workers check this flag and pause before starting new tests.
fn spawn_memory_pressure_monitor() -> std::sync::Arc<AtomicBool> {
    let pressure = std::sync::Arc::new(AtomicBool::new(false));
    let pressure_clone = pressure.clone();
    tokio::spawn(async move {
        loop {
            let critical = system_memory_pressure_critical();
            pressure_clone.store(critical, Ordering::Relaxed);
            // Note: no eprintln here — it would corrupt the ratatui dashboard.
            // The throttle message is logged by each worker via the log file.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    pressure
}

/// Async channel — a simple multi-producer multi-consumer channel.
/// We use a module-level reimplementation to avoid adding async-channel as a dep.
mod async_channel {
    use crate::compat::lock_or_recover;
    use std::sync::{Arc, Mutex};
    use tokio::sync::Notify;

    pub struct Sender<T> {
        inner: Arc<Inner<T>>,
    }

    pub struct Receiver<T> {
        inner: Arc<Inner<T>>,
    }

    struct Inner<T> {
        queue: Mutex<std::collections::VecDeque<T>>,
        notify: Notify,
        closed: std::sync::atomic::AtomicBool,
    }

    impl<T> Clone for Sender<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl<T> Clone for Receiver<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    pub fn bounded<T>(cap: usize) -> (Sender<T>, Receiver<T>) {
        let inner = Arc::new(Inner {
            queue: Mutex::new(std::collections::VecDeque::with_capacity(cap)),
            notify: Notify::new(),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        (
            Sender {
                inner: inner.clone(),
            },
            Receiver { inner },
        )
    }

    impl<T> Sender<T> {
        pub async fn send(&self, item: T) -> Result<(), T> {
            if self.inner.closed.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(item);
            }
            lock_or_recover(&self.inner.queue).push_back(item);
            self.inner.notify.notify_one();
            Ok(())
        }

        pub fn close(&self) {
            self.inner
                .closed
                .store(true, std::sync::atomic::Ordering::Relaxed);
            self.inner.notify.notify_waiters();
        }
    }

    impl<T> Receiver<T> {
        pub async fn recv(&self) -> Result<T, ()> {
            loop {
                if let Some(item) = lock_or_recover(&self.inner.queue).pop_front() {
                    return Ok(item);
                }
                if self.inner.closed.load(std::sync::atomic::Ordering::Relaxed) {
                    // Check once more after seeing closed
                    if let Some(item) = lock_or_recover(&self.inner.queue).pop_front() {
                        return Ok(item);
                    }
                    return Err(());
                }
                self.inner.notify.notified().await;
            }
        }
    }
}
