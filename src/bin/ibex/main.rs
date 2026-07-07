//! Ibex CLI - A JavaScript/TypeScript runtime with web APIs
//!
//! The `ibex` CLI provides a fast, modern runtime for JavaScript and TypeScript,
//! featuring web-standard APIs, a high-quality REPL, and Chrome DevTools debugging.

mod agent_logs;
mod cdp;
mod cli;
mod compat;
mod engine;
mod host;
mod repl;
mod runtime;
mod runtime_tests;
mod subprocess;

// Re-export module_loader from the shared runtime crate
pub use ibex_runtime::module_loader;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands, DebugCommands};

/// Project commands owned by the Exact project CLI, not the Ibex runtime.
/// @ref LLP 0010#runtime-command-surface — `ibex` is runtime-only here.
const EXACT_PROJECT_COMMANDS: &[&str] = &[
    "new", "create", "init", "verify", "facet", "agent", "mcp", "doctor", "lint",
];

/// Runtime-namespace names reserved for future features:
/// absent from the clap tree, intercepted pre-clap with a pointer error so
/// they neither advertise vapor nor fall through to package-script dispatch.
/// @ref LLP 0010#runtime-command-surface — truthful runtime surface.
const RESERVED_RUNTIME_COMMANDS: &[(&str, &str)] = &[
    ("test", "a user-facing test runner is planned"),
    (
        "install",
        "package management is not implemented; use bun or npm",
    ),
    (
        "bench",
        "a benchmark harness is planned; run `ibex <file>` directly",
    ),
    ("exec", "package-binary execution (`npx`-style) is planned"),
];

const DEFAULT_WATCH_SHUTDOWN_TIMEOUT_MS: u64 = 2_000;

/// Runtime-internal env contracts use the `IBEX_*` namespace; the legacy
/// `EX_*`/`EXACT_*` spellings are honored with a one-time deprecation
/// warning while extracted consumers catch up.
/// Cross-product agent contracts (`EXACT_AGENT_*`) are unaffected.
pub(crate) fn runtime_env(ibex_name: &str, legacy_name: &str) -> Option<String> {
    if let Ok(value) = std::env::var(ibex_name) {
        return Some(value);
    }
    if let Ok(value) = std::env::var(legacy_name) {
        use std::sync::Mutex;
        static WARNED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        if let Ok(mut warned) = WARNED.lock() {
            if !warned.iter().any(|name| name == legacy_name) {
                eprintln!("warning: {legacy_name} is deprecated; use {ibex_name}");
                warned.push(legacy_name.to_string());
            }
        }
        return Some(value);
    }
    None
}

/// Shared truthiness parse for boolean `IBEX_*` env flags, mirroring the C++
/// `env_flag_enabled` in hermes_runtime.cc so the Rust bundler driver and bundle
/// cache key agree with the engine on whether a flag is set. A bare presence
/// check (`var_os(..).is_some()`) disagreed with the engine's value check:
/// `IBEX_COMPARTMENTS=true` made the bundler emit `__compartments` references the
/// engine never installed, throwing ReferenceError (and caching the broken
/// artifact). Accepts a leading 1/y/Y/t/T (so `1`, `yes`, `true` all enable) and
/// rejects `0`/`false`/`no`/`off`/empty. (ENG-22634)
pub(crate) fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .and_then(|v| v.chars().next())
        .map(|c| matches!(c, '1' | 'y' | 'Y' | 't' | 'T'))
        .unwrap_or(false)
}

fn trace_startup() -> bool {
    runtime_env("IBEX_STARTUP_TRACE", "EX_STARTUP_TRACE")
        .map(|v| v.starts_with('1') || v.starts_with('y') || v.starts_with('Y'))
        .unwrap_or(false)
}

fn watch_shutdown_timeout_from_env(value: Option<&str>) -> std::time::Duration {
    subprocess::parse_timeout_ms(value, DEFAULT_WATCH_SHUTDOWN_TIMEOUT_MS)
}

fn watch_shutdown_timeout() -> std::time::Duration {
    let raw = runtime_env(
        "IBEX_WATCH_SHUTDOWN_TIMEOUT_MS",
        "EXACT_WATCH_SHUTDOWN_TIMEOUT_MS",
    );
    watch_shutdown_timeout_from_env(raw.as_deref())
}

/// Message prefixes that classify an error as a host-lifecycle failure
/// (exit code 3 instead of the generic 1).
///
/// These errors cross FFI/JSI boundaries as strings, so only ordinary
/// `io::Error` causes can be classified structurally here. The prefixes below
/// are produced by the local host ABI and HTTP bridge.
const HOST_LIFECYCLE_ERROR_PREFIXES: &[&str] = &[
    "Host not initialized",
    "Permission denied for ",
    "Failed to start HTTP server",
];

/// Error carrying a package script's own exit status. `run_package_script`
/// returns this on failure so `ibex` propagates the child's exit code — matching
/// npm/bun — instead of collapsing every script failure to the generic 1.
/// `exit_code_for_error` downcasts to it. (ENG-22958)
#[derive(Debug)]
struct PackageScriptExit {
    script: String,
    code: i32,
}

impl std::fmt::Display for PackageScriptExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "package script `{}` exited with code {}",
            self.script, self.code
        )
    }
}

impl std::error::Error for PackageScriptExit {}

/// Resolve a finished child's exit code the way a shell would: the explicit
/// code when present, else `128 + signal` on Unix. Never returns 0 for a
/// non-success status (so a propagated code always signals failure).
fn package_script_exit_code(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        if code != 0 {
            return code;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

fn exit_code_for_error(error: &anyhow::Error) -> i32 {
    // A failing package script propagates its own exit code (e.g. eslint's 2),
    // matching npm/bun, rather than collapsing to the generic 1. (ENG-22958)
    if let Some(script_exit) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<PackageScriptExit>())
    {
        return script_exit.code;
    }
    if error.chain().any(|cause| {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::AddrInUse
                    | std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::TimedOut
            );
        }

        let message = cause.to_string();
        HOST_LIFECYCLE_ERROR_PREFIXES
            .iter()
            .any(|prefix| message.starts_with(prefix))
    }) {
        3
    } else {
        1
    }
}

#[cfg(unix)]
fn request_watch_child_shutdown(child: &tokio::process::Child) -> Result<bool> {
    let Some(pid) = child.id() else {
        return Ok(false);
    };

    let rc = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if rc == 0 {
        return Ok(true);
    }

    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(false);
    }

    Err(error.into())
}

#[cfg(not(unix))]
fn request_watch_child_shutdown(_child: &tokio::process::Child) -> Result<bool> {
    Ok(false)
}

async fn stop_watch_child(
    child: &mut tokio::process::Child,
    timeout: std::time::Duration,
) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }

    if request_watch_child_shutdown(child)? {
        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(status) => {
                let _ = status?;
                return Ok(());
            }
            Err(_) => {
                eprintln!(
                    "\x1b[33m[watch]\x1b[0m process did not exit within {}ms, force killing...",
                    timeout.as_millis()
                );
            }
        }
    }

    let _ = child.kill().await;
    let _ = child.wait().await;
    Ok(())
}

/// Keep non-runtime names out of clap without coupling this binary back to the
/// Exact project CLI. An existing file always wins: `ibex test` runs a file
/// named `test` when one exists; only non-paths hit these tables.
fn pre_clap_namespace_dispatch() -> bool {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let Some(first) = argv.get(1).and_then(|arg| arg.to_str()) else {
        return false;
    };
    if std::path::Path::new(first).exists() {
        return false;
    }
    if let Some((name, reason)) = RESERVED_RUNTIME_COMMANDS
        .iter()
        .find(|(name, _)| *name == first)
    {
        eprintln!("ibex {name} is reserved and not yet implemented: {reason}");
        std::process::exit(2);
    }
    if !EXACT_PROJECT_COMMANDS.contains(&first) {
        return false;
    }

    eprintln!("ibex {first} is an Exact project command; use exact {first}");
    std::process::exit(2);
}

fn legacy_project_dispatch() -> bool {
    pre_clap_namespace_dispatch()
}

/// Expand Node-style combined eval shorthands (`-pe CODE`, `-ep CODE`) into
/// `-p CODE` before clap parsing. The old implementation special-cased `-p`
/// with the literal value "e" and re-read the positional as code, which
/// misread a legitimate `ibex -p e`.
fn expand_combined_eval_shorthand(argv: &mut [std::ffi::OsString]) {
    // Only the leading flags region is rewritten: stop at `--` or the first
    // positional so script argv is never corrupted (review R5 —
    // `ibex tool.js -- -pe x` must deliver `-pe` untouched).
    for arg in argv.iter_mut().skip(1) {
        if *arg == "--" {
            break;
        }
        let is_flag = arg.to_str().is_some_and(|s| s.starts_with('-'));
        if !is_flag {
            break;
        }
        if arg == "-pe" || arg == "-ep" {
            *arg = "-p".into();
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let t0 = std::time::Instant::now();
    if legacy_project_dispatch() {
        return;
    }
    let mut argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    expand_combined_eval_shorthand(&mut argv);
    let cli = Cli::parse_from(argv);
    if trace_startup() {
        eprintln!(
            "[startup] {:<30} {:>6} us ({:>5.1} ms)",
            "cli_parse",
            t0.elapsed().as_micros(),
            t0.elapsed().as_micros() as f64 / 1000.0
        );
    }
    if let Err(e) = run(cli).await {
        eprintln!("error: {:#}", e);
        std::process::exit(exit_code_for_error(&e));
    }
}

async fn run(cli: Cli) -> Result<()> {
    // @ref LLP 0013#mechanism-1 — the boot lockdown is read by the engine from
    // the environment (std::getenv). Setting it here, before any runtime is
    // created, lets `--lockdown` reach the in-process Hermes runtime.
    if cli.lockdown {
        std::env::set_var("IBEX_LOCKDOWN", "1");
    }

    if cli.version {
        println!("v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if cli.completion_bash {
        print_completions(clap_complete::Shell::Bash);
        return Ok(());
    }

    if let Some(code) = &cli.eval_code {
        return eval_code(&cli, code, false).await;
    }
    if let Some(code) = &cli.print_eval {
        return eval_code(&cli, code, true).await;
    }

    match &cli.command {
        Some(Commands::Run {
            file,
            args,
            watch,
            inspect,
            inspect_wait,
            inspect_open,
            inspect_pause,
            keep_alive,
            inspect_port,
            inspect_host,
        }) => {
            if should_run_package_script(file) {
                run_package_script(file, args).await
            } else if *watch || cli.watch {
                run_watch(&cli, file, args).await
            } else {
                run_file(
                    &cli,
                    file,
                    args,
                    RunFileOptions {
                        inspect: *inspect,
                        inspect_wait: *inspect_wait,
                        inspect_open: *inspect_open,
                        inspect_pause: *inspect_pause,
                        keep_alive: *keep_alive,
                        inspect_port: *inspect_port,
                        inspect_host: inspect_host.as_deref(),
                    },
                )
                .await
            }
        }
        Some(Commands::Eval { code }) => eval_code(&cli, code, false).await,
        Some(Commands::Repl) => start_repl(&cli).await,
        Some(Commands::Build { file, outdir }) => {
            build_bytecode(&cli, file, outdir.as_deref()).await
        }
        Some(Commands::Version) => {
            print_version(&cli);
            Ok(())
        }
        Some(Commands::Completions { shell }) => {
            print_completions(*shell);
            Ok(())
        }
        Some(Commands::Debug { command }) => match command {
            DebugCommands::Modules => run_debug_modules(),
        },
        Some(Commands::Policy { command }) => runtime::run_policy_command(command).await,
        Some(Commands::SelfTest) => runtime_tests::run_all(&cli).await,
        Some(Commands::Compat {
            section,
            module,
            test,
            quick,
            failed,
            update_expectations,
            report,
            json,
            log,
            log_color,
            log_no_skip,
            jobs,
            strict,
            all,
            no_retry,
            timeout,
        }) => {
            compat::run_compat(compat::CompatOptions {
                section: section.clone(),
                module: module.clone(),
                test_filter: test.clone(),
                quick: *quick,
                failed: *failed,
                update_expectations: *update_expectations,
                report: *report,
                json: *json,
                log: *log,
                log_color: *log_color,
                log_no_skip: *log_no_skip,
                jobs: *jobs,
                strict: *strict,
                all: *all,
                no_retry: *no_retry,
                timeout: *timeout,
            })
            .await
        }
        None => {
            // If no command but a file is provided via positional argument
            if let Some(file) = &cli.file {
                if should_run_package_script(file) {
                    run_package_script(file, &cli.args).await
                } else if cli.watch {
                    run_watch(&cli, file, &cli.args).await
                } else {
                    run_file(
                        &cli,
                        file,
                        &cli.args,
                        RunFileOptions {
                            inspect: cli.inspect,
                            inspect_wait: cli.inspect_wait,
                            inspect_open: cli.inspect_open,
                            inspect_pause: cli.inspect_pause,
                            keep_alive: cli.keep_alive,
                            inspect_port: cli.inspect_port,
                            inspect_host: cli.inspect_host.as_deref(),
                        },
                    )
                    .await
                }
            } else {
                // No command and no file - start REPL
                start_repl(&cli).await
            }
        }
    }
}

fn should_run_package_script(file: &str) -> bool {
    let path = std::path::Path::new(file);
    if path.exists() {
        return false;
    }

    if file.contains('/') || file.contains('\\') || file.starts_with('.') || file.ends_with('/') {
        return false;
    }

    if let Some(ext) = path.extension().and_then(|ext| ext.to_str()) {
        let ext = ext.to_ascii_lowercase();
        if matches!(
            ext.as_str(),
            "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx" | "mts" | "cts"
        ) {
            return false;
        }
    }

    true
}

fn run_debug_modules() -> Result<()> {
    println!("specifier\tsource_key\tkind\tpath\tavailability\tmodule_builtin\tbundle_external");
    for entry in module_loader::builtin_module_debug_entries() {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            entry.specifier,
            entry.source_key,
            entry.source_kind,
            entry.source_path.unwrap_or("<inline>"),
            entry.platform_availability,
            entry.module_builtin,
            entry.bundle_external,
        );
    }
    Ok(())
}

async fn run_package_script(script: &str, args: &[String]) -> Result<()> {
    let package_root = find_package_root(std::env::current_dir()?)?;
    let package_json = package_root.join("package.json");

    let manifest = std::fs::read_to_string(&package_json)
        .with_context(|| format!("Failed to read {}", package_json.display()))?;
    let package: serde_json::Value = serde_json::from_str(&manifest)
        .with_context(|| format!("Invalid package manifest {}", package_json.display()))?;
    let scripts = package
        .get("scripts")
        .and_then(|s| s.as_object())
        .and_then(|scripts| scripts.get(script))
        .and_then(|entry| entry.as_str())
        .map(|entry| entry.to_string())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Package script '{}' not found in {}",
                script,
                package_json.display()
            )
        })?;

    // Spawn the script line via the shell with `node_modules/.bin` prepended to
    // PATH, matching the npm/bun execution model. The script body's own tool
    // requirements are the script's business.
    let bin_dir = package_root.join("node_modules").join(".bin");
    let mut path_entries: Vec<std::path::PathBuf> = vec![bin_dir];
    if let Some(existing) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&existing));
    }
    let child_path =
        std::env::join_paths(path_entries).context("Failed to compose PATH for package script")?;

    let mut command_line = scripts.clone();
    for arg in args {
        command_line.push(' ');
        command_line.push_str(&escape_script_arg(arg)?);
    }

    #[cfg(not(windows))]
    let mut cmd = {
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(&command_line);
        cmd
    };
    #[cfg(windows)]
    let mut cmd = {
        let mut cmd = tokio::process::Command::new("cmd");
        cmd.arg("/C").arg(&command_line);
        cmd
    };

    cmd.env("PATH", &child_path);
    cmd.current_dir(&package_root);
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    eprintln!("running package script `{}` ({})", script, scripts);

    let status = cmd
        .status()
        .await
        .with_context(|| format!("Failed to run package script `{script}`"))?;
    if !status.success() {
        // Propagate the child's own exit code so `ibex check` mirrors npm/bun
        // (e.g. an eslint script exiting 2 makes `ibex` exit 2, not 1). (ENG-22958)
        return Err(PackageScriptExit {
            script: script.to_string(),
            code: package_script_exit_code(&status),
        }
        .into());
    }

    Ok(())
}

/// Escape an argument appended to a package-script line for the platform
/// shell. Plain identifier-ish arguments pass through unquoted so command
/// lines stay readable.
#[cfg(not(windows))]
fn escape_script_arg(arg: &str) -> Result<String> {
    let is_plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '='));
    Ok(if is_plain {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    })
}

/// cmd.exe ignores single quotes and treats `&|<>^%` as live metacharacters
/// even inside some quoting forms (review R8). Spaced arguments are
/// double-quoted with embedded quotes doubled; metacharacter arguments are
/// rejected with an instructive error rather than mis-executed.
#[cfg(windows)]
fn escape_script_arg(arg: &str) -> Result<String> {
    if arg
        .chars()
        .any(|c| matches!(c, '&' | '|' | '<' | '>' | '^' | '%'))
    {
        anyhow::bail!(
            "package-script argument {arg:?} contains cmd.exe metacharacters;              quote the call inside the script itself or run the tool directly"
        );
    }
    let needs_quotes = arg.is_empty() || arg.chars().any(|c| c.is_whitespace() || c == '"');
    Ok(if needs_quotes {
        format!("\"{}\"", arg.replace('"', "\"\""))
    } else {
        arg.to_string()
    })
}

fn find_package_root(start: std::path::PathBuf) -> Result<std::path::PathBuf> {
    let mut current = if start.is_file() {
        start
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Cannot resolve package root"))?
            .to_path_buf()
    } else {
        start
    };

    loop {
        if current.join("package.json").exists() {
            return Ok(current);
        }
        if !current.pop() {
            break;
        }
    }

    anyhow::bail!("Could not find package.json in current directory or any parent directories");
}

async fn suppress_runtime_banner(runtime: &runtime::Runtime) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = runtime;
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        runtime
            .engine()
            .eval_immediate("globalThis.__exactSuppressRuntimeBanner = true;")
            .await?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct RunFileOptions<'a> {
    inspect: bool,
    inspect_wait: bool,
    inspect_open: bool,
    inspect_pause: bool,
    keep_alive: bool,
    inspect_port: Option<u16>,
    inspect_host: Option<&'a str>,
}

/// Run a JavaScript/TypeScript file
async fn run_file(
    cli: &Cli,
    file: &str,
    args: &[String],
    options: RunFileOptions<'_>,
) -> Result<()> {
    let t0 = std::time::Instant::now();
    let runtime = runtime::Runtime::from_cli(cli)?;
    if trace_startup() {
        eprintln!(
            "[startup] {:<30} {:>6} us ({:>5.1} ms)",
            "runtime_from_cli",
            t0.elapsed().as_micros(),
            t0.elapsed().as_micros() as f64 / 1000.0
        );
    }

    suppress_runtime_banner(&runtime).await?;

    // Load the runtime bundle first
    let t1 = std::time::Instant::now();
    runtime.load_runtime().await?;
    if trace_startup() {
        eprintln!(
            "[startup] {:<30} {:>6} us ({:>5.1} ms)",
            "load_runtime",
            t1.elapsed().as_micros(),
            t1.elapsed().as_micros() as f64 / 1000.0
        );
    }

    // Set up inspector if requested
    let inspect_enabled = options.inspect
        || options.inspect_wait
        || options.inspect_open
        || options.inspect_pause
        || cli.inspect
        || cli.inspect_wait
        || cli.inspect_open
        || cli.inspect_pause;
    let open_devtools = options.inspect_open || cli.inspect_open;
    // Wait for debugger if explicitly requested, or if we opened DevTools
    // (since opening DevTools implies wanting to debug before code runs)
    let wait_for_debugger = options.inspect_wait
        || cli.inspect_wait
        || options.inspect_pause
        || cli.inspect_pause
        || open_devtools;
    if inspect_enabled {
        let host = options
            .inspect_host
            .or(cli.inspect_host.as_deref())
            .unwrap_or("127.0.0.1");
        let port = options.inspect_port.or(cli.inspect_port).unwrap_or(9229);
        runtime.start_inspector(host, port).await?;
        eprintln!("Debugger listening on ws://{}:{}", host, port);
        eprintln!("For help, see: https://nodejs.org/en/docs/guides/debugging-getting-started");
        eprintln!("DevTools URL: {}", devtools_url(host, port));
        if open_devtools {
            open_devtools_for_port(port);
        }
        if wait_for_debugger {
            eprintln!("Waiting for debugger to attach...");
            runtime.wait_for_inspector().await?;
            eprintln!("Debugger attached.");
            // Also wait for the Debugger domain to be enabled
            runtime.wait_for_debugger().await?;
        }
    }

    if options.inspect_pause || cli.inspect_pause {
        let _ = runtime.eval("debugger;").await?;
    }

    // Run the user's file
    runtime.run_file_with_args(file, args).await?;

    // @ref LLP 0013#phase-1 — surface would-deny decisions collected in audit
    // mode so operators see exactly what to declare before enforcing.
    if let Some(report) = crate::host::abi::current_audit_report() {
        eprintln!("\n{report}");
    }

    if options.keep_alive || cli.keep_alive {
        eprintln!("Press Ctrl+C to exit.");
        run_debug_loop(&runtime).await;
    }

    let exit_code = read_process_exit_code(&runtime).await;

    // Stop the inspector before the runtime is dropped to avoid use-after-free.
    // The CDP server thread holds a raw pointer to the runtime, so it must be
    // shut down first.
    runtime.stop_inspector().await?;

    if let Some(code) = exit_code {
        std::process::exit(code);
    }

    Ok(())
}

/// A script that sets `process.exitCode` and returns must exit with that code.
async fn read_process_exit_code(runtime: &runtime::Runtime) -> Option<i32> {
    let result = runtime
        .engine()
        .eval_immediate(
            "(typeof globalThis.process === 'object' && globalThis.process !== null && \
             typeof globalThis.process.exitCode === 'number') \
             ? String(globalThis.process.exitCode) : ''",
        )
        .await
        .ok()??;
    result.trim().parse::<i32>().ok().filter(|code| *code != 0)
}

/// Run a file in watch mode — re-run on file changes
async fn run_watch(cli: &Cli, file: &str, args: &[String]) -> Result<()> {
    use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
    use std::time::Duration;
    use tokio::sync::mpsc;

    let file_path = std::path::Path::new(file)
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(file));
    let watch_dir = file_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    eprintln!(
        "\x1b[2m[watch]\x1b[0m watching for changes in {}",
        watch_dir.display()
    );

    let shutdown_timeout = watch_shutdown_timeout();
    let debounce = Duration::from_millis(300);

    // Create the watcher ONCE and keep it alive across restarts. The old code
    // rebuilt the watcher + channel every iteration, so any change that landed
    // between stopping the old child and re-arming the watcher was lost. (ENG-22958)
    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        Config::default().with_poll_interval(Duration::from_millis(200)),
    )
    .context("Failed to create file watcher")?;
    watcher
        .watch(watch_dir, RecursiveMode::Recursive)
        .context("Failed to watch directory")?;

    loop {
        // Run the file in a child process so we can kill it on change
        let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("ibex"));
        let mut cmd = tokio::process::Command::new(&exe);
        for flag in watch_child_args(cli) {
            cmd.arg(flag);
        }
        cmd.arg("run").arg(file);
        for arg in args {
            cmd.arg(arg);
        }
        cmd.stdin(std::process::Stdio::inherit());
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());

        let mut child = cmd.spawn().context("Failed to spawn child process")?;

        let should_continue = await_restart_trigger(&mut child, &mut rx, debounce).await;
        // Always stop the (possibly still-running) child before restarting.
        stop_watch_child(&mut child, shutdown_timeout).await?;
        if !should_continue {
            break;
        }
    }

    Ok(())
}

/// Block until watch mode should restart the child.
///
/// Trailing-edge debounce (ENG-22958): after the first relevant change,
/// coalesce further relevant changes and only restart once the filesystem has
/// been quiet for `debounce`. The old leading-edge check *discarded* any change
/// arriving within the window (`if last_change.elapsed() < debounce { continue }`),
/// so a format-on-save write landing shortly after a restart left the new child
/// running stale code until the next manual save. Here that trailing write is
/// deferred, never dropped — each relevant change extends the quiet window, so
/// the restarted child always sees the final file contents.
///
/// If the child exits on its own first, wait for the next relevant change before
/// restarting. Returns `false` only if the watch channel closed (watcher gone),
/// signalling the caller to stop watching.
async fn await_restart_trigger(
    child: &mut tokio::process::Child,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<notify::Event>,
    debounce: std::time::Duration,
) -> bool {
    use std::time::Instant;

    // Phase 1: wait for the first trigger — a relevant change or the child
    // exiting on its own. `child_running` disables the exit arm after the child
    // is reaped so we keep waiting for a change instead of re-polling `wait()`.
    let mut child_running = true;
    loop {
        tokio::select! {
            status = child.wait(), if child_running => {
                child_running = false;
                match status {
                    Ok(status) => {
                        let code = status.code().unwrap_or(0);
                        if code != 0 {
                            eprintln!(
                                "\x1b[31m[watch]\x1b[0m process exited with code {}",
                                code
                            );
                        }
                        eprintln!("\x1b[2m[watch]\x1b[0m waiting for changes...");
                        // Keep looping — the change arm below drives the restart.
                    }
                    Err(e) => {
                        eprintln!("\x1b[31m[watch]\x1b[0m error: {}", e);
                        return true;
                    }
                }
            }
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else { return false; };
                if is_relevant_change(&event) {
                    break;
                }
            }
        }
    }

    // Phase 2: a relevant change arrived. Coalesce a burst (format-on-save,
    // multi-file writes) by extending a quiet window on each further relevant
    // change; restart only once it elapses. Irrelevant events don't extend it.
    let mut deadline = Instant::now() + debounce;
    loop {
        let now = Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            break;
        };
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(event)) => {
                if is_relevant_change(&event) {
                    deadline = Instant::now() + debounce;
                }
            }
            Ok(None) => break, // channel closed; restart once with what we have
            Err(_) => break,   // quiet window elapsed
        }
    }

    eprintln!("\x1b[33m[watch]\x1b[0m change detected, restarting...");
    true
}

/// Reconstruct the global flag set for the watch child. The child previously
/// received only `--engine`, silently dropping `--capsec`/`--allow`/`--deny`
/// and the rest. `--watch` itself and `--keep-alive` are intentionally
/// excluded: the watch loop owns the child's lifecycle.
fn watch_child_args(cli: &Cli) -> Vec<String> {
    let mut flags = vec!["--engine".to_string(), cli.engine.clone()];

    match cli.capsec {
        // Auto is the default — forward nothing so the child also defers to policy.
        cli::CapSecMode::Auto => {}
        cli::CapSecMode::Permissive => flags.extend(["--capsec".into(), "permissive".into()]),
        cli::CapSecMode::Audit => flags.extend(["--capsec".into(), "audit".into()]),
        cli::CapSecMode::Enforce => flags.extend(["--capsec".into(), "enforce".into()]),
    }
    if cli.lockdown {
        flags.push("--lockdown".into());
    }
    if let Some(policy) = &cli.policy {
        flags.extend(["--policy".into(), policy.to_string_lossy().into_owned()]);
    }
    for allow in &cli.allow {
        flags.extend(["--allow".into(), allow.clone()]);
    }
    for deny in &cli.deny {
        flags.extend(["--deny".into(), deny.clone()]);
    }
    if cli.allow_all {
        flags.push("--allow-all".into());
    }
    // @ref LLP 0013#mechanism-2 — (ENG-22684) — the env-endowment escape hatch must
    // reach the watch child, else an enforce-mode restart would drop IBEX_ENDOW
    // the parent honored, silently changing behavior across a reload.
    if cli.allow_env_endowments {
        flags.push("--allow-env-endowments".into());
    }
    if cli.capsec_allow_advisory {
        flags.push("--capsec-allow-advisory".into());
    }
    if cli.bundle_format != cli::BundleFormat::Esm {
        flags.extend(["--bundle-format".into(), cli.bundle_format.as_str().into()]);
    }
    if cli.inspect {
        flags.push("--inspect".into());
    }
    if cli.inspect_wait {
        flags.push("--inspect-wait".into());
    }
    if cli.inspect_open {
        flags.push("--inspect-open".into());
    }
    if cli.inspect_pause {
        flags.push("--inspect-pause".into());
    }
    if let Some(port) = cli.inspect_port {
        flags.extend(["--inspect-port".into(), port.to_string()]);
    }
    if let Some(host) = &cli.inspect_host {
        flags.extend(["--inspect-host".into(), host.clone()]);
    }
    // Opt-in compat surfaces and the hidden compat-fidelity flags ride along
    // too (review R1 — `ibex --watch --compat=bun` lost the Bun surface).
    if let Some(compat) = &cli.compat {
        flags.extend(["--compat".into(), compat.clone()]);
    }
    if cli.expose_internals {
        flags.push("--expose-internals".into());
    }
    if let Some(stack_size) = &cli.stack_size {
        flags.extend(["--stack-size".into(), stack_size.clone()]);
    }
    if let Some(size) = cli.max_http_header_size {
        flags.extend(["--max-http-header-size".into(), size.to_string()]);
    }

    flags
}

fn is_relevant_change(event: &notify::Event) -> bool {
    use notify::EventKind;
    match &event.kind {
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
            // Only restart for relevant file types
            event.paths.iter().any(|p| {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                matches!(
                    ext,
                    "js" | "ts" | "tsx" | "jsx" | "mjs" | "cjs" | "json" | "css" | "html"
                )
            })
        }
        _ => false,
    }
}

/// Run an event loop that allows debugger interactions while keeping the process
/// alive. It drives the runtime's event loop each tick so DevTools
/// `Runtime.evaluate` and timers scheduled from DevTools actually run — the old
/// loop only ticked a counter and never polled, so those hung. (ENG-22958)
async fn run_debug_loop(runtime: &runtime::Runtime) {
    use tokio::sync::mpsc;
    use tokio::time::{interval, Duration, Instant};

    let engine = runtime.engine();

    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<()>();

    let tx = shutdown_tx.clone();
    let ctrl_handle = tokio::spawn(async move {
        loop {
            if tokio::signal::ctrl_c().await.is_err() {
                break;
            }
            let _ = tx.send(());
        }
    });

    #[cfg(unix)]
    let terminate_handle = if let Ok(mut signal) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        let tx = shutdown_tx.clone();
        Some(tokio::spawn(async move {
            while signal.recv().await.is_some() {
                let _ = tx.send(());
            }
        }))
    } else {
        None
    };

    let mut shutdown_requests = 0u8;
    let mut force_deadline: Option<Instant> = None;
    let mut ticker = interval(Duration::from_millis(50));

    const SHUTDOWN_FORCE_DELAY_MS: u64 = 5_000;

    let stop_signal_watchers = || {
        ctrl_handle.abort();
        #[cfg(unix)]
        if let Some(handle) = terminate_handle.as_ref() {
            handle.abort();
        }
    };

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Drive the runtime's event loop so DevTools evaluations and
                // timers scheduled from DevTools run while we stay alive.
                if let Err(err) = engine.drive_ready_tasks().await {
                    eprintln!("error: keep-alive event loop failed: {err:#}");
                    stop_signal_watchers();
                    break;
                }
                if shutdown_requests == 0 {
                    continue;
                }
                let active = crate::host::http_server::ex_host_http_has_referenced() != 0
                    || crate::host::http_server::ex_host_http_has_pending_requests() != 0;
                if !active {
                    stop_signal_watchers();
                    break;
                }
                if let Some(deadline) = force_deadline {
                    if Instant::now() >= deadline {
                        let _ = crate::host::http_server::close_all_http_servers(1);
                        stop_signal_watchers();
                        break;
                    }
                }
            }
            signal = shutdown_rx.recv() => {
                match signal {
                    Some(()) => {
                        shutdown_requests = shutdown_requests.saturating_add(1);
                        if shutdown_requests == 1 {
                            let active = crate::host::http_server::close_all_http_servers(0);
                            if active == 0 {
                                stop_signal_watchers();
                                break;
                            }
                            force_deadline = Some(
                                Instant::now() + Duration::from_millis(SHUTDOWN_FORCE_DELAY_MS),
                            );
                        } else {
                            let _ = crate::host::http_server::close_all_http_servers(1);
                            stop_signal_watchers();
                            break;
                        }
                    }
                    None => {
                        stop_signal_watchers();
                        break;
                    }
                }
            }
        }
    }
}

/// Evaluate a one-liner JavaScript expression
async fn eval_code(cli: &Cli, code: &str, print_result: bool) -> Result<()> {
    let runtime = runtime::Runtime::from_cli(cli)?;

    suppress_runtime_banner(&runtime).await?;

    // Load the runtime bundle
    if trace_startup() {
        eprintln!("[startup] eval_load_runtime_start");
    }
    runtime.load_runtime().await?;
    if trace_startup() {
        eprintln!("[startup] eval_load_runtime_end");
    }

    if cli.inspect || cli.inspect_wait || cli.inspect_open || cli.inspect_pause {
        let host = cli.inspect_host.as_deref().unwrap_or("127.0.0.1");
        let port = cli.inspect_port.unwrap_or(9229);
        runtime.start_inspector(host, port).await?;
        eprintln!("Debugger listening on ws://{}:{}", host, port);
        eprintln!("For help, see: https://nodejs.org/en/docs/guides/debugging-getting-started");
        eprintln!("DevTools URL: {}", devtools_url(host, port));
        if cli.inspect_open {
            open_devtools_for_port(port);
        }
        // Wait for debugger if explicitly requested, or if we opened DevTools
        // (since opening DevTools implies wanting to debug before code runs)
        if cli.inspect_wait || cli.inspect_pause || cli.inspect_open {
            eprintln!("Waiting for debugger to attach...");
            runtime.wait_for_inspector().await?;
            eprintln!("Debugger attached.");
            // Also wait for the Debugger domain to be enabled
            runtime.wait_for_debugger().await?;
        }
    }

    if cli.inspect_pause {
        let _ = runtime.eval("debugger;").await?;
    }

    // Set up process.argv0 from raw OS argv[0] (needed for argv0 option in spawn)
    #[cfg(not(windows))]
    {
        let raw_argv0 = std::env::args().next().unwrap_or_default();
        let argv0_json = serde_json::to_string(&raw_argv0).unwrap_or_else(|_| "\"\"".to_string());
        let argv0_code = format!(
            "if (typeof globalThis.process === 'object' && globalThis.process !== null) {{ \
                if (globalThis.process.argv0 === undefined) {{ globalThis.process.argv0 = {}; }} \
            }}",
            argv0_json
        );
        let _ = runtime.eval(&argv0_code).await;
    }

    let mut eval_source = if !cfg!(windows)
        && !print_result
        && runtime::contains_top_level_await(code)
    {
        format!(
            "Promise.resolve((async () => {{\n{}\n}})()).catch(err => {{ setTimeout(() => {{ throw err; }}, 0); }});",
            code
        )
    } else {
        code.to_string()
    };

    if print_result {
        eval_source = format!(
            r#"(function() {{
  if (typeof globalThis.require !== 'function') return;
  var moduleBuiltin;
  try {{
    moduleBuiltin = globalThis.require('module');
  }} catch (_) {{
    return;
  }}
  var builtins = moduleBuiltin && Array.isArray(moduleBuiltin.builtinModules)
    ? moduleBuiltin.builtinModules
    : [];
  for (var i = 0; i < builtins.length; i++) {{
    var name = builtins[i];
    if (typeof name !== 'string') continue;
    if (name.indexOf(':') !== -1 || name.indexOf('/') !== -1 || name.indexOf('-') !== -1) continue;
    if (!/^[$A-Z_][0-9A-Z_$]*$/i.test(name)) continue;
    if (Object.prototype.hasOwnProperty.call(globalThis, name)) continue;
    (function(moduleName) {{
      try {{
        Object.defineProperty(globalThis, moduleName, {{
          configurable: true,
          enumerable: false,
          get: function() {{
            var value = globalThis.require(moduleName);
            try {{
              Object.defineProperty(globalThis, moduleName, {{
                value: value,
                writable: true,
                configurable: true,
                enumerable: false
              }});
            }} catch (_defineValueErr) {{}}
            return value;
          }},
          set: function(value) {{
            try {{
              Object.defineProperty(globalThis, moduleName, {{
                value: value,
                writable: true,
                configurable: true,
                enumerable: true
              }});
            }} catch (_setErr) {{}}
          }}
        }});
      }} catch (_defineErr) {{}}
    }})(name);
  }}
}})();
{}"#,
            eval_source
        );
    }

    // Evaluate the code
    if trace_startup() {
        eprintln!("[startup] eval_user_code_start");
    }
    let result = runtime.eval(&eval_source).await?;
    if trace_startup() {
        eprintln!("[startup] eval_user_code_end");
    }

    // Print the result (only for -p, not -e)
    if print_result {
        if let Some(value) = result {
            println!("{}", value);
        }
    }

    if cli.keep_alive {
        eprintln!("Press Ctrl+C to exit.");
        run_debug_loop(&runtime).await;
    }

    if let Some(code) = read_process_exit_code(&runtime).await {
        std::process::exit(code);
    }

    Ok(())
}

/// Start the interactive REPL
async fn start_repl(cli: &Cli) -> Result<()> {
    // REPL respects --capsec mode (defaults to permissive)
    // User can override with --capsec capability or --capsec strict for security testing
    let runtime = runtime::Runtime::from_cli(cli)?;
    suppress_runtime_banner(&runtime).await?;

    // Load the runtime bundle
    runtime.load_runtime().await?;

    if cli.inspect || cli.inspect_wait || cli.inspect_open || cli.inspect_pause {
        let host = cli.inspect_host.as_deref().unwrap_or("127.0.0.1");
        let port = cli.inspect_port.unwrap_or(9229);
        runtime.start_inspector(host, port).await?;
        eprintln!("Debugger listening on ws://{}:{}", host, port);
        eprintln!("For help, see: https://nodejs.org/en/docs/guides/debugging-getting-started");
        eprintln!("DevTools URL: {}", devtools_url(host, port));
        if cli.inspect_open {
            open_devtools_for_port(port);
        }
        // Wait for debugger if explicitly requested, or if we opened DevTools
        if cli.inspect_wait || cli.inspect_pause || cli.inspect_open {
            eprintln!("Waiting for debugger to attach...");
            runtime.wait_for_inspector().await?;
            eprintln!("Debugger attached.");
            runtime.wait_for_debugger().await?;
        }
    }

    if cli.inspect_pause {
        let _ = runtime.eval("debugger;").await?;
    }

    // Start the REPL
    repl::start(runtime.engine()).await
}

/// Compile a file to Hermes bytecode
async fn build_bytecode(cli: &Cli, file: &str, outdir: Option<&std::path::Path>) -> Result<()> {
    if cli.engine != "hermes" {
        anyhow::bail!("build command is only supported for the Hermes engine");
    }

    // Apply the same enforce/audit isolation prerequisite the run path applies,
    // so a build under an enforce policy produces a per-package-chunked artifact
    // (each dependency in its own Domain/principal) instead of a flat,
    // single-principal bundle that attributes every dependency to trusted root.
    // Sets IBEX_PER_PACKAGE_CHUNKS before bundling so the bundler chunks and the
    // cache key agrees. @ref LLP 0013#mechanism-3 — (ENG-22760)
    runtime::apply_build_isolation(cli)?;

    let output_path = runtime::compute_build_output(file, outdir)?;
    let map_path = output_path.with_extension("hbc.map");
    // hermesc doesn't support ESM — always use CJS for bytecode compilation
    let format = if cli.bundle_format == crate::cli::BundleFormat::Esm {
        crate::cli::BundleFormat::Cjs
    } else {
        cli.bundle_format
    };
    let bundled = runtime::prepare_entry_with_format(file, format).await?;
    let bundled_str = bundled.to_string_lossy().to_string();

    engine::hermes::compile_to_bytecode(&bundled_str, &output_path, Some(&map_path)).await?;

    // Under per-package chunking the entry bundle requires sibling chunk files
    // (`__ibexpkg__*`, `rolldown-runtime.js`) that live in the bundle cache dir,
    // not next to the built `.hbc`. The run path resolves them against the
    // artifact's own directory (`__exactChunkDir`), so ship them alongside the
    // `.hbc` — otherwise the built artifact silently loses per-package
    // attribution (a flat single-Domain run). @ref LLP 0013#mechanism-3 — (ENG-22760)
    if crate::env_flag_enabled("IBEX_PER_PACKAGE_CHUNKS") {
        if let Some(dest_dir) = output_path.parent() {
            let copied = runtime::ship_chunk_siblings(&bundled, dest_dir)?;
            if copied > 0 {
                println!(
                    "Shipped {} per-package chunk file(s) alongside {}",
                    copied,
                    output_path.display()
                );
            }
        }
    }

    println!("Compiled {} -> {}", file, output_path.display());
    Ok(())
}

/// Print version information
fn print_version(cli: &Cli) {
    println!("ibex {} ({})", env!("CARGO_PKG_VERSION"), cli.engine);
    println!("Ibex - JavaScript Runtime");

    // Print engine-specific version
    if cli.engine == "hermes" {
        if let Ok(version) = engine::hermes::get_version() {
            println!("Hermes: {}", version);
        }
    }
}

fn print_completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "ibex", &mut std::io::stdout());
}

fn devtools_url(host: &str, port: u16) -> String {
    format!(
        "devtools://devtools/bundled/inspector.html?ws={}:{}/",
        host, port
    )
}

fn open_devtools_for_port(port: u16) {
    let devtools_url = devtools_url("127.0.0.1", port);
    let inspect_url = "chrome://inspect/#devices";
    let json_url = format!("http://127.0.0.1:{}/json", port);

    #[cfg(target_os = "macos")]
    {
        let mut opened = false;
        for app in ["Google Chrome", "Chromium"] {
            if let Ok(status) = std::process::Command::new("open")
                .args(["-a", app, &devtools_url])
                .status()
            {
                if status.success() {
                    opened = true;
                    break;
                }
            }
        }

        if !opened {
            let _ = std::process::Command::new("open").arg(inspect_url).status();
        }

        if !opened {
            eprintln!("Open DevTools manually: {}", devtools_url);
            eprintln!("Or open: {}", inspect_url);
            eprintln!("Or open: {}", json_url);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut opened = false;
        if let Ok(status) = std::process::Command::new("xdg-open")
            .arg(&devtools_url)
            .status()
        {
            opened = status.success();
        }
        if !opened {
            let _ = std::process::Command::new("xdg-open")
                .arg(inspect_url)
                .status();
        }
        if !opened {
            eprintln!("Open DevTools manually: {}", devtools_url);
            eprintln!("Or open: {}", inspect_url);
            eprintln!("Or open: {}", json_url);
        }
    }
    #[cfg(target_os = "windows")]
    {
        let mut opened = false;
        if let Ok(status) = std::process::Command::new("cmd")
            .args(["/C", "start", &devtools_url])
            .status()
        {
            opened = status.success();
        }
        if !opened {
            let _ = std::process::Command::new("cmd")
                .args(["/C", "start", inspect_url])
                .status();
        }
        if !opened {
            eprintln!("Open DevTools manually: {}", devtools_url);
            eprintln!("Or open: {}", inspect_url);
            eprintln!("Or open: {}", json_url);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{
        cli, exit_code_for_error, watch_child_args, watch_shutdown_timeout_from_env,
        DEFAULT_WATCH_SHUTDOWN_TIMEOUT_MS, EXACT_PROJECT_COMMANDS, RESERVED_RUNTIME_COMMANDS,
    };
    use clap::Parser;

    /// The pre-clap dispatcher tables must agree with the runtime surface
    /// manifest (`runtime-surface.json`, LLP 0010#runtime-command-surface):
    /// cli.rs::surface_manifest_matches_clap_tree proves the names are absent
    /// from clap; this proves the dispatcher actually owns exactly those names.
    #[test]
    fn dispatcher_tables_match_surface_manifest() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../../runtime-surface.json"))
                .expect("runtime-surface.json parses");
        let names = |key: &str| -> Vec<String> {
            manifest[key]
                .as_array()
                .unwrap_or_else(|| panic!("{key} is an array"))
                .iter()
                .map(|v| v.as_str().expect("string entry").to_string())
                .collect()
        };

        let mut reserved: Vec<String> = RESERVED_RUNTIME_COMMANDS
            .iter()
            .map(|(name, _)| name.to_string())
            .collect();
        reserved.sort();
        let mut manifest_reserved = names("reservedCommands");
        manifest_reserved.sort();
        assert_eq!(reserved, manifest_reserved, "reserved runtime commands");

        let mut legacy: Vec<String> = EXACT_PROJECT_COMMANDS
            .iter()
            .map(|name| name.to_string())
            .collect();
        legacy.sort();
        let mut manifest_legacy = names("legacyProjectCommands");
        manifest_legacy.sort();
        assert_eq!(legacy, manifest_legacy, "legacy Exact project commands");
    }

    #[test]
    fn watch_child_preserves_security_flags() {
        // @ref LLP 0013#phase-0 — `strict` is a back-compat alias that parses to
        // Enforce; the child receives the canonical `--capsec enforce`.
        let cli = cli::Cli::parse_from([
            "ibex",
            "--watch",
            "--capsec",
            "strict",
            "--allow",
            "fs:read:/tmp",
            "--deny",
            "net",
            "app.ts",
        ]);
        let flags = watch_child_args(&cli);
        let joined = flags.join(" ");
        assert!(joined.contains("--capsec enforce"), "flags: {joined}");
        assert!(joined.contains("--allow fs:read:/tmp"), "flags: {joined}");
        assert!(joined.contains("--deny net"), "flags: {joined}");
        assert!(
            !joined.contains("--watch"),
            "watch must not recurse: {joined}"
        );

        // Audit mode round-trips.
        let cli = cli::Cli::parse_from(["ibex", "--watch", "--capsec", "audit", "app.ts"]);
        let joined = watch_child_args(&cli).join(" ");
        assert!(joined.contains("--capsec audit"), "flags: {joined}");

        // ENG-22684 — the env-endowment escape hatch must survive a watch restart,
        // else an enforce reload would silently drop IBEX_ENDOW the parent honored.
        let cli = cli::Cli::parse_from([
            "ibex",
            "--watch",
            "--capsec",
            "enforce",
            "--allow-env-endowments",
            "--capsec-allow-advisory",
            "app.ts",
        ]);
        let joined = watch_child_args(&cli).join(" ");
        assert!(joined.contains("--allow-env-endowments"), "flags: {joined}");
        assert!(
            joined.contains("--capsec-allow-advisory"),
            "flags: {joined}"
        );
        // Not passed → not forwarded.
        let cli = cli::Cli::parse_from(["ibex", "--watch", "--capsec", "enforce", "app.ts"]);
        assert!(
            !watch_child_args(&cli)
                .join(" ")
                .contains("--allow-env-endowments"),
            "should not forward the hatch when it wasn't set"
        );
        assert!(
            !watch_child_args(&cli)
                .join(" ")
                .contains("--capsec-allow-advisory"),
            "should not forward the advisory hatch when it wasn't set"
        );

        // review R1: opt-in compat surfaces ride along too.
        let cli = cli::Cli::parse_from(["ibex", "--watch", "--compat", "bun", "app.ts"]);
        let joined = watch_child_args(&cli).join(" ");
        assert!(joined.contains("--compat bun"), "flags: {joined}");
    }

    #[test]
    fn watch_child_excludes_lifecycle_flags() {
        let cli = cli::Cli::parse_from(["ibex", "--watch", "--keep-alive", "app.ts"]);
        let flags = watch_child_args(&cli);
        assert!(!flags.contains(&"--keep-alive".to_string()));
        assert_eq!(flags, vec!["--engine".to_string(), "hermes".to_string()]);
    }

    #[test]
    fn watch_shutdown_timeout_uses_override() {
        assert_eq!(
            watch_shutdown_timeout_from_env(Some("3500")).as_millis(),
            3500
        );
    }

    #[test]
    fn watch_shutdown_timeout_falls_back_to_default() {
        assert_eq!(
            watch_shutdown_timeout_from_env(None).as_millis(),
            DEFAULT_WATCH_SHUTDOWN_TIMEOUT_MS as u128
        );
    }

    #[test]
    fn exit_code_for_error_marks_host_io_failures() {
        let error = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "nope",
        ));

        assert_eq!(exit_code_for_error(&error), 3);
    }

    #[test]
    fn exit_code_for_error_leaves_runtime_failures_as_generic() {
        let error = anyhow::anyhow!("syntax error");

        assert_eq!(exit_code_for_error(&error), 1);
    }

    #[test]
    fn exit_code_for_error_propagates_package_script_code() {
        // A failing package script must surface its own exit code (eslint's 2),
        // matching npm/bun, not the generic 1. (ENG-22958)
        let error = anyhow::Error::new(super::PackageScriptExit {
            script: "lint".to_string(),
            code: 2,
        });
        assert_eq!(exit_code_for_error(&error), 2);

        // The code survives extra context layered on top of the error.
        let wrapped = error.context("running package script `lint`");
        assert_eq!(exit_code_for_error(&wrapped), 2);
    }

    #[test]
    fn exit_code_for_error_marks_host_lifecycle_messages() {
        for message in [
            "Host not initialized",
            "Permission denied for /tmp/blocked.txt",
            "Failed to start HTTP server",
        ] {
            assert_eq!(
                exit_code_for_error(&anyhow::anyhow!("{message}")),
                3,
                "message: {message}"
            );
        }
    }

    /// Read an error-origin source file in this repo. Test-only use of
    /// CARGO_MANIFEST_DIR is intentional: these tests pin local source strings
    /// that cross the FFI/JSI boundary.
    fn origin_source(relative: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
    }

    // `exit_code_for_error` cannot downcast these errors, so each matched
    // prefix is pinned to its origin file. If one fails, update the prefix
    // table and this test together.

    #[test]
    fn host_lifecycle_host_not_initialized_matches_origin() {
        let source = origin_source("src/host/abi.rs");
        assert!(
            source.contains(r#"anyhow!("Host not initialized")"#),
            "with_host() defaults in ibex-runtime/src/host/abi.rs no longer use \
             \"Host not initialized\""
        );
    }

    #[test]
    fn host_lifecycle_permission_denied_matches_origin() {
        let source = origin_source("src/host/mod.rs");
        assert!(
            source.contains(r#""Permission denied for {}""#),
            "Host::resolve_module in ibex-runtime/src/host/mod.rs no longer uses \
             \"Permission denied for {{}}\""
        );
    }

    #[test]
    fn host_lifecycle_http_server_matches_origin() {
        let cc_source = origin_source("src/engine/hermes_runtime_http.cc");
        assert!(
            cc_source.contains(r#""Failed to start HTTP server""#),
            "__exactHttpServe in ibex-runtime/src/engine/hermes_runtime_http.cc no longer \
             uses \"Failed to start HTTP server\""
        );

        let js_source = origin_source("src/engine/bootstrap/exact-global.js");
        assert!(
            js_source.contains("'Failed to start HTTP server'"),
            "the exact:http bootstrap in ibex-runtime/src/engine/bootstrap/exact-global.js \
             no longer uses 'Failed to start HTTP server'"
        );
    }
}
