//! End-to-end startup distributions for the CLI and direct embedder surface.
//!
//! Wall-clock performance is environment-sensitive, so ordinary `cargo test`
//! runs one correctness smoke and never enforces budgets. The scheduled
//! startup workflow runs the precommitted sample count and may enforce the
//! checked p95 limits after recording the complete JSON report.
//!
//! @ref LLP 0038#fully-open-mode-insecure — insecure work is compile-time
//! profile work; the benchmark never installs a runtime-controlled bypass.
//! @ref LLP 0022#2-startup-project-identity-and-session-arming — the REPL
//! endpoint is the first prompt observed through a real pseudoterminal.
//! @ref LLP 0002#the-narrow-consumer-contract-semver-major — the embedded arm
//! uses the explicit diagnostic constructor and legacy evaluation ABI.

use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::ffi::{c_char, CString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BUDGETS_JSON: &str = include_str!("startup-budgets-v1.json");
const REPL_PROMPT: &[u8] = "➤ ".as_bytes();
const SCENARIOS: [Scenario; 4] = [
    Scenario::ReplFirstPrompt,
    Scenario::EvalTrivial,
    Scenario::RunTrivial,
    Scenario::PackageScript,
];

#[repr(C)]
struct ExactHermesRuntime {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn ex_hermes_create_diagnostic() -> *mut ExactHermesRuntime;
    fn ex_hermes_destroy(runtime: *mut ExactHermesRuntime);
    fn ex_hermes_eval(
        runtime: *mut ExactHermesRuntime,
        data: *const u8,
        len: usize,
        source_url: *const c_char,
        is_bytecode: i32,
        out_value: *mut *mut c_char,
    ) -> i32;
    fn ex_hermes_free_string(value: *mut c_char);
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Scenario {
    ReplFirstPrompt,
    EvalTrivial,
    RunTrivial,
    PackageScript,
}

impl Scenario {
    fn key(self) -> &'static str {
        match self {
            Self::ReplFirstPrompt => "replFirstPromptMs",
            Self::EvalTrivial => "evalTrivialMs",
            Self::RunTrivial => "runTrivialMs",
            Self::PackageScript => "packageScriptMs",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ReplFirstPrompt => "REPL first prompt",
            Self::EvalTrivial => "trivial eval",
            Self::RunTrivial => "trivial run",
            Self::PackageScript => "package script",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CacheMode {
    Cold,
    Warm,
}

impl CacheMode {
    fn key(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BudgetFile {
    schema: String,
    baseline_revision: String,
    measurement: Measurement,
    pre_capsec_comparison: PreCapsecComparison,
    platforms: BTreeMap<String, BTreeMap<String, ProfileBudgets>>,
}

#[derive(Debug, Deserialize)]
struct Measurement {
    warmups: usize,
    samples: usize,
    percentile: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreCapsecComparison {
    eval_trivial_p95_ratio: f64,
    run_trivial_p95_ratio: f64,
}

#[derive(Debug, Deserialize)]
struct ProfileBudgets {
    warm: CliBudgets,
    cold: CliBudgets,
    embedded: EmbeddedBudgets,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CliBudgets {
    repl_first_prompt_ms: f64,
    eval_trivial_ms: f64,
    run_trivial_ms: f64,
    package_script_ms: f64,
}

impl CliBudgets {
    fn for_scenario(&self, scenario: Scenario) -> f64 {
        match scenario {
            Scenario::ReplFirstPrompt => self.repl_first_prompt_ms,
            Scenario::EvalTrivial => self.eval_trivial_ms,
            Scenario::RunTrivial => self.run_trivial_ms,
            Scenario::PackageScript => self.package_script_ms,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmbeddedBudgets {
    runtime_create_ms: f64,
    bootstrap_complete_ms: f64,
    first_evaluation_ms: f64,
    total_ms: f64,
}

impl EmbeddedBudgets {
    fn for_key(&self, key: &str) -> f64 {
        match key {
            "runtimeCreateMs" => self.runtime_create_ms,
            "bootstrapCompleteMs" => self.bootstrap_complete_ms,
            "firstEvaluationMs" => self.first_evaluation_ms,
            "totalMs" => self.total_ms,
            _ => panic!("unknown embedded budget key: {key}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Distribution {
    min_ms: f64,
    median_ms: f64,
    mad_ms: f64,
    p95_ms: f64,
    max_ms: f64,
}

impl Distribution {
    fn from_samples(samples: &[f64]) -> Self {
        assert!(!samples.is_empty(), "distribution requires samples");
        let mut ordered = samples.to_vec();
        ordered.sort_by(f64::total_cmp);
        let median_ms = median(&ordered);
        let deviations = ordered
            .iter()
            .map(|sample| (sample - median_ms).abs())
            .collect::<Vec<_>>();
        Self {
            min_ms: ordered[0],
            median_ms,
            mad_ms: median(&deviations),
            p95_ms: percentile(&ordered, 95),
            max_ms: *ordered.last().expect("samples are nonempty"),
        }
    }

    fn json(self) -> Value {
        json!({
            "minMs": round3(self.min_ms),
            "medianMs": round3(self.median_ms),
            "madMs": round3(self.mad_ms),
            "p95Ms": round3(self.p95_ms),
            "maxMs": round3(self.max_ms)
        })
    }
}

#[derive(Default)]
struct EmbeddedSample {
    runtime_create_ms: f64,
    bootstrap_complete_ms: f64,
    first_evaluation_ms: f64,
    total_ms: f64,
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn median(samples: &[f64]) -> f64 {
    let mut ordered = samples.to_vec();
    ordered.sort_by(f64::total_cmp);
    let midpoint = ordered.len() / 2;
    if ordered.len().is_multiple_of(2) {
        (ordered[midpoint - 1] + ordered[midpoint]) / 2.0
    } else {
        ordered[midpoint]
    }
}

fn percentile(ordered: &[f64], percentile: usize) -> f64 {
    assert!(!ordered.is_empty());
    assert!((1..=100).contains(&percentile));
    let rank = (percentile * ordered.len()).div_ceil(100);
    ordered[rank.saturating_sub(1)]
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_root() -> PathBuf {
    repo_root()
        .join("benches")
        .join("fixtures")
        .join("startup_performance")
}

fn ibex_binary() -> PathBuf {
    std::env::var_os("IBEX_BENCH_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_ibex")))
}

fn baseline_binary() -> Option<PathBuf> {
    std::env::var_os("IBEX_BENCH_BASELINE_BIN").map(PathBuf::from)
}

fn profile_name() -> String {
    std::env::var("STARTUP_BENCH_PROFILE").unwrap_or_else(|_| {
        if cfg!(feature = "insecure") {
            "insecure".to_owned()
        } else {
            "secure".to_owned()
        }
    })
}

fn platform_key() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}-{arch}")
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn smoke_mode() -> bool {
    std::env::var_os("STARTUP_BENCH_SMOKE").as_deref() == Some("1".as_ref())
        || std::env::args_os().any(|argument| argument == "--test")
}

fn enforce_budgets() -> bool {
    std::env::var_os("STARTUP_BENCH_ENFORCE").as_deref() == Some("1".as_ref()) && !smoke_mode()
}

fn clean_environment(command: &mut Command) {
    for name in [
        "EXACT_COMPAT_TEST",
        "EXACT_NO_BYTECODE",
        "EXACT_POLICY",
        "IBEX_CAPSEC_ALLOW_ADVISORY",
        "IBEX_COMPARTMENTS",
        "IBEX_ENDOW",
        "IBEX_LOCKDOWN",
        "IBEX_NATIVE_LOCKDOWN",
        "IBEX_NO_BYTECODE",
        "IBEX_PER_PACKAGE_CHUNKS",
        "IBEX_POLICY",
        "IBEX_STARTUP_TRACE",
    ] {
        command.env_remove(name);
    }
    command.env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1");
}

fn set_cache_home(command: &mut Command, home: &Path) {
    command.env("HOME", home);
    command.env("XDG_CACHE_HOME", home.join(".cache"));
    command.env("LOCALAPPDATA", home.join("AppData").join("Local"));
}

fn command_for(binary: &Path, scenario: Scenario) -> Command {
    let mut command = Command::new(binary);
    match scenario {
        Scenario::ReplFirstPrompt => {
            command.arg("repl").current_dir(repo_root());
        }
        Scenario::EvalTrivial => {
            command.args(["eval", "1 + 1"]).current_dir(repo_root());
        }
        Scenario::RunTrivial => {
            command
                .arg("run")
                .arg(fixture_root().join("trivial.mjs"))
                .current_dir(repo_root());
        }
        Scenario::PackageScript => {
            command
                .args(["run", "startup-noop"])
                .current_dir(fixture_root().join("package"));
        }
    }
    command
}

fn checked_output(mut command: Command, label: &str) -> f64 {
    let started = Instant::now();
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("failed to launch {label}: {error}"));
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    if !output.status.success() {
        panic!(
            "{label} failed with {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    elapsed
}

#[cfg(unix)]
fn run_repl_to_first_prompt(binary: &Path, home: &Path) -> f64 {
    use std::os::fd::AsRawFd;

    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
    }

    let script = which::which("script")
        .expect("the startup REPL benchmark requires the platform `script` utility");
    let mut command = Command::new(script);
    if cfg!(target_os = "macos") {
        command.arg("-q").arg("/dev/null").arg(binary).arg("repl");
    } else {
        command
            .args(["-q", "-c"])
            .arg(format!("{} repl", shell_quote(binary)))
            .arg("/dev/null");
    }
    command
        .current_dir(repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    clean_environment(&mut command);
    set_cache_home(&mut command, home);

    let started = Instant::now();
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed to launch REPL: {error}"));
    let mut terminal = child
        .stdout
        .take()
        .expect("script utility did not expose its transcript");
    let terminal_fd = terminal.as_raw_fd();
    let flags = unsafe { libc::fcntl(terminal_fd, libc::F_GETFL) };
    assert!(flags >= 0, "failed to read transcript-pipe flags");
    assert!(
        unsafe { libc::fcntl(terminal_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "failed to make transcript pipe nonblocking"
    );
    let mut transcript = Vec::new();
    let deadline = started + Duration::from_secs(20);
    let elapsed = loop {
        let mut chunk = [0u8; 4096];
        match terminal.read(&mut chunk) {
            Ok(0) => {}
            Ok(count) => transcript.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                let _ = child.kill();
                panic!(
                    "failed reading REPL pseudoterminal: {error}\n{}",
                    String::from_utf8_lossy(&transcript)
                );
            }
        }
        if transcript
            .windows(REPL_PROMPT.len())
            .any(|window| window == REPL_PROMPT)
        {
            break started.elapsed().as_secs_f64() * 1000.0;
        }
        if let Some(status) = child.try_wait().expect("failed to poll REPL") {
            panic!(
                "REPL exited before its first prompt with {:?}\n{}",
                status.code(),
                String::from_utf8_lossy(&transcript)
            );
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!(
                "REPL did not publish its first prompt within 20 seconds\n{}",
                String::from_utf8_lossy(&transcript)
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    };

    // Output publication and the reader's prompt-provenance snapshot cross
    // threads. Give the latter one scheduling turn, then use the generated
    // orderly-EOF keybinding while the edit buffer is empty. Teardown is
    // deliberately outside the measured interval.
    std::thread::sleep(Duration::from_millis(10));
    child
        .stdin
        .as_mut()
        .expect("script utility did not expose terminal input")
        .write_all(&[0x04])
        .expect("failed to ask benchmark REPL to exit");
    let exit_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("failed to poll REPL exit") {
            assert!(
                status.success(),
                "scripted REPL exited with {:?}\n{}",
                status.code(),
                String::from_utf8_lossy(&transcript)
            );
            break;
        }
        if Instant::now() >= exit_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "scripted REPL did not honor orderly EOF after its first prompt\n{}",
                String::from_utf8_lossy(&transcript)
            );
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    elapsed
}

#[cfg(not(unix))]
fn run_repl_to_first_prompt(_binary: &Path, _home: &Path) -> f64 {
    panic!("startup REPL benchmark requires a Unix pseudoterminal");
}

fn run_scenario(binary: &Path, scenario: Scenario, home: &Path) -> f64 {
    if scenario == Scenario::ReplFirstPrompt {
        return run_repl_to_first_prompt(binary, home);
    }
    let mut command = command_for(binary, scenario);
    clean_environment(&mut command);
    set_cache_home(&mut command, home);
    checked_output(command, scenario.label())
}

fn run_cli_distributions(
    binary: &Path,
    mode: CacheMode,
    warmups: usize,
    samples: usize,
) -> BTreeMap<Scenario, Distribution> {
    let shared_home = tempfile::tempdir().expect("failed to create warm cache home");
    let mut measured = SCENARIOS
        .into_iter()
        .map(|scenario| (scenario, Vec::with_capacity(samples)))
        .collect::<BTreeMap<_, _>>();

    for round in 0..(warmups + samples) {
        for offset in 0..SCENARIOS.len() {
            let scenario = SCENARIOS[(round + offset) % SCENARIOS.len()];
            let cold_home;
            let home = match mode {
                CacheMode::Warm => shared_home.path(),
                CacheMode::Cold => {
                    cold_home =
                        tempfile::tempdir().expect("failed to create cold cache sample home");
                    cold_home.path()
                }
            };
            let elapsed = run_scenario(binary, scenario, home);
            if round >= warmups {
                measured
                    .get_mut(&scenario)
                    .expect("scenario was initialized")
                    .push(elapsed);
            }
        }
    }

    measured
        .into_iter()
        .map(|(scenario, values)| (scenario, Distribution::from_samples(&values)))
        .collect()
}

fn run_baseline_distributions(
    binary: &Path,
    warmups: usize,
    samples: usize,
) -> BTreeMap<Scenario, Distribution> {
    let home = tempfile::tempdir().expect("failed to create baseline cache home");
    let scenarios = [Scenario::EvalTrivial, Scenario::RunTrivial];
    let mut measured = scenarios
        .into_iter()
        .map(|scenario| (scenario, Vec::with_capacity(samples)))
        .collect::<BTreeMap<_, _>>();
    for round in 0..(warmups + samples) {
        for offset in 0..scenarios.len() {
            let scenario = scenarios[(round + offset) % scenarios.len()];
            let elapsed = run_scenario(binary, scenario, home.path());
            if round >= warmups {
                measured.get_mut(&scenario).unwrap().push(elapsed);
            }
        }
    }
    measured
        .into_iter()
        .map(|(scenario, values)| (scenario, Distribution::from_samples(&values)))
        .collect()
}

unsafe fn eval_checked(runtime: *mut ExactHermesRuntime, source: &[u8], label: &str) {
    let label = CString::new(label).expect("source label has no NUL");
    let mut output: *mut c_char = std::ptr::null_mut();
    let status = unsafe {
        ex_hermes_eval(
            runtime,
            source.as_ptr(),
            source.len(),
            label.as_ptr(),
            0,
            &mut output,
        )
    };
    if !output.is_null() {
        unsafe { ex_hermes_free_string(output) };
    }
    assert_eq!(status, 0, "embedded evaluation failed for {label:?}");
}

fn run_embedded_sample() -> EmbeddedSample {
    let total_started = Instant::now();
    let create_started = Instant::now();
    let host = ibex_runtime::host::Host::default_legacy();
    assert_ne!(
        ibex_runtime::host::abi::install_host(host),
        0,
        "failed to install embedded diagnostic host"
    );
    let runtime = unsafe { ex_hermes_create_diagnostic() };
    assert!(!runtime.is_null(), "failed to create embedded runtime");
    let runtime_create_ms = create_started.elapsed().as_secs_f64() * 1000.0;

    // Native construction installs the generated core runtime bundle before
    // returning the opaque handle. There is intentionally no observable
    // half-bootstrapped diagnostic handle, so create and bootstrap-complete
    // are two names for the same cumulative readiness boundary rather than
    // separately timed additive phases.
    // @ref LLP 0003#the-bootstrap-sequence
    let bootstrap_complete_ms = total_started.elapsed().as_secs_f64() * 1000.0;

    let eval_started = Instant::now();
    unsafe { eval_checked(runtime, b"1 + 1", "<startup-benchmark-first-eval>") };
    let first_evaluation_ms = eval_started.elapsed().as_secs_f64() * 1000.0;
    let total_ms = total_started.elapsed().as_secs_f64() * 1000.0;
    unsafe { ex_hermes_destroy(runtime) };

    EmbeddedSample {
        runtime_create_ms,
        bootstrap_complete_ms,
        first_evaluation_ms,
        total_ms,
    }
}

fn run_embedded_distributions(
    warmups: usize,
    samples: usize,
) -> BTreeMap<&'static str, Distribution> {
    let mut measured = BTreeMap::from([
        ("runtimeCreateMs", Vec::with_capacity(samples)),
        ("bootstrapCompleteMs", Vec::with_capacity(samples)),
        ("firstEvaluationMs", Vec::with_capacity(samples)),
        ("totalMs", Vec::with_capacity(samples)),
    ]);
    for round in 0..(warmups + samples) {
        let sample = run_embedded_sample();
        if round >= warmups {
            measured
                .get_mut("runtimeCreateMs")
                .unwrap()
                .push(sample.runtime_create_ms);
            measured
                .get_mut("bootstrapCompleteMs")
                .unwrap()
                .push(sample.bootstrap_complete_ms);
            measured
                .get_mut("firstEvaluationMs")
                .unwrap()
                .push(sample.first_evaluation_ms);
            measured.get_mut("totalMs").unwrap().push(sample.total_ms);
        }
    }
    measured
        .into_iter()
        .map(|(key, samples)| (key, Distribution::from_samples(&samples)))
        .collect()
}

fn cli_budget(budgets: &ProfileBudgets, mode: CacheMode) -> &CliBudgets {
    match mode {
        CacheMode::Cold => &budgets.cold,
        CacheMode::Warm => &budgets.warm,
    }
}

fn machine_metadata() -> Value {
    let uname = Command::new("uname")
        .args(["-a"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
    let revision = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
    json!({
        "platform": platform_key(),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "uname": uname,
        "revision": revision
    })
}

fn print_distribution(label: &str, distribution: Distribution, budget: f64) {
    println!(
        "{label:<28} {:>8.2} {:>8.2} {:>8.2} {:>8.2} {:>9.2}  {}",
        distribution.min_ms,
        distribution.median_ms,
        distribution.mad_ms,
        distribution.p95_ms,
        distribution.max_ms,
        if distribution.p95_ms <= budget {
            "within budget"
        } else {
            "OVER BUDGET"
        }
    );
}

fn main() {
    let budget_file: BudgetFile =
        serde_json::from_str(BUDGETS_JSON).expect("startup budget JSON must be valid");
    assert_eq!(budget_file.schema, "ibex/startup-budgets/1");
    assert_eq!(budget_file.measurement.percentile, 95);

    let profile = profile_name();
    let platform = platform_key();
    let profile_budgets = budget_file
        .platforms
        .get(&platform)
        .unwrap_or_else(|| panic!("no startup budgets for platform {platform}"))
        .get(&profile)
        .unwrap_or_else(|| panic!("no startup budgets for profile {profile} on {platform}"));
    let binary = ibex_binary();
    assert!(
        binary.is_file(),
        "Ibex benchmark binary does not exist: {}",
        binary.display()
    );

    let smoke = smoke_mode();
    let warmups = if smoke {
        0
    } else {
        env_usize("STARTUP_BENCH_WARMUPS", budget_file.measurement.warmups)
    };
    let samples = if smoke {
        1
    } else {
        env_usize("STARTUP_BENCH_SAMPLES", budget_file.measurement.samples).max(1)
    };

    println!("Ibex startup performance");
    println!("binary   : {}", binary.display());
    println!("platform : {platform}");
    println!("profile  : {profile}");
    println!("samples  : {samples} (+ {warmups} warmups)");
    println!("baseline : {}", budget_file.baseline_revision);

    let warm = run_cli_distributions(&binary, CacheMode::Warm, warmups, samples);
    let cold = run_cli_distributions(&binary, CacheMode::Cold, warmups, samples);
    let embedded = run_embedded_distributions(warmups, samples);

    let mut failures = Vec::new();
    let mut cli_json = Map::new();
    for (mode, distributions) in [(CacheMode::Warm, &warm), (CacheMode::Cold, &cold)] {
        println!();
        println!("{} application cache", mode.key());
        println!(
            "{:<28} {:>8} {:>8} {:>8} {:>8} {:>9}",
            "scenario", "min", "median", "MAD", "p95", "max"
        );
        let budgets = cli_budget(profile_budgets, mode);
        let mut mode_json = Map::new();
        for scenario in SCENARIOS {
            let distribution = distributions[&scenario];
            let budget = budgets.for_scenario(scenario);
            print_distribution(scenario.label(), distribution, budget);
            if distribution.p95_ms > budget {
                failures.push(format!(
                    "{} {} p95 {:.2} ms > {:.2} ms",
                    mode.key(),
                    scenario.label(),
                    distribution.p95_ms,
                    budget
                ));
            }
            mode_json.insert(
                scenario.key().to_owned(),
                json!({
                    "distribution": distribution.json(),
                    "p95BudgetMs": budget,
                    "withinBudget": distribution.p95_ms <= budget
                }),
            );
        }
        cli_json.insert(mode.key().to_owned(), Value::Object(mode_json));
    }

    println!();
    println!("embedded repeated-runtime");
    println!(
        "{:<28} {:>8} {:>8} {:>8} {:>8} {:>9}",
        "phase", "min", "median", "MAD", "p95", "max"
    );
    let mut embedded_json = Map::new();
    for (key, label) in [
        ("runtimeCreateMs", "runtime + Host create"),
        ("bootstrapCompleteMs", "bootstrap complete"),
        ("firstEvaluationMs", "first evaluation"),
        ("totalMs", "ready total"),
    ] {
        let distribution = embedded[key];
        let budget = profile_budgets.embedded.for_key(key);
        print_distribution(label, distribution, budget);
        if distribution.p95_ms > budget {
            failures.push(format!(
                "embedded {label} p95 {:.2} ms > {:.2} ms",
                distribution.p95_ms, budget
            ));
        }
        embedded_json.insert(
            key.to_owned(),
            json!({
                "distribution": distribution.json(),
                "p95BudgetMs": budget,
                "withinBudget": distribution.p95_ms <= budget
            }),
        );
    }

    let baseline_json = if let Some(baseline) = baseline_binary() {
        assert!(
            baseline.is_file(),
            "baseline binary does not exist: {}",
            baseline.display()
        );
        let baseline_results = run_baseline_distributions(&baseline, warmups, samples);
        let mut comparisons = Map::new();
        for (scenario, allowed_ratio) in [
            (
                Scenario::EvalTrivial,
                budget_file.pre_capsec_comparison.eval_trivial_p95_ratio,
            ),
            (
                Scenario::RunTrivial,
                budget_file.pre_capsec_comparison.run_trivial_p95_ratio,
            ),
        ] {
            let current = warm[&scenario].p95_ms;
            let historical = baseline_results[&scenario].p95_ms;
            let ratio = current / historical;
            println!(
                "pre-CapSec {:<14} current/base p95 = {:.2}× (limit {:.2}×)",
                scenario.label(),
                ratio,
                allowed_ratio
            );
            if ratio > allowed_ratio {
                failures.push(format!(
                    "{} p95 {:.2}× pre-CapSec baseline > {:.2}×",
                    scenario.label(),
                    ratio,
                    allowed_ratio
                ));
            }
            comparisons.insert(
                scenario.key().to_owned(),
                json!({
                    "baseline": baseline_results[&scenario].json(),
                    "currentP95Ms": round3(current),
                    "p95Ratio": round3(ratio),
                    "p95RatioBudget": allowed_ratio,
                    "withinBudget": ratio <= allowed_ratio
                }),
            );
        }
        Some(json!({
            "binary": baseline,
            "revision": budget_file.baseline_revision,
            "comparisons": comparisons
        }))
    } else {
        None
    };

    let report = json!({
        "schema": "ibex/startup-benchmark-report/1",
        "machine": machine_metadata(),
        "profile": profile,
        "binary": binary,
        "measurement": {
            "warmups": warmups,
            "samples": samples,
            "smoke": smoke
        },
        "cli": cli_json,
        "embedded": embedded_json,
        "preCapsecBaseline": baseline_json,
        "failures": failures
    });
    if let Some(output) = std::env::var_os("STARTUP_BENCH_OUTPUT") {
        let output = PathBuf::from(output);
        std::fs::write(
            &output,
            serde_json::to_vec_pretty(&report).expect("report serialization succeeds"),
        )
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", output.display()));
        println!("report    : {}", output.display());
    }

    if failures.is_empty() {
        println!("\nPASS: every measured startup p95 is within its precommitted budget.");
    } else {
        println!("\nStartup budget misses:");
        for failure in &failures {
            println!("  - {failure}");
        }
        if enforce_budgets() {
            std::process::exit(1);
        }
        println!("Informational run: set STARTUP_BENCH_ENFORCE=1 to fail on misses.");
    }
}
