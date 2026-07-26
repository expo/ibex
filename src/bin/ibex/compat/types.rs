//! Shared types for the compatibility test runner.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// CLI options for `ibex compat`.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CompatOptions {
    /// Probe-mode expression (`--probe`): run one JS expression at each
    /// observation point of the serving path instead of the fixture suite.
    pub probe: Option<String>,
    pub section: Option<String>,
    pub module: Option<String>,
    pub test_filter: Vec<String>,
    pub quick: bool,
    pub failed: bool,
    pub update_expectations: bool,
    pub report: bool,
    pub json: bool,
    pub log: bool,
    pub log_color: bool,
    pub log_no_skip: bool,
    pub jobs: Option<usize>,
    pub strict: bool,
    pub all: bool,
    pub no_retry: bool,
    pub timeout: Option<u64>,
}

impl CompatOptions {
    /// Default maximum parallelism for compatibility runs when `--jobs` is not set.
    /// Kept conservative (4) because macOS has no RLIMIT_AS protection and
    /// resource-heavy tests (net servers, child_process spawns) can exhaust
    /// memory if too many run concurrently.
    const DEFAULT_PARALLELISM_LIMIT: usize = 4;

    /// Maximum tier to include based on flags.
    pub fn max_tier(&self) -> u8 {
        if self.quick {
            0
        } else if self.all || self.module.is_some() || !self.test_filter.is_empty() || self.failed {
            2
        } else {
            1
        }
    }

    /// Number of parallel workers.
    pub fn parallelism(&self) -> usize {
        // Port delta (ENG-23081): std replaces the original's num_cpus dep.
        let cpus = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .max(1);
        let jobs = self.jobs.unwrap_or(cpus);
        let jobs = if self.jobs.is_none() {
            jobs.min(Self::DEFAULT_PARALLELISM_LIMIT)
        } else {
            jobs
        };
        jobs.max(1)
    }
}

/// Test status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestStatus {
    Pass,
    Fail,
    Skip,
    Timeout,
    Crash,
    Flaky,
}

impl std::fmt::Display for TestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
            Self::Skip => write!(f, "skip"),
            Self::Timeout => write!(f, "timeout"),
            Self::Crash => write!(f, "crash"),
            Self::Flaky => write!(f, "flaky"),
        }
    }
}

/// Section identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Section {
    Wpt,
    Node,
    Bun,
    Exact,
}

impl Section {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Wpt => "wpt",
            Self::Node => "node",
            Self::Bun => "bun",
            Self::Exact => "exact",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Wpt => "Web Platform",
            Self::Node => "Node.js",
            Self::Bun => "Bun",
            Self::Exact => "Exact",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "wpt" | "web" | "web-platform" => Some(Self::Wpt),
            "node" | "nodejs" | "node.js" => Some(Self::Node),
            "bun" => Some(Self::Bun),
            "exact" => Some(Self::Exact),
            _ => None,
        }
    }

    pub fn all() -> &'static [Section] {
        &[Self::Wpt, Self::Node, Self::Bun, Self::Exact]
    }
}

/// A single test to execute.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TestEntry {
    /// Stable identity, e.g. "node/fs/parallel/test-fs-read.js"
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Section this test belongs to
    pub section: Section,
    /// Module/category name
    pub module: String,
    /// Absolute path to the test file
    pub file_path: PathBuf,
    /// Timeout in milliseconds
    pub timeout_ms: u64,
    /// Tier (0, 1, or 2)
    pub tier: u8,
    /// How to run this test
    pub run_mode: RunMode,
    /// Expected status from expectations.json, if configured.
    pub expected_status: Option<TestStatus>,
}

/// How to execute a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    /// Run in a child process (default — each test gets its own process)
    #[default]
    ChildProcess,
    /// Run inline in the runner process (for lightweight tests)
    Inline,
}

/// The plan of tests to execute.
#[derive(Debug, Clone)]
pub struct TestPlan {
    pub tests: Vec<TestEntry>,
}

impl TestPlan {
    /// Count tests per section.
    pub fn section_counts(&self) -> HashMap<Section, usize> {
        let mut counts = HashMap::new();
        for test in &self.tests {
            *counts.entry(test.section).or_insert(0) += 1;
        }
        counts
    }

    /// Count tests per module within a section.
    #[allow(dead_code)]
    pub fn module_counts(&self, section: Section) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for test in &self.tests {
            if test.section == section {
                *counts.entry(test.module.clone()).or_insert(0) += 1;
            }
        }
        counts
    }
}

/// Result of a single test execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub id: String,
    pub status: TestStatus,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_url: Option<String>,
}

/// Results for a module (group of tests).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    pub pass: u32,
    pub fail: u32,
    pub skip: u32,
    pub total: u32,
    pub duration_ms: u64,
    pub tests: Vec<TestResult>,
}

impl ModuleResult {
    pub fn new() -> Self {
        Self {
            pass: 0,
            fail: 0,
            skip: 0,
            total: 0,
            duration_ms: 0,
            tests: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: TestResult) {
        match result.status {
            TestStatus::Pass => self.pass += 1,
            TestStatus::Fail => self.fail += 1,
            TestStatus::Skip => self.skip += 1,
            TestStatus::Timeout => self.fail += 1,
            TestStatus::Crash => self.fail += 1,
            TestStatus::Flaky => self.pass += 1, // flaky counts as pass unless --strict
        }
        self.total += 1;
        self.duration_ms += result.duration_ms;
        self.tests.push(result);
    }
}

/// Results for a section (WPT, Node, Bun, Exact).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionResult {
    pub pass: u32,
    pub fail: u32,
    pub skip: u32,
    pub total: u32,
    pub duration_ms: u64,
    pub modules: HashMap<String, ModuleResult>,
}

impl SectionResult {
    pub fn new() -> Self {
        Self {
            pass: 0,
            fail: 0,
            skip: 0,
            total: 0,
            duration_ms: 0,
            modules: HashMap::new(),
        }
    }

    pub fn score_pct(&self) -> f64 {
        if self.total == 0 {
            return 100.0;
        }
        (self.pass as f64 / self.total as f64) * 100.0
    }
}

/// Complete compatibility test results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatResults {
    pub timestamp: String,
    pub duration_ms: u64,
    pub exact_version: String,
    pub platform: String,
    pub sections: HashMap<Section, SectionResult>,
}

impl CompatResults {
    pub fn new() -> Self {
        Self {
            timestamp: chrono_now(),
            duration_ms: 0,
            exact_version: env!("CARGO_PKG_VERSION").to_string(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            sections: HashMap::new(),
        }
    }

    pub fn total_pass(&self) -> u32 {
        self.sections.values().map(|s| s.pass).sum()
    }

    pub fn total_fail(&self) -> u32 {
        self.sections.values().map(|s| s.fail).sum()
    }

    pub fn total_skip(&self) -> u32 {
        self.sections.values().map(|s| s.skip).sum()
    }

    pub fn total_tests(&self) -> u32 {
        self.sections.values().map(|s| s.total).sum()
    }

    pub fn overall_score_pct(&self) -> f64 {
        let total = self.total_tests();
        if total == 0 {
            return 100.0;
        }
        (self.total_pass() as f64 / total as f64) * 100.0
    }
}

/// Live update event sent from the runner to the dashboard.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum RunnerEvent {
    /// A test started executing
    TestStarted {
        id: String,
        section: Section,
        module: String,
    },
    /// A test completed
    TestCompleted {
        id: String,
        section: Section,
        module: String,
        result: Box<TestResult>,
    },
    /// All tests in a module completed
    ModuleCompleted { section: Section, module: String },
    /// All tests completed
    AllCompleted,
}

/// Regression information.
#[derive(Debug, Clone)]
pub struct Regression {
    pub test_id: String,
    pub expected: String,
    pub actual: String,
}

/// Convert days since the Unix epoch into a `(year, month, day)` civil date
/// in the proleptic Gregorian calendar.
///
/// Standard `civil_from_days` algorithm (Howard Hinnant, public domain); kept
/// dependency-free on purpose. This replaced 365-day-year / 30-day-month
/// approximations that wrote wrong dates into checked-in `expectations.json`
/// and a fake "ISO 8601" timestamp (LLP 0175 ledger item 13).
pub fn civil_from_unix_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day-of-era, [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // year-of-era, [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day-of-year (Mar 1 based), [0, 365]
    let mp = (5 * doy + 2) / 153; // month index (Mar = 0), [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Format a Unix timestamp (seconds) as an ISO 8601 UTC timestamp,
/// e.g. `2026-06-12T17:03:09Z`.
pub fn format_iso8601_utc(unix_secs: u64) -> String {
    let (year, month, day) = civil_from_unix_days((unix_secs / 86_400) as i64);
    let secs_of_day = unix_secs % 86_400;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        day,
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60
    )
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_iso8601_utc(now.as_secs())
}

#[cfg(test)]
mod tests {
    use super::{chrono_now, civil_from_unix_days, format_iso8601_utc, CompatOptions};

    fn base_compat_options() -> CompatOptions {
        CompatOptions {
            probe: None,
            section: None,
            module: None,
            test_filter: Vec::new(),
            quick: false,
            failed: false,
            update_expectations: false,
            report: false,
            json: false,
            log: false,
            log_color: false,
            log_no_skip: false,
            jobs: None,
            strict: false,
            all: false,
            no_retry: false,
            timeout: None,
        }
    }

    #[test]
    fn targeted_compat_runs_include_tier_two_modules() {
        let mut opts = base_compat_options();
        assert_eq!(opts.max_tier(), 1);

        opts.module = Some("websockets".to_string());
        assert_eq!(opts.max_tier(), 2);

        opts.module = None;
        opts.test_filter = vec!["Close-1000".to_string()];
        assert_eq!(opts.max_tier(), 2);

        opts.test_filter.clear();
        opts.failed = true;
        assert_eq!(opts.max_tier(), 2);
    }

    #[test]
    fn quick_compat_runs_stay_tier_zero_even_when_targeted() {
        let mut opts = base_compat_options();
        opts.quick = true;
        opts.all = true;
        opts.module = Some("websockets".to_string());
        opts.test_filter = vec!["Close-1000".to_string()];

        assert_eq!(opts.max_tier(), 0);
    }

    #[test]
    fn civil_from_unix_days_matches_known_dates() {
        assert_eq!(civil_from_unix_days(0), (1970, 1, 1));
        // 2026-06-12 (this LLP's date).
        assert_eq!(civil_from_unix_days(20_616), (2026, 6, 12));
        // End-of-year boundary.
        assert_eq!(civil_from_unix_days(19_722), (2023, 12, 31));
        assert_eq!(civil_from_unix_days(19_723), (2024, 1, 1));
    }

    #[test]
    fn civil_from_unix_days_handles_leap_years() {
        // Ordinary leap year.
        assert_eq!(civil_from_unix_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_unix_days(19_783), (2024, 3, 1));
        // 400-year-rule leap year.
        assert_eq!(civil_from_unix_days(11_016), (2000, 2, 29));
        // 100-year-rule non-leap year: Feb 28 is followed by Mar 1.
        assert_eq!(civil_from_unix_days(47_540), (2100, 2, 28));
        assert_eq!(civil_from_unix_days(47_541), (2100, 3, 1));
    }

    #[test]
    fn format_iso8601_utc_matches_known_instants() {
        assert_eq!(format_iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_iso8601_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_iso8601_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn chrono_now_emits_iso8601_utc_shape() {
        let now = chrono_now();
        let bytes = now.as_bytes();
        assert_eq!(now.len(), 20, "timestamp: {now}");
        assert_eq!(bytes[4], b'-', "timestamp: {now}");
        assert_eq!(bytes[7], b'-', "timestamp: {now}");
        assert_eq!(bytes[10], b'T', "timestamp: {now}");
        assert_eq!(bytes[13], b':', "timestamp: {now}");
        assert_eq!(bytes[16], b':', "timestamp: {now}");
        assert_eq!(bytes[19], b'Z', "timestamp: {now}");
        assert!(
            now.chars()
                .enumerate()
                .filter(|(i, _)| ![4, 7, 10, 13, 16, 19].contains(i))
                .all(|(_, c)| c.is_ascii_digit()),
            "timestamp: {now}"
        );
    }
}
