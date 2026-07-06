//! Expectations file management.
//!
//! Tracks expected test status per section, detects regressions
//! (new failures) and progressions (new passes).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use super::types::*;

/// Expected status entry for a single test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectationEntry {
    pub status: TestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// Expectations file for a section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectationsFile {
    pub version: String,
    pub updated: String,
    pub tests: HashMap<String, ExpectationEntry>,
}

impl ExpectationsFile {
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_string(),
            updated: today(),
            tests: HashMap::new(),
        }
    }
}

/// Load expectations for a section.
pub fn load_section_expectations(compat_dir: &Path, section: Section) -> Result<ExpectationsFile> {
    let path = compat_dir.join(section.as_str()).join("expectations.json");

    if !path.exists() {
        return Ok(ExpectationsFile::new("unknown"));
    }

    let content = std::fs::read_to_string(&path)?;
    let expectations: ExpectationsFile = serde_json::from_str(&content)?;
    Ok(expectations)
}

/// Update expectations files from current results (--update-expectations).
pub fn update_expectations(compat_dir: &Path, results: &CompatResults) -> Result<()> {
    for (section, section_result) in &results.sections {
        let path = compat_dir.join(section.as_str()).join("expectations.json");

        // Load existing expectations to preserve metadata (reason, issue, owner)
        let mut expectations = if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            serde_json::from_str::<ExpectationsFile>(&content)
                .unwrap_or_else(|_| ExpectationsFile::new("unknown"))
        } else {
            ExpectationsFile::new("unknown")
        };

        expectations.updated = today();

        // Update test statuses from current results
        for module_result in section_result.modules.values() {
            for test in &module_result.tests {
                let entry = expectations
                    .tests
                    .entry(test.id.clone())
                    .or_insert_with(|| ExpectationEntry {
                        status: test.status,
                        timeout_ms: None,
                        reason: None,
                        issue: None,
                        owner: None,
                    });
                entry.status = test.status;
            }
        }

        // Write back
        let json = serde_json::to_string_pretty(&expectations)?;
        std::fs::write(&path, format!("{}\n", json))?;
    }

    Ok(())
}

/// Check for regressions: tests that were expected to pass but now fail.
pub fn check_regressions(compat_dir: &Path, results: &CompatResults) -> Result<Vec<Regression>> {
    let mut regressions = Vec::new();

    for (section, section_result) in &results.sections {
        let expectations = load_section_expectations(compat_dir, *section)?;

        for module_result in section_result.modules.values() {
            for test in &module_result.tests {
                if let Some(expected) = expectations.tests.get(&test.id) {
                    // Regression: expected pass, got fail/timeout/crash
                    if expected.status == TestStatus::Pass
                        && matches!(
                            test.status,
                            TestStatus::Fail | TestStatus::Timeout | TestStatus::Crash
                        )
                    {
                        regressions.push(Regression {
                            test_id: test.id.clone(),
                            expected: expected.status.to_string(),
                            actual: test.status.to_string(),
                        });
                    }
                }
            }
        }
    }

    Ok(regressions)
}

/// Current UTC date as `YYYY-MM-DD`. This string is written into checked-in
/// expectations.json files, so it must be exact, not approximate
/// (LLP 0175 ledger item 13).
fn today() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let (year, month, day) = civil_from_unix_days((now.as_secs() / 86_400) as i64);
    format!("{:04}-{:02}-{:02}", year, month, day)
}
