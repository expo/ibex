//! Test discovery — find test files based on manifests and filters.

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

use super::expectations::load_section_expectations;
use super::manifest::ResolvedManifest;
use super::types::{CompatOptions, RunMode, Section, TestEntry, TestPlan, TestStatus};

/// Discover all tests to run based on loaded manifests and CLI options.
pub fn discover_tests(
    compat_dir: &Path,
    manifests: &[ResolvedManifest],
    opts: &CompatOptions,
) -> Result<TestPlan> {
    let max_tier = opts.max_tier();
    let mut tests = Vec::new();

    for manifest in manifests {
        let section = manifest.section;
        let section_fixture_dir = compat_dir.join("fixtures").join(section.as_str());
        let section_test_dir = compat_dir.join(section.as_str());

        if manifest.modules.is_empty() {
            // No manifest modules defined — auto-discover from directories
            discover_section_auto(
                &section_test_dir,
                &section_fixture_dir,
                section,
                max_tier,
                opts,
                &mut tests,
            )?;
        } else {
            // Use manifest-defined modules
            for module in &manifest.modules {
                if module.skipped {
                    continue;
                }
                if module.tier > max_tier {
                    continue;
                }
                if let Some(ref filter_module) = opts.module {
                    if !module.name.contains(filter_module.as_str()) {
                        continue;
                    }
                }

                // For exact section (and any section with tests directly in
                // its directory rather than in fixtures/), search the section
                // test dir. For others, search in fixtures/.
                let search_dir = if section == Section::Exact {
                    &section_test_dir
                } else if section_fixture_dir.exists() {
                    &section_fixture_dir
                } else {
                    &section_test_dir
                };

                discover_module(search_dir, section, module, &mut tests)?;
            }
        }
    }

    // If --failed, filter to only previously failed tests
    if opts.failed {
        let results_path = compat_dir.join("results").join("latest.json");
        if results_path.exists() {
            let failed_ids = load_failed_test_ids(&results_path)?;
            tests.retain(|t| failed_ids.contains(&t.id));
        }
    }

    // If --test filters provided, keep only tests whose ID or name matches any filter
    if !opts.test_filter.is_empty() {
        tests.retain(|t| {
            opts.test_filter
                .iter()
                .any(|f| t.id.contains(f.as_str()) || t.name.contains(f.as_str()))
        });
    }

    // Apply CLI timeout override if provided
    if let Some(timeout_ms) = opts.timeout {
        for test in &mut tests {
            test.timeout_ms = timeout_ms;
        }
    }

    apply_expectation_statuses(compat_dir, &mut tests, opts.timeout)?;

    Ok(TestPlan { tests })
}

fn apply_expectation_statuses(
    compat_dir: &Path,
    tests: &mut [TestEntry],
    cli_timeout_ms: Option<u64>,
) -> Result<()> {
    let mut expectation_cache: HashMap<
        Section,
        HashMap<String, super::expectations::ExpectationEntry>,
    > = HashMap::new();

    for test in tests.iter_mut() {
        let entry = expectation_cache.entry(test.section).or_insert_with(|| {
            load_section_expectations(compat_dir, test.section)
                .map(|expectations| expectations.tests)
                .unwrap_or_default()
        });

        if let Some(expectation) = entry.get(&test.id) {
            if expectation.status == TestStatus::Skip {
                test.expected_status = Some(TestStatus::Skip);
            }
            if cli_timeout_ms.is_none() {
                if let Some(timeout_ms) = expectation.timeout_ms {
                    test.timeout_ms = timeout_ms;
                }
            }
        }
    }

    Ok(())
}

fn discover_section_auto(
    section_test_dir: &Path,
    section_fixture_dir: &Path,
    section: Section,
    max_tier: u8,
    opts: &CompatOptions,
    tests: &mut Vec<TestEntry>,
) -> Result<()> {
    // For exact section, look for .test.ts files directly
    if section == Section::Exact {
        discover_exact_tests(section_test_dir, max_tier, opts, tests)?;
        return Ok(());
    }

    // For other sections, look for test files in fixtures
    if !section_fixture_dir.exists() {
        return Ok(());
    }

    // Auto-discover by walking the fixture directory
    discover_fixture_dir(section_fixture_dir, section, "", 1, 6000, opts, tests)?;

    Ok(())
}

fn discover_exact_tests(
    dir: &Path,
    _max_tier: u8,
    opts: &CompatOptions,
    tests: &mut Vec<TestEntry>,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".test.ts") || name.ends_with(".test.js") {
                let module_name = name
                    .trim_end_matches(".test.ts")
                    .trim_end_matches(".test.js")
                    .to_string();

                if let Some(ref filter_module) = opts.module {
                    if !module_name.contains(filter_module.as_str()) {
                        continue;
                    }
                }

                tests.push(TestEntry {
                    id: format!("exact/{}/{}", module_name, name),
                    name: name.to_string(),
                    section: Section::Exact,
                    module: module_name,
                    file_path: path,
                    timeout_ms: 6000,
                    tier: 0,
                    run_mode: RunMode::ChildProcess,
                    expected_status: None,
                });
            }
        }
    }

    Ok(())
}

fn discover_module(
    fixture_dir: &Path,
    section: Section,
    module: &super::manifest::ResolvedModule,
    tests: &mut Vec<TestEntry>,
) -> Result<()> {
    for pattern in &module.include {
        let full_pattern = fixture_dir.join(pattern);
        let pattern_str = full_pattern.to_string_lossy();

        let Ok(entries) = glob::glob(&pattern_str) else {
            continue;
        };

        for path in entries.flatten() {
            if !path.is_file() {
                continue;
            }

            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            // Check exclude patterns
            let excluded = module.exclude.iter().any(|excl| {
                let excl_pattern = fixture_dir.join(excl);
                glob::Pattern::new(&excl_pattern.to_string_lossy())
                    .map(|p| p.matches_path(&path))
                    .unwrap_or(false)
            });

            if excluded {
                continue;
            }

            let rel = path.strip_prefix(fixture_dir).unwrap_or(&path);
            let id = format!(
                "{}/{}/{}",
                section.as_str(),
                module.name,
                rel.to_string_lossy()
            );

            tests.push(TestEntry {
                id,
                name,
                section,
                module: module.name.clone(),
                file_path: path,
                timeout_ms: module.timeout_ms,
                tier: module.tier,
                run_mode: module.run_mode,
                expected_status: None,
            });
        }
    }

    Ok(())
}

fn discover_fixture_dir(
    dir: &Path,
    section: Section,
    module_prefix: &str,
    tier: u8,
    timeout_ms: u64,
    opts: &CompatOptions,
    tests: &mut Vec<TestEntry>,
) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            let dir_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();

            // Skip hidden directories and common non-test dirs
            if dir_name.starts_with('.') || dir_name == "node_modules" || dir_name == "resources" {
                continue;
            }

            let module = if module_prefix.is_empty() {
                dir_name.clone()
            } else {
                format!("{}/{}", module_prefix, dir_name)
            };

            if let Some(ref filter_module) = opts.module {
                if !module.contains(filter_module.as_str())
                    && !filter_module.contains(module.as_str())
                {
                    continue;
                }
            }

            discover_fixture_dir(&path, section, &module, tier, timeout_ms, opts, tests)?;
        } else if is_test_file(&path) {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            let module = if module_prefix.is_empty() {
                "default".to_string()
            } else {
                module_prefix.to_string()
            };

            if let Some(ref filter_module) = opts.module {
                if !module.contains(filter_module.as_str()) {
                    continue;
                }
            }

            let base_dir = find_section_fixture_base(dir, section);
            let rel = path.strip_prefix(&base_dir).unwrap_or(&path);
            let id = format!("{}/{}/{}", section.as_str(), module, rel.to_string_lossy());

            tests.push(TestEntry {
                id,
                name,
                section,
                module,
                file_path: path,
                timeout_ms,
                tier,
                run_mode: RunMode::ChildProcess,
                expected_status: None,
            });
        }
    }

    Ok(())
}

fn is_test_file(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "js" | "ts" | "mjs" => {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Include test files but not helper/support files (unless they start with "test-")
            name.starts_with("test-")
                || name.ends_with(".test.js")
                || name.ends_with(".test.ts")
                || name.ends_with(".any.js")
        }
        _ => false,
    }
}

fn find_section_fixture_base(dir: &Path, _section: Section) -> std::path::PathBuf {
    // Walk up to find the fixtures/<section> directory
    let mut current = dir.to_path_buf();
    while current.pop() {
        if current.file_name().and_then(|n| n.to_str()) == Some("fixtures") {
            return current;
        }
    }
    dir.to_path_buf()
}

fn load_failed_test_ids(results_path: &Path) -> Result<std::collections::HashSet<String>> {
    use super::types::CompatResults;
    let content = std::fs::read_to_string(results_path)?;
    let results: CompatResults = serde_json::from_str(&content)?;
    let mut failed = std::collections::HashSet::new();

    for section_result in results.sections.values() {
        for module_result in section_result.modules.values() {
            for test in &module_result.tests {
                if matches!(
                    test.status,
                    super::types::TestStatus::Fail
                        | super::types::TestStatus::Timeout
                        | super::types::TestStatus::Crash
                ) {
                    failed.insert(test.id.clone());
                }
            }
        }
    }

    Ok(failed)
}
