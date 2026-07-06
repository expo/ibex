//! Result formatting, saving, and web report serving.

use anyhow::Result;
use std::path::Path;

use super::types::*;

/// Print the final summary table to stderr.
pub fn print_summary(results: &CompatResults) {
    eprintln!();
    eprintln!("  \x1b[1;32mEXACT COMPATIBILITY RESULTS\x1b[0m");
    eprintln!();
    eprintln!(
        "  {:<16} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "Section", "Pass", "Fail", "Skip", "Total", "Score"
    );
    eprintln!("  {}", "\u{2500}".repeat(60));

    for section in Section::all() {
        if let Some(section_result) = results.sections.get(section) {
            if section_result.total == 0 {
                continue;
            }
            let score = section_result.score_pct();
            let color = if score >= 95.0 {
                "\x1b[32m" // green
            } else if score >= 80.0 {
                "\x1b[33m" // yellow
            } else {
                "\x1b[31m" // red
            };

            eprintln!(
                "  {}{:<16}\x1b[0m {:>8} {:>8} {:>8} {:>8} {:>7.1}%",
                color,
                section.display_name(),
                section_result.pass,
                section_result.fail,
                section_result.skip,
                section_result.total,
                score,
            );
        }
    }

    eprintln!("  {}", "\u{2500}".repeat(60));
    eprintln!(
        "  {:<16} {:>8} {:>8} {:>8} {:>8} {:>7.1}%",
        "\x1b[1mTotal\x1b[0m",
        results.total_pass(),
        results.total_fail(),
        results.total_skip(),
        results.total_tests(),
        results.overall_score_pct(),
    );
    eprintln!();

    // Print duration
    let secs = results.duration_ms / 1000;
    let mins = secs / 60;
    let remaining_secs = secs % 60;
    if mins > 0 {
        eprintln!("  Completed in {}m {}s", mins, remaining_secs);
    } else {
        eprintln!("  Completed in {}s", remaining_secs);
    }
    eprintln!();
}

/// Save results to the history directory.
pub fn save_results(compat_dir: &Path, results: &CompatResults) -> Result<()> {
    let results_dir = compat_dir.join("results");
    std::fs::create_dir_all(&results_dir)?;
    std::fs::create_dir_all(results_dir.join("history"))?;

    // Save as latest.json
    let latest_path = results_dir.join("latest.json");
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(&latest_path, format!("{}\n", json))?;

    // Save to history with timestamp
    let timestamp = results.timestamp.replace(':', "-");
    let history_path = results_dir
        .join("history")
        .join(format!("{}.json", timestamp));
    std::fs::write(&history_path, format!("{}\n", json))?;

    Ok(())
}

/// Serve the web report on a local HTTP server.
pub fn serve_report(compat_dir: &Path) -> Result<()> {
    let web_dir = compat_dir.join("runner").join("web");
    if !web_dir.join("index.html").exists() {
        eprintln!(
            "Web UI not found at {}. Skipping report.",
            web_dir.display()
        );
        eprintln!(
            "Results saved to {}/results/latest.json",
            compat_dir.display()
        );
        return Ok(());
    }

    eprintln!(
        "\x1b[32m\u{2713}\x1b[0m Web report: file://{}",
        web_dir.join("index.html").display()
    );
    Ok(())
}
