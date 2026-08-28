//! `ibex2` — run a JavaScript program.
//!
//! Deliberately small. LLP 0057 §5 observes that ibex 1 carries 137K lines of
//! CLI against a 152K-line runtime, and that `run`, `build`, and perhaps `repl`
//! is the whole surface a runtime needs. This is `run`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ibex2::engine::hermes::{DynamicCode, Hermes};
use ibex2::loader::ModuleGrants;

/// The intrinsic freeze from LLP 0062 §3/R4 — ~2 ms, before any module runs.
const HARDEN: &str = include_str!("../bindings/harden.js");

fn usage() -> &'static str {
    "usage: ibex2 run <entry.js> [--grants <file>] [--budget-ms <n>]\n\
     \n\
     Runs <entry.js>. Modules require() each other by relative path and cannot\n\
     escape the entry's directory. Each module receives only the capabilities\n\
     its grant manifest names; without --grants, nothing is granted."
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("run") || args.len() < 2 {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }

    let entry = PathBuf::from(&args[1]);
    let mut grants_path: Option<PathBuf> = None;
    let mut budget_ms: u64 = 30_000;
    let mut rest = args[2..].iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--grants" => match rest.next() {
                Some(path) => grants_path = Some(PathBuf::from(path)),
                None => {
                    eprintln!("--grants needs a file");
                    return ExitCode::from(2);
                }
            },
            "--budget-ms" => match rest.next().and_then(|v| v.parse().ok()) {
                Some(ms) => budget_ms = ms,
                None => {
                    eprintln!("--budget-ms needs a number");
                    return ExitCode::from(2);
                }
            },
            other => {
                eprintln!("unknown flag {other}\n\n{}", usage());
                return ExitCode::from(2);
            }
        }
    }

    match run(&entry, grants_path.as_deref(), budget_ms) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ibex2: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(entry: &Path, grants_path: Option<&Path>, budget_ms: u64) -> Result<(), String> {
    let entry = entry
        .canonicalize()
        .map_err(|e| format!("cannot open {}: {e}", entry.display()))?;
    let root = entry
        .parent()
        .ok_or_else(|| format!("{} has no directory", entry.display()))?
        .to_path_buf();
    let name = entry
        .file_name()
        .ok_or("entry has no file name")?
        .to_string_lossy()
        .into_owned();

    let grants = match grants_path {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            ModuleGrants::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?
        }
        // No manifest means no authority — not ambient authority. A program
        // that needs the network must say so.
        None => ModuleGrants::none(),
    };

    let mut rt = Hermes::new(DynamicCode::Closed).ok_or("could not create a runtime")?;
    if !rt.install_stdlib() {
        return Err("could not install the standard library".into());
    }
    rt.install_bindings().map_err(|e| e.0)?;
    rt.set_loader(&root, grants);

    // R4: intrinsics frozen after the standard library is installed and before
    // any module code runs.
    rt.eval(HARDEN).map_err(|e| e.0)?;

    // R5: assert what the global object carries, before running anything.
    let unexpected: Vec<String> = rt
        .global_names()
        .into_iter()
        .filter(|name| {
            !ibex2::loader::ALLOWED_GLOBALS.contains(&name.as_str())
                && !name.starts_with("__ibex2_")
                && !is_intrinsic(name)
        })
        .collect();
    if !unexpected.is_empty() {
        return Err(format!(
            "refusing to run: unexpected globals {unexpected:?} (LLP 0062 R1)"
        ));
    }

    rt.run_entry(&format!("./{name}")).map_err(|e| e.0)?;
    rt.run_to_quiescence(std::time::Duration::from_millis(budget_ms));

    for record in rt.drain_console() {
        match record.level {
            ibex2::stdlib::console::Level::Error | ibex2::stdlib::console::Level::Warn => {
                eprintln!("{}", record.message)
            }
            _ => println!("{}", record.message),
        }
    }
    Ok(())
}

/// Names the engine puts on the global object. Not a policy list — these are
/// ECMAScript's, and Ibex neither adds to nor removes from them.
fn is_intrinsic(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        // Static Hermes publishes its compiler-builtin namespace here.
        || name.starts_with('$')
        || matches!(
            name,
            "globalThis"
                | "undefined"
                | "NaN"
                | "Infinity"
                | "eval"
                | "isNaN"
                | "isFinite"
                | "parseInt"
                | "parseFloat"
                | "decodeURI"
                | "decodeURIComponent"
                | "encodeURI"
                | "encodeURIComponent"
                | "escape"
                | "unescape"
                | "print"
                | "gc"
                | "require"
        )
}
