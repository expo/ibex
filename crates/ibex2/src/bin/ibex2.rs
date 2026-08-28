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
    "usage: ibex2 run   <entry.js> [--grants <file>] [--budget-ms <n>] [--precompiled] [--no-compile]\n\
    \x20      ibex2 build <entry.js>\n\
     \n\
     run    Runs <entry.js>. Modules require() each other by relative path and\n\
     \x20      cannot escape the entry's directory. Each module receives only the\n\
     \x20      capabilities its grant manifest names; without --grants, nothing\n\
     \x20      is granted. Modules are compiled to bytecode and cached under\n\
     \x20      .ibex2/cache; --precompiled refuses to compile anything on demand,\n\
     \x20      and --no-compile falls back to loading source.\n\
     \n\
     build  Compiles the whole graph to bytecode ahead of time, so `run\n\
     \x20      --precompiled` has everything it needs. rules/RULES.md forbids\n\
     \x20      compiling at runtime what could be built ahead of it."
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("");
    if !matches!(command, "run" | "build") || args.len() < 2 {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }

    let entry = PathBuf::from(&args[1]);
    let mut grants_path: Option<PathBuf> = None;
    let mut budget_ms: u64 = 30_000;
    let mut precompiled_only = false;
    let mut compile = true;
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
            "--precompiled" => precompiled_only = true,
            "--no-compile" => compile = false,
            other => {
                eprintln!("unknown flag {other}\n\n{}", usage());
                return ExitCode::from(2);
            }
        }
    }

    let outcome = match command {
        "build" => build(&entry),
        _ => run(
            &entry,
            grants_path.as_deref(),
            budget_ms,
            compile,
            precompiled_only,
        ),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ibex2: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Where compiled modules live: beside the project, visible and deletable.
fn cache_dir(root: &Path) -> PathBuf {
    root.join(".ibex2/cache")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The engine these artifacts are built for.
fn engine_dir() -> PathBuf {
    match std::env::var("IBEX2_VANILLA_HERMES_DIR") {
        Ok(path) => PathBuf::from(path),
        Err(_) => repo_root().join("ios/Frameworks-vanilla"),
    }
}

/// A compiler bound to the installed engine's receipt, so artifacts built for
/// one engine are never found under another (LLP 0058.000.001 §5).
fn compiler_for(root: &Path, require_receipt: bool) -> Result<ibex2::bytecode::Compiler, String> {
    ibex2::bytecode::Compiler::discover_for_engine(
        &repo_root(),
        cache_dir(root),
        &engine_dir(),
        require_receipt,
    )
}

/// Compile the whole reachable graph ahead of time.
fn build(entry: &Path) -> Result<(), String> {
    let entry = entry
        .canonicalize()
        .map_err(|e| format!("cannot open {}: {e}", entry.display()))?;
    let root = entry
        .parent()
        .ok_or("entry has no directory")?
        .to_path_buf();
    let name = entry
        .file_name()
        .ok_or("entry has no file name")?
        .to_string_lossy()
        .into_owned();
    // A build produces artifacts others will trust, so it requires the receipt.
    let compiler = compiler_for(&root, true)?;

    // Walk from the entry, following require() and import as the loader would.
    // Compiling every .js under the root instead would build files nothing
    // imports.
    let mut queue = vec![format!("./{name}")];
    let mut seen = std::collections::BTreeSet::new();
    let mut edges: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut manifest = ibex2::bytecode::Manifest::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut built = 0usize;

    while let Some(specifier) = queue.pop() {
        if !seen.insert(specifier.clone()) {
            continue;
        }
        let path = root.join(specifier.trim_start_matches("./"));
        let source = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let wrapped = ibex2::loader::lower_and_wrap(&source)?;
        compiler
            .compile(&wrapped)
            .map_err(|e| format!("{specifier}: {e}"))?;
        // Recorded so the runtime finds this artifact without opening, reading,
        // or hashing the source again.
        manifest.insert(&specifier, &compiler.key(&wrapped));
        built += 1;

        // LLP 0064 §3.1: an importer writing `import { n }` snapshots, so a
        // reassignment of `n` is invisible to it. The divergence is silent;
        // this is where it stops being.
        for binding in ibex2::esm::mutable_exports(&source) {
            warnings.push(format!(
                "{specifier} exports `{binding}` and reassigns it. An importer writing \
                 `import {{ {binding} }}` will see a stale value; `import * as ns` reads \
                 through and is live (LLP 0064 §3.1)."
            ));
        }

        // Both module systems: import/export-from come from the parser,
        // require from a scan, because a require's specifier is an ordinary
        // call argument no module-syntax parse reports.
        let mut dependencies: Vec<(String, bool)> = ibex2::esm::dependencies(&source)
            .into_iter()
            .map(|dependency| (dependency, true))
            .collect();
        dependencies.extend(
            requires_in(&source)
                .into_iter()
                .map(|dependency| (dependency, true)),
        );
        // A literal dynamic import is worth building — otherwise it is missing
        // from the manifest and fails under --precompiled — but it is
        // CONDITIONAL where a static import is not, so a target that does not
        // exist is a warning rather than a build failure. Code that guards an
        // optional import is correct.
        dependencies.extend(
            ibex2::esm::dynamic_dependencies(&source)
                .into_iter()
                .map(|dependency| (dependency, false)),
        );

        for (dependency, required) in dependencies {
            match ibex2::loader::resolve(&root, &specifier, &dependency) {
                Ok(resolved) => {
                    if !required && !root.join(resolved.trim_start_matches("./")).exists() {
                        warnings.push(format!(
                            "{specifier} dynamically imports {dependency:?}, which does not \
                             exist. The call rejects at run time; it is not built."
                        ));
                        continue;
                    }
                    edges
                        .entry(specifier.clone())
                        .or_default()
                        .push(resolved.clone());
                    queue.push(resolved);
                }
                // A require() this scan cannot resolve is not a build failure:
                // it may be inside a branch that never runs, and the loader
                // will report it properly if it is ever reached.
                Err(_) => continue,
            }
        }
    }

    // LLP 0064 §3.2: a cycle observes partial exports rather than raising a
    // ReferenceError, so one that works today can start returning undefined
    // after an unrelated reordering. Reported here because the graph is already
    // in hand and nothing else in the system will ever mention it.
    for cycle in find_cycles(&edges) {
        warnings.push(format!(
            "import cycle: {}. Cycles resolve to partial exports rather than failing, \
             so this will not error if the order changes (LLP 0064 §3.2).",
            cycle.join(" -> ")
        ));
    }

    for warning in &warnings {
        eprintln!("ibex2: warning: {warning}");
    }

    manifest.write(&cache_dir(&root))?;
    println!("built {built} modules into {}", cache_dir(&root).display());
    Ok(())
}

/// Every import cycle in the graph, each reported once from its entry point.
fn find_cycles(edges: &std::collections::BTreeMap<String, Vec<String>>) -> Vec<Vec<String>> {
    let mut found = Vec::new();
    let mut reported = std::collections::BTreeSet::new();
    let mut visited = std::collections::BTreeSet::new();

    // Iterative depth-first search carrying its own path, so a deep graph
    // cannot overflow the stack and the cycle can be named rather than merely
    // detected.
    for start in edges.keys() {
        if visited.contains(start) {
            continue;
        }
        let mut stack = vec![(start.clone(), 0usize)];
        let mut path = vec![start.clone()];
        while let Some((node, index)) = stack.pop() {
            let children = edges.get(&node).map(Vec::as_slice).unwrap_or(&[]);
            if index < children.len() {
                stack.push((node.clone(), index + 1));
                let child = &children[index];
                if let Some(at) = path.iter().position(|seen| seen == child) {
                    let mut cycle: Vec<String> = path[at..].to_vec();
                    cycle.push(child.clone());
                    // Normalize so the same cycle found from two entry points
                    // is reported once.
                    let mut key: Vec<String> = cycle[..cycle.len() - 1].to_vec();
                    key.sort();
                    if reported.insert(key) {
                        found.push(cycle);
                    }
                    continue;
                }
                path.push(child.clone());
                stack.push((child.clone(), 0));
            } else {
                visited.insert(node);
                path.pop();
            }
        }
    }
    found
}

/// Find `require('...')` specifiers by scanning.
///
/// A scanner, not a parser: it can see a require inside a comment or a string
/// and will compile a module nothing imports. That is wasted work rather than a
/// wrong result. ES module specifiers come from the parser instead — see
/// `esm::dependencies`.
fn requires_in(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find("require(") {
        rest = &rest[at + "require(".len()..];
        let rest_trimmed = rest.trim_start();
        let quote = match rest_trimmed.chars().next() {
            Some(q @ ('\'' | '"')) => q,
            _ => continue,
        };
        let body = &rest_trimmed[1..];
        if let Some(end) = body.find(quote) {
            found.push(body[..end].to_string());
        }
    }
    found
}

fn run(
    entry: &Path,
    grants_path: Option<&Path>,
    budget_ms: u64,
    compile: bool,
    precompiled_only: bool,
) -> Result<(), String> {
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
    let compiler = if compile || precompiled_only {
        match compiler_for(&root, precompiled_only) {
            Ok(compiler) => Some(compiler),
            Err(message) if precompiled_only => return Err(message),
            // Without hermesc the runtime can still load source. That path is
            // forbidden for anything shippable (rules/RULES.md) and says so.
            Err(message) => {
                eprintln!("ibex2: {message}");
                eprintln!("ibex2: falling back to loading source; this compiles at runtime");
                None
            }
        }
    } else {
        None
    };
    rt.set_loader_with(&root, grants, compiler, precompiled_only);

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
