//! Walk a project's module graph exactly as `ibex2 build` would — TypeScript
//! strip, ESM lowering, dependency scan, resolve — but compile nothing and
//! report every failure instead of stopping at the first.
//!
//! The measurement instrument behind LLP 0066: run it at an application's
//! entry and it says which modules cannot be lowered, which specifiers cannot
//! be resolved and by whom, which files have a platform variant the resolver
//! is ignoring, and which modules are boot-eager (reachable by static edges)
//! against lazy (reachable only through a dynamic `import()`).
//!
//!     cargo run -p ibex2 --example graph -- <root> <entry> [platform] [out-dir]
//!
//! With an out-dir, `eager.txt` and `lazy.txt` list the two sets, which is
//! what the API-usage counts in LLP 0066 §4 were taken over. No engine is
//! needed: this is the loader alone.
use ibex2::loader::{self, Root};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

const PLATFORM_SUFFIXES: &[&str] = &["agent", "android", "ios", "mac", "native", "tv", "web", "windows"];
const SCRIPT_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs"];

fn requires_in(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find("require(") {
        rest = &rest[at + "require(".len()..];
        let t = rest.trim_start();
        let quote = match t.chars().next() { Some(q @ ('\'' | '"')) => q, _ => continue };
        let body = &t[1..];
        if let Some(end) = body.find(quote) { found.push(body[..end].to_string()); }
    }
    found
}

/// A `.native.*` sibling that Exact's build would have selected instead.
fn shadowing_variant(root: &Path, resolved: &str) -> Option<String> {
    let path = root.join(resolved.trim_start_matches("./"));
    let file = path.file_name()?.to_string_lossy().into_owned();
    let stem_ext: Vec<&str> = file.rsplitn(2, '.').collect();
    if stem_ext.len() != 2 { return None; }
    let (ext, stem) = (stem_ext[0], stem_ext[1]);
    if !SCRIPT_EXTENSIONS.contains(&ext) { return None; }
    if PLATFORM_SUFFIXES.iter().any(|s| stem.ends_with(&format!(".{s}"))) { return None; }
    let dir = path.parent()?;
    for e in SCRIPT_EXTENSIONS {
        let candidate = dir.join(format!("{stem}.native.{e}"));
        if candidate.is_file() {
            return Some(candidate.strip_prefix(root).ok()?.to_string_lossy().into_owned());
        }
    }
    None
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let root_path = PathBuf::from(&args[1]).canonicalize().expect("root");
    let entry = PathBuf::from(&args[2]).canonicalize().expect("entry");
    let name = format!("./{}", entry.strip_prefix(&root_path).expect("entry under root").display());
    let root = Root::Declared(root_path.clone());
    let platform: Option<String> = args.get(3).cloned();

    let mut queue = VecDeque::from([name.clone()]);
    let mut seen = BTreeSet::new();
    // Reachable through static imports/requires alone: the boot-eager graph.
    let mut eager: BTreeSet<String> = BTreeSet::from([name]);
    let out_dir: Option<PathBuf> = args.get(4).map(PathBuf::from);
    let mut lowered_ok = 0usize;
    let mut bytes = 0usize;
    let mut ext_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut in_node_modules = 0usize;
    let mut read_errors: Vec<(String, String)> = Vec::new();
    let mut lower_errors: Vec<(String, String)> = Vec::new();
    // specifier -> [(importer, error)]
    let mut resolve_errors: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut dyn_unresolved: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut variants_shadowed: BTreeMap<String, (String, BTreeSet<String>)> = BTreeMap::new();

    while let Some(spec) = queue.pop_front() {
        if !seen.insert(spec.clone()) { continue; }
        let path = root_path.join(spec.trim_start_matches("./"));
        let source = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => { read_errors.push((spec.clone(), e.to_string())); continue; }
        };
        bytes += source.len();
        if spec.contains("/node_modules/") { in_node_modules += 1; }
        let ext = path.extension().map(|e| e.to_string_lossy().into_owned()).unwrap_or_default();
        *ext_counts.entry(ext).or_default() += 1;

        let javascript = match loader::to_javascript(&source, &spec) {
            Ok(j) => j,
            Err(e) => { lower_errors.push((spec.clone(), format!("strip: {e}"))); continue; }
        };
        match loader::lower_and_wrap(&source, &spec) {
            Ok(_) => lowered_ok += 1,
            Err(e) => lower_errors.push((spec.clone(), format!("lower: {e}"))),
        }

        let mut deps: Vec<(String, bool)> = ibex2::esm::dependencies(&javascript, &spec).into_iter().map(|d| (d, true)).collect();
        deps.extend(requires_in(&javascript).into_iter().map(|d| (d, true)));
        deps.extend(ibex2::esm::dynamic_dependencies(&javascript, &spec).into_iter().map(|d| (d, false)));

        for (dep, required) in deps {
            let outcome = loader::resolve_for(&root, platform.as_deref(), &spec, &dep).and_then(|resolved| {
                if root_path.join(resolved.trim_start_matches("./")).is_file() { Ok(resolved) }
                else { Err(format!("resolved to {resolved}, which does not exist")) }
            });
            match outcome {
                Ok(resolved) => {
                    if let Some(variant) = shadowing_variant(&root_path, &resolved) {
                        let entry = variants_shadowed.entry(resolved.clone()).or_insert_with(|| (variant, BTreeSet::new()));
                        entry.1.insert(spec.clone());
                    }
                    if required && eager.contains(&spec) { eager.insert(resolved.clone()); }
                    queue.push_back(resolved);
                }
                Err(e) => {
                    let bucket = if required { &mut resolve_errors } else { &mut dyn_unresolved };
                    bucket.entry(dep.clone()).or_default().push((spec.clone(), e));
                }
            }
        }
    }

    // A second pass: eagerness propagates along static edges, and the queue
    // order above may have visited a module lazily before its static importer.
    let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for spec in &seen {
        let path = root_path.join(spec.trim_start_matches("./"));
        let Ok(source) = std::fs::read_to_string(&path) else { continue };
        let Ok(javascript) = loader::to_javascript(&source, spec) else { continue };
        let mut deps: Vec<String> = ibex2::esm::dependencies(&javascript, spec);
        deps.extend(requires_in(&javascript));
        for dep in deps {
            if let Ok(resolved) = loader::resolve_for(&root, platform.as_deref(), spec, &dep) {
                edges.entry(spec.clone()).or_default().push(resolved);
            }
        }
    }
    loop {
        let before = eager.len();
        let additions: Vec<String> = eager.iter().flat_map(|s| edges.get(s).cloned().unwrap_or_default()).collect();
        eager.extend(additions);
        if eager.len() == before { break; }
    }
    if let Some(dir) = &out_dir {
        std::fs::create_dir_all(dir).unwrap();
        let eager_list: Vec<&String> = seen.iter().filter(|s| eager.contains(*s)).collect();
        let lazy_list: Vec<&String> = seen.iter().filter(|s| !eager.contains(*s)).collect();
        std::fs::write(dir.join("eager.txt"), eager_list.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n")).unwrap();
        std::fs::write(dir.join("lazy.txt"), lazy_list.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n")).unwrap();
    }
    println!("== graph reached from entry ==");
    println!("boot-eager (static edges only): {}   lazy (only via dynamic import): {}", eager.iter().filter(|s| seen.contains(*s)).count(), seen.len() - eager.iter().filter(|s| seen.contains(*s)).count());
    println!("modules: {}  ({} under node_modules)  bytes: {}  lowered ok: {}", seen.len(), in_node_modules, bytes, lowered_ok);
    println!("by extension: {:?}", ext_counts);
    println!();
    println!("== read errors: {} ==", read_errors.len());
    for (s, e) in &read_errors { println!("  {s}: {e}"); }
    println!();
    println!("== strip/lower errors: {} ==", lower_errors.len());
    for (s, e) in &lower_errors { println!("  {s}: {e}"); }
    println!();
    println!("== unresolvable static imports/requires: {} distinct specifiers ==", resolve_errors.len());
    for (dep, sites) in &resolve_errors {
        println!("  {dep}  [{} importer(s)]  e.g. {} -> {}", sites.len(), sites[0].0, sites[0].1);
    }
    println!();
    println!("== unresolvable dynamic imports: {} distinct specifiers ==", dyn_unresolved.len());
    for (dep, sites) in &dyn_unresolved {
        println!("  {dep}  [{} importer(s)]  e.g. {} -> {}", sites.len(), sites[0].0, sites[0].1);
    }
    println!();
    println!("== platform variants ignored (.native sibling exists, unsuffixed file selected): {} ==", variants_shadowed.len());
    for (resolved, (variant, importers)) in &variants_shadowed {
        println!("  {resolved} -> should be {variant}  [{} importer(s)]", importers.len());
    }
}
