//! Module loader for ESM and CommonJS.
//!
//! This provides a minimal resolver and loader with `exact:` builtins.
//! Node-style package resolution and full ESM/CJS interop are implemented
//! incrementally (see TODOs).

pub mod transpile;

use anyhow::{anyhow, Context, Result};
use oxc_resolver::{ModuleType, ResolveOptions, Resolver};
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Esm,
    CommonJs,
    Json,
    Builtin,
}

#[derive(Debug, Clone)]
pub struct ResolvedModule {
    pub id: String,
    pub kind: ModuleKind,
    pub path: Option<PathBuf>,
    pub source: Option<String>,
}

pub struct ModuleLoader {
    builtins: HashMap<String, String>,
    resolver: Resolver,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct BuiltinManifestRegistration {
    specifier: &'static str,
    source_key: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BuiltinManifestDebugEntry {
    pub specifier: &'static str,
    pub source_key: &'static str,
    pub source_kind: &'static str,
    pub source_path: Option<&'static str>,
    pub platform_availability: &'static str,
    pub module_builtin: bool,
    pub bundle_external: bool,
}

include!(concat!(env!("OUT_DIR"), "/builtin_manifest.generated.rs"));

impl Default for ModuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleLoader {
    pub fn new() -> Self {
        let builtins = build_builtin_registry(BUILTIN_MANIFEST_REGISTRATIONS);

        let options = ResolveOptions {
            extensions: vec![
                ".js".into(),
                ".cjs".into(),
                ".mjs".into(),
                ".ts".into(),
                ".tsx".into(),
                ".jsx".into(),
                ".mts".into(),
                ".cts".into(),
                ".json".into(),
            ],
            condition_names: vec![
                "node".into(),
                "require".into(),
                "import".into(),
                "default".into(),
            ],
            // TS NodeNext convention: `./x.js` in TS sources refers to `./x.ts`
            // on disk. Real `.js` files keep priority, mirroring Vite's
            // resolution on the web side. @ref LLP 0004#the-oxc_resolver-configuration
            extension_alias: vec![
                (
                    ".js".into(),
                    vec![".js".into(), ".ts".into(), ".tsx".into()],
                ),
                (".mjs".into(), vec![".mjs".into(), ".mts".into()]),
                (".cjs".into(), vec![".cjs".into(), ".cts".into()]),
            ],
            ..ResolveOptions::default()
        };

        Self {
            builtins,
            resolver: Resolver::new(options),
        }
    }

    pub fn resolve(&self, specifier: &str, referrer: Option<&Path>) -> Result<ResolvedModule> {
        let meta = self.resolve_meta(specifier, referrer)?;
        self.load_source(meta)
    }

    pub fn resolve_meta(&self, specifier: &str, referrer: Option<&Path>) -> Result<ResolvedModule> {
        let specifier = specifier.trim();
        if specifier.is_empty() {
            return Err(anyhow!("Empty module specifier"));
        }
        if specifier.starts_with('#') {
            if let Some(referrer_path) = referrer {
                if let Some(module) = self.resolve_package_import(specifier, referrer_path) {
                    return Ok(module);
                }
            }
            return Err(anyhow!("Failed to resolve package import {}", specifier));
        }
        if let Some(source) = self.builtins.get(specifier) {
            return Ok(ResolvedModule {
                id: specifier.to_string(),
                kind: ModuleKind::Builtin,
                path: None,
                source: Some(source.clone()),
            });
        }

        if specifier.starts_with("exact:") {
            return Err(anyhow!("Unknown exact builtin: {}", specifier));
        }

        if specifier.starts_with("node:") {
            return Err(anyhow!("Unsupported node builtin: {}", specifier));
        }

        self.resolve_with_oxc(specifier, referrer)
    }

    fn resolve_package_import(&self, specifier: &str, referrer: &Path) -> Option<ResolvedModule> {
        let package_root = find_package_root(referrer)?;
        let manifest_path = package_root.join("package.json");
        let manifest = read_package_manifest(&manifest_path).ok()?;
        let imports = manifest.get("imports")?.as_object()?;

        let raw_target = resolve_package_import_target(specifier, imports)?;
        let target_path = normalize_import_target(&package_root, package_root.join(raw_target))?;

        Some(ResolvedModule {
            id: target_path.to_string_lossy().to_string(),
            kind: module_kind_from_path(&target_path),
            path: Some(target_path),
            source: None,
        })
    }

    pub fn load_source(&self, mut module: ResolvedModule) -> Result<ResolvedModule> {
        if module.source.is_some() {
            return Ok(module);
        }
        let path = module
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("Module path missing"))?;
        let source = self
            .load_module_source(path)
            .with_context(|| format!("Failed to read module {}", path.display()))?;
        module.source = Some(source);
        Ok(module)
    }

    fn load_module_source(&self, path: &Path) -> Result<String> {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read module {}", path.display()))?;
        if Self::needs_transpile(path) || Self::needs_js_downlevel(path, &source) {
            let target = Self::transpile_target_for_source(&source);
            return self.transpile_module(path, target);
        }
        Ok(source)
    }

    fn needs_transpile(path: &Path) -> bool {
        path.extension()
            .and_then(OsStr::to_str)
            .map(|ext| matches!(ext, "ts" | "tsx" | "jsx" | "mts" | "cts"))
            .unwrap_or(false)
    }

    fn needs_js_downlevel(path: &Path, source: &str) -> bool {
        path.extension()
            .and_then(OsStr::to_str)
            .map(|ext| matches!(ext, "js" | "mjs" | "cjs"))
            .unwrap_or(false)
            && Self::source_needs_downlevel(source)
    }

    fn js_file_needs_downlevel(path: &Path) -> bool {
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(_) => return false,
        };
        Self::needs_js_downlevel(path, &source)
    }

    fn source_needs_downlevel(source: &str) -> bool {
        Self::source_needs_async_downlevel(source)
            || Self::source_needs_for_of_scoping_fix(source)
            || Self::source_needs_loop_scope_downlevel(source)
    }

    fn source_needs_async_downlevel(source: &str) -> bool {
        source.contains("async function*")
            || source.contains("async function *")
            || source.contains("async*")
            || source.contains("async *")
            || source.contains("for await")
            || source.contains("await using")
            || source.starts_with("using ")
            || source.contains("\nusing ")
            || source.contains("\n  using ")
            || source.contains("\n    using ")
    }

    fn scan_block_scoped_loop_closures<F>(source: &str, mut matcher: F) -> bool
    where
        F: FnMut(usize, bool, bool, bool, bool) -> bool,
    {
        fn skip_ws_and_comments(bytes: &[u8], mut idx: usize) -> usize {
            while idx < bytes.len() {
                if bytes[idx].is_ascii_whitespace() {
                    idx += 1;
                    continue;
                }
                if bytes[idx] == b'/' && bytes.get(idx + 1) == Some(&b'/') {
                    idx += 2;
                    while idx < bytes.len() && bytes[idx] != b'\n' {
                        idx += 1;
                    }
                    continue;
                }
                if bytes[idx] == b'/' && bytes.get(idx + 1) == Some(&b'*') {
                    idx += 2;
                    while idx + 1 < bytes.len() && !(bytes[idx] == b'*' && bytes[idx + 1] == b'/') {
                        idx += 1;
                    }
                    idx = (idx + 2).min(bytes.len());
                    continue;
                }
                break;
            }
            idx
        }

        fn scan_balanced_region(bytes: &[u8], start: usize, open: u8, close: u8) -> Option<usize> {
            let mut depth = 1usize;
            let mut idx = start + 1;
            let mut in_single = false;
            let mut in_double = false;
            let mut in_template = false;
            let mut in_line_comment = false;
            let mut in_block_comment = false;
            let mut escaped = false;

            while idx < bytes.len() {
                let ch = bytes[idx];
                let next = bytes.get(idx + 1).copied();

                if in_line_comment {
                    if ch == b'\n' {
                        in_line_comment = false;
                    }
                    idx += 1;
                    continue;
                }

                if in_block_comment {
                    if ch == b'*' && next == Some(b'/') {
                        in_block_comment = false;
                        idx += 2;
                    } else {
                        idx += 1;
                    }
                    continue;
                }

                if escaped {
                    escaped = false;
                    idx += 1;
                    continue;
                }

                if in_single {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'\'' {
                        in_single = false;
                    }
                    idx += 1;
                    continue;
                }

                if in_double {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'"' {
                        in_double = false;
                    }
                    idx += 1;
                    continue;
                }

                if in_template {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'`' {
                        in_template = false;
                    }
                    idx += 1;
                    continue;
                }

                if ch == b'/' && next == Some(b'/') {
                    in_line_comment = true;
                    idx += 2;
                    continue;
                }

                if ch == b'/' && next == Some(b'*') {
                    in_block_comment = true;
                    idx += 2;
                    continue;
                }

                if ch == b'\'' {
                    in_single = true;
                    idx += 1;
                    continue;
                }

                if ch == b'"' {
                    in_double = true;
                    idx += 1;
                    continue;
                }

                if ch == b'`' {
                    in_template = true;
                    idx += 1;
                    continue;
                }

                if ch == open {
                    depth += 1;
                } else if ch == close {
                    depth -= 1;
                    if depth == 0 {
                        return Some(idx);
                    }
                }

                idx += 1;
            }

            None
        }

        let bytes = source.as_bytes();
        let mut idx = 0;

        while idx + 3 <= bytes.len() {
            if &bytes[idx..idx + 3] != b"for" {
                idx += 1;
                continue;
            }

            if idx > 0 {
                let prev = bytes[idx - 1];
                if prev == b'_' || prev.is_ascii_alphanumeric() {
                    idx += 3;
                    continue;
                }
            }

            let mut cursor = idx + 3;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor >= bytes.len() || bytes[cursor] != b'(' {
                idx += 3;
                continue;
            }

            let mut paren_depth = 1usize;
            let mut header_end = None;
            let mut semicolons = 0usize;
            let mut in_single = false;
            let mut in_double = false;
            let mut in_template = false;
            let mut in_line_comment = false;
            let mut in_block_comment = false;
            let mut escaped = false;
            let mut scan = cursor + 1;

            while scan < bytes.len() {
                let ch = bytes[scan];
                let next = bytes.get(scan + 1).copied();

                if in_line_comment {
                    if ch == b'\n' {
                        in_line_comment = false;
                    }
                    scan += 1;
                    continue;
                }

                if in_block_comment {
                    if ch == b'*' && next == Some(b'/') {
                        in_block_comment = false;
                        scan += 2;
                    } else {
                        scan += 1;
                    }
                    continue;
                }

                if escaped {
                    escaped = false;
                    scan += 1;
                    continue;
                }

                if in_single {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'\'' {
                        in_single = false;
                    }
                    scan += 1;
                    continue;
                }

                if in_double {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'"' {
                        in_double = false;
                    }
                    scan += 1;
                    continue;
                }

                if in_template {
                    if ch == b'\\' {
                        escaped = true;
                    } else if ch == b'`' {
                        in_template = false;
                    }
                    scan += 1;
                    continue;
                }

                if ch == b'/' && next == Some(b'/') {
                    in_line_comment = true;
                    scan += 2;
                    continue;
                }

                if ch == b'/' && next == Some(b'*') {
                    in_block_comment = true;
                    scan += 2;
                    continue;
                }

                if ch == b'\'' {
                    in_single = true;
                    scan += 1;
                    continue;
                }

                if ch == b'"' {
                    in_double = true;
                    scan += 1;
                    continue;
                }

                if ch == b'`' {
                    in_template = true;
                    scan += 1;
                    continue;
                }

                if ch == b'(' {
                    paren_depth += 1;
                } else if ch == b')' {
                    paren_depth -= 1;
                    if paren_depth == 0 {
                        header_end = Some(scan);
                        break;
                    }
                } else if ch == b';' && paren_depth == 1 {
                    semicolons += 1;
                }

                scan += 1;
            }

            if let Some(end) = header_end {
                let header = source[cursor + 1..end].trim_start();
                let has_block_scoped_loop_binding = header.starts_with("let ")
                    || header.starts_with("let\t")
                    || header.starts_with("let[")
                    || header.starts_with("let{")
                    || header.starts_with("const ")
                    || header.starts_with("const\t")
                    || header.starts_with("const[")
                    || header.starts_with("const{");

                if has_block_scoped_loop_binding {
                    let body_start = skip_ws_and_comments(bytes, end + 1);
                    let body_end = if body_start < bytes.len() && bytes[body_start] == b'{' {
                        scan_balanced_region(bytes, body_start, b'{', b'}')
                            .map(|idx| idx + 1)
                            .unwrap_or(bytes.len())
                    } else {
                        let mut body_end = body_start;
                        while body_end < bytes.len() && bytes[body_end] != b';' {
                            body_end += 1;
                        }
                        if body_end < bytes.len() {
                            body_end += 1;
                        }
                        body_end
                    };
                    let body = &source[body_start..body_end];
                    let captures_loop_binding = body.contains("=>")
                        || body.contains("function")
                        || body.contains("class ")
                        || body.contains("class\n");
                    let is_for_of = semicolons < 2
                        && (header.contains(" of ")
                            || header.contains(" of\t")
                            || header.contains("\tof "));
                    let is_for_of_or_in = semicolons < 2
                        && (is_for_of
                            || header.contains(" in ")
                            || header.contains(" in\t")
                            || header.contains("\tin "));
                    let has_unsafe_for_of_control_flow = body.contains("continue")
                        || body.contains("break")
                        || body.contains("return");

                    if matcher(
                        semicolons,
                        captures_loop_binding,
                        is_for_of,
                        is_for_of_or_in,
                        has_unsafe_for_of_control_flow,
                    ) {
                        return true;
                    }
                }
                idx = end + 1;
                continue;
            }

            idx = cursor + 1;
        }

        false
    }

    fn source_needs_for_of_scoping_fix(source: &str) -> bool {
        Self::scan_block_scoped_loop_closures(
            source,
            |_, captures_loop_binding, is_for_of, _, _| captures_loop_binding && is_for_of,
        )
    }

    fn source_needs_loop_scope_downlevel(source: &str) -> bool {
        Self::scan_block_scoped_loop_closures(
            source,
            |semicolons,
             captures_loop_binding,
             _,
             is_for_of_or_in,
             has_unsafe_for_of_control_flow| {
                captures_loop_binding
                    && (semicolons >= 2 || (is_for_of_or_in && has_unsafe_for_of_control_flow))
            },
        )
    }

    fn transpile_target_for_source(source: &str) -> &'static str {
        if Self::source_needs_loop_scope_downlevel(source) {
            "es5"
        } else {
            "es2015"
        }
    }

    fn transpile_module(&self, path: &Path, target: &str) -> Result<String> {
        let cache_key = module_cache_key(path, target)?;
        let cache_dir = transpile_cache_dir()?;
        std::fs::create_dir_all(&cache_dir).with_context(|| {
            format!(
                "Failed to create transpile cache directory {}",
                cache_dir.display()
            )
        })?;

        let output = cache_dir.join(format!("{cache_key}.js"));
        if should_rebuild_output(path, &output)? {
            run_transpile_command(path, &output, target)?;
        }

        std::fs::read_to_string(&output)
            .with_context(|| format!("Failed to read transpiled module {}", output.display()))
    }

    fn resolve_with_oxc(&self, specifier: &str, referrer: Option<&Path>) -> Result<ResolvedModule> {
        let base_dir = if let Some(path) = referrer {
            let resolved = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(path)
            };

            if resolved.is_dir() {
                resolved
            } else if resolved.is_file() {
                resolved
                    .parent()
                    .map(|parent| parent.to_path_buf())
                    .unwrap_or(resolved)
            } else {
                let is_probably_file = resolved
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| matches!(ext, "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx" | "json"))
                    .unwrap_or(false);
                if is_probably_file {
                    resolved
                        .parent()
                        .map(|parent| parent.to_path_buf())
                        .unwrap_or(resolved)
                } else {
                    resolved
                }
            }
        } else {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        };

        let resolution = match self.resolver.resolve(&base_dir, specifier) {
            Ok(resolution) => resolution,
            Err(err) => {
                // Native hosts pass referrer-relative entry paths without a
                // leading "./" (e.g. "packages/ibex-runtime-js/src/native"),
                // which Node-style resolution treats as bare package
                // specifiers. If the path exists on disk relative to the
                // referrer, retry as an explicit relative specifier so
                // directory imports still land on index.*.
                // @ref LLP 0004#resolution-order
                let path_like = !specifier.starts_with('.')
                    && !Path::new(specifier).is_absolute()
                    && base_dir.join(specifier).exists();
                if path_like {
                    self.resolver
                        .resolve(&base_dir, &format!("./{specifier}"))
                        .with_context(|| format!("Failed to resolve module {}", specifier))?
                } else {
                    return Err(err)
                        .with_context(|| format!("Failed to resolve module {}", specifier));
                }
            }
        };

        let mut kind = match resolution.module_type() {
            Some(ModuleType::Module) => ModuleKind::Esm,
            Some(ModuleType::CommonJs) => ModuleKind::CommonJs,
            Some(ModuleType::Json) => ModuleKind::Json,
            Some(ModuleType::Wasm) | Some(ModuleType::Addon) => ModuleKind::CommonJs,
            None => ModuleKind::CommonJs,
        };
        // Force JSON kind for .json files regardless of what OXC reports,
        // so they get parsed with JSON.parse() instead of new Function().
        if resolution.full_path().extension().and_then(|e| e.to_str()) == Some("json") {
            kind = ModuleKind::Json;
        }
        if kind == ModuleKind::Esm
            && (Self::needs_transpile(&resolution.full_path())
                || Self::js_file_needs_downlevel(&resolution.full_path()))
        {
            kind = ModuleKind::CommonJs;
        }

        let full_path = resolution.full_path().to_path_buf();
        Ok(ResolvedModule {
            id: full_path.to_string_lossy().to_string(),
            kind,
            path: Some(full_path),
            source: None,
        })
    }
}

fn read_package_manifest(path: &Path) -> Result<Value> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read package manifest {}", path.display()))?;
    let manifest: Value = serde_json::from_str(&contents)
        .with_context(|| format!("Invalid package manifest {}", path.display()))?;
    Ok(manifest)
}

fn find_package_root(start: &Path) -> Option<PathBuf> {
    let mut current = if start.is_file() {
        start.parent()?.to_path_buf()
    } else {
        start.to_path_buf()
    };

    loop {
        if current.join("package.json").exists() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

fn pick_package_import_path(value: &Value, subpath: Option<&str>) -> Option<String> {
    match value {
        Value::String(target) => {
            if let Some(subpath) = subpath {
                if target.contains('*') {
                    return Some(target.replacen('*', subpath, 1));
                }
            }
            Some(target.to_string())
        }
        Value::Object(map) => {
            for condition in ["node", "default", "import", "require"] {
                if let Some(condition_target) = map.get(condition) {
                    if let Some(path) = pick_package_import_path(condition_target, subpath) {
                        return Some(path);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn resolve_package_import_target(
    specifier: &str,
    imports: &serde_json::Map<String, Value>,
) -> Option<String> {
    if let Some(value) = imports.get(specifier) {
        if let Some(path) = pick_package_import_path(value, None) {
            return Some(path);
        }
    }

    for (key, value) in imports {
        if !key.ends_with("/*") {
            continue;
        }
        let prefix = &key[..key.len() - 2];
        if !specifier.starts_with(prefix) {
            continue;
        }
        let subpath = specifier[prefix.len()..].trim_start_matches('/');
        if let Some(path) = pick_package_import_path(value, Some(subpath)) {
            return Some(path);
        }
    }

    None
}

fn normalize_import_target(base: &Path, target: PathBuf) -> Option<PathBuf> {
    let normalized = if target.is_absolute() {
        target
    } else {
        base.join(target)
    };

    if normalized.exists() {
        return Some(normalized);
    }
    if normalized.extension().is_none() {
        for ext in ["js", "cjs", "mjs", "ts", "tsx", "jsx", "json"].iter() {
            let candidate = normalized.with_extension(ext);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn module_kind_from_path(path: &Path) -> ModuleKind {
    match path
        .extension()
        .and_then(OsStr::to_str)
        .map(|ext| ext.to_ascii_lowercase())
    {
        Some(ext) if matches!(ext.as_str(), "mjs" | "ts" | "tsx" | "jsx") => ModuleKind::Esm,
        Some(ext) if ext == "json" => ModuleKind::Json,
        _ => ModuleKind::CommonJs,
    }
}

fn module_cache_key(path: &Path, target: &str) -> Result<String> {
    let mut hasher = DefaultHasher::new();
    "loader-transpile-v13-engine-tagged-runtime-transform".hash(&mut hasher);
    target.hash(&mut hasher);
    let cache_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    cache_path.hash(&mut hasher);
    if let Ok(meta) = std::fs::metadata(path) {
        meta.len().hash(&mut hasher);
        if let Ok(modified) = meta.modified() {
            if let Ok(duration) = modified.duration_since(SystemTime::UNIX_EPOCH) {
                duration.as_nanos().hash(&mut hasher);
            }
        }
    }
    transpile_tooling_hash()?.hash(&mut hasher);
    Ok(format!("{:x}", hasher.finish()))
}

/// Hash of the transpile tooling scripts, computed once per process.
/// The scripts don't change underneath a running loader, and re-reading
/// both files for every module load showed up in runtime-loader profiling.
/// @ref LLP 0007#runtime-module-loading
fn transpile_tooling_hash() -> Result<u64> {
    // @ref LLP 0007#proposal - the in-process engine is part of the cache key
    // so the SWC fallback and Oxc candidate never share output.
    // Only the explicit subprocess override hashes a repo script.
    if std::env::var("EXACT_TRANSPILE_SCRIPT").is_ok() {
        let script = transpile_script_path()?;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&std::fs::read(&script).unwrap_or_default(), &mut hasher);
        return Ok(std::hash::Hasher::finish(&hasher));
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(transpile::selected_engine_cache_tag()?, &mut hasher);
    Ok(std::hash::Hasher::finish(&hasher))
}

fn transpile_cache_dir() -> Result<PathBuf> {
    let mut dir = crate::runtime_cache_dir()?;
    dir.push("typescript");
    dir.push("loader");
    if let Err(err) = ensure_transpile_cache_dir(&dir) {
        let fallback = std::env::temp_dir()
            .join("exact")
            .join("typescript")
            .join("loader");
        if let Err(fallback_err) = ensure_transpile_cache_dir(&fallback) {
            return Err(anyhow::anyhow!(
                "Failed to create transpile cache directory {} ({}) and fallback {} ({})",
                dir.display(),
                err,
                fallback.display(),
                fallback_err
            ));
        }
        Ok(fallback)
    } else {
        Ok(dir)
    }
}

fn ensure_transpile_cache_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| {
        format!(
            "Failed to create transpile cache directory {}",
            dir.display()
        )
    })?;

    let probe_path = dir.join(".exact-transpile-cache-write");
    match std::fs::File::create(&probe_path) {
        Ok(handle) => {
            drop(handle);
            std::fs::remove_file(&probe_path).with_context(|| {
                format!("Failed to clean up probe file {}", probe_path.display())
            })?;
            Ok(())
        }
        Err(err) => Err(anyhow::anyhow!(
            "Transpile cache directory {} is not writable: {}",
            dir.display(),
            err
        )),
    }
}

fn should_rebuild_output(path: &Path, output: &Path) -> Result<bool> {
    if !output.exists() {
        return Ok(true);
    }

    let output_meta = match std::fs::metadata(output) {
        Ok(meta) => meta,
        Err(_) => return Ok(true),
    };
    let output_time = output_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);

    let source_meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return Ok(true),
    };
    let source_time = source_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);

    Ok(source_time > output_time)
}

fn run_transpile_command(entry: &Path, output: &Path, target: &str) -> Result<()> {
    // Explicit override keeps a custom transpiler-script escape hatch;
    // everything else is in-process per LLP 0007, so TypeScript works
    // standalone without a Bun/Node subprocess.
    if std::env::var("EXACT_TRANSPILE_SCRIPT").is_ok() {
        return run_transpile_subprocess(entry, output, target);
    }

    let code = transpile::transpile_file_to_cjs(entry, target)?;

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    // tmp + rename so a concurrent reader never sees a half-written module.
    let tmp = output.with_extension("tmp");
    std::fs::write(&tmp, code).with_context(|| format!("Failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, output)
        .with_context(|| format!("Failed to publish {}", output.display()))?;
    Ok(())
}

fn run_transpile_subprocess(entry: &Path, output: &Path, target: &str) -> Result<()> {
    let (runner, runner_name) = find_js_runner()?;
    let script = transpile_script_path()?;

    let status = Command::new(&runner)
        .arg(script)
        .arg("--entry")
        .arg(entry)
        .arg("--out")
        .arg(output)
        .arg("--target")
        .arg(target)
        .status()
        .with_context(|| format!("Failed to run {} for {}", runner_name, entry.display()))?;

    if !status.success() {
        anyhow::bail!(
            "TypeScript transpile failed with status {} for {}",
            status,
            entry.display()
        );
    }

    if !output.exists() {
        anyhow::bail!(
            "TypeScript transpile did not emit output {}",
            output.display()
        );
    }

    Ok(())
}

fn transpile_script_path() -> Result<PathBuf> {
    // Runtime override so TS loading works off the build machine instead of
    // depending on the CARGO_MANIFEST_DIR baked in at compile time.
    // @ref LLP 0007#runtime-module-loading
    if let Ok(script) = std::env::var("EXACT_TRANSPILE_SCRIPT") {
        let script = PathBuf::from(script);
        if script.exists() {
            return Ok(script);
        }
        anyhow::bail!(
            "EXACT_TRANSPILE_SCRIPT points to missing file {}",
            script.display()
        );
    }
    let root = repo_root()?;
    let script = root
        .join("packages")
        .join("exact-devtools")
        .join("src")
        .join("scripts")
        .join("transpile-typescript.mjs");
    if !script.exists() {
        anyhow::bail!("Transpile script not found at {}", script.display());
    }
    Ok(script)
}

fn find_js_runner() -> Result<(PathBuf, &'static str)> {
    if let Ok(path) = which::which("bun") {
        return Ok((path, "bun"));
    }
    if let Ok(path) = which::which("node") {
        return Ok((path, "node"));
    }
    anyhow::bail!("bun or node is required to transpile TypeScript");
}

fn repo_root() -> Result<PathBuf> {
    // Runtime override (same convention as exact-cli) with the compile-time
    // path as a dev-machine fallback. @ref LLP 0007#runtime-module-loading
    if let Ok(root) = std::env::var("EXACT_REPO_ROOT") {
        let root = PathBuf::from(root);
        if root.exists() {
            return Ok(root);
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve repo root"))
}

pub fn builtin_module_debug_entries() -> &'static [BuiltinManifestDebugEntry] {
    BUILTIN_MANIFEST_DEBUG_ENTRIES
}

fn build_builtin_registry(
    registrations: &[BuiltinManifestRegistration],
) -> HashMap<String, String> {
    let mut builtins = HashMap::new();
    let mut source_cache: HashMap<&'static str, String> = HashMap::new();

    for registration in registrations {
        let source = if let Some(source) = source_cache.get(registration.source_key) {
            source.clone()
        } else {
            let Some(source) = generated_builtin_source(registration.source_key) else {
                eprintln!(
                    "Skipping builtin manifest entry {} with unknown source key {}",
                    registration.specifier, registration.source_key
                );
                continue;
            };
            source_cache.insert(registration.source_key, source.clone());
            source
        };
        builtins.insert(registration.specifier.to_string(), source);
    }

    builtins
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_loader() -> ModuleLoader {
        ModuleLoader::new()
    }

    #[test]
    fn resolves_relative_extension() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mod.js");
        std::fs::write(&file, "export const x = 1;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve("./mod", Some(&dir.path().join("entry.js")))
            .unwrap();
        let resolved_path = resolved.path.unwrap();
        assert_eq!(
            resolved_path.canonicalize().unwrap(),
            file.canonicalize().unwrap()
        );
    }

    #[test]
    fn resolves_bare_specifier() {
        let dir = tempdir().unwrap();
        let node_modules = dir.path().join("node_modules");
        let pkg_dir = node_modules.join("demo-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("package.json"), r#"{ "main": "index.js" }"#).unwrap();
        std::fs::write(pkg_dir.join("index.js"), "module.exports = { ok: true };").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve("demo-pkg", Some(&dir.path().join("entry.js")))
            .unwrap();
        assert!(resolved
            .path
            .unwrap()
            .ends_with("node_modules/demo-pkg/index.js"));
    }

    #[test]
    fn resolves_exports_condition() {
        let dir = tempdir().unwrap();
        let node_modules = dir.path().join("node_modules");
        let pkg_dir = node_modules.join("exports-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{ "exports": { "require": "./cjs.js", "import": "./esm.js" } }"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("cjs.js"), "module.exports = { ok: true };").unwrap();
        std::fs::write(pkg_dir.join("esm.js"), "export const ok = true;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve("exports-pkg", Some(&dir.path().join("entry.js")))
            .unwrap();
        assert!(resolved
            .path
            .unwrap()
            .ends_with("node_modules/exports-pkg/cjs.js"));
    }

    #[test]
    fn resolves_node_fs_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:fs", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("readFileSync"));
    }

    #[test]
    fn resolves_bun_fs_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("bun:fs", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("readFileSync"));
    }

    #[test]
    fn resolves_fs_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("fs", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("readFileSync"));
    }

    #[test]
    fn resolves_node_fs_promises_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:fs/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("fs.promises"));
    }

    #[test]
    fn resolves_bun_fs_promises_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("bun:fs/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("fs.promises"));
    }

    #[test]
    fn resolves_node_path_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:path", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("dirname"));
    }

    #[test]
    fn resolves_path_builtin_alias() {
        let loader = test_loader();
        let resolved = loader.resolve("path", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("dirname"));
    }

    #[test]
    fn builtin_aliases_have_distinct_ids() {
        let loader = test_loader();
        let path = loader.resolve("path", None).unwrap();
        let node_path = loader.resolve("node:path", None).unwrap();
        let bun_fs = loader.resolve("bun:fs", None).unwrap();
        let bun_fs_promises = loader.resolve("bun:fs/promises", None).unwrap();
        let node_fs = loader.resolve("node:fs", None).unwrap();
        let fs_promises = loader.resolve("node:fs/promises", None).unwrap();
        let process = loader.resolve("process", None).unwrap();
        let node_process = loader.resolve("node:process", None).unwrap();

        assert_ne!(path.id, node_path.id);
        assert_ne!(process.id, node_process.id);
        assert_ne!(bun_fs.id, node_fs.id);
        assert_ne!(bun_fs_promises.id, fs_promises.id);

        assert_eq!(path.source, node_path.source);
        assert_eq!(process.source, node_process.source);
        assert_eq!(bun_fs.source, node_fs.source);
        assert_eq!(bun_fs_promises.source, fs_promises.source);
    }

    #[test]
    fn resolves_bun_sqlite_aliases_exact_sqlite() {
        let loader = test_loader();
        let exact_sqlite = loader.resolve("exact:sqlite", None).unwrap();
        let bun_sqlite = loader.resolve("bun:sqlite", None).unwrap();
        assert_eq!(exact_sqlite.kind, ModuleKind::Builtin);
        assert_eq!(bun_sqlite.kind, ModuleKind::Builtin);
        assert_eq!(exact_sqlite.source.as_deref(), bun_sqlite.source.as_deref());
        let exact_source = exact_sqlite.source.expect("exact:sqlite source");
        assert!(exact_source.contains("__exactSqliteOpen"));
    }

    #[test]
    fn resolves_node_process_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:process", None).unwrap();
        let source = resolved.source.unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(source.contains("function cwd"));
        assert!(source.contains("function chdir"));
    }

    #[test]
    fn resolves_process_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("process", None).unwrap();
        let source = resolved.source.unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(source.contains("function cwd"));
        assert!(source.contains("function chdir"));
    }

    #[test]
    fn resolves_node_async_hooks_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:async_hooks", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("AsyncLocalStorage"));
        assert!(source.contains("createHook"));
    }

    #[test]
    fn resolves_async_hooks_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("async_hooks", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("AsyncLocalStorage"));
    }

    #[test]
    fn resolves_node_crypto_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:crypto", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("randomBytes"));
    }

    #[test]
    fn resolves_crypto_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("crypto", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("randomBytes"));
    }

    #[test]
    fn resolves_node_events_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:events", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("EventEmitter"));
        assert!(source.contains("setMaxListeners"));
        assert!(source.contains("getMaxListeners"));
        assert!(source.contains("module.exports.default = EventEmitter"));
    }

    #[test]
    fn resolves_events_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("events", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("EventEmitter"));
    }

    #[test]
    fn resolves_node_stream_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:stream", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("PassThrough"));
    }

    #[test]
    fn resolves_stream_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("stream", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("PassThrough"));
    }

    #[test]
    fn resolves_node_stream_promises_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:stream/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("pipeline"));
    }

    #[test]
    fn resolves_stream_promises_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("stream/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("pipeline"));
    }

    #[test]
    fn resolves_node_buffer_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:buffer", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("toByteArray"));
        assert!(source.contains("BufferProto"));
    }

    #[test]
    fn resolves_buffer_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("buffer", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("Buffer.from"));
        assert!(source.contains("Buffer.alloc"));
    }

    #[test]
    fn resolves_node_util_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:util", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("util ="));
    }

    #[test]
    fn resolves_util_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("util", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("promisify"));
        assert!(source.contains("format"));
    }

    #[test]
    fn resolves_node_timers_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:timers", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("setTimeout"));
        assert!(source.contains("setImmediate"));
    }

    #[test]
    fn resolves_timers_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("timers", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("clearInterval"));
    }

    #[test]
    fn resolves_node_timers_promises_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:timers/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("setTimeout"));
        assert!(source.contains("setImmediate"));
    }

    #[test]
    fn resolves_node_stream_web_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:stream/web", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("fromWeb"));
        assert!(source.contains("toWeb"));
    }

    #[test]
    fn resolves_stream_web_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("stream/web", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("ReadableStream"));
        assert!(source.contains("WritableStream"));
    }

    #[test]
    fn stream_web_aliases_share_source() {
        let loader = test_loader();
        let node_stream_web = loader.resolve("node:stream/web", None).unwrap();
        let stream_web = loader.resolve("stream/web", None).unwrap();
        assert_eq!(node_stream_web.id, "node:stream/web");
        assert_eq!(stream_web.id, "stream/web");
        assert_ne!(node_stream_web.id, stream_web.id);
        assert_eq!(node_stream_web.source, stream_web.source);
    }

    #[test]
    fn resolves_node_http_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:http", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("ClientRequest"));
        assert!(source.contains("IncomingMessage"));
    }

    #[test]
    fn resolves_http_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("http", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("request"));
    }

    #[test]
    fn resolves_node_https_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:https", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        let resolved_http = loader.resolve("http", None).unwrap();
        assert_ne!(source, resolved_http.source.unwrap());
        assert!(source.contains("tls.connect"));
        assert!(source.contains("createServer"));
    }

    #[test]
    fn resolves_node_url_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("node:url", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("fileURLToPath"));
        assert!(source.contains("pathToFileURL"));
    }

    #[test]
    fn resolves_url_builtin() {
        let loader = test_loader();
        let resolved = loader.resolve("url", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("require('node:url')"));
        assert!(source.contains("Object.getOwnPropertyDescriptors"));
    }

    #[test]
    fn url_aliases_use_distinct_sources() {
        let loader = test_loader();
        let node_url = loader.resolve("node:url", None).unwrap();
        let url = loader.resolve("url", None).unwrap();
        assert_eq!(node_url.id, "node:url");
        assert_eq!(url.id, "url");
        assert_ne!(node_url.id, url.id);
        assert_ne!(node_url.source, url.source);
    }

    #[test]
    fn resolves_transpiled_typescript_module() {
        let dir = tempdir().unwrap();
        let ts_file = dir.path().join("mod.ts");
        let tsx_file = dir.path().join("mod.tsx");
        let jsx_file = dir.path().join("mod.jsx");
        std::fs::write(&ts_file, "export const value: number = 42;").unwrap();
        std::fs::write(
            &tsx_file,
            "export const label: string = \"ts-x\";\nexport const value: number = 21;\n",
        )
        .unwrap();
        std::fs::write(
            &jsx_file,
            r#"
var React = { createElement: function() { return "jsx"; } };
export const value = <span />;
"#,
        )
        .unwrap();

        let loader = test_loader();

        let resolved = loader
            .resolve("./mod", Some(&dir.path().join("entry.ts")))
            .unwrap();
        let source = resolved.source.unwrap();
        assert_eq!(resolved.kind, ModuleKind::CommonJs);
        assert!(
            !source.contains("export const"),
            "esm exports lowered: {source}"
        );
        assert!(source.contains("value"), "export wiring present: {source}");
        assert!(!source.contains(": number"), "types stripped: {source}");

        let resolved_tsx = loader
            .resolve("./mod.tsx", Some(&dir.path().join("entry.ts")))
            .unwrap();
        let tsx_source = resolved_tsx.source.unwrap();
        assert_eq!(resolved_tsx.kind, ModuleKind::CommonJs);
        assert!(
            !tsx_source.contains("export const"),
            "esm exports lowered: {tsx_source}"
        );
        assert!(
            tsx_source.contains("value"),
            "export wiring present: {tsx_source}"
        );
        assert!(!tsx_source.contains(": number"));

        let resolved_jsx = loader
            .resolve("./mod.jsx", Some(&dir.path().join("entry.ts")))
            .unwrap();
        let jsx_source = resolved_jsx.source.unwrap();
        assert_eq!(resolved_jsx.kind, ModuleKind::CommonJs);
        assert!(
            !jsx_source.contains("export const"),
            "esm exports lowered: {jsx_source}"
        );
        assert!(
            jsx_source.contains("value"),
            "export wiring present: {jsx_source}"
        );
        assert!(jsx_source.contains("createElement"));
        assert!(!jsx_source.contains("<span"));
    }

    #[test]
    fn detects_async_generator_method_js_for_downleveling() {
        let source = r#"
const asyncIterable = {
    async* [Symbol.asyncIterator]() {
        yield 'a';
    }
};
"#;

        assert!(ModuleLoader::source_needs_async_downlevel(source));
        assert!(ModuleLoader::needs_js_downlevel(
            std::path::Path::new("fixture.js"),
            source
        ));
    }

    #[test]
    fn skips_for_of_loops_when_selecting_loop_scope_downlevel_target() {
        let source = r#"
const values = [1, 2, 3];
for (const value of values) {
    queue.push(() => value);
}
"#;

        assert!(ModuleLoader::source_needs_for_of_scoping_fix(source));
        assert!(!ModuleLoader::source_needs_loop_scope_downlevel(source));
        assert_eq!(ModuleLoader::transpile_target_for_source(source), "es2015");
    }

    #[test]
    fn detects_destructured_for_of_loops_for_es2015_scoping_fix() {
        let source = r#"
const cases = [{ value: 1 }, { value: 2 }];
for (const { value } of cases) {
    setTimeout(() => write(value), 0);
}
"#;

        assert!(ModuleLoader::source_needs_for_of_scoping_fix(source));
        assert!(!ModuleLoader::source_needs_loop_scope_downlevel(source));
        assert_eq!(ModuleLoader::transpile_target_for_source(source), "es2015");
    }

    #[test]
    fn keeps_for_of_loops_with_closures_and_continue_on_es5_fallback_path() {
        let source = r#"
const cases = [{ skip: false, filePath: 'a' }, { skip: false, filePath: 'b' }];
for (const testCase of cases) {
    if (testCase.skip) continue;
    setInterval(() => {
        write(testCase.filePath);
    }, 100);
}
"#;

        assert!(ModuleLoader::source_needs_for_of_scoping_fix(source));
        assert!(ModuleLoader::source_needs_loop_scope_downlevel(source));
        assert_eq!(ModuleLoader::transpile_target_for_source(source), "es5");
    }

    #[test]
    fn keeps_classic_let_for_loops_with_closures_on_es5_fallback_path() {
        let source = r#"
const queue = [];
for (let i = 0; i < 3; i++) {
    queue.push(() => i);
}
"#;

        assert!(ModuleLoader::source_needs_loop_scope_downlevel(source));
        assert_eq!(ModuleLoader::transpile_target_for_source(source), "es5");
    }

    #[test]
    fn skips_classic_let_for_loops_without_closures() {
        let source = r#"
const a = {};
for (let i = 0; i < 3; i++) {
    a[`key${i}`] = i;
}
"#;

        assert!(!ModuleLoader::source_needs_loop_scope_downlevel(source));
        assert_eq!(ModuleLoader::transpile_target_for_source(source), "es2015");
    }

    #[test]
    fn skips_unknown_manifest_source_keys() {
        let registrations = [
            BuiltinManifestRegistration {
                specifier: "node:process",
                source_key: "exact_process",
            },
            BuiltinManifestRegistration {
                specifier: "node:broken",
                source_key: "missing_source_key",
            },
        ];

        let builtins = build_builtin_registry(&registrations);
        assert!(builtins.contains_key("node:process"));
        assert!(!builtins.contains_key("node:broken"));
    }

    #[test]
    fn resolves_directory_import_to_index_ts() {
        // @ref LLP 0004#resolution-order
        let dir = tempdir().unwrap();
        let native = dir.path().join("native");
        std::fs::create_dir_all(&native).unwrap();
        std::fs::write(native.join("index.ts"), "export const ok = 1;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve_meta("./native", Some(&dir.path().join("entry.ts")))
            .unwrap();
        assert!(resolved.path.unwrap().ends_with("native/index.ts"));

        let abs = native.to_string_lossy().to_string();
        let resolved_abs = loader.resolve_meta(&abs, None).unwrap();
        assert!(resolved_abs.path.unwrap().ends_with("native/index.ts"));
    }

    #[test]
    fn resolves_referrer_relative_path_without_dot_prefix() {
        // Native hosts pass entry paths like "packages/ibex-runtime-js/src/native"
        // without a leading "./". @ref LLP 0004#resolution-order
        let dir = tempdir().unwrap();
        let nested = dir
            .path()
            .join("packages")
            .join("demo")
            .join("src")
            .join("native");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("index.ts"), "export const ok = 1;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve_meta("packages/demo/src/native", Some(dir.path()))
            .unwrap();
        assert!(resolved
            .path
            .unwrap()
            .ends_with("packages/demo/src/native/index.ts"));

        // A genuinely-bare specifier still reports the original failure.
        let err = loader
            .resolve_meta("definitely-not-a-package", Some(dir.path()))
            .unwrap_err();
        assert!(err.to_string().contains("definitely-not-a-package"));
    }

    #[test]
    fn resolves_ts_style_js_specifier_to_ts_source() {
        // TS NodeNext convention: "../x.js" written in TS resolves to ../x.ts.
        // @ref LLP 0004#the-oxc_resolver-configuration
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("bootstrap.ts"), "export const b = 1;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve_meta("./bootstrap.js", Some(&dir.path().join("entry.ts")))
            .unwrap();
        assert!(resolved.path.unwrap().ends_with("bootstrap.ts"));
    }

    #[test]
    fn extension_alias_prefers_real_js_over_ts() {
        // @ref LLP 0004#the-oxc_resolver-configuration
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("both.js"), "module.exports = 1;").unwrap();
        std::fs::write(dir.path().join("both.ts"), "export const b = 1;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve_meta("./both.js", Some(&dir.path().join("entry.ts")))
            .unwrap();
        assert!(resolved.path.unwrap().ends_with("both.js"));
    }

    #[test]
    fn resolves_exports_import_only() {
        let dir = tempdir().unwrap();
        let node_modules = dir.path().join("node_modules");
        let pkg_dir = node_modules.join("exports-import-only");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{ "exports": { "import": "./esm.js" } }"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("esm.js"), "export const ok = true;").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve("exports-import-only", Some(&dir.path().join("entry.js")))
            .unwrap();
        assert!(resolved
            .path
            .unwrap()
            .ends_with("node_modules/exports-import-only/esm.js"));
    }

    #[test]
    fn manifest_registrations_resolve_as_builtins() {
        let loader = test_loader();

        for registration in BUILTIN_MANIFEST_REGISTRATIONS {
            let resolved = loader.resolve(registration.specifier, None).unwrap();
            assert_eq!(
                resolved.kind,
                ModuleKind::Builtin,
                "{}",
                registration.specifier
            );
        }
    }

    #[test]
    fn builtin_debug_entries_cover_manifest_registrations() {
        assert_eq!(
            BUILTIN_MANIFEST_DEBUG_ENTRIES.len(),
            BUILTIN_MANIFEST_REGISTRATIONS.len()
        );

        for (debug, registration) in BUILTIN_MANIFEST_DEBUG_ENTRIES
            .iter()
            .zip(BUILTIN_MANIFEST_REGISTRATIONS.iter())
        {
            assert_eq!(debug.specifier, registration.specifier);
            assert_eq!(debug.source_key, registration.source_key);
        }
    }

    #[test]
    fn manifest_aliases_share_sources_and_keep_distinct_ids() {
        let loader = test_loader();
        let mut registrations_by_source: HashMap<&str, Vec<&str>> = HashMap::new();

        for registration in BUILTIN_MANIFEST_REGISTRATIONS {
            registrations_by_source
                .entry(registration.source_key)
                .or_default()
                .push(registration.specifier);
        }

        for specifiers in registrations_by_source.values() {
            if specifiers.len() < 2 {
                continue;
            }

            let first = loader.resolve(specifiers[0], None).unwrap();
            let first_source = first.source.clone();

            for specifier in &specifiers[1..] {
                let resolved = loader.resolve(specifier, None).unwrap();
                assert_ne!(resolved.id, first.id, "{}", specifier);
                assert_eq!(resolved.source, first_source, "{}", specifier);
            }
        }
    }
}
