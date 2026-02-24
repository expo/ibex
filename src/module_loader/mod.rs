//! Module loader for ESM and CommonJS.
//!
//! This provides a minimal resolver and loader with `exact:` builtins.
//! Node-style package resolution and full ESM/CJS interop are implemented
//! incrementally (see TODOs).

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

impl Default for ModuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleLoader {
    pub fn new() -> Self {
        let mut builtins = HashMap::new();
        builtins.insert("exact:process".to_string(), exact_process_module());
        builtins.insert("exact:crypto".to_string(), exact_crypto_module());
        builtins.insert("exact:clipboard".to_string(), exact_clipboard_module());
        builtins.insert("exact:http".to_string(), exact_http_module());
        builtins.insert("exact:sqlite".to_string(), exact_sqlite_module());
        builtins.insert("bun:sqlite".to_string(), exact_sqlite_module());
        builtins.insert("bun".to_string(), bun_module());
        builtins.insert("bun:test".to_string(), bun_test_module());
        builtins.insert("harness".to_string(), bun_harness_module());
        builtins.insert("node-harness".to_string(), node_harness_module());
        builtins.insert("bun:jsc".to_string(), bun_jsc_module());
        builtins.insert(
            "bun:internal-for-testing".to_string(),
            bun_internal_for_testing_module(),
        );

        let node_test_src = "module.exports = require('bun:test');".to_string();
        builtins.insert("node:test".to_string(), node_test_src);

        let node_fs_src = node_fs_module();
        builtins.insert("bun:fs".to_string(), node_fs_src.clone());
        builtins.insert("node:fs".to_string(), node_fs_src.clone());
        builtins.insert("fs".to_string(), node_fs_src);

        let node_process_src = exact_process_module();
        builtins.insert("node:process".to_string(), node_process_src.clone());
        builtins.insert("process".to_string(), node_process_src);

        let node_fs_promises_src = node_fs_promises_module();
        builtins.insert("bun:fs/promises".to_string(), node_fs_promises_src.clone());
        builtins.insert("node:fs/promises".to_string(), node_fs_promises_src.clone());
        builtins.insert("fs/promises".to_string(), node_fs_promises_src.clone());
        builtins.insert(
            "internal/fs/promises".to_string(),
            node_fs_promises_src.clone(),
        );

        let path_module = node_path_module();
        builtins.insert("node:path".to_string(), path_module.clone());
        builtins.insert("path".to_string(), path_module);

        let path_posix_src = "module.exports = require('path').posix;".to_string();
        builtins.insert("node:path/posix".to_string(), path_posix_src.clone());
        builtins.insert("path/posix".to_string(), path_posix_src);

        let path_win32_src = "module.exports = require('path').win32;".to_string();
        builtins.insert("node:path/win32".to_string(), path_win32_src.clone());
        builtins.insert("path/win32".to_string(), path_win32_src);

        let crypto_module = exact_crypto_module();
        builtins.insert("node:crypto".to_string(), crypto_module.clone());
        builtins.insert("crypto".to_string(), crypto_module);

        let events_module = node_events_module();
        builtins.insert("node:events".to_string(), events_module.clone());
        builtins.insert("events".to_string(), events_module);

        let stream_module = node_stream_module();
        builtins.insert("node:stream".to_string(), stream_module.clone());
        builtins.insert("stream".to_string(), stream_module);

        let stream_consumers_module = node_stream_consumers_module();
        builtins.insert(
            "node:stream/consumers".to_string(),
            stream_consumers_module.clone(),
        );
        builtins.insert("stream/consumers".to_string(), stream_consumers_module);

        let stream_promises_module = node_stream_promises_module();
        builtins.insert(
            "node:stream/promises".to_string(),
            stream_promises_module.clone(),
        );
        builtins.insert("stream/promises".to_string(), stream_promises_module);

        let buffer_module = node_buffer_module();
        builtins.insert("node:buffer".to_string(), buffer_module.clone());
        builtins.insert("buffer".to_string(), buffer_module);

        let util_module = node_util_module();
        builtins.insert("node:util".to_string(), util_module.clone());
        builtins.insert("util".to_string(), util_module);
        builtins.insert(
            "util/types".to_string(),
            "module.exports = require('util').types;".to_string(),
        );
        builtins.insert(
            "node:util/types".to_string(),
            "module.exports = require('node:util').types;".to_string(),
        );

        let timers_module = node_timers_module();
        builtins.insert("node:timers".to_string(), timers_module.clone());
        builtins.insert("timers".to_string(), timers_module);

        let timers_promises_module = node_timers_promises_module();
        builtins.insert(
            "node:timers/promises".to_string(),
            timers_promises_module.clone(),
        );
        builtins.insert("timers/promises".to_string(), timers_promises_module);

        let http_module = node_http_module();
        builtins.insert("node:http".to_string(), http_module.clone());
        builtins.insert("http".to_string(), http_module.clone());
        builtins.insert("node:https".to_string(), http_module.clone());
        builtins.insert("https".to_string(), http_module);

        let stream_web_module = node_stream_web_module();
        builtins.insert("node:stream/web".to_string(), stream_web_module.clone());
        builtins.insert("stream/web".to_string(), stream_web_module);

        let url_module = node_url_module();
        builtins.insert("node:url".to_string(), url_module.clone());
        builtins.insert("url".to_string(), url_module);

        let os_module = node_os_module();
        builtins.insert("node:os".to_string(), os_module.clone());
        builtins.insert("os".to_string(), os_module);

        let tty_module = node_tty_module();
        builtins.insert("node:tty".to_string(), tty_module.clone());
        builtins.insert("tty".to_string(), tty_module);

        let assert_module = node_assert_module();
        builtins.insert("node:assert".to_string(), assert_module.clone());
        builtins.insert("assert".to_string(), assert_module.clone());
        builtins.insert("node:assert/strict".to_string(), assert_module.clone());
        builtins.insert("assert/strict".to_string(), assert_module);

        let string_decoder_module = node_string_decoder_module();
        builtins.insert(
            "node:string_decoder".to_string(),
            string_decoder_module.clone(),
        );
        builtins.insert("string_decoder".to_string(), string_decoder_module);

        let querystring_module = node_querystring_module();
        builtins.insert("node:querystring".to_string(), querystring_module.clone());
        builtins.insert("querystring".to_string(), querystring_module);

        let punycode_module = node_punycode_module();
        builtins.insert("node:punycode".to_string(), punycode_module.clone());
        builtins.insert("punycode".to_string(), punycode_module);

        let child_process_module = node_child_process_module();
        builtins.insert(
            "node:child_process".to_string(),
            child_process_module.clone(),
        );
        builtins.insert("child_process".to_string(), child_process_module);

        let readline_module = node_readline_module();
        builtins.insert("node:readline".to_string(), readline_module.clone());
        builtins.insert("readline".to_string(), readline_module.clone());
        builtins.insert(
            "node:readline/promises".to_string(),
            readline_module.clone(),
        );
        builtins.insert("readline/promises".to_string(), readline_module);

        let module_module = node_module_module();
        builtins.insert("node:module".to_string(), module_module.clone());
        builtins.insert("module".to_string(), module_module);

        let zlib_module = node_zlib_module();
        builtins.insert("node:zlib".to_string(), zlib_module.clone());
        builtins.insert("zlib".to_string(), zlib_module);

        let tls_module = node_tls_module();
        builtins.insert("node:tls".to_string(), tls_module.clone());
        builtins.insert("tls".to_string(), tls_module);

        let dns_module = node_dns_module();
        builtins.insert("node:dns".to_string(), dns_module.clone());
        builtins.insert("dns".to_string(), dns_module.clone());
        builtins.insert("node:dns/promises".to_string(), dns_module.clone());
        builtins.insert("dns/promises".to_string(), dns_module);

        let internal_fs_utils_module = internal_fs_utils_module();
        builtins.insert("internal/fs/utils".to_string(), internal_fs_utils_module);

        let net_module = node_net_module();
        builtins.insert("node:net".to_string(), net_module.clone());
        builtins.insert("net".to_string(), net_module);

        let perf_hooks_module = node_perf_hooks_module();
        builtins.insert("node:perf_hooks".to_string(), perf_hooks_module.clone());
        builtins.insert("perf_hooks".to_string(), perf_hooks_module);

        let async_hooks_module = node_async_hooks_module();
        builtins.insert("node:async_hooks".to_string(), async_hooks_module.clone());
        builtins.insert("async_hooks".to_string(), async_hooks_module);

        let worker_threads_module = node_worker_threads_module();
        builtins.insert(
            "node:worker_threads".to_string(),
            worker_threads_module.clone(),
        );
        builtins.insert("worker_threads".to_string(), worker_threads_module);

        let vm_module = node_vm_module();
        builtins.insert("node:vm".to_string(), vm_module.clone());
        builtins.insert("vm".to_string(), vm_module);

        let console_module = node_console_module();
        builtins.insert("node:console".to_string(), console_module.clone());
        builtins.insert("console".to_string(), console_module);

        let cluster_module = node_cluster_module();
        builtins.insert("node:cluster".to_string(), cluster_module.clone());
        builtins.insert("cluster".to_string(), cluster_module);

        let dgram_module = node_dgram_module();
        builtins.insert("node:dgram".to_string(), dgram_module.clone());
        builtins.insert("dgram".to_string(), dgram_module);

        let domain_module = node_domain_module();
        builtins.insert("node:domain".to_string(), domain_module.clone());
        builtins.insert("domain".to_string(), domain_module);

        let v8_module = node_v8_module();
        builtins.insert("node:v8".to_string(), v8_module.clone());
        builtins.insert("v8".to_string(), v8_module);

        let constants_module = node_constants_module();
        builtins.insert("node:constants".to_string(), constants_module.clone());
        builtins.insert("constants".to_string(), constants_module);

        let ws_module = ws_module();
        builtins.insert("ws".to_string(), ws_module);

        let http2_module = node_http2_module();
        builtins.insert("node:http2".to_string(), http2_module.clone());
        builtins.insert("http2".to_string(), http2_module);

        let diagnostics_channel_module = node_diagnostics_channel_module();
        builtins.insert(
            "node:diagnostics_channel".to_string(),
            diagnostics_channel_module.clone(),
        );
        builtins.insert(
            "diagnostics_channel".to_string(),
            diagnostics_channel_module,
        );

        let trace_events_module = node_trace_events_module();
        builtins.insert("node:trace_events".to_string(), trace_events_module.clone());
        builtins.insert("trace_events".to_string(), trace_events_module);

        let inspector_module = node_inspector_module();
        builtins.insert("node:inspector".to_string(), inspector_module.clone());
        builtins.insert("inspector".to_string(), inspector_module.clone());
        builtins.insert(
            "node:inspector/promises".to_string(),
            inspector_module.clone(),
        );
        builtins.insert("inspector/promises".to_string(), inspector_module);

        let wasi_module = node_wasi_module();
        builtins.insert("node:wasi".to_string(), wasi_module.clone());
        builtins.insert("wasi".to_string(), wasi_module);

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
        if Self::needs_transpile(path) {
            return self.transpile_module(path);
        }
        std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read module {}", path.display()))
    }

    fn needs_transpile(path: &Path) -> bool {
        path.extension()
            .and_then(OsStr::to_str)
            .map(|ext| matches!(ext, "ts" | "tsx" | "jsx" | "mts" | "cts"))
            .unwrap_or(false)
    }

    fn transpile_module(&self, path: &Path) -> Result<String> {
        let cache_key = module_cache_key(path)?;
        let cache_dir = transpile_cache_dir()?;
        std::fs::create_dir_all(&cache_dir).with_context(|| {
            format!(
                "Failed to create transpile cache directory {}",
                cache_dir.display()
            )
        })?;

        let output = cache_dir.join(format!("{cache_key}.js"));
        if should_rebuild_output(path, &output)? {
            run_transpile_command(path, &output)?;
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

        let resolution = self
            .resolver
            .resolve(&base_dir, specifier)
            .with_context(|| format!("Failed to resolve module {}", specifier))?;

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
        if Self::needs_transpile(&resolution.full_path()) && kind == ModuleKind::Esm {
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

fn module_cache_key(path: &Path) -> Result<String> {
    let mut hasher = DefaultHasher::new();
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
    Ok(format!("{:x}", hasher.finish()))
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

fn run_transpile_command(entry: &Path, output: &Path) -> Result<()> {
    let (runner, runner_name) = find_js_runner()?;
    let script = transpile_script_path()?;

    let status = Command::new(&runner)
        .arg(script)
        .arg("--entry")
        .arg(entry)
        .arg("--out")
        .arg(output)
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
    let root = repo_root()?;
    let script = root
        .join("js")
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
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve repo root"))
}

fn exact_process_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/process.js")).to_string()
}

fn exact_crypto_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/crypto.js")).to_string()
}

fn exact_http_module() -> String {
    include_str!("../../../../js/src/runtime/http-server/index.js").to_string()
}

fn exact_sqlite_module() -> String {
    include_str!("../../../../js/src/runtime/sqlite/module.js").to_string()
}

fn bun_test_module() -> String {
    include_str!("../../../../test/compat/harness/bun-adapter.js").to_string()
}

fn bun_module() -> String {
    include_str!("../../../../test/compat/harness/bun.js").to_string()
}

fn bun_harness_module() -> String {
    include_str!("../../../../test/compat/harness/harness.js").to_string()
}

fn node_harness_module() -> String {
    include_str!("../../../../test/compat/harness/node-harness.js").to_string()
}

fn bun_jsc_module() -> String {
    include_str!("../../../../test/compat/harness/bun-jsc.js").to_string()
}

fn bun_internal_for_testing_module() -> String {
    include_str!("../../../../test/compat/harness/bun-internal-for-testing.js").to_string()
}

fn exact_clipboard_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/clipboard.js")).to_string()
}

fn node_fs_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/fs.js")).to_string()
}

fn node_fs_promises_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/fs-promises.js")).to_string()
}

fn node_path_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/path.js")).to_string()
}

fn node_events_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/events.js")).to_string()
}

fn node_stream_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/stream.js")).to_string()
}

fn node_stream_promises_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/stream-promises.js")).to_string()
}

fn node_stream_consumers_module() -> String {
    r#"var _bufferMod = require('buffer');
var _Buffer = _bufferMod && _bufferMod.Buffer ? _bufferMod.Buffer : null;

function _toUint8Array(chunk) {
  if (!chunk) {
    return new Uint8Array(0);
  }
  if (chunk instanceof Uint8Array) {
    return chunk;
  }
  if (chunk instanceof ArrayBuffer) {
    return new Uint8Array(chunk);
  }
  if (ArrayBuffer.isView(chunk)) {
    return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  }
  if (typeof chunk === 'string') {
    if (typeof TextEncoder === 'function') {
      return new TextEncoder().encode(chunk);
    }
    if (_Buffer && typeof _Buffer.from === 'function') {
      return _Buffer.from(chunk);
    }
    return new Uint8Array(chunk.length);
  }
  return _Buffer && _Buffer.isBuffer(chunk) ? chunk : new Uint8Array(0);
}

function _collect(stream) {
  if (!stream) {
    return Promise.reject(new TypeError('The "stream" argument must be of type stream. Received ' + String(stream)));
  }
  if (typeof stream.getReader === 'function') {
    return new Promise(function(resolve, reject) {
      var chunks = [];
      var reader = stream.getReader();
      function read() {
        reader.read().then(function(result) {
          if (result.done) {
            resolve(chunks);
            return;
          }
          chunks.push(_toUint8Array(result.value));
          read();
        }).catch(reject);
      }
      read();
    });
  }
  if (typeof stream.on === 'function') {
    return new Promise(function(resolve, reject) {
      var chunks = [];
      var ended = false;

      function cleanup() {
        stream.removeListener && stream.removeListener('data', onData);
        stream.removeListener && stream.removeListener('error', onError);
        stream.removeListener && stream.removeListener('end', onEnd);
        stream.removeListener && stream.removeListener('close', onEnd);
      }
      function onData(chunk) {
        chunks.push(_toUint8Array(chunk));
      }
      function onError(err) {
        if (ended) {
          return;
        }
        ended = true;
        cleanup();
        reject(err);
      }
      function onEnd() {
        if (ended) {
          return;
        }
        ended = true;
        cleanup();
        resolve(chunks);
      }
      stream.on('data', onData);
      stream.on('error', onError);
      stream.on('end', onEnd);
      stream.on('close', onEnd);
      if (stream.readableEnded) {
        onEnd();
      }
    });
  }
  return Promise.reject(new TypeError('The "stream" argument must be of type stream. Received ' + String(stream)));
}

function _concatChunks(chunks) {
  var total = 0;
  for (var i = 0; i < chunks.length; i++) {
    total += chunks[i].byteLength || 0;
  }
  var merged = new Uint8Array(total);
  var offset = 0;
  for (var j = 0; j < chunks.length; j++) {
    var chunk = chunks[j];
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

function _streamToBuffer(chunks) {
  if (_Buffer && _Buffer.concat) {
    return _Buffer.concat(chunks);
  }
  var merged = _concatChunks(chunks);
  return _Buffer ? _Buffer.from(merged) : merged;
}

function _decode(chunks) {
  var merged = _concatChunks(chunks);
  if (typeof TextDecoder === 'function') {
    return new TextDecoder().decode(merged);
  }
  var out = '';
  for (var i = 0; i < merged.length; i++) {
    out += String.fromCharCode(merged[i]);
  }
  return out;
}

function buffer(stream) {
  return _collect(stream).then(function(chunks) {
    return _streamToBuffer(chunks);
  });
}

function arrayBuffer(stream) {
  return _collect(stream).then(function(chunks) {
    return _concatChunks(chunks).buffer;
  });
}

function text(stream) {
  return _collect(stream).then(function(chunks) {
    return _decode(chunks);
  });
}

function blob(stream, options) {
  return _collect(stream).then(function(chunks) {
    if (typeof Blob === 'function') {
      return new Blob(chunks, options);
    }
    var data = _concatChunks(chunks);
    return {
      size: data.length,
      type: options && options.type || '',
      arrayBuffer: function() {
        return Promise.resolve(data.buffer);
      }
    };
  });
}

function json(stream) {
  return text(stream).then(JSON.parse);
}

module.exports = {
  blob: blob,
  buffer: buffer,
  arrayBuffer: arrayBuffer,
  text: text,
  json: json
};"#
        .to_string()
}

fn node_stream_web_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/stream-web.js")).to_string()
}

fn node_buffer_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/buffer.js")).to_string()
}

fn node_util_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/util.js")).to_string()
}

fn node_timers_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/timers.js")).to_string()
}

fn node_timers_promises_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/timers-promises.js")).to_string()
}

fn node_http_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/http.js")).to_string()
}

fn node_url_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/url.js")).to_string()
}

fn node_assert_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/assert.js")).to_string()
}

fn node_os_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/os.js")).to_string()
}

fn node_tty_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/tty.js")).to_string()
}

fn node_string_decoder_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/string-decoder.js")).to_string()
}

fn node_querystring_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/querystring.js")).to_string()
}

fn node_punycode_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/punycode.js")).to_string()
}

fn node_child_process_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/child-process.js")).to_string()
}

fn node_readline_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/readline.js")).to_string()
}

fn node_tls_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/tls.js")).to_string()
}

fn node_dns_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/dns.js")).to_string()
}

fn node_net_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/net.js")).to_string()
}

fn internal_fs_utils_module() -> String {
    r#"function isFd(fd) {
  return typeof fd === 'number' && Number.isInteger(fd) && fd >= 0;
}

function isFileMode(mode) {
  return typeof mode === 'number' && Number.isInteger(mode);
}

function validateFd(fd) {
  if (!isFd(fd)) {
    throw new TypeError('The "fd" argument must be a non-negative integer. Received ' + String(fd));
  }
}

function toPathIfFileURL(value) {
  if (typeof value === 'string' || value instanceof String) {
    return value;
  }
  if (value && typeof value === 'object' && typeof value.path === 'string') {
    return value.path;
  }
  return value;
}

module.exports = {
  isFd: isFd,
  isFileMode: isFileMode,
  validateFd: validateFd,
  toPathIfFileURL: toPathIfFileURL,
  kMinPoolSpace: 8192
};"#
    .to_string()
}

fn node_zlib_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/zlib.js")).to_string()
}

fn node_module_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/module.js")).to_string()
}

fn node_perf_hooks_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/perf-hooks.js")).to_string()
}

fn node_async_hooks_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/async-hooks.js")).to_string()
}

fn node_worker_threads_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/worker-threads.js")).to_string()
}

fn node_vm_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/vm.js")).to_string()
}

fn node_console_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/console.js")).to_string()
}

fn node_cluster_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/cluster.js")).to_string()
}

fn node_dgram_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/dgram.js")).to_string()
}

fn node_domain_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/domain.js")).to_string()
}

fn node_v8_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/v8.js")).to_string()
}

fn node_constants_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/constants.js")).to_string()
}

fn ws_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/ws.js")).to_string()
}

fn node_http2_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/http2.js")).to_string()
}

fn node_diagnostics_channel_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/diagnostics-channel.js")).to_string()
}

fn node_trace_events_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/trace-events.js")).to_string()
}

fn node_inspector_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/inspector.js")).to_string()
}

fn node_wasi_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/wasi.js")).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resolves_relative_extension() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mod.js");
        std::fs::write(&file, "export const x = 1;").unwrap();

        let loader = ModuleLoader::new();
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

        let loader = ModuleLoader::new();
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

        let loader = ModuleLoader::new();
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
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:fs", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("readFileSync"));
    }

    #[test]
    fn resolves_bun_fs_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("bun:fs", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("readFileSync"));
    }

    #[test]
    fn resolves_fs_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("fs", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("readFileSync"));
    }

    #[test]
    fn resolves_node_fs_promises_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:fs/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("fs.promises"));
    }

    #[test]
    fn resolves_bun_fs_promises_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("bun:fs/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("fs.promises"));
    }

    #[test]
    fn resolves_node_path_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:path", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("dirname"));
    }

    #[test]
    fn resolves_path_builtin_alias() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("path", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("dirname"));
    }

    #[test]
    fn builtin_aliases_have_distinct_ids() {
        let loader = ModuleLoader::new();
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
        let loader = ModuleLoader::new();
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
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:process", None).unwrap();
        let source = resolved.source.unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(source.contains("function cwd"));
        assert!(source.contains("function chdir"));
    }

    #[test]
    fn resolves_process_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("process", None).unwrap();
        let source = resolved.source.unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(source.contains("function cwd"));
        assert!(source.contains("function chdir"));
    }

    #[test]
    fn resolves_node_async_hooks_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:async_hooks", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("AsyncLocalStorage"));
        assert!(source.contains("createHook"));
    }

    #[test]
    fn resolves_async_hooks_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("async_hooks", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("AsyncLocalStorage"));
    }

    #[test]
    fn resolves_node_crypto_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:crypto", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("randomBytes"));
    }

    #[test]
    fn resolves_crypto_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("crypto", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("randomBytes"));
    }

    #[test]
    fn resolves_node_events_builtin() {
        let loader = ModuleLoader::new();
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
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("events", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("EventEmitter"));
    }

    #[test]
    fn resolves_node_stream_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:stream", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("PassThrough"));
    }

    #[test]
    fn resolves_stream_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("stream", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("PassThrough"));
    }

    #[test]
    fn resolves_node_stream_promises_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:stream/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("pipeline"));
    }

    #[test]
    fn resolves_stream_promises_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("stream/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("pipeline"));
    }

    #[test]
    fn resolves_node_buffer_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:buffer", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("toByteArray"));
        assert!(source.contains("BufferProto"));
    }

    #[test]
    fn resolves_buffer_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("buffer", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("Buffer.from"));
        assert!(source.contains("Buffer.alloc"));
    }

    #[test]
    fn resolves_node_util_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:util", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("util ="));
    }

    #[test]
    fn resolves_util_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("util", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("promisify"));
        assert!(source.contains("format"));
    }

    #[test]
    fn resolves_node_timers_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:timers", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("setTimeout"));
        assert!(source.contains("setImmediate"));
    }

    #[test]
    fn resolves_timers_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("timers", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("clearInterval"));
    }

    #[test]
    fn resolves_node_timers_promises_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:timers/promises", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("setTimeout"));
        assert!(source.contains("setImmediate"));
    }

    #[test]
    fn resolves_node_stream_web_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:stream/web", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("fromWeb"));
        assert!(source.contains("toWeb"));
    }

    #[test]
    fn resolves_stream_web_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("stream/web", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("ReadableStream"));
        assert!(source.contains("WritableStream"));
    }

    #[test]
    fn stream_web_aliases_share_source() {
        let loader = ModuleLoader::new();
        let node_stream_web = loader.resolve("node:stream/web", None).unwrap();
        let stream_web = loader.resolve("stream/web", None).unwrap();
        assert_eq!(node_stream_web.id, "node:stream/web");
        assert_eq!(stream_web.id, "stream/web");
        assert_ne!(node_stream_web.id, stream_web.id);
        assert_eq!(node_stream_web.source, stream_web.source);
    }

    #[test]
    fn resolves_node_http_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:http", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("ClientRequest"));
        assert!(source.contains("IncomingMessage"));
    }

    #[test]
    fn resolves_http_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("http", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("request"));
    }

    #[test]
    fn resolves_node_https_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:https", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let resolved_http = loader.resolve("http", None).unwrap();
        assert_eq!(resolved.source.unwrap(), resolved_http.source.unwrap());
    }

    #[test]
    fn resolves_node_url_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("node:url", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        let source = resolved.source.unwrap();
        assert!(source.contains("fileURLToPath"));
        assert!(source.contains("pathToFileURL"));
    }

    #[test]
    fn resolves_url_builtin() {
        let loader = ModuleLoader::new();
        let resolved = loader.resolve("url", None).unwrap();
        assert_eq!(resolved.kind, ModuleKind::Builtin);
        assert!(resolved.source.unwrap().contains("parse"));
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

        let loader = ModuleLoader::new();

        let resolved = loader
            .resolve("./mod", Some(&dir.path().join("entry.ts")))
            .unwrap();
        let source = resolved.source.unwrap();
        assert_eq!(resolved.kind, ModuleKind::CommonJs);
        assert!(source.contains("exports.value ="));
        assert!(!source.contains(": number"));

        let resolved_tsx = loader
            .resolve("./mod.tsx", Some(&dir.path().join("entry.ts")))
            .unwrap();
        let tsx_source = resolved_tsx.source.unwrap();
        assert_eq!(resolved_tsx.kind, ModuleKind::CommonJs);
        assert!(tsx_source.contains("exports.value ="));
        assert!(!tsx_source.contains(": number"));

        let resolved_jsx = loader
            .resolve("./mod.jsx", Some(&dir.path().join("entry.ts")))
            .unwrap();
        let jsx_source = resolved_jsx.source.unwrap();
        assert_eq!(resolved_jsx.kind, ModuleKind::CommonJs);
        assert!(jsx_source.contains("exports.value"));
        assert!(jsx_source.contains("createElement"));
        assert!(!jsx_source.contains("<span"));
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

        let loader = ModuleLoader::new();
        let resolved = loader
            .resolve("exports-import-only", Some(&dir.path().join("entry.js")))
            .unwrap();
        assert!(resolved
            .path
            .unwrap()
            .ends_with("node_modules/exports-import-only/esm.js"));
    }
}
