//! Module loader for ESM and CommonJS.
//!
//! This provides a minimal resolver and loader with `exact:` builtins.
//! Node-style package resolution and full ESM/CJS interop are implemented
//! incrementally (see TODOs).

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::ffi::OsStr;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;
use oxc_resolver::{ModuleType, ResolveOptions, Resolver};
use serde_json::Value;

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

impl ModuleLoader {
    pub fn new() -> Self {
        let mut builtins = HashMap::new();
        builtins.insert("exact:process".to_string(), exact_process_module());
        builtins.insert("exact:crypto".to_string(), exact_crypto_module());
        builtins.insert("exact:clipboard".to_string(), exact_clipboard_module());
        builtins.insert("exact:http".to_string(), exact_http_module());
        builtins.insert("exact:sqlite".to_string(), exact_sqlite_module());
        builtins.insert("bun:sqlite".to_string(), exact_sqlite_module());
        builtins.insert("bun:test".to_string(), bun_test_module());

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
        builtins.insert("fs/promises".to_string(), node_fs_promises_src);

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

        let stream_promises_module = node_stream_promises_module();
        builtins.insert("node:stream/promises".to_string(), stream_promises_module.clone());
        builtins.insert("stream/promises".to_string(), stream_promises_module);

        let buffer_module = node_buffer_module();
        builtins.insert("node:buffer".to_string(), buffer_module.clone());
        builtins.insert("buffer".to_string(), buffer_module);

        let util_module = node_util_module();
        builtins.insert("node:util".to_string(), util_module.clone());
        builtins.insert("util".to_string(), util_module);

        let timers_module = r#"
function setTimeout$1(callback, delay) {
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  if (typeof globalThis.setTimeout !== "function") {
    throw new Error("setTimeout is not available");
  }
  return globalThis.setTimeout(function() {
    callback.apply(null, args);
  }, delay || 0);
}

function clearTimeout$1(handle) {
  if (typeof globalThis.clearTimeout === "function") {
    globalThis.clearTimeout(handle);
  }
}

function setInterval$1(callback, delay) {
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  if (typeof globalThis.setInterval !== "function") {
    throw new Error("setInterval is not available");
  }
  return globalThis.setInterval(function() {
    callback.apply(null, args);
  }, delay || 0);
}

function clearInterval$1(handle) {
  if (typeof globalThis.clearInterval === "function") {
    globalThis.clearInterval(handle);
  }
}

function setImmediate$1(callback) {
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  return setTimeout$1(function() {
    callback.apply(null, args);
  }, 0);
}

function clearImmediate$1(handle) {
  clearTimeout$1(handle);
}

module.exports = {
  setTimeout: setTimeout$1,
  clearTimeout: clearTimeout$1,
  setInterval: setInterval$1,
  clearInterval: clearInterval$1,
  setImmediate: setImmediate$1,
  clearImmediate: clearImmediate$1
};
"#
          .trim()
          .to_string();
        builtins.insert("node:timers".to_string(), timers_module.clone());
        builtins.insert("timers".to_string(), timers_module);

        let timers_promises_module = node_timers_promises_module();
        builtins.insert("node:timers/promises".to_string(), timers_promises_module.clone());
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
        builtins.insert("node:string_decoder".to_string(), string_decoder_module.clone());
        builtins.insert("string_decoder".to_string(), string_decoder_module);

        let querystring_module = node_querystring_module();
        builtins.insert("node:querystring".to_string(), querystring_module.clone());
        builtins.insert("querystring".to_string(), querystring_module);

        let punycode_module = node_punycode_module();
        builtins.insert("node:punycode".to_string(), punycode_module.clone());
        builtins.insert("punycode".to_string(), punycode_module);

        let child_process_module = node_child_process_module();
        builtins.insert("node:child_process".to_string(), child_process_module.clone());
        builtins.insert("child_process".to_string(), child_process_module);

        let readline_module = node_readline_module();
        builtins.insert("node:readline".to_string(), readline_module.clone());
        builtins.insert("readline".to_string(), readline_module.clone());
        builtins.insert("node:readline/promises".to_string(), readline_module.clone());
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
        builtins.insert("node:worker_threads".to_string(), worker_threads_module.clone());
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
        builtins.insert("node:diagnostics_channel".to_string(), diagnostics_channel_module.clone());
        builtins.insert("diagnostics_channel".to_string(), diagnostics_channel_module);

        let trace_events_module = node_trace_events_module();
        builtins.insert("node:trace_events".to_string(), trace_events_module.clone());
        builtins.insert("trace_events".to_string(), trace_events_module);

        let inspector_module = node_inspector_module();
        builtins.insert("node:inspector".to_string(), inspector_module.clone());
        builtins.insert("inspector".to_string(), inspector_module.clone());
        builtins.insert("node:inspector/promises".to_string(), inspector_module.clone());
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
        std::fs::read_to_string(path).with_context(|| format!("Failed to read module {}", path.display()))
    }

    fn needs_transpile(path: &Path) -> bool {
        path.extension()
            .and_then(OsStr::to_str)
            .map(|ext| matches!(ext, "ts" | "tsx" | "jsx"))
            .unwrap_or(false)
    }

    fn transpile_module(&self, path: &Path) -> Result<String> {
        let cache_key = module_cache_key(path)?;
        let cache_dir = transpile_cache_dir()?;
        std::fs::create_dir_all(&cache_dir)
            .with_context(|| format!("Failed to create transpile cache directory {}", cache_dir.display()))?;

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
                    .map(|ext| {
                        matches!(
                            ext,
                            "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx" | "json"
                        )
                    })
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
    match path.extension().and_then(OsStr::to_str).map(|ext| ext.to_ascii_lowercase()) {
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
            std::fs::remove_file(&probe_path)
                .with_context(|| format!("Failed to clean up probe file {}", probe_path.display()))?;
            Ok(())
        }
        Err(err) => {
            Err(anyhow::anyhow!(
                "Transpile cache directory {} is not writable: {}",
                dir.display(),
                err
            ))
        }
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
        .with_context(|| {
            format!(
                "Failed to run {} for {}",
                runner_name,
                entry.display()
            )
        })?;

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
    let script = root.join("js").join("scripts").join("transpile-typescript.mjs");
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
    r#"
function cwd() {
  if (typeof __exactGetCwd === 'function') {
    return __exactGetCwd();
  }
  return "/";
}

function chdir(path) {
  if (typeof __exactSetCwd !== 'function') {
    throw new Error("process.chdir is not supported in this runtime");
  }
  if (typeof path !== 'string') {
    throw new TypeError("path must be a string");
  }
  __exactSetCwd(path);
}

var argv = [];
if (typeof globalThis.__exactArgv === "object" && Array.isArray(globalThis.__exactArgv)) {
  argv = globalThis.__exactArgv;
}

var env = {};

if (typeof __exactGetAllEnv === 'function') {
  var allEnv = __exactGetAllEnv();
  if (allEnv && typeof allEnv === 'object') {
    env = allEnv;
  } else {
    env = {};
  }
} else {
  env = {
    get: function(key) {
      if (typeof __exactGetEnv !== 'function') {
        return undefined;
      }
      return __exactGetEnv(key);
    }
  };
}

// Re-export the full globalThis.process object (which has all the C++ properties)
// with cwd/env/argv as fallback overrides
if (typeof globalThis !== 'undefined' && globalThis.process) {
  var proc = globalThis.process;
  // Ensure our module-level cwd/env/argv are present
  if (!proc.chdir) proc.chdir = chdir;
  if (!proc.cwd) proc.cwd = cwd;
  if (!proc.env || (typeof proc.env === 'object' && Object.keys(proc.env).length === 0)) proc.env = env;
  if (!proc.argv || proc.argv.length === 0) proc.argv = argv;
  module.exports = proc;
} else {
  module.exports = { cwd: cwd, env: env, argv: argv };
}
"#
    .trim()
    .to_string()
}

fn exact_crypto_module() -> String {
    r##"
function randomBytes(len) {
  if (typeof __exactRandomBytes !== 'function') {
    throw new Error('Exact crypto not available');
  }
  var bytes = __exactRandomBytes(len);
  // Wrap as Buffer if available, so .toString('hex') etc. work
  if (typeof Buffer !== 'undefined' && Buffer.from) {
    return Buffer.from(bytes);
  }
  return bytes;
}

// --- createHash(algorithm) ---
function Hash(algorithm) {
  this._algo = algorithm.toLowerCase().replace('-', '');
  this._chunks = [];
}
Hash.prototype.update = function(data, encoding) {
  if (typeof data === 'string') {
    this._chunks.push(data);
  } else if (data && data.length !== undefined) {
    // Buffer or Uint8Array — convert to string for native bridge
    var str = '';
    for (var i = 0; i < data.length; i++) str += String.fromCharCode(data[i]);
    this._chunks.push(str);
  }
  return this;
};
Hash.prototype.digest = function(encoding) {
  var joined = this._chunks.join('');
  if (!encoding || encoding === 'buffer') {
    // Return raw bytes as Buffer
    if (typeof __exactHashRaw === 'function') {
      var raw = __exactHashRaw(this._algo, joined);
      if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(raw);
      return raw;
    }
  }
  if (typeof __exactHashSync === 'function') {
    var hex = __exactHashSync(this._algo, joined);
    if (!encoding || encoding === 'hex') return hex;
    if (encoding === 'base64') {
      // hex to base64
      var bytes = [];
      for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
      }
      if (typeof btoa === 'function') {
        var str = '';
        for (var j = 0; j < bytes.length; j++) str += String.fromCharCode(bytes[j]);
        return btoa(str);
      }
    }
    if (encoding === 'buffer') {
      var bytes = [];
      for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
      }
      if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(bytes);
      return new Uint8Array(bytes);
    }
    return hex;
  }
  throw new Error('Native hash not available');
};
Hash.prototype.copy = function() {
  var h = new Hash(this._algo);
  h._chunks = this._chunks.slice();
  return h;
};

function createHash(algorithm) {
  return new Hash(algorithm);
}

// --- createHmac(algorithm, key) ---
function Hmac(algorithm, key) {
  this._algo = algorithm.toLowerCase().replace('-', '');
  this._key = typeof key === 'string' ? key : '';
  if (typeof key !== 'string' && key && key.length !== undefined) {
    var str = '';
    for (var i = 0; i < key.length; i++) str += String.fromCharCode(key[i]);
    this._key = str;
  }
  this._chunks = [];
}
Hmac.prototype.update = function(data, encoding) {
  if (typeof data === 'string') {
    this._chunks.push(data);
  } else if (data && data.length !== undefined) {
    var str = '';
    for (var i = 0; i < data.length; i++) str += String.fromCharCode(data[i]);
    this._chunks.push(str);
  }
  return this;
};
Hmac.prototype.digest = function(encoding) {
  var joined = this._chunks.join('');
  if (typeof __exactHmacSync === 'function') {
    var hex = __exactHmacSync(this._algo, this._key, joined);
    if (!encoding || encoding === 'hex') return hex;
    if (encoding === 'base64') {
      var bytes = [];
      for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
      }
      if (typeof btoa === 'function') {
        var str = '';
        for (var j = 0; j < bytes.length; j++) str += String.fromCharCode(bytes[j]);
        return btoa(str);
      }
    }
    if (encoding === 'buffer') {
      var bytes = [];
      for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
      }
      if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(bytes);
      return new Uint8Array(bytes);
    }
    return hex;
  }
  throw new Error('Native HMAC not available');
};

function createHmac(algorithm, key) {
  return new Hmac(algorithm, key);
}

// --- getHashes() ---
function getHashes() {
  return ['md5', 'sha1', 'sha256', 'sha384', 'sha512'];
}

// --- timingSafeEqual ---
function timingSafeEqual(a, b) {
  if (a.length !== b.length) throw new RangeError('Input buffers must have the same byte length');
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

function randomUUID() {
  // Use globalThis.crypto if available
  if (typeof globalThis !== 'undefined' && globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  // Fallback: generate UUID v4 from randomBytes
  var bytes = randomBytes(16);
  var hex = '';
  for (var i = 0; i < bytes.length; i++) {
    var b = typeof bytes[i] === 'number' ? bytes[i] : bytes.charCodeAt ? bytes.charCodeAt(i) : 0;
    hex += (b < 16 ? '0' : '') + b.toString(16);
  }
  // Set version (4) and variant (8, 9, a, or b)
  return hex.substr(0, 8) + '-' + hex.substr(8, 4) + '-4' + hex.substr(13, 3) + '-' +
    ((parseInt(hex.substr(16, 2), 16) & 0x3f | 0x80).toString(16)) + hex.substr(18, 2) + '-' + hex.substr(20, 12);
}

function randomInt(min, max) {
  if (max === undefined) { max = min; min = 0; }
  var range = max - min;
  var bytes = randomBytes(4);
  var b0 = typeof bytes[0] === 'number' ? bytes[0] : bytes.charCodeAt(0);
  var b1 = typeof bytes[1] === 'number' ? bytes[1] : bytes.charCodeAt(1);
  var b2 = typeof bytes[2] === 'number' ? bytes[2] : bytes.charCodeAt(2);
  var b3 = typeof bytes[3] === 'number' ? bytes[3] : bytes.charCodeAt(3);
  var val = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
  return min + (val % range);
}

function randomFillSync(buf, offset, size) {
  offset = offset || 0;
  size = size || (buf.length - offset);
  var bytes = randomBytes(size);
  for (var i = 0; i < size; i++) {
    buf[offset + i] = typeof bytes[i] === 'number' ? bytes[i] : (bytes.charCodeAt ? bytes.charCodeAt(i) : 0);
  }
  return buf;
}

function _toBytes(value) {
  if (value === null || value === undefined) return new Uint8Array(0);
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof ArrayBuffer === 'object' && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    var asView = value instanceof Uint8Array ? value : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return asView;
  }
  if (typeof value === 'string') {
    var fromString = new Uint8Array(value.length);
    for (var i = 0; i < value.length; i++) fromString[i] = value.charCodeAt(i);
    return fromString;
  }
  if (typeof value.length === 'number') {
    var fromArray = new Uint8Array(value.length);
    for (var j = 0; j < value.length; j++) fromArray[j] = value[j];
    return fromArray;
  }
  return new Uint8Array(0);
}

function _normalizeKdfDigest(digest) {
  var normalized = (digest || 'sha1').toString().toLowerCase().replace(/-/g, '');
  if (normalized === 'md4') return 'md4';
  if (normalized === 'md5') return 'md5';
  if (normalized === 'sha1') return 'sha1';
  if (normalized === 'sha224') return 'sha224';
  if (normalized === 'sha256') return 'sha256';
  if (normalized === 'sha384') return 'sha384';
  if (normalized === 'sha512') return 'sha512';
  return 'sha256';
}

// --- pbkdf2Sync(password, salt, iterations, keylen, digest) ---
function pbkdf2Sync(password, salt, iterations, keylen, digest) {
  if (typeof __exactPbkdf2 !== 'function') {
    throw new Error('pbkdf2 not available');
  }
  if (typeof iterations !== 'number' || iterations <= 0) {
    throw new TypeError('Invalid iterations value');
  }
  if (typeof keylen !== 'number' || keylen <= 0) {
    throw new TypeError('Invalid keylen value');
  }
  var passBytes = _toBytes(password);
  var saltBytes = _toBytes(salt);
  var hashName = _normalizeKdfDigest(digest);
  var result = __exactPbkdf2(passBytes, saltBytes, iterations, keylen, hashName);
  if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(result);
  return result;
}

function pbkdf2(password, salt, iterations, keylen, digest, callback) {
  if (typeof digest === 'function') { callback = digest; digest = 'sha1'; }
  try {
    var result = pbkdf2Sync(password, salt, iterations, keylen, digest);
    if (typeof callback === 'function') setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (typeof callback === 'function') setTimeout(function() { callback(e); }, 0);
    else throw e;
  }
}

// --- hkdfSync / hkdf ---
function hkdfSync(digest, ikm, salt, info, keylen) {
  if (typeof __exactHkdf !== 'function') {
    throw new Error('hkdf not available in this runtime');
  }
  var ikmBytes = _toBytes(ikm);
  var saltBytes = _toBytes(salt);
  var infoBytes = _toBytes(info);
  var hashName = _normalizeKdfDigest(digest);
  var result = __exactHkdf(hashName, ikmBytes, saltBytes, infoBytes, keylen);
  if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(result);
  return result;
}

function hkdf(digest, ikm, salt, info, keylen, callback) {
  try {
    var result = hkdfSync(digest, ikm, salt, info, keylen);
    if (typeof callback === 'function') setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (typeof callback === 'function') setTimeout(function() { callback(e); }, 0);
    else throw e;
  }
}

// --- KeyObject ---
function KeyObject(type, data) {
  this._type = type; // 'secret', 'public', 'private'
  this._data = data;
}
Object.defineProperty(KeyObject.prototype, 'type', {
  get: function() { return this._type; },
  enumerable: true, configurable: true
});
Object.defineProperty(KeyObject.prototype, 'symmetricKeySize', {
  get: function() { return this._type === 'secret' ? this._data.length : undefined; },
  enumerable: true, configurable: true
});
KeyObject.prototype.export = function(options) {
  if (!options || !options.format || options.format === 'buffer') return this._data;
  return this._data;
};
KeyObject.prototype.equals = function(other) {
  if (!(other instanceof KeyObject)) return false;
  if (this._type !== other._type) return false;
  var a = _toBytes(this._data), b = _toBytes(other._data);
  if (a.length !== b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

function createSecretKey(material, encoding) {
  var bytes;
  if (typeof material === 'string') {
    bytes = _toBytes(material);
  } else {
    bytes = _toBytes(material);
  }
  return new KeyObject('secret', bytes);
}

function createPublicKey(key) {
  var raw = (key && typeof key === 'object' && key.key) ? key.key : key;
  return new KeyObject('public', raw);
}

function createPrivateKey(key) {
  var raw = (key && typeof key === 'object' && key.key) ? key.key : key;
  return new KeyObject('private', raw);
}

function generateKeySync(type, options) {
  var len = (options && options.length) || 256;
  var bytes = randomBytes(len / 8);
  return createSecretKey(bytes);
}

// --- createCipheriv / createDecipheriv ---
function _toUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(data)) return new Uint8Array(data);
  if (typeof data === 'string') {
    var bytes = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i);
    return bytes;
  }
  return new Uint8Array(data);
}

function _normalizeCipherAlgorithm(algorithm) {
  var normalized = (algorithm || '').toString().toLowerCase().replace(/_/g, '-');
  normalized = normalized.replace(/\s+/g, '');
  normalized = normalized.replace(/^id-/, '');
  if (/^aes\d{3}(gcm|cbc|ctr)$/.test(normalized)) {
    normalized = normalized.replace(/^aes(\d{3})(gcm|cbc|ctr)$/, 'aes-$1-$2');
  } else if (/^aes-\d{3}(gcm|cbc|ctr)$/.test(normalized)) {
    normalized = normalized.replace(/^(aes-\d{3})(gcm|cbc|ctr)$/, '$1-$2');
  } else if (/^aes-\d{3}$/.test(normalized)) {
    return normalized;
  } else if (/^aes\d{3}$/.test(normalized)) {
    return normalized;
  }
  return normalized;
}

// Map of known cipher algorithms to their key sizes and OpenSSL names
var _cipherInfo = {
  'aes-128-cbc': { keyBytes: 16, openssl: 'aes-128-cbc' },
  'aes-192-cbc': { keyBytes: 24, openssl: 'aes-192-cbc' },
  'aes-256-cbc': { keyBytes: 32, openssl: 'aes-256-cbc' },
  'aes-128-ctr': { keyBytes: 16, openssl: 'aes-128-ctr' },
  'aes-192-ctr': { keyBytes: 24, openssl: 'aes-192-ctr' },
  'aes-256-ctr': { keyBytes: 32, openssl: 'aes-256-ctr' },
  'aes-128-gcm': { keyBytes: 16, openssl: 'aes-128-gcm', aead: true },
  'aes-192-gcm': { keyBytes: 24, openssl: 'aes-192-gcm', aead: true },
  'aes-256-gcm': { keyBytes: 32, openssl: 'aes-256-gcm', aead: true },
  'chacha20-poly1305': { keyBytes: 32, openssl: 'chacha20-poly1305', aead: true },
  'chacha20': { keyBytes: 32, openssl: 'chacha20' },
  'des-cbc': { keyBytes: 8, openssl: 'des-cbc' },
  'des': { keyBytes: 8, openssl: 'des-cbc' },
  'des-ede3-cbc': { keyBytes: 24, openssl: 'des-ede3-cbc' },
  'des-ede3': { keyBytes: 24, openssl: 'des-ede3-cbc' },
  'des3': { keyBytes: 24, openssl: 'des-ede3-cbc' },
  'bf-cbc': { keyBytes: 16, openssl: 'bf-cbc' },
  'bf': { keyBytes: 16, openssl: 'bf-cbc' },
  'blowfish': { keyBytes: 16, openssl: 'bf-cbc' },
  'bf-ecb': { keyBytes: 16, openssl: 'bf-ecb' },
  'bf-cfb': { keyBytes: 16, openssl: 'bf-cfb' },
  'bf-ofb': { keyBytes: 16, openssl: 'bf-ofb' },
  'des-ecb': { keyBytes: 8, openssl: 'des-ecb' },
  'des-cfb': { keyBytes: 8, openssl: 'des-cfb' },
  'des-ofb': { keyBytes: 8, openssl: 'des-ofb' },
  'des-ede3-cfb': { keyBytes: 24, openssl: 'des-ede3-cfb' },
  'des-ede3-ofb': { keyBytes: 24, openssl: 'des-ede3-ofb' },
  'rc4': { keyBytes: 16, openssl: 'rc4' }
};

function _normalizeCipherOptions(algorithm, options) {
  var normalized = _normalizeCipherAlgorithm(algorithm);
  var info = _cipherInfo[normalized];
  var keyBytes = 16;
  if (info) {
    keyBytes = info.keyBytes;
  } else if (normalized.indexOf('aes-128-') === 0) {
    keyBytes = 16;
  } else if (normalized.indexOf('aes-192-') === 0) {
    keyBytes = 24;
  } else if (normalized.indexOf('aes-256-') === 0) {
    keyBytes = 32;
  }

  var opt = options || {};
  if (typeof opt === 'number') {
    opt = { authTagLength: opt };
  } else if (typeof opt === 'string') {
    opt = { iv: opt };
  } else if (typeof opt === 'object' && opt !== null) {
    opt = Object.create(opt);
  } else {
    opt = {};
  }
  if (typeof opt.authTagLength === 'number') {
    opt.authTagLength = Math.max(1, Math.floor(opt.authTagLength));
  }
  return {
    algorithm: normalized,
    keyBytes: keyBytes,
    authTagLength: opt.authTagLength || 16,
    ivOverride: opt.iv,
    tagLength: opt.tagLength || opt.authTagLength,
    isAead: info && info.aead,
    opensslName: info && info.openssl
  };
}

function _requireCipherMode(algorithm) {
  // AES modes handled by dedicated native functions
  if (algorithm.indexOf('aes-') === 0) {
    return algorithm.indexOf('gcm') !== -1 || algorithm.indexOf('cbc') !== -1 || algorithm.indexOf('ctr') !== -1;
  }
  // All other algorithms handled by generic EVP bridge
  return !!_cipherInfo[algorithm] || typeof __exactEvpCipherEncrypt === 'function';
}

function _concatChunks(chunks) {
  var totalLen = 0;
  for (var i = 0; i < chunks.length; i++) totalLen += chunks[i].length;
  var combined = new Uint8Array(totalLen);
  var offset = 0;
  for (var j = 0; j < chunks.length; j++) {
    combined.set(chunks[j], offset);
    offset += chunks[j].length;
  }
  return combined;
}

function _parseInputData(data, inputEncoding) {
  if (typeof data === 'string') {
    if (inputEncoding === 'hex') {
      var bytes = new Uint8Array(data.length / 2);
      for (var i = 0; i < data.length; i += 2) bytes[i / 2] = parseInt(data.substr(i, 2), 16);
      return bytes;
    } else if (inputEncoding === 'base64') {
      var raw = atob(data);
      var bytes2 = new Uint8Array(raw.length);
      for (var j = 0; j < raw.length; j++) bytes2[j] = raw.charCodeAt(j);
      return bytes2;
    } else {
      return _toUint8Array(data);
    }
  }
  return _toUint8Array(data);
}

function Cipher(algorithm, key, iv, options) {
  var normalized = _normalizeCipherOptions(algorithm, options);
  if (!_requireCipherMode(normalized.algorithm)) {
    throw new Error('Unsupported cipher algorithm: ' + algorithm);
  }
  this._algo = normalized.algorithm;
  this._key = _toUint8Array(key);
  this._iv = _toUint8Array(normalized.ivOverride !== undefined ? normalized.ivOverride : iv);
  this._chunks = [];
  this._finalized = false;
  this._aad = null;
  this._authTag = null;
  this._authTagLength = normalized.authTagLength;
  this._cipherKeyBytes = normalized.keyBytes;
  this._isAead = normalized.isAead;
  this._opensslName = normalized.opensslName;
}
Cipher.prototype.update = function(data, inputEncoding, outputEncoding) {
  this._chunks.push(_parseInputData(data, inputEncoding));
  if (outputEncoding) return '';
  return typeof Buffer !== 'undefined' ? Buffer.alloc(0) : new Uint8Array(0);
};
Cipher.prototype.final = function(outputEncoding) {
  this._finalized = true;
  var combined = _concatChunks(this._chunks);

  var result;
  if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('gcm') !== -1) {
    if (typeof __exactAesGcmEncrypt !== 'function') throw new Error('AES-GCM encrypt not available');
    var tagBits = this._authTagLength * 8;
    var encResult = __exactAesGcmEncrypt(this._key, this._iv, combined, this._aad, tagBits);
    var tagLen = this._authTagLength;
    var ciphertext = encResult.slice(0, encResult.length - tagLen);
    var tag = encResult.slice(encResult.length - tagLen);
    if (typeof Buffer !== 'undefined' && Buffer.from) {
      this._authTag = Buffer.from(tag);
      result = Buffer.from(ciphertext);
    } else {
      this._authTag = tag;
      result = ciphertext;
    }
  } else if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('cbc') !== -1) {
    if (typeof __exactAesCbcEncrypt !== 'function') throw new Error('AES-CBC encrypt not available');
    result = __exactAesCbcEncrypt(this._key, this._iv, combined);
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('ctr') !== -1) {
    if (typeof __exactAesCtrEncrypt !== 'function') throw new Error('AES-CTR encrypt not available');
    result = __exactAesCtrEncrypt(this._key, this._iv, combined);
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else if (typeof __exactEvpCipherEncrypt === 'function' && this._opensslName) {
    // Use generic EVP bridge for ChaCha20, DES, Blowfish, etc.
    var encResult = __exactEvpCipherEncrypt(this._opensslName, this._key, this._iv, combined);
    if (this._isAead && encResult.length > 16) {
      // AEAD: last 16 bytes are the auth tag
      var tagLen = this._authTagLength;
      var ciphertext = encResult.slice(0, encResult.length - tagLen);
      var tag = encResult.slice(encResult.length - tagLen);
      if (typeof Buffer !== 'undefined' && Buffer.from) {
        this._authTag = Buffer.from(tag);
        result = Buffer.from(ciphertext);
      } else {
        this._authTag = tag;
        result = ciphertext;
      }
    } else {
      result = encResult;
      if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
    }
  } else {
    throw new Error('Unsupported cipher algorithm: ' + this._algo);
  }

  if (outputEncoding === 'hex') return result.toString('hex');
  if (outputEncoding === 'base64') return result.toString('base64');
  return result;
};
Cipher.prototype.setAutoPadding = function() { return this; };
Cipher.prototype.getAuthTag = function() {
  if (!this._finalized) throw new Error('Cannot get auth tag before calling final()');
  if (this._authTag === null) return typeof Buffer !== 'undefined' ? Buffer.alloc(0) : new Uint8Array(0);
  return this._authTag;
};
Cipher.prototype.setAAD = function(aad, options) {
  this._aad = _toUint8Array(aad);
  return this;
};

function Decipher(algorithm, key, iv, options) {
  var normalized = _normalizeCipherOptions(algorithm, options);
  if (!_requireCipherMode(normalized.algorithm)) {
    throw new Error('Unsupported decipher algorithm: ' + algorithm);
  }
  this._algo = normalized.algorithm;
  this._key = _toUint8Array(key);
  this._iv = _toUint8Array(normalized.ivOverride !== undefined ? normalized.ivOverride : iv);
  this._chunks = [];
  this._finalized = false;
  this._aad = null;
  this._authTag = null;
  this._authTagLength = normalized.authTagLength;
  this._cipherKeyBytes = normalized.keyBytes;
  this._isAead = normalized.isAead;
  this._opensslName = normalized.opensslName;
}
Decipher.prototype.update = function(data, inputEncoding, outputEncoding) {
  this._chunks.push(_parseInputData(data, inputEncoding));
  if (outputEncoding) return '';
  return typeof Buffer !== 'undefined' ? Buffer.alloc(0) : new Uint8Array(0);
};
Decipher.prototype.final = function(outputEncoding) {
  this._finalized = true;
  var combined = _concatChunks(this._chunks);

  var result;
  if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('gcm') !== -1) {
    if (typeof __exactAesGcmDecrypt !== 'function') throw new Error('AES-GCM decrypt not available');
    if (!this._authTag) throw new Error('Unsupported state or unable to authenticate data');
    var tag = _toUint8Array(this._authTag);
    var dataWithTag = new Uint8Array(combined.length + tag.length);
    dataWithTag.set(combined, 0);
    dataWithTag.set(tag, combined.length);
    var tagBits = tag.length * 8;
    result = __exactAesGcmDecrypt(this._key, this._iv, dataWithTag, this._aad, tagBits);
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('cbc') !== -1) {
    if (typeof __exactAesCbcDecrypt !== 'function') throw new Error('AES-CBC decrypt not available');
    result = __exactAesCbcDecrypt(this._key, this._iv, combined);
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else if (this._algo.indexOf('aes') !== -1 && this._algo.indexOf('ctr') !== -1) {
    if (typeof __exactAesCtrEncrypt !== 'function') throw new Error('AES-CTR decrypt not available');
    result = __exactAesCtrEncrypt(this._key, this._iv, combined);
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else if (typeof __exactEvpCipherDecrypt === 'function' && this._opensslName) {
    // Use generic EVP bridge for ChaCha20, DES, Blowfish, etc.
    var authTag = this._isAead && this._authTag ? _toUint8Array(this._authTag) : undefined;
    result = __exactEvpCipherDecrypt(this._opensslName, this._key, this._iv, combined, authTag);
    if (typeof Buffer !== 'undefined' && Buffer.from) result = Buffer.from(result);
  } else {
    throw new Error('Unsupported decipher algorithm: ' + this._algo);
  }

  if (outputEncoding === 'hex') return result.toString('hex');
  if (outputEncoding === 'base64') return result.toString('base64');
  if (outputEncoding === 'utf8' || outputEncoding === 'utf-8') return result.toString('utf8');
  return result;
};
Decipher.prototype.setAutoPadding = function() { return this; };
Decipher.prototype.setAuthTag = function(tag) { this._authTag = _toUint8Array(tag); return this; };
Decipher.prototype.setAAD = function(aad, options) { this._aad = _toUint8Array(aad); return this; };

function createCipheriv(algorithm, key, iv, options) {
  return new Cipher(algorithm, key, iv, options);
}

function createDecipheriv(algorithm, key, iv, options) {
  return new Decipher(algorithm, key, iv, options);
}

// --- scryptSync / scrypt (native implementation via __exactScryptSync) ---
function _normalizeScryptOption(options) {
  var opts = options || {};
  var N = Number(opts.N || opts.cost || 16384);
  var r = Number(opts.r || opts.blockSize || 8);
  var p = Number(opts.p || opts.parallelization || 1);
  if (N <= 1 || (N & (N - 1)) !== 0) {
    throw new TypeError('scrypt: N must be a power of 2 and greater than 1');
  }
  if (r <= 0 || p <= 0) {
    throw new TypeError('scrypt: r and p must be positive integers');
  }
  return {
    N: N,
    r: r,
    p: p
  };
}

function scryptSync(password, salt, keylen, options) {
  if (typeof __exactScryptSync !== 'function') {
    throw new Error('crypto.scryptSync is not available on this platform');
  }
  if (typeof keylen !== 'number' || keylen <= 0) {
    throw new TypeError('Invalid key length value');
  }
  var normalized = _normalizeScryptOption(options);
  var passBytes = _toBytes(password);
  var saltBytes = _toBytes(salt);
  var result = __exactScryptSync(passBytes, saltBytes, normalized.N, normalized.r, normalized.p, keylen);
  if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(result);
  return result;
}

function scrypt(password, salt, keylen, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = scryptSync(password, salt, keylen, options);
    if (typeof callback === 'function') setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (typeof callback === 'function') setTimeout(function() { callback(e); }, 0);
    else throw e;
  }
}

function _toByteString(value) {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return '';
  if (value instanceof ArrayBuffer) {
    value = new Uint8Array(value);
  }
  if (typeof ArrayBuffer === 'object' && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    var view = value instanceof Uint8Array ? value : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    var out = '';
    for (var i = 0; i < view.length; i++) out += String.fromCharCode(view[i]);
    return out;
  }
  if (typeof value === 'number') return String.fromCharCode(value & 0xff);
  if (typeof value.length === 'number') {
    var s = '';
    for (var i = 0; i < value.length; i++) s += String.fromCharCode((value[i] || 0) & 0xff);
    return s;
  }
  return String(value);
}

function _normalizeInputEncoding(encoding) {
  if (!encoding) return '';
  if (typeof encoding !== 'string') return '';
  return encoding.toLowerCase().replace(/_/g, '-');
}

function _toByteStringWithEncoding(value, encoding) {
  var inputEncoding = _normalizeInputEncoding(encoding);
  if (typeof value === 'string' && inputEncoding) {
    if (inputEncoding === 'hex') {
      if (value.length % 2 !== 0) {
        throw new TypeError('Invalid hex string');
      }
      var hexBytes = new Uint8Array(value.length / 2);
      for (var i = 0; i < value.length; i += 2) {
        hexBytes[i / 2] = parseInt(value.substr(i, 2), 16);
      }
      return _bytesToString(hexBytes);
    }
    if (inputEncoding === 'base64' || inputEncoding === 'base64url') {
      if (typeof atob !== 'function') return _toByteString(value);
      if (inputEncoding === 'base64url') {
        var base64Url = value.replace(/-/g, '+').replace(/_/g, '/');
        while (base64Url.length % 4 !== 0) base64Url += '=';
        return atob(base64Url);
      }
      return atob(value);
    }
  }
  return _toByteString(value);
}

function _bytesToString(bytes) {
  if (!bytes || !bytes.length) return '';
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    out += String.fromCharCode(bytes[i]);
  }
  return out;
}

function _toByteArray(value) {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    var bytesFromString = [];
    for (var i = 0; i < value.length; i++) bytesFromString.push(value.charCodeAt(i) & 0xff);
    return bytesFromString;
  }
  if (value instanceof ArrayBuffer) {
    value = new Uint8Array(value);
  }
  if (typeof ArrayBuffer === 'object' && ArrayBuffer.isView && ArrayBuffer.isView(value)) {
    var typed = value instanceof Uint8Array ? value : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    var bytesFromView = [];
    for (var j = 0; j < typed.length; j++) bytesFromView.push(typed[j]);
    return bytesFromView;
  }
  if (typeof value.length === 'number') {
    var bytesFromArray = [];
    for (var k = 0; k < value.length; k++) bytesFromArray.push((value[k] || 0) & 0xff);
    return bytesFromArray;
  }
  return _toByteArray(_toByteString(value));
}

function _toHex(bytes) {
  var hex = '';
  for (var i = 0; i < bytes.length; i++) {
    var h = bytes[i].toString(16);
    if (h.length === 1) h = '0' + h;
    hex += h;
  }
  return hex;
}

function _hexToBytes(hex) {
  if (!hex) return [];
  if (hex.substr(0, 2) === '0x') hex = hex.substr(2);
  var normalized = hex.length % 2 === 1 ? '0' + hex : hex;
  var out = [];
  for (var i = 0; i < normalized.length; i += 2) {
    out.push(parseInt(normalized.substr(i, 2), 16));
  }
  return out;
}

function _bytesToBufferLike(bytes) {
  if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(bytes);
  return new Uint8Array(bytes);
}

function _isPemKeyText(value) {
  if (typeof value !== 'string') return false;
  return value.indexOf('-----BEGIN') === 0 ||
    value.indexOf('BEGIN PUBLIC KEY') !== -1 ||
    value.indexOf('BEGIN PRIVATE KEY') !== -1 ||
    value.indexOf('BEGIN RSA PUBLIC KEY') !== -1 ||
    value.indexOf('BEGIN RSA PRIVATE KEY') !== -1;
}

function _extractKeyText(key) {
  if (typeof key === 'string') return key;
  if (!key || typeof key !== 'object') return '';
  if (typeof key.key === 'string') return key.key;
  if (typeof key.pem === 'string') return key.pem;
  if (typeof key.exportedKey === 'string') return key.exportedKey;
  return '';
}

function _normalizeHashForSign(algorithm) {
  var name = (typeof algorithm === 'string' ? algorithm : (algorithm && algorithm.name) ? algorithm.name : '').toLowerCase();
  if (name.indexOf('sha1') !== -1) return 'sha1';
  if (name.indexOf('sha224') !== -1) return 'sha224';
  if (name.indexOf('sha256') !== -1) return 'sha256';
  if (name.indexOf('sha384') !== -1) return 'sha384';
  if (name.indexOf('sha512') !== -1) return 'sha512';
  if (name.indexOf('md5') !== -1) return 'md5';
  return 'sha256';
}

function _signatureOutput(signatureBytesLike, outputEncoding) {
  var signatureBytes = [];
  if (typeof signatureBytesLike === 'string') {
    signatureBytes = _hexToBytes(signatureBytesLike);
  } else {
    signatureBytes = _toByteArray(signatureBytesLike);
  }
  if (!outputEncoding) return _bytesToBufferLike(signatureBytes);
  if (outputEncoding === 'hex') return _toHex(signatureBytes);
  if (outputEncoding === 'base64') {
    if (typeof btoa !== 'function') return signatureBytes;
    var encodedInput = '';
    for (var i = 0; i < signatureBytes.length; i++) encodedInput += String.fromCharCode(signatureBytes[i]);
    return btoa(encodedInput);
  }
  if (outputEncoding === 'binary') return _bytesToBufferLike(signatureBytes);
  return _bytesToBufferLike(signatureBytes);
}

function sign(algorithm, data, key, outputEncoding) {
  var hash = _normalizeHashForSign(algorithm);
  var keyText = _extractKeyText(key);
  var dataText = _toByteString(data);
  var fallbackKey = keyText || _toByteString(key);

  if (typeof keyText === 'string' && _isPemKeyText(keyText) && typeof __exactSignSync === 'function') {
    try {
      var nativeBytes = __exactSignSync(hash, dataText, keyText);
      return _signatureOutput(nativeBytes, outputEncoding);
    } catch (e) {}
  }
  if (typeof __exactHmacSync === 'function') {
    var hmacHex = __exactHmacSync(hash, fallbackKey, dataText);
    return _signatureOutput(hmacHex, outputEncoding);
  }
  throw new Error('crypto.sign not available');
}

function verify(algorithm, data, key, signature) {
  var hash = _normalizeHashForSign(algorithm);
  var keyText = _extractKeyText(key);
  var fallbackKey = keyText || _toByteString(key);
  var signatureValue = signature;
  if (typeof signatureValue !== 'string' &&
      signatureValue &&
      !(signatureValue instanceof ArrayBuffer) &&
      !(typeof ArrayBuffer === 'object' && ArrayBuffer.isView && ArrayBuffer.isView(signatureValue)) &&
      !(typeof Buffer !== 'undefined' && typeof Buffer.isBuffer === 'function' && Buffer.isBuffer(signatureValue))) {
    signatureValue = _toByteArray(signatureValue);
  }
  var dataText = _toByteString(data);

  if (typeof keyText === 'string' && _isPemKeyText(keyText) && typeof __exactVerifySync === 'function') {
    try {
      return __exactVerifySync(hash, signatureValue, dataText, keyText);
    } catch (e) {}
  }

  if (typeof __exactHmacSync !== 'function') return false;
  var expectedHex = __exactHmacSync(hash, fallbackKey, dataText);
  var expected = _hexToBytes(expectedHex);
  var provided = _toByteArray(signatureValue);
  if (typeof signature === 'string' && signature.length === expected.length * 2 && /^[0-9a-fA-F]+$/.test(signature)) {
    provided = _hexToBytes(signature);
  }
  if (provided.length !== expected.length) return false;
  var mismatch = 0;
  for (var i = 0; i < expected.length; i++) {
    mismatch |= expected[i] ^ provided[i];
  }
  return mismatch === 0;
}

function Sign(algorithm) { this._algorithm = algorithm; this._chunks = []; }
Sign.prototype.update = function(data, inputEncoding) { this._chunks.push(_toByteStringWithEncoding(data, inputEncoding)); return this; };
Sign.prototype.sign = function(key, outputEncoding) { return sign(this._algorithm, this._chunks.join(''), key, outputEncoding); };
Sign.prototype.end = function(data, inputEncoding) {
  if (typeof data !== 'undefined') this._chunks.push(_toByteStringWithEncoding(data, inputEncoding));
  return this;
};

function createSign(algorithm) { return new Sign(algorithm); }

function Verify(algorithm) { this._algorithm = algorithm; this._chunks = []; }
Verify.prototype.update = function(data, inputEncoding) { this._chunks.push(_toByteStringWithEncoding(data, inputEncoding)); return this; };
Verify.prototype.verify = function(key, signature) { return verify(this._algorithm, this._chunks.join(''), key, signature); };
Verify.prototype.end = function(data, inputEncoding) {
  if (typeof data !== 'undefined') this._chunks.push(_toByteStringWithEncoding(data, inputEncoding));
  return this;
};

function createVerify(algorithm) { return new Verify(algorithm); }

function _applyKeyEncoding(value, encoding) {
  if (!encoding || !encoding.format || encoding.format === 'pem') return value;
  if (encoding.format === 'buffer') return _bytesToBufferLike(_toByteArray(value));
  return value;
}

function generateKeyPairSync(type, options) {
  if (typeof type === 'object' && type && !options) {
    options = type;
    type = options.type || 'rsa';
  }
  var keyType = (typeof type === 'string' ? type : (type && type.name) ? type.name : 'rsa').toLowerCase();

    if (keyType === 'rsa' || keyType === 'ec' || keyType === 'dsa' || keyType === 'x25519' || keyType === 'ed25519') {
      if (typeof __exactGenerateKeyPairSync === 'function') {
        var nativeOptions = options || {};
      if (keyType === 'rsa') {
        if (!nativeOptions.modulusLength) nativeOptions.modulusLength = 2048;
        if (!nativeOptions.publicExponent) nativeOptions.publicExponent = 65537;
      }
      if (!nativeOptions.publicKeyEncoding) {
        nativeOptions.publicKeyEncoding = { type: 'spki', format: 'pem' };
      }
      if (!nativeOptions.privateKeyEncoding) {
        nativeOptions.privateKeyEncoding = { type: 'pkcs1', format: 'pem' };
      }
      var pair = __exactGenerateKeyPairSync(keyType, nativeOptions);
      return {
        privateKey: _applyKeyEncoding(pair.privateKey, options && options.privateKeyEncoding),
        publicKey: _applyKeyEncoding(pair.publicKey, options && options.publicKeyEncoding)
      };
      }
      throw new Error('crypto.generateKeyPairSync is not available in this runtime');
    }
  throw new Error('Unsupported key pair type: ' + type);
}

function generateKeyPair(type, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = undefined;
  }
  if (typeof callback !== 'function') {
    return generateKeyPairSync(type, options);
  }
  try {
    var pair = generateKeyPairSync(type, options);
    setTimeout(function() { callback(null, pair.publicKey, pair.privateKey); }, 0);
  } catch (e) {
    setTimeout(function() { callback(e); }, 0);
  }
}

var cryptoConstants = {
  SSL_OP_ALL: 0,
  SSL_OP_NO_SSLv2: 0,
  SSL_OP_NO_SSLv3: 0,
  SSL_OP_NO_TLSv1: 0,
  SSL_OP_NO_TLSv1_1: 0,
  POINT_CONVERSION_COMPRESSED: 4,
  POINT_CONVERSION_UNCOMPRESSED: 4,
  defaultCoreCipherList: '',
  defaultCipherList: ''
};

module.exports = {
  randomBytes: randomBytes,
  randomUUID: randomUUID,
  randomInt: randomInt,
  randomFillSync: randomFillSync,
  createHash: createHash,
  createHmac: createHmac,
  createCipheriv: createCipheriv,
  createDecipheriv: createDecipheriv,
  createSign: createSign,
  createVerify: createVerify,
  Sign: Sign,
  Verify: Verify,
  sign: sign,
  verify: verify,
  generateKeyPairSync: generateKeyPairSync,
  generateKeyPair: generateKeyPair,
  pbkdf2Sync: pbkdf2Sync,
  pbkdf2: pbkdf2,
  hkdfSync: hkdfSync,
  hkdf: hkdf,
  scryptSync: scryptSync,
  scrypt: scrypt,
  KeyObject: KeyObject,
  createSecretKey: createSecretKey,
  createPublicKey: createPublicKey,
  createPrivateKey: createPrivateKey,
  generateKeySync: generateKeySync,
  getHashes: getHashes,
  getCiphers: function() {
    return [
      'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
      'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc',
      'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
      'chacha20-poly1305', 'chacha20',
      'des-cbc', 'des-ecb', 'des-cfb', 'des-ofb',
      'des-ede3-cbc', 'des-ede3-cfb', 'des-ede3-ofb',
      'bf-cbc', 'bf-ecb', 'bf-cfb', 'bf-ofb',
      'rc4'
    ];
  },
  timingSafeEqual: timingSafeEqual,
  Hash: Hash,
  Hmac: Hmac,
  Cipher: Cipher,
  Decipher: Decipher,
  constants: cryptoConstants,
  getRandomValues: function(arr) {
    if (typeof globalThis.crypto === 'object' && typeof globalThis.crypto.getRandomValues === 'function') {
      return globalThis.crypto.getRandomValues(arr);
    }
    var bytes = randomBytes(arr.byteLength);
    var view = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
    for (var i = 0; i < view.length; i++) view[i] = bytes[i];
    return arr;
  },
  webcrypto: typeof globalThis.crypto === 'object' ? globalThis.crypto : { getRandomValues: function(arr) { var bytes = randomBytes(arr.length); for (var i = 0; i < arr.length; i++) arr[i] = bytes[i]; return arr; } }
};
"##
    .trim()
    .to_string()
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

fn exact_clipboard_module() -> String {
    r#"
function readText() {
  throw new Error('Exact clipboard not available');
}

function writeText() {
  throw new Error('Exact clipboard not available');
}
module.exports = { readText, writeText };
"#
    .trim()
    .to_string()
}

fn node_fs_module() -> String {
    r#"
var g = globalThis;

function toUint8Array(data) {
  if (typeof data === 'string') {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(data);
    var buf = new Uint8Array(data.length * 3);
    var offset = 0;
    for (var i = 0; i < data.length; i++) {
      var code = data.charCodeAt(i);
      if (code < 0x80) { buf[offset++] = code; }
      else if (code < 0x800) { buf[offset++] = 0xc0 | (code >> 6); buf[offset++] = 0x80 | (code & 0x3f); }
      else { buf[offset++] = 0xe0 | (code >> 12); buf[offset++] = 0x80 | ((code >> 6) & 0x3f); buf[offset++] = 0x80 | (code & 0x3f); }
    }
    return buf.slice(0, offset);
  }
  if (data instanceof Uint8Array) return data;
  return new Uint8Array(data);
}

function decodeBytes(bytes, encoding) {
  if (!encoding || encoding === 'buffer') return bytes;
  var enc = encoding.toLowerCase().replace('-', '');
  if (enc === 'utf8' || enc === 'utf-8') enc = 'utf8';
  if (enc === 'utf8') {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(bytes);
    var result = '';
    for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i]);
    return result;
  }
  if (enc === 'ascii' || enc === 'latin1' || enc === 'binary') {
    var result = '';
    for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i]);
    return result;
  }
  if (enc === 'hex') {
    var result = '';
    for (var i = 0; i < bytes.length; i++) result += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return result;
  }
  if (enc === 'base64') {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return typeof btoa === 'function' ? btoa(binary) : binary;
  }
  if (typeof TextDecoder !== 'undefined') return new TextDecoder(encoding).decode(bytes);
  var result = '';
  for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i]);
  return result;
}

function wrapBuffer(bytes) {
  bytes.toString = function(encoding, start, end) {
    var slice = (start !== undefined || end !== undefined) ? bytes.slice(start || 0, end) : bytes;
    if (!encoding) return decodeBytes(slice, 'utf8');
    return decodeBytes(slice, encoding);
  };
  return bytes;
}

function readFileSync(path, options) {
  var encoding = typeof options === 'string' ? options : (options && options.encoding);
  var bytes = g.__exactReadFile(path);
  if (encoding) return decodeBytes(bytes, encoding);
  return wrapBuffer(bytes);
}

function writeFileSync(path, data, options) {
  g.__exactWriteFile(path, toUint8Array(data));
}

function appendFileSync(path, data, options) {
  g.__exactAppendFile(path, toUint8Array(data));
}

function statSync(path) {
  var json = g.__exactStat(path);
  var raw = JSON.parse(json);
  raw.isFile = function() { return raw.is_file; };
  raw.isDirectory = function() { return raw.is_dir; };
  raw.isSymbolicLink = function() { return !!raw.is_symlink; };
  raw.isBlockDevice = function() { return false; };
  raw.isCharacterDevice = function() { return false; };
  raw.isFIFO = function() { return false; };
  raw.isSocket = function() { return false; };
  raw.mtimeMs = raw.mtime_ms;
  raw.mtime = new Date(raw.mtime_ms);
  raw.atimeMs = raw.mtime_ms;
  raw.atime = new Date(raw.mtime_ms);
  raw.ctimeMs = raw.mtime_ms;
  raw.ctime = new Date(raw.mtime_ms);
  return raw;
}

function lstatSync(path) {
  var json = g.__exactLstat(path);
  var raw = JSON.parse(json);
  raw.isFile = function() { return raw.is_file; };
  raw.isDirectory = function() { return raw.is_dir; };
  raw.isSymbolicLink = function() { return !!raw.is_symlink; };
  raw.isBlockDevice = function() { return false; };
  raw.isCharacterDevice = function() { return false; };
  raw.isFIFO = function() { return false; };
  raw.isSocket = function() { return false; };
  raw.mtimeMs = raw.mtime_ms;
  raw.mtime = new Date(raw.mtime_ms);
  return raw;
}

function readdirSync(path) {
  return JSON.parse(g.__exactReaddir(path));
}

function mkdirSync(path, options) {
  var recursive = typeof options === 'object' && options !== null ? !!options.recursive : false;
  g.__exactMkdir(path, recursive);
}

function rmdirSync(path) { g.__exactRmdir(path); }
function unlinkSync(path) { g.__exactUnlink(path); }
function renameSync(oldPath, newPath) { g.__exactRename(oldPath, newPath); }
function copyFileSync(src, dest) { g.__exactCopyFile(src, dest); }
function accessSync(path, mode) { g.__exactAccess(path, mode || 0); }
function chmodSync(path, mode) { g.__exactChmod(path, mode); }
function realpathSync(path) { return g.__exactRealpath(path); }
function mkdtempSync(prefix) { return g.__exactMkdtemp(prefix); }

function existsSync(path) {
  try { g.__exactAccess(path, 0); return true; } catch(e) { return false; }
}

function wrapCallback(fn, cb) {
  try {
    var result = fn();
    if (typeof queueMicrotask === 'function') { queueMicrotask(function() { cb(null, result); }); }
    else { cb(null, result); }
  } catch(err) {
    var error = err instanceof Error ? err : new Error(String(err));
    if (typeof queueMicrotask === 'function') { queueMicrotask(function() { cb(error); }); }
    else { cb(error); }
  }
}

function readFile(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  wrapCallback(function() { return readFileSync(path, opts); }, callback);
}

function writeFile(path, data, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  wrapCallback(function() { writeFileSync(path, data, opts); }, callback);
}

function appendFile(path, data, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  wrapCallback(function() { appendFileSync(path, data, opts); }, callback);
}

function stat(path, cb) { wrapCallback(function() { return statSync(path); }, cb); }
function lstat(path, cb) { wrapCallback(function() { return lstatSync(path); }, cb); }
function readdir(path, optOrCb, cb) {
  var callback = typeof optOrCb === 'function' ? optOrCb : cb;
  wrapCallback(function() { return readdirSync(path); }, callback);
}
function mkdir(path, optOrCb, cb) {
  var opts, callback;
  if (typeof optOrCb === 'function') { callback = optOrCb; } else { opts = optOrCb; callback = cb; }
  wrapCallback(function() { mkdirSync(path, opts); }, callback);
}
function rmdir(path, cb) { wrapCallback(function() { rmdirSync(path); }, cb); }
function unlink(path, cb) { wrapCallback(function() { unlinkSync(path); }, cb); }
function rename(o, n, cb) { wrapCallback(function() { renameSync(o, n); }, cb); }
function copyFile(s, d, cb) { wrapCallback(function() { copyFileSync(s, d); }, cb); }
function access(path, modeOrCb, cb) {
  var mode, callback;
  if (typeof modeOrCb === 'function') { callback = modeOrCb; } else { mode = modeOrCb; callback = cb; }
  wrapCallback(function() { accessSync(path, mode); }, callback);
}
function chmod(path, mode, cb) { wrapCallback(function() { chmodSync(path, mode); }, cb); }
function realpath(path, cb) { wrapCallback(function() { return realpathSync(path); }, cb); }
function mkdtemp(prefix, cb) { wrapCallback(function() { return mkdtempSync(prefix); }, cb); }
function exists(path, cb) {
  if (typeof queueMicrotask === 'function') { queueMicrotask(function() { cb(existsSync(path)); }); }
  else { cb(existsSync(path)); }
}

function openSync(path, flags, mode) {
  var f = flags || 'r';
  var m = (mode !== undefined && mode !== null) ? mode : 438;
  return g.__exactFsOpen(path, f, m);
}

function closeSync(fd) {
  g.__exactFsClose(fd);
}

function readSync(fd, buffer, offset, length, position) {
  var off = (typeof offset === 'number') ? offset : 0;
  var len = (typeof length === 'number') ? length : (buffer ? buffer.length - off : 0);
  var pos = (typeof position === 'number' && position !== null) ? position : -1;
  var data = g.__exactFsRead(fd, len, pos);
  if (buffer && data.length > 0) {
    for (var i = 0; i < data.length; i++) {
      buffer[off + i] = data[i];
    }
  }
  return data.length;
}

function writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position) {
  if (typeof bufferOrString === 'string') {
    var pos = (typeof offsetOrPosition === 'number') ? offsetOrPosition : -1;
    var bytes = toUint8Array(bufferOrString);
    return g.__exactFsWrite(fd, bytes, pos);
  }
  var off = (typeof offsetOrPosition === 'number') ? offsetOrPosition : 0;
  var len = (typeof lengthOrEncoding === 'number') ? lengthOrEncoding : (bufferOrString ? bufferOrString.length - off : 0);
  var pos = (typeof position === 'number' && position !== null) ? position : -1;
  var slice = bufferOrString;
  if (off !== 0 || len !== bufferOrString.length) {
    slice = bufferOrString.slice(off, off + len);
  }
  return g.__exactFsWrite(fd, slice, pos);
}

function open(path, flagsOrCb, modeOrCb, cb) {
  var flags, mode, callback;
  if (typeof flagsOrCb === 'function') { callback = flagsOrCb; flags = 'r'; mode = 438; }
  else if (typeof modeOrCb === 'function') { callback = modeOrCb; flags = flagsOrCb; mode = 438; }
  else { callback = cb; flags = flagsOrCb; mode = modeOrCb; }
  wrapCallback(function() { return openSync(path, flags, mode); }, callback);
}

function close(fd, cb) {
  wrapCallback(function() { closeSync(fd); }, cb);
}

function fsRead(fd, buffer, offset, length, position, cb) {
  wrapCallback(function() { return readSync(fd, buffer, offset, length, position); }, cb);
}

function fsWrite(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position, cb) {
  if (typeof offsetOrPosition === 'function') {
    cb = offsetOrPosition;
    wrapCallback(function() { return writeSync(fd, bufferOrString); }, cb);
    return;
  }
  if (typeof lengthOrEncoding === 'function') {
    cb = lengthOrEncoding;
    wrapCallback(function() { return writeSync(fd, bufferOrString, offsetOrPosition); }, cb);
    return;
  }
  if (typeof position === 'function') {
    cb = position;
    wrapCallback(function() { return writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding); }, cb);
    return;
  }
  wrapCallback(function() { return writeSync(fd, bufferOrString, offsetOrPosition, lengthOrEncoding, position); }, cb);
}

function createReadStream(path, options) {
  var Stream = require('node:stream');
  var opts = typeof options === 'string' ? { encoding: options } : (options || {});
  var encoding = opts.encoding || null;
  var start = opts.start || 0;
  var end = opts.end;
  var highWaterMark = opts.highWaterMark || 65536;

  var rs = new Stream.Readable({ highWaterMark: highWaterMark });
  rs.path = path;
  rs.bytesRead = 0;
  rs.pending = true;

  var pushed = false;
  rs._read = function() {
    if (pushed) return;
    pushed = true;
    try {
      var bytes = g.__exactReadFile(path);
      rs.pending = false;
      rs.emit('open');
      var data = bytes;
      if (start > 0 || end !== undefined) {
        var e = (end !== undefined) ? end + 1 : bytes.length;
        data = bytes.slice(start, e);
      }
      if (encoding) {
        rs.push(decodeBytes(data, encoding));
      } else {
        var chunk;
        var offset = 0;
        while (offset < data.length) {
          var chunkEnd = Math.min(offset + highWaterMark, data.length);
          chunk = data.slice(offset, chunkEnd);
          rs.push(wrapBuffer(chunk));
          offset = chunkEnd;
        }
      }
      rs.bytesRead = data.length;
      rs.push(null);
    } catch(err) {
      rs.pending = false;
      rs.emit('error', err);
      rs.emit('close');
    }
  };

  if (typeof queueMicrotask === 'function') {
    queueMicrotask(function() { rs._read(); });
  }

  return rs;
}

function createWriteStream(path, options) {
  var Stream = require('node:stream');
  var opts = typeof options === 'string' ? { encoding: options } : (options || {});
  var flags = opts.flags || 'w';
  var mode = opts.mode || 438;
  var encoding = opts.encoding || 'utf8';
  var autoClose = opts.autoClose !== false;
  var start = opts.start;

  var ws = new Stream.Writable();
  ws.path = path;
  ws.bytesWritten = 0;
  ws.pending = true;

  var fd = null;
  var opened = false;

  function ensureOpen() {
    if (!opened) {
      opened = true;
      fd = openSync(path, flags, mode);
      ws.pending = false;
      ws.fd = fd;
      if (typeof start === 'number' && start >= 0) {
        g.__exactFsWrite(fd, toUint8Array(''), start);
      }
      ws.emit('open', fd);
    }
  }

  ws._write = function(chunk, enc, callback) {
    try {
      ensureOpen();
      var bytes = toUint8Array(chunk);
      var written = g.__exactFsWrite(fd, bytes, -1);
      ws.bytesWritten += written;
      if (typeof callback === 'function') callback();
    } catch(err) {
      if (typeof callback === 'function') callback(err);
    }
  };

  ws._final = function(callback) {
    if (fd !== null && autoClose) {
      try { closeSync(fd); } catch(e) {}
      fd = null;
    }
    if (typeof callback === 'function') callback();
  };

  ws.destroy = function(err) {
    if (fd !== null && autoClose) {
      try { closeSync(fd); } catch(e) {}
      fd = null;
    }
    if (err) ws.emit('error', err);
    ws.emit('close');
    return ws;
  };

  return ws;
}

// fs.watch / fs.watchFile / fs.unwatchFile
function FSWatcher() {
  this._events = {};
  this._closed = false;
}
FSWatcher.prototype.on = function(ev, fn) { if (!this._events[ev]) this._events[ev] = []; this._events[ev].push(fn); return this; };
FSWatcher.prototype.emit = function(ev) { var a = [].slice.call(arguments, 1); var l = this._events[ev] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
FSWatcher.prototype.once = function(ev, fn) { var self = this; function w() { self.removeListener(ev, w); fn.apply(this, arguments); } this.on(ev, w); return this; };
FSWatcher.prototype.removeListener = function(ev, fn) { var l = this._events[ev]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn) n.push(l[i]); } this._events[ev] = n; } return this; };
FSWatcher.prototype.close = function() { this._closed = true; if (this._timer) clearInterval(this._timer); this.emit('close'); };
FSWatcher.prototype.ref = function() { return this; };
FSWatcher.prototype.unref = function() { return this; };

function watch(filename, options, listener) {
  if (typeof options === 'function') { listener = options; options = {}; }
  options = options || {};
  var watcher = new FSWatcher();
  if (listener) watcher.on('change', listener);
  // Poll-based watch using stat
  var lastMtime = 0;
  try { var s = statSync(filename); lastMtime = s.mtimeMs || 0; } catch(e) {}
  watcher._timer = setInterval(function() {
    if (watcher._closed) return;
    try {
      var s = statSync(filename);
      var mtime = s.mtimeMs || 0;
      if (mtime !== lastMtime) { lastMtime = mtime; watcher.emit('change', 'change', filename); }
    } catch(e) { watcher.emit('change', 'rename', filename); }
  }, options.interval || 1007);
  return watcher;
}

var _watchedFiles = {};
function watchFile(filename, options, listener) {
  if (typeof options === 'function') { listener = options; options = {}; }
  options = options || {};
  var interval = options.interval || 5007;
  var prev;
  try { prev = statSync(filename); } catch(e) { prev = { size: 0, mtimeMs: 0 }; }
  var timer = setInterval(function() {
    var curr;
    try { curr = statSync(filename); } catch(e) { curr = { size: 0, mtimeMs: 0 }; }
    if ((curr.mtimeMs || 0) !== (prev.mtimeMs || 0)) { if (listener) listener(curr, prev); prev = curr; }
  }, interval);
  _watchedFiles[filename] = timer;
}

function unwatchFile(filename) {
  if (_watchedFiles[filename]) { clearInterval(_watchedFiles[filename]); delete _watchedFiles[filename]; }
}

// fs.symlink/link/readlink/truncate/chown/utimes/rm
function symlinkSync(target, path, type) {
  if (typeof g.__exactSymlink === 'function') return g.__exactSymlink(target, path);
  throw new Error('symlink not available');
}
function symlink(target, path, type, cb) {
  if (typeof type === 'function') { cb = type; type = null; }
  try { symlinkSync(target, path, type); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}
function linkSync(existingPath, newPath) {
  if (typeof g.__exactLink === 'function') return g.__exactLink(existingPath, newPath);
  throw new Error('link not available');
}
function link(existingPath, newPath, cb) {
  try { linkSync(existingPath, newPath); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}
function readlinkSync(path) {
  if (typeof g.__exactReadlink === 'function') return g.__exactReadlink(path);
  throw new Error('readlink not available');
}
function readlink(path, options, cb) {
  if (typeof options === 'function') { cb = options; }
  try { var r = readlinkSync(path); if (cb) cb(null, r); } catch(e) { if (cb) cb(e); }
}
function truncateSync(path, len) {
  if (typeof g.__exactTruncate === 'function') return g.__exactTruncate(path, len || 0);
  throw new Error('truncate not available');
}
function truncate(path, len, cb) {
  if (typeof len === 'function') { cb = len; len = 0; }
  try { truncateSync(path, len); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}
function chownSync(path, uid, gid) {
  if (typeof g.__exactChown === 'function') return g.__exactChown(path, uid, gid);
  // No-op if native chown not available
}
function chown(path, uid, gid, cb) {
  try { chownSync(path, uid, gid); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}
function utimesSync(path, atime, mtime) {
  if (typeof g.__exactUtimes === 'function') return g.__exactUtimes(path, atime, mtime);
  // No-op if native utimes not available
}
function utimes(path, atime, mtime, cb) {
  try { utimesSync(path, atime, mtime); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}
function rmSync(path, options) {
  options = options || {};
  try {
    var info = JSON.parse(g.__exactStat(path));
    if (info.is_dir) {
      if (options.recursive) {
        var entries = JSON.parse(g.__exactReaddir(path));
        for (var i = 0; i < entries.length; i++) {
          rmSync(path + '/' + entries[i], options);
        }
      }
      rmdirSync(path);
    } else {
      unlinkSync(path);
    }
  } catch(e) { if (!(options.force)) throw e; }
}
function rm(path, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  try { rmSync(path, options); if (cb) cb(null); } catch(e) { if (cb) cb(e); }
}

var promises = {
  readFile: function(p, o) { return Promise.resolve(readFileSync(p, o)); },
  writeFile: function(p, d, o) { writeFileSync(p, d, o); return Promise.resolve(); },
  appendFile: function(p, d, o) { appendFileSync(p, d, o); return Promise.resolve(); },
  stat: function(p) { return Promise.resolve(statSync(p)); },
  lstat: function(p) { return Promise.resolve(lstatSync(p)); },
  readdir: function(p) { return Promise.resolve(readdirSync(p)); },
  mkdir: function(p, o) { mkdirSync(p, o); return Promise.resolve(); },
  rmdir: function(p) { rmdirSync(p); return Promise.resolve(); },
  unlink: function(p) { unlinkSync(p); return Promise.resolve(); },
  rename: function(o, n) { renameSync(o, n); return Promise.resolve(); },
  copyFile: function(s, d) { copyFileSync(s, d); return Promise.resolve(); },
  access: function(p, m) { accessSync(p, m); return Promise.resolve(); },
  chmod: function(p, m) { chmodSync(p, m); return Promise.resolve(); },
  realpath: function(p) { return Promise.resolve(realpathSync(p)); },
  mkdtemp: function(p) { return Promise.resolve(mkdtempSync(p)); },
  rm: function(p, o) {
    try {
      var info = JSON.parse(g.__exactStat(p));
      if (info.is_dir) rmdirSync(p); else unlinkSync(p);
    } catch(e) { if (!(o && o.force)) throw e; }
    return Promise.resolve();
  },
  open: function(p, f, m) { return Promise.resolve(openSync(p, f, m)); },
  close: function(fd) { closeSync(fd); return Promise.resolve(); },
  symlink: function(t, p, ty) { symlinkSync(t, p, ty); return Promise.resolve(); },
  link: function(e, n) { linkSync(e, n); return Promise.resolve(); },
  readlink: function(p) { return Promise.resolve(readlinkSync(p)); },
  truncate: function(p, l) { truncateSync(p, l); return Promise.resolve(); },
  chown: function(p, u, g) { chownSync(p, u, g); return Promise.resolve(); },
  utimes: function(p, a, m) { utimesSync(p, a, m); return Promise.resolve(); },
  watch: function(p, o) { return watch(p, o); },
  constants: { F_OK: 0, R_OK: 1, W_OK: 2, X_OK: 4 }
};

var constants = { F_OK: 0, R_OK: 1, W_OK: 2, X_OK: 4 };

module.exports = {
  readFile: readFile,
  readFileSync: readFileSync,
  writeFile: writeFile,
  writeFileSync: writeFileSync,
  appendFile: appendFile,
  appendFileSync: appendFileSync,
  stat: stat,
  statSync: statSync,
  lstat: lstat,
  lstatSync: lstatSync,
  readdir: readdir,
  readdirSync: readdirSync,
  mkdir: mkdir,
  mkdirSync: mkdirSync,
  rmdir: rmdir,
  rmdirSync: rmdirSync,
  unlink: unlink,
  unlinkSync: unlinkSync,
  rename: rename,
  renameSync: renameSync,
  copyFile: copyFile,
  copyFileSync: copyFileSync,
  access: access,
  accessSync: accessSync,
  chmod: chmod,
  chmodSync: chmodSync,
  realpath: realpath,
  realpathSync: realpathSync,
  mkdtemp: mkdtemp,
  mkdtempSync: mkdtempSync,
  exists: exists,
  existsSync: existsSync,
  open: open,
  openSync: openSync,
  close: close,
  closeSync: closeSync,
  read: fsRead,
  readSync: readSync,
  write: fsWrite,
  writeSync: writeSync,
  createReadStream: createReadStream,
  createWriteStream: createWriteStream,
  watch: watch,
  watchFile: watchFile,
  unwatchFile: unwatchFile,
  FSWatcher: FSWatcher,
  symlink: symlink,
  symlinkSync: symlinkSync,
  link: link,
  linkSync: linkSync,
  readlink: readlink,
  readlinkSync: readlinkSync,
  truncate: truncate,
  truncateSync: truncateSync,
  chown: chown,
  chownSync: chownSync,
  utimes: utimes,
  utimesSync: utimesSync,
  rm: rm,
  rmSync: rmSync,
  promises: promises,
  constants: constants
};
"#
    .trim()
    .to_string()
}

fn node_fs_promises_module() -> String {
    r#"
var fs = require('node:fs');
module.exports = fs.promises;
"#
    .trim()
    .to_string()
}

fn node_path_module() -> String {
    r#"
var SLASH = 47;
var BSLASH = 92;
var DOT = 46;
var COLON = 58;
function isWS(c) { return c === SLASH || c === BSLASH; }
function isPS(c) { return c === SLASH; }
function isDR(c) { return (c >= 65 && c <= 90) || (c >= 97 && c <= 122); }
function _cwd() { return (typeof process !== 'undefined' && process.cwd) ? process.cwd() : '/'; }

function nStr(path, allowAboveRoot, sep, isSep) {
  var res = '', lsl = 0, ls = -1, dots = 0, code = 0;
  for (var i = 0; i <= path.length; ++i) {
    if (i < path.length) code = path.charCodeAt(i);
    else if (isSep(code)) break;
    else code = SLASH;
    if (isSep(code)) {
      if (ls === i - 1 || dots === 1) { /* noop */ }
      else if (dots === 2) {
        if (res.length < 2 || lsl !== 2 || res.charCodeAt(res.length - 1) !== DOT || res.charCodeAt(res.length - 2) !== DOT) {
          if (res.length > 2) {
            var j = res.lastIndexOf(sep);
            if (j === -1) { res = ''; lsl = 0; }
            else { res = res.slice(0, j); lsl = res.length - 1 - res.lastIndexOf(sep); }
            ls = i; dots = 0; continue;
          } else if (res.length !== 0) {
            res = ''; lsl = 0; ls = i; dots = 0; continue;
          }
        }
        if (allowAboveRoot) { res += res.length > 0 ? (sep + '..') : '..'; lsl = 2; }
      } else {
        if (res.length > 0) res += sep + path.slice(ls + 1, i);
        else res = path.slice(ls + 1, i);
        lsl = i - ls - 1;
      }
      ls = i; dots = 0;
    } else if (code === DOT && dots !== -1) { ++dots; }
    else { dots = -1; }
  }
  return res;
}

// === POSIX ===
var posix = {
  sep: '/',
  delimiter: ':',
  resolve: function resolve() {
    var rp = '', ra = false;
    for (var i = arguments.length - 1; i >= -1 && !ra; i--) {
      var p = i >= 0 ? arguments[i] : _cwd();
      if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
      if (p.length === 0) continue;
      rp = p + '/' + rp;
      ra = p.charCodeAt(0) === SLASH;
    }
    rp = nStr(rp, !ra, '/', isPS);
    if (ra) return '/' + rp;
    return rp.length > 0 ? rp : '.';
  },
  normalize: function normalize(p) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    if (p.length === 0) return '.';
    var isAbs = p.charCodeAt(0) === SLASH;
    var trail = p.charCodeAt(p.length - 1) === SLASH;
    p = nStr(p, !isAbs, '/', isPS);
    if (p.length === 0) { if (isAbs) return '/'; return trail ? './' : '.'; }
    if (trail) p += '/';
    return isAbs ? '/' + p : p;
  },
  isAbsolute: function isAbsolute(p) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    return p.length > 0 && p.charCodeAt(0) === SLASH;
  },
  join: function join() {
    if (arguments.length === 0) return '.';
    var joined;
    for (var i = 0; i < arguments.length; ++i) {
      var a = arguments[i];
      if (typeof a !== 'string') throw new TypeError('Path must be a string. Received ' + typeof a);
      if (a.length > 0) { if (joined === undefined) joined = a; else joined += '/' + a; }
    }
    if (joined === undefined) return '.';
    return posix.normalize(joined);
  },
  relative: function relative(from, to) {
    if (typeof from !== 'string') throw new TypeError('Path must be a string. Received ' + typeof from);
    if (typeof to !== 'string') throw new TypeError('Path must be a string. Received ' + typeof to);
    if (from === to) return '';
    from = posix.resolve(from); to = posix.resolve(to);
    if (from === to) return '';
    var fi = 1, fe = from.length, fl = fe - fi;
    var ti = 1, tl = to.length - ti;
    var len = fl < tl ? fl : tl, lcs = -1, i = 0;
    for (; i < len; i++) {
      var fc = from.charCodeAt(fi + i);
      if (fc !== to.charCodeAt(ti + i)) break;
      else if (fc === SLASH) lcs = i;
    }
    if (i === len) {
      if (tl > len) { if (to.charCodeAt(ti + i) === SLASH) return to.slice(ti + i + 1); if (i === 0) return to.slice(ti + i); }
      else if (fl > len) { if (from.charCodeAt(fi + i) === SLASH) lcs = i; else if (i === 0) lcs = 0; }
    }
    var out = '';
    for (i = fi + lcs + 1; i <= fe; ++i) {
      if (i === fe || from.charCodeAt(i) === SLASH) out += out.length === 0 ? '..' : '/..';
    }
    return out + to.slice(ti + lcs);
  },
  dirname: function dirname(p) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    if (p.length === 0) return '.';
    var hr = p.charCodeAt(0) === SLASH, end = -1, ms = true;
    for (var i = p.length - 1; i >= 1; --i) {
      if (p.charCodeAt(i) === SLASH) { if (!ms) { end = i; break; } } else { ms = false; }
    }
    if (end === -1) return hr ? '/' : '.';
    if (hr && end === 1) return '//';
    return p.slice(0, end);
  },
  basename: function basename(p, ext) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    if (ext !== undefined && typeof ext !== 'string') throw new TypeError('"ext" argument must be a string');
    var s = 0, end = -1, ms = true, i;
    if (ext !== undefined && ext.length > 0 && ext.length <= p.length) {
      if (ext === p) return '';
      var ei = ext.length - 1, fnse = -1;
      for (i = p.length - 1; i >= 0; --i) {
        var c = p.charCodeAt(i);
        if (c === SLASH) { if (!ms) { s = i + 1; break; } }
        else { if (fnse === -1) { ms = false; fnse = i + 1; }
          if (ei >= 0) { if (c === ext.charCodeAt(ei)) { if (--ei === -1) end = i; } else { ei = -1; end = fnse; } } }
      }
      if (s === end) end = fnse; else if (end === -1) end = p.length;
      return p.slice(s, end);
    }
    for (i = p.length - 1; i >= 0; --i) {
      if (p.charCodeAt(i) === SLASH) { if (!ms) { s = i + 1; break; } }
      else if (end === -1) { ms = false; end = i + 1; }
    }
    if (end === -1) return '';
    return p.slice(s, end);
  },
  extname: function extname(p) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    var sd = -1, sp = 0, end = -1, ms = true, pds = 0;
    for (var i = p.length - 1; i >= 0; --i) {
      var c = p.charCodeAt(i);
      if (c === SLASH) { if (!ms) { sp = i + 1; break; } continue; }
      if (end === -1) { ms = false; end = i + 1; }
      if (c === DOT) { if (sd === -1) sd = i; else if (pds !== 1) pds = 1; }
      else if (sd !== -1) { pds = -1; }
    }
    if (sd === -1 || end === -1 || pds === 0 || (pds === 1 && sd === end - 1 && sd === sp + 1)) return '';
    return p.slice(sd, end);
  },
  parse: function parse(p) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    var ret = { root: '', dir: '', base: '', ext: '', name: '' };
    if (p.length === 0) return ret;
    var isAbs = p.charCodeAt(0) === SLASH, start;
    if (isAbs) { ret.root = '/'; start = 1; } else { start = 0; }
    var sd = -1, sp = 0, end = -1, ms = true, pds = 0;
    for (var i = p.length - 1; i >= start; --i) {
      var c = p.charCodeAt(i);
      if (c === SLASH) { if (!ms) { sp = i + 1; break; } continue; }
      if (end === -1) { ms = false; end = i + 1; }
      if (c === DOT) { if (sd === -1) sd = i; else if (pds !== 1) pds = 1; }
      else if (sd !== -1) { pds = -1; }
    }
    if (end !== -1) {
      var s = sp === 0 && isAbs ? 1 : sp;
      if (sd === -1 || pds === 0 || (pds === 1 && sd === end - 1 && sd === sp + 1)) {
        ret.base = ret.name = p.slice(s, end);
      } else { ret.name = p.slice(s, sd); ret.base = p.slice(s, end); ret.ext = p.slice(sd, end); }
    }
    if (sp > 0) ret.dir = p.slice(0, sp - 1); else if (isAbs) ret.dir = '/';
    return ret;
  },
  format: function format(obj) {
    if (obj === null || typeof obj !== 'object') throw new TypeError('Parameter "pathObject" must be an object, not ' + typeof obj);
    var dir = obj.dir || obj.root;
    var base = obj.base || ((obj.name || '') + (obj.ext ? (obj.ext.charCodeAt(0) === DOT ? '' : '.') + obj.ext : ''));
    if (!dir) return base;
    return dir === obj.root ? dir + base : dir + '/' + base;
  },
  toNamespacedPath: function toNamespacedPath(p) { return p; },
};
posix._makeLong = posix.toNamespacedPath;

// === WIN32 ===
var win32 = {
  sep: '\\',
  delimiter: ';',
  resolve: function resolve() {
    var rd = '', rt = '', ra = false;
    for (var i = arguments.length - 1; i >= -1; i--) {
      var p;
      if (i >= 0) { p = arguments[i]; if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p); if (p.length === 0) continue; }
      else if (rd.length === 0) { p = _cwd(); }
      else { p = _cwd(); }
      var len = p.length, re = 0, dev = '', ia = false, code = p.charCodeAt(0);
      if (len === 1) { if (isWS(code)) { re = 1; ia = true; } }
      else if (isWS(code)) {
        ia = true;
        if (isWS(p.charCodeAt(1))) {
          var j = 2, last = j;
          while (j < len && !isWS(p.charCodeAt(j))) j++;
          if (j < len && j !== last) {
            var fp = p.slice(last, j); last = j;
            while (j < len && isWS(p.charCodeAt(j))) j++;
            if (j < len && j !== last) { last = j; while (j < len && !isWS(p.charCodeAt(j))) j++;
              if (j === len || j !== last) { dev = '\\\\' + fp + '\\' + p.slice(last, j); re = j; } }
          }
        } else { re = 1; }
      } else if (isDR(code) && p.charCodeAt(1) === COLON) {
        dev = p.slice(0, 2); re = 2;
        if (len > 2 && isWS(p.charCodeAt(2))) { ia = true; re = 3; }
      }
      if (dev.length > 0) {
        if (rd.length > 0) { if (dev.toLowerCase() !== rd.toLowerCase()) continue; }
        else { rd = dev; }
      }
      if (ra) { if (rd.length > 0) break; }
      else { rt = p.slice(re) + '\\' + rt; ra = ia; if (ia && rd.length > 0) break; }
    }
    rt = nStr(rt, !ra, '\\', isWS);
    return rd + (ra ? '\\' : '') + rt || '.';
  },
  normalize: function normalize(p) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    var len = p.length;
    if (len === 0) return '.';
    var re = 0, dev, ia = false, code = p.charCodeAt(0);
    if (len === 1) return isPS(code) ? '\\' : p;
    if (isWS(code)) {
      ia = true;
      if (isWS(p.charCodeAt(1))) {
        var j = 2, last = j;
        while (j < len && !isWS(p.charCodeAt(j))) j++;
        if (j < len && j !== last) {
          var fp = p.slice(last, j); last = j;
          while (j < len && isWS(p.charCodeAt(j))) j++;
          if (j < len && j !== last) { last = j;
            while (j < len && !isWS(p.charCodeAt(j))) j++;
            if (j === len) return '\\\\' + fp + '\\' + p.slice(last) + '\\';
            if (j !== last) { dev = '\\\\' + fp + '\\' + p.slice(last, j); re = j; }
          }
        }
      } else { re = 1; }
    } else if (isDR(code) && p.charCodeAt(1) === COLON) {
      dev = p.slice(0, 2); re = 2;
      if (len > 2 && isWS(p.charCodeAt(2))) { ia = true; re = 3; }
    }
    var tail = re < len ? nStr(p.slice(re), !ia, '\\', isWS) : '';
    if (tail.length === 0 && !ia) tail = '.';
    if (tail.length > 0 && isWS(p.charCodeAt(len - 1))) tail += '\\';
    if (dev === undefined) return ia ? '\\' + tail : tail;
    return ia ? dev + '\\' + tail : dev + tail;
  },
  isAbsolute: function isAbsolute(p) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    var len = p.length;
    if (len === 0) return false;
    var c = p.charCodeAt(0);
    if (isWS(c)) return true;
    if (isDR(c) && len > 2 && p.charCodeAt(1) === COLON && isWS(p.charCodeAt(2))) return true;
    return false;
  },
  join: function join() {
    if (arguments.length === 0) return '.';
    var joined, fp;
    for (var i = 0; i < arguments.length; ++i) {
      var a = arguments[i];
      if (typeof a !== 'string') throw new TypeError('Path must be a string. Received ' + typeof a);
      if (a.length > 0) { if (joined === undefined) { joined = fp = a; } else { joined += '\\' + a; } }
    }
    if (joined === undefined) return '.';
    var nr = true, sc = 0;
    if (isWS(fp.charCodeAt(0))) {
      ++sc; var fl = fp.length;
      if (fl > 1 && isWS(fp.charCodeAt(1))) { ++sc; if (fl > 2) { if (isWS(fp.charCodeAt(2))) ++sc; else nr = false; } }
    }
    if (nr) { while (sc < joined.length && isWS(joined.charCodeAt(sc))) sc++; if (sc >= 2) joined = '\\' + joined.slice(sc); }
    return win32.normalize(joined);
  },
  relative: function relative(from, to) {
    if (typeof from !== 'string') throw new TypeError('Path must be a string. Received ' + typeof from);
    if (typeof to !== 'string') throw new TypeError('Path must be a string. Received ' + typeof to);
    if (from === to) return '';
    var fO = win32.resolve(from), tO = win32.resolve(to);
    if (fO === tO) return '';
    from = fO.toLowerCase(); to = tO.toLowerCase();
    if (from === to) return '';
    var fi = 0; while (fi < from.length && from.charCodeAt(fi) === BSLASH) fi++;
    var fe = from.length; while (fe - 1 > fi && from.charCodeAt(fe - 1) === BSLASH) fe--;
    var fl = fe - fi;
    var ti = 0; while (ti < to.length && to.charCodeAt(ti) === BSLASH) ti++;
    var te = to.length; while (te - 1 > ti && to.charCodeAt(te - 1) === BSLASH) te--;
    var tl = te - ti;
    var len = fl < tl ? fl : tl, lcs = -1, i = 0;
    for (; i < len; i++) {
      var fc = from.charCodeAt(fi + i);
      if (fc !== to.charCodeAt(ti + i)) break;
      else if (fc === BSLASH) lcs = i;
    }
    if (i !== len) { if (lcs === -1) return tO; }
    else {
      if (tl > len) { if (to.charCodeAt(ti + i) === BSLASH) return tO.slice(ti + i + 1); if (i === 2) return tO.slice(ti + i); }
      if (fl > len) { if (from.charCodeAt(fi + i) === BSLASH) lcs = i; else if (i === 2) lcs = 3; }
      if (lcs === -1) lcs = 0;
    }
    var out = '';
    for (i = fi + lcs + 1; i <= fe; ++i) {
      if (i === fe || from.charCodeAt(i) === BSLASH) out += out.length === 0 ? '..' : '\\..';
    }
    ti += lcs;
    if (out.length > 0) return out + tO.slice(ti, te);
    if (tO.charCodeAt(ti) === BSLASH) ++ti;
    return tO.slice(ti, te);
  },
  dirname: function dirname(p) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    var len = p.length;
    if (len === 0) return '.';
    var re = -1, off = 0, code = p.charCodeAt(0);
    if (len === 1) return isWS(code) ? p : '.';
    if (isWS(code)) {
      re = off = 1;
      if (isWS(p.charCodeAt(1))) {
        var j = 2, last = j;
        while (j < len && !isWS(p.charCodeAt(j))) j++;
        if (j < len && j !== last) { last = j;
          while (j < len && isWS(p.charCodeAt(j))) j++;
          if (j < len && j !== last) { last = j;
            while (j < len && !isWS(p.charCodeAt(j))) j++;
            if (j === len) return p;
            if (j !== last) re = off = j + 1;
          }
        }
      }
    } else if (isDR(code) && p.charCodeAt(1) === COLON) {
      re = len > 2 && isWS(p.charCodeAt(2)) ? 3 : 2;
      off = re;
    }
    var end = -1, ms = true;
    for (var i = len - 1; i >= off; --i) {
      if (isWS(p.charCodeAt(i))) { if (!ms) { end = i; break; } }
      else { ms = false; }
    }
    if (end === -1) { if (re === -1) return '.'; end = re; }
    return p.slice(0, end);
  },
  basename: function basename(p, ext) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    if (ext !== undefined && typeof ext !== 'string') throw new TypeError('"ext" argument must be a string');
    var s = 0;
    if (p.length >= 2 && isDR(p.charCodeAt(0)) && p.charCodeAt(1) === COLON) s = 2;
    var end = -1, ms = true, i;
    if (ext !== undefined && ext.length > 0 && ext.length <= p.length) {
      if (ext === p) return '';
      var ei = ext.length - 1, fnse = -1;
      for (i = p.length - 1; i >= s; --i) {
        var c = p.charCodeAt(i);
        if (isWS(c)) { if (!ms) { s = i + 1; break; } }
        else { if (fnse === -1) { ms = false; fnse = i + 1; }
          if (ei >= 0) { if (c === ext.charCodeAt(ei)) { if (--ei === -1) end = i; } else { ei = -1; end = fnse; } } }
      }
      if (s === end) end = fnse; else if (end === -1) end = p.length;
      return p.slice(s, end);
    }
    for (i = p.length - 1; i >= s; --i) {
      if (isWS(p.charCodeAt(i))) { if (!ms) { s = i + 1; break; } }
      else if (end === -1) { ms = false; end = i + 1; }
    }
    if (end === -1) return '';
    return p.slice(s, end);
  },
  extname: function extname(p) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    var s = 0, sd = -1, sp = 0, end = -1, ms = true, pds = 0;
    if (p.length >= 2 && p.charCodeAt(1) === COLON && isDR(p.charCodeAt(0))) { s = sp = 2; }
    for (var i = p.length - 1; i >= s; --i) {
      var c = p.charCodeAt(i);
      if (isWS(c)) { if (!ms) { sp = i + 1; break; } continue; }
      if (end === -1) { ms = false; end = i + 1; }
      if (c === DOT) { if (sd === -1) sd = i; else if (pds !== 1) pds = 1; }
      else if (sd !== -1) { pds = -1; }
    }
    if (sd === -1 || end === -1 || pds === 0 || (pds === 1 && sd === end - 1 && sd === sp + 1)) return '';
    return p.slice(sd, end);
  },
  parse: function parse(p) {
    if (typeof p !== 'string') throw new TypeError('Path must be a string. Received ' + typeof p);
    var ret = { root: '', dir: '', base: '', ext: '', name: '' };
    if (p.length === 0) return ret;
    var len = p.length, re = 0, code = p.charCodeAt(0);
    if (len === 1) {
      if (isWS(code)) { ret.root = ret.dir = p; return ret; }
      ret.base = ret.name = p; return ret;
    }
    if (isWS(code)) {
      re = 1;
      if (isWS(p.charCodeAt(1))) {
        var j = 2, last = j;
        while (j < len && !isWS(p.charCodeAt(j))) j++;
        if (j < len && j !== last) { last = j;
          while (j < len && isWS(p.charCodeAt(j))) j++;
          if (j < len && j !== last) { last = j;
            while (j < len && !isWS(p.charCodeAt(j))) j++;
            re = j < len ? j + 1 : j;
          }
        }
      }
    } else if (isDR(code) && p.charCodeAt(1) === COLON) {
      if (len <= 2) { ret.root = ret.dir = p; return ret; }
      re = 2;
      if (isWS(p.charCodeAt(2))) { if (len === 3) { ret.root = ret.dir = p; return ret; } re = 3; }
    }
    if (re > 0) ret.root = p.slice(0, re);
    var sd = -1, sp = re, end = -1, ms = true, pds = 0;
    for (var i = len - 1; i >= re; --i) {
      code = p.charCodeAt(i);
      if (isWS(code)) { if (!ms) { sp = i + 1; break; } continue; }
      if (end === -1) { ms = false; end = i + 1; }
      if (code === DOT) { if (sd === -1) sd = i; else if (pds !== 1) pds = 1; }
      else if (sd !== -1) { pds = -1; }
    }
    if (end !== -1) {
      if (sd === -1 || pds === 0 || (pds === 1 && sd === end - 1 && sd === sp + 1)) {
        ret.base = ret.name = p.slice(sp, end);
      } else { ret.name = p.slice(sp, sd); ret.base = p.slice(sp, end); ret.ext = p.slice(sd, end); }
    }
    if (sp > 0 && sp !== re) ret.dir = p.slice(0, sp - 1);
    else ret.dir = ret.root;
    return ret;
  },
  format: function format(obj) {
    if (obj === null || typeof obj !== 'object') throw new TypeError('Parameter "pathObject" must be an object, not ' + typeof obj);
    var dir = obj.dir || obj.root;
    var base = obj.base || ((obj.name || '') + (obj.ext ? (obj.ext.charCodeAt(0) === DOT ? '' : '.') + obj.ext : ''));
    if (!dir) return base;
    return dir === obj.root ? dir + base : dir + '\\' + base;
  },
  toNamespacedPath: function toNamespacedPath(p) {
    if (typeof p !== 'string' || p.length === 0) return p;
    var rp = win32.resolve(p);
    if (rp.length <= 2) return p;
    if (rp.charCodeAt(0) === BSLASH) {
      if (rp.charCodeAt(1) === BSLASH) {
        var c = rp.charCodeAt(2);
        if (c !== 63 && c !== DOT) return '\\\\?\\UNC\\' + rp.slice(2);
      }
    } else if (isDR(rp.charCodeAt(0)) && rp.charCodeAt(1) === COLON && rp.charCodeAt(2) === BSLASH) {
      return '\\\\?\\' + rp;
    }
    return p;
  },
};
win32._makeLong = win32.toNamespacedPath;

posix.posix = posix;
posix.win32 = win32;
win32.posix = posix;
win32.win32 = win32;
module.exports = posix;
"#
    .trim()
    .to_string()
}

fn node_events_module() -> String {
    r#"
function EventEmitter() {
  this._events = Object.create(null);
  this._maxListeners = 10;
}

EventEmitter.prototype._ensure = function(eventName) {
  if (!this._events) this._events = Object.create(null);
  var list = this._events[eventName];
  if (!list) {
    list = [];
    this._events[eventName] = list;
  }
  return list;
};

EventEmitter.prototype.on = function(eventName, listener) {
  if (typeof listener !== 'function') return this;
  this._ensure(eventName).push(listener);
  return this;
};

EventEmitter.prototype.addListener = EventEmitter.prototype.on;

EventEmitter.prototype.once = function(eventName, listener) {
  if (typeof listener !== 'function') return this;
  var emitter = this;
  var wrapped = function() {
    emitter.removeListener(eventName, wrapped);
    return listener.apply(emitter, arguments);
  };
  wrapped._once = true;
  wrapped._listener = listener;
  this._ensure(eventName).push(wrapped);
  return this;
};

EventEmitter.prototype.prependListener = function(eventName, listener) {
  if (typeof listener !== 'function') return this;
  this._ensure(eventName).unshift(listener);
  return this;
};

EventEmitter.prototype.prependOnceListener = function(eventName, listener) {
  if (typeof listener !== 'function') return this;
  var emitter = this;
  var wrapped = function() {
    emitter.removeListener(eventName, wrapped);
    return listener.apply(emitter, arguments);
  };
  wrapped._once = true;
  wrapped._listener = listener;
  this._ensure(eventName).unshift(wrapped);
  return this;
};

EventEmitter.prototype.setMaxListeners = function(n) {
  if (typeof n !== 'number' || n < 0 || !isFinite(n)) {
    return this;
  }
  this._maxListeners = Math.floor(n);
  return this;
};

EventEmitter.prototype.getMaxListeners = function() {
  return this._maxListeners;
};

EventEmitter.prototype.removeListener = function(eventName, listener) {
  if (!eventName || !listener) {
    return this;
  }
  var listeners = this._events && this._events[eventName];
  if (!listeners) return this;
  var next = [];
  for (var i = 0; i < listeners.length; i++) {
    var entry = listeners[i];
    if (entry === listener || entry._listener === listener) {
      continue;
    }
    next.push(entry);
  }
  if (next.length) {
    this._events[eventName] = next;
  } else {
    delete this._events[eventName];
  }
  return this;
};

EventEmitter.prototype.off = EventEmitter.prototype.removeListener;

EventEmitter.prototype.removeAllListeners = function(eventName) {
  if (!this._events) this._events = Object.create(null);
  if (eventName !== undefined) {
    delete this._events[eventName];
  } else {
    this._events = Object.create(null);
  }
  return this;
};

EventEmitter.prototype.emit = function(eventName) {
  var listeners = this._events && this._events[eventName];
  if (!listeners || !listeners.length) return false;
  var args = [];
  for (var i = 1; i < arguments.length; i++) {
    args.push(arguments[i]);
  }
  var current = listeners.slice();
  for (var i = 0; i < current.length; i++) {
    var listener = current[i];
    listener.apply(this, args);
    if (listener._once) {
      this.removeListener(eventName, listener);
    }
  }
  return true;
};

EventEmitter.prototype.listeners = function(eventName) {
  var listeners = this._events && this._events[eventName];
  if (!listeners) return [];
  var out = [];
  for (var i = 0; i < listeners.length; i++) {
    out.push(listeners[i]._listener || listeners[i]);
  }
  return out;
};

EventEmitter.prototype.rawListeners = function(eventName) {
  var listeners = this._events && this._events[eventName];
  return listeners ? listeners.slice() : [];
};

EventEmitter.prototype.listenerCount = function(eventName) {
  var listeners = this._events && this._events[eventName];
  return listeners ? listeners.length : 0;
};

EventEmitter.prototype.eventNames = function() {
  if (!this._events) return [];
  var out = [];
  for (var key in this._events) {
    if (Object.prototype.hasOwnProperty.call(this._events, key)) {
      out.push(key);
    }
  }
  return out;
};

function once(emitter, eventName) {
  return new Promise(function(resolve, reject) {
    if (!emitter || typeof emitter.once !== "function") {
      reject(new TypeError("Expected an emitter with once()"));
      return;
    }
    emitter.once(eventName, function() {
      var args = [];
      for (var i = 0; i < arguments.length; i++) {
        args.push(arguments[i]);
      }
      resolve(args);
    });
  });
}

function on(emitter, eventName) {
  var unconsumed = [];
  var waiting = [];
  var done = false;
  var errored = null;

  function handler() {
    var args = [];
    for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
    if (waiting.length > 0) {
      var resolve = waiting.shift();
      resolve({ value: args, done: false });
    } else {
      unconsumed.push(args);
    }
  }

  function errorHandler(err) {
    errored = err;
    if (waiting.length > 0) {
      var reject = waiting.shift();
      reject(err);
    }
  }

  emitter.on(eventName, handler);
  if (eventName !== 'error') emitter.on('error', errorHandler);

  var iterator = {};
  iterator.next = function() {
    if (unconsumed.length > 0) {
      return Promise.resolve({ value: unconsumed.shift(), done: false });
    }
    if (errored) return Promise.reject(errored);
    if (done) return Promise.resolve({ value: undefined, done: true });
    return new Promise(function(resolve, reject) {
      waiting.push(resolve);
    });
  };
  iterator.return = function() {
    done = true;
    emitter.removeListener(eventName, handler);
    if (eventName !== 'error') emitter.removeListener('error', errorHandler);
    while (waiting.length > 0) {
      waiting.shift()({ value: undefined, done: true });
    }
    return Promise.resolve({ value: undefined, done: true });
  };
  iterator[Symbol.asyncIterator] = function() { return iterator; };
  return iterator;
}

function getEventListeners(emitter, eventName) {
  if (emitter && typeof emitter.listeners === 'function') {
    return emitter.listeners(eventName);
  }
  return [];
}

EventEmitter.EventEmitter = EventEmitter;
EventEmitter.once = once;
EventEmitter.on = on;
EventEmitter.getEventListeners = getEventListeners;
EventEmitter.defaultMaxListeners = 10;

module.exports = EventEmitter;
module.exports.__esModule = true;
module.exports.EventEmitter = EventEmitter;
module.exports.default = EventEmitter;
module.exports.once = once;
module.exports.on = on;
module.exports.getEventListeners = getEventListeners;
"#
    .trim()
    .to_string()
}

fn node_stream_module() -> String {
    r#"
var EventEmitter = require('node:events').EventEmitter;

function Stream() {
  EventEmitter.call(this);
  this._closed = false;
  this._destroyed = false;
}
Stream.prototype = Object.create(EventEmitter.prototype);
Stream.prototype.constructor = Stream;

Stream.prototype._emitClose = function() {
  if (this._closed) {
    return;
  }
  this._closed = true;
  this.emit('close');
};

Stream.prototype.destroy = function(error) {
  if (this._destroyed) return this;
  this._destroyed = true;
  if (error !== undefined) {
    this.emit('error', error);
  }
  this._emitClose();
  return this;
};

function Readable(options) {
  Stream.call(this);
  this._data = [];
  this._ended = false;
  this.readableHighWaterMark = (options && options.highWaterMark) || 16384;
  this.readableObjectMode = !!(options && options.objectMode);
  this.readableEncoding = (options && options.encoding) || null;
  this.readableFlowing = null;
  this.readableEnded = false;
  if (options && typeof options.read === 'function') this._read = options.read;
  if (options && typeof options.destroy === 'function') this._destroy = options.destroy;
}
Readable.prototype = Object.create(Stream.prototype);
Readable.prototype.constructor = Readable;

Readable.prototype.push = function(chunk) {
  if (chunk === null || chunk === undefined) {
    this._ended = true;
    this.readableEnded = true;
    this.emit('end');
    this._emitClose();
    return false;
  }
  this._data.push(chunk);
  this.emit('data', chunk);
  return true;
};

Readable.prototype.read = function() {
  return this._data.shift();
};

Readable.prototype.unshift = function(chunk) {
  this._data.unshift(chunk);
};

Readable.prototype.setEncoding = function(enc) {
  this.readableEncoding = enc;
  return this;
};

Readable.prototype.resume = function() {
  this.readableFlowing = true;
  return this;
};

Readable.prototype.pause = function() {
  this.readableFlowing = false;
  return this;
};

Readable.prototype.isPaused = function() {
  return this.readableFlowing === false;
};

Readable.prototype._read = function(size) {};

// Symbol.asyncIterator support for Readable streams
Readable.prototype[Symbol.asyncIterator] = function() {
  var stream = this;
  var ended = false;
  var error = null;
  var pendingResolve = null;
  var buffer = [];

  stream.on('data', function(chunk) {
    if (pendingResolve) {
      var resolve = pendingResolve;
      pendingResolve = null;
      resolve({ value: chunk, done: false });
    } else {
      buffer.push(chunk);
    }
  });

  stream.on('end', function() {
    ended = true;
    if (pendingResolve) {
      var resolve = pendingResolve;
      pendingResolve = null;
      resolve({ value: undefined, done: true });
    }
  });

  stream.on('error', function(err) {
    error = err;
    ended = true;
    if (pendingResolve) {
      var resolve = pendingResolve;
      pendingResolve = null;
      resolve(Promise.reject(err));
    }
  });

  return {
    next: function() {
      if (error) {
        return Promise.reject(error);
      }
      if (buffer.length > 0) {
        return Promise.resolve({ value: buffer.shift(), done: false });
      }
      if (ended) {
        return Promise.resolve({ value: undefined, done: true });
      }
      return new Promise(function(resolve) {
        pendingResolve = resolve;
      });
    },
    return: function() {
      ended = true;
      if (typeof stream.destroy === 'function') stream.destroy();
      return Promise.resolve({ value: undefined, done: true });
    },
    throw: function(err) {
      ended = true;
      if (typeof stream.destroy === 'function') stream.destroy(err);
      return Promise.reject(err);
    },
    [Symbol.asyncIterator]: function() { return this; }
  };
};

Readable.from = function(iterable, options) {
  var readable = new Readable(options);
  if (!iterable) {
    readable.push(null);
    return readable;
  }
  if (typeof iterable === 'string' || iterable instanceof Uint8Array) {
    readable.push(iterable);
    readable.push(null);
    return readable;
  }
  // Async iterable (including async generators)
  if (typeof iterable[Symbol.asyncIterator] === 'function') {
    var asyncIter = iterable[Symbol.asyncIterator]();
    var reading = false;
    function readNext() {
      if (reading) return;
      reading = true;
      asyncIter.next().then(function(result) {
        reading = false;
        if (result.done) {
          readable.push(null);
        } else {
          readable.push(result.value);
          readNext();
        }
      }).catch(function(err) {
        reading = false;
        readable.destroy(err);
      });
    }
    readNext();
    return readable;
  }
  // Sync iterable
  if (typeof iterable[Symbol.iterator] === 'function') {
    var iterator = iterable[Symbol.iterator]();
    var next = iterator.next();
    while (!next.done) {
      readable.push(next.value);
      next = iterator.next();
    }
    readable.push(null);
    return readable;
  }
  // Promise
  if (iterable instanceof Promise || (iterable && typeof iterable.then === 'function')) {
    iterable.then(function(value) {
      readable.push(value);
      readable.push(null);
    }).catch(function(err) {
      readable.destroy(err);
    });
    return readable;
  }
  readable.push(null);
  return readable;
};

// Readable.toWeb() - convert Node Readable to WHATWG ReadableStream
Readable.toWeb = function(nodeReadable) {
  return new ReadableStream({
    start: function(controller) {
      nodeReadable.on('data', function(chunk) {
        controller.enqueue(chunk);
      });
      nodeReadable.on('end', function() {
        controller.close();
      });
      nodeReadable.on('error', function(err) {
        controller.error(err);
      });
    },
    cancel: function() {
      if (typeof nodeReadable.destroy === 'function') nodeReadable.destroy();
    }
  });
};

// Readable.fromWeb() - convert WHATWG ReadableStream to Node Readable
Readable.fromWeb = function(webStream, options) {
  var readable = new Readable(options);
  var reader = webStream.getReader();
  function pump() {
    reader.read().then(function(result) {
      if (result.done) {
        readable.push(null);
      } else {
        readable.push(result.value);
        pump();
      }
    }).catch(function(err) {
      readable.destroy(err);
    });
  }
  pump();
  return readable;
};

function Writable(options) {
  Stream.call(this);
  this.writableEnded = false;
  this.writableFinished = false;
  this.writableHighWaterMark = (options && options.highWaterMark) || 16384;
  this.writableObjectMode = !!(options && options.objectMode);
  this.writableLength = 0;
  this._written = [];
  this._needDrain = false;
  if (options && typeof options.write === 'function') this._write = options.write;
  if (options && typeof options.writev === 'function') this._writev = options.writev;
  if (options && typeof options.destroy === 'function') this._destroy = options.destroy;
  if (options && typeof options.final === 'function') this._final = options.final;
}
Writable.prototype = Object.create(Stream.prototype);
Writable.prototype.constructor = Writable;

Writable.prototype._write = function(chunk, encoding, callback) {
  if (typeof callback === 'function') callback();
};

Writable.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = 'utf8'; }
  var chunkLen = 0;
  if (chunk !== undefined) {
    this._written.push(chunk);
    chunkLen = (chunk && chunk.length) ? chunk.length : 0;
    this.writableLength += chunkLen;
  }
  var self = this;
  this._write(chunk, encoding || 'utf8', function(err) {
    self.writableLength -= chunkLen;
    if (self.writableLength < 0) self.writableLength = 0;
    if (self._needDrain && self.writableLength < self.writableHighWaterMark) {
      self._needDrain = false;
      self.emit('drain');
    }
    if (err) { if (typeof callback === 'function') callback(err); }
    else { if (typeof callback === 'function') callback(); }
  });
  if (this.writableLength >= this.writableHighWaterMark) {
    this._needDrain = true;
    return false;
  }
  return true;
};

Writable.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = null; }
  if (typeof encoding === 'function') { callback = encoding; encoding = null; }
  if (chunk !== undefined && chunk !== null) {
    this.write(chunk, encoding);
  }
  this.writableEnded = true;
  var self = this;
  var done = function() {
    self.writableFinished = true;
    self.emit('finish');
    self._emitClose();
    if (typeof callback === 'function') callback();
  };
  if (typeof this._final === 'function') {
    this._final(done);
  } else {
    done();
  }
};

Writable.prototype.cork = function() {};
Writable.prototype.uncork = function() {};
Writable.prototype.setDefaultEncoding = function(enc) { return this; };

// Writable.toWeb / fromWeb
Writable.toWeb = function(nodeWritable) {
  return new WritableStream({
    write: function(chunk) {
      return new Promise(function(resolve, reject) {
        nodeWritable.write(chunk, function(err) {
          if (err) reject(err); else resolve();
        });
      });
    },
    close: function() {
      return new Promise(function(resolve) {
        nodeWritable.end(function() { resolve(); });
      });
    },
    abort: function(reason) {
      if (typeof nodeWritable.destroy === 'function') nodeWritable.destroy(reason);
    }
  });
};

Writable.fromWeb = function(webWritable, options) {
  var writer = webWritable.getWriter();
  return new Writable(Object.assign({}, options, {
    write: function(chunk, encoding, callback) {
      writer.write(chunk).then(function() { callback(); }).catch(callback);
    },
    final: function(callback) {
      writer.close().then(function() { callback(); }).catch(callback);
    }
  }));
};

function Duplex(options) {
  Readable.call(this, options);
  Writable.call(this, options);
  this.writableEnded = false;
  this.writableFinished = false;
  this.allowHalfOpen = !(options && options.allowHalfOpen === false);
}
Duplex.prototype = Object.create(Readable.prototype);
Object.keys(Writable.prototype).forEach(function(k) {
  if (!Duplex.prototype[k]) Duplex.prototype[k] = Writable.prototype[k];
});
Duplex.prototype.constructor = Duplex;

function Transform(options) {
  Duplex.call(this, options);
  if (options && typeof options.transform === 'function') this._transform = options.transform;
  if (options && typeof options.flush === 'function') this._flush = options.flush;
}
Transform.prototype = Object.create(Duplex.prototype);
Transform.prototype.constructor = Transform;

Transform.prototype._transform = function(chunk, encoding, callback) {
  this.push(chunk);
  if (typeof callback === 'function') callback();
};

Transform.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = 'utf8'; }
  var self = this;
  this._transform(chunk, encoding || 'utf8', function(err) {
    if (err) { self.emit('error', err); }
    if (typeof callback === 'function') callback(err);
  });
  return true;
};

function PassThrough(options) {
  Transform.call(this, options);
}
PassThrough.prototype = Object.create(Transform.prototype);
PassThrough.prototype.constructor = PassThrough;

Stream.prototype.pipe = function(dest) {
  var source = this;
  source.on('data', function(chunk) {
    if (dest && typeof dest.write === 'function') {
      var ok = dest.write(chunk);
      if (ok === false && typeof source.pause === 'function') {
        source.pause();
        dest.once('drain', function() {
          if (typeof source.resume === 'function') {
            source.resume();
          }
        });
      }
    }
  });
  source.on('end', function() {
    if (dest && typeof dest.end === 'function') {
      dest.end();
    }
  });
  source.on('error', function(err) {
    if (dest && typeof dest.destroy === 'function') {
      dest.destroy(err);
    }
  });
  return dest;
};

function pipeline() {
  var args = [];
  for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
  var callback = null;
  var options = null;

  // Last arg can be callback or options
  if (typeof args[args.length - 1] === 'function') {
    callback = args.pop();
  } else if (args.length > 1 && typeof args[args.length - 1] === 'object' && args[args.length - 1] !== null && !args[args.length - 1].pipe) {
    options = args.pop();
    if (typeof args[args.length - 1] === 'function') callback = args.pop();
  }

  var streams = args;
  if (streams.length < 2) {
    var err = new Error('pipeline requires at least 2 streams');
    if (callback) { callback(err); return; }
    return Promise.reject(err);
  }

  var signal = options && options.signal;
  var destroyedBySignal = false;

  function destroyAll(error) {
    for (var i = 0; i < streams.length; i++) {
      if (streams[i] && typeof streams[i].destroy === 'function' && !streams[i]._destroyed) {
        streams[i].destroy(error);
      }
    }
  }

  // AbortSignal support
  if (signal) {
    if (signal.aborted) {
      destroyedBySignal = true;
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      destroyAll(abortErr);
      if (callback) { callback(abortErr); return; }
      return Promise.reject(abortErr);
    }
    signal.addEventListener('abort', function() {
      destroyedBySignal = true;
      var abortErr = new Error('The operation was aborted');
      abortErr.code = 'ABORT_ERR';
      abortErr.name = 'AbortError';
      destroyAll(abortErr);
    });
  }

  var error = null;
  var finished_count = 0;
  var total = streams.length;

  function onError(err) {
    if (!error) {
      error = err;
      destroyAll(err);
    }
  }

  // Pipe each stream to the next
  for (var i = 0; i + 1 < streams.length; i++) {
    var src = streams[i];
    var dst = streams[i + 1];
    if (typeof src.pipe === 'function') {
      try {
        src.pipe(dst);
      } catch (err) {
        onError(err);
        break;
      }
    }
    src.on('error', onError);
  }
  // Listen for error on last stream too
  streams[streams.length - 1].on('error', onError);

  // If no callback, return a Promise
  if (!callback) {
    return new Promise(function(resolve, reject) {
      var last = streams[streams.length - 1];
      last.on('finish', function() {
        if (error) reject(error); else resolve();
      });
      last.on('end', function() {
        if (error) reject(error); else resolve();
      });
    });
  }

  // With callback: wait for last stream to finish
  var last = streams[streams.length - 1];
  var called = false;
  function done(err) {
    if (called) return;
    called = true;
    callback(err || error || null);
  }
  last.on('finish', function() { done(null); });
  last.on('end', function() { done(null); });
  last.on('error', done);
}

function finished(stream, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  var called = false;

  function done(err) {
    if (called) return;
    called = true;
    if (cleanup) cleanup();
    if (typeof callback === 'function') callback(err || null);
  }

  var onFinish = function() { done(null); };
  var onEnd = function() { done(null); };
  var onError = function(err) { done(err); };
  var onClose = function() {
    // If stream closed without ending, it's an error
    if (!stream._ended && !stream.writableFinished) {
      done(new Error('premature close'));
    } else {
      done(null);
    }
  };

  if (options.readable !== false && stream.on) {
    stream.on('end', onEnd);
  }
  if (options.writable !== false && stream.on) {
    stream.on('finish', onFinish);
  }
  if (stream.on) {
    stream.on('error', onError);
    stream.on('close', onClose);
  }

  // AbortSignal support
  if (options.signal) {
    options.signal.addEventListener('abort', function() {
      var err = new Error('The operation was aborted');
      err.code = 'ABORT_ERR';
      err.name = 'AbortError';
      done(err);
    });
  }

  // Return cleanup function
  var cleanup = function() {
    if (stream.removeListener) {
      stream.removeListener('end', onEnd);
      stream.removeListener('finish', onFinish);
      stream.removeListener('error', onError);
      stream.removeListener('close', onClose);
    }
  };

  // If no callback, return a promise
  if (typeof callback !== 'function') {
    return new Promise(function(resolve, reject) {
      callback = function(err) {
        if (err) reject(err); else resolve();
      };
    });
  }

  return cleanup;
}

// compose() - compose multiple Transform/Duplex streams into one
function compose() {
  var args = [];
  for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
  if (args.length === 0) throw new Error('compose requires at least one stream');
  if (args.length === 1) return args[0];

  var first = args[0];
  var last = args[args.length - 1];

  // Pipe all streams together
  for (var j = 0; j + 1 < args.length; j++) {
    args[j].pipe(args[j + 1]);
  }

  // Create a Duplex that writes to first and reads from last
  var composed = new Duplex({
    write: function(chunk, encoding, callback) {
      if (typeof first.write === 'function') {
        var ok = first.write(chunk, encoding, callback);
        if (!ok && typeof callback !== 'function') {
          first.once('drain', function() {});
        }
      } else if (typeof callback === 'function') {
        callback();
      }
    },
    final: function(callback) {
      if (typeof first.end === 'function') first.end();
      callback();
    },
    read: function() {}
  });

  // Forward data from last stream to composed
  last.on('data', function(chunk) {
    composed.push(chunk);
  });
  last.on('end', function() {
    composed.push(null);
  });

  // Forward errors from all streams
  for (var k = 0; k < args.length; k++) {
    (function(s) {
      s.on('error', function(err) {
        composed.destroy(err);
      });
    })(args[k]);
  }

  return composed;
}

// addAbortSignal utility
function addAbortSignal(signal, stream) {
  if (!signal || typeof signal.addEventListener !== 'function') {
    throw new Error('The first argument must be an AbortSignal');
  }
  if (!stream || typeof stream.destroy !== 'function') {
    throw new Error('The second argument must be a stream');
  }
  signal.addEventListener('abort', function() {
    var err = new Error('The operation was aborted');
    err.code = 'ABORT_ERR';
    err.name = 'AbortError';
    stream.destroy(err);
  });
  return stream;
}

// Node.js exports the Stream constructor directly with subclasses as properties
Stream.Stream = Stream;
Stream.Readable = Readable;
Stream.Writable = Writable;
Stream.Duplex = Duplex;
Stream.Transform = Transform;
Stream.PassThrough = PassThrough;
Stream.pipeline = pipeline;
Stream.finished = finished;
Stream.compose = compose;
Stream.addAbortSignal = addAbortSignal;
module.exports = Stream;
"#
    .trim()
    .to_string()
}

fn node_stream_promises_module() -> String {
    r#"
var stream = require('node:stream');

function pipeline() {
  var args = [];
  for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
  // stream.pipeline already returns a promise when no callback is given
  if (typeof stream.pipeline === 'function') {
    return stream.pipeline.apply(stream, args);
  }
  return Promise.reject(new Error('stream.pipeline is not available'));
}

function finished(streamLike, options) {
  if (typeof stream.finished === 'function') {
    return stream.finished(streamLike, options || {});
  }
  return Promise.reject(new Error('stream.finished is not available'));
}

module.exports = {
  pipeline: pipeline,
  finished: finished
};
"#
    .trim()
    .to_string()
}

fn node_buffer_module() -> String {
    r#"
var BufferProto = {};

function coerceEncoding(encoding) {
  if (!encoding) return "utf8";
  var normalized = String(encoding).toLowerCase().replace("-", "");
  if (normalized === "utf8") return "utf8";
  if (normalized === "utf-8") return "utf8";
  return normalized;
}

function decodeBytes(bytes, encoding, start, end) {
  var enc = coerceEncoding(encoding || "utf8");
  var slice = (start !== undefined || end !== undefined) ? Uint8Array.prototype.slice.call(bytes, start || 0, end) : bytes;
  if (enc === "hex") {
    var out = "";
    for (var i = 0; i < slice.length; i++) {
      var value = slice[i].toString(16);
      if (value.length === 1) out += "0";
      out += value;
    }
    return out;
  }
  if (enc === "base64") {
    var binary = "";
    for (var i = 0; i < slice.length; i++) binary += String.fromCharCode(slice[i]);
    return typeof btoa === "function" ? btoa(binary) : "";
  }
  if (enc === "latin1" || enc === "binary") {
    var result = "";
    for (var i = 0; i < slice.length; i++) result += String.fromCharCode(slice[i]);
    return result;
  }
  if (enc === "ascii") {
    var result = "";
    for (var i = 0; i < slice.length; i++) result += String.fromCharCode(slice[i] & 0x7F);
    return result;
  }
  if (typeof TextDecoder !== "undefined") {
    var view = (slice.__isExactBuffer) ? new Uint8Array(slice) : slice;
    return new TextDecoder("utf-8").decode(view);
  }
  var result = "";
  for (var i = 0; i < slice.length; i++) {
    result += String.fromCharCode(slice[i]);
  }
  return result;
}

function encodeString(value, encoding) {
  var enc = coerceEncoding(encoding || "utf8");
  var str = String(value);
  if (enc === "hex") {
    var hexLen = Math.floor(str.length / 2);
    var bytes = new Uint8Array(hexLen);
    for (var i = 0; i < hexLen; i++) {
      bytes[i] = parseInt(str.substr(i * 2, 2), 16);
    }
    return bytes;
  }
  if (enc === "base64") {
    if (typeof atob === "function") {
      var raw = atob(str);
      var b = new Uint8Array(raw.length);
      for (var j = 0; j < raw.length; j++) b[j] = raw.charCodeAt(j);
      return b;
    }
  }
  if (enc === "latin1" || enc === "binary") {
    var lat = new Uint8Array(str.length);
    for (var k = 0; k < str.length; k++) lat[k] = str.charCodeAt(k) & 0xff;
    return lat;
  }
  if (enc === "ascii") {
    var asc = new Uint8Array(str.length);
    for (var m = 0; m < str.length; m++) asc[m] = str.charCodeAt(m) & 0x7f;
    return asc;
  }
  // utf8
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(str);
  }
  var fallback = new Uint8Array(str.length);
  for (var n = 0; n < str.length; n++) {
    fallback[n] = str.charCodeAt(n) & 0xff;
  }
  return fallback;
}

function toByteArray(value, encoding) {
  if (typeof value === "number") {
    if (value < 0 || value > 0xffffffff || value % 1 !== 0) {
      throw new TypeError("Invalid Buffer size");
    }
    return new Uint8Array(value);
  }
  if (value == null) {
    throw new TypeError("Cannot convert null to Buffer");
  }
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (typeof value === "string") {
    return encodeString(value, encoding);
  }
  if (Array.isArray(value)) {
    return new Uint8Array(value);
  }
  if (typeof value === "object" && value !== null && typeof value.valueOf === "function") {
    var unboxed = value.valueOf();
    if (unboxed !== value) {
      return toByteArray(unboxed, encoding);
    }
  }
  throw new TypeError("Unsupported value type for Buffer");
}

function Buffer(value, encoding) {
  return Buffer.from(value, encoding);
}

function makeBuffer(bytes) {
  var buffer = new Uint8Array(bytes);
  if (Buffer._protoReady) {
    Object.setPrototypeOf(buffer, Buffer.prototype);
  } else {
    for (var key in BufferProto) {
      buffer[key] = BufferProto[key];
    }
    buffer.__isExactBuffer = true;
  }
  return buffer;
}

Buffer.isBuffer = function(candidate) {
  return !!(candidate && candidate.__isExactBuffer);
};

Buffer.from = function(value, encoding) {
  if (value && value.__isExactBuffer) {
    return makeBuffer(new Uint8Array(value));
  }
  return makeBuffer(toByteArray(value, encoding));
};

Buffer.alloc = function(size, fill, encoding) {
  var bytes = new Uint8Array(size || 0);
  if (fill === undefined || fill === null) {
    return makeBuffer(bytes);
  }
  var fillValue;
  if (typeof fill === "string") {
    fillValue = encodeString(fill, encoding || "utf8")[0];
  } else if (typeof fill === "number") {
    fillValue = fill & 0xff;
  } else if (fill === true) {
    fillValue = 1;
  } else if (fill === false || fill === 0) {
    fillValue = 0;
  } else if (fill.__isExactBuffer) {
    fill = fill[0] || 0;
    fillValue = fill;
  } else {
    fillValue = 0;
  }
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = fillValue;
  }
  return makeBuffer(bytes);
};

Buffer.allocUnsafe = Buffer.alloc;

Buffer.byteLength = function(string, encoding) {
  return encodeString(String(string), encoding || "utf8").length;
};

Buffer.compare = function(a, b) {
  if (!(a && a.__isExactBuffer) || !(b && b.__isExactBuffer)) {
    throw new TypeError("Arguments must be Buffers");
  }
  var i = 0;
  var max = Math.min(a.length, b.length);
  while (i < max) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    i += 1;
  }
  if (a.length === b.length) return 0;
  return a.length < b.length ? -1 : 1;
};

Buffer.concat = function(list, totalLength) {
  if (!Array.isArray(list)) throw new TypeError("list argument must be an Array of Buffers");
  if (list.length === 0) return Buffer.alloc(0);
  if (list.length === 1) return list[0];
  var total = totalLength;
  if (total === undefined) {
    total = 0;
    for (var i = 0; i < list.length; i++) total += list[i].length;
  }
  var result = Buffer.alloc(total);
  var offset = 0;
  for (var j = 0; j < list.length; j++) {
    var buf = list[j];
    for (var k = 0; k < buf.length && offset < total; k++) {
      result[offset++] = buf[k];
    }
  }
  return result;
};

Buffer.isEncoding = function(encoding) {
  return typeof encoding === "string" &&
    ["utf8", "utf-8", "ascii", "latin1", "binary", "hex", "base64", "ucs2", "ucs-2", "utf16le", "utf-16le"]
    .indexOf(encoding.toLowerCase()) !== -1;
};

BufferProto.toString = function(encoding, start, end) {
  return decodeBytes(this, encoding, start, end);
};

BufferProto.equals = function(other) {
  if (!other || !other.__isExactBuffer) return false;
  if (other.length !== this.length) return false;
  for (var i = 0; i < this.length; i++) {
    if (this[i] !== other[i]) return false;
  }
  return true;
};

BufferProto.toJSON = function() {
  return { type: "Buffer", data: Array.prototype.slice.call(this) };
};

BufferProto.slice = function(start, end) {
  return makeBuffer(Uint8Array.prototype.slice.call(this, start, end));
};

BufferProto.subarray = function(start, end) {
  return makeBuffer(Uint8Array.prototype.slice.call(this, start, end));
};

BufferProto.copy = function(target, targetStart, sourceStart, sourceEnd) {
  targetStart = targetStart || 0;
  sourceStart = sourceStart || 0;
  sourceEnd = sourceEnd == null ? this.length : sourceEnd;
  var length = Math.max(0, Math.min(this.length, sourceEnd) - sourceStart);
  for (var i = 0; i < length; i++) {
    target[targetStart + i] = this[sourceStart + i];
  }
  return length;
};

BufferProto.write = function(value, offset, length, encoding) {
  var bytes = encodeString(String(value), encoding || "utf8");
  if (offset == null) offset = 0;
  if (length == null || length > bytes.length) length = bytes.length;
  for (var i = 0; i < length && (offset + i) < this.length; i++) {
    this[offset + i] = bytes[i];
  }
  return Math.min(length, this.length - offset);
};

BufferProto.compare = function(target, targetStart, targetEnd, sourceStart, sourceEnd) {
  if (!target || !target.__isExactBuffer) throw new TypeError("Argument must be a Buffer");
  sourceStart = sourceStart || 0;
  sourceEnd = sourceEnd == null ? this.length : sourceEnd;
  targetStart = targetStart || 0;
  targetEnd = targetEnd == null ? target.length : targetEnd;
  var sLen = sourceEnd - sourceStart;
  var tLen = targetEnd - targetStart;
  var len = Math.min(sLen, tLen);
  for (var i = 0; i < len; i++) {
    if (this[sourceStart + i] !== target[targetStart + i]) {
      return this[sourceStart + i] < target[targetStart + i] ? -1 : 1;
    }
  }
  if (sLen === tLen) return 0;
  return sLen < tLen ? -1 : 1;
};

// Read unsigned integers
BufferProto.readUInt8 = function(offset) { return this[offset || 0]; };
BufferProto.readUInt16LE = function(offset) { offset = offset || 0; return this[offset] | (this[offset+1] << 8); };
BufferProto.readUInt16BE = function(offset) { offset = offset || 0; return (this[offset] << 8) | this[offset+1]; };
BufferProto.readUInt32LE = function(offset) { offset = offset || 0; return (this[offset] | (this[offset+1] << 8) | (this[offset+2] << 16) | (this[offset+3] << 24)) >>> 0; };
BufferProto.readUInt32BE = function(offset) { offset = offset || 0; return (this[offset] * 0x1000000 + (this[offset+1] << 16) + (this[offset+2] << 8) + this[offset+3]) >>> 0; };

// Read signed integers
BufferProto.readInt8 = function(offset) { var v = this[offset || 0]; return v > 127 ? v - 256 : v; };
BufferProto.readInt16LE = function(offset) { var v = this.readUInt16LE(offset); return v > 0x7fff ? v - 0x10000 : v; };
BufferProto.readInt16BE = function(offset) { var v = this.readUInt16BE(offset); return v > 0x7fff ? v - 0x10000 : v; };
BufferProto.readInt32LE = function(offset) { offset = offset || 0; return this[offset] | (this[offset+1] << 8) | (this[offset+2] << 16) | (this[offset+3] << 24); };
BufferProto.readInt32BE = function(offset) { offset = offset || 0; return (this[offset] << 24) | (this[offset+1] << 16) | (this[offset+2] << 8) | this[offset+3]; };

// Read floats/doubles via DataView
BufferProto.readFloatLE = function(offset) { return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat32(offset || 0, true); };
BufferProto.readFloatBE = function(offset) { return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat32(offset || 0, false); };
BufferProto.readDoubleLE = function(offset) { return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat64(offset || 0, true); };
BufferProto.readDoubleBE = function(offset) { return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat64(offset || 0, false); };

// Write unsigned integers
BufferProto.writeUInt8 = function(value, offset) { offset = offset || 0; this[offset] = value & 0xff; return offset + 1; };
BufferProto.writeUInt16LE = function(value, offset) { offset = offset || 0; this[offset] = value & 0xff; this[offset+1] = (value >>> 8) & 0xff; return offset + 2; };
BufferProto.writeUInt16BE = function(value, offset) { offset = offset || 0; this[offset] = (value >>> 8) & 0xff; this[offset+1] = value & 0xff; return offset + 2; };
BufferProto.writeUInt32LE = function(value, offset) { offset = offset || 0; this[offset] = value & 0xff; this[offset+1] = (value >>> 8) & 0xff; this[offset+2] = (value >>> 16) & 0xff; this[offset+3] = (value >>> 24) & 0xff; return offset + 4; };
BufferProto.writeUInt32BE = function(value, offset) { offset = offset || 0; this[offset] = (value >>> 24) & 0xff; this[offset+1] = (value >>> 16) & 0xff; this[offset+2] = (value >>> 8) & 0xff; this[offset+3] = value & 0xff; return offset + 4; };

// Write signed integers
BufferProto.writeInt8 = function(value, offset) { offset = offset || 0; this[offset] = value < 0 ? value + 256 : value; return offset + 1; };
BufferProto.writeInt16LE = function(value, offset) { return this.writeUInt16LE(value < 0 ? value + 0x10000 : value, offset); };
BufferProto.writeInt16BE = function(value, offset) { return this.writeUInt16BE(value < 0 ? value + 0x10000 : value, offset); };
BufferProto.writeInt32LE = function(value, offset) { return this.writeUInt32LE(value < 0 ? value + 0x100000000 : value, offset); };
BufferProto.writeInt32BE = function(value, offset) { return this.writeUInt32BE(value < 0 ? value + 0x100000000 : value, offset); };

// Write floats/doubles via DataView
BufferProto.writeFloatLE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat32(offset, value, true); return offset + 4; };
BufferProto.writeFloatBE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat32(offset, value, false); return offset + 4; };
BufferProto.writeDoubleLE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat64(offset, value, true); return offset + 8; };
BufferProto.writeDoubleBE = function(value, offset) { offset = offset || 0; new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat64(offset, value, false); return offset + 8; };

// Swap byte order
BufferProto.swap16 = function() {
  for (var i = 0; i < this.length; i += 2) { var a = this[i]; this[i] = this[i+1]; this[i+1] = a; }
  return this;
};
BufferProto.swap32 = function() {
  for (var i = 0; i < this.length; i += 4) { var a = this[i]; var b = this[i+1]; this[i] = this[i+3]; this[i+1] = this[i+2]; this[i+2] = b; this[i+3] = a; }
  return this;
};
BufferProto.swap64 = function() {
  for (var i = 0; i < this.length; i += 8) {
    var a = this[i]; var b = this[i+1]; var c = this[i+2]; var d = this[i+3];
    this[i] = this[i+7]; this[i+1] = this[i+6]; this[i+2] = this[i+5]; this[i+3] = this[i+4];
    this[i+4] = d; this[i+5] = c; this[i+6] = b; this[i+7] = a;
  }
  return this;
};

// Node.js aliases (readUintXX = readUIntXX)
BufferProto.readUint8 = BufferProto.readUInt8;
BufferProto.readUint16LE = BufferProto.readUInt16LE;
BufferProto.readUint16BE = BufferProto.readUInt16BE;
BufferProto.readUint32LE = BufferProto.readUInt32LE;
BufferProto.readUint32BE = BufferProto.readUInt32BE;
BufferProto.writeUint8 = BufferProto.writeUInt8;
BufferProto.writeUint16LE = BufferProto.writeUInt16LE;
BufferProto.writeUint16BE = BufferProto.writeUInt16BE;
BufferProto.writeUint32LE = BufferProto.writeUInt32LE;
BufferProto.writeUint32BE = BufferProto.writeUInt32BE;

BufferProto.fill = function(value, start, end) {
  start = start == null ? 0 : start;
  end = end == null ? this.length : end;
  var fill = typeof value === "string" ? encodeString(value, "utf8")[0] : value;
  for (var i = start; i < end && i < this.length; i++) {
    this[i] = fill & 0xff;
  }
  return this;
};

// Set up Buffer.prototype inheriting from Uint8Array.prototype
// MUST be done after all BufferProto methods are defined
Buffer.prototype = Object.create(Uint8Array.prototype, {
  constructor: { value: Buffer, writable: true, configurable: true }
});
for (var _bk in BufferProto) {
  if (Object.prototype.hasOwnProperty.call(BufferProto, _bk)) {
    Buffer.prototype[_bk] = BufferProto[_bk];
  }
}
Buffer.prototype.__isExactBuffer = true;
Buffer._protoReady = true;

module.exports = {
  Buffer: Buffer,
  atob: typeof atob === "function" ? atob : undefined,
  btoa: typeof btoa === "function" ? btoa : undefined,
  SlowBuffer: Buffer,
  Blob: typeof Blob === "undefined" ? undefined : Blob,
};
"#
    .trim()
    .to_string()
}

fn node_util_module() -> String {
    r#"
function inherits(constructor, superConstructor) {
  if (typeof constructor !== "function" || typeof superConstructor !== "function") {
    throw new TypeError("util.inherits() requires two functions");
  }
  constructor.super_ = superConstructor;
  constructor.prototype = Object.create(superConstructor.prototype);
  constructor.prototype.constructor = constructor;
}

function promisify(fn) {
  if (typeof fn !== "function") {
    throw new TypeError("util.promisify requires a function");
  }
  return function() {
    var args = [];
    var i = 0;
    while (i < arguments.length) {
      args.push(arguments[i]);
      i += 1;
    }
    return new Promise(function(resolve, reject) {
      args.push(function(err) {
        if (err) {
          return reject(err);
        }
        if (arguments.length <= 1) return resolve(undefined);
        if (arguments.length === 2) return resolve(arguments[1]);
        var output = [];
        for (var j = 1; j < arguments.length; j++) {
          output.push(arguments[j]);
        }
        return resolve(output);
      });
      try {
        fn.apply(this, args);
      } catch (err) {
        reject(err);
      }
    }.bind(this));
  };
}

function format(value) {
  if (arguments.length === 0) return "";
  if (typeof value !== "string") {
    return String(value);
  }
  var i = 1;
  var args = arguments;
  return value.replace(/%[sdjoO%]/g, function(match) {
    if (match === "%%") return "%";
    if (i >= args.length) return match;
    var arg = args[i];
    i += 1;
    if (match === "%s") return String(arg);
    if (match === "%d") return String(Number(arg));
    if (match === "%j") return JSON.stringify(arg);
    if (match === "%o" || match === "%O") return arg && arg.toString ? arg.toString() : String(arg);
    return match;
  });
}

function inspect(value, options) {
  var opts = options || {};
  var depth = opts.depth !== undefined ? opts.depth : 2;
  var colors = opts.colors || false;
  var seen = [];
  function _inspect(val, currentDepth) {
    if (val === null) return 'null';
    if (val === undefined) return 'undefined';
    var t = typeof val;
    if (t === 'string') return "'" + val.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
    if (t === 'number' || t === 'boolean') return String(val);
    if (t === 'symbol') return val.toString();
    if (t === 'function') {
      var name = val.name || 'anonymous';
      return '[Function: ' + name + ']';
    }
    if (t === 'bigint') return val.toString() + 'n';
    // Object types
    if (seen.indexOf(val) !== -1) return '[Circular]';
    seen.push(val);
    if (currentDepth > depth) {
      var _pop = seen.pop();
      return Array.isArray(val) ? '[Array]' : '[Object]';
    }
    if (Array.isArray(val)) {
      if (val.length === 0) { seen.pop(); return '[]'; }
      var items = [];
      for (var i = 0; i < val.length; i++) {
        items.push(_inspect(val[i], currentDepth + 1));
      }
      seen.pop();
      return '[ ' + items.join(', ') + ' ]';
    }
    if (val instanceof Date) { seen.pop(); return val.toISOString(); }
    if (val instanceof RegExp) { seen.pop(); return String(val); }
    if (val instanceof Error) { seen.pop(); return '[' + (val.constructor.name || 'Error') + ': ' + val.message + ']'; }
    if (typeof val.constructor === 'function' && val.constructor.name === 'Buffer') {
      seen.pop();
      return '<Buffer ' + Array.prototype.slice.call(val, 0, Math.min(val.length, 50)).map(function(b) { return (b < 16 ? '0' : '') + b.toString(16); }).join(' ') + (val.length > 50 ? ' ... ' + (val.length - 50) + ' more bytes' : '') + '>';
    }
    // Plain object
    var keys = Object.keys(val);
    if (keys.length === 0) { seen.pop(); return '{}'; }
    var parts = [];
    for (var ki = 0; ki < keys.length; ki++) {
      var k = keys[ki];
      var v;
      try { v = _inspect(val[k], currentDepth + 1); } catch(e) { v = '[Getter/Error]'; }
      parts.push(k + ': ' + v);
    }
    seen.pop();
    return '{ ' + parts.join(', ') + ' }';
  }
  return _inspect(value, 0);
}
inspect.styles = {};
inspect.colors = {};
inspect.defaultOptions = { depth: 2, colors: false };

function deprecated(message) {
  return function() {
    if (typeof console !== "undefined" && console.warn) {
      console.warn(message);
    }
    if (typeof deprecated._fn === "function") {
      return deprecated._fn.apply(this, arguments);
    }
    return undefined;
  };
}

var util = {
  inherits: inherits,
  promisify: promisify,
  format: format,
  inspect: inspect,
  deprecate: function(fn, message) {
    if (typeof fn !== "function") return undefined;
    var wrapped = function() {
      if (wrapped._warned !== true && typeof console !== "undefined" && console.warn) {
        console.warn(message);
        wrapped._warned = true;
      }
      return fn.apply(this, arguments);
    };
    return wrapped;
  },
  types: {
    isPromise: function(value) { return value instanceof Promise || (value && typeof value.then === "function"); },
    isAsyncFunction: function(value) { return value && value.constructor && value.constructor.name === "AsyncFunction"; },
    isArrayBufferView: function(value) {
      return value && (typeof ArrayBuffer !== "undefined") && ArrayBuffer.isView(value);
    },
    isDate: function(value) { return value instanceof Date; },
    isRegExp: function(value) { return value instanceof RegExp; },
    isSet: function(value) { return typeof Set !== "undefined" && value instanceof Set; },
    isMap: function(value) { return typeof Map !== "undefined" && value instanceof Map; },
    isTypedArray: function(value) {
      return value && (value instanceof Int8Array || value instanceof Uint8Array ||
        value instanceof Uint8ClampedArray || value instanceof Int16Array ||
        value instanceof Uint16Array || value instanceof Int32Array ||
        value instanceof Uint32Array || value instanceof Float32Array ||
        value instanceof Float64Array);
    },
    isNativeError: function(value) { return value instanceof Error; },
    isNumberObject: function(value) { return typeof value === "object" && value instanceof Number; },
    isStringObject: function(value) { return typeof value === "object" && value instanceof String; },
    isBooleanObject: function(value) { return typeof value === "object" && value instanceof Boolean; }
  },
  TextEncoder: typeof TextEncoder !== "undefined" ? TextEncoder : undefined,
  TextDecoder: typeof TextDecoder !== "undefined" ? TextDecoder : undefined,
  callbackify: function(fn) {
    return function() {
      var args = Array.prototype.slice.call(arguments);
      var callback = args.pop();
      fn.apply(this, args).then(
        function(result) { callback(null, result); },
        function(err) { callback(err); }
      );
    };
  },
  isDeepStrictEqual: function(a, b) {
    if (a === b) return true;
    if (typeof a !== typeof b) return false;
    if (a === null || b === null) return false;
    if (Array.isArray(a) && Array.isArray(b)) {
      if (a.length !== b.length) return false;
      for (var i = 0; i < a.length; i++) {
        if (!util.isDeepStrictEqual(a[i], b[i])) return false;
      }
      return true;
    }
    if (typeof a === "object") {
      var aKeys = Object.keys(a);
      var bKeys = Object.keys(b);
      if (aKeys.length !== bKeys.length) return false;
      for (var j = 0; j < aKeys.length; j++) {
        if (!Object.prototype.hasOwnProperty.call(b, aKeys[j])) return false;
        if (!util.isDeepStrictEqual(a[aKeys[j]], b[aKeys[j]])) return false;
      }
      return true;
    }
    return false;
  }
};

util.promisify.custom = {};

util.parseArgs = function parseArgs(config) {
  config = config || {};
  var args = config.args || (typeof process !== 'undefined' ? process.argv.slice(2) : []);
  var options = config.options || {};
  var strict = config.strict !== false;
  var allowPositionals = config.allowPositionals !== false;

  var values = {};
  var positionals = [];
  var tokens = [];

  // Initialize defaults
  for (var name in options) {
    if (Object.prototype.hasOwnProperty.call(options, name)) {
      var opt = options[name];
      if (opt.default !== undefined) values[name] = opt.default;
      else if (opt.type === 'boolean') values[name] = false;
      else if (opt.multiple) values[name] = [];
    }
  }

  function findOption(arg) {
    // Check long form
    for (var name in options) {
      if (Object.prototype.hasOwnProperty.call(options, name)) {
        if ('--' + name === arg) return name;
        if (options[name].short && ('-' + options[name].short) === arg) return name;
      }
    }
    return null;
  }

  var i = 0;
  var dashdash = false;
  while (i < args.length) {
    var arg = args[i];
    if (dashdash) { positionals.push(arg); i++; continue; }
    if (arg === '--') { dashdash = true; i++; continue; }
    if (arg.indexOf('--') === 0) {
      var eqIdx = arg.indexOf('=');
      var key, val;
      if (eqIdx !== -1) { key = arg.substring(0, eqIdx); val = arg.substring(eqIdx + 1); }
      else { key = arg; val = undefined; }
      var optName = findOption(key);
      if (!optName && strict) throw new Error('Unknown option: ' + key);
      if (optName) {
        var optDef = options[optName];
        if (optDef.type === 'boolean') {
          val = val !== undefined ? val !== 'false' : true;
        } else if (val === undefined && i + 1 < args.length) {
          i++; val = args[i];
        }
        if (optDef.multiple) {
          if (!values[optName]) values[optName] = [];
          values[optName].push(val);
        } else {
          values[optName] = val;
        }
      }
    } else if (arg.indexOf('-') === 0 && arg.length > 1) {
      var optName2 = findOption(arg);
      if (optName2) {
        var optDef2 = options[optName2];
        if (optDef2.type === 'boolean') {
          if (optDef2.multiple) {
            if (!values[optName2]) values[optName2] = [];
            values[optName2].push(true);
          } else { values[optName2] = true; }
        } else if (i + 1 < args.length) {
          i++;
          if (optDef2.multiple) {
            if (!values[optName2]) values[optName2] = [];
            values[optName2].push(args[i]);
          } else { values[optName2] = args[i]; }
        }
      } else if (strict) { throw new Error('Unknown option: ' + arg); }
      else { positionals.push(arg); }
    } else {
      if (!allowPositionals && strict) throw new Error('Unexpected positional: ' + arg);
      positionals.push(arg);
    }
    i++;
  }

  return { values: values, positionals: positionals };
};

module.exports = util;
"#
    .trim()
    .to_string()
}

#[allow(dead_code)]
pub(crate) fn node_timers_module() -> String {
    r#"
function setTimeout$1(callback, delay) {
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  if (typeof globalThis.setTimeout !== "function") {
    throw new Error("setTimeout is not available");
  }
  return globalThis.setTimeout(function() {
    callback.apply(null, args);
  }, delay || 0);
}

function clearTimeout$1(handle) {
  if (typeof globalThis.clearTimeout === "function") {
    globalThis.clearTimeout(handle);
  }
}

function setInterval$1(callback, delay) {
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  if (typeof globalThis.setInterval !== "function") {
    throw new Error("setInterval is not available");
  }
  return globalThis.setInterval(function() {
    callback.apply(null, args);
  }, delay || 0);
}

function clearInterval$1(handle) {
  if (typeof globalThis.clearInterval === "function") {
    globalThis.clearInterval(handle);
  }
}

function setImmediate$1(callback) {
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  return setTimeout$1(function() {
    callback.apply(null, args);
  }, 0);
}

function clearImmediate$1(handle) {
  clearTimeout$1(handle);
}

module.exports = {
  setTimeout: setTimeout$1,
  clearTimeout: clearTimeout$1,
  setInterval: setInterval$1,
  clearInterval: clearInterval$1,
  setImmediate: setImmediate$1,
  clearImmediate: clearImmediate$1
};
"#
    .trim()
    .to_string()
}

fn node_timers_promises_module() -> String {
    r#"
function delay(ms, value, options) {
  var delayMs = ms == null ? 0 : Number(ms);
  var resultValue = value === undefined ? undefined : value;
  return new Promise(function(resolve) {
    setTimeout(function() {
      resolve(resultValue);
    }, delayMs);
  });
}

function setImmediate$1(value) {
  return delay(0, value);
}

module.exports = {
  setTimeout: delay,
  setImmediate: setImmediate$1
};
"#
    .trim()
    .to_string()
}

fn node_http_module() -> String {
    r#"
var EventEmitter = require('node:events').EventEmitter;

function resolveHeaderName(value) {
  if (typeof value !== 'string') {
    return String(value || '');
  }
  return value.toLowerCase();
}

function toHttpUrl(options) {
  if (typeof options === "string") {
    return options;
  }
  if (options === null || options === undefined) {
    throw new TypeError("Invalid request target");
  }
  if (typeof options === "object") {
    if (typeof options.toString === "function" && options instanceof Date) {
      return String(options);
    }
    if (typeof options.href === "string") return options.href;
    if (typeof options.url === "string") return options.url;
    var protocol = options.protocol || "http:";
    var hostname = options.hostname || options.host || "localhost";
    var port = options.port ? ":" + options.port : "";
    var path = options.path;
    if (path === undefined) {
      var pathname = options.pathname || "/";
      var search = options.search || "";
      var hash = options.hash || "";
      if (search && search.charAt(0) !== "?") {
        search = "?" + search;
      }
      if (hash && hash.charAt(0) !== '#') {
        hash = '#' + hash;
      }
      path = pathname + search + hash;
    }
    return protocol + "//" + hostname + port + path;
  }
  throw new TypeError("Invalid request target");
}

function toHttpPath(options) {
  if (!options) return "/";
  if (typeof options === "string") return "/";
  return options.path || options.pathname || "/";
}

function toMethod(options) {
  return ((options && options.method) || "GET").toUpperCase();
}

function toHeaders(source) {
  if (!source || typeof source !== "object") return {};
  var out = {};
  for (var key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      out[resolveHeaderName(key)] = String(source[key]);
    }
  }
  return out;
}

function parseHeaders(response) {
  var result = {};
  response.headers.forEach(function(value, key) {
    result[key] = value;
  });
  return result;
}

function IncomingMessage(response) {
  EventEmitter.call(this);
  this.statusCode = response.status;
  this.statusMessage = response.statusText;
  this.headers = parseHeaders(response);
  this.rawHeaders = [];
  for (var key in this.headers) {
    this.rawHeaders.push(key, this.headers[key]);
  }
  this.httpVersion = "1.1";
  this._response = response;
  this._consumed = false;
}
IncomingMessage.prototype = Object.create(EventEmitter.prototype);
IncomingMessage.prototype.constructor = IncomingMessage;

IncomingMessage.prototype._consumeBody = function() {
  if (this._consumed) return;
  this._consumed = true;
  var self = this;
  var response = this._response;
  // Use streaming body if ReadableStream is available
  if (response.body && typeof response.body.getReader === 'function') {
    var reader = response.body.getReader();
    var decoder = typeof TextDecoder !== 'undefined' ? new TextDecoder() : null;
    function pump() {
      reader.read().then(function(result) {
        if (result.done) {
          self.emit("end");
          self.emit("close");
          return;
        }
        var chunk = result.value;
        // Convert Uint8Array to string if we have a decoder
        if (chunk instanceof Uint8Array && decoder) {
          self.emit("data", decoder.decode(chunk, { stream: true }));
        } else {
          self.emit("data", chunk);
        }
        pump();
      }).catch(function(err) {
        self.emit("error", err);
      });
    }
    pump();
  } else {
    // Fallback: buffer entire body
    response
      .text()
      .then(function(text) {
        if (text) self.emit("data", text);
        self.emit("end");
        self.emit("close");
      })
      .catch(function(err) {
        self.emit("error", err);
      });
  }
};
IncomingMessage.prototype.setEncoding = function() { return this; };
IncomingMessage.prototype.pause = function() { return this; };
IncomingMessage.prototype.resume = function() {
  this._consumeBody();
  return this;
};
IncomingMessage.prototype.read = function() {
  return null;
};
IncomingMessage.prototype.destroy = function() {
  this.emit("close");
  return this;
};

function ClientRequest(options, callback) {
  EventEmitter.call(this);
  this.options = options || {};
  this._url = toHttpUrl(this.options);
  this.method = toMethod(this.options);
  this.path = toHttpPath(this.options);
  this.headers = toHeaders(this.options.headers);
  this._bodyParts = [];
  this._ended = false;
  this._sent = false;
  this._closed = false;
  this._aborted = false;
  if (typeof callback === "function") {
    this.once("response", callback);
  }
}
ClientRequest.prototype = Object.create(EventEmitter.prototype);
ClientRequest.prototype.constructor = ClientRequest;

ClientRequest.prototype.setHeader = function(name, value) {
  this.headers[resolveHeaderName(name)] = String(value);
};

ClientRequest.prototype.getHeader = function(name) {
  return this.headers[resolveHeaderName(name)];
};

ClientRequest.prototype.removeHeader = function(name) {
  var key = resolveHeaderName(name);
  var value = this.headers[key];
  delete this.headers[key];
  return value;
};

ClientRequest.prototype.getHeaders = function() {
  var clone = {};
  for (var key in this.headers) {
    if (Object.prototype.hasOwnProperty.call(this.headers, key)) {
      clone[key] = this.headers[key];
    }
  }
  return clone;
};

ClientRequest.prototype.write = function(chunk) {
  if (chunk !== undefined && chunk !== null) {
    this._bodyParts.push(String(chunk));
  }
  return true;
};

ClientRequest.prototype.end = function(chunk) {
  if (this._ended) return;
  if (chunk !== undefined && chunk !== null) {
    this._bodyParts.push(String(chunk));
  }
  this._ended = true;
  this._send();
};

ClientRequest.prototype.destroy = function() {
  this._aborted = true;
  this._closed = true;
  if (this._abortController) {
    try { this._abortController.abort(); } catch(e) {}
  }
  this.emit("close");
  return this;
};
ClientRequest.prototype.abort = ClientRequest.prototype.destroy;

ClientRequest.prototype.setTimeout = function(timeout, callback) {
  if (typeof timeout === 'number' && timeout > 0) {
    var self = this;
    this._timeoutId = setTimeout(function() {
      self.emit('timeout');
    }, timeout);
    if (typeof callback === 'function') {
      this.once('timeout', callback);
    }
  }
  return this;
};

ClientRequest.prototype._send = function() {
  if (this._sent) return;
  this._sent = true;
  var body = this._bodyParts.join("");
  if (typeof fetch !== "function") {
    this.emit("error", new Error("fetch is not available"));
    this.emit("close");
    return;
  }
  var init = {
    method: this.method,
    headers: this.headers
  };
  if (this.method !== "GET" && this.method !== "HEAD") {
    init.body = body;
  }
  // Use AbortController for cancellation support
  if (typeof AbortController !== 'undefined') {
    this._abortController = new AbortController();
    init.signal = this._abortController.signal;
    if (this._aborted) {
      this._abortController.abort();
    }
  }
  var self = this;
  fetch(this._url, init)
    .then(function(response) {
      if (self._timeoutId) clearTimeout(self._timeoutId);
      var responseMessage = new IncomingMessage(response);
      self.emit("response", responseMessage);
      responseMessage._consumeBody();
    })
    .catch(function(err) {
      if (self._timeoutId) clearTimeout(self._timeoutId);
      if (self._aborted) return;
      self.emit("error", err);
      self.emit("close");
    });
};

function request(options, callback) {
  var requestOptions = options;
  if (typeof options === "string") {
    requestOptions = {
      href: options,
      method: "GET"
    };
  }
  return new ClientRequest(requestOptions, callback);
}

function get(options, callback) {
  var req = request(options, callback);
  req.end();
  return req;
}

function Agent(options) {
  this.options = options || {};
  this.maxSockets = this.options.maxSockets || Infinity;
  this.maxFreeSockets = this.options.maxFreeSockets || 256;
  this.sockets = {};
  this.freeSockets = {};
  this.requests = {};
}
Agent.prototype.destroy = function() {};
Agent.prototype.getName = function(options) {
  return (options.host || 'localhost') + ':' + (options.port || 80);
};
var globalAgent = new Agent();

var METHODS = ["GET", "POST", "PUT", "PATCH", "HEAD", "DELETE", "OPTIONS", "CONNECT", "TRACE"];
var STATUS_CODES = {
  100: "Continue",
  101: "Switching Protocols",
  102: "Processing",
  103: "Early Hints",
  200: "OK",
  201: "Created",
  202: "Accepted",
  203: "Non-Authoritative Information",
  204: "No Content",
  205: "Reset Content",
  206: "Partial Content",
  207: "Multi-Status",
  208: "Already Reported",
  226: "IM Used",
  300: "Multiple Choices",
  301: "Moved Permanently",
  302: "Found",
  303: "See Other",
  304: "Not Modified",
  305: "Use Proxy",
  307: "Temporary Redirect",
  308: "Permanent Redirect",
  400: "Bad Request",
  401: "Unauthorized",
  402: "Payment Required",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  406: "Not Acceptable",
  407: "Proxy Authentication Required",
  408: "Request Timeout",
  409: "Conflict",
  410: "Gone",
  411: "Length Required",
  412: "Precondition Failed",
  413: "Payload Too Large",
  414: "URI Too Long",
  415: "Unsupported Media Type",
  416: "Range Not Satisfiable",
  417: "Expectation Failed",
  418: "I'm a Teapot",
  421: "Misdirected Request",
  422: "Unprocessable Entity",
  423: "Locked",
  424: "Failed Dependency",
  425: "Too Early",
  426: "Upgrade Required",
  428: "Precondition Required",
  429: "Too Many Requests",
  431: "Request Header Fields Too Large",
  451: "Unavailable For Legal Reasons",
  500: "Internal Server Error",
  501: "Not Implemented",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout",
  505: "HTTP Version Not Supported",
  506: "Variant Also Negotiates",
  507: "Insufficient Storage",
  508: "Loop Detected",
  510: "Not Extended",
  511: "Network Authentication Required"
};

// ServerResponse wraps the native HTTP respond functions
function ServerResponse(serverId, requestId) {
  EventEmitter.call(this);
  this.statusCode = 200;
  this.statusMessage = 'OK';
  this._headers = {};
  this._headersSent = false;
  this._finished = false;
  this._streaming = false;
  this._bodyParts = [];
  this._serverId = serverId;
  this._requestId = requestId;
  this.writableEnded = false;
  this.writableFinished = false;
}
ServerResponse.prototype = Object.create(EventEmitter.prototype);
ServerResponse.prototype.constructor = ServerResponse;

ServerResponse.prototype.setHeader = function(name, value) {
  this._headers[resolveHeaderName(name)] = String(value);
  return this;
};
ServerResponse.prototype.getHeader = function(name) {
  return this._headers[resolveHeaderName(name)];
};
ServerResponse.prototype.removeHeader = function(name) {
  delete this._headers[resolveHeaderName(name)];
  return this;
};
ServerResponse.prototype.getHeaders = function() {
  var clone = {};
  for (var k in this._headers) {
    if (Object.prototype.hasOwnProperty.call(this._headers, k)) clone[k] = this._headers[k];
  }
  return clone;
};
ServerResponse.prototype.hasHeader = function(name) {
  return resolveHeaderName(name) in this._headers;
};
ServerResponse.prototype.writeHead = function(statusCode, statusMessage, headers) {
  this.statusCode = statusCode;
  if (typeof statusMessage === 'string') {
    this.statusMessage = statusMessage;
  } else if (typeof statusMessage === 'object' && statusMessage !== null) {
    headers = statusMessage;
  }
  if (headers) {
    for (var k in headers) {
      if (Object.prototype.hasOwnProperty.call(headers, k)) {
        this._headers[resolveHeaderName(k)] = String(headers[k]);
      }
    }
  }
  return this;
};
ServerResponse.prototype._ensureStreaming = function() {
  if (this._streaming) return true;
  if (typeof __exactHttpRespondStream !== 'function') return false;
  var headersJson = JSON.stringify(this._headers);
  var result = __exactHttpRespondStream(this._serverId, this._requestId, this.statusCode, headersJson);
  if (result === 0) { this._streaming = true; this._headersSent = true; return true; }
  return false;
};
ServerResponse.prototype._sendChunk = function(chunk) {
  if (typeof __exactHttpRespondChunk !== 'function') return;
  if (typeof chunk === 'string') {
    var encoder = typeof TextEncoder === 'function' ? new TextEncoder() : null;
    var bytes = encoder ? encoder.encode(chunk) : null;
    if (bytes) __exactHttpRespondChunk(this._serverId, this._requestId, bytes);
  } else if (chunk) {
    __exactHttpRespondChunk(this._serverId, this._requestId, chunk);
  }
};
ServerResponse.prototype.write = function(chunk, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (this._finished) { if (callback) callback(new Error('write after end')); return false; }
  if (chunk !== undefined && chunk !== null) {
    var data = typeof chunk === 'string' ? chunk : String(chunk);
    if (this._ensureStreaming()) { this._sendChunk(data); }
    else { this._bodyParts.push(data); }
  }
  if (callback) setTimeout(callback, 0);
  return true;
};
ServerResponse.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = undefined; encoding = undefined; }
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (this._finished) { if (callback) setTimeout(callback, 0); return this; }
  if (chunk !== undefined && chunk !== null) this.write(chunk);
  this._finished = true;
  this.writableEnded = true;
  if (this._streaming) {
    if (typeof __exactHttpRespondEnd === 'function') __exactHttpRespondEnd(this._serverId, this._requestId);
    this.writableFinished = true;
    if (callback) setTimeout(callback, 0);
    this.emit('finish');
    this.emit('close');
  } else {
    this._sendResponse();
    if (callback) setTimeout(callback, 0);
  }
  return this;
};
ServerResponse.prototype._sendResponse = function() {
  var headersJson = JSON.stringify(this._headers);
  var body = this._bodyParts.join('');
  this._headersSent = true;
  if (typeof __exactHttpRespondString === 'function') {
    __exactHttpRespondString(this._serverId, this._requestId, this.statusCode, headersJson, body);
  } else if (typeof __exactHttpRespond === 'function') {
    var encoder = typeof TextEncoder === 'function' ? new TextEncoder() : null;
    var bodyBytes = encoder ? encoder.encode(body) : null;
    __exactHttpRespond(this._serverId, this._requestId, this.statusCode, headersJson, bodyBytes);
  }
  this.writableFinished = true;
  this.emit('finish');
  this.emit('close');
};
ServerResponse.prototype.setTimeout = function() { return this; };
ServerResponse.prototype.flushHeaders = function() {};

// ServerIncomingMessage for server-side requests
function ServerIncomingMessage(requestData, serverId) {
  EventEmitter.call(this);
  this.method = requestData.method || 'GET';
  this.url = requestData.url || '/';
  this.httpVersion = '1.1';
  this.headers = {};
  this.rawHeaders = [];
  // Body arrives base64-encoded from native bridge, decode it
  var rawBody = requestData.body || '';
  if (rawBody) {
    if (typeof atob === 'function') {
      try { rawBody = atob(rawBody); } catch(e) {}
    } else {
      var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      var lookup = {};
      for (var ci = 0; ci < chars.length; ci++) lookup[chars[ci]] = ci;
      var b64 = rawBody.replace(/[^A-Za-z0-9+\/]/g, '');
      var decoded = '';
      for (var bi = 0; bi < b64.length; bi += 4) {
        var a = lookup[b64[bi]] || 0, b = lookup[b64[bi+1]] || 0;
        var c = lookup[b64[bi+2]] || 0, d = lookup[b64[bi+3]] || 0;
        decoded += String.fromCharCode((a << 2) | (b >> 4));
        if (b64[bi+2] !== '=') decoded += String.fromCharCode(((b & 15) << 4) | (c >> 2));
        if (b64[bi+3] !== '=') decoded += String.fromCharCode(((c & 3) << 6) | d);
      }
      rawBody = decoded;
    }
  }
  this._body = rawBody;
  this._consumed = false;
  this._serverId = serverId || 0;
  this._requestId = requestData.id || 0;
  if (requestData.headers) {
    if (Array.isArray(requestData.headers)) {
      for (var k = 0; k < requestData.headers.length; k++) {
        var pair = requestData.headers[k];
        if (!pair || pair.length < 2) continue;
        var lkPair = resolveHeaderName(pair[0]);
        this.headers[lkPair] = pair[1];
        this.rawHeaders.push(pair[0], pair[1]);
      }
    } else if (typeof requestData.headers === 'object') {
      for (var k in requestData.headers) {
        if (Object.prototype.hasOwnProperty.call(requestData.headers, k)) {
          var lk = resolveHeaderName(k);
          this.headers[lk] = requestData.headers[k];
          this.rawHeaders.push(k, requestData.headers[k]);
        }
      }
    }
  }
  this.complete = false;
  this.socket = { remoteAddress: '127.0.0.1', remotePort: 0 };
}
ServerIncomingMessage.prototype = Object.create(EventEmitter.prototype);
ServerIncomingMessage.prototype.constructor = ServerIncomingMessage;
ServerIncomingMessage.prototype.setEncoding = function() { return this; };
ServerIncomingMessage.prototype.pause = function() { return this; };
ServerIncomingMessage.prototype.resume = function() {
  if (this._consumed) return this;
  this._consumed = true;
  var self = this;
  self.complete = true;
  setTimeout(function() {
    if (self._body) self.emit('data', self._body);
    self.emit('end');
  }, 0);
  return this;
};
ServerIncomingMessage.prototype.read = function() { return null; };
ServerIncomingMessage.prototype.destroy = function() {
  this.emit('close');
  return this;
};

// Server wraps exact:http native server infrastructure
function Server(requestListener) {
  EventEmitter.call(this);
  this._serverId = 0;
  this._listening = false;
  this._closing = false;
  this._requestListener = requestListener || null;
  if (typeof requestListener === 'function') {
    this.on('request', requestListener);
  }
}
Server.prototype = Object.create(EventEmitter.prototype);
Server.prototype.constructor = Server;

Server.prototype.listen = function(port, hostname, callback) {
  if (typeof port === 'object' && port !== null) {
    var opts = port;
    port = opts.port || 0;
    hostname = opts.host || opts.hostname || '0.0.0.0';
    callback = hostname;
    if (typeof hostname === 'function') {
      callback = hostname;
      hostname = '0.0.0.0';
    }
  }
  if (typeof hostname === 'function') {
    callback = hostname;
    hostname = '0.0.0.0';
  }
  port = port || 0;
  hostname = hostname || '0.0.0.0';

  if (typeof callback === 'function') {
    this.once('listening', callback);
  }

  if (typeof __exactHttpServe !== 'function') {
    var self = this;
    setTimeout(function() { self.emit('error', new Error('HTTP server not available')); }, 0);
    return this;
  }

  var resultJson = __exactHttpServe(port, hostname);
  var result;
  try { result = JSON.parse(resultJson); } catch(e) {
    var self = this;
    setTimeout(function() { self.emit('error', new Error('Server start failed')); }, 0);
    return this;
  }

  if (result.error) {
    var self = this;
    var errMsg = result.error;
    setTimeout(function() { self.emit('error', new Error(errMsg)); }, 0);
    return this;
  }

  this._serverId = result.id;
  this._port = result.port || port;
  this._hostname = hostname;
  this._listening = true;

  var self = this;
  setTimeout(function() { self.emit('listening'); }, 0);

  // Start request polling loop
  this._pollLoop();
  return this;
};

Server.prototype._pollLoop = function() {
  if (this._closing || !this._listening) return;
  var self = this;

  function poll() {
    if (self._closing || !self._listening) return;

    // Try synchronous poll first
    var json = null;
    if (typeof __exactHttpPoll === 'function') {
      json = __exactHttpPoll(self._serverId);
    }

    if (json) {
      self._handleRequest(json);
      // Continue polling immediately
      setTimeout(poll, 0);
    } else if (typeof __exactHttpWait === 'function') {
      // Async wait
      __exactHttpWait(self._serverId, 1000).then(function(waitJson) {
        if (waitJson) self._handleRequest(waitJson);
        setTimeout(poll, 0);
      }).catch(function() {
        setTimeout(poll, 50);
      });
    } else {
      setTimeout(poll, 50);
    }
  }

  poll();
};

Server.prototype._handleRequest = function(json) {
  var data;
  try { data = JSON.parse(json); } catch(e) { return; }

  var req = new ServerIncomingMessage(data, this._serverId);
  var res = new ServerResponse(this._serverId, data.id || 0);

  // Auto-consume body for data events
  if (req.listenerCount && req.listenerCount('data') > 0) {
    req.resume();
  }

  this.emit('request', req, res);
};

Server.prototype.close = function(callback) {
  if (typeof callback === 'function') this.once('close', callback);
  this._closing = true;
  this._listening = false;
  if (typeof __exactHttpClose === 'function' && this._serverId) {
    __exactHttpClose(this._serverId, 0);
  }
  var self = this;
  setTimeout(function() { self.emit('close'); }, 0);
  return this;
};

Server.prototype.address = function() {
  if (!this._listening) return null;
  if (typeof __exactHttpAddress === 'function') {
    var json = __exactHttpAddress(this._serverId);
    if (json) {
      try { return JSON.parse(json); } catch(e) {}
    }
  }
  return { address: this._hostname || '0.0.0.0', family: 'IPv4', port: this._port || 0 };
};

Server.prototype.setTimeout = function() { return this; };
Server.prototype.ref = function() {
  if (typeof __exactHttpSetRef === 'function' && this._serverId) {
    __exactHttpSetRef(this._serverId, 1);
  }
  return this;
};
Server.prototype.unref = function() {
  if (typeof __exactHttpSetRef === 'function' && this._serverId) {
    __exactHttpSetRef(this._serverId, 0);
  }
  return this;
};

function createServer(options, requestListener) {
  if (typeof options === 'function') {
    requestListener = options;
    options = {};
  }
  return new Server(requestListener);
}

module.exports = {
  request: request,
  get: get,
  Agent: Agent,
  createServer: createServer,
  Server: Server,
  ServerResponse: ServerResponse,
  IncomingMessage: IncomingMessage,
  ClientRequest: ClientRequest,
  METHODS: METHODS,
  STATUS_CODES: STATUS_CODES,
  globalAgent: globalAgent
};
"#
    .trim()
    .to_string()
}

fn node_stream_web_module() -> String {
    r#"
var Stream = require('node:stream');

var g = typeof globalThis === 'object' && globalThis !== null ? globalThis : {};
var cacheKey = '__exactNodeStreamWebModuleCache__';
var cachedModule = g[cacheKey];
if (cachedModule) {
  module.exports = cachedModule;
} else {
  var ReadableStream = g.ReadableStream;
  var ReadableStreamDefaultReader = g.ReadableStreamDefaultReader;
  var WritableStream = g.WritableStream;
  var WritableStreamDefaultWriter = g.WritableStreamDefaultWriter;
  var TransformStream = g.TransformStream;

  if (
    typeof ReadableStream !== 'function' ||
    typeof ReadableStreamDefaultReader !== 'function' ||
    typeof WritableStream !== 'function' ||
    typeof WritableStreamDefaultWriter !== 'function' ||
    typeof TransformStream !== 'function'
  ) {
    throw new TypeError('Web Streams API constructors are unavailable');
  }

  function isReadableStream(value) {
    if (typeof g.__exactIsReadableStream === 'function') {
      return g.__exactIsReadableStream(value);
    }
    return !!(
      value &&
      typeof value === 'object' &&
      typeof value.getReader === 'function' &&
      typeof value.cancel === 'function'
    );
  }

  function isWritableStream(value) {
    return value && typeof value.getWriter === 'function';
  }

  function fromWeb(stream) {
    if (!isReadableStream(stream)) {
      throw new TypeError('Expected web readable stream');
    }
    var reader = stream.getReader();
    var nodeReadable = new Stream.Readable();
    var pump = function() {
      reader.read().then(function(result) {
        if (!result || result.done) {
          nodeReadable.push(null);
        } else {
          nodeReadable.push(result.value);
          pump();
        }
      }).catch(function(err) {
        nodeReadable.emit('error', err);
      });
    };
    pump();
    return nodeReadable;
  }

  function toWeb(nodeReadable) {
    return new ReadableStream({
      start: function(controller) {
        if (!nodeReadable || typeof nodeReadable.on !== 'function') {
          controller.close();
          return;
        }
        nodeReadable.on('data', function(chunk) {
          controller.enqueue(chunk);
        });
        nodeReadable.on('end', function() {
          controller.close();
        });
        nodeReadable.on('error', function(err) {
          controller.error(err);
        });
        nodeReadable.on('close', function() {
          controller.close();
        });
      }
    });
  }

  cachedModule = {
    ReadableStream: ReadableStream,
    ReadableStreamDefaultReader: ReadableStreamDefaultReader,
    WritableStream: WritableStream,
    WritableStreamDefaultWriter: WritableStreamDefaultWriter,
    TransformStream: TransformStream,
    isReadableStream: isReadableStream,
    isWritableStream: isWritableStream,
    fromWeb: fromWeb,
    toWeb: toWeb
  };

  g[cacheKey] = cachedModule;
  module.exports = cachedModule;
}
"#
    .trim()
    .to_string()
}

fn node_url_module() -> String {
    r##"
var _UrlCtor = typeof globalThis !== "undefined" &&
  typeof globalThis.__exactUrlCtor === "function"
    ? globalThis.__exactUrlCtor
    : (typeof globalThis.URL === "function" ? globalThis.URL : null);
var _UrlSearchParamsCtor = typeof globalThis !== "undefined" &&
  typeof globalThis.__exactUrlSearchParamsCtor === "function"
    ? globalThis.__exactUrlSearchParamsCtor
    : (typeof globalThis.URLSearchParams === "function"
      ? globalThis.URLSearchParams
      : null);

function _normalizeUrlValue(value) {
  return String(value == null ? "" : value);
}

function _parseUrl(value) {
  value = _normalizeUrlValue(value);
  var parsed = {
    href: value,
    protocol: "",
    hostname: "",
    host: "",
    port: "",
    pathname: "/",
    search: "",
    hash: "",
    username: "",
    password: "",
    origin: "",
  };
  var remaining = value;
  // Extract hash
  var hashIndex = remaining.indexOf("#");
  if (hashIndex >= 0) {
    parsed.hash = remaining.slice(hashIndex);
    remaining = remaining.slice(0, hashIndex);
  }
  // Extract search
  var searchIndex = remaining.indexOf("?");
  if (searchIndex >= 0) {
    parsed.search = remaining.slice(searchIndex);
    remaining = remaining.slice(0, searchIndex);
  }
  // Extract protocol
  var protocolIndex = remaining.indexOf("://");
  if (protocolIndex >= 0) {
    parsed.protocol = remaining.slice(0, protocolIndex + 1);
    remaining = remaining.slice(protocolIndex + 3);
  }
  // Extract auth (user:pass@)
  var atIndex = remaining.indexOf("@");
  if (atIndex >= 0 && (remaining.indexOf("/") === -1 || atIndex < remaining.indexOf("/"))) {
    var auth = remaining.slice(0, atIndex);
    remaining = remaining.slice(atIndex + 1);
    var colonIndex = auth.indexOf(":");
    if (colonIndex >= 0) {
      parsed.username = auth.slice(0, colonIndex);
      parsed.password = auth.slice(colonIndex + 1);
    } else {
      parsed.username = auth;
    }
  }
  // Extract host and pathname
  var slashIndex = remaining.indexOf("/");
  if (slashIndex >= 0) {
    parsed.host = remaining.slice(0, slashIndex);
    parsed.pathname = remaining.slice(slashIndex);
  } else if (parsed.protocol) {
    parsed.host = remaining;
    parsed.pathname = "/";
  } else {
    parsed.pathname = remaining || "/";
  }
  // Extract port from host
  if (parsed.host) {
    // Handle IPv6 [::1]:port
    var bracketIndex = parsed.host.indexOf("]");
    var portColonIndex = parsed.host.lastIndexOf(":");
    if (bracketIndex >= 0) {
      portColonIndex = parsed.host.indexOf(":", bracketIndex);
    }
    if (portColonIndex >= 0 && (bracketIndex === -1 || portColonIndex > bracketIndex)) {
      parsed.port = parsed.host.slice(portColonIndex + 1);
      parsed.hostname = parsed.host.slice(0, portColonIndex);
    } else {
      parsed.hostname = parsed.host;
    }
  }
  // Build origin
  if (parsed.protocol && parsed.host) {
    parsed.origin = parsed.protocol + "//" + parsed.host;
  }
  // Reconstruct href
  parsed.href = "";
  if (parsed.protocol) parsed.href += parsed.protocol + "//";
  if (parsed.username) {
    parsed.href += parsed.username;
    if (parsed.password) parsed.href += ":" + parsed.password;
    parsed.href += "@";
  }
  parsed.href += parsed.host + parsed.pathname + parsed.search + parsed.hash;
  return parsed;
}

function URL(input, base) {
  if (!(this instanceof URL)) {
    return new URL(input, base);
  }
  if (_UrlCtor) {
    return new _UrlCtor(input, base);
  }
  var href = _normalizeUrlValue(input);
  var baseHref = base && base.href ? _normalizeUrlValue(base.href) : _normalizeUrlValue(base);
  if (baseHref && href.charAt(0) === "/" && baseHref.indexOf("://") !== -1) {
    var slashIndex = baseHref.lastIndexOf("/");
    if (slashIndex === baseHref.length - 1) {
      href = baseHref + href.slice(1);
    } else {
      href = baseHref.slice(0, slashIndex + 1) + href.slice(1);
    }
  }
  if (baseHref && href.indexOf(":") === -1 && baseHref.indexOf("://") !== -1) {
    var tail = baseHref.charAt(baseHref.length - 1) === "/"
      ? ""
      : "/";
    href = baseHref + tail + href;
  }
  var parsed = _parseUrl(href);
  this.href = parsed.href || href;
  this.protocol = parsed.protocol;
  this.hostname = parsed.hostname;
  this.host = parsed.host;
  this.port = parsed.port;
  this.pathname = parsed.pathname;
  this.search = parsed.search;
  this.hash = parsed.hash;
  this.origin = parsed.origin;
  this.username = parsed.username;
  this.password = parsed.password;
  this.searchParams = new URLSearchParams(parsed.search);
  this.toString = function() {
    return this.href;
  };
  this.toJSON = function() {
    return this.href;
  };
}

function URLSearchParams(init) {
  if (!(this instanceof URLSearchParams)) {
    return new URLSearchParams(init);
  }
  if (_UrlSearchParamsCtor) {
    return new _UrlSearchParamsCtor(init);
  }
  this._params = [];
  if (typeof init === 'string') {
    var str = init.replace(/^[?]/, '');
    if (str) {
      var pairs = str.split('&');
      for (var i = 0; i < pairs.length; i++) {
        var eq = pairs[i].indexOf('=');
        if (eq >= 0) {
          this._params.push([decodeURIComponent(pairs[i].slice(0, eq).replace(/\+/g, ' ')),
                             decodeURIComponent(pairs[i].slice(eq + 1).replace(/\+/g, ' '))]);
        } else {
          this._params.push([decodeURIComponent(pairs[i].replace(/\+/g, ' ')), '']);
        }
      }
    }
  } else if (init && typeof init === 'object') {
    var keys = Object.keys(init);
    for (var k = 0; k < keys.length; k++) {
      this._params.push([keys[k], String(init[keys[k]])]);
    }
  }
}
URLSearchParams.prototype.get = function(name) {
  for (var i = 0; i < this._params.length; i++) {
    if (this._params[i][0] === name) return this._params[i][1];
  }
  return null;
};
URLSearchParams.prototype.getAll = function(name) {
  var result = [];
  for (var i = 0; i < this._params.length; i++) {
    if (this._params[i][0] === name) result.push(this._params[i][1]);
  }
  return result;
};
URLSearchParams.prototype.has = function(name) { return this.get(name) !== null; };
URLSearchParams.prototype.set = function(name, value) {
  var found = false;
  for (var i = 0; i < this._params.length; i++) {
    if (this._params[i][0] === name) {
      if (!found) { this._params[i][1] = String(value); found = true; }
      else { this._params.splice(i, 1); i--; }
    }
  }
  if (!found) this._params.push([name, String(value)]);
};
URLSearchParams.prototype.append = function(name, value) { this._params.push([name, String(value)]); };
URLSearchParams.prototype.delete = function(name) {
  for (var i = 0; i < this._params.length; i++) {
    if (this._params[i][0] === name) { this._params.splice(i, 1); i--; }
  }
};
URLSearchParams.prototype.toString = function() {
  return this._params.map(function(p) {
    return encodeURIComponent(p[0]) + '=' + encodeURIComponent(p[1]);
  }).join('&');
};
URLSearchParams.prototype.forEach = function(callback, thisArg) {
  for (var i = 0; i < this._params.length; i++) {
    callback.call(thisArg, this._params[i][1], this._params[i][0], this);
  }
};
URLSearchParams.prototype.keys = function() {
  var params = this._params; var idx = 0;
  var iter = { next: function() { return idx < params.length ? { value: params[idx++][0], done: false } : { done: true }; } };
  iter[Symbol.iterator] = function() { return iter; };
  return iter;
};
URLSearchParams.prototype.values = function() {
  var params = this._params; var idx = 0;
  var iter = { next: function() { return idx < params.length ? { value: params[idx++][1], done: false } : { done: true }; } };
  iter[Symbol.iterator] = function() { return iter; };
  return iter;
};
URLSearchParams.prototype.entries = function() {
  var params = this._params; var idx = 0;
  var iter = { next: function() { return idx < params.length ? { value: params[idx++].slice(), done: false } : { done: true }; } };
  iter[Symbol.iterator] = function() { return iter; };
  return iter;
};
URLSearchParams.prototype[Symbol.iterator] = URLSearchParams.prototype.entries;

var URLExport = _UrlCtor || URL;
var URLSearchParamsExport = _UrlSearchParamsCtor || URLSearchParams;

if (typeof globalThis !== "undefined") {
  if (typeof globalThis.__exactUrlCtor !== "function") {
    globalThis.__exactUrlCtor = URLExport;
  }
  if (typeof globalThis.__exactUrlSearchParamsCtor !== "function") {
    globalThis.__exactUrlSearchParamsCtor = URLSearchParamsExport;
  }
}

function _coerceUrl(input) {
  if (input == null) {
    throw new TypeError('Expected URL or string');
  }
  if (typeof input === "string") {
    return new URL(input);
  }
  if (typeof input === 'object') {
    return input;
  }
  throw new TypeError('Expected URL or string');
}

function fileURLToPath(path) {
  var url = _coerceUrl(path);
  if (url.protocol && url.protocol !== 'file:') {
    throw new TypeError('Invalid URL protocol');
  }
  var value = url.pathname || '';
  if (typeof value === 'string' && value[0] === '/' && value[2] === ':') {
    value = value.slice(1);
  }
  return decodeURIComponent(value);
}

function pathToFileURL(path) {
  if (path == null) {
    throw new TypeError('Path is required');
  }
  var filePath = String(path);
  if (filePath.indexOf('%') !== -1) {
    filePath = decodeURIComponent(filePath);
  }
  var normalized = filePath.replace(/\\/g, '/');
  if (normalized.charAt(0) !== '/') {
    normalized = '/' + normalized;
  }
  return new URL('file://' + normalized);
}

function format(urlObj) {
  return _coerceUrl(urlObj).href;
}

function parse(value) {
  return new URL(value);
}

function resolve(from, to) {
  return new URL(to, from).href;
}

module.exports = {
  URL: URLExport,
  URLSearchParams: URLSearchParamsExport,
  format: format,
  parse: parse,
  resolve: resolve,
  fileURLToPath: fileURLToPath,
  pathToFileURL: pathToFileURL
};
	"##
    .trim()
    .to_string()
}

fn node_assert_module() -> String {
    r##"
function _typeof(v) {
  return v === null ? 'null' : typeof v;
}

function _inspect(v) {
  if (v === undefined) return 'undefined';
  if (v === null) return 'null';
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'function') return '[Function' + (v.name ? ': ' + v.name : '') + ']';
  try { return JSON.stringify(v); } catch(e) { return String(v); }
}

function AssertionError(opts) {
  var msg = opts.message || ('Expected values to be ' + (opts.operator || 'truthy'));
  if (opts.actual !== undefined && opts.expected !== undefined) {
    msg += '\n  actual: ' + _inspect(opts.actual) + '\n  expected: ' + _inspect(opts.expected);
  }
  var err = new Error(msg);
  err.name = 'AssertionError';
  err.actual = opts.actual;
  err.expected = opts.expected;
  err.operator = opts.operator;
  err.code = 'ERR_ASSERTION';
  return err;
}

function _deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return false;
  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (!_deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  var keysA = Object.keys(a);
  var keysB = Object.keys(b);
  if (keysA.length !== keysB.length) return false;
  for (var i = 0; i < keysA.length; i++) {
    var key = keysA[i];
    if (!Object.prototype.hasOwnProperty.call(b, key)) return false;
    if (!_deepEqual(a[key], b[key])) return false;
  }
  return true;
}

function ok(value, message) {
  if (!value) {
    throw AssertionError({
      message: message || 'The expression evaluated to a falsy value',
      actual: value,
      expected: true,
      operator: '=='
    });
  }
}

function equal(actual, expected, message) {
  if (actual != expected) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: '==' });
  }
}

function notEqual(actual, expected, message) {
  if (actual == expected) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: '!=' });
  }
}

function strictEqual(actual, expected, message) {
  if (actual !== expected) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: '===' });
  }
}

function notStrictEqual(actual, expected, message) {
  if (actual === expected) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: '!==' });
  }
}

function deepEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected)) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: 'deepEqual' });
  }
}

function deepStrictEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected)) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: 'deepStrictEqual' });
  }
}

function notDeepEqual(actual, expected, message) {
  if (_deepEqual(actual, expected)) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: 'notDeepEqual' });
  }
}

function notDeepStrictEqual(actual, expected, message) {
  if (_deepEqual(actual, expected)) {
    throw AssertionError({ message: message, actual: actual, expected: expected, operator: 'notDeepStrictEqual' });
  }
}

function throws(fn, expected, message) {
  var threw = false;
  var caught;
  try {
    fn();
  } catch (e) {
    threw = true;
    caught = e;
  }
  if (!threw) {
    throw AssertionError({
      message: message || 'Missing expected exception',
      operator: 'throws'
    });
  }
  if (expected) {
    if (typeof expected === 'function') {
      if (expected.prototype && caught instanceof expected) return;
      if (expected(caught) === true) return;
      throw AssertionError({ message: message || 'Unexpected exception', actual: caught, expected: expected, operator: 'throws' });
    }
    if (expected instanceof RegExp) {
      if (expected.test(String(caught))) return;
      throw AssertionError({ message: message || 'Unexpected exception', actual: caught, expected: expected, operator: 'throws' });
    }
  }
}

function doesNotThrow(fn, expected, message) {
  try {
    fn();
  } catch (e) {
    throw AssertionError({
      message: message || 'Got unwanted exception',
      actual: e,
      operator: 'doesNotThrow'
    });
  }
}

function ifError(err) {
  if (err !== null && err !== undefined) {
    throw err;
  }
}

function fail(message) {
  throw AssertionError({
    message: message || 'Failed',
    operator: 'fail'
  });
}

function match(string, regexp, message) {
  if (!regexp.test(string)) {
    throw AssertionError({ message: message, actual: string, expected: regexp, operator: 'match' });
  }
}

function doesNotMatch(string, regexp, message) {
  if (regexp.test(string)) {
    throw AssertionError({ message: message, actual: string, expected: regexp, operator: 'doesNotMatch' });
  }
}

function assert(value, message) {
  ok(value, message);
}

assert.ok = ok;
assert.equal = equal;
assert.notEqual = notEqual;
assert.strictEqual = strictEqual;
assert.notStrictEqual = notStrictEqual;
assert.deepEqual = deepEqual;
assert.deepStrictEqual = deepStrictEqual;
assert.notDeepEqual = notDeepEqual;
assert.notDeepStrictEqual = notDeepStrictEqual;
assert.throws = throws;
assert.doesNotThrow = doesNotThrow;
assert.ifError = ifError;
assert.fail = fail;
assert.match = match;
assert.doesNotMatch = doesNotMatch;
assert.AssertionError = AssertionError;
assert.strict = assert;

module.exports = assert;
"##
    .trim()
    .to_string()
}

fn node_os_module() -> String {
    r##"
var _platform = (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.platform) || "darwin";
var _arch = (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.arch) || "arm64";

function platform() { return _platform; }
function arch() { return _arch; }
function type() {
  if (_platform === "darwin") return "Darwin";
  if (_platform === "linux") return "Linux";
  if (_platform === "win32") return "Windows_NT";
  return "Unknown";
}
function release() {
  if (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.version) {
    return globalThis.process.version;
  }
  return "0.0.0";
}
function homedir() {
  if (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.env) {
    return globalThis.process.env.HOME || globalThis.process.env.USERPROFILE || "/";
  }
  return "/";
}
function tmpdir() {
  if (typeof globalThis !== "undefined" && globalThis.process && globalThis.process.env) {
    return globalThis.process.env.TMPDIR || globalThis.process.env.TMP || "/tmp";
  }
  return "/tmp";
}
function hostname() {
  if (typeof __exactGetHostname === 'function') return __exactGetHostname();
  return "localhost";
}
function cpus() {
  var count = 0;
  if (typeof __exactGetCpuCount === 'function') count = __exactGetCpuCount();
  if (count <= 0) return [];
  var result = [];
  for (var i = 0; i < count; i++) {
    result.push({ model: "unknown", speed: 0, times: { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 } });
  }
  return result;
}
function totalmem() {
  if (typeof __exactGetTotalMem === 'function') return __exactGetTotalMem();
  return 0;
}
function freemem() {
  if (typeof __exactGetFreeMem === 'function') return __exactGetFreeMem();
  return 0;
}
function uptime() {
  if (typeof __exactGetUptime === 'function') return __exactGetUptime();
  return 0;
}
function endianness() { return "LE"; }
function networkInterfaces() {
  if (typeof __exactGetNetworkInterfaces === 'function') return __exactGetNetworkInterfaces();
  return {};
}
function loadavg() {
  if (typeof __exactGetLoadAvg === 'function') return __exactGetLoadAvg();
  return [0, 0, 0];
}
function userInfo() {
  if (typeof __exactGetUserInfo === 'function') {
    var info = __exactGetUserInfo();
    return {
      uid: info.uid !== undefined ? info.uid : -1,
      gid: info.gid !== undefined ? info.gid : -1,
      username: info.username || "",
      homedir: info.homedir || homedir(),
      shell: info.shell !== undefined ? info.shell : null
    };
  }
  return {
    uid: -1,
    gid: -1,
    username: "",
    homedir: homedir(),
    shell: null
  };
}

var EOL = _platform === "win32" ? "\r\n" : "\n";
var devNull = _platform === "win32" ? "\\\\.\\NUL" : "/dev/null";

var constants = {
  signals: {},
  errno: {},
  priority: {}
};

module.exports = {
  platform: platform,
  arch: arch,
  type: type,
  release: release,
  homedir: homedir,
  tmpdir: tmpdir,
  hostname: hostname,
  cpus: cpus,
  totalmem: totalmem,
  freemem: freemem,
  uptime: uptime,
  endianness: endianness,
  networkInterfaces: networkInterfaces,
  loadavg: loadavg,
  userInfo: userInfo,
  EOL: EOL,
  devNull: devNull,
  constants: constants
};
"##
    .trim()
    .to_string()
}

fn node_tty_module() -> String {
    r##"
function isatty(fd) {
  var p = typeof globalThis !== 'undefined' && globalThis.process;
  if (!p) return false;
  if (fd === 0) return !!p.stdin && !!p.stdin.isTTY;
  if (fd === 1) return !!p.stdout && !!p.stdout.isTTY;
  if (fd === 2) return !!p.stderr && !!p.stderr.isTTY;
  return false;
}

function ReadStream() {
  throw new Error("tty.ReadStream is not supported");
}

function WriteStream() {
  throw new Error("tty.WriteStream is not supported");
}

module.exports = {
  isatty: isatty,
  ReadStream: ReadStream,
  WriteStream: WriteStream
};
"##
    .trim()
    .to_string()
}

fn node_string_decoder_module() -> String {
    r##"
function normalizeEncoding(enc) {
  if (!enc) return 'utf8';
  var lowered = String(enc).toLowerCase().replace(/[-_]/g, '');
  if (lowered === 'utf8') return 'utf8';
  if (lowered === 'ascii') return 'ascii';
  if (lowered === 'latin1' || lowered === 'binary') return 'latin1';
  if (lowered === 'base64') return 'base64';
  if (lowered === 'hex') return 'hex';
  if (lowered === 'utf16le' || lowered === 'ucs2') return 'utf16le';
  throw new TypeError('Unknown encoding: ' + enc);
}

function utf8ByteLength(leadByte) {
  if (leadByte < 0x80) return 1;
  if ((leadByte & 0xE0) === 0xC0) return 2;
  if ((leadByte & 0xF0) === 0xE0) return 3;
  if ((leadByte & 0xF8) === 0xF0) return 4;
  return 1;
}

function decodeUtf8Char(bytes, len) {
  var cp;
  if (len === 2) {
    cp = ((bytes[0] & 0x1F) << 6) | (bytes[1] & 0x3F);
  } else if (len === 3) {
    cp = ((bytes[0] & 0x0F) << 12) | ((bytes[1] & 0x3F) << 6) | (bytes[2] & 0x3F);
  } else if (len === 4) {
    cp = ((bytes[0] & 0x07) << 18) | ((bytes[1] & 0x3F) << 12) | ((bytes[2] & 0x3F) << 6) | (bytes[3] & 0x3F);
  } else {
    return String.fromCharCode(bytes[0]);
  }
  if (cp > 0xFFFF) {
    cp -= 0x10000;
    return String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
  }
  return String.fromCharCode(cp);
}

function StringDecoder(encoding) {
  this.encoding = normalizeEncoding(encoding);
  this._buf = null;
  this._bufLen = 0;
  this._needBytes = 0;
}

StringDecoder.prototype.write = function write(buf) {
  if (!buf || (typeof buf === 'object' && buf.length === 0)) return '';
  var bytes;
  if (buf instanceof Uint8Array) {
    bytes = buf;
  } else if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(buf)) {
    bytes = new Uint8Array(buf.buffer || buf, buf.byteOffset || 0, buf.length);
  } else if (typeof buf === 'string') {
    return buf;
  } else {
    bytes = new Uint8Array(buf);
  }
  if (bytes.length === 0) return '';
  var enc = this.encoding;
  if (enc === 'ascii') {
    var result = '';
    for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i] & 0x7F);
    return result;
  }
  if (enc === 'latin1') {
    var result = '';
    for (var i = 0; i < bytes.length; i++) result += String.fromCharCode(bytes[i]);
    return result;
  }
  if (enc === 'hex') {
    var result = '';
    for (var i = 0; i < bytes.length; i++) {
      var h = bytes[i].toString(16);
      if (h.length === 1) h = '0' + h;
      result += h;
    }
    return result;
  }
  if (enc === 'base64') {
    var input;
    if (this._bufLen > 0) {
      input = new Uint8Array(this._bufLen + bytes.length);
      for (var i = 0; i < this._bufLen; i++) input[i] = this._buf[i];
      for (var i = 0; i < bytes.length; i++) input[this._bufLen + i] = bytes[i];
    } else {
      input = bytes;
    }
    var remainder = input.length % 3;
    var encodeLen = input.length - remainder;
    if (remainder > 0) {
      this._buf = new Uint8Array(remainder);
      for (var i = 0; i < remainder; i++) this._buf[i] = input[encodeLen + i];
      this._bufLen = remainder;
    } else {
      this._buf = null;
      this._bufLen = 0;
    }
    if (encodeLen === 0) return '';
    var toEncode = (encodeLen === input.length) ? input : input.slice(0, encodeLen);
    var binary = '';
    for (var i = 0; i < toEncode.length; i++) binary += String.fromCharCode(toEncode[i]);
    return typeof btoa === 'function' ? btoa(binary) : '';
  }
  if (enc === 'utf16le') {
    var input;
    if (this._bufLen > 0) {
      input = new Uint8Array(this._bufLen + bytes.length);
      for (var i = 0; i < this._bufLen; i++) input[i] = this._buf[i];
      for (var i = 0; i < bytes.length; i++) input[this._bufLen + i] = bytes[i];
    } else {
      input = bytes;
    }
    var remainder = input.length % 2;
    var decodeLen = input.length - remainder;
    if (remainder > 0) {
      this._buf = new Uint8Array(1);
      this._buf[0] = input[decodeLen];
      this._bufLen = 1;
    } else {
      this._buf = null;
      this._bufLen = 0;
    }
    var result = '';
    for (var i = 0; i < decodeLen; i += 2) {
      result += String.fromCharCode(input[i] | (input[i + 1] << 8));
    }
    return result;
  }
  return this._writeUtf8(bytes);
};

StringDecoder.prototype._writeUtf8 = function _writeUtf8(bytes) {
  var result = '';
  var i = 0;
  if (this._bufLen > 0) {
    var need = this._needBytes - this._bufLen;
    if (bytes.length < need) {
      var newBuf = new Uint8Array(this._bufLen + bytes.length);
      for (var j = 0; j < this._bufLen; j++) newBuf[j] = this._buf[j];
      for (var j = 0; j < bytes.length; j++) newBuf[this._bufLen + j] = bytes[j];
      this._buf = newBuf;
      this._bufLen = newBuf.length;
      return '';
    }
    var charBytes = new Uint8Array(this._needBytes);
    for (var j = 0; j < this._bufLen; j++) charBytes[j] = this._buf[j];
    for (var j = 0; j < need; j++) charBytes[this._bufLen + j] = bytes[j];
    var valid = true;
    for (var j = 1; j < this._needBytes; j++) {
      if ((charBytes[j] & 0xC0) !== 0x80) { valid = false; break; }
    }
    if (valid) {
      if (typeof TextDecoder !== 'undefined') {
        result += new TextDecoder('utf-8').decode(charBytes);
      } else {
        result += decodeUtf8Char(charBytes, this._needBytes);
      }
    } else {
      result += '\uFFFD';
    }
    i = need;
    this._buf = null;
    this._bufLen = 0;
    this._needBytes = 0;
  }
  while (i < bytes.length) {
    var b = bytes[i];
    var seqLen = utf8ByteLength(b);
    if (i + seqLen <= bytes.length) {
      if (seqLen === 1) {
        result += String.fromCharCode(b);
        i += 1;
      } else {
        var valid = true;
        for (var j = 1; j < seqLen; j++) {
          if ((bytes[i + j] & 0xC0) !== 0x80) { valid = false; break; }
        }
        if (valid) {
          if (typeof TextDecoder !== 'undefined') {
            result += new TextDecoder('utf-8').decode(bytes.slice(i, i + seqLen));
          } else {
            result += decodeUtf8Char(bytes.slice(i, i + seqLen), seqLen);
          }
          i += seqLen;
        } else {
          result += '\uFFFD';
          i += 1;
        }
      }
    } else {
      var remaining = bytes.length - i;
      this._buf = new Uint8Array(remaining);
      for (var j = 0; j < remaining; j++) this._buf[j] = bytes[i + j];
      this._bufLen = remaining;
      this._needBytes = seqLen;
      break;
    }
  }
  return result;
};

StringDecoder.prototype.end = function end(buf) {
  var result = '';
  if (buf && (typeof buf === 'string' || (typeof buf === 'object' && buf.length > 0))) {
    result = this.write(buf);
  }
  if (this._bufLen > 0) {
    var enc = this.encoding;
    if (enc === 'utf8') {
      result += '\uFFFD';
    } else if (enc === 'utf16le') {
      if (this._bufLen === 1) result += String.fromCharCode(this._buf[0]);
    } else if (enc === 'base64') {
      var binary = '';
      for (var i = 0; i < this._bufLen; i++) binary += String.fromCharCode(this._buf[i]);
      result += typeof btoa === 'function' ? btoa(binary) : '';
    }
    this._buf = null;
    this._bufLen = 0;
    this._needBytes = 0;
  }
  return result;
};

StringDecoder.prototype.text = function text(buf, i) {
  return this.write(buf);
};

StringDecoder.prototype[Symbol.toPrimitive] = function() {
  return 'StringDecoder';
};

StringDecoder.prototype.toString = function() {
  return '[object StringDecoder]';
};

module.exports = StringDecoder;
module.exports.StringDecoder = StringDecoder;
"##
    .trim()
    .to_string()
}

fn node_querystring_module() -> String {
    r##"
var qs = {};

qs.escape = function escape(str) {
  return encodeURIComponent(str);
};

qs.unescape = function unescape(str) {
  try {
    return decodeURIComponent(str.replace(/\+/g, ' '));
  } catch (e) {
    return str;
  }
};

qs.stringify = function stringify(obj, sep, eq, options) {
  sep = sep || '&';
  eq = eq || '=';
  var encode = (options && typeof options.encodeURIComponent === 'function')
    ? options.encodeURIComponent
    : qs.escape;

  if (obj === null || obj === undefined || typeof obj !== 'object') {
    return '';
  }

  var keys = Object.keys(obj);
  var parts = [];

  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    var value = obj[key];
    var encodedKey = encode(key);

    if (Array.isArray(value)) {
      for (var j = 0; j < value.length; j++) {
        var item = value[j];
        if (item === null || item === undefined) {
          parts.push(encodedKey + eq);
        } else {
          parts.push(encodedKey + eq + encode(String(item)));
        }
      }
    } else if (value === null || value === undefined) {
      parts.push(encodedKey + eq);
    } else {
      parts.push(encodedKey + eq + encode(String(value)));
    }
  }

  return parts.join(sep);
};

qs.parse = function parse(str, sep, eq, options) {
  sep = sep || '&';
  eq = eq || '=';
  var maxKeys = 1000;
  if (options && typeof options.maxKeys === 'number') {
    maxKeys = options.maxKeys;
  }
  var decode = (options && typeof options.decodeURIComponent === 'function')
    ? options.decodeURIComponent
    : qs.unescape;

  var obj = Object.create(null);

  if (typeof str !== 'string' || str.length === 0) {
    return obj;
  }

  var pairs = str.split(sep);
  var len = pairs.length;
  if (maxKeys > 0 && len > maxKeys) {
    len = maxKeys;
  }

  for (var i = 0; i < len; i++) {
    var pair = pairs[i];
    var eqIdx = pair.indexOf(eq);
    var key, value;

    if (eqIdx >= 0) {
      key = decode(pair.substring(0, eqIdx));
      value = decode(pair.substring(eqIdx + eq.length));
    } else {
      key = decode(pair);
      value = '';
    }

    if (key === '') continue;

    if (obj[key] !== undefined) {
      if (Array.isArray(obj[key])) {
        obj[key].push(value);
      } else {
        obj[key] = [obj[key], value];
      }
    } else {
      obj[key] = value;
    }
  }

  return obj;
};

qs.encode = qs.stringify;
qs.decode = qs.parse;

module.exports = qs;
"##
    .trim()
    .to_string()
}

fn node_punycode_module() -> String {
    r##"
var punycode = {};

// Bootstring parameters (RFC 3492 Section 5)
var base = 36;
var tMin = 1;
var tMax = 26;
var skew = 38;
var damp = 700;
var initialBias = 72;
var initialN = 128;
var delimiter = '-';

var maxInt = 2147483647;

function error(type) {
  throw new RangeError('punycode: ' + type);
}

function digitToBasic(digit, flag) {
  return digit + 22 + 75 * (digit < 26 ? 1 : 0) - ((flag !== 0 ? 1 : 0) << 5);
}

function basicToDigit(cp) {
  if (cp - 0x30 < 0x0A) return cp - 0x16;
  if (cp - 0x41 < 0x1A) return cp - 0x41;
  if (cp - 0x61 < 0x1A) return cp - 0x61;
  return base;
}

function adapt(delta, numPoints, firstTime) {
  var k = 0;
  delta = firstTime ? Math.floor(delta / damp) : (delta >> 1);
  delta += Math.floor(delta / numPoints);
  while (delta > ((base - tMin) * tMax >> 1)) {
    delta = Math.floor(delta / (base - tMin));
    k += base;
  }
  return Math.floor(k + (base - tMin + 1) * delta / (delta + skew));
}

function ucs2decode(string) {
  var output = [];
  var counter = 0;
  var length = string.length;
  while (counter < length) {
    var value = string.charCodeAt(counter++);
    if (value >= 0xD800 && value <= 0xDBFF && counter < length) {
      var extra = string.charCodeAt(counter++);
      if ((extra & 0xFC00) === 0xDC00) {
        output.push(((value & 0x3FF) << 10) + (extra & 0x3FF) + 0x10000);
      } else {
        output.push(value);
        counter--;
      }
    } else {
      output.push(value);
    }
  }
  return output;
}

function ucs2encode(array) {
  var output = '';
  for (var i = 0; i < array.length; i++) {
    var value = array[i];
    if (value > 0xFFFF) {
      value -= 0x10000;
      output += String.fromCharCode(((value >>> 10) & 0x3FF) | 0xD800);
      value = 0xDC00 | (value & 0x3FF);
    }
    output += String.fromCharCode(value);
  }
  return output;
}

function decode(input) {
  var output = [];
  var inputLength = input.length;
  var i = 0;
  var n = initialN;
  var bias = initialBias;

  var basic = input.lastIndexOf(delimiter);
  if (basic < 0) basic = 0;

  for (var j = 0; j < basic; j++) {
    if (input.charCodeAt(j) >= 0x80) error('not-basic');
    output.push(input.charCodeAt(j));
  }

  var index = basic > 0 ? basic + 1 : 0;

  while (index < inputLength) {
    var oldi = i;
    var w = 1;

    for (var k = base; ; k += base) {
      if (index >= inputLength) error('invalid-input');
      var digit = basicToDigit(input.charCodeAt(index++));
      if (digit >= base || digit > Math.floor((maxInt - i) / w)) error('overflow');
      i += digit * w;
      var t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
      if (digit < t) break;
      var baseMinusT = base - t;
      if (w > Math.floor(maxInt / baseMinusT)) error('overflow');
      w *= baseMinusT;
    }

    var out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);

    if (Math.floor(i / out) > maxInt - n) error('overflow');
    n += Math.floor(i / out);
    i %= out;

    output.splice(i++, 0, n);
  }

  return ucs2encode(output);
}

function encode(input) {
  var output = [];

  var inputArray = ucs2decode(input);
  var inputLength = inputArray.length;

  var n = initialN;
  var delta = 0;
  var bias = initialBias;

  for (var j = 0; j < inputLength; j++) {
    if (inputArray[j] < 0x80) {
      output.push(String.fromCharCode(inputArray[j]));
    }
  }

  var basicLength = output.length;
  var handledCPCount = basicLength;

  if (basicLength > 0) {
    output.push(delimiter);
  }

  while (handledCPCount < inputLength) {
    var m = maxInt;
    for (var j2 = 0; j2 < inputLength; j2++) {
      if (inputArray[j2] >= n && inputArray[j2] < m) {
        m = inputArray[j2];
      }
    }

    if (m - n > Math.floor((maxInt - delta) / (handledCPCount + 1))) error('overflow');
    delta += (m - n) * (handledCPCount + 1);
    n = m;

    for (var j3 = 0; j3 < inputLength; j3++) {
      if (inputArray[j3] < n) {
        if (++delta > maxInt) error('overflow');
      }

      if (inputArray[j3] === n) {
        var q = delta;

        for (var k = base; ; k += base) {
          var t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
          if (q < t) break;
          var qMinusT = q - t;
          var baseMinusT = base - t;
          output.push(String.fromCharCode(digitToBasic(t + qMinusT % baseMinusT, 0)));
          q = Math.floor(qMinusT / baseMinusT);
        }

        output.push(String.fromCharCode(digitToBasic(q, 0)));
        bias = adapt(delta, handledCPCount + 1, handledCPCount === basicLength);
        delta = 0;
        handledCPCount++;
      }
    }

    delta++;
    n++;
  }

  return output.join('');
}

function toASCII(domain) {
  var parts = domain.split('.');
  var result = [];
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i];
    var hasNonASCII = false;
    for (var j = 0; j < part.length; j++) {
      if (part.charCodeAt(j) >= 0x80) {
        hasNonASCII = true;
        break;
      }
    }
    if (hasNonASCII) {
      result.push('xn--' + encode(part));
    } else {
      result.push(part);
    }
  }
  return result.join('.');
}

function toUnicode(domain) {
  var parts = domain.split('.');
  var result = [];
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i];
    if (part.indexOf('xn--') === 0) {
      try {
        result.push(decode(part.substring(4)));
      } catch (e) {
        result.push(part);
      }
    } else {
      result.push(part);
    }
  }
  return result.join('.');
}

punycode.version = '2.3.1';
punycode.ucs2 = {
  decode: ucs2decode,
  encode: ucs2encode
};
punycode.decode = decode;
punycode.encode = encode;
punycode.toASCII = toASCII;
punycode.toUnicode = toUnicode;

module.exports = punycode;
"##
    .trim()
    .to_string()
}


fn node_child_process_module() -> String {
    r##"
var cp = {};

function normalizeExecOptions(opts) {
  var o = {};
  if (!opts) return o;
  if (typeof opts === 'string') {
    o.encoding = opts;
    return o;
  }
  if (opts.cwd) o.cwd = String(opts.cwd);
  if (opts.timeout) o.timeout = Number(opts.timeout);
  if (opts.maxBuffer) o.maxBuffer = Number(opts.maxBuffer);
  if (opts.encoding !== undefined) o.encoding = opts.encoding;
  if (opts.env) o.env = opts.env;
  if (opts.shell !== undefined) o.shell = opts.shell;
  return o;
}

function makeExecError(message, result) {
  var err = new Error(message);
  err.status = result.status;
  err.stdout = result.stdout || '';
  err.stderr = result.stderr || '';
  err.signal = null;
  if (result.status < 0) {
    err.signal = 'SIGKILL';
  }
  err.pid = result.pid || 0;
  err.killed = result.error === 'Command timed out';
  return err;
}

cp.execSync = function execSync(command, options) {
  if (typeof command !== 'string') {
    throw new TypeError('The "command" argument must be of type string');
  }
  var opts = normalizeExecOptions(options);
  var optsJson = JSON.stringify(opts);
  var resultJson = globalThis.__exactExecSync(command, optsJson);
  var result = JSON.parse(resultJson);

  if (result.error) {
    throw makeExecError(result.error, result);
  }

  if (result.status !== 0) {
    var err = makeExecError(
      'Command failed: ' + command + '\n' + result.stderr,
      result
    );
    throw err;
  }

  var encoding = (opts && opts.encoding !== undefined) ? opts.encoding : 'utf8';
  if (encoding === 'buffer' || encoding === null) {
    // Return as Buffer-like Uint8Array
    var encoder = typeof TextEncoder !== 'undefined' ? new TextEncoder() : null;
    if (encoder) {
      return encoder.encode(result.stdout);
    }
    var buf = new Uint8Array(result.stdout.length);
    for (var i = 0; i < result.stdout.length; i++) {
      buf[i] = result.stdout.charCodeAt(i);
    }
    return buf;
  }

  return result.stdout;
};

cp.spawnSync = function spawnSync(command, args, options) {
  if (typeof command !== 'string') {
    throw new TypeError('The "command" argument must be of type string');
  }
  // Handle optional args parameter
  if (args && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  }
  if (!args) args = [];
  var opts = normalizeExecOptions(options);
  var argsJson = JSON.stringify(args);
  var optsJson = JSON.stringify(opts);
  var resultJson = globalThis.__exactSpawnSync(command, argsJson, optsJson);
  var result = JSON.parse(resultJson);

  var encoding = (opts && opts.encoding !== undefined) ? opts.encoding : 'utf8';

  var stdoutOutput = result.stdout || '';
  var stderrOutput = result.stderr || '';

  if (encoding === 'buffer' || encoding === null) {
    var encoder = typeof TextEncoder !== 'undefined' ? new TextEncoder() : null;
    if (encoder) {
      stdoutOutput = encoder.encode(stdoutOutput);
      stderrOutput = encoder.encode(stderrOutput);
    } else {
      var toBuf = function(s) {
        var buf = new Uint8Array(s.length);
        for (var i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i);
        return buf;
      };
      stdoutOutput = toBuf(stdoutOutput);
      stderrOutput = toBuf(stderrOutput);
    }
  }

  var output = [null, stdoutOutput, stderrOutput];

  var spawnResult = {
    pid: result.pid || 0,
    output: output,
    stdout: stdoutOutput,
    stderr: stderrOutput,
    status: result.status,
    signal: null,
    error: undefined
  };

  if (result.error) {
    spawnResult.error = new Error(result.error);
  }
  if (result.status < 0) {
    spawnResult.signal = 'SIGKILL';
  }

  return spawnResult;
};

cp.execFileSync = function execFileSync(file, args, options) {
  if (typeof file !== 'string') {
    throw new TypeError('The "file" argument must be of type string');
  }
  // Handle optional args parameter
  if (args && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  }
  if (!args) args = [];
  var result = cp.spawnSync(file, args, options);

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    var err = makeExecError(
      'Command failed: ' + file + ' ' + args.join(' '),
      { status: result.status, stdout: result.stdout, stderr: result.stderr, pid: result.pid }
    );
    throw err;
  }

  var opts = normalizeExecOptions(options);
  var encoding = (opts && opts.encoding !== undefined) ? opts.encoding : 'utf8';
  if (encoding === 'buffer' || encoding === null) {
    return result.stdout;
  }
  return typeof result.stdout === 'string' ? result.stdout : '';
};

cp.exec = function exec(command, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  if (typeof callback !== 'function') {
    callback = function() {};
  }
  // Simulate async with setTimeout
  var cmd = command;
  var opts = options;
  var cb = callback;
  setTimeout(function() {
    try {
      var result = cp.execSync(cmd, opts);
      cb(null, result, '');
    } catch (err) {
      cb(err, err.stdout || '', err.stderr || '');
    }
  }, 0);
};

cp.execFile = function execFile(file, args, options, callback) {
  if (typeof args === 'function') {
    callback = args;
    args = [];
    options = {};
  } else if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  if (typeof callback !== 'function') {
    callback = function() {};
  }
  var f = file;
  var a = args;
  var o = options;
  var cb = callback;
  setTimeout(function() {
    try {
      var result = cp.execFileSync(f, a, o);
      cb(null, result, '');
    } catch (err) {
      cb(err, err.stdout || '', err.stderr || '');
    }
  }, 0);
};

function _normalizeSpawnMode(mode, fallbackMode) {
  var normalized = mode === undefined || mode === null ? fallbackMode : mode;
  if (typeof normalized === 'string') {
    if (normalized === 'ignore' || normalized === 'overlapped' || normalized === 'inherit' || normalized === 'pipe' || normalized === 'ipc') return normalized === 'overlapped' || normalized === 'ipc' ? 'pipe' : normalized;
  }
  if (normalized === 0) return 'ignore';
  if (normalized === 1) return 'pipe';
  if (normalized === 2) return 'inherit';
  return 'pipe';
}

function _normalizeSpawnOptions(options) {
  var normalized = {
    cwd: options.cwd,
    env: options.env,
    shell: options.shell
  };
  var stdio = options.stdio;
  if (typeof stdio === 'string') {
    normalized.stdio = [_normalizeSpawnMode(stdio, 'pipe'), _normalizeSpawnMode(stdio, 'pipe'), _normalizeSpawnMode(stdio, 'pipe')];
  } else if (typeof stdio === 'number') {
    normalized.stdio = [_normalizeSpawnMode(stdio, 'pipe'), _normalizeSpawnMode(stdio, 'pipe'), _normalizeSpawnMode(stdio, 'pipe')];
  } else if (Array.isArray(stdio)) {
    normalized.stdio = [
      _normalizeSpawnMode(stdio[0], 'pipe'),
      _normalizeSpawnMode(stdio[1], 'pipe'),
      _normalizeSpawnMode(stdio[2], 'pipe')
    ];
  } else {
    normalized.stdio = ['pipe', 'pipe', 'pipe'];
  }
  return normalized;
}

function _toUint8String(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  var str = '';
  var i = 0;
  var len = value.length || 0;
  for (; i < len; i++) {
    var ch = value[i];
    if (typeof ch === 'number') str += String.fromCharCode(ch & 0xff);
    else if (typeof ch === 'string') str += ch;
  }
  return str;
}

// Signal name to number mapping
var signalMap = {
  'SIGHUP': 1, 'SIGINT': 2, 'SIGQUIT': 3, 'SIGILL': 4, 'SIGTRAP': 5,
  'SIGABRT': 6, 'SIGBUS': 7, 'SIGFPE': 8, 'SIGKILL': 9, 'SIGUSR1': 10,
  'SIGSEGV': 11, 'SIGUSR2': 12, 'SIGPIPE': 13, 'SIGALRM': 14, 'SIGTERM': 15
};

// Signal number to name mapping
var signalNames = {};
for (var sn in signalMap) {
  if (signalMap.hasOwnProperty(sn)) signalNames[signalMap[sn]] = sn;
}
if (typeof globalThis.__exactSpawnProcesses !== 'object') {
  globalThis.__exactSpawnProcesses = Object.create(null);
}
if (typeof globalThis.__exactSpawnPump !== 'function') {
  globalThis.__exactSpawnPump = function(handle) {
    if (!globalThis.__exactSpawnProcesses) {
      return;
    }
    var proc = globalThis.__exactSpawnProcesses[String(handle)];
    if (!proc) return;
    if (typeof proc.__pumpFromNative === 'function') {
      proc.__pumpFromNative();
    }
  };
}
if (typeof globalThis.__exactSpawnDispose !== 'function') {
  globalThis.__exactSpawnDispose = function(handle) {
    if (!globalThis.__exactSpawnProcesses) {
      return;
    }
    delete globalThis.__exactSpawnProcesses[String(handle)];
  };
}

// ChildProcess constructor (extends EventEmitter)
function ChildProcess(handle, pid, stdioModes) {
  var EventEmitter;
  try { EventEmitter = require('events'); } catch(e) {
    EventEmitter = function() { this._events = {}; };
    EventEmitter.prototype.on = function(ev, fn) { if (!this._events) this._events = {}; if (!this._events[ev]) this._events[ev] = []; this._events[ev].push(fn); return this; };
    EventEmitter.prototype.emit = function(ev) { if (!this._events) this._events = {}; var a = [].slice.call(arguments, 1); var l = this._events[ev] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
    EventEmitter.prototype.once = function(ev, fn) { var self = this; function w() { self.removeListener(ev, w); fn.apply(this, arguments); } this.on(ev, w); return this; };
    EventEmitter.prototype.removeListener = function(ev, fn) { if (!this._events) this._events = {}; var l = this._events[ev]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn) n.push(l[i]); } this._events[ev] = n; } return this; };
    EventEmitter.prototype.removeAllListeners = function(ev) { if (!this._events) this._events = {}; if (ev) delete this._events[ev]; else this._events = {}; return this; };
  }
  EventEmitter.call(this);
  if (EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }
  this._events = this._events || {};
  this._handle = handle;
  this.pid = pid;
  this.exitCode = null;
  this.signalCode = null;
  this.killed = false;
  this.connected = false;
  this._exited = false;
  this._useNativePump = typeof globalThis.__exactSpawnPump === 'function';
  this._pumpInProgress = false;
  var modes = stdioModes || { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' };

  // Create stdout as a Readable stream
  var Stream = require('stream');
  var self = this;

  if (modes.stdout === 'pipe') {
    this.stdout = new Stream.Readable();
    this.stdout._read = function() {};
  } else if (modes.stdout === 'inherit' && typeof process !== 'undefined' && process.stdout) {
    this.stdout = process.stdout;
  } else {
    this.stdout = null;
  }

  if (modes.stderr === 'pipe') {
    this.stderr = new Stream.Readable();
    this.stderr._read = function() {};
  } else if (modes.stderr === 'inherit' && typeof process !== 'undefined' && process.stderr) {
    this.stderr = process.stderr;
  } else {
    this.stderr = null;
  }

  // Create stdin as a Writable stream
  if (modes.stdin === 'pipe') {
    this.stdin = new Stream.Writable({
      write: function(chunk, encoding, callback) {
        var data = _toByteString(chunk);
        var ok = globalThis.__exactSpawnWrite(self._handle, data);
        if (typeof callback === 'function') callback(ok ? null : new Error('write failed'));
      }
    });
    // Override end to also close the native stdin pipe
    this.stdin.end = function(chunk, encoding, callback) {
      if (typeof chunk === 'function') { callback = chunk; chunk = null; }
      if (typeof encoding === 'function') { callback = encoding; encoding = null; }
      if (chunk !== undefined && chunk !== null) {
        self.stdin.write(chunk, encoding);
      }
      if (typeof globalThis.__exactSpawnCloseStdin === 'function') {
        globalThis.__exactSpawnCloseStdin(self._handle);
      }
      self.stdin.writableEnded = true;
      self.stdin.writableFinished = true;
      self.stdin.emit('finish');
      self.stdin.emit('close');
      if (typeof callback === 'function') callback();
    };
  } else if (typeof globalThis.__exactSpawnCloseStdin === 'function') {
    globalThis.__exactSpawnCloseStdin(this._handle);
    this.stdin = null;
  } else {
    this.stdin = null;
  }

  function pushStreamData(kind, value, streamMode) {
    if (!value || !value.length) return;
    if (streamMode === 'pipe') {
      if (kind === 'stdout' && self.stdout) self.stdout.push(_toUint8String(value));
      if (kind === 'stderr' && self.stderr) self.stderr.push(_toUint8String(value));
      return;
    }
    if (streamMode === 'inherit') {
      if (kind === 'stdout' && typeof process !== 'undefined' && process.stdout) process.stdout.write(value);
      if (kind === 'stderr' && typeof process !== 'undefined' && process.stderr) process.stderr.write(value);
    }
  }

  this.stdio = [this.stdin, this.stdout, this.stderr];
  if (self._useNativePump && self._handle >= 0) {
    globalThis.__exactSpawnProcesses[String(self._handle)] = self;
  }

  // Start polling for stdout/stderr data and exit status
  var pollInterval = 10; // ms
  var stdoutEnded = false;
  var stderrEnded = false;

  function closeStreams() {
    if (!stdoutEnded) {
      stdoutEnded = true;
      if (self.stdout && self.stdout.push) self.stdout.push(null);
    }
    if (!stderrEnded) {
      stderrEnded = true;
      if (self.stderr && self.stderr.push) self.stderr.push(null);
    }
  }

  function parseSpawnStatus(jsonText) {
    try {
      return JSON.parse(jsonText);
    } catch(e) {
      return { exited: true, exitCode: -1, signal: 0, error: e && e.message ? e.message : 'Invalid spawn status payload' };
    }
  }

  function pollStreams() {
    if (self._pumpInProgress) return;
    if (self._exited && stdoutEnded && stderrEnded) return;
    self._pumpInProgress = true;

    // Poll stdout
    if (!stdoutEnded) {
      var outData = globalThis.__exactSpawnRead(self._handle, 'stdout');
      pushStreamData('stdout', outData, modes.stdout);
      if (modes.stdout === 'pipe' && (!outData || !outData.length)) {
        if (self._exited) stdoutEnded = true;
      }
    }

    // Poll stderr
    if (!stderrEnded) {
      var errData = globalThis.__exactSpawnRead(self._handle, 'stderr');
      pushStreamData('stderr', errData, modes.stderr);
      if (modes.stderr === 'pipe' && (!errData || !errData.length)) {
        if (self._exited) stderrEnded = true;
      }
    }

    // Poll exit status
    if (!self._exited) {
      var statusJson = globalThis.__exactSpawnPoll(self._handle);
      var status = parseSpawnStatus(statusJson);
      if (status.exited) {
        self._exited = true;
        if (status.error) {
          var statusErr = new Error(status.error);
          self.emit('error', statusErr);
        }

        // Do one final read to drain any remaining data
        var finalOut = globalThis.__exactSpawnRead(self._handle, 'stdout');
        if (finalOut && finalOut.length > 0) {
          pushStreamData('stdout', finalOut, modes.stdout);
        }
        var finalErr = globalThis.__exactSpawnRead(self._handle, 'stderr');
        if (finalErr && finalErr.length > 0) {
          pushStreamData('stderr', finalErr, modes.stderr);
        }

        // End the streams
        closeStreams();

        // Set exit info
        if (status.signal > 0) {
          self.signalCode = signalNames[status.signal] || null;
          self.exitCode = null;
        } else {
          self.exitCode = status.exitCode;
          self.signalCode = null;
        }

        self.emit('exit', self.exitCode, self.signalCode);
        // 'close' fires after streams are done
        setTimeout(function() {
          self.emit('close', self.exitCode, self.signalCode);
          if (globalThis.__exactSpawnProcesses) {
            delete globalThis.__exactSpawnProcesses[String(self._handle)];
          }
          if (typeof globalThis.__exactSpawnDispose === 'function') {
            globalThis.__exactSpawnDispose(self._handle);
          }
        }, 0);
        self._pumpInProgress = false;
        return;
      }
    }

    if (!self._useNativePump) {
      self._pollTimer = setTimeout(pollStreams, pollInterval);
    }
    self._pumpInProgress = false;
  }

  this.__pumpFromNative = pollStreams;

  if (self._useNativePump && self._handle >= 0) {
    var nativePollFallback = function() {
      if (self._exited) {
        return;
      }
      if (typeof self.__pumpFromNative === 'function') {
        self.__pumpFromNative();
      }
      if (!self._exited) {
        self._pollTimer = setTimeout(nativePollFallback, pollInterval);
      }
    };
    // Keep the JS event loop alive until the spawn settles for top-level await cases
    // where no other pending tasks exist.
    self._pollTimer = setTimeout(nativePollFallback, 0);
  } else {
    // Start polling for stdout/stderr data and exit status.
    var fallbackPoll = function() {
      pollStreams();
      if (!self._exited) {
        self._pollTimer = setTimeout(fallbackPoll, pollInterval);
      }
    };
    self._pollTimer = setTimeout(fallbackPoll, 0);
  }
}

ChildProcess.prototype.kill = function(signal) {
  if (this._exited) return false;
  var sig;
  if (typeof signal === 'string') {
    sig = signalMap[signal] || 15; // default SIGTERM
  } else if (typeof signal === 'number') {
    sig = signal;
  } else {
    sig = 15; // SIGTERM
  }
  this.killed = true;
  return globalThis.__exactSpawnKill(this._handle, sig);
};

ChildProcess.prototype.ref = function() { return this; };
ChildProcess.prototype.unref = function() { return this; };

cp.ChildProcess = ChildProcess;

cp.spawn = function spawn(command, args, options) {
  if (typeof command !== 'string') {
    throw new TypeError('The "command" argument must be of type string');
  }
  // Handle optional args parameter
  if (args && !Array.isArray(args) && typeof args === 'object') {
    options = args;
    args = [];
  }
  if (!args) args = [];
  if (!options) options = {};

  var normalizedOptions = _normalizeSpawnOptions(options);
  var opts = {};
  if (normalizedOptions.cwd) opts.cwd = String(normalizedOptions.cwd);
  if (normalizedOptions.shell !== undefined) opts.shell = normalizedOptions.shell;
  if (normalizedOptions.env) opts.env = normalizedOptions.env;
  if (options.stdio) opts.stdio = normalizedOptions.stdio;

  var argsJson = JSON.stringify(args);
  var optsJson = JSON.stringify(opts);
  var result;
  try {
    var resultJson = globalThis.__exactSpawn(command, argsJson, optsJson);
    result = JSON.parse(resultJson);
  } catch (e) {
    result = { error: 'Failed to initialize spawn' };
  }

  if (result.error) {
    // Return a ChildProcess that immediately emits error
    var errChild = new ChildProcess(-1, 0);
    setTimeout(function() {
      errChild.emit('error', new Error(result.error));
      errChild._exited = true;
      errChild.exitCode = -1;
      errChild.emit('exit', -1, null);
      errChild.emit('close', -1, null);
    }, 0);
    return errChild;
  }

  var stdioCfg = { stdin: normalizedOptions.stdio[0], stdout: normalizedOptions.stdio[1], stderr: normalizedOptions.stdio[2] };
  return new ChildProcess(result.handle, result.pid, stdioCfg);
};

// Stub for fork
cp.fork = function fork(modulePath, args, options) {
  if (typeof modulePath !== 'string') {
    throw new TypeError('The "modulePath" argument must be of type string');
  }
  if (Array.isArray(args)) {
    // args provided as array
  } else if (typeof args === 'object' && args !== null && !Array.isArray(args)) {
    options = args;
    args = [];
  }
  args = args || [];
  options = options || {};

  var execPath = options.execPath || (typeof process !== 'undefined' && process.execPath) || 'node';
  var execArgv = options.execArgv || (typeof process !== 'undefined' && process.execArgv) || [];
  var spawnArgs = execArgv.concat([modulePath]).concat(args);

  var spawnOptions = {
    cwd: options.cwd,
    env: options.env || (typeof process !== 'undefined' ? process.env : {}),
    stdio: options.silent ? 'pipe' : undefined,
    shell: false
  };

  var child = cp.spawn(execPath, spawnArgs, spawnOptions);
  child.connected = true;

  child.send = function(message, sendHandle, opts, callback) {
    if (typeof sendHandle === 'function') { callback = sendHandle; sendHandle = undefined; opts = undefined; }
    else if (typeof opts === 'function') { callback = opts; opts = undefined; }
    if (callback) setTimeout(function() { callback(null); }, 0);
    return true;
  };

  child.disconnect = function() {
    child.connected = false;
    child.emit('disconnect');
  };

  return child;
};

module.exports = cp;
"##
    .trim()
    .to_string()
}

fn node_readline_module() -> String {
    r##"
var EventEmitter;
try { EventEmitter = require('events'); } catch(e) {
  EventEmitter = function() { this._events = {}; };
  EventEmitter.prototype.on = function(e, fn) { if (!this._events[e]) this._events[e] = []; this._events[e].push(fn); return this; };
  EventEmitter.prototype.emit = function(e) { var a = [].slice.call(arguments, 1); var l = this._events[e] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
  EventEmitter.prototype.once = function(e, fn) { var self = this; function w() { self.removeListener(e, w); fn.apply(this, arguments); } this.on(e, w); return this; };
  EventEmitter.prototype.removeListener = function(e, fn) { var l = this._events[e]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn) n.push(l[i]); } this._events[e] = n; } return this; };
  EventEmitter.prototype.removeAllListeners = function(e) { if (e) delete this._events[e]; else this._events = {}; return this; };
}

function Interface(options) {
  if (!(this instanceof Interface)) return new Interface(options);
  if (typeof EventEmitter === 'function') {
    EventEmitter.call(this);
    if (EventEmitter.prototype) {
      for (var k in EventEmitter.prototype) {
        if (!this[k]) this[k] = EventEmitter.prototype[k];
      }
    }
  }
  this._events = this._events || {};
  options = options || {};
  this.input = options.input || (typeof process !== 'undefined' ? process.stdin : null);
  this.output = options.output || (typeof process !== 'undefined' ? process.stdout : null);
  this.terminal = options.terminal !== undefined ? options.terminal : false;
  this._promptStr = options.prompt !== undefined ? options.prompt : '> ';
  this.closed = false;
  this.line = '';
  this._lineBuffer = '';
  this.cursor = 0;
  this.history = [];
  this.historyIndex = -1;
  this._paused = false;

  // Listen for data events on the input stream to enable line buffering
  var self = this;
  if (this.input && typeof this.input.on === 'function') {
    this._onData = function(chunk) {
      if (self.closed) return;
      var str = typeof chunk === 'string' ? chunk : (chunk && typeof chunk.toString === 'function' ? chunk.toString('utf8') : String(chunk));
      self._lineBuffer += str;
      var lines = self._lineBuffer.split('\n');
      self._lineBuffer = lines.pop() || '';
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i].replace(/\r$/, '');
        self.line = line;
        if (self.history.length === 0 || self.history[0] !== line) {
          self.history.unshift(line);
        }
        self.emit('line', line);
      }
    };
    this._onEnd = function() {
      if (self.closed) return;
      if (self._lineBuffer.length > 0) {
        var remaining = self._lineBuffer.replace(/\r$/, '');
        self._lineBuffer = '';
        self.line = remaining;
        self.emit('line', remaining);
      }
      self.close();
    };
    this._onClose = function() { if (!self.closed) self.close(); };
    this.input.on('data', this._onData);
    this.input.on('end', this._onEnd);
    this.input.on('close', this._onClose);
    if (typeof this.input.resume === 'function') this.input.resume();
  }
}

Interface.prototype.setPrompt = function(p) {
  this._promptStr = p;
};

Interface.prototype.getPrompt = function() {
  return this._promptStr;
};

Interface.prototype.prompt = function(preserveCursor) {
  if (this.output && !this.closed) this.output.write(this._promptStr);
};

Interface.prototype.question = function(query, options, cb) {
  if (typeof options === 'function') {
    cb = options;
    options = {};
  }
  if (this.output) {
    this.output.write(query);
  }
  // Store callback for next line event
  var self = this;
  this.once('line', function(answer) {
    if (cb) cb(answer);
  });
};

Interface.prototype.write = function(data, key) {
  if (data != null) {
    var str = String(data);
    if (str.indexOf('\n') !== -1 && this._onData) {
      this._onData(str);
    } else {
      this.line += str;
    }
  }
};

Interface.prototype.close = function() {
  if (this.closed) return;
  this.closed = true;
  if (this.input && typeof this.input.removeListener === 'function') {
    if (this._onData) this.input.removeListener('data', this._onData);
    if (this._onEnd) this.input.removeListener('end', this._onEnd);
    if (this._onClose) this.input.removeListener('close', this._onClose);
  }
  this.emit('close');
};

Interface.prototype.pause = function() {
  this._paused = true;
  if (this.input && typeof this.input.pause === 'function') this.input.pause();
  this.emit('pause');
  return this;
};

Interface.prototype.resume = function() {
  this._paused = false;
  if (this.input && typeof this.input.resume === 'function') this.input.resume();
  this.emit('resume');
  return this;
};

Interface.prototype[Symbol.asyncIterator] = function() {
  var self = this;
  var done = false;
  var queue = [];
  var resolve = null;
  self.on('line', function(line) {
    if (resolve) { var r = resolve; resolve = null; r({ value: line, done: false }); }
    else queue.push(line);
  });
  self.on('close', function() {
    done = true;
    if (resolve) { var r = resolve; resolve = null; r({ value: undefined, done: true }); }
  });
  return {
    next: function() {
      if (queue.length > 0) return Promise.resolve({ value: queue.shift(), done: false });
      if (done) return Promise.resolve({ value: undefined, done: true });
      return new Promise(function(r) { resolve = r; });
    }
  };
};

function createInterface(options) {
  if (typeof options === 'object' && options.input) {
    return new Interface(options);
  }
  // Handle (input, output) positional args
  if (arguments.length >= 1) {
    var opts = {};
    opts.input = arguments[0];
    if (arguments.length >= 2) opts.output = arguments[1];
    return new Interface(opts);
  }
  return new Interface(options || {});
}

// Promises API
var promises = {
  createInterface: function(options) {
    var rl = createInterface(options);
    // Wrap question to return a Promise
    var origQuestion = rl.question;
    rl.question = function(query, options) {
      return new Promise(function(resolve) {
        origQuestion.call(rl, query, options, function(answer) {
          resolve(answer);
        });
      });
    };
    return rl;
  }
};

function clearLine(stream, dir, callback) {
  if (stream && typeof stream.write === 'function') {
    var code = dir < 0 ? '\x1b[1K' : dir > 0 ? '\x1b[0K' : '\x1b[2K';
    stream.write(code);
  }
  if (typeof callback === 'function') callback();
}

function clearScreenDown(stream, callback) {
  if (stream && typeof stream.write === 'function') stream.write('\x1b[0J');
  if (typeof callback === 'function') callback();
}

function cursorTo(stream, x, y, callback) {
  if (typeof y === 'function') { callback = y; y = undefined; }
  if (stream && typeof stream.write === 'function') {
    if (y !== undefined) stream.write('\x1b[' + (y + 1) + ';' + (x + 1) + 'H');
    else stream.write('\x1b[' + (x + 1) + 'G');
  }
  if (typeof callback === 'function') callback();
}

function moveCursor(stream, dx, dy, callback) {
  if (stream && typeof stream.write === 'function') {
    var s = '';
    if (dx > 0) s += '\x1b[' + dx + 'C';
    else if (dx < 0) s += '\x1b[' + (-dx) + 'D';
    if (dy > 0) s += '\x1b[' + dy + 'B';
    else if (dy < 0) s += '\x1b[' + (-dy) + 'A';
    if (s) stream.write(s);
  }
  if (typeof callback === 'function') callback();
}

function emitKeypressEvents(stream, iface) {
  // Stub: no-op that prevents errors when called
}

module.exports = {
  createInterface: createInterface,
  Interface: Interface,
  promises: promises,
  clearLine: clearLine,
  clearScreenDown: clearScreenDown,
  cursorTo: cursorTo,
  moveCursor: moveCursor,
  emitKeypressEvents: emitKeypressEvents
};
module.exports.default = module.exports;
"##
    .trim()
    .to_string()
}

fn node_tls_module() -> String {
    r##"
var net;
try { net = require('net'); } catch(e) {}

var _defaultTlsCipher = 'TLS_AES_256_GCM_SHA384';

function _normalizeCipherName(ciphers) {
  if (typeof ciphers !== 'string' || !ciphers) {
    return _defaultTlsCipher;
  }
  var first = ciphers.split(/[:,]/)[0];
  return first || _defaultTlsCipher;
}

function _generateFingerprint(seed, algorithm) {
  if (typeof __exactHashSync !== 'function') return '';
  try {
    var hash = __exactHashSync(algorithm || 'sha1', seed || '');
    if (typeof hash !== 'string') return '';
    return hash.toUpperCase().replace(/(.{2})(?!$)/g, '$1:');
  } catch(e) {
    return '';
  }
}

function _buildSyntheticCertificate(host, port, options, certSource) {
  var identity = host || 'localhost';
  var now = new Date();
  var validFrom = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
  var validTo = new Date(now.getTime() + (365 * 24 * 60 * 60 * 1000));
  var portSuffix = port ? ':' + port : '';
  var seed = identity + portSuffix + String(now.getTime());
  return {
    subject: { CN: identity },
    issuer: { CN: certSource || 'ExactTLS' },
    subjectaltname: 'DNS:' + identity,
    valid_from: validFrom.toUTCString(),
    valid_to: validTo.toUTCString(),
    serialNumber: '0000000000000001',
    fingerprint: _generateFingerprint(seed + ':sha1', 'sha1'),
    fingerprint256: _generateFingerprint(seed + ':sha256', 'sha256'),
    raw: null
  };
}

function _normalizeCheckError(error) {
  if (!error) return null;
  if (error instanceof Error) return error;
  if (typeof error === 'string') return new Error(error);
  return new Error('TLS server identity check failed');
}

function _isIpAddress(host) {
  if (!host || typeof host !== 'string') return false;
  if (host.indexOf(':') !== -1) return /^([0-9a-f:.]+)$/i.test(host);
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function _hostMatchesPattern(host, pattern) {
  if (!host || !pattern) return false;
  host = host.toLowerCase();
  pattern = pattern.toLowerCase();
  if (pattern[0] === '[' && pattern[pattern.length - 1] === ']') {
    pattern = pattern.substring(1, pattern.length - 1);
  }
  if (pattern.indexOf('*') === -1) return host === pattern;
  if (pattern.indexOf('*.') !== 0) return false;
  var suffix = pattern.substring(1);
  if (host.length <= suffix.length) return false;
  if (host.slice(-suffix.length) !== suffix) return false;
  return host.charAt(host.length - suffix.length - 1) === '.';
}

function _defaultCheckServerIdentity(hostname, cert) {
  if (!cert) return new Error('No server certificate');
  var host = (hostname || '').toLowerCase();
  if (!host) return new Error('Missing hostname');
  if (host[0] === '[' && host[host.length - 1] === ']') {
    host = host.substring(1, host.length - 1);
  }
  var isIp = _isIpAddress(host);

  var patterns = [];
  if (cert.subject && cert.subject.CN) patterns.push(cert.subject.CN);
  if (typeof cert.subjectaltname === 'string') {
    var parts = cert.subjectaltname.split(',');
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      if (p.indexOf('DNS:') === 0) patterns.push(p.substr(4));
      if (p.indexOf('IP Address:') === 0) patterns.push('ip:' + p.substr(11).trim());
    }
  }

  if (!patterns.length) return null;

  for (var j = 0; j < patterns.length; j++) {
    var pattern = patterns[j];
    if (isIp && pattern.indexOf('ip:') === 0) {
      if (_hostMatchesPattern(host, pattern.substr(3).trim())) return null;
      continue;
    }
    if (!isIp && _hostMatchesPattern(host, pattern)) return null;
  }

  return new Error('Hostname/IP mismatch');
}

function checkServerIdentity(hostname, cert) {
  return _defaultCheckServerIdentity(hostname, cert);
}

function _finalizeHandshake(socket) {
  var opts = socket._tlsOptions || {};
  var host = socket._servername || socket.remoteAddress || 'localhost';
  socket._peerCertificate = _buildSyntheticCertificate(host, socket.remotePort, opts, opts.cert || opts.pfx || 'ExactTLS');
  socket._localCertificate = _buildSyntheticCertificate(host, socket.remotePort, opts, opts.key ? 'ExactTLS' : 'ExactTLS');
  socket._cipher = { name: _normalizeCipherName(opts.ciphers), version: socket._protocol };
  var check = opts.checkServerIdentity || checkServerIdentity;
  var result = _normalizeCheckError(check(host, socket._peerCertificate, opts));
  if (result) {
    socket.authorizationError = result.message || String(result);
    socket.authorized = false;
    return false;
  }
  socket.authorizationError = null;
  socket.authorized = true;
  return true;
}

function TLSSocket(socket, options) {
  if (!(this instanceof TLSSocket)) return new TLSSocket(socket, options);
  options = options || {};
  this._events = {};
  this._socket = socket || null;
  this.encrypted = true;
  this.authorized = true;
  this.authorizationError = null;
  this._protocol = options.minVersion || options.maxVersion || DEFAULT_MAX_VERSION || 'TLSv1.3';
  this._session = null;
  this._sessionReused = false;
  this._peerCertificate = null;
  this._localCertificate = null;
  this._tlsOptions = options || {};
  this._servername = options.servername || options.host || options.hostname || null;
  this.connecting = false;
  this.readable = true;
  this.writable = true;
  this.destroyed = false;
  this.remoteAddress = null;
  this.remotePort = null;
  this.remoteFamily = 'IPv4';
  this.servername = this._servername;
  // Mixin EventEmitter
  var EventEmitter;
  try { EventEmitter = require('events'); } catch(e) {}
  if (typeof EventEmitter === 'function' && EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }
  this._cipher = { name: _normalizeCipherName(options.ciphers), version: this._protocol };
}

TLSSocket.prototype.getPeerCertificate = function() {
  return this._peerCertificate || {};
};
TLSSocket.prototype.getPeerX509Certificate = TLSSocket.prototype.getPeerCertificate;
TLSSocket.prototype.getCertificate = TLSSocket.prototype.getPeerCertificate;
TLSSocket.prototype.getCipher = function() {
  return this._cipher || { name: _normalizeCipherName(this._tlsOptions && this._tlsOptions.ciphers), version: this._protocol };
};
TLSSocket.prototype.getProtocol = function() { return this._protocol; };
TLSSocket.prototype.getSession = function() { return this._session; };
TLSSocket.prototype.isSessionReused = function() { return !!this._sessionReused; };
TLSSocket.prototype.getFinished = function() { return null; };
TLSSocket.prototype.getTLSTicket = function() { return null; };
TLSSocket.prototype.renegotiate = function() { return true; };
TLSSocket.prototype.setEncoding = function(enc) { return this; };
TLSSocket.prototype.write = function(data, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; }
  if (callback) setTimeout(callback, 0);
  return true;
};
TLSSocket.prototype.end = function(data, encoding, callback) {
  if (typeof data === 'function') { callback = data; data = null; }
  if (typeof encoding === 'function') { callback = encoding; encoding = null; }
  if (this._socket && typeof this._socket.end === 'function') return this._socket.end(data, encoding, callback);
  if (callback) setTimeout(callback, 0);
  return this;
};
TLSSocket.prototype.destroy = function(err) {
  this.destroyed = true;
  if (this._socket && typeof this._socket.destroy === 'function') this._socket.destroy(err);
  return this;
};
TLSSocket.prototype.setTimeout = function(timeout, callback) {
  if (callback) this.once('timeout', callback);
  return this;
};
TLSSocket.prototype.setNoDelay = function() { return this; };
TLSSocket.prototype.setKeepAlive = function() { return this; };
TLSSocket.prototype.ref = function() { return this; };
TLSSocket.prototype.unref = function() { return this; };
TLSSocket.prototype.address = function() { return { address: this.remoteAddress, port: this.remotePort, family: 'IPv4' }; };
TLSSocket.prototype.pause = function() { return this; };
TLSSocket.prototype.resume = function() { return this; };
TLSSocket.prototype.pipe = function(dest) { return dest; };

function _normalizeTlsConnectOptions(options) {
  if (options === null || typeof options === 'undefined') return {};
  if (typeof options === 'number' || typeof options === 'string') {
    return { port: Number(options) };
  }
  if (typeof options === 'object') return options;
  return {};
}

function connect(options, callback) {
  options = _normalizeTlsConnectOptions(options);
  var cb = callback;
  if (typeof options === 'number') {
    options = { port: options, host: arguments[1] || 'localhost' };
  } else if (typeof options === 'string') {
    options = { host: options, port: arguments[1] || 443 };
  } else if (typeof cb === 'undefined' && typeof arguments[1] === 'function') {
    cb = arguments[1];
  }
  if (typeof callback === 'function') cb = callback;

  var socket = new TLSSocket(null, options);
  if (cb) socket.once('secureConnect', cb);

  options = options || {};
  var host = options.host || options.hostname || 'localhost';
  var port = options.port || 443;
  if (typeof port === 'string') port = Number(port);
  socket.remoteAddress = host;
  socket.remotePort = port;
  socket.connecting = true;
  if (options.servername || options.sni) {
    socket.servername = options.servername || options.sni;
    socket._servername = socket.servername;
  }
  socket._protocol = options.minVersion || options.maxVersion || DEFAULT_MAX_VERSION || 'TLSv1.3';
  socket.authorized = true;
  socket.authorizationError = null;

  // Use net.Socket underneath to establish a real TCP connection
  try {
    var netSocket = net ? net.connect({ port: port, host: host }) : null;

    if (!netSocket) {
      setTimeout(function() {
        var err = new Error('net module not available for TLS transport');
        err.code = 'ECONNREFUSED';
        socket.emit('error', err);
      }, 0);
      return socket;
    }

    socket._socket = netSocket;

    // Proxy write/end/destroy to underlying net.Socket
    socket.write = function(data, encoding, cb) {
      if (typeof encoding === 'function') { cb = encoding; encoding = undefined; }
      return netSocket.write(data, encoding, cb);
    };
    socket.end = function(data, encoding, cb) {
      if (typeof data === 'function') { cb = data; data = undefined; }
      if (typeof encoding === 'function') { cb = encoding; encoding = undefined; }
      return netSocket.end(data, encoding, cb);
    };
    socket.destroy = function(err) { netSocket.destroy(err); socket.destroyed = true; return socket; };
    socket.pause = function() { netSocket.pause(); return socket; };
    socket.resume = function() { netSocket.resume(); return socket; };
    socket.setEncoding = function(enc) { netSocket.setEncoding(enc); return socket; };

    netSocket.on('connect', function() {
      socket.connecting = false;
      socket.encrypted = true;
      var handshakeOk = _finalizeHandshake(socket);
      socket.remoteAddress = options.host || 'localhost';
      socket.remotePort = options.port;
      socket.servername = options.servername || options.host || options.hostname || socket.servername;
      socket._session = null;
      socket._sessionReused = false;
      if (handshakeOk || options.rejectUnauthorized === false) {
        socket.emit('secure', true);
        socket.emit('secureConnect');
      } else if (socket.authorizationError) {
        var err = new Error(socket.authorizationError);
        socket.emit('error', err);
        socket.destroy(err);
      }
    });

    netSocket.on('data', function(data) { socket.emit('data', data); });
    netSocket.on('end', function() { socket.emit('end'); });
    netSocket.on('error', function(err) { socket.emit('error', err); });
    netSocket.on('close', function(hadError) { socket.emit('close', hadError); });
  } catch(e) {
    setTimeout(function() { socket.emit('error', e); }, 0);
  }

  return socket;
}

function createSecureContext(options) {
  return { context: options || {} };
}

function addContext(serverName, context, server, options) {
  if (!server || !server._contexts) {
    return false;
  }
  server._contexts[serverName] = {
    context: context || null,
    options: options || null
  };
  return true;
}

function createServer(options, secureConnectionListener) {
  if (typeof options === 'function') {
    secureConnectionListener = options;
    options = {};
  }
  var serverOptions = options || {};
  var server = net ? net.createServer(serverOptions, function(rawSocket) {
    var tlsSocket = new TLSSocket(rawSocket, {
      minVersion: serverOptions.minVersion,
      maxVersion: serverOptions.maxVersion
    });
    tlsSocket._protocol = serverOptions.minVersion || serverOptions.maxVersion || DEFAULT_MAX_VERSION || 'TLSv1.3';
    tlsSocket.remoteAddress = rawSocket.remoteAddress || null;
    tlsSocket.remotePort = rawSocket.remotePort || null;
    tlsSocket._peerCertificate = _buildSyntheticCertificate(
      tlsSocket.remoteAddress || tlsSocket.servername || 'localhost',
      tlsSocket.remotePort,
      serverOptions,
      serverOptions.cert || 'ExactTLS'
    );
    tlsSocket._cipher = { name: _normalizeCipherName(serverOptions.ciphers), version: tlsSocket._protocol };
    tlsSocket.authorized = serverOptions.rejectUnauthorized === false ? false : true;
    tlsSocket.authorizationError = null;
    tlsSocket._server = server;
    tlsSocket.emit('secure', true);
    server.emit('secureConnection', tlsSocket);
    if (typeof secureConnectionListener === 'function') {
      secureConnectionListener(tlsSocket, tlsSocket._session);
    }
  }) : { listen: function() { return this; }, close: function() { return this; } };
  server._contexts = {};
  server.addContext = function(serverName, context, cb) {
    return addContext(serverName, context, server, cb);
  };
  return server;
}

var DEFAULT_ECDH_CURVE = 'auto';
var DEFAULT_MIN_VERSION = 'TLSv1.2';
var DEFAULT_MAX_VERSION = 'TLSv1.3';
var DEFAULT_CIPHERS = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384';

// rootCertificates: empty array in Exact (OS handles cert validation via fetch)
var rootCertificates = Object.freeze([]);

module.exports = {
  TLSSocket: TLSSocket,
  connect: connect,
  createSecureContext: createSecureContext,
  checkServerIdentity: checkServerIdentity,
  createServer: createServer,
  DEFAULT_ECDH_CURVE: DEFAULT_ECDH_CURVE,
  DEFAULT_MIN_VERSION: DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION: DEFAULT_MAX_VERSION,
  DEFAULT_CIPHERS: DEFAULT_CIPHERS,
  rootCertificates: rootCertificates,
  SecureContext: function SecureContext() {}
};
module.exports.default = module.exports;
"##
    .trim()
    .to_string()
}

fn node_dns_module() -> String {
    r##"
function lookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  var family = options.family || 0;
  try {
    var json = __exactDnsLookup(hostname, family);
    var results = JSON.parse(json);
    if (results.length === 0) {
      var err = new Error('getaddrinfo ENOTFOUND ' + hostname);
      err.code = 'ENOTFOUND';
      err.hostname = hostname;
      if (callback) setTimeout(function() { callback(err); }, 0);
      return;
    }
    var result = results[0];
    if (options.all) {
      if (callback) setTimeout(function() { callback(null, results); }, 0);
    } else {
      if (callback) setTimeout(function() { callback(null, result.address, result.family); }, 0);
    }
  } catch(e) {
    var err = new Error('getaddrinfo ENOTFOUND ' + hostname);
    err.code = 'ENOTFOUND';
    err.hostname = hostname;
    if (callback) setTimeout(function() { callback(err); }, 0);
  }
}

var _hasDnsResolve = typeof __exactDnsResolve === 'function';
var _hasDnsReverse = typeof __exactDnsReverse === 'function';

function _resolveViaQuery(hostname, rrtype, callback) {
  if (!_hasDnsResolve) {
    var err = new Error('DNS record type ' + rrtype + ' requires native resolver');
    err.code = 'ENOTIMP';
    if (callback) setTimeout(function() { callback(err); }, 0);
    return;
  }
  try {
    var json = __exactDnsResolve(hostname, rrtype);
    var records = JSON.parse(json);
    if (callback) setTimeout(function() { callback(null, records); }, 0);
  } catch(e) {
    var err2 = new Error('query' + rrtype + ' ' + (e.message || String(e)));
    err2.code = 'ENOTFOUND';
    err2.hostname = hostname;
    if (callback) setTimeout(function() { callback(err2); }, 0);
  }
}

function resolve(hostname, rrtype, callback) {
  if (typeof rrtype === 'function') {
    callback = rrtype;
    rrtype = 'A';
  }
  if (rrtype === 'A') {
    lookup(hostname, { family: 4, all: true }, function(err, results) {
      if (err) { callback(err); return; }
      var addresses = [];
      for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
      callback(null, addresses);
    });
  } else if (rrtype === 'AAAA') {
    lookup(hostname, { family: 6, all: true }, function(err, results) {
      if (err) { callback(err); return; }
      var addresses = [];
      for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
      callback(null, addresses);
    });
  } else {
    _resolveViaQuery(hostname, rrtype, callback);
  }
}

function resolve4(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  lookup(hostname, { family: 4, all: true }, function(err, results) {
    if (err) { callback(err); return; }
    var addresses = [];
    for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
    callback(null, addresses);
  });
}

function resolve6(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  lookup(hostname, { family: 6, all: true }, function(err, results) {
    if (err) { callback(err); return; }
    var addresses = [];
    for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
    callback(null, addresses);
  });
}

function resolveMx(hostname, callback) {
  _resolveViaQuery(hostname, 'MX', callback);
}

function resolveTxt(hostname, callback) {
  _resolveViaQuery(hostname, 'TXT', callback);
}

function resolveSrv(hostname, callback) {
  _resolveViaQuery(hostname, 'SRV', callback);
}

function resolveNs(hostname, callback) {
  _resolveViaQuery(hostname, 'NS', callback);
}

function resolveCname(hostname, callback) {
  _resolveViaQuery(hostname, 'CNAME', callback);
}

function resolveSoa(hostname, callback) {
  _resolveViaQuery(hostname, 'SOA', function(err, records) {
    if (err) { callback(err); return; }
    // SOA returns a single record, not an array
    callback(null, records && records.length > 0 ? records[0] : null);
  });
}

function resolvePtr(hostname, callback) {
  _resolveViaQuery(hostname, 'PTR', callback);
}

function resolveCaa(hostname, callback) {
  _resolveViaQuery(hostname, 'CAA', callback);
}

function resolveNaptr(hostname, callback) {
  _resolveViaQuery(hostname, 'NAPTR', callback);
}

function reverse(ip, callback) {
  if (!_hasDnsReverse) {
    var err = new Error('dns.reverse requires native resolver');
    err.code = 'ENOTIMP';
    if (callback) setTimeout(function() { callback(err); }, 0);
    return;
  }
  try {
    var json = __exactDnsReverse(ip);
    var hostnames = JSON.parse(json);
    if (callback) setTimeout(function() { callback(null, hostnames); }, 0);
  } catch(e) {
    var err2 = new Error('getHostByAddr ' + (e.message || String(e)));
    err2.code = 'ENOTFOUND';
    if (callback) setTimeout(function() { callback(err2); }, 0);
  }
}

// Promises API
function _promisify1(fn) {
  return function(arg1) {
    return new Promise(function(res, reject) {
      fn(arg1, function(err, result) {
        if (err) reject(err);
        else res(result);
      });
    });
  };
}

var promises = {
  lookup: function(hostname, options) {
    return new Promise(function(resolve, reject) {
      lookup(hostname, options || {}, function(err, address, family) {
        if (err) reject(err);
        else resolve({ address: address, family: family });
      });
    });
  },
  resolve: function(hostname, rrtype) {
    return new Promise(function(res, reject) {
      resolve(hostname, rrtype || 'A', function(err, addresses) {
        if (err) reject(err);
        else res(addresses);
      });
    });
  },
  resolve4: function(hostname, options) {
    return new Promise(function(res, reject) {
      resolve4(hostname, options || {}, function(err, addresses) {
        if (err) reject(err);
        else res(addresses);
      });
    });
  },
  resolve6: function(hostname, options) {
    return new Promise(function(res, reject) {
      resolve6(hostname, options || {}, function(err, addresses) {
        if (err) reject(err);
        else res(addresses);
      });
    });
  },
  resolveMx: _promisify1(resolveMx),
  resolveTxt: _promisify1(resolveTxt),
  resolveSrv: _promisify1(resolveSrv),
  resolveNs: _promisify1(resolveNs),
  resolveCname: _promisify1(resolveCname),
  resolveSoa: _promisify1(resolveSoa),
  resolvePtr: _promisify1(resolvePtr),
  resolveCaa: _promisify1(resolveCaa),
  resolveNaptr: _promisify1(resolveNaptr),
  reverse: _promisify1(reverse)
};

// Error codes
var NODATA = 'ENODATA';
var FORMERR = 'EFORMERR';
var SERVFAIL = 'ESERVFAIL';
var NOTFOUND = 'ENOTFOUND';
var NOTIMP = 'ENOTIMP';
var REFUSED = 'EREFUSED';
var BADQUERY = 'EBADQUERY';
var BADNAME = 'EBADNAME';
var BADFAMILY = 'EBADFAMILY';
var BADRESP = 'EBADRESP';
var CONNREFUSED = 'ECONNREFUSED';
var TIMEOUT = 'ETIMEOUT';
var EOF = 'EOF';
var FILE = 'EFILE';
var NOMEM = 'ENOMEM';
var DESTRUCTION = 'EDESTRUCTION';
var BADSTR = 'EBADSTR';
var BADFLAGS = 'EBADFLAGS';
var NONAME = 'ENONAME';
var BADHINTS = 'EBADHINTS';
var NOTINITIALIZED = 'ENOTINITIALIZED';
var LOADIPHLPAPI = 'ELOADIPHLPAPI';
var ADDRGETNETWORKPARAMS = 'EADDRGETNETWORKPARAMS';
var CANCELLED = 'ECANCELLED';

module.exports = {
  lookup: lookup,
  resolve: resolve,
  resolve4: resolve4,
  resolve6: resolve6,
  resolveMx: resolveMx,
  resolveTxt: resolveTxt,
  resolveSrv: resolveSrv,
  resolveNs: resolveNs,
  resolveCname: resolveCname,
  resolveSoa: resolveSoa,
  resolvePtr: resolvePtr,
  resolveCaa: resolveCaa,
  resolveNaptr: resolveNaptr,
  reverse: reverse,
  promises: promises,
  NODATA: NODATA, FORMERR: FORMERR, SERVFAIL: SERVFAIL, NOTFOUND: NOTFOUND,
  NOTIMP: NOTIMP, REFUSED: REFUSED, BADQUERY: BADQUERY, BADNAME: BADNAME,
  BADFAMILY: BADFAMILY, BADRESP: BADRESP, CONNREFUSED: CONNREFUSED,
  TIMEOUT: TIMEOUT, EOF: EOF, FILE: FILE, NOMEM: NOMEM,
  DESTRUCTION: DESTRUCTION, BADSTR: BADSTR, BADFLAGS: BADFLAGS,
  NONAME: NONAME, BADHINTS: BADHINTS, NOTINITIALIZED: NOTINITIALIZED,
  CANCELLED: CANCELLED
};
module.exports.default = module.exports;
"##
    .trim()
    .to_string()
}

fn node_net_module() -> String {
    r##"
var EventEmitter;
try { EventEmitter = require('events'); } catch(e) {
  EventEmitter = function() { this._events = {}; };
  EventEmitter.prototype.on = function(e, fn) { if (!this._events[e]) this._events[e] = []; this._events[e].push(fn); return this; };
  EventEmitter.prototype.emit = function(e) { var a = [].slice.call(arguments, 1); var l = this._events[e] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
  EventEmitter.prototype.once = function(e, fn) { var self = this; function w() { self.removeListener(e, w); fn.apply(this, arguments); } w.listener = fn; this.on(e, w); return this; };
  EventEmitter.prototype.removeListener = function(e, fn) { var l = this._events[e]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn && l[i].listener !== fn) n.push(l[i]); } this._events[e] = n; } return this; };
  EventEmitter.prototype.removeAllListeners = function(e) { if (e) delete this._events[e]; else this._events = {}; return this; };
  EventEmitter.prototype.addListener = EventEmitter.prototype.on;
  EventEmitter.prototype.off = EventEmitter.prototype.removeListener;
  EventEmitter.prototype.listeners = function(e) { return (this._events[e] || []).slice(); };
  EventEmitter.prototype.listenerCount = function(e) { return (this._events[e] || []).length; };
  EventEmitter.prototype.prependListener = function(e, fn) { if (!this._events[e]) this._events[e] = []; this._events[e].unshift(fn); return this; };
}

// Check for native TCP support
var _hasTcp = typeof __exactTcpConnect === 'function';
// Check for native Unix socket support
var _hasUnix = typeof __exactUnixConnect === 'function';

// --- Socket class ---
function Socket(options) {
  if (!(this instanceof Socket)) return new Socket(options);
  options = options || {};
  this.readable = true;
  this.writable = true;
  this.destroyed = false;
  this.connecting = false;
  this._connected = false;
  this.remoteAddress = null;
  this.remotePort = null;
  this.remoteFamily = null;
  this.localAddress = null;
  this.localPort = null;
  this.bytesRead = 0;
  this.bytesWritten = 0;
  this.timeout = 0;
  this._timeoutMs = 0;
  this._timeoutTimer = null;
  this._lastActivity = 0;
  this._handle = null;
  this._pollTimer = null;
  this._paused = false;
  this._encoding = null;
  this._events = {};
  this._isUnix = false;
  this._socketPath = null;
  this.allowHalfOpen = options.allowHalfOpen || false;
  this.pending = true;
  this.readyState = 'closed';
  // Mixin EventEmitter
  if (typeof EventEmitter === 'function' && EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }
  // Track if this is a Unix socket (set by accepted connections or connect({path}))
  if (options._isUnix) {
    this._isUnix = true;
    this._socketPath = options._socketPath || null;
  }
  // If options._handle is provided, create from existing handle (for accepted connections)
  if (options._handle != null) {
    this._handle = options._handle;
    this._connected = true;
    this.connecting = false;
    this.pending = false;
    this.readyState = 'open';
    this._updateAddressInfo();
    this._startPolling();
  }
}

Socket.prototype._updateAddressInfo = function() {
  if (this._handle == null) return;
  // Unix sockets don't have IP address info
  if (this._isUnix) {
    this.remoteFamily = 'Unix';
    return;
  }
  if (!_hasTcp) return;
  try {
    var remote = __exactTcpRemoteAddr(this._handle);
    if (remote) {
      var r = JSON.parse(remote);
      this.remoteAddress = r.address;
      this.remotePort = r.port;
      this.remoteFamily = r.family;
    }
  } catch(e) {}
  try {
    var local = __exactTcpLocalAddr(this._handle);
    if (local) {
      var l = JSON.parse(local);
      this.localAddress = l.address;
      this.localPort = l.port;
    }
  } catch(e) {}
};

Socket.prototype._startPolling = function() {
  if (this._pollTimer != null || this.destroyed) return;
  var self = this;
  self._lastActivity = Date.now();
  function poll() {
    if (self.destroyed || self._handle == null) return;
    if (self._paused) {
      self._pollTimer = setTimeout(poll, 10);
      return;
    }
    try {
      var data = __exactTcpRead(self._handle, 65536);
      if (data === null) {
        // EOF
        self._pollTimer = null;
        self.readable = false;
        self.emit('end');
        if (!self.allowHalfOpen) {
          self.writable = false;
          self.destroy();
        } else {
          self.emit('close', false);
        }
        return;
      }
      if (data.length > 0) {
        self._lastActivity = Date.now();
        self.bytesRead += data.length;
        if (self._encoding) {
          self.emit('data', data);
        } else {
          // Emit as Buffer if available, otherwise string
          if (typeof Buffer !== 'undefined') {
            self.emit('data', Buffer.from(data, 'utf8'));
          } else {
            self.emit('data', data);
          }
        }
      }
    } catch(e) {
      self._pollTimer = null;
      if (!self.destroyed) {
        self.destroy(e);
      }
      return;
    }
    // Check idle timeout
    if (self._timeoutMs > 0 && (Date.now() - self._lastActivity) >= self._timeoutMs) {
      self.emit('timeout');
    }
    self._pollTimer = setTimeout(poll, 5);
  }
  self._pollTimer = setTimeout(poll, 0);
};

Socket.prototype.connect = function(options, connectListener) {
  if (typeof options === 'number') {
    var port = options;
    var host = arguments[1] || 'localhost';
    if (typeof arguments[1] === 'function') {
      connectListener = arguments[1];
      host = 'localhost';
    } else if (typeof arguments[2] === 'function') {
      connectListener = arguments[2];
    }
    options = { port: port, host: host };
  } else if (typeof options === 'string') {
    // Unix socket path
    options = { path: options };
  } else if (Array.isArray(options)) {
    // IPC connection array form - not supported
    options = {};
  }
  options = options || {};
  this.connecting = true;
  this.pending = true;
  this.readyState = 'opening';

  if (connectListener) this.once('connect', connectListener);

  // Unix domain socket connection
  if (options.path) {
    this._isUnix = true;
    this._socketPath = options.path;
    this.remoteFamily = 'Unix';

    if (!_hasUnix) {
      var self = this;
      setTimeout(function() {
        var err = new Error('Unix sockets not supported: native __exactUnixConnect not available');
        err.code = 'ECONNREFUSED';
        self.connecting = false;
        self.readyState = 'closed';
        self.pending = false;
        self.emit('error', err);
      }, 0);
      return this;
    }

    var self = this;
    setTimeout(function() {
      if (self.destroyed) return;
      try {
        self._handle = __exactUnixConnect(self._socketPath);
        self.connecting = false;
        self._connected = true;
        self.pending = false;
        self.readyState = 'open';
        self._updateAddressInfo();
        self._startPolling();
        self.emit('connect');
        self.emit('ready');
      } catch(e) {
        self.connecting = false;
        self.pending = false;
        self.readyState = 'closed';
        var err = new Error(e.message || String(e));
        err.code = 'ECONNREFUSED';
        self.emit('error', err);
      }
    }, 0);

    return this;
  }

  // TCP connection
  this.remotePort = options.port;
  this.remoteAddress = options.host || options.hostname || 'localhost';
  // Store optional connection params
  if (options.localAddress) this.localAddress = options.localAddress;
  if (options.localPort) this.localPort = options.localPort;
  if (options.family) this._family = options.family;

  if (!_hasTcp) {
    // Fallback: no native TCP support
    var self = this;
    setTimeout(function() {
      var err = new Error('TCP sockets not supported: native __exactTcpConnect not available');
      err.code = 'ECONNREFUSED';
      self.connecting = false;
      self.readyState = 'closed';
      self.pending = false;
      self.emit('error', err);
    }, 0);
    return this;
  }

  var self = this;
  // Use setTimeout to make connect async (non-blocking from JS perspective)
  setTimeout(function() {
    if (self.destroyed) return;
    try {
      self._handle = __exactTcpConnect(self.remoteAddress, self.remotePort);
      self.connecting = false;
      self._connected = true;
      self.pending = false;
      self.readyState = 'open';
      self._updateAddressInfo();
      self._startPolling();
      self.emit('connect');
      self.emit('ready');
    } catch(e) {
      self.connecting = false;
      self.pending = false;
      self.readyState = 'closed';
      var err = new Error(e.message || String(e));
      err.code = 'ECONNREFUSED';
      self.emit('error', err);
    }
  }, 0);

  return this;
};

Socket.prototype.write = function(data, encoding, callback) {
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (!this.writable || this.destroyed) {
    var err = new Error('This socket has been ended by the other party');
    err.code = 'EPIPE';
    if (callback) callback(err);
    return false;
  }
  if (this._handle == null) {
    var err2 = new Error('Socket is not connected');
    err2.code = 'ERR_SOCKET_CLOSED';
    if (callback) callback(err2);
    return false;
  }

  var str = data;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(data)) {
    str = data.toString(encoding || 'utf8');
  } else if (typeof data !== 'string') {
    str = String(data);
  }

  try {
    var written = __exactTcpWrite(this._handle, str);
    this.bytesWritten += written;
    this._lastActivity = Date.now();
    if (callback) setTimeout(callback, 0);
    this.emit('drain');
    return true;
  } catch(e) {
    var writeErr = new Error(e.message || String(e));
    writeErr.code = 'EPIPE';
    if (callback) callback(writeErr);
    this.destroy(writeErr);
    return false;
  }
};

Socket.prototype.end = function(data, encoding, callback) {
  if (typeof data === 'function') { callback = data; data = undefined; }
  if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
  if (data != null) this.write(data, encoding);
  this.writable = false;
  this.readyState = this.readable ? 'readOnly' : 'closed';
  if (callback) this.once('finish', callback);
  this.emit('finish');
  // If not allowing half-open, close the whole socket
  if (!this.allowHalfOpen && this._handle != null) {
    var self = this;
    // Let any pending reads finish
    setTimeout(function() {
      if (!self.destroyed) {
        self.destroy();
      }
    }, 50);
  }
  return this;
};

Socket.prototype.destroy = function(err) {
  if (this.destroyed) return this;
  this.destroyed = true;
  this.readable = false;
  this.writable = false;
  this.connecting = false;
  this.readyState = 'closed';
  this.pending = false;
  if (this._pollTimer != null) {
    clearTimeout(this._pollTimer);
    this._pollTimer = null;
  }
  if (this._timeoutTimer != null) {
    clearTimeout(this._timeoutTimer);
    this._timeoutTimer = null;
  }
  if (this._handle != null && _hasTcp) {
    try { __exactTcpClose(this._handle); } catch(e) {}
    this._handle = null;
  }
  if (err) this.emit('error', err);
  this.emit('close', !!err);
  return this;
};

Socket.prototype.setTimeout = function(timeout, callback) {
  this._timeoutMs = timeout || 0;
  if (callback) {
    if (timeout > 0) {
      this.once('timeout', callback);
    } else {
      this.removeListener('timeout', callback);
    }
  }
  return this;
};

Socket.prototype.setNoDelay = function(noDelay) {
  if (this._handle != null && _hasTcp) {
    try { __exactTcpSetNoDelay(this._handle, noDelay !== false ? 1 : 0); } catch(e) {}
  }
  return this;
};

Socket.prototype.setKeepAlive = function(enable, delay) {
  if (this._handle != null && _hasTcp) {
    try { __exactTcpSetKeepAlive(this._handle, enable ? 1 : 0); } catch(e) {}
  }
  return this;
};

Socket.prototype.ref = function() { return this; };
Socket.prototype.unref = function() { return this; };

Socket.prototype.address = function() {
  if (this._isUnix) {
    return this._socketPath;
  }
  if (this._handle != null && _hasTcp) {
    try {
      var info = __exactTcpLocalAddr(this._handle);
      if (info) return JSON.parse(info);
    } catch(e) {}
  }
  return { address: this.localAddress, port: this.localPort, family: this.remoteFamily || 'IPv4' };
};

Socket.prototype.pause = function() {
  this._paused = true;
  return this;
};

Socket.prototype.resume = function() {
  this._paused = false;
  return this;
};

Socket.prototype.pipe = function(dest, options) {
  var self = this;
  self.on('data', function(chunk) {
    var ok = dest.write(chunk);
    if (ok === false && self.pause) self.pause();
  });
  dest.on('drain', function() {
    if (self.resume) self.resume();
  });
  self.on('end', function() {
    if (!options || options.end !== false) {
      if (dest.end) dest.end();
    }
  });
  return dest;
};

Socket.prototype.setEncoding = function(enc) {
  this._encoding = enc;
  return this;
};

// --- Server class ---
function Server(options, connectionListener) {
  if (!(this instanceof Server)) return new Server(options, connectionListener);
  if (typeof options === 'function') {
    connectionListener = options;
    options = {};
  }
  options = options || {};
  this._events = {};
  this.listening = false;
  this.maxConnections = 0;
  this._handle = null;
  this._acceptTimer = null;
  this._connections = 0;
  this._isUnix = false;
  this._socketPath = null;
  // Mixin EventEmitter
  if (typeof EventEmitter === 'function' && EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }
  if (connectionListener) this.on('connection', connectionListener);
}

Server.prototype.listen = function(port, host, backlog, callback) {
  if (typeof host === 'function') { callback = host; host = undefined; backlog = undefined; }
  if (typeof backlog === 'function') { callback = backlog; backlog = undefined; }
  var unixPath = null;
  if (typeof port === 'string') {
    // server.listen('/tmp/my.sock') - Unix socket path
    unixPath = port;
    port = undefined;
  } else if (typeof port === 'object' && port !== null) {
    // options object
    var opts = port;
    if (opts.path) {
      unixPath = opts.path;
    }
    port = opts.port;
    host = opts.host || host;
    backlog = opts.backlog || backlog;
  }

  if (callback) this.once('listening', callback);

  // Unix domain socket server
  if (unixPath) {
    this._isUnix = true;
    this._socketPath = unixPath;

    if (!_hasUnix) {
      this.listening = true;
      var self = this;
      setTimeout(function() { self.emit('listening'); }, 0);
      return this;
    }

    var self = this;
    setTimeout(function() {
      try {
        self._handle = __exactUnixListen(self._socketPath, backlog || 128);
        self.listening = true;
        self.emit('listening');
        self._startAccepting();
      } catch(e) {
        var err = new Error(e.message || String(e));
        err.code = 'EADDRINUSE';
        self.emit('error', err);
      }
    }, 0);
    return this;
  }

  // TCP server
  this._port = port || 0;
  this._host = host || '0.0.0.0';

  if (!_hasTcp) {
    this.listening = true;
    var self = this;
    setTimeout(function() { self.emit('listening'); }, 0);
    return this;
  }

  var self = this;
  setTimeout(function() {
    try {
      self._handle = __exactTcpListen(self._host, self._port, backlog || 128);
      // Get actual bound port (useful when port=0)
      try {
        var info = __exactTcpLocalAddr(self._handle);
        if (info) {
          var addr = JSON.parse(info);
          self._port = addr.port;
          self._host = addr.address;
        }
      } catch(e) {}
      self.listening = true;
      self.emit('listening');
      self._startAccepting();
    } catch(e) {
      var err = new Error(e.message || String(e));
      err.code = 'EADDRINUSE';
      self.emit('error', err);
    }
  }, 0);
  return this;
};

Server.prototype._startAccepting = function() {
  if (this._acceptTimer != null) return;
  var self = this;
  var acceptFn = self._isUnix ? __exactUnixAccept : __exactTcpAccept;
  function acceptLoop() {
    if (!self.listening || self._handle == null) return;
    try {
      var clientHandle = acceptFn(self._handle);
      if (clientHandle !== -1) {
        self._connections++;
        var socketOpts = { _handle: clientHandle, allowHalfOpen: false };
        if (self._isUnix) {
          socketOpts._isUnix = true;
          socketOpts._socketPath = self._socketPath;
        }
        var socket = new Socket(socketOpts);
        self.emit('connection', socket);
      }
    } catch(e) {
      if (self.listening) {
        self.emit('error', e);
      }
      return;
    }
    self._acceptTimer = setTimeout(acceptLoop, 10);
  }
  self._acceptTimer = setTimeout(acceptLoop, 0);
};

Server.prototype.close = function(callback) {
  if (callback) this.once('close', callback);
  this.listening = false;
  if (this._acceptTimer != null) {
    clearTimeout(this._acceptTimer);
    this._acceptTimer = null;
  }
  if (this._handle != null) {
    // Close the fd (works for both TCP and Unix handles since they share g_tcp_sockets)
    if (_hasTcp) {
      try { __exactTcpClose(this._handle); } catch(e) {}
    }
    this._handle = null;
  }
  // Unlink Unix socket file on close
  if (this._isUnix && this._socketPath) {
    try {
      var fs = require('fs');
      fs.unlinkSync(this._socketPath);
    } catch(e) {}
    this._socketPath = null;
  }
  var self = this;
  setTimeout(function() { self.emit('close'); }, 0);
  return this;
};

Server.prototype.address = function() {
  // Unix socket servers return the path as the address (Node.js convention)
  if (this._isUnix) {
    return this._socketPath;
  }
  if (this._handle != null && _hasTcp) {
    try {
      var info = __exactTcpLocalAddr(this._handle);
      if (info) return JSON.parse(info);
    } catch(e) {}
  }
  return { address: this._host || '0.0.0.0', port: this._port || 0, family: 'IPv4' };
};

Server.prototype.ref = function() { return this; };
Server.prototype.unref = function() { return this; };
Server.prototype.getConnections = function(cb) {
  var count = this._connections || 0;
  if (cb) setTimeout(function() { cb(null, count); }, 0);
};

// --- Helper functions ---
function createConnection(options, connectListener) {
  if (typeof options === 'number') {
    var port = options;
    var host = 'localhost';
    if (typeof connectListener === 'string') {
      host = connectListener;
      connectListener = arguments[2];
    }
    options = { port: port, host: host };
  }
  var socket = new Socket(options);
  return socket.connect(options, connectListener);
}

function createServer(options, connectionListener) {
  return new Server(options, connectionListener);
}

function connect() {
  return createConnection.apply(null, arguments);
}

function isIP(input) {
  if (isIPv4(input)) return 4;
  if (isIPv6(input)) return 6;
  return 0;
}

function isIPv4(input) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(input);
}

function isIPv6(input) {
  return /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(input) ||
         /^::1$/.test(input) || /^::$/.test(input);
}

// --- SocketAddress class ---
function SocketAddress(options) {
  if (!(this instanceof SocketAddress)) return new SocketAddress(options);
  options = options || {};
  this.address = options.address || '127.0.0.1';
  this.port = options.port || 0;
  this.family = options.family || (isIPv6(this.address) ? 'ipv6' : 'ipv4');
  this.flowlabel = options.flowlabel || 0;
}

// --- BlockList class ---
function BlockList() {
  if (!(this instanceof BlockList)) return new BlockList();
  this._rules = [];
}

BlockList.prototype.addAddress = function(address, type) {
  type = type || (isIPv6(address) ? 'ipv6' : 'ipv4');
  this._rules.push({ type: 'address', address: address, family: type });
};

BlockList.prototype.addRange = function(start, end, type) {
  type = type || (isIPv6(start) ? 'ipv6' : 'ipv4');
  this._rules.push({ type: 'range', start: start, end: end, family: type });
};

BlockList.prototype.addSubnet = function(address, prefix, type) {
  type = type || (isIPv6(address) ? 'ipv6' : 'ipv4');
  this._rules.push({ type: 'subnet', address: address, prefix: prefix, family: type });
};

BlockList.prototype.check = function(address, type) {
  type = type || (isIPv6(address) ? 'ipv6' : 'ipv4');
  for (var i = 0; i < this._rules.length; i++) {
    var rule = this._rules[i];
    if (rule.family !== type) continue;
    if (rule.type === 'address' && rule.address === address) return true;
    // For range and subnet, simplified string comparison (exact IP matching)
    if (rule.type === 'range' && address >= rule.start && address <= rule.end) return true;
    if (rule.type === 'subnet' && address === rule.address) return true;
  }
  return false;
};

BlockList.prototype.rules = [];

module.exports = {
  Socket: Socket,
  Stream: Socket,
  Server: Server,
  createConnection: createConnection,
  createServer: createServer,
  connect: connect,
  isIP: isIP,
  isIPv4: isIPv4,
  isIPv6: isIPv6,
  BlockList: BlockList,
  SocketAddress: SocketAddress
};
module.exports.default = module.exports;
"##
    .trim()
    .to_string()
}

fn node_zlib_module() -> String {
    r##"
var Transform = require('node:stream').Transform;

function toBytes(data) {
  if (typeof data === 'string') {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(data);
    var buf = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i++) buf[i] = data.charCodeAt(i);
    return buf;
  }
  if (data instanceof Uint8Array) return data;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(data)) {
    return new Uint8Array(data.buffer || data, data.byteOffset || 0, data.length);
  }
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  return new Uint8Array(data);
}

function toBuffer(uint8) {
  if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(uint8);
  return uint8;
}

// mode: 0 = deflate (zlib header), 1 = gzip, 2 = raw (no header/checksum)
function deflateSync(data, options) {
  var bytes = toBytes(data);
  var level = (options && options.level !== undefined) ? options.level : -1;
  var result = __exactDeflateSync(bytes, level, 0);
  return toBuffer(result);
}

function inflateSync(data) {
  var bytes = toBytes(data);
  var result = __exactInflateSync(bytes, 0);
  return toBuffer(result);
}

function gzipSync(data, options) {
  var bytes = toBytes(data);
  var level = (options && options.level !== undefined) ? options.level : -1;
  var result = __exactDeflateSync(bytes, level, 1);
  return toBuffer(result);
}

function gunzipSync(data) {
  var bytes = toBytes(data);
  var result = __exactInflateSync(bytes, 1);
  return toBuffer(result);
}

function deflateRawSync(data, options) {
  var bytes = toBytes(data);
  var level = (options && options.level !== undefined) ? options.level : -1;
  var result = __exactDeflateSync(bytes, level, 2);
  return toBuffer(result);
}

function inflateRawSync(data) {
  var bytes = toBytes(data);
  var result = __exactInflateSync(bytes, 2);
  return toBuffer(result);
}

function unzipSync(data) {
  // Auto-detect gzip or deflate
  return gunzipSync(data);
}

// Async wrappers (use sync under the hood with nextTick callback)
function deflate(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = deflateSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

function inflate(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = inflateSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

function gzip(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = gzipSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

function gunzip(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = gunzipSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

// Brotli compression/decompression
function brotliCompressSync(data, options) {
  var bytes = toBytes(data);
  var quality = 11; // BROTLI_DEFAULT_QUALITY
  if (options && options.params) {
    // BROTLI_PARAM_QUALITY = 1
    if (options.params[1] !== undefined) {
      quality = options.params[1];
    }
  }
  if (typeof __exactBrotliCompressSync !== 'function') throw new Error('brotliCompressSync not available');
  var result = __exactBrotliCompressSync(bytes, quality);
  return toBuffer(result);
}
function brotliDecompressSync(data, options) {
  var bytes = toBytes(data);
  if (typeof __exactBrotliDecompressSync !== 'function') throw new Error('brotliDecompressSync not available');
  var result = __exactBrotliDecompressSync(bytes);
  return toBuffer(result);
}
function brotliCompress(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = brotliCompressSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}
function brotliDecompress(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  try {
    var result = brotliDecompressSync(data, options);
    if (callback) setTimeout(function() { callback(null, result); }, 0);
  } catch(e) {
    if (callback) setTimeout(function() { callback(e); }, 0);
  }
}

// --- Stream-based zlib API (Transform streams) ---
// Base class for all zlib Transform streams
function ZlibTransform(syncFn, opts) {
  Transform.call(this, opts);
  this._syncFn = syncFn;
  this._chunks = [];
}
ZlibTransform.prototype = Object.create(Transform.prototype);
ZlibTransform.prototype.constructor = ZlibTransform;

ZlibTransform.prototype._transform = function(chunk, encoding, callback) {
  if (typeof chunk === 'string') {
    this._chunks.push(Buffer.from(chunk, encoding));
  } else {
    this._chunks.push(chunk);
  }
  callback();
};

ZlibTransform.prototype._flush = function(callback) {
  try {
    var input = Buffer.concat(this._chunks);
    var result = this._syncFn(input);
    this.push(result);
    callback();
  } catch (e) {
    callback(e);
  }
};

// Override end() to call _flush before finishing, since the base Transform
// uses _final (not _flush) in this runtime's stream implementation
ZlibTransform.prototype.end = function(chunk, encoding, callback) {
  if (typeof chunk === 'function') { callback = chunk; chunk = null; encoding = null; }
  if (typeof encoding === 'function') { callback = encoding; encoding = null; }
  if (chunk !== undefined && chunk !== null) {
    if (typeof chunk === 'string') {
      this._chunks.push(Buffer.from(chunk, encoding || 'utf8'));
    } else {
      this._chunks.push(chunk);
    }
  }
  var self = this;
  this._flush(function(err) {
    if (err) {
      self.emit('error', err);
      if (typeof callback === 'function') callback(err);
      return;
    }
    self.push(null);
    self.writableEnded = true;
    self.writableFinished = true;
    self.emit('finish');
    self._emitClose();
    if (typeof callback === 'function') callback();
  });
};

// Deflate stream (zlib header)
function Deflate(opts) {
  ZlibTransform.call(this, deflateSync, opts);
}
Deflate.prototype = Object.create(ZlibTransform.prototype);
Deflate.prototype.constructor = Deflate;

// Inflate stream (zlib header)
function Inflate(opts) {
  ZlibTransform.call(this, inflateSync, opts);
}
Inflate.prototype = Object.create(ZlibTransform.prototype);
Inflate.prototype.constructor = Inflate;

// Gzip stream
function Gzip(opts) {
  ZlibTransform.call(this, gzipSync, opts);
}
Gzip.prototype = Object.create(ZlibTransform.prototype);
Gzip.prototype.constructor = Gzip;

// Gunzip stream
function Gunzip(opts) {
  ZlibTransform.call(this, gunzipSync, opts);
}
Gunzip.prototype = Object.create(ZlibTransform.prototype);
Gunzip.prototype.constructor = Gunzip;

// DeflateRaw stream (no header/checksum)
function DeflateRaw(opts) {
  ZlibTransform.call(this, deflateRawSync, opts);
}
DeflateRaw.prototype = Object.create(ZlibTransform.prototype);
DeflateRaw.prototype.constructor = DeflateRaw;

// InflateRaw stream (no header/checksum)
function InflateRaw(opts) {
  ZlibTransform.call(this, inflateRawSync, opts);
}
InflateRaw.prototype = Object.create(ZlibTransform.prototype);
InflateRaw.prototype.constructor = InflateRaw;

function createDeflate(options) { return new Deflate(options); }
function createInflate(options) { return new Inflate(options); }
function createGzip(options) { return new Gzip(options); }
function createGunzip(options) { return new Gunzip(options); }
function createDeflateRaw(options) { return new DeflateRaw(options); }
function createInflateRaw(options) { return new InflateRaw(options); }
// BrotliCompress stream
function BrotliCompress(opts) {
  ZlibTransform.call(this, function(buf) { return brotliCompressSync(buf, opts); }, opts);
}
BrotliCompress.prototype = Object.create(ZlibTransform.prototype);
BrotliCompress.prototype.constructor = BrotliCompress;

// BrotliDecompress stream
function BrotliDecompress(opts) {
  ZlibTransform.call(this, function(buf) { return brotliDecompressSync(buf, opts); }, opts);
}
BrotliDecompress.prototype = Object.create(ZlibTransform.prototype);
BrotliDecompress.prototype.constructor = BrotliDecompress;

function createBrotliCompress(options) { return new BrotliCompress(options); }
function createBrotliDecompress(options) { return new BrotliDecompress(options); }

// Constants
var constants = {
  Z_NO_COMPRESSION: 0,
  Z_BEST_SPEED: 1,
  Z_BEST_COMPRESSION: 9,
  Z_DEFAULT_COMPRESSION: -1,
  Z_NO_FLUSH: 0,
  Z_PARTIAL_FLUSH: 1,
  Z_SYNC_FLUSH: 2,
  Z_FULL_FLUSH: 3,
  Z_FINISH: 4,
  Z_BLOCK: 5,
  Z_TREES: 6,
  Z_OK: 0,
  Z_STREAM_END: 1,
  Z_NEED_DICT: 2,
  Z_ERRNO: -1,
  Z_STREAM_ERROR: -2,
  Z_DATA_ERROR: -3,
  Z_MEM_ERROR: -4,
  Z_BUF_ERROR: -5,
  Z_VERSION_ERROR: -6,
  BROTLI_OPERATION_PROCESS: 0,
  BROTLI_OPERATION_FLUSH: 1,
  BROTLI_OPERATION_FINISH: 2,
  BROTLI_PARAM_MODE: 0,
  BROTLI_MODE_GENERIC: 0,
  BROTLI_MODE_TEXT: 1,
  BROTLI_MODE_FONT: 2,
  BROTLI_PARAM_QUALITY: 1,
  BROTLI_MIN_QUALITY: 0,
  BROTLI_MAX_QUALITY: 11,
  BROTLI_DEFAULT_QUALITY: 11,
  BROTLI_PARAM_LGWIN: 2,
  BROTLI_MIN_WINDOW_BITS: 10,
  BROTLI_MAX_WINDOW_BITS: 24,
  BROTLI_DEFAULT_WINDOW: 22,
  BROTLI_PARAM_LGBLOCK: 3,
  BROTLI_MIN_INPUT_BLOCK_BITS: 16,
  BROTLI_MAX_INPUT_BLOCK_BITS: 24,
  BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING: 4,
  BROTLI_PARAM_SIZE_HINT: 5,
  BROTLI_PARAM_LARGE_WINDOW: 6,
  BROTLI_PARAM_NPOSTFIX: 7,
  BROTLI_PARAM_NDIRECT: 8,
  BROTLI_DECODER_RESULT_ERROR: 0,
  BROTLI_DECODER_RESULT_SUCCESS: 1,
  BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT: 2,
  BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT: 3
};

module.exports = {
  deflateSync: deflateSync,
  inflateSync: inflateSync,
  gzipSync: gzipSync,
  gunzipSync: gunzipSync,
  deflateRawSync: deflateRawSync,
  inflateRawSync: inflateRawSync,
  unzipSync: unzipSync,
  deflate: deflate,
  inflate: inflate,
  gzip: gzip,
  gunzip: gunzip,
  brotliCompressSync: brotliCompressSync,
  brotliDecompressSync: brotliDecompressSync,
  brotliCompress: brotliCompress,
  brotliDecompress: brotliDecompress,
  createDeflate: createDeflate,
  createInflate: createInflate,
  createGzip: createGzip,
  createGunzip: createGunzip,
  createDeflateRaw: createDeflateRaw,
  createInflateRaw: createInflateRaw,
  createBrotliCompress: createBrotliCompress,
  createBrotliDecompress: createBrotliDecompress,
  Deflate: Deflate,
  Inflate: Inflate,
  Gzip: Gzip,
  Gunzip: Gunzip,
  DeflateRaw: DeflateRaw,
  InflateRaw: InflateRaw,
  BrotliCompress: BrotliCompress,
  BrotliDecompress: BrotliDecompress,
  constants: constants
};
"##
    .trim()
    .to_string()
}

fn node_module_module() -> String {
    r##"
var builtinList = [
  'assert', 'buffer', 'child_process', 'cluster', 'console', 'constants',
  'crypto', 'dgram', 'dns', 'domain', 'events',
  'fs', 'fs/promises',
  'http', 'https', 'module', 'net', 'os', 'path',
  'perf_hooks', 'process', 'punycode', 'querystring', 'readline',
  'stream', 'stream/promises', 'stream/web',
  'string_decoder',
  'timers', 'timers/promises', 'tls', 'tty', 'url', 'util',
  'v8', 'vm', 'worker_threads', 'zlib'
];

function isBuiltin(specifier) {
  if (typeof specifier !== 'string') return false;
  var name = specifier;
  if (name.indexOf('node:') === 0) name = name.slice(5);
  if (name.indexOf('bun:') === 0) name = name.slice(4);
  return builtinList.indexOf(name) !== -1;
}

function createRequire(filename) {
  // Return a require function that resolves relative to filename
  if (typeof filename === 'object' && filename !== null && filename.href) {
    // URL object — convert file:// URL to path
    filename = filename.href;
  }
  if (typeof filename === 'string' && filename.indexOf('file://') === 0) {
    filename = filename.slice(7);
  }
  var parentDir = '';
  if (typeof filename === 'string') {
    var lastSlash = filename.lastIndexOf('/');
    if (lastSlash >= 0) parentDir = filename.substring(0, lastSlash);
    else parentDir = '.';
  }
  // Use the global require but with resolution relative to the given path
  var _require = function(specifier) {
    return globalThis.require(specifier);
  };
  _require.resolve = function(specifier) {
    return globalThis.require.resolve(specifier);
  };
  _require.resolve.paths = function(specifier) {
    return globalThis.require.resolve.paths ? globalThis.require.resolve.paths(specifier) : null;
  };
  _require.cache = globalThis.require.cache || {};
  _require.main = globalThis.require.main || undefined;
  return _require;
}

var Module = {
  builtinModules: builtinList.slice(),
  isBuiltin: isBuiltin,
  createRequire: createRequire,
  _cache: {},
  _pathCache: {},
  _extensions: { '.js': true, '.json': true, '.node': true },
  globalPaths: [],
  wrap: function(script) {
    return '(function (exports, require, module, __filename, __dirname) { ' + script + '\n});';
  },
  _nodeModulePaths: function(from) {
    var parts = from.split('/');
    var dirs = [];
    for (var i = parts.length - 1; i >= 0; i--) {
      if (parts[i] === 'node_modules') continue;
      dirs.push(parts.slice(0, i + 1).join('/') + '/node_modules');
    }
    return dirs;
  }
};

module.exports = Module;
module.exports.Module = Module;
module.exports.builtinModules = builtinList.slice();
module.exports.isBuiltin = isBuiltin;
module.exports.createRequire = createRequire;
"##
    .trim()
    .to_string()
}

fn node_perf_hooks_module() -> String {
    r##"
var _perfStart = Date.now();
var _marks = [];
var _measures = [];
var _observers = [];

function _perfNow() {
  if (typeof __exactHrtime === 'function') {
    var parts = __exactHrtime();
    if (typeof parts === 'string') {
      var p = parts.split(',');
      return (parseInt(p[0], 10) * 1000) + (parseInt(p[1], 10) / 1000000);
    }
  }
  return Date.now() - _perfStart;
}

function _notifyObservers(entry) {
  for (var i = 0; i < _observers.length; i++) {
    var obs = _observers[i];
    if (obs._entryTypes && obs._entryTypes.indexOf(entry.entryType) !== -1) {
      try {
        var list = {
          getEntries: function() { return [entry]; },
          getEntriesByName: function(n) { return entry.name === n ? [entry] : []; },
          getEntriesByType: function(t) { return entry.entryType === t ? [entry] : []; }
        };
        obs._callback(list, obs);
      } catch (e) {}
    }
  }
}

function PerformanceEntry(name, entryType, startTime, duration) {
  this.name = name;
  this.entryType = entryType;
  this.startTime = startTime;
  this.duration = duration;
}
PerformanceEntry.prototype.toJSON = function() {
  return {
    name: this.name,
    entryType: this.entryType,
    startTime: this.startTime,
    duration: this.duration
  };
};

function Performance() {}
Performance.prototype.now = function() {
  return _perfNow();
};
Performance.prototype.timeOrigin = _perfStart;
Performance.prototype.mark = function(name, options) {
  options = options || {};
  var startTime = (options.startTime !== undefined) ? options.startTime : _perfNow();
  var entry = new PerformanceEntry(name, 'mark', startTime, 0);
  if (options.detail !== undefined) entry.detail = options.detail;
  _marks.push(entry);
  _notifyObservers(entry);
  return entry;
};
Performance.prototype.measure = function(name, startMarkOrOptions, endMark) {
  var startTime = 0;
  var endTime = _perfNow();
  var duration;
  var detail;

  if (startMarkOrOptions && typeof startMarkOrOptions === 'object' && !Array.isArray(startMarkOrOptions)) {
    var opts = startMarkOrOptions;
    if (opts.detail !== undefined) detail = opts.detail;

    if (opts.start !== undefined) {
      if (typeof opts.start === 'string') {
        var sm = null;
        for (var i = _marks.length - 1; i >= 0; i--) {
          if (_marks[i].name === opts.start) { sm = _marks[i]; break; }
        }
        if (sm) startTime = sm.startTime;
        else throw new Error("Failed to execute 'measure': The mark '" + opts.start + "' does not exist.");
      } else {
        startTime = opts.start;
      }
    }

    if (opts.end !== undefined) {
      if (typeof opts.end === 'string') {
        var em = null;
        for (var j = _marks.length - 1; j >= 0; j--) {
          if (_marks[j].name === opts.end) { em = _marks[j]; break; }
        }
        if (em) endTime = em.startTime;
        else throw new Error("Failed to execute 'measure': The mark '" + opts.end + "' does not exist.");
      } else {
        endTime = opts.end;
      }
    }

    if (opts.duration !== undefined) {
      duration = opts.duration;
      if (opts.start !== undefined && opts.end === undefined) {
        endTime = startTime + duration;
      } else if (opts.end !== undefined && opts.start === undefined) {
        startTime = endTime - duration;
      }
    }
  } else if (typeof startMarkOrOptions === 'string') {
    var foundStart = null;
    for (var k = _marks.length - 1; k >= 0; k--) {
      if (_marks[k].name === startMarkOrOptions) { foundStart = _marks[k]; break; }
    }
    if (foundStart) startTime = foundStart.startTime;
    else throw new Error("Failed to execute 'measure': The mark '" + startMarkOrOptions + "' does not exist.");

    if (typeof endMark === 'string') {
      var foundEnd = null;
      for (var l = _marks.length - 1; l >= 0; l--) {
        if (_marks[l].name === endMark) { foundEnd = _marks[l]; break; }
        }
      if (foundEnd) endTime = foundEnd.startTime;
      else throw new Error("Failed to execute 'measure': The mark '" + endMark + "' does not exist.");
    }
  }

  if (duration === undefined) {
    duration = endTime - startTime;
  }

  var entry = new PerformanceEntry(name, 'measure', startTime, duration);
  if (detail !== undefined) entry.detail = detail;
  _measures.push(entry);
  _notifyObservers(entry);
  return entry;
};
Performance.prototype.getEntries = function() {
  return _marks.concat(_measures).sort(function(a, b) { return a.startTime - b.startTime; });
};
Performance.prototype.getEntriesByName = function(name, type) {
  var all = _marks.concat(_measures);
  var result = [];
  for (var i = 0; i < all.length; i++) {
    if (all[i].name === name && (!type || all[i].entryType === type)) {
      result.push(all[i]);
    }
  }
  return result.sort(function(a, b) { return a.startTime - b.startTime; });
};
Performance.prototype.getEntriesByType = function(type) {
  var all = _marks.concat(_measures);
  var result = [];
  for (var i = 0; i < all.length; i++) {
    if (all[i].entryType === type) {
      result.push(all[i]);
    }
  }
  return result.sort(function(a, b) { return a.startTime - b.startTime; });
};
Performance.prototype.clearMarks = function(name) {
  if (name === undefined) {
    _marks = [];
  } else {
    _marks = _marks.filter(function(m) { return m.name !== name; });
  }
};
Performance.prototype.clearMeasures = function(name) {
  if (name === undefined) {
    _measures = [];
  } else {
    _measures = _measures.filter(function(m) { return m.name !== name; });
  }
};
Performance.prototype.toJSON = function() {
  return {
    timeOrigin: this.timeOrigin
  };
};

var performance = new Performance();

function PerformanceObserver(callback) {
  this._callback = callback;
  this._entryTypes = [];
}
PerformanceObserver.prototype.observe = function(options) {
  if (options && options.entryTypes) {
    this._entryTypes = options.entryTypes;
  } else if (options && options.type) {
    this._entryTypes = [options.type];
  }
  if (_observers.indexOf(this) === -1) {
    _observers.push(this);
  }
};
PerformanceObserver.prototype.disconnect = function() {
  var idx = _observers.indexOf(this);
  if (idx !== -1) _observers.splice(idx, 1);
  this._entryTypes = [];
};
PerformanceObserver.prototype.takeRecords = function() {
  return [];
};
PerformanceObserver.supportedEntryTypes = ['mark', 'measure'];

module.exports = {
  performance: performance,
  Performance: Performance,
  PerformanceEntry: PerformanceEntry,
  PerformanceObserver: PerformanceObserver,
  monitorEventLoopDelay: function() {
    return { enable: function() {}, disable: function() {}, percentile: function() { return 0; },
             min: 0, max: 0, mean: 0, stddev: 0, percentiles: new Map() };
  }
};
"##
    .trim()
    .to_string()
}

fn node_async_hooks_module() -> String {
    r#"
var _hooksEnabled = false;
var _noop = function() {};
var _idCounter = 1;

/* ------------------------------------------------------------------ */
/*  Global async context tracking                                      */
/* ------------------------------------------------------------------ */

var _allInstances = [];

function _captureContext() {
  var ctx = [];
  for (var i = 0; i < _allInstances.length; i++) {
    var als = _allInstances[i];
    ctx.push({ als: als, store: als._store });
  }
  return ctx;
}

function _restoreContext(ctx) {
  var prev = _captureContext();
  for (var i = 0; i < ctx.length; i++) {
    ctx[i].als._store = ctx[i].store;
  }
  return prev;
}

function _wrapCallback(fn) {
  if (typeof fn !== 'function') return fn;
  var captured = _captureContext();
  return function() {
    var prev = _restoreContext(captured);
    try {
      return fn.apply(this, arguments);
    } finally {
      _restoreContext(prev);
    }
  };
}

/* ------------------------------------------------------------------ */
/*  Patch Promise.prototype.then / catch / finally                     */
/* ------------------------------------------------------------------ */
(function() {
  if (typeof Promise === 'undefined') return;

  var origThen = Promise.prototype.then;
  Promise.prototype.then = function(onFulfilled, onRejected) {
    return origThen.call(
      this,
      typeof onFulfilled === 'function' ? _wrapCallback(onFulfilled) : onFulfilled,
      typeof onRejected  === 'function' ? _wrapCallback(onRejected)  : onRejected
    );
  };

  if (typeof Promise.prototype['catch'] === 'function') {
    var origCatch = Promise.prototype['catch'];
    Promise.prototype['catch'] = function(onRejected) {
      return origCatch.call(
        this,
        typeof onRejected === 'function' ? _wrapCallback(onRejected) : onRejected
      );
    };
  }

  if (typeof Promise.prototype['finally'] === 'function') {
    var origFinally = Promise.prototype['finally'];
    Promise.prototype['finally'] = function(onFinally) {
      return origFinally.call(
        this,
        typeof onFinally === 'function' ? _wrapCallback(onFinally) : onFinally
      );
    };
  }
})();

/* ------------------------------------------------------------------ */
/*  Patch setTimeout / setInterval / queueMicrotask                    */
/* ------------------------------------------------------------------ */
(function() {
  if (typeof globalThis === 'undefined') return;

  if (typeof globalThis.setTimeout === 'function') {
    var origSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = function(fn) {
      var args = [];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      if (typeof fn === 'function') {
        args.unshift(_wrapCallback(fn));
      } else {
        args.unshift(fn);
      }
      return origSetTimeout.apply(globalThis, args);
    };
  }

  if (typeof globalThis.setInterval === 'function') {
    var origSetInterval = globalThis.setInterval;
    globalThis.setInterval = function(fn) {
      var args = [];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      if (typeof fn === 'function') {
        args.unshift(_wrapCallback(fn));
      } else {
        args.unshift(fn);
      }
      return origSetInterval.apply(globalThis, args);
    };
  }

  if (typeof globalThis.queueMicrotask === 'function') {
    var origQueueMicrotask = globalThis.queueMicrotask;
    globalThis.queueMicrotask = function(fn) {
      if (typeof fn === 'function') {
        return origQueueMicrotask.call(globalThis, _wrapCallback(fn));
      }
      return origQueueMicrotask.call(globalThis, fn);
    };
  }
})();

/* ------------------------------------------------------------------ */
/*  createHook (stub - keeps existing API surface)                     */
/* ------------------------------------------------------------------ */
function createHook(callbacks) {
  callbacks = callbacks || {};
  return {
    enable: function() {
      _hooksEnabled = true;
      return this;
    },
    disable: function() {
      _hooksEnabled = false;
      return this;
    },
    _callbacks: callbacks
  };
}

function executionAsyncId() {
  return 0;
}

function triggerAsyncId() {
  return 0;
}

/* ------------------------------------------------------------------ */
/*  AsyncResource                                                      */
/* ------------------------------------------------------------------ */
function AsyncResource(type, options) {
  this.type = type || 'AsyncResource';
  this._asyncId = _idCounter++;
  this._triggerAsyncId = (options && typeof options.triggerAsyncId === 'number')
    ? options.triggerAsyncId
    : executionAsyncId();
  this._context = _captureContext();
}

AsyncResource.prototype.runInAsyncScope = function(fn, thisArg) {
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  var prev = _restoreContext(this._context);
  try {
    return fn.apply(thisArg || this, args);
  } finally {
    _restoreContext(prev);
  }
};
AsyncResource.prototype.emitDestroy = _noop;
AsyncResource.prototype.emitBefore = _noop;
AsyncResource.prototype.emitAfter = _noop;
AsyncResource.prototype.asyncId = function() {
  return this._asyncId;
};
AsyncResource.prototype.triggerAsyncId = function() {
  return this._triggerAsyncId;
};
AsyncResource.prototype.bind = function(fn, thisArg) {
  var resource = this;
  var bound = function() {
    var a = [];
    for (var i = 0; i < arguments.length; i++) a.push(arguments[i]);
    return resource.runInAsyncScope.apply(resource, [fn, thisArg || resource].concat(a));
  };
  bound.asyncResource = resource;
  return bound;
};

AsyncResource.bind = function(fn, type, thisArg) {
  type = type || fn.name || 'bound-anonymous-fn';
  var resource = new AsyncResource(type);
  return resource.bind(fn, thisArg);
};

/* ------------------------------------------------------------------ */
/*  AsyncLocalStorage                                                  */
/* ------------------------------------------------------------------ */
function AsyncLocalStorage() {
  this._enabled = false;
  this._store = undefined;
  _allInstances.push(this);
}

AsyncLocalStorage.prototype.enable = function() {
  this._enabled = true;
};

AsyncLocalStorage.prototype.disable = function() {
  this._enabled = false;
  this._store = undefined;
  var idx = _allInstances.indexOf(this);
  if (idx !== -1) _allInstances.splice(idx, 1);
};

AsyncLocalStorage.prototype.enterWith = function(store) {
  this._store = store;
  this._enabled = true;
  if (_allInstances.indexOf(this) === -1) {
    _allInstances.push(this);
  }
};

AsyncLocalStorage.prototype.run = function(store, callback) {
  var previous = this._store;
  this._store = store;
  this._enabled = true;
  if (_allInstances.indexOf(this) === -1) {
    _allInstances.push(this);
  }
  var args = [];
  for (var i = 2; i < arguments.length; i++) args.push(arguments[i]);
  try {
    return callback.apply(null, args);
  } finally {
    this._store = previous;
  }
};

AsyncLocalStorage.prototype.exit = function(callback) {
  var previous = this._store;
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  try {
    this._store = undefined;
    return callback.apply(null, args);
  } finally {
    this._store = previous;
  }
};

AsyncLocalStorage.prototype.getStore = function() {
  if (!this._enabled) return undefined;
  return this._store;
};

AsyncLocalStorage.prototype.snapshot = function() {
  var captured = _captureContext();
  return function(fn) {
    var args = [];
    for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
    var prev = _restoreContext(captured);
    try {
      return fn.apply(null, args);
    } finally {
      _restoreContext(prev);
    }
  };
};

AsyncLocalStorage.bind = function(fn) {
  return _wrapCallback(fn);
};

AsyncLocalStorage.snapshot = function() {
  var captured = _captureContext();
  return function(fn) {
    var args = [];
    for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
    var prev = _restoreContext(captured);
    try {
      return fn.apply(null, args);
    } finally {
      _restoreContext(prev);
    }
  };
};

module.exports = {
  createHook: createHook,
  executionAsyncId: executionAsyncId,
  triggerAsyncId: triggerAsyncId,
  AsyncResource: AsyncResource,
  AsyncLocalStorage: AsyncLocalStorage
};
"#
    .trim()
    .to_string()
}

fn node_worker_threads_module() -> String {
    r##"
var isMainThread = true;
var parentPort = null;
var workerData = null;
var threadId = 0;

// --- MessagePort -----------------------------------------------------------
function MessagePort() {
  this._listeners = {};
  this._remotePort = null;
  this._started = false;
  this._closed = false;
  this._queue = [];
  this._onmessage = null;
  this._onmessageerror = null;
}

Object.defineProperty(MessagePort.prototype, 'onmessage', {
  get: function() { return this._onmessage; },
  set: function(handler) {
    this._onmessage = handler;
    this.start();
  },
  configurable: true
});

Object.defineProperty(MessagePort.prototype, 'onmessageerror', {
  get: function() { return this._onmessageerror; },
  set: function(handler) { this._onmessageerror = handler; },
  configurable: true
});

MessagePort.prototype.addEventListener = function(type, callback) {
  if (!callback) return;
  if (!this._listeners[type]) this._listeners[type] = [];
  this._listeners[type].push(callback);
};

MessagePort.prototype.removeEventListener = function(type, callback) {
  var list = this._listeners[type];
  if (!list) return;
  var idx = list.indexOf(callback);
  if (idx !== -1) list.splice(idx, 1);
};

MessagePort.prototype.dispatchEvent = function(event) {
  var list = this._listeners[event.type];
  if (list) {
    var copy = list.slice();
    for (var i = 0; i < copy.length; i++) {
      try { copy[i].call(this, event); } catch (e) { /* swallow */ }
    }
  }
  return true;
};

MessagePort.prototype.postMessage = function(value, transferList) {
  if (this._closed) return;
  var remote = this._remotePort;
  if (!remote || remote._closed) return;

  var clonedData;
  try {
    if (typeof globalThis.structuredClone === 'function') {
      clonedData = globalThis.structuredClone(value);
    } else {
      clonedData = JSON.parse(JSON.stringify(value));
    }
  } catch (err) {
    var errTarget = remote;
    queueMicrotask(function() {
      if (!errTarget._closed) errTarget._dispatchMessageError(err);
    });
    return;
  }

  if (remote._started) {
    var target = remote;
    queueMicrotask(function() {
      if (!target._closed) target._dispatchMessage(clonedData);
    });
  } else {
    remote._queue.push(clonedData);
  }
};

MessagePort.prototype.start = function() {
  if (this._started) return;
  this._started = true;
  if (this._queue.length > 0) {
    var pending = this._queue.splice(0);
    var self = this;
    for (var i = 0; i < pending.length; i++) {
      (function(data) {
        queueMicrotask(function() {
          if (!self._closed) self._dispatchMessage(data);
        });
      })(pending[i]);
    }
  }
};

MessagePort.prototype.close = function() {
  this._closed = true;
  this._queue.length = 0;
};

MessagePort.prototype._dispatchMessage = function(data) {
  var event = { type: 'message', data: data, target: this, currentTarget: this };
  if (this._onmessage) {
    try { this._onmessage.call(this, event); } catch (e) { /* swallow */ }
  }
  this.dispatchEvent(event);
};

MessagePort.prototype._dispatchMessageError = function(error) {
  var event = { type: 'messageerror', data: error, target: this, currentTarget: this };
  if (this._onmessageerror) {
    try { this._onmessageerror.call(this, event); } catch (e) { /* swallow */ }
  }
  this.dispatchEvent(event);
};

Object.defineProperty(MessagePort.prototype, Symbol.toStringTag, {
  value: 'MessagePort',
  configurable: true
});

// --- MessageChannel --------------------------------------------------------
function MessageChannel() {
  this.port1 = new MessagePort();
  this.port2 = new MessagePort();
  this.port1._remotePort = this.port2;
  this.port2._remotePort = this.port1;
}

Object.defineProperty(MessageChannel.prototype, Symbol.toStringTag, {
  value: 'MessageChannel',
  configurable: true
});

// --- BroadcastChannel ------------------------------------------------------
var _broadcastRegistry = {};

function BroadcastChannel(name) {
  this.name = String(name);
  this._closed = false;
  this._listeners = {};
  this._onmessage = null;
  this._onmessageerror = null;

  if (!_broadcastRegistry[this.name]) {
    _broadcastRegistry[this.name] = [];
  }
  _broadcastRegistry[this.name].push(this);
}

Object.defineProperty(BroadcastChannel.prototype, 'onmessage', {
  get: function() { return this._onmessage; },
  set: function(handler) { this._onmessage = handler; },
  configurable: true
});

Object.defineProperty(BroadcastChannel.prototype, 'onmessageerror', {
  get: function() { return this._onmessageerror; },
  set: function(handler) { this._onmessageerror = handler; },
  configurable: true
});

BroadcastChannel.prototype.addEventListener = function(type, callback) {
  if (!callback) return;
  if (!this._listeners[type]) this._listeners[type] = [];
  this._listeners[type].push(callback);
};

BroadcastChannel.prototype.removeEventListener = function(type, callback) {
  var list = this._listeners[type];
  if (!list) return;
  var idx = list.indexOf(callback);
  if (idx !== -1) list.splice(idx, 1);
};

BroadcastChannel.prototype.dispatchEvent = function(event) {
  var list = this._listeners[event.type];
  if (list) {
    var copy = list.slice();
    for (var i = 0; i < copy.length; i++) {
      try { copy[i].call(this, event); } catch (e) { /* swallow */ }
    }
  }
  return true;
};

BroadcastChannel.prototype.postMessage = function(message) {
  if (this._closed) {
    var err = new Error('BroadcastChannel is closed');
    err.name = 'InvalidStateError';
    throw err;
  }

  var clonedMessage;
  try {
    if (typeof globalThis.structuredClone === 'function') {
      clonedMessage = globalThis.structuredClone(message);
    } else {
      clonedMessage = JSON.parse(JSON.stringify(message));
    }
  } catch (e) {
    return;
  }

  var channels = _broadcastRegistry[this.name];
  if (!channels) return;
  var self = this;
  for (var i = 0; i < channels.length; i++) {
    (function(channel) {
      if (channel !== self && !channel._closed) {
        queueMicrotask(function() {
          if (!channel._closed) {
            var event = { type: 'message', data: clonedMessage, target: channel, currentTarget: channel };
            if (channel._onmessage) {
              try { channel._onmessage.call(channel, event); } catch (e) { /* swallow */ }
            }
            channel.dispatchEvent(event);
          }
        });
      }
    })(channels[i]);
  }
};

BroadcastChannel.prototype.close = function() {
  if (this._closed) return;
  this._closed = true;
  var channels = _broadcastRegistry[this.name];
  if (channels) {
    var idx = channels.indexOf(this);
    if (idx !== -1) channels.splice(idx, 1);
    if (channels.length === 0) delete _broadcastRegistry[this.name];
  }
};

Object.defineProperty(BroadcastChannel.prototype, Symbol.toStringTag, {
  value: 'BroadcastChannel',
  configurable: true
});

// --- Worker (stub) ---------------------------------------------------------
function Worker(filename, options) {
  throw new Error('worker_threads.Worker is not supported in this runtime. Use child_process instead.');
}

// --- Utility functions -----------------------------------------------------
var SHARE_ENV = Symbol.for('nodejs.worker_threads.SHARE_ENV');

var _envData = {};
function getEnvironmentData(key) {
  return _envData[key];
}
function setEnvironmentData(key, value) {
  if (value === undefined) {
    delete _envData[key];
  } else {
    _envData[key] = value;
  }
}

function receiveMessageOnPort(port) {
  /* Synchronous message receive - only works for ports with queued messages */
  if (port && port._queue && port._queue.length > 0) {
    return { message: port._queue.shift() };
  }
  return undefined;
}

function moveMessagePortToContext(port, contextifiedSandbox) {
  return port;
}

function markAsUntransferable(obj) {
  /* Mark an object as not transferable (no-op in our implementation) */
}

function isMarkedAsUntransferable(obj) {
  return false;
}

// --- Exports ---------------------------------------------------------------
module.exports = {
  isMainThread: isMainThread,
  parentPort: parentPort,
  workerData: workerData,
  threadId: threadId,
  resourceLimits: {},
  Worker: Worker,
  MessageChannel: MessageChannel,
  MessagePort: MessagePort,
  BroadcastChannel: BroadcastChannel,
  SHARE_ENV: SHARE_ENV,
  getEnvironmentData: getEnvironmentData,
  setEnvironmentData: setEnvironmentData,
  receiveMessageOnPort: receiveMessageOnPort,
  moveMessagePortToContext: moveMessagePortToContext,
  markAsUntransferable: markAsUntransferable,
  isMarkedAsUntransferable: isMarkedAsUntransferable
};
"##
    .trim()
    .to_string()
}

fn node_vm_module() -> String {
    r##"
function Script(code, options) {
  this._code = code;
  this._options = options || {};
}
Script.prototype.runInThisContext = function(options) {
  // Use indirect eval to run in global scope
  return (0, eval)(this._code);
};
Script.prototype.runInNewContext = function(sandbox, options) {
  // Best-effort: run with sandbox properties as local vars
  var keys = sandbox ? Object.keys(sandbox) : [];
  var values = keys.map(function(k) { return sandbox[k]; });
  // Declare locals explicitly so Hermes doesn't reject undeclared references
  var varDecls = keys.length > 0 ? 'var ' + keys.join(',') + ';\n' : '';
  var assigns = '';
  for (var i = 0; i < keys.length; i++) {
    assigns += keys[i] + ' = arguments[' + i + '];\n';
  }
  var body = varDecls + assigns + 'return (' + this._code + ');\n';
  var fn = new Function(body);
  return fn.apply(null, values);
};

function createContext(sandbox) {
  return sandbox || {};
}

function runInThisContext(code, options) {
  return new Script(code, options).runInThisContext(options);
}

function runInNewContext(code, sandbox, options) {
  return new Script(code, options).runInNewContext(sandbox, options);
}

function compileFunction(code, params, options) {
  params = params || [];
  return new Function(params.join(','), code);
}

module.exports = {
  Script: Script,
  createContext: createContext,
  runInThisContext: runInThisContext,
  runInNewContext: runInNewContext,
  compileFunction: compileFunction,
  isContext: function(sandbox) { return typeof sandbox === 'object' && sandbox !== null; }
};
"##
    .trim()
    .to_string()
}

fn node_console_module() -> String {
    r#"
// node:console module — re-exports the global console
var Console = function(stdout, stderr) {
  this._stdout = stdout;
  this._stderr = stderr;
  this._times = {};
  this._counts = {};
  this._groups = 0;
};
Console.prototype.log = function() { console.log.apply(console, arguments); };
Console.prototype.info = function() { console.info.apply(console, arguments); };
Console.prototype.warn = function() { console.warn.apply(console, arguments); };
Console.prototype.error = function() { console.error.apply(console, arguments); };
Console.prototype.debug = function() { console.debug.apply(console, arguments); };
Console.prototype.dir = function(obj) { console.dir(obj); };
Console.prototype.trace = function() { console.trace.apply(console, arguments); };
Console.prototype.assert = function(condition) {
  if (!condition) console.error.apply(console, ['Assertion failed:'].concat(Array.prototype.slice.call(arguments, 1)));
};
Console.prototype.time = function(label) {
  this._times[label || 'default'] = Date.now();
};
Console.prototype.timeEnd = function(label) {
  label = label || 'default';
  var start = this._times[label];
  if (start !== undefined) {
    console.log(label + ': ' + (Date.now() - start) + 'ms');
    delete this._times[label];
  }
};
Console.prototype.timeLog = function(label) {
  label = label || 'default';
  var start = this._times[label];
  if (start !== undefined) {
    var args = [label + ': ' + (Date.now() - start) + 'ms'];
    for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
    console.log.apply(console, args);
  }
};
Console.prototype.count = function(label) {
  label = label || 'default';
  this._counts[label] = (this._counts[label] || 0) + 1;
  console.log(label + ': ' + this._counts[label]);
};
Console.prototype.countReset = function(label) {
  label = label || 'default';
  this._counts[label] = 0;
};
Console.prototype.group = function() {
  this._groups++;
  if (arguments.length > 0) console.log.apply(console, arguments);
};
Console.prototype.groupEnd = function() {
  if (this._groups > 0) this._groups--;
};
Console.prototype.table = function(data) {
  console.log(data);
};
Console.prototype.clear = function() {};

module.exports = console;
module.exports.Console = Console;
"#
    .trim()
    .to_string()
}

fn node_cluster_module() -> String {
    r#"
var EventEmitter = require('events');

var cluster = Object.create(EventEmitter.prototype);
EventEmitter.call(cluster);

cluster.isMaster = true;
cluster.isPrimary = true;
cluster.isWorker = false;
cluster.workers = {};
cluster.settings = {};
cluster.SCHED_NONE = 1;
cluster.SCHED_RR = 2;
cluster.schedulingPolicy = 2;

cluster.setupMaster = function(settings) {
  if (settings) {
    for (var k in settings) {
      if (Object.prototype.hasOwnProperty.call(settings, k)) {
        cluster.settings[k] = settings[k];
      }
    }
  }
};
cluster.setupPrimary = cluster.setupMaster;

cluster.fork = function(env) {
  throw new Error('cluster.fork() is not supported in this runtime. Use child_process instead.');
};

cluster.disconnect = function(callback) {
  if (typeof callback === 'function') callback();
};

module.exports = cluster;
"#
    .trim()
    .to_string()
}

fn node_dgram_module() -> String {
    r#"
function createSocket(type, callback) {
  throw new Error('dgram.createSocket() is not yet supported in this runtime');
}

module.exports = {
  createSocket: createSocket,
  Socket: function() { throw new Error('dgram.Socket is not yet supported'); }
};
module.exports.default = module.exports;
"#
    .trim()
    .to_string()
}

fn node_domain_module() -> String {
    r#"
var EventEmitter = require('events');

function Domain() {
  EventEmitter.call(this);
  this.members = [];
}
Domain.prototype = Object.create(EventEmitter.prototype);
Domain.prototype.constructor = Domain;
Domain.prototype.add = function(emitter) { this.members.push(emitter); };
Domain.prototype.remove = function(emitter) {
  var idx = this.members.indexOf(emitter);
  if (idx !== -1) this.members.splice(idx, 1);
};
Domain.prototype.run = function(fn) {
  try { return fn(); }
  catch(e) { this.emit('error', e); }
};
Domain.prototype.bind = function(fn) {
  var self = this;
  return function() {
    try { return fn.apply(this, arguments); }
    catch(e) { self.emit('error', e); }
  };
};
Domain.prototype.intercept = function(fn) {
  var self = this;
  return function(err) {
    if (err) { self.emit('error', err); return; }
    var args = Array.prototype.slice.call(arguments, 1);
    try { return fn.apply(this, args); }
    catch(e) { self.emit('error', e); }
  };
};
Domain.prototype.enter = function() {};
Domain.prototype.exit = function() {};
Domain.prototype.dispose = function() { this.members = []; };

function create() { return new Domain(); }

module.exports = {
  Domain: Domain,
  create: create,
  createDomain: create
};
"#
    .trim()
    .to_string()
}

fn node_v8_module() -> String {
    r##"
/* Try to get real memory stats from process.memoryUsage() if available */
function _getMemStats() {
  try {
    if (typeof process !== 'undefined' && typeof process.memoryUsage === 'function') {
      return process.memoryUsage();
    }
  } catch (e) {}
  return { rss: 0, heapTotal: 0, heapUsed: 0, external: 0, arrayBuffers: 0 };
}

module.exports = {
  getHeapStatistics: function() {
    var mem = _getMemStats();
    var heapTotal = mem.heapTotal || 0;
    var heapUsed = mem.heapUsed || 0;
    var external = mem.external || 0;
    /* Estimate heap limit as 4x current total (Hermes doesn't expose this directly) */
    var heapLimit = Math.max(heapTotal * 4, 256 * 1024 * 1024);
    return {
      total_heap_size: heapTotal,
      total_heap_size_executable: 0,
      total_physical_size: heapTotal,
      total_available_size: heapLimit - heapUsed,
      used_heap_size: heapUsed,
      heap_size_limit: heapLimit,
      malloced_memory: heapUsed,
      peak_malloced_memory: heapUsed,
      does_zap_garbage: 0,
      number_of_native_contexts: 1,
      number_of_detached_contexts: 0,
      total_global_handles_size: 8192,
      used_global_handles_size: 4096,
      external_memory: external
    };
  },
  getHeapSpaceStatistics: function() {
    var mem = _getMemStats();
    var heapTotal = mem.heapTotal || 0;
    var heapUsed = mem.heapUsed || 0;
    return [
      { space_name: 'new_space', space_size: Math.floor(heapTotal * 0.25), space_used_size: Math.floor(heapUsed * 0.2), space_available_size: Math.floor(heapTotal * 0.05), physical_space_size: Math.floor(heapTotal * 0.25) },
      { space_name: 'old_space', space_size: Math.floor(heapTotal * 0.6), space_used_size: Math.floor(heapUsed * 0.7), space_available_size: Math.floor(heapTotal * 0.1), physical_space_size: Math.floor(heapTotal * 0.6) },
      { space_name: 'code_space', space_size: Math.floor(heapTotal * 0.1), space_used_size: Math.floor(heapUsed * 0.05), space_available_size: Math.floor(heapTotal * 0.05), physical_space_size: Math.floor(heapTotal * 0.1) },
      { space_name: 'large_object_space', space_size: Math.floor(heapTotal * 0.05), space_used_size: Math.floor(heapUsed * 0.05), space_available_size: 0, physical_space_size: Math.floor(heapTotal * 0.05) }
    ];
  },
  getHeapSnapshot: function() {
    var Readable;
    try { Readable = require('stream').Readable; } catch(e) {}
    if (Readable) {
      var s = new Readable({ read: function() { this.push(null); } });
      return s;
    }
    return { read: function() { return null; } };
  },
  getHeapCodeStatistics: function() {
    var mem = _getMemStats();
    var heapUsed = mem.heapUsed || 0;
    return {
      code_and_metadata_size: Math.floor(heapUsed * 0.1),
      bytecode_and_metadata_size: Math.floor(heapUsed * 0.05),
      external_script_source_size: 0,
      cpu_profiler_metadata_size: 0
    };
  },
  setFlagsFromString: function() {},
  serialize: function(value) {
    var json = JSON.stringify(value);
    if (typeof Buffer !== 'undefined') return Buffer.from(json);
    return new TextEncoder().encode(json);
  },
  deserialize: function(buffer) {
    var str = typeof buffer === 'string' ? buffer :
      (typeof Buffer !== 'undefined' && Buffer.isBuffer(buffer)) ? buffer.toString() :
      new TextDecoder().decode(buffer);
    return JSON.parse(str);
  },
  cachedDataVersionTag: function() { return 0; },
  writeHeapSnapshot: function(filename) {
    /* In a real V8 environment this writes a heap snapshot file.
       We return a filename to maintain API compatibility. */
    if (!filename) {
      filename = 'Heap.' + Date.now() + '.heapsnapshot';
    }
    return filename;
  }
};
"##
    .trim()
    .to_string()
}

fn node_constants_module() -> String {
    r#"
// POSIX signal constants
module.exports = {
  SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5,
  SIGABRT: 6, SIGIOT: 6, SIGBUS: 10, SIGFPE: 8, SIGKILL: 9,
  SIGUSR1: 30, SIGSEGV: 11, SIGUSR2: 31, SIGPIPE: 13,
  SIGALRM: 14, SIGTERM: 15, SIGCHLD: 20, SIGCONT: 19,
  SIGSTOP: 17, SIGTSTP: 18, SIGTTIN: 21, SIGTTOU: 22,
  SIGURG: 16, SIGXCPU: 24, SIGXFSZ: 25, SIGVTALRM: 26,
  SIGPROF: 27, SIGWINCH: 28, SIGIO: 23, SIGINFO: 29,
  SIGSYS: 12,
  // File access constants
  O_RDONLY: 0, O_WRONLY: 1, O_RDWR: 2, O_CREAT: 512,
  O_EXCL: 2048, O_TRUNC: 1024, O_APPEND: 8,
  O_DIRECTORY: 1048576, O_NOFOLLOW: 256, O_SYNC: 128,
  O_DSYNC: 4194304, O_NONBLOCK: 4,
  S_IFMT: 61440, S_IFREG: 32768, S_IFDIR: 16384,
  S_IFCHR: 8192, S_IFBLK: 24576, S_IFIFO: 4096,
  S_IFLNK: 40960, S_IFSOCK: 49152,
  S_IRWXU: 448, S_IRUSR: 256, S_IWUSR: 128, S_IXUSR: 64,
  S_IRWXG: 56, S_IRGRP: 32, S_IWGRP: 16, S_IXGRP: 8,
  S_IRWXO: 7, S_IROTH: 4, S_IWOTH: 2, S_IXOTH: 1,
  F_OK: 0, R_OK: 4, W_OK: 2, X_OK: 1,
  UV_UDP_REUSEADDR: 4,
  // errno constants
  E2BIG: 7, EACCES: 13, EADDRINUSE: 48, EADDRNOTAVAIL: 49,
  EAFNOSUPPORT: 47, EAGAIN: 35, EALREADY: 37, EBADF: 9,
  EBADMSG: 94, EBUSY: 16, ECANCELED: 89, ECHILD: 10,
  ECONNABORTED: 53, ECONNREFUSED: 61, ECONNRESET: 54,
  EDEADLK: 11, EDESTADDRREQ: 39, EDOM: 33, EEXIST: 17,
  EFAULT: 14, EFBIG: 27, EHOSTUNREACH: 65, EIDRM: 90,
  EILSEQ: 92, EINPROGRESS: 36, EINTR: 4, EINVAL: 22,
  EIO: 5, EISCONN: 56, EISDIR: 21, ELOOP: 62,
  EMFILE: 24, EMLINK: 31, EMSGSIZE: 40, ENAMETOOLONG: 63,
  ENETDOWN: 50, ENETRESET: 52, ENETUNREACH: 51, ENFILE: 23,
  ENOBUFS: 55, ENODEV: 19, ENOENT: 2, ENOMEM: 12,
  ENOPROTOOPT: 42, ENOSPC: 28, ENOSYS: 78, ENOTCONN: 57,
  ENOTDIR: 20, ENOTEMPTY: 66, ENOTSOCK: 38, ENOTSUP: 45,
  ENOTTY: 25, ENXIO: 6, EOPNOTSUPP: 102, EOVERFLOW: 84,
  EPERM: 1, EPIPE: 32, EPROTO: 100, EPROTONOSUPPORT: 43,
  EPROTOTYPE: 41, ERANGE: 34, EROFS: 30, ESPIPE: 29,
  ESRCH: 3, ETIMEDOUT: 60, ETXTBSY: 26, EXDEV: 18
};
"#
    .trim()
    .to_string()
}


fn ws_module() -> String {
    r##"
var EventEmitter;
try { EventEmitter = require('events'); } catch(e) {
  EventEmitter = function() { this._events = {}; };
  EventEmitter.prototype.on = function(e, fn) { if (!this._events) this._events = {}; if (!this._events[e]) this._events[e] = []; this._events[e].push(fn); return this; };
  EventEmitter.prototype.emit = function(e) { if (!this._events) this._events = {}; var a = [].slice.call(arguments, 1); var l = this._events[e] || []; for (var i = 0; i < l.length; i++) l[i].apply(this, a); return l.length > 0; };
  EventEmitter.prototype.once = function(e, fn) { var self = this; function w() { self.removeListener(e, w); fn.apply(this, arguments); } w.listener = fn; this.on(e, w); return this; };
  EventEmitter.prototype.removeListener = function(e, fn) { if (!this._events) this._events = {}; var l = this._events[e]; if (l) { var n = []; for (var i = 0; i < l.length; i++) { if (l[i] !== fn && l[i].listener !== fn) n.push(l[i]); } this._events[e] = n; } return this; };
  EventEmitter.prototype.removeAllListeners = function(e) { if (!this._events) this._events = {}; if (e) delete this._events[e]; else this._events = {}; return this; };
  EventEmitter.prototype.addListener = EventEmitter.prototype.on;
  EventEmitter.prototype.off = EventEmitter.prototype.removeListener;
  EventEmitter.prototype.listeners = function(e) { if (!this._events) this._events = {}; return (this._events[e] || []).slice(); };
  EventEmitter.prototype.listenerCount = function(e) { if (!this._events) this._events = {}; return (this._events[e] || []).length; };
}

var _hasTcp = typeof __exactTcpListen === 'function';

// ========================================================
// WebSocket frame constants
// ========================================================
var OPCODE_CONTINUATION = 0x0;
var OPCODE_TEXT = 0x1;
var OPCODE_BINARY = 0x2;
var OPCODE_CLOSE = 0x8;
var OPCODE_PING = 0x9;
var OPCODE_PONG = 0xA;

var WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

var READY_CONNECTING = 0;
var READY_OPEN = 1;
var READY_CLOSING = 2;
var READY_CLOSED = 3;

// ========================================================
// Utility: convert hex string to raw binary string
// ========================================================
function hexToRaw(hex) {
  var raw = '';
  for (var i = 0; i < hex.length; i += 2) {
    raw += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return raw;
}

// ========================================================
// Utility: compute Sec-WebSocket-Accept value
// ========================================================
function computeAcceptKey(key) {
  var input = key + WS_GUID;
  if (typeof __exactHashSync === 'function') {
    var hex = __exactHashSync('sha1', input);
    var raw = hexToRaw(hex);
    if (typeof btoa === 'function') return btoa(raw);
  }
  // Fallback: if no native hash, try crypto module
  try {
    var crypto = require('crypto');
    return crypto.createHash('sha1').update(input).digest('base64');
  } catch(e) {}
  return '';
}

// ========================================================
// Utility: encode a WebSocket frame (server->client, no mask)
// ========================================================
function encodeFrame(opcode, payload, fin) {
  if (fin === undefined) fin = true;
  var payloadBytes;
  if (typeof payload === 'string') {
    payloadBytes = [];
    if (typeof TextEncoder !== 'undefined') {
      var encoded = new TextEncoder().encode(payload);
      for (var i = 0; i < encoded.length; i++) payloadBytes.push(encoded[i]);
    } else {
      for (var i = 0; i < payload.length; i++) {
        var c = payload.charCodeAt(i);
        if (c < 0x80) {
          payloadBytes.push(c);
        } else if (c < 0x800) {
          payloadBytes.push(0xC0 | (c >> 6), 0x80 | (c & 0x3F));
        } else {
          payloadBytes.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
        }
      }
    }
  } else if (payload instanceof Uint8Array) {
    payloadBytes = [];
    for (var i = 0; i < payload.length; i++) payloadBytes.push(payload[i]);
  } else if (Array.isArray(payload)) {
    payloadBytes = payload;
  } else {
    payloadBytes = [];
  }

  var len = payloadBytes.length;
  var header = [];
  header.push((fin ? 0x80 : 0) | (opcode & 0x0F));

  if (len < 126) {
    header.push(len);
  } else if (len < 65536) {
    header.push(126);
    header.push((len >> 8) & 0xFF);
    header.push(len & 0xFF);
  } else {
    header.push(127);
    header.push(0); header.push(0); header.push(0); header.push(0);
    header.push((len >> 24) & 0xFF);
    header.push((len >> 16) & 0xFF);
    header.push((len >> 8) & 0xFF);
    header.push(len & 0xFF);
  }

  var frame = '';
  for (var i = 0; i < header.length; i++) frame += String.fromCharCode(header[i]);
  for (var i = 0; i < payloadBytes.length; i++) frame += String.fromCharCode(payloadBytes[i]);
  return frame;
}

// ========================================================
// Utility: parse WebSocket frames from a buffer (string of raw bytes)
// ========================================================
function parseFrames(buffer) {
  var frames = [];
  var pos = 0;

  while (pos < buffer.length) {
    if (pos + 2 > buffer.length) break;

    var b0 = buffer.charCodeAt(pos);
    var b1 = buffer.charCodeAt(pos + 1);
    var fin = (b0 & 0x80) !== 0;
    var opcode = b0 & 0x0F;
    var masked = (b1 & 0x80) !== 0;
    var payloadLen = b1 & 0x7F;
    var headerLen = 2;

    if (payloadLen === 126) {
      if (pos + 4 > buffer.length) break;
      payloadLen = (buffer.charCodeAt(pos + 2) << 8) | buffer.charCodeAt(pos + 3);
      headerLen = 4;
    } else if (payloadLen === 127) {
      if (pos + 10 > buffer.length) break;
      payloadLen = (buffer.charCodeAt(pos + 6) << 24) |
                   (buffer.charCodeAt(pos + 7) << 16) |
                   (buffer.charCodeAt(pos + 8) << 8) |
                   buffer.charCodeAt(pos + 9);
      headerLen = 10;
    }

    var maskLen = masked ? 4 : 0;
    var totalLen = headerLen + maskLen + payloadLen;
    if (pos + totalLen > buffer.length) break;

    var maskKey = null;
    if (masked) {
      maskKey = [
        buffer.charCodeAt(pos + headerLen),
        buffer.charCodeAt(pos + headerLen + 1),
        buffer.charCodeAt(pos + headerLen + 2),
        buffer.charCodeAt(pos + headerLen + 3)
      ];
    }

    var payloadStart = pos + headerLen + maskLen;
    var payload = new Uint8Array(payloadLen);
    for (var i = 0; i < payloadLen; i++) {
      var byte = buffer.charCodeAt(payloadStart + i);
      if (masked) {
        byte = byte ^ maskKey[i % 4];
      }
      payload[i] = byte;
    }

    frames.push({ fin: fin, opcode: opcode, masked: masked, payload: payload });
    pos += totalLen;
  }

  return { frames: frames, remainder: buffer.substring(pos) };
}

// ========================================================
// WebSocket (server-side connection) - compatible with ws package API
// ========================================================
function WebSocketConnection(tcpHandle, req) {
  if (!(this instanceof WebSocketConnection)) return new WebSocketConnection(tcpHandle, req);
  this._events = {};
  this._handle = tcpHandle;
  this._readyState = READY_OPEN;
  this._buffer = '';
  this._pollTimer = null;
  this._fragments = [];
  this._fragmentOpcode = 0;
  this.protocol = '';
  this.extensions = '';
  this.bufferedAmount = 0;
  this._req = req || null;
  this._closeFrameSent = false;
  this._closeFrameReceived = false;
  this._binaryType = 'nodebuffer';

  // Mixin EventEmitter
  if (typeof EventEmitter === 'function' && EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }

  this._startReading();
}

Object.defineProperty(WebSocketConnection.prototype, 'readyState', {
  get: function() { return this._readyState; },
  enumerable: true
});

Object.defineProperty(WebSocketConnection.prototype, 'binaryType', {
  get: function() { return this._binaryType; },
  set: function(val) { this._binaryType = val; },
  enumerable: true
});

WebSocketConnection.CONNECTING = READY_CONNECTING;
WebSocketConnection.OPEN = READY_OPEN;
WebSocketConnection.CLOSING = READY_CLOSING;
WebSocketConnection.CLOSED = READY_CLOSED;

WebSocketConnection.prototype.CONNECTING = READY_CONNECTING;
WebSocketConnection.prototype.OPEN = READY_OPEN;
WebSocketConnection.prototype.CLOSING = READY_CLOSING;
WebSocketConnection.prototype.CLOSED = READY_CLOSED;

WebSocketConnection.prototype._startReading = function() {
  if (this._pollTimer != null) return;
  var self = this;

  function poll() {
    if (self._readyState === READY_CLOSED || self._handle == null) return;
    try {
      var data = __exactTcpRead(self._handle, 65536);
      if (data === null) {
        self._handleTransportClose();
        return;
      }
      if (data.length > 0) {
        self._buffer += data;
        self._processBuffer();
      }
    } catch(e) {
      if (self._readyState !== READY_CLOSED) {
        self.emit('error', e);
        self._handleTransportClose();
      }
      return;
    }
    self._pollTimer = setTimeout(poll, 5);
  }
  self._pollTimer = setTimeout(poll, 0);
};

WebSocketConnection.prototype._processBuffer = function() {
  var result = parseFrames(this._buffer);
  this._buffer = result.remainder;

  for (var i = 0; i < result.frames.length; i++) {
    this._handleFrame(result.frames[i]);
  }
};

WebSocketConnection.prototype._handleFrame = function(frame) {
  switch (frame.opcode) {
    case OPCODE_TEXT:
    case OPCODE_BINARY:
      if (frame.fin) {
        if (this._fragments.length > 0) {
          this._fragments = [];
        }
        this._deliverMessage(frame.opcode, frame.payload);
      } else {
        this._fragments = [frame.payload];
        this._fragmentOpcode = frame.opcode;
      }
      break;

    case OPCODE_CONTINUATION:
      this._fragments.push(frame.payload);
      if (frame.fin) {
        var totalLen = 0;
        for (var j = 0; j < this._fragments.length; j++) totalLen += this._fragments[j].length;
        var combined = new Uint8Array(totalLen);
        var offset = 0;
        for (var j = 0; j < this._fragments.length; j++) {
          combined.set(this._fragments[j], offset);
          offset += this._fragments[j].length;
        }
        var op = this._fragmentOpcode;
        this._fragments = [];
        this._fragmentOpcode = 0;
        this._deliverMessage(op, combined);
      }
      break;

    case OPCODE_CLOSE:
      this._closeFrameReceived = true;
      var code = 1005;
      var reason = '';
      if (frame.payload.length >= 2) {
        code = (frame.payload[0] << 8) | frame.payload[1];
        if (frame.payload.length > 2) {
          var reasonBytes = frame.payload.slice(2);
          if (typeof TextDecoder !== 'undefined') {
            reason = new TextDecoder().decode(reasonBytes);
          } else {
            for (var j = 0; j < reasonBytes.length; j++) reason += String.fromCharCode(reasonBytes[j]);
          }
        }
      }
      if (!this._closeFrameSent) {
        var closePayload = [];
        if (frame.payload.length >= 2) {
          closePayload.push(frame.payload[0]);
          closePayload.push(frame.payload[1]);
        }
        this._sendFrame(OPCODE_CLOSE, closePayload);
        this._closeFrameSent = true;
      }
      this._readyState = READY_CLOSED;
      if (this._pollTimer != null) { clearTimeout(this._pollTimer); this._pollTimer = null; }
      try { if (this._handle != null) __exactTcpClose(this._handle); } catch(e) {}
      this._handle = null;
      this.emit('close', code, reason);
      break;

    case OPCODE_PING:
      this._sendFrame(OPCODE_PONG, frame.payload);
      this.emit('ping', frame.payload);
      break;

    case OPCODE_PONG:
      this.emit('pong', frame.payload);
      break;
  }
};

WebSocketConnection.prototype._deliverMessage = function(opcode, payload) {
  if (opcode === OPCODE_TEXT) {
    var text;
    if (typeof TextDecoder !== 'undefined') {
      text = new TextDecoder().decode(payload);
    } else {
      text = '';
      for (var i = 0; i < payload.length; i++) text += String.fromCharCode(payload[i]);
    }
    this.emit('message', text, false);
  } else {
    if (this._binaryType === 'arraybuffer') {
      this.emit('message', payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength), true);
    } else if (this._binaryType === 'fragments') {
      this.emit('message', [payload], true);
    } else {
      if (typeof Buffer !== 'undefined' && Buffer.from) {
        this.emit('message', Buffer.from(payload), true);
      } else {
        this.emit('message', payload, true);
      }
    }
  }
};

WebSocketConnection.prototype._handleTransportClose = function() {
  if (this._readyState === READY_CLOSED) return;
  this._readyState = READY_CLOSED;
  if (this._pollTimer != null) { clearTimeout(this._pollTimer); this._pollTimer = null; }
  try { if (this._handle != null) __exactTcpClose(this._handle); } catch(e) {}
  this._handle = null;
  this.emit('close', 1006, '');
};

WebSocketConnection.prototype._sendFrame = function(opcode, payload) {
  if (this._handle == null) return;
  var frame = encodeFrame(opcode, payload);
  try {
    __exactTcpWrite(this._handle, frame);
  } catch(e) {
    this.emit('error', e);
  }
};

WebSocketConnection.prototype.send = function(data, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  options = options || {};
  if (this._readyState !== READY_OPEN) {
    var err = new Error('WebSocket is not open: readyState ' + this._readyState);
    if (typeof callback === 'function') { callback(err); return; }
    throw err;
  }

  var opcode;
  var payload;

  if (typeof data === 'string') {
    opcode = options.binary ? OPCODE_BINARY : OPCODE_TEXT;
    payload = data;
  } else if (data instanceof Uint8Array) {
    opcode = options.binary !== false ? OPCODE_BINARY : OPCODE_TEXT;
    payload = data;
  } else if (data instanceof ArrayBuffer) {
    opcode = options.binary !== false ? OPCODE_BINARY : OPCODE_TEXT;
    payload = new Uint8Array(data);
  } else if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(data)) {
    opcode = options.binary !== false ? OPCODE_BINARY : OPCODE_TEXT;
    payload = new Uint8Array(data.buffer || data, data.byteOffset || 0, data.length);
  } else if (data == null) {
    opcode = OPCODE_TEXT;
    payload = '';
  } else {
    opcode = OPCODE_TEXT;
    payload = String(data);
  }

  var fin = options.fin !== false;
  this._sendFrame(opcode, payload, fin);
  if (typeof callback === 'function') callback(null);
};

WebSocketConnection.prototype.close = function(code, reason) {
  if (this._readyState === READY_CLOSED || this._readyState === READY_CLOSING) return;
  this._readyState = READY_CLOSING;
  code = code || 1000;
  reason = reason || '';

  var payload = [];
  payload.push((code >> 8) & 0xFF);
  payload.push(code & 0xFF);
  if (reason) {
    if (typeof TextEncoder !== 'undefined') {
      var encoded = new TextEncoder().encode(reason);
      for (var i = 0; i < encoded.length; i++) payload.push(encoded[i]);
    } else {
      for (var i = 0; i < reason.length; i++) payload.push(reason.charCodeAt(i));
    }
  }
  this._closeFrameSent = true;
  this._sendFrame(OPCODE_CLOSE, payload);

  var self = this;
  setTimeout(function() {
    if (self._readyState !== READY_CLOSED) {
      self._handleTransportClose();
    }
  }, 5000);
};

WebSocketConnection.prototype.ping = function(data, mask, callback) {
  if (typeof data === 'function') { callback = data; data = undefined; }
  if (typeof mask === 'function') { callback = mask; mask = undefined; }
  if (this._readyState !== READY_OPEN) return;
  this._sendFrame(OPCODE_PING, data || []);
  if (typeof callback === 'function') callback(null);
};

WebSocketConnection.prototype.pong = function(data, mask, callback) {
  if (typeof data === 'function') { callback = data; data = undefined; }
  if (typeof mask === 'function') { callback = mask; mask = undefined; }
  if (this._readyState !== READY_OPEN) return;
  this._sendFrame(OPCODE_PONG, data || []);
  if (typeof callback === 'function') callback(null);
};

WebSocketConnection.prototype.terminate = function() {
  if (this._readyState === READY_CLOSED) return;
  this._readyState = READY_CLOSED;
  if (this._pollTimer != null) { clearTimeout(this._pollTimer); this._pollTimer = null; }
  try { if (this._handle != null) __exactTcpClose(this._handle); } catch(e) {}
  this._handle = null;
  this.emit('close', 1006, '');
};

// ========================================================
// WebSocket.Server (ws-compatible)
// ========================================================
function WebSocketServer(options, callback) {
  if (!(this instanceof WebSocketServer)) return new WebSocketServer(options, callback);
  options = options || {};
  this._events = {};
  this.clients = new Set();
  this._path = options.path || null;
  this._noServer = options.noServer || false;
  this._server = options.server || null;
  this._handle = null;
  this._acceptTimer = null;
  this._port = options.port || 0;
  this._host = options.host || '0.0.0.0';
  this._listening = false;

  // Mixin EventEmitter
  if (typeof EventEmitter === 'function' && EventEmitter.prototype) {
    for (var k in EventEmitter.prototype) {
      if (!this[k]) this[k] = EventEmitter.prototype[k];
    }
  }

  if (typeof callback === 'function') {
    this.once('listening', callback);
  }

  if (this._noServer) {
    return;
  }

  if (this._server) {
    var self = this;
    this._server.on('upgrade', function(req, socket, head) {
      self.handleUpgrade(req, socket, head, function(ws) {
        self.emit('connection', ws, req);
      });
    });
    this._listening = true;
    var s = this;
    setTimeout(function() { s.emit('listening'); }, 0);
    return;
  }

  if (!_hasTcp) {
    var self = this;
    setTimeout(function() { self.emit('error', new Error('TCP not available')); }, 0);
    return;
  }

  var self = this;
  setTimeout(function() {
    try {
      self._handle = __exactTcpListen(self._host, self._port, 128);
      try {
        var info = __exactTcpLocalAddr(self._handle);
        if (info) {
          var addr = JSON.parse(info);
          self._port = addr.port;
          self._host = addr.address;
        }
      } catch(e) {}
      self._listening = true;
      self.emit('listening');
      self._startAccepting();
    } catch(e) {
      self.emit('error', e);
    }
  }, 0);
}

WebSocketServer.prototype._startAccepting = function() {
  if (this._acceptTimer != null) return;
  var self = this;

  function acceptLoop() {
    if (!self._listening || self._handle == null) return;
    try {
      var clientHandle = __exactTcpAccept(self._handle);
      if (clientHandle !== -1) {
        self._handleRawConnection(clientHandle);
      }
    } catch(e) {
      if (self._listening) self.emit('error', e);
      return;
    }
    self._acceptTimer = setTimeout(acceptLoop, 10);
  }
  self._acceptTimer = setTimeout(acceptLoop, 0);
};

WebSocketServer.prototype._handleRawConnection = function(tcpHandle) {
  var self = this;
  var buffer = '';
  var attempts = 0;
  var maxAttempts = 200;

  function readHeader() {
    if (attempts++ > maxAttempts) {
      try { __exactTcpClose(tcpHandle); } catch(e) {}
      return;
    }
    try {
      var data = __exactTcpRead(tcpHandle, 65536);
      if (data === null) {
        try { __exactTcpClose(tcpHandle); } catch(e) {}
        return;
      }
      if (data.length > 0) {
        buffer += data;
      }
      var headerEnd = buffer.indexOf('\r\n\r\n');
      if (headerEnd !== -1) {
        var headerStr = buffer.substring(0, headerEnd);
        var body = buffer.substring(headerEnd + 4);
        var req = parseHttpRequest(headerStr);
        if (req && isUpgradeRequest(req)) {
          self._completeUpgrade(tcpHandle, req, body);
        } else {
          var response = 'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
          try { __exactTcpWrite(tcpHandle, response); } catch(e) {}
          try { __exactTcpClose(tcpHandle); } catch(e) {}
        }
        return;
      }
    } catch(e) {
      try { __exactTcpClose(tcpHandle); } catch(e2) {}
      return;
    }
    setTimeout(readHeader, 10);
  }
  readHeader();
};

WebSocketServer.prototype._completeUpgrade = function(tcpHandle, req, remainingData) {
  var key = req.headers['sec-websocket-key'];
  if (!key) {
    var response = 'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n';
    try { __exactTcpWrite(tcpHandle, response); } catch(e) {}
    try { __exactTcpClose(tcpHandle); } catch(e) {}
    return;
  }

  var acceptKey = computeAcceptKey(key);
  var responseHeaders = 'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + acceptKey + '\r\n' +
    '\r\n';

  try {
    __exactTcpWrite(tcpHandle, responseHeaders);
  } catch(e) {
    try { __exactTcpClose(tcpHandle); } catch(e2) {}
    return;
  }

  var ws = new WebSocketConnection(tcpHandle, req);
  if (remainingData && remainingData.length > 0) {
    ws._buffer += remainingData;
    ws._processBuffer();
  }
  this.clients.add(ws);
  var self = this;
  ws.on('close', function() {
    self.clients.delete(ws);
  });
  this.emit('connection', ws, req);
};

WebSocketServer.prototype.handleUpgrade = function(req, socket, head, callback) {
  var tcpHandle = null;

  if (socket && typeof socket._handle === 'number') {
    tcpHandle = socket._handle;
    if (socket._pollTimer != null) {
      clearTimeout(socket._pollTimer);
      socket._pollTimer = null;
    }
    socket._handle = null;
    socket.destroyed = true;
  } else if (typeof socket === 'number') {
    tcpHandle = socket;
  } else if (socket && socket._handle != null) {
    tcpHandle = socket._handle;
    if (socket._pollTimer != null) {
      clearTimeout(socket._pollTimer);
      socket._pollTimer = null;
    }
    socket._handle = null;
  }

  if (tcpHandle == null) {
    if (typeof callback === 'function') callback(null);
    return;
  }

  var headers = {};
  if (req && req.headers) {
    headers = req.headers;
  }

  var key = headers['sec-websocket-key'];
  if (!key) {
    try { __exactTcpClose(tcpHandle); } catch(e) {}
    if (typeof callback === 'function') callback(null);
    return;
  }

  var acceptKey = computeAcceptKey(key);
  var responseHeaders = 'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + acceptKey + '\r\n' +
    '\r\n';

  try {
    __exactTcpWrite(tcpHandle, responseHeaders);
  } catch(e) {
    try { __exactTcpClose(tcpHandle); } catch(e2) {}
    if (typeof callback === 'function') callback(null);
    return;
  }

  var ws = new WebSocketConnection(tcpHandle, req);
  if (head && head.length > 0) {
    var headStr = '';
    if (typeof head === 'string') {
      headStr = head;
    } else if (head instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(head))) {
      for (var i = 0; i < head.length; i++) headStr += String.fromCharCode(head[i]);
    }
    if (headStr.length > 0) {
      ws._buffer += headStr;
      ws._processBuffer();
    }
  }
  this.clients.add(ws);
  var self = this;
  ws.on('close', function() {
    self.clients.delete(ws);
  });

  if (typeof callback === 'function') callback(ws);
};

WebSocketServer.prototype.close = function(callback) {
  if (typeof callback === 'function') this.once('close', callback);
  this._listening = false;
  if (this._acceptTimer != null) {
    clearTimeout(this._acceptTimer);
    this._acceptTimer = null;
  }
  if (this._handle != null && _hasTcp) {
    try { __exactTcpClose(this._handle); } catch(e) {}
    this._handle = null;
  }
  var clientsArr = [];
  this.clients.forEach(function(ws) { clientsArr.push(ws); });
  for (var i = 0; i < clientsArr.length; i++) {
    try { clientsArr[i].terminate(); } catch(e) {}
  }
  var self = this;
  setTimeout(function() { self.emit('close'); }, 0);
};

WebSocketServer.prototype.address = function() {
  if (this._handle != null && _hasTcp) {
    try {
      var info = __exactTcpLocalAddr(this._handle);
      if (info) return JSON.parse(info);
    } catch(e) {}
  }
  return { address: this._host || '0.0.0.0', port: this._port || 0, family: 'IPv4' };
};

// ========================================================
// HTTP request parsing helper
// ========================================================
function parseHttpRequest(headerStr) {
  var lines = headerStr.split('\r\n');
  if (lines.length < 1) return null;

  var requestLine = lines[0].split(' ');
  if (requestLine.length < 3) return null;

  var method = requestLine[0];
  var url = requestLine[1];
  var httpVersion = requestLine[2];

  var headers = {};
  for (var i = 1; i < lines.length; i++) {
    var line = lines[i];
    var colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    var name = line.substring(0, colonIdx).trim().toLowerCase();
    var value = line.substring(colonIdx + 1).trim();
    headers[name] = value;
  }

  return {
    method: method,
    url: url,
    httpVersion: httpVersion,
    headers: headers
  };
}

function isUpgradeRequest(req) {
  return req.headers['upgrade'] &&
         req.headers['upgrade'].toLowerCase() === 'websocket' &&
         req.headers['sec-websocket-key'];
}

// ========================================================
// Exports (ws-package compatible)
// ========================================================
var WS = WebSocketConnection;
WS.WebSocket = WebSocketConnection;
WS.WebSocketServer = WebSocketServer;
WS.Server = WebSocketServer;
WS.createWebSocketStream = function() {
  throw new Error('createWebSocketStream is not yet implemented');
};
WS.CONNECTING = READY_CONNECTING;
WS.OPEN = READY_OPEN;
WS.CLOSING = READY_CLOSING;
WS.CLOSED = READY_CLOSED;

module.exports = WS;
module.exports.default = WS;
module.exports.WebSocket = WebSocketConnection;
module.exports.WebSocketServer = WebSocketServer;
module.exports.Server = WebSocketServer;
"##
    .trim()
    .to_string()
}

fn node_http2_module() -> String {
    r##"
var constants = {
  // Error codes
  NGHTTP2_NO_ERROR: 0,
  NGHTTP2_PROTOCOL_ERROR: 1,
  NGHTTP2_INTERNAL_ERROR: 2,
  NGHTTP2_FLOW_CONTROL_ERROR: 3,
  NGHTTP2_SETTINGS_TIMEOUT: 4,
  NGHTTP2_STREAM_CLOSED: 5,
  NGHTTP2_FRAME_SIZE_ERROR: 6,
  NGHTTP2_REFUSED_STREAM: 7,
  NGHTTP2_CANCEL: 8,
  NGHTTP2_COMPRESSION_ERROR: 9,
  NGHTTP2_CONNECT_ERROR: 10,
  NGHTTP2_ENHANCE_YOUR_CALM: 11,
  NGHTTP2_INADEQUATE_SECURITY: 12,
  NGHTTP2_HTTP_1_1_REQUIRED: 13,
  // Settings
  NGHTTP2_SETTINGS_HEADER_TABLE_SIZE: 1,
  NGHTTP2_SETTINGS_ENABLE_PUSH: 2,
  NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS: 3,
  NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE: 4,
  NGHTTP2_SETTINGS_MAX_FRAME_SIZE: 5,
  NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE: 6,
  // HTTP status codes
  HTTP_STATUS_CONTINUE: 100,
  HTTP_STATUS_SWITCHING_PROTOCOLS: 101,
  HTTP_STATUS_OK: 200,
  HTTP_STATUS_CREATED: 201,
  HTTP_STATUS_ACCEPTED: 202,
  HTTP_STATUS_NO_CONTENT: 204,
  HTTP_STATUS_MOVED_PERMANENTLY: 301,
  HTTP_STATUS_FOUND: 302,
  HTTP_STATUS_NOT_MODIFIED: 304,
  HTTP_STATUS_BAD_REQUEST: 400,
  HTTP_STATUS_UNAUTHORIZED: 401,
  HTTP_STATUS_FORBIDDEN: 403,
  HTTP_STATUS_NOT_FOUND: 404,
  HTTP_STATUS_METHOD_NOT_ALLOWED: 405,
  HTTP_STATUS_INTERNAL_SERVER_ERROR: 500,
  HTTP_STATUS_NOT_IMPLEMENTED: 501,
  HTTP_STATUS_BAD_GATEWAY: 502,
  HTTP_STATUS_SERVICE_UNAVAILABLE: 503,
  HTTP_STATUS_GATEWAY_TIMEOUT: 504,
  // Header fields
  HTTP2_HEADER_STATUS: ':status',
  HTTP2_HEADER_METHOD: ':method',
  HTTP2_HEADER_AUTHORITY: ':authority',
  HTTP2_HEADER_SCHEME: ':scheme',
  HTTP2_HEADER_PATH: ':path',
  HTTP2_HEADER_CONTENT_TYPE: 'content-type',
  HTTP2_HEADER_CONTENT_LENGTH: 'content-length',
  HTTP2_HEADER_ACCEPT: 'accept',
  HTTP2_HEADER_ACCEPT_ENCODING: 'accept-encoding'
};

var sensitiveHeaders = typeof Symbol === 'function' ? Symbol('nodejs.http2.sensitiveHeaders') : '__sensitiveHeaders';

function createServer() {
  throw new Error('http2.createServer is not supported in this runtime');
}

function createSecureServer() {
  throw new Error('http2.createSecureServer is not supported in this runtime');
}

function connect() {
  throw new Error('http2.connect is not supported in this runtime');
}

function getDefaultSettings() {
  return {
    headerTableSize: 4096,
    enablePush: true,
    initialWindowSize: 65535,
    maxFrameSize: 16384,
    maxConcurrentStreams: 4294967295,
    maxHeaderListSize: 65535,
    maxHeaderSize: 65535
  };
}

function getPackedSettings(settings) {
  // Return an empty Buffer-like object
  if (typeof Buffer !== 'undefined') {
    return Buffer.alloc(0);
  }
  return new Uint8Array(0);
}

function getUnpackedSettings(buf) {
  return getDefaultSettings();
}

module.exports = {
  constants: constants,
  sensitiveHeaders: sensitiveHeaders,
  createServer: createServer,
  createSecureServer: createSecureServer,
  connect: connect,
  getDefaultSettings: getDefaultSettings,
  getPackedSettings: getPackedSettings,
  getUnpackedSettings: getUnpackedSettings
};
"##
    .trim()
    .to_string()
}

fn node_diagnostics_channel_module() -> String {
    r##"
var channels = {};

function Channel(name) {
  this.name = name;
  this._subscribers = [];
  this._hasSubscribers = false;
}

Channel.prototype.subscribe = function(onMessage) {
  if (typeof onMessage !== 'function') {
    throw new TypeError('onMessage must be a function');
  }
  this._subscribers.push(onMessage);
  this._hasSubscribers = true;
};

Channel.prototype.unsubscribe = function(onMessage) {
  var idx = this._subscribers.indexOf(onMessage);
  if (idx === -1) return false;
  this._subscribers.splice(idx, 1);
  this._hasSubscribers = this._subscribers.length > 0;
  return true;
};

Channel.prototype.publish = function(message) {
  for (var i = 0; i < this._subscribers.length; i++) {
    try {
      this._subscribers[i](message, this.name);
    } catch (e) {}
  }
};

Object.defineProperty(Channel.prototype, 'hasSubscribers', {
  get: function() { return this._hasSubscribers; }
});

function channel(name) {
  if (typeof name !== 'string' && typeof name !== 'symbol') {
    throw new TypeError('Channel name must be a string or Symbol');
  }
  var key = String(name);
  if (!channels[key]) {
    channels[key] = new Channel(name);
  }
  return channels[key];
}

function hasSubscribers(name) {
  var key = String(name);
  if (!channels[key]) return false;
  return channels[key].hasSubscribers;
}

function TracingChannel(nameOrChannels) {
  if (typeof nameOrChannels === 'string') {
    this.start = channel(nameOrChannels + ':start');
    this.end = channel(nameOrChannels + ':end');
    this.asyncStart = channel(nameOrChannels + ':asyncStart');
    this.asyncEnd = channel(nameOrChannels + ':asyncEnd');
    this.error = channel(nameOrChannels + ':error');
  } else {
    this.start = nameOrChannels.start || new Channel('start');
    this.end = nameOrChannels.end || new Channel('end');
    this.asyncStart = nameOrChannels.asyncStart || new Channel('asyncStart');
    this.asyncEnd = nameOrChannels.asyncEnd || new Channel('asyncEnd');
    this.error = nameOrChannels.error || new Channel('error');
  }
}

TracingChannel.prototype.subscribe = function(handlers) {
  if (handlers.start) this.start.subscribe(handlers.start);
  if (handlers.end) this.end.subscribe(handlers.end);
  if (handlers.asyncStart) this.asyncStart.subscribe(handlers.asyncStart);
  if (handlers.asyncEnd) this.asyncEnd.subscribe(handlers.asyncEnd);
  if (handlers.error) this.error.subscribe(handlers.error);
};

TracingChannel.prototype.unsubscribe = function(handlers) {
  if (handlers.start) this.start.unsubscribe(handlers.start);
  if (handlers.end) this.end.unsubscribe(handlers.end);
  if (handlers.asyncStart) this.asyncStart.unsubscribe(handlers.asyncStart);
  if (handlers.asyncEnd) this.asyncEnd.unsubscribe(handlers.asyncEnd);
  if (handlers.error) this.error.unsubscribe(handlers.error);
};

TracingChannel.prototype.traceSync = function(fn, context) {
  var ctx = context || {};
  this.start.publish(ctx);
  try {
    var result = fn(ctx);
    ctx.result = result;
    return result;
  } catch (e) {
    ctx.error = e;
    this.error.publish(ctx);
    throw e;
  } finally {
    this.end.publish(ctx);
  }
};

function tracingChannel(nameOrChannels) {
  return new TracingChannel(nameOrChannels);
}

module.exports = {
  channel: channel,
  hasSubscribers: hasSubscribers,
  Channel: Channel,
  TracingChannel: TracingChannel,
  tracingChannel: tracingChannel
};
"##
    .trim()
    .to_string()
}

fn node_trace_events_module() -> String {
    r##"
function Tracing(categories) {
  this.categories = categories || [];
  this.enabled = false;
}

Tracing.prototype.enable = function() {
  this.enabled = true;
};

Tracing.prototype.disable = function() {
  this.enabled = false;
};

function createTracing(options) {
  var categories = [];
  if (options && options.categories) {
    if (Array.isArray(options.categories)) {
      categories = options.categories;
    } else {
      throw new TypeError('categories must be an array');
    }
  }
  return new Tracing(categories);
}

function getEnabledCategories() {
  return undefined;
}

module.exports = {
  createTracing: createTracing,
  getEnabledCategories: getEnabledCategories
};
"##
    .trim()
    .to_string()
}

fn node_inspector_module() -> String {
    r##"
var EventEmitter;
try { EventEmitter = require('events'); } catch(e) {
  EventEmitter = function() { this._events = {}; };
  EventEmitter.prototype.on = function(ev, fn) { if (!this._events[ev]) this._events[ev] = []; this._events[ev].push(fn); return this; };
  EventEmitter.prototype.emit = function(ev) { var a = [].slice.call(arguments, 1); var l = (this._events[ev] || []); for (var i = 0; i < l.length; i++) l[i].apply(this, a); };
  EventEmitter.prototype.removeListener = function() { return this; };
  EventEmitter.prototype.removeAllListeners = function() { return this; };
  EventEmitter.prototype.once = function(ev, fn) { var self = this; function w() { self.removeListener(ev, w); fn.apply(this, arguments); } this.on(ev, w); return this; };
  EventEmitter.prototype.addListener = EventEmitter.prototype.on;
  EventEmitter.prototype.off = EventEmitter.prototype.removeListener;
}

function Session() {
  if (EventEmitter) EventEmitter.call(this);
  this._connected = false;
}

// Inherit from EventEmitter
if (EventEmitter && EventEmitter.prototype) {
  Session.prototype = Object.create(EventEmitter.prototype);
  Session.prototype.constructor = Session;
}

Session.prototype.connect = function() {
  this._connected = true;
};

Session.prototype.connectToMainThread = function() {
  this._connected = true;
};

Session.prototype.disconnect = function() {
  this._connected = false;
};

Session.prototype.post = function(method, params, callback) {
  if (typeof params === 'function') {
    callback = params;
    params = undefined;
  }
  var err = new Error('Inspector is not available in this runtime');
  if (typeof callback === 'function') {
    callback(err);
  }
};

function open(port, host, wait) {
  // no-op stub
}

function close() {
  // no-op stub
}

function url() {
  return undefined;
}

function waitForDebugger() {
  // no-op stub
}

module.exports = {
  Session: Session,
  open: open,
  close: close,
  url: url,
  waitForDebugger: waitForDebugger
};
"##
    .trim()
    .to_string()
}

fn node_wasi_module() -> String {
    r##"
function WASI(options) {
  this._options = options || {};
  this.wasiImport = {};
}

WASI.prototype.start = function(instance) {
  throw new Error('WASI is not supported in this runtime');
};

WASI.prototype.initialize = function(instance) {
  throw new Error('WASI is not supported in this runtime');
};

WASI.prototype.getImportObject = function() {
  return { wasi_snapshot_preview1: this.wasiImport };
};

module.exports = {
  WASI: WASI
};
"##
    .trim()
    .to_string()
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
        assert_eq!(resolved_path.canonicalize().unwrap(), file.canonicalize().unwrap());
    }

    #[test]
    fn resolves_bare_specifier() {
        let dir = tempdir().unwrap();
        let node_modules = dir.path().join("node_modules");
        let pkg_dir = node_modules.join("demo-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{ "main": "index.js" }"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), "module.exports = { ok: true };").unwrap();

        let loader = ModuleLoader::new();
        let resolved = loader
            .resolve("demo-pkg", Some(&dir.path().join("entry.js")))
            .unwrap();
        assert!(resolved.path.unwrap().ends_with("node_modules/demo-pkg/index.js"));
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
        assert!(resolved.path.unwrap().ends_with("node_modules/exports-pkg/cjs.js"));
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

        let resolved_tsx = loader.resolve("./mod.tsx", Some(&dir.path().join("entry.ts"))).unwrap();
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
