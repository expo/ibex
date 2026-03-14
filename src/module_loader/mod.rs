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

#[path = "builtin_manifest.generated.rs"]
mod builtin_manifest_generated;

use builtin_manifest_generated::BUILTIN_MANIFEST_REGISTRATIONS;

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
struct BuiltinManifestRegistration {
    specifier: &'static str,
    source_key: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum BuiltinSource {
    ExactProcess,
    ExactCrypto,
    ExactClipboard,
    ExactHttp,
    ExactSqlite,
    Bun,
    BunTest,
    BunHarness,
    NodeHarness,
    BunJsc,
    BunInternalForTesting,
    NodeTestAlias,
    NodeFs,
    NodeFsPromises,
    NodePath,
    PathPosixAlias,
    PathWin32Alias,
    NodeEvents,
    NodeStream,
    LegacyStreamReadable,
    LegacyStreamWritable,
    LegacyStreamDuplex,
    LegacyStreamTransform,
    LegacyStreamPassthrough,
    NodeStreamConsumers,
    NodeStreamPromises,
    NodeBuffer,
    NodeUtil,
    UtilTypesAlias,
    NodeUtilTypesAlias,
    NodeTimers,
    NodeTimersPromises,
    NodeHttp,
    NodeHttps,
    NodeStreamWeb,
    NodeUrl,
    UrlAlias,
    NodeAssert,
    NodeOs,
    NodeTty,
    NodeStringDecoder,
    NodeQuerystring,
    NodePunycode,
    NodeChildProcess,
    NodeReadline,
    NodeModule,
    NodeZlib,
    NodeTls,
    NodeDns,
    NodeDnsPromises,
    InternalFsUtils,
    NodeNet,
    NodePerfHooks,
    NodeAsyncHooks,
    NodeWorkerThreads,
    NodeVm,
    NodeConsole,
    NodeCluster,
    NodeDgram,
    NodeDomain,
    NodeV8,
    NodeConstants,
    Ws,
    NodeHttp2,
    NodeDiagnosticsChannel,
    NodeTraceEvents,
    NodeInspector,
    NodeWasi,
}

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

    fn source_needs_loop_scope_downlevel(source: &str) -> bool {
        source.contains("for (let")
            || source.contains("for(let")
            || source.contains("for (const")
            || source.contains("for(const")
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

fn hash_cache_input_file<H: Hasher>(hasher: &mut H, path: &Path) -> Result<()> {
    path.hash(hasher);
    let bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read transpile cache input {}", path.display()))?;
    bytes.hash(hasher);
    Ok(())
}

fn module_cache_key(path: &Path, target: &str) -> Result<String> {
    let mut hasher = DefaultHasher::new();
    "loader-transpile-v8-pipeline-aware".hash(&mut hasher);
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
    let root = repo_root()?;
    hash_cache_input_file(
        &mut hasher,
        &root
            .join("js")
            .join("scripts")
            .join("transpile-typescript.mjs"),
    )?;
    hash_cache_input_file(
        &mut hasher,
        &root.join("js").join("scripts").join("transforms.mjs"),
    )?;
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

fn run_transpile_command(entry: &Path, output: &Path, target: &str) -> Result<()> {
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

impl BuiltinSource {
    fn from_key(source_key: &str) -> Option<Self> {
        Some(match source_key {
            "exact_process" => Self::ExactProcess,
            "exact_crypto" => Self::ExactCrypto,
            "exact_clipboard" => Self::ExactClipboard,
            "exact_http" => Self::ExactHttp,
            "exact_sqlite" => Self::ExactSqlite,
            "bun" => Self::Bun,
            "bun_test" => Self::BunTest,
            "bun_harness" => Self::BunHarness,
            "node_harness" => Self::NodeHarness,
            "bun_jsc" => Self::BunJsc,
            "bun_internal_for_testing" => Self::BunInternalForTesting,
            "node_test_alias" => Self::NodeTestAlias,
            "node_fs" => Self::NodeFs,
            "node_fs_promises" => Self::NodeFsPromises,
            "node_path" => Self::NodePath,
            "path_posix_alias" => Self::PathPosixAlias,
            "path_win32_alias" => Self::PathWin32Alias,
            "node_events" => Self::NodeEvents,
            "node_stream" => Self::NodeStream,
            "legacy_stream_readable" => Self::LegacyStreamReadable,
            "legacy_stream_writable" => Self::LegacyStreamWritable,
            "legacy_stream_duplex" => Self::LegacyStreamDuplex,
            "legacy_stream_transform" => Self::LegacyStreamTransform,
            "legacy_stream_passthrough" => Self::LegacyStreamPassthrough,
            "node_stream_consumers" => Self::NodeStreamConsumers,
            "node_stream_promises" => Self::NodeStreamPromises,
            "node_buffer" => Self::NodeBuffer,
            "node_util" => Self::NodeUtil,
            "util_types_alias" => Self::UtilTypesAlias,
            "node_util_types_alias" => Self::NodeUtilTypesAlias,
            "node_timers" => Self::NodeTimers,
            "node_timers_promises" => Self::NodeTimersPromises,
            "node_http" => Self::NodeHttp,
            "node_https" => Self::NodeHttps,
            "node_stream_web" => Self::NodeStreamWeb,
            "node_url" => Self::NodeUrl,
            "url_alias" => Self::UrlAlias,
            "node_assert" => Self::NodeAssert,
            "node_os" => Self::NodeOs,
            "node_tty" => Self::NodeTty,
            "node_string_decoder" => Self::NodeStringDecoder,
            "node_querystring" => Self::NodeQuerystring,
            "node_punycode" => Self::NodePunycode,
            "node_child_process" => Self::NodeChildProcess,
            "node_readline" => Self::NodeReadline,
            "node_module" => Self::NodeModule,
            "node_zlib" => Self::NodeZlib,
            "node_tls" => Self::NodeTls,
            "node_dns" => Self::NodeDns,
            "node_dns_promises" => Self::NodeDnsPromises,
            "internal_fs_utils" => Self::InternalFsUtils,
            "node_net" => Self::NodeNet,
            "node_perf_hooks" => Self::NodePerfHooks,
            "node_async_hooks" => Self::NodeAsyncHooks,
            "node_worker_threads" => Self::NodeWorkerThreads,
            "node_vm" => Self::NodeVm,
            "node_console" => Self::NodeConsole,
            "node_cluster" => Self::NodeCluster,
            "node_dgram" => Self::NodeDgram,
            "node_domain" => Self::NodeDomain,
            "node_v8" => Self::NodeV8,
            "node_constants" => Self::NodeConstants,
            "ws" => Self::Ws,
            "node_http2" => Self::NodeHttp2,
            "node_diagnostics_channel" => Self::NodeDiagnosticsChannel,
            "node_trace_events" => Self::NodeTraceEvents,
            "node_inspector" => Self::NodeInspector,
            "node_wasi" => Self::NodeWasi,
            _ => return None,
        })
    }
}

fn build_builtin_registry(
    registrations: &[BuiltinManifestRegistration],
) -> HashMap<String, String> {
    let mut builtins = HashMap::new();
    let mut source_cache: HashMap<BuiltinSource, String> = HashMap::new();

    for registration in registrations {
        let Some(source_key) = BuiltinSource::from_key(registration.source_key) else {
            eprintln!(
                "Skipping builtin manifest entry {} with unknown source key {}",
                registration.specifier, registration.source_key
            );
            continue;
        };
        let source = source_cache
            .entry(source_key)
            .or_insert_with(|| builtin_source(source_key))
            .clone();
        builtins.insert(registration.specifier.to_string(), source);
    }

    builtins
}

fn builtin_source(source: BuiltinSource) -> String {
    match source {
        BuiltinSource::ExactProcess => exact_process_module(),
        BuiltinSource::ExactCrypto => exact_crypto_module(),
        BuiltinSource::ExactClipboard => exact_clipboard_module(),
        BuiltinSource::ExactHttp => exact_http_module(),
        BuiltinSource::ExactSqlite => exact_sqlite_module(),
        BuiltinSource::Bun => bun_module(),
        BuiltinSource::BunTest => bun_test_module(),
        BuiltinSource::BunHarness => bun_harness_module(),
        BuiltinSource::NodeHarness => node_harness_module(),
        BuiltinSource::BunJsc => bun_jsc_module(),
        BuiltinSource::BunInternalForTesting => bun_internal_for_testing_module(),
        BuiltinSource::NodeTestAlias => node_test_alias_source(),
        BuiltinSource::NodeFs => node_fs_module(),
        BuiltinSource::NodeFsPromises => node_fs_promises_module(),
        BuiltinSource::NodePath => node_path_module(),
        BuiltinSource::PathPosixAlias => path_posix_alias_source(),
        BuiltinSource::PathWin32Alias => path_win32_alias_source(),
        BuiltinSource::NodeEvents => node_events_module(),
        BuiltinSource::NodeStream => node_stream_module(),
        BuiltinSource::LegacyStreamReadable => legacy_stream_readable_alias_source(),
        BuiltinSource::LegacyStreamWritable => legacy_stream_writable_alias_source(),
        BuiltinSource::LegacyStreamDuplex => legacy_stream_duplex_alias_source(),
        BuiltinSource::LegacyStreamTransform => legacy_stream_transform_alias_source(),
        BuiltinSource::LegacyStreamPassthrough => legacy_stream_passthrough_alias_source(),
        BuiltinSource::NodeStreamConsumers => node_stream_consumers_module(),
        BuiltinSource::NodeStreamPromises => node_stream_promises_module(),
        BuiltinSource::NodeBuffer => node_buffer_module(),
        BuiltinSource::NodeUtil => node_util_module(),
        BuiltinSource::UtilTypesAlias => util_types_alias_source(),
        BuiltinSource::NodeUtilTypesAlias => node_util_types_alias_source(),
        BuiltinSource::NodeTimers => node_timers_module(),
        BuiltinSource::NodeTimersPromises => node_timers_promises_module(),
        BuiltinSource::NodeHttp => node_http_module(),
        BuiltinSource::NodeHttps => node_https_module(),
        BuiltinSource::NodeStreamWeb => node_stream_web_module(),
        BuiltinSource::NodeUrl => node_url_module(),
        BuiltinSource::UrlAlias => url_alias_module(),
        BuiltinSource::NodeAssert => node_assert_module(),
        BuiltinSource::NodeOs => node_os_module(),
        BuiltinSource::NodeTty => node_tty_module(),
        BuiltinSource::NodeStringDecoder => node_string_decoder_module(),
        BuiltinSource::NodeQuerystring => node_querystring_module(),
        BuiltinSource::NodePunycode => node_punycode_module(),
        BuiltinSource::NodeChildProcess => node_child_process_module(),
        BuiltinSource::NodeReadline => node_readline_module(),
        BuiltinSource::NodeModule => node_module_module(),
        BuiltinSource::NodeZlib => node_zlib_module(),
        BuiltinSource::NodeTls => node_tls_module(),
        BuiltinSource::NodeDns => node_dns_module(),
        BuiltinSource::NodeDnsPromises => node_dns_promises_module(),
        BuiltinSource::InternalFsUtils => internal_fs_utils_module(),
        BuiltinSource::NodeNet => node_net_module(),
        BuiltinSource::NodePerfHooks => node_perf_hooks_module(),
        BuiltinSource::NodeAsyncHooks => node_async_hooks_module(),
        BuiltinSource::NodeWorkerThreads => node_worker_threads_module(),
        BuiltinSource::NodeVm => node_vm_module(),
        BuiltinSource::NodeConsole => node_console_module(),
        BuiltinSource::NodeCluster => node_cluster_module(),
        BuiltinSource::NodeDgram => node_dgram_module(),
        BuiltinSource::NodeDomain => node_domain_module(),
        BuiltinSource::NodeV8 => node_v8_module(),
        BuiltinSource::NodeConstants => node_constants_module(),
        BuiltinSource::Ws => ws_module(),
        BuiltinSource::NodeHttp2 => node_http2_module(),
        BuiltinSource::NodeDiagnosticsChannel => node_diagnostics_channel_module(),
        BuiltinSource::NodeTraceEvents => node_trace_events_module(),
        BuiltinSource::NodeInspector => node_inspector_module(),
        BuiltinSource::NodeWasi => node_wasi_module(),
    }
}

fn node_test_alias_source() -> String {
    "module.exports = require('test');".to_string()
}

fn path_posix_alias_source() -> String {
    "module.exports = require('path').posix;".to_string()
}

fn path_win32_alias_source() -> String {
    "module.exports = require('path').win32;".to_string()
}

fn legacy_stream_readable_alias_source() -> String {
    "module.exports = require('stream').Readable;".to_string()
}

fn legacy_stream_writable_alias_source() -> String {
    "module.exports = require('stream').Writable;".to_string()
}

fn legacy_stream_duplex_alias_source() -> String {
    "module.exports = require('stream').Duplex;".to_string()
}

fn legacy_stream_transform_alias_source() -> String {
    "module.exports = require('stream').Transform;".to_string()
}

fn legacy_stream_passthrough_alias_source() -> String {
    "module.exports = require('stream').PassThrough;".to_string()
}

fn util_types_alias_source() -> String {
    "module.exports = require('util').types;".to_string()
}

fn node_util_types_alias_source() -> String {
    "module.exports = require('node:util').types;".to_string()
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

fn node_https_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/https.js")).to_string()
}

fn node_url_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/url.js")).to_string()
}

fn url_alias_module() -> String {
    r#"
const nodeUrl = require('node:url');
const exported = {};
Object.defineProperties(exported, Object.getOwnPropertyDescriptors(nodeUrl));
module.exports = exported;
"#
    .trim()
    .to_string()
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

fn node_dns_promises_module() -> String {
    include_str!(concat!(env!("OUT_DIR"), "/builtins/dns-promises.js")).to_string()
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

function _invalidValueError(name, value, extra) {
  var received;
  if (value === null) {
    received = 'null';
  } else if (value === undefined) {
    received = 'undefined';
  } else if (typeof value === 'number') {
    received = 'type number (' + value + ')';
  } else if (value === '') {
    received = 'type string';
  } else {
    received = 'type ' + typeof value;
  }
  if (extra) {
    return new TypeError('The "' + name + '" argument ' + extra + '. Received ' + received);
  }
  return new TypeError('The "' + name + '" argument must be of type object. Received ' + received);
}

function _invalidArgType(name, value, expected, check) {
  var err = new TypeError('The "' + name + '" argument must be of type ' + expected + '. Received ' + (value === null ? 'null' : typeof value));
  err.code = 'ERR_INVALID_ARG_TYPE';
  if (check) throw err;
  return err;
}

function _invalidArgValue(name, value, reason) {
  var err = new TypeError('The "' + name + '" argument must be ' + reason + '. Received ' + (value === null ? 'null' : value));
  err.code = 'ERR_INVALID_ARG_VALUE';
  return err;
}

function _stringToInt(value) {
  return Number.parseInt(value, 10);
}

function _rangeError(name, value, min, max) {
  var err = new RangeError('The value of "' + name + '" is out of range. It must be ' + min + '. Received ' + value);
  err.code = 'ERR_OUT_OF_RANGE';
  return err;
}

function _validateOffsetLength(offset, length, byteLength, mode, maxLength) {
  if (!Number.isInteger(offset) || offset < 0) {
    throw _rangeError('offset', offset, '>= 0', offset);
  }
  if (!Number.isInteger(length) || length < 0) {
    throw _rangeError('length', length, '>= 0', length);
  }
  if (mode === 'write') {
    if (offset > byteLength) {
      var offsetErr = new RangeError('The value of "offset" is out of range. It must be <= ' + byteLength + '. Received ' + offset);
      offsetErr.code = 'ERR_OUT_OF_RANGE';
      throw offsetErr;
    }
  }
  if (length > maxLength) {
    var maxLenErr = new RangeError('The value of "length" is out of range. It must be <= ' + maxLength + '. Received ' + length);
    maxLenErr.code = 'ERR_OUT_OF_RANGE';
    throw maxLenErr;
  }
  var max = byteLength - offset;
  if (length > max) {
    var err = new RangeError('The value of "length" is out of range. It must be <= ' + max + '. Received ' + length);
    err.code = 'ERR_OUT_OF_RANGE';
    throw err;
  }
}

function validateOffsetLengthRead(offset, length, byteLength, lengthIsBigInt) {
  if (lengthIsBigInt !== undefined && lengthIsBigInt) {
    if (typeof offset === 'bigint' || typeof length === 'bigint') {
      offset = _stringToInt(offset);
      length = _stringToInt(length);
    }
  }
  _validateOffsetLength(offset, length, byteLength, 'read', (2 ** 31) - 1);
}

function validateOffsetLengthWrite(offset, length, byteLength, lengthIsBigInt) {
  if (lengthIsBigInt !== undefined && lengthIsBigInt) {
    if (typeof offset === 'bigint' || typeof length === 'bigint') {
      offset = _stringToInt(offset);
      length = _stringToInt(length);
    }
  }
  _validateOffsetLength(offset, length, byteLength, 'write', (2 ** 31) - 1);
}

function _validateOption(name, value, expectedType) {
  if (value === undefined) return;
  if (expectedType === 'boolean' && typeof value !== 'boolean') {
    var boolErr = new TypeError('The "options.' + name + '" property must be of type boolean. Received type ' + typeof value + '.');
    boolErr.code = 'ERR_INVALID_ARG_TYPE';
    throw boolErr;
  }
  if (expectedType === 'number' && (typeof value !== 'number' || !Number.isFinite(value))) {
    var rangeError = new RangeError('The value of "options.' + name + '" is out of range. Received ' + value);
    rangeError.code = 'ERR_OUT_OF_RANGE';
    throw rangeError;
  }
}

function validateRmdirOptions(options) {
  if (options === undefined) {
    return { retryDelay: 100, maxRetries: 0, recursive: false };
  }
  if (options === null || typeof options !== 'object') {
    var e = _invalidArgType('options', options, 'object');
    e.code = 'ERR_INVALID_ARG_TYPE';
    throw e;
  }
  if (options.recursive !== undefined) {
    _validateOption('recursive', options.recursive, 'boolean');
  }
  if (options.retryDelay !== undefined) {
    if (typeof options.retryDelay !== 'number' || !Number.isFinite(options.retryDelay) || options.retryDelay < 0) {
      var retryErr = new RangeError('The value of "options.retryDelay" is out of range. Received ' + options.retryDelay);
      retryErr.code = 'ERR_OUT_OF_RANGE';
      throw retryErr;
    }
  }
  if (options.maxRetries !== undefined) {
    if (typeof options.maxRetries !== 'number' || !Number.isFinite(options.maxRetries) || options.maxRetries < 0) {
      var maxErr = new RangeError('The value of "options.maxRetries" is out of range. Received ' + options.maxRetries);
      maxErr.code = 'ERR_OUT_OF_RANGE';
      throw maxErr;
    }
  }
  return {
    retryDelay: options.retryDelay === undefined ? 100 : options.retryDelay,
    maxRetries: options.maxRetries === undefined ? 0 : options.maxRetries,
    recursive: options.recursive === undefined ? false : options.recursive
  };
}

function validateRmOptionsSync(path, options) {
  var base = validateRmdirOptions(options);
  var force = options && options.force;
  if (options && options.force !== undefined) {
    _validateOption('force', options.force, 'boolean');
  }
  return {
    retryDelay: base.retryDelay,
    maxRetries: base.maxRetries,
    recursive: base.recursive,
    force: options && options.force !== undefined ? options.force : false
  };
}

function _validatePathLike(value, name) {
  if (typeof value === 'string' || Buffer.isBuffer(value)) return;
  if (value && typeof value === 'object' && typeof value.href === 'string' && value.protocol === 'file:') {
    return;
  }
  var err = new TypeError('The "' + name + '" argument must be of type string or an instance of Buffer. Received type ' + (value === null ? 'object' : typeof value) + ' (' + String(value) + ')');
  err.code = 'ERR_INVALID_ARG_TYPE';
  throw err;
}

function Dirent(name, parentPath, type) {
  this.name = name;
  this.path = parentPath;
  this.parentPath = parentPath;
  this._type = type;
}

Dirent.prototype.isFile = function() { return this._type === 1; };
Dirent.prototype.isDirectory = function() { return this._type === 2; };
Dirent.prototype.isSymbolicLink = function() { return this._type === 3; };
Dirent.prototype.isFIFO = function() { return this._type === 4; };
Dirent.prototype.isSocket = function() { return this._type === 5; };
Dirent.prototype.isCharacterDevice = function() { return this._type === 6; };
Dirent.prototype.isBlockDevice = function() { return this._type === 7; };

function getDirent(path, name, type, callback) {
  _validatePathLike(path, 'path');
  var dirent = new Dirent(name, path, type);
  if (callback) {
    callback(null, dirent);
    return null;
  }
  return dirent;
}

function getDirents(path, entries, callback) {
  _validatePathLike(path, 'path');
  var result = [];
  for (var i = 0; i < entries.length; i++) {
    var entry = entries[i];
    if (!entry || !entry.length) {
      continue;
    }
    result.push(getDirent(path, entry[0], entry[1]));
  }
  callback(null, result);
}

function stringToFlags(flags) {
  if (typeof flags !== 'string' || flags === '') {
    var err = new TypeError('The flags argument must be a valid flags string. Received ' + flags);
    err.code = 'ERR_INVALID_ARG_VALUE';
    throw err;
  }
  var hasPlus = flags.indexOf('+') !== -1;
  if (flags.indexOf('+') !== flags.lastIndexOf('+')) {
    throw _invalidArgValue('flags', flags, 'a valid flag string');
  }
  if (hasPlus && flags.indexOf('+') !== flags.length - 1) {
    throw _invalidArgValue('flags', flags, 'a valid flag string');
  }
  var flagChars = hasPlus ? flags.slice(0, -1) : flags;
  var hasSync = false;
  var hasExclusive = false;
  var modeFlags = '';
  for (var i = 0; i < flagChars.length; i++) {
    var ch = flagChars.charAt(i);
    if (ch === 's') {
      if (hasSync) throw _invalidArgValue('flags', flags, 'a valid flag string');
      hasSync = true;
    } else if (ch === 'x') {
      if (hasExclusive) throw _invalidArgValue('flags', flags, 'a valid flag string');
      hasExclusive = true;
    } else if (ch === 'r' || ch === 'w' || ch === 'a') {
      if (modeFlags.length >= 1) throw _invalidArgValue('flags', flags, 'a valid flag string');
      modeFlags = ch;
    } else {
      throw _invalidArgValue('flags', flags, 'a valid flag string');
    }
  }

  if (modeFlags.length !== 1) {
    throw _invalidArgValue('flags', flags, 'a valid flag string');
  }
  if (hasExclusive && modeFlags === 'r') {
    throw _invalidArgValue('flags', flags, 'a valid flag string');
  }
  var result = 0;
  if (modeFlags === 'r') {
    result = hasPlus ? 2 : 0;
  } else if (modeFlags === 'w') {
    result = 0x200 | 0x400 | 0x1;
  } else {
    result = 0x8 | 0x200 | 0x1;
  }
  if (hasPlus) {
    result = (result & ~0x1) | 0x2;
  }
  if (hasExclusive) result |= 0x800;
  if (hasSync) result |= 0x80;
  return result;
}

function BigIntStats(dev, mode, nlink, uid, gid, rdev, blksize, ino, size, blocks, atimeMs, mtimeMs, ctimeMs, birthtimeMs, atimeNs, mtimeNs, ctimeNs, birthtimeNs) {
  this.dev = BigInt(dev);
  this.mode = BigInt(mode);
  this.nlink = BigInt(nlink);
  this.uid = BigInt(uid);
  this.gid = BigInt(gid);
  this.rdev = BigInt(rdev);
  this.size = BigInt(size);
  this.blksize = BigInt(blksize);
  this.blocks = BigInt(blocks);
  this.atimeMs = BigInt(atimeMs);
  this.mtimeMs = BigInt(mtimeMs);
  this.ctimeMs = BigInt(ctimeMs);
  this.birthtimeMs = BigInt(birthtimeMs);
  this.atimeNs = BigInt(atimeNs || 0);
  this.mtimeNs = BigInt(mtimeNs || 0);
  this.ctimeNs = BigInt(ctimeNs || 0);
  this.birthtimeNs = BigInt(birthtimeNs || 0);
  this.atime = new Date(Number(this.atimeMs));
  this.mtime = new Date(Number(this.mtimeMs));
  this.ctime = new Date(Number(this.ctimeMs));
  this.birthtime = new Date(Number(this.birthtimeMs));
  this._isFile = (mode & 0o170000) === 0o100000;
  this._isDir = (mode & 0o170000) === 0o40000;
  this._isChrDev = (mode & 0o170000) === 0o20000;
  this._isBlkDev = (mode & 0o170000) === 0o60000;
  this._isFifo = (mode & 0o170000) === 0o10000;
  this._isSocket = (mode & 0o170000) === 0o140000;
  this._isSymlink = (mode & 0o170000) === 0o120000;
}
BigIntStats.prototype.isFile = function() { return this._isFile; };
BigIntStats.prototype.isDirectory = function() { return this._isDir; };
BigIntStats.prototype.isBlockDevice = function() { return this._isBlkDev; };
BigIntStats.prototype.isCharacterDevice = function() { return this._isChrDev; };
BigIntStats.prototype.isFIFO = function() { return this._isFifo; };
BigIntStats.prototype.isSocket = function() { return this._isSocket; };
BigIntStats.prototype.isSymbolicLink = function() { return this._isSymlink; };

function SyncWriteStream() {}
SyncWriteStream.prototype = {
  _write: function(chunk, encoding, cb) {
    if (cb && typeof cb === 'function') {
      cb();
    }
  }
};

module.exports = {
  isFd: isFd,
  isFileMode: isFileMode,
  validateFd: validateFd,
  toPathIfFileURL: toPathIfFileURL,
  stringToFlags: stringToFlags,
  validateOffsetLengthRead: validateOffsetLengthRead,
  validateOffsetLengthWrite: validateOffsetLengthWrite,
  validateRmdirOptions: validateRmdirOptions,
  validateRmOptionsSync: validateRmOptionsSync,
  getDirents: getDirents,
  getDirent: getDirent,
  BigIntStats: BigIntStats,
  SyncWriteStream: SyncWriteStream,
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
