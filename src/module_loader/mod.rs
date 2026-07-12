//! Module loader for ESM and CommonJS.
//!
//! This provides a minimal resolver and loader with `exact:` builtins.
//! Node-style package resolution and full ESM/CJS interop are implemented
//! incrementally (see TODOs).

pub mod transpile;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oxc_resolver::{ModuleType, ResolveOptions, Resolver};
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use sha2::{Digest as _, Sha256};

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
    /// Package selector reported by resolver/package metadata, not inferred by
    /// the JS loader from the resolved path. `None` means first-party/root or
    /// an unclassified local path.
    pub package_name: Option<String>,
    /// Canonical package root for propagating a package classification across
    /// relative imports inside a linked/realpathed dependency.
    pub package_root: Option<PathBuf>,
    /// The self-reported `version` field of the resolved module's own nearest
    /// `package.json` when the module lives under `node_modules`, else `None`.
    /// Combined with the resolver/path-derived package **name** by the loader
    /// into `name@version`, so coexisting versions of one package get distinct
    /// principals/compartments and a `name@version` policy selector can pin a
    /// specific installed version. This is not an integrity boundary against a
    /// malicious package that forges its manifest version; authoritative identity
    /// would need lockfile/integrity input. @ref LLP 0013#resolved-questions
    /// (ENG-22621/ENG-22768)
    pub package_version: Option<String>,
    /// Integrity authenticated by the armed package graph. The generic
    /// resolver leaves this unset; `Host::resolve_module_meta` fills it only
    /// after matching the exact verified package-root binding.
    pub package_integrity: Option<String>,
}

pub struct ModuleLoader {
    builtins: HashMap<String, String>,
    resolver: Resolver,
    /// Memoized `version` per package root dir (the nearest `package.json`), so
    /// version derivation is one read per package, not per module. (ENG-22621)
    package_versions: std::sync::RwLock<HashMap<PathBuf, Option<String>>>,
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
            package_versions: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// The `version` of the package that owns `path`, when `path` is under a
    /// `node_modules` tree — read from the nearest enclosing `package.json` and
    /// memoized per package root. `None` for first-party/workspace code (no
    /// `node_modules` ancestor) or a manifest with no `version`. The resolver
    /// metadata/path is authoritative for the package name; the version is
    /// self-reported and only distinguishes coexisting installed copies.
    /// Version-pinned selectors are therefore convenience/precision, not a trust
    /// boundary against a malicious package forging its package.json.
    /// @ref LLP 0013#resolved-questions — ENG-22621/ENG-22768
    fn package_version_for(&self, path: &Path) -> Option<String> {
        // Read the version from the package's OWN root (`node_modules/<name>`,
        // the same segment the loader derives the package NAME from), NOT the
        // nearest enclosing package.json: a package commonly ships a nested,
        // versionless `package.json` (e.g. `dist/package.json` with
        // `{"type":"module"}`, or subpath-exports dirs), and walking to the
        // nearest one would read that versionless manifest and silently degrade
        // the identity to the bare name — disabling version pinning for those
        // packages. (ENG-22621)
        let root = package_root_in_node_modules(path)?;
        if let Ok(memo) = self.package_versions.read() {
            if let Some(v) = memo.get(&root) {
                return v.clone();
            }
        }
        let version = read_package_manifest(&root.join("package.json"))
            .ok()
            .and_then(|m| m.get("version").and_then(Value::as_str).map(str::to_string));
        if let Ok(mut memo) = self.package_versions.write() {
            memo.insert(root, version.clone());
        }
        version
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
                package_name: None,
                package_root: None,
                package_version: None,
                package_integrity: None,
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

    pub(crate) fn is_builtin_specifier(&self, specifier: &str) -> bool {
        self.builtins.contains_key(specifier.trim())
    }

    /// Resolve a bare package request from the one package root authenticated
    /// by the armed graph. Starting ordinary Node resolution at the requester's
    /// directory would still probe ambient `node_modules` trees before the
    /// post-resolution owner check. Package-self resolution keeps `exports`
    /// semantics while anchoring every permitted lookup at `package_root`; the
    /// legacy `main`/subpath case is rewritten to an exact relative lookup.
    /// @ref LLP 0021#decision-staging-and-principal-semantics
    pub(crate) fn resolve_meta_from_bound_package(
        &self,
        specifier: &str,
        package_name: &str,
        package_root: &Path,
    ) -> Result<ResolvedModule> {
        let specifier = specifier.trim();
        let requested_name = package_name_from_bare_specifier(specifier)
            .ok_or_else(|| anyhow!("bound package resolution requires a bare specifier"))?;
        if requested_name != package_name {
            return Err(anyhow!("bound package name differs from requested package"));
        }

        let manifest = read_package_manifest(&package_root.join("package.json"))?;
        if manifest.get("name").and_then(Value::as_str) != Some(package_name) {
            return Err(anyhow!(
                "authenticated package manifest name differs from its principal"
            ));
        }

        let suffix = specifier
            .strip_prefix(package_name)
            .ok_or_else(|| anyhow!("bound package prefix is absent"))?;
        if !suffix.is_empty() && !suffix.starts_with('/') {
            return Err(anyhow!("invalid package subpath"));
        }
        if suffix
            .split('/')
            .any(|component| component == "." || component == "..")
        {
            return Err(anyhow!("package subpath contains traversal components"));
        }

        // A package with `exports` must go through OXC's PACKAGE_SELF path so
        // private subpaths remain private. Without `exports`, an exact relative
        // request preserves `main`/index and extension behavior without ever
        // starting an ambient node_modules search.
        let anchored_specifier = if manifest
            .get("exports")
            .is_some_and(|value| !value.is_null())
        {
            specifier.to_owned()
        } else if suffix.is_empty() {
            ".".to_owned()
        } else {
            format!(".{suffix}")
        };
        let mut resolved = self.resolve_with_oxc_at(&anchored_specifier, package_root, false)?;
        resolved.package_name = Some(package_name.to_owned());
        resolved.package_root = Some(package_root.to_path_buf());
        resolved.package_version = manifest
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(resolved)
    }

    fn resolve_package_import(&self, specifier: &str, referrer: &Path) -> Option<ResolvedModule> {
        let package_root = find_package_root(referrer)?;
        let manifest_path = package_root.join("package.json");
        let manifest = read_package_manifest(&manifest_path).ok()?;
        let imports = manifest.get("imports")?.as_object()?;

        let raw_target = resolve_package_import_target(specifier, imports)?;
        let target_path = normalize_import_target(&package_root, package_root.join(raw_target))?;

        let (package_name, package_root_from_path) =
            package_name_and_root_in_node_modules(&target_path).unzip();
        let package_root_for_record = package_root_from_path.or_else(|| Some(package_root.clone()));
        let package_version = self.package_version_for(&target_path);
        Some(ResolvedModule {
            id: target_path.to_string_lossy().to_string(),
            kind: module_kind_from_path(&target_path),
            path: Some(target_path),
            source: None,
            package_name,
            package_root: package_root_for_record,
            package_version,
            package_integrity: None,
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

    /// Compile source bytes that were captured while authenticating the
    /// package tree. Armed package loads must not reopen the pathname after
    /// integrity validation: a replacement in that gap would execute bytes
    /// that never contributed to the authenticated principal digest.
    pub(crate) fn load_source_bytes(
        &self,
        mut module: ResolvedModule,
        bytes: Vec<u8>,
    ) -> Result<ResolvedModule> {
        let path = module
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("Module path missing"))?;
        let source = String::from_utf8(bytes)
            .with_context(|| format!("Module source is not valid UTF-8: {}", path.display()))?;
        let source = if Self::needs_transpile(path) || Self::needs_js_downlevel(path, &source) {
            let target = Self::transpile_target_for_source(&source);
            self.transpile_module(path, target, &source)?
        } else {
            source
        };
        // Discard any resolver prefetch: only the bytes captured by the
        // integrity traversal are eligible for execution.
        module.source = Some(source);
        Ok(module)
    }

    fn load_module_source(&self, path: &Path) -> Result<String> {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read module {}", path.display()))?;
        if Self::needs_transpile(path) || Self::needs_js_downlevel(path, &source) {
            let target = Self::transpile_target_for_source(&source);
            return self.transpile_module(path, target, &source);
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
        // Runtime bundler outputs are already lowered for Hermes. Re-parsing
        // their script/IIFE wrapper as a module can reject legal top-level
        // `return` statements before the generated entry is ever evaluated.
        if path.file_name().and_then(OsStr::to_str) == Some("bundle.js")
            || path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.ends_with(".bundle.js"))
        {
            return false;
        }
        path.extension()
            .and_then(OsStr::to_str)
            .map(|ext| matches!(ext, "js" | "mjs" | "cjs"))
            .unwrap_or(false)
            && Self::source_needs_downlevel(source)
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

    fn transpile_module(&self, path: &Path, target: &str, source: &str) -> Result<String> {
        let cache_key = module_cache_key(path, target)?;
        // `transpile_cache_dir` is memoized and already created+probed the
        // directory once per process, so we don't re-`create_dir_all` here on
        // every (mostly cache-hit) module load. A cache miss recreates the
        // parent inside `run_transpile_command` before writing.
        let cache_dir = transpile_cache_dir()?;

        let output = cache_dir.join(format!("{cache_key}.js"));
        if should_rebuild_output(path, &output)? {
            run_transpile_command(path, &output, target, source)?;
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

        self.resolve_with_oxc_at(specifier, &base_dir, true)
    }

    fn resolve_with_oxc_at(
        &self,
        specifier: &str,
        base_dir: &Path,
        retry_bare_as_relative: bool,
    ) -> Result<ResolvedModule> {
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
                let path_like = retry_bare_as_relative
                    && !specifier.starts_with('.')
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

        let full_path = resolution.full_path().to_path_buf();
        let mut kind = match resolution.module_type() {
            Some(ModuleType::Module) => ModuleKind::Esm,
            Some(ModuleType::CommonJs) => ModuleKind::CommonJs,
            Some(ModuleType::Json) => ModuleKind::Json,
            Some(ModuleType::Wasm) | Some(ModuleType::Addon) => ModuleKind::CommonJs,
            None => ModuleKind::CommonJs,
        };
        // Force JSON kind for .json files regardless of what OXC reports,
        // so they get parsed with JSON.parse() instead of new Function().
        if full_path.extension().and_then(|e| e.to_str()) == Some("json") {
            kind = ModuleKind::Json;
        }
        // Classify an ESM candidate with a SINGLE source read and reuse it.
        // A TS/JSX module is detected by extension (no read) and served as CJS.
        // Otherwise read the source once: a module that needs JS downleveling
        // flips to CJS and is (re)read by the transpile path; a plain ESM module
        // is served verbatim, so we stash the source we already read on the
        // resolved module and let `load_source` skip the redundant second read
        // and downlevel re-scan on the hot path (modern ESM-heavy node_modules).
        let mut prefetched_source: Option<String> = None;
        if kind == ModuleKind::Esm {
            if Self::needs_transpile(&full_path) {
                kind = ModuleKind::CommonJs;
            } else if let Ok(source) = std::fs::read_to_string(&full_path) {
                if Self::needs_js_downlevel(&full_path, &source) {
                    kind = ModuleKind::CommonJs;
                } else {
                    prefetched_source = Some(source);
                }
            }
        }

        let (mut package_name, mut package_root) =
            package_name_and_root_in_node_modules(&full_path).unzip();
        let mut package_version = self.package_version_for(&full_path);
        if let Some(pkg) = resolution.package_json() {
            let resolved_package_root = pkg.directory().to_path_buf();
            if package_name.is_none() {
                let requested = package_name_from_bare_specifier(specifier);
                if let Some(requested_name) = requested {
                    if pkg.name() == Some(requested_name.as_str()) {
                        package_name = Some(requested_name);
                    }
                }
                package_root = Some(resolved_package_root.clone());
            }
            if package_root.is_none() {
                package_root = Some(resolved_package_root);
            }
            if package_version.is_none() {
                package_version = pkg.version().map(str::to_string);
            }
        }
        Ok(ResolvedModule {
            id: full_path.to_string_lossy().to_string(),
            kind,
            path: Some(full_path),
            source: prefetched_source,
            package_name,
            package_root,
            package_version,
            package_integrity: None,
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

/// Hash the complete installed package content tree using the same record
/// format as the policy generator. Nested `node_modules` and VCS metadata are
/// separate graph/store state; symlinks and special files are rejected rather
/// than allowing content identity to escape the authenticated root.
/// @ref LLP 0021#decision-staging-and-principal-semantics
pub fn package_tree_integrity(root: &Path) -> Result<String> {
    package_tree_integrity_and_source(root, None, None).map(|(integrity, _)| integrity)
}

#[cfg(test)]
static PACKAGE_SOURCE_OPEN_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<(PathBuf, std::sync::Arc<std::sync::Barrier>)>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static PACKAGE_ROOT_OPEN_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<(PathBuf, std::sync::Arc<std::sync::Barrier>)>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static PACKAGE_INVENTORY_PASS_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<(PathBuf, std::sync::Arc<std::sync::Barrier>)>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn pause_before_authenticated_source_open(path: &Path) {
    let hook = PACKAGE_SOURCE_OPEN_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()
        .and_then(|hook| hook.as_ref().cloned());
    if let Some((target, barrier)) = hook {
        if target == path {
            barrier.wait();
            barrier.wait();
        }
    }
}

#[cfg(test)]
fn pause_package_hook(
    hook: &std::sync::OnceLock<
        std::sync::Mutex<Option<(PathBuf, std::sync::Arc<std::sync::Barrier>)>>,
    >,
    path: &Path,
) {
    let hook = hook
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()
        .and_then(|hook| hook.as_ref().cloned());
    if let Some((target, barrier)) = hook {
        if target == path {
            barrier.wait();
            barrier.wait();
        }
    }
}

fn package_tree_integrity_and_source(
    root: &Path,
    source_path: Option<&Path>,
    expected_root: Option<&capsec_semantics::model::ObjectIdentity>,
) -> Result<(String, Option<Vec<u8>>)> {
    #[cfg(unix)]
    {
        package_tree_integrity_and_source_unix(root, source_path, expected_root)
    }
    #[cfg(not(unix))]
    {
        if expected_root.is_some() {
            anyhow::bail!(
                "armed package source authentication requires a root-relative object handle on this target"
            );
        }
        package_tree_integrity_and_source_path(root, source_path)
    }
}

#[cfg(unix)]
fn package_tree_integrity_and_source_unix(
    root: &Path,
    source_path: Option<&Path>,
    expected_root: Option<&capsec_semantics::model::ObjectIdentity>,
) -> Result<(String, Option<Vec<u8>>)> {
    use std::ffi::{CStr, CString};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DirectoryStamp {
        device: u64,
        inode: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    fn stamp(metadata: &std::fs::Metadata) -> DirectoryStamp {
        DirectoryStamp {
            device: metadata.dev(),
            inode: metadata.ino(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    fn object_identity(
        metadata: &std::fs::Metadata,
    ) -> Result<capsec_semantics::model::ObjectIdentity> {
        use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};
        Ok(ObjectIdentity {
            platform: if cfg!(any(target_os = "macos", target_os = "ios")) {
                ObjectPlatform::Apple
            } else if cfg!(target_os = "android") {
                ObjectPlatform::Android
            } else {
                ObjectPlatform::Unix
            },
            volume: NonEmptyString::new(format!("dev:{}", metadata.dev()))
                .map_err(anyhow::Error::msg)?,
            file: NonEmptyString::new(format!("ino:{}", metadata.ino()))
                .map_err(anyhow::Error::msg)?,
        })
    }

    fn directory_names(fd: RawFd) -> Result<Vec<Vec<u8>>> {
        let dot = b".\0";
        let enumeration_fd = unsafe {
            libc::openat(
                fd,
                dot.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if enumeration_fd < 0 {
            return Err(std::io::Error::last_os_error()).context("opening package directory");
        }
        let directory = unsafe { libc::fdopendir(enumeration_fd) };
        if directory.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(enumeration_fd) };
            return Err(error).context("enumerating package directory");
        }
        let mut names = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if matches!(name, b"." | b".." | b"node_modules" | b".git") {
                continue;
            }
            names.push(name.to_vec());
        }
        unsafe { libc::closedir(directory) };
        names.sort();
        Ok(names)
    }

    fn walk(
        root: &Path,
        directory_fd: RawFd,
        relative_directory: &Path,
        source_relative: Option<&Path>,
        capture_source: bool,
        records: &mut Vec<(String, String)>,
        captured_source: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        let before_fd = unsafe { libc::dup(directory_fd) };
        if before_fd < 0 {
            return Err(std::io::Error::last_os_error()).context("pinning package directory");
        }
        let before = unsafe { std::fs::File::from_raw_fd(before_fd) };
        let before_stamp = stamp(&before.metadata()?);
        drop(before);
        let names = directory_names(directory_fd)?;
        for name in names {
            let relative_path = relative_directory.join(std::ffi::OsString::from_vec(name.clone()));
            let capture =
                capture_source && source_relative.is_some_and(|source| source == relative_path);
            #[cfg(test)]
            if capture {
                pause_before_authenticated_source_open(&root.join(&relative_path));
            }
            let c_name = CString::new(name.clone())?;
            let fd = unsafe {
                libc::openat(
                    directory_fd,
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "package entry changed while opening {}",
                        root.join(relative_directory)
                            .join(std::ffi::OsString::from_vec(name.clone()))
                            .display()
                    )
                });
            }
            let mut opened = unsafe { std::fs::File::from_raw_fd(fd) };
            let metadata_before = opened.metadata()?;
            let relative = relative_path
                .to_str()
                .ok_or_else(|| {
                    anyhow!(
                        "Package path is not valid UTF-8: {}",
                        relative_path.display()
                    )
                })?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if metadata_before.is_dir() {
                walk(
                    root,
                    opened.as_raw_fd(),
                    &relative_path,
                    source_relative,
                    capture_source,
                    records,
                    captured_source,
                )?;
            } else if metadata_before.is_file() {
                let mut digest = Sha256::new();
                let mut bytes = capture.then(Vec::new);
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let read = opened.read(&mut buffer).with_context(|| {
                        format!("Failed to read package file {}", relative_path.display())
                    })?;
                    if read == 0 {
                        break;
                    }
                    digest.update(&buffer[..read]);
                    if let Some(captured) = bytes.as_mut() {
                        captured.extend_from_slice(&buffer[..read]);
                    }
                }
                let metadata_after = opened.metadata()?;
                if stamp(&metadata_before) != stamp(&metadata_after)
                    || metadata_before.len() != metadata_after.len()
                {
                    return Err(anyhow!(
                        "Package file changed while authenticating {}",
                        relative_path.display()
                    ));
                }
                if let Some(bytes) = bytes {
                    if captured_source.replace(bytes).is_some() {
                        return Err(anyhow!("Package source appeared more than once"));
                    }
                }
                records.push((
                    relative,
                    format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest.finalize())),
                ));
            } else {
                return Err(anyhow!(
                    "Package content contains a symlink or unsupported file type: {relative}"
                ));
            }
        }
        let after_metadata = unsafe {
            let duplicate = libc::dup(directory_fd);
            if duplicate < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("revalidating package directory");
            }
            std::fs::File::from_raw_fd(duplicate)
        }
        .metadata()?;
        if stamp(&after_metadata) != before_stamp {
            return Err(anyhow!(
                "Package directory changed while authenticating {}",
                root.join(relative_directory).display()
            ));
        }
        Ok(())
    }

    let root = std::fs::canonicalize(root)
        .with_context(|| format!("Failed to canonicalize package root {}", root.display()))?;
    let source_relative = source_path
        .map(|source| {
            let normalized = match (source.parent(), source.file_name()) {
                (Some(parent), Some(name)) => std::fs::canonicalize(parent)
                    .map(|parent| parent.join(name))
                    .with_context(|| {
                        format!("Failed to authenticate module parent {}", parent.display())
                    })?,
                _ => source.to_path_buf(),
            };
            normalized
                .strip_prefix(&root)
                .map(Path::to_path_buf)
                .with_context(|| {
                    format!(
                        "Authenticated module source {} is outside package root {}",
                        source.display(),
                        root.display()
                    )
                })
        })
        .transpose()?;
    if source_relative.as_ref().is_some_and(|path| {
        path.components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    }) {
        return Err(anyhow!(
            "Authenticated package source is not a relative file path"
        ));
    }

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW);
    #[cfg(test)]
    pause_package_hook(&PACKAGE_ROOT_OPEN_HOOK, &root);
    let root_handle = options
        .open(&root)
        .with_context(|| format!("Failed to pin package root {}", root.display()))?;
    let root_metadata = root_handle.metadata()?;
    if let Some(expected) = expected_root {
        if object_identity(&root_metadata)? != *expected {
            return Err(anyhow!(
                "Authenticated package root object changed before traversal: {}",
                root.display()
            ));
        }
    }

    let inventory = |capture_source: bool| -> Result<(Vec<(String, String)>, Option<Vec<u8>>)> {
        let mut records = Vec::new();
        let mut captured = None;
        walk(
            &root,
            root_handle.as_raw_fd(),
            Path::new(""),
            source_relative.as_deref(),
            capture_source,
            &mut records,
            &mut captured,
        )?;
        records.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        Ok((records, captured))
    };
    let (first, _) = inventory(false)?;
    #[cfg(test)]
    pause_package_hook(&PACKAGE_INVENTORY_PASS_HOOK, &root);
    let (second, captured_source) = inventory(source_relative.is_some())?;
    if first != second {
        return Err(anyhow!(
            "Package content changed between authenticated inventory passes"
        ));
    }
    if source_relative.is_some() && captured_source.is_none() {
        return Err(anyhow!(
            "Authenticated module source disappeared during package traversal"
        ));
    }
    let bytes = serde_json::to_vec(&second)?;
    Ok((
        format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))),
        captured_source,
    ))
}

/// Authenticate the complete package tree and optionally retain the exact
/// bytes of one source file from the same pinned file handle that contributed
/// its digest record.
#[cfg(not(unix))]
fn package_tree_integrity_and_source_path(
    root: &Path,
    source_path: Option<&Path>,
) -> Result<(String, Option<Vec<u8>>)> {
    fn digest_file(path: &Path, capture: bool) -> Result<(String, Option<Vec<u8>>)> {
        #[cfg(test)]
        if capture {
            pause_before_authenticated_source_open(path);
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_FLAG_OPEN_REPARSE_POINT: inspect the named object rather
            // than following a late replacement to an unauthenticated target.
            options.custom_flags(0x0020_0000);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("Failed to open package file {}", path.display()))?;
        if !file.metadata()?.is_file() {
            return Err(anyhow!(
                "Package content changed to a non-file while authenticating {}",
                path.display()
            ));
        }
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut captured = capture.then(Vec::new);
        loop {
            let read = file
                .read(&mut buffer)
                .with_context(|| format!("Failed to read package file {}", path.display()))?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
            if let Some(bytes) = captured.as_mut() {
                bytes.extend_from_slice(&buffer[..read]);
            }
        }
        Ok((
            format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest.finalize())),
            captured,
        ))
    }

    fn walk(
        root: &Path,
        current: &Path,
        source_relative: Option<&Path>,
        records: &mut Vec<(String, String)>,
        captured_source: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        let mut entries = std::fs::read_dir(current)
            .with_context(|| {
                format!(
                    "Failed to enumerate package directory {}",
                    current.display()
                )
            })?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
        for entry in entries {
            let name = entry.file_name();
            if name == OsStr::new("node_modules") || name == OsStr::new(".git") {
                continue;
            }
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            let relative_path = path
                .strip_prefix(root)
                .expect("walk stays below package root");
            let relative = relative_path
                .to_str()
                .ok_or_else(|| {
                    anyhow!(
                        "Package path is not valid UTF-8: {}",
                        relative_path.display()
                    )
                })?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "Package content contains an unauthenticated symlink: {relative}"
                ));
            }
            if metadata.is_dir() {
                walk(root, &path, source_relative, records, captured_source)?;
            } else if metadata.is_file() {
                let capture = source_relative.is_some_and(|source| source == relative_path);
                let (digest, bytes) = digest_file(&path, capture)?;
                if let Some(bytes) = bytes {
                    if captured_source.replace(bytes).is_some() {
                        return Err(anyhow!("Package source appeared more than once"));
                    }
                }
                records.push((relative, digest));
            } else {
                return Err(anyhow!(
                    "Package content contains an unsupported file type: {relative}"
                ));
            }
        }
        Ok(())
    }

    let root = std::fs::canonicalize(root)
        .with_context(|| format!("Failed to canonicalize package root {}", root.display()))?;
    let source_relative = source_path
        .map(|source| {
            let normalized = match (source.parent(), source.file_name()) {
                (Some(parent), Some(name)) => std::fs::canonicalize(parent)
                    .map(|parent| parent.join(name))
                    .with_context(|| {
                        format!("Failed to authenticate module parent {}", parent.display())
                    })?,
                _ => source.to_path_buf(),
            };
            normalized
                .strip_prefix(&root)
                .map(Path::to_path_buf)
                .with_context(|| {
                    format!(
                        "Authenticated module source {} is outside package root {}",
                        source.display(),
                        root.display()
                    )
                })
        })
        .transpose()?;
    let mut records = Vec::new();
    let mut captured_source = None;
    walk(
        &root,
        &root,
        source_relative.as_deref(),
        &mut records,
        &mut captured_source,
    )?;
    if source_relative.is_some() && captured_source.is_none() {
        return Err(anyhow!(
            "Authenticated module source disappeared during package traversal"
        ));
    }
    records.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let bytes = serde_json::to_vec(&records)?;
    Ok((
        format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))),
        captured_source,
    ))
}

pub(crate) fn authenticated_package_source(
    root: &Path,
    source_path: &Path,
    expected_integrity: &str,
    expected_root: &capsec_semantics::model::ObjectIdentity,
) -> Result<Vec<u8>> {
    let (actual, source) =
        package_tree_integrity_and_source(root, Some(source_path), Some(expected_root))?;
    if actual != expected_integrity {
        return Err(anyhow!(
            "Installed package content changed after arming: expected {expected_integrity}, observed {actual}"
        ));
    }
    source.ok_or_else(|| anyhow!("Authenticated package source is absent"))
}

/// The installed package root for a module path: the `node_modules/<name>`
/// prefix (two segments for an `@scope/name`), using the LAST `node_modules`
/// segment so nested and pnpm layouts resolve to the package that actually owns
/// the file. Returns `None` for first-party code (no `node_modules` ancestor).
/// Mirrors the loader's `packageNameFromPath` so the version manifest agrees
/// with the derived package name. (ENG-22621)
fn package_root_in_node_modules(path: &Path) -> Option<PathBuf> {
    package_name_and_root_in_node_modules(path).map(|(_, root)| root)
}

fn package_name_and_root_in_node_modules(path: &Path) -> Option<(String, PathBuf)> {
    let comps: Vec<Component> = path.components().collect();
    let nm_idx = comps
        .iter()
        .rposition(|c| c.as_os_str() == OsStr::new("node_modules"))?;
    let name_start = nm_idx + 1;
    let first = comps.get(name_start)?;
    let scoped = first.as_os_str().to_string_lossy().starts_with('@');
    let end = if scoped {
        name_start + 2
    } else {
        name_start + 1
    };
    if end > comps.len() {
        return None; // `node_modules/@scope` with no name segment
    }
    let name = if scoped {
        format!(
            "{}/{}",
            first.as_os_str().to_string_lossy(),
            comps.get(name_start + 1)?.as_os_str().to_string_lossy()
        )
    } else {
        first.as_os_str().to_string_lossy().to_string()
    };
    Some((name, comps[..end].iter().collect()))
}

fn package_name_from_bare_specifier(specifier: &str) -> Option<String> {
    if specifier.is_empty()
        || specifier.starts_with('.')
        || specifier.starts_with('/')
        || specifier.starts_with('#')
        || Path::new(specifier).is_absolute()
    {
        return None;
    }
    let mut parts = specifier.split('/');
    let first = parts.next()?;
    if first.starts_with('@') {
        let second = parts.next()?;
        return Some(format!("{first}/{second}"));
    }
    Some(first.to_string())
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
            // This loader runs CommonJS `require()`; among CJS-compatible
            // conditions, `default` remains the lowest-priority fallback.
            for condition in ["node", "require", "import", "default"] {
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

    // Among subpath patterns, Node selects the most specific match: the one
    // with the longest prefix (the portion before `*`) that the specifier
    // starts with. The serde_json map here is not insertion-ordered
    // (`preserve_order` is off, so keys iterate alphabetically), so we must
    // rank explicitly rather than returning the first hit.
    let mut best: Option<(&str, &Value)> = None;
    for (key, value) in imports {
        // Only `#foo/*`-style subpath patterns participate. Keep the trailing
        // slash in the prefix so `#internal/*` matches `#internal/thing` but
        // NOT the sibling specifier `#internal-utils`.
        if !key.ends_with("/*") {
            continue;
        }
        let prefix = &key[..key.len() - 1];
        if !specifier.starts_with(prefix) {
            continue;
        }
        if best.is_none_or(|(best_prefix, _)| prefix.len() > best_prefix.len()) {
            best = Some((prefix, value));
        }
    }

    let (prefix, value) = best?;
    let subpath = &specifier[prefix.len()..];
    pick_package_import_path(value, Some(subpath))
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

/// Hash of the transpile tooling scripts, computed once per process and then
/// memoized. The scripts/engine don't change underneath a running loader, and
/// re-reading the override script for every module cache-key computation showed
/// up in runtime-loader profiling. @ref LLP 0007#runtime-module-loading
fn transpile_tooling_hash() -> Result<u64> {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    if let Some(hash) = CACHED.get() {
        return Ok(*hash);
    }
    let hash = compute_transpile_tooling_hash()?;
    // A concurrent initializer may win the race; either value is equally valid
    // for the process, so ignore a failed set and return what we computed.
    let _ = CACHED.set(hash);
    Ok(hash)
}

fn compute_transpile_tooling_hash() -> Result<u64> {
    // @ref LLP 0007#proposal — the in-process engine is part of the cache key
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
    // The resolved, writable cache directory doesn't change during a process
    // run, so resolve it once (create_dir_all + a probe write) and reuse it.
    // Without this, every transpiled-module load re-ran mkdir + a probe
    // create/remove round trip even on cache hits — the per-load syscall churn
    // runtime-loader profiling flagged. @ref LLP 0007#runtime-module-loading
    static CACHED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    if let Some(dir) = CACHED.get() {
        return Ok(dir.clone());
    }
    let dir = resolve_transpile_cache_dir()?;
    let _ = CACHED.set(dir.clone());
    Ok(dir)
}

fn resolve_transpile_cache_dir() -> Result<PathBuf> {
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

fn run_transpile_command(entry: &Path, output: &Path, target: &str, source: &str) -> Result<()> {
    // Explicit override keeps a custom transpiler-script escape hatch;
    // everything else is in-process per LLP 0007, so TypeScript works
    // standalone without a Bun/Node subprocess.
    if std::env::var("EXACT_TRANSPILE_SCRIPT").is_ok() {
        // The subprocess reads the entry by path; it can't take in-memory source.
        return run_transpile_subprocess(entry, output, target);
    }

    // Reuse the source the loader already read for this module instead of
    // re-reading the file inside the transpiler on a cache miss.
    let code = transpile::transpile_source_to_cjs(source, entry, target)?;

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    // tmp + rename so a concurrent reader never sees a half-written module.
    // The tmp name must be unique per process AND per call: the transpile cache
    // dir is shared per user, so a deterministic tmp path lets two processes
    // cold-loading the same module write the same file — one truncates the
    // other's in-flight write and the rename publishes a torn inode.
    let tmp = unique_tmp_path(output);
    if let Err(err) = std::fs::write(&tmp, code) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("Failed to write {}", tmp.display()));
    }
    if let Err(err) = std::fs::rename(&tmp, output) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("Failed to publish {}", output.display()));
    }
    Ok(())
}

/// A tmp sibling of `output` whose name is unique to this process and this
/// call, so a rename-based publish can never collide with another process (or
/// another concurrent transpile in this one) writing the same cache entry. The
/// tmp stays in `output`'s directory so the rename remains atomic on one
/// filesystem.
fn unique_tmp_path(output: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut bytes = [0u8; 8];
    let rand = if getrandom::getrandom(&mut bytes).is_ok() {
        u64::from_le_bytes(bytes)
    } else {
        // getrandom only fails in pathological environments; the pid + counter
        // already disambiguate, so a time-based fallback is plenty.
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    };

    let stem = output
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("module");
    let name = format!("{stem}.{}.{seq}.{rand:016x}.tmp", std::process::id());
    match output.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
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
    let script = std::env::var("EXACT_TRANSPILE_SCRIPT")
        .context("EXACT_TRANSPILE_SCRIPT must be set for subprocess transpilation")?;
    let script = PathBuf::from(script);
    if script.exists() {
        return Ok(script);
    }
    anyhow::bail!(
        "EXACT_TRANSPILE_SCRIPT points to missing file {}",
        script.display()
    );
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

    fn package_race_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap()
    }

    struct PackageHookReset;

    impl Drop for PackageHookReset {
        fn drop(&mut self) {
            for hook in [
                PACKAGE_SOURCE_OPEN_HOOK.get(),
                PACKAGE_ROOT_OPEN_HOOK.get(),
                PACKAGE_INVENTORY_PASS_HOOK.get(),
            ]
            .into_iter()
            .flatten()
            {
                *hook.lock().unwrap() = None;
            }
        }
    }

    #[cfg(unix)]
    fn test_object_identity(path: &Path) -> capsec_semantics::model::ObjectIdentity {
        use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path).unwrap();
        ObjectIdentity {
            platform: if cfg!(any(target_os = "macos", target_os = "ios")) {
                ObjectPlatform::Apple
            } else if cfg!(target_os = "android") {
                ObjectPlatform::Android
            } else {
                ObjectPlatform::Unix
            },
            volume: NonEmptyString::new(format!("dev:{}", metadata.dev())).unwrap(),
            file: NonEmptyString::new(format!("ino:{}", metadata.ino())).unwrap(),
        }
    }

    #[cfg(windows)]
    fn test_object_identity(path: &Path) -> capsec_semantics::model::ObjectIdentity {
        use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};
        use std::os::windows::fs::MetadataExt;
        let metadata = std::fs::metadata(path).unwrap();
        ObjectIdentity {
            platform: ObjectPlatform::Windows,
            volume: NonEmptyString::new(format!(
                "volume:{}",
                metadata.volume_serial_number().unwrap_or(0)
            ))
            .unwrap(),
            file: NonEmptyString::new(format!("file:{}", metadata.file_index().unwrap_or(0)))
                .unwrap(),
        }
    }

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

    // ENG-23007: `require.resolve` needs only the resolved path, so `resolve_meta`
    // (which backs it over the ABI) must return the metadata WITHOUT reading or
    // transpiling the module body. The differential proof is Node's own
    // `require.resolve` semantics: resolving a module whose body is un-parseable
    // still succeeds, because resolution never touches the body.
    #[test]
    fn resolve_meta_does_not_read_or_transpile_body() {
        let dir = tempdir().unwrap();
        // A .ts body that is a hard syntax error. The full loader would try to
        // transpile it; resolve_meta must never open it.
        let file = dir.path().join("broken.ts");
        std::fs::write(&file, "export const x: = = 1 ((( not valid typescript $$$").unwrap();

        let loader = test_loader();
        let meta = loader
            .resolve_meta("./broken", Some(&dir.path().join("entry.ts")))
            .expect("resolve_meta must succeed for a syntactically-broken body");

        assert_eq!(
            meta.path.as_ref().unwrap().canonicalize().unwrap(),
            file.canonicalize().unwrap()
        );
        // The proof the body was not read/transpiled: `source` is still unset.
        // (The un-parseable body would fail transpile on the full load path.)
        assert!(
            meta.source.is_none(),
            "resolve_meta must not load the module body"
        );
    }

    // ENG-23007: the metadata-only path skips the load that the full resolve
    // performs. For a VALID module, `resolve` populates `source` (read +
    // transpiled) while `resolve_meta` leaves it `None` for the same path.
    #[test]
    fn resolve_meta_omits_source_that_full_resolve_loads() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mod.ts");
        std::fs::write(&file, "export const answer: number = 42;").unwrap();
        let referrer = dir.path().join("entry.ts");

        let loader = test_loader();
        let meta = loader.resolve_meta("./mod", Some(&referrer)).unwrap();
        assert!(
            meta.source.is_none(),
            "resolve_meta must not populate source"
        );

        let full = loader.resolve("./mod", Some(&referrer)).unwrap();
        let source = full.source.expect("full resolve must load source");
        // Transpiled TS: the `: number` annotation is stripped, proving the full
        // path did the read + transpile work that resolve_meta skips.
        assert!(source.contains("answer"));
        assert!(!source.contains(": number"));
        assert_eq!(meta.path, full.path);
    }

    #[test]
    fn package_import_condition_prefers_require_over_import() {
        // `require` is the correct branch for the CJS loader; `default` remains
        // the lowest-priority fallback. (ENG-23457)
        let value: Value = serde_json::json!({
            "import": "./esm.mjs",
            "require": "./cjs.js",
            "default": "./browser.js",
        });
        assert_eq!(
            pick_package_import_path(&value, None),
            Some("./cjs.js".to_string())
        );
    }

    #[test]
    fn package_import_condition_falls_back_to_default() {
        let value: Value = serde_json::json!({ "default": "./browser.js" });
        assert_eq!(
            pick_package_import_path(&value, None),
            Some("./browser.js".to_string())
        );
    }

    #[test]
    fn package_import_wildcard_requires_slash_boundary() {
        // `#internal/*` must match `#internal/thing` but NOT the unrelated
        // sibling `#internal-utils`. (ENG-22949 finding 2a)
        let mut imports = serde_json::Map::new();
        imports.insert(
            "#internal/*".to_string(),
            Value::String("./src/internal/*.js".to_string()),
        );
        assert_eq!(
            resolve_package_import_target("#internal/thing", &imports),
            Some("./src/internal/thing.js".to_string())
        );
        assert_eq!(
            resolve_package_import_target("#internal-utils", &imports),
            None
        );
    }

    #[test]
    fn package_import_wildcard_prefers_longest_prefix() {
        // The most specific (longest-prefix) pattern must win regardless of
        // map iteration order. serde_json iterates keys alphabetically, so
        // `#a/*` sorts before `#a/b/*` — the old first-hit loop picked the
        // wrong one. (ENG-22949 finding 2b)
        let mut imports = serde_json::Map::new();
        imports.insert("#a/*".to_string(), Value::String("./a/*.js".to_string()));
        imports.insert("#a/b/*".to_string(), Value::String("./ab/*.js".to_string()));
        assert_eq!(
            resolve_package_import_target("#a/b/thing", &imports),
            Some("./ab/thing.js".to_string())
        );
        assert_eq!(
            resolve_package_import_target("#a/thing", &imports),
            Some("./a/thing.js".to_string())
        );
    }

    #[test]
    fn unique_tmp_path_is_process_and_call_unique() {
        // The publish tmp name must differ per call and embed the pid so two
        // processes cold-loading the same cache entry never share a tmp inode.
        // (ENG-22949 finding 3)
        let output = Path::new("/tmp/exact-transpile-cache/abc123def.js");
        let a = unique_tmp_path(output);
        let b = unique_tmp_path(output);
        assert_ne!(a, b);
        // Same directory keeps the publishing rename atomic on one filesystem.
        assert_eq!(a.parent(), output.parent());
        let name = a.file_name().unwrap().to_str().unwrap();
        assert!(name.contains(&std::process::id().to_string()));
        assert!(name.ends_with(".tmp"));
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
        assert!(!ModuleLoader::needs_js_downlevel(
            std::path::Path::new("bundle.js"),
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
    fn bound_package_resolution_never_selects_an_ambient_package() {
        let dir = tempdir().unwrap();
        let authenticated = dir.path().join("authenticated/pkg");
        let ambient = dir.path().join("app/node_modules/pkg");
        std::fs::create_dir_all(&authenticated).unwrap();
        std::fs::create_dir_all(&ambient).unwrap();
        let authenticated = std::fs::canonicalize(authenticated).unwrap();
        std::fs::write(
            authenticated.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0","main":"index.js"}"#,
        )
        .unwrap();
        std::fs::write(authenticated.join("index.js"), "module.exports = 'auth';").unwrap();
        std::fs::write(
            ambient.join("package.json"),
            r#"{"name":"pkg","version":"9.0.0","main":"index.js"}"#,
        )
        .unwrap();
        std::fs::write(ambient.join("index.js"), "module.exports = 'ambient';").unwrap();

        let resolved = test_loader()
            .resolve_meta_from_bound_package("pkg", "pkg", &authenticated)
            .unwrap();
        assert_eq!(
            resolved.path.as_deref(),
            Some(authenticated.join("index.js").as_path())
        );
        assert_eq!(
            resolved.package_root.as_deref(),
            Some(authenticated.as_path())
        );
        assert_eq!(resolved.package_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn bound_package_resolution_preserves_exports_encapsulation() {
        let dir = tempdir().unwrap();
        let authenticated = dir.path().join("pkg");
        std::fs::create_dir_all(&authenticated).unwrap();
        let authenticated = std::fs::canonicalize(authenticated).unwrap();
        std::fs::write(
            authenticated.join("package.json"),
            r#"{"name":"pkg","exports":{".":"./public.js"}}"#,
        )
        .unwrap();
        std::fs::write(
            authenticated.join("public.js"),
            "module.exports = 'public';",
        )
        .unwrap();
        std::fs::write(
            authenticated.join("private.js"),
            "module.exports = 'private';",
        )
        .unwrap();

        let loader = test_loader();
        let public = loader
            .resolve_meta_from_bound_package("pkg", "pkg", &authenticated)
            .unwrap();
        assert_eq!(
            public.path.as_deref(),
            Some(authenticated.join("public.js").as_path())
        );
        assert!(loader
            .resolve_meta_from_bound_package("pkg/private", "pkg", &authenticated)
            .is_err());
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

    // @ref LLP 0014#the-grant-channel — package/root trust classification must
    // come from resolver/package metadata, not only the post-resolution path
    // shape: linked dependencies can resolve outside node_modules.
    #[cfg(unix)]
    #[test]
    fn symlinked_dependency_resolution_keeps_package_metadata() {
        let dir = tempdir().unwrap();
        let app = dir.path().join("app");
        let real_pkg = dir.path().join("workspace").join("linked-pkg");
        let nm = app.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::create_dir_all(&real_pkg).unwrap();
        std::fs::write(
            real_pkg.join("package.json"),
            r#"{ "name":"linked-pkg", "version":"1.2.3", "main":"index.js" }"#,
        )
        .unwrap();
        std::fs::write(
            real_pkg.join("index.js"),
            "module.exports = require('./lib');",
        )
        .unwrap();
        std::fs::write(real_pkg.join("lib.js"), "module.exports = 1;").unwrap();
        std::os::unix::fs::symlink(&real_pkg, nm.join("linked-pkg")).unwrap();

        let loader = test_loader();
        let entry = loader
            .resolve_meta("linked-pkg", Some(&app.join("entry.js")))
            .unwrap();
        assert_eq!(entry.package_name.as_deref(), Some("linked-pkg"));
        assert_eq!(entry.package_version.as_deref(), Some("1.2.3"));
        let entry_root = entry.package_root.clone().expect("package root");

        let internal = loader
            .resolve_meta("./lib.js", Some(entry.path.as_ref().unwrap()))
            .unwrap();
        assert_eq!(internal.package_root.as_deref(), Some(entry_root.as_path()));
        assert_eq!(internal.package_version.as_deref(), Some("1.2.3"));
    }

    // @ref LLP 0013#resolved-questions — (ENG-22621) — the package root for
    // version derivation is node_modules/<name>, so a nested versionless
    // package.json (e.g. dist/) doesn't degrade identity to the bare name.
    #[test]
    fn package_root_uses_the_node_modules_name_segment() {
        let p = Path::new("/app/node_modules/foo/dist/index.js");
        assert_eq!(
            package_root_in_node_modules(p),
            Some(PathBuf::from("/app/node_modules/foo"))
        );
        // @scope takes two segments.
        let s = Path::new("/app/node_modules/@acme/tool/lib/x.js");
        assert_eq!(
            package_root_in_node_modules(s),
            Some(PathBuf::from("/app/node_modules/@acme/tool"))
        );
        // Nested layout resolves to the deepest owning package.
        let nested = Path::new("/a/node_modules/uses/node_modules/foo/dist/i.js");
        assert_eq!(
            package_root_in_node_modules(nested),
            Some(PathBuf::from("/a/node_modules/uses/node_modules/foo"))
        );
        // First-party code has no package root.
        assert_eq!(
            package_root_in_node_modules(Path::new("/app/src/index.js")),
            None
        );
    }

    #[test]
    fn package_version_reads_the_outer_manifest_not_a_nested_versionless_one() {
        let dir = tempdir().unwrap();
        let pkg = dir.path().join("node_modules").join("foo");
        std::fs::create_dir_all(pkg.join("dist")).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{ "name": "foo", "version": "2.0.0", "main": "dist/index.js" }"#,
        )
        .unwrap();
        // A nested, versionless package.json (the common "type" marker) must NOT
        // shadow the package's real version.
        std::fs::write(
            pkg.join("dist").join("package.json"),
            r#"{ "type": "commonjs" }"#,
        )
        .unwrap();
        std::fs::write(pkg.join("dist").join("index.js"), "module.exports = 1;").unwrap();

        let loader = test_loader();
        let version = loader.package_version_for(&pkg.join("dist").join("index.js"));
        assert_eq!(version.as_deref(), Some("2.0.0"));
    }

    // ENG-22950: a module that needs no transpile/downlevel is served verbatim.
    // NOTE: the resolver runs with `module_type` detection disabled
    // (ResolveOptions.module_type = false), so modules classify as CommonJs and
    // the resolve-time single-read + prefetch branch (`kind == Esm`) is dormant
    // in this configuration. Regardless of classification, a plain module must
    // round-trip its source unchanged — this guards that the loader never
    // corrupts or needlessly transpiles a pass-through module.
    #[test]
    fn serves_plain_module_source_verbatim() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("plain.js"), "module.exports = 1;\n").unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve("./plain.js", Some(&dir.path().join("entry.js")))
            .unwrap();
        assert_eq!(resolved.source.as_deref(), Some("module.exports = 1;\n"));
    }

    // ENG-22950: a TypeScript module loaded end-to-end must still be transpiled
    // to CommonJS. This exercises the source-threading path (the source read in
    // `load_module_source` is passed straight into the transpiler instead of the
    // file being read a second time) and, on the second load, the transpile
    // cache hit + memoized cache directory.
    #[test]
    fn loads_typescript_through_loader_and_caches() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("mod.ts"),
            "export const value: number = 41 + 1;\n",
        )
        .unwrap();

        let loader = test_loader();
        let resolved = loader
            .resolve("./mod.ts", Some(&dir.path().join("entry.ts")))
            .unwrap();
        let source = resolved.source.expect("transpiled source");
        // Type annotation stripped and the ESM export lowered to CommonJS.
        assert!(
            !source.contains(": number"),
            "type annotation not stripped: {source}"
        );
        assert!(source.contains("exports"), "not CommonJS output: {source}");

        // A second load hits the transpile cache (and the memoized cache dir)
        // and returns byte-identical output.
        let again = loader
            .resolve("./mod.ts", Some(&dir.path().join("entry.ts")))
            .unwrap();
        assert_eq!(again.source.as_deref(), Some(source.as_str()));
    }

    #[test]
    fn authenticated_package_source_rejects_post_arming_mutation() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("package");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        let source = root.join("index.js");
        std::fs::write(&source, "module.exports = 'armed';\n").unwrap();
        let integrity = package_tree_integrity(&root).unwrap();
        let root_object = test_object_identity(&root);

        assert_eq!(
            authenticated_package_source(&root, &source, &integrity, &root_object).unwrap(),
            b"module.exports = 'armed';\n"
        );
        std::fs::write(&source, "module.exports = 'mutated';\n").unwrap();
        let error =
            authenticated_package_source(&root, &source, &integrity, &root_object).unwrap_err();
        assert!(
            error.to_string().contains("changed after arming"),
            "{error:#}"
        );
    }

    #[test]
    fn authenticated_package_source_closes_metadata_to_read_replacement_race() {
        let _race_guard = package_race_test_lock();

        let dir = tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        let source = root.join("index.js");
        std::fs::write(&source, "module.exports = 'authenticated';\n").unwrap();
        let integrity = package_tree_integrity(&root).unwrap();
        let root_object = test_object_identity(&root);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        *PACKAGE_SOURCE_OPEN_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = Some((source.clone(), std::sync::Arc::clone(&barrier)));
        let _reset = PackageHookReset;

        let worker_root = root.clone();
        let worker_source = source.clone();
        let worker = std::thread::spawn(move || {
            authenticated_package_source(&worker_root, &worker_source, &integrity, &root_object)
        });
        barrier.wait();
        std::fs::write(&source, "module.exports = 'racing replacement';\n").unwrap();
        barrier.wait();

        let error = worker.join().unwrap().unwrap_err();
        assert!(error.to_string().contains("changed"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_package_source_rejects_same_content_root_object_swap() {
        let _race_guard = package_race_test_lock();
        let _reset = PackageHookReset;
        let dir = tempdir().unwrap();
        let root = dir.path().join("package");
        let replacement = dir.path().join("replacement");
        for path in [&root, &replacement] {
            std::fs::create_dir(path).unwrap();
            std::fs::write(path.join("package.json"), r#"{"name":"pkg"}"#).unwrap();
            std::fs::write(path.join("index.js"), "module.exports = 1;\n").unwrap();
        }
        let root = std::fs::canonicalize(root).unwrap();
        let source = root.join("index.js");
        let integrity = package_tree_integrity(&root).unwrap();
        let expected_root = test_object_identity(&root);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        *PACKAGE_ROOT_OPEN_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = Some((root.clone(), barrier.clone()));
        let worker_root = root.clone();
        let worker = std::thread::spawn(move || {
            authenticated_package_source(&worker_root, &source, &integrity, &expected_root)
        });
        barrier.wait();
        let original = dir.path().join("original");
        std::fs::rename(&root, &original).unwrap();
        std::fs::rename(&replacement, &root).unwrap();
        barrier.wait();
        let error = worker.join().unwrap().unwrap_err();
        assert!(
            error.to_string().contains("root object changed"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_package_source_rejects_add_remove_and_directory_swap_between_passes() {
        for mutation in ["add", "remove", "directory-swap"] {
            let _race_guard = package_race_test_lock();
            let _reset = PackageHookReset;
            let dir = tempdir().unwrap();
            let root = std::fs::canonicalize(dir.path()).unwrap();
            std::fs::write(root.join("package.json"), r#"{"name":"pkg"}"#).unwrap();
            std::fs::create_dir(root.join("lib")).unwrap();
            std::fs::write(root.join("lib/index.js"), "module.exports = 1;\n").unwrap();
            if mutation == "remove" {
                std::fs::write(root.join("remove-me.js"), "present\n").unwrap();
            }
            let source = root.join("lib/index.js");
            let integrity = package_tree_integrity(&root).unwrap();
            let expected_root = test_object_identity(&root);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            *PACKAGE_INVENTORY_PASS_HOOK
                .get_or_init(|| std::sync::Mutex::new(None))
                .lock()
                .unwrap() = Some((root.clone(), barrier.clone()));
            let worker_root = root.clone();
            let worker = std::thread::spawn(move || {
                authenticated_package_source(&worker_root, &source, &integrity, &expected_root)
            });
            barrier.wait();
            match mutation {
                "add" => std::fs::write(root.join("added.js"), "new\n").unwrap(),
                "remove" => std::fs::remove_file(root.join("remove-me.js")).unwrap(),
                "directory-swap" => {
                    let old = root.join("old-lib");
                    let replacement = root.join("replacement-lib");
                    std::fs::create_dir(&replacement).unwrap();
                    std::fs::write(replacement.join("index.js"), "module.exports = 2;\n").unwrap();
                    std::fs::rename(root.join("lib"), old).unwrap();
                    std::fs::rename(replacement, root.join("lib")).unwrap();
                }
                _ => unreachable!(),
            }
            barrier.wait();
            let error = worker.join().unwrap().unwrap_err();
            assert!(
                error.to_string().contains("changed"),
                "{mutation}: {error:#}"
            );
            drop(_reset);
            drop(_race_guard);
        }
    }
}
