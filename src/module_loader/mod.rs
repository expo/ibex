//! Module loader for ESM and CommonJS.
//!
//! This provides a minimal resolver and loader with `exact:` builtins.
//! Node-style package resolution and full ESM/CJS interop are implemented
//! incrementally (see TODOs).

pub mod artifact;
pub mod carrier;
#[cfg(any(test, feature = "module-runner"))]
pub mod commonjs;
pub mod commonjs_lexer;
#[cfg(any(test, feature = "module-runner"))]
pub mod generation;
#[cfg(any(test, feature = "module-runner"))]
pub mod graph;
pub mod identity;
pub mod producer_spike;
#[cfg(any(test, feature = "module-runner"))]
pub mod runner_pipeline;
#[cfg(any(test, feature = "module-runner"))]
pub mod security;
pub mod transpile;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oxc_resolver::{ModuleType, ResolveOptions, Resolver};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use identity::{ConditionSet, ImportAttributes, ResolutionKind, SourceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Esm,
    CommonJs,
    Json,
    Builtin,
}

#[derive(Debug, Clone)]
pub struct ResolvedModule {
    /// Authenticated record identity. Host paths remain display/debug labels
    /// and must never replace this key in the armed runtime.
    pub source_id: Option<SourceId>,
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
    resolver_import: Resolver,
    resolver_require: Resolver,
    /// Memoized `version` per package root dir (the nearest `package.json`), so
    /// version derivation is one read per package, not per module. (ENG-22621)
    package_versions: std::sync::RwLock<HashMap<PathBuf, Option<String>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct BuiltinManifestRegistration {
    specifier: &'static str,
    source_key: &'static str,
}

/// Whether the generated builtin manifest owns this exact public specifier.
/// @ref LLP 0004#one-source-many-specifiers — every authored alias belongs to
/// the builtin import axis even when it is not spelled with a `node:` prefix.
pub(crate) fn is_registered_builtin_specifier(specifier: &str) -> bool {
    BUILTIN_MANIFEST_REGISTRATIONS
        .iter()
        .any(|registration| registration.specifier == specifier)
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

        let options_for = |condition: &str| ResolveOptions {
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
            // `default` is unconditional in package exports and must not be
            // represented as an active condition. Import and require are
            // separate cache/authorization domains. @ref LLP 0026#1-source-admission-and-resolution
            condition_names: vec!["node".into(), condition.into()],
            // `.js` source goal is inherited from the nearest package scope;
            // explicit `.mjs/.cjs/.mts/.cts` still override below. Resolution
            // metadata is needed before the runner may decide whether a graph
            // is native or belongs to the bounded compatibility path.
            module_type: true,
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
            resolver_import: Resolver::new(options_for("import")),
            resolver_require: Resolver::new(options_for("require")),
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
        let meta = self.resolve_meta_typed(
            specifier,
            referrer,
            ResolutionKind::CommonJsRequire,
            &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            &ImportAttributes::default(),
        )?;
        self.load_source(meta)
    }

    pub fn resolve_meta(&self, specifier: &str, referrer: Option<&Path>) -> Result<ResolvedModule> {
        self.resolve_meta_typed(
            specifier,
            referrer,
            ResolutionKind::CommonJsRequire,
            &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            &ImportAttributes::default(),
        )
    }

    pub fn resolve_meta_typed(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        kind: ResolutionKind,
        conditions: &ConditionSet,
        attributes: &ImportAttributes,
    ) -> Result<ResolvedModule> {
        let specifier = specifier.trim();
        if specifier.is_empty() {
            return Err(anyhow!("Empty module specifier"));
        }
        let specifier = strip_file_specifier_decorations(specifier);
        if !attributes.is_empty() && kind == ResolutionKind::CommonJsRequire {
            return Err(anyhow!(
                "CommonJS require does not accept import attributes"
            ));
        }
        if specifier.starts_with('#') {
            if let Some(referrer_path) = referrer {
                if let Some(module) =
                    self.resolve_package_import(specifier, referrer_path, conditions)
                {
                    return Self::validate_import_attributes(module, kind, attributes);
                }
            }
            return Err(anyhow!("Failed to resolve package import {}", specifier));
        }
        if let Some(source) = self.builtins.get(specifier) {
            let source_key = BUILTIN_MANIFEST_REGISTRATIONS
                .iter()
                .find(|registration| registration.specifier == specifier)
                .map(|registration| registration.source_key)
                .ok_or_else(|| anyhow!("builtin registry record has no manifest identity"))?;
            return Self::validate_import_attributes(
                ResolvedModule {
                    source_id: Some(SourceId::builtin("ibex-runtime", source_key)?),
                    id: specifier.to_string(),
                    kind: ModuleKind::Builtin,
                    path: None,
                    source: Some(source.clone()),
                    package_name: None,
                    package_root: None,
                    package_version: None,
                    package_integrity: None,
                },
                kind,
                attributes,
            );
        }

        if specifier.starts_with("exact:") {
            return Err(anyhow!("Unknown exact builtin: {}", specifier));
        }

        if specifier.starts_with("node:") {
            return Err(anyhow!("Unsupported node builtin: {}", specifier));
        }

        let resolved = self.resolve_with_oxc(specifier, referrer, kind)?;
        Self::validate_import_attributes(resolved, kind, attributes)
    }

    fn validate_import_attributes(
        module: ResolvedModule,
        resolution_kind: ResolutionKind,
        attributes: &ImportAttributes,
    ) -> Result<ResolvedModule> {
        if attributes.asserts_json() && module.kind != ModuleKind::Json {
            return Err(anyhow!(
                "type=json import attribute requires a JSON module target"
            ));
        }
        if module.kind == ModuleKind::Json
            && resolution_kind != ResolutionKind::CommonJsRequire
            && !attributes.asserts_json()
        {
            return Err(anyhow!(
                "ESM JSON import requires the type=json import attribute"
            ));
        }
        Ok(module)
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
    #[allow(dead_code)] // retained as the reviewed CommonJS compatibility surface
    pub(crate) fn resolve_meta_from_bound_package(
        &self,
        specifier: &str,
        package_name: &str,
        package_root: &Path,
    ) -> Result<ResolvedModule> {
        self.resolve_meta_from_bound_package_typed(
            specifier,
            package_name,
            package_root,
            ResolutionKind::CommonJsRequire,
            &ImportAttributes::default(),
        )
    }

    pub(crate) fn resolve_meta_from_bound_package_typed(
        &self,
        specifier: &str,
        package_name: &str,
        package_root: &Path,
        kind: ResolutionKind,
        attributes: &ImportAttributes,
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
        let mut resolved =
            self.resolve_with_oxc_at(&anchored_specifier, package_root, false, kind)?;
        resolved.package_name = Some(package_name.to_owned());
        resolved.package_root = Some(package_root.to_path_buf());
        resolved.package_version = manifest
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Self::validate_import_attributes(resolved, kind, attributes)
    }

    fn resolve_package_import(
        &self,
        specifier: &str,
        referrer: &Path,
        conditions: &ConditionSet,
    ) -> Option<ResolvedModule> {
        let package_root = find_package_root(referrer)?;
        let manifest_path = package_root.join("package.json");
        let manifest = read_package_manifest(&manifest_path).ok()?;
        let imports = manifest.get("imports")?.as_object()?;

        let raw_target = resolve_package_import_target(specifier, imports, conditions)?;
        let target_path = normalize_import_target(&package_root, package_root.join(raw_target))?;

        let (package_name, package_root_from_path) =
            package_name_and_root_in_node_modules(&target_path).unzip();
        let package_root_for_record = package_root_from_path.or_else(|| Some(package_root.clone()));
        let package_version = self.package_version_for(&target_path);
        Some(ResolvedModule {
            source_id: None,
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
        let (source, lowered) = self.load_module_source(path)?;
        if lowered {
            module.kind = ModuleKind::CommonJs;
        }
        module.source = Some(source);
        Ok(module)
    }

    /// Preserve authenticated source bytes for the Oxc module-artifact
    /// producer. Unlike the compatibility loader, this never performs SWC
    /// ESM-to-CommonJS or syntax-scanner-selected lowering.
    pub(crate) fn load_runner_source_bytes(
        &self,
        mut module: ResolvedModule,
        bytes: Vec<u8>,
    ) -> Result<ResolvedModule> {
        let path = module
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("Module path missing"))?;
        module.source =
            Some(String::from_utf8(bytes).with_context(|| {
                format!("Module source is not valid UTF-8: {}", path.display())
            })?);
        Ok(module)
    }

    pub(crate) fn load_runner_source(&self, mut module: ResolvedModule) -> Result<ResolvedModule> {
        if module.source.is_some() {
            return Ok(module);
        }
        let path = module
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("Module path missing"))?;
        module.source = Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read module {}", path.display()))?,
        );
        Ok(module)
    }

    /// Read and lower a module only after Host has completed the staged
    /// identity/edge authorization. Resolution-only paths never call this.
    fn load_module_source(&self, path: &Path) -> Result<(String, bool)> {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read module {}", path.display()))?;
        let needs_lowering = Self::needs_transpile(path) || Self::needs_js_downlevel(path, &source);
        if needs_lowering {
            let target = Self::transpile_target_for_source(&source);
            return Ok((self.transpile_module(path, target, &source)?, true));
        }
        Ok((source, false))
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
            module.kind = ModuleKind::CommonJs;
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
        let is_runtime_bundle = path.file_name().and_then(OsStr::to_str) == Some("bundle.js")
            || path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.ends_with(".bundle.js"));
        if is_runtime_bundle && !Self::source_needs_downlevel(source) {
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
        fn contains_using_keyword(source: &str) -> bool {
            let bytes = source.as_bytes();
            let mut offset = 0;
            while let Some(relative) = source[offset..].find("using") {
                let start = offset + relative;
                let end = start + "using".len();
                let is_identifier =
                    |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$';
                let starts_token = start == 0 || !is_identifier(bytes[start - 1]);
                let ends_token = end == bytes.len() || !is_identifier(bytes[end]);
                if starts_token && ends_token {
                    return true;
                }
                offset = end;
            }
            false
        }

        source.contains("async function*")
            || source.contains("async function *")
            || source.contains("async*")
            || source.contains("async *")
            || source.contains("for await")
            || source.contains("await using")
            || contains_using_keyword(source)
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
        let cache_key = module_cache_key(path, target, source)?;
        // `transpile_cache_dir` is memoized and already created+probed the
        // directory once per process, so we don't re-`create_dir_all` here on
        // every (mostly cache-hit) module load. A cache miss recreates the
        // parent inside `run_transpile_command` before writing.
        let cache_dir = transpile_cache_dir()?;

        let artifact_dir = cache_dir.join(&cache_key);
        for _ in 0..3 {
            if let Some(output) = read_transpile_cache(&artifact_dir, target, source)? {
                touch_transpile_artifact(&artifact_dir);
                return Ok(output);
            }
            publish_transpile_artifact(path, &artifact_dir, target, source)?;
            enforce_transpile_cache_quota(&cache_dir, &artifact_dir);
        }
        anyhow::bail!(
            "Transpile cache artifact {} repeatedly disappeared during publication",
            artifact_dir.display()
        )
    }

    fn resolve_with_oxc(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        kind: ResolutionKind,
    ) -> Result<ResolvedModule> {
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
                            "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx" | "mts" | "cts" | "json"
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

        self.resolve_with_oxc_at(specifier, &base_dir, true, kind)
    }

    fn resolve_with_oxc_at(
        &self,
        specifier: &str,
        base_dir: &Path,
        retry_bare_as_relative: bool,
        kind: ResolutionKind,
    ) -> Result<ResolvedModule> {
        let resolver = match kind {
            ResolutionKind::CommonJsRequire => &self.resolver_require,
            ResolutionKind::EsmStatic | ResolutionKind::DynamicImport | ResolutionKind::Entry => {
                &self.resolver_import
            }
        };
        let resolution = match resolver.resolve(&base_dir, specifier) {
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
                    resolver
                        .resolve(&base_dir, &format!("./{specifier}"))
                        .with_context(|| format!("Failed to resolve module {}", specifier))?
                } else {
                    return Err(err)
                        .with_context(|| format!("Failed to resolve module {}", specifier));
                }
            }
        };

        let full_path = resolution.full_path().to_path_buf();
        // Oxc reports addon/Wasm candidates inconsistently across direct-file
        // and package resolution (a direct `.node` file can arrive as
        // CommonJS). The filename is therefore an independent fail-closed
        // guard, including case-folded spellings on case-insensitive targets.
        if let Some(extension) = full_path.extension().and_then(|value| value.to_str()) {
            if extension.eq_ignore_ascii_case("node") {
                anyhow::bail!("Native addons are closed in the CapSec profile");
            }
            if extension.eq_ignore_ascii_case("wasm") {
                anyhow::bail!("WebAssembly modules are closed in the CapSec profile");
            }
        }
        let mut kind = match resolution.module_type() {
            Some(ModuleType::Module) => ModuleKind::Esm,
            Some(ModuleType::CommonJs) => ModuleKind::CommonJs,
            Some(ModuleType::Json) => ModuleKind::Json,
            // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces —
            // unsupported executable loader kinds refuse before their bytes
            // enter the JavaScript compiler. Treating an addon or Wasm payload
            // as CommonJS lets a text file with a privileged extension execute.
            Some(ModuleType::Wasm) => {
                anyhow::bail!("WebAssembly modules are closed in the CapSec profile")
            }
            Some(ModuleType::Addon) => {
                anyhow::bail!("Native addons are closed in the CapSec profile")
            }
            None => ModuleKind::CommonJs,
        };
        // Explicit Node/TypeScript module extensions are source-goal facts and
        // outrank an absent or inherited package type from the resolver.
        match full_path
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("mjs" | "mts") => kind = ModuleKind::Esm,
            Some("cjs" | "cts") => kind = ModuleKind::CommonJs,
            _ => {}
        }
        // Force JSON kind for .json files regardless of what OXC reports,
        // so they get parsed with JSON.parse() instead of new Function().
        if full_path.extension().and_then(|e| e.to_str()) == Some("json") {
            kind = ModuleKind::Json;
        }
        // Extension-only classification is safe before source authorization.
        // Body-dependent syntax/downlevel classification occurs in
        // `load_source{,_bytes}` after the source-acquisition gate.
        // @ref LLP 0023#21-staged-authorization-identity
        if kind == ModuleKind::Esm {
            if Self::needs_transpile(&full_path) {
                kind = ModuleKind::CommonJs;
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
            source_id: None,
            id: full_path.to_string_lossy().to_string(),
            kind,
            path: Some(full_path),
            source: None,
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

fn strip_file_specifier_decorations(specifier: &str) -> &str {
    let file_like = specifier.starts_with('.')
        || specifier.starts_with('/')
        || Path::new(specifier).is_absolute();
    if !file_like {
        return specifier;
    }
    let end = specifier
        .char_indices()
        .find_map(|(index, character)| matches!(character, '?' | '#').then_some(index))
        .unwrap_or(specifier.len());
    &specifier[..end]
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

fn pick_package_import_path(
    value: &Value,
    subpath: Option<&str>,
    conditions: &ConditionSet,
) -> Option<String> {
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
            for condition in conditions.names().chain(std::iter::once("default")) {
                if let Some(condition_target) = map.get(condition) {
                    if let Some(path) =
                        pick_package_import_path(condition_target, subpath, conditions)
                    {
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
    conditions: &ConditionSet,
) -> Option<String> {
    if let Some(value) = imports.get(specifier) {
        if let Some(path) = pick_package_import_path(value, None, conditions) {
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
    pick_package_import_path(value, Some(subpath), conditions)
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
        for ext in ["js", "cjs", "mjs", "ts", "tsx", "jsx", "mts", "cts", "json"] {
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
        Some(ext) if matches!(ext.as_str(), "mjs" | "mts" | "ts" | "tsx" | "jsx") => {
            ModuleKind::Esm
        }
        Some(ext) if ext == "json" => ModuleKind::Json,
        _ => ModuleKind::CommonJs,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn module_cache_key(path: &Path, target: &str, source: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"loader-transpile-v14-content-addressed\0");
    hasher.update(target.as_bytes());
    hasher.update(b"\0");
    let cache_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let cache_path = cache_path.to_str().with_context(|| {
        format!(
            "Transpile cache does not support a non-UTF-8 module path: {}",
            cache_path.display()
        )
    })?;
    hasher.update(cache_path.as_bytes());
    hasher.update(b"\0");
    hasher.update(transpile_tooling_hash()?);
    hasher.update(b"\0");
    hasher.update(source.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

/// Hash of the transpile tooling scripts, computed once per process and then
/// memoized. The scripts/engine don't change underneath a running loader, and
/// re-reading the override script for every module cache-key computation showed
/// up in runtime-loader profiling. @ref LLP 0007#runtime-module-loading
fn transpile_tooling_hash() -> Result<[u8; 32]> {
    static CACHED: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    if let Some(hash) = CACHED.get() {
        return Ok(*hash);
    }
    let hash = compute_transpile_tooling_hash()?;
    // A concurrent initializer may win the race; either value is equally valid
    // for the process, so ignore a failed set and return what we computed.
    let _ = CACHED.set(hash);
    Ok(hash)
}

#[derive(Clone)]
struct CapturedTranspileToolFile {
    original: PathBuf,
    relative: PathBuf,
    source: std::sync::Arc<Vec<u8>>,
}

#[derive(Clone)]
struct TranspileOverrideIdentity {
    path: PathBuf,
    root: PathBuf,
    entry_relative: PathBuf,
    files: std::sync::Arc<Vec<CapturedTranspileToolFile>>,
    directory_digest: [u8; 32],
    runner: PathBuf,
    runner_name: &'static str,
    runner_digest: [u8; 32],
    digest: [u8; 32],
}

fn capture_transpile_tool_directory(
    root: &Path,
) -> Result<(Vec<CapturedTranspileToolFile>, [u8; 32])> {
    const MAX_FILES: usize = 4096;
    const MAX_BYTES: u64 = 256 * 1024 * 1024;

    fn walk(
        root: &Path,
        directory: &Path,
        files: &mut Vec<CapturedTranspileToolFile>,
        total: &mut u64,
    ) -> Result<()> {
        let mut entries =
            std::fs::read_dir(directory)?.collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
        for item in entries {
            let path = item.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "Transpile override tool directories may not contain symlinks: {}",
                    path.display()
                );
            }
            if metadata.is_dir() {
                walk(root, &path, files, total)?;
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            if files.len() >= MAX_FILES {
                anyhow::bail!("Transpile override exceeds {MAX_FILES} authenticated files");
            }
            *total = total
                .checked_add(metadata.len())
                .context("Transpile override size overflow")?;
            if *total > MAX_BYTES {
                anyhow::bail!("Transpile override exceeds the 256 MiB authenticated size limit");
            }
            let source = std::fs::read(&path)?;
            let relative = path
                .strip_prefix(root)
                .context("Transpile override file escaped its tool root")?
                .to_path_buf();
            if relative.to_str().is_none() {
                anyhow::bail!("Transpile override paths must be valid UTF-8");
            }
            files.push(CapturedTranspileToolFile {
                original: path,
                relative,
                source: std::sync::Arc::new(source),
            });
        }
        Ok(())
    }

    let mut files = Vec::new();
    let mut total = 0;
    walk(root, root, &mut files, &mut total)?;
    files.sort_by(|left, right| left.relative.cmp(&right.relative));
    let mut hasher = Sha256::new();
    hasher.update(b"transpile-tool-directory-v1\0");
    for file in &files {
        hasher.update(file.relative.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hasher.update((file.source.len() as u64).to_le_bytes());
        hasher.update(file.source.as_slice());
    }
    Ok((files, hasher.finalize().into()))
}

fn compute_transpile_override_identity(path: &Path) -> Result<TranspileOverrideIdentity> {
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("Failed to authenticate transpile script {}", path.display()))?;
    let root = path
        .parent()
        .context("Transpile override has no parent directory")?
        .to_path_buf();
    let entry_relative = path
        .strip_prefix(&root)
        .context("Transpile override escaped its parent directory")?
        .to_path_buf();
    let (files, directory_digest) = capture_transpile_tool_directory(&root)?;
    if !files.iter().any(|file| file.original == path) {
        anyhow::bail!(
            "Transpile override entry was not captured: {}",
            path.display()
        );
    }
    let (runner, runner_name) = find_js_runner()?;
    let runner = std::fs::canonicalize(&runner)
        .with_context(|| format!("Failed to authenticate JS runner {}", runner.display()))?;
    const MAX_RUNNER_BYTES: u64 = 512 * 1024 * 1024;
    if std::fs::metadata(&runner)?.len() > MAX_RUNNER_BYTES {
        anyhow::bail!("Selected JS runner exceeds the 512 MiB identity limit");
    }
    let runner_digest: [u8; 32] = Sha256::digest(
        std::fs::read(&runner)
            .with_context(|| format!("Failed to read JS runner {}", runner.display()))?,
    )
    .into();
    let mut hasher = Sha256::new();
    hasher.update(b"subprocess-transpile-toolchain-v2\0");
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update(b"\0");
    hasher.update(directory_digest);
    hasher.update(runner.to_string_lossy().as_bytes());
    hasher.update(b"\0");
    hasher.update(runner_digest);
    Ok(TranspileOverrideIdentity {
        path,
        root,
        entry_relative,
        files: std::sync::Arc::new(files),
        directory_digest,
        runner,
        runner_name,
        runner_digest,
        digest: hasher.finalize().into(),
    })
}

fn transpile_override_identity() -> Result<TranspileOverrideIdentity> {
    static CACHED: std::sync::OnceLock<TranspileOverrideIdentity> = std::sync::OnceLock::new();
    if let Some(identity) = CACHED.get() {
        return Ok(identity.clone());
    }
    let identity = compute_transpile_override_identity(&transpile_script_path()?)?;
    let _ = CACHED.set(identity.clone());
    Ok(identity)
}

fn compute_transpile_tooling_hash() -> Result<[u8; 32]> {
    // @ref LLP 0007#proposal — the in-process engine is part of the cache key
    // so the SWC fallback and Oxc candidate never share output.
    // Only the explicit subprocess override hashes a repo script.
    if std::env::var("EXACT_TRANSPILE_SCRIPT").is_ok() {
        let mut hasher = Sha256::new();
        hasher.update(b"subprocess-transpile-script\0");
        let identity = transpile_override_identity()?;
        let script_path = identity.path.to_str().with_context(|| {
            format!(
                "Transpile override does not support a non-UTF-8 path: {}",
                identity.path.display()
            )
        })?;
        hasher.update(script_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(identity.digest);
        return Ok(hasher.finalize().into());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"in-process-transpile-engine\0");
    hasher.update(transpile::selected_engine_cache_tag()?.as_bytes());
    Ok(hasher.finalize().into())
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

    let probe_path = unique_tmp_path(&dir.join(".exact-transpile-cache-write"));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_path)
    {
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

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TranspileCacheManifest {
    version: u32,
    target: String,
    source_sha256: String,
    output_sha256: String,
}

fn read_transpile_cache(artifact_dir: &Path, target: &str, source: &str) -> Result<Option<String>> {
    let output = artifact_dir.join("module.js");
    let manifest_path = artifact_dir.join("manifest.json");
    let (Ok(output_bytes), Ok(manifest_bytes)) =
        (std::fs::read(&output), std::fs::read(&manifest_path))
    else {
        return Ok(None);
    };
    let Ok(manifest) = serde_json::from_slice::<TranspileCacheManifest>(&manifest_bytes) else {
        return Ok(None);
    };
    let valid = manifest.version == 1
        && manifest.target == target
        && manifest.source_sha256 == sha256_hex(source.as_bytes())
        && manifest.output_sha256 == sha256_hex(&output_bytes);
    if !valid {
        return Ok(None);
    }
    String::from_utf8(output_bytes)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("cached transpile output is not UTF-8: {error}"))
}

fn transpile_cache_is_valid(artifact_dir: &Path, target: &str, source: &str) -> Result<bool> {
    Ok(read_transpile_cache(artifact_dir, target, source)?.is_some())
}

fn touch_transpile_artifact(artifact_dir: &Path) {
    // Recency is separate from the immutable code+manifest unit. Quota
    // eviction uses this marker when present, so cache hits implement LRU
    // rather than creation-time FIFO.
    let marker = artifact_dir.join(".last-used");
    let _ = std::fs::write(marker, []);
}

fn publish_transpile_artifact(
    entry: &Path,
    artifact_dir: &Path,
    target: &str,
    source: &str,
) -> Result<()> {
    let stage = unique_tmp_path(artifact_dir);
    std::fs::create_dir_all(&stage)
        .with_context(|| format!("Failed to create transpile stage {}", stage.display()))?;
    let stage_output = stage.join("module.js");
    let result = (|| -> Result<()> {
        run_transpile_command(entry, &stage_output, target, source)?;
        let output_bytes = std::fs::read(&stage_output)?;
        let manifest = TranspileCacheManifest {
            version: 1,
            target: target.to_string(),
            source_sha256: sha256_hex(source.as_bytes()),
            output_sha256: sha256_hex(&output_bytes),
        };
        std::fs::write(
            stage.join("manifest.json"),
            serde_json::to_vec(&manifest).context("serialize transpile cache manifest")?,
        )?;

        for _ in 0..4 {
            match std::fs::rename(&stage, artifact_dir) {
                Ok(()) => {
                    touch_transpile_artifact(artifact_dir);
                    return Ok(());
                }
                Err(_) if artifact_dir.exists() => {
                    if transpile_cache_is_valid(artifact_dir, target, source)? {
                        std::fs::remove_dir_all(&stage).ok();
                        touch_transpile_artifact(artifact_dir);
                        return Ok(());
                    }
                    // Quarantine a corrupt same-key directory with a rename,
                    // never remove it in place while another process may be
                    // inspecting it. Only one contender wins this rename;
                    // losers retry against the winner's replacement.
                    let quarantine = unique_tmp_path(&artifact_dir.with_extension("invalid"));
                    match std::fs::rename(artifact_dir, &quarantine) {
                        Ok(()) => {
                            std::fs::remove_dir_all(&quarantine).ok();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(error).with_context(|| {
                                format!(
                                    "Failed to quarantine invalid transpile cache {}",
                                    artifact_dir.display()
                                )
                            })
                        }
                    }
                }
                Err(error) => return Err(error).context("publish transpile cache directory"),
            }
        }
        anyhow::bail!(
            "Transpile cache {} remained contested after repeated atomic publication attempts",
            artifact_dir.display()
        )
    })();
    if result.is_err() {
        std::fs::remove_dir_all(&stage).ok();
    }
    result
}

fn directory_size(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => directory_size(&entry.path()),
            Ok(file_type) if file_type.is_file() => {
                entry.metadata().map(|meta| meta.len()).unwrap_or(0)
            }
            _ => 0,
        })
        .sum()
}

fn prune_transpile_cache_to_limit(cache_dir: &Path, keep: &Path, limit: u64) {
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return;
    };
    let mut artifacts: Vec<_> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path() != keep)
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            if !metadata.is_dir() || entry.file_name().to_string_lossy().contains(".tmp") {
                return None;
            }
            let recency = std::fs::metadata(entry.path().join(".last-used"))
                .and_then(|marker| marker.modified())
                .or_else(|_| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            Some((recency, directory_size(&entry.path()), entry.path()))
        })
        .collect();
    let keep_size = directory_size(keep);
    let mut total = keep_size + artifacts.iter().map(|(_, size, _)| size).sum::<u64>();
    if total <= limit {
        return;
    }
    artifacts.sort_by_key(|(modified, _, _)| *modified);
    for (_, size, path) in artifacts {
        if total <= limit {
            break;
        }
        if std::fs::remove_dir_all(&path).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

fn enforce_transpile_cache_quota(cache_dir: &Path, keep: &Path) {
    const DEFAULT_LIMIT: u64 = 256 * 1024 * 1024;
    let limit = std::env::var("IBEX_TRANSPILE_CACHE_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LIMIT);
    prune_transpile_cache_to_limit(cache_dir, keep, limit);
}

fn run_transpile_command(entry: &Path, output: &Path, target: &str, source: &str) -> Result<()> {
    // Explicit override keeps a custom transpiler-script escape hatch;
    // everything else is in-process per LLP 0007, so TypeScript works
    // standalone without a Bun/Node subprocess.
    if std::env::var("EXACT_TRANSPILE_SCRIPT").is_ok() {
        let script = transpile_override_identity()?;
        return run_transpile_override(entry, output, target, source, &script);
    }

    // Reuse the source the loader already read for this module instead of
    // re-reading the file inside the transpiler on a cache miss.
    let code = transpile::transpile_source_to_cjs(source, entry, target)?;

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    // The caller publishes the containing staged directory atomically after
    // both module.js and its digest manifest are complete.
    std::fs::write(output, code)
        .with_context(|| format!("Failed to write {}", output.display()))?;
    Ok(())
}

fn run_transpile_override(
    entry: &Path,
    output: &Path,
    target: &str,
    source: &str,
    script: &TranspileOverrideIdentity,
) -> Result<()> {
    verify_transpile_override_identity(script)?;

    // The cache key and manifest bind `source`, the loader's single read.
    // Give the subprocess an immutable staged copy of those exact bytes;
    // sending the live entry path lets A→B (or ABA) publish output for B
    // under A's content-addressed key.
    let staged_input = unique_staged_transpile_input(entry, output);
    let staged_tool_root = unique_tmp_path(&output.with_file_name("transpile-tool"));
    struct StageCleanup<'a> {
        input: &'a Path,
        tool_root: &'a Path,
    }
    impl Drop for StageCleanup<'_> {
        fn drop(&mut self) {
            std::fs::remove_file(self.input).ok();
            std::fs::remove_dir_all(self.tool_root).ok();
        }
    }
    let _cleanup = StageCleanup {
        input: &staged_input,
        tool_root: &staged_tool_root,
    };
    if let Some(parent) = staged_input.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut input = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged_input)
        .with_context(|| {
            format!(
                "Failed to create staged transpile input {}",
                staged_input.display()
            )
        })?;
    use std::io::Write as _;
    input.write_all(source.as_bytes())?;
    input.sync_all()?;
    drop(input);

    // Stage the complete authenticated tool directory, not only its entry
    // script. Relative helpers and package.json module-mode semantics are real
    // executable inputs; resolving them from the live directory after hashing
    // only the entry created stale-cache and split-input races.
    std::fs::create_dir(&staged_tool_root)?;
    for tool_file in script.files.iter() {
        let staged = staged_tool_root.join(&tool_file.relative);
        if let Some(parent) = staged.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        file.write_all(tool_file.source.as_slice())?;
        file.sync_all()?;
    }
    let staged_script = staged_tool_root.join(&script.entry_relative);

    wait_for_transpile_test_barrier(output)?;
    run_transpile_subprocess(
        &staged_input,
        output,
        target,
        &staged_script,
        &script.runner,
        script.runner_name,
    )?;
    // Do not publish output if either the selected runner or any live tool
    // file changed during the subprocess. The staged copy guarantees the
    // output itself used the pre-run bytes; this check keeps the cache key
    // from blessing a concurrently upgraded toolchain.
    verify_transpile_override_identity(script)
}

fn verify_transpile_override_identity(script: &TranspileOverrideIdentity) -> Result<()> {
    let (_, current_directory_digest) = capture_transpile_tool_directory(&script.root)?;
    if current_directory_digest != script.directory_digest {
        anyhow::bail!("Transpile override tool directory changed during this process");
    }
    let current_runner_digest: [u8; 32] = Sha256::digest(
        std::fs::read(&script.runner)
            .with_context(|| format!("Failed to verify JS runner {}", script.runner.display()))?,
    )
    .into();
    if current_runner_digest != script.runner_digest {
        anyhow::bail!("Selected JS runner changed during this process");
    }
    Ok(())
}

fn unique_staged_transpile_input(entry: &Path, output: &Path) -> PathBuf {
    let base = unique_tmp_path(&output.with_file_name("transpile-input"));
    let Some(extension) = entry.extension() else {
        return base;
    };
    let mut name = base.into_os_string();
    name.push(".");
    name.push(extension);
    PathBuf::from(name)
}

fn wait_for_transpile_test_barrier(output: &Path) -> Result<()> {
    let Ok(dir) = std::env::var("IBEX_TEST_TRANSPILE_INPUT_BARRIER") else {
        return Ok(());
    };
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir)?;
    if let Ok(target) = std::fs::read_to_string(dir.join("target")) {
        if target != output.to_string_lossy() {
            return Ok(());
        }
    }
    std::fs::write(dir.join("ready"), [])?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !dir.join("release").exists() {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for transpile input test barrier");
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
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

    let mut name = output
        .file_name()
        .unwrap_or_else(|| OsStr::new("module"))
        .to_os_string();
    name.push(format!(".{}.{seq}.{rand:016x}.tmp", std::process::id()));
    match output.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

fn run_transpile_subprocess(
    entry: &Path,
    output: &Path,
    target: &str,
    script: &Path,
    runner: &Path,
    runner_name: &str,
) -> Result<()> {
    let status = Command::new(runner)
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
        crate::host::object_identity_for_host_path(path).unwrap()
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
    fn executable_extension_modules_fail_closed_before_source_loading() {
        let dir = tempdir().unwrap();
        let entry = dir.path().join("entry.js");
        std::fs::write(&entry, "module.exports = true;").unwrap();
        for (name, expected) in [
            ("payload.node", "Native addons are closed"),
            ("payload.NODE", "Native addons are closed"),
            ("payload.wasm", "WebAssembly modules are closed"),
            ("payload.WASM", "WebAssembly modules are closed"),
        ] {
            // Deliberately valid JavaScript: the regression was that the
            // resolver relabeled these executable kinds as CommonJS.
            std::fs::write(dir.path().join(name), "globalThis.pwned = true;").unwrap();
            let error = test_loader()
                .resolve(&format!("./{name}"), Some(&entry))
                .expect_err("unsupported executable module kind resolved as JavaScript");
            assert!(
                error.to_string().contains(expected),
                "unexpected {name} refusal: {error:#}"
            );
        }
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

        let imported = loader
            .resolve_meta_typed(
                "exports-pkg",
                Some(&dir.path().join("entry.mjs")),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .unwrap();
        assert!(imported
            .path
            .unwrap()
            .ends_with("node_modules/exports-pkg/esm.js"));
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
    fn resolve_meta_does_not_prefetch_plain_esm_body() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mod.mjs");
        std::fs::write(&file, "export const answer = 42;").unwrap();

        let meta = test_loader()
            .resolve_meta_typed(
                "./mod.mjs",
                Some(&dir.path().join("entry.mjs")),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .unwrap();

        assert_eq!(
            std::fs::canonicalize(meta.path.unwrap()).unwrap(),
            std::fs::canonicalize(file).unwrap()
        );
        assert!(meta.source.is_none(), "resolution must not open ESM source");
    }

    #[test]
    fn file_query_and_fragment_do_not_change_resolved_identity_input() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("mod.js");
        std::fs::write(&file, "module.exports = 1;").unwrap();
        let referrer = dir.path().join("entry.js");
        let loader = test_loader();

        let plain = loader.resolve_meta("./mod.js", Some(&referrer)).unwrap();
        let decorated = loader
            .resolve_meta("./mod.js?cache=one#section", Some(&referrer))
            .unwrap();

        assert_eq!(plain.path, decorated.path);
        assert_eq!(plain.id, decorated.id);
    }

    #[test]
    fn ambiguous_js_source_goal_follows_authenticated_package_type() {
        let dir = tempdir().unwrap();
        let esm = dir.path().join("esm");
        let cjs = dir.path().join("cjs");
        std::fs::create_dir_all(&esm).unwrap();
        std::fs::create_dir_all(&cjs).unwrap();
        std::fs::write(esm.join("package.json"), r#"{"type":"module"}"#).unwrap();
        std::fs::write(cjs.join("package.json"), r#"{"type":"commonjs"}"#).unwrap();
        std::fs::write(esm.join("value.js"), "export const value = 1;").unwrap();
        std::fs::write(cjs.join("value.js"), "module.exports = 1;").unwrap();
        let loader = test_loader();

        let esm_meta = loader
            .resolve_meta_typed(
                "./value.js",
                Some(&esm.join("entry.mjs")),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .unwrap();
        let cjs_meta = loader
            .resolve_meta_typed(
                "./value.js",
                Some(&cjs.join("entry.mjs")),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .unwrap();

        assert_eq!(esm_meta.kind, ModuleKind::Esm);
        assert_eq!(cjs_meta.kind, ModuleKind::CommonJs);
    }

    #[test]
    fn json_import_attributes_are_typed_and_fail_closed() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("value.json"), r#"{"value":1}"#).unwrap();
        std::fs::write(dir.path().join("value.js"), "export const value = 1;").unwrap();
        let referrer = dir.path().join("entry.mjs");
        let loader = test_loader();
        let json_attributes = ImportAttributes::new([("type".into(), "json".into())]).unwrap();

        assert!(loader
            .resolve_meta_typed(
                "./value.json",
                Some(&referrer),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
            .is_err());
        assert_eq!(
            loader
                .resolve_meta_typed(
                    "./value.json",
                    Some(&referrer),
                    ResolutionKind::EsmStatic,
                    &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                    &json_attributes,
                )
                .unwrap()
                .kind,
            ModuleKind::Json
        );
        assert!(loader
            .resolve_meta_typed(
                "./value.js",
                Some(&referrer),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &json_attributes,
            )
            .is_err());
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
            pick_package_import_path(
                &value,
                None,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
            Some("./cjs.js".to_string())
        );
    }

    #[test]
    fn package_import_condition_keeps_import_and_require_separate() {
        let value: Value = serde_json::json!({
            "import": "./esm.mjs",
            "require": "./cjs.js",
            "default": "./fallback.js",
        });
        assert_eq!(
            pick_package_import_path(
                &value,
                None,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
            ),
            Some("./esm.mjs".to_string())
        );
    }

    #[test]
    fn package_import_condition_falls_back_to_default() {
        let value: Value = serde_json::json!({ "default": "./browser.js" });
        assert_eq!(
            pick_package_import_path(
                &value,
                None,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
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
            resolve_package_import_target(
                "#internal/thing",
                &imports,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
            Some("./src/internal/thing.js".to_string())
        );
        assert_eq!(
            resolve_package_import_target(
                "#internal-utils",
                &imports,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
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
            resolve_package_import_target(
                "#a/b/thing",
                &imports,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
            Some("./ab/thing.js".to_string())
        );
        assert_eq!(
            resolve_package_import_target(
                "#a/thing",
                &imports,
                &ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ),
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
    fn transpile_cache_key_tracks_same_length_same_mtime_source_changes() {
        let dir = tempdir().unwrap();
        let entry = dir.path().join("module.ts");
        std::fs::write(&entry, "module.exports = 1").unwrap();
        let first = module_cache_key(&entry, "es2015", "module.exports = 1").unwrap();
        // The two sources have identical length and the file metadata is left
        // untouched between key computations. Content identity must still move.
        let second = module_cache_key(&entry, "es2015", "module.exports = 2").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn subprocess_transpile_consumes_staged_exact_source_across_aba_mutation() {
        if find_js_runner().is_err() {
            return;
        }
        let dir = tempdir().unwrap();
        let tool_dir = dir.path().join("tool");
        std::fs::create_dir(&tool_dir).unwrap();
        let entry = dir.path().join("module.ts");
        let output = dir.path().join("module.js");
        let script = tool_dir.join("transpile.cjs");
        let helper = tool_dir.join("helper.cjs");
        let ready = dir.path().join("ready");
        let release = dir.path().join("release");
        let observed = dir.path().join("observed-entry");
        let quoted = |path: &Path| serde_json::to_string(&path.to_string_lossy()).unwrap();
        std::fs::write(
            &script,
            format!(
                "const fs=require('fs'); if (!require('./helper.cjs')) throw new Error('missing helper'); const a=process.argv; \
                 const entry=a[a.indexOf('--entry')+1], out=a[a.indexOf('--out')+1]; \
                 fs.writeFileSync({}, entry); fs.writeFileSync({}, ''); \
                 while(!fs.existsSync({})) {{}} \
                 fs.writeFileSync(out, fs.readFileSync(entry));",
                quoted(&observed),
                quoted(&ready),
                quoted(&release),
            ),
        )
        .unwrap();
        std::fs::write(&helper, "module.exports = true;\n").unwrap();
        let script_identity = compute_transpile_override_identity(&script).unwrap();
        let source_a = "export const answer: number = 41;";
        let source_b = "export const answer: number = 99;";
        std::fs::write(&entry, source_a).unwrap();

        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                run_transpile_override(&entry, &output, "es2015", source_a, &script_identity)
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !ready.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            let reached_barrier = ready.exists();
            if reached_barrier {
                std::fs::write(&entry, source_b).unwrap();
                std::fs::write(&entry, source_a).unwrap();
            }
            // Always release the child before joining. Panicking on the
            // deadline while a scoped child is deliberately blocked on this
            // file makes scope unwinding wait forever.
            std::fs::write(&release, []).unwrap();
            let result = handle.join().unwrap();
            assert!(
                reached_barrier,
                "transpiler did not reach barrier: {result:?}"
            );
            result.unwrap();
        });

        assert_eq!(std::fs::read_to_string(&output).unwrap(), source_a);
        let observed_entry = PathBuf::from(std::fs::read_to_string(&observed).unwrap());
        assert_ne!(observed_entry, entry);
        assert_eq!(
            observed_entry.extension().and_then(OsStr::to_str),
            Some("ts")
        );
        assert!(
            !observed_entry.exists(),
            "staged input must be removed after subprocess exit"
        );
    }

    #[test]
    fn subprocess_transpile_rejects_live_helper_mutation() {
        if find_js_runner().is_err() {
            return;
        }
        let dir = tempdir().unwrap();
        let tool_dir = dir.path().join("tool");
        std::fs::create_dir(&tool_dir).unwrap();
        let entry = dir.path().join("module.ts");
        let output = dir.path().join("module.js");
        let script = tool_dir.join("transpile.cjs");
        let helper = tool_dir.join("helper.cjs");
        let ready = dir.path().join("ready");
        let release = dir.path().join("release");
        let quoted = |path: &Path| serde_json::to_string(&path.to_string_lossy()).unwrap();
        std::fs::write(
            &script,
            format!(
                "const fs=require('fs'); require('./helper.cjs'); const a=process.argv; \
                 const entry=a[a.indexOf('--entry')+1], out=a[a.indexOf('--out')+1]; \
                 fs.writeFileSync({}, ''); while(!fs.existsSync({})) {{}} \
                 fs.writeFileSync(out, fs.readFileSync(entry));",
                quoted(&ready),
                quoted(&release),
            ),
        )
        .unwrap();
        std::fs::write(&helper, "module.exports = 'old';\n").unwrap();
        std::fs::write(&entry, "export const answer = 42;\n").unwrap();
        let identity = compute_transpile_override_identity(&script).unwrap();

        let error = std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                run_transpile_override(
                    &entry,
                    &output,
                    "es2015",
                    "export const answer = 42;\n",
                    &identity,
                )
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !ready.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            let reached_barrier = ready.exists();
            if reached_barrier {
                std::fs::write(&helper, "module.exports = 'new';\n").unwrap();
            }
            // See the sibling ABA test: a timeout must not strand the scoped
            // child in its intentional busy-wait.
            std::fs::write(&release, []).unwrap();
            let result = handle.join().unwrap();
            assert!(
                reached_barrier,
                "transpiler did not reach barrier: {result:?}"
            );
            result.unwrap_err()
        });
        assert!(
            error
                .to_string()
                .contains("tool directory changed during this process"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn transpile_cache_rejects_tampered_output() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("artifact");
        std::fs::create_dir(&artifact).unwrap();
        let source = "export const answer: number = 42";
        let output = b"exports.answer = 42;";
        std::fs::write(artifact.join("module.js"), output).unwrap();
        let manifest = TranspileCacheManifest {
            version: 1,
            target: "es2015".into(),
            source_sha256: sha256_hex(source.as_bytes()),
            output_sha256: sha256_hex(output),
        };
        std::fs::write(
            artifact.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(transpile_cache_is_valid(&artifact, "es2015", source).unwrap());
        std::fs::write(artifact.join("module.js"), "exports.answer = 99;").unwrap();
        assert!(!transpile_cache_is_valid(&artifact, "es2015", source).unwrap());
    }

    #[test]
    fn transpile_cache_quota_evicts_old_artifacts_but_keeps_current() {
        let dir = tempdir().unwrap();
        let old = dir.path().join("old");
        let current = dir.path().join("current");
        std::fs::create_dir(&old).unwrap();
        std::fs::write(old.join("module.js"), vec![0u8; 64]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::create_dir(&current).unwrap();
        std::fs::write(current.join("module.js"), vec![0u8; 64]).unwrap();

        prune_transpile_cache_to_limit(dir.path(), &current, 64);
        assert!(!old.exists());
        assert!(current.exists());
    }

    #[test]
    fn concurrent_transpile_publishers_share_one_complete_immutable_artifact() {
        let dir = tempdir().unwrap();
        let entry = dir.path().join("module.ts");
        let artifact = dir.path().join("artifact");
        let source = "export const answer: number = 42;";
        std::fs::write(&entry, source).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));

        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..12 {
                let barrier = barrier.clone();
                let entry = entry.clone();
                let artifact = artifact.clone();
                handles.push(scope.spawn(move || {
                    barrier.wait();
                    publish_transpile_artifact(&entry, &artifact, "es2015", source)
                }));
            }
            for handle in handles {
                handle.join().unwrap().unwrap();
            }
        });
        assert!(transpile_cache_is_valid(&artifact, "es2015", source).unwrap());
        assert_eq!(
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp"))
                .count(),
            0,
            "losing publishers must clean their staging directories"
        );
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
        assert!(ModuleLoader::needs_js_downlevel(
            std::path::Path::new("bundle.js"),
            source
        ));
        // Runtime bundles may contain top-level syntax that is legal only in
        // their wrapper, so plain bundles remain exempt. The exemption must be
        // content-aware: a bundle that actually contains unsupported syntax is
        // still lowered before Hermes sees it.
        assert!(!ModuleLoader::needs_js_downlevel(
            std::path::Path::new("bundle.js"),
            "return (function () { return 42; })();"
        ));
    }

    #[test]
    fn detects_using_declarations_after_other_tokens_on_the_same_line() {
        assert!(ModuleLoader::source_needs_async_downlevel(
            "initialize(); using resource = acquire();"
        ));
        assert!(ModuleLoader::source_needs_async_downlevel(
            "if (ready) { using resource = acquire(); }"
        ));
        assert!(ModuleLoader::source_needs_async_downlevel(
            "initialize(); await using resource = acquireAsync();"
        ));
        assert!(!ModuleLoader::source_needs_async_downlevel(
            "const amusing = true;"
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
            .resolve_meta_typed(
                "exports-import-only",
                Some(&dir.path().join("entry.mjs")),
                ResolutionKind::EsmStatic,
                &ConditionSet::for_kind(ResolutionKind::EsmStatic),
                &ImportAttributes::default(),
            )
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
    // Package-scope module-type detection is enabled, but this fixture has no
    // `type: module` package boundary and therefore remains CommonJS.
    // Regardless of classification, a plain module must round-trip its source
    // unchanged — this guards that the loader never corrupts or needlessly
    // transpiles a pass-through module.
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
