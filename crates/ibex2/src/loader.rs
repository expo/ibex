//! The module loader: resolution, wrapping, and per-module authority.
//!
//! This is where LLP 0067's properties are actually enforced. R1 (nothing
//! capability-bearing on the global object), R2 (each module receives its
//! bindings as parameters of its own scope), and R5 (the global name list is
//! asserted) are properties of *this* file, not of the boundary below it.
//!
//! **v1 is CommonJS-shaped and loads from source.** Not because that is the
//! destination — LLP 0067 R3 requires wrappers compiled ahead of time, and
//! LLP 0057 §1 is a complaint about exactly the per-launch parsing this does —
//! but because it is the smallest loader that makes per-module injection real,
//! and because the boot measurement it enables is what motivates the AOT step.
//! ESM waits on a parser; see LLP 0026.
//!
//! @ref LLP 0058.000.000#6-module-binding-globals-and-bootstrap — module binding, globals, and bootstrap
//! @ref LLP 0067#1-five-properties — R1 and R2: capability-bearing bindings are parameters, never ambient

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use crate::grant::GrantSet;

/// What a module is allowed to reach, and what it is called.
#[derive(Debug, Clone)]
pub struct ModuleGrants {
    /// Grants keyed by module specifier, resolved relative to the root.
    per_module: BTreeMap<String, GrantSet>,
    /// Grants keyed by package name: every file of the package, in every
    /// installed copy. See `package_of` for what names a package.
    per_package: BTreeMap<String, GrantSet>,
    /// Grants keyed by directory (`./src/`): every module under it, the
    /// longest prefix winning. How first-party trees and workspace packages
    /// are granted.
    per_directory: BTreeMap<String, GrantSet>,
    /// Applied to any module without its own entry.
    default_grants: GrantSet,
}

/// What a manifest section names.
#[derive(Debug, PartialEq, Eq)]
enum Section {
    Default,
    Module(String),
    Directory(String),
    Package(String),
}

impl Section {
    /// `*`, `./file.js`, `./dir/`, or a package name — and nothing else. A
    /// section that is none of these is refused rather than stored under a
    /// key nothing will ever match, because a manifest that silently grants
    /// nothing is the worst kind of wrong.
    fn parse(name: &str) -> Result<Self, String> {
        if name == "*" {
            return Ok(Section::Default);
        }
        if let Some(rest) = name.strip_prefix("./") {
            if rest.is_empty() || rest.split('/').any(|s| s == "..") {
                return Err(format!("manifest section [{name}] is not a path inside the project"));
            }
            return Ok(if name.ends_with('/') {
                Section::Directory(name.to_string())
            } else {
                Section::Module(name.to_string())
            });
        }
        if is_package_name(name) {
            return Ok(Section::Package(name.to_string()));
        }
        Err(format!(
            "manifest section [{name}] is neither a module (./x.js), a directory (./dir/), \
             a package name (react, @scope/pkg), nor *"
        ))
    }
}

fn is_package_name(name: &str) -> bool {
    let ok_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    let parts: Vec<&str> = name.split('/').collect();
    let unscoped = |part: &str| !part.is_empty() && !part.starts_with('.') && part.chars().all(ok_char);
    match parts.as_slice() {
        [bare] => !bare.starts_with('@') && unscoped(bare),
        [scope, bare] => scope
            .strip_prefix('@')
            .is_some_and(unscoped)
            && unscoped(bare),
        _ => false,
    }
}

/// The package a module belongs to, from its canonical specifier alone.
///
/// The innermost `node_modules/<name>/` segment names it: `react` for
/// `./node_modules/react/cjs/react.js`, for a nested copy under another
/// package, and for pnpm's `.pnpm/react@19/node_modules/react/`. The name
/// comes from the *path*, never from the package's own `package.json` — a
/// package that declares itself `react` gets nothing by saying so.
///
/// A module outside `node_modules` belongs to no package here. It is
/// first-party and is granted by path; a workspace package, whose symlink
/// canonicalizes outside `node_modules`, is bound to its real directory by
/// `ModuleGrants::bind`.
///
/// @ref LLP 0065#42-packages-are-granted-by-name-first-party-code-by-path
pub fn package_of(specifier: &str) -> Option<String> {
    const MARKER: &str = "node_modules/";
    let at = specifier
        .rmatch_indices(MARKER)
        .map(|(i, _)| i)
        .find(|&i| i == 0 || specifier.as_bytes()[i - 1] == b'/')?;
    let mut segments = specifier[at + MARKER.len()..].split('/');
    let first = segments.next().filter(|s| !s.is_empty())?;
    let name = if first.starts_with('@') {
        let second = segments.next().filter(|s| !s.is_empty())?;
        format!("{first}/{second}")
    } else {
        first.to_string()
    };
    // A package directory is not a module; there has to be a file inside it.
    segments.next().filter(|s| !s.is_empty())?;
    Some(name)
}

impl ModuleGrants {
    /// Nothing granted to anyone. The correct default: a module that was not
    /// named in the manifest reaches nothing, rather than inheriting whatever
    /// the application happened to hold.
    pub fn none() -> Self {
        Self {
            per_module: BTreeMap::new(),
            per_package: BTreeMap::new(),
            per_directory: BTreeMap::new(),
            default_grants: GrantSet::none(),
        }
    }

    pub fn with_default(mut self, grants: GrantSet) -> Self {
        self.default_grants = grants;
        self
    }

    pub fn with_module(mut self, specifier: &str, grants: GrantSet) -> Self {
        self.per_module.insert(specifier.to_string(), grants);
        self
    }

    pub fn with_package(mut self, name: &str, grants: GrantSet) -> Self {
        self.per_package.insert(name.to_string(), grants);
        self
    }

    pub fn with_directory(mut self, prefix: &str, grants: GrantSet) -> Self {
        self.per_directory.insert(prefix.to_string(), grants);
        self
    }

    /// The grant set for one module: its own section if it has one, else its
    /// package's, else the longest directory prefix naming it, else the
    /// default. Replacement, not union — a module has one grant set, from the
    /// most specific section that names it, so an explicit empty section still
    /// means "nothing".
    pub fn for_module(&self, specifier: &str) -> &GrantSet {
        if let Some(grants) = self.per_module.get(specifier) {
            return grants;
        }
        if let Some(name) = package_of(specifier) {
            if let Some(grants) = self.per_package.get(&name) {
                return grants;
            }
        }
        self.per_directory
            .iter()
            .filter(|(prefix, _)| specifier.starts_with(prefix.as_str()))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, grants)| grants)
            .unwrap_or(&self.default_grants)
    }

    /// The package names the manifest grants.
    pub fn packages(&self) -> impl Iterator<Item = &str> {
        self.per_package.keys().map(String::as_str)
    }

    /// Bind the manifest to a project.
    ///
    /// Every package section must name a package installed under `root`. One
    /// that is a workspace symlink — whose files canonicalize outside
    /// `node_modules`, so `package_of` cannot name them — is bound here to its
    /// real directory, so `[@w/ui]` reaches the package whether it is imported
    /// by name or by relative path (LLP 0065 §4.1: one file, one name).
    ///
    /// Refusing an uninstalled name is a usability property, not a safety one:
    /// a misspelt section grants nothing either way. It is refused because a
    /// manifest that silently does nothing is the worst kind of wrong.
    pub fn bind(&mut self, root: &Path) -> Result<(), String> {
        let canonical_root = root
            .canonicalize()
            .map_err(|e| format!("project root {} cannot be resolved: {e}", root.display()))?;
        let names: Vec<String> = self.per_package.keys().cloned().collect();
        for name in names {
            let installed = canonical_root.join("node_modules").join(&name);
            let canonical = installed.canonicalize().map_err(|_| {
                format!(
                    "the manifest grants package {name:?}, which is not installed under {}/node_modules. \
                     Install it, or grant a nested copy by its directory \
                     ([./node_modules/<parent>/node_modules/{name}/])",
                    canonical_root.display()
                )
            })?;
            let relative = canonical.strip_prefix(&canonical_root).map_err(|_| {
                format!(
                    "the manifest grants package {name:?}, which resolves outside the project root: {}",
                    canonical.display()
                )
            })?;
            let relative = relative.to_string_lossy().replace('\\', "/");
            // Installed in place: the path names it, and every nested copy too.
            if relative.split('/').any(|segment| segment == "node_modules") {
                continue;
            }
            // A workspace package: first-party files under a name. An explicit
            // directory section for the same tree, if the author wrote one, wins.
            let grants = self.per_package[&name].clone();
            self.per_directory
                .entry(format!("./{relative}/"))
                .or_insert(grants);
        }
        Ok(())
    }

    /// Parse a manifest: sections of grant lines.
    ///
    /// ```text
    /// # applies to every module without its own section
    /// [*]
    /// # (nothing)
    ///
    /// [./net.js]                  # one module
    /// net.fetch https://api.example.com
    ///
    /// [./src/telemetry/]          # every module under a directory
    /// net.fetch https://telemetry.example.com
    ///
    /// [react]                     # every file of a package, every copy
    /// env NODE_ENV
    /// [@w/ui]                     # a scoped package, workspace or installed
    /// ```
    ///
    /// A module gets the most specific section naming it — its own, then its
    /// package's, then the longest directory, then `*` — and nothing is
    /// combined. Package sections are checked against the project by `bind`.
    ///
    /// Provisional, and LLP 0062 OQ1 is where that is recorded: whether grants
    /// belong in a manifest, the build graph, or import sites is undecided, and
    /// this is the simplest form that makes the loader real without foreclosing
    /// the others.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut grants = ModuleGrants::none();
        let mut section: Option<Section> = None;
        let mut buffer = String::new();

        let flush = |grants: &mut ModuleGrants,
                     section: &Option<Section>,
                     buffer: &str|
         -> Result<(), String> {
            let Some(section) = section else { return Ok(()) };
            let parsed = GrantSet::parse(buffer)?;
            match section {
                Section::Default => grants.default_grants = parsed,
                Section::Module(name) => {
                    grants.per_module.insert(name.clone(), parsed);
                }
                Section::Directory(prefix) => {
                    grants.per_directory.insert(prefix.clone(), parsed);
                }
                Section::Package(name) => {
                    grants.per_package.insert(name.clone(), parsed);
                }
            }
            Ok(())
        };

        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(name) = trimmed.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                flush(&mut grants, &section, &buffer)?;
                buffer.clear();
                section = Some(Section::parse(name.trim())?);
                continue;
            }
            buffer.push_str(line);
            buffer.push('\n');
        }
        flush(&mut grants, &section, &buffer)?;
        Ok(grants)
    }
}

/// The conditions honored when resolving a package's `exports`.
///
/// A policy choice, not a mechanism.
///
/// **This is a set, not a preference order.** Matching walks the *package's*
/// `exports` keys and takes the first one this set contains, so listing
/// `import` before `require` here expresses nothing — a package that writes
/// `require` first gets CommonJS either way. The order is kept only because it
/// reads as intent to a human; `a_packages_own_key_order_decides_between_import_and_require`
/// pins the real behaviour.
///
/// **`node` is deliberately absent.** LLP 0059 §6 deleted Node's server
/// surface, so a package selecting a Node build would get one written against
/// modules that do not exist here. The cost is real and not a fallback: a
/// package exporting *only* a `node` condition does not quietly resolve to
/// `default`, it fails to resolve at all.
///
/// @ref LLP 0065#1-conditions-and-the-one-that-is-missing — why `node` is omitted
pub const CONDITIONS: &[&str] = &["import", "require", "default"];

/// Resolve `specifier` as written inside `from`, against `root`.
///
/// Relative specifiers resolve lexically and are contained. **Containment is
/// enforced**: a resolved path must stay under the root, so
/// `require('../../../../etc/passwd')` fails at resolution rather than becoming
/// an fs.read question. Path reach is a capability concern (LLP 0059.000
/// §3.11), and the loader is not an exception to it.
///
/// Bare specifiers go through `oxc_resolver` — Node resolution is a real
/// algorithm with `exports` maps and condition matching, and the ecosystem
/// already has the answer (LLP 0028). The result is still contained: a package
/// resolving outside the root is refused, which is what makes `node_modules`
/// part of the project rather than a hole in it.
///
/// **Containment is checked against the canonical path**, so a symlink in
/// `node_modules` pointing out of the project is refused like any other escape.
/// A workspace package therefore resolves to its real location and is reachable
/// only when that location is itself inside the root.
/// The containment boundary, and — the part that matters — where it came from.
///
/// Relative specifiers need only a file's neighbours. **Package resolution
/// needs a project**: Node resolution walks *up* looking for `node_modules`,
/// so it is meaningful only against a boundary that someone chose. The entry
/// file's own directory is not that. It is where a file happens to sit, and in
/// a monorepo it is one or two levels below where the packages actually live.
///
/// Rather than guess — every rule for inferring a project root from
/// `package.json` or `node_modules` can be induced to widen it further than
/// the author expected, and a stray `package.json` in a home directory should
/// not make the home directory reachable — an undeclared root simply refuses
/// bare specifiers and says so. Relative resolution is unaffected.
///
/// @ref LLP 0065#5-the-root-must-be-declared — why this is not inferred
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Root {
    /// Declared by the author (`--root`). The project is what they said it is,
    /// so packages resolve and containment is enforced against it.
    Declared(PathBuf),
    /// Nothing was declared, so the boundary fell back to the entry's own
    /// directory. Enough to run a self-contained program; not enough to say
    /// where a package would come from.
    EntryDirectory(PathBuf),
}

impl Root {
    pub fn path(&self) -> &Path {
        match self {
            Root::Declared(path) | Root::EntryDirectory(path) => path,
        }
    }

    /// Whether a bare specifier may be resolved against this root.
    pub fn packages_resolvable(&self) -> bool {
        matches!(self, Root::Declared(_))
    }
}

impl std::ops::Deref for Root {
    type Target = Path;
    fn deref(&self) -> &Path {
        self.path()
    }
}

impl AsRef<Path> for Root {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

/// Reduce a resolved path to the project-relative specifier that identifies it,
/// refusing anything that does not live inside the root.
///
/// **This is the one place a path becomes a module identity**, and both arms of
/// `resolve` go through it, because two things depend on a file having exactly
/// one name:
///
/// - *Containment.* Comparing canonical paths is what makes a symlink out of
///   the project an escape. A lexical check compares the *spelling*, and a
///   spelling can stay inside the root while the bytes come from outside it.
/// - *Authority.* Grants are keyed by specifier (LLP 0067 §2). If one file has
///   two names it has two grant sets, and a module locked down under one name
///   holds the default's authority under the other. That is a capability
///   bypass, not a cosmetic inconsistency.
///
/// Canonicalizing also settles case on a case-insensitive filesystem, so
/// `./LOCKED.js` and `./locked.js` are one module rather than two.
///
/// Fails closed: a path that cannot be canonicalized is refused rather than
/// falling back to its spelling.
///
/// @ref LLP 0065#2-node_modules-is-inside-the-project-not-a-hole-in-it
fn contain(root: &Path, path: &Path, specifier: &str) -> Result<String, String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|e| format!("project root {} cannot be resolved: {e}", root.display()))?;
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("cannot resolve {specifier:?}: {e}"))?;
    let relative = canonical.strip_prefix(&canonical_root).map_err(|_| {
        format!(
            "{specifier:?} resolves outside the project root: {}",
            canonical.display()
        )
    })?;
    Ok(format!(
        "./{}",
        relative.to_string_lossy().replace('\\', "/")
    ))
}

pub fn resolve(root: &Root, from: &str, specifier: &str) -> Result<String, String> {
    if !specifier.starts_with("./") && !specifier.starts_with("../") {
        return resolve_bare(root, from, specifier);
    }

    let from_dir = Path::new(from).parent().unwrap_or(Path::new(""));
    let joined = from_dir.join(specifier);

    // Normalize without touching the filesystem: `..` is resolved lexically so
    // a symlink cannot change what containment means.
    let mut parts: Vec<String> = Vec::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(format!("{specifier:?} escapes the project root"));
                }
            }
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("{specifier:?} must be relative"))
            }
        }
    }

    let relative = parts.join("/");
    // Belt and braces: the lexical walk above already refuses escapes, and this
    // catches anything a future change to it might miss.
    if !root.join(&relative).starts_with(root) {
        return Err(format!("{specifier:?} escapes the project root"));
    }

    // An extension may be omitted, and TypeScript's is not the one on disk:
    // `import './x'` in a TypeScript project means `x.ts`, and `import './x.js'`
    // conventionally means `x.ts` too, because TypeScript makes you write the
    // OUTPUT extension in the source. Both have to resolve or a TypeScript
    // codebase cannot import anything.
    if let Some(resolved) = probe_extensions(root, &relative) {
        // Through `contain`, not straight out: the lexical walk above proves
        // the *spelling* stays inside the root, which says nothing about where
        // a symlink at that spelling points. Returning here directly is how a
        // package could `require('./payload')` and execute bytes from outside
        // the project under an inside name.
        return contain(root, &root.join(&resolved), specifier);
    }

    // Nothing on disk. Return the specifier as written so the error names what
    // the author asked for rather than the last candidate tried.
    let fallback = if EXTENSIONS.iter().any(|ext| relative.ends_with(ext)) {
        relative
    } else {
        format!("{relative}.js")
    };
    Ok(format!("./{fallback}"))
}

/// Resolve a package specifier through Node resolution, then contain it.
///
/// @ref LLP 0065#2-node_modules-is-inside-the-project-not-a-hole-in-it — containment
/// still applies, and matters more here because resolution walks upward
fn resolve_bare(root: &Root, from: &str, specifier: &str) -> Result<String, String> {
    // A package name is a question about the project, and without a declared
    // root there is no project to ask — only the directory this file happens
    // to sit in. Refuse, and say what would fix it. Guessing here is how a
    // containment boundary silently becomes the home directory.
    if !root.packages_resolvable() {
        return Err(format!(
            "cannot resolve package {specifier:?}: no project root was declared, so there is \
             nowhere to look for it. Pass --root <dir> naming the directory that contains both \
             {from} and node_modules"
        ));
    }

    // Anything with a scheme is not a package name, and the two kinds fail for
    // different reasons — so they say different things. `node:`/`bun:` name
    // builtin namespaces this runtime does not have; a URL names a module to be
    // fetched, which no amount of node_modules searching will find. Reporting
    // either as "not installed" sends the reader looking in the wrong place.
    if let Some((scheme, _)) = specifier.split_once(':') {
        return Err(match scheme {
            "node" | "bun" => format!(
                "{specifier:?} names the {scheme:?} builtin namespace, which this runtime does \
                 not provide (LLP 0059 §6)"
            ),
            _ => format!(
                "cannot resolve {specifier:?} from {from}: modules are loaded from the project, \
                 not over {scheme:?}"
            ),
        });
    }

    let from_dir = root.join(
        Path::new(from.trim_start_matches("./"))
            .parent()
            .unwrap_or(Path::new("")),
    );

    let options = oxc_resolver::ResolveOptions {
        condition_names: CONDITIONS.iter().map(|c| (*c).to_string()).collect(),
        extensions: EXTENSIONS.iter().map(|e| (*e).to_string()).collect(),
        // `module` before `main`: the ESM entry where a package offers one.
        main_fields: vec!["module".to_string(), "main".to_string()],
        ..oxc_resolver::ResolveOptions::default()
    };
    let resolved = oxc_resolver::Resolver::new(options)
        .resolve(&from_dir, specifier)
        .map_err(|e| format!("cannot resolve {specifier:?} from {from}: {e}"))?;

    // `path()`, not `full_path()`: the latter appends `?query` and `#fragment`
    // to the filesystem path, so a package whose exports target is
    // `./index.js?raw` — a real bundler convention — would "resolve" to a name
    // no file has, pass containment on the laundered string, and only fail
    // later at the read.
    //
    // Containment matters more on this arm than the other: Node resolution
    // walks UP the directory tree, so without it a package could resolve to a
    // node_modules outside the project entirely.
    contain(root, resolved.path(), specifier)
}

/// Extensions tried, in order. TypeScript first: in a project that has both,
/// the `.ts` is the source and the `.js` is build output.
/// `.json` is last, as in Node: a `.js` sibling wins for an extensionless
/// specifier. It is here at all because Exact's boot graph imports JSON —
/// `@exact/core`'s colour policy is the first module `main.tsx` reaches that
/// is not JavaScript — and a resolver that cannot find `data.json` behind
/// `require('pkg/data')` reports a missing module for a file that exists.
pub const EXTENSIONS: &[&str] = &[".ts", ".tsx", ".mts", ".js", ".mjs", ".jsx", ".cjs", ".json"];

/// Find the file a specifier names, allowing for an omitted or rewritten
/// extension.
fn probe_extensions(root: &Path, relative: &str) -> Option<String> {
    let exists = |candidate: &str| {
        root.join(candidate)
            .is_file()
            .then(|| candidate.to_string())
    };

    // Exactly as written.
    if let Some(found) = exists(relative) {
        return Some(found);
    }

    // `./x.js` where the source is `./x.ts` — TypeScript's own convention of
    // writing the emitted extension in the import.
    for js in [".js", ".mjs", ".jsx"] {
        if let Some(stem) = relative.strip_suffix(js) {
            for ts in [".ts", ".tsx", ".mts"] {
                if let Some(found) = exists(&format!("{stem}{ts}")) {
                    return Some(found);
                }
            }
        }
    }

    // No extension at all.
    if !EXTENSIONS.iter().any(|ext| relative.ends_with(ext)) {
        for ext in EXTENSIONS {
            if let Some(found) = exists(&format!("{relative}{ext}")) {
                return Some(found);
            }
        }
        // A directory's index file.
        for ext in EXTENSIONS {
            if let Some(found) = exists(&format!("{relative}/index{ext}")) {
                return Some(found);
            }
        }
    }
    None
}

/// The names every module receives, in a fixed order.
///
/// Capability-bearing names are here — as PARAMETERS — and correspondingly not
/// on the global object. That is R1 and R2 in one list.
pub const MODULE_PARAMETERS: &[&str] = &[
    "module",
    "exports",
    "require",
    "fetch",
    "fs",
    "process",
    "__ibex2_meta",
];

/// Wrap module source in a function of its injected bindings.
///
/// The result is a function *expression*, evaluated by the host to obtain a
/// callable. `new Function` cannot be used: dynamic code is closed at
/// construction (LLP 0067 §4), which is also why this cannot be done from
/// JavaScript.
///
/// The trailing newline before `})` matters: a module whose last line is a
/// `//` comment would otherwise swallow the closing brace.
pub fn wrap(source: &str) -> String {
    format!(
        "(function ({}) {{\n{}\n}})",
        MODULE_PARAMETERS.join(", "),
        source
    )
}

/// Lower ES module syntax, then wrap.
///
/// One function, because the artifact key is computed over the wrapper text and
/// the wrapper must therefore be the LOWERED form. Two call sites producing the
/// wrapper differently would produce two keys for one module.
pub fn lower_and_wrap(source: &str, specifier: &str) -> Result<String, String> {
    let javascript = to_javascript(source, specifier)?;
    // Named, because the error reaches the author through a dynamic import's
    // rejection or a build failure, and "overlapping module declarations"
    // with no module is a search rather than a diagnosis.
    let lowered = crate::esm::lower(&javascript).map_err(|e| format!("{specifier}: {e}"))?;
    Ok(wrap(&lowered))
}

/// A module's source as JavaScript, before ESM lowering.
///
/// TypeScript first: the ESM lowering parses JavaScript, and a `.ts` module is
/// not JavaScript. Type stripping deliberately leaves module syntax alone, so
/// `esm::lower` still sees the imports and exports.
///
/// **Public because the build walk must scan this text, not the original.** The
/// JSX transform *injects* `import { jsx } from "react/jsx-runtime"`, which
/// does not appear in the `.tsx` a developer wrote. A dependency scan over the
/// original source cannot see that edge, so the module never gets compiled and
/// `run --precompiled` fails on a graph the build reported as complete.
pub fn to_javascript(source: &str, specifier: &str) -> Result<String, String> {
    if specifier.ends_with(".json") {
        Ok(json_module(source))
    } else if crate::typescript::needs_stripping(specifier) {
        crate::typescript::strip(source, specifier)
    } else {
        Ok(source.to_string())
    }
}

/// A JSON module: a CommonJS module whose `module.exports` is the parsed
/// value, so `import data from './x.json'` binds it through the default
/// interop and `require('./x.json')` returns it directly.
///
/// Parsed with `JSON.parse` at load rather than pasted in as an object
/// literal, because the two disagree: a literal `{"__proto__": …}` sets the
/// prototype where JSON gives an own property, and JSON's grammar is not a
/// subset of an expression's in every engine. Compiled to bytecode like any
/// other module, so a large JSON file is a string constant in the artifact and
/// costs one parse at load — the same as it would in Node.
///
/// Import attributes (`with { type: 'json' }`) are accepted and not required.
/// Node and the browser require them; Exact's own imports are split between
/// the two forms, and a bundler-targeted codebase does not get to be strict
/// about what its bundler never enforced. Named imports from a JSON module
/// are permitted for the same reason — the lowering destructures
/// `module.exports` — where the specification allows only `default`.
fn json_module(text: &str) -> String {
    format!("module.exports = JSON.parse({});", js_string_literal(text))
}

/// `text` as a double-quoted JavaScript string literal.
///
/// U+2028 and U+2029 are escaped even though ES2019 admits them in literals,
/// because the same text is also a build-time scan target and a bytecode
/// constant, and a line terminator inside a literal is what every tool that
/// splits on lines gets wrong.
fn js_string_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The global names a module may see. Anything outside this list on
/// `globalThis` after boot is an R1 violation.
///
/// Capability-bearing names are deliberately absent: they arrive as parameters.
pub const ALLOWED_GLOBALS: &[&str] = &[
    // The lowering's helpers, referenced by name from lowered module code.
    "__ibex2_default",
    "__ibex2_dynamic_import",
    "__ibex2_export_all",
    // Called by the pump, from the engine side, once per due timer.
    "__ibex2_fire_timer",
    "console",
    "setTimeout",
    "setInterval",
    "clearTimeout",
    "clearInterval",
    "performance",
    "queueMicrotask",
    "Headers",
    "URL",
    "URLSearchParams",
    "atob",
    "btoa",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{Grant, Operation, Origin};

    fn root() -> std::path::PathBuf {
        std::path::PathBuf::from("/project")
    }

    #[test]
    fn relative_specifiers_resolve_against_the_importing_module() {
        assert_eq!(
            resolve(&Root::Declared(root()), "./index.js", "./util").unwrap(),
            "./util.js"
        );
        assert_eq!(
            resolve(&Root::Declared(root()), "./a/b.js", "./c").unwrap(),
            "./a/c.js"
        );
        assert_eq!(
            resolve(&Root::Declared(root()), "./a/b.js", "../top").unwrap(),
            "./top.js"
        );
        assert_eq!(
            resolve(&Root::Declared(root()), "./a/b/c.js", "../../x.js").unwrap(),
            "./x.js"
        );
    }

    /// `node:` and `bun:` are builtin namespaces, not packages. LLP 0059 §6
    /// deleted Node's server surface, so the error should say that rather than
    /// "not found in node_modules".
    /// The JSX transform *injects* a dependency the developer never wrote, and
    /// the build walk scans `to_javascript` output for exactly that reason.
    /// Scanning the original `.tsx` misses the edge, so `react/jsx-runtime`
    /// never gets compiled and `run --precompiled` fails on a graph the build
    /// reported as complete — a failure that looks like a fast start when timed.
    ///
    /// Both shapes are covered because the transform emits different ones: a
    /// module gets an `import`, a script gets a `require`. A test over only one
    /// would leave half the walk unguarded.
    #[test]
    fn the_jsx_transform_injects_a_dependency_the_source_does_not_contain() {
        // Module form: the injected edge is an import.
        let module_source = "import { useState } from 'react';\nconst el = <div/>;";
        assert_eq!(
            crate::esm::dependencies(module_source, "./a.tsx"),
            vec!["react".to_string()],
            "the source itself imports only react"
        );
        let javascript = to_javascript(module_source, "./a.tsx").expect("strips");
        assert!(
            crate::esm::dependencies(&javascript, "./a.tsx")
                .iter()
                .any(|d| d == "react/jsx-runtime"),
            "the injected import must be visible to the build walk: {javascript}"
        );

        // Script form: no imports, so the transform reaches for require instead.
        let script_source = "const el = <div id=\"a\">hi</div>;";
        assert!(
            crate::esm::dependencies(script_source, "./a.tsx").is_empty(),
            "the source itself depends on nothing"
        );
        let javascript = to_javascript(script_source, "./a.tsx").expect("strips");
        assert!(
            javascript.contains("require(\"react/jsx-runtime\")"),
            "the injected require must be visible to the build walk: {javascript}"
        );
    }

    #[test]
    fn builtin_namespaces_are_refused_by_name() {
        let err = resolve(&Root::Declared(root()), "./index.js", "node:fs").unwrap_err();
        assert!(err.contains("builtin namespace"), "{err}");
        assert!(resolve(&Root::Declared(root()), "./index.js", "bun:test").is_err());
    }

    /// A URL is not a package and not a builtin, and saying otherwise sends the
    /// reader to `node_modules` for something that was never going to be there.
    #[test]
    fn a_url_specifier_is_refused_as_a_url() {
        let err = resolve(
            &Root::Declared(root()),
            "./index.js",
            "https://evil.example/m.js",
        )
        .unwrap_err();
        assert!(!err.contains("builtin namespace"), "{err}");
        assert!(err.contains("not over"), "{err}");
    }

    #[test]
    fn a_package_that_does_not_exist_is_a_resolution_error() {
        let err = resolve(&Root::Declared(root()), "./index.js", "lodash").unwrap_err();
        assert!(err.contains("cannot resolve"), "{err}");
    }

    /// Escaping the root is a resolution failure, not an fs.read question.
    #[test]
    fn escaping_the_project_root_is_refused() {
        assert!(resolve(&Root::Declared(root()), "./index.js", "../secrets").is_err());
        assert!(resolve(&Root::Declared(root()), "./index.js", "../../etc/passwd").is_err());
        assert!(resolve(&Root::Declared(root()), "./a/b.js", "../../../etc/passwd").is_err());
        assert!(resolve(&Root::Declared(root()), "./index.js", "/etc/passwd").is_err());
    }

    #[test]
    fn the_js_extension_is_added_but_not_doubled() {
        assert_eq!(
            resolve(&Root::Declared(root()), "./index.js", "./a").unwrap(),
            "./a.js"
        );
        assert_eq!(
            resolve(&Root::Declared(root()), "./index.js", "./a.js").unwrap(),
            "./a.js"
        );
    }

    /// A JSON module becomes `module.exports = JSON.parse("…")`: the text is
    /// carried as a string literal and parsed at load, never pasted in as an
    /// object literal. The text passes through the ESM lowering and the build
    /// walk's dependency scan untouched, however much it looks like code.
    #[test]
    fn a_json_module_is_parsed_not_evaluated() {
        let text = "{\"a\": \"line\\nbreak\"}\n";
        let out = to_javascript(text, "./x.json").unwrap();
        assert_eq!(
            out,
            "module.exports = JSON.parse(\"{\\\"a\\\": \\\"line\\\\nbreak\\\"}\\n\");"
        );
        assert!(
            to_javascript("\"\u{2028}\"", "./x.json").unwrap().contains("\\u2028"),
            "a line terminator inside the literal is escaped"
        );

        let looks_like_code = "{\"k\": \"import a from './b'; require('./c')\"}";
        let javascript = to_javascript(looks_like_code, "./x.json").unwrap();
        assert!(crate::esm::dependencies(&javascript, "./x.json").is_empty());
        assert_eq!(crate::esm::lower(&javascript).unwrap(), javascript);
        assert!(lower_and_wrap(looks_like_code, "./x.json").unwrap().contains("JSON.parse("));
    }

    #[test]
    fn a_wrapped_module_ends_cleanly_after_a_trailing_comment() {
        let wrapped = wrap("exports.x = 1; // trailing comment");
        assert!(wrapped.ends_with("\n})"), "{wrapped}");
        assert!(wrapped.starts_with(
            "(function (module, exports, require, fetch, fs, process, __ibex2_meta) {"
        ));
    }

    #[test]
    fn capability_names_are_parameters_and_not_globals() {
        for capability in ["fetch", "fs"] {
            assert!(MODULE_PARAMETERS.contains(&capability));
            assert!(
                !ALLOWED_GLOBALS.contains(&capability),
                "{capability} must not be reachable from the global object (LLP 0067 R1)"
            );
        }
    }

    #[test]
    fn a_module_without_an_entry_gets_the_default_and_the_default_is_nothing() {
        let grants = ModuleGrants::none();
        assert!(grants.for_module("./anything.js").is_empty());
    }

    #[test]
    fn a_manifest_gives_each_module_its_own_authority() {
        let grants = ModuleGrants::parse(
            "[*]\n\
             [./net.js]\n\
             net.fetch https://api.example.com\n\
             [./storage.js]\n\
             fs.read /data\n",
        )
        .unwrap();

        let api = Operation::Fetch {
            origin: Origin::new("https", "api.example.com", 443),
        };
        assert!(grants.for_module("./net.js").permits(&api));
        assert!(!grants.for_module("./storage.js").permits(&api));
        assert!(!grants.for_module("./other.js").permits(&api));

        let data = Operation::FsRead {
            path: "/data/x".into(),
        };
        assert!(grants.for_module("./storage.js").permits(&data));
        assert!(!grants.for_module("./net.js").permits(&data));
    }

    #[test]
    fn a_default_section_applies_only_where_there_is_no_entry() {
        let grants = ModuleGrants::parse(
            "[*]\n\
             net.fetch https://common.example.com\n\
             [./locked.js]\n",
        )
        .unwrap();
        let common = Operation::Fetch {
            origin: Origin::new("https", "common.example.com", 443),
        };
        assert!(grants.for_module("./anything.js").permits(&common));
        assert!(
            !grants.for_module("./locked.js").permits(&common),
            "an explicit empty section must not inherit the default"
        );
    }

    #[test]
    fn a_bad_manifest_is_refused() {
        assert!(ModuleGrants::parse("[./a.js]\nnonsense.cap x\n").is_err());
        assert!(ModuleGrants::parse("[./a.js]\nnet.fetch not-a-url\n").is_err());
    }

    #[test]
    fn grants_compose_from_the_spec_format_the_binding_already_uses() {
        let grants = ModuleGrants::none().with_module(
            "./a.js",
            GrantSet::none().with(Grant::Fetch(Origin::new("https", "x.test", 443))),
        );
        assert!(grants.for_module("./a.js").permits(&Operation::Fetch {
            origin: Origin::new("https", "x.test", 443)
        }));
    }

    /// The package is named by its path, and only by its path.
    #[test]
    fn a_package_is_named_by_its_innermost_node_modules_segment() {
        assert_eq!(package_of("./node_modules/react/index.js").as_deref(), Some("react"));
        assert_eq!(package_of("./node_modules/react/cjs/react.js").as_deref(), Some("react"));
        assert_eq!(package_of("./node_modules/@w/ui/index.js").as_deref(), Some("@w/ui"));
        // A nested copy, and pnpm's layout, are still `react`.
        assert_eq!(
            package_of("./node_modules/a/node_modules/react/y.js").as_deref(),
            Some("react")
        );
        assert_eq!(
            package_of("./node_modules/.pnpm/react@19.0.0/node_modules/react/z.js").as_deref(),
            Some("react")
        );
        // A package directory is not a module; a first-party file has no package.
        assert_eq!(package_of("./node_modules/react"), None);
        assert_eq!(package_of("./node_modules/@w/ui"), None);
        assert_eq!(package_of("./src/index.js"), None);
        assert_eq!(package_of("./packages/ui/index.js"), None);
        // A directory that merely ends in the marker is not node_modules.
        assert_eq!(package_of("./xnode_modules/react/index.js"), None);
    }

    /// `[react]` covers every file of react and nothing beside it: not
    /// `react-dom`, not a sibling, not the module that imported it.
    #[test]
    fn a_package_section_covers_the_package_and_nothing_beside_it() {
        let grants = ModuleGrants::parse(
            "[*]\n[react]\nnet.fetch https://api.example.com\n[@w/ui]\nfs.read /data\n",
        )
        .unwrap();
        let api = Operation::Fetch {
            origin: Origin::new("https", "api.example.com", 443),
        };
        assert!(grants.for_module("./node_modules/react/index.js").permits(&api));
        assert!(grants.for_module("./node_modules/react/cjs/react.production.js").permits(&api));
        assert!(grants.for_module("./node_modules/x/node_modules/react/index.js").permits(&api));
        assert!(!grants.for_module("./node_modules/react-dom/index.js").permits(&api));
        assert!(!grants.for_module("./node_modules/evil/index.js").permits(&api));
        assert!(!grants.for_module("./index.js").permits(&api));
        let data = Operation::FsRead { path: "/data/x".into() };
        assert!(grants.for_module("./node_modules/@w/ui/index.js").permits(&data));
        assert!(!grants.for_module("./node_modules/@w/ui-extra/index.js").permits(&data));
        assert!(!grants.for_module("./node_modules/react/index.js").permits(&data));
    }

    /// Most specific wins, and nothing is combined: a file section beats its
    /// package's, a package section beats a directory covering it, the
    /// longest directory beats a shorter one, and `*` is last.
    #[test]
    fn the_most_specific_section_names_a_module_and_nothing_is_combined() {
        let grants = ModuleGrants::parse(
            "[*]\nnet.fetch https://star.test\n\
             [./src/]\nnet.fetch https://src.test\n\
             [./src/deep/]\nnet.fetch https://deep.test\n\
             [./node_modules/]\nnet.fetch https://nm.test\n\
             [react]\nnet.fetch https://react.test\n\
             [./node_modules/react/locked.js]\n",
        )
        .unwrap();
        let reaches = |module: &str, host: &str| {
            grants.for_module(module).permits(&Operation::Fetch {
                origin: Origin::new("https", host, 443),
            })
        };
        assert!(reaches("./src/a.js", "src.test") && !reaches("./src/a.js", "star.test"));
        assert!(reaches("./src/deep/b.js", "deep.test") && !reaches("./src/deep/b.js", "src.test"));
        assert!(reaches("./other.js", "star.test"));
        assert!(reaches("./node_modules/react/index.js", "react.test"));
        assert!(!reaches("./node_modules/react/index.js", "nm.test"), "package beats directory");
        assert!(reaches("./node_modules/lodash/index.js", "nm.test"));
        assert!(
            !reaches("./node_modules/react/locked.js", "react.test"),
            "an explicit empty file section inside a granted package still means nothing"
        );
    }

    #[test]
    fn a_section_that_names_nothing_is_refused() {
        for bad in ["[../x.js]", "[/etc/x.js]", "[node_modules/react]", "[react/]", "[@w]", "[@w/ui/x]", "[./]", "[./a/../b.js]"] {
            assert!(
                ModuleGrants::parse(&format!("{bad}\n")).is_err(),
                "{bad} should be refused"
            );
        }
        for good in ["[*]", "[./x.js]", "[./src/]", "[react]", "[@w/ui]", "[lodash.merge]"] {
            assert!(ModuleGrants::parse(&format!("{good}\n")).is_ok(), "{good} should parse");
        }
    }

    /// `bind` refuses a package that is not installed, and turns a workspace
    /// package — a symlink whose files live in the project's own tree — into
    /// the directory section its files actually match.
    #[test]
    fn bind_refuses_the_uninstalled_and_binds_workspace_packages_to_their_directory() {
        let root = std::env::temp_dir().join(format!("ibex2-bind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("node_modules/react")).unwrap();
        std::fs::write(root.join("node_modules/react/index.js"), "").unwrap();
        std::fs::create_dir_all(root.join("packages/ui")).unwrap();
        std::fs::write(root.join("packages/ui/index.js"), "").unwrap();
        std::fs::create_dir_all(root.join("node_modules/@w")).unwrap();
        std::os::unix::fs::symlink(root.join("packages/ui"), root.join("node_modules/@w/ui")).unwrap();

        let api = Operation::Fetch {
            origin: Origin::new("https", "api.example.com", 443),
        };
        let mut grants =
            ModuleGrants::parse("[react]\nnet.fetch https://api.example.com\n[@w/ui]\nnet.fetch https://api.example.com\n")
                .unwrap();
        assert!(
            !grants.for_module("./packages/ui/index.js").permits(&api),
            "before bind the path does not name the workspace package"
        );
        grants.bind(&root).unwrap();
        assert!(grants.for_module("./packages/ui/index.js").permits(&api));
        assert!(grants.for_module("./node_modules/react/index.js").permits(&api));
        assert!(!grants.for_module("./packages/other/index.js").permits(&api));

        let err = ModuleGrants::parse("[nope]\nnet.fetch https://api.example.com\n")
            .unwrap()
            .bind(&root)
            .unwrap_err();
        assert!(err.contains("\"nope\"") && err.contains("not installed"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
