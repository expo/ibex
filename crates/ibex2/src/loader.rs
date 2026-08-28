//! The module loader: resolution, wrapping, and per-module authority.
//!
//! This is where LLP 0062's requirements are actually enforced. R1 (nothing
//! capability-bearing on the global object), R2 (each module receives its
//! bindings as parameters of its own scope), and R5 (the global name list is
//! asserted) are properties of *this* file, not of the boundary below it.
//!
//! **v1 is CommonJS-shaped and loads from source.** Not because that is the
//! destination — LLP 0062 R3 requires wrappers compiled ahead of time, and
//! LLP 0057 §1 is a complaint about exactly the per-launch parsing this does —
//! but because it is the smallest loader that makes per-module injection real,
//! and because the boot measurement it enables is what motivates the AOT step.
//! ESM waits on a parser; see LLP 0026.
//!
//! @ref LLP 0058.000.000#6-module-binding-globals-and-bootstrap — module binding, globals, and bootstrap
//! @ref LLP 0060#1-the-decision — D2: capability-bearing bindings are injected, never ambient

use std::collections::BTreeMap;
use std::path::{Component, Path};

use crate::grant::GrantSet;

/// What a module is allowed to reach, and what it is called.
#[derive(Debug, Clone)]
pub struct ModuleGrants {
    /// Grants keyed by module specifier, resolved relative to the root.
    per_module: BTreeMap<String, GrantSet>,
    /// Applied to any module without its own entry.
    default_grants: GrantSet,
}

impl ModuleGrants {
    /// Nothing granted to anyone. The correct default: a module that was not
    /// named in the manifest reaches nothing, rather than inheriting whatever
    /// the application happened to hold.
    pub fn none() -> Self {
        Self {
            per_module: BTreeMap::new(),
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

    pub fn for_module(&self, specifier: &str) -> &GrantSet {
        self.per_module
            .get(specifier)
            .unwrap_or(&self.default_grants)
    }

    /// Parse a manifest: `[module-specifier]` sections of grant lines.
    ///
    /// ```text
    /// # applies to every module without its own section
    /// [*]
    /// # (nothing)
    ///
    /// [./net.js]
    /// net.fetch https://api.example.com
    /// ```
    ///
    /// Provisional, and LLP 0062 OQ1 is where that is recorded: whether grants
    /// belong in a manifest, the build graph, or import sites is undecided, and
    /// this is the simplest form that makes the loader real without foreclosing
    /// the others.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut grants = ModuleGrants::none();
        let mut section: Option<String> = None;
        let mut buffer = String::new();

        let flush = |grants: &mut ModuleGrants,
                     section: &Option<String>,
                     buffer: &str|
         -> Result<(), String> {
            let Some(name) = section else { return Ok(()) };
            let parsed = GrantSet::parse(buffer)?;
            if name == "*" {
                grants.default_grants = parsed;
            } else {
                grants.per_module.insert(name.clone(), parsed);
            }
            Ok(())
        };

        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(name) = trimmed.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                flush(&mut grants, &section, &buffer)?;
                buffer.clear();
                section = Some(name.trim().to_string());
                continue;
            }
            buffer.push_str(line);
            buffer.push('\n');
        }
        flush(&mut grants, &section, &buffer)?;
        Ok(grants)
    }
}

/// Resolve `specifier` as written inside `from`, against `root`.
///
/// Relative specifiers only in v1. Bare specifiers are refused rather than
/// silently searched: a resolution algorithm that walks `node_modules` is a
/// design decision (LLP 0059 §6 deleted Node's server surface), not a detail to
/// slip in here.
///
/// **Containment is enforced.** A resolved path must stay under the root, so
/// `require('../../../../etc/passwd')` fails at resolution rather than becoming
/// an fs.read question. Path reach is a capability concern (LLP 0059.000
/// §3.11), and the loader is not an exception to it.
pub fn resolve(root: &Path, from: &str, specifier: &str) -> Result<String, String> {
    if !specifier.starts_with("./") && !specifier.starts_with("../") {
        return Err(format!(
            "cannot resolve bare specifier {specifier:?}; only ./ and ../ are supported"
        ));
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

    let mut relative = parts.join("/");
    if !relative.ends_with(".js") {
        relative.push_str(".js");
    }
    // Belt and braces: the lexical walk above already refuses escapes, and this
    // catches anything a future change to it might miss.
    let full = root.join(&relative);
    if !full.starts_with(root) {
        return Err(format!("{specifier:?} escapes the project root"));
    }
    Ok(format!("./{relative}"))
}

/// The names every module receives, in a fixed order.
///
/// Capability-bearing names are here — as PARAMETERS — and correspondingly not
/// on the global object. That is R1 and R2 in one list.
pub const MODULE_PARAMETERS: &[&str] = &["module", "exports", "require", "fetch", "fs"];

/// Wrap module source in a function of its injected bindings.
///
/// The result is a function *expression*, evaluated by the host to obtain a
/// callable. `new Function` cannot be used: dynamic code is closed at
/// construction (LLP 0060 D4), which is also why this cannot be done from
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

/// The global names a module may see. Anything outside this list on
/// `globalThis` after boot is an R1 violation.
///
/// Capability-bearing names are deliberately absent: they arrive as parameters.
pub const ALLOWED_GLOBALS: &[&str] = &[
    "console",
    "setTimeout",
    "setInterval",
    "clearTimeout",
    "clearInterval",
    "performance",
    "Headers",
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
            resolve(&root(), "./index.js", "./util").unwrap(),
            "./util.js"
        );
        assert_eq!(resolve(&root(), "./a/b.js", "./c").unwrap(), "./a/c.js");
        assert_eq!(resolve(&root(), "./a/b.js", "../top").unwrap(), "./top.js");
        assert_eq!(
            resolve(&root(), "./a/b/c.js", "../../x.js").unwrap(),
            "./x.js"
        );
    }

    #[test]
    fn bare_specifiers_are_refused_rather_than_searched() {
        let err = resolve(&root(), "./index.js", "lodash").unwrap_err();
        assert!(err.contains("bare specifier"), "{err}");
        assert!(resolve(&root(), "./index.js", "node:fs").is_err());
    }

    /// Escaping the root is a resolution failure, not an fs.read question.
    #[test]
    fn escaping_the_project_root_is_refused() {
        assert!(resolve(&root(), "./index.js", "../secrets").is_err());
        assert!(resolve(&root(), "./index.js", "../../etc/passwd").is_err());
        assert!(resolve(&root(), "./a/b.js", "../../../etc/passwd").is_err());
        assert!(resolve(&root(), "./index.js", "/etc/passwd").is_err());
    }

    #[test]
    fn the_js_extension_is_added_but_not_doubled() {
        assert_eq!(resolve(&root(), "./index.js", "./a").unwrap(), "./a.js");
        assert_eq!(resolve(&root(), "./index.js", "./a.js").unwrap(), "./a.js");
    }

    #[test]
    fn a_wrapped_module_ends_cleanly_after_a_trailing_comment() {
        let wrapped = wrap("exports.x = 1; // trailing comment");
        assert!(wrapped.ends_with("\n})"), "{wrapped}");
        assert!(wrapped.starts_with("(function (module, exports, require, fetch, fs) {"));
    }

    #[test]
    fn capability_names_are_parameters_and_not_globals() {
        for capability in ["fetch", "fs"] {
            assert!(MODULE_PARAMETERS.contains(&capability));
            assert!(
                !ALLOWED_GLOBALS.contains(&capability),
                "{capability} must not be reachable from the global object (LLP 0062 R1)"
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
}
