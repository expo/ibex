//! Package resolution, containment, and the standard-library surface a
//! real dependency graph needs.
//!
//! Split from `tests/loader.rs` when it outgrew the line cap.
#![cfg(feature = "hermes")]

mod common;

use common::Project;
use ibex2::engine::hermes::{DynamicCode, Hermes};
use ibex2::loader::{ModuleGrants, Root};

// ---------------------------------------------------------------------------
// Package resolution.
//
// Bare specifiers go through `oxc_resolver`, which implements Node resolution
// including `exports` maps and condition matching. These tests are the reason
// to trust that: they build real packages on disk and require them.
// ---------------------------------------------------------------------------

/// The plain case: `main`, and exports flowing back out.
#[test]
fn a_package_resolves_through_its_main_field() {
    let p = Project::new("pkg-main");
    p.file("index.js", "console.log(require('tiny').shout('hi'));")
        .file(
            "node_modules/tiny/package.json",
            r#"{"name":"tiny","version":"1.0.0","main":"lib/index.js"}"#,
        )
        .file(
            "node_modules/tiny/lib/index.js",
            "exports.shout = s => s.toUpperCase();",
        );
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["HI"]);
}

/// A package with no `main` at all falls back to `index.js`, which is a real
/// part of the algorithm and not something to reimplement by hand.
#[test]
fn a_package_without_a_main_field_falls_back_to_index() {
    let p = Project::new("pkg-index");
    p.file("index.js", "console.log(require('bare').value);")
        .file("node_modules/bare/package.json", r#"{"name":"bare"}"#)
        .file("node_modules/bare/index.js", "exports.value = 'found';");
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["found"]);
}

/// `exports` maps are the modern surface, and `node` must never be selected:
/// LLP 0059 §6 deleted Node's server surface, so a Node build would be written
/// against modules that do not exist here. Listed FIRST in the package, so this
/// fails if `node` is ever added to `CONDITIONS`.
#[test]
fn the_node_condition_is_never_selected() {
    let p = Project::new("pkg-exports");
    p.file("index.js", "console.log(require('conditional').which);")
        .file(
            "node_modules/conditional/package.json",
            r#"{"name":"conditional","exports":{".":{"node":"./node.js","import":"./esm.js","require":"./cjs.js","default":"./default.js"}}}"#,
        )
        .file("node_modules/conditional/node.js", "exports.which = 'node';")
        .file(
            "node_modules/conditional/esm.js",
            "export const which = 'esm';",
        )
        .file("node_modules/conditional/cjs.js", "exports.which = 'cjs';")
        .file(
            "node_modules/conditional/default.js",
            "exports.which = 'default';",
        );
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["esm"]);
}

/// **`CONDITIONS` is a set, not a preference order.** Matching walks the
/// package's own `exports` keys, so a package listing `require` before
/// `import` gets CommonJS regardless of the order in our list. Worth pinning,
/// because the natural reading of `["import","require","default"]` is a
/// ranking and it is not one — reordering it changes nothing.
#[test]
fn a_packages_own_key_order_decides_between_import_and_require() {
    let p = Project::new("pkg-order");
    p.file("index.js", "console.log(require('pkg').which);")
        .file(
            "node_modules/pkg/package.json",
            r#"{"name":"pkg","exports":{".":{"require":"./cjs.js","import":"./esm.js"}}}"#,
        )
        .file("node_modules/pkg/cjs.js", "exports.which = 'cjs';")
        .file("node_modules/pkg/esm.js", "export const which = 'esm';");
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["cjs"], "the package's key order should decide");
}

/// The cost of omitting `node`, as a test rather than something to be
/// discovered later: a package exporting **only** a `node` build does not fall
/// through to anything. It fails to resolve, and the error names the
/// conditions so a reader can see why.
#[test]
fn a_package_exporting_only_node_does_not_resolve() {
    let p = Project::new("pkg-onlynode");
    p.file("index.js", "require('o');")
        .file(
            "node_modules/o/package.json",
            r#"{"name":"o","exports":{".":{"node":"./node.js"}}}"#,
        )
        .file("node_modules/o/node.js", "exports.w = 'node';");
    let (_, err) = p.run("./index.js", "");
    let err = err.expect("a node-only package must not resolve");
    assert!(err.contains("not exported under the conditions"), "{err}");
}

/// Subpath exports, and the fact that a package can hide files: a subpath not
/// listed in the map is not reachable, which is the package's own decision and
/// the loader must honor it rather than falling back to a raw file read.
#[test]
fn subpath_exports_are_honored_including_what_they_conceal() {
    let p = Project::new("pkg-subpath");
    p.file("index.js", "console.log(require('lib/public').ok);")
        .file(
            "node_modules/lib/package.json",
            r#"{"name":"lib","exports":{"./public":"./src/public.js"}}"#,
        )
        .file("node_modules/lib/src/public.js", "exports.ok = 'public';")
        .file("node_modules/lib/src/private.js", "exports.ok = 'private';");
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["public"]);

    let p2 = Project::new("pkg-subpath-hidden");
    p2.file("index.js", "require('lib/src/private');")
        .file(
            "node_modules/lib/package.json",
            r#"{"name":"lib","exports":{"./public":"./src/public.js"}}"#,
        )
        .file("node_modules/lib/src/private.js", "exports.ok = 'private';");
    let (_, err) = p2.run("./index.js", "");
    assert!(err.is_some(), "an unexported subpath must not resolve");
}

/// Scoped packages, which is what `@exact/*` are.
#[test]
fn a_scoped_package_resolves() {
    let p = Project::new("pkg-scoped");
    p.file("index.js", "console.log(require('@scope/pkg').id);")
        .file(
            "node_modules/@scope/pkg/package.json",
            r#"{"name":"@scope/pkg","main":"main.js"}"#,
        )
        .file("node_modules/@scope/pkg/main.js", "exports.id = 'scoped';");
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["scoped"]);
}

/// A package can require its own dependencies, resolved from *its* directory
/// rather than the entry's. This is the part hand-rolled resolvers get wrong.
#[test]
fn a_package_resolves_its_own_dependencies_from_its_own_directory() {
    let p = Project::new("pkg-nested");
    p.file("index.js", "console.log(require('outer').run());")
        .file(
            "node_modules/outer/package.json",
            r#"{"name":"outer","main":"index.js"}"#,
        )
        .file(
            "node_modules/outer/index.js",
            "const inner = require('inner'); exports.run = () => inner.tag + '/outer';",
        )
        .file(
            "node_modules/outer/node_modules/inner/package.json",
            r#"{"name":"inner","main":"index.js"}"#,
        )
        .file(
            "node_modules/outer/node_modules/inner/index.js",
            "exports.tag = 'inner';",
        );
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["inner/outer"]);
}

/// Workspace packages are symlinks into the monorepo, and `@exact/*` — the
/// dominant case in the real graph — are exactly that. The link is followed and
/// the module's identity is its real path, so the same file has one name however
/// it is reached (see `two_spellings_of_one_file_are_one_module_with_one_grant_set`).
/// It resolves only because the target is inside the root.
#[cfg(unix)]
#[test]
fn a_workspace_symlink_resolves_to_its_real_path() {
    let p = Project::new("pkg-workspace");
    p.file("index.js", "console.log(require('@w/ui').name);")
        .file(
            "packages/ui/package.json",
            r#"{"name":"@w/ui","main":"index.js"}"#,
        )
        .file("packages/ui/index.js", "exports.name = 'workspace-ui';");
    std::fs::create_dir_all(p.0.join("node_modules/@w")).unwrap();
    std::os::unix::fs::symlink(p.0.join("packages/ui"), p.0.join("node_modules/@w/ui")).unwrap();

    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["workspace-ui"]);
    // And the identity is the real path, not the node_modules spelling.
    assert_eq!(
        ibex2::loader::resolve(&Root::Declared(p.0.clone()), "./index.js", "@w/ui").unwrap(),
        "./packages/ui/index.js"
    );
}

/// ES modules, TypeScript, and packages are one system, not three. A package
/// written in TypeScript, imported with `import`, re-exporting a dependency.
#[test]
fn a_typescript_package_imports_and_re_exports_through_esm() {
    let p = Project::new("pkg-ts-esm");
    p.file(
        "index.ts",
        "import { label } from 'ts-pkg';\nconsole.log(label({ n: 2 }));",
    )
    .file(
        "node_modules/ts-pkg/package.json",
        r#"{"name":"ts-pkg","exports":{".":{"import":"./src/index.ts"}}}"#,
    )
    .file(
        "node_modules/ts-pkg/src/index.ts",
        "export * from './label';",
    )
    .file(
        "node_modules/ts-pkg/src/label.ts",
        "interface Arg { n: number }\nexport const label = (a: Arg): string => `n=${a.n}`;",
    );
    let (out, err) = p.run("./index.ts", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["n=2"]);
}

/// The security property, and the reason resolution did not simply get turned
/// on. A package is a module like any other: it holds exactly the authority the
/// manifest names under its resolved specifier, and nothing by virtue of being
/// a dependency (LLP 0060 D1).
///
/// The probe is behavioural, not `typeof`. Every module is handed a `fetch`
/// parameter; what differs is the authority that parameter carries, so the
/// question "does this package have fetch?" is only answered by calling it.
/// The target is unroutable on purpose: a capability denial and a connection
/// failure are different answers, and neither needs the internet to tell them
/// apart.
#[test]
fn a_package_gets_no_authority_it_was_not_granted() {
    let p = Project::new("pkg-authority");
    p.file(
        "index.js",
        "require('greedy').probe().then(m => console.log('pkg: ' + m));",
    )
    .file(
        "node_modules/greedy/package.json",
        r#"{"name":"greedy","main":"index.js"}"#,
    )
    .file(
        "node_modules/greedy/index.js",
        "exports.probe = () => fetch('https://127.0.0.1:1/').then(
           () => 'REACHED', e => e.message);",
    );
    // The entry holds the capability; the package is named nowhere.
    let (out, err) = p.run(
        "./index.js",
        "[./index.js]\nnet.fetch https://127.0.0.1:1\n",
    );
    assert_eq!(err, None);
    assert_eq!(out, vec!["pkg: denied: net.fetch"]);
}

/// ...and the same package, once the manifest names it under its resolved
/// specifier, does get it. Grants key on where a module resolved to, so a
/// package is addressable without being ambient.
///
/// Reaching the transport at all is the assertion. The connection then fails,
/// which is the point: the capability check is behind us.
#[test]
fn a_package_can_be_granted_authority_under_its_resolved_specifier() {
    let p = Project::new("pkg-granted");
    p.file(
        "index.js",
        "require('needy').probe().then(m => console.log('pkg: ' + m));",
    )
    .file(
        "node_modules/needy/package.json",
        r#"{"name":"needy","main":"index.js"}"#,
    )
    .file(
        "node_modules/needy/index.js",
        "exports.probe = () => fetch('https://127.0.0.1:1/').then(
           () => 'REACHED', e => e.message);",
    );
    let (out, err) = p.run(
        "./index.js",
        "[./node_modules/needy/index.js]\nnet.fetch https://127.0.0.1:1\n",
    );
    assert_eq!(err, None);
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(
        !out[0].contains("denied"),
        "the granted package was denied: {out:?}"
    );
    assert!(
        out[0].contains("Failed to fetch"),
        "expected a transport failure, got: {out:?}"
    );
}

// --- Containment, probed adversarially -------------------------------------
//
// Resolution decides what code enters the process, so these are the tests that
// matter most. Each states the attack it represents, not just the API it calls.
// @ref LLP 0065#2-node_modules-is-inside-the-project-not-a-hole-in-it

/// A package whose `exports` target climbs out of the package. Refused by
/// Node's own rule that an exports target may not escape — so this asserts
/// oxc_resolver enforces it, rather than trusting that it does.
#[test]
fn an_exports_target_cannot_escape_its_package() {
    let p = Project::new("atk-exports-escape");
    p.file("index.js", "require('evil');").file(
        "node_modules/evil/package.json",
        r#"{"name":"evil","exports":{".":"../../../../../../etc/passwd"}}"#,
    );
    let (_, err) = p.run("./index.js", "");
    let err = err.expect("an escaping exports target must not resolve");
    assert!(err.contains("Invalid \"exports\" target"), "{err}");
}

/// An absolute specifier is neither relative nor a package name, and must not
/// become a way to name any file on the machine.
#[test]
fn an_absolute_specifier_is_refused() {
    let p = Project::new("atk-abs");
    p.file("index.js", "require('/etc/passwd');");
    let (_, err) = p.run("./index.js", "");
    let err = err.expect("an absolute specifier must not resolve");
    assert!(err.contains("outside the project root"), "{err}");
}

/// The attack containment exists for: Node resolution walks UP, so a package
/// installed above the project would otherwise be loaded without the author
/// ever having seen it.
#[test]
fn a_package_above_the_project_root_is_refused() {
    let outer = std::env::temp_dir().join(format!("ibex2-atk-outer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outer);
    std::fs::create_dir_all(outer.join("node_modules/sneaky")).unwrap();
    std::fs::write(
        outer.join("node_modules/sneaky/package.json"),
        r#"{"name":"sneaky","main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(
        outer.join("node_modules/sneaky/index.js"),
        "exports.x = 'LOADED FROM ABOVE THE ROOT';",
    )
    .unwrap();
    let root = outer.join("project");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("index.js"), "require('sneaky');").unwrap();

    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    assert!(rt.install_stdlib());
    rt.install_bindings().expect("bindings");
    rt.set_loader(Root::Declared(root.clone()), ModuleGrants::none());
    let err = rt.run_entry("./index.js").err().map(|e| e.0);
    let _ = std::fs::remove_dir_all(&outer);
    let err = err.expect("a package above the root must not resolve");
    assert!(err.contains("outside the project root"), "{err}");
}

/// A symlink out of the project is refused, because containment is checked
/// against the *canonical* path in `loader::contain`. Worth asserting
/// explicitly: the protection is the canonicalize, not the resolver, and would
/// be lost if identity ever went back to being the requested spelling.
#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_project_is_refused() {
    let p = Project::new("atk-symlink");
    p.file("index.js", "require('esc');");
    let outside = std::env::temp_dir().join(format!("ibex2-atk-outside-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(
        outside.join("package.json"),
        r#"{"name":"esc","main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(outside.join("index.js"), "exports.x = 'ESCAPED';").unwrap();
    std::fs::create_dir_all(p.0.join("node_modules")).unwrap();
    std::os::unix::fs::symlink(&outside, p.0.join("node_modules/esc")).unwrap();
    let (_, err) = p.run("./index.js", "");
    let _ = std::fs::remove_dir_all(&outside);
    let err = err.expect("a symlink out of the project must not resolve");
    assert!(err.contains("outside the project root"), "{err}");
}
/// A symlink *inside* a package, pointing outside the project. The package
/// itself is legitimately inside, so only the nested relative load can catch
/// this — and it did not, until both resolver arms shared one containment step.
///
/// Regression test for a confirmed escape: `require('./payload')` returned a
/// spelling inside the root while `read_to_string` followed the link and ran
/// bytes from outside it.
#[cfg(unix)]
#[test]
fn a_relative_symlink_inside_a_package_cannot_escape() {
    let p = Project::new("atk-relsym");
    p.file("index.js", "console.log(require('innocent').x);")
        .file(
            "node_modules/innocent/package.json",
            r#"{"name":"innocent","main":"index.js"}"#,
        )
        .file(
            "node_modules/innocent/index.js",
            "exports.x = require('./payload').x;",
        );
    let outside = std::env::temp_dir().join(format!("ibex2-atk-evil-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("payload.js"), "exports.x = 'ESCAPED';").unwrap();
    std::os::unix::fs::symlink(
        outside.join("payload.js"),
        p.0.join("node_modules/innocent/payload.js"),
    )
    .unwrap();

    let (out, err) = p.run("./index.js", "");
    let _ = std::fs::remove_dir_all(&outside);
    assert!(!out.iter().any(|l| l.contains("ESCAPED")), "{out:?}");
    let err = err.expect("a symlink out of the project must not resolve");
    assert!(err.contains("outside the project root"), "{err}");
}

/// One file, one identity — the property grants depend on.
///
/// A workspace package is reachable as `@w/ui` and as the literal path through
/// `node_modules`. If those are two specifiers they are two grant sets, and a
/// module locked down under one name silently inherits `[*]` under the other.
/// Regression test for a confirmed capability bypass.
#[cfg(unix)]
#[test]
fn two_spellings_of_one_file_are_one_module_with_one_grant_set() {
    let p = Project::new("atk-identity");
    p.file(
        "index.js",
        "const a = require('@w/ui');
         const b = require('./node_modules/@w/ui/index.js');
         a.probe('via-package'); b.probe('via-path');",
    )
    .file(
        "packages/ui/package.json",
        r#"{"name":"@w/ui","main":"index.js"}"#,
    )
    .file(
        "packages/ui/index.js",
        "exports.probe = (tag) => fetch('https://127.0.0.1:1/').then(
           () => console.log(tag + ': REACHED'), e => console.log(tag + ': ' + e.message));",
    );
    std::fs::create_dir_all(p.0.join("node_modules/@w")).unwrap();
    std::os::unix::fs::symlink(p.0.join("packages/ui"), p.0.join("node_modules/@w/ui")).unwrap();

    // Everything is granted by default; this one module is locked down.
    let (out, err) = p.run(
        "./index.js",
        "[*]\nnet.fetch https://127.0.0.1:1\n[./packages/ui/index.js]\n",
    );
    assert_eq!(err, None);
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(
        out.iter().all(|l| l.contains("denied: net.fetch")),
        "the lockdown was bypassed by spelling: {out:?}"
    );
}

/// Case is not identity either. macOS filesystems are case-insensitive by
/// default, so `./LOCKED.js` and `./locked.js` are the same file — and must be
/// the same module, or the lockdown above is bypassable by shifting a letter.
#[test]
fn case_variants_of_one_file_are_one_module() {
    let p = Project::new("atk-case");
    p.file(
        "index.js",
        "require('./locked.js').probe('lower'); require('./LOCKED.js').probe('upper');",
    )
    .file(
        "locked.js",
        "exports.probe = (tag) => fetch('https://127.0.0.1:1/').then(
           () => console.log(tag + ': REACHED'), e => console.log(tag + ': ' + e.message));",
    );
    let (out, err) = p.run(
        "./index.js",
        "[*]\nnet.fetch https://127.0.0.1:1\n[./locked.js]\n",
    );
    assert_eq!(err, None);
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(
        out.iter().all(|l| l.contains("denied: net.fetch")),
        "the lockdown was bypassed by case: {out:?}"
    );
}

/// `exports` targets carrying `?query` are a real bundler convention. The
/// resolver must hand back a path that names a file, not one with the query
/// concatenated onto it — that laundered string passes containment and then
/// fails at the read, far from the cause.
#[test]
fn a_query_string_does_not_survive_into_the_resolved_path() {
    let p = Project::new("atk-query");
    p.file("index.js", "x")
        .file(
            "node_modules/q/package.json",
            r#"{"name":"q","exports":{".":"./index.js?raw"}}"#,
        )
        .file("node_modules/q/index.js", "exports.x = 1;");
    let resolved = ibex2::loader::resolve(&Root::Declared(p.0.clone()), "./index.js", "q")
        .expect("should resolve");
    assert_eq!(resolved, "./node_modules/q/index.js");
}

// --- The root must be declared ----------------------------------------------

/// Without a declared root there is no project, so a package name has nowhere
/// to resolve. It is refused rather than guessed at, and the message says what
/// would fix it — a resolution failure the author can act on beats a boundary
/// silently widened to wherever a `package.json` happened to sit.
///
/// @ref LLP 0065#5-the-root-must-be-declared
#[test]
fn a_bare_specifier_is_refused_when_no_root_was_declared() {
    let p = Project::new("noroot");
    p.file("index.js", "require('tiny');").file(
        "node_modules/tiny/package.json",
        r#"{"name":"tiny","main":"index.js"}"#,
    );
    // The package is right there on disk; what is missing is the declaration.
    std::fs::write(p.0.join("node_modules/tiny/index.js"), "exports.x = 1;").unwrap();

    let err = ibex2::loader::resolve(&Root::EntryDirectory(p.0.clone()), "./index.js", "tiny")
        .expect_err("a package must not resolve without a declared root");
    assert!(err.contains("no project root was declared"), "{err}");
    assert!(
        err.contains("--root"),
        "the message must say what fixes it: {err}"
    );
}

/// Relative specifiers are unaffected: a self-contained program runs without
/// anyone declaring anything. Only package resolution needs a project.
#[test]
fn relative_specifiers_still_work_without_a_declared_root() {
    let p = Project::new("noroot-rel");
    p.file("index.js", "x")
        .file("lib/helper.js", "exports.x = 1;");
    let root = Root::EntryDirectory(p.0.clone());
    assert_eq!(
        ibex2::loader::resolve(&root, "./index.js", "./lib/helper").unwrap(),
        "./lib/helper.js"
    );
    // ...and containment still applies to them.
    assert!(ibex2::loader::resolve(&root, "./index.js", "../../../etc/passwd").is_err());
}

/// The monorepo layout, which is the reason `--root` exists: the entry is in
/// `apps/mobile`, dependencies are hoisted to the repository root, workspace
/// packages live in `packages/`. Declaring the root resolves both.
#[cfg(unix)]
#[test]
fn a_declared_root_resolves_a_monorepo() {
    let repo = std::env::temp_dir().join(format!("ibex2-monorepo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&repo);
    let w = |path: &str, contents: &str| {
        let full = repo.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, contents).unwrap();
    };
    w("apps/mobile/index.js", "x");
    w(
        "packages/ui/package.json",
        r#"{"name":"@x/ui","main":"index.js"}"#,
    );
    w("packages/ui/index.js", "exports.name = 'workspace';");
    w(
        "node_modules/vendor/package.json",
        r#"{"name":"vendor","main":"index.js"}"#,
    );
    w("node_modules/vendor/index.js", "exports.name = 'hoisted';");
    std::fs::create_dir_all(repo.join("node_modules/@x")).unwrap();
    std::os::unix::fs::symlink(repo.join("packages/ui"), repo.join("node_modules/@x/ui")).unwrap();

    let entry = "./apps/mobile/index.js";

    // Undeclared, the root is apps/mobile and everything is above it.
    let narrow = Root::EntryDirectory(repo.join("apps/mobile"));
    assert!(ibex2::loader::resolve(&narrow, "./index.js", "@x/ui").is_err());

    // Declared at the repository root, both resolve — and the workspace
    // package resolves to its real path, which is its grant key.
    let declared = Root::Declared(repo.canonicalize().unwrap());
    assert_eq!(
        ibex2::loader::resolve(&declared, entry, "@x/ui").unwrap(),
        "./packages/ui/index.js"
    );
    assert_eq!(
        ibex2::loader::resolve(&declared, entry, "vendor").unwrap(),
        "./node_modules/vendor/index.js"
    );
    let _ = std::fs::remove_dir_all(&repo);
}

// --- process.env ------------------------------------------------------------

/// `process.env` is a snapshot of exactly the granted variables (LLP 0059.000
/// §3.8), so an ungranted one is undefined because it is *absent*, not because
/// a check refused it. Uses `PATH`, which every environment has, so the test
/// never has to mutate the process environment.
#[test]
fn process_env_contains_only_the_granted_variables() {
    let p = Project::new("env-granted");
    p.file(
        "index.js",
        "console.log(typeof process.env.PATH);
         console.log(JSON.stringify(Object.keys(process.env)));",
    );
    let (out, err) = p.run("./index.js", "[*]\nenv.read PATH\n");
    assert_eq!(err, None);
    assert_eq!(out, vec!["string", "[\"PATH\"]"]);
}

/// The supply-chain case LLP 0059.000 §3.8 names: a package reading a secret it
/// was never granted. It cannot even enumerate it — `Object.keys` is empty, so
/// there is nothing to probe for.
#[test]
fn an_ungranted_variable_is_not_even_enumerable() {
    let p = Project::new("env-ungranted");
    p.file(
        "index.js",
        "console.log(String(process.env.PATH));
         console.log(JSON.stringify(Object.keys(process.env)));",
    );
    let (out, err) = p.run("./index.js", "[*]\n");
    assert_eq!(err, None);
    assert_eq!(out, vec!["undefined", "[]"]);
}

/// Authority is per module, and `process` is no exception: a dependency does
/// not inherit the entry's environment access.
#[test]
fn each_module_gets_its_own_environment_snapshot() {
    let p = Project::new("env-per-module");
    p.file(
        "index.js",
        "console.log('entry:' + typeof process.env.PATH);
             require('./dep');",
    )
    .file("dep.js", "console.log('dep:' + typeof process.env.PATH);");
    let (out, err) = p.run("./index.js", "[./index.js]\nenv.read PATH\n");
    assert_eq!(err, None);
    assert_eq!(out, vec!["entry:string", "dep:undefined"]);
}

// --- MessageChannel ---------------------------------------------------------

/// Delivery must be a **task**, not a microtask. React's server renderer uses
/// a MessageChannel precisely to yield to the event loop, so delivering on the
/// microtask queue would starve what the caller was trying to let through.
///
/// The ordering below is the assertion: a promise callback queued before the
/// message must run first, because microtasks drain before the next task.
#[test]
fn a_message_is_delivered_as_a_task_not_a_microtask() {
    let p = Project::new("mc-task");
    p.file(
        "index.js",
        "const c = new MessageChannel();
         c.port1.onmessage = () => console.log('message');
         c.port2.postMessage(null);
         Promise.resolve().then(() => console.log('microtask'));
         console.log('sync');",
    );
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["sync", "microtask", "message"]);
}

/// The scheduling idiom in full: a queue drained one entry per message, which
/// is what `scheduleWork` does in React's renderer.
#[test]
fn the_scheduling_idiom_drains_a_queue_in_order() {
    let p = Project::new("mc-idiom");
    p.file(
        "index.js",
        "const channel = new MessageChannel();
         const tasks = [];
         channel.port1.onmessage = () => { const t = tasks.shift(); t && t(); };
         const schedule = (fn) => { tasks.push(fn); channel.port2.postMessage(null); };
         schedule(() => console.log('one'));
         schedule(() => console.log('two'));
         schedule(() => console.log('three'));",
    );
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["one", "two", "three"]);
}

/// Ports are paired, and a message goes to the *peer*. A port that echoed to
/// itself would deadlock the idiom above rather than fail loudly.
#[test]
fn ports_deliver_to_their_peer_and_carry_data() {
    let p = Project::new("mc-pair");
    p.file(
        "index.js",
        "const c = new MessageChannel();
         c.port1.onmessage = (e) => console.log('p1 got ' + e.data);
         c.port2.onmessage = (e) => console.log('p2 got ' + e.data);
         c.port2.postMessage('a');
         c.port1.postMessage('b');",
    );
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["p1 got a", "p2 got b"]);
}

// --- JSX, end to end --------------------------------------------------------

/// TSX through the whole pipeline: type stripping, the JSX transform's
/// *injected* `react/jsx-runtime` import, package resolution of that import,
/// ESM lowering, and CommonJS interop with the package it lands on.
///
/// The runtime is a local stub rather than React, so the test pins the pipeline
/// and not a dependency — but this is the exact shape real React renders
/// through.
#[test]
fn tsx_resolves_the_injected_jsx_runtime_and_renders() {
    let p = Project::new("jsx-e2e");
    p.file(
        "app.tsx",
        "interface Props { label: string }
         function Item({ label }: Props) { return <li>{label}</li>; }
         const tree = <ul><Item label=\"a\" /></ul>;
         console.log(JSON.stringify(tree));",
    )
    .file(
        "node_modules/react/package.json",
        r#"{"name":"react","exports":{"./jsx-runtime":"./jsx-runtime.js"}}"#,
    )
    .file(
        "node_modules/react/jsx-runtime.js",
        "function render(type, props) {
           if (typeof type === 'function') return render.apply(null, [type(props).type, type(props).props]);
           const kids = props && props.children;
           const inner = kids === undefined ? ''
             : Array.isArray(kids) ? kids.map(String).join('')
             : typeof kids === 'object' ? JSON.stringify(kids) : String(kids);
           return { type: type, props: props };
         }
         exports.jsx = (type, props) => ({ type: typeof type === 'function' ? 'fn' : type,
                                           props: { children: props && props.children } });
         exports.jsxs = exports.jsx;",
    );
    let (out, err) = p.run("./app.tsx", "");
    assert_eq!(err, None);
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(out[0].contains("\"type\":\"ul\""), "{out:?}");
}

// ---------------------------------------------------------------------------
// Platform variants (LLP 0065 §8).
// ---------------------------------------------------------------------------

/// `x.native.js` shadows `x.js` when the platform says so, on both arms, and
/// never otherwise. Exact's boot graph has 22 such pairs, four of them on the
/// first import line of its entry; without this the runtime evaluates the web
/// build of a native app and every later finding is about the wrong program.
#[test]
fn a_platform_selects_suffixed_variants_on_both_arms() {
    let p = Project::new("platform");
    p.file(
        "index.js",
        "console.log([require('./greet').tag, require('./greet.js').tag, require('pkg').tag, \
         require('./only').tag].join(' '));",
    )
    .file("greet.js", "exports.tag = 'web-greet';")
    .file("greet.native.js", "exports.tag = 'native-greet';")
    .file("only.js", "exports.tag = 'only';")
    .file(
        "node_modules/pkg/package.json",
        r#"{"name":"pkg","main":"index.js"}"#,
    )
    .file("node_modules/pkg/index.js", "exports.tag = 'web-pkg';")
    .file("node_modules/pkg/index.native.js", "exports.tag = 'native-pkg';");
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["web-greet web-greet web-pkg only"], "no platform, no variant");
    let (out, err) = p.run_for("native", "./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["native-greet native-greet native-pkg only"]);
}

/// The chain: a platform tries its own suffix, then `native`; `web` tries only
/// itself. A file asked for by its suffixed name is returned as asked, and a
/// `.json` has no platform.
#[test]
fn the_variant_chain_is_platform_then_native_except_for_web() {
    use ibex2::loader::resolve_for;
    let p = Project::new("platform-chain");
    p.file("a.ts", "")
        .file("a.native.ts", "")
        .file("a.mac.tsx", "")
        .file("b.ts", "")
        .file("b.native.ts", "")
        .file("b.web.ts", "")
        .file("d.json", "{}")
        .file("d.native.json", "{}");
    let root = Root::Declared(p.0.clone());
    let r = |platform: Option<&str>, specifier: &str| {
        resolve_for(&root, platform, "./index.ts", specifier).unwrap()
    };
    assert_eq!(r(Some("mac"), "./a"), "./a.mac.tsx");
    assert_eq!(r(Some("ios"), "./a"), "./a.native.ts");
    assert_eq!(r(Some("native"), "./a.js"), "./a.native.ts", "through the .js -> .ts rewrite");
    assert_eq!(r(Some("web"), "./a"), "./a.ts", "web never takes a native file");
    assert_eq!(r(Some("web"), "./b"), "./b.web.ts");
    assert_eq!(r(Some("native"), "./b.web.ts"), "./b.web.ts", "asked for by name");
    assert_eq!(r(Some("native"), "./a.native.ts"), "./a.native.ts");
    assert_eq!(r(Some("native"), "./d.json"), "./d.json", "JSON has no platform");
    assert_eq!(r(None, "./a"), "./a.ts");
}

