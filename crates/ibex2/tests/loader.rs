//! The module loader, and the LLP 0062 requirements it is responsible for.
#![cfg(feature = "hermes")]

use std::path::PathBuf;

use ibex2::engine::hermes::{DynamicCode, Hermes};
use ibex2::loader::ModuleGrants;

struct Project(PathBuf);

impl Project {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ibex2-loader-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("project dir");
        Self(dir)
    }

    fn file(&self, name: &str, source: &str) -> &Self {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        std::fs::write(path, source).expect("write");
        self
    }

    fn run(&self, entry: &str, manifest: &str) -> (Vec<String>, Option<String>) {
        let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
        assert!(rt.install_stdlib());
        rt.install_bindings().expect("bindings");
        rt.set_loader(&self.0, ModuleGrants::parse(manifest).expect("manifest"));
        let error = rt.run_entry(entry).err().map(|e| e.0);
        rt.run_to_quiescence(std::time::Duration::from_secs(10));
        let output = rt.drain_console().into_iter().map(|r| r.message).collect();
        (output, error)
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn modules_require_each_other_and_exports_flow() {
    let p = Project::new("basic");
    p.file(
        "index.js",
        "const g = require('./greet'); console.log(g.hello('x'));",
    )
    .file("greet.js", "exports.hello = w => 'hello ' + w;");
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["hello x"]);
}

#[test]
fn module_exports_assignment_replaces_the_object() {
    let p = Project::new("replace");
    p.file("index.js", "console.log(require('./m')(2));")
        .file("m.js", "module.exports = n => n * 21;");
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["42"]);
}

/// A cycle returns partial exports rather than recursing forever, as CommonJS
/// does. Without the registry entry being made before evaluation, this hangs.
#[test]
fn a_require_cycle_terminates() {
    let p = Project::new("cycle");
    p.file(
        "index.js",
        "const a = require('./a'); console.log(a.name, a.peer);",
    )
    .file(
        "a.js",
        "exports.name = 'a'; exports.peer = require('./b').name;",
    )
    .file(
        "b.js",
        "exports.name = 'b'; exports.peer = require('./a').name;",
    );
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["a b"]);
}

/// LLP 0060 D2, end to end: two modules in one runtime, different authority.
#[test]
fn each_module_gets_only_the_authority_its_manifest_names() {
    let p = Project::new("grants");
    p.file(
        "index.js",
        "const net = require('./net');
         fetch('https://example.com/').then(
           () => console.log('index: LEAKED'),
           e => console.log('index: ' + e.message));
         net.probe();",
    )
    .file(
        "net.js",
        "exports.probe = () => fetch('https://example.com/').then(
           () => console.log('net: allowed'),
           e => console.log('net: ' + e.message));",
    );

    let (out, err) = p.run(
        "./index.js",
        "[*]\n[./net.js]\nnet.fetch https://example.com\n",
    );
    assert_eq!(err, None);
    assert!(
        out.iter().any(|l| l == "index: denied: net.fetch"),
        "the ungranted module was not denied: {out:?}"
    );
    assert!(
        out.iter().any(|l| l == "net: allowed"),
        "the granted module was denied: {out:?}"
    );
}

/// No manifest means no authority, not ambient authority.
#[test]
fn without_a_manifest_nothing_is_granted() {
    let p = Project::new("nogrants");
    p.file(
        "index.js",
        "fetch('https://example.com/').then(
           () => console.log('LEAKED'), e => console.log(e.message));",
    );
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["denied: net.fetch"]);
}

/// Path reach is a capability concern, so a traversal fails at resolution
/// rather than becoming a question about the filesystem.
#[test]
fn a_module_cannot_require_its_way_out_of_the_project() {
    let p = Project::new("traversal");
    p.file(
        "index.js",
        "try { require('../../../etc/passwd'); console.log('ESCAPED'); }
         catch (e) { console.log('refused'); }",
    );
    let (out, _) = p.run("./index.js", "");
    assert_eq!(out, vec!["refused"]);
}

#[test]
fn bare_specifiers_are_refused_with_a_useful_message() {
    let p = Project::new("bare");
    p.file(
        "index.js",
        "try { require('lodash'); } catch (e) { console.log(e.message); }",
    );
    let (out, _) = p.run("./index.js", "");
    assert!(out[0].contains("bare specifier"), "{out:?}");
}

/// LLP 0062 R1: after boot, no capability-bearing name is on the global object.
#[test]
fn no_capability_is_reachable_from_the_global_object() {
    let p = Project::new("r1");
    p.file("index.js", "");
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    assert!(rt.install_stdlib());
    rt.install_bindings().expect("bindings");
    rt.set_loader(&p.0, ModuleGrants::none());

    let globals = rt.global_names();
    for forbidden in ["fetch", "WebSocket", "localStorage", "process"] {
        assert!(
            !globals.iter().any(|n| n == forbidden),
            "{forbidden} is reachable from globalThis (R1): {globals:?}"
        );
    }
}

/// LLP 0062 R2: a module's `fetch` is its own, so one cannot use another's.
#[test]
fn a_module_cannot_borrow_another_modules_binding_by_name() {
    let p = Project::new("r2");
    p.file(
        "index.js",
        "require('./leaky');
         // The leaked binding is a real capability and works — handoff is out
         // of scope. What must NOT work is reaching it without the handoff.
         console.log(typeof globalThis.fetch);",
    )
    .file("leaky.js", "exports.mine = fetch;");
    let (out, err) = p.run("./index.js", "[*]\nnet.fetch https://example.com\n");
    assert_eq!(err, None);
    assert_eq!(out, vec!["undefined"]);
}
