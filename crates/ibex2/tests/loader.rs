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
        self.run_with(entry, manifest, None, false)
    }

    fn compiler(&self) -> Option<ibex2::bytecode::Compiler> {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        ibex2::bytecode::Compiler::discover(&root, self.0.join(".ibex2/cache")).ok()
    }

    fn engine_dir() -> std::path::PathBuf {
        match std::env::var("IBEX2_VANILLA_HERMES_DIR") {
            Ok(path) => std::path::PathBuf::from(path),
            Err(_) => std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../ios/Frameworks-vanilla"),
        }
    }

    fn run_with(
        &self,
        entry: &str,
        manifest: &str,
        compiler: Option<ibex2::bytecode::Compiler>,
        precompiled_only: bool,
    ) -> (Vec<String>, Option<String>) {
        let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
        assert!(rt.install_stdlib());
        rt.install_bindings().expect("bindings");
        rt.set_loader_with(
            &self.0,
            ModuleGrants::parse(manifest).expect("manifest"),
            compiler,
            precompiled_only,
        );
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

// --- Ahead-of-time bytecode -------------------------------------------------

/// The bytecode path must behave exactly as the source path does. If it does
/// not, everything measured about it is measuring a different program.
#[test]
fn bytecode_and_source_produce_identical_behaviour() {
    let p = Project::new("parity");
    p.file(
        "index.js",
        "const m = require('./m');
         console.log('sum', m.add(2, 3));
         console.log('exports replaced', typeof require('./r'));
         setTimeout(() => console.log('timer'), 5);",
    )
    .file("m.js", "exports.add = (a, b) => a + b;")
    .file("r.js", "module.exports = function () {};");

    let (source_out, source_err) = p.run("./index.js", "");
    let Some(compiler) = p.compiler() else { return };
    let (hbc_out, hbc_err) = p.run_with("./index.js", "", Some(compiler), false);

    assert_eq!(source_err, None);
    assert_eq!(hbc_err, None);
    assert_eq!(
        hbc_out, source_out,
        "bytecode diverged from source: {hbc_out:?} vs {source_out:?}"
    );
    assert!(source_out.iter().any(|l| l == "sum 5"));
}

/// The lifetime bug this caught, pinned. Hermes RETAINS a bytecode buffer for
/// the life of the module, so a borrowed buffer over a local leaves callbacks
/// executing against freed memory — and the failure is silent, because the
/// bytecode is gone rather than wrong. The synchronous body still runs, which
/// is what made it look like an async bug.
#[test]
fn a_callback_still_works_after_its_module_has_finished_loading() {
    let p = Project::new("lifetime");
    p.file(
        "index.js",
        "let done = false;
         setTimeout(() => { done = true; console.log('callback ran'); }, 5);
         Promise.resolve().then(() => console.log('microtask ran'));
         console.log('module body ran');",
    );
    let Some(compiler) = p.compiler() else { return };
    let (out, err) = p.run_with("./index.js", "", Some(compiler), false);
    assert_eq!(err, None);
    assert_eq!(
        out,
        vec!["module body ran", "microtask ran", "callback ran"],
        "a callback outliving its module's load lost its bytecode"
    );
}

/// `--precompiled` compiles nothing: the shipping posture rules/RULES.md wants.
#[test]
fn precompiled_only_refuses_what_was_not_built() {
    let p = Project::new("strict");
    p.file("index.js", "console.log('ran');");
    let Some(compiler) = p.compiler() else { return };

    let (_, err) = p.run_with("./index.js", "", Some(compiler.clone()), true);
    assert!(
        err.is_some_and(|e| e.contains("no precompiled artifact")),
        "strict mode compiled on demand"
    );

    // Build it, and the same run succeeds without compiling anything.
    let source = std::fs::read_to_string(p.0.join("index.js")).unwrap();
    compiler
        .compile(&ibex2::loader::wrap(&source))
        .expect("build");
    let (out, err) = p.run_with("./index.js", "", Some(compiler), true);
    assert_eq!(err, None);
    assert_eq!(out, vec!["ran"]);
}

/// Grants must not be an input to the artifact, or changing policy would mean
/// recompiling. The same module compiled under different manifests is one file.
#[test]
fn the_artifact_does_not_depend_on_the_modules_grants() {
    let p = Project::new("grantfree");
    p.file("index.js", "console.log(typeof fetch);");
    let Some(compiler) = p.compiler() else { return };

    p.run_with("./index.js", "", Some(compiler.clone()), false);
    let after_empty: Vec<_> = std::fs::read_dir(p.0.join(".ibex2/cache"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();

    p.run_with(
        "./index.js",
        "[*]\nnet.fetch https://example.com\n",
        Some(compiler),
        false,
    );
    let after_granted: Vec<_> = std::fs::read_dir(p.0.join(".ibex2/cache"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();

    assert_eq!(
        after_empty.len(),
        after_granted.len(),
        "a grant change produced a new artifact; bytecode depends on policy"
    );
}

// --- fs: the second real capability ------------------------------------------

/// Per-path-prefix grants, which per-origin cannot express: two modules in one
/// runtime, one able to reach a directory and one able to reach nothing.
#[test]
fn fs_authority_is_per_module_and_per_prefix() {
    let p = Project::new("fs");
    let data = p.0.join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    let dir = data.to_string_lossy().into_owned();

    p.file(
        "index.js",
        "(async () => {
           try { await fs.readFile('/etc/hosts'); console.log('index: LEAKED'); }
           catch (e) { console.log('index: ' + e.message); }
           await require('./worker').run();
         })();",
    )
    .file(
        "worker.js",
        &format!(
            "exports.run = async () => {{
               const dir = '{dir}';
               await fs.writeFile(dir + '/note.txt', new TextEncoder().encode('payload'));
               const back = await fs.readFile(dir + '/note.txt');
               console.log('worker: ' + new TextDecoder().decode(back));
               console.log('worker: ls ' + (await fs.readdir(dir)));
               try {{ await fs.readFile('/etc/hosts'); console.log('worker: LEAKED'); }}
               catch (e) {{ console.log('worker: ' + e.message); }}
             }};"
        ),
    );

    let manifest = format!("[*]\n[./worker.js]\nfs.read {dir}\nfs.write {dir}\n");
    let (out, err) = p.run("./index.js", &manifest);
    assert_eq!(err, None);
    assert!(out.iter().any(|l| l == "index: denied: fs.read"), "{out:?}");
    assert!(out.iter().any(|l| l == "worker: payload"), "{out:?}");
    assert!(out.iter().any(|l| l == "worker: ls note.txt"), "{out:?}");
    assert!(
        out.iter().any(|l| l == "worker: denied: fs.read"),
        "a prefix grant leaked outside its prefix: {out:?}"
    );
}

/// A traversal inside a granted prefix must not escape it. The path is
/// normalized BEFORE the grant is checked, or `/data/../etc` passes a `/data`
/// grant.
#[test]
fn fs_paths_are_normalized_before_they_are_admitted() {
    let p = Project::new("fstraversal");
    let data = p.0.join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    let dir = data.to_string_lossy().into_owned();
    p.file(
        "index.js",
        &format!(
            "(async () => {{
               try {{ await fs.readFile('{dir}' + '/../../../../etc/hosts'); console.log('LEAKED'); }}
               catch (e) {{ console.log(e.message); }}
             }})();"
        ),
    );
    let manifest = format!("[*]\nfs.read {dir}\nfs.write {dir}\n");
    let (out, err) = p.run("./index.js", &manifest);
    assert_eq!(err, None);
    assert_eq!(out, vec!["denied: fs.read"]);
}

/// Write authority does not imply read authority.
#[test]
fn fs_read_and_write_are_separate_grants() {
    let p = Project::new("fssplit");
    let data = p.0.join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    let dir = data.to_string_lossy().into_owned();
    p.file(
        "index.js",
        &format!(
            "(async () => {{
               const dir = '{dir}';
               await fs.writeFile(dir + '/x.txt', new TextEncoder().encode('ok'));
               console.log('wrote');
               try {{ await fs.readFile(dir + '/x.txt'); console.log('LEAKED'); }}
               catch (e) {{ console.log(e.message); }}
             }})();"
        ),
    );
    let manifest = format!("[*]\nfs.write {dir}\n");
    let (out, err) = p.run("./index.js", &manifest);
    assert_eq!(err, None);
    assert_eq!(out, vec!["wrote", "denied: fs.read"]);
}

// --- Receipts ----------------------------------------------------------------

/// The shipping posture requires a HermesInputReceipt. An engine with none is
/// indistinguishable from a patched one to a reader that only checks receipts
/// it can find, and "no evidence" is not evidence.
#[test]
fn an_unreceipted_engine_is_refused_in_the_shipping_posture() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let patched = root.join("ios/Frameworks");
    if !patched.join("hermesvm.framework").exists() {
        return; // no patched engine installed on this machine
    }
    assert!(
        !ibex2::receipt::HermesInput::path(&patched).exists(),
        "this test assumes the patched engine carries no vanilla receipt"
    );

    let cache = std::env::temp_dir().join(format!("ibex2-receipt-{}", std::process::id()));
    let err = ibex2::bytecode::Compiler::discover_for_engine(&root, cache.clone(), &patched, true)
        .expect_err("an unreceipted engine must be refused when a receipt is required");
    assert!(err.contains("no HermesInputReceipt"), "{err}");

    // ...and tolerated when it is not required, so a machine can still work
    // before its engine has been receipted.
    if ibex2::bytecode::Compiler::discover(&root, cache.clone()).is_ok() {
        assert!(ibex2::bytecode::Compiler::discover_for_engine(
            &root,
            cache.clone(),
            &patched,
            false
        )
        .is_ok());
    }
    let _ = std::fs::remove_dir_all(cache);
}

/// A receipted vanilla engine passes, and its receipt describes the bytes that
/// are actually there.
#[test]
fn a_receipted_vanilla_engine_is_accepted_and_verified() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let engine = Project::engine_dir();
    if !ibex2::receipt::HermesInput::path(&engine).exists() {
        return;
    }
    let receipt = ibex2::receipt::HermesInput::read(&engine).expect("read");
    assert!(receipt.is_vanilla());
    receipt
        .verify_binary(&engine)
        .expect("the receipt describes this engine");

    let cache = std::env::temp_dir().join(format!("ibex2-receipt-ok-{}", std::process::id()));
    assert!(
        ibex2::bytecode::Compiler::discover_for_engine(&root, cache.clone(), &engine, true).is_ok()
    );
    let _ = std::fs::remove_dir_all(cache);
}

// --- ESM ---------------------------------------------------------------------

#[test]
fn es_modules_import_and_export_across_files() {
    let p = Project::new("esm");
    p.file(
        "index.js",
        "import greet, { NAME, shout } from './greet.js';
         import * as all from './greet.js';
         console.log(greet('world'));
         console.log(shout(NAME));
         console.log('namespace:', Object.keys(all).sort().join(','));",
    )
    .file(
        "greet.js",
        "export const NAME = 'ibex2';
         export function shout(s) { return s.toUpperCase() + '!'; }
         export default function greet(who) { return 'hello, ' + who; }",
    );
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(
        out,
        vec!["hello, world", "IBEX2!", "namespace: NAME,default,shout",]
    );
}

/// ESM exports are live. A snapshot would print 0 twice.
#[test]
fn an_exported_binding_is_a_live_view() {
    let p = Project::new("esmlive");
    p.file(
        "index.js",
        "import * as counter from './counter.js';
         console.log('before', counter.value);
         counter.bump();
         console.log('after', counter.value);",
    )
    .file(
        "counter.js",
        "export let value = 0;
         export function bump() { value += 1; }",
    );
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["before 0", "after 1"]);
}

#[test]
fn re_exports_and_export_star_compose() {
    let p = Project::new("esmstar");
    p.file(
        "index.js",
        "import { a, b, renamed } from './barrel.js';
         console.log([a, b, renamed].join(','));",
    )
    .file(
        "barrel.js",
        "export * from './one.js';
         export { c as renamed } from './two.js';",
    )
    .file("one.js", "export const a = 1; export const b = 2;")
    .file("two.js", "export const c = 3;");
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["1,2,3"]);
}

/// A CommonJS module imported by an ES module: its module.exports becomes the
/// default, which is the interop every bundler converged on.
#[test]
fn an_es_module_can_import_a_commonjs_one() {
    let p = Project::new("esminterop");
    p.file(
        "index.js",
        "import cjs from './legacy.js';
         import { named } from './legacy.js';
         console.log(cjs.hello(), named);",
    )
    .file(
        "legacy.js",
        "exports.hello = () => 'from cjs'; exports.named = 'also works';",
    );
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["from cjs also works"]);
}

/// ESM and CommonJS in one graph, since a real migration has both.
#[test]
fn es_modules_and_commonjs_coexist_in_one_graph() {
    let p = Project::new("esmmixed");
    p.file(
        "index.js",
        "import { fromEsm } from './esm.js';
         const cjs = require('./cjs.js');
         console.log(fromEsm(), cjs.fromCjs());",
    )
    .file("esm.js", "export const fromEsm = () => 'esm';")
    .file("cjs.js", "exports.fromCjs = () => 'cjs';");
    let (out, err) = p.run("./index.js", "");
    assert_eq!(err, None);
    assert_eq!(out, vec!["esm cjs"]);
}

/// ESM through the ahead-of-time path must behave identically, since the
/// artifact is the LOWERED wrapper.
#[test]
fn es_modules_behave_identically_from_bytecode() {
    let p = Project::new("esmhbc");
    p.file(
        "index.js",
        "import { value } from './dep.js';
         console.log('value is', value);",
    )
    .file("dep.js", "export const value = 7;");

    let (source_out, source_err) = p.run("./index.js", "");
    let Some(compiler) = p.compiler() else { return };
    let (hbc_out, hbc_err) = p.run_with("./index.js", "", Some(compiler), false);
    assert_eq!(source_err, None);
    assert_eq!(hbc_err, None);
    assert_eq!(hbc_out, source_out);
    assert_eq!(source_out, vec!["value is 7"]);
}
