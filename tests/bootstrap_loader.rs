//! End-to-end regression tests for bootstrap module-loader fixes (ENG-23481),
//! driving the real `ibex` binary:
//!
//!   * Default-import ESM->CJS fallback interop: `import X from 'm'` must bind
//!     a FALSY default export (0/''/false/null), not the whole namespace
//!     (finding #9 — the old rewrite was `require(m).default || require(m)`).
//!   * Stack-trace line numbers for loader-served modules must point at the
//!     real source line: the eval-shim preamble is injected as a single line
//!     and the for-of rewrite replaces lines one-for-one (finding #11 — the
//!     old 38-line preamble shifted every reported line by ~39).
//!   * The bundled-entry `__filename`/`__dirname` remap must key on the
//!     bundle-output path shape, not a macOS-only '/Caches/' substring
//!     (finding #4), and must be consumed by the entry so a later parentless
//!     require of a user file named `*.bundle.js` is not remapped.
//!   * import.meta.url must be a well-formed file:// URL (finding #12; the
//!     Windows drive-letter half is review-only on this platform, but the
//!     POSIX shape is pinned here).
//!
//! Run with: `scripts/run-tests.sh --scope test bootstrap_loader`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("ibex-loader-{}-{}-{}", tag, std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_text(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    std::fs::write(path, contents).expect("write test file");
}

/// Run `ibex run <entry>` in `dir` with EXACT_COMPAT_TEST=1 so the entry goes
/// through the in-process loader (no pre-bundling) and return stdout.
fn run_compat(dir: &Path, entry: &str) -> (String, String, bool) {
    let output = Command::new(IBEX)
        .arg("run")
        .arg(entry)
        .current_dir(dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .env("EXACT_COMPAT_TEST", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run ibex");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.success(),
    )
}

/// Finding #9: a falsy ESM default export must be bound as the default, not
/// as the module namespace object, through the loader's ESM->CJS fallback.
#[test]
fn default_import_binds_falsy_default_export() {
    let dir = unique_dir("falsy-default");
    write_text(&dir.join("dep.mjs"), "export default false;\n");
    write_text(
        &dir.join("consumer.mjs"),
        "import flag from './dep.mjs';\n\
         console.log('RESULT|' + JSON.stringify(flag) + '|' + typeof flag);\n",
    );
    write_text(&dir.join("entry.js"), "require('./consumer.mjs');\n");
    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("RESULT|false|boolean"),
        "falsy default export was not bound as the default binding \
         (namespace leak?)\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}

/// Finding #9 (guard): a plain CJS dependency imported via `import X from`
/// must still bind the namespace (no __esModule marker).
#[test]
fn default_import_of_cjs_module_binds_namespace() {
    let dir = unique_dir("cjs-default");
    write_text(&dir.join("dep.js"), "module.exports = { a: 1 };\n");
    write_text(
        &dir.join("consumer.mjs"),
        "import ns from './dep.js';\n\
         console.log('RESULT|' + JSON.stringify(ns));\n",
    );
    write_text(&dir.join("entry.js"), "require('./consumer.mjs');\n");
    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("RESULT|{\"a\":1}"),
        "CJS default import no longer binds module.exports\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}

/// Finding #11: a module that throws on source line N must report line N in
/// its stack frame, not N + ~39 (the old per-module eval-shim preamble).
#[test]
fn loader_module_stack_line_numbers_match_source() {
    let dir = unique_dir("stack-lines");
    write_text(
        &dir.join("thrower.js"),
        "// line 1\n// line 2\n// line 3\n// line 4\nthrow new Error('boom-on-line-5');\n",
    );
    write_text(
        &dir.join("entry.js"),
        "try { require('./thrower.js'); } catch (e) {\n\
         var m = /thrower\\.js:(\\d+)/.exec(e.stack || '');\n\
         console.log('RESULT|line=' + (m ? m[1] : 'none'));\n\
         }\n",
    );
    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("RESULT|line=5"),
        "stack line for a throw on source line 5 is shifted\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}

/// Finding #11 (for-of tier): the for-of scoping rewrite must stay
/// line-preserving — a throw INSIDE a rewritten for-of body reports the
/// original source line.
#[test]
fn for_of_rewrite_preserves_line_numbers() {
    let dir = unique_dir("forof-lines");
    // The for-of over a const binding with a closure-capturing body is the
    // rewrite-eligible shape (no bail keywords in the body). The fixture is
    // deliberately transpile-stable: no leading comments (the in-process
    // transpile tier drops them) and no multi-element array literal (it
    // reprints those across lines) — this test pins the LOADER tiers
    // (preamble + for-of rewrite) as line-neutral, not the transpiler.
    write_text(
        &dir.join("looper.js"),
        "var fns = [];\n\
         var xs = \"ab\";\n\
         for (const x of xs) {\n\
         fns.push(() => x);\n\
         boomOnLineFive();\n\
         }\n",
    );
    write_text(
        &dir.join("entry.js"),
        "try { require('./looper.js'); } catch (e) {\n\
         var m = /looper\\.js:(\\d+)/.exec(e.stack || '');\n\
         console.log('RESULT|line=' + (m ? m[1] : 'none'));\n\
         }\n",
    );
    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("RESULT|line=5"),
        "for-of rewrite shifted line numbers\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}

/// Finding #4: the bundled-entry remap keys on the bundle-output shape
/// (`<key>.bundle.js` / `<key>/bundle.js`), so it fires for cache dirs that
/// do not contain '/Caches/' (Linux `~/.cache/ibex`, Windows LOCALAPPDATA).
/// Simulated via eval mode: set __exactEntryFile, then load a bundle-shaped
/// file from a non-Caches dir as the first parentless module.
#[test]
fn bundled_entry_remap_fires_outside_macos_caches_dir() {
    let dir = unique_dir("entry-remap");
    write_text(
        &dir.join("fakecache/abc123.bundle.js"),
        "console.log('RESULT|' + __filename);\n",
    );
    write_text(&dir.join("srcdir/realapp.js"), "// original source\n");
    let entry_file = dir.join("srcdir/realapp.js");
    let bundle = dir.join("fakecache/abc123.bundle.js");
    let code = format!(
        "globalThis.__exactEntryFile={:?}; require({:?});",
        entry_file.to_string_lossy(),
        bundle.to_string_lossy()
    );
    let output = Command::new(IBEX)
        .arg("-e")
        .arg(&code)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run ibex");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("RESULT|{}", entry_file.to_string_lossy())),
        "entry __filename not remapped to the source path for a \
         non-'/Caches/' bundle location\nstdout:\n{}\nstderr:\n{}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Finding #4 (guard): the remap is consumed by the ENTRY. A later parentless
/// require of a user file that happens to be named `*.bundle.js` keeps its
/// own __filename.
#[test]
fn user_bundle_named_file_is_not_remapped() {
    let dir = unique_dir("no-steal");
    write_text(
        &dir.join("dist/foo.bundle.js"),
        "module.exports = { file: __filename };\n",
    );
    write_text(
        &dir.join("entry.js"),
        "var r = globalThis.require(__dirname + '/dist/foo.bundle.js');\n\
         console.log('RESULT|' + r.file);\n",
    );
    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("dist/foo.bundle.js"),
        "a user *.bundle.js require stole the entry remap\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}

/// Finding #12 (POSIX shape pin): import.meta.url through the loader's
/// string-transpile tier must be a well-formed file:/// URL.
#[test]
fn import_meta_url_is_wellformed_file_url() {
    let dir = unique_dir("import-meta-url");
    write_text(
        &dir.join("meta.mjs"),
        "export const url = import.meta.url;\n",
    );
    write_text(
        &dir.join("entry.js"),
        "var m = require('./meta.mjs');\n\
         console.log('RESULT|' + m.url);\n",
    );
    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("RESULT|"))
        .unwrap_or("");
    let url = line.trim_start_matches("RESULT|");
    assert!(
        url.starts_with("file:///") && url.ends_with("/meta.mjs") && !url.contains('\\'),
        "import.meta.url is not a well-formed file URL: {}\nstderr:\n{}",
        url,
        stderr
    );
}
