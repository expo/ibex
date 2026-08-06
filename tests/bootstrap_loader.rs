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
//!   * The unarmed diagnostic loader must keep its retained native resolver
//!     paths opaque, including for host files named `*.bundle.js`, while a
//!     relative require of such a file still resolves through the retained
//!     private referrer (the secure successor to finding #4's host-path remap).
//!   * import.meta.url must be a well-formed file:// URL (finding #12; the
//!     Windows drive-letter half is review-only on this platform, but the
//!     POSIX shape is pinned here).
//!   * A package-shaped CommonJS conditional entry may select a license-headed
//!     development file whose first non-directive statement starts with a
//!     string literal (the React package shape).
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

fn result_value(stdout: &str) -> &str {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT|"))
        .unwrap_or("")
}

fn is_opaque_resolver_path(value: &str) -> bool {
    let Some(handle) = value.strip_prefix("/project/.ibex-resolver/r") else {
        return false;
    };
    handle.len() == 16
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_opaque_resolver_file_url(value: &str) -> bool {
    value
        .strip_prefix("file://")
        .is_some_and(is_opaque_resolver_path)
}

fn assert_fixture_path_is_private(
    stdout: &str,
    stderr: &str,
    dir: &Path,
    source_basenames: &[&str],
) {
    let output = format!("{stdout}\n{stderr}");
    let host_dir = dir.to_string_lossy();
    assert!(
        !output.contains(host_dir.as_ref()),
        "diagnostic output disclosed fixture host path {host_dir}:\n{output}"
    );
    for basename in source_basenames {
        assert!(
            !output.contains(basename),
            "diagnostic output disclosed source basename {basename}:\n{output}"
        );
    }
}

fn assert_opaque_line_result(
    stdout: &str,
    stderr: &str,
    dir: &Path,
    source_basename: &str,
    expected_line: &str,
) {
    let result = result_value(stdout);
    let mut fields = result.split('|');
    let (Some(label), Some(line), Some(privacy)) = (fields.next(), fields.next(), fields.next())
    else {
        panic!("missing opaque stack result in stdout:\n{stdout}\nstderr:\n{stderr}");
    };
    assert!(
        fields.next().is_none(),
        "stack result had unexpected fields: {result}"
    );
    assert!(
        is_opaque_resolver_path(label),
        "stack frame did not use an opaque resolver label: {label}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        line, expected_line,
        "loader transform shifted the source line\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        privacy, "private",
        "JavaScript-visible stack disclosed {source_basename}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_fixture_path_is_private(stdout, stderr, dir, &[source_basename]);
}

/// Run `ibex capsec audit <entry>` in `dir` with EXACT_COMPAT_TEST=1 so the
/// entry goes through the in-process loader (no pre-bundling) and return
/// stdout. Production execution is deliberately closed until this target has
/// a verified advertisement, so compatibility fixtures use the explicit
/// foreground diagnostic.
fn run_compat(dir: &Path, entry: &str) -> (String, String, bool) {
    run_compat_with_env(dir, entry, &[])
}

fn run_compat_with_env(
    dir: &Path,
    entry: &str,
    environment: &[(&str, &str)],
) -> (String, String, bool) {
    let mut command = Command::new(IBEX);
    command
        .arg("capsec")
        .arg("audit")
        .arg(entry)
        .current_dir(dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .env("EXACT_COMPAT_TEST", "1")
        .env("IBEX_COMPAT_LOADER_TEST", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in environment {
        command.env(name, value);
    }
    let output = command.output().expect("run ibex");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.success(),
    )
}

/// A complete Directive Prologue ends before React's leading production guard:
/// `"production" !== process.env.NODE_ENV` is a binary expression, not a
/// directive. The compatibility loader must inject its eval shim before that
/// expression instead of splitting it after the string token.
/// @ref LLP 0027#esmcommonjs-interop-matrix
#[test]
fn package_conditional_commonjs_with_license_header_parses_and_evaluates() {
    let dir = unique_dir("conditional-cjs-license");
    write_text(
        &dir.join("node_modules/conditional-cjs/package.json"),
        r#"{"name":"conditional-cjs","main":"index.js"}
"#,
    );
    write_text(
        &dir.join("node_modules/conditional-cjs/index.js"),
        r#"'use strict';

if (process.env.NODE_ENV === 'production') {
  module.exports = require('./cjs/production.js');
} else {
  module.exports = require('./cjs/development.js');
}
"#,
    );
    write_text(
        &dir.join("node_modules/conditional-cjs/cjs/development.js"),
        r#"/**
 * @license loader regression fixture
 */

"use strict";
"production" !== process.env.NODE_ENV && (function () {
  module.exports = { branch: "development" };
})();
"#,
    );
    write_text(
        &dir.join("node_modules/conditional-cjs/cjs/production.js"),
        "'use strict';\nmodule.exports = { branch: 'production' };\n",
    );
    write_text(
        &dir.join("consumer.mjs"),
        "import selected from 'conditional-cjs';\n\
         console.log('RESULT|' + selected.branch);\n",
    );
    write_text(&dir.join("entry.js"), "require('./consumer.mjs');\n");

    let (stdout, stderr, ok) =
        run_compat_with_env(&dir, "entry.js", &[("NODE_ENV", "development")]);
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("RESULT|development"),
        "conditional CommonJS package selected or evaluated the wrong branch\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
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
         var stack = e.stack || '';\n\
         var m = /(\\/project\\/\\.ibex-resolver\\/r[0-9a-f]{16}):(\\d+):\\d+/.exec(stack);\n\
         console.log('RESULT|' + (m ? m[1] + '|' + m[2] : 'none|none') + '|' + (stack.indexOf('thrower.js') === -1 ? 'private' : 'leaked'));\n\
         }\n",
    );
    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert_opaque_line_result(&stdout, &stderr, &dir, "thrower.js", "5");
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
         var stack = e.stack || '';\n\
         var m = /(\\/project\\/\\.ibex-resolver\\/r[0-9a-f]{16}):(\\d+):\\d+/.exec(stack);\n\
         console.log('RESULT|' + (m ? m[1] + '|' + m[2] : 'none|none') + '|' + (stack.indexOf('looper.js') === -1 ? 'private' : 'leaked'));\n\
         }\n",
    );
    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert_opaque_line_result(&stdout, &stderr, &dir, "looper.js", "5");
}

/// The unarmed diagnostic resolver retains native paths behind opaque handles.
/// Even a parentless host file with a legacy bundle-output-shaped name must not
/// let `__exactEntryFile` remap its public `__filename` back to a host path.
#[test]
fn parentless_bundle_shaped_load_keeps_opaque_filename() {
    let dir = unique_dir("entry-remap");
    write_text(
        &dir.join("fakecache/abc123.bundle.js"),
        "console.log('RESULT|' + __filename);\n",
    );
    write_text(&dir.join("srcdir/realapp.js"), "// original source\n");
    let entry_file = dir.join("srcdir/realapp.js");
    let bundle = dir.join("fakecache/abc123.bundle.js");
    let code = format!(
        "globalThis.__exactEntryFile={:?}; globalThis.require({:?}); if ('__exactEntryFileConsumed' in globalThis) throw new Error('entry remap state leaked');",
        entry_file.to_string_lossy(),
        bundle.to_string_lossy()
    );
    write_text(&dir.join("remap-entry.js"), &code);
    let output = Command::new(IBEX)
        .arg("capsec")
        .arg("audit")
        .arg("remap-entry.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .env("EXACT_COMPAT_TEST", "1")
        .env("IBEX_COMPAT_LOADER_TEST", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run ibex");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "run failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    let filename = result_value(&stdout);
    assert!(
        is_opaque_resolver_path(filename),
        "bundle-shaped parentless load disclosed a non-opaque filename: {filename}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_fixture_path_is_private(&stdout, &stderr, &dir, &["abc123.bundle.js", "realapp.js"]);
}

/// A display-only opaque `__dirname` is not a resolver credential. The module's
/// local relative require retains the private referrer separately, so an
/// ordinary user file named `*.bundle.js` must still resolve without exposing
/// either native path or authored basename.
#[test]
fn relative_user_bundle_named_file_resolves_through_private_referrer() {
    let dir = unique_dir("no-steal");
    write_text(
        &dir.join("dist/foo.bundle.js"),
        "module.exports = { file: __filename };\n",
    );
    write_text(
        &dir.join("entry.js"),
        "var r = require('./dist/foo.bundle.js');\n\
         console.log('RESULT|' + __filename + '|' + r.file);\n",
    );
    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    let result = result_value(&stdout);
    let Some((entry_filename, dependency_filename)) = result.split_once('|') else {
        panic!("missing private-referrer result in stdout:\n{stdout}\nstderr:\n{stderr}");
    };
    assert!(
        is_opaque_resolver_path(entry_filename)
            && is_opaque_resolver_path(dependency_filename)
            && entry_filename != dependency_filename,
        "relative bundle-named load did not preserve distinct opaque identities: {result}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_fixture_path_is_private(&stdout, &stderr, &dir, &["entry.js", "foo.bundle.js"]);
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
    let url = result_value(&stdout);
    assert!(
        is_opaque_resolver_file_url(url) && !url.contains('\\'),
        "import.meta.url is not a well-formed file URL: {}\nstderr:\n{}",
        url,
        stderr
    );
    assert_fixture_path_is_private(&stdout, &stderr, &dir, &["meta.mjs"]);
}

/// A semicolonless multiline export ends by ASI before the next top-level
/// export, even when a documentation comment separates the declarations.
/// micromark-util-html-tag-name uses this exact source shape.
#[test]
fn semicolonless_multiline_exports_do_not_swallow_the_next_export() {
    let dir = unique_dir("semicolonless-exports");
    write_text(
        &dir.join("names.mjs"),
        r#"export const htmlBlockNames = [
  'address',
  'article'
]

/** Raw HTML tag names. */
export const htmlRawNames = ['pre', 'script']
"#,
    );
    write_text(
        &dir.join("entry.js"),
        "var names = require('./names.mjs');\n\
         console.log('RESULT|' + names.htmlBlockNames.join(',') + '|' + names.htmlRawNames.join(','));\n",
    );

    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("RESULT|address,article|pre,script"),
        "semicolonless multiline exports were not both exposed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}

/// Guard the complementary ASI case: a newline after a balanced array does
/// not end the declaration when the next line continues its initializer.
#[test]
fn semicolonless_multiline_export_keeps_chained_initializer() {
    let dir = unique_dir("chained-export");
    write_text(
        &dir.join("values.mjs"),
        r#"export const values = [
  'a',
  'b'
]
.map(function (value) { return value.toUpperCase() })

export const count = values.length
"#,
    );
    write_text(
        &dir.join("entry.js"),
        "var result = require('./values.mjs');\n\
         console.log('RESULT|' + result.values.join(',') + '|' + result.count);\n",
    );

    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("RESULT|A,B|2"),
        "chained initializer was detached from its export\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}

/// Unified/remark packages also format multiline static imports without
/// semicolons. The statement joiner must stop at the closing `from` clause
/// instead of consuming the next import (or the rest of the module).
#[test]
fn semicolonless_multiline_imports_stop_at_complete_from_clause() {
    let dir = unique_dir("semicolonless-imports");
    write_text(
        &dir.join("dep.mjs"),
        "export const first = 'one';\nexport const second = 'two';\n",
    );
    write_text(
        &dir.join("consumer.mjs"),
        r#"import {
  // Example syntax: } from './missing.mjs'
  first,
  second
} from './dep.mjs'

export const joined = first + '-' + second
"#,
    );
    write_text(
        &dir.join("entry.js"),
        "var result = require('./consumer.mjs');\n\
         console.log('RESULT|' + result.joined);\n",
    );

    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("RESULT|one-two"),
        "semicolonless multiline import did not bind both names\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}

/// ESM function declarations are hoisted even when exported. Packages in the
/// unified ecosystem attach helper properties before the declaration appears.
#[test]
fn named_exported_function_preserves_declaration_hoisting() {
    let dir = unique_dir("export-function-hoisting");
    write_text(
        &dir.join("handler.mjs"),
        r#"handler.peek = peek

export function handler() {
  return 'handled'
}

function peek() {
  return 'peeked'
}
"#,
    );
    write_text(
        &dir.join("entry.js"),
        "var result = require('./handler.mjs');\n\
         console.log('RESULT|' + result.handler() + '|' + result.handler.peek());\n",
    );

    let (stdout, stderr, ok) = run_compat(&dir, "entry.js");
    assert!(ok, "run failed\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
    assert!(
        stdout.contains("RESULT|handled|peeked"),
        "named exported function lost declaration hoisting\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
}
