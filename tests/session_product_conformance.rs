//! Non-PTY product fixtures for LLP 0022/0024.
//!
//! These tests deliberately invoke the public binary instead of internal
//! evaluator helpers. They remain ignored until the current platform's target
//! advertisement is independently verified; a test must never promote its own
//! target cell merely to make product startup succeed.
//! @ref LLP 0022#3-input-modes
//! @ref LLP 0024#acceptance-criteria

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

fn project() -> TempDir {
    let project = tempfile::tempdir().expect("temporary project");
    std::fs::write(
        project.path().join("package.json"),
        "{\"name\":\"session-product-fixture\",\"private\":true,\"type\":\"module\"}\n",
    )
    .expect("package manifest");
    project
}

fn run(project: &Path, args: &[&str], stdin: &[u8]) -> Output {
    let binary = env!("CARGO_BIN_EXE_ibex");
    let mut command = Command::new(binary);
    command
        .arg("--project-root")
        .arg(project)
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn ibex product fixture");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(stdin)
        .expect("write product stdin");
    child.wait_with_output().expect("wait for ibex")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label}: status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        text(&output.stdout),
        text(&output.stderr)
    );
}

fn assert_no_session_framing(output: &Output, label: &str) {
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    for forbidden in ["Welcome to Ibex", "ibex> ", "...> ", "\u{1b}["] {
        assert!(
            !stdout.contains(forbidden) && !stderr.contains(forbidden),
            "{label}: non-PTY route emitted session framing {forbidden:?}"
        );
    }
}

#[test]
#[ignore = "requires an independently verified production target advertisement"]
fn eval_program_stdin_and_transcript_are_distinct_non_pty_products() {
    let project = project();

    let printed = run(project.path(), &["-p", "1 + 1"], b"");
    assert_success(&printed, "print eval");
    assert_eq!(text(&printed.stdout), "2\n");
    assert_no_session_framing(&printed, "print eval");

    let suppressed = run(
        project.path(),
        &["-e", "console.log('EVAL-AUTHORED'); 41"],
        b"",
    );
    assert_success(&suppressed, "suppressed eval");
    assert_eq!(text(&suppressed.stdout), "EVAL-AUTHORED\n");
    assert_no_session_framing(&suppressed, "suppressed eval");

    let program = run(
        project.path(),
        &[],
        b"console.log('PROGRAM-AUTHORED'); 42;\n",
    );
    assert_success(&program, "program stdin");
    assert_eq!(text(&program.stdout), "PROGRAM-AUTHORED\n");
    assert_no_session_framing(&program, "program stdin");

    let transcript = run(project.path(), &["repl"], b"let x = 1\nx + 1\n");
    assert_success(&transcript, "plain transcript");
    assert_eq!(text(&transcript.stdout), "2\n");
    assert_no_session_framing(&transcript, "plain transcript");

    let authored_ansi = run(
        project.path(),
        &["repl"],
        b"console.log('\\x1b[31mPROGRAM-COLOR\\x1b[0m')\n",
    );
    assert_success(&authored_ansi, "program-authored ANSI");
    assert!(text(&authored_ansi.stdout).contains("\x1b[31mPROGRAM-COLOR\x1b[0m"));
}

#[test]
#[ignore = "requires an independently verified production target advertisement"]
fn transcript_utf8_eof_and_exit_status_contracts_are_executable() {
    let project = project();

    let invalid_utf8 = run(project.path(), &["repl"], &[0xff, b'\n']);
    assert!(
        !invalid_utf8.status.success(),
        "invalid transcript UTF-8 must terminate the session"
    );
    assert!(
        text(&invalid_utf8.stderr).contains("repl-invalid-utf8")
            || text(&invalid_utf8.stdout).contains("repl-invalid-utf8")
    );

    let incomplete = run(project.path(), &["repl"], b"function pending() {\n");
    assert_success(&incomplete, "incomplete transcript EOF");
    assert!(
        text(&incomplete.stderr).contains("repl-incomplete-eof")
            || text(&incomplete.stdout).contains("repl-incomplete-eof")
    );
    assert_no_session_framing(&incomplete, "incomplete transcript EOF");

    let eval_status = run(project.path(), &["-e", "process.exitCode = 7"], b"");
    assert_eq!(eval_status.status.code(), Some(7));
    let program_status = run(project.path(), &[], b"process.exitCode = 9;\n");
    assert_eq!(program_status.status.code(), Some(9));
}

#[test]
#[ignore = "requires an independently verified production target advertisement"]
fn file_program_keeps_orderly_lifecycle_and_failure_statuses_distinct() {
    let project = project();
    let entry = project.path().join("entry.mjs");
    let entry_arg = entry.to_str().expect("UTF-8 fixture path");

    std::fs::write(&entry, "process.exitCode = 5;\n").expect("orderly file program");
    let orderly = run(project.path(), &[entry_arg], b"");
    assert_eq!(
        orderly.status.code(),
        Some(5),
        "orderly file exitCode: {}",
        text(&orderly.stderr)
    );

    std::fs::write(&entry, "process.exit(7);\n").expect("lifecycle file program");
    let lifecycle = run(project.path(), &[entry_arg], b"");
    assert_eq!(
        lifecycle.status.code(),
        Some(7),
        "explicit file lifecycle: {}",
        text(&lifecycle.stderr)
    );

    // @ref LLP 0025#8-exit-and-lifecycle — the unhandled rejection is the
    // primary termination cause, so an earlier orderly exitCode cannot win.
    std::fs::write(
        &entry,
        "process.exitCode = 9; Promise.reject(new Error('file-async-boom'));\n",
    )
    .expect("async-failure file program");
    let failed = run(project.path(), &[entry_arg], b"");
    assert_eq!(
        failed.status.code(),
        Some(1),
        "async file failure: {}",
        text(&failed.stderr)
    );
    assert!(text(&failed.stderr).contains("file-async-boom"));

    // A background failure can become reportable while top-level await keeps
    // the foreground evaluation in flight. It must be drained before the later
    // foreground outcome is classified, rather than disappearing when that
    // outcome returns.
    std::fs::write(
        &entry,
        "setTimeout(() => { throw new Error('file-async-before-outcome'); }, 0);\nawait new Promise(resolve => setTimeout(resolve, 10));\nprocess.exit(7);\n",
    )
    .expect("TLA async-before-lifecycle file program");
    let async_before_lifecycle = run(project.path(), &[entry_arg], b"");
    assert_eq!(
        async_before_lifecycle.status.code(),
        Some(1),
        "an earlier asynchronous failure wins: {}",
        text(&async_before_lifecycle.stderr)
    );
    assert!(
        text(&async_before_lifecycle.stderr).contains("file-async-before-outcome"),
        "the earlier structured failure must be reported exactly once: {}",
        text(&async_before_lifecycle.stderr)
    );
}

#[test]
#[ignore = "requires an independently verified production target advertisement"]
fn program_stdin_uses_one_strict_main_module_with_real_loader_edges() {
    let project = project();
    std::fs::write(
        project.path().join("dep.mjs"),
        "export const named = 4; export default 5;\n",
    )
    .expect("dependency module");
    std::fs::write(
        project.path().join("throwing.mjs"),
        "console.log('IMPORT-SIDE-EFFECT'); throw new Error('dependency boom');\n",
    )
    .expect("throwing dependency");

    let cases: &[(&str, &[u8], &str)] = &[
        (
            "named/default exports",
            b"export const localNamed = 3; export default 4; console.log(localNamed + 4);\n",
            "7\n",
        ),
        (
            "re-export and export-all",
            b"export { default as forwarded } from './dep.mjs'; export * from './dep.mjs'; import { named } from './dep.mjs'; console.log(named);\n",
            "4\n",
        ),
        (
            "entry top-level await",
            b"await Promise.resolve(); console.log('TLA-SETTLED');\n",
            "TLA-SETTLED\n",
        ),
        (
            "import.meta identity",
            b"console.log(String(import.meta.main) + '|' + import.meta.url);\n",
            "true|ibex:stdin\n",
        ),
        (
            "strict top-level this",
            b"console.log(String(this === undefined));\n",
            "true\n",
        ),
    ];
    for (label, source, expected_stdout) in cases {
        let output = run(project.path(), &[], source);
        assert_success(&output, label);
        assert_eq!(text(&output.stdout), *expected_stdout, "{label}");
        assert_no_session_framing(&output, label);
    }

    let throwing = run(
        project.path(),
        &[],
        b"import './throwing.mjs'; console.log('ENTRY-RAN');\n",
    );
    assert!(!throwing.status.success());
    assert!(text(&throwing.stdout).contains("IMPORT-SIDE-EFFECT"));
    assert!(!text(&throwing.stdout).contains("ENTRY-RAN"));
    assert!(text(&throwing.stderr).contains("dependency boom"));
}
