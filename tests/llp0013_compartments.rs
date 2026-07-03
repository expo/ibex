//! @ref LLP 0013 — conformance + red-team suite for per-package capability
//! compartments. This is the durable asset the RFC's fork phases and every
//! future Hermes rebase are measured against: it drives the real `ibex` binary
//! against fixtures and asserts the security properties end-to-end.
//!
//! Run with: `cargo test --test llp0013_compartments`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("llp0013")
}

struct RunOutput {
    stdout: String,
    stderr: String,
    status: i32,
}

/// Run the ibex binary with the given args + extra env, returning captured
/// output. `cwd` defaults to the manifest dir.
fn run_ibex(args: &[&str], envs: &[(&str, &str)], cwd: Option<&Path>) -> RunOutput {
    let mut cmd = Command::new(IBEX);
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let out = cmd.output().expect("failed to spawn ibex binary");
    RunOutput {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        status: out.status.code().unwrap_or(-1),
    }
}

fn fixture(name: &str) -> String {
    fixtures_dir().join(name).to_string_lossy().into_owned()
}

/// A unique scratch dir under the system temp dir (no external crates).
fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("ibex-llp0013-{}-{}-{}", tag, std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn have_js_runner() -> bool {
    which("bun") || which("node")
}

fn which(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Red-team suite (Mechanism 1: lockdown)
// ---------------------------------------------------------------------------

#[test]
fn redteam_all_contained_under_lockdown() {
    let out = run_ibex(&["--lockdown", "run", &fixture("redteam.js")], &[], None);
    assert!(
        !out.stdout.contains("NOT_CONTAINED"),
        "an attack was not contained under lockdown:\n{}",
        out.stdout
    );
    // Every named case must appear and be contained.
    for case in [
        "recover-real-global",
        "dynamic-code-Function",
        "dynamic-code-eval",
        "prototype-patch-Array",
        "proto-pollution",
        "generator-evaluator",
        "host-tamper-setActiveModuleId",
        "host-tamper-grantCapability",
    ] {
        assert!(
            out.stdout.contains(&format!("{case}: CONTAINED")),
            "case {case} missing/uncontained:\n{}",
            out.stdout
        );
    }
}

#[test]
fn redteam_ambient_attacks_succeed_without_lockdown() {
    // Without lockdown the ambient-authority attacks are real (NOT_CONTAINED),
    // which is exactly why lockdown is needed. This guards against the suite
    // silently passing because the attacks stopped working.
    let out = run_ibex(&["run", &fixture("redteam.js")], &[], None);
    for case in [
        "recover-real-global",
        "dynamic-code-Function",
        "prototype-patch-Array",
    ] {
        assert!(
            out.stdout.contains(&format!("{case}: NOT_CONTAINED")),
            "case {case} should be uncontained without lockdown:\n{}",
            out.stdout
        );
    }
    // The Phase 0 escape-hatch seal runs in ALL modes, so host tampering is
    // contained even without lockdown.
    assert!(
        out.stdout
            .contains("host-tamper-setActiveModuleId: CONTAINED"),
        "escape-hatch seal should hold in all modes:\n{}",
        out.stdout
    );
}

#[test]
fn lockdown_conformance_keeps_runtime_usable() {
    let out = run_ibex(
        &["--lockdown", "run", &fixture("lockdown-conformance.js")],
        &[],
        None,
    );
    for expected in [
        "lockedDown=true",
        "mapWorks=true",
        "instanceofWorks=true",
        "frozenProtoThrows=true",
        "registry=true",
    ] {
        assert!(
            out.stdout.contains(expected),
            "expected {expected} in output:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    }
}

#[test]
fn lockdown_seals_lazy_installers_and_self_grant_channel() {
    // @ref LLP 0013#phase-1 — under lockdown the lazy `__exactEnsure*` installers
    // are eager-installed then deleted, and the `Exact.setModuleCapabilities`
    // self-grant channel is removed; fs still works (installed before the seal).
    let out = run_ibex(
        &["--lockdown", "run", &fixture("phase1-seal.js")],
        &[],
        None,
    );
    for expected in [
        "installers-sealed: true",
        "self-grant-sealed: true",
        "fs-usable: true",
    ] {
        assert!(
            out.stdout.contains(expected),
            "expected {expected} under lockdown:\nstdout:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    }
}

#[test]
fn lazy_installers_present_without_lockdown() {
    // Off the lockdown path the installers stay lazy (startup cost) and the
    // legacy self-grant path is retained for back-compat.
    let out = run_ibex(&["run", &fixture("phase1-seal.js")], &[], None);
    assert!(
        out.stdout.contains("installers-sealed: false"),
        "installers should stay lazy without lockdown:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn lockdown_is_off_by_default() {
    let out = run_ibex(&["run", &fixture("lockdown-conformance.js")], &[], None);
    assert!(
        out.stdout.contains("lockedDown=false"),
        "lockdown must be opt-in (off by default):\n{}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// Compartment endowment (Mechanism 2)
// ---------------------------------------------------------------------------

#[test]
fn compartment_withholds_powerful_globals_and_honors_endowments() {
    let out = run_ibex(
        &["--lockdown", "run", &fixture("compartment-endowment.js")],
        &[("IBEX_ENDOW", "trusted-net:fetch")],
        None,
    );
    for expected in [
        "evil.process=undefined", // withheld
        "evil.fetch=undefined",   // withheld
        "evil.Object=function",   // shared intrinsic passes through
        "evil.console=object",    // shared intrinsic passes through
        "trusted.fetch=function", // endowed
    ] {
        assert!(
            out.stdout.contains(expected),
            "expected {expected}:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    }
}

// ---------------------------------------------------------------------------
// End-to-end supply-chain containment (Mechanisms 1 + 2 via the bundler)
// ---------------------------------------------------------------------------

fn write_supply_chain_app(dir: &Path) {
    let pkg_dir = dir.join("node_modules").join("evil-pkg");
    std::fs::create_dir_all(&pkg_dir).expect("mkdir node_modules/evil-pkg");
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "evil-pkg", "version": "1.0.0", "main": "index.js" }"#,
    )
    .unwrap();
    std::fs::write(
        pkg_dir.join("index.js"),
        "module.exports = function steal() {\n\
         try { return 'STOLEN:' + process.env.SECRET_TOKEN; }\n\
         catch (e) { return 'CONTAINED:' + (e && e.name); }\n\
         };\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("app.js"),
        "const steal = require('evil-pkg');\nconsole.log('result: ' + steal());\n",
    )
    .unwrap();
}

#[test]
fn compromised_dependency_cannot_read_env_under_lockdown() {
    if !have_js_runner() {
        eprintln!("skipping: bundler (bun/node) not available; compartment rewrite needs it");
        return;
    }
    // Distinct dirs so the entry-path-keyed bundle cache never collides between
    // the locked-down and open runs.
    let locked = unique_dir("locked");
    write_supply_chain_app(&locked);
    let out = run_ibex(
        &["--lockdown", "run", locked.join("app.js").to_str().unwrap()],
        &[("SECRET_TOKEN", "hunter2")],
        None,
    );
    assert!(
        out.stdout.contains("result: CONTAINED"),
        "compromised dependency should be contained under lockdown:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        !out.stdout.contains("STOLEN:hunter2"),
        "secret leaked under lockdown:\n{}",
        out.stdout
    );
    let _ = std::fs::remove_dir_all(&locked);
}

#[test]
fn compromised_dependency_succeeds_without_lockdown() {
    if !have_js_runner() {
        eprintln!("skipping: bundler (bun/node) not available");
        return;
    }
    let open = unique_dir("open");
    write_supply_chain_app(&open);
    let out = run_ibex(
        &["run", open.join("app.js").to_str().unwrap()],
        &[("SECRET_TOKEN", "hunter2")],
        None,
    );
    // Baseline: without compartments the attack works — proves the test setup
    // actually exercises the exfiltration path.
    assert!(
        out.stdout.contains("STOLEN:hunter2"),
        "baseline attack should succeed without lockdown:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&open);
}

// ---------------------------------------------------------------------------
// Import-site grants → generated policy (LLP 0014)
// ---------------------------------------------------------------------------
// @ref LLP 0014#conformance — end-to-end: the artifact generated from
// root-principal import sites endows exactly the granted packages; grant
// syntax inside node_modules confers nothing; the committed artifact is
// drift-checked with expansions reported.

fn grants_app() -> PathBuf {
    fixtures_dir().join("grants-app")
}

fn copy_dir_recursive(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("mkdir");
    for entry in std::fs::read_dir(from).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir_recursive(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

#[test]
fn generated_policy_endows_granted_package_and_contains_the_rest() {
    if !have_js_runner() {
        eprintln!("skipping: bundler/generator (bun/node) not available");
        return;
    }
    // Own copy: the bundle cache is keyed by entry path; sibling tests run the
    // same fixture under different policies.
    let dir = unique_dir("grants-endow");
    copy_dir_recursive(&grants_app(), &dir);
    let out = run_ibex(
        &[
            "--lockdown",
            "--policy",
            dir.join("ibex-policy.json").to_str().unwrap(),
            "run",
            dir.join("app.mjs").to_str().unwrap(),
        ],
        &[("SECRET_TOKEN", "hunter2")],
        None,
    );
    // The package granted `process:env` at its import site works under lockdown…
    assert!(
        out.stdout.contains("env-reader:  OK:string"),
        "granted package should be endowed via the generated policy:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // …the ungranted one is contained, and the secret never leaks.
    assert!(
        out.stdout.contains("evil-pkg:    CONTAINED"),
        "ungranted package must be contained:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        !out.stdout.contains("STOLEN:hunter2"),
        "secret leaked:\n{}",
        out.stdout
    );
    // The self-grant inside node_modules conferred nothing; the code still runs.
    assert!(
        out.stdout
            .contains("sneaky-pkg:  requested-nothing-got-nothing"),
        "package self-grant must be inert:\n{}",
        out.stdout
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn without_generated_policy_no_package_is_endowed() {
    if !have_js_runner() {
        eprintln!("skipping: bundler (bun/node) not available");
        return;
    }
    let dir = unique_dir("grants-noendow");
    copy_dir_recursive(&grants_app(), &dir);
    let out = run_ibex(
        &[
            "--lockdown",
            "--policy",
            fixtures_dir().join("empty-policy.json").to_str().unwrap(),
            "run",
            dir.join("app.mjs").to_str().unwrap(),
        ],
        &[("SECRET_TOKEN", "hunter2")],
        None,
    );
    // Proves the endowment comes from the generated artifact, not a default:
    // under lockdown with an empty policy even the "granted" package is blocked.
    assert!(
        out.stdout.contains("env-reader:  BLOCKED"),
        "no policy → no endowment:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// A principal denied `env:read` must not be able to read the environment through
// any path. Every real read funnels through the `env:read:<key>` capability check
// (`process.env.KEY` → native __exactGetEnv); there must also be no plain-object
// env snapshot on `process` that launders past it. Regression for the removed
// `process.__exactPlainEnv`. Per-principal env discrimination (granted reads /
// ungranted denied) is proven deterministically by
// `capability.rs::env_read_is_gated_per_principal`. @ref LLP 0013#mechanism-3
#[test]
fn env_reads_are_gated_with_no_plain_snapshot_bypass() {
    if !have_js_runner() {
        eprintln!("skipping: bundler (bun/node) not available; `run` bundles the app");
        return;
    }
    // Enforce mode; the policy denies `env:read` to this principal (a denial wins
    // over the default trust of first-party root), so the env gate is active.
    let dir = unique_dir("env-snapshot");
    copy_dir_recursive(&fixtures_dir().join("env-snapshot"), &dir);
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            dir.join("ibex-policy.json").to_str().unwrap(),
            "run",
            dir.join("app.js").to_str().unwrap(),
        ],
        &[("SECRET_TOKEN", "hunter2")],
        None,
    );
    // The gated read is denied, the snapshot is gone, and a brute-force scan of
    // `process` finds no object carrying the secret.
    assert!(
        out.stdout.contains("direct=undefined")
            && out.stdout.contains("snapshot=undefined")
            && out.stdout.contains("scan=none"),
        "env must be gated with no plain-snapshot bypass:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // The secret never appears anywhere in the output.
    assert!(
        !out.stdout.contains("hunter2"),
        "secret leaked:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // Positive control: the SAME app under forced permissive (no gate) reads the
    // secret — proving `direct=undefined` above is the deny suppressing a live
    // read path, not a dead one.
    let control = run_ibex(
        &[
            "--capsec",
            "permissive",
            "--policy",
            dir.join("ibex-policy.json").to_str().unwrap(),
            "run",
            dir.join("app.js").to_str().unwrap(),
        ],
        &[("SECRET_TOKEN", "hunter2")],
        None,
    );
    assert!(
        control.stdout.contains("direct=hunter2") && control.stdout.contains("scan=via:env"),
        "control: the read path must reach the secret without the gate:\nstdout:\n{}\nstderr:\n{}",
        control.stdout,
        control.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn committed_grants_artifact_is_in_sync() {
    if !have_js_runner() {
        eprintln!("skipping: generator (bun/node) not available");
        return;
    }
    // The committed fixture artifact regenerates byte-identically — the
    // reproducibility contract behind treating it like a lockfile.
    let out = run_ibex(
        &[
            "policy",
            "check",
            "--entry",
            grants_app().join("app.mjs").to_str().unwrap(),
        ],
        &[],
        None,
    );
    assert_eq!(
        out.status, 0,
        "committed artifact drifted from the import sites:\nstdout:\n{}\nstderr:\n{}",
        out.stdout, out.stderr
    );
    // The self-grant attempt inside node_modules is surfaced as a signal.
    assert!(
        out.stderr.contains("not a grant channel"),
        "package self-grant should be reported:\n{}",
        out.stderr
    );
}

#[test]
fn policy_check_reports_capability_expansion_on_drift() {
    if !have_js_runner() {
        eprintln!("skipping: generator (bun/node) not available");
        return;
    }
    let dir = unique_dir("grants-drift");
    copy_dir_recursive(&grants_app(), &dir);
    // Root code grows a grant the committed artifact doesn't have.
    let app = dir.join("app.mjs");
    let source = std::fs::read_to_string(&app).unwrap().replace(
        "import steal from \"evil-pkg\";",
        "import steal from \"evil-pkg\" with { grants: \"network:fetch\" };",
    );
    std::fs::write(&app, source).unwrap();
    let out = run_ibex(
        &["policy", "check", "--entry", app.to_str().unwrap()],
        &[],
        None,
    );
    assert_ne!(out.status, 0, "drift must fail the check:\n{}", out.stdout);
    assert!(
        out.stderr.contains("EXPANSIONS"),
        "expansions are the review tripwire:\n{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("evil-pkg: network:fetch"),
        "the expanded grant should be named:\n{}",
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Audit / enforce modes (Phase 0/1)
// ---------------------------------------------------------------------------

#[test]
fn audit_mode_reports_would_deny_but_proceeds() {
    // First-party root is trusted by default, so the probe's spawn is denied by
    // an explicit policy `deny` (a denial wins over root trust) — that is the
    // would-deny audit surfaces while still letting the operation proceed.
    let out = run_ibex(
        &[
            "--capsec",
            "audit",
            "--policy",
            &fixture("audit-spawn-policy.json"),
            "run",
            &fixture("audit-probe.js"),
        ],
        &[],
        None,
    );
    // The operation proceeds (audit does not block)...
    assert!(
        out.stdout.contains("spawn: audit-probe-ran"),
        "audit mode must let the spawn proceed:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // ...and a would-deny report is emitted.
    assert!(
        out.stderr.contains("would-deny under enforce mode"),
        "audit mode must print a would-deny report:\n{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("process:spawn"),
        "the ungranted spawn should appear in the audit report:\n{}",
        out.stderr
    );
    // Audit never blocks, so the run exits cleanly.
    assert_eq!(
        out.status, 0,
        "audit run should exit 0; stderr:\n{}",
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// fs:write is gated on the actual open access (regression: the fd-based write
// path only ever checked fs:read).
// ---------------------------------------------------------------------------

#[test]
fn fs_write_requires_fs_write_capability() {
    let dir = fixtures_dir().join("fs-write-gate");
    let readable = dir.join("readable.txt");
    let out = dir.join("out");
    // Only fs:read granted: the read succeeds, the write is denied.
    let ro = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("readonly-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[
            ("OUTDIR", &out.to_string_lossy()),
            ("READABLE", &readable.to_string_lossy()),
        ],
        Some(&dir),
    );
    assert!(
        ro.stdout.contains("write: DENIED") && ro.stdout.contains("read: OK"),
        "fs:read alone must allow reads but deny writes:\nstdout:\n{}\nstderr:\n{}",
        ro.stdout,
        ro.stderr
    );
    // ENG-22627: path-based mutators (truncate, symlink) are gated on fs:write too.
    assert!(
        ro.stdout.contains("truncate: DENIED") && ro.stdout.contains("symlink: DENIED"),
        "path-based fs mutators must be denied without fs:write:\nstdout:\n{}\nstderr:\n{}",
        ro.stdout,
        ro.stderr
    );
    // With fs granted, the write succeeds.
    let rw = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("readwrite-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[
            ("OUTDIR", &out.to_string_lossy()),
            ("READABLE", &readable.to_string_lossy()),
        ],
        Some(&dir),
    );
    assert!(
        rw.stdout.contains("write: SUCCEEDED"),
        "fs (read+write) must allow the write:\nstdout:\n{}\nstderr:\n{}",
        rw.stdout,
        rw.stderr
    );
    // ENG-22627: with fs:write granted, the path-based mutators succeed (the gate
    // permits, not blocks) — proving the DENIED above is enforcement, not breakage.
    assert!(
        rw.stdout.contains("truncate: SUCCEEDED") && rw.stdout.contains("symlink: SUCCEEDED"),
        "path-based fs mutators must succeed when fs:write is granted:\nstdout:\n{}\nstderr:\n{}",
        rw.stdout,
        rw.stderr
    );
}

// ---------------------------------------------------------------------------
// Authority-bearing attenuator handles (Phase 4 / §Delegation)
//
// A package with no ambient fs uses a handle the app hands it: reads within the
// handle's grant succeed (possession-based, not frame-based), reads outside are
// denied, `scoped()` re-attenuates to a narrower grant, and revoking the root
// handle fail-closes it and every handle derived from it.
// ---------------------------------------------------------------------------

#[test]
fn attenuator_handle_delegation_scoping_and_revocation() {
    let dir = fixtures_dir().join("handles");
    let policy = dir.join("ibex-policy.json");
    let images = dir.join("images");
    let secret = dir.join("secret.txt");
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &policy.to_string_lossy(),
            "run",
            "app.js",
        ],
        &[
            ("IMAGES", &images.to_string_lossy()),
            ("SECRET", &secret.to_string_lossy()),
            ("EXACT_COMPAT_TEST", "1"),
        ],
        Some(&dir),
    );
    // Ambient fs denied; the passed handle works within its grant only; the
    // re-attenuated (scoped) handle is narrower; revocation fail-closes.
    assert!(
        out.stdout.contains(
            "result: ambient=DENIED within=LOGO-BYTES outside=DENIED scoped-in=THUMB-BYTES scoped-out=DENIED"
        ),
        "handle delegation/scoping failed:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stdout.contains("after-revoke: DENIED"),
        "revocation should fail-close the handle:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// Per-package bundled units (frame attribution for a *bundled* app)
//
// A flat bundle collapses to one Domain, so a bundled dependency is attributed
// to root. With per-package chunking (IBEX_PER_PACKAGE_CHUNKS) each package
// becomes its own chunk that loads into its own Domain, so a bundled app gets
// per-package frame attribution too.
// ---------------------------------------------------------------------------

#[test]
fn per_package_chunks_give_bundled_apps_frame_attribution() {
    if !cfg!(exact_frame_attribution) {
        eprintln!("skipping: frame attribution needs the patched Hermes engine");
        return;
    }
    if !have_js_runner() {
        eprintln!("skipping: per-package chunking needs the bundler (bun/node)");
        return;
    }
    let dir = fixtures_dir().join("per-package-chunks");
    let policy = dir.join("ibex-policy.json");
    let secret = dir.join("secret.txt");
    let args = [
        "--capsec",
        "enforce",
        "--policy",
        &policy.to_string_lossy() as &str,
        "run",
        "app.js",
    ];
    // Bundled with per-package chunking: evil-pkg loads into its own Domain, so
    // its deferred read is attributed to evil-pkg and denied; the app's succeeds.
    let chunked = run_ibex(
        &args,
        &[
            ("SECRETPATH", &secret.to_string_lossy()),
            ("IBEX_PER_PACKAGE_CHUNKS", "1"),
        ],
        Some(&dir),
    );
    assert!(
        chunked.stdout.contains("app-deferred: READ:TOPSECRET-ppc")
            && chunked.stdout.contains("evil-deferred: CONTAINED")
            && !chunked.stdout.contains("evil-deferred: STOLEN"),
        "per-package chunking should give the bundled dependency its own principal:\nstdout:\n{}\nstderr:\n{}",
        chunked.stdout,
        chunked.stderr
    );
    // The entry keeps a source-relative __dirname even though sibling package
    // chunks are resolved from the cache dir.
    assert!(
        chunked.stdout.contains("dirname-source: true"),
        "entry __dirname should stay source-relative under per-package chunking:\nstdout:\n{}\nstderr:\n{}",
        chunked.stdout,
        chunked.stderr
    );
    // Control: a flat bundle collapses to one Domain, so the dependency's read is
    // attributed to root and succeeds (proving the chunking is what separates it).
    let flat = run_ibex(
        &args,
        &[("SECRETPATH", &secret.to_string_lossy())],
        Some(&dir),
    );
    assert!(
        flat.stdout.contains("evil-deferred: STOLEN:TOPSECRET-ppc"),
        "a flat bundle should collapse to one Domain (control):\nstdout:\n{}\nstderr:\n{}",
        flat.stdout,
        flat.stderr
    );
}

// ---------------------------------------------------------------------------
// Dynamic permissions: tri-state status + ceiling-bounded runtime grants
// (Phase 4 / §Interaction with user-facing dynamic permissions)
// ---------------------------------------------------------------------------

#[test]
fn permission_acquisition_is_async_with_a_pluggable_broker() {
    // Acquisition is async (returns a Promise); the sync status query reflects
    // the resolved grant. The default broker approves within-ceiling caps; a
    // custom broker can reject.
    let dir = fixtures_dir().join("async-broker");
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[],
        Some(&dir),
    );
    for expected in [
        "before: prompt",
        "acquired: true after: granted",
        "denied-acquire: false status: denied",
        "broker-reject: false status: prompt",
    ] {
        assert!(
            out.stdout.contains(expected),
            "expected {expected}:\nstdout:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    }
}

#[test]
fn dynamic_permissions_are_tri_state_and_bounded_by_the_ceiling() {
    let dir = fixtures_dir().join("dynamic-permissions");
    let policy = dir.join("ibex-policy.json");
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &policy.to_string_lossy(),
            "run",
            "app.js",
        ],
        &[],
        Some(&dir),
    );
    // A capability in the ceiling is `prompt` until requested, then `granted`,
    // and returns to `prompt` after revoke.
    for expected in [
        "fetch-before: prompt",
        "fetch-request: true",
        "fetch-after: granted",
        "fetch-revoked: prompt",
    ] {
        assert!(
            out.stdout.contains(expected),
            "expected {expected}:\nstdout:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    }
    // A capability outside the ceiling is `denied`, and a runtime request for it
    // must fail — the static artifact is the ceiling, dynamic grants never
    // exceed it.
    assert!(
        out.stdout.contains("loc-status: denied") && out.stdout.contains("loc-request: false"),
        "a capability outside the ceiling must stay denied and un-grantable:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// Native compartments (Mechanism 2, Phase 3)
//
// With the carried Hermes patch stack, the interpreter resolves bare-global
// references and sloppy-mode `this` through the executing frame's Domain
// compartment global — a per-package object that withholds powerful globals —
// with NO build-time source rewrite. The package here runs unbundled, so any
// containment is the native engine path, not a transform.
// ---------------------------------------------------------------------------

#[test]
fn native_compartment_withholds_globals_without_rewrite() {
    if !cfg!(exact_frame_attribution) {
        eprintln!("skipping: native compartments need the patched Hermes engine");
        return;
    }
    let dir = fixtures_dir().join("native-compartment");
    let out = run_ibex(
        &["--lockdown", "run", "app.js"],
        &[("IBEX_COMPARTMENTS", "1"), ("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );
    // The app (root) keeps the real global.
    assert!(
        out.stdout.contains("app-process: object"),
        "root should retain process:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // evil-pkg's bare `process` AND its sloppy-`this` UMD escape both resolve
    // through its compartment natively — both withheld, no source rewrite.
    assert!(
        out.stdout
            .contains("evil: bare-process=undefined this-process=undefined"),
        "native compartment should withhold process via both bare-global and sloppy-this:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn eval_and_function_inherit_the_caller_compartment() {
    if !cfg!(exact_frame_attribution) {
        eprintln!("skipping: eval/Function binding needs the patched Hermes engine");
        return;
    }
    // Even with eval + Function endowed to the package, code they produce
    // inherits the package's compartment (captured at the eval call site), so
    // `process` stays withheld — dynamic code cannot escape the compartment.
    let dir = fixtures_dir().join("eval-binding");
    let out = run_ibex(
        &["run", "app.js"],
        &[
            ("IBEX_COMPARTMENTS", "1"),
            ("IBEX_ENDOW", "evil-pkg:Function,eval"),
            ("EXACT_COMPAT_TEST", "1"),
        ],
        Some(&dir),
    );
    assert!(
        out.stdout.contains("evil: fn=undefined directEval=undefined"),
        "eval/Function-produced code must inherit the compartment (process withheld):\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn native_lockdown_freezes_intrinsics_and_contains_redteam() {
    if !cfg!(exact_frame_attribution) {
        eprintln!("skipping: native lockdown needs the patched Hermes engine");
        return;
    }
    // IBEX_NATIVE_LOCKDOWN freezes the intrinsics graph natively
    // (__exactDeepFreeze) instead of the JS walk — the runtime stays usable and
    // the red-team attacks are still contained.
    let conf = run_ibex(
        &["--lockdown", "run", &fixture("lockdown-conformance.js")],
        &[("IBEX_NATIVE_LOCKDOWN", "1")],
        None,
    );
    for expected in [
        "lockedDown=true",
        "mapWorks=true",
        "instanceofWorks=true",
        "frozenProtoThrows=true",
    ] {
        assert!(
            conf.stdout.contains(expected),
            "native lockdown must keep the runtime usable ({expected}):\nstdout:\n{}\nstderr:\n{}",
            conf.stdout,
            conf.stderr
        );
    }
    let redteam = run_ibex(
        &["--lockdown", "run", &fixture("redteam.js")],
        &[("IBEX_NATIVE_LOCKDOWN", "1")],
        None,
    );
    assert!(
        !redteam.stdout.contains("NOT_CONTAINED"),
        "native lockdown must contain the red-team attacks:\nstdout:\n{}\nstderr:\n{}",
        redteam.stdout,
        redteam.stderr
    );
}

#[test]
fn native_deep_freeze_freezes_a_graph_without_invoking_getters() {
    if !cfg!(exact_frame_attribution) {
        eprintln!("skipping: native deep-freeze needs the patched Hermes engine");
        return;
    }
    // The native transitive deep-freeze freezes the whole reachable graph
    // (nested objects, array elements) via descriptors — without invoking the
    // accessor getter (getterCalls stays 0).
    let js = "var g = { a: { b: { c: 1 } }, arr: [ { x: 1 } ] }; var calls = 0; \
              Object.defineProperty(g, 'acc', { get: function(){ calls++; return {}; }, configurable: true }); \
              globalThis.__exactDeepFreeze(g); \
              console.log('df: ' + Object.isFrozen(g) + ',' + Object.isFrozen(g.a) + ',' + \
                Object.isFrozen(g.a.b) + ',' + Object.isFrozen(g.arr[0]) + ',' + calls);";
    let dir = unique_dir("deepfreeze");
    let path = dir.join("df.js");
    std::fs::write(&path, js).unwrap();
    let out = run_ibex(&["run", &path.to_string_lossy()], &[], None);
    assert!(
        out.stdout.contains("df: true,true,true,true,0"),
        "deep-freeze should freeze the graph without invoking getters:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn permission_onchange_signals_grants_and_revocations() {
    // The grant-change signal fires on request/revoke (so handles/embedder react
    // to revocation) and stops after unsubscribe.
    let js = "var log = []; \
              var off = Ibex.permissions.onChange(function (cap, status) { log.push(cap + '=' + status); }); \
              Ibex.permissions.request('network:fetch'); \
              Ibex.permissions.revoke('network:fetch'); \
              off(); \
              Ibex.permissions.request('network:fetch'); \
              console.log('changes: ' + log.join(' '));";
    let dir = unique_dir("onchange");
    let path = dir.join("oc.js");
    std::fs::write(&path, js).unwrap();
    let policy = dir.join("policy.json");
    std::fs::write(
        &policy,
        r#"{ "mode":"enforce", "allow":["fs","process","crypto","time","env","os"], "ceiling":["network:fetch"] }"#,
    )
    .unwrap();
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &policy.to_string_lossy(),
            "run",
            &path.to_string_lossy(),
        ],
        &[],
        None,
    );
    assert!(
        out.stdout
            .contains("changes: network:fetch=granted network:fetch=prompt"),
        "onChange should fire on grant + revoke and stop after unsubscribe:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn native_freeze_primitive_freezes_objects() {
    if !cfg!(exact_frame_attribution) {
        eprintln!("skipping: native freeze needs the patched Hermes engine");
        return;
    }
    // @ref LLP 0013#mechanism-1 (Phase 3) — the native freeze primitive freezes
    // an object and returns it; a subsequent write is a no-op.
    let js = "var o = { a: 1 }; var r = globalThis.__exactNativeFreeze(o); \
              try { o.a = 2; } catch (e) {} \
              console.log('freeze: ' + Object.isFrozen(o) + ',' + o.a + ',' + (r === o));";
    let dir = unique_dir("freeze");
    let path = dir.join("f.js");
    std::fs::write(&path, js).unwrap();
    let out = run_ibex(&["run", &path.to_string_lossy()], &[], None);
    assert!(
        out.stdout.contains("freeze: true,1,true"),
        "native freeze should freeze the object and return it:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn native_compartment_control_no_containment_without_compartments() {
    // Same unbundled package, no compartments: it reaches process both ways.
    let dir = fixtures_dir().join("native-compartment");
    let out = run_ibex(
        &["run", "app.js"],
        &[("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );
    assert!(
        out.stdout
            .contains("evil: bare-process=object this-process=object"),
        "without compartments the unbundled package reaches process (control):\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// Import-graph gate (Policy surface 3)
//
// Builtins are reachable by `require`, so withholding the `fs` endowment is not
// containment if a package can still `require('fs')`. Import policy is the
// primary gate. This uses the loader's package registration + the check_import
// ABI, so it holds on patched and unpatched engines alike.
// ---------------------------------------------------------------------------

#[test]
fn import_gate_denies_restricted_package_builtin() {
    let dir = fixtures_dir().join("import-gate");
    let policy = dir.join("ibex-policy.json");
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &policy.to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );
    // The app (root) may import fs.
    assert!(
        out.stdout.contains("app-fs: function"),
        "the root app should be able to import fs:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // evil-pkg has `builtins: []` — its require('fs') is denied by import policy.
    assert!(
        out.stdout.contains("evil-import: IMPORT-DENIED"),
        "evil-pkg's forbidden builtin import should be denied:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // ENG-22618/ENG-22629: the alternate require surfaces (globalThis.require and
    // dynamic import()) are gated by the requesting frame's principal too, not
    // bypassed as root.
    assert!(
        out.stdout.contains("evil-global-require: IMPORT-DENIED"),
        "globalThis.require must be gated by the package principal:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stdout.contains("evil-dynamic-import: IMPORT-DENIED"),
        "dynamic import() must be gated by the package principal:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn import_gate_is_inert_without_restriction() {
    // Same graph, but evil-pkg has no import policy: the gate is inert and the
    // import proceeds (import policy only bites what the app restricts).
    let dir = fixtures_dir().join("import-gate");
    let policy = dir.join("ibex-policy-open.json");
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &policy.to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );
    assert!(
        out.stdout.contains("evil-import: IMPORTED:function"),
        "an unrestricted package should still import fs:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // ENG-22618/ENG-22629 control: the gate is inert on every surface, not just
    // static require, when the package is unrestricted.
    assert!(
        out.stdout
            .contains("evil-global-require: IMPORTED:function")
            && out
                .stdout
                .contains("evil-dynamic-import: IMPORTED:function"),
        "unrestricted package: alternate require surfaces still import:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn capsec_aliases_parse() {
    // `strict` and `capability` are back-compat aliases for `enforce`.
    for mode in ["strict", "capability", "enforce", "audit", "permissive"] {
        let out = run_ibex(
            &["--capsec", mode, "run", &fixture("lockdown-conformance.js")],
            &[],
            None,
        );
        assert!(
            !out.stderr.contains("invalid value"),
            "--capsec {mode} should parse; stderr:\n{}",
            out.stderr
        );
    }
    // An unknown mode is rejected.
    let out = run_ibex(
        &[
            "--capsec",
            "bogus",
            "run",
            &fixture("lockdown-conformance.js"),
        ],
        &[],
        None,
    );
    assert!(
        out.stderr.contains("invalid value"),
        "unknown --capsec should be rejected:\n{}",
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// Frame-derived attribution (Mechanism 3 / Phase 2)
//
// These require the carried Hermes patch stack (patches/hermes/0001-0003): the
// engine must attribute a host-boundary capability check to the executing
// frame's package, not a thread-local. build.rs sets `exact_frame_attribution`
// when the linked framework exports the bridge; without it the runtime falls
// back to the forgeable thread-local id and these properties do not hold, so the
// tests skip rather than fail on an unpatched engine.
// ---------------------------------------------------------------------------

/// The malicious dependency and the app both defer an ordinary `fs.readFileSync`
/// into a Promise microtask that runs after their modules finish evaluating —
/// the exact point where the legacy thread-local attribution has reverted to the
/// caller. The read flows through the trusted `fs` runtime module (a deputy).
/// With frame attribution the app's callback (root Domain) reads the secret
/// while the dependency's callback (its own Domain) is denied. Same API, same
/// async mechanism, same deputy, different principal, different outcome: that is
/// frame accuracy.
#[test]
fn frame_attribution_denies_deferred_dependency_but_allows_app() {
    if !cfg!(exact_frame_attribution) {
        eprintln!("skipping: engine built without frame attribution (unpatched Hermes framework)");
        return;
    }
    let dir = fixtures_dir().join("frame-attribution");
    let policy = dir.join("ibex-policy.json");
    let secret = dir.join("secret.txt");
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &policy.to_string_lossy(),
            "run",
            "app.js",
        ],
        &[
            ("SECRETPATH", &secret.to_string_lossy()),
            ("EXACT_COMPAT_TEST", "1"),
        ],
        Some(&dir),
    );
    // The app is the root principal and is granted fs — its deferred read
    // succeeds.
    assert!(
        out.stdout.contains("app-deferred: READ:TOPSECRET-llp0013"),
        "the app's own deferred read should be allowed (root principal):\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // evil-pkg is granted nothing — its deferred read through the same async
    // path and the same fs deputy is attributed to evil-pkg and denied.
    assert!(
        !out.stdout.contains("STOLEN:"),
        "the compromised dependency exfiltrated the secret — frame attribution failed:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stdout.contains("evil-deferred: CONTAINED"),
        "the dependency's deferred read should be contained:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

// Red-team: a dependency must not launder a deputy op past frame attribution by
// DETACHING it from its own frame — passing the fs method directly as a promise
// callback (`.then(fs.readFileSync)`), so the reaction runs with no evil frame on
// the stack. The internal Promise trampoline is a runtime deputy (runtime
// principal), not first-party root, so the walk reaches no user frame and fails
// closed. Regression for the internal-bytecode principal stamp + kNoUserPrincipal
// sentinel. @ref LLP 0013#mechanism-3
#[test]
fn detached_deputy_read_is_contained_but_app_wrapped_read_works() {
    if !cfg!(exact_frame_attribution) {
        eprintln!("skipping: engine built without frame attribution (unpatched Hermes framework)");
        return;
    }
    let dir = fixtures_dir().join("detached-deputy");
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[
            ("SECRETPATH", &dir.join("secret.txt").to_string_lossy()),
            ("EXACT_COMPAT_TEST", "1"),
        ],
        Some(&dir),
    );
    // The app (root) is granted fs — its own wrapped async read succeeds.
    assert!(
        out.stdout.contains("app: READ:TOPSECRET-detached"),
        "the app's own wrapped read should be allowed (root principal):\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // evil-pkg's read is contained BOTH when wrapped (its frame is seen) and when
    // detached (no frame → fails closed), and the secret never leaks.
    assert!(
        out.stdout
            .contains("evil: attached:CONTAINED detached:CONTAINED")
            && !out.stdout.contains("STOLEN"),
        "the dependency's detached-deputy read must be contained:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

/// Control: in permissive mode nothing is enforced, so the same deferred read
/// exfiltrates the secret. This proves the containment above is the capability
/// system working, not a broken fs path or a dead code path.
#[test]
fn frame_attribution_control_permissive_leaks() {
    let dir = fixtures_dir().join("frame-attribution");
    let secret = dir.join("secret.txt");
    let out = run_ibex(
        &["--capsec", "permissive", "run", "app.js"],
        &[
            ("SECRETPATH", &secret.to_string_lossy()),
            ("EXACT_COMPAT_TEST", "1"),
        ],
        Some(&dir),
    );
    assert!(
        out.stdout.contains("STOLEN:TOPSECRET-llp0013"),
        "permissive mode should let the dependency read the file (control):\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// Stack-intersection / deputy hardening (Phase 5)
//
// deputy-pkg is granted fs:read and reads whatever path a caller hands it. With
// `deputyClasses: ["fs:read"]` the effective grant for an fs:read is the AND of
// every principal on the call stack, so the deputy may read for the app (root,
// granted) but not for evil-pkg (ungranted) — closing the confused-deputy hole
// that default per-package attribution intentionally leaves open. Needs the
// real principal stack, so it requires frame attribution.
// ---------------------------------------------------------------------------

#[test]
fn stack_intersection_denies_deputy_driven_by_ungranted_caller() {
    if !cfg!(exact_frame_attribution) {
        eprintln!("skipping: stack intersection needs frame attribution");
        return;
    }
    let dir = fixtures_dir().join("deputy");
    let policy = dir.join("ibex-policy.json");
    let secret = dir.join("secret.txt");
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &policy.to_string_lossy(),
            "run",
            "app.js",
        ],
        &[
            ("SECRETPATH", &secret.to_string_lossy()),
            ("EXACT_COMPAT_TEST", "1"),
        ],
        Some(&dir),
    );
    // The deputy reads for the app (both principals on the stack are granted).
    assert!(
        out.stdout
            .contains("app-via-deputy: READ:DEPUTY-SECRET-llp0013"),
        "the deputy should read for the granted app:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // The same deputy is denied when driven by the ungranted package.
    assert!(
        out.stdout.contains("evil-via-deputy: CONTAINED")
            && !out.stdout.contains("evil-via-deputy: STOLEN"),
        "stack intersection should deny the deputy acting for evil-pkg:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn stack_intersection_is_off_by_default() {
    if !cfg!(exact_frame_attribution) {
        eprintln!("skipping: stack intersection needs frame attribution");
        return;
    }
    // Same graph, same grants, but no deputyClasses: the deputy acts with its
    // own authority for anyone (deputy-by-design is out of scope by default).
    let dir = fixtures_dir().join("deputy");
    let policy = dir.join("ibex-policy-nodeputy.json");
    let secret = dir.join("secret.txt");
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &policy.to_string_lossy(),
            "run",
            "app.js",
        ],
        &[
            ("SECRETPATH", &secret.to_string_lossy()),
            ("EXACT_COMPAT_TEST", "1"),
        ],
        Some(&dir),
    );
    assert!(
        out.stdout.contains("evil-via-deputy: STOLEN:DEPUTY-SECRET-llp0013"),
        "without deputyClasses the deputy should act for anyone (proves Phase 5 is opt-in):\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}
