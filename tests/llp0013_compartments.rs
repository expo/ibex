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
///
/// The advisory hatch is on by default: these suites exercise capability
/// *decision* logic and must keep running on checkouts whose Hermes lacks the
/// frame-attribution bridge, where `--capsec enforce` now fails closed
/// (ENG-22884). The fail-closed gate itself is covered by
/// `capsec_enforce_fails_closed_on_missing_attribution_prerequisites`, which
/// overrides this default. Caller env wins (applied after this).
fn run_ibex(args: &[&str], envs: &[(&str, &str)], cwd: Option<&Path>) -> RunOutput {
    let mut cmd = Command::new(IBEX);
    cmd.args(args);
    cmd.env("IBEX_CAPSEC_ALLOW_ADVISORY", "1");
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

fn write_text(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    std::fs::write(path, contents).expect("write test file");
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

/// Shared gate for the frame-attribution suites: on an unpatched Hermes
/// (no `exact_frame_attribution` cfg) they cannot observe anything, so they
/// skip — but libtest counts an early `return` as PASS, so a runner that
/// *expects* the patched engine (compartment-conformance CI, a dev machine
/// that just built the patched framework) would be certified green while 18
/// tests verified nothing. Setting `IBEX_REQUIRE_FRAME_ATTRIBUTION=1` turns
/// the silent skip into a loud failure. @ref LLP 0018#the-governing-rule
fn frame_attribution_unavailable() -> bool {
    if cfg!(exact_frame_attribution) {
        return false;
    }
    if std::env::var("IBEX_REQUIRE_FRAME_ATTRIBUTION").is_ok_and(|v| !v.is_empty() && v != "0") {
        panic!(
            "IBEX_REQUIRE_FRAME_ATTRIBUTION is set, but this binary was built without the \
             patched Hermes frame-attribution engine (cfg exact_frame_attribution). Build the \
             patched framework (scripts/download-hermes.sh) and rebuild, or unset the variable \
             to allow the frame-attribution tests to self-skip."
        );
    }
    true
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
// IBEX_ENDOW cannot widen policy endowments under enforce (ENG-22684)
//
// Under an enforce-mode policy the generated artifact is the sole endowment
// source: an ambient/operator-set IBEX_ENDOW must not hand a package a powerful
// global (`process`) the policy withholds. The `--allow-env-endowments` escape
// hatch restores the ambient override, and permissive mode is unaffected —
// each proven with the same fixture so the suppression is a live gate, not a
// dead path.
// ---------------------------------------------------------------------------

#[test]
fn env_endowments_cannot_widen_policy_under_enforce() {
    let dir = unique_dir("endow-precedence");
    // A generated-shaped enforce policy that endows evil-pkg with nothing.
    std::fs::write(
        dir.join("policy.json"),
        r#"{ "mode":"enforce", "packages":{ "evil-pkg":{} } }"#,
    )
    .unwrap();
    let policy = dir.join("policy.json").to_string_lossy().into_owned();

    // Enforce, no hatch: the ambient IBEX_ENDOW is dropped, so evil-pkg does not
    // receive `process`, and the drop is reported on stderr.
    let enforced = run_ibex(
        &[
            "--lockdown",
            "--capsec",
            "enforce",
            "--policy",
            &policy,
            "run",
            &fixture("compartment-endowment.js"),
        ],
        &[("IBEX_ENDOW", "evil-pkg:process")],
        None,
    );
    assert!(
        enforced.stdout.contains("evil.process=undefined"),
        "IBEX_ENDOW must not widen a package's globals under enforce:\nstdout:\n{}\nstderr:\n{}",
        enforced.stdout,
        enforced.stderr
    );
    assert!(
        enforced.stderr.contains("IBEX_ENDOW ignored"),
        "the dropped env endowment should be reported:\nstdout:\n{}\nstderr:\n{}",
        enforced.stdout,
        enforced.stderr
    );

    // Enforce, no policy file resolved: still fail closed. This guards the early
    // return where a stale ambient IBEX_ENDOW used to survive if policy discovery
    // found no readable artifact. (ENG-22761)
    let home = unique_dir("endow-no-policy-home");
    let xdg = unique_dir("endow-no-policy-xdg");
    let home_str = home.to_string_lossy().into_owned();
    let xdg_str = xdg.to_string_lossy().into_owned();
    let no_policy = run_ibex(
        &[
            "--lockdown",
            "--capsec",
            "enforce",
            "run",
            &fixture("compartment-endowment.js"),
        ],
        &[
            ("IBEX_ENDOW", "evil-pkg:process"),
            ("IBEX_POLICY", ""),
            ("EXACT_POLICY", ""),
            ("HOME", &home_str),
            ("XDG_CONFIG_HOME", &xdg_str),
        ],
        None,
    );
    assert!(
        no_policy.stdout.contains("evil.process=undefined"),
        "IBEX_ENDOW must be cleared under enforce even when no policy file exists:\nstdout:\n{}\nstderr:\n{}",
        no_policy.stdout,
        no_policy.stderr
    );
    assert!(
        no_policy.stderr.contains("IBEX_ENDOW ignored"),
        "the no-policy fail-closed drop should be reported:\nstdout:\n{}\nstderr:\n{}",
        no_policy.stdout,
        no_policy.stderr
    );

    // Escape hatch: the ambient override is honored again (proves the deny above
    // is a live suppression).
    let hatched = run_ibex(
        &[
            "--lockdown",
            "--capsec",
            "enforce",
            "--allow-env-endowments",
            "--policy",
            &policy,
            "run",
            &fixture("compartment-endowment.js"),
        ],
        &[("IBEX_ENDOW", "evil-pkg:process")],
        None,
    );
    assert!(
        hatched.stdout.contains("evil.process=object"),
        "--allow-env-endowments should restore the ambient override:\nstdout:\n{}\nstderr:\n{}",
        hatched.stdout,
        hatched.stderr
    );

    // Permissive (no policy): back-compat — IBEX_ENDOW still endows.
    let permissive = run_ibex(
        &["--lockdown", "run", &fixture("compartment-endowment.js")],
        &[("IBEX_ENDOW", "evil-pkg:process")],
        None,
    );
    assert!(
        permissive.stdout.contains("evil.process=object"),
        "permissive mode must keep honoring IBEX_ENDOW:\nstdout:\n{}\nstderr:\n{}",
        permissive.stdout,
        permissive.stderr
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&xdg);
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
    // This exercises the Mechanism-2 *endowment rewrite* (env-reader reaches the
    // endowed `process`; evil-pkg's is withheld), which is a build-time,
    // flat-bundle mechanism. Enforce now auto-enables per-package chunking
    // (ENG-22681), which additionally attributes env-reader's `process.env` read
    // to its own principal and gates it on `env:read` — a capability the
    // `process:env` import grant does not confer (that per-principal gating is
    // covered by env_reads_are_gated_with_no_plain_snapshot_bypass and
    // capability.rs::env_read_is_gated_per_principal). Pin the flat bundle here
    // with the explicit advisory hatch so this test stays about endowment
    // reachability, not env-read gating.
    let out = run_ibex(
        &[
            "--lockdown",
            "--capsec-allow-advisory",
            "--policy",
            dir.join("runtime-policy.json").to_str().unwrap(),
            "run",
            dir.join("app.mjs").to_str().unwrap(),
        ],
        &[
            ("SECRET_TOKEN", "hunter2"),
            ("IBEX_PER_PACKAGE_CHUNKS", "0"),
        ],
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

// @ref LLP 0014#generator — (ENG-22818) — the generated cascade operates on
// version-qualified identities, so a delegate declared by one installed version
// cannot flow along a coexisting version's import edge. Fixture: top-level
// shared-pkg@2.0.0 imports helper-pkg but declares no delegates; nested
// shared-pkg@1.0.0 delegates fs:read to helper-pkg but never imports it. No
// single version both imports helper-pkg and delegates to it, so no grant may
// reach helper-pkg (the bare-name merge that this test guards against would have
// handed it fs:read).
#[test]
fn generated_policy_keeps_delegation_version_local() {
    if !have_js_runner() {
        eprintln!("skipping: generator (bun/node) not available");
        return;
    }
    // Own copy: the bundle cache is keyed by entry path.
    let dir = unique_dir("versioned-deleg");
    copy_dir_recursive(&fixtures_dir().join("versioned-delegation"), &dir);
    let policy = dir.join("ibex-policy.json");
    let out = run_ibex(
        &[
            "policy",
            "generate",
            "--entry",
            dir.join("app.mjs").to_str().unwrap(),
            "--out",
            policy.to_str().unwrap(),
        ],
        &[],
        None,
    );
    assert_eq!(
        out.status, 0,
        "policy generation should succeed:\nstdout:\n{}\nstderr:\n{}",
        out.stdout, out.stderr
    );
    let artifact: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&policy).unwrap()).unwrap();
    let principals = artifact["principals"].as_array().expect("principals array");
    // No helper-pkg selector (bare or identity) may carry a capability.
    for key in ["helper-pkg@1.0.0"] {
        let entry = principals
            .iter()
            .find(|entry| entry["principal"]["locator"] == key)
            .unwrap_or_else(|| panic!("expected {key} in the analyzed graph"));
        assert!(
            entry["floor"].as_array().is_some_and(Vec::is_empty),
            "cross-version delegation leak: {key} received a capability:\n{}",
            serde_json::to_string_pretty(&artifact).unwrap()
        );
    }
    // The app-wide import-site grant still reaches shared-pkg under the bare name.
    assert!(
        principals
            .iter()
            .any(|entry| entry["principal"]["locator"] == "shared-pkg@2.0.0"
                && entry["floor"]
                    .as_array()
                    .is_some_and(|rows| !rows.is_empty())),
        "the import-site grant on shared-pkg must survive:\n{}",
        serde_json::to_string_pretty(&artifact).unwrap()
    );
    let _ = std::fs::remove_dir_all(&dir);
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
        "import steal from \"evil-pkg\" with { authorities: \"[{\\\"cap\\\":\\\"network:fetch\\\",\\\"resource\\\":{\\\"kind\\\":\\\"fetch-endpoint\\\",\\\"schemes\\\":[\\\"https\\\"],\\\"host\\\":{\\\"kind\\\":\\\"dns-name\\\",\\\"name\\\":\\\"example.com\\\"},\\\"port\\\":{\\\"kind\\\":\\\"exact\\\",\\\"value\\\":443},\\\"peerClasses\\\":[\\\"public\\\"],\\\"route\\\":{\\\"kind\\\":\\\"direct\\\"}}}]\" };",
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
        out.stderr.contains("network:fetch"),
        "the expanded grant should be named:\n{}",
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Generated policy closes the builtins import axis by default (ENG-22683)
//
// A generated package entry emits an explicit `builtins` list (empty when the
// package imports no builtin), so an omitted field can only ever come from a
// hand-authored policy. A statically-observed builtin import is allowlisted (so
// legit imports keep working under enforce); a builtin reached through a
// computed specifier the generator can't see stays denied (fail closed).
// ---------------------------------------------------------------------------

#[test]
fn generated_policy_closes_builtins_axis() {
    if !have_js_runner() {
        eprintln!("skipping: bundler/generator (bun/node) not available");
        return;
    }
    let dir = fixtures_dir().join("generated-builtins");
    let policy = dir.join("runtime-policy.json");
    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &policy.to_string_lossy(),
            "run",
            "app.mjs",
        ],
        &[],
        Some(&dir),
    );
    // Observed static builtin import (`node:os`) is allowlisted → works.
    assert!(
        out.stdout.contains("os-user:   OK:function"),
        "a statically-imported builtin the generator observed must stay allowed:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // A builtin reached via a computed specifier is not in the allowlist → denied.
    assert!(
        out.stdout.contains("sneaky-os: IMPORT-DENIED"),
        "a builtin not in the generated allowlist must be denied under enforce:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn generated_builtins_artifact_is_in_sync() {
    if !have_js_runner() {
        eprintln!("skipping: generator (bun/node) not available");
        return;
    }
    // The committed generated-builtins artifact regenerates byte-identically,
    // and its version-qualified `os-user` identity carries the observed
    // `node:os` allowlist while `sneaky-os` stays `[]` (deny-all).
    let out = run_ibex(
        &[
            "policy",
            "check",
            "--entry",
            fixtures_dir()
                .join("generated-builtins")
                .join("app.mjs")
                .to_str()
                .unwrap(),
        ],
        &[],
        None,
    );
    assert_eq!(
        out.status, 0,
        "committed generated-builtins artifact drifted:\nstdout:\n{}\nstderr:\n{}",
        out.stdout, out.stderr
    );
}

#[test]
fn policy_check_reports_builtin_expansion_on_drift() {
    if !have_js_runner() {
        eprintln!("skipping: generator (bun/node) not available");
        return;
    }
    let dir = unique_dir("builtins-drift");
    copy_dir_recursive(&fixtures_dir().join("generated-builtins"), &dir);
    // os-user grows a new builtin import the committed allowlist doesn't have.
    let os_user = dir.join("node_modules").join("os-user").join("index.js");
    let source = std::fs::read_to_string(&os_user).unwrap().replace(
        "var os = require(\"os\");",
        "var os = require(\"os\");\nvar cp = require(\"child_process\");",
    );
    std::fs::write(&os_user, source).unwrap();
    let out = run_ibex(
        &[
            "policy",
            "check",
            "--entry",
            dir.join("app.mjs").to_str().unwrap(),
        ],
        &[],
        None,
    );
    assert_ne!(
        out.status, 0,
        "builtin drift must fail the check:\n{}",
        out.stdout
    );
    assert!(
        out.stderr.contains("EXPANSIONS")
            && out
                .stderr
                .contains("os-user@1.0.0: import node:child_process"),
        "a new builtin import must surface as an import-axis expansion:\nstderr:\n{}",
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn generated_policy_observes_relative_cjs_bridge_dependencies() {
    if !have_js_runner() {
        eprintln!("skipping: generator (bun/node) not available");
        return;
    }
    let dir = unique_dir("generated-cjs-bridge");
    let bridge = dir.join("node_modules").join("bridge-pkg");
    let child = dir.join("node_modules").join("child-pkg");
    std::fs::create_dir_all(&bridge).unwrap();
    std::fs::create_dir_all(&child).unwrap();
    std::fs::write(
        dir.join("app.mjs"),
        r#"import bridge from "bridge-pkg";
console.log(bridge());
"#,
    )
    .unwrap();
    std::fs::write(
        bridge.join("package.json"),
        r#"{ "name":"bridge-pkg", "version":"1.2.3", "main":"index.js" }"#,
    )
    .unwrap();
    std::fs::write(
        bridge.join("index.js"),
        r#"module.exports = require("./bridge.cjs");"#,
    )
    .unwrap();
    std::fs::write(
        bridge.join("bridge.cjs"),
        r#"var os = require("os");
var child = require("child-pkg");
module.exports = function bridge() { return os.platform() + ":" + child.name; };
"#,
    )
    .unwrap();
    std::fs::write(
        child.join("package.json"),
        r#"{ "name":"child-pkg", "version":"0.5.0", "main":"index.js" }"#,
    )
    .unwrap();
    std::fs::write(child.join("index.js"), r#"exports.name = "child";"#).unwrap();

    let policy = dir.join("ibex-policy.json");
    let out = run_ibex(
        &[
            "policy",
            "generate",
            "--entry",
            dir.join("app.mjs").to_str().unwrap(),
            "--out",
            policy.to_str().unwrap(),
        ],
        &[],
        None,
    );
    assert_eq!(
        out.status, 0,
        "policy generation should analyze relative CJS bridge modules:\nstdout:\n{}\nstderr:\n{}",
        out.stdout, out.stderr
    );
    let artifact = std::fs::read_to_string(&policy).unwrap();
    assert!(
        artifact.contains(r#""bridge-pkg@1.2.3""#)
            && artifact.contains(r#""node:os""#)
            && artifact.contains(r#""child-pkg""#),
        "policy artifact must include bridge identity, observed builtin, and child package:\n{}",
        artifact
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn generated_policy_observed_builtins_are_version_scoped() {
    if !have_js_runner() {
        eprintln!("skipping: generator (bun/node) not available");
        return;
    }
    let dir = unique_dir("generated-version-builtins");
    let top = dir.join("node_modules").join("shared-pkg");
    let uses_old = dir.join("node_modules").join("uses-old");
    let old = uses_old.join("node_modules").join("shared-pkg");
    std::fs::create_dir_all(&top).unwrap();
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(
        dir.join("app.js"),
        r#"require("shared-pkg");
require("uses-old");
"#,
    )
    .unwrap();
    std::fs::write(
        top.join("package.json"),
        r#"{ "name":"shared-pkg", "version":"2.0.0", "main":"index.js" }"#,
    )
    .unwrap();
    std::fs::write(top.join("index.js"), r#"exports.v = "v2";"#).unwrap();
    std::fs::write(
        uses_old.join("package.json"),
        r#"{ "name":"uses-old", "version":"1.0.0", "main":"index.js" }"#,
    )
    .unwrap();
    std::fs::write(
        uses_old.join("index.js"),
        r#"module.exports = require("shared-pkg");"#,
    )
    .unwrap();
    std::fs::write(
        old.join("package.json"),
        r#"{ "name":"shared-pkg", "version":"1.0.0", "main":"index.js" }"#,
    )
    .unwrap();
    std::fs::write(
        old.join("index.js"),
        r#"var os = require("os");
exports.platform = os.platform();
"#,
    )
    .unwrap();

    let policy = dir.join("ibex-policy.json");
    let out = run_ibex(
        &[
            "policy",
            "generate",
            "--entry",
            dir.join("app.js").to_str().unwrap(),
            "--out",
            policy.to_str().unwrap(),
        ],
        &[],
        None,
    );
    assert_eq!(
        out.status, 0,
        "policy generation should distinguish coexisting package versions:\nstdout:\n{}\nstderr:\n{}",
        out.stdout, out.stderr
    );
    let artifact: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&policy).unwrap()).unwrap();
    let principals = artifact["principals"]
        .as_array()
        .expect("generated principals array");
    let old = principals
        .iter()
        .find(|entry| entry["principal"]["locator"] == "shared-pkg@1.0.0")
        .unwrap();
    let top = principals
        .iter()
        .find(|entry| entry["principal"]["locator"] == "shared-pkg@2.0.0")
        .unwrap();
    let old_builtins = old["imports"]["builtins"]
        .as_array()
        .expect("old shared-pkg builtins array");
    let top_builtins = top["imports"]["builtins"]
        .as_array()
        .expect("top shared-pkg builtins array");
    assert!(
        old_builtins.iter().any(|b| b == "node:os"),
        "nested shared-pkg@1.0.0 should carry its observed os import:\n{}",
        artifact
    );
    assert!(
        !top_builtins.iter().any(|b| b == "node:os"),
        "top shared-pkg@2.0.0 must not inherit the nested version's builtin import:\n{}",
        artifact
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
    let dir = unique_dir("fs-write-gate");
    copy_dir_recursive(&fixtures_dir().join("fs-write-gate"), &dir);
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
        ro.stdout.contains("truncate: DENIED")
            && ro.stdout.contains("symlink: DENIED")
            && (!cfg!(unix) || ro.stdout.contains("fchmod-read-fd: DENIED")),
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
        rw.stdout.contains("truncate: SUCCEEDED")
            && rw.stdout.contains("symlink: SUCCEEDED")
            && (!cfg!(unix) || rw.stdout.contains("fchmod-read-fd: SUCCEEDED")),
        "path-based fs mutators must succeed when fs:write is granted:\nstdout:\n{}\nstderr:\n{}",
        rw.stdout,
        rw.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn posix_access_w_ok_requires_fs_write_capability() {
    let dir = unique_dir("access-w-ok");
    let file = dir.join("writable.txt");
    write_text(&file, "writable");
    let pkg = dir.join("node_modules").join("access-probe");
    write_text(
        &pkg.join("package.json"),
        r#"{"name":"access-probe","version":"1.0.0","main":"index.js"}"#,
    );
    write_text(
        &pkg.join("index.js"),
        r#"
const fs = require("fs");
exports.run = function(path) {
  try {
    fs.accessSync(path, fs.constants.W_OK);
    return "W_OK: ALLOWED";
  } catch (e) {
    return String(e && e.message || e).indexOf("Permission denied") !== -1
      ? "W_OK: DENIED"
      : "W_OK: ERR";
  }
};
"#,
    );
    write_text(
        &dir.join("app.js"),
        &format!(
            "console.log(require('access-probe').run({}));\n",
            serde_json::to_string(&file.to_string_lossy()).unwrap()
        ),
    );
    let policy = serde_json::json!({
        "mode": "enforce",
        "packages": {
            "access-probe": {
                "capabilities": [format!("fs:read:{}", file.to_string_lossy())]
            }
        }
    });
    write_text(&dir.join("ibex-policy.json"), &policy.to_string());

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
    assert!(
        out.stdout.contains("W_OK: DENIED"),
        "fs.access(W_OK) must require fs:write, not only fs:read:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[cfg(unix)]
#[test]
fn link_own_metadata_gates_the_link_path_not_the_target() {
    let dir = unique_dir("link-own-metadata");
    let target = dir.join("target.txt");
    let link = dir.join("link.txt");
    write_text(&target, "target");
    std::os::unix::fs::symlink(&target, &link).expect("create symlink");

    let pkg = dir.join("node_modules").join("link-probe");
    write_text(
        &pkg.join("package.json"),
        r#"{"name":"link-probe","version":"1.0.0","main":"index.js"}"#,
    );
    write_text(
        &pkg.join("index.js"),
        r#"
const fs = require("fs");
function classify(fn) {
  try {
    fn();
    return "OK";
  } catch (e) {
    return String(e && e.message || e).indexOf("Permission denied") !== -1
      ? "CAP_DENIED"
      : "SYSCALL";
  }
}
exports.run = function(path) {
  return [
    "lchown=" + classify(function() { fs.lchownSync(path, 0, 0); }),
    "lutimes=" + classify(function() { fs.lutimesSync(path, new Date(), new Date()); }),
    "lchmod=" + classify(function() { fs.lchmodSync(path, 0o777); })
  ].join(" ");
};
"#,
    );
    write_text(
        &dir.join("app.js"),
        &format!(
            "console.log(require('link-probe').run({}));\n",
            serde_json::to_string(&link.to_string_lossy()).unwrap()
        ),
    );

    let target_policy = serde_json::json!({
        "mode": "enforce",
        "packages": {
            "link-probe": {
                "capabilities": [format!("fs:write:{}", target.to_string_lossy())]
            }
        }
    });
    write_text(&dir.join("target-policy.json"), &target_policy.to_string());
    let target_out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("target-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[],
        Some(&dir),
    );
    assert!(
        target_out
            .stdout
            .contains("lchown=CAP_DENIED lutimes=CAP_DENIED lchmod=CAP_DENIED"),
        "a grant on the symlink target must not authorize link-own metadata:\nstdout:\n{}\nstderr:\n{}",
        target_out.stdout,
        target_out.stderr
    );

    let link_policy = serde_json::json!({
        "mode": "enforce",
        "packages": {
            "link-probe": {
                "capabilities": [format!("fs:write:{}", link.to_string_lossy())]
            }
        }
    });
    write_text(&dir.join("link-policy.json"), &link_policy.to_string());
    let link_out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("link-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[],
        Some(&dir),
    );
    assert!(
        !link_out.stdout.contains("CAP_DENIED"),
        "a grant on the symlink path should pass the capability gate; platform syscall errors are okay:\nstdout:\n{}\nstderr:\n{}",
        link_out.stdout,
        link_out.stderr
    );
}

#[test]
fn mkdtemp_checks_the_created_directory_path_not_only_the_prefix() {
    let dir = unique_dir("mkdtemp-actual");
    let base = dir.canonicalize().expect("canonicalize temp base");
    let base_str = base.to_string_lossy().into_owned();
    let prefix = base.join("tmp-");
    let prefix_str = prefix.to_string_lossy().into_owned();
    let policy = serde_json::json!({
        "mode": "enforce",
        "allow": [
            format!("fs:read:{base_str}/**"),
            format!("fs:write:{prefix_str}"),
            "network",
            "process",
            "crypto",
            "time",
            "env",
            "os",
            "device",
            "worker",
            "ffi"
        ],
        "ceiling": ["network:fetch:example.invalid"]
    })
    .to_string();
    std::fs::write(base.join("ibex-policy.json"), policy).unwrap();
    std::fs::write(
        base.join("app.js"),
        r#"var fs = require("fs");
var prefix = process.env.PREFIX;
try {
  var made = fs.mkdtempSync(prefix);
  console.log("mkdtemp-exact-prefix: SUCCEEDED:" + made);
  try { fs.rmdirSync(made); } catch (_) {}
} catch (e) {
  var msg = (e && e.message) || "";
  console.log("mkdtemp-exact-prefix: DENIED:" + msg);
}
"#,
    )
    .unwrap();

    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &base.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("PREFIX", &prefix_str), ("EXACT_COMPAT_TEST", "1")],
        Some(&base),
    );
    assert!(
        out.stdout.contains("mkdtemp-exact-prefix: DENIED"),
        "mkdtemp must gate the actual created path, not the unsuffixed prefix:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    let created = std::fs::read_dir(&base)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            entry.file_name().to_string_lossy().starts_with("tmp-")
                && entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
        });
    assert!(
        !created,
        "denied mkdtemp must not leave behind a suffixed directory"
    );

    let allowed_policy = serde_json::json!({
        "mode": "enforce",
        "allow": [
            format!("fs:read:{base_str}/**"),
            format!("fs:write:{base_str}/**"),
            "network",
            "process",
            "crypto",
            "time",
            "env",
            "os",
            "device",
            "worker",
            "ffi"
        ],
        "ceiling": ["network:fetch:example.invalid"]
    })
    .to_string();
    std::fs::write(base.join("ibex-policy.json"), allowed_policy).unwrap();
    let allowed = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &base.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("PREFIX", &prefix_str), ("EXACT_COMPAT_TEST", "1")],
        Some(&base),
    );
    assert!(
        allowed.stdout.contains("mkdtemp-exact-prefix: SUCCEEDED"),
        "positive control: mkdtemp should succeed when the actual suffixed path is allowed:\nstdout:\n{}\nstderr:\n{}",
        allowed.stdout,
        allowed.stderr
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn native_byte_extraction_rejects_forged_arraybuffer_view_bounds() {
    let dir = unique_dir("native-byte-bounds");
    let out_file = dir.join("out.bin");
    let policy = serde_json::json!({
        "mode": "enforce",
        "allow": [
            "fs",
            "network",
            "process",
            "crypto",
            "time",
            "env",
            "os",
            "device",
            "worker",
            "ffi"
        ]
    })
    .to_string();
    std::fs::write(dir.join("ibex-policy.json"), policy).unwrap();
    std::fs::write(
        dir.join("app.js"),
        r#"var fs = require("fs");
var fd = fs.openSync(process.env.OUTFILE, "w");
try {
  globalThis.__exactFsWrite(fd, new Uint8Array([1, 2, 3, 4]), -1);
  console.log("real-view: WROTE");
  var forged = { buffer: new ArrayBuffer(4), byteOffset: 3, byteLength: 4 };
  globalThis.__exactFsWrite(fd, forged, -1);
  console.log("forged-view: ACCEPTED");
} catch (e) {
  console.log("forged-view: REJECTED");
} finally {
  fs.closeSync(fd);
}
console.log("forged-size: " + fs.statSync(process.env.OUTFILE).size);
"#,
    )
    .unwrap();

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
            ("OUTFILE", &out_file.to_string_lossy()),
            ("EXACT_COMPAT_TEST", "1"),
        ],
        Some(&dir),
    );
    assert!(
        out.stdout.contains("forged-view: REJECTED")
            && out.stdout.contains("real-view: WROTE")
            && out.stdout.contains("forged-size: 4")
            && !out.stdout.contains("forged-view: ACCEPTED"),
        "native byte extraction must accept real views but reject forged view bounds before the second write:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Symlink escape from a path-scoped fs:write grant (ENG-22682)
//
// A grant `fs:write:<base>/granted/**` must be matched against the
// symlink-resolved path, not the supplied spelling. With `granted/link` a
// symlink to `outside/`, a write to `granted/link/escaped.txt` (leaf missing,
// so the old lexical fallback kept the syntactic `granted/**` prefix) must be
// DENIED because the parent resolves outside the grant — while an ordinary
// in-tree write still succeeds (proving the deny is the resolution, not a
// blanket block). A `ceiling` is configured so the first-party root loses its
// ambient trust and the path-scoped grant actually binds.
//
// Unix-only: the escape is planted with a real symlink, so the test is
// meaningless without one — gate the whole test rather than assert ordinary-path
// semantics on non-Unix. (ENG-22702)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn path_scoped_write_grant_cannot_escape_through_a_symlink() {
    let dir = unique_dir("fs-symlink-escape");
    // Canonicalize: macOS temp lives under /var → /private/var, so the grant
    // string must be built from the resolved base to compare with resolved
    // check values.
    let base = dir.canonicalize().expect("canonicalize temp base");
    std::fs::create_dir_all(base.join("granted").join("real")).unwrap();
    std::fs::create_dir_all(base.join("outside")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(base.join("outside"), base.join("granted").join("link"))
        .expect("plant escaping symlink");

    let base_str = base.to_string_lossy().into_owned();
    // Path-scoped write grant + a (harmless) ceiling so root is no longer
    // blanket-trusted and the path scope binds. `env`/`os`/etc. keep the app
    // runnable under enforce.
    let policy = format!(
        r#"{{ "mode":"enforce",
              "allow":["fs:write:{base}/granted/**","fs:read","env","process","os","network","crypto","time","device","worker","ffi"],
              "ceiling":["network:fetch:example.invalid"] }}"#,
        base = base_str
    );
    std::fs::write(base.join("ibex-policy.json"), policy).unwrap();
    std::fs::write(
        base.join("app.js"),
        r#"var fs = require("fs");
var base = process.env.BASE;
function probe(label, path) {
  try { fs.writeFileSync(path, "x"); console.log(label + ": SUCCEEDED"); }
  catch (e) {
    var msg = (e && e.message) || "";
    console.log(label + ": " + (msg.indexOf("Permission denied") !== -1 ? "DENIED" : "ERR"));
  }
}
probe("escape", base + "/granted/link/escaped.txt");
probe("in-tree", base + "/granted/real/escaped.txt");
"#,
    )
    .unwrap();

    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &base.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("BASE", &base_str), ("EXACT_COMPAT_TEST", "1")],
        Some(&base),
    );

    // The escaping write is denied; the in-tree write succeeds (control).
    assert!(
        out.stdout.contains("escape: DENIED"),
        "a write through a symlink escaping the granted tree must be denied:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stdout.contains("in-tree: SUCCEEDED"),
        "an ordinary in-tree write must still succeed (grant binds):\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // And nothing was created outside the grant on disk.
    assert!(
        !base.join("outside").join("escaped.txt").exists(),
        "the escaping write must not have created a file outside the grant"
    );

    let _ = std::fs::remove_dir_all(&dir);
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
// Handles dropped by JS with no explicit revoke() are auto-reclaimed (ENG-23010)
//
// The FsHandle wrapper registers itself in a FinalizationRegistry whose cleanup
// callback invokes __exactRevokeHandle(id); revoke evicts the handle and its
// whole descendant subtree (ENG-22955). So a wrapper the app drops WITHOUT
// calling revoke() is reclaimed once it is garbage-collected — closing the
// drop-without-revoke unbounded-growth path a long-running server hits when it
// mints a per-request handle and relies on GC. A handle the app still holds a
// strong reference to survives GC (the revoke is targeted, not blanket), and the
// explicit revoke() path is unchanged.
//
// Runs in allow-all mode so minting needs no frame attribution: the possession
// check, gc(), and FinalizationRegistry are all core/Rust and framework-
// independent, so this does NOT skip vacuously on the stock checked-in Hermes
// (unlike the enforce-mode frame-attribution suites). If the runtime exposes no
// gc() to force a collection the finalizer can't be driven deterministically, so
// the auto-revoke assertion is skipped (and reported) rather than flaking.
// ---------------------------------------------------------------------------

const HANDLE_FINALIZER_APP_JS: &str = r#"var g = globalThis;
var dir = process.env.HDIR;
var file = dir + '/data.txt';
function state(id) {
  try { g.__exactHandleReadFileSync(id, file); return 'LIVE'; }
  catch (e) { return (String(e && e.message).indexOf('does not grant') !== -1) ? 'REVOKED' : 'ERR'; }
}
console.log('gc-available=' + (typeof gc === 'function'));
// kept: a strong reference is held, so GC must not collect (or revoke) it.
var kept = Ibex.fs.readHandle(dir);
var keptId = kept._id;
// dropped: minted inside an IIFE and released — GC should auto-revoke it.
var droppedId;
(function () { var h = Ibex.fs.readHandle(dir); droppedId = h._id; })();
console.log('dropped-before=' + state(droppedId) + ' kept-before=' + state(keptId));
if (typeof gc === 'function') gc();
setTimeout(function () {
  if (typeof gc === 'function') gc();
  setTimeout(function () {
    if (typeof gc === 'function') gc();
    setTimeout(function () {
      console.log('dropped-after=' + state(droppedId) + ' kept-after=' + state(keptId));
      kept.revoke();
      console.log('kept-after-revoke=' + state(keptId));
    }, 30);
  }, 30);
}, 30);
"#;

#[test]
fn dropped_handle_is_auto_revoked_when_garbage_collected() {
    let dir = unique_dir("handle-finalizer");
    write_text(&dir.join("data.txt"), "hello-handle-data");
    write_text(&dir.join("app.js"), HANDLE_FINALIZER_APP_JS);
    let out = run_ibex(
        &["run", "app.js"],
        &[("HDIR", &dir.to_string_lossy())],
        Some(&dir),
    );
    // Preconditions: both handles start live (proves minting + possession work,
    // so a later REVOKED is a real state change, not a mint that never happened).
    assert!(
        out.stdout.contains("dropped-before=LIVE kept-before=LIVE"),
        "both handles should start live:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // The explicit revoke() path is unchanged and still fail-closes.
    assert!(
        out.stdout.contains("kept-after-revoke=REVOKED"),
        "explicit revoke() must still fail-close the handle:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    if out.stdout.contains("gc-available=true") {
        // Core assertion: the dropped wrapper is auto-revoked on GC, while the
        // still-referenced one survives — proving the reclamation is driven by
        // the specific wrapper's finalization, not a blanket/timed revoke.
        assert!(
            out.stdout.contains("dropped-after=REVOKED kept-after=LIVE"),
            "a dropped handle must be auto-revoked on GC while a held handle survives:\nstdout:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    } else {
        eprintln!("skipping auto-revoke assertion: runtime exposes no gc() to force a collection");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// GC of a delegation parent must NOT over-revoke a still-in-use child (ENG-23029)
//
// The headline delegation pattern is "mint broad -> scope narrow -> hand the
// child off -> forget the parent". `scoped()` returns a fresh FsHandle wrapping
// only the child id, so the parent wrapper can become an unreachable temporary
// while the child is still held and in use. The GC auto-revoke (ENG-23010) routes
// a collected wrapper's id to __exactRevokeHandle, which cascade-evicts the id AND
// its descendant subtree — so collecting the parent wrapper would revoke the live
// child. The fix pins the parent on the child (`child.__parent = this`) so a live
// descendant keeps its ancestors reachable and the parent finalizer can't fire
// while any child is in use.
//
// Same framework-independence and gc()-gating as the ENG-23010 test above: the
// possession read, gc(), and FinalizationRegistry are core/Rust, so this does not
// skip vacuously on the stock checked-in Hermes. When gc() drives collection this
// FAILS on the pre-fix cascade (child-after=REVOKED) and passes with the pin.
// ---------------------------------------------------------------------------

const HANDLE_PARENT_PIN_APP_JS: &str = r#"var g = globalThis;
var dir = process.env.HDIR;
var file = dir + '/images/data.txt';
function childState(id) {
  try { g.__exactHandleReadFileSync(id, file); return 'LIVE'; }
  catch (e) { return (String(e && e.message).indexOf('does not grant') !== -1) ? 'REVOKED' : 'ERR'; }
}
console.log('gc-available=' + (typeof gc === 'function'));
// Mint broad, scope narrow, keep ONLY the child: the parent wrapper is a
// temporary that goes unreachable when this IIFE returns.
var child;
var childId;
(function () {
  var parent = Ibex.fs.readHandle(dir);
  child = parent.scoped('images');
  childId = child._id;
})();
console.log('child-before=' + childState(childId));
if (typeof gc === 'function') gc();
setTimeout(function () {
  if (typeof gc === 'function') gc();
  setTimeout(function () {
    if (typeof gc === 'function') gc();
    setTimeout(function () {
      // The child is still strongly referenced and in use, so GC of the parent
      // wrapper must not have revoked it.
      console.log('child-after=' + childState(childId));
    }, 30);
  }, 30);
}, 30);
"#;

#[test]
fn gc_of_delegation_parent_does_not_over_revoke_live_child() {
    let dir = unique_dir("handle-parent-pin");
    write_text(&dir.join("images").join("data.txt"), "child-handle-data");
    write_text(&dir.join("app.js"), HANDLE_PARENT_PIN_APP_JS);
    let out = run_ibex(
        &["run", "app.js"],
        &[("HDIR", &dir.to_string_lossy())],
        Some(&dir),
    );
    // Precondition: the scoped child is usable before any GC (proves the mint +
    // scope + possession read work, so a later REVOKED is a real regression).
    assert!(
        out.stdout.contains("child-before=LIVE"),
        "the scoped child handle should be usable before GC:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    if out.stdout.contains("gc-available=true") {
        assert!(
            out.stdout.contains("child-after=LIVE"),
            "GC of the (temporary) delegation parent must not over-revoke the still-held child:\nstdout:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    } else {
        eprintln!("skipping over-revoke assertion: runtime exposes no gc() to force a collection");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Exact fs grants cannot mint subtree handles (ENG-22882)
//
// Handle grant coverage uses the same path algebra as ambient capability
// matching: an exact `fs:read:<path>` grant is exact — it can mint an exact
// handle for that path (usable on exactly that resource), but neither
// `Ibex.fs.readHandle(dir)` (which mints `fs:read:<dir>/**`) nor the minted
// exact handle may reach descendants. Only an ambient `/**` subtree grant
// mints a working directory handle.
// ---------------------------------------------------------------------------

#[test]
fn exact_fs_grant_cannot_mint_subtree_handle() {
    if frame_attribution_unavailable() {
        // Without the patched engine every ambient mint is denied outright
        // (misattributed principal), so the exact-vs-subtree distinction this
        // test guards is unobservable — same gate as the per-package test.
        eprintln!("skipping: frame attribution needs the patched Hermes engine");
        return;
    }
    let dir = unique_dir("handle-exact-grant");
    // Canonicalize: macOS temp lives under /var → /private/var, so grant
    // strings must be built from the resolved base.
    let base = dir.canonicalize().expect("canonicalize temp base");
    let data = base.join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("child.txt"), "CHILD-BYTES\n").unwrap();
    std::fs::write(data.join("exact.txt"), "EXACT-BYTES\n").unwrap();
    let sub = base.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("file.txt"), "SUB-BYTES\n").unwrap();

    let base_str = base.to_string_lossy().into_owned();
    // Root module "0": an exact grant on the data dir, an exact grant on one
    // file inside it, and a `/**` subtree grant on `sub` as the positive
    // control. The loader keeps broad read so app.js itself loads.
    let policy = format!(
        r#"{{ "mode":"enforce",
              "allow":["env","process","os","network","crypto","time","device","worker","ffi"],
              "modules": {{
                "0": {{ "allow":["fs:read:{base}/data","fs:read:{base}/data/exact.txt","fs:read:{base}/sub/**"] }},
                "module-loader": {{ "allow":["fs:read"] }} }} }}"#,
        base = base_str
    );
    std::fs::write(base.join("ibex-policy.json"), policy).unwrap();
    std::fs::write(
        base.join("app.js"),
        r#"var base = process.env.BASE;
// Exact ambient grant on the dir: minting a *subtree* handle must fail.
try { Ibex.fs.readHandle(base + '/data'); console.log('mint-subtree: MINTED'); }
catch (e) { console.log('mint-subtree: DENIED'); }
// The exact resource itself can still be minted as an exact handle...
var id = 0;
try { id = globalThis.__exactCreateHandle('fs:read:' + base + '/data'); } catch (e) {}
console.log('mint-exact: ' + (id ? 'MINTED' : 'DENIED'));
// ...but that handle must not read descendants (the amplification bug).
try { globalThis.__exactHandleReadFileSync(id, base + '/data/child.txt'); console.log('exact-child: LEAKED'); }
catch (e) { console.log('exact-child: DENIED'); }
// An exact file grant mints a handle that reads exactly that file.
var fid = 0;
try { fid = globalThis.__exactCreateHandle('fs:read:' + base + '/data/exact.txt'); } catch (e) {}
try {
  var bytes = globalThis.__exactHandleReadFileSync(fid, base + '/data/exact.txt');
  var s = ''; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  console.log('exact-self: ' + s.trim());
} catch (e) { console.log('exact-self: DENIED'); }
// Control: an ambient `/**` subtree grant mints a working directory handle.
try {
  var h = Ibex.fs.readHandle(base + '/sub');
  console.log('subtree: ' + h.readTextSync(base + '/sub/file.txt').trim());
} catch (e) { console.log('subtree: DENIED'); }
"#,
    )
    .unwrap();

    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &base.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("BASE", &base_str), ("EXACT_COMPAT_TEST", "1")],
        Some(&base),
    );

    assert!(
        out.stdout.contains("mint-subtree: DENIED"),
        "readHandle over an exact grant must not mint subtree authority:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stdout.contains("mint-exact: MINTED") && out.stdout.contains("exact-child: DENIED"),
        "an exact-grant handle must cover only the exact resource:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stdout.contains("exact-self: EXACT-BYTES"),
        "an exact file grant should still mint a handle usable on that file:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stdout.contains("subtree: SUB-BYTES"),
        "a /** subtree grant should mint a working directory handle:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );

    let _ = std::fs::remove_dir_all(&dir);
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
    if frame_attribution_unavailable() {
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
    // Enforce auto-enables chunking (ENG-22681), so the flat control must opt out
    // explicitly with IBEX_PER_PACKAGE_CHUNKS=0 and acknowledge the advisory
    // attribution downgrade.
    let flat_args = [
        "--capsec",
        "enforce",
        "--capsec-allow-advisory",
        "--policy",
        &policy.to_string_lossy() as &str,
        "run",
        "app.js",
    ];
    let flat = run_ibex(
        &flat_args,
        &[
            ("SECRETPATH", &secret.to_string_lossy()),
            ("IBEX_PER_PACKAGE_CHUNKS", "0"),
        ],
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
// Enforce auto-enables per-package attribution for a bundled app (ENG-22681)
//
// `ibex run --policy <mode:enforce>` (no --capsec, no IBEX_* env) must not leave
// a bundled dependency attributed to root: enforce implies per-package chunking,
// so the dependency loads into its own Domain and its ungranted read is denied.
// The explicit `IBEX_PER_PACKAGE_CHUNKS=0` opt-out plus
// `--capsec-allow-advisory` restores the flat behavior (proving the
// auto-enable is what contains it).
// ---------------------------------------------------------------------------

#[test]
fn policy_declared_enforce_auto_enables_bundled_attribution() {
    if frame_attribution_unavailable() {
        eprintln!("skipping: frame attribution needs the patched Hermes engine");
        return;
    }
    if !have_js_runner() {
        eprintln!("skipping: per-package chunking needs the bundler (bun/node)");
        return;
    }
    // Own copy: the bundle cache is keyed by entry path, and this run must not
    // collide with per_package_chunks_give_bundled_apps_frame_attribution.
    let dir = unique_dir("enforce-auto-attr");
    copy_dir_recursive(&fixtures_dir().join("per-package-chunks"), &dir);
    let policy = dir.join("ibex-policy.json"); // fixture policy declares mode:enforce
    let secret = dir.join("secret.txt");
    // No --capsec (Auto → the policy's enforce), and no IBEX_PER_PACKAGE_CHUNKS.
    let auto = run_ibex(
        &["--policy", &policy.to_string_lossy(), "run", "app.js"],
        &[("SECRETPATH", &secret.to_string_lossy())],
        Some(&dir),
    );
    assert!(
        auto.stdout.contains("app-deferred: READ:TOPSECRET-ppc")
            && auto.stdout.contains("evil-deferred: CONTAINED")
            && !auto.stdout.contains("evil-deferred: STOLEN"),
        "a policy-declared enforce run must auto-enable per-package attribution:\nstdout:\n{}\nstderr:\n{}",
        auto.stdout,
        auto.stderr
    );

    // Opt out: the flat bundle collapses to root again (control for the auto-enable).
    let opt_out = run_ibex(
        &[
            "--capsec-allow-advisory",
            "--policy",
            &policy.to_string_lossy(),
            "run",
            "app.js",
        ],
        &[
            ("SECRETPATH", &secret.to_string_lossy()),
            ("IBEX_PER_PACKAGE_CHUNKS", "0"),
        ],
        Some(&dir),
    );
    assert!(
        opt_out.stdout.contains("evil-deferred: STOLEN:TOPSECRET-ppc"),
        "IBEX_PER_PACKAGE_CHUNKS=0 must restore the flat (root-attributed) behavior:\nstdout:\n{}\nstderr:\n{}",
        opt_out.stdout,
        opt_out.stderr
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn enforce_rejects_disabled_package_isolation_without_advisory_flag() {
    let dir = unique_dir("advisory-readiness-deny");
    write_text(&dir.join("app.js"), "console.log('READYNESS-APP-RAN');\n");
    write_text(&dir.join("ibex-policy.json"), r#"{"mode":"enforce"}"#);

    let out = run_ibex(
        &["--policy", "ibex-policy.json", "run", "app.js"],
        &[
            ("IBEX_PER_PACKAGE_CHUNKS", "0"),
            ("IBEX_CAPSEC_ALLOW_ADVISORY", "0"),
        ],
        Some(&dir),
    );

    assert_ne!(
        out.status, 0,
        "enforce must fail when package isolation is explicitly disabled:\nstdout:\n{}\nstderr:\n{}",
        out.stdout, out.stderr
    );
    assert!(
        out.stderr
            .contains("capsec enforce requires attribution prerequisites")
            && out.stderr.contains("per-package principal isolation")
            && out.stderr.contains("--capsec-allow-advisory")
            && !out.stdout.contains("READYNESS-APP-RAN"),
        "failure should name the advisory-attribution hatch and stop before app code:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn advisory_attribution_flag_makes_downgrade_explicit() {
    let dir = unique_dir("advisory-readiness-allow");
    write_text(&dir.join("app.js"), "console.log('READINESS-APP-RAN');\n");
    write_text(&dir.join("ibex-policy.json"), r#"{"mode":"enforce"}"#);

    let out = run_ibex(
        &[
            "--capsec-allow-advisory",
            "--policy",
            "ibex-policy.json",
            "run",
            "app.js",
        ],
        &[("IBEX_PER_PACKAGE_CHUNKS", "0")],
        Some(&dir),
    );

    assert_eq!(
        out.status, 0,
        "explicit advisory attribution should allow the downgraded run:\nstdout:\n{}\nstderr:\n{}",
        out.stdout, out.stderr
    );
    assert!(
        out.stdout.contains("READINESS-APP-RAN")
            && out.stderr.contains("capsec readiness:")
            && out
                .stderr
                .contains("package-isolation=disabled(IBEX_PER_PACKAGE_CHUNKS=0)")
            && out.stderr.contains("ADVISORY attribution"),
        "downgraded run should be reported loudly:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Version-distinguished principals and policy selectors (ENG-22621)
//
// Two installed versions of one package coexist (shared-pkg@2.0.0 top-level and
// shared-pkg@1.0.0 nested under uses-old). The loader gives each its own
// `name@version` principal, so a policy that grants the bare `shared-pkg`
// selector fs:read but pins `shared-pkg@1.0.0` with a deny treats the two
// versions differently — the pinned version is contained while the other reads.
// The control (bare grant only) reads through both, proving the pin discriminates.
// ---------------------------------------------------------------------------

#[test]
fn coexisting_versions_get_distinct_policy_treatment() {
    if frame_attribution_unavailable() {
        eprintln!("skipping: version-distinguished attribution needs the patched Hermes engine");
        return;
    }
    let dir = fixtures_dir().join("versioned-pkgs");
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
    // shared-pkg@2.0.0 (bare selector grant) reads; shared-pkg@1.0.0 (pinned
    // deny) is contained — the two versions get different treatment.
    assert!(
        out.stdout.contains("direct-v2: READ:TOPSECRET-versioned"),
        "the unpinned version should read via the bare `shared-pkg` grant:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        out.stdout.contains("via-old-v1: DENIED"),
        "the pinned `shared-pkg@1.0.0` version should be denied:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );

    // Control: with only the bare `shared-pkg` grant (no version pin), the grant
    // applies to every resolved version, so BOTH read — proving the pin above is
    // what discriminates, not a coincidental denial.
    let ctrl_dir = unique_dir("versioned-control");
    std::fs::write(
        ctrl_dir.join("policy.json"),
        r#"{ "mode":"enforce",
             "allow":["process","env","os","crypto","time","network","device","worker","ffi"],
             "packages": { "shared-pkg": { "capabilities": ["fs:read"] } } }"#,
    )
    .unwrap();
    let control = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &ctrl_dir.join("policy.json").to_string_lossy(),
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
        control.stdout.contains("direct-v2: READ:TOPSECRET-versioned")
            && control.stdout.contains("via-old-v1: READ:TOPSECRET-versioned"),
        "the bare selector grant should apply to every version (control):\nstdout:\n{}\nstderr:\n{}",
        control.stdout,
        control.stderr
    );
    let _ = std::fs::remove_dir_all(&ctrl_dir);

    // Bundled path: enforce auto-enables per-package chunking, and the bundler
    // groups by the version identity, so the two versions land in separate
    // chunks (`__ibexpkg__shared-pkg@1.0.0` / `@2.0.0`) → separate Domains →
    // separate principals. The devtools chunk grouping and the runtime registry
    // agree on the identity (criterion c). Needs the bundler.
    if have_js_runner() {
        let bundled = run_ibex(
            &[
                "--capsec",
                "enforce",
                "--policy",
                &policy.to_string_lossy(),
                "run",
                "app.js",
            ],
            &[("SECRETPATH", &secret.to_string_lossy())],
            Some(&dir),
        );
        assert!(
            bundled.stdout.contains("direct-v2: READ:TOPSECRET-versioned")
                && bundled.stdout.contains("via-old-v1: DENIED"),
            "a bundled app must distinguish the two versions via per-version chunks:\nstdout:\n{}\nstderr:\n{}",
            bundled.stdout,
            bundled.stderr
        );
    }
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
    if frame_attribution_unavailable() {
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
    if frame_attribution_unavailable() {
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
    if frame_attribution_unavailable() {
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
    if frame_attribution_unavailable() {
        eprintln!("skipping: native deep-freeze needs the patched Hermes engine");
        return;
    }
    // @ref LLP 0013#mechanism-1 — (ENG-23112 finding L) — `__exactDeepFreeze` is an
    // INTERNAL primitive the bootstrap lockdown pass consumes; it must NOT stay
    // reachable from package code after bootstrap. Left reachable in the default
    // (non-lockdown) enforce/audit mode — where the compartment membrane that
    // would withhold `__exact*` never runs — a package could call
    // `globalThis.__exactDeepFreeze(x)` to transitively freeze shared intrinsics or
    // another package's object graph: an ungated native integrity/DoS primitive
    // while every other dangerous native is capability-gated. The end-of-bootstrap
    // freeze seal deletes it in ALL modes; assert user script observes it as
    // undefined. (The deep-freeze algorithm itself is still exercised via the
    // internal lockdown consumer in native_lockdown_freezes_intrinsics_and_contains_redteam.)
    let js = "console.log('deepfreeze-typeof: ' + typeof globalThis.__exactDeepFreeze);";
    let dir = unique_dir("deepfreeze-sealed");
    let path = dir.join("df.js");
    std::fs::write(&path, js).unwrap();
    let out = run_ibex(&["run", &path.to_string_lossy()], &[], None);
    assert!(
        out.stdout.contains("deepfreeze-typeof: undefined"),
        "__exactDeepFreeze must be sealed away from package code in all modes:\nstdout:\n{}\nstderr:\n{}",
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
    if frame_attribution_unavailable() {
        eprintln!("skipping: native freeze needs the patched Hermes engine");
        return;
    }
    // @ref LLP 0013#mechanism-1 — (ENG-23112 finding L) like `__exactDeepFreeze`,
    // the shallow `__exactNativeFreeze` primitive must not remain reachable from
    // package code after bootstrap. The end-of-bootstrap freeze seal deletes it in
    // ALL modes; assert user script observes it as undefined.
    let js = "console.log('nativefreeze-typeof: ' + typeof globalThis.__exactNativeFreeze);";
    let dir = unique_dir("freeze-sealed");
    let path = dir.join("f.js");
    std::fs::write(&path, js).unwrap();
    let out = run_ibex(&["run", &path.to_string_lossy()], &[], None);
    assert!(
        out.stdout.contains("nativefreeze-typeof: undefined"),
        "__exactNativeFreeze must be sealed away from package code in all modes:\nstdout:\n{}\nstderr:\n{}",
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
// Runtime capability-escape channels closed under enforce (ENG-22695/96/97)
//
// A compromised dependency (evil-pkg, granted nothing, builtins:[]) must not be
// able to: self-grant via Exact.setModuleCapabilities (22695), import a builtin
// through a detached globalThis.require callback (22696), or import a builtin
// via the exact:/bun: alias namespaces (22697). Each has a permissive control
// proving the enforce denial is enforcement, not breakage.
// ---------------------------------------------------------------------------

#[test]
fn enforce_closes_runtime_capability_escapes() {
    if frame_attribution_unavailable() {
        eprintln!("skipping: the self-grant/detached-require reads need frame attribution");
        return;
    }
    let dir = fixtures_dir().join("enforce-escapes");
    let policy = dir.join("ibex-policy.json");
    let secret = dir.join("secret.txt");
    let enforced = run_ibex(
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
    // ENG-22695: the self-grant surface is removed and the grant is refused —
    // the later read stays denied.
    assert!(
        enforced
            .stdout
            .contains("selfgrant: setModuleCapabilities=absent read=DENIED"),
        "self-grant must be sealed and refused under enforce:\nstdout:\n{}\nstderr:\n{}",
        enforced.stdout,
        enforced.stderr
    );
    // ENG-22697: exact:/bun: builtin aliases are denied by builtins:[].
    assert!(
        enforced
            .stdout
            .contains("aliases: exact:sqlite=DENIED bun:sqlite=DENIED bun:fs=DENIED"),
        "builtin aliases must be denied under builtins:[]:\nstdout:\n{}\nstderr:\n{}",
        enforced.stdout,
        enforced.stderr
    );
    // ENG-22696: the detached require callback fails closed.
    assert!(
        enforced.stdout.contains("detached: DENIED"),
        "a detached globalThis.require must fail closed:\nstdout:\n{}\nstderr:\n{}",
        enforced.stdout,
        enforced.stderr
    );
    // ENG-22883: the SCM_RIGHTS IPC helpers refuse a forged/inherited socket fd
    // by fd ownership before any sendmsg/recvmsg — the ungranted package cannot
    // drive them at all (GATED, not a live syscall).
    assert!(
        enforced.stdout.contains("ipcfds: send=GATED recv=GATED"),
        "IPC sendmsg/recvmsg must be gated by fd ownership under enforce:\nstdout:\n{}\nstderr:\n{}",
        enforced.stdout,
        enforced.stderr
    );
    // ENG-22906: process:spawn authority does not imply raw stdio fd authority.
    assert!(
        enforced.stdout.contains("spawnstdio: GATED"),
        "child_process stdio fd:N redirects must be gated by fd ownership under enforce:\nstdout:\n{}\nstderr:\n{}",
        enforced.stdout,
        enforced.stderr
    );
    assert!(
        !enforced.stdout.contains("STOLEN") && !enforced.stdout.contains("IMPORTED"),
        "no escape channel may succeed under enforce:\nstdout:\n{}\nstderr:\n{}",
        enforced.stdout,
        enforced.stderr
    );

    // Permissive control: every channel is live (the deny above is enforcement).
    let permissive = run_ibex(
        &[
            "--capsec",
            "permissive",
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
        permissive.stdout.contains("read=STOLEN")
            && permissive.stdout.contains("exact:sqlite=IMPORTED")
            && permissive.stdout.contains("detached: IMPORTED"),
        "permissive control must show the escape channels are live:\nstdout:\n{}\nstderr:\n{}",
        permissive.stdout,
        permissive.stderr
    );
    // ENG-22883 control: under permissive the ownership gate is skipped, so the
    // helpers reach the real syscall (which fails ENOTSOCK on stdio) — proving
    // the enforce GATED result above is the ownership check, not a broken call.
    assert!(
        permissive
            .stdout
            .contains("ipcfds: send=SYSCALL recv=SYSCALL"),
        "permissive IPC helpers must reach the syscall (gate skipped):\nstdout:\n{}\nstderr:\n{}",
        permissive.stdout,
        permissive.stderr
    );
    assert!(
        permissive.stdout.contains("spawnstdio: SYSCALL"),
        "permissive stdio fd:N redirect must reach fork/exec (gate skipped):\nstdout:\n{}\nstderr:\n{}",
        permissive.stdout,
        permissive.stderr
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
        out.stdout.contains("evil-exact-require: IMPORT-DENIED"),
        "__exactRequire must be gated by the package principal:\nstdout:\n{}\nstderr:\n{}",
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
fn dynamic_relative_import_uses_the_calling_module_referrer() {
    let dir = unique_dir("dynamic-relative-import");
    let dynamic_pkg = dir.join("node_modules").join("dynamic-pkg");
    let sibling_pkg = dir.join("node_modules").join("sibling-pkg");
    write_text(
        &dynamic_pkg.join("package.json"),
        r#"{"name":"dynamic-pkg","version":"1.0.0","main":"index.js"}"#,
    );
    write_text(
        &dynamic_pkg.join("index.js"),
        r#"
exports.run = async function() {
  var local = await import("./local.js").then(
    function(m) { return m.value || (m.default && m.default.value); },
    function(e) { return "LOCAL_ERR:" + (e && e.message || e); }
  );
  var sibling = await import("../sibling-pkg/index.js").then(
    function(m) { return "SIBLING:" + (m.value || (m.default && m.default.value)); },
    function() { return "SIBLING:DENIED"; }
  );
  return "local=" + local + " " + sibling;
};
"#,
    );
    write_text(&dynamic_pkg.join("local.js"), r#"exports.value = "LOCAL";"#);
    write_text(
        &sibling_pkg.join("package.json"),
        r#"{"name":"sibling-pkg","version":"1.0.0","main":"index.js"}"#,
    );
    write_text(
        &sibling_pkg.join("index.js"),
        r#"exports.value = "SIBLING";"#,
    );
    write_text(
        &dir.join("app.js"),
        r#"
(async function() {
  console.log(await require("dynamic-pkg").run());
})().catch(function(e) {
  console.log("ERR:" + (e && e.message || e));
});
"#,
    );
    let policy = serde_json::json!({
        "mode": "enforce",
        "packages": {
            "dynamic-pkg": {
                "builtins": [],
                "packages": []
            },
            "sibling-pkg": {
                "builtins": []
            }
        }
    });
    write_text(&dir.join("ibex-policy.json"), &policy.to_string());

    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );
    assert!(
        out.stdout.contains("local=LOCAL SIBLING:DENIED"),
        "dynamic import must resolve ./local.js from the caller while still gating sibling traversal:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn bun_which_requires_process_spawn_capability() {
    let dir = unique_dir("bun-which");
    let pkg = dir.join("node_modules").join("which-probe");
    write_text(
        &pkg.join("package.json"),
        r#"{"name":"which-probe","version":"1.0.0","main":"index.js"}"#,
    );
    write_text(
        &pkg.join("index.js"),
        r#"
exports.run = function() {
  try {
    var found = Bun.which("sh");
    return found ? "which: ALLOWED" : "which: NULL";
  } catch (e) {
    return String(e && e.message || e).indexOf("process:spawn") !== -1
      ? "which: DENIED"
      : "which: ERR";
  }
};
"#,
    );
    write_text(
        &dir.join("app.js"),
        "console.log(require('which-probe').run());\n",
    );
    let policy = serde_json::json!({
        "mode": "enforce",
        "packages": {
            "which-probe": {
                "builtins": [],
                "endow": ["Bun"]
            }
        }
    });
    write_text(&dir.join("ibex-policy.json"), &policy.to_string());

    let out = run_ibex(
        &[
            "--compat",
            "bun",
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );
    assert!(
        out.stdout.contains("which: DENIED"),
        "Bun.which must not probe PATH/executables without process:spawn:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

#[cfg(unix)]
#[test]
fn server_and_socket_host_functions_require_network_capabilities() {
    let dir = unique_dir("network-gates");
    let pkg = dir.join("node_modules").join("network-probe");
    write_text(
        &pkg.join("package.json"),
        r#"{"name":"network-probe","version":"1.0.0","main":"index.js"}"#,
    );
    write_text(
        &pkg.join("index.js"),
        r#"
function once(emitter, event, cb) {
  var done = false;
  emitter.once(event, function(value) {
    if (done) return;
    done = true;
    cb(value);
  });
}
exports.run = async function() {
  var out = [];
  var net = require("net");
  await new Promise(function(resolve) {
    var socket = net.connect({ host: "127.0.0.1", port: 9 });
    once(socket, "error", function(err) {
      out.push("tcp-connect:" + (err && err.code === "EACCES" ? "DENIED" : "ERR(" + String(err && err.code || err) + ")"));
      resolve();
    });
    socket.once("connect", function() {
      out.push("tcp-connect:ALLOWED");
      socket.destroy();
      resolve();
    });
  });
  await new Promise(function(resolve) {
    var server = net.createServer();
    once(server, "error", function(err) {
      out.push("tcp-listen:" + (err && err.code === "EACCES" ? "DENIED" : "ERR(" + String(err && err.code || err) + ")"));
      resolve();
    });
    server.listen(0, "127.0.0.1", function() {
      out.push("tcp-listen:ALLOWED");
      server.close(resolve);
    });
  });
  var dgram = require("dgram");
  await new Promise(function(resolve) {
    var udp = dgram.createSocket("udp4");
    once(udp, "error", function(err) {
      // Suffix the code (assertion matches the "udp-bind:DENIED" prefix): a
      // transient bind error under load must not masquerade as a clean deny.
      out.push("udp-bind:DENIED(" + String(err && err.code || err) + ")");
      try { udp.close(); } catch (_) {}
      resolve();
    });
    udp.bind(0, "127.0.0.1", function() {
      out.push("udp-bind:ALLOWED");
      udp.close(resolve);
    });
  });
  return out.join(" ");
};
"#,
    );
    write_text(
        &dir.join("app.js"),
        r#"
(async function() {
  console.log(await require("network-probe").run());
})().catch(function(e) {
  console.log("ERR:" + (e && e.message || e));
});
"#,
    );
    let policy = serde_json::json!({
        "mode": "enforce",
        "packages": {
            "network-probe": {
                "capabilities": []
            }
        }
    });
    write_text(&dir.join("ibex-policy.json"), &policy.to_string());

    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );
    assert!(
        out.stdout
            .contains("tcp-connect:DENIED tcp-listen:DENIED udp-bind:DENIED"),
        "net/dgram host operations must require network capabilities:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

// @ref LLP 0013#policy — (ENG-22819) — a UDP socket handle created by a package is
// authority-bearing:
// receiving datagrams, reading the (implicitly-bound) local address, and exporting
// the raw fd are all listening-side authority. A package holding only
// `network:connect` to one endpoint must not gain any of them by connecting and
// sending — that would hand it an ephemeral listening socket with no
// `network:listen` grant. The probe runs at module-evaluation time so its host
// calls are attributed to the `udp-probe` principal even without the
// frame-attribution patch.
#[cfg(unix)]
#[test]
fn udp_connect_only_socket_cannot_receive_or_expose_fd_without_listen() {
    fn probe_source() -> &'static str {
        r#"
var out = [];
var dgram = require("dgram");
var s = dgram.createSocket("udp4");
try { s.connect(9, "127.0.0.1"); out.push("connect-returned"); }
catch (e) { out.push("connect-threw"); }
try { s.send("x"); out.push("send-returned"); }
catch (e) { out.push("send-threw"); }
try {
  var a = s.address();
  out.push("address:" + (a && typeof a === "object" ? (a.address + ":" + a.port) : String(a)));
} catch (e) { out.push("address:DENIED"); }
try {
  var fd = s._getFd();
  out.push("fd:" + (typeof fd === "number" && fd >= 0 ? "EXPOSED" : "HIDDEN"));
} catch (e) { out.push("fd:DENIED"); }
try { s.close(); } catch (_) {}
exports.result = out.join(" ");
"#
    }

    let run_probe = |label: &str, capabilities: serde_json::Value| {
        let dir = unique_dir(label);
        let pkg = dir.join("node_modules").join("udp-probe");
        write_text(
            &pkg.join("package.json"),
            r#"{"name":"udp-probe","version":"1.0.0","main":"index.js"}"#,
        );
        write_text(&pkg.join("index.js"), probe_source());
        write_text(
            &dir.join("app.js"),
            r#"console.log(require("udp-probe").result);"#,
        );
        let policy = serde_json::json!({
            "mode": "enforce",
            "packages": {
                "udp-probe": {
                    "capabilities": capabilities,
                    "builtins": ["node:dgram", "node:events", "node:buffer"]
                }
            }
        });
        write_text(&dir.join("ibex-policy.json"), &policy.to_string());
        run_ibex(
            &[
                "--capsec",
                "enforce",
                "--policy",
                &dir.join("ibex-policy.json").to_string_lossy(),
                "run",
                "app.js",
            ],
            &[("EXACT_COMPAT_TEST", "1")],
            Some(&dir),
        )
    };

    // Connect-only: send is allowed (per-datagram network:connect), but the
    // ephemeral bound address, the raw fd, and receiving must all be denied.
    let connect_only = run_probe(
        "udp-connect-only",
        serde_json::json!(["network:connect:127.0.0.1:9"]),
    );
    assert!(
        connect_only.stdout.contains("send-returned"),
        "connect-only send must still work:\nstdout:\n{}\nstderr:\n{}",
        connect_only.stdout,
        connect_only.stderr
    );
    assert!(
        !connect_only.stdout.contains("fd:EXPOSED"),
        "connect-only UDP socket must not expose its fd without network:listen:\nstdout:\n{}\nstderr:\n{}",
        connect_only.stdout,
        connect_only.stderr
    );
    assert!(
        !connect_only.stdout.contains("address:127.0.0.1")
            && !connect_only.stdout.contains("address:0.0.0.0"),
        "connect-only UDP socket must not reveal its bound address without network:listen:\nstdout:\n{}\nstderr:\n{}",
        connect_only.stdout,
        connect_only.stderr
    );

    // Control: granting network:listen too makes the same operations succeed,
    // proving the gate above is load-bearing (not a general breakage).
    let with_listen = run_probe(
        "udp-with-listen",
        serde_json::json!(["network:connect:127.0.0.1:9", "network:listen"]),
    );
    assert!(
        with_listen.stdout.contains("fd:EXPOSED"),
        "with network:listen the fd should be reachable (control):\nstdout:\n{}\nstderr:\n{}",
        with_listen.stdout,
        with_listen.stderr
    );
}

#[cfg(unix)]
#[test]
fn fetch_endpoint_capabilities_are_host_scoped() {
    let dir = unique_dir("fetch-endpoints");
    let pkg = dir.join("node_modules").join("fetch-probe");
    write_text(
        &pkg.join("package.json"),
        r#"{"name":"fetch-probe","version":"1.0.0","main":"index.js"}"#,
    );
    write_text(
        &pkg.join("index.js"),
        r#"
exports.run = async function(port) {
  var out = [];
  try {
    var allowed = await fetch("http://127.0.0.1:" + port + "/ok");
    out.push("fetch-127:" + await allowed.text());
  } catch (e) {
    // Carry the error detail: a transient under-load failure (ECONNRESET,
    // ENOBUFS, ...) must be distinguishable from a capsec denial in the
    // assertion output when this branch is unexpectedly taken.
    out.push("fetch-127:DENIED(" + String(e && e.message || e) + ")");
  }
  try {
    await fetch("http://localhost:" + port + "/deny");
    out.push("fetch-localhost:ALLOWED");
  } catch (e) {
    out.push("fetch-localhost:DENIED");
  }
  try {
    var local = await fetch("data:text/plain,local");
    out.push("fetch-data:" + await local.text());
  } catch (e) {
    out.push("fetch-data:DENIED");
  }
  return out.join(" ");
};
"#,
    );
    write_text(
        &dir.join("app.js"),
        r#"
var http = require("node:http");
var probe = require("fetch-probe");
var server = http.createServer(function(_req, res) {
  res.statusCode = 200;
  res.end("ok");
});
server.listen(0, "127.0.0.1", async function() {
  try {
    console.log(await probe.run(server.address().port));
  } finally {
    server.close();
  }
});
"#,
    );
    let policy = serde_json::json!({
        "mode": "enforce",
        "packages": {
            "fetch-probe": {
                "capabilities": ["network:fetch:127.0.0.1"],
                "builtins": [],
                "endow": ["fetch"]
            }
        }
    });
    write_text(&dir.join("ibex-policy.json"), &policy.to_string());

    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );
    assert!(
        out.stdout
            .contains("fetch-127:ok fetch-localhost:DENIED fetch-data:local"),
        "fetch must honor endpoint-scoped grants and keep data URLs local:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dns_requires_network_resolve_capability() {
    let dir = unique_dir("dns-resolve-gate");
    write_text(
        &dir.join("node_modules/dns-probe/package.json"),
        r#"{ "name": "dns-probe", "version": "1.0.0", "main": "index.js" }"#,
    );
    write_text(
        &dir.join("node_modules/dns-probe/index.js"),
        r#"
var dns = require("node:dns");
exports.run = function run(label) {
  try {
    __exactDnsLookup("localhost", 4);
    console.log(label + ":native:OK");
  } catch (e) {
    console.log(label + ":native:DENIED:" + String(e && e.message || e));
  }
  dns.lookup("localhost", { family: 4 }, function(err, address) {
    // Suffix the code so a transient resolver failure under parallel load is
    // distinguishable from a capsec denial (assertions match the "DENIED"
    // prefix either way).
    console.log(label + ":api:" + (err ? "DENIED:" + String(err.code || err) : ("OK:" + !!address)));
  });
};
"#,
    );
    write_text(
        &dir.join("app.js"),
        r#"
var probe = require("dns-probe");
probe.run("dns");
"#,
    );

    let denied_policy = serde_json::json!({
        "mode": "enforce",
        "packages": {
            "dns-probe": {
                "capabilities": [],
                "builtins": ["node:dns", "buffer"]
            }
        }
    });
    write_text(&dir.join("denied-policy.json"), &denied_policy.to_string());
    let denied = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("denied-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );
    assert!(
        denied.stdout.contains("dns:native:DENIED")
            && denied.stdout.contains("network:resolve:localhost")
            && denied.stdout.contains("dns:api:DENIED"),
        "node:dns lookup must be denied without network:resolve:\nstdout:\n{}\nstderr:\n{}",
        denied.stdout,
        denied.stderr
    );

    let granted_policy = serde_json::json!({
        "mode": "enforce",
        "packages": {
            "dns-probe": {
                "capabilities": ["network:resolve:localhost"],
                "builtins": ["node:dns", "buffer"]
            }
        }
    });
    write_text(
        &dir.join("granted-policy.json"),
        &granted_policy.to_string(),
    );
    let granted = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("granted-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );
    assert!(
        granted.stdout.contains("dns:native:OK") && granted.stdout.contains("dns:api:OK:true"),
        "network:resolve:localhost should allow localhost lookup:\nstdout:\n{}\nstderr:\n{}",
        granted.stdout,
        granted.stderr
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn native_tcp_handles_cannot_be_stolen_by_guessing_ids() {
    let dir = unique_dir("tcp-handle-owner");
    let pkg = dir.join("node_modules").join("handle-thief");
    write_text(
        &pkg.join("package.json"),
        r#"{"name":"handle-thief","version":"1.0.0","main":"index.js"}"#,
    );
    write_text(
        &pkg.join("index.js"),
        r#"
exports.run = function() {
  var net = require("node:net");
  for (var handle = 1; handle <= 8; handle++) {
    try {
      new net.Socket({ _handle: handle }).destroy();
    } catch (_) {}
  }
  return "steal-attempted";
};
"#,
    );
    write_text(
        &dir.join("app.js"),
        r#"
var net = require("node:net");
var thief = require("handle-thief");
var server = net.createServer(function(socket) {
  socket.end("ok");
});
server.listen(0, "127.0.0.1", function() {
  var port = server.address().port;
  console.log(thief.run());
  var client = net.connect({ host: "127.0.0.1", port: port });
  var body = "";
  client.setEncoding("utf8");
  client.on("data", function(chunk) { body += chunk; });
  client.on("end", function() {
    console.log("server:" + body);
    server.close();
  });
  client.on("error", function(err) {
    console.log("server-error:" + (err && err.code || err));
    server.close();
  });
});
"#,
    );
    let policy = serde_json::json!({
        "mode": "enforce",
        "packages": {
            "handle-thief": {
                "capabilities": [],
                "builtins": ["node:net"]
            }
        }
    });
    write_text(&dir.join("ibex-policy.json"), &policy.to_string());

    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--policy",
            &dir.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );
    assert!(
        out.stdout.contains("steal-attempted") && out.stdout.contains("server:ok"),
        "a package must not be able to close another principal's native TCP handle:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn raw_ipc_helpers_reject_unowned_file_descriptors() {
    let dir = unique_dir("ipc-fd-owner");
    let pkg = dir.join("node_modules").join("ipc-probe");
    write_text(
        &pkg.join("package.json"),
        r#"{"name":"ipc-probe","version":"1.0.0","main":"index.js"}"#,
    );
    write_text(
        &pkg.join("index.js"),
        r#"
function classify(fn) {
  try {
    fn();
    return "ALLOWED";
  } catch (e) {
    var msg = String(e && e.message || e);
    if (msg.indexOf("Permission denied") !== -1 ||
        msg.indexOf("bad file descriptor") !== -1) {
      return "DENIED";
    }
    return "SYSCALL";
  }
}
exports.run = function() {
  var data = "x";
  return [
    "sendfd=" + (typeof globalThis.__exactIpcSendMsg === "function"
      ? classify(function() { globalThis.__exactIpcSendMsg(1, data, 1); })
      : "UNAVAILABLE"),
    "recv=" + (typeof globalThis.__exactIpcRecvMsg === "function"
      ? classify(function() { globalThis.__exactIpcRecvMsg(1, 1); })
      : "UNAVAILABLE")
  ].join(" ");
};
"#,
    );
    write_text(
        &dir.join("app.js"),
        r#"console.log(require("ipc-probe").run());"#,
    );
    let policy = serde_json::json!({
        "mode": "enforce",
        "packages": {
            "ipc-probe": {
                "capabilities": [],
                "builtins": []
            }
        }
    });
    write_text(&dir.join("ibex-policy.json"), &policy.to_string());

    let out = run_ibex(
        &[
            "--capsec",
            "enforce",
            "--capsec-allow-advisory",
            "--policy",
            &dir.join("ibex-policy.json").to_string_lossy(),
            "run",
            "app.js",
        ],
        &[("EXACT_COMPAT_TEST", "1")],
        Some(&dir),
    );

    assert!(
        (out.stdout.contains("sendfd=DENIED") || out.stdout.contains("sendfd=UNAVAILABLE"))
            && (out.stdout.contains("recv=DENIED") || out.stdout.contains("recv=UNAVAILABLE")),
        "raw IPC helpers must deny unowned fd integers before syscalls:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
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
            && out.stdout.contains("evil-exact-require: IMPORTED:function")
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
    if frame_attribution_unavailable() {
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
    if frame_attribution_unavailable() {
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
    if frame_attribution_unavailable() {
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
    if frame_attribution_unavailable() {
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

// ENG-22631: the async-detached variant of the confused-deputy attack. evil
// launders a deputy-class read by passing the deputy method straight to `.then`
// (`Promise.resolve(SECRET).then(deputy.readFor)`), so the reaction drains with
// only the deputy's own frame live — the scheduling frame has returned. Patch
// 0007 (empty-stack native-callback fail-closed) does NOT cover this: the deputy
// frame is a real user frame, so the collected stack is [deputy] (len 1), the
// deputy-class AND is skipped, and the read would be allowed. Patch 0008 captures
// the SCHEDULING principal at enqueueJob and re-attributes it into the job, so the
// read now collects [deputy, evil] and the AND denies. The same test pins the
// non-regression the reverted Rust-only fix broke: a GRANTED package's own async
// continuation (scheduler == running principal) collapses to a single-principal
// stack and stays allowed. Needs frame attribution + schedule-time capture.
#[test]
fn async_detached_deputy_read_is_contained_but_granted_self_async_works() {
    if frame_attribution_unavailable() {
        eprintln!("skipping: async deputy attribution needs frame attribution");
        return;
    }
    let dir = fixtures_dir().join("async-deputy");
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
    // (A) The app (root) schedules the deputy across a microtask — allowed: the
    // scheduler captured at enqueue is the trusted root principal.
    assert!(
        out.stdout
            .contains("app-async-via-deputy: READ:ASYNC-DEPUTY-SECRET-llp0013"),
        "root's own async deputy read should be allowed:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // (B) A granted package's OWN async continuation — allowed. This is the shape
    // a blunt len==1 deny would false-deny; schedule-time capture collapses the
    // scheduler (== running principal) instead of denying.
    assert!(
        out.stdout
            .contains("logger-async-self: READ:ASYNC-DEPUTY-SECRET-llp0013"),
        "a granted package's own async read must NOT be false-denied:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // (C) A granted package driving the deputy across a microtask — allowed, since
    // both the scheduler (logger) and the deputy are granted.
    assert!(
        out.stdout
            .contains("logger-async-via-deputy: READ:ASYNC-DEPUTY-SECRET-llp0013"),
        "a granted package's async deputy read should be allowed:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // (D) The attack: ungranted evil detaches the deputy across a microtask. The
    // recovered scheduler (evil) makes the deputy-class AND deny, and the secret
    // never leaks.
    assert!(
        out.stdout.contains("evil-async-via-deputy: CONTAINED")
            && !out.stdout.contains("evil-async-via-deputy: STOLEN"),
        "schedule-time capture must contain the async-detached deputy read:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

/// Control: with the SAME graph and deputyClasses configured but the mode forced
/// to permissive, nothing is enforced, so the async-detached deputy read leaks the
/// secret. Proves the containment above is the capability system working, not a
/// broken fs path, a rejected promise, or a dead code path.
#[test]
fn async_detached_deputy_control_permissive_leaks() {
    if frame_attribution_unavailable() {
        eprintln!("skipping: async deputy attribution needs frame attribution");
        return;
    }
    let dir = fixtures_dir().join("async-deputy");
    let policy = dir.join("ibex-policy.json");
    let secret = dir.join("secret.txt");
    let out = run_ibex(
        &[
            "--capsec",
            "permissive",
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
        out.stdout
            .contains("evil-async-via-deputy: STOLEN:ASYNC-DEPUTY-SECRET-llp0013"),
        "permissive mode should let the detached deputy read leak (control):\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

// ENG-22759: the async-detached confused-deputy attack laundered through the HOST
// callback queues instead of the Promise microtask queue. The Promise queue is
// covered in the VM (schedule-time principal captured at enqueueJob, appended by
// collectStackPackageIds). But setTimeout / setInterval / setImmediate /
// process.nextTick / the non-JSI queueMicrotask fallback are queues owned by the
// embedder, drained by its event loop, so a deputy method detached across one of
// them (`setTimeout(deputy.readFor, 0, SECRET)`) fired with only the deputy's frame
// live: collectStackPackageIds returned [deputy] (len 1), the deputy-class AND was
// skipped, and the read leaked for the ungranted scheduler. setTimeout needs no
// endowment. ENG-22761 already captures the scheduling principal into
// g_native_callback_principal_id (ScopedNativePrincipal around each detached
// drain); this change folds that principal into the deputy-class stack in
// checkCapabilityWithFsMode, so the read now collects [deputy, evil] and the AND
// denies on every channel — while a granted package's own timer continuation
// (scheduler == running principal) collapses and is not false-denied. Needs frame
// attribution.
#[test]
fn host_scheduled_detached_deputy_read_is_contained_across_timer_channels() {
    if frame_attribution_unavailable() {
        eprintln!("skipping: host-queue deputy attribution needs frame attribution");
        return;
    }
    let dir = fixtures_dir().join("timer-deputy");
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
    // (A) The app (root) drives the deputy across a timer — allowed: the scheduler
    // captured at enqueue is the trusted root principal.
    assert!(
        out.stdout
            .contains("app-timer-via-deputy: READ:TIMER-DEPUTY-SECRET-llp0013"),
        "root's own timer-scheduled deputy read should be allowed:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // (B) A granted package's OWN timer continuation — allowed. This is the shape a
    // blunt len==1 deny would false-deny; the scheduler (== running principal)
    // collapses against the innermost frame instead of denying.
    assert!(
        out.stdout
            .contains("logger-timer-self: READ:TIMER-DEPUTY-SECRET-llp0013"),
        "a granted package's own timer read must NOT be false-denied:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // (C) A granted package driving the deputy across a timer — allowed, since both
    // the scheduler (logger) and the deputy are granted.
    assert!(
        out.stdout
            .contains("logger-timer-via-deputy: READ:TIMER-DEPUTY-SECRET-llp0013"),
        "a granted package's timer-scheduled deputy read should be allowed:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // (D) The attack across all three host channels: ungranted evil detaches the
    // deputy. The recovered scheduler (evil) makes the deputy-class AND deny, and
    // the secret never leaks — on setTimeout, process.nextTick, AND setImmediate.
    for label in [
        "evil-timer-via-deputy",
        "evil-nexttick-via-deputy",
        "evil-setimmediate-via-deputy",
    ] {
        assert!(
            out.stdout.contains(&format!("{label}: CONTAINED"))
                && !out.stdout.contains(&format!("{label}: STOLEN")),
            "schedule-time capture must contain the {label} channel:\nstdout:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    }
}

/// Control: the SAME graph and deputyClasses configured but the mode forced to
/// permissive — nothing is enforced, so every host-channel detached deputy read
/// leaks the secret. Proves the containment above is the capability system working
/// on the timer/nextTick/setImmediate paths, not a broken fs path, a dead code
/// path, or a read that never actually happens.
#[test]
fn host_scheduled_detached_deputy_control_permissive_leaks() {
    if frame_attribution_unavailable() {
        eprintln!("skipping: host-queue deputy attribution needs frame attribution");
        return;
    }
    let dir = fixtures_dir().join("timer-deputy");
    let policy = dir.join("ibex-policy.json");
    let secret = dir.join("secret.txt");
    let out = run_ibex(
        &[
            "--capsec",
            "permissive",
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
    for label in [
        "evil-timer-via-deputy",
        "evil-nexttick-via-deputy",
        "evil-setimmediate-via-deputy",
    ] {
        assert!(
            out.stdout
                .contains(&format!("{label}: STOLEN:TIMER-DEPUTY-SECRET-llp0013")),
            "permissive mode should let the {label} detached deputy read leak (control):\nstdout:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    }
}

// ENG-23112 (finding H): the timer fire loop scoped its `ScopedNativePrincipal`
// over `runNextTickQueue` AND `drainMicrotasks`, pinning
// g_native_callback_principal_id to the timer owner while pending Promise
// microtasks drained. The ungranted `evil-pkg` cannot read the secret itself — its
// DETACHED read (the runtime fs deputy passed straight to `.then`, no user frame)
// reaches kNoUserPrincipal and fails closed at the top-level poll. But when that
// same detached read is scheduled INSIDE root's timer callback, the leaked scope
// pinned root over the microtask drain, so the kNoUserPrincipal fallback resolved
// to root's authority and the read leaked — an escalation reachable in the default
// enforce mode with NO deputyClasses configured (distinct from the Phase 5
// host-queue deputy-class laundering closed by ENG-22759). The fix restricts the
// override to just the callback invocation so the microtask drain matches the
// top-level poll. Needs frame attribution (the runtime-deputy skip that yields
// kNoUserPrincipal lives in the patched engine); on an unpatched engine the whole
// escalation is moot because there is no frame attribution to launder.
#[test]
fn timer_microtask_drain_does_not_launder_detached_deputy_into_owner() {
    if !cfg!(exact_frame_attribution) {
        eprintln!("skipping: detached-deputy attribution needs frame attribution");
        return;
    }
    let dir = fixtures_dir().join("timer-microtask-launder");
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
    // (A) Control: root's direct read is allowed — the file, grant, and path are
    // wired, so a CONTAINED below is a real capability denial, not a broken read.
    assert!(
        out.stdout
            .contains("direct: READ:TIMER-MICROTASK-SECRET-llp0013"),
        "root's direct read should be allowed (control):\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // (B) Baseline: the ungranted dependency's detached read fails closed at the
    // top-level poll — it cannot read on its own, so a leak in (C) is laundering
    // through the timer scope, not evil's own grant.
    assert!(
        out.stdout.contains("evil-top-detached: CONTAINED")
            && !out.stdout.contains("evil-top-detached: STOLEN"),
        "the ungranted dependency's detached read must fail closed at the top-level poll:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // (C) The fix: the SAME ungranted detached read scheduled inside a root timer
    // callback must ALSO fail closed — the leaked native-principal scope no longer
    // pins root over the microtask drain. Pre-fix this laundered the read (STOLEN)
    // into root's authority.
    assert!(
        out.stdout.contains("evil-timer-detached: CONTAINED")
            && !out.stdout.contains("evil-timer-detached: STOLEN"),
        "the timer microtask drain must not launder an ungranted detached deputy into the owner's authority:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // (D) No false-deny: root's OWN detached read scheduled across a timer stays
    // allowed — the fix closes only the no-user laundering path, not legitimate
    // timer-scheduled work by the granted owner.
    assert!(
        out.stdout
            .contains("root-timer-detached: READ:TIMER-MICROTASK-SECRET-llp0013"),
        "root's own timer-scheduled read must NOT be false-denied:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// ENG-22884 — capsec readiness: enforce must not silently proceed as
// full-strength capsec when an attribution prerequisite is missing. An explicit
// IBEX_PER_PACKAGE_CHUNKS=0 collapses bundled dependencies into the trusted
// root principal on EVERY engine, so this exercises the fail-closed gate
// deterministically (no dependence on the checkout's Hermes patch level). The
// advisory hatch that run_ibex defaults on is overridden off here.
// ---------------------------------------------------------------------------

#[test]
fn capsec_enforce_fails_closed_on_missing_attribution_prerequisites() {
    // Enforce + operator-disabled package isolation, no hatch: refuse to run.
    let denied = run_ibex(
        &[
            "--capsec",
            "enforce",
            "run",
            &fixture("compartment-endowment.js"),
        ],
        &[
            ("IBEX_PER_PACKAGE_CHUNKS", "0"),
            ("IBEX_CAPSEC_ALLOW_ADVISORY", "0"),
        ],
        None,
    );
    assert_ne!(
        denied.status, 0,
        "enforce with IBEX_PER_PACKAGE_CHUNKS=0 must fail closed:\nstdout:\n{}\nstderr:\n{}",
        denied.stdout, denied.stderr
    );
    assert!(
        denied.stderr.contains("per-package principal isolation")
            && denied.stderr.contains("--capsec-allow-advisory"),
        "the refusal must name the missing prerequisite and the escape hatch:\nstderr:\n{}",
        denied.stderr
    );

    // Same run with the hatch: proceeds, but reports advisory attribution and
    // the readiness line loudly.
    let advisory = run_ibex(
        &[
            "--capsec",
            "enforce",
            "run",
            &fixture("compartment-endowment.js"),
        ],
        &[
            ("IBEX_PER_PACKAGE_CHUNKS", "0"),
            ("IBEX_CAPSEC_ALLOW_ADVISORY", "1"),
        ],
        None,
    );
    assert_eq!(
        advisory.status, 0,
        "the advisory hatch must let the run proceed:\nstdout:\n{}\nstderr:\n{}",
        advisory.stdout, advisory.stderr
    );
    assert!(
        advisory.stderr.contains("ADVISORY")
            && advisory.stderr.contains("capsec readiness:")
            && advisory
                .stderr
                .contains("package-isolation=disabled(IBEX_PER_PACKAGE_CHUNKS=0)"),
        "advisory enforce must report readiness conspicuously:\nstderr:\n{}",
        advisory.stderr
    );

    // Audit is advisory by design: proceeds without the hatch, but warns.
    let audit = run_ibex(
        &[
            "--capsec",
            "audit",
            "run",
            &fixture("compartment-endowment.js"),
        ],
        &[
            ("IBEX_PER_PACKAGE_CHUNKS", "0"),
            ("IBEX_CAPSEC_ALLOW_ADVISORY", "0"),
        ],
        None,
    );
    assert_eq!(
        audit.status, 0,
        "audit must proceed with advisory attribution:\nstdout:\n{}\nstderr:\n{}",
        audit.stdout, audit.stderr
    );
    assert!(
        audit.stderr.contains("ADVISORY") && audit.stderr.contains("capsec readiness:"),
        "audit must still report the readiness fields:\nstderr:\n{}",
        audit.stderr
    );
}
