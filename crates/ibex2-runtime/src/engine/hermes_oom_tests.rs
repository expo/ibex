use super::*;

#[cfg(feature = "test-support")]
#[test]
fn env_snapshot_failure_frees_adapter_strings() {
    use crate::{bindings, boundary_abi::env_snapshot_test as probe, grant::GrantSet};

    // PATH is already present, so the test does not mutate process environment.
    assert!(std::env::var("PATH").is_ok());
    let context = bindings::Context::new(GrantSet::parse("env.read PATH\n").unwrap());
    let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
    let before = probe::counts();
    probe::fail(true);
    let result = runtime.install_runtime(bindings::Groups::ENV, &context);
    probe::fail(false);
    assert!(result.is_err(), "injected allocation failure must escape");
    assert_eq!(probe::counts(), (before.0 + 2, before.1));
}

#[cfg(all(feature = "test-support", feature = "loader"))]
#[test]
fn env_snapshot_failure_frees_module_strings() {
    use crate::{bindings, boundary_abi::env_snapshot_test as probe, grant::GrantSet, loader};

    assert!(std::env::var("PATH").is_ok());
    let directory = std::env::temp_dir().join(format!("ibex2-env-oom-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("index.js"),
        "module.exports = process.env.PATH;",
    )
    .unwrap();
    let context = bindings::Context::new(GrantSet::none());
    let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
    runtime
        .install_runtime(bindings::Groups::ENV, &context)
        .unwrap();
    runtime
        .set_loader(
            loader::Root::Declared(directory.clone()),
            loader::ModuleGrants::parse("[./index.js]\nenv.read PATH\n").unwrap(),
        )
        .unwrap();
    let before = probe::counts();
    probe::fail(true);
    let result = runtime.run_entry("./index.js");
    probe::fail(false);
    std::fs::remove_dir_all(directory).unwrap();
    assert!(result.is_err(), "injected allocation failure must escape");
    assert_eq!(probe::counts(), (before.0 + 2, before.1));
}

const EXHAUST: &str = "var held = []; for (var i = 0; i < 1000000; ++i) \
                      held.push({id: i, title: 'task', done: false});";

#[test]
#[ignore = "requires exception-on-OOM Hermes (v6 or a local build)"]
fn heap_oom_refuses_every_later_entrance() {
    for path in 0..3 {
        let mut runtime = Hermes::with_heap_limit(DynamicCode::Closed, 8 << 20).unwrap();
        let result = match path {
            0 => runtime.eval(EXHAUST).map(|_| ()),
            1 => {
                runtime
                    .eval(&format!(
                        "HermesInternal.enqueueJob(function () {{ {EXHAUST} }})"
                    ))
                    .unwrap();
                runtime.pump().map(|_| ())
            }
            _ => {
                runtime
                    .eval(&format!(
                        "HermesInternal.enqueueJob(function () {{ {EXHAUST} }})"
                    ))
                    .unwrap();
                runtime.drain_microtasks()
            }
        };
        assert_eq!(result, Err(JsError::OutOfMemory), "path {path}");
        // Clearing a deadline cannot make an exhausted runtime reusable.
        runtime.clear_deadline();
        assert_eq!(runtime.eval("1 + 1"), Err(JsError::OutOfMemory));
        assert_eq!(runtime.eval_bytes(b"1 + 1"), Err(JsError::OutOfMemory));
        assert_eq!(runtime.pump(), Err(JsError::OutOfMemory));
        assert_eq!(runtime.drain_microtasks(), Err(JsError::OutOfMemory));
        assert_eq!(runtime.run_entry("./missing.js"), Err(JsError::OutOfMemory));
        assert_eq!(runtime.capture_intrinsics(), Err(JsError::OutOfMemory));
        assert_eq!(runtime.harden(), Err(JsError::OutOfMemory));
        drop(runtime);
        let mut replacement = Hermes::new(DynamicCode::Closed).unwrap();
        assert_eq!(replacement.eval("1 + 1").unwrap(), "2");
    }
}

#[test]
#[ignore = "requires exception-on-OOM Hermes (v6 or a local build)"]
fn heap_oom_propagates_through_blocking_helpers() {
    for helper in 0..2 {
        for timer in [false, true] {
            let mut runtime = Hermes::with_heap_limit(DynamicCode::Closed, 8 << 20).unwrap();
            let context = crate::bindings::Context::new(crate::grant::GrantSet::none());
            runtime
                .install_runtime(crate::bindings::Groups::DEFAULT, &context)
                .unwrap();
            let schedule = if timer {
                "setTimeout"
            } else {
                "HermesInternal.enqueueJob"
            };
            runtime
                .eval(&format!("{schedule}(function () {{ {EXHAUST} }}, 0)"))
                .unwrap();
            let result = if helper == 0 {
                runtime.pump_until(1).map(|_| ())
            } else {
                runtime.run_to_quiescence(Duration::from_secs(5))
            };
            assert_eq!(
                result,
                Err(JsError::OutOfMemory),
                "helper {helper}, timer {timer}"
            );
        }
    }
}

#[cfg(feature = "test-support")]
#[test]
#[ignore = "requires exception-on-OOM Hermes (v6 or a local build)"]
fn heap_oom_during_deadline_flush_takes_precedence() {
    extern "C" {
        fn ibex2_hermes_test_deadline_flush_oom(handle: *mut c_void, outcome: c_int) -> c_int;
    }
    for outcome in 0..3 {
        let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
        let status = unsafe { ibex2_hermes_test_deadline_flush_oom(runtime.handle, outcome) };
        runtime.clear_deadline();
        assert_eq!(runtime.eval("1 + 1"), Err(JsError::OutOfMemory));
        assert_eq!(status, 3, "OOM must override outcome {outcome}");
    }
}
