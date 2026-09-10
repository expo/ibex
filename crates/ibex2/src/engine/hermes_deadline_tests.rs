//! The deadline: one per runtime, held at every entrance.
//!
//! Its own file for the reason `hermes_tests.rs` is: the 1,500-line cap in
//! `rules/RULES.md`. Every test here is wall-clock — the deadline is one —
//! so the windows are wide enough to hold under a loaded machine and narrow
//! enough to tell a stopped program from one that ran to its end.

use super::*;
use std::time::{Duration, Instant};

fn runtime() -> Hermes {
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    assert!(rt.install_stdlib());
    rt.install_bindings().expect("bindings");
    rt
}

/// A program that busy-waits `millis` of wall-clock time and then returns.
fn spin(millis: u64) -> String {
    format!(
        "(function () {{ const end = Date.now() + {millis}; \
         while (Date.now() < end) {{}} return 'spun'; }})()"
    )
}

/// Pump until the runtime reports its deadline, or fail if it never does.
fn pump_until_stopped(rt: &mut Hermes, started: Instant) -> (JsError, i32) {
    let mut cycles = 0;
    loop {
        match rt.pump() {
            Ok(ran) => cycles += ran,
            Err(stop) => return (stop, cycles),
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the pump was never stopped"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// The ticket's first case: `while (true) {}` in a host evaluation.
#[test]
fn a_synchronous_loop_is_stopped_at_the_deadline() {
    let mut rt = runtime();
    let started = Instant::now();
    rt.set_deadline(started + Duration::from_millis(150));
    assert_eq!(rt.eval("while (true) {}"), Err(JsError::Deadline));
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(150), "stopped early: {elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "stopped late: {elapsed:?}");
    // Reusable once the deadline is cleared.
    rt.clear_deadline();
    assert_eq!(rt.eval("1 + 1").unwrap(), "2");
}

/// The ticket's second case: a microtask that schedules itself forever.
///
/// The engine's check sits at a function's return, after the callback has
/// scheduled its successor — so the stop pauses the chain rather than
/// killing it, and a drain with no deadline would resume it. What the
/// deadline promises is that no drain outlives it: a second deadline stops
/// the same chain again, and the runtime is still there for a fresh
/// evaluation. Whether to keep such a runtime is the consumer's call;
/// Snapback 2 discards one whose deadline fired.
#[test]
fn a_recursive_microtask_chain_is_stopped_at_the_deadline() {
    let mut rt = runtime();
    let started = Instant::now();
    rt.set_deadline(started + Duration::from_millis(150));
    rt.eval(
        "globalThis.steps = 0; \
         function again() { steps++; Promise.resolve().then(again); } again();",
    )
    .unwrap();
    assert_eq!(rt.drain_microtasks(), Err(JsError::Deadline));
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(150), "stopped early: {elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "stopped late: {elapsed:?}");

    let rearmed = Instant::now();
    rt.set_deadline(rearmed + Duration::from_millis(100));
    assert_eq!(rt.drain_microtasks(), Err(JsError::Deadline));
    let elapsed = rearmed.elapsed();
    assert!(elapsed >= Duration::from_millis(100), "stopped early: {elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "stopped late: {elapsed:?}");

    rt.clear_deadline();
    assert_eq!(rt.eval("String(steps > 0)").unwrap(), "true", "the chain never ran");
}

/// A timer callback that never returns is stopped inside the pump, and the
/// stopped cycle releases the drive flag: the next cycle runs rather than
/// being refused as nested.
#[test]
fn a_timer_callback_is_stopped_at_the_deadline_and_the_drive_is_released() {
    let mut rt = runtime();
    rt.eval("globalThis.entered = false; setTimeout(() => { entered = true; while (true) {} }, 1);")
        .unwrap();
    let started = Instant::now();
    rt.set_deadline(started + Duration::from_millis(150));
    let (stop, _) = pump_until_stopped(&mut rt, started);
    assert_eq!(stop, JsError::Deadline);
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(150), "stopped early: {elapsed:?}");
    rt.clear_deadline();
    assert_eq!(rt.eval("String(entered)").unwrap(), "true", "the callback never ran");
    rt.eval("globalThis.again = false; setTimeout(() => { again = true; }, 1);")
        .unwrap();
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(rt.pump().unwrap(), 1, "the drive flag was left set");
    assert_eq!(rt.eval("String(again)").unwrap(), "true");
}

/// A chain of short timers, each rescheduling the next, is ended at the
/// door: the deadline passes between cycles and the next cycle is refused
/// without running anything.
#[test]
fn a_self_rescheduling_timer_chain_is_refused_at_the_deadline() {
    let mut rt = runtime();
    rt.eval("globalThis.ticks = 0; function tick() { ticks++; setTimeout(tick, 0); } tick();")
        .unwrap();
    let started = Instant::now();
    rt.set_deadline(started + Duration::from_millis(150));
    let (stop, cycles) = pump_until_stopped(&mut rt, started);
    assert_eq!(stop, JsError::Deadline);
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(150), "stopped early: {elapsed:?}");
    assert!(elapsed < Duration::from_millis(400), "the refusal waited: {elapsed:?}");
    assert!(cycles > 0, "the chain never ran before the deadline");
    rt.clear_deadline();
    assert_eq!(rt.eval("String(ticks > 0)").unwrap(), "true");
}

/// The control: a program that behaves completes under the same deadline,
/// through every entrance, with the deadline nowhere in its results.
#[test]
fn a_well_behaved_program_completes_under_a_deadline() {
    let mut rt = runtime();
    let started = Instant::now();
    rt.set_deadline(started + Duration::from_secs(10));
    assert_eq!(rt.eval("40 + 2").unwrap(), "42");
    rt.eval("globalThis.n = 0; function step() { if (++n < 1000) Promise.resolve().then(step); } step();")
        .unwrap();
    rt.drain_microtasks().unwrap();
    assert_eq!(rt.eval("String(n)").unwrap(), "1000");
    rt.eval("globalThis.fired = false; setTimeout(() => { fired = true; }, 1);")
        .unwrap();
    while rt.eval("String(fired)").unwrap() != "true" {
        rt.pump().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5), "the timer never fired");
        std::thread::sleep(Duration::from_millis(1));
    }
    rt.clear_deadline();
    assert!(started.elapsed() < Duration::from_secs(10));
}

/// The deadline is one point in time, not a budget renewed at each
/// entrance: three spins that would each fit are stopped where the deadline
/// falls, not after the third has had its own full share.
#[test]
fn the_remaining_time_is_what_is_left_of_the_same_deadline() {
    let mut rt = runtime();
    let started = Instant::now();
    rt.set_deadline(started + Duration::from_millis(600));
    assert_eq!(rt.eval(&spin(250)).unwrap(), "spun");
    assert_eq!(rt.eval(&spin(250)).unwrap(), "spun");
    // A per-entrance budget would let this one finish at ~750 ms.
    assert_eq!(rt.eval(&spin(250)), Err(JsError::Deadline));
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(600), "stopped early: {elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(700),
        "the third entrance was given a fresh budget: {elapsed:?}"
    );
}

/// Past the deadline an entrance is refused at the door — immediately, and
/// without running what it was given.
#[test]
fn a_deadline_already_passed_refuses_the_entrance_without_running_it() {
    let mut rt = runtime();
    rt.set_deadline(Instant::now());
    std::thread::sleep(Duration::from_millis(2));
    let started = Instant::now();
    assert_eq!(rt.eval("globalThis.ran = true"), Err(JsError::Deadline));
    assert_eq!(rt.drain_microtasks(), Err(JsError::Deadline));
    assert_eq!(rt.pump(), Err(JsError::Deadline));
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(100), "a refusal waited: {elapsed:?}");
    rt.clear_deadline();
    assert_eq!(rt.eval("String(globalThis.ran)").unwrap(), "undefined");
}

/// The interruption is a kind, not a string: a throw that forges the
/// engine's own timeout text is `Thrown`, and the real stop needs no text.
#[test]
fn the_interruption_is_reported_by_kind_not_by_message_text() {
    let mut rt = runtime();
    rt.set_deadline(Instant::now() + Duration::from_secs(10));
    let forged = rt
        .eval("throw new Error('Javascript execution has timed out.')")
        .unwrap_err();
    assert!(
        matches!(forged, JsError::Thrown(ref text) if text.contains("timed out")),
        "{forged:?}"
    );
    rt.set_deadline(Instant::now() + Duration::from_millis(50));
    assert_eq!(rt.eval("while (true) {}"), Err(JsError::Deadline));
}

/// Bytecode carries only the checks it was compiled with, and hermesc emits
/// none by default: such a program is not stopped mid-way, but it is held
/// to the deadline on the way out, and the request the monitor left pending
/// while it ran is flushed rather than thrown at the next entrance.
#[test]
fn uncheckable_bytecode_is_reported_at_exit_and_its_pending_break_is_flushed() {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cache = std::env::temp_dir().join(format!("ibex2-deadline-{}", std::process::id()));
    let compiler = crate::bytecode::Compiler::discover(&repo_root, cache.clone())
        .expect("the hermesc this build compiled its bindings with");
    let bytes = compiler.compile(&spin(200)).expect("compile");
    let mut rt = runtime();
    let started = Instant::now();
    rt.set_deadline(started + Duration::from_millis(50));
    assert_eq!(rt.eval_bytes(&bytes), Err(JsError::Deadline));
    let elapsed = started.elapsed();
    // Its own end, give or take the millisecond `Date.now()` rounds to —
    // against a 50 ms deadline.
    assert!(
        elapsed >= Duration::from_millis(190),
        "check-free bytecode was stopped mid-way: {elapsed:?}"
    );
    // Without the flush this would throw the engine's timeout for a
    // deadline that is no longer armed.
    rt.clear_deadline();
    assert_eq!(rt.eval("1 + 1").unwrap(), "2");
    let _ = std::fs::remove_dir_all(cache);
}

/// Teardown with a deadline armed, and with one that fired, is clean.
#[test]
fn a_runtime_is_dropped_cleanly_with_its_deadline_armed_or_fired() {
    let mut armed = runtime();
    armed.set_deadline(Instant::now() + Duration::from_secs(10));
    drop(armed);
    let mut fired = runtime();
    fired.set_deadline(Instant::now() + Duration::from_millis(50));
    assert_eq!(fired.eval("while (true) {}"), Err(JsError::Deadline));
    drop(fired);
}
