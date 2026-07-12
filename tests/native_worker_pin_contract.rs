//! Source-level lifetime contract for the cross-subsystem native-worker pin.
//!
//! The bug this protects is a narrow teardown race: publishing the last pin
//! before taking the waiter mutex lets destroy observe zero and free the
//! runtime before unpin reaches that mutex/condvar. Keeping the whole final
//! access sequence under the waiter mutex makes the ordering deterministic.

const RUNTIME: &str = include_str!("../src/engine/hermes_runtime.cc");

#[test]
fn native_worker_unpin_publishes_zero_under_the_teardown_mutex() {
    let start = RUNTIME
        .find("void exactUnpinRuntimeNativeWorker")
        .expect("native worker unpin implementation");
    let end = RUNTIME[start..]
        .find("\n}\n\nstatic bool beginRuntimeTeardown")
        .map(|offset| start + offset)
        .expect("native worker unpin function boundary");
    let body = &RUNTIME[start..end];

    let lock = body
        .find("std::lock_guard<std::mutex> lock(runtime->native_worker_mutex);")
        .expect("unpin must take the teardown waiter mutex");
    let decrement = body
        .find("runtime->native_worker_pins.fetch_sub")
        .expect("unpin must publish its decrement");
    let notify = body
        .find("runtime->native_worker_cv.notify_all();")
        .expect("last unpin must notify teardown");

    assert!(
        lock < decrement && decrement < notify,
        "decrement and notify must both occur after acquiring the waiter mutex"
    );
    assert_eq!(
        body.matches("native_worker_mutex").count(),
        1,
        "unpin must use one critical section, not publish zero before a later lock"
    );
}
