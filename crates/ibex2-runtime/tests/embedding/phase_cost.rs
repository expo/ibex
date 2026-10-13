//! Diagnostic phase timings for an Exact-shaped borrowed-runtime startup.
//!
//! @ref LLP 0063#9-methodology-and-three-measurements-that-were-wrong — use
//! repeated samples and report the distribution instead of trusting one run.
//! @ref LLP 0068#deferred-intrinsic-integrity-baseline — measure the supported
//! install, trusted-prelude, capture, harden lifecycle without application code.

use super::*;
use std::{
    process::Command,
    time::{Duration, Instant},
};

const GROUPS: Groups = Groups::PURE.union(Groups::CRYPTO).union(Groups::ABORT);
const ABORT_HOOKS: &str = "__exact2_private_abort_hooks";
const WARMUP_SAMPLES: usize = 20;
const MEASURED_SAMPLES: usize = 200;

// This is the trusted-prelude shape already exercised by the deferred-baseline
// functional test: consume and delete the private abort handoff, retain its
// operation only in a closure, replace one intrinsic property, and add one.
// It is deliberately not represented as Exact's complete production prelude.
const TRUSTED_PRELUDE: &str = r#"
globalThis.exact2AbortSubscribe = (function (hooks) {
  var subscribe = hooks.subscribe;
  delete globalThis.__exact2_private_abort_hooks;
  return function (signal, callback) {
    return subscribe(signal, callback);
  };
})(globalThis.__exact2_private_abort_hooks);
Number.prototype.toLocaleString = function () { return "trusted-number"; };
Object.defineProperty(Array.prototype, "trustedArrayMethod", {
  value: function () { return "trusted-array"; },
  writable: true,
  configurable: true
});
"trusted-prelude-ready";
"#;

#[derive(Clone, Copy)]
struct Sample {
    context_create: Duration,
    runtime_and_adapter_create: Duration,
    binding_install: Duration,
    trusted_prelude: Duration,
    intrinsic_capture: Duration,
    harden: Duration,
    door_total: Duration,
    startup_through_harden: Duration,
    runtime_destroy: Duration,
    context_destroy: Duration,
}

fn compile_prelude_once() -> (PathBuf, Vec<u8>) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let directory = std::env::temp_dir().join(format!(
        "ibex2-phase-cost-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).expect("phase-cost fixture directory");
    let input = directory.join("trusted-prelude.js");
    let output = directory.join("trusted-prelude.hbc");
    std::fs::write(&input, TRUSTED_PRELUDE).expect("write trusted prelude");
    let status = Command::new(ibex2_runtime::HERMESC_PATH)
        .args(["-O", "-emit-binary", "-out"])
        .arg(&output)
        .arg(&input)
        .status()
        .expect("run hermesc once for the trusted prelude");
    assert!(status.success(), "hermesc failed for phase-cost prelude");
    let bytecode = std::fs::read(&output).expect("read trusted prelude bytecode");
    (directory, bytecode)
}

fn duration_since(start: Instant) -> Duration {
    start.elapsed()
}

fn measure_once(scripts: &[CompiledScript], abort_hooks: &CString, prelude: &[u8]) -> Sample {
    let startup_started = Instant::now();

    let phase_started = Instant::now();
    let context = Context::new(GrantSet::none());
    let context_create = duration_since(phase_started);

    let phase_started = Instant::now();
    let handle = unsafe { bindings_consumer_create_uninstalled(context.state_ptr()) };
    assert!(!handle.is_null(), "create uninstalled borrowed runtime");
    let runtime_and_adapter_create = duration_since(phase_started);

    let door_started = Instant::now();
    let phase_started = Instant::now();
    let mut error = std::ptr::null_mut();
    let installed = unsafe {
        bindings_consumer_install_with_options(
            handle,
            context.bindings_ptr(),
            GROUPS.bits(),
            scripts.as_ptr(),
            scripts.len(),
            std::ptr::null(),
            abort_hooks.as_ptr(),
            true,
            &mut error,
        )
    };
    assert_eq!(installed, 1, "binding install: {}", take(error));
    let binding_install = duration_since(phase_started);

    let phase_started = Instant::now();
    let mut out = std::ptr::null_mut();
    let eval_status =
        unsafe { storage_consumer_eval(handle, prelude.as_ptr(), prelude.len(), &mut out) };
    let eval_result = take(out);
    assert_eq!(eval_status, 0, "trusted prelude: {eval_result}");
    assert_eq!(eval_result, "trusted-prelude-ready");
    let trusted_prelude = duration_since(phase_started);

    let phase_started = Instant::now();
    let mut error = std::ptr::null_mut();
    let captured = unsafe { bindings_consumer_capture_intrinsics(handle, &mut error) };
    assert_eq!(captured, 1, "intrinsic capture: {}", take(error));
    let intrinsic_capture = duration_since(phase_started);

    let phase_started = Instant::now();
    let mut error = std::ptr::null_mut();
    let harden = ibex2::bindings::HARDEN_BYTECODE;
    let hardened =
        unsafe { bindings_consumer_harden(handle, harden.as_ptr(), harden.len(), &mut error) };
    assert_eq!(hardened, 1, "harden: {}", take(error));
    let harden = duration_since(phase_started);

    let door_total = duration_since(door_started);
    let startup_through_harden = duration_since(startup_started);

    let phase_started = Instant::now();
    unsafe { storage_consumer_destroy(handle) };
    let runtime_destroy = duration_since(phase_started);

    let phase_started = Instant::now();
    drop(context);
    let context_destroy = duration_since(phase_started);

    Sample {
        context_create,
        runtime_and_adapter_create,
        binding_install,
        trusted_prelude,
        intrinsic_capture,
        harden,
        door_total,
        startup_through_harden,
        runtime_destroy,
        context_destroy,
    }
}

fn percentile(sorted: &[Duration], numerator: usize, denominator: usize) -> Duration {
    let index = ((sorted.len() - 1) * numerator).div_ceil(denominator);
    sorted[index]
}

fn print_distribution(name: &str, samples: impl Iterator<Item = Duration>) {
    let mut samples: Vec<_> = samples.collect();
    samples.sort_unstable();
    let micros = |value: Duration| value.as_secs_f64() * 1_000_000.0;
    eprintln!(
        "{name:>27}  min {:>9.1} us  p25 {:>9.1} us  median {:>9.1} us  p75 {:>9.1} us  p95 {:>9.1} us  max {:>9.1} us",
        micros(samples[0]),
        micros(percentile(&samples, 1, 4)),
        micros(percentile(&samples, 1, 2)),
        micros(percentile(&samples, 3, 4)),
        micros(percentile(&samples, 95, 100)),
        micros(*samples.last().expect("nonempty samples")),
    );
}

fn uptime() -> String {
    Command::new("uptime")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "uptime unavailable".to_owned())
}

#[test]
#[ignore = "manual startup diagnostic; distributions are machine and load dependent"]
fn exact_shaped_borrowed_runtime_phase_costs() {
    ibex2_runtime::ensure_linked();

    // Build every stable input before warmup or measurement. In particular,
    // hermesc runs exactly once here, never from `BareConsumer::eval` and never
    // inside a timed sample.
    let scripts: Vec<_> = ibex2::bindings::scripts(GROUPS)
        .expect("Exact-shaped groups are valid")
        .into_iter()
        .map(|(name, _)| compiled_script(name))
        .collect();
    let abort_hooks = CString::new(ABORT_HOOKS).expect("static hook name has no NUL");
    let (fixture_directory, prelude) = compile_prelude_once();

    eprintln!("host: {} {}", std::env::consts::OS, std::env::consts::ARCH);
    eprintln!(
        "parallelism: {} logical CPUs",
        std::thread::available_parallelism().map_or(0, usize::from)
    );
    eprintln!("load before warmup: {}", uptime());
    eprintln!(
        "engine: full source-capable borrowed Hermes runtime; this does not measure the separate lean VM"
    );
    eprintln!("groups: PURE|CRYPTO|ABORT; deferred baseline: true; abort handoff: {ABORT_HOOKS}");
    eprintln!(
        "fixture boundary: test trusted prelude only (abort capture/delete plus one intrinsic replacement and one addition); no Exact production prelude or application module"
    );
    eprintln!(
        "prelude eval includes the existing fixture ABI's completion-value stringify/copy/free"
    );
    eprintln!(
        "compiled inputs prepared before timing: {} binding scripts, {} prelude bytes, {} harden bytes",
        scripts.len(),
        prelude.len(),
        ibex2::bindings::HARDEN_BYTECODE.len()
    );

    for _ in 0..WARMUP_SAMPLES {
        let _ = measure_once(&scripts, &abort_hooks, &prelude);
    }
    eprintln!("load after warmup: {}", uptime());

    let samples: Vec<_> = (0..MEASURED_SAMPLES)
        .map(|_| measure_once(&scripts, &abort_hooks, &prelude))
        .collect();

    eprintln!("samples: {MEASURED_SAMPLES} after {WARMUP_SAMPLES} discarded warmups");
    print_distribution("Context::new", samples.iter().map(|s| s.context_create));
    print_distribution(
        "runtime + Adapter::new",
        samples.iter().map(|s| s.runtime_and_adapter_create),
    );
    print_distribution("binding install", samples.iter().map(|s| s.binding_install));
    print_distribution(
        "trusted prelude eval",
        samples.iter().map(|s| s.trusted_prelude),
    );
    print_distribution(
        "capture_intrinsics",
        samples.iter().map(|s| s.intrinsic_capture),
    );
    print_distribution("harden", samples.iter().map(|s| s.harden));
    print_distribution(
        "door total (4 phases)",
        samples.iter().map(|s| s.door_total),
    );
    print_distribution(
        "startup through harden",
        samples.iter().map(|s| s.startup_through_harden),
    );
    print_distribution(
        "borrowed runtime destroy",
        samples.iter().map(|s| s.runtime_destroy),
    );
    print_distribution("Context drop", samples.iter().map(|s| s.context_destroy));
    eprintln!("load after measurement: {}", uptime());

    std::fs::remove_dir_all(fixture_directory).expect("remove phase-cost fixture directory");
}
