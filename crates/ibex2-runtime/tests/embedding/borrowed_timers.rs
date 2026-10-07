//! LLP 0071: a borrowed runtime's timers, on the caller's clock, driven by the
//! caller's cycle (pre-checkpoint, admit, deliver one, post-checkpoint).
use super::*;
use std::sync::atomic::AtomicU64;

/// A clock the test holds, in milliseconds.
#[derive(Clone)]
struct Held(Arc<AtomicU64>);

impl Held {
    fn new(ms: f64) -> Self {
        Self(Arc::new(AtomicU64::new(ms.to_bits())))
    }
    fn set(&self, ms: f64) {
        self.0.store(ms.to_bits(), Ordering::SeqCst);
    }
    fn clock(&self) -> Arc<dyn Fn() -> f64 + Send + Sync> {
        let at = self.0.clone();
        Arc::new(move || f64::from_bits(at.load(Ordering::SeqCst)))
    }
}

const TIMED: Groups = Groups::CONSOLE
    .union(Groups::PURE)
    .union(Groups::EVENTS)
    .union(Groups::TIMERS);

fn clocked(groups: Groups, grants: &str, at: f64) -> (BareConsumer, Held) {
    ibex2_runtime::ensure_linked();
    let held = Held::new(at);
    let context = Context::new(GrantSet::parse(grants).expect("grants"));
    context
        .set_clock(held.clock())
        .expect("a fresh context takes a clock");
    (BareConsumer::from_context(groups, context), held)
}

fn context(consumer: &BareConsumer) -> &Context {
    consumer.context.as_ref().expect("live borrowed context")
}

/// `Adapter::cycle` until one is idle: settled at this clock.
fn settle(consumer: &BareConsumer) {
    for _ in 0..1000 {
        if consumer.cycle() == 0 {
            return;
        }
    }
    panic!("not settled in 1000 cycles");
}

fn log(consumer: &BareConsumer) -> String {
    consumer.eval("log.join(',')")
}

#[test]
fn timers_fire_in_order_on_the_callers_clock_and_never_on_the_wall_clock() {
    let (consumer, held) = clocked(TIMED, "", 0.0);
    consumer.eval(
        "globalThis.log = []; setTimeout(function () { log.push('f'); }, 50); \
         setTimeout(function () { log.push('g'); }, 10); \
         setInterval(function () { log.push('h'); }, 20);",
    );
    settle(&consumer);
    std::thread::sleep(Duration::from_millis(100));
    settle(&consumer);
    assert_eq!(
        log(&consumer),
        "",
        "a held clock admits nothing, however long it is held"
    );
    held.set(25.0);
    settle(&consumer);
    assert_eq!(log(&consumer), "g,h");
    assert_eq!(
        context(&consumer).millis_until_next_timer(),
        Some(20.0),
        "h was rescheduled from 25 when delivered"
    );
    held.set(60.0);
    settle(&consumer);
    assert_eq!(log(&consumer), "g,h,h,f");
}

#[test]
fn clearing_an_interval_from_its_callback_ends_it() {
    let (consumer, held) = clocked(TIMED, "", 0.0);
    consumer.eval(
        "globalThis.log = []; var h = setInterval(function () { log.push('h'); clearInterval(h); }, 20);",
    );
    held.set(25.0);
    settle(&consumer);
    held.set(1000.0);
    settle(&consumer);
    assert_eq!(log(&consumer), "h");
    assert_eq!(
        context(&consumer).millis_until_next_timer(),
        None,
        "nothing left on the wheel"
    );
}

#[test]
fn the_pre_checkpoint_runs_before_a_due_timer_and_one_delivery_runs_one_callback() {
    let (consumer, _held) = clocked(TIMED, "", 0.0);
    consumer.eval(
        "globalThis.log = []; var t = setTimeout(function () { log.push('t'); }, 0); \
         Promise.resolve().then(function () { clearTimeout(t); log.push('p'); }); \
         setTimeout(function () { log.push('a'); Promise.resolve().then(function () { log.push('ma'); }); }, 0); \
         setTimeout(function () { log.push('b'); }, 0);",
    );
    consumer.step(false);
    assert_eq!(
        context(&consumer).admit_due_timers(),
        2,
        "the cleared timer is not admitted"
    );
    assert_eq!(consumer.step(true), 1);
    assert_eq!(
        log(&consumer),
        "p,a",
        "one callback, and its microtask not yet drained"
    );
    consumer.step(false);
    assert_eq!(consumer.step(true), 1);
    consumer.step(false);
    assert_eq!(log(&consumer), "p,a,ma,b");
}

#[test]
fn a_delivery_is_refused_while_another_holds_the_drive_flag() {
    let (consumer, _held) = clocked(TIMED, "", 0.0);
    consumer.eval("globalThis.log = []; setTimeout(function () { log.push('t'); }, 0);");
    assert_eq!(context(&consumer).admit_due_timers(), 1);
    let state = context(&consumer)
        .state_ptr()
        .cast::<ibex2::task::RuntimeState>();
    // SAFETY: the context owns the state for this test.
    let state = unsafe { ibex2::task::borrow_state(state) }.expect("live state");
    assert!(state.begin_drive(), "nothing is driving yet");
    let refused = consumer.step_result(true).unwrap_err();
    assert!(refused.contains("nested delivery"), "{refused}");
    state.end_drive();
    assert_eq!(consumer.step(true), 1, "the task stayed queued");
    assert_eq!(log(&consumer), "t");
}

#[test]
fn an_interval_has_one_queued_occurrence_and_meets_the_nesting_clamp() {
    let (consumer, held) = clocked(TIMED, "", 0.0);
    consumer.eval("globalThis.log = []; setInterval(function () { log.push('i'); }, 0);");
    consumer.step(false);
    assert_eq!(context(&consumer).admit_due_timers(), 1);
    assert_eq!(
        context(&consumer).admit_due_timers(),
        0,
        "one occurrence queued, not two"
    );
    assert_eq!(consumer.step(true), 1);
    settle(&consumer);
    assert_eq!(
        log(&consumer),
        "i,i,i,i,i",
        "five runs at the interval given, then HTML's clamp"
    );
    held.set(3.999);
    settle(&consumer);
    assert_eq!(log(&consumer), "i,i,i,i,i");
    held.set(4.0);
    settle(&consumer);
    assert_eq!(log(&consumer), "i,i,i,i,i,i");
}

#[test]
fn an_interval_left_queued_across_a_clock_jump_repeats_from_its_delivery() {
    let (consumer, held) = clocked(TIMED, "", 0.0);
    consumer.eval("globalThis.log = []; setInterval(function () { log.push('h'); }, 20);");
    held.set(25.0);
    consumer.step(false);
    assert_eq!(context(&consumer).admit_due_timers(), 1);
    held.set(60.0);
    assert_eq!(consumer.step(true), 1);
    assert_eq!(
        context(&consumer).millis_until_next_timer(),
        Some(20.0),
        "next at 80, not 45"
    );
}

#[test]
fn an_interval_cleared_between_admission_and_delivery_is_a_no_op_and_ends() {
    let (consumer, held) = clocked(TIMED, "", 0.0);
    consumer.eval(
        "globalThis.log = []; globalThis.h = setInterval(function () { log.push('h'); }, 20);",
    );
    held.set(25.0);
    consumer.step(false);
    assert_eq!(context(&consumer).admit_due_timers(), 1);
    consumer.eval("clearInterval(h);");
    assert_eq!(consumer.step(true), 1, "the queued occurrence is delivered");
    assert_eq!(log(&consumer), "", "as timers.js's no-op");
    held.set(1000.0);
    settle(&consumer);
    assert_eq!(log(&consumer), "");
    assert_eq!(
        context(&consumer).millis_until_next_timer(),
        None,
        "and is not rescheduled"
    );
}

#[test]
fn the_callers_loop_reached_from_javascript_does_not_nest() {
    let (consumer, _held) = clocked(TIMED, "", 0.0);
    consumer.install_loop_probe();
    consumer.eval(
        "globalThis.log = []; \
         setTimeout(function () { \
           log.push('t:' + cycleFromJs()); \
           log.push('t:' + deliverFromJs().slice(0, 8)); \
           Promise.resolve().then(function () { log.push('m:' + cycleFromJs()); }); \
         }, 0); \
         setTimeout(function () { log.push('u'); }, 0);",
    );
    assert_eq!(consumer.cycle(), 1);
    assert_eq!(
        log(&consumer),
        "t:nested,t:refused:,m:nested",
        "the post-checkpoint is inside the cycle"
    );
    settle(&consumer);
    assert_eq!(
        log(&consumer),
        "t:nested,t:refused:,m:nested,u",
        "the second timer waited for its own cycle"
    );
}

#[test]
fn events_and_timers_share_one_fifo() {
    let (consumer, _held) = clocked(TIMED, "", 0.0);
    consumer.eval("globalThis.log = []; globalThis.onEvent = function () { log.push('event'); };");
    let callback = std::ffi::CString::new("onEvent").unwrap();
    let subscription = unsafe { storage_consumer_subscribe(consumer.handle, callback.as_ptr()) };
    let state = context(&consumer).state_ptr();
    assert_eq!(unsafe { ibex2_test_publish_event(state, subscription) }, 1);
    consumer.eval("setTimeout(function () { log.push('timer'); }, 0);");
    settle(&consumer);
    assert_eq!(
        log(&consumer),
        "event,timer",
        "the event was admitted first"
    );
}

#[test]
fn time_never_runs_backward_and_bad_readings_repeat_the_last() {
    let flaky = Arc::new(AtomicU64::new(10.0f64.to_bits()));
    let reading = flaky.clone();
    let clock: Arc<dyn Fn() -> f64 + Send + Sync> = Arc::new(move || {
        let ms = f64::from_bits(reading.load(Ordering::SeqCst));
        if ms == 7.0 {
            panic!("a clock that panics");
        }
        ms
    });
    ibex2_runtime::ensure_linked();
    let fresh = Context::new(GrantSet::none());
    fresh.set_clock(clock).expect("fresh");
    let consumer = BareConsumer::from_context(TIMED, fresh);
    consumer.eval("globalThis.log = []; setTimeout(function () { log.push('x'); }, 20);");
    let now = |c: &BareConsumer| c.eval("String(performance.now())");
    assert_eq!(now(&consumer), "10");
    for bad in [5.0, f64::NAN, f64::INFINITY, -1.0, 7.0, 1e300] {
        flaky.store(bad.to_bits(), Ordering::SeqCst);
        assert_eq!(now(&consumer), "10", "{bad} moved time");
        assert_eq!(context(&consumer).millis_until_next_timer(), Some(20.0));
    }
    flaky.store(30.0f64.to_bits(), Ordering::SeqCst);
    settle(&consumer);
    assert_eq!(log(&consumer), "x");
}

#[test]
fn due_and_the_distance_to_due_agree_on_a_fractional_clock() {
    let (consumer, held) = clocked(TIMED, "", 0.0);
    consumer.eval("globalThis.log = []; setTimeout(function () { log.push('x'); }, 1);");
    held.set(0.9996);
    assert!(context(&consumer).millis_until_next_timer().unwrap() > 0.0);
    assert_eq!(context(&consumer).admit_due_timers(), 0);
    held.set(1.0004);
    assert_eq!(context(&consumer).millis_until_next_timer(), Some(0.0));
    assert_eq!(context(&consumer).admit_due_timers(), 1);
}

#[test]
fn the_clock_is_sealed_at_its_first_read() {
    let held = Held::new(0.0);
    let read = Context::new(GrantSet::none());
    let _ = read.is_idle();
    assert!(
        read.set_clock(held.clock()).is_err(),
        "an idle is_idle read time"
    );
    let deadline = Context::new(GrantSet::none());
    let _ = deadline.millis_until_next_timer();
    assert!(
        deadline.set_clock(held.clock()).is_err(),
        "millis_until_next_timer read time"
    );
    let twice = Context::new(GrantSet::none());
    twice.set_clock(held.clock()).expect("first");
    assert!(twice.set_clock(held.clock()).is_err(), "a second clock");
    let (consumer, _) = clocked(TIMED, "", 0.0);
    consumer.eval("setTimeout(function () {}, 5);");
    assert!(context(&consumer).set_clock(held.clock()).is_err());
    assert_eq!(
        context(&consumer).millis_until_next_timer(),
        Some(5.0),
        "the stored deadline did not move"
    );
}

/// A diagnostic, not a supported use: D3 forbids a clock that calls into its
/// runtime. With a one-shot recursion guard, a clock that reads the wheel once
/// completes, which it could not if Ibex called the clock with the wheel's
/// lock held (`the_take_reads_the_clock_outside_the_subscription_lock` covers
/// the other lock).
#[test]
fn the_clock_is_called_with_no_ibex_lock_held() {
    use std::sync::OnceLock;
    let state: Arc<OnceLock<usize>> = Arc::new(OnceLock::new());
    let inner = state.clone();
    let clock: Arc<dyn Fn() -> f64 + Send + Sync> = Arc::new(move || {
        thread_local!(static INSIDE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) });
        if let Some(&address) = inner.get() {
            if !INSIDE.with(|inside| inside.replace(true)) {
                // SAFETY: the test's context outlives every read of its clock.
                let state = unsafe {
                    ibex2::task::borrow_state(address as *const ibex2::task::RuntimeState)
                };
                let _ = state.map(|state| state.millis_until_next_timer());
                INSIDE.with(|inside| inside.set(false));
            }
        }
        5.0
    });
    ibex2_runtime::ensure_linked();
    let fresh = Context::new(GrantSet::none());
    fresh.set_clock(clock).expect("fresh");
    let _ = state.set(fresh.state_ptr() as usize);
    let consumer = BareConsumer::from_context(TIMED, fresh);
    consumer.eval("globalThis.log = []; setTimeout(function () { log.push('x'); }, 0);");
    settle(&consumer);
    assert_eq!(log(&consumer), "x");
}

#[test]
fn a_throwing_timer_reaches_a_cancelable_error_event_and_delivery_goes_on() {
    let (consumer, _held) = clocked(TIMED, "", 0.0);
    let _ = ibex2::boundary_abi::drain_console();
    consumer.eval(
        "globalThis.log = []; addEventListener('error', function (event) { log.push('error:' + event.message); event.preventDefault(); }); \
         setTimeout(function () { throw new Error('timer boom'); }, 0); \
         setTimeout(function () { log.push('next'); }, 0);",
    );
    settle(&consumer);
    assert_eq!(log(&consumer), "error:timer boom,next");
    assert!(
        ibex2::boundary_abi::drain_console().is_empty(),
        "preventDefault canceled host reporting"
    );
}

#[test]
fn performance_now_and_event_time_stamps_read_the_callers_clock() {
    let (consumer, held) = clocked(TIMED, "", 1234.5);
    assert_eq!(consumer.eval("String(performance.now())"), "1234.5");
    held.set(2000.0);
    assert_eq!(consumer.eval("String(new Event('x').timeStamp)"), "2000");
}

fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126, "test frames are short");
    let mut out = vec![0x80 | opcode, payload.len() as u8];
    out.extend_from_slice(payload);
    out
}

fn client_frame(stream: &mut std::net::TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).ok()?;
    let length = (head[1] & 0x7f) as usize;
    assert!(length < 126, "test frames are short");
    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask).ok()?;
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).ok()?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    Some((head[0] & 0x0f, payload))
}

/// A local echo server; the count is the connections it accepted.
fn echo_server() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            count.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head);
                let key = head
                    .lines()
                    .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
                    .map(str::trim)
                    .expect("a WebSocket handshake");
                let accept = ibex2::stdlib::websocket::accept_key(key);
                let answer = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                stream.write_all(answer.as_bytes()).unwrap();
                while let Some((opcode, payload)) = client_frame(&mut stream) {
                    match opcode {
                        0x1 => stream.write_all(&frame(0x1, &payload)).unwrap(),
                        0x8 => {
                            let _ = stream.write_all(&frame(0x8, &payload));
                            return;
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    (port, accepted)
}

/// Cycles, letting real time pass for I/O, until `done` is true.
fn until(consumer: &BareConsumer, done: &str) {
    let end = Instant::now() + Duration::from_secs(10);
    while consumer.eval(done) != "true" {
        assert!(
            Instant::now() < end,
            "never true: {done}; log {}",
            log(consumer)
        );
        context(consumer).wait(Duration::from_millis(20));
        settle(consumer);
    }
}

#[cfg(feature = "websocket")]
#[test]
fn a_websocket_echoes_and_a_timer_reconnects_it_driven_only_by_the_cycle() {
    let (port, accepted) = echo_server();
    let groups = TIMED.union(Groups::WEBSOCKET);
    let (consumer, held) = clocked(
        groups,
        &format!("net.websocket ws://127.0.0.1:{port}\n"),
        0.0,
    );
    consumer.eval(&format!(
        r#"
        globalThis.log = [];
        globalThis.connects = 0;
        function connect() {{
          connects++;
          var socket = new WebSocket("ws://127.0.0.1:{port}/");
          socket.onopen = function () {{ log.push("open"); socket.send("hello"); }};
          socket.onmessage = function (event) {{ log.push("echo:" + event.data); socket.close(1000); }};
          socket.onclose = function (event) {{
            log.push("close:" + event.code);
            if (log.filter(function (entry) {{ return entry === "open"; }}).length < 2)
              setTimeout(connect, 100);
          }};
        }}
        connect();
        "#
    ));
    until(&consumer, "log.indexOf('close:1000') >= 0");
    assert_eq!(log(&consumer), "open,echo:hello,close:1000");
    std::thread::sleep(Duration::from_millis(150));
    settle(&consumer);
    assert_eq!(
        consumer.eval("String(connects)"),
        "1",
        "the reconnect timer waits for the caller's clock"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    held.set(100.0);
    until(&consumer, "log.length === 6");
    assert_eq!(
        log(&consumer),
        "open,echo:hello,close:1000,open,echo:hello,close:1000"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[cfg(feature = "websocket")]
#[test]
fn a_denied_websocket_still_errors_and_closes_with_timers_installed() {
    let (consumer, _held) = clocked(TIMED.union(Groups::WEBSOCKET), "", 0.0);
    consumer.eval(
        r#"
        globalThis.log = [];
        var socket = new WebSocket("ws://127.0.0.1:9/");
        socket.onerror = function () { log.push("error"); };
        socket.onclose = function (event) { log.push("close:" + event.code); };
        "#,
    );
    until(&consumer, "log.indexOf('close:1006') >= 0");
    assert_eq!(log(&consumer), "error,close:1006");
}

#[test]
fn a_cycle_runs_its_own_pre_checkpoint() {
    let (consumer, _held) = clocked(TIMED, "", 0.0);
    consumer.eval(
        "globalThis.log = []; var t = setTimeout(function () { log.push('t'); }, 0); \
         Promise.resolve().then(function () { clearTimeout(t); log.push('p'); });",
    );
    assert_eq!(
        consumer.cycle(),
        0,
        "the reaction cleared t before admission"
    );
    assert_eq!(log(&consumer), "p");
}

#[test]
fn a_job_that_throws_out_of_a_checkpoint_is_reported_and_the_drain_resumes() {
    let (consumer, _held) = clocked(TIMED, "", 0.0);
    let _ = ibex2::boundary_abi::drain_console();
    consumer.eval(
        "globalThis.log = []; \
         addEventListener('error', function (event) { log.push('error:' + event.message); event.preventDefault(); }); \
         HermesInternal.enqueueJob(function () { throw new Error('job boom'); }); \
         HermesInternal.enqueueJob(function () { log.push('after'); }); \
         setTimeout(function () { \
           log.push('t'); \
           HermesInternal.enqueueJob(function () { throw new Error('post boom'); }); \
           HermesInternal.enqueueJob(function () { log.push('post-after'); }); \
         }, 0);",
    );
    assert_eq!(
        consumer.cycle(),
        1,
        "the cycle went on after the pre-checkpoint's throw"
    );
    assert_eq!(
        log(&consumer),
        "error:job boom,after,t,error:post boom,post-after"
    );
    assert_eq!(consumer.cycle(), 0, "and the drive flag was released");
    assert!(
        ibex2::boundary_abi::drain_console().is_empty(),
        "preventDefault canceled host reporting"
    );
}

#[test]
fn a_callback_that_detaches_the_adapter_ends_the_cycle() {
    let (consumer, _held) = clocked(TIMED, "", 0.0);
    consumer.install_loop_probe();
    consumer.eval(
        "globalThis.log = []; \
         setTimeout(function () { log.push('t'); detachFromJs(); Promise.resolve().then(function () { log.push('late'); }); }, 0); \
         setTimeout(function () { log.push('u'); }, 0);",
    );
    assert_eq!(consumer.cycle(), 1);
    assert_eq!(consumer.cycle(), 0, "a detached adapter runs nothing");
    assert_eq!(log(&consumer), "t", "no post-checkpoint, no second timer");
}

/// LLP 0071 D3 and D6: the clock read at a timer's take runs after the
/// subscription lock is released. The clock publishes an event (which takes
/// that lock) on the second read after it is armed -- admission's is the
/// first, the take's the second; a watchdog fails the test instead of hanging.
#[test]
fn the_take_reads_the_clock_outside_the_subscription_lock() {
    use std::sync::atomic::AtomicBool;
    let countdown = Arc::new(AtomicUsize::new(0));
    let target: Arc<std::sync::OnceLock<(usize, u64)>> = Arc::new(std::sync::OnceLock::new());
    let (inner_countdown, inner_target) = (countdown.clone(), target.clone());
    let clock: Arc<dyn Fn() -> f64 + Send + Sync> = Arc::new(move || {
        if inner_countdown.load(Ordering::SeqCst) > 0
            && inner_countdown.fetch_sub(1, Ordering::SeqCst) == 1
        {
            if let Some(&(state, subscription)) = inner_target.get() {
                // SAFETY: the test's context outlives every read of its clock.
                assert_eq!(
                    unsafe { ibex2_test_publish_event(state as *const c_void, subscription) },
                    1
                );
            }
        }
        0.0
    });
    ibex2_runtime::ensure_linked();
    let fresh = Context::new(GrantSet::none());
    fresh.set_clock(clock).expect("fresh");
    let consumer = BareConsumer::from_context(TIMED, fresh);
    consumer.eval("globalThis.log = []; globalThis.onEvent = function () { log.push('event'); };");
    let callback = std::ffi::CString::new("onEvent").unwrap();
    let subscription = unsafe { storage_consumer_subscribe(consumer.handle, callback.as_ptr()) };
    let _ = target.set((context(&consumer).state_ptr() as usize, subscription));
    consumer.eval("setTimeout(function () { log.push('timer'); }, 0);");
    let done = Arc::new(AtomicBool::new(false));
    let watching = done.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(30));
        if !watching.load(Ordering::SeqCst) {
            eprintln!("the clock was read under the subscription lock: deadlock");
            std::process::abort();
        }
    });
    countdown.store(2, Ordering::SeqCst);
    settle(&consumer);
    done.store(true, Ordering::SeqCst);
    assert_eq!(log(&consumer), "timer,event");
}

#[test]
fn reading_time_seals_and_answering_without_it_does_not() {
    let held = Held::new(0.0);
    ibex2_runtime::ensure_linked();
    let unclocked = BareConsumer::from_context(TIMED, Context::new(GrantSet::none()));
    unclocked.eval("setTimeout(function () {}, 5);");
    assert!(
        context(&unclocked).set_clock(held.clock()).is_err(),
        "setTimeout read time"
    );

    let busy = BareConsumer::from_context(TIMED, Context::new(GrantSet::none()));
    busy.eval("globalThis.onEvent = function () {};");
    let callback = std::ffi::CString::new("onEvent").unwrap();
    let subscription = unsafe { storage_consumer_subscribe(busy.handle, callback.as_ptr()) };
    assert_eq!(
        unsafe { ibex2_test_publish_event(context(&busy).state_ptr(), subscription) },
        1
    );
    assert!(!context(&busy).is_idle(), "work is queued");
    assert!(
        context(&busy).set_clock(held.clock()).is_ok(),
        "a busy is_idle read no time"
    );
}

#[test]
fn due_and_the_distance_to_due_agree_far_from_the_origin() {
    let origin = 1.0e12;
    let (consumer, held) = clocked(TIMED, "", origin);
    consumer.eval("globalThis.log = []; setTimeout(function () { log.push('x'); }, 1);");
    held.set(origin + 0.9996);
    assert_eq!(context(&consumer).millis_until_next_timer(), Some(0.001));
    assert_eq!(context(&consumer).admit_due_timers(), 0);
    held.set(origin + 1.0004);
    assert_eq!(context(&consumer).millis_until_next_timer(), Some(0.0));
    assert_eq!(context(&consumer).admit_due_timers(), 1);
}

#[test]
fn a_delay_too_large_for_a_duration_is_never_due() {
    let (consumer, held) = clocked(TIMED, "", 0.0);
    consumer.eval("globalThis.log = []; setTimeout(function () { log.push('never'); }, 1e300);");
    held.set(9.0e15);
    settle(&consumer);
    assert_eq!(log(&consumer), "");
}

#[test]
fn an_invalid_first_reading_is_time_zero() {
    let bad = Held::new(f64::NAN);
    ibex2_runtime::ensure_linked();
    let fresh = Context::new(GrantSet::none());
    fresh.set_clock(bad.clock()).expect("fresh");
    let consumer = BareConsumer::from_context(TIMED, fresh);
    assert_eq!(consumer.eval("String(performance.now())"), "0");
    bad.set(3.0);
    assert_eq!(consumer.eval("String(performance.now())"), "3");
}
