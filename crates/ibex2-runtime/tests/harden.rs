//! LLP 0067 R4: the intrinsic freeze, exercised from the same file the
//! binary runs (`intrinsic_harden.rs` measures a copy; this pins behaviour).

use ibex2_runtime::engine::hermes::{DynamicCode, Hermes, InstallOptions};

fn install_runtime(rt: &mut Hermes) {
    let context = ibex2::bindings::Context::new(ibex2::grant::GrantSet::none());
    rt.install_runtime(ibex2::bindings::Groups::DEFAULT, &context)
        .expect("bindings");
}

fn hardened() -> Hermes {
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    install_runtime(&mut rt);
    rt.harden().expect("harden");
    rt
}

fn eval(rt: &mut Hermes, program: &str) -> String {
    rt.eval(program)
        .unwrap_or_else(|e| panic!("{program}: {e}"))
}

#[test]
fn owning_runtime_can_defer_and_capture_its_intrinsic_baseline_once() {
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    let context = ibex2::bindings::Context::new(ibex2::grant::GrantSet::none());
    rt.install_with(
        ibex2::bindings::Groups::PURE,
        &context,
        InstallOptions {
            defer_intrinsic_snapshot: true,
            ..InstallOptions::default()
        },
    )
    .expect("deferred install");
    eval(
        &mut rt,
        "Number.prototype.toLocaleString = function () { return 'trusted'; }; \
         Object.defineProperty(Array.prototype, 'trustedMethod', { value: function () { return 7; }, configurable: true });",
    );
    assert!(rt
        .harden()
        .unwrap_err()
        .to_string()
        .contains("deferred intrinsic snapshot is captured"));
    rt.capture_intrinsics().expect("capture trusted prelude");
    rt.harden().expect("capture permits hardening");
    assert_eq!(
        eval(&mut rt, "(1).toLocaleString() + [][\"trustedMethod\"]()"),
        "trusted7"
    );
    assert!(rt
        .capture_intrinsics()
        .unwrap_err()
        .to_string()
        .contains("already captured"));
}

#[test]
fn intrinsics_are_frozen_and_global_bindings_are_locked() {
    let mut rt = hardened();
    assert_eq!(
        eval(
            &mut rt,
            "(function () { try { Object.prototype.polluted = 1; } catch (e) {} \
             return String(({}).polluted); })()"
        ),
        "undefined"
    );
    assert_eq!(
        eval(
            &mut rt,
            "(function () { const m = Array.prototype.map; \
             try { Array.prototype.map = function () { return 'x'; }; } catch (e) {} \
             return String(Array.prototype.map === m); })()"
        ),
        "true"
    );
    // The binding itself is locked, not just the object it names: `Array`
    // cannot be pointed at something else.
    assert_eq!(
        eval(
            &mut rt,
            "(function () { 'use strict'; try { globalThis.Array = 1; return 'took'; } \
             catch (e) { return e.constructor.name; } })()"
        ),
        "TypeError"
    );
    assert_eq!(eval(&mut rt, "String(typeof Array === 'function')"), "true");
    // A runtime helper is as locked as an intrinsic.
    assert_eq!(
        eval(
            &mut rt,
            "String(Object.getOwnPropertyDescriptor(globalThis, '__ibex2_default').writable)"
        ),
        "false"
    );
}

/// The global object stays extensible. Application code anchors shared state
/// on it — Exact under 193 distinct `globalThis.__exact*` names, plus
/// `process`, `window`, `self`, `global`, and `navigator` — and with the object
/// frozen every one of those writes silently did nothing. What an application
/// adds is state, not authority: R1 is about what is there at boot.
#[test]
fn the_global_object_accepts_new_properties() {
    let mut rt = hardened();
    assert_eq!(
        eval(&mut rt, "String(Object.isExtensible(globalThis))"),
        "true"
    );
    assert_eq!(
        eval(
            &mut rt,
            "(function () { 'use strict'; globalThis.__appState ??= { n: 1 }; \
             globalThis.__appState.n += 1; return String(globalThis.__appState.n); })()"
        ),
        "2"
    );
    // Exact's own bootstrap shape. `navigator` is now a runtime global, so an
    // application keeps it rather than replacing it with its former shim.
    assert_eq!(
        eval(
            &mut rt,
            "(function () { const r = globalThis; r.global = r; r.self = r; r.window = r; \
             r.navigator ??= { product: 'x' }; \
             return String(r.window === globalThis) + r.navigator.userAgent; })()"
        ),
        "trueIbex/0.1.0"
    );
}

#[test]
fn application_cannot_reach_the_private_timer_dispatcher_after_harden() {
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    install_runtime(&mut rt);
    assert!(rt.expose_timer_dispatch_for_test());
    eval(
        &mut rt,
        r#"
        globalThis.__timerDispatcherAbsent = (function (dispatcher) {
          delete globalThis.__ibex2_test_timer_dispatch;
          return function () {
            var targets = [setTimeout, clearTimeout, Function.prototype, globalThis];
            var labels = ["setTimeout", "clearTimeout", "Function.prototype", "globalThis"];
            for (var i = 0; i < targets.length; i++) {
              var names = Object.getOwnPropertyNames(targets[i]);
              for (var j = 0; j < names.length; j++) {
                var descriptor = Object.getOwnPropertyDescriptor(targets[i], names[j]);
                if (descriptor.value === dispatcher || descriptor.get === dispatcher ||
                    descriptor.set === dispatcher) {
                  return labels[i] + "." + names[j];
                }
              }
            }
            return "absent";
          };
        })(globalThis.__ibex2_test_timer_dispatch);
        "#,
    );
    rt.harden().expect("harden");
    assert_eq!(
        eval(&mut rt, "globalThis.__timerDispatcherAbsent()"),
        "absent"
    );

    eval(
        &mut rt,
        "globalThis.__timerFired = false; setTimeout(function () { __timerFired = true; }, 0);",
    );
    for _ in 0..100 {
        rt.pump().expect("owning timer pump");
        if eval(&mut rt, "String(globalThis.__timerFired)") == "true" {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    panic!("the owning pump did not fire setTimeout after hardening");
}

#[test]
fn forged_headers_receivers_cannot_reach_native_handle_rows_after_harden() {
    let mut rt = hardened();
    assert_eq!(
        eval(
            &mut rt,
            r#"(function () {
              var victim = new Headers({secret: "value"});
              var touched = 0;
              var fake = {};
              Object.defineProperty(fake, "_handle", {
                get: function () { touched++; return victim._handle; }
              });
              function kind(method, receiver, args) {
                try { Reflect.apply(method, receiver, args); return "none"; }
                catch (error) { return error.constructor.name; }
              }
              var get = kind(Headers.prototype.get, fake, ["secret"]);
              var iterator = victim.entries();
              var next = Object.getPrototypeOf(iterator).next;
              var iterate = kind(next, {
                _headers: victim, _index: 0,
                _pick: function (name, value) { return [name, value]; }
              }, []);
              return get + "|" + iterate + "|" + victim.get("secret") + "|" + touched;
            })()"#
        ),
        "TypeError|TypeError|value|0"
    );
}

#[test]
fn abort_timeout_does_not_adopt_an_application_global_after_harden() {
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    let context = ibex2::bindings::Context::new(ibex2::grant::GrantSet::none());
    rt.install_runtime(
        ibex2::bindings::Groups::PURE | ibex2::bindings::Groups::ABORT,
        &context,
    )
    .expect("bindings without TIMERS");
    rt.harden().expect("harden");
    assert_eq!(
        eval(
            &mut rt,
            r#"(function () {
              var called = false;
              globalThis.setTimeout = function () { called = true; };
              try { AbortSignal.timeout(0); return "accepted"; }
              catch (error) { return error.name + "|" + called; }
            })()"#
        ),
        "NotSupportedError|false"
    );
}

/// The freeze has a budget in rules/RULES.md, and this is where the build
/// refuses to exceed it. The MINIMUM of 20 fresh runtimes, not the median:
/// `cargo test` runs this beside every other test binary on the machine, a
/// median under that load measured the load (2.15 ms against a 0.7 ms
/// freeze), and LLP 0063 §2 says to take the minimum for exactly this
/// reason — it is the cost with the least of everything else in it.
#[test]
fn the_freeze_stays_within_its_budget() {
    let rules =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules/RULES.md"))
            .expect("rules/RULES.md");
    let budget_ms: f64 = rules
        .lines()
        .find(|line| line.contains("Intrinsic freeze"))
        .and_then(|line| line.rsplit('|').nth(1))
        .and_then(|cell| {
            cell.trim()
                .trim_matches('*')
                .trim_end_matches("ms")
                .trim()
                .parse()
                .ok()
        })
        .expect("a parseable `Intrinsic freeze | <n>ms` row in rules/RULES.md");
    let mut samples: Vec<f64> = (0..20)
        .map(|_| {
            let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
            install_runtime(&mut rt);
            let t = std::time::Instant::now();
            rt.harden().expect("harden");
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let best = samples[0];
    assert!(
        best <= budget_ms,
        "the freeze took {best:.2} ms at best over 20 runs, against the {budget_ms} ms budget in rules/RULES.md"
    );
}

/// LLP 0067 R5, mechanically: after the standard library, the bindings, and
/// the freeze, the global object carries the engine's own names plus exactly
/// `ALLOWED_GLOBALS` — nothing more. This is the assertion `ibex2 run` makes
/// before any module runs, and it is what turns R1 from a property of a list
/// into a property of the runtime. A helper the bindings forgot to remove, or
/// an accessor over a handle table, fails it by name.
#[test]
fn the_global_object_carries_exactly_the_allowed_names() {
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    let baseline: std::collections::BTreeSet<String> = rt.global_names().into_iter().collect();
    install_runtime(&mut rt);
    rt.harden().expect("harden");
    let added: std::collections::BTreeSet<String> = rt
        .global_names()
        .into_iter()
        .filter(|name| !baseline.contains(name))
        .collect();
    // The set to match is what the list allows beyond what the engine already
    // had (anything the engine provides natively is in the baseline).
    let allowed: std::collections::BTreeSet<String> = ibex2_runtime::loader::allowed_globals(
        rt.installed_groups().expect("groups were installed"),
    )
    .into_iter()
    .map(|s| s.to_string())
    .filter(|name| !baseline.contains(name))
    .collect();
    // L1e is opt-in: neither its conventional handoff name nor any member of
    // the handoff object may appear as a new default global. The exact-set
    // comparison below also catches an implementation choosing another name.
    for primitive in [
        "__snapback_ibex2_fetch_primitives",
        "responseField",
        "responseRead",
        "fetchControl",
        "textEncode",
        "textDecode",
        "textEncodeInto",
        "headersFree",
    ] {
        assert!(
            !added.contains(primitive),
            "default install leaked {primitive}"
        );
    }
    assert_eq!(
        added, allowed,
        "left: on the global object; right: ALLOWED_GLOBALS minus the engine's own"
    );
}

/// Grok 4.6's finding 5: the walk went by name, so functions reachable only
/// through a symbol key — `Date.prototype[Symbol.toPrimitive]`, the RegExp
/// `Symbol.split` family — were never frozen. R4 says every object reachable
/// from the global bindings; this walks the whole graph, names and symbols,
/// and reports anything still open.
#[test]
fn every_object_reachable_from_the_global_bindings_is_frozen() {
    let mut rt = hardened();
    assert_eq!(
        eval(&mut rt, "String(Object.isFrozen(Date.prototype[Symbol.toPrimitive]) && Object.isFrozen(RegExp.prototype[Symbol.split]))"),
        "true"
    );
    assert_eq!(
        eval(
            &mut rt,
            "(function () { 'use strict'; const f = Date.prototype[Symbol.toPrimitive]; \
             try { f.pwn = 1; return 'took'; } catch (e) { return e.constructor.name; } })()"
        ),
        "TypeError"
    );
    let open = eval(
        &mut rt,
        "(function () {
           const seen = new Set([globalThis]);
           const queue = [];
           const push = (path, obj) => { if (obj !== null && (typeof obj === 'object' || typeof obj === 'function') && !seen.has(obj)) { seen.add(obj); queue.push([path, obj]); } };
           const expand = (path, obj) => {
             const keys = Object.getOwnPropertyNames(obj).concat(Object.getOwnPropertySymbols(obj));
             for (let i = 0; i < keys.length; i++) {
               const key = keys[i];
               let d; try { d = Object.getOwnPropertyDescriptor(obj, key); } catch (e) { continue; }
               if (!d) continue;
               const name = path + '.' + String(key);
               if ('value' in d) push(name, d.value); else { push(name + '#get', d.get); push(name + '#set', d.set); }
             }
             try { push(path + '.__proto__', Object.getPrototypeOf(obj)); } catch (e) {}
           };
           expand('globalThis', globalThis);
           const open = [];
           while (queue.length) {
             const entry = queue.pop();
             if (!Object.isFrozen(entry[1])) open.push(entry[0]);
             expand(entry[0], entry[1]);
           }
           return open.sort().join(', ');
         })()",
    );
    assert_eq!(open, "", "reachable and not frozen: {open}");
}

#[test]
fn the_freeze_needs_only_object_and_classifies_own_value_fields() {
    // An embedder may delete Function, Reflect, and other globals before
    // hardening, as Snapback 2 effects do. The freeze then still runs, and an
    // accessor hidden behind an inherited `value` field is still frozen.
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    install_runtime(&mut rt);
    eval(
        &mut rt,
        r#"globalThis.__getter = function () { return 1; };
           Object.defineProperty(globalThis, "hidden", { get: globalThis.__getter, configurable: true });
           Object.defineProperty(Object.prototype, "value", { value: 0, configurable: true });
           delete globalThis.Function;
           delete globalThis.Reflect;
           "ok""#,
    );
    rt.harden().expect("harden without Function or Reflect");
    assert_eq!(
        eval(&mut rt, "String(Object.isFrozen(globalThis.__getter))"),
        "true"
    );
}
