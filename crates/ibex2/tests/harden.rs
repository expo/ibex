//! LLP 0062 §3/R4: the intrinsic freeze, exercised from the same file the
//! binary runs (`intrinsic_harden.rs` measures a copy; this pins behaviour).
#![cfg(feature = "hermes")]

use ibex2::engine::hermes::{DynamicCode, Hermes};

const HARDEN: &str = include_str!("../src/bindings/harden.js");

fn hardened() -> Hermes {
    let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
    assert!(rt.install_stdlib());
    rt.install_bindings().expect("bindings");
    rt.eval(HARDEN).expect("harden");
    rt
}

fn eval(rt: &mut Hermes, program: &str) -> String {
    rt.eval(program).unwrap_or_else(|e| panic!("{program}: {}", e.0))
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
    assert_eq!(eval(&mut rt, "String(Object.isExtensible(globalThis))"), "true");
    assert_eq!(
        eval(
            &mut rt,
            "(function () { 'use strict'; globalThis.__appState ??= { n: 1 }; \
             globalThis.__appState.n += 1; return String(globalThis.__appState.n); })()"
        ),
        "2"
    );
    // Exact's own bootstrap shape.
    assert_eq!(
        eval(
            &mut rt,
            "(function () { const r = globalThis; r.global = r; r.self = r; r.window = r; \
             r.navigator ??= { product: 'x' }; \
             return String(r.window === globalThis) + r.navigator.product; })()"
        ),
        "truex"
    );
}
