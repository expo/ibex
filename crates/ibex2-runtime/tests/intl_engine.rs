//! The engine surface that remains when Ibex's optional INTL install group is
//! omitted. Linux's non-lite Hermes profile exposes no `Intl` object but uses
//! trimmed root+en ICU data for correct basic Unicode operations; Apple's
//! profile delegates to the operating system.
#![cfg(any(target_os = "linux", target_vendor = "apple"))]

use ibex2::bindings::{Context, Groups};
use ibex2::grant::GrantSet;
use ibex2_runtime::engine::hermes::{DynamicCode, Hermes};

#[test]
fn engine_intl_surface_without_ibex_intl_group() {
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    let context = Context::new(GrantSet::none());
    runtime
        .install_runtime(Groups::DEFAULT.without(Groups::INTL), &context)
        .expect("bindings without INTL");

    let observed = runtime
        .eval("[typeof Intl, (1234.5).toLocaleString('de-DE')].join('|')")
        .expect("inspect engine Intl");

    #[cfg(target_os = "linux")]
    {
        assert_eq!(observed, "undefined|1234.5");
        assert_eq!(
            runtime
                .eval(
                    r#"[
                      "é".toUpperCase() === "É",
                      "ß".toUpperCase() === "SS",
                      "é".normalize("NFC") === "é",
                      ["b", "a", "á"].sort(function (x, y) { return x.localeCompare(y); }).join(","),
                      new Date(0).toLocaleString().replace(/\u202f/g, " "),
                      typeof Intl
                    ].join("|")"#,
                )
                .expect("exercise the trimmed ICU basic-JavaScript profile"),
            "true|true|true|a,á,b|Jan 1, 1970, 12:00:00 AM|undefined"
        );
    }
    #[cfg(target_vendor = "apple")]
    assert_eq!(observed, "object|1.234,5");
}

#[cfg(all(target_os = "linux", feature = "intl"))]
#[test]
fn opted_in_linux_group_supplies_intl_and_locale_methods() {
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    let context = Context::new(GrantSet::none());
    runtime
        .install_runtime(Groups::DEFAULT, &context)
        .expect("bindings with INTL");

    assert_eq!(
        runtime
            .eval("[typeof Intl, (1234.5).toLocaleString('de-DE')].join('|')")
            .expect("inspect opted-in Intl"),
        "object|1.234,5"
    );
    assert_eq!(
        runtime
            .eval("JSON.stringify(Intl.getCanonicalLocales(['EN-us', 'en-US']))")
            .expect("inspect locale canonicalization"),
        r#"["en-US"]"#
    );
}
