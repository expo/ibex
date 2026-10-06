//! The engine surface that remains when Ibex's optional INTL install group is
//! omitted. Linux's non-lite Hermes profile exposes no `Intl` object but uses
//! base ICU data for correct basic Unicode operations; Apple's
//! profile delegates to the operating system.
#![cfg(any(target_os = "linux", windows, target_vendor = "apple"))]

use ibex2::bindings::{Context, Groups};
use ibex2::grant::GrantSet;
use ibex2_runtime::engine::hermes::{DynamicCode, Hermes};
use std::sync::Once;

/// Whether the linked ICU carries every locale: Linux's `intl-all-locales` data
/// tier, or Windows, whose OS ICU always does. Linux's default English tier
/// reports and falls back to English only.
#[cfg(any(target_os = "linux", windows))]
const ALL_LOCALES: bool = cfg!(any(feature = "intl-all-locales", windows));

fn set_stable_process_defaults() {
    static DEFAULTS: Once = Once::new();
    DEFAULTS.call_once(|| {
        std::env::set_var("TZ", "UTC");
        std::env::set_var("LC_ALL", "C");
        std::env::set_var("LANG", "C");
    });
}

#[test]
fn engine_intl_surface_without_ibex_intl_group() {
    set_stable_process_defaults();
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
        let basic_unicode = runtime
            .eval(
                r#"[
                      "é".toUpperCase() === "É",
                      "ß".toUpperCase() === "SS",
                      "é".normalize("NFC") === "é",
                      ["b", "a", "á"].sort(function (x, y) { return x.localeCompare(y); }).join(","),
                      (() => {
                        try { return new Date(0).toLocaleString().replace(/\u202f/g, " "); }
                        catch (error) { return String(error); }
                      })(),
                      typeof Intl
                    ].join("|")"#,
            )
            .expect("exercise the trimmed ICU basic-JavaScript profile");
        assert!(
            !basic_unicode.contains("dateFormat not implemented"),
            "trimmed ICU must supply the engine's basic Date formatting: {basic_unicode}"
        );
        assert_eq!(
            basic_unicode,
            "true|true|true|a,á,b|Jan 1, 1970, 12:00:00 AM|undefined"
        );
    }
    #[cfg(target_vendor = "apple")]
    assert_eq!(observed, "object|1.234,5");
    // Windows Hermes is built without Intl; its basic Unicode backend uses
    // the OS ICU (HERMES_ENABLE_WIN10_ICU_FALLBACK), not Ibex's shims.
    #[cfg(windows)]
    {
        assert_eq!(observed, "undefined|1234.5");
        assert_eq!(
            runtime
                .eval(r#"["é".toUpperCase() === "É", "ß".toUpperCase()].join("|")"#)
                .expect("exercise the engine's OS-ICU basic Unicode"),
            "true|SS"
        );
    }
}

#[cfg(all(any(target_os = "linux", windows), feature = "intl"))]
#[test]
fn opted_in_linux_group_supplies_intl_and_locale_methods() {
    set_stable_process_defaults();
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    let context = Context::new(GrantSet::none());
    runtime
        .install_runtime(Groups::DEFAULT, &context)
        .expect("bindings with INTL");

    let expected = if ALL_LOCALES {
        "object|1.234,5"
    } else {
        "object|1,234.5"
    };
    assert_eq!(
        runtime
            .eval("[typeof Intl, (1234.5).toLocaleString('de-DE')].join('|')")
            .expect("inspect opted-in Intl"),
        expected
    );
    assert_eq!(
        runtime
            .eval("JSON.stringify(Intl.getCanonicalLocales(['EN-us', 'en-US']))")
            .expect("inspect locale canonicalization"),
        r#"["en-US"]"#
    );
}

#[cfg(all(target_os = "linux", feature = "intl"))]
#[test]
fn selected_intl_reports_only_available_locale_data() {
    set_stable_process_defaults();
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    let context = Context::new(GrantSet::none());
    runtime
        .install_runtime(Groups::DEFAULT, &context)
        .expect("bindings with selected INTL data");

    let expected = if ALL_LOCALES {
        r#"{"numberSupported":["en-US","de-DE"],"dateSupported":["en-US","de-DE"],"numberLocale":"de-DE","dateLocale":"de-DE","number":"1.234,5"}"#
    } else {
        r#"{"numberSupported":["en-US"],"dateSupported":["en-US"],"numberLocale":"en-US","dateLocale":"en-US","number":"1,234.5"}"#
    };
    assert_eq!(
        runtime
            .eval(
                r#"JSON.stringify({
                  numberSupported: Intl.NumberFormat.supportedLocalesOf(["en-US", "de-DE"]),
                  dateSupported: Intl.DateTimeFormat.supportedLocalesOf(["en-US", "de-DE"]),
                  numberLocale: new Intl.NumberFormat("de-DE").resolvedOptions().locale,
                  dateLocale: new Intl.DateTimeFormat("de-DE", {
                    timeZone:"UTC", year:"numeric"
                  }).resolvedOptions().locale,
                  number: new Intl.NumberFormat("de-DE").format(1234.5)
                })"#,
            )
            .expect("inspect selected locale negotiation"),
        expected
    );
}

#[cfg(all(target_os = "linux", feature = "intl-all-locales"))]
#[test]
fn all_locales_formats_german_with_german_separators() {
    set_stable_process_defaults();
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    let context = Context::new(GrantSet::none());
    runtime
        .install_runtime(Groups::DEFAULT, &context)
        .expect("bindings with all-locale INTL");

    assert_eq!(
        runtime
            .eval("new Intl.NumberFormat('de-DE').format(1234.5)")
            .expect("format German number"),
        "1.234,5"
    );
}
