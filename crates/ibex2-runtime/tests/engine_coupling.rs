//! Structural witnesses for LLP 0057.000 R-e: binding bytecode and the owning
//! runtime use one archive identity even under resolver-v2 feature contexts.

use ibex2::bindings::{Context, Groups};
use ibex2::grant::GrantSet;
use ibex2_runtime::engine::hermes::{DynamicCode, Hermes};
use sha2::{Digest, Sha256};

#[test]
fn bindings_sys_and_linked_archive_have_one_digest() {
    assert_eq!(
        ibex2::bindings::ENGINE_DIGEST,
        hermes_lean_sys::ENGINE_DIGEST
    );
    assert_eq!(
        ibex2_runtime::LINKED_ENGINE_DIGEST,
        hermes_lean_sys::LINKED_ENGINE_DIGEST.expect("runtime links one Hermes VM")
    );
    assert_eq!(
        ibex2_runtime::LINKED_ENGINE_ARCHIVE,
        hermes_lean_sys::LINKED_ARCHIVE.expect("runtime links one Hermes VM")
    );

    let archive = std::fs::read(ibex2_runtime::LINKED_ENGINE_ARCHIVE)
        .expect("read the archive linked into ibex2-runtime");
    let actual = format!("sha256-{:x}", Sha256::digest(archive));
    assert_eq!(actual, ibex2_runtime::LINKED_ENGINE_DIGEST);

    if cfg!(target_os = "linux") {
        assert_eq!(
            ibex2::bindings::ICU_DATA_ARCHIVE,
            hermes_lean_sys::ICU_DATA_ARCHIVE,
            "bindings export the available base data without selecting it"
        );
        assert_eq!(
            ibex2::bindings::ICU_DATA_DIGEST,
            hermes_lean_sys::ICU_DATA_DIGEST
        );
        assert_eq!(
            ibex2::bindings::ICU_EN_DATA_ARCHIVE,
            hermes_lean_sys::ICU_EN_DATA_ARCHIVE,
            "bindings export the available English data without selecting it"
        );
        assert_eq!(
            ibex2::bindings::ICU_EN_DATA_DIGEST,
            hermes_lean_sys::ICU_EN_DATA_DIGEST
        );
        assert_eq!(
            ibex2::bindings::ICU_FULL_DATA_ARCHIVE,
            hermes_lean_sys::ICU_FULL_DATA_ARCHIVE,
            "bindings export the available full data without selecting it"
        );
        assert_eq!(
            ibex2::bindings::ICU_FULL_DATA_DIGEST,
            hermes_lean_sys::ICU_FULL_DATA_DIGEST
        );
        let linked_archive = ibex2_runtime::LINKED_ICU_DATA_ARCHIVE
            .expect("Linux runtime links one ICU data variant");
        let linked_digest = ibex2_runtime::LINKED_ICU_DATA_DIGEST
            .expect("Linux runtime exports its ICU data identity");
        assert_eq!(
            hermes_lean_sys::LINKED_ICU_DATA_ARCHIVE,
            Some(linked_archive)
        );
        assert_eq!(hermes_lean_sys::LINKED_ICU_DATA_DIGEST, Some(linked_digest));
        let expected_archive = if cfg!(feature = "intl-all-locales") {
            hermes_lean_sys::ICU_FULL_DATA_ARCHIVE
        } else if cfg!(feature = "intl") {
            hermes_lean_sys::ICU_EN_DATA_ARCHIVE
        } else {
            hermes_lean_sys::ICU_DATA_ARCHIVE
        };
        let expected_digest = if cfg!(feature = "intl-all-locales") {
            hermes_lean_sys::ICU_FULL_DATA_DIGEST
        } else if cfg!(feature = "intl") {
            hermes_lean_sys::ICU_EN_DATA_DIGEST
        } else {
            hermes_lean_sys::ICU_DATA_DIGEST
        };
        assert_eq!(Some(linked_archive), expected_archive);
        assert_eq!(Some(linked_digest), expected_digest);
        let data = std::fs::read(linked_archive).expect("read linked ICU data archive");
        assert_eq!(format!("sha256-{:x}", Sha256::digest(data)), linked_digest);
    } else {
        assert_eq!(ibex2::bindings::ICU_DATA_ARCHIVE, None);
        assert_eq!(ibex2::bindings::ICU_EN_DATA_ARCHIVE, None);
        assert_eq!(ibex2::bindings::ICU_FULL_DATA_ARCHIVE, None);
        assert_eq!(ibex2_runtime::LINKED_ICU_DATA_ARCHIVE, None);
        assert_eq!(hermes_lean_sys::LINKED_ICU_DATA_ARCHIVE, None);
    }
}

#[test]
fn exported_compiled_scripts_install_in_the_linked_runtime() {
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("linked Hermes runtime");
    let context = Context::new(GrantSet::none());
    runtime
        .install(Groups::PURE, &context)
        .expect("install ibex2::bindings::compiled_scripts bytes");
    runtime.harden().expect("harden exported by the same door");
    assert_eq!(
        runtime
            .eval("new URL('/b', 'https://example.com/a').href")
            .expect("evaluate through installed PURE bindings"),
        "https://example.com/b"
    );
}
