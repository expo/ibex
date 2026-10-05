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
