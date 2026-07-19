// GENERATED FILE - DO NOT EDIT.
// Source authority: runtime-identity.json (LLP 0012)
// Generator: bun packages/ibex-devtools/src/scripts/generate-runtime-identity.ts

/// Runtime identity constants (LLP 0012).
pub const RUNTIME_NAME: &str = "ibex";
pub const PROCESS_TITLE: &str = "ibex";
pub const USER_AGENT: &str = "Ibex/0.1.0 (Hermes)";
pub const RELEASE_NAME: &str = "node";
pub const NODE_VERSION: &str = "24.13.1";
pub const IBEX_VERSION: &str = "0.1.0";
pub const BUN_COMPAT_VERSION: &str = "1.2.0";
/// The full versions table as a JS object literal, for host bootstrap
/// snippets that seed process.versions before the runtime bundle loads.
pub const VERSIONS_JS_OBJECT: &str = "{ ibex: '0.1.0', node: '24.13.1', hermes: '1.0.0' }";
pub const RUNTIME_IDENTITY_SCHEMA: &str = "ibex/runtime-identity/1";
pub const RUNTIME_IDENTITY_DOMAIN: &str = "ibex:runtime-identity:1";
pub const RUNTIME_IDENTITY_DIGEST: &str = "sha256-dmZB5Er2GWaTKtPV648dAVePxidOkP5bPvXDVnUabKs";

#[cfg(test)]
mod tests {
    #[test]
    fn generated_runtime_identity_digest_matches_projection() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vendored-generated/runtime-identity-projection.canonical.json"
        ));
        let text = std::str::from_utf8(bytes).unwrap();
        let value = capsec_semantics::strict_json::parse_strict(text).unwrap();
        assert_eq!(
            capsec_semantics::canonical::to_jcs_bytes(&value).unwrap(),
            bytes
        );
        assert_eq!(value["schema"], super::RUNTIME_IDENTITY_SCHEMA);
        assert_eq!(
            capsec_semantics::digest::compute_domain_digest(
                super::RUNTIME_IDENTITY_DOMAIN,
                &value,
                &[],
            )
            .unwrap(),
            super::RUNTIME_IDENTITY_DIGEST,
        );
    }
}
