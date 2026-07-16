// Exact loaded-engine executor for inherited intrinsic alias membership.
// The JavaScript plan is authored and content-addressed by the devtools
// source-review module. This executor binds it to the compiled target and the
// mapped Hermes factory object's current file snapshot before and after
// evaluating it. This is not a hash of already-mapped executable pages.
//
// @ref LLP 0013#mechanism-1-lockdown
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Digest as _;
use std::fmt::Write as _;
use std::io::Write as _;

const PLAN_SCHEMA: &str = "ibex/capsec-inherited-intrinsic-alias-execution-plan/1";
const OBSERVATION_SCHEMA: &str = "ibex/capsec-inherited-intrinsic-alias-observation/1";
const PREFLIGHT_SCHEMA: &str = "ibex/capsec-inherited-intrinsic-alias-loaded-engine-preflight/1";
const EVIDENCE_SCHEMA: &str = "ibex/capsec-inherited-intrinsic-alias-loaded-execution/1";
const PLAN_DIGEST_DOMAIN: &str = "ibex.capsec.inherited-intrinsic-alias.execution-plan.v1";
const EXECUTOR_CONTRACT_SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bin/ibex/engine/capsec_inherited_intrinsic_alias_batch.test.rs"
));

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetBinding {
    triple: String,
    features: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProbeBinding {
    schema: String,
    source: String,
    source_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutionPlan {
    schema: String,
    profile_id: String,
    target_variant: String,
    target: TargetBinding,
    executor_contract_digest: String,
    reviewed_profile_identity: Value,
    source_review_digest: String,
    profile_review_digest: String,
    probe: ProbeBinding,
    plan_digest: String,
}

fn runtime_target_triple() -> String {
    let triple = match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => "aarch64-apple-darwin",
        ("x86_64", "macos") => "x86_64-apple-darwin",
        ("aarch64", "android") => "aarch64-linux-android",
        ("arm", "android") => "armv7-linux-androideabi",
        ("x86", "android") => "i686-linux-android",
        ("x86_64", "android") => "x86_64-linux-android",
        ("aarch64", "linux") if cfg!(target_env = "musl") => "aarch64-unknown-linux-musl",
        ("aarch64", "linux") if cfg!(target_env = "gnu") => "aarch64-unknown-linux-gnu",
        ("x86_64", "linux") if cfg!(target_env = "musl") => "x86_64-unknown-linux-musl",
        ("x86_64", "linux") if cfg!(target_env = "gnu") => "x86_64-unknown-linux-gnu",
        ("aarch64", "windows") if cfg!(target_env = "msvc") => {
            "aarch64-pc-windows-msvc"
        }
        ("x86_64", "windows") if cfg!(target_env = "msvc") => {
            "x86_64-pc-windows-msvc"
        }
        ("x86_64", "windows") if cfg!(target_env = "gnu") => "x86_64-pc-windows-gnu",
        (architecture, operating_system) => panic!(
            "no exact inherited-intrinsic target triple mapping for {architecture}-{operating_system}"
        ),
    };
    triple.to_owned()
}

fn runtime_profile() -> (&'static str, &'static str) {
    match std::env::consts::OS {
        "android" => ("android-maven", "android"),
        "windows" => ("windows-nuget", "windows"),
        _ => ("source-patched", "default"),
    }
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    let digest = sha2::Sha256::digest(bytes.as_ref());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("write digest to String");
    }
    format!("sha256-{encoded}")
}

fn tagged_jcs_hex_digest(domain: &str, value: &Value) -> String {
    let canonical = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("intrinsic alias plan must have canonical JSON bytes");
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len() + 1);
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    sha256_hex(bytes)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256-")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_sorted_set(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn write_new_json(path: impl AsRef<std::path::Path>, value: &Value, label: &str) {
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| panic!("create owned {label}: {error}"));
    serde_json::to_writer_pretty(&mut output, value)
        .unwrap_or_else(|error| panic!("serialize {label}: {error}"));
    output
        .write_all(b"\n")
        .unwrap_or_else(|error| panic!("finish {label}: {error}"));
    output
        .sync_all()
        .unwrap_or_else(|error| panic!("sync {label}: {error}"));
}

fn load_plan(path: &str) -> ExecutionPlan {
    let text = std::fs::read_to_string(path).expect("read intrinsic alias execution plan");
    let mut value = capsec_semantics::strict_json::parse_strict(&text)
        .expect("intrinsic alias execution plan must be strict JSON");
    let unsigned = value
        .as_object_mut()
        .expect("intrinsic alias execution plan must be an object")
        .remove("planDigest")
        .expect("intrinsic alias execution plan has no digest");
    let claimed_digest = unsigned
        .as_str()
        .expect("intrinsic alias execution plan digest must be a string")
        .to_owned();
    let computed_digest = tagged_jcs_hex_digest(PLAN_DIGEST_DOMAIN, &value);
    assert_eq!(
        claimed_digest, computed_digest,
        "execution plan digest drifted"
    );
    value["planDigest"] = Value::String(claimed_digest);
    let plan: ExecutionPlan = serde_json::from_value(value)
        .expect("intrinsic alias execution plan has malformed exact fields");

    let (profile_id, target_variant) = runtime_profile();
    assert_eq!(plan.schema, PLAN_SCHEMA);
    assert_eq!(plan.profile_id, profile_id, "plan/profile target mismatch");
    assert_eq!(
        plan.target_variant, target_variant,
        "plan target variant does not describe this binary"
    );
    assert_eq!(
        plan.target.triple,
        runtime_target_triple(),
        "plan target triple does not describe this binary"
    );
    assert!(is_sorted_set(&plan.target.features));
    assert_eq!(
        plan.executor_contract_digest,
        sha256_hex(EXECUTOR_CONTRACT_SOURCE.as_bytes()),
        "plan does not bind this exact loaded-engine executor"
    );
    assert!(plan.reviewed_profile_identity.is_object());
    assert!(is_sha256_hex(&plan.source_review_digest));
    assert!(is_sha256_hex(&plan.profile_review_digest));
    assert_eq!(plan.probe.schema, OBSERVATION_SCHEMA);
    assert!(is_sha256_hex(&plan.probe.source_digest));
    assert_eq!(
        sha256_hex(plan.probe.source.as_bytes()),
        plan.probe.source_digest,
        "probe source digest drifted"
    );
    assert!(is_sha256_hex(&plan.plan_digest));
    plan
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_inherited_intrinsic_alias_loaded_engine_preflight() {
    let Ok(output_path) = std::env::var("IBEX_CAPSEC_INTRINSIC_ALIAS_PREFLIGHT_OUTPUT") else {
        return;
    };
    let _lock = hermes_engine_test_lock().lock().await;
    let identity = HermesEngine::loaded_engine_identity()
        .expect("identify mapped Hermes factory object for intrinsic preflight");
    let verified = ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity)
        .expect("recheck Hermes factory-object file snapshot for intrinsic preflight");
    assert_eq!(verified, identity);
    let (profile_id, target_variant) = runtime_profile();
    let provenance = ibex_runtime::engine::loaded_engine_profile_provenance()
        .expect("compare Hermes factory-object file snapshot with its embedded receipt")
        .expect("loaded intrinsic conformance requires a profile provenance receipt");
    assert_eq!(provenance["profileId"], profile_id);
    assert_eq!(provenance["targetVariant"], target_variant);
    write_new_json(
        output_path,
        &json!({
            "schema": PREFLIGHT_SCHEMA,
            "profileId": profile_id,
            "targetVariant": target_variant,
            "target": {
                "triple": runtime_target_triple(),
                "features": identity.structural_features.clone(),
            },
            "loadedEngineIdentity": identity,
            "loadedEngineProfileProvenance": provenance,
        }),
        "inherited intrinsic preflight",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_inherited_intrinsic_alias_loaded_execution() {
    let Ok(plan_path) = std::env::var("IBEX_CAPSEC_INTRINSIC_ALIAS_PLAN") else {
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_INTRINSIC_ALIAS_EVIDENCE_OUTPUT")
        .expect("intrinsic alias execution requires an owned evidence output path");
    let plan = load_plan(&plan_path);

    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("identify Hermes factory-object file snapshot before intrinsic probe");
    let provenance_before = ibex_runtime::engine::loaded_engine_profile_provenance()
        .expect("check Hermes file snapshot/profile receipt before intrinsic probe")
        .expect("loaded intrinsic conformance requires a profile provenance receipt");
    assert_eq!(provenance_before["profileId"], plan.profile_id);
    assert_eq!(provenance_before["targetVariant"], plan.target_variant);
    assert_eq!(
        provenance_before["origin"]["reviewedProfileIdentity"], plan.reviewed_profile_identity,
        "embedded Hermes receipt does not bind the reviewed execution profile"
    );
    assert_eq!(
        plan.target.features, identity_before.structural_features,
        "plan structural features do not describe the loaded engine"
    );

    let engine = HermesEngine::new().expect("create inherited intrinsic probe engine");
    engine
        .load_runtime()
        .await
        .expect("load the exact runtime before inherited intrinsic probe");
    let script = format!("JSON.stringify({})", plan.probe.source);
    let encoded = engine
        .eval_immediate(&script)
        .await
        .expect("execute inherited intrinsic probe in loaded Hermes")
        .expect("loaded inherited intrinsic probe returned no value");
    let observation: Value = serde_json::from_str(&encoded)
        .expect("loaded inherited intrinsic probe returned invalid JSON");
    assert_eq!(observation["schema"], OBSERVATION_SCHEMA);
    assert_eq!(observation["profileId"], plan.profile_id);
    assert_eq!(observation["targetVariant"], plan.target_variant);
    assert_eq!(observation["targetTriple"], plan.target.triple);
    assert_eq!(
        observation["structuralFeatures"],
        json!(&plan.target.features)
    );

    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("identify Hermes factory-object file snapshot after intrinsic probe");
    assert_eq!(
        identity_after, identity_before,
        "mapped Hermes identity changed during inherited intrinsic probe"
    );
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("recheck Hermes factory-object file snapshot after intrinsic probe");
    let provenance_after = ibex_runtime::engine::loaded_engine_profile_provenance()
        .expect("recheck Hermes file snapshot/profile receipt after intrinsic probe")
        .expect("loaded intrinsic conformance requires a profile provenance receipt");
    assert_eq!(
        provenance_after, provenance_before,
        "mapped Hermes provenance changed during inherited intrinsic probe"
    );

    write_new_json(
        output_path,
        &json!({
            "schema": EVIDENCE_SCHEMA,
            "executorContractDigest": plan.executor_contract_digest,
            "planDigest": plan.plan_digest,
            "profileId": plan.profile_id,
            "targetVariant": plan.target_variant,
            "target": {
                "triple": plan.target.triple,
                "features": plan.target.features,
            },
            "probeSourceDigest": plan.probe.source_digest,
            "observation": observation,
            "loadedEngineIdentity": identity_before,
            "loadedEngineProfileProvenance": provenance_before,
        }),
        "inherited intrinsic loaded execution evidence",
    );
}
