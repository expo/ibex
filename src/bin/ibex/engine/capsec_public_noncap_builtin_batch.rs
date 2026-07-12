use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write as _;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecipeCatalog {
    recipe_catalog_schema: String,
    recipe_catalog_digest: String,
    recipes: Vec<Recipe>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recipe {
    fixture_id: String,
    plan_digest: String,
    classification: String,
    scenario: String,
    action_ids: Vec<String>,
    expected_observation: serde_json::Value,
    route: PublicRoute,
    status: String,
    public_surface_probe: Option<PublicSurfaceProbe>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicRoute {
    alternatives: Vec<RouteAlternative>,
    ambiguous_callees: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteAlternative {
    terminal_observed_key: String,
    proof_paths: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicSurfaceProbe {
    kind: String,
    surface_observed_key: String,
    command: Vec<String>,
    invocation: BuiltinInvocation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BuiltinInvocation {
    invocation_schema: String,
    kind: String,
    module_specifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    export_name: Option<String>,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    template_id: Option<String>,
    arguments: Vec<serde_json::Value>,
    setup: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    body_entry_proof: Option<BodyEntryProof>,
    required_authority: Vec<serde_json::Value>,
    expected_result: String,
    expected_typed_decision_count: usize,
    expected_typed_stages: Vec<String>,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BodyEntryProof {
    kind: String,
    result_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BuiltinSourceDescriptor {
    kind: String,
    source_key: String,
    export_name: String,
    export_idioms: Vec<String>,
    module_specifiers: Vec<String>,
    source_ref: String,
    value_shape: String,
    #[serde(default)]
    platform_availability: Option<Vec<String>>,
    access: BuiltinAccess,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BuiltinModuleAliasDescriptor {
    kind: String,
    source_key: String,
    module_specifier: String,
    source_ref: String,
    resolution_kind: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct BuiltinAccess {
    kind: String,
    path: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicBatchArtifact {
    public_batch_evidence_schema: &'static str,
    recipe_catalog_digest: String,
    loaded_engine_identity: ibex_runtime::engine::LoadedEngineBinaryIdentity,
    executions: Vec<serde_json::Value>,
}

fn tagged_jcs_digest(value: &serde_json::Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("public recipe evidence must have a canonical JSON encoding");
    let digest = sha2::Sha256::digest(bytes);
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

fn load_catalog(path: &std::path::Path) -> RecipeCatalog {
    let bytes = std::fs::read(path).expect("read CapSec executable recipe catalog");
    let text = std::str::from_utf8(&bytes).expect("recipe catalog must be UTF-8");
    let value = capsec_semantics::strict_json::parse_strict(text)
        .expect("recipe catalog must be strict JSON");
    let expected_digest = value["recipeCatalogDigest"]
        .as_str()
        .expect("recipe catalog has no digest");
    let mut projected = value.clone();
    projected
        .as_object_mut()
        .expect("recipe catalog must be an object")
        .remove("recipeCatalogDigest");
    assert_eq!(
        tagged_jcs_digest(&projected),
        expected_digest,
        "recipe catalog digest mismatch"
    );
    let catalog: RecipeCatalog =
        serde_json::from_value(value).expect("recipe catalog shape must be valid");
    assert_eq!(
        catalog.recipe_catalog_schema,
        "ibex/capsec-executable-recipes/1"
    );
    assert!(
        catalog
            .recipes
            .windows(2)
            .all(|pair| pair[0].fixture_id < pair[1].fixture_id),
        "recipe fixtures must be a strictly sorted set"
    );
    catalog
}

fn is_sorted_set(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn module_specifier_rank(value: &str) -> u8 {
    if value.starts_with("node:") {
        0
    } else if value.starts_with("exact:") {
        1
    } else if value.starts_with("bun:") {
        2
    } else if value.starts_with("internal/") {
        3
    } else {
        4
    }
}

fn canonical_module_specifier(values: &[String]) -> Option<&str> {
    values
        .iter()
        .min_by_key(|value| (module_specifier_rank(value), value.as_str()))
        .map(String::as_str)
}

fn expected_access(descriptor: &BuiltinSourceDescriptor) -> Option<BuiltinAccess> {
    if descriptor.export_name.contains("[[") || descriptor.export_name.contains("]]") {
        return None;
    }
    let segments = descriptor
        .export_name
        .split('.')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if segments.iter().any(String::is_empty) {
        return None;
    }
    let prototype_idioms = descriptor
        .export_idioms
        .iter()
        .filter(|idiom| {
            matches!(
                idiom.as_str(),
                "exported-constructor-prototype" | "exported-constructor-inherited-prototype"
            )
        })
        .collect::<Vec<_>>();
    if !prototype_idioms.is_empty() {
        if prototype_idioms.len() != descriptor.export_idioms.len() || segments.len() < 2 {
            return None;
        }
        let mut path = vec![segments[0].clone(), "prototype".to_owned()];
        path.extend_from_slice(&segments[1..]);
        return Some(BuiltinAccess {
            kind: if prototype_idioms[0].as_str() == "exported-constructor-inherited-prototype" {
                "inherited-prototype-property".to_owned()
            } else {
                "prototype-property".to_owned()
            },
            path,
        });
    }
    if descriptor.export_name == "default"
        && descriptor
            .export_idioms
            .iter()
            .any(|idiom| idiom == "module-exports-assignment")
    {
        return Some(BuiltinAccess {
            kind: "module-value".to_owned(),
            path: Vec::new(),
        });
    }
    Some(BuiltinAccess {
        kind: "export-property".to_owned(),
        path: segments,
    })
}

fn assert_object_keys(value: &serde_json::Value, expected: &[&str], context: &str) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("{context} must be an object"));
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "{context} has unexpected fields");
}

fn validate_byte_array(value: &serde_json::Value, context: &str) {
    let bytes = value
        .as_array()
        .unwrap_or_else(|| panic!("{context} must be an array"));
    assert!(!bytes.is_empty() && bytes.len() <= 64, "{context} is unbounded");
    assert!(
        bytes
            .iter()
            .all(|byte| byte.as_u64().is_some_and(|byte| byte <= u8::MAX.into())),
        "{context} contains a non-byte value"
    );
}

fn is_zlib_owner(value: &str) -> bool {
    matches!(
        value,
        "BrotliCompress"
            | "BrotliDecompress"
            | "Deflate"
            | "DeflateRaw"
            | "Gunzip"
            | "Gzip"
            | "Inflate"
            | "InflateRaw"
            | "Unzip"
            | "ZstdCompress"
            | "ZstdDecompress"
    )
}

fn is_stream_owner(value: &str) -> bool {
    matches!(
        value,
        "Duplex" | "PassThrough" | "Readable" | "Stream" | "Transform" | "Writable" | "default"
    )
}

fn validate_authored_argument(argument: &serde_json::Value, allow_setup_value: bool) {
    let object = argument
        .as_object()
        .expect("authored builtin argument must be an object");
    let kind = object["kind"]
        .as_str()
        .expect("authored builtin argument has no kind");
    match kind {
        "json" => {
            assert_object_keys(argument, &["kind", "value"], "JSON argument");
            assert!(
                serde_json::to_vec(&object["value"]).unwrap().len() <= 1024,
                "JSON argument is unbounded"
            );
        }
        "noop-function" | "event-emitter" => {
            assert_object_keys(argument, &["kind"], "authored special argument");
        }
        "constant-function" => {
            assert_object_keys(
                argument,
                &["kind", "value"],
                "constant function argument",
            );
            assert!(
                serde_json::to_vec(&object["value"]).unwrap().len() <= 1024,
                "constant function result is unbounded"
            );
        }
        "first-argument-function" | "abort-signal" => {
            assert_object_keys(argument, &["kind"], "authored function/signal argument");
        }
        "stream-instance" => {
            assert_object_keys(
                argument,
                &["ended", "kind", "ownerExportName"],
                "stream instance argument",
            );
            let owner = object["ownerExportName"]
                .as_str()
                .expect("stream argument owner must be text");
            assert!(is_stream_owner(owner));
            assert!(object["ended"].is_boolean());
        }
        "throwing-function" => {
            assert_object_keys(
                argument,
                &["errorMessage", "kind"],
                "throwing function argument",
            );
            let message = object["errorMessage"]
                .as_str()
                .expect("throwing function message must be text");
            assert!(!message.is_empty() && message.len() <= 128);
        }
        "regexp" => {
            assert_object_keys(argument, &["flags", "kind", "source"], "regexp argument");
            let source = object["source"]
                .as_str()
                .expect("regexp source must be text");
            let flags = object["flags"]
                .as_str()
                .expect("regexp flags must be text");
            assert!(source.len() <= 128 && flags.len() <= 8);
            assert!(flags.chars().all(|flag| "dgimsuvy".contains(flag)));
        }
        "buffer" | "uint8-array" => {
            assert_object_keys(argument, &["bytes", "kind"], "byte array argument");
            validate_byte_array(&object["bytes"], "authored argument bytes");
        }
        "bigint" => {
            assert_object_keys(argument, &["kind", "value"], "bigint argument");
            object["value"]
                .as_str()
                .expect("bigint argument must be decimal text")
                .parse::<i128>()
                .expect("bigint argument must be bounded decimal text");
        }
        "setup-value" => {
            assert!(allow_setup_value, "setup value used outside its authored setup");
            assert_object_keys(argument, &["kind", "name"], "setup value argument");
            assert_eq!(object["name"], "tracked");
        }
        "zlib-input" => {
            assert_object_keys(
                argument,
                &["kind", "ownerExportName"],
                "zlib input argument",
            );
            let owner = object["ownerExportName"]
                .as_str()
                .expect("zlib input owner must be text");
            assert!(is_zlib_owner(owner));
        }
        other => panic!("unsupported authored builtin argument kind {other}"),
    }
}

fn descriptor_is_prototype(descriptor: &BuiltinSourceDescriptor) -> bool {
    matches!(
        descriptor.access.kind.as_str(),
        "prototype-property" | "inherited-prototype-property"
    )
}

fn validate_call_setup(invocation: &BuiltinInvocation, descriptor: &BuiltinSourceDescriptor) {
    let setup = invocation
        .setup
        .as_object()
        .expect("authored builtin call setup must be an object");
    let kind = setup["kind"]
        .as_str()
        .expect("authored builtin call setup has no kind");
    let prototype = descriptor_is_prototype(descriptor);
    let mut allow_setup_value = false;
    match kind {
        "root-call" => {
            assert_object_keys(&invocation.setup, &["kind"], "root call setup");
            assert!(!prototype, "root call cannot dispatch a prototype surface");
        }
        "construct-target" => {
            assert_object_keys(&invocation.setup, &["kind"], "target constructor setup");
            if prototype {
                assert!(descriptor.export_name.ends_with(".constructor"));
            }
        }
        "constructed-owner" => {
            assert_object_keys(
                &invocation.setup,
                &["constructorArguments", "kind", "ownerExportName"],
                "constructed owner setup",
            );
            assert!(prototype);
            let owner = setup["ownerExportName"]
                .as_str()
                .expect("constructed owner name must be text");
            assert_eq!(descriptor.access.path.first().map(String::as_str), Some(owner));
            let constructor_arguments = setup["constructorArguments"]
                .as_array()
                .expect("constructor arguments must be an array");
            assert!(constructor_arguments.len() <= 4);
            for argument in constructor_arguments {
                validate_authored_argument(argument, false);
            }
        }
        "buffer-owner" => {
            assert_object_keys(
                &invocation.setup,
                &["bytes", "kind", "ownerExportName"],
                "buffer owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_buffer");
            let owner = setup["ownerExportName"]
                .as_str()
                .expect("buffer owner name must be text");
            assert!(matches!(owner, "Buffer" | "SlowBuffer"));
            assert_eq!(descriptor.access.path.first().map(String::as_str), Some(owner));
            validate_byte_array(&setup["bytes"], "buffer receiver bytes");
        }
        "call-tracker-owner" => {
            assert_object_keys(
                &invocation.setup,
                &["kind", "ownerExportName", "trackedExpectedCalls"],
                "CallTracker owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_assert");
            assert_eq!(setup["ownerExportName"], "CallTracker");
            assert_eq!(setup["trackedExpectedCalls"], 1);
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some("CallTracker")
            );
            allow_setup_value = true;
        }
        "zlib-owner" => {
            assert_object_keys(
                &invocation.setup,
                &["ensureNativeStream", "kind", "ownerExportName"],
                "zlib owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_zlib");
            let owner = setup["ownerExportName"]
                .as_str()
                .expect("zlib owner name must be text");
            assert!(is_zlib_owner(owner));
            assert_eq!(descriptor.access.path.first().map(String::as_str), Some(owner));
            assert!(setup["ensureNativeStream"].is_boolean());
        }
        "stream-owner" => {
            assert_object_keys(
                &invocation.setup,
                &["endedInput", "kind", "ownerExportName"],
                "stream owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_stream");
            let owner = setup["ownerExportName"]
                .as_str()
                .expect("stream owner name must be text");
            assert!(is_stream_owner(owner));
            assert_eq!(descriptor.access.path.first().map(String::as_str), Some(owner));
            assert!(setup["endedInput"].is_boolean());
        }
        other => panic!("unsupported authored builtin setup kind {other}"),
    }
    assert!(invocation.arguments.len() <= 8);
    for argument in &invocation.arguments {
        validate_authored_argument(argument, allow_setup_value);
    }
}

fn expected_template_id(source_key: &str) -> Option<&'static str> {
    match source_key {
        "node_assert" => Some("node-assert-bounded-v1"),
        "node_buffer" => Some("node-buffer-bounded-v1"),
        "node_events" => Some("node-events-bounded-v1"),
        "node_perf_hooks" => Some("node-perf-hooks-bounded-v1"),
        "node_path" => Some("node-path-pure-v1"),
        "node_punycode" => Some("node-punycode-pure-v1"),
        "node_querystring" => Some("node-querystring-pure-v1"),
        "node_stream" => Some("node-stream-bounded-v1"),
        "node_string_decoder" => Some("node-string-decoder-bounded-v1"),
        "node_url" => Some("node-url-pure-v1"),
        "node_util" => Some("node-util-pure-v1"),
        "node_zlib" => Some("node-zlib-bounded-v1"),
        _ => None,
    }
}

fn validate_probe_binding(
    recipe: &Recipe,
    probe: &PublicSurfaceProbe,
    invocation: &BuiltinInvocation,
) {
    assert_eq!(recipe.route.ambiguous_callees, Vec::<String>::new());
    assert_eq!(recipe.route.alternatives.len(), 1);
    assert_eq!(
        recipe.route.alternatives[0].terminal_observed_key,
        probe.surface_observed_key
    );
    assert!(!recipe.route.alternatives[0].proof_paths.is_empty());
    assert_eq!(
        tagged_jcs_digest(&invocation.source_descriptor),
        invocation.source_descriptor_digest,
        "{}: source descriptor digest drift",
        recipe.fixture_id
    );
}

fn validate_probe(recipe: &Recipe, probe: &PublicSurfaceProbe) {
    let invocation = &probe.invocation;
    assert_eq!(recipe.classification, "non-capability");
    assert_eq!(recipe.scenario, "non-capability");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(!probe.command.is_empty());
    let is_read = invocation.invocation_schema == "ibex/capsec-builtin-export-invocation/1"
        && invocation.kind == "builtin-export-read";
    let is_call = invocation.invocation_schema == "ibex/capsec-builtin-call-invocation/1"
        && invocation.kind == "builtin-export-call";
    let is_import = invocation.invocation_schema
        == "ibex/capsec-builtin-module-import-invocation/1"
        && invocation.kind == "builtin-module-import";
    assert!(
        is_read || is_call || is_import,
        "unsupported non-capability builtin probe"
    );
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert!(invocation.allowed_coverage_edge_ids.is_empty());
    assert!(invocation.expected_action_ids.is_empty());
    assert!(invocation.required_authority.is_empty());

    if is_import {
        let descriptor: BuiltinModuleAliasDescriptor =
            serde_json::from_value(invocation.source_descriptor.clone())
                .expect("non-capability builtin module descriptor must be typed");
        assert_eq!(descriptor.kind, "builtin-module-alias");
        assert!(!descriptor.source_key.is_empty());
        assert_eq!(descriptor.module_specifier, invocation.module_specifier);
        assert!(!descriptor.source_ref.is_empty());
        assert!(matches!(
            descriptor.resolution_kind.as_str(),
            "bootstrap-internal" | "manifest"
        ));
        assert!(invocation.export_name.is_none());
        assert_eq!(invocation.expected_result, "return");
        assert!(invocation.template_id.is_none());
        assert!(invocation.body_entry_proof.is_none());
        assert!(invocation.arguments.is_empty());
        assert_eq!(invocation.setup, serde_json::json!({"kind": "none"}));
        assert_eq!(
            probe.surface_observed_key,
            format!("builtin:{}", descriptor.module_specifier)
        );
        validate_probe_binding(recipe, probe, invocation);
        return;
    }

    let descriptor: BuiltinSourceDescriptor =
        serde_json::from_value(invocation.source_descriptor.clone())
            .expect("non-capability builtin source descriptor must be typed");
    assert_eq!(descriptor.kind, "builtin-export");
    assert!(!descriptor.source_key.is_empty());
    assert_ne!(descriptor.source_key, "node_os");
    assert_eq!(
        invocation.export_name.as_deref(),
        Some(descriptor.export_name.as_str())
    );
    assert!(!descriptor.source_ref.is_empty());
    if let Some(platforms) = descriptor.platform_availability.as_deref() {
        assert!(!platforms.is_empty());
        assert!(is_sorted_set(platforms));
        assert!(platforms
            .iter()
            .all(|platform| matches!(platform.as_str(), "android" | "darwin" | "linux")));
        assert!(platforms.iter().any(|platform| platform == "darwin"));
    }
    assert!(!descriptor.export_idioms.is_empty());
    assert!(is_sorted_set(&descriptor.export_idioms));
    assert!(!descriptor.module_specifiers.is_empty());
    assert!(is_sorted_set(&descriptor.module_specifiers));
    assert_eq!(
        canonical_module_specifier(&descriptor.module_specifiers),
        Some(invocation.module_specifier.as_str())
    );
    assert_eq!(
        expected_access(&descriptor).as_ref(),
        Some(&descriptor.access)
    );
    if is_read {
        assert_eq!(invocation.expected_result, "return");
        assert!(invocation.template_id.is_none());
        assert!(invocation.body_entry_proof.is_none());
        assert!(invocation.arguments.is_empty());
        assert_eq!(invocation.setup, serde_json::json!({"kind": "none"}));
        assert!(matches!(
            descriptor.value_shape.as_str(),
            "accessor" | "data"
        ));
        assert!(matches!(
            descriptor.access.kind.as_str(),
            "export-property" | "module-value"
        ));
        if descriptor.value_shape == "accessor" {
            assert_eq!(descriptor.access.kind, "export-property");
        }
    } else {
        assert_eq!(invocation.expected_result, "normal-return");
        assert_eq!(descriptor.value_shape, "callable");
        assert!(matches!(
            descriptor.access.kind.as_str(),
            "export-property"
                | "module-value"
                | "prototype-property"
                | "inherited-prototype-property"
        ));
        let expected_template = expected_template_id(&descriptor.source_key)
            .expect("unsupported non-capability builtin call source");
        assert_eq!(invocation.template_id.as_deref(), Some(expected_template));
        let proof = invocation
            .body_entry_proof
            .as_ref()
            .expect("authored builtin call requires a body-entry proof");
        assert_eq!(proof.kind, "normal-return-from-source-call");
        assert!(matches!(
            proof.result_type.as_str(),
            "bigint" | "boolean" | "function" | "null" | "number" | "object" | "string" | "undefined"
        ));
        validate_call_setup(invocation, &descriptor);
    }
    assert_eq!(
        probe.surface_observed_key,
        format!(
            "builtin:export:{}:{}",
            descriptor.source_key, descriptor.export_name
        )
    );
    validate_probe_binding(recipe, probe, invocation);
}

fn noncap_builtin_recipes(catalog: &RecipeCatalog) -> Vec<&Recipe> {
    catalog
        .recipes
        .iter()
        .filter(|recipe| {
            recipe.status == "fully-executable"
                && recipe.public_surface_probe.as_ref().is_some_and(|probe| {
                    matches!(
                        (
                            probe.invocation.invocation_schema.as_str(),
                            probe.invocation.kind.as_str()
                        ),
                        (
                            "ibex/capsec-builtin-export-invocation/1",
                            "builtin-export-read"
                        ) | (
                            "ibex/capsec-builtin-call-invocation/1",
                            "builtin-export-call"
                        ) | (
                            "ibex/capsec-builtin-module-import-invocation/1",
                            "builtin-module-import"
                        )
                    )
                })
        })
        .inspect(|recipe| validate_probe(recipe, recipe.public_surface_probe.as_ref().unwrap()))
        .collect()
}

fn invocation_script(invocation: &BuiltinInvocation) -> String {
    const HARNESS: &str = include_str!("capsec_public_noncap_builtin_invocation.js");
    format!(
        "JSON.stringify(({})({}))",
        HARNESS.trim(),
        serde_json::to_string(invocation).expect("serialize authored builtin invocation")
    )
}

async fn execute_recipe(
    engine: &HermesEngine,
    recipe: &Recipe,
    engine_binary_digest: &str,
) -> std::result::Result<serde_json::Value, String> {
    let probe = recipe
        .public_surface_probe
        .as_ref()
        .expect("builtin recipe has no public probe");
    let session_id = format!("public-observation:{}", recipe.plan_digest);
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id),
        "public builtin observer has no installed host"
    );
    let encoded = engine
        .eval_immediate(&invocation_script(&probe.invocation))
        .await
        .expect("execute public builtin probe")
        .expect("public builtin probe returned no result");
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    let invocation_result: serde_json::Value =
        serde_json::from_str(&encoded).expect("public builtin returned invalid JSON");
    if invocation_result["kind"] != "return" {
        return Err(format!(
            "{}: public builtin probe failed: {invocation_result}",
            recipe.fixture_id
        ));
    }
    if probe.invocation.kind == "builtin-export-call" {
        let proof = probe
            .invocation
            .body_entry_proof
            .as_ref()
            .expect("validated builtin call has no body-entry proof");
        if invocation_result["bodyEntryProof"] != proof.kind
            || invocation_result["valueType"] != proof.result_type
        {
            return Err(format!(
                "{}: public builtin call returned without its exact body-entry proof: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if probe.invocation.setup["kind"] == "zlib-owner"
            && invocation_result["cleanupPerformed"] != true
        {
            return Err(format!(
                "{}: public zlib call did not prove native-state cleanup: {invocation_result}",
                recipe.fixture_id
            ));
        }
    }
    if !legacy.is_empty() || !typed.is_empty() {
        return Err(format!(
            "{}: non-capability builtin probe observed {} legacy and {} typed decisions",
            recipe.fixture_id,
            legacy.len(),
            typed.len()
        ));
    }
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": probe.invocation.invocation_schema,
            "kind": probe.invocation.kind,
            "surfaceObservedKey": probe.surface_observed_key,
            "moduleSpecifier": probe.invocation.module_specifier,
            "exportName": probe.invocation.export_name,
            "sourceDescriptorDigest": probe.invocation.source_descriptor_digest,
            "result": invocation_result,
        },
        "legacyObservationCount": 0,
        "typedDecisions": [],
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected observation must be an object")
        .insert("result".into(), serde_json::Value::String("passed".into()));
    let mut evidence = serde_json::json!({
        "evidenceSchema": "ibex/capsec-public-surface-fixture-evidence/2",
        "fixtureId": recipe.fixture_id,
        "planDigest": recipe.plan_digest,
        "engineBinaryDigest": engine_binary_digest,
        "probe": probe,
        "terminalObservedKey": probe.surface_observed_key,
        "exitCode": 0,
        "resultMarker": format!("ibex-capsec-public-fixture:{}:passed", recipe.fixture_id),
        "observation": observation,
        "runtimeObservation": runtime_observation,
    });
    let digest = tagged_jcs_digest(&evidence);
    evidence
        .as_object_mut()
        .unwrap()
        .insert("evidenceDigest".into(), serde_json::Value::String(digest));
    Ok(serde_json::json!({
        "fixtureId": recipe.fixture_id,
        "outcome": "passed",
        "executor": "ibex-noncap-builtin-public-surface-harness",
        "evidence": evidence,
    }))
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_public_noncap_builtin_recipe_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping noncap builtin public batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT")
        .expect("noncap builtin public batch requires an owned evidence output path");
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipes = noncap_builtin_recipes(&catalog);
    assert!(
        !recipes.is_empty(),
        "recipe catalog contains no non-capability builtin probes"
    );
    let builtin_imports = recipes
        .iter()
        .map(|recipe| {
            recipe
                .public_surface_probe
                .as_ref()
                .unwrap()
                .invocation
                .module_specifier
                .clone()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let _lock = hermes_engine_test_lock().lock().await;
    let (host, digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] = serde_json::json!(builtin_imports);
        });
    assert_ne!(crate::host::abi::install_host(host), 0);
    let _reset = HostResetGuard;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before noncap builtin public probes");
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))
        .expect("create exact noncap builtin engine");
    engine
        .load_runtime()
        .await
        .expect("load exact noncap builtin runtime");
    let mut executions = Vec::with_capacity(recipes.len());
    let mut failures = Vec::new();
    for (index, recipe) in recipes.iter().enumerate() {
        match execute_recipe(&engine, recipe, &identity_before.binary_digest).await {
            Ok(execution) => executions.push(execution),
            Err(error) => failures.push(error),
        }
        if index % 256 == 255 {
            eprintln!(
                "CapSec public non-capability builtin probes passed: {}/{}",
                index + 1,
                recipes.len()
            );
        }
    }
    assert!(
        failures.is_empty(),
        "{} non-capability builtin public probes failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    executions.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
    assert_eq!(executions.len(), recipes.len());
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after noncap builtin public probes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after noncap builtin public probes");
    let artifact = PublicBatchArtifact {
        public_batch_evidence_schema: "ibex/capsec-public-batch-evidence/1",
        recipe_catalog_digest: catalog.recipe_catalog_digest,
        loaded_engine_identity: identity_before,
        executions,
    };
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("create owned noncap builtin public evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize noncap builtin public evidence artifact");
    output.write_all(b"\n").expect("finish builtin evidence");
    output.sync_all().expect("sync builtin evidence artifact");
}

fn path_basename_call_invocation(argument: serde_json::Value) -> BuiltinInvocation {
    BuiltinInvocation {
        invocation_schema: "ibex/capsec-builtin-call-invocation/1".to_owned(),
        kind: "builtin-export-call".to_owned(),
        module_specifier: "node:path".to_owned(),
        export_name: Some("basename".to_owned()),
        source_descriptor: serde_json::json!({
            "kind": "builtin-export",
            "sourceKey": "node_path",
            "exportName": "basename",
            "exportIdioms": ["object-binding", "object-source"],
            "moduleSpecifiers": ["node:path", "path"],
            "sourceRef": "src/builtins/path.js#exports:basename",
            "valueShape": "callable",
            "access": {"kind": "export-property", "path": ["basename"]},
        }),
        source_descriptor_digest: "test-only".to_owned(),
        template_id: Some("node-path-pure-v1".to_owned()),
        arguments: vec![argument],
        setup: serde_json::json!({"kind": "root-call"}),
        body_entry_proof: Some(BodyEntryProof {
            kind: "normal-return-from-source-call".to_owned(),
            result_type: "string".to_owned(),
        }),
        required_authority: Vec::new(),
        expected_result: "normal-return".to_owned(),
        expected_typed_decision_count: 0,
        expected_typed_stages: Vec::new(),
        allowed_coverage_edge_ids: Vec::new(),
        expected_action_ids: Vec::new(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn authored_call_harness_never_counts_a_throw_as_body_entry() {
    let _lock = hermes_engine_test_lock().lock().await;
    let (host, digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] = serde_json::json!(["node:path"]);
        });
    assert_ne!(crate::host::abi::install_host(host), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))
        .expect("create exact authored-call marker engine");
    engine
        .load_runtime()
        .await
        .expect("load exact authored-call marker runtime");

    let invalid = path_basename_call_invocation(serde_json::json!({
        "kind": "json",
        "value": null,
    }));
    let invalid_encoded = engine
        .eval_immediate(&invocation_script(&invalid))
        .await
        .expect("execute invalid authored call")
        .expect("invalid authored call returned no result");
    let invalid_result: serde_json::Value =
        serde_json::from_str(&invalid_encoded).expect("invalid call result must be JSON");
    assert_eq!(invalid_result["kind"], "throw");
    assert!(invalid_result.get("bodyEntryProof").is_none());

    let valid = path_basename_call_invocation(serde_json::json!({
        "kind": "json",
        "value": "/ibex/file.txt",
    }));
    let valid_encoded = engine
        .eval_immediate(&invocation_script(&valid))
        .await
        .expect("execute valid authored call")
        .expect("valid authored call returned no result");
    let valid_result: serde_json::Value =
        serde_json::from_str(&valid_encoded).expect("valid call result must be JSON");
    assert_eq!(valid_result["kind"], "return");
    assert_eq!(
        valid_result["bodyEntryProof"],
        "normal-return-from-source-call"
    );
    assert_eq!(valid_result["valueType"], "string");
}

#[tokio::test(flavor = "current_thread")]
async fn manifest_builtin_fanout_preserves_terminal_authority_checks() {
    let temp = tempfile::tempdir().expect("create builtin terminal fixture root");
    let root = std::fs::canonicalize(temp.path()).expect("canonicalize builtin terminal root");
    let secret = root.join("secret.txt");
    std::fs::write(&secret, b"must stay unread").expect("write builtin terminal fixture");
    let _lock = hermes_engine_test_lock().lock().await;
    let (host, digest) = build_armed_test_host_custom(
        Some(&root),
        false,
        false,
        false,
        Vec::new(),
        None,
        |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] = serde_json::json!(["node:fs"]);
        },
    );
    assert_ne!(crate::host::abi::install_host(host), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))
        .expect("create exact builtin terminal authority engine");
    engine
        .load_runtime()
        .await
        .expect("load exact builtin terminal authority runtime");
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(
            "public.builtin.internal-fanout-terminal-denial"
        )
    );
    let script = format!(
        "(function(){{var fs;try{{fs=require('node:fs');}}catch(error){{return 'import-denied';}}try{{fs.readFileSync({},'utf8');return 'terminal-allowed';}}catch(error){{return 'terminal-denied';}}}})()",
        serde_json::to_string(&secret.to_string_lossy()).expect("serialize terminal fixture path")
    );
    let result = engine
        .eval_immediate(&script)
        .await
        .expect("execute builtin terminal denial")
        .expect("builtin terminal denial returned no result");
    assert_eq!(
        result, "terminal-denied",
        "builtin import must succeed but its terminal must deny"
    );
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(
        legacy.is_empty(),
        "rev2 terminal must not consult legacy gates"
    );
    assert!(
        !typed.is_empty(),
        "the fs terminal must execute a typed decision"
    );
    assert!(typed.iter().any(|decision| {
        decision.evidence.outcome == capsec_semantics::decision::DecisionOutcome::Deny
    }));
}
