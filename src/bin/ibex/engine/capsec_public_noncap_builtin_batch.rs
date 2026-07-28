use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[cfg(not(feature = "host-http-server"))]
use std::io::Write as _;

const EVENT_LOOP_COMPLETION_KIND: &str = "event-loop-quiescence";
const EVENT_LOOP_COMPLETION_TIMEOUT_MS: u64 = 1_000;
const CAPTURED_INVOCATION_SCHEMA: &str =
    "ibex/capsec-builtin-noncap-captured-invocation/1";
const LOADER_CAPTURED_INVOCATION_SCHEMA: &str =
    "ibex/capsec-loader-captured-invocation/1";

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
    edge_ids: Vec<String>,
    action_ids: Vec<String>,
    expected_observation: serde_json::Value,
    route: PublicRoute,
    status: String,
    public_surface_probe: Option<serde_json::Value>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    captured_output_invocation: Option<serde_json::Value>,
    completion: CompletionExpectation,
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
struct CompletionExpectation {
    kind: String,
    timeout_milliseconds: u64,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_value_type: Option<String>,
    #[serde(default)]
    platform_availability: Option<Vec<String>>,
    access: BuiltinAccess,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuiltinModuleAliasSourceDescriptor {
    kind: String,
    module_specifier: String,
    source_key: String,
    source_ref: String,
    source_metadata: BuiltinModuleAliasSourceMetadata,
    expected_root_type: String,
    carrier_edge_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuiltinModuleAliasSourceMetadata {
    source_key: String,
    bundle_external: bool,
    import_reachability: String,
    module_builtin: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuiltinSourceObservation {
    schema: String,
    runtime_nonce: String,
    observation_id: String,
    expected_alias: String,
    status: String,
    source_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoaderPublicSurfaceProbe {
    kind: String,
    surface_observed_key: String,
    command: Vec<String>,
    invocation: LoaderCapturedInvocation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoaderCapturedInvocation {
    invocation_schema: String,
    kind: String,
    coverage_edge_id: String,
    coverage_classification: String,
    module_specifier: String,
    entrypoint: String,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    captured_output_invocation: serde_json::Value,
    captured_output_invocation_digest: String,
    completion: CompletionExpectation,
    required_authority: Vec<serde_json::Value>,
    expected_result: String,
    expected_typed_stages: Vec<String>,
    expected_typed_decision_count: usize,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoaderPointObservation {
    schema: String,
    runtime_nonce: String,
    observation_id: String,
    expected_point: String,
    status: String,
    match_count: u64,
}

fn reviewed_noncap_module_alias(module_specifier: &str) -> Option<(&'static str, bool, &'static str)> {
    match module_specifier {
        "buffer" | "node:buffer" => Some(("node_buffer", true, "object")),
        "bun:sqlite" | "exact:sqlite" => Some(("exact_sqlite", false, "function")),
        "console" | "node:console" => Some(("node_console", true, "object")),
        "dns" | "node:dns" => Some(("node_dns", true, "object")),
        "dns/promises" | "node:dns/promises" => {
            Some(("node_dns_promises", true, "object"))
        }
        "exact:clipboard" => Some(("exact_clipboard", false, "object")),
        "exact:http" => Some(("exact_http", false, "object")),
        "module" | "node:module" => Some(("node_module", true, "object")),
        "node:path" | "path" => Some(("node_path", true, "object")),
        "node:path/posix" | "path/posix" => Some(("path_posix_alias", true, "object")),
        "node:path/win32" | "path/win32" => Some(("path_win32_alias", true, "object")),
        "node:punycode" | "punycode" => Some(("node_punycode", true, "object")),
        "node:querystring" | "querystring" => {
            Some(("node_querystring", true, "object"))
        }
        "node:string_decoder" | "string_decoder" => {
            Some(("node_string_decoder", true, "function"))
        }
        "node:timers" | "timers" => Some(("node_timers", true, "object")),
        "node:timers/promises" | "timers/promises" => {
            Some(("node_timers_promises", true, "object"))
        }
        "node:trace_events" | "trace_events" => {
            Some(("node_trace_events", true, "object"))
        }
        "node:v8" | "v8" => Some(("node_v8", true, "object")),
        _ => None,
    }
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

/// Test-only armed engine facade. Its `eval_immediate` spelling preserves the
/// existing public-builtin harness while every source string is consumed as a
/// closed authenticated submission, never by the post-bootstrap bare evaluator.
/// Reclaiming the sequence between calls is safe because the Host's cached
/// session token owns the single monotonic ordinal stream. The facade also
/// acts as the authenticated lifecycle controller: it continuously consumes
/// and validates the runtime's bounded work-unit publication stream.
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry —
/// armed project source enters only through authenticated session submission.
/// @ref LLP 0025#11-delegated-obligations — OBL-UNIT-PUBLICATION requires
/// every unit to reach a controller with pairing and scheduling identity.
struct AuthenticatedNoncapEngine {
    host: crate::host::Host,
    engine: HermesEngine,
    publications: AuthenticatedPublicationTracker,
}

impl std::ops::Deref for AuthenticatedNoncapEngine {
    type Target = HermesEngine;

    fn deref(&self) -> &Self::Target {
        &self.engine
    }
}

impl AuthenticatedNoncapEngine {
    async fn eval_immediate(&mut self, source: &str) -> anyhow::Result<Option<String>> {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};

        self.drain_publications()?;
        let session = self.host.mint_armed_session_token()?;
        let mut sequence =
            ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())?;
        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })?
            .authorize_inline()
            .bind_bytes(source.as_bytes().to_vec())
            .into_request()?;
        let ordinal = request.submission_ordinal();
        let evaluation = self.engine.evaluate_authenticated(&session, request).await;
        self.drain_publications()?;
        let evaluation = evaluation.map_err(|error| {
            anyhow::anyhow!("authenticated public-builtin submission {ordinal} failed: {error:#}")
        })?;
        match evaluation {
            AuthenticatedEvaluation::Empty => Ok(None),
            AuthenticatedEvaluation::Value { display, receipt } => {
                let release = self
                    .engine
                    .release_undisplayed_value(receipt.ok_or_else(|| {
                        anyhow::anyhow!(
                            "authenticated public-builtin submission {ordinal} lost its value receipt"
                        )
                    })?)
                    .await;
                let publications = self.drain_publications();
                match (release, publications) {
                    (Err(release_error), Err(publication_error)) => anyhow::bail!(
                        "authenticated public-builtin submission {ordinal} failed to release its value ({release_error:#}) and its publication stream ({publication_error:#})"
                    ),
                    (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
                    (Ok(()), Ok(())) => {}
                }
                match display.kind {
                    AuthenticatedDisplayKind::Undefined => Ok(None),
                    AuthenticatedDisplayKind::String => serde_json::from_str(&display.text)
                        .map(Some)
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "authenticated public-builtin submission {ordinal} returned an invalid string display: {error}"
                            )
                        }),
                    _ => Ok(Some(display.text)),
                }
            }
            AuthenticatedEvaluation::Throw(thrown) => anyhow::bail!(
                "authenticated public-builtin submission {ordinal} threw: {thrown:?}"
            ),
            AuthenticatedEvaluation::Cancelled => anyhow::bail!(
                "authenticated public-builtin submission {ordinal} was cancelled"
            ),
            AuthenticatedEvaluation::Lifecycle(code) => anyhow::bail!(
                "authenticated public-builtin submission {ordinal} exited with lifecycle code {code}"
            ),
        }
    }

    fn drain_publications(&mut self) -> anyhow::Result<()> {
        self.publications
            .drain(&self.engine, "public builtin probe")
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        self.drain_publications()?;
        self.require_no_due_schedules("public builtin probes")
    }

    fn require_no_due_schedules(&self, context: &str) -> anyhow::Result<()> {
        self.publications.require_no_due_schedules(context)
    }
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

fn expected_builtin_cache_source_id(source_key: &str) -> String {
    let identity = serde_json::json!({
        "kind": "builtin",
        "key": source_key,
        "sourceIdSchema": "ibex.source-id.v1",
    });
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&identity)
        .expect("builtin cache SourceId identity must canonicalize");
    format!(
        "ibex-source-id-v1:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonical)
    )
}

fn is_tagged_nonzero_u64(value: &str) -> bool {
    let Some(decimal) = value.strip_prefix("u64:") else {
        return false;
    };
    if decimal.is_empty() || decimal.starts_with('0') {
        return false;
    }
    decimal.parse::<u64>().is_ok_and(|value| value != 0)
}

#[test]
fn authenticated_builtin_runtime_nonce_uses_exact_u64_tagging() {
    assert!(is_tagged_nonzero_u64("u64:1"));
    assert!(is_tagged_nonzero_u64("u64:18446744073709551615"));
    for rejected in [
        "",
        "1",
        "u64:0",
        "u64:01",
        "u64:-1",
        "u64:18446744073709551616",
    ] {
        assert!(!is_tagged_nonzero_u64(rejected), "accepted {rejected:?}");
    }
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

fn is_reviewed_dns_promise_error_code(value: &str) -> bool {
    matches!(
        value,
        "ADDRGETNETWORKPARAMS"
            | "BADFAMILY"
            | "BADFLAGS"
            | "BADHINTS"
            | "BADNAME"
            | "BADQUERY"
            | "BADRESP"
            | "BADSTR"
            | "CANCELLED"
            | "CONNREFUSED"
            | "DESTRUCTION"
            | "EOF"
            | "FILE"
            | "FORMERR"
            | "LOADIPHLPAPI"
            | "NODATA"
            | "NOMEM"
            | "NONAME"
            | "NOTFOUND"
            | "NOTIMP"
            | "NOTINITIALIZED"
            | "REFUSED"
            | "SERVFAIL"
            | "TIMEOUT"
    )
}

fn is_reviewed_dns_promise_error_descriptor(descriptor: &BuiltinSourceDescriptor) -> bool {
    descriptor.source_key == "node_dns_promises"
        && is_reviewed_dns_promise_error_code(&descriptor.export_name)
        && descriptor.export_idioms == ["member-assignment"]
        && descriptor.module_specifiers == ["dns/promises", "node:dns/promises"]
        && descriptor.source_ref
            == format!(
                "src/builtins/dns-promises.js#exports:{}",
                descriptor.export_name
            )
        && descriptor.value_shape == "unknown"
        && descriptor.expected_value_type.as_deref() == Some("string")
        && descriptor.platform_availability.is_none()
        && descriptor.access.kind == "export-property"
        && descriptor.access.path == [descriptor.export_name.clone()]
}

fn is_reviewed_tls_secure_context_instance_descriptor(
    descriptor: &BuiltinSourceDescriptor,
) -> bool {
    descriptor.source_key == "node_tls"
        && descriptor.export_name == "SecureContext.context"
        && descriptor.export_idioms == ["exported-constructor-prototype"]
        && descriptor.module_specifiers == ["node:tls", "tls"]
        && descriptor.source_ref == "src/builtins/tls.js#exports:SecureContext.context"
        && descriptor.value_shape == "unknown"
        && descriptor.expected_value_type.as_deref() == Some("object")
        && descriptor.platform_availability.is_none()
        && descriptor.access.kind == "constructed-instance-property"
        && descriptor.access.path == ["context"]
}

fn is_reviewed_dgram_socket_closed_instance_descriptor(
    descriptor: &BuiltinSourceDescriptor,
) -> bool {
    descriptor.source_key == "node_dgram"
        && descriptor.export_name == "Socket._closed"
        && descriptor.export_idioms == ["exported-constructor-prototype"]
        && descriptor.module_specifiers == ["dgram", "node:dgram"]
        && descriptor.source_ref == "src/builtins/dgram.js#exports:Socket._closed"
        && descriptor.value_shape == "unknown"
        && descriptor.expected_value_type.as_deref() == Some("boolean")
        && descriptor.platform_availability.is_none()
        && descriptor.access.kind == "constructed-instance-property"
        && descriptor.access.path == ["_closed"]
}

fn reviewed_post_initialization_value_spec(
    source_key: &str,
    export_name: &str,
) -> Option<(&'static str, &'static str)> {
    match (source_key, export_name) {
        ("node_cluster", "SCHED_NONE" | "SCHED_RR") => Some(("data", "number")),
        ("node_cluster", "isMaster" | "isPrimary") => Some(("data", "boolean")),
        ("node_cluster", "isWorker") => Some(("unknown", "boolean")),
        ("node_http", "METHODS" | "STATUS_CODES" | "methods") => Some(("data", "object")),
        (
            "node_http",
            "kConnectionsCheckingInterval" | "kHighWaterMark" | "kTimeout",
        ) => Some(("unknown", "symbol")),
        ("node_http", "maxHeaderSize") => Some(("unknown", "number")),
        ("node_os", "EOL" | "devNull") => Some(("data", "string")),
        ("node_os", "constants") => Some(("data", "object")),
        ("node_dns" | "node_dns_promises", "default") => Some(("unknown", "object")),
        ("exact_crypto", "subtle" | "webcrypto") => Some(("unknown", "object")),
        (
            "exact_crypto",
            "KeyObject.asymmetricKeyDetails"
            | "KeyObject.asymmetricKeyType"
            | "KeyObject.symmetricKeySize"
            | "KeyObject.type"
            | "X509Certificate.infoAccess"
            | "X509Certificate.issuerCertificate"
            | "X509Certificate.subjectAltName",
        ) => Some(("accessor", "undefined")),
        (
            "exact_crypto",
            "X509Certificate.fingerprint"
            | "X509Certificate.fingerprint256"
            | "X509Certificate.issuer"
            | "X509Certificate.serialNumber"
            | "X509Certificate.subject"
            | "X509Certificate.validFrom"
            | "X509Certificate.validTo",
        ) => Some(("accessor", "string")),
        ("exact_crypto", "X509Certificate.keyUsage" | "X509Certificate.raw") => {
            Some(("accessor", "object"))
        }
        ("exact_crypto", "X509Certificate.publicKey") => Some(("unknown", "undefined")),
        (
            "node_buffer",
            "Buffer.__isExactBuffer" | "SlowBuffer.__isExactBuffer",
        ) => Some(("data", "boolean")),
        ("node_perf_hooks", "Performance.timeOrigin") => Some(("unknown", "number")),
        (
            "node_stream_web",
            "ByteLengthQueuingStrategy"
            | "CountQueuingStrategy"
            | "ReadableStream"
            | "ReadableStreamBYOBReader"
            | "ReadableStreamDefaultReader"
            | "TransformStream"
            | "WritableStream"
            | "WritableStreamDefaultWriter",
        ) => Some(("unknown", "function")),
        (
            "node_stream",
            "default.destroyed"
            | "default.closed"
            | "Duplex.closed"
            | "Duplex.destroyed"
            | "PassThrough.closed"
            | "PassThrough.destroyed"
            | "Readable.closed"
            | "Readable.destroyed"
            | "Stream.closed"
            | "Stream.destroyed"
            | "Transform.closed"
            | "Transform.destroyed"
            | "Writable.__exactWritableProtoPatched"
            | "Writable.closed"
            | "Writable.destroyed",
        ) => Some((
            if export_name.ends_with(".closed") {
                "unknown"
            } else {
                "data"
            },
            "boolean",
        )),
        (
            "ws",
            "WebSocket.CLOSED"
            | "WebSocket.CLOSING"
            | "WebSocket.CONNECTING"
            | "WebSocket.OPEN",
        ) => Some(("data", "number")),
        ("node_console", "default") => Some(("unknown", "object")),
        ("node_events", "captureRejectionSymbol" | "errorMonitor") => {
            Some(("unknown", "symbol"))
        }
        ("node_fs" | "node_fs_promises", "constants") => Some(("unknown", "object")),
        ("node_http2", "sensitiveHeaders") => Some(("unknown", "symbol")),
        ("node_module", "builtinModules")
        | ("node_perf_hooks", "performance")
        | ("node_timers_promises", "scheduler")
        | ("path_posix_alias" | "path_win32_alias", "default") => {
            Some(("unknown", "object"))
        }
        _ => None,
    }
}

fn is_reviewed_post_initialization_value_descriptor(
    descriptor: &BuiltinSourceDescriptor,
) -> bool {
    let Some((value_shape, expected_value_type)) =
        reviewed_post_initialization_value_spec(&descriptor.source_key, &descriptor.export_name)
    else {
        return false;
    };
    let source_contract_matches = match descriptor.source_key.as_str() {
        "node_cluster" => {
            descriptor.export_idioms == ["member-assignment"]
                && descriptor.module_specifiers == ["cluster", "node:cluster"]
                && descriptor.source_ref
                    == format!(
                        "src/builtins/cluster.js#exports:{}",
                        descriptor.export_name
                    )
        }
        "node_http" => {
            descriptor.export_idioms == ["module-exports-object"]
                && descriptor.module_specifiers
                    == [
                        "_http_agent",
                        "_http_common",
                        "_http_incoming",
                        "_http_outgoing",
                        "_http_server",
                        "http",
                        "node:http",
                    ]
                && descriptor.source_ref
                    == format!(
                        "src/builtins/http.js#exports:{}",
                        descriptor.export_name
                    )
        }
        "node_os" => {
            descriptor.export_idioms
                == if descriptor.export_name == "EOL" {
                    ["define-property"]
                } else {
                    ["module-exports-object"]
                }
                && descriptor.module_specifiers == ["node:os", "os"]
                && descriptor.source_ref
                    == format!(
                        "src/builtins/os.js#exports:{}",
                        descriptor.export_name
                    )
        }
        "exact_crypto" => {
            descriptor.export_idioms
                == if matches!(descriptor.export_name.as_str(), "subtle" | "webcrypto") {
                    vec!["object-binding".to_owned(), "object-source".to_owned()]
                } else {
                    vec!["exported-constructor-prototype".to_owned()]
                }
                && descriptor.module_specifiers == ["crypto", "exact:crypto", "node:crypto"]
                && descriptor.source_ref
                    == format!(
                        "src/builtins/crypto.js#exports:{}",
                        descriptor.export_name
                    )
        }
        "node_buffer" => {
            descriptor.export_idioms == ["exported-constructor-prototype"]
                && descriptor.module_specifiers == ["buffer", "node:buffer"]
                && descriptor.source_ref
                    == format!(
                        "src/builtins/buffer.js#exports:{}",
                        descriptor.export_name
                    )
        }
        "node_stream" => {
            let inherited = matches!(
                descriptor.export_name.as_str(),
                "Duplex.closed"
                    | "Duplex.destroyed"
                    | "PassThrough.closed"
                    | "PassThrough.destroyed"
                    | "Readable.closed"
                    | "Readable.destroyed"
                    | "Transform.closed"
                    | "Transform.destroyed"
                    | "Writable.closed"
                    | "Writable.destroyed"
            );
            descriptor.export_idioms
                == [if inherited {
                    "exported-constructor-inherited-prototype"
                } else {
                    "exported-constructor-prototype"
                }]
                && descriptor.module_specifiers == ["node:stream", "stream"]
                && descriptor.source_ref
                    == format!(
                        "src/builtins/stream.js#exports:{}",
                        descriptor.export_name
                    )
        }
        "ws" => {
            descriptor.export_idioms == ["exported-constructor-prototype"]
                && descriptor.module_specifiers == ["ws"]
                && descriptor.source_ref
                    == format!(
                        "src/builtins/ws.js#exports:{}",
                        descriptor.export_name
                    )
        }
        "node_console" => {
            descriptor.export_idioms == ["module-exports-assignment"]
                && descriptor.module_specifiers == ["console", "node:console"]
                && descriptor.source_ref == "src/builtins/console.js#exports:default"
        }
        "node_events" => {
            descriptor.export_idioms == ["member-assignment"]
                && descriptor.module_specifiers == ["events", "node:events"]
                && descriptor.source_ref
                    == format!(
                        "src/builtins/events.js#exports:{}",
                        descriptor.export_name
                    )
        }
        "node_fs" => {
            descriptor.export_idioms == ["module-exports-object"]
                && descriptor.module_specifiers == ["bun:fs", "fs", "node:fs"]
                && descriptor.source_ref == "src/builtins/fs.js#exports:constants"
        }
        "node_fs_promises" => {
            descriptor.export_idioms == ["object-binding", "object-source"]
                && descriptor.module_specifiers
                    == [
                        "bun:fs/promises",
                        "fs/promises",
                        "internal/fs/promises",
                        "node:fs/promises",
                    ]
                && descriptor.source_ref
                    == "src/builtins/fs-promises.js#exports:constants"
        }
        "node_http2" => {
            descriptor.export_idioms == ["module-exports-object"]
                && descriptor.module_specifiers == ["http2", "node:http2"]
                && descriptor.source_ref
                    == "src/builtins/http2.js#exports:sensitiveHeaders"
        }
        "node_module" => {
            descriptor.export_idioms
                == ["member-assignment", "object-binding", "object-source"]
                && descriptor.module_specifiers == ["module", "node:module"]
                && descriptor.source_ref
                    == "src/builtins/module.js#exports:builtinModules"
        }
        "node_dns" => {
            descriptor.export_idioms
                == ["member-assignment", "module-exports-assignment"]
                && descriptor.module_specifiers == ["dns", "node:dns"]
                && descriptor.source_ref == "src/builtins/dns.js#exports:default"
        }
        "node_dns_promises" => {
            descriptor.export_idioms == ["module-exports-assignment"]
                && descriptor.module_specifiers == ["dns/promises", "node:dns/promises"]
                && descriptor.source_ref
                    == "src/builtins/dns-promises.js#exports:default"
        }
        "node_perf_hooks" => {
            descriptor.export_idioms
                == if descriptor.export_name == "performance" {
                    ["module-exports-object"]
                } else {
                    ["exported-constructor-prototype"]
                }
                && descriptor.module_specifiers == ["node:perf_hooks", "perf_hooks"]
                && descriptor.source_ref
                    == format!(
                        "src/builtins/perf-hooks.js#exports:{}",
                        descriptor.export_name
                    )
        }
        "node_stream_web" => {
            descriptor.export_idioms == ["object-assignment", "object-source"]
                && descriptor.module_specifiers == ["node:stream/web", "stream/web"]
                && descriptor.source_ref
                    == format!(
                        "src/builtins/stream-web.js#exports:{}",
                        descriptor.export_name
                    )
        }
        "node_timers_promises" => {
            descriptor.export_idioms == ["module-exports-object"]
                && descriptor.module_specifiers == ["node:timers/promises", "timers/promises"]
                && descriptor.source_ref
                    == "src/builtins/timers-promises.js#exports:scheduler"
        }
        "path_posix_alias" => {
            descriptor.export_idioms == ["module-exports-assignment"]
                && descriptor.module_specifiers == ["node:path/posix", "path/posix"]
                && descriptor.source_ref
                    == "modules.ts#sources:path_posix_alias:exports:default"
        }
        "path_win32_alias" => {
            descriptor.export_idioms == ["module-exports-assignment"]
                && descriptor.module_specifiers == ["node:path/win32", "path/win32"]
                && descriptor.source_ref
                    == "modules.ts#sources:path_win32_alias:exports:default"
        }
        _ => false,
    };
    source_contract_matches
        && descriptor.value_shape == value_shape
        && descriptor.expected_value_type.as_deref() == Some(expected_value_type)
        && descriptor.platform_availability.is_none()
        && expected_access(descriptor).as_ref() == Some(&descriptor.access)
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

fn is_base_stream_module_value_method(export_name: &str) -> bool {
    matches!(
        export_name,
        "default._close"
            | "default._emitClose"
            | "default._undestroy"
            | "default.constructor"
            | "default.destroy"
            | "default.unpipe"
    )
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
    if descriptor.source_key == "exact_crypto"
        && descriptor.export_name == "X509Certificate.raw"
    {
        return Some(BuiltinAccess {
            kind: "constructed-instance-property".to_owned(),
            path: vec!["raw".to_owned()],
        });
    }
    if descriptor.source_key == "node_tls"
        && descriptor.export_name == "SecureContext.context"
    {
        return Some(BuiltinAccess {
            kind: "constructed-instance-property".to_owned(),
            path: vec!["context".to_owned()],
        });
    }
    if descriptor.source_key == "node_dgram"
        && descriptor.export_name == "Socket._closed"
    {
        return Some(BuiltinAccess {
            kind: "constructed-instance-property".to_owned(),
            path: vec!["_closed".to_owned()],
        });
    }
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // these inventory prototype rows execute only on fresh owned instances.
    if descriptor.source_key == "node_stream"
        && segments.len() == 2
        && segments[1] == "closed"
        && matches!(
            segments[0].as_str(),
            "default"
                | "Duplex"
                | "PassThrough"
                | "Readable"
                | "Stream"
                | "Transform"
                | "Writable"
        )
    {
        return Some(BuiltinAccess {
            kind: "constructed-instance-property".to_owned(),
            path: vec!["closed".to_owned()],
        });
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
        let path = if descriptor.source_key == "node_stream"
            && (descriptor.export_name == "default.destroyed"
                || is_base_stream_module_value_method(&descriptor.export_name))
        {
            vec![
                "prototype".to_owned(),
                segments.last().expect("prototype method").clone(),
            ]
        } else {
            let mut path = vec![segments[0].clone(), "prototype".to_owned()];
            path.extend_from_slice(&segments[1..]);
            path
        };
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
    assert!(
        !bytes.is_empty() && bytes.len() <= 64,
        "{context} is unbounded"
    );
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

fn is_zlib_sync_encoder(value: &str) -> bool {
    matches!(
        value,
        "brotliCompressSync" | "deflateRawSync" | "deflateSync" | "gzipSync"
    )
}

fn zlib_sync_decoder_input(value: &str) -> Option<&'static [u8]> {
    match value {
        "brotliDecompressSync" => Some(&[139, 1, 128, 105, 98, 101, 120, 3]),
        "gunzipSync" | "unzipSync" => Some(&[
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30, 109, 106, 4, 0,
            0, 0,
        ]),
        "inflateRawSync" => Some(&[203, 76, 74, 173, 0, 0]),
        "inflateSync" => Some(&[120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169]),
        _ => None,
    }
}

fn zlib_callback_contract(value: &str) -> Option<(&'static [u8], &'static str)> {
    match value {
        "brotliCompress" => Some((&[105, 98, 101, 120], "nonempty-byte-view")),
        "brotliDecompress" => Some((
            &[139, 1, 128, 105, 98, 101, 120, 3],
            "exact-ibex-byte-view",
        )),
        "deflate" | "deflateRaw" | "gzip" => {
            Some((&[105, 98, 101, 120], "nonempty-byte-view"))
        }
        "gunzip" | "unzip" => Some((
            &[
                31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30, 109, 106,
                4, 0, 0, 0,
            ],
            "exact-ibex-byte-view",
        )),
        "inflate" => Some((
            &[120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
            "exact-ibex-byte-view",
        )),
        "inflateRaw" => Some((&[203, 76, 74, 173, 0, 0], "exact-ibex-byte-view")),
        _ => None,
    }
}

fn zlib_end_contract(value: &str) -> Option<(&'static [u8], &'static str)> {
    match value {
        "BrotliCompress" | "Deflate" | "DeflateRaw" | "Gzip" => {
            Some((&[105, 98, 101, 120], "nonempty-byte-view"))
        }
        "BrotliDecompress" => Some((
            &[139, 1, 128, 105, 98, 101, 120, 3],
            "exact-ibex-byte-view",
        )),
        "Gunzip" | "Unzip" => Some((
            &[
                31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30, 109,
                106, 4, 0, 0, 0,
            ],
            "exact-ibex-byte-view",
        )),
        "Inflate" => Some((
            &[120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
            "exact-ibex-byte-view",
        )),
        "InflateRaw" => Some((&[203, 76, 74, 173, 0, 0], "exact-ibex-byte-view")),
        _ => None,
    }
}

fn zlib_process_chunk_contract(value: &str) -> Option<(&'static [u8], &'static str)> {
    match value {
        "BrotliCompress" | "Deflate" | "DeflateRaw" | "Gzip" => {
            Some((&[105, 98, 101, 120], "nonempty-byte-view"))
        }
        "BrotliDecompress" => Some((
            &[139, 1, 128, 105, 98, 101, 120, 3],
            "exact-ibex-byte-view",
        )),
        "Gunzip" | "Unzip" => Some((
            &[
                31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30, 109,
                106, 4, 0, 0, 0,
            ],
            "exact-ibex-byte-view",
        )),
        "Inflate" => Some((
            &[120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
            "exact-ibex-byte-view",
        )),
        "InflateRaw" => Some((&[203, 76, 74, 173, 0, 0], "exact-ibex-byte-view")),
        _ => None,
    }
}

fn zlib_write_contract(value: &str) -> Option<(&'static [u8], &'static str)> {
    zlib_end_contract(value)
}

fn zlib_flush_owner(value: &str) -> bool {
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

fn zlib_transform_input(value: &str) -> Option<&'static [u8]> {
    zlib_end_contract(value)
        .map(|(input, _)| input)
        .or_else(|| match value {
            "ZstdCompress" | "ZstdDecompress" => Some(&[105, 98, 101, 120]),
            _ => None,
        })
}

fn timer_root_contract(
    export_name: &str,
) -> Option<(serde_json::Value, serde_json::Value, &'static str)> {
    let contract = match export_name {
        "active" | "_unrefActive" | "unenroll" => (
            serde_json::json!({
                "kind": "timer-legacy-root",
                "operation": export_name
            }),
            serde_json::json!([
                {"kind": "setup-value", "name": "timerRecord"}
            ]),
            "undefined",
        ),
        "enroll" => (
            serde_json::json!({
                "kind": "timer-legacy-root",
                "operation": "enroll"
            }),
            serde_json::json!([
                {"kind": "setup-value", "name": "timerRecord"},
                {"kind": "json", "value": 60_000}
            ]),
            "undefined",
        ),
        "clearInterval" | "clearTimeout" => {
            let timer_kind = match export_name {
                "clearInterval" => "interval",
                "clearTimeout" => "timeout",
                _ => unreachable!(),
            };
            (
                serde_json::json!({
                    "kind": "timer-clear-root",
                    "timerKind": timer_kind
                }),
                serde_json::json!([
                    {"kind": "setup-value", "name": "timerHandle"}
                ]),
                "undefined",
            )
        }
        "setImmediate" => (
            serde_json::json!({
                "kind": "timer-factory-root",
                "timerKind": "immediate"
            }),
            serde_json::json!([
                {"kind": "timer-callback"}
            ]),
            "object",
        ),
        "setInterval" | "setTimeout" => (
            serde_json::json!({
                "kind": "timer-factory-root",
                "timerKind": if export_name == "setInterval" {
                    "interval"
                } else {
                    "timeout"
                }
            }),
            serde_json::json!([
                {"kind": "timer-callback"},
                {"kind": "json", "value": 60_000}
            ]),
            "object",
        ),
        _ => return None,
    };
    Some(contract)
}

fn timer_prototype_contract(
    export_name: &str,
) -> Option<(serde_json::Value, serde_json::Value, &'static str)> {
    let (owner, method) = export_name.split_once('.')?;
    let result_type = match (owner, method) {
        ("Immediate", "close" | "ref" | "unref")
        | ("Timeout", "close" | "ref" | "refresh" | "unref") => "object",
        ("Immediate" | "Timeout", "hasRef") => "boolean",
        ("Timeout", "_scheduleNative") => "undefined",
        _ => return None,
    };
    Some((
        serde_json::json!({
            "kind": "timer-owner",
            "ownerExportName": owner,
            "preclosed": method == "_scheduleNative"
        }),
        serde_json::json!([]),
        result_type,
    ))
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
        "noop-function"
        | "event-emitter"
        | "timer-callback"
        | "zlib-flush-callback"
        | "zlib-params-callback"
        | "zlib-transform-callback"
        | "zlib-write-callback" => {
            assert_object_keys(argument, &["kind"], "authored special argument");
        }
        "constant-function" => {
            assert_object_keys(argument, &["kind", "value"], "constant function argument");
            assert!(
                serde_json::to_vec(&object["value"]).unwrap().len() <= 1024,
                "constant function result is unbounded"
            );
        }
        "abort-signal" => {
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
            let flags = object["flags"].as_str().expect("regexp flags must be text");
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
            assert!(
                allow_setup_value,
                "setup value used outside its authored setup"
            );
            assert_object_keys(argument, &["kind", "name"], "setup value argument");
            assert!(matches!(
                object["name"].as_str(),
                Some("tracked" | "peer" | "timerHandle" | "timerRecord")
            ));
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
        "zlib-callback" => {
            assert_object_keys(
                argument,
                &["kind", "resultContract"],
                "zlib callback argument",
            );
            assert!(matches!(
                object["resultContract"].as_str(),
                Some("nonempty-byte-view" | "exact-ibex-byte-view")
            ));
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
        "timer-clear-root" | "timer-factory-root" | "timer-legacy-root" => {
            assert!(!prototype);
            assert_eq!(descriptor.source_key, "node_timers");
            let (expected_setup, _, _) = timer_root_contract(&descriptor.export_name)
                .expect("timer root setup must name a reviewed operation");
            assert_eq!(invocation.setup, expected_setup);
            allow_setup_value = matches!(kind, "timer-clear-root" | "timer-legacy-root");
        }
        "timer-owner" => {
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_timers");
            let (expected_setup, _, _) = timer_prototype_contract(&descriptor.export_name)
                .expect("timer owner setup must name a reviewed operation");
            assert_eq!(invocation.setup, expected_setup);
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                setup["ownerExportName"].as_str()
            );
        }
        "construct-target" => {
            assert_object_keys(&invocation.setup, &["kind"], "target constructor setup");
            if prototype {
                assert!(descriptor.export_name.ends_with(".constructor"));
            }
        }
        "tls-server-construct-target" => {
            assert_object_keys(
                &invocation.setup,
                &["kind"],
                "TLS Server constructor setup",
            );
            assert!(matches!(
                descriptor.source_key.as_str(),
                "node_tls" | "node_https"
            ));
            assert!(matches!(
                descriptor.export_name.as_str(),
                "Server" | "Server.constructor"
            ));
            assert_eq!(
                prototype,
                descriptor.export_name == "Server.constructor"
            );
        }
        "tls-server-root-call" => {
            assert_object_keys(
                &invocation.setup,
                &["kind"],
                "TLS Server root-call setup",
            );
            assert!(!prototype);
            assert!(matches!(
                descriptor.source_key.as_str(),
                "node_tls" | "node_https"
            ));
            assert_eq!(descriptor.export_name, "createServer");
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
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some(owner)
            );
            let constructor_arguments = setup["constructorArguments"]
                .as_array()
                .expect("constructor arguments must be an array");
            assert!(constructor_arguments.len() <= 4);
            for argument in constructor_arguments {
                validate_authored_argument(argument, false);
            }
        }
        "net-terminal-owner" => {
            assert_object_keys(
                &invocation.setup,
                &["kind", "ownerExportName"],
                "net terminal owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_net");
            let owner = setup["ownerExportName"]
                .as_str()
                .expect("net terminal owner name must be text");
            assert!(matches!(owner, "Server" | "Socket" | "Stream"));
            assert!(matches!(
                (owner, descriptor.export_name.as_str()),
                ("Server", "Server.close")
                    | ("Socket", "Socket.close")
                    | ("Socket", "Socket.resetAndDestroy")
                    | ("Stream", "Stream.close")
                    | ("Stream", "Stream.resetAndDestroy")
            ));
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some(owner)
            );
        }
        "key-object-pair-owner" => {
            assert_object_keys(
                &invocation.setup,
                &["bytes", "keyType", "kind", "ownerExportName"],
                "KeyObject pair owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "exact_crypto");
            assert_eq!(setup["ownerExportName"], "KeyObject");
            assert_eq!(setup["keyType"], "secret");
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some("KeyObject")
            );
            validate_byte_array(&setup["bytes"], "KeyObject pair bytes");
            allow_setup_value = true;
        }
        "readline-interface-owner" => {
            assert_object_keys(
                &invocation.setup,
                &["kind", "ownerExportName", "terminal"],
                "readline Interface owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_readline");
            assert_eq!(descriptor.export_name, "Interface.close");
            assert_eq!(setup["ownerExportName"], "Interface");
            assert_eq!(setup["terminal"], false);
            assert_eq!(
                descriptor.access.path,
                ["Interface", "prototype", "close"].map(str::to_owned)
            );
        }
        "readline-interface-pause-owner" => {
            assert_object_keys(
                &invocation.setup,
                &["cleanupMethod", "kind", "ownerExportName", "terminal"],
                "readline Interface pause owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_readline");
            assert_eq!(descriptor.export_name, "Interface.pause");
            assert_eq!(setup["ownerExportName"], "Interface");
            assert_eq!(setup["terminal"], false);
            assert_eq!(setup["cleanupMethod"], "close");
            assert_eq!(
                descriptor.access.path,
                ["Interface", "prototype", "pause"].map(str::to_owned)
            );
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
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some(owner)
            );
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
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some(owner)
            );
            assert!(setup["ensureNativeStream"].is_boolean());
        }
        "zlib-end-owner" => {
            assert_object_keys(
                &invocation.setup,
                &["kind", "outputContract", "ownerExportName"],
                "zlib end owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_zlib");
            let owner = setup["ownerExportName"]
                .as_str()
                .expect("zlib end owner name must be text");
            let (_, output_contract) =
                zlib_end_contract(owner).expect("zlib end owner must be reviewed");
            assert_eq!(setup["outputContract"].as_str(), Some(output_contract));
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some(owner)
            );
        }
        "zlib-process-chunk-owner" => {
            assert_object_keys(
                &invocation.setup,
                &["kind", "outputContract", "ownerExportName"],
                "zlib process-chunk owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_zlib");
            let owner = setup["ownerExportName"]
                .as_str()
                .expect("zlib process-chunk owner name must be text");
            let (_, output_contract) = zlib_process_chunk_contract(owner)
                .expect("zlib process-chunk owner must be reviewed");
            assert_eq!(setup["outputContract"].as_str(), Some(output_contract));
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some(owner)
            );
        }
        "zlib-write-owner" => {
            assert_object_keys(
                &invocation.setup,
                &[
                    "kind",
                    "outputContract",
                    "ownerExportName",
                    "terminalMethod",
                ],
                "zlib write owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_zlib");
            let owner = setup["ownerExportName"]
                .as_str()
                .expect("zlib write owner name must be text");
            let (_, output_contract) =
                zlib_write_contract(owner).expect("zlib write owner must be reviewed");
            assert_eq!(setup["outputContract"].as_str(), Some(output_contract));
            assert_eq!(setup["terminalMethod"], "end");
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some(owner)
            );
        }
        "zlib-flush-owner" => {
            assert_object_keys(
                &invocation.setup,
                &[
                    "callbackPosition",
                    "cleanupMethod",
                    "flushKind",
                    "kind",
                    "ownerExportName",
                ],
                "zlib flush owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_zlib");
            let owner = setup["ownerExportName"]
                .as_str()
                .expect("zlib flush owner name must be text");
            assert!(zlib_flush_owner(owner), "zlib flush owner must be reviewed");
            assert_eq!(setup["callbackPosition"], "first-argument");
            assert_eq!(setup["flushKind"], "default-full-flush");
            assert_eq!(setup["cleanupMethod"], "destroy");
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some(owner)
            );
        }
        "zlib-params-owner" => {
            assert_object_keys(
                &invocation.setup,
                &[
                    "cleanupMethod",
                    "kind",
                    "level",
                    "ownerExportName",
                    "strategy",
                ],
                "zlib params owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_zlib");
            let owner = setup["ownerExportName"]
                .as_str()
                .expect("zlib params owner name must be text");
            assert!(zlib_flush_owner(owner), "zlib params owner must be reviewed");
            assert_eq!(setup["level"], 1);
            assert_eq!(setup["strategy"], 0);
            assert_eq!(setup["cleanupMethod"], "destroy");
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some(owner)
            );
        }
        "zlib-transform-owner" => {
            assert_object_keys(
                &invocation.setup,
                &[
                    "cleanupMethod",
                    "inputLength",
                    "kind",
                    "ownerExportName",
                ],
                "zlib transform owner setup",
            );
            assert!(prototype);
            assert_eq!(descriptor.source_key, "node_zlib");
            let owner = setup["ownerExportName"]
                .as_str()
                .expect("zlib transform owner name must be text");
            let input =
                zlib_transform_input(owner).expect("zlib transform owner must be reviewed");
            assert_eq!(setup["inputLength"], input.len());
            assert_eq!(setup["cleanupMethod"], "destroy");
            assert_eq!(
                descriptor.access.path.first().map(String::as_str),
                Some(owner)
            );
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
            if owner == "default" {
                assert!(is_base_stream_module_value_method(
                    &descriptor.export_name
                ));
                assert_eq!(
                    descriptor.access.path.first().map(String::as_str),
                    Some("prototype")
                );
            } else {
                assert_eq!(
                    descriptor.access.path.first().map(String::as_str),
                    Some(owner)
                );
            }
            assert!(setup["endedInput"].is_boolean());
        }
        other => panic!("unsupported authored builtin setup kind {other}"),
    }
    assert!(invocation.arguments.len() <= 8);
    for argument in &invocation.arguments {
        validate_authored_argument(argument, allow_setup_value);
    }
}

fn validate_explicit_diffie_hellman_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "exact_crypto" {
        return;
    }
    let constructor_arguments = serde_json::json!([
        {"kind": "uint8-array", "bytes": [23]},
        {"kind": "json", "value": 5}
    ]);
    let (expected_setup, expected_arguments, expected_result_type) =
        match descriptor.export_name.as_str() {
            "DiffieHellman" => (
                serde_json::json!({"kind": "construct-target"}),
                constructor_arguments.clone(),
                "object",
            ),
            "createDiffieHellman" => (
                serde_json::json!({"kind": "root-call"}),
                constructor_arguments.clone(),
                "object",
            ),
            "DiffieHellman.getGenerator"
            | "DiffieHellman.getPrime"
            | "DiffieHellman.getPrivateKey"
            | "DiffieHellman.getPublicKey" => (
                serde_json::json!({
                    "kind": "constructed-owner",
                    "ownerExportName": "DiffieHellman",
                    "constructorArguments": constructor_arguments
                }),
                serde_json::json!([]),
                "object",
            ),
            "DiffieHellman.setPrivateKey" | "DiffieHellman.setPublicKey" => (
                serde_json::json!({
                    "kind": "constructed-owner",
                    "ownerExportName": "DiffieHellman",
                    "constructorArguments": constructor_arguments
                }),
                serde_json::json!([
                    {"kind": "uint8-array", "bytes": [3]}
                ]),
                "undefined",
            ),
            _ => return,
        };
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, expected_result_type);
    assert_eq!(invocation.setup, expected_setup);
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        expected_arguments
    );
}

fn validate_x509_state_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "exact_crypto"
        || descriptor.export_name != "X509Certificate.toString"
    {
        return;
    }
    assert_eq!(invocation.template_id.as_deref(), Some("exact-crypto-bounded-v1"));
    assert_eq!(descriptor.access.kind, "prototype-property");
    assert_eq!(
        descriptor.access.path,
        ["X509Certificate", "prototype", "toString"].map(str::to_owned)
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "string");
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "constructed-owner",
            "ownerExportName": "X509Certificate",
            "constructorArguments": [
                {"kind": "json", "value": "ibex-x509-fixture"}
            ],
        })
    );
    assert!(invocation.arguments.is_empty());
}

fn validate_pure_compatibility_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    let (
        module_specifier,
        template_id,
        export_idioms,
        module_specifiers,
        source_ref,
        argument,
        result_type,
    ) = match (
        descriptor.source_key.as_str(),
        descriptor.export_name.as_str(),
    ) {
        ("exact_crypto", "createPrivateKey" | "createPublicKey") => (
            "node:crypto",
            "exact-crypto-bounded-v1",
            vec!["object-binding".to_owned(), "object-source".to_owned()],
            vec![
                "crypto".to_owned(),
                "exact:crypto".to_owned(),
                "node:crypto".to_owned(),
            ],
            format!("src/builtins/crypto.js#exports:{}", descriptor.export_name),
            serde_json::json!({"kind": "json", "value": "ibex-key"}),
            "object",
        ),
        ("node_readline", "CSI") => (
            "node:readline",
            "node-readline-pure-v1",
            vec!["module-exports-object".to_owned()],
            vec![
                "node:readline".to_owned(),
                "node:readline/promises".to_owned(),
                "readline".to_owned(),
                "readline/promises".to_owned(),
            ],
            "src/builtins/readline.js#exports:CSI".to_owned(),
            serde_json::json!({"kind": "json", "value": ["31m"]}),
            "string",
        ),
        _ => return,
    };
    assert_eq!(invocation.module_specifier, module_specifier);
    assert_eq!(invocation.template_id.as_deref(), Some(template_id));
    assert_eq!(descriptor.export_idioms, export_idioms);
    assert_eq!(descriptor.module_specifiers, module_specifiers);
    assert_eq!(descriptor.source_ref, source_ref);
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(descriptor.access.kind, "export-property");
    assert_eq!(descriptor.access.path, [descriptor.export_name.clone()]);
    assert_eq!(invocation.setup, serde_json::json!({"kind": "root-call"}));
    assert_eq!(invocation.arguments, [argument]);
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, result_type);
}

fn validate_key_object_equals_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "exact_crypto" || descriptor.export_name != "KeyObject.equals" {
        return;
    }
    assert_eq!(invocation.module_specifier, "node:crypto");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("exact-crypto-bounded-v1")
    );
    assert_eq!(descriptor.export_idioms, ["exported-constructor-prototype"]);
    assert_eq!(
        descriptor.module_specifiers,
        ["crypto", "exact:crypto", "node:crypto"]
    );
    assert_eq!(
        descriptor.source_ref,
        "src/builtins/crypto.js#exports:KeyObject.equals"
    );
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(descriptor.access.kind, "prototype-property");
    assert_eq!(descriptor.access.path, ["KeyObject", "prototype", "equals"]);
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "key-object-pair-owner",
            "ownerExportName": "KeyObject",
            "keyType": "secret",
            "bytes": [0x69, 0x62, 0x65, 0x78],
        })
    );
    assert_eq!(
        invocation.arguments,
        [serde_json::json!({"kind": "setup-value", "name": "peer"})]
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "boolean");
}

// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
// independently close exact listener-owning readline lifecycle receipts.
fn validate_readline_interface_close_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_readline"
        || descriptor.export_name != "Interface.close"
    {
        return;
    }
    assert_eq!(invocation.module_specifier, "node:readline");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-readline-pure-v1")
    );
    assert_eq!(descriptor.export_idioms, ["exported-constructor-prototype"]);
    assert_eq!(
        descriptor.module_specifiers,
        [
            "node:readline",
            "node:readline/promises",
            "readline",
            "readline/promises",
        ]
    );
    assert_eq!(
        descriptor.source_ref,
        "src/builtins/readline.js#exports:Interface.close"
    );
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(descriptor.access.kind, "prototype-property");
    assert_eq!(
        descriptor.access.path,
        ["Interface", "prototype", "close"].map(str::to_owned)
    );
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "readline-interface-owner",
            "ownerExportName": "Interface",
            "terminal": false,
        })
    );
    assert!(invocation.arguments.is_empty());
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "undefined");
}

fn validate_readline_interface_pause_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_readline"
        || descriptor.export_name != "Interface.pause"
    {
        return;
    }
    assert_eq!(invocation.module_specifier, "node:readline");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-readline-pure-v1")
    );
    assert_eq!(descriptor.export_idioms, ["exported-constructor-prototype"]);
    assert_eq!(
        descriptor.module_specifiers,
        [
            "node:readline",
            "node:readline/promises",
            "readline",
            "readline/promises",
        ]
    );
    assert_eq!(
        descriptor.source_ref,
        "src/builtins/readline.js#exports:Interface.pause"
    );
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(descriptor.access.kind, "prototype-property");
    assert_eq!(
        descriptor.access.path,
        ["Interface", "prototype", "pause"].map(str::to_owned)
    );
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "readline-interface-pause-owner",
            "ownerExportName": "Interface",
            "terminal": false,
            "cleanupMethod": "close",
        })
    );
    assert!(invocation.arguments.is_empty());
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "object");
}

fn validate_base_stream_module_value_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_stream"
        || !is_base_stream_module_value_method(&descriptor.export_name)
    {
        return;
    }
    let (expected_setup, expected_arguments, expected_result_type) =
        match descriptor.export_name.as_str() {
            "default._close" => (
                serde_json::json!({
                    "kind": "stream-owner",
                    "ownerExportName": "default",
                    "endedInput": false
                }),
                serde_json::json!([{"kind": "json", "value": true}]),
                "undefined",
            ),
            "default._emitClose" | "default._undestroy" => (
                serde_json::json!({
                    "kind": "stream-owner",
                    "ownerExportName": "default",
                    "endedInput": false
                }),
                serde_json::json!([]),
                "undefined",
            ),
            "default.constructor" => (
                serde_json::json!({"kind": "construct-target"}),
                serde_json::json!([]),
                "object",
            ),
            "default.destroy" | "default.unpipe" => (
                serde_json::json!({
                    "kind": "stream-owner",
                    "ownerExportName": "default",
                    "endedInput": false
                }),
                serde_json::json!([]),
                "object",
            ),
            _ => unreachable!("base Stream contract set drift"),
        };
    assert_eq!(descriptor.access.kind, "prototype-property");
    assert_eq!(
        descriptor.access.path,
        vec![
            "prototype".to_owned(),
            descriptor
                .export_name
                .split('.')
                .next_back()
                .expect("base Stream method")
                .to_owned()
        ]
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, expected_result_type);
    assert_eq!(invocation.setup, expected_setup);
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        expected_arguments
    );
}

fn validate_idle_zlib_destroy_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_zlib"
        || !descriptor.export_name.ends_with(".destroy")
    {
        return;
    }
    let (owner, method) = descriptor
        .export_name
        .split_once('.')
        .expect("zlib destroy export has owner and method");
    if method != "destroy" || !is_zlib_owner(owner) {
        return;
    }
    assert_eq!(descriptor.access.kind, "inherited-prototype-property");
    assert_eq!(
        descriptor.access.path,
        vec![
            owner.to_owned(),
            "prototype".to_owned(),
            "destroy".to_owned()
        ]
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "object");
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "zlib-owner",
            "ownerExportName": owner,
            "ensureNativeStream": false
        })
    );
    assert!(invocation.arguments.is_empty());
}

fn validate_zlib_end_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_zlib"
        || !descriptor.export_name.ends_with(".end")
    {
        return;
    }
    let (owner, method) = descriptor
        .export_name
        .split_once('.')
        .expect("zlib end export has owner and method");
    let Some((input, output_contract)) = zlib_end_contract(owner) else {
        return;
    };
    assert_eq!(method, "end");
    assert_eq!(invocation.module_specifier, "node:zlib");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-zlib-bounded-v1")
    );
    assert_eq!(descriptor.kind, "builtin-export");
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.source_ref,
        format!("src/builtins/zlib.js#exports:{}", descriptor.export_name)
    );
    assert_eq!(
        descriptor.export_idioms,
        ["exported-constructor-inherited-prototype"]
    );
    assert_eq!(descriptor.module_specifiers, ["node:zlib", "zlib"]);
    assert_eq!(descriptor.access.kind, "inherited-prototype-property");
    assert_eq!(
        descriptor.access.path,
        vec![
            owner.to_owned(),
            "prototype".to_owned(),
            "end".to_owned()
        ]
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "object");
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "zlib-end-owner",
            "ownerExportName": owner,
            "outputContract": output_contract
        })
    );
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        serde_json::json!([{"kind": "buffer", "bytes": input}])
    );
}

fn validate_zlib_process_chunk_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_zlib"
        || !descriptor.export_name.ends_with("._processChunk")
    {
        return;
    }
    let (owner, method) = descriptor
        .export_name
        .split_once('.')
        .expect("zlib process-chunk export has owner and method");
    let Some((input, output_contract)) = zlib_process_chunk_contract(owner) else {
        return;
    };
    assert_eq!(method, "_processChunk");
    assert_eq!(invocation.module_specifier, "node:zlib");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-zlib-bounded-v1")
    );
    assert_eq!(descriptor.kind, "builtin-export");
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.source_ref,
        format!("src/builtins/zlib.js#exports:{}", descriptor.export_name)
    );
    assert_eq!(
        descriptor.export_idioms,
        ["exported-constructor-inherited-prototype"]
    );
    assert_eq!(descriptor.module_specifiers, ["node:zlib", "zlib"]);
    assert_eq!(descriptor.access.kind, "inherited-prototype-property");
    assert_eq!(
        descriptor.access.path,
        vec![
            owner.to_owned(),
            "prototype".to_owned(),
            "_processChunk".to_owned()
        ]
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "object");
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "zlib-process-chunk-owner",
            "ownerExportName": owner,
            "outputContract": output_contract
        })
    );
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        serde_json::json!([
            {"kind": "buffer", "bytes": input},
            {"kind": "json", "value": 4}
        ])
    );
}

fn validate_zlib_write_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_zlib" || !descriptor.export_name.ends_with(".write") {
        return;
    }
    let (owner, method) = descriptor
        .export_name
        .split_once('.')
        .expect("zlib write export has owner and method");
    let Some((input, output_contract)) = zlib_write_contract(owner) else {
        return;
    };
    assert_eq!(method, "write");
    assert_eq!(invocation.module_specifier, "node:zlib");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-zlib-bounded-v1")
    );
    assert_eq!(descriptor.kind, "builtin-export");
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.source_ref,
        format!("src/builtins/zlib.js#exports:{}", descriptor.export_name)
    );
    assert_eq!(
        descriptor.export_idioms,
        ["exported-constructor-inherited-prototype"]
    );
    assert_eq!(descriptor.module_specifiers, ["node:zlib", "zlib"]);
    assert_eq!(descriptor.access.kind, "inherited-prototype-property");
    assert_eq!(
        descriptor.access.path,
        vec![
            owner.to_owned(),
            "prototype".to_owned(),
            "write".to_owned()
        ]
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "boolean");
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "zlib-write-owner",
            "ownerExportName": owner,
            "outputContract": output_contract,
            "terminalMethod": "end"
        })
    );
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        serde_json::json!([
            {"kind": "buffer", "bytes": input},
            {"kind": "zlib-write-callback"}
        ])
    );
}

fn validate_zlib_flush_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_zlib" || !descriptor.export_name.ends_with(".flush") {
        return;
    }
    let (owner, method) = descriptor
        .export_name
        .split_once('.')
        .expect("zlib flush export has owner and method");
    if !zlib_flush_owner(owner) {
        return;
    }
    assert_eq!(method, "flush");
    assert_eq!(invocation.module_specifier, "node:zlib");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-zlib-bounded-v1")
    );
    assert_eq!(descriptor.kind, "builtin-export");
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.source_ref,
        format!("src/builtins/zlib.js#exports:{}", descriptor.export_name)
    );
    assert_eq!(
        descriptor.export_idioms,
        ["exported-constructor-inherited-prototype"]
    );
    assert_eq!(descriptor.module_specifiers, ["node:zlib", "zlib"]);
    assert_eq!(descriptor.access.kind, "inherited-prototype-property");
    assert_eq!(
        descriptor.access.path,
        vec![
            owner.to_owned(),
            "prototype".to_owned(),
            "flush".to_owned()
        ]
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "object");
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "zlib-flush-owner",
            "ownerExportName": owner,
            "callbackPosition": "first-argument",
            "flushKind": "default-full-flush",
            "cleanupMethod": "destroy"
        })
    );
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        serde_json::json!([{"kind": "zlib-flush-callback"}])
    );
}

fn validate_zlib_params_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_zlib" || !descriptor.export_name.ends_with(".params") {
        return;
    }
    let (owner, method) = descriptor
        .export_name
        .split_once('.')
        .expect("zlib params export has owner and method");
    if !zlib_flush_owner(owner) {
        return;
    }
    assert_eq!(method, "params");
    assert_eq!(invocation.module_specifier, "node:zlib");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-zlib-bounded-v1")
    );
    assert_eq!(descriptor.kind, "builtin-export");
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.source_ref,
        format!("src/builtins/zlib.js#exports:{}", descriptor.export_name)
    );
    assert_eq!(
        descriptor.export_idioms,
        ["exported-constructor-inherited-prototype"]
    );
    assert_eq!(descriptor.module_specifiers, ["node:zlib", "zlib"]);
    assert_eq!(descriptor.access.kind, "inherited-prototype-property");
    assert_eq!(
        descriptor.access.path,
        vec![
            owner.to_owned(),
            "prototype".to_owned(),
            "params".to_owned()
        ]
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "object");
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "zlib-params-owner",
            "ownerExportName": owner,
            "level": 1,
            "strategy": 0,
            "cleanupMethod": "destroy"
        })
    );
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        serde_json::json!([
            {"kind": "json", "value": 1},
            {"kind": "json", "value": 0},
            {"kind": "zlib-params-callback"}
        ])
    );
}

fn validate_zlib_transform_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_zlib" || !descriptor.export_name.ends_with("._transform") {
        return;
    }
    let (owner, method) = descriptor
        .export_name
        .split_once('.')
        .expect("zlib transform export has owner and method");
    let Some(input) = zlib_transform_input(owner) else {
        return;
    };
    assert_eq!(method, "_transform");
    assert_eq!(invocation.module_specifier, "node:zlib");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-zlib-bounded-v1")
    );
    assert_eq!(descriptor.kind, "builtin-export");
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.source_ref,
        format!("src/builtins/zlib.js#exports:{}", descriptor.export_name)
    );
    assert_eq!(
        descriptor.export_idioms,
        ["exported-constructor-inherited-prototype"]
    );
    assert_eq!(descriptor.module_specifiers, ["node:zlib", "zlib"]);
    assert_eq!(descriptor.access.kind, "inherited-prototype-property");
    assert_eq!(
        descriptor.access.path,
        vec![
            owner.to_owned(),
            "prototype".to_owned(),
            "_transform".to_owned()
        ]
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "undefined");
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "zlib-transform-owner",
            "ownerExportName": owner,
            "inputLength": input.len(),
            "cleanupMethod": "destroy"
        })
    );
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        serde_json::json!([
            {"kind": "buffer", "bytes": input},
            {"kind": "json", "value": "buffer"},
            {"kind": "zlib-transform-callback"}
        ])
    );
}

fn validate_timer_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_timers" {
        return;
    }
    let root_contract = timer_root_contract(&descriptor.export_name);
    let prototype_contract = timer_prototype_contract(&descriptor.export_name);
    let (setup, arguments, result_type) = root_contract
        .as_ref()
        .or(prototype_contract.as_ref())
        .expect("node:timers call must name an exact reviewed contract");
    let prototype = prototype_contract.is_some();
    assert_eq!(invocation.module_specifier, "node:timers");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-timers-bounded-v1")
    );
    assert_eq!(descriptor.kind, "builtin-export");
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.source_ref,
        format!(
            "src/builtins/timers.js#exports:{}",
            descriptor.export_name
        )
    );
    assert_eq!(descriptor.module_specifiers, ["node:timers", "timers"]);
    assert_eq!(
        descriptor.export_idioms,
        if prototype {
            vec!["exported-constructor-prototype".to_owned()]
        } else {
            vec!["module-exports-object".to_owned()]
        }
    );
    assert_eq!(
        descriptor.access.kind,
        if prototype {
            "prototype-property"
        } else {
            "export-property"
        }
    );
    let expected_path = if prototype {
        let (owner, method) = descriptor
            .export_name
            .split_once('.')
            .expect("reviewed timer prototype has owner and method");
        vec![
            owner.to_owned(),
            "prototype".to_owned(),
            method.to_owned(),
        ]
    } else {
        vec![descriptor.export_name.clone()]
    };
    assert_eq!(descriptor.access.path, expected_path);
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, *result_type);
    assert_eq!(&invocation.setup, setup);
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        *arguments
    );
}

fn validate_zlib_sync_encoder_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_zlib"
        || !is_zlib_sync_encoder(&descriptor.export_name)
    {
        return;
    }
    assert_eq!(invocation.module_specifier, "node:zlib");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-zlib-bounded-v1")
    );
    assert_eq!(descriptor.kind, "builtin-export");
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.export_idioms,
        ["object-binding", "object-source"]
    );
    assert_eq!(descriptor.module_specifiers, ["node:zlib", "zlib"]);
    assert_eq!(
        descriptor.source_ref,
        format!("src/builtins/zlib.js#exports:{}", descriptor.export_name)
    );
    assert_eq!(descriptor.access.kind, "export-property");
    assert_eq!(descriptor.access.path, [descriptor.export_name.clone()]);
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "object");
    assert_eq!(invocation.setup, serde_json::json!({"kind": "root-call"}));
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        serde_json::json!([
            {"kind": "buffer", "bytes": [105, 98, 101, 120]}
        ])
    );
}

fn validate_zlib_sync_decoder_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    let Some(input) = (descriptor.source_key == "node_zlib")
        .then(|| zlib_sync_decoder_input(&descriptor.export_name))
        .flatten()
    else {
        return;
    };
    assert_eq!(invocation.module_specifier, "node:zlib");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-zlib-bounded-v1")
    );
    assert_eq!(descriptor.kind, "builtin-export");
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.export_idioms,
        ["object-binding", "object-source"]
    );
    assert_eq!(descriptor.module_specifiers, ["node:zlib", "zlib"]);
    assert_eq!(
        descriptor.source_ref,
        format!("src/builtins/zlib.js#exports:{}", descriptor.export_name)
    );
    assert_eq!(descriptor.access.kind, "export-property");
    assert_eq!(descriptor.access.path, [descriptor.export_name.clone()]);
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "object");
    assert_eq!(invocation.setup, serde_json::json!({"kind": "root-call"}));
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        serde_json::json!([{"kind": "buffer", "bytes": input}])
    );
}

fn validate_zlib_callback_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    let has_callback_argument = invocation.arguments.iter().any(|argument| {
        argument
            .get("kind")
            .and_then(serde_json::Value::as_str)
            == Some("zlib-callback")
    });
    let contract = (descriptor.source_key == "node_zlib")
        .then(|| zlib_callback_contract(&descriptor.export_name))
        .flatten();
    let Some((input, result_contract)) = contract else {
        assert!(
            !has_callback_argument,
            "zlib callback credential escaped its reviewed operation"
        );
        return;
    };
    assert!(has_callback_argument);
    assert_eq!(invocation.module_specifier, "node:zlib");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-zlib-bounded-v1")
    );
    assert_eq!(descriptor.kind, "builtin-export");
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.export_idioms,
        ["object-binding", "object-source"]
    );
    assert_eq!(descriptor.module_specifiers, ["node:zlib", "zlib"]);
    assert_eq!(
        descriptor.source_ref,
        format!("src/builtins/zlib.js#exports:{}", descriptor.export_name)
    );
    assert_eq!(descriptor.access.kind, "export-property");
    assert_eq!(descriptor.access.path, [descriptor.export_name.clone()]);
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "undefined");
    assert_eq!(invocation.setup, serde_json::json!({"kind": "root-call"}));
    assert_eq!(
        serde_json::Value::Array(invocation.arguments.clone()),
        serde_json::json!([
            {"kind": "buffer", "bytes": input},
            {"kind": "zlib-callback", "resultContract": result_contract}
        ])
    );
}

fn validate_idle_net_terminal_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
    if descriptor.source_key != "node_net"
        || !matches!(
            descriptor.export_name.as_str(),
            "Server.close"
                | "Socket.close"
                | "Socket.resetAndDestroy"
                | "Stream.close"
                | "Stream.resetAndDestroy"
        )
    {
        return;
    }
    let (owner, method) = descriptor
        .export_name
        .split_once('.')
        .expect("net terminal export has owner and method");
    assert!(matches!(owner, "Server" | "Socket" | "Stream"));
    assert!(
        method == "close"
            || (matches!(owner, "Socket" | "Stream")
                && method == "resetAndDestroy")
    );
    assert_eq!(invocation.module_specifier, "node:net");
    assert_eq!(
        invocation.template_id.as_deref(),
        Some("node-net-bounded-v1")
    );
    assert_eq!(
        descriptor.export_idioms,
        vec!["exported-constructor-prototype".to_owned()]
    );
    assert_eq!(
        descriptor.module_specifiers,
        ["net", "node:net"].map(str::to_owned)
    );
    assert_eq!(
        descriptor.source_ref,
        format!("src/builtins/net.js#exports:{}", descriptor.export_name)
    );
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(descriptor.access.kind, "prototype-property");
    assert_eq!(
        descriptor.access.path,
        [owner, "prototype", method].map(str::to_owned)
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "object");
    assert_eq!(
        invocation.setup,
        serde_json::json!({
            "kind": "net-terminal-owner",
            "ownerExportName": owner
        })
    );
    assert!(invocation.arguments.is_empty());
}

fn validate_bounded_http_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
    if descriptor.source_key != "node_http" {
        return;
    }
    let (expected_setup, expected_arguments, expected_result_type) =
        match descriptor.export_name.as_str() {
            "_checkInvalidHeaderChar" => (
                serde_json::json!({"kind": "root-call"}),
                vec![serde_json::json!({"kind": "json", "value": "ibex"})],
                "boolean",
            ),
            "_checkIsHttpToken" => (
                serde_json::json!({"kind": "root-call"}),
                vec![serde_json::json!({"kind": "json", "value": "x-ibex"})],
                "boolean",
            ),
            "Agent.destroy" => (
                serde_json::json!({
                    "kind": "constructed-owner",
                    "ownerExportName": "Agent",
                    "constructorArguments": []
                }),
                vec![],
                "undefined",
            ),
            "Server" | "Server.constructor" => (
                serde_json::json!({"kind": "construct-target"}),
                vec![],
                "object",
            ),
            "Server.close" => (
                serde_json::json!({
                    "kind": "constructed-owner",
                    "ownerExportName": "Server",
                    "constructorArguments": []
                }),
                vec![],
                "object",
            ),
            "Server.closeAllConnections" | "Server.closeIdleConnections" => (
                serde_json::json!({
                    "kind": "constructed-owner",
                    "ownerExportName": "Server",
                    "constructorArguments": []
                }),
                vec![],
                "undefined",
            ),
            "Server.ref" | "Server.unref" => (
                serde_json::json!({
                    "kind": "constructed-owner",
                    "ownerExportName": "Server",
                    "constructorArguments": []
                }),
                vec![],
                "object",
            ),
            "createServer" => (
                serde_json::json!({"kind": "root-call"}),
                vec![],
                "object",
            ),
            "validateHeaderName" => (
                serde_json::json!({"kind": "root-call"}),
                vec![serde_json::json!({"kind": "json", "value": "x-ibex"})],
                "undefined",
            ),
            "validateHeaderValue" => (
                serde_json::json!({"kind": "root-call"}),
                vec![
                    serde_json::json!({"kind": "json", "value": "x-ibex"}),
                    serde_json::json!({"kind": "json", "value": "ibex"}),
                ],
                "undefined",
            ),
            other => panic!("unsupported bounded HTTP call {other}"),
        };
    let segments = descriptor.export_name.split('.').collect::<Vec<_>>();
    let prototype = segments.len() == 2;
    assert!(matches!(segments.len(), 1 | 2));
    assert_eq!(
        descriptor.export_idioms,
        vec![if prototype {
            "exported-constructor-prototype".to_owned()
        } else {
            "module-exports-object".to_owned()
        }]
    );
    assert_eq!(
        descriptor.module_specifiers,
        [
            "_http_agent",
            "_http_common",
            "_http_incoming",
            "_http_outgoing",
            "_http_server",
            "http",
            "node:http",
        ]
        .map(str::to_owned)
    );
    assert_eq!(
        descriptor.source_ref,
        format!("src/builtins/http.js#exports:{}", descriptor.export_name)
    );
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.access.kind,
        if prototype {
            "prototype-property"
        } else {
            "export-property"
        }
    );
    assert_eq!(
        descriptor.access.path,
        if prototype {
            vec![
                segments[0].to_owned(),
                "prototype".to_owned(),
                segments[1].to_owned(),
            ]
        } else {
            vec![segments[0].to_owned()]
        }
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, expected_result_type);
    assert_eq!(invocation.setup, expected_setup);
    assert_eq!(invocation.arguments, expected_arguments);
}

fn validate_idle_tls_socket_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if descriptor.source_key != "node_tls"
        || matches!(
            descriptor.export_name.as_str(),
            "getCiphers" | "Server" | "Server.constructor" | "createServer"
        )
    {
        return;
    }
    let expected_setup = match descriptor.export_name.as_str() {
        "TLSSocket" => serde_json::json!({"kind": "construct-target"}),
        "TLSSocket.close" | "TLSSocket.destroy" | "TLSSocket.ref" | "TLSSocket.unref" => {
            serde_json::json!({
                "kind": "constructed-owner",
                "ownerExportName": "TLSSocket",
                "constructorArguments": []
            })
        }
        other => panic!("unsupported idle TLS socket call {other}"),
    };
    let segments = descriptor.export_name.split('.').collect::<Vec<_>>();
    let prototype = segments.len() == 2;
    assert!(matches!(segments.len(), 1 | 2));
    assert_eq!(invocation.module_specifier, "node:tls");
    assert_eq!(
        descriptor.export_idioms,
        vec![if prototype {
            "exported-constructor-prototype".to_owned()
        } else {
            "module-exports-object".to_owned()
        }]
    );
    assert_eq!(
        descriptor.module_specifiers,
        ["node:tls", "tls"].map(str::to_owned)
    );
    assert_eq!(
        descriptor.source_ref,
        format!(
            "src/builtins/tls.js#exports:{}",
            descriptor.export_name
        )
    );
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.access.kind,
        if prototype {
            "prototype-property"
        } else {
            "export-property"
        }
    );
    assert_eq!(
        descriptor.access.path,
        if prototype {
            vec![
                "TLSSocket".to_owned(),
                "prototype".to_owned(),
                segments[1].to_owned(),
            ]
        } else {
            vec!["TLSSocket".to_owned()]
        }
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "object");
    assert_eq!(invocation.setup, expected_setup);
    assert!(invocation.arguments.is_empty());
}

fn validate_idle_tls_server_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    if !matches!(descriptor.source_key.as_str(), "node_tls" | "node_https")
        || !matches!(
            descriptor.export_name.as_str(),
            "Server" | "Server.constructor" | "createServer"
        )
    {
        return;
    }
    let https = descriptor.source_key == "node_https";
    let prototype = descriptor.export_name == "Server.constructor";
    let expected_setup = if descriptor.export_name == "createServer" {
        serde_json::json!({"kind": "tls-server-root-call"})
    } else {
        serde_json::json!({"kind": "tls-server-construct-target"})
    };
    assert_eq!(
        invocation.module_specifier,
        if https { "node:https" } else { "node:tls" }
    );
    assert_eq!(
        invocation.template_id.as_deref(),
        Some(if https {
            "node-https-idle-v1"
        } else {
            "node-tls-pure-v1"
        })
    );
    assert_eq!(
        descriptor.export_idioms,
        vec![if prototype {
            "exported-constructor-prototype".to_owned()
        } else if https {
            "member-assignment".to_owned()
        } else {
            "module-exports-object".to_owned()
        }]
    );
    assert_eq!(
        descriptor.module_specifiers,
        if https {
            ["https", "node:https"].map(str::to_owned)
        } else {
            ["node:tls", "tls"].map(str::to_owned)
        }
    );
    assert_eq!(
        descriptor.source_ref,
        format!(
            "src/builtins/{}#exports:{}",
            if https { "https.js" } else { "tls.js" },
            descriptor.export_name
        )
    );
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.access.kind,
        if prototype {
            "prototype-property"
        } else {
            "export-property"
        }
    );
    assert_eq!(
        descriptor.access.path,
        if prototype {
            ["Server", "prototype", "constructor"].map(str::to_owned).to_vec()
        } else {
            vec![descriptor.export_name.clone()]
        }
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(proof.result_type, "object");
    assert_eq!(invocation.setup, expected_setup);
    assert!(invocation.arguments.is_empty());
}

fn validate_idle_dgram_contract(
    invocation: &BuiltinInvocation,
    descriptor: &BuiltinSourceDescriptor,
    proof: &BodyEntryProof,
) {
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
    if descriptor.source_key != "node_dgram" {
        return;
    }
    let udp4_argument = serde_json::json!({"kind": "json", "value": "udp4"});
    let (expected_setup, expected_arguments) = match descriptor.export_name.as_str() {
        "Socket" | "Socket.constructor" => (
            serde_json::json!({"kind": "construct-target"}),
            vec![udp4_argument],
        ),
        "Socket.close" | "Socket.ref" | "Socket.unref" => (
            serde_json::json!({
                "kind": "constructed-owner",
                "ownerExportName": "Socket",
                "constructorArguments": [udp4_argument]
            }),
            Vec::new(),
        ),
        "Socket.dropMembership" => (
            serde_json::json!({
                "kind": "constructed-owner",
                "ownerExportName": "Socket",
                "constructorArguments": [udp4_argument]
            }),
            vec![serde_json::json!({
                "kind": "json",
                "value": "224.0.0.1"
            })],
        ),
        "createSocket" => (
            serde_json::json!({"kind": "root-call"}),
            vec![udp4_argument],
        ),
        other => panic!("unsupported idle UDP socket call {other}"),
    };
    let segments = descriptor.export_name.split('.').collect::<Vec<_>>();
    let prototype = segments.len() == 2;
    assert!(matches!(segments.len(), 1 | 2));
    assert_eq!(invocation.module_specifier, "node:dgram");
    assert_eq!(
        descriptor.export_idioms,
        vec![if prototype {
            "exported-constructor-prototype".to_owned()
        } else {
            "module-exports-object".to_owned()
        }]
    );
    assert_eq!(
        descriptor.module_specifiers,
        ["dgram", "node:dgram"].map(str::to_owned)
    );
    assert_eq!(
        descriptor.source_ref,
        format!(
            "src/builtins/dgram.js#exports:{}",
            descriptor.export_name
        )
    );
    assert_eq!(descriptor.value_shape, "callable");
    assert_eq!(
        descriptor.access.kind,
        if prototype {
            "prototype-property"
        } else {
            "export-property"
        }
    );
    assert_eq!(
        descriptor.access.path,
        if prototype {
            vec![
                segments[0].to_owned(),
                "prototype".to_owned(),
                segments[1].to_owned(),
            ]
        } else {
            vec![segments[0].to_owned()]
        }
    );
    assert_eq!(proof.kind, "normal-return-from-source-call");
    assert_eq!(
        proof.result_type,
        if descriptor.export_name == "Socket.dropMembership" {
            "undefined"
        } else {
            "object"
        }
    );
    assert_eq!(invocation.setup, expected_setup);
    assert_eq!(invocation.arguments, expected_arguments);
}

fn expected_template_id(source_key: &str) -> Option<&'static str> {
    match source_key {
        "exact_crypto" => Some("exact-crypto-bounded-v1"),
        "node_assert" => Some("node-assert-bounded-v1"),
        "node_buffer" => Some("node-buffer-bounded-v1"),
        "node_dgram" => Some("node-dgram-idle-v1"),
        "node_dns" => Some("node-dns-pure-v1"),
        "node_fs" => Some("node-fs-pure-v1"),
        "node_http" => Some("node-http-idle-v1"),
        "node_http2" => Some("node-http2-pure-v1"),
        "node_https" => Some("node-https-idle-v1"),
        "node_events" => Some("node-events-bounded-v1"),
        "node_module" => Some("node-module-pure-v1"),
        "node_net" => Some("node-net-bounded-v1"),
        "node_perf_hooks" => Some("node-perf-hooks-bounded-v1"),
        "node_path" => Some("node-path-pure-v1"),
        "node_punycode" => Some("node-punycode-pure-v1"),
        "node_querystring" => Some("node-querystring-pure-v1"),
        "node_readline" => Some("node-readline-pure-v1"),
        "node_stream" => Some("node-stream-bounded-v1"),
        "node_stream_web" => Some("node-stream-web-pure-v1"),
        "node_string_decoder" => Some("node-string-decoder-bounded-v1"),
        "node_timers" => Some("node-timers-bounded-v1"),
        "node_tls" => Some("node-tls-pure-v1"),
        "node_url" => Some("node-url-pure-v1"),
        "node_util" => Some("node-util-pure-v1"),
        "node_v8" => Some("node-v8-pure-v1"),
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
    let is_module_import = invocation.invocation_schema
        == "ibex/capsec-builtin-module-import-no-effect-invocation/1"
        && invocation.kind == "builtin-module-import";
    let is_captured = invocation.invocation_schema == CAPTURED_INVOCATION_SCHEMA
        && invocation.kind == "builtin-noncap-captured-call";
    assert!(
        is_read || is_call || is_module_import || is_captured,
        "unsupported non-capability builtin probe"
    );
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert!(invocation.allowed_coverage_edge_ids.is_empty());
    assert!(invocation.expected_action_ids.is_empty());
    assert!(invocation.required_authority.is_empty());
    assert_eq!(invocation.completion.kind, EVENT_LOOP_COMPLETION_KIND);
    assert_eq!(
        invocation.completion.timeout_milliseconds,
        EVENT_LOOP_COMPLETION_TIMEOUT_MS
    );

    if is_captured {
        let captured = invocation
            .captured_output_invocation
            .as_ref()
            .expect("captured builtin probe has no output invocation");
        let descriptor = &invocation.source_descriptor;
        assert_eq!(
            captured["invocationSchema"],
            "ibex/capsec-builtin-noncap-closed-output-invocation/1"
        );
        assert_eq!(captured["kind"], "builtin-noncap-closed-output");
        assert_eq!(captured["coverageClassification"], "non-capability");
        assert_eq!(captured["coverageEdgeId"], recipe.edge_ids[0]);
        assert_eq!(captured["surfaceObservedKey"], probe.surface_observed_key);
        assert_eq!(captured["moduleSpecifier"], invocation.module_specifier);
        assert_eq!(captured["sourceDescriptor"], *descriptor);
        assert_eq!(
            captured["sourceDescriptorDigest"],
            invocation.source_descriptor_digest
        );
        assert_eq!(
            tagged_jcs_digest(descriptor),
            invocation.source_descriptor_digest
        );
        assert_eq!(descriptor["kind"], "builtin-export");
        assert_eq!(descriptor["importReachability"], "public");
        assert_eq!(
            descriptor["exportName"].as_str(),
            invocation.export_name.as_deref()
        );
        assert!(descriptor["moduleSpecifiers"]
            .as_array()
            .is_some_and(|specifiers| specifiers
                .iter()
                .any(|specifier| specifier == &invocation.module_specifier)));
        assert!(matches!(
            captured["route"]["operation"].as_str(),
            Some("call" | "construct" | "get")
        ));
        assert_eq!(
            captured["route"]["outcomeCapture"],
            "public-builtin-family"
        );
        assert_eq!(
            captured["completion"],
            serde_json::to_value(&invocation.completion)
                .expect("serialize captured builtin completion")
        );
        assert!(invocation.template_id.is_none());
        assert!(invocation.body_entry_proof.is_none());
        assert!(invocation.arguments.is_empty());
        assert_eq!(
            invocation.setup,
            serde_json::json!({"kind": "captured-output-route"})
        );
        assert_eq!(invocation.expected_result, "captured-source-return");
        validate_probe_binding(recipe, probe, invocation);
        return;
    }

    assert!(invocation.captured_output_invocation.is_none());
    if is_module_import {
        let descriptor: BuiltinModuleAliasSourceDescriptor =
            serde_json::from_value(invocation.source_descriptor.clone())
                .expect("non-capability builtin module descriptor must be exact");
        let (expected_source_key, expected_module_builtin, expected_root_type) =
            reviewed_noncap_module_alias(&descriptor.module_specifier).unwrap_or_else(|| {
                panic!(
                    "unsupported non-capability builtin module alias {}",
                    descriptor.module_specifier
                )
            });
        assert_eq!(descriptor.kind, "builtin-module-alias");
        assert_eq!(descriptor.module_specifier, invocation.module_specifier);
        assert_eq!(descriptor.source_key, expected_source_key);
        assert_eq!(
            descriptor.source_ref,
            format!("modules.ts#specifiers:{expected_source_key}")
        );
        assert_eq!(descriptor.source_metadata.source_key, expected_source_key);
        assert!(descriptor.source_metadata.bundle_external);
        assert_eq!(descriptor.source_metadata.import_reachability, "public");
        assert_eq!(
            descriptor.source_metadata.module_builtin,
            expected_module_builtin
        );
        assert_eq!(descriptor.expected_root_type, expected_root_type);
        assert_eq!(recipe.edge_ids, vec![descriptor.carrier_edge_id.clone()]);
        assert!(invocation.export_name.is_none());
        assert!(invocation.template_id.is_none());
        assert!(invocation.body_entry_proof.is_none());
        assert!(invocation.arguments.is_empty());
        assert_eq!(invocation.setup, serde_json::json!({"kind": "none"}));
        assert_eq!(invocation.expected_result, "return");
        assert_eq!(
            probe.surface_observed_key,
            format!("builtin:{}", invocation.module_specifier)
        );
        assert_eq!(
            recipe.route.alternatives[0].proof_paths,
            vec![probe.surface_observed_key.clone()]
        );
        validate_probe_binding(recipe, probe, invocation);
        return;
    }

    let descriptor: BuiltinSourceDescriptor =
        serde_json::from_value(invocation.source_descriptor.clone())
            .expect("non-capability builtin source descriptor must be typed");
    assert_eq!(descriptor.kind, "builtin-export");
    assert!(!descriptor.source_key.is_empty());
    assert!(
        descriptor.source_key != "node_os"
            || is_reviewed_post_initialization_value_descriptor(&descriptor)
    );
    assert_eq!(
        invocation.export_name.as_deref(),
        Some(descriptor.export_name.as_str())
    );
    assert!(!descriptor.source_ref.is_empty());
    if invocation.expected_result == "absent" {
        assert!(descriptor.platform_availability.is_some());
    }
    if let Some(platforms) = descriptor.platform_availability.as_deref() {
        assert!(!platforms.is_empty());
        assert!(is_sorted_set(platforms));
        assert!(platforms
            .iter()
            .all(|platform| matches!(platform.as_str(), "android" | "darwin" | "linux")));
        if invocation.expected_result == "absent" {
            assert!(!platforms.iter().any(|platform| platform == "darwin"));
        } else {
            assert!(platforms.iter().any(|platform| platform == "darwin"));
        }
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
        assert!(matches!(
            invocation.expected_result.as_str(),
            "return" | "absent"
        ));
        assert!(invocation.template_id.is_none());
        assert!(invocation.body_entry_proof.is_none());
        assert!(invocation.arguments.is_empty());
        let constructed_instance_read =
            descriptor.access.kind == "constructed-instance-property";
        if descriptor.source_key == "node_stream" && constructed_instance_read {
            let owner = descriptor
                .export_name
                .split_once('.')
                .expect("stream instance read must name its owner")
                .0;
            assert_eq!(
                invocation.setup,
                serde_json::json!({
                    "kind": "stream-owner",
                    "ownerExportName": owner,
                    "endedInput": false,
                })
            );
        } else if descriptor.source_key == "exact_crypto" && constructed_instance_read {
            assert_eq!(descriptor.export_name, "X509Certificate.raw");
            assert_eq!(
                invocation.setup,
                serde_json::json!({
                    "kind": "constructed-owner",
                    "ownerExportName": "X509Certificate",
                    "constructorArguments": [
                        {"kind": "json", "value": "ibex-x509-fixture"}
                    ],
                })
            );
        } else if descriptor.source_key == "node_tls" && constructed_instance_read {
            assert!(is_reviewed_tls_secure_context_instance_descriptor(
                &descriptor
            ));
            assert_eq!(
                invocation.setup,
                serde_json::json!({
                    "kind": "constructed-owner",
                    "ownerExportName": "SecureContext",
                    "constructorArguments": [],
                })
            );
        } else if descriptor.source_key == "node_dgram" && constructed_instance_read {
            assert!(is_reviewed_dgram_socket_closed_instance_descriptor(
                &descriptor
            ));
            assert_eq!(
                invocation.setup,
                serde_json::json!({
                    "kind": "constructed-owner",
                    "ownerExportName": "Socket",
                    "constructorArguments": [
                        {"kind": "json", "value": "udp4"}
                    ],
                })
            );
        } else {
            assert_eq!(invocation.setup, serde_json::json!({"kind": "none"}));
        }
        let reviewed_runtime_typed_read =
            is_reviewed_dns_promise_error_descriptor(&descriptor)
                || is_reviewed_post_initialization_value_descriptor(&descriptor)
                || is_reviewed_tls_secure_context_instance_descriptor(&descriptor)
                || is_reviewed_dgram_socket_closed_instance_descriptor(&descriptor);
        assert!(
            reviewed_runtime_typed_read
                || (matches!(descriptor.value_shape.as_str(), "accessor" | "data")
                    && descriptor.expected_value_type.is_none())
        );
        if reviewed_runtime_typed_read {
            assert!(matches!(
                descriptor.access.kind.as_str(),
                "export-property"
                    | "module-value"
                    | "prototype-property"
                    | "inherited-prototype-property"
                    | "constructed-instance-property"
            ));
        } else {
            assert!(matches!(
                descriptor.access.kind.as_str(),
                "export-property" | "module-value"
            ));
            if descriptor.value_shape == "accessor" {
                assert_eq!(descriptor.access.kind, "export-property");
            }
        }
    } else {
        assert_eq!(invocation.expected_result, "normal-return");
        assert_eq!(descriptor.value_shape, "callable");
        assert!(descriptor.expected_value_type.is_none());
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
        assert!(matches!(
            proof.kind.as_str(),
            "normal-return-from-source-call" | "settled-return-from-source-call"
        ));
        if proof.kind == "settled-return-from-source-call" {
            assert_eq!(descriptor.source_key, "node_stream");
            assert_eq!(invocation.setup["kind"], "stream-owner");
            assert_eq!(invocation.setup["endedInput"], true);
            let (owner, method) = descriptor
                .export_name
                .split_once('.')
                .expect("settled stream consumer must name one owner and method");
            assert!(matches!(
                owner,
                "Duplex" | "PassThrough" | "Readable" | "Transform"
            ));
            assert_eq!(invocation.setup["ownerExportName"], owner);
            let (arguments, result_type) = match method {
                "every" | "some" => (
                    serde_json::json!([{"kind": "constant-function", "value": true}]),
                    "boolean",
                ),
                "find" => (
                    serde_json::json!([{"kind": "constant-function", "value": true}]),
                    "undefined",
                ),
                "forEach" => (
                    serde_json::json!([{"kind": "noop-function"}]),
                    "undefined",
                ),
                "reduce" => (
                    serde_json::json!([
                        {"kind": "constant-function", "value": "ibex"},
                        {"kind": "json", "value": "ibex-initial"}
                    ]),
                    "string",
                ),
                "toArray" => (serde_json::json!([]), "object"),
                other => panic!("unsupported settled stream consumer {other}"),
            };
            assert_eq!(
                serde_json::Value::Array(invocation.arguments.clone()),
                arguments
            );
            assert_eq!(proof.result_type, result_type);
        }
        validate_explicit_diffie_hellman_contract(invocation, &descriptor, proof);
        validate_x509_state_contract(invocation, &descriptor, proof);
        validate_pure_compatibility_contract(invocation, &descriptor, proof);
        validate_key_object_equals_contract(invocation, &descriptor, proof);
        validate_readline_interface_close_contract(
            invocation,
            &descriptor,
            proof,
        );
        validate_readline_interface_pause_contract(
            invocation,
            &descriptor,
            proof,
        );
        validate_base_stream_module_value_contract(invocation, &descriptor, proof);
        validate_idle_zlib_destroy_contract(invocation, &descriptor, proof);
        validate_zlib_end_contract(invocation, &descriptor, proof);
        validate_zlib_process_chunk_contract(invocation, &descriptor, proof);
        validate_zlib_write_contract(invocation, &descriptor, proof);
        validate_zlib_flush_contract(invocation, &descriptor, proof);
        validate_zlib_params_contract(invocation, &descriptor, proof);
        validate_zlib_transform_contract(invocation, &descriptor, proof);
        validate_timer_contract(invocation, &descriptor, proof);
        validate_zlib_sync_encoder_contract(invocation, &descriptor, proof);
        validate_zlib_sync_decoder_contract(invocation, &descriptor, proof);
        validate_zlib_callback_contract(invocation, &descriptor, proof);
        validate_idle_net_terminal_contract(invocation, &descriptor, proof);
        validate_bounded_http_contract(invocation, &descriptor, proof);
        validate_idle_tls_socket_contract(invocation, &descriptor, proof);
        validate_idle_tls_server_contract(invocation, &descriptor, proof);
        validate_idle_dgram_contract(invocation, &descriptor, proof);
        assert!(matches!(
            proof.result_type.as_str(),
            "bigint"
                | "boolean"
                | "function"
                | "null"
                | "number"
                | "object"
                | "string"
                | "undefined"
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

fn public_probe(recipe: &Recipe) -> Option<PublicSurfaceProbe> {
    if recipe.classification != "non-capability"
        || recipe.scenario != "non-capability"
        || !recipe.action_ids.is_empty()
    {
        return None;
    }
    let value = recipe.public_surface_probe.as_ref()?;
    let schema = value["invocation"]["invocationSchema"].as_str()?;
    let kind = value["invocation"]["kind"].as_str()?;
    if !matches!(
        (schema, kind),
        (
            "ibex/capsec-builtin-export-invocation/1",
            "builtin-export-read"
        ) | (
            "ibex/capsec-builtin-call-invocation/1",
            "builtin-export-call"
        ) | (
            "ibex/capsec-builtin-module-import-no-effect-invocation/1",
            "builtin-module-import"
        ) | (
            CAPTURED_INVOCATION_SCHEMA,
            "builtin-noncap-captured-call"
        )
    ) {
        return None;
    }
    Some(
        serde_json::from_value(value.clone())
            .expect("selected non-capability builtin probe must match its typed schema"),
    )
}

fn noncap_builtin_recipes(catalog: &RecipeCatalog) -> Vec<&Recipe> {
    catalog
        .recipes
        .iter()
        .filter(|recipe| recipe.status == "fully-executable" && public_probe(recipe).is_some())
        .inspect(|recipe| validate_probe(recipe, &public_probe(recipe).unwrap()))
        .collect()
}

fn loader_public_probe(recipe: &Recipe) -> Option<LoaderPublicSurfaceProbe> {
    if recipe.classification != "non-capability"
        || recipe.scenario != "non-capability"
        || !recipe.action_ids.is_empty()
    {
        return None;
    }
    let value = recipe.public_surface_probe.as_ref()?;
    if value["invocation"]["invocationSchema"] != LOADER_CAPTURED_INVOCATION_SCHEMA
        || value["invocation"]["kind"] != "module-loader-captured-route"
    {
        return None;
    }
    Some(
        serde_json::from_value(value.clone())
            .expect("selected module-loader probe must match its typed schema"),
    )
}

fn expected_loader_execution_point(surface_name: &str, evidence_type: Option<&str>) -> Option<String> {
    let _ = evidence_type;
    match surface_name {
        "function:javascript:checkImportGate" => {
            Some("function:javascript:checkImportGate".to_owned())
        }
        "function:javascript:__exactResolvedPath" => {
            Some("function:javascript:__exactResolvedPath".to_owned())
        }
        "function:javascript:idToModuleId" => {
            Some("function:javascript:idToModuleId".to_owned())
        }
        "function:javascript:privateBridgesForBuiltin" => {
            Some("function:javascript:privateBridgesForBuiltin".to_owned())
        }
        "function:javascript:privateResolverPath" => {
            Some("function:javascript:privateResolverPath".to_owned())
        }
        "function:javascript:rejectRuntimeLoaderOptions" | "import-needs" => {
            Some("function:javascript:rejectRuntimeLoaderOptions".to_owned())
        }
        "function:javascript:resolverVirtualPath" => {
            Some("function:javascript:resolverVirtualPath".to_owned())
        }
        "function:javascript:stripViteImportQuery" => {
            Some("function:javascript:stripViteImportQuery".to_owned())
        }
        "import-policy-bare" => {
            Some("function:javascript:checkImportGate".to_owned())
        }
        "internal-route:assert/strict" => {
            Some("internal-route:assert/strict".to_owned())
        }
        "internal-route:internal/fs/utils" => {
            Some("internal-route:internal/fs/utils".to_owned())
        }
        "kind:builtin" => Some("kind:builtin".to_owned()),
        _ => None,
    }
}

fn validate_loader_probe(recipe: &Recipe, probe: &LoaderPublicSurfaceProbe) {
    let invocation = &probe.invocation;
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(
        probe.command
            .iter()
            .any(|part| part == "capsec_public_loader_recipe_batch"),
        "{}: loader probe command does not select the reviewed batch",
        recipe.fixture_id
    );
    assert_eq!(recipe.edge_ids, vec![invocation.coverage_edge_id.clone()]);
    assert_eq!(invocation.coverage_classification, "non-capability");
    assert_eq!(
        invocation.allowed_coverage_edge_ids,
        vec![invocation.coverage_edge_id.clone()]
    );
    assert!(invocation.required_authority.is_empty());
    assert!(invocation.expected_action_ids.is_empty());
    assert!(invocation.expected_typed_stages.is_empty());
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert_eq!(invocation.expected_result, "source-completion");
    assert_eq!(invocation.completion.kind, EVENT_LOOP_COMPLETION_KIND);
    assert_eq!(
        invocation.completion.timeout_milliseconds,
        EVENT_LOOP_COMPLETION_TIMEOUT_MS
    );
    assert_eq!(
        tagged_jcs_digest(&invocation.source_descriptor),
        invocation.source_descriptor_digest
    );
    assert_eq!(
        tagged_jcs_digest(&invocation.captured_output_invocation),
        invocation.captured_output_invocation_digest
    );
    let descriptor = invocation
        .source_descriptor
        .as_object()
        .expect("loader source descriptor must be an object");
    assert_eq!(descriptor["kind"], "module-loader-public-route");
    let surface_name = descriptor["surfaceName"]
        .as_str()
        .expect("loader source descriptor has no surface name");
    assert_eq!(
        probe.surface_observed_key,
        format!("loader:{surface_name}")
    );
    let evidence_type = descriptor["evidenceType"].as_str();
    let execution_point = descriptor["executionPoint"]
        .as_str()
        .expect("loader source descriptor has no execution point");
    assert_eq!(
        expected_loader_execution_point(surface_name, evidence_type).as_deref(),
        Some(execution_point),
        "{}: loader execution point is not derived from its source surface",
        recipe.fixture_id
    );
    let source_refs = descriptor["sourceRefs"]
        .as_array()
        .expect("loader source refs must be an array");
    assert!(!source_refs.is_empty());
    assert!(source_refs.iter().all(|source_ref| {
        source_ref
            .as_str()
            .is_some_and(|source_ref| !source_ref.is_empty())
    }));
    assert!(source_refs.iter().any(|source_ref| {
        source_ref.as_str().is_some_and(|source_ref| {
            source_ref.starts_with("src/engine/bootstrap/module-loader.js#")
        })
    }));
    let captured = invocation
        .captured_output_invocation
        .as_object()
        .expect("captured loader output invocation must be an object");
    assert_eq!(
        captured["invocationSchema"],
        "ibex/capsec-loader-output-invocation/1"
    );
    assert_eq!(captured["kind"], "loader-output");
    assert_eq!(captured["coverageEdgeId"], invocation.coverage_edge_id);
    assert_eq!(
        captured["coverageClassification"],
        invocation.coverage_classification
    );
    assert_eq!(
        captured["sourceDescriptorDigest"],
        descriptor["outputSourceDescriptorDigest"]
    );
    let route = captured["route"]
        .as_object()
        .expect("captured loader route must be an object");
    assert_eq!(route["operation"], "invoke-public-loader");
    assert_eq!(route["specifier"], invocation.module_specifier);
    assert_eq!(route["entrypoint"], invocation.entrypoint);
    assert!(
        !route.contains_key("authority"),
        "{}: zero-effect loader probe carries typed authority",
        recipe.fixture_id
    );
    assert!(matches!(
        invocation.entrypoint.as_str(),
        "exact-require"
            | "global-import"
            | "global-require"
            | "import-module"
            | "require-resolve"
    ));
    assert_eq!(recipe.route.ambiguous_callees, Vec::<String>::new());
    assert_eq!(recipe.route.alternatives.len(), 1);
    assert_eq!(
        recipe.route.alternatives[0].terminal_observed_key,
        probe.surface_observed_key
    );
    assert!(!recipe.route.alternatives[0].proof_paths.is_empty());
}

fn loader_recipes(catalog: &RecipeCatalog) -> Vec<&Recipe> {
    catalog
        .recipes
        .iter()
        .filter(|recipe| {
            recipe.status == "fully-executable" && loader_public_probe(recipe).is_some()
        })
        .inspect(|recipe| {
            validate_loader_probe(recipe, &loader_public_probe(recipe).unwrap())
        })
        .collect()
}

fn invocation_script(invocation: &BuiltinInvocation) -> String {
    const HARNESS: &str = include_str!("capsec_public_noncap_builtin_invocation.js");
    const CAPTURED_HARNESS: &str =
        include_str!("capsec_builtin_noncap_closed_output_invocation.js");
    if invocation.invocation_schema == CAPTURED_INVOCATION_SCHEMA {
        return format!(
            "JSON.stringify(({})({},{}))",
            CAPTURED_HARNESS.trim(),
            serde_json::to_string(
                invocation
                    .captured_output_invocation
                    .as_ref()
                    .expect("captured builtin invocation has no route"),
            )
            .expect("serialize captured builtin output invocation"),
            HARNESS.trim(),
        );
    }
    format!(
        "JSON.stringify(await ({})({}))",
        HARNESS.trim(),
        serde_json::to_string(invocation).expect("serialize authored builtin invocation")
    )
}

fn captured_completion_verification_script(token: &str) -> String {
    format!(
        "JSON.stringify((function(){{var token={};var store=globalThis.__ibexBuiltinOutputAsyncCompletions;var record=store&&store[token];if(store)delete store[token];return{{calls:record&&record.calls,error:record&&record.error,cleanupPerformed:record&&record.cleanupPerformed}};}})())",
        serde_json::to_string(token).expect("serialize captured builtin completion token")
    )
}

fn module_import_invocation_script(invocation: &BuiltinInvocation) -> String {
    format!(
        "JSON.stringify((function(moduleSpecifier){{try{{var value=require(moduleSpecifier);return {{kind:'return',moduleSpecifier:moduleSpecifier,valueType:value===null?'null':typeof value}};}}catch(error){{return {{kind:'throw',moduleSpecifier:moduleSpecifier,errorName:error&&error.name||'Error'}};}}}})({}))",
        serde_json::to_string(&invocation.module_specifier)
            .expect("serialize authored builtin module specifier")
    )
}

fn export_module_preload_script(invocation: &BuiltinInvocation) -> String {
    format!(
        "(function(){{require({});return 'ibex-capsec-builtin-preloaded';}})()",
        serde_json::to_string(&invocation.module_specifier)
            .expect("serialize authored builtin module specifier")
    )
}

async fn authenticated_noncap_engine(
    host: &crate::host::Host,
    digest: &str,
) -> AuthenticatedNoncapEngine {
    let engine = HermesEngine::new_with_armed_snapshot(Some(digest))
        .expect("create authenticated noncap builtin engine");
    engine
        .load_runtime()
        .await
        .expect("load authenticated noncap builtin runtime");
    AuthenticatedNoncapEngine {
        host: host.clone(),
        engine,
        publications: AuthenticatedPublicationTracker::default(),
    }
}

async fn drive_invocation_to_quiescence(
    engine: &mut AuthenticatedNoncapEngine,
    completion: &CompletionExpectation,
    fixture_id: &str,
) -> std::result::Result<(), String> {
    if completion.kind != EVENT_LOOP_COMPLETION_KIND
        || completion.timeout_milliseconds != EVENT_LOOP_COMPLETION_TIMEOUT_MS
    {
        return Err(format!(
            "{fixture_id}: public builtin completion expectation is not the reviewed bound"
        ));
    }
    let quiescence = tokio::time::timeout(
        std::time::Duration::from_millis(completion.timeout_milliseconds),
        engine.drive_event_loop(),
    )
    .await;
    engine.drain_publications().map_err(|error| {
        format!("{fixture_id}: public builtin work-unit publication failed: {error:#}")
    })?;
    let quiescence = quiescence
        .map_err(|_| {
            format!("{fixture_id}: public builtin probe did not reach event-loop quiescence")
        })?
        .map_err(|error| {
            format!("{fixture_id}: public builtin event-loop completion failed: {error:#}")
        });
    quiescence?;
    engine
        .require_no_due_schedules(fixture_id)
        .map_err(|error| error.to_string())
}

async fn observe_script_to_quiescence(
    engine: &mut AuthenticatedNoncapEngine,
    session_id: &str,
    script: &str,
    completion: &CompletionExpectation,
    fixture_id: &str,
) -> std::result::Result<
    (
        String,
        Vec<ibex_runtime::host::capability::ObservedCapabilityDecision>,
        Vec<ibex_runtime::host::ObservedTypedDecision>,
    ),
    String,
> {
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(session_id),
        "public builtin observer has no installed host"
    );
    let encoded = engine.eval_immediate(script).await;
    // Observation begins before source execution and remains open through all
    // ready/future work. Taking it earlier would let either synchronous module
    // initialization or deferred work evade a zero-decision claim.
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
    let quiescence = drive_invocation_to_quiescence(engine, completion, fixture_id).await;
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    quiescence?;
    let encoded = encoded
        .map_err(|error| format!("{fixture_id}: execute public builtin probe: {error:#}"))?
        .ok_or_else(|| format!("{fixture_id}: public builtin probe returned no result"))?;
    Ok((encoded, legacy, typed))
}

async fn execute_recipe(
    engine: &mut AuthenticatedNoncapEngine,
    recipe: &Recipe,
    engine_binary_digest: &str,
) -> std::result::Result<serde_json::Value, String> {
    let probe = public_probe(recipe).expect("builtin recipe has no public probe");
    let is_module_import = probe.invocation.invocation_schema
        == "ibex/capsec-builtin-module-import-no-effect-invocation/1";
    let is_captured = probe.invocation.invocation_schema == CAPTURED_INVOCATION_SCHEMA;
    if is_module_import {
        engine
            .arm_builtin_source_observation(
                &recipe.fixture_id,
                &probe.invocation.module_specifier,
            )
            .await
            .map_err(|error| {
                format!(
                    "{}: arm authenticated builtin source observation: {error:#}",
                    recipe.fixture_id
                )
            })?;
    }
    // Import-only and exported-operation obligations are distinct. Load the
    // exact public module and settle its event loop before opening an export
    // observer so synchronous or deferred initialization cannot be attributed
    // to every later read/call; the invocation still performs a real
    // authenticated public require against that cache.
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
    if !is_module_import {
        let preloaded = engine
            .eval_immediate(&export_module_preload_script(&probe.invocation))
            .await
            .map_err(|error| {
                format!(
                    "{}: preload public builtin module: {error:#}",
                    recipe.fixture_id
                )
            })?
            .ok_or_else(|| {
                format!(
                    "{}: public builtin module preload returned no result",
                    recipe.fixture_id
                )
            })?;
        if preloaded != "ibex-capsec-builtin-preloaded" {
            return Err(format!(
                "{}: public builtin module preload returned {preloaded:?}",
                recipe.fixture_id
            ));
        }
        drive_invocation_to_quiescence(
            engine,
            &probe.invocation.completion,
            &format!("{}: module preload", recipe.fixture_id),
        )
        .await?;
    }
    let session_id = format!("public-observation:{}", recipe.plan_digest);
    let script = if is_module_import {
        module_import_invocation_script(&probe.invocation)
    } else {
        invocation_script(&probe.invocation)
    };
    let (encoded, legacy, typed) = observe_script_to_quiescence(
        engine,
        &session_id,
        &script,
        &probe.invocation.completion,
        &recipe.fixture_id,
    )
    .await?;
    let source_execution = if is_module_import {
        let observation_value = engine
            .take_builtin_source_observation()
            .await
            .map_err(|error| {
                format!(
                    "{}: take authenticated builtin source observation: {error:#}",
                    recipe.fixture_id
                )
            })?;
        let observation: BuiltinSourceObservation =
            serde_json::from_value(observation_value).map_err(|error| {
                format!(
                    "{}: decode authenticated builtin source observation: {error}",
                    recipe.fixture_id
                )
            })?;
        let descriptor: BuiltinModuleAliasSourceDescriptor =
            serde_json::from_value(probe.invocation.source_descriptor.clone())
                .expect("validated builtin module descriptor must remain exact");
        let expected_source_id = expected_builtin_cache_source_id(&descriptor.source_key);
        if observation.schema != "ibex/capsec-builtin-source-observation/1"
            || !is_tagged_nonzero_u64(&observation.runtime_nonce)
            || observation.observation_id != recipe.fixture_id
            || observation.expected_alias != probe.invocation.module_specifier
            || observation.status != "completed"
            || observation.source_id.as_deref() != Some(expected_source_id.as_str())
        {
            return Err(format!(
                "{}: authenticated builtin source did not complete one exact cache miss: {:?}",
                recipe.fixture_id, observation
            ));
        }
        Some(serde_json::json!({
            "schema": "ibex/capsec-authenticated-builtin-source-execution/1",
            "observationId": observation.observation_id,
            "runtimeNonce": observation.runtime_nonce,
            "moduleSpecifier": observation.expected_alias,
            "sourceId": expected_source_id,
            "cacheMiss": true,
            "bodyCompleted": true,
        }))
    } else {
        None
    };
    let mut invocation_result: serde_json::Value =
        serde_json::from_str(&encoded).expect("public builtin returned invalid JSON");
    if is_captured {
        let captured = probe
            .invocation
            .captured_output_invocation
            .as_ref()
            .expect("validated captured builtin route disappeared");
        if let Some(completion_token) = invocation_result["completionToken"].as_str() {
            let completion = engine
                .eval_immediate(&captured_completion_verification_script(completion_token))
                .await
                .map_err(|error| {
                    format!(
                        "{}: captured builtin completion proof failed: {error:#}",
                        recipe.fixture_id
                    )
                })?
                .ok_or_else(|| {
                    format!(
                        "{}: captured builtin completion proof returned no result",
                        recipe.fixture_id
                    )
                })?;
            let completion: serde_json::Value =
                serde_json::from_str(&completion).map_err(|error| {
                    format!(
                        "{}: captured builtin completion proof returned invalid JSON: {error}",
                        recipe.fixture_id
                    )
                })?;
            if completion["calls"].as_u64() != Some(1)
                || completion["cleanupPerformed"] != true
                || completion["error"] != false
            {
                return Err(format!(
                    "{}: captured builtin async completion was not successful: {completion}",
                    recipe.fixture_id
                ));
            }
        }
        let raw = &invocation_result["rawOutput"];
        let descriptor_proof = &invocation_result["descriptorProof"];
        if invocation_result["kind"] != "return"
            || invocation_result["sourceOperationAttempted"] != true
            || invocation_result["cleanupPerformed"] != true
            || raw["kind"] != "return"
            || !raw["rawValueShape"]
                .as_str()
                .is_some_and(|shape| {
                    matches!(
                        shape,
                        "array"
                            | "bigint"
                            | "boolean"
                            | "function"
                            | "null"
                            | "number"
                            | "object"
                            | "string"
                            | "undefined"
                    )
                })
            || !raw["errorCode"].is_null()
            || !matches!(
                descriptor_proof["descriptorKind"].as_str(),
                Some("data" | "accessor" | "module-value")
            )
            || !matches!(
                descriptor_proof["accessKind"].as_str(),
                Some(
                    "export-property"
                        | "prototype-property"
                        | "inherited-prototype-property"
                        | "module-value"
                )
            )
            || captured["route"]["outcomeCapture"] != "public-builtin-family"
        {
            return Err(format!(
                "{}: captured public builtin did not prove one normal source return and cleanup: {invocation_result}",
                recipe.fixture_id
            ));
        }
        invocation_result = serde_json::json!({
            "kind": "captured-source-return",
            "sourceOperationAttempted": true,
            "descriptorProof": descriptor_proof,
            "cleanupPerformed": true,
            "rawOutput": raw,
            "engineExecuted": true,
            "projectCodeExecuted": true,
        });
    }
    let expected_kind = match probe.invocation.expected_result.as_str() {
        "absent" => "missing",
        "captured-source-return" => "captured-source-return",
        _ => "return",
    };
    if invocation_result["kind"] != expected_kind {
        return Err(format!(
            "{}: public builtin probe failed: {invocation_result}",
            recipe.fixture_id
        ));
    }
    if is_module_import {
        let descriptor: BuiltinModuleAliasSourceDescriptor =
            serde_json::from_value(probe.invocation.source_descriptor.clone())
                .expect("validated builtin module descriptor must remain exact");
        if invocation_result["moduleSpecifier"] != probe.invocation.module_specifier
            || invocation_result["valueType"] != descriptor.expected_root_type
        {
            return Err(format!(
                "{}: reviewed module import returned the wrong root without selecting an export: {invocation_result}",
                recipe.fixture_id
            ));
        }
    }
    if probe.invocation.kind == "builtin-export-read" {
        let descriptor: BuiltinSourceDescriptor =
            serde_json::from_value(probe.invocation.source_descriptor.clone())
                .expect("validated builtin export descriptor must remain exact");
        if let Some(expected_value_type) = descriptor.expected_value_type.as_deref() {
            if invocation_result["valueType"] != expected_value_type {
                return Err(format!(
                    "{}: reviewed builtin read returned the wrong value type: {invocation_result}",
                    recipe.fixture_id
                ));
            }
        }
    }
    if probe.invocation.kind == "builtin-export-call" {
        let descriptor: BuiltinSourceDescriptor =
            serde_json::from_value(probe.invocation.source_descriptor.clone())
                .expect("validated builtin call descriptor must remain exact");
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
        if matches!(
            probe.invocation.setup["kind"].as_str(),
            Some(
                "zlib-owner"
                    | "zlib-end-owner"
                    | "zlib-process-chunk-owner"
                    | "zlib-flush-owner"
                    | "zlib-params-owner"
                    | "zlib-transform-owner"
                    | "zlib-write-owner"
            )
        ) && invocation_result["cleanupPerformed"] != true
        {
            return Err(format!(
                "{}: public zlib call did not prove native-state cleanup: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if descriptor.source_key == "node_zlib"
            && is_zlib_sync_encoder(&descriptor.export_name)
            && invocation_result["zlibSyncEncoderOutputVerified"] != true
        {
            return Err(format!(
                "{}: public sync zlib encoder did not prove a nonempty byte result: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if descriptor.source_key == "node_zlib"
            && zlib_sync_decoder_input(&descriptor.export_name).is_some()
            && invocation_result["zlibSyncDecoderOutputVerified"] != true
        {
            return Err(format!(
                "{}: public sync zlib decoder did not prove the exact decoded bytes: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if descriptor.source_key == "node_zlib"
            && zlib_callback_contract(&descriptor.export_name).is_some()
            && invocation_result["zlibCallbackOutputVerified"] != true
        {
            return Err(format!(
                "{}: public zlib callback did not prove its exact delivery contract: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if probe.invocation.setup["kind"] == "zlib-end-owner"
            && invocation_result["zlibEndLifecycleVerified"] != true
        {
            return Err(format!(
                "{}: public zlib end call did not prove finish, output, and cleanup: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if probe.invocation.setup["kind"] == "zlib-process-chunk-owner"
            && invocation_result["zlibProcessChunkOutputVerified"] != true
        {
            return Err(format!(
                "{}: public zlib process-chunk call did not prove output and cleanup: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if probe.invocation.setup["kind"] == "zlib-write-owner"
            && invocation_result["zlibWriteLifecycleVerified"] != true
        {
            return Err(format!(
                "{}: public zlib write call did not prove callback, output, and cleanup: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if probe.invocation.setup["kind"] == "zlib-flush-owner"
            && invocation_result["zlibFlushLifecycleVerified"] != true
        {
            return Err(format!(
                "{}: public zlib flush call did not prove callback, non-terminal state, and cleanup: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if probe.invocation.setup["kind"] == "zlib-params-owner"
            && invocation_result["zlibParamsLifecycleVerified"] != true
        {
            return Err(format!(
                "{}: public zlib params call did not prove callback, selected state, and cleanup: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if probe.invocation.setup["kind"] == "zlib-transform-owner"
            && invocation_result["zlibTransformLifecycleVerified"] != true
        {
            return Err(format!(
                "{}: direct zlib transform did not prove callback, accepted bytes, and cleanup: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if matches!(
            probe.invocation.setup["kind"].as_str(),
            Some(
                "timer-clear-root"
                    | "timer-factory-root"
                    | "timer-legacy-root"
                    | "timer-owner"
            )
        ) && (invocation_result["cleanupPerformed"] != true
            || invocation_result["timerLifecycleVerified"] != true)
        {
            return Err(format!(
                "{}: public timer call did not prove callback suppression and cleanup: {invocation_result}",
                recipe.fixture_id
            ));
        }
        if matches!(
            probe.invocation.setup["kind"].as_str(),
            Some("readline-interface-owner" | "readline-interface-pause-owner")
        )
            && (invocation_result["cleanupPerformed"] != true
                || invocation_result["inputLifecycleVerified"] != true)
        {
            return Err(format!(
                "{}: public readline call did not prove listener cleanup and input lifecycle: {invocation_result}",
                recipe.fixture_id
            ));
        }
    }
    if !legacy.is_empty() || !typed.is_empty() {
        return Err(format!(
            "{}: non-capability builtin probe observed {} legacy and {} typed decisions: {}",
            recipe.fixture_id,
            legacy.len(),
            typed.len(),
            serde_json::to_string(&typed)
                .expect("serialize unexpected non-capability builtin decisions")
        ));
    }
    let mut runtime_invocation = serde_json::json!({
        "invocationSchema": probe.invocation.invocation_schema,
        "kind": probe.invocation.kind,
        "surfaceObservedKey": probe.surface_observed_key,
        "moduleSpecifier": probe.invocation.module_specifier,
        "sourceDescriptorDigest": probe.invocation.source_descriptor_digest,
        "completion": {
            "kind": probe.invocation.completion.kind,
            "timeoutMilliseconds": probe.invocation.completion.timeout_milliseconds,
            "status": "quiescent",
        },
        "result": invocation_result,
    });
    if let Some(source_execution) = source_execution {
        runtime_invocation
            .as_object_mut()
            .expect("runtime invocation must be an object")
            .insert("sourceExecution".into(), source_execution);
    }
    if let Some(export_name) = &probe.invocation.export_name {
        runtime_invocation
            .as_object_mut()
            .expect("runtime invocation must be an object")
            .insert(
                "exportName".into(),
                serde_json::Value::String(export_name.clone()),
            );
    }
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": runtime_invocation,
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

fn is_no_effect_module_import_recipe(recipe: &Recipe) -> bool {
    public_probe(recipe).is_some_and(|probe| {
        probe.invocation.invocation_schema
            == "ibex/capsec-builtin-module-import-no-effect-invocation/1"
    })
}

fn is_captured_builtin_recipe(recipe: &Recipe) -> bool {
    public_probe(recipe).is_some_and(|probe| {
        probe.invocation.invocation_schema == CAPTURED_INVOCATION_SCHEMA
    })
}

async fn execute_isolated_module_import_recipe(
    recipe: &Recipe,
    engine_binary_digest: &str,
) -> std::result::Result<serde_json::Value, String> {
    assert!(is_no_effect_module_import_recipe(recipe));
    let module_specifier = public_probe(recipe)
        .expect("isolated noncap module import has no probe")
        .invocation
        .module_specifier;
    let (host, digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] =
                serde_json::json!([module_specifier]);
        });
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let mut engine = authenticated_noncap_engine(&host, &digest).await;
    let execution = execute_recipe(&mut engine, recipe, engine_binary_digest).await;
    let finish = engine.finish().map_err(|error| {
        format!(
            "{}: finish isolated reviewed module import publication stream: {error:#}",
            recipe.fixture_id
        )
    });
    match (execution, finish) {
        (Ok(execution), Ok(())) => Ok(execution),
        (Err(execution_error), Ok(())) => Err(execution_error),
        (Ok(_), Err(finish_error)) => Err(finish_error),
        (Err(execution_error), Err(finish_error)) => {
            Err(format!("{execution_error}; {finish_error}"))
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_public_noncap_builtin_recipe_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping noncap builtin public batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT").ok();
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipes = noncap_builtin_recipes(&catalog);
    assert!(
        !recipes.is_empty(),
        "recipe catalog contains no non-capability builtin probes"
    );
    let module_import_recipes = recipes
        .iter()
        .copied()
        .filter(|recipe| is_no_effect_module_import_recipe(recipe))
        .collect::<Vec<_>>();
    assert_eq!(
        module_import_recipes.len(),
        34,
        "expected exactly 34 fresh-engine reviewed import carriers"
    );
    let export_recipes = recipes
        .iter()
        .copied()
        .filter(|recipe| !is_no_effect_module_import_recipe(recipe))
        .collect::<Vec<_>>();
    let captured_recipes = export_recipes
        .iter()
        .copied()
        .filter(|recipe| is_captured_builtin_recipe(recipe))
        .collect::<Vec<_>>();
    let standard_export_recipes = export_recipes
        .iter()
        .copied()
        .filter(|recipe| !is_captured_builtin_recipe(recipe))
        .collect::<Vec<_>>();
    let builtin_imports = standard_export_recipes
        .iter()
        .map(|recipe| public_probe(recipe).unwrap().invocation.module_specifier)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before noncap builtin public probes");
    let portable = super::capsec_portable_public_batch::PortablePublicBatchContext::begin(
        "ibex-noncap-builtin-public-surface-harness",
    );
    assert_ne!(
        output_path.is_some(),
        portable.is_some(),
        "noncap builtin public batch requires exactly one legacy output or portable plan"
    );
    let mut executions = Vec::with_capacity(recipes.len());
    let mut failures = Vec::new();

    for recipe in &module_import_recipes {
        match execute_isolated_module_import_recipe(recipe, &identity_before.binary_digest).await {
            Ok(execution) => executions.push(execution),
            Err(error) => {
                failures.push(error);
                break;
            }
        }
    }

    if failures.is_empty() {
        let module_import_runtime_nonces = executions
            .iter()
            .filter_map(|execution| {
                execution["evidence"]["runtimeObservation"]["invocation"]["sourceExecution"]
                    ["runtimeNonce"]
                    .as_str()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            module_import_runtime_nonces.len(),
            module_import_recipes.len(),
            "fresh-engine reviewed import receipts reused or omitted a runtime nonce"
        );
        {
            let (host, digest) = build_armed_test_host_custom(
                None,
                false,
                false,
                false,
                Vec::new(),
                None,
                |snapshot| {
                    snapshot["principals"][0]["imports"]["builtins"] =
                        serde_json::json!(builtin_imports);
                },
            );
            assert_ne!(crate::host::abi::install_host(host.clone()), 0);
            let _reset = HostResetGuard;
            let mut engine = authenticated_noncap_engine(&host, &digest).await;
            for (index, recipe) in standard_export_recipes.iter().enumerate() {
                match execute_recipe(&mut engine, recipe, &identity_before.binary_digest).await {
                    Ok(execution) => executions.push(execution),
                    Err(error) => {
                        failures.push(error);
                        break;
                    }
                }
                if index % 256 == 255 {
                    eprintln!(
                        "CapSec public non-capability builtin export probes passed: {}/{}",
                        index + 1,
                        standard_export_recipes.len()
                    );
                }
            }
            if let Err(error) = engine.finish() {
                failures.push(format!(
                    "finish authenticated public-builtin publication stream: {error:#}"
                ));
            }
        }
    }

    if failures.is_empty() && !captured_recipes.is_empty() {
        let captured_imports = captured_recipes
            .iter()
            .flat_map(|recipe| {
                let probe = public_probe(recipe).unwrap();
                let mut imports = vec![probe.invocation.module_specifier];
                if let Some(dependencies) = probe
                    .invocation
                    .captured_output_invocation
                    .as_ref()
                    .and_then(|invocation| invocation["route"]["dependencyModuleSpecifiers"].as_array())
                {
                    imports.extend(
                        dependencies
                            .iter()
                            .map(|specifier| {
                                specifier
                                    .as_str()
                                    .expect("captured builtin dependency must be a string")
                                    .to_owned()
                            }),
                    );
                }
                imports
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let (host, digest) = build_armed_test_host_custom(
            None,
            true,
            true,
            true,
            Vec::new(),
            None,
            |snapshot| {
                snapshot["bootstrapCompatibilityModes"] = serde_json::json!(["bun"]);
                snapshot["principals"][0]["imports"]["builtins"] =
                    serde_json::json!(captured_imports);
                snapshot["entry"] = serde_json::json!({
                    "kind": "repl",
                    "identity": "ibex:repl",
                    "mode": "interactive",
                });
            },
        );
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let mut engine = authenticated_noncap_engine(&host, &digest).await;
        for (index, recipe) in captured_recipes.iter().enumerate() {
            match execute_recipe(&mut engine, recipe, &identity_before.binary_digest).await {
                Ok(execution) => executions.push(execution),
                Err(error) => {
                    failures.push(error);
                }
            }
            if index % 128 == 127 {
                eprintln!(
                    "CapSec captured non-capability builtin probes passed: {}/{}",
                    index + 1,
                    captured_recipes.len()
                );
            }
        }
        if let Err(error) = engine.finish() {
            failures.push(format!(
                "finish captured public-builtin publication stream: {error:#}"
            ));
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
    if let Some(portable) = portable {
        portable.finish(&executions);
        return;
    }
    let artifact = PublicBatchArtifact {
        public_batch_evidence_schema: "ibex/capsec-public-batch-evidence/1",
        recipe_catalog_digest: catalog.recipe_catalog_digest,
        loaded_engine_identity: identity_before,
        executions,
    };
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path.expect("legacy noncap builtin batch has no output path"))
        .expect("create owned noncap builtin public evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize noncap builtin public evidence artifact");
    output.write_all(b"\n").expect("finish builtin evidence");
    output.sync_all().expect("sync builtin evidence artifact");
}

fn loader_invocation_script(invocation: &LoaderCapturedInvocation) -> String {
    const HARNESS: &str = include_str!("capsec_loader_output_invocation.js");
    format!(
        "JSON.stringify(await ({})({}))",
        HARNESS.trim(),
        serde_json::to_string(&invocation.captured_output_invocation)
            .expect("serialize captured module-loader invocation")
    )
}

async fn execute_isolated_loader_recipe(
    recipe: &Recipe,
    engine_binary_digest: &str,
) -> std::result::Result<serde_json::Value, String> {
    let probe = loader_public_probe(recipe).expect("loader recipe has no public probe");
    let execution_point = probe.invocation.source_descriptor["executionPoint"]
        .as_str()
        .expect("validated loader descriptor has no execution point")
        .to_owned();
    let module_specifier = probe.invocation.module_specifier.clone();
    let (host, digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] =
                serde_json::json!([module_specifier]);
        });
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let mut engine = authenticated_noncap_engine(&host, &digest).await;
    engine
        .arm_loader_point_observation(&recipe.fixture_id, &execution_point)
        .await
        .map_err(|error| {
            format!(
                "{}: arm loader source-point observation: {error:#}",
                recipe.fixture_id
            )
        })?;
    let session_id = format!("loader-public-observation:{}", recipe.plan_digest);
    let (encoded, legacy, typed) = observe_script_to_quiescence(
        &mut engine,
        &session_id,
        &loader_invocation_script(&probe.invocation),
        &probe.invocation.completion,
        &recipe.fixture_id,
    )
    .await?;
    let point_value = engine
        .take_loader_point_observation()
        .await
        .map_err(|error| {
            format!(
                "{}: take loader source-point observation: {error:#}",
                recipe.fixture_id
            )
        })?;
    let point: LoaderPointObservation =
        serde_json::from_value(point_value).map_err(|error| {
            format!(
                "{}: decode loader source-point observation: {error}",
                recipe.fixture_id
            )
        })?;
    if point.schema != "ibex/capsec-loader-source-point-observation/1"
        || !is_tagged_nonzero_u64(&point.runtime_nonce)
        || point.observation_id != recipe.fixture_id
        || point.expected_point != execution_point
        || point.status != "completed"
        || point.match_count == 0
    {
        return Err(format!(
            "{}: exact loader source point did not execute: {:?}",
            recipe.fixture_id, point
        ));
    }
    if !legacy.is_empty() || !typed.is_empty() {
        return Err(format!(
            "{}: non-capability loader route observed {} legacy and {} typed decisions: {}",
            recipe.fixture_id,
            legacy.len(),
            typed.len(),
            serde_json::to_string(&typed)
                .expect("serialize unexpected loader typed decisions")
        ));
    }
    let invocation_result: serde_json::Value =
        serde_json::from_str(&encoded).map_err(|error| {
            format!(
                "{}: loader invocation returned invalid JSON: {error}",
                recipe.fixture_id
            )
        })?;
    if invocation_result["kind"] != "return"
        || invocation_result["sourceOperationAttempted"] != true
        || invocation_result["entrypointProof"]["valueType"] != "function"
        || invocation_result["rawOutput"]["kind"] != "return"
    {
        return Err(format!(
            "{}: public loader route did not complete normally: {}",
            recipe.fixture_id, invocation_result
        ));
    }
    engine.finish().map_err(|error| {
        format!(
            "{}: finish isolated loader publication stream: {error:#}",
            recipe.fixture_id
        )
    })?;

    let source_execution = serde_json::json!({
        "schema": "ibex/capsec-loader-source-point-execution/1",
        "observationId": point.observation_id,
        "runtimeNonce": point.runtime_nonce,
        "executionPoint": point.expected_point,
        "matchCount": point.match_count,
        "loaderPrivate": true,
    });
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": probe.invocation.invocation_schema,
            "kind": probe.invocation.kind,
            "surfaceObservedKey": probe.surface_observed_key,
            "moduleSpecifier": probe.invocation.module_specifier,
            "entrypoint": probe.invocation.entrypoint,
            "sourceDescriptorDigest": probe.invocation.source_descriptor_digest,
            "completion": {
                "kind": probe.invocation.completion.kind,
                "timeoutMilliseconds": probe.invocation.completion.timeout_milliseconds,
                "status": "quiescent",
            },
            "sourceExecution": source_execution,
            "result": invocation_result,
        },
        "legacyObservationCount": 0,
        "typedDecisions": [],
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected loader observation must be an object")
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
        .expect("loader evidence must be an object")
        .insert("evidenceDigest".into(), serde_json::Value::String(digest));
    Ok(serde_json::json!({
        "fixtureId": recipe.fixture_id,
        "outcome": "passed",
        "executor": "ibex-loader-public-surface-harness",
        "evidence": evidence,
    }))
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_public_loader_recipe_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping loader public batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT").ok();
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipes = loader_recipes(&catalog);
    assert!(
        !recipes.is_empty(),
        "recipe catalog contains no source-bound module-loader probes"
    );

    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before loader public probes");
    let portable = super::capsec_portable_public_batch::PortablePublicBatchContext::begin(
        "ibex-loader-public-surface-harness",
    );
    assert_ne!(
        output_path.is_some(),
        portable.is_some(),
        "loader public batch requires exactly one legacy output or portable plan"
    );
    let mut executions = Vec::with_capacity(recipes.len());
    let mut failures = Vec::new();
    for (index, recipe) in recipes.iter().enumerate() {
        match execute_isolated_loader_recipe(recipe, &identity_before.binary_digest).await {
            Ok(execution) => executions.push(execution),
            Err(error) => {
                failures.push(error);
            }
        }
        if index % 32 == 31 {
            eprintln!(
                "CapSec source-bound module-loader probes passed: {}/{}",
                index + 1,
                recipes.len()
            );
        }
    }
    assert!(
        failures.is_empty(),
        "{} module-loader public probes failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    executions.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
    assert_eq!(executions.len(), recipes.len());
    let runtime_nonces = executions
        .iter()
        .filter_map(|execution| {
            execution["evidence"]["runtimeObservation"]["invocation"]["sourceExecution"]
                ["runtimeNonce"]
                .as_str()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        runtime_nonces.len(),
        recipes.len(),
        "isolated loader source-point receipts reused or omitted a runtime nonce"
    );
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after loader public probes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after loader public probes");
    if let Some(portable) = portable {
        portable.finish(&executions);
        return;
    }
    let artifact = PublicBatchArtifact {
        public_batch_evidence_schema: "ibex/capsec-public-batch-evidence/1",
        recipe_catalog_digest: catalog.recipe_catalog_digest,
        loaded_engine_identity: identity_before,
        executions,
    };
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path.expect("legacy loader batch has no output path"))
        .expect("create owned loader public evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize loader public evidence artifact");
    output
        .write_all(b"\n")
        .expect("finish loader public evidence");
    output.sync_all().expect("sync loader public evidence artifact");
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
        captured_output_invocation: None,
        completion: CompletionExpectation {
            kind: EVENT_LOOP_COMPLETION_KIND.to_owned(),
            timeout_milliseconds: EVENT_LOOP_COMPLETION_TIMEOUT_MS,
        },
        required_authority: Vec::new(),
        expected_result: "normal-return".to_owned(),
        expected_typed_decision_count: 0,
        expected_typed_stages: Vec::new(),
        allowed_coverage_edge_ids: Vec::new(),
        expected_action_ids: Vec::new(),
    }
}

#[test]
fn mixed_public_catalog_selects_before_strict_builtin_decode() {
    let residual_recipe = |fixture_id: &str, public_surface_probe: serde_json::Value| Recipe {
        fixture_id: fixture_id.to_owned(),
        plan_digest: "test-only".to_owned(),
        classification: "non-capability".to_owned(),
        scenario: "non-capability".to_owned(),
        edge_ids: Vec::new(),
        action_ids: Vec::new(),
        expected_observation: serde_json::json!({}),
        route: PublicRoute {
            alternatives: Vec::new(),
            ambiguous_callees: Vec::new(),
        },
        status: "fully-executable".to_owned(),
        public_surface_probe: Some(public_surface_probe),
    };
    let mut effect_probe = residual_recipe(
        "fixture.unrelated.effect-builtin",
        serde_json::json!({
            "invocation": {
                "invocationSchema": "ibex/capsec-builtin-export-invocation/1",
                "kind": "builtin-effect-call"
            }
        }),
    );
    effect_probe.classification = "effects".to_owned();
    effect_probe.scenario = "allow".to_owned();
    effect_probe.action_ids = vec!["fs:read".to_owned()];
    let catalog = RecipeCatalog {
        recipe_catalog_schema: "ibex/capsec-executable-recipes/1".to_owned(),
        recipe_catalog_digest: "test-only".to_owned(),
        recipes: vec![
            residual_recipe(
                "fixture.retracted.builtin-import",
                serde_json::json!({
                    "invocation": {
                        "invocationSchema": "ibex/capsec-builtin-module-import-invocation/1",
                        "kind": "builtin-module-import"
                    }
                }),
            ),
            residual_recipe(
                "fixture.unrelated.native",
                serde_json::json!({
                    "invocation": {
                        "invocationSchema": "ibex/capsec-native-global-invocation/1",
                        "kind": "native-global-function"
                    }
                }),
            ),
            effect_probe,
        ],
    };
    assert!(noncap_builtin_recipes(&catalog).is_empty());
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(feature = "insecure"))]
async fn noncap_observer_covers_source_entry_and_ready_work_through_completion() {
    let _lock = hermes_engine_test_lock().lock().await;
    let (host, digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |_| {});
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let mut engine = authenticated_noncap_engine(&host, &digest).await;
    let (result, legacy, typed) = observe_script_to_quiescence(
        &mut engine,
        "public.noncap.source-entry-and-ready-work",
        "try{void process.env.PATH;}catch(_error){};setTimeout(function(){try{void process.env.PATH;}catch(_error){}},0);'observed'",
        &CompletionExpectation {
            kind: EVENT_LOOP_COMPLETION_KIND.to_owned(),
            timeout_milliseconds: EVENT_LOOP_COMPLETION_TIMEOUT_MS,
        },
        "fixture.test.source-entry-and-ready-work",
    )
    .await
    .expect("observe synchronous source entry and completion-proof work");
    assert_eq!(result, "observed");
    assert!(legacy.is_empty());
    assert!(
        typed.len() >= 2,
        "the observer must begin before source entry and remain open while scheduled work reaches its typed gate"
    );
    engine
        .finish()
        .expect("finish ready-work publication stream");
}

#[tokio::test(flavor = "current_thread")]
async fn authored_call_harness_never_counts_a_throw_as_body_entry() {
    let _lock = hermes_engine_test_lock().lock().await;
    let (host, digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] = serde_json::json!(["node:path"]);
        });
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let mut engine = authenticated_noncap_engine(&host, &digest).await;

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
    engine
        .finish()
        .expect("finish authored-call publication stream");
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_builtin_source_observer_rejects_wrong_alias_and_cache_hit() {
    let _lock = hermes_engine_test_lock().lock().await;
    let (host, digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] =
                serde_json::json!(["dns", "node:dns"]);
        });
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let mut engine = authenticated_noncap_engine(&host, &digest).await;

    engine
        .arm_builtin_source_observation("receipt.alias-mismatch", "node:dns")
        .await
        .expect("arm wrong-alias builtin source observation");
    assert_eq!(
        engine
            .eval_immediate("typeof require('dns')")
            .await
            .expect("execute cold wrong-alias builtin import")
            .as_deref(),
        Some("object")
    );
    let wrong_alias: BuiltinSourceObservation = serde_json::from_value(
        engine
            .take_builtin_source_observation()
            .await
            .expect("take wrong-alias builtin source observation"),
    )
    .expect("decode wrong-alias builtin source observation");
    assert_eq!(wrong_alias.status, "missing");
    assert!(wrong_alias.source_id.is_none());
    assert!(is_tagged_nonzero_u64(&wrong_alias.runtime_nonce));

    engine
        .arm_builtin_source_observation("receipt.cache-hit", "node:dns")
        .await
        .expect("arm cache-hit builtin source observation");
    assert_eq!(
        engine
            .eval_immediate("typeof require('node:dns')")
            .await
            .expect("execute same-SourceId alias cache hit")
            .as_deref(),
        Some("object")
    );
    let cache_hit: BuiltinSourceObservation = serde_json::from_value(
        engine
            .take_builtin_source_observation()
            .await
            .expect("take cache-hit builtin source observation"),
    )
    .expect("decode cache-hit builtin source observation");
    assert_eq!(cache_hit.status, "missing");
    assert!(cache_hit.source_id.is_none());
    assert_eq!(cache_hit.runtime_nonce, wrong_alias.runtime_nonce);

    engine
        .finish()
        .expect("finish builtin source-observer negative stream");
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(feature = "insecure"))]
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
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let mut engine = authenticated_noncap_engine(&host, &digest).await;
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(
            "public.builtin.internal-fanout-terminal-denial"
        )
    );
    // Authenticated project source names the armed VFS namespace, never the
    // backing host path used to materialize this fixture.
    // @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings —
    // project files are addressed through their logical `/project` mount.
    let virtual_secret = "/project/secret.txt";
    let script = format!(
        "(function(){{var fs;try{{fs=require('node:fs');}}catch(error){{return 'import-denied';}}try{{fs.readFileSync({},'utf8');return 'terminal-allowed';}}catch(error){{return 'terminal-denied';}}}})()",
        serde_json::to_string(virtual_secret).expect("serialize virtual terminal path")
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
    assert!(
        typed.iter().any(|decision| {
            decision.evidence.outcome == capsec_semantics::decision::DecisionOutcome::Deny
        }),
        "terminal observation contained no denial: {typed:#?}"
    );
    engine
        .finish()
        .expect("finish builtin-terminal publication stream");
}
