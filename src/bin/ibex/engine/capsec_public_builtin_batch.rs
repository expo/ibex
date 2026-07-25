use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "host-http-server"))]
use std::io::Write as _;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecipeCatalog {
    recipe_catalog_schema: String,
    recipe_catalog_digest: String,
    target: RecipeTarget,
    recipes: Vec<Recipe>,
}

#[derive(Debug, Deserialize)]
struct RecipeTarget {
    triple: String,
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
    public_surface_probe: Option<PublicSurfaceProbe>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicRoute {
    surface_observed_keys: Vec<String>,
    alternatives: Vec<RouteAlternative>,
    ambiguous_callees: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteAlternative {
    terminal_observed_key: String,
    proof_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PublicSurfaceProbe {
    EffectBuiltin(Box<EffectBuiltinPublicSurfaceProbe>),
    Other {
        #[serde(flatten)]
        _fields: BTreeMap<String, serde_json::Value>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EffectBuiltinPublicSurfaceProbe {
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
    arguments: Vec<serde_json::Value>,
    setup: serde_json::Value,
    required_authority: Vec<serde_json::Value>,
    expected_result: String,
    expected_typed_decision_count: usize,
    expected_typed_stages: Vec<String>,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicBatchArtifact {
    public_batch_evidence_schema: &'static str,
    recipe_catalog_digest: String,
    loaded_engine_identity: ibex_runtime::engine::LoadedEngineBinaryIdentity,
    executions: Vec<serde_json::Value>,
}

/// Test-only armed engine facade. Public builtin source must enter through an
/// authenticated submission even though this harness preserves the compact
/// `eval_immediate` call shape used to separate preload from observation. The
/// facade also consumes the engine's bounded native publication stream.
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
/// @ref LLP 0025#11-delegated-obligations — OBL-UNIT-PUBLICATION requires
/// every authenticated unit to reach a controller with paired identities.
struct AuthenticatedBuiltinEngine {
    host: crate::host::Host,
    engine: HermesEngine,
    publications: AuthenticatedPublicationTracker,
}

impl AuthenticatedBuiltinEngine {
    async fn eval_immediate(&mut self, source: &str) -> anyhow::Result<Option<String>> {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};

        self.drain_publications("before authenticated effect-builtin evaluation")?;
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
        let evaluation = self
            .engine
            .evaluate_authenticated(&session, request)
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "authenticated effect-builtin submission {ordinal} failed: {error:#}"
                )
            });
        let publications =
            self.drain_publications("after authenticated effect-builtin evaluation");
        let evaluation = match (evaluation, publications) {
            (Err(evaluation_error), Err(publication_error)) => anyhow::bail!(
                "authenticated effect-builtin submission {ordinal} failed ({evaluation_error:#}) and its publication stream failed ({publication_error:#})"
            ),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
            (Ok(evaluation), Ok(())) => evaluation,
        };
        match evaluation {
            AuthenticatedEvaluation::Empty => Ok(None),
            AuthenticatedEvaluation::Value { display, receipt } => {
                let release = match receipt {
                    Some(receipt) => self.engine.release_undisplayed_value(receipt).await,
                    None => Err(anyhow::anyhow!(
                        "authenticated effect-builtin submission {ordinal} lost its value receipt"
                    )),
                };
                let publications =
                    self.drain_publications("after authenticated effect-builtin value release");
                match (release, publications) {
                    (Err(release_error), Err(publication_error)) => anyhow::bail!(
                        "authenticated effect-builtin submission {ordinal} failed to release its value ({release_error:#}) and its publication stream failed ({publication_error:#})"
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
                                "authenticated effect-builtin submission {ordinal} returned an invalid string display: {error}"
                            )
                        }),
                    _ => Ok(Some(display.text)),
                }
            }
            AuthenticatedEvaluation::Throw(thrown) => anyhow::bail!(
                "authenticated effect-builtin submission {ordinal} threw: {thrown:?}"
            ),
            AuthenticatedEvaluation::Cancelled => anyhow::bail!(
                "authenticated effect-builtin submission {ordinal} was cancelled"
            ),
            AuthenticatedEvaluation::Lifecycle(code) => anyhow::bail!(
                "authenticated effect-builtin submission {ordinal} exited with lifecycle code {code}"
            ),
        }
    }

    fn drain_publications(&mut self, context: &str) -> anyhow::Result<()> {
        self.publications.drain(&self.engine, context)
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        let publications = self.drain_publications("authenticated effect-builtin engine finish");
        let due = self
            .publications
            .require_no_due_schedules("authenticated effect-builtin engine finish");
        match (publications, due) {
            (Err(publication_error), Err(due_error)) => anyhow::bail!(
                "authenticated effect-builtin engine publication stream failed ({publication_error:#}) and retained due schedules ({due_error:#})"
            ),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
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

fn coverage_terminals() -> BTreeMap<String, String> {
    let value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/registry/coverage-edges.json"
    )))
    .expect("checked coverage registry must be JSON");
    value["edges"]
        .as_array()
        .expect("coverage registry must contain edges")
        .iter()
        .map(|edge| {
            let id = edge["id"]
                .as_str()
                .expect("coverage edge must have an id")
                .to_owned();
            let kind = edge["surface"]["kind"]
                .as_str()
                .expect("coverage edge must have a surface kind");
            let name = edge["surface"]["name"]
                .as_str()
                .expect("coverage edge must have a surface name");
            (id, format!("{kind}:{name}"))
        })
        .collect()
}

fn canonical_values(values: impl IntoIterator<Item = serde_json::Value>) -> Vec<serde_json::Value> {
    let mut values = values
        .into_iter()
        .map(|value| {
            (
                capsec_semantics::canonical::to_jcs_bytes(&value)
                    .expect("authority selector must be canonical"),
                value,
            )
        })
        .collect::<Vec<_>>();
    values.sort_by(|left, right| left.0.cmp(&right.0));
    values.dedup_by(|left, right| left.0 == right.0);
    values.into_iter().map(|(_, value)| value).collect()
}

fn module_alias_source(
    module_specifier: &str,
) -> Option<(&'static str, bool, bool, &'static str)> {
    Some(match module_specifier {
        "node:sys" | "node:util" | "sys" | "util" => {
            ("node_util", true, true, "env:read")
        }
        "node:util/types" => ("node_util_types_alias", true, true, "env:read"),
        "util/types" => ("util_types_alias", true, true, "env:read"),
        _ => return None,
    })
}

fn validate_module_import_probe(
    recipe: &Recipe,
    probe: &EffectBuiltinPublicSurfaceProbe,
    invocation: &BuiltinInvocation,
) {
    let (source_key, bundle_external, module_builtin, action_id) =
        module_alias_source(&invocation.module_specifier).unwrap_or_else(|| {
            panic!(
                "{}: unreviewed effect-bearing builtin module alias {}",
                recipe.fixture_id, invocation.module_specifier
            )
        });
    assert_eq!(invocation.kind, "builtin-module-import");
    assert!(invocation.export_name.is_none());
    assert!(invocation.arguments.is_empty());
    assert_eq!(invocation.setup, serde_json::json!({"kind": "none"}));
    assert_eq!(
        probe.surface_observed_key,
        format!("builtin:{}", invocation.module_specifier)
    );
    assert_eq!(recipe.route.surface_observed_keys, [probe.surface_observed_key.as_str()]);
    assert_eq!(recipe.route.ambiguous_callees, Vec::<String>::new());
    assert_eq!(recipe.route.alternatives.len(), 1);
    assert_eq!(
        recipe.route.alternatives[0].terminal_observed_key,
        probe.surface_observed_key
    );
    assert_eq!(
        recipe.route.alternatives[0].proof_paths,
        [probe.surface_observed_key.as_str()]
    );
    assert_eq!(recipe.edge_ids.len(), 1);
    const ENVIRONMENT_AUXILIARY_EDGE_ID: &str = "surface.native.op.exactgetenv.0k6bv7a";
    assert_eq!(
        invocation.source_descriptor,
        serde_json::json!({
            "kind": "builtin-module-alias",
            "moduleSpecifier": invocation.module_specifier,
            "sourceKey": source_key,
            "sourceRef": format!("modules.ts#specifiers:{source_key}"),
            "sourceMetadata": {
                "sourceKey": source_key,
                "bundleExternal": bundle_external,
                "importReachability": "public",
                "moduleBuiltin": module_builtin,
            },
            "carrierEdgeId": recipe.edge_ids[0],
            "auxiliaryDecisionEdgeId": ENVIRONMENT_AUXILIARY_EDGE_ID,
        })
    );
    assert_eq!(invocation.expected_action_ids, [action_id]);
    assert_eq!(recipe.action_ids, [action_id]);
    let expected_authority = match action_id {
        "env:read" => serde_json::json!({
            "cap": "env:read",
            "resource": {
                "kind": "environment-name",
                "target": "principal-overlay",
                "name": "NODE_DEBUG",
            },
        }),
        _ => unreachable!(),
    };
    assert_eq!(invocation.required_authority, [expected_authority]);
    assert_eq!(
        invocation.allowed_coverage_edge_ids,
        [ENVIRONMENT_AUXILIARY_EDGE_ID]
    );
    let public_denial = recipe.scenario == "deny";
    assert_eq!(invocation.expected_result, "return");
    assert_eq!(
        invocation.expected_typed_stages,
        if public_denial {
            vec!["requested"]
        } else {
            vec!["requested", "commit"]
        }
    );
    assert_eq!(
        invocation.expected_typed_decision_count,
        invocation.expected_typed_stages.len()
    );
}

fn builtin_recipes(catalog: &RecipeCatalog) -> Vec<&Recipe> {
    catalog
        .recipes
        .iter()
        .filter(|recipe| {
            recipe.classification == "effects"
                && recipe.status == "fully-executable"
                && recipe.public_surface_probe.as_ref().is_some_and(|probe| {
                    matches!(
                        probe,
                        PublicSurfaceProbe::EffectBuiltin(probe)
                            if matches!(
                                probe.invocation.invocation_schema.as_str(),
                                "ibex/capsec-builtin-export-invocation/1"
                                    | "ibex/capsec-builtin-module-import-invocation/1"
                            )
                    )
                })
        })
        .collect()
}

fn expected_authored_builtin_recipe_count(target: &str) -> usize {
    match target {
        // @ref LLP 0037#d1--ambient-mount-authority-for-traversal-decisions
        // +5 each on Apple for fs:list accessSync/realpathSync, fs:read
        // readFileSync, and fs:write writeFileSync (their allow/deny/malformed/
        // missing-attribution/wrong-principal scenario matrices). Windows
        // keeps 120: its node_fs enforcement route is ambiguous, so these
        // public probes are not authored there.
        "aarch64-apple-darwin" => 155,
        "x86_64-pc-windows-msvc" => 120,
        target => panic!("builtin public recipe batch has no reviewed target shape for {target}"),
    }
}

#[test]
fn capsec_public_builtin_recipe_counts_are_target_specific() {
    assert_eq!(
        expected_authored_builtin_recipe_count("aarch64-apple-darwin"),
        155
    );
    assert_eq!(
        expected_authored_builtin_recipe_count("x86_64-pc-windows-msvc"),
        120
    );
}

fn invocation_script(invocation: &BuiltinInvocation, arguments: &[serde_json::Value]) -> String {
    match invocation.invocation_schema.as_str() {
        "ibex/capsec-builtin-module-import-invocation/1" => format!(
            "JSON.stringify((function(){{var m={};try{{var value=require(m);return {{kind:\"return\",moduleSpecifier:m,valueType:value===null?\"null\":typeof value}};}}catch(error){{return {{kind:\"throw\",moduleSpecifier:m,errorName:String(error&&error.name||\"Error\"),errorMessage:String(error&&error.message||error)}};}}}})())",
            serde_json::to_string(&invocation.module_specifier)
                .expect("serialize imported builtin module")
        ),
        "ibex/capsec-builtin-export-invocation/1" => format!(
            "JSON.stringify((function(){{var m={};var e={};try{{var api=require(m);var f=api[e];if(typeof f!==\"function\")return {{kind:\"missing\",moduleSpecifier:m,exportName:e}};var value=Reflect.apply(f,api,{});return {{kind:\"return\",moduleSpecifier:m,exportName:e,valueType:value===null?\"null\":typeof value}};}}catch(error){{return {{kind:\"throw\",moduleSpecifier:m,exportName:e,errorName:String(error&&error.name||\"Error\"),errorMessage:String(error&&error.message||error)}};}}}})())",
            serde_json::to_string(&invocation.module_specifier)
                .expect("serialize builtin module"),
            serde_json::to_string(
                invocation
                    .export_name
                    .as_ref()
                    .expect("builtin export invocation has no export name"),
            )
            .expect("serialize builtin export"),
            serde_json::to_string(arguments).expect("serialize builtin arguments")
        ),
        schema => panic!("unsupported effect-builtin invocation schema {schema}"),
    }
}

struct PreparedInvocation {
    _fixture_root: Option<tempfile::TempDir>,
    project_root: Option<std::path::PathBuf>,
    arguments: Vec<serde_json::Value>,
}

impl PreparedInvocation {
    fn project_root(&self) -> Option<&std::path::Path> {
        self.project_root.as_deref()
    }
}

fn prepare_invocation(invocation: &BuiltinInvocation) -> PreparedInvocation {
    if invocation.invocation_schema == "ibex/capsec-builtin-module-import-invocation/1" {
        assert_eq!(invocation.kind, "builtin-module-import");
        assert!(invocation.export_name.is_none());
        assert_eq!(invocation.setup, serde_json::json!({"kind": "none"}));
        assert!(invocation.arguments.is_empty());
        return PreparedInvocation {
            _fixture_root: None,
            project_root: None,
            arguments: Vec::new(),
        };
    }
    assert_eq!(
        invocation.invocation_schema,
        "ibex/capsec-builtin-export-invocation/1"
    );
    assert_eq!(invocation.kind, "builtin-export-call");
    let export_name = invocation
        .export_name
        .as_deref()
        .expect("builtin export invocation has no export name");
    match invocation.setup["kind"].as_str() {
        Some("none") => {
            assert_eq!(invocation.module_specifier, "node:os");
            assert_eq!(invocation.source_descriptor["sourceKey"], "node_os");
            assert_eq!(invocation.setup, serde_json::json!({"kind": "none"}));
            assert!(invocation.arguments.is_empty());
            PreparedInvocation {
                _fixture_root: None,
                project_root: None,
                arguments: invocation.arguments.clone(),
            }
        }
        Some("filesystem-file") => {
            assert_eq!(invocation.module_specifier, "node:fs");
            assert_eq!(invocation.source_descriptor["sourceKey"], "node_fs");
            // fs:list stat exports bind list authority over the fixture; the
            // fs:read readFileSync export binds read authority; the fs:write
            // writeFileSync export binds write authority over the same
            // authenticated file. All are driven by the generic export
            // invocation script — the read/list exports take one path argument,
            // the write export additionally takes the literal payload.
            // @ref LLP 0037#d1--ambient-mount-authority-for-traversal-decisions
            let expected_cap = match export_name {
                "accessSync" | "lstatSync" | "realpathSync" | "statSync" => "fs:list",
                "readFileSync" => "fs:read",
                "writeFileSync" => "fs:write",
                other => panic!("unsupported filesystem-file fs export {other}"),
            };
            if export_name == "realpathSync" {
                assert_eq!(
                    invocation.source_descriptor["auxiliaryDecisionEdges"],
                    serde_json::json!([
                        {
                            "edgeId": "surface.native.op.exactgetcwd.1bhagb7",
                            "observedKey": "native-op:__exactGetCwd",
                            "actionIds": ["path:cwd-observe"],
                        },
                        {
                            "edgeId": "surface.native.op.exactlstat.1c98s6l",
                            "observedKey": "native-op:__exactLstat",
                            "actionIds": ["fs:list"],
                        },
                    ])
                );
                assert_eq!(
                    invocation.source_descriptor["denialTerminalEdgeId"],
                    "surface.native.op.exactlstat.1c98s6l"
                );
                assert_eq!(
                    invocation.allowed_coverage_edge_ids,
                    [
                        "surface.native.op.exactaccess.1a12cmn",
                        "surface.native.op.exactensurefs.1dih7no",
                        "surface.native.op.exactgetcwd.1bhagb7",
                        "surface.native.op.exactlstat.1c98s6l",
                        "surface.native.op.exactrealpath.06qb6s2",
                    ]
                );
            } else {
                assert!(invocation.source_descriptor["auxiliaryDecisionEdges"].is_null());
                assert!(invocation.source_descriptor["denialTerminalEdgeId"].is_null());
            }
            let logical_path = serde_json::json!({
                "root": "project",
                "components": [
                    {"encoding": "utf8", "value": "capsec-stat-fixture.txt"}
                ]
            });
            assert_eq!(invocation.setup["logicalPath"], logical_path);
            assert_eq!(
                invocation.required_authority,
                vec![serde_json::json!({
                    "cap": expected_cap,
                    "resource": {"kind": "path-exact", "path": logical_path.clone()},
                })]
            );
            let contents = invocation.setup["contents"]
                .as_str()
                .expect("filesystem fixture contents must be a string");
            assert_eq!(
                invocation.arguments[0],
                serde_json::json!({
                    "kind": "filesystem-fixture-path",
                    "logicalPath": logical_path,
                })
            );
            let mut runtime_arguments = vec![serde_json::Value::String(
                "/project/capsec-stat-fixture.txt".to_owned(),
            )];
            if expected_cap == "fs:write" {
                // The write export takes a literal payload as its second
                // argument; the read/list exports take only the path.
                assert_eq!(invocation.arguments.len(), 2);
                let payload = invocation.arguments[1]["value"]
                    .as_str()
                    .expect("fs:write literal payload must be a string");
                assert_eq!(invocation.arguments[1]["kind"], "literal-utf8");
                runtime_arguments.push(serde_json::Value::String(payload.to_owned()));
            } else {
                assert_eq!(invocation.arguments.len(), 1);
            }
            let fixture_root = tempfile::tempdir().expect("create builtin filesystem fixture");
            let project_root = std::fs::canonicalize(fixture_root.path())
                .expect("canonicalize builtin filesystem fixture root");
            let fixture_path = project_root.join("capsec-stat-fixture.txt");
            std::fs::write(&fixture_path, contents).expect("write builtin filesystem fixture");
            PreparedInvocation {
                _fixture_root: Some(fixture_root),
                project_root: Some(project_root),
                arguments: runtime_arguments,
            }
        }
        Some("filesystem-directory") => {
            assert_eq!(invocation.module_specifier, "node:fs");
            assert_eq!(invocation.source_descriptor["sourceKey"], "node_fs");
            assert_eq!(export_name, "readdirSync");
            let logical_path = serde_json::json!({
                "root": "project",
                "components": [
                    {"encoding": "utf8", "value": "capsec-directory-fixture"}
                ]
            });
            assert_eq!(invocation.setup["logicalPath"], logical_path);
            assert_eq!(
                invocation.setup["entries"],
                serde_json::json!([{
                    "kind": "file",
                    "name": "entry.txt",
                    "contents": "ibex-capsec-directory-entry\n",
                }])
            );
            assert_eq!(
                invocation.required_authority,
                vec![serde_json::json!({
                    "cap": "fs:list",
                    "resource": {"kind": "path-exact", "path": logical_path.clone()},
                })]
            );
            assert_eq!(
                invocation.arguments,
                vec![serde_json::json!({
                    "kind": "filesystem-fixture-path",
                    "logicalPath": logical_path,
                })]
            );
            let fixture_root = tempfile::tempdir().expect("create builtin directory fixture");
            let project_root = std::fs::canonicalize(fixture_root.path())
                .expect("canonicalize builtin directory fixture root");
            let fixture_path = project_root.join("capsec-directory-fixture");
            std::fs::create_dir(&fixture_path).expect("create builtin directory fixture");
            std::fs::write(
                fixture_path.join("entry.txt"),
                "ibex-capsec-directory-entry\n",
            )
            .expect("write builtin directory entry");
            PreparedInvocation {
                _fixture_root: Some(fixture_root),
                project_root: Some(project_root),
                arguments: vec![serde_json::Value::String(
                    "/project/capsec-directory-fixture".to_owned(),
                )],
            }
        }
        other => panic!("unsupported effect-builtin setup {other:?}"),
    }
}

fn typed_decision_values(
    session_id: &str,
    decisions: Vec<ibex_runtime::host::ObservedTypedDecision>,
) -> Vec<serde_json::Value> {
    decisions
        .into_iter()
        .map(|decision| {
            assert_eq!(
                decision.terminal_branch_id, session_id,
                "observer session marker is not terminal evidence"
            );
            let mut value =
                serde_json::to_value(decision).expect("serialize observed typed decision");
            value
                .as_object_mut()
                .expect("observed decision must be an object")
                .remove("terminalBranchId");
            value
        })
        .collect()
}

fn validate_observation(
    recipe: &Recipe,
    probe: &EffectBuiltinPublicSurfaceProbe,
    invocation_result: &serde_json::Value,
    expected_decision_identity: &serde_json::Value,
    legacy_count: usize,
    typed_decisions: &[serde_json::Value],
    terminal_by_edge: &BTreeMap<String, String>,
) -> String {
    let invocation = &probe.invocation;
    assert_eq!(recipe.classification, "effects");
    assert!(matches!(
        recipe.scenario.as_str(),
        "allow" | "deny" | "malformed" | "missing-attribution" | "wrong-principal"
    ));
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(!probe.command.is_empty());
    match invocation.invocation_schema.as_str() {
        "ibex/capsec-builtin-module-import-invocation/1" => {
            validate_module_import_probe(recipe, probe, invocation)
        }
        "ibex/capsec-builtin-export-invocation/1" => {
            assert_eq!(invocation.kind, "builtin-export-call");
            assert!(invocation.export_name.is_some());
        }
        schema => panic!("unsupported effect-builtin invocation schema {schema}"),
    }
    assert_eq!(invocation.expected_action_ids, recipe.action_ids);
    assert!(matches!(
        invocation.setup["kind"].as_str(),
        Some("none" | "filesystem-file" | "filesystem-directory")
    ));
    assert_eq!(
        tagged_jcs_digest(&invocation.source_descriptor),
        invocation.source_descriptor_digest,
        "{}: source descriptor digest drift",
        recipe.fixture_id
    );
    assert_eq!(legacy_count, 0, "legacy checks are not typed evidence");
    assert_eq!(
        typed_decisions.len(),
        invocation.expected_typed_decision_count,
        "{}: wrong typed decision count: {}",
        recipe.fixture_id,
        serde_json::to_string(typed_decisions)
            .expect("serialize mismatched public builtin decisions")
    );
    match invocation.expected_result.as_str() {
        "return" => assert_eq!(invocation_result["kind"], "return"),
        "permission-denied" => {
            assert_eq!(invocation_result["kind"], "throw");
            assert!(
                invocation_result["errorMessage"]
                    .as_str()
                    .is_some_and(|message| message
                        .to_ascii_lowercase()
                        .contains("permission denied")),
                "{}: denial threw the wrong error: {invocation_result}",
                recipe.fixture_id
            );
        }
        other => panic!("unsupported expected builtin result {other}"),
    }

    let stages = typed_decisions
        .iter()
        .map(|decision| {
            decision["decisionSet"]["context"]["stage"]
                .as_str()
                .expect("observed decision has no stage")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(stages, invocation.expected_typed_stages);
    let allowed_edges = invocation
        .allowed_coverage_edge_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(!allowed_edges.is_empty());
    // A public carrier may authenticate reviewed helper decisions before its
    // source-derived terminal. realpathSync is the first such metadata carrier:
    // cwd and lstat are exact auxiliaries, and lstat is the fail-closed denial
    // terminal when authority is absent.
    // @ref LLP 0037#additional-multi-edge-metadata-evidence-realpathsync
    let auxiliary_edges = invocation.source_descriptor["auxiliaryDecisionEdges"]
        .as_array()
        .map(|descriptors| {
            descriptors
                .iter()
                .map(|descriptor| {
                    let edge_id = descriptor["edgeId"]
                        .as_str()
                        .expect("auxiliary decision descriptor has no edgeId")
                        .to_owned();
                    let action_ids = descriptor["actionIds"]
                        .as_array()
                        .expect("auxiliary decision descriptor has no actionIds")
                        .iter()
                        .map(|action| {
                            action
                                .as_str()
                                .expect("auxiliary decision action must be a string")
                                .to_owned()
                        })
                        .collect::<BTreeSet<_>>();
                    assert!(!action_ids.is_empty());
                    assert!(allowed_edges.contains(&edge_id));
                    (edge_id, action_ids)
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let denial_terminal_edge = invocation.source_descriptor["denialTerminalEdgeId"]
        .as_str()
        .map(str::to_owned);
    if let Some(edge_id) = &denial_terminal_edge {
        assert!(
            auxiliary_edges.contains_key(edge_id),
            "denial terminal must be an authenticated auxiliary edge"
        );
    }
    let mut observed_edges = BTreeSet::new();
    let mut observed_actions = BTreeSet::new();
    let mut observed_terminals = BTreeSet::new();
    for decision in typed_decisions {
        assert_eq!(
            decision["evidence"]["identity"], *expected_decision_identity,
            "{}: observed decision identity differs from the installed armed Host",
            recipe.fixture_id
        );
        let set = &decision["decisionSet"];
        let effects = set["effects"]
            .as_array()
            .expect("observed decision has no effects");
        let gates = decision["gates"]
            .as_array()
            .expect("observed decision has no gates");
        assert_eq!(effects.len(), gates.len());
        let public_denial = recipe.scenario == "deny";
        let decision_is_auxiliary = gates.iter().all(|gate| {
            auxiliary_edges.contains_key(
                gate["coverageEdgeId"]
                    .as_str()
                    .expect("observed gate has no coverage edge"),
            )
        });
        let decision_is_designated_denial_terminal = public_denial
            && denial_terminal_edge.as_ref().is_some_and(|denial_edge| {
                gates.iter().all(|gate| {
                    gate["coverageEdgeId"]
                        .as_str()
                        .is_some_and(|edge_id| edge_id == denial_edge)
                })
            });
        for (effect, gate) in effects.iter().zip(gates) {
            let action = effect["cap"]
                .as_str()
                .expect("observed effect has no action")
                .to_owned();
            let edge_id = gate["coverageEdgeId"]
                .as_str()
                .expect("observed gate has no coverage edge");
            assert!(allowed_edges.contains(edge_id));
            if let Some(auxiliary_actions) = auxiliary_edges.get(edge_id) {
                assert!(
                    auxiliary_actions.contains(&action),
                    "{}: auxiliary edge {edge_id} observed undeclared action {action}",
                    recipe.fixture_id
                );
            }
            if !auxiliary_edges.contains_key(edge_id)
                || decision_is_designated_denial_terminal
            {
                observed_actions.insert(action);
            }
            assert_eq!(set["atomicityGroup"], format!("{edge_id}.decision"));
            assert_eq!(gate["targetCell"], "complete");
            assert_eq!(gate["definitionAndEdgePredicatesSatisfied"], true);
            observed_edges.insert(edge_id.to_owned());
            if !auxiliary_edges.contains_key(edge_id)
                || decision_is_designated_denial_terminal
            {
                observed_terminals.insert(
                    terminal_by_edge
                        .get(edge_id)
                        .unwrap_or_else(|| panic!("unknown observed edge {edge_id}"))
                        .clone(),
                );
            }
        }
        // LLP 0037 D1/D4: an fs:read export (readFileSync) opens the file (an
        // fs:list path traversal credited to ambient mount authority) and then
        // reads it (the fs:read operation). The traversal is always allowed —
        // even in the deny scenario, where only the operation capability is
        // refused — so per-decision expectations key on whether this decision is
        // the ambient traversal or the gated operation.
        // @ref LLP 0037#d4--the-deny-shape-of-an-open-then-act-operation
        let opens_via_traversal =
            recipe.action_ids == ["fs:read"] || recipe.action_ids == ["fs:write"];
        let decision_is_traversal = opens_via_traversal
            && effects.iter().all(|effect| effect["cap"] == "fs:list");
        let decision_denied = public_denial
            && !decision_is_traversal
            && (!decision_is_auxiliary || decision_is_designated_denial_terminal);
        let expected_outcome = if decision_denied { "deny" } else { "allow" };
        assert_eq!(
            decision["evidence"]["outcome"], expected_outcome,
            "{}: decision outcome drifted",
            recipe.fixture_id
        );
        let decisive = decision["evidence"]["evidence"]
            .as_array()
            .expect("observed decision has no decisive evidence");
        assert_eq!(
            decisive.len(),
            1,
            "{}: builtin decision must have one decisive authority row",
            recipe.fixture_id
        );
        let mount_binding_discovery = !decision_denied
            && set["context"]["stage"] == "discovery"
            && effects.iter().all(|effect| {
                effect["resource"]["kind"] == "path-occurrence"
                    && effect["resource"]["requested"]["root"] == "project"
                    && effect["resource"]["requested"]["components"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
            });
        // The read capability itself (fs:read) is gated by the authored static
        // floor at commit and its repeats; the open's fs:list traversal resolves
        // through ambient mount authority (LLP 0037 D1). A stat export, whose
        // fs:list IS the operation, is not a traversal and stays on the floor.
        // Authenticating the retained project-mount object is likewise root
        // ambient authority over the empty logical root.
        // @ref LLP 0023#21-staged-authorization-identity
        let ambient_auxiliary_decision = gates.iter().all(|gate| {
            auxiliary_edges
                .get(
                    gate["coverageEdgeId"]
                        .as_str()
                        .expect("observed gate has no coverage edge"),
                )
                .is_some_and(|actions| actions.contains("path:cwd-observe"))
        });
        let (expected_stratum, expected_reason, expected_source_prefix) = if decision_denied {
            (
                "principal-denial",
                "principal-denial",
                Some("principal.000000.denial."),
            )
        } else if ambient_auxiliary_decision || mount_binding_discovery || decision_is_traversal {
            ("ambient-root", "ambient-root", None)
        } else {
            (
                "static-floor",
                "static-floor",
                Some("principal.000000.floor."),
            )
        };
        assert_eq!(
            decisive[0]["stratum"], expected_stratum,
            "{}: decisive authority stratum drifted: {}",
            recipe.fixture_id, decisive[0]
        );
        assert_eq!(
            decisive[0]["reason"], expected_reason,
            "{}: decisive authority reason drifted: {}",
            recipe.fixture_id, decisive[0]
        );
        assert_eq!(
            decisive[0]["principal"],
            serde_json::json!({"kind": "root", "identity": "project-root"})
        );
        if let Some(expected_source_prefix) = expected_source_prefix {
            assert!(
                decisive[0]["sourceId"]
                    .as_str()
                    .is_some_and(|source| source.starts_with(expected_source_prefix)),
                "{}: decisive authority source has the wrong stratum index: {}",
                recipe.fixture_id,
                decisive[0]
            );
        } else {
            assert_eq!(decisive[0]["sourceId"], serde_json::Value::Null);
        }
    }
    assert!(!observed_edges.is_empty());
    assert!(observed_edges.is_subset(&allowed_edges));
    // LLP 0037 D2: every capability the operation declares must be observed, and
    // any *extra* observed capability must be a sanctioned traversal effect
    // (fs:list, when the operation opens a path for fs:read/fs:write) — never an
    // undeclared operation capability. A stat export, whose declared fs:list IS
    // the operation, observes exactly its declared set, so `opens_via_traversal`
    // is false for it and no extra is tolerated.
    // @ref LLP 0037#d2--declared-vs-incidental-capabilities-in-the-coverage-edge
    let declared_actions: BTreeSet<String> =
        invocation.expected_action_ids.iter().cloned().collect();
    assert!(
        declared_actions.is_subset(&observed_actions),
        "{}: declared actions {:?} were not all observed in {:?}",
        recipe.fixture_id,
        declared_actions,
        observed_actions
    );
    let opens_via_traversal = invocation
        .expected_action_ids
        .iter()
        .any(|cap| cap == "fs:read" || cap == "fs:write");
    for extra in observed_actions.difference(&declared_actions) {
        assert!(
            opens_via_traversal && extra == "fs:list",
            "{}: undeclared observed capability {extra} is not a sanctioned traversal effect",
            recipe.fixture_id
        );
    }
    assert_eq!(observed_terminals.len(), 1);
    let terminal = observed_terminals.into_iter().next().unwrap();
    if recipe.scenario == "deny" {
        if let Some(denial_edge_id) = denial_terminal_edge {
            assert_eq!(
                terminal,
                *terminal_by_edge
                    .get(&denial_edge_id)
                    .expect("unknown designated denial terminal"),
                "{}: public denial reached the wrong auxiliary terminal",
                recipe.fixture_id
            );
            return probe.surface_observed_key.clone();
        }
    }
    if invocation.invocation_schema == "ibex/capsec-builtin-module-import-invocation/1" {
        assert_eq!(
            terminal, "native-op:__exactGetEnv",
            "{}: module-import carrier observed the wrong auxiliary terminal",
            recipe.fixture_id
        );
        return probe.surface_observed_key.clone();
    }
    assert!(
        recipe
            .route
            .alternatives
            .iter()
            .any(|alternative| alternative.terminal_observed_key == terminal),
        "{}: runtime terminal {terminal} is outside the source-derived route",
        recipe.fixture_id
    );
    terminal
}

async fn execute_recipe(
    engine: &mut AuthenticatedBuiltinEngine,
    recipe: &Recipe,
    arguments: &[serde_json::Value],
    expected_decision_identity: &serde_json::Value,
    terminal_by_edge: &BTreeMap<String, String>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let probe = match recipe.public_surface_probe.as_ref() {
        Some(PublicSurfaceProbe::EffectBuiltin(probe)) => probe,
        _ => panic!("builtin recipe has no effect-builtin public probe"),
    };
    // The manifest has distinct obligations for importing a builtin root and
    // invoking each exported operation. Export evidence loads the exact public
    // module before opening its observer so import-time effects cannot be
    // misattributed to every exported function. Module-import evidence takes
    // the opposite path: this is a fresh engine and the observer opens before
    // its first require, so a cached alias can never masquerade as a
    // decision-free initialization.
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
    if probe.invocation.invocation_schema == "ibex/capsec-builtin-export-invocation/1" {
        let preload = format!(
            "require({}); 'loaded'",
            serde_json::to_string(&probe.invocation.module_specifier)
                .expect("serialize preloaded builtin module")
        );
        assert_eq!(
            engine
                .eval_immediate(&preload)
                .await
                .expect("preload public builtin module")
                .as_deref(),
            Some("loaded")
        );
    }
    let session_id = format!("public-observation:{}", recipe.plan_digest);
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id),
        "public builtin observer has no installed host"
    );
    let encoded = engine
        .eval_immediate(&invocation_script(&probe.invocation, arguments))
        .await
        .expect("execute public builtin invocation")
        .expect("public builtin invocation returned no result");
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    let invocation_result: serde_json::Value =
        serde_json::from_str(&encoded).expect("public builtin returned invalid JSON");
    let typed_decisions = typed_decision_values(&session_id, typed);
    let terminal = validate_observation(
        recipe,
        probe,
        &invocation_result,
        expected_decision_identity,
        legacy.len(),
        &typed_decisions,
        terminal_by_edge,
    );
    let mut runtime_invocation = serde_json::json!({
        "invocationSchema": probe.invocation.invocation_schema,
        "kind": probe.invocation.kind,
        "surfaceObservedKey": probe.surface_observed_key,
        "moduleSpecifier": probe.invocation.module_specifier,
        "sourceDescriptorDigest": probe.invocation.source_descriptor_digest,
        "result": invocation_result,
    });
    if probe.invocation.invocation_schema == "ibex/capsec-builtin-module-import-invocation/1" {
        runtime_invocation
            .as_object_mut()
            .expect("runtime invocation observation must be an object")
            .insert(
                "decisionIdentity".into(),
                expected_decision_identity.clone(),
            );
    }
    if let Some(export_name) = &probe.invocation.export_name {
        runtime_invocation
            .as_object_mut()
            .expect("runtime invocation observation must be an object")
            .insert(
                "exportName".into(),
                serde_json::Value::String(export_name.clone()),
            );
    }
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": runtime_invocation,
        "legacyObservationCount": legacy.len(),
        "typedDecisions": typed_decisions,
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
        "terminalObservedKey": terminal,
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
    serde_json::json!({
        "fixtureId": recipe.fixture_id,
        "outcome": "passed",
        "executor": "ibex-builtin-public-surface-harness",
        "evidence": evidence,
    })
}

async fn execute_isolated_recipe(
    recipe: &Recipe,
    terminal_by_edge: &BTreeMap<String, String>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let invocation = recipe
        .public_surface_probe
        .as_ref()
        .and_then(|probe| match probe {
            PublicSurfaceProbe::EffectBuiltin(probe) => Some(&probe.invocation),
            PublicSurfaceProbe::Other { .. } => None,
        })
        .expect("isolated recipe has no effect-builtin invocation");
    let authority = canonical_values(invocation.required_authority.clone());
    assert_eq!(
        authority.len(),
        1,
        "{}: isolated builtin recipe must bind one exact authority selector",
        recipe.fixture_id
    );
    let prepared = prepare_invocation(invocation);
    let module_specifier = invocation.module_specifier.clone();
    let denials = if recipe.scenario == "deny" {
        authority.clone()
    } else {
        Vec::new()
    };
    let (host, digest) = build_armed_test_host_control(
        prepared.project_root(),
        false,
        false,
        false,
        authority,
        Vec::new(),
        false,
        0,
        None,
        move |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] =
                serde_json::json!([module_specifier]);
            if !denials.is_empty() {
                snapshot["principals"][0]["denials"] = serde_json::Value::Array(denials);
            }
        },
    );
    let expected_decision_identity = serde_json::to_value(
        host.typed_semantic_identity_for_conformance()
            .expect("armed builtin Host has no semantic identity"),
    )
    .expect("serialize armed builtin Host semantic identity");
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))
        .expect("create exact public builtin engine");
    engine
        .load_runtime()
        .await
        .expect("load exact public builtin runtime");
    let mut engine = AuthenticatedBuiltinEngine {
        host,
        engine,
        publications: AuthenticatedPublicationTracker::default(),
    };
    let execution = execute_recipe(
        &mut engine,
        recipe,
        &prepared.arguments,
        &expected_decision_identity,
        terminal_by_edge,
        engine_binary_digest,
    )
    .await;
    engine
        .finish()
        .expect("finish authenticated effect-builtin publications");
    execution
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn capsec_public_builtin_recipe_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping builtin public recipe batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT").ok();
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipes = builtin_recipes(&catalog);
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // keep target-specific public evidence pinned to the exact authored slice:
    // Windows has the OS recipes but does not borrow Apple's typed fs probes.
    let expected_recipe_count = expected_authored_builtin_recipe_count(&catalog.target.triple);
    assert_eq!(
        recipes.len(),
        expected_recipe_count,
        "expected the target-authored export recipes plus 30 fresh-engine module-import recipes"
    );
    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before builtin public recipes");
    let portable = super::capsec_portable_public_batch::PortablePublicBatchContext::begin(
        "ibex-builtin-public-surface-harness",
    );
    assert_ne!(
        output_path.is_some(),
        portable.is_some(),
        "builtin public batch requires exactly one legacy output or portable plan"
    );
    let terminal_by_edge = coverage_terminals();
    let mut executions = Vec::with_capacity(recipes.len());
    for recipe in &recipes {
        executions.push(
            execute_isolated_recipe(recipe, &terminal_by_edge, &identity_before.binary_digest)
                .await,
        );
    }
    executions.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
    assert_eq!(executions.len(), recipes.len());
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after builtin public recipes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after builtin public recipes");
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
        .open(output_path.expect("legacy builtin public batch has no output path"))
        .expect("create owned builtin public evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize builtin public evidence artifact");
    output
        .write_all(b"\n")
        .expect("finish builtin public evidence");
    output.sync_all().expect("sync builtin public evidence");
}
