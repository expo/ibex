//! Oxc module producer proven by the LLP 0026 adoption-gate spike.
//!
//! The spike bundles remain fixture-only and are not wired into the evaluator
//! or cache. `produce_module_artifact_v1` is the production typed adapter and
//! requires an authenticated `SourceId`; it cannot emit the spike's interim
//! path identity.
//! @ref LLP 0026#adoption-gate — acceptance requires executed canonical
//! artifacts before implementation proceeds beyond spike scope.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, AssignmentExpression, AssignmentTarget, CallExpression, Declaration,
    ExportDefaultDeclarationKind, Expression, ForOfStatement, FunctionBody, IdentifierReference,
    ImportAttributeKey, ImportDeclarationSpecifier, ImportExpression, ImportOrExportKind,
    MetaProperty, Program, SimpleAssignmentTarget, Statement, UpdateExpression,
    VariableDeclarationKind, WithClause,
};
use oxc_ast_visit::{walk, Visit};
use oxc_codegen::{Codegen, CodegenOptions};
use oxc_parser::Parser;
use oxc_semantic::{IsGlobalReference, Scoping, SemanticBuilder};
use oxc_sourcemap::{SourceMap, SourceMapBuilder};
use oxc_span::{GetSpan, SourceType, Span};
use oxc_transformer::{JsxOptions, JsxRuntime, Module, TransformOptions, Transformer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::artifact::{
    digest_bytes, source_integrity, CanonicalSourceId, CommonJsExportsV1, DynamicEdgeV1,
    ExportDescriptorV1, ModuleArtifactV1, ModulePayloadV1, ModuleSemanticsV1, ProducerIdentityV1,
    SourceDialectV1, SourceGoalV1, SourceMapV1, StaticEdgeV1, TransformFingerprintV1,
    MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
};
use super::commonjs_lexer::{lex_commonjs, CJS_MODULE_LEXER_VERSION};
use super::identity::{ImportAttributes, SourceId};
use capsec_semantics::model::{Digest as CapsecDigest, NonEmptyString};

pub const SPIKE_TRANSFORM_FINGERPRINT: &str =
    "ibex-module-runner-spike/2+oxc-0.121.0+module-goal+hermes-abi-draft-1";

pub fn module_artifact_transform_fingerprint_v1(
    hermes_target: &str,
) -> Result<TransformFingerprintV1> {
    let option_digest = |label: &str| {
        source_integrity(label.as_bytes()).expect("static fingerprint input is valid")
    };
    Ok(TransformFingerprintV1 {
        producer: NonEmptyString::new("ibex-oxc-module-producer").unwrap(),
        parser_version: NonEmptyString::new("oxc-0.121.0").unwrap(),
        transform_version: NonEmptyString::new("ibex-module-artifact-producer-1").unwrap(),
        hermes_target: NonEmptyString::new(hermes_target).map_err(anyhow::Error::msg)?,
        typescript_jsx_options_digest: option_digest(
            "typescript=strip;jsx=classic;module-goal=true;decorators=off",
        ),
        module_runner_abi: NonEmptyString::new("ibex-module-runner-1").unwrap(),
        hermes_compat_version: NonEmptyString::new("llp0019-hermes-compat-1").unwrap(),
        commonjs_detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
        commonjs_detector_version: NonEmptyString::new("2.1.0").unwrap(),
        output_options_digest: option_digest(
            "factory=declare-execute;source-map=v3-source-id;minify=false",
        ),
    })
}

fn commonjs_artifact_transform_fingerprint_v1(
    hermes_target: &str,
) -> Result<TransformFingerprintV1> {
    let mut fingerprint = module_artifact_transform_fingerprint_v1(hermes_target)?;
    fingerprint.typescript_jsx_options_digest =
        source_integrity(b"typescript=strip;jsx=classic;module-goal=false;decorators=off")?;
    fingerprint.output_options_digest =
        source_integrity(b"factory=commonjs-wrapper;source-map=v3-source-id;minify=false")?;
    Ok(fingerprint)
}

fn json_artifact_transform_fingerprint_v1(hermes_target: &str) -> Result<TransformFingerprintV1> {
    let mut fingerprint = module_artifact_transform_fingerprint_v1(hermes_target)?;
    fingerprint.typescript_jsx_options_digest =
        source_integrity(b"strict-json=true;duplicate-keys=reject")?;
    fingerprint.output_options_digest =
        source_integrity(b"factory=json-default-export;source-map=v3-source-id;minify=false")?;
    Ok(fingerprint)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpikeManifest {
    pub schema: String,
    pub fixtures: Vec<SpikeFixtureManifest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpikeFixtureManifest {
    pub id: String,
    pub entry: String,
    pub modules: Vec<String>,
    pub expected: Value,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpikeArtifactBundle {
    pub schema: &'static str,
    pub transform_fingerprint: &'static str,
    pub manifest_schema: String,
    pub fixtures: Vec<SpikeFixtureArtifacts>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpikeFixtureArtifacts {
    pub id: String,
    pub entry: String,
    pub expected: Value,
    pub tags: Vec<String>,
    pub modules: Vec<SpikeModuleArtifact>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpikeModuleArtifact {
    pub fixture_id: String,
    pub source_name: String,
    pub dialect: String,
    pub source_integrity: String,
    pub transform_fingerprint: &'static str,
    pub static_edges: Vec<SpikeStaticEdge>,
    pub dynamic_edges: Vec<SpikeDynamicEdge>,
    pub export_descriptors: Vec<SpikeExportDescriptor>,
    pub has_top_level_await: bool,
    pub factory_source: String,
    pub source_map: Value,
    pub hermes_compat_passes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpikeDynamicEdge {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub specifier: Option<String>,
    pub site: u32,
    pub has_options: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpikeStaticEdge {
    pub specifier: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpikeExportDescriptor {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exported: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub specifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Test262SubsetManifest {
    pub schema: String,
    pub upstream: Value,
    pub minimum_pass_rate: Value,
    pub expected_divergences: Vec<Value>,
    pub cases: Vec<Test262SubsetCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Test262SubsetCase {
    pub id: String,
    pub suite: String,
    pub upstream_path: String,
    pub upstream_file_sha256: String,
    pub executable_body_sha256: String,
    pub source: String,
    pub expected_divergence: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Test262ArtifactBundle {
    pub schema: &'static str,
    pub transform_fingerprint: &'static str,
    pub subset_schema: String,
    pub upstream: Value,
    pub minimum_pass_rate: Value,
    pub expected_divergences: Vec<Value>,
    pub cases: Vec<Test262ArtifactCase>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Test262ArtifactCase {
    pub id: String,
    pub suite: String,
    pub upstream_path: String,
    pub upstream_file_sha256: String,
    pub executable_body_sha256: String,
    pub expected_divergence: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<SpikeModuleArtifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer_error: Option<String>,
}

#[derive(Debug)]
struct IntermediateSource {
    code: String,
    map: SourceMap,
}

#[derive(Debug, Clone)]
struct Replacement {
    span: Span,
    text: String,
}

#[derive(Debug, Default)]
struct LoweredFactoryBody {
    preamble: String,
    declare: String,
    execute: String,
    execute_line_origins: Vec<Option<u32>>,
}

#[derive(Debug, Default)]
struct NestedRewriteVisitor {
    imported: BTreeMap<String, (String, String)>,
    exported: BTreeSet<String>,
    export_callback: String,
    context: String,
    replacements: Vec<Replacement>,
    dynamic_edges: Vec<SpikeDynamicEdge>,
    function_depth: usize,
    hermes_compat_passes: BTreeSet<String>,
}

#[derive(Debug)]
struct CommonJsDependencyVisitor<'s> {
    scoping: &'s Scoping,
    require_specifiers: BTreeSet<String>,
    dynamic_edges: Vec<SpikeDynamicEdge>,
    replacements: Vec<Replacement>,
    computed_require_site: Option<u32>,
}

impl<'a> Visit<'a> for CommonJsDependencyVisitor<'_> {
    fn visit_call_expression(&mut self, expression: &CallExpression<'a>) {
        let is_wrapper_require = expression
            .callee
            .is_global_reference_name("require".into(), self.scoping);
        if is_wrapper_require {
            match expression.arguments.as_slice() {
                [Argument::StringLiteral(specifier)] => {
                    self.require_specifiers.insert(specifier.value.to_string());
                }
                _ => {
                    self.computed_require_site
                        .get_or_insert(expression.span.start);
                }
            };
        }
        walk::walk_call_expression(self, expression);
    }

    fn visit_import_expression(&mut self, expression: &ImportExpression<'a>) {
        let specifier = match &expression.source {
            Expression::StringLiteral(literal) => Some(literal.value.to_string()),
            _ => None,
        };
        self.dynamic_edges.push(SpikeDynamicEdge {
            kind: if specifier.is_some() {
                "literal".into()
            } else {
                "computed".into()
            },
            specifier,
            site: expression.span.start,
            has_options: expression.options.is_some(),
        });
        self.replacements.push(Replacement {
            span: expression.span,
            text: "dynamicImport(__IBEX_IMPORT_ARGUMENTS__)".into(),
        });
    }
}

impl<'a> Visit<'a> for NestedRewriteVisitor {
    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
        if self.function_depth == 0 && identifier.name == "arguments" {
            self.replacements.push(Replacement {
                span: identifier.span,
                text: "void 0".to_string(),
            });
            return;
        }
        if let Some((specifier, imported)) = self.imported.get(identifier.name.as_str()) {
            self.replacements.push(Replacement {
                span: identifier.span,
                text: format!(
                    "{}.importValue({}, {})",
                    self.context,
                    js_string(specifier),
                    js_string(imported)
                ),
            });
            return;
        }
        walk::walk_identifier_reference(self, identifier);
    }

    fn visit_assignment_expression(&mut self, expression: &AssignmentExpression<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(identifier) = &expression.left {
            if self.exported.contains(identifier.name.as_str()) {
                self.replacements.push(Replacement {
                    span: expression.span,
                    text: format!(
                        "{}({}, ({}))",
                        self.export_callback,
                        js_string(identifier.name.as_str()),
                        "__IBEX_ORIGINAL__"
                    ),
                });
                return;
            }
        }
        walk::walk_assignment_expression(self, expression);
    }

    fn visit_update_expression(&mut self, expression: &UpdateExpression<'a>) {
        if let SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) = &expression.argument
        {
            if self.exported.contains(identifier.name.as_str()) {
                self.replacements.push(Replacement {
                    span: expression.span,
                    text: format!(
                        "{}({}, ({}))",
                        self.export_callback,
                        js_string(identifier.name.as_str()),
                        "__IBEX_ORIGINAL__"
                    ),
                });
                return;
            }
        }
        walk::walk_update_expression(self, expression);
    }

    fn visit_import_expression(&mut self, expression: &ImportExpression<'a>) {
        let specifier = match &expression.source {
            Expression::StringLiteral(literal) => Some(literal.value.to_string()),
            _ => None,
        };
        self.dynamic_edges.push(SpikeDynamicEdge {
            kind: if specifier.is_some() {
                "literal".into()
            } else {
                "computed".into()
            },
            specifier,
            site: expression.span.start,
            has_options: expression.options.is_some(),
        });
        self.replacements.push(Replacement {
            span: expression.span,
            text: format!(
                "{}.dynamicImport({})",
                self.context, "__IBEX_IMPORT_ARGUMENTS__"
            ),
        });
    }

    fn visit_meta_property(&mut self, property: &MetaProperty<'a>) {
        if property.meta.name == "import" && property.property.name == "meta" {
            self.replacements.push(Replacement {
                span: property.span,
                text: format!("{}.meta", self.context),
            });
            return;
        }
        walk::walk_meta_property(self, property);
    }

    fn visit_for_of_statement(&mut self, statement: &ForOfStatement<'a>) {
        if let oxc_ast::ast::ForStatementLeft::VariableDeclaration(declaration) = &statement.left {
            if matches!(
                declaration.kind,
                VariableDeclarationKind::Const | VariableDeclarationKind::Let
            ) && declaration.declarations.len() == 1
                && declaration.declarations[0]
                    .id
                    .get_identifier_name()
                    .is_some()
                && matches!(&statement.body, Statement::BlockStatement(_))
            {
                let name = declaration.declarations[0]
                    .id
                    .get_identifier_name()
                    .expect("guarded identifier")
                    .to_string();
                let right = statement.right.span();
                let body = statement.body.span();
                self.replacements.push(Replacement {
                    span: statement.span,
                    text: format!(
                        "for (var {name} of __IBEX_FOR_RIGHT__) {{\n(function ({name}) {{\n__IBEX_FOR_BODY__\n}})({name});\n}}"
                    ),
                });
                // Encode the two child spans in a deterministic marker. They
                // are expanded from the original source by `materialize_replacement`.
                let replacement = self.replacements.last_mut().expect("just pushed");
                replacement.text = replacement
                    .text
                    .replace(
                        "__IBEX_FOR_RIGHT__",
                        &format!("__IBEX_SPAN_{}_{}__", right.start, right.end),
                    )
                    .replace(
                        "__IBEX_FOR_BODY__",
                        &format!("__IBEX_BODY_SPAN_{}_{}__", body.start + 1, body.end - 1),
                    );
                self.hermes_compat_passes
                    .insert("llp0019-for-of-block-capture-v1".to_string());
                return;
            }
        }
        walk::walk_for_of_statement(self, statement);
    }

    fn visit_function_body(&mut self, body: &FunctionBody<'a>) {
        self.function_depth += 1;
        walk::walk_function_body(self, body);
        self.function_depth -= 1;
    }
}

pub fn generate_spike_bundle(manifest_path: &Path) -> Result<SpikeArtifactBundle> {
    let manifest_text = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("read spike manifest {}", manifest_path.display()))?;
    let manifest: SpikeManifest = serde_json::from_str(&manifest_text)
        .with_context(|| format!("parse spike manifest {}", manifest_path.display()))?;
    if manifest.schema != "ibex/module-runner-spike-manifest/1" {
        bail!("unsupported spike manifest schema {}", manifest.schema);
    }
    let source_root = manifest_path
        .parent()
        .context("spike manifest has no parent")?
        .join("sources");
    let mut fixtures = Vec::with_capacity(manifest.fixtures.len());
    for fixture in manifest.fixtures {
        if fixture.modules.is_empty() || !fixture.modules.iter().any(|name| name == &fixture.entry)
        {
            bail!("fixture {} must enumerate its entry module", fixture.id);
        }
        let mut modules = Vec::with_capacity(fixture.modules.len());
        for source_name in &fixture.modules {
            let source_path = source_root.join(&fixture.id).join(source_name);
            let source = std::fs::read_to_string(&source_path)
                .with_context(|| format!("read spike source {}", source_path.display()))?;
            modules.push(produce_spike_artifact(
                &fixture.id,
                source_name,
                &source_path,
                &source,
            )?);
        }
        fixtures.push(SpikeFixtureArtifacts {
            id: fixture.id,
            entry: fixture.entry,
            expected: fixture.expected,
            tags: fixture.tags,
            modules,
        });
    }
    Ok(SpikeArtifactBundle {
        schema: "ibex/module-runner-spike-artifacts/1",
        transform_fingerprint: SPIKE_TRANSFORM_FINGERPRINT,
        manifest_schema: manifest.schema,
        fixtures,
    })
}

pub fn generate_test262_artifact_bundle(subset_path: &Path) -> Result<Test262ArtifactBundle> {
    let subset_text = std::fs::read_to_string(subset_path)
        .with_context(|| format!("read test262 subset {}", subset_path.display()))?;
    let subset: Test262SubsetManifest = serde_json::from_str(&subset_text)
        .with_context(|| format!("parse test262 subset {}", subset_path.display()))?;
    if subset.schema != "ibex/module-runner-test262-subset/1" {
        bail!("unsupported test262 subset schema {}", subset.schema);
    }
    let mut cases = Vec::with_capacity(subset.cases.len());
    for case in subset.cases {
        let source_path = Path::new(&case.upstream_path);
        let produced = produce_spike_artifact(&case.id, "entry.js", source_path, &case.source);
        let (artifact, producer_error) = match produced {
            Ok(artifact) => (Some(artifact), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
        cases.push(Test262ArtifactCase {
            id: case.id,
            suite: case.suite,
            upstream_path: case.upstream_path,
            upstream_file_sha256: case.upstream_file_sha256,
            executable_body_sha256: case.executable_body_sha256,
            expected_divergence: case.expected_divergence,
            artifact,
            producer_error,
        });
    }
    Ok(Test262ArtifactBundle {
        schema: "ibex/module-runner-test262-artifacts/1",
        transform_fingerprint: SPIKE_TRANSFORM_FINGERPRINT,
        subset_schema: subset.schema,
        upstream: subset.upstream,
        minimum_pass_rate: subset.minimum_pass_rate,
        expected_divergences: subset.expected_divergences,
        cases,
    })
}

pub fn produce_spike_artifact(
    fixture_id: &str,
    source_name: &str,
    source_path: &Path,
    source: &str,
) -> Result<SpikeModuleArtifact> {
    let intermediate = transform_with_oxc(source_path, source)?;
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, &intermediate.code, SourceType::mjs()).parse();
    if !parsed.errors.is_empty() {
        bail!(
            "Oxc could not parse transformed {}: {:?}\ntransformed source:\n{}",
            source_name,
            parsed.errors,
            intermediate.code
        );
    }
    let program = parsed.program;
    let has_top_level_await = has_top_level_await(&program);
    let (export_callback, context) = fresh_abi_names(&program);

    let mut static_edges = Vec::new();
    let mut export_descriptors = Vec::new();
    let mut imported = BTreeMap::new();
    let mut exported = BTreeSet::new();

    for statement in &program.body {
        match statement {
            Statement::ImportDeclaration(declaration) => {
                let specifier = declaration.source.value.to_string();
                let attributes = import_attributes(&declaration.with_clause)?;
                let Some(specifiers) = &declaration.specifiers else {
                    static_edges.push(SpikeStaticEdge {
                        specifier,
                        kind: "sideEffect".to_string(),
                        attributes,
                        imported: None,
                        local: None,
                    });
                    continue;
                };
                for item in specifiers {
                    match item {
                        ImportDeclarationSpecifier::ImportSpecifier(item)
                            if item.import_kind == ImportOrExportKind::Value =>
                        {
                            let imported_name = item.imported.name().to_string();
                            let local = item.local.name.to_string();
                            imported
                                .insert(local.clone(), (specifier.clone(), imported_name.clone()));
                            static_edges.push(SpikeStaticEdge {
                                specifier: specifier.clone(),
                                kind: "named".to_string(),
                                attributes: attributes.clone(),
                                imported: Some(imported_name),
                                local: Some(local),
                            });
                        }
                        ImportDeclarationSpecifier::ImportDefaultSpecifier(item) => {
                            let local = item.local.name.to_string();
                            imported
                                .insert(local.clone(), (specifier.clone(), "default".to_string()));
                            static_edges.push(SpikeStaticEdge {
                                specifier: specifier.clone(),
                                kind: "default".to_string(),
                                attributes: attributes.clone(),
                                imported: Some("default".to_string()),
                                local: Some(local),
                            });
                        }
                        ImportDeclarationSpecifier::ImportNamespaceSpecifier(item) => {
                            let local = item.local.name.to_string();
                            imported.insert(local.clone(), (specifier.clone(), "*".to_string()));
                            static_edges.push(SpikeStaticEdge {
                                specifier: specifier.clone(),
                                kind: "namespace".to_string(),
                                attributes: attributes.clone(),
                                imported: Some("*".to_string()),
                                local: Some(local),
                            });
                        }
                        ImportDeclarationSpecifier::ImportSpecifier(_) => {}
                    }
                }
            }
            Statement::ExportNamedDeclaration(declaration) => {
                let attributes = import_attributes(&declaration.with_clause)?;
                if let Some(inner) = &declaration.declaration {
                    for name in declaration_names(inner)? {
                        exported.insert(name.clone());
                        export_descriptors.push(local_export(&name));
                    }
                }
                for item in &declaration.specifiers {
                    if item.export_kind != ImportOrExportKind::Value {
                        continue;
                    }
                    let exported_name = item.exported.name().to_string();
                    if let Some(source) = &declaration.source {
                        let imported_name = item.local.name().to_string();
                        static_edges.push(SpikeStaticEdge {
                            specifier: source.value.to_string(),
                            kind: "reExport".to_string(),
                            attributes: attributes.clone(),
                            imported: Some(imported_name.clone()),
                            local: None,
                        });
                        export_descriptors.push(SpikeExportDescriptor {
                            kind: "indirect".to_string(),
                            exported: Some(exported_name),
                            local: None,
                            specifier: Some(source.value.to_string()),
                            imported: Some(imported_name),
                        });
                    } else {
                        let local = item.local.name().to_string();
                        exported.insert(local.clone());
                        export_descriptors.push(SpikeExportDescriptor {
                            kind: "local".to_string(),
                            exported: Some(exported_name),
                            local: Some(local),
                            specifier: None,
                            imported: None,
                        });
                    }
                }
            }
            Statement::ExportDefaultDeclaration(_) => {
                exported.insert("__ibex_default_value".to_string());
                export_descriptors.push(SpikeExportDescriptor {
                    kind: "local".to_string(),
                    exported: Some("default".to_string()),
                    local: Some("__ibex_default_value".to_string()),
                    specifier: None,
                    imported: None,
                });
            }
            Statement::ExportAllDeclaration(declaration) => {
                let specifier = declaration.source.value.to_string();
                static_edges.push(SpikeStaticEdge {
                    specifier: specifier.clone(),
                    kind: "reExportStar".to_string(),
                    attributes: import_attributes(&declaration.with_clause)?,
                    imported: Some("*".to_string()),
                    local: None,
                });
                export_descriptors.push(SpikeExportDescriptor {
                    kind: if declaration.exported.is_some() {
                        "namespace"
                    } else {
                        "star"
                    }
                    .to_string(),
                    exported: declaration
                        .exported
                        .as_ref()
                        .map(|name| name.name().to_string()),
                    local: None,
                    specifier: Some(specifier),
                    imported: Some("*".to_string()),
                });
            }
            _ => {}
        }
    }

    let mut visitor = NestedRewriteVisitor {
        imported,
        exported,
        export_callback: export_callback.clone(),
        context: context.clone(),
        ..NestedRewriteVisitor::default()
    };
    visitor.visit_program(&program);

    let lowered = lower_module_body(
        &program,
        &intermediate.code,
        &visitor.replacements,
        &export_callback,
    )?;
    let execute = if has_top_level_await {
        "async function"
    } else {
        "function"
    };
    let prefix = format!(
        "function ({export_callback}, {context}) {{\n\"use strict\";\n{}return {{\ndeclare: function () {{\n{}\n}},\nexecute: {execute} () {{\n",
        lowered.preamble, lowered.declare
    );
    let suffix = "\n}\n};\n}\n";
    let factory_source = format!("{prefix}{}{suffix}", lowered.execute);
    let source_map = compose_factory_source_map(
        source_name,
        source,
        &intermediate.map,
        prefix.lines().count() as u32,
        &lowered.execute_line_origins,
        &factory_source,
    )?;

    let dialect = source_path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("js")
        .to_ascii_uppercase();
    let integrity = Sha256::digest(source.as_bytes());
    visitor.dynamic_edges.sort_by_key(|edge| edge.site);
    for (site, edge) in visitor.dynamic_edges.iter_mut().enumerate() {
        edge.site = u32::try_from(site).context("too many dynamic-import sites")?;
    }
    Ok(SpikeModuleArtifact {
        fixture_id: fixture_id.to_string(),
        source_name: source_name.to_string(),
        dialect,
        source_integrity: format!(
            "sha256-{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, integrity)
        ),
        transform_fingerprint: SPIKE_TRANSFORM_FINGERPRINT,
        static_edges,
        dynamic_edges: visitor.dynamic_edges,
        export_descriptors,
        has_top_level_await,
        factory_source,
        source_map,
        hermes_compat_passes: visitor.hermes_compat_passes.into_iter().collect(),
    })
}

/// Production v1 adapter over the proven Oxc spike producer. The adapter is
/// intentionally typed and fail-closed: lossy spike fields do not pass through
/// as free-form artifact variants.
/// @ref LLP 0027#artifact-envelope — the producer emits the closed semantic
/// core and authenticates the inline factory separately.
pub fn produce_module_artifact_v1(
    source_id: SourceId,
    source_name: &str,
    source_path: &Path,
    source: &str,
    producer_binary_digest: CapsecDigest,
    hermes_target: &str,
) -> Result<ModuleArtifactV1> {
    let spike = produce_spike_artifact("module-artifact-v1", source_name, source_path, source)?;
    let fingerprint = module_artifact_transform_fingerprint_v1(hermes_target)?;
    let static_edges = spike
        .static_edges
        .iter()
        .map(|edge| static_edge_v1(edge, &spike.export_descriptors))
        .collect::<Result<Vec<_>>>()?;
    let dynamic_edges = spike
        .dynamic_edges
        .iter()
        .map(|edge| {
            if edge.has_options {
                bail!("dynamic import options are not yet representable in ModuleArtifact v1");
            }
            match edge.specifier.as_deref() {
                Some(specifier) => Ok(DynamicEdgeV1::Literal {
                    specifier: non_empty(specifier, "dynamic import specifier")?,
                    attributes: ImportAttributes::default(),
                }),
                None => Ok(DynamicEdgeV1::Computed { site: edge.site }),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let export_descriptors = spike
        .export_descriptors
        .iter()
        .map(export_descriptor_v1)
        .collect::<Result<Vec<_>>>()?;
    let source_map = SourceMapV1 {
        version: spike.source_map["version"]
            .as_u64()
            .and_then(|version| u8::try_from(version).ok())
            .ok_or_else(|| anyhow!("producer source map has no supported version"))?,
        source_ids: vec![CanonicalSourceId(source_id.clone())],
        names: spike.source_map["names"]
            .as_array()
            .ok_or_else(|| anyhow!("producer source map has no names array"))?
            .iter()
            .map(|name| {
                name.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("producer source-map name is not a string"))
            })
            .collect::<Result<Vec<_>>>()?,
        mappings: spike.source_map["mappings"]
            .as_str()
            .ok_or_else(|| anyhow!("producer source map has no mappings string"))?
            .to_owned(),
    };
    let dialect = match spike.dialect.as_str() {
        "JS" | "MJS" => SourceDialectV1::Js,
        "JSX" => SourceDialectV1::Jsx,
        "TS" | "MTS" => SourceDialectV1::Ts,
        "TSX" => SourceDialectV1::Tsx,
        other => bail!("unsupported producer source dialect {other:?}"),
    };
    let factory_digest = digest_bytes(
        MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
        spike.factory_source.as_bytes(),
    )?;
    let semantics = ModuleSemanticsV1 {
        source_id: CanonicalSourceId(source_id),
        source_goal: SourceGoalV1::Module,
        dialect: Some(dialect),
        source_integrity: source_integrity(source.as_bytes())?,
        transform_fingerprint: fingerprint,
        static_edges,
        dynamic_edges,
        export_descriptors,
        commonjs_exports: None,
        has_top_level_await: spike.has_top_level_await,
        factory_digest,
        source_map,
    };
    ModuleArtifactV1::new_inline(
        semantics,
        spike.factory_source,
        ProducerIdentityV1::InProcess {
            producer_id: NonEmptyString::new("ibex-runtime-oxc").map_err(anyhow::Error::msg)?,
            producer_binary_digest,
        },
    )
}

/// Produce a script-goal CommonJS factory without invoking an ambient JS
/// runtime. Literal require edges are authenticated separately from dynamic
/// imports, and computed require remains an explicit bounded-fallback shape.
pub fn produce_commonjs_artifact_v1(
    source_id: SourceId,
    source_name: &str,
    source_path: &Path,
    source: &str,
    producer_binary_digest: CapsecDigest,
    hermes_target: &str,
) -> Result<ModuleArtifactV1> {
    let intermediate = transform_with_oxc_goal(source_path, source, false)?;
    let allocator = Allocator::default();
    let parsed = Parser::new(
        &allocator,
        &intermediate.code,
        SourceType::default().with_module(false),
    )
    .parse();
    if !parsed.errors.is_empty() {
        bail!(
            "Oxc could not parse transformed CommonJS {}: {:?}",
            source_name,
            parsed.errors
        );
    }
    let program = parsed.program;
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&program);
    if !semantic.errors.is_empty() {
        bail!(
            "Oxc semantics failed for transformed CommonJS {}: {:?}",
            source_name,
            semantic.errors
        );
    }
    let mut visitor = CommonJsDependencyVisitor {
        scoping: semantic.semantic.scoping(),
        require_specifiers: BTreeSet::new(),
        dynamic_edges: Vec::new(),
        replacements: Vec::new(),
        computed_require_site: None,
    };
    visitor.visit_program(&program);
    if let Some(site) = visitor.computed_require_site {
        bail!(
            "computed CommonJS require at transformed byte offset {site} has no authenticated finite candidate table"
        );
    }
    if visitor.dynamic_edges.iter().any(|edge| edge.has_options) {
        bail!("dynamic import options are not yet representable in ModuleArtifact v1");
    }

    let detector = lex_commonjs(&intermediate.code)?;
    visitor
        .require_specifiers
        .extend(detector.reexports.iter().cloned());
    let static_edges = visitor
        .require_specifiers
        .into_iter()
        .map(|specifier| {
            Ok(StaticEdgeV1::CommonJsRequire {
                specifier: non_empty(&specifier, "CommonJS require specifier")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    visitor.dynamic_edges.sort_by_key(|edge| edge.site);
    let dynamic_edges = visitor
        .dynamic_edges
        .iter()
        .enumerate()
        .map(|(site, edge)| match edge.specifier.as_deref() {
            Some(specifier) => Ok(DynamicEdgeV1::Literal {
                specifier: non_empty(specifier, "dynamic import specifier")?,
                attributes: ImportAttributes::default(),
            }),
            None => Ok(DynamicEdgeV1::Computed {
                site: u32::try_from(site).context("too many dynamic-import sites")?,
            }),
        })
        .collect::<Result<Vec<_>>>()?;
    let rewritten = apply_replacements(
        &intermediate.code,
        Span::new(0, intermediate.code.len() as u32),
        &visitor.replacements,
    )?;
    let prefix = "function (require, module, exports, __filename, __dirname, dynamicImport) {\n";
    let suffix = "\n}\n";
    let factory_source = format!("{prefix}{rewritten}{suffix}");
    let line_origins = (0..intermediate.code.lines().count().max(1))
        .map(|line| Some(line as u32))
        .collect::<Vec<_>>();
    let source_map_value = compose_factory_source_map(
        source_name,
        source,
        &intermediate.map,
        prefix.lines().count() as u32,
        &line_origins,
        &factory_source,
    )?;
    let source_map = source_map_v1(source_id.clone(), &source_map_value)?;
    let dialect = source_dialect(source_path)?;
    let fingerprint = commonjs_artifact_transform_fingerprint_v1(hermes_target)?;
    let commonjs_exports = CommonJsExportsV1 {
        detector: fingerprint.commonjs_detector.clone(),
        detector_version: non_empty(CJS_MODULE_LEXER_VERSION, "CommonJS detector version")?,
        names: detector
            .exports
            .iter()
            .map(|name| non_empty(name, "CommonJS export name"))
            .collect::<Result<Vec<_>>>()?,
        reexports: detector
            .reexports
            .iter()
            .map(|specifier| non_empty(specifier, "CommonJS reexport specifier"))
            .collect::<Result<Vec<_>>>()?,
    };
    let factory_digest =
        digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory_source.as_bytes())?;
    ModuleArtifactV1::new_inline(
        ModuleSemanticsV1 {
            source_id: CanonicalSourceId(source_id),
            source_goal: SourceGoalV1::CommonJs,
            dialect: Some(dialect),
            source_integrity: source_integrity(source.as_bytes())?,
            transform_fingerprint: fingerprint,
            static_edges,
            dynamic_edges,
            export_descriptors: Vec::new(),
            commonjs_exports: Some(commonjs_exports),
            has_top_level_await: false,
            factory_digest,
            source_map,
        },
        factory_source,
        ProducerIdentityV1::InProcess {
            producer_id: NonEmptyString::new("ibex-runtime-oxc").map_err(anyhow::Error::msg)?,
            producer_binary_digest,
        },
    )
}

/// Produce one strict JSON record whose sole export is `default`. The original
/// bytes remain the integrity input; only the trusted factory embeds canonical
/// JCS so whitespace and object-order choices cannot become executable text.
pub fn produce_json_artifact_v1(
    source_id: SourceId,
    source: &str,
    producer_binary_digest: CapsecDigest,
    hermes_target: &str,
) -> Result<ModuleArtifactV1> {
    let value = capsec_semantics::strict_json::parse_strict(source)
        .map_err(|error| anyhow!("JSON module is not strict JSON: {error}"))?;
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
        .map_err(|error| anyhow!("JSON module cannot be canonicalized: {error}"))?;
    let canonical = String::from_utf8(canonical).context("canonical JSON is not UTF-8")?;
    let factory_source = format!(
        "function ($export) {{ return {{ declare: function () {{}}, execute: function () {{ $export('default', {canonical}); }} }}; }}"
    );
    let factory_digest =
        digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory_source.as_bytes())?;
    ModuleArtifactV1::new_inline(
        ModuleSemanticsV1 {
            source_id: CanonicalSourceId(source_id.clone()),
            source_goal: SourceGoalV1::Json,
            dialect: None,
            source_integrity: source_integrity(source.as_bytes())?,
            transform_fingerprint: json_artifact_transform_fingerprint_v1(hermes_target)?,
            static_edges: Vec::new(),
            dynamic_edges: Vec::new(),
            export_descriptors: Vec::new(),
            commonjs_exports: None,
            has_top_level_await: false,
            factory_digest,
            source_map: SourceMapV1 {
                version: 3,
                source_ids: vec![CanonicalSourceId(source_id)],
                names: Vec::new(),
                mappings: String::new(),
            },
        },
        factory_source,
        ProducerIdentityV1::InProcess {
            producer_id: NonEmptyString::new("ibex-runtime-oxc").map_err(anyhow::Error::msg)?,
            producer_binary_digest,
        },
    )
}

/// Builtins are authenticated registry sources with CommonJS execution
/// semantics. They retain the distinct Builtin source goal and SourceId so
/// package code cannot counterfeit host-owned module identity.
pub fn produce_builtin_artifact_v1(
    source_id: SourceId,
    source_name: &str,
    source: &str,
    producer_binary_digest: CapsecDigest,
    hermes_target: &str,
) -> Result<ModuleArtifactV1> {
    let path = PathBuf::from(format!("{source_name}.js"));
    let staging_id = SourceId::synthetic("builtin-producer", source_name)?;
    let artifact = produce_commonjs_artifact_v1(
        staging_id,
        source_name,
        &path,
        source,
        producer_binary_digest,
        hermes_target,
    )?;
    let ModulePayloadV1::Inline { factory_source, .. } = artifact.payload else {
        unreachable!()
    };
    let mut semantics = artifact.semantics;
    semantics.source_id = CanonicalSourceId(source_id.clone());
    semantics.source_map.source_ids = vec![CanonicalSourceId(source_id)];
    semantics.source_goal = SourceGoalV1::Builtin;
    ModuleArtifactV1::new_inline(semantics, factory_source, artifact.producer)
}

fn source_dialect(path: &Path) -> Result<SourceDialectV1> {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("js")
        .to_ascii_lowercase()
        .as_str()
    {
        "js" | "mjs" | "cjs" => Ok(SourceDialectV1::Js),
        "jsx" => Ok(SourceDialectV1::Jsx),
        "ts" | "mts" | "cts" => Ok(SourceDialectV1::Ts),
        "tsx" => Ok(SourceDialectV1::Tsx),
        other => bail!("unsupported producer source dialect {other:?}"),
    }
}

fn source_map_v1(source_id: SourceId, value: &Value) -> Result<SourceMapV1> {
    Ok(SourceMapV1 {
        version: value["version"]
            .as_u64()
            .and_then(|version| u8::try_from(version).ok())
            .ok_or_else(|| anyhow!("producer source map has no supported version"))?,
        source_ids: vec![CanonicalSourceId(source_id)],
        names: value["names"]
            .as_array()
            .ok_or_else(|| anyhow!("producer source map has no names array"))?
            .iter()
            .map(|name| {
                name.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("producer source-map name is not a string"))
            })
            .collect::<Result<Vec<_>>>()?,
        mappings: value["mappings"]
            .as_str()
            .ok_or_else(|| anyhow!("producer source map has no mappings string"))?
            .to_owned(),
    })
}

fn non_empty(value: &str, label: &str) -> Result<NonEmptyString> {
    NonEmptyString::new(value).map_err(|error| anyhow!("invalid {label}: {error}"))
}

fn import_attributes(
    with_clause: &Option<oxc_allocator::Box<'_, WithClause<'_>>>,
) -> Result<BTreeMap<String, String>> {
    let mut attributes = BTreeMap::new();
    let Some(with_clause) = with_clause else {
        return Ok(attributes);
    };
    for attribute in &with_clause.with_entries {
        let key = match &attribute.key {
            ImportAttributeKey::Identifier(identifier) => identifier.name.as_str(),
            ImportAttributeKey::StringLiteral(literal) => literal.value.as_str(),
        };
        let value = attribute.value.value.as_str();
        if attributes
            .insert(key.to_owned(), value.to_owned())
            .is_some()
        {
            bail!("duplicate import attribute {key:?}");
        }
    }
    Ok(attributes)
}

fn static_edge_v1(
    edge: &SpikeStaticEdge,
    exports: &[SpikeExportDescriptor],
) -> Result<StaticEdgeV1> {
    let specifier = non_empty(&edge.specifier, "static-edge specifier")?;
    let attributes = ImportAttributes::new(edge.attributes.clone())?;
    Ok(match edge.kind.as_str() {
        "sideEffect" => StaticEdgeV1::SideEffect {
            specifier,
            attributes,
        },
        "default" => StaticEdgeV1::Default {
            specifier,
            local: non_empty(
                edge.local
                    .as_deref()
                    .ok_or_else(|| anyhow!("default edge has no local"))?,
                "default local",
            )?,
            attributes,
        },
        "namespace" => StaticEdgeV1::Namespace {
            specifier,
            local: non_empty(
                edge.local
                    .as_deref()
                    .ok_or_else(|| anyhow!("namespace edge has no local"))?,
                "namespace local",
            )?,
            attributes,
        },
        "named" => StaticEdgeV1::Named {
            specifier,
            imported: non_empty(
                edge.imported
                    .as_deref()
                    .ok_or_else(|| anyhow!("named edge has no imported name"))?,
                "imported name",
            )?,
            local: non_empty(
                edge.local
                    .as_deref()
                    .ok_or_else(|| anyhow!("named edge has no local"))?,
                "named local",
            )?,
            attributes,
        },
        "reExport" => {
            let imported = edge
                .imported
                .as_deref()
                .ok_or_else(|| anyhow!("re-export edge has no imported name"))?;
            let exported = exports
                .iter()
                .find(|descriptor| {
                    descriptor.kind == "indirect"
                        && descriptor.specifier.as_deref() == Some(edge.specifier.as_str())
                        && descriptor.imported.as_deref() == Some(imported)
                })
                .and_then(|descriptor| descriptor.exported.as_deref())
                .ok_or_else(|| anyhow!("re-export edge has no matching export descriptor"))?;
            StaticEdgeV1::ReExportNamed {
                specifier,
                imported: non_empty(imported, "re-export imported name")?,
                exported: non_empty(exported, "re-export exported name")?,
                attributes,
            }
        }
        "reExportStar" => {
            let namespace = exports.iter().find(|descriptor| {
                descriptor.kind == "namespace"
                    && descriptor.specifier.as_deref() == Some(edge.specifier.as_str())
            });
            if let Some(namespace) = namespace {
                StaticEdgeV1::ReExportNamespace {
                    specifier,
                    exported: non_empty(
                        namespace
                            .exported
                            .as_deref()
                            .ok_or_else(|| anyhow!("namespace re-export has no exported name"))?,
                        "namespace re-export name",
                    )?,
                    attributes,
                }
            } else {
                StaticEdgeV1::ReExportStar {
                    specifier,
                    attributes,
                }
            }
        }
        other => bail!("unsupported producer static-edge kind {other:?}"),
    })
}

fn export_descriptor_v1(descriptor: &SpikeExportDescriptor) -> Result<ExportDescriptorV1> {
    Ok(match descriptor.kind.as_str() {
        "local" => ExportDescriptorV1::Local {
            exported: non_empty(
                descriptor
                    .exported
                    .as_deref()
                    .ok_or_else(|| anyhow!("local export has no exported name"))?,
                "exported name",
            )?,
            local: non_empty(
                descriptor
                    .local
                    .as_deref()
                    .ok_or_else(|| anyhow!("local export has no local name"))?,
                "local export name",
            )?,
        },
        "indirect" => ExportDescriptorV1::Indirect {
            exported: non_empty(
                descriptor
                    .exported
                    .as_deref()
                    .ok_or_else(|| anyhow!("indirect export has no exported name"))?,
                "indirect exported name",
            )?,
            specifier: non_empty(
                descriptor
                    .specifier
                    .as_deref()
                    .ok_or_else(|| anyhow!("indirect export has no specifier"))?,
                "indirect specifier",
            )?,
            imported: non_empty(
                descriptor
                    .imported
                    .as_deref()
                    .ok_or_else(|| anyhow!("indirect export has no imported name"))?,
                "indirect imported name",
            )?,
        },
        "star" => ExportDescriptorV1::Star {
            specifier: non_empty(
                descriptor
                    .specifier
                    .as_deref()
                    .ok_or_else(|| anyhow!("star export has no specifier"))?,
                "star specifier",
            )?,
        },
        "namespace" => ExportDescriptorV1::Namespace {
            exported: non_empty(
                descriptor
                    .exported
                    .as_deref()
                    .ok_or_else(|| anyhow!("namespace export has no exported name"))?,
                "namespace exported name",
            )?,
            specifier: non_empty(
                descriptor
                    .specifier
                    .as_deref()
                    .ok_or_else(|| anyhow!("namespace export has no specifier"))?,
                "namespace specifier",
            )?,
        },
        other => bail!("unsupported producer export-descriptor kind {other:?}"),
    })
}

fn transform_with_oxc(path: &Path, source: &str) -> Result<IntermediateSource> {
    transform_with_oxc_goal(path, source, true)
}

fn transform_with_oxc_goal(
    path: &Path,
    source: &str,
    module_goal: bool,
) -> Result<IntermediateSource> {
    let allocator = Allocator::default();
    // The producer contract is an ESM artifact regardless of whether the
    // resolved pathname ends in `.js`, `.mjs`, `.ts`, or `.tsx`. Leaving a
    // plain `.js` path in Script goal makes `await /regexp/` lex as identifier
    // division identifier division identifier before module metadata exists.
    // @ref LLP 0026#parse-once-never-infer-grammar-with-runtime-regular-expressions
    let source_type = SourceType::from_path(path)
        .unwrap_or_else(|_| SourceType::mjs())
        .with_module(module_goal);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() {
        bail!(
            "Oxc parse failed for {}: {:?}",
            path.display(),
            parsed.errors
        );
    }
    let mut program = parsed.program;
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&program);
    if !semantic.errors.is_empty() {
        bail!(
            "Oxc semantics failed for {}: {:?}",
            path.display(),
            semantic.errors
        );
    }
    // The factory ABI, not Hermes' native module parser, consumes TLA. Keep
    // Oxc's target at ES2022 so it preserves top-level await for the async
    // execute function; the explicit LLP 0019 compatibility tier handles
    // Hermes-specific syntax/runtime gaps separately.
    let mut options = TransformOptions::from_target("es2022")
        .map_err(|error| anyhow!("configure Oxc ES2022 target: {error}"))?;
    options.env.module = Module::Preserve;
    options.jsx = JsxOptions {
        runtime: JsxRuntime::Classic,
        ..JsxOptions::enable()
    };
    let transformed = Transformer::new(&allocator, path, &options)
        .build_with_scoping(semantic.semantic.into_scoping(), &mut program);
    if !transformed.errors.is_empty() {
        bail!(
            "Oxc transform failed for {}: {:?}",
            path.display(),
            transformed.errors
        );
    }
    let codegen = Codegen::new()
        .with_options(CodegenOptions {
            source_map_path: Some(path.to_path_buf()),
            ..CodegenOptions::default()
        })
        .with_source_text(source)
        .with_scoping(Some(transformed.scoping))
        .build(&program);
    let map = codegen
        .map
        .ok_or_else(|| anyhow!("Oxc emitted no source map for {}", path.display()))?;
    Ok(IntermediateSource {
        code: codegen.code,
        map,
    })
}

fn declaration_names(declaration: &Declaration<'_>) -> Result<Vec<String>> {
    match declaration {
        Declaration::VariableDeclaration(declaration) => Ok(declaration
            .declarations
            .iter()
            .flat_map(|item| item.id.get_binding_identifiers())
            .map(|identifier| identifier.name.to_string())
            .collect()),
        Declaration::FunctionDeclaration(function) => function
            .id
            .as_ref()
            .map(|identifier| vec![identifier.name.to_string()])
            .ok_or_else(|| anyhow!("exported function declaration must be named")),
        Declaration::ClassDeclaration(class) => class
            .id
            .as_ref()
            .map(|identifier| vec![identifier.name.to_string()])
            .ok_or_else(|| anyhow!("exported class declaration must be named")),
        _ => bail!("producer spike does not emit TypeScript-only export declarations"),
    }
}

fn local_export(name: &str) -> SpikeExportDescriptor {
    SpikeExportDescriptor {
        kind: "local".to_string(),
        exported: Some(name.to_string()),
        local: Some(name.to_string()),
        specifier: None,
        imported: None,
    }
}

fn lower_module_body(
    program: &Program<'_>,
    source: &str,
    nested: &[Replacement],
    export_callback: &str,
) -> Result<LoweredFactoryBody> {
    let mut lowered = LoweredFactoryBody::default();
    for statement in &program.body {
        let statement_span = statement.span();
        match statement {
            Statement::ImportDeclaration(_) | Statement::ExportAllDeclaration(_) => {}
            Statement::ExportNamedDeclaration(declaration) => {
                if let Some(inner) = &declaration.declaration {
                    match inner {
                        Declaration::VariableDeclaration(declaration) => {
                            for declarator in &declaration.declarations {
                                let names = declarator.id.get_binding_identifiers();
                                if names.len() != 1 {
                                    bail!("producer spike supports one simple binding per exported declarator");
                                }
                                let name = names[0].name.to_string();
                                lowered.preamble.push_str(&format!("let {name};\n"));
                                let initializer = if let Some(initializer) = &declarator.init {
                                    apply_replacements(source, initializer.span(), nested)?
                                } else {
                                    "void 0".to_string()
                                };
                                append_mapped(
                                    &mut lowered.execute,
                                    &mut lowered.execute_line_origins,
                                    &format!(
                                        "{name} = {initializer};\n{export_callback}({}, {name});\n",
                                        js_string(&name)
                                    ),
                                    line_of(source, declarator.span.start),
                                );
                            }
                        }
                        Declaration::FunctionDeclaration(_) => {
                            let span = inner.span();
                            let function = apply_replacements(source, span, nested)?;
                            lowered.preamble.push_str(&function);
                            lowered.preamble.push('\n');
                            for name in declaration_names(inner)? {
                                lowered.declare.push_str(&format!(
                                    "{export_callback}({}, {name});\n",
                                    js_string(&name)
                                ));
                            }
                        }
                        _ => {
                            let span = inner.span();
                            let declaration = apply_replacements(source, span, nested)?;
                            append_mapped(
                                &mut lowered.execute,
                                &mut lowered.execute_line_origins,
                                &declaration,
                                line_of(source, span.start),
                            );
                            for name in declaration_names(inner)? {
                                append_mapped(
                                    &mut lowered.execute,
                                    &mut lowered.execute_line_origins,
                                    &format!("\n{export_callback}({}, {name});", js_string(&name)),
                                    line_of(source, span.start),
                                );
                            }
                            lowered.execute.push('\n');
                        }
                    }
                } else if declaration.source.is_none() {
                    for item in &declaration.specifiers {
                        if item.export_kind == ImportOrExportKind::Value {
                            append_mapped(
                                &mut lowered.execute,
                                &mut lowered.execute_line_origins,
                                &format!(
                                    "{export_callback}({}, {});\n",
                                    js_string(item.exported.name().as_str()),
                                    item.local.name()
                                ),
                                line_of(source, statement_span.start),
                            );
                        }
                    }
                }
            }
            Statement::ExportDefaultDeclaration(declaration) => {
                let span = declaration.declaration.span();
                let expression = apply_replacements(source, span, nested)?;
                let default_code = match &declaration.declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                        if let Some(identifier) = &function.id {
                            format!(
                                "{expression}\n{export_callback}(\"default\", {});",
                                identifier.name
                            )
                        } else {
                            format!("const __ibex_default_value = {expression};\n{export_callback}(\"default\", __ibex_default_value);")
                        }
                    }
                    ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                        if let Some(identifier) = &class.id {
                            format!(
                                "{expression}\n{export_callback}(\"default\", {});",
                                identifier.name
                            )
                        } else {
                            format!("const __ibex_default_value = {expression};\n{export_callback}(\"default\", __ibex_default_value);")
                        }
                    }
                    _ => format!("const __ibex_default_value = {expression};\n{export_callback}(\"default\", __ibex_default_value);"),
                };
                append_mapped(
                    &mut lowered.execute,
                    &mut lowered.execute_line_origins,
                    &default_code,
                    line_of(source, span.start),
                );
                lowered.execute.push('\n');
            }
            _ => {
                let statement = apply_replacements(source, statement_span, nested)?;
                append_mapped(
                    &mut lowered.execute,
                    &mut lowered.execute_line_origins,
                    &statement,
                    line_of(source, statement_span.start),
                );
                lowered.execute.push('\n');
            }
        }
    }
    lowered.execute = lowered.execute.trim_end().to_string();
    Ok(lowered)
}

fn apply_replacements(source: &str, range: Span, replacements: &[Replacement]) -> Result<String> {
    let mut selected = replacements
        .iter()
        .filter(|replacement| {
            replacement.span.start >= range.start && replacement.span.end <= range.end
        })
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_by_key(|replacement| (replacement.span.start, replacement.span.end));
    for pair in selected.windows(2) {
        if pair[0].span.end > pair[1].span.start {
            bail!(
                "producer spike encountered overlapping AST rewrites at {}..{} and {}..{}",
                pair[0].span.start,
                pair[0].span.end,
                pair[1].span.start,
                pair[1].span.end
            );
        }
    }
    let mut output = String::new();
    let mut cursor = range.start as usize;
    for replacement in selected {
        output.push_str(&source[cursor..replacement.span.start as usize]);
        output.push_str(&materialize_replacement(source, &replacement));
        cursor = replacement.span.end as usize;
    }
    output.push_str(&source[cursor..range.end as usize]);
    Ok(output)
}

fn materialize_replacement(source: &str, replacement: &Replacement) -> String {
    let original = &source[replacement.span.start as usize..replacement.span.end as usize];
    let mut text = replacement.text.replace("__IBEX_ORIGINAL__", original);
    if text.contains("__IBEX_IMPORT_ARGUMENTS__") {
        let arguments = original
            .strip_prefix("import(")
            .and_then(|value| value.strip_suffix(')'))
            .unwrap_or(original);
        text = text.replace("__IBEX_IMPORT_ARGUMENTS__", arguments);
    }
    while let Some(start) = text.find("__IBEX_SPAN_") {
        let suffix = &text[start + "__IBEX_SPAN_".len()..];
        let Some(end) = suffix.find("__") else { break };
        let bounds = &suffix[..end];
        let Some((from, to)) = bounds.split_once('_') else {
            break;
        };
        let from = from.parse::<usize>().expect("encoded span start");
        let to = to.parse::<usize>().expect("encoded span end");
        text.replace_range(
            start..start + "__IBEX_SPAN_".len() + end + 2,
            &source[from..to],
        );
    }
    while let Some(start) = text.find("__IBEX_BODY_SPAN_") {
        let suffix = &text[start + "__IBEX_BODY_SPAN_".len()..];
        let Some(end) = suffix.find("__") else { break };
        let bounds = &suffix[..end];
        let Some((from, to)) = bounds.split_once('_') else {
            break;
        };
        let from = from.parse::<usize>().expect("encoded body span start");
        let to = to.parse::<usize>().expect("encoded body span end");
        text.replace_range(
            start..start + "__IBEX_BODY_SPAN_".len() + end + 2,
            &source[from..to],
        );
    }
    text
}

fn append_mapped(
    output: &mut String,
    origins: &mut Vec<Option<u32>>,
    text: &str,
    first_source_line: u32,
) {
    let start_line = output.lines().count() as u32;
    output.push_str(text);
    let line_count = text.lines().count().max(1);
    while origins.len() < start_line as usize + line_count {
        let offset = origins.len().saturating_sub(start_line as usize) as u32;
        origins.push(Some(first_source_line + offset));
    }
}

fn compose_factory_source_map(
    source_name: &str,
    source: &str,
    intermediate_map: &SourceMap,
    body_line_offset: u32,
    line_origins: &[Option<u32>],
    factory_source: &str,
) -> Result<Value> {
    let stage_map = intermediate_map.clone();
    let lookup = stage_map.generate_lookup_table();
    let mut builder = SourceMapBuilder::default();
    builder.set_file(&format!("{source_name}.factory.js"));
    let source_id = builder.set_source_and_content(source_name, source);
    for (body_line, intermediate_line) in line_origins.iter().enumerate() {
        let Some(intermediate_line) = intermediate_line else {
            continue;
        };
        let original_line = stage_map
            .lookup_token(&lookup, *intermediate_line, 0)
            .map(|token| token.get_src_line())
            .unwrap_or(*intermediate_line);
        builder.add_token(
            body_line_offset + body_line as u32,
            0,
            original_line,
            0,
            Some(source_id),
            None,
        );
    }
    let mut value: Value = serde_json::from_str(&builder.into_sourcemap().to_json_string())?;
    value["x_ibex_composed"] = Value::Bool(true);
    value["x_ibex_factory_lines"] = Value::from(factory_source.lines().count() as u64);
    Ok(value)
}

fn fresh_abi_names(program: &Program<'_>) -> (String, String) {
    #[derive(Default)]
    struct Names(BTreeSet<String>);
    impl<'a> Visit<'a> for Names {
        fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
            self.0.insert(identifier.name.to_string());
            walk::walk_identifier_reference(self, identifier);
        }
        fn visit_binding_identifier(&mut self, identifier: &oxc_ast::ast::BindingIdentifier<'a>) {
            self.0.insert(identifier.name.to_string());
            walk::walk_binding_identifier(self, identifier);
        }
    }
    let mut names = Names::default();
    names.visit_program(program);
    let mut suffix = 0;
    loop {
        let export = format!("__ibex_export${suffix}");
        let context = format!("__ibex_context${suffix}");
        if !names.0.contains(&export) && !names.0.contains(&context) {
            return (export, context);
        }
        suffix += 1;
    }
}

fn has_top_level_await(program: &Program<'_>) -> bool {
    #[derive(Default)]
    struct Finder {
        function_depth: usize,
        found: bool,
    }
    impl<'a> Visit<'a> for Finder {
        fn visit_await_expression(&mut self, expression: &oxc_ast::ast::AwaitExpression<'a>) {
            if self.function_depth == 0 {
                self.found = true;
            } else {
                walk::walk_await_expression(self, expression);
            }
        }
        fn visit_function_body(&mut self, body: &FunctionBody<'a>) {
            self.function_depth += 1;
            walk::walk_function_body(self, body);
            self.function_depth -= 1;
        }
    }
    let mut finder = Finder::default();
    finder.visit_program(program);
    finder.found
}

fn line_of(source: &str, offset: u32) -> u32 {
    source.as_bytes()[..offset as usize]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u32
}

fn js_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization")
}

pub fn default_spike_manifest(repo_root: &Path) -> PathBuf {
    repo_root.join("tests/fixtures/module-runner-spike/manifest.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_loader::artifact::ModulePayloadV1;
    use capsec_semantics::model::{PathComponent, Principal};

    #[test]
    fn fixture_producer_is_deterministic_and_exercises_oxc() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bundle = generate_spike_bundle(&default_spike_manifest(root)).expect("generate");
        assert!(!bundle.fixtures.is_empty());
        let rendered = serde_json::to_string_pretty(&bundle).expect("serialize") + "\n";
        let checked_in = std::fs::read_to_string(
            root.join("tests/fixtures/module-runner-spike/canonical-artifacts.json"),
        )
        .expect("checked-in artifacts");
        assert_eq!(
            rendered, checked_in,
            "regenerate the canonical spike artifacts"
        );
        assert!(bundle.fixtures.iter().all(|fixture| {
            fixture.modules.iter().all(|module| {
                module.source_map["x_ibex_composed"] == Value::Bool(true)
                    && !module.factory_source.is_empty()
            })
        }));
    }

    #[test]
    fn test262_artifacts_are_deterministic_and_keep_the_frozen_threshold() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let subset = root.join("tests/fixtures/module-runner-spike/test262-subset.json");
        let bundle = generate_test262_artifact_bundle(&subset).expect("generate test262 artifacts");
        assert_eq!(bundle.cases.len(), 20);
        assert_eq!(bundle.minimum_pass_rate["numerator"], Value::from(18));
        assert_eq!(bundle.expected_divergences.len(), 0);
        let rendered = serde_json::to_string_pretty(&bundle).expect("serialize") + "\n";
        let checked_in = std::fs::read_to_string(
            root.join("tests/fixtures/module-runner-spike/test262-artifacts.json"),
        )
        .expect("checked-in test262 artifacts");
        assert_eq!(
            rendered, checked_in,
            "regenerate the test262 spike artifacts"
        );
    }

    #[test]
    fn producer_forces_module_goal_for_plain_js_top_level_await_regexp() {
        let artifact = produce_spike_artifact(
            "await-regexp",
            "entry.js",
            Path::new("test262/top-level-await/await-expr-regexp.js"),
            "var g = 42;\nawait /x.y/g;\n",
        )
        .expect("produce Module-goal artifact");

        assert!(artifact.has_top_level_await);
        assert!(artifact.factory_source.contains("await /x.y/g"));
    }

    #[test]
    fn production_adapter_emits_canonical_authenticated_artifact() {
        let source_id = SourceId::file(
            Principal::Root {
                identity: NonEmptyString::new("project-fixture").unwrap(),
            },
            vec![PathComponent::utf8("entry.mjs").unwrap()],
        )
        .unwrap();
        let producer_digest = source_integrity(b"producer-binary").unwrap();
        let artifact = produce_module_artifact_v1(
            source_id.clone(),
            "entry.mjs",
            Path::new("entry.mjs"),
            "import { value } from 'dep'; export { value };",
            producer_digest.clone(),
            "hermes-bytecode-96",
        )
        .unwrap();
        let bytes = artifact.encode_canonical().unwrap();
        let decoded = ModuleArtifactV1::decode_canonical(&bytes).unwrap();
        decoded
            .verify_for_admission(
                &super::super::artifact::ArtifactAdmissionV1::TrustedInProcess {
                    expected_source_id: source_id,
                    expected_source_integrity: source_integrity(
                        b"import { value } from 'dep'; export { value };",
                    )
                    .unwrap(),
                    expected_producer_id: NonEmptyString::new("ibex-runtime-oxc").unwrap(),
                    producer_binary_digest: producer_digest,
                    transform_fingerprint_digest: module_artifact_transform_fingerprint_v1(
                        "hermes-bytecode-96",
                    )
                    .unwrap()
                    .digest()
                    .unwrap(),
                },
            )
            .unwrap();
        assert_eq!(decoded.semantics.static_edges.len(), 1);
        assert_eq!(decoded.semantics.export_descriptors.len(), 1);
    }

    #[test]
    fn production_adapter_preserves_json_import_attributes() {
        let source_id = SourceId::synthetic("fixture", "json-import").unwrap();
        let artifact = produce_module_artifact_v1(
            source_id,
            "entry.mjs",
            Path::new("entry.mjs"),
            "import data from './data.json' with { type: 'json' }; export default data;",
            source_integrity(b"producer-binary").unwrap(),
            "hermes-bytecode-96",
        )
        .unwrap();
        let StaticEdgeV1::Default { attributes, .. } = &artifact.semantics.static_edges[0] else {
            panic!("expected default JSON edge")
        };
        assert!(attributes.asserts_json());
    }

    #[test]
    fn production_adapter_authenticates_literal_and_computed_dynamic_import_sites() {
        let source_id = SourceId::synthetic("fixture", "dynamic-imports").unwrap();
        let artifact = produce_module_artifact_v1(
            source_id,
            "entry.mjs",
            Path::new("entry.mjs"),
            "const name = './computed.mjs'; export const results = [import('./literal.mjs'), import(name)];",
            source_integrity(b"producer-binary").unwrap(),
            "hermes-bytecode-96",
        )
        .unwrap();
        assert_eq!(
            artifact.semantics.dynamic_edges,
            [
                DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./literal.mjs").unwrap(),
                    attributes: ImportAttributes::default(),
                },
                DynamicEdgeV1::Computed { site: 1 },
            ]
        );
        let super::super::artifact::ModulePayloadV1::Inline {
            factory_source: factory,
            ..
        } = &artifact.payload
        else {
            panic!("production spike producer emits inline artifacts")
        };
        assert!(
            factory.contains(".dynamicImport('./literal.mjs')")
                || factory.contains(".dynamicImport(\"./literal.mjs\")")
        );
        assert!(factory.contains(".dynamicImport(name)"));
    }

    #[test]
    fn commonjs_adapter_uses_script_goal_typed_edges_and_pinned_detection() {
        let source_id = SourceId::synthetic("fixture", "commonjs-entry").unwrap();
        let source = r#"
            const typed: number = 41;
            exports.answer = typed + 1;
            function shadowed(require: (name: string) => unknown) {
                return require('./ignored.cjs');
            }
            module.exports = require('./reexport.cjs');
            import('./async.mjs');
        "#;
        let artifact = produce_commonjs_artifact_v1(
            source_id,
            "entry.cts",
            Path::new("entry.cts"),
            source,
            source_integrity(b"producer-binary").unwrap(),
            "hermes-bytecode-96",
        )
        .unwrap();

        assert_eq!(artifact.semantics.source_goal, SourceGoalV1::CommonJs);
        assert_eq!(artifact.semantics.dialect, Some(SourceDialectV1::Ts));
        assert_eq!(
            artifact.semantics.static_edges,
            [StaticEdgeV1::CommonJsRequire {
                specifier: NonEmptyString::new("./reexport.cjs").unwrap(),
            }]
        );
        assert_eq!(
            artifact.semantics.dynamic_edges,
            [DynamicEdgeV1::Literal {
                specifier: NonEmptyString::new("./async.mjs").unwrap(),
                attributes: ImportAttributes::default(),
            }]
        );
        let detected = artifact.semantics.commonjs_exports.as_ref().unwrap();
        assert_eq!(detected.detector_version.as_str(), CJS_MODULE_LEXER_VERSION);
        assert_eq!(detected.names, [NonEmptyString::new("answer").unwrap()]);
        assert_eq!(
            detected.reexports,
            [NonEmptyString::new("./reexport.cjs").unwrap()]
        );
        let ModulePayloadV1::Inline { factory_source, .. } = &artifact.payload else {
            unreachable!()
        };
        assert!(factory_source.starts_with(
            "function (require, module, exports, __filename, __dirname, dynamicImport)"
        ));
        assert!(!factory_source.contains("import('./async.mjs')"));
        assert!(
            factory_source.contains("dynamicImport('./async.mjs')")
                || factory_source.contains("dynamicImport(\"./async.mjs\")")
        );
        assert!(!factory_source.contains(": number"));
    }

    #[test]
    fn commonjs_adapter_rejects_computed_require_without_candidate_table() {
        let error = produce_commonjs_artifact_v1(
            SourceId::synthetic("fixture", "computed-require").unwrap(),
            "entry.cjs",
            Path::new("entry.cjs"),
            "const name = './dep.cjs'; module.exports = require(name);",
            source_integrity(b"producer-binary").unwrap(),
            "hermes-bytecode-96",
        )
        .unwrap_err();
        assert!(error.to_string().contains("computed CommonJS require"));
    }

    #[test]
    fn json_artifact_is_strict_and_exports_canonical_default() {
        let artifact = produce_json_artifact_v1(
            SourceId::synthetic("fixture", "data-json").unwrap(),
            "{\"z\":1,\"a\":[true,null]}",
            source_integrity(b"producer-binary").unwrap(),
            "hermes-bytecode-96",
        )
        .unwrap();
        assert_eq!(artifact.semantics.source_goal, SourceGoalV1::Json);
        assert_eq!(artifact.semantics.dialect, None);
        let ModulePayloadV1::Inline { factory_source, .. } = artifact.payload else {
            unreachable!()
        };
        assert!(factory_source.contains("$export('default', {\"a\":[true,null],\"z\":1})"));

        let duplicate = produce_json_artifact_v1(
            SourceId::synthetic("fixture", "duplicate-json").unwrap(),
            "{\"value\":1,\"value\":2}",
            source_integrity(b"producer-binary").unwrap(),
            "hermes-bytecode-96",
        )
        .unwrap_err();
        assert!(duplicate.to_string().contains("strict JSON"));
    }
}
