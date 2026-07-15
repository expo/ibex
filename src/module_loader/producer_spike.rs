//! Fixture-only Oxc producer used by the LLP 0026 adoption-gate spike.
//!
//! This is deliberately not wired into the evaluator or artifact cache. The
//! spike has no interim path-based `SourceId`; it proves the uncertain
//! transform/factory seam against enumerated fixtures and real Hermes only.
//! @ref LLP 0026#adoption-gate — acceptance requires executed canonical
//! artifacts before implementation proceeds beyond spike scope.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentTarget, Declaration, ExportDefaultDeclarationKind,
    ForOfStatement, FunctionBody, IdentifierReference, ImportDeclarationSpecifier,
    ImportExpression, ImportOrExportKind, MetaProperty, Program, SimpleAssignmentTarget, Statement,
    UpdateExpression, VariableDeclarationKind,
};
use oxc_ast_visit::{walk, Visit};
use oxc_codegen::{Codegen, CodegenOptions};
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_sourcemap::{SourceMap, SourceMapBuilder};
use oxc_span::{GetSpan, SourceType, Span};
use oxc_transformer::{JsxOptions, JsxRuntime, Module, TransformOptions, Transformer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SPIKE_TRANSFORM_FINGERPRINT: &str =
    "ibex-module-runner-spike/1+oxc-0.121.0+hermes-abi-draft-1";

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
    pub export_descriptors: Vec<SpikeExportDescriptor>,
    pub has_top_level_await: bool,
    pub factory_source: String,
    pub source_map: Value,
    pub hermes_compat_passes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpikeStaticEdge {
    pub specifier: String,
    pub kind: String,
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
    function_depth: usize,
    hermes_compat_passes: BTreeSet<String>,
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
            "Oxc could not parse transformed {}: {:?}",
            source_name,
            parsed.errors
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
                let Some(specifiers) = &declaration.specifiers else {
                    static_edges.push(SpikeStaticEdge {
                        specifier,
                        kind: "sideEffect".to_string(),
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
                                imported: Some("*".to_string()),
                                local: Some(local),
                            });
                        }
                        ImportDeclarationSpecifier::ImportSpecifier(_) => {}
                    }
                }
            }
            Statement::ExportNamedDeclaration(declaration) => {
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
        export_descriptors,
        has_top_level_await,
        factory_source,
        source_map,
        hermes_compat_passes: visitor.hermes_compat_passes.into_iter().collect(),
    })
}

fn transform_with_oxc(path: &Path, source: &str) -> Result<IntermediateSource> {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path).unwrap_or_else(|_| SourceType::mjs());
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
}
