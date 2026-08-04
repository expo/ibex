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
    JSXElement, JSXFragment, MetaProperty, ObjectProperty, ObjectPropertyKind, Program,
    PropertyKind, SimpleAssignmentTarget, Statement, TSEnumDeclaration, TSModuleDeclaration,
    UpdateExpression, VariableDeclarationKind, WithClause,
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
use super::compatibility::{
    HermesSyntaxQuarantineReason, LegacyModuleRunnerRequirement, Tier3ForOfQuarantineReason,
};
use super::computed_candidates::OriginalSourceSpanV1;
use super::identity::{ImportAttributes, SourceId};
use super::transform_config_generated as transform_config;
use capsec_semantics::model::{Digest as CapsecDigest, NonEmptyString, StableId};

pub const SPIKE_TRANSFORM_FINGERPRINT: &str = transform_config::SPIKE_TRANSFORM_FINGERPRINT;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct UnsupportedModuleRunnerShape(LegacyModuleRunnerRequirement);

fn unsupported_module_runner_shape(requirement: LegacyModuleRunnerRequirement) -> anyhow::Error {
    UnsupportedModuleRunnerShape(requirement).into()
}

pub fn unsupported_module_runner_reason(
    error: &anyhow::Error,
) -> Option<&LegacyModuleRunnerRequirement> {
    error
        .downcast_ref::<UnsupportedModuleRunnerShape>()
        .map(|unsupported| &unsupported.0)
}

pub fn module_artifact_transform_cache_tag_v1() -> &'static str {
    transform_config::TRANSFORM_CACHE_TAG
}

fn configured_digest(value: &'static str) -> Result<CapsecDigest> {
    CapsecDigest::new(value).map_err(anyhow::Error::msg)
}

/// The producer identity comes exclusively from the generated projection of
/// the authored transform configuration. Evaluator and HBC compiler identity
/// belong to carrier admission and are deliberately not accepted as inputs.
/// @ref LLP 0028#1-toolchain-and-pin-rotation--atomic-with-identity-rotation
pub fn module_artifact_transform_fingerprint_v1() -> Result<TransformFingerprintV1> {
    Ok(TransformFingerprintV1 {
        producer: NonEmptyString::new(transform_config::PRODUCER_ID).map_err(anyhow::Error::msg)?,
        parser_version: NonEmptyString::new(transform_config::PARSER_VERSION_IDENTITY)
            .map_err(anyhow::Error::msg)?,
        transform_version: NonEmptyString::new(transform_config::TRANSFORM_VERSION_IDENTITY)
            .map_err(anyhow::Error::msg)?,
        hermes_target: NonEmptyString::new(transform_config::HERMES_TARGET)
            .map_err(anyhow::Error::msg)?,
        typescript_jsx_options_digest: configured_digest(transform_config::MODULE_OPTIONS_DIGEST)?,
        module_runner_abi: NonEmptyString::new(transform_config::MODULE_RUNNER_ABI)
            .map_err(anyhow::Error::msg)?,
        hermes_compat_version: NonEmptyString::new(transform_config::HERMES_COMPAT_VERSION)
            .map_err(anyhow::Error::msg)?,
        commonjs_detector: NonEmptyString::new(transform_config::COMMONJS_DETECTOR)
            .map_err(anyhow::Error::msg)?,
        commonjs_detector_version: NonEmptyString::new(transform_config::COMMONJS_DETECTOR_VERSION)
            .map_err(anyhow::Error::msg)?,
        output_options_digest: configured_digest(transform_config::MODULE_OUTPUT_OPTIONS_DIGEST)?,
    })
}

fn commonjs_artifact_transform_fingerprint_v1() -> Result<TransformFingerprintV1> {
    let mut fingerprint = module_artifact_transform_fingerprint_v1()?;
    fingerprint.typescript_jsx_options_digest =
        configured_digest(transform_config::COMMONJS_OPTIONS_DIGEST)?;
    fingerprint.output_options_digest =
        configured_digest(transform_config::COMMONJS_OUTPUT_OPTIONS_DIGEST)?;
    Ok(fingerprint)
}

fn json_artifact_transform_fingerprint_v1() -> Result<TransformFingerprintV1> {
    let mut fingerprint = module_artifact_transform_fingerprint_v1()?;
    fingerprint.typescript_jsx_options_digest =
        configured_digest(transform_config::JSON_OPTIONS_DIGEST)?;
    fingerprint.output_options_digest =
        configured_digest(transform_config::JSON_OUTPUT_OPTIONS_DIGEST)?;
    Ok(fingerprint)
}

pub fn configured_transform_fingerprint_for_goal_v1(
    goal: SourceGoalV1,
) -> Result<TransformFingerprintV1> {
    match goal {
        SourceGoalV1::Module => module_artifact_transform_fingerprint_v1(),
        SourceGoalV1::CommonJs | SourceGoalV1::Builtin => {
            commonjs_artifact_transform_fingerprint_v1()
        }
        SourceGoalV1::Json => json_artifact_transform_fingerprint_v1(),
    }
}

pub fn verify_current_transform_fingerprint_v1(semantics: &ModuleSemanticsV1) -> Result<()> {
    let expected = configured_transform_fingerprint_for_goal_v1(semantics.source_goal)?.digest()?;
    if semantics.transform_fingerprint.digest()? != expected {
        bail!("artifact transform fingerprint predates the active configuration");
    }
    Ok(())
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
    #[serde(skip)]
    pub original_source_offset: u32,
    #[serde(skip)]
    pub original_source_end: u32,
    pub has_options: bool,
    #[serde(skip)]
    pub label: Option<String>,
    #[serde(skip)]
    pub attributes: BTreeMap<String, String>,
    #[serde(skip)]
    pub runtime_options_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicImportSiteV1 {
    pub site: u32,
    pub label: Option<StableId>,
    pub original_source_span: OriginalSourceSpanV1,
    pub attributes: ImportAttributes,
    pub runtime_options_supported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GuardedUnsupportedShapeV1 {
    ComputedDynamicImportWithoutCandidateTable,
    ComputedCommonJsRequire,
    UnsupportedDynamicImportOptions,
}

impl GuardedUnsupportedShapeV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ComputedDynamicImportWithoutCandidateTable => {
                "computed-dynamic-import-without-candidate-table"
            }
            Self::ComputedCommonJsRequire => "computed-commonjs-require",
            Self::UnsupportedDynamicImportOptions => "unsupported-dynamic-import-options",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedUnsupportedSiteV1 {
    pub shape: GuardedUnsupportedShapeV1,
    pub original_source_span: OriginalSourceSpanV1,
}

pub struct ProducedModuleArtifactV1 {
    pub artifact: ModuleArtifactV1,
    pub dynamic_import_sites: Vec<DynamicImportSiteV1>,
    pub guarded_unsupported_sites: Vec<GuardedUnsupportedSiteV1>,
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
    map: SourceMap<'static>,
    authored_dynamic_imports: Vec<AuthoredDynamicImportSite>,
    authored_computed_requires: Vec<OriginalSourceSpanV1>,
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
    dynamic_option_error: Option<String>,
    function_depth: usize,
    for_of_rewrite_counter: usize,
    hermes_compat_passes: BTreeSet<String>,
    tier3_for_of_quarantine: Option<(u32, Tier3ForOfQuarantineReason)>,
}

#[derive(Default)]
struct HermesSyntaxVisitor {
    quarantine: Option<(u32, HermesSyntaxQuarantineReason)>,
}

impl<'a> Visit<'a> for HermesSyntaxVisitor {
    fn visit_function(
        &mut self,
        function: &oxc_ast::ast::Function<'a>,
        flags: oxc_semantic::ScopeFlags,
    ) {
        if function.r#async && function.generator {
            self.quarantine.get_or_insert((
                function.span.start,
                HermesSyntaxQuarantineReason::AsyncGenerator,
            ));
        }
        walk::walk_function(self, function, flags);
    }

    fn visit_variable_declaration(&mut self, declaration: &oxc_ast::ast::VariableDeclaration<'a>) {
        let reason = match declaration.kind {
            VariableDeclarationKind::Using => Some(HermesSyntaxQuarantineReason::UsingDeclaration),
            VariableDeclarationKind::AwaitUsing => {
                Some(HermesSyntaxQuarantineReason::AwaitUsingDeclaration)
            }
            _ => None,
        };
        if let Some(reason) = reason {
            self.quarantine
                .get_or_insert((declaration.span.start, reason));
        }
        walk::walk_variable_declaration(self, declaration);
    }

    fn visit_decorator(&mut self, decorator: &oxc_ast::ast::Decorator<'a>) {
        self.quarantine.get_or_insert((
            decorator.span.start,
            HermesSyntaxQuarantineReason::Decorator,
        ));
        walk::walk_decorator(self, decorator);
    }
}

// @ref LLP 0019#tier-3-the-rustoxc-module-artifact-producer — Tier 3 mirrors
// the canonical rewrite/leave-raw decision. This visitor identifies the
// canonical leave-raw hazards; only separately unsupported for-await syntax
// becomes a typed producer quarantine.
struct ForOfHazardVisitor {
    quarantine: Option<Tier3ForOfQuarantineReason>,
}

impl ForOfHazardVisitor {
    fn quarantine(&mut self, reason: Tier3ForOfQuarantineReason) {
        self.quarantine.get_or_insert(reason);
    }
}

impl<'a> Visit<'a> for ForOfHazardVisitor {
    fn visit_break_statement(&mut self, _statement: &oxc_ast::ast::BreakStatement<'a>) {
        self.quarantine(Tier3ForOfQuarantineReason::BreakStatement);
    }

    fn visit_continue_statement(&mut self, _statement: &oxc_ast::ast::ContinueStatement<'a>) {
        self.quarantine(Tier3ForOfQuarantineReason::ContinueStatement);
    }

    fn visit_return_statement(&mut self, _statement: &oxc_ast::ast::ReturnStatement<'a>) {
        self.quarantine(Tier3ForOfQuarantineReason::ReturnStatement);
    }

    fn visit_await_expression(&mut self, _expression: &oxc_ast::ast::AwaitExpression<'a>) {
        self.quarantine(Tier3ForOfQuarantineReason::AwaitExpression);
    }

    fn visit_yield_expression(&mut self, _expression: &oxc_ast::ast::YieldExpression<'a>) {
        self.quarantine(Tier3ForOfQuarantineReason::YieldExpression);
    }

    fn visit_variable_declaration(&mut self, declaration: &oxc_ast::ast::VariableDeclaration<'a>) {
        if declaration.kind == VariableDeclarationKind::Var {
            self.quarantine(Tier3ForOfQuarantineReason::VarDeclaration);
        }
        walk::walk_variable_declaration(self, declaration);
    }

    fn visit_function(
        &mut self,
        function: &oxc_ast::ast::Function<'a>,
        _flags: oxc_semantic::ScopeFlags,
    ) {
        if function.r#type == oxc_ast::ast::FunctionType::FunctionDeclaration {
            self.quarantine(Tier3ForOfQuarantineReason::FunctionDeclaration);
        }
        // Function and class boundaries own control flow and declarations.
    }

    fn visit_arrow_function_expression(
        &mut self,
        _expression: &oxc_ast::ast::ArrowFunctionExpression<'a>,
    ) {
    }

    fn visit_class(&mut self, _class: &oxc_ast::ast::Class<'a>) {}

    fn visit_for_of_statement(&mut self, statement: &ForOfStatement<'a>) {
        if statement.r#await {
            self.quarantine(Tier3ForOfQuarantineReason::AwaitLoop);
        }
        walk::walk_for_of_statement(self, statement);
    }
}

fn body_redeclares_for_of_bindings(body: &Statement<'_>, bound_names: &BTreeSet<String>) -> bool {
    let Statement::BlockStatement(body) = body else {
        return false;
    };
    body.body.iter().any(|statement| match statement {
        Statement::VariableDeclaration(declaration) => {
            declaration.declarations.iter().any(|declarator| {
                declarator
                    .id
                    .get_binding_identifiers()
                    .into_iter()
                    .any(|identifier| bound_names.contains(identifier.name.as_str()))
            })
        }
        Statement::FunctionDeclaration(function) => function
            .id
            .as_ref()
            .is_some_and(|identifier| bound_names.contains(identifier.name.as_str())),
        Statement::ClassDeclaration(class) => class
            .id
            .as_ref()
            .is_some_and(|identifier| bound_names.contains(identifier.name.as_str())),
        _ => false,
    })
}

#[derive(Debug)]
struct CommonJsDependencyVisitor<'s> {
    scoping: &'s Scoping,
    dynamic_import_binding: String,
    computed_require_binding: String,
    require_specifiers: BTreeSet<String>,
    dynamic_edges: Vec<SpikeDynamicEdge>,
    replacements: Vec<Replacement>,
    computed_require_calls: Vec<Span>,
    dynamic_option_error: Option<String>,
}

#[derive(Debug)]
struct AuthoredComputedRequireVisitor<'s> {
    scoping: &'s Scoping,
    sites: Vec<OriginalSourceSpanV1>,
}

impl<'a> Visit<'a> for AuthoredComputedRequireVisitor<'_> {
    fn visit_call_expression(&mut self, expression: &CallExpression<'a>) {
        if expression
            .callee
            .is_global_reference_name("require".into(), self.scoping)
            && !matches!(
                expression.arguments.as_slice(),
                [Argument::StringLiteral(_)]
            )
        {
            self.sites.push(OriginalSourceSpanV1 {
                start: expression.span.start,
                end: expression.span.end,
            });
        }
        walk::walk_call_expression(self, expression);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthoredDynamicImportSite {
    computed: bool,
    original_source_offset: u32,
    original_source_end: u32,
    label: Option<String>,
    attributes: BTreeMap<String, String>,
    runtime_options_supported: bool,
}

#[derive(Debug, Default)]
struct AuthoredDynamicImportVisitor {
    sites: Vec<AuthoredDynamicImportSite>,
    source_option_error: Option<String>,
}

#[derive(Debug, Default)]
struct DynamicImportOptionsAnalysis {
    label: Option<String>,
    runtime: BTreeMap<String, String>,
    runtime_supported: bool,
    source_error: Option<String>,
}

/// Classify authored options without turning runtime-only defects into build
/// failures. The producer is the one parsing authority, so this same result
/// supplies both the original-source correspondence table and the guarded
/// factory ABI. Only statically visible misuse of LLP 0014's build-time-only
/// policy vocabulary is an unconditional source error.
/// @ref LLP 0028#2-disposition-of-the-legacy-window-interop-shapes
fn dynamic_import_options(options: Option<&Expression<'_>>) -> DynamicImportOptionsAnalysis {
    let Some(options) = options else {
        return DynamicImportOptionsAnalysis {
            runtime_supported: true,
            ..DynamicImportOptionsAnalysis::default()
        };
    };
    let Expression::ObjectExpression(options) = options else {
        return DynamicImportOptionsAnalysis::default();
    };
    if options.properties.len() != 1 {
        return DynamicImportOptionsAnalysis::default();
    }
    let ObjectPropertyKind::ObjectProperty(with_property) = &options.properties[0] else {
        return DynamicImportOptionsAnalysis::default();
    };
    if with_property.kind != PropertyKind::Init
        || with_property.method
        || with_property.computed
        || with_property.key.static_name().as_deref() != Some("with")
    {
        return DynamicImportOptionsAnalysis::default();
    }
    let Expression::ObjectExpression(attributes) = &with_property.value else {
        return DynamicImportOptionsAnalysis::default();
    };
    let mut analysis = DynamicImportOptionsAnalysis {
        runtime_supported: true,
        ..DynamicImportOptionsAnalysis::default()
    };
    for property in &attributes.properties {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            analysis.runtime_supported = false;
            continue;
        };
        let key = property.key.static_name();
        if key.as_deref() == Some("authorities") {
            analysis.source_error.get_or_insert_with(|| {
                "reserved build-time import attribute authorities is invalid at runtime".to_string()
            });
            continue;
        }
        if property.kind != PropertyKind::Init || property.method || property.computed {
            analysis.runtime_supported = false;
            continue;
        }
        let (Some(key), Expression::StringLiteral(value)) = (key, &property.value) else {
            analysis.runtime_supported = false;
            continue;
        };
        match key.as_ref() {
            "ibex:site" => {
                if analysis.label.replace(value.value.to_string()).is_some() {
                    analysis.runtime_supported = false;
                }
            }
            "type" if value.value == "json" => {
                if analysis
                    .runtime
                    .insert("type".into(), "json".into())
                    .is_some()
                {
                    analysis.runtime_supported = false;
                }
            }
            _ => analysis.runtime_supported = false,
        }
    }
    analysis
}

impl<'a> Visit<'a> for AuthoredDynamicImportVisitor {
    fn visit_import_expression(&mut self, expression: &ImportExpression<'a>) {
        let analysis = dynamic_import_options(expression.options.as_ref());
        if let Some(error) = analysis.source_error {
            self.source_option_error.get_or_insert(error);
        }
        self.sites.push(AuthoredDynamicImportSite {
            computed: !matches!(expression.source, Expression::StringLiteral(_)),
            original_source_offset: expression.span.start,
            original_source_end: expression.span.end,
            label: analysis.label,
            attributes: analysis.runtime,
            runtime_options_supported: analysis.runtime_supported,
        });
        walk::walk_import_expression(self, expression);
    }
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
                    self.computed_require_calls.push(expression.span);
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
        let analysis = dynamic_import_options(expression.options.as_ref());
        if let Some(error) = analysis.source_error {
            self.dynamic_option_error.get_or_insert(error);
        }
        self.dynamic_edges.push(SpikeDynamicEdge {
            kind: if specifier.is_some() {
                "literal".into()
            } else {
                "computed".into()
            },
            specifier,
            site: expression.span.start,
            original_source_offset: expression.span.start,
            original_source_end: expression.span.end,
            has_options: expression.options.is_some(),
            label: analysis.label,
            attributes: analysis.runtime,
            runtime_options_supported: analysis.runtime_supported,
        });
        self.replacements.push(Replacement {
            span: expression.span,
            text: format!(
                "{}(__IBEX_DYNAMIC_KIND_{1}__, __IBEX_DYNAMIC_START_{1}__, __IBEX_DYNAMIC_END_{1}__, __IBEX_DYNAMIC_OPTIONS_{1}__, __IBEX_IMPORT_ARGUMENTS__)",
                self.dynamic_import_binding, expression.span.start
            ),
        });
        walk::walk_import_expression(self, expression);
    }
}

impl<'a> Visit<'a> for NestedRewriteVisitor {
    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        // Replacing only the value identifier of `{ imported }` would emit
        // invalid `{ context.importValue(...) }` syntax. Expand the complete
        // shorthand property before the ordinary identifier visitor runs.
        if property.shorthand {
            if let Expression::Identifier(identifier) = &property.value {
                if let Some((specifier, imported)) = self.imported.get(identifier.name.as_str()) {
                    self.replacements.push(Replacement {
                        span: property.span,
                        text: format!(
                            "{}: {}.importValue({}, {})",
                            identifier.name,
                            self.context,
                            js_string(specifier),
                            js_string(imported)
                        ),
                    });
                    return;
                }
            }
        }
        walk::walk_object_property(self, property);
    }

    fn visit_big_int_literal(&mut self, literal: &oxc_ast::ast::BigIntLiteral<'a>) {
        let raw = literal
            .raw
            .as_ref()
            .map_or_else(|| literal.value.to_string(), ToString::to_string);
        let value = raw
            .strip_suffix('n')
            .unwrap_or(raw.as_str())
            .replace('_', "");
        self.replacements.push(Replacement {
            span: literal.span,
            text: format!("BigInt({})", js_string(&value)),
        });
        self.hermes_compat_passes
            .insert("llp0019-bigint-constructor-v1".to_string());
    }

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
        let analysis = dynamic_import_options(expression.options.as_ref());
        if let Some(error) = analysis.source_error {
            self.dynamic_option_error.get_or_insert(error);
        }
        self.dynamic_edges.push(SpikeDynamicEdge {
            kind: if specifier.is_some() {
                "literal".into()
            } else {
                "computed".into()
            },
            specifier,
            site: expression.span.start,
            original_source_offset: expression.span.start,
            original_source_end: expression.span.end,
            has_options: expression.options.is_some(),
            label: analysis.label,
            attributes: analysis.runtime,
            runtime_options_supported: analysis.runtime_supported,
        });
        self.replacements.push(Replacement {
            span: expression.span,
            text: format!(
                "{0}.dynamicImport(__IBEX_DYNAMIC_KIND_{1}__, __IBEX_DYNAMIC_START_{1}__, __IBEX_DYNAMIC_END_{1}__, __IBEX_DYNAMIC_OPTIONS_{1}__, __IBEX_IMPORT_ARGUMENTS__)",
                self.context, expression.span.start
            ),
        });
        walk::walk_import_expression(self, expression);
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
        if statement.r#await {
            self.tier3_for_of_quarantine
                .get_or_insert((statement.span.start, Tier3ForOfQuarantineReason::AwaitLoop));
            walk::walk_for_of_statement(self, statement);
            return;
        }

        let (left_source_span, declaration_kind, bound_names) = match &statement.left {
            oxc_ast::ast::ForStatementLeft::VariableDeclaration(declaration)
                if declaration.declarations.len() == 1 =>
            {
                let declarator = &declaration.declarations[0];
                (
                    declarator.id.span(),
                    Some(declaration.kind),
                    declarator
                        .id
                        .get_binding_identifiers()
                        .into_iter()
                        .map(|identifier| identifier.name.to_string())
                        .collect::<BTreeSet<_>>(),
                )
            }
            oxc_ast::ast::ForStatementLeft::VariableDeclaration(_) => {
                walk::walk_for_of_statement(self, statement);
                return;
            }
            _ => (statement.left.span(), None, BTreeSet::new()),
        };
        let needs_per_iteration_binding = matches!(
            declaration_kind,
            Some(VariableDeclarationKind::Const | VariableDeclarationKind::Let)
        );

        let mut hazards = ForOfHazardVisitor { quarantine: None };
        hazards.visit_statement(&statement.body);
        let must_leave_raw = hazards.quarantine.is_some()
            || (needs_per_iteration_binding
                && body_redeclares_for_of_bindings(&statement.body, &bound_names));
        if must_leave_raw {
            // The canonical LLP 0019 pass leaves these loops intact. Hermes'
            // native loop is safe for the quarantined concern, while rewriting
            // would change control flow or declaration scope.
            walk::walk_for_of_statement(self, statement);
            return;
        }

        let index = self.for_of_rewrite_counter;
        self.for_of_rewrite_counter += 1;
        let iterator = format!("__exactForOfIterator{index}");
        let step = format!("__exactForOfStep{index}");
        let value = format!("__exactForOfValue{index}");
        let body_fn = format!("__exactForOfBody{index}");
        let error = format!("__exactForOfError{index}");
        let return_fn = format!("__exactForOfReturn{index}");
        let ignore = format!("__exactForOfIgnore{index}");
        let right = statement.right.span();
        let body = statement.body.span();
        let body_inner = if matches!(&statement.body, Statement::BlockStatement(_)) {
            Span::new(body.start + 1, body.end - 1)
        } else {
            body
        };
        let right_marker = format!("__IBEX_REWRITE_SPAN_{}_{}__", right.start, right.end);
        let body_marker = format!(
            "__IBEX_REWRITE_SPAN_{}_{}__",
            body_inner.start, body_inner.end
        );
        let left_marker = format!(
            "__IBEX_SPAN_{}_{}__",
            left_source_span.start, left_source_span.end
        );
        let close_on_throw = format!(
            "catch ({error}) {{ const {return_fn} = {iterator}.return; if (typeof {return_fn} === 'function') {{ try {{ {return_fn}.call({iterator}); }} catch ({ignore}) {{}} }} throw {error}; }}"
        );
        let text = if needs_per_iteration_binding {
            let kind = match declaration_kind.expect("per-iteration declaration") {
                VariableDeclarationKind::Const => "const",
                VariableDeclarationKind::Let => "let",
                _ => unreachable!("guarded declaration kind"),
            };
            format!(
                "{{ const {iterator} = ({right_marker})[Symbol.iterator](); const {body_fn} = ({value}) => {{ {kind} {left_marker} = {value};\n{body_marker} }}; for (;;) {{ const {step} = {iterator}.next(); if ({step}.done) break; try {{ {body_fn}({step}.value); }} {close_on_throw} }} }}"
            )
        } else {
            let setup = if let Some(kind) = declaration_kind {
                let kind = match kind {
                    VariableDeclarationKind::Var => "var",
                    VariableDeclarationKind::Const => "const",
                    VariableDeclarationKind::Let => "let",
                    VariableDeclarationKind::Using => "using",
                    VariableDeclarationKind::AwaitUsing => "await using",
                };
                format!("{kind} {left_marker} = {step}.value;\n")
            } else if statement.left.as_assignment_target_pattern().is_some() {
                format!("({left_marker} = {step}.value);\n")
            } else {
                format!("{left_marker} = {step}.value;\n")
            };
            format!(
                "{{ const {iterator} = ({right_marker})[Symbol.iterator](); for (;;) {{ const {step} = {iterator}.next(); if ({step}.done) break; try {{ {setup}{body_marker} }} {close_on_throw} }} }}"
            )
        };
        self.replacements.push(Replacement {
            span: statement.span,
            text,
        });
        self.hermes_compat_passes
            .insert("llp0019-for-of-canonical-v2".to_string());
        // Child rewrites are collected and expanded through the recursive span
        // markers in the parent replacement.
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
    if !parsed.diagnostics.is_empty() {
        bail!(
            "Oxc could not parse transformed {}: {:?}\ntransformed source:\n{}",
            source_name,
            parsed.diagnostics,
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
    if let Some(error) = visitor.dynamic_option_error.take() {
        bail!("{error}");
    }
    if let Some((site, quarantine)) = visitor.tier3_for_of_quarantine {
        return Err(unsupported_module_runner_shape(
            LegacyModuleRunnerRequirement::tier3_for_of(site, quarantine),
        ));
    }
    finalize_dynamic_sites(
        &mut visitor.dynamic_edges,
        &mut visitor.replacements,
        &intermediate.authored_dynamic_imports,
    )?;
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
        dynamic_edges: visitor.dynamic_edges,
        export_descriptors,
        has_top_level_await,
        factory_source,
        source_map,
        hermes_compat_passes: visitor.hermes_compat_passes.into_iter().collect(),
    })
}

fn finalize_dynamic_sites(
    edges: &mut [SpikeDynamicEdge],
    replacements: &mut [Replacement],
    authored: &[AuthoredDynamicImportSite],
) -> Result<()> {
    edges.sort_by_key(|edge| edge.site);
    let mut authored = authored.to_vec();
    authored.sort_by_key(|site| site.original_source_offset);
    if edges.len() != authored.len() {
        bail!(
            "Oxc transform changed the dynamic-import site count (authored {}, transformed {})",
            authored.len(),
            edges.len()
        );
    }
    for (ordinal, (edge, authored)) in edges.iter_mut().zip(authored).enumerate() {
        let ordinal = u32::try_from(ordinal).context("too many dynamic-import sites")?;
        if (edge.specifier.is_none()) != authored.computed {
            bail!("Oxc transform changed dynamic-import computedness at site {ordinal}");
        }
        let transformed_offset = edge.site;
        edge.original_source_offset = authored.original_source_offset;
        edge.original_source_end = authored.original_source_end;
        edge.label = authored.label;
        edge.attributes = authored.attributes;
        edge.runtime_options_supported = authored.runtime_options_supported;
        let kind_marker = format!("__IBEX_DYNAMIC_KIND_{transformed_offset}__");
        let start_marker = format!("__IBEX_DYNAMIC_START_{transformed_offset}__");
        let end_marker = format!("__IBEX_DYNAMIC_END_{transformed_offset}__");
        let options_marker = format!("__IBEX_DYNAMIC_OPTIONS_{transformed_offset}__");
        for replacement in replacements.iter_mut() {
            if replacement.text.contains(&kind_marker) {
                let kind = if authored.computed {
                    ordinal.to_string()
                } else {
                    "-1".to_string()
                };
                replacement.text = replacement
                    .text
                    .replace(&kind_marker, &kind)
                    .replace(&start_marker, &authored.original_source_offset.to_string())
                    .replace(&end_marker, &authored.original_source_end.to_string())
                    .replace(
                        &options_marker,
                        if authored.runtime_options_supported {
                            "0"
                        } else {
                            "1"
                        },
                    );
            }
        }
        edge.site = ordinal;
    }
    if replacements
        .iter()
        .any(|replacement| replacement.text.contains("__IBEX_DYNAMIC_"))
    {
        bail!("dynamic-import site marker has no producer edge");
    }
    Ok(())
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
) -> Result<ModuleArtifactV1> {
    Ok(produce_module_artifact_with_sites_v1(
        source_id,
        source_name,
        source_path,
        source,
        producer_binary_digest,
    )?
    .artifact)
}

/// Produce the immutable ModuleArtifact plus the producer-owned correspondence
/// table used to join stable source labels to deployment candidate rows.
/// ModuleArtifact v1 remains unchanged; only the separately versioned sidecar
/// consumes this table. @ref LLP 0028#2-disposition-of-the-legacy-window-interop-shapes
pub fn produce_module_artifact_with_sites_v1(
    source_id: SourceId,
    source_name: &str,
    source_path: &Path,
    source: &str,
    producer_binary_digest: CapsecDigest,
) -> Result<ProducedModuleArtifactV1> {
    let spike = produce_spike_artifact("module-artifact-v1", source_name, source_path, source)?;
    let fingerprint = module_artifact_transform_fingerprint_v1()?;
    let static_edges = spike
        .static_edges
        .iter()
        .map(|edge| static_edge_v1(edge, &spike.export_descriptors))
        .collect::<Result<Vec<_>>>()?;
    let dynamic_edges = spike
        .dynamic_edges
        .iter()
        .map(|edge| {
            let attributes = ImportAttributes::new(edge.attributes.clone())?;
            if edge.specifier.is_some() && edge.label.is_some() {
                bail!("ibex:site is valid only on computed dynamic imports");
            }
            if !edge.runtime_options_supported {
                return Ok(DynamicEdgeV1::Computed { site: edge.site });
            }
            match edge.specifier.as_deref() {
                Some(specifier) => Ok(DynamicEdgeV1::Literal {
                    specifier: non_empty(specifier, "dynamic import specifier")?,
                    attributes,
                }),
                None => Ok(DynamicEdgeV1::Computed { site: edge.site }),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let mut labels = BTreeSet::new();
    let dynamic_import_sites = spike
        .dynamic_edges
        .iter()
        .filter(|edge| edge.specifier.is_none())
        .map(|edge| {
            let label = edge
                .label
                .as_ref()
                .map(|value| StableId::new(value.clone()).map_err(anyhow::Error::msg))
                .transpose()?;
            if label
                .as_ref()
                .is_some_and(|label| !labels.insert(label.as_str().to_owned()))
            {
                bail!("computed dynamic-import labels must be unique per requester");
            }
            Ok(DynamicImportSiteV1 {
                site: edge.site,
                label,
                original_source_span: OriginalSourceSpanV1 {
                    start: edge.original_source_offset,
                    end: edge.original_source_end,
                },
                attributes: ImportAttributes::new(edge.attributes.clone())?,
                runtime_options_supported: edge.runtime_options_supported,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let guarded_unsupported_sites = spike
        .dynamic_edges
        .iter()
        .filter(|edge| !edge.runtime_options_supported)
        .map(|edge| GuardedUnsupportedSiteV1 {
            shape: GuardedUnsupportedShapeV1::UnsupportedDynamicImportOptions,
            original_source_span: OriginalSourceSpanV1 {
                start: edge.original_source_offset,
                end: edge.original_source_end,
            },
        })
        .collect();
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
    let artifact = ModuleArtifactV1::new_inline(
        semantics,
        spike.factory_source,
        ProducerIdentityV1::InProcess {
            producer_id: NonEmptyString::new("ibex-runtime-oxc").map_err(anyhow::Error::msg)?,
            producer_binary_digest,
        },
    )?;
    Ok(ProducedModuleArtifactV1 {
        artifact,
        dynamic_import_sites,
        guarded_unsupported_sites,
    })
}

/// Produce a script-goal CommonJS factory without invoking an ambient JS
/// runtime. Literal require edges are authenticated separately from dynamic
/// imports, and computed require remains a guarded invocation-time refusal.
/// @ref LLP 0028#2-disposition-of-the-legacy-window-interop-shapes
pub fn produce_commonjs_artifact_v1(
    source_id: SourceId,
    source_name: &str,
    source_path: &Path,
    source: &str,
    producer_binary_digest: CapsecDigest,
) -> Result<ModuleArtifactV1> {
    Ok(produce_commonjs_artifact_with_sites_v1(
        source_id,
        source_name,
        source_path,
        source,
        producer_binary_digest,
    )?
    .artifact)
}

pub fn produce_commonjs_artifact_with_sites_v1(
    source_id: SourceId,
    source_name: &str,
    source_path: &Path,
    source: &str,
    producer_binary_digest: CapsecDigest,
) -> Result<ProducedModuleArtifactV1> {
    let intermediate = transform_with_oxc_goal(source_path, source, false)?;
    // The native site-bearing callbacks carry producer-owned authority
    // metadata. Keep them in an outer compiler-private closure: authored
    // CommonJS sees only the five ordinary wrapper arguments, and a generated
    // identifier is selected precisely because it is absent from the complete
    // transformed source. Direct eval/Function are closed by the armed runtime,
    // so package code has no reflective route back to these lexical bindings.
    let private_binding = |stem: &str| {
        (0_u64..)
            .map(|index| format!("__ibex_private_{stem}_{index}"))
            .find(|candidate| !intermediate.code.contains(candidate))
            .expect("finite source always leaves a private identifier available")
    };
    let dynamic_import_binding = private_binding("dynamic_import");
    let computed_require_binding = private_binding("computed_require");
    let allocator = Allocator::default();
    let parsed = Parser::new(
        &allocator,
        &intermediate.code,
        SourceType::default().with_module(false),
    )
    .parse();
    if !parsed.diagnostics.is_empty() {
        bail!(
            "Oxc could not parse transformed CommonJS {}: {:?}",
            source_name,
            parsed.diagnostics
        );
    }
    let program = parsed.program;
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&program);
    if !semantic.diagnostics.is_empty() {
        bail!(
            "Oxc semantics failed for transformed CommonJS {}: {:?}",
            source_name,
            semantic.diagnostics
        );
    }
    let mut visitor = CommonJsDependencyVisitor {
        scoping: semantic.semantic.scoping(),
        dynamic_import_binding: dynamic_import_binding.clone(),
        computed_require_binding: computed_require_binding.clone(),
        require_specifiers: BTreeSet::new(),
        dynamic_edges: Vec::new(),
        replacements: Vec::new(),
        computed_require_calls: Vec::new(),
        dynamic_option_error: None,
    };
    visitor.visit_program(&program);
    if let Some(error) = visitor.dynamic_option_error.take() {
        bail!("{error}");
    }
    if visitor.computed_require_calls.len() != intermediate.authored_computed_requires.len() {
        bail!("computed CommonJS require correspondence changed during Oxc lowering");
    }
    for (call, original) in visitor
        .computed_require_calls
        .iter()
        .zip(&intermediate.authored_computed_requires)
    {
        visitor.replacements.push(Replacement {
            span: *call,
            text: format!(
                "{}({}, {}__IBEX_REQUIRE_ARGUMENTS__)",
                visitor.computed_require_binding, original.start, original.end
            ),
        });
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
    finalize_dynamic_sites(
        &mut visitor.dynamic_edges,
        &mut visitor.replacements,
        &intermediate.authored_dynamic_imports,
    )?;
    let dynamic_edges = visitor
        .dynamic_edges
        .iter()
        .map(|edge| {
            if !edge.runtime_options_supported {
                return Ok(DynamicEdgeV1::Computed { site: edge.site });
            }
            match edge.specifier.as_deref() {
                Some(specifier) => Ok(DynamicEdgeV1::Literal {
                    specifier: non_empty(specifier, "dynamic import specifier")?,
                    attributes: ImportAttributes::new(edge.attributes.clone())?,
                }),
                None => Ok(DynamicEdgeV1::Computed { site: edge.site }),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let mut labels = BTreeSet::new();
    let dynamic_import_sites = visitor
        .dynamic_edges
        .iter()
        .filter(|edge| edge.specifier.is_none())
        .map(|edge| {
            let label = edge
                .label
                .as_ref()
                .map(|value| StableId::new(value.clone()).map_err(anyhow::Error::msg))
                .transpose()?;
            if label
                .as_ref()
                .is_some_and(|label| !labels.insert(label.as_str().to_owned()))
            {
                bail!("computed dynamic-import labels must be unique per requester");
            }
            Ok(DynamicImportSiteV1 {
                site: edge.site,
                label,
                original_source_span: OriginalSourceSpanV1 {
                    start: edge.original_source_offset,
                    end: edge.original_source_end,
                },
                attributes: ImportAttributes::new(edge.attributes.clone())?,
                runtime_options_supported: edge.runtime_options_supported,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut guarded_unsupported_sites = visitor
        .dynamic_edges
        .iter()
        .filter(|edge| !edge.runtime_options_supported)
        .map(|edge| GuardedUnsupportedSiteV1 {
            shape: GuardedUnsupportedShapeV1::UnsupportedDynamicImportOptions,
            original_source_span: OriginalSourceSpanV1 {
                start: edge.original_source_offset,
                end: edge.original_source_end,
            },
        })
        .collect::<Vec<_>>();
    guarded_unsupported_sites.extend(intermediate.authored_computed_requires.iter().cloned().map(
        |original_source_span| GuardedUnsupportedSiteV1 {
            shape: GuardedUnsupportedShapeV1::ComputedCommonJsRequire,
            original_source_span,
        },
    ));
    guarded_unsupported_sites.sort_by_key(|site| {
        (
            site.original_source_span.start,
            site.original_source_span.end,
            site.shape,
        )
    });
    let rewritten = apply_replacements(
        &intermediate.code,
        Span::new(0, intermediate.code.len() as u32),
        &visitor.replacements,
    )?;
    let prefix = format!(
        "function (require, module, exports, __filename, __dirname, {dynamic_import_binding}, {computed_require_binding}) {{\nreturn (function (require, module, exports, __filename, __dirname) {{\n\"use strict\";\n"
    );
    let suffix = "\n}).call(exports, require, module, exports, __filename, __dirname);\n}\n";
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
    let fingerprint = commonjs_artifact_transform_fingerprint_v1()?;
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
    let artifact = ModuleArtifactV1::new_inline(
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
    )?;
    Ok(ProducedModuleArtifactV1 {
        artifact,
        dynamic_import_sites,
        guarded_unsupported_sites,
    })
}

/// Produce one strict JSON record whose sole export is `default`. The original
/// bytes remain the integrity input; only the trusted factory embeds canonical
/// JCS so whitespace and object-order choices cannot become executable text.
pub fn produce_json_artifact_v1(
    source_id: SourceId,
    source: &str,
    producer_binary_digest: CapsecDigest,
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
            transform_fingerprint: json_artifact_transform_fingerprint_v1()?,
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
) -> Result<ModuleArtifactV1> {
    let path = PathBuf::from(format!("{source_name}.js"));
    let staging_id = SourceId::synthetic("builtin-producer", source_name)?;
    let artifact = produce_commonjs_artifact_v1(
        staging_id,
        source_name,
        &path,
        source,
        producer_binary_digest,
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

/// Closed Oxc transform for one app-bound external script. The output is one
/// callable expression consumed by the restricted-worker constructor; it is
/// never admitted to the parent module graph.
/// @ref LLP 0048#2-external-script-language-and-transform-profile
#[derive(Debug, Clone)]
pub struct ExternalScriptTransformV1 {
    pub callable_source: Vec<u8>,
    pub composed_source_map: Vec<u8>,
    pub has_default_export: bool,
}

pub fn transform_external_script_v1(
    path: &Path,
    source: &str,
) -> Result<ExternalScriptTransformV1> {
    if source.len() > 1024 * 1024 {
        bail!("external script exceeds the fixed 1 MiB source ceiling");
    }
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_else(|_| SourceType::mjs())
        .with_module(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.diagnostics.is_empty() {
        bail!("external script parse failed: {:?}", parsed.diagnostics);
    }
    let program = parsed.program;
    let mut default_span = None;
    for statement in &program.body {
        match statement {
            Statement::ImportDeclaration(_)
            | Statement::ExportAllDeclaration(_)
            | Statement::ExportNamedDeclaration(_) => {
                bail!("external scripts cannot import or export runtime bindings")
            }
            Statement::ExportDefaultDeclaration(declaration) => {
                if default_span.is_some() {
                    bail!("external scripts may contain at most one default export");
                }
                let Some(expression) = declaration.declaration.as_expression() else {
                    bail!("external script default export must be an assignment expression");
                };
                default_span = Some((declaration.span, expression.span()));
            }
            _ => {}
        }
    }
    #[derive(Default)]
    struct ClosedProfile {
        dynamic_import: bool,
        import_meta: bool,
        jsx: bool,
        non_erasable_typescript: bool,
    }
    impl<'a> Visit<'a> for ClosedProfile {
        fn visit_import_expression(&mut self, expression: &ImportExpression<'a>) {
            self.dynamic_import = true;
            walk::walk_import_expression(self, expression);
        }
        fn visit_meta_property(&mut self, property: &MetaProperty<'a>) {
            if property.meta.name == "import" && property.property.name == "meta" {
                self.import_meta = true;
            }
            walk::walk_meta_property(self, property);
        }
        fn visit_jsx_element(&mut self, _: &JSXElement<'a>) {
            self.jsx = true;
        }
        fn visit_jsx_fragment(&mut self, _: &JSXFragment<'a>) {
            self.jsx = true;
        }
        fn visit_ts_enum_declaration(&mut self, _: &TSEnumDeclaration<'a>) {
            self.non_erasable_typescript = true;
        }
        fn visit_ts_module_declaration(&mut self, _: &TSModuleDeclaration<'a>) {
            self.non_erasable_typescript = true;
        }
    }
    let mut closed = ClosedProfile::default();
    closed.visit_program(&program);
    if closed.dynamic_import || closed.import_meta {
        bail!("external scripts cannot use import() or import.meta");
    }
    if closed.jsx {
        bail!("external scripts do not admit JSX");
    }
    if closed.non_erasable_typescript {
        bail!("external scripts admit only erasable TypeScript syntax");
    }

    let binding = "__ibex_external_default_value__";
    if source.contains(binding) {
        bail!("external script uses a producer-reserved binding");
    }
    let rewritten = if let Some((declaration, expression)) = default_span {
        let start = usize::try_from(declaration.start).context("external span overflow")?;
        let expression_start =
            usize::try_from(expression.start).context("external expression span overflow")?;
        let end = usize::try_from(expression.end).context("external expression span overflow")?;
        format!(
            "{}const {binding} = ({});{}",
            &source[..start],
            &source[expression_start..end],
            &source[end..]
        )
    } else {
        source.to_owned()
    };
    let intermediate = transform_with_oxc_goal(path, &rewritten, true)?;
    if intermediate.code.as_bytes().len() > 4 * 1024 * 1024 {
        bail!("external script transform exceeds the fixed 4 MiB ceiling");
    }
    let prefix = "(async function(api,snapback,args,signal,console,setTimeout,clearTimeout){\n\"use strict\";\n";
    let suffix = if default_span.is_some() {
        format!("\nreturn {{present:true,value:await {binding}}};\n}})")
    } else {
        "\nreturn {present:false};\n})".to_owned()
    };
    let callable = format!("{prefix}{}{suffix}", intermediate.code);
    let mut builder = SourceMapBuilder::default();
    builder.set_file("external-script.worker.js");
    let source_name = path.to_string_lossy();
    let source_id = builder.set_source_and_content(&source_name, source);
    let lookup = intermediate.map.generate_lookup_table();
    let offset = prefix.lines().count().saturating_sub(1) as u32;
    for (line, _) in intermediate.code.lines().enumerate() {
        let generated = u32::try_from(line).context("external source map line overflow")?;
        let original = intermediate
            .map
            .lookup_token(&lookup, generated, 0)
            .map(|token| token.get_src_line())
            .unwrap_or(generated);
        builder.add_token(offset + generated, 0, original, 0, Some(source_id), None);
    }
    let mut map: Value = serde_json::from_str(&builder.into_sourcemap().to_json_string())?;
    map["x_ibex_composed"] = Value::Bool(true);
    let map = serde_json::to_vec(&map)?;
    if map.len() > 8 * 1024 * 1024 {
        bail!("external script source map exceeds the fixed 8 MiB ceiling");
    }
    Ok(ExternalScriptTransformV1 {
        callable_source: callable.into_bytes(),
        composed_source_map: map,
        has_default_export: default_span.is_some(),
    })
}

#[cfg(test)]
mod external_script_tests {
    use super::*;

    #[test]
    fn transforms_erased_typescript_and_default_value() {
        let output = transform_external_script_v1(
            Path::new("example.ts"),
            "const value: number = 41; export default await Promise.resolve(value + 1);",
        )
        .unwrap();
        let code = String::from_utf8(output.callable_source).unwrap();
        assert!(output.has_default_export);
        assert!(code.starts_with(
            "(async function(api,snapback,args,signal,console,setTimeout,clearTimeout)"
        ));
        assert!(code.contains("return {present:true,value:await __ibex_external_default_value__}"));
        assert!(!code.contains(": number"));
        assert!(!output.composed_source_map.is_empty());
    }

    #[test]
    fn transforms_no_default_to_absent_settlement() {
        let output =
            transform_external_script_v1(Path::new("example.js"), "console.log('ok');").unwrap();
        assert!(!output.has_default_export);
        assert!(String::from_utf8(output.callable_source)
            .unwrap()
            .contains("return {present:false}"));
    }

    #[test]
    fn refuses_open_module_and_non_erasable_profiles() {
        for (name, source) in [
            ("static-import.ts", "import x from './x.js';"),
            ("dynamic-import.ts", "void import('./x.js');"),
            ("jsx.tsx", "const x = <div />;"),
            ("enum.ts", "enum Value { A }"),
            ("default-function.ts", "export default function nope() {}"),
        ] {
            assert!(
                transform_external_script_v1(Path::new(name), source).is_err(),
                "{name}"
            );
        }
    }
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
    if !parsed.diagnostics.is_empty() {
        bail!(
            "Oxc parse failed for {}: {:?}",
            path.display(),
            parsed.diagnostics
        );
    }
    let mut program = parsed.program;
    let mut authored_dynamic_imports = AuthoredDynamicImportVisitor::default();
    authored_dynamic_imports.visit_program(&program);
    if let Some(error) = authored_dynamic_imports.source_option_error {
        bail!("{error}");
    }
    let mut hermes_syntax = HermesSyntaxVisitor::default();
    hermes_syntax.visit_program(&program);
    if let Some((site, quarantine)) = hermes_syntax.quarantine {
        return Err(unsupported_module_runner_shape(
            LegacyModuleRunnerRequirement::hermes_syntax(site, quarantine),
        ));
    }
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        // Oxc's TypeScript enum transform evaluates constant members through
        // semantic scoping and panics if this projection was omitted. Keep the
        // prerequisite adjacent to the production Transformer call.
        // @ref LLP 0028#5-conformance-gates-telemetry-and-rollout
        .with_enum_eval(true)
        .build(&program);
    if !semantic.diagnostics.is_empty() {
        bail!(
            "Oxc semantics failed for {}: {:?}",
            path.display(),
            semantic.diagnostics
        );
    }
    let authored_computed_requires = if module_goal {
        Vec::new()
    } else {
        let mut visitor = AuthoredComputedRequireVisitor {
            scoping: semantic.semantic.scoping(),
            sites: Vec::new(),
        };
        visitor.visit_program(&program);
        visitor.sites
    };
    // The factory ABI, not Hermes' native module parser, consumes TLA. Every
    // output-affecting option is generated from the canonical configuration;
    // unsupported authored values fail closed instead of silently selecting an
    // Oxc default. @ref LLP 0028#1-toolchain-and-pin-rotation--atomic-with-identity-rotation
    if transform_config::OXC_MODULE_MODE != "preserve"
        || transform_config::OXC_TYPESCRIPT_MODE != "strip"
        || !transform_config::OXC_JSX_ENABLED
        || transform_config::OXC_JSX_RUNTIME != "classic"
        || transform_config::OXC_DECORATORS
        || transform_config::CODEGEN_SOURCE_MAP != "v3-source-id"
        || transform_config::CODEGEN_MINIFY
    {
        bail!("generated module-transform configuration is unsupported by this producer");
    }
    let mut options =
        TransformOptions::from_target(transform_config::ECMASCRIPT_TARGET).map_err(|error| {
            anyhow!(
                "configure Oxc {} target: {error}",
                transform_config::ECMASCRIPT_TARGET
            )
        })?;
    options.env.module = Module::Preserve;
    options.jsx = JsxOptions {
        runtime: JsxRuntime::Classic,
        ..JsxOptions::enable()
    };
    let transformed = Transformer::new(&allocator, path, &options)
        .build_with_scoping(semantic.semantic.into_scoping(), &mut program);
    if !transformed.diagnostics.is_empty() {
        bail!(
            "Oxc transform failed for {}: {:?}",
            path.display(),
            transformed.diagnostics
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
        map: map.into_owned(),
        authored_dynamic_imports: authored_dynamic_imports.sites,
        authored_computed_requires,
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
                                    line_of(source, declarator.span.end),
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
                                line_of(source, span.end),
                            );
                            for name in declaration_names(inner)? {
                                append_mapped(
                                    &mut lowered.execute,
                                    &mut lowered.execute_line_origins,
                                    &format!("\n{export_callback}({}, {name});", js_string(&name)),
                                    line_of(source, span.start),
                                    line_of(source, span.end),
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
                                line_of(source, statement_span.end),
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
                    line_of(source, span.end),
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
                    line_of(source, statement_span.end),
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
    selected.sort_by_key(|replacement| {
        (
            replacement.span.start,
            std::cmp::Reverse(replacement.span.end),
        )
    });
    let mut top_level: Vec<Replacement> = Vec::new();
    for replacement in selected {
        if let Some(parent) = top_level.last() {
            if replacement.span.start < parent.span.end {
                if replacement.span.end <= parent.span.end {
                    continue;
                }
                bail!(
                    "producer spike encountered crossing AST rewrites at {}..{} and {}..{}",
                    parent.span.start,
                    parent.span.end,
                    replacement.span.start,
                    replacement.span.end
                );
            }
        }
        top_level.push(replacement);
    }
    let mut output = String::new();
    let mut cursor = range.start as usize;
    for replacement in top_level {
        output.push_str(&source[cursor..replacement.span.start as usize]);
        output.push_str(&materialize_replacement(
            source,
            &replacement,
            replacements,
        )?);
        cursor = replacement.span.end as usize;
    }
    output.push_str(&source[cursor..range.end as usize]);
    Ok(output)
}

fn materialize_replacement(
    source: &str,
    replacement: &Replacement,
    replacements: &[Replacement],
) -> Result<String> {
    let nested = replacements
        .iter()
        .filter(|candidate| {
            candidate.span.start >= replacement.span.start
                && candidate.span.end <= replacement.span.end
                && candidate.span != replacement.span
        })
        .cloned()
        .collect::<Vec<_>>();
    let original = if nested.is_empty() {
        source[replacement.span.start as usize..replacement.span.end as usize].to_owned()
    } else {
        apply_replacements(source, replacement.span, &nested)?
    };
    let mut text = replacement.text.replace("__IBEX_ORIGINAL__", &original);
    if text.contains("__IBEX_IMPORT_ARGUMENTS__") {
        let arguments = original
            .strip_prefix("import(")
            .and_then(|value| value.strip_suffix(')'))
            .unwrap_or(&original);
        text = text.replace("__IBEX_IMPORT_ARGUMENTS__", arguments);
    }
    if text.contains("__IBEX_REQUIRE_ARGUMENTS__") {
        let arguments = original
            .strip_prefix("require(")
            .and_then(|value| value.strip_suffix(')'))
            .ok_or_else(|| anyhow!("computed require rewrite lost its call expression"))?;
        let arguments = if arguments.trim().is_empty() {
            String::new()
        } else {
            format!(", {arguments}")
        };
        text = text.replace("__IBEX_REQUIRE_ARGUMENTS__", &arguments);
    }
    while let Some(start) = text.find("__IBEX_REWRITE_SPAN_") {
        let suffix = &text[start + "__IBEX_REWRITE_SPAN_".len()..];
        let Some(end) = suffix.find("__") else { break };
        let bounds = &suffix[..end];
        let Some((from, to)) = bounds.split_once('_') else {
            break;
        };
        let from = from.parse::<u32>().expect("encoded rewrite span start");
        let to = to.parse::<u32>().expect("encoded rewrite span end");
        let rewritten = apply_replacements(source, Span::new(from, to), &nested)?;
        text.replace_range(
            start..start + "__IBEX_REWRITE_SPAN_".len() + end + 2,
            &rewritten,
        );
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
    Ok(text)
}

fn append_mapped(
    output: &mut String,
    origins: &mut Vec<Option<u32>>,
    text: &str,
    first_source_line: u32,
    last_source_line: u32,
) {
    debug_assert!(first_source_line <= last_source_line);
    let start_line = output.lines().count() as u32;
    output.push_str(text);
    let line_count = text.lines().count().max(1);
    while origins.len() < start_line as usize + line_count {
        let offset = origins.len().saturating_sub(start_line as usize) as u32;
        // Handwritten rewrites can expand one source statement into more
        // generated lines than the statement occupied. Those synthetic lines
        // retain the statement's last real source line instead of inventing
        // out-of-range original locations.
        // @ref LLP 0028#1-toolchain-and-pin-rotation--atomic-with-identity-rotation
        origins.push(Some((first_source_line + offset).min(last_source_line)));
    }
}

fn compose_factory_source_map(
    source_name: &str,
    source: &str,
    intermediate_map: &SourceMap<'_>,
    body_line_offset: u32,
    line_origins: &[Option<u32>],
    factory_source: &str,
) -> Result<Value> {
    let stage_map = intermediate_map.clone();
    let lookup = stage_map.generate_lookup_table();
    let mut builder = SourceMapBuilder::default();
    let factory_file = format!("{source_name}.factory.js");
    builder.set_file(&factory_file);
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
        let golden = root.join("tests/fixtures/module-runner-spike/canonical-artifacts.json");
        if std::env::var_os("IBEX_REGENERATE_MODULE_RUNNER_SPIKE_GOLDENS").is_some() {
            std::fs::write(&golden, &rendered).expect("regenerate canonical spike artifacts");
        }
        let checked_in = std::fs::read_to_string(golden).expect("checked-in artifacts");
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
        let golden = root.join("tests/fixtures/module-runner-spike/test262-artifacts.json");
        if std::env::var_os("IBEX_REGENERATE_MODULE_RUNNER_SPIKE_GOLDENS").is_some() {
            std::fs::write(&golden, &rendered).expect("regenerate test262 spike artifacts");
        }
        let checked_in = std::fs::read_to_string(golden).expect("checked-in test262 artifacts");
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
                    transform_fingerprint_digest: module_artifact_transform_fingerprint_v1()
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
    fn canonical_transform_config_rejects_pre_rotation_artifacts() {
        let current = module_artifact_transform_fingerprint_v1().unwrap();
        assert_eq!(
            current.hermes_target.as_str(),
            transform_config::HERMES_TARGET,
            "producer syntax target must not come from a loaded evaluator"
        );
        assert!(module_artifact_transform_cache_tag_v1()
            .contains(transform_config::TRANSFORM_CONFIGURATION_DIGEST));

        let mut stale = current.clone();
        stale.transform_version = NonEmptyString::new("pre-rotation-config").unwrap();
        let mut semantics = ModuleSemanticsV1 {
            source_id: CanonicalSourceId(
                SourceId::synthetic("fixture", "stale-transform").unwrap(),
            ),
            source_goal: SourceGoalV1::Module,
            dialect: Some(SourceDialectV1::Js),
            source_integrity: source_integrity(b"export const value = 1;").unwrap(),
            transform_fingerprint: stale,
            static_edges: Vec::new(),
            dynamic_edges: Vec::new(),
            export_descriptors: Vec::new(),
            commonjs_exports: None,
            has_top_level_await: false,
            factory_digest: source_integrity(b"factory").unwrap(),
            source_map: SourceMapV1 {
                version: 3,
                source_ids: vec![CanonicalSourceId(
                    SourceId::synthetic("fixture", "stale-transform").unwrap(),
                )],
                names: Vec::new(),
                mappings: String::new(),
            },
        };
        assert!(verify_current_transform_fingerprint_v1(&semantics).is_err());
        semantics.transform_fingerprint = current;
        verify_current_transform_fingerprint_v1(&semantics).unwrap();
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
        )
        .unwrap();
        let StaticEdgeV1::Default { attributes, .. } = &artifact.semantics.static_edges[0] else {
            panic!("expected default JSON edge")
        };
        assert!(attributes.asserts_json());
    }

    #[test]
    fn production_adapter_emits_site_bearing_computed_import_and_correspondence() {
        let literal = produce_module_artifact_v1(
            SourceId::synthetic("fixture", "literal-dynamic-import").unwrap(),
            "entry.mjs",
            Path::new("entry.mjs"),
            "export const result = import('./literal.mjs');",
            source_integrity(b"producer-binary").unwrap(),
        )
        .unwrap();
        assert_eq!(
            literal.semantics.dynamic_edges,
            [DynamicEdgeV1::Literal {
                specifier: NonEmptyString::new("./literal.mjs").unwrap(),
                attributes: ImportAttributes::default(),
            }]
        );

        let source = "const name = './computed.mjs'; export const results = [import('./literal.mjs'), import(name, { with: { 'ibex:site': 'routes' } })];";
        let produced = produce_module_artifact_with_sites_v1(
            SourceId::synthetic("fixture", "computed-dynamic-import").unwrap(),
            "entry.mjs",
            Path::new("entry.mjs"),
            source,
            source_integrity(b"producer-binary").unwrap(),
        )
        .unwrap();
        assert_eq!(
            produced.artifact.semantics.dynamic_edges,
            [
                DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./literal.mjs").unwrap(),
                    attributes: ImportAttributes::default(),
                },
                DynamicEdgeV1::Computed { site: 1 },
            ]
        );
        let ModulePayloadV1::Inline { factory_source, .. } = &produced.artifact.payload else {
            panic!("expected inline factory")
        };
        assert!(factory_source.contains(&format!(
            "dynamicImport(1, {}, {}, 0, name",
            source.find("import(name").unwrap(),
            source.find("import(name").unwrap()
                + source[source.find("import(name").unwrap()..]
                    .find(')')
                    .unwrap()
                + 1
        )));
        assert_eq!(produced.dynamic_import_sites.len(), 1);
        let site = &produced.dynamic_import_sites[0];
        assert_eq!(site.site, 1);
        assert_eq!(site.label.as_ref().unwrap().as_str(), "routes");
        assert_eq!(
            site.original_source_span.start,
            u32::try_from(source.find("import(name").unwrap()).unwrap()
        );
    }

    #[test]
    fn computed_site_span_comes_from_authored_typescript_not_transformed_bytes() {
        let source = "const prefix: string = './'; const name: string = prefix + 'target.mjs'; export const result = import(name, { with: { 'ibex:site': 'typed-route' } });";
        let produced = produce_module_artifact_with_sites_v1(
            SourceId::synthetic("fixture", "typed-computed-import").unwrap(),
            "entry.ts",
            Path::new("entry.ts"),
            source,
            source_integrity(b"producer-binary").unwrap(),
        )
        .unwrap();
        let site = &produced.dynamic_import_sites[0];
        let authored_start = u32::try_from(source.find("import(name").unwrap()).unwrap();
        assert_eq!(site.original_source_span.start, authored_start);
        let ModulePayloadV1::Inline { factory_source, .. } = produced.artifact.payload else {
            unreachable!()
        };
        assert!(factory_source.contains(&format!("dynamicImport(0, {authored_start},")));
    }

    #[test]
    fn non_reserved_option_defects_are_guarded_but_reserved_policy_keys_fail_generation() {
        let unknown = "const name = './target.mjs'; if (false) import(name, { with: { mystery: 'value', 'ibex:site': 'guarded' } });";
        let produced = produce_module_artifact_with_sites_v1(
            SourceId::synthetic("fixture", "guarded-options").unwrap(),
            "entry.mjs",
            Path::new("entry.mjs"),
            unknown,
            source_integrity(b"producer-binary").unwrap(),
        )
        .expect("an unknown option in a dead branch must remain loadable");
        assert_eq!(
            produced.dynamic_import_sites[0]
                .label
                .as_ref()
                .unwrap()
                .as_str(),
            "guarded"
        );
        let ModulePayloadV1::Inline { factory_source, .. } = produced.artifact.payload else {
            unreachable!()
        };
        assert!(factory_source.contains("dynamicImport(0,"));
        assert!(factory_source.contains(", 1, name"));

        let guarded_literal = produce_module_artifact_v1(
            SourceId::synthetic("fixture", "guarded-literal-options").unwrap(),
            "entry.mjs",
            Path::new("entry.mjs"),
            "if (false) import('./must-not-resolve.mjs', { with: { mystery: 'value' } });",
            source_integrity(b"producer-binary").unwrap(),
        )
        .expect("an invalid literal site must be representable without resolving its target");
        assert_eq!(
            guarded_literal.semantics.dynamic_edges,
            [DynamicEdgeV1::Computed { site: 0 }]
        );

        let error = produce_module_artifact_v1(
            SourceId::synthetic("fixture", "reserved-options").unwrap(),
            "entry.mjs",
            Path::new("entry.mjs"),
            "if (false) import('./target.mjs', { with: { authorities: 'fs' } });",
            source_integrity(b"producer-binary").unwrap(),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("reserved build-time import attribute"));
    }

    #[test]
    fn nested_dynamic_imports_receive_distinct_site_metadata_and_rewrites() {
        let source = "const name = './target.mjs'; export const nested = import(import(name, { with: { 'ibex:site': 'inner' } }));";
        let produced = produce_module_artifact_with_sites_v1(
            SourceId::synthetic("fixture", "nested-imports").unwrap(),
            "entry.mjs",
            Path::new("entry.mjs"),
            source,
            source_integrity(b"producer-binary").unwrap(),
        )
        .unwrap();
        assert_eq!(produced.dynamic_import_sites.len(), 2);
        assert_eq!(produced.dynamic_import_sites[0].site, 0);
        assert_eq!(produced.dynamic_import_sites[1].site, 1);
        assert_eq!(
            produced.dynamic_import_sites[1]
                .label
                .as_ref()
                .unwrap()
                .as_str(),
            "inner"
        );
        let ModulePayloadV1::Inline { factory_source, .. } = produced.artifact.payload else {
            unreachable!()
        };
        assert!(!factory_source.contains("import("));
        assert!(factory_source.matches("dynamicImport(").count() >= 2);
    }

    #[test]
    fn tier3_for_of_retains_only_the_for_await_typed_quarantine() {
        for source in [
            "for (const value of [1, 2]) { if (value) break; }",
            "for (const { value } of [{ value: 1 }]) { console.log(value); }",
            "for (const value of [1, 2]) console.log(value);",
            "for (var value of [1, 2]) { console.log(value); }",
            "for (value of [1, 2]) { console.log(value); }",
            "export function log(xs) { for (const value of xs) { console.log(this, arguments, value); } }",
        ] {
            produce_module_artifact_v1(
                SourceId::synthetic("fixture", "canonical-for-of").unwrap(),
                "entry.mjs",
                Path::new("entry.mjs"),
                source,
                source_integrity(b"producer-binary").unwrap(),
            )
            .unwrap_or_else(|error| panic!("canonical for-of shape refused: {error:#}"));
        }

        let expected = Tier3ForOfQuarantineReason::AwaitLoop;
        for source in [
            "export async function visit(xs) { for await (const value of xs) { console.log(value); } }",
            "export async function visit(xss) { for (const xs of xss) { for await (const value of xs) { console.log(value); } } }",
        ] {
            let error = produce_module_artifact_v1(
                SourceId::synthetic("fixture", expected.as_str()).unwrap(),
                "entry.mjs",
                Path::new("entry.mjs"),
                source,
                source_integrity(b"producer-binary").unwrap(),
            )
            .unwrap_err();
            let requirement = unsupported_module_runner_reason(&error)
                .unwrap_or_else(|| panic!("missing typed fallback for {expected:?}: {error:#}"));
            assert_eq!(
                requirement.kind,
                super::super::compatibility::LegacyModuleRunnerRequirementKind::Tier3ForOf(
                    expected
                )
            );
            assert_eq!(requirement.kind.stable_code(), "IBEX_LEGACY_TIER3_FOR_OF");
            assert!(requirement.original_source_offset.is_some());
        }
    }

    #[test]
    fn tier3_for_of_keeps_the_proven_simple_capture_row_native() {
        let artifact = produce_module_artifact_v1(
            SourceId::synthetic("fixture", "simple-for-of-capture").unwrap(),
            "entry.mjs",
            Path::new("entry.mjs"),
            "const handlers = []; for (const value of [1, 2]) { handlers.push(() => value); } export { handlers };",
            source_integrity(b"producer-binary").unwrap(),
        )
        .expect("the corpus-proven capture-only row remains native");
        let ModulePayloadV1::Inline { factory_source, .. } = artifact.payload else {
            unreachable!()
        };
        assert!(factory_source.contains("const __exactForOfBody0 = (__exactForOfValue0) =>"));
        assert!(factory_source.contains("const value = __exactForOfValue0"));
    }

    #[test]
    fn expanded_rewrite_lines_never_invent_source_lines() {
        let mut output = String::new();
        let mut origins = Vec::new();
        append_mapped(
            &mut output,
            &mut origins,
            "synthetic one\nsynthetic two\noriginal body",
            4,
            5,
        );
        assert_eq!(origins, [Some(4), Some(5), Some(5)]);
    }

    #[test]
    fn hermes_syntax_without_a_native_pass_is_typed_before_execution() {
        let cases = [
            (
                HermesSyntaxQuarantineReason::AsyncGenerator,
                "export async function* values() { yield 1; }",
            ),
            (
                HermesSyntaxQuarantineReason::UsingDeclaration,
                "using resource = acquire(); export { resource };",
            ),
            (
                HermesSyntaxQuarantineReason::AwaitUsingDeclaration,
                "await using resource = acquire(); export { resource };",
            ),
            (
                HermesSyntaxQuarantineReason::Decorator,
                "@sealed export class Example {}",
            ),
        ];
        for (expected, source) in cases {
            let error = produce_module_artifact_v1(
                SourceId::synthetic("fixture", expected.as_str()).unwrap(),
                "entry.mjs",
                Path::new("entry.mjs"),
                source,
                source_integrity(b"producer-binary").unwrap(),
            )
            .unwrap_err();
            let requirement = unsupported_module_runner_reason(&error)
                .unwrap_or_else(|| panic!("missing typed fallback for {expected:?}: {error:#}"));
            assert_eq!(
                requirement.kind,
                super::super::compatibility::LegacyModuleRunnerRequirementKind::HermesSyntax(
                    expected
                )
            );
            assert_eq!(requirement.kind.stable_code(), "IBEX_LEGACY_HERMES_SYNTAX");
        }
    }

    #[test]
    fn tier3_lowers_bigint_literals_with_the_canonical_constructor_shape() {
        let artifact = produce_module_artifact_v1(
            SourceId::synthetic("fixture", "bigint").unwrap(),
            "entry.mjs",
            Path::new("entry.mjs"),
            "export const values = [1_000n, 0xffn];",
            source_integrity(b"producer-binary").unwrap(),
        )
        .unwrap();
        let ModulePayloadV1::Inline { factory_source, .. } = artifact.payload else {
            unreachable!()
        };
        assert!(factory_source.contains("BigInt(\"1000\")"));
        assert!(factory_source.contains("BigInt(\"255\")"));
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
            "function (require, module, exports, __filename, __dirname, __ibex_private_dynamic_import_0, __ibex_private_computed_require_0) {\nreturn (function (require, module, exports, __filename, __dirname) {\n\"use strict\";"
        ));
        assert!(factory_source.ends_with(
            "\n}).call(exports, require, module, exports, __filename, __dirname);\n}\n"
        ));
        assert!(!factory_source.contains("import('./async.mjs')"));
        assert!(factory_source.contains("__ibex_private_dynamic_import_0(-1,"));
        assert!(
            factory_source.contains("'./async.mjs')")
                || factory_source.contains("\"./async.mjs\")")
        );
        assert!(!factory_source.contains(": number"));
    }

    #[test]
    fn commonjs_adapter_guards_computed_require_until_invocation() {
        let source = "const prefix: string = './'; if (false) { require(prefix + 'dead.cjs'); } const name = './dep.cjs'; module.exports = require(name);";
        let artifact = produce_commonjs_artifact_v1(
            SourceId::synthetic("fixture", "computed-require").unwrap(),
            "entry.cjs",
            Path::new("entry.cts"),
            source,
            source_integrity(b"producer-binary").unwrap(),
        )
        .unwrap();
        let ModulePayloadV1::Inline { factory_source, .. } = artifact.payload else {
            unreachable!()
        };
        let dead_start = source.find("require(prefix").unwrap();
        let dead_end = source[dead_start..].find(')').unwrap() + dead_start + 1;
        let live_start = source.rfind("require(name)").unwrap();
        let live_end = live_start + "require(name)".len();
        assert!(factory_source.contains(&format!(
            "__ibex_private_computed_require_0({dead_start}, {dead_end},"
        )));
        assert!(factory_source.contains(&format!(
            "__ibex_private_computed_require_0({live_start}, {live_end},"
        )));
        assert!(!factory_source.contains("require(name)"));
    }

    #[test]
    fn json_artifact_is_strict_and_exports_canonical_default() {
        let artifact = produce_json_artifact_v1(
            SourceId::synthetic("fixture", "data-json").unwrap(),
            "{\"z\":1,\"a\":[true,null]}",
            source_integrity(b"producer-binary").unwrap(),
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
        )
        .unwrap_err();
        assert!(duplicate.to_string().contains("strict JSON"));
    }
}
