//! Oxc-backed syntax analysis shared by non-module evaluation surfaces.
//!
//! This is LLP 0028's bounded frontend for `-e`, `-p`, REPL, `.load`, and
//! program stdin. Oxc owns parsing, Script early-error validation, TypeScript
//! and JSX lowering, and the AST spans used to lower imports. The result still
//! targets the existing session evaluator; the structured session protocol and
//! composed session source maps remain the separate LLP 0024 implementation.
//! @ref LLP 0028#3-the-llp-0024-gates-revise-the-seam-then-build-on-oxc

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, bail, Result};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AwaitExpression, Expression, FunctionBody, IdentifierReference, ImportAttributeKey,
    ImportDeclaration, ImportDeclarationSpecifier, ImportExpression, ImportOrExportKind,
    MetaProperty, Program, Statement,
};
use oxc_ast_visit::{walk, Visit};
use oxc_codegen::Codegen;
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::{GetSpan, SourceType, Span};
use oxc_transformer::{JsxOptions, JsxRuntime, Module, TransformOptions, Transformer};

use super::transform_config_generated as transform_config;

pub const SCRIPT_COMPUTED_IMPORT_ERROR_CODE: &str = "IBEX_ERR_SCRIPT_COMPUTED_IMPORT_NO_CANDIDATES";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationGoal {
    HybridScript,
    Module,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEvaluation {
    /// Hoisted import work. It contains `await`, so callers place it in an
    /// async wrapper whenever it is non-empty.
    pub preamble: String,
    /// Oxc-lowered body with module syntax removed.
    pub body: String,
    /// Lowered single-expression input, when the authored input has an
    /// expression completion that an interactive/print caller can preserve.
    pub expression: Option<String>,
    pub has_top_level_await: bool,
    pub has_static_imports: bool,
    pub empty_completion: bool,
    pub goal: EvaluationGoal,
}

impl PreparedEvaluation {
    pub fn needs_async_wrapper(&self) -> bool {
        self.has_top_level_await || self.has_static_imports
    }

    pub fn joined_source(&self) -> String {
        match (self.preamble.is_empty(), self.body.is_empty()) {
            (true, _) => self.body.clone(),
            (_, true) => self.preamble.clone(),
            _ => format!("{}\n{}", self.preamble, self.body),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptSyntaxAnalysis {
    pub has_top_level_await: bool,
}

/// Parse an evaluation surface with Oxc and project only syntax facts that do
/// not depend on choosing Script versus Module runtime semantics.
///
/// Oxc has no hybrid Script-plus-import-plus-TLA goal. Module goal is used
/// only as a permissive syntax oracle here; callers must not evaluate the
/// resulting AST or treat it as proof of Module semantics.
pub fn analyze_script_syntax(source: &str, source_path: &Path) -> Result<ScriptSyntaxAnalysis> {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(source_path)
        .unwrap_or_else(|_| SourceType::mjs())
        .with_module(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.diagnostics.is_empty() {
        bail!(
            "Oxc could not analyze script syntax for {}: {:?}",
            source_path.display(),
            parsed.diagnostics
        );
    }

    let mut program = parsed.program;
    let import_count = program
        .body
        .iter()
        .filter(|statement| matches!(statement, Statement::ImportDeclaration(_)))
        .count();
    // Oxc's parser retains sloppy-only syntax in the Module AST. Relabeling
    // that AST before semantic validation applies Script early-error rules;
    // the only expected diagnostic is the one produced for each deliberately
    // admitted static import declaration. This exact diagnostic is pin-bound
    // to Oxc 0.140.0 and therefore rotates with the transform configuration.
    program.source_type = source_type.with_script(true);
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&program);
    let admitted_import_diagnostics = semantic
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.message == "Cannot use import statement outside a module")
        .count();
    let unexpected = semantic
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.message != "Cannot use import statement outside a module")
        .collect::<Vec<_>>();
    if admitted_import_diagnostics != import_count || !unexpected.is_empty() {
        bail!(
            "Oxc hybrid Script semantic validation failed for {}: {:?}",
            source_path.display(),
            semantic.diagnostics
        );
    }

    Ok(ScriptSyntaxAnalysis {
        has_top_level_await: program_has_top_level_await(&program),
    })
}

/// Prepare an LLP 0024 Script-plus-import-plus-TLA source for the existing
/// session evaluator. `syntax_path` selects the Oxc dialect; virtual sources
/// should use a `.ts` path because extensionless evaluation is TypeScript,
/// non-JSX. `source_label` is retained in invocation diagnostics and
/// `referrer` is supplied to literal imports for relative resolution.
pub fn prepare_hybrid_script(
    source: &str,
    syntax_path: &Path,
    source_label: &str,
    referrer: &str,
) -> Result<PreparedEvaluation> {
    prepare_evaluation(
        source,
        syntax_path,
        source_label,
        referrer,
        EvaluationGoal::HybridScript,
    )
}

/// Prepare program-mode stdin under ordinary Module goal. Unlike the hybrid
/// surfaces, callers must execute the result in a strict wrapper so top-level
/// `this` is `undefined` and declarations do not enter the session global.
pub fn prepare_module_entry(
    source: &str,
    syntax_path: &Path,
    source_label: &str,
    referrer: &str,
) -> Result<PreparedEvaluation> {
    prepare_evaluation(
        source,
        syntax_path,
        source_label,
        referrer,
        EvaluationGoal::Module,
    )
}

fn prepare_evaluation(
    source: &str,
    syntax_path: &Path,
    source_label: &str,
    referrer: &str,
    goal: EvaluationGoal,
) -> Result<PreparedEvaluation> {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(syntax_path)
        .unwrap_or_else(|_| SourceType::ts())
        .with_module(true);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.diagnostics.is_empty() {
        bail!(
            "Oxc could not parse evaluation source {}: {:?}",
            source_label,
            parsed.diagnostics
        );
    }

    let mut program = parsed.program;
    let has_top_level_await = program_has_top_level_await(&program);
    let mut original_imports = DynamicImportInventory::default();
    original_imports.visit_program(&program);

    if goal == EvaluationGoal::HybridScript {
        program.source_type = source_type.with_script(true);
    }
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .with_enum_eval(true)
        .build(&program);
    validate_semantic_diagnostics(
        &program,
        goal,
        source_type.is_typescript(),
        &semantic.diagnostics,
        source_label,
    )?;
    let _script_scoping = semantic.semantic.into_scoping();
    // The semantic graph above is deliberately Script-goal. Oxc's TypeScript
    // transformer, however, drops value imports and emits `export {}` when it
    // sees import nodes on a Script-tagged Program. Restore only the syntactic
    // module tag for preserve-module transformation; the generated module
    // declarations are removed by AST span below and are never evaluated as a
    // Module. @ref LLP 0024#3-source-goal
    if goal == EvaluationGoal::HybridScript {
        program.source_type = source_type;
    }
    let transform_semantic = SemanticBuilder::new()
        // Script early errors were already checked above. This second graph
        // exists only because Oxc's TS transformer needs module-tagged import
        // bindings to preserve value imports; re-applying Module early errors
        // here would incorrectly reject the admitted sloppy Script forms.
        .with_check_syntax_error(false)
        .with_enum_eval(true)
        .build(&program);
    let scoping = transform_semantic.semantic.into_scoping();

    if transform_config::OXC_MODULE_MODE != "preserve"
        || transform_config::OXC_TYPESCRIPT_MODE != "strip"
        || !transform_config::OXC_JSX_ENABLED
        || transform_config::OXC_JSX_RUNTIME != "classic"
        || transform_config::OXC_DECORATORS
    {
        bail!("generated module-transform configuration is unsupported by the script frontend");
    }
    let mut options =
        TransformOptions::from_target(transform_config::ECMASCRIPT_TARGET).map_err(|error| {
            anyhow!(
                "configure Oxc {} target for {}: {error}",
                transform_config::ECMASCRIPT_TARGET,
                source_label
            )
        })?;
    options.env.module = Module::Preserve;
    // Session/script imports are runtime edges even when the imported binding
    // is not referenced. Oxc's Babel-compatible default elides unused value
    // imports; `only_remove_type_imports` preserves their side effects while
    // still erasing explicit `import type` declarations.
    options.typescript.only_remove_type_imports = true;
    options.jsx = JsxOptions {
        runtime: JsxRuntime::Classic,
        ..JsxOptions::enable()
    };
    let transformed = Transformer::new(&allocator, syntax_path, &options)
        .build_with_scoping(scoping, &mut program);
    if !transformed.diagnostics.is_empty() {
        bail!(
            "Oxc could not transform evaluation source {}: {:?}",
            source_label,
            transformed.diagnostics
        );
    }
    let intermediate = Codegen::new()
        .with_source_text(source)
        .with_scoping(Some(transformed.scoping))
        .build(&program)
        .code;
    if goal == EvaluationGoal::HybridScript {
        validate_transformed_hybrid_projection(&intermediate, source_label)?;
    }

    lower_evaluation_module_syntax(
        &intermediate,
        source,
        source_label,
        referrer,
        goal,
        has_top_level_await,
        &original_imports.sites,
    )
}

fn validate_semantic_diagnostics<T: std::fmt::Debug + std::fmt::Display>(
    program: &Program<'_>,
    goal: EvaluationGoal,
    typescript: bool,
    diagnostics: &[T],
    source_label: &str,
) -> Result<()> {
    if goal == EvaluationGoal::Module {
        if !diagnostics.is_empty() {
            bail!(
                "Oxc Module semantic validation failed for {}: {:?}",
                source_label,
                diagnostics
            );
        }
        return Ok(());
    }

    let import_count = program
        .body
        .iter()
        .filter(|statement| matches!(statement, Statement::ImportDeclaration(_)))
        .count();
    let messages = diagnostics
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let admitted = messages
        .iter()
        .filter(|message| message.as_str() == "Cannot use import statement outside a module")
        .count();
    // Oxc 0.140's TypeScript semantic pass omits the otherwise pinned
    // Script-goal import diagnostic. The post-transform JavaScript projection
    // below must produce the exact one-per-import count; this first pass still
    // rejects every non-import early error before TypeScript erasure can hide
    // it.
    let admitted_count_is_valid = admitted == import_count || (typescript && admitted == 0);
    if !admitted_count_is_valid || diagnostics.len() != admitted {
        bail!(
            "Oxc hybrid Script semantic validation failed for {}: {:?}",
            source_label,
            diagnostics
        );
    }
    Ok(())
}

fn validate_transformed_hybrid_projection(source: &str, source_label: &str) -> Result<()> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    if !parsed.diagnostics.is_empty() {
        bail!(
            "Oxc could not reparse transformed hybrid source {}: {:?}",
            source_label,
            parsed.diagnostics
        );
    }
    let mut program = parsed.program;
    program.source_type = SourceType::script();
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&program);
    validate_semantic_diagnostics(
        &program,
        EvaluationGoal::HybridScript,
        false,
        &semantic.diagnostics,
        source_label,
    )
    .map_err(|error| anyhow!("{error}\ntransformed source:\n{source}"))
}

fn lower_evaluation_module_syntax(
    intermediate: &str,
    original_source: &str,
    source_label: &str,
    referrer: &str,
    goal: EvaluationGoal,
    has_top_level_await: bool,
    original_dynamic_sites: &[DynamicImportSite],
) -> Result<PreparedEvaluation> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, intermediate, SourceType::mjs()).parse();
    if !parsed.diagnostics.is_empty() {
        bail!(
            "Oxc could not parse its lowered evaluation output for {}: {:?}",
            source_label,
            parsed.diagnostics
        );
    }
    let program = parsed.program;
    let prefix = fresh_helper_prefix(&program);
    let mut rewrites = Vec::new();
    let mut preamble = String::new();
    let mut static_import_count = 0usize;
    let mut runtime_statement_count = 0usize;
    let mut expression_spans = Vec::new();

    for statement in &program.body {
        if let Statement::ImportDeclaration(declaration) = statement {
            rewrites.push(Rewrite::new(declaration.span, String::new()));
            if declaration.import_kind == ImportOrExportKind::Type {
                continue;
            }
            emit_static_import(
                declaration,
                static_import_count,
                &prefix,
                referrer,
                goal,
                &mut preamble,
            )?;
            static_import_count += 1;
        } else {
            runtime_statement_count += 1;
            if let Statement::ExpressionStatement(statement) = statement {
                expression_spans.push(statement.expression.span());
            }
        }
    }

    let mut dynamic_rewriter = DynamicImportRewriter {
        rewrites: Vec::new(),
        original_sites: original_dynamic_sites,
        next_site: 0,
        original_source,
        intermediate,
        source_label,
        referrer,
        failure: None,
    };
    dynamic_rewriter.visit_program(&program);
    if let Some(error) = dynamic_rewriter.failure {
        return Err(error);
    }
    if dynamic_rewriter.next_site != original_dynamic_sites.len() {
        bail!(
            "Oxc dynamic-import inventory changed during lowering for {}",
            source_label
        );
    }
    rewrites.extend(dynamic_rewriter.rewrites);

    let mut meta_rewriter = ImportMetaRewriter {
        rewrites: Vec::new(),
        goal,
    };
    meta_rewriter.visit_program(&program);
    rewrites.extend(meta_rewriter.rewrites);

    let body = apply_rewrites(
        intermediate,
        Span::new(0, intermediate.len() as u32),
        &rewrites,
    )?
    .trim()
    .to_owned();
    let expression = if runtime_statement_count == 1 && expression_spans.len() == 1 {
        Some(
            apply_rewrites(intermediate, expression_spans[0], &rewrites)?
                .trim()
                .to_owned(),
        )
    } else {
        None
    };

    Ok(PreparedEvaluation {
        preamble: preamble.trim_end().to_owned(),
        body,
        expression,
        has_top_level_await,
        has_static_imports: static_import_count != 0,
        empty_completion: static_import_count != 0 && runtime_statement_count == 0,
        goal,
    })
}

fn emit_static_import(
    declaration: &ImportDeclaration<'_>,
    ordinal: usize,
    prefix: &str,
    referrer: &str,
    goal: EvaluationGoal,
    output: &mut String,
) -> Result<()> {
    let specifier = js_string(declaration.source.value.as_str())?;
    let options = import_options(declaration)?;
    let referrer = js_string(referrer)?;
    let temporary = format!("{prefix}{ordinal}");
    output.push_str(&format!(
        "var {temporary} = await globalThis['import']({specifier}, {options}, {referrer});\n"
    ));
    let Some(specifiers) = &declaration.specifiers else {
        return Ok(());
    };
    for specifier in specifiers {
        let (local, imported) = match specifier {
            ImportDeclarationSpecifier::ImportSpecifier(item)
                if item.import_kind == ImportOrExportKind::Value =>
            {
                (item.local.name.as_str(), item.imported.name().as_str())
            }
            ImportDeclarationSpecifier::ImportDefaultSpecifier(item) => {
                (item.local.name.as_str(), "default")
            }
            ImportDeclarationSpecifier::ImportNamespaceSpecifier(item) => {
                (item.local.name.as_str(), "*")
            }
            ImportDeclarationSpecifier::ImportSpecifier(_) => continue,
        };
        let value = if imported == "*" {
            temporary.clone()
        } else {
            format!("{temporary}[{}]", js_string(imported)?)
        };
        if goal == EvaluationGoal::HybridScript {
            output.push_str(&format!("globalThis[{}] = {value};\n", js_string(local)?));
        } else {
            output.push_str(&format!("const {local} = {value};\n"));
        }
    }
    Ok(())
}

fn import_options(declaration: &ImportDeclaration<'_>) -> Result<String> {
    let Some(with_clause) = &declaration.with_clause else {
        return Ok("void 0".to_owned());
    };
    let mut values = BTreeMap::new();
    for attribute in &with_clause.with_entries {
        let key = match &attribute.key {
            ImportAttributeKey::Identifier(identifier) => identifier.name.as_str(),
            ImportAttributeKey::StringLiteral(literal) => literal.value.as_str(),
        };
        if values
            .insert(key.to_owned(), attribute.value.value.to_string())
            .is_some()
        {
            bail!("duplicate import attribute {key:?}");
        }
    }
    serde_json::to_string(&values).map_err(anyhow::Error::from)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DynamicImportSite {
    computed: bool,
    offset: u32,
}

#[derive(Default)]
struct DynamicImportInventory {
    sites: Vec<DynamicImportSite>,
}

impl<'a> Visit<'a> for DynamicImportInventory {
    fn visit_import_expression(&mut self, expression: &ImportExpression<'a>) {
        self.sites.push(DynamicImportSite {
            computed: !matches!(&expression.source, Expression::StringLiteral(_)),
            offset: expression.span.start,
        });
        walk::walk_import_expression(self, expression);
    }
}

struct DynamicImportRewriter<'a> {
    rewrites: Vec<Rewrite>,
    original_sites: &'a [DynamicImportSite],
    next_site: usize,
    original_source: &'a str,
    intermediate: &'a str,
    source_label: &'a str,
    referrer: &'a str,
    failure: Option<anyhow::Error>,
}

impl<'a> Visit<'a> for DynamicImportRewriter<'_> {
    fn visit_import_expression(&mut self, expression: &ImportExpression<'a>) {
        if self.failure.is_some() {
            return;
        }
        let Some(site) = self.original_sites.get(self.next_site).copied() else {
            return;
        };
        self.next_site += 1;
        let nested_start = self.rewrites.len();
        walk::walk_import_expression(self, expression);
        if self.failure.is_some() {
            return;
        }
        let nested = self.rewrites.split_off(nested_start);
        let source = match apply_rewrites(self.intermediate, expression.source.span(), &nested) {
            Ok(source) => source,
            Err(error) => {
                self.failure = Some(error);
                return;
            }
        };
        let options = match &expression.options {
            Some(options) => match apply_rewrites(self.intermediate, options.span(), &nested) {
                Ok(options) => options,
                Err(error) => {
                    self.failure = Some(error);
                    return;
                }
            },
            None => "void 0".to_owned(),
        };
        let replacement = if site.computed {
            // Script sources have a SourceLabel but deliberately no SourceId,
            // so no candidate-table row can authorize a computed spelling.
            // Reject only here, after argument evaluation, never while a dead
            // site is parsed or lowered.
            // @ref LLP 0028#2-disposition-of-the-legacy-window-interop-shapes
            let (line, column) = source_line_column(self.original_source, site.offset);
            let message = format!(
                "computed import on a script surface has no candidate table at {}:{}:{}",
                self.source_label, line, column
            );
            format!(
                "(function({0}specifier, {0}options) {{ var {0}error = new TypeError({1}); {0}error.code = {2}; return Promise.reject({0}error); }})({3}, {4})",
                "__ibex_",
                js_string(&message).unwrap_or_else(|_| "\"computed import has no candidate table\"".to_owned()),
                js_string(SCRIPT_COMPUTED_IMPORT_ERROR_CODE).unwrap_or_else(|_| "\"IBEX_ERR_SCRIPT_COMPUTED_IMPORT_NO_CANDIDATES\"".to_owned()),
                source,
                options,
            )
        } else {
            format!(
                "globalThis['import']({source}, {options}, {})",
                js_string(self.referrer).unwrap_or_else(|_| "\"\"".to_owned())
            )
        };
        self.rewrites
            .push(Rewrite::new(expression.span, replacement));
    }
}

struct ImportMetaRewriter {
    rewrites: Vec<Rewrite>,
    goal: EvaluationGoal,
}

impl<'a> Visit<'a> for ImportMetaRewriter {
    fn visit_meta_property(&mut self, property: &MetaProperty<'a>) {
        if self.goal == EvaluationGoal::Module
            && property.meta.name == "import"
            && property.property.name == "meta"
        {
            self.rewrites.push(Rewrite::new(
                property.span,
                "globalThis.__exactImportMeta".to_owned(),
            ));
            return;
        }
        walk::walk_meta_property(self, property);
    }
}

#[derive(Debug, Clone)]
struct Rewrite {
    span: Span,
    text: String,
}

impl Rewrite {
    fn new(span: Span, text: String) -> Self {
        Self { span, text }
    }
}

fn apply_rewrites(source: &str, range: Span, rewrites: &[Rewrite]) -> Result<String> {
    let mut selected = rewrites
        .iter()
        .filter(|rewrite| rewrite.span.start >= range.start && rewrite.span.end <= range.end)
        .collect::<Vec<_>>();
    selected.sort_by_key(|rewrite| (rewrite.span.start, rewrite.span.end));
    for pair in selected.windows(2) {
        if pair[0].span.end > pair[1].span.start {
            bail!("overlapping Oxc script-frontend rewrites");
        }
    }
    let mut output = String::new();
    let mut cursor = range.start as usize;
    for rewrite in selected {
        output.push_str(&source[cursor..rewrite.span.start as usize]);
        output.push_str(&rewrite.text);
        cursor = rewrite.span.end as usize;
    }
    output.push_str(&source[cursor..range.end as usize]);
    Ok(output)
}

fn fresh_helper_prefix(program: &Program<'_>) -> String {
    #[derive(Default)]
    struct Names(Vec<String>);
    impl<'a> Visit<'a> for Names {
        fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
            self.0.push(identifier.name.to_string());
            walk::walk_identifier_reference(self, identifier);
        }
        fn visit_binding_identifier(&mut self, identifier: &oxc_ast::ast::BindingIdentifier<'a>) {
            self.0.push(identifier.name.to_string());
            walk::walk_binding_identifier(self, identifier);
        }
    }
    let mut names = Names::default();
    names.visit_program(program);
    for suffix in 0usize.. {
        let candidate = format!("__ibex_script_import_{suffix}_");
        if names.0.iter().all(|name| !name.starts_with(&candidate)) {
            return candidate;
        }
    }
    unreachable!()
}

fn source_line_column(source: &str, offset: u32) -> (usize, usize) {
    let offset = offset as usize;
    let prefix = &source[..offset.min(source.len())];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rfind('\n')
        .map_or(prefix.len() + 1, |newline| prefix.len() - newline);
    (line, column)
}

fn js_string(value: &str) -> Result<String> {
    serde_json::to_string(value).map_err(anyhow::Error::from)
}

pub fn has_top_level_await(source: &str, source_path: &Path) -> bool {
    analyze_script_syntax(source, source_path)
        .map(|analysis| analysis.has_top_level_await)
        .unwrap_or(false)
}

fn program_has_top_level_await(program: &Program<'_>) -> bool {
    let mut visitor = TopLevelAwaitVisitor::default();
    visitor.visit_program(program);
    visitor.found
}

#[derive(Default)]
struct TopLevelAwaitVisitor {
    function_depth: usize,
    found: bool,
}

impl<'a> Visit<'a> for TopLevelAwaitVisitor {
    fn visit_await_expression(&mut self, expression: &AwaitExpression<'a>) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn prepare(source: &str) -> PreparedEvaluation {
        prepare_hybrid_script(
            source,
            Path::new("ibex-evaluation.ts"),
            "ibex:evaluation",
            "",
        )
        .unwrap()
    }

    fn detects(source: &str) -> bool {
        has_top_level_await(source, Path::new("ibex-evaluation.js"))
    }

    #[test]
    fn detects_tla_inside_top_level_control_flow() {
        assert!(detects("await start();"));
        assert!(detects("if (ready) { await start(); }"));
        assert!(detects("for (const item of items) { await visit(item); }"));
    }

    #[test]
    fn excludes_await_under_function_boundaries() {
        assert!(!detects("async function run() { await start(); }"));
        assert!(!detects("const run = async () => await start();"));
        assert!(!detects("class C { async run() { await start(); } }"));
    }

    #[test]
    fn parser_ignores_non_syntax_mentions() {
        assert!(!detects("const text = 'await';"));
        assert!(!detects("const re = /(await)/;"));
        assert!(!detects("// await\nconst awaited = true;"));
    }

    #[test]
    fn uses_the_path_dialect() {
        let analysis = analyze_script_syntax(
            "const value: number = await Promise.resolve(1);",
            Path::new("ibex-evaluation.ts"),
        )
        .unwrap();
        assert!(analysis.has_top_level_await);
    }

    #[test]
    fn pinned_oxc_has_no_direct_hybrid_script_goal() {
        let allocator = Allocator::default();
        let extended = "import value from './value.js'; await value();";
        let script = Parser::new(&allocator, extended, SourceType::script()).parse();
        assert!(
            !script.diagnostics.is_empty(),
            "plain Script goal must not silently become the LLP 0024 hybrid goal"
        );
        let allocator = Allocator::default();
        let mut hybrid = Parser::new(&allocator, extended, SourceType::mjs()).parse();
        assert!(hybrid.diagnostics.is_empty(), "{:?}", hybrid.diagnostics);
        hybrid.program.source_type = SourceType::script();
        let hybrid_semantic = SemanticBuilder::new()
            .with_check_syntax_error(true)
            .build(&hybrid.program);
        assert!(
            hybrid_semantic.diagnostics.len() == 1
                && hybrid_semantic.diagnostics[0].message
                    == "Cannot use import statement outside a module",
            "module parse plus Script semantic validation must isolate only the admitted import diagnostic: {:?}",
            hybrid_semantic.diagnostics
        );

        for sloppy_only in [
            "var octal = 010;",
            "delete unqualified;",
            "function duplicate(value, value) {}",
            "function nested() { var await = 1; return await; }",
        ] {
            let allocator = Allocator::default();
            let mut module = Parser::new(&allocator, sloppy_only, SourceType::mjs()).parse();
            assert!(
                module.diagnostics.is_empty(),
                "Oxc must retain the sloppy-only AST for the hybrid feasibility path: {sloppy_only}; {:?}",
                module.diagnostics
            );
            module.program.source_type = SourceType::script();
            let semantic = SemanticBuilder::new()
                .with_check_syntax_error(true)
                .build(&module.program);
            assert!(
                semantic.diagnostics.is_empty(),
                "Script semantic validation rejected sloppy-only source: {sloppy_only}; {:?}",
                semantic.diagnostics
            );
        }
    }

    #[test]
    fn hybrid_projection_preserves_script_early_errors() {
        let admitted = analyze_script_syntax(
            "import value from './value.js'; var octal = 010; delete unqualified; function duplicate(value, value) {} await value();",
            Path::new("ibex-evaluation.js"),
        )
        .unwrap();
        assert!(admitted.has_top_level_await);

        for refused in [
            "export const value = 1;",
            "var await = 1;",
            "'use strict'; var octal = 010;",
            "'use strict'; delete unqualified;",
            "'use strict'; function duplicate(value, value) {}",
        ] {
            assert!(
                analyze_script_syntax(refused, Path::new("ibex-evaluation.js")).is_err(),
                "hybrid projection must retain Script early errors: {refused}"
            );
        }
    }

    #[test]
    fn frontend_strips_types_and_preserves_script_semantics() {
        let prepared = prepare(
            "var octal = 010; delete unqualified; function duplicate(value, value) {} const answer: number = 42;",
        );
        assert!(!prepared.body.contains(": number"), "{}", prepared.body);
        assert!(prepared.body.contains("var octal = 8"), "{}", prepared.body);
        assert!(
            prepared.body.contains("delete unqualified"),
            "{}",
            prepared.body
        );
        assert!(!prepared.needs_async_wrapper());
    }

    #[test]
    fn frontend_hoists_static_imports_from_ast() {
        let prepared = prepare(
            "console.log(answer); import value, { answer as renamed } from './dep.js'; import * as ns from './ns.js';",
        );
        assert!(prepared.has_static_imports);
        assert!(prepared.preamble.contains("await globalThis['import']"));
        assert!(prepared.preamble.contains("globalThis[\"value\"]"));
        assert!(prepared.preamble.contains("globalThis[\"renamed\"]"));
        assert!(prepared.preamble.contains("globalThis[\"ns\"]"));
        assert!(!prepared.body.contains("import "), "{}", prepared.body);
        assert!(prepared.body.contains("console.log(answer)"));
    }

    #[test]
    fn frontend_uses_ast_spans_for_dynamic_imports() {
        let prepared = prepare(
            "const text = 'import(untouched)'; if (false) import(name()); const literal = import('./dep.js');",
        );
        assert!(
            prepared.body.contains("import(untouched)"),
            "{}",
            prepared.body
        );
        assert!(
            prepared.body.contains(SCRIPT_COMPUTED_IMPORT_ERROR_CODE),
            "{}",
            prepared.body
        );
        assert!(
            prepared.body.contains("})(name(), void 0)"),
            "{}",
            prepared.body
        );
        assert!(
            prepared
                .body
                .contains("globalThis['import'](\"./dep.js\", void 0, \"\")"),
            "{}",
            prepared.body
        );
    }

    #[test]
    fn frontend_rewrites_nested_dynamic_imports_without_generation_failure() {
        let prepared = prepare("if (false) import(import('./name.js'));");
        assert_eq!(
            prepared
                .body
                .matches(SCRIPT_COMPUTED_IMPORT_ERROR_CODE)
                .count(),
            1,
            "{}",
            prepared.body
        );
        assert_eq!(
            prepared.body.matches("globalThis['import']").count(),
            1,
            "{}",
            prepared.body
        );
    }

    #[test]
    fn frontend_reports_expression_completion_after_typescript_lowering() {
        let prepared = prepare("({ answer: 42 } satisfies { answer: number })");
        assert_eq!(prepared.expression.as_deref(), Some("({ answer: 42 })"));
    }

    #[test]
    fn program_stdin_uses_module_bindings_and_import_meta_projection() {
        let prepared = prepare_module_entry(
            "import { value } from './dep.js'; console.log(value, import.meta.url);",
            Path::new("ibex-stdin.ts"),
            "ibex:stdin",
            "",
        )
        .unwrap();
        assert_eq!(prepared.goal, EvaluationGoal::Module);
        assert!(prepared.preamble.contains("const value ="));
        assert!(!prepared.preamble.contains("globalThis[\"value\"]"));
        assert!(prepared.body.contains("globalThis.__exactImportMeta.url"));
    }
}
