//! AST-directed lowering for persistent structured sessions.
//!
//! The generated wrapper is a native invocation target, not JavaScript-visible
//! state. Its sole parameter is a hygienic private binding populated by the
//! Hermes adapter with checked-cell host objects. No hook is installed on the
//! realm global and no dynamic source constructor participates in lowering.
//! @ref LLP 0024#71-the-environment-a-modified-globalenvironmentrecord — every
//! free session reference is a late, checked lookup by name.
//! @ref LLP 0024#6-evaluation-outcomes-and-the-abi — completion travels out of
//! band and async settlement returns only a private non-thenable sentinel.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use swc_common::comments::SingleThreadedComments;
use swc_common::sync::Lrc;
use swc_common::util::take::Take;
use swc_common::{FileName, Globals, Mark, SourceMap, SyntaxContext, DUMMY_SP, GLOBALS};
use swc_ecma_ast::*;
use swc_ecma_codegen::text_writer::JsWriter;
use swc_ecma_codegen::Emitter;
use swc_ecma_parser::error::SyntaxError as SwcSyntaxError;
use swc_ecma_parser::{lexer::Lexer, Parser, StringInput, Syntax};
use swc_ecma_transforms_base::fixer::fixer;
use swc_ecma_transforms_base::helpers::{inject_helpers, Helpers, HELPERS};
use swc_ecma_transforms_base::hygiene::hygiene;
use swc_ecma_transforms_base::resolver;
use swc_ecma_transforms_react as react;
use swc_ecma_transforms_typescript::typescript;
use swc_ecma_visit::{VisitMut, VisitMutWith, VisitWith};
use thiserror::Error;

use super::evaluation::{ParserDialect, ProgramSourceRequest, SourceGoal, SourceRole};
use super::import_grants::{
    validate_and_strip_runtime_import_options, validate_static_import_attributes,
    ImportOptionRefusal,
};
use super::session_syntax::{
    analyze_source, mask_static_imports, DeclarationOrigin, SessionDeclaration,
    SessionDeclarationKind, StaticImport, StaticImportBindingKind, SyntaxFrontendError,
    SyntaxFrontendResult, SyntaxRequest,
};

/// Versioned contract between this AST lowering and the private native hook
/// implementation. It is independent of the public result ABI version.
pub const SESSION_LOWERING_PROTOCOL_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LoweredDeclarationKind {
    Var = 1,
    Function = 2,
    Let = 3,
    Const = 4,
    Class = 5,
    Import = 6,
}

impl From<SessionDeclarationKind> for LoweredDeclarationKind {
    fn from(value: SessionDeclarationKind) -> Self {
        match value {
            SessionDeclarationKind::Var => Self::Var,
            SessionDeclarationKind::Function => Self::Function,
            SessionDeclarationKind::Let => Self::Let,
            SessionDeclarationKind::Const => Self::Const,
            SessionDeclarationKind::Class => Self::Class,
            SessionDeclarationKind::Import => Self::Import,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoweredDeclaration {
    pub name: Arc<str>,
    pub kind: LoweredDeclarationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LoweredStaticImportBindingKind {
    Default = 1,
    Named = 2,
    Namespace = 3,
}

impl From<StaticImportBindingKind> for LoweredStaticImportBindingKind {
    fn from(value: StaticImportBindingKind) -> Self {
        match value {
            StaticImportBindingKind::Default => Self::Default,
            StaticImportBindingKind::Named => Self::Named,
            StaticImportBindingKind::Namespace => Self::Namespace,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoweredStaticImportBinding {
    /// `None` is a re-export validation row. Its Get still occurs during
    /// phase 4, but no persistent session cell is published.
    pub local: Option<Arc<str>>,
    pub imported: Option<Arc<str>>,
    pub kind: LoweredStaticImportBindingKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoweredStaticImport {
    pub specifier: Arc<str>,
    pub bindings: Arc<[LoweredStaticImportBinding]>,
}

/// Engine-ready program produced only by the checked AST pipeline.
#[derive(Debug)]
pub struct LoweredSessionProgram {
    source: Arc<str>,
    source_map: Arc<[u8]>,
    declarations: Arc<[LoweredDeclaration]>,
    static_imports: Arc<[LoweredStaticImport]>,
    asynchronous: bool,
    strict: bool,
}

impl LoweredSessionProgram {
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn source_map(&self) -> &[u8] {
        &self.source_map
    }

    pub fn declarations(&self) -> &[LoweredDeclaration] {
        &self.declarations
    }

    pub fn static_imports(&self) -> &[LoweredStaticImport] {
        &self.static_imports
    }

    pub fn is_asynchronous(&self) -> bool {
        self.asynchronous
    }

    pub fn is_strict(&self) -> bool {
        self.strict
    }
}

#[derive(Debug, Error)]
pub enum SessionLoweringError {
    #[error(transparent)]
    Syntax(#[from] SyntaxFrontendError),
    #[error("JSON data has no JavaScript session lowering")]
    JsonData,
    #[error("module-goal dependency lowering is not wired to the asynchronous module graph")]
    ModuleGoalUnavailable,
    #[error("IBEX_UNSUPPORTED_SCRIPT_EXTENSIONS_GOAL: the pinned parser cannot prove Script+extensions semantics for this input")]
    UnsupportedScriptExtensionsGoal,
    #[error("runtime import attributes reserve the build-time grant key {key:?}")]
    ReservedImportGrantAttribute { key: String },
    #[error("runtime import options must be a recursively data-only literal")]
    ImportOptionsNotDataOnly,
    #[error("module entry exports are not available through the session-cell lowering")]
    ModuleExportUnavailable,
    #[error("direct or indirect eval syntax is closed in a persistent session")]
    EvalClosed,
    #[error("dynamic Function construction is closed in a persistent session")]
    FunctionConstructorClosed,
    #[error("unsupported session declaration pattern: {0}")]
    UnsupportedDeclarationPattern(&'static str),
    #[error("session lowering failed to parse checked source: {0}")]
    Parser(String),
    #[error("session lowering failed to emit JavaScript: {0}")]
    Emitter(String),
    #[error("session lowering emitted non-UTF-8 bytes")]
    NonUtf8Output,
}

fn parser_syntax(dialect: ParserDialect) -> Syntax {
    super::session_syntax::syntax_for_lowering(dialect)
}

fn script_is_strict(script: &Script) -> bool {
    script
        .body
        .iter()
        .take_while(|statement| statement.can_precede_directive())
        .any(Stmt::is_use_strict)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AnnexBFunctionKey {
    start: usize,
    end: usize,
}

impl AnnexBFunctionKey {
    fn from_ident(identifier: &Ident, source_start: u32) -> Option<Self> {
        let start = identifier.span.lo.0.checked_sub(source_start)? as usize;
        let end = identifier.span.hi.0.checked_sub(source_start)? as usize;
        Some(Self { start, end })
    }
}

#[derive(Clone, Debug)]
struct AnnexBFunctionPlan {
    name: String,
    publish: bool,
}

#[derive(Clone, Debug, Default)]
struct AnnexBPlan {
    source_start: u32,
    functions: HashMap<AnnexBFunctionKey, AnnexBFunctionPlan>,
}

impl AnnexBPlan {
    fn build(
        script: &Script,
        declarations: &[SessionDeclaration],
        source_start: u32,
    ) -> Result<Self, SessionLoweringError> {
        let candidates = declarations
            .iter()
            .filter(|declaration| declaration.origin == DeclarationOrigin::AnnexB)
            .map(|declaration| {
                (
                    AnnexBFunctionKey {
                        start: declaration.range.start,
                        end: declaration.range.end,
                    },
                    declaration.name.clone(),
                )
            })
            .collect::<HashMap<_, _>>();
        if candidates.is_empty() {
            return Ok(Self {
                source_start,
                functions: HashMap::new(),
            });
        }

        let mut imported_lexicals = HashSet::new();
        for declaration in declarations {
            if declaration.kind == SessionDeclarationKind::Import {
                imported_lexicals.insert(declaration.name.clone());
            }
        }
        let mut builder = AnnexBPlanBuilder {
            source_start,
            candidates: &candidates,
            functions: HashMap::new(),
        };
        builder.visit_statement_list(&script.body, &imported_lexicals);
        if builder.functions.len() != candidates.len() {
            return Err(SessionLoweringError::UnsupportedDeclarationPattern(
                "Annex-B function placement",
            ));
        }
        Ok(Self {
            source_start,
            functions: builder.functions,
        })
    }

    fn function(&self, declaration: &FnDecl) -> Option<&AnnexBFunctionPlan> {
        let key = AnnexBFunctionKey::from_ident(&declaration.ident, self.source_start)?;
        self.functions.get(&key)
    }

    fn publishes(&self, declaration: &SessionDeclaration) -> bool {
        self.functions
            .get(&AnnexBFunctionKey {
                start: declaration.range.start,
                end: declaration.range.end,
            })
            .is_some_and(|function| function.publish)
    }
}

struct AnnexBPlanBuilder<'a> {
    source_start: u32,
    candidates: &'a HashMap<AnnexBFunctionKey, String>,
    functions: HashMap<AnnexBFunctionKey, AnnexBFunctionPlan>,
}

impl AnnexBPlanBuilder<'_> {
    fn visit_statement_list(&mut self, statements: &[Stmt], inherited: &HashSet<String>) {
        let mut blocked = inherited.clone();
        collect_direct_lexical_names(statements, &mut blocked);
        for statement in statements {
            self.visit_statement(statement, &blocked);
        }
    }

    fn visit_statement(&mut self, statement: &Stmt, blocked: &HashSet<String>) {
        if let Stmt::Decl(Decl::Fn(declaration)) = statement {
            if self.record_function(declaration, blocked) {
                return;
            }
            // A top-level ordinary function is a scope boundary for this plan.
            return;
        }
        match statement {
            Stmt::Block(block) => self.visit_statement_list(&block.stmts, blocked),
            Stmt::If(statement) => {
                self.visit_statement(&statement.cons, blocked);
                if let Some(alternate) = &statement.alt {
                    self.visit_statement(alternate, blocked);
                }
            }
            Stmt::Labeled(statement) => self.visit_statement(&statement.body, blocked),
            Stmt::While(statement) => self.visit_statement(&statement.body, blocked),
            Stmt::DoWhile(statement) => self.visit_statement(&statement.body, blocked),
            Stmt::For(statement) => {
                let mut loop_blocked = blocked.clone();
                if let Some(VarDeclOrExpr::VarDecl(declaration)) = &statement.init {
                    if declaration.kind != VarDeclKind::Var {
                        collect_var_bound_names(declaration, &mut loop_blocked);
                    }
                }
                self.visit_statement(&statement.body, &loop_blocked);
            }
            Stmt::ForIn(statement) => {
                let mut loop_blocked = blocked.clone();
                collect_for_head_lexical_names(&statement.left, &mut loop_blocked);
                self.visit_statement(&statement.body, &loop_blocked);
            }
            Stmt::ForOf(statement) => {
                let mut loop_blocked = blocked.clone();
                collect_for_head_lexical_names(&statement.left, &mut loop_blocked);
                self.visit_statement(&statement.body, &loop_blocked);
            }
            Stmt::Switch(statement) => self.visit_switch(statement, blocked),
            Stmt::Try(statement) => {
                self.visit_statement_list(&statement.block.stmts, blocked);
                if let Some(handler) = &statement.handler {
                    let mut catch_blocked = blocked.clone();
                    // Annex B.3.4 admits the legacy `catch (f) { var f }`
                    // spelling only for a simple catch parameter. Replacing a
                    // nested block function by `var f` still conflicts with a
                    // destructuring catch parameter.
                    if let Some(parameter) = &handler.param {
                        if !matches!(parameter, Pat::Ident(_)) {
                            collect_pattern_bound_names(parameter, &mut catch_blocked);
                        }
                    }
                    self.visit_statement_list(&handler.body.stmts, &catch_blocked);
                }
                if let Some(finalizer) = &statement.finalizer {
                    self.visit_statement_list(&finalizer.stmts, blocked);
                }
            }
            Stmt::With(statement) => self.visit_statement(&statement.body, blocked),
            Stmt::Decl(_)
            | Stmt::Expr(_)
            | Stmt::Empty(_)
            | Stmt::Debugger(_)
            | Stmt::Return(_)
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Throw(_) => {}
        }
    }

    fn visit_switch(&mut self, statement: &SwitchStmt, inherited: &HashSet<String>) {
        let mut blocked = inherited.clone();
        for case in &statement.cases {
            collect_direct_lexical_names(&case.cons, &mut blocked);
        }
        for case in &statement.cases {
            for statement in &case.cons {
                self.visit_statement(statement, &blocked);
            }
        }
    }

    fn record_function(&mut self, declaration: &FnDecl, blocked: &HashSet<String>) -> bool {
        let Some(key) = AnnexBFunctionKey::from_ident(&declaration.ident, self.source_start) else {
            return false;
        };
        let Some(name) = self.candidates.get(&key) else {
            return false;
        };
        self.functions.insert(
            key,
            AnnexBFunctionPlan {
                name: name.clone(),
                publish: !blocked.contains(name)
                    && !declaration.function.is_async
                    && !declaration.function.is_generator,
            },
        );
        true
    }
}

fn collect_direct_lexical_names(statements: &[Stmt], output: &mut HashSet<String>) {
    for statement in statements {
        match statement {
            Stmt::Decl(Decl::Var(declaration)) if declaration.kind != VarDeclKind::Var => {
                collect_var_bound_names(declaration, output);
            }
            Stmt::Decl(Decl::Class(declaration)) if !declaration.declare => {
                output.insert(declaration.ident.sym.to_string());
            }
            Stmt::Decl(Decl::Using(declaration)) => {
                for declarator in &declaration.decls {
                    collect_pattern_bound_names(&declarator.name, output);
                }
            }
            _ => {}
        }
    }
}

fn collect_var_bound_names(declaration: &VarDecl, output: &mut HashSet<String>) {
    for declarator in &declaration.decls {
        collect_pattern_bound_names(&declarator.name, output);
    }
}

fn collect_for_head_lexical_names(head: &ForHead, output: &mut HashSet<String>) {
    match head {
        ForHead::VarDecl(declaration) if declaration.kind != VarDeclKind::Var => {
            collect_var_bound_names(declaration, output);
        }
        ForHead::UsingDecl(declaration) => {
            for declarator in &declaration.decls {
                collect_pattern_bound_names(&declarator.name, output);
            }
        }
        ForHead::VarDecl(_) | ForHead::Pat(_) => {}
    }
}

fn collect_pattern_bound_names(pattern: &Pat, output: &mut HashSet<String>) {
    match pattern {
        Pat::Ident(binding) => {
            output.insert(binding.id.sym.to_string());
        }
        Pat::Array(array) => {
            for element in array.elems.iter().flatten() {
                collect_pattern_bound_names(element, output);
            }
        }
        Pat::Object(object) => {
            for property in &object.props {
                match property {
                    ObjectPatProp::KeyValue(property) => {
                        collect_pattern_bound_names(&property.value, output)
                    }
                    ObjectPatProp::Assign(property) => {
                        output.insert(property.key.id.sym.to_string());
                    }
                    ObjectPatProp::Rest(property) => {
                        collect_pattern_bound_names(&property.arg, output)
                    }
                }
            }
        }
        Pat::Assign(assignment) => collect_pattern_bound_names(&assignment.left, output),
        Pat::Rest(rest) => collect_pattern_bound_names(&rest.arg, output),
        Pat::Invalid(_) | Pat::Expr(_) => {}
    }
}

#[cfg(test)]
fn parse_checked_script(
    source: &str,
    dialect: ParserDialect,
    label: &str,
) -> Result<(Lrc<SourceMap>, SingleThreadedComments, Script), SessionLoweringError> {
    let source_map: Lrc<SourceMap> = Default::default();
    let file = source_map.new_source_file(
        Lrc::new(FileName::Custom(label.to_owned())),
        source.to_owned(),
    );
    let comments = SingleThreadedComments::default();
    let lexer = Lexer::new(
        parser_syntax(dialect),
        EsVersion::Es2022,
        StringInput::from(&*file),
        Some(&comments),
    );
    let mut parser = Parser::new_from(lexer);
    let script = parser
        .parse_script()
        .map_err(|error| SessionLoweringError::Parser(error.kind().msg().into_owned()))?;
    let errors = parser.take_errors();
    if let Some(error) = errors.first() {
        return Err(SessionLoweringError::Parser(
            error.kind().msg().into_owned(),
        ));
    }
    Ok((source_map, comments, script))
}

fn parse_checked_extension_script(
    source: &str,
    imports: &[StaticImport],
    dialect: ParserDialect,
    label: &str,
) -> Result<(Lrc<SourceMap>, SingleThreadedComments, Script), SessionLoweringError> {
    let masked = mask_static_imports(source, imports);
    let source_map: Lrc<SourceMap> = Default::default();
    let file = source_map.new_source_file(Lrc::new(FileName::Custom(label.to_owned())), masked);
    let comments = SingleThreadedComments::default();
    let lexer = Lexer::new(
        parser_syntax(dialect),
        EsVersion::Es2022,
        StringInput::from(&*file),
        Some(&comments),
    );
    let mut parser = Parser::new_from(lexer);
    let script = parser
        .parse_script()
        .map_err(|error| SessionLoweringError::Parser(error.kind().msg().into_owned()))?;
    if let Some(error) = parser
        .take_errors()
        .into_iter()
        .find(|error| !matches!(error.kind(), SwcSyntaxError::TopLevelAwaitInScript))
    {
        return Err(SessionLoweringError::Parser(
            error.kind().msg().into_owned(),
        ));
    }
    Ok((source_map, comments, script))
}

fn parse_checked_module(
    source: &str,
    dialect: ParserDialect,
    label: &str,
    allow_script_only_diagnostics: bool,
) -> Result<(Lrc<SourceMap>, SingleThreadedComments, Module), SessionLoweringError> {
    let source_map: Lrc<SourceMap> = Default::default();
    let file = source_map.new_source_file(
        Lrc::new(FileName::Custom(label.to_owned())),
        source.to_owned(),
    );
    let comments = SingleThreadedComments::default();
    let lexer = Lexer::new(
        parser_syntax(dialect),
        EsVersion::Es2022,
        StringInput::from(&*file),
        Some(&comments),
    );
    let mut parser = Parser::new_from(lexer);
    let module = parser
        .parse_module()
        .map_err(|error| SessionLoweringError::Parser(error.kind().msg().into_owned()))?;
    let errors = parser.take_errors();
    if !allow_script_only_diagnostics {
        if let Some(error) = errors.first() {
            return Err(SessionLoweringError::Parser(
                error.kind().msg().into_owned(),
            ));
        }
    }
    Ok((source_map, comments, module))
}

impl From<ImportOptionRefusal> for SessionLoweringError {
    fn from(value: ImportOptionRefusal) -> Self {
        match value {
            ImportOptionRefusal::ReservedGrantKey(key) => {
                Self::ReservedImportGrantAttribute { key }
            }
            ImportOptionRefusal::NonDataOnly => Self::ImportOptionsNotDataOnly,
        }
    }
}

/// Validate and lower an authenticated program request. The request itself is
/// retained by the caller; this function cannot mint or alter credentials.
pub fn lower_program(
    request: &ProgramSourceRequest,
    source: &str,
    source_label: &str,
) -> Result<LoweredSessionProgram, SessionLoweringError> {
    lower_checked_source_with_module_meta(
        SyntaxRequest {
            dialect: request.dialect(),
            goal: request.goal(),
            role: request.role(),
        },
        source,
        source_label,
        request.is_main(),
        request.authenticated_file_virtual_path(),
    )
}

#[cfg(test)]
fn lower_checked_source(
    syntax_request: SyntaxRequest,
    source: &str,
    source_label: &str,
) -> Result<LoweredSessionProgram, SessionLoweringError> {
    lower_checked_source_with_module_meta(syntax_request, source, source_label, false, None)
}

fn lower_checked_source_with_module_meta(
    syntax_request: SyntaxRequest,
    source: &str,
    source_label: &str,
    is_main: bool,
    virtual_path: Option<&str>,
) -> Result<LoweredSessionProgram, SessionLoweringError> {
    if syntax_request.role != SourceRole::Entry {
        return Err(SessionLoweringError::ModuleGoalUnavailable);
    }
    let analysis = match analyze_source(syntax_request, source)? {
        SyntaxFrontendResult::Ready(analysis) => analysis,
        SyntaxFrontendResult::UnsupportedGoal(_) => {
            return Err(SessionLoweringError::UnsupportedScriptExtensionsGoal)
        }
    };
    let (source_map, comments, mut program, strict) = match syntax_request.goal {
        SourceGoal::ScriptWithExtensions => {
            if !analysis.outline.static_imports.is_empty() {
                let (_, _, module) =
                    parse_checked_module(source, syntax_request.dialect, source_label, true)?;
                validate_static_import_attributes(&module)?;
            }
            let (source_map, comments, script) = parse_checked_extension_script(
                source,
                &analysis.outline.static_imports,
                syntax_request.dialect,
                source_label,
            )?;
            let strict = script_is_strict(&script);
            (source_map, comments, Program::Script(script), strict)
        }
        SourceGoal::Module => {
            let (source_map, comments, module) =
                parse_checked_module(source, syntax_request.dialect, source_label, false)?;
            validate_static_import_attributes(&module)?;
            (source_map, comments, Program::Module(module), true)
        }
    };
    let annex_b_plan = match &program {
        Program::Script(script) if !strict => AnnexBPlan::build(
            script,
            &analysis.outline.declarations,
            source_map.lookup_source_file(script.span.lo).start_pos.0,
        )?,
        Program::Script(script) => AnnexBPlan {
            source_start: source_map.lookup_source_file(script.span.lo).start_pos.0,
            functions: HashMap::new(),
        },
        Program::Module(_) => AnnexBPlan::default(),
    };
    // @ref LLP 0024#73-evaluation-phases-collisions-and-the-cross-kind-matrix
    // — Annex-B's outer publication participates in GDI as `var`, while the
    // block-local declaration remains a lexical function initialized by the
    // engine when control enters its block.
    let declarations = analysis
        .outline
        .declarations
        .iter()
        .filter_map(|declaration| {
            if declaration.origin == DeclarationOrigin::AnnexB {
                return annex_b_plan
                    .publishes(declaration)
                    .then(|| LoweredDeclaration {
                        name: Arc::from(declaration.name.as_str()),
                        kind: LoweredDeclarationKind::Var,
                    });
            }
            Some(LoweredDeclaration {
                name: Arc::from(declaration.name.as_str()),
                kind: declaration.kind.into(),
            })
        })
        .collect::<Vec<_>>();
    let globals = Globals::new();
    GLOBALS.set(&globals, || {
        HELPERS.set(&Helpers::new(false), || {
            lower_parsed_program(
                source_map,
                comments,
                &mut program,
                declarations,
                &annex_b_plan,
                &analysis.outline.static_imports,
                ProgramLoweringOptions {
                    asynchronous: analysis.outline.top_level_await,
                    strict,
                    source_goal: syntax_request.goal,
                    source_label,
                    is_main,
                    virtual_path,
                    is_jsx: matches!(
                        syntax_request.dialect,
                        ParserDialect::JavaScriptJsx | ParserDialect::TypeScriptJsx
                    ),
                },
            )
        })
    })
}

fn reject_closed_dynamic_code_in_program(
    program: &Program,
    unresolved_ctxt: SyntaxContext,
) -> Result<(), SessionLoweringError> {
    let mut visitor = DynamicCodeVisitor {
        unresolved_ctxt,
        ..Default::default()
    };
    program.visit_with(&mut visitor);
    if visitor.eval_reference {
        return Err(SessionLoweringError::EvalClosed);
    }
    if visitor.function_constructor_reference {
        return Err(SessionLoweringError::FunctionConstructorClosed);
    }
    Ok(())
}

fn static_computed_property_name(expression: &Expr) -> Option<&str> {
    match expression {
        Expr::Lit(Lit::Str(string)) => string.value.as_wtf8().as_str(),
        Expr::Paren(paren) => static_computed_property_name(&paren.expr),
        _ => None,
    }
}

fn static_member_property_name(property: &MemberProp) -> Option<&str> {
    match property {
        MemberProp::Ident(identifier) => Some(identifier.sym.as_ref()),
        MemberProp::Computed(computed) => static_computed_property_name(&computed.expr),
        MemberProp::PrivateName(_) => None,
    }
}

fn static_pattern_property_name(property: &PropName) -> Option<&str> {
    match property {
        PropName::Ident(identifier) => Some(identifier.sym.as_ref()),
        PropName::Str(string) => string.value.as_wtf8().as_str(),
        PropName::Computed(computed) => static_computed_property_name(&computed.expr),
        PropName::Num(_) | PropName::BigInt(_) => None,
    }
}

fn is_realm_global_name(name: &str) -> bool {
    matches!(name, "globalThis" | "global" | "self" | "window")
}

fn is_realm_global_expression(expression: &Expr, unresolved_ctxt: SyntaxContext) -> bool {
    match expression {
        Expr::Ident(identifier) => {
            identifier.ctxt == unresolved_ctxt && is_realm_global_name(identifier.sym.as_ref())
        }
        Expr::Paren(paren) => is_realm_global_expression(&paren.expr, unresolved_ctxt),
        Expr::Seq(sequence) => sequence
            .exprs
            .last()
            .is_some_and(|expression| is_realm_global_expression(expression, unresolved_ctxt)),
        Expr::Member(member) => {
            is_realm_global_expression(&member.obj, unresolved_ctxt)
                && static_member_property_name(&member.prop).is_some_and(is_realm_global_name)
        }
        Expr::Cond(conditional) => {
            is_realm_global_expression(&conditional.cons, unresolved_ctxt)
                && is_realm_global_expression(&conditional.alt, unresolved_ctxt)
        }
        _ => false,
    }
}

#[derive(Default)]
struct DynamicCodeVisitor {
    unresolved_ctxt: SyntaxContext,
    eval_reference: bool,
    function_constructor_reference: bool,
}

impl DynamicCodeVisitor {
    fn record_evaluator_name(&mut self, name: &str) {
        if name == "eval" {
            self.eval_reference = true;
        } else if name == "Function" {
            self.function_constructor_reference = true;
        }
    }

    fn inspect_global_object_pattern(&mut self, pattern: &ObjectPat) {
        for property in &pattern.props {
            match property {
                ObjectPatProp::KeyValue(property) => {
                    if let Some(name) = static_pattern_property_name(&property.key) {
                        self.record_evaluator_name(name);
                        if is_realm_global_name(name) {
                            if let Pat::Object(object) = &*property.value {
                                self.inspect_global_object_pattern(object);
                            }
                        }
                    }
                }
                ObjectPatProp::Assign(property) => {
                    self.record_evaluator_name(property.key.id.sym.as_ref());
                }
                ObjectPatProp::Rest(_) => {}
            }
        }
    }
}

impl swc_ecma_visit::Visit for DynamicCodeVisitor {
    fn visit_ident(&mut self, identifier: &Ident) {
        if identifier.ctxt != self.unresolved_ctxt {
            return;
        }
        if identifier.sym == *"eval" {
            self.eval_reference = true;
        } else if identifier.sym == *"Function" {
            self.function_constructor_reference = true;
        }
    }

    fn visit_member_expr(&mut self, member: &MemberExpr) {
        if is_realm_global_expression(&member.obj, self.unresolved_ctxt) {
            if let Some(name) = static_member_property_name(&member.prop) {
                self.record_evaluator_name(name);
            }
        }
        member.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if declarator.init.as_deref().is_some_and(|initializer| {
            is_realm_global_expression(initializer, self.unresolved_ctxt)
        }) {
            if let Pat::Object(object) = &declarator.name {
                self.inspect_global_object_pattern(object);
            }
        }
        declarator.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if assignment.op == AssignOp::Assign
            && is_realm_global_expression(&assignment.right, self.unresolved_ctxt)
        {
            if let AssignTarget::Pat(AssignTargetPat::Object(object)) = &assignment.left {
                self.inspect_global_object_pattern(object);
            }
        }
        assignment.visit_children_with(self);
    }
}

struct ProgramLoweringOptions<'a> {
    asynchronous: bool,
    strict: bool,
    source_goal: SourceGoal,
    source_label: &'a str,
    is_main: bool,
    virtual_path: Option<&'a str>,
    is_jsx: bool,
}

fn lower_parsed_program(
    source_map: Lrc<SourceMap>,
    comments: SingleThreadedComments,
    program: &mut Program,
    declarations: Vec<LoweredDeclaration>,
    annex_b_plan: &AnnexBPlan,
    static_imports: &[StaticImport],
    options: ProgramLoweringOptions<'_>,
) -> Result<LoweredSessionProgram, SessionLoweringError> {
    let ProgramLoweringOptions {
        asynchronous,
        strict,
        source_goal,
        source_label,
        is_main,
        virtual_path,
        is_jsx,
    } = options;
    let unresolved_mark = Mark::new();
    let top_level_mark = Mark::new();
    let unresolved_ctxt = SyntaxContext::empty().apply_mark(unresolved_mark);
    let top_level_ctxt = SyntaxContext::empty().apply_mark(top_level_mark);
    let hook = Ident::new_private("__ibex_session_hooks".into(), DUMMY_SP);
    let completion_has = Ident::new_private("__ibex_completion_has".into(), DUMMY_SP);
    let completion_value = Ident::new_private("__ibex_completion_value".into(), DUMMY_SP);

    program.mutate(resolver(unresolved_mark, top_level_mark, true));
    if !annex_b_plan.functions.is_empty() {
        if let Program::Script(script) = program {
            AnnexBPublicationLowering {
                plan: annex_b_plan,
                hook: hook.clone(),
            }
            .lower_script(script);
        }
    }
    validate_and_strip_runtime_import_options(program, unresolved_ctxt)?;
    program.mutate(typescript(
        Default::default(),
        unresolved_mark,
        top_level_mark,
    ));
    if is_jsx {
        program.mutate(react::react(
            source_map.clone(),
            Some(&comments),
            react::Options::default(),
            top_level_mark,
            unresolved_mark,
        ));
    }
    // Resolver marks distinguish an evaluator reference from a harmless local
    // binding or property spelling. Run after TypeScript/JSX lowering so names
    // that cannot survive to runtime (type positions and intrinsic JSX tags)
    // cannot be mistaken for JavaScript-reachable evaluator access.
    // @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
    // — only the JavaScript-reachable global evaluators remain closed.
    reject_closed_dynamic_code_in_program(program, unresolved_ctxt)?;
    program.mutate(inject_helpers(unresolved_mark));

    if source_goal == SourceGoal::Module {
        program.visit_mut_with(&mut ImportMetaLowering {
            source_label: source_label.to_owned(),
            is_main,
            virtual_path: virtual_path.map(str::to_owned),
        });
        program.visit_mut_with(&mut ModuleTopLevelThisLowering);
    }

    let mut script = program_to_session_script(program.take())?;
    if source_goal == SourceGoal::Module && !script_is_strict(&script) {
        script.body.insert(0, use_strict_directive());
    };
    let mut lowering = ReferenceLowering {
        unresolved_ctxt,
        top_level_ctxt,
        hook: hook.clone(),
        strict,
    };
    script.visit_mut_with(&mut lowering);

    let mut statement_lowering = StatementLowering {
        hook: hook.clone(),
        completion_has: completion_has.clone(),
        completion_value: completion_value.clone(),
        unresolved_ctxt,
        top_level_ctxt,
        strict,
        function_initializers: Vec::new(),
    };
    let body = statement_lowering.lower_root(script.body)?;
    let wrapper = wrapper_expression(
        hook,
        completion_has,
        completion_value,
        body,
        statement_lowering.function_initializers,
        asynchronous,
    );
    let mut emitted = Program::Script(Script {
        span: DUMMY_SP,
        body: vec![Stmt::Expr(ExprStmt {
            span: DUMMY_SP,
            expr: Box::new(wrapper),
        })],
        shebang: None,
    });
    emitted.mutate(hygiene());
    emitted.mutate(fixer(Some(&comments)));

    let mut bytes = Vec::new();
    let mut mappings = Vec::new();
    {
        let mut emitter = Emitter {
            cfg: Default::default(),
            cm: source_map.clone(),
            comments: None,
            wr: JsWriter::new(source_map.clone(), "\n", &mut bytes, Some(&mut mappings)),
        };
        emitter
            .emit_program(&emitted)
            .map_err(|error| SessionLoweringError::Emitter(error.to_string()))?;
    }
    let source = String::from_utf8(bytes).map_err(|_| SessionLoweringError::NonUtf8Output)?;
    let source_map_bytes = emit_source_map(&source_map, &mappings)?;
    Ok(LoweredSessionProgram {
        source: Arc::from(source),
        source_map: Arc::from(source_map_bytes),
        declarations: Arc::from(declarations),
        static_imports: lower_static_import_plan(static_imports),
        asynchronous,
        strict,
    })
}

fn lower_static_import_plan(imports: &[StaticImport]) -> Arc<[LoweredStaticImport]> {
    imports
        .iter()
        .filter(|import| {
            !import.type_only
                && (import.bindings.is_empty()
                    || import.bindings.iter().any(|binding| !binding.type_only))
        })
        .map(|import| LoweredStaticImport {
            specifier: Arc::from(import.specifier.as_str()),
            bindings: import
                .bindings
                .iter()
                .filter(|binding| !binding.type_only)
                .map(|binding| LoweredStaticImportBinding {
                    local: binding.local.as_deref().map(Arc::from),
                    imported: matches!(binding.kind, StaticImportBindingKind::Named).then(|| {
                        Arc::from(
                            binding
                                .imported
                                .as_deref()
                                .expect("named static import has an imported name"),
                        )
                    }),
                    kind: binding.kind.into(),
                })
                .collect::<Vec<_>>()
                .into(),
        })
        .collect::<Vec<_>>()
        .into()
}

fn program_to_session_script(program: Program) -> Result<Script, SessionLoweringError> {
    match program {
        Program::Script(script) => Ok(script),
        Program::Module(module) => {
            let mut body = Vec::new();
            for item in module.body {
                match item {
                    ModuleItem::Stmt(statement) => body.push(statement),
                    ModuleItem::ModuleDecl(ModuleDecl::Import(_)) => {}
                    ModuleItem::ModuleDecl(ModuleDecl::ExportDecl(export)) => {
                        body.push(Stmt::Decl(export.decl));
                    }
                    // Local export clauses are linkage-only. Re-export
                    // clauses and export-all declarations have already become
                    // phase-4 static-import rows, so their dependency edges
                    // remain executable even though the program consumer
                    // intentionally discards the entry namespace.
                    ModuleItem::ModuleDecl(
                        ModuleDecl::ExportNamed(_) | ModuleDecl::ExportAll(_),
                    ) => {}
                    ModuleItem::ModuleDecl(ModuleDecl::ExportDefaultExpr(export)) => {
                        body.push(discarded_module_export(export.expr));
                    }
                    ModuleItem::ModuleDecl(ModuleDecl::ExportDefaultDecl(export)) => {
                        match export.decl {
                            DefaultDecl::Fn(function) => {
                                let FnExpr { ident, function } = function;
                                if let Some(identifier) = ident {
                                    body.push(Stmt::Decl(Decl::Fn(FnDecl {
                                        ident: identifier,
                                        declare: false,
                                        function,
                                    })));
                                } else {
                                    body.push(discarded_module_export(Box::new(Expr::Fn(
                                        FnExpr {
                                            ident: None,
                                            function,
                                        },
                                    ))));
                                }
                            }
                            DefaultDecl::Class(class) => {
                                let ClassExpr { ident, class } = class;
                                if let Some(identifier) = ident {
                                    body.push(Stmt::Decl(Decl::Class(ClassDecl {
                                        ident: identifier,
                                        declare: false,
                                        class,
                                    })));
                                } else {
                                    body.push(discarded_module_export(Box::new(Expr::Class(
                                        ClassExpr { ident: None, class },
                                    ))));
                                }
                            }
                            DefaultDecl::TsInterfaceDecl(_) => {}
                        }
                    }
                    ModuleItem::ModuleDecl(ModuleDecl::TsExportAssignment(export)) => {
                        body.push(discarded_module_export(export.expr));
                    }
                    ModuleItem::ModuleDecl(ModuleDecl::TsNamespaceExport(_)) => {}
                    ModuleItem::ModuleDecl(ModuleDecl::TsImportEquals(_)) => {
                        return Err(SessionLoweringError::ModuleExportUnavailable)
                    }
                }
            }
            Ok(Script {
                span: module.span,
                body,
                shebang: module.shebang,
            })
        }
    }
}

fn discarded_module_export(expression: Box<Expr>) -> Stmt {
    Stmt::Expr(ExprStmt {
        span: DUMMY_SP,
        expr: Box::new(Expr::Unary(UnaryExpr {
            span: DUMMY_SP,
            op: UnaryOp::Void,
            arg: expression,
        })),
    })
}

fn use_strict_directive() -> Stmt {
    Stmt::Expr(ExprStmt {
        span: DUMMY_SP,
        expr: Box::new(Expr::Lit(Lit::Str(Str {
            span: DUMMY_SP,
            value: "use strict".into(),
            raw: Some("\"use strict\"".into()),
        }))),
    })
}

struct ImportMetaLowering {
    source_label: String,
    is_main: bool,
    virtual_path: Option<String>,
}

impl VisitMut for ImportMetaLowering {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        if matches!(
            expression,
            Expr::MetaProp(MetaPropExpr {
                kind: MetaPropKind::ImportMeta,
                ..
            })
        ) {
            let mut props = vec![
                PropOrSpread::Prop(Box::new(Prop::KeyValue(KeyValueProp {
                    key: PropName::Ident(IdentName::new("url".into(), DUMMY_SP)),
                    value: Box::new(string_expr(&self.source_label)),
                }))),
                PropOrSpread::Prop(Box::new(Prop::KeyValue(KeyValueProp {
                    key: PropName::Ident(IdentName::new("main".into(), DUMMY_SP)),
                    value: Box::new(bool_expr(self.is_main)),
                }))),
            ];
            if let Some(virtual_path) = self.virtual_path.as_deref() {
                let (dirname, file) = virtual_path
                    .rsplit_once('/')
                    .expect("authenticated virtual file path must contain a separator");
                for (name, value) in [
                    ("path", virtual_path),
                    ("filename", virtual_path),
                    ("file", file),
                    ("dirname", dirname),
                    ("dir", dirname),
                ] {
                    props.push(PropOrSpread::Prop(Box::new(Prop::KeyValue(KeyValueProp {
                        key: PropName::Ident(IdentName::new(name.into(), DUMMY_SP)),
                        value: Box::new(string_expr(value)),
                    }))));
                }
            } else {
                // The legacy module transform exposes an empty basename for a
                // module with no file while leaving path-like properties absent.
                // @ref LLP 0023#6-path-bearing-observables
                props.push(PropOrSpread::Prop(Box::new(Prop::KeyValue(KeyValueProp {
                    key: PropName::Ident(IdentName::new("file".into(), DUMMY_SP)),
                    value: Box::new(string_expr("")),
                }))));
            }
            *expression = Expr::Object(ObjectLit {
                span: DUMMY_SP,
                props,
            });
            return;
        }
        expression.visit_mut_children_with(self);
    }
}

/// Module top-level `this` is undefined. Arrow functions inherit that value;
/// ordinary functions/classes own their own `this` and are skipped here.
struct ModuleTopLevelThisLowering;

impl VisitMut for ModuleTopLevelThisLowering {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        if matches!(expression, Expr::This(_)) {
            *expression = undefined_expr();
            return;
        }
        expression.visit_mut_children_with(self);
    }

    fn visit_mut_function(&mut self, _function: &mut Function) {}

    fn visit_mut_class(&mut self, _class: &mut Class) {}
}

fn emit_source_map(
    source_map: &Lrc<SourceMap>,
    mappings: &[(swc_common::BytePos, swc_common::LineCol)],
) -> Result<Vec<u8>, SessionLoweringError> {
    let map = source_map.build_source_map(
        mappings,
        None,
        swc_common::source_map::DefaultSourceMapGenConfig,
    );
    let mut bytes = Vec::new();
    map.to_writer(&mut bytes)
        .map_err(|error| SessionLoweringError::Emitter(error.to_string()))?;
    Ok(bytes)
}

fn string_expr(value: &str) -> Expr {
    Expr::Lit(Lit::Str(Str {
        span: DUMMY_SP,
        value: value.into(),
        raw: None,
    }))
}

fn bool_expr(value: bool) -> Expr {
    Expr::Lit(Lit::Bool(Bool {
        span: DUMMY_SP,
        value,
    }))
}

fn undefined_expr() -> Expr {
    Expr::Unary(UnaryExpr {
        span: DUMMY_SP,
        op: UnaryOp::Void,
        arg: Box::new(Expr::Lit(Lit::Num(Number {
            span: DUMMY_SP,
            value: 0.0,
            raw: None,
        }))),
    })
}

fn ident_expr(identifier: &Ident) -> Expr {
    Expr::Ident(identifier.clone())
}

fn ident_target(identifier: &Ident) -> AssignTarget {
    AssignTarget::Simple(SimpleAssignTarget::Ident(BindingIdent {
        id: identifier.clone(),
        type_ann: None,
    }))
}

fn member(object: Expr, property: &str) -> Expr {
    Expr::Member(MemberExpr {
        span: DUMMY_SP,
        obj: Box::new(object),
        prop: MemberProp::Ident(IdentName::new(property.into(), DUMMY_SP)),
    })
}

fn call(callee: Expr, arguments: Vec<Expr>) -> Expr {
    Expr::Call(CallExpr {
        span: DUMMY_SP,
        ctxt: SyntaxContext::empty(),
        callee: Callee::Expr(Box::new(callee)),
        args: arguments
            .into_iter()
            .map(|expr| ExprOrSpread {
                spread: None,
                expr: Box::new(expr),
            })
            .collect(),
        type_args: None,
    })
}

fn hook_call(hook: &Ident, method: &str, arguments: Vec<Expr>) -> Expr {
    call(member(ident_expr(hook), method), arguments)
}

fn session_reference(hook: &Ident, name: &str, strict: bool, initialize: bool) -> Expr {
    let method = if initialize {
        "initialize"
    } else {
        "reference"
    };
    member(
        hook_call(
            hook,
            method,
            if initialize {
                vec![string_expr(name)]
            } else {
                vec![string_expr(name), bool_expr(strict)]
            },
        ),
        "value",
    )
}

fn unbound_callee(callee: Expr) -> Expr {
    Expr::Seq(SeqExpr {
        span: DUMMY_SP,
        exprs: vec![
            Box::new(Expr::Lit(Lit::Num(Number {
                span: DUMMY_SP,
                value: 0.0,
                raw: None,
            }))),
            Box::new(callee),
        ],
    })
}

// @ref LLP 0024#73-evaluation-phases-collisions-and-the-cross-kind-matrix
// — a sloppy block function has two bindings: the engine-owned block lexical
// and a var-style session publication copied only when the declaration runs.
// SWC can collapse both spellings into the top-level context, so repair the
// lexical side before free-reference lowering and publish through the private
// checked reference without adding a JavaScript-visible hook.
struct AnnexBPublicationLowering<'a> {
    plan: &'a AnnexBPlan,
    hook: Ident,
}

impl AnnexBPublicationLowering<'_> {
    fn lower_script(&mut self, script: &mut Script) {
        self.lower_statement_list(&mut script.body);
    }

    fn lower_statement_list(&mut self, statements: &mut Vec<Stmt>) {
        for statement in statements.iter_mut() {
            self.lower_statement_children(statement);
        }
        let groups = self.binding_groups(statements.iter().filter_map(direct_function));
        if groups.is_empty() {
            return;
        }
        let mut repair = AnnexBBindingContextRepair { groups: &groups };
        for statement in statements.iter_mut() {
            statement.visit_mut_with(&mut repair);
        }
        self.inject_publications(statements);
    }

    fn lower_statement_children(&mut self, statement: &mut Stmt) {
        match statement {
            Stmt::Block(block) => self.lower_statement_list(&mut block.stmts),
            Stmt::If(statement) => {
                self.lower_boxed_statement(&mut statement.cons);
                if let Some(alternate) = &mut statement.alt {
                    self.lower_boxed_statement(alternate);
                }
            }
            Stmt::Labeled(statement) => self.lower_boxed_statement(&mut statement.body),
            Stmt::While(statement) => self.lower_boxed_statement(&mut statement.body),
            Stmt::DoWhile(statement) => self.lower_boxed_statement(&mut statement.body),
            Stmt::For(statement) => self.lower_boxed_statement(&mut statement.body),
            Stmt::ForIn(statement) => self.lower_boxed_statement(&mut statement.body),
            Stmt::ForOf(statement) => self.lower_boxed_statement(&mut statement.body),
            Stmt::Switch(statement) => self.lower_switch(statement),
            Stmt::Try(statement) => {
                self.lower_statement_list(&mut statement.block.stmts);
                if let Some(handler) = &mut statement.handler {
                    self.lower_statement_list(&mut handler.body.stmts);
                }
                if let Some(finalizer) = &mut statement.finalizer {
                    self.lower_statement_list(&mut finalizer.stmts);
                }
            }
            Stmt::With(statement) => self.lower_boxed_statement(&mut statement.body),
            Stmt::Decl(_)
            | Stmt::Expr(_)
            | Stmt::Empty(_)
            | Stmt::Debugger(_)
            | Stmt::Return(_)
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Throw(_) => {}
        }
    }

    fn lower_boxed_statement(&mut self, statement: &mut Box<Stmt>) {
        let candidate = direct_function(statement)
            .is_some_and(|declaration| self.plan.function(declaration).is_some());
        if candidate {
            let original = *statement.take();
            let mut statements = vec![original];
            self.lower_statement_list(&mut statements);
            **statement = Stmt::Block(BlockStmt {
                span: DUMMY_SP,
                ctxt: SyntaxContext::empty(),
                stmts: statements,
            });
        } else {
            self.lower_statement_children(statement);
        }
    }

    fn lower_switch(&mut self, statement: &mut SwitchStmt) {
        for case in &mut statement.cases {
            for statement in &mut case.cons {
                self.lower_statement_children(statement);
            }
        }
        let groups = self.binding_groups(
            statement
                .cases
                .iter()
                .flat_map(|case| case.cons.iter())
                .filter_map(direct_function),
        );
        if groups.is_empty() {
            return;
        }
        let mut repair = AnnexBBindingContextRepair { groups: &groups };
        for case in &mut statement.cases {
            if let Some(test) = &mut case.test {
                test.visit_mut_with(&mut repair);
            }
            for statement in &mut case.cons {
                statement.visit_mut_with(&mut repair);
            }
        }
        for case in &mut statement.cases {
            self.inject_publications(&mut case.cons);
        }
    }

    fn binding_groups<'a>(
        &self,
        declarations: impl Iterator<Item = &'a FnDecl>,
    ) -> Vec<AnnexBBindingGroup> {
        let mut groups: Vec<AnnexBBindingGroup> = Vec::new();
        for declaration in declarations {
            let Some(function) = self.plan.function(declaration) else {
                continue;
            };
            if let Some(group) = groups.iter_mut().find(|group| group.name == function.name) {
                if !group.originals.contains(&declaration.ident.ctxt) {
                    group.originals.push(declaration.ident.ctxt);
                }
                continue;
            }
            groups.push(AnnexBBindingGroup {
                name: function.name.clone(),
                originals: vec![declaration.ident.ctxt],
                repaired: SyntaxContext::empty().apply_mark(Mark::new()),
            });
        }
        groups
    }

    fn inject_publications(&self, statements: &mut Vec<Stmt>) {
        let mut lowered = Vec::with_capacity(statements.len());
        for statement in std::mem::take(statements) {
            let publication = direct_function(&statement).and_then(|declaration| {
                let function = self.plan.function(declaration)?;
                function
                    .publish
                    .then(|| self.publication_statement(&function.name, declaration.ident.clone()))
            });
            lowered.push(statement);
            if let Some(publication) = publication {
                lowered.push(publication);
            }
        }
        *statements = lowered;
    }

    fn publication_statement(&self, name: &str, local: Ident) -> Stmt {
        let target = session_reference(&self.hook, name, false, false);
        let assignment = Expr::Assign(AssignExpr {
            span: DUMMY_SP,
            op: AssignOp::Assign,
            left: AssignTarget::try_from(Box::new(target))
                .expect("session Annex-B publication target is assignable"),
            right: Box::new(Expr::Ident(local)),
        });
        // A declaration has empty completion. Keep the synthetic copy inside a
        // private lexical declaration so it cannot become the input's value.
        Stmt::Decl(Decl::Var(Box::new(VarDecl {
            span: DUMMY_SP,
            ctxt: SyntaxContext::empty(),
            kind: VarDeclKind::Let,
            declare: false,
            decls: vec![VarDeclarator {
                span: DUMMY_SP,
                name: Pat::Ident(BindingIdent {
                    id: Ident::new_private("__ibex_annex_b_publication".into(), DUMMY_SP),
                    type_ann: None,
                }),
                init: Some(Box::new(assignment)),
                definite: false,
            }],
        })))
    }
}

fn direct_function(statement: &Stmt) -> Option<&FnDecl> {
    let Stmt::Decl(Decl::Fn(declaration)) = statement else {
        return None;
    };
    Some(declaration)
}

struct AnnexBBindingGroup {
    name: String,
    originals: Vec<SyntaxContext>,
    repaired: SyntaxContext,
}

struct AnnexBBindingContextRepair<'a> {
    groups: &'a [AnnexBBindingGroup],
}

impl VisitMut for AnnexBBindingContextRepair<'_> {
    fn visit_mut_ident(&mut self, identifier: &mut Ident) {
        if let Some(group) = self.groups.iter().find(|group| {
            identifier.sym.as_ref() == group.name && group.originals.contains(&identifier.ctxt)
        }) {
            identifier.ctxt = group.repaired;
        }
    }
}

struct ReferenceLowering {
    unresolved_ctxt: SyntaxContext,
    top_level_ctxt: SyntaxContext,
    hook: Ident,
    strict: bool,
}

struct StatementLowering {
    hook: Ident,
    completion_has: Ident,
    completion_value: Ident,
    unresolved_ctxt: SyntaxContext,
    top_level_ctxt: SyntaxContext,
    strict: bool,
    function_initializers: Vec<Stmt>,
}

impl StatementLowering {
    fn references(&self) -> ReferenceLowering {
        ReferenceLowering {
            unresolved_ctxt: self.unresolved_ctxt,
            top_level_ctxt: self.top_level_ctxt,
            hook: self.hook.clone(),
            strict: self.strict,
        }
    }

    fn completion_statement(&self, expression: Box<Expr>) -> Stmt {
        let set_value = Expr::Assign(AssignExpr {
            span: DUMMY_SP,
            op: AssignOp::Assign,
            left: ident_target(&self.completion_value),
            right: expression,
        });
        let set_has = Expr::Assign(AssignExpr {
            span: DUMMY_SP,
            op: AssignOp::Assign,
            left: ident_target(&self.completion_has),
            right: Box::new(bool_expr(true)),
        });
        Stmt::Expr(ExprStmt {
            span: DUMMY_SP,
            expr: Box::new(Expr::Seq(SeqExpr {
                span: DUMMY_SP,
                exprs: vec![Box::new(set_value), Box::new(set_has)],
            })),
        })
    }

    fn execution_statement(expression: Expr) -> Stmt {
        Stmt::Expr(ExprStmt {
            span: DUMMY_SP,
            expr: Box::new(expression),
        })
    }

    fn protect_finalizer_completion(&self, finalizer: &mut BlockStmt, lowered: Vec<Stmt>) {
        let saved_has = Ident::new_private("__ibex_finally_completion_has".into(), DUMMY_SP);
        let saved_value = Ident::new_private("__ibex_finally_completion_value".into(), DUMMY_SP);
        let snapshot = Stmt::Decl(Decl::Var(Box::new(VarDecl {
            span: DUMMY_SP,
            ctxt: SyntaxContext::empty(),
            kind: VarDeclKind::Let,
            declare: false,
            decls: vec![
                VarDeclarator {
                    span: DUMMY_SP,
                    name: Pat::Ident(BindingIdent {
                        id: saved_has.clone(),
                        type_ann: None,
                    }),
                    init: Some(Box::new(ident_expr(&self.completion_has))),
                    definite: false,
                },
                VarDeclarator {
                    span: DUMMY_SP,
                    name: Pat::Ident(BindingIdent {
                        id: saved_value.clone(),
                        type_ann: None,
                    }),
                    init: Some(Box::new(ident_expr(&self.completion_value))),
                    definite: false,
                },
            ],
        })));
        let restore_value = Self::execution_statement(Expr::Assign(AssignExpr {
            span: DUMMY_SP,
            op: AssignOp::Assign,
            left: ident_target(&self.completion_value),
            right: Box::new(ident_expr(&saved_value)),
        }));
        let restore_has = Self::execution_statement(Expr::Assign(AssignExpr {
            span: DUMMY_SP,
            op: AssignOp::Assign,
            left: ident_target(&self.completion_has),
            right: Box::new(ident_expr(&saved_has)),
        }));

        // A normal Finally clause's value is discarded, while an abrupt
        // break/continue receives the try/catch completion through UpdateEmpty.
        // Restore in a nested finally so both paths recover the incoming
        // accumulator; a thrown value still propagates through the JS outcome.
        // @ref LLP 0024#77-deviations-and-the-four-gates-that-prove-them
        finalizer.stmts = vec![
            snapshot,
            Stmt::Try(Box::new(TryStmt {
                span: DUMMY_SP,
                block: BlockStmt {
                    span: DUMMY_SP,
                    ctxt: SyntaxContext::empty(),
                    stmts: lowered,
                },
                handler: None,
                finalizer: Some(BlockStmt {
                    span: DUMMY_SP,
                    ctxt: SyntaxContext::empty(),
                    stmts: vec![restore_value, restore_has],
                }),
            })),
        ];
    }

    fn lower_root(&mut self, statements: Vec<Stmt>) -> Result<Vec<Stmt>, SessionLoweringError> {
        let directive_count = statements
            .iter()
            .take_while(|statement| {
                matches!(statement, Stmt::Expr(ExprStmt { expr, .. }) if matches!(&**expr, Expr::Lit(Lit::Str(_))))
            })
            .count();
        let mut directives = statements[..directive_count].to_vec();
        let directive_completion = directives.last().and_then(|statement| {
            let Stmt::Expr(ExprStmt { expr, .. }) = statement else {
                return None;
            };
            let Expr::Lit(Lit::Str(value)) = &**expr else {
                return None;
            };
            Some(Box::new(Expr::Lit(Lit::Str(value.clone()))))
        });
        let lowered = self.lower_statement_list(statements[directive_count..].to_vec(), true)?;

        directives.push(local_completion_declaration(
            &self.completion_has,
            &self.completion_value,
        ));
        if let Some(value) = directive_completion {
            directives.push(self.completion_statement(value));
        }
        directives.append(&mut self.function_initializers);
        directives.extend(lowered);
        Ok(directives)
    }

    fn lower_statement_list(
        &mut self,
        statements: Vec<Stmt>,
        root: bool,
    ) -> Result<Vec<Stmt>, SessionLoweringError> {
        let mut output = Vec::new();
        for statement in statements {
            output.extend(self.lower_statement(statement, root)?);
        }
        Ok(output)
    }

    fn lower_single_statement(
        &mut self,
        statement: Stmt,
    ) -> Result<Box<Stmt>, SessionLoweringError> {
        let mut lowered = self.lower_statement(statement, false)?;
        if lowered.len() == 1 {
            Ok(Box::new(lowered.pop().expect("one statement")))
        } else {
            Ok(Box::new(Stmt::Block(BlockStmt {
                span: DUMMY_SP,
                ctxt: SyntaxContext::empty(),
                stmts: lowered,
            })))
        }
    }

    fn lower_statement(
        &mut self,
        statement: Stmt,
        root: bool,
    ) -> Result<Vec<Stmt>, SessionLoweringError> {
        Ok(match statement {
            Stmt::Expr(expression) => vec![self.completion_statement(expression.expr)],
            Stmt::Block(mut block) => {
                block.stmts = self.lower_statement_list(block.stmts, false)?;
                vec![Stmt::Block(block)]
            }
            Stmt::If(mut statement) => {
                statement.cons = self.lower_single_statement(*statement.cons)?;
                statement.alt = statement
                    .alt
                    .map(|alternate| self.lower_single_statement(*alternate))
                    .transpose()?;
                vec![Stmt::If(statement)]
            }
            Stmt::Labeled(mut statement) => {
                statement.body = self.lower_single_statement(*statement.body)?;
                vec![Stmt::Labeled(statement)]
            }
            Stmt::While(mut statement) => {
                statement.body = self.lower_single_statement(*statement.body)?;
                vec![Stmt::While(statement)]
            }
            Stmt::DoWhile(mut statement) => {
                statement.body = self.lower_single_statement(*statement.body)?;
                vec![Stmt::DoWhile(statement)]
            }
            Stmt::For(mut statement) => {
                if let Some(VarDeclOrExpr::VarDecl(declaration)) = statement.init.take() {
                    if declaration.kind == VarDeclKind::Var {
                        let expressions = self.variable_initializers(*declaration, false)?;
                        statement.init = sequence_or_none(expressions).map(VarDeclOrExpr::Expr);
                    } else {
                        statement.init = Some(VarDeclOrExpr::VarDecl(declaration));
                    }
                }
                statement.body = self.lower_single_statement(*statement.body)?;
                vec![Stmt::For(statement)]
            }
            Stmt::ForIn(mut statement) => {
                self.lower_for_head(&mut statement.left)?;
                statement.body = self.lower_single_statement(*statement.body)?;
                vec![Stmt::ForIn(statement)]
            }
            Stmt::ForOf(mut statement) => {
                self.lower_for_head(&mut statement.left)?;
                statement.body = self.lower_single_statement(*statement.body)?;
                vec![Stmt::ForOf(statement)]
            }
            Stmt::Switch(mut statement) => {
                for case in &mut statement.cases {
                    case.cons = self.lower_statement_list(std::mem::take(&mut case.cons), false)?;
                }
                vec![Stmt::Switch(statement)]
            }
            Stmt::Try(mut statement) => {
                statement.block.stmts = self.lower_statement_list(statement.block.stmts, false)?;
                if let Some(handler) = &mut statement.handler {
                    handler.body.stmts =
                        self.lower_statement_list(std::mem::take(&mut handler.body.stmts), false)?;
                }
                if let Some(finalizer) = &mut statement.finalizer {
                    let lowered =
                        self.lower_statement_list(std::mem::take(&mut finalizer.stmts), false)?;
                    self.protect_finalizer_completion(finalizer, lowered);
                }
                vec![Stmt::Try(statement)]
            }
            Stmt::With(_) => {
                return Err(SessionLoweringError::UnsupportedDeclarationPattern(
                    "with statement",
                ))
            }
            Stmt::Decl(declaration) => self.lower_declaration(declaration, root)?,
            other => vec![other],
        })
    }

    fn lower_declaration(
        &mut self,
        declaration: Decl,
        root: bool,
    ) -> Result<Vec<Stmt>, SessionLoweringError> {
        match declaration {
            Decl::Var(declaration) if declaration.kind == VarDeclKind::Var || root => {
                let initialize = declaration.kind != VarDeclKind::Var;
                Ok(self
                    .variable_initializers(*declaration, initialize)?
                    .into_iter()
                    .map(Self::execution_statement)
                    .collect())
            }
            Decl::Fn(declaration) if root => {
                let name = declaration.ident.sym.to_string();
                self.function_initializers
                    .push(Self::execution_statement(hook_call(
                        &self.hook,
                        "hoistFunction",
                        vec![
                            string_expr(&name),
                            Expr::Fn(FnExpr {
                                ident: None,
                                function: declaration.function,
                            }),
                        ],
                    )));
                Ok(Vec::new())
            }
            Decl::Class(declaration) if root => {
                let target = session_reference(
                    &self.hook,
                    declaration.ident.sym.as_ref(),
                    self.strict,
                    true,
                );
                Ok(vec![Self::execution_statement(Expr::Assign(AssignExpr {
                    span: DUMMY_SP,
                    op: AssignOp::Assign,
                    left: AssignTarget::try_from(Box::new(target))
                        .expect("session class target is assignable"),
                    right: Box::new(Expr::Class(ClassExpr {
                        ident: None,
                        class: declaration.class,
                    })),
                }))])
            }
            declaration => Ok(vec![Stmt::Decl(declaration)]),
        }
    }

    fn variable_initializers(
        &mut self,
        declaration: VarDecl,
        initialize: bool,
    ) -> Result<Vec<Expr>, SessionLoweringError> {
        let mut references = self.references();
        let mut expressions = Vec::new();
        for declarator in declaration.decls {
            let right = match declarator.init {
                Some(initializer) => initializer,
                None if initialize => Box::new(undefined_expr()),
                None => continue,
            };
            let pattern = references.transform_assignment_pattern(declarator.name, initialize);
            let target = AssignTarget::try_from(pattern).map_err(|_| {
                SessionLoweringError::UnsupportedDeclarationPattern("binding pattern")
            })?;
            expressions.push(Expr::Assign(AssignExpr {
                span: declarator.span,
                op: AssignOp::Assign,
                left: target,
                right,
            }));
        }
        Ok(expressions)
    }

    fn lower_for_head(&mut self, head: &mut ForHead) -> Result<(), SessionLoweringError> {
        let ForHead::VarDecl(declaration) = head else {
            return Ok(());
        };
        if declaration.kind != VarDeclKind::Var || declaration.decls.len() != 1 {
            return Ok(());
        }
        let declarator = declaration
            .decls
            .pop()
            .expect("length checked for for-head declaration");
        let mut references = self.references();
        *head = ForHead::Pat(Box::new(
            references.transform_assignment_pattern(declarator.name, false),
        ));
        Ok(())
    }
}

fn sequence_or_none(expressions: Vec<Expr>) -> Option<Box<Expr>> {
    match expressions.len() {
        0 => None,
        1 => expressions.into_iter().next().map(Box::new),
        _ => Some(Box::new(Expr::Seq(SeqExpr {
            span: DUMMY_SP,
            exprs: expressions.into_iter().map(Box::new).collect(),
        }))),
    }
}

fn local_completion_declaration(has: &Ident, value: &Ident) -> Stmt {
    Stmt::Decl(Decl::Var(Box::new(VarDecl {
        span: DUMMY_SP,
        ctxt: SyntaxContext::empty(),
        kind: VarDeclKind::Var,
        declare: false,
        decls: vec![
            VarDeclarator {
                span: DUMMY_SP,
                name: Pat::Ident(BindingIdent {
                    id: has.clone(),
                    type_ann: None,
                }),
                init: Some(Box::new(bool_expr(false))),
                definite: false,
            },
            VarDeclarator {
                span: DUMMY_SP,
                name: Pat::Ident(BindingIdent {
                    id: value.clone(),
                    type_ann: None,
                }),
                init: None,
                definite: false,
            },
        ],
    })))
}

fn wrapper_expression(
    hook: Ident,
    completion_has: Ident,
    completion_value: Ident,
    mut body: Vec<Stmt>,
    _function_initializers: Vec<Stmt>,
    asynchronous: bool,
) -> Expr {
    body.push(Stmt::Return(ReturnStmt {
        span: DUMMY_SP,
        arg: Some(Box::new(hook_call(
            &hook,
            "finish",
            vec![ident_expr(&completion_has), ident_expr(&completion_value)],
        ))),
    }));
    // An arrow is load-bearing here: a normal function would expose the
    // private hook as `arguments[0]` to user-authored statements in its body.
    // The arrow has no own `arguments`, `this`, or `new.target`; its lexical
    // `this` also preserves sloppy Script top-level `this` from the evaluated
    // wrapper expression.
    Expr::Arrow(ArrowExpr {
        span: DUMMY_SP,
        ctxt: SyntaxContext::empty(),
        params: vec![Pat::Ident(BindingIdent {
            id: hook,
            type_ann: None,
        })],
        body: Box::new(BlockStmtOrExpr::BlockStmt(BlockStmt {
            span: DUMMY_SP,
            ctxt: SyntaxContext::empty(),
            stmts: body,
        })),
        is_generator: false,
        is_async: asynchronous,
        type_params: None,
        return_type: None,
    })
}

impl ReferenceLowering {
    fn is_session_identifier(&self, identifier: &Ident) -> bool {
        identifier.ctxt == self.unresolved_ctxt || identifier.ctxt == self.top_level_ctxt
    }

    fn reference(&self, identifier: &Ident, initialize: bool) -> Expr {
        session_reference(&self.hook, identifier.sym.as_ref(), self.strict, initialize)
    }

    fn transform_assignment_pattern(&mut self, pattern: Pat, initialize: bool) -> Pat {
        match pattern {
            Pat::Ident(binding) if self.is_session_identifier(&binding.id) => {
                Pat::Expr(Box::new(self.reference(&binding.id, initialize)))
            }
            Pat::Array(mut array) => {
                array.elems = array
                    .elems
                    .into_iter()
                    .map(|element| {
                        element
                            .map(|pattern| self.transform_assignment_pattern(pattern, initialize))
                    })
                    .collect();
                Pat::Array(array)
            }
            Pat::Object(mut object) => {
                object.props = object
                    .props
                    .into_iter()
                    .map(|property| match property {
                        ObjectPatProp::KeyValue(mut property) => {
                            property.value = Box::new(
                                self.transform_assignment_pattern(*property.value, initialize),
                            );
                            ObjectPatProp::KeyValue(property)
                        }
                        ObjectPatProp::Assign(mut property)
                            if self.is_session_identifier(&property.key.id) =>
                        {
                            let key = PropName::Ident(IdentName::new(
                                property.key.id.sym.clone(),
                                property.key.id.span,
                            ));
                            let target =
                                Pat::Expr(Box::new(self.reference(&property.key.id, initialize)));
                            let value = match property.value.take() {
                                Some(default) => Pat::Assign(AssignPat {
                                    span: property.span,
                                    left: Box::new(target),
                                    right: default,
                                }),
                                None => target,
                            };
                            ObjectPatProp::KeyValue(KeyValuePatProp {
                                key,
                                value: Box::new(value),
                            })
                        }
                        ObjectPatProp::Assign(mut property) => {
                            property.value.visit_mut_with(self);
                            ObjectPatProp::Assign(property)
                        }
                        ObjectPatProp::Rest(mut rest) => {
                            rest.arg =
                                Box::new(self.transform_assignment_pattern(*rest.arg, initialize));
                            ObjectPatProp::Rest(rest)
                        }
                    })
                    .collect();
                Pat::Object(object)
            }
            Pat::Assign(mut assignment) => {
                assignment.left =
                    Box::new(self.transform_assignment_pattern(*assignment.left, initialize));
                assignment.right.visit_mut_with(self);
                Pat::Assign(assignment)
            }
            Pat::Rest(mut rest) => {
                rest.arg = Box::new(self.transform_assignment_pattern(*rest.arg, initialize));
                Pat::Rest(rest)
            }
            Pat::Expr(mut expression) => {
                expression.visit_mut_with(self);
                Pat::Expr(expression)
            }
            other => other,
        }
    }
}

impl VisitMut for ReferenceLowering {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        match expression {
            Expr::Unary(unary)
                if matches!(unary.op, UnaryOp::TypeOf | UnaryOp::Delete)
                    && matches!(&*unary.arg, Expr::Ident(identifier) if self.is_session_identifier(identifier)) =>
            {
                let Expr::Ident(identifier) = &*unary.arg else {
                    unreachable!()
                };
                let method = if unary.op == UnaryOp::TypeOf {
                    "typeofName"
                } else {
                    "deleteName"
                };
                *expression = hook_call(
                    &self.hook,
                    method,
                    vec![string_expr(identifier.sym.as_ref())],
                );
                return;
            }
            _ => {}
        }

        expression.visit_mut_children_with(self);
        if let Expr::Ident(identifier) = expression {
            if self.is_session_identifier(identifier) {
                *expression = self.reference(identifier, false);
            }
        }
    }

    fn visit_mut_call_expr(&mut self, call_expression: &mut CallExpr) {
        if matches!(call_expression.callee, Callee::Import(_)) {
            // Dynamic import must keep the C-only logical referrer captured by
            // the authenticated session request. A realm-global `importModule`
            // lookup loses that identity when a delayed callback runs and can
            // only fall back to an unrelated cwd-observe request. The private
            // hook is native-owned, hygienic, and survives exactly as long as
            // the lowered session closure.
            // @ref LLP 0026#6-top-level-await-and-dynamic-import
            call_expression.callee =
                Callee::Expr(Box::new(member(ident_expr(&self.hook), "dynamicImport")));
        }
        let unbind = matches!(
            &call_expression.callee,
            Callee::Expr(expression)
                if matches!(&**expression, Expr::Ident(identifier) if self.is_session_identifier(identifier))
        );
        call_expression.visit_mut_children_with(self);
        if unbind {
            if let Callee::Expr(callee) = &mut call_expression.callee {
                let transformed = *callee.take();
                **callee = unbound_callee(transformed);
            }
        }
    }

    fn visit_mut_opt_call(&mut self, call_expression: &mut OptCall) {
        let unbind = matches!(
            &*call_expression.callee,
            Expr::Ident(identifier) if self.is_session_identifier(identifier)
        );
        call_expression.visit_mut_children_with(self);
        if unbind {
            let transformed = *call_expression.callee.take();
            *call_expression.callee = unbound_callee(transformed);
        }
    }

    fn visit_mut_tagged_tpl(&mut self, tagged: &mut TaggedTpl) {
        let unbind = matches!(&*tagged.tag, Expr::Ident(identifier) if self.is_session_identifier(identifier));
        tagged.visit_mut_children_with(self);
        if unbind {
            let transformed = *tagged.tag.take();
            *tagged.tag = unbound_callee(transformed);
        }
    }

    fn visit_mut_assign_target(&mut self, target: &mut AssignTarget) {
        if let AssignTarget::Simple(SimpleAssignTarget::Ident(binding)) = target {
            if self.is_session_identifier(&binding.id) {
                *target = AssignTarget::try_from(Box::new(self.reference(&binding.id, false)))
                    .expect("session reference is a simple member target");
                return;
            }
        }
        if let AssignTarget::Pat(pattern) = target {
            let pattern = std::mem::take(pattern);
            let lowered = self.transform_assignment_pattern(pattern.into(), false);
            *target = AssignTarget::try_from(lowered)
                .expect("lowered assignment pattern remains an assignment target");
            return;
        }
        target.visit_mut_children_with(self);
    }

    fn visit_mut_prop(&mut self, property: &mut Prop) {
        if let Prop::Shorthand(identifier) = property {
            if self.is_session_identifier(identifier) {
                *property = Prop::KeyValue(KeyValueProp {
                    key: PropName::Ident(IdentName::new(identifier.sym.clone(), identifier.span)),
                    value: Box::new(self.reference(identifier, false)),
                });
                return;
            }
        }
        property.visit_mut_children_with(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(source: &str) -> Result<LoweredSessionProgram, SessionLoweringError> {
        lower_with_dialect(source, ParserDialect::TypeScript)
    }

    fn lower_with_dialect(
        source: &str,
        dialect: ParserDialect,
    ) -> Result<LoweredSessionProgram, SessionLoweringError> {
        lower_checked_source(
            SyntaxRequest {
                dialect,
                goal: SourceGoal::ScriptWithExtensions,
                role: SourceRole::Entry,
            },
            source,
            "repl:17",
        )
    }

    fn emitted_wrapper(source: &str) -> ArrowExpr {
        let lowered = lower(source).unwrap();
        let (_, _, script) = parse_checked_script(
            lowered.source(),
            ParserDialect::JavaScript,
            "lowered:repl:17",
        )
        .unwrap();
        let [Stmt::Expr(ExprStmt { expr, .. })] = script.body.as_slice() else {
            panic!("lowering must emit one wrapper expression")
        };
        let Expr::Arrow(wrapper) = &**expr else {
            panic!("the private wrapper must be an arrow")
        };
        wrapper.clone()
    }

    fn generated_position(source: &str, needle: &str) -> (u32, u32) {
        let offset = source.find(needle).expect("generated marker");
        let prefix = &source[..offset];
        let line = prefix.bytes().filter(|byte| *byte == b'\n').count() as u32;
        let column = prefix
            .rsplit_once('\n')
            .map_or(prefix.len(), |(_, tail)| tail.len()) as u32;
        (line, column)
    }

    #[test]
    fn wrapper_hook_is_not_reachable_through_arguments_or_the_global() {
        let wrapper = emitted_wrapper("arguments; this;");
        assert_eq!(wrapper.params.len(), 1);
        let BlockStmtOrExpr::BlockStmt(body) = &*wrapper.body else {
            panic!("wrapper must use a block body")
        };
        let emitted = lower("arguments; this;").unwrap();
        assert!(emitted.source().contains("reference(\"arguments\""));
        assert!(!emitted.source().contains("globalThis.__ibex"));
        assert!(matches!(body.stmts.last(), Some(Stmt::Return(_))));
    }

    #[test]
    fn finally_restores_the_incoming_completion_on_normal_and_abrupt_paths() {
        let emitted = lower("done: try { 1; } finally { 2; break done; }").unwrap();
        let source = emitted.source();
        assert!(source.contains("__ibex_finally_completion_has"), "{source}");
        assert!(
            source.contains("__ibex_finally_completion_value"),
            "{source}"
        );
        assert!(
            source.matches("finally").count() >= 2,
            "the synthetic nested finally must restore even across break: {source}"
        );
    }

    #[test]
    fn bare_calls_tags_and_optional_calls_are_unbound_but_members_keep_receivers() {
        let emitted = lower("fn(1); fn`x`; fn?.(2); obj.method();").unwrap();
        let source = emitted.source();
        assert_eq!(source.matches("reference(\"fn\"").count(), 3);
        assert!(source.matches("(0,").count() >= 3, "{source}");
        assert!(source.contains("reference(\"obj\""), "{source}");
        assert!(source.contains(".value.method()"), "{source}");
    }

    #[test]
    fn updates_and_compound_assignments_evaluate_one_session_reference() {
        let emitted = lower("x += f(); x++; ++x; x &&= g();").unwrap();
        let source = emitted.source();
        assert_eq!(source.matches("reference(\"x\"").count(), 4, "{source}");
        assert_eq!(source.matches("reference(\"f\"").count(), 1, "{source}");
        assert_eq!(source.matches("reference(\"g\"").count(), 1, "{source}");
    }

    #[test]
    fn destructuring_defaults_and_rest_initialize_each_declared_cell() {
        let emitted = lower("let [a = fallback(), ...rest] = iterable;").unwrap();
        let source = emitted.source();
        assert_eq!(source.matches("initialize(\"a\"").count(), 1, "{source}");
        assert_eq!(source.matches("initialize(\"rest\"").count(), 1, "{source}");
        assert_eq!(
            source.matches("reference(\"fallback\"").count(),
            1,
            "{source}"
        );
        assert_eq!(
            source.matches("reference(\"iterable\"").count(),
            1,
            "{source}"
        );
    }

    #[test]
    fn var_for_in_and_for_of_heads_write_session_cells() {
        let emitted = lower("for (var x of xs) x; for (var y in ys) y;").unwrap();
        let source = emitted.source();
        assert!(!source.contains("for(var x"), "{source}");
        assert!(!source.contains("for(var y"), "{source}");
        assert!(source.matches("reference(\"x\"").count() >= 2, "{source}");
        assert!(source.matches("reference(\"y\"").count() >= 2, "{source}");
    }

    #[test]
    fn typeof_and_delete_use_name_operations() {
        let emitted = lower("typeof missing; delete missing;").unwrap();
        let source = emitted.source();
        assert!(source.contains("typeofName(\"missing\")"), "{source}");
        assert!(source.contains("deleteName(\"missing\")"), "{source}");
        assert!(!source.contains("reference(\"missing\""), "{source}");
    }

    #[test]
    fn functions_hoist_and_classes_initialize_checked_cells() {
        let emitted = lower("f(); function f() {} typeof C; class C {}").unwrap();
        let source = emitted.source();
        let hoist = source.find("hoistFunction(\"f\"").unwrap();
        let call = source.find("reference(\"f\"").unwrap();
        assert!(hoist < call, "{source}");
        assert!(source.contains("initialize(\"C\")"), "{source}");
        assert!(source.contains("typeofName(\"C\")"), "{source}");
    }

    #[test]
    fn sloppy_annex_b_publication_is_var_style_and_control_flow_local() {
        let lowered = lower_with_dialect(
            "if (condition) { function f() { return 1; } }",
            ParserDialect::JavaScript,
        )
        .unwrap();
        assert_eq!(
            lowered
                .declarations()
                .iter()
                .map(|declaration| (&*declaration.name, declaration.kind))
                .collect::<Vec<_>>(),
            vec![("f", LoweredDeclarationKind::Var)]
        );
        let wrapper = emitted_wrapper("if (condition) { function f() { return 1; } }");
        let BlockStmtOrExpr::BlockStmt(body) = &*wrapper.body else {
            panic!("wrapper must use a block body")
        };
        let conditional = body
            .stmts
            .iter()
            .find_map(|statement| match statement {
                Stmt::If(statement) => Some(statement),
                _ => None,
            })
            .expect("lowered program retains the conditional");
        let Stmt::Block(branch) = &*conditional.cons else {
            panic!("Annex-B single statements are normalized to a block")
        };
        assert!(matches!(
            branch.stmts.as_slice(),
            [Stmt::Decl(Decl::Fn(_)), Stmt::Decl(Decl::Var(_))]
        ));
        let source = lowered.source();
        assert!(source.contains("function f()"), "{source}");
        assert!(source.contains("__ibex_annex_b_publication"), "{source}");
        assert!(!source.contains("hoistFunction(\"f\""), "{source}");
    }

    #[test]
    fn annex_b_uses_gdi_collision_precedence_and_preserves_local_references() {
        let var_and_block = lower_with_dialect(
            "var f = 1; if (condition) { f(); function f() { return f; } }",
            ParserDialect::JavaScript,
        )
        .unwrap();
        assert_eq!(
            var_and_block
                .declarations()
                .iter()
                .filter(|declaration| declaration.name.as_ref() == "f")
                .map(|declaration| declaration.kind)
                .collect::<Vec<_>>(),
            vec![LoweredDeclarationKind::Var, LoweredDeclarationKind::Var]
        );
        // One checked reference initializes the outer `var`; one publishes the
        // block function. The call and recursive reference stay block-local.
        assert_eq!(
            var_and_block.source().matches("reference(\"f\"").count(),
            2,
            "{}",
            var_and_block.source()
        );

        let ordinary = lower_with_dialect(
            "var g; function g() { return 1; }",
            ParserDialect::JavaScript,
        )
        .unwrap();
        assert_eq!(
            ordinary
                .declarations()
                .iter()
                .filter(|declaration| declaration.name.as_ref() == "g")
                .map(|declaration| declaration.kind)
                .collect::<Vec<_>>(),
            vec![
                LoweredDeclarationKind::Var,
                LoweredDeclarationKind::Function
            ]
        );
        assert!(ordinary.source().contains("hoistFunction(\"g\""));
    }

    #[test]
    fn annex_b_outer_publication_respects_same_input_lexical_blockers() {
        for (source, expected_kinds) in [
            (
                "let f = 1; { function f() {} }",
                vec![LoweredDeclarationKind::Let],
            ),
            ("{ let f = 1; { function f() {} } }", vec![]),
            ("for (let f = 0; f < 1; ++f) { function f() {} }", vec![]),
            (
                "try { throw {}; } catch ({ f }) { { function f() {} } }",
                vec![],
            ),
            (
                "import { f } from './dep.js'; { function f() {} }",
                vec![LoweredDeclarationKind::Import],
            ),
        ] {
            let lowered = lower_with_dialect(source, ParserDialect::JavaScript).unwrap();
            assert_eq!(
                lowered
                    .declarations()
                    .iter()
                    .filter(|declaration| declaration.name.as_ref() == "f")
                    .map(|declaration| declaration.kind)
                    .collect::<Vec<_>>(),
                expected_kinds,
                "{source}"
            );
            assert!(lowered.source().contains("function f()"), "{source}");
            assert!(
                !lowered.source().contains("__ibex_annex_b_publication"),
                "{source}: {}",
                lowered.source()
            );
        }
    }

    #[test]
    fn non_ordinary_block_functions_do_not_gain_annex_b_publication() {
        for source in [
            "{ async function f() {} }",
            "{ function* f() {} }",
            "{ async function* f() {} }",
        ] {
            let lowered = lower_with_dialect(source, ParserDialect::JavaScript).unwrap();
            assert!(lowered.declarations().is_empty(), "{source}");
            assert!(
                !lowered.source().contains("__ibex_annex_b_publication"),
                "{source}: {}",
                lowered.source()
            );
            assert!(lowered.source().contains("function"), "{source}");
        }
    }

    #[test]
    fn strict_scripts_and_modules_keep_block_functions_lexical() {
        let strict = lower_with_dialect(
            "'use strict'; { function f() { return 1; } }",
            ParserDialect::JavaScript,
        )
        .unwrap();
        assert!(strict.is_strict());
        assert!(strict.declarations().is_empty());
        assert!(!strict.source().contains("__ibex_annex_b_publication"));
        assert!(strict.source().contains("function f()"));

        let module = lower_checked_source_with_module_meta(
            SyntaxRequest {
                dialect: ParserDialect::JavaScript,
                goal: SourceGoal::Module,
                role: SourceRole::Entry,
            },
            "if (true) { function f() { return 1; } }",
            "ibex:stdin",
            true,
            None,
        )
        .unwrap();
        assert!(module.is_strict());
        assert!(module.declarations().is_empty());
        assert!(!module.source().contains("__ibex_annex_b_publication"));
        assert!(module.source().contains("function f()"));
    }

    #[test]
    fn annex_b_switch_scope_publishes_without_rewriting_local_calls() {
        let lowered = lower_with_dialect(
            "switch (kind) { case 0: f(); function f() {} break; default: f(); }",
            ParserDialect::JavaScript,
        )
        .unwrap();
        assert_eq!(
            lowered
                .declarations()
                .iter()
                .filter(|declaration| declaration.name.as_ref() == "f")
                .map(|declaration| declaration.kind)
                .collect::<Vec<_>>(),
            vec![LoweredDeclarationKind::Var]
        );
        assert_eq!(
            lowered.source().matches("reference(\"f\"").count(),
            1,
            "{}",
            lowered.source()
        );
        assert!(lowered.source().contains("__ibex_annex_b_publication"));
    }

    #[test]
    fn dynamic_source_routes_fail_closed() {
        for source in [
            "eval('1')",
            "(0, eval)('1')",
            "const alias = eval; alias('1')",
            "function nested() { return eval; }",
            "({ eval })",
            "({ [eval]: 1 })",
            "globalThis.eval('1')",
            "globalThis['eval']('1')",
            "const evaluator = globalThis.eval; evaluator('1')",
            "const { eval: evaluator } = globalThis; evaluator('1')",
            "window.eval('1')",
        ] {
            assert!(
                matches!(lower(source).unwrap_err(), SessionLoweringError::EvalClosed),
                "{source}"
            );
        }
        for source in [
            "Function('return 1')",
            "new Function('return 1')",
            "const Constructor = Function; new Constructor('return 1')",
            "({ Function })",
            "class Derived extends Function {}",
            "globalThis.Function('return 1')",
            "new globalThis['Function']('return 1')",
            "const Constructor = globalThis.Function; new Constructor('return 1')",
            "const { Function: Constructor } = globalThis; new Constructor('return 1')",
            "self.Function('return 1')",
        ] {
            assert!(
                matches!(
                    lower(source).unwrap_err(),
                    SessionLoweringError::FunctionConstructorClosed
                ),
                "{source}"
            );
        }
    }

    #[test]
    fn shadowed_evaluator_names_and_inert_property_spellings_are_allowed() {
        for source in [
            "const eval = (source: string) => source.length; eval('safe');",
            "const eval = 1; ({ eval });",
            "function local(eval: any, Function: any) { return [eval(), new Function()]; }",
            "{ const eval = 1; const Function = 2; eval + Function; }",
            "const object = { eval: 1, Function() { return 2; } }; object.eval + object.Function();",
            "const object = { eval: 1, Function: 2 }; object['eval'] + object['Function'];",
            "const object = {}; const { eval: localEval, Function: LocalFunction } = object; localEval + LocalFunction;",
            "const globalThis = { eval(x: string) { return x; }, Function: class {} }; globalThis.eval('safe'); new globalThis.Function();",
            "eval: { break eval; } Function: { break Function; }",
            "type Function = { value: number }; const value: Function = { value: 1 }; value;",
            "({ ['eval']: 1, ['Function']: 2 });",
        ] {
            assert!(lower(source).is_ok(), "{source}");
        }

        assert!(lower_with_dialect(
            "const node = <eval Function={1} />; node;",
            ParserDialect::TypeScriptJsx,
        )
        .is_ok());
    }

    #[test]
    fn typescript_jsx_and_source_labels_survive_the_composed_stage() {
        let typescript = lower("enum E { A } E.A;").unwrap();
        assert!(!typescript.source().contains("enum E"));
        assert!(typescript.source().contains("reference(\"E\""));

        let jsx = lower_with_dialect(
            "const node = <View value={answer} />;",
            ParserDialect::TypeScriptJsx,
        )
        .unwrap();
        assert!(!jsx.source().contains("<View"), "{}", jsx.source());
        assert!(jsx.source().contains("createElement"), "{}", jsx.source());
        assert!(
            jsx.source().contains("reference(\"React\""),
            "{}",
            jsx.source()
        );

        let map: serde_json::Value = serde_json::from_slice(jsx.source_map()).unwrap();
        assert_eq!(map["version"], 3);
        assert_eq!(map["sources"][0], "repl:17");
        assert!(map["mappings"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
    }

    #[test]
    fn multiline_throw_position_survives_types_import_tla_and_session_lowering() {
        let source = "import './dependency.js';\nlet answer: number = 41;\nawait Promise.resolve(answer);\nthrow new Error(\"boom\");";
        let lowered = lower(source).unwrap();
        assert!(lowered.is_asynchronous());

        let (generated_line, generated_column) = generated_position(lowered.source(), "\"boom\"");
        let map = crate::engine::sourcemap::SourceMap::from_bytes(lowered.source_map())
            .expect("lowered in-memory source map");
        let (label, original_line, original_column) = map
            .lookup(generated_line, generated_column)
            .expect("throw marker mapping");
        let expected_column = source.lines().nth(3).unwrap().find("\"boom\"").unwrap() as u32 + 1;

        assert_eq!(label, "repl:17");
        assert_eq!(original_line, 4);
        assert_eq!(original_column, expected_column);
    }

    #[test]
    fn top_level_await_and_static_imports_lower_as_sloppy_script_extensions() {
        let await_program = lower("await Promise.resolve(1)").unwrap();
        assert!(await_program.is_asynchronous());
        assert!(!await_program.is_strict());
        assert!(await_program.source().starts_with("async ("));

        let imported = lower(
            "import value, { x as y } from './x.js'; import * as ns from './n.js'; await value(y, ns);",
        )
        .unwrap();
        let source = imported.source();
        assert!(!source.contains("require("), "{source}");
        assert!(!source.contains("initialize(\"value\")"), "{source}");
        assert_eq!(imported.static_imports().len(), 2);
        assert_eq!(&*imported.static_imports()[0].specifier, "./x.js");
        assert_eq!(imported.static_imports()[0].bindings.len(), 2);
        assert_eq!(
            imported.static_imports()[0].bindings[0].local.as_deref(),
            Some("value")
        );
        assert_eq!(
            imported.static_imports()[0].bindings[1].imported.as_deref(),
            Some("x")
        );
        assert_eq!(
            imported.static_imports()[1].bindings[0].kind,
            LoweredStaticImportBindingKind::Namespace
        );
        assert_eq!(
            imported
                .declarations()
                .iter()
                .filter(|declaration| declaration.kind == LoweredDeclarationKind::Import)
                .count(),
            3
        );

        let map: serde_json::Value = serde_json::from_slice(imported.source_map()).unwrap();
        assert_eq!(map["sources"][0], "repl:17");
        assert!(map["mappings"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
    }

    #[test]
    fn every_generated_grant_spelling_is_refused_in_static_and_runtime_forms() {
        for key in super::super::import_grants::RESERVED_IMPORT_GRANT_KEYS {
            for source in [
                format!("import value from './x.js' with {{ {key}: 'x' }}; value"),
                format!("require('./x.js', {{ {key}: 'x' }})"),
                format!("import('./x.js', {{ with: {{ {key}: 'x' }} }})"),
            ] {
                assert!(
                    matches!(
                        lower(&source),
                        Err(SessionLoweringError::ReservedImportGrantAttribute { key: ref found })
                            if found == key
                    ),
                    "{source}"
                );
            }
            for source in [
                format!("export {{ value }} from './x.js' with {{ {key}: 'x' }}"),
                format!("export * from './x.js' with {{ {key}: 'x' }}"),
            ] {
                assert!(
                    matches!(
                        lower_checked_source_with_module_meta(
                            SyntaxRequest {
                                dialect: ParserDialect::JavaScript,
                                goal: SourceGoal::Module,
                                role: SourceRole::Entry,
                            },
                            &source,
                            "ibex:stdin",
                            true,
                            None,
                        ),
                        Err(SessionLoweringError::ReservedImportGrantAttribute { key: ref found })
                            if found == key
                    ),
                    "{source}"
                );
            }
        }
    }

    #[test]
    fn runtime_option_bags_are_recursively_data_only_and_shadowing_is_respected() {
        for source in [
            "require('./x', options)",
            "import('./x', options)",
            "require('./x', { get needs() { return 'x' } })",
            "require('./x', { ...options })",
            "import('./x', { with: { [key]: 'x' } })",
            "import('./x', { with: { needs: compute() } })",
        ] {
            assert!(
                matches!(
                    lower(source),
                    Err(SessionLoweringError::ImportOptionsNotDataOnly)
                ),
                "{source}"
            );
        }

        let ordinary = lower(
            "require('./data.json', { type: 'json' }); import('./data.json', { with: { type: 'json' } });",
        )
        .unwrap();
        assert!(!ordinary.source().contains("type: \"json\""));
        assert!(ordinary.source().contains("dynamicImport"));
        assert!(!ordinary.source().contains("importModule"));

        // A lexical parameter named `require` is not the runtime loader and is
        // therefore outside this syntactic refusal.
        lower("function invoke(require, options) { return require('./x', options) }").unwrap();
    }

    #[test]
    fn module_entry_lowers_exports_tla_import_meta_and_strict_top_level_this() {
        let lowered = lower_checked_source_with_module_meta(
            SyntaxRequest {
                dialect: ParserDialect::TypeScript,
                goal: SourceGoal::Module,
                role: SourceRole::Entry,
            },
            "import data from './data.json' with { type: 'json' }; export const named = 1; export default function chosen() {} export { value as forwarded } from './dep.js'; export * from './all.js'; export * as namespace from './ns.js'; const facts = [data, named, chosen, import.meta.main, import.meta.url, import.meta.file, this]; await Promise.resolve(facts);",
            "ibex:stdin",
            true,
            None,
        )
        .unwrap();
        assert!(lowered.is_asynchronous());
        assert!(lowered.is_strict());
        assert!(lowered.source().contains("\"use strict\""));
        assert!(lowered.source().contains("ibex:stdin"));
        assert!(!lowered.source().contains("require("));
        assert_eq!(
            lowered
                .static_imports()
                .iter()
                .map(|import| import.specifier.as_ref())
                .collect::<Vec<_>>(),
            vec!["./data.json", "./dep.js", "./all.js", "./ns.js"]
        );
        assert!(lowered.static_imports()[1].bindings[0].local.is_none());
        assert_eq!(
            lowered.static_imports()[1].bindings[0].imported.as_deref(),
            Some("value")
        );
        assert!(lowered
            .declarations()
            .iter()
            .any(|declaration| declaration.name.as_ref() == "chosen"));
        assert!(!lowered.source().contains("import.meta"));
        assert!(lowered.source().contains("file: \"\""));
        assert!(!lowered.source().contains("type: \"json\""));
        assert!(lowered.source().contains("void 0"));

        let file_backed = lower_checked_source_with_module_meta(
            SyntaxRequest {
                dialect: ParserDialect::JavaScript,
                goal: SourceGoal::Module,
                role: SourceRole::Entry,
            },
            "[import.meta.path, import.meta.filename, import.meta.file, import.meta.dirname, import.meta.dir]",
            "file:///project/src/entry.mjs",
            true,
            Some("/project/src/entry.mjs"),
        )
        .unwrap();
        for expected in ["/project/src/entry.mjs", "entry.mjs", "/project/src"] {
            assert!(file_backed.source().contains(expected), "{expected}");
        }
    }
}
