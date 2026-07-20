//! Parser-backed syntax frontend for structured session evaluation.
//!
//! The pinned SWC parser has Script and Module goals, but not LLP 0024's
//! sloppy Script goal extended with static imports and top-level await. The
//! frontend therefore runs an independent Script validator over a same-width
//! source in which only static import declarations are blanked, while a Module
//! parse supplies the extension nodes. Module strict diagnostics never decide
//! whether the Script body is accepted.
//!
//! @ref LLP 0024#3-source-goal — Script+extensions must preserve Script early
//! errors and sloppy semantics; Module-goal parsing is not a substitute.
//! @ref LLP 0024#4-grammar-selection — dialect is selected strictly by source
//! surface/extension and the in-process SWC parser is the named authority.
//! @ref LLP 0024#5-completeness — continuation uses parser error kinds rather
//! than delimiter counting and ambiguous cases fail safe as syntax errors.

use std::fmt;
use std::path::Path;

use swc_common::sync::Lrc;
use swc_common::{FileName, SourceMap, Span, Spanned};
use swc_ecma_ast::{
    ArrowExpr, Class, ClassExpr, Decl, DefaultDecl, ExportAll, ExportSpecifier, FnDecl, FnExpr,
    Function, Ident, ImportDecl, ImportNamedSpecifier, ImportSpecifier, MetaPropExpr, MetaPropKind,
    Module, ModuleDecl, ModuleExportName, ModuleItem, NamedExport, ObjectPatProp, Pat, Program,
    Script, Stmt, TsModuleName, VarDecl, VarDeclKind,
};
use swc_ecma_parser::error::{Error as SwcError, SyntaxError as SwcSyntaxError};
use swc_ecma_parser::{lexer::Lexer, EsSyntax, Parser, StringInput, Syntax, TsSyntax};
use swc_ecma_visit::{Visit, VisitWith};
use thiserror::Error;

use super::evaluation::{ParserDialect, SourceGoal, SourceRole};

/// Version fixed by `Cargo.toml` and `Cargo.lock` for the session grammar.
pub const PINNED_SWC_ECMA_PARSER_VERSION: &str = "41.0.1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilePurpose {
    Load,
    Dependency,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyntaxOrigin<'a> {
    Extensionless,
    File {
        path: &'a Path,
        purpose: FilePurpose,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialectSelection {
    Program(ParserDialect),
    JsonData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParserGoal {
    Script,
    Module,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntaxRequest {
    pub dialect: ParserDialect,
    pub goal: SourceGoal,
    pub role: SourceRole,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParserDiagnostic {
    pub code: &'static str,
    pub message: String,
    pub range: ByteRange,
}

impl fmt::Display for ParserDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at bytes {}..{}: {}",
            self.code, self.range.start, self.range.end, self.message
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncompleteReason {
    UnexpectedEof,
    UnterminatedBlockComment,
    UnterminatedString,
    UnterminatedTemplate,
    UnterminatedRegularExpression,
    UnterminatedJsx,
    IncompleteTypeScriptProduction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Completeness {
    Complete,
    Incomplete {
        reason: IncompleteReason,
        diagnostic: ParserDiagnostic,
    },
    SyntaxError(ParserDiagnostic),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticImportBindingKind {
    Default,
    Named,
    Namespace,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticImportBinding {
    pub kind: StaticImportBindingKind,
    /// Session-cell name for an ordinary import. Re-export validation rows
    /// deliberately have no local cell: they materialize the dependency (and
    /// named/default Get) during phase 4, then discard the value.
    pub local: Option<String>,
    pub imported: Option<String>,
    pub type_only: bool,
    pub range: ByteRange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticImport {
    /// Source-order ordinal among static `ImportDeclaration`s.
    pub order: usize,
    pub specifier: String,
    pub type_only: bool,
    pub bindings: Vec<StaticImportBinding>,
    pub range: ByteRange,
}

/// Kinds consumed by the executable LLP 0024 section-7 model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionDeclarationKind {
    Var,
    Function,
    Let,
    Const,
    Class,
    Import,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeclarationOrigin {
    UserAuthored,
    /// A user-authored TypeScript runtime declaration which becomes `var`
    /// after type stripping (`enum`, value namespace, or `import =`).
    TypeScriptRuntime,
    /// A sloppy block function whose exact publication is owned by the Annex-B
    /// lowering. It is kept distinct rather than silently treated as ordinary
    /// top-level syntax.
    AnnexB,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeclarationPlacement {
    TopLevel,
    VarHoistedFromNestedStatement,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionDeclaration {
    pub name: String,
    pub kind: SessionDeclarationKind,
    pub origin: DeclarationOrigin,
    pub placement: DeclarationPlacement,
    pub range: ByteRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopLevelUsing {
    Using,
    AwaitUsing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntaxOutline {
    pub parser_goal: ParserGoal,
    pub top_level_await: bool,
    pub static_imports: Vec<StaticImport>,
    /// Duplicates and source order are preserved for section-7 collision and
    /// initialization-order checks.
    pub declarations: Vec<SessionDeclaration>,
    pub has_import_meta: bool,
    pub has_exports: bool,
    pub top_level_using: Option<TopLevelUsing>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntaxAnalysis {
    pub strict_by_default: bool,
    pub outline: SyntaxOutline,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedGoal {
    pub code: &'static str,
    pub required_goal: SourceGoal,
    pub parser_goal_used_for_outline: Option<ParserGoal>,
    pub outline: Option<SyntaxOutline>,
    /// Diagnostics from the non-authoritative Module attempt. They explain why
    /// an outline may be absent, but never reclassify the source as invalid
    /// under the unavailable Script+extensions goal.
    pub parser_diagnostics: Vec<ParserDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyntaxFrontendResult {
    Ready(SyntaxAnalysis),
    UnsupportedGoal(UnsupportedGoal),
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SyntaxFrontendError {
    #[error(".load refuses the module-kind-asserting extension {extension}")]
    LoadModuleKindAssertion { extension: String },
    #[error("declaration file {path} is not executable source")]
    DeclarationFileNotExecutable { path: String },
    #[error(".load refuses extensionless file {path}")]
    ExtensionlessLoad { path: String },
    #[error("source file {path} has unsupported extension {extension}")]
    UnknownExtension { path: String, extension: String },
    #[error("source file name is not valid UTF-8")]
    NonUtf8FileName,
    #[error("JSON is data and cannot be submitted to the program parser")]
    JsonIsNotProgram,
    #[error("Script+extensions is entry-only")]
    InvalidGoalRole,
    #[error("top-level await is unsupported in dependency {label}")]
    DependencyTopLevelAwait { label: String },
    #[error("top-level using is unsupported in a session script")]
    TopLevelUsingNotSupported,
    #[error("top-level await using is unsupported in a session script")]
    TopLevelAwaitUsingNotSupported,
    #[error("await is reserved as an identifier at the top level of a session script")]
    TopLevelAwaitIdentifierReserved,
    #[error("export syntax is not allowed in a session script")]
    ScriptExportNotAllowed,
    #[error("import.meta is not allowed in a session script")]
    ScriptImportMetaNotAllowed,
    #[error("import specifier cannot be represented as UTF-8")]
    NonUtf8ImportSpecifier,
    #[error("imported binding name cannot be represented as UTF-8")]
    NonUtf8ImportName,
    #[error("{diagnostic}")]
    ParserSyntax { diagnostic: ParserDiagnostic },
}

impl SyntaxFrontendError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::LoadModuleKindAssertion { .. } => "IBEX_LOAD_MODULE_KIND_ASSERTION",
            Self::DeclarationFileNotExecutable { .. } => "IBEX_DECLARATION_FILE_NOT_EXECUTABLE",
            Self::ExtensionlessLoad { .. } => "IBEX_EXTENSIONLESS_LOAD_REFUSED",
            Self::UnknownExtension { .. } => "IBEX_UNKNOWN_SOURCE_EXTENSION",
            Self::NonUtf8FileName => "IBEX_NON_UTF8_SOURCE_NAME",
            Self::JsonIsNotProgram => "IBEX_JSON_IS_NOT_PROGRAM",
            Self::InvalidGoalRole => "IBEX_INVALID_SOURCE_GOAL_ROLE",
            Self::DependencyTopLevelAwait { .. } => "IBEX_DEPENDENCY_TOP_LEVEL_AWAIT",
            Self::TopLevelUsingNotSupported => "IBEX_TOP_LEVEL_USING_NOT_SUPPORTED",
            Self::TopLevelAwaitUsingNotSupported => "IBEX_TOP_LEVEL_AWAIT_USING_NOT_SUPPORTED",
            Self::TopLevelAwaitIdentifierReserved => "IBEX_TOP_LEVEL_AWAIT_IDENTIFIER_RESERVED",
            Self::ScriptExportNotAllowed => "IBEX_SCRIPT_EXPORT_NOT_ALLOWED",
            Self::ScriptImportMetaNotAllowed => "IBEX_SCRIPT_IMPORT_META_NOT_ALLOWED",
            Self::NonUtf8ImportSpecifier => "IBEX_NON_UTF8_IMPORT_SPECIFIER",
            Self::NonUtf8ImportName => "IBEX_NON_UTF8_IMPORT_NAME",
            Self::ParserSyntax { .. } => "IBEX_PARSER_SYNTAX_ERROR",
        }
    }
}

/// Select the grammar without inspecting source bytes.
pub fn select_dialect(origin: SyntaxOrigin<'_>) -> Result<DialectSelection, SyntaxFrontendError> {
    match origin {
        SyntaxOrigin::Extensionless => Ok(DialectSelection::Program(ParserDialect::TypeScript)),
        SyntaxOrigin::File { path, purpose } => {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or(SyntaxFrontendError::NonUtf8FileName)?;
            let lower_name = name.to_ascii_lowercase();
            let display = path.display().to_string();
            if lower_name.ends_with(".d.ts") {
                return Err(SyntaxFrontendError::DeclarationFileNotExecutable { path: display });
            }
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if extension.is_empty() {
                return match purpose {
                    FilePurpose::Load => {
                        Err(SyntaxFrontendError::ExtensionlessLoad { path: display })
                    }
                    FilePurpose::Dependency => Err(SyntaxFrontendError::UnknownExtension {
                        path: display,
                        extension: "<extensionless>".into(),
                    }),
                };
            }
            if purpose == FilePurpose::Load
                && matches!(extension.as_str(), "mjs" | "cjs" | "mts" | "cts")
            {
                return Err(SyntaxFrontendError::LoadModuleKindAssertion {
                    extension: format!(".{extension}"),
                });
            }
            let selection = match extension.as_str() {
                "js" | "mjs" | "cjs" => DialectSelection::Program(ParserDialect::JavaScript),
                "jsx" => DialectSelection::Program(ParserDialect::JavaScriptJsx),
                "ts" | "mts" | "cts" => DialectSelection::Program(ParserDialect::TypeScript),
                "tsx" => DialectSelection::Program(ParserDialect::TypeScriptJsx),
                "json" => DialectSelection::JsonData,
                _ => {
                    return Err(SyntaxFrontendError::UnknownExtension {
                        path: display,
                        extension: format!(".{extension}"),
                    });
                }
            };
            Ok(selection)
        }
    }
}

pub(super) fn syntax_for_lowering(dialect: ParserDialect) -> Syntax {
    match dialect {
        ParserDialect::JavaScript => Syntax::Es(EsSyntax {
            explicit_resource_management: true,
            ..Default::default()
        }),
        ParserDialect::JavaScriptJsx => Syntax::Es(EsSyntax {
            jsx: true,
            explicit_resource_management: true,
            ..Default::default()
        }),
        ParserDialect::TypeScript => Syntax::Typescript(TsSyntax {
            decorators: true,
            ..Default::default()
        }),
        ParserDialect::TypeScriptJsx => Syntax::Typescript(TsSyntax {
            tsx: true,
            decorators: true,
            ..Default::default()
        }),
    }
}

#[derive(Debug)]
struct ParseAttempt {
    program: Option<Program>,
    issues: Vec<SwcError>,
    start_pos: u32,
    end_pos: u32,
}

fn parse(source: &str, dialect: ParserDialect, goal: ParserGoal) -> ParseAttempt {
    let source_map: Lrc<SourceMap> = Default::default();
    let source_file = source_map.new_source_file(
        Lrc::new(FileName::Custom("session-input".into())),
        source.to_owned(),
    );
    let start_pos = source_file.start_pos.0;
    let end_pos = source_file.end_pos.0;
    let lexer = Lexer::new(
        syntax_for_lowering(dialect),
        swc_ecma_ast::EsVersion::Es2022,
        StringInput::from(&*source_file),
        None,
    );
    let mut parser = Parser::new_from(lexer);
    let parsed = match goal {
        ParserGoal::Script => parser.parse_script().map(Program::Script),
        ParserGoal::Module => parser.parse_module().map(Program::Module),
    };
    let mut issues = parser.take_errors();
    let program = match parsed {
        Ok(program) => Some(program),
        Err(error) => {
            issues.push(error);
            None
        }
    };
    issues.sort_by_key(|error| (error.span().lo.0, error.span().hi.0));
    ParseAttempt {
        program,
        issues,
        start_pos,
        end_pos,
    }
}

fn byte_range(span: Span, attempt: &ParseAttempt) -> ByteRange {
    let source_len = attempt.end_pos.saturating_sub(attempt.start_pos) as usize;
    ByteRange {
        start: span.lo.0.saturating_sub(attempt.start_pos) as usize,
        end: (span.hi.0.saturating_sub(attempt.start_pos) as usize).min(source_len),
    }
}

fn parser_diagnostic(error: &SwcError, attempt: &ParseAttempt) -> ParserDiagnostic {
    ParserDiagnostic {
        code: "IBEX_PARSER_SYNTAX_ERROR",
        message: error.kind().msg().into_owned(),
        range: byte_range(error.span(), attempt),
    }
}

fn parser_error(attempt: &ParseAttempt) -> SyntaxFrontendError {
    let error = attempt
        .issues
        .first()
        .expect("parser_error requires at least one parser issue");
    SyntaxFrontendError::ParserSyntax {
        diagnostic: parser_diagnostic(error, attempt),
    }
}

fn extension_goal_error(kind: &SwcSyntaxError) -> bool {
    matches!(
        kind,
        SwcSyntaxError::TopLevelAwaitInScript | SwcSyntaxError::ImportExportInScript
    )
}

fn script_import_meta_error(kind: &SwcSyntaxError) -> bool {
    matches!(kind, SwcSyntaxError::ImportMetaInScript)
}

fn script_export_error(kind: &SwcSyntaxError) -> bool {
    matches!(kind, SwcSyntaxError::ExportNotAllowed)
}

fn incomplete_reason(error: &SwcError, attempt: &ParseAttempt) -> Option<IncompleteReason> {
    use SwcSyntaxError as E;
    let at_eof = error.span().hi.0 >= attempt.end_pos;
    match error.kind() {
        E::Eof => Some(IncompleteReason::UnexpectedEof),
        E::UnterminatedBlockComment => Some(IncompleteReason::UnterminatedBlockComment),
        E::UnterminatedStrLit => Some(IncompleteReason::UnterminatedString),
        E::UnterminatedTpl => Some(IncompleteReason::UnterminatedTemplate),
        E::UnterminatedRegExp => Some(IncompleteReason::UnterminatedRegularExpression),
        E::UnterminatedJSXContents
        | E::JSXExpectedClosingTagForLtGt
        | E::JSXExpectedClosingTag { .. } => Some(IncompleteReason::UnterminatedJsx),
        // SWC reports an unmatched delimiter as `Unexpected { got:
        // "<eof>" }`, but its zero-width span may sit just before the source
        // file's end position. The token kind, not that implementation detail,
        // is the parser-grade continuation signal.
        E::Unexpected { got, .. } if got.to_ascii_lowercase().contains("eof") => {
            Some(IncompleteReason::UnexpectedEof)
        }
        E::Expected(_, got) if got.to_ascii_lowercase().contains("eof") => {
            Some(IncompleteReason::UnexpectedEof)
        }
        E::TS1005 | E::TS1109 | E::TS1110 if at_eof && error.span().lo.0 == error.span().hi.0 => {
            Some(IncompleteReason::IncompleteTypeScriptProduction)
        }
        _ => None,
    }
}

/// Classify whether the editor should request another line. Goal-only errors
/// are complete submissions: the syntax frontend must issue their named
/// refusal instead of trapping the operator in continuation mode.
pub fn classify_completeness(request: SyntaxRequest, source: &str) -> Completeness {
    let parser_goal = match request.goal {
        SourceGoal::ScriptWithExtensions => ParserGoal::Script,
        SourceGoal::Module => ParserGoal::Module,
    };
    let attempt = parse(source, request.dialect, parser_goal);
    if attempt.issues.is_empty() {
        return Completeness::Complete;
    }

    let mut first_incomplete = None;
    let mut first_definite = None;
    for error in &attempt.issues {
        if let Some(reason) = incomplete_reason(error, &attempt) {
            first_incomplete.get_or_insert((error, reason));
        } else if !extension_goal_error(error.kind())
            && !script_import_meta_error(error.kind())
            && !script_export_error(error.kind())
        {
            first_definite.get_or_insert(error);
        }
    }
    if let Some((error, reason)) = first_incomplete {
        let incomplete_starts_first = first_definite
            // A definite error at the same byte makes the submission
            // ambiguous. LLP 0024 requires those to submit as a recoverable
            // syntax error instead of trapping the caller in continuation.
            .map(|definite| error.span().lo.0 < definite.span().lo.0)
            .unwrap_or(true);
        if incomplete_starts_first {
            return Completeness::Incomplete {
                reason,
                diagnostic: parser_diagnostic(error, &attempt),
            };
        }
    }
    if let Some(error) = first_definite {
        Completeness::SyntaxError(parser_diagnostic(error, &attempt))
    } else {
        Completeness::Complete
    }
}

#[derive(Default)]
struct FeatureVisitor {
    top_level_await: bool,
    import_meta: bool,
    top_level_await_identifier: bool,
}

impl Visit for FeatureVisitor {
    fn visit_await_expr(&mut self, expression: &swc_ecma_ast::AwaitExpr) {
        self.top_level_await = true;
        expression.arg.visit_with(self);
    }

    fn visit_meta_prop_expr(&mut self, expression: &MetaPropExpr) {
        if expression.kind == MetaPropKind::ImportMeta {
            self.import_meta = true;
        }
    }

    fn visit_ident(&mut self, identifier: &Ident) {
        if identifier.sym == *"await" {
            self.top_level_await_identifier = true;
        }
    }

    // An imported export name is a property-like name, not a local identifier.
    // Only the local half participates in the session's reserved-word rule.
    fn visit_import_named_specifier(&mut self, specifier: &ImportNamedSpecifier) {
        specifier.local.visit_with(self);
    }

    // Await and await-named bindings inside a function are not top-level.
    fn visit_function(&mut self, _function: &Function) {}

    fn visit_arrow_expr(&mut self, _function: &ArrowExpr) {}

    // The optional name of a function expression is local to that function.
    fn visit_fn_expr(&mut self, _function: &FnExpr) {}

    // The optional name of a class expression is local to that class. Still
    // inspect the class itself: computed keys and static initializers execute
    // in the surrounding top-level evaluation context.
    fn visit_class_expr(&mut self, expression: &ClassExpr) {
        expression.class.visit_with(self);
    }
}

fn top_level_using_in_script(script: &Script) -> Option<TopLevelUsing> {
    script.body.iter().find_map(|statement| match statement {
        Stmt::Decl(Decl::Using(declaration)) => Some(if declaration.is_await {
            TopLevelUsing::AwaitUsing
        } else {
            TopLevelUsing::Using
        }),
        _ => None,
    })
}

fn top_level_using_in_module(module: &Module) -> Option<TopLevelUsing> {
    module.body.iter().find_map(|item| match item {
        ModuleItem::Stmt(Stmt::Decl(Decl::Using(declaration))) => Some(if declaration.is_await {
            TopLevelUsing::AwaitUsing
        } else {
            TopLevelUsing::Using
        }),
        _ => None,
    })
}

fn push_pattern_bindings(
    pattern: &Pat,
    kind: SessionDeclarationKind,
    origin: DeclarationOrigin,
    placement: DeclarationPlacement,
    start_pos: u32,
    output: &mut Vec<SessionDeclaration>,
) {
    match pattern {
        Pat::Ident(binding) => output.push(SessionDeclaration {
            name: binding.id.sym.to_string(),
            kind,
            origin,
            placement,
            range: relative_span(binding.id.span, start_pos),
        }),
        Pat::Array(array) => {
            for element in array.elems.iter().flatten() {
                push_pattern_bindings(element, kind, origin, placement, start_pos, output);
            }
        }
        Pat::Object(object) => {
            for property in &object.props {
                match property {
                    ObjectPatProp::KeyValue(property) => push_pattern_bindings(
                        &property.value,
                        kind,
                        origin,
                        placement,
                        start_pos,
                        output,
                    ),
                    ObjectPatProp::Assign(property) => output.push(SessionDeclaration {
                        name: property.key.id.sym.to_string(),
                        kind,
                        origin,
                        placement,
                        range: relative_span(property.key.id.span, start_pos),
                    }),
                    ObjectPatProp::Rest(rest) => {
                        push_pattern_bindings(&rest.arg, kind, origin, placement, start_pos, output)
                    }
                }
            }
        }
        Pat::Assign(assignment) => {
            push_pattern_bindings(&assignment.left, kind, origin, placement, start_pos, output)
        }
        Pat::Rest(rest) => {
            push_pattern_bindings(&rest.arg, kind, origin, placement, start_pos, output)
        }
        Pat::Invalid(_) | Pat::Expr(_) => {}
    }
}

fn relative_span(span: Span, start_pos: u32) -> ByteRange {
    ByteRange {
        start: span.lo.0.saturating_sub(start_pos) as usize,
        end: span.hi.0.saturating_sub(start_pos) as usize,
    }
}

fn collect_var_declaration(
    declaration: &VarDecl,
    origin: DeclarationOrigin,
    placement: DeclarationPlacement,
    start_pos: u32,
    output: &mut Vec<SessionDeclaration>,
) {
    if declaration.declare {
        return;
    }
    let kind = match declaration.kind {
        VarDeclKind::Var => SessionDeclarationKind::Var,
        VarDeclKind::Let => SessionDeclarationKind::Let,
        VarDeclKind::Const => SessionDeclarationKind::Const,
    };
    for declarator in &declaration.decls {
        push_pattern_bindings(&declarator.name, kind, origin, placement, start_pos, output);
    }
}

fn collect_direct_declaration(
    declaration: &Decl,
    start_pos: u32,
    output: &mut Vec<SessionDeclaration>,
) {
    match declaration {
        Decl::Var(declaration) => collect_var_declaration(
            declaration,
            DeclarationOrigin::UserAuthored,
            DeclarationPlacement::TopLevel,
            start_pos,
            output,
        ),
        Decl::Fn(declaration) if !declaration.declare => output.push(SessionDeclaration {
            name: declaration.ident.sym.to_string(),
            kind: SessionDeclarationKind::Function,
            origin: DeclarationOrigin::UserAuthored,
            placement: DeclarationPlacement::TopLevel,
            range: relative_span(declaration.ident.span, start_pos),
        }),
        Decl::Class(declaration) if !declaration.declare => output.push(SessionDeclaration {
            name: declaration.ident.sym.to_string(),
            kind: SessionDeclarationKind::Class,
            origin: DeclarationOrigin::UserAuthored,
            placement: DeclarationPlacement::TopLevel,
            range: relative_span(declaration.ident.span, start_pos),
        }),
        Decl::TsEnum(declaration) if !declaration.declare => {
            output.push(SessionDeclaration {
                name: declaration.id.sym.to_string(),
                kind: SessionDeclarationKind::Var,
                origin: DeclarationOrigin::TypeScriptRuntime,
                placement: DeclarationPlacement::TopLevel,
                range: relative_span(declaration.id.span, start_pos),
            });
        }
        Decl::TsModule(declaration) if !declaration.declare && !declaration.global => {
            if let TsModuleName::Ident(identifier) = &declaration.id {
                output.push(SessionDeclaration {
                    name: identifier.sym.to_string(),
                    kind: SessionDeclarationKind::Var,
                    origin: DeclarationOrigin::TypeScriptRuntime,
                    placement: DeclarationPlacement::TopLevel,
                    range: relative_span(identifier.span, start_pos),
                });
            }
        }
        Decl::Class(_)
        | Decl::Fn(_)
        | Decl::Using(_)
        | Decl::TsInterface(_)
        | Decl::TsTypeAlias(_)
        | Decl::TsEnum(_)
        | Decl::TsModule(_) => {}
    }
}

struct NestedVarCollector<'a> {
    start_pos: u32,
    output: &'a mut Vec<SessionDeclaration>,
    collect_annex_b_functions: bool,
}

impl Visit for NestedVarCollector<'_> {
    fn visit_var_decl(&mut self, declaration: &VarDecl) {
        if declaration.kind == VarDeclKind::Var {
            collect_var_declaration(
                declaration,
                DeclarationOrigin::UserAuthored,
                DeclarationPlacement::VarHoistedFromNestedStatement,
                self.start_pos,
                self.output,
            );
        }
        declaration.visit_children_with(self);
    }

    fn visit_fn_decl(&mut self, declaration: &FnDecl) {
        if self.collect_annex_b_functions && !declaration.declare {
            self.output.push(SessionDeclaration {
                name: declaration.ident.sym.to_string(),
                kind: SessionDeclarationKind::Function,
                origin: DeclarationOrigin::AnnexB,
                placement: DeclarationPlacement::VarHoistedFromNestedStatement,
                range: relative_span(declaration.ident.span, self.start_pos),
            });
        }
        // Never collect declarations from the function's own scope.
    }

    fn visit_function(&mut self, _function: &Function) {}

    fn visit_arrow_expr(&mut self, _function: &ArrowExpr) {}

    fn visit_class(&mut self, _class: &Class) {}
}

fn collect_script_declarations(script: &Script, start_pos: u32) -> Vec<SessionDeclaration> {
    let mut output = Vec::new();
    let strict = script
        .body
        .iter()
        .take_while(|statement| statement.can_precede_directive())
        .any(Stmt::is_use_strict);
    for statement in &script.body {
        if let Stmt::Decl(declaration) = statement {
            collect_direct_declaration(declaration, start_pos, &mut output);
        } else {
            statement.visit_with(&mut NestedVarCollector {
                start_pos,
                output: &mut output,
                collect_annex_b_functions: !strict,
            });
        }
    }
    output
}

fn module_export_name(name: &ModuleExportName) -> Result<String, SyntaxFrontendError> {
    match name {
        ModuleExportName::Ident(identifier) => Ok(identifier.sym.to_string()),
        ModuleExportName::Str(string) => string
            .value
            .as_str()
            .map(str::to_owned)
            .ok_or(SyntaxFrontendError::NonUtf8ImportName),
    }
}

fn static_import(
    declaration: &ImportDecl,
    order: usize,
    start_pos: u32,
) -> Result<StaticImport, SyntaxFrontendError> {
    let specifier = declaration
        .src
        .value
        .as_str()
        .map(str::to_owned)
        .ok_or(SyntaxFrontendError::NonUtf8ImportSpecifier)?;
    let bindings = declaration
        .specifiers
        .iter()
        .map(|specifier| match specifier {
            ImportSpecifier::Default(default) => Ok(StaticImportBinding {
                kind: StaticImportBindingKind::Default,
                local: Some(default.local.sym.to_string()),
                imported: Some("default".into()),
                type_only: declaration.type_only,
                range: relative_span(default.local.span, start_pos),
            }),
            ImportSpecifier::Namespace(namespace) => Ok(StaticImportBinding {
                kind: StaticImportBindingKind::Namespace,
                local: Some(namespace.local.sym.to_string()),
                imported: None,
                type_only: declaration.type_only,
                range: relative_span(namespace.local.span, start_pos),
            }),
            ImportSpecifier::Named(named) => Ok(StaticImportBinding {
                kind: StaticImportBindingKind::Named,
                local: Some(named.local.sym.to_string()),
                imported: Some(match &named.imported {
                    Some(imported) => module_export_name(imported)?,
                    None => named.local.sym.to_string(),
                }),
                type_only: declaration.type_only || named.is_type_only,
                range: relative_span(named.local.span, start_pos),
            }),
        })
        .collect::<Result<Vec<_>, SyntaxFrontendError>>()?;
    Ok(StaticImport {
        order,
        specifier,
        type_only: declaration.type_only,
        bindings,
        range: relative_span(declaration.span, start_pos),
    })
}

fn static_reexport_named(
    declaration: &NamedExport,
    order: usize,
    start_pos: u32,
) -> Result<StaticImport, SyntaxFrontendError> {
    let source = declaration
        .src
        .as_ref()
        .expect("re-export helper requires a source");
    let specifier = source
        .value
        .as_str()
        .map(str::to_owned)
        .ok_or(SyntaxFrontendError::NonUtf8ImportSpecifier)?;
    let bindings = declaration
        .specifiers
        .iter()
        .map(|export| match export {
            ExportSpecifier::Namespace(namespace) => Ok(StaticImportBinding {
                kind: StaticImportBindingKind::Namespace,
                local: None,
                imported: None,
                type_only: declaration.type_only,
                range: relative_span(namespace.span, start_pos),
            }),
            ExportSpecifier::Default(default) => Ok(StaticImportBinding {
                kind: StaticImportBindingKind::Default,
                local: None,
                imported: Some("default".into()),
                type_only: declaration.type_only,
                range: relative_span(default.exported.span, start_pos),
            }),
            ExportSpecifier::Named(named) => Ok(StaticImportBinding {
                kind: StaticImportBindingKind::Named,
                local: None,
                imported: Some(module_export_name(&named.orig)?),
                type_only: declaration.type_only || named.is_type_only,
                range: relative_span(named.span, start_pos),
            }),
        })
        .collect::<Result<Vec<_>, SyntaxFrontendError>>()?;
    Ok(StaticImport {
        order,
        specifier,
        type_only: declaration.type_only,
        bindings,
        range: relative_span(declaration.span, start_pos),
    })
}

fn static_reexport_all(
    declaration: &ExportAll,
    order: usize,
    start_pos: u32,
) -> Result<StaticImport, SyntaxFrontendError> {
    let specifier = declaration
        .src
        .value
        .as_str()
        .map(str::to_owned)
        .ok_or(SyntaxFrontendError::NonUtf8ImportSpecifier)?;
    Ok(StaticImport {
        order,
        specifier,
        type_only: declaration.type_only,
        bindings: Vec::new(),
        range: relative_span(declaration.span, start_pos),
    })
}

fn collect_module_declarations(module: &Module, start_pos: u32) -> Vec<SessionDeclaration> {
    let mut output = Vec::new();
    for item in &module.body {
        match item {
            ModuleItem::Stmt(Stmt::Decl(declaration)) => {
                collect_direct_declaration(declaration, start_pos, &mut output);
            }
            ModuleItem::Stmt(statement) => statement.visit_with(&mut NestedVarCollector {
                start_pos,
                output: &mut output,
                collect_annex_b_functions: false,
            }),
            ModuleItem::ModuleDecl(ModuleDecl::Import(declaration)) => {
                if !declaration.type_only {
                    for specifier in &declaration.specifiers {
                        if !specifier.is_type_only() {
                            output.push(SessionDeclaration {
                                name: specifier.local().sym.to_string(),
                                kind: SessionDeclarationKind::Import,
                                origin: DeclarationOrigin::UserAuthored,
                                placement: DeclarationPlacement::TopLevel,
                                range: relative_span(specifier.local().span, start_pos),
                            });
                        }
                    }
                }
            }
            ModuleItem::ModuleDecl(ModuleDecl::TsImportEquals(declaration))
                if !declaration.is_type_only && !declaration.is_export =>
            {
                output.push(SessionDeclaration {
                    name: declaration.id.sym.to_string(),
                    kind: SessionDeclarationKind::Var,
                    origin: DeclarationOrigin::TypeScriptRuntime,
                    placement: DeclarationPlacement::TopLevel,
                    range: relative_span(declaration.id.span, start_pos),
                });
            }
            ModuleItem::ModuleDecl(ModuleDecl::ExportDecl(export)) => {
                collect_direct_declaration(&export.decl, start_pos, &mut output);
            }
            ModuleItem::ModuleDecl(ModuleDecl::ExportDefaultDecl(export)) => match &export.decl {
                DefaultDecl::Fn(function) => {
                    if let Some(identifier) = &function.ident {
                        output.push(SessionDeclaration {
                            name: identifier.sym.to_string(),
                            kind: SessionDeclarationKind::Function,
                            origin: DeclarationOrigin::UserAuthored,
                            placement: DeclarationPlacement::TopLevel,
                            range: relative_span(identifier.span, start_pos),
                        });
                    }
                }
                DefaultDecl::Class(class) => {
                    if let Some(identifier) = &class.ident {
                        output.push(SessionDeclaration {
                            name: identifier.sym.to_string(),
                            kind: SessionDeclarationKind::Class,
                            origin: DeclarationOrigin::UserAuthored,
                            placement: DeclarationPlacement::TopLevel,
                            range: relative_span(identifier.span, start_pos),
                        });
                    }
                }
                DefaultDecl::TsInterfaceDecl(_) => {}
            },
            ModuleItem::ModuleDecl(_) => {}
        }
    }
    output
}

fn script_outline(script: &Script, start_pos: u32) -> SyntaxOutline {
    let mut features = FeatureVisitor::default();
    script.visit_with(&mut features);
    SyntaxOutline {
        parser_goal: ParserGoal::Script,
        top_level_await: features.top_level_await,
        static_imports: Vec::new(),
        declarations: collect_script_declarations(script, start_pos),
        has_import_meta: features.import_meta,
        has_exports: false,
        top_level_using: top_level_using_in_script(script),
    }
}

fn module_outline(
    module: &Module,
    start_pos: u32,
) -> Result<(SyntaxOutline, bool), SyntaxFrontendError> {
    let mut features = FeatureVisitor::default();
    module.visit_with(&mut features);
    let mut imports = Vec::new();
    let mut has_exports = false;
    for item in &module.body {
        if let ModuleItem::ModuleDecl(declaration) = item {
            match declaration {
                ModuleDecl::Import(import) => {
                    imports.push(static_import(import, imports.len(), start_pos)?);
                }
                ModuleDecl::ExportNamed(export) if export.src.is_some() => {
                    imports.push(static_reexport_named(export, imports.len(), start_pos)?);
                }
                ModuleDecl::ExportAll(export) => {
                    imports.push(static_reexport_all(export, imports.len(), start_pos)?);
                }
                ModuleDecl::TsImportEquals(import) if !import.is_export => {}
                _ => has_exports = true,
            }
        }
    }
    let top_level_using = top_level_using_in_module(module);
    let outline = SyntaxOutline {
        parser_goal: ParserGoal::Module,
        top_level_await: features.top_level_await
            || top_level_using == Some(TopLevelUsing::AwaitUsing),
        static_imports: imports,
        declarations: collect_module_declarations(module, start_pos),
        has_import_meta: features.import_meta,
        has_exports,
        top_level_using,
    };
    Ok((outline, features.top_level_await_identifier))
}

fn validate_script_outline(
    outline: &SyntaxOutline,
    top_level_await_identifier: bool,
) -> Result<(), SyntaxFrontendError> {
    if outline.has_import_meta {
        return Err(SyntaxFrontendError::ScriptImportMetaNotAllowed);
    }
    if outline.has_exports {
        return Err(SyntaxFrontendError::ScriptExportNotAllowed);
    }
    match outline.top_level_using {
        Some(TopLevelUsing::Using) => {
            return Err(SyntaxFrontendError::TopLevelUsingNotSupported);
        }
        Some(TopLevelUsing::AwaitUsing) => {
            return Err(SyntaxFrontendError::TopLevelAwaitUsingNotSupported);
        }
        None => {}
    }
    if top_level_await_identifier {
        return Err(SyntaxFrontendError::TopLevelAwaitIdentifierReserved);
    }
    Ok(())
}

/// Replace static-import bytes with spaces while retaining every newline and
/// byte offset. The resulting source is only an independent Script validation
/// carrier; it is never evaluated or surfaced as the authored input.
pub(super) fn mask_static_imports(source: &str, imports: &[StaticImport]) -> String {
    let mut bytes = source.as_bytes().to_vec();
    for import in imports {
        let end = import.range.end.min(bytes.len());
        for byte in &mut bytes[import.range.start.min(end)..end] {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b' ';
            }
        }
    }
    // Replacing complete source-range bytes by ASCII cannot create invalid
    // UTF-8, even when an import contained a multi-byte string literal.
    String::from_utf8(bytes).expect("masked UTF-8 source remains UTF-8")
}

fn issue_intersects_import(
    error: &SwcError,
    attempt: &ParseAttempt,
    imports: &[StaticImport],
) -> bool {
    let issue = byte_range(error.span(), attempt);
    imports
        .iter()
        .any(|import| issue.start < import.range.end && issue.end > import.range.start)
}

/// Parse and validate one program source. JSON must be routed through the
/// separate data parser selected by [`select_dialect`].
pub fn analyze_source(
    request: SyntaxRequest,
    source: &str,
) -> Result<SyntaxFrontendResult, SyntaxFrontendError> {
    if request.goal == SourceGoal::ScriptWithExtensions && request.role != SourceRole::Entry {
        return Err(SyntaxFrontendError::InvalidGoalRole);
    }

    match request.goal {
        SourceGoal::Module => {
            let attempt = parse(source, request.dialect, ParserGoal::Module);
            if !attempt.issues.is_empty() {
                return Err(parser_error(&attempt));
            }
            let Program::Module(module) = attempt
                .program
                .as_ref()
                .expect("successful module parse must return a module")
            else {
                unreachable!("module parser returned a script")
            };
            let (outline, _) = module_outline(module, attempt.start_pos)?;
            if request.role == SourceRole::Dependency && outline.top_level_await {
                return Err(SyntaxFrontendError::DependencyTopLevelAwait {
                    label: "dependency source".into(),
                });
            }
            Ok(SyntaxFrontendResult::Ready(SyntaxAnalysis {
                strict_by_default: true,
                outline,
            }))
        }
        SourceGoal::ScriptWithExtensions => {
            let script_attempt = parse(source, request.dialect, ParserGoal::Script);
            if script_attempt.issues.is_empty() {
                let Program::Script(script) = script_attempt
                    .program
                    .as_ref()
                    .expect("successful script parse must return a script")
                else {
                    unreachable!("script parser returned a module")
                };
                let outline = script_outline(script, script_attempt.start_pos);
                let mut features = FeatureVisitor::default();
                script.visit_with(&mut features);
                validate_script_outline(&outline, features.top_level_await_identifier)?;
                return Ok(SyntaxFrontendResult::Ready(SyntaxAnalysis {
                    strict_by_default: false,
                    outline,
                }));
            }

            if script_attempt
                .issues
                .iter()
                .any(|error| script_import_meta_error(error.kind()))
            {
                return Err(SyntaxFrontendError::ScriptImportMetaNotAllowed);
            }
            if script_attempt
                .issues
                .iter()
                .any(|error| script_export_error(error.kind()))
            {
                return Err(SyntaxFrontendError::ScriptExportNotAllowed);
            }
            // SWC frequently returns a useful Script AST together with the
            // goal error. That AST retains await-named bindings/references
            // which a Module fallback necessarily rejects or reinterprets.
            if let Some(Program::Script(script)) = script_attempt.program.as_ref() {
                let mut features = FeatureVisitor::default();
                script.visit_with(&mut features);
                if features.top_level_await_identifier {
                    return Err(SyntaxFrontendError::TopLevelAwaitIdentifierReserved);
                }
            }
            if !script_attempt
                .issues
                .iter()
                .any(|error| extension_goal_error(error.kind()))
            {
                return Err(parser_error(&script_attempt));
            }

            let module_attempt = parse(source, request.dialect, ParserGoal::Module);
            let Some(Program::Module(module)) = module_attempt.program.as_ref() else {
                return Err(parser_error(&module_attempt));
            };
            let (mut outline, top_level_await_identifier) =
                module_outline(module, module_attempt.start_pos)?;
            validate_script_outline(&outline, top_level_await_identifier)?;

            // Module-only strict diagnostics in the body are intentionally not
            // authoritative. Diagnostics inside an import declaration still
            // belong to the extension grammar and must fail closed.
            if let Some(error) = module_attempt.issues.iter().find(|error| {
                issue_intersects_import(error, &module_attempt, &outline.static_imports)
            }) {
                return Err(SyntaxFrontendError::ParserSyntax {
                    diagnostic: parser_diagnostic(error, &module_attempt),
                });
            }

            let masked = mask_static_imports(source, &outline.static_imports);
            let body_attempt = parse(&masked, request.dialect, ParserGoal::Script);
            if let Some(error) = body_attempt
                .issues
                .iter()
                .find(|error| !matches!(error.kind(), SwcSyntaxError::TopLevelAwaitInScript))
            {
                return Err(SyntaxFrontendError::ParserSyntax {
                    diagnostic: parser_diagnostic(error, &body_attempt),
                });
            }
            let Some(Program::Script(body)) = body_attempt.program.as_ref() else {
                return Err(parser_error(&body_attempt));
            };
            let body_outline = script_outline(body, body_attempt.start_pos);
            let mut declarations = outline
                .declarations
                .into_iter()
                .filter(|declaration| declaration.kind == SessionDeclarationKind::Import)
                .collect::<Vec<_>>();
            declarations.extend(body_outline.declarations);
            declarations.sort_by_key(|declaration| declaration.range.start);
            outline.parser_goal = ParserGoal::Script;
            outline.top_level_await |= body_outline.top_level_await;
            outline.declarations = declarations;
            Ok(SyntaxFrontendResult::Ready(SyntaxAnalysis {
                strict_by_default: false,
                outline,
            }))
        }
    }
}

/// Inspect authenticated, loader-ready dependency source without admitting it
/// as a session submission. A parse failure is left for the module loader to
/// report; only a proven module-top-level await produces the stable dependency
/// refusal used by the closed static-import path.
pub(crate) fn module_source_has_top_level_await(source: &str) -> bool {
    let attempt = parse(source, ParserDialect::JavaScript, ParserGoal::Module);
    if !attempt.issues.is_empty() {
        return false;
    }
    let Some(Program::Module(module)) = attempt.program.as_ref() else {
        return false;
    };
    module_outline(module, attempt.start_pos)
        .map(|(outline, _)| outline.top_level_await)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script_request(dialect: ParserDialect) -> SyntaxRequest {
        SyntaxRequest {
            dialect,
            goal: SourceGoal::ScriptWithExtensions,
            role: SourceRole::Entry,
        }
    }

    fn module_request(role: SourceRole) -> SyntaxRequest {
        SyntaxRequest {
            dialect: ParserDialect::TypeScript,
            goal: SourceGoal::Module,
            role,
        }
    }

    fn ready(result: SyntaxFrontendResult) -> SyntaxAnalysis {
        match result {
            SyntaxFrontendResult::Ready(analysis) => analysis,
            SyntaxFrontendResult::UnsupportedGoal(gap) => {
                panic!("unexpected unsupported goal: {gap:?}")
            }
        }
    }

    #[test]
    fn dialect_selection_is_extension_driven_and_json_is_separate() {
        assert_eq!(
            select_dialect(SyntaxOrigin::Extensionless).unwrap(),
            DialectSelection::Program(ParserDialect::TypeScript)
        );
        let cases = [
            ("a.js", ParserDialect::JavaScript),
            ("a.mjs", ParserDialect::JavaScript),
            ("a.cjs", ParserDialect::JavaScript),
            ("a.jsx", ParserDialect::JavaScriptJsx),
            ("a.ts", ParserDialect::TypeScript),
            ("a.mts", ParserDialect::TypeScript),
            ("a.cts", ParserDialect::TypeScript),
            ("a.tsx", ParserDialect::TypeScriptJsx),
        ];
        for (path, expected) in cases {
            assert_eq!(
                select_dialect(SyntaxOrigin::File {
                    path: Path::new(path),
                    purpose: FilePurpose::Dependency,
                })
                .unwrap(),
                DialectSelection::Program(expected),
                "{path}"
            );
        }
        assert_eq!(
            select_dialect(SyntaxOrigin::File {
                path: Path::new("a.json"),
                purpose: FilePurpose::Load,
            })
            .unwrap(),
            DialectSelection::JsonData
        );
        assert_eq!(
            select_dialect(SyntaxOrigin::File {
                path: Path::new("a.tsx"),
                purpose: FilePurpose::Load,
            })
            .unwrap(),
            DialectSelection::Program(ParserDialect::TypeScriptJsx)
        );
    }

    #[test]
    fn load_edges_have_stable_named_refusals() {
        for path in ["x.mjs", "x.cjs", "x.mts", "x.cts"] {
            let error = select_dialect(SyntaxOrigin::File {
                path: Path::new(path),
                purpose: FilePurpose::Load,
            })
            .unwrap_err();
            assert_eq!(error.code(), "IBEX_LOAD_MODULE_KIND_ASSERTION", "{path}");
        }
        let declaration = select_dialect(SyntaxOrigin::File {
            path: Path::new("types.d.ts"),
            purpose: FilePurpose::Load,
        })
        .unwrap_err();
        assert_eq!(declaration.code(), "IBEX_DECLARATION_FILE_NOT_EXECUTABLE");
        let extensionless = select_dialect(SyntaxOrigin::File {
            path: Path::new("script"),
            purpose: FilePurpose::Load,
        })
        .unwrap_err();
        assert_eq!(extensionless.code(), "IBEX_EXTENSIONLESS_LOAD_REFUSED");
        let unknown = select_dialect(SyntaxOrigin::File {
            path: Path::new("script.wat"),
            purpose: FilePurpose::Load,
        })
        .unwrap_err();
        assert_eq!(unknown.code(), "IBEX_UNKNOWN_SOURCE_EXTENSION");
    }

    #[test]
    fn dialects_are_applied_without_source_content_sniffing() {
        ready(
            analyze_source(
                script_request(ParserDialect::TypeScript),
                "const value: number = 1;",
            )
            .unwrap(),
        );
        assert_eq!(
            analyze_source(
                script_request(ParserDialect::JavaScript),
                "const value: number = 1;",
            )
            .unwrap_err()
            .code(),
            "IBEX_PARSER_SYNTAX_ERROR"
        );
        ready(
            analyze_source(
                script_request(ParserDialect::JavaScriptJsx),
                "const view = <div />;",
            )
            .unwrap(),
        );
        assert_eq!(
            analyze_source(
                script_request(ParserDialect::TypeScript),
                "const view = <div />;",
            )
            .unwrap_err()
            .code(),
            "IBEX_PARSER_SYNTAX_ERROR"
        );
    }

    #[test]
    fn completeness_uses_parser_signals_for_literals_comments_and_typescript() {
        let request = script_request(ParserDialect::TypeScript);
        for source in [
            "const t = `x${{a: 1}.a}`;",
            r"const r = /[()[\]{}]+/g;",
            "type X<T> = { value: T }; const x: X<number> = { value: 1 };",
            "/* complete */ const x = 1;",
        ] {
            assert_eq!(
                classify_completeness(request, source),
                Completeness::Complete
            );
        }

        let incomplete = [
            "{",
            "'unterminated",
            "`unterminated ${1",
            "const r = /unterminated",
            "/* unterminated",
            "const x: Array<",
        ];
        for source in incomplete {
            assert!(
                matches!(
                    classify_completeness(request, source),
                    Completeness::Incomplete { .. }
                ),
                "{source:?}: {:?}",
                classify_completeness(request, source)
            );
        }
        assert!(matches!(
            classify_completeness(request, "const = 1"),
            Completeness::SyntaxError(_)
        ));
        assert!(
            matches!(
                classify_completeness(request, "}"),
                Completeness::SyntaxError(_)
            ),
            "{:?}",
            classify_completeness(request, "}")
        );
    }

    #[test]
    fn complete_extension_syntax_is_submitted_to_the_named_goal_refusal() {
        let request = script_request(ParserDialect::TypeScript);
        assert_eq!(
            classify_completeness(request, "import { x } from './x';"),
            Completeness::Complete
        );
        assert_eq!(
            classify_completeness(request, "await task();"),
            Completeness::Complete
        );
    }

    #[test]
    fn ordinary_sloppy_script_is_parsed_as_script_not_module() {
        let source = "010; delete missing; function f(a, a) { return this }";
        let analysis =
            ready(analyze_source(script_request(ParserDialect::JavaScript), source).unwrap());
        assert!(!analysis.strict_by_default);
        assert_eq!(analysis.outline.parser_goal, ParserGoal::Script);
        assert!(!analysis.outline.top_level_await);
        assert!(analysis.outline.static_imports.is_empty());
    }

    #[test]
    fn script_extensions_use_module_nodes_under_independent_sloppy_validation() {
        let analysis = ready(
            analyze_source(
                script_request(ParserDialect::TypeScript),
                "import value, { x as y } from './dep'; const z = await value(y);",
            )
            .unwrap(),
        );
        assert!(!analysis.strict_by_default);
        let outline = analysis.outline;
        assert_eq!(outline.parser_goal, ParserGoal::Script);
        assert!(outline.top_level_await);
        assert_eq!(outline.static_imports[0].specifier, "./dep");
        assert_eq!(
            outline
                .declarations
                .iter()
                .map(|declaration| (&*declaration.name, declaration.kind))
                .collect::<Vec<_>>(),
            vec![
                ("value", SessionDeclarationKind::Import),
                ("y", SessionDeclarationKind::Import),
                ("z", SessionDeclarationKind::Const),
            ]
        );

        // Module parsing rejects duplicate parameters, legacy octal, and
        // delete-identifier. The independent Script pass proves those forms.
        for source in [
            "import './dep'; function sloppy(a, a) {}",
            "import './dep'; 010;",
            "import './dep'; delete missing;",
        ] {
            let sloppy =
                ready(analyze_source(script_request(ParserDialect::JavaScript), source).unwrap());
            assert!(!sloppy.strict_by_default, "{source}");
        }
    }

    #[test]
    fn script_export_and_import_meta_have_distinct_named_refusals() {
        let export = analyze_source(
            script_request(ParserDialect::TypeScript),
            "export const x = 1;",
        )
        .unwrap_err();
        assert_eq!(export.code(), "IBEX_SCRIPT_EXPORT_NOT_ALLOWED");

        let import_meta = analyze_source(
            script_request(ParserDialect::TypeScript),
            "import.meta.url;",
        )
        .unwrap_err();
        assert_eq!(import_meta.code(), "IBEX_SCRIPT_IMPORT_META_NOT_ALLOWED");
    }

    #[test]
    fn await_is_reserved_only_at_script_top_level() {
        for source in [
            "var await = 1",
            "function await() {}",
            "class await {}",
            "let { await } = value",
        ] {
            let error = match analyze_source(script_request(ParserDialect::TypeScript), source) {
                Err(error) => error,
                Ok(result) => panic!("{source}: {result:?}"),
            };
            assert_eq!(
                error.code(),
                "IBEX_TOP_LEVEL_AWAIT_IDENTIFIER_RESERVED",
                "{source}"
            );
        }
        let await_call =
            ready(analyze_source(script_request(ParserDialect::TypeScript), "await(1)").unwrap());
        assert!(await_call.outline.top_level_await);
        ready(
            analyze_source(
                script_request(ParserDialect::TypeScript),
                "import { await as value } from './dep'",
            )
            .unwrap(),
        );
        for source in ["await = 1", "import { value as await } from './dep'"] {
            assert!(
                !matches!(
                    analyze_source(script_request(ParserDialect::TypeScript), source),
                    Ok(SyntaxFrontendResult::Ready(_))
                ),
                "{source}"
            );
        }
        for source in [
            "function f() { var await = 1; return await }",
            "const x = object.await; const y = { await: 1 };",
            "const { await: value } = object; class C { await() {} }",
            "const f = function await() { return 1 };",
        ] {
            ready(analyze_source(script_request(ParserDialect::TypeScript), source).unwrap());
        }
    }

    #[test]
    fn top_level_await_detection_is_ast_scoped_and_dependency_refusal_is_stable() {
        let entry =
            ready(analyze_source(module_request(SourceRole::Entry), "await task();").unwrap());
        assert!(entry.outline.top_level_await);

        let nested = ready(
            analyze_source(
                module_request(SourceRole::Entry),
                "async function f() { await task() } const text = 'await';",
            )
            .unwrap(),
        );
        assert!(!nested.outline.top_level_await);

        let dependency =
            analyze_source(module_request(SourceRole::Dependency), "await task();").unwrap_err();
        assert_eq!(dependency.code(), "IBEX_DEPENDENCY_TOP_LEVEL_AWAIT");
    }

    #[test]
    fn static_import_manifest_preserves_order_and_type_only_bindings() {
        let analysis = ready(
            analyze_source(
                module_request(SourceRole::Entry),
                "import value, { x as y, type T } from 'a';\nimport * as ns from 'b';\nimport 'c';",
            )
            .unwrap(),
        );
        assert_eq!(
            analysis
                .outline
                .static_imports
                .iter()
                .map(|import| (&*import.specifier, import.order))
                .collect::<Vec<_>>(),
            vec![("a", 0), ("b", 1), ("c", 2)]
        );
        assert_eq!(
            analysis.outline.static_imports[0]
                .bindings
                .iter()
                .map(|binding| (binding.local.as_deref(), binding.type_only))
                .collect::<Vec<_>>(),
            vec![
                (Some("value"), false),
                (Some("y"), false),
                (Some("T"), true)
            ]
        );
        assert_eq!(
            analysis
                .outline
                .declarations
                .iter()
                .map(|declaration| declaration.name.as_str())
                .collect::<Vec<_>>(),
            vec!["value", "y", "ns"]
        );
    }

    #[test]
    fn top_level_using_is_rejected_for_script_and_await_using_counts_as_tla() {
        let using_error = analyze_source(
            script_request(ParserDialect::TypeScript),
            "using resource = acquire();",
        )
        .unwrap_err();
        assert_eq!(using_error.code(), "IBEX_TOP_LEVEL_USING_NOT_SUPPORTED");

        ready(
            analyze_source(
                script_request(ParserDialect::TypeScript),
                "{ using resource = acquire(); }",
            )
            .unwrap(),
        );

        let entry = ready(
            analyze_source(
                module_request(SourceRole::Entry),
                "await using resource = acquire();",
            )
            .unwrap(),
        );
        assert_eq!(
            entry.outline.top_level_using,
            Some(TopLevelUsing::AwaitUsing)
        );
        assert!(entry.outline.top_level_await);

        let dependency = analyze_source(
            module_request(SourceRole::Dependency),
            "await using resource = acquire();",
        )
        .unwrap_err();
        assert_eq!(dependency.code(), "IBEX_DEPENDENCY_TOP_LEVEL_AWAIT");
    }

    #[test]
    fn declaration_ir_preserves_patterns_typescript_runtime_and_hoisted_var() {
        let source = r#"
            var [a, { b }] = values;
            let c;
            const d = 1;
            function f() {}
            class C {}
            enum E { A }
            namespace N { export const x = 1 }
            if (condition) { var nested = 1; function annex() {} }
            interface TypeOnly {}
        "#;
        let analysis =
            ready(analyze_source(script_request(ParserDialect::TypeScript), source).unwrap());
        let declarations = analysis.outline.declarations;
        let names = declarations
            .iter()
            .map(|declaration| declaration.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["a", "b", "c", "d", "f", "C", "E", "N", "nested", "annex"]
        );
        assert_eq!(
            declarations
                .iter()
                .find(|declaration| declaration.name == "E")
                .unwrap()
                .origin,
            DeclarationOrigin::TypeScriptRuntime
        );
        assert_eq!(
            declarations
                .iter()
                .find(|declaration| declaration.name == "annex")
                .unwrap()
                .origin,
            DeclarationOrigin::AnnexB
        );
        assert_eq!(
            declarations
                .iter()
                .find(|declaration| declaration.name == "nested")
                .unwrap()
                .placement,
            DeclarationPlacement::VarHoistedFromNestedStatement
        );
        assert!(!names.contains(&"TypeOnly"));
    }

    #[test]
    fn duplicate_declarations_remain_in_ir_for_model_collision_checks() {
        let analysis = ready(
            analyze_source(
                script_request(ParserDialect::TypeScript),
                "var a; var a; function a() {}",
            )
            .unwrap(),
        );
        assert_eq!(
            analysis
                .outline
                .declarations
                .iter()
                .map(|declaration| declaration.kind)
                .collect::<Vec<_>>(),
            vec![
                SessionDeclarationKind::Var,
                SessionDeclarationKind::Var,
                SessionDeclarationKind::Function,
            ]
        );
    }

    #[test]
    fn annex_b_origin_is_limited_to_sloppy_script_directive_semantics() {
        let sloppy = ready(
            analyze_source(
                script_request(ParserDialect::JavaScript),
                "if (condition) { function published() {} var hoisted = 1; }",
            )
            .unwrap(),
        );
        assert_eq!(
            sloppy
                .outline
                .declarations
                .iter()
                .map(|declaration| (&*declaration.name, declaration.origin))
                .collect::<Vec<_>>(),
            vec![
                ("published", DeclarationOrigin::AnnexB),
                ("hoisted", DeclarationOrigin::UserAuthored),
            ]
        );

        let strict = ready(
            analyze_source(
                script_request(ParserDialect::JavaScript),
                "'use strict'; if (condition) { function local() {} var hoisted = 1; }",
            )
            .unwrap(),
        );
        assert_eq!(
            strict
                .outline
                .declarations
                .iter()
                .map(|declaration| declaration.name.as_str())
                .collect::<Vec<_>>(),
            vec!["hoisted"]
        );
    }

    #[test]
    fn source_goal_role_is_validated_before_parsing() {
        let error = analyze_source(
            SyntaxRequest {
                dialect: ParserDialect::JavaScript,
                goal: SourceGoal::ScriptWithExtensions,
                role: SourceRole::Dependency,
            },
            "const x = 1;",
        )
        .unwrap_err();
        assert_eq!(error.code(), "IBEX_INVALID_SOURCE_GOAL_ROLE");
    }

    #[test]
    fn parser_pin_is_present_in_the_lockfile() {
        let lockfile = include_str!("../../Cargo.lock");
        assert!(lockfile.contains(&format!(
            "name = \"swc_ecma_parser\"\nversion = \"{PINNED_SWC_ECMA_PARSER_VERSION}\""
        )));
    }
}
