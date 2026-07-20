//! One-shot, content-addressed parser cutover report for LLP 0024/0028.
//!
//! The projection and corpus are checked in independently so this runner cannot
//! fit equivalence fields to the observed result.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use oxc_allocator::Allocator;
use oxc_ast::ast::Statement as OxcStatement;
use oxc_semantic::SemanticBuilder;
use oxc_span::{GetSpan, SourceType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use swc_common::{BytePos, Span as SwcSpan, Spanned};
use swc_ecma_ast::{Expr, Lit, ModuleDecl, ModuleItem, Stmt};
use swc_ecma_parser::{lexer::Lexer, EsSyntax, Parser as SwcParser, StringInput, Syntax, TsSyntax};

const PROJECTION_PATH: &str = "config/llp0024-parser-differential-projection.json";
const CORPUS_PATH: &str = "tests/fixtures/llp0024-parser-differential/corpus.json";
const MAX_SWEEP_SOURCE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Corpus {
    parser_differential_corpus_schema: String,
    fixtures: Vec<Fixture>,
}

#[derive(Debug, Clone, Deserialize)]
struct Fixture {
    id: String,
    goal: Goal,
    dialect: Dialect,
    source: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Goal {
    Script,
    Module,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Dialect {
    Js,
    Jsx,
    Ts,
    Tsx,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ParserProjection {
    outcome: &'static str,
    ast_available: bool,
    directive_count: usize,
    top_level_category_sequence: Vec<&'static str>,
    top_level_span_validity: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseReport {
    id: String,
    source_digest: String,
    goal: Goal,
    dialect: Dialect,
    origin: &'static str,
    swc: ParserProjection,
    oxc: ParserProjection,
    equivalent: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Summary {
    total: usize,
    equivalent: usize,
    divergent: usize,
    corpus_cases: usize,
    node_modules_cases: usize,
    node_modules_files: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    parser_differential_report_schema: &'static str,
    projection_path: &'static str,
    projection_digest: String,
    corpus_path: &'static str,
    corpus_digest: String,
    parser_pins: BTreeMap<&'static str, &'static str>,
    node_modules_root: Option<String>,
    node_modules_limit: usize,
    summary: Summary,
    cases: Vec<CaseReport>,
}

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let args = arguments()?;
    let projection_bytes = std::fs::read(root.join(PROJECTION_PATH))?;
    let _: serde_json::Value = serde_json::from_slice(&projection_bytes)
        .context("parse predeclared differential projection")?;
    let corpus_bytes = std::fs::read(root.join(CORPUS_PATH))?;
    let corpus: Corpus =
        serde_json::from_slice(&corpus_bytes).context("parse parser differential corpus")?;
    if corpus.parser_differential_corpus_schema != "ibex/llp0024-parser-differential-corpus/1" {
        bail!("unsupported parser differential corpus schema");
    }

    let mut cases = corpus
        .fixtures
        .iter()
        .map(|fixture| project_case(fixture, "corpus"))
        .collect::<Vec<_>>();
    let corpus_cases = cases.len();

    let mut node_modules_files = 0usize;
    if let Some(node_modules) = &args.node_modules {
        let sweep_root = if node_modules.is_absolute() {
            node_modules.clone()
        } else {
            root.join(node_modules)
        };
        let files = representative_javascript_files(&sweep_root, args.limit)?;
        node_modules_files = files.len();
        for path in files {
            let source = std::fs::read_to_string(&path)
                .with_context(|| format!("read sweep input {}", path.display()))?;
            let relative = path.strip_prefix(&sweep_root).unwrap_or(&path);
            for goal in [Goal::Script, Goal::Module] {
                let fixture = Fixture {
                    id: format!("node_modules:{}:{goal:?}", display_path(relative)),
                    goal,
                    dialect: Dialect::Js,
                    source: source.clone(),
                };
                cases.push(project_case(&fixture, "node_modules"));
            }
        }
    }

    let equivalent = cases.iter().filter(|case| case.equivalent).count();
    let report = Report {
        parser_differential_report_schema: "ibex/llp0024-parser-differential-report/1",
        projection_path: PROJECTION_PATH,
        projection_digest: digest(&projection_bytes),
        corpus_path: CORPUS_PATH,
        corpus_digest: digest(&corpus_bytes),
        parser_pins: BTreeMap::from([("oxcParser", "0.140.0"), ("swcEcmaParser", "41.0.1")]),
        node_modules_root: args.node_modules.as_ref().map(|path| display_path(path)),
        node_modules_limit: args.limit,
        summary: Summary {
            total: cases.len(),
            equivalent,
            divergent: cases.len() - equivalent,
            corpus_cases,
            node_modules_cases: cases.len() - corpus_cases,
            node_modules_files,
        },
        cases,
    };
    let bytes = serde_json::to_vec_pretty(&report)?;
    let report_digest = digest(&bytes);
    std::fs::create_dir_all(&args.output_dir)?;
    let output = args
        .output_dir
        .join(format!("0024-parser-differential-{report_digest}.json"));
    std::fs::write(&output, &bytes)?;
    println!("{}", output.display());
    if report.summary.divergent != 0 {
        eprintln!(
            "parser differential recorded {} divergence(s) out of {} cases",
            report.summary.divergent, report.summary.total
        );
    }
    Ok(())
}

struct Arguments {
    output_dir: PathBuf,
    node_modules: Option<PathBuf>,
    limit: usize,
}

fn arguments() -> Result<Arguments> {
    let mut output_dir = PathBuf::from("llp/evidence");
    let mut node_modules = None;
    let mut limit = 256usize;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--output-dir" => {
                output_dir = PathBuf::from(args.next().context("--output-dir requires a path")?);
            }
            "--node-modules" => {
                node_modules = Some(PathBuf::from(
                    args.next().context("--node-modules requires a path")?,
                ));
            }
            "--limit" => {
                limit = args
                    .next()
                    .context("--limit requires a count")?
                    .parse()
                    .context("parse --limit")?;
            }
            other => bail!("unknown argument {other:?}"),
        }
    }
    Ok(Arguments {
        output_dir,
        node_modules,
        limit,
    })
}

fn project_case(fixture: &Fixture, origin: &'static str) -> CaseReport {
    let swc = project_swc(&fixture.source, fixture.goal, fixture.dialect);
    let oxc = project_oxc(&fixture.source, fixture.goal, fixture.dialect);
    let equivalent = projections_equivalent(&swc, &oxc);
    CaseReport {
        id: fixture.id.clone(),
        source_digest: digest(fixture.source.as_bytes()),
        goal: fixture.goal,
        dialect: fixture.dialect,
        origin,
        swc,
        oxc,
        equivalent,
    }
}

fn projections_equivalent(left: &ParserProjection, right: &ParserProjection) -> bool {
    if left.outcome != right.outcome || left.ast_available != right.ast_available {
        return false;
    }
    left.outcome != "accepted"
        || (left.directive_count == right.directive_count
            && left.top_level_category_sequence == right.top_level_category_sequence
            && left.top_level_span_validity
            && right.top_level_span_validity)
}

fn project_oxc(source: &str, goal: Goal, dialect: Dialect) -> ParserProjection {
    let allocator = Allocator::default();
    let source_type = oxc_source_type(goal, dialect);
    let parsed = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&parsed.program);
    let diagnostic = !parsed.diagnostics.is_empty() || !semantic.diagnostics.is_empty();
    let mut categories = Vec::new();
    let mut spans = Vec::new();
    for directive in &parsed.program.directives {
        categories.push("directive");
        spans.push((directive.span.start as usize, directive.span.end as usize));
    }
    for statement in &parsed.program.body {
        categories.push(oxc_category(statement));
        let span = statement.span();
        spans.push((span.start as usize, span.end as usize));
    }
    ParserProjection {
        outcome: if diagnostic { "diagnostic" } else { "accepted" },
        ast_available: true,
        directive_count: parsed.program.directives.len(),
        top_level_category_sequence: categories,
        top_level_span_validity: spans_valid(&spans, source.len()),
    }
}

fn oxc_source_type(goal: Goal, dialect: Dialect) -> SourceType {
    let source_type = match dialect {
        Dialect::Js => SourceType::mjs(),
        Dialect::Jsx => SourceType::jsx(),
        Dialect::Ts => SourceType::ts(),
        Dialect::Tsx => SourceType::tsx(),
    };
    match goal {
        Goal::Script => source_type.with_script(true),
        Goal::Module => source_type.with_module(true),
    }
}

fn oxc_category(statement: &OxcStatement<'_>) -> &'static str {
    match statement {
        OxcStatement::ImportDeclaration(_) => "import",
        OxcStatement::ExportAllDeclaration(_)
        | OxcStatement::ExportDefaultDeclaration(_)
        | OxcStatement::ExportNamedDeclaration(_)
        | OxcStatement::TSExportAssignment(_)
        | OxcStatement::TSNamespaceExportDeclaration(_) => "export",
        statement if statement.is_declaration() => "declaration",
        _ => "statement",
    }
}

fn project_swc(source: &str, goal: Goal, dialect: Dialect) -> ParserProjection {
    let syntax = match dialect {
        Dialect::Js | Dialect::Jsx => Syntax::Es(EsSyntax {
            jsx: matches!(dialect, Dialect::Jsx),
            ..Default::default()
        }),
        Dialect::Ts | Dialect::Tsx => Syntax::Typescript(TsSyntax {
            tsx: matches!(dialect, Dialect::Tsx),
            decorators: false,
            ..Default::default()
        }),
    };
    let input = StringInput::new(
        source,
        BytePos(0),
        BytePos(u32::try_from(source.len()).unwrap_or(u32::MAX)),
    );
    let lexer = Lexer::new(syntax, swc_ecma_ast::EsVersion::Es2022, input, None);
    let mut parser = SwcParser::new_from(lexer);
    let mut categories = Vec::new();
    let mut spans = Vec::new();
    let mut directive_count = 0usize;
    let parse_ok = match goal {
        Goal::Script => parser.parse_script().map(|script| {
            project_swc_statements(
                &script.body,
                &mut categories,
                &mut spans,
                &mut directive_count,
            );
        }),
        Goal::Module => parser.parse_module().map(|module| {
            let mut in_directive_prologue = true;
            for item in &module.body {
                match item {
                    ModuleItem::Stmt(statement) => project_swc_statement(
                        statement,
                        &mut in_directive_prologue,
                        &mut categories,
                        &mut spans,
                        &mut directive_count,
                    ),
                    ModuleItem::ModuleDecl(declaration) => {
                        in_directive_prologue = false;
                        categories.push(match declaration {
                            ModuleDecl::Import(_) | ModuleDecl::TsImportEquals(_) => "import",
                            _ => "export",
                        });
                        spans.push(swc_span(declaration.span()));
                    }
                }
            }
        }),
    };
    let recovered = parser.take_errors();
    let ast_available = parse_ok.is_ok();
    ParserProjection {
        outcome: if ast_available && recovered.is_empty() {
            "accepted"
        } else {
            "diagnostic"
        },
        ast_available,
        directive_count,
        top_level_category_sequence: categories,
        top_level_span_validity: ast_available && spans_valid(&spans, source.len()),
    }
}

fn project_swc_statements(
    statements: &[Stmt],
    categories: &mut Vec<&'static str>,
    spans: &mut Vec<(usize, usize)>,
    directive_count: &mut usize,
) {
    let mut in_directive_prologue = true;
    for statement in statements {
        project_swc_statement(
            statement,
            &mut in_directive_prologue,
            categories,
            spans,
            directive_count,
        );
    }
}

fn project_swc_statement(
    statement: &Stmt,
    in_directive_prologue: &mut bool,
    categories: &mut Vec<&'static str>,
    spans: &mut Vec<(usize, usize)>,
    directive_count: &mut usize,
) {
    let directive = *in_directive_prologue
        && matches!(statement, Stmt::Expr(expression) if matches!(&*expression.expr, Expr::Lit(Lit::Str(_))));
    if directive {
        categories.push("directive");
        *directive_count += 1;
    } else {
        *in_directive_prologue = false;
        categories.push(if matches!(statement, Stmt::Decl(_)) {
            "declaration"
        } else {
            "statement"
        });
    }
    spans.push(swc_span(statement.span()));
}

fn swc_span(span: SwcSpan) -> (usize, usize) {
    (span.lo.0 as usize, span.hi.0 as usize)
}

fn spans_valid(spans: &[(usize, usize)], source_len: usize) -> bool {
    let mut previous_end = 0usize;
    for &(start, end) in spans {
        if start > end || end > source_len || start < previous_end {
            return false;
        }
        previous_end = end;
    }
    true
}

fn representative_javascript_files(root: &Path, limit: usize) -> Result<Vec<PathBuf>> {
    if !root.is_dir() {
        bail!(
            "node_modules sweep root is not a directory: {}",
            root.display()
        );
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let file_name = entry.file_name();
            if entry.file_type()?.is_dir() {
                if file_name != ".bin" {
                    pending.push(path);
                }
                continue;
            }
            if !entry.file_type()?.is_file() {
                continue;
            }
            let extension = path.extension().and_then(|value| value.to_str());
            if !matches!(extension, Some("js" | "mjs" | "cjs")) {
                continue;
            }
            if entry.metadata()?.len() <= MAX_SWEEP_SOURCE_BYTES {
                files.push(path);
            }
        }
    }
    files.sort();
    files.truncate(limit);
    Ok(files)
}

fn digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("write to String");
    }
    output
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}
