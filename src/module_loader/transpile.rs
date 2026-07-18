//! In-process TypeScript/ESM lowering for the module loader.
//!
//! SWC is the default compatibility engine for the synchronous `require()`
//! path. Oxc is available as an explicit candidate engine so we can compare
//! syntax-transform semantics without reusing SWC cache entries or changing
//! defaults before the loader contract is proven.

use std::path::Path;

use anyhow::{anyhow, bail, Result};
use oxc_allocator::Allocator;
use oxc_ast::ast::{AwaitExpression, FunctionBody, Program as OxcProgram};
use oxc_ast_visit::{walk, Visit};
use oxc_codegen::Codegen;
use oxc_parser::Parser as OxcParser;
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;
use oxc_transformer::{
    JsxOptions as OxcJsxOptions, JsxRuntime as OxcJsxRuntime, Module as OxcModule,
    TransformOptions as OxcTransformOptions, Transformer as OxcTransformer,
};

use super::transform_config_generated as transform_config;
use swc_common::comments::SingleThreadedComments;
use swc_common::sync::Lrc;
use swc_common::{Globals, Mark, SourceMap, GLOBALS};
use swc_ecma_ast::{EsVersion, Program};
use swc_ecma_codegen::text_writer::JsWriter;
use swc_ecma_codegen::Emitter;
use swc_ecma_parser::{lexer::Lexer, Parser, StringInput, Syntax, TsSyntax};
use swc_ecma_transforms_base::fixer::fixer;
use swc_ecma_transforms_base::helpers::{inject_helpers, Helpers, HELPERS};
use swc_ecma_transforms_base::hygiene::hygiene;
use swc_ecma_transforms_base::resolver;
use swc_ecma_transforms_module::common_js::{common_js, Config as CommonJsConfig};
use swc_ecma_transforms_module::util::ImportInterop;
use swc_ecma_transforms_react as react;
use swc_ecma_transforms_typescript::typescript;

const RUNTIME_TRANSFORM_ENV: &str = "IBEX_RUNTIME_TRANSFORM";
const LEGACY_RUNTIME_TRANSFORM_ENV: &str = "EXACT_RUNTIME_TRANSFORM";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TransformEngine {
    Swc,
    Oxc,
}

impl TransformEngine {
    pub(crate) fn cache_tag(self) -> &'static str {
        match self {
            Self::Swc => "in-process-swc-v2",
            Self::Oxc => transform_config::TRANSFORM_CACHE_TAG,
        }
    }

    fn from_value(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "swc" => Some(Self::Swc),
            "oxc" => Some(Self::Oxc),
            _ => None,
        }
    }
}

pub(crate) fn selected_transform_engine() -> Result<TransformEngine> {
    if let Ok(value) = std::env::var(RUNTIME_TRANSFORM_ENV) {
        return TransformEngine::from_value(&value).ok_or_else(|| {
            anyhow!("Unsupported {RUNTIME_TRANSFORM_ENV} value {value:?}; expected swc or oxc")
        });
    }
    if let Ok(value) = std::env::var(LEGACY_RUNTIME_TRANSFORM_ENV) {
        return TransformEngine::from_value(&value).ok_or_else(|| {
            anyhow!(
                "Unsupported {LEGACY_RUNTIME_TRANSFORM_ENV} value {value:?}; expected swc or oxc"
            )
        });
    }
    Ok(TransformEngine::Swc)
}

pub(crate) fn selected_engine_cache_tag() -> Result<&'static str> {
    Ok(selected_transform_engine()?.cache_tag())
}

/// Lower a module the loader has ALREADY read to CommonJS. Taking the source
/// in (rather than re-reading `path` here) avoids a second disk read of the
/// same module on a transpile-cache miss; `path` is still needed for the engine
/// to derive syntax/JSX from the extension and for diagnostics.
pub(crate) fn transpile_source_to_cjs(source: &str, path: &Path, target: &str) -> Result<String> {
    match selected_transform_engine()? {
        TransformEngine::Swc => transpile_to_cjs(source, path),
        // @ref LLP 0007#proposal — Oxc is opt-in until the runtime has a
        // proven replacement for SWC's general ESM-to-CJS lowering.
        TransformEngine::Oxc => transpile_with_oxc(source, path, target),
    }
}

/// Lower a JS/TS/JSX/TSX module to CommonJS script output that the module
/// loader's synchronous `require()` chain can evaluate on Hermes: types
/// stripped, JSX compiled, `import`/`export` lowered, helpers inlined.
/// Top-level `await` is passed through untouched — only the entry module may
/// use it, and the entry path wraps it in the async shim.
pub fn transpile_to_cjs(source: &str, path: &Path) -> Result<String> {
    let globals = Globals::new();
    GLOBALS.set(&globals, || {
        HELPERS.set(&Helpers::new(false), || transpile_with_swc(source, path))
    })
}

fn transpile_with_swc(source: &str, path: &Path) -> Result<String> {
    let cm: Lrc<SourceMap> = Lrc::default();
    let file_name = swc_common::FileName::Real(path.to_path_buf());
    let fm = cm.new_source_file(Lrc::new(file_name), source.to_string());

    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .unwrap_or_default();
    let is_jsx = matches!(ext.as_str(), "tsx" | "jsx");
    let syntax = Syntax::Typescript(TsSyntax {
        tsx: is_jsx,
        decorators: true,
        ..Default::default()
    });

    let comments = SingleThreadedComments::default();
    let lexer = Lexer::new(
        syntax,
        EsVersion::Es2022,
        StringInput::from(&*fm),
        Some(&comments),
    );
    let mut parser = Parser::new_from(lexer);
    let program = parser
        .parse_program()
        .map_err(|err| anyhow!("Failed to parse {}: {}", path.display(), err.kind().msg()))?;
    let recovered_errors = parser.take_errors();
    if !recovered_errors.is_empty() {
        let rendered = recovered_errors
            .iter()
            .map(|err| err.kind().msg().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        return Err(anyhow!("Failed to parse {}:\n{rendered}", path.display()));
    }

    let unresolved_mark = Mark::new();
    let top_level_mark = Mark::new();

    let mut program: Program = program;
    program.mutate(resolver(unresolved_mark, top_level_mark, true));
    program.mutate(typescript(
        Default::default(),
        unresolved_mark,
        top_level_mark,
    ));
    if is_jsx {
        program.mutate(react::react(
            cm.clone(),
            Some(&comments),
            react::Options::default(),
            top_level_mark,
            unresolved_mark,
        ));
    }
    // Node-flavored interop matches the loader's CJS `require()` semantics
    // and avoids @swc/helpers imports, which would otherwise need to be
    // resolvable at runtime (standalone runs have no node_modules).
    let cjs_config = CommonJsConfig {
        import_interop: Some(ImportInterop::Node),
        ..Default::default()
    };
    program.mutate(common_js(
        Default::default(),
        unresolved_mark,
        cjs_config,
        Default::default(),
    ));
    program.mutate(inject_helpers(unresolved_mark));
    program.mutate(hygiene());
    program.mutate(fixer(Some(&comments)));

    let mut buf = Vec::new();
    {
        let mut emitter = Emitter {
            cfg: Default::default(),
            cm: cm.clone(),
            comments: None,
            wr: JsWriter::new(cm.clone(), "\n", &mut buf, None),
        };
        emitter
            .emit_program(&program)
            .map_err(|err| anyhow!("Failed to emit {}: {err}", path.display()))?;
    }

    String::from_utf8(buf).map_err(|err| anyhow!("Emitted non-UTF8 output: {err}"))
}

fn transpile_with_oxc(source: &str, path: &Path, target: &str) -> Result<String> {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path).unwrap_or_else(|_| SourceType::mjs());
    let parse_return = OxcParser::new(&allocator, source, source_type).parse();
    if !parse_return.diagnostics.is_empty() {
        bail!(
            "Failed to parse {} with Oxc:\n{}",
            path.display(),
            format_oxc_errors(&parse_return.diagnostics)
        );
    }

    let mut program = parse_return.program;
    if program_has_top_level_await(&program) {
        bail!(
            "Oxc candidate cannot run top-level await through the synchronous CommonJS loader yet: {}",
            path.display()
        );
    }

    let semantic_return = SemanticBuilder::new()
        .with_check_syntax_error(true)
        // Match the canonical producer prerequisite while this bounded Oxc
        // file-at-a-time candidate remains compiled.
        // @ref LLP 0028#5-conformance-gates-telemetry-and-rollout
        .with_enum_eval(true)
        .build(&program);
    if !semantic_return.diagnostics.is_empty() {
        bail!(
            "Failed semantic analysis for {} with Oxc:\n{}",
            path.display(),
            format_oxc_errors(&semantic_return.diagnostics)
        );
    }

    let mut options = OxcTransformOptions::from_target(oxc_target(target)).map_err(|err| {
        anyhow!(
            "Failed to configure Oxc target {} for {}: {err}",
            target,
            path.display()
        )
    })?;
    options.env.module = OxcModule::CommonJS;
    options.jsx = OxcJsxOptions {
        runtime: OxcJsxRuntime::Classic,
        ..OxcJsxOptions::enable()
    };

    let transform_return = OxcTransformer::new(&allocator, path, &options)
        .build_with_scoping(semantic_return.semantic.into_scoping(), &mut program);
    if !transform_return.diagnostics.is_empty() {
        bail!(
            "Failed to transform {} with Oxc:\n{}",
            path.display(),
            format_oxc_errors(&transform_return.diagnostics)
        );
    }

    let output = Codegen::new()
        .with_source_text(source)
        .with_scoping(Some(transform_return.scoping))
        .build(&program)
        .code;
    if output_has_esm_module_syntax(&output) {
        bail!(
            "Oxc transformed {} but cannot lower general ESM import/export syntax to CommonJS for the synchronous loader yet",
            path.display()
        );
    }
    Ok(output)
}

fn oxc_target(target: &str) -> &str {
    match target {
        // Oxc's public target floor is ES2015; the existing in-process SWC
        // path also does not honor the loader's ES5 cache target today.
        "es5" => "es2015",
        _ => target,
    }
}

fn output_has_esm_module_syntax(output: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("import ")
            || line.starts_with("export ")
            || line.starts_with("export{")
            || line.starts_with("export*")
    })
}

fn program_has_top_level_await(program: &OxcProgram<'_>) -> bool {
    let mut visitor = TopLevelAwaitVisitor {
        function_depth: 0,
        found: false,
    };
    visitor.visit_program(program);
    visitor.found
}

struct TopLevelAwaitVisitor {
    function_depth: usize,
    found: bool,
}

impl<'a> Visit<'a> for TopLevelAwaitVisitor {
    fn visit_await_expression(&mut self, it: &AwaitExpression<'a>) {
        if self.function_depth == 0 {
            self.found = true;
            return;
        }
        walk::walk_await_expression(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        self.function_depth += 1;
        walk::walk_function_body(self, it);
        self.function_depth -= 1;
    }
}

fn format_oxc_errors<T: std::fmt::Debug>(errors: &[T]) -> String {
    errors
        .iter()
        .map(|error| format!("{error:?}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Instant;
    use tempfile::tempdir;

    #[test]
    fn lowers_ts_esm_to_cjs() {
        let source = "import { x } from './dep.ts';\nexport const y: number = x + 1;\n";
        let out = transpile_to_cjs(source, &PathBuf::from("/tmp/spike.ts")).expect("transpile");
        assert!(out.contains("require("), "imports lowered: {out}");
        assert!(!out.contains("import {"), "no esm imports remain: {out}");
        assert!(!out.contains(": number"), "types stripped: {out}");
        assert!(out.contains("exports"), "exports lowered: {out}");
    }

    #[test]
    fn lowers_tsx() {
        let source = "export function App() {\n  return <div title=\"hi\">ok</div>;\n}\n";
        let out = transpile_to_cjs(source, &PathBuf::from("/tmp/spike.tsx")).expect("transpile");
        assert!(!out.contains("<div"), "jsx compiled: {out}");
    }

    #[test]
    fn passes_top_level_await_through_for_entry_wrapping() {
        let source = "const z = await Promise.resolve(1);\nconsole.log(z);\n";
        let out = transpile_to_cjs(source, &PathBuf::from("/tmp/spike-tla.ts")).expect("transpile");
        assert!(out.contains("await"), "TLA passes through: {out}");
    }

    #[test]
    fn lowers_dynamic_import_and_reports_import_meta() {
        let source = "console.log(import.meta.url);\nconst p = import('./other.ts');\n";
        let out =
            transpile_to_cjs(source, &PathBuf::from("/tmp/spike-meta.ts")).expect("transpile");
        // Documentation assertion: record what swc does with import.meta and
        // dynamic import under CJS lowering so the loader can compensate.
        println!("import.meta/dynamic-import lowering: {out}");
    }

    #[test]
    fn transform_engine_cache_tags_are_distinct() {
        assert_ne!(
            TransformEngine::Swc.cache_tag(),
            TransformEngine::Oxc.cache_tag()
        );
    }

    #[test]
    fn oxc_candidate_strips_types_for_cjs_shaped_source() {
        let source = "const y: number = 42;\nmodule.exports = { y };\n";
        let out =
            transpile_with_oxc(source, &PathBuf::from("/tmp/spike.cts"), "es2015").expect("oxc");
        assert!(!out.contains(": number"), "types stripped: {out}");
        assert!(
            out.contains("module.exports"),
            "cjs output preserved: {out}"
        );
    }

    #[test]
    fn oxc_candidate_lowers_tsx_with_classic_jsx_runtime() {
        let source = r#"
var React = { createElement: function() { return "jsx"; } };
const app = <div title="hi">ok</div>;
module.exports = { app };
"#;
        let out =
            transpile_with_oxc(source, &PathBuf::from("/tmp/spike.tsx"), "es2015").expect("oxc");
        assert!(!out.contains("<div"), "jsx compiled: {out}");
        assert!(
            out.contains("createElement"),
            "classic JSX runtime preserved: {out}"
        );
    }

    #[test]
    fn oxc_candidate_reports_esm_to_cjs_gap() {
        let source = "export const y: number = 42;\n";
        let err = transpile_with_oxc(source, &PathBuf::from("/tmp/spike.ts"), "es2015")
            .expect_err("Oxc cannot lower general ESM to CJS yet");
        let rendered = err.to_string();
        assert!(
            rendered.contains("cannot lower general ESM"),
            "expected ESM lowering gap, got: {rendered}"
        );
    }

    #[test]
    fn oxc_candidate_reports_top_level_await_gap_for_cjs_loader() {
        let source = "const value = await Promise.resolve(1);\nmodule.exports = { value };\n";
        let err = transpile_with_oxc(source, &PathBuf::from("/tmp/spike.mts"), "es2015")
            .expect_err("Oxc should reject TLA for a CJS-shaped dependency module");
        let rendered = err.to_string();
        assert!(
            rendered.contains("top-level await") || rendered.contains("Top-level await"),
            "expected TLA contract error, got: {rendered}"
        );
    }

    #[test]
    #[ignore = "diagnostic harness for LLP 0007 transform-engine comparisons"]
    fn benchmark_runtime_transform_fixtures() {
        let fixtures = [
            (
                "ts-cjs",
                "entry.cts",
                "const y: number = 42;\nmodule.exports = { y };\n",
            ),
            (
                "tsx",
                "entry.tsx",
                r#"
var React = { createElement: function() { return "jsx"; } };
const app = <section data-kind="fixture">ok</section>;
module.exports = { app };
"#,
            ),
        ];

        for (name, file_name, source) in fixtures {
            let dir = tempdir().unwrap();
            std::fs::write(dir.path().join("dep.ts"), "export const x = 1;\n").unwrap();
            let entry = dir.path().join(file_name);
            std::fs::write(&entry, source).unwrap();

            let swc_start = Instant::now();
            let swc = transpile_to_cjs(source, &entry).expect("swc fixture");
            let swc_elapsed = swc_start.elapsed();

            let oxc_start = Instant::now();
            let oxc = transpile_with_oxc(source, &entry, "es2015").expect("oxc fixture");
            let oxc_elapsed = oxc_start.elapsed();

            println!(
                "{name}: swc={swc_elapsed:?} bytes={} oxc={oxc_elapsed:?} bytes={}",
                swc.len(),
                oxc.len()
            );
        }
    }
}
