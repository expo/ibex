//! In-process TypeScript/ESM lowering for the module loader
//! (LLP 0175 §9.2): swc parse → TS strip + JSX → ESM→CJS → codegen.
//! Replaces the bun/node subprocess transpile, which made running
//! TypeScript depend on a competitor runtime and a repo checkout.
//! `exact-runtime` owns resolution *and* transpilation (Codex round-2
//! finding 3); the CLI calls this API.
//!
//! Engine choice (LLP 0175 OQ9, spike 2026-06-12): oxc_transformer 0.121 and
//! 0.133 have no general ESM→CJS lowering — `Module::CommonJS` only gates the
//! TypeScript `import x = require()` form — and oxc_transformer_plugins'
//! ModuleRunnerTransform targets an async module-runner ABI that would
//! require rearchitecting the loader's synchronous `require()` chain. swc's
//! `transform-modules-commonjs` is the drop-in for the existing loader, so
//! swc is the lowering engine, per the RFC's named fallback. The ModuleRunner
//! ABI remains the candidate end-state architecture.

use std::path::Path;

use anyhow::{anyhow, Result};
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

/// Lower a JS/TS/JSX/TSX module to CommonJS script output that the module
/// loader's synchronous `require()` chain can evaluate on Hermes: types
/// stripped, JSX compiled, `import`/`export` lowered, helpers inlined.
/// Top-level `await` is passed through untouched — only the entry module may
/// use it, and the entry path wraps it in the async shim.
pub fn transpile_to_cjs(source: &str, path: &Path) -> Result<String> {
    let globals = Globals::new();
    GLOBALS.set(&globals, || {
        HELPERS.set(&Helpers::new(false), || transpile_inner(source, path))
    })
}

fn transpile_inner(source: &str, path: &Path) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
}
