//! ESM lowering, with Oxc as the parser.
//!
//! LLP 0057 §5.2 records that Ibex 2 targets Exact, and Exact is 4,350 ES
//! modules against 79 CommonJS ones — so the loader has to accept `import` and
//! `export` or it cannot load a single one.
//!
//! **Oxc parses; this file splices.** LLP 0028 makes Oxc the transform
//! authority, so the parser is not a choice to re-make. What is a choice is
//! rewriting spans rather than rebuilding an AST: the parser gives exact byte
//! ranges for each import and export, everything outside them is copied
//! verbatim, and a module's own code reaches the engine unchanged. That keeps
//! the transform auditable and leaves source positions recoverable.
//!
//! `hermesc` cannot do this job: its `-commonjs` mode is the one that accepts
//! module syntax, and on the pinned engine it segfaults on every input.
//!
//! @ref LLP 0028#summary — Oxc is the transform authority
//! @ref LLP 0057#52-what-ibex-2-is-for — why ESM is required at all

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Declaration, ExportDefaultDeclarationKind, ImportDeclarationSpecifier, ModuleDeclaration,
    Statement,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

/// One rewritten span: everything else in the source is copied untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Splice {
    start: usize,
    end: usize,
    replacement: String,
}

/// Does this source use ES module syntax?
///
/// Answered by the parser, not by scanning for the word `import`: a string
/// containing "export" is not an export, and `import()` is a CommonJS-legal
/// dynamic expression.
pub fn is_module(source: &str) -> bool {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    parsed.program.body.iter().any(|statement| {
        matches!(
            statement,
            Statement::ImportDeclaration(_)
                | Statement::ExportNamedDeclaration(_)
                | Statement::ExportDefaultDeclaration(_)
                | Statement::ExportAllDeclaration(_)
        )
    })
}

/// Every static dependency a module declares: imports and re-exports alike.
///
/// From the parser, not a scan. `export { a } from './x'` and
/// `export * from './x'` are dependencies as much as `import` is, and a text
/// scan for the word "import" finds them in strings and comments while missing
/// these two entirely.
///
/// Dynamic `import()` is deliberately absent: its specifier is an expression,
/// so a build cannot resolve it in general, and pretending otherwise would make
/// the build's module list quietly wrong.
pub fn dependencies(source: &str) -> Vec<String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    let mut found = Vec::new();
    for statement in &parsed.program.body {
        let Some(module) = as_module_declaration(statement) else {
            continue;
        };
        match module {
            ModuleDeclaration::ImportDeclaration(d) => found.push(d.source.value.to_string()),
            ModuleDeclaration::ExportAllDeclaration(d) => found.push(d.source.value.to_string()),
            ModuleDeclaration::ExportNamedDeclaration(d) => {
                if let Some(source_module) = &d.source {
                    found.push(source_module.value.to_string());
                }
            }
            _ => {}
        }
    }
    found
}

/// Lower ES module syntax to the CommonJS-shaped factory body the loader runs.
///
/// Returns the source unchanged when it uses no module syntax, so a CommonJS
/// module costs a parse and nothing else.
pub fn lower(source: &str) -> Result<String, String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    if !parsed.diagnostics.is_empty() {
        return Err(parsed
            .diagnostics
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; "));
    }

    let mut splices: Vec<Splice> = Vec::new();
    let mut saw_module_syntax = false;

    for statement in &parsed.program.body {
        let Some(module) = as_module_declaration(statement) else {
            continue;
        };
        saw_module_syntax = true;
        match module {
            ModuleDeclaration::ImportDeclaration(declaration) => {
                let from = declaration.source.value.as_str();
                let mut parts: Vec<String> = Vec::new();
                match &declaration.specifiers {
                    // `import './side-effect.js'` — evaluate, bind nothing.
                    None => parts.push(format!("require({from:?});")),
                    Some(specifiers) => {
                        let mut named: Vec<String> = Vec::new();
                        for specifier in specifiers {
                            match specifier {
                                ImportDeclarationSpecifier::ImportSpecifier(s) => named.push({
                                    let imported = s.imported.name();
                                    let local = s.local.name.as_str();
                                    if imported == local {
                                        local.to_string()
                                    } else {
                                        format!("{imported}: {local}")
                                    }
                                }),
                                ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                                    // Interop: a CommonJS module has no
                                    // `default`, and treating its
                                    // `module.exports` as one is what every
                                    // bundler settled on.
                                    parts.push(format!(
                                        "const {} = __ibex2_default(require({from:?}));",
                                        s.local.name
                                    ));
                                }
                                ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                                    parts.push(format!(
                                        "const {} = require({from:?});",
                                        s.local.name
                                    ));
                                }
                            }
                        }
                        if !named.is_empty() {
                            parts.push(format!(
                                "const {{ {} }} = require({from:?});",
                                named.join(", ")
                            ));
                        }
                        if parts.is_empty() {
                            parts.push(format!("require({from:?});"));
                        }
                    }
                }
                splices.push(Splice {
                    start: declaration.span.start as usize,
                    end: declaration.span.end as usize,
                    replacement: parts.join(" "),
                });
            }

            ModuleDeclaration::ExportNamedDeclaration(declaration) => {
                let mut parts: Vec<String> = Vec::new();
                if let Some(inner) = &declaration.declaration {
                    // `export const x = 1` / `export function f() {}` — keep the
                    // declaration exactly as written and publish it after.
                    let text = &source[inner.span().start as usize..inner.span().end as usize];
                    parts.push(text.to_string());
                    for name in declared_names(inner) {
                        parts.push(live_export(&name, &name));
                    }
                } else {
                    for specifier in &declaration.specifiers {
                        let local = specifier.local.name();
                        let exported = specifier.exported.name();
                        match &declaration.source {
                            // `export { a } from './x'` — a re-export never
                            // binds locally, so it reads through each time.
                            Some(source_module) => parts.push(format!(
                                "Object.defineProperty(exports, {:?}, {{ get: () => require({:?})[{:?}], enumerable: true, configurable: true }});",
                                exported.as_ref(),
                                source_module.value.as_str(),
                                local.as_ref()
                            )),
                            None => parts.push(live_export(&exported, &local)),
                        }
                    }
                }
                splices.push(Splice {
                    start: declaration.span.start as usize,
                    end: declaration.span.end as usize,
                    replacement: parts.join(" "),
                });
            }

            ModuleDeclaration::ExportDefaultDeclaration(declaration) => {
                let replacement = match &declaration.declaration {
                    // A named function or class keeps its name, so recursion and
                    // self-reference still work.
                    ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                        let text = &source[f.span.start as usize..f.span.end as usize];
                        match &f.id {
                            Some(id) => format!("{text} exports.default = {};", id.name),
                            None => format!("exports.default = {text};"),
                        }
                    }
                    ExportDefaultDeclarationKind::ClassDeclaration(c) => {
                        let text = &source[c.span.start as usize..c.span.end as usize];
                        match &c.id {
                            Some(id) => format!("{text} exports.default = {};", id.name),
                            None => format!("exports.default = {text};"),
                        }
                    }
                    other => {
                        let span = other.span();
                        let text = &source[span.start as usize..span.end as usize];
                        format!("exports.default = {text};")
                    }
                };
                splices.push(Splice {
                    start: declaration.span.start as usize,
                    end: declaration.span.end as usize,
                    replacement,
                });
            }

            ModuleDeclaration::ExportAllDeclaration(declaration) => {
                let from = declaration.source.value.as_str();
                let replacement = match &declaration.exported {
                    // `export * as ns from './x'`
                    Some(name) => format!(
                        "Object.defineProperty(exports, {:?}, {{ get: () => require({from:?}), enumerable: true, configurable: true }});",
                        name.name().as_ref()
                    ),
                    // `export * from './x'` — `default` is deliberately not
                    // re-exported, per the spec.
                    None => format!("__ibex2_export_all(exports, require({from:?}));"),
                };
                splices.push(Splice {
                    start: declaration.span.start as usize,
                    end: declaration.span.end as usize,
                    replacement,
                });
            }

            // TypeScript-only module forms; this runtime does not accept them.
            _ => {}
        }
    }

    if !saw_module_syntax {
        return Ok(source.to_string());
    }

    splices.sort_by_key(|splice| splice.start);
    let mut out = String::with_capacity(source.len() + 256);
    let mut cursor = 0usize;
    for splice in &splices {
        if splice.start < cursor {
            return Err("overlapping module declarations".into());
        }
        out.push_str(&source[cursor..splice.start]);
        out.push_str(&splice.replacement);
        cursor = splice.end;
    }
    out.push_str(&source[cursor..]);
    Ok(out)
}

/// Publish an export as a live view of its binding.
///
/// `exports.x = x` would snapshot, and ESM exports are live: a module that
/// reassigns an exported `let` after evaluation must have that visible to its
/// importers. A getter is the cheapest way to keep that true, and it is what
/// makes an import cycle see values defined after it read the module.
fn live_export(exported: &str, local: &str) -> String {
    format!(
        "Object.defineProperty(exports, {exported:?}, {{ get: () => {local}, enumerable: true, configurable: true }});"
    )
}

fn as_module_declaration<'a>(statement: &'a Statement<'a>) -> Option<&'a ModuleDeclaration<'a>> {
    statement.as_module_declaration()
}

/// The names a declaration introduces, so each can be published.
fn declared_names(declaration: &Declaration) -> Vec<String> {
    let mut names = Vec::new();
    match declaration {
        Declaration::VariableDeclaration(variable) => {
            for declarator in &variable.declarations {
                collect_pattern_names(&declarator.id, &mut names);
            }
        }
        Declaration::FunctionDeclaration(function) => {
            if let Some(id) = &function.id {
                names.push(id.name.to_string());
            }
        }
        Declaration::ClassDeclaration(class) => {
            if let Some(id) = &class.id {
                names.push(id.name.to_string());
            }
        }
        _ => {}
    }
    names
}

/// Destructuring exports every name it binds, not just simple identifiers:
/// `export const { a, b } = obj` publishes both.
fn collect_pattern_names(pattern: &oxc_ast::ast::BindingPattern, names: &mut Vec<String>) {
    use oxc_ast::ast::BindingPattern;
    match pattern {
        BindingPattern::BindingIdentifier(id) => names.push(id.name.to_string()),
        BindingPattern::ObjectPattern(object) => {
            for property in &object.properties {
                collect_pattern_names(&property.value, names);
            }
            if let Some(rest) = &object.rest {
                collect_pattern_names(&rest.argument, names);
            }
        }
        BindingPattern::ArrayPattern(array) => {
            for element in array.elements.iter().flatten() {
                collect_pattern_names(element, names);
            }
            if let Some(rest) = &array.rest {
                collect_pattern_names(&rest.argument, names);
            }
        }
        BindingPattern::AssignmentPattern(assignment) => {
            collect_pattern_names(&assignment.left, names)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lowered(source: &str) -> String {
        lower(source).expect("lowers")
    }

    #[test]
    fn commonjs_passes_through_untouched() {
        let source = "const a = require('./a');\nmodule.exports = a;\n";
        assert_eq!(lowered(source), source);
        assert!(!is_module(source));
    }

    /// `import()` is a call expression, legal in CommonJS, and the word
    /// "export" inside a string is not an export. The parser knows; a scan
    /// would not.
    #[test]
    fn module_detection_is_syntactic_not_textual() {
        assert!(!is_module("const p = import('./x');"));
        assert!(!is_module("const s = 'export default nope';"));
        assert!(!is_module("// import { a } from './b'"));
        assert!(is_module("import { a } from './b';"));
        assert!(is_module("export const x = 1;"));
    }

    #[test]
    fn named_imports_become_a_destructure() {
        let out = lowered("import { a, b as c } from './x';\nuse(a, c);\n");
        assert!(
            out.contains(r#"const { a, b: c } = require("./x");"#),
            "{out}"
        );
        assert!(
            out.contains("use(a, c);"),
            "the module's own code is untouched"
        );
    }

    #[test]
    fn a_default_import_goes_through_interop() {
        let out = lowered("import d from './x';\n");
        assert!(
            out.contains(r#"const d = __ibex2_default(require("./x"));"#),
            "{out}"
        );
    }

    #[test]
    fn a_namespace_import_is_the_module_object() {
        let out = lowered("import * as ns from './x';\n");
        assert!(out.contains(r#"const ns = require("./x");"#), "{out}");
    }

    #[test]
    fn a_side_effect_import_binds_nothing() {
        let out = lowered("import './x';\n");
        assert_eq!(out.trim(), r#"require("./x");"#);
    }

    #[test]
    fn mixed_default_and_named_imports_both_bind() {
        let out = lowered("import d, { a } from './x';\n");
        assert!(out.contains("__ibex2_default(require(\"./x\"))"), "{out}");
        assert!(out.contains(r#"const { a } = require("./x");"#), "{out}");
    }

    /// Exports are LIVE. `exports.x = x` would snapshot, and a module that
    /// reassigns an exported binding after evaluation must have that visible.
    #[test]
    fn exports_are_live_views_not_snapshots() {
        let out = lowered("export let counter = 0;\n");
        assert!(
            out.contains("let counter = 0;"),
            "the declaration survives: {out}"
        );
        assert!(out.contains("get: () => counter"), "not a live view: {out}");
        assert!(
            !out.contains("exports.counter = counter;"),
            "snapshotted: {out}"
        );
    }

    #[test]
    fn exported_functions_and_classes_keep_their_declarations() {
        let out = lowered("export function f() { return f; }\n");
        assert!(out.contains("function f() { return f; }"), "{out}");
        assert!(out.contains("get: () => f"), "{out}");

        let out = lowered("export class C {}\n");
        assert!(out.contains("class C {}"), "{out}");
        assert!(out.contains("get: () => C"), "{out}");
    }

    /// A default-exported function keeps its name, so recursion still works.
    #[test]
    fn a_named_default_export_keeps_its_binding() {
        let out =
            lowered("export default function fact(n) { return n < 2 ? 1 : n * fact(n - 1); }\n");
        assert!(out.contains("function fact(n)"), "{out}");
        assert!(out.contains("exports.default = fact;"), "{out}");
    }

    #[test]
    fn an_anonymous_default_export_is_assigned_directly() {
        let out = lowered("export default 42;\n");
        assert_eq!(out.trim(), "exports.default = 42;");
        let out = lowered("export default { a: 1 };\n");
        assert!(out.contains("exports.default = { a: 1 };"), "{out}");
    }

    #[test]
    fn an_export_list_publishes_each_name() {
        let out = lowered("const a = 1, b = 2;\nexport { a, b as bee };\n");
        assert!(out.contains("get: () => a"), "{out}");
        assert!(
            out.contains(r#"Object.defineProperty(exports, "bee", { get: () => b"#),
            "{out}"
        );
    }

    #[test]
    fn a_re_export_reads_through_to_its_source() {
        let out = lowered("export { a } from './x';\n");
        assert!(out.contains(r#"require("./x")["a"]"#), "{out}");
        assert!(
            !out.contains("const"),
            "a re-export must not bind locally: {out}"
        );
    }

    #[test]
    fn export_star_uses_the_helper_and_export_star_as_does_not() {
        let out = lowered("export * from './x';\n");
        assert!(
            out.contains(r#"__ibex2_export_all(exports, require("./x"));"#),
            "{out}"
        );

        let out = lowered("export * as ns from './x';\n");
        assert!(
            out.contains(r#"Object.defineProperty(exports, "ns""#),
            "{out}"
        );
    }

    #[test]
    fn destructured_exports_publish_every_bound_name() {
        let out = lowered("export const { a, b: c } = obj;\n");
        assert!(out.contains("get: () => a"), "{out}");
        assert!(out.contains("get: () => c"), "{out}");
        let out = lowered("export const [x, ...rest] = arr;\n");
        assert!(out.contains("get: () => x"), "{out}");
        assert!(out.contains("get: () => rest"), "{out}");
    }

    #[test]
    fn several_declarations_all_get_rewritten_in_order() {
        let out = lowered(
            "import { a } from './a';\nimport { b } from './b';\nexport const c = a + b;\n",
        );
        let a_at = out.find("./a").expect("a");
        let b_at = out.find("./b").expect("b");
        assert!(a_at < b_at, "order not preserved: {out}");
        assert!(out.contains("const c = a + b;"), "{out}");
    }

    #[test]
    fn dependencies_include_imports_and_re_exports() {
        let deps = dependencies(
            "import a from './a.js';\n\
             import './side.js';\n\
             export { b } from './b.js';\n\
             export * from './c.js';\n\
             const d = require('./d.js');\n",
        );
        assert_eq!(deps, vec!["./a.js", "./side.js", "./b.js", "./c.js"]);
    }

    /// A dynamic import's specifier is an expression, so the build cannot
    /// resolve it and must not claim to.
    #[test]
    fn dynamic_import_is_not_a_static_dependency() {
        assert!(dependencies("const m = import('./' + name);").is_empty());
        assert!(dependencies("const s = 'import x from y';").is_empty());
    }

    #[test]
    fn a_syntax_error_is_reported_rather_than_mangled() {
        let err = lower("import { from './x';").unwrap_err();
        assert!(!err.is_empty());
    }
}
