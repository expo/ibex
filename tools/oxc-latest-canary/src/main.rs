use oxc_allocator::Allocator;
use oxc_codegen::Codegen;
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;
use oxc_transformer::{TransformOptions, Transformer};

fn main() {
    let allocator = Allocator::default();
    let source = "export const answer: number = 42;";
    let parsed = Parser::new(&allocator, source, SourceType::ts()).parse();
    assert!(parsed.diagnostics.is_empty());
    let mut program = parsed.program;
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&program);
    assert!(semantic.diagnostics.is_empty());
    let options = TransformOptions::from_target("es2022").expect("latest Oxc accepts es2022");
    let transformed = Transformer::new(&allocator, "canary.ts".as_ref(), &options)
        .build_with_scoping(semantic.semantic.into_scoping(), &mut program);
    assert!(transformed.diagnostics.is_empty());
    let output = Codegen::new()
        .with_source_text(source)
        .with_scoping(Some(transformed.scoping))
        .build(&program)
        .code;
    assert!(output.contains("answer"));
}
