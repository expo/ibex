//! Closed import-option grammar and generated grant-key refusal vocabulary.
//!
//! This pass is deliberately syntax-only. It never reads a JavaScript object,
//! invokes a getter, or resolves a module while deciding whether an option bag
//! is admissible.
//! @ref LLP 0022#6-imports-and-authority — authority-bearing import
//! attributes are build inputs, never a runtime self-grant channel.

use swc_common::SyntaxContext;
use swc_ecma_ast::{
    CallExpr, Callee, Expr, Lit, MemberProp, Module, ModuleDecl, ModuleItem, ObjectLit, Prop,
    PropName, PropOrSpread,
};
use swc_ecma_visit::{VisitMut, VisitMutWith};

#[path = "../../vendored-generated/import_grant_keys.generated.rs"]
mod generated;

pub(crate) use generated::RESERVED_IMPORT_GRANT_KEYS;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ImportOptionRefusal {
    ReservedGrantKey(String),
    NonDataOnly,
}

fn static_property_name(name: &PropName) -> Option<&str> {
    match name {
        PropName::Ident(name) => Some(name.sym.as_ref()),
        PropName::Str(name) => name.value.as_str(),
        PropName::Num(_) | PropName::BigInt(_) | PropName::Computed(_) => None,
    }
}

fn inspect_data_only_expression(expression: &Expr, reserved: &mut Option<String>) -> bool {
    match expression {
        Expr::Lit(
            Lit::Str(_)
            | Lit::Bool(_)
            | Lit::Null(_)
            | Lit::Num(_)
            | Lit::BigInt(_)
            | Lit::Regex(_),
        ) => true,
        Expr::Object(object) => inspect_data_only_object(object, reserved),
        Expr::Array(array) => array.elems.iter().all(|element| {
            element.as_ref().is_none_or(|element| {
                element.spread.is_none()
                    && inspect_data_only_expression(element.expr.as_ref(), reserved)
            })
        }),
        _ => false,
    }
}

fn inspect_data_only_object(object: &ObjectLit, reserved: &mut Option<String>) -> bool {
    object.props.iter().all(|property| {
        let PropOrSpread::Prop(property) = property else {
            return false;
        };
        let Prop::KeyValue(property) = property.as_ref() else {
            return false;
        };
        let Some(key) = static_property_name(&property.key) else {
            return false;
        };
        if RESERVED_IMPORT_GRANT_KEYS.contains(&key) && reserved.is_none() {
            *reserved = Some(key.to_owned());
        }
        inspect_data_only_expression(property.value.as_ref(), reserved)
    })
}

fn validate_data_only_object(object: &ObjectLit) -> Result<(), ImportOptionRefusal> {
    let mut reserved = None;
    if !inspect_data_only_object(object, &mut reserved) {
        return Err(ImportOptionRefusal::NonDataOnly);
    }
    if let Some(key) = reserved {
        return Err(ImportOptionRefusal::ReservedGrantKey(key));
    }
    Ok(())
}

pub(crate) fn validate_static_import_attributes(
    module: &Module,
) -> Result<(), ImportOptionRefusal> {
    for item in &module.body {
        let attributes = match item {
            ModuleItem::ModuleDecl(ModuleDecl::Import(import)) => import.with.as_deref(),
            ModuleItem::ModuleDecl(ModuleDecl::ExportNamed(export)) => export.with.as_deref(),
            ModuleItem::ModuleDecl(ModuleDecl::ExportAll(export)) => export.with.as_deref(),
            _ => None,
        };
        if let Some(attributes) = attributes {
            validate_data_only_object(attributes)?;
        }
    }
    Ok(())
}

fn is_unresolved_require(expression: &Expr, unresolved_ctxt: SyntaxContext) -> bool {
    matches!(expression, Expr::Ident(identifier)
        if identifier.sym == *"require" && identifier.ctxt == unresolved_ctxt)
}

fn is_runtime_import_call(call: &CallExpr, unresolved_ctxt: SyntaxContext) -> bool {
    match &call.callee {
        Callee::Import(_) => true,
        Callee::Expr(callee) if is_unresolved_require(callee, unresolved_ctxt) => true,
        Callee::Expr(callee) => matches!(callee.as_ref(),
            Expr::Member(member)
                if is_unresolved_require(member.obj.as_ref(), unresolved_ctxt)
                    && matches!(&member.prop, MemberProp::Ident(property) if property.sym == *"resolve")
        ),
        Callee::Super(_) => false,
    }
}

struct RuntimeOptionPass {
    unresolved_ctxt: SyntaxContext,
    refusal: Option<ImportOptionRefusal>,
}

impl VisitMut for RuntimeOptionPass {
    fn visit_mut_call_expr(&mut self, call: &mut CallExpr) {
        if self.refusal.is_some() {
            return;
        }
        let runtime_import = is_runtime_import_call(call, self.unresolved_ctxt);
        if runtime_import && call.args.len() > 1 {
            if call.args.len() != 2 || call.args[1].spread.is_some() {
                self.refusal = Some(ImportOptionRefusal::NonDataOnly);
                return;
            }
            let Expr::Object(options) = call.args[1].expr.as_ref() else {
                self.refusal = Some(ImportOptionRefusal::NonDataOnly);
                return;
            };
            if let Err(refusal) = validate_data_only_object(options) {
                self.refusal = Some(refusal);
                return;
            }
            // The runtime loader does not interpret ordinary attributes today;
            // the parser has proved this bag inert, so erase it before the
            // loader's alias-safe second-argument refusal.
            call.args.truncate(1);
        }
        call.visit_mut_children_with(self);
    }
}

pub(crate) fn validate_and_strip_runtime_import_options(
    program: &mut swc_ecma_ast::Program,
    unresolved_ctxt: SyntaxContext,
) -> Result<(), ImportOptionRefusal> {
    let mut pass = RuntimeOptionPass {
        unresolved_ctxt,
        refusal: None,
    };
    program.visit_mut_with(&mut pass);
    pass.refusal.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_set_is_exact_and_historical() {
        assert_eq!(
            RESERVED_IMPORT_GRANT_KEYS,
            &[
                "authorities",
                "grants",
                "endow",
                "builtins",
                "also",
                "needs"
            ]
        );
    }
}
