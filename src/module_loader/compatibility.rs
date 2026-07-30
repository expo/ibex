//! Typed reasons why a source graph must use the bounded compatibility loader.
//!
//! These values are runtime/telemetry categories rather than diagnostic prose.
//! Callers may add context to `reason`, but the enum and stable code remain the
//! machine-readable contract.

use std::fmt;

use anyhow::{bail, Result};
use serde::Serialize;

pub const LEGACY_REQUIRED_TELEMETRY_PREFIX: &str = "IBEX_LEGACY_REQUIRED_EVENT ";
pub const LEGACY_REQUIRED_TELEMETRY_SCHEMA_V1: &str = "ibex/legacy-required-telemetry-event/1";

/// Stable Tier-3 `for...of` compatibility categories.
///
/// `AwaitLoop` remains active. The other values preserve telemetry/API
/// vocabulary issued by the bounded pre-parity producer and must not be
/// renumbered or silently repurposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier3ForOfQuarantineReason {
    AwaitLoop,
    VarLoopBinding,
    AssignmentLoopBinding,
    DestructuredLoopBinding,
    NonBlockBody,
    ThisExpression,
    ArgumentsReference,
    BreakStatement,
    ContinueStatement,
    ReturnStatement,
    AwaitExpression,
    YieldExpression,
    VarDeclaration,
    FunctionDeclaration,
    LoopBindingRedeclaration,
    NestedForOf,
    DirectEval,
    SuperReference,
    NewTarget,
}

impl Tier3ForOfQuarantineReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitLoop => "await-loop",
            Self::VarLoopBinding => "var-loop-binding",
            Self::AssignmentLoopBinding => "assignment-loop-binding",
            Self::DestructuredLoopBinding => "destructured-loop-binding",
            Self::NonBlockBody => "non-block-body",
            Self::ThisExpression => "this-expression",
            Self::ArgumentsReference => "arguments-reference",
            Self::BreakStatement => "break-statement",
            Self::ContinueStatement => "continue-statement",
            Self::ReturnStatement => "return-statement",
            Self::AwaitExpression => "await-expression",
            Self::YieldExpression => "yield-expression",
            Self::VarDeclaration => "var-declaration",
            Self::FunctionDeclaration => "function-declaration",
            Self::LoopBindingRedeclaration => "loop-binding-redeclaration",
            Self::NestedForOf => "nested-for-of",
            Self::DirectEval => "direct-eval",
            Self::SuperReference => "super-reference",
            Self::NewTarget => "new-target",
        }
    }
}

/// Syntax families accepted by the pinned Oxc parser but not yet lowered to
/// the advertised Hermes target by the native producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HermesSyntaxQuarantineReason {
    AsyncGenerator,
    UsingDeclaration,
    AwaitUsingDeclaration,
    Decorator,
}

impl HermesSyntaxQuarantineReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AsyncGenerator => "async-generator",
            Self::UsingDeclaration => "using-declaration",
            Self::AwaitUsingDeclaration => "await-using-declaration",
            Self::Decorator => "decorator",
        }
    }
}

/// Stable compatibility-loader categories. The human-readable explanation is
/// deliberately separate so wording changes cannot silently change telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyModuleRunnerRequirementKind {
    ComputedDynamicImport,
    ComputedCommonJsRequire,
    DynamicImportOptions,
    Tier3ForOf(Tier3ForOfQuarantineReason),
    HermesSyntax(HermesSyntaxQuarantineReason),
}

impl LegacyModuleRunnerRequirementKind {
    pub const fn stable_code(&self) -> &'static str {
        match self {
            Self::ComputedDynamicImport => "IBEX_LEGACY_COMPUTED_DYNAMIC_IMPORT",
            Self::ComputedCommonJsRequire => "IBEX_LEGACY_COMPUTED_REQUIRE",
            Self::DynamicImportOptions => "IBEX_LEGACY_DYNAMIC_IMPORT_OPTIONS",
            Self::Tier3ForOf(_) => "IBEX_LEGACY_TIER3_FOR_OF",
            Self::HermesSyntax(_) => "IBEX_LEGACY_HERMES_SYNTAX",
        }
    }

    pub const fn category(&self) -> &'static str {
        match self {
            Self::ComputedDynamicImport => "computed-dynamic-import",
            Self::ComputedCommonJsRequire => "computed-commonjs-require",
            Self::DynamicImportOptions => "dynamic-import-options",
            Self::Tier3ForOf(_) => "tier3-for-of",
            Self::HermesSyntax(_) => "hermes-syntax",
        }
    }

    pub const fn shape(&self) -> Option<&'static str> {
        match self {
            Self::Tier3ForOf(reason) => Some(reason.as_str()),
            Self::HermesSyntax(reason) => Some(reason.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyOriginalSourceSiteV1 {
    pub byte_offset: u32,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyModuleRunnerRequirement {
    pub kind: LegacyModuleRunnerRequirementKind,
    pub reason: String,
    pub original_source_offset: Option<u32>,
    pub module_source_id: Option<String>,
    pub original_source_site: Option<LegacyOriginalSourceSiteV1>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyRequiredTelemetryEventV1<'a> {
    pub schema: &'static str,
    pub category: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<&'static str>,
    pub code: &'static str,
    pub module_source_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_source_site: Option<&'a LegacyOriginalSourceSiteV1>,
    pub runtime_version: &'a str,
}

impl LegacyModuleRunnerRequirement {
    pub fn computed_dynamic_import(original_source_offset: u32) -> Self {
        Self {
            kind: LegacyModuleRunnerRequirementKind::ComputedDynamicImport,
            reason: "computed dynamic import has no authenticated finite candidate table".into(),
            original_source_offset: Some(original_source_offset),
            module_source_id: None,
            original_source_site: None,
        }
    }

    pub fn computed_commonjs_require(producer_offset: u32) -> Self {
        Self {
            kind: LegacyModuleRunnerRequirementKind::ComputedCommonJsRequire,
            reason: "computed CommonJS require has no authenticated finite candidate table".into(),
            original_source_offset: Some(producer_offset),
            module_source_id: None,
            original_source_site: None,
        }
    }

    pub fn dynamic_import_options(original_source_offset: u32) -> Self {
        Self {
            kind: LegacyModuleRunnerRequirementKind::DynamicImportOptions,
            reason: "dynamic import options are not yet representable in ModuleArtifact v1".into(),
            original_source_offset: Some(original_source_offset),
            module_source_id: None,
            original_source_site: None,
        }
    }

    pub fn tier3_for_of(producer_offset: u32, quarantine: Tier3ForOfQuarantineReason) -> Self {
        Self {
            kind: LegacyModuleRunnerRequirementKind::Tier3ForOf(quarantine),
            reason: format!(
                "native Tier 3 for-of shape is quarantined pending canonical-pass parity ({})",
                quarantine.as_str()
            ),
            original_source_offset: Some(producer_offset),
            module_source_id: None,
            original_source_site: None,
        }
    }

    pub fn hermes_syntax(producer_offset: u32, quarantine: HermesSyntaxQuarantineReason) -> Self {
        Self {
            kind: LegacyModuleRunnerRequirementKind::HermesSyntax(quarantine),
            reason: format!(
                "native producer has no advertised Hermes lowering for {}",
                quarantine.as_str()
            ),
            original_source_offset: Some(producer_offset),
            module_source_id: None,
            original_source_site: None,
        }
    }

    pub fn with_original_source(mut self, module_source_id: String, source: &str) -> Result<Self> {
        self.module_source_id = Some(module_source_id);
        if let Some(offset) = self.original_source_offset {
            let offset = usize::try_from(offset).expect("u32 fits usize on supported targets");
            if offset > source.len() || !source.is_char_boundary(offset) {
                bail!("LegacyRequired original-source offset is outside its UTF-8 module");
            }
            let prefix = &source[..offset];
            let line = u32::try_from(prefix.bytes().filter(|byte| *byte == b'\n').count() + 1)?;
            let column = u32::try_from(
                prefix
                    .rsplit_once('\n')
                    .map_or(prefix, |(_, tail)| tail)
                    .chars()
                    .count()
                    + 1,
            )?;
            self.original_source_site = Some(LegacyOriginalSourceSiteV1 {
                byte_offset: u32::try_from(offset).expect("offset originated as u32"),
                line,
                column,
            });
        }
        Ok(self)
    }

    pub fn telemetry_event(
        &self,
        runtime_version: &'static str,
    ) -> Result<LegacyRequiredTelemetryEventV1<'_>> {
        let Some(module_source_id) = self.module_source_id.as_deref() else {
            bail!("LegacyRequired telemetry is missing its canonical module SourceId");
        };
        Ok(LegacyRequiredTelemetryEventV1 {
            schema: LEGACY_REQUIRED_TELEMETRY_SCHEMA_V1,
            category: self.kind.category(),
            shape: self.kind.shape(),
            code: self.kind.stable_code(),
            module_source_id,
            original_source_site: self.original_source_site.as_ref(),
            runtime_version,
        })
    }
}

impl fmt::Display for LegacyModuleRunnerRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.stable_code(), self.reason)?;
        if let Some(site) = &self.original_source_site {
            write!(f, " at original source {}:{}", site.line, site.column)?;
        } else if let Some(offset) = self.original_source_offset {
            write!(f, " at original source byte offset {offset}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_event_names_the_canonical_module_and_original_source_site() {
        let source = "const value = 1;\nawait import(value);\n";
        let offset = u32::try_from(source.find("import(value)").unwrap()).unwrap();
        let requirement = LegacyModuleRunnerRequirement::computed_dynamic_import(offset)
            .with_original_source("ibex-source-id-v1:test".into(), source)
            .unwrap();
        let event = requirement.telemetry_event("0.1.0-test").unwrap();
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["schema"], LEGACY_REQUIRED_TELEMETRY_SCHEMA_V1);
        assert_eq!(value["category"], "computed-dynamic-import");
        assert_eq!(value["code"], "IBEX_LEGACY_COMPUTED_DYNAMIC_IMPORT");
        assert_eq!(value["moduleSourceId"], "ibex-source-id-v1:test");
        assert_eq!(value["originalSourceSite"]["line"], 2);
        assert_eq!(value["originalSourceSite"]["column"], 7);
        assert_eq!(value["runtimeVersion"], "0.1.0-test");
        assert!(value.get("shape").is_none());
    }

    #[test]
    fn telemetry_refuses_invalid_or_unattributed_sites() {
        assert!(LegacyModuleRunnerRequirement::computed_dynamic_import(99)
            .with_original_source("ibex-source-id-v1:test".into(), "import(x)")
            .is_err());
        assert!(LegacyModuleRunnerRequirement::computed_dynamic_import(0)
            .telemetry_event("0.1.0-test")
            .is_err());
    }
}
