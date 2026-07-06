//! Execution manifest loader.
//!
//! Each section (wpt, node, bun, exact) has a manifest.json controlling
//! which tests to run, their timeouts, tier assignments, and skip rules.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use super::types::{CompatOptions, RunMode, Section};

/// Top-level execution manifest for a section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub section: String,
    #[serde(default)]
    pub defaults: ManifestDefaults,
    #[serde(default)]
    pub modules: HashMap<String, ModuleManifest>,
}

/// Default settings for all modules in a section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestDefaults {
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub run_mode: RunMode,
    #[serde(default = "default_tier")]
    pub tier: u8,
}

impl Default for ManifestDefaults {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout(),
            run_mode: RunMode::ChildProcess,
            tier: default_tier(),
        }
    }
}

/// Per-module settings in a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleManifest {
    #[serde(default)]
    pub tier: Option<u8>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub run_mode: Option<RunMode>,
    #[serde(default)]
    pub skip_on_platform: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_timeout() -> u64 {
    6000
}

fn default_tier() -> u8 {
    1
}

/// Loaded and resolved manifest with effective settings.
#[derive(Debug, Clone)]
pub struct ResolvedManifest {
    pub section: Section,
    pub modules: Vec<ResolvedModule>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResolvedModule {
    pub name: String,
    pub tier: u8,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub timeout_ms: u64,
    pub run_mode: RunMode,
    pub skipped: bool,
    pub skip_reason: Option<String>,
}

/// Load manifests for the requested sections.
pub fn load_manifests(compat_dir: &Path, opts: &CompatOptions) -> Result<Vec<ResolvedManifest>> {
    let sections: Vec<Section> = if let Some(ref s) = opts.section {
        match Section::from_str(s) {
            Some(section) => vec![section],
            None => anyhow::bail!(
                "Unknown section '{}'. Valid sections: wpt, node, bun, exact",
                s
            ),
        }
    } else {
        Section::all().to_vec()
    };

    let platform = current_platform();
    let mut manifests = Vec::new();

    for section in &sections {
        let manifest_path = compat_dir.join(section.as_str()).join("manifest.json");
        let manifest = if manifest_path.exists() {
            let content = std::fs::read_to_string(&manifest_path)?;
            serde_json::from_str::<Manifest>(&content)?
        } else {
            // Create a default manifest for sections without one
            Manifest {
                section: section.as_str().to_string(),
                defaults: ManifestDefaults::default(),
                modules: HashMap::new(),
            }
        };

        let resolved = resolve_manifest(*section, &manifest, &platform);
        manifests.push(resolved);
    }

    Ok(manifests)
}

fn resolve_manifest(section: Section, manifest: &Manifest, platform: &str) -> ResolvedManifest {
    let defaults = &manifest.defaults;
    let mut modules = Vec::new();

    for (name, module) in &manifest.modules {
        let skipped = module.skip_on_platform.iter().any(|p| platform.contains(p));

        modules.push(ResolvedModule {
            name: name.clone(),
            tier: module.tier.unwrap_or(defaults.tier),
            include: if module.include.is_empty() {
                vec!["**/*.js".to_string(), "**/*.ts".to_string()]
            } else {
                module.include.clone()
            },
            exclude: module.exclude.clone(),
            timeout_ms: module.timeout_ms.unwrap_or(defaults.timeout_ms),
            run_mode: module.run_mode.unwrap_or(defaults.run_mode),
            skipped,
            skip_reason: if skipped {
                module
                    .reason
                    .clone()
                    .or(Some(format!("Skipped on platform: {}", platform)))
            } else {
                None
            },
        });
    }

    ResolvedManifest { section, modules }
}

fn current_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}
