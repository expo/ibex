//! Product-neutral compiled-executable mount semantics.
//!
//! The caller supplies whether an authenticated `/work` binding exists; this
//! module deliberately does not decide whether cwd authority is implicit or
//! policy-authored. `/app` is always a module/diagnostic namespace and never a
//! filesystem mount in the v1 envelope.
//! @ref LLP 0029#4-compiled-mode-authority

use crate::model::{LogicalPath, LogicalRoot, PathComponent};

pub const COMPILED_CWD_UNSET_SENTINEL_V1: &str = "ibex:cwd:unset";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompiledMountErrorKindV1 {
    MalformedPath,
    AppFilesystemUnavailable,
    WorkMountUnavailable,
    OutsideMount,
    SyntheticNode,
}

impl CompiledMountErrorKindV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::MalformedPath => "ERR_INVALID_ARG_VALUE",
            Self::AppFilesystemUnavailable => "ERR_IBEX_COMPILED_APP_NOT_FILESYSTEM",
            Self::WorkMountUnavailable => "ERR_IBEX_COMPILED_CWD_UNSET",
            Self::OutsideMount => "ERR_IBEX_OUTSIDE_MOUNT",
            Self::SyntheticNode => "ERR_IBEX_SYNTHETIC_NODE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledMountErrorV1 {
    pub kind: CompiledMountErrorKindV1,
    pub input: String,
}

impl std::fmt::Display for CompiledMountErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.kind.code(), self.input)
    }
}

impl std::error::Error for CompiledMountErrorV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompiledMountTableV1 {
    work_mounted: bool,
}

impl CompiledMountTableV1 {
    pub const fn new(work_mounted: bool) -> Self {
        Self { work_mounted }
    }

    pub const fn work_mounted(self) -> bool {
        self.work_mounted
    }

    /// The authenticated cwd view and relative-resolution base are one value.
    /// @ref LLP 0023#53-cwd-visibility-is-an-explicit-information-grant
    pub const fn cwd_view(self) -> &'static str {
        if self.work_mounted {
            "/work"
        } else {
            COMPILED_CWD_UNSET_SENTINEL_V1
        }
    }

    /// Resolve syntax into the only filesystem-visible compiled root. This
    /// performs no host lookup; later arming/adapters authenticate the returned
    /// `/work` identity before any filesystem effect.
    /// @ref LLP 0023#3-path-grammar-normalization-aliasing-and-containment
    pub fn resolve_filesystem_path(self, input: &str) -> Result<LogicalPath, CompiledMountErrorV1> {
        if input.is_empty() || input.contains('\0') {
            return Err(error(CompiledMountErrorKindV1::MalformedPath, input));
        }

        let mut components = if input.starts_with('/') {
            Vec::new()
        } else if self.work_mounted {
            vec!["work".to_owned()]
        } else {
            return Err(error(CompiledMountErrorKindV1::WorkMountUnavailable, input));
        };
        for component in input.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    components.pop();
                }
                value => components.push(value.to_owned()),
            }
        }

        let Some(root) = components.first().map(String::as_str) else {
            return Err(error(CompiledMountErrorKindV1::SyntheticNode, input));
        };
        match root {
            "app" => Err(error(
                CompiledMountErrorKindV1::AppFilesystemUnavailable,
                input,
            )),
            "work" if !self.work_mounted => {
                Err(error(CompiledMountErrorKindV1::WorkMountUnavailable, input))
            }
            "work" => {
                let components = components
                    .into_iter()
                    .skip(1)
                    .map(|value| {
                        PathComponent::utf8(value)
                            .map_err(|_| error(CompiledMountErrorKindV1::MalformedPath, input))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(LogicalPath {
                    root: LogicalRoot::Work,
                    components,
                    host_bound: None,
                })
            }
            _ => Err(error(CompiledMountErrorKindV1::OutsideMount, input)),
        }
    }
}

fn error(kind: CompiledMountErrorKindV1, input: &str) -> CompiledMountErrorV1 {
    CompiledMountErrorV1 {
        kind,
        input: input.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_work_has_an_unambiguous_view_and_denies_relative_paths() {
        let mounts = CompiledMountTableV1::new(false);
        assert_eq!(mounts.cwd_view(), COMPILED_CWD_UNSET_SENTINEL_V1);
        assert_eq!(
            mounts
                .resolve_filesystem_path("state.json")
                .unwrap_err()
                .kind,
            CompiledMountErrorKindV1::WorkMountUnavailable
        );
        assert_eq!(
            mounts
                .resolve_filesystem_path("/work/state.json")
                .unwrap_err()
                .kind,
            CompiledMountErrorKindV1::WorkMountUnavailable
        );
    }

    #[test]
    fn app_is_never_a_filesystem_mount() {
        for mounted in [false, true] {
            let error = CompiledMountTableV1::new(mounted)
                .resolve_filesystem_path("/app/modules/entry.mjs")
                .unwrap_err();
            assert_eq!(
                error.kind,
                CompiledMountErrorKindV1::AppFilesystemUnavailable
            );
            assert_eq!(error.kind.code(), "ERR_IBEX_COMPILED_APP_NOT_FILESYSTEM");
        }
    }

    #[test]
    fn mounted_work_normalizes_without_clamping_escape_to_the_mount() {
        let mounts = CompiledMountTableV1::new(true);
        assert_eq!(mounts.cwd_view(), "/work");
        assert_eq!(
            mounts
                .resolve_filesystem_path("state/../result.json")
                .unwrap(),
            LogicalPath {
                root: LogicalRoot::Work,
                components: vec![PathComponent::utf8("result.json").unwrap()],
                host_bound: None,
            }
        );
        assert_eq!(
            mounts
                .resolve_filesystem_path("../etc/passwd")
                .unwrap_err()
                .kind,
            CompiledMountErrorKindV1::OutsideMount
        );
    }
}
