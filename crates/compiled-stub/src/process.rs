//! Compiled application argument capture.
//!
//! The stub reserves two exact first-position selectors and a leading `--`
//! escape. Every other OS argument after `argv[0]` is preserved verbatim as an
//! application argument after Unicode validation.
//! @ref LLP 0029#6-compiled-boot-and-process-semantics

use std::ffi::OsString;

use anyhow::{bail, Context, Result};

use crate::environment::CompiledBootMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedProcessArguments {
    pub invoked_name: String,
    pub application_arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProcessMetadata {
    pub exec_path: String,
    pub entry_designation: String,
    pub invoked_name: String,
    pub application_arguments: Vec<String>,
}

impl CapturedProcessArguments {
    pub fn capture(mode: CompiledBootMode) -> Result<Self> {
        decode_arguments(std::env::args_os().collect(), mode)
    }

    pub fn bind_entry(self, entry_designation: String) -> Result<CompiledProcessMetadata> {
        let exec_path = std::env::current_exe()
            .context("cannot resolve compiled executable path")?
            .into_os_string()
            .into_string()
            .map_err(|_| anyhow::anyhow!("compiled executable path is not valid Unicode"))?;
        Ok(CompiledProcessMetadata {
            exec_path,
            entry_designation,
            invoked_name: self.invoked_name,
            application_arguments: self.application_arguments,
        })
    }
}

fn decode_arguments(
    arguments: Vec<OsString>,
    mode: CompiledBootMode,
) -> Result<CapturedProcessArguments> {
    let mut decoded = Vec::with_capacity(arguments.len());
    for (index, argument) in arguments.into_iter().enumerate() {
        let argument = argument.into_string().map_err(|_| {
            anyhow::anyhow!("compiled process argument {index} is not valid Unicode")
        })?;
        decoded.push(argument);
    }
    if decoded.is_empty() {
        bail!("compiled process argument 0 is absent");
    }
    let invoked_name = decoded.remove(0);
    match mode {
        CompiledBootMode::CapsecRequested => {
            if decoded.first().map(String::as_str) != Some("--ibex-capsec") {
                bail!("pre-init CapSec selection disagrees with process arguments");
            }
            decoded.remove(0);
        }
        CompiledBootMode::InformationRequested => {
            if decoded.first().map(String::as_str) != Some("--ibex-info") {
                bail!("pre-init information selection disagrees with process arguments");
            }
            decoded.remove(0);
        }
        CompiledBootMode::AmbientCompatibility => {
            if matches!(
                decoded.first().map(String::as_str),
                Some("--ibex-capsec" | "--ibex-info")
            ) {
                bail!("pre-init ambient selection disagrees with process arguments");
            }
            if decoded.first().map(String::as_str) == Some("--") {
                decoded.remove(0);
            }
        }
    }
    Ok(CapturedProcessArguments {
        invoked_name,
        application_arguments: decoded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_ibex_spellings_remain_application_arguments() {
        let captured = decode_arguments(
            vec![
                "app".into(),
                "--inspect".into(),
                "compile".into(),
                "--policy".into(),
            ],
            CompiledBootMode::AmbientCompatibility,
        )
        .unwrap();
        assert_eq!(captured.invoked_name, "app");
        assert_eq!(
            captured.application_arguments,
            ["--inspect", "compile", "--policy"]
        );
    }

    #[test]
    fn reserved_selector_is_removed_only_in_authoritative_capsec_mode() {
        let capsec = decode_arguments(
            vec!["app".into(), "--ibex-capsec".into(), "value".into()],
            CompiledBootMode::CapsecRequested,
        )
        .unwrap();
        assert_eq!(capsec.application_arguments, ["value"]);

        let escaped = decode_arguments(
            vec!["app".into(), "--".into(), "--ibex-capsec".into()],
            CompiledBootMode::AmbientCompatibility,
        )
        .unwrap();
        assert_eq!(escaped.application_arguments, ["--ibex-capsec"]);
    }

    #[test]
    fn information_selector_is_removed_only_in_authoritative_information_mode() {
        let information = decode_arguments(
            vec!["app".into(), "--ibex-info".into(), "ignored".into()],
            CompiledBootMode::InformationRequested,
        )
        .unwrap();
        assert_eq!(information.application_arguments, ["ignored"]);

        let later = decode_arguments(
            vec!["app".into(), "value".into(), "--ibex-info".into()],
            CompiledBootMode::AmbientCompatibility,
        )
        .unwrap();
        assert_eq!(later.application_arguments, ["value", "--ibex-info"]);

        let escaped = decode_arguments(
            vec!["app".into(), "--".into(), "--ibex-info".into()],
            CompiledBootMode::AmbientCompatibility,
        )
        .unwrap();
        assert_eq!(escaped.application_arguments, ["--ibex-info"]);
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_argument_refusal_names_the_index() {
        use std::os::unix::ffi::OsStringExt as _;

        let error = decode_arguments(
            vec!["app".into(), OsString::from_vec(vec![0xff])],
            CompiledBootMode::AmbientCompatibility,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(error, "compiled process argument 1 is not valid Unicode");
    }
}
