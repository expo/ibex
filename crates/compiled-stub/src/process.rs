//! Compiled application argument capture.
//!
//! The stub has no command grammar. OS arguments after `argv[0]` are preserved
//! verbatim as application arguments after Unicode validation; Ibex option and
//! subcommand spellings have no special meaning here.
//! @ref LLP 0029#6-compiled-boot-and-process-semantics

use std::ffi::OsString;

use anyhow::{bail, Context, Result};

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
    pub fn capture() -> Result<Self> {
        decode_arguments(std::env::args_os().collect())
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

fn decode_arguments(arguments: Vec<OsString>) -> Result<CapturedProcessArguments> {
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
    Ok(CapturedProcessArguments {
        invoked_name: decoded.remove(0),
        application_arguments: decoded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_ibex_spellings_remain_application_arguments() {
        let captured = decode_arguments(vec![
            "app".into(),
            "--inspect".into(),
            "compile".into(),
            "--policy".into(),
        ])
        .unwrap();
        assert_eq!(captured.invoked_name, "app");
        assert_eq!(
            captured.application_arguments,
            ["--inspect", "compile", "--policy"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_argument_refusal_names_the_index() {
        use std::os::unix::ffi::OsStringExt as _;

        let error = decode_arguments(vec!["app".into(), OsString::from_vec(vec![0xff])])
            .unwrap_err()
            .to_string();
        assert_eq!(error, "compiled process argument 1 is not valid Unicode");
    }
}
