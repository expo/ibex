use std::path::Path;
use std::process::Command;

/// Run hermesc from the source's directory and expose only its stable basename
/// as the compiler input label. Hermes records that label in HBC debug metadata,
/// so passing a checkout-absolute path makes otherwise identical release stubs
/// differ across builders.
// @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog — release HBC labels must be checkout-independent
pub fn append_checkout_independent_source(
    command: &mut Command,
    source: &Path,
) -> Result<(), String> {
    let source_name = source
        .file_name()
        .ok_or_else(|| format!("Hermes source has no file name: {}", source.display()))?;
    let source_directory = source
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    command.current_dir(source_directory).arg(source_name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn absolute_checkout_path_becomes_only_a_stable_source_label() {
        let mut command = Command::new("hermesc");
        append_checkout_independent_source(
            &mut command,
            Path::new("/different-builder/checkout/src/bootstrap/main.js"),
        )
        .unwrap();

        assert_eq!(
            command.get_current_dir(),
            Some(Path::new("/different-builder/checkout/src/bootstrap"))
        );
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [OsStr::new("main.js")]
        );
    }

    #[test]
    fn leaf_source_uses_the_invocation_directory() {
        let mut command = Command::new("hermesc");
        append_checkout_independent_source(&mut command, Path::new("main.js")).unwrap();

        assert_eq!(command.get_current_dir(), Some(Path::new(".")));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [OsStr::new("main.js")]
        );
    }

    #[test]
    fn directory_source_is_refused() {
        let mut command = Command::new("hermesc");
        let error = append_checkout_independent_source(&mut command, Path::new("/")).unwrap_err();
        assert!(error.contains("no file name"));
        assert!(command.get_args().next().is_none());
    }
}
