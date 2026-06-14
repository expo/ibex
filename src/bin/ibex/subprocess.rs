use anyhow::{anyhow, Context, Result};
use std::process::Output;
use std::time::Duration;
use tokio::process::Command;

pub const DEFAULT_BUNDLER_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_HERMESC_TIMEOUT_MS: u64 = 60_000;

pub fn parse_timeout_ms(value: Option<&str>, default_ms: u64) -> Duration {
    value
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|timeout_ms| *timeout_ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(default_ms))
}

pub fn timeout_from_env(name: &str, default_ms: u64) -> Duration {
    let raw = std::env::var(name).ok();
    parse_timeout_ms(raw.as_deref(), default_ms)
}

pub async fn output_with_timeout(
    command: &mut Command,
    timeout: Duration,
    label: &str,
) -> Result<Output> {
    command.kill_on_drop(true);
    match tokio::time::timeout(timeout, command.output()).await {
        Ok(result) => result.with_context(|| format!("Failed to run {label}")),
        Err(_) => Err(anyhow!("{label} timed out after {}ms", timeout.as_millis())),
    }
}

#[cfg(test)]
mod tests {
    use super::{output_with_timeout, parse_timeout_ms};
    use std::time::Duration;
    use tokio::process::Command;

    #[cfg(unix)]
    fn echo_command() -> Command {
        let mut command = Command::new("sh");
        command.arg("-c").arg("printf ibex");
        command
    }

    #[cfg(windows)]
    fn echo_command() -> Command {
        let mut command = Command::new("cmd");
        command.arg("/C").arg("echo|set /p=ibex");
        command
    }

    #[cfg(unix)]
    fn sleep_command() -> Command {
        let mut command = Command::new("sh");
        command.arg("-c").arg("sleep 1");
        command
    }

    #[cfg(windows)]
    fn sleep_command() -> Command {
        let mut command = Command::new("cmd");
        command.arg("/C").arg("ping -n 2 127.0.0.1 >NUL");
        command
    }

    #[test]
    fn parse_timeout_ms_falls_back_for_invalid_values() {
        assert_eq!(parse_timeout_ms(Some("1500"), 500).as_millis(), 1500);
        assert_eq!(parse_timeout_ms(Some("0"), 500).as_millis(), 500);
        assert_eq!(parse_timeout_ms(Some("bad"), 500).as_millis(), 500);
        assert_eq!(parse_timeout_ms(None, 500).as_millis(), 500);
    }

    #[tokio::test]
    async fn output_with_timeout_returns_stdout() {
        let mut command = echo_command();
        let output = output_with_timeout(&mut command, Duration::from_secs(1), "echo")
            .await
            .expect("command should succeed");
        assert_eq!(String::from_utf8_lossy(&output.stdout), "ibex");
    }

    #[tokio::test]
    async fn output_with_timeout_reports_timeouts() {
        let mut command = sleep_command();
        let error = output_with_timeout(&mut command, Duration::from_millis(10), "sleep")
            .await
            .expect_err("command should time out");
        assert!(error.to_string().contains("timed out after 10ms"));
    }
}
