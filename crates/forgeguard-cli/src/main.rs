#![forbid(unsafe_code)]
//! ForgeGuard command-line entry point.
//!
//! This binary keeps process-level concerns at the edge: logging setup,
//! argument parsing, top-level error reporting, and documented exit-code
//! mapping. Scanning, report generation, policy evaluation, and SBOM logic live
//! in dedicated modules.

mod app;
mod sbom;

use app::{status_for_error, Cli, RunStatus};
use clap::Parser;
use std::{
    env,
    io::{self, Write},
    process::ExitCode,
};
use tracing_subscriber::EnvFilter;

const DEFAULT_LOG_FILTER: &str = "warn";
const RUST_BACKTRACE_ENV: &str = "RUST_BACKTRACE";

#[tokio::main]
async fn main() -> ExitCode {
    match run_process().await {
        Ok(status) => status.exit_code(),
        Err(error) => {
            print_error(&error);
            status_for_error(&error).exit_code()
        }
    }
}

async fn run_process() -> anyhow::Result<RunStatus> {
    init_tracing();
    let cli = Cli::parse();
    app::run(cli).await
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));

    // Tracing initialization is intentionally best-effort. A global subscriber
    // may already be installed by an embedding test harness or future wrapper.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(io::stderr)
        .try_init();
}

fn print_error(error: &anyhow::Error) {
    let mut stderr = io::stderr().lock();
    let _ = write_error_report(&mut stderr, error, backtrace_requested());
}

fn write_error_report(
    writer: &mut impl Write,
    error: &anyhow::Error,
    include_debug_context: bool,
) -> io::Result<()> {
    writeln!(writer, "error: {error}")?;

    for cause in error.chain().skip(1) {
        writeln!(writer, "  caused by: {cause}")?;
    }

    if include_debug_context {
        writeln!(writer, "\nDebug context:")?;
        writeln!(writer, "{error:?}")?;
    }

    Ok(())
}

fn backtrace_requested() -> bool {
    env::var(RUST_BACKTRACE_ENV)
        .map(|value| is_enabled_env_value(&value))
        .unwrap_or(false)
}

fn is_enabled_env_value(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "off" | "no"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context as _;

    #[test]
    fn writes_error_chain_without_debug_context() {
        let error = Err::<(), _>(anyhow::anyhow!("root cause"))
            .context("top-level failure")
            .expect_err("expected error");

        let mut buffer = Vec::new();
        write_error_report(&mut buffer, &error, false).expect("error report writes");
        let output = String::from_utf8(buffer).expect("valid UTF-8");

        assert!(output.contains("error: top-level failure"));
        assert!(output.contains("caused by: root cause"));
        assert!(!output.contains("Debug context:"));
    }

    #[test]
    fn writes_debug_context_when_requested() {
        let error = anyhow::anyhow!("operation failed");

        let mut buffer = Vec::new();
        write_error_report(&mut buffer, &error, true).expect("error report writes");
        let output = String::from_utf8(buffer).expect("valid UTF-8");

        assert!(output.contains("error: operation failed"));
        assert!(output.contains("Debug context:"));
    }

    #[test]
    fn parses_backtrace_environment_values() {
        assert!(!is_enabled_env_value(""));
        assert!(!is_enabled_env_value("0"));
        assert!(!is_enabled_env_value("false"));
        assert!(!is_enabled_env_value("OFF"));
        assert!(!is_enabled_env_value(" no "));
        assert!(is_enabled_env_value("1"));
        assert!(is_enabled_env_value("full"));
        assert!(is_enabled_env_value("true"));
    }
}
