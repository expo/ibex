//! CLI argument parsing for the `ibex` command
//!
//! `ibex` runs JavaScript and TypeScript. Project tooling remains on the
//! `exact` binary; reserved-but-unbuilt runtime names (`test`, `install`,
//! `bench`, `exec`) are absent from this clap tree and intercepted by the
//! pre-clap dispatcher in `main.rs`. The hidden `self-test` command is a CI
//! harness smoke, not a user-facing test runner.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Ibex CLI - A JavaScript/TypeScript runtime with web APIs
#[derive(Parser, Debug, Clone)]
#[command(name = "ibex")]
#[command(author = "Ibex Runtime Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Run JavaScript/TypeScript with web-standard APIs", long_about = None)]
#[command(propagate_version = true)]
#[command(disable_version_flag = true)]
#[command(
    after_help = "Examples:\n  ibex app.ts                  Run a TypeScript file\n  ibex eval '1 + 1'            Evaluate an expression\n  ibex -p 'process.versions'   Evaluate and print the result\n  ibex --watch server.ts       Run with auto-restart on changes\n  ibex run dev                 Run a package script\n  ibex build app.ts            Compile to Hermes bytecode\n  ibex completions zsh         Generate shell completions\n  ibex debug modules           Print builtin module registry metadata\n  ibex repl                    Interactive REPL (also: ibex with no arguments)"
)]
pub struct Cli {
    /// Print version information
    #[arg(short = 'v', short_alias = 'V', long = "version")]
    pub version: bool,

    /// JavaScript engine to use
    // @ref LLP 0010#runtime-command-surface — the public binary is Hermes-only
    // until another engine exists behind an accepted local design.
    #[arg(long, default_value = "hermes", value_parser = ["hermes"])]
    pub engine: String,

    /// Enable inspector/debugger
    #[arg(long)]
    pub inspect: bool,

    /// Wait for debugger to attach before running
    #[arg(long)]
    pub inspect_wait: bool,

    /// Open DevTools automatically when inspector starts
    #[arg(long)]
    pub inspect_open: bool,

    /// Pause on the first statement after debugger attach
    #[arg(long)]
    pub inspect_pause: bool,

    /// Keep the process alive after running (useful for DevTools)
    #[arg(long)]
    pub keep_alive: bool,

    /// Inspector port (default: 9229)
    #[arg(long)]
    pub inspect_port: Option<u16>,

    /// Inspector host (default: 127.0.0.1). Use 0.0.0.0 for remote debugging.
    #[arg(long)]
    pub inspect_host: Option<String>,

    /// Capability security mode
    #[arg(long, value_enum, default_value = "permissive")]
    pub capsec: CapSecMode,

    /// Enable an opt-in compatibility surface. `bun` installs the Bun-shaped
    /// global facade and sets process.versions.bun.
    #[arg(long, value_name = "MODE", value_parser = ["bun"])]
    pub compat: Option<String>,

    /// Bundler output format. Hidden: Hermes executes CJS only, so the
    /// effective format is always coerced; this stays internal plumbing until
    /// an ESM-capable engine exists.
    #[arg(long, value_enum, default_value = "esm", hide = true)]
    pub bundle_format: BundleFormat,

    /// Capability policy file
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Allow capability (can be repeated)
    #[arg(long, value_name = "CAPABILITY")]
    pub allow: Vec<String>,

    /// Deny capability (can be repeated)
    #[arg(long, value_name = "CAPABILITY")]
    pub deny: Vec<String>,

    /// Disable capability checks (legacy mode)
    #[arg(long)]
    pub allow_all: bool,

    /// Watch for file changes and auto-restart
    #[arg(long)]
    pub watch: bool,

    /// Output a Bash completion script and exit (alias of `ibex
    /// completions bash`; hidden — the subcommand is the documented form)
    #[arg(long = "completion-bash", hide = true)]
    pub completion_bash: bool,

    /// Evaluate JavaScript code (Node/Bun-compatible shorthand for `eval`)
    #[arg(short = 'e', long = "eval", value_name = "CODE")]
    pub eval_code: Option<String>,

    /// Evaluate JavaScript code and print the result
    #[arg(short = 'p', long = "print", value_name = "CODE")]
    pub print_eval: Option<String>,

    /// Expose internals (Node.js compatibility flag, ignored; kept hidden for
    /// execArgv fidelity)
    #[arg(long = "expose-internals", hide = true)]
    pub expose_internals: bool,

    /// Stack size (Node.js compatibility flag, ignored; kept hidden for
    /// compat-fixture execArgv fidelity)
    #[arg(long = "stack-size", value_name = "SIZE", hide = true)]
    pub stack_size: Option<String>,

    /// Max HTTP header size (Node/Bun compatibility flag; recorded into
    /// process.execArgv for compat fixtures)
    #[arg(long = "max-http-header-size", value_name = "BYTES", hide = true)]
    pub max_http_header_size: Option<usize>,

    /// File to run (shorthand for `ibex run <file>`)
    #[arg(value_name = "FILE")]
    pub file: Option<String>,

    /// Arguments passed to the script (shorthand form: `ibex <file> <arg1> <arg2> ...`)
    #[arg(value_name = "ARGS", num_args = 0.., allow_hyphen_values = true)]
    pub args: Vec<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum Commands {
    /// Run a JavaScript/TypeScript file or package script
    Run {
        /// The file to execute, or package script name when no local file exists
        #[arg(required = true)]
        file: String,

        /// Watch for file changes and auto-restart
        #[arg(long)]
        watch: bool,

        /// Enable inspector/debugger
        #[arg(long)]
        inspect: bool,

        /// Wait for debugger to attach before running
        #[arg(long)]
        inspect_wait: bool,

        /// Open DevTools automatically when inspector starts
        #[arg(long)]
        inspect_open: bool,

        /// Pause on the first statement after debugger attach
        #[arg(long)]
        inspect_pause: bool,

        /// Keep the process alive after running
        #[arg(long)]
        keep_alive: bool,

        /// Inspector port (default: 9229)
        #[arg(long)]
        inspect_port: Option<u16>,

        /// Inspector host (default: 127.0.0.1). Use 0.0.0.0 for remote debugging.
        #[arg(long)]
        inspect_host: Option<String>,

        /// Arguments passed to the script
        #[arg(value_name = "ARGS", num_args = 0.., allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Evaluate JavaScript code
    Eval {
        /// The code to evaluate
        #[arg(required = true)]
        code: String,
    },

    /// Start an interactive REPL
    Repl,

    /// Compile to Hermes bytecode
    Build {
        /// The file to compile
        #[arg(required = true)]
        file: String,

        /// Output directory (default: ./dist)
        #[arg(long)]
        outdir: Option<PathBuf>,
    },

    /// Generate shell completions
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Print version information
    Version,

    /// Print internal runtime diagnostics
    Debug {
        #[command(subcommand)]
        command: DebugCommands,
    },

    /// Run the hidden in-binary runtime smoke suite
    #[command(hide = true, name = "self-test")]
    SelfTest,
}

#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum DebugCommands {
    /// Print builtin module registry entries and source metadata
    Modules,
}

/// Capability security enforcement mode for CLI
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapSecMode {
    /// Allow all capabilities (development/legacy mode)
    Permissive,
    /// Enforce capability declarations, wildcards allowed
    Capability,
    /// Enforce capability declarations, no wildcards
    Strict,
}

/// Bundler output format for runnable files
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleFormat {
    /// Generate CommonJS output
    Cjs,
    /// Generate ESM output
    Esm,
}

impl BundleFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cjs => "cjs",
            Self::Esm => "esm",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_default_engine() {
        let cli = Cli::parse_from(["ibex", "test.js"]);
        assert_eq!(cli.engine, "hermes");
    }

    #[test]
    fn engine_rejects_unimplemented_values() {
        assert!(Cli::try_parse_from(["ibex", "--engine", "jsc", "test.js"]).is_err());
        assert!(Cli::try_parse_from(["ibex", "--engine", "v8", "test.js"]).is_err());
    }

    #[test]
    fn test_run_command() {
        let cli = Cli::parse_from(["ibex", "run", "test.js"]);
        assert!(matches!(cli.command, Some(Commands::Run { ref file, .. }) if file == "test.js"));
    }

    #[test]
    fn test_run_command_with_args() {
        let cli = Cli::parse_from(["ibex", "run", "test.js", "foo", "bar"]);
        assert!(matches!(
            cli.command,
            Some(Commands::Run { ref file, ref args, .. })
                if file == "test.js" && args == &vec!["foo".to_string(), "bar".to_string()]
        ));
    }

    #[test]
    fn test_run_command_with_flag_arg() {
        let cli = Cli::parse_from(["ibex", "run", "test.js", "--foo", "bar"]);
        assert!(matches!(
            cli.command,
            Some(Commands::Run { ref file, ref args, .. })
                if file == "test.js" && args == &vec!["--foo".to_string(), "bar".to_string()]
        ));
    }

    #[test]
    fn test_eval_flag() {
        let cli = Cli::parse_from(["ibex", "-e", "1 + 1"]);
        assert_eq!(cli.eval_code, Some("1 + 1".to_string()));
        assert_eq!(cli.command, None);
    }

    #[test]
    fn eval_and_print_long_forms_match_node() {
        let cli = Cli::parse_from(["ibex", "--eval", "1 + 1"]);
        assert_eq!(cli.eval_code, Some("1 + 1".to_string()));
        let cli = Cli::parse_from(["ibex", "--print", "2 + 2"]);
        assert_eq!(cli.print_eval, Some("2 + 2".to_string()));
    }

    #[test]
    fn test_default_file_with_args() {
        let cli = Cli::parse_from(["ibex", "test.js", "foo", "bar"]);
        assert_eq!(cli.file, Some("test.js".to_string()));
        assert_eq!(cli.args, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn test_default_file_with_flag_arg() {
        let cli = Cli::parse_from(["ibex", "test.js", "--foo", "bar"]);
        assert_eq!(cli.file, Some("test.js".to_string()));
        assert_eq!(cli.args, vec!["--foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn test_eval_command() {
        let cli = Cli::parse_from(["ibex", "eval", "1 + 1"]);
        assert!(matches!(cli.command, Some(Commands::Eval { ref code }) if code == "1 + 1"));
    }

    #[test]
    fn test_engine_flag() {
        let cli = Cli::parse_from(["ibex", "--engine", "hermes", "test.js"]);
        assert_eq!(cli.engine, "hermes");
        assert!(Cli::try_parse_from(["ibex", "--engine", "jsc", "test.js"]).is_err());
        assert!(Cli::try_parse_from(["ibex", "--engine", "v8", "test.js"]).is_err());
    }

    #[test]
    fn test_inspect_flags() {
        let cli = Cli::parse_from(["ibex", "--inspect", "--inspect-port", "9230", "test.js"]);
        assert!(cli.inspect);
        assert_eq!(cli.inspect_port, Some(9230));
    }

    #[test]
    fn test_inspect_pause_flag() {
        let cli = Cli::parse_from(["ibex", "--inspect-pause", "test.js"]);
        assert!(cli.inspect_pause);
    }

    #[test]
    fn test_max_http_header_size_flag() {
        let cli = Cli::parse_from(["ibex", "--max-http-header-size", "1024", "test.js"]);
        assert_eq!(cli.max_http_header_size, Some(1024));
        assert_eq!(cli.file, Some("test.js".to_string()));
    }

    #[test]
    fn test_security_flags() {
        let cli = Cli::parse_from([
            "ibex",
            "--allow",
            "fs:read:/tmp",
            "--deny",
            "net",
            "--allow-all",
            "test.js",
        ]);
        assert_eq!(cli.allow, vec!["fs:read:/tmp".to_string()]);
        assert_eq!(cli.deny, vec!["net".to_string()]);
        assert!(cli.allow_all);
    }

    #[test]
    fn completions_command_parses() {
        let cli = Cli::parse_from(["ibex", "completions", "zsh"]);
        assert!(matches!(
            cli.command,
            Some(Commands::Completions { shell }) if shell == clap_complete::Shell::Zsh
        ));
    }

    #[test]
    fn test_debug_modules_command() {
        let cli = Cli::parse_from(["ibex", "debug", "modules"]);
        assert!(matches!(
            cli.command,
            Some(Commands::Debug {
                command: DebugCommands::Modules,
            })
        ));
    }

    #[test]
    fn self_test_command_parses() {
        let cli = Cli::parse_from(["ibex", "self-test"]);
        assert!(matches!(cli.command, Some(Commands::SelfTest)));
    }

    #[test]
    fn runtime_only_clap_tree_has_no_reserved_or_project_commands() {
        let cmd = Cli::command();
        let mut visible: Vec<String> = cmd
            .get_subcommands()
            .filter(|c| !c.is_hide_set())
            .map(|c| c.get_name().to_string())
            .collect();
        visible.sort();
        assert_eq!(
            visible,
            [
                "build",
                "completions",
                "debug",
                "eval",
                "repl",
                "run",
                "version"
            ]
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>(),
            "visible clap subcommands"
        );

        let all: Vec<String> = cmd
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        for reserved in ["test", "install", "bench", "exec"] {
            assert!(
                !all.iter().any(|name| name == reserved),
                "reserved name `{reserved}` must not be a clap subcommand"
            );
        }
        for legacy in [
            "new", "create", "init", "verify", "facet", "agent", "mcp", "doctor", "lint",
        ] {
            assert!(
                !all.iter().any(|name| name == legacy),
                "Exact project name `{legacy}` must not be a clap subcommand"
            );
        }
    }
}
