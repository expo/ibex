//! CLI argument parsing for the `ibex` command
//!
//! `ibex` runs JavaScript and TypeScript. Project tooling remains on the
//! `exact` binary; reserved-but-unbuilt runtime names (`test`, `install`,
//! `bench`, `exec`) are absent from this clap tree and intercepted by the
//! pre-clap dispatcher in `main.rs`. The hidden `self-test` command is a CI
//! harness smoke, not a user-facing test runner; the hidden `compat` command
//! is the WPT/exact compat harness (fixtures live in the exact repo).

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
    #[arg(long, value_enum, default_value = "auto")]
    pub capsec: CapSecMode,

    /// Harden the runtime at boot: freeze the shared intrinsics and tame the
    /// intrinsic evaluators (SES-style lockdown). Opt-in — it can break packages
    /// that mutate intrinsics. Composes with any `--capsec` mode.
    /// @ref LLP 0013#mechanism-1
    #[arg(long)]
    pub lockdown: bool,

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

    /// Permit `IBEX_ENDOW` to add or widen compartment endowments even under an
    /// enforce-mode policy. Development escape hatch: by default a generated
    /// enforce policy is the sole endowment source and an ambient `IBEX_ENDOW`
    /// cannot broaden it. @ref LLP 0013#mechanism-2
    #[arg(long)]
    pub allow_env_endowments: bool,

    /// Let `--capsec enforce` proceed even when a hard attribution prerequisite
    /// is missing (frame-derived attribution compiled out of the linked engine,
    /// or per-package isolation explicitly disabled). Capability decisions still
    /// run, but attribution is ADVISORY: a dependency's access may be attributed
    /// to the trusted root. Also honored via `IBEX_CAPSEC_ALLOW_ADVISORY=1`;
    /// `--allow-advisory-attribution` is accepted as a hidden compatibility alias.
    /// @ref LLP 0013#mechanism-3 (ENG-22884)
    #[arg(long, alias = "allow-advisory-attribution")]
    pub capsec_allow_advisory: bool,

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

    /// Generate or check the capability policy artifact (LLP 0014)
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// Run the hidden in-binary runtime smoke suite
    #[command(hide = true, name = "self-test")]
    SelfTest,

    /// Run compatibility test suite (WPT, Node.js, Bun, Exact) — repo
    /// harness; requires the fixture tree (`test/compat/` in the exact
    /// repo). Ported from exact-cli (ENG-23081); hidden like `self-test`
    /// per LLP 0010#runtime-command-surface.
    #[command(hide = true)]
    Compat {
        /// Run only a specific section: wpt, node, bun, exact
        #[arg(long, value_name = "SECTION")]
        section: Option<String>,

        /// Run tests for a specific module across all sections
        #[arg(long, value_name = "MODULE")]
        module: Option<String>,

        /// Filter tests by ID substring (can be repeated for multiple tests)
        #[arg(long, short = 't', value_name = "FILTER")]
        test: Vec<String>,

        /// Run only Tier 0 subset (~500 tests, <30s)
        #[arg(long)]
        quick: bool,

        /// Re-run only tests that failed in the previous run
        #[arg(long)]
        failed: bool,

        /// Run suite and overwrite expectations with current results
        #[arg(long)]
        update_expectations: bool,

        /// Generate web report after running
        #[arg(long)]
        report: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,

        /// Stream live pass/fail output to the console.
        #[arg(long, conflicts_with = "json")]
        log: bool,

        /// Add ANSI colors to `--log` output.
        #[arg(long)]
        log_color: bool,

        /// Skip printing SKIP lines in `--log` output.
        #[arg(long)]
        log_no_skip: bool,

        /// Number of parallel test processes (default: min(CPU count, 4))
        #[arg(long, short = 'j', value_name = "N")]
        jobs: Option<usize>,

        /// Treat flaky tests as failures
        #[arg(long)]
        strict: bool,

        /// Run all tiers including Tier 2 (third-party)
        #[arg(long)]
        all: bool,

        /// Skip flaky-detection retries for failed tests
        #[arg(long)]
        no_retry: bool,

        /// Override timeout per test in milliseconds (default: 6000)
        #[arg(long, value_name = "MS")]
        timeout: Option<u64>,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum DebugCommands {
    /// Print builtin module registry entries and source metadata
    Modules,
}

/// `ibex policy` — the LLP 0014 grant-authoring toolchain: the policy file is
/// generated from root-principal import-site grant declarations, committed,
/// and drift-checked; it is not hand-maintained.
#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum PolicyCommands {
    /// Generate the policy artifact from the entry's import-site grants
    Generate {
        /// Entry point whose module graph scopes the policy
        #[arg(long)]
        entry: PathBuf,

        /// Artifact path (default: <entry dir>/ibex-policy.json)
        #[arg(long)]
        out: Option<PathBuf>,

        /// Policy mode recorded in the artifact
        #[arg(long)]
        mode: Option<String>,
    },
    /// Regenerate and fail if the committed artifact drifted (CI gate)
    Check {
        /// Entry point whose module graph scopes the policy
        #[arg(long)]
        entry: PathBuf,

        /// Artifact path to check (default: <entry dir>/ibex-policy.json)
        #[arg(long)]
        out: Option<PathBuf>,

        /// Policy mode the artifact was generated with. Must be forwarded so a
        /// policy generated with `--mode audit` doesn't false-drift against a
        /// regeneration that defaults to `enforce`. (ENG-22642)
        #[arg(long)]
        mode: Option<String>,
    },
}

/// Capability security enforcement mode for CLI.
///
/// @ref LLP 0013#phase-0 — the old `capability`/`strict` split was a no-op; they
/// are kept as hidden back-compat aliases for the single `enforce` mode. `audit`
/// (Phase 1) logs would-deny decisions but lets operations proceed.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapSecMode {
    /// Default: honor the policy artifact's declared `mode`, else permissive.
    Auto,
    /// Force permissive — allow all capabilities (development/legacy mode) even if
    /// a policy declares a stricter mode.
    Permissive,
    /// Log would-deny decisions but let operations proceed (supply-chain audit)
    Audit,
    /// Enforce capability declarations; deny on a miss
    #[value(alias = "strict", alias = "capability")]
    Enforce,
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
            "--capsec-allow-advisory",
            "test.js",
        ]);
        assert_eq!(cli.allow, vec!["fs:read:/tmp".to_string()]);
        assert_eq!(cli.deny, vec!["net".to_string()]);
        assert!(cli.allow_all);
        assert!(cli.capsec_allow_advisory);
    }

    #[test]
    fn advisory_attribution_alias_parses() {
        let cli = Cli::parse_from(["ibex", "--allow-advisory-attribution", "test.js"]);
        assert!(cli.capsec_allow_advisory);
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

    /// The registered exact-side checks invoke exactly this surface
    /// (`compat --section wpt --module websockets --log --log-no-skip -j N
    /// --timeout MS --strict --no-retry` and the `--section exact
    /// --module websocket-server` variant) — pin that it parses. (ENG-23081)
    #[test]
    fn compat_command_parses_registered_check_surface() {
        let cli = Cli::parse_from([
            "ibex",
            "compat",
            "--section",
            "wpt",
            "--module",
            "websockets",
            "--strict",
            "--no-retry",
            "-j",
            "2",
            "--timeout",
            "15000",
            "--log",
            "--log-no-skip",
        ]);
        match cli.command {
            Some(Commands::Compat {
                section,
                module,
                strict,
                no_retry,
                jobs,
                timeout,
                log,
                log_no_skip,
                json,
                all,
                ..
            }) => {
                assert_eq!(section.as_deref(), Some("wpt"));
                assert_eq!(module.as_deref(), Some("websockets"));
                assert!(strict);
                assert!(no_retry);
                assert_eq!(jobs, Some(2));
                assert_eq!(timeout, Some(15000));
                assert!(log);
                assert!(log_no_skip);
                assert!(!json);
                assert!(!all);
            }
            other => panic!("expected Compat command, got {other:?}"),
        }
    }

    #[test]
    fn compat_all_flag_parses_and_log_conflicts_with_json() {
        let cli = Cli::parse_from(["ibex", "compat", "--all"]);
        assert!(matches!(
            cli.command,
            Some(Commands::Compat { all: true, .. })
        ));
        assert!(Cli::try_parse_from(["ibex", "compat", "--log", "--json"]).is_err());
    }

    /// The runtime surface manifest (`runtime-surface.json` at the repo root,
    /// LLP 0010#runtime-command-surface) is the single authority for what is
    /// visible, hidden, reserved, and legacy-shimmed. This test pins the clap
    /// tree to it — ported from exact's stranded
    /// `packages/exact-cli/src/cli.rs::surface_manifest_matches_clap_tree`
    /// (LLP 0175 §8.1a) after the LLP 0180 split (ENG-22429). It supersedes
    /// the earlier hardcoded-list test
    /// `runtime_only_clap_tree_has_no_reserved_or_project_commands`.
    #[test]
    fn surface_manifest_matches_clap_tree() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../../runtime-surface.json"))
                .expect("runtime-surface.json parses");

        let names = |key: &str| -> Vec<String> {
            manifest[key]
                .as_array()
                .unwrap_or_else(|| panic!("{key} is an array"))
                .iter()
                .map(|v| v.as_str().expect("string entry").to_string())
                .collect()
        };

        let cmd = Cli::command();
        let mut visible: Vec<String> = cmd
            .get_subcommands()
            .filter(|c| !c.is_hide_set())
            .map(|c| c.get_name().to_string())
            .collect();
        visible.sort();
        let mut manifest_visible = names("visibleCommands");
        manifest_visible.sort();
        assert_eq!(visible, manifest_visible, "visible clap subcommands");

        // Unlike exact's original, ibex has no `harness` cargo feature: the
        // hidden harness surface (`self-test`) is always compiled in, so the
        // hidden set must match the manifest unconditionally.
        let mut hidden: Vec<String> = cmd
            .get_subcommands()
            .filter(|c| c.is_hide_set())
            .map(|c| c.get_name().to_string())
            .collect();
        hidden.sort();
        let mut manifest_hidden = names("hiddenHarnessCommands");
        manifest_hidden.sort();
        assert_eq!(hidden, manifest_hidden, "hidden clap subcommands");

        // Reserved and legacy names must NOT exist in the clap tree at all —
        // the pre-clap dispatcher in main.rs owns them.
        let all: Vec<String> = cmd
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        for reserved in names("reservedCommands") {
            assert!(
                !all.contains(&reserved),
                "reserved name `{reserved}` must not be a clap subcommand"
            );
        }
        for legacy in names("legacyProjectCommands") {
            assert!(
                !all.contains(&legacy),
                "Exact project name `{legacy}` must not be a clap subcommand"
            );
        }
    }
}
