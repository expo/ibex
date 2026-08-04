//! CLI argument parsing for the `ibex` command
//!
//! `ibex` runs JavaScript and TypeScript. Project tooling remains on the
//! `exact` binary; reserved-but-unbuilt runtime names (`test`, `install`,
//! `bench`, `exec`) are absent from this clap tree and intercepted by the
//! pre-clap dispatcher in `main.rs`. The hidden `self-test` command is a CI
//! harness smoke, not a user-facing test runner; the hidden `compat` command
//! is the WPT/exact compat harness (fixtures live in the exact repo).

use clap::{builder::PossibleValue, Parser, Subcommand, ValueEnum};
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
    after_help = "Examples:\n  ibex app.ts                  Run a TypeScript file\n  ibex eval '1 + 1'            Evaluate an expression\n  ibex -p 'process.versions'   Evaluate and print the result\n  ibex --watch server.ts       Run with auto-restart on changes\n  ibex run dev                 Run a package script\n  ibex build app.ts            Compile to Hermes bytecode\n  ibex compile app.ts -o app   Build a single-file executable\n  ibex inspect-executable app  Inspect an SFE without executing it\n  ibex completions zsh         Generate shell completions\n  ibex debug modules           Print builtin module registry metadata\n  ibex repl                    Interactive REPL (also: ibex with no arguments)"
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

    /// Capability security posture (ordinary execution is enforce-only)
    #[arg(long, value_enum, default_value = "auto")]
    pub capsec: CapSecMode,

    /// Persistent REPL history scope. History is used only by an interactive
    /// session with an editor; other modes ignore the recorded default and
    /// diagnose an explicitly supplied value they cannot honor.
    // @ref LLP 0025#9-history — the operator selects project-scoped history,
    // explicit global history, or no persistence before the host is armed.
    #[arg(long, value_enum, default_value = "project", global = true)]
    pub history: HistoryMode,

    /// Whether the operator supplied `--history` rather than receiving the
    /// manifest default. This is argv provenance, not a second Clap surface.
    #[arg(skip)]
    pub history_was_explicit: bool,

    /// Affirm the production lockdown posture. Ordinary execution enables
    /// lockdown structurally; this flag is retained as an explicit affirmation.
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

    /// Canonical, digest-bound CapSec policy file
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Trusted project-root override. When omitted, every execution mode uses
    /// the same discovery rule: the outermost matching workspace wins, then
    /// the nearest lockfile, then the nearest package.json; markerless projects
    /// use their discovery origin with a diagnostic. Origins at a home,
    /// filesystem-root, or device stop boundary require this override.
    // @ref LLP 0023#11-project-root-discovery — operator help must describe the authority boundary
    #[arg(long, value_name = "DIR")]
    pub project_root: Option<PathBuf>,

    /// Trusted runtime-cache override. The directory remains runtime-private
    /// and must be disjoint from the authenticated project and package roots.
    // @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings — operator-selected caches remain unmounted and topology-authenticated
    #[arg(long, value_name = "DIR")]
    pub runtime_cache_dir: Option<PathBuf>,

    /// Immutable capability snapshot selected by the trusted launcher.
    /// Must be paired with --capsec-arming-identity. Hidden trusted-launcher
    /// plumbing; ordinary execution generates and authenticates the same shape.
    /// @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
    #[arg(long = "capsec-armed-snapshot", value_name = "FILE", hide = true)]
    pub capsec_armed_snapshot: Option<PathBuf>,

    /// Independently observed execution identity used to authenticate the
    /// immutable snapshot. Must be paired with --capsec-armed-snapshot.
    /// @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
    #[arg(long = "capsec-arming-identity", value_name = "FILE", hide = true)]
    pub capsec_arming_identity: Option<PathBuf>,

    /// Removed legacy authority override; production always refuses it.
    #[arg(long, value_name = "CAPABILITY", hide = true)]
    pub allow: Vec<String>,

    /// Removed legacy authority override; production always refuses it.
    #[arg(long, value_name = "CAPABILITY", hide = true)]
    pub deny: Vec<String>,

    /// Removed legacy weakening flag; production always refuses it.
    #[arg(long, hide = true)]
    pub allow_all: bool,

    /// Removed legacy endowment-widening flag; production always refuses it.
    /// @ref LLP 0013#mechanism-2
    #[arg(long, hide = true)]
    pub allow_env_endowments: bool,

    /// Removed advisory-attribution escape hatch; production always refuses it.
    /// @ref LLP 0013#mechanism-3 — (ENG-22884)
    #[arg(long, alias = "allow-advisory-attribution", hide = true)]
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

    /// Build a self-contained executable from an authored policy (ambient by
    /// default; use --ibex-capsec for CapSec or --ibex-info for artifact facts)
    Compile {
        /// Application entry point
        #[arg(required = true)]
        entry: PathBuf,

        /// Executable output path
        #[arg(short = 'o', long = "output", required = true)]
        output: PathBuf,

        /// Prepared module carrier encoding
        #[arg(long, value_enum, default_value = "hbc")]
        carrier: CompileCarrier,

        /// Canonical production policy (conflicts with root --policy)
        #[arg(long = "policy", value_name = "FILE")]
        compile_policy: Option<PathBuf>,

        /// Refuse graphs containing guarded invocation-time unsupported sites
        #[arg(long)]
        deny_unsupported: bool,
    },

    /// Inspect a single-file executable without evaluating application code
    InspectExecutable {
        /// Executable to inspect
        #[arg(required = true)]
        file: PathBuf,
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

    /// Run an explicit foreground capability audit diagnostic
    Capsec {
        #[command(subcommand)]
        command: CapsecCommands,
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
        /// Probe mode (Exact LLP 0404 N-1): evaluate one JS expression at
        /// each observation point of the serving path (raw engine, then
        /// post-bootstrap; module-record and packaged-HBC points are not
        /// implemented yet) and emit a JSON measurement tuple naming the
        /// first edge where behavior diverges. Ignores the suite-mode
        /// flags; `--timeout` bounds each point's evaluation.
        #[arg(long, value_name = "EXPR")]
        probe: Option<String>,

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
pub enum CapsecCommands {
    /// Execute one file while reporting would-deny legacy compatibility calls
    Audit {
        #[arg(required = true)]
        file: String,
        #[arg(value_name = "ARGS", num_args = 0.., allow_hyphen_values = true)]
        args: Vec<String>,
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

        /// Deployment profile name (defaults to portable-v1 or sfe-v1)
        #[arg(long)]
        target_profile: Option<String>,

        /// Compile for this exact target and bind the authenticated native graph
        #[arg(long)]
        target_triple: Option<String>,

        /// Logical mount profile (derived from the target when omitted)
        #[arg(long)]
        mount_profile: Option<String>,
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

        /// Deployment profile name used by the committed artifact
        #[arg(long)]
        target_profile: Option<String>,

        /// Compiled target triple used by the committed artifact
        #[arg(long)]
        target_triple: Option<String>,

        /// Logical mount profile used by the committed artifact
        #[arg(long)]
        mount_profile: Option<String>,
    },
}

/// Capability security enforcement mode for CLI.
///
/// Ordinary execution accepts only the enforced armed workflow. Historical
/// values remain parseable but hidden so validation can issue a precise refusal;
/// foreground audit is the separately named `ibex capsec audit` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapSecMode {
    /// Generate and authenticate the enforce-only armed execution snapshot.
    Auto,
    /// Removed legacy mode; ordinary execution refuses it.
    Permissive,
    /// Removed legacy spelling; use `ibex capsec audit` for foreground audit.
    Audit,
    /// Explicitly affirm enforce-only armed execution.
    Enforce,
}

/// Supervisor-owned persistent REPL history policy.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryMode {
    /// Isolate recall by the authenticated project root (the default).
    Project,
    /// Explicitly share recall across projects for this user.
    Global,
    /// Keep editor recall in memory only; perform no persistent history I/O.
    Off,
}

/// Capture default provenance before Clap consumes argv. The `--` boundary is
/// respected so a script argument named `--history` is never reclassified as
/// terminal-operator configuration.
pub(crate) fn history_option_was_explicit(argv: &[std::ffi::OsString]) -> bool {
    argv.iter()
        .skip(1)
        .take_while(|argument| argument.as_os_str() != "--")
        .filter_map(|argument| argument.to_str())
        .any(|argument| argument == "--history" || argument.starts_with("--history="))
}

impl ValueEnum for CapSecMode {
    fn value_variants<'a>() -> &'a [Self] {
        const VARIANTS: &[CapSecMode] = &[
            CapSecMode::Auto,
            CapSecMode::Permissive,
            CapSecMode::Audit,
            CapSecMode::Enforce,
        ];
        VARIANTS
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(match self {
            Self::Auto => PossibleValue::new("auto"),
            Self::Permissive => PossibleValue::new("permissive").hide(true),
            Self::Audit => PossibleValue::new("audit").hide(true),
            Self::Enforce => PossibleValue::new("enforce")
                .alias("strict")
                .alias("capability"),
        })
    }
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

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileCarrier {
    /// Catalog-paired Hermes bytecode (release default)
    #[value(name = "hbc")]
    Hbc,
    /// Diagnostic factory-table carrier; not release eligible
    #[value(name = "factory-table")]
    FactoryTable,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use clap::{Arg, ArgAction, Command, CommandFactory};
    use serde_json::{json, Value};
    use std::collections::BTreeSet;
    use std::ffi::OsStr;

    #[test]
    fn project_root_help_describes_versioned_discovery_and_override() {
        let command = Cli::command();
        let argument = command
            .get_arguments()
            .find(|argument| argument.get_id() == "project_root")
            .expect("--project-root remains an authored option");
        let help = argument
            .get_long_help()
            .or_else(|| argument.get_help())
            .expect("--project-root has help")
            .to_string();
        assert!(help.contains("outermost matching workspace"), "{help}");
        assert!(help.contains("nearest lockfile"), "{help}");
        assert!(
            help.contains("discovery origin with a diagnostic"),
            "{help}"
        );
        assert!(!help.contains("nearest ancestor containing package.json"));
    }

    #[test]
    fn runtime_cache_help_preserves_the_private_topology_boundary() {
        let command = Cli::command();
        let argument = command
            .get_arguments()
            .find(|argument| argument.get_id() == "runtime_cache_dir")
            .expect("--runtime-cache-dir remains an authored option");
        let help = argument
            .get_long_help()
            .or_else(|| argument.get_help())
            .expect("--runtime-cache-dir has help")
            .to_string();
        assert!(help.contains("runtime-private"), "{help}");
        assert!(help.contains("disjoint"), "{help}");
    }

    // @ref LLP 0010#runtime-command-surface — the recursive manifest records
    // authored Clap semantics, while framework-generated controls stay out.

    /// Clap materializes help/version controls while building the command. We
    /// snapshot authored identities first: action/name heuristics alone would
    /// also hide a deliberately authored Help/Version argument or `help`
    /// subcommand when the corresponding generated control is disabled.
    #[derive(Default)]
    struct AuthoredClapIdentities {
        arguments: BTreeSet<String>,
        commands: BTreeSet<String>,
        global_arguments: BTreeSet<String>,
    }

    fn argument_key(path: &str, arg: &Arg) -> String {
        format!("{path}\0{}", arg.get_id())
    }

    fn collect_authored_clap_identities(
        command: &Command,
        path: &str,
        authored: &mut AuthoredClapIdentities,
    ) {
        assert!(
            authored.commands.insert(path.to_string()),
            "duplicate authored Clap command path {path}"
        );
        for arg in command.get_arguments() {
            let key = argument_key(path, arg);
            assert!(
                authored.arguments.insert(key),
                "duplicate authored Clap argument {} on {path}",
                arg.get_id()
            );
            if arg.is_global_set() {
                authored.global_arguments.insert(arg.get_id().to_string());
            }
        }
        for subcommand in command.get_subcommands() {
            collect_authored_clap_identities(
                subcommand,
                &format!("{path} {}", subcommand.get_name()),
                authored,
            );
        }
    }

    fn is_generated_framework_action(action: &ArgAction) -> bool {
        matches!(
            action,
            ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong | ArgAction::Version
        )
    }

    fn is_authored_argument(authored: &AuthoredClapIdentities, path: &str, arg: &Arg) -> bool {
        if authored.arguments.contains(&argument_key(path, arg)) {
            return true;
        }
        // Clap materializes root-authored global arguments on every built
        // descendant. Their single root authority row records `global: true`;
        // child copies are derived reachability, not separately authored rows.
        if authored.global_arguments.contains(arg.get_id().as_str()) {
            return false;
        }
        if is_generated_framework_action(arg.get_action()) {
            return false;
        }
        panic!(
            "unreviewed synthesized Clap argument {} ({:?}) on {path}",
            arg.get_id(),
            arg.get_action()
        );
    }

    fn option_aliases(arg: &Arg) -> (Vec<String>, Vec<String>) {
        let mut visible = BTreeSet::new();
        let mut all = BTreeSet::new();

        for alias in arg.get_visible_aliases().unwrap_or_default() {
            visible.insert(format!("--{alias}"));
        }
        for alias in arg.get_all_aliases().unwrap_or_default() {
            all.insert(format!("--{alias}"));
        }
        for alias in arg.get_visible_short_aliases().unwrap_or_default() {
            visible.insert(format!("-{alias}"));
        }
        for alias in arg.get_all_short_aliases().unwrap_or_default() {
            all.insert(format!("-{alias}"));
        }

        let hidden = all.difference(&visible).cloned().collect();
        (visible.into_iter().collect(), hidden)
    }

    fn action_name(action: &ArgAction) -> &'static str {
        match action {
            ArgAction::Set => "Set",
            ArgAction::Append => "Append",
            ArgAction::SetTrue => "SetTrue",
            ArgAction::SetFalse => "SetFalse",
            ArgAction::Count => "Count",
            ArgAction::Help => "Help",
            ArgAction::HelpShort => "HelpShort",
            ArgAction::HelpLong => "HelpLong",
            ArgAction::Version => "Version",
            _ => panic!("unreviewed Clap ArgAction in runtime surface: {action:?}"),
        }
    }

    fn os_values(values: &[impl AsRef<OsStr>]) -> Vec<String> {
        values
            .iter()
            .map(|value| value.as_ref().to_string_lossy().into_owned())
            .collect()
    }

    fn possible_value_surface(arg: &Arg) -> Vec<Value> {
        arg.get_possible_values()
            .into_iter()
            .map(|value| {
                let aliases: Vec<String> = value
                    .get_name_and_aliases()
                    .skip(1)
                    .map(ToString::to_string)
                    .collect();
                json!({
                    "value": value.get_name(),
                    "aliases": aliases,
                    "hidden": value.is_hide_set(),
                })
            })
            .collect()
    }

    fn positional_probe_value(arg: &Arg) -> String {
        arg.get_possible_values()
            .into_iter()
            .next()
            .map(|value| value.get_name().to_string())
            .unwrap_or_else(|| "__ibex_surface_probe__".to_string())
    }

    /// Clap does not expose `default_missing_values` through its reflection
    /// API. Probe the built parser with the option present and no value so the
    /// manifest still records explicit default-missing values, not only the
    /// implicit SetTrue/SetFalse cases. The `--` boundary prevents required
    /// positionals from being consumed as an optional option value.
    fn default_missing_values(command: &Command, arg: &Arg, primary_name: &str) -> Vec<String> {
        let arity = arg.get_num_args().unwrap_or_default();
        if is_generated_framework_action(arg.get_action())
            || (arity.max_values() > 0 && arity.min_values() > 0)
        {
            return Vec::new();
        }

        let mut argv = vec![command.get_name().to_string()];
        // Required options must also be satisfied or the probe parse fails
        // validation before the probed argument is ever inspected. They go
        // before the probed option so a 0..=1-arity probe cannot try to
        // consume them as its own value.
        for required in command
            .get_arguments()
            .filter(|candidate| !candidate.is_positional())
            .filter(|candidate| candidate.is_required_set())
            .filter(|candidate| candidate.get_id() != arg.get_id())
        {
            match required.get_long() {
                Some(long) => argv.push(format!("--{long}")),
                None => match required.get_short() {
                    Some(short) => argv.push(format!("-{short}")),
                    None => continue,
                },
            }
            let required_arity = required.get_num_args().unwrap_or_default();
            if required_arity.max_values() > 0 {
                for _ in 0..required_arity.min_values().max(1) {
                    argv.push(positional_probe_value(required));
                }
            }
        }
        argv.push(primary_name.to_string());
        let required_positionals: Vec<&Arg> = command
            .get_positionals()
            .filter(|positional| positional.is_required_set())
            .collect();
        if !required_positionals.is_empty() {
            argv.push("--".to_string());
            for positional in required_positionals {
                let count = positional
                    .get_num_args()
                    .unwrap_or_default()
                    .min_values()
                    .max(1);
                for _ in 0..count {
                    argv.push(positional_probe_value(positional));
                }
            }
        }

        let matches = command
            .clone()
            .try_get_matches_from(argv)
            .unwrap_or_else(|error| {
                panic!(
                    "unable to probe default-missing value for {} on {}: {error}",
                    arg.get_id(),
                    command.get_name()
                )
            });
        matches
            .get_raw(arg.get_id().as_str())
            .map(|values| {
                values
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn value_shape(command: &Command, arg: &Arg, primary_name: Option<&str>) -> Value {
        let arity = arg.get_num_args().unwrap_or_default();
        let max_values = if arity.max_values() == usize::MAX {
            Value::Null
        } else {
            json!(arity.max_values())
        };
        let value_names: Vec<String> = arg
            .get_value_names()
            .unwrap_or_default()
            .iter()
            .map(ToString::to_string)
            .collect();
        let possible_values = possible_value_surface(arg);
        let value_domain = if arity.max_values() == 0 {
            "none"
        } else if possible_values.is_empty() {
            "arbitrary"
        } else {
            "enumerated"
        };
        let default_missing_values = primary_name
            .map(|name| default_missing_values(command, arg, name))
            .unwrap_or_default();

        json!({
            "action": action_name(arg.get_action()),
            "required": arg.is_required_set(),
            "valueNames": value_names,
            "minValues": arity.min_values(),
            "maxValues": max_values,
            "valueDomain": value_domain,
            "possibleValues": possible_values,
            "possibleValuesHidden": arg.is_hide_possible_values_set(),
            "defaultValues": os_values(arg.get_default_values()),
            "defaultMissingValues": default_missing_values,
            "allowHyphenValues": arg.is_allow_hyphen_values_set(),
        })
    }

    fn option_surface(command: &Command, arg: &Arg) -> Value {
        let mut names = Vec::new();
        if let Some(long) = arg.get_long() {
            names.push(format!("--{long}"));
        }
        if let Some(short) = arg.get_short() {
            names.push(format!("-{short}"));
        }
        names.sort();

        let (visible_aliases, hidden_aliases) = option_aliases(arg);
        let primary_name = names
            .iter()
            .find(|name| name.starts_with("--"))
            .or_else(|| names.first())
            .expect("authored option has a long or short name")
            .clone();
        let mut surface = json!({
            "id": arg.get_id().to_string(),
            "names": names,
            "valueShape": value_shape(command, arg, Some(&primary_name)),
        });
        let object = surface
            .as_object_mut()
            .expect("option surface is an object");
        if arg.is_hide_set() {
            object.insert("hidden".to_string(), json!(true));
        }
        if !visible_aliases.is_empty() {
            object.insert("visibleAliases".to_string(), json!(visible_aliases));
        }
        if !hidden_aliases.is_empty() {
            object.insert("hiddenAliases".to_string(), json!(hidden_aliases));
        }
        if arg.is_global_set() {
            object.insert("global".to_string(), json!(true));
        }
        surface
    }

    fn positional_surface(command: &Command, arg: &Arg) -> Value {
        let shape = value_shape(command, arg, None);
        let passthrough = shape["maxValues"].is_null() && arg.is_allow_hyphen_values_set();

        json!({
            "id": arg.get_id().to_string(),
            "index": arg.get_index().expect("positional argument has an index"),
            "passthrough": passthrough,
            "valueShape": shape,
        })
    }

    fn command_aliases(command: &Command) -> (Vec<String>, Vec<String>) {
        let mut visible = BTreeSet::new();
        let mut all = BTreeSet::new();

        visible.extend(command.get_visible_aliases().map(ToString::to_string));
        all.extend(command.get_all_aliases().map(ToString::to_string));
        visible.extend(
            command
                .get_visible_short_flag_aliases()
                .map(|alias| format!("-{alias}")),
        );
        all.extend(
            command
                .get_all_short_flag_aliases()
                .map(|alias| format!("-{alias}")),
        );
        visible.extend(
            command
                .get_visible_long_flag_aliases()
                .map(|alias| format!("--{alias}")),
        );
        all.extend(
            command
                .get_all_long_flag_aliases()
                .map(|alias| format!("--{alias}")),
        );

        let hidden = all.difference(&visible).cloned().collect();
        (visible.into_iter().collect(), hidden)
    }

    fn collect_clap_surface(
        command: &Command,
        path: &str,
        authored: &AuthoredClapIdentities,
        surface: &mut Vec<Value>,
    ) {
        let mut options: Vec<Value> = command
            .get_arguments()
            .filter(|arg| !arg.is_positional() && is_authored_argument(authored, path, arg))
            .map(|arg| option_surface(command, arg))
            .collect();
        options.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));

        let mut positionals: Vec<Value> = command
            .get_positionals()
            .filter(|arg| is_authored_argument(authored, path, arg))
            .map(|arg| positional_surface(command, arg))
            .collect();
        positionals.sort_by(|left, right| {
            left["index"]
                .as_u64()
                .cmp(&right["index"].as_u64())
                .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
        });

        let (visible_aliases, hidden_aliases) = command_aliases(command);
        let mut command_surface = json!({
            "path": path,
        });
        let object = command_surface
            .as_object_mut()
            .expect("command surface is an object");
        if command.is_hide_set() {
            object.insert("hidden".to_string(), json!(true));
        }
        if let Some(flag) = command.get_short_flag() {
            object.insert("shortFlag".to_string(), json!(format!("-{flag}")));
        }
        if let Some(flag) = command.get_long_flag() {
            object.insert("longFlag".to_string(), json!(format!("--{flag}")));
        }
        if !visible_aliases.is_empty() {
            object.insert("visibleAliases".to_string(), json!(visible_aliases));
        }
        if !hidden_aliases.is_empty() {
            object.insert("hiddenAliases".to_string(), json!(hidden_aliases));
        }
        if !options.is_empty() {
            object.insert("options".to_string(), json!(options));
        }
        if !positionals.is_empty() {
            object.insert("positionals".to_string(), json!(positionals));
        }
        surface.push(command_surface);

        for subcommand in command.get_subcommands() {
            let subcommand_path = format!("{path} {}", subcommand.get_name());
            if authored.commands.contains(&subcommand_path) {
                collect_clap_surface(subcommand, &subcommand_path, authored, surface);
            } else if subcommand.get_name() != "help" {
                panic!("unreviewed synthesized Clap command {subcommand_path}");
            }
        }
    }

    const REVIEWED_TYPE_ERASED_PARSERS: &[(&str, &str, &str)] = &[
        ("ibex", "inspect_port", "unsigned-integer-u16"),
        ("ibex", "max_http_header_size", "unsigned-integer-usize"),
        ("ibex compat", "jobs", "unsigned-integer-usize"),
        ("ibex compat", "timeout", "unsigned-integer-u64"),
        ("ibex run", "inspect_port", "unsigned-integer-u16"),
    ];

    fn reviewed_type_erased_parser(path: &str, arg: &Arg) -> Option<&'static str> {
        REVIEWED_TYPE_ERASED_PARSERS
            .iter()
            .find(|(reviewed_path, reviewed_id, _)| {
                *reviewed_path == path && *reviewed_id == arg.get_id().as_str()
            })
            .map(|(_, _, parser_kind)| *parser_kind)
    }

    fn non_enumerated_parser_kind(
        path: &str,
        arg: &Arg,
        seen_type_erased: &mut BTreeSet<String>,
    ) -> Option<&'static str> {
        let arity = arg.get_num_args().unwrap_or_default();
        if arity.max_values() == 0 || !arg.get_possible_values().is_empty() {
            return None;
        }
        let debug = format!("{:?}", arg.get_value_parser());
        match debug.as_str() {
            "ValueParser::string" => Some("utf8-string"),
            "ValueParser::os_string" => Some("os-string"),
            "ValueParser::path_buf" => Some("os-path"),
            _ if debug.starts_with("ValueParser::other(") => {
                let parser_kind = reviewed_type_erased_parser(path, arg).unwrap_or_else(|| {
                    panic!(
                        "unreviewed type-erased parser for {} on {path}; add a stable parser contract and boundary test",
                        arg.get_id()
                    )
                });
                seen_type_erased.insert(argument_key(path, arg));
                Some(parser_kind)
            }
            _ => panic!(
                "unreviewed non-enumerated parser for {} on {path}: {debug}",
                arg.get_id()
            ),
        }
    }

    fn collect_clap_semantic_relations(
        command: &Command,
        path: &str,
        authored: &AuthoredClapIdentities,
        conflicts: &mut Vec<Value>,
        parsers: &mut Vec<Value>,
        seen_type_erased: &mut BTreeSet<String>,
    ) {
        for arg in command
            .get_arguments()
            .filter(|arg| is_authored_argument(authored, path, arg))
        {
            let mut conflict_ids: Vec<String> = command
                .get_arg_conflicts_with(arg)
                .into_iter()
                .map(|conflict| {
                    assert!(
                        authored.arguments.contains(&argument_key(path, conflict)),
                        "{} on {path} conflicts with synthesized argument {}",
                        arg.get_id(),
                        conflict.get_id()
                    );
                    conflict.get_id().to_string()
                })
                .collect();
            conflict_ids.sort();
            conflict_ids.dedup();
            if !conflict_ids.is_empty() {
                conflicts.push(json!({
                    "commandPath": path,
                    "argumentId": arg.get_id().to_string(),
                    "conflictsWith": conflict_ids,
                }));
            }

            if let Some(parser_kind) = non_enumerated_parser_kind(path, arg, seen_type_erased) {
                parsers.push(json!({
                    "commandPath": path,
                    "argumentId": arg.get_id().to_string(),
                    "parserKind": parser_kind,
                }));
            }
        }

        for subcommand in command.get_subcommands() {
            let subcommand_path = format!("{path} {}", subcommand.get_name());
            if authored.commands.contains(&subcommand_path) {
                collect_clap_semantic_relations(
                    subcommand,
                    &subcommand_path,
                    authored,
                    conflicts,
                    parsers,
                    seen_type_erased,
                );
            }
        }
    }

    pub(crate) struct ClapManifestSnapshot {
        pub(crate) commands: Vec<Value>,
        pub(crate) semantic_relations: Value,
        type_erased_parser_keys: BTreeSet<String>,
    }

    fn clap_manifest_snapshot_from(mut command: Command) -> ClapManifestSnapshot {
        let root_name = command.get_name().to_string();
        let mut authored = AuthoredClapIdentities::default();
        collect_authored_clap_identities(&command, &root_name, &mut authored);
        command.build();

        let mut commands = Vec::new();
        collect_clap_surface(&command, &root_name, &authored, &mut commands);
        commands.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));

        let mut conflicts = Vec::new();
        let mut parsers = Vec::new();
        let mut seen_type_erased = BTreeSet::new();
        collect_clap_semantic_relations(
            &command,
            &root_name,
            &authored,
            &mut conflicts,
            &mut parsers,
            &mut seen_type_erased,
        );
        conflicts.sort_by_key(|row| {
            format!(
                "{}\0{}",
                row["commandPath"].as_str().unwrap_or_default(),
                row["argumentId"].as_str().unwrap_or_default()
            )
        });
        parsers.sort_by_key(|row| {
            format!(
                "{}\0{}",
                row["commandPath"].as_str().unwrap_or_default(),
                row["argumentId"].as_str().unwrap_or_default()
            )
        });
        ClapManifestSnapshot {
            commands,
            semantic_relations: json!({
                "argumentConflicts": conflicts,
                "nonEnumeratedParsers": parsers,
            }),
            type_erased_parser_keys: seen_type_erased,
        }
    }

    pub(crate) fn clap_manifest_snapshot() -> ClapManifestSnapshot {
        // Build is intentionally deferred until authored identities have been
        // captured by `clap_manifest_snapshot_from`.
        let snapshot = clap_manifest_snapshot_from(Cli::command());
        let expected_type_erased: BTreeSet<String> = REVIEWED_TYPE_ERASED_PARSERS
            .iter()
            .map(|(path, id, _)| format!("{path}\0{id}"))
            .collect();
        assert_eq!(
            snapshot.type_erased_parser_keys, expected_type_erased,
            "reviewed type-erased parser set drifted"
        );
        snapshot
    }

    #[derive(Clone, Copy, Debug)]
    struct RustSourceToken<'a> {
        identifier: bool,
        text: &'a str,
        start: usize,
    }

    fn quoted_rust_literal_end(source: &str, quote: usize) -> Result<usize, String> {
        let bytes = source.as_bytes();
        let mut cursor = quote + 1;
        let mut escaped = false;
        while cursor < bytes.len() {
            if escaped {
                escaped = false;
            } else if bytes[cursor] == b'\\' {
                escaped = true;
            } else if bytes[cursor] == b'"' {
                return Ok(cursor + 1);
            }
            cursor += 1;
        }
        Err("unterminated Rust string literal in cli.rs source guard".to_string())
    }

    fn char_rust_literal_end(source: &str, quote: usize) -> Option<usize> {
        let bytes = source.as_bytes();
        let mut cursor = quote + 1;
        if bytes.get(cursor) == Some(&b'\\') {
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\'' && bytes.get(cursor.wrapping_sub(1)) != Some(&b'\\') {
                    return Some(cursor + 1);
                }
                if bytes[cursor].is_ascii_whitespace() {
                    return None;
                }
                cursor += 1;
            }
            return None;
        }
        let character = source.get(cursor..)?.chars().next()?;
        cursor += character.len_utf8();
        (bytes.get(cursor) == Some(&b'\'')).then_some(cursor + 1)
    }

    fn raw_rust_literal_end(source: &str, start: usize) -> Result<Option<usize>, String> {
        let bytes = source.as_bytes();
        let mut cursor = match (bytes.get(start), bytes.get(start + 1)) {
            (Some(b'r'), _) => start + 1,
            (Some(b'b' | b'c'), Some(b'r')) => start + 2,
            _ => return Ok(None),
        };
        let mut hashes = 0usize;
        while bytes.get(cursor) == Some(&b'#') {
            hashes += 1;
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'"') {
            return Ok(None);
        }
        cursor += 1;
        while cursor < bytes.len() {
            if bytes[cursor] == b'"'
                && (0..hashes).all(|offset| bytes.get(cursor + 1 + offset) == Some(&b'#'))
            {
                return Ok(Some(cursor + 1 + hashes));
            }
            cursor += 1;
        }
        Err("unterminated raw Rust string literal in cli.rs source guard".to_string())
    }

    fn lex_rust_source(source: &str) -> Result<Vec<RustSourceToken<'_>>, String> {
        let bytes = source.as_bytes();
        let mut tokens = Vec::new();
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            if bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
                continue;
            }
            if bytes[cursor..].starts_with(b"//") {
                cursor += 2;
                while cursor < bytes.len() && bytes[cursor] != b'\n' {
                    cursor += 1;
                }
                continue;
            }
            if bytes[cursor..].starts_with(b"/*") {
                let mut depth = 1usize;
                cursor += 2;
                while cursor < bytes.len() && depth > 0 {
                    if bytes[cursor..].starts_with(b"/*") {
                        depth += 1;
                        cursor += 2;
                    } else if bytes[cursor..].starts_with(b"*/") {
                        depth -= 1;
                        cursor += 2;
                    } else {
                        cursor += 1;
                    }
                }
                if depth != 0 {
                    return Err(
                        "unterminated Rust block comment in cli.rs source guard".to_string()
                    );
                }
                continue;
            }
            if let Some(end) = raw_rust_literal_end(source, cursor)? {
                cursor = end;
                continue;
            }
            let quote = if bytes[cursor] == b'"' {
                Some(cursor)
            } else if matches!(bytes[cursor], b'b' | b'c') && bytes.get(cursor + 1) == Some(&b'"') {
                Some(cursor + 1)
            } else {
                None
            };
            if let Some(quote) = quote {
                cursor = quoted_rust_literal_end(source, quote)?;
                continue;
            }
            let char_quote = if bytes[cursor] == b'\'' {
                Some(cursor)
            } else if bytes[cursor] == b'b' && bytes.get(cursor + 1) == Some(&b'\'') {
                Some(cursor + 1)
            } else {
                None
            };
            if let Some(end) = char_quote.and_then(|quote| char_rust_literal_end(source, quote)) {
                cursor = end;
                continue;
            }
            if bytes[cursor] == b'r'
                && bytes.get(cursor + 1) == Some(&b'#')
                && bytes
                    .get(cursor + 2)
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            {
                let start = cursor;
                cursor += 2;
                let identifier_start = cursor;
                cursor += 1;
                while bytes
                    .get(cursor)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    cursor += 1;
                }
                tokens.push(RustSourceToken {
                    identifier: true,
                    text: &source[identifier_start..cursor],
                    start,
                });
                continue;
            }
            if bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_' {
                let start = cursor;
                cursor += 1;
                while bytes
                    .get(cursor)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    cursor += 1;
                }
                tokens.push(RustSourceToken {
                    identifier: true,
                    text: &source[start..cursor],
                    start,
                });
                continue;
            }
            let start = cursor;
            let character = source[cursor..]
                .chars()
                .next()
                .ok_or_else(|| "invalid UTF-8 boundary in cli.rs source guard".to_string())?;
            cursor += character.len_utf8();
            tokens.push(RustSourceToken {
                identifier: false,
                text: &source[start..cursor],
                start,
            });
        }
        Ok(tokens)
    }

    fn matching_source_token(
        tokens: &[RustSourceToken<'_>],
        open: usize,
        open_text: &str,
        close_text: &str,
    ) -> Option<usize> {
        (tokens.get(open)?.text == open_text).then_some(())?;
        let mut depth = 0usize;
        for (index, token) in tokens.iter().enumerate().skip(open) {
            if token.text == open_text {
                depth += 1;
            } else if token.text == close_text {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
        }
        None
    }

    #[derive(Clone, Debug)]
    struct RustSourceAttribute {
        body: Option<(usize, usize)>,
        close: usize,
        name: String,
        start: usize,
    }

    fn rust_source_attributes(
        tokens: &[RustSourceToken<'_>],
    ) -> Result<Vec<RustSourceAttribute>, String> {
        let mut attributes = Vec::new();
        let mut cursor = 0usize;
        while cursor + 1 < tokens.len() {
            if tokens[cursor].text != "#" || tokens[cursor + 1].text != "[" {
                cursor += 1;
                continue;
            }
            let close = matching_source_token(tokens, cursor + 1, "[", "]")
                .ok_or_else(|| "unterminated Rust source attribute in cli.rs".to_string())?;
            let mut item = cursor + 2;
            if tokens.get(item).is_some_and(|token| token.text == "!") {
                item += 1;
            }
            let name = tokens
                .get(item)
                .filter(|token| token.identifier)
                .ok_or_else(|| "unparsed Rust source attribute in cli.rs".to_string())?
                .text
                .to_string();
            item += 1;
            while tokens.get(item).is_some_and(|token| token.text == ":")
                && tokens.get(item + 1).is_some_and(|token| token.text == ":")
                && tokens.get(item + 2).is_some_and(|token| token.identifier)
            {
                item += 3;
            }
            let body = if tokens.get(item).is_some_and(|token| token.text == "(") {
                let body_close = matching_source_token(tokens, item, "(", ")")
                    .filter(|body_close| *body_close < close)
                    .ok_or_else(|| format!("unterminated #[{name}(..)] attribute in cli.rs"))?;
                Some((item + 1, body_close))
            } else {
                None
            };
            attributes.push(RustSourceAttribute {
                body,
                close,
                name,
                start: tokens[cursor].start,
            });
            cursor = close + 1;
        }
        Ok(attributes)
    }

    fn top_level_source_segments(
        tokens: &[RustSourceToken<'_>],
        start: usize,
        end: usize,
    ) -> Vec<(usize, usize)> {
        let mut segments = Vec::new();
        let mut segment_start = start;
        let mut parentheses = 0usize;
        let mut brackets = 0usize;
        let mut braces = 0usize;
        for (index, token) in tokens.iter().enumerate().take(end).skip(start) {
            match token.text {
                "(" => parentheses += 1,
                ")" => parentheses = parentheses.saturating_sub(1),
                "[" => brackets += 1,
                "]" => brackets = brackets.saturating_sub(1),
                "{" => braces += 1,
                "}" => braces = braces.saturating_sub(1),
                "," if parentheses == 0 && brackets == 0 && braces == 0 => {
                    segments.push((segment_start, index));
                    segment_start = index + 1;
                }
                _ => {}
            }
        }
        segments.push((segment_start, end));
        segments
    }

    fn top_level_attribute_keys(
        tokens: &[RustSourceToken<'_>],
        start: usize,
        end: usize,
    ) -> Result<Vec<String>, String> {
        top_level_source_segments(tokens, start, end)
            .into_iter()
            .filter(|(segment_start, segment_end)| segment_start < segment_end)
            .map(|(segment_start, _)| {
                tokens
                    .get(segment_start)
                    .filter(|token| token.identifier)
                    .map(|token| token.text.to_string())
                    .ok_or_else(|| "unparsed Clap attribute item in cli.rs".to_string())
            })
            .collect()
    }

    fn nested_cfg_attr_clap_namespace(
        tokens: &[RustSourceToken<'_>],
        start: usize,
        end: usize,
    ) -> Option<String> {
        for (segment_index, (segment_start, segment_end)) in
            top_level_source_segments(tokens, start, end)
                .into_iter()
                .enumerate()
        {
            if segment_index == 0 || segment_start >= segment_end {
                continue;
            }
            let name = tokens.get(segment_start)?.text;
            if matches!(name, "arg" | "command" | "group" | "clap" | "structopt") {
                return Some(name.to_string());
            }
            if name == "cfg_attr" && tokens.get(segment_start + 1)?.text == "(" {
                let close = matching_source_token(tokens, segment_start + 1, "(", ")")?;
                if close <= segment_end {
                    if let Some(namespace) =
                        nested_cfg_attr_clap_namespace(tokens, segment_start + 2, close)
                    {
                        return Some(namespace);
                    }
                }
            }
        }
        None
    }

    fn review_clap_source_attributes(source: &str) -> Result<(), String> {
        let tokens = lex_rust_source(source)?;
        let attributes = rust_source_attributes(&tokens)?;
        let reviewed_arg_keys: BTreeSet<&str> = [
            "alias",
            "allow_hyphen_values",
            "conflicts_with",
            "default_value",
            "global",
            "hide",
            "long",
            "num_args",
            "required",
            "short",
            "short_alias",
            "skip",
            "value_enum",
            "value_name",
            "value_parser",
        ]
        .into_iter()
        .collect();
        let reviewed_command_keys: BTreeSet<&str> = [
            "about",
            "after_help",
            "author",
            "disable_version_flag",
            "hide",
            "long_about",
            "name",
            "propagate_version",
            "subcommand",
            "version",
        ]
        .into_iter()
        .collect();

        for attribute in attributes {
            if matches!(attribute.name.as_str(), "group" | "clap" | "structopt") {
                return Err(format!(
                    "unreviewed Clap-affecting #[{}] attribute namespace",
                    attribute.name
                ));
            }
            if attribute.name == "cfg" {
                return Err(
                    "production #[cfg] is unmodeled for the target-invariant CLI surface"
                        .to_string(),
                );
            }
            if attribute.name == "cfg_attr" {
                if let Some((start, end)) = attribute.body {
                    if let Some(namespace) = nested_cfg_attr_clap_namespace(&tokens, start, end) {
                        return Err(format!(
                            "conditional #[cfg_attr] contains Clap-affecting {namespace}(..)"
                        ));
                    }
                }
                return Err(
                    "production #[cfg_attr] is unmodeled for the target-invariant CLI surface"
                        .to_string(),
                );
            }
            let reviewed = match attribute.name.as_str() {
                "arg" => &reviewed_arg_keys,
                "command" => &reviewed_command_keys,
                _ => continue,
            };
            let (start, end) = attribute.body.ok_or_else(|| {
                format!(
                    "#[{}] must use a reviewed parenthesized form",
                    attribute.name
                )
            })?;
            for key in top_level_attribute_keys(&tokens, start, end)? {
                if !reviewed.contains(key.as_str()) {
                    return Err(format!(
                        "unreviewed #[{}] semantic {key}; represent it in runtime-surface.json or explicitly review it as non-semantic",
                        attribute.name
                    ));
                }
            }
        }
        Ok(())
    }

    fn production_cli_source_end(source: &str) -> Result<usize, String> {
        let tokens = lex_rust_source(source)?;
        let attributes = rust_source_attributes(&tokens)?;
        let mut candidates = Vec::new();
        for attribute in attributes {
            if attribute.name != "cfg" {
                continue;
            }
            let Some((body_start, body_end)) = attribute.body else {
                continue;
            };
            if body_end != body_start + 1 || tokens[body_start].text != "test" {
                continue;
            }
            let mut brace_depth = 0usize;
            for token in tokens
                .iter()
                .take_while(|token| token.start < attribute.start)
            {
                match token.text {
                    "{" => brace_depth += 1,
                    "}" => brace_depth = brace_depth.saturating_sub(1),
                    _ => {}
                }
            }
            if brace_depth != 0 {
                continue;
            }
            let mut item = attribute.close + 1;
            if tokens.get(item).is_some_and(|token| token.text == "pub") {
                item += 1;
                if tokens.get(item).is_some_and(|token| token.text == "(") {
                    item = matching_source_token(&tokens, item, "(", ")").ok_or_else(|| {
                        "unterminated visibility on cfg(test) module in cli.rs".to_string()
                    })? + 1;
                }
            }
            if tokens.get(item).is_some_and(|token| token.text == "mod")
                && tokens
                    .get(item + 1)
                    .is_some_and(|token| token.text == "tests")
                && tokens.get(item + 2).is_some_and(|token| token.text == "{")
            {
                let module_close = matching_source_token(&tokens, item + 2, "{", "}")
                    .ok_or_else(|| "unterminated cfg(test) module in cli.rs".to_string())?;
                if module_close + 1 == tokens.len() {
                    candidates.push(attribute.start);
                }
            }
        }
        if candidates.len() != 1 {
            return Err(format!(
                "cli.rs must have exactly one final structural #[cfg(test)] mod tests boundary; observed {}",
                candidates.len()
            ));
        }
        Ok(candidates[0])
    }

    fn assert_reviewed_clap_source_attributes() {
        let source = include_str!("cli.rs");
        let production_end =
            production_cli_source_end(source).unwrap_or_else(|error| panic!("{error}"));
        review_clap_source_attributes(&source[..production_end])
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn authored_controls_are_not_confused_with_generated_controls() {
        let generated =
            clap_manifest_snapshot_from(Command::new("sample").subcommand(Command::new("run")));
        expect_command_paths(&generated.commands, &["sample", "sample run"]);
        assert!(generated.commands[0].get("options").is_none());

        let authored = clap_manifest_snapshot_from(
            Command::new("sample")
                .version("1")
                .disable_help_flag(true)
                .disable_version_flag(true)
                .disable_help_subcommand(true)
                .arg(
                    Arg::new("authored_help")
                        .long("show-help")
                        .action(ArgAction::Help),
                )
                .arg(
                    Arg::new("authored_version")
                        .long("show-version")
                        .action(ArgAction::Version),
                )
                .subcommand(
                    Command::new("help")
                        .disable_help_flag(true)
                        .disable_version_flag(true)
                        .disable_help_subcommand(true),
                ),
        );
        expect_command_paths(&authored.commands, &["sample", "sample help"]);
        let option_ids: Vec<&str> = authored.commands[0]["options"]
            .as_array()
            .expect("authored control options")
            .iter()
            .map(|option| option["id"].as_str().expect("option id"))
            .collect();
        assert_eq!(option_ids, ["authored_help", "authored_version"]);
    }

    fn expect_command_paths(commands: &[Value], expected: &[&str]) {
        let paths: Vec<&str> = commands
            .iter()
            .map(|command| command["path"].as_str().expect("command path"))
            .collect();
        assert_eq!(paths, expected);
    }

    #[test]
    fn authored_clap_attribute_semantics_are_reviewed() {
        assert_reviewed_clap_source_attributes();
    }

    #[test]
    fn clap_source_guard_preserves_the_authored_arg_and_command_allowlist() {
        review_clap_source_attributes(
            r#"
                # [ arg ( long, conflicts_with = "json", value_parser = ["yes", "no"] ) ]
                field: bool,
                #[command(hide = true, subcommand)]
                command: Command,
            "#,
        )
        .expect("reviewed arg/command keys and whitespace remain accepted");

        review_clap_source_attributes(
            r##"
                const LOOKALIKE: &str = "#[group(required = true)]";
                // # [clap(long)]
                /* #[structopt(long)] */
                #[arg(long)]
                field: bool,
            "##,
        )
        .expect("comments and literals cannot fabricate Clap attributes");
    }

    #[test]
    fn clap_source_guard_rejects_alternate_and_spaced_attribute_bypasses() {
        for (source, expected) in [
            ("#[group(required = true)] struct Grouped;", "#[group]"),
            ("#[clap(long)] field: bool,", "#[clap]"),
            ("#[structopt(long)] field: bool,", "#[structopt]"),
        ] {
            let error = review_clap_source_attributes(source)
                .expect_err("legacy or group namespace must fail closed");
            assert!(error.contains(expected), "unexpected error: {error}");
        }

        let error =
            review_clap_source_attributes("# [ arg ( requires = \"hidden\" ) ] field: bool,")
                .expect_err("spaced unreviewed arg attribute must be tokenized");
        assert!(
            error.contains("unreviewed #[arg] semantic requires"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn clap_source_guard_rejects_conditional_attributes_and_nested_namespaces() {
        for namespace in ["arg", "command", "group", "clap", "structopt"] {
            let source = format!("#[cfg_attr(unix, {namespace}(long))] field: bool,");
            let error = review_clap_source_attributes(&source)
                .expect_err("conditional Clap namespace must fail closed");
            assert!(
                error.contains(&format!("Clap-affecting {namespace}(..)")),
                "unexpected error: {error}"
            );
        }

        let nested = review_clap_source_attributes(
            "#[cfg_attr(unix, cfg_attr(windows, arg(long)))] field: bool,",
        )
        .expect_err("nested cfg_attr Clap namespace must fail closed");
        assert!(
            nested.contains("Clap-affecting arg(..)"),
            "unexpected error: {nested}"
        );

        let conditional_field = review_clap_source_attributes(
            r#"
                #[derive(Parser)]
                struct ConditionalCli {
                    #[cfg(unix)]
                    #[arg(long)]
                    hidden: bool,
                }
            "#,
        )
        .expect_err("target-conditional CLI field must fail closed");
        assert!(conditional_field.contains("production #[cfg]"));

        let conditional_variant = review_clap_source_attributes(
            r#"
                #[derive(Subcommand)]
                enum ConditionalCommands {
                    #[cfg_attr(unix, allow(dead_code))]
                    Hidden,
                }
            "#,
        )
        .expect_err("target-conditional CLI variant must fail closed");
        assert!(conditional_variant.contains("production #[cfg_attr]"));
    }

    #[test]
    fn clap_source_guard_canonicalizes_raw_attribute_identifiers() {
        let raw_arg = review_clap_source_attributes("#[r#arg(requires = \"x\")] field: bool,")
            .expect_err("raw arg identifier must reach the reviewed-key allowlist");
        assert!(
            raw_arg.contains("unreviewed #[arg] semantic requires"),
            "unexpected error: {raw_arg}"
        );

        let raw_group =
            review_clap_source_attributes("#[r#group(required = true)] struct Grouped;")
                .expect_err("raw group namespace must fail closed");
        assert!(
            raw_group.contains("#[group]"),
            "unexpected error: {raw_group}"
        );

        let raw_cfg_attr =
            review_clap_source_attributes("#[r#cfg_attr(unix, arg(long))] field: bool,")
                .expect_err("raw cfg_attr namespace must fail closed");
        assert!(
            raw_cfg_attr.contains("Clap-affecting arg(..)"),
            "unexpected error: {raw_cfg_attr}"
        );
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
    fn history_mode_is_root_owned_and_reaches_both_repl_spellings() {
        let implicit = Cli::parse_from(["ibex", "--history=global"]);
        assert_eq!(implicit.history, HistoryMode::Global);

        let explicit_before = Cli::parse_from(["ibex", "--history=off", "repl"]);
        assert_eq!(explicit_before.history, HistoryMode::Off);
        assert!(matches!(explicit_before.command, Some(Commands::Repl)));

        let explicit_after = Cli::parse_from(["ibex", "repl", "--history=project"]);
        assert_eq!(explicit_after.history, HistoryMode::Project);
        assert!(matches!(explicit_after.command, Some(Commands::Repl)));

        assert!(Cli::try_parse_from(["ibex", "--history=local"]).is_err());

        let argv = ["ibex", "repl", "--history=global"]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        assert!(history_option_was_explicit(&argv));
        let script_argv = ["ibex", "app.js", "--", "--history=global"]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        assert!(!history_option_was_explicit(&script_argv));
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
    fn reviewed_numeric_parser_boundaries_are_exact() {
        assert!(Cli::try_parse_from(["ibex", "--inspect-port", "65535"]).is_ok());
        assert!(Cli::try_parse_from(["ibex", "--inspect-port", "65536"]).is_err());
        assert!(Cli::try_parse_from(["ibex", "run", "app.js", "--inspect-port", "65535"]).is_ok());
        assert!(Cli::try_parse_from(["ibex", "run", "app.js", "--inspect-port", "65536"]).is_err());

        let usize_max = usize::MAX.to_string();
        let usize_overflow = (usize::MAX as u128 + 1).to_string();
        assert!(
            Cli::try_parse_from(["ibex", "--max-http-header-size", usize_max.as_str()]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["ibex", "--max-http-header-size", usize_overflow.as_str(),])
                .is_err()
        );
        assert!(Cli::try_parse_from(["ibex", "compat", "--jobs", usize_max.as_str()]).is_ok());
        assert!(
            Cli::try_parse_from(["ibex", "compat", "--jobs", usize_overflow.as_str(),]).is_err()
        );

        let u64_max = u64::MAX.to_string();
        let u64_overflow = (u64::MAX as u128 + 1).to_string();
        assert!(Cli::try_parse_from(["ibex", "compat", "--timeout", u64_max.as_str()]).is_ok());
        assert!(
            Cli::try_parse_from(["ibex", "compat", "--timeout", u64_overflow.as_str(),]).is_err()
        );
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

    #[test]
    fn foreground_capsec_audit_command_parses() {
        let cli = Cli::parse_from(["ibex", "capsec", "audit", "app.ts", "--arg"]);
        assert!(matches!(
            cli.command,
            Some(Commands::Capsec {
                command: CapsecCommands::Audit { file, args },
            }) if file == "app.ts" && args == ["--arg"]
        ));
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

    /// The probe harness (Exact LLP 0404 N-1) is invoked as
    /// `compat --probe '<expr>'` (optionally with `--timeout`) — pin that
    /// surface, and that a bare `compat` still routes to suite mode.
    #[test]
    fn compat_probe_flag_parses() {
        let cli = Cli::parse_from([
            "ibex",
            "compat",
            "--probe",
            "Object.getOwnPropertyDescriptor(Error.prototype,'name')",
            "--timeout",
            "20000",
        ]);
        match cli.command {
            Some(Commands::Compat { probe, timeout, .. }) => {
                assert_eq!(
                    probe.as_deref(),
                    Some("Object.getOwnPropertyDescriptor(Error.prototype,'name')")
                );
                assert_eq!(timeout, Some(20000));
            }
            other => panic!("expected Compat command, got {other:?}"),
        }
        let bare = Cli::parse_from(["ibex", "compat"]);
        assert!(matches!(
            bare.command,
            Some(Commands::Compat { probe: None, .. })
        ));
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
    /// LLP 0010#runtime-command-surface) is the single authority for the full
    /// recursive clap surface and for what is visible, hidden, reserved, and
    /// legacy-shimmed. This test pins the clap tree to it — ported from exact's
    /// stranded
    /// `packages/exact-cli/src/cli.rs::surface_manifest_matches_clap_tree`
    /// (LLP 0175 §8.1a) after the LLP 0180 split (ENG-22429). It supersedes
    /// the earlier hardcoded-list test
    /// `runtime_only_clap_tree_has_no_reserved_or_project_commands`.
    #[test]
    fn surface_manifest_matches_clap_tree() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../../runtime-surface.json"))
                .expect("runtime-surface.json parses");
        let snapshot = clap_manifest_snapshot();

        assert_eq!(manifest["version"], json!(5), "recursive manifest version");
        assert_eq!(
            manifest["clapSurface"]["frameworkGenerated"],
            json!({
                "authoredControlDetection": "pre-build-command-and-argument-identities",
                "helpArguments": "excluded",
                "versionArguments": "excluded",
                "helpSubcommand": "excluded",
            }),
            "manifest must state how Clap-generated controls are treated"
        );
        assert_eq!(
            manifest["clapSurface"]["positionalArguments"],
            json!({
                "inventory": "included",
                "passthroughWhen": "unbounded-and-allows-hyphen-values",
            }),
            "manifest must state how positional passthrough is classified"
        );
        assert_eq!(
            manifest["clapSurface"]["commands"],
            json!(snapshot.commands),
            "every authored command, option, alias, and positional must join exactly once"
        );
        assert_eq!(
            manifest["clapSurface"]["semanticRelations"], snapshot.semantic_relations,
            "reviewed parser kinds and argument conflicts must join exactly once"
        );

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
