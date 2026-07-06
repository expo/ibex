//! Interactive REPL for Ibex
//!
//! A high-quality REPL with:
//! - Multiline input with bracket/quote balancing
//! - Persistent history
//! - Built-in commands (.help, .load, .clear, .time, .env)
//! - Top-level await support (when engine supports it)

use crate::engine::Engine;
use anyhow::Result;
use colored::Colorize;
use rustyline::completion::Completer;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::{ValidationContext, ValidationResult, Validator};
use rustyline::{Context, Editor, Helper};
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const DEFAULT_PROMPT_SYMBOL: &str = "\u{27A4}";

/// Upper bound the completer waits for the engine thread to answer a member-
/// completion query. In practice the answer is near-instant (a pure prototype
/// walk with no yield points); the bound only guards against the engine loop
/// being unexpectedly unavailable, so a Tab press can never hang the line
/// editor. (ENG-23001)
const COMPLETION_DISPATCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Signal from the engine loop to the readline thread: draw the next prompt, or
/// stop and save history. (ENG-23001)
enum ReplControl {
    Continue,
    Stop,
}

/// A read-only member-completion query dispatched from the readline thread's
/// completer back to the engine's creating thread, with a channel to return the
/// JSON result. The Hermes runtime may only be touched from its creating
/// thread, so completion cannot run on the readline thread directly. (ENG-23001)
struct CompletionRequest {
    query: String,
    respond: std::sync::mpsc::Sender<Option<String>>,
}

fn style_prompt_symbol(symbol: &str) -> String {
    let symbol = format!("{} ", symbol);
    symbol.bright_black().bold().to_string()
}

fn styled_prompt_with_colors(symbol: &str) -> String {
    style_prompt_symbol(symbol)
}

fn plain_prompt(symbol: &str) -> String {
    format!("{} ", symbol)
}

fn repl_inspect_expression() -> &'static str {
    "if (typeof Exact !== 'undefined' && typeof Exact.inspect === 'function') { return Exact.inspect(_val, {colors: true, compact: true}); } else { return String(_val); }"
}

fn wrap_inspected_expression(code: &str, async_expression: bool) -> String {
    if async_expression {
        format!(
            "(async function() {{ var __repl_slot = [ ({}) ]; var _val = __repl_slot[0]; globalThis.$_ = _val; {} }})()",
            code,
            repl_inspect_expression()
        )
    } else {
        format!(
            "(function() {{ var _val = {}; globalThis.$_ = _val; {} }})()",
            code,
            repl_inspect_expression()
        )
    }
}

fn highlight_prompt_text<'a>(prompt_symbol: &str, prompt: &'a str) -> Cow<'a, str> {
    if prompt == plain_prompt(prompt_symbol) {
        Cow::Owned(styled_prompt_with_colors(prompt_symbol))
    } else {
        Cow::Borrowed(prompt)
    }
}

fn configured_prompt_symbol(fallback: &str) -> String {
    std::env::var("IBEX_REPL_PROMPT")
        .or_else(|_| std::env::var("EX_REPL_PROMPT"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// Format a REPL error for display, with source context when possible.
///
/// Hermes compile errors look like: "Compiling JS failed: 1:44:invalid numeric literal, sourceURL: <eval>"
/// Runtime errors look like: "Property 'foo' doesn't exist" or "Cannot read property 'x' of undefined"
///
/// For compile errors, we parse out the column, adjust for wrapper code offset,
/// and show a pointer to the error location in the user's source.
fn format_repl_error(error_msg: &str, user_code: &str, wrapper_prefix_len: usize) -> String {
    // Try to parse Hermes compile error: "Compiling JS failed: LINE:COL:message, sourceURL: ..."
    if let Some(rest) = error_msg.strip_prefix("Compiling JS failed: ") {
        // Strip ", sourceURL: ..." suffix
        let rest = if let Some(idx) = rest.rfind(", sourceURL:") {
            &rest[..idx]
        } else {
            rest
        };

        // Parse "LINE:COL:message"
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        if parts.len() == 3 {
            if let Ok(col) = parts[1].trim().parse::<usize>() {
                let message = parts[2].trim();
                // Adjust column for wrapper prefix
                let user_col = if col > wrapper_prefix_len {
                    col - wrapper_prefix_len
                } else {
                    1
                };

                // Build a nice error display like bun
                let mut output = String::new();
                // Error message header
                output.push_str(&format!("{} {}\n", "×".red().bold(), message));
                // Source line with line number
                let line_num = "1";
                let gutter_width = line_num.len();
                // Top border
                output.push_str(&format!(
                    "   {}\n",
                    format!("╭─[input:{}:{}]", line_num, user_col).dimmed()
                ));
                // Source line
                output.push_str(&format!(
                    " {} {} {}\n",
                    line_num.blue().bold(),
                    "│".dimmed(),
                    user_code
                ));
                // Pointer line
                let pointer_offset = gutter_width + 3 + user_col; // "N │ " prefix
                let pointer_pad = " ".repeat(pointer_offset);
                output.push_str(&format!("{}{}\n", pointer_pad, "▲".red().bold()));
                // Bottom border
                output.push_str(&format!("   {}", "╰────".dimmed()));
                return output;
            }
        }

        // Fallback: couldn't parse line:col but still a compile error
        return format!("{} {}", "×".red().bold(), rest);
    }

    // Runtime errors: just clean up the message
    format!("{} {}", "×".red().bold(), error_msg)
}

/// REPL helper for rustyline
struct ExHelper {
    /// JavaScript globals for completion hints
    globals: Vec<String>,
    prompt_symbol: String,
    /// Channel to dispatch member-completion queries to the engine's creating
    /// thread. The completer runs on the readline thread (ENG-23001), which is
    /// not the engine thread, so it cannot evaluate directly. (ENG-23001)
    completion_tx: mpsc::UnboundedSender<CompletionRequest>,
}

impl ExHelper {
    fn new(prompt_symbol: &str, completion_tx: mpsc::UnboundedSender<CompletionRequest>) -> Self {
        Self {
            globals: vec![
                "console",
                "globalThis",
                "undefined",
                "NaN",
                "Infinity",
                "fetch",
                "URL",
                "URLSearchParams",
                "Headers",
                "Request",
                "Response",
                "AbortController",
                "AbortSignal",
                "TextEncoder",
                "TextDecoder",
                "Blob",
                "File",
                "FileReader",
                "WebSocket",
                "Event",
                "EventTarget",
                "setTimeout",
                "clearTimeout",
                "setInterval",
                "clearInterval",
                "Array",
                "Object",
                "String",
                "Number",
                "Boolean",
                "Symbol",
                "Function",
                "Promise",
                "Map",
                "Set",
                "Date",
                "RegExp",
                "Error",
                "JSON",
                "Math",
                "Reflect",
                "Proxy",
                "ArrayBuffer",
                "Uint8Array",
                "Int8Array",
                "DataView",
                "exact",
                "process",
                "performance",
                "crypto",
                "atob",
                "btoa",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            prompt_symbol: prompt_symbol.to_string(),
            completion_tx,
        }
    }

    /// Send a read-only completion query to the engine's creating thread and
    /// block (bounded) for the JSON result. Returns `None` if the engine loop
    /// is gone or does not answer in time, matching the previous behavior of
    /// yielding no candidates rather than surfacing an error at the prompt.
    /// (ENG-23001)
    fn dispatch_completion_query(&self, query: &str) -> Option<String> {
        let (respond, response) = std::sync::mpsc::channel();
        self.completion_tx
            .send(CompletionRequest {
                query: query.to_string(),
                respond,
            })
            .ok()?;
        response
            .recv_timeout(COMPLETION_DISPATCH_TIMEOUT)
            .ok()
            .flatten()
    }

    fn completion_query(line: &str, pos: usize) -> (usize, Option<String>, String) {
        let start = line[..pos]
            .rfind(Self::is_identifier_boundary)
            .map(|i| i + 1)
            .unwrap_or(0);
        let prefix = &line[start..pos];

        let trimmed = line[..start].trim_end();
        if let Some(stripped) = trimmed.strip_suffix('.') {
            let base_expr = stripped.trim_end();
            if !base_expr.is_empty() {
                return (start, Some(base_expr.to_string()), prefix.to_string());
            }
        }

        (start, None, prefix.to_string())
    }

    fn is_identifier_boundary(c: char) -> bool {
        !(c.is_ascii_alphanumeric() || c == '_' || c == '$')
    }

    fn complete_object_members(&self, expr: &str, prefix: &str) -> Vec<String> {
        // Member completion evaluates the base expression to enumerate its
        // properties, so it must refuse anything that could carry side
        // effects: `dropTables().` + Tab must not execute dropTables().
        if !is_side_effect_free_path(expr) {
            return Vec::new();
        }

        let expr_json = serde_json::to_string(expr).unwrap_or_else(|_| "\"\"".to_string());
        let prefix_json = serde_json::to_string(prefix).unwrap_or_else(|_| "\"\"".to_string());
        let query = format!(
            "(function() {{\n\
                try {{\n\
                  var __expr = {};\n\
                  var __base = Function('return (' + __expr + ')')();\n\
                  if (__base === null || __base === undefined) {{\n\
                    return JSON.stringify([]);\n\
                  }}\n\
                  if (typeof __base === 'number' || typeof __base === 'string' || typeof __base === 'boolean' || typeof __base === 'bigint' || typeof __base === 'symbol') {{\n\
                    __base = Object(__base);\n\
                  }}\n\
                  if (typeof __base !== 'object' && typeof __base !== 'function') {{\n\
                    return JSON.stringify([]);\n\
                  }}\n\
                  var __prefix = {};\n\
                  var __set = Object.create(null);\n\
                  var __out = [];\n\
                  var __current = __base;\n\
                  while (__current !== null) {{\n\
                    var __props = Object.getOwnPropertyNames(__current);\n\
                    for (var i = 0; i < __props.length; i++) {{\n\
                      var __key = __props[i];\n\
                      if (__set[__key]) {{\n\
                        continue;\n\
                      }}\n\
                      if (__key.indexOf(__prefix) === 0) {{\n\
                        __set[__key] = true;\n\
                        __out.push(__key);\n\
                      }}\n\
                    }}\n\
                    __current = Object.getPrototypeOf(__current);\n\
                    if (typeof __current !== 'object' && typeof __current !== 'function') {{\n\
                      break;\n\
                    }}\n\
                  }}\n\
                  __out.sort();\n\
                  return JSON.stringify(__out);\n\
                }} catch (error) {{\n\
                  return JSON.stringify([]);\n\
                }}\n\
            }})()",
            expr_json,
            prefix_json
        );

        // The completer runs on the readline OS thread, which ENG-23001 split
        // off the engine's creating thread so background timers fire while the
        // prompt is idle. The Hermes runtime may only be touched from its
        // creating thread, so hand the read-only introspection query to the
        // engine loop (which evaluates it with `eval_immediate` — no event-loop
        // driving — and answers over a channel) and block for the result. The
        // query is a pure `Object.getOwnPropertyNames` prototype walk with no
        // side effects, and the completer only runs while the engine loop sits
        // idle in `select!`, so the answer comes back promptly. (ENG-23001)
        let result = self
            .dispatch_completion_query(&query)
            .and_then(|text| serde_json::from_str::<Vec<String>>(&text).ok())
            .unwrap_or_default();

        let mut seen = HashSet::new();
        result
            .into_iter()
            .filter_map(|value| {
                if !value.is_empty() && seen.insert(value.clone()) {
                    Some(value)
                } else {
                    None
                }
            })
            .collect()
    }

    fn complete_globals(&self, prefix: &str) -> Vec<String> {
        let mut result = self.complete_object_members("globalThis", prefix);

        for global in &self.globals {
            if global.starts_with(prefix) {
                result.push(global.clone());
            }
        }

        result.sort_unstable();
        let mut seen = HashSet::new();
        result
            .into_iter()
            .filter_map(|value| {
                if seen.insert(value.clone()) {
                    Some(value)
                } else {
                    None
                }
            })
            .collect()
    }

    fn current_prompt(&self) -> &str {
        &self.prompt_symbol
    }
}

impl Completer for ExHelper {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let (start, base_expr, prefix) = Self::completion_query(line, pos);

        if prefix.is_empty() && base_expr.is_none() {
            return Ok((pos, vec![]));
        }

        let matches = if let Some(expr) = base_expr {
            self.complete_object_members(&expr, &prefix)
        } else {
            self.complete_globals(&prefix)
        };

        Ok((start, matches))
    }
}

impl Hinter for ExHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<Self::Hint> {
        if pos < line.len() {
            return None;
        }

        let (start, base_expr, prefix) = Self::completion_query(line, pos);
        if prefix.is_empty() && base_expr.is_none() {
            return None;
        }

        // Hints run on every keystroke, so keep them cheap/synchronous to avoid
        // blocking the REPL while typing. Keep runtime object introspection for
        // explicit completion (Tab) only.
        if base_expr.is_some() {
            return None;
        }

        let mut matches: Vec<String> = self
            .globals
            .iter()
            .filter(|global| global.starts_with(&prefix))
            .cloned()
            .collect();
        matches.sort_unstable();

        let _ = start;

        for candidate in matches {
            if candidate.len() > prefix.len() {
                return Some(candidate[prefix.len()..].to_string());
            }
        }

        None
    }
}

impl Highlighter for ExHelper {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> Cow<'b, str> {
        highlight_prompt_text(self.current_prompt(), prompt)
    }

    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        Cow::Borrowed(line)
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Cow::Owned(hint.dimmed().to_string())
    }

    fn highlight_char(&self, _line: &str, _pos: usize, _forced: bool) -> bool {
        false
    }
}

impl Validator for ExHelper {
    fn validate(&self, ctx: &mut ValidationContext) -> rustyline::Result<ValidationResult> {
        let input = ctx.input();

        // Check for unbalanced brackets/parens/braces
        let mut stack = Vec::new();
        let mut in_string = false;
        let mut string_char = '"';
        let mut trailing_backslashes = 0usize;

        for c in input.chars() {
            if in_string {
                if c == string_char && trailing_backslashes.is_multiple_of(2) {
                    in_string = false;
                }
            } else {
                match c {
                    '"' | '\'' | '`' => {
                        in_string = true;
                        string_char = c;
                    }
                    '(' | '[' | '{' => stack.push(c),
                    ')' => {
                        if stack.pop() != Some('(') {
                            return Ok(ValidationResult::Invalid(Some("Unmatched )".to_string())));
                        }
                    }
                    ']' => {
                        if stack.pop() != Some('[') {
                            return Ok(ValidationResult::Invalid(Some("Unmatched ]".to_string())));
                        }
                    }
                    '}' => {
                        if stack.pop() != Some('{') {
                            return Ok(ValidationResult::Invalid(Some("Unmatched }".to_string())));
                        }
                    }
                    _ => {}
                }
            }
            if c == '\\' {
                trailing_backslashes += 1;
            } else {
                trailing_backslashes = 0;
            }
        }

        if in_string || !stack.is_empty() {
            Ok(ValidationResult::Incomplete)
        } else {
            Ok(ValidationResult::Valid(None))
        }
    }
}

impl Helper for ExHelper {}

/// True when `expr` is a plain identifier dot-chain (`a`, `a.b.c`, `$x._y1`),
/// i.e. matches `^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$`. Anything else —
/// calls, indexing, operators — may have side effects and must not be
/// evaluated for tab completion.
fn is_side_effect_free_path(expr: &str) -> bool {
    if expr.is_empty() {
        return false;
    }
    expr.split('.').all(|segment| {
        let mut chars = segment.chars();
        matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    })
}

/// Get the history file path, migrating the pre-rename location once.
fn history_path() -> std::path::PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    history_path_in(&base)
}

/// History lives under `ibex/`. A legacy `exact/repl_history` left by older
/// builds is migrated when the new path does not exist yet.
fn history_path_in(base: &std::path::Path) -> std::path::PathBuf {
    let new_path = base.join("ibex").join("repl_history");
    let old_path = base.join("exact").join("repl_history");
    if !new_path.exists() && old_path.exists() {
        if let Some(parent) = new_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::rename(&old_path, &new_path);
    }
    new_path
}

/// Print the welcome message
fn print_welcome() {
    println!("{} {} (Hermes)", "Ibex".bold(), env!("CARGO_PKG_VERSION"));
    println!("Type .help for help, Ctrl+D to exit");
}

/// Print help for REPL commands
fn print_help() {
    println!("{}", "REPL Commands:".bold());
    println!("  {}  - Show this help", ".help".yellow());
    println!("  {}  - Load and execute a file", ".load <file>".yellow());
    println!("  {} - Clear the screen", ".clear".yellow());
    println!(
        "  {}  - Time the execution of code",
        ".time <code>".yellow()
    );
    println!("  {}   - Show environment variables", ".env".yellow());
    println!("  {}  - Exit the REPL", ".exit".yellow());
    println!();
    println!("{}", "Keyboard Shortcuts:".bold());
    println!("  {}   - Exit", "Ctrl+D".cyan());
    println!("  {}   - Cancel current input", "Ctrl+C".cyan());
    println!(
        "  {} - Prompt can be customized with IBEX_REPL_PROMPT",
        "Environment".yellow()
    );
    println!("  {} - Search history", "Ctrl+R".cyan());
    println!();
}

/// Start the REPL.
///
/// The line editor (`rustyline::readline`) runs on a dedicated OS thread while
/// this — the engine's creating thread — drives the Hermes event loop between
/// keystrokes. A `select!` interleaves three things: an idle park + non-blocking
/// pump so background timers/async callbacks fire while the prompt sits idle
/// (Node-like parity, the point of ENG-23001); submitted lines; and
/// member-completion queries dispatched back from the readline thread's
/// completer (the Hermes runtime is single-threaded, so completion can only
/// evaluate on this thread). The park (`wait_for_pending_tasks`) is sized by the
/// soonest scheduled timer instead of a fixed cadence, so an idle prompt does
/// not busy-poll (ENG-23030 #5); the pump uses `drive_ready_tasks` — never the
/// quiescence-driving `eval` — so the prompt cannot re-wedge on
/// `setInterval`/servers the way it did before ENG-22957. (ENG-23001)
pub async fn start(engine: Arc<dyn Engine>) -> Result<()> {
    print_welcome();

    let prompt_symbol = configured_prompt_symbol(DEFAULT_PROMPT_SYMBOL);
    let history_file = history_path();

    // readline thread -> engine loop: the result of each `readline()` call.
    let (line_tx, mut line_rx) = mpsc::unbounded_channel::<Result<String, ReadlineError>>();
    // completer (readline thread) -> engine loop: member-completion queries.
    let (completion_tx, mut completion_rx) = mpsc::unbounded_channel::<CompletionRequest>();
    // engine loop -> readline thread: draw the next prompt, or stop.
    let (control_tx, control_rx) = std::sync::mpsc::channel::<ReplControl>();

    // The line editor is owned entirely by its own thread so it never crosses a
    // thread boundary. It blocks in `readline()` there while this thread keeps
    // the runtime's event loop alive.
    let reader = std::thread::Builder::new()
        .name("ibex-repl-readline".to_string())
        .spawn(move || -> Result<()> {
            let helper = ExHelper::new(&prompt_symbol, completion_tx);
            let config = rustyline::Config::builder()
                .history_ignore_space(true)
                .completion_type(rustyline::CompletionType::List)
                .edit_mode(rustyline::EditMode::Emacs)
                .build();
            let mut rl: Editor<ExHelper, DefaultHistory> = Editor::with_config(config)?;
            rl.set_helper(Some(helper));

            if let Some(parent) = history_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = rl.load_history(&history_file);

            let prompt = plain_prompt(&prompt_symbol);
            loop {
                let readline = rl.readline(&prompt);
                if let Ok(line) = readline.as_ref() {
                    if !line.trim().is_empty() {
                        let _ = rl.add_history_entry(line);
                    }
                }
                // Hand the result to the engine loop. If it is gone, stop.
                if line_tx.send(readline).is_err() {
                    break;
                }
                // Wait until the engine loop has finished handling this line
                // (and printed any result) before drawing the next prompt, so
                // eval output stays ordered above the prompt.
                match control_rx.recv() {
                    Ok(ReplControl::Continue) => continue,
                    Ok(ReplControl::Stop) | Err(_) => break,
                }
            }
            let _ = rl.save_history(&history_file);
            Ok(())
        })?;

    // Track capabilities for the REPL session (whole conversation is one module)
    let mut session_capabilities: HashSet<String> = HashSet::new();

    'main: loop {
        tokio::select! {
            biased;

            // Answer a completion query on the engine's creating thread. The
            // completer is blocking on the response, so service it first.
            Some(req) = completion_rx.recv() => {
                let candidates = engine.eval_immediate(&req.query).await.ok().flatten();
                let _ = req.respond.send(candidates);
            }

            // A submitted line (or a readline error) arrived.
            maybe_line = line_rx.recv() => {
                let Some(readline) = maybe_line else { break 'main; };
                match readline {
                    Ok(line) => {
                        let keep_going =
                            handle_repl_line(&engine, &line, &mut session_capabilities).await;
                        let signal = if keep_going {
                            ReplControl::Continue
                        } else {
                            ReplControl::Stop
                        };
                        // A send error means the reader already exited.
                        if control_tx.send(signal).is_err() || !keep_going {
                            break 'main;
                        }
                    }
                    Err(ReadlineError::Interrupted) => {
                        println!("^C");
                        if control_tx.send(ReplControl::Continue).is_err() {
                            break 'main;
                        }
                    }
                    Err(ReadlineError::Eof) => {
                        // Release the reader (it saves history and exits), then
                        // let pending event-loop work scheduled during the
                        // session finish before we exit — Node's REPL and
                        // `ibex <file>` both drain rather than drop a still-due
                        // `setTimeout`/`fetch().then()`. This runs only after
                        // input has ended, so it cannot re-wedge a live prompt
                        // (the ENG-22957 concern). (ENG-23001)
                        let _ = control_tx.send(ReplControl::Stop);
                        if let Err(err) = engine.drain_event_loop().await {
                            eprintln!("{}: {err:#}", "Error".red().bold());
                        }
                        break 'main;
                    }
                    Err(err) => {
                        eprintln!("{}: {:?}", "Error".red().bold(), err);
                        let _ = control_tx.send(ReplControl::Stop);
                        break 'main;
                    }
                }
            }

            // Idle park + pump: wait until the soonest scheduled timer is due (or
            // a background callback wakes us, or — nothing scheduled — for
            // IDLE_PARK), then run whatever became ready. The engine sizes the
            // park, so an idle prompt no longer runs an FFI poll 20×/s; the pump
            // is the non-blocking `drive_ready_tasks` (never the quiescence-
            // driving `eval`), so background timers/servers fire without ever
            // wedging the prompt. (ENG-23001, ENG-23030 #5)
            _ = engine.wait_for_pending_tasks() => {
                if let Err(err) = engine.drive_ready_tasks().await {
                    eprintln!(
                        "{}: REPL event loop pump failed: {err:#}",
                        "Error".red().bold()
                    );
                }
            }
        }
    }

    // Every `break 'main` above either sent `Stop` or observed the reader gone,
    // so the reader thread is unblocked and about to save history and exit.
    let _ = reader.join();

    Ok(())
}

/// Handle one submitted REPL line: dispatch a built-in `.command` or evaluate
/// JavaScript. Returns `true` to keep the session going, `false` to exit.
/// Split out of `start` so the engine loop's `select!` arm stays small; it runs
/// on the engine's creating thread. (ENG-23001)
async fn handle_repl_line(
    engine: &Arc<dyn Engine>,
    line: &str,
    session_capabilities: &mut HashSet<String>,
) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }

    // Handle REPL commands
    if trimmed.starts_with('.') {
        return match handle_command(trimmed, engine).await {
            Ok(keep_going) => keep_going,
            Err(e) => {
                eprintln!("{}: {}", "Error".red().bold(), e);
                true
            }
        };
    }

    // Evaluate JavaScript and wrap result in Exact.inspect for pretty printing
    let async_expression = needs_top_level_await(trimmed) && !is_statement(trimmed);
    let (code, use_inspect) = if is_import_statement(trimmed) {
        // Transform import statement to require() and extract capabilities
        match transform_import(trimmed) {
            Some((transformed, capabilities)) => {
                // Track capabilities for this REPL session
                if !capabilities.is_empty() {
                    for cap in &capabilities {
                        session_capabilities.insert(cap.clone());
                        println!("{}", format!("  [capability granted: {}]", cap).dimmed());
                    }

                    // Register capabilities with the runtime (module ID 0 for REPL)
                    let cap_list: Vec<String> = session_capabilities.iter().cloned().collect();
                    let cap_json = serde_json::to_string(&cap_list).unwrap_or_default();
                    let register_code = format!(
                        "(function() {{ \
                            if (typeof Exact !== 'undefined' && Exact.setModuleCapabilities) {{ \
                                Exact.setModuleCapabilities(0, {}); \
                            }} \
                        }})()",
                        cap_json
                    );
                    let _ = engine.eval_immediate(&register_code).await;
                }

                (transformed, true) // Inspect import results to show module exports
            }
            None => {
                eprintln!(
                    "{}: Could not parse import statement. Try: import {{ x }} from 'mod' or const x = require('mod')",
                    "Error".red().bold()
                );
                return true;
            }
        }
    } else if async_expression {
        (trimmed.to_string(), true)
    } else if needs_top_level_await(trimmed) {
        (wrap_top_level_await(trimmed), false)
    } else if is_statement(trimmed) {
        (trimmed.to_string(), false) // Statements don't return values to inspect
    } else {
        // Expression: will be wrapped by inspect below
        (trimmed.to_string(), true)
    };

    // Transform import() to globalThis['import']() since Hermes parser doesn't support import() syntax
    // Use bracket notation to avoid parser issues with 'import' keyword
    let code = code.replace("import(", "globalThis['import'](");

    // Wrap with Exact.inspect if it's an expression result
    // Avoid wrapping user code in extra parens — use "var _val = CODE;" directly
    // so syntax errors reference the user's code, not wrapper artifacts
    let final_code = if use_inspect {
        wrap_inspected_expression(&code, async_expression)
    } else {
        code
    };

    // Compute how many characters of wrapper precede the user's code
    let wrapper_prefix_len = final_code.find(trimmed).unwrap_or(0);

    // Use `eval_immediate`, not `eval`: the native eval path already drains
    // microtasks and unwraps/awaits the result Promise before returning (so
    // top-level `await` still resolves), while `eval` additionally drives the
    // event loop to full quiescence. At an interactive prompt that means
    // `setInterval(...)` or `Bun.serve(...)` never return control — the prompt
    // wedges until Ctrl+C. Background work now runs via the idle pump in
    // `start` instead. Node's REPL returns immediately; match that. (ENG-22957,
    // ENG-23001)
    match engine.eval_immediate(&final_code).await {
        Ok(Some(result)) => {
            println!("{}", result);
        }
        Ok(None) => {
            println!("{}", "undefined".dimmed());
        }
        Err(e) => {
            eprintln!(
                "{}",
                format_repl_error(&e.to_string(), trimmed, wrapper_prefix_len)
            );
        }
    }

    true
}

/// Clear the terminal and move the cursor home. Emits the ANSI sequence
/// directly rather than `rustyline::Editor::clear_screen`, because the line
/// editor now lives on a separate thread (ENG-23001) while the command handler
/// runs on the engine thread. The reader thread draws the next prompt fresh, so
/// a plain clear is sufficient. (ENG-23001)
fn clear_screen() {
    use std::io::Write;
    print!("\x1b[H\x1b[2J");
    let _ = std::io::stdout().flush();
}

/// Handle a REPL command
/// Returns Ok(true) to continue, Ok(false) to exit, Err for errors
async fn handle_command(cmd: &str, engine: &Arc<dyn Engine>) -> Result<bool> {
    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
    let command = parts[0];
    let arg = parts.get(1).map(|s| s.trim());

    match command {
        ".help" | ".h" => {
            print_help();
            Ok(true)
        }
        ".exit" | ".quit" | ".q" => Ok(false),
        ".clear" | ".cls" => {
            clear_screen();
            Ok(true)
        }
        ".load" => {
            let file = arg.ok_or_else(|| anyhow::anyhow!("Usage: .load <file>"))?;
            // `run_file_immediate`, not `run_file`: the latter drives the event
            // loop to quiescence, so `.load server.js` (Bun.serve/setInterval)
            // never returned and the prompt hard-wedged — the same ENG-22957
            // wedge every other eval path already avoids. Background work runs
            // via the idle pump instead. (ENG-23030 #2)
            match engine.run_file_immediate(file).await {
                Ok(Some(result)) => println!("{}", result),
                Ok(None) => println!("{}", "Loaded".green()),
                Err(e) => eprintln!("{}: {}", "Error".red().bold(), e),
            }
            Ok(true)
        }
        ".time" => {
            let code = arg.ok_or_else(|| anyhow::anyhow!("Usage: .time <code>"))?;
            let start = std::time::Instant::now();
            let code = if needs_top_level_await(code) {
                wrap_top_level_await(code)
            } else {
                code.to_string()
            };
            // Match the prompt's `eval_immediate` semantics so `.time` cannot
            // wedge on background work (setInterval/servers). (ENG-22957)
            let result = engine.eval_immediate(&code).await;
            let elapsed = start.elapsed();

            match result {
                Ok(Some(val)) => println!("{}", val),
                Ok(None) => println!("{}", "undefined".dimmed()),
                Err(e) => eprintln!("{}: {}", "Error".red().bold(), e),
            }

            println!("{}: {:?}", "Time".cyan(), elapsed);
            Ok(true)
        }
        ".env" => {
            for (key, value) in std::env::vars() {
                println!("{}={}", key.cyan(), value);
            }
            Ok(true)
        }
        _ => {
            eprintln!(
                "{}: Unknown command '{}'. Type .help for help.",
                "Error".red().bold(),
                command
            );
            Ok(true)
        }
    }
}

fn needs_top_level_await(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.starts_with("async ") || trimmed.starts_with("function") {
        return false;
    }
    // Word-boundary + literal/comment-aware detection: a raw `contains("await")`
    // fired on identifiers like `awaited`/`awaitTime` and on `"await"` inside a
    // string, wrapping the line in an async IIFE and shifting `let`/`const`
    // bindings out of the visible scope. Reuse the runtime's scanner. (ENG-22957)
    crate::runtime::contains_await_keyword(trimmed)
}

/// Check if input starts with a statement keyword (not valid in expression position)
fn is_statement(input: &str) -> bool {
    let prefixes = [
        "let ",
        "let{",
        "const ",
        "const{",
        "var ",
        "var{",
        "if ",
        "if(",
        "for ",
        "for(",
        "while ",
        "while(",
        "do ",
        "do{",
        "switch ",
        "switch(",
        "try ",
        "try{",
        "throw ",
        "class ",
        "function ",
        "import ",
    ];
    prefixes.iter().any(|p| input.starts_with(p))
}

/// Check if input is an import statement
fn is_import_statement(input: &str) -> bool {
    let trimmed = input.trim();
    trimmed.starts_with("import ") && !trimmed.starts_with("import(")
}

/// Parse import attributes from "with { needs: [...] }" clause
/// Returns (module_specifier, capabilities)
fn parse_import_with_clause(module_part: &str) -> (&str, Vec<String>) {
    // Check if there's a "with" clause
    if let Some(with_pos) = module_part.find(" with ") {
        let module_spec = module_part[..with_pos].trim();
        let with_clause = &module_part[with_pos + 6..]; // Skip " with "

        // Parse "{ needs: [...] }" or "{ needs: '*' }"
        if let Some(start) = with_clause.find('{') {
            if let Some(end) = with_clause.find('}') {
                let content = &with_clause[start + 1..end];

                // Look for "needs:" followed by array or string
                if let Some(needs_pos) = content.find("needs:") {
                    let needs_value = content[needs_pos + 6..].trim();

                    // Handle array: ['cap1', 'cap2']
                    if needs_value.starts_with('[') {
                        if let Some(end_bracket) = needs_value.find(']') {
                            let array_content = &needs_value[1..end_bracket];
                            let caps: Vec<String> = array_content
                                .split(',')
                                .map(|s| s.trim().trim_matches(|c| c == '\'' || c == '"'))
                                .filter(|s| !s.is_empty())
                                .map(String::from)
                                .collect();
                            return (module_spec, caps);
                        }
                    }
                    // Handle string: any capability string
                    else if needs_value.starts_with('\'') || needs_value.starts_with('"') {
                        let cap = needs_value.trim_matches(|c| c == '\'' || c == '"' || c == ',');
                        if !cap.is_empty() {
                            return (module_spec, vec![cap.to_string()]);
                        }
                    }
                }
            }
        }

        (module_spec, vec![])
    } else {
        (module_part, vec![])
    }
}

/// Transform import statement to require (CommonJS)
/// Converts: import fs from 'node:fs' with { needs: ['fs:read'] }
/// To: globalThis.fs = require('node:fs')
/// Also returns extracted capabilities
/// (We use globalThis instead of const/let because eval() scope doesn't persist)
fn transform_import(input: &str) -> Option<(String, Vec<String>)> {
    let trimmed = input.trim();

    // Handle: import fs from 'module' [with { needs: [...] }]
    if let Some(rest) = trimmed.strip_prefix("import ") {
        // Simple regex-like parsing
        let parts: Vec<&str> = rest.splitn(2, " from ").collect();
        if parts.len() == 2 {
            let binding = parts[0].trim();
            let module_with_attrs = parts[1].trim().trim_matches(';');

            // Parse module specifier and capabilities
            let (module, capabilities) = parse_import_with_clause(module_with_attrs);
            let module = module.trim_matches(|c| c == '\'' || c == '"');

            // Handle different import forms
            if binding.starts_with('{') && binding.ends_with('}') {
                // Named imports: import { foo, bar } from 'mod'
                // Extract names and assign each to globalThis
                let names = binding.trim_matches(|c| c == '{' || c == '}');
                let bindings: Vec<&str> = names.split(',').map(|s| s.trim()).collect();
                let assignments: Vec<String> = bindings
                    .iter()
                    .map(|name| {
                        // Handle "foo as bar" syntax
                        if name.contains(" as ") {
                            let parts: Vec<&str> = name.splitn(2, " as ").collect();
                            let orig = parts[0].trim();
                            let alias = parts[1].trim();
                            format!("globalThis.{} = _mod.{}", alias, orig)
                        } else {
                            format!("globalThis.{} = _mod.{}", name, name)
                        }
                    })
                    .collect();
                return Some((
                    format!(
                        "(function(){{ const _mod = require('{}'); {}; return _mod; }})()",
                        module,
                        assignments.join("; ")
                    ),
                    capabilities,
                ));
            } else if binding.contains(" as ") {
                // Default with alias: import foo as bar from 'mod'
                let alias_parts: Vec<&str> = binding.splitn(2, " as ").collect();
                if alias_parts.len() == 2 {
                    let _original = alias_parts[0].trim();
                    let alias = alias_parts[1].trim();
                    return Some((
                        format!("globalThis.{} = require('{}')", alias, module),
                        capabilities,
                    ));
                }
            } else if binding.starts_with('*') {
                // Star import: import * as foo from 'mod'
                if let Some(name) = binding.strip_prefix("* as ") {
                    let name = name.trim();
                    return Some((
                        format!("globalThis.{} = require('{}')", name, module),
                        capabilities,
                    ));
                }
            } else {
                // Default import: import foo from 'mod'
                // For ESM modules (marked with __esModule), use .default
                return Some((
                    format!(
                        "(function(){{ var _m = require('{}'); globalThis.{} = _m && _m.__esModule ? _m.default : _m; return _m; }})()",
                        module, binding
                    ),
                    capabilities,
                ));
            }
        }
    }

    // Handle: import 'module' (side effects only)
    if let Some(rest) = trimmed.strip_prefix("import ") {
        if !rest.contains(" from ") {
            let (module, capabilities) = parse_import_with_clause(rest);
            let module = module.trim_matches(|c| c == '\'' || c == '"' || c == ';');
            return Some((format!("require('{}')", module), capabilities));
        }
    }

    None
}

fn wrap_top_level_await(input: &str) -> String {
    let trimmed = input.trim();
    if is_statement(trimmed) {
        // Statements can't be wrapped in return(...), just execute them
        format!("(async () => {{ {} }})()", trimmed)
    } else {
        // Capture result as $_ for REPL history
        format!(
            "(async () => {{ return (globalThis.$_ = ({})); }})()",
            trimmed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        highlight_prompt_text, history_path_in, is_side_effect_free_path, needs_top_level_await,
        plain_prompt, styled_prompt_with_colors, wrap_inspected_expression, DEFAULT_PROMPT_SYMBOL,
    };

    #[test]
    fn top_level_await_detection_ignores_identifiers_and_literals() {
        // Real top-level await must be detected.
        assert!(needs_top_level_await("await fetch('http://x')"));
        assert!(needs_top_level_await("const x = await f();"));
        assert!(needs_top_level_await("for (const y of z) { await y; }"));

        // Substrings of `await` inside identifiers must NOT trigger the async
        // IIFE wrap — that was the bug that moved `let`/`const` bindings out of
        // scope so the next line threw ReferenceError. (ENG-22957)
        assert!(!needs_top_level_await("const awaited = 1"));
        assert!(!needs_top_level_await("let awaitTime = 5;"));
        assert!(!needs_top_level_await("const kawaii = 1;"));

        // `await` appearing only inside a string literal is not top-level await.
        assert!(!needs_top_level_await("console.log('await')"));
        assert!(!needs_top_level_await("const s = \"please await\";"));

        // `await` inside a regex literal must NOT be read as top-level await:
        // wrapping `var re = /await/g` in an async IIFE dropped the `re` binding
        // from the global scope, so the next line threw ReferenceError. (ENG-23031)
        assert!(!needs_top_level_await("var re = /await/g"));
        assert!(!needs_top_level_await("var re = /(await)/"));
        assert!(!needs_top_level_await("x.replace(/await/g, '')"));

        // Guards for empty / async-function / plain statements still hold.
        assert!(!needs_top_level_await(""));
        assert!(!needs_top_level_await("async function f() { await g(); }"));
        assert!(!needs_top_level_await("1 + 1"));
    }

    #[test]
    fn completion_guard_accepts_identifier_dot_chains() {
        for expr in [
            "a",
            "console",
            "globalThis",
            "a.b",
            "a.b.c",
            "$_",
            "_private.$inner",
            "obj1.prop2.value3",
        ] {
            assert!(is_side_effect_free_path(expr), "should accept: {expr}");
        }
    }

    #[test]
    fn completion_guard_rejects_expressions_with_potential_side_effects() {
        for expr in [
            "",
            "dropTables()",
            "a.b()",
            "fn().chain",
            "arr[0]",
            "a[b]",
            "a + b",
            "new Thing",
            "await x",
            "a..b",
            "a.b.",
            ".a",
            "1a",
            "a.1b",
            "a;b",
            "a`b`",
            "a, b",
        ] {
            assert!(!is_side_effect_free_path(expr), "should reject: {expr}");
        }
    }

    #[test]
    fn history_path_migrates_legacy_exact_file() {
        let base = std::env::temp_dir().join(format!(
            "ibex-repl-history-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let old_dir = base.join("exact");
        std::fs::create_dir_all(&old_dir).expect("create old dir");
        std::fs::write(old_dir.join("repl_history"), "1 + 1\n").expect("write old history");

        let resolved = history_path_in(&base);

        assert_eq!(resolved, base.join("ibex").join("repl_history"));
        assert_eq!(
            std::fs::read_to_string(&resolved).expect("read migrated history"),
            "1 + 1\n"
        );
        assert!(
            !old_dir.join("repl_history").exists(),
            "old file should be renamed away"
        );

        // Second resolution is a no-op (no old file left; new path exists).
        assert_eq!(history_path_in(&base), resolved);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn highlights_primary_prompt_only() {
        let prompt = plain_prompt(DEFAULT_PROMPT_SYMBOL);
        assert_eq!(
            highlight_prompt_text(DEFAULT_PROMPT_SYMBOL, &prompt),
            styled_prompt_with_colors(DEFAULT_PROMPT_SYMBOL)
        );
    }

    #[test]
    fn preserves_reverse_search_prompt() {
        let reverse_prompt = "(reverse-i-search)`foo`: ";
        assert_eq!(
            highlight_prompt_text(DEFAULT_PROMPT_SYMBOL, reverse_prompt),
            reverse_prompt
        );
    }

    #[test]
    fn async_expression_wrapper_preserves_returned_promises() {
        let wrapped =
            wrap_inspected_expression("(await fetch('https://example.org')).text()", true);
        assert!(wrapped
            .contains("var __repl_slot = [ ((await fetch('https://example.org')).text()) ];"));
        assert!(!wrapped.contains("var _val = await"));
    }

    #[test]
    fn sync_expression_wrapper_still_uses_sync_iife() {
        let wrapped = wrap_inspected_expression("Promise.resolve(3)", false);
        assert!(wrapped.starts_with("(function() { var _val = Promise.resolve(3);"));
        assert!(!wrapped.contains("__repl_slot"));
    }
}
