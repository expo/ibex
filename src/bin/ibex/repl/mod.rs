//! Interactive REPL for Ibex
//!
//! A high-quality REPL with:
//! - Multiline input with bracket/quote balancing
//! - Persistent history
//! - Built-in commands (.help, .load, .clear, .time, .env)
//! - Top-level await support (when engine supports it)

use crate::engine::Engine;
use anyhow::{Context as _, Result};
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
use std::path::{Path, PathBuf};
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
    "var _commitDisplay = function(_rendered) { var _text = String(_rendered); globalThis.$_ = _val; return _text; }; var _display = (typeof Exact !== 'undefined' && typeof Exact.inspect === 'function') ? Exact.inspect(_val, {colors: true, compact: true}) : String(_val); if (_display !== null && (typeof _display === 'object' || typeof _display === 'function')) { var _then = _display.then; if (typeof _then === 'function') { return new Promise(function(_resolve, _reject) { try { _then.call(_display, _resolve, _reject); } catch (_error) { _reject(_error); } }).then(_commitDisplay); } } return _commitDisplay(_display);"
}

#[cfg(test)]
fn wrap_inspected_expression(code: &str, async_expression: bool) -> String {
    wrap_inspected_prepared_expression("", code, async_expression)
}

fn wrap_inspected_prepared_expression(
    preamble: &str,
    code: &str,
    async_expression: bool,
) -> String {
    if async_expression {
        format!(
            "(async function() {{ {}\nvar __repl_slot = [ ({}) ]; var _val = __repl_slot[0]; {} }})()",
            preamble,
            code,
            repl_inspect_expression()
        )
    } else {
        format!(
            "(function() {{ var _val = {}; {} }})()",
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
        Ok(validate_repl_input(ctx.input()))
    }
}

fn validate_repl_input(input: &str) -> ValidationResult {
    let mut stack = Vec::new();
    let mut in_string = false;
    let mut string_char = '"';
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut trailing_backslashes = 0usize;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if in_line_comment {
            if c == '\n' {
                in_line_comment = false;
            }
            continue;
        }

        if in_block_comment {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }

        if in_string {
            if c == string_char && trailing_backslashes.is_multiple_of(2) {
                in_string = false;
            }
        } else {
            match c {
                '/' if chars.peek() == Some(&'/') => {
                    chars.next();
                    in_line_comment = true;
                    continue;
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    in_block_comment = true;
                    continue;
                }
                '"' | '\'' | '`' => {
                    in_string = true;
                    string_char = c;
                }
                '(' | '[' | '{' => stack.push(c),
                ')' => {
                    if stack.pop() != Some('(') {
                        return ValidationResult::Invalid(Some("Unmatched )".to_string()));
                    }
                }
                ']' => {
                    if stack.pop() != Some('[') {
                        return ValidationResult::Invalid(Some("Unmatched ]".to_string()));
                    }
                }
                '}' => {
                    if stack.pop() != Some('{') {
                        return ValidationResult::Invalid(Some("Unmatched }".to_string()));
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
        ValidationResult::Incomplete
    } else {
        ValidationResult::Valid(None)
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
    _session_capabilities: &mut HashSet<String>,
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

    let prepared = match ibex_runtime::module_loader::script_frontend::prepare_hybrid_script(
        trimmed,
        Path::new("ibex-repl.ts"),
        "ibex:repl",
        "",
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!("{}: {error:#}", "Error".red().bold());
            return true;
        }
    };
    let (final_code, suppress_output) = render_repl_evaluation(&prepared);

    // The bounded frontend retains the source label but composed session maps
    // remain LLP 0024 work; use the transformed body's offset when available.
    let wrapper_prefix_len = final_code.find(&prepared.body).unwrap_or(0);

    // Use `eval_immediate`, not `eval`: the native eval path already drains
    // microtasks and unwraps/awaits the result Promise before returning (so
    // top-level `await` still resolves), while `eval` additionally drives the
    // event loop to full quiescence. At an interactive prompt that means
    // `setInterval(...)` or `Bun.serve(...)` never return control — the prompt
    // wedges until Ctrl+C. Background work now runs via the idle pump in
    // `start` instead. Node's REPL returns immediately; match that. (ENG-22957,
    // ENG-23001)
    match engine.eval_immediate(&final_code).await {
        Ok(Some(result)) if !suppress_output => {
            println!("{}", result);
        }
        Ok(None) if !suppress_output => {
            println!("{}", "undefined".dimmed());
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!(
                "{}",
                format_repl_error(&e.to_string(), trimmed, wrapper_prefix_len)
            );
        }
    }

    true
}

fn render_repl_evaluation(
    prepared: &ibex_runtime::module_loader::script_frontend::PreparedEvaluation,
) -> (String, bool) {
    let code = if let Some(expression) = prepared.expression.as_deref() {
        wrap_inspected_prepared_expression(
            &prepared.preamble,
            expression,
            prepared.needs_async_wrapper(),
        )
    } else if prepared.needs_async_wrapper() {
        format!(
            "(async () => {{\n{}\n{}\n}})()",
            prepared.preamble, prepared.body
        )
    } else {
        prepared.body.clone()
    };
    (code, prepared.empty_completion)
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
            match prepare_load_source(file) {
                Ok(LoadEvaluation::Json(value)) => {
                    println!("{}", serde_json::to_string_pretty(&value)?);
                }
                Ok(LoadEvaluation::Script(prepared)) => {
                    let code = render_uninspected_evaluation(&prepared, true);
                    match engine.eval_immediate(&code).await {
                        Ok(Some(result)) => println!("{}", result),
                        Ok(None) => println!("{}", "Loaded".green()),
                        Err(e) => eprintln!("{}: {}", "Error".red().bold(), e),
                    }
                }
                Err(error) => eprintln!("{}: {error:#}", "Error".red().bold()),
            }
            Ok(true)
        }
        ".time" => {
            let code = arg.ok_or_else(|| anyhow::anyhow!("Usage: .time <code>"))?;
            let start = std::time::Instant::now();
            let prepared = ibex_runtime::module_loader::script_frontend::prepare_hybrid_script(
                code,
                Path::new("ibex-repl.ts"),
                "ibex:repl:.time",
                "",
            )?;
            let code = render_uninspected_evaluation(&prepared, true);
            // Match the prompt's `eval_immediate` semantics so `.time` cannot
            // wedge on background work (setInterval/servers). (ENG-22957)
            let result = engine.eval_immediate(&code).await;
            let elapsed = start.elapsed();

            match result {
                Ok(Some(result)) => println!("{}", result),
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

enum LoadEvaluation {
    Script(ibex_runtime::module_loader::script_frontend::PreparedEvaluation),
    Json(serde_json::Value),
}

fn prepare_load_source(file: &str) -> Result<LoadEvaluation> {
    // `.load` selects only dialect by extension while retaining Script goal;
    // module-asserting extensions are an explicit refusal, and JSON is the
    // parse-and-display exception.
    // @ref LLP 0024#4-grammar-selection
    let path = PathBuf::from(file);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let path = path
        .canonicalize()
        .with_context(|| format!("Could not resolve .load source {file}"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if file_name.ends_with(".d.ts") {
        anyhow::bail!(
            ".load refuses TypeScript declaration files; import a runtime module instead"
        );
    }
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("Could not read .load source {}", path.display()))?;
    match extension.as_str() {
        "json" => Ok(LoadEvaluation::Json(
            serde_json::from_str(&source)
                .with_context(|| format!("Invalid JSON in {}", path.display()))?,
        )),
        "js" | "jsx" | "ts" | "tsx" => {
            let label = path.to_string_lossy();
            let prepared = ibex_runtime::module_loader::script_frontend::prepare_hybrid_script(
                &source, &path, &label, &label,
            )?;
            Ok(LoadEvaluation::Script(prepared))
        }
        "mjs" | "cjs" | "mts" | "cts" => anyhow::bail!(
            ".load refuses module-kind extension .{extension}; use import() for {}",
            path.display()
        ),
        "" => anyhow::bail!(".load refuses extensionless sources"),
        _ => anyhow::bail!(".load does not recognize extension .{extension}"),
    }
}

fn render_uninspected_evaluation(
    prepared: &ibex_runtime::module_loader::script_frontend::PreparedEvaluation,
    preserve_expression_completion: bool,
) -> String {
    if !prepared.needs_async_wrapper() {
        return prepared.body.clone();
    }
    let body = if preserve_expression_completion {
        prepared
            .expression
            .as_deref()
            .map(|expression| format!("return ({expression});"))
            .unwrap_or_else(|| prepared.body.clone())
    } else {
        prepared.body.clone()
    };
    format!("(async () => {{\n{}\n{}\n}})()", prepared.preamble, body)
}

#[cfg(test)]
mod tests {
    use super::{
        highlight_prompt_text, history_path_in, is_side_effect_free_path, plain_prompt,
        render_repl_evaluation, render_uninspected_evaluation, styled_prompt_with_colors,
        wrap_inspected_expression, LoadEvaluation, DEFAULT_PROMPT_SYMBOL,
    };
    use crate::engine::{
        hermes::{hermes_engine_test_lock, HermesEngine},
        Engine,
    };

    fn uninspected(source: &str) -> String {
        let prepared = ibex_runtime::module_loader::script_frontend::prepare_hybrid_script(
            source,
            std::path::Path::new("ibex-repl.ts"),
            "ibex:repl:test",
            "",
        )
        .expect("prepare REPL fixture");
        render_uninspected_evaluation(&prepared, true)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn minimal_frontend_repl_and_load_run_on_real_hermes() {
        let _guard = hermes_engine_test_lock().lock().await;
        let engine = HermesEngine::new().expect("Hermes should initialize");

        for (label, source) in [
            ("repl-non-tla", "(21 as number) * 2"),
            ("repl-tla", "await Promise.resolve(42 as number)"),
        ] {
            let prepared = ibex_runtime::module_loader::script_frontend::prepare_hybrid_script(
                source,
                std::path::Path::new("ibex-repl.ts"),
                "ibex:repl",
                "",
            )
            .unwrap_or_else(|error| panic!("prepare {label}: {error:#}"));
            let (code, suppress) = render_repl_evaluation(&prepared);
            assert!(!suppress, "{label}");
            let rendered = engine
                .eval_immediate(&code)
                .await
                .unwrap_or_else(|error| panic!("execute {label}: {error:#}"))
                .unwrap_or_else(|| panic!("{label} produced no display value"));
            assert!(rendered.contains("42"), "{label}: {rendered:?}");
        }

        let directory = tempfile::tempdir().expect("load fixture directory");
        for (label, source) in [
            ("load-non-tla", "(21 as number) * 2"),
            ("load-tla", "await Promise.resolve(42 as number)"),
        ] {
            let path = directory.path().join(format!("{label}.ts"));
            std::fs::write(&path, source).expect("write load fixture");
            let prepared = match super::prepare_load_source(path.to_str().unwrap())
                .unwrap_or_else(|error| panic!("prepare {label}: {error:#}"))
            {
                LoadEvaluation::Script(prepared) => prepared,
                LoadEvaluation::Json(_) => panic!("{label} unexpectedly parsed as JSON"),
            };
            assert_eq!(
                engine
                    .eval_immediate(&render_uninspected_evaluation(&prepared, true))
                    .await
                    .unwrap_or_else(|error| panic!("execute {label}: {error:#}"))
                    .as_deref(),
                Some("42"),
                "{label}"
            );
        }
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

    #[test]
    fn inspected_wrappers_materialize_display_before_committing_last_value() {
        for wrapped in [
            wrap_inspected_expression("41 + 1", false),
            wrap_inspected_expression("await Promise.resolve(42)", true),
        ] {
            let conversion = wrapped.find("String(_rendered)").unwrap();
            let commit = wrapped.find("globalThis.$_ = _val").unwrap();
            assert!(
                conversion < commit,
                "final display conversion must precede $_ commit: {wrapped}"
            );
            assert_eq!(wrapped.matches("globalThis.$_ = _val").count(), 1);
        }

        for timed in [
            "41 + 1".to_string(),
            uninspected("await Promise.resolve(42)"),
            uninspected("const answer = await Promise.resolve(42)"),
        ] {
            assert!(
                !timed.contains("globalThis.$_"),
                "timed/uninspected paths must not commit $_: {timed}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hermes_commits_last_value_only_after_display_fully_succeeds() {
        async fn last_value(engine: &HermesEngine) -> String {
            engine
                .eval_immediate("String(globalThis.$_)")
                .await
                .expect("history query should evaluate")
                .expect("history query should return text")
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let engine = HermesEngine::new().expect("Hermes should initialize");

        for formatter in [
            "function() { throw new Error('sync-display-failure'); }",
            "function() { return { toString: function() { throw new Error('string-conversion-failure'); } }; }",
            "function() { return Promise.reject(new Error('promise-display-failure')); }",
            "function() { return { then: function(_resolve, reject) { reject(new Error('thenable-display-failure')); } }; }",
        ] {
            engine
                .eval_immediate(&format!(
                    "globalThis.$_ = 'old'; Object.defineProperty(Exact, 'inspect', {{ value: {formatter}, writable: true, configurable: true }});"
                ))
                .await
                .expect("formatter setup should evaluate");
            let failure = engine
                .eval_immediate(&wrap_inspected_expression("42", false))
                .await;
            assert!(failure.is_err(), "display should fail for {formatter}");
            assert_eq!(last_value(&engine).await, "old");
        }

        engine
            .eval_immediate(
                "Object.defineProperty(Exact, 'inspect', { value: function(value) { return 'sync:' + String(value); }, writable: true, configurable: true });",
            )
            .await
            .expect("sync formatter setup should evaluate");
        let sync_display = engine
            .eval_immediate(&wrap_inspected_expression("43", false))
            .await
            .expect("sync display should evaluate");
        assert_eq!(sync_display.as_deref(), Some("sync:43"));
        assert_eq!(last_value(&engine).await, "43");

        engine
            .eval_immediate(
                "Object.defineProperty(Exact, 'inspect', { value: function(value) { return Promise.resolve('async:' + String(value)); }, writable: true, configurable: true });",
            )
            .await
            .expect("async formatter setup should evaluate");
        let async_display = engine
            .eval_immediate(&wrap_inspected_expression(
                "await Promise.resolve(44)",
                true,
            ))
            .await
            .expect("async display should evaluate");
        assert_eq!(async_display.as_deref(), Some("async:44"));
        assert_eq!(last_value(&engine).await, "44");

        engine
            .eval_immediate("globalThis.$_ = 'timed'")
            .await
            .expect("timed history setup should evaluate");
        engine
            .eval_immediate("45")
            .await
            .expect("non-await timed expression should evaluate");
        assert_eq!(last_value(&engine).await, "timed");
        engine
            .eval_immediate(&uninspected("await Promise.resolve(46)"))
            .await
            .expect("awaited timed expression should evaluate");
        assert_eq!(last_value(&engine).await, "timed");
    }
}
