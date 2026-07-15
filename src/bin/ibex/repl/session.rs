//! Product-neutral REPL input and command state machine.
//!
//! Terminal ownership lives in `terminal_session`; this module only decides
//! when bytes form a submission and which generated command they name. It has
//! no file, environment, evaluator, or terminal escape hatch of its own.
//! @ref LLP 0022#3-input-modes — transcript and interactive presentations use
//! the same grouping and session semantics.
//! @ref LLP 0022#8-commands — generated command classification is the sole
//! dispatcher authority.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::Result;
use capsec_semantics::arming::ArmedExecutionMode;
use ibex_runtime::engine::evaluation::{ParserDialect, SourceGoal, SourceRole};
use ibex_runtime::engine::session_syntax::{
    analyze_source, classify_completeness, Completeness, SyntaxFrontendResult, SyntaxRequest,
};

use crate::repl_surface::{
    classify_command_line, validate_argument, ArgumentError, CommandLine, ReplCommandId, ReplMode,
};
use crate::runtime::ReplEvaluationFailure;
use crate::runtime::ReplMountsDescription;
use ibex_runtime::session_constants::MAX_INPUT_BYTES;

use super::{
    evaluate_loaded_submission, evaluate_repl_submission, evaluate_timed_submission,
    ReplEvaluation, ReplEvaluationSession,
};

const INPUT_SYNTAX: SyntaxRequest = SyntaxRequest {
    dialect: ParserDialect::TypeScript,
    goal: SourceGoal::ScriptWithExtensions,
    role: SourceRole::Entry,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplDiagnostic {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl ReplDiagnostic {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ReplStep {
    Idle,
    Continuation,
    Evaluation {
        source: String,
        result: std::result::Result<ReplEvaluation, ReplEvaluationFailure>,
    },
    TimedEvaluation {
        source: String,
        result: std::result::Result<ReplEvaluation, ReplEvaluationFailure>,
        elapsed: Duration,
    },
    Loaded {
        result: std::result::Result<ReplEvaluation, ReplEvaluationFailure>,
    },
    Help(&'static str),
    Clear,
    Mounts(ReplMountsDescription),
    Exit,
    Diagnostic(ReplDiagnostic),
}

/// Stateful grouping shared by the editor and plain-transcript adapters.
pub(crate) struct ReplDriver {
    mode: ReplMode,
    continuation: String,
    bindings: BTreeSet<String>,
}

impl ReplDriver {
    pub(crate) fn new(mode: ArmedExecutionMode) -> Result<Self> {
        let mode = match mode {
            ArmedExecutionMode::Interactive => ReplMode::Interactive,
            ArmedExecutionMode::Transcript => ReplMode::PlainTranscript,
            _ => anyhow::bail!("REPL driver requires interactive or transcript mode"),
        };
        Ok(Self {
            mode,
            continuation: String::new(),
            bindings: BTreeSet::new(),
        })
    }

    pub(crate) fn is_continuation(&self) -> bool {
        !self.continuation.is_empty()
    }

    pub(crate) fn pending_source(&self) -> &str {
        &self.continuation
    }

    pub(crate) fn abandon_continuation(&mut self) {
        self.continuation.clear();
    }

    /// Handle one strict-UTF-8 input record. The caller owns record framing;
    /// this function inserts only the source newline between continuation rows.
    pub(crate) async fn submit_line(
        &mut self,
        session: &mut ReplEvaluationSession,
        line: &str,
    ) -> ReplStep {
        self.submit_line_with_hook(session, line, |_| {}).await
    }

    /// Submit a line while notifying the supervisor at the exact point a
    /// complete operator submission is accepted. The hook runs before engine
    /// dispatch, so persistent history survives cancellation or process death;
    /// continuation rows are delivered together as one multiline record.
    /// @ref LLP 0025#9-history — history is appended at submission rather than
    /// at evaluation completion or session exit.
    pub(crate) async fn submit_line_with_hook(
        &mut self,
        session: &mut ReplEvaluationSession,
        line: &str,
        mut on_submission: impl FnMut(&str),
    ) -> ReplStep {
        if self.is_continuation() && is_exact_break_command(line) {
            self.continuation.clear();
            on_submission(line);
            return ReplStep::Idle;
        }

        if !self.is_continuation() {
            match classify_command_line(line) {
                CommandLine::Known { command, argument } => {
                    on_submission(line);
                    if !command.modes.contains(&self.mode) {
                        return ReplStep::Diagnostic(ReplDiagnostic::new(
                            "repl-command-mode",
                            format!("{} is unavailable in this REPL mode", command.name),
                        ));
                    }
                    if let Err(error) = validate_argument(command, argument) {
                        let detail = match error {
                            ArgumentError::Missing => "missing required argument",
                            ArgumentError::Unexpected => "unexpected argument",
                        };
                        return ReplStep::Diagnostic(ReplDiagnostic::new(
                            "repl-command-argument",
                            format!("{detail}; usage: {}", command.usage),
                        ));
                    }
                    return self.execute_command(session, command.id, argument).await;
                }
                CommandLine::Unknown { name } => {
                    on_submission(line);
                    return ReplStep::Diagnostic(ReplDiagnostic::new(
                        "repl-unknown-command",
                        format!("unknown command {name}; type .help for help"),
                    ));
                }
                CommandLine::JavaScript => {}
            }
        }

        if self.continuation.is_empty() && line.trim().is_empty() {
            return ReplStep::Idle;
        }
        if !self.continuation.is_empty() {
            self.continuation.push('\n');
        }
        self.continuation.push_str(line);
        if self.continuation.len() > MAX_INPUT_BYTES {
            let source = std::mem::take(&mut self.continuation);
            on_submission(&source);
            return ReplStep::Diagnostic(ReplDiagnostic::new(
                "repl-input-too-large",
                format!("input exceeds the {MAX_INPUT_BYTES}-byte session limit"),
            ));
        }

        match classify_completeness(INPUT_SYNTAX, &self.continuation) {
            Completeness::Incomplete { .. } => ReplStep::Continuation,
            // A definite syntax error is still a submitted evaluation. The
            // authenticated evaluator owns its `repl:<n>` diagnostic and must
            // consume that ordinal just like any other submitted source.
            Completeness::Complete | Completeness::SyntaxError(_) => {
                let source = std::mem::take(&mut self.continuation);
                on_submission(&source);
                let outline = parser_tracked_bindings(&source);
                let result = evaluate_repl_submission(session, &source).await;
                if accepted_for_binding_tracking(&result) {
                    self.bindings.extend(outline);
                }
                ReplStep::Evaluation { source, result }
            }
        }
    }

    pub(crate) fn finish_transcript(&mut self) -> ReplStep {
        if self.continuation.is_empty() {
            ReplStep::Idle
        } else {
            self.continuation.clear();
            ReplStep::Diagnostic(ReplDiagnostic::new(
                "repl-incomplete-eof",
                "end of input while a REPL submission was incomplete",
            ))
        }
    }

    /// Advisory candidates from generated/static facts only. This never calls
    /// the engine and deliberately returns no member candidates in v1.
    pub(crate) fn completion_candidates(&self, line: &str, cursor: usize) -> Vec<String> {
        let cursor = cursor.min(line.len());
        if !line.is_char_boundary(cursor) {
            return Vec::new();
        }
        let prefix_start = line[..cursor]
            .char_indices()
            .rev()
            .find(|(_, ch)| !is_identifier_character(*ch) && *ch != '.' && *ch != ':')
            .map_or(0, |(offset, ch)| offset + ch.len_utf8());
        let prefix = &line[prefix_start..cursor];
        if prefix.contains('.') && !prefix.starts_with('.') && !prefix.starts_with("node:") {
            return Vec::new();
        }

        let mut candidates = BTreeSet::new();
        if prefix.starts_with('.') {
            candidates.extend(
                crate::repl_surface::COMMAND_COMPLETIONS
                    .iter()
                    .filter(|candidate| candidate.starts_with(prefix))
                    .map(|candidate| (*candidate).to_owned()),
            );
        } else {
            candidates.extend(
                self.bindings
                    .iter()
                    .filter(|candidate| candidate.starts_with(prefix))
                    .cloned(),
            );
            candidates.extend(
                ibex_runtime::module_loader::builtin_module_debug_entries()
                    .iter()
                    .map(|entry| entry.specifier)
                    .filter(|candidate| candidate.starts_with(prefix))
                    .map(str::to_owned),
            );
        }
        candidates.into_iter().collect()
    }

    async fn execute_command(
        &mut self,
        session: &mut ReplEvaluationSession,
        command: ReplCommandId,
        argument: &str,
    ) -> ReplStep {
        match command {
            ReplCommandId::Help => ReplStep::Help(crate::repl_surface::REPL_HELP_TEXT),
            ReplCommandId::Exit => ReplStep::Exit,
            ReplCommandId::Clear => ReplStep::Clear,
            ReplCommandId::Load => ReplStep::Loaded {
                result: evaluate_loaded_submission(session, argument).await,
            },
            ReplCommandId::Time => {
                let (result, elapsed) = evaluate_timed_submission(session, argument).await;
                ReplStep::TimedEvaluation {
                    source: argument.to_owned(),
                    result,
                    elapsed,
                }
            }
            ReplCommandId::Break => {
                self.continuation.clear();
                ReplStep::Idle
            }
            ReplCommandId::Mounts => match session.mounts_description().await {
                Ok(description) => ReplStep::Mounts(description),
                Err(error) => ReplStep::Diagnostic(ReplDiagnostic::new(
                    "repl-mounts-failed",
                    format!("failed to obtain authenticated mount table: {error:#}"),
                )),
            },
        }
    }
}

fn is_exact_break_command(line: &str) -> bool {
    matches!(
        classify_command_line(line),
        CommandLine::Known {
            command,
            argument: ""
        } if command.id == ReplCommandId::Break
    )
}

fn is_identifier_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '$' | '/' | '-')
}

fn parser_tracked_bindings(source: &str) -> Vec<String> {
    let Ok(result) = analyze_source(INPUT_SYNTAX, source) else {
        return Vec::new();
    };
    let outline = match result {
        SyntaxFrontendResult::Ready(analysis) => Some(analysis.outline),
        SyntaxFrontendResult::UnsupportedGoal(unsupported) => unsupported.outline,
    };
    outline
        .into_iter()
        .flat_map(|outline| outline.declarations)
        .map(|declaration| declaration.name)
        .collect()
}

fn accepted_for_binding_tracking(
    result: &std::result::Result<ReplEvaluation, ReplEvaluationFailure>,
) -> bool {
    matches!(
        result,
        Ok(ReplEvaluation::Empty)
            | Ok(ReplEvaluation::Value { .. })
            | Ok(ReplEvaluation::Throw(_))
            | Ok(ReplEvaluation::Lifecycle(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_break_is_the_only_continuation_command_escape() {
        assert!(is_exact_break_command(".break"));
        assert!(is_exact_break_command("  .break"));
        assert!(!is_exact_break_command(".break now"));
        assert!(!is_exact_break_command(".help"));
        assert!(!is_exact_break_command(".unknown"));
    }

    #[test]
    fn parser_tracking_never_evaluates_and_extracts_declared_names() {
        let names = parser_tracked_bindings("let alpha: number = 1; function beta() {};");
        assert!(names.contains(&"alpha".to_owned()));
        assert!(names.contains(&"beta".to_owned()));
    }

    #[test]
    fn eof_discards_incomplete_input_with_a_recoverable_diagnostic() {
        let mut driver = ReplDriver {
            mode: ReplMode::PlainTranscript,
            continuation: "function f() {".to_owned(),
            bindings: BTreeSet::new(),
        };
        assert!(matches!(
            driver.finish_transcript(),
            ReplStep::Diagnostic(ReplDiagnostic {
                code: "repl-incomplete-eof",
                ..
            })
        ));
        assert!(!driver.is_continuation());
    }

    #[test]
    fn completion_uses_only_generated_commands_static_builtins_and_tracked_names() {
        let mut driver = ReplDriver {
            mode: ReplMode::Interactive,
            continuation: String::new(),
            bindings: BTreeSet::from(["answer".to_owned()]),
        };
        assert_eq!(
            driver.completion_candidates(".he", 3),
            vec![".help".to_owned()]
        );
        assert_eq!(
            driver.completion_candidates("ans", 3),
            vec!["answer".to_owned()]
        );
        assert!(driver
            .completion_candidates("node:f", 6)
            .iter()
            .any(|candidate| candidate == "node:fs"));
        assert!(driver.completion_candidates("object.pro", 10).is_empty());

        // A candidate list has no engine/effect handle and is deterministic.
        driver.bindings.insert("another".to_owned());
        assert_eq!(
            driver.completion_candidates("an", 2),
            vec!["another".to_owned(), "answer".to_owned()]
        );
    }
}
