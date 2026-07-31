/**
 * Validate LLP 0022's authenticated-code-ingress obligation dataset.
 *
 * The coverage registry can record only a non-capability rationale on an
 * ingress edge. This checked join carries the mechanism obligations that make
 * that classification true and pins each obligation to reviewed source bytes.
 *
 * @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry — an
 * authenticated ingress needs checked session, attribution, provenance, and
 * refusal obligations rather than a rationale string alone.
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const PROFILE = "ibex/capsec/1";
const DATASET_SCHEMA = "ibex/capsec-ingress-obligations/1";
export const AUTHENTICATED_CODE_INGRESS_RATIONALE =
  "authenticated-code-ingress";

function freezeEvidence(pathname, tokens) {
  return Object.freeze({
    path: pathname,
    tokens: Object.freeze(tokens),
  });
}

// This is a normative closed contract, independent of the registry dataset.
// Adding or weakening an obligation therefore requires an intentional code and
// data review rather than silently changing one handwritten projection.
export const REQUIRED_INGRESS_OBLIGATIONS = Object.freeze([
  Object.freeze({
    id: "armed-session-bound",
    assertion:
      "Submission requires an armed runtime whose named shared-runtime global seal and bootstrap finalization completed and whose exact opaque session token has already been bound.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/hermes_runtime.cc", [
        "if (!runtime->armed) {",
        'extern "C" uint32_t ex_hermes_seal_armed_shared_runtime_globals_v1(',
        "runtime->armed_shared_runtime_globals_sealed = true;",
        "if (!runtime->armed_shared_runtime_globals_sealed) {",
        "if (runtime->armed_bootstrap_eval_open) {",
        "runtime->structured_session_bound = true;",
        "if (!runtime->structured_session_bound) {",
        "EX_HERMES_EVAL_FAULT_SESSION_NOT_BOUND",
        "credential->session_token",
      ]),
    ]),
  }),
  Object.freeze({
    id: "bare-eval-post-bootstrap-refused",
    assertion:
      "Finishing armed bootstrap irreversibly seals the bare evaluator, and later armed project-source calls through ex_hermes_eval are refused.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/hermes_runtime.cc", [
        "extern \"C\" uint32_t ex_hermes_finish_bootstrap(",
        "runtime->armed_bootstrap_eval_open = false;",
        "if (runtime->armed &&",
        "!runtime->armed_bootstrap_eval_open",
        "Hermes bare evaluation is sealed for armed project source",
      ]),
    ]),
  }),
  Object.freeze({
    id: "checked-native-module-graph",
    assertion:
      "Advertised direct-file module graphs consume the exact structured admission before Host graph discovery or lowering; the engine centrally rejoins every returned native graph to the admitted snapshot, principal, VFS SourceId, source integrity, and grammar; prepared-cache discovery requires the opaque result of that join; and execution either begins with that graph or continues the bounded session-lowering fallback with the same admission and argv.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/bin/ibex/runtime.rs", [
        ".evaluate_authenticated_module_graph(",
        "Box::new(|admitted_request|",
        "self.prepare_authenticated_module_graph(admitted_request)",
        "build_authenticated_source_graph_v1_for_host(",
        "graph.validate_authenticated_entry_request(request)?",
        "let entry_join = graph.validate_authenticated_entry_request(request)?;",
        "load_authenticated_prepared_module_graph(&source_entry, &graph, &entry_join)",
      ]),
      freezeEvidence("src/module_loader/runner_pipeline.rs", [
        "pub fn validate_authenticated_entry_request(",
        "verify_record(record, &self.producer_binary_digest)?.artifact()",
        "self.entry_vfs_source_id.as_ref() != request.source_id()",
        "self.snapshot.digest() != request.authenticated_snapshot_digest()",
        "entry_artifact.semantics.source_integrity != *request.source_digest()",
        "entry_artifact.semantics.source_goal != expected_goal",
        "entry_artifact.semantics.dialect != Some(expected_dialect)",
        "pub fn load_prepared_source_graph_v1(",
        "entry_join: &AuthenticatedEntryJoinV1,",
        "prepared graph entry join does not authenticate this source graph",
        "let index_bytes = read_authenticated_prepared_file(",
      ]),
      freezeEvidence("src/bin/ibex/engine/hermes.rs", [
        "admit_prepare_authenticated_module_graph(raw.cast(), session, request, |request|",
        ".validate_authenticated_entry_request(request)",
        "authenticated module graph does not belong to its admitted request",
      ]),
      freezeEvidence("src/engine/hermes_structured.rs", [
        "pub unsafe fn admit_prepare_authenticated_module_graph<T, F>(",
        "let mut admission = unsafe { admit_authenticated_submission(runtime, session, &mut request)? };",
        "let preparation = match prepare(&request) {",
        "ex_hermes_structured_module_graph_begin(",
        "evaluate_authenticated_inner_with_admission(request, None, admission)",
      ]),
      freezeEvidence("src/engine/hermes_runtime.cc", [
        "extern \"C\" uint32_t ex_hermes_structured_submission_admit(",
        "extern \"C\" uint32_t ex_hermes_structured_module_graph_begin(",
        "structuredAdmittedCredentialMatches(runtime, credential)",
        "runtime->structured_module_graph_work_target_id = workTargetId;",
      ]),
    ]),
  }),
  Object.freeze({
    id: "checked-session-lowering",
    assertion:
      "Authenticated Program requests cross the exact native submission boundary before syntax/lowering, so parse failures consume their ordinal; the checked AST pipeline and native lowered-session ABI then compile and preflight the complete declaration plan before mutating persistent session state.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/hermes_structured.rs", [
        "SourceRequest::Program(program) => lower_program(",
        "SESSION_LOWERING_PROTOCOL_VERSION",
        "ex_hermes_eval_lowered_session(",
        "let declarations = lowered",
        ".declarations()",
        "lowered.source_map()",
      ]),
      freezeEvidence("src/engine/session_lowering.rs", [
        "pub fn lower_program(",
        "analyze_source(syntax_request, source)?",
        "reject_closed_dynamic_code_in_program(program, unresolved_ctxt)?;",
        "ReferenceLowering",
      ]),
      freezeEvidence("src/engine/hermes_runtime.cc", [
        "extern \"C\" uint32_t ex_hermes_structured_submission_admit(",
        "This is the submission boundary:",
        "extern \"C\" int ex_hermes_eval_lowered_session(",
        "clearStructuredAdmittedSubmission(runtime);",
        "auto prepared = runtime->runtime->prepareJavaScript(sourceBuffer, label);",
        "structuredDeclarationPlanFeasibility(runtime, plan)",
        "beginStructuredSessionTransaction(runtime, plan);",
      ]),
    ]),
  }),
  Object.freeze({
    id: "endowments-projected",
    assertion:
      "The endowment projection comes from authenticated armed-session state and its digest is included in the opaque request binding.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/evaluation.rs", [
        "endowment_projection_digest: Digest,",
        "pub(crate) fn from_authenticated_snapshot(",
        "submission\n            .session\n            .0\n            .endowment_projection_digest",
      ]),
    ]),
  }),
  Object.freeze({
    id: "exact-ordinal-required",
    assertion:
      "The consumer accepts only the session's exact next nonzero ordinal and consumes it before evaluation so later faults cannot make it reusable.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/evaluation.rs", [
        "next_ordinal: Option<NonZeroU64>,",
        "state.in_flight = Some(ordinal);",
      ]),
      freezeEvidence("src/engine/hermes_runtime.cc", [
        "const uint64_t expectedOrdinal =",
        "credential->ordinal > expectedOrdinal",
        "EX_HERMES_EVAL_FAULT_WRONG_ORDINAL",
        "runtime->next_structured_submission_ordinal =",
        "This is the submission boundary:",
      ]),
    ]),
  }),
  Object.freeze({
    id: "file-argv-bound",
    assertion:
      "Direct-file argv is derived from the armed virtual file identity with a fixed runtime/entry prefix; only trailing arguments remain operator data, and the complete projection is covered by the opaque request binding.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/evaluation.rs", [
        "pub fn mint_file(",
        "self.require_route(EntryKind::File, &[ExecutionMode::Program])?;",
        "let virtual_path = virtual_path_from_file_identity(&self.session.0.entry_identity)?;",
        "arguments.push(Arc::<str>::from(\"ibex:runtime\"));",
        "arguments.push(virtual_path);",
        "arguments.extend(user_arguments.iter().cloned());",
        "match &submission.file_arguments {",
        "hash_field(&mut hash, b\"file-arguments\");",
        "hash_field(&mut hash, argument.as_bytes());",
        "pub fn authenticated_file_virtual_path(&self) -> Option<&str>",
      ]),
    ]),
  }),
  Object.freeze({
    id: "file-program-adapter-bound",
    assertion:
      "Direct-file execution selects only the authenticated File/Program route; its native file adapter retains descriptor capture, a readiness lease, and exact evaluator cancellation across Runtime construction and settlement, while Runtime claims the closed AuthenticatedFileIngress before evaluation.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/bin/ibex/main.rs", [
        "(ArmedEntryKind::File, ArmedExecutionMode::Program) => {",
        "Some(AuthenticatedProductIngress::FileProgram)",
        "async fn run_file_with_execution_adapter(",
        "authenticated_product_ingress(session_io.route)",
        "FileProgramExecutionAdapter::new(session_io)",
        ".run_with_diagnostics_and_interrupt(|diagnostics, interrupt_cancellation| {",
        "interrupt_cancellation,",
      ]),
      freezeEvidence("src/bin/ibex/terminal_session.rs", [
        "pub struct FileProgramExecutionAdapter",
        "pub fn new(plan: SessionIoPlan)",
        "let mut active = ActiveFileProgramCapture::start(self.plan)?;",
        "DirectExecutionInterruptCoordinator::install(",
        "let diagnostics = active.diagnostic_port();",
        "let readiness = mint_execution_adapter_ready(&mut active.lease, active.plan.route);",
        "let mut execution = Box::pin(build(diagnostics, cancellation));",
        "let report = active.finish();",
      ]),
      freezeEvidence("src/bin/ibex/runtime.rs", [
        "pub(crate) async fn run_authenticated_file_program(",
        "let mut ingress = self.authenticated_file_ingress()?;",
        "pub(crate) fn authenticated_file_ingress(&self) -> Result<AuthenticatedFileIngress>",
        ".evaluate(self.engine.as_ref(), args)",
      ]),
    ]),
  }),
  Object.freeze({
    id: "file-vfs-source-bound",
    assertion:
      "Direct-file ingress reconstructs its namespace entry only from the armed file identity, rechecks the exact session, principal, referrer, shape, and canonical label before lookup, then binds the typed VFS read evidence, final SourceId, and immutable bytes into the same linear submission.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/bin/ibex/runtime.rs", [
        ".resolve_root_file_url(armed_entry.identity.as_str(), None)",
        "fn file_request(",
        "let referrer = self.entry.logical_referrer()?;",
        ".mint_file(referrer, user_arguments)?;",
        ".authenticated_vfs_file_read(&self.vfs, self.entry.clone(), submission)?;",
        "read.source_id().is_some()",
        "read.into_capsule()",
        ".into_request()",
      ]),
      freezeEvidence("src/host/mod.rs", [
        "pub fn authenticated_vfs_file_read(",
        "AuthenticatedVfsSourceRoute::FileModule",
        "if !submission.authenticates_for(&host_session) {",
        ".is_canonical_file_for(namespace.virtual_path(), requested_source_label.as_str())",
        "fn read_authenticated_vfs(",
        "vfs.read_authenticated(namespace, source_use, |stage| {",
        "let read = self.read_authenticated_vfs(vfs, namespace, source_use, \"0\", None)?;",
        ".with_authenticated_file_source(",
        ".with_authenticated_referrer(logical_referrer.clone())",
        ".authorize_typed_read(typed_read_evidence);",
        "authorized.bind_module_bytes(bytes, source_id.clone())",
      ]),
    ]),
  }),
  Object.freeze({
    id: "implicit-route-derived",
    assertion:
      "Implicit no-file dispatch uses the immutable pre-arming session route to select exactly program stdin or the REPL and never re-probes fd 0 after snapshot construction.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/bin/ibex/main.rs", [
        "let session_io = terminal_session::SessionIoPlan::capture_for_cli(&cli);",
        "session_io.context(\"implicit session route has no terminal session plan\")?;",
        "pub(crate) const fn authenticated_product_ingress(",
        "match (route.entry_kind, route.mode)",
        "Some(AuthenticatedProductIngress::WorkerProgram)",
        "Some(AuthenticatedProductIngress::WorkerRepl)",
        "match authenticated_product_ingress(plan.route)",
        "run_stdin_program(&cli, plan).await",
        "start_repl(&cli, plan).await",
      ]),
    ]),
  }),
  Object.freeze({
    id: "inline-session-adapter-bound",
    assertion:
      "One-shot and program-stdin bytes cross only the runtime's route-matched AuthenticatedInlineIngress while the native output broker, readiness lease, lifecycle port, and exact session remain live through settlement.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/bin/ibex/terminal_session.rs", [
        "pub(crate) async fn run_authenticated_inline_execution_adapter(",
        "let mut ingress = runtime.authenticated_inline_ingress()?;",
        "if ingress.entry_kind() != plan.route.entry_kind || ingress.mode() != plan.route.mode",
        "let mut active = ActiveReplCapture::start(plan, None)",
        "let readiness = mint_execution_adapter_ready(&mut active.lease, plan.route);",
        "let evaluation = ingress.evaluate(engine.as_ref(), source).await;",
        "settle_authenticated_inline_evaluation(",
      ]),
      freezeEvidence("src/bin/ibex/runtime.rs", [
        "pub(crate) struct AuthenticatedInlineIngress",
        "pub(crate) fn authenticated_inline_ingress(&self) -> Result<AuthenticatedInlineIngress>",
        "AuthenticatedInlineIngress::from_armed_runtime(self.host.clone(), session_io)",
      ]),
    ]),
  }),
  Object.freeze({
    id: "javascript-origin-refused",
    assertion:
      "JavaScript cannot construct or obtain the private authenticated submission and native credential required by the session evaluator.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/evaluation.rs", [
        "This value has no public constructor.",
        "pub(crate) struct AuthenticatedSubmission",
        "fn new(",
        "pub(crate) struct NativeCredentialView",
        "pub(crate) fn native_credential_for<'a>(",
        "if !self.authenticates_for(session) {",
      ]),
      freezeEvidence("include/exact_runtime.h", [
        "Tokens are exact-length binary values and are never",
        "exposed to JavaScript.",
      ]),
    ]),
  }),
  Object.freeze({
    id: "load-vfs-source-bound",
    assertion:
      "The .load route mints only a generated-classifier shape, rechecks the exact session, root, referrer, and canonical load shape before VFS lookup, authorizes the staged virtual identity, and binds the canonical final referrer plus bounded immutable bytes and read-evidence digest into that same linear submission before authenticated evaluation.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/bin/ibex/repl/mod.rs", [
        "async fn evaluate_loaded_submission(",
        ".evaluate_load(engine.as_ref(), virtual_path)",
      ]),
      freezeEvidence("src/bin/ibex/runtime.rs", [
        "fn load_request(",
        "mint_load(",
        "authenticated_vfs_script_read(",
        ".evaluate_authenticated(",
      ]),
      freezeEvidence("src/engine/evaluation.rs", [
        "pub fn mint_load(",
        "let shape = canonical_load_shape(&virtual_path)?;",
        "crate::repl_surface::classify_load_path(virtual_path)",
        "SourceRefusal::LoadedOriginRequiresClassifier",
      ]),
      freezeEvidence("src/host/mod.rs", [
        "if !submission.authenticates_for(&host_session) {",
        "if namespace.caller() != vfs.root_principal() {",
        "submission.is_canonical_load_for(namespace.virtual_path())",
        "fn read_authenticated_vfs(",
        "vfs.read_authenticated(namespace, source_use, |stage| {",
        "let read = self.read_authenticated_vfs(vfs, namespace, source_use, \"0\", None)?;",
        ".with_authenticated_referrer(logical_referrer.clone())",
        ".authorize_typed_read(typed_read_evidence);",
      ]),
      freezeEvidence("src/vfs/mod.rs", [
        "let requested = authorize(ReadAuthorization::Requested(&namespace))?;",
        ".take(crate::session_constants::MAX_INPUT_BYTES as u64 + 1);",
        "if bytes.len() > crate::session_constants::MAX_INPUT_BYTES {",
        "let content_digest = digest_bytes(b\"ibex/vfs-content/1\\0\", &bytes);",
        "let evidence_digest = digest_read_evidence(",
      ]),
    ]),
  }),
  Object.freeze({
    id: "product-route-plan-bound",
    assertion:
      "Every admitted product session route constructs its Runtime from the same SessionIoPlan captured before production validation and delegates source execution to a closed authenticated adapter.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/bin/ibex/main.rs", [
        "let session_io = terminal_session::SessionIoPlan::capture_for_cli(&cli);",
        "async fn run_file(",
        "async fn run_file_with_execution_adapter(",
        "async fn eval_code(",
        "async fn run_stdin_program(",
        "async fn start_repl(",
        "runtime::Runtime::from_cli_with_session(&effective_cli, session_io)?;",
        "runtime::Runtime::from_cli_with_session(cli, session_io)?;",
        "FileProgramExecutionAdapter::new(session_io)",
        "terminal_session::run_authenticated_inline_execution_adapter(",
        "let status = repl::start_worker(cli, session_io).await?;",
      ]),
    ]),
  }),
  Object.freeze({
    id: "repl-session-adapter-bound",
    assertion:
      "Interactive and transcript REPL input reaches only the Runtime-bound ReplSessionIngress while the native descriptor broker, exact cancellation port, lifecycle state, and readiness lease remain live.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/bin/ibex/repl/mod.rs", [
        "pub(crate) enum ReplEvaluationSession",
        "ingress: runtime.repl_session_ingress()?",
        ".evaluate_inline(engine.as_ref(), input.as_bytes().to_vec())",
        "crate::terminal_session::run_repl_execution_adapter(plan, session, driver, history).await",
      ]),
      freezeEvidence("src/bin/ibex/terminal_session.rs", [
        "async fn run_repl_unix(",
        "if !session.cancellation_port().is_available()",
        "let mut active = ActiveReplCapture::start(plan, worker_relays)",
        "let readiness = mint_execution_adapter_ready(&mut active.lease, plan.route);",
        "run_interactive_repl(",
        "run_plain_repl(&mut session, &mut driver, broker, &mut settlement_damage).await",
      ]),
    ]),
  }),
  Object.freeze({
    id: "replay-refused",
    assertion:
      "A credential whose ordinal is lower than the session's exact next ordinal is refused as a submission replay before source executes.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/hermes_runtime.cc", [
        "credential->ordinal < expected_ordinal",
        "EX_HERMES_EVAL_FAULT_SUBMISSION_REPLAY",
      ]),
    ]),
  }),
  Object.freeze({
    id: "request-bytes-bound",
    assertion:
      "The opaque request binding includes the exact source-byte digest and is recomputed from retained bytes and request shape before native credentials are exposed.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/evaluation.rs", [
        "bytes_digest: sha256_digest(&bytes),",
        "let actual_bytes_digest = sha256_digest(self.text().as_bytes());",
        "common.bytes_digest == actual_bytes_digest",
        "credential_binding_from_request(self, &actual_bytes_digest)",
        "hash_field(&mut hash, bytes_digest.as_str().as_bytes());",
      ]),
      freezeEvidence("src/engine/hermes_runtime.cc", [
        "credential->request_binding",
        "EX_HERMES_REQUEST_BINDING_LENGTH",
      ]),
    ]),
  }),
  Object.freeze({
    id: "root-attribution-derived",
    assertion:
      "Root attribution is derived while constructing the authenticated armed session, retained in the request, and covered by the opaque binding.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/evaluation.rs", [
        "derived (rather than accepted) the root/session fields.",
        "pub(crate) fn from_authenticated_snapshot(",
        "root_principal: Principal,",
        "pub fn authenticated_principal(&self) -> &Principal",
        "&serde_json::to_vec(&submission.session.0.root_principal)",
      ]),
    ]),
  }),
  Object.freeze({
    id: "source-goal-derived",
    assertion:
      "The session-selected source shape and goal are retained in the closed request and included when the native credential binding is recomputed.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/evaluation.rs", [
        "shape: SourceShape,",
        "match self.submission.shape {",
        "SourceShape::Program {",
        "match goal {",
        "SourceGoal::ScriptWithExtensions => b\"script-with-extensions\"",
      ]),
    ]),
  }),
  Object.freeze({
    id: "synthetic-source-label-derived",
    assertion:
      "The session sequence derives the synthetic source label from origin and ordinal, and the label is included in the opaque request binding.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/evaluation.rs", [
        "SubmissionOrigin::Repl => (SourceLabel::repl(ordinal), None)",
        "SourceLabel::loaded(ordinal, &virtual_path)?",
        "SubmissionOrigin::Stdin => (SourceLabel::stdin(), None)",
        "SubmissionOrigin::Eval => (SourceLabel::eval(), None)",
        "hash_field(&mut hash, submission.label.as_str().as_bytes());",
      ]),
    ]),
  }),
  Object.freeze({
    id: "time-same-authenticated-submission",
    assertion:
      "The .time route is only an observation wrapper: it delegates the unchanged input to the same authenticated REPL submission function and times that result instead of opening an evaluator or minting a second credential path.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/bin/ibex/repl/mod.rs", [
        "async fn evaluate_timed_submission(",
        "evaluate_repl_submission(session, input).await",
      ]),
    ]),
  }),
  Object.freeze({
    id: "wrong-session-refused",
    assertion:
      "An equal-looking or differently bound session cannot authenticate the request, and a token mismatch is refused before source executes.",
    sourceEvidence: Object.freeze([
      freezeEvidence("src/engine/evaluation.rs", [
        "Arc::ptr_eq(&self.0, &other.0)",
        "common.session.same_session(session)",
      ]),
      freezeEvidence("src/engine/hermes_runtime.cc", [
        "runtime->structured_session_token.data()",
        "credential->session_token",
        "EX_HERMES_EVAL_FAULT_WRONG_SESSION",
      ]),
    ]),
  }),
]);

export const REQUIRED_INGRESS_SUPPORTING_SURFACES = Object.freeze([
  Object.freeze({
    role: "bootstrap-seal",
    edgeId: "surface.host.abi.ex.hermes.finish.bootstrap.11ahb91",
    surface: Object.freeze({
      kind: "host-abi",
      name: "ex_hermes_finish_bootstrap",
    }),
    classification: "non-capability",
    rationaleId: "runtime-bootstrap-state",
  }),
  Object.freeze({
    role: "diagnostic-evaluator",
    edgeId:
      "surface.host.abi.ex.hermes.eval.structured.diagnostic.1viduch",
    surface: Object.freeze({
      kind: "host-abi",
      name: "ex_hermes_eval_structured_diagnostic",
    }),
    classification: "closed",
    cap: "vm:evaluate",
  }),
  Object.freeze({
    role: "session-binding",
    edgeId:
      "surface.host.abi.ex.hermes.structured.session.bind.0o0sk2j",
    surface: Object.freeze({
      kind: "host-abi",
      name: "ex_hermes_structured_session_bind",
    }),
    classification: "non-capability",
    rationaleId: "authority-control-plane",
  }),
  Object.freeze({
    role: "shared-runtime-global-seal",
    edgeId:
      "surface.host.abi.ex.hermes.seal.armed.shared.runtime.globals.v1.1gs1iq6",
    surface: Object.freeze({
      kind: "host-abi",
      name: "ex_hermes_seal_armed_shared_runtime_globals_v1",
    }),
    classification: "non-capability",
    rationaleId: "runtime-bootstrap-state",
  }),
  Object.freeze({
    role: "submission-admission",
    edgeId:
      "surface.host.abi.ex.hermes.structured.submission.admit.1hsgiyn",
    surface: Object.freeze({
      kind: "host-abi",
      name: "ex_hermes_structured_submission_admit",
    }),
    classification: "non-capability",
    rationaleId: "terminal-session-control",
  }),
  Object.freeze({
    role: "submission-settlement",
    edgeId:
      "surface.host.abi.ex.hermes.structured.submission.settle.1hj4fkx",
    surface: Object.freeze({
      kind: "host-abi",
      name: "ex_hermes_structured_submission_settle",
    }),
    classification: "non-capability",
    rationaleId: "terminal-session-control",
  }),
  Object.freeze({
    role: "unauthenticated-bare-evaluator",
    edgeId: "surface.host.abi.ex.hermes.eval.1t7nlsx",
    surface: Object.freeze({ kind: "host-abi", name: "ex_hermes_eval" }),
    classification: "closed",
    cap: "vm:evaluate",
  }),
]);

const COMMON_INGRESS_OBLIGATION_IDS = Object.freeze([
  "armed-session-bound",
  "bare-eval-post-bootstrap-refused",
  "endowments-projected",
  "exact-ordinal-required",
  "javascript-origin-refused",
  "replay-refused",
  "request-bytes-bound",
  "root-attribution-derived",
  "source-goal-derived",
  "synthetic-source-label-derived",
  "wrong-session-refused",
]);

function obligationProfile(...specific) {
  return Object.freeze(
    [...COMMON_INGRESS_OBLIGATION_IDS, ...specific].sort(compareText),
  );
}

function fileObligationProfile(...specific) {
  return Object.freeze(
    [
      ...COMMON_INGRESS_OBLIGATION_IDS.filter(
        (id) => id !== "synthetic-source-label-derived",
      ),
      ...specific,
    ].sort(compareText),
  );
}

// This list is independent of both the scanned coverage edges and the authored
// dataset. A route disappearing from both inputs is therefore still a hard
// totality failure instead of a self-consistent omission.
export const REQUIRED_AUTHENTICATED_INGRESS_ROUTES = Object.freeze([
  "cli:authenticated-direct-file-ingress",
  "cli:authenticated-one-shot-ingress",
  "cli:authenticated-program-stdin-ingress",
  "cli:authenticated-repl-ingress",
  "cli:implicit-no-file-dispatch",
  "cli:repl-command:load",
  "cli:repl-command:time",
  "host-abi:ex_hermes_eval_lowered_session",
  "host-abi:ex_hermes_eval_structured_session",
  "host-abi:ex_hermes_structured_module_graph_begin",
]);

// Each authenticated edge has an exact, closed profile. CLI routes inherit the
// complete native-ingress chain and add the route-specific proof which makes
// their delegation non-bypassable; unknown future routes fail closed.
export const REQUIRED_INGRESS_ROW_PROFILES = Object.freeze({
  "cli:authenticated-direct-file-ingress": fileObligationProfile(
    "checked-native-module-graph",
    "checked-session-lowering",
    "file-argv-bound",
    "file-program-adapter-bound",
    "file-vfs-source-bound",
    "product-route-plan-bound",
  ),
  "cli:authenticated-one-shot-ingress": obligationProfile(
    "checked-session-lowering",
    "inline-session-adapter-bound",
    "product-route-plan-bound",
  ),
  "cli:authenticated-program-stdin-ingress": obligationProfile(
    "checked-session-lowering",
    "inline-session-adapter-bound",
    "product-route-plan-bound",
  ),
  "cli:authenticated-repl-ingress": obligationProfile(
    "checked-session-lowering",
    "product-route-plan-bound",
    "repl-session-adapter-bound",
  ),
  "cli:implicit-no-file-dispatch": obligationProfile(
    "checked-session-lowering",
    "implicit-route-derived",
    "inline-session-adapter-bound",
    "product-route-plan-bound",
    "repl-session-adapter-bound",
  ),
  "cli:repl-command:load": obligationProfile(
    "checked-session-lowering",
    "load-vfs-source-bound",
    "repl-session-adapter-bound",
  ),
  "cli:repl-command:time": obligationProfile(
    "checked-session-lowering",
    "repl-session-adapter-bound",
    "time-same-authenticated-submission",
  ),
  "host-abi:ex_hermes_eval_lowered_session": obligationProfile(
    "checked-session-lowering",
  ),
  "host-abi:ex_hermes_eval_structured_session": obligationProfile(),
  "host-abi:ex_hermes_structured_module_graph_begin": fileObligationProfile(
    "checked-native-module-graph",
    "file-argv-bound",
    "file-vfs-source-bound",
  ),
});

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort(compareText)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function freezeReviewedRange(id, start, end, digest) {
  return Object.freeze({ id, start, end, digest });
}

// Token assertions are useful only when they are tied to the reviewed code
// which gives them meaning. Each range is bounded by unique structural anchors
// and pins normalized source bytes. A matching token copied into a comment,
// another function, or a dead branch therefore cannot preserve the proof after
// the reviewed implementation changes.
const REVIEWED_INGRESS_SOURCE_RANGES = Object.freeze({
  "include/exact_runtime.h": Object.freeze([
    freezeReviewedRange(
      "structured-session-contract",
      "/// Bind one opaque authenticated-session token to an armed runtime.",
      "enum {\n  EX_HERMES_CANCEL_UNAVAILABLE",
      "sha256-DBE0rIgjhVZ9TraiOQp-NGzSflFn-Pv3ODuZfJxWAj8",
    ),
  ]),
  "src/bin/ibex/main.rs": Object.freeze([
    freezeReviewedRange(
      "authenticated-product-routing",
      "pub(crate) enum AuthenticatedProductIngress {",
      "async fn run_capsec_audit(",
      "sha256-Jyk-aRGDH9a3z1vOn2nXFVy0s5lTbGJXWb8U1SD09Qk",
    ),
    freezeReviewedRange(
      "authenticated-product-execution",
      "async fn eval_code(",
      "async fn build_bytecode(",
      "sha256-pdwTDexzLmWCbNh0d21SOe0aonpJA-6pxk1CKeZZNcg",
    ),
    freezeReviewedRange(
      "file-program-adapter",
      "async fn run_file_with_execution_adapter(",
      "fn process_exit_code(",
      "sha256-Q1Tmnu9p7V_-zxZyLuCnioIUqhwDjAEjTGwalySx82E",
    ),
    freezeReviewedRange(
      "authenticated-file-runtime",
      "async fn run_file(",
      "async fn run_file_with_execution_adapter(",
      "sha256-q5hVF2q87SToxcfJLMZ1iXlTjhvXcbAcTEnZpmU_Heo",
    ),
  ]),
  "src/bin/ibex/repl/mod.rs": Object.freeze([
    freezeReviewedRange(
      "repl-authenticated-evaluation",
      "pub(crate) enum ReplEvaluationSession {",
      "pub async fn start_worker(",
      "sha256-fKtJ2lRO490s_1zdxpHDBDrEuePVlVDVbR6-guZ-Kdc",
    ),
  ]),
  "src/bin/ibex/runtime.rs": Object.freeze([
    freezeReviewedRange(
      "closed-ingress-types",
      "pub(crate) struct ReplSessionIngress {",
      "impl AuthenticatedFileIngress {",
      "sha256-HHcVXVMkehf_gRGI8S8XgqR57Y5155xZJV_WsA70A7M",
    ),
    freezeReviewedRange(
      "runtime-ingress-constructors",
      "    pub(crate) fn repl_session_ingress(&self) -> Result<ReplSessionIngress> {",
      "    pub fn session_io_plan(&self) -> Option<crate::terminal_session::SessionIoPlan> {",
      "sha256-FrVwKFkoWJuvPmzSSTpkyf1joz5YcCE5bbHy-S9mXYI",
    ),
    freezeReviewedRange(
      "authenticated-file-ingress",
      "impl AuthenticatedFileIngress {",
      "fn expected_identity_from_snapshot(",
      // Restamped 2026-07-31: 1a9e8234 added the LLP 0042 committed-admission
      // gate (parse-free publication attempted first; any refusal rebuilds
      // cold and never rejoins the refused cache generation).
      "sha256-Xy6O5FqO6aNU32dKQAk6y9IxVPrbf0m52BxEEip_358",
    ),
    freezeReviewedRange(
      "runtime-file-execution",
      "    pub(crate) async fn run_authenticated_file_program(",
      "    pub async fn run_file_with_args(",
      "sha256-VjQEVsbf1GBYVWyxg4kKSwk21sj6Hh2LwJzqCeXSYL4",
    ),
  ]),
  "src/bin/ibex/engine/hermes.rs": Object.freeze([
    freezeReviewedRange(
      "authenticated-native-graph-join",
      "    async fn evaluate_native_module_graph(",
      "    async fn install_capsec_context_test_observer(",
      "sha256-bA65eLY2kZALZnUkHwbNyg-teFvNI0-xYiJ3wpGEBCw",
    ),
  ]),
  "src/bin/ibex/terminal_session.rs": Object.freeze([
    freezeReviewedRange(
      "execution-adapters",
      "fn mint_execution_adapter_ready<'adapter>(",
      "async fn settle_authenticated_inline_evaluation(",
      "sha256-6Pf31ksfh6WIBv8EA4MTUvKKaxGBNPzumBQtDV7B1PU",
    ),
    freezeReviewedRange(
      "repl-unix-adapter",
      "async fn run_repl_unix(",
      "fn read_bounded_transcript_record(",
      "sha256-mXe1Syfaq0DmwEYxdaHS2-rI_WVH03wdC6qLf5xXXX8",
    ),
    freezeReviewedRange(
      "file-program-adapter",
      "pub struct FileProgramExecutionAdapter {",
      "struct NativeFd(i32);",
      "sha256-ud4Hd31m-s4ESvbQ5j_zBYnqTy5aVle1UgTr7eKjbwg",
    ),
  ]),
  "src/engine/evaluation.rs": Object.freeze([
    freezeReviewedRange(
      "authenticated-session-and-minting",
      "struct ArmedSessionIdentity {",
      "struct SubmissionPermit {",
      "sha256-Ym76Z7zEgrQrIS1m-CqFYlWOFHgAypqdzkLG321uqak",
    ),
    freezeReviewedRange(
      "immutable-request-and-native-credential",
      "struct SubmissionPermit {",
      "fn credential_binding_from_request(",
      "sha256-zOTyR0x1e9oNG84pQ9jJc_Hhgx9kjedfipkyPTjM75A",
    ),
    freezeReviewedRange(
      "request-binding",
      "fn credential_binding_from_request(",
      "fn volatile_wipe(",
      "sha256-B6enF1mRc7fK3fOJ71pqHuu0Uh8_WKLHK5HER1uaURo",
    ),
  ]),
  "src/engine/hermes_runtime.cc": Object.freeze([
    freezeReviewedRange(
      "finish-bootstrap",
      'extern "C" uint32_t ex_hermes_seal_armed_shared_runtime_globals_v1(',
      'extern "C" void ex_hermes_destroy(',
      "sha256-TJdtgb60Nbv3Wj16bmzL0AOlO1SAxqFTRPaVdztd8Q4",
    ),
    freezeReviewedRange(
      "structured-session-ingress",
      'extern "C" uint32_t ex_hermes_structured_session_bind(',
      'extern "C" int ex_hermes_resume_structured_session(',
      "sha256-3e99Kc5kboU7zFPvs8-YvBJf0FB-dZnol6EorlywWf4",
    ),
    freezeReviewedRange(
      "sealed-bare-evaluator",
      'extern "C" int ex_hermes_eval(',
      'extern "C" int ibex_test_install_capsec_context_observer(',
      "sha256-4AGreCjy0lSN5U4a_MPIiC0cGeodlQ7hdXDuulWAK0k",
    ),
  ]),
  "src/engine/hermes_structured.rs": Object.freeze([
    freezeReviewedRange(
      "lowered-session-protocol",
      "use super::session_lowering::{",
      "pub struct StructuredEvaluation {",
      "sha256-5SMphAyc8CTKlFWUuwgmp2AkjMmRk2XJnK-XSAhak1c",
    ),
    freezeReviewedRange(
      "authenticated-lowering-adapter",
      "pub unsafe fn admit_prepare_authenticated_module_graph<T, F>(",
      "/// Poll the nonblocking native settlement state for one exact suspended",
      "sha256-tewuyRf15sG7xlkkpLdaackVlr9w6A5prAnB9WRQbBU",
    ),
  ]),
  "src/engine/session_lowering.rs": Object.freeze([
    freezeReviewedRange(
      "checked-program-lowering",
      "pub fn lower_program(",
      "struct ReferenceLowering {",
      "sha256-MzikPPKaTqBZ3SgvMbSfukTC7OBnEaPxn-9H3mz7EUc",
    ),
  ]),
  "src/host/mod.rs": Object.freeze([
    freezeReviewedRange(
      "authenticated-vfs-source-read",
      "    pub fn authenticated_vfs_file_read(",
      "    fn authorize_vfs_script_read_stage(",
      "sha256-LpkJ2-xRvIvtl1Tjyu-IRxgl6__a5aXLLoQF2bnxX_M",
    ),
  ]),
  "src/module_loader/runner_pipeline.rs": Object.freeze([
    freezeReviewedRange(
      "authenticated-entry-request-join",
      "    pub fn validate_authenticated_entry_request(",
      "    pub fn plan(&self) -> Result<SynchronousGraphPlan<'_>> {",
      "sha256-qDgqsKmfuVCl7WC9d3PZGx-Q6V7NM3JkOAo9uj47acI",
    ),
    freezeReviewedRange(
      "prepared-entry-join-consumption",
      "pub fn load_prepared_source_graph_v1(",
      "    let text = std::str::from_utf8(&index_bytes)?;",
      "sha256-NoA1544vUsV4hf3njehxoR0sMbhChadmJr54dUz2MDw",
    ),
  ]),
  "src/vfs/mod.rs": Object.freeze([
    freezeReviewedRange(
      "authenticated-vfs-read",
      "    pub(crate) fn read_authenticated<F>(",
      "    #[cfg(unix)]\n    /// Walk one link at a time",
      "sha256-Ezbs1O6y8dNxd3T_voZtMHKhR12lGGDG2-IMLH7q9FA",
    ),
  ]),
});

function normalizeReviewedSource(source) {
  return source
    .replace(/\r\n?/gu, "\n")
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/gu, ""))
    .join("\n");
}

function sha256Source(source) {
  return `sha256-${createHash("sha256")
    .update(normalizeReviewedSource(source), "utf8")
    .digest("base64url")}`;
}

function uniqueAnchorOffset(source, anchor, label) {
  const offset = source.indexOf(anchor);
  if (offset < 0) {
    throw new Error(`${label}: lacks structural anchor ${JSON.stringify(anchor)}`);
  }
  if (source.indexOf(anchor, offset + anchor.length) >= 0) {
    throw new Error(`${label}: structural anchor is not unique ${JSON.stringify(anchor)}`);
  }
  return offset;
}

function extractReviewedRange(source, range, label) {
  const start = uniqueAnchorOffset(source, range.start, `${label} start`);
  const end = uniqueAnchorOffset(source, range.end, `${label} end`);
  if (end <= start) {
    throw new Error(`${label}: structural range is reversed`);
  }
  return source.slice(start, end);
}

// Kept exported so an intentional source review can print the new scoped
// digests without weakening validation: validateIngressObligationDataset still
// compares only against the constants above.
export function reviewedIngressSourceRangeDigests(repoRoot) {
  const root = path.resolve(repoRoot);
  return Object.entries(REVIEWED_INGRESS_SOURCE_RANGES).flatMap(
    ([pathname, ranges]) => {
      const filePath = path.resolve(root, pathname);
      if (filePath !== root && !filePath.startsWith(`${root}${path.sep}`)) {
        throw new Error(`reviewed ingress source ${pathname}: path escapes the repository`);
      }
      const source = fs.readFileSync(filePath, "utf8");
      return ranges.map((range) => ({
        path: pathname,
        id: range.id,
        digest: sha256Source(
          extractReviewedRange(
            source,
            range,
            `reviewed ingress source ${pathname}#${range.id}`,
          ),
        ),
      }));
    },
  );
}

function assertExact(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new Error(`${label}: expected ${canonicalJson(expected)}, got ${canonicalJson(actual)}`);
  }
}

function assertSortedUnique(values, label) {
  if (new Set(values).size !== values.length) {
    throw new Error(`${label}: duplicate value`);
  }
  const sorted = [...values].sort(compareText);
  assertExact(values, sorted, `${label} order`);
}

function assertUnique(values, label) {
  if (new Set(values).size !== values.length) {
    throw new Error(`${label}: duplicate value`);
  }
}

function surfaceKey(surface) {
  return `${surface.kind}:${surface.name}`;
}

function sourceAssertion(repoRoot, assertion, label) {
  const root = path.resolve(repoRoot);
  const filePath = path.resolve(root, assertion.path);
  if (filePath !== root && !filePath.startsWith(`${root}${path.sep}`)) {
    throw new Error(`${label}: source path escapes the repository`);
  }
  const source = fs.readFileSync(filePath, "utf8");
  const specifications = REVIEWED_INGRESS_SOURCE_RANGES[assertion.path];
  if (!specifications) {
    throw new Error(
      `${label}: ${assertion.path} has no reviewed structural source range`,
    );
  }
  const reviewed = specifications.map((range) => ({
    range,
    source: extractReviewedRange(
      source,
      range,
      `${label}: reviewed source range ${assertion.path}#${range.id}`,
    ),
  }));
  for (const token of assertion.tokens) {
    if (!reviewed.some((range) => range.source.includes(token))) {
      throw new Error(
        `${label}: ${assertion.path} lacks token ${JSON.stringify(token)} in its reviewed source ranges`,
      );
    }
  }
  for (const { range, source: reviewedSource } of reviewed) {
    const actual = sha256Source(reviewedSource);
    if (actual !== range.digest) {
      throw new Error(
        `${label}: reviewed source range ${assertion.path}#${range.id} digest expected ${range.digest}, got ${actual}`,
      );
    }
  }
}

function assertCoverageEdge(edge, specification, label) {
  if (!edge) throw new Error(`${label}: coverage edge is missing`);
  assertExact(edge.surface, specification.surface, `${label} surface`);
  if (edge.classification !== specification.classification) {
    throw new Error(
      `${label}: expected classification ${specification.classification}, got ${edge.classification}`,
    );
  }
  if (specification.classification === "non-capability") {
    if (edge.rationaleId !== specification.rationaleId) {
      throw new Error(
        `${label}: expected rationale ${specification.rationaleId}, got ${edge.rationaleId}`,
      );
    }
  } else if (edge.cap !== specification.cap) {
    throw new Error(`${label}: expected closed capability ${specification.cap}, got ${edge.cap}`);
  }
}

export function validateIngressObligationDataset({
  coverage,
  dataset,
  repoRoot,
}) {
  if (!coverage || !Array.isArray(coverage.edges)) {
    throw new Error("ingress obligations require coverage edges");
  }
  if (dataset?.ingressObligationsSchema !== DATASET_SCHEMA) {
    throw new Error("ingress obligations have an unknown schema");
  }
  if (dataset.profile !== PROFILE) {
    throw new Error("ingress obligations have an unknown profile");
  }
  if (dataset.rationaleId !== AUTHENTICATED_CODE_INGRESS_RATIONALE) {
    throw new Error("ingress obligations have the wrong rationale id");
  }

  const edgeById = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  if (edgeById.size !== coverage.edges.length) {
    throw new Error("coverage edges contain duplicate ids");
  }

  const supportingRoles = dataset.supportingSurfaces.map((row) => row.role);
  assertSortedUnique(supportingRoles, "ingress supporting-surface roles");
  assertExact(
    dataset.supportingSurfaces,
    REQUIRED_INGRESS_SUPPORTING_SURFACES,
    "ingress supporting surfaces",
  );
  for (const specification of REQUIRED_INGRESS_SUPPORTING_SURFACES) {
    assertCoverageEdge(
      edgeById.get(specification.edgeId),
      specification,
      `ingress supporting surface ${specification.role}`,
    );
  }

  const obligationIds = dataset.obligations.map((row) => row.id);
  assertSortedUnique(obligationIds, "ingress obligation ids");
  assertExact(
    dataset.obligations,
    REQUIRED_INGRESS_OBLIGATIONS,
    "ingress obligation definitions",
  );
  for (const obligation of dataset.obligations) {
    for (const [index, evidence] of obligation.sourceEvidence.entries()) {
      assertUnique(
        evidence.tokens,
        `ingress obligation ${obligation.id} evidence ${index} tokens`,
      );
      sourceAssertion(
        repoRoot,
        evidence,
        `ingress obligation ${obligation.id} evidence ${index}`,
      );
    }
  }

  const ingressEdges = coverage.edges
    .filter(
      (edge) =>
        edge.classification === "non-capability" &&
        edge.rationaleId === AUTHENTICATED_CODE_INGRESS_RATIONALE,
    )
    .sort((left, right) => compareText(left.id, right.id));
  assertExact(
    Object.keys(REQUIRED_INGRESS_ROW_PROFILES).sort(compareText),
    REQUIRED_AUTHENTICATED_INGRESS_ROUTES,
    "reviewed authenticated ingress route profiles",
  );
  const ingressRouteKeys = ingressEdges
    .map((edge) => surfaceKey(edge.surface))
    .sort(compareText);
  assertSortedUnique(ingressRouteKeys, "authenticated ingress route keys");
  assertExact(
    ingressRouteKeys,
    REQUIRED_AUTHENTICATED_INGRESS_ROUTES,
    "required authenticated ingress routes",
  );
  const rowIds = dataset.rows.map((row) => row.edgeId);
  assertSortedUnique(rowIds, "ingress obligation row ids");
  assertExact(
    rowIds,
    ingressEdges.map((edge) => edge.id),
    "authenticated-code-ingress coverage join",
  );

  for (const row of dataset.rows) {
    const edge = edgeById.get(row.edgeId);
    assertCoverageEdge(
      edge,
      {
        surface: row.surface,
        classification: "non-capability",
        rationaleId: AUTHENTICATED_CODE_INGRESS_RATIONALE,
      },
      `ingress obligation row ${row.edgeId}`,
    );
    const profile = REQUIRED_INGRESS_ROW_PROFILES[surfaceKey(row.surface)];
    if (!profile) {
      throw new Error(
        `ingress obligation row ${row.edgeId}: authenticated route has no reviewed obligation profile`,
      );
    }
    assertSortedUnique(
      row.obligationIds,
      `ingress obligation row ${row.edgeId} obligation ids`,
    );
    assertExact(
      row.obligationIds,
      profile,
      `ingress obligation row ${row.edgeId} obligation coverage`,
    );
  }

  const referencedObligations = [
    ...new Set(dataset.rows.flatMap((row) => row.obligationIds)),
  ].sort(compareText);
  assertExact(
    referencedObligations,
    obligationIds,
    "authenticated-code-ingress referenced obligation definitions",
  );

  return {
    ingressEdges: ingressEdges.length,
    obligations: obligationIds.length,
    sourceAssertions: dataset.obligations.reduce(
      (count, obligation) => count + obligation.sourceEvidence.length,
      0,
    ),
    supportingSurfaces: supportingRoles.length,
  };
}
