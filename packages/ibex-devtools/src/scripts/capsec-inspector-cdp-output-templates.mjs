/**
 * Structural output-account closure for the binary's inspector/CDP surface.
 *
 * Every armed Runtime and Hermes engine rejects inspector start at its local
 * capability sink, before debugger/backend allocation. The CDP listener also
 * requires a private authorization minted only after Hermes proves the engine
 * is unarmed. Consequently the listener, HTTP discovery routes, WebSocket
 * request handlers, and backend calls are not armed value boundaries. This
 * module binds those sink invariants to the source-discovered CDP family and
 * publishes structural-only integration rows with no output slots. Unarmed
 * protocol response values are deliberately absent.
 *
 * @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces —
 * armed runtimes reject inspector flags early and refuse again at the sink.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * registrar alone is not proof; the armed sink and listener authorization are
 * source-bound here.
 * @ref LLP 0023#6-path-bearing-observables — an unreachable unarmed response
 * does not create an armed path/URL output slot.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";
import { scanCdpSurfaces } from "./capsec-surface-inventory.mjs";

export const INSPECTOR_CDP_STRUCTURAL_ACCOUNT_SCHEMA =
  "ibex/capsec-inspector-cdp-structural-account/1";
export const INSPECTOR_CDP_STRUCTURAL_REASON_CODE =
  "closed-before-inspector-dispatch";
export const INSPECTOR_CDP_OUTPUT_CATALOG_BINDINGS = Object.freeze([]);

const REQUIRED_PATHS = Object.freeze([
  "src/bin/ibex/main.rs",
  "src/bin/ibex/runtime.rs",
  "src/bin/ibex/engine/hermes.rs",
  "src/bin/ibex/cdp/mod.rs",
]);

const CLOSED_MESSAGE =
  "production capability enforcement closes compatibility, inspector, and runtime-fidelity overrides";
const ARMED_SINK_CLOSED_MESSAGE =
  "armed capability runtime closes inspector activation and configuration";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function frozen(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value))
    return value;
  for (const child of Object.values(value)) frozen(child);
  return Object.freeze(value);
}

/** Remove Rust trivia while preserving string contents and token order. */
function compactRust(source, label) {
  requireCondition(
    typeof source === "string",
    `${label}: expected Rust source`,
  );
  let result = "";
  let index = 0;

  const rawStringEnd = (start) => {
    let cursor = start;
    if (source[cursor] === "b") cursor += 1;
    if (source[cursor] !== "r") return null;
    cursor += 1;
    let hashes = 0;
    while (source[cursor] === "#") {
      hashes += 1;
      cursor += 1;
    }
    if (source[cursor] !== '"') return null;
    const terminator = `"${"#".repeat(hashes)}`;
    const end = source.indexOf(terminator, cursor + 1);
    requireCondition(end !== -1, `${label}: unterminated raw string`);
    return end + terminator.length;
  };

  while (index < source.length) {
    const rawEnd = rawStringEnd(index);
    if (rawEnd !== null) {
      result += source.slice(index, rawEnd);
      index = rawEnd;
      continue;
    }
    if (/\s/u.test(source[index])) {
      index += 1;
      continue;
    }
    if (source.startsWith("//", index)) {
      const end = source.indexOf("\n", index + 2);
      index = end === -1 ? source.length : end + 1;
      continue;
    }
    if (source.startsWith("/*", index)) {
      let depth = 1;
      let cursor = index + 2;
      while (cursor < source.length && depth > 0) {
        if (source.startsWith("/*", cursor)) {
          depth += 1;
          cursor += 2;
        } else if (source.startsWith("*/", cursor)) {
          depth -= 1;
          cursor += 2;
        } else cursor += 1;
      }
      requireCondition(depth === 0, `${label}: unterminated block comment`);
      index = cursor;
      continue;
    }
    if (source[index] === '"') {
      let cursor = index + 1;
      while (cursor < source.length) {
        if (source[cursor] === "\\") cursor += 2;
        else if (source[cursor] === '"') {
          cursor += 1;
          break;
        } else cursor += 1;
      }
      requireCondition(
        source[cursor - 1] === '"',
        `${label}: unterminated string`,
      );
      result += source.slice(index, cursor);
      index = cursor;
      continue;
    }
    if (source[index] === "'" && source[index + 2] === "'") {
      result += source.slice(index, index + 3);
      index += 3;
      continue;
    }
    if (
      source[index] === "'" &&
      source[index + 1] === "\\" &&
      source[index + 3] === "'"
    ) {
      result += source.slice(index, index + 4);
      index += 4;
      continue;
    }
    result += source[index];
    index += 1;
  }
  return result;
}

function compactToken(token, label) {
  return compactRust(token, `${label} token`);
}

function orderedTokens(source, tokens, label) {
  let offset = 0;
  const matched = [];
  for (const token of tokens) {
    const compact = compactToken(token, label);
    const found = source.indexOf(compact, offset);
    requireCondition(found !== -1, `${label}: missing source token ${token}`);
    matched.push(compact);
    offset = found + compact.length;
  }
  return matched;
}

function exactOccurrence(source, token, expected, label) {
  const compact = compactToken(token, label);
  let count = 0;
  let offset = 0;
  while (true) {
    const found = source.indexOf(compact, offset);
    if (found === -1) break;
    count += 1;
    offset = found + compact.length;
  }
  requireCondition(
    count === expected,
    `${label}: expected ${expected} occurrences of ${token}, got ${count}`,
  );
  return compact;
}

const RUNTIME_INSPECTOR_GUARD = String.raw`
let run_inspector = matches!(
    cli.command.as_ref(),
    Some(crate::cli::Commands::Run { inspect: true, .. })
        | Some(crate::cli::Commands::Run {
            inspect_wait: true,
            ..
        })
        | Some(crate::cli::Commands::Run {
            inspect_open: true,
            ..
        })
        | Some(crate::cli::Commands::Run {
            inspect_pause: true,
            ..
        })
        | Some(crate::cli::Commands::Run {
            inspect_port: Some(_),
            ..
        })
        | Some(crate::cli::Commands::Run {
            inspect_host: Some(_),
            ..
        })
);
let external_arming_artifact_supplied =
    cli.capsec_armed_snapshot.is_some() || cli.capsec_arming_identity.is_some();
if (cli.compat.is_some() && external_arming_artifact_supplied)
    || cli.inspect
    || cli.inspect_wait
    || cli.inspect_open
    || cli.inspect_pause
    || cli.inspect_port.is_some()
    || cli.inspect_host.is_some()
    || cli.expose_internals
    || cli.stack_size.is_some()
    || cli.max_http_header_size.is_some()
    || run_inspector
{
    anyhow::bail!(
        "production capability enforcement closes compatibility, inspector, and runtime-fidelity overrides"
    );
}`;

const MAIN_PRODUCTION_GUARD = String.raw`
if cli.eval_code.is_some()
    || cli.print_eval.is_some()
    || matches!(
        cli.command.as_ref(),
        None | Some(Commands::Run { .. })
            | Some(Commands::Eval { .. })
            | Some(Commands::Repl)
            | Some(Commands::Build { .. })
            | Some(Commands::Debug { .. })
    )
{
    runtime::validate_production_inputs(&cli)?;
}`;

const RUNTIME_ARMED_INSPECTOR_SINK = String.raw`
pub async fn start_inspector(&self, host: &str, port: u16) -> Result<()> {
    if self.host.armed_snapshot().is_some() {
        anyhow::bail!(ARMED_INSPECTOR_CLOSED_MESSAGE);
    }
    self.engine.start_inspector(host, port).await
}`;

const ENGINE_ARMED_INSPECTOR_SINK = String.raw`
fn unarmed_inspector_authorization(&self) -> Result<UnarmedInspectorAuthorization> {
    if self.armed_snapshot_digest.is_some() {
        anyhow::bail!(ARMED_INSPECTOR_CLOSED_MESSAGE);
    }
    Ok(UnarmedInspectorAuthorization(()))
}`;

const PROOF_SOURCE_ASSERTIONS = frozen([
  {
    id: "runtime-armed-inspector-sink",
    path: "src/bin/ibex/runtime.rs",
    exact: RUNTIME_ARMED_INSPECTOR_SINK,
  },
  {
    id: "engine-armed-inspector-sink",
    path: "src/bin/ibex/engine/hermes.rs",
    exact: ENGINE_ARMED_INSPECTOR_SINK,
  },
  {
    id: "engine-mints-listener-authorization-after-guard",
    path: "src/bin/ibex/engine/hermes.rs",
    tokens: [
      "pub(crate) struct UnarmedInspectorAuthorization(())",
      "async fn start_inspector(&self, host: &str, port: u16) -> Result<()>",
      "let authorization = self.unarmed_inspector_authorization()?",
      "let runtime = self.ensure_runtime().await?",
      "HermesCdpBackend::new(",
      "let server = cdp::start_server(&authorization, host, port, backend)?",
    ],
  },
  {
    id: "listener-requires-unarmed-authorization",
    path: "src/bin/ibex/cdp/mod.rs",
    tokens: [
      "pub fn start_server(",
      "_authorization: &crate::engine::hermes::UnarmedInspectorAuthorization",
      "socket.bind(&addr.into())",
      "socket.listen(128)?",
      "runtime.block_on(run_server(",
      "async fn run_server(",
      "accept = listener.accept()",
      "handle_connection(",
    ],
  },
  {
    id: "connection-to-http-and-websocket",
    path: "src/bin/ibex/cdp/mod.rs",
    tokens: [
      "async fn handle_connection(",
      "if !is_websocket_upgrade(&peek_text)",
      "handle_http_request(&mut stream, local_addr).await?",
      "tokio_tungstenite::accept_hdr_async_with_config(",
      "let (mut write, mut read) = ws.split()",
      "handle_request(id, method, params, &mut context).await",
    ],
  },
]);

// These assertions catch familiar drift early, but they are not a Rust name-
// resolved call graph and are deliberately excluded from each account's proof
// digest. The proof above remains local to the guarded sinks and authorization
// token even when receiver, import, or UFCS spellings change.
const DIAGNOSTIC_SOURCE_ASSERTIONS = frozen([
  {
    id: "production-dispatch-guard",
    path: "src/bin/ibex/main.rs",
    exact: MAIN_PRODUCTION_GUARD,
  },
  {
    id: "guard-before-command-dispatch",
    path: "src/bin/ibex/main.rs",
    tokens: [
      "async fn run(cli: Cli) -> Result<()>",
      "runtime::validate_production_inputs(&cli)?",
      "match &cli.command",
    ],
  },
  {
    id: "all-inspector-spellings-closed",
    path: "src/bin/ibex/runtime.rs",
    exact: RUNTIME_INSPECTOR_GUARD,
  },
  {
    id: "runtime-construction-revalidates",
    path: "src/bin/ibex/runtime.rs",
    tokens: [
      "pub fn from_cli_with_session(",
      "build_host_with_route(cli, session_io.route)?",
      "fn build_host_with_route(",
      "validate_production_inputs(cli)?",
      "build_default_armed_host",
      "validate_production_inputs(cli)?",
    ],
  },
  {
    id: "file-inspector-after-runtime-construction",
    path: "src/bin/ibex/main.rs",
    tokens: [
      "async fn run_file(",
      "let effective_cli = effective_run_cli(cli, options)",
      "runtime::Runtime::from_cli_with_session(&effective_cli, session_io)?",
      "runtime.start_inspector(host, port).await?",
    ],
  },
  {
    id: "session-inspector-after-runtime-construction",
    path: "src/bin/ibex/main.rs",
    tokens: [
      "let runtime = runtime::Runtime::from_cli_with_session(cli, session_io)?",
      "configure_session_inspector(cli, &runtime).await?",
      "async fn configure_session_inspector(",
      "runtime.start_inspector(host, port).await?",
    ],
  },
  {
    id: "worker-material-builds-the-guarded-runtime",
    path: "src/bin/ibex/runtime.rs",
    tokens: [
      "pub(crate) fn from_session_worker_material(",
      "authenticated_session_worker_snapshot(application, session_io)?",
      "Host::new_armed(",
      'engine::create_engine("hermes", Some(&digest))?',
      "Self::from_authenticated_session_worker_parts(",
    ],
  },
  {
    id: "pre-clap-worker-uses-guarded-runtime",
    path: "src/bin/ibex/session_worker_runtime.rs",
    tokens: [
      "fn run_evaluator_owner(",
      "Runtime::from_session_worker_material(",
      "runtime.load_runtime().await",
      "let engine = runtime.engine()",
    ],
  },
]);

function sourceMap(value, label) {
  const entries =
    value instanceof Map ? [...value.entries()] : Object.entries(value ?? {});
  const result = new Map();
  for (const [path, source] of entries) {
    requireCondition(
      typeof path === "string" && path.length > 0 && typeof source === "string",
      `${label}: malformed source row`,
    );
    requireCondition(!result.has(path), `${label}: duplicate source ${path}`);
    result.set(path, source);
  }
  return result;
}

/**
 * Non-exhaustive lexical drift diagnostics. This intentionally recognizes only
 * the current literal spellings; aliases, UFCS, macros, and cfg expansion are
 * outside its authority and do not participate in the structural proof.
 */
function literalCallSiteDiagnostics(binarySources) {
  const compactByPath = new Map(
    [...binarySources].map(([path, source]) => [
      path,
      compactRust(source, path),
    ]),
  );
  const sites = [];
  for (const [path, source] of compactByPath) {
    for (const [callee, expectedPath, expectedCount] of [
      ["runtime.start_inspector(", "src/bin/ibex/main.rs", 2],
      ["self.engine.start_inspector(", "src/bin/ibex/runtime.rs", 1],
      ["cdp::start_server(", "src/bin/ibex/engine/hermes.rs", 1],
    ]) {
      const token = compactToken(callee, `inspector call site ${callee}`);
      let offset = 0;
      let count = 0;
      while (true) {
        const found = source.indexOf(token, offset);
        if (found === -1) break;
        count += 1;
        offset = found + token.length;
      }
      if (count > 0) sites.push({ path, callee, count });
      if (path === expectedPath) {
        requireCondition(
          count === expectedCount,
          `inspector call-site audit: ${path} has ${count} ${callee} calls, expected ${expectedCount}`,
        );
      } else {
        requireCondition(
          count === 0,
          `inspector call-site audit: unexpected ${callee} call in ${path}`,
        );
      }
    }
  }
  for (const expectedPath of [
    "src/bin/ibex/main.rs",
    "src/bin/ibex/runtime.rs",
    "src/bin/ibex/engine/hermes.rs",
  ]) {
    requireCondition(
      compactByPath.has(expectedPath),
      `inspector call-site audit lacks ${expectedPath}`,
    );
  }
  return sites.sort((left, right) =>
    compareText(`${left.path}:${left.callee}`, `${right.path}:${right.callee}`),
  );
}

function structuralSourceRefs(surface) {
  return [
    ...new Set([
      ...surface.sourceRefs,
      "src/bin/ibex/runtime.rs#Runtime::start_inspector:armed-sink-guard",
      "src/bin/ibex/engine/hermes.rs#HermesEngine::unarmed_inspector_authorization",
      "src/bin/ibex/engine/hermes.rs#HermesEngine::start_inspector:authorization-before-backend",
      "src/bin/ibex/cdp/mod.rs#start_server:requires-UnarmedInspectorAuthorization",
      "src/bin/ibex/cdp/mod.rs#run_server",
      "src/bin/ibex/cdp/mod.rs#handle_connection",
    ]),
  ].sort(compareText);
}

/**
 * Bind every source-discovered CDP route to the armed Runtime/engine sink
 * guards and the listener's unarmed-only authorization type. The recursive
 * Rust corpus is used only for non-exhaustive literal-spelling diagnostics;
 * aliases and UFCS cannot weaken the local guards or mint the private token.
 */
export function auditInspectorCdpStructuralClosure({
  sourceFiles,
  binaryRustSources,
}) {
  const required = sourceMap(sourceFiles, "inspector closure source files");
  const binary = sourceMap(binaryRustSources, "inspector binary Rust sources");
  for (const path of REQUIRED_PATHS) {
    requireCondition(
      required.has(path),
      `inspector closure audit lacks ${path}`,
    );
    requireCondition(binary.has(path), `inspector binary audit lacks ${path}`);
    requireCondition(
      required.get(path) === binary.get(path),
      `inspector closure audit source differs for ${path}`,
    );
  }

  const assertionEvidence = (assertions) =>
    assertions.map((assertion) => {
      const source = required.get(assertion.path) ?? binary.get(assertion.path);
      requireCondition(
        typeof source === "string",
        `inspector closure audit lacks ${assertion.path}`,
      );
      const compact = compactRust(source, assertion.path);
      const matched = assertion.exact
        ? [exactOccurrence(compact, assertion.exact, 1, assertion.id)]
        : orderedTokens(compact, assertion.tokens, assertion.id);
      return {
        id: assertion.id,
        path: assertion.path,
        digest: taggedDigest({
          id: assertion.id,
          path: assertion.path,
          matched,
        }),
      };
    });
  const proofAssertions = assertionEvidence(PROOF_SOURCE_ASSERTIONS);
  const diagnosticAssertions = assertionEvidence(DIAGNOSTIC_SOURCE_ASSERTIONS);

  const mainSource = compactRust(
    required.get("src/bin/ibex/main.rs"),
    "src/bin/ibex/main.rs",
  );
  const runtimeSource = compactRust(
    required.get("src/bin/ibex/runtime.rs"),
    "src/bin/ibex/runtime.rs",
  );
  exactOccurrence(
    mainSource,
    "runtime.start_inspector(",
    2,
    "production start-inspector callers",
  );
  exactOccurrence(
    runtimeSource,
    `"${CLOSED_MESSAGE}"`,
    1,
    "production inspector closure message",
  );

  const literalCallSites = literalCallSiteDiagnostics(binary);
  const cdpPath = "src/bin/ibex/cdp/mod.rs";
  const discovered = scanCdpSurfaces(required.get(cdpPath), cdpPath);
  requireCondition(
    discovered.length > 1 &&
      discovered.some((surface) => surface.name === "inspector.cdp-listener") &&
      discovered.some((surface) =>
        surface.name.startsWith("inspector.cdp-http:"),
      ) &&
      discovered.some((surface) =>
        surface.name.startsWith("inspector.cdp-request:"),
      ) &&
      discovered.some((surface) =>
        surface.name.startsWith("inspector.cdp-request-fallback:"),
      ),
    "inspector closure audit found no complete CDP dispatch family",
  );

  const sharedProof = {
    reasonCode: INSPECTOR_CDP_STRUCTURAL_REASON_CODE,
    sinkGuardMessage: ARMED_SINK_CLOSED_MESSAGE,
    assertions: proofAssertions,
  };
  const surfaces = Object.fromEntries(
    discovered.map((surface) => {
      const sourceRefs = structuralSourceRefs(surface);
      return [
        surface.name,
        {
          observedKey: surface.observedKey,
          sourceRefs,
          proofDigest: taggedDigest({
            ...sharedProof,
            observedKey: surface.observedKey,
            inventorySourceRefs: surface.sourceRefs,
          }),
        },
      ];
    }),
  );
  return frozen({
    structuralAccountSchema: INSPECTOR_CDP_STRUCTURAL_ACCOUNT_SCHEMA,
    reasonCode: INSPECTOR_CDP_STRUCTURAL_REASON_CODE,
    sinkGuardMessage: ARMED_SINK_CLOSED_MESSAGE,
    guardPhase: "armed-runtime-and-engine-start-sinks",
    dispatchBoundary: "cdp::start_server(&UnarmedInspectorAuthorization, ...)",
    assertions: proofAssertions,
    diagnostics: {
      startupGuardMessage: CLOSED_MESSAGE,
      assertions: diagnosticAssertions,
      literalCallSites,
    },
    surfaces,
    proofSetDigest: taggedDigest(
      Object.fromEntries(
        Object.entries(surfaces).map(([name, row]) => [name, row.proofDigest]),
      ),
    ),
  });
}

function validateAudit(audit) {
  requireCondition(
    audit?.structuralAccountSchema ===
      INSPECTOR_CDP_STRUCTURAL_ACCOUNT_SCHEMA &&
      audit.reasonCode === INSPECTOR_CDP_STRUCTURAL_REASON_CODE &&
      audit.sinkGuardMessage === ARMED_SINK_CLOSED_MESSAGE &&
      audit.guardPhase === "armed-runtime-and-engine-start-sinks" &&
      audit.dispatchBoundary ===
        "cdp::start_server(&UnarmedInspectorAuthorization, ...)" &&
      audit.surfaces &&
      typeof audit.surfaces === "object" &&
      Object.keys(audit.surfaces).length > 0,
    "invalid inspector CDP structural audit",
  );
  return audit;
}

/** Integration rows for the catalog builder; intentionally no output shapes. */
export function inspectorCdpStructuralAccountBindings(sourceAudit) {
  validateAudit(sourceAudit);
  return Object.entries(sourceAudit.surfaces)
    .map(([surfaceName, proof]) => ({
      surfaceName,
      status: "structural-only",
      reasonCode: INSPECTOR_CDP_STRUCTURAL_REASON_CODE,
      sourceRefs: [...proof.sourceRefs],
      proofDigest: proof.proofDigest,
      outputKinds: [],
    }))
    .sort((left, right) => compareText(left.surfaceName, right.surfaceName));
}

export function validateInspectorCdpStructuralAccount(
  account,
  { surface, coverageEdge, sourceAudit },
) {
  validateAudit(sourceAudit);
  const proof = sourceAudit.surfaces[surface?.name];
  requireCondition(
    proof &&
      surface.kind === "native-op" &&
      surface.observedKey === proof.observedKey &&
      canonicalJson(structuralSourceRefs(surface)) ===
        canonicalJson(proof.sourceRefs) &&
      coverageEdge.surface?.kind === "native-op" &&
      coverageEdge.surface.name === surface.name &&
      account.structuralAccountSchema ===
        INSPECTOR_CDP_STRUCTURAL_ACCOUNT_SCHEMA &&
      account.surfaceId === coverageEdge.id &&
      account.surfaceObservedKey === surface.observedKey &&
      account.status === "structural-only" &&
      account.reasonCode === INSPECTOR_CDP_STRUCTURAL_REASON_CODE &&
      canonicalJson(account.sourceRefs) === canonicalJson(proof.sourceRefs) &&
      account.proofDigest === proof.proofDigest &&
      Array.isArray(account.outputKinds) &&
      account.outputKinds.length === 0,
    `${surface?.name}: invalid inspector CDP structural account`,
  );
  return account;
}

export function authoredInspectorCdpStructuralAccount({
  surface,
  coverageEdge,
  sourceAudit,
}) {
  validateAudit(sourceAudit);
  const proof = sourceAudit.surfaces[surface?.name];
  if (!proof) return null;
  const account = {
    structuralAccountSchema: INSPECTOR_CDP_STRUCTURAL_ACCOUNT_SCHEMA,
    surfaceId: coverageEdge?.id,
    surfaceObservedKey: surface.observedKey,
    status: "structural-only",
    reasonCode: INSPECTOR_CDP_STRUCTURAL_REASON_CODE,
    sourceRefs: [...proof.sourceRefs],
    proofDigest: proof.proofDigest,
    outputKinds: [],
  };
  return validateInspectorCdpStructuralAccount(account, {
    surface,
    coverageEdge,
    sourceAudit,
  });
}

/** Verify the standard catalog projection retains every proved closure. */
export function validateInspectorCdpStructuralCatalog({
  catalog,
  coverage,
  sourceAudit,
}) {
  validateAudit(sourceAudit);
  const edges = new Map();
  for (const edge of coverage?.edges ?? []) {
    const observedKey = `${edge?.surface?.kind}:${edge?.surface?.name}`;
    requireCondition(
      !edges.has(observedKey),
      `${observedKey}: duplicate inspector coverage edge`,
    );
    edges.set(observedKey, edge);
  }
  const accounts = new Map(
    (catalog?.surfaceAccounts ?? []).map((account) => [
      account.surfaceId,
      account,
    ]),
  );
  const rowsBySurfaceId = Map.groupBy(
    catalog?.rows ?? [],
    (row) => row.key?.surfaceId,
  );
  for (const [surfaceName, proof] of Object.entries(sourceAudit.surfaces)) {
    const edge = edges.get(proof.observedKey);
    const account = accounts.get(edge?.id);
    requireCondition(
      edge?.surface?.name === surfaceName &&
        account?.status === "structural-only" &&
        account.reasonCode === INSPECTOR_CDP_STRUCTURAL_REASON_CODE &&
        Array.isArray(account.outputKinds) &&
        account.outputKinds.length === 0 &&
        proof.sourceRefs.every((sourceRef) =>
          account.sourceRefs.includes(sourceRef),
        ) &&
        (rowsBySurfaceId.get(edge.id) ?? []).length === 0,
      `${surfaceName}: inspector CDP catalog closure drift`,
    );
  }
  return true;
}
