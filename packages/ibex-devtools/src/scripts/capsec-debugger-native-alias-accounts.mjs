/**
 * Structural accounts for the six value-returning native debugger aliases.
 *
 * The `inspector.debugger-*` inventory rows do not describe a second ABI
 * return boundary. They name the debugger operations reached by the guarded
 * CDP backend. The actual values cross the companion `ex_hermes_debugger_*`
 * Host ABI surfaces, which remain output-bearing and retain their own catalog
 * rows. This module closes only the duplicate native aliases, and only while:
 *
 * - the armed engine cannot construct the CDP backend or listener token;
 * - every Rust reference to the six C symbols remains in that backend path;
 * - source-Hermes, debugger-disabled, and Windows implementations remain
 *   bound to the same six Host ABI signatures; and
 * - the catalog contains the exact companion Host ABI accounts and rows.
 *
 * @ref LLP 0003#the-platform-shims-map — debugger support has distinct
 * source-Hermes, debugger-disabled, and Windows-stub implementations.
 * @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces —
 * armed runtimes refuse inspector activation at the engine sink.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
 * structural closure is source- and catalog-bound rather than name-derived.
 * @ref LLP 0023#6-path-bearing-observables — the Host ABI return is the one
 * value slot; the internal native alias must not manufacture a duplicate.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";
import {
  deriveHostAbiOutputCatalogAccount,
  HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
} from "./capsec-surface-inventory.mjs";

export const DEBUGGER_NATIVE_ALIAS_STRUCTURAL_ACCOUNT_SCHEMA =
  "ibex/capsec-debugger-native-alias-structural-account/1";
export const DEBUGGER_NATIVE_ALIAS_STRUCTURAL_REASON_CODE =
  "armed-inspector-native-alias-unreachable";
export const DEBUGGER_NATIVE_ALIAS_OUTPUT_CATALOG_BINDINGS = Object.freeze([]);

const SOURCE_HERMES_PATH = "src/engine/hermes_runtime_debugger.cc";
const WINDOWS_PATH = "src/engine/hermes_runtime_platform_windows.cc";
const HERMES_RUST_PATH = "src/bin/ibex/engine/hermes.rs";
const CDP_RUST_PATH = "src/bin/ibex/cdp/mod.rs";
const RUNTIME_RUST_PATH = "src/bin/ibex/runtime.rs";
const HOST_ABI_OUTPUT_TEST_PATH =
  "src/bin/ibex/engine/capsec_host_abi_output_batch.test.rs";
const PUBLIC_CLOSED_TEST_PATH =
  "src/bin/ibex/engine/capsec_public_closed_batch.rs";
function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

/**
 * Keep the guard spelling in one exported record. The proof code below uses
 * only this record, so a deliberate authorization API rename has one review
 * point instead of being scattered through the account logic.
 */
export const DEBUGGER_NATIVE_ALIAS_GUARD_BINDING = deepFreeze({
  authorizationType: "UnarmedInspectorAuthorization",
  cdpPath: CDP_RUST_PATH,
  engineGuardMethod: "unarmed_inspector_authorization",
  enginePath: HERMES_RUST_PATH,
  runtimePath: RUNTIME_RUST_PATH,
  sinkMessage:
    "armed capability runtime closes inspector activation and configuration",
});

const TYPE_DESCRIPTORS = deepFreeze({
  "ExactHermesRuntime *": {
    tokens: ["ExactHermesRuntime", "*"],
    valueKind: "pointer",
    pointerDepth: 1,
    ownership: { kind: "borrowed" },
  },
  "const char *": {
    tokens: ["const", "char", "*"],
    valueKind: "pointer",
    pointerDepth: 1,
    ownership: { kind: "borrowed" },
  },
  uint32_t: {
    tokens: ["uint32_t"],
    valueKind: "scalar",
    pointerDepth: 0,
    ownership: { kind: "not-applicable" },
  },
});

const DEBUGGER_ALIAS_SPECS = deepFreeze(
  [
    {
      nativeName: "inspector.debugger-enable",
      hostName: "ex_hermes_debugger_enable",
      symbol: "ex_hermes_debugger_enable",
      returnType: "int",
      returnKind: "scalar",
      parameters: [["runtime", "ExactHermesRuntime *"]],
      disabledSentinel: "0",
      windowsSentinel: "0",
      sourceEnabledTokens: [
        "auto debugger = snapshotDebugger(runtime);",
        "handle->debugger_attached.store(true, std::memory_order_release);",
        "return 1;",
      ],
      windowsTokens: ["(void)runtime;", "return 0;"],
    },
    {
      nativeName: "inspector.debugger-eval",
      hostName: "ex_hermes_debugger_eval",
      symbol: "ex_hermes_debugger_eval",
      returnType: "char *",
      returnKind: "pointer",
      parameters: [
        ["runtime", "ExactHermesRuntime *"],
        ["expression", "const char *"],
        ["frame_index", "uint32_t"],
      ],
      disabledSentinel: "null",
      windowsSentinel: "null",
      sourceEnabledTokens: [
        "auto debugger = snapshotDebugger(runtime);",
        "debugger->evalWhilePaused(",
        'rt.evaluateJavaScript(buffer, "<cdp>")',
        "malloc(result.size() + 1)",
        "auto json = runOnRuntimeThread(",
        "malloc(json.size() + 1)",
        "return heap;",
      ],
      windowsTokens: [
        "(void)runtime;",
        "(void)expression;",
        "(void)frame_index;",
        "return nullptr;",
      ],
    },
    {
      nativeName: "inspector.debugger-get-script-source",
      hostName: "ex_hermes_debugger_get_script_source",
      symbol: "ex_hermes_debugger_get_script_source",
      returnType: "char *",
      returnKind: "pointer",
      parameters: [
        ["runtime", "ExactHermesRuntime *"],
        ["script_id", "uint32_t"],
      ],
      disabledSentinel: "null",
      windowsSentinel: "null",
      sourceEnabledTokens: [
        "auto source = withDebuggerOnRuntimeThread(",
        "handle->sources_by_name.find(it->second)",
        "malloc(source.size() + 1)",
        "memcpy(heap, source.data(), source.size());",
        "return heap;",
      ],
      windowsTokens: ["(void)runtime;", "(void)script_id;", "return nullptr;"],
    },
    {
      nativeName: "inspector.debugger-get-scripts",
      hostName: "ex_hermes_debugger_get_scripts",
      symbol: "ex_hermes_debugger_get_scripts",
      returnType: "char *",
      returnKind: "pointer",
      parameters: [["runtime", "ExactHermesRuntime *"]],
      disabledSentinel: "null",
      windowsSentinel: "null",
      sourceEnabledTokens: [
        "auto json = withDebuggerOnRuntimeThread(",
        "debugger.getLoadedScripts()",
        "malloc(json.size() + 1)",
        "memcpy(heap, json.data(), json.size());",
        "return heap;",
      ],
      windowsTokens: ["(void)runtime;", "return nullptr;"],
    },
    {
      nativeName: "inspector.debugger-next-event",
      hostName: "ex_hermes_debugger_next_event",
      symbol: "ex_hermes_debugger_next_event",
      returnType: "char *",
      returnKind: "pointer",
      parameters: [["runtime", "ExactHermesRuntime *"]],
      disabledSentinel: "null",
      windowsSentinel: "null",
      sourceEnabledTokens: [
        "runtime->debug_events.empty()",
        "runtime->debug_events.pop_front();",
        "malloc(event.size() + 1)",
        "memcpy(heap, event.data(), event.size());",
        "return heap;",
      ],
      windowsTokens: ["(void)runtime;", "return nullptr;"],
    },
    {
      nativeName: "inspector.debugger-set-breakpoint",
      hostName: "ex_hermes_debugger_set_breakpoint",
      symbol: "ex_hermes_debugger_set_breakpoint",
      returnType: "char *",
      returnKind: "pointer",
      parameters: [
        ["runtime", "ExactHermesRuntime *"],
        ["script_id", "uint32_t"],
        ["line_number", "uint32_t"],
        ["column_number", "uint32_t"],
        ["condition", "const char *"],
      ],
      disabledSentinel: "null",
      windowsSentinel: "null",
      sourceEnabledTokens: [
        "auto json = withDebuggerOnRuntimeThread(",
        "debugger.setBreakpoint(loc)",
        "debugger.getBreakpointInfo(id)",
        "malloc(json.size() + 1)",
        "memcpy(heap, json.data(), json.size());",
        "return heap;",
      ],
      windowsTokens: [
        "(void)runtime;",
        "(void)script_id;",
        "(void)line_number;",
        "(void)column_number;",
        "(void)condition;",
        "return nullptr;",
      ],
    },
  ].sort((left, right) => compareText(left.nativeName, right.nativeName)),
);

export const DEBUGGER_NATIVE_ALIAS_SURFACES = Object.freeze(
  DEBUGGER_ALIAS_SPECS.map((spec) => spec.nativeName),
);

const REQUIRED_SOURCE_PATHS = Object.freeze([
  SOURCE_HERMES_PATH,
  WINDOWS_PATH,
  HERMES_RUST_PATH,
  CDP_RUST_PATH,
  RUNTIME_RUST_PATH,
]);

// This is the complete Rust module corpus that can participate in the `ibex`
// binary today. A new module must be reviewed and added here before the exact
// native-symbol reachability proof can pass.
const REVIEWED_BINARY_RUST_PATHS = Object.freeze([
  "src/bin/ibex/agent_logs.rs",
  "src/bin/ibex/cdp/mod.rs",
  "src/bin/ibex/cli.rs",
  "src/bin/ibex/compat/discovery.rs",
  "src/bin/ibex/compat/expectations.rs",
  "src/bin/ibex/compat/manifest.rs",
  "src/bin/ibex/compat/mod.rs",
  "src/bin/ibex/compat/probe.rs",
  "src/bin/ibex/compat/reporter.rs",
  "src/bin/ibex/compat/runner.rs",
  "src/bin/ibex/compat/types.rs",
  "src/bin/ibex/direct_execution_interrupt.rs",
  "src/bin/ibex/engine/capsec_builtin_effects_output_batch.test.rs",
  "src/bin/ibex/engine/capsec_builtin_noncap_closed_output_batch.test.rs",
  "src/bin/ibex/engine/capsec_closed_control_output_batch.test.rs",
  "src/bin/ibex/engine/capsec_conformance_batch.rs",
  "src/bin/ibex/engine/capsec_cwd_facade_batch.test.rs",
  "src/bin/ibex/engine/capsec_exact_fixture_evidence_batch.rs",
  "src/bin/ibex/engine/capsec_global_callable_batch.test.rs",
  "src/bin/ibex/engine/capsec_host_abi_output_batch.test.rs",
  "src/bin/ibex/engine/capsec_inherited_intrinsic_alias_batch.test.rs",
  "src/bin/ibex/engine/capsec_native_freeze_output_batch.test.rs",
  "src/bin/ibex/engine/capsec_output_shape_sweep_batch.test.rs",
  "src/bin/ibex/engine/capsec_portable_public_batch.rs",
  "src/bin/ibex/engine/capsec_public_builtin_batch.rs",
  "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs",
  "src/bin/ibex/engine/capsec_public_closed_batch.rs",
  "src/bin/ibex/engine/capsec_public_noncap_builtin_batch.rs",
  "src/bin/ibex/engine/capsec_public_startup_batch.rs",
  "src/bin/ibex/engine/capsec_public_startup_environment_batch.test.rs",
  "src/bin/ibex/engine/capsec_public_target_absence_batch.rs",
  "src/bin/ibex/engine/hermes.rs",
  "src/bin/ibex/engine/mod.rs",
  "src/bin/ibex/history.rs",
  "src/bin/ibex/host.rs",
  "src/bin/ibex/main.rs",
  "src/bin/ibex/repl/mod.rs",
  "src/bin/ibex/repl/session.rs",
  "src/bin/ibex/repl_surface.rs",
  "src/bin/ibex/runtime.rs",
  "src/bin/ibex/runtime_tests.rs",
  "src/bin/ibex/session_semantics_conformance.rs",
  "src/bin/ibex/session_worker.rs",
  "src/bin/ibex/session_worker/bounded_lane.rs",
  "src/bin/ibex/session_worker_runtime.rs",
  "src/bin/ibex/sfe.rs",
  "src/bin/ibex/subprocess.rs",
  "src/bin/ibex/terminal_session.rs",
]);

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value))
    return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

function sourceMap(value, label) {
  const entries =
    value instanceof Map ? [...value.entries()] : Object.entries(value ?? {});
  const result = new Map();
  for (const [sourcePath, source] of entries) {
    requireCondition(
      typeof sourcePath === "string" &&
        sourcePath.length > 0 &&
        typeof source === "string",
      `${label}: malformed source row`,
    );
    requireCondition(
      !result.has(sourcePath),
      `${label}: duplicate source ${sourcePath}`,
    );
    result.set(sourcePath, source);
  }
  return result;
}

/** Remove Rust/C++ trivia while retaining quoted contents and token order. */
function compactSource(source, label, { nestedBlockComments }) {
  requireCondition(typeof source === "string", `${label}: expected source`);
  let result = "";
  let index = 0;

  const quotedEnd = (start, quote) => {
    let cursor = start + 1;
    while (cursor < source.length) {
      if (source[cursor] === "\\") cursor += 2;
      else if (source[cursor] === quote) return cursor + 1;
      else cursor += 1;
    }
    throw new Error(`${label}: unterminated ${quote} literal`);
  };

  const rustRawStringEnd = (start) => {
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
    const rawEnd = nestedBlockComments ? rustRawStringEnd(index) : null;
    if (rawEnd !== null) {
      result += source.slice(index, rawEnd);
      index = rawEnd;
      continue;
    }
    if (/\s/u.test(source[index])) {
      do index += 1;
      while (index < source.length && /\s/u.test(source[index]));
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
        if (nestedBlockComments && source.startsWith("/*", cursor)) {
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
    const rustCharacter =
      nestedBlockComments &&
      source[index] === "'" &&
      /^'(?:\\(?:.|x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\})|[^\\'\r\n])'/u.test(
        source.slice(index),
      );
    if (
      source[index] === '"' ||
      (!nestedBlockComments && source[index] === "'") ||
      rustCharacter
    ) {
      const end = quotedEnd(index, source[index]);
      result += source.slice(index, end);
      index = end;
      continue;
    }
    result += source[index];
    index += 1;
  }
  return result;
}

const compactRust = (source, label) =>
  compactSource(source, label, { nestedBlockComments: true });
const compactCpp = (source, label) =>
  compactSource(source, label, { nestedBlockComments: false });

function matchingBrace(source, openIndex, label) {
  requireCondition(source[openIndex] === "{", `${label}: missing open brace`);
  let depth = 1;
  let index = openIndex + 1;
  while (index < source.length) {
    if (source[index] === '"' || source[index] === "'") {
      const quote = source[index];
      index += 1;
      while (index < source.length) {
        if (source[index] === "\\") index += 2;
        else if (source[index] === quote) {
          index += 1;
          break;
        } else index += 1;
      }
      continue;
    }
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
    index += 1;
  }
  throw new Error(`${label}: unterminated braced region`);
}

function occurrences(source, token) {
  let count = 0;
  let offset = 0;
  while (true) {
    const found = source.indexOf(token, offset);
    if (found === -1) return count;
    count += 1;
    offset = found + token.length;
  }
}

function identifierOccurrences(source, identifier) {
  // The trivia compactor deliberately removes whitespace, so a declaration's
  // return type may abut its identifier. These exact C ABI names are not
  // prefixes of one another; substring counting therefore preserves both the
  // declaration and reference while still catching aliases/function pointers.
  return occurrences(source, identifier);
}

function exactOccurrence(source, token, expected, label) {
  const count = occurrences(source, token);
  requireCondition(
    count === expected,
    `${label}: expected ${expected} occurrences of ${token}, got ${count}`,
  );
}

function orderedTokens(source, tokens, compact, label) {
  let offset = 0;
  const matched = [];
  for (const token of tokens) {
    const normalized = compact(token, `${label} token`);
    const found = source.indexOf(normalized, offset);
    requireCondition(found !== -1, `${label}: missing source token ${token}`);
    matched.push(normalized);
    offset = found + normalized.length;
  }
  return matched;
}

function extractRegion(source, startToken, label) {
  const start = source.indexOf(startToken);
  requireCondition(start !== -1, `${label}: missing region ${startToken}`);
  requireCondition(
    source.indexOf(startToken, start + startToken.length) === -1,
    `${label}: duplicate region ${startToken}`,
  );
  const open = source.indexOf("{", start + startToken.length);
  requireCondition(open !== -1, `${label}: region has no body`);
  return source.slice(start, matchingBrace(source, open, label) + 1);
}

function extractCppFunction(compact, symbol, label) {
  const definitionCount = identifierOccurrences(compact, symbol);
  requireCondition(
    definitionCount === 1,
    `${label}: expected one definition of ${symbol}, got ${definitionCount}`,
  );
  const symbolStart = compact.indexOf(symbol);
  const declarationStart = compact.lastIndexOf('extern"C"', symbolStart);
  requireCondition(
    declarationStart !== -1,
    `${label}: ${symbol} lacks extern C definition`,
  );
  const open = compact.indexOf("{", symbolStart + symbol.length);
  requireCondition(open !== -1, `${label}: ${symbol} has no body`);
  return compact.slice(
    declarationStart,
    matchingBrace(compact, open, `${label}:${symbol}`) + 1,
  );
}

function exactPairMap(rows, keyFor, expectedKeys, label) {
  requireCondition(Array.isArray(rows), `${label}: expected rows`);
  const expected = new Set(expectedKeys);
  const result = new Map();
  for (const row of rows) {
    const key = keyFor(row);
    if (!expected.has(key)) continue;
    requireCondition(!result.has(key), `${label}: duplicate ${key}`);
    result.set(key, row);
  }
  requireCondition(
    canonicalJson([...result.keys()].sort(compareText)) ===
      canonicalJson([...expected].sort(compareText)),
    `${label}: expected exact set ${[...expected].sort(compareText).join(", ")}`,
  );
  return result;
}

function sourceRefsFor(spec) {
  return [
    `${SOURCE_HERMES_PATH}#${spec.symbol}`,
    `${WINDOWS_PATH}#${spec.symbol}`,
  ];
}

function structuralSourceRefs(spec) {
  return [
    ...sourceRefsFor(spec),
    `${HERMES_RUST_PATH}#ffi:${spec.symbol}`,
    `${HERMES_RUST_PATH}#HermesCdpBackend`,
    `${HERMES_RUST_PATH}#HermesEngine::maybe_enable_debugger`,
    `${HERMES_RUST_PATH}#HermesEngine::start_inspector`,
    `${HERMES_RUST_PATH}#HermesEngine::unarmed_inspector_authorization`,
    `${CDP_RUST_PATH}#start_server:requires-UnarmedInspectorAuthorization`,
    `${RUNTIME_RUST_PATH}#Runtime::start_inspector:armed-sink-guard`,
  ].sort(compareText);
}

function parameterContract([name, canonical], index) {
  const descriptor = TYPE_DESCRIPTORS[canonical];
  requireCondition(descriptor, `${name}: unsupported ABI parameter type`);
  return {
    index,
    name,
    ownership: structuredClone(descriptor.ownership),
    pointerDepth: descriptor.pointerDepth,
    role: "input",
    type: { canonical, tokens: [...descriptor.tokens] },
    valueKind: descriptor.valueKind,
  };
}

function recognizedReturnOwnership(contract, spec, label) {
  if (spec.returnKind === "scalar") {
    requireCondition(
      contract.status === "resolved" &&
        canonicalJson(contract.unresolved) === canonicalJson([]) &&
        canonicalJson(contract.return?.ownership) ===
          canonicalJson({ kind: "not-applicable" }),
      `${label}: scalar return ownership drifted`,
    );
    return { kind: "not-applicable" };
  }

  const ownership = contract.return?.ownership;
  const unresolved =
    ownership?.kind === "unknown" &&
    contract.status === "unresolved" &&
    canonicalJson(contract.unresolved) ===
      canonicalJson(["return-pointer-ownership"]);
  const callerOwned =
    ownership?.kind === "caller-owned" &&
    ownership.releaseFunction === "ex_hermes_free_string" &&
    contract.status === "resolved" &&
    canonicalJson(contract.unresolved) === canonicalJson([]);
  requireCondition(
    unresolved || callerOwned,
    `${label}: pointer return ownership is neither exact unresolved evidence nor ex_hermes_free_string ownership`,
  );
  return structuredClone(ownership);
}

function expectedOutputContract(spec, sourceRef, ownership, status) {
  return {
    bufferLengthPairs: [],
    functionName: spec.hostName,
    language: "c++",
    outputChannels: [
      {
        kind: spec.returnKind,
        ownership: structuredClone(ownership),
        role: "return",
        selector: "[[return]]",
      },
    ],
    parameters: spec.parameters.map(parameterContract),
    return: {
      kind: spec.returnKind,
      ownership: structuredClone(ownership),
      role: "value",
      type: {
        canonical: spec.returnType,
        tokens: spec.returnType === "int" ? ["int"] : ["char", "*"],
      },
    },
    schema: HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
    sourceRef,
    status,
    unresolved: status === "resolved" ? [] : ["return-pointer-ownership"],
  };
}

function validateCompanionSurface(surface, spec) {
  const refs = sourceRefsFor(spec);
  requireCondition(
    surface.kind === "host-abi" &&
      surface.name === spec.hostName &&
      surface.observedKey === `host-abi:${spec.hostName}` &&
      canonicalJson(surface.sourceRefs) === canonicalJson(refs),
    `${spec.nativeName}: companion Host ABI identity drifted`,
  );

  const variants = [
    ["default", refs[0]],
    ["windows", refs[1]],
  ];
  const expectedBranches = variants.map(([targetVariant, sourceRef]) => ({
    id: targetVariant,
    kind: "alternative",
    sourceRefs: [sourceRef],
    stubDisposition: "not-structurally-proven",
    targetVariant,
  }));
  const contracts = surface.metadata?.outputContracts;
  requireCondition(
    Array.isArray(contracts) && contracts.length === 2,
    `${spec.nativeName}: companion Host ABI lacks two output contracts`,
  );
  const ownershipStates = contracts.map((contract, index) =>
    recognizedReturnOwnership(
      contract,
      spec,
      `${spec.hostName}:${variants[index][0]}`,
    ),
  );
  requireCondition(
    canonicalJson(ownershipStates[0]) === canonicalJson(ownershipStates[1]),
    `${spec.nativeName}: companion target ownership contracts disagree`,
  );
  const status = contracts[0].status;
  requireCondition(
    contracts.every((contract) => contract.status === status),
    `${spec.nativeName}: companion target contract status disagrees`,
  );
  const expectedContracts = variants.map(([, sourceRef]) =>
    expectedOutputContract(spec, sourceRef, ownershipStates[0], status),
  );
  const expectedDefinitions = variants.map(
    ([targetVariant, sourceRef], index) => ({
      language: "c++",
      outputContract: expectedContracts[index],
      sourceRef,
      targetVariant,
      unsafe: false,
      weak: false,
    }),
  );
  const expectedMetadata = {
    alternatives: expectedBranches,
    branches: expectedBranches,
    definitions: expectedDefinitions,
    outputContracts: expectedContracts,
    provenanceLimitation:
      "ABI definitions are source-structural evidence; supported/unsupported target semantics require fixtures.",
  };
  requireCondition(
    canonicalJson(surface.metadata) === canonicalJson(expectedMetadata),
    `${spec.nativeName}: companion Host ABI output contracts or target bindings drifted`,
  );

  const derived = deriveHostAbiOutputCatalogAccount(surface);
  requireCondition(
    derived.status === "output-bearing" &&
      derived.reasonCode === "source-derived-host-abi-output" &&
      derived.membershipUnresolved.length === 0 &&
      derived.outputChannels.length === 1 &&
      derived.outputChannels[0].selector === "[[return]]" &&
      canonicalJson(derived.outputChannels[0].sourceRefs) ===
        canonicalJson(refs) &&
      derived.outputChannels[0].variants.length === 2,
    `${spec.nativeName}: companion Host ABI is not an exact output-bearing return account`,
  );
  return derived;
}

function validateCoverageEdge(edge, kind, name) {
  requireCondition(
    typeof edge?.id === "string" &&
      edge.id.length > 0 &&
      edge.surface?.kind === kind &&
      edge.surface.name === name,
    `${kind}:${name}: coverage edge drifted`,
  );
  return edge;
}

function auditCppBranches(requiredSources) {
  const sourceHermes = compactCpp(
    requiredSources.get(SOURCE_HERMES_PATH),
    SOURCE_HERMES_PATH,
  );
  const windows = compactCpp(requiredSources.get(WINDOWS_PATH), WINDOWS_PATH);
  orderedTokens(
    sourceHermes,
    [
      "#if defined(HERMES_ENABLE_DEBUGGER) && EXACT_HAS_HERMES_ASYNC_DEBUGGER",
      "#define EXACT_COMPILE_HERMES_DEBUGGER 1",
      '#include "hermes_runtime_templates.inl"',
      "#else",
      "#define EXACT_COMPILE_HERMES_DEBUGGER 0",
      "#endif",
    ],
    compactCpp,
    "source-Hermes debugger compile branch",
  );

  return new Map(
    DEBUGGER_ALIAS_SPECS.map((spec) => {
      const sourceRegion = extractCppFunction(
        sourceHermes,
        spec.symbol,
        SOURCE_HERMES_PATH,
      );
      const windowsRegion = extractCppFunction(
        windows,
        spec.symbol,
        WINDOWS_PATH,
      );
      const disabledReturn =
        spec.disabledSentinel === "0" ? "return 0;" : "return nullptr;";
      const sourceMatched = orderedTokens(
        sourceRegion,
        [
          "#if !EXACT_COMPILE_HERMES_DEBUGGER",
          disabledReturn,
          "#else",
          ...spec.sourceEnabledTokens,
          "#endif",
        ],
        compactCpp,
        `${spec.symbol}: source-Hermes branches`,
      );
      const windowsMatched = orderedTokens(
        windowsRegion,
        spec.windowsTokens,
        compactCpp,
        `${spec.symbol}: Windows stub`,
      );
      const sourceDigest = taggedDigest({
        path: SOURCE_HERMES_PATH,
        symbol: spec.symbol,
        matched: sourceMatched,
        region: sourceRegion,
      });
      const windowsDigest = taggedDigest({
        path: WINDOWS_PATH,
        symbol: spec.symbol,
        matched: windowsMatched,
        region: windowsRegion,
      });
      return [
        spec.nativeName,
        {
          branches: [
            {
              id: "source-hermes:debugger-disabled",
              targetVariant: "default",
              sourceRef: `${SOURCE_HERMES_PATH}#${spec.symbol}`,
              returnSentinel: spec.disabledSentinel,
              outputOwnerObservedKey: `host-abi:${spec.hostName}`,
              proofDigest: sourceDigest,
            },
            {
              id: "source-hermes:debugger-enabled",
              targetVariant: "default",
              sourceRef: `${SOURCE_HERMES_PATH}#${spec.symbol}`,
              returnSentinel: "implementation-value-or-failure-sentinel",
              outputOwnerObservedKey: `host-abi:${spec.hostName}`,
              proofDigest: sourceDigest,
            },
            {
              id: "windows-stub",
              targetVariant: "windows",
              sourceRef: `${WINDOWS_PATH}#${spec.symbol}`,
              returnSentinel: spec.windowsSentinel,
              outputOwnerObservedKey: `host-abi:${spec.hostName}`,
              proofDigest: windowsDigest,
            },
          ],
          proofDigest: taggedDigest({ sourceDigest, windowsDigest }),
        },
      ];
    }),
  );
}

function auditGuardAndRustReachability(requiredSources, binaryRustSources) {
  for (const rustPath of [HERMES_RUST_PATH, CDP_RUST_PATH, RUNTIME_RUST_PATH]) {
    requireCondition(
      binaryRustSources.has(rustPath),
      `debugger native alias Rust audit lacks ${rustPath}`,
    );
    requireCondition(
      binaryRustSources.get(rustPath) === requiredSources.get(rustPath),
      `debugger native alias source differs for ${rustPath}`,
    );
  }
  const compactByPath = new Map(
    [...binaryRustSources].map(([sourcePath, source]) => [
      sourcePath,
      compactRust(source, sourcePath),
    ]),
  );
  const hermes = compactByPath.get(HERMES_RUST_PATH);
  const cdp = compactByPath.get(CDP_RUST_PATH);
  const runtime = compactByPath.get(RUNTIME_RUST_PATH);
  const hostAbiOutputTest = compactByPath.get(HOST_ABI_OUTPUT_TEST_PATH);
  requireCondition(
    typeof hostAbiOutputTest === "string",
    `debugger native alias Rust audit lacks ${HOST_ABI_OUTPUT_TEST_PATH}`,
  );
  const publicClosedTest = compactByPath.get(PUBLIC_CLOSED_TEST_PATH);
  requireCondition(
    typeof publicClosedTest === "string",
    `debugger native alias Rust audit lacks ${PUBLIC_CLOSED_TEST_PATH}`,
  );

  // The conformance-only Host-ABI executor is compiled solely as a Rust test
  // child module. It may call the exported debugger ABI to observe its real
  // return values, but it must construct the explicitly diagnostic runtime and
  // keep every debugger symbol reference inside that one bounded executor.
  const diagnosticRuntimeConstructor = extractRegion(
    hostAbiOutputTest,
    compactRust(
      "impl OwnedDiagnosticRuntime {\n    fn new() -> Result<Self, String>",
      "Host ABI diagnostic runtime constructor token",
    ),
    "Host ABI diagnostic runtime constructor",
  );
  const diagnosticRuntimeMatched = orderedTokens(
    diagnosticRuntimeConstructor,
    [
      "fresh_legacy_host();",
      "let raw = unsafe { ex_hermes_create_diagnostic() };",
      "if raw.is_null()",
    ],
    compactRust,
    "Host ABI diagnostic runtime constructor",
  );
  const diagnosticOutputExecutor = extractRegion(
    hostAbiOutputTest,
    compactRust(
      "fn execute_hermes_diagnostic(function_name: &str, selector: &str) -> Result<Value, String>",
      "Host ABI diagnostic output executor token",
    ),
    "Host ABI diagnostic output executor",
  );
  const diagnosticOutputMatched = orderedTokens(
    diagnosticOutputExecutor,
    [
      "let runtime = OwnedDiagnosticRuntime::new()?;",
      '"ex_hermes_debugger_enable" =>',
      '"ex_hermes_debugger_eval" =>',
      '"ex_hermes_debugger_get_script_source" =>',
      '"ex_hermes_debugger_get_scripts" =>',
      '"ex_hermes_debugger_next_event" =>',
      '"ex_hermes_debugger_set_breakpoint" =>',
    ],
    compactRust,
    "Host ABI diagnostic output executor",
  );
  const closedDebuggerMap = extractRegion(
    publicClosedTest,
    compactRust(
      "fn reviewed_debugger_abi(function_name: &str) -> Option<(&'static str, &'static str)>",
      "closed debugger ABI map token",
    ),
    "closed debugger ABI map",
  );
  const closedDebuggerExecutor = extractRegion(
    publicClosedTest,
    compactRust(
      "async fn execute_closed_debugger_abi(",
      "closed debugger ABI executor token",
    ),
    "closed debugger ABI executor",
  );
  const closedDebuggerMatched = orderedTokens(
    closedDebuggerExecutor,
    [
      "begin_installed_conformance_observation",
      "engine.eval_immediate",
      "engine.ensure_runtime()",
      "ex_hermes_debugger_enable(raw)",
      'match function_name.as_str()',
      '"ex_hermes_debugger_eval" =>',
      '"ex_hermes_debugger_get_script_source" =>',
      '"ex_hermes_debugger_get_scripts" =>',
      '"ex_hermes_debugger_next_event" =>',
      '"ex_hermes_debugger_set_breakpoint" =>',
      '"ex_hermes_debugger_next_event after closed call"',
    ],
    compactRust,
    "closed debugger ABI executor",
  );

  const runtimeSink = extractRegion(
    runtime,
    compactRust(
      "pub async fn start_inspector(&self, host: &str, port: u16) -> Result<()>",
      "Runtime::start_inspector token",
    ),
    "Runtime::start_inspector",
  );
  const runtimeMatched = orderedTokens(
    runtimeSink,
    [
      "if self.host.armed_snapshot().is_some()",
      "anyhow::bail!(ARMED_INSPECTOR_CLOSED_MESSAGE);",
      "self.engine.start_inspector(host, port).await",
    ],
    compactRust,
    "Runtime armed inspector sink",
  );

  exactOccurrence(
    hermes,
    compactRust(
      "UnarmedInspectorAuthorization(())",
      "authorization constructor token",
    ),
    3,
    "private inspector authorization constructors",
  );
  orderedTokens(
    hermes,
    [
      "pub(crate) struct UnarmedInspectorAuthorization(())",
      "#[cfg(test)]",
      "pub(crate) const fn unarmed_inspector_authorization_for_test() -> UnarmedInspectorAuthorization",
      "UnarmedInspectorAuthorization(())",
      "fn unarmed_inspector_authorization(&self) -> Result<UnarmedInspectorAuthorization>",
    ],
    compactRust,
    "private inspector authorization declaration",
  );
  const engineGuard = extractRegion(
    hermes,
    compactRust(
      "fn unarmed_inspector_authorization(&self) -> Result<UnarmedInspectorAuthorization>",
      "engine guard token",
    ),
    "HermesEngine::unarmed_inspector_authorization",
  );
  const engineGuardMatched = orderedTokens(
    engineGuard,
    [
      "if self.armed_snapshot_digest.is_some()",
      "anyhow::bail!(ARMED_INSPECTOR_CLOSED_MESSAGE);",
      "Ok(UnarmedInspectorAuthorization(()))",
    ],
    compactRust,
    "Hermes armed inspector sink",
  );

  const engineStart = extractRegion(
    hermes,
    compactRust(
      "async fn start_inspector(&self, host: &str, port: u16) -> Result<()>",
      "engine start token",
    ),
    "HermesEngine::start_inspector",
  );
  const engineStartMatched = orderedTokens(
    engineStart,
    [
      "let authorization = self.unarmed_inspector_authorization()?;",
      "let mut handle = self.cdp_handle.lock().await;",
      "let runtime = self.ensure_runtime().await?;",
      "Arc::new(HermesCdpBackend::new(",
      "self.debugger_requested.clone()",
      "cdp::start_server(&authorization, host, port, backend)?;",
    ],
    compactRust,
    "guard before debugger backend and listener",
  );
  exactOccurrence(
    hermes,
    compactRust("HermesCdpBackend::new(", "backend constructor token"),
    1,
    "Hermes CDP backend construction",
  );
  exactOccurrence(
    hermes,
    compactRust("HermesCdpBackend {", "backend literal token"),
    3,
    "Hermes CDP backend type and literal sites",
  );
  exactOccurrence(
    hermes,
    compactRust(
      "self.debugger_requested.clone()",
      "debugger request clone token",
    ),
    1,
    "debugger request ownership transfer",
  );
  exactOccurrence(
    hermes,
    compactRust("cdp::start_server(", "listener call token"),
    1,
    "CDP listener production call",
  );
  exactOccurrence(
    hermes,
    compactRust(
      "self.debugger_requested.store(true, Ordering::SeqCst)",
      "debugger requested mutation token",
    ),
    1,
    "debugger request enable mutation",
  );
  exactOccurrence(
    hermes,
    compactRust(
      "debugger_requested: Arc::new(AtomicBool::new(false))",
      "debugger requested initialization token",
    ),
    1,
    "debugger request initialization",
  );

  const backend = extractRegion(
    hermes,
    compactRust(
      "impl CdpBackend for HermesCdpBackend",
      "Hermes CdpBackend token",
    ),
    "HermesCdpBackend implementation",
  );
  orderedTokens(
    backend,
    [
      "fn enable(&self) -> bool",
      "self.debugger_requested.store(true, Ordering::SeqCst);",
      "fn get_scripts(&self)",
      "fn get_script_source(&self",
      "fn set_breakpoint(",
      "fn next_event(&self)",
      "fn eval(&self",
    ],
    compactRust,
    "guarded debugger backend methods",
  );
  const maybeEnable = extractRegion(
    hermes,
    compactRust(
      "async fn maybe_enable_debugger(&self) -> Result<()>",
      "maybe enable debugger token",
    ),
    "HermesEngine::maybe_enable_debugger",
  );
  orderedTokens(
    maybeEnable,
    [
      "if !self.debugger_requested.load(Ordering::SeqCst)",
      "return Ok(());",
      "ex_hermes_debugger_enable(raw)",
    ],
    compactRust,
    "debugger enable request gate",
  );

  const cdpStart = extractRegion(
    cdp,
    compactRust("pub fn start_server(", "CDP start token"),
    "cdp::start_server",
  );
  const cdpMatched = orderedTokens(
    cdpStart,
    [
      "_authorization: &crate::engine::hermes::UnarmedInspectorAuthorization",
      "socket.bind(&addr.into())",
      "socket.listen(128)?;",
      "runtime.block_on(run_server(",
    ],
    compactRust,
    "CDP listener authorization",
  );
  exactOccurrence(
    cdp,
    compactRust(
      "crate::engine::hermes::UnarmedInspectorAuthorization",
      "CDP authorization type token",
    ),
    1,
    "CDP listener authorization type",
  );

  const allRust = [...compactByPath.entries()];
  const symbolEvidence = new Map();
  for (const spec of DEBUGGER_ALIAS_SPECS) {
    let total = 0;
    const sites = [];
    for (const [sourcePath, source] of allRust) {
      const count = identifierOccurrences(source, spec.symbol);
      total += count;
      if (count > 0) sites.push({ path: sourcePath, count });
    }
    const diagnosticTestCount =
      spec.symbol === "ex_hermes_debugger_enable" ? 7 : 2;
    const closedTestCount =
      spec.symbol === "ex_hermes_debugger_next_event" ? 5 : 3;
    requireCondition(
      identifierOccurrences(diagnosticOutputExecutor, spec.symbol) ===
        diagnosticTestCount &&
        identifierOccurrences(hostAbiOutputTest, spec.symbol) ===
          diagnosticTestCount &&
        identifierOccurrences(closedDebuggerMap, spec.symbol) +
            identifierOccurrences(closedDebuggerExecutor, spec.symbol) ===
          closedTestCount &&
        identifierOccurrences(publicClosedTest, spec.symbol) ===
          closedTestCount &&
        total === 2 + diagnosticTestCount + closedTestCount &&
        sites.length === 3 &&
        sites.some(
          (site) =>
            site.path === HERMES_RUST_PATH &&
            site.count === 2,
        ) &&
        sites.some(
          (site) =>
            site.path === HOST_ABI_OUTPUT_TEST_PATH &&
            site.count === diagnosticTestCount,
        ) &&
        sites.some(
          (site) =>
            site.path === PUBLIC_CLOSED_TEST_PATH &&
            site.count === closedTestCount,
        ),
      `${spec.nativeName}: expected one Rust declaration, one guarded production call, and only the bounded diagnostic/closed-target test calls of ${spec.symbol}`,
    );
    const backendCount = identifierOccurrences(backend, spec.symbol);
    const enableCount = identifierOccurrences(maybeEnable, spec.symbol);
    requireCondition(
      spec.symbol === "ex_hermes_debugger_enable"
        ? backendCount === 0 && enableCount === 1
        : backendCount === 1 && enableCount === 0,
      `${spec.nativeName}: Rust call escaped its guarded debugger owner`,
    );
    symbolEvidence.set(
      spec.nativeName,
      taggedDigest({
        symbol: spec.symbol,
        sites,
        backendCount,
        enableCount,
      }),
    );
  }

  return {
    sharedProofDigest: taggedDigest({
      runtimeMatched,
      engineGuardMatched,
      engineStartMatched,
      cdpMatched,
      diagnosticRuntimeMatched,
      diagnosticOutputMatched,
      closedDebuggerMatched,
    }),
    assertions: [
      {
        id: "runtime-armed-inspector-sink",
        path: RUNTIME_RUST_PATH,
        digest: taggedDigest(runtimeMatched),
      },
      {
        id: "engine-private-unarmed-authorization",
        path: HERMES_RUST_PATH,
        digest: taggedDigest({ engineGuardMatched, engineStartMatched }),
      },
      {
        id: "listener-requires-unarmed-authorization",
        path: CDP_RUST_PATH,
        digest: taggedDigest(cdpMatched),
      },
      {
        id: "test-only-diagnostic-output-executor",
        path: HOST_ABI_OUTPUT_TEST_PATH,
        digest: taggedDigest({
          diagnosticRuntimeMatched,
          diagnosticOutputMatched,
        }),
      },
      {
        id: "test-only-closed-debugger-executor",
        path: PUBLIC_CLOSED_TEST_PATH,
        digest: taggedDigest({ closedDebuggerMatched }),
      },
    ],
    symbolEvidence,
  };
}

function expectedCompanionCatalogAccount(hostEdge, hostSurface, derived) {
  return {
    surfaceId: hostEdge.id,
    status: "output-bearing",
    reasonCode: "source-derived-host-abi-output",
    sourceRefs: [...hostSurface.sourceRefs],
    outputKinds: derived.outputChannels.map((channel) => channel.selector),
  };
}

function expectedCompanionCatalogRow(hostEdge, hostSurface, derived) {
  const channel = derived.outputChannels[0];
  return {
    key: {
      surfaceId: hostEdge.id,
      output: "[[return]]",
      alias: hostSurface.name,
      mode: "all",
      sourceKind: "host-abi",
      returnVariant: "default",
      contextId: "host.private-native-call-initialized",
    },
    discovery: {
      kind: "source-inventory-surface",
      observedKeys: [hostSurface.observedKey],
      sourceRefs: [...channel.sourceRefs],
    },
    requiredValueProof: "live-value-observation",
  };
}

function validateAudit(sourceAudit) {
  requireCondition(
    sourceAudit?.structuralAccountSchema ===
      DEBUGGER_NATIVE_ALIAS_STRUCTURAL_ACCOUNT_SCHEMA &&
      sourceAudit.reasonCode === DEBUGGER_NATIVE_ALIAS_STRUCTURAL_REASON_CODE &&
      canonicalJson(
        Object.keys(sourceAudit.surfaces ?? {}).sort(compareText),
      ) === canonicalJson(DEBUGGER_NATIVE_ALIAS_SURFACES),
    "invalid debugger native alias structural audit",
  );
  return sourceAudit;
}

/**
 * Prove that the six native debugger rows are guarded aliases of the six
 * output-bearing Host ABI rows. This does not demote or close the Host ABI.
 */
export function auditDebuggerNativeAliasClosure({
  sourceFiles,
  binaryRustSources,
  surfaces,
  coverage,
}) {
  const required = sourceMap(sourceFiles, "debugger native alias sources");
  const binary = sourceMap(
    binaryRustSources,
    "debugger native alias binary Rust sources",
  );
  requireCondition(
    canonicalJson([...required.keys()].sort(compareText)) ===
      canonicalJson([...REQUIRED_SOURCE_PATHS].sort(compareText)),
    "debugger native alias audit requires the exact five-file source set",
  );
  requireCondition(
    canonicalJson([...binary.keys()].sort(compareText)) ===
      canonicalJson(REVIEWED_BINARY_RUST_PATHS),
    "debugger native alias audit binary Rust corpus differs from the reviewed exact path set",
  );

  const nativeObservedKeys = DEBUGGER_ALIAS_SPECS.map(
    (spec) => `native-op:${spec.nativeName}`,
  );
  const hostObservedKeys = DEBUGGER_ALIAS_SPECS.map(
    (spec) => `host-abi:${spec.hostName}`,
  );
  const surfaceByObservedKey = exactPairMap(
    surfaces,
    (surface) => surface?.observedKey,
    [...nativeObservedKeys, ...hostObservedKeys],
    "debugger native alias inventory pairs",
  );
  const edgeByObservedKey = exactPairMap(
    coverage?.edges,
    (edge) => `${edge?.surface?.kind}:${edge?.surface?.name}`,
    [...nativeObservedKeys, ...hostObservedKeys],
    "debugger native alias coverage pairs",
  );
  const cpp = auditCppBranches(required);
  const rust = auditGuardAndRustReachability(required, binary);

  const auditedSurfaces = Object.fromEntries(
    DEBUGGER_ALIAS_SPECS.map((spec) => {
      const nativeObservedKey = `native-op:${spec.nativeName}`;
      const hostObservedKey = `host-abi:${spec.hostName}`;
      const nativeSurface = surfaceByObservedKey.get(nativeObservedKey);
      const hostSurface = surfaceByObservedKey.get(hostObservedKey);
      const refs = sourceRefsFor(spec);
      requireCondition(
        nativeSurface.kind === "native-op" &&
          nativeSurface.name === spec.nativeName &&
          nativeSurface.observedKey === nativeObservedKey &&
          canonicalJson(nativeSurface.sourceRefs) === canonicalJson(refs) &&
          nativeSurface.metadata == null,
        `${spec.nativeName}: native alias inventory identity drifted`,
      );
      const nativeEdge = validateCoverageEdge(
        edgeByObservedKey.get(nativeObservedKey),
        "native-op",
        spec.nativeName,
      );
      const hostEdge = validateCoverageEdge(
        edgeByObservedKey.get(hostObservedKey),
        "host-abi",
        spec.hostName,
      );
      const derived = validateCompanionSurface(hostSurface, spec);
      const sourceRefs = structuralSourceRefs(spec);
      const implementationBranches = cpp.get(spec.nativeName).branches;
      const companionCatalogAccount = expectedCompanionCatalogAccount(
        hostEdge,
        hostSurface,
        derived,
      );
      const companionCatalogRow = expectedCompanionCatalogRow(
        hostEdge,
        hostSurface,
        derived,
      );
      const proofDigest = taggedDigest({
        nativeObservedKey,
        hostObservedKey,
        nativeSurfaceId: nativeEdge.id,
        hostSurfaceId: hostEdge.id,
        sourceRefs,
        implementationProof: cpp.get(spec.nativeName).proofDigest,
        rustProof: rust.sharedProofDigest,
        symbolProof: rust.symbolEvidence.get(spec.nativeName),
        companionCatalogAccount,
        companionCatalogRow,
      });
      return [
        spec.nativeName,
        {
          nativeObservedKey,
          nativeSurfaceId: nativeEdge.id,
          hostObservedKey,
          hostSurfaceId: hostEdge.id,
          symbol: spec.symbol,
          sourceRefs,
          implementationBranches,
          outputDependency: {
            surfaceObservedKey: hostObservedKey,
            selector: "[[return]]",
          },
          companionCatalogAccount,
          companionCatalogRow,
          proofDigest,
        },
      ];
    }),
  );

  return deepFreeze({
    structuralAccountSchema: DEBUGGER_NATIVE_ALIAS_STRUCTURAL_ACCOUNT_SCHEMA,
    reasonCode: DEBUGGER_NATIVE_ALIAS_STRUCTURAL_REASON_CODE,
    guardBinding: structuredClone(DEBUGGER_NATIVE_ALIAS_GUARD_BINDING),
    assertions: rust.assertions,
    surfaces: auditedSurfaces,
    pairSetDigest: taggedDigest(
      Object.fromEntries(
        Object.entries(auditedSurfaces).map(([name, proof]) => [
          name,
          {
            nativeSurfaceId: proof.nativeSurfaceId,
            hostSurfaceId: proof.hostSurfaceId,
            proofDigest: proof.proofDigest,
          },
        ]),
      ),
    ),
  });
}

/** Integration rows for the catalog builder; deliberately no output shapes. */
export function debuggerNativeAliasStructuralAccountBindings(sourceAudit) {
  validateAudit(sourceAudit);
  return Object.entries(sourceAudit.surfaces)
    .map(([surfaceName, proof]) => ({
      surfaceName,
      status: "structural-only",
      reasonCode: DEBUGGER_NATIVE_ALIAS_STRUCTURAL_REASON_CODE,
      sourceRefs: [...proof.sourceRefs],
      proofDigest: proof.proofDigest,
      outputKinds: [],
      outputDependencies: [structuredClone(proof.outputDependency)],
    }))
    .sort((left, right) => compareText(left.surfaceName, right.surfaceName));
}

export function validateDebuggerNativeAliasStructuralAccount(
  account,
  { surface, coverageEdge, sourceAudit },
) {
  validateAudit(sourceAudit);
  const proof = sourceAudit.surfaces[surface?.name];
  const expected = proof
    ? {
        structuralAccountSchema:
          DEBUGGER_NATIVE_ALIAS_STRUCTURAL_ACCOUNT_SCHEMA,
        surfaceId: proof.nativeSurfaceId,
        surfaceObservedKey: proof.nativeObservedKey,
        status: "structural-only",
        reasonCode: DEBUGGER_NATIVE_ALIAS_STRUCTURAL_REASON_CODE,
        sourceRefs: [...proof.sourceRefs],
        proofDigest: proof.proofDigest,
        outputKinds: [],
        outputDependencies: [structuredClone(proof.outputDependency)],
      }
    : null;
  requireCondition(
    expected &&
      surface.kind === "native-op" &&
      surface.observedKey === proof.nativeObservedKey &&
      coverageEdge?.id === proof.nativeSurfaceId &&
      canonicalJson(account) === canonicalJson(expected),
    `${surface?.name}: invalid debugger native alias structural account`,
  );
  return account;
}

export function authoredDebuggerNativeAliasStructuralAccount({
  surface,
  coverageEdge,
  sourceAudit,
}) {
  validateAudit(sourceAudit);
  const proof = sourceAudit.surfaces[surface?.name];
  if (!proof) return null;
  return validateDebuggerNativeAliasStructuralAccount(
    {
      structuralAccountSchema: DEBUGGER_NATIVE_ALIAS_STRUCTURAL_ACCOUNT_SCHEMA,
      surfaceId: proof.nativeSurfaceId,
      surfaceObservedKey: proof.nativeObservedKey,
      status: "structural-only",
      reasonCode: DEBUGGER_NATIVE_ALIAS_STRUCTURAL_REASON_CODE,
      sourceRefs: [...proof.sourceRefs],
      proofDigest: proof.proofDigest,
      outputKinds: [],
      outputDependencies: [structuredClone(proof.outputDependency)],
    },
    { surface, coverageEdge, sourceAudit },
  );
}

/**
 * Verify both halves of the alias account. Native rows must be structural and
 * rowless; the exact six Host ABI companions must remain output-bearing with
 * one exact `[[return]]` row apiece.
 */
export function validateDebuggerNativeAliasStructuralCatalog({
  catalog,
  coverage,
  sourceAudit,
}) {
  validateAudit(sourceAudit);
  requireCondition(
    Array.isArray(catalog?.surfaceAccounts) && Array.isArray(catalog?.rows),
    "debugger native alias catalog lacks accounts or rows",
  );
  const expectedIds = Object.values(sourceAudit.surfaces).flatMap((proof) => [
    proof.nativeSurfaceId,
    proof.hostSurfaceId,
  ]);
  requireCondition(
    new Set(expectedIds).size === DEBUGGER_ALIAS_SPECS.length * 2,
    "debugger native alias audit does not bind twelve distinct accounts",
  );
  const accountById = exactPairMap(
    catalog.surfaceAccounts,
    (account) => account?.surfaceId,
    expectedIds,
    "debugger native alias catalog accounts",
  );
  const edgeById = exactPairMap(
    coverage?.edges,
    (edge) => edge?.id,
    expectedIds,
    "debugger native alias catalog coverage",
  );
  const expectedRowIds = Object.values(sourceAudit.surfaces).map(
    (proof) => proof.hostSurfaceId,
  );
  const relevantRows = catalog.rows.filter((row) =>
    expectedIds.includes(row?.key?.surfaceId),
  );
  requireCondition(
    relevantRows.length === DEBUGGER_ALIAS_SPECS.length,
    "debugger native alias catalog must contain exactly six companion rows",
  );
  const rowBySurfaceId = exactPairMap(
    relevantRows,
    (row) => row?.key?.surfaceId,
    expectedRowIds,
    "debugger native alias companion rows",
  );

  for (const [surfaceName, proof] of Object.entries(sourceAudit.surfaces)) {
    const nativeEdge = edgeById.get(proof.nativeSurfaceId);
    const hostEdge = edgeById.get(proof.hostSurfaceId);
    requireCondition(
      nativeEdge.surface?.kind === "native-op" &&
        nativeEdge.surface.name === surfaceName &&
        hostEdge.surface?.kind === "host-abi" &&
        `host-abi:${hostEdge.surface.name}` === proof.hostObservedKey,
      `${surfaceName}: catalog coverage pair drifted`,
    );
    const expectedNativeAccount = {
      surfaceId: proof.nativeSurfaceId,
      status: "structural-only",
      reasonCode: DEBUGGER_NATIVE_ALIAS_STRUCTURAL_REASON_CODE,
      sourceRefs: [...proof.sourceRefs],
      outputKinds: [],
    };
    requireCondition(
      canonicalJson(accountById.get(proof.nativeSurfaceId)) ===
        canonicalJson(expectedNativeAccount),
      `${surfaceName}: native alias catalog account drifted`,
    );
    requireCondition(
      canonicalJson(accountById.get(proof.hostSurfaceId)) ===
        canonicalJson(proof.companionCatalogAccount),
      `${surfaceName}: companion Host ABI account is absent or mismatched`,
    );
    requireCondition(
      canonicalJson(rowBySurfaceId.get(proof.hostSurfaceId)) ===
        canonicalJson(proof.companionCatalogRow),
      `${surfaceName}: companion Host ABI output row is absent or mismatched`,
    );
  }
  return true;
}
