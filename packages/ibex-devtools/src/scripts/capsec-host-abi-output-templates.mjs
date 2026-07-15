/**
 * Author exact native-output probes for the Rust-owned Host ABI.
 *
 * This module deliberately does not turn an inventory row into evidence.  It
 * accepts only ABI families for which the companion Rust executor owns a
 * bounded invocation and cleanup recipe.  Platform-only target absence is
 * handled by `capsec-target-absence-output-templates.mjs` before this author is
 * consulted.
 *
 * @ref LLP 0002#the-rust-host-surface — Host ABI values cross a typed C
 * boundary and returned strings/buffers retain their native ownership rules.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * source inventory definition is an obligation, not execution evidence.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "./capsec-contract.mjs";
import { canonicalOutputDispositionKey } from "./capsec-output-dispositions.mjs";
import { HOST_ABI_OUTPUT_CONTRACT_SCHEMA } from "./capsec-surface-inventory.mjs";

export const HOST_ABI_OUTPUT_INVOCATION_SCHEMA =
  "ibex/capsec-host-abi-output-invocation/1";
export const HOST_ABI_OUTPUT_SOURCE_DESCRIPTOR_KIND =
  "source-bound-host-abi-output";
export const HOST_ABI_OUTPUT_PARTITION_SCHEMA =
  "ibex/capsec-host-abi-output-partition/1";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

const taggedDigest = (bytes) =>
  `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;

const descriptorDigest = (value) =>
  taggedDigest(Buffer.from(canonicalJson(value), "utf8"));

const HOST_FS_FUNCTIONS = new Set([
  "ex_host_fs_access",
  "ex_host_fs_append",
  "ex_host_fs_chmod",
  "ex_host_fs_close",
  "ex_host_fs_copy",
  "ex_host_fs_copy_exclusive",
  "ex_host_fs_fstat",
  "ex_host_fs_last_error",
  "ex_host_fs_lstat",
  "ex_host_fs_mkdir",
  "ex_host_fs_mkdir_recursive_result",
  "ex_host_fs_mkdtemp",
  "ex_host_fs_open",
  "ex_host_fs_pread",
  "ex_host_fs_pwrite",
  "ex_host_fs_read",
  "ex_host_fs_read_file",
  "ex_host_fs_readdir",
  "ex_host_fs_realpath",
  "ex_host_fs_rename",
  "ex_host_fs_rmdir",
  "ex_host_fs_seek",
  "ex_host_fs_stat",
  "ex_host_fs_statfs",
  "ex_host_fs_sync",
  "ex_host_fs_truncate",
  "ex_host_fs_unlink",
  "ex_host_fs_utimes",
  "ex_host_fs_write",
]);

const HOST_SQLITE_FUNCTIONS = new Set([
  "ex_host_sqlite_all",
  "ex_host_sqlite_close",
  "ex_host_sqlite_exec",
  "ex_host_sqlite_expanded_sql",
  "ex_host_sqlite_finalize",
  "ex_host_sqlite_get",
  "ex_host_sqlite_in_transaction",
  "ex_host_sqlite_open",
  "ex_host_sqlite_open_checked_fd",
  "ex_host_sqlite_open_isolated_memory",
  "ex_host_sqlite_prepare",
  "ex_host_sqlite_run",
  "ex_host_sqlite_values",
]);

const HOST_TERMINAL_FUNCTIONS = new Set([
  "ex_host_session_descriptor_alias_source_route",
  "ex_host_session_descriptor_alias_target_route",
  "ex_host_session_descriptor_close_route",
  "ex_host_session_descriptor_is_protected",
  "ex_host_session_descriptor_read_route",
  "ex_host_session_descriptor_write_route",
  "ex_host_terminal_session_close_is_noop",
  "ex_host_terminal_session_stdio_query",
]);

const HOST_BASIC_FUNCTIONS = new Set([
  "ex_host_armed_endowments",
  "ex_host_check_capability",
  "ex_host_check_capability_no_follow_final",
  "ex_host_check_capability_stack",
  "ex_host_check_capability_stack_no_follow_final",
  "ex_host_check_handle_mint",
  "ex_host_check_import",
  "ex_host_claim_armed_context",
  "ex_host_claim_diagnostic_context",
  "ex_host_console_flush",
  "ex_host_console_log",
  "ex_host_console_log_bytes",
  "ex_host_enter_context",
  "ex_host_env_get",
  "ex_host_free_buffer",
  "ex_host_free_string",
  "ex_host_grant_capability",
  "ex_host_handle_check",
  "ex_host_handle_create",
  "ex_host_handle_revoke",
  "ex_host_handle_scoped",
  "ex_host_has_deputy_classes",
  "ex_host_init",
  "ex_host_is_allow_all",
  "ex_host_is_armed",
  "ex_host_legacy_authorization_cacheable",
  "ex_host_legacy_authorization_generation",
  "ex_host_log_event",
  "ex_host_module_resolve",
  "ex_host_module_resolve_meta",
  "ex_host_permission_request",
  "ex_host_permission_revoke",
  "ex_host_permission_status",
  "ex_host_random_fill",
  "ex_host_register_module_package",
  "ex_host_release_context",
  "ex_host_resolve_manifest_builtin_internal",
  "ex_host_restore_context",
  "ex_host_time_now_ms",
  "ex_host_version",
]);

const HERMES_STATELESS_FUNCTIONS = new Set([
  "ex_hermes_bytecode_version",
  "ex_hermes_create",
  "ex_hermes_current_principal_id",
  "ex_hermes_current_runtime_nonce",
  "ex_hermes_engine_binary_path",
  "ex_hermes_engine_mapped_object",
  "ex_hermes_evaluation_result_dispose",
  "ex_hermes_evaluation_result_init",
  "ex_hermes_free_string",
  "ex_hermes_now_ms",
]);

const HERMES_DIAGNOSTIC_FUNCTIONS = new Set([
  "ex_hermes_callback_backlog",
  "ex_hermes_cancel_structured_work_target",
  "ex_hermes_create_diagnostic",
  "ex_hermes_destroy",
  "ex_hermes_eval",
  "ex_hermes_finish_bootstrap",
  "ex_hermes_gc",
  "ex_hermes_get_gc_stats",
  "ex_hermes_get_heap_info",
  "ex_hermes_has_pending_tasks",
  "ex_hermes_next_timer",
  "ex_hermes_poll",
  "ex_hermes_resolve_host_call",
  "ex_hermes_runtime_nonce",
  "ex_hermes_set_host_call",
  "ex_hermes_set_host_call_async",
  "ex_hermes_set_keep_alive_on_async_error",
  "ex_hermes_structured_active_work_target",
  "ex_hermes_take_async_failure_event",
  "ex_hermes_take_cancellation_event",
  "ex_hermes_take_work_unit_event",
]);

const HERMES_WORKLET_FUNCTIONS = new Set([
  "ex_worklet_bind_shared_values",
  "ex_worklet_create",
  "ex_worklet_destroy",
  "ex_worklet_drain_logs",
  "ex_worklet_drain_scheduled",
  "ex_worklet_generation",
  "ex_worklet_install",
  "ex_worklet_invoke",
  "ex_worklet_set_generation",
  "ex_worklet_set_measure_callback",
]);

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function operationFor(functionName) {
  if (HOST_FS_FUNCTIONS.has(functionName)) return { kind: "rust-host-fs-sandbox" };
  if (HOST_SQLITE_FUNCTIONS.has(functionName)) {
    return { kind: "rust-host-sqlite-memory" };
  }
  if (HOST_TERMINAL_FUNCTIONS.has(functionName)) {
    return { kind: "rust-host-terminal-inert" };
  }
  if (HOST_BASIC_FUNCTIONS.has(functionName)) {
    return { kind: "rust-host-bounded-basic" };
  }
  if (HERMES_STATELESS_FUNCTIONS.has(functionName)) {
    return {
      kind: "native-hermes-stateless-current-target",
      targetVariant: "default",
    };
  }
  if (HERMES_DIAGNOSTIC_FUNCTIONS.has(functionName)) {
    return {
      kind: "native-hermes-diagnostic-runtime",
      targetVariant: "default",
    };
  }
  if (HERMES_WORKLET_FUNCTIONS.has(functionName)) {
    return {
      kind: "native-hermes-worklet-runtime",
      targetVariant: "default",
    };
  }
  return null;
}

function sourceFileBindings(sourceRefs, functionName) {
  const files = [...new Set(sourceRefs.map((sourceRef) => sourceRef.split("#")[0]))]
    .sort(compareText);
  return files.map((sourcePath) => {
    requireCondition(
      sourcePath.length > 0 &&
        !path.isAbsolute(sourcePath) &&
        !sourcePath.split("/").includes(".."),
      `${functionName}: invalid source path ${JSON.stringify(sourcePath)}`,
    );
    const absolute = path.resolve(repoRoot, sourcePath);
    requireCondition(
      absolute.startsWith(`${repoRoot}${path.sep}`),
      `${functionName}: source path escaped the repository`,
    );
    const bytes = fs.readFileSync(absolute);
    requireCondition(
      bytes.includes(Buffer.from(functionName, "utf8")),
      `${functionName}: named symbol is absent from ${sourcePath}`,
    );
    return {
      path: sourcePath,
      rawContentDigest: taggedDigest(bytes),
    };
  });
}

function selectedReturnContracts(selectedDefinitions, functionName) {
  return selectedDefinitions.map((definition) => {
    const contract = definition.outputContract;
    requireCondition(
      contract?.schema === HOST_ABI_OUTPUT_CONTRACT_SCHEMA &&
        contract.functionName === functionName &&
        contract.sourceRef === definition.sourceRef &&
        contract.language === definition.language &&
        Array.isArray(contract.outputChannels) &&
        contract.return?.role,
      `${functionName}: selected definition lost its source-derived output contract`,
    );
    const returnChannels = contract.outputChannels.filter(
      (channel) =>
        channel.selector === "[[return]]" && channel.role === "return",
    );
    requireCondition(
      (contract.return.role === "none" && returnChannels.length === 0) ||
        (contract.return.role === "value" && returnChannels.length === 1),
      `${functionName}: syntactic return slot disagrees with output channels`,
    );
    return structuredClone(contract);
  });
}

/**
 * Return one loaded-engine/native return-record probe, or null when this
 * tranche has no sound bounded executor.  `targetAbsenceBinding` is an exact
 * binding from the separate target-absence author and always wins.
 */
export function authoredHostAbiOutputProbe({
  catalogRow,
  surface,
  coverageEdge,
  targetAbsenceBinding = null,
}) {
  if (targetAbsenceBinding) return null;
  const key = catalogRow?.key;
  if (key?.sourceKind !== "host-abi") return null;
  const functionName = coverageEdge?.surface?.name;
  requireCondition(
    coverageEdge?.id === key.surfaceId &&
      coverageEdge.surface?.kind === "host-abi" &&
      surface?.kind === "host-abi" &&
      surface.name === functionName &&
      surface.observedKey === `host-abi:${functionName}`,
    `${key.surfaceId}: Host ABI output source/coverage identity drift`,
  );
  if (key.output !== "[[return]]" || key.mode !== "all") return null;
  const operation = operationFor(functionName);
  if (!operation) return null;

  const inventorySourceRefs = [
    ...new Set([
      ...(surface.sourceRefs ?? []),
      ...(catalogRow.discovery?.sourceRefs ?? []),
    ]),
  ].sort(compareText);
  const definitions = surface.metadata?.definitions;
  const isRustOperation = operation.kind.startsWith("rust-host-");
  const selectedDefinitions = Array.isArray(definitions)
    ? definitions.filter(
        (definition) =>
          definition.targetVariant === (operation.targetVariant ?? "default") &&
          definition.language === (isRustOperation ? "rust" : "c++"),
      )
    : [];
  const sourceRefs = [
    ...new Set(selectedDefinitions.map((definition) => definition.sourceRef)),
  ].sort(compareText);
  requireCondition(
    inventorySourceRefs.length > 0 &&
      selectedDefinitions.length > 0 &&
      sourceRefs.every((sourceRef) => inventorySourceRefs.includes(sourceRef)) &&
      (!isRustOperation || selectedDefinitions.length === definitions.length),
    `${functionName}: bounded Host ABI route lost its exact compiled definition`,
  );
  const outputContracts = selectedReturnContracts(
    selectedDefinitions,
    functionName,
  );
  if (
    !outputContracts.every(
      (contract) =>
        contract.return.role === "value" &&
        contract.return.kind === "scalar" &&
        contract.return.ownership?.kind === "not-applicable",
    )
  ) {
    return null;
  }

  const sourceDescriptor = {
    kind: HOST_ABI_OUTPUT_SOURCE_DESCRIPTOR_KIND,
    invocationSchema: HOST_ABI_OUTPUT_INVOCATION_SCHEMA,
    functionName,
    catalogOutput: key.output,
    catalogMode: key.mode,
    returnVariant: key.returnVariant,
    inventorySourceRefs,
    sourceRefs,
    sourceFiles: sourceFileBindings(sourceRefs, functionName),
    definitions: structuredClone(definitions),
    selectedDefinitions: structuredClone(selectedDefinitions),
    outputContractSchema: HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
    outputContracts,
    selectedOutput: {
      kind: "scalar",
      ownership: "not-applicable",
      selector: "[[return]]",
    },
    operation,
  };
  const sourceDescriptorDigest = descriptorDigest(sourceDescriptor);
  return {
    kind: "loaded-engine-return-record",
    fixtureId: `host-abi-output-${sourceDescriptorDigest.slice(7, 23)}`,
    sourceDescriptor,
    sourceDescriptorDigest,
    recordPath: ["[[return]]"],
  };
}

export function hostAbiOutputExecutorCoverage(functionName) {
  const operation = operationFor(functionName);
  return operation ? structuredClone(operation) : null;
}

export function hostAbiOutputResidualReason({ catalogRow, surface }) {
  if (catalogRow?.key?.sourceKind !== "host-abi") return null;
  if (
    catalogRow.key.output !== "[[return]]" ||
    catalogRow.key.mode !== "all"
  ) {
    return "private-vfs-return-record-requires-authenticated-runtime-session";
  }
  const operation = operationFor(surface?.name);
  if (operation) {
    const expectedLanguage = operation.kind.startsWith("rust-host-")
      ? "rust"
      : "c++";
    const definitions = (surface?.metadata?.definitions ?? []).filter(
      (definition) =>
        definition.targetVariant === (operation.targetVariant ?? "default") &&
        definition.language === expectedLanguage,
    );
    const contracts = selectedReturnContracts(definitions, surface.name);
    const returnKinds = new Set(
      contracts.map((contract) =>
        contract.return.role === "none" ? "void" : contract.return.kind,
      ),
    );
    if (returnKinds.size !== 1)
      return "selected-definitions-disagree-on-return-contract";
    const [returnKind] = returnKinds;
    if (returnKind === "void")
      return "void-abi-has-no-syntactic-return-slot";
    if (returnKind === "pointer")
      return "pointer-return-ownership-is-not-source-bound";
    if (returnKind === "aggregate")
      return "aggregate-return-normalization-is-not-source-bound";
    if (returnKind === "unknown") return "return-contract-is-unresolved";
    return null;
  }
  const variants = new Set(
    (surface?.metadata?.definitions ?? []).map(
      (definition) => definition.targetVariant,
    ),
  );
  if (
    variants.size > 0 &&
    [...variants].every((variant) => new Set(["android", "ios"]).has(variant))
  ) {
    return "platform-only-route-requires-separate-target-absence-evidence";
  }
  if (surface?.name?.startsWith("ex_host_http_")) {
    return "http-server-route-requires-owned-live-server-state";
  }
  if (surface?.name?.startsWith("ex_worklet_")) {
    return "worklet-route-requires-owned-runtime-and-worklet-state";
  }
  if (surface?.name?.startsWith("ex_hermes_debugger_")) {
    return "debugger-route-requires-owned-live-debug-session";
  }
  if (surface?.name?.startsWith("ex_hermes_")) {
    return "engine-route-requires-owned-armed-or-diagnostic-runtime-state";
  }
  if (surface?.name?.startsWith("ex_host_vfs_")) {
    return "vfs-route-requires-authenticated-runtime-session";
  }
  if (
    /^ex_host_(?:authorize_typed|evaluate_typed|typed_|lifecycle_)/u.test(
      surface?.name ?? "",
    )
  ) {
    return "typed-authority-route-requires-authenticated-armed-context";
  }
  return "stateful-host-abi-route-has-no-bounded-output-template";
}

/**
 * Partition the complete Host ABI catalog into exact target-absence bindings,
 * executable native probes, and explicit residuals.  This is the integration
 * boundary used by the master sweep: it rejects both an orphan result key and
 * an input catalog key that disappears during authoring.
 */
export function buildHostAbiOutputProbePartition({
  catalog,
  coverage,
  surfaces,
  targetAbsenceBindings = [],
}) {
  requireCondition(Array.isArray(catalog?.rows), "output catalog has no rows");
  requireCondition(Array.isArray(coverage?.edges), "coverage registry has no edges");
  requireCondition(Array.isArray(surfaces), "source inventory has no surfaces");
  requireCondition(
    Array.isArray(targetAbsenceBindings),
    "target-absence bindings must be an array",
  );

  const catalogRows = catalog.rows.filter(
    (row) => row.key?.sourceKind === "host-abi",
  );
  const catalogByKey = new Map();
  for (const row of catalogRows) {
    const canonicalKey = canonicalOutputDispositionKey(
      row.key,
      "Host ABI catalog key",
    );
    requireCondition(
      !catalogByKey.has(canonicalKey),
      `${canonicalKey}: duplicate Host ABI catalog key`,
    );
    catalogByKey.set(canonicalKey, row);
  }

  const edgesById = new Map();
  for (const edge of coverage.edges) {
    requireCondition(
      !edgesById.has(edge.id),
      `${edge.id}: duplicate coverage edge`,
    );
    edgesById.set(edge.id, edge);
  }
  const surfacesByObservedKey = new Map();
  for (const surface of surfaces) {
    if (surface.kind !== "host-abi") continue;
    requireCondition(
      typeof surface.observedKey === "string" &&
        !surfacesByObservedKey.has(surface.observedKey),
      `${surface.observedKey}: duplicate or invalid Host ABI source surface`,
    );
    surfacesByObservedKey.set(surface.observedKey, surface);
  }

  const targetAbsenceByKey = new Map();
  for (const binding of targetAbsenceBindings) {
    const canonicalKey = canonicalOutputDispositionKey(
      binding?.key,
      "Host ABI target-absence key",
    );
    requireCondition(
      binding.key.sourceKind === "host-abi" && catalogByKey.has(canonicalKey),
      `${canonicalKey}: target-absence binding is not an exact Host ABI catalog row`,
    );
    requireCondition(
      !targetAbsenceByKey.has(canonicalKey),
      `${canonicalKey}: duplicate Host ABI target-absence binding`,
    );
    targetAbsenceByKey.set(canonicalKey, binding);
  }

  const targetAbsence = [];
  const rows = [];
  const residuals = [];
  const emittedKeys = new Set();
  for (const catalogRow of catalogRows) {
    const canonicalKey = canonicalOutputDispositionKey(catalogRow.key);
    const edge = edgesById.get(catalogRow.key.surfaceId);
    requireCondition(
      edge?.surface?.kind === "host-abi",
      `${catalogRow.key.surfaceId}: missing Host ABI coverage edge`,
    );
    const surface = surfacesByObservedKey.get(
      `host-abi:${edge.surface.name}`,
    );
    requireCondition(
      surface,
      `${edge.id}: missing Host ABI source-inventory surface`,
    );
    const targetAbsenceBinding = targetAbsenceByKey.get(canonicalKey) ?? null;
    const probe = authoredHostAbiOutputProbe({
      catalogRow,
      surface,
      coverageEdge: edge,
      targetAbsenceBinding,
    });
    if (targetAbsenceBinding) {
      targetAbsence.push(structuredClone(targetAbsenceBinding));
    } else if (probe) {
      rows.push({ key: structuredClone(catalogRow.key), probe });
    } else {
      residuals.push({
        key: structuredClone(catalogRow.key),
        reason: hostAbiOutputResidualReason({ catalogRow, surface }),
      });
    }
    requireCondition(
      !emittedKeys.has(canonicalKey),
      `${canonicalKey}: Host ABI output key was emitted twice`,
    );
    emittedKeys.add(canonicalKey);
  }

  requireCondition(
    emittedKeys.size === catalogByKey.size &&
      [...catalogByKey.keys()].every((key) => emittedKeys.has(key)) &&
      [...emittedKeys].every((key) => catalogByKey.has(key)),
    "Host ABI output partition is not bidirectional with the catalog",
  );
  const compareRows = (left, right) =>
    compareText(
      canonicalOutputDispositionKey(left.key),
      canonicalOutputDispositionKey(right.key),
    );
  targetAbsence.sort(compareRows);
  rows.sort(compareRows);
  residuals.sort(compareRows);
  return {
    hostAbiOutputPartitionSchema: HOST_ABI_OUTPUT_PARTITION_SCHEMA,
    targetAbsenceBindings: targetAbsence,
    rows,
    residuals,
  };
}
