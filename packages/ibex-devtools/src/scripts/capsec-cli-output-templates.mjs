/**
 * Source-bound recipes for outputs owned by the compiled CLI and generated
 * REPL tables. The plan carries only source identity and a bounded operation;
 * the Rust executor reads the live Clap/generated structures and emits the
 * selected value.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — CLI
 * evidence reconciles source-discovered routes against the live command tree.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const INVOCATION_SCHEMA = "ibex/capsec-cli-output-invocation/1";

const CLAP_EVIDENCE_TYPES = new Set([
  "cli-argument-conflict",
  "cli-command-route",
  "cli-default-missing-value",
  "cli-default-value",
  "cli-enum-alias",
  "cli-enum-value",
  "cli-non-enumerated-parser",
  "cli-option-name",
  "cli-option-route",
  "cli-positional-route",
  "cli-value-action",
  "cli-value-arity",
  "cli-value-name",
]);

const REPL_EVIDENCE_TYPES = new Set([
  "repl-command-recognition",
  "repl-command-route",
  "repl-keybinding",
  "repl-load-extension",
]);

const PRODUCT_INGRESS_REFS = new Set([
  "src/bin/ibex/main.rs#eval_code",
  "src/bin/ibex/main.rs#run",
  "src/bin/ibex/main.rs#run_file_with_execution_adapter",
  "src/bin/ibex/main.rs#run_stdin_program",
  "src/bin/ibex/main.rs#start_repl",
]);

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

export function authoredCliOutputInvocation({ surface, coverageEdge }) {
  const manifestCommandRef = surface?.sourceRefs?.find((sourceRef) =>
    new Set([
      "runtime-surface.json#hiddenHarnessCommands",
      "runtime-surface.json#legacyProjectCommands",
      "runtime-surface.json#reservedCommands",
      "runtime-surface.json#visibleCommands",
    ]).has(sourceRef),
  );
  const productIngressRef = surface?.sourceRefs?.find((sourceRef) =>
    PRODUCT_INGRESS_REFS.has(sourceRef),
  );
  const evidenceType =
    surface?.metadata?.evidenceType ??
    (manifestCommandRef
      ? "cli-manifest-command"
      : productIngressRef
        ? "cli-product-ingress"
        : null);
  const operationKind = CLAP_EVIDENCE_TYPES.has(evidenceType)
    ? "clap-surface-read"
    : REPL_EVIDENCE_TYPES.has(evidenceType)
      ? "repl-surface-read"
      : evidenceType === "cli-manifest-command" &&
          new Set([
            "runtime-surface.json#hiddenHarnessCommands",
            "runtime-surface.json#visibleCommands",
          ]).has(manifestCommandRef)
        ? "clap-command-name-read"
        : evidenceType === "cli-manifest-command"
          ? "namespace-command-name-read"
          : evidenceType === "cli-product-ingress"
            ? "product-ingress-route-read"
            : null;
  if (
    operationKind === null ||
    !coverageEdge ||
    surface?.kind !== "cli" ||
    surface.observedKey !== `cli:${surface.name}` ||
    typeof surface.name !== "string" ||
    surface.name.length === 0 ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length === 0 ||
    !surface.sourceRefs.every(
      (sourceRef) => typeof sourceRef === "string" && sourceRef.length > 0,
    )
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "compiled-cli-surface",
    surfaceName: surface.name,
    evidenceType,
    sourceRefs: [...surface.sourceRefs],
  };
  return {
    invocationSchema: INVOCATION_SCHEMA,
    kind: "cli-output",
    coverageEdgeId: coverageEdge.id,
    coverageClassification: coverageEdge.classification,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: { kind: operationKind },
    completion: { kind: "synchronous-compiled-runtime" },
  };
}

export const compiledCliEvidenceTypes = Object.freeze(
  [
    ...CLAP_EVIDENCE_TYPES,
    ...REPL_EVIDENCE_TYPES,
    "cli-manifest-command",
    "cli-product-ingress",
  ].sort(),
);
