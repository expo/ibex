/**
 * Source-bound public probes for the production JavaScript module loader.
 *
 * Output-shape routes alone prove only that an outer public entrypoint
 * completed. Promotion additionally requires a loader-private source-point
 * receipt emitted by the exact loaded helper/branch. The receipt is armed
 * natively, cannot be called by project code after bootstrap, and is joined to
 * the expectation-free output invocation only after execution.
 *
 * @ref LLP 0013#import-gating-policy-surface-3 — every authored route uses a
 * real package-facing loader entry and retains the production import gate.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
 * source inventory and outer completion never substitute for executed,
 * source-bound fixture evidence.
 * @ref LLP 0032#authority-boundary — the exact loaded engine and batch command
 * remain part of the authoritative evidence binding.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";
import { authoredModuleLoaderOutputInvocation } from "./capsec-loader-output-templates.mjs";
import { capsecSecureCargoTestCommand } from "./capsec-secure-test-command.mjs";

export const MODULE_LOADER_CAPTURED_INVOCATION_SCHEMA =
  "ibex/capsec-loader-captured-invocation/1";

export const MODULE_LOADER_CAPTURED_BATCH_COMMAND = Object.freeze(
  capsecSecureCargoTestCommand("capsec_public_loader_recipe_batch", true),
);

const COMPLETION = Object.freeze({
  kind: "event-loop-quiescence",
  timeoutMilliseconds: 1_000,
});

const REVIEWED_ARMED_EXECUTION_POINTS = new Map([
  [
    "function:javascript:checkImportGate",
    "function:javascript:checkImportGate",
  ],
  [
    "function:javascript:__exactResolvedPath",
    "function:javascript:__exactResolvedPath",
  ],
  ["function:javascript:idToModuleId", "function:javascript:idToModuleId"],
  [
    "function:javascript:privateBridgesForBuiltin",
    "function:javascript:privateBridgesForBuiltin",
  ],
  [
    "function:javascript:privateResolverPath",
    "function:javascript:privateResolverPath",
  ],
  [
    "function:javascript:rejectRuntimeLoaderOptions",
    "function:javascript:rejectRuntimeLoaderOptions",
  ],
  [
    "function:javascript:resolverVirtualPath",
    "function:javascript:resolverVirtualPath",
  ],
  [
    "function:javascript:stripViteImportQuery",
    "function:javascript:stripViteImportQuery",
  ],
  ["import-needs", "function:javascript:rejectRuntimeLoaderOptions"],
  ["import-policy-bare", "function:javascript:checkImportGate"],
  ["internal-route:assert/strict", "internal-route:assert/strict"],
  [
    "internal-route:internal/fs/utils",
    "internal-route:internal/fs/utils",
  ],
  ["kind:builtin", "kind:builtin"],
]);

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

function executionPointFor(surface, captured) {
  if (captured?.route?.operation !== "invoke-public-loader") return null;
  if (captured.route.authority !== undefined) {
    // The package.json path carries typed fs authorization. It remains
    // residual until a dedicated observed decision sequence is pinned.
    return null;
  }
  return REVIEWED_ARMED_EXECUTION_POINTS.get(surface.name) ?? null;
}

export function authoredModuleLoaderCapturedInvocation({
  surface,
  coverageEdge,
}) {
  const capturedOutputInvocation = authoredModuleLoaderOutputInvocation({
    surface,
    coverageEdge,
  });
  const executionPoint = executionPointFor(surface, capturedOutputInvocation);
  if (!executionPoint) return null;
  const sourceDescriptor = {
    kind: "module-loader-public-route",
    surfaceName: surface.name,
    evidenceType: surface.metadata?.evidenceType ?? null,
    sourceRefs: [...surface.sourceRefs],
    executionPoint,
    outputSourceDescriptorDigest:
      capturedOutputInvocation.sourceDescriptorDigest,
  };
  return {
    invocationSchema: MODULE_LOADER_CAPTURED_INVOCATION_SCHEMA,
    kind: "module-loader-captured-route",
    coverageEdgeId: coverageEdge.id,
    coverageClassification: coverageEdge.classification,
    moduleSpecifier: capturedOutputInvocation.route.specifier,
    entrypoint: capturedOutputInvocation.route.entrypoint,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    capturedOutputInvocation,
    capturedOutputInvocationDigest: taggedDigest(capturedOutputInvocation),
    completion: { ...COMPLETION },
    requiredAuthority: [],
    expectedResult: "source-completion",
    expectedTypedStages: [],
    expectedTypedDecisionCount: 0,
    allowedCoverageEdgeIds: [coverageEdge.id],
    expectedActionIds: [],
  };
}
