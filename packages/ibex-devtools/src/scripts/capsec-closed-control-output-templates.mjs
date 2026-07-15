/**
 * Expectation-free output-shape routes for production controls that are
 * closed before project code.  The existing public-surface authoring logic
 * remains the source of the production invocation; this adapter removes every
 * reviewed result/assertion before the route enters the output sweep plan. The
 * executor must retain the production boundary's actual failure as the outer
 * observation; it may not turn that failure into a successful wrapper return.
 *
 * @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces —
 * closed CLI, startup-environment, and executable-loader controls must refuse
 * at their production boundary.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * compiled registrar is not execution evidence for an output value.
 * @ref LLP 0023#6-path-bearing-observables — output-shape plans carry only
 * source-bound reachability, while the executor owns the observed result.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";
import { authoredClosedPublicProbe } from "./capsec-closed-probe-templates.mjs";

export const CLOSED_CONTROL_OUTPUT_INVOCATION_SCHEMA =
  "ibex/capsec-closed-control-output-invocation/1";
export const CLOSED_CONTROL_OUTPUT_TIMEOUT_MILLISECONDS = 1_000;

const OUTPUT_OPERATION_KINDS = new Set([
  "cli-control",
  "startup-environment",
  "loader-executable-file",
]);

function taggedDigest(value) {
  return `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;
}

function rows(value, property, label) {
  const selected = Array.isArray(value) ? value : value?.[property];
  if (!Array.isArray(selected)) {
    throw new Error(`${label}: expected an array`);
  }
  return selected;
}

function uniqueObservedMap(values, label) {
  const result = new Map();
  for (const value of values) {
    if (typeof value?.observedKey !== "string" || value.observedKey.length === 0) {
      throw new Error(`${label}: row has no observed key`);
    }
    if (result.has(value.observedKey)) {
      throw new Error(`${label}: duplicate observed key ${value.observedKey}`);
    }
    result.set(value.observedKey, value);
  }
  return result;
}

function coverageByObservedKey(coverage) {
  const result = new Map();
  for (const edge of rows(coverage, "edges", "closed-control coverage")) {
    const kind = edge?.surface?.kind;
    const name = edge?.surface?.name;
    if (
      typeof edge?.id !== "string" ||
      typeof kind !== "string" ||
      typeof name !== "string"
    ) {
      throw new Error("closed-control coverage: malformed edge");
    }
    const observedKey = `${kind}:${name}`;
    if (result.has(observedKey)) {
      throw new Error(
        `closed-control coverage: duplicate observed key ${observedKey}`,
      );
    }
    result.set(observedKey, edge);
  }
  return result;
}

function outputOperation(operation) {
  switch (operation?.kind) {
    case "cli-control":
      return {
        kind: operation.kind,
        argumentVectors: structuredClone(operation.argumentVectors),
        projectCodePlaceholder: operation.projectCodePlaceholder,
      };
    case "startup-environment":
      return {
        kind: operation.kind,
        environmentName: operation.environmentName,
      };
    case "loader-executable-file":
      return {
        kind: operation.kind,
        loaderKind: operation.loaderKind,
        extension: operation.extension,
      };
    default:
      return null;
  }
}

/**
 * Return one source-bound production invocation for a closed output row.
 *
 * Eligibility is recomputed from the exact coverage edge and live inventory;
 * no recipe artifact or disposition policy is accepted.  Internally this
 * calls the same authoring function as conformance recipes, then projects only
 * its source descriptor and operation inputs.  Expected results, expected
 * message fragments, decision counts, and result markers never enter this
 * return value.
 */
export function authoredClosedControlOutputInvocation({
  surface,
  surfaces,
  coverageEdge,
  coverage,
}) {
  if (
    !surface ||
    typeof surface.observedKey !== "string" ||
    !coverageEdge ||
    coverageEdge.classification !== "closed" ||
    coverageEdge.surface?.kind !== surface.kind ||
    coverageEdge.surface?.name !== surface.name ||
    surface.observedKey !== `${surface.kind}:${surface.name}`
  ) {
    return null;
  }

  const liveByObservedKey = uniqueObservedMap(
    rows(surfaces, "surfaces", "closed-control live inventory"),
    "closed-control live inventory",
  );
  if (liveByObservedKey.get(surface.observedKey) !== surface) {
    return null;
  }
  const edgesByObservedKey = coverageByObservedKey(coverage);
  if (edgesByObservedKey.get(surface.observedKey)?.id !== coverageEdge.id) {
    return null;
  }

  const probe = authoredClosedPublicProbe({
    plan: {
      classification: "closed",
      expectedObservation: { kind: "enforcement-branch" },
      edgeIds: [coverageEdge.id],
      actionIds: [],
    },
    scenario: "closed",
    route: {
      surfaceObservedKeys: [surface.observedKey],
      alternatives: [{ terminalObservedKey: surface.observedKey }],
      ambiguousCallees: [],
    },
    liveByObservedKey,
    coverageByObservedKey: edgesByObservedKey,
  });
  const authored = probe?.invocation;
  const operation = outputOperation(authored?.operation);
  if (
    authored?.invocationSchema !==
      "ibex/capsec-closed-surface-invocation/1" ||
    authored.kind !== "closed-surface" ||
    probe.surfaceObservedKey !== surface.observedKey ||
    !OUTPUT_OPERATION_KINDS.has(operation?.kind)
  ) {
    return null;
  }

  const sourceDescriptor = structuredClone(authored.sourceDescriptor);
  if (taggedDigest(sourceDescriptor) !== authored.sourceDescriptorDigest) {
    throw new Error(
      `${surface.observedKey}: closed source descriptor digest mismatch`,
    );
  }
  return {
    invocationSchema: CLOSED_CONTROL_OUTPUT_INVOCATION_SCHEMA,
    kind: "closed-control-output",
    coverageEdgeId: coverageEdge.id,
    surfaceObservedKey: surface.observedKey,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation,
    completion: {
      kind: "bounded-production-boundary",
      timeoutMilliseconds: CLOSED_CONTROL_OUTPUT_TIMEOUT_MILLISECONDS,
    },
  };
}
