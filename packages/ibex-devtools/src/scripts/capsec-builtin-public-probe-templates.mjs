/**
 * Source-bound public probes for builtin exports whose classification can be
 * demonstrated by importing and reading the exact export through Hermes.
 *
 * A read probe never calls a discovered function. That is intentional for a
 * non-capability row: it proves that the inventoried public export is present
 * on the loaded runtime while the conformance observer proves that access did
 * not cross a capability gate. Calls that need arguments or setup remain
 * residual until an explicit bounded template is authored.
 *
 * @ref LLP 0004#the-builtin-module-surface — builtin aliases share one
 * source-derived export inventory.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
 * inventory references are not evidence; the bound engine must execute each
 * authored public probe.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const BUILTIN_BATCH_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer",
  "capsec_public_builtin_recipe_batch",
  "--",
  "--test-threads=1",
  "--nocapture",
]);

const PROTOTYPE_IDIOMS = new Set([
  "exported-constructor-prototype",
  "exported-constructor-inherited-prototype",
]);

function canonicalModuleSpecifier(specifiers) {
  const ranked = canonicalSet(specifiers).sort((left, right) => {
    const rank = (value) =>
      value.startsWith("node:")
        ? 0
        : value.startsWith("exact:")
          ? 1
          : value.startsWith("bun:")
            ? 2
            : value.startsWith("internal/")
              ? 3
              : 4;
    return rank(left) - rank(right) || compareText(left, right);
  });
  return ranked[0] ?? null;
}

function exportAccess(exportName, exportIdioms) {
  if (exportName.includes("[[") || exportName.includes("]]")) return null;
  const segments = exportName.split(".");
  if (segments.some((segment) => segment.length === 0)) return null;
  const prototype = exportIdioms.filter((idiom) => PROTOTYPE_IDIOMS.has(idiom));
  if (prototype.length > 0) {
    if (prototype.length !== exportIdioms.length || segments.length < 2) {
      return null;
    }
    return {
      kind:
        prototype[0] === "exported-constructor-inherited-prototype"
          ? "inherited-prototype-property"
          : "prototype-property",
      path: [segments[0], "prototype", ...segments.slice(1)],
    };
  }
  if (
    exportName === "default" &&
    exportIdioms.includes("module-exports-assignment")
  ) {
    return { kind: "module-value", path: [] };
  }
  return { kind: "export-property", path: segments };
}

function sourceDescriptor(surface) {
  const metadata = surface?.metadata;
  if (
    metadata?.surfaceType !== "export" ||
    typeof metadata.sourceKey !== "string" ||
    metadata.sourceKey.length === 0 ||
    metadata.sourceKey === "node_os" ||
    typeof metadata.exportName !== "string" ||
    metadata.exportName.length === 0 ||
    !Array.isArray(metadata.exportIdioms) ||
    metadata.exportIdioms.length === 0 ||
    canonicalJson(metadata.exportIdioms) !==
      canonicalJson(canonicalSet(metadata.exportIdioms)) ||
    !Array.isArray(metadata.moduleSpecifiers) ||
    metadata.moduleSpecifiers.length === 0 ||
    !metadata.moduleSpecifiers.every(
      (specifier) => typeof specifier === "string" && specifier.length > 0,
    ) ||
    canonicalJson(metadata.moduleSpecifiers) !==
      canonicalJson(canonicalSet(metadata.moduleSpecifiers)) ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length !== 1
  ) {
    return null;
  }
  const expectedObservedKey = `builtin:export:${metadata.sourceKey}:${metadata.exportName}`;
  if (surface.observedKey !== expectedObservedKey) return null;
  const access = exportAccess(metadata.exportName, metadata.exportIdioms);
  const moduleSpecifier = canonicalModuleSpecifier(metadata.moduleSpecifiers);
  if (!access || !moduleSpecifier) return null;
  return {
    kind: "builtin-export",
    sourceKey: metadata.sourceKey,
    exportName: metadata.exportName,
    exportIdioms: [...metadata.exportIdioms],
    moduleSpecifiers: [...metadata.moduleSpecifiers],
    sourceRef: surface.sourceRefs[0],
    access,
  };
}

export function authoredNonCapabilityBuiltinProbe({
  plan,
  scenario,
  route,
  liveByObservedKey,
}) {
  if (
    plan.classification !== "non-capability" ||
    scenario !== "non-capability" ||
    plan.actionIds.length !== 0 ||
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  if (!surfaceObservedKey.startsWith("builtin:export:")) return null;
  const alternative = route.alternatives[0];
  if (
    alternative.terminalObservedKey !== surfaceObservedKey ||
    !Array.isArray(alternative.proofPaths) ||
    alternative.proofPaths.length === 0
  ) {
    return null;
  }
  const descriptor = sourceDescriptor(
    liveByObservedKey.get(surfaceObservedKey),
  );
  if (!descriptor) return null;
  const moduleSpecifier = canonicalModuleSpecifier(descriptor.moduleSpecifiers);
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...BUILTIN_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-builtin-export-invocation/1",
      kind: "builtin-export-read",
      moduleSpecifier,
      exportName: descriptor.exportName,
      sourceDescriptor: descriptor,
      sourceDescriptorDigest: taggedDigest(descriptor),
      arguments: [],
      setup: { kind: "none" },
      requiredAuthority: [],
      expectedResult: "return",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}
