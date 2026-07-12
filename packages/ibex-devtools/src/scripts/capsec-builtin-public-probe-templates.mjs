/**
 * Source-bound public probes for builtin exports whose classification can be
 * demonstrated by importing and reading the exact export through Hermes.
 *
 * A generic read probe is emitted only for a source-proven data property or
 * root accessor. Merely retrieving a discovered function, constructor, or
 * prototype method does not execute that surface and therefore is not
 * conformance evidence. Those callable surfaces remain residual until an
 * explicit bounded call/setup template is authored.
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
  "capsec_public_noncap_builtin_recipe_batch",
  "--",
  "--test-threads=1",
  "--nocapture",
]);

const PROTOTYPE_IDIOMS = new Set([
  "exported-constructor-prototype",
  "exported-constructor-inherited-prototype",
]);
const KNOWN_PLATFORMS = new Set(["android", "darwin", "linux"]);

function platformForTarget(target) {
  const triple =
    typeof target === "string"
      ? target
      : typeof target?.triple === "string"
        ? target.triple
        : null;
  if (!triple) return null;
  if (triple.includes("android")) return "android";
  if (triple.includes("apple-darwin")) return "darwin";
  if (triple.includes("linux")) return "linux";
  return null;
}

function platformAvailability(metadata) {
  const availability = metadata?.platformAvailability;
  if (availability === undefined) return null;
  if (
    !Array.isArray(availability) ||
    availability.length === 0 ||
    !availability.every((platform) => KNOWN_PLATFORMS.has(platform)) ||
    canonicalJson(availability) !== canonicalJson(canonicalSet(availability))
  ) {
    return false;
  }
  return availability;
}

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

function sourceDescriptor(surface, target) {
  const metadata = surface?.metadata;
  const availability = platformAvailability(metadata);
  const targetPlatform = platformForTarget(target);
  if (
    metadata?.surfaceType !== "export" ||
    typeof metadata.sourceKey !== "string" ||
    metadata.sourceKey.length === 0 ||
    metadata.sourceKey === "node_os" ||
    !new Set(["accessor", "data"]).has(metadata.valueShape) ||
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
    availability === false ||
    (availability &&
      (!targetPlatform || !availability.includes(targetPlatform))) ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length !== 1
  ) {
    return null;
  }
  const expectedObservedKey = `builtin:export:${metadata.sourceKey}:${metadata.exportName}`;
  if (surface.observedKey !== expectedObservedKey) return null;
  const access = exportAccess(metadata.exportName, metadata.exportIdioms);
  const moduleSpecifier = canonicalModuleSpecifier(metadata.moduleSpecifiers);
  if (
    !access ||
    !moduleSpecifier ||
    !new Set(["export-property", "module-value"]).has(access.kind) ||
    (metadata.valueShape === "accessor" && access.kind !== "export-property")
  ) {
    return null;
  }
  const descriptor = {
    kind: "builtin-export",
    sourceKey: metadata.sourceKey,
    exportName: metadata.exportName,
    exportIdioms: [...metadata.exportIdioms],
    moduleSpecifiers: [...metadata.moduleSpecifiers],
    sourceRef: surface.sourceRefs[0],
    valueShape: metadata.valueShape,
    access,
  };
  if (availability) descriptor.platformAvailability = [...availability];
  return descriptor;
}

export function authoredNonCapabilityBuiltinProbe({
  plan,
  scenario,
  route,
  liveByObservedKey,
  target,
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
    target,
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

export function nonCapabilityBuiltinProbeResidualReason({
  route,
  liveByObservedKey,
  target,
}) {
  if (route.surfaceObservedKeys.length !== 1) return null;
  const surface = liveByObservedKey.get(route.surfaceObservedKeys[0]);
  const availability = platformAvailability(surface?.metadata);
  const targetPlatform = platformForTarget(target);
  if (
    availability &&
    targetPlatform &&
    !availability.includes(targetPlatform)
  ) {
    return "builtin-export-not-available-on-target";
  }
  return null;
}
