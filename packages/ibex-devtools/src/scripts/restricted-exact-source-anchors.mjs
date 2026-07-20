/**
 * Resolve legacy CapSec `path#locator` references to exact source ranges.
 *
 * The legacy inventory intentionally treated locators as discovery labels.
 * LLP 0033 executable-route v2 upgrades them into byte-bound anchors. This
 * resolver is closed: an unsupported, missing, or ambiguous locator is an
 * error and whole-file hashing is never used as a successful fallback.
 *
 * @ref LLP 0033#third-review-disposition-and-executable-route-v2
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parse } from "@babel/parser";

import { capsecRoot, readJsonStrict } from "./capsec-contract.mjs";

const repoRoot = path.dirname(capsecRoot);
const sourceCache = new Map();
const rangeCache = new Map();
const containerRangeCache = new Map();
const javascriptIndexCache = new Map();

function digest(bytes) {
  return `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function lineRange(text, offset) {
  const startByte = text.lastIndexOf("\n", offset - 1) + 1;
  const newline = text.indexOf("\n", offset);
  const endByte = newline < 0 ? text.length : newline;
  return { startByte, endByte };
}

function matchingDelimiterEnd(text, opening, openCharacter, closeCharacter) {
  let depth = 0;
  let state = "code";
  for (let index = opening; index < text.length; index += 1) {
    const current = text[index];
    const next = text[index + 1];
    if (state === "line-comment") {
      if (current === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      if (current === "*" && next === "/") {
        state = "code";
        index += 1;
      }
      continue;
    }
    if (state === "single" || state === "double" || state === "template") {
      if (current === "\\") {
        index += 1;
        continue;
      }
      if (
        (state === "single" && current === "'")
        || (state === "double" && current === '"')
        || (state === "template" && current === "`")
      ) {
        state = "code";
      }
      continue;
    }
    if (current === "/" && next === "/") {
      state = "line-comment";
      index += 1;
      continue;
    }
    if (current === "/" && next === "*") {
      state = "block-comment";
      index += 1;
      continue;
    }
    if (current === "'") state = "single";
    else if (current === '"') state = "double";
    else if (current === "`") state = "template";
    else if (current === openCharacter) depth += 1;
    else if (current === closeCharacter) {
      depth -= 1;
      if (depth === 0) return index + 1;
    }
  }
  return -1;
}

function matchingBraceEnd(text, opening) {
  return matchingDelimiterEnd(text, opening, "{", "}");
}

function declarationCandidateGroups(text, name) {
  const escaped = escapeRegExp(name);
  const patterns = [
    new RegExp(`(?:^|\\n)[^\\n;{}]*\\b(?:function|class|struct|enum|trait|fn)\\s+${escaped}\\b`, "gu"),
    new RegExp(`(?:^|\\n)[^\\n;{}]*\\b(?:const|let|var|static)\\s+${escaped}\\s*(?::[^=;]+)?=`, "gu"),
    new RegExp(`(?:^|\\n)\\s*(?!(?:if|while|for|switch|return|else)\\b)[^\\n;{}]*\\b${escaped}\\s*\\([^;{}]*\\)[ \\t]*(?:const[ \\t]*)?(?:noexcept[ \\t]*)?(?:->[^\\n{]+)?(?:\\n[ \\t]*)?\\{`, "gu"),
  ];
  return patterns.map((pattern) => [...new Set(
    [...text.matchAll(pattern)].map(
      (match) => match.index + match[0].search(/\S/u),
    ),
  )].sort((left, right) => left - right));
}

function declarationRange(text, name) {
  const candidates = [...new Set(declarationCandidateGroups(text, name).flat())]
    .sort((left, right) => left - right);
  if (candidates.length !== 1) return null;
  const startByte = candidates[0];
  const opening = text.indexOf("{", startByte);
  if (opening < 0) return lineRange(text, startByte);
  const endByte = matchingBraceEnd(text, opening);
  return endByte < 0 ? null : { startByte, endByte };
}

function robustFunctionDeclarationRange(text, name) {
  const definitions = [];
  for (const call of callExpressionRangesWithin(text, name, { startByte: 0, endByte: text.length })) {
    let cursor = call.endByte;
    while (cursor < text.length && cursor < call.endByte + 500 && /\s/u.test(text[cursor])) cursor += 1;
    while (cursor < text.length && cursor < call.endByte + 500 && text[cursor] !== "{") {
      if ([";", ",", ")", "]", "="].includes(text[cursor])) break;
      cursor += 1;
      while (cursor < text.length && /\s/u.test(text[cursor])) cursor += 1;
    }
    if (text[cursor] !== "{") continue;
    const lineStart = text.lastIndexOf("\n", call.startByte - 1) + 1;
    const prefix = text.slice(lineStart, call.startByte);
    if (/^\s*(?:if|while|for|switch|return|else)\b/u.test(prefix)) continue;
    const endByte = matchingBraceEnd(text, cursor);
    if (endByte < 0) continue;
    const prefixStart = prefix.search(/\S/u);
    definitions.push({ startByte: prefixStart < 0 ? call.startByte : lineStart + prefixStart, endByte });
  }
  const unique = [...new Map(definitions.map((range) => [`${range.startByte}:${range.endByte}`, range])).values()];
  return unique.length === 1 ? unique[0] : null;
}

function typeDeclarationRange(text, name) {
  const escaped = escapeRegExp(name);
  const matches = [...text.matchAll(new RegExp(`(?:^|\\n)\\s*(?:class|struct|enum|trait)\\s+${escaped}\\b`, "gu"))];
  if (matches.length !== 1) return null;
  const startByte = matches[0].index + matches[0][0].search(/\S/u);
  const opening = text.indexOf("{", startByte);
  const endByte = opening < 0 ? -1 : matchingBraceEnd(text, opening);
  return endByte < 0 ? null : { startByte, endByte };
}

function qualifiedDeclarationRange(text, name) {
  const direct = robustFunctionDeclarationRange(text, name);
  if (direct || !name.includes("::")) return direct;
  const separator = name.lastIndexOf("::");
  const owner = name.slice(0, separator);
  const member = name.slice(separator + 2);
  const ownerRange = typeDeclarationRange(text, owner);
  if (!ownerRange) return null;
  const ownerText = text.slice(ownerRange.startByte, ownerRange.endByte);
  const memberRange = robustFunctionDeclarationRange(ownerText, member);
  return memberRange && {
    startByte: ownerRange.startByte + memberRange.startByte,
    endByte: ownerRange.startByte + memberRange.endByte,
  };
}

function arrayDeclarationRange(text, name) {
  const candidates = [...new Set(declarationCandidateGroups(text, name).flat())]
    .sort((left, right) => left - right);
  if (candidates.length !== 1) return null;
  const startByte = candidates[0];
  const equals = text.indexOf("=", startByte);
  const opening = text.indexOf("[", equals >= 0 ? equals : startByte);
  if (opening < 0) return null;
  const endByte = matchingDelimiterEnd(text, opening, "[", "]");
  return endByte < 0 ? null : { startByte, endByte };
}

function uniqueTokenRange(text, tokens) {
  const offsets = [];
  for (const token of new Set(tokens.filter(Boolean))) {
    let offset = text.indexOf(token);
    while (offset >= 0) {
      offsets.push({ offset, token });
      offset = text.indexOf(token, offset + token.length);
    }
  }
  const unique = [...new Map(
    offsets.map(({ offset, token }) => [offset, { offset, token }]),
  ).values()];
  return unique.length === 1 ? lineRange(text, unique[0].offset) : null;
}

function tokenRangesWithin(text, token, containerRange) {
  const ranges = [];
  let offset = text.indexOf(token, containerRange.startByte);
  while (offset >= 0 && offset < containerRange.endByte) {
    ranges.push(lineRange(text, offset));
    offset = text.indexOf(token, offset + token.length);
  }
  return ranges;
}

function callExpressionRangesWithin(text, callee, containerRange) {
  const ranges = [];
  let state = "code";
  for (let index = containerRange.startByte; index < containerRange.endByte; index += 1) {
    const current = text[index];
    const next = text[index + 1];
    if (state === "line-comment") {
      if (current === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      if (current === "*" && next === "/") {
        state = "code";
        index += 1;
      }
      continue;
    }
    if (state === "single" || state === "double") {
      if (current === "\\") index += 1;
      else if ((state === "single" && current === "'") || (state === "double" && current === '"')) {
        state = "code";
      }
      continue;
    }
    if (current === "/" && next === "/") {
      state = "line-comment";
      index += 1;
      continue;
    }
    if (current === "/" && next === "*") {
      state = "block-comment";
      index += 1;
      continue;
    }
    if (current === "'") {
      state = "single";
      continue;
    }
    if (current === '"') {
      state = "double";
      continue;
    }
    if (!text.startsWith(callee, index)) continue;
    const previous = text[index - 1];
    const following = text[index + callee.length];
    if ((previous && /[A-Za-z0-9_$]/u.test(previous)) || (following && /[A-Za-z0-9_$]/u.test(following))) {
      continue;
    }
    let opening = index + callee.length;
    while (/\s/u.test(text[opening])) opening += 1;
    if (text[opening] !== "(") continue;
    const endByte = matchingDelimiterEnd(text, opening, "(", ")");
    if (endByte < 0 || endByte > containerRange.endByte) continue;
    ranges.push({ startByte: index, endByte });
    index = endByte - 1;
  }
  return ranges;
}

function enclosingGuardLineRange(text, token, offset) {
  const candidates = [];
  let guardOffset = text.indexOf(token);
  while (guardOffset >= 0) {
    const opening = text.indexOf("{", guardOffset);
    const end = opening < 0 ? -1 : matchingBraceEnd(text, opening);
    if (opening >= 0 && opening < offset && end > offset) {
      candidates.push(lineRange(text, guardOffset));
    }
    guardOffset = text.indexOf(token, guardOffset + token.length);
  }
  return candidates.length === 1 ? candidates[0] : null;
}

function locatorContainer(locator) {
  if (locator === "<module>" || locator.startsWith("<module>.")) return "<module>";
  let value = locator;
  for (const marker of [
    ":external:", ":dynamic:", ":globals:", ":apple:", ":posix:",
    ":windows:", ":android:", ":ios:", ":linux:", ":defined:",
    ":source:", ":output:", ":call:", ":method:", ":qualified:",
  ]) {
    const index = value.indexOf(marker);
    if (index > 0) value = value.slice(0, index);
  }
  if (value.startsWith("exports:")) value = value.slice("exports:".length);
  if (value.startsWith("java-call:")) value = value.slice("java-call:".length);
  if (value.startsWith("java:")) value = value.slice("java:".length);
  if (value.startsWith("jni-callback:")) value = value.slice("jni-callback:".length);
  if (value.startsWith("jni:")) value = value.slice("jni:".length);
  value = value.replace(/\.prototype(?:\.|$).*/u, "");
  value = value.replace(/\.\[\[.*$/u, "");
  value = value.split(/[.:]/u)[0];
  return value;
}

function modulesRange(text, locator) {
  const parts = locator.split(":");
  if (parts[0] === "specifiers" && parts[1]) {
    return uniqueTokenRange(text, [`  ${parts[1]}:`, `${parts[1]}:`]);
  }
  if (parts[0] === "sources" && parts[1]) {
    return uniqueTokenRange(text, [`  ${parts[1]}:`, `${parts[1]}:`]);
  }
  return null;
}

function runtimeSurfaceRange(text, locator) {
  const prefix = "clapSurface.command:";
  if (!locator.startsWith(prefix)) return null;
  const rest = locator.slice(prefix.length);
  const optionMarker = ":option:";
  const positionalMarker = ":positional:";
  const marker = rest.includes(optionMarker)
    ? optionMarker
    : rest.includes(positionalMarker)
      ? positionalMarker
      : null;
  const command = marker ? rest.slice(0, rest.indexOf(marker)) : rest;
  const child = marker ? rest.slice(rest.indexOf(marker) + marker.length) : null;
  const commandRange = uniqueTokenRange(text, [`"path": "${command}"`]);
  if (!commandRange || !child) return commandRange;
  const commandStart = commandRange.startByte;
  const nextCommand = text.indexOf('"path": "ibex', commandRange.endByte);
  const commandEnd = nextCommand < 0 ? text.length : nextCommand;
  const slice = text.slice(commandStart, commandEnd);
  const childRange = uniqueTokenRange(slice, [`"id": "${child}"`]);
  return childRange
    ? {
        startByte: commandStart + childRange.startByte,
        endByte: commandStart + childRange.endByte,
      }
    : null;
}

function buildSelectionRange(text, locator) {
  const prefix = "backend-selection:";
  if (!locator.startsWith(prefix)) return null;
  const filename = locator.slice(prefix.length).split(":").at(-1);
  return uniqueTokenRange(text, [`.file("src/engine/${filename}")`]);
}

function moduleGlobalRange(text, locator) {
  const prefix = "<module>:globals:";
  if (!locator.startsWith(prefix)) return null;
  const logicalPath = locator.slice(prefix.length).split(".");
  if (logicalPath[0] !== "ExactBundle") return null;
  if (logicalPath.length === 1) {
    return uniqueTokenRange(text, [
      "(globalThis as any).ExactBundle = (globalThis as any).ExactBundle || runtimeBundle;",
    ]);
  }
  return declarationRange(text, logicalPath[1]);
}

function namedObjectEntryRange(text, containerRange, name) {
  const escaped = escapeRegExp(name);
  const pattern = new RegExp(`^  ${escaped}:`, "gmu");
  const matches = [...text.slice(containerRange.startByte, containerRange.endByte).matchAll(pattern)];
  if (matches.length !== 1) return null;
  const startByte = containerRange.startByte + matches[0].index;
  const next = /^  [A-Za-z_$][A-Za-z0-9_$]*:/gmu;
  next.lastIndex = matches[0].index + matches[0][0].length;
  const following = next.exec(text.slice(containerRange.startByte, containerRange.endByte));
  return {
    startByte,
    endByte: following ? containerRange.startByte + following.index : containerRange.endByte,
  };
}

function enclosingObjectRange(text, offset, lowerBound, upperBound) {
  let opening = text.lastIndexOf("{", offset);
  while (opening >= lowerBound) {
    const endByte = matchingBraceEnd(text, opening);
    if (endByte > offset && endByte <= upperBound) return { startByte: opening, endByte };
    opening = text.lastIndexOf("{", opening - 1);
  }
  return null;
}

function resolveRange(sourcePath, locator, text, absolute) {
  const cacheKey = `${absolute}\0${locator}`;
  if (rangeCache.has(cacheKey)) return rangeCache.get(cacheKey);
  let range;
  if (sourcePath === "modules.ts") return modulesRange(text, locator);
  if (sourcePath === "runtime-surface.json") return runtimeSurfaceRange(text, locator);
  if (sourcePath === "build.rs" && locator.startsWith("backend-selection:")) {
    return buildSelectionRange(text, locator);
  }
  if (locator.startsWith("<module>:globals:")) {
    range = moduleGlobalRange(text, locator);
  } else if (locator === "<module>" || locator.startsWith("<module>.")) {
    range = null;
  } else if (locator.startsWith("jsi-global:")) {
    const name = locator.slice("jsi-global:".length).split(/[.:]/u)[0];
    range = uniqueTokenRange(text, [`"${name}"`, `'${name}'`]);
  } else if (locator.startsWith("defineLazyGlobal:globals:")) {
    const name = locator.slice("defineLazyGlobal:globals:".length).split(/[.:]/u)[0];
    range = uniqueTokenRange(text, [
      `defineLazyGlobal(g, '${name}'`,
      `defineLazyGlobal(g, "${name}"`,
    ]);
  } else {
    const container = locatorContainer(locator);
    const containerKey = `${absolute}\0${container}`;
    let declaration = containerRangeCache.get(containerKey);
    if (declaration === undefined) {
      declaration = container && container !== "default"
        ? declarationRange(text, container)
        : null;
      containerRangeCache.set(containerKey, declaration);
    }
    range = declaration ?? uniqueTokenRange(text, [
      container && `"${container}"`,
      container && `'${container}'`,
      container && `.${container}`,
      container,
    ]);
  }
  rangeCache.set(cacheKey, range);
  return range;
}

function stableId(prefix, value) {
  return `${prefix}-${crypto.createHash("sha256").update(value).digest("hex").slice(0, 20)}`;
}

function sourceSite({ sourceRef, path: sourcePath, role, siteKey, range, text, bytes }) {
  const startByte = Buffer.byteLength(text.slice(0, range.startByte), "utf8");
  const endByte = Buffer.byteLength(text.slice(0, range.endByte), "utf8");
  const slice = bytes.subarray(startByte, endByte);
  return {
    siteId: stableId("site", `${sourceRef}\0${siteKey}`),
    path: sourcePath,
    role,
    startByte,
    endByte,
    startLine: text.slice(0, range.startByte).split("\n").length,
    endLine: text.slice(0, range.endByte).split("\n").length,
    rawContentDigest: digest(slice),
  };
}

function errnoExportBinding({ sourceRef, sourcePath, locator, text, bytes }) {
  if (sourcePath !== "src/builtins/constants.js" || !locator.startsWith("exports:")) {
    return null;
  }
  const name = locator.slice("exports:".length);
  if (!/^E[A-Z0-9_]+$/u.test(name)) return null;
  const darwinTable = declarationRange(text, "_errnoDarwin");
  const linuxTable = declarationRange(text, "_errnoLinux");
  const selector = declarationRange(text, "_errno");
  const aggregation = uniqueTokenRange(text, ["_assign(_errno());"]);
  const publication = uniqueTokenRange(text, ["module.exports = constants;"]);
  if (!darwinTable || !linuxTable || !selector || !aggregation || !publication) return null;
  const darwin = tokenRangesWithin(text, `${name}:`, darwinTable);
  const linux = tokenRangesWithin(text, `${name}:`, linuxTable);
  if (darwin.length !== 1 || linux.length !== 1) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${name}.darwin`, range: darwin[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${name}.linux-android`, range: linux[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "selector", siteKey: "errno.selector", range: selector, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "errno.aggregation", range: aggregation, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "constants.publication", range: publication, text, bytes }),
  ];
  const byKey = new Map([
    ["darwin", sites[0].siteId],
    ["linux-android", sites[1].siteId],
    ["selector", sites[2].siteId],
    ["aggregation", sites[3].siteId],
    ["publication", sites[4].siteId],
  ]);
  const common = [byKey.get("selector"), byKey.get("aggregation"), byKey.get("publication")];
  return {
    sourceRef,
    locatorKind: "commonjs-export-platform-table",
    resolutionPolicy: "conditioned-alternatives",
    sites,
    producerPaths: [
      {
        pathId: stableId("producer", `${sourceRef}\0darwin-default`),
        conditionId: "runtime-platform:not-linux-or-android",
        requiredSiteIds: [byKey.get("darwin"), ...common],
      },
      {
        pathId: stableId("producer", `${sourceRef}\0linux-android`),
        conditionId: "runtime-platform:linux-or-android",
        requiredSiteIds: [byKey.get("linux-android"), ...common],
      },
    ],
  };
}

function processCwdBinding({ sourceRef, sourcePath, locator, text, bytes }) {
  if (
    sourcePath !== "src/engine/hermes_runtime_process_setup.cc"
    || locator !== "jsi-global:process.cwd"
  ) return null;
  const installer = declarationRange(text, "installProcessSetup");
  if (!installer) return null;
  const definitionStart = text.indexOf("  auto cwdFn =", installer.startByte);
  const definitionEndToken = "  processObj.setProperty(rt, \"cwd\", std::move(cwdFn));";
  const publicationStart = text.indexOf(definitionEndToken, definitionStart);
  const rootPublication = uniqueTokenRange(text, [
    "  rt.global().setProperty(rt, \"process\", std::move(processObj));",
  ]);
  if (definitionStart < 0 || publicationStart < 0 || !rootPublication) return null;
  const definition = {
    startByte: definitionStart,
    endByte: publicationStart,
  };
  const publication = lineRange(text, publicationStart);
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: "process.cwd.host-function", range: definition, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "process.cwd.property", range: publication, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "process.root-global", range: rootPublication, text, bytes }),
  ];
  return {
    sourceRef,
    locatorKind: "jsi-root-global-member",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${sourceRef}\0default`),
      conditionId: "target-branch:default",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  };
}

function moduleSpecifierBranchBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (sourcePath !== "modules.ts" || !locator.startsWith("specifiers:")) return null;
  if (!branch?.observedKey?.startsWith("builtin:")) return null;
  const sourceKey = locator.slice("specifiers:".length);
  const observedSpecifier = branch.observedKey.slice("builtin:".length);
  const sources = declarationRange(text, "sources");
  const specifiers = arrayDeclarationRange(text, "specifiers");
  if (!sources || !specifiers) return null;
  const sourceEntry = namedObjectEntryRange(text, sources, sourceKey);
  if (!sourceEntry) return null;
  const candidateNames = [observedSpecifier, `node:${observedSpecifier}`];
  const nameMatches = candidateNames.flatMap((name) => {
    const matches = [];
    for (const quote of ["'", '"']) {
      const token = `${quote}${name}${quote}`;
      let offset = text.indexOf(token, specifiers.startByte);
      while (offset >= 0 && offset < specifiers.endByte) {
        matches.push({ name, offset });
        offset = text.indexOf(token, offset + token.length);
      }
    }
    return matches;
  });
  const groups = [...new Map(nameMatches.map(({ offset }) => {
    const range = enclosingObjectRange(text, offset, specifiers.startByte, specifiers.endByte);
    return range ? [`${range.startByte}:${range.endByte}`, range] : [String(offset), null];
  })).values()].filter(Boolean).filter(
    (range) => range && text.slice(range.startByte, range.endByte).includes(`source: '${sourceKey}'`),
  );
  if (groups.length !== 1) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${sourceKey}.source-entry`, range: sourceEntry, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${sourceKey}.specifier.${observedSpecifier}`, range: groups[0], text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "builtin-specifier-registration",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${observedSpecifier}`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function walkJavaScript(node, visitor, parent = null) {
  if (!node || typeof node !== "object") return;
  if (typeof node.type === "string") visitor(node, parent);
  for (const [key, value] of Object.entries(node)) {
    if (["loc", "tokens", "comments", "errors"].includes(key)) continue;
    if (Array.isArray(value)) {
      for (const child of value) walkJavaScript(child, visitor, node);
    } else if (value && typeof value === "object" && typeof value.type === "string") {
      walkJavaScript(value, visitor, node);
    }
  }
}

function propertyName(node) {
  if (!node) return null;
  if (node.type === "Identifier" || node.type === "PrivateName") return node.name ?? node.id?.name ?? null;
  if (["StringLiteral", "NumericLiteral"].includes(node.type)) return String(node.value);
  return null;
}

function memberSegments(node) {
  if (!node) return null;
  if (node.type === "Identifier") return [node.name];
  if (node.type !== "MemberExpression" && node.type !== "OptionalMemberExpression") return null;
  const base = memberSegments(node.object);
  const property = node.computed ? propertyName(node.property) : propertyName(node.property);
  return base && property !== null ? [...base, property] : null;
}

function javascriptIndex(absolute, text) {
  const cached = javascriptIndexCache.get(absolute);
  if (cached) return cached;
  const ast = parse(text, {
    sourceType: "unambiguous",
    allowReturnOutsideFunction: true,
    plugins: [
      "classProperties",
      "classPrivateProperties",
      "classPrivateMethods",
      ...(absolute.endsWith(".ts") || absolute.endsWith(".tsx")
        ? ["typescript", "decorators-legacy"]
        : []),
    ],
  });
  const declarations = new Map();
  const assignments = [];
  const modulePublications = [];
  const defineProperties = [];
  const esmPublications = [];
  const addDeclaration = (name, row) => {
    if (!name) return;
    const rows = declarations.get(name) ?? [];
    rows.push(row);
    declarations.set(name, rows);
  };
  walkJavaScript(ast.program, (node, parent) => {
    if (["FunctionDeclaration", "ClassDeclaration"].includes(node.type)) {
      addDeclaration(node.id?.name, { node, value: node, parent });
    } else if (node.type === "VariableDeclarator" && node.id?.type === "Identifier") {
      addDeclaration(node.id.name, { node: parent ?? node, value: node.init, parent });
    } else if (node.type === "AssignmentExpression") {
      const segments = memberSegments(node.left);
      assignments.push({ node, segments, value: node.right, parent });
      if (
        segments?.length === 2
        && segments[0] === "module"
        && segments[1] === "exports"
      ) {
        modulePublications.push({ node: parent ?? node, value: node.right });
      }
    } else if (node.type === "CallExpression"
      && JSON.stringify(memberSegments(node.callee)) === JSON.stringify(["Object", "defineProperty"])
      && propertyName(node.arguments[1]) !== null) {
      defineProperties.push({
        node: parent?.type === "ExpressionStatement" ? parent : node,
        targetSegments: memberSegments(node.arguments[0]),
        property: propertyName(node.arguments[1]),
        descriptor: node.arguments[2],
      });
    } else if (node.type === "ExportNamedDeclaration") {
      if (node.declaration) {
        const name = node.declaration.id?.name;
        if (name) esmPublications.push({
          exported: name,
          local: name,
          node,
          value: node.declaration,
        });
      }
      for (const specifier of node.specifiers ?? []) {
        const exported = propertyName(specifier.exported);
        const local = propertyName(specifier.local);
        if (exported && local) esmPublications.push({ exported, local, node, value: specifier.local });
      }
    } else if (node.type === "ExportDefaultDeclaration") {
      esmPublications.push({
        exported: "default",
        local: node.declaration?.name ?? null,
        node,
        value: node.declaration,
      });
    }
  });
  const result = { declarations, assignments, modulePublications, defineProperties, esmPublications };
  javascriptIndexCache.set(absolute, result);
  return result;
}

function objectProperties(objectNode, name) {
  if (objectNode?.type !== "ObjectExpression") return null;
  return objectNode.properties.filter(
    (property) => ["ObjectProperty", "ObjectMethod"].includes(property.type)
      && !property.computed
      && propertyName(property.key) === name,
  );
}

function objectProperty(objectNode, name) {
  const properties = objectProperties(objectNode, name) ?? [];
  return properties.length === 1 ? properties[0] : null;
}

function declarationFor(index, name) {
  const rows = index.declarations.get(name) ?? [];
  return rows.length === 1 ? rows[0] : null;
}

function resolveIdentifierValue(index, node, seen = new Set()) {
  if (node?.type !== "Identifier" || seen.has(node.name)) return { node, declaration: null };
  seen.add(node.name);
  const declaration = declarationFor(index, node.name);
  if (!declaration) return { node, declaration: null };
  if (declaration.value?.type === "Identifier") {
    const resolved = resolveIdentifierValue(index, declaration.value, seen);
    return { ...resolved, aliasDeclaration: declaration };
  }
  return { node: declaration.value ?? declaration.node, declaration };
}

function memberProducer(index, ownerName, memberName, preference = "prefer-static") {
  const owner = declarationFor(index, ownerName);
  const ownerValue = owner?.value;
  const selectClassMember = (classNode) => {
    const matching = classNode.body.body.filter(
      (method) => ["ClassMethod", "ClassPrivateMethod", "ClassProperty"].includes(method.type)
        && propertyName(method.key) === memberName,
    );
    const staticMembers = matching.filter((method) => Boolean(method.static));
    const prototypeMembers = matching.filter((method) => !method.static);
    if (preference === "static") return staticMembers.length === 1 ? staticMembers[0] : null;
    if (preference === "prototype") return prototypeMembers.length === 1 ? prototypeMembers[0] : null;
    if (staticMembers.length === 1) return staticMembers[0];
    return prototypeMembers.length === 1 ? prototypeMembers[0] : null;
  };
  if (ownerValue?.type === "ClassDeclaration" || ownerValue?.type === "ClassExpression") {
    const selected = selectClassMember(ownerValue);
    if (selected) return selected;
  }
  if (owner?.node?.type === "ClassDeclaration") {
    const selected = selectClassMember(owner.node);
    if (selected) return selected;
  }
  const staticAssignments = index.assignments.filter(({ segments }) =>
    JSON.stringify(segments) === JSON.stringify([ownerName, memberName]));
  const prototypeAssignments = index.assignments.filter(({ segments }) =>
    JSON.stringify(segments) === JSON.stringify([ownerName, "prototype", memberName]));
  const staticDescriptors = index.defineProperties.filter((row) =>
    row.property === memberName
    && JSON.stringify(row.targetSegments) === JSON.stringify([ownerName]));
  const prototypeDescriptors = index.defineProperties.filter((row) =>
    row.property === memberName
    && JSON.stringify(row.targetSegments) === JSON.stringify([ownerName, "prototype"]));
  if (preference === "prototype") {
    if (prototypeAssignments.length === 1) return prototypeAssignments[0].node;
    return prototypeDescriptors.length === 1 ? prototypeDescriptors[0].node : null;
  }
  if (preference === "static") {
    if (staticAssignments.length === 1) return staticAssignments[0].node;
    return staticDescriptors.length === 1 ? staticDescriptors[0].node : null;
  }
  if (staticAssignments.length === 1) return staticAssignments[0].node;
  if (staticDescriptors.length === 1) return staticDescriptors[0].node;
  if (prototypeAssignments.length === 1) return prototypeAssignments[0].node;
  if (prototypeDescriptors.length === 1) return prototypeDescriptors[0].node;
  return null;
}

function commonjsInheritedExportBinding({ branch, sourceRef, sourcePath, exportPath, absolute, text, bytes }) {
  const match = /^([^.]*)\.\[\[dynamic-table:inherited-[^\]]+-properties\]\]$/u.exec(exportPath);
  if (!match) return null;
  const exportedRoot = match[1];
  const index = javascriptIndex(absolute, text);
  if (index.modulePublications.length !== 1) return null;
  const modulePublication = index.modulePublications[0];
  const moduleDeclaration = modulePublication.value.type === "Identifier"
    ? declarationFor(index, modulePublication.value.name)
    : null;
  const moduleValue = moduleDeclaration?.value ?? modulePublication.value;
  const rootProperty = objectProperty(moduleValue, exportedRoot);
  const rootValue = rootProperty?.value;
  if (!rootProperty || rootValue?.type !== "Identifier") return null;
  const owner = rootValue.name;
  const ownerDeclaration = declarationFor(index, owner);
  if (!ownerDeclaration) return null;
  const aliases = [];
  walkJavaScript(parse(text, { sourceType: "script", allowReturnOutsideFunction: true }).program, (node, parent) => {
    if (node.type === "CallExpression"
      && JSON.stringify(memberSegments(node.callee)) === JSON.stringify(["Object", "setPrototypeOf"])
      && JSON.stringify(memberSegments(node.arguments[0])) === JSON.stringify([owner, "prototype"])) {
      aliases.push(parent?.type === "ExpressionStatement" ? parent : node);
    }
  });
  if (aliases.length !== 1) return null;
  const baseExpression = aliases[0].expression?.arguments?.[1] ?? aliases[0].arguments?.[1];
  const baseSegments = memberSegments(baseExpression);
  if (!baseSegments || baseSegments.at(-1) !== "prototype") return null;
  const retainedBase = baseSegments[0];
  const retentionAssignments = index.assignments.filter(({ segments, value }) =>
    JSON.stringify(segments) === JSON.stringify([retainedBase])
    && value?.type === "MemberExpression"
    && propertyName(value.property) === "Transform");
  const guard = enclosingGuardLineRange(
    text,
    `if (${retainedBase}) {`,
    aliases[0].start,
  );
  if (retentionAssignments.length !== 1 || !guard) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${owner}.definition`, range: { startByte: ownerDeclaration.node.start, endByte: ownerDeclaration.node.end }, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "retention", siteKey: `${retainedBase}.capture`, range: { startByte: retentionAssignments[0].node.start, endByte: retentionAssignments[0].node.end }, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "guard", siteKey: `${retainedBase}.guard`, range: guard, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "alias", siteKey: `${owner}.prototype-alias`, range: { startByte: aliases[0].start, endByte: aliases[0].end }, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "alias", siteKey: `${exportedRoot}.root-export`, range: { startByte: rootProperty.start, endByte: rootProperty.end }, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "module.exports", range: { startByte: modulePublication.node.start, endByte: modulePublication.node.end }, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "commonjs-inherited-export-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0inherited`),
      conditionId: "runtime-dependency:stream-transform-present",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function classElementName(element) {
  const direct = propertyName(element.key);
  if (direct !== null) return direct;
  const segments = memberSegments(element.key);
  return element.computed && segments ? `[[${segments.join(".")}]]` : null;
}

function typescriptClassMemberBinding({ sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (!sourcePath.startsWith("packages/ibex-runtime-js/src/") || !/\.tsx?$/u.test(sourcePath)) {
    return null;
  }
  if (locator.includes(":globals:") || locator.startsWith("<module>")) return null;
  const extendsMarker = ":extends:";
  const extendsIndex = locator.indexOf(extendsMarker);
  const pathPart = extendsIndex >= 0 ? locator.slice(0, extendsIndex) : locator;
  const className = pathPart.split(".")[0];
  const index = javascriptIndex(absolute, text);
  const declaration = declarationFor(index, className);
  const classNode = declaration?.node?.type === "ClassDeclaration"
    ? declaration.node
    : declaration?.value;
  if (!classNode || !["ClassDeclaration", "ClassExpression"].includes(classNode.type)) return null;
  let producer = classNode;
  let siteKey = `${className}.definition`;
  if (extendsIndex >= 0) {
    const expectedBase = locator.slice(extendsIndex + extendsMarker.length);
    const actualBase = memberSegments(classNode.superClass)?.join(".");
    if (actualBase !== expectedBase) return null;
    siteKey = `${className}.extends.${expectedBase}`;
  } else if (pathPart !== className) {
    const prototypePrefix = `${className}.prototype.`;
    const staticPrefix = `${className}.`;
    const prototype = pathPart.startsWith(prototypePrefix);
    const memberName = pathPart.slice((prototype ? prototypePrefix : staticPrefix).length);
    if (!memberName || (!prototype && !pathPart.startsWith(staticPrefix))) return null;
    const members = classNode.body.body.filter((element) =>
      classElementName(element) === memberName
      && Boolean(element.static) === !prototype,
    );
    if (members.length !== 1) return null;
    producer = members[0];
    siteKey = `${className}.${prototype ? "prototype." : ""}${memberName}`;
  }
  const site = sourceSite({
    sourceRef,
    path: sourcePath,
    role: extendsIndex >= 0 ? "alias" : "value-producer",
    siteKey,
    range: { startByte: producer.start, endByte: producer.end },
    text,
    bytes,
  });
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: extendsIndex >= 0 ? "typescript-class-inheritance" : "typescript-class-member",
    resolutionPolicy: "provenance-only",
    sites: [site],
    producerPaths: [],
  });
}

function bootstrapGlobalBinding({ sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (sourcePath !== "packages/ibex-runtime-js/src/bootstrap.ts") return null;
  const lazyPrefix = "defineLazyGlobal:globals:";
  const installMarker = ":globals:";
  const lazy = locator.startsWith(lazyPrefix);
  const markerIndex = locator.indexOf(installMarker);
  if (!lazy && markerIndex < 1) return null;
  const logicalPath = (lazy
    ? locator.slice(lazyPrefix.length)
    : locator.slice(markerIndex + installMarker.length)).split(".");
  const root = logicalPath[0];
  const candidates = [];
  walkJavaScript(parse(text, {
    sourceType: "module",
    plugins: ["typescript", "decorators-legacy"],
  }).program, (node, parent) => {
    if (lazy && node.type === "CallExpression" && node.callee?.type === "Identifier"
      && node.callee.name === "defineLazyGlobal" && propertyName(node.arguments[1]) === root) {
      candidates.push({ node: parent?.type === "ExpressionStatement" ? parent : node, role: "lazy-trigger" });
    }
    if (!lazy && node.type === "CallExpression"
      && JSON.stringify(memberSegments(node.callee)) === JSON.stringify(["Object", "defineProperty"])
      && ["g", "globalThis"].includes(node.arguments[0]?.name)
      && propertyName(node.arguments[1]) === root) {
      candidates.push({ node: parent?.type === "ExpressionStatement" ? parent : node, role: "publication" });
    }
    if (!lazy && node.type === "AssignmentExpression") {
      const segments = memberSegments(node.left);
      if (segments?.length === 2 && ["g", "globalThis"].includes(segments[0]) && segments[1] === root) {
        candidates.push({ node: parent?.type === "ExpressionStatement" ? parent : node, role: "publication" });
      }
    }
  });
  const unique = [...new Map(candidates.map((candidate) => [
    `${candidate.node.start}:${candidate.node.end}`,
    candidate,
  ])).values()];
  if (unique.length !== 1) return null;
  const candidate = unique[0];
  const site = sourceSite({
    sourceRef,
    path: sourcePath,
    role: candidate.role,
    siteKey: `${root}.${candidate.role}`,
    range: { startByte: candidate.node.start, endByte: candidate.node.end },
    text,
    bytes,
  });
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: lazy ? "typescript-lazy-global-publication" : "typescript-global-publication",
    resolutionPolicy: "provenance-only",
    sites: [site],
    producerPaths: [],
  });
}

function legacyBootstrapGlobalBinding({ branch, sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (!sourcePath.startsWith("src/engine/bootstrap/") || !sourcePath.endsWith(".js")) return null;
  if (locator.includes(":") || locator.includes("[[")) return null;
  const parts = locator.split(".");
  if (parts.length > 2) return null;
  const root = parts[0];
  const index = javascriptIndex(absolute, text);
  const rootDeclaration = declarationFor(index, root);
  let producer = parts.length === 1
    ? rootDeclaration?.node
    : memberProducer(index, root, parts[1]);
  if (!producer) return null;
  const publications = [];
  for (const assignment of index.assignments) {
    if (JSON.stringify(assignment.segments) === JSON.stringify(["globalThis", root])) {
      publications.push({ node: assignment.parent?.type === "ExpressionStatement" ? assignment.parent : assignment.node, role: "publication" });
    }
  }
  const ast = parse(text, { sourceType: "script", allowReturnOutsideFunction: true });
  walkJavaScript(ast.program, (node, parent) => {
    if (node.type === "CallExpression" && node.callee?.type === "Identifier"
      && node.callee.name === "defineLazyGlobal" && propertyName(node.arguments[0]) === root) {
      publications.push({ node: parent?.type === "ExpressionStatement" ? parent : node, role: "lazy-trigger" });
    }
    if (node.type === "CallExpression"
      && JSON.stringify(memberSegments(node.callee)) === JSON.stringify(["Object", "defineProperty"])
      && node.arguments[0]?.type === "Identifier" && node.arguments[0].name === "globalThis"
      && propertyName(node.arguments[1]) === root) {
      publications.push({ node: parent?.type === "ExpressionStatement" ? parent : node, role: "publication" });
    }
  });
  const uniquePublications = [...new Map(publications.map((publication) => [
    `${publication.role}:${publication.node.start}:${publication.node.end}`,
    publication,
  ])).values()];
  if (
    uniquePublications.length === 0
    || !uniquePublications.some((publication) => publication.role === "publication")
  ) return null;
  const sites = [sourceSite({
    sourceRef,
    path: sourcePath,
    role: "value-producer",
    siteKey: `${locator}.producer`,
    range: { startByte: producer.start, endByte: producer.end },
    text,
    bytes,
  })];
  for (const [indexValue, publication] of uniquePublications.entries()) {
    sites.push(sourceSite({
      sourceRef,
      path: sourcePath,
      role: publication.role,
      siteKey: `${root}.${publication.role}.${indexValue}`,
      range: { startByte: publication.node.start, endByte: publication.node.end },
      text,
      bytes,
    }));
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "legacy-bootstrap-global-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0legacy-fallback`),
      conditionId: "legacy-bootstrap:global-missing",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function builtinExportBranchBinding({ branch, sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (!sourcePath.endsWith(".js")) return null;
  if (!locator.startsWith("exports:") || !branch?.observedKey?.startsWith("builtin:export:")) return null;
  const exportPath = locator.slice("exports:".length);
  const index = javascriptIndex(absolute, text);
  if (exportPath.includes("[[")) {
    return commonjsInheritedExportBinding({ branch, sourceRef, sourcePath, exportPath, absolute, text, bytes });
  }
  if (exportPath.includes("<")) return null;
  const parts = exportPath.split(".");
  if (index.modulePublications.length === 0) {
    const publications = index.esmPublications.filter((publication) => publication.exported === parts[0]);
    if (publications.length !== 1) return null;
    const publication = publications[0];
    const rootValue = publication.value;
    const resolvedRoot = resolveIdentifierValue(index, rootValue);
    let producerNode = resolvedRoot.declaration?.node ?? resolvedRoot.node;
    if (parts.length > 1) {
      if (parts.length !== 2) return null;
      const ownerName = publication.local ?? rootValue?.name;
      producerNode = ownerName ? memberProducer(index, ownerName, parts[1]) : null;
    }
    if (!producerNode || producerNode.start === undefined || producerNode.end === undefined) return null;
    const sites = [
      sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${exportPath}.producer`, range: { startByte: producerNode.start, endByte: producerNode.end }, text, bytes }),
      sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${exportPath}.esm-export`, range: { startByte: publication.node.start, endByte: publication.node.end }, text, bytes }),
    ];
    return validateRestrictedExactSourceBinding({
      sourceRef,
      locatorKind: "esm-export-route",
      resolutionPolicy: "composite-path",
      sites,
      producerPaths: [{
        pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${exportPath}`),
        conditionId: `target-branch:${branch.targetVariant}`,
        requiredSiteIds: sites.map((site) => site.siteId),
      }],
    });
  }
  if (index.modulePublications.length !== 1) return null;
  const modulePublication = index.modulePublications[0];
  let moduleValue = modulePublication.value;
  let moduleDeclaration = null;
  if (moduleValue.type === "Identifier") {
    moduleDeclaration = declarationFor(index, moduleValue.name);
    moduleValue = moduleDeclaration?.value;
  }
  let rootProperty;
  let rootValue;
  if (parts[0] === "default") {
    rootValue = modulePublication.value;
  } else {
    const matchingProperties = objectProperties(moduleValue, parts[0]) ?? [];
    if (
      parts.length === 1
      && matchingProperties.length === 2
      && new Set(matchingProperties.map((property) => property.kind)).size === 2
      && matchingProperties.every((property) => ["get", "set"].includes(property.kind))
    ) {
      const sites = matchingProperties.map((property) => sourceSite({
        sourceRef,
        path: sourcePath,
        role: "value-producer",
        siteKey: `${exportPath}.${property.kind}`,
        range: { startByte: property.start, endByte: property.end },
        text,
        bytes,
      }));
      sites.push(sourceSite({
        sourceRef,
        path: sourcePath,
        role: "publication",
        siteKey: "module.exports",
        range: { startByte: modulePublication.node.start, endByte: modulePublication.node.end },
        text,
        bytes,
      }));
      return validateRestrictedExactSourceBinding({
        sourceRef,
        locatorKind: "commonjs-export-route",
        resolutionPolicy: "composite-path",
        sites,
        producerPaths: [{
          pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${exportPath}`),
          conditionId: `target-branch:${branch.targetVariant}`,
          requiredSiteIds: sites.map((site) => site.siteId),
        }],
      });
    }
    rootProperty = matchingProperties.length === 1 ? matchingProperties[0] : null;
    rootValue = rootProperty?.type === "ObjectMethod" ? rootProperty : rootProperty?.value;
    if (!rootProperty) {
      const moduleIdentifier = modulePublication.value.type === "Identifier"
        ? modulePublication.value.name
        : null;
      const direct = index.assignments.filter(({ segments }) =>
        JSON.stringify(segments) === JSON.stringify(["module", "exports", parts[0]])
        || JSON.stringify(segments) === JSON.stringify(["exports", parts[0]])
        || (moduleIdentifier
          && JSON.stringify(segments) === JSON.stringify([moduleIdentifier, parts[0]]))
      );
      if (direct.length !== 1) return null;
      rootProperty = direct[0].node;
      rootValue = direct[0].value;
    }
  }
  const resolvedRoot = resolveIdentifierValue(index, rootValue);
  let producerNode = resolvedRoot.declaration?.node ?? resolvedRoot.node;
  if (parts.length > 1) {
    if (parts.length !== 2 || parts[1] === "constructor") {
      if (parts.length === 2 && parts[1] === "constructor") {
        producerNode = resolvedRoot.declaration?.node ?? resolvedRoot.node;
      } else {
        return null;
      }
    } else {
      const ownerName = rootValue?.type === "Identifier"
        ? (resolvedRoot.declaration?.node?.id?.name ?? rootValue.name)
        : null;
      producerNode = ownerName ? memberProducer(index, ownerName, parts[1]) : null;
    }
  }
  if (!producerNode?.start && producerNode?.start !== 0) return null;
  const sites = [
    sourceSite({
      sourceRef,
      path: sourcePath,
      role: "value-producer",
      siteKey: `${exportPath}.producer`,
      range: { startByte: producerNode.start, endByte: producerNode.end },
      text,
      bytes,
    }),
  ];
  if (rootProperty && rootProperty !== producerNode) {
    sites.push(sourceSite({
      sourceRef,
      path: sourcePath,
      role: rootValue?.type === "Identifier" ? "alias" : "registration",
      siteKey: `${exportPath}.root-export`,
      range: { startByte: rootProperty.start, endByte: rootProperty.end },
      text,
      bytes,
    }));
  }
  sites.push(sourceSite({
    sourceRef,
    path: sourcePath,
    role: "publication",
    siteKey: "module.exports",
    range: { startByte: modulePublication.node.start, endByte: modulePublication.node.end },
    text,
    bytes,
  }));
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "commonjs-export-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${exportPath}`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function splitTopLevelArguments(text) {
  const parts = [];
  let start = 0;
  let depth = 0;
  let state = "code";
  for (let index = 0; index < text.length; index += 1) {
    const current = text[index];
    const next = text[index + 1];
    if (state === "line-comment") {
      if (current === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      if (current === "*" && next === "/") {
        state = "code";
        index += 1;
      }
      continue;
    }
    if (["single", "double"].includes(state)) {
      if (current === "\\") index += 1;
      else if ((state === "single" && current === "'") || (state === "double" && current === '"')) state = "code";
      continue;
    }
    if (current === "/" && next === "/") {
      state = "line-comment";
      index += 1;
    } else if (current === "/" && next === "*") {
      state = "block-comment";
      index += 1;
    } else if (current === "'") state = "single";
    else if (current === '"') state = "double";
    else if (["(", "[", "{"].includes(current)) depth += 1;
    else if ([")", "]", "}"].includes(current)) depth -= 1;
    else if (current === "," && depth === 0) {
      parts.push(text.slice(start, index).trim());
      start = index + 1;
    }
  }
  parts.push(text.slice(start).trim());
  return parts;
}

function setPropertyCalls(text, property) {
  const calls = [];
  const marker = ".setProperty";
  let markerOffset = text.indexOf(marker);
  while (markerOffset >= 0) {
    const opening = text.indexOf("(", markerOffset + marker.length);
    const end = opening < 0 ? -1 : matchingDelimiterEnd(text, opening, "(", ")");
    if (end < 0) break;
    const prefix = text.slice(Math.max(0, markerOffset - 100), markerOffset);
    const callerMatch = /((?:[A-Za-z_$][A-Za-z0-9_$]*\.)?global\(\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*$/u.exec(prefix);
    const args = splitTopLevelArguments(text.slice(opening + 1, end - 1));
    const propertyArg = args[1]?.trim();
    if (callerMatch && [`"${property}"`, `'${property}'`].includes(propertyArg)) {
      const startByte = markerOffset - callerMatch[0].trimStart().length;
      const semicolon = text.indexOf(";", end);
      calls.push({
        caller: callerMatch[1],
        value: args.slice(2).join(", ").trim(),
        range: { startByte, endByte: semicolon >= 0 ? semicolon + 1 : end },
      });
    }
    markerOffset = text.indexOf(marker, end);
  }
  return calls;
}

function movedIdentifier(expression) {
  const match = /^(?:std::move\()?([A-Za-z_$][A-Za-z0-9_$]*)(?:\))?$/u.exec(expression.trim());
  return match?.[1] ?? null;
}

function cppValueProducerRange(text, variable, before) {
  if (!variable) return null;
  const escaped = escapeRegExp(variable);
  const declaration = new RegExp(
    `(?:^|\\n)[^\\n;{}]*\\b${escaped}\\s*(?:=|\\()`,
    "gu",
  );
  const matches = [...text.slice(0, before).matchAll(declaration)];
  if (matches.length === 0) return null;
  const match = matches.at(-1);
  const startByte = match.index + (match[0][0] === "\n" ? 1 : 0);
  const equal = text.indexOf("=", startByte);
  const opening = text.indexOf("(", equal >= 0 && equal < before ? equal : startByte);
  if (opening >= 0 && opening < before) {
    const end = matchingDelimiterEnd(text, opening, "(", ")");
    if (end > 0 && end <= before) {
      const semicolon = text.indexOf(";", end);
      return { startByte, endByte: semicolon >= 0 && semicolon < before ? semicolon + 1 : end };
    }
  }
  return lineRange(text, startByte);
}

function jsiGlobalBranchBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!/\.(?:cc|mm|h)$/u.test(sourcePath) || !locator.startsWith("jsi-global:")) return null;
  if (locator === "jsi-global:process.cwd") return null;
  const logicalPath = locator.slice("jsi-global:".length).split(".");
  if (logicalPath.length > 2 || logicalPath.some((part) => part.includes("[["))) return null;
  const rootCalls = setPropertyCalls(text, logicalPath[0]).filter(
    (call) => ["rt.global()", "runtime.global()"].includes(call.caller),
  );
  if (rootCalls.length !== 1) return null;
  const rootCall = rootCalls[0];
  const rootVariable = movedIdentifier(rootCall.value);
  let producerRange;
  let memberCall;
  if (logicalPath.length === 1) {
    producerRange = cppValueProducerRange(text, rootVariable, rootCall.range.startByte)
      ?? rootCall.range;
  } else {
    if (!rootVariable) return null;
    const memberCalls = setPropertyCalls(text, logicalPath[1]).filter(
      (call) => call.caller === rootVariable && call.range.startByte < rootCall.range.startByte,
    );
    if (memberCalls.length !== 1) return null;
    memberCall = memberCalls[0];
    producerRange = cppValueProducerRange(
      text,
      movedIdentifier(memberCall.value),
      memberCall.range.startByte,
    ) ?? memberCall.range;
  }
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${logicalPath.join(".")}.producer`, range: producerRange, text, bytes }),
  ];
  if (memberCall) {
    sites.push(sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${logicalPath.join(".")}.member-publication`, range: memberCall.range, text, bytes }));
  }
  sites.push(sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${logicalPath[0]}.root-publication`, range: rootCall.range, text, bytes }));
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "jsi-root-global-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${logicalPath.join(".")}`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function exportedHostAbiBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("host-abi:") || branch.observedKey.startsWith("host-abi:java:")) {
    return null;
  }
  const symbol = branch.observedKey.slice("host-abi:".length);
  if (locator !== symbol || !/\.(?:cc|mm|rs)$/u.test(sourcePath)) return null;
  const range = declarationRange(text, symbol);
  if (!range) return null;
  const declaration = text.slice(range.startByte, Math.min(range.endByte, range.startByte + 500));
  const exported = sourcePath.endsWith(".rs")
    ? /pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn/u.test(declaration)
    : /extern\s+"C"/u.test(declaration);
  if (!exported) return null;
  const conditionId = sourcePath.endsWith(".rs")
    ? "linkage:strong-rust-export"
    : /\bWEAK_STUB\b/u.test(declaration)
      ? "linkage:weak-fallback-without-strong-export"
      : `target-branch:${branch.targetVariant}`;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${symbol}.definition`, range, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${symbol}.export`, range, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "exported-host-abi",
    resolutionPolicy: "single-site",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0exported-abi`),
      conditionId,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function callbackProducerBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  const marker = ":pushRuntimeCallback";
  if (
    branch?.observedKey !== `callback:producer:${sourcePath}:${locator}`
    || !locator.endsWith(marker)
    || !/\.(?:cc|mm)$/u.test(sourcePath)
  ) return null;
  const producerName = locator.slice(0, -marker.length);
  const producer = qualifiedDeclarationRange(text, producerName);
  if (!producer) return null;
  const enqueueCalls = callExpressionRangesWithin(text, "pushRuntimeCallback", producer);
  if (enqueueCalls.length === 0) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${producerName}.definition`, range: producer, text, bytes }),
    ...enqueueCalls.map((range, index) => sourceSite({
      sourceRef,
      path: sourcePath,
      role: "publication",
      siteKey: `${producerName}.enqueue.${index + 1}`,
      range,
      text,
      bytes,
    })),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "callback-producer-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0callback-enqueue`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function callbackDeliveryCondition(sourcePath, targetVariant) {
  if (sourcePath.includes("_windows.")) return "target-platform:windows";
  if (sourcePath === "src/engine/hermes_runtime_fs.cc") return "target-platform:not-windows";
  if (sourcePath.includes("_android.")) return "target-platform:android";
  if (sourcePath.includes("_ios.")) return "target-platform:ios";
  return `target-branch:${targetVariant}`;
}

function callbackDeliveryBinding({ branch, sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (
    !branch?.observedKey?.startsWith("callback:")
    || branch.observedKey.startsWith("callback:producer:")
    || !/\.(?:cc|mm)$/u.test(sourcePath)
  ) return null;
  const producer = qualifiedDeclarationRange(text, locator);
  if (!producer) return null;
  const enqueueCalls = callExpressionRangesWithin(text, "pushRuntimeCallback", producer);
  if (enqueueCalls.length === 0) return null;

  const root = path.resolve(
    path.dirname(absolute),
    ...Array(sourcePath.split("/").length - 1).fill(".."),
  );
  const queuePath = "src/engine/hermes_runtime.cc";
  const queueBytes = sourcePath === queuePath
    ? bytes
    : fs.readFileSync(path.join(root, queuePath));
  const queueText = sourcePath === queuePath ? text : queueBytes.toString("utf8");
  const enqueue = robustFunctionDeclarationRange(queueText, "pushRuntimeCallback");
  const drain = robustFunctionDeclarationRange(queueText, "drainCallbackQueue");
  if (!enqueue || !drain) return null;
  const retention = callExpressionRangesWithin(
    queueText,
    "runtime->callbackQueue.push_back",
    enqueue,
  );
  const dispatch = callExpressionRangesWithin(queueText, "entry.callback", drain);
  if (retention.length !== 1 || dispatch.length !== 1) return null;

  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${locator}.producer`, range: producer, text, bytes }),
    ...enqueueCalls.map((range, index) => sourceSite({
      sourceRef,
      path: sourcePath,
      role: "publication",
      siteKey: `${locator}.enqueue.${index + 1}`,
      range,
      text,
      bytes,
    })),
    sourceSite({ sourceRef, path: queuePath, role: "definition", siteKey: "callback-queue.enqueue", range: enqueue, text: queueText, bytes: queueBytes }),
    sourceSite({ sourceRef, path: queuePath, role: "retention", siteKey: "callback-queue.retention", range: retention[0], text: queueText, bytes: queueBytes }),
    sourceSite({ sourceRef, path: queuePath, role: "definition", siteKey: "callback-queue.drain", range: drain, text: queueText, bytes: queueBytes }),
    sourceSite({ sourceRef, path: queuePath, role: "dispatch", siteKey: "callback-queue.dispatch", range: dispatch[0], text: queueText, bytes: queueBytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "callback-delivery-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0callback-delivery`),
      conditionId: callbackDeliveryCondition(sourcePath, branch.targetVariant),
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function callbackSetterBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    !branch?.observedKey?.startsWith("callback:")
    || branch.observedKey.startsWith("callback:producer:")
    || !/\.(?:cc|mm)$/u.test(sourcePath)
    || !/(?:set|register).*(?:callback|handler)/iu.test(locator)
  ) return null;
  const setter = qualifiedDeclarationRange(text, locator);
  if (!setter) return null;
  const callbackAssignments = tokenRangesWithin(text, "= callback;", setter);
  const contextAssignments = tokenRangesWithin(text, "= context;", setter);
  if (callbackAssignments.length !== 1) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${locator}.setter`, range: setter, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${locator}.callback-retention`, range: callbackAssignments[0], text, bytes }),
    ...contextAssignments.map((range, index) => sourceSite({
      sourceRef,
      path: sourcePath,
      role: "retention",
      siteKey: `${locator}.context-retention.${index + 1}`,
      range,
      text,
      bytes,
    })),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "callback-setter-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0callback-setter`),
      conditionId: callbackDeliveryCondition(sourcePath, branch.targetVariant),
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function callbackDirectDispatchBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("callback:") || branch.observedKey.startsWith("callback:producer:")) {
    return null;
  }
  const specifications = {
    "callback:microtask-drain": {
      locator: "drainMicrotasks",
      callee: "rt.drainMicrotasks",
      conditions: ["target-platform:windows", "target-platform:not-windows"],
    },
    "callback:next-tick-drain": {
      locator: "runNextTickQueue",
      callee: "entry.callback.call",
      conditions: ["next-tick:without-arguments", "next-tick:with-arguments"],
    },
    "callback:queue-drain": {
      locator: "drainCallbackQueue",
      callee: "entry.callback",
      conditions: ["callback-queue:entry"],
      retentionCallee: "queue.swap",
    },
    "callback:queue-enqueue": {
      locator: "pushRuntimeCallback",
      callee: "runtime->callbackQueue.push_back",
      conditions: ["callback-queue:accepted-generation"],
    },
    "callback:worklet-scheduled-drain": {
      locator: "ex_worklet_drain_scheduled",
      callee: "drainJsonArray",
      conditions: ["worklet-queue:scheduled"],
    },
  };
  const specification = specifications[branch.observedKey];
  if (!specification || locator !== specification.locator) return null;
  const dispatcher = qualifiedDeclarationRange(text, locator);
  if (!dispatcher) return null;
  const dispatches = callExpressionRangesWithin(text, specification.callee, dispatcher);
  if (dispatches.length !== specification.conditions.length) return null;
  const retention = specification.retentionCallee
    ? callExpressionRangesWithin(text, specification.retentionCallee, dispatcher)
    : [];
  if (specification.retentionCallee && retention.length !== 1) return null;
  const definitionSite = sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${locator}.dispatcher`, range: dispatcher, text, bytes });
  const retentionSites = retention.map((range, index) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "retention",
    siteKey: `${locator}.retention.${index + 1}`,
    range,
    text,
    bytes,
  }));
  const dispatchSites = dispatches.map((range, index) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "dispatch",
    siteKey: `${locator}.dispatch.${index + 1}`,
    range,
    text,
    bytes,
  }));
  const sites = [definitionSite, ...retentionSites, ...dispatchSites];
  const commonSiteIds = [definitionSite, ...retentionSites].map((site) => site.siteId);
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "callback-direct-dispatch-route",
    resolutionPolicy: dispatches.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths: dispatchSites.map((site, index) => ({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${specification.conditions[index]}`),
      conditionId: specification.conditions[index],
      requiredSiteIds: [...commonSiteIds, site.siteId],
    })),
  });
}

function nativePrincipalRestoreBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    branch?.observedKey !== "callback:native-principal-restore"
    || sourcePath !== "src/engine/hermes_runtime_internal.h"
    || locator !== "ScopedNativePrincipal"
  ) return null;
  const declaration = typeDeclarationRange(text, locator);
  if (!declaration) return null;
  const install = tokenRangesWithin(
    text,
    "g_native_callback_principal_id = principal;",
    declaration,
  );
  const restore = tokenRangesWithin(
    text,
    "g_native_callback_principal_id = previous_;",
    declaration,
  );
  if (install.length !== 1 || restore.length !== 1) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: "ScopedNativePrincipal.scope", range: declaration, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "ScopedNativePrincipal.install", range: install[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "ScopedNativePrincipal.restore", range: restore[0], text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "callback-native-principal-restore-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0native-principal-restore`),
      conditionId: "native-principal-scope:destruction",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function timerCallbackBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    branch?.observedKey !== "callback:timer-invoke"
    || sourcePath !== "src/engine/hermes_runtime.cc"
    || locator !== "ex_hermes_poll"
  ) return null;
  const entry = robustFunctionDeclarationRange(text, locator);
  const dispatcher = robustFunctionDeclarationRange(text, "pollRuntime");
  if (!entry || !dispatcher) return null;
  const enterDispatch = callExpressionRangesWithin(text, "pollRuntime", entry);
  const invocations = callExpressionRangesWithin(text, "it->second.callback.call", dispatcher);
  if (enterDispatch.length !== 1 || invocations.length !== 2) return null;
  const commonSites = [
    sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: "timer.poll-entry", range: entry, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "timer.poll-dispatch", range: enterDispatch[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: "timer.poll-runtime", range: dispatcher, text, bytes }),
  ];
  const invocationSites = invocations.map((range, index) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "dispatch",
    siteKey: `timer.invoke.${index + 1}`,
    range,
    text,
    bytes,
  }));
  const sites = [...commonSites, ...invocationSites];
  const commonSiteIds = commonSites.map((site) => site.siteId);
  const conditions = ["timer-callback:without-arguments", "timer-callback:with-arguments"];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "callback-timer-dispatch-route",
    resolutionPolicy: "conditioned-alternatives",
    sites,
    producerPaths: invocationSites.map((site, index) => ({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${conditions[index]}`),
      conditionId: conditions[index],
      requiredSiteIds: [...commonSiteIds, site.siteId],
    })),
  });
}

function websocketContextReleaseBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    branch?.observedKey !== "callback:websocket-context-release"
    || sourcePath !== "src/engine/hermes_runtime.cc"
    || locator !== "native_ws_release_context"
  ) return null;
  const release = robustFunctionDeclarationRange(text, locator);
  if (!release) return null;
  const deletes = tokenRangesWithin(text, "delete ctx;", release);
  const finalizer = callExpressionRangesWithin(text, "pushRuntimeFinalizer", release);
  if (deletes.length !== 2 || finalizer.length !== 1) return null;
  const definitionSite = sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: "websocket-context.release", range: release, text, bytes });
  const directSite = sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "websocket-context.direct-delete", range: deletes[0], text, bytes });
  const finalizerSite = sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "websocket-context.finalizer-publication", range: finalizer[0], text, bytes });
  const deferredSite = sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "websocket-context.deferred-delete", range: deletes[1], text, bytes });
  const sites = [definitionSite, directSite, finalizerSite, deferredSite];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "callback-context-release-route",
    resolutionPolicy: "conditioned-alternatives",
    sites,
    producerPaths: [
      {
        pathId: stableId("producer", `${branch.branchId}\0direct-release`),
        conditionId: "callback-release:on-runtime-thread",
        requiredSiteIds: [definitionSite.siteId, directSite.siteId],
      },
      {
        pathId: stableId("producer", `${branch.branchId}\0deferred-release`),
        conditionId: "callback-release:off-runtime-thread",
        requiredSiteIds: [definitionSite.siteId, finalizerSite.siteId, deferredSite.siteId],
      },
    ],
  });
}

function signalDispatchBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    branch?.observedKey !== "callback:signal-delivery"
    || sourcePath !== "src/engine/bootstrap/stream-enhance.js"
    || locator !== "__exactDispatchPendingSignals"
  ) return null;
  const assignmentToken = "globalThis.__exactDispatchPendingSignals = function()";
  const assignment = text.indexOf(assignmentToken);
  const opening = assignment < 0 ? -1 : text.indexOf("{", assignment + assignmentToken.length);
  const endByte = opening < 0 ? -1 : matchingBraceEnd(text, opening);
  if (endByte < 0) return null;
  const dispatcher = { startByte: assignment, endByte };
  const publication = lineRange(text, assignment);
  const poll = callExpressionRangesWithin(text, "__exactPollSignal", dispatcher);
  const emit = callExpressionRangesWithin(text, "proc.emit", dispatcher);
  const reset = callExpressionRangesWithin(text, "__exactResetSignal", dispatcher);
  const redeliver = callExpressionRangesWithin(text, "proc.kill", dispatcher);
  if (poll.length !== 1 || emit.length !== 1 || reset.length !== 1 || redeliver.length !== 1) {
    return null;
  }
  const definitionSite = sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: "signal.dispatcher", range: dispatcher, text, bytes });
  const publicationSite = sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "signal.dispatcher-global", range: publication, text, bytes });
  const pollSite = sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "signal.poll", range: poll[0], text, bytes });
  const emitSite = sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "signal.emit", range: emit[0], text, bytes });
  const resetSite = sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "signal.reset", range: reset[0], text, bytes });
  const redeliverSite = sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "signal.redeliver", range: redeliver[0], text, bytes });
  const sites = [definitionSite, publicationSite, pollSite, emitSite, resetSite, redeliverSite];
  const common = [definitionSite.siteId, publicationSite.siteId, pollSite.siteId];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "callback-signal-dispatch-route",
    resolutionPolicy: "conditioned-alternatives",
    sites,
    producerPaths: [
      {
        pathId: stableId("producer", `${branch.branchId}\0signal-listener`),
        conditionId: "signal-listener:present",
        requiredSiteIds: [...common, emitSite.siteId],
      },
      {
        pathId: stableId("producer", `${branch.branchId}\0signal-default`),
        conditionId: "signal-listener:absent",
        requiredSiteIds: [...common, resetSite.siteId, redeliverSite.siteId],
      },
    ],
  });
}

function cliNamespaceRefusalBinding({ branch, sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (!branch?.observedKey?.startsWith("cli:") || sourcePath !== "runtime-surface.json") return null;
  if (!["legacyProjectCommands", "reservedCommands"].includes(locator)) return null;
  const command = branch.observedKey.slice("cli:".length).split(":")[0];
  const propertyToken = `"${locator}"`;
  const propertyOffset = text.indexOf(propertyToken);
  if (propertyOffset < 0 || text.indexOf(propertyToken, propertyOffset + 1) >= 0) return null;
  const opening = text.indexOf("[", propertyOffset + propertyToken.length);
  const end = opening < 0 ? -1 : matchingDelimiterEnd(text, opening, "[", "]");
  if (end < 0) return null;
  const manifestEntries = tokenRangesWithin(text, `"${command}"`, { startByte: opening, endByte: end });
  if (manifestEntries.length !== 1) return null;
  const root = path.dirname(absolute);
  const mainPath = "src/bin/ibex/main.rs";
  const mainBytes = fs.readFileSync(path.join(root, mainPath));
  const mainText = mainBytes.toString("utf8");
  const tableName = locator === "legacyProjectCommands"
    ? "EXACT_PROJECT_COMMANDS"
    : "RESERVED_RUNTIME_COMMANDS";
  const table = arrayDeclarationRange(mainText, tableName);
  const dispatcher = declarationRange(mainText, "pre_clap_namespace_dispatch");
  if (!table || !dispatcher) return null;
  const compiledEntries = tokenRangesWithin(mainText, `"${command}"`, table);
  if (compiledEntries.length !== 1) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${locator}.${command}.manifest`, range: manifestEntries[0], text, bytes }),
    sourceSite({ sourceRef, path: mainPath, role: "guard", siteKey: `${tableName}.${command}.compiled`, range: compiledEntries[0], text: mainText, bytes: mainBytes }),
    sourceSite({ sourceRef, path: mainPath, role: "guard", siteKey: "pre-clap-namespace-dispatch", range: dispatcher, text: mainText, bytes: mainBytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "cli-namespace-refusal",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [],
    refusalPaths: [{
      pathId: stableId("refusal", `${branch.branchId}\0${sourceRef}\0namespace`),
      conditionId: "cli-namespace:non-path-token",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function rustEnumVariantRange(text, enumRange, variant) {
  const escaped = escapeRegExp(variant);
  const slice = text.slice(enumRange.startByte, enumRange.endByte);
  const pattern = new RegExp(`^    ${escaped}(?:\\s*[({,]|$)`, "mu");
  const match = pattern.exec(slice);
  if (!match) return null;
  const startByte = enumRange.startByte + match.index;
  const nextPattern = /^    [A-Z][A-Za-z0-9_]*(?:\s*[({,]|$)/gmu;
  nextPattern.lastIndex = match.index + match[0].length;
  const next = nextPattern.exec(slice);
  return { startByte, endByte: next ? enumRange.startByte + next.index : enumRange.endByte };
}

function cliVisibleCommandBinding({ branch, sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (!branch?.observedKey?.startsWith("cli:") || sourcePath !== "runtime-surface.json") return null;
  if (!["visibleCommands", "hiddenHarnessCommands"].includes(locator)) return null;
  const command = branch.observedKey.slice("cli:".length).split(":")[0];
  const propertyOffset = text.indexOf(`"${locator}"`);
  const opening = propertyOffset < 0 ? -1 : text.indexOf("[", propertyOffset);
  const end = opening < 0 ? -1 : matchingDelimiterEnd(text, opening, "[", "]");
  if (end < 0) return null;
  const manifestEntries = tokenRangesWithin(text, `"${command}"`, { startByte: opening, endByte: end });
  if (manifestEntries.length !== 1) return null;
  const root = path.dirname(absolute);
  const cliPath = "src/bin/ibex/cli.rs";
  const mainPath = "src/bin/ibex/main.rs";
  const cliBytes = fs.readFileSync(path.join(root, cliPath));
  const mainBytes = fs.readFileSync(path.join(root, mainPath));
  const cliText = cliBytes.toString("utf8");
  const mainText = mainBytes.toString("utf8");
  const variant = command.split(/[-_]/u).map((part) =>
    `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`).join("");
  const commands = declarationRange(cliText, "Commands");
  const enumVariant = commands && rustEnumVariantRange(cliText, commands, variant);
  const dispatchMarker = "match &cli.command {";
  const dispatchStart = mainText.indexOf(dispatchMarker);
  const dispatchOpening = dispatchStart < 0 ? -1 : mainText.indexOf("{", dispatchStart);
  const dispatchEnd = dispatchOpening < 0 ? -1 : matchingBraceEnd(mainText, dispatchOpening);
  if (!enumVariant || dispatchEnd < 0) return null;
  const dispatchMatches = tokenRangesWithin(
    mainText,
    `Some(Commands::${variant}`,
    { startByte: dispatchStart, endByte: dispatchEnd },
  );
  if (dispatchMatches.length !== 1) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${locator}.${command}.manifest`, range: manifestEntries[0], text, bytes }),
    sourceSite({ sourceRef, path: cliPath, role: "publication", siteKey: `Commands.${variant}`, range: enumVariant, text: cliText, bytes: cliBytes }),
    sourceSite({ sourceRef, path: mainPath, role: "dispatch", siteKey: `dispatch.${variant}`, range: dispatchMatches[0], text: mainText, bytes: mainBytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "cli-command-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0cli-command`),
      conditionId: locator === "visibleCommands" ? "cli-command:visible" : "cli-command:hidden-harness",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

export function validateRestrictedExactSourceBinding(binding) {
  binding.refusalPaths ??= [];
  const siteIds = binding.sites.map((site) => site.siteId);
  if (new Set(siteIds).size !== siteIds.length) {
    throw new Error(`${binding.sourceRef}: duplicate source site ID`);
  }
  for (const site of binding.sites) {
    if (site.startByte >= site.endByte || site.startLine > site.endLine) {
      throw new Error(`${binding.sourceRef}: invalid source site range ${site.siteId}`);
    }
  }
  if (binding.resolutionPolicy === "provenance-only") {
    if (binding.producerPaths.length !== 0 || binding.refusalPaths.length !== 0) {
      throw new Error(`${binding.sourceRef}: provenance-only binding has executable paths`);
    }
    return binding;
  }
  if (binding.producerPaths.length === 0 && binding.refusalPaths.length === 0) {
    throw new Error(`${binding.sourceRef}: executable binding lacks producer or refusal paths`);
  }
  if (
    binding.resolutionPolicy === "conditioned-alternatives"
    && binding.producerPaths.length < 2
  ) {
    throw new Error(`${binding.sourceRef}: conditioned alternatives require multiple paths`);
  }
  const allPaths = [...binding.producerPaths, ...binding.refusalPaths];
  const pathIds = allPaths.map((producerPath) => producerPath.pathId);
  const conditions = allPaths.map((producerPath) => producerPath.conditionId);
  if (new Set(pathIds).size !== pathIds.length) {
    throw new Error(`${binding.sourceRef}: duplicate producer path ID`);
  }
  if (
    binding.resolutionPolicy === "conditioned-alternatives"
    && new Set(conditions).size !== conditions.length
  ) {
    throw new Error(`${binding.sourceRef}: alternative paths require distinct conditions`);
  }
  const referenced = new Set();
  for (const producerPath of allPaths) {
    if (
      producerPath.requiredSiteIds.length === 0
      || new Set(producerPath.requiredSiteIds).size !== producerPath.requiredSiteIds.length
    ) {
      throw new Error(`${binding.sourceRef}: invalid required source sites in ${producerPath.pathId}`);
    }
    for (const siteId of producerPath.requiredSiteIds) {
      if (!siteIds.includes(siteId)) {
        throw new Error(`${binding.sourceRef}: producer path references unknown site ${siteId}`);
      }
      referenced.add(siteId);
    }
    const roles = producerPath.requiredSiteIds.map(
      (siteId) => binding.sites.find((site) => site.siteId === siteId).role,
    );
    if (binding.producerPaths.includes(producerPath)) {
      if (!roles.some((role) => ["publication", "dispatch"].includes(role))) {
        throw new Error(`${binding.sourceRef}: producer path lacks publication or dispatch site`);
      }
      if (!roles.some((role) => ["definition", "value-producer", "registration"].includes(role))) {
        throw new Error(`${binding.sourceRef}: producer path lacks definition or value producer`);
      }
    } else if (!roles.includes("guard")) {
      throw new Error(`${binding.sourceRef}: refusal path lacks guard site`);
    }
  }
  if (referenced.size !== siteIds.length) {
    throw new Error(`${binding.sourceRef}: executable binding has unreferenced semantic sites`);
  }
  return binding;
}

function loadSourceRef(sourceRef, root) {
  const separator = sourceRef.indexOf("#");
  if (separator < 1 || separator === sourceRef.length - 1) {
    throw new Error(`source ref lacks path#locator: ${sourceRef}`);
  }
  const sourcePath = sourceRef.slice(0, separator);
  const locator = sourceRef.slice(separator + 1);
  const absolute = path.resolve(root, sourcePath);
  const relative = path.relative(root, absolute);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`source ref escapes repository: ${sourceRef}`);
  }
  let source = sourceCache.get(absolute);
  if (!source) {
    const stat = fs.lstatSync(absolute);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`source ref is not a regular non-symlink file: ${sourceRef}`);
    }
    const bytes = fs.readFileSync(absolute);
    source = { bytes, text: bytes.toString("utf8") };
    sourceCache.set(absolute, source);
  }
  return { sourcePath, locator, absolute, ...source };
}

export function resolveRestrictedExactSourceBinding(sourceRef, root = repoRoot) {
  const { sourcePath, locator, absolute, bytes, text } = loadSourceRef(sourceRef, root);
  const specialized = errnoExportBinding({ sourceRef, sourcePath, locator, text, bytes })
    ?? processCwdBinding({ sourceRef, sourcePath, locator, text, bytes });
  if (specialized) return validateRestrictedExactSourceBinding(specialized);
  const range = resolveRange(sourcePath, locator, text, absolute);
  if (!range || range.endByte <= range.startByte) {
    throw new Error(`source locator is missing, ambiguous, or unsupported: ${sourceRef}`);
  }
  const site = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "definition",
    siteKey: "provenance",
    range,
    text,
    bytes,
  });
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: sourcePath.endsWith(".json") ? "generated-table-entry" : "source-range",
    resolutionPolicy: "provenance-only",
    sites: [site],
    producerPaths: [],
  });
}

export function resolveRestrictedExactBranchSourceBinding(
  branch,
  sourceRef,
  root = repoRoot,
) {
  const loaded = loadSourceRef(sourceRef, root);
  const contextual = moduleSpecifierBranchBinding({ branch, sourceRef, ...loaded })
    ?? builtinExportBranchBinding({ branch, sourceRef, ...loaded })
    ?? jsiGlobalBranchBinding({ branch, sourceRef, ...loaded })
    ?? exportedHostAbiBinding({ branch, sourceRef, ...loaded })
    ?? callbackProducerBinding({ branch, sourceRef, ...loaded })
    ?? callbackDeliveryBinding({ branch, sourceRef, ...loaded })
    ?? callbackSetterBinding({ branch, sourceRef, ...loaded })
    ?? callbackDirectDispatchBinding({ branch, sourceRef, ...loaded })
    ?? nativePrincipalRestoreBinding({ branch, sourceRef, ...loaded })
    ?? timerCallbackBinding({ branch, sourceRef, ...loaded })
    ?? websocketContextReleaseBinding({ branch, sourceRef, ...loaded })
    ?? signalDispatchBinding({ branch, sourceRef, ...loaded })
    ?? cliVisibleCommandBinding({ branch, sourceRef, ...loaded })
    ?? cliNamespaceRefusalBinding({ branch, sourceRef, ...loaded })
    ?? bootstrapGlobalBinding({ branch, sourceRef, ...loaded })
    ?? legacyBootstrapGlobalBinding({ branch, sourceRef, ...loaded })
    ?? typescriptClassMemberBinding({ branch, sourceRef, ...loaded });
  return contextual ?? resolveRestrictedExactSourceBinding(sourceRef, root);
}

function locatorOf(sourceRef) {
  return sourceRef.slice(sourceRef.indexOf("#") + 1);
}

function selectGlobalProducerEntry(observedPath, entries) {
  const [root, ...memberParts] = observedPath.split(".");
  const member = memberParts.join(".");
  const exactLocator = member ? `${root}.${member}` : root;
  const prototypeLocator = member ? `${root}.prototype.${member}` : null;
  const producers = entries.filter(({ binding }) =>
    ["typescript-class-member", "typescript-class-inheritance"].includes(binding.locatorKind),
  );
  const exact = producers.filter(({ sourceRef }) => locatorOf(sourceRef) === exactLocator);
  if (exact.length === 1) return exact[0];
  const prototype = producers.filter(({ sourceRef }) => locatorOf(sourceRef) === prototypeLocator);
  return prototype.length === 1 ? prototype[0] : null;
}

export function buildRestrictedExactBranchSourceRoute(branch, sourceRefs, root = repoRoot) {
  const entries = [];
  const unresolved = [];
  for (const sourceRef of [...new Set(sourceRefs)].sort()) {
    try {
      entries.push({
        sourceRef,
        binding: resolveRestrictedExactBranchSourceBinding(branch, sourceRef, root),
      });
    } catch (error) {
      unresolved.push({ sourceRef, error: error.message });
    }
  }
  if (unresolved.length > 0) {
    return { branchId: branch.branchId, status: "incomplete", unresolved };
  }
  const selectedEntries = new Set();
  const producerPaths = [];
  const refusalPaths = [];
  if (branch.observedKey === "callback:signal-delivery") {
    const producer = entries.find(({ binding }) => binding.locatorKind === "callback-delivery-route");
    const dispatcher = entries.find(({ binding }) => binding.locatorKind === "callback-signal-dispatch-route");
    if (producer?.binding.producerPaths.length === 1 && dispatcher) {
      selectedEntries.add(producer);
      selectedEntries.add(dispatcher);
      const producerSiteIds = producer.binding.producerPaths[0].requiredSiteIds;
      for (const pathEntry of dispatcher.binding.producerPaths) {
        producerPaths.push({
          pathId: stableId("producer", `${branch.branchId}\0${pathEntry.conditionId}`),
          conditionId: pathEntry.conditionId,
          requiredSiteIds: [...producerSiteIds, ...pathEntry.requiredSiteIds],
        });
      }
    }
  } else if (branch.observedKey.startsWith("native-op:global:")) {
    const observedPath = branch.observedKey.slice("native-op:global:".length);
    const producer = selectGlobalProducerEntry(observedPath, entries);
    const publications = entries.filter(({ binding }) =>
      ["typescript-global-publication", "typescript-lazy-global-publication"].includes(binding.locatorKind),
    );
    if (producer && publications.length === 1) {
      selectedEntries.add(producer);
      selectedEntries.add(publications[0]);
      const requiredSiteIds = [
        ...producer.binding.sites,
        ...publications[0].binding.sites,
      ].map((site) => site.siteId);
      producerPaths.push({
        pathId: stableId("producer", `${branch.branchId}\0runtime-bundle`),
        conditionId: publications[0].binding.locatorKind === "typescript-lazy-global-publication"
          ? "runtime-bundle:global-missing"
          : `target-branch:${branch.targetVariant}`,
        requiredSiteIds,
      });
    }
    for (const entry of entries.filter(({ binding }) => binding.locatorKind === "legacy-bootstrap-global-route")) {
      selectedEntries.add(entry);
      producerPaths.push(...entry.binding.producerPaths);
    }
  } else {
    for (const entry of entries.filter(({ binding }) =>
      binding.producerPaths.length > 0 || binding.refusalPaths.length > 0)) {
      selectedEntries.add(entry);
      producerPaths.push(...entry.binding.producerPaths);
      refusalPaths.push(...entry.binding.refusalPaths);
    }
  }
  if (producerPaths.length === 0 && refusalPaths.length === 0) {
    return {
      branchId: branch.branchId,
      status: "incomplete",
      unresolved: [{ sourceRef: "<branch-route>", error: "no executable producer path" }],
    };
  }
  const sites = [...new Map(
    [...selectedEntries].flatMap((entry) => entry.binding.sites)
      .map((site) => [site.siteId, site]),
  ).values()];
  const siteIds = new Set(sites.map((site) => site.siteId));
  const allPaths = [...producerPaths, ...refusalPaths];
  if (allPaths.some((producerPath) =>
    producerPath.requiredSiteIds.some((siteId) => !siteIds.has(siteId)))) {
    throw new Error(`${branch.branchId}: executable path references an unselected site`);
  }
  const conditions = allPaths.map((producerPath) => producerPath.conditionId);
  if (allPaths.length > 1 && new Set(conditions).size !== conditions.length) {
    throw new Error(`${branch.branchId}: alternative producer paths lack distinct conditions`);
  }
  const bindingDispositions = entries.map((entry) => ({
    sourceRef: entry.sourceRef,
    disposition: selectedEntries.has(entry)
      ? "selected-route"
      : entry.binding.resolutionPolicy === "provenance-only"
        ? "supporting-provenance"
        : "excluded-nonterminal-route",
    locatorKind: entry.binding.locatorKind,
  }));
  return {
    branchId: branch.branchId,
    edgeId: branch.edgeId,
    observedKey: branch.observedKey,
    targetVariant: branch.targetVariant,
    status: "executable",
    resolutionPolicy: allPaths.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths,
    refusalPaths,
    bindingDispositions,
  };
}

export function resolveRestrictedExactSourceAnchor(sourceRef, root = repoRoot) {
  const binding = resolveRestrictedExactSourceBinding(sourceRef, root);
  if (binding.sites.length !== 1) {
    throw new Error(`source binding requires an anchor set: ${sourceRef}`);
  }
  return { sourceRef, ...binding.sites[0] };
}

export function auditRestrictedExactSourceAnchors() {
  const implementation = readJsonStrict(
    path.join(capsecRoot, "generated/implementation-manifest.json"),
  );
  const refs = [...new Set(
    implementation.surfaces.flatMap((surface) => surface.sourceRefs),
  )].sort();
  const anchors = [];
  const unresolved = [];
  for (const sourceRef of refs) {
    try {
      anchors.push(resolveRestrictedExactSourceBinding(sourceRef));
    } catch (error) {
      unresolved.push({ sourceRef, error: error.message });
    }
  }
  return { anchors, unresolved, total: refs.length };
}

export function auditRestrictedExactBranchSourceBindings() {
  const implementation = readJsonStrict(
    path.join(capsecRoot, "generated/implementation-manifest.json"),
  );
  const bindings = [];
  const unresolved = [];
  for (const branch of implementation.surfaces) {
    const refs = [...new Set([
      ...branch.sourceRefs,
      ...branch.enforcementRoute.sourceRefs,
      ...branch.enforcementRoute.proofSourceRefs,
    ])].sort();
    for (const sourceRef of refs) {
      try {
        bindings.push({
          branchId: branch.branchId,
          edgeId: branch.edgeId,
          observedKey: branch.observedKey,
          targetVariant: branch.targetVariant,
          binding: resolveRestrictedExactBranchSourceBinding(branch, sourceRef),
        });
      } catch (error) {
        unresolved.push({
          branchId: branch.branchId,
          observedKey: branch.observedKey,
          sourceRef,
          error: error.message,
        });
      }
    }
  }
  return { bindings, unresolved, total: bindings.length + unresolved.length };
}

export function auditRestrictedExactBranchSourceRoutes() {
  const implementation = readJsonStrict(
    path.join(capsecRoot, "generated/implementation-manifest.json"),
  );
  const routes = [];
  const incomplete = [];
  for (const branch of implementation.surfaces) {
    const refs = [...new Set([
      ...branch.sourceRefs,
      ...branch.enforcementRoute.sourceRefs,
      ...branch.enforcementRoute.proofSourceRefs,
    ])].sort();
    const route = buildRestrictedExactBranchSourceRoute(branch, refs);
    if (route.status === "executable") routes.push(route);
    else incomplete.push({
      branchId: branch.branchId,
      edgeId: branch.edgeId,
      observedKey: branch.observedKey,
      targetVariant: branch.targetVariant,
      ...route,
    });
  }
  return { routes, incomplete, total: implementation.surfaces.length };
}

function main() {
  const audit = auditRestrictedExactSourceAnchors();
  console.log(JSON.stringify({
    total: audit.total,
    resolved: audit.anchors.length,
    executable: audit.anchors.filter((anchor) => anchor.producerPaths.length > 0).length,
    provenanceOnly: audit.anchors.filter((anchor) => anchor.resolutionPolicy === "provenance-only").length,
    unresolved: audit.unresolved.length,
    unresolvedSample: audit.unresolved.slice(0, 100),
  }, null, 2));
  if (audit.unresolved.length > 0) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
