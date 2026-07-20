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

import { capsecRoot, readJsonStrict } from "./capsec-contract.mjs";

const repoRoot = path.dirname(capsecRoot);
const sourceCache = new Map();
const rangeCache = new Map();
const containerRangeCache = new Map();

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

function matchingBraceEnd(text, opening) {
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
    else if (current === "{") depth += 1;
    else if (current === "}") {
      depth -= 1;
      if (depth === 0) return index + 1;
    }
  }
  return -1;
}

function declarationCandidateGroups(text, name) {
  const escaped = escapeRegExp(name);
  const patterns = [
    new RegExp(`(?:^|\\n)[^\\n;{}]*\\b(?:function|class|struct|enum|trait|fn)\\s+${escaped}\\b`, "gu"),
    new RegExp(`(?:^|\\n)[^\\n;{}]*\\b(?:const|let|var|static)\\s+${escaped}\\s*(?::[^=;]+)?=`, "gu"),
    new RegExp(`(?:^|\\n)[^\\n;{}]*\\b${escaped}\\s*\\([^;{}]*\\)[^;{]*\\{`, "gu"),
  ];
  return patterns.map((pattern) => [...new Set(
    [...text.matchAll(pattern)].map(
      (match) => match.index + (match[0][0] === "\n" ? 1 : 0),
    ),
  )].sort((left, right) => left - right));
}

function declarationRange(text, name) {
  const candidates = declarationCandidateGroups(text, name)
    .find((group) => group.length === 1);
  if (!candidates) return null;
  const startByte = candidates[0];
  const opening = text.indexOf("{", startByte);
  if (opening < 0) return lineRange(text, startByte);
  const endByte = matchingBraceEnd(text, opening);
  return endByte < 0 ? null : { startByte, endByte };
}

function uniqueTokenRange(text, tokens) {
  for (const token of tokens) {
    if (!token) continue;
    const offsets = [];
    let offset = text.indexOf(token);
    while (offset >= 0) {
      offsets.push(offset);
      offset = text.indexOf(token, offset + token.length);
    }
    if (offsets.length === 1) return lineRange(text, offsets[0]);
  }
  return null;
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

function resolveRange(sourcePath, locator, text) {
  const cacheKey = `${sourcePath}\0${locator}`;
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
    range = { startByte: 0, endByte: text.length };
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
    const containerKey = `${sourcePath}\0${container}`;
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

export function resolveRestrictedExactSourceAnchor(sourceRef, root = repoRoot) {
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
  const { bytes, text } = source;
  const range = resolveRange(sourcePath, locator, text);
  if (!range || range.endByte <= range.startByte) {
    throw new Error(`source locator is missing, ambiguous, or unsupported: ${sourceRef}`);
  }
  const slice = bytes.subarray(range.startByte, range.endByte);
  return {
    sourceRef,
    path: sourcePath,
    locator,
    locatorKind: sourcePath.endsWith(".json") ? "generated-table-entry" : "source-range",
    startByte: range.startByte,
    endByte: range.endByte,
    startLine: text.slice(0, range.startByte).split("\n").length,
    endLine: text.slice(0, range.endByte).split("\n").length,
    rawContentDigest: digest(slice),
  };
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
      anchors.push(resolveRestrictedExactSourceAnchor(sourceRef));
    } catch (error) {
      unresolved.push({ sourceRef, error: error.message });
    }
  }
  return { anchors, unresolved, total: refs.length };
}

function main() {
  const audit = auditRestrictedExactSourceAnchors();
  console.log(JSON.stringify({
    total: audit.total,
    resolved: audit.anchors.length,
    unresolved: audit.unresolved.length,
    unresolvedSample: audit.unresolved.slice(0, 100),
  }, null, 2));
  if (audit.unresolved.length > 0) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
