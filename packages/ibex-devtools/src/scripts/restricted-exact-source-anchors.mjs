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
import {
  discoverHermesEvaluatorIdentityProfiles,
  scanLegacyEvaluatorBootstrapInstallations,
} from "./capsec-surface-inventory.mjs";

const repoRoot = path.dirname(capsecRoot);
const sourceCache = new Map();
const rangeCache = new Map();
const containerRangeCache = new Map();
const javascriptIndexCache = new Map();
const rustTestModuleRangeCache = new Map();
const lineStartCache = new Map();
const declarationRangeCache = new Map();
const robustFunctionRangeCache = new Map();
const javaTypeRangeCache = new Map();
const prototypeLinkCache = new Map();
const hermesEvaluatorProfileCache = new Map();

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
  let byName = declarationRangeCache.get(text);
  if (!byName) {
    byName = new Map();
    declarationRangeCache.set(text, byName);
  }
  if (byName.has(name)) return byName.get(name);
  const candidates = [...new Set(declarationCandidateGroups(text, name).flat())]
    .sort((left, right) => left - right);
  if (candidates.length !== 1) {
    byName.set(name, null);
    return null;
  }
  const startByte = candidates[0];
  const opening = text.indexOf("{", startByte);
  if (opening < 0) {
    const range = lineRange(text, startByte);
    byName.set(name, range);
    return range;
  }
  const endByte = matchingBraceEnd(text, opening);
  const range = endByte < 0 ? null : { startByte, endByte };
  byName.set(name, range);
  return range;
}

function robustFunctionDeclarationRange(text, name) {
  let byName = robustFunctionRangeCache.get(text);
  if (!byName) {
    byName = new Map();
    robustFunctionRangeCache.set(text, byName);
  }
  if (byName.has(name)) return byName.get(name);
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
  const range = unique.length === 1 ? unique[0] : null;
  byName.set(name, range);
  return range;
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

function javascriptNamedFunctionRange(text, name) {
  const escaped = escapeRegExp(name);
  const patterns = [
    new RegExp(`(?:^|\\n)\\s*(?:const|let|var)\\s+${escaped}\\s*=\\s*(?:async\\s+)?function\\b`, "gu"),
    new RegExp(`(?:^|\\n)\\s*(?:async\\s+)?function\\s+${escaped}\\b`, "gu"),
  ];
  const matches = patterns.flatMap((pattern) => [...text.matchAll(pattern)]);
  if (matches.length !== 1) return null;
  const startByte = matches[0].index + matches[0][0].search(/\S/u);
  const opening = text.indexOf("{", startByte);
  const endByte = opening < 0 ? -1 : matchingBraceEnd(text, opening);
  return endByte > opening ? { startByte, endByte } : null;
}

function rustFunctionRanges(text, name) {
  const escaped = escapeRegExp(name);
  const pattern = new RegExp(
    `(?:^|\\n)\\s*(?:pub(?:\\([^)]*\\))?\\s+)?(?:unsafe\\s+)?(?:async\\s+)?fn\\s+${escaped}\\b`,
    "gu",
  );
  const matches = [...text.matchAll(pattern)];
  return matches.map((match) => {
    const startByte = match.index + match[0].search(/\S/u);
    const opening = text.indexOf("{", startByte);
    const endByte = opening < 0 ? -1 : matchingBraceEnd(text, opening);
    return endByte > opening ? { startByte, endByte } : null;
  }).filter(Boolean);
}

function rustFunctionRange(text, name) {
  const ranges = rustFunctionRanges(text, name);
  return ranges.length === 1 ? ranges[0] : null;
}

function declarationRanges(text, name) {
  const ranges = [];
  for (const startByte of [...new Set(declarationCandidateGroups(text, name).flat())]) {
    const opening = text.indexOf("{", startByte);
    const semicolon = text.indexOf(";", startByte);
    if (opening < 0 || (semicolon >= 0 && semicolon < opening)) continue;
    const endByte = matchingBraceEnd(text, opening);
    if (endByte > opening) ranges.push({ startByte, endByte });
  }
  return [...new Map(ranges.map((range) => [
    `${range.startByte}:${range.endByte}`,
    range,
  ])).values()];
}

function javaTypeRanges(text) {
  const cached = javaTypeRangeCache.get(text);
  if (cached) return cached;
  const ranges = [];
  const pattern = /\b(?:class|interface|enum)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/gu;
  for (const match of text.matchAll(pattern)) {
    const opening = text.indexOf("{", match.index + match[0].length);
    const endByte = opening < 0 ? -1 : matchingBraceEnd(text, opening);
    if (endByte > opening) ranges.push({ name: match[1], startByte: match.index, endByte });
  }
  javaTypeRangeCache.set(text, ranges);
  return ranges;
}

function javaMethodDeclarationRange(text, ownerName, methodName) {
  const candidates = [];
  for (const call of callExpressionRangesWithin(
    text,
    methodName,
    { startByte: 0, endByte: text.length },
  )) {
    const lineStart = text.lastIndexOf("\n", call.startByte - 1) + 1;
    const prefix = text.slice(lineStart, call.startByte);
    if (
      prefix.trim().length === 0
      || /[.=]/u.test(prefix)
      || /^\s*(?:if|while|for|switch|return|throw|new)\b/u.test(prefix)
    ) continue;
    let cursor = call.endByte;
    while (cursor < text.length && /\s/u.test(text[cursor])) cursor += 1;
    if (text.startsWith("throws", cursor)) {
      cursor += "throws".length;
      while (cursor < text.length && text[cursor] !== "{" && text[cursor] !== ";") cursor += 1;
    }
    let endByte;
    if (text[cursor] === "{") endByte = matchingBraceEnd(text, cursor);
    else if (text[cursor] === ";") endByte = cursor + 1;
    else continue;
    if (endByte < 0) continue;
    const prefixStart = prefix.search(/\S/u);
    candidates.push({
      startByte: prefixStart < 0 ? call.startByte : lineStart + prefixStart,
      endByte,
    });
  }
  const types = javaTypeRanges(text);
  const matching = candidates.filter((candidate) => {
    const owners = types
      .filter((type) => type.startByte < candidate.startByte && type.endByte >= candidate.endByte)
      .sort((left, right) => (left.endByte - left.startByte) - (right.endByte - right.startByte));
    return owners[0]?.name === ownerName;
  });
  return matching.length === 1 ? matching[0] : null;
}

function enclosingCallRange(text, offset, lowerBound = 0, upperBound = text.length) {
  let opening = text.lastIndexOf("(", offset);
  while (opening >= lowerBound) {
    const endByte = matchingDelimiterEnd(text, opening, "(", ")");
    if (endByte > offset && endByte <= upperBound) {
      let startByte = opening;
      while (startByte > lowerBound && /[A-Za-z0-9_$:>.\-]/u.test(text[startByte - 1])) {
        startByte -= 1;
      }
      const callee = text.slice(startByte, opening).trim();
      if (callee && !["if", "while", "for", "switch"].includes(callee)) {
        return { startByte, endByte };
      }
    }
    opening = text.lastIndexOf("(", opening - 1);
  }
  return null;
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

function callExpressionRangesWithin(
  text,
  callee,
  containerRange,
  { includeNested = false } = {},
) {
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
    if (!includeNested) index = endByte - 1;
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
  if (locator.startsWith(prefix)) {
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
    const commandLine = uniqueTokenRange(text, [`"path": "${command}"`]);
    if (!commandLine) return null;
    const commandRange = enclosingObjectRange(text, commandLine.startByte, 0, text.length);
    if (!commandRange || !child) return commandRange;
    const childLines = tokenRangesWithin(text, `"id": "${child}"`, commandRange);
    if (childLines.length !== 1) return null;
    return enclosingObjectRange(
      text,
      childLines[0].startByte,
      commandRange.startByte,
      commandRange.endByte,
    );
  }

  const semanticPrefix = "clapSurface.semanticRelations:";
  if (locator.startsWith(semanticPrefix)) {
    const parts = locator.slice(semanticPrefix.length).split(":");
    const [kind, commandPath, argumentId, value] = parts;
    if (!["parser", "argument-conflict"].includes(kind) || !value) return null;
    const candidateLines = tokenRangesWithin(
      text,
      `"commandPath": "${commandPath}"`,
      { startByte: 0, endByte: text.length },
    );
    const candidates = candidateLines
      .map((line) => enclosingObjectRange(text, line.startByte, 0, text.length))
      .filter(Boolean)
      .filter((range) => {
        const slice = text.slice(range.startByte, range.endByte);
        return slice.includes(`"argumentId": "${argumentId}"`)
          && slice.includes(`"${value}"`);
      });
    const unique = [...new Map(candidates.map((range) => [`${range.startByte}:${range.endByte}`, range])).values()];
    return unique.length === 1 ? unique[0] : null;
  }

  const replCommandPrefix = "replSurface.command:";
  if (locator.startsWith(replCommandPrefix)) {
    const id = locator.slice(replCommandPrefix.length);
    const lines = tokenRangesWithin(text, `"name": ".${id}"`, { startByte: 0, endByte: text.length });
    if (lines.length !== 1) return null;
    return enclosingObjectRange(text, lines[0].startByte, 0, text.length);
  }

  const loadExtensionPrefix = "replSurface.loadExtension:";
  if (locator.startsWith(loadExtensionPrefix)) {
    const extension = locator.slice(loadExtensionPrefix.length).split(":")[0];
    if (extension === "default") {
      const line = uniqueTokenRange(text, ['"defaultDisposition": "refuse-unknown-or-extensionless"']);
      return line ? enclosingObjectRange(text, line.startByte, 0, text.length) : null;
    }
    const lines = tokenRangesWithin(text, `"extension": "${extension}"`, { startByte: 0, endByte: text.length });
    if (lines.length !== 1) return null;
    return enclosingObjectRange(text, lines[0].startByte, 0, text.length);
  }

  const keybindingPrefix = "keybindingSurface.binding:";
  if (locator.startsWith(keybindingPrefix)) {
    const id = locator.slice(keybindingPrefix.length);
    const lines = tokenRangesWithin(text, `"id": "${id}"`, { startByte: 0, endByte: text.length })
      .map((line) => enclosingObjectRange(text, line.startByte, 0, text.length))
      .filter((range) => range && text.slice(range.startByte, range.endByte).includes('"bytes":'));
    const unique = [...new Map(lines.map((range) => [`${range.startByte}:${range.endByte}`, range])).values()];
    return unique.length === 1 ? unique[0] : null;
  }

  if (locator === "replSurface.recognition") {
    const line = uniqueTokenRange(text, ['"unknownDisposition": "recoverable-error-naming-.help"']);
    return line ? enclosingObjectRange(text, line.startByte, 0, text.length) : null;
  }
  return null;
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

function sourceIdentityRange(sourcePath, locator, text) {
  if (sourcePath.endsWith(".patch") && locator === "patch-content") {
    const startByte = text.indexOf("diff --git ");
    if (startByte < 0) return null;
    return { startByte, endByte: text.length };
  }
  if (!/\.(?:sh|ps1)$/u.test(sourcePath)) return null;
  if (locator.startsWith("evaluator-identity:")) return null;
  const lines = [];
  let startByte = 0;
  for (const line of text.split(/(?<=\n)/u)) {
    const content = line.endsWith("\n") ? line.slice(0, -1) : line;
    const identifier = /^[A-Za-z_][A-Za-z0-9_]*$/u.test(locator);
    const assignment = identifier
      && new RegExp(`^\\s*(?:export\\s+)?(?:\\$)?${escapeRegExp(locator)}\\s*=`, "u").test(content);
    if (assignment || (!identifier && content.includes(locator))) {
      lines.push({ startByte, endByte: startByte + content.length });
    }
    startByte += line.length;
  }
  return lines.length === 1 ? lines[0] : null;
}

function sourceIdentityBinding({ sourceRef, sourcePath, locator, text, bytes }) {
  if (!/\.(?:sh|ps1|patch)$/u.test(sourcePath) || locator.startsWith("evaluator-identity:")) {
    return null;
  }
  if (sourcePath.endsWith(".patch") && locator !== "patch-content") return null;
  const ranges = [];
  if (sourcePath.endsWith(".patch")) {
    const range = sourceIdentityRange(sourcePath, locator, text);
    if (range) ranges.push(range);
  } else {
    const identifier = /^[A-Za-z_][A-Za-z0-9_]*$/u.test(locator);
    let startByte = 0;
    for (const line of text.split(/(?<=\n)/u)) {
      const content = line.endsWith("\n") ? line.slice(0, -1) : line;
      const assignment = identifier
        && new RegExp(`^(?:export\\s+)?(?:\\$)?${escapeRegExp(locator)}\\s*=`, "u").test(content);
      if (assignment || (!identifier && content.includes(locator))) {
        ranges.push({ startByte, endByte: startByte + content.length });
      }
      startByte += line.length;
    }
  }
  if (ranges.length === 0) return null;
  const sites = ranges.map((range, indexValue) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "identity-authority",
    siteKey: `identity.${indexValue}`,
    range,
    text,
    bytes,
  }));
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: sourcePath.endsWith(".patch") ? "patch-payload-identity" : "script-identity-authority",
    resolutionPolicy: "provenance-only",
    sites,
    producerPaths: [],
  });
}

function canonicalIdentityValue(value) {
  if (Array.isArray(value)) return value.map(canonicalIdentityValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [
      key,
      canonicalIdentityValue(value[key]),
    ]));
  }
  return value;
}

function evaluatorIdentityBinding({ sourceRef, sourcePath, locator, absolute, text, bytes }) {
  const prefix = "evaluator-identity:sha256-";
  if (!locator.startsWith(prefix) || !/\.(?:sh|ps1)$/u.test(sourcePath)) return null;
  const root = absolute.slice(0, -sourcePath.length).replace(/[\\/]$/u, "");
  let profiles = hermesEvaluatorProfileCache.get(root);
  if (!profiles) {
    profiles = discoverHermesEvaluatorIdentityProfiles(root);
    hermesEvaluatorProfileCache.set(root, profiles);
  }
  const requestedDigest = locator.slice("evaluator-identity:".length);
  const matches = profiles.filter((profile) => {
    const identityDigest = crypto.createHash("sha256")
      .update(JSON.stringify(canonicalIdentityValue(profile.identity)))
      .digest("hex");
    return requestedDigest === `sha256-${identityDigest}`
      && profile.sourceRefs.some((ref) => ref.startsWith(`${sourcePath}#`));
  });
  if (matches.length !== 1) return null;
  const authorityRefs = matches[0].sourceRefs.filter((ref) => ref.startsWith(`${sourcePath}#`));
  const ranges = [];
  for (const authorityRef of authorityRefs) {
    const authorityLocator = authorityRef.slice(authorityRef.indexOf("#") + 1);
    const authority = sourceIdentityBinding({
      sourceRef,
      sourcePath,
      locator: authorityLocator,
      text,
      bytes,
    });
    for (const site of authority?.sites ?? []) {
      ranges.push({ startByte: site.startByte, endByte: site.endByte });
    }
  }
  const unique = [...new Map(ranges.map((range) => [
    `${range.startByte}:${range.endByte}`,
    range,
  ])).values()];
  if (unique.length === 0) return null;
  const sites = unique.map((range, indexValue) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "identity-authority",
    siteKey: `evaluator-identity.${indexValue}`,
    range,
    text,
    bytes,
  }));
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "hermes-evaluator-identity-authority",
    resolutionPolicy: "provenance-only",
    sites,
    producerPaths: [],
  });
}

function lockdownTamingIdentityBinding({ sourceRef, sourcePath, locator, text, bytes }) {
  const prefix = "lockdown-taming:sha256-";
  if (sourcePath !== "src/engine/hermes_runtime.cc" || !locator.startsWith(prefix)) return null;
  const pattern = /std::string lockdownJS = std::string\(R"JS\(([\s\S]*?)\)JS"\) \+ \(handle->armed \? "true" : "false"\) \+ R"JS\(([\s\S]*?)\)JS";/gu;
  const matches = [...text.matchAll(pattern)];
  if (matches.length !== 1) return null;
  const armedScript = `${matches[0][1]}true${matches[0][2]}`;
  const actual = `lockdown-taming:sha256-${crypto.createHash("sha256").update(armedScript).digest("hex")}`;
  if (locator !== actual) return null;
  const range = { startByte: matches[0].index, endByte: matches[0].index + matches[0][0].length };
  const sites = [sourceSite({
    sourceRef,
    path: sourcePath,
    role: "identity-authority",
    siteKey: "lockdown-taming",
    range,
    text,
    bytes,
  })];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "lockdown-taming-identity-authority",
    resolutionPolicy: "provenance-only",
    sites,
    producerPaths: [],
  });
}

function legacyEvaluatorRunnerBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  const match = /^legacy-runner:([A-Za-z_$][A-Za-z0-9_$]*):(sha256-[a-f0-9]{64})$/u.exec(locator);
  if (sourcePath !== "src/engine/hermes_bootstrap.cc" || !match) return null;
  const [, functionName] = match;
  const installations = scanLegacyEvaluatorBootstrapInstallations(text, sourcePath);
  const installation = Object.values(installations).find((entry) =>
    entry.sourceRefs.includes(sourceRef));
  if (!installation || !installation.targetVariants.includes(branch?.targetVariant)) return null;
  const definition = robustFunctionDeclarationRange(text, functionName);
  if (!definition) return null;
  const dispatches = callExpressionRangesWithin(text, "eval_bootstrap_script", definition);
  if (dispatches.length !== 1) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: `${functionName}.definition`, range: definition, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: `${functionName}.dispatch`, range: dispatches[0], text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "legacy-native-evaluator-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0legacy-evaluator`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
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
  const identity = sourceIdentityRange(sourcePath, locator, text);
  if (identity) return identity;
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

function lineNumberAt(text, offset) {
  let starts = lineStartCache.get(text);
  if (!starts) {
    starts = [0];
    let newline = text.indexOf("\n");
    while (newline >= 0) {
      starts.push(newline + 1);
      newline = text.indexOf("\n", newline + 1);
    }
    lineStartCache.set(text, starts);
  }
  let low = 0;
  let high = starts.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (starts[middle] <= offset) low = middle + 1;
    else high = middle;
  }
  return low;
}

function sourceSite({ sourceRef, path: sourcePath, role, siteKey, range, text, bytes }) {
  const ascii = bytes.length === text.length;
  const startByte = ascii
    ? range.startByte
    : Buffer.byteLength(text.slice(0, range.startByte), "utf8");
  const endByte = ascii
    ? range.endByte
    : Buffer.byteLength(text.slice(0, range.endByte), "utf8");
  const slice = bytes.subarray(startByte, endByte);
  return {
    siteId: stableId("site", `${sourceRef}\0${siteKey}`),
    path: sourcePath,
    role,
    startByte,
    endByte,
    startLine: lineNumberAt(text, range.startByte),
    endLine: lineNumberAt(text, range.endByte),
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

function signalNumberOverlayBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    branch?.observedKey !== "builtin:export:node_constants:[[dynamic-table:signal-number-overlay]]"
    || sourcePath !== "src/builtins/constants.js"
    || locator !== "exports:[[dynamic-table:signal-number-overlay]]"
  ) return null;
  const producer = declarationRange(text, "_signalNumbers");
  const dispatch = uniqueTokenRange(text, ["_assign(_signalNumbers());"]);
  const publication = uniqueTokenRange(text, ["module.exports = constants;"]);
  if (!producer || !dispatch || !publication) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: "signal-number-overlay.producer", range: producer, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "signal-number-overlay.assignment", range: dispatch, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "signal-number-overlay.publication", range: publication, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "commonjs-signal-number-overlay-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0signal-number-overlay`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
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

function moduleInlineExportBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    sourcePath !== "modules.ts"
    || !locator.startsWith("sources:")
    || !branch?.observedKey?.startsWith("builtin:export:")
  ) return null;
  const match = /^sources:([^:]+):exports:(.+)$/u.exec(locator);
  if (!match) return null;
  const [, sourceKey, exportPath] = match;
  const sourceEntryPattern = new RegExp(
    `(?:^|\\n)\\s*${escapeRegExp(sourceKey)}:\\s*\\{[^\\n]+\\}`,
    "gu",
  );
  const sourceEntries = [...text.matchAll(sourceEntryPattern)];
  if (sourceEntries.length !== 1) return null;
  const sourceEntry = lineRange(text, sourceEntries[0].index + sourceEntries[0][0].search(/\S/u));
  const sourceEntryText = text.slice(sourceEntry.startByte, sourceEntry.endByte);
  const codeIdentifier = /\bcode:\s*([A-Za-z_$][A-Za-z0-9_$]*)\b/u.exec(sourceEntryText)?.[1];
  let codeRange = sourceEntry;
  if (codeIdentifier) {
    const declarationPattern = new RegExp(
      `(?:^|\\n)\\s*const\\s+${escapeRegExp(codeIdentifier)}\\s*=\\s*String\\.raw\\x60`,
      "gu",
    );
    const declarations = [...text.matchAll(declarationPattern)];
    if (declarations.length !== 1) return null;
    const templateStart = text.indexOf("`", declarations[0].index) + 1;
    const templateEnd = text.indexOf("`;", templateStart);
    if (templateStart <= 0 || templateEnd < templateStart) return null;
    codeRange = { startByte: templateStart, endByte: templateEnd };
  }

  const moduleAssignments = tokenRangesWithin(text, "module.exports =", codeRange);
  if (moduleAssignments.length !== 1) return null;
  const assignmentLine = moduleAssignments[0];
  const equals = text.indexOf("=", assignmentLine.startByte);
  const opening = text.indexOf("{", equals);
  const moduleObjectEnd = opening >= 0 && opening < codeRange.endByte
    ? matchingBraceEnd(text, opening)
    : -1;
  const modulePublication = moduleObjectEnd > opening && moduleObjectEnd <= codeRange.endByte
    ? { startByte: assignmentLine.startByte, endByte: moduleObjectEnd + 1 }
    : assignmentLine;
  const parts = exportPath.split(".");
  const root = parts[0];
  let producer = null;
  let rootRegistration = null;
  if (root === "default") {
    producer = modulePublication;
  } else if (moduleObjectEnd > opening && moduleObjectEnd <= codeRange.endByte) {
    const properties = tokenRangesWithin(
      text,
      `${root}:`,
      { startByte: opening, endByte: moduleObjectEnd },
    );
    if (properties.length === 1) rootRegistration = properties[0];
  }
  if (!producer && parts.length > 1) {
    const member = parts.at(-1);
    const patterns = [
      `${root}.prototype.${member} =`,
      `${member}: function`,
      `${member}(`,
    ];
    const candidates = patterns.flatMap((token) => tokenRangesWithin(text, token, codeRange));
    const unique = dedupeRanges(candidates);
    if (unique.length === 1) producer = unique[0];
  }
  if (!producer) {
    const functionPattern = new RegExp(
      `(?:^|\\n)\\s*function\\s+${escapeRegExp(root)}\\s*\\(`,
      "gu",
    );
    const functions = [...text.slice(codeRange.startByte, codeRange.endByte).matchAll(functionPattern)];
    if (functions.length === 1) {
      const startByte = codeRange.startByte + functions[0].index + functions[0][0].search(/\S/u);
      const openingBrace = text.indexOf("{", startByte);
      const endByte = openingBrace < 0 ? -1 : matchingBraceEnd(text, openingBrace);
      if (endByte > openingBrace && endByte <= codeRange.endByte) producer = { startByte, endByte };
    }
  }
  if (!producer && rootRegistration) producer = rootRegistration;
  if (!producer || !rootRegistration && root !== "default") return null;

  const specifierCandidates = tokenRangesWithin(
    text,
    `source: '${sourceKey}'`,
    { startByte: 0, endByte: text.length },
  ).map((line) => enclosingObjectRange(text, line.startByte, 0, text.length)).filter(Boolean);
  const uniqueSpecifiers = dedupeRanges(specifierCandidates);
  if (uniqueSpecifiers.length !== 1) return null;
  const ranges = [
    { role: "value-producer", key: `${exportPath}.inline-producer`, range: producer },
    { role: "registration", key: `${sourceKey}.source-registration`, range: sourceEntry },
    { role: "registration", key: `${sourceKey}.specifier-registration`, range: uniqueSpecifiers[0] },
    ...(rootRegistration && rootRegistration !== producer
      ? [{ role: "registration", key: `${exportPath}.root-registration`, range: rootRegistration }]
      : []),
    { role: "publication", key: `${exportPath}.inline-publication`, range: modulePublication },
  ];
  const sites = ranges.map(({ role, key, range }) => sourceSite({
    sourceRef,
    path: sourcePath,
    role,
    siteKey: key,
    range,
    text,
    bytes,
  }));
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "inline-module-export-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0inline-module-export`),
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
  if (["TSAsExpression", "TSTypeAssertion", "TSNonNullExpression", "ParenthesizedExpression"].includes(node.type)) {
    return memberSegments(node.expression);
  }
  if (node.type === "Identifier") return [node.name];
  if (node.type === "ThisExpression") return ["this"];
  if (node.type !== "MemberExpression" && node.type !== "OptionalMemberExpression") return null;
  const base = memberSegments(node.object);
  const property = node.computed ? propertyName(node.property) : propertyName(node.property);
  return base && property !== null ? [...base, property] : null;
}

function globalPathMatches(candidate, logicalPath) {
  if (!candidate || candidate.length === 0) return false;
  const normalized = ["g", "globalThis", "window", "self"].includes(candidate[0])
    ? candidate.slice(1)
    : candidate;
  if (JSON.stringify(normalized) === JSON.stringify(logicalPath)) return true;
  if (normalized.length === logicalPath.length
    && normalized[0]?.toLowerCase() === logicalPath[0]?.toLowerCase()
    && JSON.stringify(normalized.slice(1)) === JSON.stringify(logicalPath.slice(1))) return true;
  if (logicalPath.length > 1 && normalized.length > 1) {
    return JSON.stringify(normalized.slice(-2)) === JSON.stringify(logicalPath.slice(-2));
  }
  return logicalPath.length === 1 && normalized.at(-1) === logicalPath[0];
}

function typescriptGlobalInstallerBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("native-op:")
    || !sourcePath.startsWith("packages/ibex-runtime-js/src/")
    || !/\.tsx?$/u.test(sourcePath)) return null;
  const marker = ":globals:";
  const markerIndex = locator.indexOf(marker);
  if (markerIndex < 1) return null;
  const installerName = locator.slice(0, markerIndex);
  const getterInstaller = installerName === "get";
  const moduleInstaller = installerName === "<module>" || getterInstaller;
  if (!moduleInstaller && !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(installerName)) return null;
  const logicalPath = locator.slice(markerIndex + marker.length).split(".");
  if (logicalPath.some((part) => !part || part.includes("[["))) return null;
  const ast = parse(text, {
    sourceType: "module",
    plugins: ["typescript", "decorators-legacy"],
  });
  const installers = moduleInstaller ? [ast.program] : [];
  if (!moduleInstaller) {
    walkJavaScript(ast.program, (node) => {
      if (["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(node.type)
        && (node.id?.name === installerName)) installers.push(node);
    });
  }
  if (installers.length !== 1) return null;
  const installer = installers[0];
  const aliases = new Map();
  const expandAliases = (segments) => {
    let expanded = segments;
    const seen = new Set();
    while (expanded?.length > 0 && aliases.has(expanded[0]) && !seen.has(expanded[0])) {
      seen.add(expanded[0]);
      expanded = [...aliases.get(expanded[0]), ...expanded.slice(1)];
    }
    return expanded;
  };
  const installerPathMatches = (segments) => {
    const expanded = expandAliases(segments);
    const normalized = ["g", "globalThis", "window", "self"].includes(expanded?.[0])
      ? expanded.slice(1)
      : expanded;
    if (JSON.stringify(normalized) === JSON.stringify(logicalPath)) return true;
    return normalized?.length === logicalPath.length
      && normalized[0]?.toLowerCase() === logicalPath[0]?.toLowerCase()
      && JSON.stringify(normalized.slice(1)) === JSON.stringify(logicalPath.slice(1));
  };
  const candidates = [];
  walkJavaScript(moduleInstaller ? installer : installer.body, (node, parent) => {
    if (node.type === "VariableDeclarator" && node.id?.type === "Identifier") {
      const segments = memberSegments(node.init);
      if (segments && segments.length > 0) aliases.set(node.id.name, segments);
    }
    if (!getterInstaller && node.type === "AssignmentExpression") {
      const segments = memberSegments(node.left);
      if (installerPathMatches(segments)) {
        candidates.push({
          producer: node.right,
          publication: parent?.type === "ExpressionStatement" ? parent : node,
        });
      }
    }
    if (node.type === "CallExpression"
      && JSON.stringify(memberSegments(node.callee)) === JSON.stringify(["Object", "defineProperty"])) {
      const target = memberSegments(node.arguments[0]);
      const property = propertyName(node.arguments[1]);
      if (property !== null && installerPathMatches([...(target ?? []), property])) {
        const getter = objectProperty(node.arguments[2], "get");
        if (getterInstaller && !getter) return;
        candidates.push({
          producer: getter ?? node.arguments[2] ?? node,
          publication: parent?.type === "ExpressionStatement" ? parent : node,
        });
      }
    }
    if (getterInstaller
      && node.type === "CallExpression"
      && node.callee?.type === "Identifier"
      && node.callee.name === "defineLazyGlobal") {
      const target = memberSegments(node.arguments[0]);
      const property = propertyName(node.arguments[1]);
      if (property !== null && installerPathMatches([...(target ?? []), property])) {
        candidates.push({
          producer: node.arguments[2] ?? node,
          publication: parent?.type === "ExpressionStatement" ? parent : node,
        });
      }
    }
  });
  const unique = [...new Map(candidates.map((candidate) => [
    `${candidate.publication.start}:${candidate.publication.end}`,
    candidate,
  ])).values()];
  if (unique.length !== 1) return null;
  const candidate = unique[0];
  const sites = [
    sourceSite({
      sourceRef,
      path: sourcePath,
      role: "value-producer",
      siteKey: `${logicalPath.join(".")}.producer`,
      range: { startByte: candidate.producer.start, endByte: candidate.producer.end },
      text,
      bytes,
    }),
    sourceSite({
      sourceRef,
      path: sourcePath,
      role: "publication",
      siteKey: `${logicalPath.join(".")}.publication`,
      range: { startByte: candidate.publication.start, endByte: candidate.publication.end },
      text,
      bytes,
    }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "typescript-global-installer-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0global-installer`),
      conditionId: `target-branch:${branch.targetVariant}:installer:${installerName}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function cppSymbolProvenanceBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("native-op:")
    || !/\.(?:cc|mm|h)$/u.test(sourcePath)
    || locator.startsWith("jsi-global:")) return null;
  let token = locator;
  for (const prefix of ["jsi-global:", "jsi-global-property:", "definition:"]) {
    if (token.startsWith(prefix)) token = token.slice(prefix.length);
  }
  if (token.startsWith("embedded:")) token = token.split(":").at(-1);
  if (token.includes(":")) token = token.split(":").at(-1);
  if (token.includes(".")) token = token.split(".").at(-1);
  token = token.replace(/^\[\[|\]\]$/gu, "");
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(token)) return null;
  const pattern = new RegExp(`\\b${escapeRegExp(token)}\\b`, "gu");
  const ranges = [];
  for (const match of text.matchAll(pattern)) {
    const range = lineRange(text, match.index);
    const line = text.slice(range.startByte, range.endByte).trimStart();
    if (line.startsWith("//") || line.startsWith("/*") || line.startsWith("*")) continue;
    ranges.push(range);
  }
  const unique = dedupeRanges(ranges);
  if (unique.length === 0) return null;
  const sites = unique.map((range, indexValue) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "symbol-provenance",
    siteKey: `${locator}.${indexValue}`,
    range,
    text,
    bytes,
  }));
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "cpp-symbol-provenance",
    resolutionPolicy: "provenance-only",
    sites,
    producerPaths: [],
  });
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
    } else if (node.type === "CallExpression") {
      const calleeSegments = memberSegments(node.callee);
      if (
        JSON.stringify(calleeSegments) === JSON.stringify(["Object", "defineProperty"])
        && propertyName(node.arguments[1]) !== null
      ) {
        defineProperties.push({
          node: parent?.type === "ExpressionStatement" ? parent : node,
          targetSegments: memberSegments(node.arguments[0]),
          property: propertyName(node.arguments[1]),
          descriptor: node.arguments[2],
        });
      } else if (
        JSON.stringify(calleeSegments) === JSON.stringify(["Object", "defineProperties"])
        && node.arguments[1]?.type === "ObjectExpression"
      ) {
        for (const property of node.arguments[1].properties) {
          if (!["ObjectProperty", "ObjectMethod"].includes(property.type)) continue;
          const name = propertyName(property.key);
          if (name === null) continue;
          defineProperties.push({
            node: property,
            targetSegments: memberSegments(node.arguments[0]),
            property: name,
            descriptor: property.type === "ObjectProperty" ? property.value : property,
          });
        }
      } else if (
        ["__defineGetter__", "__defineSetter__"].includes(calleeSegments?.at(-1))
        && propertyName(node.arguments[0]) !== null
      ) {
        defineProperties.push({
          node: parent?.type === "ExpressionStatement" ? parent : node,
          targetSegments: calleeSegments.slice(0, -1),
          property: propertyName(node.arguments[0]),
          descriptor: node.arguments[1],
          accessorKind: calleeSegments.at(-1) === "__defineGetter__" ? "getter" : "setter",
        });
      }
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

function memberProducers(index, ownerName, memberName, preference = "prefer-static") {
  const owner = declarationFor(index, ownerName);
  const ownerValue = owner?.value;
  const selectClassMember = (classNode) => {
    const matching = classNode.body.body.filter(
      (method) => ["ClassMethod", "ClassPrivateMethod", "ClassProperty"].includes(method.type)
        && propertyName(method.key) === memberName,
    );
    const staticMembers = matching.filter((method) => Boolean(method.static));
    const prototypeMembers = matching.filter((method) => !method.static);
    if (preference === "static") return staticMembers;
    if (preference === "prototype") return prototypeMembers;
    if (staticMembers.length > 0) return staticMembers;
    return prototypeMembers;
  };
  if (ownerValue?.type === "ClassDeclaration" || ownerValue?.type === "ClassExpression") {
    const selected = selectClassMember(ownerValue);
    if (selected.length > 0) return selected;
  }
  if (owner?.node?.type === "ClassDeclaration") {
    const selected = selectClassMember(owner.node);
    if (selected.length > 0) return selected;
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
  const readDescriptors = (rows) => {
    const getters = rows.filter((row) => row.accessorKind === "getter");
    return getters.length > 0 ? getters : rows;
  };
  if (preference === "prototype") {
    if (prototypeAssignments.length > 0) return prototypeAssignments.map((row) => row.node);
    return readDescriptors(prototypeDescriptors).map((row) => row.node);
  }
  if (preference === "static") {
    if (staticAssignments.length > 0) return staticAssignments.map((row) => row.node);
    return readDescriptors(staticDescriptors).map((row) => row.node);
  }
  if (staticAssignments.length > 0) return staticAssignments.map((row) => row.node);
  if (staticDescriptors.length > 0) return readDescriptors(staticDescriptors).map((row) => row.node);
  if (prototypeAssignments.length > 0) return prototypeAssignments.map((row) => row.node);
  return readDescriptors(prototypeDescriptors).map((row) => row.node);
}

function memberProducer(index, ownerName, memberName, preference = "prefer-static") {
  const producers = memberProducers(index, ownerName, memberName, preference);
  return producers.length === 1 ? producers[0] : null;
}

function commonjsInheritedExportBinding({ branch, sourceRef, sourcePath, exportPath, absolute, text, bytes }) {
  const match = /^(?:([^.]*)\.)?\[\[dynamic-table:inherited-[^\]]+-properties\]\]$/u.exec(exportPath);
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
  let classNode = declaration?.node?.type === "ClassDeclaration"
    ? declaration.node
    : declaration?.value;
  if (!classNode || !["ClassDeclaration", "ClassExpression"].includes(classNode.type)) {
    const matches = [];
    walkJavaScript(parse(text, {
      sourceType: "module",
      plugins: ["typescript", "decorators-legacy"],
    }).program, (node) => {
      if (["ClassDeclaration", "ClassExpression"].includes(node.type)
        && node.id?.name === className) matches.push(node);
    });
    classNode = matches.length === 1 ? matches[0] : null;
  }
  if (!classNode || !["ClassDeclaration", "ClassExpression"].includes(classNode.type)) return null;
  let producers = [classNode];
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
      ["ClassMethod", "ClassProperty", "ClassAccessorProperty"].includes(element.type)
      && classElementName(element) === memberName
      && Boolean(element.static) === !prototype,
    );
    const accessorPair = members.length === 2
      && members.every((member) => member.type === "ClassMethod")
      && new Set(members.map((member) => member.kind)).size === 2
      && members.every((member) => ["get", "set"].includes(member.kind));
    if (members.length !== 1 && !accessorPair) {
      const descriptors = index.defineProperties.filter((row) =>
        row.property === memberName
        && JSON.stringify(row.targetSegments) === JSON.stringify([className]));
      if (descriptors.length !== 1) return null;
      producers = [descriptors[0].node];
    } else {
      producers = members;
    }
    siteKey = `${className}.${prototype ? "prototype." : ""}${memberName}`;
  }
  const sites = producers.map((producer, indexValue) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: extendsIndex >= 0 ? "alias" : "value-producer",
    siteKey: producers.length === 1 ? siteKey : `${siteKey}.${producer.kind}.${indexValue}`,
    range: { startByte: producer.start, endByte: producer.end },
    text,
    bytes,
  }));
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: extendsIndex >= 0 ? "typescript-class-inheritance" : "typescript-class-member",
    resolutionPolicy: "provenance-only",
    sites,
    producerPaths: [],
  });
}

function typescriptComputedMemberBinding({ sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (!sourcePath.startsWith("packages/ibex-runtime-js/src/")
    || !/\.tsx?$/u.test(sourcePath)
    || locator.includes(":globals:")) return null;
  const match = /^(?:[A-Za-z_$][A-Za-z0-9_$]*)(?:\.prototype)?\.\[\[(?:Symbol\.|symbol-binding:)[^\]]+\]\]$/u.exec(locator);
  if (!match) return null;
  const range = resolveRange(sourcePath, locator, text, absolute);
  if (!range) return null;
  const site = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "value-producer",
    siteKey: `${locator}.computed-member`,
    range,
    text,
    bytes,
  });
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "typescript-computed-member",
    resolutionPolicy: "provenance-only",
    sites: [site],
    producerPaths: [],
  });
}

function typescriptStaticDescriptorBinding({ branch, sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (!branch?.observedKey?.startsWith("native-op:global:")
    || !sourcePath.startsWith("packages/ibex-runtime-js/src/")
    || !/\.tsx?$/u.test(sourcePath)
    || branch.observedKey.slice("native-op:global:".length) !== locator) return null;
  const parts = locator.split(".");
  if (parts.length !== 2) return null;
  const [owner, member] = parts;
  const index = javascriptIndex(absolute, text);
  const descriptors = index.defineProperties.filter((row) =>
    row.property === member
    && JSON.stringify(row.targetSegments) === JSON.stringify([owner]));
  if (descriptors.length !== 1 || !descriptors[0].descriptor) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${locator}.descriptor`, range: { startByte: descriptors[0].descriptor.start, endByte: descriptors[0].descriptor.end }, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${locator}.publication`, range: { startByte: descriptors[0].node.start, endByte: descriptors[0].node.end }, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "typescript-static-descriptor-route",
    targetGlobalPath: locator,
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0static-descriptor`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function typescriptObjectMemberBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("native-op:global:")
    || !sourcePath.startsWith("packages/ibex-runtime-js/src/")
    || !/\.tsx?$/u.test(sourcePath)
    || locator.includes(":")
    || locator.includes("[[")
    || locator.startsWith("<")) return null;
  const parts = locator.split(".");
  if (parts.length < 2) return null;
  const member = parts.at(-1);
  const candidates = [];
  const ast = parse(text, {
    sourceType: "module",
    plugins: ["typescript", "decorators-legacy"],
  });
  walkJavaScript(ast.program, (node) => {
    if (["ObjectMethod", "ObjectProperty"].includes(node.type)
      && propertyName(node.key) === member) candidates.push(node);
  });
  if (candidates.length !== 1) return null;
  const site = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "value-producer",
    siteKey: `${locator}.object-member`,
    range: { startByte: candidates[0].start, endByte: candidates[0].end },
    text,
    bytes,
  });
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "typescript-object-member",
    resolutionPolicy: "provenance-only",
    sites: [site],
    producerPaths: [],
  });
}

function typescriptFactoryObjectMemberBinding({ sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (!sourcePath.startsWith("packages/ibex-runtime-js/src/")
    || !/\.tsx?$/u.test(sourcePath)
    || locator.includes(":")
    || locator.includes("[[")) return null;
  const parts = locator.split(".");
  if (parts.length !== 2) return null;
  let [factoryName, memberName] = parts;
  if (sourcePath === "packages/ibex-runtime-js/src/core/accessibility.ts"
    && factoryName === memberName) {
    factoryName = "createAccessibilityNamespace";
  }
  const index = javascriptIndex(absolute, text);
  const declaration = declarationFor(index, factoryName);
  const factory = declaration?.node ?? declaration?.value;
  if (!factory || factory.start === undefined || factory.end === undefined) return null;
  const candidates = [];
  walkJavaScript(factory, (node) => {
    if (["ObjectMethod", "ObjectProperty"].includes(node.type)
      && propertyName(node.key) === memberName) candidates.push(node);
  });
  const unique = [...new Map(candidates.map((node) => [`${node.start}:${node.end}`, node])).values()];
  if (unique.length !== 1) return null;
  const site = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "value-producer",
    siteKey: `${factoryName}.${memberName}.factory-member`,
    range: { startByte: unique[0].start, endByte: unique[0].end },
    text,
    bytes,
  });
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "typescript-factory-object-member",
    resolutionPolicy: "provenance-only",
    sites: [site],
    producerPaths: [],
  });
}

function javascriptSymbolProvenanceBinding({ sourceRef, sourcePath, locator, text, bytes }) {
  if (!sourcePath.endsWith(".js")
    || locator.includes(":")
    || locator.includes("[[")
    || locator.startsWith("<")) return null;
  const logicalPath = locator.split(".");
  if (logicalPath.some((part) => !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(part))) return null;
  const candidates = [];
  const ast = parse(text, { sourceType: "script", allowReturnOutsideFunction: true });
  walkJavaScript(ast.program, (node, parent) => {
    const segments = memberSegments(node);
    if (segments && JSON.stringify(segments) === JSON.stringify(logicalPath)) {
      const parentSegments = memberSegments(parent);
      if (!parentSegments || parentSegments.length <= segments.length) candidates.push(node);
      return;
    }
    if (logicalPath.length === 1 && node.type === "Identifier" && node.name === logicalPath[0]) {
      candidates.push(node);
    }
    if (logicalPath.length === 1 && node.type === "MemberExpression") {
      const member = memberSegments(node);
      if (member?.at(-1) === logicalPath[0]) candidates.push(node);
    }
  });
  if (candidates.length === 0 && logicalPath.length > 1) {
    walkJavaScript(ast.program, (node) => {
      const segments = memberSegments(node);
      if (segments?.at(-1) === logicalPath[0]) candidates.push(node);
    });
  }
  const unique = [...new Map(candidates.map((node) => [
    `${node.start}:${node.end}`,
    node,
  ])).values()];
  if (unique.length === 0) return null;
  const sites = unique.map((node, indexValue) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "symbol-provenance",
    siteKey: `${logicalPath.join(".")}.${indexValue}`,
    range: { startByte: node.start, endByte: node.end },
    text,
    bytes,
  }));
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "javascript-symbol-provenance",
    resolutionPolicy: "provenance-only",
    sites,
    producerPaths: [],
  });
}

function generatedJavascriptGlobalBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("native-op:")
    || !sourcePath.endsWith(".generated.js")) return null;
  const observedName = branch.observedKey.slice("native-op:".length);
  const root = observedName.split(".")[0];
  const locatorRoot = locator.split(".[[")[0];
  if (locatorRoot !== root) return null;
  const ast = parse(text, { sourceType: "script", allowReturnOutsideFunction: true });
  const publications = [];
  walkJavaScript(ast.program, (node, parent) => {
    if (node.type === "CallExpression"
      && JSON.stringify(memberSegments(node.callee)) === JSON.stringify(["Object", "defineProperty"])
      && propertyName(node.arguments[1]) === root) {
      publications.push({ node: parent?.type === "ExpressionStatement" ? parent : node, descriptor: node.arguments[2] });
    }
  });
  const invocations = ast.program.body.filter((node) =>
    node.type === "ExpressionStatement" && node.expression?.type === "CallExpression");
  if (publications.length !== 1 || invocations.length !== 1 || !publications[0].descriptor) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${root}.generated-value`, range: { startByte: publications[0].descriptor.start, endByte: publications[0].descriptor.end }, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${root}.defineProperty`, range: { startByte: publications[0].node.start, endByte: publications[0].node.end }, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: `${root}.installer-invocation`, range: { startByte: invocations[0].start, endByte: invocations[0].end }, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "generated-javascript-global-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0generated-global`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function typescriptModuleGlobalMemberBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("native-op:")
    || !/\.tsx?$/u.test(sourcePath)
    || !locator.startsWith("<module>.")) return null;
  const observedName = branch.observedKey.startsWith("native-op:global:")
    ? branch.observedKey.slice("native-op:global:".length)
    : branch.observedKey.slice("native-op:".length);
  const observedPath = observedName.split(".");
  const member = locator.slice("<module>.".length);
  const memberIndex = observedPath.lastIndexOf(member);
  if (memberIndex < 1) return null;
  const publicationPath = observedPath.slice(0, memberIndex);
  const root = publicationPath.join(".");
  const assignments = [];
  const ast = parse(text, {
    sourceType: "module",
    plugins: ["typescript", "decorators-legacy"],
  });
  walkJavaScript(ast.program, (node, parent) => {
    if (node.type !== "AssignmentExpression") return;
    const segments = memberSegments(node.left);
    if (segments
      && JSON.stringify(segments.slice(-publicationPath.length)) === JSON.stringify(publicationPath)
      && node.right?.type === "ObjectExpression") {
      assignments.push({ node: parent?.type === "ExpressionStatement" ? parent : node, value: node.right });
    }
  });
  if (assignments.length !== 1) return null;
  const property = objectProperty(assignments[0].value, member);
  if (!property) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${root}.${member}.module-value`, range: { startByte: property.start, endByte: property.end }, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${root}.module-publication`, range: { startByte: assignments[0].node.start, endByte: assignments[0].node.end }, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "typescript-module-global-member-route",
    targetGlobalPath: observedName,
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0module-global-member`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function typescriptBundleMemberBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (sourcePath !== "packages/ibex-runtime-js/src/bootstrap.ts"
    || !branch?.observedKey?.startsWith("native-op:global:ExactBundle")
    || !locator.startsWith("<module>.")) return null;
  const observedPath = branch.observedKey.slice("native-op:global:".length).split(".");
  const memberPath = observedPath.slice(1);
  const locatorMember = locator.slice("<module>.".length);
  if (memberPath.length === 0 || memberPath.at(-1) !== locatorMember) return null;
  const ast = parse(text, {
    sourceType: "module",
    plugins: ["typescript", "decorators-legacy"],
  });
  const declarations = new Map();
  const publications = [];
  walkJavaScript(ast.program, (node, parent) => {
    if (node.type === "VariableDeclarator" && node.id?.type === "Identifier") {
      declarations.set(node.id.name, node.init);
    }
    if (node.type === "AssignmentExpression") {
      const segments = memberSegments(node.left);
      if (segments?.at(-1) === "ExactBundle") {
        publications.push(parent?.type === "ExpressionStatement" ? parent : node);
      }
    }
  });
  if (publications.length !== 1) return null;
  let object = declarations.get("runtimeBundle");
  if (object?.type !== "ObjectExpression") return null;
  let producer = object;
  for (const member of memberPath) {
    const property = objectProperty(object, member);
    if (!property) return null;
    producer = property;
    const value = property.value;
    if (member !== memberPath.at(-1)) {
      object = value?.type === "Identifier" ? declarations.get(value.name) : value;
      if (object?.type !== "ObjectExpression") return null;
    }
  }
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `ExactBundle.${memberPath.join(".")}.producer`, range: { startByte: producer.start, endByte: producer.end }, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "ExactBundle.publication", range: { startByte: publications[0].start, endByte: publications[0].end }, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "typescript-bundle-member-route",
    targetGlobalPath: observedPath.join("."),
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0exact-bundle-member`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function typescriptModuleObjectMemberProvenanceBinding({ sourceRef, sourcePath, locator, text, bytes }) {
  if (!/\.tsx?$/u.test(sourcePath) || !locator.startsWith("<module>.")) return null;
  const member = locator.slice("<module>.".length);
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(member)) return null;
  const ast = parse(text, {
    sourceType: "module",
    plugins: ["typescript", "decorators-legacy"],
  });
  const properties = [];
  walkJavaScript(ast.program, (node) => {
    if (["ObjectProperty", "ObjectMethod"].includes(node.type)
      && !node.computed
      && propertyName(node.key) === member) properties.push(node);
  });
  const unique = [...new Map(properties.map((node) => [`${node.start}:${node.end}`, node])).values()];
  if (unique.length !== 1) return null;
  const sites = [sourceSite({
    sourceRef,
    path: sourcePath,
    role: "symbol-provenance",
    siteKey: `<module>.${member}`,
    range: { startByte: unique[0].start, endByte: unique[0].end },
    text,
    bytes,
  })];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "typescript-module-object-member-provenance",
    resolutionPolicy: "provenance-only",
    sites,
    producerPaths: [],
  });
}

function legacyViewConstructorTableBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("native-op:global:")
    || !sourcePath.startsWith("src/engine/bootstrap/")
    || !sourcePath.endsWith(".js")) return null;
  const observedPath = branch.observedKey.slice("native-op:global:".length);
  if (observedPath !== locator) return null;
  const constructorName = observedPath.split(".")[0];
  const ast = parse(text, { sourceType: "script", allowReturnOutsideFunction: true });
  const wrapperNames = new Set([
    "wrapCtor",
    "wrapSharedArrayBufferViewCtor",
    "__exactWrapSharedArrayBufferViewCtor",
  ]);
  const wrappers = new Map();
  const arrays = [];
  const calls = [];
  walkJavaScript(ast.program, (node, parent) => {
    if (node.type === "FunctionDeclaration" && wrapperNames.has(node.id?.name)) {
      wrappers.set(node.id.name, node);
    }
    if (node.type === "VariableDeclarator"
      && node.id?.type === "Identifier"
      && node.init?.type === "ArrayExpression") {
      arrays.push({ name: node.id.name, node, value: node.init });
    }
    if (node.type === "CallExpression"
      && node.callee?.type === "Identifier"
      && wrapperNames.has(node.callee.name)) {
      calls.push({ node: parent?.type === "ExpressionStatement" ? parent : node, call: node });
    }
  });
  const publications = new Map();
  for (const [name, wrapper] of wrappers) {
    const matches = [];
    walkJavaScript(wrapper.body, (node, parent) => {
      if (node.type !== "AssignmentExpression" || node.left?.type !== "MemberExpression") return;
      const object = memberSegments(node.left.object);
      if (JSON.stringify(object) === JSON.stringify(["globalThis"])
        && node.left.computed
        && node.left.property?.type === "Identifier"
        && node.left.property.name === wrapper.params[0]?.name) {
        matches.push(parent?.type === "ExpressionStatement" ? parent : node);
      }
    });
    if (matches.length === 1) publications.set(name, matches[0]);
  }
  const routes = [];
  for (const { node, call } of calls) {
    const wrapperName = call.callee.name;
    const publication = publications.get(wrapperName);
    if (!publication) continue;
    const argument = call.arguments[0];
    let entry = null;
    if (propertyName(argument) === constructorName) {
      entry = argument;
    } else if (argument?.type === "MemberExpression" && argument.object?.type === "Identifier") {
      const candidates = arrays.filter((row) =>
        row.name === argument.object.name
        && row.node.start < call.start
        && row.value.elements.some((element) => propertyName(element) === constructorName));
      if (candidates.length > 0) {
        const table = candidates.at(-1);
        entry = table.value.elements.find((element) => propertyName(element) === constructorName);
      }
    }
    if (entry) routes.push({ wrapperName, entry, dispatch: node, publication });
  }
  if (routes.length === 0) return null;
  const sites = [];
  const producerPaths = [];
  for (const [indexValue, route] of routes.entries()) {
    const pathSites = [
      sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${constructorName}.table-entry.${indexValue}`, range: { startByte: route.entry.start, endByte: route.entry.end }, text, bytes }),
      sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: `${constructorName}.wrapper-dispatch.${indexValue}`, range: { startByte: route.dispatch.start, endByte: route.dispatch.end }, text, bytes }),
      sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${constructorName}.wrapper-publication.${indexValue}`, range: { startByte: route.publication.start, endByte: route.publication.end }, text, bytes }),
    ];
    sites.push(...pathSites);
    producerPaths.push({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0view-wrapper\0${indexValue}`),
      conditionId: `legacy-wrapper:${sourcePath}:${route.wrapperName}:${route.dispatch.start}`,
      requiredSiteIds: pathSites.map((site) => site.siteId),
    });
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "legacy-view-constructor-table-route",
    targetGlobalPath: observedPath,
    resolutionPolicy: producerPaths.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths,
  });
}

function legacyReturnedPrototypeMemberBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (sourcePath !== "src/engine/bootstrap/web-streams-polyfill.js"
    || branch?.observedKey !== `native-op:global:${locator}`) return null;
  const match = /^(ReadableStream|VideoFrame)\.\[\[return\]\]\.([A-Za-z_$][A-Za-z0-9_$]*)$/u.exec(locator);
  if (!match) return null;
  const [, owner, member] = match;
  const ast = parse(text, { sourceType: "script", allowReturnOutsideFunction: true });
  const candidates = [];
  walkJavaScript(ast.program, (node, parent) => {
    if (owner === "ReadableStream"
      && node.type === "ClassDeclaration"
      && node.id?.name === "ReadableStream") {
      for (const element of node.body.body) {
        if (["ClassMethod", "ClassProperty"].includes(element.type)
          && classElementName(element) === member
          && !element.static) candidates.push({ node: element, kind: "polyfill-class" });
      }
    }
    if (node.type !== "AssignmentExpression") return;
    const segments = memberSegments(node.left);
    const readableMatch = owner === "ReadableStream"
      && JSON.stringify(segments) === JSON.stringify(["OriginalReadableStream", "prototype", member]);
    const videoMatch = owner === "VideoFrame"
      && JSON.stringify(segments) === JSON.stringify(["exactVideoFrameCtor", "prototype", member]);
    if (readableMatch || videoMatch) {
      candidates.push({
        node: parent?.type === "ExpressionStatement" ? parent : node,
        kind: readableMatch ? "compat-wrapper" : "fallback-constructor",
      });
    }
  });
  const unique = [...new Map(candidates.map((candidate) => [
    `${candidate.node.start}:${candidate.node.end}`,
    candidate,
  ])).values()];
  if (unique.length === 0) return null;
  const sites = [];
  const producerPaths = [];
  for (const [indexValue, candidate] of unique.entries()) {
    const pathSites = [
      sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${locator}.producer.${indexValue}`, range: { startByte: candidate.node.start, endByte: candidate.node.end }, text, bytes }),
      sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${locator}.publication.${indexValue}`, range: { startByte: candidate.node.start, endByte: candidate.node.end }, text, bytes }),
    ];
    sites.push(...pathSites);
    producerPaths.push({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0returned-member\0${indexValue}`),
      conditionId: `returned-member:${candidate.kind}:${candidate.node.start}`,
      requiredSiteIds: pathSites.map((site) => site.siteId),
    });
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "legacy-returned-prototype-member-route",
    targetGlobalPath: locator,
    resolutionPolicy: producerPaths.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths,
  });
}

function intlLocaleDirectionBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (sourcePath !== "packages/ibex-runtime-js/src/polyfills/intl.ts"
    || locator !== "get.direction"
    || branch?.observedKey !== "native-op:global:Intl.Locale.prototype.textInfo.direction") {
    return null;
  }
  const ast = parse(text, {
    sourceType: "module",
    plugins: ["typescript", "decorators-legacy"],
  });
  const directions = [];
  const textInfoMethods = [];
  const localePublications = [];
  const textInfoPublications = [];
  const guards = [];
  walkJavaScript(ast.program, (node, parent) => {
    if (node.type === "ObjectProperty" && propertyName(node.key) === "direction") {
      directions.push(node);
    }
    if (node.type === "ClassMethod"
      && node.kind === "get"
      && propertyName(node.key) === "textInfo") textInfoMethods.push(node);
    if (node.type === "IfStatement") {
      const testText = text.slice(node.test.start, node.test.end);
      if (testText.includes("Intl.Locale")) guards.push(node.test);
    }
    if (node.type === "CallExpression"
      && JSON.stringify(memberSegments(node.callee)) === JSON.stringify(["Object", "defineProperty"])) {
      const target = memberSegments(node.arguments[0]);
      const property = propertyName(node.arguments[1]);
      const row = parent?.type === "ExpressionStatement" ? parent : node;
      if (JSON.stringify(target) === JSON.stringify(["Intl"])
        && property === "Locale") localePublications.push(row);
      if (JSON.stringify(target) === JSON.stringify(["Intl", "Locale", "prototype"])
        && property === "textInfo") textInfoPublications.push(row);
    }
  });
  if (directions.length !== 2
    || textInfoMethods.length !== 1
    || localePublications.length !== 1
    || textInfoPublications.length !== 1
    || guards.length !== 2) return null;
  const classDirection = directions.find((node) =>
    node.start > textInfoMethods[0].start && node.end < textInfoMethods[0].end);
  const descriptorDirection = directions.find((node) =>
    node.start > textInfoPublications[0].start && node.end < textInfoPublications[0].end);
  if (!classDirection || !descriptorDirection) return null;
  const routeSpecs = [
    { kind: "polyfill-class", direction: classDirection, definition: textInfoMethods[0], publication: localePublications[0], guard: guards[0] },
    { kind: "native-prototype-extension", direction: descriptorDirection, definition: textInfoPublications[0], publication: textInfoPublications[0], guard: guards[1] },
  ];
  const sites = [];
  const producerPaths = [];
  for (const [indexValue, route] of routeSpecs.entries()) {
    const pathSites = [
      sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `Intl.Locale.textInfo.direction.${indexValue}`, range: { startByte: route.direction.start, endByte: route.direction.end }, text, bytes }),
      sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: `Intl.Locale.textInfo.definition.${indexValue}`, range: { startByte: route.definition.start, endByte: route.definition.end }, text, bytes }),
      sourceSite({ sourceRef, path: sourcePath, role: "guard", siteKey: `Intl.Locale.textInfo.guard.${indexValue}`, range: { startByte: route.guard.start, endByte: route.guard.end }, text, bytes }),
      sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `Intl.Locale.textInfo.publication.${indexValue}`, range: { startByte: route.publication.start, endByte: route.publication.end }, text, bytes }),
    ];
    sites.push(...pathSites);
    producerPaths.push({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0intl-direction\0${indexValue}`),
      conditionId: `intl-locale:${route.kind}`,
      requiredSiteIds: pathSites.map((site) => site.siteId),
    });
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "intl-locale-direction-route",
    targetGlobalPath: "Intl.Locale.prototype.textInfo.direction",
    resolutionPolicy: "conditioned-alternatives",
    sites,
    producerPaths,
  });
}

function sharedArrayBufferViewWrapperBinding({
  branch,
  sourceRef,
  sourcePath,
  locator,
  text,
  bytes,
}) {
  const locatorPrefix = "wrapSharedArrayBufferViewCtor:globals:";
  if (sourcePath !== "packages/ibex-runtime-js/src/bootstrap.ts"
    || !locator.startsWith(locatorPrefix)
    || !branch?.observedKey?.startsWith("native-op:global:")) return null;
  const constructorName = locator.slice(locatorPrefix.length);
  const observedPath = branch.observedKey.slice("native-op:global:".length);
  if (observedPath !== constructorName
    && !observedPath.startsWith(`${constructorName}.`)) return null;
  const member = observedPath === constructorName
    ? null
    : observedPath.slice(constructorName.length + 1);
  if (member?.includes(".")) return null;

  const declarationLine = uniqueTokenRange(text, [
    "    const wrapSharedArrayBufferViewCtor = (name: string) => {",
  ]);
  if (!declarationLine) return null;
  const opening = text.indexOf("{", declarationLine.startByte);
  const endByte = opening < 0 ? -1 : matchingBraceEnd(text, opening);
  if (endByte < 0) return null;
  const wrapperRange = { startByte: declarationLine.startByte, endByte };
  const selections = tokenRangesWithin(text, `'${constructorName}'`, {
    startByte: endByte,
    endByte: Math.min(text.length, endByte + 1_500),
  });
  if (selections.length !== 1) return null;
  const wrappedDefinition = uniqueTokenRange(text, [
    "      const WrappedCtor = function(this: any, buffer?: any, byteOffset?: number, length?: number) {",
  ]);
  if (!wrappedDefinition || wrappedDefinition.startByte > endByte) return null;

  const descriptorCalls = callExpressionRangesWithin(text, "Object.defineProperty", wrapperRange);
  const globalPublications = descriptorCalls.filter((range) => {
    const call = text.slice(range.startByte, range.endByte);
    return /Object\.defineProperty\(g,\s*name,/u.test(call);
  });
  const fallbackPublications = tokenRangesWithin(
    text,
    "(g as any)[name] = WrappedCtor;",
    wrapperRange,
  );
  if (globalPublications.length !== 1 || fallbackPublications.length !== 1) return null;

  let memberRange = null;
  if (member) {
    if (member === "prototype") {
      const prototypeAssignments = tokenRangesWithin(
        text,
        "WrappedCtor.prototype = NativeCtor.prototype;",
        wrapperRange,
      );
      if (prototypeAssignments.length !== 1) return null;
      memberRange = prototypeAssignments[0];
    } else {
      const expectedTarget = member === "constructor" ? "WrappedCtor.prototype" : "WrappedCtor";
      const expectedProperty = member;
      const memberCalls = descriptorCalls.filter((range) => {
        const call = text.slice(range.startByte, range.endByte);
        return call.includes(`Object.defineProperty(${expectedTarget}, '${expectedProperty}'`);
      });
      if (memberCalls.length !== 1) return null;
      memberRange = memberCalls[0];
    }
  }

  const commonSites = [
    sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${constructorName}.wrapper-selection`, range: selections[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${constructorName}.wrapped-constructor`, range: wrappedDefinition, text, bytes }),
  ];
  if (memberRange) {
    commonSites.push(sourceSite({
      sourceRef,
      path: sourcePath,
      role: "registration",
      siteKey: `${constructorName}.${member}.descriptor`,
      range: memberRange,
      text,
      bytes,
    }));
  }
  const descriptorPublication = sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${constructorName}.descriptor-publication`, range: globalPublications[0], text, bytes });
  const fallbackPublication = sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${constructorName}.assignment-publication`, range: fallbackPublications[0], text, bytes });
  const commonSiteIds = commonSites.map((site) => site.siteId);
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "typescript-shared-view-wrapper-route",
    targetGlobalPath: observedPath,
    resolutionPolicy: "conditioned-alternatives",
    sites: [...commonSites, descriptorPublication, fallbackPublication],
    producerPaths: [
      {
        pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0shared-view-descriptor`),
        conditionId: "shared-view-wrapper:define-property-succeeds",
        requiredSiteIds: [...commonSiteIds, descriptorPublication.siteId],
      },
      {
        pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0shared-view-fallback`),
        conditionId: "shared-view-wrapper:define-property-throws",
        requiredSiteIds: [...commonSiteIds, fallbackPublication.siteId],
      },
    ],
  });
}

function typedArraySubarrayRouteBinding({
  branch,
  sourceRef,
  sourcePath,
  locator,
  text,
  bytes,
}) {
  const prefix = "installTypedArrayPolyfills:globals:";
  if (sourcePath !== "packages/ibex-runtime-js/src/polyfills/typedarray.ts"
    || !locator.startsWith(prefix)
    || !branch?.observedKey?.startsWith("native-op:global:")) return null;
  const installedPath = locator.slice(prefix.length);
  const match = /^([A-Za-z0-9_$]+)\.prototype\.subarray$/u.exec(installedPath);
  if (!match) return null;
  const constructorName = match[1];
  const observedPath = branch.observedKey.slice("native-op:global:".length);
  if (observedPath !== installedPath
    && observedPath !== `${installedPath}.__exactZeroLengthWrapped`) return null;
  const installer = robustFunctionDeclarationRange(text, "installTypedArrayPolyfills");
  if (!installer) return null;
  const selections = tokenRangesWithin(text, `'${constructorName}'`, installer);
  const retention = uniqueTokenRange(text, [
    "    const originalSubarray = TypedArrayCtor.prototype.subarray as typeof Uint8Array.prototype.subarray & {",
  ]);
  const patchedDefinition = uniqueTokenRange(text, [
    "    const patchedSubarray = function (",
  ]);
  const descriptorCalls = callExpressionRangesWithin(text, "Object.defineProperty", installer);
  const markerPublications = descriptorCalls.filter((range) =>
    text.slice(range.startByte, range.endByte)
      .includes("Object.defineProperty(patchedSubarray, '__exactZeroLengthWrapped'"));
  const subarrayPublications = descriptorCalls.filter((range) =>
    text.slice(range.startByte, range.endByte)
      .includes("Object.defineProperty(TypedArrayCtor.prototype, 'subarray'"));
  if (selections.length !== 1
    || !retention
    || !patchedDefinition
    || markerPublications.length !== 1
    || subarrayPublications.length !== 1) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${constructorName}.typed-array-selection`, range: selections[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "retention", siteKey: `${constructorName}.original-subarray`, range: retention, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${constructorName}.patched-subarray`, range: patchedDefinition, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${constructorName}.subarray-publication`, range: subarrayPublications[0], text, bytes }),
  ];
  if (observedPath.endsWith(".__exactZeroLengthWrapped")) {
    sites.splice(3, 0, sourceSite({
      sourceRef,
      path: sourcePath,
      role: "registration",
      siteKey: `${constructorName}.zero-length-marker`,
      range: markerPublications[0],
      text,
      bytes,
    }));
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "typescript-typed-array-subarray-route",
    targetGlobalPath: observedPath,
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0typed-array-subarray`),
      conditionId: `typed-array-constructor:${constructorName}:available-and-unpatched`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function legacyJavascriptGlobalRouteBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("native-op:global:")
    || !sourcePath.startsWith("src/engine/bootstrap/")
    || !sourcePath.endsWith(".js")
    || locator.includes(":")
    || locator.includes("[[")
    || locator.startsWith("<")) return null;
  const logicalPath = locator.split(".");
  if (branch.observedKey.slice("native-op:global:".length) !== locator) return null;
  const candidates = [];
  const ast = parse(text, { sourceType: "script", allowReturnOutsideFunction: true });
  const normalize = (segments) => {
    if (!segments) return null;
    return ["globalThis", "__global", "g", "self", "window"].includes(segments[0])
      ? segments.slice(1)
      : segments;
  };
  walkJavaScript(ast.program, (node, parent) => {
    if (node.type === "AssignmentExpression"
      && JSON.stringify(normalize(memberSegments(node.left))) === JSON.stringify(logicalPath)) {
      candidates.push({
        producer: node.right,
        publication: parent?.type === "ExpressionStatement" ? parent : node,
      });
    }
    if (node.type === "CallExpression"
      && JSON.stringify(memberSegments(node.callee)) === JSON.stringify(["Object", "defineProperty"])) {
      const target = normalize(memberSegments(node.arguments[0]));
      const property = propertyName(node.arguments[1]);
      if (property !== null
        && JSON.stringify([...(target ?? []), property]) === JSON.stringify(logicalPath)) {
        candidates.push({
          producer: node.arguments[2] ?? node,
          publication: parent?.type === "ExpressionStatement" ? parent : node,
        });
      }
    }
  });
  const unique = [...new Map(candidates.map((candidate) => [
    `${candidate.publication.start}:${candidate.publication.end}`,
    candidate,
  ])).values()];
  if (unique.length === 0) return null;
  const sites = [];
  const producerPaths = [];
  for (const [indexValue, candidate] of unique.entries()) {
    const producer = sourceSite({
      sourceRef,
      path: sourcePath,
      role: "value-producer",
      siteKey: `${locator}.producer.${indexValue}`,
      range: { startByte: candidate.producer.start, endByte: candidate.producer.end },
      text,
      bytes,
    });
    const publication = sourceSite({
      sourceRef,
      path: sourcePath,
      role: "publication",
      siteKey: `${locator}.publication.${indexValue}`,
      range: { startByte: candidate.publication.start, endByte: candidate.publication.end },
      text,
      bytes,
    });
    sites.push(producer, publication);
    producerPaths.push({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0legacy-global\0${indexValue}`),
      conditionId: `legacy-bootstrap:${sourcePath}:${candidate.publication.start}`,
      requiredSiteIds: [producer.siteId, publication.siteId],
    });
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "javascript-global-assignment-route",
    resolutionPolicy: producerPaths.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths,
  });
}

function legacyJavascriptTerminalRouteBinding({
  branch,
  sourceRef,
  sourcePath,
  locator,
  text,
  bytes,
}) {
  if (!branch?.observedKey?.startsWith("native-op:")
    || !sourcePath.startsWith("src/engine/bootstrap/")
    || !sourcePath.endsWith(".js")
    || locator.includes(":")
    || locator.includes("[[")
    || locator.startsWith("<")) return null;
  const observedPath = branch.observedKey.startsWith("native-op:global:")
    ? branch.observedKey.slice("native-op:global:".length)
    : branch.observedKey.slice("native-op:".length);
  if (observedPath !== locator) return null;
  const logicalPath = locator.split(".");
  if (logicalPath.some((part) => !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(part))) return null;
  const normalize = (segments) => {
    if (!segments) return null;
    return ["globalThis", "__global", "g", "self", "window"].includes(segments[0])
      ? segments.slice(1)
      : segments;
  };
  const candidates = [];
  const ast = parse(text, { sourceType: "script", allowReturnOutsideFunction: true });
  walkJavaScript(ast.program, (node, parent) => {
    const segments = normalize(memberSegments(node));
    const exactMember = segments
      && JSON.stringify(segments) === JSON.stringify(logicalPath);
    const exactIdentifier = logicalPath.length === 1
      && node.type === "Identifier"
      && node.name === logicalPath[0]
      && parent?.type !== "MemberExpression";
    if (!exactMember && !exactIdentifier) return;
    const range = { startByte: node.start, endByte: node.end };
    const statement = lineRange(text, node.start);
    const publication = parent?.type === "AssignmentExpression" && parent.left === node;
    candidates.push({ range, statement, publication });
  });
  const unique = [...new Map(candidates.map((candidate) => [
    `${candidate.range.startByte}:${candidate.range.endByte}`,
    candidate,
  ])).values()];
  if (unique.length === 0) return null;
  const sites = [];
  const producerPaths = [];
  for (const [indexValue, candidate] of unique.entries()) {
    const targetSite = sourceSite({
      sourceRef,
      path: sourcePath,
      role: "value-producer",
      siteKey: `${locator}.terminal.${indexValue}`,
      range: candidate.range,
      text,
      bytes,
    });
    const executionSite = sourceSite({
      sourceRef,
      path: sourcePath,
      role: candidate.publication ? "publication" : "dispatch",
      siteKey: `${locator}.execution.${indexValue}`,
      range: candidate.statement,
      text,
      bytes,
    });
    sites.push(targetSite, executionSite);
    producerPaths.push({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0legacy-terminal\0${indexValue}`),
      conditionId: `legacy-source-site:${sourcePath}:${candidate.range.startByte}`,
      requiredSiteIds: [targetSite.siteId, executionSite.siteId],
    });
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "javascript-terminal-route",
    targetGlobalPath: branch.observedKey.startsWith("native-op:global:") ? observedPath : undefined,
    resolutionPolicy: producerPaths.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths,
  });
}

function legacyJavascriptAliasRouteBinding({
  branch,
  sourceRef,
  sourcePath,
  locator,
  text,
  bytes,
}) {
  if (!branch?.observedKey?.startsWith("native-op:global:")
    || !sourcePath.startsWith("src/engine/bootstrap/")
    || !sourcePath.endsWith(".js")
    || locator.includes(":")
    || locator.includes("[[")) return null;
  const observedPath = branch.observedKey.slice("native-op:global:".length);
  if (observedPath !== locator) return null;
  const logicalPath = locator.split(".");
  if (logicalPath.length < 2) return null;
  const normalize = (segments) => {
    if (!segments) return null;
    return ["globalThis", "__global", "g", "self", "window"].includes(segments[0])
      ? segments.slice(1)
      : segments;
  };
  const ast = parse(text, { sourceType: "script", allowReturnOutsideFunction: true });
  const aliases = [];
  walkJavaScript(ast.program, (node) => {
    let alias = null;
    let value = null;
    let range = null;
    if (node.type === "VariableDeclarator" && node.id?.type === "Identifier") {
      alias = node.id.name;
      value = normalize(memberSegments(node.init));
      range = { startByte: node.start, endByte: node.end };
    } else if (node.type === "AssignmentExpression" && node.left?.type === "Identifier") {
      alias = node.left.name;
      value = normalize(memberSegments(node.right));
      range = { startByte: node.start, endByte: node.end };
    }
    if (!alias || !value || value.length >= logicalPath.length) return;
    if (JSON.stringify(value) !== JSON.stringify(logicalPath.slice(0, value.length))) return;
    aliases.push({ alias, value, range });
  });
  const candidates = [];
  walkJavaScript(ast.program, (node, parent) => {
    const segments = memberSegments(node);
    if (!segments || segments.length < 2) return;
    for (const alias of aliases) {
      const remaining = logicalPath.slice(alias.value.length);
      if (alias.range.endByte >= node.start
        || JSON.stringify(segments) !== JSON.stringify([alias.alias, ...remaining])) continue;
      const laterAlias = aliases.some((candidate) =>
        candidate.alias === alias.alias
        && candidate.range.startByte > alias.range.startByte
        && candidate.range.startByte < node.start);
      if (laterAlias) continue;
      candidates.push({
        alias,
        terminal: { startByte: node.start, endByte: node.end },
        statement: lineRange(text, node.start),
        publication: parent?.type === "AssignmentExpression" && parent.left === node,
      });
    }
  });
  const unique = [...new Map(candidates.map((candidate) => [
    `${candidate.alias.range.startByte}:${candidate.terminal.startByte}:${candidate.terminal.endByte}`,
    candidate,
  ])).values()];
  if (unique.length === 0) return null;
  const sites = [];
  const producerPaths = [];
  for (const [indexValue, candidate] of unique.entries()) {
    const aliasSite = sourceSite({ sourceRef, path: sourcePath, role: "retention", siteKey: `${locator}.alias.${indexValue}`, range: candidate.alias.range, text, bytes });
    const terminalSite = sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${locator}.terminal.${indexValue}`, range: candidate.terminal, text, bytes });
    const executionSite = sourceSite({ sourceRef, path: sourcePath, role: candidate.publication ? "publication" : "dispatch", siteKey: `${locator}.execution.${indexValue}`, range: candidate.statement, text, bytes });
    sites.push(aliasSite, terminalSite, executionSite);
    producerPaths.push({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0legacy-alias\0${indexValue}`),
      conditionId: `legacy-alias-site:${sourcePath}:${candidate.terminal.startByte}`,
      requiredSiteIds: [aliasSite.siteId, terminalSite.siteId, executionSite.siteId],
    });
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "javascript-alias-terminal-route",
    targetGlobalPath: observedPath,
    resolutionPolicy: producerPaths.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths,
  });
}

function legacyStdioLazyMethodBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (sourcePath !== "src/engine/bootstrap/lazy-getters.js"
    || branch?.observedKey !== `native-op:global:${locator}`) return null;
  const match = /^process\.(stdin|stdout|stderr)\.([A-Za-z_$][A-Za-z0-9_$]*)$/u.exec(locator);
  if (!match) return null;
  const [, streamName, methodName] = match;
  const allowedMethods = new Set([
    "on", "once", "pipe", "cork", "uncork", "end", "write",
    "addListener", "removeListener", "emit",
  ]);
  if (!allowedMethods.has(methodName)) return null;
  const streamEntries = tokenRangesWithin(
    text,
    `'${streamName}'`,
    { startByte: 0, endByte: text.length },
  );
  const methodEntries = tokenRangesWithin(
    text,
    `'${methodName}'`,
    { startByte: 0, endByte: text.length },
  );
  const processCapture = uniqueTokenRange(text, ["  var p = globalThis.process;"]);
  const streamCapture = uniqueTokenRange(text, ["      var stream = p[streams[si]];"]);
  const stubDefinition = uniqueTokenRange(text, ["            var stub = function() {"]);
  const publication = uniqueTokenRange(text, ["            s[method] = stub;"]);
  const dispatch = uniqueTokenRange(text, [
    "        })(stream, streams[si], methods[mi]);",
  ]);
  if (streamEntries.length !== 1
    || methodEntries.length !== 1
    || !processCapture
    || !streamCapture
    || !stubDefinition
    || !publication
    || !dispatch) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${streamName}.stream-entry`, range: streamEntries[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${methodName}.method-entry`, range: methodEntries[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "retention", siteKey: "process.capture", range: processCapture, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "retention", siteKey: `${streamName}.capture`, range: streamCapture, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${streamName}.${methodName}.stub`, range: stubDefinition, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: `${streamName}.${methodName}.loop-dispatch`, range: dispatch, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${streamName}.${methodName}.publication`, range: publication, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "javascript-stdio-lazy-method-route",
    targetGlobalPath: locator,
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0stdio-lazy-method`),
      conditionId: `stdio-lazy-table:${streamName}:${methodName}:missing`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function exactGlobalAliasBinding({ branch, sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (sourcePath !== "src/engine/bootstrap/exact-global.js"
    || !/^native-op:global:(?:Bun|Exact)(?:\.|$)/u.test(branch?.observedKey ?? "")
    || branch.observedKey.slice("native-op:global:".length) !== locator
    || !/^(?:Bun|Exact)(?:\.|$)/u.test(locator)) return null;
  const publishedRoot = locator.split(".")[0];
  const ast = parse(text, { sourceType: "script", allowReturnOutsideFunction: true });
  const index = javascriptIndex(absolute, text);
  const assignments = [];
  walkJavaScript(ast.program, (node, parent) => {
    if (node.type === "AssignmentExpression") {
      assignments.push({
        node,
        parent: parent?.type === "ExpressionStatement" ? parent : node,
        segments: memberSegments(node.left),
        value: node.right,
      });
    }
  });
  const aliasPublications = assignments.filter(({ segments, value }) =>
    JSON.stringify(segments) === JSON.stringify(["g", publishedRoot])
    && value?.type === "Identifier"
    && value.name === "E");
  if (aliasPublications.length !== 1) return null;
  const tail = locator === publishedRoot ? [] : locator.slice(publishedRoot.length + 1).split(".");
  let producer;
  let rootAssignment;
  if (tail.length === 0) {
    producer = aliasPublications[0];
  } else {
    const exact = assignments.filter(({ segments }) =>
      JSON.stringify(segments) === JSON.stringify(["E", ...tail]));
    if (exact.length === 1) {
      producer = exact[0];
      rootAssignment = exact[0];
    } else {
      const roots = assignments.filter(({ segments }) =>
        JSON.stringify(segments) === JSON.stringify(["E", tail[0]]));
      if (roots.length !== 1) return null;
      rootAssignment = roots[0];
      if (rootAssignment.value?.type === "ObjectExpression") {
        let current = rootAssignment.value;
        let property;
        for (const part of tail.slice(1)) {
          property = objectProperty(current, part);
          if (!property) return null;
          current = property.type === "ObjectProperty" ? property.value : property;
        }
        if (!property) return null;
        producer = {
          node: property,
          parent: property,
          segments: ["E", ...tail],
          value: current,
        };
      }
      if (producer) {
        // The object-literal member is already tied to its Exact root below.
      } else {
        let factory;
        if (rootAssignment.value?.type === "CallExpression") {
          if (["FunctionExpression", "ArrowFunctionExpression"].includes(rootAssignment.value.callee?.type)) {
            factory = rootAssignment.value.callee;
          } else if (rootAssignment.value.callee?.type === "Identifier") {
            const declaration = declarationFor(index, rootAssignment.value.callee.name);
            factory = declaration?.value ?? declaration?.node;
          }
        }
        if (!factory || !["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(factory.type)) {
          return null;
        }
        const returned = factory.body?.type === "BlockStatement"
          ? factory.body.body
            .filter((node) => node.type === "ReturnStatement" && node.argument?.type === "Identifier")
            .map((node) => node.argument.name)
          : factory.body?.type === "Identifier"
            ? [factory.body.name]
            : [];
        if (new Set(returned).size !== 1) return null;
        const alias = returned[0];
        if (tail.length === 2 && tail[1] === "prototype") {
          producer = rootAssignment;
        }
        const members = assignments.filter(({ segments }) =>
          JSON.stringify(segments) === JSON.stringify([alias, ...tail.slice(1)])
          || JSON.stringify(segments) === JSON.stringify([alias, "prototype", ...tail.slice(1)]));
        if (!producer) {
          if (members.length !== 1) return null;
          producer = members[0];
        }
      }
    }
  }
  const ranges = [
    { role: "value-producer", key: `${locator}.producer`, row: producer },
    ...(rootAssignment && rootAssignment !== producer
      ? [{ role: "alias", key: `${locator}.constructor-alias`, row: rootAssignment }]
      : []),
    { role: "publication", key: `${publishedRoot}.Exact.alias`, row: aliasPublications[0] },
  ];
  const sites = ranges.map(({ role, key, row }) => sourceSite({
    sourceRef,
    path: sourcePath,
    role,
    siteKey: key,
    range: { startByte: row.parent.start, endByte: row.parent.end },
    text,
    bytes,
  }));
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "exact-global-alias-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0exact-bun-alias`),
      conditionId: publishedRoot === "Bun"
        ? "runtime-compat:bun"
        : `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function evaluatedCppGlobalBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("native-op:")
    || !/\.(?:cc|mm)$/u.test(sourcePath)
    || !locator.startsWith("embedded:")) return null;
  const match = /^embedded:([^:]+):(.+)$/u.exec(locator);
  if (!match) return null;
  const [, variable, logicalName] = match;
  const observedName = branch.observedKey.startsWith("native-op:global:")
    ? branch.observedKey.slice("native-op:global:".length)
    : branch.observedKey.slice("native-op:".length);
  if (observedName !== logicalName) return null;
  const declarationPattern = new RegExp(`\\b${escapeRegExp(variable)}\\b\\s*=\\s*R\"([A-Za-z0-9_]*)\\(`, "gu");
  const declarations = [...text.matchAll(declarationPattern)];
  if (declarations.length !== 1) return null;
  const declaration = declarations[0];
  const delimiter = declaration[1];
  const scriptStart = declaration.index + declaration[0].length;
  const scriptEnd = text.indexOf(`)${delimiter}\"`, scriptStart);
  if (scriptEnd < scriptStart) return null;
  const script = text.slice(scriptStart, scriptEnd);
  const bufferPattern = new RegExp(`StringBuffer>\\(${escapeRegExp(variable)}\\)`, "gu");
  const buffers = [...text.matchAll(bufferPattern)].filter((row) => row.index > scriptEnd);
  if (buffers.length !== 1) return null;
  const dispatchSearchEnd = Math.min(text.length, buffers[0].index + 1_000);
  let dispatchOffset = text.indexOf("evaluateJavaScript(buffer", buffers[0].index);
  if (dispatchOffset < 0 || dispatchOffset >= dispatchSearchEnd) {
    const direct = text.lastIndexOf("evaluateJavaScript(", buffers[0].index);
    dispatchOffset = direct >= 0 && buffers[0].index - direct < 300 ? direct : -1;
  }
  if (dispatchOffset < 0) return null;
  const dispatchStart = text.lastIndexOf("\n", Math.min(dispatchOffset, buffers[0].index)) + 1;
  const dispatchSemicolon = text.indexOf(";", Math.max(dispatchOffset, buffers[0].index));
  const dispatchRange = {
    startByte: dispatchStart,
    endByte: dispatchSemicolon >= 0 && dispatchSemicolon < dispatchSearchEnd
      ? dispatchSemicolon + 1
      : lineRange(text, Math.max(dispatchOffset, buffers[0].index)).endByte,
  };
  const logicalPath = logicalName.split(".");
  const ast = parse(script, { sourceType: "script", allowReturnOutsideFunction: true });
  const aliases = new Map();
  walkJavaScript(ast.program, (node) => {
    if (node.type !== "VariableDeclarator" || node.id?.type !== "Identifier") return;
    const segments = memberSegments(node.init);
    if (segments?.length === 2 && ["globalThis", "g", "self", "window"].includes(segments[0])) {
      aliases.set(node.id.name, segments[1]);
    }
  });
  const normalize = (segments) => {
    if (!segments) return null;
    const normalized = ["globalThis", "g", "self", "window"].includes(segments[0])
      ? segments.slice(1)
      : segments;
    return aliases.has(normalized[0])
      ? [aliases.get(normalized[0]), ...normalized.slice(1)]
      : normalized;
  };
  const rootAssignments = [];
  const exactAssignments = [];
  const leafCandidates = [];
  walkJavaScript(ast.program, (node, parent) => {
    if (node.type === "AssignmentExpression") {
      const segments = normalize(memberSegments(node.left));
      const publicSegments = segments?.filter((part) => part !== "prototype");
      const row = { node, parent: parent?.type === "ExpressionStatement" ? parent : node, value: node.right };
      if (JSON.stringify(segments) === JSON.stringify([logicalPath[0]])) rootAssignments.push(row);
      if (JSON.stringify(segments) === JSON.stringify(logicalPath)
        || JSON.stringify(publicSegments) === JSON.stringify(logicalPath)) exactAssignments.push(row);
    }
    if (node.type === "CallExpression"
      && JSON.stringify(memberSegments(node.callee)) === JSON.stringify(["Object", "defineProperty"])) {
      const property = propertyName(node.arguments[1]);
      const segments = property === null
        ? null
        : [...(normalize(memberSegments(node.arguments[0])) ?? []), property];
      const publicSegments = segments?.filter((part) => part !== "prototype");
      const row = {
        node,
        parent: parent?.type === "ExpressionStatement" ? parent : node,
        value: node.arguments[2] ?? node,
      };
      if (JSON.stringify(segments) === JSON.stringify([logicalPath[0]])) rootAssignments.push(row);
      if (JSON.stringify(segments) === JSON.stringify(logicalPath)
        || JSON.stringify(publicSegments) === JSON.stringify(logicalPath)) exactAssignments.push(row);
    }
    if (["ObjectMethod", "ObjectProperty", "ClassMethod", "ClassProperty"].includes(node.type)
      && propertyName(node.key) === logicalPath.at(-1)) leafCandidates.push(node);
  });
  let producer;
  let publication;
  if (exactAssignments.length === 1) {
    producer = exactAssignments[0].value;
    publication = exactAssignments[0].parent;
  } else if (rootAssignments.length === 1 && logicalPath.length > 1) {
    let current = rootAssignments[0].value;
    let property;
    for (const part of logicalPath.slice(1)) {
      property = objectProperty(current, part);
      if (!property) break;
      current = property.type === "ObjectProperty" ? property.value : property;
    }
    if (property) {
      producer = property;
      publication = rootAssignments[0].parent;
    } else if (leafCandidates.length === 1) {
      producer = leafCandidates[0];
      publication = rootAssignments[0].parent;
    }
  }
  if (!producer || !publication) return null;
  const embeddedRange = (node) => ({
    startByte: scriptStart + node.start,
    endByte: scriptStart + node.end,
  });
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${logicalName}.embedded-producer`, range: embeddedRange(producer), text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${logicalName}.embedded-publication`, range: embeddedRange(publication), text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: `${variable}.evaluate`, range: dispatchRange, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "evaluated-cpp-global-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0evaluated-cpp`),
      conditionId: `target-branch:${branch.targetVariant}:embedded:${variable}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function nativeDefinitionBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("native-op:")
    || !/\.(?:cc|mm|h)$/u.test(sourcePath)
    || !locator.startsWith("definition:")) return null;
  const symbol = locator.slice("definition:".length);
  if (branch.observedKey.slice("native-op:".length) !== symbol) return null;
  const definition = robustFunctionDeclarationRange(text, symbol);
  if (!definition) return null;
  const definitionText = text.slice(definition.startByte, definition.endByte);
  if (!/\bextern\s+"C"/u.test(definitionText)) return null;
  const producer = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "value-producer",
    siteKey: `${symbol}.native-definition`,
    range: definition,
    text,
    bytes,
  });
  const publication = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "publication",
    siteKey: `${symbol}.extern-c-publication`,
    range: definition,
    text,
    bytes,
  });
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "native-operation-definition",
    resolutionPolicy: "composite-path",
    sites: [producer, publication],
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0native-definition`),
      conditionId: `target-branch:${branch.targetVariant}:definition:${sourcePath}`,
      requiredSiteIds: [producer.siteId, publication.siteId],
    }],
  });
}

function inspectorCdpRouteBinding({
  branch,
  sourceRef,
  sourcePath,
  locator,
  absolute,
  text,
  bytes,
}) {
  if (!branch?.observedKey?.startsWith("native-op:inspector.")
    || sourcePath !== "src/bin/ibex/cdp/mod.rs") return null;
  const handlerName = locator.split(":")[0];
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(handlerName)) return null;
  const handler = rustFunctionRange(text, handlerName);
  const exact = resolveRange(sourcePath, locator, text, absolute);
  if (!handler || !exact) return null;
  const branchSite = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "registration",
    siteKey: `${locator}.request-branch`,
    range: exact,
    text,
    bytes,
  });
  const dispatchSite = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "dispatch",
    siteKey: `${handlerName}.handler-dispatch`,
    range: handler,
    text,
    bytes,
  });
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "inspector-cdp-handler-route",
    resolutionPolicy: "composite-path",
    sites: [branchSite, dispatchSite],
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0cdp-handler`),
      conditionId: `inspector-route:${locator}`,
      requiredSiteIds: [branchSite.siteId, dispatchSite.siteId],
    }],
  });
}

function inspectorDebuggerExportBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("native-op:inspector.debugger-")
    || ![
      "src/engine/hermes_runtime_debugger.cc",
      "src/engine/hermes_runtime_platform_windows.cc",
    ].includes(sourcePath)
    || !locator.startsWith("ex_hermes_debugger_")) return null;
  const definition = robustFunctionDeclarationRange(text, locator);
  if (!definition || !/\bextern\s+"C"/u.test(
    text.slice(definition.startByte, Math.min(definition.endByte, definition.startByte + 500)),
  )) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${locator}.definition`, range: definition, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${locator}.export`, range: definition, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "inspector-native-export-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0debugger-export`),
      conditionId: sourcePath.endsWith("_windows.cc")
        ? "target-platform:windows"
        : "target-platform:not-windows",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function preprocessorBranchBinding({ sourceRef, sourcePath, locator, text, bytes }) {
  if (!/\.(?:cc|mm|h)$/u.test(sourcePath) || !locator.startsWith("preprocessor:")) return null;
  const [, macro, expected] = locator.split(":");
  if (!macro || !expected) return null;
  const directives = [];
  let offset = 0;
  for (const line of text.split(/(?<=\n)/u)) {
    const content = line.endsWith("\n") ? line.slice(0, -1) : line;
    if (/^\s*#\s*(?:if|ifdef|ifndef|elif)\b/u.test(content) && content.includes(macro)) {
      directives.push({ startByte: offset, endByte: offset + content.length });
    }
    offset += line.length;
  }
  if (directives.length === 0) return null;
  const sites = directives.map((range, indexValue) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "branch-selector",
    siteKey: `${macro}.${expected}.${indexValue}`,
    range,
    text,
    bytes,
  }));
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "preprocessor-branch-provenance",
    resolutionPolicy: "provenance-only",
    sites,
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

function prototypeOwners(node) {
  if (!node) return [];
  if (node.type === "Identifier") return [node.name];
  if (node.type === "LogicalExpression" || node.type === "ConditionalExpression") {
    return [...new Set([
      ...prototypeOwners(node.left ?? node.consequent),
      ...prototypeOwners(node.right ?? node.alternate),
    ])];
  }
  if (node.type === "MemberExpression" && propertyName(node.property) === "prototype") {
    const segments = memberSegments(node.object);
    return segments ? [segments.join(".")] : prototypeOwners(node.object);
  }
  return [];
}

function prototypeLinks(absolute, text, index) {
  const cached = prototypeLinkCache.get(absolute);
  if (cached) return cached;
  const links = new Map();
  const add = (owner, base, node, kind) => {
    if (!owner || !base || owner === base || node?.start === undefined || node?.end === undefined) return;
    const rows = links.get(owner) ?? [];
    rows.push({ base, node, kind });
    links.set(owner, rows);
  };
  walkJavaScript(parse(text, { sourceType: "script", allowReturnOutsideFunction: true }).program, (node, parent) => {
    if (node.type === "ClassDeclaration" && node.id?.name && node.superClass) {
      for (const base of prototypeOwners(node.superClass)) add(node.id.name, base, node, "class-extends");
    }
    if (node.type === "AssignmentExpression") {
      const left = memberSegments(node.left);
      const create = node.right?.type === "CallExpression"
        && JSON.stringify(memberSegments(node.right.callee)) === JSON.stringify(["Object", "create"]);
      if (left?.length === 2 && left[1] === "prototype" && create) {
        for (const base of prototypeOwners(node.right.arguments[0])) {
          add(left[0], base, parent?.type === "ExpressionStatement" ? parent : node, "object-create");
        }
      }
      if (
        node.left?.type === "MemberExpression"
        && node.left.computed
        && node.right?.type === "MemberExpression"
        && node.right.computed
        && propertyName(node.left.property) === propertyName(node.right.property)
      ) {
        const target = memberSegments(node.left.object);
        const source = memberSegments(node.right.object);
        if (target?.length === 2 && target[1] === "prototype" && source?.length === 1) {
          add(target[0], source[0], parent?.type === "ExpressionStatement" ? parent : node, "computed-copy");
        }
      }
    }
    if (node.type === "CallExpression") {
      const callee = memberSegments(node.callee);
      if (JSON.stringify(callee) === JSON.stringify(["Object", "setPrototypeOf"])) {
        const target = memberSegments(node.arguments[0]);
        if (target?.length === 2 && target[1] === "prototype") {
          for (const base of prototypeOwners(node.arguments[1])) {
            add(target[0], base, parent?.type === "ExpressionStatement" ? parent : node, "set-prototype");
          }
        }
      } else if (callee?.at(-1) === "inherits") {
        const owner = memberSegments(node.arguments[0]);
        const base = memberSegments(node.arguments[1]);
        if (owner?.length === 1 && base?.length === 1) {
          add(owner[0], base[0], parent?.type === "ExpressionStatement" ? parent : node, "inherits-call");
        }
      } else if (propertyName(node.callee?.property) === "forEach") {
        const namesCall = node.callee.object;
        const namesCallee = namesCall?.type === "CallExpression"
          ? memberSegments(namesCall.callee)
          : null;
        const baseSegments = namesCall?.type === "CallExpression"
          ? memberSegments(namesCall.arguments[0])
          : null;
        const callback = node.arguments[0];
        const keyName = callback?.params?.[0]?.type === "Identifier"
          ? callback.params[0].name
          : null;
        if (
          JSON.stringify(namesCallee) === JSON.stringify(["Object", "getOwnPropertyNames"])
          && baseSegments?.length === 2
          && baseSegments[1] === "prototype"
          && keyName
          && ["FunctionExpression", "ArrowFunctionExpression"].includes(callback?.type)
          && hasStableFunctionParameters(callback, [keyName])
        ) {
          const isDescriptorRead = (candidate) =>
            candidate?.type === "CallExpression"
            && JSON.stringify(memberSegments(candidate.callee))
              === JSON.stringify(["Object", "getOwnPropertyDescriptor"])
            && JSON.stringify(memberSegments(candidate.arguments[0]))
              === JSON.stringify(baseSegments)
            && candidate.arguments[1]?.type === "Identifier"
            && candidate.arguments[1].name === keyName;
          const descriptorDeclarations = new Map();
          const descriptorWrites = new Set();
          walkOwnedFunction(callback, (candidate) => {
            let declaredNames = [];
            if (candidate.type === "VariableDeclarator") {
              declaredNames = bindingPatternNames(candidate.id);
            } else if (candidate.type === "CatchClause") {
              declaredNames = bindingPatternNames(candidate.param);
            } else if (["FunctionDeclaration", "ClassDeclaration"].includes(candidate.type)) {
              declaredNames = bindingPatternNames(candidate.id);
            }
            for (const name of declaredNames) {
              const rows = descriptorDeclarations.get(name) ?? [];
              rows.push(candidate);
              descriptorDeclarations.set(name, rows);
            }
            if (candidate.type === "AssignmentExpression") {
              for (const name of bindingPatternNames(candidate.left)) descriptorWrites.add(name);
            }
            if (candidate.type === "UpdateExpression") {
              for (const name of bindingPatternNames(candidate.argument)) descriptorWrites.add(name);
            }
            if (
              ["ForInStatement", "ForOfStatement"].includes(candidate.type)
              && candidate.left?.type !== "VariableDeclaration"
            ) {
              for (const name of bindingPatternNames(candidate.left)) descriptorWrites.add(name);
            }
          });
          const isStableDescriptorBinding = (name) => {
            const declarations = descriptorDeclarations.get(name) ?? [];
            return declarations.length === 1
              && declarations[0].type === "VariableDeclarator"
              && isDescriptorRead(declarations[0].init)
              && !descriptorWrites.has(name);
          };
          const copiedOwners = new Set();
          walkOwnedFunction(callback, (candidate) => {
            if (candidate.type !== "CallExpression") return;
            const candidateCallee = memberSegments(candidate.callee);
            if (
              JSON.stringify(candidateCallee) === JSON.stringify(["Object", "defineProperty"])
              && candidate.arguments[1]?.type === "Identifier"
              && candidate.arguments[1].name === keyName
              && (
                isDescriptorRead(candidate.arguments[2])
                || (candidate.arguments[2]?.type === "Identifier"
                  && isStableDescriptorBinding(candidate.arguments[2].name))
              )
            ) {
              const target = memberSegments(candidate.arguments[0]);
              if (target?.length === 2 && target[1] === "prototype") copiedOwners.add(target[0]);
            }
          });
          for (const owner of copiedOwners) {
            add(owner, baseSegments[0], parent?.type === "ExpressionStatement" ? parent : node, "prototype-property-copy");
          }
        }
      }
    }
  });
  for (const [owner, rows] of links) {
    links.set(owner, [...new Map(rows.map((row) => [
      `${row.base}:${row.node.start}:${row.node.end}`,
      row,
    ])).values()]);
  }
  prototypeLinkCache.set(absolute, links);
  return links;
}

function walkOwnedFunction(node, visitor, root = node) {
  if (!node || typeof node !== "object") return;
  if (typeof node.type === "string") visitor(node);
  if (
    node !== root
    && ["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression", "ObjectMethod", "ClassMethod"]
      .includes(node.type)
  ) return;
  for (const [key, value] of Object.entries(node)) {
    if (["loc", "tokens", "comments", "errors"].includes(key)) continue;
    if (Array.isArray(value)) {
      for (const child of value) walkOwnedFunction(child, visitor, root);
    } else if (value && typeof value === "object" && typeof value.type === "string") {
      walkOwnedFunction(value, visitor, root);
    }
  }
}

function bindingPatternNames(pattern) {
  if (!pattern) return [];
  if (pattern.type === "Identifier") return [pattern.name];
  if (pattern.type === "AssignmentPattern") return bindingPatternNames(pattern.left);
  if (pattern.type === "RestElement") return bindingPatternNames(pattern.argument);
  if (pattern.type === "ArrayPattern") {
    return pattern.elements.flatMap((element) => bindingPatternNames(element));
  }
  if (pattern.type === "ObjectPattern") {
    return pattern.properties.flatMap((property) => bindingPatternNames(
      property.type === "RestElement" ? property.argument : property.value,
    ));
  }
  return [];
}

function hasStableFunctionParameters(helper, parameterNames) {
  const protectedNames = new Set(parameterNames);
  if (protectedNames.size !== parameterNames.length) return false;
  let stable = true;
  walkOwnedFunction(helper, (node) => {
    if (!stable) return;
    let declared = [];
    if (node.type === "VariableDeclarator") declared = bindingPatternNames(node.id);
    if (node.type === "CatchClause") declared = bindingPatternNames(node.param);
    if (node !== helper && ["FunctionDeclaration", "ClassDeclaration"].includes(node.type)) {
      declared = bindingPatternNames(node.id);
    }
    if (declared.some((name) => protectedNames.has(name))) {
      stable = false;
      return;
    }
    if (
      node.type === "AssignmentExpression"
      && bindingPatternNames(node.left).some((name) => protectedNames.has(name))
    ) stable = false;
    if (
      node.type === "UpdateExpression"
      && bindingPatternNames(node.argument).some((name) => protectedNames.has(name))
    ) stable = false;
    if (
      ["ForInStatement", "ForOfStatement"].includes(node.type)
      && node.left?.type !== "VariableDeclaration"
      && bindingPatternNames(node.left).some((name) => protectedNames.has(name))
    ) stable = false;
  });
  return stable;
}

function helperInstallsComputedProperty(helper, targetParameter, propertyParameter) {
  if (!helper || !targetParameter || !propertyParameter) return false;
  if (!hasStableFunctionParameters(helper, [targetParameter, propertyParameter])) return false;
  let installs = false;
  walkOwnedFunction(helper, (node) => {
    if (installs) return;
    if (node.type === "AssignmentExpression") {
      const left = node.left;
      installs = left?.type === "MemberExpression"
        && left.computed
        && left.object?.type === "Identifier"
        && left.object.name === targetParameter
        && left.property?.type === "Identifier"
        && left.property.name === propertyParameter;
      return;
    }
    if (node.type !== "CallExpression") return;
    const callee = memberSegments(node.callee);
    const recognizedMutation = [
      ["Object", "defineProperty"],
      ["Reflect", "defineProperty"],
      ["Reflect", "set"],
    ].some((expected) => JSON.stringify(callee) === JSON.stringify(expected));
    installs = recognizedMutation
      && node.arguments[0]?.type === "Identifier"
      && node.arguments[0].name === targetParameter
      && node.arguments[1]?.type === "Identifier"
      && node.arguments[1].name === propertyParameter;
  });
  return installs;
}

function functionTargetInstallations(index, functionNode, targetName, member) {
  if (!functionNode || !targetName) return [];
  const routes = [];
  const add = (producer, aliases = []) => {
    if (producer?.start === undefined || producer?.end === undefined) return;
    routes.push({ producer, aliases });
  };
  walkOwnedFunction(functionNode, (node) => {
    if (node.type === "AssignmentExpression") {
      const segments = memberSegments(node.left);
      if (JSON.stringify(segments) === JSON.stringify([targetName, member])) add(node);
      return;
    }
    if (node.type !== "CallExpression") return;
    const callee = memberSegments(node.callee);
    const target = memberSegments(node.arguments[0]);
    if (
      JSON.stringify(callee) === JSON.stringify(["Object", "defineProperty"])
      && JSON.stringify(target) === JSON.stringify([targetName])
      && propertyName(node.arguments[1]) === member
    ) {
      add(node);
      return;
    }
    if (
      JSON.stringify(callee) === JSON.stringify(["Object", "defineProperties"])
      && JSON.stringify(target) === JSON.stringify([targetName])
      && node.arguments[1]?.type === "ObjectExpression"
    ) {
      for (const property of node.arguments[1].properties) {
        if (propertyName(property.key) === member) add(property);
      }
      return;
    }
    const targetArgument = node.arguments.findIndex((argument) =>
      JSON.stringify(memberSegments(argument)) === JSON.stringify([targetName]));
    if (targetArgument < 0) return;
    const memberArgument = node.arguments.findIndex((argument, argumentIndex) =>
      argumentIndex !== targetArgument && propertyName(argument) === member);
    if (memberArgument < 0) return;
    const helperName = callee?.length === 1 ? callee[0] : null;
    const helper = helperName ? declarationFor(index, helperName)?.node : null;
    const targetParameter = helper?.params?.[targetArgument]?.type === "Identifier"
      ? helper.params[targetArgument].name
      : null;
    const propertyParameter = helper?.params?.[memberArgument]?.type === "Identifier"
      ? helper.params[memberArgument].name
      : null;
    if (helperInstallsComputedProperty(helper, targetParameter, propertyParameter)) {
      add(node, [helper]);
    }
  });
  return routes;
}

function constructorInstallationRoutes(index, owner, member) {
  const ownerFunction = declarationFor(index, owner)?.node;
  if (!ownerFunction || ownerFunction.type !== "FunctionDeclaration") return [];
  const routes = functionTargetInstallations(index, ownerFunction, "this", member);
  walkOwnedFunction(ownerFunction, (node) => {
    if (node.type !== "CallExpression") return;
    const thisArgument = node.arguments.findIndex((argument) => argument.type === "ThisExpression");
    if (thisArgument < 0) return;
    const callee = memberSegments(node.callee);
    const helperName = callee?.length === 1 ? callee[0] : null;
    const helper = helperName ? declarationFor(index, helperName)?.node : null;
    const targetName = helper?.params?.[thisArgument]?.type === "Identifier"
      ? helper.params[thisArgument].name
      : null;
    for (const route of functionTargetInstallations(index, helper, targetName, member)) {
      routes.push({ producer: route.producer, aliases: [node, ...route.aliases] });
    }
    if (
      helperName
      && /mixinEventEmitter/iu.test(helperName)
      && helper?.start !== undefined
      && helper?.end !== undefined
    ) {
      routes.push({ producer: helper, aliases: [node] });
    }
  });
  return routes;
}

function inheritedMemberRoutes(index, links, owner, member, seen = new Set()) {
  if (!owner || seen.has(owner)) return [];
  const direct = memberProducers(index, owner, member, "either");
  if (direct.length > 0) return direct.map((producer) => ({ producer, aliases: [] }));
  const ownerDeclaration = declarationFor(index, owner)?.node;
  if (ownerDeclaration) {
    const instanceAssignments = index.assignments.filter(({ segments, node }) =>
      JSON.stringify(segments) === JSON.stringify(["this", member])
      && node.start >= ownerDeclaration.start
      && node.end <= ownerDeclaration.end);
    const instanceDescriptors = index.defineProperties.filter((row) =>
      row.property === member
      && JSON.stringify(row.targetSegments) === JSON.stringify(["this"])
      && row.node.start >= ownerDeclaration.start
      && row.node.end <= ownerDeclaration.end);
    const instanceProducers = [
      ...instanceAssignments.map((row) => row.node),
      ...instanceDescriptors.map((row) => row.node),
    ];
    if (instanceProducers.length > 0) {
      return dedupeRanges(instanceProducers.map((node) => ({
        startByte: node.start,
        endByte: node.end,
      }))).map((range) => ({
        producer: { start: range.startByte, end: range.endByte },
        aliases: [],
      }));
    }
  }
  const installed = constructorInstallationRoutes(index, owner, member);
  if (installed.length > 0) return installed;
  const nextSeen = new Set(seen).add(owner);
  const routes = [];
  for (const link of links.get(owner) ?? []) {
    for (const route of inheritedMemberRoutes(index, links, link.base, member, nextSeen)) {
      routes.push({ producer: route.producer, aliases: [link.node, ...route.aliases] });
    }
  }
  return routes;
}

function reachablePrototypeAliases(links, owner, seen = new Set()) {
  if (!owner || seen.has(owner)) return [];
  const nextSeen = new Set(seen).add(owner);
  const aliases = [];
  for (const link of links.get(owner) ?? []) {
    aliases.push(link.node, ...reachablePrototypeAliases(links, link.base, nextSeen));
  }
  return [...new Map(aliases.map((node) => [`${node.start}:${node.end}`, node])).values()];
}

function builtinInheritedTableFallbackBinding({
  branch,
  sourceRef,
  sourcePath,
  locator,
  absolute,
  text,
  bytes,
}) {
  if (
    !sourcePath.endsWith(".js")
    || !locator.startsWith("exports:")
    || !branch?.observedKey?.startsWith("builtin:export:")
  ) return null;
  const exportPath = locator.slice("exports:".length);
  const match = /^(?:([^.]*)\.)?\[\[dynamic-table:inherited-[^\]]+-properties\]\]$/u.exec(exportPath);
  if (!match) return null;
  const root = match[1] || "default";
  const index = javascriptIndex(absolute, text);
  const links = prototypeLinks(absolute, text, index);
  const direct = index.assignments.filter(({ segments }) =>
    JSON.stringify(segments) === JSON.stringify(["module", "exports", root])
    || JSON.stringify(segments) === JSON.stringify(["exports", root]));
  const publications = direct.length > 0
    ? direct.map((row) => ({ node: row.parent ?? row.node, value: row.value, rootNode: row.node }))
    : index.modulePublications.map((row) => ({ node: row.node, value: row.value, rootNode: null }));
  const candidates = [];
  for (const publication of publications) {
    let rootNode = publication.rootNode;
    let rootValue = publication.value;
    if (!rootNode && root === "default") {
      rootNode = publication.node;
    } else if (!rootNode) {
      const moduleValue = resolveIdentifierValue(index, publication.value).node;
      const property = objectProperty(moduleValue, root);
      if (property) {
        rootNode = property;
        rootValue = property.type === "ObjectMethod" ? property : property.value;
      } else if (publication.value?.type === "Identifier") {
        const row = index.assignments.find(({ segments }) =>
          JSON.stringify(segments) === JSON.stringify([publication.value.name, root]));
        if (row) {
          rootNode = row.node;
          rootValue = row.value;
        }
      }
    }
    const resolved = resolveIdentifierValue(index, rootValue);
    const owner = rootValue?.type === "Identifier"
      ? (resolved.declaration?.node?.id?.name ?? rootValue.name)
      : resolved.declaration?.node?.id?.name;
    const definition = owner
      ? declarationFor(index, owner)?.node
      : resolved.declaration?.node ?? resolved.node;
    const aliases = reachablePrototypeAliases(links, owner);
    if (!definition || !rootNode) continue;
    candidates.push({ publication, rootNode, definition, aliases });
  }
  if (candidates.length === 0) return null;
  const sites = [];
  const producerPaths = [];
  for (const [candidateIndex, candidate] of candidates.entries()) {
    const definitionSite = sourceSite({
      sourceRef,
      path: sourcePath,
      role: "value-producer",
      siteKey: `${root}.inherited-definition.${candidateIndex + 1}`,
      range: { startByte: candidate.definition.start, endByte: candidate.definition.end },
      text,
      bytes,
    });
    const aliasSites = candidate.aliases.map((alias, aliasIndex) => sourceSite({
      sourceRef,
      path: sourcePath,
      role: "alias",
      siteKey: `${root}.inherited-alias.${candidateIndex + 1}.${aliasIndex + 1}`,
      range: { startByte: alias.start, endByte: alias.end },
      text,
      bytes,
    }));
    const registrationSite = sourceSite({
      sourceRef,
      path: sourcePath,
      role: "registration",
      siteKey: `${root}.inherited-registration.${candidateIndex + 1}`,
      range: { startByte: candidate.rootNode.start, endByte: candidate.rootNode.end },
      text,
      bytes,
    });
    const publicationSite = sourceSite({
      sourceRef,
      path: sourcePath,
      role: "publication",
      siteKey: `${root}.inherited-publication.${candidateIndex + 1}`,
      range: { startByte: candidate.publication.node.start, endByte: candidate.publication.node.end },
      text,
      bytes,
    });
    const pathSites = [definitionSite, ...aliasSites, registrationSite, publicationSite];
    sites.push(...pathSites);
    producerPaths.push({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0inherited-table\0${candidateIndex}`),
      conditionId: `builtin-inherited-publication:${branch.targetVariant}:${candidateIndex + 1}`,
      requiredSiteIds: pathSites.map((site) => site.siteId),
    });
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "commonjs-inherited-table-fallback-route",
    resolutionPolicy: producerPaths.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths,
  });
}

function builtinExportFallbackBinding({ branch, sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (
    !sourcePath.endsWith(".js")
    || !locator.startsWith("exports:")
    || !branch?.observedKey?.startsWith("builtin:export:")
  ) return null;
  const exportPath = locator.slice("exports:".length);
  if (exportPath.includes("[[") || exportPath.includes("<")) return null;
  const parts = exportPath.split(".");
  const root = parts[0];
  const index = javascriptIndex(absolute, text);
  const links = prototypeLinks(absolute, text, index);
  const directPublications = index.assignments.filter(({ segments }) =>
    JSON.stringify(segments) === JSON.stringify(["module", "exports", root])
    || JSON.stringify(segments) === JSON.stringify(["exports", root]));
  const publications = directPublications.length > 0
    ? directPublications.map((row) => ({ node: row.parent ?? row.node, value: row.value, rootNode: row.node }))
    : index.modulePublications.map((publication) => ({
      node: publication.node,
      value: publication.value,
      rootNode: null,
    }));
  const candidates = [];
  for (const publication of publications) {
    let rootNode = publication.rootNode;
    let rootValue = publication.value;
    if (!publication.rootNode && root !== "default") {
      const moduleValue = resolveIdentifierValue(index, publication.value).node;
      const property = objectProperty(moduleValue, root);
      if (property) {
        rootNode = property;
        rootValue = property.type === "ObjectMethod" ? property : property.value;
      } else if (publication.value?.type === "Identifier") {
        const row = index.assignments.find(({ segments }) =>
          JSON.stringify(segments) === JSON.stringify([publication.value.name, root]));
        if (row) {
          rootNode = row.node;
          rootValue = row.value;
        }
      }
    }
    if (!rootValue) continue;
    let producerRoutes;
    if (parts.length === 1 || (parts.length === 2 && parts[1] === "constructor")) {
      const resolved = resolveIdentifierValue(index, rootValue);
      const producer = resolved.declaration?.node ?? resolved.node;
      producerRoutes = producer ? [{ producer, aliases: [] }] : [];
    } else {
      const resolved = resolveIdentifierValue(index, rootValue);
      const owner = rootValue.type === "Identifier"
        ? (resolved.declaration?.node?.id?.name ?? rootValue.name)
        : resolved.declaration?.node?.id?.name;
      const direct = owner
        ? memberProducer(index, owner, parts.at(-1), parts.includes("prototype") ? "prototype" : "either")
        : null;
      producerRoutes = direct
        ? [{ producer: direct, aliases: [] }]
        : inheritedMemberRoutes(index, links, owner, parts.at(-1));
    }
    for (const producerRoute of producerRoutes) {
      if (
        producerRoute.producer?.start === undefined
        || producerRoute.producer?.end === undefined
        || publication.node?.start === undefined
        || publication.node?.end === undefined
      ) continue;
      candidates.push({ publication, rootNode, ...producerRoute });
    }
  }
  if (candidates.length === 0) return null;

  const sites = [];
  const producerPaths = [];
  for (const [indexValue, candidate] of candidates.entries()) {
    const producerSite = sourceSite({
      sourceRef,
      path: sourcePath,
      role: "value-producer",
      siteKey: `${exportPath}.fallback-producer.${indexValue + 1}`,
      range: { startByte: candidate.producer.start, endByte: candidate.producer.end },
      text,
      bytes,
    });
    const requiredSiteIds = [producerSite.siteId];
    sites.push(producerSite);
    for (const [aliasIndex, alias] of candidate.aliases.entries()) {
      const aliasSite = sourceSite({
        sourceRef,
        path: sourcePath,
        role: "alias",
        siteKey: `${exportPath}.fallback-alias.${indexValue + 1}.${aliasIndex + 1}`,
        range: { startByte: alias.start, endByte: alias.end },
        text,
        bytes,
      });
      sites.push(aliasSite);
      requiredSiteIds.push(aliasSite.siteId);
    }
    if (
      candidate.rootNode
      && candidate.rootNode !== candidate.producer
      && candidate.rootNode !== candidate.publication.node
    ) {
      const registrationSite = sourceSite({
        sourceRef,
        path: sourcePath,
        role: "registration",
        siteKey: `${exportPath}.fallback-registration.${indexValue + 1}`,
        range: { startByte: candidate.rootNode.start, endByte: candidate.rootNode.end },
        text,
        bytes,
      });
      sites.push(registrationSite);
      requiredSiteIds.push(registrationSite.siteId);
    }
    const publicationSite = sourceSite({
      sourceRef,
      path: sourcePath,
      role: "publication",
      siteKey: `${exportPath}.fallback-publication.${indexValue + 1}`,
      range: { startByte: candidate.publication.node.start, endByte: candidate.publication.node.end },
      text,
      bytes,
    });
    sites.push(publicationSite);
    requiredSiteIds.push(publicationSite.siteId);
    producerPaths.push({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0builtin-fallback\0${indexValue}`),
      conditionId: `builtin-publication:${branch.targetVariant}:${indexValue + 1}`,
      requiredSiteIds,
    });
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "commonjs-export-fallback-route",
    resolutionPolicy: producerPaths.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths,
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

function helperPropertyCalls(text, caller, property) {
  return callExpressionRangesWithin(
    text,
    "installStdioQueryAccessor",
    { startByte: 0, endByte: text.length },
  ).flatMap((range) => {
    const opening = text.indexOf("(", range.startByte);
    const args = splitTopLevelArguments(text.slice(opening + 1, range.endByte - 1));
    if (args[0]?.trim() !== caller
      || ![`"${property}"`, `'${property}'`].includes(args[2]?.trim())) return [];
    const declaration = /(?:^|\n)\s*auto\s+installStdioQueryAccessor\s*=/gu;
    const definitions = [...text.slice(0, range.startByte).matchAll(declaration)];
    if (definitions.length !== 1) return [];
    const startByte = definitions[0].index + (definitions[0][0][0] === "\n" ? 1 : 0);
    const body = text.indexOf("{", startByte);
    const bodyEnd = body < 0 ? -1 : matchingBraceEnd(text, body);
    if (bodyEnd < 0 || bodyEnd > range.startByte) return [];
    const semicolon = text.indexOf(";", bodyEnd);
    return [{
      caller,
      value: "",
      range,
      producerRange: {
        startByte,
        endByte: semicolon >= 0 && semicolon < range.startByte ? semicolon + 1 : bodyEnd,
      },
    }];
  });
}

function movedIdentifier(expression) {
  const match = /^(?:std::move\()?([A-Za-z_$][A-Za-z0-9_$]*)(?:\))?$/u.exec(expression.trim());
  return match?.[1] ?? null;
}

function factoryReturnedIdentifier(text, expression, before) {
  const call = /^([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/u.exec(expression.trim());
  if (!call) return null;
  const escaped = escapeRegExp(call[1]);
  const declarations = [...text.slice(0, before).matchAll(
    new RegExp(`(?:^|\\n)\\s*auto\\s+${escaped}\\s*=`, "gu"),
  )];
  if (declarations.length !== 1) return null;
  const startByte = declarations[0].index + (declarations[0][0][0] === "\n" ? 1 : 0);
  const opening = text.indexOf("{", startByte);
  const endByte = opening < 0 ? -1 : matchingBraceEnd(text, opening);
  if (endByte < 0 || endByte > before) return null;
  const returns = [...text.slice(opening, endByte).matchAll(
    /\breturn\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*;/gu,
  )];
  if (returns.length !== 1) return null;
  return { identifier: returns[0][1], range: { startByte, endByte } };
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

function activePreprocessorCondition(text, offset) {
  const stack = [];
  for (const line of text.slice(0, offset).split(/\r?\n/u)) {
    const directive = /^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b\s*(.*)$/u.exec(line);
    if (!directive) continue;
    const [, kind, expression] = directive;
    if (["if", "ifdef", "ifndef"].includes(kind)) stack.push(`${kind}:${expression.trim()}`);
    else if (kind === "elif" && stack.length > 0) stack[stack.length - 1] = `elif:${expression.trim()}`;
    else if (kind === "else" && stack.length > 0) stack[stack.length - 1] = `${stack.at(-1)}:else`;
    else if (kind === "endif") stack.pop();
  }
  return stack.length > 0 ? stack.join("+") : null;
}

function pairedControlConditions(text, rootCalls) {
  if (rootCalls.length !== 2) return null;
  const first = rootCalls[0].range.startByte;
  const second = rootCalls[1].range.startByte;
  const prefix = text.slice(Math.max(0, first - 1_500), first);
  const matches = [...prefix.matchAll(/\bif\s*\(/gu)];
  if (matches.length === 0) return null;
  const conditionStart = Math.max(0, first - 1_500) + matches.at(-1).index;
  const opening = text.indexOf("(", conditionStart);
  const conditionEnd = matchingDelimiterEnd(text, opening, "(", ")");
  if (conditionEnd < 0 || conditionEnd > first) return null;
  const between = text.slice(rootCalls[0].range.endByte, second);
  if (!/\}\s*else\s*\{/u.test(between)) return null;
  const conditionId = stableId("condition", text.slice(conditionStart, conditionEnd));
  return [`runtime-if:${conditionId}`, `runtime-else:${conditionId}`];
}

function enclosingCppFunctionIdentity(text, offset) {
  const pattern = /(?:^|\n)\s*(?:extern\s+"C"\s+)?(?:static\s+)?(?:void|bool|int|int32_t|uint32_t|size_t|facebook::jsi::Value)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^;{}]*\)\s*\{/gu;
  const candidates = [];
  for (const match of text.matchAll(pattern)) {
    const opening = text.indexOf("{", match.index);
    const endByte = opening < 0 ? -1 : matchingBraceEnd(text, opening);
    if (opening < offset && endByte > offset) {
      candidates.push({ name: match[1], size: endByte - opening });
    }
  }
  candidates.sort((left, right) => left.size - right.size);
  return candidates[0]?.name ?? null;
}

function enclosingCppFunctionRange(text, offset) {
  const pattern = /(?:^|\n)\s*(?:extern\s+"C"\s+)?(?:static\s+)?(?:void|bool|int|int32_t|uint32_t|size_t|facebook::jsi::Value)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^;{}]*\)\s*\{/gu;
  const candidates = [];
  for (const match of text.matchAll(pattern)) {
    const startByte = match.index + (match[0][0] === "\n" ? 1 : 0);
    const opening = text.indexOf("{", startByte);
    const endByte = opening < 0 ? -1 : matchingBraceEnd(text, opening);
    if (opening < offset && endByte > offset) candidates.push({ startByte, endByte });
  }
  candidates.sort((left, right) =>
    (left.endByte - left.startByte) - (right.endByte - right.startByte));
  return candidates[0] ?? null;
}

function jsiConditionalRootMemberBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!/\.(?:cc|mm)$/u.test(sourcePath) || !locator.startsWith("jsi-global:")) return null;
  const logicalPath = locator.slice("jsi-global:".length).split(".");
  if (logicalPath.length !== 2 || logicalPath.some((part) => part.includes("[["))) return null;
  const rootCalls = setPropertyCalls(text, logicalPath[0]).filter(
    (call) => ["rt.global()", "runtime.global()"].includes(call.caller),
  );
  if (rootCalls.length !== 1) return null;
  const rootVariable = movedIdentifier(rootCalls[0].value);
  if (!rootVariable) return null;
  const memberCalls = setPropertyCalls(text, logicalPath[1]).filter(
    (call) => call.caller === rootVariable && call.range.startByte < rootCalls[0].range.startByte,
  );
  if (memberCalls.length < 2) return null;
  const conditions = memberCalls.map((call) =>
    activePreprocessorCondition(text, call.range.startByte));
  if (conditions.some((condition) => !condition)
    || new Set(conditions).size !== conditions.length) return null;
  const rootSite = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "publication",
    siteKey: `${logicalPath[0]}.root-publication`,
    range: rootCalls[0].range,
    text,
    bytes,
  });
  const sites = [rootSite];
  const producerPaths = [];
  for (const [indexValue, memberCall] of memberCalls.entries()) {
    const producer = sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${logicalPath.join(".")}.producer.${indexValue}`, range: cppValueProducerRange(text, movedIdentifier(memberCall.value), memberCall.range.startByte) ?? memberCall.range, text, bytes });
    const publication = sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${logicalPath.join(".")}.publication.${indexValue}`, range: memberCall.range, text, bytes });
    sites.push(producer, publication);
    producerPaths.push({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0conditional-member\0${indexValue}`),
      conditionId: `preprocessor:${conditions[indexValue]}`,
      requiredSiteIds: [producer.siteId, publication.siteId, rootSite.siteId],
    });
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "jsi-conditional-root-member-route",
    targetGlobalPath: logicalPath.join("."),
    resolutionPolicy: "conditioned-alternatives",
    sites,
    producerPaths,
  });
}

function jsiProcessEnvBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (sourcePath !== "src/engine/hermes_runtime_process_setup.cc"
    || locator !== "jsi-global:process.env") return null;
  const rootCalls = setPropertyCalls(text, "process").filter(
    (call) => ["rt.global()", "runtime.global()"].includes(call.caller),
  );
  const memberCalls = setPropertyCalls(text, "env").filter((call) =>
    call.caller === "processObj" && call.range.startByte < rootCalls[0]?.range.startByte);
  if (rootCalls.length !== 1 || memberCalls.length !== 2) return null;
  const armedGuard = uniqueTokenRange(text, ["if (handle->armed) {"]);
  const copyGuard = uniqueTokenRange(text, ["} else if (!skipEnvCopy) {"]);
  if (!armedGuard || !copyGuard) return null;
  const rootSite = sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "process.root-publication", range: rootCalls[0].range, text, bytes });
  const guardSites = [
    sourceSite({ sourceRef, path: sourcePath, role: "guard", siteKey: "process.env.armed-guard", range: armedGuard, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "guard", siteKey: "process.env.copy-guard", range: copyGuard, text, bytes }),
  ];
  const sites = [rootSite, ...guardSites];
  const producerPaths = memberCalls.map((call, indexValue) => {
    const producer = sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `process.env.producer.${indexValue}`, range: call.range, text, bytes });
    const publication = sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `process.env.publication.${indexValue}`, range: call.range, text, bytes });
    sites.push(producer, publication);
    return {
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0process-env\0${indexValue}`),
      conditionId: indexValue === 0 ? "runtime:armed" : "runtime:unarmed+copy-host-env",
      requiredSiteIds: [producer.siteId, publication.siteId, rootSite.siteId, guardSites[indexValue].siteId],
    };
  });
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "jsi-process-env-route",
    targetGlobalPath: "process.env",
    resolutionPolicy: "conditioned-alternatives",
    sites,
    producerPaths,
    refusalPaths: [{
      pathId: stableId("refusal", `${branch.branchId}\0${sourceRef}\0process-env-omitted`),
      conditionId: "runtime:unarmed+shared-bundle-env",
      requiredSiteIds: guardSites.map((site) => site.siteId),
    }],
  });
}

function jsiProcessEnvDynamicTableBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (sourcePath !== "src/engine/hermes_runtime_process_setup.cc"
    || locator !== "jsi-global:process.env.[[dynamic-table:env-obj-properties]]"
    || branch?.observedKey
      !== "native-op:global:process.env.[[dynamic-table:env-obj-properties]]") return null;
  const rootCalls = setPropertyCalls(text, "process").filter(
    (call) => ["rt.global()", "runtime.global()"].includes(call.caller),
  );
  const memberCalls = setPropertyCalls(text, "env").filter((call) =>
    call.caller === "processObj" && movedIdentifier(call.value) === "envObj");
  const writes = callExpressionRangesWithin(
    text,
    "envObj.setProperty",
    { startByte: 0, endByte: text.length },
  );
  const copyGuard = uniqueTokenRange(text, ["} else if (!skipEnvCopy) {"]);
  const loop = uniqueTokenRange(text, ["for (char** ep = envp; *ep; ++ep) {"]);
  if (rootCalls.length !== 1
    || memberCalls.length !== 1
    || writes.length !== 1
    || !copyGuard
    || !loop) return null;
  const key = cppValueProducerRange(text, "key", writes[0].startByte);
  const value = cppValueProducerRange(text, "val", writes[0].startByte);
  if (!key || !value) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "guard", siteKey: "process.env.dynamic.copy-guard", range: copyGuard, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: "process.env.dynamic.entry-loop", range: loop, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: "process.env.dynamic.key", range: key, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: "process.env.dynamic.value", range: value, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "process.env.dynamic.property", range: writes[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "process.env.dynamic.env-publication", range: memberCalls[0].range, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "process.env.dynamic.process-publication", range: rootCalls[0].range, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "jsi-process-env-dynamic-table-route",
    targetGlobalPath: "process.env.[[dynamic-table:env-obj-properties]]",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0process-env-dynamic-table`),
      conditionId: "runtime:unarmed+copy-host-env+environment-entry",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function jsiStructuredDynamicGlobalBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (sourcePath !== "src/engine/hermes_runtime.cc"
    || locator !== "jsi-global:[[dynamic-table:native-global-name]]"
    || branch?.observedKey !== "native-op:global:[[dynamic-table:native-global-name]]") {
    return null;
  }
  const definition = robustFunctionDeclarationRange(text, "writeStructuredSessionName");
  const hostObject = typeDeclarationRange(text, "StructuredSessionReferenceHostObject");
  if (!definition || !hostObject) return null;
  const direct = callExpressionRangesWithin(text, "global.setProperty", definition);
  const reflected = callExpressionRangesWithin(
    text,
    "handle->structured_reflect_set->call",
    definition,
  );
  const dispatch = callExpressionRangesWithin(text, "writeStructuredSessionName", hostObject);
  const guards = tokenRangesWithin(
    text,
    "if (!global.hasProperty(rt, name.c_str())) {",
    definition,
  );
  if (direct.length !== 1
    || reflected.length !== 1
    || dispatch.length !== 1
    || guards.length !== 1) return null;
  const commonSites = [
    sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: "structured-global.write-definition", range: definition, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "guard", siteKey: "structured-global.existence-guard", range: guards[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "structured-global.host-object-dispatch", range: dispatch[0], text, bytes }),
  ];
  const directSite = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "publication",
    siteKey: "structured-global.create-publication",
    range: direct[0],
    text,
    bytes,
  });
  const reflectedSite = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "publication",
    siteKey: "structured-global.reflect-publication",
    range: reflected[0],
    text,
    bytes,
  });
  const sites = [...commonSites, directSite, reflectedSite];
  const commonSiteIds = commonSites.map((site) => site.siteId);
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "jsi-structured-dynamic-global-route",
    targetGlobalPath: "[[dynamic-table:native-global-name]]",
    resolutionPolicy: "conditioned-alternatives",
    sites,
    producerPaths: [
      {
        pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0structured-global-create`),
        conditionId: "structured-session:global-missing",
        requiredSiteIds: [...commonSiteIds, directSite.siteId],
      },
      {
        pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0structured-global-update`),
        conditionId: "structured-session:global-present",
        requiredSiteIds: [...commonSiteIds, reflectedSite.siteId],
      },
    ],
  });
}

function androidStoragePathGlobalBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  const prefix = "jsi-global:__exactAndroidStoragePaths.";
  if (sourcePath !== "src/engine/hermes_runtime_android.cc"
    || !locator.startsWith(prefix)
    || branch?.observedKey !== `native-op:${locator.slice("jsi-global:".length)}`) return null;
  const member = locator.slice(prefix.length);
  const memberCalls = setPropertyCalls(text, member).filter((call) => call.caller === "storage");
  const rootCalls = setPropertyCalls(text, "__exactAndroidStoragePaths").filter(
    (call) => call.caller === "runtime.global()",
  );
  const dispatches = callExpressionRangesWithin(
    text,
    "installStoragePathsGlobal",
    { startByte: 0, endByte: text.length },
  ).filter((range) => text.slice(range.startByte, range.endByte).includes("std::move(storage)"));
  const guard = uniqueTokenRange(text, ["  if (!armed) {"]);
  const descriptorPublications = callExpressionRangesWithin(
    text,
    "defineProperty.call",
    { startByte: 0, endByte: text.length },
  ).filter((range) => text.slice(range.startByte, range.endByte).includes("__exactAndroidStoragePaths"));
  if (memberCalls.length !== 1
    || rootCalls.length !== 1
    || dispatches.length !== 1
    || descriptorPublications.length !== 1
    || !guard) return null;
  const commonSites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${member}.storage-value`, range: memberCalls[0].range, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: "android-storage.root-publication", range: rootCalls[0].range, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: "android-storage.install-dispatch", range: dispatches[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "guard", siteKey: "android-storage.armed-guard", range: guard, text, bytes }),
  ];
  const sealedPublication = sourceSite({
    sourceRef,
    path: sourcePath,
    role: "publication",
    siteKey: "android-storage.sealed-publication",
    range: descriptorPublications[0],
    text,
    bytes,
  });
  const commonSiteIds = commonSites.map((site) => site.siteId);
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "android-storage-global-route",
    resolutionPolicy: "conditioned-alternatives",
    sites: [...commonSites, sealedPublication],
    producerPaths: [
      {
        pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0android-storage-unarmed`),
        conditionId: "runtime:unarmed",
        requiredSiteIds: commonSiteIds,
      },
      {
        pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0android-storage-armed`),
        conditionId: "runtime:armed",
        requiredSiteIds: [...commonSiteIds, sealedPublication.siteId],
      },
    ],
  });
}

function exactCapabilityDefinitionBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (sourcePath !== "src/engine/hermes_runtime.cc" || !locator.startsWith("jsi-global:exact.")) {
    return null;
  }
  const member = locator.slice("jsi-global:exact.".length);
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(member)) return null;
  const calls = callExpressionRangesWithin(
    text,
    "defineExactCapability",
    { startByte: 0, endByte: text.length },
  ).flatMap((range) => {
    const opening = text.indexOf("(", range.startByte);
    const args = splitTopLevelArguments(text.slice(opening + 1, range.endByte - 1));
    return args[2]?.trim() === `"${member}"` ? [{ range, args }] : [];
  });
  if (calls.length === 0) return null;
  const moved = /std::move\(([A-Za-z_$][A-Za-z0-9_$]*)\)/u.exec(calls[0].args[3] ?? "");
  if (!moved) return null;
  const producerRange = cppValueProducerRange(text, moved[1], calls[0].range.startByte);
  const exactObjectRange = cppValueProducerRange(text, "exactObject", producerRange?.startByte ?? calls[0].range.startByte);
  if (!producerRange || !exactObjectRange) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `exact.${member}.producer`, range: producerRange, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "alias", siteKey: `exact.${member}.object-resolution`, range: exactObjectRange, text, bytes }),
    ...calls.map((call, indexValue) => sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `exact.${member}.publication.${indexValue}`, range: call.range, text, bytes })),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "exact-capability-definition-route",
    targetGlobalPath: `exact.${member}`,
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0exact-capability`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function cppGlobalPropertyExpressionBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  const globalName = locator.startsWith("jsi-global:")
    ? locator.slice("jsi-global:".length)
    : locator;
  if (!/\.(?:cc|mm)$/u.test(sourcePath)
    || globalName.includes("[[")
    || branch?.observedKey !== `native-op:${globalName}`) return null;
  const matches = [];
  let marker = text.indexOf(".setProperty");
  while (marker >= 0) {
    const opening = text.indexOf("(", marker);
    const endByte = opening < 0 ? -1 : matchingDelimiterEnd(text, opening, "(", ")");
    if (endByte < 0) break;
    const prefix = text.slice(Math.max(0, marker - 200), marker);
    const args = splitTopLevelArguments(text.slice(opening + 1, endByte - 1));
    if (/global\(\)\s*$/u.test(prefix)
      && args[1]?.includes(`"${globalName}"`)
      && args.length >= 3) {
      const valueText = args.slice(2).join(", ").trim();
      const valueStart = text.indexOf(valueText, opening);
      matches.push({
        publication: { startByte: marker, endByte },
        producer: valueStart >= 0
          ? { startByte: valueStart, endByte: valueStart + valueText.length }
          : { startByte: marker, endByte },
      });
    }
    marker = text.indexOf(".setProperty", endByte);
  }
  if (matches.length !== 1) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${globalName}.expression`, range: matches[0].producer, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${globalName}.global-publication`, range: matches[0].publication, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "cpp-global-property-expression-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0cpp-global-expression`),
      conditionId: `target-branch:${branch.targetVariant}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function jsiGlobalBranchBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!/\.(?:cc|mm|h)$/u.test(sourcePath)) return null;
  const observedPath = branch?.observedKey?.startsWith("native-op:global:")
    ? branch.observedKey.slice("native-op:global:".length)
    : branch?.observedKey?.startsWith("native-op:")
      ? branch.observedKey.slice("native-op:".length)
      : null;
  const locatorPath = locator.startsWith("jsi-global:")
    ? locator.slice("jsi-global:".length)
    : locator === observedPath
      ? locator
      : null;
  if (!locatorPath || locatorPath === "process.cwd") return null;
  const logicalPath = locatorPath.split(".");
  if (logicalPath.some((part) => part.includes("[["))) return null;
  let rootCalls = setPropertyCalls(text, logicalPath[0]).filter(
    (call) => ["rt.global()", "runtime.global()"].includes(call.caller),
  );
  const memberCallsByRoot = new Map();
  if (logicalPath.length > 1) {
    rootCalls = rootCalls.filter((rootCall, rootIndex) => {
      const enclosingFunction = enclosingCppFunctionRange(text, rootCall.range.startByte);
      const lowerBound = Math.max(
        rootIndex > 0 ? rootCalls[rootIndex - 1].range.endByte : 0,
        enclosingFunction?.startByte ?? 0,
      );
      let currentVariable = movedIdentifier(rootCall.value);
      let before = rootCall.range.startByte;
      const memberCalls = [];
      for (const memberName of logicalPath.slice(1)) {
        if (!currentVariable) return false;
        const directMatches = setPropertyCalls(text, memberName).filter(
          (call) => call.caller === currentVariable
            && call.range.startByte >= lowerBound
            && call.range.startByte < before,
        );
        const helperMatches = helperPropertyCalls(text, currentVariable, memberName).filter(
          (call) => call.range.startByte >= lowerBound && call.range.startByte < before,
        );
        const matches = [...directMatches, ...helperMatches];
        if (matches.length !== 1) return false;
        const memberCall = matches[0];
        memberCalls.push(memberCall);
        currentVariable = movedIdentifier(memberCall.value);
        if (!currentVariable) {
          currentVariable = factoryReturnedIdentifier(text, memberCall.value, memberCall.range.startByte)
            ?.identifier ?? null;
        }
        before = memberCall.range.startByte;
      }
      memberCallsByRoot.set(rootCall.range.startByte, {
        memberCalls,
        currentVariable,
        before,
        producerRange: memberCalls.at(-1)?.producerRange ?? null,
      });
      return true;
    });
  }
  if (rootCalls.length === 0) return null;
  let branchConditions = rootCalls.map((rootCall) =>
    activePreprocessorCondition(text, rootCall.range.startByte));
  if (rootCalls.length > 1) {
    const explicit = branchConditions.filter(Boolean);
    const implicitCount = branchConditions.length - explicit.length;
    if (explicit.length === 0 || implicitCount > 1 || new Set(explicit).size !== explicit.length) {
      const installers = explicit.length === 0
        ? rootCalls.map((rootCall) =>
          enclosingCppFunctionIdentity(text, rootCall.range.startByte))
        : [];
      if (installers.length === rootCalls.length
        && installers.every(Boolean)
        && new Set(installers).size === installers.length) {
        branchConditions = installers.map((name) => `installer-function:${name}`);
      } else {
        const controlConditions = pairedControlConditions(text, rootCalls);
        if (!controlConditions) return null;
        branchConditions = controlConditions;
      }
    }
  }
  const sites = [];
  const producerPaths = [];
  for (const [indexValue, rootCall] of rootCalls.entries()) {
    const trace = memberCallsByRoot.get(rootCall.range.startByte);
    const memberCalls = trace?.memberCalls ?? [];
    const currentVariable = trace?.currentVariable ?? movedIdentifier(rootCall.value);
    const before = trace?.before ?? rootCall.range.startByte;
    const producerRange = trace?.producerRange
      ?? cppValueProducerRange(text, currentVariable, before)
      ?? memberCalls.at(-1)?.range
      ?? rootCall.range;
    const pathSites = [
      sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${logicalPath.join(".")}.producer.${indexValue}`, range: producerRange, text, bytes }),
    ];
    for (const [memberIndex, memberCall] of memberCalls.entries()) {
      pathSites.push(sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${logicalPath.slice(0, memberIndex + 2).join(".")}.member-publication.${indexValue}`, range: memberCall.range, text, bytes }));
    }
    pathSites.push(sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${logicalPath[0]}.root-publication.${indexValue}`, range: rootCall.range, text, bytes }));
    sites.push(...pathSites);
    producerPaths.push({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${logicalPath.join(".")}\0${indexValue}`),
      conditionId: branchConditions[indexValue]
        ? branchConditions[indexValue].startsWith("runtime-")
          || branchConditions[indexValue].startsWith("installer-function:")
          ? branchConditions[indexValue]
          : `preprocessor:${branchConditions[indexValue]}`
        : rootCalls.length > 1
          ? "preprocessor:otherwise"
          : `target-branch:${branch.targetVariant}:publication:${sourcePath}`,
      requiredSiteIds: pathSites.map((site) => site.siteId),
    });
  }
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "jsi-root-global-route",
    resolutionPolicy: producerPaths.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths,
  });
}

function exportedHostAbiBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("host-abi:") || branch.observedKey.startsWith("host-abi:java:")) {
    return null;
  }
  const symbol = branch.observedKey.slice("host-abi:".length);
  if (locator !== symbol || !/\.(?:cc|mm|rs)$/u.test(sourcePath)) return null;
  const escaped = escapeRegExp(symbol);
  const candidates = [];
  const signature = new RegExp(`(?:^|\\n)[^\\n;{}]*\\b${escaped}\\s*\\(`, "gu");
  for (const match of text.matchAll(signature)) {
    const startByte = match.index + match[0].search(/\S/u);
    const parameterStart = text.indexOf("(", startByte);
    const parameterEnd = parameterStart < 0
      ? -1
      : matchingDelimiterEnd(text, parameterStart, "(", ")");
    if (parameterEnd < 0) continue;
    let opening = parameterEnd;
    while (opening < text.length && opening < parameterEnd + 5_000 && text[opening] !== "{") {
      if (text[opening] === ";") break;
      opening += 1;
    }
    if (text[opening] !== "{") continue;
    const endByte = matchingBraceEnd(text, opening);
    if (endByte > opening) candidates.push({ startByte, endByte });
  }
  const uniqueCandidates = dedupeRanges(candidates);
  const range = (uniqueCandidates.length === 1 ? uniqueCandidates[0] : null)
    ?? declarationRange(text, symbol)
    ?? robustFunctionDeclarationRange(text, symbol);
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

function javaHostMethodBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    !branch?.observedKey?.match(/^host-abi:(?:java|jni):/u)
    || sourcePath !== "platform/android/java/dev/ibex/runtime/IbexNetworking.java"
    || !/^(?:java|jni):/u.test(locator)
  ) return null;
  const qualifiedMethod = locator.slice(locator.indexOf(":") + 1);
  const parts = qualifiedMethod.split(".");
  const methodName = parts.pop();
  const ownerName = parts.pop();
  if (!ownerName || !methodName) return null;
  const declaration = javaMethodDeclarationRange(text, ownerName, methodName);
  if (!declaration) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: `${qualifiedMethod}.declaration`, range: declaration, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${qualifiedMethod}.java-publication`, range: declaration, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: locator.startsWith("jni:") ? "android-jni-java-declaration" : "android-java-method-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0java-method`),
      conditionId: "target-platform:android",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function uniqueJavaMethodRegistration(text, methodName) {
  const calls = callExpressionRangesWithin(
    text,
    "env->GetStaticMethodID",
    { startByte: 0, endByte: text.length },
  ).filter((range) => text.slice(range.startByte, range.endByte).includes(`"${methodName}"`));
  return calls.length === 1 ? calls[0] : null;
}

function assignedGlobalBefore(text, range) {
  const prefix = text.slice(Math.max(0, range.startByte - 300), range.startByte);
  return /\b(g_[A-Za-z0-9_]+)\s*=\s*$/u.exec(prefix)?.[1] ?? null;
}

function retainedMethodMember(text, globalName) {
  const escaped = escapeRegExp(globalName);
  const matches = [...text.matchAll(new RegExp(`\\bout->([A-Za-z0-9_]+)\\s*=\\s*${escaped}\\s*;`, "gu"))];
  if (matches.length !== 1) return null;
  return {
    member: matches[0][1],
    range: lineRange(text, matches[0].index),
  };
}

function exactInvocationsForTokens(text, tokens, excludedRanges = []) {
  const calls = new Map();
  for (const { token, routeKind } of tokens) {
    let offset = text.indexOf(token);
    while (offset >= 0) {
      const previous = text[offset - 1];
      const following = text[offset + token.length];
      const exactToken = (!previous || !/[A-Za-z0-9_$]/u.test(previous))
        && (!following || !/[A-Za-z0-9_$]/u.test(following));
      const excluded = excludedRanges.some((range) =>
        offset >= range.startByte && offset < range.endByte);
      if (exactToken && !excluded) {
        const call = enclosingCallRange(text, offset);
        if (call) {
          const slice = text.slice(call.startByte, call.endByte);
          if (!slice.includes("GetStaticMethodID")) {
            calls.set(`${call.startByte}:${call.endByte}`, { range: call, routeKind });
          }
        }
      }
      offset = text.indexOf(token, offset + token.length);
    }
  }
  return [...calls.values()].sort((left, right) => left.range.startByte - right.range.startByte);
}

function androidJavaCallBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    !branch?.observedKey?.startsWith("host-abi:java:")
    && !branch?.observedKey?.startsWith("native-op:")
  ) return null;
  if (
    sourcePath !== "src/engine/native_android_networking.cc"
    || !locator.startsWith("java-call:")
  ) return null;
  const [, methodName, locatorMethod] = locator.split(":");
  if (!methodName || locatorMethod !== methodName) return null;
  const registration = uniqueJavaMethodRegistration(text, methodName);
  if (!registration) return null;
  const globalName = assignedGlobalBefore(text, registration);
  if (!globalName) return null;
  const retained = retainedMethodMember(text, globalName);
  const excluded = [registration, ...(retained ? [retained.range] : [])];
  const dispatches = exactInvocationsForTokens(text, [
    { token: globalName, routeKind: "direct-cache" },
    ...(retained ? [{ token: `methods.${retained.member}`, routeKind: "retained-method" }] : []),
  ], excluded);
  if (dispatches.length === 0) return null;
  const registrationSite = sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${methodName}.GetStaticMethodID`, range: registration, text, bytes });
  const retentionSite = retained
    ? sourceSite({ sourceRef, path: sourcePath, role: "retention", siteKey: `${methodName}.method-retention`, range: retained.range, text, bytes })
    : null;
  const dispatchSites = dispatches.map(({ range, routeKind }, index) => ({
    routeKind,
    site: sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: `${methodName}.jni-dispatch.${index + 1}`, range, text, bytes }),
  }));
  const sites = [registrationSite, ...(retentionSite ? [retentionSite] : []), ...dispatchSites.map(({ site }) => site)];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "android-java-call-route",
    resolutionPolicy: dispatchSites.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths: dispatchSites.map(({ routeKind, site }) => ({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0java-call\0${routeKind}`),
      conditionId: dispatchSites.length > 1
        ? `android-java-call:${routeKind}`
        : "target-platform:android",
      requiredSiteIds: [
        registrationSite.siteId,
        ...(routeKind === "retained-method" && retentionSite ? [retentionSite.siteId] : []),
        site.siteId,
      ],
    })),
  });
}

function jniTableEntryRange(text, javaMethod, target) {
  const nameToken = `"${javaMethod}"`;
  const candidates = [];
  let offset = text.indexOf(nameToken);
  while (offset >= 0) {
    let opening = text.lastIndexOf("{", offset);
    while (opening >= 0) {
      const endByte = matchingBraceEnd(text, opening);
      if (endByte > offset) {
        const slice = text.slice(opening, endByte);
        if (slice.includes(target)) candidates.push({ startByte: opening, endByte });
        break;
      }
      opening = text.lastIndexOf("{", opening - 1);
    }
    offset = text.indexOf(nameToken, offset + nameToken.length);
  }
  const unique = [...new Map(candidates.map((range) => [`${range.startByte}:${range.endByte}`, range])).values()];
  return unique.length === 1 ? unique[0] : null;
}

function androidJniCallbackBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    !branch?.observedKey?.startsWith("host-abi:jni:")
    && !branch?.observedKey?.startsWith("native-op:")
  ) return null;
  if (
    sourcePath !== "src/engine/native_android_networking.cc"
    || !locator.startsWith("jni-callback:")
  ) return null;
  const [, javaMethod, target] = locator.split(":");
  if (!javaMethod || !target) return null;
  const definition = robustFunctionDeclarationRange(text, target);
  if (!definition) return null;
  const tableEntry = jniTableEntryRange(text, javaMethod, target);
  const directExport = target.startsWith("Java_");
  if (!tableEntry && !directExport) return null;
  const registrationFunction = directExport
    ? null
    : robustFunctionDeclarationRange(text, "register_native_callbacks");
  const registerCalls = registrationFunction
    ? callExpressionRangesWithin(text, "env->RegisterNatives", registrationFunction)
    : [];
  if (!directExport && registerCalls.length !== 1) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${target}.definition`, range: definition, text, bytes }),
    sourceSite({
      sourceRef,
      path: sourcePath,
      role: directExport ? "publication" : "registration",
      siteKey: directExport ? `${javaMethod}.direct-jni-export` : `${javaMethod}.native-table-entry`,
      range: tableEntry ?? definition,
      text,
      bytes,
    }),
    ...(!directExport ? [sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${javaMethod}.RegisterNatives`, range: registerCalls[0], text, bytes })] : []),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: directExport ? "android-jni-direct-export-route" : "android-jni-table-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0jni-callback`),
      conditionId: "target-platform:android",
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

function cliGeneratedSurfaceBinding({ branch, sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (
    !branch?.observedKey?.startsWith("cli:")
    || sourcePath !== "runtime-surface.json"
    || ![
      "clapSurface.command:",
      "clapSurface.semanticRelations:",
      "replSurface.command:",
      "replSurface.loadExtension:",
      "keybindingSurface.binding:",
    ].some((prefix) => locator.startsWith(prefix))
      && locator !== "replSurface.recognition"
  ) return null;
  const range = runtimeSurfaceRange(text, locator, absolute);
  if (!range) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${locator}.row`, range, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${locator}.surface-publication`, range, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "cli-generated-surface-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0cli-generated-surface`),
      conditionId: "cli-surface:registered",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function cliAuthenticatedIngressBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("cli:") || sourcePath !== "src/bin/ibex/main.rs") return null;
  const specifications = {
    "cli:authenticated-direct-file-ingress": {
      locator: "run_file_with_execution_adapter",
      guard: "authenticated_product_ingress",
      dispatches: ["run_file"],
      conditions: ["authenticated-ingress:file-program"],
    },
    "cli:authenticated-one-shot-ingress": {
      locator: "eval_code",
      guard: "authenticated_product_ingress",
      dispatches: ["terminal_session::run_authenticated_inline_execution_adapter"],
      conditions: ["authenticated-ingress:inline-one-shot"],
    },
    "cli:authenticated-program-stdin-ingress": {
      locator: "run_stdin_program",
      guard: "authenticated_product_ingress",
      dispatches: ["terminal_session::run_worker_program_execution_adapter"],
      conditions: ["authenticated-ingress:worker-program"],
    },
    "cli:authenticated-repl-ingress": {
      locator: "start_repl",
      guard: "authenticated_product_ingress",
      dispatches: ["repl::start_worker"],
      conditions: ["authenticated-ingress:worker-repl"],
    },
    "cli:implicit-no-file-dispatch": {
      locator: "run",
      guard: "authenticated_product_ingress",
      dispatches: ["run_stdin_program", "start_repl"],
      conditions: ["implicit-input:program-stdin", "implicit-input:interactive-repl"],
    },
  };
  const specification = specifications[branch.observedKey];
  if (!specification || locator !== specification.locator) return null;
  const definition = declarationRange(text, locator)
    ?? robustFunctionDeclarationRange(text, locator);
  if (!definition) return null;
  let guards = callExpressionRangesWithin(text, specification.guard, definition);
  if (guards.length !== 1) {
    guards = tokenRangesWithin(text, `${specification.guard}(`, definition);
  }
  if (guards.length !== 1) return null;
  const dispatchRanges = specification.dispatches.map((callee) => {
    let allCalls = callExpressionRangesWithin(text, callee, definition);
    if (allCalls.length === 0) {
      allCalls = tokenRangesWithin(text, `${callee}(`, definition);
    }
    const calls = locator === "run"
      ? allCalls.filter((range) => range.startByte > guards[0].startByte)
      : allCalls;
    return calls.length === 1 ? calls[0] : null;
  });
  if (dispatchRanges.some((range) => !range)) return null;
  const definitionSite = sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: `${locator}.definition`, range: definition, text, bytes });
  const guardSite = sourceSite({ sourceRef, path: sourcePath, role: "guard", siteKey: `${locator}.authenticated-ingress-guard`, range: guards[0], text, bytes });
  const dispatchSites = dispatchRanges.map((range, index) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "dispatch",
    siteKey: `${locator}.dispatch.${index + 1}`,
    range,
    text,
    bytes,
  }));
  const sites = [definitionSite, guardSite, ...dispatchSites];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "cli-authenticated-ingress-route",
    resolutionPolicy: dispatchSites.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths: dispatchSites.map((site, index) => ({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${specification.conditions[index]}`),
      conditionId: specification.conditions[index],
      requiredSiteIds: [definitionSite.siteId, guardSite.siteId, site.siteId],
    })),
  });
}

function loaderFunctionBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    !branch?.observedKey?.match(/^loader:function:(?:javascript|rust):/u)
    || !["src/engine/bootstrap/module-loader.js", "src/module_loader/mod.rs", "src/module_loader/transpile.rs"].includes(sourcePath)
  ) return null;
  const functionName = decodeURIComponent(branch.observedKey.split(":").at(-1));
  if (locator !== functionName) return null;
  const definition = sourcePath.endsWith(".js")
    ? javascriptNamedFunctionRange(text, locator)
    : rustFunctionRange(text, locator);
  const resolvedDefinition = definition
    ?? declarationRange(text, locator)
    ?? robustFunctionDeclarationRange(text, locator);
  if (!resolvedDefinition) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: `${locator}.definition`, range: resolvedDefinition, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${locator}.named-function`, range: resolvedDefinition, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: sourcePath.endsWith(".js") ? "loader-javascript-function" : "loader-rust-function",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0loader-function`),
      conditionId: `loader-function:${sourcePath.endsWith(".js") ? "javascript" : "rust"}`,
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function loaderNamedTerminalBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    !branch?.observedKey?.startsWith("loader:")
    || branch.observedKey.startsWith("loader:function:")
    || branch.observedKey.startsWith("loader:external-calls:")
    || branch.observedKey.startsWith("loader:operation:")
    || locator.includes(":")
    || ![
      "src/engine/bootstrap/module-loader.js",
      "src/module_loader/mod.rs",
      "src/module_loader/transpile.rs",
      "src/module_loader/security.rs",
    ].includes(sourcePath)
  ) return null;
  let definition = sourcePath.endsWith(".js")
    ? javascriptNamedFunctionRange(text, locator)
    : rustFunctionRange(text, locator);
  if (!definition && locator === "new") {
    const candidates = rustFunctionRanges(text, locator).filter((range) =>
      text.slice(range.startByte, range.endByte).includes("expected_boundary_object"));
    definition = candidates.length === 1 ? candidates[0] : null;
  }
  if (!definition && locator === "manifest_input") {
    const candidates = rustFunctionRanges(text, locator).filter((range) =>
      text.slice(range.startByte, range.endByte).includes("uncaptured_package_manifest_probes"));
    definition = candidates.length === 1 ? candidates[0] : null;
  }
  const resolvedDefinition = definition
    ?? declarationRange(text, locator)
    ?? robustFunctionDeclarationRange(text, locator);
  if (!resolvedDefinition) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: `${locator}.terminal-definition`, range: resolvedDefinition, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${locator}.terminal-publication`, range: resolvedDefinition, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: sourcePath.endsWith(".js") ? "loader-javascript-terminal" : "loader-rust-terminal",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0loader-terminal`),
      conditionId: "loader-route:selected-terminal",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function loaderInternalRouteBinding({ branch, sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (
    !branch?.observedKey?.startsWith("loader:internal-route:")
    || sourcePath !== "src/engine/bootstrap/module-loader.js"
    || !locator.startsWith("internal-route:")
  ) return null;
  const specifier = locator.slice("internal-route:".length);
  const index = javascriptIndex(absolute, text);
  const loadInternal = javascriptNamedFunctionRange(text, "loadInternal");
  const streamInternal = javascriptNamedFunctionRange(text, "_loadNamedStreamInternal");
  if (!loadInternal || !streamInternal) return null;

  const candidates = [];
  for (const dispatcher of [loadInternal, streamInternal]) {
    for (const quote of ["'", '"']) {
      for (const line of tokenRangesWithin(text, `${quote}${specifier}${quote}`, dispatcher)) {
        const slice = text.slice(line.startByte, line.endByte);
        if (/\b(?:normalized|name)\b/u.test(slice)) {
          candidates.push({ dispatcher, route: line });
        }
      }
    }
  }

  const internalModules = declarationFor(index, "internalModules")?.value;
  const property = objectProperty(internalModules, specifier);
  if (property) {
    const genericDispatch = tokenRangesWithin(
      text,
      "internalModules.hasOwnProperty(normalized)",
      loadInternal,
    );
    if (genericDispatch.length !== 1) return null;
    candidates.push({
      dispatcher: loadInternal,
      route: { startByte: property.start, endByte: property.end },
      dispatch: genericDispatch[0],
    });
  }
  const unique = [...new Map(candidates.map((candidate) => [
    `${candidate.route.startByte}:${candidate.route.endByte}`,
    candidate,
  ])).values()];
  if (unique.length === 0 || (unique.length > 1 && specifier !== "internal/util/debuglog")) return null;
  const definitionRanges = [...new Map(unique.map(({ dispatcher }) => [
    `${dispatcher.startByte}:${dispatcher.endByte}`,
    dispatcher,
  ])).values()];
  const sites = [
    ...definitionRanges.map((range, index) => sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: `${specifier}.dispatcher.${index + 1}`, range, text, bytes })),
    ...unique.map(({ route }, index) => sourceSite({ sourceRef, path: sourcePath, role: "registration", siteKey: `${specifier}.route.${index + 1}`, range: route, text, bytes })),
    ...unique.map(({ route, dispatch }, index) => sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: `${specifier}.dispatch.${index + 1}`, range: dispatch ?? route, text, bytes })),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "loader-internal-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0internal-route`),
      conditionId: "loader-route:internal-specifier",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function loaderInstallerBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    branch?.observedKey !== "loader:install"
    || sourcePath !== "src/engine/hermes_bootstrap.cc"
    || locator !== "installModuleLoader"
  ) return null;
  const definition = robustFunctionDeclarationRange(text, locator)
    ?? declarationRange(text, locator);
  if (!definition) return null;
  let dispatches = callExpressionRangesWithin(text, "eval_bootstrap_script", definition);
  dispatches = dispatches.filter((range) =>
    text.slice(range.startByte, range.endByte).includes('"<module-loader>"'));
  if (dispatches.length !== 2) {
    dispatches = tokenRangesWithin(text, "eval_bootstrap_script(", definition);
    dispatches = dispatches.filter((range) => {
      const following = text.slice(range.startByte, Math.min(definition.endByte, range.endByte + 500));
      return following.includes('"<module-loader>"');
    });
  }
  if (dispatches.length !== 2) return null;
  const definitionSite = sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: `${locator}.definition`, range: definition, text, bytes });
  const dispatchSites = dispatches.map((range, index) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "dispatch",
    siteKey: `${locator}.evaluation.${index + 1}`,
    range,
    text,
    bytes,
  }));
  const sites = [definitionSite, ...dispatchSites];
  const conditions = ["module-loader:precompiled-bootstrap", "module-loader:source-bootstrap"];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "loader-bootstrap-installer-route",
    resolutionPolicy: "conditioned-alternatives",
    sites,
    producerPaths: dispatchSites.map((site, index) => ({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${conditions[index]}`),
      conditionId: conditions[index],
      requiredSiteIds: [definitionSite.siteId, site.siteId],
    })),
  });
}

function loaderLazyInstallerBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    !branch?.observedKey?.startsWith("loader:lazy-installer:")
    || sourcePath !== "src/engine/bootstrap/module-loader.js"
  ) return null;
  const separator = locator.indexOf(":");
  if (separator < 1) return null;
  const installer = locator.slice(0, separator);
  const specifier = locator.slice(separator + 1);
  const load = javascriptNamedFunctionRange(text, "load");
  if (!load) return null;
  const guardToken = `typeof ${installer} === 'function'`;
  const guards = tokenRangesWithin(text, guardToken, load);
  if (guards.length !== 1) return null;
  const opening = text.indexOf("{", guards[0].startByte);
  const endByte = opening < 0 ? -1 : matchingBraceEnd(text, opening);
  if (endByte < 0) return null;
  const guardRange = { startByte: guards[0].startByte, endByte };
  const selectors = ["'", '"'].flatMap((quote) =>
    tokenRangesWithin(text, `${quote}${specifier}${quote}`, guardRange));
  const dispatches = callExpressionRangesWithin(text, installer, guardRange);
  if (selectors.length !== 1 || dispatches.length !== 1) return null;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: `${installer}.load-dispatcher`, range: load, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "selector", siteKey: `${installer}.${specifier}.selector`, range: selectors[0], text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "dispatch", siteKey: `${installer}.trigger`, range: dispatches[0], text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "loader-lazy-installer-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0lazy-installer`),
      conditionId: "loader-route:lazy-specifier",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function loaderGlobalEntryBinding({ branch, sourceRef, sourcePath, locator, absolute, text, bytes }) {
  if (
    !branch?.observedKey?.startsWith("loader:entry:")
    || sourcePath !== "src/engine/bootstrap/module-loader.js"
    || !locator.startsWith("globalThis.")
  ) return null;
  const segments = locator.split(".");
  const index = javascriptIndex(absolute, text);
  const assignments = index.assignments.filter((row) =>
    JSON.stringify(row.segments) === JSON.stringify(segments));
  if (assignments.length !== 1) return null;
  const assignment = assignments[0];
  const resolved = resolveIdentifierValue(index, assignment.value);
  const producer = resolved.declaration?.node ?? resolved.node ?? assignment.value;
  if ((!producer?.start && producer?.start !== 0) || !producer?.end) return null;
  const publication = assignment.parent?.type === "ExpressionStatement"
    ? assignment.parent
    : assignment.node;
  const sites = [
    sourceSite({ sourceRef, path: sourcePath, role: "value-producer", siteKey: `${locator}.producer`, range: { startByte: producer.start, endByte: producer.end }, text, bytes }),
    sourceSite({ sourceRef, path: sourcePath, role: "publication", siteKey: `${locator}.publication`, range: { startByte: publication.start, endByte: publication.end }, text, bytes }),
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "loader-global-entry-route",
    resolutionPolicy: "composite-path",
    sites,
    producerPaths: [{
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0loader-global-entry`),
      conditionId: "loader-entry:global-publication",
      requiredSiteIds: sites.map((site) => site.siteId),
    }],
  });
}

function loaderRustContainerRange(text, container) {
  return rustFunctionRange(text, container)
    ?? declarationRange(text, container)
    ?? robustFunctionDeclarationRange(text, container);
}

function loaderRustContainerRanges(text, container) {
  let exact = rustFunctionRanges(text, container);
  if (container === "new") {
    exact = exact.filter((range) =>
      text.slice(range.startByte, range.endByte).includes("expected_boundary_object"));
  } else if (container === "manifest_input") {
    exact = exact.filter((range) =>
      text.slice(range.startByte, range.endByte).includes("uncaptured_package_manifest_probes"));
  }
  if (exact.length > 0) return exact;
  const fallback = loaderRustContainerRange(text, container);
  return fallback ? [fallback] : [];
}

function rustOperationCalls(text, container, kind, operation) {
  const callee = kind === "method" ? operation.split(":").at(-1) : operation;
  let calls = callExpressionRangesWithin(text, callee, container, { includeNested: true });
  if (kind === "method") {
    calls = calls.filter((range) => text[range.startByte - 1] === ".");
  } else if (kind === "call") {
    calls = calls.filter((range) =>
      !/[A-Za-z_$][A-Za-z0-9_$:]*::$/u.test(
        text.slice(Math.max(container.startByte, range.startByte - 160), range.startByte),
      ));
  }
  if (calls.length === 0) {
    calls = tokenRangesWithin(text, `${callee}(`, container).filter((range) =>
      kind !== "method" || text.slice(range.startByte, range.endByte).includes(`.${callee}(`));
  }
  return calls;
}

function loaderRustOperationBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    !branch?.observedKey?.startsWith("loader:operation:")
    || sourcePath !== "src/module_loader/mod.rs"
  ) return null;
  const marker = ":operation:";
  const markerIndex = locator.indexOf(marker);
  if (markerIndex < 1) return null;
  const containerName = locator.slice(0, markerIndex);
  const operationParts = locator.slice(markerIndex + marker.length).split(":");
  const kind = operationParts.shift();
  if (!["qualified", "method"].includes(kind)) return null;
  const operation = operationParts.join(":");
  const containers = loaderRustContainerRanges(text, containerName);
  if (containers.length === 0) return null;
  const calls = containers.flatMap((container, containerIndex) =>
    rustOperationCalls(text, container, kind, operation).map((range) => ({ range, container, containerIndex })));
  if (calls.length === 0) return null;
  const definitionSites = containers.map((container, index) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "definition",
    siteKey: `${containerName}.operation-container.${index + 1}`,
    range: container,
    text,
    bytes,
  }));
  const dispatchSites = calls.map(({ range }, index) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "dispatch",
    siteKey: `${operation}.operation.${index + 1}`,
    range,
    text,
    bytes,
  }));
  const sites = [
    ...definitionSites.filter((_, containerIndex) => calls.some((call) => call.containerIndex === containerIndex)),
    ...dispatchSites,
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "loader-rust-operation-route",
    resolutionPolicy: dispatchSites.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths: dispatchSites.map((site, index) => ({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0operation\0${index}`),
      conditionId: `loader-operation:${stableId("site", sourceRef)}:${index + 1}`,
      requiredSiteIds: [definitionSites[calls[index].containerIndex].siteId, site.siteId],
    })),
  });
}

function loaderRustExternalCallBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (
    !branch?.observedKey?.startsWith("loader:external-calls:")
    || !["src/module_loader/mod.rs", "src/module_loader/transpile.rs"].includes(sourcePath)
  ) return null;
  const marker = ":external:";
  const markerIndex = locator.indexOf(marker);
  if (markerIndex < 1) return null;
  const containerName = locator.slice(0, markerIndex);
  const parts = locator.slice(markerIndex + marker.length).split(":");
  const kind = parts.shift();
  const countToken = parts.pop();
  const expected = /^count-(\d+)$/u.exec(countToken)?.[1];
  if (!["call", "method", "qualified"].includes(kind) || !expected) return null;
  const operation = parts.join(":");
  const containers = loaderRustContainerRanges(text, containerName);
  if (containers.length === 0) return null;
  const callGroups = containers.map((container, containerIndex) => ({
    container,
    containerIndex,
    calls: rustOperationCalls(text, container, kind, operation),
  }));
  const expectedCount = Number(expected);
  const exactGroups = callGroups.filter((group) => group.calls.length === expectedCount);
  const selectedGroups = exactGroups.length === 1
    ? exactGroups
    : callGroups.flatMap((group) => group.calls).length === expectedCount
      ? callGroups
      : [];
  const calls = selectedGroups.flatMap(({ container, containerIndex, calls: ranges }) =>
    ranges.map((range) => ({ range, container, containerIndex })));
  if (calls.length !== expectedCount) return null;
  const definitionSites = containers.map((container, index) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "definition",
    siteKey: `${containerName}.external-container.${index + 1}`,
    range: container,
    text,
    bytes,
  }));
  const dispatchSites = calls.map(({ range }, index) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "dispatch",
    siteKey: `${operation}.external.${index + 1}`,
    range,
    text,
    bytes,
  }));
  const sites = [
    ...definitionSites.filter((_, containerIndex) => calls.some((call) => call.containerIndex === containerIndex)),
    ...dispatchSites,
  ];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: "loader-rust-external-call-route",
    resolutionPolicy: dispatchSites.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths: dispatchSites.map((site, index) => ({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0external\0${index}`),
      conditionId: `loader-external:${stableId("site", sourceRef)}:${index + 1}`,
      requiredSiteIds: [definitionSites[calls[index].containerIndex].siteId, site.siteId],
    })),
  });
}

function loaderKindBinding({ branch, sourceRef, sourcePath, locator, text, bytes }) {
  if (!branch?.observedKey?.startsWith("loader:kind:") || !locator.startsWith("kind:")) return null;
  const kind = branch.observedKey.slice("loader:kind:".length);
  if (locator.slice("kind:".length) !== kind) return null;
  if (sourcePath === "src/module_loader/mod.rs") {
    const term = {
      builtin: "ModuleKind::Builtin",
      commonjs: "ModuleKind::CommonJs",
      esm: "ModuleKind::Esm",
      json: "ModuleKind::Json",
      "native-addon": "ModuleType::Addon",
      wasm: "ModuleType::Wasm",
    }[kind];
    if (!term) return null;
    const testBoundary = text.indexOf("#[cfg(test)]");
    const production = { startByte: 0, endByte: testBoundary < 0 ? text.length : testBoundary };
    const ranges = tokenRangesWithin(text, term, production);
    if (ranges.length === 0) return null;
    const refusing = ["native-addon", "wasm"].includes(kind);
    const sites = ranges.map((range, index) => sourceSite({
      sourceRef,
      path: sourcePath,
      role: refusing ? "guard" : "value-producer",
      siteKey: `${kind}.rust-kind.${index + 1}`,
      range,
      text,
      bytes,
    }));
    if (refusing) {
      return validateRestrictedExactSourceBinding({
        sourceRef,
        locatorKind: "loader-rust-kind-refusal",
        resolutionPolicy: "composite-path",
        sites,
        producerPaths: [],
        refusalPaths: sites.map((site, index) => ({
          pathId: stableId("refusal", `${branch.branchId}\0${sourceRef}\0${index}`),
          conditionId: `loader-kind-refusal:${kind}:${index + 1}`,
          requiredSiteIds: [site.siteId],
        })),
      });
    }
    const publicationSites = ranges.map((range, index) => sourceSite({
      sourceRef,
      path: sourcePath,
      role: "publication",
      siteKey: `${kind}.rust-kind-publication.${index + 1}`,
      range,
      text,
      bytes,
    }));
    const allSites = [...sites, ...publicationSites];
    return validateRestrictedExactSourceBinding({
      sourceRef,
      locatorKind: "loader-rust-kind-route",
      resolutionPolicy: ranges.length > 1 ? "conditioned-alternatives" : "composite-path",
      sites: allSites,
      producerPaths: sites.map((site, index) => ({
        pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${index}`),
        conditionId: `loader-kind-rust:${kind}:${index + 1}`,
        requiredSiteIds: [site.siteId, publicationSites[index].siteId],
      })),
    });
  }
  if (sourcePath === "src/engine/bootstrap/module-loader.js" && ["builtin", "commonjs"].includes(kind)) {
    const load = javascriptNamedFunctionRange(text, "load");
    if (!load) return null;
    const runtimeKind = kind === "commonjs" ? "cjs" : kind;
    const ranges = ["'", '"'].flatMap((quote) =>
      tokenRangesWithin(text, `${quote}${runtimeKind}${quote}`, load))
      .filter((range) => /\bkind\b/u.test(text.slice(range.startByte, range.endByte)));
    if (ranges.length === 0) return null;
    const definitionSite = sourceSite({ sourceRef, path: sourcePath, role: "definition", siteKey: `${kind}.javascript-dispatcher`, range: load, text, bytes });
    const publicationSites = ranges.map((range, index) => sourceSite({
      sourceRef,
      path: sourcePath,
      role: "publication",
      siteKey: `${kind}.javascript-kind.${index + 1}`,
      range,
      text,
      bytes,
    }));
    const sites = [definitionSite, ...publicationSites];
    return validateRestrictedExactSourceBinding({
      sourceRef,
      locatorKind: "loader-javascript-kind-route",
      resolutionPolicy: publicationSites.length > 1 ? "conditioned-alternatives" : "composite-path",
      sites,
      producerPaths: publicationSites.map((site, index) => ({
        pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0${index}`),
        conditionId: `loader-kind-javascript:${kind}:${index + 1}`,
        requiredSiteIds: [definitionSite.siteId, site.siteId],
      })),
    });
  }
  return null;
}

function dedupeRanges(ranges) {
  return [...new Map(ranges.filter(Boolean).map((range) => [
    `${range.startByte}:${range.endByte}`,
    range,
  ])).values()];
}

function excludeRustTestModuleRanges(text, ranges, cacheKey = text) {
  let testModules = rustTestModuleRangeCache.get(cacheKey);
  if (!testModules) {
    testModules = [];
    const pattern = /#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/gu;
    for (const match of text.matchAll(pattern)) {
      // CapSec inventories production routes only. Rust test modules in this
      // corpus are terminal sections; treating the remaining suffix as test
      // code also avoids parsing braces embedded in fixture raw strings.
      testModules.push({ startByte: match.index, endByte: text.length });
    }
    rustTestModuleRangeCache.set(cacheKey, testModules);
  }
  return ranges.filter((range) => !testModules.some((testModule) =>
    range.startByte >= testModule.startByte && range.endByte <= testModule.endByte));
}

function startupEnvironmentRanges(text, locator) {
  const parts = locator.split(":");
  const mode = parts.pop();
  const key = parts.pop();
  const operation = parts.join(":");
  if (!["read", "write", "unset"].includes(mode) || !operation) return [];
  const whole = { startByte: 0, endByte: text.length };
  if (key !== "dynamic") {
    const tokens = [
      `"${key}"`,
      `'${key}'`,
      `.${key}`,
      key === "COMSPEC" && ".comspec",
      `process.env.${key}`,
      `globalThis.process.env.${key}`,
    ];
    return dedupeRanges(tokens.filter(Boolean)
      .flatMap((token) => tokenRangesWithin(text, token, whole)));
  }

  if (operation === "process-binding-flow") {
    const ranges = [];
    const pattern = /(?:export\s+\{\s*process\s*\}|(?:globalThis\.)?process\b|from\s+["'][^"']*process["'])/gu;
    for (const match of text.matchAll(pattern)) ranges.push(lineRange(text, match.index));
    return dedupeRanges(ranges);
  }
  if (operation === "Command::default_env") {
    return dedupeRanges([
      ...callExpressionRangesWithin(text, "Command::new", whole),
      ...callExpressionRangesWithin(text, "new", whole).filter((range) =>
        /\bCommand::new/u.test(text.slice(Math.max(0, range.startByte - 40), range.endByte))),
      ...tokenRangesWithin(text, "Command::new", whole),
    ]);
  }
  if (operation.endsWith("process.env[]")) {
    const ranges = [];
    for (const match of text.matchAll(/(?:globalThis\.)?process\.env\s*\[/gu)) {
      ranges.push(lineRange(text, match.index));
    }
    if (ranges.length === 0) {
      for (const match of text.matchAll(/(?:globalThis\.)?process\s*\??\.\s*env\b/gu)) {
        ranges.push(lineRange(text, match.index));
      }
    }
    return dedupeRanges(ranges);
  }
  if (operation.endsWith("process.env")) {
    const ranges = tokenRangesWithin(text, "process.env", whole);
    for (const match of text.matchAll(/(?:globalThis\.|\bg\.)?process\s*\??\.\s*env\b/gu)) {
      ranges.push(lineRange(text, match.index));
    }
    return dedupeRanges(ranges);
  }
  if (operation.endsWith("process[]")) {
    const ranges = [];
    for (const match of text.matchAll(/(?:globalThis\.)?process\s*\[/gu)) {
      ranges.push(lineRange(text, match.index));
    }
    if (ranges.length === 0) {
      for (const match of text.matchAll(/globalThis\.process\b/gu)) {
        ranges.push(lineRange(text, match.index));
      }
    }
    return dedupeRanges(ranges);
  }
  const callee = operation.split("::").at(-1);
  return dedupeRanges([
    ...callExpressionRangesWithin(text, callee, whole),
    ...tokenRangesWithin(text, operation, whole),
    ...tokenRangesWithin(text, `.${callee}(`, whole),
  ]);
}

function startupLocatorRanges({ branch, sourcePath, locator, absolute, text }) {
  if (branch.observedKey.startsWith("startup:env:")) {
    return excludeRustTestModuleRanges(
      text,
      startupEnvironmentRanges(text, locator),
      absolute,
    );
  }
  const whole = { startByte: 0, endByte: text.length };
  const labelMatch = /(?:^|:)evaluateJavaScript:(<[^>]+>)$/u.exec(locator)
    ?? /^script:(<[^>]+>)$/u.exec(locator);
  if (labelMatch) {
    return dedupeRanges([
      ...tokenRangesWithin(text, `"${labelMatch[1]}"`, whole),
      ...tokenRangesWithin(text, `'${labelMatch[1]}'`, whole),
    ]);
  }
  if (branch.observedKey.startsWith("startup:install-route:")) {
    const callee = locator.split(":").at(-1);
    return dedupeRanges([
      ...callExpressionRangesWithin(text, callee, whole),
      ...tokenRangesWithin(text, `${callee}(`, whole),
    ]);
  }
  const resolved = resolveRange(sourcePath, locator, text, absolute);
  if (resolved) return [resolved];
  if (!locator.includes(":")) {
    const ranges = dedupeRanges([
      ...declarationRanges(text, locator),
      ...rustFunctionRanges(text, locator),
    ]);
    if (ranges.length > 0) return ranges;
    const assignments = [];
    const assignmentPattern = new RegExp(
      `(?:^|\\n)[^\\n;{}]*\\b${escapeRegExp(locator)}\\b[^\\n;]*=`,
      "gu",
    );
    for (const match of text.matchAll(assignmentPattern)) {
      assignments.push(lineRange(text, match.index + match[0].search(/\S/u)));
    }
    if (assignments.length > 0) return dedupeRanges(assignments);
    const rawScript = new RegExp(
      `(?:^|\\n)[^\\n;]*\\b${escapeRegExp(locator)}\\b[^=]*=\\s*R["'][^(]*\\(`,
      "gu",
    );
    const scriptRanges = [];
    for (const match of text.matchAll(rawScript)) {
      const startByte = match.index + match[0].search(/\S/u);
      const terminator = text.indexOf(")JS\";", startByte);
      scriptRanges.push(terminator < 0
        ? lineRange(text, startByte)
        : { startByte, endByte: terminator + 5 });
    }
    return dedupeRanges(scriptRanges);
  }
  return [];
}

function startupExecutableBinding({
  branch,
  sourceRef,
  sourcePath,
  locator,
  absolute,
  text,
  bytes,
}) {
  if (!branch?.observedKey?.startsWith("startup:")) return null;
  const ranges = startupLocatorRanges({ branch, sourcePath, locator, absolute, text })
    .filter((range) =>
      range.endByte > range.startByte
      && !(range.startByte === 0 && range.endByte === bytes.length));
  if (ranges.length === 0) return null;

  const family = branch.observedKey.startsWith("startup:env:")
    ? "environment"
    : branch.observedKey.startsWith("startup:install-route:")
      ? "install-route"
      : branch.observedKey.startsWith("startup:evaluation:")
        ? "evaluation"
        : branch.observedKey.startsWith("startup:script:")
          ? "script"
          : branch.observedKey.startsWith("startup:installer:")
            ? "installer"
            : branch.observedKey.startsWith("startup:supervisor-history.")
              ? "supervisor-history"
              : "control";
  const terminalRole = ["environment", "install-route", "evaluation"].includes(family)
    ? "dispatch"
    : "publication";
  const producerSites = ranges.map((range, index) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: "value-producer",
    siteKey: `${family}.producer.${index + 1}`,
    range,
    text,
    bytes,
  }));
  const terminalSites = ranges.map((range, index) => sourceSite({
    sourceRef,
    path: sourcePath,
    role: terminalRole,
    siteKey: `${family}.terminal.${index + 1}`,
    range,
    text,
    bytes,
  }));
  const sites = [...producerSites, ...terminalSites];
  return validateRestrictedExactSourceBinding({
    sourceRef,
    locatorKind: `startup-${family}-route`,
    resolutionPolicy: ranges.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths: ranges.map((_, index) => ({
      pathId: stableId("producer", `${branch.branchId}\0${sourceRef}\0startup-route\0${index}`),
      conditionId: `startup-route:${branch.targetVariant}:${stableId("source", sourceRef)}:${index + 1}`,
      requiredSiteIds: [producerSites[index].siteId, terminalSites[index].siteId],
    })),
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
  const specialized = evaluatorIdentityBinding({ sourceRef, sourcePath, locator, absolute, text, bytes })
    ?? lockdownTamingIdentityBinding({ sourceRef, sourcePath, locator, text, bytes })
    ?? sourceIdentityBinding({ sourceRef, sourcePath, locator, text, bytes })
    ?? errnoExportBinding({ sourceRef, sourcePath, locator, text, bytes })
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
    ?? moduleInlineExportBinding({ branch, sourceRef, ...loaded })
    ?? signalNumberOverlayBinding({ branch, sourceRef, ...loaded })
    ?? builtinExportBranchBinding({ branch, sourceRef, ...loaded })
    ?? builtinInheritedTableFallbackBinding({ branch, sourceRef, ...loaded })
    ?? builtinExportFallbackBinding({ branch, sourceRef, ...loaded })
    ?? legacyEvaluatorRunnerBinding({ branch, sourceRef, ...loaded })
    ?? inspectorCdpRouteBinding({ branch, sourceRef, ...loaded })
    ?? inspectorDebuggerExportBinding({ branch, sourceRef, ...loaded })
    ?? nativeDefinitionBinding({ branch, sourceRef, ...loaded })
    ?? preprocessorBranchBinding({ branch, sourceRef, ...loaded })
    ?? jsiProcessEnvDynamicTableBinding({ branch, sourceRef, ...loaded })
    ?? jsiProcessEnvBinding({ branch, sourceRef, ...loaded })
    ?? jsiStructuredDynamicGlobalBinding({ branch, sourceRef, ...loaded })
    ?? androidStoragePathGlobalBinding({ branch, sourceRef, ...loaded })
    ?? jsiConditionalRootMemberBinding({ branch, sourceRef, ...loaded })
    ?? exactCapabilityDefinitionBinding({ branch, sourceRef, ...loaded })
    ?? jsiGlobalBranchBinding({ branch, sourceRef, ...loaded })
    ?? cppGlobalPropertyExpressionBinding({ branch, sourceRef, ...loaded })
    ?? javaHostMethodBinding({ branch, sourceRef, ...loaded })
    ?? androidJavaCallBinding({ branch, sourceRef, ...loaded })
    ?? androidJniCallbackBinding({ branch, sourceRef, ...loaded })
    ?? exportedHostAbiBinding({ branch, sourceRef, ...loaded })
    ?? callbackProducerBinding({ branch, sourceRef, ...loaded })
    ?? callbackDeliveryBinding({ branch, sourceRef, ...loaded })
    ?? callbackSetterBinding({ branch, sourceRef, ...loaded })
    ?? callbackDirectDispatchBinding({ branch, sourceRef, ...loaded })
    ?? nativePrincipalRestoreBinding({ branch, sourceRef, ...loaded })
    ?? timerCallbackBinding({ branch, sourceRef, ...loaded })
    ?? websocketContextReleaseBinding({ branch, sourceRef, ...loaded })
    ?? signalDispatchBinding({ branch, sourceRef, ...loaded })
    ?? cliAuthenticatedIngressBinding({ branch, sourceRef, ...loaded })
    ?? loaderFunctionBinding({ branch, sourceRef, ...loaded })
    ?? loaderNamedTerminalBinding({ branch, sourceRef, ...loaded })
    ?? loaderInternalRouteBinding({ branch, sourceRef, ...loaded })
    ?? loaderInstallerBinding({ branch, sourceRef, ...loaded })
    ?? loaderLazyInstallerBinding({ branch, sourceRef, ...loaded })
    ?? loaderGlobalEntryBinding({ branch, sourceRef, ...loaded })
    ?? loaderRustOperationBinding({ branch, sourceRef, ...loaded })
    ?? loaderRustExternalCallBinding({ branch, sourceRef, ...loaded })
    ?? loaderKindBinding({ branch, sourceRef, ...loaded })
    ?? startupExecutableBinding({ branch, sourceRef, ...loaded })
    ?? cliGeneratedSurfaceBinding({ branch, sourceRef, ...loaded })
    ?? cliVisibleCommandBinding({ branch, sourceRef, ...loaded })
    ?? cliNamespaceRefusalBinding({ branch, sourceRef, ...loaded })
    ?? sharedArrayBufferViewWrapperBinding({ branch, sourceRef, ...loaded })
    ?? typedArraySubarrayRouteBinding({ branch, sourceRef, ...loaded })
    ?? typescriptGlobalInstallerBinding({ branch, sourceRef, ...loaded })
    ?? bootstrapGlobalBinding({ branch, sourceRef, ...loaded })
    ?? legacyBootstrapGlobalBinding({ branch, sourceRef, ...loaded })
    ?? intlLocaleDirectionBinding({ branch, sourceRef, ...loaded })
    ?? typescriptStaticDescriptorBinding({ branch, sourceRef, ...loaded })
    ?? typescriptComputedMemberBinding({ branch, sourceRef, ...loaded })
    ?? typescriptClassMemberBinding({ branch, sourceRef, ...loaded })
    ?? typescriptFactoryObjectMemberBinding({ branch, sourceRef, ...loaded })
    ?? typescriptObjectMemberBinding({ branch, sourceRef, ...loaded })
    ?? typescriptBundleMemberBinding({ branch, sourceRef, ...loaded })
    ?? typescriptModuleGlobalMemberBinding({ branch, sourceRef, ...loaded })
    ?? typescriptModuleObjectMemberProvenanceBinding({ branch, sourceRef, ...loaded })
    ?? exactGlobalAliasBinding({ branch, sourceRef, ...loaded })
    ?? evaluatedCppGlobalBinding({ branch, sourceRef, ...loaded })
    ?? cppSymbolProvenanceBinding({ branch, sourceRef, ...loaded })
    ?? legacyViewConstructorTableBinding({ branch, sourceRef, ...loaded })
    ?? legacyReturnedPrototypeMemberBinding({ branch, sourceRef, ...loaded })
    ?? legacyJavascriptGlobalRouteBinding({ branch, sourceRef, ...loaded })
    ?? legacyStdioLazyMethodBinding({ branch, sourceRef, ...loaded })
    ?? legacyJavascriptTerminalRouteBinding({ branch, sourceRef, ...loaded })
    ?? legacyJavascriptAliasRouteBinding({ branch, sourceRef, ...loaded })
    ?? generatedJavascriptGlobalBinding({ branch, sourceRef, ...loaded })
    ?? javascriptSymbolProvenanceBinding({ branch, sourceRef, ...loaded });
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
    [
      "typescript-class-member",
      "typescript-class-inheritance",
      "typescript-computed-member",
      "typescript-factory-object-member",
      "typescript-object-member",
    ].includes(binding.locatorKind),
  );
  const exact = producers.filter(({ sourceRef }) => locatorOf(sourceRef) === exactLocator);
  if (exact.length === 1) return exact[0];
  if (memberParts[0]?.startsWith("[[dynamic-table:inherited-")) {
    const inheritedTable = producers.filter(({ sourceRef, binding }) =>
      binding.locatorKind === "typescript-class-inheritance"
      && locatorOf(sourceRef).startsWith(`${root}:extends:`));
    if (inheritedTable.length === 1) return inheritedTable[0];
  }
  const prototype = producers.filter(({ sourceRef }) => locatorOf(sourceRef) === prototypeLocator);
  if (prototype.length === 1) return prototype[0];
  if (!member) return null;
  const inherited = producers.filter(({ sourceRef }) => {
    const locator = locatorOf(sourceRef);
    return locator === member
      || locator.endsWith(`.prototype.${member}`)
      || locator.endsWith(`.${member}`);
  });
  if (inherited.length === 1) return inherited[0];
  const leaf = memberParts.at(-1);
  const aliasedLeaf = producers.filter(({ sourceRef }) => {
    const locator = locatorOf(sourceRef);
    return locator === leaf
      || locator.endsWith(`.${leaf}`)
      || locator.endsWith(`.prototype.${leaf}`);
  });
  return aliasedLeaf.length === 1 ? aliasedLeaf[0] : null;
}

function globalPublicationTarget(entry) {
  if (entry.binding.targetGlobalPath) return entry.binding.targetGlobalPath;
  const locator = locatorOf(entry.sourceRef);
  const marker = ":globals:";
  const markerIndex = locator.indexOf(marker);
  return markerIndex < 0 ? null : locator.slice(markerIndex + marker.length);
}

function selectGlobalPublicationEntries(observedPath, entries) {
  const candidates = entries.filter((entry) =>
    [
      "typescript-global-publication",
      "typescript-lazy-global-publication",
      "typescript-global-installer-route",
    ].includes(entry.binding.locatorKind))
    .map((entry) => ({ entry, target: globalPublicationTarget(entry) }))
    .filter(({ target }) =>
      target && (observedPath === target || observedPath.startsWith(`${target}.`)));
  if (candidates.length === 0) return [];
  const longest = Math.max(...candidates.map(({ target }) => target.split(".").length));
  return candidates
    .filter(({ target }) => target.split(".").length === longest)
    .map(({ entry }) => entry);
}

function entryTargetsGlobalPath(entry, observedPath) {
  if (entry.binding.targetGlobalPath) return entry.binding.targetGlobalPath === observedPath;
  const locator = locatorOf(entry.sourceRef);
  if (locator.startsWith("jsi-global:")) return locator.slice("jsi-global:".length) === observedPath;
  if (entry.binding.locatorKind === "jsi-root-global-route") return locator === observedPath;
  if (entry.binding.locatorKind === "javascript-global-assignment-route") return locator === observedPath;
  if (entry.binding.locatorKind === "exact-global-alias-route") return locator === observedPath;
  if (entry.binding.locatorKind === "evaluated-cpp-global-route") {
    return locator.endsWith(`:${observedPath}`);
  }
  const marker = ":globals:";
  const markerIndex = locator.indexOf(marker);
  return markerIndex >= 0 && locator.slice(markerIndex + marker.length) === observedPath;
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
  if (branch.observedKey.startsWith("loader:kind:")) {
    const rustEntry = entries.find(({ binding }) =>
      ["loader-rust-kind-route", "loader-rust-kind-refusal"].includes(binding.locatorKind));
    const javascriptEntry = entries.find(({ binding }) =>
      binding.locatorKind === "loader-javascript-kind-route");
    if (rustEntry) {
      selectedEntries.add(rustEntry);
      if (rustEntry.binding.refusalPaths.length > 0) {
        refusalPaths.push(...rustEntry.binding.refusalPaths);
      } else if (javascriptEntry) {
        selectedEntries.add(javascriptEntry);
        for (const rustPath of rustEntry.binding.producerPaths) {
          for (const javascriptPath of javascriptEntry.binding.producerPaths) {
            const conditionId = `${rustPath.conditionId}+${javascriptPath.conditionId}`;
            producerPaths.push({
              pathId: stableId("producer", `${branch.branchId}\0${conditionId}`),
              conditionId,
              requiredSiteIds: [
                ...rustPath.requiredSiteIds,
                ...javascriptPath.requiredSiteIds,
              ],
            });
          }
        }
      } else {
        producerPaths.push(...rustEntry.binding.producerPaths);
      }
    }
  } else if (branch.observedKey === "loader:transform-engine:swc") {
    const loaderEntries = entries.filter(({ binding }) => binding.producerPaths.length > 0);
    if (loaderEntries.length === 2) {
      for (const entry of loaderEntries) selectedEntries.add(entry);
      producerPaths.push({
        pathId: stableId("producer", `${branch.branchId}\0swc-transform-engine`),
        conditionId: "loader-transform-engine:swc",
        requiredSiteIds: loaderEntries.flatMap(({ binding }) =>
          binding.sites.map((site) => site.siteId)),
      });
    }
  } else if (branch.observedKey.match(/^host-abi:(?:java|jni):/u)) {
    const javaEntry = entries.find(({ binding }) =>
      ["android-java-method-route", "android-jni-java-declaration"].includes(binding.locatorKind));
    const nativeEntry = entries.find(({ binding }) =>
      ["android-java-call-route", "android-jni-direct-export-route", "android-jni-table-route"].includes(binding.locatorKind));
    if (javaEntry) {
      selectedEntries.add(javaEntry);
      const javaSiteIds = javaEntry.binding.producerPaths[0].requiredSiteIds;
      if (nativeEntry) {
        selectedEntries.add(nativeEntry);
        for (const nativePath of nativeEntry.binding.producerPaths) {
          producerPaths.push({
            pathId: stableId("producer", `${branch.branchId}\0${nativePath.conditionId}`),
            conditionId: nativePath.conditionId,
            requiredSiteIds: [...javaSiteIds, ...nativePath.requiredSiteIds],
          });
        }
      } else {
        producerPaths.push({
          pathId: stableId("producer", `${branch.branchId}\0android-java-only`),
          conditionId: "target-platform:android",
          requiredSiteIds: javaSiteIds,
        });
      }
    }
  } else if (branch.observedKey === "callback:signal-delivery") {
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
  } else if (branch.observedKey.startsWith("native-op:")
    && entries.some(({ binding }) => [
      "android-java-call-route",
      "android-jni-direct-export-route",
      "android-jni-table-route",
    ].includes(binding.locatorKind))) {
    const androidEntries = entries.filter(({ binding }) => [
      "native-operation-definition",
      "android-java-call-route",
      "android-jni-direct-export-route",
      "android-jni-table-route",
    ].includes(binding.locatorKind));
    if (androidEntries.some(({ binding }) => binding.locatorKind === "native-operation-definition")) {
      for (const entry of androidEntries) selectedEntries.add(entry);
      const requiredSiteIds = androidEntries.flatMap(({ binding }) =>
        binding.sites.map((site) => site.siteId));
      producerPaths.push({
        pathId: stableId("producer", `${branch.branchId}\0android-native-operation`),
        conditionId: "target-platform:android",
        requiredSiteIds,
      });
    }
  } else if (branch.observedKey.startsWith("native-op:global:")) {
    const observedPath = branch.observedKey.slice("native-op:global:".length);
    const producer = selectGlobalProducerEntry(observedPath, entries);
    const publications = selectGlobalPublicationEntries(observedPath, entries);
    const observedParts = observedPath.split(".");
    const exactAliasPath = observedParts[0] === "Bun" && observedParts.length > 1
      ? `Exact.${observedParts.slice(1).join(".")}`
      : null;
    const exactAliasEntries = exactAliasPath
      ? selectGlobalPublicationEntries(exactAliasPath, entries)
      : [];
    if (producer && publications.length > 0) {
      selectedEntries.add(producer);
      const composedPublications = publications.flatMap((publication) => {
        selectedEntries.add(publication);
        const paths = publication.binding.producerPaths.length > 0
          ? publication.binding.producerPaths
          : [{
              conditionId: publication.binding.locatorKind === "typescript-lazy-global-publication"
                ? "runtime-bundle:global-missing"
                : `target-branch:${branch.targetVariant}`,
              requiredSiteIds: publication.binding.sites.map((site) => site.siteId),
            }];
        return paths.map((publicationPath) => ({ publication, publicationPath }));
      });
      const conditionCounts = new Map();
      for (const { publicationPath } of composedPublications) {
        conditionCounts.set(
          publicationPath.conditionId,
          (conditionCounts.get(publicationPath.conditionId) ?? 0) + 1,
        );
      }
      const composedAliases = exactAliasEntries.flatMap((publication) => {
        selectedEntries.add(publication);
        const paths = publication.binding.producerPaths.length > 0
          ? publication.binding.producerPaths
          : [{
              conditionId: publication.binding.locatorKind === "typescript-lazy-global-publication"
                ? "runtime-bundle:global-missing"
                : `target-branch:${branch.targetVariant}`,
              requiredSiteIds: publication.binding.sites.map((site) => site.siteId),
            }];
        return paths.map((publicationPath) => ({ publication, publicationPath }));
      });
      const routes = composedAliases.length > 0
        ? composedPublications.flatMap((publication) =>
          composedAliases.map((alias) => ({ publication, alias })))
        : composedPublications.map((publication) => ({ publication, alias: null }));
      for (const { publication, alias } of routes) {
        const { publicationPath } = publication;
        const conditionId = conditionCounts.get(publicationPath.conditionId) === 1
          ? `${publicationPath.conditionId}${alias ? `+alias:${alias.publicationPath.conditionId}` : ""}`
          : `${publicationPath.conditionId}+publication:${stableId("source", publication.publication.sourceRef)}${alias ? `+alias:${alias.publicationPath.conditionId}` : ""}`;
        producerPaths.push({
          pathId: stableId("producer", `${branch.branchId}\0${conditionId}`),
          conditionId,
          requiredSiteIds: [
            ...producer.binding.sites.map((site) => site.siteId),
            ...publicationPath.requiredSiteIds,
            ...(alias?.publicationPath.requiredSiteIds ?? []),
          ],
        });
      }
    } else if (publications.length === 1 && exactAliasEntries.length === 1) {
      selectedEntries.add(publications[0]);
      selectedEntries.add(exactAliasEntries[0]);
      const requiredSiteIds = [publications[0], exactAliasEntries[0]]
        .flatMap((entry) => entry.binding.sites.map((site) => site.siteId));
      producerPaths.push({
        pathId: stableId("producer", `${branch.branchId}\0bun-exact-alias`),
        conditionId: `runtime-compat:bun+target-branch:${branch.targetVariant}`,
        requiredSiteIds,
      });
    } else if (!observedPath.includes(".") && publications.length === 1) {
      selectedEntries.add(publications[0]);
      const requiredSiteIds = publications[0].binding.sites.map((site) => site.siteId);
      producerPaths.push({
        pathId: stableId("producer", `${branch.branchId}\0runtime-bundle-root`),
        conditionId: publications[0].binding.locatorKind === "typescript-lazy-global-publication"
          ? "runtime-bundle:global-missing"
          : `target-branch:${branch.targetVariant}`,
        requiredSiteIds,
      });
    }
    if (producerPaths.length === 0) {
      for (const entry of entries.filter(({ binding }) =>
        binding.producerPaths.length > 0
        && !["legacy-bootstrap-global-route"].includes(binding.locatorKind))
        .filter((entry) => entryTargetsGlobalPath(entry, observedPath))) {
        selectedEntries.add(entry);
        producerPaths.push(...entry.binding.producerPaths);
      }
    }
    if (producerPaths.length === 0) {
      const descendantEntries = entries.filter((entry) => {
        if (entry.binding.locatorKind !== "typescript-global-installer-route"
          || entry.binding.producerPaths.length === 0) return false;
        const locator = locatorOf(entry.sourceRef);
        const markerIndex = locator.indexOf(":globals:");
        const installedPath = markerIndex < 0 ? null : locator.slice(markerIndex + ":globals:".length);
        return installedPath?.startsWith(`${observedPath}.`);
      });
      if (descendantEntries.length === 1) {
        selectedEntries.add(descendantEntries[0]);
        producerPaths.push(...descendantEntries[0].binding.producerPaths);
      }
    }
    for (const entry of entries.filter(({ binding }) => binding.locatorKind === "legacy-bootstrap-global-route")) {
      selectedEntries.add(entry);
      producerPaths.push(...entry.binding.producerPaths);
    }
  } else {
    const terminalEntries = entries.filter(({ binding }) =>
      binding.producerPaths.length > 0 || binding.refusalPaths.length > 0);
    for (const entry of terminalEntries) {
      if (["jsi-root-global-route", "cpp-global-property-expression-route"].includes(entry.binding.locatorKind)
        && !locatorOf(entry.sourceRef).startsWith("jsi-global:")
        && terminalEntries.some((candidate) =>
          candidate.binding.locatorKind === entry.binding.locatorKind
          && candidate.sourceRef.slice(0, candidate.sourceRef.indexOf("#"))
            === entry.sourceRef.slice(0, entry.sourceRef.indexOf("#"))
          && locatorOf(candidate.sourceRef) === `jsi-global:${locatorOf(entry.sourceRef)}`)) {
        continue;
      }
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

export function auditRestrictedExactBranchSourceRoutes({
  retainExecutableRoutes = true,
  startIndex = 0,
  endIndex = Number.POSITIVE_INFINITY,
} = {}) {
  const implementation = readJsonStrict(
    path.join(capsecRoot, "generated/implementation-manifest.json"),
  );
  const routes = [];
  let executable = 0;
  const incomplete = [];
  const selected = implementation.surfaces.slice(
    Math.max(0, startIndex),
    Math.min(implementation.surfaces.length, endIndex),
  );
  for (const branch of selected) {
    const refs = [...new Set([
      ...branch.sourceRefs,
      ...branch.enforcementRoute.sourceRefs,
      ...branch.enforcementRoute.proofSourceRefs,
    ])].sort();
    const route = buildRestrictedExactBranchSourceRoute(branch, refs);
    if (route.status === "executable") {
      executable += 1;
      if (retainExecutableRoutes) routes.push(route);
    }
    else incomplete.push({
      branchId: branch.branchId,
      edgeId: branch.edgeId,
      observedKey: branch.observedKey,
      targetVariant: branch.targetVariant,
      ...route,
    });
  }
  return {
    routes,
    executable,
    incomplete,
    scanned: selected.length,
    total: implementation.surfaces.length,
  };
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
