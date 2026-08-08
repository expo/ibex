/**
 * Deterministically discover the runtime surfaces that WP1 must classify.
 *
 * This module deliberately stops at observation. It does not assign effects,
 * gates, or capability semantics; the generated coverage model owns that step.
 *
 * @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — the
 * generated registry must fail closed when a runtime surface is unclassified.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parseSync } from "@babel/core";
import ts from "typescript";
import {
  joinAndroidBridgeImplementationRefs,
  scanAndroidCppBridgeBindings,
  scanAndroidJavaBridgeSurfaces,
} from "./capsec-android-bridge-inventory.mjs";
import { normalizeComposedInstallationBranches } from "./capsec-installation-branches.mjs";
import { discoverNativeNetworkingBackendSurfaces } from "./capsec-native-network-backend-inventory.mjs";
import {
  legacyBootstrapTargetVariant,
  nativeImplementationSourceIsReplacedOnWindows,
} from "./capsec-native-target-sources.mjs";

const textDecoder = new TextDecoder("utf-8", { fatal: true });

const COVERAGE_KINDS = new Set([
  "builtin",
  "callback",
  "cli",
  "host-abi",
  "loader",
  "native-op",
  "startup",
]);

const NATIVE_SOURCE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".cpp",
  ".cxx",
  ".h",
  ".hh",
  ".hpp",
  ".hxx",
  ".m",
  ".mm",
]);

const PUBLIC_ABI_IDENTIFIER =
  /^ex_(?:android|host|hermes|worklet)_[A-Za-z0-9_]+$/u;

export const HOST_ABI_OUTPUT_CONTRACT_SCHEMA =
  "ibex/host-abi-output-contract/1";
export const C_ABI_TYPE_REGISTRY_SCHEMA = "ibex/c-abi-type-registry/1";
export const CALLBACK_OUTPUT_CONTRACT_SCHEMA =
  "ibex/callback-output-contract/1";
export const PRINCIPAL_ENVIRONMENT_OVERLAY_SOURCE_CONTRACT_SCHEMA =
  "ibex/principal-environment-overlay-source-contract/1";
export const PRINCIPAL_ENVIRONMENT_OVERLAY_DYNAMIC_MEMBER =
  "[[dynamic-table:principal-environment-overlay-properties]]";
export const PRINCIPAL_ENVIRONMENT_OVERLAY_SURFACE_NAME = `global:process.env.${PRINCIPAL_ENVIRONMENT_OVERLAY_DYNAMIC_MEMBER}`;

const PRIVATE_NATIVE_IDENTIFIER =
  /^__[A-Za-z_$][A-Za-z0-9_$]*(?:[.:/-][A-Za-z0-9_$]+)*$/u;

// Mach-O segment/section labels share the private-JavaScript identifier shape,
// but describe bytes in the loaded image rather than a runtime operation.
const PLATFORM_METADATA_IDENTIFIERS = new Set(["__TEXT", "__text"]);

const COMMAND_CLASSES = [
  ["visibleCommands", "visible"],
  ["hiddenHarnessCommands", "hidden-harness"],
  ["reservedCommands", "reserved"],
  ["legacyProjectCommands", "legacy-project"],
];

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function evidenceHash(value) {
  let hash = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(value)) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(36).padStart(7, "0");
}

function posixPath(value) {
  return value.split(path.sep).join("/");
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(compareText);
}

function sourceSymbol(file, symbol) {
  return `${file}#${symbol}`;
}

function makeSurface(kind, name, sourceRefs, { variant, metadata } = {}) {
  if (!COVERAGE_KINDS.has(kind)) {
    throw new Error(`unknown coverage surface kind ${JSON.stringify(kind)}`);
  }
  if (typeof name !== "string" || name.length === 0) {
    throw new Error(`surface ${kind} has an empty name`);
  }
  const normalizedRefs = uniqueSorted(sourceRefs);
  if (normalizedRefs.length === 0) {
    throw new Error(`surface ${kind}:${name} has no source references`);
  }

  const surface = {
    kind,
    name,
    observedKey: `${kind}:${name}`,
    sourceRefs: normalizedRefs,
  };
  if (variant !== undefined) surface.variant = variant;
  if (metadata !== undefined) surface.metadata = metadata;
  return surface;
}

export function assertUniqueObservedKeys(
  surfaces,
  label = "surface inventory",
) {
  const seen = new Set();
  for (const surface of surfaces) {
    const expected = `${surface.kind}:${surface.name}`;
    if (surface.observedKey !== expected) {
      throw new Error(
        `${label}: ${JSON.stringify(surface.observedKey)} is not the canonical key ${JSON.stringify(expected)}`,
      );
    }
    if (seen.has(surface.observedKey)) {
      throw new Error(
        `${label}: duplicate observed key ${surface.observedKey}`,
      );
    }
    seen.add(surface.observedKey);
  }
}

function sortSurfaces(surfaces) {
  return surfaces.sort((left, right) =>
    compareText(left.observedKey, right.observedKey),
  );
}

function readUtf8(filePath) {
  try {
    return textDecoder.decode(fs.readFileSync(filePath));
  } catch (error) {
    throw new Error(
      `${filePath}: unable to read strict UTF-8: ${error.message}`,
    );
  }
}

function decodeEscapedString(value, label) {
  let output = "";
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (char !== "\\") {
      output += char;
      continue;
    }
    index += 1;
    if (index >= value.length)
      throw new Error(`${label}: trailing string escape`);
    const escaped = value[index];
    const simple = {
      "'": "'",
      '"': '"',
      "?": "?",
      "\\": "\\",
      a: "\x07",
      b: "\b",
      f: "\f",
      n: "\n",
      r: "\r",
      t: "\t",
      v: "\x0b",
    };
    if (Object.hasOwn(simple, escaped)) {
      output += simple[escaped];
      continue;
    }
    if (escaped === "\n") continue;
    if (escaped === "\r" && value[index + 1] === "\n") {
      index += 1;
      continue;
    }
    if (escaped === "x") {
      const match = value.slice(index + 1).match(/^[0-9A-Fa-f]+/u);
      if (!match) throw new Error(`${label}: empty hexadecimal escape`);
      output += String.fromCodePoint(Number.parseInt(match[0], 16));
      index += match[0].length;
      continue;
    }
    if (escaped === "u" || escaped === "U") {
      if (escaped === "u" && value[index + 1] === "{") {
        const close = value.indexOf("}", index + 2);
        const digits =
          close === -1 ? "" : value.slice(index + 2, close).replaceAll("_", "");
        if (!/^[0-9A-Fa-f]{1,6}$/u.test(digits)) {
          throw new Error(`${label}: malformed braced Unicode escape`);
        }
        output += String.fromCodePoint(Number.parseInt(digits, 16));
        index = close;
        continue;
      }
      const length = escaped === "u" ? 4 : 8;
      const digits = value.slice(index + 1, index + 1 + length);
      if (!new RegExp(`^[0-9A-Fa-f]{${length}}$`, "u").test(digits)) {
        throw new Error(`${label}: malformed Unicode escape`);
      }
      output += String.fromCodePoint(Number.parseInt(digits, 16));
      index += length;
      continue;
    }
    if (/[0-7]/u.test(escaped)) {
      const match = value.slice(index).match(/^[0-7]{1,3}/u)[0];
      output += String.fromCodePoint(Number.parseInt(match, 8));
      index += match.length - 1;
      continue;
    }
    // C/C++ accepts implementation-defined escapes. Retaining the escaped
    // character is conservative for the ASCII private identifiers we observe.
    output += escaped;
  }
  return output;
}

function scanEmbeddedScriptStrings(text) {
  const values = [];
  let index = 0;
  let canStartRegex = true;

  const skipQuoted = (quote, collect) => {
    index += 1;
    let raw = "";
    while (index < text.length) {
      const char = text[index];
      if (char === quote) {
        index += 1;
        if (collect) {
          try {
            values.push(decodeEscapedString(raw, "<embedded-script>"));
          } catch {
            // Embedded raw strings are not required to be JavaScript. Ignore a
            // token that cannot be decoded instead of weakening native scans.
          }
        }
        return;
      }
      if (char === "\\") {
        raw += char;
        index += 1;
        if (index < text.length) {
          raw += text[index];
          index += 1;
        }
        continue;
      }
      raw += char;
      index += 1;
    }
  };

  while (index < text.length) {
    const char = text[index];
    const next = text[index + 1];
    if (/\s/u.test(char)) {
      index += 1;
      continue;
    }
    if (char === "/" && next === "/") {
      index += 2;
      while (index < text.length && text[index] !== "\n") index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      index += 2;
      while (
        index < text.length &&
        !(text[index] === "*" && text[index + 1] === "/")
      ) {
        index += 1;
      }
      if (index < text.length) index += 2;
      continue;
    }
    if (char === "'" || char === '"') {
      skipQuoted(char, true);
      canStartRegex = false;
      continue;
    }
    if (char === "`") {
      // Private identifiers in template text are computed references, not
      // registration/reference string literals. Skip the complete template.
      skipQuoted(char, false);
      canStartRegex = false;
      continue;
    }
    if (char === "/" && canStartRegex) {
      index += 1;
      let inClass = false;
      while (index < text.length) {
        const token = text[index];
        if (token === "\\") {
          index += 2;
          continue;
        }
        if (token === "[") inClass = true;
        if (token === "]") inClass = false;
        index += 1;
        if (token === "/" && !inClass) break;
      }
      while (/[A-Za-z]/u.test(text[index] ?? "")) index += 1;
      canStartRegex = false;
      continue;
    }
    if (/[A-Za-z_$]/u.test(char)) {
      const start = index;
      index += 1;
      while (/[A-Za-z0-9_$]/u.test(text[index] ?? "")) index += 1;
      const word = text.slice(start, index);
      canStartRegex = new Set([
        "await",
        "case",
        "delete",
        "do",
        "else",
        "in",
        "instanceof",
        "new",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
      ]).has(word);
      continue;
    }
    canStartRegex = /[([{,;:=!?&|+*%^~<>-]/u.test(char);
    index += 1;
  }
  return values;
}

function collectCppStringValues(text, label) {
  const values = [];
  let index = 0;
  let pending = "";
  let pendingIncludesRaw = false;

  const flushPending = () => {
    if (!pending) return;
    values.push(pending);
    if (pendingIncludesRaw) values.push(...scanEmbeddedScriptStrings(pending));
    pending = "";
    pendingIncludesRaw = false;
  };

  const readQuoted = (quote) => {
    const start = index;
    index += 1;
    let raw = "";
    while (index < text.length) {
      const char = text[index];
      if (char === quote) {
        index += 1;
        return decodeEscapedString(raw, label);
      }
      if (char === "\\") {
        raw += char;
        index += 1;
        if (index < text.length) {
          raw += text[index];
          index += 1;
        }
        continue;
      }
      raw += char;
      index += 1;
    }
    throw new Error(
      `${label}: unterminated ${quote === '"' ? "string" : "character"} literal at byte ${start}`,
    );
  };

  while (index < text.length) {
    const char = text[index];
    const next = text[index + 1];
    if (/\s/u.test(char)) {
      index += 1;
      continue;
    }
    if (char === "/" && next === "/") {
      index += 2;
      while (index < text.length && text[index] !== "\n") index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      const start = index;
      index += 2;
      while (
        index < text.length &&
        !(text[index] === "*" && text[index + 1] === "/")
      ) {
        index += 1;
      }
      if (index >= text.length) {
        throw new Error(
          `${label}: unterminated block comment at byte ${start}`,
        );
      }
      index += 2;
      continue;
    }
    if (char === "R" && next === '"') {
      const start = index;
      const delimiterStart = index + 2;
      const open = text.indexOf("(", delimiterStart);
      if (open !== -1 && open - delimiterStart <= 16) {
        const delimiter = text.slice(delimiterStart, open);
        if (!/[\s\\()]/u.test(delimiter)) {
          const closeMarker = `)${delimiter}"`;
          const close = text.indexOf(closeMarker, open + 1);
          if (close === -1) {
            throw new Error(
              `${label}: unterminated raw string literal at byte ${start}`,
            );
          }
          const rawValue = text.slice(open + 1, close);
          pending += rawValue;
          pendingIncludesRaw = true;
          index = close + closeMarker.length;
          continue;
        }
      }
    }
    if (char === '"') {
      pending += readQuoted(char);
      continue;
    }
    if (char === "'") {
      if (
        /[0-9A-Fa-f]/u.test(text[index - 1] ?? "") &&
        /[0-9A-Fa-f]/u.test(next ?? "")
      ) {
        index += 1;
        continue;
      }
      flushPending();
      readQuoted(char);
      continue;
    }
    flushPending();
    index += 1;
  }
  flushPending();
  return values;
}

/**
 * Scan one C/C++/ObjC++ translation unit. Repeated observations deliberately
 * collapse to one logical surface while retaining an occurrence count.
 */
export function scanPrivateNativeIdentifiers(
  text,
  sourcePath = "<native-source>",
) {
  const counts = new Map();
  for (const value of collectCppStringValues(text, sourcePath)) {
    if (
      !PRIVATE_NATIVE_IDENTIFIER.test(value) ||
      PLATFORM_METADATA_IDENTIFIERS.has(value)
    ) {
      continue;
    }
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return sortSurfaces(
    [...counts.entries()].map(([name, occurrenceCount]) =>
      makeSurface("native-op", name, [sourceSymbol(sourcePath, name)], {
        metadata: { occurrenceCount },
      }),
    ),
  );
}

function lexRust(text, label) {
  const tokens = [];
  let index = 0;

  const push = (type, value, offset = index) =>
    tokens.push({ type, value, offset });

  const skipNormalString = (quote, type) => {
    const start = index;
    index += 1;
    let raw = "";
    while (index < text.length) {
      const char = text[index];
      if (char === quote) {
        index += 1;
        if (type) push(type, decodeEscapedString(raw, label), start);
        return;
      }
      if (char === "\\") {
        raw += char;
        index += 1;
        if (index < text.length) {
          raw += text[index];
          index += 1;
        }
        continue;
      }
      raw += char;
      index += 1;
    }
    throw new Error(`${label}: unterminated Rust literal at byte ${start}`);
  };

  while (index < text.length) {
    const char = text[index];
    const next = text[index + 1];
    if (/\s/u.test(char)) {
      index += 1;
      continue;
    }
    if (char === "/" && next === "/") {
      index += 2;
      while (index < text.length && text[index] !== "\n") index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      const start = index;
      index += 2;
      let depth = 1;
      while (index < text.length && depth > 0) {
        if (text[index] === "/" && text[index + 1] === "*") {
          depth += 1;
          index += 2;
        } else if (text[index] === "*" && text[index + 1] === "/") {
          depth -= 1;
          index += 2;
        } else {
          index += 1;
        }
      }
      if (depth !== 0)
        throw new Error(
          `${label}: unterminated Rust block comment at byte ${start}`,
        );
      continue;
    }

    const rawPrefix = text.slice(index).match(/^(?:b?r)(#{0,255})"/u);
    if (rawPrefix) {
      const start = index;
      const hashes = rawPrefix[1];
      index += rawPrefix[0].length;
      const close = `"${hashes}`;
      const end = text.indexOf(close, index);
      if (end === -1)
        throw new Error(
          `${label}: unterminated Rust raw string at byte ${start}`,
        );
      push("string", text.slice(index, end), start);
      index = end + close.length;
      continue;
    }
    if (char === '"') {
      skipNormalString(char, "string");
      continue;
    }
    if (char === "'") {
      // A lifetime is tokenized as punctuation + identifier; a character
      // literal is skipped whole. Neither participates in an extern signature.
      const close = text.indexOf("'", index + 1);
      if (close !== -1 && close - index <= 8) {
        skipNormalString(char, null);
      } else {
        push("punctuation", char, index);
        index += 1;
      }
      continue;
    }
    if (/[A-Za-z_]/u.test(char)) {
      const start = index;
      index += 1;
      while (/[A-Za-z0-9_]/u.test(text[index] ?? "")) index += 1;
      push("identifier", text.slice(start, index), start);
      continue;
    }
    push("punctuation", char, index);
    index += 1;
  }
  return tokens;
}

function exactCfgTestAttributeEnd(tokens, start) {
  if (tokens[start]?.value !== "#" || tokens[start + 1]?.value !== "[")
    return -1;
  const close = matchingToken(tokens, start + 1, "[", "]");
  if (close === -1) return -1;
  const values = tokens.slice(start + 2, close).map((token) => token.value);
  return JSON.stringify(values) === JSON.stringify(["cfg", "(", "test", ")"])
    ? close
    : -1;
}

/**
 * Remove complete `#[cfg(test)]` items without truncating production items
 * that follow them. The old first-match string split made a test module at
 * mid-file hide every later production definition from inventory.
 */
function rustProductionTokens(text, label) {
  const tokens = lexRust(text, label);
  const disabled = new Set();

  for (let index = 0; index < tokens.length; index += 1) {
    const attributeEnd = exactCfgTestAttributeEnd(tokens, index);
    if (attributeEnd === -1) continue;

    let cursor = attributeEnd + 1;
    while (tokens[cursor]?.value === "#") {
      const nextAttribute = matchingToken(tokens, cursor + 1, "[", "]");
      if (nextAttribute === -1) break;
      cursor = nextAttribute + 1;
    }

    let itemEnd = cursor;
    while (
      itemEnd < tokens.length &&
      !new Set(["{", ";"]).has(tokens[itemEnd].value)
    ) {
      itemEnd += 1;
    }
    if (tokens[itemEnd]?.value === "{") {
      const bodyEnd = matchingToken(tokens, itemEnd, "{", "}");
      itemEnd = bodyEnd === -1 ? tokens.length - 1 : bodyEnd;
    }
    for (
      let disabledIndex = index;
      disabledIndex <= itemEnd;
      disabledIndex += 1
    ) {
      disabled.add(disabledIndex);
    }
    index = itemEnd;
  }

  return tokens.filter((_, index) => !disabled.has(index));
}

function rustFunctionDefinitions(tokens) {
  const definitions = [];
  for (let index = 0; index < tokens.length - 1; index += 1) {
    if (
      tokens[index].value !== "fn" ||
      tokens[index + 1]?.type !== "identifier"
    )
      continue;
    let cursor = index + 2;
    let parenDepth = 0;
    let bracketDepth = 0;
    while (cursor < tokens.length) {
      const value = tokens[cursor].value;
      if (value === "(") parenDepth += 1;
      if (value === ")") parenDepth -= 1;
      if (value === "[") bracketDepth += 1;
      if (value === "]") bracketDepth -= 1;
      if (
        parenDepth === 0 &&
        bracketDepth === 0 &&
        (value === "{" || value === ";")
      ) {
        if (value === "{") {
          definitions.push({
            bodyOpen: cursor,
            bodyClose: matchingToken(tokens, cursor, "{", "}"),
            fnIndex: index,
            name: tokens[index + 1].value,
            nameIndex: index + 1,
          });
        }
        break;
      }
      cursor += 1;
    }
  }
  return definitions;
}

function matchingOpeningToken(tokens, closeIndex, openValue, closeValue) {
  let depth = 0;
  for (let index = closeIndex; index >= 0; index -= 1) {
    if (tokens[index]?.value === closeValue) depth += 1;
    if (tokens[index]?.value === openValue) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function rustFunctionHasPublicVisibility(tokens, fnIndex) {
  let cursor = fnIndex - 1;
  while (
    cursor >= 0 &&
    new Set(["async", "const", "unsafe"]).has(tokens[cursor]?.value)
  ) {
    cursor -= 1;
  }
  if (tokens[cursor]?.value === "pub") return true;
  if (tokens[cursor]?.value !== ")") return false;
  const open = matchingOpeningToken(tokens, cursor, "(", ")");
  return open > 0 && tokens[open - 1]?.value === "pub";
}

function rustImmediateCfgTargetVariant(tokens, itemIndex) {
  let cursor = itemIndex - 1;
  while (tokens[cursor]?.value === "]") {
    const open = matchingOpeningToken(tokens, cursor, "[", "]");
    if (open <= 0 || tokens[open - 1]?.value !== "#") break;
    const values = tokens.slice(open + 1, cursor).map((token) => token.value);
    if (values[0] === "cfg" && values.includes("unix")) {
      return values.includes("not") ? "windows" : "posix";
    }
    cursor = open - 2;
  }
  return null;
}

function rustExportNameAttribute(tokens, open, close, sourcePath) {
  const body = tokens.slice(open + 1, close);
  const exportNameIndexes = body
    .map((token, index) => (token.value === "export_name" ? index : -1))
    .filter((index) => index !== -1);
  if (exportNameIndexes.length === 0) return null;
  const direct =
    body.length === 3 &&
    body[0]?.value === "export_name" &&
    body[1]?.value === "=" &&
    body[2]?.type === "string";
  const unsafe =
    body.length === 6 &&
    body[0]?.value === "unsafe" &&
    body[1]?.value === "(" &&
    body[2]?.value === "export_name" &&
    body[3]?.value === "=" &&
    body[4]?.type === "string" &&
    body[5]?.value === ")";
  if (!direct && !unsafe) {
    throw new Error(
      `${sourcePath}: unreviewed Rust export_name attribute shape`,
    );
  }
  return direct ? body[2].value : body[4].value;
}

function rustNoMangleAttribute(tokens, open, close, sourcePath) {
  const body = tokens.slice(open + 1, close);
  if (!body.some((token) => token.value === "no_mangle")) return false;
  const direct = body.length === 1 && body[0]?.value === "no_mangle";
  const unsafe =
    body.length === 4 &&
    body[0]?.value === "unsafe" &&
    body[1]?.value === "(" &&
    body[2]?.value === "no_mangle" &&
    body[3]?.value === ")";
  if (!direct && !unsafe) {
    throw new Error(`${sourcePath}: unreviewed Rust no_mangle attribute shape`);
  }
  return true;
}

function rustAttributesImmediatelyBefore(tokens, itemIndex, sourcePath) {
  const attributes = [];
  let cursor = itemIndex - 1;
  while (tokens[cursor]?.value === "]") {
    const open = matchingOpeningToken(tokens, cursor, "[", "]");
    if (open <= 0 || tokens[open - 1]?.value !== "#") break;
    attributes.unshift({
      close: cursor,
      exportName: rustExportNameAttribute(tokens, open, cursor, sourcePath),
      noMangle: rustNoMangleAttribute(tokens, open, cursor, sourcePath),
      open,
    });
    cursor = open - 2;
  }
  return attributes;
}

function parseRustExternFunction(tokens, itemIndex, definitionsByNameIndex) {
  let cursor = itemIndex;
  if (tokens[cursor]?.value === "pub") {
    cursor += 1;
    if (tokens[cursor]?.value === "(") {
      const visibilityClose = matchingToken(tokens, cursor, "(", ")");
      if (visibilityClose === -1) return null;
      cursor = visibilityClose + 1;
    }
  }
  let isUnsafe = false;
  if (tokens[cursor]?.value === "unsafe") {
    isUnsafe = true;
    cursor += 1;
  }
  if (
    tokens[cursor]?.value !== "extern" ||
    tokens[cursor + 1]?.type !== "string" ||
    tokens[cursor + 1]?.value !== "C" ||
    tokens[cursor + 2]?.value !== "fn" ||
    tokens[cursor + 3]?.type !== "identifier" ||
    !definitionsByNameIndex.has(cursor + 3)
  ) {
    return null;
  }
  const definition = definitionsByNameIndex.get(cursor + 3);
  return {
    bodyClose: definition.bodyClose,
    bodyOpen: definition.bodyOpen,
    internalName: tokens[cursor + 3].value,
    isUnsafe,
    nameIndex: cursor + 3,
  };
}

function rustStaticallyNamedItem(tokens, itemIndex) {
  const identifierAt = (index) => {
    if (tokens[index]?.type !== "identifier") return null;
    if (
      tokens[index]?.value === "r" &&
      tokens[index + 1]?.value === "#" &&
      tokens[index + 2]?.type === "identifier"
    ) {
      return { name: tokens[index + 2].value, next: index + 3 };
    }
    return { name: tokens[index].value, next: index + 1 };
  };

  let headerEnd = itemIndex;
  while (
    headerEnd < tokens.length &&
    !new Set(["{", ";", "="]).has(tokens[headerEnd].value)
  ) {
    headerEnd += 1;
  }
  for (let index = itemIndex; index < headerEnd; index += 1) {
    if (tokens[index]?.value === "fn") {
      const identifier = identifierAt(index + 1);
      if (identifier) return { itemKind: "function", name: identifier.name };
      return null;
    }
    if (tokens[index]?.value === "static") {
      const nameIndex =
        tokens[index + 1]?.value === "mut" ? index + 2 : index + 1;
      const identifier = identifierAt(nameIndex);
      if (identifier) return { itemKind: "static", name: identifier.name };
      return null;
    }
    if (tokens[index]?.value === "const" && tokens[index + 1]?.value !== "fn") {
      const identifier = identifierAt(index + 1);
      if (identifier) return { itemKind: "const", name: identifier.name };
      return null;
    }
  }
  return null;
}

function rustPublicExternDefinitions(tokens, sourcePath) {
  const definitionsByNameIndex = new Map(
    rustFunctionDefinitions(tokens).map((definition) => [
      definition.nameIndex,
      definition,
    ]),
  );
  const records = new Map();
  const addRecord = (record, exportName = null) => {
    if (!record) return;
    const name = exportName ?? record.internalName;
    let definitions = records.get(name);
    if (!definitions) {
      definitions = new Map();
      records.set(name, definitions);
    }
    definitions.set(record.nameIndex, { ...record, name });
  };

  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index]?.value !== "pub") continue;
    const attributes = rustAttributesImmediatelyBefore(
      tokens,
      index,
      sourcePath,
    );
    const exportNames = attributes
      .map((attribute) => attribute.exportName)
      .filter((name) => name !== null);
    if (exportNames.length > 1) {
      throw new Error(`${sourcePath}: multiple Rust export_name attributes`);
    }
    addRecord(
      parseRustExternFunction(tokens, index, definitionsByNameIndex),
      exportNames[0] ?? null,
    );
  }

  // `export_name` publishes a linker symbol even when the Rust item itself is
  // private. Discover it from the production attribute and require the item to
  // retain the reviewed C ABI shape instead of trusting its Rust identifier.
  for (let index = 0; index < tokens.length - 1; index += 1) {
    if (tokens[index]?.value !== "#" || tokens[index + 1]?.value !== "[")
      continue;
    const close = matchingToken(tokens, index + 1, "[", "]");
    if (close === -1) {
      throw new Error(`${sourcePath}: unterminated Rust attribute`);
    }
    const exportName = rustExportNameAttribute(
      tokens,
      index + 1,
      close,
      sourcePath,
    );
    const noMangle = rustNoMangleAttribute(
      tokens,
      index + 1,
      close,
      sourcePath,
    );
    if (exportName === null && !noMangle) {
      index = close;
      continue;
    }
    let itemIndex = close + 1;
    while (
      tokens[itemIndex]?.value === "#" &&
      tokens[itemIndex + 1]?.value === "["
    ) {
      const nextClose = matchingToken(tokens, itemIndex + 1, "[", "]");
      if (nextClose === -1) {
        throw new Error(`${sourcePath}: unterminated Rust attribute`);
      }
      itemIndex = nextClose + 1;
    }
    const record = parseRustExternFunction(
      tokens,
      itemIndex,
      definitionsByNameIndex,
    );
    const staticallyNamedItem = noMangle
      ? rustStaticallyNamedItem(tokens, itemIndex)
      : null;
    if (noMangle && !record && staticallyNamedItem === null) {
      throw new Error(`${sourcePath}: unreviewed Rust no_mangle item shape`);
    }
    const effectiveName =
      exportName ?? record?.internalName ?? staticallyNamedItem?.name ?? "";
    if (!record && PUBLIC_ABI_IDENTIFIER.test(effectiveName)) {
      throw new Error(
        `${sourcePath}: public ABI attribute for ${effectiveName} is not attached to an inventoried extern \"C\" function definition`,
      );
    }
    addRecord(record, exportName);
    index = close;
  }
  return [...records.values()].flatMap((definitions) => [
    ...definitions.values(),
  ]);
}

/** Scan one Rust source file for actual public ex_host_* C ABI definitions. */
export function scanRustHostExterns(text, sourcePath = "<rust-source>") {
  const tokens = rustProductionTokens(text, sourcePath);
  const outputAnnotations = parseAbiOutputAnnotations(text, sourcePath);
  const callbackAnnotations = parseAbiCallbackAnnotations(text, sourcePath);
  const records = rustPublicExternDefinitions(tokens, sourcePath);
  const recordNames = new Set(records.map((record) => record.name));
  for (const functionName of outputAnnotations.keys()) {
    if (!recordNames.has(functionName)) {
      throw new Error(
        `${sourcePath}: @abi-output names absent Rust ABI definition ${functionName}`,
      );
    }
  }
  for (const functionName of callbackAnnotations.keys()) {
    if (!recordNames.has(functionName)) {
      throw new Error(
        `${sourcePath}: @abi-callback names absent Rust ABI definition ${functionName}`,
      );
    }
  }
  const names = new Map();
  for (const record of records) {
    const { name } = record;
    if (!name.startsWith("ex_host_")) continue;
    if (!/^ex_host_[A-Za-z0-9_]+$/u.test(name)) {
      throw new Error(
        `${sourcePath}: malformed public host ABI symbol ${JSON.stringify(name)}`,
      );
    }
    if (names.has(name)) {
      throw new Error(
        `${sourcePath}: duplicate public host ABI definition ${name}`,
      );
    }
    names.set(name, record);
  }

  return sortSurfaces(
    [...names.entries()].map(([name, record]) => {
      const sourceRef = sourceSymbol(sourcePath, name);
      const metadata = {
        outputContract: rustHostAbiOutputContract(
          tokens,
          record,
          outputAnnotations.get(name) ?? [],
          callbackAnnotations.get(name) ?? [],
          sourceRef,
        ),
        unsafe: record.isUnsafe,
      };
      if (record.internalName !== name)
        metadata.rustIdentifier = record.internalName;
      return makeSurface("host-abi", name, [sourceRef], {
        metadata,
      });
    }),
  );
}

/** Scan one Rust source file for all public Ibex C ABI definitions. */
export function scanRustPublicAbiDefinitions(
  text,
  sourcePath = "<rust-source>",
) {
  const tokens = rustProductionTokens(text, sourcePath);
  const outputAnnotations = parseAbiOutputAnnotations(text, sourcePath);
  const callbackAnnotations = parseAbiCallbackAnnotations(text, sourcePath);
  const records = rustPublicExternDefinitions(tokens, sourcePath);
  const recordNames = new Set(records.map((record) => record.name));
  for (const functionName of outputAnnotations.keys()) {
    if (!recordNames.has(functionName)) {
      throw new Error(
        `${sourcePath}: @abi-output names absent Rust ABI definition ${functionName}`,
      );
    }
  }
  for (const functionName of callbackAnnotations.keys()) {
    if (!recordNames.has(functionName)) {
      throw new Error(
        `${sourcePath}: @abi-callback names absent Rust ABI definition ${functionName}`,
      );
    }
  }
  const definitions = new Map();
  for (const record of records) {
    const { name } = record;
    if (!PUBLIC_ABI_IDENTIFIER.test(name)) continue;
    if (definitions.has(name)) {
      throw new Error(`${sourcePath}: duplicate public ABI definition ${name}`);
    }
    definitions.set(name, record);
  }

  return sortSurfaces(
    [...definitions.entries()].map(([name, record]) => {
      const sourceRef = sourceSymbol(sourcePath, name);
      const metadata = {
        language: "rust",
        outputContract: rustHostAbiOutputContract(
          tokens,
          record,
          outputAnnotations.get(name) ?? [],
          callbackAnnotations.get(name) ?? [],
          sourceRef,
        ),
        unsafe: record.isUnsafe,
        weak: false,
      };
      if (record.internalName !== name)
        metadata.rustIdentifier = record.internalName;
      return makeSurface("host-abi", name, [sourceRef], {
        metadata,
      });
    }),
  );
}

function lexCpp(text, label) {
  const tokens = [];
  let index = 0;
  const push = (type, value, start = index, end = start + value.length) =>
    tokens.push({ type, value, offset: start, start, end });

  const skipQuoted = (quote, collect) => {
    const start = index;
    index += 1;
    let raw = "";
    while (index < text.length) {
      const char = text[index];
      if (char === quote) {
        index += 1;
        if (collect)
          push("string", decodeEscapedString(raw, label), start, index);
        return;
      }
      if (char === "\\") {
        raw += char;
        index += 1;
        if (index < text.length) {
          raw += text[index];
          index += 1;
        }
        continue;
      }
      raw += char;
      index += 1;
    }
    throw new Error(`${label}: unterminated C/C++ literal at byte ${start}`);
  };

  while (index < text.length) {
    const char = text[index];
    const next = text[index + 1];
    if (/\s/u.test(char)) {
      index += 1;
      continue;
    }
    if (char === "/" && next === "/") {
      index += 2;
      while (index < text.length && text[index] !== "\n") index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      const start = index;
      index += 2;
      while (
        index < text.length &&
        !(text[index] === "*" && text[index + 1] === "/")
      )
        index += 1;
      if (index >= text.length)
        throw new Error(
          `${label}: unterminated block comment at byte ${start}`,
        );
      index += 2;
      continue;
    }
    if (char === "R" && next === '"') {
      const start = index;
      const delimiterStart = index + 2;
      const open = text.indexOf("(", delimiterStart);
      if (open !== -1 && open - delimiterStart <= 16) {
        const delimiter = text.slice(delimiterStart, open);
        if (!/[\s\\()]/u.test(delimiter)) {
          const closeMarker = `)${delimiter}"`;
          const close = text.indexOf(closeMarker, open + 1);
          if (close === -1)
            throw new Error(
              `${label}: unterminated raw string at byte ${start}`,
            );
          push(
            "string",
            text.slice(open + 1, close),
            start,
            close + closeMarker.length,
          );
          index = close + closeMarker.length;
          continue;
        }
      }
    }
    if (char === '"') {
      skipQuoted(char, true);
      continue;
    }
    if (char === "'") {
      if (
        /[0-9A-Fa-f]/u.test(text[index - 1] ?? "") &&
        /[0-9A-Fa-f]/u.test(next ?? "")
      ) {
        index += 1;
        continue;
      }
      skipQuoted(char, false);
      continue;
    }
    if (/[A-Za-z_]/u.test(char)) {
      const start = index;
      index += 1;
      while (/[A-Za-z0-9_]/u.test(text[index] ?? "")) index += 1;
      push("identifier", text.slice(start, index), start, index);
      continue;
    }
    const pair = text.slice(index, index + 2);
    if (new Set(["::", "->", "[[", "]]"]).has(pair)) {
      push("punctuation", pair, index, index + 2);
      index += 2;
      continue;
    }
    push("punctuation", char, index, index + 1);
    index += 1;
  }
  return tokens;
}

function matchingToken(tokens, start, open, close) {
  if (tokens[start]?.type !== "punctuation" || tokens[start]?.value !== open)
    return -1;
  let depth = 0;
  for (let index = start; index < tokens.length; index += 1) {
    if (tokens[index].type !== "punctuation") continue;
    if (tokens[index].value === open) depth += 1;
    if (tokens[index].value === close) depth -= 1;
    if (depth === 0) return index;
  }
  return -1;
}

const ABI_TYPE_WORDS = new Set([
  "bool",
  "char",
  "const",
  "double",
  "extern",
  "float",
  "int",
  "long",
  "mut",
  "short",
  "signed",
  "struct",
  "unsigned",
  "void",
  "volatile",
]);

const ABI_SCALAR_TYPES = new Set([
  "bool",
  "char",
  "double",
  "f32",
  "f64",
  "float",
  "i8",
  "i16",
  "i32",
  "i64",
  "i128",
  "int",
  "int8_t",
  "int16_t",
  "int32_t",
  "int64_t",
  "intptr_t",
  "isize",
  "long",
  "short",
  "signed",
  "size_t",
  "ssize_t",
  "u8",
  "u16",
  "u32",
  "u64",
  "u128",
  "uint8_t",
  "uint16_t",
  "uint32_t",
  "uint64_t",
  "uintptr_t",
  "unsigned",
  "usize",
]);

function abiTypeDescriptor(tokens) {
  const tokenValues = tokens.map((token) =>
    token.type === "string" ? `\"${token.value}\"` : token.value,
  );
  return {
    canonical: tokenValues.join(" "),
    tokens: tokenValues,
  };
}

function splitTopLevelAbiTokens(tokens, delimiter) {
  if (tokens.length === 0) return [];
  const parts = [];
  let start = 0;
  const depth = { "(": 0, "[": 0, "{": 0, "<": 0 };
  const closeToOpen = { ")": "(", "]": "[", "}": "{", ">": "<" };
  for (let index = 0; index < tokens.length; index += 1) {
    const value = tokens[index].value;
    if (Object.hasOwn(depth, value)) depth[value] += 1;
    if (Object.hasOwn(closeToOpen, value)) {
      const open = closeToOpen[value];
      if (depth[open] > 0) depth[open] -= 1;
    }
    if (
      value === delimiter &&
      Object.values(depth).every((value) => value === 0)
    ) {
      parts.push(tokens.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(tokens.slice(start));
  return parts.filter((part) => part.length > 0);
}

function splitAbiTokenList(tokens) {
  return splitTopLevelAbiTokens(tokens, ",");
}

function topLevelTokenIndex(tokens, searched) {
  const depth = { "(": 0, "[": 0, "{": 0, "<": 0 };
  const closeToOpen = { ")": "(", "]": "[", "}": "{", ">": "<" };
  for (let index = 0; index < tokens.length; index += 1) {
    const value = tokens[index].value;
    if (
      value === searched &&
      Object.values(depth).every((value) => value === 0)
    ) {
      return index;
    }
    if (Object.hasOwn(depth, value)) depth[value] += 1;
    if (Object.hasOwn(closeToOpen, value)) {
      const open = closeToOpen[value];
      if (depth[open] > 0) depth[open] -= 1;
    }
  }
  return -1;
}

function abiPointerShape(language, typeTokens) {
  const values = typeTokens.map((token) => token.value);
  const pointerDepth = values.filter((value) => value === "*").length;
  if (pointerDepth === 0) {
    return { constPointee: false, pointerDepth: 0 };
  }
  const firstPointer = values.indexOf("*");
  const constPointee =
    language === "rust"
      ? values[firstPointer + 1] === "const"
      : values.slice(0, firstPointer).includes("const");
  return { constPointee, pointerDepth };
}

function abiTypeKind(language, typeTokens, { isReturn = false } = {}) {
  const values = typeTokens.map((token) => token.value);
  if (
    values.length === 0 ||
    (language === "rust" && values.join("\0") === "(\0)") ||
    (language === "c++" && values.join("\0") === "void")
  ) {
    return "void";
  }
  if (abiPointerShape(language, typeTokens).pointerDepth > 0) return "pointer";
  if (
    values.some((value) => ABI_SCALAR_TYPES.has(value)) &&
    !values.some((value) => new Set(["[", "{", "("]).has(value))
  ) {
    return "scalar";
  }
  if (isReturn && values.length > 0) return "unknown";
  return "aggregate";
}

function isAbiCallbackType(typeTokens, parameterName) {
  const values = typeTokens.map((token) => token.value);
  return (
    values.includes("fn") ||
    (values.includes("(") && values.includes("*") && values.includes(")")) ||
    values.some((value) => /(?:Callback|Hook|Handler)$/u.test(value)) ||
    (/callback|hook/iu.test(parameterName ?? "") &&
      (values.includes("Option") || values.includes("*")))
  );
}

function cppParameterNameIndex(tokens) {
  for (let index = 0; index < tokens.length - 2; index += 1) {
    if (
      tokens[index].value === "*" &&
      tokens[index + 1]?.type === "identifier" &&
      tokens[index + 2]?.value === ")"
    ) {
      return index + 1;
    }
  }
  for (let index = 1; index < tokens.length; index += 1) {
    if (tokens[index].value === "[" && tokens[index - 1]?.type === "identifier")
      return index - 1;
  }
  const last = tokens.length - 1;
  if (tokens[last]?.type !== "identifier") return -1;
  const value = tokens[last].value;
  const lastPointer = tokens.map((token) => token.value).lastIndexOf("*");
  if (lastPointer !== -1) return last > lastPointer ? last : -1;
  if (ABI_TYPE_WORDS.has(value) || ABI_SCALAR_TYPES.has(value)) return -1;
  if (tokens.length === 1) return -1;
  return last;
}

function rustAbiParameters(tokens, open, close, sourcePath, functionName) {
  return splitAbiTokenList(tokens.slice(open + 1, close)).map(
    (parameterTokens, index) => {
      const colon = topLevelTokenIndex(parameterTokens, ":");
      if (
        colon <= 0 ||
        parameterTokens[colon - 1]?.type !== "identifier" ||
        colon === parameterTokens.length - 1
      ) {
        throw new Error(
          `${sourcePath}#${functionName}: unsupported Rust ABI parameter ${index}`,
        );
      }
      return {
        index,
        name: parameterTokens[colon - 1].value,
        typeTokens: parameterTokens.slice(colon + 1),
      };
    },
  );
}

function cppAbiParameters(tokens, open, close) {
  const parts = splitAbiTokenList(tokens.slice(open + 1, close));
  if (
    parts.length === 1 &&
    parts[0].length === 1 &&
    parts[0][0].value === "void"
  ) {
    return [];
  }
  return parts.map((parameterTokens, index) => {
    const nameIndex = cppParameterNameIndex(parameterTokens);
    return {
      index,
      name: nameIndex === -1 ? null : parameterTokens[nameIndex].value,
      typeTokens:
        nameIndex === -1
          ? parameterTokens
          : parameterTokens.filter((_, tokenIndex) => tokenIndex !== nameIndex),
    };
  });
}

function topLevelAbiStatementEnd(tokens, start) {
  const depth = { "(": 0, "[": 0, "{": 0, "<": 0 };
  const closeToOpen = { ")": "(", "]": "[", "}": "{", ">": "<" };
  for (let index = start; index < tokens.length; index += 1) {
    const value = tokens[index].value;
    if (value === ";" && Object.values(depth).every((entry) => entry === 0)) {
      return index;
    }
    if (Object.hasOwn(depth, value)) depth[value] += 1;
    if (Object.hasOwn(closeToOpen, value)) {
      const open = closeToOpen[value];
      if (depth[open] > 0) depth[open] -= 1;
    }
  }
  return -1;
}

function cppAggregateFields(tokens, definition) {
  const fields = [];
  for (const [index, declaration] of splitTopLevelAbiTokens(
    tokens.slice(definition.bodyOpen + 1, definition.bodyClose),
    ";",
  ).entries()) {
    const nameIndex = cppParameterNameIndex(declaration);
    if (nameIndex === -1) continue;
    const name = declaration[nameIndex].value;
    const typeTokens = declaration.filter(
      (_, tokenIndex) => tokenIndex !== nameIndex,
    );
    fields.push({
      index,
      name,
      pointerDepth: abiPointerShape("c++", typeTokens).pointerDepth,
      type: abiTypeDescriptor(typeTokens),
      typeTokens,
      valueKind: abiTypeKind("c++", typeTokens),
    });
  }
  return fields;
}

/**
 * Parse the named aggregate layouts and callback typedef signatures that the
 * public ABI definitions bind by name. The registry remains declaration-only:
 * a function body annotation still decides which aggregate members it writes
 * and whether a callback is ever delivered.
 */
export function scanCppAbiTypeRegistry(text, sourcePath = "<native-header>") {
  const tokens = lexCpp(text, sourcePath);
  const aggregates = {};
  for (const definition of cppTypeDefinitions(tokens)) {
    if (
      !/^Ex(?:Hermes|Worklet|Motion)[A-Za-z0-9_]*$/u.test(definition.name) &&
      definition.name !== "ExactModuleRunnerHandle"
    ) {
      continue;
    }
    const alias = tokens[definition.bodyClose + 1];
    const schemaName =
      alias?.type === "identifier" ? alias.value : definition.name;
    if (aggregates[schemaName]) {
      throw new Error(`${sourcePath}: duplicate ABI aggregate ${schemaName}`);
    }
    aggregates[schemaName] = {
      fields: cppAggregateFields(tokens, definition).map((field) => ({
        index: field.index,
        name: field.name,
        pointerDepth: field.pointerDepth,
        type: field.type,
        valueKind: field.valueKind,
      })),
      name: schemaName,
      sourceRef: sourceSymbol(sourcePath, schemaName),
    };
  }

  const callbacks = {};
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index].value !== "typedef") continue;
    const statementEnd = topLevelAbiStatementEnd(tokens, index + 1);
    if (statementEnd === -1) {
      throw new Error(`${sourcePath}: unterminated ABI typedef`);
    }
    let declaratorOpen = -1;
    let aggregateDepth = 0;
    for (let cursor = index + 1; cursor < statementEnd - 4; cursor += 1) {
      if (tokens[cursor].value === "{") {
        aggregateDepth += 1;
        continue;
      }
      if (tokens[cursor].value === "}") {
        aggregateDepth -= 1;
        continue;
      }
      if (
        aggregateDepth === 0 &&
        tokens[cursor].value === "(" &&
        tokens[cursor + 1]?.value === "*" &&
        tokens[cursor + 2]?.type === "identifier" &&
        tokens[cursor + 3]?.value === ")" &&
        tokens[cursor + 4]?.value === "("
      ) {
        declaratorOpen = cursor;
        break;
      }
    }
    if (declaratorOpen === -1) {
      index = statementEnd;
      continue;
    }
    const name = tokens[declaratorOpen + 2].value;
    const parametersOpen = declaratorOpen + 4;
    const parametersClose = matchingToken(tokens, parametersOpen, "(", ")");
    if (parametersClose === -1 || parametersClose >= statementEnd) {
      throw new Error(`${sourcePath}: malformed ABI callback typedef ${name}`);
    }
    if (callbacks[name]) {
      throw new Error(`${sourcePath}: duplicate ABI callback typedef ${name}`);
    }
    callbacks[name] = {
      language: "c++",
      name,
      parameters: cppAbiParameters(tokens, parametersOpen, parametersClose).map(
        (parameter) => ({
          index: parameter.index,
          name: parameter.name,
          type: abiTypeDescriptor(parameter.typeTokens),
        }),
      ),
      return: abiTypeDescriptor(tokens.slice(index + 1, declaratorOpen)),
      sourceRef: sourceSymbol(sourcePath, name),
    };
    index = statementEnd;
  }

  return {
    aggregates: Object.fromEntries(
      Object.entries(aggregates).sort(([left], [right]) =>
        compareText(left, right),
      ),
    ),
    callbacks: Object.fromEntries(
      Object.entries(callbacks).sort(([left], [right]) =>
        compareText(left, right),
      ),
    ),
    schema: C_ABI_TYPE_REGISTRY_SCHEMA,
    sourcePath,
  };
}

function descriptorTokens(descriptor) {
  return (descriptor?.tokens ?? []).map((value) => ({
    type: /^[A-Za-z_][A-Za-z0-9_]*$/u.test(value)
      ? "identifier"
      : "punctuation",
    value,
  }));
}

function registryAggregateName(typeTokens, typeRegistry) {
  if (typeRegistry?.schema !== C_ABI_TYPE_REGISTRY_SCHEMA) return null;
  const names = typeTokens
    .filter((token) => token.type === "identifier")
    .map((token) => token.value)
    .filter((name) => Object.hasOwn(typeRegistry.aggregates, name));
  return names.length === 1 ? names[0] : null;
}

function cppInlineCallbackSignature(typeTokens) {
  for (let index = 0; index < typeTokens.length - 4; index += 1) {
    if (
      typeTokens[index].value !== "(" ||
      typeTokens[index + 1]?.value !== "*" ||
      typeTokens[index + 2]?.value !== ")" ||
      typeTokens[index + 3]?.value !== "("
    ) {
      continue;
    }
    const close = matchingToken(typeTokens, index + 3, "(", ")");
    if (close === -1) return null;
    return {
      language: "c++",
      parameters: cppAbiParameters(typeTokens, index + 3, close),
      returnTokens: typeTokens.slice(0, index),
      sourceRef: null,
    };
  }
  return null;
}

function rustInlineCallbackSignature(typeTokens) {
  const functionIndex = typeTokens.findIndex((token) => token.value === "fn");
  if (functionIndex === -1 || typeTokens[functionIndex + 1]?.value !== "(") {
    return null;
  }
  const close = matchingToken(typeTokens, functionIndex + 1, "(", ")");
  if (close === -1) return null;
  const parameters = splitAbiTokenList(
    typeTokens.slice(functionIndex + 2, close),
  ).map((parameterTokens, index) => {
    let colon = -1;
    for (let cursor = 1; cursor < parameterTokens.length - 1; cursor += 1) {
      if (
        parameterTokens[cursor].value === ":" &&
        parameterTokens[cursor - 1]?.type === "identifier" &&
        parameterTokens[cursor - 1]?.value !== ":" &&
        parameterTokens[cursor + 1]?.value !== ":"
      ) {
        colon = cursor;
        break;
      }
    }
    return {
      index,
      name:
        colon > 0 && parameterTokens[colon - 1]?.type === "identifier"
          ? parameterTokens[colon - 1].value
          : null,
      typeTokens:
        colon > 0 ? parameterTokens.slice(colon + 1) : parameterTokens,
    };
  });
  let returnTokens = [];
  if (
    typeTokens[close + 1]?.value === "-" &&
    typeTokens[close + 2]?.value === ">"
  ) {
    returnTokens = typeTokens.slice(close + 3);
    while (returnTokens.at(-1)?.value === ">") returnTokens.pop();
  }
  return {
    language: "rust",
    parameters,
    returnTokens,
    sourceRef: null,
  };
}

function callbackSignatureForParameter(language, parameter, typeRegistry) {
  const inline =
    language === "rust"
      ? rustInlineCallbackSignature(parameter.typeTokens)
      : cppInlineCallbackSignature(parameter.typeTokens);
  if (inline) return inline;
  if (typeRegistry?.schema !== C_ABI_TYPE_REGISTRY_SCHEMA) return null;
  const callbackNames = parameter.typeTokens
    .filter((token) => token.type === "identifier")
    .map((token) => token.value)
    .filter((name) => Object.hasOwn(typeRegistry.callbacks, name));
  if (callbackNames.length !== 1) return null;
  const callback = typeRegistry.callbacks[callbackNames[0]];
  return {
    language: callback.language,
    name: callback.name,
    parameters: callback.parameters.map((entry) => ({
      index: entry.index,
      name: entry.name,
      typeTokens: descriptorTokens(entry.type),
    })),
    returnTokens: descriptorTokens(callback.return),
    sourceRef: callback.sourceRef,
  };
}

function aggregateLengthPairs(schema) {
  const pairs = new Map();
  for (const field of schema.fields) {
    if (field.pointerDepth === 0) continue;
    const candidates = new Set(lengthCandidates(field.name));
    if (field.name === "data") candidates.add("length");
    if (field.name.endsWith("_data")) {
      candidates.add(`${field.name.slice(0, -"_data".length)}_length`);
    }
    if (field.name.endsWith("ies")) {
      candidates.add(`${field.name.slice(0, -3)}y_count`);
    }
    const next = schema.fields[field.index + 1];
    const length =
      schema.fields.find((candidate) => candidates.has(candidate.name)) ??
      (next && /(?:^|_)(?:len|length|size|count)$/u.test(next.name)
        ? next
        : null);
    if (length) pairs.set(field.name, length.name);
  }
  return pairs;
}

function aggregateOutputChannels({
  alias,
  elements = [],
  memberOwnership,
  members,
  role,
  rootParameter,
  schemaName,
  selectorPrefix,
  typeRegistry,
}) {
  const schema = typeRegistry?.aggregates?.[schemaName];
  if (!schema) return null;
  const selected = members === "*" ? null : new Set(members);
  if (selected) {
    const fieldNames = new Set(schema.fields.map((field) => field.name));
    for (const member of selected) {
      if (!fieldNames.has(member)) {
        throw new Error(`ABI aggregate ${schemaName} has no member ${member}`);
      }
    }
  }
  const expandedElements = new Set(elements);
  const rootAlias = alias;
  const output = [];
  const walk = (currentSchemaName, currentAlias, selectedMembers, ancestry) => {
    if (ancestry.has(currentSchemaName)) {
      throw new Error(`recursive ABI aggregate schema ${currentSchemaName}`);
    }
    const currentSchema = typeRegistry.aggregates[currentSchemaName];
    if (!currentSchema) return false;
    const nextAncestry = new Set(ancestry);
    nextAncestry.add(currentSchemaName);
    const pairs = aggregateLengthPairs(currentSchema);
    const pairedLengths = new Set(pairs.values());
    for (const field of currentSchema.fields) {
      if (selectedMembers && !selectedMembers.has(field.name)) continue;
      if (pairedLengths.has(field.name)) continue;
      const fieldAlias = `${currentAlias}.${field.name}`;
      const typeTokens = descriptorTokens(field.type);
      const nestedSchema = registryAggregateName(typeTokens, typeRegistry);
      const pointer = abiPointerShape("c++", typeTokens);
      const lengthMember = pairs.get(field.name);
      if (pointer.pointerDepth === 0 && nestedSchema) {
        walk(nestedSchema, fieldAlias, null, nextAncestry);
        continue;
      }
      if (pointer.pointerDepth > 0 && nestedSchema) {
        output.push({
          aggregateSchema: currentSchemaName,
          alias: fieldAlias,
          elementSchema: nestedSchema,
          ...(lengthMember
            ? { lengthParameter: `${currentAlias}.${lengthMember}` }
            : {}),
          kind: "aggregate",
          memberPath: fieldAlias.slice(alias.length + 1),
          ownership: structuredClone(memberOwnership),
          parameter: fieldAlias,
          role,
          rootParameter,
          selector: `${selectorPrefix}${fieldAlias}`,
        });
        const relativeFieldAlias = fieldAlias.slice(rootAlias.length + 1);
        if (expandedElements.has(relativeFieldAlias)) {
          walk(nestedSchema, `${fieldAlias}[]`, null, nextAncestry);
        }
        continue;
      }
      const kind =
        pointer.pointerDepth > 0 && lengthMember
          ? "buffer"
          : pointer.pointerDepth > 0
            ? "pointer"
            : abiTypeKind("c++", typeTokens);
      output.push({
        aggregateSchema: currentSchemaName,
        alias: fieldAlias,
        ...(lengthMember
          ? { lengthParameter: `${currentAlias}.${lengthMember}` }
          : {}),
        kind,
        memberPath: fieldAlias.slice(alias.length + 1),
        ownership:
          pointer.pointerDepth > 0
            ? structuredClone(memberOwnership)
            : { kind: "not-applicable" },
        parameter: fieldAlias,
        role,
        rootParameter,
        selector: `${selectorPrefix}${fieldAlias}`,
      });
    }
    return true;
  };
  walk(schemaName, alias, selected, new Set());
  return output;
}

function bindCallbackBufferLengthPairs(parameters) {
  const pairs = [];
  for (const parameter of parameters) {
    if (parameter.pointerDepth === 0) continue;
    const candidates = new Set(lengthCandidates(parameter.name));
    if (parameter.name === "data") candidates.add("length");
    if (parameter.name?.endsWith("_data")) {
      candidates.add(`${parameter.name.slice(0, -"_data".length)}_length`);
    }
    let length = parameters.find((candidate) => candidates.has(candidate.name));
    if (!length) {
      const next = parameters[parameter.index + 1];
      const byteLike = /(?:u8|uint8_t|char|void|byte)/u.test(
        parameter.type.canonical,
      );
      if (byteLike && /^(?:len|length|size|count)$/u.test(next?.name ?? "")) {
        length = next;
      }
    }
    if (!length || length.direction !== parameter.direction) continue;
    parameter.valueKind = "buffer";
    length.valueKind = "length";
    pairs.push({
      bufferParameter: parameter.index,
      direction: parameter.direction,
      lengthParameter: length.index,
    });
  }
  return pairs;
}

function callbackParameterContract(
  language,
  parameter,
  { hasOuterContext, typeRegistry },
) {
  const pointer = abiPointerShape(language, parameter.typeTokens);
  const typeValues = new Set(parameter.typeTokens.map((token) => token.value));
  const typeIdentifiers = new Set(
    parameter.typeTokens
      .filter((token) => token.type === "identifier")
      .map((token) => token.value),
  );
  const voidLike = typeValues.has("void") || typeValues.has("c_void");
  let direction;
  if (pointer.pointerDepth === 0 || pointer.constPointee) {
    direction = "native-to-embedder";
  } else if (
    parameter.name === "context" ||
    typeIdentifiers.has("ExactHermesRuntime") ||
    (voidLike && hasOuterContext)
  ) {
    direction = "native-to-embedder";
  } else if (
    /^(?:out(?:_|$)|result_(?:data|length)$)/u.test(parameter.name ?? "")
  ) {
    direction = "embedder-to-native";
  } else {
    direction = "unknown";
  }
  const pointeeKind = abiTypeKind(
    language,
    parameter.typeTokens.filter(
      (token) => !new Set(["*", "const", "mut"]).has(token.value),
    ),
  );
  const aggregateSchema = registryAggregateName(
    parameter.typeTokens,
    typeRegistry,
  );
  return {
    ...(aggregateSchema ? { aggregateSchema } : {}),
    direction,
    index: parameter.index,
    name: parameter.name,
    ownership:
      pointer.pointerDepth === 0
        ? { kind: "not-applicable" }
        : direction === "native-to-embedder"
          ? { kind: "borrowed" }
          : direction === "embedder-to-native" && pointer.pointerDepth === 1
            ? { kind: "caller-storage" }
            : { kind: "unknown" },
    pointerDepth: pointer.pointerDepth,
    role:
      direction === "native-to-embedder"
        ? "payload"
        : direction === "embedder-to-native"
          ? "output"
          : "unknown",
    type: abiTypeDescriptor(parameter.typeTokens),
    valueKind:
      pointer.pointerDepth > 0
        ? direction === "embedder-to-native" &&
          pointer.pointerDepth === 1 &&
          pointeeKind === "scalar"
          ? "scalar"
          : "pointer"
        : aggregateSchema
          ? "aggregate"
          : abiTypeKind(language, parameter.typeTokens),
  };
}

function bindCallbackParameter({
  annotation,
  language,
  outerParameter,
  rawParameter,
  rawParameters,
  typeRegistry,
}) {
  const signature = callbackSignatureForParameter(
    language,
    rawParameter,
    typeRegistry,
  );
  if (!signature) {
    return {
      outputChannels: [],
      unresolved: [
        `callback-signature:${outerParameter.name ?? outerParameter.index}`,
      ],
    };
  }
  const hasOuterContext = rawParameters.some(
    (parameter) => parameter.name === "context",
  );
  const callbackParameters = signature.parameters.map((parameter) =>
    callbackParameterContract(signature.language, parameter, {
      hasOuterContext,
      typeRegistry,
    }),
  );
  const bufferLengthPairs = bindCallbackBufferLengthPairs(callbackParameters);
  if (annotation?.output !== undefined) {
    const output = callbackParameters[annotation.output];
    if (!output || output.direction !== "embedder-to-native") {
      throw new Error(
        `@abi-callback output ${annotation.output} is not an embedder-to-native parameter of ${outerParameter.name ?? outerParameter.index}`,
      );
    }
    output.ownership =
      annotation.ownership === "native-consumes"
        ? { kind: "native-consumes" }
        : { kind: annotation.ownership };
    if (annotation.kind) output.valueKind = annotation.kind;
    if (annotation.fixedLength) output.fixedLength = annotation.fixedLength;
  }
  const returnKind = abiTypeKind(signature.language, signature.returnTokens, {
    isReturn: true,
  });
  const returnContract = {
    direction: returnKind === "void" ? "none" : "embedder-to-native",
    kind: returnKind,
    ownership:
      returnKind === "pointer"
        ? { kind: "unknown" }
        : { kind: "not-applicable" },
    role: returnKind === "void" ? "none" : "return",
    type: abiTypeDescriptor(signature.returnTokens),
  };
  if (annotation?.returnOwnership === "native-consumes") {
    if (returnKind !== "pointer") {
      throw new Error(
        `@abi-callback return ownership requires a pointer return for ${outerParameter.name ?? outerParameter.index}`,
      );
    }
    returnContract.ownership = { kind: "native-consumes" };
  }
  const outputChannels = [];
  if (annotation?.delivery !== "none") {
    for (const parameter of callbackParameters) {
      if (
        parameter.direction !== "native-to-embedder" ||
        (parameter.valueKind === "length" &&
          bufferLengthPairs.some(
            (pair) => pair.lengthParameter === parameter.index,
          ))
      ) {
        continue;
      }
      const alias = `${outerParameter.name ?? outerParameter.index}/${parameter.index}`;
      if (parameter.aggregateSchema && parameter.pointerDepth === 0) {
        const expanded = aggregateOutputChannels({
          alias,
          elements: [],
          memberOwnership: { kind: "borrowed" },
          members: "*",
          role: "callback-payload",
          rootParameter: outerParameter.name ?? outerParameter.index,
          schemaName: parameter.aggregateSchema,
          selectorPrefix: "callback:",
          typeRegistry,
        });
        if (expanded) {
          for (const channel of expanded) {
            channel.callbackDirection = "native-to-embedder";
            outputChannels.push(channel);
          }
        }
        continue;
      }
      const pair = bufferLengthPairs.find(
        (candidate) => candidate.bufferParameter === parameter.index,
      );
      outputChannels.push({
        alias,
        callbackDirection: "native-to-embedder",
        kind: parameter.valueKind,
        ...(pair
          ? {
              lengthParameter: `${outerParameter.name ?? outerParameter.index}/${pair.lengthParameter}`,
            }
          : {}),
        ownership: structuredClone(parameter.ownership),
        parameter: outerParameter.name ?? outerParameter.index,
        role: "callback-payload",
        rootParameter: outerParameter.name ?? outerParameter.index,
        selector: `callback:${alias}`,
      });
    }
  }

  const unresolved = [];
  for (const parameter of callbackParameters) {
    if (parameter.direction === "unknown") {
      unresolved.push(
        `callback-direction:${outerParameter.name ?? outerParameter.index}/${parameter.index}`,
      );
    }
    if (parameter.ownership.kind === "unknown") {
      unresolved.push(
        `callback-parameter-ownership:${outerParameter.name ?? outerParameter.index}/${parameter.index}`,
      );
    }
    if (parameter.valueKind === "aggregate" && !parameter.aggregateSchema) {
      unresolved.push(
        `callback-aggregate-schema:${outerParameter.name ?? outerParameter.index}/${parameter.index}`,
      );
    }
  }
  if (returnKind === "unknown") {
    unresolved.push(
      `callback-return-kind:${outerParameter.name ?? outerParameter.index}`,
    );
  }
  if (returnContract.ownership.kind === "unknown") {
    unresolved.push(
      `callback-return-pointer-ownership:${outerParameter.name ?? outerParameter.index}`,
    );
  }
  outerParameter.role =
    annotation?.delivery === "none" ? "input" : "callback-payload";
  outerParameter.callbackContract = {
    bufferLengthPairs,
    delivery: annotation?.delivery ?? "invoked",
    ...(signature.name ? { name: signature.name } : {}),
    outputChannels: structuredClone(outputChannels),
    parameters: callbackParameters,
    return: returnContract,
    ...(signature.sourceRef ? { sourceRef: signature.sourceRef } : {}),
    status: unresolved.length === 0 ? "resolved" : "unresolved",
    unresolved,
  };
  return { outputChannels, unresolved };
}

const ABI_CONSUMED_INPUT_POINTERS = new Set([
  "ex_hermes_destroy:runtime",
  "ex_hermes_free_string:value",
  "ex_host_free_buffer:buf",
  "ex_host_free_string:ptr",
  "ex_host_fs_close:file",
  "ex_worklet_destroy:handle",
]);

const ABI_EXACT_BORROWED_INPUT_POINTERS = new Set([
  "ex_android_initialize:application_context",
  "ex_android_initialize:java_vm",
  "ex_hermes_set_kernel_handle:kernel_handle",
]);

function sourceProvenAbiInputPointer({
  functionName,
  hasCallbackParameter,
  parameter,
  pointer,
}) {
  if (pointer.pointerDepth === 0) return null;
  const key = `${functionName}:${parameter.name ?? parameter.index}`;
  if (pointer.pointerDepth === 1 && ABI_CONSUMED_INPUT_POINTERS.has(key)) {
    return { ownership: { kind: "callee-consumes" } };
  }

  const typeIdentifiers = new Set(
    parameter.typeTokens
      .filter((token) => token.type === "identifier")
      .map((token) => token.value),
  );
  const typeValues = new Set(parameter.typeTokens.map((token) => token.value));
  const voidLike = typeValues.has("void") || typeValues.has("c_void");
  if (
    pointer.pointerDepth === 1 &&
    (typeIdentifiers.has("ExactHermesRuntime") ||
      typeIdentifiers.has("ExactFileHandle"))
  ) {
    return { ownership: { kind: "borrowed" } };
  }
  if (
    pointer.pointerDepth === 1 &&
    voidLike &&
    ABI_EXACT_BORROWED_INPUT_POINTERS.has(key)
  ) {
    return { ownership: { kind: "borrowed" } };
  }
  if (
    pointer.pointerDepth === 1 &&
    voidLike &&
    hasCallbackParameter &&
    parameter.name === "context"
  ) {
    return { ownership: { kind: "borrowed" } };
  }
  return null;
}

function abiParameterContract(
  language,
  parameter,
  { functionName, hasCallbackParameter },
) {
  const pointer = abiPointerShape(language, parameter.typeTokens);
  const callback = isAbiCallbackType(parameter.typeTokens, parameter.name);
  const sourceProvenInput = sourceProvenAbiInputPointer({
    functionName,
    hasCallbackParameter,
    parameter,
    pointer,
  });
  let role;
  if (callback) role = "callback";
  else if (pointer.pointerDepth === 0) role = "input";
  else if (pointer.constPointee) role = "input";
  else if (sourceProvenInput) role = "input";
  else if (/^out(?:_|$)/u.test(parameter.name ?? "")) role = "output";
  else if (/^inout(?:_|$)/u.test(parameter.name ?? "")) role = "inout";
  else role = "unknown";

  let ownership = { kind: "not-applicable" };
  if (callback || (role === "input" && pointer.pointerDepth > 0)) {
    ownership = sourceProvenInput?.ownership ?? { kind: "borrowed" };
  } else if (
    new Set(["output", "inout"]).has(role) &&
    pointer.pointerDepth === 1
  ) {
    ownership = { kind: "caller-storage" };
  } else if (pointer.pointerDepth > 0) {
    ownership = { kind: "unknown" };
  }
  const pointeeKind = abiTypeKind(
    language,
    parameter.typeTokens.filter(
      (token) => !new Set(["*", "const", "mut"]).has(token.value),
    ),
  );

  return {
    index: parameter.index,
    name: parameter.name,
    ownership,
    pointerDepth: pointer.pointerDepth,
    role,
    type: abiTypeDescriptor(parameter.typeTokens),
    valueKind: callback
      ? "callback"
      : pointer.pointerDepth > 0
        ? new Set(["output", "inout"]).has(role) &&
          pointer.pointerDepth === 1 &&
          pointeeKind === "scalar"
          ? "scalar"
          : "pointer"
        : abiTypeKind(language, parameter.typeTokens),
  };
}

function lengthCandidates(parameterName) {
  if (!parameterName) return [];
  return [
    `${parameterName}_len`,
    `${parameterName}_length`,
    `${parameterName}_size`,
    `${parameterName}_count`,
  ];
}

function bindAbiBufferLengthPairs(parameters) {
  const pairs = [];
  const byName = new Map(
    parameters
      .filter((parameter) => parameter.name !== null)
      .map((parameter) => [parameter.name, parameter]),
  );
  for (const parameter of parameters) {
    if (parameter.pointerDepth === 0 || parameter.valueKind === "callback")
      continue;
    let length = lengthCandidates(parameter.name)
      .map((candidate) => byName.get(candidate))
      .find(Boolean);
    if (!length) {
      const next = parameters[parameter.index + 1];
      const byteLike = /(?:u8|uint8_t|char|void|byte)/u.test(
        parameter.type.canonical,
      );
      if (byteLike && /^(?:len|length|size|count)$/u.test(next?.name ?? ""))
        length = next;
    }
    if (!length) continue;
    parameter.valueKind = "buffer";
    length.valueKind = "length";
    const direction =
      parameter.role === "input" && length.role === "input"
        ? "input"
        : parameter.role === "output" &&
            new Set(["input", "output"]).has(length.role)
          ? "output"
          : "unknown";
    pairs.push({
      bufferParameter: parameter.name,
      direction,
      lengthParameter: length.name,
    });
  }
  return pairs;
}

function parseAbiOutputAnnotations(text, sourcePath) {
  const byFunction = new Map();
  for (const [lineIndex, line] of text.split(/\r?\n/u).entries()) {
    const match = line.match(
      /^\s*\/\/\/?\s*@abi-output\s+(ex_(?:android|host|hermes|worklet)_[A-Za-z0-9_]+)\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)\s*$/u,
    );
    if (!match) continue;
    const [, functionName, parameterName, rawFields] = match;
    const fields = new Map();
    for (const field of rawFields.split(/\s+/u)) {
      const separator = field.indexOf("=");
      if (separator <= 0 || separator === field.length - 1) {
        throw new Error(
          `${sourcePath}:${lineIndex + 1}: malformed @abi-output field ${field}`,
        );
      }
      const key = field.slice(0, separator);
      const value = field.slice(separator + 1);
      if (
        !new Set([
          "elements",
          "kind",
          "length",
          "member-ownership",
          "members",
          "ownership",
          "role",
          "schema",
        ]).has(key) ||
        fields.has(key)
      ) {
        throw new Error(
          `${sourcePath}:${lineIndex + 1}: unsupported or duplicate @abi-output field ${key}`,
        );
      }
      fields.set(key, value);
    }
    if (
      !new Set(["output", "inout"]).has(fields.get("role")) ||
      !new Set(["aggregate", "buffer", "pointer", "scalar"]).has(
        fields.get("kind"),
      ) ||
      !/^(?:caller-frees:[A-Za-z_][A-Za-z0-9_]*|caller-storage|borrowed)$/u.test(
        fields.get("ownership") ?? "",
      ) ||
      (fields.has("member-ownership") &&
        !/^(?:caller-frees:[A-Za-z_][A-Za-z0-9_]*|caller-storage|borrowed)$/u.test(
          fields.get("member-ownership"),
        )) ||
      (fields.get("kind") === "aggregate" &&
        (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(fields.get("schema") ?? "") ||
          !/^(?:\*|[A-Za-z_][A-Za-z0-9_]*(?:,[A-Za-z_][A-Za-z0-9_]*)*)$/u.test(
            fields.get("members") ?? "",
          ) ||
          (fields.has("elements") &&
            !/^[A-Za-z_][A-Za-z0-9_]*(?:,[A-Za-z_][A-Za-z0-9_]*)*$/u.test(
              fields.get("elements"),
            )) ||
          fields.has("length"))) ||
      (fields.get("kind") !== "aggregate" &&
        (fields.has("elements") ||
          fields.has("schema") ||
          fields.has("members") ||
          fields.has("member-ownership")))
    ) {
      throw new Error(
        `${sourcePath}:${lineIndex + 1}: incomplete or invalid @abi-output contract`,
      );
    }
    const annotations = byFunction.get(functionName) ?? [];
    if (
      annotations.some(
        (annotation) => annotation.parameterName === parameterName,
      )
    ) {
      throw new Error(
        `${sourcePath}:${lineIndex + 1}: duplicate @abi-output ${functionName}.${parameterName}`,
      );
    }
    annotations.push({
      fields: Object.fromEntries(fields),
      line: lineIndex + 1,
      parameterName,
    });
    byFunction.set(functionName, annotations);
  }
  return byFunction;
}

function parseAbiCallbackAnnotations(text, sourcePath) {
  const byFunction = new Map();
  for (const [lineIndex, line] of text.split(/\r?\n/u).entries()) {
    const match = line.match(
      /^\s*\/\/\/?\s*@abi-callback\s+(ex_(?:android|host|hermes|worklet)_[A-Za-z0-9_]+)\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)\s*$/u,
    );
    if (!match) continue;
    const [, functionName, parameterName, rawFields] = match;
    const fields = new Map();
    for (const field of rawFields.split(/\s+/u)) {
      const separator = field.indexOf("=");
      if (separator <= 0 || separator === field.length - 1) {
        throw new Error(
          `${sourcePath}:${lineIndex + 1}: malformed @abi-callback field ${field}`,
        );
      }
      const key = field.slice(0, separator);
      const value = field.slice(separator + 1);
      if (
        !new Set([
          "delivery",
          "fixed-length",
          "kind",
          "output",
          "ownership",
          "return-ownership",
        ]).has(key) ||
        fields.has(key)
      ) {
        throw new Error(
          `${sourcePath}:${lineIndex + 1}: unsupported or duplicate @abi-callback field ${key}`,
        );
      }
      fields.set(key, value);
    }
    const deliveryOnly = fields.size === 1 && fields.get("delivery") === "none";
    const returnOnly =
      fields.size === 1 && fields.get("return-ownership") === "native-consumes";
    const outputContract =
      fields.has("output") &&
      /^\d+$/u.test(fields.get("output")) &&
      new Set(["borrowed", "caller-storage", "native-consumes"]).has(
        fields.get("ownership"),
      ) &&
      (!fields.has("kind") ||
        new Set(["buffer", "pointer", "scalar"]).has(fields.get("kind"))) &&
      (!fields.has("fixed-length") ||
        (/^[1-9]\d*$/u.test(fields.get("fixed-length")) &&
          fields.get("kind") === "buffer")) &&
      !fields.has("delivery") &&
      !fields.has("return-ownership") &&
      [...fields.keys()].every((key) =>
        new Set(["fixed-length", "kind", "output", "ownership"]).has(key),
      );
    if (!deliveryOnly && !returnOnly && !outputContract) {
      throw new Error(
        `${sourcePath}:${lineIndex + 1}: incomplete or invalid @abi-callback contract`,
      );
    }
    const annotations = byFunction.get(functionName) ?? [];
    if (
      annotations.some(
        (annotation) => annotation.parameterName === parameterName,
      )
    ) {
      throw new Error(
        `${sourcePath}:${lineIndex + 1}: duplicate @abi-callback ${functionName}.${parameterName}`,
      );
    }
    annotations.push({
      ...(deliveryOnly ? { delivery: "none" } : {}),
      ...(fields.has("fixed-length")
        ? { fixedLength: Number(fields.get("fixed-length")) }
        : {}),
      ...(fields.has("kind") ? { kind: fields.get("kind") } : {}),
      line: lineIndex + 1,
      ...(fields.has("output") ? { output: Number(fields.get("output")) } : {}),
      ...(fields.has("ownership")
        ? { ownership: fields.get("ownership") }
        : {}),
      parameterName,
      ...(returnOnly
        ? { returnOwnership: fields.get("return-ownership") }
        : {}),
    });
    byFunction.set(functionName, annotations);
  }
  return byFunction;
}

function annotatedOwnership(value) {
  return value.startsWith("caller-frees:")
    ? {
        kind: "caller-owned",
        releaseFunction: value.slice("caller-frees:".length),
      }
    : { kind: value };
}

function publicAbiReturnOwnership(
  functionName,
  language,
  returnTokens,
  returnOwnershipProof,
) {
  const type = abiTypeDescriptor(returnTokens).canonical;
  const isCharacterPointer =
    type === "char *" ||
    type === "* mut c_char" ||
    type === "* mut std : : ffi : : c_char";
  if (isCharacterPointer) {
    return {
      kind: "caller-owned",
      releaseFunction:
        functionName.startsWith("ex_host_")
          ? "ex_host_free_string"
          : "ex_hermes_free_string",
    };
  }
  if (language === "rust" && type === "* mut u8") {
    return {
      kind: "caller-owned",
      releaseFunction: "ex_host_free_buffer",
    };
  }
  if (language === "rust" && type === "* mut ExactFileHandle") {
    return {
      kind: "caller-owned",
      releaseFunction: "ex_host_fs_close",
    };
  }
  if (language === "c++" && type === "ExactHermesRuntime *") {
    return {
      kind: "caller-owned",
      releaseFunction: functionName.startsWith("ex_worklet_")
        ? "ex_worklet_destroy"
        : "ex_hermes_destroy",
    };
  }
  return { kind: "unknown" };
}

function outputSelector(parameterName) {
  return `out:${parameterName.replace(/^out_/u, "")}`;
}

function applyAbiOutputAnnotations(
  parameters,
  pairs,
  annotations,
  sourcePath,
  functionName,
) {
  const byName = new Map(
    parameters
      .filter((parameter) => parameter.name !== null)
      .map((parameter) => [parameter.name, parameter]),
  );
  for (const annotation of annotations) {
    const parameter = byName.get(annotation.parameterName);
    if (!parameter || parameter.pointerDepth === 0) {
      throw new Error(
        `${sourcePath}:${annotation.line}: @abi-output does not name a pointer parameter of ${functionName}`,
      );
    }
    const { fields } = annotation;
    parameter.role = fields.role;
    parameter.valueKind = fields.kind;
    parameter.ownership = annotatedOwnership(fields.ownership);
    if (fields.kind === "aggregate") {
      parameter.aggregateContract = {
        elements:
          fields.elements === undefined ? [] : fields.elements.split(","),
        memberOwnership: annotatedOwnership(
          fields["member-ownership"] ?? fields.ownership,
        ),
        members: fields.members === "*" ? "*" : fields.members.split(","),
        schema: fields.schema,
      };
    }
    if (fields.length) {
      const length = byName.get(fields.length);
      if (!length) {
        throw new Error(
          `${sourcePath}:${annotation.line}: @abi-output length ${fields.length} is absent from ${functionName}`,
        );
      }
      length.valueKind = "length";
      if (
        !pairs.some(
          (pair) =>
            pair.bufferParameter === parameter.name &&
            pair.lengthParameter === length.name,
        )
      ) {
        pairs.push({
          bufferParameter: parameter.name,
          direction: fields.role,
          lengthParameter: length.name,
        });
      }
    }
  }
}

function buildHostAbiOutputContract({
  annotations,
  callbackAnnotations,
  functionName,
  language,
  parameters: rawParameters,
  returnTokens,
  returnOwnershipProof = null,
  sourceRef,
  typeRegistry,
}) {
  const hasCallbackParameter = rawParameters.some((parameter) =>
    isAbiCallbackType(parameter.typeTokens, parameter.name),
  );
  const parameters = rawParameters.map((parameter) =>
    abiParameterContract(language, parameter, {
      functionName,
      hasCallbackParameter,
    }),
  );
  const bufferLengthPairs = bindAbiBufferLengthPairs(parameters);
  applyAbiOutputAnnotations(
    parameters,
    bufferLengthPairs,
    annotations,
    sourceRef.split("#")[0],
    functionName,
  );
  const callbackAnnotationsByParameter = new Map(
    callbackAnnotations.map((annotation) => [
      annotation.parameterName,
      annotation,
    ]),
  );
  const callbackBindings = new Map();
  for (const rawParameter of rawParameters) {
    if (!isAbiCallbackType(rawParameter.typeTokens, rawParameter.name))
      continue;
    const parameter = parameters[rawParameter.index];
    const annotation = callbackAnnotationsByParameter.get(parameter.name);
    callbackAnnotationsByParameter.delete(parameter.name);
    callbackBindings.set(
      parameter.index,
      bindCallbackParameter({
        annotation,
        language,
        outerParameter: parameter,
        rawParameter,
        rawParameters,
        typeRegistry,
      }),
    );
  }
  if (callbackAnnotationsByParameter.size > 0) {
    const [parameterName, annotation] = callbackAnnotationsByParameter
      .entries()
      .next().value;
    throw new Error(
      `${sourceRef.split("#")[0]}:${annotation.line}: @abi-callback does not name a callback parameter ${functionName}.${parameterName}`,
    );
  }
  bufferLengthPairs.sort((left, right) =>
    compareText(left.bufferParameter ?? "", right.bufferParameter ?? ""),
  );

  const returnKind = abiTypeKind(language, returnTokens, { isReturn: true });
  const returnOwnership =
    returnKind === "pointer"
      ? publicAbiReturnOwnership(
          functionName,
          language,
          returnTokens,
          returnOwnershipProof,
        )
      : { kind: "not-applicable" };
  const returnContract = {
    kind: returnKind,
    ownership: returnOwnership,
    role: returnKind === "void" ? "none" : "value",
    type: abiTypeDescriptor(returnTokens),
  };
  const outputChannels = [];
  if (returnContract.role === "value") {
    outputChannels.push({
      kind: returnKind,
      ownership: structuredClone(returnOwnership),
      role: "return",
      selector: "[[return]]",
    });
  }
  for (const parameter of parameters) {
    if (new Set(["output", "inout"]).has(parameter.role)) {
      if (parameter.valueKind === "aggregate") {
        const aggregate = parameter.aggregateContract;
        const declaredSchema = registryAggregateName(
          rawParameters[parameter.index].typeTokens,
          typeRegistry,
        );
        if (
          aggregate &&
          typeRegistry?.schema === C_ABI_TYPE_REGISTRY_SCHEMA &&
          declaredSchema !== aggregate.schema
        ) {
          throw new Error(
            `${sourceRef}: aggregate annotation ${aggregate.schema} does not match ${declaredSchema} for ${parameter.name}`,
          );
        }
        const expanded = aggregate
          ? aggregateOutputChannels({
              alias: parameter.name,
              elements: aggregate.elements,
              memberOwnership: aggregate.memberOwnership,
              members: aggregate.members,
              role: parameter.role,
              rootParameter: parameter.name,
              schemaName: aggregate.schema,
              selectorPrefix: "out:",
              typeRegistry,
            })
          : null;
        if (expanded) outputChannels.push(...expanded);
        continue;
      }
      if (
        parameter.valueKind === "length" &&
        bufferLengthPairs.some(
          (candidate) => candidate.lengthParameter === parameter.name,
        )
      ) {
        continue;
      }
      const pair = bufferLengthPairs.find(
        (candidate) => candidate.bufferParameter === parameter.name,
      );
      outputChannels.push({
        kind: parameter.valueKind,
        ...(pair ? { lengthParameter: pair.lengthParameter } : {}),
        ownership: structuredClone(parameter.ownership),
        parameter: parameter.name,
        role: parameter.role,
        selector: outputSelector(parameter.name),
      });
    } else if (parameter.role === "callback-payload") {
      outputChannels.push(
        ...(callbackBindings.get(parameter.index)?.outputChannels ?? []),
      );
    }
  }

  const unresolved = [];
  if (returnKind === "unknown") unresolved.push("return-kind");
  if (returnOwnership.kind === "unknown")
    unresolved.push("return-pointer-ownership");
  for (const parameter of parameters) {
    const label = parameter.name ?? `parameter-${parameter.index}`;
    if (parameter.role === "unknown")
      unresolved.push(`parameter-role:${label}`);
    if (
      new Set(["output", "inout"]).has(parameter.role) &&
      parameter.ownership.kind === "unknown"
    ) {
      unresolved.push(`parameter-ownership:${label}`);
    }
    if (parameter.role === "callback")
      unresolved.push(`callback-signature:${label}`);
    if (
      new Set(["output", "inout"]).has(parameter.role) &&
      parameter.valueKind === "aggregate" &&
      (!parameter.aggregateContract ||
        !typeRegistry?.aggregates?.[parameter.aggregateContract.schema])
    ) {
      unresolved.push(`aggregate-schema:${label}`);
    }
    unresolved.push(
      ...(callbackBindings.get(parameter.index)?.unresolved ?? []),
    );
  }

  return {
    bufferLengthPairs,
    functionName,
    language,
    outputChannels,
    parameters,
    return: returnContract,
    schema: HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
    sourceRef,
    status: unresolved.length === 0 ? "resolved" : "unresolved",
    unresolved,
  };
}

function sourceProvesHostAbiOutputChannel(contract, channel) {
  if (
    channel.selector === "[[return]]" &&
    channel.role === "return" &&
    contract.return.role === "value"
  ) {
    return channel.kind !== "unknown";
  }

  const parameter = contract.parameters.find(
    (candidate) =>
      candidate.name === (channel.rootParameter ?? channel.parameter) ||
      candidate.index === (channel.rootParameter ?? channel.parameter),
  );
  if (!parameter || channel.kind === "unknown") return false;
  if (new Set(["output", "inout"]).has(channel.role)) {
    return parameter.role === channel.role;
  }
  return (
    channel.role === "callback-payload" && parameter.role === "callback-payload"
  );
}

/**
 * Derive catalog membership only from exact ABI signature contracts. Runtime
 * executor coverage is deliberately absent: it may prove a row's value, but
 * it cannot decide whether the output slot exists. An unresolved account may
 * retain already-proven channels for diagnostics; callers must not emit those
 * rows until membershipUnresolved is empty because another slot may be hidden.
 */
export function deriveHostAbiOutputCatalogAccount(surface) {
  if (surface?.kind !== "host-abi") {
    throw new Error("host ABI output account requires a host-abi surface");
  }
  const contracts = surface.metadata?.outputContracts;
  if (!Array.isArray(contracts) || contracts.length === 0) {
    return {
      evidenceUnresolved: [],
      membershipUnresolved: ["signature-contract-missing"],
      outputChannels: [],
      reasonCode: "host-abi-signature-contract-missing",
      status: "unresolved",
      unresolved: ["signature-contract-missing"],
    };
  }

  const outputChannels = new Map();
  const unresolved = [];
  for (const contract of contracts) {
    if (
      contract?.schema !== HOST_ABI_OUTPUT_CONTRACT_SCHEMA ||
      contract.functionName !== surface.name ||
      !surface.sourceRefs.includes(contract.sourceRef)
    ) {
      throw new Error(
        `host ABI output account ${surface.name} has an unbound signature contract`,
      );
    }
    for (const reason of contract.unresolved) {
      unresolved.push(`${contract.sourceRef}:${reason}`);
    }
    for (const channel of contract.outputChannels) {
      if (!sourceProvesHostAbiOutputChannel(contract, channel)) continue;
      const entry = outputChannels.get(channel.selector) ?? {
        selector: channel.selector,
        sourceRefs: [],
        variants: [],
      };
      entry.sourceRefs.push(contract.sourceRef);
      entry.variants.push({
        ...(channel.aggregateSchema
          ? { aggregateSchema: channel.aggregateSchema }
          : {}),
        ...(channel.alias ? { alias: channel.alias } : {}),
        ...(channel.callbackDirection
          ? { callbackDirection: channel.callbackDirection }
          : {}),
        ...(channel.elementSchema
          ? { elementSchema: channel.elementSchema }
          : {}),
        kind: channel.kind,
        ...(channel.lengthParameter
          ? { lengthParameter: channel.lengthParameter }
          : {}),
        ...(channel.memberPath ? { memberPath: channel.memberPath } : {}),
        ownership: structuredClone(channel.ownership),
        role: channel.role,
        sourceRef: contract.sourceRef,
      });
      outputChannels.set(channel.selector, entry);
    }
  }

  const catalogChannels = [...outputChannels.values()]
    .map((channel) => ({
      ...channel,
      sourceRefs: [...new Set(channel.sourceRefs)].sort(compareText),
      variants: channel.variants.sort((left, right) =>
        compareText(left.sourceRef, right.sourceRef),
      ),
    }))
    .sort((left, right) => compareText(left.selector, right.selector));
  // Ownership affects whether a known pointer-bearing slot can be executed and
  // normalized safely, but it does not make that slot disappear. Every other
  // unresolved signature fact can hide an additional return/out/callback slot,
  // so an account with one known channel is still membership-incomplete until
  // those facts are resolved.
  const evidenceUnresolved = unresolved.filter((reason) =>
    /:(?:callback-parameter-ownership:[^:]+|callback-return-pointer-ownership:[^:]+|parameter-ownership:[^:]+|return-pointer-ownership)$/u.test(
      reason,
    ),
  );
  const membershipUnresolved = unresolved.filter(
    (reason) => !evidenceUnresolved.includes(reason),
  );
  const structuralOnly = contracts.every(
    (contract) =>
      contract.return.role === "none" &&
      contract.outputChannels.length === 0 &&
      contract.parameters.every((parameter) => parameter.role === "input"),
  );
  const status =
    membershipUnresolved.length > 0
      ? "unresolved"
      : catalogChannels.length > 0
        ? "output-bearing"
        : structuralOnly
          ? "structural-only"
          : "unresolved";
  return {
    outputChannels: catalogChannels,
    reasonCode:
      status === "output-bearing"
        ? "source-derived-host-abi-output"
        : status === "structural-only"
          ? "source-derived-void-all-input-abi"
          : "host-abi-signature-membership-ambiguous",
    evidenceUnresolved: [...new Set(evidenceUnresolved)].sort(compareText),
    membershipUnresolved: [...new Set(membershipUnresolved)].sort(compareText),
    status,
    unresolved: [...new Set(unresolved)].sort(compareText),
  };
}

function rustHostAbiOutputContract(
  tokens,
  record,
  annotations,
  callbackAnnotations,
  sourceRef,
) {
  const open = record.nameIndex + 1;
  const close = matchingToken(tokens, open, "(", ")");
  if (close === -1 || record.bodyOpen <= close) {
    throw new Error(`${sourceRef}: malformed Rust ABI signature`);
  }
  let returnTokens = [];
  if (tokens[close + 1]?.value === "-" && tokens[close + 2]?.value === ">") {
    returnTokens = tokens.slice(close + 3, record.bodyOpen);
  }
  return buildHostAbiOutputContract({
    annotations,
    callbackAnnotations,
    functionName: record.name,
    language: "rust",
    parameters: rustAbiParameters(
      tokens,
      open,
      close,
      sourceRef.split("#")[0],
      record.name,
    ),
    returnTokens,
    returnOwnershipProof: null,
    sourceRef,
    typeRegistry: null,
  });
}

function cppReturnTypeTokens(tokens, nameIndex) {
  let boundary = nameIndex - 1;
  while (boundary >= 0 && !new Set([";", "{", "}"]).has(tokens[boundary].value))
    boundary -= 1;
  const signature = tokens.slice(boundary + 1, nameIndex);
  const externIndex = signature.findIndex((token) => token.value === "extern");
  if (externIndex === -1) return [];
  let output = signature.slice(externIndex + 2);
  while (
    output[0]?.type === "identifier" &&
    (/^[A-Z][A-Z0-9_]*$/u.test(output[0].value) ||
      new Set(["inline", "static"]).has(output[0].value))
  ) {
    output = output.slice(1);
  }
  return output;
}

function cppHostAbiOutputContract(
  tokens,
  definition,
  annotations,
  callbackAnnotations,
  sourceRef,
  typeRegistry,
) {
  const open = definition.nameIndex + 1;
  const close = matchingToken(tokens, open, "(", ")");
  if (close === -1 || definition.bodyOpen <= close) {
    throw new Error(`${sourceRef}: malformed C/C++ ABI signature`);
  }
  return buildHostAbiOutputContract({
    annotations,
    callbackAnnotations,
    functionName: definition.name,
    language: "c++",
    parameters: cppAbiParameters(tokens, open, close),
    returnTokens: cppReturnTypeTokens(tokens, definition.nameIndex),
    sourceRef,
    typeRegistry,
  });
}

function nextFunctionBodyToken(tokens, closeParen) {
  let cursor = closeParen + 1;
  while (cursor < tokens.length) {
    const value = tokens[cursor].value;
    if (value === "{" || value === ";" || value === "=")
      return value === "{" ? cursor : -1;
    // Attributes, trailing return types, const/noexcept, and export macros all
    // remain in the signature. A colon denotes a constructor initializer list;
    // those are irrelevant to the public ABI but still a function definition.
    if (value === "}") return -1;
    cursor += 1;
  }
  return -1;
}

function cppFunctionDefinitions(tokens) {
  const controlWords = new Set([
    "auto",
    "bool",
    "catch",
    "char",
    "defined",
    "double",
    "float",
    "for",
    "if",
    "int",
    "int32_t",
    "int64_t",
    "long",
    "requires",
    "short",
    "signed",
    "size_t",
    "sizeof",
    "switch",
    "uint32_t",
    "uint64_t",
    "unsigned",
    "void",
    "while",
    "__has_include",
  ]);
  const definitions = [];
  for (let index = 0; index < tokens.length - 2; index += 1) {
    const token = tokens[index];
    if (token.type !== "identifier" || controlWords.has(token.value)) continue;
    if (tokens[index + 1]?.value !== "(") continue;
    if (new Set([".", "->"]).has(tokens[index - 1]?.value)) continue;
    if (/^[A-Z][A-Z0-9_]*$/u.test(token.value)) continue;
    const closeParen = matchingToken(tokens, index + 1, "(", ")");
    if (closeParen === -1) continue;
    const explicitQualifier =
      tokens[index - 1]?.value === "::" &&
      tokens[index - 2]?.type === "identifier"
        ? tokens[index - 2].value
        : null;
    if (
      explicitQualifier &&
      new Set([".", "->", ",", ")", "]"]).has(tokens[closeParen + 1]?.value)
    ) {
      continue;
    }
    const bodyOpen = nextFunctionBodyToken(tokens, closeParen);
    if (bodyOpen === -1) continue;
    const bodyClose = matchingToken(tokens, bodyOpen, "{", "}");
    definitions.push({
      bodyClose,
      bodyOpen,
      explicitQualifier,
      name: token.value,
      nameIndex: index,
      signature: tokens
        .slice(index, closeParen + 1)
        .map((part) => part.value)
        .join(" "),
    });
  }
  for (let index = 0; index < definitions.length; index += 1) {
    const nextDefinition = definitions[index + 1];
    if (definitions[index].bodyClose === -1) {
      definitions[index].bodyClose = nextDefinition?.nameIndex ?? tokens.length;
    }
  }
  const typeDefinitions = cppTypeDefinitions(tokens);
  for (const definition of definitions) {
    const enclosingType = typeDefinitions
      .filter(
        (type) =>
          type.bodyOpen < definition.nameIndex &&
          definition.nameIndex < type.bodyClose,
      )
      .sort(
        (left, right) =>
          left.bodyClose - left.bodyOpen - (right.bodyClose - right.bodyOpen),
      )[0];
    definition.qualifiedName = enclosingType
      ? `${enclosingType.name}::${definition.name}`
      : definition.explicitQualifier
        ? `${definition.explicitQualifier}::${definition.name}`
        : definition.name;
  }
  const counts = new Map();
  for (const definition of definitions) {
    counts.set(
      definition.qualifiedName,
      (counts.get(definition.qualifiedName) ?? 0) + 1,
    );
  }
  for (const definition of definitions) {
    definition.identity =
      counts.get(definition.qualifiedName) === 1
        ? definition.qualifiedName
        : `${definition.qualifiedName}:${evidenceHash(definition.signature)}`;
  }
  return definitions;
}

function cppTypeDefinitions(tokens) {
  const definitions = [];
  for (let index = 0; index < tokens.length - 1; index += 1) {
    if (!new Set(["class", "struct"]).has(tokens[index].value)) continue;
    if (tokens[index + 1]?.type !== "identifier") continue;
    let cursor = index + 2;
    while (
      cursor < tokens.length &&
      !new Set(["{", ";"]).has(tokens[cursor].value)
    ) {
      cursor += 1;
    }
    if (tokens[cursor]?.value !== "{") continue;
    definitions.push({
      bodyOpen: cursor,
      bodyClose: matchingToken(tokens, cursor, "{", "}"),
      name: tokens[index + 1].value,
      nameIndex: index + 1,
    });
  }
  return definitions;
}

function cppDataDefinitions(tokens) {
  const definitions = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index].type !== "identifier") continue;
    if (new Set([".", "->", "::"]).has(tokens[index - 1]?.value)) continue;

    let boundary = index - 1;
    while (
      boundary >= 0 &&
      !new Set([";", "{", "}"]).has(tokens[boundary].value)
    ) {
      boundary -= 1;
    }
    const declarationPrefix = tokens.slice(boundary + 1, index);
    if (
      declarationPrefix.length === 0 ||
      declarationPrefix.some((token) => token.value === "=") ||
      !declarationPrefix.some((token) => token.type === "identifier")
    ) {
      continue;
    }

    let cursor = index + 1;
    if (tokens[cursor]?.value === "[") {
      const close = matchingToken(tokens, cursor, "[", "]");
      if (close === -1) continue;
      cursor = close + 1;
    }
    if (tokens[cursor]?.value !== "=") continue;
    definitions.push({ name: tokens[index].value, nameIndex: index });
  }
  return definitions;
}

function cppCallExpressions(tokens) {
  const definitionNameIndexes = new Set(
    cppFunctionDefinitions(tokens).map((definition) => definition.nameIndex),
  );
  const calls = [];
  for (let index = 0; index < tokens.length - 1; index += 1) {
    if (
      tokens[index].type !== "identifier" ||
      tokens[index + 1]?.value !== "(" ||
      definitionNameIndexes.has(index) ||
      new Set([".", "->", "::"]).has(tokens[index - 1]?.value)
    ) {
      continue;
    }
    let boundary = index - 1;
    while (
      boundary >= 0 &&
      !new Set([";", "{", "}"]).has(tokens[boundary].value)
    ) {
      boundary -= 1;
    }
    const prefix = tokens.slice(boundary + 1, index);
    const callContext =
      prefix.length === 0 ||
      prefix.some((token) =>
        new Set(["=", "(", "[", ",", "?", ":"]).has(token.value),
      ) ||
      new Set(["co_return", "return", "throw"]).has(prefix.at(-1)?.value);
    if (!callContext) continue;
    calls.push({ name: tokens[index].value, nameIndex: index });
  }
  return calls;
}

export function scanCppFunctionNames(text, sourcePath = "<native-source>") {
  return cppFunctionDefinitions(lexCpp(text, sourcePath)).map(
    (definition) => definition.name,
  );
}

/** Scan one C/C++/ObjC++ source for actual, not merely declared, C ABI definitions. */
export function scanCppPublicAbiDefinitions(
  text,
  sourcePath = "<native-source>",
  { typeRegistry = null } = {},
) {
  const tokens = lexCpp(text, sourcePath);
  const outputAnnotations = parseAbiOutputAnnotations(text, sourcePath);
  const callbackAnnotations = parseAbiCallbackAnnotations(text, sourcePath);
  const rows = [];
  const names = new Set();
  for (const definition of cppFunctionDefinitions(tokens)) {
    const { name, nameIndex } = definition;
    if (!PUBLIC_ABI_IDENTIFIER.test(name)) continue;
    let boundary = nameIndex - 1;
    while (
      boundary >= 0 &&
      !new Set([";", "{", "}"]).has(tokens[boundary].value)
    )
      boundary -= 1;
    const signature = tokens.slice(boundary + 1, nameIndex);
    const externIndex = signature.findIndex(
      (token) => token.value === "extern",
    );
    if (
      externIndex === -1 ||
      signature[externIndex + 1]?.type !== "string" ||
      signature[externIndex + 1]?.value !== "C"
    ) {
      continue;
    }
    if (names.has(name))
      throw new Error(`${sourcePath}: duplicate public ABI definition ${name}`);
    names.add(name);
    const weak = signature.some((token) => /weak/iu.test(token.value));
    const sourceRef = sourceSymbol(sourcePath, name);
    rows.push(
      makeSurface("host-abi", name, [sourceRef], {
        metadata: {
          language: "c++",
          outputContract: cppHostAbiOutputContract(
            tokens,
            definition,
            outputAnnotations.get(name) ?? [],
            callbackAnnotations.get(name) ?? [],
            sourceRef,
            typeRegistry,
          ),
          unsafe: false,
          weak,
        },
      }),
    );
  }
  for (const functionName of outputAnnotations.keys()) {
    if (!names.has(functionName)) {
      throw new Error(
        `${sourcePath}: @abi-output names absent C/C++ ABI definition ${functionName}`,
      );
    }
  }
  for (const functionName of callbackAnnotations.keys()) {
    if (!names.has(functionName)) {
      throw new Error(
        `${sourcePath}: @abi-callback names absent C/C++ ABI definition ${functionName}`,
      );
    }
  }
  return sortSurfaces(rows);
}

export function scanCppPublicAbiDeclarations(
  text,
  sourcePath = "<native-header>",
) {
  const tokens = lexCpp(text, sourcePath);
  const names = new Set();
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].type === "identifier" &&
      PUBLIC_ABI_IDENTIFIER.test(tokens[index].value) &&
      tokens[index + 1]?.value === "("
    ) {
      names.add(tokens[index].value);
    }
  }
  return uniqueSorted(names);
}

const ROOT_EXPORT_OBJECT = "<module-exports>";

function parseJavaScript(text, sourcePath) {
  try {
    return parseSync(text, {
      ast: true,
      babelrc: false,
      code: false,
      configFile: false,
      sourceType: "unambiguous",
      parserOpts: {
        allowReturnOutsideFunction: true,
      },
    }).program;
  } catch (error) {
    throw new Error(
      `${sourcePath}: unable to parse builtin source: ${error.message}`,
    );
  }
}

function walkAst(root, visitor) {
  const stack = [root];
  while (stack.length > 0) {
    const node = stack.pop();
    if (!node || typeof node !== "object") continue;
    if (typeof node.type === "string") visitor(node);
    for (const [key, value] of Object.entries(node)) {
      if (
        key === "comments" ||
        key === "errors" ||
        key === "extra" ||
        key === "loc" ||
        key === "start" ||
        key === "end"
      ) {
        continue;
      }
      if (Array.isArray(value)) {
        for (let index = value.length - 1; index >= 0; index -= 1)
          stack.push(value[index]);
      } else if (value && typeof value === "object") {
        stack.push(value);
      }
    }
  }
}

// Conservative lexical binding index for narrow source-review proofs. A
// duplicate binding or a write makes resolution unusable rather than guessing.
function javascriptLexicalBindingIndex(program) {
  const omittedKeys = new Set([
    "comments",
    "end",
    "errors",
    "extra",
    "leadingComments",
    "loc",
    "start",
    "trailingComments",
  ]);
  const nodeScopes = new WeakMap();
  const createScope = (parent, kind) => ({
    bindings: new Map(),
    kind,
    parent,
  });
  const programScope = createScope(null, "program");
  const nearestVarScope = (scope) => {
    let current = scope;
    while (current.parent && current.kind !== "function") {
      current = current.parent;
    }
    return current;
  };
  const addBinding = (scope, name, kind, node) => {
    if (!name) return;
    let bindings = scope.bindings.get(name);
    if (!bindings) {
      bindings = [];
      scope.bindings.set(name, bindings);
    }
    bindings.push({ kind, node, writes: 0 });
  };
  const addPatternBindings = (scope, pattern, kind, node = pattern) => {
    if (!pattern) return;
    if (pattern.type === "Identifier") {
      addBinding(scope, pattern.name, kind, node);
      return;
    }
    if (pattern.type === "AssignmentPattern") {
      addPatternBindings(scope, pattern.left, kind, node);
      return;
    }
    if (pattern.type === "RestElement") {
      addPatternBindings(scope, pattern.argument, kind, node);
      return;
    }
    if (pattern.type === "ArrayPattern") {
      for (const element of pattern.elements) {
        addPatternBindings(scope, element, kind, node);
      }
      return;
    }
    if (pattern.type === "ObjectPattern") {
      for (const property of pattern.properties) {
        addPatternBindings(
          scope,
          property.type === "RestElement" ? property.argument : property.value,
          kind,
          node,
        );
      }
    }
  };
  const childNodes = (node) => {
    const children = [];
    for (const [key, value] of Object.entries(node)) {
      if (omittedKeys.has(key)) continue;
      if (Array.isArray(value)) {
        children.push(
          ...value.filter((child) => child && typeof child === "object"),
        );
      } else if (value && typeof value === "object") {
        children.push(value);
      }
    }
    return children;
  };
  const visitFunction = (node, outerScope) => {
    const functionScope = createScope(outerScope, "function");
    if (node.type === "FunctionExpression" && node.id?.name) {
      addBinding(functionScope, node.id.name, "function-expression-name", node);
    }
    for (const parameter of node.params ?? []) {
      addPatternBindings(functionScope, parameter, "parameter");
      visit(parameter, functionScope);
    }
    if (node.body?.type === "BlockStatement") {
      nodeScopes.set(node.body, functionScope);
      for (const statement of node.body.body) visit(statement, functionScope);
    } else {
      visit(node.body, functionScope);
    }
  };
  const visit = (node, scope) => {
    if (!node || typeof node !== "object") return;
    nodeScopes.set(node, scope);
    if (node.type === "FunctionDeclaration") {
      addBinding(scope, node.id?.name, "function-declaration", node);
      visitFunction(node, scope);
      return;
    }
    if (
      node.type === "FunctionExpression" ||
      node.type === "ArrowFunctionExpression"
    ) {
      visitFunction(node, scope);
      return;
    }
    if (
      node.type === "ClassMethod" ||
      node.type === "ClassPrivateMethod" ||
      node.type === "ObjectMethod"
    ) {
      if (node.computed) visit(node.key, scope);
      visitFunction(node, scope);
      return;
    }
    if (node.type === "BlockStatement") {
      const blockScope = createScope(scope, "block");
      nodeScopes.set(node, blockScope);
      for (const statement of node.body) visit(statement, blockScope);
      return;
    }
    if (node.type === "VariableDeclaration") {
      const bindingScope = node.kind === "var" ? nearestVarScope(scope) : scope;
      for (const declaration of node.declarations) {
        nodeScopes.set(declaration, scope);
        addPatternBindings(
          bindingScope,
          declaration.id,
          `${node.kind}-declaration`,
          declaration,
        );
        visit(declaration.id, scope);
        visit(declaration.init, scope);
      }
      return;
    }
    if (node.type === "ClassDeclaration") {
      addBinding(scope, node.id?.name, "class-declaration", node);
    }
    if (node.type === "ImportDeclaration") {
      for (const specifier of node.specifiers) {
        addBinding(scope, specifier.local?.name, "import", specifier);
      }
    }
    if (node.type === "CatchClause") {
      const catchScope = createScope(scope, "block");
      nodeScopes.set(node, catchScope);
      addPatternBindings(catchScope, node.param, "catch-parameter");
      visit(node.param, catchScope);
      visit(node.body, catchScope);
      return;
    }
    if (
      node.type === "ForStatement" ||
      node.type === "ForInStatement" ||
      node.type === "ForOfStatement" ||
      node.type === "SwitchStatement"
    ) {
      const controlScope = createScope(scope, "block");
      nodeScopes.set(node, controlScope);
      for (const child of childNodes(node)) visit(child, controlScope);
      return;
    }
    for (const child of childNodes(node)) visit(child, scope);
  };
  visit(program, programScope);

  const resolve = (identifier) => {
    if (identifier?.type !== "Identifier") return null;
    let scope = nodeScopes.get(identifier);
    while (scope) {
      const bindings = scope.bindings.get(identifier.name);
      if (bindings) return bindings.length === 1 ? bindings[0] : null;
      scope = scope.parent;
    }
    return null;
  };
  const markPatternWrite = (pattern) => {
    if (!pattern) return;
    if (pattern.type === "Identifier") {
      const binding = resolve(pattern);
      if (binding) binding.writes += 1;
      return;
    }
    if (pattern.type === "AssignmentPattern") {
      markPatternWrite(pattern.left);
      return;
    }
    if (pattern.type === "RestElement") {
      markPatternWrite(pattern.argument);
      return;
    }
    if (pattern.type === "ArrayPattern") {
      for (const element of pattern.elements) markPatternWrite(element);
      return;
    }
    if (pattern.type === "ObjectPattern") {
      for (const property of pattern.properties) {
        markPatternWrite(
          property.type === "RestElement" ? property.argument : property.value,
        );
      }
    }
  };
  walkAst(program, (node) => {
    if (node.type === "AssignmentExpression") markPatternWrite(node.left);
    if (node.type === "UpdateExpression") markPatternWrite(node.argument);
    if (
      (node.type === "ForInStatement" || node.type === "ForOfStatement") &&
      node.left?.type !== "VariableDeclaration"
    ) {
      markPatternWrite(node.left);
    }
  });
  return { resolve };
}

function staticPropertyName(node, substitutions = new Map()) {
  if (!node) return [];
  if (node.type === "StringLiteral") return [node.value];
  if (node.type === "NumericLiteral") return [String(node.value)];
  if (node.type === "Identifier" && substitutions.has(node.name)) {
    return [...substitutions.get(node.name)];
  }
  return [];
}

function mergeSubstitutions(base, additions) {
  const merged = new Map(base);
  for (const [name, values] of additions) merged.set(name, new Set(values));
  return merged;
}

function isStaticallyNonPublicPropertyKey(node, knownBindings = new Set()) {
  if (!node) return false;
  if (node.type === "NullLiteral") return true;
  if (node.type === "StringLiteral") return node.value.startsWith("_");
  if (node.type === "Identifier") return knownBindings.has(node.name);
  if (
    node.type === "CallExpression" &&
    ((node.callee?.type === "Identifier" && node.callee.name === "Symbol") ||
      (node.callee?.type === "MemberExpression" &&
        node.callee.object?.type === "Identifier" &&
        node.callee.object.name === "Symbol"))
  ) {
    return true;
  }
  if (
    node.type === "MemberExpression" &&
    node.object?.type === "Identifier" &&
    node.object.name === "Symbol"
  ) {
    return true;
  }
  if (node.type === "ConditionalExpression") {
    return (
      isStaticallyNonPublicPropertyKey(node.consequent, knownBindings) &&
      isStaticallyNonPublicPropertyKey(node.alternate, knownBindings)
    );
  }
  if (node.type === "LogicalExpression") {
    return (
      isStaticallyNonPublicPropertyKey(node.left, knownBindings) &&
      isStaticallyNonPublicPropertyKey(node.right, knownBindings)
    );
  }
  return false;
}

function collectStaticPropertyTables(program) {
  const bindings = new Map();
  const arrays = new Map();
  const objects = new Map();
  const nonPublicBindings = new Set();

  walkAst(program, (node) => {
    if (node.type !== "VariableDeclarator" || node.id?.type !== "Identifier")
      return;
    const values = staticPropertyName(node.init, bindings);
    if (values.length > 0) bindings.set(node.id.name, new Set(values));
    const objectExpression =
      node.init?.type === "ObjectExpression"
        ? node.init
        : node.init?.type === "CallExpression" &&
            ["freeze", "seal"].includes(callName(node.init)) &&
            node.init.arguments[0]?.type === "ObjectExpression"
          ? node.init.arguments[0]
          : null;
    if (objectExpression) {
      objects.set(
        node.id.name,
        new Set(objectPropertyNames(objectExpression, bindings)),
      );
    }
    if (node.init?.type === "ArrayExpression") {
      const elements = node.init.elements.flatMap((element) =>
        staticPropertyName(element, bindings),
      );
      if (elements.length === node.init.elements.length)
        arrays.set(node.id.name, new Set(elements));
    }
    if (
      node.init?.type === "CallExpression" &&
      callName(node.init) === "keys" &&
      node.init.arguments[0]?.type === "Identifier" &&
      objects.has(node.init.arguments[0].name)
    ) {
      arrays.set(
        node.id.name,
        new Set(objects.get(node.init.arguments[0].name)),
      );
    }
  });

  let changed = true;
  while (changed) {
    changed = false;
    walkAst(program, (node) => {
      if (
        node.type === "VariableDeclarator" &&
        node.id?.type === "Identifier" &&
        !nonPublicBindings.has(node.id.name) &&
        isStaticallyNonPublicPropertyKey(node.init, nonPublicBindings)
      ) {
        nonPublicBindings.add(node.id.name);
        changed = true;
      }
    });
  }

  // Authored tables commonly append platform-conditional names before a
  // deterministic loop. Treat literal pushes as part of the same closed table.
  walkAst(program, (node) => {
    if (
      node.type !== "CallExpression" ||
      node.callee?.type !== "MemberExpression" ||
      node.callee.computed ||
      node.callee.object?.type !== "Identifier" ||
      node.callee.property?.type !== "Identifier" ||
      node.callee.property.name !== "push" ||
      !arrays.has(node.callee.object.name)
    ) {
      return;
    }
    const values = node.arguments.flatMap((argument) =>
      staticPropertyName(argument, bindings),
    );
    if (values.length !== node.arguments.length) return;
    const table = arrays.get(node.callee.object.name);
    for (const value of values) table.add(value);
  });

  return { arrays, bindings, nonPublicBindings };
}

function staticRegistrationNames(node, substitutions, staticArrays) {
  const direct = staticPropertyName(node, substitutions);
  if (direct.length > 0) return uniqueSorted(direct);
  if (
    node?.type === "MemberExpression" &&
    node.computed &&
    node.object?.type === "Identifier" &&
    staticArrays.has(node.object.name)
  ) {
    return uniqueSorted(staticArrays.get(node.object.name));
  }
  return [];
}

function registrationContext(text, node, sourcePath) {
  const line = node?.loc?.start?.line;
  const column = node?.loc?.start?.column;
  const location =
    Number.isInteger(line) && Number.isInteger(column)
      ? `${sourcePath}:${line}:${column + 1}`
      : sourcePath;
  const snippet =
    Number.isInteger(node?.start) && Number.isInteger(node?.end)
      ? text
          .slice(node.start, Math.min(node.end, node.start + 160))
          .replace(/\s+/gu, " ")
          .trim()
      : "<unknown expression>";
  return `${location}: ${snippet}`;
}

function objectPropertyNames(node, substitutions = new Map()) {
  if (!node || node.type !== "ObjectExpression") return [];
  const names = [];
  for (const property of node.properties) {
    if (property.type === "SpreadElement") continue;
    if (!property.computed && property.key?.type === "Identifier") {
      names.push(property.key.name);
    } else {
      names.push(...staticPropertyName(property.key, substitutions));
    }
  }
  return uniqueSorted(names);
}

function isModuleExports(node) {
  return Boolean(
    node?.type === "MemberExpression" &&
    node.object?.type === "Identifier" &&
    node.object.name === "module" &&
    ((!node.computed &&
      node.property?.type === "Identifier" &&
      node.property.name === "exports") ||
      (node.computed &&
        node.property?.type === "StringLiteral" &&
        node.property.value === "exports")),
  );
}

function exportTargetId(node) {
  if (isModuleExports(node)) return ROOT_EXPORT_OBJECT;
  if (node?.type === "Identifier") {
    return node.name === "exports" ? ROOT_EXPORT_OBJECT : node.name;
  }
  return null;
}

function memberTargetAndNames(
  node,
  substitutions = new Map(),
  staticArrays = new Map(),
) {
  if (node?.type !== "MemberExpression") return null;
  const target = exportTargetId(node.object);
  if (!target) return null;
  let names = [];
  if (!node.computed && node.property?.type === "Identifier") {
    names = [node.property.name];
  } else {
    names = staticRegistrationNames(node.property, substitutions, staticArrays);
  }
  return { names, target };
}

function callName(node) {
  if (
    node?.type !== "CallExpression" ||
    node.callee?.type !== "MemberExpression"
  )
    return null;
  const { callee } = node;
  if (
    callee.object?.type !== "Identifier" ||
    callee.object.name !== "Object" ||
    callee.computed ||
    callee.property?.type !== "Identifier"
  ) {
    return null;
  }
  return callee.property.name;
}

function mutationCallName(node) {
  if (
    node?.type !== "CallExpression" ||
    node.callee?.type !== "MemberExpression" ||
    node.callee.computed ||
    node.callee.object?.type !== "Identifier" ||
    node.callee.property?.type !== "Identifier"
  ) {
    return null;
  }
  const owner = node.callee.object.name;
  const method = node.callee.property.name;
  if (
    owner === "Object" &&
    new Set([
      "assign",
      "defineProperties",
      "defineProperty",
      "setPrototypeOf",
    ]).has(method)
  ) {
    return `Object.${method}`;
  }
  if (
    owner === "Reflect" &&
    new Set(["defineProperty", "set", "setPrototypeOf"]).has(method)
  ) {
    return `Reflect.${method}`;
  }
  return null;
}

function isStaticRequireMember(node) {
  return Boolean(
    node?.type === "MemberExpression" &&
    directMemberName(node) !== null &&
    node.object?.type === "CallExpression" &&
    node.object.callee?.type === "Identifier" &&
    node.object.callee.name === "require" &&
    node.object.arguments[0]?.type === "StringLiteral" &&
    node.object.arguments[0].value.length > 0,
  );
}

function callbackFunction(node) {
  return node?.type === "FunctionExpression" ||
    node?.type === "ArrowFunctionExpression"
    ? node
    : null;
}

function isJavaScriptFunctionNode(node) {
  return Boolean(
    node &&
    new Set([
      "ArrowFunctionExpression",
      "ClassMethod",
      "ClassPrivateMethod",
      "FunctionDeclaration",
      "FunctionExpression",
      "ObjectMethod",
    ]).has(node.type),
  );
}

const AST_METADATA_KEYS = new Set([
  "comments",
  "end",
  "errors",
  "extra",
  "loc",
  "start",
]);

function pushAstChildren(stack, node) {
  for (const [key, value] of Object.entries(node)) {
    if (AST_METADATA_KEYS.has(key)) continue;
    if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index -= 1) {
        stack.push(value[index]);
      }
    } else if (value && typeof value === "object") {
      stack.push(value);
    }
  }
}

// @ref LLP 0046#33-timer-admission-is-negative-valued — a source-proven
// callback argument is part of the conservative route, while the scheduling
// call itself remains an unresolved marker until separately admitted.
function walkDirectFunctionBody(
  functionNode,
  visitor,
  resolveCallbackIdentifier = null,
) {
  const visitedFunctions = new Set();
  const walkFunction = (currentFunction, isCallbackArgument = false) => {
    if (!currentFunction || visitedFunctions.has(currentFunction)) return;
    visitedFunctions.add(currentFunction);
    const root = currentFunction.body;
    if (!root) return;
    const callbackFunctions = (argument) => {
      if (callbackFunction(argument)) return [argument];
      if (argument?.type === "Identifier") {
        return resolveCallbackIdentifier?.(argument) ?? [];
      }
      if (argument?.type === "ConditionalExpression") {
        return [
          ...callbackFunctions(argument.consequent),
          ...callbackFunctions(argument.alternate),
        ];
      }
      if (argument?.type === "LogicalExpression") {
        return [
          ...callbackFunctions(argument.left),
          ...callbackFunctions(argument.right),
        ];
      }
      return [];
    };
    const stack = [root];
    while (stack.length > 0) {
      const node = stack.pop();
      if (!node || typeof node !== "object") continue;
      if (node !== root && isJavaScriptFunctionNode(node)) continue;
      if (typeof node.type === "string") visitor(node, isCallbackArgument);
      if (node.type === "CallExpression" && resolveCallbackIdentifier) {
        for (const argument of node.arguments ?? []) {
          for (const callback of callbackFunctions(argument)) {
            walkFunction(callback, true);
          }
        }
      }
      pushAstChildren(stack, node);
    }
  };
  walkFunction(functionNode);
}

function javascriptFunctionDefinitions(program) {
  const definitions = [];
  walkAst(program, (node) => {
    if (node.type === "FunctionDeclaration" && node.id?.name) {
      definitions.push({ name: node.id.name, node });
      return;
    }
    if (
      node.type === "VariableDeclarator" &&
      node.id?.type === "Identifier" &&
      callbackFunction(node.init)
    ) {
      definitions.push({ name: node.id.name, node: node.init });
      return;
    }
    if (
      node.type === "AssignmentExpression" &&
      node.operator === "=" &&
      node.left?.type === "Identifier" &&
      callbackFunction(node.right)
    ) {
      definitions.push({ name: node.left.name, node: node.right });
    }
  });
  return definitions;
}

// Fixed semantic evidence occasionally lives in a bootstrap-owned global
// assignment rather than a lexical declaration. Keep this deliberately
// narrower than javascriptFunctionDefinitions(): broad surface discovery must
// not acquire new callables merely because a global bootstrap helper is named.
function javascriptFixedGlobalFunctionDefinitions(program) {
  const definitions = [...javascriptFunctionDefinitions(program)];
  walkAst(program, (node) => {
    if (
      node.type !== "AssignmentExpression" ||
      node.operator !== "=" ||
      node.left?.type !== "MemberExpression" ||
      node.left.object?.type !== "Identifier" ||
      node.left.object.name !== "globalThis" ||
      !callbackFunction(node.right)
    ) {
      return;
    }
    const names = node.left.computed
      ? staticPropertyName(node.left.property)
      : [node.left.property?.name].filter(Boolean);
    for (const name of names) definitions.push({ name, node: node.right });
  });
  return definitions;
}

/**
 * Discover statically named CommonJS and ESM exports from one builtin source.
 * Babel supplies the lexer/parser boundary so comments, regexes, templates,
 * and strings cannot fabricate exports. The small data-flow pass follows local
 * object aliases and the export idioms used by Ibex's authored builtin files.
 */
export function scanStaticBuiltinExports(
  text,
  {
    bootstrapInternalModuleSpecifiers = [],
    sourceKey = "synthetic",
    sourceKind = "generated",
    sourcePath = "<builtin-source>",
    moduleSpecifiers = [],
    publicModuleSpecifiers = moduleSpecifiers,
  } = {},
) {
  if (!/^[A-Za-z0-9_]+$/u.test(sourceKey)) {
    throw new Error(
      `${sourcePath}: invalid builtin source key ${JSON.stringify(sourceKey)}`,
    );
  }
  const program = parseJavaScript(text, sourcePath);
  const callbackBindings = javascriptLexicalBindingIndex(program);
  const callbackAssignments = new Map();
  walkAst(program, (node) => {
    if (
      node.type !== "AssignmentExpression" ||
      node.operator !== "=" ||
      node.left?.type !== "Identifier" ||
      !callbackFunction(node.right)
    ) {
      return;
    }
    const binding = callbackBindings.resolve(node.left);
    if (!binding) return;
    let assignments = callbackAssignments.get(binding);
    if (!assignments) {
      assignments = [];
      callbackAssignments.set(binding, assignments);
    }
    assignments.push(node.right);
  });
  const callbackDefinitionForIdentifier = (identifier) => {
    const binding = callbackBindings.resolve(identifier);
    if (!binding) return [];
    if (
      binding.kind === "function-declaration" ||
      binding.kind === "function-expression-name"
    ) {
      return binding.writes === 0 ? [binding.node] : [];
    }
    if (
      binding.node?.type === "VariableDeclarator" &&
      callbackFunction(binding.node.init)
    ) {
      return binding.writes === 0 ? [binding.node.init] : [];
    }
    const assignments = callbackAssignments.get(binding) ?? [];
    return binding.writes === 1 && assignments.length === 1 ? assignments : [];
  };
  const {
    arrays: staticArrays,
    bindings: staticBindings,
    nonPublicBindings,
  } = collectStaticPropertyTables(program);
  const facts = new Map();
  const aliases = new Map();
  const bindings = new Map();
  const callValuedBindings = new Map();
  const valueShapeFacts = new Map();
  const prototypeFacts = new Map();
  const ownPrototypeFacts = new Map();
  const prototypeValueShapeFacts = new Map();
  const inheritedPrototypeFacts = new Map();
  const knownPrototypeOwners = new Set();
  const prototypeSources = new Map();
  const objectPrototypeOwners = new Map();
  const forEachCalls = [];
  const immediateCalls = [];
  const tableCopyRegistrations = new Map();
  const functionDefinitions = new Map();
  const unresolvedRegistrations = new Map();
  const resolvedRegistrations = new Set();
  const opaqueShapeRegistrations = new Map();
  const resolvedOpaqueShapeNodes = new Set();
  const unresolvedPrototypeRegistrations = new Map();
  const requiredModuleBindings = new Set();
  const requiredModuleBindingSpecifiers = new Map();
  const callableDefinitions = javascriptFunctionDefinitions(program);
  const callableDefinitionsByName = new Map();
  for (const definition of callableDefinitions) {
    let definitions = callableDefinitionsByName.get(definition.name);
    if (!definitions) {
      definitions = [];
      callableDefinitionsByName.set(definition.name, definitions);
    }
    definitions.push(definition);
  }
  const qualifiedCallableDefinitions = new Map();
  const qualifiedCallableOpaqueAlternatives = new Set();
  const classDefinitionNames = new Set();
  const localValueExpressions = new Map();
  const staticObjectBindings = new Set();
  const reassignedObjectBindings = new Set();
  walkAst(program, (node) => {
    if (
      node.type === "AssignmentExpression" &&
      node.left?.type === "Identifier"
    ) {
      reassignedObjectBindings.add(node.left.name);
    }
  });
  const addQualifiedCallable = (name, node) => {
    if (!name || !node) return;
    let definitions = qualifiedCallableDefinitions.get(name);
    if (!definitions) {
      definitions = [];
      qualifiedCallableDefinitions.set(name, definitions);
    }
    definitions.push(node);
  };
  const callableValueAlternatives = (expression) => {
    if (callbackFunction(expression)) {
      return { callbacks: [expression], opaque: false };
    }
    if (expression?.type === "LogicalExpression") {
      const left = callableValueAlternatives(expression.left);
      const right = callableValueAlternatives(expression.right);
      return {
        callbacks: [...left.callbacks, ...right.callbacks],
        opaque: left.opaque || right.opaque,
      };
    }
    if (expression?.type === "ConditionalExpression") {
      const consequent = callableValueAlternatives(expression.consequent);
      const alternate = callableValueAlternatives(expression.alternate);
      return {
        callbacks: [...consequent.callbacks, ...alternate.callbacks],
        opaque: consequent.opaque || alternate.opaque,
      };
    }
    return { callbacks: [], opaque: true };
  };
  walkAst(program, (node) => {
    if (
      (node.type === "ClassDeclaration" ||
        node.type === "FunctionDeclaration") &&
      node.id?.name
    ) {
      if (node.type === "ClassDeclaration")
        classDefinitionNames.add(node.id.name);
    }
    if (
      node.type === "VariableDeclarator" &&
      node.id?.type === "Identifier" &&
      node.init
    ) {
      let expressions = localValueExpressions.get(node.id.name);
      if (!expressions) {
        expressions = [];
        localValueExpressions.set(node.id.name, expressions);
      }
      expressions.push(node.init);
    }
    if (
      node.type === "AssignmentExpression" &&
      node.operator === "=" &&
      node.left?.type === "Identifier" &&
      node.right
    ) {
      let expressions = localValueExpressions.get(node.left.name);
      if (!expressions) {
        expressions = [];
        localValueExpressions.set(node.left.name, expressions);
      }
      expressions.push(node.right);
    }
    if (
      node.type === "VariableDeclarator" &&
      node.id?.type === "Identifier" &&
      node.init?.type === "ObjectExpression" &&
      !reassignedObjectBindings.has(node.id.name)
    ) {
      staticObjectBindings.add(node.id.name);
      for (const property of node.init.properties) {
        if (property.computed || property.key?.type !== "Identifier") continue;
        const name = `${node.id.name}.${property.key.name}`;
        if (property.type === "ObjectMethod") {
          addQualifiedCallable(name, property);
          continue;
        }
        if (property.type === "ObjectProperty") {
          const alternatives = callableValueAlternatives(property.value);
          for (const callable of alternatives.callbacks) {
            addQualifiedCallable(name, callable);
          }
          if (alternatives.callbacks.length > 0 && alternatives.opaque) {
            qualifiedCallableOpaqueAlternatives.add(name);
          }
        }
      }
      return;
    }
    if (
      (node.type === "ClassDeclaration" || node.type === "ClassExpression") &&
      node.id?.name
    ) {
      for (const method of node.body?.body ?? []) {
        if (method.computed || method.key?.type !== "Identifier") continue;
        addQualifiedCallable(`${node.id.name}.${method.key.name}`, method);
      }
      return;
    }
    if (
      node.type === "AssignmentExpression" &&
      node.operator === "=" &&
      callbackFunction(node.right)
    ) {
      const method = directMemberName(node.left);
      const owner = prototypeOwner(node.left?.object);
      if (method && owner)
        addQualifiedCallable(`${owner}.${method}`, node.right);
      else if (
        method &&
        node.left.object?.type === "Identifier" &&
        staticObjectBindings.has(node.left.object.name)
      ) {
        addQualifiedCallable(`${node.left.object.name}.${method}`, node.right);
      }
    }
  });

  const declaredIdentifiers = new Set();
  const assignedIdentifiers = new Set();
  walkAst(program, (node) => {
    if (node.type === "VariableDeclarator" && node.id?.type === "Identifier") {
      declaredIdentifiers.add(node.id.name);
    }
    if (
      (node.type === "FunctionDeclaration" ||
        node.type === "ClassDeclaration") &&
      node.id?.name
    ) {
      declaredIdentifiers.add(node.id.name);
    }
    if (
      node.type === "AssignmentExpression" &&
      node.left?.type === "Identifier"
    ) {
      assignedIdentifiers.add(node.left.name);
    }
    if (isJavaScriptFunctionNode(node)) {
      for (const parameter of node.params ?? []) {
        if (parameter?.type === "Identifier")
          declaredIdentifiers.add(parameter.name);
      }
    }
  });
  const globalObjectAliases = new Set(["globalThis"]);
  let globalAliasChanged = true;
  while (globalAliasChanged) {
    globalAliasChanged = false;
    walkAst(program, (node) => {
      if (
        node.type !== "VariableDeclarator" ||
        node.id?.type !== "Identifier" ||
        node.init?.type !== "Identifier" ||
        !globalObjectAliases.has(node.init.name) ||
        assignedIdentifiers.has(node.id.name) ||
        globalObjectAliases.has(node.id.name)
      ) {
        return;
      }
      globalObjectAliases.add(node.id.name);
      globalAliasChanged = true;
    });
  }
  const isTerminalName = (name) =>
    /^__(?:exact|native)[A-Za-z0-9_$]*$/u.test(name) ||
    name === "__hostCall" ||
    name === "__hostCallAsync";
  const intrinsicGlobalReceivers = new Set([
    "AggregateError",
    "Array",
    "ArrayBuffer",
    "Atomics",
    "BigInt",
    "BigInt64Array",
    "BigUint64Array",
    "Boolean",
    "Buffer",
    "DataView",
    "Date",
    "Error",
    "EvalError",
    "FinalizationRegistry",
    "Float32Array",
    "Float64Array",
    "Function",
    "Int8Array",
    "Int16Array",
    "Int32Array",
    "Intl",
    "JSON",
    "Map",
    "Math",
    "Number",
    "Object",
    "Promise",
    "Proxy",
    "RangeError",
    "Reflect",
    "ReferenceError",
    "RegExp",
    "Set",
    "SharedArrayBuffer",
    "String",
    "Symbol",
    "SyntaxError",
    "TextDecoder",
    "TextEncoder",
    "TypeError",
    "Uint8ClampedArray",
    "Uint16Array",
    "Uint32Array",
    "Uint8Array",
    "URIError",
    "URL",
    "URLSearchParams",
    "WeakRef",
    "WeakMap",
    "WeakSet",
    "WebAssembly",
  ]);
  const intrinsicLiteralTypes = new Set([
    "ArrayExpression",
    "BigIntLiteral",
    "BooleanLiteral",
    "NullLiteral",
    "NumericLiteral",
    "RegExpLiteral",
    "StringLiteral",
  ]);
  const mutatedIntrinsicRoots = new Set();
  const intrinsicRootName = (expression) => {
    if (!expression) return null;
    if (
      expression.type === "Identifier" &&
      intrinsicGlobalReceivers.has(expression.name) &&
      !declaredIdentifiers.has(expression.name) &&
      !assignedIdentifiers.has(expression.name)
    ) {
      return expression.name;
    }
    if (
      expression.type === "MemberExpression" &&
      !expression.computed &&
      expression.property?.type === "Identifier"
    ) {
      return intrinsicRootName(expression.object);
    }
    return null;
  };
  walkAst(program, (node) => {
    if (
      (node.type === "AssignmentExpression" ||
        node.type === "UpdateExpression") &&
      node.left
    ) {
      const root = intrinsicRootName(node.left);
      if (root) mutatedIntrinsicRoots.add(root);
      return;
    }
    if (node.type === "UnaryExpression" && node.operator === "delete") {
      const root = intrinsicRootName(node.argument);
      if (root) mutatedIntrinsicRoots.add(root);
      return;
    }
    const mutation = mutationCallName(node);
    if (!mutation) return;
    const root = intrinsicRootName(node.arguments[0]);
    if (root) mutatedIntrinsicRoots.add(root);
  });
  const isProvenIntrinsicReceiver = (expression) => {
    if (!expression) return false;
    if (intrinsicLiteralTypes.has(expression.type)) return true;
    const root = intrinsicRootName(expression);
    return root !== null && !mutatedIntrinsicRoots.has(root);
  };
  const isProvenIntrinsicValue = (expression, localBindings) => {
    if (!expression) return false;
    if (isProvenIntrinsicReceiver(expression)) return true;
    if (expression.type === "ConditionalExpression") {
      return (
        isProvenIntrinsicValue(expression.consequent, localBindings) &&
        isProvenIntrinsicValue(expression.alternate, localBindings)
      );
    }
    if (
      expression.type === "Identifier" &&
      localBindings.has(expression.name)
    ) {
      return true;
    }
    if (
      expression.type === "NewExpression" &&
      expression.callee?.type === "Identifier" &&
      intrinsicGlobalReceivers.has(expression.callee.name) &&
      !declaredIdentifiers.has(expression.callee.name) &&
      !assignedIdentifiers.has(expression.callee.name) &&
      !mutatedIntrinsicRoots.has(expression.callee.name)
    ) {
      return true;
    }
    if (expression.type === "CallExpression") {
      if (
        expression.callee?.type === "Identifier" &&
        intrinsicGlobalReceivers.has(expression.callee.name) &&
        !declaredIdentifiers.has(expression.callee.name) &&
        !assignedIdentifiers.has(expression.callee.name) &&
        !mutatedIntrinsicRoots.has(expression.callee.name)
      ) {
        return true;
      }
      if (
        expression.callee?.type === "MemberExpression" &&
        isProvenIntrinsicReceiver(expression.callee.object)
      ) {
        return true;
      }
    }
    return false;
  };
  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // suppress route ambiguity only for immutable module bindings whose source
  // initializer is recursively proven intrinsic.
  const moduleIntrinsicBindings = new Set(staticArrays.keys());
  let moduleIntrinsicChanged = true;
  while (moduleIntrinsicChanged) {
    moduleIntrinsicChanged = false;
    walkAst(program, (node) => {
      if (
        node.type !== "VariableDeclarator" ||
        node.id?.type !== "Identifier" ||
        moduleIntrinsicBindings.has(node.id.name) ||
        assignedIdentifiers.has(node.id.name) ||
        !isProvenIntrinsicValue(node.init, moduleIntrinsicBindings)
      ) {
        return;
      }
      moduleIntrinsicBindings.add(node.id.name);
      moduleIntrinsicChanged = true;
    });
  }
  const terminalReference = (expression) => {
    if (expression?.type === "Identifier" && isTerminalName(expression.name)) {
      return declaredIdentifiers.has(expression.name)
        ? { ambiguity: `shadowed:${expression.name}` }
        : { name: expression.name };
    }
    if (expression?.type !== "MemberExpression") return null;
    const name = directMemberName(expression);
    if (!name || !isTerminalName(name)) return null;
    if (expression.computed) {
      return { ambiguity: `computed-terminal:${name}` };
    }
    if (
      expression.object?.type !== "Identifier" ||
      !globalObjectAliases.has(expression.object.name)
    ) {
      return { ambiguity: `dynamic-terminal-receiver:${name}` };
    }
    return { name };
  };
  const terminalAliases = new Map();
  walkAst(program, (node) => {
    if (node.type !== "VariableDeclaration" || node.kind !== "const") return;
    for (const declaration of node.declarations) {
      if (
        declaration.id?.type !== "Identifier" ||
        assignedIdentifiers.has(declaration.id.name)
      ) {
        continue;
      }
      const reference = terminalReference(declaration.init);
      if (reference?.name)
        terminalAliases.set(declaration.id.name, reference.name);
    }
  });

  const staticEnforcementCall = (call) => {
    if (call?.type !== "CallExpression") return null;
    if (
      call.callee?.type === "MemberExpression" &&
      !call.callee.computed &&
      new Set(["apply", "call"]).has(call.callee.property?.name)
    ) {
      if (mutatedIntrinsicRoots.has("Function")) {
        return {
          ambiguity: `dynamic-call-receiver:${call.callee.property.name}`,
        };
      }
      const invokedReference = terminalReference(call.callee.object);
      if (invokedReference?.ambiguity) return invokedReference;
      if (invokedReference?.name) return { name: invokedReference.name };
    }
    const alias =
      call.callee?.type === "Identifier"
        ? terminalAliases.get(call.callee.name)
        : null;
    const reference = alias ? { name: alias } : terminalReference(call.callee);
    if (!reference) return null;
    if (reference.ambiguity) return reference;
    const name = reference.name;
    if (name === "__hostCall" || name === "__hostCallAsync") {
      const operation = call.arguments[0];
      return operation?.type === "StringLiteral"
        ? { name: `${name}:${operation.value}` }
        : { ambiguity: `${name}:dynamic-operation` };
    }
    return { name };
  };

  const directRouteMemo = new Map();
  const routeMemo = new Map();
  const shortestPath = (paths) =>
    uniqueSorted(paths).sort(
      (left, right) =>
        left.length - right.length || compareText(left, right),
    )[0];
  const representativeTerminalPaths = (paths) => {
    // Callback expansion can multiply equivalent route paths. Keep one
    // deterministic witness per terminal in the expanded memo; the complete
    // pre-callback route is merged back into each export below.
    const byTerminal = new Map();
    for (const routePath of paths) {
      const terminal = routePath.slice(routePath.lastIndexOf(" -> ") + 4);
      const current = byTerminal.get(terminal);
      if (
        !current ||
        routePath.length < current.length ||
        (routePath.length === current.length &&
          compareText(routePath, current) < 0)
      ) {
        byTerminal.set(terminal, routePath);
      }
    }
    return uniqueSorted(byTerminal.values());
  };
  const intrinsicGlobalCalls = new Set([
    "BigInt",
    "Boolean",
    "Number",
    "String",
    "decodeURI",
    "decodeURIComponent",
    "encodeURI",
    "encodeURIComponent",
    "escape",
    "isFinite",
    "isNaN",
    "parseFloat",
    "parseInt",
    "unescape",
  ]);
  const requiredExportInvocation = (callee) => {
    let target = callee;
    if (
      target?.type === "MemberExpression" &&
      !target.computed &&
      new Set(["apply", "call"]).has(directMemberName(target))
    ) {
      target = target.object;
    }
    const segments = [];
    while (
      target?.type === "MemberExpression" &&
      !target.computed &&
      target.property?.type === "Identifier"
    ) {
      segments.unshift(target.property.name);
      target = target.object;
    }
    if (target?.type !== "Identifier") return null;
    const binding = requiredModuleBindingSpecifiers.get(target.name);
    if (!binding) return null;
    return {
      exportName:
        [...binding.exportSegments, ...segments].join(".") || "default",
      moduleSpecifier: binding.moduleSpecifier,
    };
  };
  const callableNodesForName = (name) =>
    name.includes(".")
      ? (qualifiedCallableDefinitions.get(name) ?? [])
      : (callableDefinitionsByName.get(name) ?? []).map((row) => row.node);
  const routeForCallable = (
    name,
    active = new Set(),
    includeCallbackArguments = true,
  ) => {
    const memo = includeCallbackArguments ? routeMemo : directRouteMemo;
    if (memo.has(name)) return memo.get(name);
    if (active.has(name)) {
      return { ambiguous: [], dependencies: [], paths: [], terminals: [] };
    }
    const qualified = name.includes(".");
    const definitions = callableNodesForName(name);
    if (definitions.length === 0 || (!qualified && definitions.length > 1)) {
      const result = {
        ambiguous:
          definitions.length > 1
            ? [name]
            : (intrinsicGlobalCalls.has(name) ||
                  intrinsicGlobalReceivers.has(name)) &&
                !declaredIdentifiers.has(name) &&
                !assignedIdentifiers.has(name) &&
                !mutatedIntrinsicRoots.has(name)
              ? []
              : [`unresolved-call:${name}`],
        paths: [],
        dependencies: [],
        terminals: [],
      };
      memo.set(name, result);
      return result;
    }
    const nextActive = new Set(active);
    nextActive.add(name);
    const owner = qualified ? name.slice(0, name.lastIndexOf(".")) : null;
    const localIntrinsicBindings = new Set(moduleIntrinsicBindings);
    let intrinsicChanged = true;
    while (intrinsicChanged) {
      intrinsicChanged = false;
      for (const definition of definitions) {
        walkDirectFunctionBody(definition, (node) => {
          if (
            node.type !== "VariableDeclarator" ||
            node.id?.type !== "Identifier" ||
            localIntrinsicBindings.has(node.id.name) ||
            assignedIdentifiers.has(node.id.name) ||
            !isProvenIntrinsicValue(node.init, localIntrinsicBindings)
          ) {
            return;
          }
          localIntrinsicBindings.add(node.id.name);
          intrinsicChanged = true;
        });
      }
    }
    const terminalNames = new Set();
    const routePaths = new Set();
    const directAmbiguities = new Set([
      ...(definitions.length > 1 ? [name] : []),
      ...(qualifiedCallableOpaqueAlternatives.has(name)
        ? [`dynamic-callable-alternative:${name}`]
        : []),
    ]);
    const requiredDependencies = new Map();
    const addRequiredDependency = (dependency) => {
      const key = `${dependency.moduleSpecifier}\u0000${dependency.exportName}`;
      let paths = requiredDependencies.get(key)?.paths;
      if (!paths) {
        paths = new Set();
        requiredDependencies.set(key, { ...dependency, paths });
      }
      paths.add(
        `${name} -> require:${dependency.moduleSpecifier}:${dependency.exportName}`,
      );
    };
    const calleeNames = new Set();
    const analyzeDefinition = (node) => {
      if (node.type === "NewExpression") {
        const dependency = requiredExportInvocation(node.callee);
        if (dependency) {
          addRequiredDependency(dependency);
          return;
        }
        if (node.callee?.type === "Identifier") {
          if (
            intrinsicGlobalReceivers.has(node.callee.name) &&
            !declaredIdentifiers.has(node.callee.name) &&
            !assignedIdentifiers.has(node.callee.name) &&
            !mutatedIntrinsicRoots.has(node.callee.name)
          ) {
            return;
          }
          calleeNames.add(node.callee.name);
          return;
        }
        if (
          node.callee?.type === "MemberExpression" &&
          isProvenIntrinsicReceiver(node.callee.object)
        ) {
          return;
        }
        directAmbiguities.add(
          `dynamic-constructor:${node.callee?.type ?? "unknown"}`,
        );
        return;
      }
      if (node.type !== "CallExpression") return;
      const terminal = staticEnforcementCall(node);
      if (terminal?.name) {
        terminalNames.add(terminal.name);
        routePaths.add(`${name} -> ${terminal.name}`);
        return;
      }
      if (terminal?.ambiguity) {
        directAmbiguities.add(terminal.ambiguity);
        return;
      }
      const dependency = requiredExportInvocation(node.callee);
      if (dependency) {
        addRequiredDependency(dependency);
        return;
      }
      if (node.callee?.type === "MemberExpression" && node.callee.computed) {
        directAmbiguities.add("computed-call");
        return;
      }
      if (node.callee?.type === "Identifier") {
        calleeNames.add(node.callee.name);
      } else if (
        node.callee?.type === "MemberExpression" &&
        new Set(["apply", "call"]).has(directMemberName(node.callee)) &&
        node.callee.object?.type === "Identifier" &&
        (callableDefinitionsByName.get(node.callee.object.name) ?? [])
          .length === 1 &&
        !mutatedIntrinsicRoots.has("Function")
      ) {
        calleeNames.add(node.callee.object.name);
      } else if (
        owner &&
        node.callee?.type === "MemberExpression" &&
        new Set(["apply", "call"]).has(directMemberName(node.callee)) &&
        node.callee.object?.type === "MemberExpression" &&
        node.callee.object.object?.type === "ThisExpression" &&
        !mutatedIntrinsicRoots.has("Function")
      ) {
        const method = directMemberName(node.callee.object);
        if (method) calleeNames.add(`${owner}.${method}`);
      } else if (
        owner &&
        node.callee?.type === "MemberExpression" &&
        node.callee.object?.type === "ThisExpression"
      ) {
        const method = directMemberName(node.callee);
        if (method) calleeNames.add(`${owner}.${method}`);
      } else if (
        node.callee?.type === "MemberExpression" &&
        node.callee.object?.type === "Identifier" &&
        staticObjectBindings.has(node.callee.object.name)
      ) {
        const method = directMemberName(node.callee);
        if (method) calleeNames.add(`${node.callee.object.name}.${method}`);
      } else if (
        node.callee?.type === "MemberExpression" &&
        (isProvenIntrinsicReceiver(node.callee.object) ||
          (node.callee.object?.type === "Identifier" &&
            localIntrinsicBindings.has(node.callee.object.name)))
      ) {
        // Intrinsic receiver identity is lexical and non-shadowed. These
        // methods cannot hide an Ibex host boundary of their own.
      } else if (node.callee?.type === "MemberExpression") {
        directAmbiguities.add(
          `dynamic-call-receiver:${directMemberName(node.callee) ?? "computed"}`,
        );
      } else {
        directAmbiguities.add(
          `dynamic-call-target:${node.callee?.type ?? "unknown"}`,
        );
      }
    };
    for (const definition of definitions) {
      // Preserve direct-call discovery before adding deferred edges. Freezing
      // that route below prevents callback-introduced cycles from erasing it.
      walkDirectFunctionBody(definition, analyzeDefinition);
      if (includeCallbackArguments) {
        walkDirectFunctionBody(
          definition,
          (node, isCallbackArgument) => {
            if (isCallbackArgument) analyzeDefinition(node);
          },
          callbackDefinitionForIdentifier,
        );
      }
    }
    const ambiguous = new Set(directAmbiguities);
    for (const callee of calleeNames) {
      const route = routeForCallable(
        callee,
        nextActive,
        includeCallbackArguments,
      );
      for (const terminal of route.terminals) terminalNames.add(terminal);
      for (const routePath of route.paths) {
        routePaths.add(`${name} -> ${routePath}`);
      }
      for (const unresolved of route.ambiguous) ambiguous.add(unresolved);
      for (const dependency of route.dependencies) {
        const key = `${dependency.moduleSpecifier}\u0000${dependency.exportName}`;
        let accumulated = requiredDependencies.get(key)?.paths;
        if (!accumulated) {
          accumulated = new Set();
          requiredDependencies.set(key, {
            exportName: dependency.exportName,
            moduleSpecifier: dependency.moduleSpecifier,
            paths: accumulated,
          });
        }
        for (const dependencyPath of dependency.paths) {
          accumulated.add(`${name} -> ${dependencyPath}`);
        }
      }
    }
    const result = {
      ambiguous: uniqueSorted(ambiguous),
      dependencies: [...requiredDependencies.values()]
        .map((dependency) => ({
          exportName: dependency.exportName,
          moduleSpecifier: dependency.moduleSpecifier,
          paths: includeCallbackArguments
            ? [shortestPath(dependency.paths)].filter(Boolean)
            : uniqueSorted(dependency.paths),
        }))
        .sort((left, right) =>
          compareText(
            `${left.moduleSpecifier}\u0000${left.exportName}`,
            `${right.moduleSpecifier}\u0000${right.exportName}`,
          ),
        ),
      paths: includeCallbackArguments
        ? representativeTerminalPaths(routePaths)
        : uniqueSorted(routePaths),
      terminals: uniqueSorted(terminalNames),
    };
    memo.set(name, result);
    return result;
  };

  // Some builtins export a function returned by a small decorator/factory,
  // for example `legacyStringValue(platform)`.  Treating every call-valued
  // export as opaque loses the real enforcement route, while blindly
  // following a factory argument would let an unrelated constructor invent a
  // route.  Recover only factories that provably return a locally declared
  // callable and whose returned callable invokes a callable parameter.
  const routeForReturnedCallableFactory = (
    call,
    includeCallbackArguments = true,
  ) => {
    if (
      call?.callee?.type !== "Identifier" ||
      (callableDefinitionsByName.get(call.callee.name) ?? []).length !== 1
    ) {
      return null;
    }
    const factoryName = call.callee.name;
    const definition = callableDefinitionsByName.get(factoryName)[0].node;
    const parameterTargets = new Map();
    for (let index = 0; index < (definition.params ?? []).length; index += 1) {
      const parameter = definition.params[index];
      const argument = call.arguments[index];
      if (parameter?.type === "Identifier" && argument?.type === "Identifier") {
        parameterTargets.set(parameter.name, argument.name);
      }
    }
    const localCallbacks = new Map();
    const returned = [];
    walkDirectFunctionBody(definition, (node) => {
      if (
        node.type === "VariableDeclarator" &&
        node.id?.type === "Identifier" &&
        callbackFunction(node.init)
      ) {
        localCallbacks.set(node.id.name, node.init);
      }
      if (node.type === "ReturnStatement") returned.push(node.argument);
    });
    if (returned.length === 0) return null;

    const terminalNames = new Set();
    const routePaths = new Set();
    const ambiguous = new Set();
    const dependencies = new Map();
    const analyzedCallbacks = new Set();
    const mergeRoute = (prefix, route) => {
      for (const terminal of route.terminals) terminalNames.add(terminal);
      for (const routePath of route.paths) {
        routePaths.add(`${prefix} -> ${routePath}`);
      }
      for (const unresolved of route.ambiguous) ambiguous.add(unresolved);
      for (const dependency of route.dependencies ?? []) {
        const key = `${dependency.moduleSpecifier}\u0000${dependency.exportName}`;
        let accumulated = dependencies.get(key)?.paths;
        if (!accumulated) {
          accumulated = new Set();
          dependencies.set(key, {
            exportName: dependency.exportName,
            moduleSpecifier: dependency.moduleSpecifier,
            paths: accumulated,
          });
        }
        for (const dependencyPath of dependency.paths) {
          accumulated.add(`${prefix} -> ${dependencyPath}`);
        }
      }
    };
    const analyzeCallback = (label, callback) => {
      if (analyzedCallbacks.has(callback)) return;
      analyzedCallbacks.add(callback);
      walkDirectFunctionBody(callback, (node) => {
        if (node.type !== "CallExpression") return;
        const terminal = staticEnforcementCall(node);
        if (terminal?.name) {
          terminalNames.add(terminal.name);
          routePaths.add(`${factoryName} -> ${label} -> ${terminal.name}`);
          return;
        }
        if (terminal?.ambiguity) {
          ambiguous.add(terminal.ambiguity);
          return;
        }
        if (node.callee?.type === "Identifier") {
          const target = parameterTargets.get(node.callee.name);
          if (target) {
            mergeRoute(
              `${factoryName} -> ${label} -> parameter:${node.callee.name}`,
              routeForCallable(target, new Set(), includeCallbackArguments),
            );
            return;
          }
          const nested = localCallbacks.get(node.callee.name);
          if (nested) {
            analyzeCallback(node.callee.name, nested);
            return;
          }
          if (
            intrinsicGlobalCalls.has(node.callee.name) ||
            intrinsicGlobalReceivers.has(node.callee.name)
          ) {
            return;
          }
          mergeRoute(
            `${factoryName} -> ${label}`,
            routeForCallable(
              node.callee.name,
              new Set(),
              includeCallbackArguments,
            ),
          );
          return;
        }
        if (node.callee?.type === "MemberExpression" && node.callee.computed) {
          ambiguous.add("computed-call");
          return;
        }
        if (
          node.callee?.type === "MemberExpression" &&
          isProvenIntrinsicReceiver(node.callee.object)
        ) {
          return;
        }
        if (node.callee?.type === "MemberExpression") {
          ambiguous.add(
            `dynamic-call-receiver:${directMemberName(node.callee) ?? "computed"}`,
          );
        }
      });
    };

    for (const value of returned) {
      if (callbackFunction(value)) {
        analyzeCallback("returned-callback", value);
        continue;
      }
      if (value?.type !== "Identifier") return null;
      const callback = localCallbacks.get(value.name);
      if (callback) {
        analyzeCallback(value.name, callback);
        continue;
      }
      const target = parameterTargets.get(value.name);
      if (!target) return null;
      mergeRoute(
        `${factoryName} -> returned-parameter:${value.name}`,
        routeForCallable(target, new Set(), includeCallbackArguments),
      );
    }
    if (
      terminalNames.size === 0 &&
      ambiguous.size === 0 &&
      dependencies.size === 0
    ) {
      return null;
    }
    return {
      ambiguous: uniqueSorted(ambiguous),
      dependencies: [...dependencies.values()]
        .map((dependency) => ({
          exportName: dependency.exportName,
          moduleSpecifier: dependency.moduleSpecifier,
          paths: uniqueSorted(dependency.paths),
        }))
        .sort((left, right) =>
          compareText(
            `${left.moduleSpecifier}\u0000${left.exportName}`,
            `${right.moduleSpecifier}\u0000${right.exportName}`,
          ),
        ),
      paths: uniqueSorted(routePaths),
      terminals: uniqueSorted(terminalNames),
    };
  };

  const routeForExport = (exportName, includeCallbackArguments = true) => {
    const segments = exportName.split(".");
    const rootName = segments[0];
    const exactBindings = bindings.get(ROOT_EXPORT_OBJECT)?.get(exportName);
    const rootBindings = bindings.get(ROOT_EXPORT_OBJECT)?.get(rootName);
    const routes = [];
    for (const localName of exactBindings ?? []) {
      routes.push(
        routeForCallable(localName, new Set(), includeCallbackArguments),
      );
    }
    for (const call of callValuedBindings
      .get(ROOT_EXPORT_OBJECT)
      ?.get(exportName) ?? []) {
      const route = routeForReturnedCallableFactory(
        call,
        includeCallbackArguments,
      );
      if (route) routes.push(route);
    }
    if (routes.length === 0 && segments.length > 1) {
      const methodName = segments.at(-1);
      for (const owner of rootBindings ?? []) {
        routes.push(
          routeForCallable(
            `${owner}.${methodName}`,
            new Set(),
            includeCallbackArguments,
          ),
        );
      }
    }
    if (routes.length === 0) {
      for (const owner of bindings.get(ROOT_EXPORT_OBJECT)?.get("default") ??
        []) {
        routes.push(
          routeForCallable(
            `${owner}.${exportName}`,
            new Set(),
            includeCallbackArguments,
          ),
        );
      }
    }
    const terminals = uniqueSorted(routes.flatMap((route) => route.terminals));
    const ambiguous = uniqueSorted(routes.flatMap((route) => route.ambiguous));
    const dependencies = new Map();
    for (const route of routes) {
      for (const dependency of route.dependencies ?? []) {
        const key = `${dependency.moduleSpecifier}\u0000${dependency.exportName}`;
        let accumulated = dependencies.get(key)?.paths;
        if (!accumulated) {
          accumulated = new Set();
          dependencies.set(key, {
            exportName: dependency.exportName,
            moduleSpecifier: dependency.moduleSpecifier,
            paths: accumulated,
          });
        }
        for (const dependencyPath of dependency.paths) {
          accumulated.add(`export:${exportName} -> ${dependencyPath}`);
        }
      }
    }
    const paths = uniqueSorted(
      routes.flatMap((route) =>
        route.paths.map((routePath) => `export:${exportName} -> ${routePath}`),
      ),
    );
    return {
      ambiguous,
      dependencies: [...dependencies.values()]
        .map((dependency) => ({
          exportName: dependency.exportName,
          moduleSpecifier: dependency.moduleSpecifier,
          paths: uniqueSorted(dependency.paths),
        }))
        .sort((left, right) =>
          compareText(
            `${left.moduleSpecifier}\u0000${left.exportName}`,
            `${right.moduleSpecifier}\u0000${right.exportName}`,
          ),
        ),
      paths,
      terminals,
    };
  };

  const mergeEnforcementRoutes = (routes) => {
    const dependencies = new Map();
    for (const route of routes.filter(Boolean)) {
      for (const dependency of route.dependencies ?? []) {
        const key = `${dependency.moduleSpecifier}\u0000${dependency.exportName}`;
        let paths = dependencies.get(key)?.paths;
        if (!paths) {
          paths = new Set();
          dependencies.set(key, { ...dependency, paths });
        }
        for (const dependencyPath of dependency.paths) {
          paths.add(dependencyPath);
        }
      }
    }
    return {
      ambiguous: uniqueSorted(
        routes.flatMap((route) => route?.ambiguous ?? []),
      ),
      dependencies: [...dependencies.values()]
        .map((dependency) => ({
          exportName: dependency.exportName,
          moduleSpecifier: dependency.moduleSpecifier,
          paths: uniqueSorted(dependency.paths),
        }))
        .sort((left, right) =>
          compareText(
            `${left.moduleSpecifier}\u0000${left.exportName}`,
            `${right.moduleSpecifier}\u0000${right.exportName}`,
          ),
        ),
      paths: uniqueSorted(routes.flatMap((route) => route?.paths ?? [])),
      terminals: uniqueSorted(
        routes.flatMap((route) => route?.terminals ?? []),
      ),
    };
  };
  const directEnforcementRoutes = new Map();

  walkAst(program, (node) => {
    if (
      node.type === "VariableDeclarator" &&
      node.id?.type === "Identifier" &&
      node.init?.type === "CallExpression" &&
      node.init.callee?.type === "Identifier" &&
      node.init.callee.name === "require" &&
      node.init.arguments[0]?.type === "StringLiteral" &&
      node.init.arguments[0].value.length > 0 &&
      !assignedIdentifiers.has(node.id.name) &&
      !declaredIdentifiers.has("require") &&
      !assignedIdentifiers.has("require")
    ) {
      requiredModuleBindings.add(node.id.name);
      requiredModuleBindingSpecifiers.set(node.id.name, {
        exportSegments: [],
        moduleSpecifier: node.init.arguments[0].value,
      });
    }
  });
  const isClosedModuleMember = (expression) =>
    isStaticRequireMember(expression) ||
    Boolean(
      expression?.type === "MemberExpression" &&
      directMemberName(expression) !== null &&
      expression.object?.type === "Identifier" &&
      requiredModuleBindings.has(expression.object.name),
    );
  const closedArrayBindings = new Set(staticArrays.keys());
  let closedArrayChanged = true;
  while (closedArrayChanged) {
    closedArrayChanged = false;
    walkAst(program, (node) => {
      if (
        node.type !== "VariableDeclarator" ||
        node.id?.type !== "Identifier" ||
        node.init?.type !== "CallExpression" ||
        node.init.arguments.length !== 0 ||
        node.init.callee?.type !== "MemberExpression" ||
        node.init.callee.computed ||
        node.init.callee.property?.type !== "Identifier" ||
        node.init.callee.property.name !== "slice"
      ) {
        return;
      }
      const source = node.init.callee.object;
      if (
        !isClosedModuleMember(source) &&
        !(source?.type === "Identifier" && closedArrayBindings.has(source.name))
      ) {
        return;
      }
      if (!closedArrayBindings.has(node.id.name)) {
        closedArrayBindings.add(node.id.name);
        closedArrayChanged = true;
      }
    });
  }

  // Record `for (key in source) target[key] = source[key]` structurally. The
  // copy is accepted only after the source domain proves closed below (or an
  // exact live-source descriptor contributes an explicit sentinel/manifest).
  walkAst(program, (node) => {
    if (node.type === "FunctionDeclaration" && node.id?.name) {
      functionDefinitions.set(node.id.name, node);
    }
    if (node.type !== "ForInStatement") return;
    const key =
      node.left?.type === "VariableDeclaration" &&
      node.left.declarations.length === 1
        ? node.left.declarations[0].id
        : node.left;
    if (key?.type !== "Identifier" || node.right?.type !== "Identifier") return;
    walkAst(node.body, (candidate) => {
      if (
        candidate.type === "AssignmentExpression" &&
        candidate.operator === "=" &&
        candidate.left?.type === "MemberExpression" &&
        candidate.left.computed &&
        candidate.left.property?.type === "Identifier" &&
        candidate.left.property.name === key.name &&
        candidate.right?.type === "MemberExpression" &&
        candidate.right.computed &&
        candidate.right.object?.type === "Identifier" &&
        candidate.right.object.name === node.right.name &&
        candidate.right.property?.type === "Identifier" &&
        candidate.right.property.name === key.name
      ) {
        tableCopyRegistrations.set(candidate.left, {
          prototypeOwner: prototypeOwner(candidate.left.object),
          source: candidate.right.object.name,
          target:
            candidate.left.object?.type === "Identifier"
              ? candidate.left.object.name
              : null,
        });
      }
      // A locked inherited prototype member cannot be shadowed with an
      // assignment from strict CommonJS. Accept the equivalent closed-table
      // descriptor copy used by Buffer's lazy initialization, while retaining
      // the same source-closure proof as the assignment spelling above.
      const descriptor = candidate.arguments?.[2];
      const descriptorValue =
        descriptor?.type === "ObjectExpression"
          ? descriptor.properties.find(
              (property) =>
                property.type === "ObjectProperty" &&
                !property.computed &&
                property.key?.type === "Identifier" &&
                property.key.name === "value",
            )?.value
          : null;
      const isDefineProperty =
        mutationCallName(candidate) === "Object.defineProperty" ||
        mutationCallName(candidate) === "Reflect.defineProperty" ||
        (sourceKey === "node_buffer" &&
          sourcePath === "src/builtins/buffer.js" &&
          candidate.callee?.type === "Identifier" &&
          candidate.callee.name === "_defineBufferPrototypeProperty");
      if (
        candidate.type === "CallExpression" &&
        isDefineProperty &&
        candidate.arguments[1]?.type === "Identifier" &&
        candidate.arguments[1].name === key.name &&
        descriptorValue?.type === "MemberExpression" &&
        descriptorValue.computed &&
        descriptorValue.object?.type === "Identifier" &&
        descriptorValue.object.name === node.right.name &&
        descriptorValue.property?.type === "Identifier" &&
        descriptorValue.property.name === key.name
      ) {
        tableCopyRegistrations.set(candidate, {
          prototypeOwner: prototypeOwner(candidate.arguments[0]),
          source: descriptorValue.object.name,
          target:
            candidate.arguments[0]?.type === "Identifier"
              ? candidate.arguments[0].name
              : null,
        });
      }
    });
  });

  const factMap = (target) => {
    let entries = facts.get(target);
    if (!entries) {
      entries = new Map();
      facts.set(target, entries);
    }
    return entries;
  };
  const addFact = (target, name, idiom) => {
    if (!target || typeof name !== "string" || name.length === 0) return;
    const entries = factMap(target);
    let idioms = entries.get(name);
    if (!idioms) {
      idioms = new Set();
      entries.set(name, idioms);
    }
    idioms.add(idiom);
  };
  const shapeFactMap = (collection, target) => {
    let entries = collection.get(target);
    if (!entries) {
      entries = new Map();
      collection.set(target, entries);
    }
    return entries;
  };
  const addShapeFact = (collection, target, name, shape) => {
    if (
      !target ||
      typeof name !== "string" ||
      name.length === 0 ||
      !new Set(["accessor", "callable", "data", "unknown"]).has(shape)
    ) {
      return;
    }
    const entries = shapeFactMap(collection, target);
    let shapes = entries.get(name);
    if (!shapes) {
      shapes = new Set();
      entries.set(name, shapes);
    }
    shapes.add(shape);
  };
  const addValueShapeFact = (target, name, shape) =>
    addShapeFact(valueShapeFacts, target, name, shape);
  const addPrototypeValueShapeFact = (owner, name, shape) =>
    addShapeFact(prototypeValueShapeFacts, owner, name, shape);
  const resolvedValueShape = (shapes) => {
    if (!shapes || shapes.size !== 1) return "unknown";
    return [...shapes][0];
  };
  const expressionValueShape = (expression, activeNames = new Set()) => {
    if (!expression) return "unknown";
    if (
      new Set([
        "ArrowFunctionExpression",
        "ClassDeclaration",
        "ClassExpression",
        "FunctionDeclaration",
        "FunctionExpression",
      ]).has(expression.type)
    ) {
      return "callable";
    }
    if (
      new Set([
        "ArrayExpression",
        "BigIntLiteral",
        "BooleanLiteral",
        "NullLiteral",
        "NumericLiteral",
        "ObjectExpression",
        "RegExpLiteral",
        "StringLiteral",
        "TemplateLiteral",
        "UnaryExpression",
      ]).has(expression.type)
    ) {
      return "data";
    }
    if (expression.type === "BinaryExpression") return "data";
    if (expression.type === "Identifier") {
      if (
        classDefinitionNames.has(expression.name) ||
        (callableDefinitionsByName.get(expression.name) ?? []).length > 0
      ) {
        return "callable";
      }
      if (activeNames.has(expression.name)) return "unknown";
      const candidates = localValueExpressions.get(expression.name) ?? [];
      if (candidates.length === 0) return "unknown";
      const nextActive = new Set(activeNames);
      nextActive.add(expression.name);
      const shapes = new Set(
        candidates.map((candidate) =>
          expressionValueShape(candidate, nextActive),
        ),
      );
      return resolvedValueShape(shapes);
    }
    if (
      expression.type === "LogicalExpression" ||
      expression.type === "ConditionalExpression"
    ) {
      const children =
        expression.type === "LogicalExpression"
          ? [expression.left, expression.right]
          : [expression.consequent, expression.alternate];
      return resolvedValueShape(
        new Set(
          children.map((child) => expressionValueShape(child, activeNames)),
        ),
      );
    }
    if (expression.type === "SequenceExpression") {
      return expressionValueShape(expression.expressions.at(-1), activeNames);
    }
    if (expression.type === "MemberExpression") {
      const shapes = new Set();
      const member = memberTargetAndNames(expression, new Map(), staticArrays);
      if (member) {
        for (const name of member.names) {
          for (const shape of valueShapeFacts.get(member.target)?.get(name) ??
            []) {
            shapes.add(shape);
          }
        }
      }
      const owner = prototypeOwner(expression.object);
      const name = directMemberName(expression);
      if (owner && name) {
        for (const shape of prototypeValueShapeFacts.get(owner)?.get(name) ??
          []) {
          shapes.add(shape);
        }
      }
      return resolvedValueShape(shapes);
    }
    if (
      expression.type === "CallExpression" &&
      new Set(["freeze", "seal"]).has(callName(expression)) &&
      expression.callee?.type === "MemberExpression" &&
      expression.callee.object?.type === "Identifier" &&
      expression.callee.object.name === "Object" &&
      expression.arguments.length === 1
    ) {
      return expressionValueShape(expression.arguments[0], activeNames);
    }
    return "unknown";
  };
  const propertyValueShape = (property) => {
    if (property?.type === "ObjectMethod") {
      if (property.kind === "get") return "accessor";
      if (property.kind === "set") return null;
      return "callable";
    }
    if (property?.type === "ObjectProperty") {
      return expressionValueShape(property.value);
    }
    return "unknown";
  };
  const descriptorValueShape = (descriptor) => {
    if (descriptor?.type !== "ObjectExpression") return "unknown";
    let value = null;
    let getter = false;
    let invalidGetter = false;
    for (const property of descriptor.properties) {
      if (property.type === "SpreadElement" || property.computed) continue;
      const names =
        property.key?.type === "Identifier"
          ? [property.key.name]
          : staticPropertyName(property.key);
      if (names.includes("get")) {
        if (propertyValueShape(property) === "callable") getter = true;
        else invalidGetter = true;
      }
      if (names.includes("value") && property.type === "ObjectProperty") {
        value = property.value;
      }
    }
    if ((getter || invalidGetter) && value) return "unknown";
    if (invalidGetter) return "unknown";
    if (getter) return "accessor";
    return value ? expressionValueShape(value) : "unknown";
  };
  const addAlias = (target, source) => {
    if (!target || !source || target === source) return;
    let sources = aliases.get(target);
    if (!sources) {
      sources = new Set();
      aliases.set(target, sources);
    }
    sources.add(source);
  };
  const addBinding = (target, exportName, localName) => {
    if (!target || !exportName || !localName) return;
    let targetBindings = bindings.get(target);
    if (!targetBindings) {
      targetBindings = new Map();
      bindings.set(target, targetBindings);
    }
    let localNames = targetBindings.get(exportName);
    if (!localNames) {
      localNames = new Set();
      targetBindings.set(exportName, localNames);
    }
    localNames.add(localName);
  };
  const addCallValuedBinding = (target, exportName, call) => {
    if (!target || !exportName || call?.type !== "CallExpression") return;
    let targetBindings = callValuedBindings.get(target);
    if (!targetBindings) {
      targetBindings = new Map();
      callValuedBindings.set(target, targetBindings);
    }
    let calls = targetBindings.get(exportName);
    if (!calls) {
      calls = new Set();
      targetBindings.set(exportName, calls);
    }
    calls.add(call);
  };
  const recordPrototypeFact = (owner, name) => {
    if (!owner || !name) return;
    let names = prototypeFacts.get(owner);
    if (!names) {
      names = new Set();
      prototypeFacts.set(owner, names);
    }
    names.add(name);
  };
  const addPrototypeFact = (owner, name) => {
    recordPrototypeFact(owner, name);
    if (!owner || !name) return;
    let names = ownPrototypeFacts.get(owner);
    if (!names) {
      names = new Set();
      ownPrototypeFacts.set(owner, names);
    }
    names.add(name);
  };
  const markInheritedPrototypeFact = (owner, name) => {
    recordPrototypeFact(owner, name);
    let names = inheritedPrototypeFacts.get(owner);
    if (!names) {
      names = new Set();
      inheritedPrototypeFacts.set(owner, names);
    }
    names.add(name);
  };
  const inheritedShapeSentinel = (node, idiom) => {
    const source = node
      ? text.slice(node.start ?? 0, node.end ?? node.start ?? 0)
      : idiom;
    const digest = sha256Hex(`${idiom}\0${source}`).slice(0, 12);
    return `[[dynamic-table:inherited-${digest}-properties]]`;
  };
  const addPrototypeSource = (owner, sourceOwner, node, idiom) => {
    if (!owner) return;
    let sources = prototypeSources.get(owner);
    if (!sources) {
      sources = new Map();
      prototypeSources.set(owner, sources);
    }
    const key = sourceOwner ?? inheritedShapeSentinel(node, idiom);
    sources.set(key, { idiom, node, sourceOwner });
  };
  const addObjectPrototypeOwner = (target, owner) => {
    if (!target || !owner) return;
    let owners = objectPrototypeOwners.get(target);
    if (!owners) {
      owners = new Set();
      objectPrototypeOwners.set(target, owners);
    }
    owners.add(owner);
  };
  const observeComputedRegistration = (
    node,
    target,
    property,
    names,
    idiom,
  ) => {
    if (!node?.computed || !target) return;
    if (
      names.length > 0 ||
      isStaticallyNonPublicPropertyKey(property, nonPublicBindings)
    ) {
      resolvedRegistrations.add(node);
      return;
    }
    if (!unresolvedRegistrations.has(node)) {
      unresolvedRegistrations.set(node, { idiom, target });
    }
  };
  const observeOpaqueShape = (node, target, source, idiom) => {
    if (!node || !target || opaqueShapeRegistrations.has(node)) return;
    opaqueShapeRegistrations.set(node, { idiom, source, target });
  };
  const observePrototypeRegistration = (
    node,
    owner,
    property,
    names,
    idiom,
  ) => {
    if (!owner) return;
    if (
      names.length > 0 ||
      isStaticallyNonPublicPropertyKey(property, nonPublicBindings)
    ) {
      resolvedRegistrations.add(node);
      return;
    }
    if (!unresolvedPrototypeRegistrations.has(node)) {
      unresolvedPrototypeRegistrations.set(node, { idiom, owner });
    }
  };
  const recordClassMembers = (classNode, owner, substitutions) => {
    if (!classNode || !owner) return;
    knownPrototypeOwners.add(owner);
    for (const method of classNode.body?.body ?? []) {
      const names =
        !method.computed && method.key?.type === "Identifier"
          ? [method.key.name]
          : staticPropertyName(method.key, substitutions);
      observePrototypeRegistration(
        method,
        owner,
        method.key,
        names,
        method.static
          ? "computed-static-class-member"
          : "computed-class-member",
      );
      for (const name of names) {
        addPrototypeFact(owner, name);
        addPrototypeValueShapeFact(
          owner,
          name,
          method.kind === "get"
            ? "accessor"
            : method.kind === "set"
              ? null
              : "callable",
        );
      }
    }
    if (classNode.superClass) {
      const baseOwner =
        classNode.superClass.type === "Identifier"
          ? classNode.superClass.name
          : prototypeOwner(classNode.superClass);
      addPrototypeSource(
        owner,
        baseOwner,
        classNode.superClass,
        "class-extends",
      );
    }
  };
  const classExpressionOwners = new WeakMap();
  const classExpressionOwner = (classNode) => {
    let owner = classExpressionOwners.get(classNode);
    if (!owner) {
      const source = text.slice(
        classNode.start ?? 0,
        classNode.end ?? classNode.start ?? 0,
      );
      owner = `[[class-expression:${sha256Hex(source).slice(0, 12)}]]`;
      classExpressionOwners.set(classNode, owner);
    }
    return owner;
  };
  const bindClassExpression = (
    target,
    exportNames,
    classNode,
    substitutions,
    visitingCallableDefinitions = new Set(),
  ) => {
    if (!classNode) return false;
    if (classNode.type === "ClassExpression") {
      const owner = classExpressionOwner(classNode);
      recordClassMembers(classNode, owner, substitutions);
      for (const exportName of exportNames)
        addBinding(target, exportName, owner);
      return true;
    }
    if (
      classNode.type === "Identifier" &&
      (knownPrototypeOwners.has(classNode.name) ||
        prototypeFacts.has(classNode.name))
    ) {
      for (const exportName of exportNames)
        addBinding(target, exportName, classNode.name);
      return true;
    }
    if (
      classNode.type === "LogicalExpression" ||
      classNode.type === "ConditionalExpression" ||
      classNode.type === "SequenceExpression"
    ) {
      const children =
        classNode.type === "LogicalExpression"
          ? [classNode.left, classNode.right]
          : classNode.type === "ConditionalExpression"
            ? [classNode.consequent, classNode.alternate]
            : [classNode.expressions.at(-1)];
      let bound = false;
      for (const child of children) {
        bound =
          bindClassExpression(
            target,
            exportNames,
            child,
            substitutions,
            visitingCallableDefinitions,
          ) ||
          bound;
      }
      return bound;
    }
    if (
      classNode.type === "CallExpression" &&
      classNode.callee?.type === "Identifier"
    ) {
      const definitions =
        callableDefinitionsByName.get(classNode.callee.name) ?? [];
      if (definitions.length !== 1) {
        const containsDirectClass = (expression) => {
          if (!expression) return false;
          if (expression.type === "ClassExpression") return true;
          if (expression.type === "LogicalExpression")
            return (
              containsDirectClass(expression.left) ||
              containsDirectClass(expression.right)
            );
          if (expression.type === "ConditionalExpression")
            return (
              containsDirectClass(expression.consequent) ||
              containsDirectClass(expression.alternate)
            );
          if (expression.type === "SequenceExpression")
            return containsDirectClass(expression.expressions.at(-1));
          return false;
        };
        if (classNode.arguments.some(containsDirectClass)) {
          throw new Error(
            `${sourcePath}: unresolved public class decorator/factory call ${classNode.callee.name}`,
          );
        }
        return false;
      }
      const definition = definitions[0].node;
      if (visitingCallableDefinitions.has(definition)) return false;
      visitingCallableDefinitions.add(definition);
      try {
        const localValues = new Map();
        walkDirectFunctionBody(definition, (node) => {
          if (
            node.type === "VariableDeclarator" &&
            node.id?.type === "Identifier" &&
            node.init
          ) {
            localValues.set(node.id.name, node.init);
          }
        });
        const bindReturnedValue = (value, seen = new Set()) => {
          if (value?.type === "Identifier" && localValues.has(value.name)) {
            if (seen.has(value.name)) return false;
            const nextSeen = new Set(seen);
            nextSeen.add(value.name);
            return bindReturnedValue(localValues.get(value.name), nextSeen);
          }
          return bindClassExpression(
            target,
            exportNames,
            value,
            substitutions,
            visitingCallableDefinitions,
          );
        };
        let bound = false;
        if (
          definition.type === "ArrowFunctionExpression" &&
          definition.body?.type !== "BlockStatement"
        ) {
          bound = bindReturnedValue(definition.body);
        } else {
          walkDirectFunctionBody(definition, (node) => {
            if (node.type !== "ReturnStatement") return;
            bound = bindReturnedValue(node.argument) || bound;
          });
        }
        return bound;
      } finally {
        visitingCallableDefinitions.delete(definition);
      }
    }
    return false;
  };
  const reviewedClosedCallValue = (expression) => {
    if (expression?.type !== "CallExpression") return false;
    if (
      callName(expression) === "create" &&
      expression.callee?.type === "MemberExpression" &&
      expression.callee.object?.type === "Identifier" &&
      expression.callee.object.name === "Object" &&
      expression.arguments.length >= 1 &&
      expression.arguments.length <= 2 &&
      (expression.arguments[1] === undefined ||
        expression.arguments[1]?.type === "ObjectExpression")
    ) {
      return true;
    }
    if (
      new Set(["freeze", "seal"]).has(callName(expression)) &&
      expression.callee?.type === "MemberExpression" &&
      expression.callee.object?.type === "Identifier" &&
      expression.callee.object.name === "Object" &&
      expression.arguments.length === 1 &&
      expression.arguments[0]?.type === "ObjectExpression"
    ) {
      return true;
    }
    if (
      expression.arguments.length === 0 &&
      expression.callee?.type === "MemberExpression" &&
      !expression.callee.computed &&
      expression.callee.property?.type === "Identifier" &&
      expression.callee.property.name === "slice" &&
      expression.callee.object?.type === "Identifier" &&
      closedArrayBindings.has(expression.callee.object.name)
    ) {
      return true;
    }
    if (expression.callee?.type !== "Identifier") return false;
    const definitions =
      callableDefinitionsByName.get(expression.callee.name) ?? [];
    if (definitions.length !== 1) return false;
    const scalarExpression = (value) => {
      if (!value) return false;
      if (
        new Set([
          "BigIntLiteral",
          "BooleanLiteral",
          "NullLiteral",
          "NumericLiteral",
          "StringLiteral",
          "TemplateLiteral",
        ]).has(value.type)
      ) {
        return true;
      }
      if (value.type === "UnaryExpression") return true;
      if (value.type === "BinaryExpression") return true;
      if (value.type === "LogicalExpression")
        return scalarExpression(value.left) && scalarExpression(value.right);
      if (value.type === "ConditionalExpression")
        return (
          scalarExpression(value.consequent) &&
          scalarExpression(value.alternate)
        );
      if (value.type === "SequenceExpression")
        return scalarExpression(value.expressions.at(-1));
      return false;
    };
    const definition = definitions[0].node;
    if (
      definition.type === "ArrowFunctionExpression" &&
      definition.body?.type !== "BlockStatement"
    ) {
      return scalarExpression(definition.body);
    }
    const returns = [];
    walkDirectFunctionBody(definition, (node) => {
      if (node.type === "ReturnStatement") returns.push(node.argument);
    });
    return returns.length > 0 && returns.every(scalarExpression);
  };
  const opaqueCallValue = (expression) => {
    if (!expression) return null;
    if (expression.type === "CallExpression")
      return reviewedClosedCallValue(expression) ? null : expression;
    if (expression.type === "LogicalExpression")
      return (
        opaqueCallValue(expression.left) ?? opaqueCallValue(expression.right)
      );
    if (expression.type === "ConditionalExpression")
      return (
        opaqueCallValue(expression.consequent) ??
        opaqueCallValue(expression.alternate)
      );
    if (expression.type === "SequenceExpression")
      return opaqueCallValue(expression.expressions.at(-1));
    return null;
  };
  const recordOpaqueCallResult = (target, exportNames, expression, idiom) => {
    const call = opaqueCallValue(expression);
    if (!call) return false;
    const sentinel = inheritedShapeSentinel(call, idiom);
    for (const exportName of exportNames) {
      addFact(target, `${exportName}.${sentinel}`, "inherited-shape-sentinel");
    }
    resolvedOpaqueShapeNodes.add(call);
    return true;
  };

  const receiverFacts = new Map();
  const receiverUnresolved = new Map();
  const receiverKey = (functionName, parameterIndex) =>
    `${functionName}\0${parameterIndex}`;
  const receiverFactSet = (key) => {
    let names = receiverFacts.get(key);
    if (!names) {
      names = new Set();
      receiverFacts.set(key, names);
    }
    return names;
  };
  const receiverUnresolvedMap = (key) => {
    let registrations = receiverUnresolved.get(key);
    if (!registrations) {
      registrations = new Map();
      receiverUnresolved.set(key, registrations);
    }
    return registrations;
  };
  const receiverForExpression = (definition, expression) => {
    if (expression?.type === "ThisExpression") {
      return { kind: "prototype", owner: definition.name };
    }
    if (expression?.type !== "Identifier") return null;
    const parameterIndex = definition.node.params.findIndex(
      (parameter) =>
        parameter?.type === "Identifier" && parameter.name === expression.name,
    );
    return parameterIndex === -1
      ? null
      : {
          key: receiverKey(definition.name, parameterIndex),
          kind: "parameter",
        };
  };
  const addReceiverNames = (receiver, names) => {
    if (!receiver) return false;
    let changed = false;
    if (receiver.kind === "prototype") {
      const existing = prototypeFacts.get(receiver.owner) ?? new Set();
      const before = existing.size;
      for (const name of names) addPrototypeFact(receiver.owner, name);
      changed = (prototypeFacts.get(receiver.owner)?.size ?? 0) !== before;
    } else {
      const existing = receiverFactSet(receiver.key);
      const before = existing.size;
      for (const name of names) existing.add(name);
      changed = existing.size !== before;
    }
    return changed;
  };
  const addReceiverUnresolved = (receiver, node, idiom, property = null) => {
    if (!receiver || !node) return false;
    if (receiver.kind === "prototype") {
      const before = unresolvedPrototypeRegistrations.size;
      if (!unresolvedPrototypeRegistrations.has(node)) {
        unresolvedPrototypeRegistrations.set(node, {
          idiom,
          owner: receiver.owner,
          property,
        });
      }
      return unresolvedPrototypeRegistrations.size !== before;
    }
    const registrations = receiverUnresolvedMap(receiver.key);
    const before = registrations.size;
    if (!registrations.has(node)) registrations.set(node, { idiom, property });
    return registrations.size !== before;
  };
  const recordReceiverProperty = (
    definition,
    receiverExpression,
    property,
    computed,
    node,
    idiom,
  ) => {
    const receiver = receiverForExpression(definition, receiverExpression);
    if (!receiver) return;
    const names =
      !computed && property?.type === "Identifier"
        ? [property.name]
        : staticPropertyName(property, staticBindings);
    if (names.length > 0) {
      addReceiverNames(receiver, names);
      resolvedRegistrations.add(node);
    } else if (isStaticallyNonPublicPropertyKey(property, nonPublicBindings)) {
      resolvedRegistrations.add(node);
    } else {
      addReceiverUnresolved(receiver, node, idiom, property);
    }
  };

  // Constructor APIs are sometimes installed directly on each instance rather
  // than on the prototype. Follow receiver parameters through initializer
  // helpers (for example `ReadStream -> _initReadStream(this, ...)`) so those
  // methods remain part of the exported constructor surface.
  for (const definition of callableDefinitions) {
    walkDirectFunctionBody(definition.node, (node) => {
      if (
        node.type === "AssignmentExpression" &&
        node.operator === "=" &&
        node.left?.type === "MemberExpression" &&
        isJavaScriptFunctionNode(node.right)
      ) {
        recordReceiverProperty(
          definition,
          node.left.object,
          node.left.property,
          node.left.computed,
          node.left,
          "computed-instance-method-assignment",
        );
      }
      if (node.type !== "CallExpression") return;
      const mutation = mutationCallName(node);
      if (
        mutation === "Object.defineProperty" ||
        mutation === "Reflect.defineProperty"
      ) {
        recordReceiverProperty(
          definition,
          node.arguments[0],
          node.arguments[1],
          true,
          node,
          `computed-instance-${mutation.replace(".", "-")}`,
        );
      } else if (mutation === "Reflect.set") {
        recordReceiverProperty(
          definition,
          node.arguments[0],
          node.arguments[1],
          true,
          node,
          "computed-instance-reflect-set",
        );
      } else if (
        mutation === "Object.assign" &&
        node.arguments[1]?.type === "ObjectExpression"
      ) {
        const receiver = receiverForExpression(definition, node.arguments[0]);
        if (!receiver) return;
        for (const property of node.arguments[1].properties) {
          if (property.type === "SpreadElement") {
            addReceiverUnresolved(
              receiver,
              property,
              "opaque-instance-object-assign-spread",
              property,
            );
            continue;
          }
          recordReceiverProperty(
            definition,
            node.arguments[0],
            property.key,
            property.computed,
            property,
            "computed-instance-object-assign",
          );
        }
      }
    });
  }

  let receiverChanged = true;
  while (receiverChanged) {
    receiverChanged = false;
    for (const definition of callableDefinitions) {
      walkDirectFunctionBody(definition.node, (node) => {
        if (
          node.type !== "CallExpression" ||
          node.callee?.type !== "Identifier"
        ) {
          return;
        }
        const candidates =
          callableDefinitionsByName.get(node.callee.name) ?? [];
        if (candidates.length !== 1) return;
        const callee = candidates[0];
        for (let index = 0; index < node.arguments.length; index += 1) {
          const destination = receiverForExpression(
            definition,
            node.arguments[index],
          );
          if (!destination) continue;
          const sourceKey = receiverKey(callee.name, index);
          receiverChanged =
            addReceiverNames(
              destination,
              receiverFacts.get(sourceKey) ?? new Set(),
            ) || receiverChanged;
          for (const [registration, detail] of receiverUnresolved.get(
            sourceKey,
          ) ?? []) {
            let resolvedNames = [];
            if (detail.property?.type === "Identifier") {
              const propertyParameterIndex = callee.node.params.findIndex(
                (parameter) =>
                  parameter?.type === "Identifier" &&
                  parameter.name === detail.property.name,
              );
              if (propertyParameterIndex !== -1) {
                resolvedNames = staticRegistrationNames(
                  node.arguments[propertyParameterIndex],
                  staticBindings,
                  staticArrays,
                );
              }
            }
            if (resolvedNames.length > 0) {
              receiverChanged =
                addReceiverNames(destination, resolvedNames) || receiverChanged;
              continue;
            }
            receiverChanged =
              addReceiverUnresolved(
                destination,
                registration,
                detail.idiom,
                detail.property,
              ) || receiverChanged;
          }
        }
      });
    }
  }

  const recordPrototypeObjectMembers = (
    owner,
    expression,
    idiom,
    substitutions,
  ) => {
    if (!owner) return;
    if (expression?.type !== "ObjectExpression") {
      if (expression && !unresolvedPrototypeRegistrations.has(expression)) {
        unresolvedPrototypeRegistrations.set(expression, { idiom, owner });
      }
      return;
    }
    for (const property of expression.properties) {
      if (property.type === "SpreadElement") {
        if (!unresolvedPrototypeRegistrations.has(property)) {
          unresolvedPrototypeRegistrations.set(property, { idiom, owner });
        }
        continue;
      }
      const names =
        !property.computed && property.key?.type === "Identifier"
          ? [property.key.name]
          : staticPropertyName(property.key, substitutions);
      observePrototypeRegistration(property, owner, property.key, names, idiom);
      for (const name of names) {
        addPrototypeFact(owner, name);
        addPrototypeValueShapeFact(owner, name, propertyValueShape(property));
      }
    }
  };

  const recordPrototypeInheritance = (
    owner,
    expression,
    node,
    idiom,
    substitutions,
  ) => {
    if (!owner || !expression || expression.type === "NullLiteral") return;
    if (expression.type === "ObjectExpression") {
      recordPrototypeObjectMembers(
        owner,
        expression,
        `${idiom}-object-literal`,
        substitutions,
      );
      return;
    }
    const sourceOwner =
      expression.type === "Identifier"
        ? expression.name
        : prototypeOwner(expression);
    addPrototypeSource(owner, sourceOwner, node ?? expression, idiom);
  };

  const recordExpression = (
    target,
    expression,
    idiom,
    substitutions = new Map(),
  ) => {
    if (!target || !expression) return;
    if (expression.type === "ObjectExpression") {
      for (const name of objectPropertyNames(expression, substitutions))
        addFact(target, name, idiom);
      for (const property of expression.properties) {
        if (property.type === "SpreadElement") {
          if (property.argument?.type === "Identifier") {
            addAlias(target, property.argument.name);
            observeOpaqueShape(
              property,
              target,
              property.argument.name,
              `${idiom}-object-spread`,
            );
          } else {
            observeOpaqueShape(
              property,
              target,
              null,
              `${idiom}-opaque-object-spread`,
            );
          }
          continue;
        }
        const names =
          !property.computed && property.key?.type === "Identifier"
            ? [property.key.name]
            : staticPropertyName(property.key, substitutions);
        if (property.type !== "SpreadElement") {
          observeComputedRegistration(
            property,
            target,
            property.key,
            names,
            `${idiom}-object-property`,
          );
          for (const name of names) {
            addValueShapeFact(target, name, propertyValueShape(property));
          }
        }
        if (property.value?.type === "Identifier") {
          for (const name of names)
            addBinding(target, name, property.value.name);
        } else {
          if (property.value?.type === "CallExpression") {
            for (const name of names) {
              addCallValuedBinding(target, name, property.value);
            }
          }
          const classBound = bindClassExpression(
            target,
            names,
            property.value,
            substitutions,
          );
          if (!classBound) {
            recordOpaqueCallResult(
              target,
              names,
              property.value,
              `${idiom}-call-valued-property`,
            );
          }
        }
      }
      return;
    }
    if (expression.type === "Identifier") {
      addAlias(target, expression.name);
      observeOpaqueShape(
        expression,
        target,
        expression.name,
        `${idiom}-identifier-shape`,
      );
      return;
    }
    if (
      expression.type === "FunctionExpression" ||
      expression.type === "ArrowFunctionExpression" ||
      expression.type === "ClassExpression"
    ) {
      if (expression.type === "ClassExpression") {
        recordClassMembers(
          expression,
          expression.id?.name ?? target,
          substitutions,
        );
      }
      return;
    }
    if (isClosedModuleMember(expression)) return;
    if (
      expression.type === "CallExpression" &&
      callName(expression) === "create" &&
      (expression.arguments[1] === undefined ||
        expression.arguments[1]?.type === "ObjectExpression")
    ) {
      const inherited = expression.arguments[0];
      if (inherited?.type === "ObjectExpression") {
        recordExpression(
          target,
          inherited,
          `${idiom}-object-create-prototype`,
          substitutions,
        );
      } else if (inherited?.type === "Identifier") {
        addAlias(target, inherited.name);
      } else {
        const inheritedOwner = prototypeOwner(inherited);
        if (inheritedOwner) {
          addObjectPrototypeOwner(target, inheritedOwner);
        } else if (inherited && inherited.type !== "NullLiteral") {
          addFact(
            target,
            inheritedShapeSentinel(inherited, `${idiom}-object-create`),
            "inherited-shape-sentinel",
          );
        }
      }
      if (expression.arguments[1]) {
        recordExpression(
          target,
          expression.arguments[1],
          `${idiom}-object-create-descriptors`,
          substitutions,
        );
      }
      return;
    }
    if (expression.type === "CallExpression") {
      observeOpaqueShape(
        expression,
        target,
        expression.callee?.type === "Identifier"
          ? `<function-return:${expression.callee.name}>`
          : null,
        `${idiom}-call-shape`,
      );
      return;
    }
    if (
      expression.type === "LogicalExpression" ||
      expression.type === "ConditionalExpression" ||
      expression.type === "SequenceExpression"
    ) {
      const children =
        expression.type === "LogicalExpression"
          ? [expression.left, expression.right]
          : expression.type === "ConditionalExpression"
            ? [expression.consequent, expression.alternate]
            : expression.expressions;
      for (const child of children)
        recordExpression(target, child, idiom, substitutions);
      return;
    }
    if (
      expression.type === "NullLiteral" ||
      expression.type === "BooleanLiteral" ||
      expression.type === "NumericLiteral" ||
      expression.type === "StringLiteral"
    ) {
      return;
    }
    observeOpaqueShape(expression, target, null, `${idiom}-opaque-shape`);
  };

  const recordNode = (node, substitutions = new Map()) => {
    if (node.type === "FunctionDeclaration" && node.id?.name) {
      knownPrototypeOwners.add(node.id.name);
    }
    if (node.type === "ClassDeclaration" && node.id?.name) {
      recordClassMembers(node, node.id.name, substitutions);
    }
    if (node.type === "VariableDeclarator" && node.id?.type === "Identifier") {
      if (node.init?.type === "ClassExpression") {
        recordClassMembers(node.init, node.id.name, substitutions);
      } else if (node.init?.type === "FunctionExpression") {
        knownPrototypeOwners.add(node.id.name);
      }
      recordExpression(
        node.id.name,
        node.init,
        "object-binding",
        substitutions,
      );
      return;
    }

    if (node.type === "AssignmentExpression" && node.operator === "=") {
      if (isModuleExports(node.left)) {
        addFact(ROOT_EXPORT_OBJECT, "default", "module-exports-assignment");
        addValueShapeFact(
          ROOT_EXPORT_OBJECT,
          "default",
          expressionValueShape(node.right),
        );
        let classBound = false;
        if (node.right?.type === "Identifier") {
          addBinding(ROOT_EXPORT_OBJECT, "default", node.right.name);
        } else {
          classBound = bindClassExpression(
            ROOT_EXPORT_OBJECT,
            ["default"],
            node.right,
            substitutions,
          );
        }
        if (!classBound) {
          recordOpaqueCallResult(
            ROOT_EXPORT_OBJECT,
            ["default"],
            node.right,
            "module-exports-call-result",
          );
        }
        recordExpression(
          ROOT_EXPORT_OBJECT,
          node.right,
          "module-exports-object",
          substitutions,
        );
        return;
      }
      if (node.left?.type === "Identifier") {
        recordExpression(
          node.left.name,
          node.right,
          "object-assignment",
          substitutions,
        );
        return;
      }
      if (
        node.left?.type === "MemberExpression" &&
        directMemberName(node.left) === "__proto__"
      ) {
        const target = exportTargetId(node.left.object);
        const owner = prototypeOwner(node.left.object);
        if (owner) {
          recordPrototypeInheritance(
            owner,
            node.right,
            node,
            "prototype-__proto__-assignment",
            substitutions,
          );
        } else if (target) {
          if (node.right?.type === "ObjectExpression") {
            recordExpression(
              target,
              node.right,
              "object-__proto__-assignment",
              substitutions,
            );
          } else if (node.right?.type === "Identifier") {
            addAlias(target, node.right.name);
          } else {
            const inheritedOwner = prototypeOwner(node.right);
            if (inheritedOwner) addObjectPrototypeOwner(target, inheritedOwner);
            else
              addFact(
                target,
                inheritedShapeSentinel(node.right, "object-__proto__"),
                "inherited-shape-sentinel",
              );
          }
        }
        return;
      }
      if (
        node.left?.type === "MemberExpression" &&
        directMemberName(node.left) === "prototype" &&
        node.left.object?.type === "Identifier" &&
        node.right?.type === "CallExpression" &&
        callName(node.right) === "create"
      ) {
        knownPrototypeOwners.add(node.left.object.name);
        recordPrototypeInheritance(
          node.left.object.name,
          node.right.arguments[0],
          node.right,
          "prototype-object-create",
          substitutions,
        );
        if (node.right.arguments[1]) {
          recordPrototypeObjectMembers(
            node.left.object.name,
            node.right.arguments[1],
            "prototype-object-create-descriptors",
            substitutions,
          );
          for (const name of objectPropertyNames(
            node.right.arguments[1],
            substitutions,
          )) {
            markInheritedPrototypeFact(node.left.object.name, name);
          }
        }
        return;
      }
      if (
        node.left?.type === "MemberExpression" &&
        directMemberName(node.left) === "prototype" &&
        node.left.object?.type === "Identifier" &&
        node.right
      ) {
        knownPrototypeOwners.add(node.left.object.name);
        recordPrototypeInheritance(
          node.left.object.name,
          node.right,
          node,
          "prototype-assignment",
          substitutions,
        );
      }
      const prototype = prototypeOwner(node.left?.object);
      if (prototype) {
        const names =
          !node.left.computed && node.left.property?.type === "Identifier"
            ? [node.left.property.name]
            : staticPropertyName(node.left.property, substitutions);
        observePrototypeRegistration(
          node.left,
          prototype,
          node.left.property,
          names,
          "computed-prototype-assignment",
        );
        for (const name of names) {
          addPrototypeFact(prototype, name);
          addPrototypeValueShapeFact(
            prototype,
            name,
            expressionValueShape(node.right),
          );
        }
      }
      if (
        node.left?.type === "MemberExpression" &&
        directMemberName(node.left) === "prototype" &&
        node.left.object?.type === "Identifier" &&
        node.right?.type === "ObjectExpression"
      ) {
        recordPrototypeObjectMembers(
          node.left.object.name,
          node.right,
          "computed-prototype-object-assignment",
          substitutions,
        );
      }
      const member = memberTargetAndNames(
        node.left,
        substitutions,
        staticArrays,
      );
      if (member) {
        observeComputedRegistration(
          node.left,
          member.target,
          node.left.property,
          member.names,
          "member-assignment",
        );
        for (const name of member.names) {
          addFact(member.target, name, "member-assignment");
          addValueShapeFact(
            member.target,
            name,
            expressionValueShape(node.right),
          );
          if (node.right?.type === "Identifier")
            addBinding(member.target, name, node.right.name);
        }
        const classBound = bindClassExpression(
          member.target,
          member.names,
          node.right,
          substitutions,
        );
        if (!classBound) {
          recordOpaqueCallResult(
            member.target,
            member.names,
            node.right,
            "call-valued-member-assignment",
          );
        }
      }
      return;
    }

    if (node.type === "CallExpression") {
      const objectCall = callName(node);
      const mutation = mutationCallName(node);
      if (
        node.callee?.type === "MemberExpression" &&
        !node.callee.computed &&
        node.callee.object?.type === "Identifier" &&
        node.callee.object.name === "util" &&
        node.callee.property?.type === "Identifier" &&
        node.callee.property.name === "inherits" &&
        node.arguments[0]?.type === "Identifier"
      ) {
        knownPrototypeOwners.add(node.arguments[0].name);
        recordPrototypeInheritance(
          node.arguments[0].name,
          node.arguments[1],
          node,
          "util-inherits",
          substitutions,
        );
      }
      if (
        mutation === "Object.setPrototypeOf" ||
        mutation === "Reflect.setPrototypeOf"
      ) {
        const target = exportTargetId(node.arguments[0]);
        const owner =
          prototypeOwner(node.arguments[0]) ??
          (node.arguments[0]?.type === "Identifier"
            ? node.arguments[0].name
            : null);
        if (owner) {
          knownPrototypeOwners.add(owner);
          recordPrototypeInheritance(
            owner,
            node.arguments[1],
            node,
            mutation,
            substitutions,
          );
        }
        if (target) {
          const inherited = node.arguments[1];
          if (inherited?.type === "ObjectExpression") {
            recordExpression(target, inherited, mutation, substitutions);
          } else if (inherited?.type === "Identifier") {
            addAlias(target, inherited.name);
          } else {
            const inheritedOwner = prototypeOwner(inherited);
            if (inheritedOwner) addObjectPrototypeOwner(target, inheritedOwner);
            else if (inherited && inherited.type !== "NullLiteral")
              addFact(
                target,
                inheritedShapeSentinel(inherited, mutation),
                "inherited-shape-sentinel",
              );
          }
        }
      } else if (
        mutation === "Object.defineProperty" ||
        mutation === "Reflect.defineProperty"
      ) {
        const idiom =
          mutation === "Object.defineProperty"
            ? "define-property"
            : "reflect-define-property";
        const target = exportTargetId(node.arguments[0]);
        const names = staticPropertyName(node.arguments[1], substitutions);
        if (target && names.length === 0) {
          if (
            isStaticallyNonPublicPropertyKey(
              node.arguments[1],
              nonPublicBindings,
            )
          ) {
            resolvedRegistrations.add(node);
          } else if (!unresolvedRegistrations.has(node)) {
            unresolvedRegistrations.set(node, {
              idiom,
              target,
            });
          }
        } else if (names.length > 0) {
          resolvedRegistrations.add(node);
        }
        for (const name of names) {
          addFact(target, name, idiom);
          addValueShapeFact(
            target,
            name,
            descriptorValueShape(node.arguments[2]),
          );
        }
        const descriptorValue =
          node.arguments[2]?.type === "ObjectExpression"
            ? (node.arguments[2].properties.find(
                (property) =>
                  property.type === "ObjectProperty" &&
                  !property.computed &&
                  property.key?.type === "Identifier" &&
                  property.key.name === "value",
              )?.value ?? null)
            : null;
        const classBound = bindClassExpression(
          target,
          names,
          descriptorValue,
          substitutions,
        );
        if (!classBound) {
          recordOpaqueCallResult(
            target,
            names,
            descriptorValue,
            `${idiom}-call-valued-descriptor`,
          );
        }
        const prototype = prototypeOwner(node.arguments[0]);
        const prototypeNames = staticPropertyName(
          node.arguments[1],
          substitutions,
        );
        observePrototypeRegistration(
          node,
          prototype,
          node.arguments[1],
          prototypeNames,
          `computed-prototype-${idiom}`,
        );
        for (const name of prototypeNames) {
          addPrototypeFact(prototype, name);
          addPrototypeValueShapeFact(
            prototype,
            name,
            descriptorValueShape(node.arguments[2]),
          );
        }
      } else if (mutation === "Reflect.set") {
        const target = exportTargetId(node.arguments[0]);
        const names = staticPropertyName(node.arguments[1], substitutions);
        if (target && names.length === 0) {
          if (
            isStaticallyNonPublicPropertyKey(
              node.arguments[1],
              nonPublicBindings,
            )
          ) {
            resolvedRegistrations.add(node);
          } else if (!unresolvedRegistrations.has(node)) {
            unresolvedRegistrations.set(node, {
              idiom: "reflect-set",
              target,
            });
          }
        } else if (names.length > 0) {
          resolvedRegistrations.add(node);
        }
        for (const name of names) {
          addFact(target, name, "reflect-set");
          addValueShapeFact(
            target,
            name,
            expressionValueShape(node.arguments[2]),
          );
          if (node.arguments[2]?.type === "Identifier") {
            addBinding(target, name, node.arguments[2].name);
          }
        }
        const classBound = bindClassExpression(
          target,
          names,
          node.arguments[2],
          substitutions,
        );
        if (!classBound) {
          recordOpaqueCallResult(
            target,
            names,
            node.arguments[2],
            "reflect-set-call-valued-property",
          );
        }
        const prototype = prototypeOwner(node.arguments[0]);
        observePrototypeRegistration(
          node,
          prototype,
          node.arguments[1],
          names,
          "computed-prototype-reflect-set",
        );
        for (const name of names) {
          addPrototypeFact(prototype, name);
          addPrototypeValueShapeFact(
            prototype,
            name,
            expressionValueShape(node.arguments[2]),
          );
        }
      } else if (mutation === "Object.defineProperties") {
        const target = exportTargetId(node.arguments[0]);
        for (const name of objectPropertyNames(
          node.arguments[1],
          substitutions,
        )) {
          addFact(target, name, "define-properties");
        }
        if (target && node.arguments[1]?.type === "ObjectExpression") {
          for (const property of node.arguments[1].properties) {
            if (property.type === "SpreadElement") continue;
            const names =
              !property.computed && property.key?.type === "Identifier"
                ? [property.key.name]
                : staticPropertyName(property.key, substitutions);
            observeComputedRegistration(
              property,
              target,
              property.key,
              names,
              "define-properties",
            );
            for (const name of names) {
              addValueShapeFact(
                target,
                name,
                descriptorValueShape(property.value),
              );
            }
            const descriptorValue =
              property.value?.type === "ObjectExpression"
                ? (property.value.properties.find(
                    (descriptorProperty) =>
                      descriptorProperty.type === "ObjectProperty" &&
                      !descriptorProperty.computed &&
                      descriptorProperty.key?.type === "Identifier" &&
                      descriptorProperty.key.name === "value",
                  )?.value ?? null)
                : null;
            const classBound = bindClassExpression(
              target,
              names,
              descriptorValue,
              substitutions,
            );
            if (!classBound) {
              recordOpaqueCallResult(
                target,
                names,
                descriptorValue,
                "define-properties-call-valued-descriptor",
              );
            }
          }
        }
        recordPrototypeObjectMembers(
          prototypeOwner(node.arguments[0]),
          node.arguments[1],
          "computed-prototype-define-properties",
          substitutions,
        );
      } else if (mutation === "Object.assign") {
        const target = exportTargetId(node.arguments[0]);
        const prototype = prototypeOwner(node.arguments[0]);
        for (const source of node.arguments.slice(1)) {
          recordExpression(target, source, "object-assign", substitutions);
          recordPrototypeObjectMembers(
            prototype,
            source,
            "computed-prototype-object-assign",
            substitutions,
          );
        }
      }
      const legacyAccessor = directMemberName(node.callee);
      if (
        legacyAccessor === "__defineGetter__" ||
        legacyAccessor === "__defineSetter__"
      ) {
        const prototype = prototypeOwner(node.callee.object);
        const names = staticPropertyName(node.arguments[0], substitutions);
        observePrototypeRegistration(
          node,
          prototype,
          node.arguments[0],
          names,
          `computed-prototype-${legacyAccessor}`,
        );
        for (const name of names) {
          addPrototypeFact(prototype, name);
          if (legacyAccessor === "__defineGetter__") {
            addPrototypeValueShapeFact(prototype, name, "accessor");
          }
        }
      }
      if (
        node.callee?.type === "MemberExpression" &&
        !node.callee.computed &&
        node.callee.property?.type === "Identifier" &&
        node.callee.property.name === "forEach"
      ) {
        forEachCalls.push(node);
      }
      if (callbackFunction(node.callee)) immediateCalls.push(node);
      return;
    }

    if (node.type === "ExportDefaultDeclaration") {
      addFact(ROOT_EXPORT_OBJECT, "default", "esm-default-export");
      addValueShapeFact(
        ROOT_EXPORT_OBJECT,
        "default",
        expressionValueShape(node.declaration),
      );
      if (node.declaration?.type === "ClassDeclaration") {
        const owner =
          node.declaration.id?.name ?? classExpressionOwner(node.declaration);
        recordClassMembers(node.declaration, owner, substitutions);
        addBinding(ROOT_EXPORT_OBJECT, "default", owner);
      } else {
        const classBound = bindClassExpression(
          ROOT_EXPORT_OBJECT,
          ["default"],
          node.declaration,
          substitutions,
        );
        if (!classBound) {
          recordOpaqueCallResult(
            ROOT_EXPORT_OBJECT,
            ["default"],
            node.declaration,
            "esm-default-call-valued-export",
          );
        }
      }
      return;
    }
    if (node.type === "ExportAllDeclaration") {
      observeOpaqueShape(node, ROOT_EXPORT_OBJECT, null, "esm-export-all");
      return;
    }
    if (node.type === "ExportNamedDeclaration") {
      const declaration = node.declaration;
      if (
        declaration?.type === "FunctionDeclaration" ||
        declaration?.type === "ClassDeclaration"
      ) {
        if (declaration.id?.name) {
          addFact(ROOT_EXPORT_OBJECT, declaration.id.name, "esm-declaration");
          addBinding(
            ROOT_EXPORT_OBJECT,
            declaration.id.name,
            declaration.id.name,
          );
        }
      } else if (declaration?.type === "VariableDeclaration") {
        for (const item of declaration.declarations) {
          if (item.id?.type === "Identifier") {
            addFact(ROOT_EXPORT_OBJECT, item.id.name, "esm-declaration");
            addBinding(ROOT_EXPORT_OBJECT, item.id.name, item.id.name);
          }
        }
      }
      for (const specifier of node.specifiers ?? []) {
        const names = staticPropertyName(specifier.exported);
        if (specifier.exported?.type === "Identifier")
          names.push(specifier.exported.name);
        for (const name of names) {
          addFact(ROOT_EXPORT_OBJECT, name, "esm-specifier");
          if (specifier.local?.type === "Identifier") {
            addBinding(ROOT_EXPORT_OBJECT, name, specifier.local.name);
          }
        }
      }
    }
  };

  walkAst(program, (node) => recordNode(node, staticBindings));

  // Resolve the common `['A', 'B'].forEach(name => exports[name] = ...)`
  // family without executing source. This covers fs constants and similar
  // authored export tables while still rejecting comment/string lookalikes.
  for (const call of forEachCalls) {
    let values = [];
    const receiver = call.callee.object;
    if (receiver?.type === "ArrayExpression") {
      values = receiver.elements.flatMap((element) =>
        staticPropertyName(element),
      );
    } else if (receiver?.type === "Identifier") {
      values = [...(staticArrays.get(receiver.name) ?? [])];
    } else if (
      receiver?.type === "CallExpression" &&
      callName(receiver) === "keys" &&
      receiver.arguments[0]?.type === "Identifier"
    ) {
      values = [...(facts.get(receiver.arguments[0].name)?.keys() ?? [])];
    }
    const callback = callbackFunction(call.arguments[0]);
    const parameter = callback?.params[0];
    if (values.length === 0 || parameter?.type !== "Identifier") continue;
    const substitutions = mergeSubstitutions(
      staticBindings,
      new Map([[parameter.name, new Set(values)]]),
    );
    walkAst(callback.body, (node) => recordNode(node, substitutions));
  }

  for (const call of immediateCalls) {
    const callback = callbackFunction(call.callee);
    const additions = new Map();
    for (let index = 0; index < callback.params.length; index += 1) {
      const parameter = callback.params[index];
      if (parameter?.type !== "Identifier") continue;
      const values = staticRegistrationNames(
        call.arguments[index],
        staticBindings,
        staticArrays,
      );
      if (values.length > 0) additions.set(parameter.name, new Set(values));
    }
    if (additions.size === 0) continue;
    const substitutions = mergeSubstitutions(staticBindings, additions);
    walkAst(callback.body, (node) => recordNode(node, substitutions));
  }

  const returnTarget = (name) => `<function-return:${name}>`;
  const propertySources = new Map();
  const shapeSeeds = new Set();
  const shapeUnknownTargets = new Set();
  const addPropertySource = (target, source) => {
    if (!target || !source || target === source) return;
    let sources = propertySources.get(target);
    if (!sources) {
      sources = new Set();
      propertySources.set(target, sources);
    }
    sources.add(source);
  };
  const addExpressionSource = (target, expression, idiom) => {
    if (!target || !expression) return;
    if (expression.type === "Identifier") {
      addPropertySource(target, exportTargetId(expression) ?? expression.name);
      return;
    }
    if (expression.type === "ObjectExpression") {
      shapeSeeds.add(target);
      recordExpression(target, expression, idiom, staticBindings);
      for (const property of expression.properties) {
        if (property.type !== "SpreadElement") continue;
        if (property.argument?.type === "Identifier") {
          addPropertySource(target, property.argument.name);
        } else {
          shapeUnknownTargets.add(target);
        }
      }
      return;
    }
    if (isClosedModuleMember(expression)) {
      shapeSeeds.add(target);
      return;
    }
    if (
      expression.type === "CallExpression" &&
      callName(expression) === "create" &&
      (expression.arguments[1] === undefined ||
        expression.arguments[1]?.type === "ObjectExpression")
    ) {
      shapeSeeds.add(target);
      if (expression.arguments[1]) {
        addExpressionSource(
          target,
          expression.arguments[1],
          `${idiom}-object-create-descriptors`,
        );
      }
      return;
    }
    if (expression.type === "CallExpression") {
      if (expression.callee?.type === "Identifier") {
        addPropertySource(target, returnTarget(expression.callee.name));
        return;
      }
      if (
        ["freeze", "seal"].includes(callName(expression)) &&
        expression.arguments[0]?.type === "ObjectExpression"
      ) {
        addExpressionSource(target, expression.arguments[0], idiom);
      } else {
        shapeUnknownTargets.add(target);
      }
      return;
    }
    if (
      expression.type === "LogicalExpression" ||
      expression.type === "ConditionalExpression" ||
      expression.type === "SequenceExpression"
    ) {
      const children =
        expression.type === "LogicalExpression"
          ? [expression.left, expression.right]
          : expression.type === "ConditionalExpression"
            ? [expression.consequent, expression.alternate]
            : expression.expressions;
      for (const child of children) addExpressionSource(target, child, idiom);
      return;
    }
    if (
      expression.type === "FunctionExpression" ||
      expression.type === "ArrowFunctionExpression" ||
      expression.type === "ClassExpression" ||
      expression.type === "ArrayExpression" ||
      expression.type === "NullLiteral" ||
      expression.type === "BooleanLiteral" ||
      expression.type === "NumericLiteral" ||
      expression.type === "StringLiteral"
    ) {
      shapeSeeds.add(target);
      return;
    }
    shapeUnknownTargets.add(target);
  };

  // Build a closed property-domain graph for table copier functions. This is
  // what turns `_assign({...})` and `_assign(makeConstants())` into concrete
  // export facts instead of merely allowing a dynamic-looking assignment.
  walkAst(program, (node) => {
    if (
      (node.type === "FunctionDeclaration" ||
        node.type === "ClassDeclaration") &&
      node.id?.name
    ) {
      shapeSeeds.add(node.id.name);
    }
    if (node.type === "VariableDeclarator" && node.id?.type === "Identifier") {
      addExpressionSource(node.id.name, node.init, "object-source");
    }
    if (
      node.type === "AssignmentExpression" &&
      node.operator === "=" &&
      node.left?.type === "Identifier"
    ) {
      addExpressionSource(node.left.name, node.right, "object-source");
    }
    if (node.type === "FunctionDeclaration" && node.id?.name) {
      walkAst(node.body, (candidate) => {
        if (candidate.type === "ReturnStatement") {
          addExpressionSource(
            returnTarget(node.id.name),
            candidate.argument,
            "function-return",
          );
        }
      });
    }
    if (node.type === "CallExpression" && node.callee?.type === "Identifier") {
      const definition = functionDefinitions.get(node.callee.name);
      if (!definition) return;
      for (let index = 0; index < definition.params.length; index += 1) {
        const parameter = definition.params[index];
        if (parameter?.type === "Identifier") {
          addExpressionSource(
            parameter.name,
            node.arguments[index],
            "function-argument",
          );
        }
      }
    }
  });

  if (
    sourceKey === "exact_process" &&
    sourcePath === "src/builtins/process.js"
  ) {
    for (const [node, registration] of opaqueShapeRegistrations) {
      if (
        registration.target === "proc" &&
        node.type === "MemberExpression" &&
        node.object?.type === "Identifier" &&
        node.object.name === "globalThis" &&
        directMemberName(node) === "process"
      ) {
        // The ambient process object's individual native properties are
        // inventoried by the native-op scanner; this exact facade binding is
        // the closed join between that inventory and the CommonJS wrapper.
        resolvedOpaqueShapeNodes.add(node);
        shapeUnknownTargets.delete("proc");
        shapeSeeds.add("proc");
      }
    }
  }
  if (
    sourceKey === "node_console" &&
    sourcePath === "src/builtins/console.js"
  ) {
    let exactConsoleFacade = false;
    walkAst(program, (node) => {
      if (
        node.type === "AssignmentExpression" &&
        node.operator === "=" &&
        isModuleExports(node.left) &&
        node.right?.type === "Identifier" &&
        node.right.name === "console"
      ) {
        exactConsoleFacade = true;
      }
    });
    if (exactConsoleFacade) shapeSeeds.add("console");
  }
  if (
    sourceKey === "node_stream_web" &&
    sourcePath === "src/builtins/stream-web.js"
  ) {
    let cacheWrite = false;
    let closedCacheValue = false;
    walkAst(program, (node) => {
      if (
        node.type === "AssignmentExpression" &&
        node.operator === "=" &&
        node.left?.type === "MemberExpression" &&
        node.left.object?.type === "Identifier" &&
        node.left.object.name === "g" &&
        staticPropertyName(node.left.property, staticBindings).includes(
          "__exactNodeStreamWebModuleCache__",
        ) &&
        node.right?.type === "Identifier" &&
        node.right.name === "cachedModule"
      ) {
        cacheWrite = true;
      }
      if (
        node.type === "AssignmentExpression" &&
        node.operator === "=" &&
        node.left?.type === "Identifier" &&
        node.left.name === "cachedModule" &&
        node.right?.type === "ObjectExpression"
      ) {
        closedCacheValue = true;
      }
    });
    if (cacheWrite && closedCacheValue) {
      for (const [node, registration] of opaqueShapeRegistrations) {
        if (
          registration.target === "cachedModule" &&
          node.type === "MemberExpression" &&
          staticPropertyName(node.property, staticBindings).includes(
            "__exactNodeStreamWebModuleCache__",
          )
        ) {
          resolvedOpaqueShapeNodes.add(node);
          shapeUnknownTargets.delete("cachedModule");
          shapeSeeds.add("cachedModule");
        }
      }
    }
  }

  const hasNativeSignalOverlaySources = () => {
    let globalMap = false;
    let hostCall = false;
    walkAst(program, (node) => {
      if (
        node.type !== "AssignmentExpression" ||
        node.operator !== "=" ||
        node.left?.type !== "Identifier" ||
        node.left.name !== "nativeMap"
      ) {
        return;
      }
      if (
        node.right?.type === "MemberExpression" &&
        node.right.object?.type === "Identifier" &&
        node.right.object.name === "globalThis" &&
        directMemberName(node.right) === "__exactSignalNumbersMap"
      ) {
        globalMap = true;
      }
      if (
        node.right?.type === "CallExpression" &&
        node.right.callee?.type === "Identifier" &&
        node.right.callee.name === "__exactSignalNumbers"
      ) {
        hostCall = true;
      }
    });
    return globalMap && hostCall;
  };
  const hasFsPromisesOverlaySource = () => {
    let fsImport = false;
    let baseBinding = false;
    walkAst(program, (node) => {
      if (node.type !== "VariableDeclarator" || node.id?.type !== "Identifier")
        return;
      if (
        node.id.name === "fs" &&
        node.init?.type === "CallExpression" &&
        node.init.callee?.type === "Identifier" &&
        node.init.callee.name === "require" &&
        node.init.arguments[0]?.type === "StringLiteral" &&
        node.init.arguments[0].value === "node:fs"
      ) {
        fsImport = true;
      }
      if (
        node.id.name === "base" &&
        node.init?.type === "LogicalExpression" &&
        node.init.left?.type === "MemberExpression" &&
        node.init.left.object?.type === "Identifier" &&
        node.init.left.object.name === "fs" &&
        directMemberName(node.init.left) === "promises" &&
        node.init.right?.type === "ObjectExpression"
      ) {
        baseBinding = true;
      }
    });
    return fsImport && baseBinding;
  };
  const explicitlyClosedTableNodes = new Set();
  for (const [node, registration] of tableCopyRegistrations) {
    if (!registration.target) continue;
    if (
      sourceKey === "node_constants" &&
      sourcePath === "src/builtins/constants.js" &&
      registration.target === "out" &&
      registration.source === "nativeMap" &&
      hasNativeSignalOverlaySources()
    ) {
      addFact(
        registration.target,
        "[[dynamic-table:signal-number-overlay]]",
        "closed-dynamic-table:signal-number-overlay",
      );
      explicitlyClosedTableNodes.add(node);
      resolvedRegistrations.add(node);
      continue;
    }
    if (
      sourceKey === "node_fs_promises" &&
      sourcePath === "src/builtins/fs-promises.js" &&
      registration.target === "promises" &&
      registration.source === "base" &&
      hasFsPromisesOverlaySource()
    ) {
      explicitlyClosedTableNodes.add(node);
      resolvedRegistrations.add(node);
      continue;
    }
    addPropertySource(registration.target, registration.source);
  }

  // Follow local object aliases to a fixed point. This covers patterns such as
  // `const api = {...}; api.more = value; module.exports = api` regardless of
  // declaration order.
  const propagateFactSources = () => {
    let graphChanged = true;
    while (graphChanged) {
      graphChanged = false;
      for (const [target, sources] of propertySources) {
        for (const source of sources) {
          for (const [name, sourceIdioms] of facts.get(source) ?? []) {
            const before = facts.get(target)?.get(name)?.size ?? 0;
            for (const idiom of sourceIdioms) addFact(target, name, idiom);
            if ((facts.get(target)?.get(name)?.size ?? 0) !== before)
              graphChanged = true;
          }
          for (const [name, sourceShapes] of valueShapeFacts.get(source) ??
            []) {
            const before = valueShapeFacts.get(target)?.get(name)?.size ?? 0;
            for (const shape of sourceShapes)
              addValueShapeFact(target, name, shape);
            if (
              (valueShapeFacts.get(target)?.get(name)?.size ?? 0) !== before
            ) {
              graphChanged = true;
            }
          }
        }
      }
      for (const [target, sources] of aliases) {
        for (const source of sources) {
          for (const [name, sourceIdioms] of facts.get(source) ?? []) {
            const before = facts.get(target)?.get(name)?.size ?? 0;
            for (const idiom of sourceIdioms) addFact(target, name, idiom);
            if ((facts.get(target)?.get(name)?.size ?? 0) !== before)
              graphChanged = true;
          }
          for (const [name, sourceShapes] of valueShapeFacts.get(source) ??
            []) {
            const before = valueShapeFacts.get(target)?.get(name)?.size ?? 0;
            for (const shape of sourceShapes)
              addValueShapeFact(target, name, shape);
            if (
              (valueShapeFacts.get(target)?.get(name)?.size ?? 0) !== before
            ) {
              graphChanged = true;
            }
          }
          for (const [name, localNames] of bindings.get(source) ?? []) {
            const before = bindings.get(target)?.get(name)?.size ?? 0;
            for (const localName of localNames)
              addBinding(target, name, localName);
            if ((bindings.get(target)?.get(name)?.size ?? 0) !== before)
              graphChanged = true;
          }
          for (const [name, calls] of callValuedBindings.get(source) ?? []) {
            const before = callValuedBindings.get(target)?.get(name)?.size ?? 0;
            for (const call of calls) addCallValuedBinding(target, name, call);
            if (
              (callValuedBindings.get(target)?.get(name)?.size ?? 0) !== before
            ) {
              graphChanged = true;
            }
          }
        }
      }
    }
  };
  propagateFactSources();

  const shapeDependencies = new Map();
  const addShapeDependency = (target, source) => {
    if (!target || !source || target === source) return;
    let sources = shapeDependencies.get(target);
    if (!sources) {
      sources = new Set();
      shapeDependencies.set(target, sources);
    }
    sources.add(source);
  };
  for (const [target, sources] of propertySources) {
    for (const source of sources) addShapeDependency(target, source);
  }
  for (const [target, sources] of aliases) {
    for (const source of sources) addShapeDependency(target, source);
  }
  for (const [node, registration] of unresolvedRegistrations) {
    if (!resolvedRegistrations.has(node) && !tableCopyRegistrations.has(node)) {
      shapeUnknownTargets.add(registration.target);
    }
  }
  const closedShapes = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    const targets = new Set([...shapeSeeds, ...shapeDependencies.keys()]);
    for (const target of targets) {
      if (closedShapes.has(target) || shapeUnknownTargets.has(target)) continue;
      const dependencies = shapeDependencies.get(target) ?? new Set();
      if (!shapeSeeds.has(target) && dependencies.size === 0) continue;
      if ([...dependencies].some((source) => !closedShapes.has(source)))
        continue;
      closedShapes.add(target);
      changed = true;
    }
  }

  for (const [node, registration] of tableCopyRegistrations) {
    if (explicitlyClosedTableNodes.has(node)) continue;
    const names = [...(facts.get(registration.source)?.keys() ?? [])];
    if (registration.prototypeOwner && closedShapes.has(registration.source)) {
      for (const name of names) {
        addPrototypeFact(registration.prototypeOwner, name);
        for (const shape of valueShapeFacts
          .get(registration.source)
          ?.get(name) ?? []) {
          addPrototypeValueShapeFact(registration.prototypeOwner, name, shape);
        }
      }
      resolvedRegistrations.add(node);
      continue;
    }
    if (registration.target && closedShapes.has(registration.source)) {
      for (const name of names)
        addFact(registration.target, name, "table-copy");
      resolvedRegistrations.add(node);
    }
  }

  for (const [owner, sources] of prototypeSources) {
    for (const source of sources.values()) {
      if (
        source.sourceOwner &&
        (knownPrototypeOwners.has(source.sourceOwner) ||
          prototypeFacts.has(source.sourceOwner))
      ) {
        continue;
      }
      markInheritedPrototypeFact(
        owner,
        inheritedShapeSentinel(source.node, source.idiom),
      );
    }
  }
  let inheritedChanged = true;
  while (inheritedChanged) {
    inheritedChanged = false;
    for (const [owner, sources] of prototypeSources) {
      for (const source of sources.values()) {
        if (!source.sourceOwner) continue;
        const before = prototypeFacts.get(owner)?.size ?? 0;
        for (const name of prototypeFacts.get(source.sourceOwner) ?? []) {
          markInheritedPrototypeFact(owner, name);
          for (const shape of prototypeValueShapeFacts
            .get(source.sourceOwner)
            ?.get(name) ?? []) {
            addPrototypeValueShapeFact(owner, name, shape);
          }
        }
        if ((prototypeFacts.get(owner)?.size ?? 0) !== before)
          inheritedChanged = true;
      }
    }
  }
  for (const [target, owners] of objectPrototypeOwners) {
    for (const owner of owners) {
      const inherited = prototypeFacts.get(owner);
      if (!inherited || inherited.size === 0) {
        addFact(
          target,
          inheritedShapeSentinel(null, `object-prototype:${owner}`),
          "inherited-shape-sentinel",
        );
        continue;
      }
      for (const name of inherited) {
        addFact(target, name, "inherited-prototype-member");
        for (const shape of prototypeValueShapeFacts.get(owner)?.get(name) ??
          []) {
          addValueShapeFact(target, name, shape);
        }
      }
    }
  }
  propagateFactSources();

  const publicTargets = new Set([ROOT_EXPORT_OBJECT]);
  changed = true;
  while (changed) {
    changed = false;
    for (const [target, sources] of aliases) {
      for (const source of sources) {
        if (!publicTargets.has(target) && !publicTargets.has(source)) continue;
        if (!publicTargets.has(target)) {
          publicTargets.add(target);
          changed = true;
        }
        if (!publicTargets.has(source)) {
          publicTargets.add(source);
          changed = true;
        }
      }
    }
  }
  const opaqueShape = [...opaqueShapeRegistrations]
    .filter(([node, registration]) => {
      if (resolvedOpaqueShapeNodes.has(node)) return false;
      if (!publicTargets.has(registration.target)) return false;
      if (
        [...unresolvedRegistrations].some(
          ([candidate, unresolvedRegistration]) =>
            !resolvedRegistrations.has(candidate) &&
            unresolvedRegistration.target === registration.source,
        )
      ) {
        return false;
      }
      return (
        registration.source === null || !closedShapes.has(registration.source)
      );
    })
    .sort(([left], [right]) => (left.start ?? 0) - (right.start ?? 0))[0];
  if (opaqueShape) {
    const [node, registration] = opaqueShape;
    throw new Error(
      `${registrationContext(text, node, sourcePath)}: unresolved opaque builtin export shape (${registration.idiom})`,
    );
  }

  const publicPrototypeOwners = new Set([ROOT_EXPORT_OBJECT]);
  for (const localNames of bindings.get(ROOT_EXPORT_OBJECT)?.values() ?? []) {
    for (const localName of localNames) publicPrototypeOwners.add(localName);
  }
  changed = true;
  while (changed) {
    changed = false;
    for (const [target, sources] of aliases) {
      for (const source of sources) {
        if (
          !publicPrototypeOwners.has(target) &&
          !publicPrototypeOwners.has(source)
        )
          continue;
        if (!publicPrototypeOwners.has(target)) {
          publicPrototypeOwners.add(target);
          changed = true;
        }
        if (!publicPrototypeOwners.has(source)) {
          publicPrototypeOwners.add(source);
          changed = true;
        }
      }
    }
  }
  const unresolvedPrototype = [...unresolvedPrototypeRegistrations]
    .filter(
      ([node, registration]) =>
        !resolvedRegistrations.has(node) &&
        publicPrototypeOwners.has(registration.owner),
    )
    .sort(([left], [right]) => (left.start ?? 0) - (right.start ?? 0))[0];
  if (unresolvedPrototype) {
    const [node, registration] = unresolvedPrototype;
    throw new Error(
      `${registrationContext(text, node, sourcePath)}: unresolved computed exported prototype/class member (${registration.idiom})`,
    );
  }

  const unresolved = [...unresolvedRegistrations]
    .filter(
      ([node, registration]) =>
        !resolvedRegistrations.has(node) &&
        publicTargets.has(registration.target),
    )
    .sort(([left], [right]) => (left.start ?? 0) - (right.start ?? 0))[0];
  if (unresolved) {
    const [node, registration] = unresolved;
    throw new Error(
      `${registrationContext(text, node, sourcePath)}: unresolved computed builtin export registration (${registration.idiom})`,
    );
  }

  for (const [exportName, localNames] of bindings.get(ROOT_EXPORT_OBJECT) ??
    []) {
    for (const localName of localNames) {
      for (const methodName of prototypeFacts.get(localName) ?? []) {
        addFact(
          ROOT_EXPORT_OBJECT,
          `${exportName}.${methodName}`,
          inheritedPrototypeFacts.get(localName)?.has(methodName) &&
            !ownPrototypeFacts.get(localName)?.has(methodName)
            ? "exported-constructor-inherited-prototype"
            : "exported-constructor-prototype",
        );
      }
    }
  }

  // constants.js authors platform tables side by side and selects one at
  // runtime. Preserve that source-derived availability instead of treating the
  // union inventory as a promise that every named constant exists everywhere.
  // @ref LLP 0004#the-builtin-module-surface
  const platformAvailabilityByExport = new Map();
  if (
    sourceKey === "node_constants" &&
    sourcePath === "src/builtins/constants.js"
  ) {
    const darwinNames = new Set([
      ...(facts.get("_signalsDarwin")?.keys() ?? []),
      ...(facts.get("_errnoDarwin")?.keys() ?? []),
    ]);
    const linuxAndroidNames = new Set([
      ...(facts.get("_signalsLinux")?.keys() ?? []),
      ...(facts.get("_errnoLinux")?.keys() ?? []),
    ]);
    const fsFlags = callableDefinitionsByName.get("_fsFlags") ?? [];
    if (fsFlags.length === 1) {
      walkDirectFunctionBody(fsFlags[0].node, (node) => {
        if (node.type !== "IfStatement") return;
        const condition = text.slice(node.test.start ?? 0, node.test.end ?? 0);
        if (
          !condition.includes("_platform") ||
          !condition.includes("linux") ||
          !condition.includes("android")
        ) {
          return;
        }
        const collectFlagNames = (branch, destination) => {
          walkAst(branch, (candidate) => {
            if (
              candidate.type !== "AssignmentExpression" ||
              candidate.operator !== "=" ||
              candidate.left?.type !== "MemberExpression" ||
              candidate.left.object?.type !== "Identifier" ||
              candidate.left.object.name !== "out"
            ) {
              return;
            }
            const name = directMemberName(candidate.left);
            if (name) destination.add(name);
          });
        };
        collectFlagNames(node.consequent, linuxAndroidNames);
        collectFlagNames(node.alternate, darwinNames);
      });
    }
    for (const exportName of facts.get(ROOT_EXPORT_OBJECT)?.keys() ?? []) {
      const onDarwin = darwinNames.has(exportName);
      const onLinuxAndroid = linuxAndroidNames.has(exportName);
      if (onDarwin && !onLinuxAndroid) {
        platformAvailabilityByExport.set(exportName, ["darwin"]);
      } else if (onLinuxAndroid && !onDarwin) {
        platformAvailabilityByExport.set(exportName, ["android", "linux"]);
      }
    }
  }

  const specifiers = uniqueSorted(moduleSpecifiers);
  const publicSpecifiers = uniqueSorted(publicModuleSpecifiers);
  const bootstrapInternalSpecifiers = uniqueSorted(
    bootstrapInternalModuleSpecifiers,
  );
  const specifierSet = new Set(specifiers);
  const bootstrapInternalSpecifierSet = new Set(bootstrapInternalSpecifiers);
  if (
    [...publicSpecifiers, ...bootstrapInternalSpecifiers].some(
      (specifier) => !specifierSet.has(specifier),
    )
  ) {
    throw new Error(
      `${sourcePath}: builtin import reachability names an unknown module specifier`,
    );
  }
  if (
    publicSpecifiers.some((specifier) =>
      bootstrapInternalSpecifierSet.has(specifier),
    )
  ) {
    throw new Error(
      `${sourcePath}: a builtin module specifier cannot be both public and bootstrap-internal`,
    );
  }
  const importReachability = publicSpecifiers.length
    ? "public"
    : bootstrapInternalSpecifiers.length
      ? "bootstrap-internal"
      : "private-manifest";
  const prototypeExportIdioms = new Set([
    "exported-constructor-inherited-prototype",
    "exported-constructor-prototype",
  ]);
  // Freeze the pre-callback routes in the same export order as the original
  // inventory pass. Deferred edges may introduce new cycles, but they cannot
  // erase a terminal that the direct walk already proved.
  for (const [exportName] of facts.get(ROOT_EXPORT_OBJECT) ?? []) {
    directEnforcementRoutes.set(exportName, routeForExport(exportName, false));
  }
  const rows = [];
  for (const [exportName, idioms] of facts.get(ROOT_EXPORT_OBJECT) ?? []) {
    const exportIdioms = uniqueSorted(idioms);
    const enforcementRoute = mergeEnforcementRoutes([
      directEnforcementRoutes.get(exportName),
      routeForExport(exportName),
    ]);
    const valueShapes = new Set(
      valueShapeFacts.get(ROOT_EXPORT_OBJECT)?.get(exportName) ?? [],
    );
    for (const localName of bindings.get(ROOT_EXPORT_OBJECT)?.get(exportName) ??
      []) {
      valueShapes.add(
        expressionValueShape({ type: "Identifier", name: localName }),
      );
    }
    if (exportIdioms.some((idiom) => prototypeExportIdioms.has(idiom))) {
      const [ownerExportName, ...memberSegments] = exportName.split(".");
      const memberName = memberSegments.join(".");
      for (const localName of bindings
        .get(ROOT_EXPORT_OBJECT)
        ?.get(ownerExportName) ?? []) {
        for (const shape of prototypeValueShapeFacts
          .get(localName)
          ?.get(memberName) ?? []) {
          valueShapes.add(shape);
        }
      }
    }
    const inheritedShape =
      exportName.includes("[[dynamic-table:inherited-") ||
      exportIdioms.some((idiom) =>
        /(?:inherited|object-create-prototype|setPrototypeOf|__proto__)/u.test(
          idiom,
        ),
      );
    const metadata = {
      exportIdioms,
      exportName,
      enforcementRouteEvidence: {
        ambiguousCallees: enforcementRoute.ambiguous,
        kind: "static-builtin-call-graph",
        paths: enforcementRoute.paths,
        ...(enforcementRoute.dependencies.length > 0
          ? { requiredExportCalls: enforcementRoute.dependencies }
          : {}),
        terminals: enforcementRoute.terminals,
      },
      bootstrapInternalModuleSpecifiers: bootstrapInternalSpecifiers,
      importReachability,
      moduleSpecifiers: specifiers,
      publicModuleSpecifiers: publicSpecifiers,
      sourceKey,
      sourceKind,
      surfaceType: "export",
      valueShape: resolvedValueShape(valueShapes),
    };
    const platformAvailability = platformAvailabilityByExport.get(exportName);
    if (platformAvailability) {
      metadata.platformAvailability = platformAvailability;
    }
    if (inheritedShape) {
      metadata.inheritedShape = true;
      metadata.semanticRoles = ["inherited-export-shape"];
    }
    rows.push(
      makeSurface(
        "builtin",
        `export:${sourceKey}:${exportName}`,
        [
          sourceSymbol(
            sourcePath,
            sourceKind === "inline"
              ? `sources:${sourceKey}:exports:${exportName}`
              : `exports:${exportName}`,
          ),
        ],
        { metadata },
      ),
    );
  }
  return sortSurfaces(rows);
}

function directMemberName(node) {
  if (node?.type !== "MemberExpression") return null;
  if (!node.computed && node.property?.type === "Identifier")
    return node.property.name;
  if (node.computed && node.property?.type === "StringLiteral")
    return node.property.value;
  return null;
}

function prototypeOwner(node) {
  if (
    node?.type === "MemberExpression" &&
    directMemberName(node) === "prototype" &&
    node.object?.type === "Identifier"
  ) {
    return node.object.name;
  }
  return null;
}

function tokenSequenceIndex(values, sequence, start = 0) {
  for (
    let index = start;
    index <= values.length - sequence.length;
    index += 1
  ) {
    if (sequence.every((value, offset) => values[index + offset] === value)) {
      return index;
    }
  }
  return -1;
}

function tokenSequenceCount(values, sequence) {
  let count = 0;
  let cursor = 0;
  while (cursor <= values.length - sequence.length) {
    const index = tokenSequenceIndex(values, sequence, cursor);
    if (index === -1) break;
    count += 1;
    cursor = index + sequence.length;
  }
  return count;
}

/**
 * Prove which exact-engine target overlays also execute the legacy evaluator
 * wrappers. The two runners are compiled out on Windows, but remain reachable
 * on Android; without an explicit Android layer, its engine-specific branch
 * would suppress the generic fallback provenance.
 */
export function scanLegacyEvaluatorBootstrapInstallations(
  text,
  sourcePath = "src/engine/hermes_bootstrap.cc",
) {
  const specifications = [
    {
      functionName: "runLegacyCompatPolyfills",
      reviewedBodyDigest:
        "sha256-85e5f64997c896a0b0fed5d1fdbb4903a17334b0e9a0bbe32c412ee13316e1ea",
      scriptName: "compat-polyfills.js",
      sourceConstant: "COMPAT_POLYFILLS_SRC",
    },
    {
      functionName: "runLegacyProcessCompatFix",
      reviewedBodyDigest:
        "sha256-12bb5a3515187a9fd26f1f68d053496d1c15353fd95c4c603f7674d6d7f27045",
      scriptName: "process-compat-fix.js",
      sourceConstant: "PROCESS_COMPAT_FIX_SRC",
    },
  ];
  const tokens = lexCpp(text, sourcePath);
  const definitions = cppFunctionDefinitions(tokens);
  return Object.fromEntries(
    specifications.map((specification) => {
      const matches = definitions.filter(
        (definition) => definition.name === specification.functionName,
      );
      if (matches.length !== 1) {
        throw new Error(
          `${sourcePath}: expected one ${specification.functionName} definition`,
        );
      }
      const definition = matches[0];
      const values = tokens
        .slice(definition.bodyOpen + 1, definition.bodyClose)
        .map((token) => token.value);
      const bodyDigest = `sha256-${sha256Hex(JSON.stringify(values))}`;
      const guardStart = tokenSequenceIndex(values, [
        "#",
        "if",
        "defined",
        "(",
        "_WIN32",
        ")",
      ]);
      const guardEnd = tokenSequenceIndex(
        values,
        ["#", "endif"],
        guardStart + 6,
      );
      if (
        guardStart === -1 ||
        guardEnd === -1 ||
        new Set(["&", "|"]).has(values[guardStart + 6]) ||
        tokenSequenceIndex(values.slice(guardStart + 6, guardEnd), [
          "return",
          ";",
        ]) === -1 ||
        tokenSequenceIndex(values, [
          "eval_bootstrap_script",
          "(",
          "handle",
          ",",
          specification.sourceConstant,
        ]) === -1
      ) {
        throw new Error(
          `${sourcePath}#${specification.functionName}: legacy evaluator route or Windows exclusion drift`,
        );
      }
      if (bodyDigest !== specification.reviewedBodyDigest) {
        throw new Error(
          `${sourcePath}#${specification.functionName}: reviewed legacy evaluator runner drift (${bodyDigest})`,
        );
      }
      return [
        specification.scriptName,
        {
          sourceRefs: [
            sourceSymbol(sourcePath, specification.functionName),
            sourceSymbol(
              sourcePath,
              `legacy-runner:${specification.functionName}:${bodyDigest}`,
            ),
          ],
          targetVariants: ["android", "default"],
        },
      ];
    }),
  );
}

/**
 * Discover statically installed globals and their statically named
 * object/prototype APIs. This is intentionally source-based: it never executes
 * bootstrap code. Private `__exact*` rows use the same observed keys as native
 * registration evidence so alternate implementations merge structurally.
 */
const PUBLIC_READ_ACCESS_SOURCE_CONTRACT_SCHEMA =
  "ibex/public-read-access-source-contract/1";

const FACTORY_RETURNED_CALLABLE_SOURCE_CONTRACT_SCHEMA =
  "ibex/factory-returned-callable-source-contract/1";
const REVIEWED_FACTORY_RETURNED_CALLABLE_SOURCE_PATH =
  "src/engine/bootstrap/ipc-listener.js";

const REVIEWED_FACTORY_RETURNED_CALLABLES = new Map([
  [
    `${REVIEWED_FACTORY_RETURNED_CALLABLE_SOURCE_PATH}\0process.once`,
    {
      argumentPath: "process.once",
      factoryName: "wrapSingleUseListener",
    },
  ],
  [
    `${REVIEWED_FACTORY_RETURNED_CALLABLE_SOURCE_PATH}\0process.prependOnceListener`,
    {
      argumentPath: "process.prependOnceListener",
      factoryName: "wrapSingleUseListener",
    },
  ],
]);

export function scanStaticGlobalApiSurfaces(
  text,
  sourcePath = "<bootstrap-source>",
  options = {},
) {
  const fullProgram = parseJavaScript(text, sourcePath);
  const webStreamsWrapperMatch =
    /(?:^|\r?\n)(?=\(function \(\) \{\r?\n  var globalObject = )/u.exec(text);
  const webStreamsWrapperOffset = webStreamsWrapperMatch
    ? webStreamsWrapperMatch.index + webStreamsWrapperMatch[0].length
    : -1;
  const sourceText =
    webStreamsWrapperOffset === -1
      ? text
      : text.slice(webStreamsWrapperOffset);
  const program =
    webStreamsWrapperOffset === -1
      ? fullProgram
      : parseJavaScript(sourceText, sourcePath);
  const {
    arrays: staticArrays,
    bindings: staticBindings,
    nonPublicBindings,
  } = collectStaticPropertyTables(program);
  const globalAliases = new Set(["globalThis"]);
  const objectPaths = new Map([
    ["globalThis", new Set([""])],
    // JavaScript permits inherited globals to be referenced without an
    // explicit globalThis qualifier. `process` is installed by the native
    // bootstrap before evaluated marker/compat scripts run.
    ["process", new Set(["process"])],
  ]);
  const prototypeMembers = new Map();
  const objectMembers = new Map();
  const prototypeMemberShapes = new Map();
  const objectMemberShapes = new Map();
  const prototypeSources = new Map();
  const knownPrototypeOwners = new Set();
  const classExpressionOwners = new WeakMap();
  const normalizedSourcePath = sourcePath.replaceAll("\\", "/");
  const reviewedFactorySource =
    normalizedSourcePath === REVIEWED_FACTORY_RETURNED_CALLABLE_SOURCE_PATH ||
    normalizedSourcePath.endsWith(
      `/${REVIEWED_FACTORY_RETURNED_CALLABLE_SOURCE_PATH}`,
    );
  const lexicalBindings = reviewedFactorySource
    ? javascriptLexicalBindingIndex(program)
    : null;
  const installations = [];
  const functionNames = new Set();
  const functionDefinitions = new Map();
  const functionCalls = new Map();
  const forEachCalls = [];
  const unresolvedRegistrations = new Map();
  const resolvedRegistrations = new Set();
  const unresolvedPrototypeRegistrations = new Map();
  const callableDefinitionsByName = new Map();
  for (const definition of javascriptFunctionDefinitions(program)) {
    let definitions = callableDefinitionsByName.get(definition.name);
    if (!definitions) {
      definitions = [];
      callableDefinitionsByName.set(definition.name, definitions);
    }
    definitions.push(definition);
  }

  const classDefinitionNames = new Set();
  const localValueExpressions = new Map();
  const addLocalValueExpression = (name, expression) => {
    if (!name || !expression) return;
    let expressions = localValueExpressions.get(name);
    if (!expressions) {
      expressions = [];
      localValueExpressions.set(name, expressions);
    }
    expressions.push(expression);
  };
  walkAst(program, (node) => {
    if (node.type === "ClassDeclaration" && node.id?.name) {
      classDefinitionNames.add(node.id.name);
    }
    if (
      node.type === "VariableDeclarator" &&
      node.id?.type === "Identifier" &&
      node.init
    ) {
      addLocalValueExpression(node.id.name, node.init);
    }
    if (
      node.type === "AssignmentExpression" &&
      node.operator === "=" &&
      node.left?.type === "Identifier"
    ) {
      addLocalValueExpression(node.left.name, node.right);
    }
  });

  const resolvedValueShape = (shapes) => {
    const resolved = new Set([...shapes].filter(Boolean));
    return resolved.size === 1 ? [...resolved][0] : null;
  };
  const expressionValueShape = (expression, activeNames = new Set()) => {
    if (!expression) return null;
    if (
      new Set([
        "ArrowFunctionExpression",
        "ClassDeclaration",
        "ClassExpression",
        "FunctionDeclaration",
        "FunctionExpression",
      ]).has(expression.type)
    ) {
      return "callable";
    }
    if (
      new Set([
        "ArrayExpression",
        "BigIntLiteral",
        "BinaryExpression",
        "BooleanLiteral",
        "NewExpression",
        "NullLiteral",
        "NumericLiteral",
        "ObjectExpression",
        "RegExpLiteral",
        "StringLiteral",
        "TemplateLiteral",
        "UnaryExpression",
      ]).has(expression.type)
    ) {
      return "data";
    }
    if (expression.type === "Identifier") {
      if (
        classDefinitionNames.has(expression.name) ||
        (callableDefinitionsByName.get(expression.name) ?? []).length === 1
      ) {
        return "callable";
      }
      if (activeNames.has(expression.name)) return null;
      const expressions = localValueExpressions.get(expression.name) ?? [];
      if (expressions.length === 0) return null;
      const nextActive = new Set(activeNames);
      nextActive.add(expression.name);
      return resolvedValueShape(
        expressions.map((candidate) =>
          expressionValueShape(candidate, nextActive),
        ),
      );
    }
    if (
      expression.type === "LogicalExpression" ||
      expression.type === "ConditionalExpression"
    ) {
      const children =
        expression.type === "LogicalExpression"
          ? [expression.left, expression.right]
          : [expression.consequent, expression.alternate];
      const shapes = children.map((candidate) =>
        expressionValueShape(candidate, activeNames),
      );
      return shapes.every(Boolean) ? resolvedValueShape(shapes) : null;
    }
    if (expression.type === "SequenceExpression") {
      return expressionValueShape(expression.expressions.at(-1), activeNames);
    }
    if (
      expression.type === "CallExpression" &&
      new Set(["freeze", "seal"]).has(callName(expression)) &&
      expression.arguments.length === 1
    ) {
      return expressionValueShape(expression.arguments[0], activeNames);
    }
    return null;
  };
  const propertyValueShape = (property) => {
    if (property?.type === "ObjectMethod") {
      return property.kind === "get" || property.kind === "set"
        ? "accessor"
        : "callable";
    }
    if (property?.type === "ObjectProperty") {
      return expressionValueShape(property.value);
    }
    if (property?.type === "ClassMethod") {
      return property.kind === "get" || property.kind === "set"
        ? "accessor"
        : "callable";
    }
    if (property?.type === "ClassProperty") {
      return expressionValueShape(property.value);
    }
    return null;
  };
  const descriptorValueShape = (descriptor) => {
    if (descriptor?.type !== "ObjectExpression") return null;
    const values = [];
    let accessor = false;
    for (const property of descriptor.properties) {
      if (property.type === "SpreadElement" || property.computed) continue;
      const names =
        property.key?.type === "Identifier"
          ? [property.key.name]
          : staticPropertyName(property.key, staticBindings);
      if (names.includes("get") || names.includes("set")) accessor = true;
      if (
        names.includes("value") &&
        property.type === "ObjectProperty" &&
        property.value
      ) {
        values.push(expressionValueShape(property.value));
      }
    }
    if (accessor && values.length > 0) return null;
    if (accessor) return "accessor";
    return values.length > 0 ? resolvedValueShape(values) : null;
  };

  if (webStreamsWrapperOffset !== -1) {
    let hasReachableContainer = false;
    walkAst(fullProgram, (node) => {
      if (
        node.type === "AssignmentExpression" &&
        node.operator === "=" &&
        node.right?.type === "ObjectExpression" &&
        node.left?.type === "MemberExpression" &&
        ((!node.left.computed &&
          node.left.property?.type === "Identifier" &&
          node.left.property.name === "WebStreamsPolyfill") ||
          (node.left.computed &&
            node.left.property?.type === "StringLiteral" &&
            node.left.property.value === "WebStreamsPolyfill"))
      ) {
        hasReachableContainer = true;
      }
    });
    if (hasReachableContainer)
      installations.push({ pathSegments: ["WebStreamsPolyfill"], value: null });
  }

  const addMember = (map, owner, name, valueShape = null) => {
    if (!owner || !name || typeof name !== "string") return;
    let names = map.get(owner);
    if (!names) {
      names = new Set();
      map.set(owner, names);
    }
    names.add(name);
    if (valueShape) {
      const shapeMap =
        map === prototypeMembers ? prototypeMemberShapes : objectMemberShapes;
      let ownerShapes = shapeMap.get(owner);
      if (!ownerShapes) {
        ownerShapes = new Map();
        shapeMap.set(owner, ownerShapes);
      }
      let shapes = ownerShapes.get(name);
      if (!shapes) {
        shapes = new Set();
        ownerShapes.set(name, shapes);
      }
      shapes.add(valueShape);
    }
  };
  const memberValueShape = (map, owner, name) => {
    const shapeMap =
      map === prototypeMembers ? prototypeMemberShapes : objectMemberShapes;
    return resolvedValueShape(shapeMap.get(owner)?.get(name) ?? []);
  };
  const addExpressionMembers = (owner, expression) => {
    if (!owner || expression?.type !== "ObjectExpression") return;
    for (const property of expression.properties) {
      if (property.type === "SpreadElement") continue;
      const names =
        !property.computed && property.key?.type === "Identifier"
          ? [property.key.name]
          : staticPropertyName(property.key, staticBindings);
      for (const name of names) {
        addMember(objectMembers, owner, name, propertyValueShape(property));
      }
    }
  };
  const observePrototypeRegistration = (
    node,
    owner,
    property,
    names,
    idiom,
  ) => {
    if (!owner) return;
    if (
      names.length > 0 ||
      isStaticallyNonPublicPropertyKey(property, nonPublicBindings)
    ) {
      resolvedRegistrations.add(node);
      return;
    }
    if (!unresolvedPrototypeRegistrations.has(node)) {
      unresolvedPrototypeRegistrations.set(node, { idiom, owner });
    }
  };
  const inheritedShapeSentinel = (node, idiom) => {
    const source = node
      ? sourceText.slice(node.start ?? 0, node.end ?? node.start ?? 0)
      : idiom;
    const digest = sha256Hex(`${idiom}\0${source}`).slice(0, 12);
    return `[[dynamic-table:inherited-${digest}-properties]]`;
  };
  const addPrototypeSource = (owner, sourceOwner, node, idiom) => {
    if (!owner) return;
    let sources = prototypeSources.get(owner);
    if (!sources) {
      sources = new Map();
      prototypeSources.set(owner, sources);
    }
    const key = sourceOwner ?? inheritedShapeSentinel(node, idiom);
    sources.set(key, { idiom, node, sourceOwner });
  };
  const classExpressionOwner = (classNode) => {
    let owner = classExpressionOwners.get(classNode);
    if (!owner) {
      const source = sourceText.slice(
        classNode.start ?? 0,
        classNode.end ?? classNode.start ?? 0,
      );
      owner = `[[class-expression:${sha256Hex(source).slice(0, 12)}]]`;
      classExpressionOwners.set(classNode, owner);
    }
    return owner;
  };
  const classOwnersForExpression = (
    expression,
    substitutions = staticBindings,
  ) => {
    const owners = new Set();
    const visitingCallableDefinitions = new Set();
    const visit = (candidate) => {
      if (!candidate) return;
      if (candidate.type === "ClassExpression") {
        const owner = classExpressionOwner(candidate);
        recordClassMembers(candidate, owner, substitutions);
        owners.add(owner);
        return;
      }
      if (
        candidate.type === "Identifier" &&
        (knownPrototypeOwners.has(candidate.name) ||
          prototypeMembers.has(candidate.name))
      ) {
        owners.add(candidate.name);
        return;
      }
      if (
        candidate.type === "LogicalExpression" ||
        candidate.type === "ConditionalExpression" ||
        candidate.type === "SequenceExpression"
      ) {
        const children =
          candidate.type === "LogicalExpression"
            ? [candidate.left, candidate.right]
            : candidate.type === "ConditionalExpression"
              ? [candidate.consequent, candidate.alternate]
              : [candidate.expressions.at(-1)];
        for (const child of children) visit(child);
        return;
      }
      if (
        candidate.type === "CallExpression" &&
        candidate.callee?.type === "Identifier"
      ) {
        const definitions =
          callableDefinitionsByName.get(candidate.callee.name) ?? [];
        if (definitions.length !== 1) {
          const containsDirectClass = (value) => {
            if (!value) return false;
            if (value.type === "ClassExpression") return true;
            if (value.type === "LogicalExpression")
              return (
                containsDirectClass(value.left) ||
                containsDirectClass(value.right)
              );
            if (value.type === "ConditionalExpression")
              return (
                containsDirectClass(value.consequent) ||
                containsDirectClass(value.alternate)
              );
            if (value.type === "SequenceExpression")
              return containsDirectClass(value.expressions.at(-1));
            return false;
          };
          if (candidate.arguments.some(containsDirectClass)) {
            throw new Error(
              `${sourcePath}: unresolved public class decorator/factory call ${candidate.callee.name}`,
            );
          }
          return;
        }
        const definition = definitions[0].node;
        if (visitingCallableDefinitions.has(definition)) return;
        visitingCallableDefinitions.add(definition);
        try {
          const localValues = new Map();
          walkDirectFunctionBody(definition, (node) => {
            if (
              node.type === "VariableDeclarator" &&
              node.id?.type === "Identifier" &&
              node.init
            ) {
              localValues.set(node.id.name, node.init);
            }
          });
          const visitReturnedValue = (value, seen = new Set()) => {
            if (value?.type === "Identifier" && localValues.has(value.name)) {
              if (seen.has(value.name)) return;
              const nextSeen = new Set(seen);
              nextSeen.add(value.name);
              visitReturnedValue(localValues.get(value.name), nextSeen);
              return;
            }
            visit(value);
          };
          if (
            definition.type === "ArrowFunctionExpression" &&
            definition.body?.type !== "BlockStatement"
          ) {
            visitReturnedValue(definition.body);
          } else {
            walkDirectFunctionBody(definition, (node) => {
              if (node.type === "ReturnStatement")
                visitReturnedValue(node.argument);
            });
          }
        } finally {
          visitingCallableDefinitions.delete(definition);
        }
      }
    };
    visit(expression);
    return owners;
  };
  const opaqueCallValue = (expression) => {
    if (!expression) return null;
    if (expression.type === "CallExpression") return expression;
    if (expression.type === "LogicalExpression")
      return (
        opaqueCallValue(expression.left) ?? opaqueCallValue(expression.right)
      );
    if (expression.type === "ConditionalExpression")
      return (
        opaqueCallValue(expression.consequent) ??
        opaqueCallValue(expression.alternate)
      );
    if (expression.type === "SequenceExpression")
      return opaqueCallValue(expression.expressions.at(-1));
    return null;
  };
  const structuralShapeEvidence = (node) => {
    const omitted = new Set([
      "comments",
      "end",
      "errors",
      "extra",
      "leadingComments",
      "loc",
      "start",
      "trailingComments",
    ]);
    const structural = JSON.stringify(node, (key, value) =>
      omitted.has(key) ? undefined : value,
    );
    return `sha256-${sha256Hex(structural)}`;
  };
  const callShapeEvidence = structuralShapeEvidence;
  const reviewedFactoryReturnedCallableSourceContract = (
    value,
    pathSegments,
  ) => {
    const installedPath = pathSegments.join(".");
    if (!lexicalBindings) return null;
    const specification = REVIEWED_FACTORY_RETURNED_CALLABLES.get(
      `${REVIEWED_FACTORY_RETURNED_CALLABLE_SOURCE_PATH}\0${installedPath}`,
    );
    if (
      !specification ||
      value?.type !== "CallExpression" ||
      value.callee?.type !== "Identifier" ||
      value.callee.name !== specification.factoryName ||
      value.arguments.length !== 1
    ) {
      return null;
    }
    const argument = value.arguments[0];
    const argumentPath = specification.argumentPath.split(".");
    if (
      argument?.type !== "MemberExpression" ||
      argument.computed ||
      argument.object?.type !== "Identifier" ||
      argument.object.name !== argumentPath[0] ||
      argument.property?.type !== "Identifier" ||
      argument.property.name !== argumentPath[1]
    ) {
      return null;
    }
    const binding = lexicalBindings.resolve(value.callee);
    const definition = binding?.node;
    if (
      binding?.kind !== "function-declaration" ||
      binding.writes !== 0 ||
      definition?.type !== "FunctionDeclaration" ||
      definition.id?.name !== specification.factoryName ||
      definition.async ||
      definition.generator ||
      definition.params.length !== 1 ||
      definition.params[0]?.type !== "Identifier" ||
      definition.body?.type !== "BlockStatement" ||
      definition.body.body.length !== 1
    ) {
      return null;
    }
    const returnedFunction = definition.body.body[0];
    if (
      returnedFunction?.type !== "ReturnStatement" ||
      returnedFunction.argument?.type !== "FunctionExpression" ||
      returnedFunction.argument.id !== null ||
      returnedFunction.argument.async ||
      returnedFunction.argument.generator
    ) {
      return null;
    }

    // @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory —
    // admit a callable only when the exact call resolves to the reviewed
    // lexical factory declaration. Aliases and branch-dependent factories
    // deliberately retain the opaque call-result sentinel.
    const callsiteEvidence = callShapeEvidence(value);
    const factoryDefinitionEvidence = structuralShapeEvidence(definition);
    const evidence = `sha256-${sha256Hex(
      JSON.stringify({
        callsiteEvidence,
        factoryDefinitionEvidence,
        factoryName: specification.factoryName,
        installedPath,
        schema: FACTORY_RETURNED_CALLABLE_SOURCE_CONTRACT_SCHEMA,
        sourcePath: REVIEWED_FACTORY_RETURNED_CALLABLE_SOURCE_PATH,
      }),
    )}`;
    return {
      callsiteEvidence,
      evidence,
      factoryBindingKind: binding.kind,
      factoryDefinitionEvidence,
      factoryName: specification.factoryName,
      installedPath,
      proofKind: "lexically-bound-factory-returned-function",
      returnedValueShape: "callable",
      schema: FACTORY_RETURNED_CALLABLE_SOURCE_CONTRACT_SCHEMA,
      sourcePath: REVIEWED_FACTORY_RETURNED_CALLABLE_SOURCE_PATH,
    };
  };
  const reviewedIifeCallEvidence = (call) => {
    if (
      call?.type !== "CallExpression" ||
      call.arguments.length !== 0 ||
      !new Set(["ArrowFunctionExpression", "FunctionExpression"]).has(
        call.callee?.type,
      )
    ) {
      return null;
    }
    const returns = [];
    if (
      call.callee.type === "ArrowFunctionExpression" &&
      call.callee.body?.type !== "BlockStatement"
    ) {
      returns.push(call.callee.body);
    } else {
      walkDirectFunctionBody(call.callee, (node) => {
        if (node.type === "ReturnStatement") returns.push(node.argument);
      });
    }
    if (returns.length === 0 || returns.some((value) => !value)) return null;
    return callShapeEvidence(call);
  };
  const reviewedIifeReturnedFunctionShape = (call) => {
    const evidence = reviewedIifeCallEvidence(call);
    if (
      !evidence ||
      call.callee.type !== "FunctionExpression" ||
      call.callee.body?.type !== "BlockStatement"
    ) {
      return null;
    }
    const returns = call.callee.body.body.filter(
      (statement) => statement.type === "ReturnStatement",
    );
    if (returns.length !== 1 || returns[0].argument?.type !== "Identifier") {
      return null;
    }
    const owner = returns[0].argument.name;
    const declarations = call.callee.body.body.filter(
      (statement) =>
        statement.type === "FunctionDeclaration" &&
        statement.id?.name === owner,
    );
    if (declarations.length !== 1) return null;

    const members = new Map();
    const addClosedMember = (memberPath, valueShape) => {
      if (!memberPath || !valueShape) return false;
      const previous = members.get(memberPath);
      if (previous !== undefined && previous !== valueShape) return false;
      members.set(memberPath, valueShape);
      return true;
    };
    for (const statement of call.callee.body.body) {
      if (statement === declarations[0] || statement === returns[0]) {
        continue;
      }
      // Exact membership is admitted only for the narrow constructor idiom
      // used by the checked-in CryptoHasher shim: one declaration, direct
      // static/prototype assignments, then the return. Conditions, aliases,
      // helper calls, and reflective mutations retain the dynamic sentinel.
      const assignment =
        statement.type === "ExpressionStatement" &&
        statement.expression?.type === "AssignmentExpression" &&
        statement.expression.operator === "="
          ? statement.expression
          : null;
      const left = assignment?.left;
      if (left?.type !== "MemberExpression") return null;
      const directName = directMemberName(left);
      if (directName === null || directName === "prototype") return null;
      if (left.object?.type === "Identifier" && left.object.name === owner) {
        if (
          !addClosedMember(directName, expressionValueShape(assignment.right))
        )
          return null;
        continue;
      }
      if (prototypeOwner(left.object) === owner) {
        if (
          !addClosedMember(
            `prototype.${directName}`,
            expressionValueShape(assignment.right),
          )
        ) {
          return null;
        }
        continue;
      }
      return null;
    }
    if (members.size === 0) return null;
    if ([...members.keys()].some((member) => member.startsWith("prototype."))) {
      members.set("prototype", "data");
    }
    return {
      evidence,
      members: [...members.entries()]
        .map(([memberPath, valueShape]) => ({ memberPath, valueShape }))
        .sort((left, right) => compareText(left.memberPath, right.memberPath)),
      owner,
    };
  };
  const reviewedClosedGlobalCallValue = (call) =>
    Boolean(
      call?.type === "CallExpression" &&
      call.callee?.type === "Identifier" &&
      new Set(["setImmediate", "setInterval", "setTimeout"]).has(
        call.callee.name,
      ),
    );
  const recordClassMembers = (classNode, owner, substitutions) => {
    if (!classNode || !owner) return;
    knownPrototypeOwners.add(owner);
    for (const method of classNode.body?.body ?? []) {
      const names =
        !method.computed && method.key?.type === "Identifier"
          ? [method.key.name]
          : staticPropertyName(method.key, substitutions);
      observePrototypeRegistration(
        method,
        owner,
        method.key,
        names,
        method.static
          ? "computed-static-class-member"
          : "computed-class-member",
      );
      for (const name of names) {
        addMember(prototypeMembers, owner, name, propertyValueShape(method));
      }
    }
    if (classNode.superClass) {
      const sourceOwner =
        classNode.superClass.type === "Identifier"
          ? classNode.superClass.name
          : prototypeOwner(classNode.superClass);
      addPrototypeSource(
        owner,
        sourceOwner,
        classNode.superClass,
        "class-extends",
      );
    }
  };
  const recordPrototypeObjectMembers = (
    owner,
    expression,
    idiom,
    substitutions,
  ) => {
    if (!owner) return;
    if (expression?.type !== "ObjectExpression") {
      if (expression && !unresolvedPrototypeRegistrations.has(expression)) {
        unresolvedPrototypeRegistrations.set(expression, { idiom, owner });
      }
      return;
    }
    for (const property of expression.properties) {
      if (property.type === "SpreadElement") {
        if (!unresolvedPrototypeRegistrations.has(property)) {
          unresolvedPrototypeRegistrations.set(property, { idiom, owner });
        }
        continue;
      }
      const names =
        !property.computed && property.key?.type === "Identifier"
          ? [property.key.name]
          : staticPropertyName(property.key, substitutions);
      observePrototypeRegistration(property, owner, property.key, names, idiom);
      for (const name of names) {
        addMember(prototypeMembers, owner, name, propertyValueShape(property));
      }
    }
  };
  const collectReturnedConstructors = (expression, constructors) => {
    if (!expression) return;
    if (
      expression.type === "NewExpression" &&
      expression.callee?.type === "Identifier"
    ) {
      constructors.add(expression.callee.name);
      return;
    }
    if (
      expression.type === "LogicalExpression" ||
      expression.type === "ConditionalExpression" ||
      expression.type === "SequenceExpression"
    ) {
      const children =
        expression.type === "LogicalExpression"
          ? [expression.left, expression.right]
          : expression.type === "ConditionalExpression"
            ? [expression.consequent, expression.alternate]
            : expression.expressions;
      for (const child of children)
        collectReturnedConstructors(child, constructors);
    }
  };
  const returnedConstructors = (value) => {
    let functionNodes = [];
    if (isJavaScriptFunctionNode(value)) {
      functionNodes = [value];
    } else if (value?.type === "Identifier") {
      const definitions = callableDefinitionsByName.get(value.name) ?? [];
      if (definitions.length === 1) functionNodes = [definitions[0].node];
    }
    const constructors = new Set();
    for (const functionNode of functionNodes) {
      if (
        functionNode.type === "ArrowFunctionExpression" &&
        functionNode.body?.type !== "BlockStatement"
      ) {
        collectReturnedConstructors(functionNode.body, constructors);
      } else {
        walkDirectFunctionBody(functionNode, (node) => {
          if (node.type === "ReturnStatement") {
            collectReturnedConstructors(node.argument, constructors);
          }
        });
      }
    }
    return constructors;
  };
  const expressionObjectPaths = (expression) => {
    if (!expression) return [];
    if (expression.type === "Identifier")
      return [...(objectPaths.get(expression.name) ?? [])];
    if (expression.type === "MemberExpression") {
      const bases = expressionObjectPaths(expression.object);
      const names =
        !expression.computed && expression.property?.type === "Identifier"
          ? [expression.property.name]
          : staticRegistrationNames(
              expression.property,
              staticBindings,
              staticArrays,
            );
      return bases.flatMap((base) =>
        names.map((name) => [base, name].filter(Boolean).join(".")),
      );
    }
    if (expression.type === "ConditionalExpression") {
      return uniqueSorted([
        ...expressionObjectPaths(expression.consequent),
        ...expressionObjectPaths(expression.alternate),
      ]);
    }
    if (expression.type === "LogicalExpression") {
      return uniqueSorted([
        ...expressionObjectPaths(expression.left),
        ...expressionObjectPaths(expression.right),
      ]);
    }
    return [];
  };
  const addObjectPaths = (name, paths) => {
    if (!name || paths.length === 0) return false;
    let known = objectPaths.get(name);
    if (!known) {
      known = new Set();
      objectPaths.set(name, known);
    }
    const before = known.size;
    for (const objectPath of paths) {
      if (objectPath.split(".").filter(Boolean).length > 4) continue;
      if (known.size >= 128 && !known.has(objectPath)) continue;
      known.add(objectPath);
    }
    if (known.has("")) globalAliases.add(name);
    return known.size !== before;
  };
  const observeGlobalRegistration = (
    node,
    property,
    names,
    value,
    idiom,
    basePaths = [""],
    valueShape = expressionValueShape(value),
  ) => {
    if (names.length > 0) {
      const classOwners = classOwnersForExpression(value);
      const opaqueCall = classOwners.size > 0 ? null : opaqueCallValue(value);
      const closedIifeFunctionShape = opaqueCall
        ? reviewedIifeReturnedFunctionShape(opaqueCall)
        : null;
      const iifeEvidence = opaqueCall
        ? reviewedIifeCallEvidence(opaqueCall)
        : null;
      resolvedRegistrations.add(node);
      for (const basePath of basePaths) {
        for (const registeredName of names) {
          const pathSegments = [
            ...basePath.split(".").filter(Boolean),
            registeredName,
          ];
          const factoryReturnedCallableSourceContract =
            reviewedFactoryReturnedCallableSourceContract(value, pathSegments);
          const dynamicCallShape =
            opaqueCall &&
            !reviewedClosedGlobalCallValue(opaqueCall) &&
            !closedIifeFunctionShape &&
            !factoryReturnedCallableSourceContract
              ? {
                  evidence: iifeEvidence ?? callShapeEvidence(opaqueCall),
                  kind: iifeEvidence
                    ? "iife-call-result"
                    : "opaque-call-result",
                }
              : null;
          installations.push({
            ...(dynamicCallShape ? { dynamicCallShape } : {}),
            ...(factoryReturnedCallableSourceContract
              ? { factoryReturnedCallableSourceContract }
              : {}),
            memberKinds: [idiom],
            pathSegments,
            value,
            ...(closedIifeFunctionShape ? { closedIifeFunctionShape } : {}),
            valueShape:
              closedIifeFunctionShape || factoryReturnedCallableSourceContract
                ? "callable"
                : valueShape,
          });
        }
      }
      return;
    }
    if (isStaticallyNonPublicPropertyKey(property, nonPublicBindings)) {
      resolvedRegistrations.add(node);
      return;
    }
    if (!unresolvedRegistrations.has(node)) {
      unresolvedRegistrations.set(node, { idiom });
    }
  };

  // Establish root, nested-object, conditional, and IIFE-parameter aliases
  // before registration discovery so source order cannot affect results.
  let aliasChanged = true;
  while (aliasChanged) {
    aliasChanged = false;
    walkAst(program, (node) => {
      if (
        node.type === "VariableDeclarator" &&
        node.id?.type === "Identifier"
      ) {
        aliasChanged =
          addObjectPaths(node.id.name, expressionObjectPaths(node.init)) ||
          aliasChanged;
      }
      if (
        node.type === "AssignmentExpression" &&
        node.operator === "=" &&
        node.left?.type === "Identifier"
      ) {
        aliasChanged =
          addObjectPaths(node.left.name, expressionObjectPaths(node.right)) ||
          aliasChanged;
      }
      if (
        node.type === "CallExpression" &&
        (node.callee?.type === "FunctionExpression" ||
          node.callee?.type === "ArrowFunctionExpression")
      ) {
        for (let index = 0; index < node.callee.params.length; index += 1) {
          const parameter = node.callee.params[index];
          if (parameter?.type !== "Identifier") continue;
          aliasChanged =
            addObjectPaths(
              parameter.name,
              expressionObjectPaths(node.arguments[index]),
            ) || aliasChanged;
          const parameterValues = staticRegistrationNames(
            node.arguments[index],
            staticBindings,
            staticArrays,
          );
          if (parameterValues.length > 0) {
            const knownValues = staticBindings.get(parameter.name) ?? new Set();
            const before = knownValues.size;
            for (const value of parameterValues) knownValues.add(value);
            staticBindings.set(parameter.name, knownValues);
            if (knownValues.size !== before) aliasChanged = true;
          }
        }
      }
    });
  }

  // A runtime-supplied property key is not one exact string. Preserve it as an
  // explicit dynamic-table sentinel instead of silently dropping the member.
  const computedRegistrationBindings = new Set();
  walkAst(program, (node) => {
    if (
      node.type === "MemberExpression" &&
      node.computed &&
      node.property?.type === "Identifier" &&
      expressionObjectPaths(node.object).length > 0
    ) {
      computedRegistrationBindings.add(node.property.name);
    }
  });
  walkAst(program, (node) => {
    if (
      node.type !== "VariableDeclarator" ||
      node.id?.type !== "Identifier" ||
      expressionObjectPaths(node.init).length === 0
    ) {
      return;
    }
    if (!computedRegistrationBindings.has(node.id.name)) return;
    const label = node.id.name
      .replace(/([a-z0-9])([A-Z])/gu, "$1-$2")
      .replace(/[^A-Za-z0-9]+/gu, "-")
      .toLowerCase();
    staticBindings.set(node.id.name, new Set([`[[dynamic-table:${label}]]`]));
  });

  walkAst(program, (node) => {
    if (node.type === "FunctionDeclaration" && node.id?.name) {
      functionDefinitions.set(node.id.name, node);
    }
    if (node.type === "CallExpression" && node.callee?.type === "Identifier") {
      let calls = functionCalls.get(node.callee.name);
      if (!calls) {
        calls = [];
        functionCalls.set(node.callee.name, calls);
      }
      calls.push(node);
    }
  });

  const recordNode = (node, substitutions = staticBindings) => {
    if (node.type === "FunctionDeclaration" && node.id?.name)
      functionNames.add(node.id.name);
    if (node.type === "ClassDeclaration" && node.id?.name) {
      recordClassMembers(node, node.id.name, substitutions);
    }

    if (node.type === "VariableDeclarator" && node.id?.type === "Identifier") {
      if (node.init?.type === "ClassExpression") {
        recordClassMembers(node.init, node.id.name, substitutions);
        classExpressionOwners.set(node.init, node.id.name);
      }
      addExpressionMembers(node.id.name, node.init);
    }

    if (node.type === "AssignmentExpression" && node.operator === "=") {
      if (node.left?.type === "Identifier") {
        if (node.right?.type === "ClassExpression") {
          recordClassMembers(node.right, node.left.name, substitutions);
          classExpressionOwners.set(node.right, node.left.name);
        }
        addExpressionMembers(node.left.name, node.right);
      }
      const memberNames =
        node.left?.type === "MemberExpression"
          ? !node.left.computed && node.left.property?.type === "Identifier"
            ? [node.left.property.name]
            : staticRegistrationNames(
                node.left.property,
                substitutions,
                staticArrays,
              )
          : [];
      const memberName = memberNames[0] ?? null;
      const prototype = prototypeOwner(node.left?.object);
      if (prototype) {
        observePrototypeRegistration(
          node.left,
          prototype,
          node.left.property,
          memberNames,
          "computed-prototype-assignment",
        );
        for (const name of memberNames) {
          addMember(
            prototypeMembers,
            prototype,
            name,
            expressionValueShape(node.right),
          );
        }
      }
      if (
        node.left?.type === "MemberExpression" &&
        directMemberName(node.left) === "prototype" &&
        node.left.object?.type === "Identifier" &&
        node.right?.type === "ObjectExpression"
      ) {
        recordPrototypeObjectMembers(
          node.left.object.name,
          node.right,
          "computed-prototype-object-assignment",
          substitutions,
        );
      }

      if (node.left?.type === "MemberExpression") {
        const basePaths = expressionObjectPaths(node.left.object);
        if (basePaths.length === 0) return;
        observeGlobalRegistration(
          node.left,
          node.left.property,
          memberNames,
          node.right,
          "member-assignment",
          basePaths,
        );
      }
    }

    if (node.type === "CallExpression") {
      const objectCall = callName(node);
      const mutation = mutationCallName(node);
      if (
        node.callee?.type === "MemberExpression" &&
        !node.callee.computed &&
        node.callee.object?.type === "Identifier" &&
        node.callee.object.name === "util" &&
        node.callee.property?.type === "Identifier" &&
        node.callee.property.name === "inherits" &&
        node.arguments[0]?.type === "Identifier"
      ) {
        knownPrototypeOwners.add(node.arguments[0].name);
        const inherited = node.arguments[1];
        const sourceOwner =
          inherited?.type === "Identifier"
            ? inherited.name
            : prototypeOwner(inherited);
        addPrototypeSource(
          node.arguments[0].name,
          sourceOwner,
          inherited ?? node,
          "util-inherits",
        );
      }
      const targetPrototype = prototypeOwner(node.arguments?.[0]);
      if (
        targetPrototype &&
        (mutation === "Object.defineProperty" ||
          mutation === "Reflect.defineProperty" ||
          mutation === "Reflect.set")
      ) {
        const names = staticRegistrationNames(
          node.arguments[1],
          substitutions,
          staticArrays,
        );
        observePrototypeRegistration(
          node,
          targetPrototype,
          node.arguments[1],
          names,
          `computed-prototype-${mutation.replace(".", "-")}`,
        );
        for (const name of names) {
          addMember(
            prototypeMembers,
            targetPrototype,
            name,
            mutation === "Reflect.set"
              ? expressionValueShape(node.arguments[2])
              : descriptorValueShape(node.arguments[2]),
          );
        }
      }
      if (targetPrototype && mutation === "Object.defineProperties") {
        recordPrototypeObjectMembers(
          targetPrototype,
          node.arguments[1],
          "computed-prototype-define-properties",
          substitutions,
        );
      }
      if (targetPrototype && mutation === "Object.assign") {
        for (const source of node.arguments.slice(1)) {
          recordPrototypeObjectMembers(
            targetPrototype,
            source,
            "computed-prototype-object-assign",
            substitutions,
          );
        }
      }
      const legacyAccessor = directMemberName(node.callee);
      if (
        legacyAccessor === "__defineGetter__" ||
        legacyAccessor === "__defineSetter__"
      ) {
        const prototype = prototypeOwner(node.callee.object);
        const names = staticRegistrationNames(
          node.arguments[0],
          substitutions,
          staticArrays,
        );
        observePrototypeRegistration(
          node,
          prototype,
          node.arguments[0],
          names,
          `computed-prototype-${legacyAccessor}`,
        );
        for (const name of names) {
          addMember(prototypeMembers, prototype, name, "accessor");
        }
      }

      const objectTargetPaths = expressionObjectPaths(node.arguments?.[0]);
      if (
        (mutation === "Object.defineProperty" ||
          mutation === "Reflect.defineProperty") &&
        objectTargetPaths.length > 0
      ) {
        observeGlobalRegistration(
          node,
          node.arguments[1],
          staticRegistrationNames(
            node.arguments[1],
            substitutions,
            staticArrays,
          ),
          node.arguments[2]?.type === "ObjectExpression"
            ? (node.arguments[2].properties.find(
                (property) =>
                  property.type === "ObjectProperty" &&
                  !property.computed &&
                  property.key?.type === "Identifier" &&
                  property.key.name === "value",
              )?.value ?? null)
            : null,
          mutation === "Object.defineProperty"
            ? "define-property"
            : "reflect-define-property",
          objectTargetPaths,
          descriptorValueShape(node.arguments[2]),
        );
      }
      if (mutation === "Reflect.set" && objectTargetPaths.length > 0) {
        observeGlobalRegistration(
          node,
          node.arguments[1],
          staticRegistrationNames(
            node.arguments[1],
            substitutions,
            staticArrays,
          ),
          node.arguments[2] ?? null,
          "reflect-set",
          objectTargetPaths,
        );
      }
      if (
        mutation === "Object.defineProperties" &&
        objectTargetPaths.length > 0
      ) {
        if (node.arguments[1]?.type !== "ObjectExpression") {
          if (!unresolvedRegistrations.has(node)) {
            unresolvedRegistrations.set(node, {
              idiom: "opaque-define-properties-source",
            });
          }
        } else {
          for (const property of node.arguments[1].properties) {
            if (property.type === "SpreadElement") {
              if (!unresolvedRegistrations.has(property)) {
                unresolvedRegistrations.set(property, {
                  idiom: "opaque-define-properties-spread",
                });
              }
              continue;
            }
            const names =
              !property.computed && property.key?.type === "Identifier"
                ? [property.key.name]
                : staticPropertyName(property.key, substitutions);
            observeGlobalRegistration(
              property,
              property.key,
              names,
              property.value?.type === "ObjectExpression"
                ? (property.value.properties.find(
                    (descriptorProperty) =>
                      descriptorProperty.type === "ObjectProperty" &&
                      !descriptorProperty.computed &&
                      descriptorProperty.key?.type === "Identifier" &&
                      descriptorProperty.key.name === "value",
                  )?.value ?? null)
                : null,
              "define-properties",
              objectTargetPaths,
              descriptorValueShape(property.value),
            );
          }
        }
      }
      if (mutation === "Object.assign" && objectTargetPaths.length > 0) {
        for (const source of node.arguments.slice(1)) {
          if (source?.type === "Identifier" && objectMembers.has(source.name)) {
            for (const name of objectMembers.get(source.name)) {
              observeGlobalRegistration(
                source,
                source,
                [name],
                null,
                "object-assign-closed-binding",
                objectTargetPaths,
                memberValueShape(objectMembers, source.name, name),
              );
            }
            continue;
          }
          if (source?.type !== "ObjectExpression") {
            if (source && !unresolvedRegistrations.has(source)) {
              unresolvedRegistrations.set(source, {
                idiom: "opaque-object-assign-source",
              });
            }
            continue;
          }
          for (const property of source.properties) {
            if (property.type === "SpreadElement") {
              if (!unresolvedRegistrations.has(property)) {
                unresolvedRegistrations.set(property, {
                  idiom: "opaque-object-assign-spread",
                });
              }
              continue;
            }
            const names =
              !property.computed && property.key?.type === "Identifier"
                ? [property.key.name]
                : staticPropertyName(property.key, substitutions);
            observeGlobalRegistration(
              property,
              property.key,
              names,
              property.value,
              "object-assign",
              objectTargetPaths,
            );
          }
        }
      }

      if (
        node.callee?.type === "Identifier" &&
        /^(?:define|install)(?:Lazy)?Global$/u.test(node.callee.name)
      ) {
        observeGlobalRegistration(
          node,
          node.arguments[0],
          staticRegistrationNames(
            node.arguments[0],
            substitutions,
            staticArrays,
          ),
          null,
          "global-installer-call",
        );
      }

      if (
        node.callee?.type === "MemberExpression" &&
        !node.callee.computed &&
        node.callee.property?.type === "Identifier" &&
        node.callee.property.name === "forEach"
      ) {
        forEachCalls.push(node);
      }
    }
  };

  walkAst(program, (node) => recordNode(node, staticBindings));

  for (const call of forEachCalls) {
    let values = [];
    const receiver = call.callee.object;
    if (receiver?.type === "ArrayExpression") {
      values = receiver.elements.flatMap((element) =>
        staticPropertyName(element, staticBindings),
      );
    } else if (receiver?.type === "Identifier") {
      values = [...(staticArrays.get(receiver.name) ?? [])];
    }
    const callback = callbackFunction(call.arguments[0]);
    const parameter = callback?.params[0];
    if (values.length === 0 || parameter?.type !== "Identifier") continue;
    const substitutions = mergeSubstitutions(
      staticBindings,
      new Map([[parameter.name, new Set(values)]]),
    );
    walkAst(callback.body, (node) => recordNode(node, substitutions));
  }

  // Resolve private installer helpers whose authored call sites supply only
  // literal keys or members of a closed literal table. If even one call site
  // is dynamic, the parameter remains unresolved and validation fails below.
  for (const [name, definition] of functionDefinitions) {
    const calls = functionCalls.get(name) ?? [];
    if (calls.length === 0) continue;
    const additions = new Map();
    for (let index = 0; index < definition.params.length; index += 1) {
      const parameter = definition.params[index];
      if (parameter?.type !== "Identifier") continue;
      const perCall = calls.map((call) =>
        staticRegistrationNames(
          call.arguments[index],
          staticBindings,
          staticArrays,
        ),
      );
      if (perCall.some((values) => values.length === 0)) continue;
      additions.set(parameter.name, new Set(perCall.flat()));
    }
    if (additions.size === 0) continue;
    const substitutions = mergeSubstitutions(staticBindings, additions);
    walkAst(definition.body, (node) => recordNode(node, substitutions));
  }

  for (const [owner, sources] of prototypeSources) {
    for (const source of sources.values()) {
      if (
        source.sourceOwner &&
        (knownPrototypeOwners.has(source.sourceOwner) ||
          prototypeMembers.has(source.sourceOwner))
      ) {
        continue;
      }
      addMember(
        prototypeMembers,
        owner,
        inheritedShapeSentinel(source.node, source.idiom),
      );
    }
  }
  let inheritedChanged = true;
  while (inheritedChanged) {
    inheritedChanged = false;
    for (const [owner, sources] of prototypeSources) {
      for (const source of sources.values()) {
        if (!source.sourceOwner) continue;
        const before = prototypeMembers.get(owner)?.size ?? 0;
        for (const name of prototypeMembers.get(source.sourceOwner) ?? []) {
          addMember(
            prototypeMembers,
            owner,
            name,
            memberValueShape(prototypeMembers, source.sourceOwner, name),
          );
        }
        if ((prototypeMembers.get(owner)?.size ?? 0) !== before) {
          inheritedChanged = true;
        }
      }
    }
  }

  const unresolved = [...unresolvedRegistrations]
    .filter(([node]) => !resolvedRegistrations.has(node))
    .sort(([left], [right]) => (left.start ?? 0) - (right.start ?? 0))[0];
  if (unresolved) {
    const [node, registration] = unresolved;
    throw new Error(
      `${registrationContext(sourceText, node, sourcePath)}: unresolved computed global property registration (${registration.idiom})`,
    );
  }

  const publicPrototypeOwners = new Set();
  for (const { value } of installations) {
    for (const owner of classOwnersForExpression(value)) {
      publicPrototypeOwners.add(owner);
    }
    if (
      value?.type === "NewExpression" &&
      value.callee?.type === "Identifier"
    ) {
      publicPrototypeOwners.add(value.callee.name);
    } else if (value?.type === "Identifier") {
      publicPrototypeOwners.add(value.name);
    }
    for (const constructor of returnedConstructors(value)) {
      publicPrototypeOwners.add(constructor);
    }
  }
  const unresolvedPrototype = [...unresolvedPrototypeRegistrations]
    .filter(
      ([node, registration]) =>
        !resolvedRegistrations.has(node) &&
        publicPrototypeOwners.has(registration.owner),
    )
    .sort(([left], [right]) => (left.start ?? 0) - (right.start ?? 0))[0];
  if (unresolvedPrototype) {
    const [node, registration] = unresolvedPrototype;
    throw new Error(
      `${registrationContext(sourceText, node, sourcePath)}: unresolved computed public or returned-object member (${registration.idiom})`,
    );
  }

  const sourceKey = `global_${path
    .basename(sourcePath)
    .replace(/\.[^.]+$/u, "")
    .replace(/[^A-Za-z0-9]+/gu, "_")}`;
  const discovered = new Map();
  const addGlobal = (globalName, memberName = null, extraMetadata = {}) => {
    if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(globalName)) return;
    if (
      memberName !== null &&
      !memberName
        .split(".")
        .every(
          (segment) =>
            /^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(segment) ||
            /^\[\[(?:return|Symbol\.[A-Za-z0-9_$]+|dynamic-table:[a-z0-9-]+)\]\]$/u.test(
              segment,
            ),
        )
    ) {
      return;
    }
    const exportName =
      memberName === null ? globalName : `${globalName}.${memberName}`;
    const name = globalSurfaceName(exportName);
    const ipcConditional =
      path.basename(sourcePath) === "compat-polyfills.js" &&
      /^process\.(?:__exactKChannelHandle|channel|connected|disconnect|send|\[\[dynamic-table:(?:exact-channel-handle-key|k-channel-handle)\]\])/u.test(
        exportName,
      );
    const harnessConditional =
      path.basename(sourcePath) === "compat-polyfills.js" &&
      new Set(["badly", "failed", "ok"]).has(exportName);
    const evaluatorInstallation =
      exportName === "eval" ? options.evaluatorInstallation : null;
    const sourceRefs = uniqueSorted([
      sourceSymbol(sourcePath, exportName),
      ...(evaluatorInstallation?.sourceRefs ?? []),
    ]);
    const route = ipcConditional
      ? "legacy-bootstrap-ipc"
      : harnessConditional
        ? "legacy-bootstrap-harness"
        : "legacy-bootstrap";
    const targetVariants = evaluatorInstallation?.targetVariants ?? [
      ipcConditional
        ? "conditional:EXACT_IPC_FD"
        : harnessConditional
          ? "conditional:EXACT_COMPAT_TEST"
          : legacyBootstrapTargetVariant(sourcePath),
    ];
    const branches = normalizeInstallationBranches(
      targetVariants.map((targetVariant) =>
        makeInstallationBranch(route, targetVariant, sourceRefs),
      ),
    );
    const row = makeSurface("native-op", name, sourceRefs, {
      metadata: {
        branches,
        ...(ipcConditional
          ? { conditionalGate: "EXACT_IPC_FD" }
          : harnessConditional
            ? { conditionalGate: "EXACT_COMPAT_TEST" }
            : {}),
        exportName,
        globalName,
        installationBranches: branches,
        memberName,
        moduleSpecifiers: [],
        ...(exportName === "WebStreamsPolyfill"
          ? { semanticRole: "implementation-container" }
          : harnessConditional
            ? { semanticRole: "harness-only-compat-global" }
            : {}),
        sourceKey,
        surfaceType: "global-api",
        ...extraMetadata,
      },
    });
    const existing = discovered.get(name);
    if (!existing) {
      discovered.set(name, row);
      return;
    }
    const [merged] = mergeSurfaceEvidence(
      [existing, row],
      `${sourcePath} duplicate static global discovery`,
    );
    discovered.set(name, merged);
  };

  const namespaceAliases = [];
  for (const {
    closedIifeFunctionShape,
    dynamicCallShape,
    factoryReturnedCallableSourceContract,
    memberKinds = ["registration"],
    pathSegments,
    value,
    valueShape,
  } of installations) {
    const [globalName, ...memberSegments] = pathSegments;
    if (!globalName) continue;
    const installedMember =
      memberSegments.length === 0 ? null : memberSegments.join(".");
    const concreteInstallation = pathSegments.every(
      (segment) => !DYNAMIC_TABLE_MEMBER.test(segment),
    );
    const installationMetadata = {
      memberKinds,
      ...(concreteInstallation ? { publicReadAccessSourceProven: true } : {}),
      ...(valueShape ? { valueShape } : {}),
      ...(factoryReturnedCallableSourceContract
        ? { factoryReturnedCallableSourceContract }
        : {}),
    };
    addGlobal(
      globalName,
      installedMember,
      dynamicCallShape
        ? {
            ...installationMetadata,
            dynamicNamespace: true,
            dynamicNamespaceEvidence: dynamicCallShape.evidence,
            dynamicNamespaceKind: dynamicCallShape.kind,
          }
        : installationMetadata,
    );
    if (dynamicCallShape) {
      const dynamicNamespaceRoot = [globalName, ...memberSegments].join(".");
      const digest = dynamicCallShape.evidence
        .replace(/^sha256-/u, "")
        .slice(0, 12);
      const sentinel = `[[dynamic-table:call-result-${digest}-properties]]`;
      addGlobal(
        globalName,
        [installedMember, sentinel].filter(Boolean).join("."),
        {
          dynamicNamespace: true,
          dynamicNamespaceEvidence: dynamicCallShape.evidence,
          dynamicNamespaceKind: dynamicCallShape.kind,
          dynamicNamespaceRoot,
          memberKinds: ["dynamic-table"],
          semanticRoles: ["dynamic-call-result-shape"],
        },
      );
    }
    if (closedIifeFunctionShape) {
      for (const {
        memberPath,
        valueShape,
      } of closedIifeFunctionShape.members) {
        addGlobal(
          globalName,
          [installedMember, memberPath].filter(Boolean).join("."),
          {
            memberKinds: ["source-derived-iife-function-member"],
            ...(concreteInstallation
              ? { publicReadAccessSourceProven: true }
              : {}),
            valueShape,
          },
        );
      }
    }
    if (pathSegments.length === 1 && value) {
      for (const sourceObjectPath of expressionObjectPaths(value)) {
        if (sourceObjectPath)
          namespaceAliases.push({ destination: globalName, sourceObjectPath });
      }
    }
    const memberShapeFacts = new Map();
    const addMemberShapeFact = (name, shape) => {
      let shapes = memberShapeFacts.get(name);
      if (!shapes) {
        shapes = new Set();
        memberShapeFacts.set(name, shapes);
      }
      if (shape) shapes.add(shape);
    };
    const installedClassOwners = classOwnersForExpression(value);
    if (installedClassOwners.size > 0) {
      for (const owner of installedClassOwners) {
        for (const name of prototypeMembers.get(owner) ?? []) {
          addMemberShapeFact(
            name,
            memberValueShape(prototypeMembers, owner, name),
          );
        }
      }
    } else if (
      value?.type === "NewExpression" &&
      value.callee?.type === "Identifier"
    ) {
      for (const name of prototypeMembers.get(value.callee.name) ?? []) {
        addMemberShapeFact(
          name,
          memberValueShape(prototypeMembers, value.callee.name, name),
        );
      }
    } else if (value?.type === "Identifier") {
      for (const map of [prototypeMembers, objectMembers]) {
        for (const name of map.get(value.name) ?? []) {
          addMemberShapeFact(name, memberValueShape(map, value.name, name));
        }
      }
    } else if (value?.type === "ObjectExpression") {
      for (const property of value.properties) {
        if (property.type === "SpreadElement") continue;
        const names =
          !property.computed && property.key?.type === "Identifier"
            ? [property.key.name]
            : staticPropertyName(property.key, staticBindings);
        for (const name of names) {
          addMemberShapeFact(name, propertyValueShape(property));
        }
      }
    }
    for (const memberName of uniqueSorted(memberShapeFacts.keys())) {
      const memberShape = resolvedValueShape(
        memberShapeFacts.get(memberName) ?? [],
      );
      const concreteMember =
        concreteInstallation && !DYNAMIC_TABLE_MEMBER.test(memberName);
      addGlobal(
        globalName,
        [installedMember, memberName].filter(Boolean).join("."),
        {
          memberKinds: ["source-derived-member"],
          ...(concreteMember ? { publicReadAccessSourceProven: true } : {}),
          ...(memberShape ? { valueShape: memberShape } : {}),
        },
      );
    }
    for (const constructor of returnedConstructors(value)) {
      for (const memberName of prototypeMembers.get(constructor) ?? []) {
        const memberShape = memberValueShape(
          prototypeMembers,
          constructor,
          memberName,
        );
        addGlobal(
          globalName,
          [installedMember, "[[return]]", memberName].filter(Boolean).join("."),
          {
            memberKinds: ["returned-object-member"],
            ...(concreteInstallation
              ? { publicReadAccessSourceProven: true }
              : {}),
            ...(memberShape ? { valueShape: memberShape } : {}),
          },
        );
      }
    }

    if (
      globalName === "localStorage" &&
      installedMember === null &&
      value?.type === "NewExpression" &&
      value.arguments[0]?.type === "BooleanLiteral" &&
      value.arguments[0].value === true &&
      functionNames.has("_load") &&
      functionNames.has("_save")
    ) {
      const exportName = "localStorage.persistence";
      const name = `global:${exportName}`;
      discovered.set(
        name,
        makeSurface(
          "native-op",
          name,
          [
            sourceSymbol(sourcePath, "_load"),
            sourceSymbol(sourcePath, "_save"),
          ],
          {
            metadata: {
              exportName,
              globalName,
              memberName: "persistence",
              moduleSpecifiers: [],
              semanticRole: "storage-persistence",
              sourceKey,
              surfaceType: "global-api",
            },
          },
        ),
      );
    }
  }

  let namespaceChanged = true;
  while (namespaceChanged) {
    namespaceChanged = false;
    for (const { destination, sourceObjectPath } of namespaceAliases) {
      for (const row of [...discovered.values()]) {
        if (
          row.metadata.exportName !== sourceObjectPath &&
          !row.metadata.exportName.startsWith(`${sourceObjectPath}.`)
        ) {
          continue;
        }
        const suffix = row.metadata.exportName
          .slice(sourceObjectPath.length)
          .replace(/^\./u, "");
        const memberName = suffix || null;
        const aliasMetadata = {
          memberKinds: uniqueSorted([
            ...(row.metadata.memberKinds ?? []),
            "namespace-alias",
          ]),
          ...(row.metadata.publicReadAccessSourceProven === true
            ? { publicReadAccessSourceProven: true }
            : {}),
          ...(row.metadata.valueShape
            ? { valueShape: row.metadata.valueShape }
            : {}),
        };
        if (row.metadata.dynamicNamespace === true) {
          aliasMetadata.dynamicNamespace = true;
          aliasMetadata.dynamicNamespaceEvidence =
            row.metadata.dynamicNamespaceEvidence;
          aliasMetadata.dynamicNamespaceKind =
            row.metadata.dynamicNamespaceKind;
          const dynamicRoot = row.metadata.dynamicNamespaceRoot;
          if (dynamicRoot !== undefined) {
            if (
              dynamicRoot !== sourceObjectPath &&
              !dynamicRoot.startsWith(`${sourceObjectPath}.`)
            ) {
              throw new Error(
                `${sourcePath}: dynamic namespace root ${dynamicRoot} escapes aliased namespace ${sourceObjectPath}`,
              );
            }
            aliasMetadata.dynamicNamespaceRoot = `${destination}${dynamicRoot.slice(sourceObjectPath.length)}`;
          }
          if (row.metadata.semanticRoles) {
            aliasMetadata.semanticRoles = [...row.metadata.semanticRoles];
          }
        }
        const before = discovered.size;
        addGlobal(destination, memberName, aliasMetadata);
        if (discovered.size !== before) namespaceChanged = true;
      }
    }
  }

  return sortSurfaces([...discovered.values()]);
}

const SHARED_RUNTIME_ENTRY = "packages/ibex-runtime-js/src/runtime-entry.ts";
const SHARED_RUNTIME_SOURCE_ROOT = "packages/ibex-runtime-js/src";
const GENERATED_AUTHORITY_PATH =
  /(?:^|\/)(?:vendored-generated|generated|dist|out)(?:\/|$)|\.generated\.[A-Za-z0-9]+$/u;
const DYNAMIC_TABLE_MEMBER = /^\[\[dynamic-table:[a-z0-9-]+\]\]$/u;
const REVIEWED_SHARED_RUNTIME_PREFIX_READS = new Map([
  [
    "__exactLoadTimings",
    {
      activationVariants: ["baseline-input-absent", "baseline-input-present"],
      valueShape: "data",
    },
  ],
  [
    "Intl.DateTimeFormat",
    {
      activationVariants: [
        "constructor-absent-or-noncallable",
        "constructor-callable",
      ],
      valueShape: "callable",
    },
  ],
  [
    "Intl.DateTimeFormat.prototype",
    {
      activationVariants: [
        "constructor-absent-or-noncallable",
        "prototype-present",
      ],
      valueShape: "data",
    },
  ],
  [
    "Intl.Locale.prototype",
    {
      activationVariants: [
        "native-locale-prototype-absent",
        "native-locale-prototype-present",
      ],
      valueShape: "data",
    },
  ],
  [
    "Intl.NumberFormat",
    {
      activationVariants: [
        "constructor-absent-or-noncallable",
        "constructor-callable",
      ],
      valueShape: "callable",
    },
  ],
  [
    "Intl.NumberFormat.prototype",
    {
      activationVariants: [
        "constructor-absent-or-noncallable",
        "prototype-present",
      ],
      valueShape: "data",
    },
  ],
  [
    "Promise.prototype",
    {
      activationVariants: ["tracking-inactive", "tracking-active"],
      valueShape: "data",
    },
  ],
]);

function isPathInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative))
  );
}

function assertAuthoredAuthorityPath(
  candidate,
  sourceRoot,
  label,
  { allowGenerated = false } = {},
) {
  const normalized = posixPath(path.resolve(candidate));
  if (!isPathInside(path.resolve(sourceRoot), path.resolve(candidate))) {
    throw new Error(
      `${label}: authored runtime path escapes source root: ${normalized}`,
    );
  }
  if (!allowGenerated && GENERATED_AUTHORITY_PATH.test(normalized)) {
    throw new Error(
      `${label}: generated or vendored output cannot be inventory authority: ${normalized}`,
    );
  }
}

/** Verify that the active hermetic bundle command and discovery use one entry. */
export function validateRuntimeBundleEntry(
  packageJsonText,
  sourcePath = "package.json",
  expectedEntry = SHARED_RUNTIME_ENTRY,
) {
  let manifest;
  try {
    manifest = JSON.parse(packageJsonText);
  } catch (error) {
    throw new Error(`${sourcePath}: invalid JSON: ${error.message}`);
  }
  const command = manifest?.scripts?.["build:runtime"];
  if (typeof command !== "string" || command.length === 0) {
    throw new Error(`${sourcePath}: scripts.build:runtime is absent`);
  }
  const entries = [];
  const pattern = /(?:^|\s)--entry(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([^\s]+))/gu;
  for (const match of command.matchAll(pattern))
    entries.push(match[1] ?? match[2] ?? match[3]);
  if (entries.length !== 1 || entries[0] !== expectedEntry) {
    throw new Error(
      `${sourcePath}: build:runtime entry drift: expected ${expectedEntry}, discovered ${entries.length === 0 ? "<none>" : entries.join(", ")}`,
    );
  }
  return entries[0];
}

function globalSurfaceName(exportName) {
  return exportName.startsWith("_") ? exportName : `global:${exportName}`;
}

function installationRouteForRow(row) {
  const sourceKey = row.metadata?.sourceKey ?? "";
  if (sourceKey === "shared_runtime") return ["shared-runtime", "all"];
  if (sourceKey === "windows_native_shim")
    return ["windows-native-shim", "windows"];
  if (sourceKey === "evaluated_native_script")
    return ["evaluated-native-script", "default"];
  if (sourceKey === "native_jsi_global")
    return ["native-jsi-global", "default"];
  if (sourceKey === "hermes_intrinsic_evaluators")
    return ["hermes-intrinsic", "default"];
  if (sourceKey.startsWith("global_")) return ["legacy-bootstrap", "default"];
  return ["source-derived", "default"];
}

function makeInstallationBranch(
  route,
  targetVariant,
  sourceRefs,
  branchKind = "single",
) {
  const normalizedRefs = uniqueSorted(sourceRefs);
  return {
    branchKind,
    id: `${route}-${evidenceHash(`${route}\0${targetVariant}\0${normalizedRefs.join("\0")}`)}`,
    kind: branchKind,
    route,
    sourceRefs: normalizedRefs,
    targetVariant,
  };
}

function normalizeInstallationBranches(branches) {
  return normalizeComposedInstallationBranches(branches);
}

function implicitInstallationBranches(row) {
  if (Array.isArray(row.metadata?.installationBranches)) {
    return row.metadata.installationBranches;
  }
  if (row.metadata?.surfaceType !== "global-api") return [];
  const [route, targetVariant] = installationRouteForRow(row);
  return [makeInstallationBranch(route, targetVariant, row.sourceRefs)];
}

function sourcePathForRef(sourceRef) {
  const separator = sourceRef.lastIndexOf("#");
  return separator === -1 ? sourceRef : sourceRef.slice(0, separator);
}

function nativeEvidenceTargetVariant(sourceRef) {
  const sourcePath = sourcePathForRef(sourceRef);
  if (/(?:^|[_/])worklet(?:[_.\/]|$)/u.test(sourcePath)) return "worklet";
  return abiTargetVariant(sourceRef);
}

/**
 * A private-name observation is a second evidence view of an already observed
 * global implementation, not another way to install it. Join that evidence to
 * the concrete implementation branch with the same source and/or target. A
 * source can legitimately support more than one route, so an ambiguous match
 * enriches all existing candidates without manufacturing a new alternative.
 */
function mergeDualRoleInstallationBranches(globalRow, privateRow) {
  const branches = implicitInstallationBranches(globalRow).map((branch) => ({
    ...branch,
    sourceRefs: [...branch.sourceRefs],
  }));
  if (branches.length === 0) {
    throw new Error(
      `${globalRow.observedKey}: dual-role global has no implementation branch`,
    );
  }

  for (const sourceRef of privateRow.sourceRefs) {
    if (branches.some((branch) => branch.sourceRefs.includes(sourceRef)))
      continue;
    const sourcePath = sourcePathForRef(sourceRef);
    const targetVariant = nativeEvidenceTargetVariant(sourceRef);
    let candidates = branches.filter((branch) =>
      branch.sourceRefs.some(
        (candidate) => sourcePathForRef(candidate) === sourcePath,
      ),
    );
    if (candidates.length === 0) {
      candidates = branches.filter(
        (branch) => branch.targetVariant === targetVariant,
      );
    }
    if (candidates.length === 0) {
      candidates = branches.filter((branch) => branch.targetVariant === "all");
    }
    if (candidates.length === 0 && branches.length === 1) candidates = branches;
    if (candidates.length === 0) {
      // The observation identifies the operation but cannot distinguish among
      // already-proven implementations. Retain it on those implementations;
      // crucially, do not represent the evidence role as a new branch.
      candidates = branches;
    }
    for (const branch of candidates) branch.sourceRefs.push(sourceRef);
  }
  return normalizeInstallationBranches(branches);
}

function tsUnwrapExpression(node) {
  let current = node;
  while (
    current &&
    (ts.isAsExpression(current) ||
      ts.isTypeAssertionExpression(current) ||
      ts.isParenthesizedExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isSatisfiesExpression(current))
  ) {
    current = current.expression;
  }
  return current;
}

function tsMemberName(name, sourcePath) {
  if (!name || ts.isPrivateIdentifier(name)) return null;
  if (
    ts.isIdentifier(name) ||
    ts.isStringLiteralLike(name) ||
    ts.isNumericLiteral(name)
  ) {
    return name.text;
  }
  if (ts.isComputedPropertyName(name)) {
    const expression = tsUnwrapExpression(name.expression);
    if (
      ts.isPropertyAccessExpression(expression) &&
      ts.isIdentifier(expression.expression) &&
      expression.expression.text === "Symbol"
    ) {
      return `[[Symbol.${expression.name.text}]]`;
    }
    if (
      ts.isCallExpression(expression) &&
      ts.isPropertyAccessExpression(
        tsUnwrapExpression(expression.expression),
      ) &&
      ts.isIdentifier(tsUnwrapExpression(expression.expression).expression) &&
      tsUnwrapExpression(expression.expression).expression.text === "Symbol" &&
      tsUnwrapExpression(expression.expression).name.text === "for" &&
      ts.isStringLiteralLike(tsUnwrapExpression(expression.arguments[0]))
    ) {
      return `[[Symbol.for:${tsUnwrapExpression(expression.arguments[0]).text}]]`;
    }
    if (ts.isIdentifier(expression))
      return `[[symbol-binding:${expression.text}]]`;
    if (ts.isStringLiteralLike(expression) || ts.isNumericLiteral(expression))
      return expression.text;
    throw new Error(
      `${sourcePath}: unresolved computed public class/object member ${name.getText().replace(/\s+/gu, " ")}`,
    );
  }
  return null;
}

function tsHasNonPublicModifier(node) {
  return Boolean(
    node.modifiers?.some(
      (modifier) =>
        modifier.kind === ts.SyntaxKind.PrivateKeyword ||
        modifier.kind === ts.SyntaxKind.ProtectedKeyword,
    ),
  );
}

function tsFunctionLikeDeclaration(node) {
  const value = tsUnwrapExpression(node);
  if (
    ts.isFunctionDeclaration(value) ||
    ts.isFunctionExpression(value) ||
    ts.isArrowFunction(value) ||
    ts.isMethodDeclaration(value) ||
    ts.isGetAccessorDeclaration(value) ||
    ts.isSetAccessorDeclaration(value) ||
    ts.isConstructorDeclaration(value)
  ) {
    return value;
  }
  if (ts.isVariableDeclaration(value) && value.initializer) {
    return tsFunctionLikeDeclaration(value.initializer);
  }
  return null;
}

function tsReturnExpressions(functionNode) {
  if (ts.isArrowFunction(functionNode) && !ts.isBlock(functionNode.body))
    return [functionNode.body];
  const body = functionNode.body;
  if (!body || !ts.isBlock(body)) return [];
  const values = [];
  const visit = (node) => {
    if (node !== body && ts.isFunctionLike(node)) return;
    if (ts.isReturnStatement(node) && node.expression) {
      values.push(node.expression);
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(body);
  return values;
}

/**
 * Prove the authored Process.env dynamic-table route without treating a
 * runtime Proxy as an opaque object. The binding, traps, local helper graph,
 * and native bridge aliases all live in one TypeScript module, so this audit
 * can remain syntax-derived and mutation-sensitive without executing it.
 *
 * @ref LLP 0022#7-capabilities-principals-and-affordance-parity — the armed
 * environment is a shared facade over current-principal native overlays; its
 * open property domain must not inherit the legacy host-process provenance.
 */
export function scanPrincipalEnvironmentOverlayProxy(
  text,
  sourcePath = "packages/ibex-runtime-js/src/node/process.ts",
) {
  if (typeof text !== "string" || text.length === 0) {
    throw new Error(
      `${sourcePath}: principal environment Proxy source is empty`,
    );
  }
  const source = ts.createSourceFile(
    sourcePath,
    text,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TS,
  );
  for (const diagnostic of source.parseDiagnostics ?? []) {
    throw new Error(
      `${sourcePath}: unable to parse principal environment Proxy: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n")}`,
    );
  }
  const requireProof = (condition, message) => {
    if (!condition) {
      throw new Error(`${sourcePath}: ${message}`);
    }
  };
  const namedTopLevel = (predicate, name) =>
    source.statements.filter(
      (statement) => predicate(statement) && statement.name?.text === name,
    );

  const factories = namedTopLevel(ts.isFunctionDeclaration, "createEnvProxy");
  requireProof(
    factories.length === 1 && factories[0].body,
    "expected exactly one implemented top-level createEnvProxy factory",
  );
  const factory = factories[0];
  const processClasses = namedTopLevel(ts.isClassDeclaration, "Process");
  requireProof(
    processClasses.length === 1,
    "expected exactly one top-level Process class",
  );
  const envBindings = processClasses[0].members.filter((member) => {
    if (!ts.isPropertyDeclaration(member) || !member.initializer) return false;
    if (tsMemberName(member.name, sourcePath) !== "env") return false;
    const initializer = tsUnwrapExpression(member.initializer);
    const callee = ts.isCallExpression(initializer)
      ? tsUnwrapExpression(initializer.expression)
      : null;
    return (
      ts.isCallExpression(initializer) &&
      initializer.arguments.length === 0 &&
      ts.isIdentifier(callee) &&
      callee.text === "createEnvProxy"
    );
  });
  requireProof(
    envBindings.length === 1,
    "Process.env must be initialized by one direct createEnvProxy() call",
  );

  const setterBindings = factory.body.statements.flatMap((statement) =>
    ts.isVariableStatement(statement)
      ? statement.declarationList.declarations.filter(
          (declaration) =>
            ts.isIdentifier(declaration.name) &&
            declaration.name.text === "setPrincipalOverlay",
        )
      : [],
  );
  requireProof(
    setterBindings.length === 1 && setterBindings[0].initializer,
    "createEnvProxy must capture one setPrincipalOverlay binding",
  );
  const setterInitializer = tsUnwrapExpression(setterBindings[0].initializer);
  const setterCondition = ts.isConditionalExpression(setterInitializer)
    ? tsUnwrapExpression(setterInitializer.condition)
    : null;
  const setterTrue = ts.isConditionalExpression(setterInitializer)
    ? tsUnwrapExpression(setterInitializer.whenTrue)
    : null;
  const setterFalse = ts.isConditionalExpression(setterInitializer)
    ? tsUnwrapExpression(setterInitializer.whenFalse)
    : null;
  requireProof(
    ts.isConditionalExpression(setterInitializer) &&
      ts.isBinaryExpression(setterCondition) &&
      setterCondition.operatorToken.kind ===
        ts.SyntaxKind.EqualsEqualsEqualsToken &&
      ts.isTypeOfExpression(tsUnwrapExpression(setterCondition.left)) &&
      ts.isIdentifier(tsUnwrapExpression(setterCondition.left).expression) &&
      tsUnwrapExpression(setterCondition.left).expression.text ===
        "__exactSetEnv" &&
      ts.isStringLiteralLike(tsUnwrapExpression(setterCondition.right)) &&
      tsUnwrapExpression(setterCondition.right).text === "function" &&
      ts.isIdentifier(setterTrue) &&
      setterTrue.text === "__exactSetEnv" &&
      setterFalse?.kind === ts.SyntaxKind.NullKeyword,
    "setPrincipalOverlay must be the guarded lexical capture of __exactSetEnv",
  );

  const proxyReturns = factory.body.statements.filter((statement) => {
    if (!ts.isReturnStatement(statement) || !statement.expression) return false;
    const expression = tsUnwrapExpression(statement.expression);
    const constructor = ts.isNewExpression(expression)
      ? tsUnwrapExpression(expression.expression)
      : null;
    return (
      ts.isNewExpression(expression) &&
      ts.isIdentifier(constructor) &&
      constructor.text === "Proxy"
    );
  });
  requireProof(
    proxyReturns.length === 1,
    "createEnvProxy must directly return exactly one Proxy",
  );
  const proxy = tsUnwrapExpression(proxyReturns[0].expression);
  const handler = tsUnwrapExpression(proxy.arguments?.[1]);
  requireProof(
    proxy.arguments?.length === 2 && ts.isObjectLiteralExpression(handler),
    "createEnvProxy must supply one explicit Proxy handler object",
  );

  const requiredTrapNames = ["deleteProperty", "get", "ownKeys", "set"];
  const traps = new Map();
  for (const property of handler.properties) {
    if (!ts.isMethodDeclaration(property)) continue;
    const name = tsMemberName(property.name, sourcePath);
    if (!requiredTrapNames.includes(name)) continue;
    requireProof(!traps.has(name), `duplicate process.env Proxy trap ${name}`);
    traps.set(name, property);
  }
  requireProof(
    requiredTrapNames.every((name) => traps.has(name)),
    "process.env Proxy must define get, set, deleteProperty, and ownKeys traps",
  );

  const localFunctions = new Map();
  for (const statement of factory.body.statements) {
    if (!ts.isFunctionDeclaration(statement) || !statement.name) continue;
    requireProof(
      !localFunctions.has(statement.name.text),
      `duplicate createEnvProxy helper ${statement.name.text}`,
    );
    localFunctions.set(statement.name.text, statement);
  }
  const directIdentifierCalls = (callable) => {
    const calls = new Set();
    const visit = (node) => {
      if (node !== callable && ts.isFunctionDeclaration(node)) return;
      if (ts.isCallExpression(node)) {
        const callee = tsUnwrapExpression(node.expression);
        if (ts.isIdentifier(callee)) calls.add(callee.text);
      }
      ts.forEachChild(node, visit);
    };
    if (callable.body) visit(callable.body);
    return calls;
  };
  const bridgeForCall = (name) => {
    if (name === "setPrincipalOverlay") return "__exactSetEnv";
    if (
      new Set(["__exactGetAllEnv", "__exactGetEnv", "__exactSetEnv"]).has(name)
    ) {
      return name;
    }
    return null;
  };
  const reachableBridges = (callable) => {
    const bridges = new Set();
    const seenHelpers = new Set();
    const visit = (node) => {
      for (const call of directIdentifierCalls(node)) {
        const bridge = bridgeForCall(call);
        if (bridge) bridges.add(bridge);
        const helper = localFunctions.get(call);
        if (helper && !seenHelpers.has(call)) {
          seenHelpers.add(call);
          visit(helper);
        }
      }
    };
    visit(callable);
    return uniqueSorted(bridges);
  };
  const trapRoutes = requiredTrapNames.map((name) => ({
    name,
    nativeBridges: reachableBridges(traps.get(name)),
    sourceRef: sourceSymbol(sourcePath, `createEnvProxy:Proxy.${name}`),
  }));
  const routesByTrap = new Map(
    trapRoutes.map((route) => [route.name, new Set(route.nativeBridges)]),
  );
  for (const [trap, bridge] of [
    ["get", "__exactGetEnv"],
    ["set", "__exactSetEnv"],
    ["deleteProperty", "__exactSetEnv"],
    ["ownKeys", "__exactGetAllEnv"],
    ["ownKeys", "__exactGetEnv"],
  ]) {
    requireProof(
      routesByTrap.get(trap)?.has(bridge),
      `process.env ${trap} trap lost its ${bridge} route`,
    );
  }
  const nativeBridges = uniqueSorted(
    trapRoutes.flatMap((route) => route.nativeBridges),
  );
  requireProof(
    JSON.stringify(nativeBridges) ===
      JSON.stringify(["__exactGetAllEnv", "__exactGetEnv", "__exactSetEnv"]),
    "process.env Proxy native bridge set is incomplete or ambiguous",
  );

  const bindingRef = sourceSymbol(sourcePath, "Process.prototype.env");
  const factoryRef = sourceSymbol(sourcePath, "createEnvProxy");
  const sourceRefs = uniqueSorted([
    bindingRef,
    factoryRef,
    ...trapRoutes.map(({ sourceRef }) => sourceRef),
  ]);
  return {
    schema: PRINCIPAL_ENVIRONMENT_OVERLAY_SOURCE_CONTRACT_SCHEMA,
    surfaceName: PRINCIPAL_ENVIRONMENT_OVERLAY_SURFACE_NAME,
    dynamicMember: PRINCIPAL_ENVIRONMENT_OVERLAY_DYNAMIC_MEMBER,
    globalPath: "process.env",
    binding: {
      factory: "createEnvProxy",
      member: "Process.prototype.env",
      sourceRef: bindingRef,
    },
    factory: { name: "createEnvProxy", sourceRef: factoryRef },
    nativeBridges,
    proxyTraps: trapRoutes,
    sourceRefs,
  };
}

/**
 * Discover every global installed by the authored shared-runtime module graph.
 * The entry and every relative module are TypeScript authoring sources; bundle,
 * vendored, generated, and output files are deliberately rejected as authority.
 */
export function scanSharedRuntimeGlobalSurfaces(repoRoot) {
  const absoluteRepoRoot = path.resolve(repoRoot);
  const sourceRoot = path.join(absoluteRepoRoot, SHARED_RUNTIME_SOURCE_ROOT);
  const entryPath = path.join(absoluteRepoRoot, SHARED_RUNTIME_ENTRY);
  validateRuntimeBundleEntry(
    readUtf8(path.join(absoluteRepoRoot, "package.json")),
  );
  assertAuthoredAuthorityPath(entryPath, sourceRoot, SHARED_RUNTIME_ENTRY);

  const compilerOptions = {
    allowJs: false,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    noEmit: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ESNext,
  };
  const program = ts.createProgram({
    rootNames: [entryPath],
    options: compilerOptions,
  });
  const checker = program.getTypeChecker();
  const entrySource = program.getSourceFile(entryPath);
  if (!entrySource)
    throw new Error(
      `${SHARED_RUNTIME_ENTRY}: TypeScript program omitted runtime entry`,
    );

  const authoredSources = program
    .getSourceFiles()
    .filter(
      (source) =>
        !source.isDeclarationFile &&
        isPathInside(sourceRoot, source.fileName) &&
        !GENERATED_AUTHORITY_PATH.test(posixPath(source.fileName)),
    )
    .sort((left, right) => compareText(left.fileName, right.fileName));
  if (authoredSources.length === 0) {
    throw new Error(
      `${SHARED_RUNTIME_ENTRY}: authored TypeScript module graph is empty`,
    );
  }
  for (const source of authoredSources) {
    const relativePath = posixPath(
      path.relative(absoluteRepoRoot, source.fileName),
    );
    assertAuthoredAuthorityPath(source.fileName, sourceRoot, relativePath);
    for (const diagnostic of source.parseDiagnostics ?? []) {
      throw new Error(
        `${relativePath}: unable to parse authored runtime source: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n")}`,
      );
    }
    for (const statement of source.statements) {
      if (
        !ts.isImportDeclaration(statement) &&
        !ts.isExportDeclaration(statement)
      )
        continue;
      const specifier = statement.moduleSpecifier;
      if (
        !specifier ||
        !ts.isStringLiteralLike(specifier) ||
        !specifier.text.startsWith(".")
      )
        continue;
      const resolution = ts.resolveModuleName(
        specifier.text,
        source.fileName,
        compilerOptions,
        ts.sys,
      ).resolvedModule;
      if (!resolution) {
        throw new Error(
          `${relativePath}: unresolved authored relative import ${JSON.stringify(specifier.text)}`,
        );
      }
      assertAuthoredAuthorityPath(
        resolution.resolvedFileName,
        sourceRoot,
        `${relativePath}: import ${JSON.stringify(specifier.text)}`,
        { allowGenerated: true },
      );
    }
  }

  const processFacadeSources = authoredSources.filter(
    (source) =>
      posixPath(path.relative(absoluteRepoRoot, source.fileName)) ===
      "packages/ibex-runtime-js/src/node/process.ts",
  );
  if (processFacadeSources.length > 1) {
    throw new Error(
      "shared runtime inventory found duplicate authored process facades",
    );
  }
  const principalEnvironmentOverlay =
    processFacadeSources.length === 1
      ? scanPrincipalEnvironmentOverlayProxy(
          processFacadeSources[0].text,
          "packages/ibex-runtime-js/src/node/process.ts",
        )
      : null;

  const relativeSourcePath = (node) =>
    posixPath(path.relative(absoluteRepoRoot, node.getSourceFile().fileName));
  const symbolAt = (node) => {
    let symbol = checker.getSymbolAtLocation(node);
    if (
      ts.isIdentifier(node) &&
      ts.isShorthandPropertyAssignment(node.parent) &&
      node.parent.name === node
    ) {
      symbol = checker.getShorthandAssignmentValueSymbol(node.parent) ?? symbol;
    }
    const visited = new Set();
    while (
      symbol &&
      (symbol.flags & ts.SymbolFlags.Alias) !== 0 &&
      !visited.has(symbol)
    ) {
      visited.add(symbol);
      symbol = checker.getAliasedSymbol(symbol);
    }
    return symbol ?? null;
  };
  const declarationIdentity = (node) =>
    `${relativeSourcePath(node)}:${node.pos}:${node.end}`;
  const enclosingName = (node) => {
    let current = node;
    while (current) {
      if (
        (ts.isFunctionDeclaration(current) ||
          ts.isMethodDeclaration(current) ||
          ts.isClassDeclaration(current) ||
          ts.isClassExpression(current)) &&
        current.name
      ) {
        return current.name.getText();
      }
      if (
        (ts.isArrowFunction(current) || ts.isFunctionExpression(current)) &&
        ts.isVariableDeclaration(current.parent) &&
        ts.isIdentifier(current.parent.name)
      ) {
        return current.parent.name.text;
      }
      current = current.parent;
    }
    return "<module>";
  };
  const authoredRef = (node, suffix) =>
    sourceSymbol(relativeSourcePath(node), `${enclosingName(node)}:${suffix}`);

  const importBindings = [];
  for (const statement of entrySource.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      !ts.isStringLiteralLike(statement.moduleSpecifier)
    )
      continue;
    if (statement.moduleSpecifier.text !== "./bootstrap.js") continue;
    const bindings = statement.importClause?.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings)) continue;
    for (const element of bindings.elements) {
      if ((element.propertyName ?? element.name).text === "installGlobals")
        importBindings.push(element.name);
    }
  }
  if (importBindings.length !== 1) {
    throw new Error(
      `${SHARED_RUNTIME_ENTRY}: expected exactly one named installGlobals import from ./bootstrap.js`,
    );
  }
  const installSymbol = symbolAt(importBindings[0]);
  const installCalls = [];
  const findInstallCalls = (node) => {
    if (
      ts.isCallExpression(node) &&
      symbolAt(tsUnwrapExpression(node.expression)) === installSymbol
    ) {
      installCalls.push(node);
    }
    ts.forEachChild(node, findInstallCalls);
  };
  findInstallCalls(entrySource);
  if (
    installCalls.length !== 1 ||
    !ts.isExpressionStatement(installCalls[0].parent)
  ) {
    throw new Error(
      `${SHARED_RUNTIME_ENTRY}: installGlobals must have exactly one direct top-level invocation`,
    );
  }

  const literalArrays = new Map();
  const literalStringArrayInitializer = (expression) => {
    const value = tsUnwrapExpression(expression);
    if (ts.isArrayLiteralExpression(value)) return value;
    if (
      ts.isCallExpression(value) &&
      value.arguments.length === 1 &&
      ts.isPropertyAccessExpression(tsUnwrapExpression(value.expression)) &&
      ts.isIdentifier(tsUnwrapExpression(value.expression).expression) &&
      tsUnwrapExpression(value.expression).expression.text === 'Object' &&
      tsUnwrapExpression(value.expression).name.text === 'freeze'
    ) {
      const argument = tsUnwrapExpression(value.arguments[0]);
      return ts.isArrayLiteralExpression(argument) ? argument : null;
    }
    return null;
  };
  const arraySymbol = (expression) => {
    const value = tsUnwrapExpression(expression);
    return ts.isIdentifier(value) ? symbolAt(value) : null;
  };
  for (const source of authoredSources) {
    const visit = (node) => {
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.initializer
      ) {
        const initializer = literalStringArrayInitializer(node.initializer);
        if (!initializer) {
          ts.forEachChild(node, visit);
          return;
        }
        const symbol = symbolAt(node.name);
        const values = initializer
          .elements.map((element) => tsUnwrapExpression(element))
          .filter((element) => ts.isStringLiteralLike(element))
          .map((element) => element.text);
        if (
          symbol &&
          values.length === initializer.elements.length
        ) {
          literalArrays.set(symbol, new Set(values));
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  for (const source of authoredSources) {
    const visit = (node) => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(tsUnwrapExpression(node.expression)) &&
        tsUnwrapExpression(node.expression).name.text === "push"
      ) {
        const receiver = tsUnwrapExpression(node.expression).expression;
        const symbol = arraySymbol(receiver);
        const table = symbol ? literalArrays.get(symbol) : null;
        if (table) {
          const values = node.arguments.map((argument) =>
            tsUnwrapExpression(argument),
          );
          if (values.every((argument) => ts.isStringLiteralLike(argument))) {
            for (const value of values) table.add(value.text);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }

  const facts = new Map();
  const globalAliases = new Map();
  const installedSymbolPaths = new Map();
  const reviewedPrefixReadProofs = new Map();
  const addFact = (
    segments,
    refs,
    memberKinds = ["registration"],
    semanticRole,
    valueShape,
  ) => {
    if (segments.length === 0) return;
    const exportName = segments.join(".");
    let fact = facts.get(exportName);
    if (!fact) {
      fact = {
        exportName,
        globalName: segments[0],
        memberKinds: new Set(),
        memberName: segments.length === 1 ? null : segments.slice(1).join("."),
        refs: new Set(),
        semanticRoles: new Set(),
        valueShapes: new Set(),
      };
      facts.set(exportName, fact);
    }
    for (const ref of refs) fact.refs.add(ref);
    for (const kind of memberKinds) fact.memberKinds.add(kind);
    if (semanticRole) fact.semanticRoles.add(semanticRole);
    if (valueShape) fact.valueShapes.add(valueShape);
  };
  const addPathFacts = (
    segments,
    refs,
    memberKinds = ["registration"],
    semanticRole,
    valueShape,
  ) => {
    for (let length = 1; length <= segments.length; length += 1) {
      const prefixName = segments.slice(0, length).join(".");
      if (length < segments.length && facts.has(prefixName)) continue;
      addFact(
        segments.slice(0, length),
        length === segments.length ? refs : refs.slice(0, 1),
        length === segments.length ? memberKinds : ["namespace-prefix"],
        semanticRole,
        length === segments.length ? valueShape : undefined,
      );
    }
  };

  const bindingFor = (symbol, environment) =>
    symbol ? environment.get(symbol) : null;
  const staticStrings = (expression, environment, seen = new Set()) => {
    const node = tsUnwrapExpression(expression);
    if (!node) return [];
    if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node))
      return [node.text];
    if (ts.isIdentifier(node)) {
      const symbol = symbolAt(node);
      if (!symbol || seen.has(symbol)) return [];
      const bound = bindingFor(symbol, environment);
      if (bound?.strings) return [...bound.strings];
      if (literalArrays.has(symbol)) return [...literalArrays.get(symbol)];
      seen.add(symbol);
      const values = [];
      for (const declaration of symbol.declarations ?? []) {
        if (ts.isVariableDeclaration(declaration) && declaration.initializer) {
          values.push(
            ...staticStrings(declaration.initializer, environment, seen),
          );
        }
        if (ts.isParameter(declaration) && bound?.expression) {
          values.push(
            ...staticStrings(bound.expression, bound.environment, seen),
          );
        }
      }
      return uniqueSorted(values);
    }
    if (ts.isConditionalExpression(node)) {
      return uniqueSorted([
        ...staticStrings(node.whenTrue, environment, seen),
        ...staticStrings(node.whenFalse, environment, seen),
      ]);
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.BarBarToken
    ) {
      return uniqueSorted([
        ...staticStrings(node.left, environment, seen),
        ...staticStrings(node.right, environment, seen),
      ]);
    }
    return [];
  };

  const globalPaths = (
    expression,
    environment,
    seen = new Set(),
    includeInstalled = true,
  ) => {
    const node = tsUnwrapExpression(expression);
    if (!node) return [];
    if (ts.isIdentifier(node) && node.text === "globalThis") return [[]];
    if (ts.isIdentifier(node)) {
      const symbol = symbolAt(node);
      if (!symbol || seen.has(symbol)) return [];
      const bound = bindingFor(symbol, environment);
      if (bound?.globalPaths)
        return bound.globalPaths.map((segments) => [...segments]);
      if (includeInstalled && installedSymbolPaths.has(symbol)) {
        return installedSymbolPaths
          .get(symbol)
          .map((segments) => [...segments]);
      }
      seen.add(symbol);
      const paths = [];
      for (const declaration of symbol.declarations ?? []) {
        if (ts.isVariableDeclaration(declaration) && declaration.initializer) {
          paths.push(
            ...globalPaths(
              declaration.initializer,
              environment,
              seen,
              includeInstalled,
            ),
          );
        }
        if (ts.isParameter(declaration) && bound?.expression) {
          paths.push(
            ...globalPaths(
              bound.expression,
              bound.environment,
              seen,
              includeInstalled,
            ),
          );
        }
      }
      return paths;
    }
    if (ts.isPropertyAccessExpression(node) || ts.isPropertyAccessChain(node)) {
      return globalPaths(
        node.expression,
        environment,
        seen,
        includeInstalled,
      ).map((segments) => [...segments, node.name.text]);
    }
    if (ts.isElementAccessExpression(node) || ts.isElementAccessChain(node)) {
      const bases = globalPaths(
        node.expression,
        environment,
        seen,
        includeInstalled,
      );
      const names = staticStrings(node.argumentExpression, environment);
      return bases.flatMap((segments) =>
        names.map((name) => [...segments, name]),
      );
    }
    if (ts.isConditionalExpression(node)) {
      return [
        ...globalPaths(node.whenTrue, environment, seen, includeInstalled),
        ...globalPaths(node.whenFalse, environment, seen, includeInstalled),
      ];
    }
    if (
      ts.isBinaryExpression(node) &&
      (node.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
        node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)
    ) {
      return [
        ...globalPaths(node.left, environment, seen, includeInstalled),
        ...globalPaths(node.right, environment, seen, includeInstalled),
      ];
    }
    return [];
  };

  const dynamicTableValues = (expression, environment) => {
    const node = tsUnwrapExpression(expression);
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(tsUnwrapExpression(node.expression)) &&
      ts.isIdentifier(tsUnwrapExpression(node.expression).expression) &&
      tsUnwrapExpression(node.expression).expression.text === "Object" &&
      tsUnwrapExpression(node.expression).name.text === "entries" &&
      ts.isIdentifier(tsUnwrapExpression(node.arguments[0])) &&
      tsUnwrapExpression(node.arguments[0]).text === "_prevEnv"
    ) {
      return ["[[dynamic-table:host-process-env-properties]]"];
    }
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(tsUnwrapExpression(node.expression)) &&
      ts.isIdentifier(tsUnwrapExpression(node.expression).expression) &&
      tsUnwrapExpression(node.expression).expression.text === "Object" &&
      tsUnwrapExpression(node.expression).name.text === "getOwnPropertyNames"
    ) {
      const argument = tsUnwrapExpression(node.arguments[0]);
      if (ts.isIdentifier(argument) && argument.text === "_oldProcess") {
        return ["[[dynamic-table:host-process-own-properties]]"];
      }
      if (ts.isIdentifier(argument) && argument.text === "proto") {
        return ["[[dynamic-table:host-process-prototype-properties]]"];
      }
      const paths = globalPaths(argument, environment);
      if (paths.length === 1 && paths[0].length > 0) {
        return [
          `[[dynamic-table:${paths[0]
            .join("-")
            .replace(/[^a-z0-9-]/giu, "-")
            .toLowerCase()}-own-properties]]`,
        ];
      }
    }
    return [];
  };

  const propertyNames = (name, environment, sourcePath) => {
    if (!name) return [];
    if (
      ts.isIdentifier(name) ||
      ts.isStringLiteralLike(name) ||
      ts.isNumericLiteral(name)
    ) {
      return [name.text];
    }
    if (ts.isComputedPropertyName(name)) {
      const values = staticStrings(name.expression, environment);
      if (values.length > 0) return values;
      const symbolName = tsMemberName(name, sourcePath);
      return symbolName ? [symbolName] : [];
    }
    return [];
  };

  const registrationNames = (expression, environment) => {
    const direct = staticStrings(expression, environment);
    if (direct.length > 0) return direct;
    const node = tsUnwrapExpression(expression);
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "Symbol"
    ) {
      return [`[[Symbol.${node.name.text}]]`];
    }
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(tsUnwrapExpression(node.expression)) &&
      ts.isIdentifier(tsUnwrapExpression(node.expression).expression) &&
      tsUnwrapExpression(node.expression).expression.text === "Symbol" &&
      tsUnwrapExpression(node.expression).name.text === "for" &&
      ts.isStringLiteralLike(tsUnwrapExpression(node.arguments[0]))
    ) {
      return [`[[Symbol.for:${tsUnwrapExpression(node.arguments[0]).text}]]`];
    }
    if (ts.isIdentifier(node)) {
      const symbol = symbolAt(node);
      const isSymbolBinding = (symbol?.declarations ?? []).some(
        (declaration) =>
          ts.isVariableDeclaration(declaration) &&
          declaration.initializer &&
          ts.isCallExpression(tsUnwrapExpression(declaration.initializer)) &&
          ts.isIdentifier(
            tsUnwrapExpression(declaration.initializer).expression,
          ) &&
          tsUnwrapExpression(declaration.initializer).expression.text ===
            "Symbol",
      );
      if (isSymbolBinding) return [`[[symbol-binding:${node.text}]]`];
    }
    return [];
  };

  const expressionSymbol = (expression, environment, seen = new Set()) => {
    const node = tsUnwrapExpression(expression);
    if (!node) return null;
    if (ts.isIdentifier(node)) {
      const symbol = symbolAt(node);
      if (!symbol || seen.has(symbol)) return symbol;
      const bound = bindingFor(symbol, environment);
      if (bound?.expression) {
        seen.add(symbol);
        return expressionSymbol(bound.expression, bound.environment, seen);
      }
      return symbol;
    }
    if (ts.isPropertyAccessExpression(node)) return symbolAt(node.name);
    if (ts.isClassExpression(node) && node.name) return symbolAt(node.name);
    return null;
  };

  const callableDeclarations = (expression, environment, seen = new Set()) => {
    const node = tsUnwrapExpression(expression);
    if (!node) return [];
    if (ts.isFunctionExpression(node) || ts.isArrowFunction(node))
      return [node];
    if (ts.isIdentifier(node)) {
      const symbol = symbolAt(node);
      if (!symbol || seen.has(symbol)) return [];
      const bound = bindingFor(symbol, environment);
      if (bound?.expression) {
        seen.add(symbol);
        return callableDeclarations(bound.expression, bound.environment, seen);
      }
      const declarations = [];
      for (const declaration of symbol.declarations ?? []) {
        const callable = tsFunctionLikeDeclaration(declaration);
        if (callable) declarations.push(callable);
      }
      return declarations;
    }
    const symbol = symbolAt(
      ts.isPropertyAccessExpression(node) ? node.name : node,
    );
    return (symbol?.declarations ?? []).flatMap((declaration) => {
      const callable = tsFunctionLikeDeclaration(declaration);
      return callable ? [callable] : [];
    });
  };

  const invocationEnvironment = (declaration, call, callerEnvironment) => {
    const environment = new Map(callerEnvironment);
    for (let index = 0; index < declaration.parameters.length; index += 1) {
      const parameter = declaration.parameters[index];
      if (!ts.isIdentifier(parameter.name)) continue;
      const symbol = symbolAt(parameter.name);
      const argument = call.arguments?.[index];
      if (!symbol || !argument) continue;
      environment.set(symbol, {
        expression: argument,
        environment: callerEnvironment,
        globalPaths: globalPaths(argument, callerEnvironment),
        strings: new Set(staticStrings(argument, callerEnvironment)),
      });
    }
    return environment;
  };

  const classAugmentations = new Map();
  const addClassAugmentation = (symbol, augmentation) => {
    if (!symbol) return;
    let values = classAugmentations.get(symbol);
    if (!values) {
      values = [];
      classAugmentations.set(symbol, values);
    }
    values.push(augmentation);
  };
  const augmentationTarget = (expression) => {
    const node = tsUnwrapExpression(expression);
    if (ts.isPropertyAccessExpression(node) && node.name.text === "prototype") {
      return {
        memberKind: "prototype",
        symbol: expressionSymbol(node.expression, new Map()),
      };
    }
    if (ts.isIdentifier(node)) {
      return {
        memberKind: "static",
        symbol: expressionSymbol(node, new Map()),
      };
    }
    return null;
  };
  for (const source of authoredSources) {
    const sourcePath = posixPath(
      path.relative(absoluteRepoRoot, source.fileName),
    );
    const visit = (node) => {
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        (ts.isPropertyAccessExpression(tsUnwrapExpression(node.left)) ||
          ts.isElementAccessExpression(tsUnwrapExpression(node.left)))
      ) {
        const left = tsUnwrapExpression(node.left);
        const target = augmentationTarget(left.expression);
        const names = ts.isPropertyAccessExpression(left)
          ? [left.name.text]
          : staticStrings(left.argumentExpression, new Map());
        if (!target) {
          ts.forEachChild(node, visit);
          return;
        }
        for (const name of names) {
          addClassAugmentation(target.symbol, {
            memberKind: target.memberKind,
            name,
            node,
            sourcePath,
            value: node.right,
          });
        }
      }
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(tsUnwrapExpression(node.expression)) &&
        ts.isIdentifier(tsUnwrapExpression(node.expression).expression) &&
        tsUnwrapExpression(node.expression).expression.text === "Object" &&
        new Set(["defineProperty", "defineProperties", "assign"]).has(
          tsUnwrapExpression(node.expression).name.text,
        )
      ) {
        const method = tsUnwrapExpression(node.expression).name.text;
        const target = augmentationTarget(node.arguments[0]);
        if (target) {
          if (method === "defineProperty") {
            for (const name of staticStrings(node.arguments[1], new Map())) {
              addClassAugmentation(target.symbol, {
                memberKind: target.memberKind,
                name,
                node,
                sourcePath,
                value: node.arguments[2],
              });
            }
          } else {
            for (const object of node.arguments.slice(1)) {
              const value = tsUnwrapExpression(object);
              if (!ts.isObjectLiteralExpression(value)) continue;
              for (const property of value.properties) {
                if (ts.isSpreadAssignment(property)) continue;
                for (const name of propertyNames(
                  property.name,
                  new Map(),
                  sourcePath,
                )) {
                  addClassAugmentation(target.symbol, {
                    memberKind: target.memberKind,
                    name,
                    node: property,
                    sourcePath,
                    value: ts.isPropertyAssignment(property)
                      ? property.initializer
                      : property,
                  });
                }
              }
            }
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }

  const resolveValueExpressions = (
    expression,
    environment,
    seen = new Set(),
  ) => {
    const node = tsUnwrapExpression(expression);
    if (!node) return [];
    if (ts.isConditionalExpression(node)) {
      return [
        ...resolveValueExpressions(node.whenTrue, environment, seen),
        ...resolveValueExpressions(node.whenFalse, environment, seen),
      ];
    }
    if (
      ts.isBinaryExpression(node) &&
      (node.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
        node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)
    ) {
      return [
        ...resolveValueExpressions(node.left, environment, seen),
        ...resolveValueExpressions(node.right, environment, seen),
      ];
    }
    if (ts.isIdentifier(node)) {
      const symbol = symbolAt(node);
      if (!symbol || seen.has(symbol)) return [{ environment, node }];
      const bound = bindingFor(symbol, environment);
      if (bound?.expression) {
        const nextSeen = new Set(seen).add(symbol);
        return resolveValueExpressions(
          bound.expression,
          bound.environment,
          nextSeen,
        );
      }
      const declarations = symbol.declarations ?? [];
      const classes = declarations.filter(
        (declaration) =>
          ts.isClassDeclaration(declaration) ||
          ts.isClassExpression(declaration),
      );
      if (classes.length > 0)
        return classes.map((declaration) => ({
          environment,
          node: declaration,
        }));
      const functions = declarations.filter((declaration) =>
        tsFunctionLikeDeclaration(declaration),
      );
      const variables = declarations.filter(
        (declaration) =>
          ts.isVariableDeclaration(declaration) && declaration.initializer,
      );
      if (variables.length > 0) {
        const nextSeen = new Set(seen).add(symbol);
        return variables.flatMap((declaration) =>
          resolveValueExpressions(
            declaration.initializer,
            environment,
            nextSeen,
          ),
        );
      }
      if (functions.length > 0) {
        return functions.map((declaration) => ({
          environment,
          node: tsFunctionLikeDeclaration(declaration),
        }));
      }
      return [{ environment, node }];
    }
    if (ts.isCallExpression(node)) {
      const callee = tsUnwrapExpression(node.expression);
      const calleeName = ts.isIdentifier(callee)
        ? callee.text
        : ts.isPropertyAccessExpression(callee)
          ? callee.name.text
          : "";
      if (
        new Set([
          "preserveConstructorName",
          "createGlobalBufferConstructor",
        ]).has(calleeName)
      ) {
        return resolveValueExpressions(node.arguments[0], environment, seen);
      }
      const returns = [];
      for (const declaration of callableDeclarations(callee, environment)) {
        const invocation = invocationEnvironment(
          declaration,
          node,
          environment,
        );
        for (const returned of tsReturnExpressions(declaration)) {
          returns.push(...resolveValueExpressions(returned, invocation, seen));
        }
      }
      return returns.length > 0 ? returns : [{ environment, node }];
    }
    return [{ environment, node }];
  };

  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
  // public read probes may use only a source-proven value shape. A path whose
  // authored definitions disagree, or whose type is any/unknown, deliberately
  // remains unprobeable rather than relying on the loaded runtime to choose a
  // convenient interpretation.
  const directValueShape = (expression) => {
    const node = tsUnwrapExpression(expression);
    if (!node) return null;
    if (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isClassDeclaration(node) ||
      ts.isClassExpression(node)
    ) {
      return "callable";
    }
    if (
      ts.isObjectLiteralExpression(node) ||
      ts.isArrayLiteralExpression(node) ||
      ts.isNewExpression(node) ||
      ts.isStringLiteralLike(node) ||
      ts.isNumericLiteral(node) ||
      ts.isBigIntLiteral(node) ||
      ts.isRegularExpressionLiteral(node) ||
      node.kind === ts.SyntaxKind.TrueKeyword ||
      node.kind === ts.SyntaxKind.FalseKeyword ||
      node.kind === ts.SyntaxKind.NullKeyword ||
      (ts.isIdentifier(node) &&
        new Set(["undefined", "NaN", "Infinity"]).has(node.text))
    ) {
      return "data";
    }
    const type = checker.getTypeAtLocation(node);
    const candidates = type.isUnionOrIntersection() ? type.types : [type];
    const shapes = new Set();
    for (const candidate of candidates) {
      if (
        (candidate.flags &
          (ts.TypeFlags.Any | ts.TypeFlags.Unknown | ts.TypeFlags.Never)) !==
        0
      ) {
        return null;
      }
      shapes.add(
        candidate.getCallSignatures().length > 0 ||
          candidate.getConstructSignatures().length > 0
          ? "callable"
          : "data",
      );
    }
    return shapes.size === 1 ? [...shapes][0] : null;
  };
  const resolvedValueShape = (expression, environment) => {
    const candidates = resolveValueExpressions(expression, environment).map(
      (resolved) => directValueShape(resolved.node),
    );
    if (candidates.length === 0 || candidates.some((shape) => !shape)) {
      return null;
    }
    const shapes = new Set(candidates);
    return shapes.size === 1 ? [...shapes][0] : null;
  };
  const expressionUseNode = (expression) => {
    let current = expression;
    while (
      current?.parent &&
      (ts.isAsExpression(current.parent) ||
        ts.isTypeAssertionExpression(current.parent) ||
        ts.isParenthesizedExpression(current.parent) ||
        ts.isNonNullExpression(current.parent) ||
        ts.isSatisfiesExpression(current.parent)) &&
      current.parent.expression === current
    ) {
      current = current.parent;
    }
    return current;
  };
  const concretePathBinding = (
    expression,
    environment,
    expectedSegments,
    seen = new Set(),
  ) => {
    const node = tsUnwrapExpression(expression);
    if (!node) return false;
    const expectedName = expectedSegments.join(".");
    if (
      !globalPaths(node, environment).some(
        (segments) => segments.join(".") === expectedName,
      )
    ) {
      return false;
    }
    const terminalMember = expectedSegments.at(-1);
    if (ts.isPropertyAccessExpression(node)) {
      return (
        node.name.text === terminalMember &&
        /^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(terminalMember) &&
        !DYNAMIC_TABLE_MEMBER.test(terminalMember)
      );
    }
    if (ts.isElementAccessExpression(node)) {
      const names = staticStrings(node.argumentExpression, environment);
      return (
        names.length === 1 &&
        names[0] === terminalMember &&
        /^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(terminalMember) &&
        !DYNAMIC_TABLE_MEMBER.test(terminalMember)
      );
    }
    if (!ts.isIdentifier(node)) return false;
    const symbol = symbolAt(node);
    if (!symbol || seen.has(symbol)) return false;
    const nextSeen = new Set(seen).add(symbol);
    const bound = bindingFor(symbol, environment);
    if (
      bound?.expression &&
      concretePathBinding(
        bound.expression,
        bound.environment,
        expectedSegments,
        nextSeen,
      )
    ) {
      return true;
    }
    return (symbol.declarations ?? []).some(
      (declaration) =>
        ts.isVariableDeclaration(declaration) &&
        declaration.initializer &&
        concretePathBinding(
          declaration.initializer,
          environment,
          expectedSegments,
          nextSeen,
        ),
    );
  };
  const callableMembershipGuard = (expression) => {
    const use = expressionUseNode(expression);
    const typeOf = use?.parent;
    if (
      !typeOf ||
      !ts.isTypeOfExpression(typeOf) ||
      typeOf.expression !== use
    ) {
      return null;
    }
    const comparison = typeOf.parent;
    if (
      !comparison ||
      !ts.isBinaryExpression(comparison) ||
      !new Set([
        ts.SyntaxKind.EqualsEqualsToken,
        ts.SyntaxKind.EqualsEqualsEqualsToken,
        ts.SyntaxKind.ExclamationEqualsToken,
        ts.SyntaxKind.ExclamationEqualsEqualsToken,
      ]).has(comparison.operatorToken.kind)
    ) {
      return null;
    }
    const other =
      comparison.left === typeOf
        ? comparison.right
        : comparison.right === typeOf
          ? comparison.left
          : null;
    return other &&
      ts.isStringLiteralLike(tsUnwrapExpression(other)) &&
      tsUnwrapExpression(other).text === "function"
      ? comparison
      : null;
  };
  const concreteDataOwnerUse = (expression, environment, expectedSegments) => {
    const use = expressionUseNode(expression);
    const parent = use?.parent;
    if (!parent) return null;
    if (
      (ts.isPropertyAccessExpression(parent) ||
        ts.isElementAccessExpression(parent)) &&
      parent.expression === use
    ) {
      const descendantPaths = globalPaths(parent, environment);
      const exactPrefix = expectedSegments.join(".");
      const concreteDescendant = descendantPaths.some(
        (segments) =>
          segments.length > expectedSegments.length &&
          segments.slice(0, expectedSegments.length).join(".") ===
            exactPrefix &&
          segments
            .slice(expectedSegments.length)
            .every(
              (segment) =>
                /^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(segment) &&
                !DYNAMIC_TABLE_MEMBER.test(segment),
            ),
      );
      if (concreteDescendant) return parent;
    }
    if (ts.isCallExpression(parent) && parent.arguments[0] === use) {
      const callee = tsUnwrapExpression(parent.expression);
      if (
        ts.isPropertyAccessExpression(callee) &&
        ts.isIdentifier(tsUnwrapExpression(callee.expression)) &&
        new Set(["Object", "Reflect"]).has(
          tsUnwrapExpression(callee.expression).text,
        ) &&
        new Set(["defineProperties", "defineProperty"]).has(callee.name.text)
      ) {
        return parent;
      }
    }
    return null;
  };
  const recordReviewedPrefixReadProof = (
    exportName,
    proofKind,
    evidenceNode,
    valueShape,
  ) => {
    const sourceRef = authoredRef(evidenceNode, `public-read:${exportName}`);
    let proofs = reviewedPrefixReadProofs.get(exportName);
    if (!proofs) {
      proofs = new Map();
      reviewedPrefixReadProofs.set(exportName, proofs);
    }
    proofs.set(`${proofKind}\0${sourceRef}`, {
      proofKind,
      sourceRef,
      valueShape,
    });
  };
  const observeReviewedPrefixRead = (expression, environment) => {
    const node = tsUnwrapExpression(expression);
    if (
      !node ||
      (!ts.isIdentifier(node) &&
        !ts.isPropertyAccessExpression(node) &&
        !ts.isElementAccessExpression(node))
    ) {
      return;
    }
    for (const segments of globalPaths(node, environment)) {
      const exportName = segments.join(".");
      const specification =
        REVIEWED_SHARED_RUNTIME_PREFIX_READS.get(exportName);
      if (
        !specification ||
        segments.some((segment) => DYNAMIC_TABLE_MEMBER.test(segment)) ||
        !concretePathBinding(node, environment, segments)
      ) {
        continue;
      }
      if (specification.valueShape === "callable") {
        const guard = callableMembershipGuard(node);
        if (guard) {
          recordReviewedPrefixReadProof(
            exportName,
            "typeof-callable-membership",
            guard,
            "callable",
          );
        }
        continue;
      }
      const ownerUse = concreteDataOwnerUse(node, environment, segments);
      if (ownerUse) {
        recordReviewedPrefixReadProof(
          exportName,
          "concrete-member-owner",
          ownerUse,
          "data",
        );
      }
    }
  };
  const propertyValueShape = (property, environment) => {
    if (ts.isMethodDeclaration(property)) return "callable";
    if (ts.isGetAccessorDeclaration(property)) return "accessor";
    if (ts.isSetAccessorDeclaration(property)) return null;
    if (ts.isPropertyAssignment(property)) {
      return resolvedValueShape(property.initializer, environment);
    }
    if (ts.isShorthandPropertyAssignment(property)) {
      return resolvedValueShape(property.name, environment);
    }
    return null;
  };
  const descriptorValueShape = (descriptor, environment, sourcePath) => {
    const node = tsUnwrapExpression(descriptor);
    if (!node || !ts.isObjectLiteralExpression(node)) return null;
    let accessor = false;
    const values = [];
    for (const property of node.properties) {
      if (ts.isSpreadAssignment(property)) return null;
      const names = propertyNames(property.name, environment, sourcePath);
      if (names.includes("get")) {
        if (
          ts.isMethodDeclaration(property) ||
          ts.isGetAccessorDeclaration(property) ||
          (ts.isPropertyAssignment(property) &&
            resolvedValueShape(property.initializer, environment) ===
              "callable")
        ) {
          accessor = true;
        } else {
          return null;
        }
      }
      if (names.includes("value") && ts.isPropertyAssignment(property)) {
        values.push(resolvedValueShape(property.initializer, environment));
      }
    }
    if (accessor && values.length > 0) return null;
    if (accessor) return "accessor";
    if (values.length === 0 || values.some((shape) => !shape)) return null;
    const shapes = new Set(values);
    return shapes.size === 1 ? [...shapes][0] : null;
  };

  const classTargets = (expression) => {
    const node = tsUnwrapExpression(expression);
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      return [{ declaration: node, mode: "constructor" }];
    }
    if (ts.isNewExpression(node)) {
      const symbol = expressionSymbol(node.expression, new Map());
      return (symbol?.declarations ?? [])
        .filter(
          (declaration) =>
            ts.isClassDeclaration(declaration) ||
            ts.isClassExpression(declaration),
        )
        .map((declaration) => ({ declaration, mode: "instance" }));
    }
    if (ts.isIdentifier(node) || ts.isPropertyAccessExpression(node)) {
      const symbol = expressionSymbol(node, new Map());
      return (symbol?.declarations ?? [])
        .filter(
          (declaration) =>
            ts.isClassDeclaration(declaration) ||
            ts.isClassExpression(declaration),
        )
        .map((declaration) => ({ declaration, mode: "constructor" }));
    }
    return [];
  };

  const collectObjectMembers = (
    object,
    environment,
    baseSegments,
    installRefs,
    seenObjects,
  ) => {
    const node = tsUnwrapExpression(object);
    if (!ts.isObjectLiteralExpression(node)) return;
    const identity = declarationIdentity(node);
    if (seenObjects.has(identity)) return;
    seenObjects.add(identity);
    const sourcePath = relativeSourcePath(node);
    for (const property of node.properties) {
      if (ts.isSpreadAssignment(property)) {
        const spreads = resolveValueExpressions(
          property.expression,
          environment,
        ).filter((resolved) =>
          ts.isObjectLiteralExpression(tsUnwrapExpression(resolved.node)),
        );
        if (spreads.length === 0) {
          throw new Error(
            `${sourcePath}: opaque spread in installed global object ${baseSegments.join(".")}`,
          );
        }
        for (const spread of spreads) {
          collectObjectMembers(
            spread.node,
            spread.environment,
            baseSegments,
            installRefs,
            seenObjects,
          );
        }
        continue;
      }
      if (tsHasNonPublicModifier(property)) continue;
      const names = propertyNames(property.name, environment, sourcePath);
      if (names.length === 0) {
        throw new Error(
          `${sourcePath}: unresolved computed member in installed global object ${baseSegments.join(".")}`,
        );
      }
      for (const name of names) {
        const segments = [...baseSegments, name];
        const memberKind = ts.isMethodDeclaration(property)
          ? "object-method"
          : ts.isGetAccessorDeclaration(property) ||
              ts.isSetAccessorDeclaration(property)
            ? "object-accessor"
            : "object-property";
        const refs = [
          ...installRefs,
          sourceSymbol(sourcePath, `${enclosingName(property)}.${name}`),
        ];
        addPathFacts(
          segments,
          refs,
          [memberKind],
          undefined,
          propertyValueShape(property, environment),
        );
        if (ts.isPropertyAssignment(property)) {
          for (const resolved of resolveValueExpressions(
            property.initializer,
            environment,
          )) {
            collectObjectMembers(
              resolved.node,
              resolved.environment,
              segments,
              refs,
              seenObjects,
            );
          }
        }
      }
    }
  };

  const collectClassMembers = (
    declaration,
    mode,
    baseSegments,
    installRefs,
    seenClasses = new Set(),
    inherited = false,
  ) => {
    const classIdentity = `${declarationIdentity(declaration)}:${mode}`;
    if (seenClasses.has(classIdentity)) return;
    const nextSeen = new Set(seenClasses).add(classIdentity);
    const sourcePath = relativeSourcePath(declaration);
    const className = declaration.name?.text ?? "<anonymous-class>";
    const classSymbol = declaration.name
      ? symbolAt(declaration.name)
      : symbolAt(declaration);
    for (const member of declaration.members) {
      if (ts.isConstructorDeclaration(member) || tsHasNonPublicModifier(member))
        continue;
      const isStatic = Boolean(
        member.modifiers?.some(
          (modifier) => modifier.kind === ts.SyntaxKind.StaticKeyword,
        ),
      );
      if (mode === "instance" && isStatic) continue;
      const name = tsMemberName(member.name, sourcePath);
      if (name === null) continue;
      const memberKind = isStatic
        ? "static"
        : ts.isMethodDeclaration(member)
          ? "prototype-method"
          : ts.isGetAccessorDeclaration(member) ||
              ts.isSetAccessorDeclaration(member)
            ? "prototype-accessor"
            : "instance-property";
      const ref = sourceSymbol(
        sourcePath,
        isStatic ? `${className}.${name}` : `${className}.prototype.${name}`,
      );
      addPathFacts(
        [...baseSegments, name],
        [...installRefs, ref],
        inherited ? [memberKind, "inherited"] : [memberKind],
        undefined,
        ts.isMethodDeclaration(member)
          ? "callable"
          : ts.isGetAccessorDeclaration(member)
            ? "accessor"
            : ts.isSetAccessorDeclaration(member)
              ? undefined
              : member.initializer
                ? resolvedValueShape(member.initializer, new Map())
                : directValueShape(member),
      );
    }
    for (const augmentation of classAugmentations.get(classSymbol) ?? []) {
      if (mode === "instance" && augmentation.memberKind === "static") continue;
      addPathFacts(
        [...baseSegments, augmentation.name],
        [
          ...installRefs,
          sourceSymbol(
            augmentation.sourcePath,
            augmentation.memberKind === "prototype"
              ? `${className}.prototype.${augmentation.name}`
              : `${className}.${augmentation.name}`,
          ),
        ],
        [
          augmentation.memberKind === "prototype"
            ? "prototype-assignment"
            : "static-assignment",
          ...(inherited ? ["inherited"] : []),
        ],
        undefined,
        resolvedValueShape(augmentation.value, new Map()),
      );
    }

    const extendsTypes = (declaration.heritageClauses ?? [])
      .filter((clause) => clause.token === ts.SyntaxKind.ExtendsKeyword)
      .flatMap((clause) => [...clause.types]);
    for (const heritage of extendsTypes) {
      const expression = tsUnwrapExpression(heritage.expression);
      const symbol =
        expressionSymbol(expression, new Map()) ?? symbolAt(expression);
      const bases = (symbol?.declarations ?? []).filter(
        (candidate) =>
          (ts.isClassDeclaration(candidate) ||
            ts.isClassExpression(candidate)) &&
          isPathInside(sourceRoot, candidate.getSourceFile().fileName) &&
          !GENERATED_AUTHORITY_PATH.test(
            posixPath(candidate.getSourceFile().fileName),
          ),
      );
      if (bases.length > 0) {
        for (const base of bases) {
          collectClassMembers(
            base,
            mode,
            baseSegments,
            installRefs,
            nextSeen,
            true,
          );
        }
        continue;
      }
      const baseText = expression.getText().replace(/\s+/gu, " ");
      const slug = baseText
        .replace(/([a-z0-9])([A-Z])/gu, "$1-$2")
        .replace(/[^A-Za-z0-9]+/gu, "-")
        .replace(/^-|-$/gu, "")
        .toLowerCase();
      const digest = sha256Hex(
        `${sourcePath}\0${className}\0${mode}\0${baseText}`,
      ).slice(0, 10);
      const sentinel = `[[dynamic-table:inherited-${slug || "external"}-${digest}-properties]]`;
      addPathFacts(
        [...baseSegments, sentinel],
        [
          ...installRefs,
          sourceSymbol(sourcePath, `${className}:extends:${baseText}`),
        ],
        ["dynamic-table", "inherited-shape"],
        "inherited-shape",
      );
    }
  };

  const typeClassTargets = (expression) => {
    const type = checker.getTypeAtLocation(expression);
    if (
      (type.flags &
        (ts.TypeFlags.Any | ts.TypeFlags.Unknown | ts.TypeFlags.Never)) !==
      0
    ) {
      return [];
    }
    const candidates = [
      type,
      ...(type.isUnionOrIntersection() ? type.types : []),
    ];
    const targets = [];
    for (const candidate of candidates) {
      const symbol = candidate.getSymbol?.() ?? candidate.aliasSymbol;
      for (const declaration of symbol?.declarations ?? []) {
        if (
          ts.isClassDeclaration(declaration) ||
          ts.isClassExpression(declaration)
        ) {
          targets.push({ declaration, mode: "instance" });
        }
      }
    }
    return targets;
  };

  const collectRegisteredValueMembers = (
    value,
    environment,
    baseSegments,
    installRefs,
  ) => {
    const resolvedValues = resolveValueExpressions(value, environment);
    if (resolvedValues.length === 0) {
      throw new Error(
        `${relativeSourcePath(value)}: unresolved installed binding for ${baseSegments.join(".")}: ${value.getText().replace(/\s+/gu, " ")}`,
      );
    }
    let resolvedShape = false;
    for (const resolved of resolvedValues) {
      const node = tsUnwrapExpression(resolved.node);
      if (
        GENERATED_AUTHORITY_PATH.test(posixPath(node.getSourceFile().fileName))
      ) {
        throw new Error(
          `${relativeSourcePath(node)}: generated or vendored output cannot be inventory authority for ${baseSegments.join(".")}`,
        );
      }
      const targets = classTargets(node);
      const resolvedTargets =
        targets.length > 0 ? targets : typeClassTargets(node);
      if (resolvedTargets.length > 0) {
        resolvedShape = true;
        for (const target of resolvedTargets) {
          collectClassMembers(
            target.declaration,
            target.mode,
            baseSegments,
            installRefs,
          );
        }
        continue;
      }
      if (ts.isObjectLiteralExpression(node)) {
        resolvedShape = true;
        collectObjectMembers(
          node,
          resolved.environment,
          baseSegments,
          installRefs,
          new Set(),
        );
        continue;
      }
      if (
        ts.isFunctionDeclaration(node) ||
        ts.isFunctionExpression(node) ||
        ts.isArrowFunction(node) ||
        ts.isMethodDeclaration(node) ||
        ts.isGetAccessorDeclaration(node) ||
        ts.isSetAccessorDeclaration(node)
      ) {
        resolvedShape = true;
        const symbol = node.name
          ? symbolAt(node.name)
          : expressionSymbol(value, environment);
        for (const augmentation of classAugmentations.get(symbol) ?? []) {
          addPathFacts(
            [...baseSegments, augmentation.name],
            [
              ...installRefs,
              sourceSymbol(
                augmentation.sourcePath,
                `${enclosingName(node)}.${augmentation.name}`,
              ),
            ],
            ["function-property"],
            undefined,
            resolvedValueShape(augmentation.value, new Map()),
          );
        }
        continue;
      }
      if (globalPaths(node, resolved.environment).length > 0) {
        resolvedShape = true;
        continue;
      }
      if (
        ts.isStringLiteralLike(node) ||
        ts.isNumericLiteral(node) ||
        node.kind === ts.SyntaxKind.TrueKeyword ||
        node.kind === ts.SyntaxKind.FalseKeyword ||
        node.kind === ts.SyntaxKind.NullKeyword ||
        (ts.isIdentifier(node) &&
          new Set(["undefined", "NaN", "Infinity"]).has(node.text))
      ) {
        resolvedShape = true;
        continue;
      }
      // Calls and property reads can intentionally install a scalar/function
      // whose declaration shape is not statically enumerable. Their root is
      // still exact; only object/constructor bindings are required to resolve.
      if (ts.isCallExpression(node) || ts.isPropertyAccessExpression(node)) {
        resolvedShape = true;
      }
    }
    if (!resolvedShape) {
      throw new Error(
        `${relativeSourcePath(value)}: unresolved installed binding shape for ${baseSegments.join(".")}: ${value.getText().replace(/\s+/gu, " ")}`,
      );
    }
  };

  const descriptorValues = (descriptor, environment, sourcePath) => {
    const node = tsUnwrapExpression(descriptor);
    if (!node || !ts.isObjectLiteralExpression(node)) return [];
    const values = [];
    for (const property of node.properties) {
      if (ts.isSpreadAssignment(property)) {
        throw new Error(
          `${sourcePath}: opaque spread in global property descriptor`,
        );
      }
      const names = propertyNames(property.name, environment, sourcePath);
      if (names.includes("value") && ts.isPropertyAssignment(property)) {
        values.push(property.initializer);
      }
      if (
        names.includes("get") &&
        (ts.isMethodDeclaration(property) ||
          ts.isGetAccessorDeclaration(property))
      ) {
        values.push(...tsReturnExpressions(property));
      }
      if (
        names.includes("get") &&
        ts.isPropertyAssignment(property) &&
        (ts.isArrowFunction(tsUnwrapExpression(property.initializer)) ||
          ts.isFunctionExpression(tsUnwrapExpression(property.initializer)))
      ) {
        values.push(
          ...tsReturnExpressions(tsUnwrapExpression(property.initializer)),
        );
      }
    }
    return values;
  };

  const functionQueue = [];
  const visitedFunctions = new Set();
  const environmentFingerprint = (declaration, environment) =>
    declaration.parameters
      .map((parameter) => {
        if (!ts.isIdentifier(parameter.name)) return "<pattern>";
        const binding = bindingFor(symbolAt(parameter.name), environment);
        if (!binding) return `${parameter.name.text}=<unbound>`;
        const locations = binding.expression
          ? [
              `${relativeSourcePath(binding.expression)}:${binding.expression.pos}`,
            ]
          : [];
        return `${parameter.name.text}=g:${(binding.globalPaths ?? []).map((value) => value.join(".")).join("|")};s:${[
          ...(binding.strings ?? []),
        ].join("|")};e:${locations.join("|")}`;
      })
      .join(";");
  const enqueueFunction = (declaration, environment) => {
    if (!declaration?.body) return;
    if (!isPathInside(sourceRoot, declaration.getSourceFile().fileName)) return;
    const key = `${declarationIdentity(declaration)}\0${environmentFingerprint(declaration, environment)}`;
    if (visitedFunctions.has(key)) return;
    visitedFunctions.add(key);
    functionQueue.push({ declaration, environment });
  };

  const assignmentBaseAndNames = (left, environment) => {
    const node = tsUnwrapExpression(left);
    if (ts.isPropertyAccessExpression(node)) {
      return {
        bases: globalPaths(node.expression, environment),
        names: [node.name.text],
      };
    }
    if (ts.isElementAccessExpression(node)) {
      const bases = globalPaths(node.expression, environment);
      let names = registrationNames(node.argumentExpression, environment);
      if (names.length === 0 && ts.isIdentifier(node.argumentExpression)) {
        const binding = bindingFor(
          symbolAt(node.argumentExpression),
          environment,
        );
        names = [...(binding?.strings ?? [])];
      }
      return { bases, names };
    }
    return { bases: [], names: [] };
  };

  const recordRegistration = (
    segments,
    value,
    environment,
    node,
    memberKinds = ["registration"],
    valueShapeOverride,
  ) => {
    const ref = authoredRef(node, `globals:${segments.join(".")}`);
    const dynamicTable = DYNAMIC_TABLE_MEMBER.test(segments.at(-1) ?? "");
    addPathFacts(
      segments,
      [ref],
      dynamicTable ? [...memberKinds, "dynamic-table"] : memberKinds,
      dynamicTable ? "host-object-overlay" : undefined,
      valueShapeOverride ??
        (value ? resolvedValueShape(value, environment) : undefined),
    );
    if (dynamicTable) return;
    if (value) {
      const valueNode = tsUnwrapExpression(value);
      if (
        ts.isNewExpression(valueNode) &&
        ts.isIdentifier(tsUnwrapExpression(valueNode.expression)) &&
        tsUnwrapExpression(valueNode.expression).text === "Proxy"
      ) {
        const proxiedPaths = globalPaths(valueNode.arguments?.[0], environment);
        if (proxiedPaths.length > 0) {
          const tableName = `[[dynamic-table:host-${segments
            .join("-")
            .replace(/[^a-z0-9-]/giu, "-")
            .toLowerCase()}-properties]]`;
          addPathFacts(
            [...segments, tableName],
            [ref],
            ["dynamic-table", "proxy-overlay"],
            "host-object-overlay",
          );
          return;
        }
      }
      const symbol = expressionSymbol(valueNode, environment);
      const moduleScopedSymbol = (symbol?.declarations ?? []).some(
        (declaration) => {
          let current = declaration.parent;
          while (current && !ts.isSourceFile(current)) {
            if (ts.isFunctionLike(current)) return false;
            current = current.parent;
          }
          return Boolean(current);
        },
      );
      if (
        symbol &&
        moduleScopedSymbol &&
        (ts.isIdentifier(valueNode) || ts.isClassExpression(valueNode))
      ) {
        let paths = installedSymbolPaths.get(symbol);
        if (!paths) {
          paths = [];
          installedSymbolPaths.set(symbol, paths);
        }
        paths.push(segments);
      }
      const aliases = globalPaths(
        valueNode,
        environment,
        new Set(),
        false,
      ).filter((candidate) => candidate.length > 0);
      for (const alias of aliases) {
        let destinations = globalAliases.get(alias.join("."));
        if (!destinations) {
          destinations = [];
          globalAliases.set(alias.join("."), destinations);
        }
        destinations.push({ ref, segments });
      }
      collectRegisteredValueMembers(value, environment, segments, [ref]);
    }
    if (
      segments.length === 1 &&
      segments[0] === "__exactHostNavigator" &&
      value &&
      globalPaths(value, environment).some(
        (candidate) => candidate.join(".") === "navigator",
      )
    ) {
      addPathFacts(
        ["__exactHostNavigator", "[[dynamic-table:host-navigator-properties]]"],
        [ref],
        ["dynamic-table"],
        "host-object-overlay",
      );
    }
  };

  let processNode;
  const processObjectDefineCall = (call, environment) => {
    const callee = tsUnwrapExpression(call.expression);
    const sourcePath = relativeSourcePath(call);
    const method =
      ts.isPropertyAccessExpression(callee) &&
          ts.isIdentifier(callee.expression) &&
          callee.expression.text === "Object"
        ? callee.name.text
        : null;
    if (!method) return false;
    if (!new Set(["defineProperty", "defineProperties", "assign"]).has(method))
      return false;
    const target = call.arguments[0];
    const bases = target ? globalPaths(target, environment) : [];
    if (bases.length === 0) return false;

    if (method === "defineProperty") {
      const names = registrationNames(call.arguments[1], environment);
      if (names.length === 0) {
        throw new Error(
          `${sourcePath}: unresolved computed global property registration ${call.arguments[1]?.getText() ?? "<missing>"}`,
        );
      }
      const descriptor = call.arguments[2];
      const values = descriptor
        ? descriptorValues(descriptor, environment, sourcePath)
        : [];
      for (const base of bases) {
        for (const name of names) {
          const segments = [...base, name];
          recordRegistration(
            segments,
            values[0] ?? null,
            environment,
            call,
            ["define-property"],
            descriptorValueShape(descriptor, environment, sourcePath),
          );
          for (const value of values.slice(1)) {
            collectRegisteredValueMembers(value, environment, segments, [
              authoredRef(call, `globals:${segments.join(".")}`),
            ]);
          }
        }
      }
      const descriptorNode = tsUnwrapExpression(descriptor);
      if (descriptorNode && ts.isObjectLiteralExpression(descriptorNode)) {
        for (const property of descriptorNode.properties) {
          const propertyNamesFound = propertyNames(
            property.name,
            environment,
            sourcePath,
          );
          if (
            propertyNamesFound.includes("get") &&
            (ts.isMethodDeclaration(property) ||
              ts.isGetAccessorDeclaration(property))
          ) {
            enqueueFunction(property, environment);
          }
          if (
            propertyNamesFound.includes("get") &&
            ts.isPropertyAssignment(property) &&
            (ts.isArrowFunction(tsUnwrapExpression(property.initializer)) ||
              ts.isFunctionExpression(tsUnwrapExpression(property.initializer)))
          ) {
            enqueueFunction(
              tsUnwrapExpression(property.initializer),
              environment,
            );
          }
        }
      }
      return true;
    }

    for (const object of call.arguments.slice(1)) {
      const literals = resolveValueExpressions(object, environment)
        .map((resolved) => ({
          environment: resolved.environment,
          node: tsUnwrapExpression(resolved.node),
        }))
        .filter((resolved) => ts.isObjectLiteralExpression(resolved.node));
      if (literals.length === 0) {
        throw new Error(
          `${sourcePath}: opaque ${method} source in global registration`,
        );
      }
      for (const resolvedLiteral of literals) {
        for (const property of resolvedLiteral.node.properties) {
          if (ts.isSpreadAssignment(property)) {
            throw new Error(
              `${sourcePath}: opaque spread in global ${method} registration`,
            );
          }
          const names = propertyNames(
            property.name,
            resolvedLiteral.environment,
            sourcePath,
          );
          if (names.length === 0) {
            throw new Error(
              `${sourcePath}: unresolved computed global ${method} registration`,
            );
          }
          const descriptor = ts.isPropertyAssignment(property)
            ? property.initializer
            : ts.isShorthandPropertyAssignment(property)
              ? property.name
              : property;
          const values =
            method === "defineProperties"
              ? descriptorValues(
                  descriptor,
                  resolvedLiteral.environment,
                  sourcePath,
                )
              : [descriptor];
          for (const base of bases) {
            for (const name of names) {
              const segments = [...base, name];
              recordRegistration(
                segments,
                values[0] ?? null,
                resolvedLiteral.environment,
                property,
                [
                  method === "defineProperties"
                    ? "define-properties"
                    : "object-assign",
                ],
                method === "defineProperties"
                  ? descriptorValueShape(
                      descriptor,
                      resolvedLiteral.environment,
                      sourcePath,
                    )
                  : propertyValueShape(property, resolvedLiteral.environment),
              );
              for (const value of values.slice(1)) {
                collectRegisteredValueMembers(
                  value,
                  resolvedLiteral.environment,
                  segments,
                  [authoredRef(property, `globals:${segments.join(".")}`)],
                );
              }
            }
          }
        }
      }
    }
    return true;
  };

  processNode = (node, environment) => {
    if (!node) return;
    observeReviewedPrefixRead(node, environment);
    if (
      ts.isFunctionLike(node) ||
      ts.isClassDeclaration(node) ||
      ts.isClassExpression(node)
    )
      return;

    if (ts.isForOfStatement(node)) {
      processNode(node.expression, environment);
      const values = uniqueSorted([
        ...staticStrings(node.expression, environment),
        ...dynamicTableValues(node.expression, environment),
      ]);
      const loopEnvironment = new Map(environment);
      if (
        ts.isVariableDeclarationList(node.initializer) &&
        node.initializer.declarations.length === 1 &&
        ts.isIdentifier(node.initializer.declarations[0].name)
      ) {
        const symbol = symbolAt(node.initializer.declarations[0].name);
        if (symbol) loopEnvironment.set(symbol, { strings: new Set(values) });
      } else if (
        ts.isVariableDeclarationList(node.initializer) &&
        node.initializer.declarations.length === 1 &&
        ts.isArrayBindingPattern(node.initializer.declarations[0].name)
      ) {
        const first = node.initializer.declarations[0].name.elements[0];
        if (
          first &&
          ts.isBindingElement(first) &&
          ts.isIdentifier(first.name)
        ) {
          const symbol = symbolAt(first.name);
          if (symbol) loopEnvironment.set(symbol, { strings: new Set(values) });
        }
      }
      processNode(node.statement, loopEnvironment);
      return;
    }

    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      (ts.isPropertyAccessExpression(tsUnwrapExpression(node.left)) ||
        ts.isElementAccessExpression(tsUnwrapExpression(node.left)))
    ) {
      const { bases, names } = assignmentBaseAndNames(node.left, environment);
      if (bases.length > 0 && names.length === 0) {
        throw new Error(
          `${relativeSourcePath(node)}: unresolved computed global property registration ${node.left.getText().replace(/\s+/gu, " ")}`,
        );
      }
      for (const base of bases) {
        for (const name of names) {
          recordRegistration([...base, name], node.right, environment, node, [
            "assignment",
          ]);
        }
      }
    }

    if (ts.isCallExpression(node)) {
      processObjectDefineCall(node, environment);
      for (const declaration of callableDeclarations(
        node.expression,
        environment,
      )) {
        enqueueFunction(
          declaration,
          invocationEnvironment(declaration, node, environment),
        );
      }
    }

    ts.forEachChild(node, (child) => processNode(child, environment));
  };

  for (const source of authoredSources) {
    for (const statement of source.statements)
      processNode(statement, new Map());
  }
  while (functionQueue.length > 0) {
    const { declaration, environment } = functionQueue.shift();
    processNode(declaration.body, environment);
  }

  // Propagate authored namespace aliases (notably Exact -> Bun) after every
  // nested member has been observed. The global object aliases window/self are
  // intentionally roots only: recursively copying the entire inventory would
  // manufacture duplicate spellings rather than distinct APIs.
  let aliasesChanged = true;
  while (aliasesChanged) {
    aliasesChanged = false;
    for (const [sourceName, destinations] of globalAliases) {
      for (const [exportName, fact] of [...facts]) {
        if (
          exportName !== sourceName &&
          !exportName.startsWith(`${sourceName}.`)
        )
          continue;
        const suffix = exportName.slice(sourceName.length).replace(/^\./u, "");
        for (const destination of destinations) {
          if (destination.segments.length !== 1) continue;
          const aliasName = [destination.segments[0], suffix]
            .filter(Boolean)
            .join(".");
          if (facts.has(aliasName)) continue;
          addFact(
            aliasName.split("."),
            [...fact.refs, destination.ref],
            [...fact.memberKinds, "namespace-alias"],
            undefined,
            fact.valueShapes.size === 1 ? [...fact.valueShapes][0] : undefined,
          );
          aliasesChanged = true;
        }
      }
    }
  }

  const rows = [];
  for (const fact of facts.values()) {
    const sourceRefs = uniqueSorted(fact.refs);
    const branch = makeInstallationBranch("shared-runtime", "all", sourceRefs);
    const name = globalSurfaceName(fact.exportName);
    const metadata = {
      branches: [branch],
      exportName: fact.exportName,
      globalName: fact.globalName,
      installationBranches: [branch],
      memberKinds: uniqueSorted(fact.memberKinds),
      memberName: fact.memberName,
      moduleSpecifiers: [],
      sourceKey: "shared_runtime",
      surfaceType: "global-api",
    };
    const accessPath = fact.exportName.split(".");
    const reviewedPrefixSpecification =
      REVIEWED_SHARED_RUNTIME_PREFIX_READS.get(fact.exportName);
    const reviewedPrefixProofs = [
      ...(reviewedPrefixReadProofs.get(fact.exportName)?.values() ?? []),
    ];
    const reviewedPrefixContract =
      reviewedPrefixSpecification &&
      fact.memberKinds.size === 1 &&
      fact.memberKinds.has("namespace-prefix") &&
      accessPath.every(
        (segment) =>
          /^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(segment) &&
          !DYNAMIC_TABLE_MEMBER.test(segment),
      ) &&
      reviewedPrefixProofs.length > 0 &&
      reviewedPrefixProofs.every(
        (proof) => proof.valueShape === reviewedPrefixSpecification.valueShape,
      )
        ? {
            activationVariants: [
              ...reviewedPrefixSpecification.activationVariants,
            ],
            path: fact.exportName,
            presenceVariants: ["absent", "present"],
            proofKinds: uniqueSorted(
              reviewedPrefixProofs.map((proof) => proof.proofKind),
            ),
            schema: PUBLIC_READ_ACCESS_SOURCE_CONTRACT_SCHEMA,
            sourceRefs: uniqueSorted(
              reviewedPrefixProofs.map((proof) => proof.sourceRef),
            ),
            terminalMember: accessPath.at(-1),
            valueShape: reviewedPrefixSpecification.valueShape,
          }
        : null;
    const sourceProvesEveryAccessSegment = accessPath.every(
      (segment, index) => {
        if (DYNAMIC_TABLE_MEMBER.test(segment)) return false;
        const prefix = facts.get(accessPath.slice(0, index + 1).join("."));
        return (
          prefix &&
          [...prefix.memberKinds].some(
            (kind) =>
              !new Set([
                "dynamic-table",
                "inherited-shape",
                "namespace-prefix",
              ]).has(kind),
          )
        );
      },
    );
    if (sourceProvesEveryAccessSegment)
      metadata.publicReadAccessSourceProven = true;
    if (reviewedPrefixContract) {
      metadata.publicReadAccessSourceContract = reviewedPrefixContract;
      metadata.publicReadAccessSourceProven = true;
      metadata.valueShape = reviewedPrefixContract.valueShape;
    }
    if (fact.semanticRoles.size > 0)
      metadata.semanticRoles = uniqueSorted(fact.semanticRoles);
    if (fact.valueShapes.size === 1)
      metadata.valueShape = [...fact.valueShapes][0];
    rows.push(makeSurface("native-op", name, sourceRefs, { metadata }));
  }
  if (principalEnvironmentOverlay) {
    const overlaySourceRefs = principalEnvironmentOverlay.sourceRefs;
    const overlayBranch = makeInstallationBranch(
      "shared-runtime",
      "all",
      overlaySourceRefs,
    );
    rows.push(
      makeSurface(
        "native-op",
        PRINCIPAL_ENVIRONMENT_OVERLAY_SURFACE_NAME,
        overlaySourceRefs,
        {
          metadata: {
            branches: [overlayBranch],
            exportName: `process.env.${PRINCIPAL_ENVIRONMENT_OVERLAY_DYNAMIC_MEMBER}`,
            globalName: "process",
            installationBranches: [overlayBranch],
            memberKinds: ["dynamic-table"],
            memberName: `env.${PRINCIPAL_ENVIRONMENT_OVERLAY_DYNAMIC_MEMBER}`,
            moduleSpecifiers: [],
            principalEnvironmentOverlaySourceContract:
              principalEnvironmentOverlay,
            semanticRoles: [
              "principal-environment-overlay",
              "runtime-property-overlay",
            ],
            sourceKey: "shared_runtime",
            surfaceType: "global-api",
          },
        },
      ),
    );
  }
  const sortedRows = sortSurfaces(rows);
  const inheritedReviewRows = sortedRows
    .filter(
      (row) =>
        row.metadata?.memberKinds?.includes("inherited") ||
        row.metadata?.memberKinds?.includes("inherited-shape"),
    )
    .map((row) => ({
      memberKinds: row.metadata.memberKinds,
      name: row.name,
      sourceRefs: row.sourceRefs,
    }));
  if (inheritedReviewRows.length > 0) {
    const inheritedShapeReviewId = `sha256-${sha256Hex(JSON.stringify(inheritedReviewRows))}`;
    for (const row of sortedRows) {
      if (
        !row.metadata?.memberKinds?.includes("inherited") &&
        !row.metadata?.memberKinds?.includes("inherited-shape")
      ) {
        continue;
      }
      row.metadata.inheritedShape = true;
      row.metadata.inheritedShapeReviewId = inheritedShapeReviewId;
      row.metadata.semanticRoles = uniqueSorted([
        ...(row.metadata.semanticRoles ?? []),
        "inherited-global-shape",
      ]);
    }
  }
  return sortedRows;
}

function cppStatementRanges(tokens) {
  const ranges = [];
  let start = 0;
  let parenDepth = 0;
  let braceDepth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index].type !== "punctuation") continue;
    const value = tokens[index].value;
    if (value === "(") parenDepth += 1;
    if (value === ")") parenDepth -= 1;
    if (value === "{") braceDepth += 1;
    if (value === "}") braceDepth -= 1;
    if (value === ";" && parenDepth === 0) {
      ranges.push([start, index]);
      start = index + 1;
    }
  }
  if (start < tokens.length) ranges.push([start, tokens.length]);
  return ranges;
}

function cppAssignmentVariable(tokens) {
  const equals = tokens.findIndex((token) => token.value === "=");
  if (equals === -1) return null;
  for (let index = equals - 1; index >= 0; index -= 1) {
    if (tokens[index].type !== "identifier") continue;
    if (
      new Set(["const", "static", "char", "auto", "string"]).has(
        tokens[index].value,
      )
    )
      continue;
    return tokens[index].value;
  }
  return null;
}

/**
 * Scan only C++ string constants that structurally flow into
 * evaluateJavaScript. Merely containing a JavaScript-looking raw string is not
 * evidence that the runtime installs it.
 */
export function scanEvaluatedCppGlobalScripts(
  text,
  sourcePath = "<native-source>",
) {
  const tokens = lexCpp(text, sourcePath);
  const statementRecords = cppStatementRanges(tokens).map(([start, end]) => ({
    end,
    start,
    tokens: tokens.slice(start, end + 1),
  }));
  const statements = statementRecords.map((record) => record.tokens);
  const scripts = new Map();
  for (const statement of statements) {
    const variable = cppAssignmentVariable(statement);
    if (!variable) continue;
    const equals = statement.findIndex((token) => token.value === "=");
    const appends = equals > 0 && statement[equals - 1]?.value === "+";
    const values = statement
      .filter((token) => token.type === "string")
      .map((token) => token.value);
    if (values.length === 0) continue;
    const script = values.join("");
    // Ignore ordinary labels/URLs cheaply. Evaluated scripts always contain at
    // least one JavaScript statement delimiter or function/object expression.
    if (!/[;{}()]/u.test(script)) continue;
    scripts.set(
      variable,
      appends && scripts.has(variable)
        ? `${scripts.get(variable)}${script}`
        : script,
    );
  }

  const evaluated = new Map();
  const nearestSources = (name, beforeIndex, seen = new Set()) => {
    const key = `${name}\0${beforeIndex}`;
    if (seen.has(key)) return new Set();
    seen.add(key);
    const direct = new Set(scripts.has(name) ? [name] : []);
    const record = [...statementRecords]
      .reverse()
      .find(
        (candidate) =>
          candidate.start < beforeIndex &&
          cppAssignmentVariable(candidate.tokens) === name,
      );
    if (!record) return direct;
    const equals = record.tokens.findIndex((token) => token.value === "=");
    for (const token of record.tokens.slice(equals + 1)) {
      if (token.type !== "identifier" || token.value === name) continue;
      for (const source of nearestSources(token.value, record.start, seen))
        direct.add(source);
    }
    return direct;
  };
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].type !== "identifier" ||
      tokens[index].value !== "evaluateJavaScript"
    )
      continue;
    const open =
      tokens
        .slice(index + 1)
        .findIndex(
          (token) => token.type === "punctuation" && token.value === "(",
        ) +
      index +
      1;
    if (open <= index) continue;
    const close = matchingToken(tokens, open, "(", ")");
    if (close === -1)
      throw new Error(
        `${sourcePath}: evaluateJavaScript call has no closing parenthesis`,
      );
    let comma = close;
    let depth = 0;
    for (let cursor = open + 1; cursor < close; cursor += 1) {
      if (tokens[cursor].type !== "punctuation") continue;
      if (tokens[cursor].value === "(" || tokens[cursor].value === "<")
        depth += 1;
      if (tokens[cursor].value === ")" || tokens[cursor].value === ">")
        depth -= 1;
      if (tokens[cursor].value === "," && depth === 0) {
        comma = cursor;
        break;
      }
    }
    const firstArgument = tokens.slice(open + 1, comma);
    const sources = new Set();
    for (const token of firstArgument) {
      if (token.type !== "identifier") continue;
      for (const source of nearestSources(token.value, index))
        sources.add(source);
    }
    if (sources.size === 0) continue;
    const sourceUrl = tokens
      .slice(comma + 1, close)
      .find((token) => token.type === "string")?.value;
    for (const source of sources) {
      let urls = evaluated.get(source);
      if (!urls) {
        urls = new Set();
        evaluated.set(source, urls);
      }
      if (sourceUrl) urls.add(sourceUrl);
    }
  }

  const rows = [];
  for (const [variable, urls] of evaluated) {
    const script = scripts.get(variable);
    if (script === undefined) continue;
    const scanned = scanStaticGlobalApiSurfaces(
      script,
      `${sourcePath}#embedded:${variable}`,
    );
    const windowsShim = /^windows[A-Z]/u.test(variable);
    const route = windowsShim
      ? "windows-native-shim"
      : "evaluated-native-script";
    const targetVariant = windowsShim
      ? "windows"
      : sourcePath.includes("worklet")
        ? "worklet"
        : "default";
    for (const row of scanned) {
      const sourceRefs = [
        sourceSymbol(
          sourcePath,
          `embedded:${variable}:${row.metadata.exportName}`,
        ),
      ];
      const branch = makeInstallationBranch(route, targetVariant, sourceRefs);
      rows.push({
        ...row,
        sourceRefs,
        metadata: {
          ...row.metadata,
          branches: [branch],
          evaluatedScript: variable,
          installationBranches: [branch],
          sourceKey: windowsShim
            ? "windows_native_shim"
            : "evaluated_native_script",
          sourceUrls: uniqueSorted(urls),
        },
      });
    }
  }
  return mergeSurfaceEvidence(
    rows,
    `${sourcePath} evaluated JavaScript global inventory`,
  );
}

function cppCallArguments(tokens, open, close) {
  const argumentsList = [];
  let start = open + 1;
  let parenDepth = 0;
  let braceDepth = 0;
  let angleDepth = 0;
  for (let index = open + 1; index < close; index += 1) {
    const value = tokens[index].value;
    if (value === "(" || value === "[") parenDepth += 1;
    if (value === ")" || value === "]") parenDepth -= 1;
    if (value === "{") braceDepth += 1;
    if (value === "}") braceDepth -= 1;
    if (value === "<") angleDepth += 1;
    if (value === ">") angleDepth = Math.max(0, angleDepth - 1);
    if (
      value === "," &&
      parenDepth === 0 &&
      braceDepth === 0 &&
      angleDepth === 0
    ) {
      argumentsList.push(tokens.slice(start, index));
      start = index + 1;
    }
  }
  argumentsList.push(tokens.slice(start, close));
  return argumentsList;
}

function cppLiteralArgument(tokens) {
  const strings = tokens.filter((token) => token.type === "string");
  return strings.length === 1 ? strings[0].value : null;
}

function cppUnsignedIntegerArgument(tokens) {
  const text = tokens.map((token) => token.value).join("");
  if (!/^(?:0|[1-9][0-9]*)$/u.test(text)) return null;
  const value = Number(text);
  return Number.isSafeInteger(value) ? value : null;
}

function cppDirectReturnedCallIdentifier(tokens) {
  const bodyOpen = tokens.findIndex((token) => token.value === "{");
  if (bodyOpen === -1) return null;
  const bodyClose = matchingToken(tokens, bodyOpen, "{", "}");
  if (bodyClose === -1 || bodyClose !== tokens.length - 1) return null;
  const body = tokens.slice(bodyOpen + 1, bodyClose);
  if (
    body.length < 5 ||
    body[0]?.value !== "return" ||
    body[1]?.type !== "identifier" ||
    body[2]?.value !== "("
  ) {
    return null;
  }
  const callClose = matchingToken(body, 2, "(", ")");
  if (
    callClose === -1 ||
    callClose !== body.length - 2 ||
    body.at(-1)?.value !== ";"
  ) {
    return null;
  }
  return {
    identifier: body[1].value,
    start: body[1].start,
  };
}

/**
 * Recover direct `createFromHostFunction` assignments.  This is intentionally
 * narrower than the general JSI inventory: a public probe may call a global
 * only when source proves both the function identity and declared arity.  An
 * object property, factory return, alias, or dynamically named registration
 * stays unprobeable until a separate descriptor is authored.
 */
function cppAssignedHostFunctions(tokens, sourcePath) {
  const functions = new Map();
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index]?.value !== "createFromHostFunction" ||
      tokens[index + 1]?.value !== "("
    ) {
      continue;
    }
    const close = matchingToken(tokens, index + 1, "(", ")");
    if (close === -1) {
      throw new Error(
        `${sourcePath}: createFromHostFunction call has no closing parenthesis`,
      );
    }
    const args = cppCallArguments(tokens, index + 1, close);
    if (args.length < 4) continue;
    const functionName = cppLiteralArgument(args[1]);
    const arity = cppUnsignedIntegerArgument(args[2]);
    if (functionName === null || arity === null) continue;

    let equals = index - 1;
    while (
      equals >= 0 &&
      tokens[equals].value !== "=" &&
      tokens[equals].value !== ";" &&
      tokens[equals].value !== "{" &&
      tokens[equals].value !== "}"
    ) {
      equals -= 1;
    }
    if (equals < 1 || tokens[equals].value !== "=") continue;
    let variable = equals - 1;
    while (variable >= 0 && tokens[variable].type !== "identifier") {
      variable -= 1;
    }
    if (variable < 0) continue;
    const variableName = tokens[variable].value;
    const terminalCall = cppDirectReturnedCallIdentifier(args[3]);
    const descriptor = {
      arity,
      factoryEnd: tokens[close].end,
      functionName,
      terminalHandler: terminalCall?.identifier ?? null,
      terminalHandlerStart: terminalCall?.start ?? null,
    };
    const prior = functions.get(variableName);
    if (prior === null) continue;
    if (
      prior &&
      JSON.stringify({
        arity: prior.arity,
        functionName: prior.functionName,
        terminalHandler: prior.terminalHandler,
      }) !==
        JSON.stringify({
          arity: descriptor.arity,
          functionName: descriptor.functionName,
          terminalHandler: descriptor.terminalHandler,
        })
    ) {
      // Common local names such as `executor` can be reused by independent
      // nested factories. That makes the assignment ambiguous for public
      // invocation purposes, so retain no descriptor rather than guessing.
      functions.set(variableName, null);
      continue;
    }
    functions.set(variableName, descriptor);
  }
  return functions;
}

function cppMovedOrDirectIdentifier(tokens) {
  if (tokens.length === 1 && tokens[0].type === "identifier") {
    return tokens[0].value;
  }
  const move = tokens.findIndex(
    (token, index) =>
      token.value === "move" &&
      tokens[index + 1]?.value === "(" &&
      tokens[index + 2]?.type === "identifier" &&
      tokens[index + 3]?.value === ")",
  );
  return move === -1 ? null : tokens[move + 2].value;
}

function cppHostFunctionValueDescriptor(
  tokens,
  assignedHostFunctions,
  sourcePath,
) {
  const assigned = cppMovedOrDirectIdentifier(tokens);
  const assignedDescriptor = assignedHostFunctions.get(assigned);
  if (assignedDescriptor) return assignedDescriptor;

  const descriptors = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index]?.value !== "createFromHostFunction" ||
      tokens[index + 1]?.value !== "("
    ) {
      continue;
    }
    const close = matchingToken(tokens, index + 1, "(", ")");
    if (close === -1) {
      throw new Error(
        `${sourcePath}: inline createFromHostFunction call has no closing parenthesis`,
      );
    }
    const args = cppCallArguments(tokens, index + 1, close);
    if (args.length < 4) continue;
    const functionName = cppLiteralArgument(args[1]);
    const arity = cppUnsignedIntegerArgument(args[2]);
    if (functionName !== null && arity !== null) {
      descriptors.push({ arity, functionName });
    }
    index = close;
  }
  if (descriptors.length !== 1) return null;
  return descriptors[0];
}

function getAllEnvironmentInstallationBranches(tokens, sourcePath, baseRefs) {
  const definitions = [];
  for (let index = 0; index < tokens.length - 2; index += 1) {
    if (
      tokens[index]?.value !== "getAllEnvFn" ||
      tokens[index + 1]?.value !== "="
    ) {
      continue;
    }
    let factoryIndex = index + 2;
    while (
      factoryIndex < tokens.length &&
      tokens[factoryIndex]?.value !== "createFromHostFunction" &&
      tokens[factoryIndex]?.value !== ";"
    ) {
      factoryIndex += 1;
    }
    if (
      tokens[factoryIndex]?.value !== "createFromHostFunction" ||
      tokens[factoryIndex + 1]?.value !== "("
    ) {
      continue;
    }
    const close = matchingToken(tokens, factoryIndex + 1, "(", ")");
    if (close === -1) {
      throw new Error(
        `${sourcePath}: __exactGetAllEnv factory call is unterminated`,
      );
    }
    const args = cppCallArguments(tokens, factoryIndex + 1, close);
    if (args.length < 4) {
      throw new Error(
        `${sourcePath}: __exactGetAllEnv factory lacks its callback`,
      );
    }
    definitions.push(args.at(-1));
  }
  if (definitions.length !== 1) {
    throw new Error(
      `${sourcePath}: expected one structural getAllEnvFn definition; observed ${definitions.length}`,
    );
  }

  const callback = definitions[0];
  if (
    !callback.some(
      (token) => token.value === "populateDiagnosticProcessEnvironment",
    )
  ) {
    throw new Error(
      `${sourcePath}: __exactGetAllEnv must delegate diagnostic enumeration to its named helper`,
    );
  }
  const helperDefinitions = cppFunctionDefinitions(tokens).filter(
    (definition) => definition.name === "populateDiagnosticProcessEnvironment",
  );
  if (helperDefinitions.length !== 1) {
    throw new Error(
      `${sourcePath}: expected one diagnostic process-environment helper; observed ${helperDefinitions.length}`,
    );
  }
  const helper = helperDefinitions[0];
  const enumeration = tokens.slice(helper.bodyOpen + 1, helper.bodyClose);
  const indexOf = (value, start = 0) =>
    enumeration.findIndex(
      (token, index) => index >= start && token.value === value,
    );
  const windowsMacro = indexOf("_WIN32");
  const windowsAccessor = indexOf("GetEnvironmentStringsW", windowsMacro + 1);
  const appleMacro = indexOf("__APPLE__", windowsAccessor + 1);
  const appleAccessor = indexOf("_NSGetEnviron", appleMacro + 1);
  const posixScope = indexOf("::", appleAccessor + 1);
  const posixAccessor = enumeration.findIndex(
    (token, index) =>
      index > posixScope &&
      token.value === "environ" &&
      enumeration[index - 1]?.value === "::",
  );
  if (
    windowsMacro === -1 ||
    windowsAccessor === -1 ||
    appleMacro === -1 ||
    appleAccessor === -1 ||
    posixScope === -1 ||
    posixAccessor === -1 ||
    !(
      windowsMacro < windowsAccessor &&
      windowsAccessor < appleMacro &&
      appleMacro < appleAccessor &&
      appleAccessor < posixAccessor
    )
  ) {
    throw new Error(
      `${sourcePath}: __exactGetAllEnv must retain exact Windows/Apple/POSIX enumeration branches`,
    );
  }

  const specifications = [
    ["apple", "_NSGetEnviron"],
    ["posix", "::environ"],
    ["windows", "GetEnvironmentStringsW"],
  ];
  return specifications.map(([targetVariant, accessor]) => {
    const sourceRefs = uniqueSorted([
      ...baseRefs,
      sourceSymbol(sourcePath, `__exactGetAllEnv:${targetVariant}:${accessor}`),
    ]);
    return makeInstallationBranch(
      "native-env-enumeration",
      targetVariant,
      sourceRefs,
      "alternative",
    );
  });
}

/** Discover public and private JSI object registrations reachable from globals. */
export function scanCppGlobalPropertySurfaces(
  text,
  sourcePath = "<native-source>",
) {
  const tokens = lexCpp(text, sourcePath);
  const assignedHostFunctions = cppAssignedHostFunctions(tokens, sourcePath);
  const calls = [];
  const objectOwners = new Set();
  const exactCapabilityOwners = new Set();
  const closedGlobalTableNames = new Set();
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].value === "Object" &&
      tokens[index + 1]?.type === "identifier" &&
      tokens[index + 2]?.value === "("
    ) {
      objectOwners.add(tokens[index + 1].value);
    }
  }
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].type !== "identifier" ||
      tokens[index + 1]?.value !== "." ||
      tokens[index + 2]?.value !== "setProperty" ||
      tokens[index + 3]?.value !== "("
    ) {
      continue;
    }
    const close = matchingToken(tokens, index + 3, "(", ")");
    if (close === -1)
      throw new Error(
        `${sourcePath}: setProperty call has no closing parenthesis`,
      );
    const args = cppCallArguments(tokens, index + 3, close);
    if (args.length < 3) continue;
    objectOwners.add(tokens[index].value);
    calls.push({
      args,
      globalTarget: false,
      owner: tokens[index].value,
    });
  }

  // Exact's late-bound embedder capability uses Object.defineProperty through
  // this dedicated helper so the member can be sealed after the compartment
  // baseline refresh. Treat it as the same authored object-member installation
  // shape as target.setProperty; otherwise the reviewed public ingress silently
  // disappears from source-derived inventory.
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].type !== "identifier" ||
      tokens[index].value !== "defineExactCapability" ||
      tokens[index + 1]?.value !== "("
    ) {
      continue;
    }
    const close = matchingToken(tokens, index + 1, "(", ")");
    if (close === -1) {
      throw new Error(
        `${sourcePath}: defineExactCapability call has no closing parenthesis`,
      );
    }
    const args = cppCallArguments(tokens, index + 1, close);
    if (args.length < 4) continue;
    const owner = cppMovedOrDirectIdentifier(args[1]);
    if (!owner) continue;
    objectOwners.add(owner);
    exactCapabilityOwners.add(owner);
    calls.push({
      args: [args[0], args[2], args[3]],
      globalTarget: false,
      owner,
    });
  }

  // global().setProperty has a call expression rather than an identifier as
  // its target, so collect it in a second structural pass.
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].type !== "identifier" ||
      tokens[index].value !== "setProperty" ||
      tokens[index - 1]?.value !== "." ||
      tokens[index + 1]?.value !== "("
    ) {
      continue;
    }
    const prefix = tokens.slice(Math.max(0, index - 12), index - 1);
    if (
      !prefix.some(
        (token, offset) =>
          token.value === "global" && prefix[offset + 1]?.value === "(",
      )
    ) {
      continue;
    }
    const close = matchingToken(tokens, index + 1, "(", ")");
    if (close === -1)
      throw new Error(
        `${sourcePath}: global setProperty call has no closing parenthesis`,
      );
    const args = cppCallArguments(tokens, index + 1, close);
    if (args.length < 3) continue;
    calls.push({ args, globalTarget: true, owner: null });
  }

  // Accessor installers still create public object properties even though the
  // final Object.defineProperty call lives inside a helper. Recover the closed,
  // authored stdio accessor call sites so manifest coverage follows the
  // concrete property names instead of treating the helper parameter as a
  // dynamic registration.
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].type !== "identifier" ||
      tokens[index].value !== "installStdioQueryAccessor" ||
      tokens[index + 1]?.value !== "("
    ) {
      continue;
    }
    const close = matchingToken(tokens, index + 1, "(", ")");
    if (close === -1) {
      throw new Error(
        `${sourcePath}: installStdioQueryAccessor call has no closing parenthesis`,
      );
    }
    const args = cppCallArguments(tokens, index + 1, close);
    const owner =
      args[0]?.length === 1 && args[0][0].type === "identifier"
        ? args[0][0].value
        : null;
    const propertyName = args.length >= 3 ? cppLiteralArgument(args[2]) : null;
    if (!owner || !objectOwners.has(owner) || !propertyName) continue;
    calls.push({
      args: [[], args[2], []],
      globalTarget: false,
      owner,
      propertyName,
      valueShape: "accessor",
    });
  }

  // The Windows unsupported-module helper forwards each member of a closed
  // authored initializer list to installUnsupportedGlobal. Preserve the
  // dynamic helper sentinel below, but also resolve its concrete call-site
  // members so each unsupported implementation has a real Windows branch.
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].type !== "identifier" ||
      tokens[index].value !== "installUnsupportedModule" ||
      tokens[index + 1]?.value !== "("
    ) {
      continue;
    }
    const close = matchingToken(tokens, index + 1, "(", ")");
    if (close === -1) {
      throw new Error(
        `${sourcePath}: installUnsupportedModule call has no closing parenthesis`,
      );
    }
    const args = cppCallArguments(tokens, index + 1, close);
    for (const name of args
      .slice(1)
      .flat()
      .filter((token) => token.type === "string")) {
      if (PRIVATE_NATIVE_IDENTIFIER.test(name.value))
        closedGlobalTableNames.add(name.value);
    }
  }

  const valueOwners = (argument) => {
    const owners = [];
    if (
      argument.length === 1 &&
      argument[0].type === "identifier" &&
      objectOwners.has(argument[0].value)
    ) {
      owners.push(argument[0].value);
    }
    for (let index = 0; index < argument.length; index += 1) {
      if (
        argument[index].value === "move" &&
        argument[index + 1]?.value === "(" &&
        argument[index + 2]?.type === "identifier" &&
        objectOwners.has(argument[index + 2].value)
      ) {
        owners.push(argument[index + 2].value);
      }
      if (
        argument[index].type === "identifier" &&
        /^make[A-Z]/u.test(argument[index].value) &&
        argument[index + 1]?.value === "("
      ) {
        const suffix = argument[index].value.slice(4).toLowerCase();
        for (const owner of objectOwners) {
          if (owner.toLowerCase() === suffix) owners.push(owner);
        }
      }
    }
    return uniqueSorted(owners);
  };

  const ownerPaths = new Map();
  const facts = new Map();
  const publicInvocations = new Map();
  const valueShapes = new Map();
  const dynamicFacts = new Set();
  const propertyNameForCall = (call) => {
    if (call.propertyName) return call.propertyName;
    const literal = cppLiteralArgument(call.args[1]);
    if (literal) return literal;
    const label = call.globalTarget
      ? "native-global-name"
      : `${call.owner
          .replace(/([a-z0-9])([A-Z])/gu, "$1-$2")
          .replace(/[^A-Za-z0-9]+/gu, "-")
          .toLowerCase()}-properties`;
    return `[[dynamic-table:${label}]]`;
  };
  const addOwnerPath = (owner, objectPath) => {
    let paths = ownerPaths.get(owner);
    if (!paths) {
      paths = new Set();
      ownerPaths.set(owner, paths);
    }
    const before = paths.size;
    paths.add(objectPath);
    return paths.size !== before;
  };
  for (const owner of exactCapabilityOwners) addOwnerPath(owner, "exact");
  const addFact = (exportName) => {
    if (!facts.has(exportName)) facts.set(exportName, new Set());
    facts
      .get(exportName)
      .add(sourceSymbol(sourcePath, `jsi-global:${exportName}`));
  };
  const addValueShape = (exportName, valueShape) => {
    if (!valueShape) return;
    let shapes = valueShapes.get(exportName);
    if (!shapes) {
      shapes = new Set();
      valueShapes.set(exportName, shapes);
    }
    shapes.add(valueShape);
  };
  const recordInvocation = (call, exportName, propertyName) => {
    const hostFunction = cppHostFunctionValueDescriptor(
      call.args[2],
      assignedHostFunctions,
      sourcePath,
    );
    if (!hostFunction || DYNAMIC_TABLE_MEMBER.test(propertyName)) {
      addValueShape(exportName, call.valueShape);
      return;
    }
    addValueShape(exportName, "callable");
    publicInvocations.set(exportName, {
      arity: hostFunction.arity,
      globalName: exportName,
      kind: "native-global-function",
      sourceRef: sourceSymbol(sourcePath, `jsi-global:${exportName}`),
    });
  };

  for (const call of calls.filter((candidate) => candidate.globalTarget)) {
    const name = propertyNameForCall(call);
    if (DYNAMIC_TABLE_MEMBER.test(name)) dynamicFacts.add(name);
    addFact(name);
    recordInvocation(call, name, name);
    for (const owner of valueOwners(call.args[2])) addOwnerPath(owner, name);
  }
  for (const name of closedGlobalTableNames) addFact(name);

  let changed = true;
  while (changed) {
    changed = false;
    for (const call of calls.filter((candidate) => !candidate.globalTarget)) {
      const name = propertyNameForCall(call);
      for (const basePath of ownerPaths.get(call.owner) ?? []) {
        const exportName = `${basePath}.${name}`;
        if (DYNAMIC_TABLE_MEMBER.test(name)) dynamicFacts.add(exportName);
        const before = facts.size;
        addFact(exportName);
        recordInvocation(call, exportName, name);
        if (facts.size !== before) changed = true;
        for (const owner of valueOwners(call.args[2])) {
          changed = addOwnerPath(owner, exportName) || changed;
        }
      }
    }
  }

  // @ref LLP 0021#generated-semantic-datasets — target cells bind the exact
  // compiled implementation. build.rs replaces a reviewed set of backend
  // translation units on Windows, so their registrations are POSIX-family
  // branches rather than universal fallbacks.
  const targetVariant =
    nativeImplementationSourceIsReplacedOnWindows(sourcePath)
      ? "posix"
      : sourcePath.includes("windows")
        ? "windows"
        : sourcePath.includes("ios")
          ? "ios"
          : sourcePath.includes("android")
            ? "android"
            : sourcePath.includes("worklet")
              ? "worklet"
              : "default";
  return sortSurfaces(
    [...facts.entries()].map(([exportName, refs]) => {
      const [globalName, ...memberSegments] = exportName.split(".");
      const baseRefs = uniqueSorted(refs);
      const branches =
        exportName === "__exactGetAllEnv"
          ? getAllEnvironmentInstallationBranches(tokens, sourcePath, baseRefs)
          : [
              makeInstallationBranch(
                "native-jsi-global",
                targetVariant,
                baseRefs,
              ),
            ];
      const sourceRefs = uniqueSorted(
        branches.flatMap((branch) => branch.sourceRefs),
      );
      const name = globalSurfaceName(exportName);
      const concreteProperty = !exportName
        .split(".")
        .some((segment) => DYNAMIC_TABLE_MEMBER.test(segment));
      const observedValueShapes = valueShapes.get(exportName) ?? new Set();
      const valueShape =
        observedValueShapes.size === 1 ? [...observedValueShapes][0] : null;
      return makeSurface("native-op", name, sourceRefs, {
        metadata: {
          branches,
          exportName,
          globalName,
          installationBranches: branches,
          memberKinds: [
            dynamicFacts.has(exportName)
              ? "dynamic-table"
              : memberSegments.length === 0
                ? "native-root"
                : "native-object-member",
          ],
          memberName:
            memberSegments.length === 0 ? null : memberSegments.join("."),
          moduleSpecifiers: [],
          ...(concreteProperty ? { publicReadAccessSourceProven: true } : {}),
          ...(publicInvocations.has(exportName)
            ? { publicInvocation: publicInvocations.get(exportName) }
            : {}),
          sourceKey: "native_jsi_global",
          surfaceType: "global-api",
          ...(valueShape ? { valueShape } : {}),
          ...(dynamicFacts.has(exportName)
            ? { semanticRoles: ["runtime-property-overlay"] }
            : {}),
        },
      });
    }),
  );
}

const KNOWN_HERMES_EVALUATORS = new Set([
  "AsyncFunction",
  "AsyncGeneratorFunction",
  "Function",
  "GeneratorFunction",
  "eval",
]);

const REVIEWED_HERMES_PATCH_PATHS = [
  "patches/hermes/0001-domain-package-principal.patch",
  "patches/hermes/0002-frame-attribution-helper.patch",
  "patches/hermes/0003-capability-bridge-exports.patch",
  "patches/hermes/0004-native-compartment-globals.patch",
  "patches/hermes/0005-native-compartment-refinements.patch",
  "patches/hermes/0006-eval-binding-and-native-deep-freeze.patch",
  "patches/hermes/0007-fail-closed-async-deputy-attribution.patch",
  "patches/hermes/0008-schedule-time-principal-capture.patch",
  "patches/hermes/0009-raw-throw-capture.patch",
  "patches/hermes/0010-completion-record-discriminator.patch",
  "patches/hermes/0011-structured-async-failure-provenance.patch",
  "patches/hermes/0012-keyed-external-arraybuffer-alias.patch",
  "patches/hermes/0013-native-job-constrained-principals.patch",
  "patches/hermes/0014-honor-disabled-eval-for-return-this.patch",
];

const REVIEWED_REACHABLE_HERMES_EVALUATORS = [
  "AsyncFunction",
  "Function",
  "GeneratorFunction",
  "eval",
];
const REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST =
  "sha256-0afd8daf12332552b079a9416d3cd7200bf871192a8df7934fa10f3473b52437";

// These are reviewed reachability claims for exact checked-in artifact
// identities, not a floating statement about Hermes releases. Source discovery
// emits a new identity sentinel when any authority changes; the independent
// semantic classifier then rejects it until this snapshot is reviewed too.
// @ref LLP 0013#upstream-tracking-and-re-derivation — the desktop pin plus
// patch stack is the fork; Android consumes a separate pinned channel while
// Windows uses the same source-patched identity as Apple/Linux.
const REVIEWED_HERMES_EVALUATOR_PROFILES = [
  {
    id: "android-maven",
    targetVariant: "android",
    identity: {
      artifact: "com.facebook.hermes:hermes-android",
      packageDigest:
        "sha256-2399d266ed06c2a907f1ceb2606c0958a293751781f23774a292c438779c3285",
      linkedDependency: {
        artifact: "com.facebook.react:react-android",
        packageDigest:
          "sha256-46fc1bfcb0a0aa2c79a81d7804105c88de7d2936fce31ca14aa4ba0e847869ee",
        variant: "debug",
        version: "0.86.0",
      },
      variant: "debug",
      version: "250829098.0.14",
    },
    reachableEvaluators: REVIEWED_REACHABLE_HERMES_EVALUATORS,
    sourceRefs: [
      "scripts/hermes-version.sh#IBEX_HERMES_ANDROID_VERSION",
      "scripts/hermes-version.sh#IBEX_HERMES_ANDROID_DEBUG_AAR_SHA256",
      "scripts/hermes-version.sh#IBEX_REACT_ANDROID_VERSION",
      "scripts/hermes-version.sh#IBEX_REACT_ANDROID_DEBUG_AAR_SHA256",
      "scripts/install-android-hermes.sh#ANDROID_HERMES_VARIANT",
      "scripts/install-android-hermes.sh#com.facebook.hermes:hermes-android",
      "scripts/install-android-hermes.sh#com.facebook.react:react-android",
    ],
  },
  {
    id: "source-patched",
    targetVariant: "default",
    identity: {
      artifact: "facebook/hermes",
      patchApplicationAuthorityDigest:
        "sha256-4d422defe36111f1749f01c7884d942062ad54e6a7d611eee624547002bc4cdd",
      patchIdentityAuthorityDigest:
        "sha256-6e939803e5b0b5605a886debe46f3e3378ad5b34c1c7528a75954bba48366930",
      patchStackDigest:
        "sha256-9a846368e13304659cb6e0d4be78853bad6415de01f68a4191f7cd9b3af2c7d7",
      sourceBuildAuthorityDigests: {
        "scripts/build-hermes-linux.sh":
          "sha256-af521ddda077302b82de42a024eba5e708b9072462d2c4e53c742d8cc473ea92",
        "scripts/build-hermes.sh":
          "sha256-60b2b604a01cb52186061c7e6967c9303d86ca587eee2db79d2df4e0f8c991e9",
      },
      sourceCommit: "e639a7bad8bfca844d982afa54fac786c65a8856",
      sourceRef: "260318099.0.0-stable",
      sourceVersion: "260318099.0.0",
    },
    reachableEvaluators: REVIEWED_REACHABLE_HERMES_EVALUATORS,
    sourceRefs: [
      "scripts/hermes-version.sh#IBEX_HERMES_SOURCE_COMMIT",
      "scripts/hermes-version.sh#IBEX_HERMES_SOURCE_REF",
      "scripts/hermes-version.sh#IBEX_HERMES_VERSION",
      "scripts/hermes-version.sh#ibex_hermes_patch_digest",
      "scripts/apply-hermes-patches.sh#patches",
      "scripts/build-hermes.sh#apply-hermes-patches.sh",
      "scripts/build-hermes-linux.sh#apply-hermes-patches.sh",
      ...REVIEWED_HERMES_PATCH_PATHS.map((patchPath) =>
        sourceSymbol(patchPath, "patch-content"),
      ),
    ],
  },
  {
    id: "windows-source-patched",
    targetVariant: "windows",
    identity: {
      artifact: "facebook/hermes",
      patchApplicationAuthorityDigest:
        "sha256-4d422defe36111f1749f01c7884d942062ad54e6a7d611eee624547002bc4cdd",
      patchIdentityAuthorityDigest:
        "sha256-6e939803e5b0b5605a886debe46f3e3378ad5b34c1c7528a75954bba48366930",
      patchStackDigest:
        "sha256-9a846368e13304659cb6e0d4be78853bad6415de01f68a4191f7cd9b3af2c7d7",
      sourceBuildAuthorityDigest:
        "sha256-5c62e67be52076bd72364a029445f0c727d76067a4e9381abb52168392bf4f07",
      sourceCommit: "e639a7bad8bfca844d982afa54fac786c65a8856",
      sourceRef: "260318099.0.0-stable",
      sourceVersion: "260318099.0.0",
      sourceInstallerAuthorityDigest:
        "sha256-886f7b34e6f2d2d3cdffb1ca6b962ebb3239c55b4d513c8005634e62a4cae0bf",
    },
    reachableEvaluators: REVIEWED_REACHABLE_HERMES_EVALUATORS,
    sourceRefs: [
      "scripts/build-hermes-windows.ps1#apply-hermes-patches.sh",
      "scripts/install-windows-hermes.ps1#hermes-windows-",
    ],
  },
];

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

// PowerShell authorities retain platform-native checkout bytes because the
// published Windows artifact manifest attests those raw bytes independently.
// Evaluator review is source-semantic, so one CRLF/LF spelling has one review
// identity while every other source mutation still fails closed.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — keep
// artifact attestation byte-exact without making evaluator review OS-specific.
function reviewedTextAuthorityDigest(value) {
  return `sha256-${sha256Hex(value.replaceAll("\r\n", "\n"))}`;
}

function canonicalReviewValue(value) {
  if (Array.isArray(value)) return value.map(canonicalReviewValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareText)
        .map((key) => [key, canonicalReviewValue(value[key])]),
    );
  }
  return value;
}

function hermesEvaluatorReviewId(profiles, lockdownTamingDigest) {
  if (!/^sha256-[a-f0-9]{64}$/u.test(lockdownTamingDigest ?? "")) {
    throw new Error("Hermes evaluator review has no exact lockdown digest");
  }
  const normalized = profiles
    .map((profile) => ({
      ...profile,
      reachableEvaluators: uniqueSorted(profile.reachableEvaluators ?? []),
      sourceRefs: uniqueSorted(profile.sourceRefs ?? []),
    }))
    .sort((left, right) => compareText(left.id, right.id));
  return `hermes-evaluators.${sha256Hex(
    JSON.stringify(
      canonicalReviewValue({
        lockdownTamingDigest,
        profiles: normalized,
      }),
    ),
  )}`;
}

export const HERMES_EVALUATOR_REVIEW_ID = hermesEvaluatorReviewId(
  REVIEWED_HERMES_EVALUATOR_PROFILES,
  REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST,
);

function oneSourceMatch(text, pattern, label) {
  const matches = [...text.matchAll(pattern)];
  if (matches.length !== 1) {
    throw new Error(`${label}: expected exactly one source identity match`);
  }
  return matches[0];
}

function requireOneSourceLine(text, line, label) {
  const matches = text
    .split(/\r?\n/u)
    .filter((candidate) => candidate === line);
  if (matches.length !== 1) {
    throw new Error(`${label}: expected exactly one source authority line`);
  }
}

function shellDefaultValue(text, variable, sourcePath) {
  const escaped = variable.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return oneSourceMatch(
    text,
    new RegExp(`^${escaped}="\\$\\{${escaped}:-([^"\\r\\n]+)\\}"$`, "gmu"),
    `${sourcePath}#${variable}`,
  )[1];
}

function resolveCheckedShellTemplate(value, variables, label) {
  let resolved = value;
  for (const [name, replacement] of Object.entries(variables)) {
    resolved = resolved
      .replaceAll(`\${${name}}`, replacement)
      .replaceAll(`$${name}`, replacement);
  }
  if (resolved.includes("$")) {
    throw new Error(`${label}: unresolved shell identity expression ${value}`);
  }
  return resolved;
}

function canonicalPatchInputs(patches) {
  if (!Array.isArray(patches) || patches.length === 0) {
    throw new Error("Hermes evaluator identity has no patch-stack evidence");
  }
  const seen = new Set();
  return patches
    .map((patch) => {
      const sourcePath = posixPath(String(patch?.sourcePath ?? ""));
      if (
        !/^patches\/hermes\/[A-Za-z0-9_.-]+\.patch$/u.test(sourcePath) ||
        (!Buffer.isBuffer(patch?.content) && typeof patch?.content !== "string")
      ) {
        throw new Error(
          `Hermes evaluator identity has malformed patch evidence ${sourcePath || "<missing>"}`,
        );
      }
      if (seen.has(sourcePath)) {
        throw new Error(
          `Hermes evaluator identity has duplicate patch evidence ${sourcePath}`,
        );
      }
      seen.add(sourcePath);
      return { sourcePath, content: patch.content };
    })
    .sort((left, right) => compareText(left.sourcePath, right.sourcePath));
}

function hermesPatchStackDigest(patches) {
  const shasumLines = canonicalPatchInputs(patches)
    .map(({ sourcePath, content }) => `${sha256Hex(content)}  ${sourcePath}\n`)
    .join("");
  return `sha256-${sha256Hex(shasumLines)}`;
}

function cloneHermesEvaluatorProfiles(profiles) {
  return profiles.map((profile) => ({
    id: profile.id,
    targetVariant: profile.targetVariant,
    identity: structuredClone(profile.identity),
    reachableEvaluators: [...profile.reachableEvaluators],
    sourceRefs: [...profile.sourceRefs],
  }));
}

/**
 * Recover every checked-in Hermes artifact identity without executing an
 * engine or a shell. An identity change intentionally changes the review ID,
 * so the independent classifier fails until possible new Function-family
 * constructors are reviewed.
 */
export function scanHermesEvaluatorIdentityProfiles({
  hermesVersionText,
  androidInstallerText,
  windowsInstallerText,
  windowsSourceBuildText,
  patchApplicationText,
  appleSourceBuildText,
  linuxSourceBuildText,
  patches,
  hermesVersionPath = "scripts/hermes-version.sh",
  androidInstallerPath = "scripts/install-android-hermes.sh",
  windowsInstallerPath = "scripts/install-windows-hermes.ps1",
  windowsSourceBuildPath = "scripts/build-hermes-windows.ps1",
  patchApplicationPath = "scripts/apply-hermes-patches.sh",
  appleSourceBuildPath = "scripts/build-hermes.sh",
  linuxSourceBuildPath = "scripts/build-hermes-linux.sh",
}) {
  const sourceVersion = shellDefaultValue(
    hermesVersionText,
    "IBEX_HERMES_VERSION",
    hermesVersionPath,
  );
  const sourceRef = resolveCheckedShellTemplate(
    shellDefaultValue(
      hermesVersionText,
      "IBEX_HERMES_SOURCE_REF",
      hermesVersionPath,
    ),
    { IBEX_HERMES_VERSION: sourceVersion },
    `${hermesVersionPath}#IBEX_HERMES_SOURCE_REF`,
  );
  const sourceCommit = shellDefaultValue(
    hermesVersionText,
    "IBEX_HERMES_SOURCE_COMMIT",
    hermesVersionPath,
  );
  const androidVersion = shellDefaultValue(
    hermesVersionText,
    "IBEX_HERMES_ANDROID_VERSION",
    hermesVersionPath,
  );
  const reactAndroidVersion = shellDefaultValue(
    hermesVersionText,
    "IBEX_REACT_ANDROID_VERSION",
    hermesVersionPath,
  );
  const androidPackageSha256 = oneSourceMatch(
    hermesVersionText,
    /^IBEX_HERMES_ANDROID_DEBUG_AAR_SHA256="([a-f0-9]{64})"$/gmu,
    `${hermesVersionPath}#IBEX_HERMES_ANDROID_DEBUG_AAR_SHA256`,
  )[1];
  const reactAndroidPackageSha256 = oneSourceMatch(
    hermesVersionText,
    /^IBEX_REACT_ANDROID_DEBUG_AAR_SHA256="([a-f0-9]{64})"$/gmu,
    `${hermesVersionPath}#IBEX_REACT_ANDROID_DEBUG_AAR_SHA256`,
  )[1];
  const buildRefAuthority =
    'IBEX_HERMES_BUILD_REF="${IBEX_HERMES_BUILD_REF:-${IBEX_HERMES_SOURCE_COMMIT:-$IBEX_HERMES_SOURCE_REF}}"';
  if (!hermesVersionText.split(/\r?\n/u).includes(buildRefAuthority)) {
    throw new Error(
      `${hermesVersionPath}#IBEX_HERMES_BUILD_REF: checked-in build-ref authority drift`,
    );
  }
  const patchAuthorityStart = hermesVersionText.indexOf("ibex_sha256() {");
  if (patchAuthorityStart === -1) {
    throw new Error(
      `${hermesVersionPath}#ibex_hermes_patch_digest: patch identity authority is absent`,
    );
  }
  const patchIdentityAuthorityDigest = `sha256-${sha256Hex(
    hermesVersionText.slice(patchAuthorityStart),
  )}`;
  const normalizedPatches = canonicalPatchInputs(patches);

  for (const [label, line] of [
    ["patch glob", 'patches=("$PATCH_DIR"/*.patch)'],
    ["ordered patch loop", 'for patch in "${patches[@]}"; do'],
    ["patch application", '  git apply "$patch"'],
  ]) {
    requireOneSourceLine(
      patchApplicationText,
      line,
      `${patchApplicationPath}#${label}`,
    );
  }
  const patchApplicationConsumers = [
    {
      sourcePath: appleSourceBuildPath,
      text: appleSourceBuildText,
      invocation: '"$SCRIPT_DIR/apply-hermes-patches.sh" "$HERMES_SRC"',
    },
    {
      sourcePath: linuxSourceBuildPath,
      text: linuxSourceBuildText,
      invocation: '"$SCRIPT_DIR/apply-hermes-patches.sh" "$SRC_DIR"',
    },
    {
      sourcePath: windowsSourceBuildPath,
      text: windowsSourceBuildText,
      invocation: "& bash $applyScriptUnix $sourceDirUnix",
    },
  ];
  for (const consumer of patchApplicationConsumers) {
    requireOneSourceLine(
      consumer.text,
      consumer.invocation,
      `${consumer.sourcePath}#apply-hermes-patches.sh`,
    );
  }
  const patchApplicationAuthorityDigest = `sha256-${sha256Hex(
    patchApplicationText,
  )}`;
  const sourceBuildConsumers = patchApplicationConsumers.filter(
    (consumer) => consumer.sourcePath !== windowsSourceBuildPath,
  );
  const sourceBuildAuthorityDigests = Object.fromEntries(
    sourceBuildConsumers.map((consumer) => [
      consumer.sourcePath,
      `sha256-${sha256Hex(consumer.text)}`,
    ]),
  );
  const windowsSourceBuildAuthorityDigest = reviewedTextAuthorityDigest(
    windowsSourceBuildText,
  );

  const androidVersionAuthority =
    'HERMES_ANDROID_VERSION="${HERMES_ANDROID_VERSION:-$IBEX_HERMES_ANDROID_VERSION}"';
  if (!androidInstallerText.split(/\r?\n/u).includes(androidVersionAuthority)) {
    throw new Error(
      `${androidInstallerPath}#HERMES_ANDROID_VERSION: checked-in Android version authority drift`,
    );
  }
  const androidVariant = shellDefaultValue(
    androidInstallerText,
    "ANDROID_HERMES_VARIANT",
    androidInstallerPath,
  );
  for (const [label, line] of [
    [
      "Hermes AAR checksum authority",
      'HERMES_ANDROID_AAR_SHA256="${HERMES_ANDROID_AAR_SHA256:-$IBEX_HERMES_ANDROID_DEBUG_AAR_SHA256}"',
    ],
    [
      "React Android AAR checksum authority",
      'REACT_ANDROID_AAR_SHA256="${REACT_ANDROID_AAR_SHA256:-$IBEX_REACT_ANDROID_DEBUG_AAR_SHA256}"',
    ],
  ]) {
    requireOneSourceLine(androidInstallerText, line, `${androidInstallerPath}#${label}`);
  }
  const androidArtifact = oneSourceMatch(
    androidInstallerText,
    /download_aar\s+"([A-Za-z0-9.]+)"\s+"([A-Za-z0-9.-]+)"\s+"\$HERMES_ANDROID_VERSION"\s+"\$ANDROID_HERMES_VARIANT"\s+"\$HERMES_ANDROID_AAR_SHA256"/gu,
    `${androidInstallerPath}#Hermes-Maven-coordinate`,
  );
  const reactAndroidArtifact = oneSourceMatch(
    androidInstallerText,
    /download_aar\s+"([A-Za-z0-9.]+)"\s+"([A-Za-z0-9.-]+)"\s+"\$REACT_ANDROID_VERSION"\s+"\$ANDROID_HERMES_VARIANT"\s+"\$REACT_ANDROID_AAR_SHA256"/gu,
    `${androidInstallerPath}#React-Android-Maven-coordinate`,
  );

  const windowsArtifact = oneSourceMatch(
    windowsInstallerText,
    /^\$asset = "(hermes-windows-)\$Arch-\$assetKey\.zip"$/gmu,
    `${windowsInstallerPath}#release-asset`,
  )[1];
  const windowsInstallerAuthorityDigest = reviewedTextAuthorityDigest(
    windowsInstallerText,
  );

  const discovered = [
    {
      id: "android-maven",
      targetVariant: "android",
      identity: {
        artifact: `${androidArtifact[1]}:${androidArtifact[2]}`,
        packageDigest: `sha256-${androidPackageSha256}`,
        linkedDependency: {
          artifact: `${reactAndroidArtifact[1]}:${reactAndroidArtifact[2]}`,
          packageDigest: `sha256-${reactAndroidPackageSha256}`,
          variant: androidVariant,
          version: reactAndroidVersion,
        },
        variant: androidVariant,
        version: androidVersion,
      },
      reachableEvaluators: REVIEWED_REACHABLE_HERMES_EVALUATORS,
      sourceRefs: [
        sourceSymbol(hermesVersionPath, "IBEX_HERMES_ANDROID_VERSION"),
        sourceSymbol(
          hermesVersionPath,
          "IBEX_HERMES_ANDROID_DEBUG_AAR_SHA256",
        ),
        sourceSymbol(hermesVersionPath, "IBEX_REACT_ANDROID_VERSION"),
        sourceSymbol(
          hermesVersionPath,
          "IBEX_REACT_ANDROID_DEBUG_AAR_SHA256",
        ),
        sourceSymbol(androidInstallerPath, "ANDROID_HERMES_VARIANT"),
        sourceSymbol(
          androidInstallerPath,
          `${androidArtifact[1]}:${androidArtifact[2]}`,
        ),
        sourceSymbol(
          androidInstallerPath,
          `${reactAndroidArtifact[1]}:${reactAndroidArtifact[2]}`,
        ),
      ],
    },
    {
      id: "source-patched",
      targetVariant: "default",
      identity: {
        artifact: "facebook/hermes",
        patchApplicationAuthorityDigest,
        patchIdentityAuthorityDigest,
        patchStackDigest: hermesPatchStackDigest(normalizedPatches),
        sourceBuildAuthorityDigests,
        sourceCommit,
        sourceRef,
        sourceVersion,
      },
      reachableEvaluators: REVIEWED_REACHABLE_HERMES_EVALUATORS,
      sourceRefs: [
        sourceSymbol(hermesVersionPath, "IBEX_HERMES_SOURCE_COMMIT"),
        sourceSymbol(hermesVersionPath, "IBEX_HERMES_SOURCE_REF"),
        sourceSymbol(hermesVersionPath, "IBEX_HERMES_VERSION"),
        sourceSymbol(hermesVersionPath, "ibex_hermes_patch_digest"),
        sourceSymbol(patchApplicationPath, "patches"),
        ...sourceBuildConsumers.map((consumer) =>
          sourceSymbol(consumer.sourcePath, "apply-hermes-patches.sh"),
        ),
        ...normalizedPatches.map(({ sourcePath }) =>
          sourceSymbol(sourcePath, "patch-content"),
        ),
      ],
    },
    {
      id: "windows-source-patched",
      targetVariant: "windows",
      identity: {
        artifact: "facebook/hermes",
        patchApplicationAuthorityDigest,
        patchIdentityAuthorityDigest,
        patchStackDigest: hermesPatchStackDigest(normalizedPatches),
        sourceBuildAuthorityDigest: windowsSourceBuildAuthorityDigest,
        sourceCommit,
        sourceRef,
        sourceVersion,
        sourceInstallerAuthorityDigest: windowsInstallerAuthorityDigest,
      },
      reachableEvaluators: REVIEWED_REACHABLE_HERMES_EVALUATORS,
      sourceRefs: [
        sourceSymbol(windowsSourceBuildPath, "apply-hermes-patches.sh"),
        sourceSymbol(windowsInstallerPath, windowsArtifact),
      ],
    },
  ];
  return cloneHermesEvaluatorProfiles(discovered);
}

export function discoverHermesEvaluatorIdentityProfiles(repoRoot) {
  const patchRoot = path.join(repoRoot, "patches", "hermes");
  const patchEntries = fs
    .readdirSync(patchRoot, { withFileTypes: true })
    .filter((entry) => entry.name.endsWith(".patch"));
  const symbolicPatches = patchEntries
    .filter((entry) => entry.isSymbolicLink())
    .map((entry) => entry.name)
    .sort(compareText);
  if (symbolicPatches.length > 0) {
    throw new Error(
      `Hermes patch stack must not contain symbolic links: ${symbolicPatches.join(", ")}`,
    );
  }
  const patches = patchEntries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".patch"))
    .map((entry) => ({
      sourcePath: `patches/hermes/${entry.name}`,
      content: fs.readFileSync(path.join(patchRoot, entry.name)),
    }));
  return scanHermesEvaluatorIdentityProfiles({
    hermesVersionText: readUtf8(
      path.join(repoRoot, "scripts", "hermes-version.sh"),
    ),
    androidInstallerText: readUtf8(
      path.join(repoRoot, "scripts", "install-android-hermes.sh"),
    ),
    windowsInstallerText: readUtf8(
      path.join(repoRoot, "scripts", "install-windows-hermes.ps1"),
    ),
    windowsSourceBuildText: readUtf8(
      path.join(repoRoot, "scripts", "build-hermes-windows.ps1"),
    ),
    patchApplicationText: readUtf8(
      path.join(repoRoot, "scripts", "apply-hermes-patches.sh"),
    ),
    appleSourceBuildText: readUtf8(
      path.join(repoRoot, "scripts", "build-hermes.sh"),
    ),
    linuxSourceBuildText: readUtf8(
      path.join(repoRoot, "scripts", "build-hermes-linux.sh"),
    ),
    patches,
  });
}

function normalizedHermesEvaluatorProfiles(profiles, label) {
  if (!Array.isArray(profiles) || profiles.length === 0) {
    throw new Error(`${label}: Hermes engine identity profiles are absent`);
  }
  const ids = new Set();
  return profiles
    .map((profile) => {
      if (
        !profile ||
        typeof profile.id !== "string" ||
        !/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/u.test(profile.id) ||
        typeof profile.targetVariant !== "string" ||
        profile.targetVariant.length === 0 ||
        !profile.identity ||
        typeof profile.identity !== "object" ||
        Array.isArray(profile.identity)
      ) {
        throw new Error(`${label}: malformed Hermes engine identity profile`);
      }
      if (ids.has(profile.id)) {
        throw new Error(
          `${label}: duplicate Hermes engine profile ${profile.id}`,
        );
      }
      ids.add(profile.id);
      const reachableEvaluators = uniqueSorted(
        profile.reachableEvaluators ?? [],
      );
      if (
        reachableEvaluators.length === 0 ||
        reachableEvaluators.some((name) => !KNOWN_HERMES_EVALUATORS.has(name))
      ) {
        throw new Error(
          `${label}: Hermes engine profile ${profile.id} has unknown or empty evaluator reachability`,
        );
      }
      const sourceRefs = uniqueSorted(profile.sourceRefs ?? []);
      if (sourceRefs.length === 0) {
        throw new Error(
          `${label}: Hermes engine profile ${profile.id} has no source evidence`,
        );
      }
      return {
        id: profile.id,
        targetVariant: profile.targetVariant,
        identity: { ...profile.identity },
        reachableEvaluators,
        sourceRefs,
      };
    })
    .sort((left, right) => compareText(left.id, right.id));
}

/**
 * Reconcile inherited Hermes evaluator reachability with the exact lockdown
 * script that tames it. These globals do not appear as authored assignments,
 * so source-derived global scanning alone cannot observe them.
 */
export function scanLockdownEvaluatorSurfaces(
  text,
  sourcePath = "src/engine/hermes_runtime.cc",
  engineProfiles,
) {
  const profiles = normalizedHermesEvaluatorProfiles(
    engineProfiles,
    `${sourcePath}#lockdownJS`,
  );
  const tokens = lexCpp(text, sourcePath);
  const assignmentStarts = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].type === "identifier" &&
      tokens[index].value === "lockdownJS" &&
      tokens[index + 1]?.value === "="
    )
      assignmentStarts.push(index);
  }
  if (assignmentStarts.length !== 1) {
    throw new Error(
      `${sourcePath}#lockdownJS: expected one exact lockdown script assignment`,
    );
  }
  const assignmentStart = assignmentStarts[0];
  if (
    tokenSequenceCount(
      tokens.map((token) => token.value),
      ["std", "::", "string", "lockdownJS", "="],
    ) !== 1
  ) {
    throw new Error(
      `${sourcePath}#lockdownJS: expected one exact std::string declaration`,
    );
  }
  let assignmentEnd = assignmentStart + 2;
  while (assignmentEnd < tokens.length && tokens[assignmentEnd].value !== ";") {
    assignmentEnd += 1;
  }
  if (assignmentEnd === tokens.length) {
    throw new Error(`${sourcePath}#lockdownJS: unterminated script assignment`);
  }
  const assignmentTokens = tokens.slice(assignmentStart + 2, assignmentEnd);
  const assignmentValues = assignmentTokens.map((token) => token.value);
  const armedSelector = [
    "+",
    "(",
    "handle",
    "->",
    "armed",
    "?",
    "true",
    ":",
    "false",
    ")",
    "+",
  ];
  const selectorIndex = tokenSequenceIndex(assignmentValues, armedSelector);
  if (
    tokenSequenceCount(assignmentValues, armedSelector) !== 1 ||
    assignmentTokens[selectorIndex + 6]?.type !== "string" ||
    assignmentTokens[selectorIndex + 8]?.type !== "string"
  ) {
    throw new Error(
      `${sourcePath}#lockdownJS: expected one exact handle->armed selector`,
    );
  }
  const parts = assignmentTokens
    .filter((token) => token.type === "string")
    .map((token) => token.value);
  if (parts.length !== 4 || parts[1] !== "true" || parts[2] !== "false") {
    throw new Error(
      `${sourcePath}#lockdownJS: expected exact armed and diagnostic script parts`,
    );
  }
  // Reconstruct the production armed form, including any later `+=` raw
  // literals used to stay below compiler token-size limits. The diagnostic
  // false form is not target evidence and cannot satisfy the fail-closed
  // claim.
  let script = `${parts[0]}true${parts[3]}`;
  const bufferUse = tokens.findIndex(
    (token, index) =>
      token.value === "lockdownJS" &&
      tokens[index + 1]?.value === "." &&
      tokens[index + 2]?.value === "c_str",
  );
  if (bufferUse === -1) {
    throw new Error(
      `${sourcePath}#lockdownJS: expected one exact StringBuffer source route`,
    );
  }
  for (const [start, end] of cppStatementRanges(tokens)) {
    if (start <= assignmentEnd || end >= bufferUse) continue;
    const statement = tokens.slice(start, end + 1);
    if (cppAssignmentVariable(statement) !== "lockdownJS") continue;
    const equals = statement.findIndex((token) => token.value === "=");
    if (equals < 1 || statement[equals - 1]?.value !== "+") {
      throw new Error(
        `${sourcePath}#lockdownJS: post-declaration mutation must append exact literal bytes`,
      );
    }
    const appended = statement
      .slice(equals + 1)
      .filter((token) => token.type === "string")
      .map((token) => token.value);
    if (appended.length === 0) {
      throw new Error(
        `${sourcePath}#lockdownJS: append mutation omitted its literal bytes`,
      );
    }
    script += appended.join("");
  }
  const lockdownTamingDigest = `sha256-${sha256Hex(script)}`;
  const tokenValues = tokens.map((token) => token.value);
  for (const [label, sequence] of [
    [
      "StringBuffer source",
      ["StringBuffer", ">", "(", "lockdownJS", ".", "c_str", "(", ")", ")"],
    ],
    [
      "runtime evaluation",
      ["evaluateJavaScript", "(", "buffer", ",", "<lockdown>", ")"],
    ],
  ]) {
    if (tokenSequenceCount(tokenValues, sequence) !== 1) {
      throw new Error(
        `${sourcePath}#lockdownJS: expected one exact ${label} route`,
      );
    }
  }
  const engineIdentityReviewId = hermesEvaluatorReviewId(
    profiles,
    lockdownTamingDigest,
  );

  const tamingKinds = new Map();
  const addTamingFact = (name, kind) => {
    const prior = tamingKinds.get(name);
    if (prior && prior !== kind) {
      throw new Error(
        `${sourcePath}#lockdownJS: evaluator ${name} has conflicting taming shapes`,
      );
    }
    tamingKinds.set(name, kind);
  };
  walkAst(parseJavaScript(script, `${sourcePath}#lockdownJS`), (node) => {
    if (node.type !== "CallExpression" || node.callee?.type !== "Identifier")
      return;
    if (node.callee.name === "tameCtor") {
      for (const name of staticPropertyName(node.arguments[1])) {
        addTamingFact(name, "constructor");
      }
    }
    if (node.callee.name === "makeTamed") {
      for (const name of staticPropertyName(node.arguments[0])) {
        addTamingFact(name, "evaluator");
      }
    }
  });
  const tamedEvaluators = uniqueSorted(tamingKinds.keys());
  const reachableEvaluators = uniqueSorted(
    profiles.flatMap((profile) => profile.reachableEvaluators),
  );
  if (JSON.stringify(tamedEvaluators) !== JSON.stringify(reachableEvaluators)) {
    const reachable = new Set(reachableEvaluators);
    const tamed = new Set(tamedEvaluators);
    throw new Error(
      `${sourcePath}#lockdownJS: evaluator reachability/taming drift: untamed [${reachableEvaluators.filter((name) => !tamed.has(name)).join(", ")}]; tamed-but-unreachable [${tamedEvaluators.filter((name) => !reachable.has(name)).join(", ")}]`,
    );
  }

  return tamedEvaluators.map((globalName) => {
    const name = `global:${globalName}`;
    const applicableProfiles = profiles.filter((profile) =>
      profile.reachableEvaluators.includes(globalName),
    );
    const tamingRef = sourceSymbol(sourcePath, `lockdownJS:${globalName}`);
    const branches = applicableProfiles.map((profile) => {
      const identityDigest = sha256Hex(
        JSON.stringify(canonicalReviewValue(profile.identity)),
      );
      const identityAuthorityRef =
        profile.sourceRefs.find((sourceRef) =>
          sourceRef.startsWith("scripts/hermes-version.sh#"),
        ) ?? profile.sourceRefs[0];
      return {
        ...makeInstallationBranch(
          `hermes-intrinsic-${profile.id}-${identityDigest.slice(0, 12)}-${lockdownTamingDigest.slice(7, 19)}`,
          profile.targetVariant,
          [
            tamingRef,
            sourceSymbol(sourcePath, `lockdown-taming:${lockdownTamingDigest}`),
            ...profile.sourceRefs,
            sourceSymbol(
              sourcePathForRef(identityAuthorityRef),
              `evaluator-identity:sha256-${identityDigest}`,
            ),
          ],
          applicableProfiles.length > 1 ? "alternative" : "single",
        ),
        // @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory
        // — build-time engine overrides keep pin provenance provisional.
        // The checked-in pin is the default build authority, but build.rs can
        // consume an explicit external Hermes. WP10 must bind the exact engine
        // binary before this inventory evidence can become conformance proof.
        stubDisposition: "not-structurally-proven",
      };
    });
    return makeSurface(
      "native-op",
      name,
      uniqueSorted(branches.flatMap((branch) => branch.sourceRefs)),
      {
        metadata: {
          branches,
          engineIdentityReviewId,
          engineProfileIds: applicableProfiles.map((profile) => profile.id),
          evidenceType: "hermes-evaluator-reachability",
          exportName: globalName,
          globalName,
          installationBranches: branches,
          lockdownTamingDigest,
          memberKinds: ["hermes-intrinsic-reachability"],
          memberName: null,
          moduleSpecifiers: [],
          publicReadAccessSourceProven: true,
          reachability:
            globalName === "eval" || globalName === "Function"
              ? "inherited-global"
              : "intrinsic-constructor",
          sourceKey: "hermes_intrinsic_evaluators",
          surfaceType: "global-api",
          tamingEvidence: "lockdownJS",
          tamingKind: tamingKinds.get(globalName),
          valueShape: "callable",
        },
      },
    );
  });
}

/** Pure normalizer for the values imported from modules.ts. */
export function scanModuleSpecifierEntries(
  moduleExports,
  sourcePath = "modules.ts",
) {
  const {
    bootstrapInternalModules = [],
    meta,
    sources,
    specifiers,
  } = moduleExports ?? {};
  if (!Array.isArray(specifiers) || specifiers.length === 0) {
    throw new Error(
      `${sourcePath}: exported specifiers must be a non-empty array`,
    );
  }
  if (!sources || typeof sources !== "object") {
    throw new Error(`${sourcePath}: exported sources map is missing`);
  }
  const defaults = meta?.defaults ?? {};
  if (
    !Array.isArray(bootstrapInternalModules) ||
    bootstrapInternalModules.some(
      (name) => typeof name !== "string" || name.length === 0,
    ) ||
    new Set(bootstrapInternalModules).size !== bootstrapInternalModules.length
  ) {
    throw new Error(
      `${sourcePath}: bootstrapInternalModules must be a unique string array`,
    );
  }
  const bootstrapInternalSet = new Set(bootstrapInternalModules);
  const rows = [];
  const names = new Set();

  for (const [groupIndex, group] of specifiers.entries()) {
    if (!group || !Array.isArray(group.names) || group.names.length === 0) {
      throw new Error(
        `${sourcePath}: specifier group ${groupIndex} has no names`,
      );
    }
    if (typeof group.source !== "string" || group.source.length === 0) {
      throw new Error(
        `${sourcePath}: specifier group ${groupIndex} has no source key`,
      );
    }
    if (!Object.hasOwn(sources, group.source)) {
      throw new Error(
        `${sourcePath}: unknown source key ${JSON.stringify(group.source)}`,
      );
    }
    for (const name of group.names) {
      if (typeof name !== "string" || name.length === 0) {
        throw new Error(
          `${sourcePath}: specifier group ${groupIndex} contains an empty name`,
        );
      }
      if (names.has(name)) {
        throw new Error(
          `${sourcePath}: duplicate builtin specifier ${JSON.stringify(name)}`,
        );
      }
      names.add(name);
      const bundleExternal =
        group.bundleExternal ?? defaults.bundleExternal ?? true;
      const moduleBuiltin =
        group.moduleBuiltin ?? defaults.moduleBuiltin ?? true;
      // @ref LLP 0004#one-source-many-specifiers — every registry alias remains
      // package-importable under an exact policy grant even when it is neither
      // advertised nor bundler-external. A same-named bootstrap internal is the
      // exception: loadInternal() preempts the manifest source.
      const importReachability = bootstrapInternalSet.has(name)
        ? "bootstrap-internal"
        : "public";
      rows.push(
        makeSurface(
          "builtin",
          name,
          [sourceSymbol(sourcePath, `specifiers:${group.source}`)],
          {
            metadata: {
              sourceKey: group.source,
              bundleExternal,
              importReachability,
              moduleBuiltin,
            },
          },
        ),
      );
    }
  }
  assertUniqueObservedKeys(rows, sourcePath);
  return sortSurfaces(rows);
}

/** Import modules.ts through Bun and normalize its authored specifier groups. */
export async function scanModuleSpecifiers(
  modulePath,
  sourcePath = "modules.ts",
) {
  const moduleExports = await import(pathToFileURL(modulePath).href);
  return scanModuleSpecifierEntries(moduleExports, sourcePath);
}

const REVIEWED_DNS_PROMISE_ERROR_CODES = Object.freeze(
  [
    "ADDRGETNETWORKPARAMS",
    "BADFAMILY",
    "BADFLAGS",
    "BADHINTS",
    "BADNAME",
    "BADQUERY",
    "BADRESP",
    "BADSTR",
    "CANCELLED",
    "CONNREFUSED",
    "DESTRUCTION",
    "EOF",
    "FILE",
    "FORMERR",
    "LOADIPHLPAPI",
    "NODATA",
    "NOMEM",
    "NONAME",
    "NOTFOUND",
    "NOTIMP",
    "NOTINITIALIZED",
    "REFUSED",
    "SERVFAIL",
    "TIMEOUT",
  ].sort(compareText),
);

const REVIEWED_DNS_PROMISE_TOP_OPERATIONS = Object.freeze(
  [
    "Resolver",
    "getDefaultResultOrder",
    "getServers",
    "lookup",
    "lookupService",
    "resolve",
    "resolve4",
    "resolve6",
    "resolveAny",
    "resolveCaa",
    "resolveCname",
    "resolveMx",
    "resolveNaptr",
    "resolveNs",
    "resolvePtr",
    "resolveSoa",
    "resolveSrv",
    "resolveTxt",
    "reverse",
    "setDefaultResultOrder",
    "setServers",
  ].sort(compareText),
);

const REVIEWED_DNS_PROMISE_RESOLVER_OWN_OPERATIONS = Object.freeze(
  [
    "resolve",
    "resolve4",
    "resolve6",
    "resolveAny",
    "resolveCaa",
    "resolveCname",
    "resolveMx",
    "resolveNaptr",
    "resolveNs",
    "resolvePtr",
    "resolveSoa",
    "resolveSrv",
    "resolveTxt",
    "reverse",
  ].sort(compareText),
);

const REVIEWED_DNS_PROMISE_RESOLVER_INHERITED_OPERATIONS = Object.freeze(
  ["cancel", "getServers", "setLocalAddress", "setServers"].sort(
    compareText,
  ),
);

const REVIEWED_DNS_PROMISE_RESOLVER_OPERATIONS = Object.freeze(
  uniqueSorted([
    ...REVIEWED_DNS_PROMISE_RESOLVER_OWN_OPERATIONS,
    ...REVIEWED_DNS_PROMISE_RESOLVER_INHERITED_OPERATIONS,
  ]),
);

export const DNS_PROMISE_EXPORT_SHAPE_REVIEW_SCHEMA =
  "ibex/capsec-dns-promises-export-shape-review/1";
export const REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID =
  "sha256-161c4e4bf9027d0d3e4f9427954c18529f7ef0bd727be9064fc8f79270a75c75";

const AST_REVIEW_OMITTED_KEYS = new Set([
  "comments",
  "end",
  "errors",
  "extra",
  "loc",
  "start",
  "tokens",
]);

function canonicalReviewedAst(value) {
  if (Array.isArray(value)) return value.map(canonicalReviewedAst);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .filter(
          (key) =>
            !AST_REVIEW_OMITTED_KEYS.has(key) &&
            !/(?:^|[a-z])Comments$/u.test(key),
        )
        .sort(compareText)
        .map((key) => [key, canonicalReviewedAst(value[key])]),
    );
  }
  return value;
}

function dnsPromiseExportShapeReviewId({
  carrierProgram,
  carrierSourcePath,
  providerProgram,
  providerSourcePath,
}) {
  return `sha256-${sha256Hex(
    JSON.stringify(
      canonicalReviewValue({
        carrier: {
          ast: canonicalReviewedAst(carrierProgram),
          sourceKey: "node_dns_promises",
          sourcePath: carrierSourcePath,
        },
        provider: {
          ast: canonicalReviewedAst(providerProgram),
          sourceKey: "node_dns",
          sourcePath: providerSourcePath,
        },
        schema: DNS_PROMISE_EXPORT_SHAPE_REVIEW_SCHEMA,
      }),
    ),
  )}`;
}

export function deriveDnsPromiseExportShapeReviewId(
  carrierText,
  providerText,
  {
    carrierSourcePath = "src/builtins/dns-promises.js",
    providerSourcePath = "src/builtins/dns.js",
  } = {},
) {
  return dnsPromiseExportShapeReviewId({
    carrierProgram: parseJavaScript(carrierText, carrierSourcePath),
    carrierSourcePath,
    providerProgram: parseJavaScript(providerText, providerSourcePath),
    providerSourcePath,
  });
}

function assertReviewedNameSet(actualNames, expectedNames, label, sourcePath) {
  const duplicateNames = uniqueSorted(
    actualNames.filter(
      (name, index) => actualNames.indexOf(name) !== index,
    ),
  );
  const actual = uniqueSorted(actualNames);
  const expected = uniqueSorted(expectedNames);
  if (
    duplicateNames.length > 0 ||
    JSON.stringify(actual) !== JSON.stringify(expected)
  ) {
    const actualSet = new Set(actual);
    const expectedSet = new Set(expected);
    throw new Error(
      `${sourcePath}: ${label} drift: missing [${expected
        .filter((name) => !actualSet.has(name))
        .join(", ")}]; extra [${actual
        .filter((name) => !expectedSet.has(name))
        .join(", ")}]; duplicates [${duplicateNames.join(", ")}]`,
    );
  }
}

function exactVariableDeclarator(program, name, sourcePath) {
  const declarations = [];
  walkAst(program, (node) => {
    if (
      node.type === "VariableDeclarator" &&
      node.id?.type === "Identifier" &&
      node.id.name === name
    ) {
      declarations.push(node);
    }
  });
  if (declarations.length !== 1) {
    throw new Error(
      `${sourcePath}: expected one exact ${name} variable declaration; found ${declarations.length}`,
    );
  }
  return declarations[0];
}

function exactRootModuleExportAssignment(program, sourcePath) {
  const assignments = [];
  walkAst(program, (node) => {
    if (
      node.type === "AssignmentExpression" &&
      node.operator === "=" &&
      isModuleExports(node.left)
    ) {
      assignments.push(node);
    }
  });
  if (assignments.length !== 1) {
    throw new Error(
      `${sourcePath}: expected one exact module.exports assignment; found ${assignments.length}`,
    );
  }
  return assignments[0];
}

function exactObjectPropertyEntries(object, label, sourcePath) {
  if (object?.type !== "ObjectExpression") {
    throw new Error(`${sourcePath}: ${label} must be an object literal`);
  }
  const entries = new Map();
  for (const property of object.properties) {
    if (
      property.type !== "ObjectProperty" ||
      property.computed ||
      !["Identifier", "StringLiteral"].includes(property.key?.type)
    ) {
      throw new Error(
        `${registrationContext("", property, sourcePath)}: ${label} contains an unresolved property shape`,
      );
    }
    const name =
      property.key.type === "Identifier"
        ? property.key.name
        : property.key.value;
    if (entries.has(name)) {
      throw new Error(`${sourcePath}: ${label} duplicates property ${name}`);
    }
    entries.set(name, property);
  }
  return entries;
}

function exactUnwrittenBinding(bindingIndex, declaration, label, sourcePath) {
  const binding = bindingIndex.resolve(declaration.id);
  if (!binding || binding.node !== declaration || binding.writes !== 0) {
    throw new Error(
      `${sourcePath}: ${label} must resolve to one immutable lexical binding`,
    );
  }
  return binding;
}

function isNonReferenceIdentifier(node, parent) {
  return Boolean(
    (parent?.type === "MemberExpression" &&
      parent.property === node &&
      !parent.computed) ||
      (parent?.type === "ObjectProperty" &&
        parent.key === node &&
        parent.value !== node &&
        !parent.computed),
  );
}

function assertReviewedBindingReferences({
  program,
  bindingIndex,
  binding,
  declaration,
  label,
  sourcePath,
  allowed,
}) {
  walkAstWithAncestors(program, (node, ancestors) => {
    if (
      node.type !== "Identifier" ||
      bindingIndex.resolve(node) !== binding ||
      node === declaration.id
    ) {
      return;
    }
    const parent = ancestors.at(-1);
    if (isNonReferenceIdentifier(node, parent)) return;
    if (allowed(node, parent, ancestors)) return;
    throw new Error(
      `${registrationContext("", node, sourcePath)}: unreviewed ${label} reference`,
    );
  });
}

function isCodeIndex(node) {
  return Boolean(
    node?.type === "MemberExpression" &&
      node.computed &&
      node.object?.type === "Identifier" &&
      node.object.name === "codes" &&
      node.property?.type === "Identifier" &&
      node.property.name === "i",
  );
}

function isCodeMember(node, objectName) {
  return Boolean(
    node?.type === "MemberExpression" &&
      node.computed &&
      node.object?.type === "Identifier" &&
      node.object.name === objectName &&
      isCodeIndex(node.property),
  );
}

function assertExactCarrierCodeCopy(program, sourcePath) {
  const writes = [];
  let writeAncestors = [];
  walkAstWithAncestors(program, (node, ancestors) => {
    if (
      node.type === "AssignmentExpression" &&
      node.left?.type === "MemberExpression" &&
      node.left.object?.type === "Identifier" &&
      node.left.object.name === "promises"
    ) {
      writes.push(node);
      writeAncestors = ancestors;
    }
  });
  if (
    writes.length !== 1 ||
    writes[0].operator !== "=" ||
    !isCodeMember(writes[0].left, "promises") ||
    !isCodeMember(writes[0].right, "dns")
  ) {
    throw new Error(
      `${sourcePath}: expected one exact promises[codes[i]] copy`,
    );
  }
  const assignment = writes[0];
  let loop = null;
  for (let index = writeAncestors.length - 1; index >= 0; index -= 1) {
    if (writeAncestors[index].type === "ForStatement") {
      loop = writeAncestors[index];
      break;
    }
  }
  const initializer = loop?.init;
  const declaration = initializer?.declarations?.[0];
  const test = loop?.test;
  const update = loop?.update;
  const bodyStatement = loop?.body?.body?.[0];
  const consequent = bodyStatement?.consequent;
  const copiedStatement =
    consequent?.type === "BlockStatement"
      ? consequent.body?.[0]
      : consequent;
  if (
    !loop ||
    initializer?.type !== "VariableDeclaration" ||
    initializer.declarations.length !== 1 ||
    declaration?.id?.type !== "Identifier" ||
    declaration.id.name !== "i" ||
    declaration.init?.type !== "NumericLiteral" ||
    declaration.init.value !== 0 ||
    test?.type !== "BinaryExpression" ||
    test.operator !== "<" ||
    test.left?.type !== "Identifier" ||
    test.left.name !== "i" ||
    test.right?.type !== "MemberExpression" ||
    test.right.object?.type !== "Identifier" ||
    test.right.object.name !== "codes" ||
    directMemberName(test.right) !== "length" ||
    update?.type !== "UpdateExpression" ||
    update.operator !== "++" ||
    update.argument?.type !== "Identifier" ||
    update.argument.name !== "i" ||
    loop.body?.type !== "BlockStatement" ||
    loop.body.body.length !== 1 ||
    bodyStatement?.type !== "IfStatement" ||
    bodyStatement.alternate !== null ||
    bodyStatement.test?.type !== "BinaryExpression" ||
    bodyStatement.test.operator !== "!==" ||
    !isCodeMember(bodyStatement.test.left, "dns") ||
    bodyStatement.test.right?.type !== "Identifier" ||
    bodyStatement.test.right.name !== "undefined" ||
    copiedStatement?.type !== "ExpressionStatement" ||
    copiedStatement.expression !== assignment ||
    (consequent?.type === "BlockStatement" && consequent.body.length !== 1)
  ) {
    throw new Error(`${sourcePath}: reviewed error-code copy loop drifted`);
  }
  return assignment;
}

function isSourceProvenCallable(expression, bindingIndex, seen = new Set()) {
  if (
    expression?.type === "FunctionExpression" ||
    expression?.type === "ArrowFunctionExpression"
  ) {
    return true;
  }
  if (expression?.type === "Identifier") {
    const binding = bindingIndex.resolve(expression);
    if (!binding || binding.writes !== 0 || seen.has(binding)) return false;
    seen.add(binding);
    if (
      binding.node?.type === "FunctionDeclaration" ||
      binding.node?.type === "ClassDeclaration"
    ) {
      return true;
    }
    if (binding.node?.type === "VariableDeclarator") {
      return isSourceProvenCallable(binding.node.init, bindingIndex, seen);
    }
    return false;
  }
  if (
    expression?.type === "CallExpression" &&
    expression.callee?.type === "Identifier"
  ) {
    const binding = bindingIndex.resolve(expression.callee);
    if (
      !binding ||
      binding.writes !== 0 ||
      binding.node?.type !== "FunctionDeclaration" ||
      binding.node.body?.type !== "BlockStatement" ||
      binding.node.body.body.length !== 1
    ) {
      return false;
    }
    const statement = binding.node.body.body[0];
    return Boolean(
      statement.type === "ReturnStatement" &&
        (statement.argument?.type === "FunctionExpression" ||
          statement.argument?.type === "ArrowFunctionExpression"),
    );
  }
  return false;
}

function prototypeAssignments(program, owner, sourcePath) {
  const whole = [];
  const members = new Map();
  walkAst(program, (node) => {
    if (node.type !== "AssignmentExpression" || node.operator !== "=") return;
    if (prototypeOwner(node.left) === owner) {
      whole.push(node);
      return;
    }
    if (
      node.left?.type !== "MemberExpression" ||
      prototypeOwner(node.left.object) !== owner
    ) {
      return;
    }
    if (node.left.computed) {
      throw new Error(
        `${registrationContext("", node, sourcePath)}: ${owner}.prototype has a computed write`,
      );
    }
    const name = directMemberName(node.left);
    if (!name || members.has(name)) {
      throw new Error(
        `${sourcePath}: ${owner}.prototype has a duplicate or unresolved member`,
      );
    }
    members.set(name, node);
  });
  return { whole, members };
}

function isExactPromiseResolverInheritance(expression) {
  const argument = expression?.arguments?.[0];
  return Boolean(
    expression?.type === "CallExpression" &&
      expression.arguments.length === 1 &&
      expression.callee?.type === "MemberExpression" &&
      expression.callee.object?.type === "Identifier" &&
      expression.callee.object.name === "Object" &&
      directMemberName(expression.callee) === "create" &&
      prototypeOwner(argument) === "Resolver",
  );
}

function assertReviewedPrototypeObjectUses({
  program,
  owner,
  inheritance,
  memberAssignments,
  sourcePath,
}) {
  walkAstWithAncestors(program, (node, ancestors) => {
    if (prototypeOwner(node) !== owner) return;
    const parent = ancestors.at(-1);
    if (owner === "PromiseResolver" && node === inheritance.left) return;
    if (
      owner === "Resolver" &&
      node === inheritance.right?.arguments?.[0]
    ) {
      return;
    }
    if (
      parent?.type === "MemberExpression" &&
      parent.object === node
    ) {
      const mutation = ancestors.at(-2);
      if (
        mutation?.type === "AssignmentExpression" &&
        mutation.left === parent &&
        mutation.operator === "=" &&
        memberAssignments.get(directMemberName(parent)) === mutation
      ) {
        return;
      }
      const applyMember = ancestors.at(-2);
      const applyCall = ancestors.at(-3);
      if (
        owner === "Resolver" &&
        parent.computed &&
        parent.property?.type === "Identifier" &&
        parent.property.name === "method" &&
        applyMember?.type === "MemberExpression" &&
        applyMember.object === parent &&
        directMemberName(applyMember) === "apply" &&
        applyCall?.type === "CallExpression" &&
        applyCall.callee === applyMember
      ) {
        return;
      }
      throw new Error(
        `${sourcePath}: ${owner}.prototype has an unreviewed member access or mutation`,
      );
    }
    throw new Error(
      `${registrationContext("", node, sourcePath)}: unreviewed ${owner}.prototype object escape`,
    );
  });
}

function nearestFunctionAncestor(ancestors) {
  for (let index = ancestors.length - 1; index >= 0; index -= 1) {
    if (isJavaScriptFunctionNode(ancestors[index])) return ancestors[index];
  }
  return null;
}

function assertReviewedResolverInstanceInitialization({
  bindingIndex,
  program,
  providerText,
  resolverFunction,
  promiseResolverFunction,
  sourcePath,
}) {
  const directWrites = new Map([
    [resolverFunction, []],
    [promiseResolverFunction, []],
  ]);
  walkAstWithAncestors(program, (node, ancestors) => {
    if (node.type !== "ThisExpression") return;
    const owner = nearestFunctionAncestor(ancestors);
    if (!directWrites.has(owner)) return;
    const parent = ancestors.at(-1);
    if (
      parent?.type === "BinaryExpression" &&
      parent.operator === "instanceof" &&
      parent.left === node
    ) {
      return;
    }
    if (
      owner === promiseResolverFunction &&
      parent?.type === "CallExpression" &&
      parent.arguments[0] === node &&
      parent.callee?.type === "MemberExpression" &&
      parent.callee.object?.type === "Identifier" &&
      parent.callee.object.name === "Resolver" &&
      directMemberName(parent.callee) === "call" &&
      parent.arguments.length === 2 &&
      parent.arguments[1]?.type === "Identifier" &&
      parent.arguments[1].name === "options"
    ) {
      return;
    }
    if (
      owner === resolverFunction &&
      parent?.type === "VariableDeclarator" &&
      parent.id?.type === "Identifier" &&
      parent.id.name === "self" &&
      parent.init === node
    ) {
      return;
    }
    if (parent?.type === "MemberExpression" && parent.object === node) {
      const name = directMemberName(parent);
      if (parent.computed || !name?.startsWith("_")) {
        throw new Error(
          `${registrationContext(providerText, parent, sourcePath)}: Resolver constructor exposes an unreviewed public instance member`,
        );
      }
      const mutation = ancestors.at(-2);
      if (
        mutation?.type === "AssignmentExpression" &&
        mutation.left === parent
      ) {
        if (mutation.operator !== "=") {
          throw new Error(
            `${sourcePath}: Resolver instance initializer uses an unreviewed compound write`,
          );
        }
        directWrites.get(owner).push({ assignment: mutation, name });
      }
      return;
    }
    throw new Error(
      `${registrationContext(providerText, node, sourcePath)}: Resolver constructor has an unreviewed this escape`,
    );
  });
  assertReviewedNameSet(
    directWrites.get(resolverFunction).map(({ name }) => name),
    [
      "_activeQueries",
      "_handle",
      "_localAddressIPv4",
      "_localAddressIPv6",
      "_maxTimeout",
      "_nextServerIndex",
      "_pendingQueries",
      "_servers",
      "_timeout",
      "_tries",
      "_usesCustomServers",
    ],
    "Resolver constructor instance domain",
    sourcePath,
  );
  assertReviewedNameSet(
    directWrites.get(promiseResolverFunction).map(({ name }) => name),
    [],
    "PromiseResolver constructor instance domain",
    sourcePath,
  );

  const selfDeclaration = exactVariableDeclarator(program, "self", sourcePath);
  if (selfDeclaration.init?.type !== "ThisExpression") {
    throw new Error(`${sourcePath}: Resolver self alias drifted`);
  }
  const selfBinding = exactUnwrittenBinding(
    bindingIndex,
    selfDeclaration,
    "Resolver self alias",
    sourcePath,
  );
  assertReviewedBindingReferences({
    program,
    bindingIndex,
    binding: selfBinding,
    declaration: selfDeclaration,
    label: "Resolver self alias",
    sourcePath,
    allowed: (node, parent) => {
      if (
        parent?.type === "MemberExpression" &&
        parent.object === node &&
        !parent.computed &&
        directMemberName(parent)?.startsWith("_")
      ) {
        return true;
      }
      return Boolean(
        parent?.type === "CallExpression" &&
          parent.arguments[0] === node &&
          parent.arguments.length === 1 &&
          parent.callee?.type === "Identifier" &&
          parent.callee.name === "_cancelResolverQueries",
      );
    },
  });
  const handleAssignment = directWrites
    .get(resolverFunction)
    .find(({ name }) => name === "_handle")?.assignment;
  const handleEntries = exactObjectPropertyEntries(
    handleAssignment?.right,
    "Resolver instance _handle",
    sourcePath,
  );
  assertReviewedNameSet(
    [...handleEntries.keys()],
    ["cancel", "getServers", "setServers"],
    "Resolver instance _handle callable domain",
    sourcePath,
  );
  for (const [name, property] of handleEntries) {
    if (!isSourceProvenCallable(property.value, bindingIndex)) {
      throw new Error(
        `${registrationContext(providerText, property, sourcePath)}: Resolver._handle.${name} is not source-proven callable`,
      );
    }
  }
  return { handleOperations: uniqueSorted(handleEntries.keys()) };
}

/**
 * Resolve the one reviewed cross-source CommonJS object projection used by
 * `dns/promises`. This proves the carrier/provider object identity and closes
 * the exact callable property domain, but deliberately leaves every call route
 * ambiguous until a public operation recipe executes it.
 *
 * @ref LLP 0004#one-source-many-specifiers — projected exports remain owned by
 * the public carrier source rather than by the provider's aliases.
 * @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — an
 * unreviewed write, alias, member, or prototype shape fails inventory.
 */
export function scanReviewedDnsPromisesProjection(
  carrierText,
  providerText,
  {
    carrierSourceKind = "generated",
    carrierSourcePath = "src/builtins/dns-promises.js",
    moduleSpecifiers = ["dns/promises", "node:dns/promises"],
    providerSourcePath = "src/builtins/dns.js",
  } = {},
) {
  const carrierProgram = parseJavaScript(carrierText, carrierSourcePath);
  const providerProgram = parseJavaScript(providerText, providerSourcePath);
  const carrierBindings = javascriptLexicalBindingIndex(carrierProgram);
  const providerBindings = javascriptLexicalBindingIndex(providerProgram);

  const dnsDeclaration = exactVariableDeclarator(
    carrierProgram,
    "dns",
    carrierSourcePath,
  );
  const carrierPromisesDeclaration = exactVariableDeclarator(
    carrierProgram,
    "promises",
    carrierSourcePath,
  );
  const codesDeclaration = exactVariableDeclarator(
    carrierProgram,
    "codes",
    carrierSourcePath,
  );
  if (
    dnsDeclaration.init?.type !== "CallExpression" ||
    dnsDeclaration.init.callee?.type !== "Identifier" ||
    dnsDeclaration.init.callee.name !== "require" ||
    dnsDeclaration.init.arguments.length !== 1 ||
    dnsDeclaration.init.arguments[0]?.type !== "StringLiteral" ||
    dnsDeclaration.init.arguments[0].value !== "dns"
  ) {
    throw new Error(
      `${carrierSourcePath}: dns must be bound by exact require("dns")`,
    );
  }
  const carrierRequireCalls = [];
  walkAst(carrierProgram, (node) => {
    if (
      node.type === "CallExpression" &&
      ((node.callee?.type === "Identifier" &&
        node.callee.name === "require") ||
        (node.callee?.type === "MemberExpression" &&
          directMemberName(node.callee) === "require"))
    ) {
      carrierRequireCalls.push(node);
    }
  });
  if (
    carrierRequireCalls.length !== 1 ||
    carrierRequireCalls[0] !== dnsDeclaration.init
  ) {
    throw new Error(
      `${carrierSourcePath}: reviewed carrier must have exactly one require call`,
    );
  }
  if (
    carrierPromisesDeclaration.init?.type !== "MemberExpression" ||
    carrierPromisesDeclaration.init.object?.type !== "Identifier" ||
    carrierPromisesDeclaration.init.object.name !== "dns" ||
    carrierPromisesDeclaration.init.computed ||
    directMemberName(carrierPromisesDeclaration.init) !== "promises"
  ) {
    throw new Error(
      `${carrierSourcePath}: promises must be bound to exact dns.promises`,
    );
  }
  if (
    codesDeclaration.init?.type !== "ArrayExpression" ||
    codesDeclaration.init.elements.some(
      (element) => element?.type !== "StringLiteral",
    )
  ) {
    throw new Error(
      `${carrierSourcePath}: error codes must be an exact string array`,
    );
  }
  assertReviewedNameSet(
    codesDeclaration.init.elements.map((element) => element.value),
    REVIEWED_DNS_PROMISE_ERROR_CODES,
    "error-code domain",
    carrierSourcePath,
  );
  const carrierExport = exactRootModuleExportAssignment(
    carrierProgram,
    carrierSourcePath,
  );
  if (
    carrierExport.right?.type !== "Identifier" ||
    carrierExport.right.name !== "promises"
  ) {
    throw new Error(
      `${carrierSourcePath}: module.exports must be the promises binding`,
    );
  }
  walkAstWithAncestors(carrierProgram, (node, ancestors) => {
    const parent = ancestors.at(-1);
    if (
      (node.type === "MemberExpression" &&
        isModuleExports(node) &&
        node !== carrierExport.left) ||
      (node.type === "Identifier" &&
        node.name === "exports" &&
        !(
          parent?.type === "MemberExpression" &&
          parent.property === node &&
          !parent.computed
        ))
    ) {
      throw new Error(
        `${carrierSourcePath}: exported promises object has an unreviewed reacquisition`,
      );
    }
  });
  const codeCopy = assertExactCarrierCodeCopy(
    carrierProgram,
    carrierSourcePath,
  );
  const dnsBinding = exactUnwrittenBinding(
    carrierBindings,
    dnsDeclaration,
    "dns",
    carrierSourcePath,
  );
  const carrierPromisesBinding = exactUnwrittenBinding(
    carrierBindings,
    carrierPromisesDeclaration,
    "promises",
    carrierSourcePath,
  );
  const codesBinding = exactUnwrittenBinding(
    carrierBindings,
    codesDeclaration,
    "codes",
    carrierSourcePath,
  );
  assertReviewedBindingReferences({
    program: carrierProgram,
    bindingIndex: carrierBindings,
    binding: dnsBinding,
    declaration: dnsDeclaration,
    label: "dns carrier",
    sourcePath: carrierSourcePath,
    allowed: (_node, parent) =>
      parent?.type === "MemberExpression" &&
      parent.object?.type === "Identifier" &&
      parent.object.name === "dns" &&
      (parent === carrierPromisesDeclaration.init ||
        parent === codeCopy.right ||
        isCodeMember(parent, "dns")),
  });
  assertReviewedBindingReferences({
    program: carrierProgram,
    bindingIndex: carrierBindings,
    binding: carrierPromisesBinding,
    declaration: carrierPromisesDeclaration,
    label: "promises carrier",
    sourcePath: carrierSourcePath,
    allowed: (_node, parent, ancestors) =>
      (parent === carrierExport && carrierExport.right === _node) ||
      (parent === codeCopy.left &&
        ancestors.at(-2) === codeCopy &&
        codeCopy.left.object === _node),
  });
  assertReviewedBindingReferences({
    program: carrierProgram,
    bindingIndex: carrierBindings,
    binding: codesBinding,
    declaration: codesDeclaration,
    label: "error-code table",
    sourcePath: carrierSourcePath,
    allowed: (_node, parent) =>
      parent?.type === "MemberExpression" &&
      parent.object === _node &&
      (directMemberName(parent) === "length" || isCodeIndex(parent)),
  });

  const providerPromisesDeclaration = exactVariableDeclarator(
    providerProgram,
    "promises",
    providerSourcePath,
  );
  const providerPromisesBinding = exactUnwrittenBinding(
    providerBindings,
    providerPromisesDeclaration,
    "provider promises",
    providerSourcePath,
  );
  const promiseEntries = exactObjectPropertyEntries(
    providerPromisesDeclaration.init,
    "promises object",
    providerSourcePath,
  );
  assertReviewedNameSet(
    [...promiseEntries.keys()],
    REVIEWED_DNS_PROMISE_TOP_OPERATIONS,
    "promises operation domain",
    providerSourcePath,
  );
  for (const [name, property] of promiseEntries) {
    if (!isSourceProvenCallable(property.value, providerBindings)) {
      throw new Error(
        `${registrationContext(providerText, property, providerSourcePath)}: promises.${name} is not source-proven callable`,
      );
    }
  }

  const providerPromiseWrites = new Map();
  walkAst(providerProgram, (node) => {
    if (
      node.type !== "AssignmentExpression" ||
      node.operator !== "=" ||
      node.left?.type !== "MemberExpression" ||
      node.left.object?.type !== "Identifier" ||
      node.left.object.name !== "promises"
    ) {
      return;
    }
    if (node.left.computed) {
      throw new Error(
        `${registrationContext(providerText, node, providerSourcePath)}: promises has a computed write`,
      );
    }
    const name = directMemberName(node.left);
    if (!name || providerPromiseWrites.has(name)) {
      throw new Error(
        `${providerSourcePath}: promises has a duplicate or unresolved write`,
      );
    }
    providerPromiseWrites.set(name, node);
  });
  assertReviewedNameSet(
    [...providerPromiseWrites.keys()],
    ["Resolver", ...REVIEWED_DNS_PROMISE_ERROR_CODES],
    "promises post-declaration writes",
    providerSourcePath,
  );
  for (const code of REVIEWED_DNS_PROMISE_ERROR_CODES) {
    const value = providerPromiseWrites.get(code)?.right;
    if (value?.type !== "Identifier" || value.name !== code) {
      throw new Error(
        `${providerSourcePath}: promises.${code} must copy the exact ${code} binding`,
      );
    }
  }
  const resolverWrite = providerPromiseWrites.get("Resolver");
  if (
    resolverWrite?.right?.type !== "Identifier" ||
    resolverWrite.right.name !== "PromiseResolver" ||
    !isSourceProvenCallable(resolverWrite.right, providerBindings)
  ) {
    throw new Error(
      `${providerSourcePath}: promises.Resolver must bind PromiseResolver`,
    );
  }
  const resolverFunction = providerBindings.resolve(
    promiseEntries.get("Resolver").value,
  )?.node;
  const promiseResolverFunction = providerBindings.resolve(
    resolverWrite.right,
  )?.node;
  if (
    resolverFunction?.type !== "FunctionDeclaration" ||
    resolverFunction.id?.name !== "Resolver" ||
    promiseResolverFunction?.type !== "FunctionDeclaration" ||
    promiseResolverFunction.id?.name !== "PromiseResolver"
  ) {
    throw new Error(
      `${providerSourcePath}: reviewed Resolver constructors are not exact function declarations`,
    );
  }
  const resolverInstanceShape = assertReviewedResolverInstanceInitialization({
    bindingIndex: providerBindings,
    program: providerProgram,
    providerText,
    resolverFunction,
    promiseResolverFunction,
    sourcePath: providerSourcePath,
  });

  const providerExport = exactRootModuleExportAssignment(
    providerProgram,
    providerSourcePath,
  );
  const providerDefaultAssignments = [];
  walkAst(providerProgram, (node) => {
    if (
      node.type === "AssignmentExpression" &&
      node.operator === "=" &&
      node.left?.type === "MemberExpression" &&
      isModuleExports(node.left.object) &&
      directMemberName(node.left) === "default" &&
      isModuleExports(node.right)
    ) {
      providerDefaultAssignments.push(node);
    }
  });
  if (providerDefaultAssignments.length !== 1) {
    throw new Error(
      `${providerSourcePath}: expected one exact module.exports.default self-alias`,
    );
  }
  const providerDefault = providerDefaultAssignments[0];
  const reviewedModuleExportsNodes = new Set([
    providerExport.left,
    providerDefault.left.object,
    providerDefault.right,
  ]);
  walkAstWithAncestors(providerProgram, (node, ancestors) => {
    const parent = ancestors.at(-1);
    if (
      (node.type === "MemberExpression" &&
        isModuleExports(node) &&
        !reviewedModuleExportsNodes.has(node)) ||
      (node.type === "Identifier" &&
        node.name === "exports" &&
        !(
          parent?.type === "MemberExpression" &&
          parent.property === node &&
          !parent.computed
        ))
    ) {
      throw new Error(
        `${providerSourcePath}: module.exports has an unreviewed reference`,
      );
    }
  });
  const providerExportEntries = exactObjectPropertyEntries(
    providerExport.right,
    "module.exports object",
    providerSourcePath,
  );
  const exportedPromises = providerExportEntries.get("promises");
  if (
    exportedPromises?.value?.type !== "Identifier" ||
    providerBindings.resolve(exportedPromises.value) !== providerPromisesBinding
  ) {
    throw new Error(
      `${providerSourcePath}: module.exports.promises must bind the reviewed promises object`,
    );
  }
  walkAst(providerProgram, (node) => {
    if (node.type === "MemberExpression") {
      const chain = staticMemberChain(node);
      if (
        (chain?.[0] === "module" &&
          chain[1] === "exports" &&
          chain[2] === "promises") ||
        (chain?.[0] === "exports" && chain[1] === "promises")
      ) {
        throw new Error(
          `${providerSourcePath}: module.exports.promises has an unreviewed reacquisition`,
        );
      }
    }
    if (
      node.type === "AssignmentExpression" &&
      node.left?.type === "MemberExpression" &&
      (isModuleExports(node.left.object) ||
        (node.left.object?.type === "Identifier" &&
          node.left.object.name === "exports")) &&
      directMemberName(node.left) === "promises"
    ) {
      throw new Error(
        `${providerSourcePath}: module.exports.promises has an unreviewed overwrite`,
      );
    }
  });
  assertReviewedBindingReferences({
    program: providerProgram,
    bindingIndex: providerBindings,
    binding: providerPromisesBinding,
    declaration: providerPromisesDeclaration,
    label: "provider promises",
    sourcePath: providerSourcePath,
    allowed: (node, parent, ancestors) => {
      if (
        parent?.type === "MemberExpression" &&
        parent.object === node &&
        ancestors.at(-2)?.type === "AssignmentExpression" &&
        ancestors.at(-2).left === parent &&
        providerPromiseWrites.get(directMemberName(parent)) ===
          ancestors.at(-2)
      ) {
        return true;
      }
      return Boolean(
        parent === exportedPromises &&
          exportedPromises.value === node &&
          ancestors.at(-2) === providerExport.right,
      );
    },
  });

  const resolverPrototype = prototypeAssignments(
    providerProgram,
    "Resolver",
    providerSourcePath,
  );
  const promiseResolverPrototype = prototypeAssignments(
    providerProgram,
    "PromiseResolver",
    providerSourcePath,
  );
  if (resolverPrototype.whole.length !== 0) {
    throw new Error(
      `${providerSourcePath}: Resolver.prototype has an unreviewed replacement`,
    );
  }
  assertReviewedNameSet(
    [...resolverPrototype.members.keys()],
    REVIEWED_DNS_PROMISE_RESOLVER_OPERATIONS,
    "Resolver.prototype operation domain",
    providerSourcePath,
  );
  if (
    promiseResolverPrototype.whole.length !== 1 ||
    !isExactPromiseResolverInheritance(
      promiseResolverPrototype.whole[0].right,
    )
  ) {
    throw new Error(
      `${providerSourcePath}: PromiseResolver.prototype must inherit exact Resolver.prototype`,
    );
  }
  assertReviewedNameSet(
    [...promiseResolverPrototype.members.keys()],
    ["constructor", ...REVIEWED_DNS_PROMISE_RESOLVER_OWN_OPERATIONS],
    "PromiseResolver.prototype own domain",
    providerSourcePath,
  );
  const constructorWrite = promiseResolverPrototype.members.get("constructor");
  if (
    constructorWrite?.right?.type !== "Identifier" ||
    constructorWrite.right.name !== "PromiseResolver" ||
    !isSourceProvenCallable(constructorWrite.right, providerBindings)
  ) {
    throw new Error(
      `${providerSourcePath}: PromiseResolver.prototype.constructor drifted`,
    );
  }
  for (const [name, assignment] of [
    ...resolverPrototype.members,
    ...[...promiseResolverPrototype.members].filter(
      ([member]) => member !== "constructor",
    ),
  ]) {
    if (!isSourceProvenCallable(assignment.right, providerBindings)) {
      throw new Error(
        `${registrationContext(providerText, assignment, providerSourcePath)}: ${name} prototype member is not source-proven callable`,
      );
    }
  }
  const inheritedOperations = [...resolverPrototype.members.keys()].filter(
    (name) => !promiseResolverPrototype.members.has(name),
  );
  assertReviewedNameSet(
    inheritedOperations,
    REVIEWED_DNS_PROMISE_RESOLVER_INHERITED_OPERATIONS,
    "PromiseResolver.prototype inherited domain",
    providerSourcePath,
  );

  const inheritance = promiseResolverPrototype.whole[0];
  assertReviewedPrototypeObjectUses({
    program: providerProgram,
    owner: "Resolver",
    inheritance,
    memberAssignments: resolverPrototype.members,
    sourcePath: providerSourcePath,
  });
  assertReviewedPrototypeObjectUses({
    program: providerProgram,
    owner: "PromiseResolver",
    inheritance,
    memberAssignments: promiseResolverPrototype.members,
    sourcePath: providerSourcePath,
  });
  const shapeReviewId = dnsPromiseExportShapeReviewId({
    carrierProgram,
    carrierSourcePath,
    providerProgram,
    providerSourcePath,
  });
  if (shapeReviewId !== REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID) {
    throw new Error(
      `dns/promises export-shape AST review drifted: observed ${shapeReviewId}; expected ${REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID}`,
    );
  }
  const carrierRef = sourceSymbol(
    carrierSourcePath,
    "module.exports:dns.promises",
  );
  const specifiers = uniqueSorted(moduleSpecifiers);
  const operationRows = [];
  const addOperation = (
    exportName,
    providerRefs,
    exportIdioms,
    inheritedShape = false,
  ) => {
    const metadata = {
      bootstrapInternalModuleSpecifiers: [],
      crossSourceExportProjection: {
        carrierBinding: "module.exports=dns.promises",
        carrierSourceKey: "node_dns_promises",
        kind: "immutable-commonjs-member-object",
        memberPath: exportName,
        providerBinding: "module.exports.promises",
        providerSourceKey: "node_dns",
      },
      dnsPromiseExportShapeReviewId: shapeReviewId,
      enforcementRouteEvidence: {
        ambiguousCallees: [
          `cross-source-export-projection:dns.promises:${exportName}`,
        ],
        kind: "static-builtin-call-graph",
        paths: [],
        terminals: [],
      },
      exportIdioms,
      exportName,
      importReachability: "public",
      moduleSpecifiers: specifiers,
      publicModuleSpecifiers: specifiers,
      sourceKey: "node_dns_promises",
      sourceKind: carrierSourceKind,
      surfaceType: "export",
      valueShape: "callable",
    };
    if (inheritedShape) {
      metadata.inheritedShape = true;
      metadata.semanticRoles = [
        "cross-source-export-projection",
        "inherited-export-shape",
      ];
    }
    operationRows.push(
      makeSurface(
        "builtin",
        `export:node_dns_promises:${exportName}`,
        [carrierRef, ...providerRefs],
        { metadata },
      ),
    );
  };

  for (const name of REVIEWED_DNS_PROMISE_TOP_OPERATIONS) {
    addOperation(
      name,
      [
        sourceSymbol(
          providerSourcePath,
          name === "Resolver"
            ? "promises:Resolver:PromiseResolver"
            : `promises:${name}`,
        ),
      ],
      ["cross-source-required-member-object-property"],
    );
  }
  for (const name of REVIEWED_DNS_PROMISE_RESOLVER_OWN_OPERATIONS) {
    addOperation(
      `Resolver.${name}`,
      [sourceSymbol(providerSourcePath, `PromiseResolver.prototype:${name}`)],
      ["exported-constructor-prototype"],
    );
  }
  for (const name of REVIEWED_DNS_PROMISE_RESOLVER_INHERITED_OPERATIONS) {
    addOperation(
      `Resolver.${name}`,
      [
        sourceSymbol(
          providerSourcePath,
          "PromiseResolver.prototype:Object.create:Resolver.prototype",
        ),
        sourceSymbol(providerSourcePath, `Resolver.prototype:${name}`),
      ],
      ["exported-constructor-inherited-prototype"],
      true,
    );
  }
  for (const name of resolverInstanceShape.handleOperations) {
    addOperation(
      `Resolver._handle.${name}`,
      [
        sourceSymbol(
          providerSourcePath,
          "PromiseResolver:Resolver.call:this:options",
        ),
        sourceSymbol(providerSourcePath, `Resolver:instance:_handle.${name}`),
      ],
      ["exported-constructor-instance-nested-object"],
    );
  }
  if (
    inheritance.start === undefined ||
    [...promiseResolverPrototype.members.values()].some(
      (assignment) => assignment.start <= inheritance.start,
    )
  ) {
    throw new Error(
      `${providerSourcePath}: PromiseResolver prototype members must follow the reviewed inheritance join`,
    );
  }
  assertUniqueObservedKeys(operationRows, "dns/promises projection");
  return sortSurfaces(operationRows);
}

function reviewedDnsResolverHandleRows({
  moduleSpecifiers,
  providerSourceKind,
  providerSourcePath,
  shapeReviewId,
}) {
  return ["cancel", "getServers", "setServers"].map((name) => {
    const exportName = `Resolver._handle.${name}`;
    return makeSurface(
      "builtin",
      `export:node_dns:${exportName}`,
      [
        sourceSymbol(providerSourcePath, "Resolver:instance:_handle"),
        sourceSymbol(providerSourcePath, `Resolver:instance:_handle.${name}`),
      ],
      {
        metadata: {
          bootstrapInternalModuleSpecifiers: [],
          constructorInstanceProjection: {
            constructorExport: "Resolver",
            instancePath: `_handle.${name}`,
            kind: "constructor-installed-nested-object",
          },
          dnsPromiseExportShapeReviewId: shapeReviewId,
          enforcementRouteEvidence: {
            ambiguousCallees: [
              `constructor-instance-projection:Resolver._handle.${name}`,
            ],
            kind: "static-builtin-call-graph",
            paths: [],
            terminals: [],
          },
          exportIdioms: ["exported-constructor-instance-nested-object"],
          exportName,
          importReachability: "public",
          moduleSpecifiers: uniqueSorted(moduleSpecifiers),
          publicModuleSpecifiers: uniqueSorted(moduleSpecifiers),
          sourceKey: "node_dns",
          sourceKind: providerSourceKind,
          surfaceType: "export",
          valueShape: "callable",
        },
      },
    );
  });
}

function composeReviewedBuiltinExportShapes(exports, aliases, sourcesByKey) {
  const carrier = sourcesByKey.get("node_dns_promises");
  if (!carrier) return [];
  const provider = sourcesByKey.get("node_dns");
  if (!provider) {
    throw new Error(
      "modules.ts: node_dns_promises requires the reviewed node_dns provider source",
    );
  }
  if (
    carrier.source.kind !== "generated" ||
    carrier.authoredPath !== "src/builtins/dns-promises.js" ||
    provider.source.kind !== "generated" ||
    provider.authoredPath !== "src/builtins/dns.js"
  ) {
    throw new Error(
      "modules.ts: reviewed dns/promises projection source kind/path drifted",
    );
  }
  const carrierAliases = aliases.filter(
    (alias) => alias.metadata?.sourceKey === "node_dns_promises",
  );
  assertReviewedNameSet(
    carrierAliases.map((alias) => alias.name),
    ["dns/promises", "node:dns/promises"],
    "node_dns_promises public aliases",
    "modules.ts",
  );
  if (
    carrierAliases.some(
      (alias) => alias.metadata?.importReachability !== "public",
    )
  ) {
    throw new Error(
      "modules.ts: node_dns_promises aliases must remain publicly reachable",
    );
  }
  const providerAliases = aliases.filter(
    (alias) => alias.metadata?.sourceKey === "node_dns",
  );
  assertReviewedNameSet(
    providerAliases.map((alias) => alias.name),
    ["dns", "node:dns"],
    "node_dns public aliases",
    "modules.ts",
  );
  if (
    providerAliases.some(
      (alias) => alias.metadata?.importReachability !== "public",
    )
  ) {
    throw new Error("modules.ts: node_dns aliases must remain publicly reachable");
  }
  const dnsAlias = aliases.find((alias) => alias.name === "dns");
  if (
    !dnsAlias ||
    dnsAlias.metadata?.sourceKey !== "node_dns" ||
    dnsAlias.metadata?.importReachability !== "public"
  ) {
    throw new Error(
      'modules.ts: reviewed require("dns") must resolve publicly to node_dns',
    );
  }
  const existingCarrierExports = exports
    .filter(
      (row) =>
        row.metadata?.sourceKey === "node_dns_promises" &&
        row.metadata?.surfaceType === "export",
    )
    .map((row) => row.metadata.exportName);
  assertReviewedNameSet(
    existingCarrierExports,
    ["default", ...REVIEWED_DNS_PROMISE_ERROR_CODES],
    "locally authored node_dns_promises exports",
    carrier.authoredPath,
  );
  const carrierRows = scanReviewedDnsPromisesProjection(
    carrier.text,
    provider.text,
    {
    carrierSourceKind: carrier.source.kind,
    carrierSourcePath: carrier.authoredPath,
    moduleSpecifiers: carrierAliases.map((alias) => alias.name),
    providerSourcePath: provider.authoredPath,
    },
  );
  const shapeReviewIds = uniqueSorted(
    carrierRows.map((row) => row.metadata.dnsPromiseExportShapeReviewId),
  );
  if (
    shapeReviewIds.length !== 1 ||
    shapeReviewIds[0] !== REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID
  ) {
    throw new Error("dns/promises projected rows lost their AST review binding");
  }
  return [
    ...reviewedDnsResolverHandleRows({
      moduleSpecifiers: providerAliases.map((alias) => alias.name),
      providerSourceKind: provider.source.kind,
      providerSourcePath: provider.authoredPath,
      shapeReviewId: shapeReviewIds[0],
    }),
    ...carrierRows,
  ];
}

// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory —
// literal immutable builtin dependencies join to exact source/export routes;
// unresolved or tampered receivers remain explicit ambiguity.
function composeRequiredBuiltinRoutes(exports, aliases) {
  const sourceKeyBySpecifier = new Map(
    aliases.map((alias) => [alias.name, alias.metadata.sourceKey]),
  );
  const rowBySourceExport = new Map(
    exports
      .filter(
        (row) =>
          typeof row.metadata?.sourceKey === "string" &&
          typeof row.metadata?.exportName === "string",
      )
      .map((row) => [
        `${row.metadata.sourceKey}\u0000${row.metadata.exportName}`,
        row,
      ]),
  );
  const states = new Map();
  for (const row of exports) {
    const evidence = row.metadata?.enforcementRouteEvidence;
    if (evidence?.kind !== "static-builtin-call-graph") continue;
    states.set(row.observedKey, {
      ambiguous: new Set(evidence.ambiguousCallees ?? []),
      baseTerminals: new Set(evidence.terminals ?? []),
      derivedPaths: new Map(),
      paths: new Set(evidence.paths ?? []),
      terminals: new Set(evidence.terminals ?? []),
    });
  }

  const resolvedDependencies = new Map();
  for (const row of exports) {
    const evidence = row.metadata?.enforcementRouteEvidence;
    if (evidence?.kind !== "static-builtin-call-graph") continue;
    const dependencies = [];
    for (const dependency of evidence.requiredExportCalls ?? []) {
      const sourceKey = sourceKeyBySpecifier.get(dependency.moduleSpecifier);
      const target = sourceKey
        ? rowBySourceExport.get(`${sourceKey}\u0000${dependency.exportName}`)
        : null;
      dependencies.push({ dependency, target });
      if (!target) {
        states
          .get(row.observedKey)
          .ambiguous.add(
            `unresolved-required-export:${dependency.moduleSpecifier}:${dependency.exportName}`,
          );
      }
    }
    resolvedDependencies.set(row.observedKey, dependencies);
  }

  const betterPath = (candidate, existing) =>
    existing === undefined ||
    candidate.length < existing.length ||
    (candidate.length === existing.length &&
      compareText(candidate, existing) < 0);
  let changed = true;
  let iterations = 0;
  while (changed && iterations <= states.size) {
    changed = false;
    iterations += 1;
    for (const row of exports) {
      const state = states.get(row.observedKey);
      if (!state) continue;
      for (const { dependency, target } of resolvedDependencies.get(
        row.observedKey,
      ) ?? []) {
        const targetState = target ? states.get(target.observedKey) : null;
        if (!targetState) continue;
        for (const ambiguity of targetState.ambiguous) {
          if (!state.ambiguous.has(ambiguity)) {
            state.ambiguous.add(ambiguity);
            changed = true;
          }
        }
        for (const terminal of targetState.terminals) {
          if (!state.terminals.has(terminal)) {
            state.terminals.add(terminal);
            changed = true;
          }
          if (state.baseTerminals.has(terminal)) continue;
          const targetPath =
            targetState.derivedPaths.get(terminal) ??
            [...targetState.paths]
              .filter((routePath) => routePath.endsWith(` -> ${terminal}`))
              .sort(
                (left, right) =>
                  left.length - right.length || compareText(left, right),
              )[0] ??
            `export:${dependency.exportName} -> ${terminal}`;
          for (const dependencyPath of dependency.paths) {
            const candidate = `${dependencyPath} -> ${targetPath}`;
            const existing = state.derivedPaths.get(terminal);
            if (betterPath(candidate, existing)) {
              state.derivedPaths.set(terminal, candidate);
              changed = true;
            }
          }
        }
      }
    }
  }
  if (changed) {
    throw new Error(
      "builtin required-export route composition did not converge",
    );
  }
  for (const row of exports) {
    const evidence = row.metadata?.enforcementRouteEvidence;
    const state = states.get(row.observedKey);
    if (!evidence || !state) continue;
    evidence.ambiguousCallees = uniqueSorted(state.ambiguous);
    evidence.paths = uniqueSorted([
      ...state.paths,
      ...state.derivedPaths.values(),
    ]);
    evidence.terminals = uniqueSorted(state.terminals);
  }
}

/** Discover both manifest aliases and the statically named exports they expose. */
export async function scanBuiltinSurfaces(
  modulePath,
  repoRoot,
  sourcePath = "modules.ts",
) {
  const moduleExports = await import(pathToFileURL(modulePath).href);
  const aliases = scanModuleSpecifierEntries(moduleExports, sourcePath);
  const aliasesBySource = new Map();
  for (const alias of aliases) {
    const sourceKey = alias.metadata.sourceKey;
    let sourceAliases = aliasesBySource.get(sourceKey);
    if (!sourceAliases) {
      sourceAliases = [];
      aliasesBySource.set(sourceKey, sourceAliases);
    }
    sourceAliases.push(alias);
  }

  const exports = [];
  const sourcesByKey = new Map();
  for (const sourceKey of Object.keys(moduleExports.sources).sort(
    compareText,
  )) {
    const source = moduleExports.sources[sourceKey];
    let text;
    let authoredPath;
    if (source.kind === "generated") {
      if (typeof source.path !== "string" || source.path.length === 0) {
        throw new Error(
          `${sourcePath}: generated source ${sourceKey} has no path`,
        );
      }
      authoredPath = posixPath(path.join("src", source.path));
      text = readUtf8(path.join(repoRoot, authoredPath));
    } else if (source.kind === "repo") {
      if (typeof source.path !== "string" || source.path.length === 0) {
        throw new Error(`${sourcePath}: repo source ${sourceKey} has no path`);
      }
      authoredPath = posixPath(source.path);
      text = readUtf8(path.join(repoRoot, authoredPath));
    } else if (source.kind === "inline") {
      if (typeof source.code !== "string") {
        throw new Error(
          `${sourcePath}: inline source ${sourceKey} has no code`,
        );
      }
      authoredPath = sourcePath;
      text = source.code;
    } else {
      throw new Error(
        `${sourcePath}: source ${sourceKey} has unknown kind ${JSON.stringify(source.kind)}`,
      );
    }
    const sourceAliases = aliasesBySource.get(sourceKey) ?? [];
    sourcesByKey.set(sourceKey, {
      authoredPath,
      source,
      sourceAliases,
      text,
    });
    for (const row of scanStaticBuiltinExports(text, {
        bootstrapInternalModuleSpecifiers: sourceAliases
          .filter(
            (alias) =>
              alias.metadata.importReachability === "bootstrap-internal",
          )
          .map((alias) => alias.name),
        sourceKey,
        sourceKind: source.kind,
        sourcePath: authoredPath,
        moduleSpecifiers: sourceAliases.map((alias) => alias.name),
        publicModuleSpecifiers: sourceAliases
          .filter((alias) => alias.metadata.importReachability === "public")
          .map((alias) => alias.name),
      })) {
      exports.push(row);
    }
  }

  exports.push(
    ...composeReviewedBuiltinExportShapes(exports, aliases, sourcesByKey),
  );
  assertUniqueObservedKeys(exports, "builtin export inventory");
  composeRequiredBuiltinRoutes(exports, aliases);

  const inheritedReviewRows = exports
    .filter(
      (row) =>
        row.metadata?.inheritedShape === true &&
        row.metadata?.dnsPromiseExportShapeReviewId === undefined,
    )
    .map((row) => ({
      exportIdioms: row.metadata.exportIdioms,
      name: row.name,
      sourceRefs: row.sourceRefs,
    }))
    .sort((left, right) => compareText(left.name, right.name));
  if (inheritedReviewRows.length > 0) {
    const inheritedShapeReviewId = `sha256-${sha256Hex(JSON.stringify(inheritedReviewRows))}`;
    for (const row of exports) {
      if (
        row.metadata?.inheritedShape === true &&
        row.metadata?.dnsPromiseExportShapeReviewId === undefined
      ) {
        row.metadata.inheritedShapeReviewId = inheritedShapeReviewId;
      }
    }
  }

  const rows = sortSurfaces([...aliases, ...exports]);
  assertUniqueObservedKeys(rows, "builtin alias and export inventory");
  return rows;
}

export function scanRuntimeCommandClasses(
  manifestInput,
  sourcePath = "runtime-surface.json",
) {
  let manifest = manifestInput;
  if (typeof manifestInput === "string") {
    try {
      manifest = JSON.parse(manifestInput);
    } catch (error) {
      throw new Error(`${sourcePath}: invalid JSON: ${error.message}`);
    }
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error(`${sourcePath}: command manifest must be an object`);
  }

  const rows = [];
  const names = new Set();
  for (const [field, variant] of COMMAND_CLASSES) {
    const commands = manifest[field];
    if (!Array.isArray(commands) || commands.length === 0) {
      throw new Error(`${sourcePath}: ${field} must be a non-empty array`);
    }
    for (const name of commands) {
      if (typeof name !== "string" || name.length === 0) {
        throw new Error(`${sourcePath}: ${field} contains an empty command`);
      }
      if (names.has(name)) {
        throw new Error(
          `${sourcePath}: duplicate runtime command ${JSON.stringify(name)}`,
        );
      }
      names.add(name);
      rows.push(
        makeSurface("cli", name, [sourceSymbol(sourcePath, field)], {
          variant,
          metadata: { commandClass: field },
        }),
      );
    }
  }
  assertUniqueObservedKeys(rows, sourcePath);
  return sortSurfaces(rows);
}

function cliSurfaceComponent(value) {
  return encodeURIComponent(String(value));
}

function assertExactObjectKeys(value, allowed, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw new Error(
      `${label} has unreviewed fields: ${unknown.sort(compareText).join(", ")}`,
    );
  }
}

function cliStringArray(value, label, { allowEmpty = false } = {}) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  for (const entry of value) {
    if (typeof entry !== "string" || (!allowEmpty && entry.length === 0)) {
      throw new Error(`${label} contains an invalid string value`);
    }
  }
  if (new Set(value).size !== value.length) {
    throw new Error(`${label} contains a duplicate value`);
  }
  return value;
}

const CLI_VALUE_SHAPE_KEYS = new Set([
  "action",
  "allowHyphenValues",
  "defaultMissingValues",
  "defaultValues",
  "maxValues",
  "minValues",
  "possibleValues",
  "possibleValuesHidden",
  "required",
  "valueDomain",
  "valueNames",
]);

function validateCliValueShape(shape, label) {
  assertExactObjectKeys(shape, CLI_VALUE_SHAPE_KEYS, label);
  for (const key of CLI_VALUE_SHAPE_KEYS) {
    if (!Object.hasOwn(shape, key))
      throw new Error(`${label} is missing ${key}`);
  }
  if (
    !new Set(["Append", "Count", "Set", "SetFalse", "SetTrue"]).has(
      shape.action,
    )
  ) {
    throw new Error(
      `${label} has unreviewed action ${JSON.stringify(shape.action)}`,
    );
  }
  if (
    !Number.isSafeInteger(shape.minValues) ||
    shape.minValues < 0 ||
    (shape.maxValues !== null &&
      (!Number.isSafeInteger(shape.maxValues) ||
        shape.maxValues < shape.minValues))
  ) {
    throw new Error(`${label} has invalid value arity`);
  }
  for (const field of [
    "allowHyphenValues",
    "possibleValuesHidden",
    "required",
  ]) {
    if (typeof shape[field] !== "boolean")
      throw new Error(`${label}.${field} must be boolean`);
  }
  if (!new Set(["none", "arbitrary", "enumerated"]).has(shape.valueDomain)) {
    throw new Error(
      `${label} has unknown valueDomain ${JSON.stringify(shape.valueDomain)}`,
    );
  }
  cliStringArray(shape.valueNames, `${label}.valueNames`);
  cliStringArray(shape.defaultValues, `${label}.defaultValues`, {
    allowEmpty: true,
  });
  cliStringArray(shape.defaultMissingValues, `${label}.defaultMissingValues`, {
    allowEmpty: true,
  });
  if (!Array.isArray(shape.possibleValues)) {
    throw new Error(`${label}.possibleValues must be an array`);
  }
  for (const [index, possible] of shape.possibleValues.entries()) {
    const possibleLabel = `${label}.possibleValues[${index}]`;
    assertExactObjectKeys(
      possible,
      new Set(["aliases", "hidden", "value"]),
      possibleLabel,
    );
    if (typeof possible.value !== "string" || possible.value.length === 0) {
      throw new Error(`${possibleLabel}.value must be a non-empty string`);
    }
    if (typeof possible.hidden !== "boolean") {
      throw new Error(`${possibleLabel}.hidden must be boolean`);
    }
    cliStringArray(possible.aliases, `${possibleLabel}.aliases`);
  }
  const expectedDomain =
    shape.maxValues === 0
      ? "none"
      : shape.possibleValues.length === 0
        ? "arbitrary"
        : "enumerated";
  if (shape.valueDomain !== expectedDomain) {
    throw new Error(
      `${label} valueDomain does not match its arity and possible values`,
    );
  }
}

const REPL_COMMAND_KEYS = new Set([
  "affordance",
  "aliases",
  "argument",
  "errorOutput",
  "help",
  "id",
  "modes",
  "name",
  "registryRelations",
  "sourceSubmission",
  "states",
  "successOutput",
  "usage",
]);

function replRegistryRelations(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  const keys = new Set();
  return value.map((relation, index) => {
    const relationLabel = `${label}[${index}]`;
    assertExactObjectKeys(relation, new Set(["id", "kind"]), relationLabel);
    if (
      !new Set(["capability", "non-capability-rationale"]).has(relation.kind) ||
      typeof relation.id !== "string" ||
      !/^[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)?$/u.test(relation.id)
    ) {
      throw new Error(`${relationLabel} is not a typed registry relation`);
    }
    const key = `${relation.kind}:${relation.id}`;
    if (keys.has(key)) throw new Error(`${label} contains duplicate ${key}`);
    keys.add(key);
    return structuredClone(relation);
  });
}

/**
 * Expand LLP 0022/0025's generated REPL contract into reviewable CapSec
 * surfaces. Canonical commands and aliases are separate routes; recognition,
 * `.load` dialect selection, and key controls are explicit rows so none can
 * hide inside opaque manifest metadata.
 */
export function scanRuntimeReplSurfaces(
  manifestInput,
  sourcePath = "runtime-surface.json",
) {
  let manifest = manifestInput;
  if (typeof manifestInput === "string") {
    try {
      manifest = JSON.parse(manifestInput);
    } catch (error) {
      throw new Error(`${sourcePath}: invalid JSON: ${error.message}`);
    }
  }
  if (manifest?.version !== 5) {
    throw new Error(
      `${sourcePath}: REPL inventory requires manifest version 5`,
    );
  }
  const repl = manifest.replSurface;
  const keybindings = manifest.keybindingSurface;
  assertExactObjectKeys(
    repl,
    new Set([
      "$comment",
      "commands",
      "loadExtensions",
      "modes",
      "recognition",
      "version",
    ]),
    `${sourcePath}: replSurface`,
  );
  assertExactObjectKeys(
    keybindings,
    new Set(["$comment", "bindings", "editorProfile", "scope", "version"]),
    `${sourcePath}: keybindingSurface`,
  );
  if (repl.version !== 1 || keybindings.version !== 1) {
    throw new Error(
      `${sourcePath}: only REPL/keybinding surface version 1 is reviewed`,
    );
  }
  if (
    JSON.stringify(repl.modes) !==
    JSON.stringify(["interactive", "plain-transcript"])
  ) {
    throw new Error(`${sourcePath}: replSurface.modes drifted`);
  }
  if (!Array.isArray(repl.commands) || repl.commands.length === 0) {
    throw new Error(`${sourcePath}: replSurface.commands must be non-empty`);
  }
  if (
    !Array.isArray(keybindings.bindings) ||
    keybindings.bindings.length === 0
  ) {
    throw new Error(
      `${sourcePath}: keybindingSurface.bindings must be non-empty`,
    );
  }

  const rows = [];
  const ids = new Set();
  const names = new Set();
  assertExactObjectKeys(
    repl.recognition,
    new Set([
      "argumentRemainder",
      "commandsNeverContinue",
      "leadingWhitespace",
      "namePattern",
      "nonmatchDisposition",
      "prefix",
      "termination",
      "unknownDisposition",
    ]),
    `${sourcePath}: replSurface.recognition`,
  );
  rows.push(
    makeSurface(
      "cli",
      "repl-command-recognition:v1",
      [sourceSymbol(sourcePath, "replSurface.recognition")],
      {
        metadata: {
          evidenceType: "repl-command-recognition",
          replSurfaceVersion: repl.version,
          recognition: structuredClone(repl.recognition),
        },
      },
    ),
  );

  for (const [index, command] of repl.commands.entries()) {
    const label = `${sourcePath}: replSurface.commands[${index}]`;
    assertExactObjectKeys(command, REPL_COMMAND_KEYS, label);
    if (
      typeof command.id !== "string" ||
      !/^[a-z][a-z0-9-]*$/u.test(command.id) ||
      ids.has(command.id)
    ) {
      throw new Error(`${label}.id is invalid or duplicate`);
    }
    ids.add(command.id);
    const routedNames = [
      ["canonical", command.name],
      ...cliStringArray(command.aliases, `${label}.aliases`).map((alias) => [
        "alias",
        alias,
      ]),
    ];
    if (
      typeof command.name !== "string" ||
      !/^\.[A-Za-z][A-Za-z0-9_-]*$/u.test(command.name)
    ) {
      throw new Error(`${label}.name violates the command grammar`);
    }
    assertExactObjectKeys(
      command.argument,
      command.argument?.kind === "none"
        ? new Set(["kind"])
        : new Set(["kind", "name", "preserve"]),
      `${label}.argument`,
    );
    if (
      !new Set(["none", "required-remainder"]).has(command.argument.kind) ||
      (command.argument.kind === "required-remainder" &&
        (typeof command.argument.name !== "string" ||
          command.argument.preserve !== "verbatim"))
    ) {
      throw new Error(`${label}.argument is not a reviewed argument shape`);
    }
    const registryRelations = replRegistryRelations(
      command.registryRelations,
      `${label}.registryRelations`,
    );
    for (const [routeKind, name] of routedNames) {
      if (!/^\.[A-Za-z][A-Za-z0-9_-]*$/u.test(name) || names.has(name)) {
        throw new Error(`${label} has invalid or duplicate route ${name}`);
      }
      names.add(name);
      rows.push(
        makeSurface(
          "cli",
          routeKind === "canonical"
            ? `repl-command:${cliSurfaceComponent(command.id)}`
            : `repl-command-alias:${cliSurfaceComponent(command.id)}:${cliSurfaceComponent(name)}`,
          [sourceSymbol(sourcePath, `replSurface.command:${command.id}`)],
          {
            metadata: {
              affordance: command.affordance,
              argument: structuredClone(command.argument),
              canonicalCommandId: command.id,
              commandName: name,
              evidenceType: "repl-command-route",
              help: command.help,
              modes: cliStringArray(command.modes, `${label}.modes`),
              registryRelations,
              replSurfaceVersion: repl.version,
              routeKind,
              sourceSubmission: command.sourceSubmission,
              states: cliStringArray(command.states, `${label}.states`),
              successOutput: command.successOutput,
              usage: command.usage,
            },
          },
        ),
      );
    }
  }

  const load = repl.loadExtensions;
  assertExactObjectKeys(
    load,
    new Set(["defaultDisposition", "defaultErrorCode", "matching", "rows"]),
    `${sourcePath}: replSurface.loadExtensions`,
  );
  if (load.matching !== "longest-suffix-first" || !Array.isArray(load.rows)) {
    throw new Error(`${sourcePath}: load extension matching is not reviewed`);
  }
  const extensions = new Set();
  for (const [index, row] of load.rows.entries()) {
    const label = `${sourcePath}: replSurface.loadExtensions.rows[${index}]`;
    assertExactObjectKeys(
      row,
      new Set(["dialect", "disposition", "errorCode", "extension"]),
      label,
    );
    if (
      typeof row.extension !== "string" ||
      !/^\.[a-z.]+$/u.test(row.extension) ||
      extensions.has(row.extension) ||
      typeof row.disposition !== "string"
    ) {
      throw new Error(`${label} is invalid or duplicate`);
    }
    extensions.add(row.extension);
    rows.push(
      makeSurface(
        "cli",
        `repl-load-extension:${cliSurfaceComponent(row.extension)}`,
        [
          sourceSymbol(
            sourcePath,
            `replSurface.loadExtension:${row.extension}`,
          ),
        ],
        {
          metadata: {
            ...structuredClone(row),
            evidenceType: "repl-load-extension",
            replSurfaceVersion: repl.version,
          },
        },
      ),
    );
  }
  rows.push(
    makeSurface(
      "cli",
      "repl-load-extension:default",
      [sourceSymbol(sourcePath, "replSurface.loadExtension:default")],
      {
        metadata: {
          defaultDisposition: load.defaultDisposition,
          errorCode: load.defaultErrorCode,
          evidenceType: "repl-load-extension",
          replSurfaceVersion: repl.version,
        },
      },
    ),
  );

  const keybindingIds = new Set();
  const keySequences = new Set();
  for (const [index, binding] of keybindings.bindings.entries()) {
    const label = `${sourcePath}: keybindingSurface.bindings[${index}]`;
    assertExactObjectKeys(
      binding,
      new Set([
        "action",
        "bytes",
        "countsAsEditorInput",
        "display",
        "help",
        "id",
      ]),
      label,
    );
    const sequence = Array.isArray(binding.bytes)
      ? binding.bytes.join(",")
      : "";
    if (
      typeof binding.id !== "string" ||
      !/^[a-z][a-z0-9-]*$/u.test(binding.id) ||
      keybindingIds.has(binding.id) ||
      keySequences.has(sequence) ||
      binding.bytes.length === 0 ||
      binding.bytes.some(
        (byte) => !Number.isSafeInteger(byte) || byte < 0 || byte > 255,
      ) ||
      typeof binding.countsAsEditorInput !== "boolean"
    ) {
      throw new Error(`${label} is invalid or duplicates a control`);
    }
    keybindingIds.add(binding.id);
    keySequences.add(sequence);
    rows.push(
      makeSurface(
        "cli",
        `repl-keybinding:${cliSurfaceComponent(binding.id)}`,
        [sourceSymbol(sourcePath, `keybindingSurface.binding:${binding.id}`)],
        {
          metadata: {
            ...structuredClone(binding),
            evidenceType: "repl-keybinding",
            keybindingSurfaceVersion: keybindings.version,
          },
        },
      ),
    );
  }
  assertUniqueObservedKeys(rows, `${sourcePath} REPL surface inventory`);
  return sortSurfaces(rows);
}

function cliValueShapeRows(kind, pathName, id, shape, sourcePath, refPrefix) {
  const prefix = `${kind}:${cliSurfaceComponent(pathName)}:${cliSurfaceComponent(id)}`;
  const refs = [sourceSymbol(sourcePath, refPrefix)];
  const rows = [
    makeSurface("cli", `${prefix}:action:${shape.action}`, refs, {
      metadata: { action: shape.action, evidenceType: "cli-value-action" },
    }),
    makeSurface(
      "cli",
      `${prefix}:arity:${shape.minValues}:${shape.maxValues === null ? "unbounded" : shape.maxValues}`,
      refs,
      {
        metadata: {
          evidenceType: "cli-value-arity",
          maxValues: shape.maxValues,
          minValues: shape.minValues,
        },
      },
    ),
  ];
  for (const valueName of shape.valueNames) {
    rows.push(
      makeSurface(
        "cli",
        `${prefix}:value-name:${cliSurfaceComponent(valueName)}`,
        refs,
        {
          metadata: { evidenceType: "cli-value-name", valueName },
        },
      ),
    );
  }
  for (const possible of shape.possibleValues) {
    rows.push(
      makeSurface(
        "cli",
        `${prefix}:enum:${cliSurfaceComponent(possible.value)}`,
        refs,
        {
          metadata: {
            aliases: possible.aliases,
            evidenceType: "cli-enum-value",
            hidden: possible.hidden,
            value: possible.value,
          },
        },
      ),
    );
    for (const alias of possible.aliases) {
      rows.push(
        makeSurface(
          "cli",
          `${prefix}:enum-alias:${cliSurfaceComponent(possible.value)}:${cliSurfaceComponent(alias)}`,
          refs,
          {
            metadata: {
              canonicalValue: possible.value,
              evidenceType: "cli-enum-alias",
              value: alias,
            },
          },
        ),
      );
    }
  }
  for (const value of shape.defaultValues) {
    rows.push(
      makeSurface(
        "cli",
        `${prefix}:default:${cliSurfaceComponent(value)}`,
        refs,
        {
          metadata: { evidenceType: "cli-default-value", value },
        },
      ),
    );
  }
  for (const value of shape.defaultMissingValues) {
    rows.push(
      makeSurface(
        "cli",
        `${prefix}:default-missing:${cliSurfaceComponent(value)}`,
        refs,
        {
          metadata: { evidenceType: "cli-default-missing-value", value },
        },
      ),
    );
  }
  return rows;
}

/**
 * Expand the recursive Clap manifest into exact route and value-shape rows.
 * Shape components receive their own observed keys so aliases, actions,
 * enums, defaults, and arity changes cannot hide inside opaque metadata.
 */
export function scanRuntimeCliSurfaces(
  manifestInput,
  sourcePath = "runtime-surface.json",
) {
  let manifest = manifestInput;
  if (typeof manifestInput === "string") {
    try {
      manifest = JSON.parse(manifestInput);
    } catch (error) {
      throw new Error(`${sourcePath}: invalid JSON: ${error.message}`);
    }
  }
  const rows = scanRuntimeCommandClasses(manifest, sourcePath);
  if (manifest.version !== 5) {
    throw new Error(`${sourcePath}: recursive CLI manifest version must be 5`);
  }
  assertExactObjectKeys(
    manifest.clapSurface,
    new Set([
      "$comment",
      "commands",
      "frameworkGenerated",
      "positionalArguments",
      "semanticRelations",
    ]),
    `${sourcePath}: clapSurface`,
  );
  const commands = manifest.clapSurface?.commands;
  if (!Array.isArray(commands) || commands.length === 0) {
    throw new Error(
      `${sourcePath}: clapSurface.commands must be a non-empty array`,
    );
  }

  const commandPaths = new Set();
  const argumentsByCommand = new Map();
  for (const [commandIndex, command] of commands.entries()) {
    const commandLabel = `${sourcePath}: clapSurface.commands[${commandIndex}]`;
    assertExactObjectKeys(
      command,
      new Set([
        "hidden",
        "hiddenAliases",
        "longFlag",
        "options",
        "path",
        "positionals",
        "shortFlag",
        "visibleAliases",
      ]),
      commandLabel,
    );
    if (
      typeof command.path !== "string" ||
      !/^ibex(?: [A-Za-z0-9_-]+)*$/u.test(command.path)
    ) {
      throw new Error(
        `${commandLabel}.path is not a canonical ibex command path`,
      );
    }
    if (commandPaths.has(command.path)) {
      throw new Error(
        `${sourcePath}: duplicate Clap command path ${JSON.stringify(command.path)}`,
      );
    }
    commandPaths.add(command.path);
    const commandRef = `clapSurface.command:${command.path}`;
    rows.push(
      makeSurface(
        "cli",
        `command:${cliSurfaceComponent(command.path)}`,
        [sourceSymbol(sourcePath, commandRef)],
        {
          metadata: {
            evidenceType: "cli-command-route",
            hidden: command.hidden === true,
            longFlag: command.longFlag ?? null,
            path: command.path,
            shortFlag: command.shortFlag ?? null,
          },
        },
      ),
    );
    for (const aliasKind of ["visibleAliases", "hiddenAliases"]) {
      const aliases = cliStringArray(
        command[aliasKind] ?? [],
        `${commandLabel}.${aliasKind}`,
      );
      for (const alias of aliases) {
        rows.push(
          makeSurface(
            "cli",
            `command-alias:${cliSurfaceComponent(command.path)}:${cliSurfaceComponent(alias)}`,
            [sourceSymbol(sourcePath, commandRef)],
            {
              metadata: {
                alias,
                aliasVisibility:
                  aliasKind === "visibleAliases" ? "visible" : "hidden",
                commandPath: command.path,
                evidenceType: "cli-command-alias",
              },
            },
          ),
        );
      }
    }

    const argumentIds = new Set();
    const options = command.options ?? [];
    if (!Array.isArray(options))
      throw new Error(`${commandLabel}.options must be an array`);
    for (const [optionIndex, option] of options.entries()) {
      const optionLabel = `${commandLabel}.options[${optionIndex}]`;
      assertExactObjectKeys(
        option,
        new Set([
          "global",
          "hidden",
          "hiddenAliases",
          "id",
          "names",
          "valueShape",
          "visibleAliases",
        ]),
        optionLabel,
      );
      if (
        typeof option.id !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_-]*$/u.test(option.id)
      ) {
        throw new Error(`${optionLabel}.id is invalid`);
      }
      if (argumentIds.has(option.id)) {
        throw new Error(
          `${commandLabel} has duplicate argument id ${JSON.stringify(option.id)}`,
        );
      }
      argumentIds.add(option.id);
      let commandArguments = argumentsByCommand.get(command.path);
      if (!commandArguments) {
        commandArguments = new Map();
        argumentsByCommand.set(command.path, commandArguments);
      }
      commandArguments.set(option.id, {
        argumentKind: "option",
        valueShape: option.valueShape,
      });
      const names = cliStringArray(option.names, `${optionLabel}.names`);
      if (
        names.length === 0 ||
        names.some(
          (name) =>
            !/^(?:--[A-Za-z0-9][A-Za-z0-9-]*|-[A-Za-z0-9])$/u.test(name),
        )
      ) {
        throw new Error(`${optionLabel}.names has an invalid option route`);
      }
      validateCliValueShape(option.valueShape, `${optionLabel}.valueShape`);
      if (option.global !== undefined && option.global !== true) {
        throw new Error(`${optionLabel}.global must be true when present`);
      }
      const ref = `clapSurface.command:${command.path}:option:${option.id}`;
      const refs = [sourceSymbol(sourcePath, ref)];
      rows.push(
        makeSurface(
          "cli",
          `option:${cliSurfaceComponent(command.path)}:${cliSurfaceComponent(option.id)}`,
          refs,
          {
            metadata: {
              commandPath: command.path,
              evidenceType: "cli-option-route",
              global: option.global === true,
              hidden: option.hidden === true,
              id: option.id,
              valueShape: option.valueShape,
            },
          },
        ),
      );
      const routedNames = [
        ...names.map((name) => ["primary", name]),
        ...cliStringArray(
          option.visibleAliases ?? [],
          `${optionLabel}.visibleAliases`,
        ).map((name) => ["visible-alias", name]),
        ...cliStringArray(
          option.hiddenAliases ?? [],
          `${optionLabel}.hiddenAliases`,
        ).map((name) => ["hidden-alias", name]),
      ];
      for (const [routeKind, name] of routedNames) {
        if (!/^(?:--[A-Za-z0-9][A-Za-z0-9-]*|-[A-Za-z0-9])$/u.test(name)) {
          throw new Error(
            `${optionLabel} has invalid ${routeKind} ${JSON.stringify(name)}`,
          );
        }
        rows.push(
          makeSurface(
            "cli",
            `option-name:${cliSurfaceComponent(command.path)}:${cliSurfaceComponent(option.id)}:${cliSurfaceComponent(name)}`,
            refs,
            {
              metadata: { evidenceType: "cli-option-name", name, routeKind },
            },
          ),
        );
      }
      rows.push(
        ...cliValueShapeRows(
          "option",
          command.path,
          option.id,
          option.valueShape,
          sourcePath,
          ref,
        ),
      );
    }

    const positionals = command.positionals ?? [];
    if (!Array.isArray(positionals)) {
      throw new Error(`${commandLabel}.positionals must be an array`);
    }
    for (const [positionalIndex, positional] of positionals.entries()) {
      const positionalLabel = `${commandLabel}.positionals[${positionalIndex}]`;
      assertExactObjectKeys(
        positional,
        new Set(["id", "index", "passthrough", "valueShape"]),
        positionalLabel,
      );
      if (
        typeof positional.id !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_-]*$/u.test(positional.id)
      ) {
        throw new Error(`${positionalLabel}.id is invalid`);
      }
      if (argumentIds.has(positional.id)) {
        throw new Error(
          `${commandLabel} has duplicate argument id ${JSON.stringify(positional.id)}`,
        );
      }
      argumentIds.add(positional.id);
      let commandArguments = argumentsByCommand.get(command.path);
      if (!commandArguments) {
        commandArguments = new Map();
        argumentsByCommand.set(command.path, commandArguments);
      }
      commandArguments.set(positional.id, {
        argumentKind: "positional",
        valueShape: positional.valueShape,
      });
      if (!Number.isSafeInteger(positional.index) || positional.index < 1) {
        throw new Error(`${positionalLabel}.index must be a positive integer`);
      }
      if (typeof positional.passthrough !== "boolean") {
        throw new Error(`${positionalLabel}.passthrough must be boolean`);
      }
      validateCliValueShape(
        positional.valueShape,
        `${positionalLabel}.valueShape`,
      );
      if (
        positional.passthrough !==
        (positional.valueShape.maxValues === null &&
          positional.valueShape.allowHyphenValues)
      ) {
        throw new Error(
          `${positionalLabel}.passthrough does not match its value shape`,
        );
      }
      const ref = `clapSurface.command:${command.path}:positional:${positional.id}`;
      rows.push(
        makeSurface(
          "cli",
          `positional:${cliSurfaceComponent(command.path)}:${cliSurfaceComponent(positional.id)}`,
          [sourceSymbol(sourcePath, ref)],
          {
            metadata: {
              commandPath: command.path,
              evidenceType: "cli-positional-route",
              id: positional.id,
              index: positional.index,
              passthrough: positional.passthrough,
              valueShape: positional.valueShape,
            },
          },
        ),
      );
      rows.push(
        ...cliValueShapeRows(
          "positional",
          command.path,
          positional.id,
          positional.valueShape,
          sourcePath,
          ref,
        ),
      );
    }
  }

  const semanticRelations = manifest.clapSurface.semanticRelations;
  assertExactObjectKeys(
    semanticRelations,
    new Set(["argumentConflicts", "nonEnumeratedParsers"]),
    `${sourcePath}: clapSurface.semanticRelations`,
  );
  const conflicts = semanticRelations.argumentConflicts;
  if (!Array.isArray(conflicts)) {
    throw new Error(
      `${sourcePath}: clapSurface.semanticRelations.argumentConflicts must be an array`,
    );
  }
  const conflictKeys = new Set();
  for (const [index, conflict] of conflicts.entries()) {
    const label = `${sourcePath}: clapSurface.semanticRelations.argumentConflicts[${index}]`;
    assertExactObjectKeys(
      conflict,
      new Set(["argumentId", "commandPath", "conflictsWith"]),
      label,
    );
    const commandArguments = argumentsByCommand.get(conflict.commandPath);
    if (!commandArguments?.has(conflict.argumentId)) {
      throw new Error(`${label} references an unknown source argument`);
    }
    const targets = cliStringArray(
      conflict.conflictsWith,
      `${label}.conflictsWith`,
    );
    if (targets.length === 0) {
      throw new Error(`${label}.conflictsWith must not be empty`);
    }
    for (const target of targets) {
      if (target === conflict.argumentId || !commandArguments.has(target)) {
        throw new Error(`${label} references an invalid conflict target`);
      }
      const key = `${conflict.commandPath}\0${conflict.argumentId}\0${target}`;
      if (conflictKeys.has(key)) {
        throw new Error(`${label} duplicates an argument conflict`);
      }
      conflictKeys.add(key);
      const ref =
        `clapSurface.semanticRelations:argument-conflict:` +
        `${conflict.commandPath}:${conflict.argumentId}:${target}`;
      rows.push(
        makeSurface(
          "cli",
          `argument-conflict:${cliSurfaceComponent(conflict.commandPath)}:${cliSurfaceComponent(conflict.argumentId)}:${cliSurfaceComponent(target)}`,
          [sourceSymbol(sourcePath, ref)],
          {
            metadata: {
              argumentId: conflict.argumentId,
              commandPath: conflict.commandPath,
              conflictsWith: target,
              evidenceType: "cli-argument-conflict",
            },
          },
        ),
      );
    }
  }

  const parserRelations = semanticRelations.nonEnumeratedParsers;
  if (!Array.isArray(parserRelations)) {
    throw new Error(
      `${sourcePath}: clapSurface.semanticRelations.nonEnumeratedParsers must be an array`,
    );
  }
  const reviewedParserKinds = new Set([
    "os-path",
    "unsigned-integer-u16",
    "unsigned-integer-u64",
    "unsigned-integer-usize",
    "utf8-string",
  ]);
  const parserKeys = new Set();
  for (const [index, parser] of parserRelations.entries()) {
    const label = `${sourcePath}: clapSurface.semanticRelations.nonEnumeratedParsers[${index}]`;
    assertExactObjectKeys(
      parser,
      new Set(["argumentId", "commandPath", "parserKind"]),
      label,
    );
    const argument = argumentsByCommand
      .get(parser.commandPath)
      ?.get(parser.argumentId);
    if (!argument || argument.valueShape.valueDomain !== "arbitrary") {
      throw new Error(`${label} does not reference a non-enumerated argument`);
    }
    if (!reviewedParserKinds.has(parser.parserKind)) {
      throw new Error(
        `${label} has unreviewed parserKind ${JSON.stringify(parser.parserKind)}`,
      );
    }
    const key = `${parser.commandPath}\0${parser.argumentId}`;
    if (parserKeys.has(key)) {
      throw new Error(`${label} duplicates a non-enumerated parser`);
    }
    parserKeys.add(key);
    const ref =
      `clapSurface.semanticRelations:parser:` +
      `${parser.commandPath}:${parser.argumentId}:${parser.parserKind}`;
    rows.push(
      makeSurface(
        "cli",
        `argument-parser:${cliSurfaceComponent(parser.commandPath)}:${cliSurfaceComponent(parser.argumentId)}:${cliSurfaceComponent(parser.parserKind)}`,
        [sourceSymbol(sourcePath, ref)],
        {
          metadata: {
            argumentId: parser.argumentId,
            commandPath: parser.commandPath,
            evidenceType: "cli-non-enumerated-parser",
            parserKind: parser.parserKind,
          },
        },
      ),
    );
  }
  const arbitraryArguments = [];
  for (const [commandPath, commandArguments] of argumentsByCommand) {
    for (const [argumentId, argument] of commandArguments) {
      if (argument.valueShape.valueDomain === "arbitrary") {
        arbitraryArguments.push(`${commandPath}\0${argumentId}`);
      }
    }
  }
  const missingParsers = arbitraryArguments.filter(
    (key) => !parserKeys.has(key),
  );
  if (
    missingParsers.length > 0 ||
    parserKeys.size !== arbitraryArguments.length
  ) {
    throw new Error(
      `${sourcePath}: every non-enumerated CLI argument must have exactly one reviewed parser relation`,
    );
  }
  assertUniqueObservedKeys(
    rows,
    `${sourcePath} recursive CLI surface inventory`,
  );
  return sortSurfaces(rows);
}

function mergeHermesEvaluatorEvidence(existing, row, label) {
  const evaluatorClaims = [existing, row].filter(
    (candidate) =>
      candidate.metadata?.evidenceType === "hermes-evaluator-reachability",
  );
  if (evaluatorClaims.length === 0) return;
  const evidenceKeys = [
    "engineIdentityReviewId",
    "engineProfileIds",
    "evidenceType",
    "lockdownTamingDigest",
    "reachability",
    "tamingEvidence",
  ];
  for (const claim of evaluatorClaims) {
    if (
      typeof claim.metadata.engineIdentityReviewId !== "string" ||
      !Array.isArray(claim.metadata.engineProfileIds) ||
      claim.metadata.engineProfileIds.length === 0 ||
      !/^sha256-[a-f0-9]{64}$/u.test(
        claim.metadata.lockdownTamingDigest ?? "",
      ) ||
      typeof claim.metadata.reachability !== "string" ||
      claim.metadata.tamingEvidence !== "lockdownJS"
    ) {
      throw new Error(
        `${label}: malformed Hermes evaluator evidence for ${claim.observedKey}`,
      );
    }
  }
  const authority = evaluatorClaims[0].metadata;
  for (const claim of evaluatorClaims.slice(1)) {
    for (const key of evidenceKeys) {
      if (
        JSON.stringify(claim.metadata[key]) !== JSON.stringify(authority[key])
      ) {
        throw new Error(
          `${label}: conflicting Hermes evaluator evidence for ${claim.observedKey}`,
        );
      }
    }
  }
  existing.metadata ??= {};
  for (const key of evidenceKeys) {
    existing.metadata[key] = structuredClone(authority[key]);
  }
}

function mergeDynamicNamespaceEvidence(existing, row, label) {
  const evidenceKeys = [
    "dynamicNamespaceEvidence",
    "dynamicNamespaceKind",
    "dynamicNamespaceRoot",
  ];
  const claims = [existing, row].filter(
    (candidate) =>
      candidate.metadata?.dynamicNamespace === true ||
      evidenceKeys.some((key) => candidate.metadata?.[key] !== undefined),
  );
  if (claims.length === 0) return;
  for (const claim of claims) {
    if (
      claim.metadata?.dynamicNamespace !== true ||
      !/^sha256-[a-f0-9]{64}$/u.test(
        claim.metadata.dynamicNamespaceEvidence ?? "",
      ) ||
      !new Set(["iife-call-result", "opaque-call-result"]).has(
        claim.metadata.dynamicNamespaceKind,
      )
    ) {
      throw new Error(
        `${label}: malformed dynamic-namespace evidence for ${claim.observedKey}`,
      );
    }
  }
  const authority = claims[0].metadata;
  for (const claim of claims.slice(1)) {
    for (const key of evidenceKeys) {
      const authorityValue = authority[key];
      const claimValue = claim.metadata[key];
      if (
        authorityValue !== undefined &&
        claimValue !== undefined &&
        JSON.stringify(claimValue) !== JSON.stringify(authorityValue)
      ) {
        throw new Error(
          `${label}: conflicting dynamic-namespace evidence for ${claim.observedKey}`,
        );
      }
    }
  }
  existing.metadata ??= {};
  existing.metadata.dynamicNamespace = true;
  for (const key of evidenceKeys) {
    const value = claims.find((claim) => claim.metadata[key] !== undefined)
      ?.metadata[key];
    if (value !== undefined) existing.metadata[key] = structuredClone(value);
  }
}

function mergeFactoryReturnedCallableEvidence(existing, row, label) {
  const claims = [existing, row].filter(
    (candidate) =>
      candidate.metadata?.factoryReturnedCallableSourceContract !== undefined,
  );
  if (claims.length === 0) return;
  for (const claim of claims) {
    const contract = claim.metadata.factoryReturnedCallableSourceContract;
    if (
      contract?.schema !== FACTORY_RETURNED_CALLABLE_SOURCE_CONTRACT_SCHEMA ||
      contract.proofKind !== "lexically-bound-factory-returned-function" ||
      contract.factoryBindingKind !== "function-declaration" ||
      contract.factoryName !== "wrapSingleUseListener" ||
      contract.returnedValueShape !== "callable" ||
      contract.sourcePath !== REVIEWED_FACTORY_RETURNED_CALLABLE_SOURCE_PATH ||
      contract.installedPath !== claim.metadata.exportName ||
      !new Set(["process.once", "process.prependOnceListener"]).has(
        contract.installedPath,
      ) ||
      ![
        contract.callsiteEvidence,
        contract.evidence,
        contract.factoryDefinitionEvidence,
      ].every((evidence) => /^sha256-[a-f0-9]{64}$/u.test(evidence ?? ""))
    ) {
      throw new Error(
        `${label}: malformed factory-returned callable evidence for ${claim.observedKey}`,
      );
    }
  }
  const contracts = new Map(
    claims.map((claim) => {
      const contract = claim.metadata.factoryReturnedCallableSourceContract;
      return [contract.evidence, contract];
    }),
  );
  if (contracts.size !== 1) {
    throw new Error(
      `${label}: conflicting factory-returned callable evidence for ${row.observedKey}`,
    );
  }
  existing.metadata ??= {};
  existing.metadata.factoryReturnedCallableSourceContract = structuredClone(
    contracts.values().next().value,
  );
}

function mergeSurfaceEvidence(rows, label) {
  const merged = new Map();
  for (const row of rows) {
    const existing = merged.get(row.observedKey);
    if (!existing) {
      merged.set(row.observedKey, structuredClone(row));
      continue;
    }
    const existingIsGlobalApi = existing.metadata?.surfaceType === "global-api";
    const rowIsGlobalApi = row.metadata?.surfaceType === "global-api";
    const dualNativeGlobalRole =
      existing.kind === "native-op" &&
      row.kind === "native-op" &&
      existingIsGlobalApi !== rowIsGlobalApi;
    const installationBranches = dualNativeGlobalRole
      ? mergeDualRoleInstallationBranches(
          existingIsGlobalApi ? existing : row,
          existingIsGlobalApi ? row : existing,
        )
      : normalizeInstallationBranches([
          ...implicitInstallationBranches(existing),
          ...implicitInstallationBranches(row),
        ]);
    existing.sourceRefs = uniqueSorted([
      ...existing.sourceRefs,
      ...row.sourceRefs,
    ]);
    if (dualNativeGlobalRole) {
      existing.metadata ??= {};
      existing.metadata.surfaceType = "global-api";
      existing.metadata.surfaceTypes = [
        "global-api",
        "private-native-operation",
      ];
      existing.metadata.semanticRoles = uniqueSorted([
        ...(existing.metadata.semanticRoles ?? []),
        ...(row.metadata?.semanticRoles ?? []),
        "global-api-installation",
        "private-native-operation",
      ]);
    }
    if (installationBranches.length > 0) {
      existing.metadata ??= {};
      existing.metadata.installationBranches = installationBranches;
      existing.metadata.branches = installationBranches;
    }
    // @ref LLP 0013#mechanism-1-lockdown — a compatibility shim may also
    // install `eval`; merging its route must not erase pin-bound taming proof.
    mergeHermesEvaluatorEvidence(existing, row, label);
    mergeDynamicNamespaceEvidence(existing, row, label);
    mergeFactoryReturnedCallableEvidence(existing, row, label);
    const readClaims = [existing, row].filter(
      (candidate) => candidate.metadata?.publicReadAccessSourceProven === true,
    );
    if (readClaims.length > 0) {
      existing.metadata ??= {};
      existing.metadata.publicReadAccessSourceProven = true;
      const valueShapes = readClaims.map(
        (candidate) => candidate.metadata?.valueShape ?? null,
      );
      const resolvedShape =
        valueShapes.every(
          (valueShape) => valueShape !== null && valueShape === valueShapes[0],
        ) && valueShapes.length > 0
          ? valueShapes[0]
          : null;
      if (resolvedShape) existing.metadata.valueShape = resolvedShape;
      else delete existing.metadata.valueShape;
    }
    for (const listKey of ["memberKinds", "semanticRoles"]) {
      if (existing.metadata?.[listKey] || row.metadata?.[listKey]) {
        existing.metadata ??= {};
        existing.metadata[listKey] = uniqueSorted([
          ...(existing.metadata[listKey] ?? []),
          ...(row.metadata?.[listKey] ?? []),
        ]);
      }
    }
    if (
      existing.metadata?.inheritedShape === true ||
      row.metadata?.inheritedShape === true
    ) {
      existing.metadata ??= {};
      existing.metadata.inheritedShape = true;
      const reviewIds = uniqueSorted(
        [
          existing.metadata.inheritedShapeReviewId,
          row.metadata?.inheritedShapeReviewId,
        ].filter(Boolean),
      );
      if (reviewIds.length !== 1) {
        throw new Error(
          `${label}: conflicting inherited-shape review evidence for ${row.observedKey}`,
        );
      }
      existing.metadata.inheritedShapeReviewId = reviewIds[0];
    }
    if (existing.metadata?.sourceKey || row.metadata?.sourceKey) {
      existing.metadata.sourceKeys = uniqueSorted([
        ...(existing.metadata.sourceKeys ??
          [existing.metadata.sourceKey].filter(Boolean)),
        ...(row.metadata?.sourceKeys ??
          [row.metadata?.sourceKey].filter(Boolean)),
      ]);
    }
    for (const countKey of ["definitionCount", "occurrenceCount"]) {
      if (row.metadata?.[countKey] !== undefined) {
        existing.metadata[countKey] =
          (existing.metadata[countKey] ?? 0) + row.metadata[countKey];
      }
    }
  }
  const result = sortSurfaces([...merged.values()]);
  for (const row of result) {
    if (row.metadata?.surfaceType !== "global-api") continue;
    const branches = normalizeInstallationBranches(
      implicitInstallationBranches(row),
    );
    if (branches.length === 0) {
      throw new Error(
        `${label}: global API ${row.observedKey} has no installation branch`,
      );
    }
    const branchRefs = uniqueSorted(
      branches.flatMap((branch) => branch.sourceRefs),
    );
    if (JSON.stringify(branchRefs) !== JSON.stringify(row.sourceRefs)) {
      throw new Error(
        `${label}: global API ${row.observedKey} installation branches do not cover exact source refs`,
      );
    }
    row.metadata.installationBranches = branches;
    row.metadata.branches = branches;
  }
  assertUniqueObservedKeys(result, label);
  return result;
}

/**
 * Derive callback producers and startup installers/scripts from one native
 * translation unit. Callback calls group by stable enclosing-definition
 * identity, so source reordering cannot rename the producer while additions
 * still change its occurrence evidence.
 */
export function scanNativeLifecycleSurfaces(
  text,
  sourcePath = "<native-source>",
) {
  const tokens = lexCpp(text, sourcePath);
  const rows = [];
  const definitions = cppFunctionDefinitions(tokens);
  const definitionNameIndexes = new Set(
    definitions.map((definition) => definition.nameIndex),
  );
  const directCallNameIndexes = new Set(
    cppCallExpressions(tokens).map((call) => call.nameIndex),
  );
  const callbackProducers = new Map();
  const callbackProducerNames = new Set([
    "pushRuntimeCallback",
    "tryPushRuntimeExtensionCallback",
  ]);
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].type !== "identifier" ||
      !callbackProducerNames.has(tokens[index].value) ||
      tokens[index + 1]?.value !== "(" ||
      !directCallNameIndexes.has(index) ||
      definitionNameIndexes.has(index)
    ) {
      continue;
    }
    const producer = tokens[index].value;
    const previous = tokens[index - 1]?.value;
    // Header declarations are not producers. Calls are preceded by statement
    // punctuation/flow, while the declaration is preceded by its return type.
    if (previous === "void") continue;
    const enclosing = definitions
      .filter(
        (definition) =>
          definition.bodyOpen < index && index < definition.bodyClose,
      )
      .sort(
        (left, right) =>
          left.bodyClose - left.bodyOpen - (right.bodyClose - right.bodyOpen),
      )[0];
    if (!enclosing) {
      throw new Error(
        `${sourcePath}: ${producer} producer has no structural enclosing definition`,
      );
    }
    const producerIdentity = `${enclosing.identity}:${producer}`;
    const existing = callbackProducers.get(producerIdentity);
    if (existing) {
      existing.occurrenceCount += 1;
    } else {
      callbackProducers.set(producerIdentity, {
        enclosingDefinition: enclosing.identity,
        occurrenceCount: 1,
        producer,
      });
    }
  }
  for (const {
    enclosingDefinition,
    occurrenceCount,
    producer,
  } of callbackProducers.values()) {
    rows.push(
      makeSurface(
        "callback",
        `producer:${sourcePath}:${enclosingDefinition}:${producer}`,
        [
          sourceSymbol(
            sourcePath,
            `${enclosingDefinition}:${producer}`,
          ),
        ],
        {
          metadata: {
            enclosingDefinition,
            evidenceType: "push-runtime-callback-producer",
            occurrenceCount,
            producer,
          },
        },
      ),
    );
  }

  const scriptCounts = new Map();
  for (const token of tokens) {
    if (token.type !== "string" || !/^<[a-z][a-z0-9._-]*>$/u.test(token.value))
      continue;
    scriptCounts.set(token.value, (scriptCounts.get(token.value) ?? 0) + 1);
  }
  for (const [url, occurrenceCount] of scriptCounts) {
    rows.push(
      makeSurface(
        "startup",
        `script:${url.slice(1, -1)}`,
        [sourceSymbol(sourcePath, `script:${url}`)],
        {
          metadata: {
            evidenceType: "startup-evaluation-url",
            occurrenceCount,
            sourceUrl: url,
          },
        },
      ),
    );
  }

  for (const definition of definitions) {
    const isInstaller = /^install[A-Z][A-Za-z0-9_]*$/u.test(definition.name);
    if (isInstaller) {
      rows.push(
        makeSurface(
          "startup",
          `installer:${definition.name}`,
          [sourceSymbol(sourcePath, definition.name)],
          {
            metadata: {
              definitionCount: 1,
              evidenceType: "installer-definition",
              installer: definition.name,
            },
          },
        ),
      );
    }
  }

  const enclosingDefinition = (tokenIndex) =>
    definitions
      .filter(
        (definition) =>
          definition.bodyOpen < tokenIndex && tokenIndex < definition.bodyClose,
      )
      .sort(
        (left, right) =>
          left.bodyClose - left.bodyOpen - (right.bodyClose - right.bodyOpen),
      )[0];
  const lifecycleCaller = (tokenIndex) =>
    enclosingDefinition(tokenIndex) ?? {
      identity: "translation-unit-fallback",
      structuralFallback: true,
    };
  const evaluationRoutes = new Map();
  const installationRoutes = new Map();
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index]?.type === "identifier" &&
      tokens[index].value === "evaluateJavaScript" &&
      tokens[index + 1]?.value === "("
    ) {
      const caller = lifecycleCaller(index);
      const close = matchingToken(tokens, index + 1, "(", ")");
      if (close === -1) {
        throw new Error(
          `${sourcePath}: evaluateJavaScript call has no closing parenthesis`,
        );
      }
      for (const argument of tokens.slice(index + 2, close)) {
        if (
          argument.type !== "string" ||
          !/^<[a-z][a-z0-9._-]*>$/u.test(argument.value)
        ) {
          continue;
        }
        const sourceUrl = argument.value;
        const key = `${caller.identity}\0${sourceUrl}`;
        const route = evaluationRoutes.get(key) ?? {
          caller: caller.identity,
          occurrenceCount: 0,
          sourceUrl,
          structuralFallback: caller.structuralFallback === true,
        };
        route.occurrenceCount += 1;
        evaluationRoutes.set(key, route);
      }
    }
    if (
      tokens[index]?.type === "identifier" &&
      /^install[A-Z][A-Za-z0-9_]*$/u.test(tokens[index].value) &&
      tokens[index + 1]?.value === "(" &&
      !definitionNameIndexes.has(index) &&
      directCallNameIndexes.has(index)
    ) {
      const caller = lifecycleCaller(index);
      const installer = tokens[index].value;
      const key = `${caller.identity}\0${installer}`;
      const route = installationRoutes.get(key) ?? {
        caller: caller.identity,
        installer,
        occurrenceCount: 0,
        structuralFallback: caller.structuralFallback === true,
      };
      route.occurrenceCount += 1;
      installationRoutes.set(key, route);
    }
  }
  for (const route of evaluationRoutes.values()) {
    const url = route.sourceUrl.slice(1, -1);
    rows.push(
      makeSurface(
        "startup",
        `evaluation:${route.caller}:${url}`,
        [
          sourceSymbol(
            sourcePath,
            `${route.caller}:evaluateJavaScript:${route.sourceUrl}`,
          ),
        ],
        {
          metadata: {
            caller: route.caller,
            evidenceType: "startup-evaluation-route",
            occurrenceCount: route.occurrenceCount,
            sourceUrl: route.sourceUrl,
            ...(route.structuralFallback
              ? { structuralFallback: "translation-unit" }
              : {}),
          },
        },
      ),
    );
  }
  for (const route of installationRoutes.values()) {
    rows.push(
      makeSurface(
        "startup",
        `install-route:${route.caller}:${route.installer}`,
        [sourceSymbol(sourcePath, `${route.caller}:${route.installer}`)],
        {
          metadata: {
            caller: route.caller,
            evidenceType: "startup-installer-call-route",
            installer: route.installer,
            occurrenceCount: route.occurrenceCount,
            ...(route.structuralFallback
              ? { structuralFallback: "translation-unit" }
              : {}),
          },
        },
      ),
    );
  }
  return mergeSurfaceEvidence(rows, `${sourcePath} native lifecycle inventory`);
}

const LOADER_FUNCTION_NAME =
  /(?:builtin|capabilit|compile|import|load|module|principal|resolve)/iu;
const CROSS_TARGET_AUTHENTICATED_RESOLVER_FUNCTIONS = new Set([
  "authenticated_resolver_base_dir",
  "canonicalize",
  "metadata",
  "new",
  "read_link",
  "resolve_direct_file_meta_authenticated",
  "resolve_meta_authenticated",
  "resolve_meta_from_authenticated_bound_package",
  "symlink_metadata",
]);

function authenticatedResolverTargetMetadata(name, targetVariant = null) {
  if (targetVariant) return { targetVariant };
  if (!CROSS_TARGET_AUTHENTICATED_RESOLVER_FUNCTIONS.has(name)) return {};
  return {
    branches: [
      {
        id: "descriptor-relative-posix",
        implementationDisposition: "concrete",
        targetVariant: "posix",
      },
      {
        id: "windows-unsupported",
        implementationDisposition: "unsupported-stub",
        targetVariant: "windows",
      },
    ],
  };
}

function isKindMember(node) {
  if (!(
    node?.type === "MemberExpression" &&
    ((!node.computed &&
      node.property?.type === "Identifier" &&
      node.property.name === "kind") ||
      (node.computed &&
        node.property?.type === "StringLiteral" &&
        node.property.value === "kind"))
  )) {
    return false;
  }

  // The authenticated loader now carries principal records whose discriminator
  // is also named `kind` (`root` / `package`). They are authority identities,
  // not module-format branches. Keep the source-derived module-kind inventory
  // open to genuinely new record kinds while excluding only the structurally
  // distinct principal owners.
  const owner = staticMemberChain(node.object);
  return !owner?.some((segment) => /principal/iu.test(segment));
}

function directLoaderKindLiteral(node) {
  if (
    node.type === "BinaryExpression" &&
    new Set(["==", "===", "!=", "!=="]).has(node.operator)
  ) {
    if (isKindMember(node.left) && node.right?.type === "StringLiteral") {
      return node.right.value;
    }
    if (isKindMember(node.right) && node.left?.type === "StringLiteral") {
      return node.left.value;
    }
  }
  if (
    node.type === "LogicalExpression" &&
    new Set(["||", "??"]).has(node.operator)
  ) {
    if (isKindMember(node.left) && node.right?.type === "StringLiteral") {
      return node.right.value;
    }
    if (isKindMember(node.right) && node.left?.type === "StringLiteral") {
      return node.left.value;
    }
  }
  return null;
}

function normalizeLoaderKind(value) {
  const normalized = value
    .replace(/([a-z0-9])([A-Z])/gu, "$1-$2")
    .replaceAll("_", "-")
    .toLowerCase();
  if (normalized === "cjs" || normalized === "common-js") return "commonjs";
  if (normalized === "module") return "esm";
  if (normalized === "addon") return "native-addon";
  if (
    new Set(["builtin", "esm", "json", "native-addon", "wasm"]).has(normalized)
  )
    return normalized;
  return normalized;
}

/** Source-derived JS loader functions and record-kind decision branches. */
export function scanJavaScriptLoaderSurfaces(
  text,
  sourcePath = "<loader-source>",
) {
  const program = parseJavaScript(text, sourcePath);
  const rows = [];
  const functionCounts = new Map();
  const kindRefs = new Map();
  for (const definition of javascriptFunctionDefinitions(program)) {
    if (!LOADER_FUNCTION_NAME.test(definition.name)) continue;
    functionCounts.set(
      definition.name,
      (functionCounts.get(definition.name) ?? 0) + 1,
    );
  }
  walkAst(program, (node) => {
    const literal = directLoaderKindLiteral(node);
    if (literal === null || !/^[A-Za-z][A-Za-z0-9_-]*$/u.test(literal)) return;
    const kind = normalizeLoaderKind(literal);
    if (!kindRefs.has(kind)) kindRefs.set(kind, 0);
    kindRefs.set(kind, kindRefs.get(kind) + 1);
  });

  for (const [name, occurrenceCount] of functionCounts) {
    rows.push(
      makeSurface(
        "loader",
        `function:javascript:${name}`,
        [sourceSymbol(sourcePath, name)],
        {
          metadata: { evidenceType: "loader-function", occurrenceCount },
        },
      ),
    );
  }
  for (const [kind, occurrenceCount] of kindRefs) {
    rows.push(
      makeSurface(
        "loader",
        `kind:${kind}`,
        [sourceSymbol(sourcePath, `kind:${kind}`)],
        {
          metadata: {
            evidenceType: "loader-kind-branch",
            loaderKind: kind,
            occurrenceCount,
          },
        },
      ),
    );
  }
  return mergeSurfaceEvidence(
    rows,
    `${sourcePath} JavaScript loader inventory`,
  );
}

function walkAstWithAncestors(root, visitor) {
  const visit = (node, ancestors) => {
    if (!node || typeof node !== "object") return;
    if (typeof node.type === "string") visitor(node, ancestors);
    const nextAncestors =
      typeof node.type === "string" ? [...ancestors, node] : ancestors;
    for (const [key, value] of Object.entries(node)) {
      if (
        new Set(["comments", "errors", "extra", "loc", "start", "end"]).has(key)
      ) {
        continue;
      }
      if (Array.isArray(value)) {
        for (const child of value) visit(child, nextAncestors);
      } else if (value && typeof value === "object") {
        visit(value, nextAncestors);
      }
    }
  };
  visit(root, []);
}

function staticMemberChain(node) {
  if (node?.type === "Identifier") return [node.name];
  if (node?.type !== "MemberExpression") return null;
  const parent = staticMemberChain(node.object);
  const member = directMemberName(node);
  return parent && member !== null ? [...parent, member] : null;
}

function equalityStrings(node, identifiers) {
  const values = new Set();
  walkAst(node, (candidate) => {
    if (
      candidate.type === "BinaryExpression" &&
      new Set(["==", "==="]).has(candidate.operator)
    ) {
      const pairs = [
        [candidate.left, candidate.right],
        [candidate.right, candidate.left],
      ];
      for (const [identifier, literal] of pairs) {
        if (
          identifier?.type === "Identifier" &&
          identifiers.has(identifier.name) &&
          literal?.type === "StringLiteral"
        ) {
          values.add(literal.value);
        }
      }
    }
    if (
      candidate.type === "CallExpression" &&
      candidate.callee?.type === "MemberExpression" &&
      directMemberName(candidate.callee) === "indexOf" &&
      candidate.callee.object?.type === "Identifier" &&
      identifiers.has(candidate.callee.object.name) &&
      candidate.arguments[0]?.type === "StringLiteral"
    ) {
      values.add(candidate.arguments[0].value);
    }
  });
  return values;
}

/** Exact internal routes, entry points, and lazy bootstrap installers. */
export function scanJavaScriptLoaderRoutes(
  text,
  sourcePath = "src/engine/bootstrap/module-loader.js",
) {
  const program = parseJavaScript(text, sourcePath);
  const definitions = new Map(
    javascriptFunctionDefinitions(program).map((definition) => [
      definition.name,
      definition.node,
    ]),
  );
  const rows = [];

  const internalModules = [];
  walkAst(program, (node) => {
    if (
      node.type === "VariableDeclarator" &&
      node.id?.type === "Identifier" &&
      node.id.name === "internalModules"
    ) {
      internalModules.push(node.init);
    }
  });
  if (
    internalModules.length !== 1 ||
    internalModules[0]?.type !== "ObjectExpression"
  ) {
    throw new Error(
      `${sourcePath}: expected one static internalModules object`,
    );
  }
  const internalNames = new Set();
  for (const property of internalModules[0].properties) {
    if (property.type === "SpreadElement") {
      throw new Error(
        `${sourcePath}: internalModules has an opaque spread route`,
      );
    }
    const names =
      !property.computed && property.key?.type === "Identifier"
        ? [property.key.name]
        : staticPropertyName(property.key);
    if (names.length !== 1) {
      throw new Error(
        `${registrationContext(text, property, sourcePath)}: unresolved computed internal loader route`,
      );
    }
    internalNames.add(names[0]);
  }
  for (const [functionName, identifiers] of [
    ["loadInternal", new Set(["normalized"])],
    ["_loadNamedStreamInternal", new Set(["name"])],
  ]) {
    const definition = definitions.get(functionName);
    if (!definition)
      throw new Error(
        `${sourcePath}: missing loader route function ${functionName}`,
      );
    for (const name of equalityStrings(definition.body, identifiers))
      internalNames.add(name);
  }
  for (const name of internalNames) {
    rows.push(
      makeSurface(
        "loader",
        `internal-route:${name}`,
        [sourceSymbol(sourcePath, `internal-route:${name}`)],
        {
          metadata: { evidenceType: "internal-loader-route", specifier: name },
        },
      ),
    );
  }

  const lazyRoutes = new Map();
  walkAstWithAncestors(program, (node, ancestors) => {
    if (
      node.type !== "CallExpression" ||
      node.callee?.type !== "Identifier" ||
      !/^__exactEnsure[A-Z][A-Za-z0-9_]*$/u.test(node.callee.name)
    ) {
      return;
    }
    const installer = node.callee.name;
    const enclosingIfs = ancestors.filter(
      (ancestor) => ancestor.type === "IfStatement",
    );
    const specifiers = new Set();
    for (const statement of enclosingIfs) {
      for (const specifier of equalityStrings(
        statement.test,
        new Set(["specifier"]),
      )) {
        specifiers.add(specifier);
      }
    }
    if (specifiers.size === 0) {
      throw new Error(
        `${registrationContext(text, node, sourcePath)}: lazy installer ${installer} has no exact specifier routes`,
      );
    }
    const existing = lazyRoutes.get(installer) ?? new Set();
    for (const specifier of specifiers) existing.add(specifier);
    lazyRoutes.set(installer, existing);
  });
  if (lazyRoutes.size === 0)
    throw new Error(`${sourcePath}: no lazy loader installers discovered`);
  for (const [installer, specifiers] of lazyRoutes) {
    for (const specifier of specifiers) {
      rows.push(
        makeSurface(
          "loader",
          `lazy-installer:${installer}:${specifier}`,
          [sourceSymbol(sourcePath, `${installer}:${specifier}`)],
          {
            metadata: {
              evidenceType: "lazy-loader-installer-route",
              installer,
              specifier,
            },
          },
        ),
      );
    }
  }

  const definitionRoutes = new Map([
    ["__exactResolvePath", "entry:resolve-path"],
    ["importImpl", "entry:dynamic-import"],
    ["load", "entry:load"],
    ["loadInternal", "entry:load-internal"],
    ["localRequire", "entry:local-require"],
    ["moduleDynamicImport", "entry:module-dynamic-import"],
    ["moduleStaticImport", "entry:module-static-import"],
  ]);
  for (const [definition, route] of definitionRoutes) {
    if (!definitions.has(definition)) {
      throw new Error(
        `${sourcePath}: loader entry route ${definition} is absent`,
      );
    }
    rows.push(
      makeSurface("loader", route, [sourceSymbol(sourcePath, definition)], {
        metadata: {
          evidenceType: "loader-entry-route",
          implementation: definition,
        },
      }),
    );
  }

  const globalRoutes = new Map([
    ["globalThis.__exactRequire", "entry:exact-require"],
    ["globalThis.import", "entry:global-import"],
    ["globalThis.importModule", "entry:import-module"],
    ["globalThis.require", "entry:global-require"],
    ["globalThis.require.resolve", "entry:require-resolve"],
  ]);
  const observedGlobals = new Set();
  walkAst(program, (node) => {
    if (node.type === "AssignmentExpression") {
      const chain = staticMemberChain(node.left);
      if (chain) observedGlobals.add(chain.join("."));
    }
    if (
      node.type === "CallExpression" &&
      callName(node) === "defineProperty" &&
      node.arguments[0]?.type === "Identifier" &&
      node.arguments[0].name === "globalThis" &&
      node.arguments[1]?.type === "StringLiteral"
    ) {
      observedGlobals.add(`globalThis.${node.arguments[1].value}`);
    }
  });
  for (const [globalName, route] of globalRoutes) {
    if (!observedGlobals.has(globalName)) {
      throw new Error(
        `${sourcePath}: loader global entry ${globalName} is absent`,
      );
    }
    rows.push(
      makeSurface("loader", route, [sourceSymbol(sourcePath, globalName)], {
        metadata: { evidenceType: "loader-entry-route", globalName },
      }),
    );
  }

  return sortSurfaces(rows);
}

/** Source-derived Rust loader functions and ModuleKind/ModuleType branches. */
export function scanRustLoaderSurfaces(
  text,
  sourcePath = "<loader-source>",
  options = {},
) {
  const tokens = rustProductionTokens(text, sourcePath);
  const rows = [];
  const functionCounts = new Map();
  const kindCounts = new Map();

  for (const definition of rustFunctionDefinitions(tokens)) {
    if (!LOADER_FUNCTION_NAME.test(definition.name)) continue;
    if (
      options.publicOnly === true &&
      !rustFunctionHasPublicVisibility(tokens, definition.fnIndex)
    ) {
      continue;
    }
    const observed = functionCounts.get(definition.name) ?? {
      occurrenceCount: 0,
      targetVariants: new Set(),
    };
    observed.occurrenceCount += 1;
    const targetVariant = rustImmediateCfgTargetVariant(
      tokens,
      definition.fnIndex,
    );
    if (targetVariant) observed.targetVariants.add(targetVariant);
    functionCounts.set(definition.name, observed);
  }

  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index].type === "identifier" &&
      new Set(["ModuleKind", "ModuleType"]).has(tokens[index].value) &&
      tokens[index + 1]?.value === ":" &&
      tokens[index + 2]?.value === ":" &&
      tokens[index + 3]?.type === "identifier"
    ) {
      const kind = normalizeLoaderKind(tokens[index + 3].value);
      kindCounts.set(kind, (kindCounts.get(kind) ?? 0) + 1);
    }
  }

  for (const [name, observed] of functionCounts) {
    const targetVariant =
      observed.targetVariants.size === 1
        ? [...observed.targetVariants][0]
        : null;
    rows.push(
      makeSurface(
        "loader",
        `function:rust:${name}`,
        [sourceSymbol(sourcePath, name)],
        {
          metadata: {
            evidenceType: "loader-function",
            occurrenceCount: observed.occurrenceCount,
            ...authenticatedResolverTargetMetadata(name, targetVariant),
          },
        },
      ),
    );
  }
  for (const [kind, occurrenceCount] of kindCounts) {
    rows.push(
      makeSurface(
        "loader",
        `kind:${kind}`,
        [sourceSymbol(sourcePath, `kind:${kind}`)],
        {
          metadata: {
            evidenceType: "loader-kind-branch",
            loaderKind: kind,
            occurrenceCount,
          },
        },
      ),
    );
  }
  return mergeSurfaceEvidence(rows, `${sourcePath} Rust loader inventory`);
}

function rustQualifiedCallPath(tokens, terminalIndex) {
  const segments = [tokens[terminalIndex].value];
  let cursor = terminalIndex;
  while (
    tokens[cursor - 1]?.value === ":" &&
    tokens[cursor - 2]?.value === ":" &&
    tokens[cursor - 3]?.type === "identifier"
  ) {
    segments.unshift(tokens[cursor - 3].value);
    cursor -= 3;
  }
  return segments;
}

function qualifiedLoaderAuthorityOperation(segments) {
  const joined = segments.join("::");
  const terminal = segments.at(-1);
  if (/^libc::(?:open|openat)$/u.test(joined)) return "open";
  if (/^libc::(?:fstat|fstatat)$/u.test(joined)) return "metadata";
  if (joined === "libc::readlinkat") return "read_link";
  const authorityPrefix =
    /^(?:std::(?:env|fs|io|net|process)|(?:async_std|tokio)::(?:fs|io|net|process))::/u.test(
      joined,
    ) ||
    /^(?:Command|File|OpenOptions|TcpListener|TcpStream|UdpSocket|UnixListener|UnixStream)::/u.test(
      joined,
    );
  if (!authorityPrefix) return null;
  if (/(?:^|::)Command::new$/u.test(joined)) return "command-new";
  if (/(?:^|::)File::from$/u.test(joined)) return "from-owned-fd";
  if (/^(?:std::)?env::/u.test(joined)) return `env-${terminal}`;
  if (/^std::process::/u.test(joined)) return `process-${terminal}`;
  return terminal;
}

function loaderExternalCallIdentity(tokens, index, localTargets) {
  if (tokens[index]?.type !== "identifier" || tokens[index + 1]?.value !== "(")
    return null;
  const name = tokens[index].value;
  if (new Set(["if", "loop", "match", "return", "while"]).has(name)) {
    return null;
  }
  if (localTargets.length > 0) return null;
  const qualified = rustQualifiedCallPath(tokens, index);
  if (qualified.length > 1) return `qualified:${qualified.join("::")}`;
  if (tokens[index - 1]?.value === ".") return `method:${name}`;
  return `call:${name}`;
}

/**
 * Follow the production-local Rust call graph from reviewed loader roots.
 * Categories are kept separate because resolution, loader-cache I/O,
 * in-process transformation, and the opt-in subprocess escape hatch have
 * different authority semantics even when they share helpers.
 */
export function scanRustLoaderRoutes(sources) {
  if (!Array.isArray(sources) || sources.length === 0) {
    throw new Error("Rust loader route scan requires source inputs");
  }

  const moduleIdForSourcePath = (sourcePath) => {
    const segments = sourcePath.split("/");
    const file = segments.at(-1) ?? sourcePath;
    const stem = file.replace(/\.rs$/u, "");
    return stem === "mod" ? (segments.at(-2) ?? stem) : stem;
  };
  const implScopes = (tokens) => {
    const scopes = [];
    const firstTypeIdentifier = (start, end) => {
      let cursor = start;
      if (tokens[cursor]?.value === "<") {
        let depth = 0;
        while (cursor < end) {
          if (tokens[cursor]?.value === "<") depth += 1;
          if (tokens[cursor]?.value === ">") {
            depth -= 1;
            if (depth === 0) {
              cursor += 1;
              break;
            }
          }
          cursor += 1;
        }
      }
      while (cursor < end) {
        if (tokens[cursor]?.type === "identifier") {
          let name = tokens[cursor].value;
          while (
            tokens[cursor + 1]?.value === ":" &&
            tokens[cursor + 2]?.value === ":" &&
            tokens[cursor + 3]?.type === "identifier"
          ) {
            name = tokens[cursor + 3].value;
            cursor += 3;
          }
          return name;
        }
        cursor += 1;
      }
      return null;
    };

    for (let index = 0; index < tokens.length; index += 1) {
      if (tokens[index]?.value !== "impl") continue;
      let bodyOpen = index + 1;
      while (
        bodyOpen < tokens.length &&
        !new Set(["{", ";"]).has(tokens[bodyOpen]?.value)
      ) {
        bodyOpen += 1;
      }
      if (tokens[bodyOpen]?.value !== "{") continue;
      const bodyClose = matchingToken(tokens, bodyOpen, "{", "}");
      if (bodyClose === -1) continue;
      let forIndex = -1;
      for (let cursor = index + 1; cursor < bodyOpen; cursor += 1) {
        if (tokens[cursor]?.value === "for") forIndex = cursor;
      }
      const trait =
        forIndex === -1
          ? null
          : firstTypeIdentifier(index + 1, forIndex);
      const selfType = firstTypeIdentifier(
        forIndex === -1 ? index + 1 : forIndex + 1,
        bodyOpen,
      );
      if (selfType) {
        scopes.push({ bodyClose, bodyOpen, selfType, trait });
      }
    }
    return scopes;
  };

  const records = [];
  for (const source of sources) {
    const tokens = rustProductionTokens(source.text, source.sourcePath);
    const definitions = rustFunctionDefinitions(tokens);
    const sourceRecords = definitions.map((definition) => ({
      definition,
      id: `${source.sourcePath}#fn-${definition.nameIndex}`,
      moduleId: moduleIdForSourcePath(source.sourcePath),
      sourcePath: source.sourcePath,
      targetVariant: rustImmediateCfgTargetVariant(tokens, definition.fnIndex),
      tokens,
    }));
    const scopes = implScopes(tokens);
    for (const record of sourceRecords) {
      const lexicalParent = sourceRecords
        .filter(
          (candidate) =>
            candidate.definition.bodyOpen < record.definition.fnIndex &&
            candidate.definition.bodyClose > record.definition.bodyClose,
        )
        .sort(
          (left, right) =>
            right.definition.bodyOpen - left.definition.bodyOpen,
        )[0];
      const enclosingImpl = scopes
        .filter(
          (scope) =>
            scope.bodyOpen < record.definition.fnIndex &&
            scope.bodyClose > record.definition.bodyClose,
        )
        .sort((left, right) => right.bodyOpen - left.bodyOpen)[0];
      const directImplMember =
        enclosingImpl &&
        enclosingImpl.bodyOpen >
          (lexicalParent?.definition.bodyOpen ?? Number.NEGATIVE_INFINITY);
      record.lexicalParentFnId = lexicalParent?.id ?? null;
      record.implSelfType = directImplMember
        ? enclosingImpl.selfType
        : null;
      record.implTrait = directImplMember ? enclosingImpl.trait : null;
      const parameters = new Map();
      const parametersOpen = tokens.findIndex(
        (token, index) =>
          index > record.definition.nameIndex &&
          index < record.definition.bodyOpen &&
          token.value === "(",
      );
      const parametersClose =
        parametersOpen === -1
          ? -1
          : matchingToken(tokens, parametersOpen, "(", ")");
      record.parametersClose = parametersClose;
      if (parametersClose !== -1) {
        for (
          let cursor = parametersOpen + 1;
          cursor < parametersClose - 1;
          cursor += 1
        ) {
          if (
            tokens[cursor]?.type !== "identifier" ||
            tokens[cursor + 1]?.value !== ":" ||
            tokens[cursor + 2]?.value === ":"
          ) {
            continue;
          }
          let typeCursor = cursor + 2;
          while (
            typeCursor < parametersClose &&
            tokens[typeCursor]?.type !== "identifier"
          ) {
            typeCursor += 1;
          }
          if (tokens[typeCursor]?.type === "identifier") {
            let typeName = tokens[typeCursor].value;
            while (
              tokens[typeCursor + 1]?.value === ":" &&
              tokens[typeCursor + 2]?.value === ":" &&
              tokens[typeCursor + 3]?.type === "identifier"
            ) {
              typeName = tokens[typeCursor + 3].value;
              typeCursor += 3;
            }
            parameters.set(tokens[cursor].value, typeName);
          }
        }
      }
      record.parameterTypes = parameters;
      record.definitionId = record.implSelfType
        ? `${record.moduleId}::${record.implSelfType}${record.implTrait ? ` as ${record.implTrait}` : ""}::${record.definition.name}`
        : record.lexicalParentFnId
          ? `${lexicalParent.definitionId ?? `${record.moduleId}::${lexicalParent.definition.name}`}::${record.definition.name}`
          : `${record.moduleId}::${record.definition.name}`;
    }
    records.push(...sourceRecords);
  }

  const byId = new Map(records.map((record) => [record.id, record]));
  const byName = new Map();
  const freeByModuleAndName = new Map();
  const methodByModuleTypeAndName = new Map();
  const append = (map, key, record) => {
    const values = map.get(key) ?? [];
    values.push(record);
    map.set(key, values);
  };
  for (const record of records) {
    append(byName, record.definition.name, record);
    if (record.implSelfType) {
      append(
        methodByModuleTypeAndName,
        `${record.moduleId}\0${record.implSelfType}\0${record.definition.name}`,
        record,
      );
    } else if (!record.lexicalParentFnId) {
      append(
        freeByModuleAndName,
        `${record.moduleId}\0${record.definition.name}`,
        record,
      );
    }
  }
  const moduleIds = new Set(records.map((record) => record.moduleId));
  const locallyImplementedTypes = new Set(
    records.map((record) => record.implSelfType).filter(Boolean),
  );
  const reviewedRustValueTypes = new Set([
    ...locallyImplementedTypes,
    "Command",
    "DirEntry",
    "File",
    "OpenOptions",
    "Path",
    "PathBuf",
    "ReadDir",
    "ResolvedModule",
  ]);
  for (const record of records) {
    const returnTokens = record.tokens.slice(
      Math.max(record.parametersClose + 1, record.definition.nameIndex + 1),
      record.definition.bodyOpen,
    );
    record.returnType = returnTokens.some(
      (token) => token.value === "Self",
    )
      ? record.implSelfType
      : returnTokens.find(
          (token) =>
            token.type === "identifier" &&
            reviewedRustValueTypes.has(token.value),
        )?.value ?? null;
  }
  const externalReturnType = (tokens, index, receiverType = null) => {
    const qualified = rustQualifiedCallPath(tokens, index).join("::");
    if (/(?:^|::)File::(?:from|from_raw_fd)$/u.test(qualified)) return "File";
    if (/(?:^|::)Command::new$/u.test(qualified)) return "Command";
    if (/(?:^|::)OpenOptions::new$/u.test(qualified)) return "OpenOptions";
    if (/(?:^|::)Path::new$/u.test(qualified)) return "Path";
    if (/(?:^|::)PathBuf::from$/u.test(qualified)) return "PathBuf";
    if (/^(?:std::)?fs::read_dir$/u.test(qualified)) return "ReadDir";
    if (receiverType === "OpenOptions" && tokens[index]?.value === "open") {
      return "File";
    }
    return null;
  };
  const reviewedLetPostfixType = (receiverType, method) => {
    if (new Set(["context", "with_context"]).has(method)) return receiverType;
    if (receiverType === "OpenOptions") {
      if (method === "open") return "File";
      if (
        new Set([
          "append",
          "create",
          "create_new",
          "custom_flags",
          "read",
          "truncate",
          "write",
        ]).has(method)
      ) {
        return "OpenOptions";
      }
    }
    if (receiverType === "Command") {
      if (
        new Set([
          "arg",
          "args",
          "current_dir",
          "env",
          "env_clear",
          "env_remove",
          "stderr",
          "stdin",
          "stdout",
        ]).has(method)
      ) {
        return "Command";
      }
    }
    if (receiverType === "ReadDir" && method === "collect") {
      return "VecDirEntry";
    }
    if (receiverType === "PathBuf" && method === "as_path") return "Path";
    return null;
  };
  const exactReviewedLetRhsType = (
    tokens,
    rhsStart,
    statementEnd,
    candidate,
  ) => {
    const [callIndex, initialType, callDepth] = candidate;
    const unsafeWrapper =
      tokens[rhsStart]?.value === "unsafe" &&
      tokens[rhsStart + 1]?.value === "{" &&
      matchingToken(tokens, rhsStart + 1, "{", "}") === statementEnd - 1;
    if (callDepth !== (unsafeWrapper ? 1 : 0)) return null;
    let cursor = matchingToken(tokens, callIndex + 1, "(", ")") + 1;
    if (cursor === 0) return null;
    let inferredType = initialType;
    const valueEnd = unsafeWrapper ? statementEnd - 1 : statementEnd;
    while (cursor < valueEnd) {
      if (tokens[cursor]?.value === "?") {
        cursor += 1;
        continue;
      }
      if (
        tokens[cursor]?.value !== "." ||
        tokens[cursor + 1]?.type !== "identifier"
      ) {
        return null;
      }
      const method = tokens[cursor + 1].value;
      inferredType = reviewedLetPostfixType(inferredType, method);
      if (!inferredType) return null;
      let argsOpen = cursor + 2;
      while (argsOpen < valueEnd && tokens[argsOpen]?.value !== "(") {
        argsOpen += 1;
      }
      if (tokens[argsOpen]?.value !== "(") return null;
      const argsClose = matchingToken(tokens, argsOpen, "(", ")");
      if (argsClose === -1 || argsClose >= valueEnd) return null;
      cursor = argsClose + 1;
    }
    return cursor === valueEnd ? inferredType : null;
  };
  for (const record of records) {
    const inferred = new Map(record.parameterTypes);
    const { bodyOpen, bodyClose } = record.definition;
    for (let index = bodyOpen + 1; index < bodyClose; index += 1) {
      if (record.tokens[index]?.value !== "let") continue;
      let bindingCursor = index + 1;
      if (record.tokens[bindingCursor]?.value === "mut") bindingCursor += 1;
      let binding = null;
      if (
        record.tokens[bindingCursor]?.value === "Ok" &&
        record.tokens[bindingCursor + 1]?.value === "(" &&
        record.tokens[bindingCursor + 2]?.type === "identifier" &&
        record.tokens[bindingCursor + 3]?.value === ")"
      ) {
        binding = record.tokens[bindingCursor + 2].value;
      } else if (record.tokens[bindingCursor]?.type === "identifier") {
        binding = record.tokens[bindingCursor].value;
      }
      if (!binding) continue;

      let equalsIndex = bindingCursor + 1;
      while (
        equalsIndex < bodyClose &&
        !new Set(["=", ";"]).has(record.tokens[equalsIndex]?.value)
      ) {
        equalsIndex += 1;
      }
      if (record.tokens[equalsIndex]?.value !== "=") continue;

      let statementEnd = equalsIndex + 1;
      const delimiterStack = [];
      while (statementEnd < bodyClose) {
        const value = record.tokens[statementEnd]?.value;
        if (new Set(["(", "[", "{"]).has(value)) {
          delimiterStack.push(value);
        } else if (new Set([")", "]", "}"]).has(value)) {
          delimiterStack.pop();
        } else if (
          delimiterStack.length === 0 &&
          new Set(["else", ";"]).has(value)
        ) {
          break;
        }
        statementEnd += 1;
      }

      let explicitType = null;
      const colonIndex = record.tokens.findIndex(
        (token, cursor) =>
          cursor > bindingCursor &&
          cursor < equalsIndex &&
          token.value === ":" &&
          record.tokens[cursor + 1]?.value !== ":",
      );
      if (colonIndex !== -1) {
        explicitType = record.tokens
          .slice(colonIndex + 1, equalsIndex)
          .find(
            (token) =>
              token.type === "identifier" &&
              reviewedRustValueTypes.has(token.value),
          )?.value;
      }

      let expressionDepth = 0;
      let hasTopLevelControl = false;
      let hasTopLevelComma = false;
      let firstRhsCallIndex = null;
      const candidates = [];
      for (let cursor = equalsIndex + 1; cursor < statementEnd; cursor += 1) {
        const value = record.tokens[cursor]?.value;
        if (new Set(["(", "[", "{"]).has(value)) expressionDepth += 1;
        if (new Set([")", "]", "}"]).has(value)) expressionDepth -= 1;
        if (expressionDepth === 0 && new Set(["if", "match"]).has(value)) {
          hasTopLevelControl = true;
        }
        if (expressionDepth === 0 && value === ",") hasTopLevelComma = true;
        if (
          record.tokens[cursor]?.type !== "identifier" ||
          record.tokens[cursor + 1]?.value !== "("
        ) {
          continue;
        }
        firstRhsCallIndex ??= cursor;
        const qualifiedType = externalReturnType(record.tokens, cursor);
        if (qualifiedType) {
          candidates.push([cursor, qualifiedType, expressionDepth]);
        }
        if (
          record.tokens[cursor - 1]?.value === "." &&
          record.tokens[cursor - 2]?.type === "identifier"
        ) {
          const receiver = record.tokens[cursor - 2].value;
          const receiverType =
            inferred.get(receiver) ??
            (receiver === "self" ? record.implSelfType : null);
          if (receiverType) {
            const targets =
              methodByModuleTypeAndName.get(
                `${record.moduleId}\0${receiverType}\0${record.tokens[cursor].value}`,
              ) ?? [];
            if (targets.length === 1 && targets[0].returnType) {
              candidates.push([
                cursor,
                targets[0].returnType,
                expressionDepth,
              ]);
            } else {
              const externalType = externalReturnType(
                record.tokens,
                cursor,
                receiverType,
              );
              if (externalType) {
                candidates.push([cursor, externalType, expressionDepth]);
              }
            }
          }
        }
      }
      const rhsStart = equalsIndex + 1;
      const outerTupleClose =
        record.tokens[rhsStart]?.value === "("
          ? matchingToken(record.tokens, rhsStart, "(", ")")
          : -1;
      const hasOuterTuple =
        outerTupleClose === statementEnd - 1 &&
        record.tokens
          .slice(rhsStart + 1, outerTupleClose)
          .some((token) => token.value === ",");

      let inferredType = explicitType ?? null;
      if (
        !inferredType &&
        !hasTopLevelControl &&
        !hasTopLevelComma &&
        !hasOuterTuple &&
        candidates.length === 1 &&
        candidates[0][0] === firstRhsCallIndex
      ) {
        inferredType = exactReviewedLetRhsType(
          record.tokens,
          rhsStart,
          statementEnd,
          candidates[0],
        );
      }
      if (inferredType) inferred.set(binding, inferredType);
    }
    record.inferredReceiverTypes = inferred;
    record.scopedReceiverTypes = [];
  }
  const nestedDefinitionRanges = new Map();
  for (const record of records) {
    nestedDefinitionRanges.set(
      record.id,
      new Map(
        records
          .filter(
            (candidate) =>
              candidate.sourcePath === record.sourcePath &&
              candidate.id !== record.id &&
              candidate.definition.fnIndex > record.definition.bodyOpen &&
              candidate.definition.bodyClose < record.definition.bodyClose,
          )
          .map((candidate) => [
            candidate.definition.fnIndex,
            candidate.definition.bodyClose,
          ]),
      ),
    );
  }
  const requireUnambiguous = (candidates, label) => {
    if (candidates.length > 1) {
      throw new Error(
        `ambiguous Rust loader local call ${label}: ${candidates
          .map((candidate) => candidate.definitionId)
          .join(", ")}`,
      );
    }
    return candidates;
  };
  const localCallTargets = (record, index) => {
    const token = record.tokens[index];
    if (
      token?.type !== "identifier" ||
      record.tokens[index + 1]?.value !== "(" ||
      new Set(["if", "loop", "match", "return", "while"]).has(token.value)
    ) {
      return [];
    }

    if (record.tokens[index - 1]?.value === ".") {
      const receiver = record.tokens[index - 2];
      let receiverType =
        receiver?.type === "identifier" && receiver.value === "self"
          ? record.implSelfType
          : null;
      if (receiver?.type === "identifier") {
        receiverType ??=
          record.inferredReceiverTypes.get(receiver.value) ?? null;
      }
      if (
        !receiverType &&
        receiver?.type === "identifier" &&
        record.tokens[index - 3]?.value === "." &&
        record.tokens[index - 4]?.value === "self" &&
        record.implSelfType === "ModuleLoader" &&
        receiver.value === "environment"
      ) {
        receiverType = "CapturedModuleLoaderEnvironment";
      }
      if (
        !receiverType &&
        receiver?.type === "identifier" &&
        record.tokens[index - 3]?.value === ":" &&
        record.tokens[index - 4]?.value === ":" &&
        record.tokens[index - 5]?.value === "TransformEngine"
      ) {
        receiverType = "TransformEngine";
      }
      if (!receiverType) {
        let closeIndex = index - 2;
        if (record.tokens[closeIndex]?.value === "?") closeIndex -= 1;
        if (record.tokens[closeIndex]?.value === ")") {
          const openIndex = matchingOpeningToken(
            record.tokens,
            closeIndex,
            "(",
            ")",
          );
          const callIndex = openIndex - 1;
          if (record.tokens[callIndex]?.type === "identifier") {
            const targets = localCallTargets(record, callIndex);
            if (targets.length === 1) {
              receiverType = targets[0].returnType;
            }
            receiverType ??= externalReturnType(
              record.tokens,
              callIndex,
            );
          }
        }
      }
      if (
        !receiverType &&
        record.moduleId === "transpile" &&
        record.definition.name === "selected_engine_cache_tag" &&
        token.value === "cache_tag"
      ) {
        receiverType = "TransformEngine";
      }
      if (!receiverType) return [];
      return requireUnambiguous(
        methodByModuleTypeAndName.get(
          `${record.moduleId}\0${receiverType}\0${token.value}`,
        ) ?? [],
        `${record.definitionId}:${receiver?.value ?? "expression"}.${token.value}`,
      );
    }

    const qualified = rustQualifiedCallPath(record.tokens, index);
    if (qualified.length > 1) {
      const qualifier = qualified.at(-2);
      if (qualifier === "Self") {
        if (!record.implSelfType) return [];
        return requireUnambiguous(
          methodByModuleTypeAndName.get(
            `${record.moduleId}\0${record.implSelfType}\0${token.value}`,
          ) ?? [],
          `${record.definitionId}:Self::${token.value}`,
        );
      }
      const qualifiedModule = moduleIds.has(qualifier)
        ? qualifier
        : record.moduleId;
      const candidates = [
        ...(methodByModuleTypeAndName.get(
          `${qualifiedModule}\0${qualifier}\0${token.value}`,
        ) ?? []),
        ...(moduleIds.has(qualifier)
          ? (freeByModuleAndName.get(`${qualifier}\0${token.value}`) ?? [])
          : []),
      ];
      return requireUnambiguous(
        candidates,
        `${record.definitionId}:${qualified.join("::")}`,
      );
    }

    const sameName = byName.get(token.value) ?? [];
    if (
      record.definition.name === token.value &&
      !record.implSelfType &&
      record.lexicalParentFnId
    ) {
      return [record];
    }
    let scopeId = record.id;
    while (scopeId) {
      const nested = sameName.filter(
        (candidate) =>
          !candidate.implSelfType && candidate.lexicalParentFnId === scopeId,
      );
      if (nested.length > 0) {
        return requireUnambiguous(
          nested,
          `${record.definitionId}:nested:${token.value}`,
        );
      }
      scopeId = byId.get(scopeId)?.lexicalParentFnId ?? null;
    }
    return requireUnambiguous(
      freeByModuleAndName.get(`${record.moduleId}\0${token.value}`) ?? [],
      `${record.definitionId}:free:${token.value}`,
    );
  };

  const reviewedFieldType = (ownerType, field) => {
    if (ownerType === "ResolvedModule" && field === "path") {
      return "OptionPathBuf";
    }
    return null;
  };
  const exactReadDirOkFilterMap = (tokens, callIndex) => {
    const argsOpen = callIndex + 1;
    const argsClose = matchingToken(tokens, argsOpen, "(", ")");
    if (argsClose === -1) return false;
    const body = tokens.slice(argsOpen + 1, argsClose).map((token) => token.value);
    return (
      body.length === 7 &&
      body[0] === "|" &&
      body[2] === "|" &&
      body[3] === body[1] &&
      body[4] === "." &&
      body[5] === "ok" &&
      body[6] === "("
    ) || (
      body.length === 8 &&
      body[0] === "|" &&
      body[2] === "|" &&
      body[3] === body[1] &&
      body[4] === "." &&
      body[5] === "ok" &&
      body[6] === "(" &&
      body[7] === ")"
    );
  };
  const reviewedMethodValueType = (receiverType, method, tokens, callIndex) => {
    if (receiverType === "OpenOptions") {
      if (method === "open") return "File";
      if (
        new Set([
          "append",
          "create",
          "create_new",
          "custom_flags",
          "read",
          "truncate",
          "write",
        ]).has(method)
      ) {
        return "OpenOptions";
      }
    }
    if (receiverType === "Command") {
      if (
        new Set([
          "arg",
          "args",
          "current_dir",
          "env",
          "env_clear",
          "env_remove",
          "stderr",
          "stdin",
          "stdout",
        ]).has(method)
      ) {
        return "Command";
      }
    }
    if (receiverType === "OptionPathBuf" && method === "as_deref") {
      return "OptionPath";
    }
    if (receiverType === "OptionPath" && method === "ok_or_else") {
      return "Path";
    }
    if (receiverType === "PathBuf" && method === "as_path") return "Path";
    if (
      new Set(["Path", "PathBuf"]).has(receiverType) &&
      method === "canonicalize"
    ) {
      return "PathBuf";
    }
    if (receiverType === "ReadDir") {
      if (method === "collect") return "VecDirEntry";
      if (method === "filter_map" && exactReadDirOkFilterMap(tokens, callIndex)) {
        return "IteratorDirEntry";
      }
    }
    if (receiverType === "VecDirEntry") {
      if (new Set(["filter", "iter", "into_iter"]).has(method)) {
        return "IteratorDirEntry";
      }
    }
    if (receiverType === "IteratorDirEntry" && method === "filter") {
      return "IteratorDirEntry";
    }
    return externalReturnType(tokens, callIndex, receiverType);
  };

  const expressionTypeAtEnd = (record, rawEndIndex, seen = new Set()) => {
    let endIndex = rawEndIndex;
    while (new Set(["?", "&", "mut"]).has(record.tokens[endIndex]?.value)) {
      endIndex -= 1;
    }
    if (endIndex < record.definition.bodyOpen || seen.has(endIndex)) return null;
    seen.add(endIndex);
    const end = record.tokens[endIndex];
    if (end?.type === "identifier") {
      if (
        record.tokens[endIndex - 1]?.value === "." &&
        record.tokens[endIndex - 2]?.type === "identifier"
      ) {
        const ownerType = expressionTypeAtEnd(record, endIndex - 2, seen);
        const fieldType = reviewedFieldType(ownerType, end.value);
        if (fieldType) return fieldType;
      }
      return (
        record.inferredReceiverTypes.get(end.value) ??
        (end.value === "self" ? record.implSelfType : null)
      );
    }
    if (end?.value !== ")") return null;
    const openIndex = matchingOpeningToken(
      record.tokens,
      endIndex,
      "(",
      ")",
    );
    if (openIndex <= record.definition.bodyOpen) return null;
    const callIndex = openIndex - 1;
    if (record.tokens[callIndex]?.type !== "identifier") return null;
    if (record.tokens[callIndex - 1]?.value === ".") {
      const receiverType = expressionTypeAtEnd(record, callIndex - 2, seen);
      if (!receiverType) return null;
      const localTargets =
        methodByModuleTypeAndName.get(
          `${record.moduleId}\0${receiverType}\0${record.tokens[callIndex].value}`,
        ) ?? [];
      if (localTargets.length > 1) {
        throw new Error(
          `ambiguous Rust loader receiver type ${record.definitionId}:${receiverType}.${record.tokens[callIndex].value}`,
        );
      }
      return (
        localTargets[0]?.returnType ??
        reviewedMethodValueType(
          receiverType,
          record.tokens[callIndex].value,
          record.tokens,
          callIndex,
        )
      );
    }
    const localTargets = localCallTargets(record, callIndex);
    if (localTargets.length === 1 && localTargets[0].returnType) {
      return localTargets[0].returnType;
    }
    return externalReturnType(record.tokens, callIndex);
  };

  for (const record of records) {
    const { bodyOpen, bodyClose } = record.definition;
    for (let index = bodyOpen + 1; index < bodyClose; index += 1) {
      if (
        record.tokens[index]?.value === "for" &&
        record.tokens[index + 1]?.type === "identifier"
      ) {
        let inIndex = index + 2;
        while (inIndex < bodyClose && record.tokens[inIndex]?.value !== "in") {
          inIndex += 1;
        }
        let loopBodyOpen = inIndex + 1;
        while (
          loopBodyOpen < bodyClose &&
          record.tokens[loopBodyOpen]?.value !== "{"
        ) {
          loopBodyOpen += 1;
        }
        const sourceType = expressionTypeAtEnd(
          record,
          loopBodyOpen - 1,
        );
        if (sourceType === "VecDirEntry") {
          const loopBodyClose = matchingToken(
            record.tokens,
            loopBodyOpen,
            "{",
            "}",
          );
          record.scopedReceiverTypes.push({
            end: loopBodyClose,
            name: record.tokens[index + 1].value,
            start: loopBodyOpen,
            type: "DirEntry",
          });
        }
      }
      if (
        record.tokens[index]?.value !== "|" ||
        record.tokens[index + 1]?.type !== "identifier" ||
        record.tokens[index + 2]?.value !== "|" ||
        record.tokens[index - 1]?.value !== "("
      ) {
        continue;
      }
      const callIndex = index - 2;
      if (record.tokens[callIndex - 1]?.value !== ".") continue;
      const receiverType = expressionTypeAtEnd(record, callIndex - 2);
      if (!new Set(["IteratorDirEntry", "VecDirEntry"]).has(receiverType)) {
        continue;
      }
      const callClose = matchingToken(
        record.tokens,
        index - 1,
        "(",
        ")",
      );
      record.scopedReceiverTypes.push({
        end: callClose,
        name: record.tokens[index + 1].value,
        start: index + 2,
        type: "DirEntry",
      });
    }
  }

  const receiverTypeAt = (record, receiver, index) => {
    const scoped = record.scopedReceiverTypes
      .filter(
        (scope) =>
          scope.name === receiver && scope.start < index && scope.end > index,
      )
      .sort((left, right) => right.start - left.start)[0];
    return scoped?.type ?? record.inferredReceiverTypes.get(receiver) ?? null;
  };
  const localCallCache = new Map();
  const localCalls = (record) => {
    if (localCallCache.has(record.id)) return localCallCache.get(record.id);
    const calls = new Map();
    const { bodyOpen, bodyClose } = record.definition;
    for (let index = bodyOpen + 1; index < bodyClose; index += 1) {
      const nestedClose = nestedDefinitionRanges.get(record.id)?.get(index);
      if (nestedClose !== undefined) {
        index = nestedClose;
        continue;
      }
      for (const target of localCallTargets(record, index)) {
        calls.set(target.id, target);
      }
    }
    const resolved = [...calls.values()];
    localCallCache.set(record.id, resolved);
    return resolved;
  };

  const freeRoot = (moduleId, name) => ({ kind: "free", moduleId, name });
  const methodRoot = (moduleId, selfType, name, trait = null) => ({
    kind: "method",
    moduleId,
    name,
    selfType,
    trait,
  });
  const categories = new Map([
    [
      "resolution",
      [
        freeRoot("module_loader", "normalize_import_target"),
        freeRoot("module_loader", "open_resolver_boundary"),
        methodRoot("module_loader", "AuthenticatedResolverInputs", "new"),
        methodRoot(
          "module_loader",
          "AuthenticatedResolverInputs",
          "parse_manifest",
        ),
        methodRoot(
          "module_loader",
          "AuthenticatedResolverInputs",
          "uncaptured_package_manifest_probes",
        ),
        methodRoot("module_loader", "ModuleLoader", "resolve"),
        methodRoot(
          "module_loader",
          "ModuleLoader",
          "resolve_direct_file_meta_authenticated",
        ),
        methodRoot("module_loader", "ModuleLoader", "resolve_meta"),
        methodRoot(
          "module_loader",
          "ModuleLoader",
          "resolve_meta_authenticated",
        ),
        methodRoot(
          "module_loader",
          "ModuleLoader",
          "resolve_meta_from_authenticated_bound_package",
        ),
        methodRoot(
          "module_loader",
          "ModuleLoader",
          "resolve_package_import",
        ),
        ...[
          "canonicalize",
          "metadata",
          "read",
          "read_link",
          "read_to_string",
          "symlink_metadata",
        ].map((name) =>
          methodRoot(
            "module_loader",
            "BoundedResolverFileSystem",
            name,
            "ResolverFileSystem",
          ),
        ),
      ],
    ],
    [
      "load",
      ["load_module_source", "load_source", "load_source_bytes"].map((name) =>
        methodRoot("module_loader", "ModuleLoader", name),
      ),
    ],
    [
      "cache",
      [
        "ensure_transpile_cache_dir",
        "enforce_transpile_cache_quota",
        "module_cache_key",
        "publish_transpile_artifact",
        "resolve_transpile_cache_dir",
        "transpile_cache_is_valid",
        "transpile_cache_dir",
      ].map((name) => freeRoot("module_loader", name)),
    ],
    [
      "transform",
      [
        freeRoot("module_loader", "run_transpile_command"),
        methodRoot("module_loader", "ModuleLoader", "transpile_module"),
        freeRoot("transpile", "transpile_source_to_cjs"),
      ],
    ],
    [
      "subprocess",
      [freeRoot("module_loader", "run_transpile_subprocess")],
    ],
  ]);
  const rows = [];

  const resolveRoot = (category, root) => {
    const candidates =
      root.kind === "free"
        ? (freeByModuleAndName.get(`${root.moduleId}\0${root.name}`) ?? [])
        : (
            methodByModuleTypeAndName.get(
              `${root.moduleId}\0${root.selfType}\0${root.name}`,
            ) ?? []
          ).filter(
            (record) => !root.trait || record.implTrait === root.trait,
          );
    if (candidates.length !== 1) {
      throw new Error(
        `Rust loader ${category} root ${root.moduleId}::${root.selfType ? `${root.selfType}::` : ""}${root.name} expected one definition; observed ${candidates.length}`,
      );
    }
    return candidates[0];
  };
  const rootLabel = (root) =>
    `${root.moduleId}::${root.selfType ? `${root.selfType}${root.trait ? ` as ${root.trait}` : ""}::` : ""}${root.name}`;
  const reviewedMergedRouteDefinitions = new Map([
    [
      "manifest_input",
      [
        "module_loader::AuthenticatedResolverInputs::manifest_input",
        "module_loader::BoundedResolverFileSystem::manifest_input",
      ],
    ],
  ]);

  for (const [category, roots] of categories) {
    const rootRecords = roots.map((root) => resolveRoot(category, root));
    const rootLabels = roots.map(rootLabel);
    const reachable = new Map(
      rootRecords.map((record) => [record.id, record]),
    );
    const queue = [...rootRecords];
    while (queue.length > 0) {
      const record = queue.shift();
      for (const call of localCalls(record)) {
        if (reachable.has(call.id)) continue;
        reachable.set(call.id, call);
        queue.push(call);
      }
    }

    const operationRefs = new Map();
    const operationPaths = new Map();
    const externalCalls = new Map();
    const addOperation = (operation, record, functionName, callIdentity) => {
      const refsForOperation = operationRefs.get(operation) ?? new Set();
      refsForOperation.add(
        sourceSymbol(
          record.sourcePath,
          `${functionName}:operation:${callIdentity}`,
        ),
      );
      operationRefs.set(operation, refsForOperation);
      const paths = operationPaths.get(operation) ?? new Set();
      paths.add(callIdentity);
      operationPaths.set(operation, paths);
    };
    const reachableByName = new Map();
    for (const record of reachable.values()) {
      append(reachableByName, record.definition.name, record);
    }
    for (const name of uniqueSorted(reachableByName.keys())) {
      const functionRecords = reachableByName.get(name) ?? [];
      const refs = functionRecords.map((record) =>
        sourceSymbol(record.sourcePath, name),
      );
      const callees = uniqueSorted(
        functionRecords.flatMap((record) =>
          localCalls(record).map((callee) => callee.definition.name),
        ),
      );
      const calleeDefinitions = uniqueSorted(
        functionRecords.flatMap((record) =>
          localCalls(record).map((callee) => callee.definitionId),
        ),
      );
      const definitions = uniqueSorted(
        functionRecords.map((record) => record.definitionId),
      );
      if (definitions.length > 1) {
        const reviewed = reviewedMergedRouteDefinitions.get(name);
        if (
          !reviewed ||
          JSON.stringify(definitions) !== JSON.stringify(reviewed)
        ) {
          throw new Error(
            `Rust loader route ${category}:${name} merges unreviewed definitions [${definitions.join(", ")}]`,
          );
        }
      }
      rows.push(
        makeSurface("loader", `route:${category}:rust:${name}`, refs, {
          metadata: {
            callees,
            calleeDefinitions,
            category,
            definitions,
            evidenceType: "transitive-rust-loader-route",
            roots: rootLabels,
            ...authenticatedResolverTargetMetadata(
              name,
              functionRecords.every(
                (record) => record.targetVariant === "posix",
              )
                ? "posix"
                : null,
            ),
          },
        }),
      );
      for (const record of functionRecords) {
        const { bodyOpen, bodyClose } = record.definition;
        for (let index = bodyOpen + 1; index < bodyClose; index += 1) {
          const nestedClose = nestedDefinitionRanges.get(record.id)?.get(index);
          if (nestedClose !== undefined) {
            index = nestedClose;
            continue;
          }
          const identity = loaderExternalCallIdentity(
            record.tokens,
            index,
            localCallTargets(record, index),
          );
          if (!identity) continue;
          const evidenceKey = `${record.sourcePath}\0${name}\0${identity}`;
          externalCalls.set(
            evidenceKey,
            (externalCalls.get(evidenceKey) ?? 0) + 1,
          );

          const qualified = rustQualifiedCallPath(record.tokens, index);
          const qualifiedOperation =
            qualified.length > 1
              ? qualifiedLoaderAuthorityOperation(qualified)
              : null;
          const receiver = record.tokens[index - 2];
          const receiverType =
            receiver?.type === "identifier"
              ? receiverTypeAt(record, receiver.value, index)
              : expressionTypeAtEnd(record, index - 2);
          let reviewedMethodOperation =
            receiverType === "Command" &&
            record.tokens[index].value === "status"
              ? "status"
              : null;
          if (
            !reviewedMethodOperation &&
            ((receiverType === "File" &&
              /^(?:metadata|read)$/u.test(record.tokens[index].value)) ||
              (receiverType === "DirEntry" &&
                record.tokens[index].value === "metadata"))
          ) {
            reviewedMethodOperation = record.tokens[index].value;
          }
          if (
            !reviewedMethodOperation &&
            new Set(["Path", "PathBuf"]).has(receiverType) &&
            record.tokens[index].value === "canonicalize"
          ) {
            reviewedMethodOperation = "canonicalize";
          }
          const operation = qualifiedOperation ?? reviewedMethodOperation;
          if (operation) {
            addOperation(
              operation,
              record,
              name,
              reviewedMethodOperation && receiverType
                ? `method:${receiverType}:${record.tokens[index].value}`
                : identity,
            );
          }
        }
      }
    }
    if (externalCalls.size === 0) {
      throw new Error(`Rust loader ${category} route has no external calls`);
    }
    rows.push(
      makeSurface(
        "loader",
        `external-calls:${category}`,
        [...externalCalls.entries()].map(([key, occurrenceCount]) => {
          const [sourcePath, functionName, identity] = key.split("\0");
          return sourceSymbol(
            sourcePath,
            `${functionName}:external:${identity}:count-${occurrenceCount}`,
          );
        }),
        {
          metadata: {
            category,
            evidenceType: "rust-loader-external-call-set",
            externalCallCount: [...externalCalls.values()].reduce(
              (total, count) => total + count,
              0,
            ),
          },
        },
      ),
    );
    for (const [operation, refs] of operationRefs) {
      rows.push(
        makeSurface("loader", `operation:${category}:${operation}`, [...refs], {
          metadata: {
            category,
            evidenceType: "rust-loader-operation",
            operation,
            qualifiedPaths: uniqueSorted(operationPaths.get(operation) ?? []),
            ...(category === "resolution" &&
            new Set(["from-owned-fd", "open", "read_link"]).has(operation)
              ? { targetVariant: "posix" }
              : {}),
          },
        }),
      );
    }
  }

  const engines = new Map();
  for (const record of records) {
    for (
      let index = record.definition.bodyOpen + 1;
      index < record.definition.bodyClose;
      index += 1
    ) {
      if (
        record.tokens[index]?.value === "TransformEngine" &&
        record.tokens[index + 1]?.value === ":" &&
        record.tokens[index + 2]?.value === ":" &&
        record.tokens[index + 3]?.type === "identifier"
      ) {
        if (!/^[A-Z][A-Za-z0-9_]*$/u.test(record.tokens[index + 3].value))
          continue;
        const engine = record.tokens[index + 3].value.toLowerCase();
        const refs = engines.get(engine) ?? new Set();
        refs.add(sourceSymbol(record.sourcePath, record.definition.name));
        engines.set(engine, refs);
      }
    }
  }
  if (engines.size === 0)
    throw new Error("Rust loader transform engines are absent");
  for (const [engine, refs] of engines) {
    rows.push(
      makeSurface("loader", `transform-engine:${engine}`, [...refs], {
        metadata: { engine, evidenceType: "rust-loader-transform-engine" },
      }),
    );
  }

  return mergeSurfaceEvidence(rows, "transitive Rust loader route inventory");
}

function rustDefinitionByName(tokens, name, sourcePath) {
  const definitions = rustFunctionDefinitions(tokens).filter(
    (definition) => definition.name === name,
  );
  if (definitions.length !== 1) {
    throw new Error(
      `${sourcePath}: expected exactly one production Rust function ${name}; observed ${definitions.length}`,
    );
  }
  return definitions[0];
}

function sameRustTokens(tokens, source, label) {
  const expected = rustProductionTokens(source, label);
  if (tokens.length !== expected.length) return false;
  return tokens.every(
    (token, index) =>
      token.type === expected[index].type &&
      token.value === expected[index].value,
  );
}

function rustTokenEvidence(tokens) {
  return tokens.map((token) => [token.type, token.value]);
}

const REVIEWED_CDP_FUNCTION_BODY_DIGESTS = new Map([
  [
    "start_server",
    "sha256-669a9ac3395e7e783a158caa34ad9d9a72f819e5a333185df898570bcad78e11",
  ],
  [
    "run_server",
    "sha256-a8fe3dac78a422e48a0a040a9d8fb0bba3dc64bdeed5c36848f5e10cb825c480",
  ],
  [
    "handle_connection",
    "sha256-80d5ea720d1655f9464e44ca45041c6e5ea58ce5147402ddea89ec11837a2836",
  ],
]);

function assertCdpFunctionBodyClosure(tokens, definition, sourcePath) {
  const body = tokens.slice(definition.bodyOpen + 1, definition.bodyClose);
  const observed = `sha256-${sha256Hex(JSON.stringify(rustTokenEvidence(body)))}`;
  const expected = REVIEWED_CDP_FUNCTION_BODY_DIGESTS.get(definition.name);
  if (observed !== expected) {
    throw new Error(
      `${sourcePath}: CDP ${definition.name} body drifted from its reviewed ` +
        `token evidence; observed ${observed}`,
    );
  }
}

function cdpDispatchMatch(tokens, definition, subject, sourcePath) {
  const matches = [];
  for (
    let index = definition.bodyOpen + 1;
    index < definition.bodyClose;
    index += 1
  ) {
    if (
      tokens[index]?.value !== "match" ||
      tokens[index + 1]?.value !== subject ||
      tokens[index + 2]?.value !== "{"
    ) {
      continue;
    }
    const close = matchingToken(tokens, index + 2, "{", "}");
    if (close !== -1 && close < definition.bodyClose) {
      matches.push({ close, matchIndex: index, open: index + 2, subject });
      index = close;
    }
  }
  if (matches.length !== 1) {
    throw new Error(
      `${sourcePath}: expected exactly one structural CDP match ${subject} ` +
        `dispatch; observed ${matches.length}`,
    );
  }
  return matches[0];
}

/**
 * Enumerate only top-level string arms from one reviewed dispatch. Every arm
 * must be a closed string-alternative pattern or the single wildcard. A new
 * constant, guard, nested match, or dynamic pattern therefore cannot become a
 * route without changing this inventory contract.
 */
function cdpDispatchStringAlternatives(tokens, dispatch, accept, sourcePath) {
  const values = [];
  const matchingClose = { "(": ")", "[": "]", "{": "}" };
  let wildcardCount = 0;
  let index = dispatch.open + 1;
  while (index < dispatch.close) {
    while (tokens[index]?.value === ",") index += 1;
    if (index >= dispatch.close) break;

    const patternStart = index;
    let arrow = -1;
    while (index < dispatch.close) {
      const closeValue = matchingClose[tokens[index]?.value];
      if (closeValue) {
        const close = matchingToken(
          tokens,
          index,
          tokens[index].value,
          closeValue,
        );
        if (close === -1 || close > dispatch.close) {
          throw new Error(
            `${sourcePath}: malformed CDP ${dispatch.subject} arm`,
          );
        }
        index = close + 1;
        continue;
      }
      if (tokens[index]?.value === "=" && tokens[index + 1]?.value === ">") {
        arrow = index;
        break;
      }
      if (tokens[index]?.value === ",") break;
      index += 1;
    }
    if (arrow === -1) {
      throw new Error(
        `${sourcePath}: unreviewed CDP ${dispatch.subject} dispatch arm`,
      );
    }

    const pattern = tokens.slice(patternStart, arrow);
    if (pattern.length === 1 && pattern[0]?.value === "_") {
      wildcardCount += 1;
    } else {
      for (let cursor = 0; cursor < pattern.length; cursor += 2) {
        const alternative = pattern[cursor];
        if (
          alternative?.type !== "string" ||
          !accept(alternative.value) ||
          (cursor + 1 < pattern.length && pattern[cursor + 1]?.value !== "|")
        ) {
          throw new Error(
            `${sourcePath}: unreviewed CDP ${dispatch.subject} dispatch pattern`,
          );
        }
        values.push(alternative.value);
      }
    }

    index = arrow + 2;
    const expressionClose = matchingClose[tokens[index]?.value];
    if (expressionClose) {
      const close = matchingToken(
        tokens,
        index,
        tokens[index].value,
        expressionClose,
      );
      if (close === -1 || close > dispatch.close) {
        throw new Error(`${sourcePath}: malformed CDP ${dispatch.subject} arm`);
      }
      index = close + 1;
    } else {
      while (index < dispatch.close && tokens[index]?.value !== ",") {
        const closeValue = matchingClose[tokens[index]?.value];
        if (closeValue) {
          const close = matchingToken(
            tokens,
            index,
            tokens[index].value,
            closeValue,
          );
          if (close === -1 || close > dispatch.close) {
            throw new Error(
              `${sourcePath}: malformed CDP ${dispatch.subject} arm`,
            );
          }
          index = close + 1;
        } else {
          index += 1;
        }
      }
    }
    if (tokens[index]?.value === ",") index += 1;
  }

  if (wildcardCount !== 1) {
    throw new Error(
      `${sourcePath}: expected exactly one CDP ${dispatch.subject} wildcard; observed ${wildcardCount}`,
    );
  }
  const unique = uniqueSorted(values);
  if (unique.length !== values.length) {
    throw new Error(
      `${sourcePath}: duplicate CDP ${dispatch.subject} dispatch alternative`,
    );
  }
  return unique;
}

function assertCdpDispatchSubjectClosure(
  tokens,
  definition,
  dispatch,
  sourcePath,
) {
  const before = [];
  const after = [];
  for (
    let index = definition.bodyOpen + 1;
    index < dispatch.matchIndex;
    index += 1
  ) {
    if (
      tokens[index]?.type === "identifier" &&
      tokens[index].value === dispatch.subject
    ) {
      before.push(index);
    }
  }
  for (
    let index = dispatch.close + 1;
    index < definition.bodyClose;
    index += 1
  ) {
    if (
      tokens[index]?.type === "identifier" &&
      tokens[index].value === dispatch.subject
    ) {
      after.push(index);
    }
  }

  if (dispatch.subject === "path") {
    const exactBinding =
      before.length === 1 &&
      tokens[before[0] - 1]?.value === "let" &&
      tokens[before[0] + 1]?.value === "=";
    if (!exactBinding || after.length !== 0) {
      throw new Error(
        `${sourcePath}: CDP path is used outside its reviewed match dispatch`,
      );
    }
    return;
  }

  if (before.length !== 0) {
    throw new Error(
      `${sourcePath}: CDP method is used before its reviewed match dispatch`,
    );
  }
  const exactFallbackUse = (index) =>
    tokens[index - 4]?.value === "method_not_found_response" &&
    tokens[index - 3]?.value === "(" &&
    tokens[index - 2]?.value === "id" &&
    tokens[index - 1]?.value === "," &&
    tokens[index + 1]?.value === ")";
  if (after.length > 1 || after.some((index) => !exactFallbackUse(index))) {
    throw new Error(
      `${sourcePath}: CDP method is used after its reviewed match dispatch`,
    );
  }
}

const REVIEWED_CDP_HTTP_PREFIX = String.raw`
  let mut buf = Vec::new();
  let mut tmp = [0u8; 1024];
  let read_result = tokio::time::timeout(CDP_HTTP_READ_TIMEOUT, async {
      loop {
          let n = stream.read(&mut tmp).await?;
          if n == 0 {
              break;
          }
          buf.extend_from_slice(&tmp[..n]);
          if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
              break;
          }
      }
      Ok::<(), std::io::Error>(())
  })
  .await;
  match read_result {
      Ok(result) => result?,
      Err(_) => {
          write_tcp_with_timeout(
              stream,
              b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
          )
          .await?;
          return Ok(());
      }
  }

  let request = String::from_utf8_lossy(&buf);
  let mut lines = request.lines();
  let request_line = lines.next().unwrap_or("");
  let mut parts = request_line.split_whitespace();
  let _method = parts.next().unwrap_or("GET");
  let path = parts.next().unwrap_or("/");
  if !cdp_request_headers_allowed(&request) {
      write_http_response(stream, "403 Forbidden", "{}").await?;
      return Ok(());
  }

  let websocket_url = format!("ws://{}/", local_addr);
  let devtools_url = format!(
      "devtools://devtools/bundled/inspector.html?ws={}/",
      local_addr
  );
  let devtools_compat_url = format!(
      "chrome-devtools://devtools/bundled/inspector.html?ws={}/",
      local_addr
  );
  let (status, body) =
`;

const REVIEWED_CDP_HTTP_SUFFIX = String.raw`
  ;
  write_http_response(stream, status, &body).await
`;

/**
 * The route arms are enumerated separately. Every other token in the HTTP
 * handler is one reviewed template so raw `buf`/`tmp` checks, reparses,
 * aliases, early returns, and post-match response rewrites cannot add a route
 * while leaving `match path` byte-identical.
 */
function assertCdpHttpHandlerClosure(tokens, definition, dispatch, sourcePath) {
  const prefix = tokens.slice(definition.bodyOpen + 1, dispatch.matchIndex);
  const suffix = tokens.slice(dispatch.close + 1, definition.bodyClose);
  if (
    !sameRustTokens(
      prefix,
      REVIEWED_CDP_HTTP_PREFIX,
      "reviewed CDP HTTP prefix",
    )
  ) {
    throw new Error(
      `${sourcePath}: CDP HTTP handler prefix drifted from its reviewed token template ` +
        `(evidence ${evidenceHash(JSON.stringify(rustTokenEvidence(prefix)))})`,
    );
  }
  if (
    !sameRustTokens(
      suffix,
      REVIEWED_CDP_HTTP_SUFFIX,
      "reviewed CDP HTTP suffix",
    )
  ) {
    throw new Error(
      `${sourcePath}: CDP HTTP handler suffix drifted from its reviewed token template ` +
        `(evidence ${evidenceHash(JSON.stringify(rustTokenEvidence(suffix)))})`,
    );
  }
}

function cdpWildcardArm(tokens, dispatch, sourcePath) {
  const candidates = [];
  const matchingClose = { "(": ")", "[": "]", "{": "}" };
  for (let index = dispatch.open + 1; index < dispatch.close; index += 1) {
    const closeValue = matchingClose[tokens[index]?.value];
    if (closeValue) {
      const close = matchingToken(
        tokens,
        index,
        tokens[index].value,
        closeValue,
      );
      if (close === -1 || close > dispatch.close) {
        throw new Error(`${sourcePath}: malformed CDP method dispatch`);
      }
      index = close;
      continue;
    }
    if (
      tokens[index]?.value === "_" &&
      tokens[index + 1]?.value === "=" &&
      tokens[index + 2]?.value === ">"
    ) {
      candidates.push(index);
    }
  }
  if (candidates.length !== 1) {
    throw new Error(
      `${sourcePath}: expected exactly one structural CDP wildcard ` +
        `fallback; observed ${candidates.length}`,
    );
  }

  const wildcard = candidates[0];
  const expressionStart = wildcard + 3;
  let expressionEnd = expressionStart;
  if (tokens[expressionStart]?.value === "{") {
    const close = matchingToken(tokens, expressionStart, "{", "}");
    if (close === -1 || close > dispatch.close) {
      throw new Error(`${sourcePath}: malformed CDP wildcard block`);
    }
    expressionEnd = close + 1;
  } else {
    while (
      expressionEnd < dispatch.close &&
      tokens[expressionEnd]?.value !== ","
    ) {
      const closeValue = matchingClose[tokens[expressionEnd]?.value];
      if (closeValue) {
        const close = matchingToken(
          tokens,
          expressionEnd,
          tokens[expressionEnd].value,
          closeValue,
        );
        if (close === -1 || close > dispatch.close) {
          throw new Error(`${sourcePath}: malformed CDP wildcard expression`);
        }
        expressionEnd = close + 1;
      } else {
        expressionEnd += 1;
      }
    }
  }

  let afterArm = expressionEnd;
  if (tokens[afterArm]?.value === ",") afterArm += 1;
  return {
    expression: tokens.slice(expressionStart, expressionEnd),
    isFinal: afterArm === dispatch.close,
    wildcard,
  };
}

function cdpJsonRpcErrorCode(helperTokens) {
  for (let index = 0; index < helperTokens.length - 3; index += 1) {
    if (
      helperTokens[index]?.type !== "string" ||
      helperTokens[index].value !== "code" ||
      helperTokens[index + 1]?.value !== ":"
    ) {
      continue;
    }
    let cursor = index + 2;
    let sign = 1;
    if (helperTokens[cursor]?.value === "-") {
      sign = -1;
      cursor += 1;
    }
    let digits = "";
    while (/^[0-9]$/u.test(helperTokens[cursor]?.value ?? "")) {
      digits += helperTokens[cursor].value;
      cursor += 1;
    }
    if (digits.length > 0 && helperTokens[cursor]?.value === ",") {
      return sign * Number.parseInt(digits, 10);
    }
  }
  return null;
}

function exactCdpMethodNotFoundHelper(helperTokens, errorCode) {
  if (!Number.isSafeInteger(errorCode)) return false;
  return sameRustTokens(
    helperTokens,
    String.raw`
      json!({
          "id": id,
          "error": {
              "code": ${errorCode},
              "message": format!("'{}' wasn't found", method)
          }
      })
    `,
    "<expected CDP method-not-found helper>",
  );
}

function exactCdpFallbackTail(tailTokens) {
  const tails = [
    String.raw`
      let response = method_not_found_response(id, method);
      ctx.write.send(Message::Text(response.to_string())).await?;
      Ok(())
    `,
    String.raw`
      let response = method_not_found_response(id, method);
      if cdp_log_enabled() {
          eprintln!("CDP <- id={} error={}", id, response);
      }
      ctx.write.send(Message::Text(response.to_string())).await?;
      Ok(())
    `,
    String.raw`
      let response = method_not_found_response(id, method);
      if cdp_log_enabled() {
          eprintln!("CDP <- id={} error={}", id, response);
      }
      ctx.send_text(response.to_string()).await?;
      Ok(())
    `,
  ];
  return tails.some((tail, index) =>
    sameRustTokens(tailTokens, tail, `<expected CDP fallback tail ${index}>`),
  );
}

function cdpUnknownMethodFallbackSurface(
  tokens,
  requestHandler,
  dispatch,
  sourcePath,
) {
  const wildcard = cdpWildcardArm(tokens, dispatch, sourcePath);
  const tailTokens = tokens.slice(dispatch.close + 1, requestHandler.bodyClose);
  const helperDefinitions = rustFunctionDefinitions(tokens).filter(
    (definition) => definition.name === "method_not_found_response",
  );
  const helper = helperDefinitions.length === 1 ? helperDefinitions[0] : null;
  const helperTokens = helper
    ? tokens.slice(helper.bodyOpen + 1, helper.bodyClose)
    : [];
  const semanticEvidence = evidenceHash(
    JSON.stringify({
      helper: rustTokenEvidence(helperTokens),
      tail: rustTokenEvidence(tailTokens),
      wildcard: rustTokenEvidence(wildcard.expression),
      wildcardIsFinal: wildcard.isFinal,
    }),
  );

  const emptyWildcard = sameRustTokens(
    wildcard.expression,
    "{}",
    "<expected CDP fallthrough wildcard>",
  );
  const silentSuccess = ["return Ok(())", "{ return Ok(()); }"]
    .map((source, index) =>
      sameRustTokens(
        wildcard.expression,
        source,
        `<expected CDP silent fallback ${index}>`,
      ),
    )
    .some(Boolean);

  let disposition;
  let metadata;
  const sourceRefs = [
    sourceSymbol(sourcePath, "handle_request:unknown-method-fallback"),
  ];
  if (wildcard.isFinal && silentSuccess) {
    disposition = "silent-success";
    metadata = {
      evidenceType: "cdp-unknown-method-fallback",
      responseDisposition: "none",
      semanticEvidence,
      wildcardDisposition: "return-ok",
    };
  } else {
    const errorCode = cdpJsonRpcErrorCode(helperTokens);
    const exactMethodNotFound =
      wildcard.isFinal &&
      emptyWildcard &&
      exactCdpFallbackTail(tailTokens) &&
      exactCdpMethodNotFoundHelper(helperTokens, errorCode);
    if (exactMethodNotFound) {
      disposition = `json-rpc-error-${errorCode}`;
      metadata = {
        errorCode,
        evidenceType: "cdp-unknown-method-fallback",
        responseDisposition: "json-rpc-error",
        responseHelper: "method_not_found_response",
        semanticEvidence,
        wildcardDisposition: "fallthrough",
      };
      sourceRefs.push(sourceSymbol(sourcePath, "method_not_found_response"));
    } else {
      disposition = `unreviewed-${semanticEvidence}`;
      metadata = {
        evidenceType: "cdp-unknown-method-fallback",
        responseDisposition: "unreviewed",
        semanticEvidence,
        wildcardDisposition: emptyWildcard
          ? "fallthrough"
          : wildcard.isFinal
            ? "unreviewed"
            : "non-final",
      };
      if (helper) {
        sourceRefs.push(sourceSymbol(sourcePath, "method_not_found_response"));
      }
    }
  }

  return makeSurface(
    "native-op",
    `inspector.cdp-request-fallback:${disposition}`,
    sourceRefs,
    { metadata },
  );
}

/**
 * Discover the CDP listener plus every statically accepted HTTP and protocol
 * request route and the fail-closed unknown-method disposition. This
 * intentionally observes the production Rust dispatch rather than maintaining
 * a second protocol allowlist.
 */
export function scanCdpSurfaces(text, sourcePath = "src/bin/ibex/cdp/mod.rs") {
  const tokens = rustProductionTokens(text, sourcePath);
  const startServer = rustDefinitionByName(tokens, "start_server", sourcePath);
  const runServer = rustDefinitionByName(tokens, "run_server", sourcePath);
  const handleConnection = rustDefinitionByName(
    tokens,
    "handle_connection",
    sourcePath,
  );
  const httpHandler = rustDefinitionByName(
    tokens,
    "handle_http_request",
    sourcePath,
  );
  const requestHandler = rustDefinitionByName(
    tokens,
    "handle_request",
    sourcePath,
  );

  for (const definition of [startServer, runServer, handleConnection]) {
    assertCdpFunctionBodyClosure(tokens, definition, sourcePath);
  }

  const callsIn = (definition, name) => {
    let count = 0;
    for (
      let index = definition.bodyOpen + 1;
      index < definition.bodyClose;
      index += 1
    ) {
      if (
        tokens[index]?.value === "." &&
        tokens[index + 1]?.type === "identifier" &&
        tokens[index + 1].value === name &&
        tokens[index + 2]?.value === "("
      ) {
        count += 1;
      }
    }
    return count;
  };
  const listenerOperations = {
    accept: callsIn(runServer, "accept"),
    bind: callsIn(startServer, "bind"),
    listen: callsIn(startServer, "listen"),
  };
  for (const [operation, count] of Object.entries(listenerOperations)) {
    if (count === 0) {
      throw new Error(
        `${sourcePath}: CDP listener route has no structural ${operation} call`,
      );
    }
  }

  const rows = [
    makeSurface(
      "native-op",
      "inspector.cdp-listener",
      [
        sourceSymbol(sourcePath, "start_server"),
        sourceSymbol(sourcePath, "run_server"),
      ],
      {
        metadata: {
          evidenceType: "cdp-listener-route",
          listenerOperations,
        },
      },
    ),
  ];

  const httpDispatch = cdpDispatchMatch(
    tokens,
    httpHandler,
    "path",
    sourcePath,
  );
  assertCdpDispatchSubjectClosure(
    tokens,
    httpHandler,
    httpDispatch,
    sourcePath,
  );
  assertCdpHttpHandlerClosure(tokens, httpHandler, httpDispatch, sourcePath);
  const httpPaths = cdpDispatchStringAlternatives(
    tokens,
    httpDispatch,
    (value) => /^\/[A-Za-z0-9/_-]+$/u.test(value),
    sourcePath,
  );
  for (const route of httpPaths) {
    rows.push(
      makeSurface(
        "native-op",
        `inspector.cdp-http:${route}`,
        [sourceSymbol(sourcePath, `handle_http_request:${route}`)],
        {
          metadata: { evidenceType: "cdp-http-route", route },
        },
      ),
    );
  }

  const requestDispatch = cdpDispatchMatch(
    tokens,
    requestHandler,
    "method",
    sourcePath,
  );
  assertCdpDispatchSubjectClosure(
    tokens,
    requestHandler,
    requestDispatch,
    sourcePath,
  );
  const methods = cdpDispatchStringAlternatives(
    tokens,
    requestDispatch,
    (value) => /^[A-Z][A-Za-z0-9]+\.[A-Za-z][A-Za-z0-9]+$/u.test(value),
    sourcePath,
  );
  for (const method of methods) {
    rows.push(
      makeSurface(
        "native-op",
        `inspector.cdp-request:${method}`,
        [sourceSymbol(sourcePath, `handle_request:${method}`)],
        {
          metadata: { evidenceType: "cdp-request-route", method },
        },
      ),
    );
  }

  rows.push(
    cdpUnknownMethodFallbackSurface(
      tokens,
      requestHandler,
      requestDispatch,
      sourcePath,
    ),
  );

  if (httpPaths.length === 0 || methods.length === 0) {
    throw new Error(`${sourcePath}: CDP route inventory is unexpectedly empty`);
  }
  return sortSurfaces(rows);
}

function environmentContext(sourcePath, direction, name = null) {
  if (direction !== "read") {
    if (sourcePath.endsWith("native_android_networking.cc"))
      return "trusted-bootstrap-output";
    if (sourcePath.endsWith("hermes_runtime_process.cc"))
      return "spawn-child-env";
    if (
      sourcePath.includes("/child-process.js") ||
      sourcePath.includes("/cluster.js")
    ) {
      return "spawn-child-env";
    }
    return "runtime-bootstrap-output";
  }
  if (
    sourcePath.endsWith("/host/abi.rs") &&
    new Set(["EXACT_IPC_FD", "EXACT_IPC_SERIALIZATION"]).has(name)
  ) {
    // These controls are captured once into the private Host-to-engine
    // construction handoff before either armed or diagnostic project code can
    // observe its principal environment. They are startup inputs even though
    // other host ABI environment reads are runtime inputs.
    return "startup-input";
  }
  if (
    sourcePath.includes("/host/") ||
    sourcePath.includes("/builtins/") ||
    sourcePath.includes("/fetch/") ||
    sourcePath.includes("/streams/")
  ) {
    return "runtime-input";
  }
  return "startup-input";
}

// These environment occurrences are compiled only for the named target. Keep
// the exact member list ahead of the generic environment collector so a source
// filename or accessor prefix can never widen target applicability.
//
// The two `environ` spellings are selected by `!_WIN32 && !__APPLE__`, while
// the WPT TLS control has separate Linux and macOS implementations. Model
// those disjunctions as exact alternatives instead of pretending they are
// `all`.
const EXACT_RUNTIME_ENVIRONMENT_TARGET_VARIANTS = new Map([
  ["env:<dynamic>:cpp:GetEnvironmentStringsW", "windows"],
  ["env:<dynamic>:cpp:GetEnvironmentVariableA", "windows"],
  ["env:<dynamic>:cpp:_NSGetEnviron", "apple"],
  ["env:<dynamic>:cpp:_dupenv_s", "windows"],
  ["env:EXACT_ANDROID_CODE_CACHE_DIR", "android"],
  ["env:EXACT_ANDROID_EXTERNAL_FILES_DIR", "android"],
  ["env:EXACT_ANDROID_NO_BACKUP_FILES_DIR", "android"],
  ["env:EXACT_WINHTTP_ENABLE_HTTP2", "windows"],
  ["env:EXACT_WPT_FIXTURE_CLOSE_SEMANTICS", "macos"],
  ["env:USERNAME", "windows"],
]);
const EXACT_RUNTIME_ENVIRONMENT_TARGET_ALTERNATIVES = new Map([
  ["env:<dynamic>:cpp:::environ", ["android", "linux"]],
  ["env:<dynamic>:cpp:environ", ["android", "linux"]],
  ["env:EXACT_WPT_TRUST_LOOPBACK_TLS", ["linux", "macos"]],
]);

function runtimeEnvironmentTargetMetadata(name, sourceRefs) {
  const targetVariant = EXACT_RUNTIME_ENVIRONMENT_TARGET_VARIANTS.get(name);
  if (targetVariant !== undefined) return { targetVariant };
  const alternatives = EXACT_RUNTIME_ENVIRONMENT_TARGET_ALTERNATIVES.get(name);
  if (alternatives !== undefined) {
    return {
      branches: alternatives.map((variant) => ({
        id: variant,
        kind: "alternative",
        sourceRefs,
        targetVariant: variant,
      })),
    };
  }
  return {};
}

function createEnvironmentCollector() {
  const exact = new Map();
  const dynamic = new Map();
  const validName = /^[A-Za-z_][A-Za-z0-9_]*$/u;

  const add = ({
    accessor,
    context: contextOverride = null,
    direction,
    language,
    name,
    scope = null,
    sourceOffset = null,
    sourcePath,
  }) => {
    if (!validName.test(name)) {
      throw new Error(
        `${sourcePath}: invalid static environment name ${JSON.stringify(name)}`,
      );
    }
    const authoredName = name;
    if (name.toLowerCase() === "comspec") name = "COMSPEC";
    const entry = exact.get(name) ?? {
      accessDirections: new Set(),
      accessors: new Set(),
      authoredNames: new Set(),
      contexts: new Set(),
      languages: new Set(),
      occurrences: new Map(),
      sourceRefs: new Set(),
    };
    const context =
      contextOverride ?? environmentContext(sourcePath, direction, name);
    const sourceRef = sourceSymbol(
      sourcePath,
      `${accessor}:${name}:${direction}`,
    );
    entry.accessDirections.add(direction);
    entry.accessors.add(accessor);
    entry.authoredNames.add(authoredName);
    entry.contexts.add(context);
    entry.languages.add(language);
    const occurrenceKey = `${sourceRef}\0${scope ?? ""}\0${sourceOffset ?? ""}`;
    entry.occurrences.set(occurrenceKey, {
      accessor,
      context,
      direction,
      language,
      scope,
      sourceOffset,
      sourcePath,
      sourceRef,
    });
    entry.sourceRefs.add(sourceRef);
    exact.set(name, entry);
  };

  const addDynamic = ({
    accessor,
    context: contextOverride = null,
    direction = "read",
    language,
    scope = null,
    sourceOffset = null,
    sourcePath,
  }) => {
    const key = `${language}:${accessor}`;
    const entry = dynamic.get(key) ?? {
      accessDirections: new Set(),
      accessors: new Set(),
      contexts: new Set(),
      languages: new Set(),
      occurrences: new Map(),
      sourceRefs: new Set(),
    };
    const context =
      contextOverride ?? environmentContext(sourcePath, direction);
    const sourceRef = sourceSymbol(
      sourcePath,
      `${accessor}:dynamic:${direction}`,
    );
    entry.accessDirections.add(direction);
    entry.accessors.add(accessor);
    entry.contexts.add(context);
    entry.languages.add(language);
    const occurrenceKey = `${sourceRef}\0${scope ?? ""}\0${sourceOffset ?? ""}`;
    entry.occurrences.set(occurrenceKey, {
      accessor,
      context,
      direction,
      language,
      scope,
      sourceOffset,
      sourcePath,
      sourceRef,
    });
    entry.sourceRefs.add(sourceRef);
    dynamic.set(key, entry);
  };

  const rows = () => {
    const emit = (name, entry, dynamicKey = null) => {
      const sourceRefs = [...entry.sourceRefs];
      return makeSurface("startup", name, sourceRefs, {
        metadata: {
          accessDirections: uniqueSorted(entry.accessDirections),
          accessors: uniqueSorted(entry.accessors),
          authoredNames: uniqueSorted(entry.authoredNames ?? []),
          contexts: uniqueSorted(entry.contexts),
          dynamic: dynamicKey !== null,
          dynamicKey,
          evidenceType:
            dynamicKey === null
              ? "static-runtime-environment-control"
              : "dynamic-runtime-environment-sentinel",
          languages: uniqueSorted(entry.languages),
          occurrences: [...entry.occurrences.values()].sort((left, right) =>
            compareText(
              `${left.sourceRef}\0${left.scope ?? ""}\0${left.sourceOffset ?? ""}`,
              `${right.sourceRef}\0${right.scope ?? ""}\0${right.sourceOffset ?? ""}`,
            ),
          ),
          ...runtimeEnvironmentTargetMetadata(name, sourceRefs),
        },
      });
    };
    return sortSurfaces([
      ...[...exact.entries()].map(([name, entry]) =>
        emit(`env:${name}`, entry),
      ),
      ...[...dynamic.entries()].map(([key, entry]) =>
        emit(`env:<dynamic>:${key}`, entry, key),
      ),
    ]);
  };
  return { add, addDynamic, rows };
}

/**
 * Discover the session worker's private process bootstrap route from the two
 * constants consumed by the supervisor/worker dispatcher. The route is not a
 * command-line API: an authenticated supervisor constructs it internally and
 * project JavaScript cannot name or reach it.
 *
 * @ref LLP 0025#10-registry-obligations — the worker bootstrap must be
 * inventoried without turning its implementation argument into a public CLI.
 */
export function scanPrivateSessionWorkerBootstrap(
  text,
  sourcePath = "src/bin/ibex/session_worker.rs",
) {
  const constant = (name) => {
    const pattern = new RegExp(
      `\\bpub\\(crate\\)\\s+const\\s+${name}\\s*:\\s*&str\\s*=\\s*"([^"\\r\\n]+)"\\s*;`,
      "gu",
    );
    const matches = [...text.matchAll(pattern)];
    if (matches.length !== 1) {
      throw new Error(
        `${sourcePath}: expected exactly one private worker constant ${name}`,
      );
    }
    return matches[0][1];
  };
  const argument = constant("WORKER_BOOTSTRAP_ARG");
  const surfaceId = constant("WORKER_BOOTSTRAP_SURFACE_ID");
  if (argument !== "__ibex-session-worker-v1") {
    throw new Error(`${sourcePath}: private worker bootstrap argument drifted`);
  }
  if (surfaceId !== "private:ibex:session-worker-bootstrap:v1") {
    throw new Error(`${sourcePath}: private worker bootstrap surface id drifted`);
  }
  return makeSurface(
    "startup",
    surfaceId,
    [
      sourceSymbol(sourcePath, "WORKER_BOOTSTRAP_ARG"),
      sourceSymbol(sourcePath, "WORKER_BOOTSTRAP_SURFACE_ID"),
    ],
    {
      metadata: {
        argument,
        evidenceType: "private-session-worker-bootstrap",
        javascriptReachability: "none",
        visibility: "private-supervisor-worker",
      },
    },
  );
}

function parseEnvironmentJavaScript(text, sourcePath) {
  const extension = path.extname(sourcePath);
  const plugins = [];
  if (extension === ".ts" || extension === ".tsx") plugins.push("typescript");
  if (extension === ".jsx" || extension === ".tsx") plugins.push("jsx");
  try {
    return parseSync(text, {
      ast: true,
      babelrc: false,
      code: false,
      configFile: false,
      parserOpts: {
        allowReturnOutsideFunction: true,
        plugins,
      },
      sourceType: "unambiguous",
    }).program;
  } catch (error) {
    throw new Error(
      `${sourcePath}: unable to parse environment source: ${error.message}`,
    );
  }
}

function unwrapEnvironmentExpression(node) {
  let current = node;
  while (
    current &&
    new Set([
      "ChainExpression",
      "TSAsExpression",
      "TSNonNullExpression",
      "TSSatisfiesExpression",
      "TypeCastExpression",
    ]).has(current.type)
  ) {
    current = current.expression;
  }
  return current;
}

function environmentMemberName(node) {
  const current = unwrapEnvironmentExpression(node);
  if (
    !new Set(["MemberExpression", "OptionalMemberExpression"]).has(
      current?.type,
    )
  )
    return null;
  if (!current.computed && current.property?.type === "Identifier")
    return current.property.name;
  if (current.computed && current.property?.type === "StringLiteral")
    return current.property.value;
  return null;
}

function environmentMemberChain(node) {
  const current = unwrapEnvironmentExpression(node);
  if (current?.type === "Identifier") return [current.name];
  if (
    !new Set(["MemberExpression", "OptionalMemberExpression"]).has(
      current?.type,
    )
  )
    return null;
  const parent = environmentMemberChain(current.object);
  const member = environmentMemberName(current);
  return parent && member !== null ? [...parent, member] : null;
}

function expressionIsProcessAlias(node, processAliases) {
  const current = unwrapEnvironmentExpression(node);
  if (!current) return false;
  if (current.type === "Identifier") return processAliases.has(current.name);
  const chain = environmentMemberChain(current);
  if (chain && chain.length >= 2 && chain.at(-1) === "process") {
    return true;
  }
  if (current.type === "LogicalExpression") {
    return (
      expressionIsProcessAlias(current.left, processAliases) ||
      expressionIsProcessAlias(current.right, processAliases)
    );
  }
  if (current.type === "ConditionalExpression") {
    return (
      expressionIsProcessAlias(current.consequent, processAliases) ||
      expressionIsProcessAlias(current.alternate, processAliases)
    );
  }
  if (current.type === "SequenceExpression") {
    return expressionIsProcessAlias(current.expressions.at(-1), processAliases);
  }
  if (current.type === "ObjectExpression") {
    return current.properties.some(
      (property) =>
        property.type === "SpreadElement" &&
        expressionIsProcessAlias(property.argument, processAliases),
    );
  }
  return false;
}

function isDirectProcessEnvironment(node, processAliases) {
  const current = unwrapEnvironmentExpression(node);
  return Boolean(
    new Set(["MemberExpression", "OptionalMemberExpression"]).has(
      current?.type,
    ) &&
    environmentMemberName(current) === "env" &&
    expressionIsProcessAlias(current.object, processAliases),
  );
}

function expressionIsEnvironmentAlias(node, aliases, processAliases) {
  const current = unwrapEnvironmentExpression(node);
  if (!current) return false;
  if (isDirectProcessEnvironment(current, processAliases)) return true;
  if (current.type === "Identifier") return aliases.has(current.name);
  if (current.type === "LogicalExpression") {
    return (
      expressionIsEnvironmentAlias(current.left, aliases, processAliases) ||
      expressionIsEnvironmentAlias(current.right, aliases, processAliases)
    );
  }
  if (current.type === "ConditionalExpression") {
    return (
      expressionIsEnvironmentAlias(
        current.consequent,
        aliases,
        processAliases,
      ) ||
      expressionIsEnvironmentAlias(current.alternate, aliases, processAliases)
    );
  }
  if (current.type === "SequenceExpression") {
    return expressionIsEnvironmentAlias(
      current.expressions.at(-1),
      aliases,
      processAliases,
    );
  }
  return false;
}

function scanJavaScriptEnvironmentSource(text, sourcePath, collector) {
  const program = parseEnvironmentJavaScript(text, sourcePath);
  const aliases = new Set();
  const processAliases = new Set(["process"]);
  let changed = true;
  while (changed) {
    changed = false;
    walkAst(program, (node) => {
      let binding = null;
      let expression = null;
      if (node.type === "VariableDeclarator") {
        binding = node.id;
        expression = node.init;
      } else if (
        node.type === "AssignmentExpression" &&
        node.operator === "="
      ) {
        binding = node.left;
        expression = node.right;
      }
      if (!binding || !expression) return;
      if (binding.type === "Identifier") {
        if (
          !processAliases.has(binding.name) &&
          expressionIsProcessAlias(expression, processAliases)
        ) {
          processAliases.add(binding.name);
          changed = true;
        }
        if (
          !aliases.has(binding.name) &&
          expressionIsEnvironmentAlias(expression, aliases, processAliases)
        ) {
          aliases.add(binding.name);
          changed = true;
        }
        return;
      }
      if (
        binding.type !== "ObjectPattern" ||
        !expressionIsProcessAlias(expression, processAliases)
      ) {
        return;
      }
      for (const property of binding.properties) {
        if (property.type === "RestElement") {
          if (
            property.argument?.type === "Identifier" &&
            !processAliases.has(property.argument.name)
          ) {
            processAliases.add(property.argument.name);
            changed = true;
          }
          continue;
        }
        const names = property.computed
          ? staticPropertyName(property.key)
          : property.key?.type === "Identifier"
            ? [property.key.name]
            : staticPropertyName(property.key);
        const destination =
          property.value?.type === "Identifier"
            ? property.value
            : property.value?.type === "AssignmentPattern" &&
                property.value.left?.type === "Identifier"
              ? property.value.left
              : null;
        if (
          names.length === 1 &&
          names[0] === "env" &&
          destination &&
          !aliases.has(destination.name)
        ) {
          aliases.add(destination.name);
          changed = true;
        }
      }
    });
  }

  walkAst(program, (node) => {
    const binding =
      node.type === "VariableDeclarator"
        ? node.id
        : node.type === "AssignmentExpression" && node.operator === "="
          ? node.left
          : null;
    const expression =
      node.type === "VariableDeclarator"
        ? node.init
        : node.type === "AssignmentExpression"
          ? node.right
          : null;
    if (
      binding?.type !== "ObjectPattern" ||
      !expressionIsProcessAlias(expression, processAliases)
    ) {
      return;
    }
    if (
      binding.properties.some(
        (property) =>
          property.type !== "RestElement" &&
          property.computed &&
          staticPropertyName(property.key).length === 0,
      )
    ) {
      collector.addDynamic({
        accessor: "process-destructure",
        language: "javascript",
        sourcePath,
      });
    }

    for (const property of binding.properties) {
      if (property.type === "RestElement") continue;
      const names = property.computed
        ? staticPropertyName(property.key)
        : property.key?.type === "Identifier"
          ? [property.key.name]
          : staticPropertyName(property.key);
      if (names.length !== 1 || names[0] !== "env") continue;
      const destination =
        property.value?.type === "AssignmentPattern"
          ? property.value.left
          : property.value;
      if (destination?.type !== "ObjectPattern") continue;

      for (const environmentProperty of destination.properties) {
        if (environmentProperty.type === "RestElement") {
          collector.addDynamic({
            accessor: "process-destructure",
            language: "javascript",
            sourcePath,
          });
          continue;
        }
        const environmentNames = environmentProperty.computed
          ? staticPropertyName(environmentProperty.key)
          : environmentProperty.key?.type === "Identifier"
            ? [environmentProperty.key.name]
            : staticPropertyName(environmentProperty.key);
        if (environmentNames.length !== 1) {
          collector.addDynamic({
            accessor: "process-destructure",
            language: "javascript",
            sourcePath,
          });
          continue;
        }
        collector.add({
          accessor: "process-destructure",
          direction: "read",
          language: "javascript",
          name: environmentNames[0],
          sourcePath,
        });
      }
    }
  });

  // A process value that crosses an unreviewed binding or call boundary can
  // be used to recover process.env under a name that this local alias analysis
  // cannot prove. Keep those flows visible as one conservative dynamic
  // environment sentinel instead of silently treating them as unrelated data.
  // Direct identifier assignments and one-level process/env destructuring are
  // handled exactly by the fixed-point pass above.
  walkAst(program, (node) => {
    const carriesProcess = (expression) =>
      expressionIsProcessAlias(expression, processAliases);
    const argumentsCarryProcess = (argumentsList) =>
      argumentsList.some((argument) =>
        argument?.type === "SpreadElement"
          ? carriesProcess(argument.argument)
          : carriesProcess(argument),
      );
    let unresolved = false;
    if (node.type === "VariableDeclarator" && carriesProcess(node.init)) {
      unresolved = !new Set(["Identifier", "ObjectPattern"]).has(node.id?.type);
    } else if (
      node.type === "AssignmentExpression" &&
      node.operator === "=" &&
      carriesProcess(node.right)
    ) {
      unresolved = !new Set(["Identifier", "ObjectPattern"]).has(
        node.left?.type,
      );
    } else if (
      node.type === "AssignmentPattern" &&
      carriesProcess(node.right)
    ) {
      unresolved = true;
    } else if (
      new Set([
        "CallExpression",
        "OptionalCallExpression",
        "NewExpression",
      ]).has(node.type)
    ) {
      unresolved = argumentsCarryProcess(node.arguments ?? []);
    } else if (node.type === "ArrayExpression") {
      unresolved = node.elements.some(
        (element) =>
          element &&
          (element.type === "SpreadElement"
            ? carriesProcess(element.argument)
            : carriesProcess(element)),
      );
    } else if (node.type === "ObjectProperty") {
      unresolved =
        carriesProcess(node.value) ||
        (node.computed && carriesProcess(node.key));
    } else if (node.type === "SpreadElement") {
      unresolved = carriesProcess(node.argument);
    } else if (
      new Set([
        "ClassPrivateProperty",
        "ClassProperty",
        "PropertyDefinition",
      ]).has(node.type)
    ) {
      unresolved =
        carriesProcess(node.value) ||
        (node.computed && carriesProcess(node.key));
    } else if (
      new Set([
        "AwaitExpression",
        "ReturnStatement",
        "ThrowStatement",
        "YieldExpression",
      ]).has(node.type)
    ) {
      unresolved = carriesProcess(node.argument);
    } else if (node.type === "ExportDefaultDeclaration") {
      unresolved = carriesProcess(node.declaration);
    } else if (node.type === "ExportNamedDeclaration") {
      unresolved =
        (node.declaration?.type === "VariableDeclaration" &&
          node.declaration.declarations.some((declaration) =>
            carriesProcess(declaration.init),
          )) ||
        (node.specifiers ?? []).some((specifier) =>
          carriesProcess(specifier.local),
        );
    } else if (
      node.type === "ArrowFunctionExpression" &&
      node.body?.type !== "BlockStatement"
    ) {
      unresolved = carriesProcess(node.body);
    } else if (node.type === "JSXExpressionContainer") {
      unresolved = carriesProcess(node.expression);
    } else if (node.type === "TemplateLiteral") {
      unresolved = node.expressions.some(carriesProcess);
    } else if (node.type === "TaggedTemplateExpression") {
      unresolved = carriesProcess(node.tag);
    } else if (
      new Set(["ForInStatement", "ForOfStatement", "WithStatement"]).has(
        node.type,
      )
    ) {
      unresolved = carriesProcess(node.right ?? node.object);
    }
    if (unresolved) {
      collector.addDynamic({
        accessor: "process-binding-flow",
        language: "javascript",
        sourcePath,
      });
    }
  });

  const isEnvironmentObject = (node) => {
    const current = unwrapEnvironmentExpression(node);
    return Boolean(
      isDirectProcessEnvironment(current, processAliases) ||
      (current?.type === "Identifier" && aliases.has(current.name)),
    );
  };
  const environmentMutation = (call) => {
    if (call?.type !== "CallExpression") return null;
    const callee = environmentMemberChain(call.callee)?.join(".");
    const mutation = new Map([
      [
        "Object.assign",
        {
          accessor: "Object.assign(process.env)",
          direction: "write",
          mode: "sources",
        },
      ],
      [
        "Object.defineProperties",
        {
          accessor: "Object.defineProperties(process.env)",
          direction: "write",
          mode: "descriptor-object",
        },
      ],
      [
        "Object.defineProperty",
        {
          accessor: "Object.defineProperty(process.env)",
          direction: "write",
          mode: "key",
        },
      ],
      [
        "Reflect.defineProperty",
        {
          accessor: "Reflect.defineProperty(process.env)",
          direction: "write",
          mode: "key",
        },
      ],
      [
        "Reflect.deleteProperty",
        {
          accessor: "Reflect.deleteProperty(process.env)",
          direction: "unset",
          mode: "key",
        },
      ],
      [
        "Reflect.set",
        {
          accessor: "Reflect.set(process.env)",
          direction: "write",
          mode: "key",
        },
      ],
    ]).get(callee);
    if (!mutation || !isEnvironmentObject(call.arguments[0])) return null;
    return mutation;
  };
  const recordMutationName = (node, mutation) => {
    const current = unwrapEnvironmentExpression(node);
    if (current?.type === "StringLiteral") {
      collector.add({
        accessor: mutation.accessor,
        direction: mutation.direction,
        language: "javascript",
        name: current.value,
        sourcePath,
      });
      return true;
    }
    return false;
  };
  const recordDescriptorObject = (node, mutation) => {
    const current = unwrapEnvironmentExpression(node);
    if (current?.type !== "ObjectExpression") return false;
    let exact = true;
    for (const property of current.properties) {
      if (property.type === "SpreadElement") {
        exact = false;
        continue;
      }
      const names =
        !property.computed && property.key?.type === "Identifier"
          ? [property.key.name]
          : staticPropertyName(property.key);
      if (property.computed || names.length !== 1) {
        exact = false;
        continue;
      }
      collector.add({
        accessor: mutation.accessor,
        direction: mutation.direction,
        language: "javascript",
        name: names[0],
        sourcePath,
      });
    }
    return exact;
  };
  const meaningfulParent = (ancestors) => {
    for (let index = ancestors.length - 1; index >= 0; index -= 1) {
      const candidate = ancestors[index];
      if (
        !new Set([
          "ChainExpression",
          "TSAsExpression",
          "TSNonNullExpression",
          "TSSatisfiesExpression",
          "TypeCastExpression",
        ]).has(candidate.type)
      ) {
        return candidate;
      }
    }
    return null;
  };

  walkAstWithAncestors(program, (node, ancestors) => {
    const current = unwrapEnvironmentExpression(node);
    if (current !== node) return;
    if (current?.type === "CallExpression") {
      const mutation = environmentMutation(current);
      if (mutation) {
        let exact = true;
        if (mutation.mode === "key") {
          exact = recordMutationName(current.arguments[1], mutation);
        } else if (mutation.mode === "descriptor-object") {
          exact = recordDescriptorObject(current.arguments[1], mutation);
        } else {
          for (const source of current.arguments.slice(1)) {
            exact = recordDescriptorObject(source, mutation) && exact;
          }
        }
        if (!exact) {
          collector.addDynamic({
            accessor: mutation.accessor,
            direction: mutation.direction,
            language: "javascript",
            sourcePath,
          });
        }
        return;
      }
      const callee = unwrapEnvironmentExpression(current.callee);
      if (callee?.type === "Identifier" && callee.name === "readRuntimeEnv") {
        const argument = current.arguments[0];
        if (argument?.type === "StringLiteral") {
          collector.add({
            accessor: "readRuntimeEnv",
            direction: "read",
            language: "javascript",
            name: argument.value,
            sourcePath,
          });
        } else {
          collector.addDynamic({
            accessor: "readRuntimeEnv",
            language: "javascript",
            sourcePath,
          });
        }
      }
      return;
    }
    if (
      !new Set(["MemberExpression", "OptionalMemberExpression"]).has(
        current?.type,
      )
    )
      return;
    if (
      expressionIsProcessAlias(current.object, processAliases) &&
      environmentMemberName(current) === null
    ) {
      collector.addDynamic({
        accessor: "process[]",
        language: "javascript",
        sourcePath,
      });
      return;
    }
    if (!isEnvironmentObject(current.object)) {
      if (!isDirectProcessEnvironment(current, processAliases)) return;
      const parent = meaningfulParent(ancestors);
      const parentCurrent = unwrapEnvironmentExpression(parent);
      if (
        parentCurrent?.type === "CallExpression" &&
        environmentMutation(parentCurrent) &&
        unwrapEnvironmentExpression(parentCurrent.arguments[0]) === current
      ) {
        // The call-level record above owns the exact write/unset direction.
        return;
      }
      if (
        new Set(["MemberExpression", "OptionalMemberExpression"]).has(
          parentCurrent?.type,
        ) &&
        unwrapEnvironmentExpression(parentCurrent.object) === current
      ) {
        return;
      }
      collector.addDynamic({
        accessor: "process.env",
        language: "javascript",
        sourcePath,
      });
      return;
    }

    const property = environmentMemberName(current);
    const parent = meaningfulParent(ancestors);
    let direction = "read";
    if (
      parent?.type === "AssignmentExpression" &&
      unwrapEnvironmentExpression(parent.left) === current
    ) {
      direction = "write";
    } else if (
      parent?.type === "UnaryExpression" &&
      parent.operator === "delete" &&
      unwrapEnvironmentExpression(parent.argument) === current
    ) {
      direction = "unset";
    }
    if (property === null) {
      collector.addDynamic({
        accessor: "process.env[]",
        direction,
        language: "javascript",
        sourcePath,
      });
      return;
    }
    collector.add({
      accessor: "process.env",
      direction,
      language: "javascript",
      name: property,
      sourcePath,
    });
  });

  // Spawn environment objects are intentionally local copies rather than
  // process.env aliases. Their exact control keys still need output direction.
  if (
    sourcePath.includes("/child-process.js") ||
    sourcePath.includes("/cluster.js")
  ) {
    walkAstWithAncestors(program, (node, ancestors) => {
      const current = unwrapEnvironmentExpression(node);
      if (
        !new Set(["MemberExpression", "OptionalMemberExpression"]).has(
          current?.type,
        )
      )
        return;
      if (unwrapEnvironmentExpression(current.object)?.type !== "Identifier")
        return;
      if (!/^env$/iu.test(unwrapEnvironmentExpression(current.object).name))
        return;
      const name = environmentMemberName(current);
      if (!name || !/^(?:EXACT|IBEX|NODE)_/u.test(name)) return;
      const parent = ancestors.at(-1);
      const direction =
        parent?.type === "UnaryExpression" && parent.operator === "delete"
          ? "unset"
          : parent?.type === "AssignmentExpression"
            ? "write"
            : "read";
      collector.add({
        accessor: "spawn-env-object",
        direction,
        language: "javascript",
        name,
        sourcePath,
      });
    });
  }
}

function tokenCallArguments(tokens, openIndex) {
  const close = matchingToken(tokens, openIndex, "(", ")");
  if (close === -1) return null;
  const argumentsList = [];
  let start = openIndex + 1;
  let parenDepth = 0;
  let bracketDepth = 0;
  let braceDepth = 0;
  for (let index = start; index < close; index += 1) {
    const value = tokens[index].value;
    if (value === "(") parenDepth += 1;
    if (value === ")") parenDepth -= 1;
    if (value === "[") bracketDepth += 1;
    if (value === "]") bracketDepth -= 1;
    if (value === "{") braceDepth += 1;
    if (value === "}") braceDepth -= 1;
    if (
      value === "," &&
      parenDepth === 0 &&
      bracketDepth === 0 &&
      braceDepth === 0
    ) {
      argumentsList.push(tokens.slice(start, index));
      start = index + 1;
    }
  }
  argumentsList.push(tokens.slice(start, close));
  return argumentsList;
}

function staticTokenArgument(tokens, constants) {
  for (const token of tokens) {
    if (token.type === "string") return token.value;
    if (token.type === "identifier" && constants.has(token.value))
      return constants.get(token.value);
  }
  return null;
}

function rustStringConstants(tokens) {
  const constants = new Map();
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      !new Set(["const", "static"]).has(tokens[index]?.value) ||
      tokens[index + 1]?.type !== "identifier"
    ) {
      continue;
    }
    const name = tokens[index + 1].value;
    let cursor = index + 2;
    while (
      cursor < tokens.length &&
      !new Set(["=", ";"]).has(tokens[cursor].value)
    )
      cursor += 1;
    if (tokens[cursor]?.value !== "=") continue;
    const end = tokens.findIndex(
      (token, tokenIndex) => tokenIndex > cursor && token.value === ";",
    );
    if (end === -1) continue;
    const value = staticTokenArgument(tokens.slice(cursor + 1, end), constants);
    if (value !== null) constants.set(name, value);
  }
  return constants;
}

function environmentOccurrenceSite(tokens, definitions, tokenIndex) {
  const containing = definitions
    .filter(
      (definition) =>
        definition.bodyOpen < tokenIndex && tokenIndex < definition.bodyClose,
    )
    .sort(
      (left, right) =>
        left.bodyClose - left.bodyOpen - (right.bodyClose - right.bodyOpen),
    )[0];
  return {
    scope: containing?.name ?? "<top-level>",
    sourceOffset: tokens[tokenIndex]?.offset ?? null,
  };
}

function scanRustEnvironmentSource(text, sourcePath, collector) {
  const tokens = rustProductionTokens(text, sourcePath);
  const constants = rustStringConstants(tokens);
  const definitions = rustFunctionDefinitions(tokens);
  const definitionNameIndexes = new Set(
    definitions.map((definition) => definition.nameIndex),
  );
  const directApis = new Map([
    ["remove_var", "unset"],
    ["set_var", "write"],
    ["var", "read"],
    ["var_os", "read"],
  ]);
  const helperArities = new Map([
    ["env_flag_enabled", 1],
    ["runtime_env", 2],
    ["timeout_from_env", 1],
  ]);
  const importsProcessCommand =
    /\buse\s+(?:std|tokio)\s*::\s*process\s*::\s*(?:\{[^}]*\bCommand\b[^}]*\}|Command)\s*;/su.test(
      text,
    );
  for (let index = 0; index < tokens.length; index += 1) {
    const name = tokens[index]?.value;
    if (tokens[index + 1]?.value !== "(") continue;
    const argumentsList = tokenCallArguments(tokens, index + 1);
    if (!argumentsList) continue;
    const processCommandConstructor =
      name === "new" &&
      tokens[index - 1]?.value === ":" &&
      tokens[index - 2]?.value === ":" &&
      tokens[index - 3]?.value === "Command" &&
      (importsProcessCommand ||
        (tokens[index - 4]?.value === ":" &&
          tokens[index - 5]?.value === ":" &&
          tokens[index - 6]?.value === "process" &&
          tokens[index - 7]?.value === ":" &&
          tokens[index - 8]?.value === ":" &&
          new Set(["std", "tokio"]).has(tokens[index - 9]?.value)));
    if (processCommandConstructor) {
      // Rust Command starts with inherited parent state until env_clear is
      // applied. Inventory the default explicitly even when a later method
      // closes it, so review can distinguish denylist and closed builders.
      collector.addDynamic({
        accessor: "Command::default_env",
        context: "spawn-child-env",
        direction: "write",
        language: "rust",
        ...environmentOccurrenceSite(tokens, definitions, index),
        sourcePath,
      });
      continue;
    }
    if (
      new Set(["env", "env_clear", "env_remove"]).has(name) &&
      tokens[index - 1]?.value === "."
    ) {
      const direction = name === "env" ? "write" : "unset";
      if (name === "env_clear") {
        collector.addDynamic({
          accessor: "Command::env_clear",
          context: "spawn-child-env",
          direction,
          language: "rust",
          ...environmentOccurrenceSite(tokens, definitions, index),
          sourcePath,
        });
        continue;
      }
      const value = staticTokenArgument(argumentsList[0] ?? [], constants);
      if (value === null) {
        collector.addDynamic({
          accessor: `Command::${name}`,
          context: "spawn-child-env",
          direction,
          language: "rust",
          ...environmentOccurrenceSite(tokens, definitions, index),
          sourcePath,
        });
      } else {
        collector.add({
          accessor: `Command::${name}`,
          context: "spawn-child-env",
          direction,
          language: "rust",
          name: value,
          ...environmentOccurrenceSite(tokens, definitions, index),
          sourcePath,
        });
      }
      continue;
    }
    const precededByEnv =
      tokens[index - 1]?.value === ":" &&
      tokens[index - 2]?.value === ":" &&
      tokens[index - 3]?.value === "env";
    if (directApis.has(name) && precededByEnv) {
      const direction = directApis.get(name);
      const value = staticTokenArgument(argumentsList[0] ?? [], constants);
      if (value === null) {
        collector.addDynamic({
          accessor: `env::${name}`,
          direction,
          language: "rust",
          ...environmentOccurrenceSite(tokens, definitions, index),
          sourcePath,
        });
      } else {
        collector.add({
          accessor: `env::${name}`,
          direction,
          language: "rust",
          name: value,
          ...environmentOccurrenceSite(tokens, definitions, index),
          sourcePath,
        });
      }
      continue;
    }
    if (new Set(["vars", "vars_os"]).has(name) && precededByEnv) {
      collector.addDynamic({
        accessor: `env::${name}`,
        language: "rust",
        ...environmentOccurrenceSite(tokens, definitions, index),
        sourcePath,
      });
      continue;
    }
    if (!helperArities.has(name) || definitionNameIndexes.has(index)) continue;
    const expected = helperArities.get(name);
    for (let argumentIndex = 0; argumentIndex < expected; argumentIndex += 1) {
      const value = staticTokenArgument(
        argumentsList[argumentIndex] ?? [],
        constants,
      );
      if (value === null) {
        collector.addDynamic({
          accessor: name,
          language: "rust",
          ...environmentOccurrenceSite(tokens, definitions, index),
          sourcePath,
        });
      } else {
        collector.add({
          accessor: name,
          direction: "read",
          language: "rust",
          name: value,
          ...environmentOccurrenceSite(tokens, definitions, index),
          sourcePath,
        });
      }
    }
  }
}

function cppStringConstants(tokens) {
  const constants = new Map();
  for (let index = 0; index < tokens.length - 2; index += 1) {
    if (tokens[index]?.type !== "identifier") continue;
    let cursor = index + 1;
    if (tokens[cursor]?.value !== "=") continue;
    cursor += 1;
    if (
      tokens[cursor]?.type === "identifier" &&
      new Set(["L", "U", "u", "u8"]).has(tokens[cursor].value)
    ) {
      cursor += 1;
    }
    if (tokens[cursor]?.type === "string")
      constants.set(tokens[index].value, tokens[cursor].value);
  }
  return constants;
}

function cppEnvironmentCallNameIndexes(tokens, definitionNameIndexes) {
  const callNameIndexes = new Set();
  for (let index = 0; index < tokens.length - 1; index += 1) {
    if (
      tokens[index]?.type !== "identifier" ||
      tokens[index + 1]?.value !== "(" ||
      definitionNameIndexes.has(index) ||
      new Set([".", "->"]).has(tokens[index - 1]?.value)
    ) {
      continue;
    }
    let boundary = index - 1;
    while (
      boundary >= 0 &&
      !new Set([";", "{", "}"]).has(tokens[boundary].value)
    ) {
      boundary -= 1;
    }
    const prefix = tokens.slice(boundary + 1, index);
    // A qualified free/static call such as std::getenv has no expression
    // prefix once its namespace is removed. Preserve earlier tokens so an
    // initializer such as `auto value = std::getenv(...)` still observes the
    // assignment marker.
    while (prefix.at(-1)?.value === "::") {
      prefix.pop();
      if (prefix.at(-1)?.type === "identifier") prefix.pop();
    }
    const callContext =
      prefix.length === 0 ||
      prefix.some((token) =>
        new Set(["=", "(", "[", ",", "?", ":"]).has(token.value),
      ) ||
      new Set(["co_return", "return", "throw"]).has(prefix.at(-1)?.value);
    if (callContext) callNameIndexes.add(index);
  }
  return callNameIndexes;
}

function cppBareEnvironmentRead(tokens, tokenIndex) {
  if (
    tokens[tokenIndex]?.value !== "environ" ||
    tokens[tokenIndex + 1]?.value === "(" ||
    new Set([".", "->", "::"]).has(tokens[tokenIndex - 1]?.value)
  ) {
    return false;
  }
  let boundary = tokenIndex - 1;
  while (
    boundary >= 0 &&
    !new Set([";", "{", "}"]).has(tokens[boundary].value)
  ) {
    boundary -= 1;
  }
  const prefix = tokens.slice(boundary + 1, tokenIndex);
  if (prefix.some((token) => token.value === "extern")) return false;
  // `extern char** environ;` and equivalent declarations have a type-only
  // prefix. Reads necessarily appear in an expression position: initializer,
  // argument, condition, subscript, conditional, or return/throw operand.
  return (
    prefix.length === 0 ||
    prefix.some((token) =>
      new Set(["=", "(", "[", ",", "?", ":"]).has(token.value),
    ) ||
    new Set(["co_return", "return", "throw"]).has(prefix.at(-1)?.value)
  );
}

function scanCppEnvironmentSource(text, sourcePath, collector) {
  const tokens = lexCpp(text, sourcePath);
  const constants = cppStringConstants(tokens);
  const definitions = cppFunctionDefinitions(tokens);
  const definitionNameIndexes = new Set(
    definitions
      .filter(
        (definition) =>
          !definitions.some(
            (candidate) =>
              candidate !== definition &&
              candidate.bodyOpen < definition.nameIndex &&
              definition.nameIndex < candidate.bodyClose,
          ),
      )
      .map((definition) => definition.nameIndex),
  );
  const callNameIndexes = cppEnvironmentCallNameIndexes(
    tokens,
    definitionNameIndexes,
  );
  const accessors = new Map([
    ["GetEnvironmentVariableA", "read"],
    ["GetEnvironmentVariableW", "read"],
    ["SetEnvironmentVariableA", "write"],
    ["SetEnvironmentVariableW", "write"],
    ["_dupenv_s", "read"],
    ["env_flag_enabled", "read"],
    ["getenv", "read"],
    ["getenvString", "read"],
    ["setenv", "write"],
    ["unsetenv", "unset"],
  ]);
  const enumerationAccessors = new Set([
    "GetEnvironmentStringsW",
    "_NSGetEnviron",
  ]);
  for (let index = 0; index < tokens.length; index += 1) {
    const accessor = tokens[index]?.value;
    if (
      accessor === "s_setEnvEntry" &&
      callNameIndexes.has(index)
    ) {
      const argumentsList = tokenCallArguments(tokens, index + 1);
      if (!argumentsList) continue;
      const name = staticTokenArgument(argumentsList[1] ?? [], constants);
      if (name === null) {
        collector.addDynamic({
          accessor,
          direction: "write",
          language: "cpp",
          ...environmentOccurrenceSite(tokens, definitions, index),
          sourcePath,
        });
      } else {
        collector.add({
          accessor,
          direction: "write",
          language: "cpp",
          name,
          ...environmentOccurrenceSite(tokens, definitions, index),
          sourcePath,
        });
      }
      continue;
    }
    if (
      enumerationAccessors.has(accessor) &&
      callNameIndexes.has(index)
    ) {
      collector.addDynamic({
        accessor,
        direction: "read",
        language: "cpp",
        ...environmentOccurrenceSite(tokens, definitions, index),
        sourcePath,
      });
      continue;
    }
    const qualifiedEnviron =
      accessor === "environ" &&
      tokens[index - 1]?.value === "::" &&
      tokens[index + 1]?.value !== "(";
    const bareEnviron = cppBareEnvironmentRead(tokens, index);
    if (qualifiedEnviron || bareEnviron) {
      collector.addDynamic({
        accessor: qualifiedEnviron ? "::environ" : "environ",
        direction: "read",
        language: "cpp",
        ...environmentOccurrenceSite(tokens, definitions, index),
        sourcePath,
      });
      continue;
    }
    if (
      !accessors.has(accessor) ||
      !callNameIndexes.has(index)
    ) {
      continue;
    }
    const argumentsList = tokenCallArguments(tokens, index + 1);
    if (!argumentsList) continue;
    const direction = accessors.get(accessor);
    const nameArgumentIndex = accessor === "_dupenv_s" ? 2 : 0;
    const name = staticTokenArgument(
      argumentsList[nameArgumentIndex] ?? [],
      constants,
    );
    if (name === null) {
      collector.addDynamic({
        accessor,
        direction,
        language: "cpp",
        ...environmentOccurrenceSite(tokens, definitions, index),
        sourcePath,
      });
    } else {
      collector.add({
        accessor,
        direction,
        language: "cpp",
        name,
        ...environmentOccurrenceSite(tokens, definitions, index),
        sourcePath,
      });
    }
  }
}

/**
 * Inventory authored runtime environment controls across JS/TS, Rust, and
 * native sources. Callers decide the production source set; generated files,
 * build scripts, tests, and devtools are deliberately outside this scanner.
 */
export function scanRuntimeEnvironmentSurfaces({
  javascript = [],
  native = [],
  rust = [],
}) {
  const collector = createEnvironmentCollector();
  for (const source of javascript) {
    scanJavaScriptEnvironmentSource(source.text, source.sourcePath, collector);
  }
  for (const source of rust) {
    scanRustEnvironmentSource(source.text, source.sourcePath, collector);
  }
  for (const source of native) {
    scanCppEnvironmentSource(source.text, source.sourcePath, collector);
  }
  const rows = collector.rows();
  if (rows.length === 0)
    throw new Error("runtime environment surface inventory is empty");
  return rows;
}

export function isRuntimeEnvironmentSourceAllowed(relativePath) {
  const normalized = posixPath(relativePath);
  return (
    !normalized.includes("generated") &&
    !/(?:^|\/)(?:__tests__|benchmarks?|devtools|fixtures?|tests?)(?:\/|$)/u.test(
      normalized,
    ) &&
    !/(?:^|\/)[^/]*devtools[^/]*(?:\/|$)/u.test(normalized) &&
    !/\.(?:bench|e2e|fixture|spec|test)\.[^/]+$/u.test(normalized) &&
    !/(?:^|[/_-])tests?\.(?:c|cc|cpp|cxx|m|mm|rs)$/u.test(normalized) &&
    !normalized.endsWith("/build.rs") &&
    normalized !== "build.rs" &&
    !normalized.startsWith("src/bin/ibex/compat/")
  );
}

const FIXED_EVIDENCE_TYPES = new Set([
  "cpp-call",
  "cpp-data",
  "cpp-function",
  "cpp-type",
  "javascript-function",
  "public-abi",
  "rust-function",
]);

const FIXED_EVIDENCE_ROLES = new Set([
  "implementation",
  "implementation-container",
]);

function definitionEvidenceRows(type, sourcePath, definitions) {
  const counts = new Map();
  for (const definition of definitions) {
    counts.set(definition.name, (counts.get(definition.name) ?? 0) + 1);
  }
  return [...counts.entries()].map(([symbol, occurrenceCount]) => ({
    type,
    sourceRef: sourceSymbol(sourcePath, symbol),
    occurrenceCount,
  }));
}

/** Structural definitions available to the fixed semantic inventory. */
export function scanFixedRuntimeEvidenceCandidates(text, sourcePath) {
  const extension = path.extname(sourcePath);
  let rows;
  if (new Set([".js", ".cjs", ".mjs"]).has(extension)) {
    const program = parseJavaScript(text, sourcePath);
    rows = definitionEvidenceRows(
      "javascript-function",
      sourcePath,
      javascriptFixedGlobalFunctionDefinitions(program),
    );
  } else if (extension === ".rs") {
    const tokens = rustProductionTokens(text, sourcePath);
    rows = [
      ...definitionEvidenceRows(
        "rust-function",
        sourcePath,
        rustFunctionDefinitions(tokens),
      ),
      ...scanRustPublicAbiDefinitions(text, sourcePath).map((row) => ({
        type: "public-abi",
        sourceRef: row.sourceRefs[0],
        occurrenceCount: 1,
      })),
    ];
  } else if (NATIVE_SOURCE_EXTENSIONS.has(extension)) {
    const tokens = lexCpp(text, sourcePath);
    rows = [
      ...definitionEvidenceRows(
        "cpp-call",
        sourcePath,
        cppCallExpressions(tokens),
      ),
      ...definitionEvidenceRows(
        "cpp-function",
        sourcePath,
        cppFunctionDefinitions(tokens),
      ),
      ...definitionEvidenceRows(
        "cpp-type",
        sourcePath,
        cppTypeDefinitions(tokens),
      ),
      ...definitionEvidenceRows(
        "cpp-data",
        sourcePath,
        cppDataDefinitions(tokens),
      ),
      ...scanCppPublicAbiDefinitions(text, sourcePath).map((row) => ({
        type: "public-abi",
        sourceRef: row.sourceRefs[0],
        occurrenceCount: 1,
      })),
    ];
  } else {
    throw new Error(
      `${sourcePath}: unsupported fixed-evidence source extension ${extension}`,
    );
  }

  return rows.sort((left, right) =>
    compareText(
      `${left.type}\0${left.sourceRef}`,
      `${right.type}\0${right.sourceRef}`,
    ),
  );
}

function fixedEvidence(type, file, symbol, role = "implementation") {
  return { type, file, symbol, role };
}

function fixedSurface(kind, name, ...evidence) {
  return { kind, name, evidence };
}

function fixedCallbackControlSurface(name, ...evidence) {
  return {
    ...fixedSurface("callback", name, ...evidence),
    callbackOutputBoundary: "none",
  };
}

function callbackOutput(
  selector,
  returnVariant,
  direction,
  role,
  valueShape,
  ...sourceRefs
) {
  return {
    selector,
    returnVariant,
    direction,
    role,
    valueShape,
    sourceRefs,
  };
}

function fixedCallbackOutputSurface(name, outputContracts, ...evidence) {
  return {
    ...fixedSurface("callback", name, ...evidence),
    callbackOutputContracts: outputContracts,
  };
}

function implementationContainer(type, file, symbol) {
  return fixedEvidence(type, file, symbol, "implementation-container");
}

const FIXED_RUNTIME_SURFACE_DEFINITIONS = [
  // Loader branches. Several intentionally share a source symbol: they are
  // distinct decision branches in load(), not duplicate handwritten tables.
  fixedSurface(
    "loader",
    "module-runner-edge-authorization",
    fixedEvidence(
      "rust-function",
      "src/module_loader/security.rs",
      "authorize",
    ),
  ),
  fixedSurface(
    "loader",
    "module-runner-trusted-source-acquisition",
    implementationContainer(
      "rust-function",
      "src/module_loader/security.rs",
      "authorize_then_access",
    ),
  ),
  fixedSurface(
    "loader",
    "module-runner-cache-access",
    implementationContainer(
      "rust-function",
      "src/module_loader/security.rs",
      "authorize_then_access",
    ),
  ),
  fixedSurface(
    "loader",
    "module-runner-prepared-carrier-access",
    implementationContainer(
      "rust-function",
      "src/module_loader/security.rs",
      "authorize_then_access",
    ),
  ),
  fixedSurface(
    "loader",
    "install",
    implementationContainer(
      "cpp-function",
      "src/engine/hermes_bootstrap.cc",
      "installModuleLoader",
    ),
  ),
  fixedSurface(
    "loader",
    "internal-module",
    fixedEvidence(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "loadInternal",
    ),
  ),
  fixedSurface(
    "loader",
    "builtin-module",
    fixedEvidence(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "builtinCacheKeyFor",
    ),
  ),
  fixedSurface(
    "loader",
    "empty-specifier-rejection",
    implementationContainer(
      "rust-function",
      "src/module_loader/mod.rs",
      "resolve_meta",
    ),
  ),
  fixedSurface(
    "loader",
    "private-package-import",
    fixedEvidence(
      "rust-function",
      "src/module_loader/mod.rs",
      "resolve_package_import",
    ),
  ),
  fixedSurface(
    "loader",
    "unknown-exact-rejection",
    implementationContainer(
      "rust-function",
      "src/module_loader/mod.rs",
      "resolve_meta",
    ),
  ),
  fixedSurface(
    "loader",
    "unsupported-node-rejection",
    implementationContainer(
      "rust-function",
      "src/module_loader/mod.rs",
      "resolve_meta",
    ),
  ),
  fixedSurface(
    "loader",
    "oxc-on-disk-resolution",
    implementationContainer(
      "rust-function",
      "src/module_loader/mod.rs",
      "resolve_with_oxc",
    ),
  ),
  fixedSurface(
    "loader",
    "native-resolve",
    implementationContainer(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "load",
    ),
  ),
  fixedSurface(
    "loader",
    "import-policy-bare",
    fixedEvidence(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "checkImportGate",
    ),
  ),
  fixedSurface(
    "loader",
    "import-policy-resolved-path",
    implementationContainer(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "load",
    ),
  ),
  fixedSurface(
    "loader",
    "package-principal",
    fixedEvidence(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "packagePrincipalFor",
    ),
  ),
  fixedSurface(
    "loader",
    "package-compile",
    fixedEvidence(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "compileModuleBody",
    ),
  ),
  fixedSurface(
    "loader",
    "json-module",
    implementationContainer(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "load",
    ),
  ),
  fixedSurface(
    "loader",
    "commonjs-module",
    implementationContainer(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "load",
    ),
  ),
  fixedSurface(
    "loader",
    "esm-module",
    implementationContainer(
      "rust-function",
      "src/module_loader/mod.rs",
      "resolve_with_oxc",
    ),
  ),
  fixedSurface(
    "loader",
    "wasm-module",
    implementationContainer(
      "rust-function",
      "src/module_loader/mod.rs",
      "resolve_with_oxc",
    ),
  ),
  fixedSurface(
    "loader",
    "native-addon-module",
    implementationContainer(
      "rust-function",
      "src/module_loader/mod.rs",
      "resolve_with_oxc",
    ),
  ),
  fixedSurface(
    "loader",
    "dynamic-import",
    fixedEvidence(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "importImpl",
    ),
  ),
  fixedSurface(
    "loader",
    "require-resolve",
    fixedEvidence(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "__exactResolvePath",
    ),
  ),
  fixedSurface(
    "loader",
    "import-needs",
    fixedEvidence(
      "javascript-function",
      "src/engine/bootstrap/module-loader.js",
      "rejectRuntimeLoaderOptions",
    ),
  ),

  // Product session ingress. Parser rows describe only argv shape; these
  // fixed routes prove where operator-authored bytes actually enter the
  // armed, authenticated session adapter.
  // @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
  fixedSurface(
    "cli",
    "authenticated-one-shot-ingress",
    fixedEvidence("rust-function", "src/bin/ibex/main.rs", "eval_code"),
  ),
  fixedSurface(
    "cli",
    "authenticated-direct-file-ingress",
    fixedEvidence(
      "rust-function",
      "src/bin/ibex/main.rs",
      "run_file_with_execution_adapter",
    ),
  ),
  fixedSurface(
    "cli",
    "authenticated-program-stdin-ingress",
    fixedEvidence("rust-function", "src/bin/ibex/main.rs", "run_stdin_program"),
  ),
  fixedSurface(
    "cli",
    "authenticated-repl-ingress",
    fixedEvidence("rust-function", "src/bin/ibex/main.rs", "start_repl"),
  ),
  fixedSurface(
    "cli",
    "implicit-no-file-dispatch",
    fixedEvidence("rust-function", "src/bin/ibex/main.rs", "run"),
  ),

  // Callback and continuation branches, including the native-principal stamp
  // that must survive scheduling and be restored only around the callback.
  fixedCallbackControlSurface(
    "queue-enqueue",
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime.cc",
      "pushRuntimeCallback",
    ),
  ),
  fixedCallbackControlSurface(
    "queue-drain",
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime.cc",
      "drainCallbackQueue",
    ),
  ),
  fixedCallbackControlSurface(
    "next-tick-drain",
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime.cc",
      "runNextTickQueue",
    ),
  ),
  fixedCallbackControlSurface(
    "microtask-drain",
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime.cc",
      "drainMicrotasks",
    ),
  ),
  fixedCallbackControlSurface(
    "timer-invoke",
    fixedEvidence(
      "public-abi",
      "src/engine/hermes_runtime.cc",
      "ex_hermes_poll",
    ),
  ),
  fixedCallbackControlSurface(
    "native-principal-restore",
    fixedEvidence(
      "cpp-type",
      "src/engine/hermes_runtime_internal.h",
      "ScopedNativePrincipal",
    ),
  ),
  fixedCallbackOutputSurface(
    "host-call-async-resolve",
    [
      callbackOutput(
        "callback:resolve/0",
        "decoded-json",
        "native-to-javascript",
        "payload",
        "json-value",
        "src/engine/hermes_runtime.cc#ex_hermes_resolve_host_call",
      ),
      callbackOutput(
        "callback:resolve/0",
        "null-sentinel",
        "native-to-javascript",
        "payload",
        "null",
        "src/engine/hermes_runtime.cc#ex_hermes_resolve_host_call",
      ),
      callbackOutput(
        "callback:reject/0",
        "host-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime.cc#ex_hermes_resolve_host_call",
      ),
      callbackOutput(
        "callback:reject/0",
        "decode-or-delivery-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime.cc#ex_hermes_resolve_host_call",
      ),
    ],
    fixedEvidence(
      "public-abi",
      "src/engine/hermes_runtime.cc",
      "ex_hermes_resolve_host_call",
    ),
  ),
  fixedCallbackOutputSurface(
    "exact-host-call-async-resolve",
    [
      callbackOutput(
        "callback:resolve/0",
        "success-bytes",
        "native-to-javascript",
        "payload",
        "uint8-array",
        "src/engine/hermes_runtime.cc#ex_hermes_resolve_exact_host_call",
      ),
      callbackOutput(
        "callback:reject/0",
        "status-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime.cc#ex_hermes_resolve_exact_host_call",
      ),
      callbackOutput(
        "callback:reject/0",
        "malformed-payload-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime.cc#ex_hermes_resolve_exact_host_call",
      ),
      callbackOutput(
        "callback:reject/0",
        "delivery-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime.cc#ex_hermes_resolve_exact_host_call",
      ),
    ],
    fixedEvidence(
      "public-abi",
      "src/engine/hermes_runtime.cc",
      "ex_hermes_resolve_exact_host_call",
    ),
  ),
  fixedCallbackControlSurface(
    "watchdog-heartbeat",
    fixedEvidence(
      "public-abi",
      "src/engine/hermes_runtime.cc",
      "ex_hermes_schedule_watchdog_heartbeat_for_generation",
    ),
  ),
  fixedCallbackOutputSurface(
    "signal-delivery",
    [
      callbackOutput(
        "callback:process-listener/0",
        "signal-name",
        "native-to-javascript",
        "payload",
        "string",
        "src/engine/bootstrap/stream-enhance.js#__exactDispatchPendingSignals",
      ),
    ],
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime_crypto.cc",
      "signalWatcherThreadMain",
    ),
    fixedEvidence(
      "javascript-function",
      "src/engine/bootstrap/stream-enhance.js",
      "__exactDispatchPendingSignals",
    ),
  ),
  fixedCallbackOutputSurface(
    "fetch-delivery",
    [
      callbackOutput(
        "callback:resolve/0",
        "response-body-buffer",
        "native-to-javascript",
        "payload",
        "object",
        "src/engine/hermes_runtime_fetch.cc#installFetchGlobals",
      ),
      callbackOutput(
        "callback:resolve/0",
        "response-body-null",
        "native-to-javascript",
        "payload",
        "object",
        "src/engine/hermes_runtime_fetch.cc#installFetchGlobals",
      ),
      callbackOutput(
        "callback:reject/0",
        "network-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime_fetch.cc#installFetchGlobals",
      ),
      callbackOutput(
        "callback:reject/0",
        "delivery-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime_fetch.cc#installFetchGlobals",
      ),
    ],
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime_fetch.cc",
      "installFetchGlobals",
    ),
  ),
  fixedCallbackOutputSurface(
    "filesystem-async-delivery",
    [
      callbackOutput(
        "callback:resolve/0",
        "bytes",
        "native-to-javascript",
        "payload",
        "uint8-array",
        "src/engine/hermes_runtime_fs.cc#startFsAsync",
        "src/engine/hermes_runtime_fs_windows.cc#startFsAsync",
      ),
      callbackOutput(
        "callback:resolve/0",
        "json-string",
        "native-to-javascript",
        "payload",
        "string",
        "src/engine/hermes_runtime_fs.cc#startFsAsync",
        "src/engine/hermes_runtime_fs_windows.cc#startFsAsync",
      ),
      callbackOutput(
        "callback:resolve/0",
        "number",
        "native-to-javascript",
        "payload",
        "number",
        "src/engine/hermes_runtime_fs.cc#startFsAsync",
        "src/engine/hermes_runtime_fs_windows.cc#startFsAsync",
      ),
      callbackOutput(
        "callback:resolve/0",
        "undefined",
        "native-to-javascript",
        "payload",
        "undefined",
        "src/engine/hermes_runtime_fs.cc#startFsAsync",
        "src/engine/hermes_runtime_fs_windows.cc#startFsAsync",
      ),
      callbackOutput(
        "callback:reject/0",
        "operation-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime_fs.cc#startFsAsync",
        "src/engine/hermes_runtime_fs_windows.cc#startFsAsync",
      ),
      callbackOutput(
        "callback:reject/0",
        "queue-full-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime_fs.cc#startFsAsync",
        "src/engine/hermes_runtime_fs_windows.cc#startFsAsync",
      ),
      callbackOutput(
        "callback:reject/0",
        "delivery-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime_fs.cc#startFsAsync",
        "src/engine/hermes_runtime_fs_windows.cc#startFsAsync",
      ),
    ],
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime_fs.cc",
      "startFsAsync",
    ),
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime_fs_windows.cc",
      "startFsAsync",
    ),
  ),
  fixedCallbackOutputSurface(
    "dns-async-delivery",
    [
      callbackOutput(
        "callback:resolve/0",
        "lookup-json",
        "native-to-javascript",
        "payload",
        "string",
        "src/engine/hermes_runtime_dns.cc#installDnsHostFunctions",
        "src/engine/hermes_runtime_dns.cc#startDnsAsync",
      ),
      callbackOutput(
        "callback:resolve/0",
        "resolve-json",
        "native-to-javascript",
        "payload",
        "string",
        "src/engine/hermes_runtime_dns.cc#installDnsHostFunctions",
        "src/engine/hermes_runtime_dns.cc#startDnsAsync",
      ),
      callbackOutput(
        "callback:resolve/0",
        "reverse-json",
        "native-to-javascript",
        "payload",
        "string",
        "src/engine/hermes_runtime_dns.cc#installDnsHostFunctions",
        "src/engine/hermes_runtime_dns.cc#startDnsAsync",
      ),
      callbackOutput(
        "callback:reject/0",
        "resolver-or-worker-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime_dns.cc#startDnsAsync",
      ),
      callbackOutput(
        "callback:reject/0",
        "queue-full-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime_dns.cc#startDnsAsync",
      ),
    ],
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime_dns.cc",
      "startDnsAsync",
    ),
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime_dns.cc",
      "installDnsHostFunctions",
    ),
  ),
  fixedCallbackOutputSurface(
    "http-wait-delivery",
    [
      callbackOutput(
        "callback:resolve/0",
        "request-json",
        "native-to-javascript",
        "payload",
        "json-string",
        "src/engine/hermes_runtime_http.cc#installHttpHostFunctions",
      ),
      callbackOutput(
        "callback:resolve/0",
        "timeout",
        "native-to-javascript",
        "payload",
        "null",
        "src/engine/hermes_runtime_http.cc#installHttpHostFunctions",
      ),
      callbackOutput(
        "callback:reject/0",
        "queue-full-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime_http.cc#installHttpHostFunctions",
      ),
      callbackOutput(
        "callback:reject/0",
        "delivery-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime_http.cc#installHttpHostFunctions",
      ),
    ],
    implementationContainer(
      "cpp-function",
      "src/engine/hermes_runtime_http.cc",
      "installHttpHostFunctions",
    ),
  ),
  fixedCallbackOutputSurface(
    "http-writable-delivery",
    [
      callbackOutput(
        "callback:resolve/0",
        "status-code",
        "native-to-javascript",
        "payload",
        "number",
        "src/engine/hermes_runtime_http.cc#installHttpHostFunctions",
      ),
      callbackOutput(
        "callback:reject/0",
        "queue-full-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime_http.cc#installHttpHostFunctions",
      ),
      callbackOutput(
        "callback:reject/0",
        "delivery-error",
        "native-to-javascript",
        "error",
        "error",
        "src/engine/hermes_runtime_http.cc#installHttpHostFunctions",
      ),
    ],
    implementationContainer(
      "cpp-function",
      "src/engine/hermes_runtime_http.cc",
      "installHttpHostFunctions",
    ),
  ),
  fixedCallbackControlSurface(
    "websocket-context-release",
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime.cc",
      "native_ws_release_context",
    ),
  ),
  ...[
    [
      "websocket-open-delivery",
      [
        callbackOutput(
          "callback:_handleOpen/0",
          "protocol",
          "native-to-javascript",
          "payload",
          "string",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
        callbackOutput(
          "callback:_handleOpen/1",
          "extensions",
          "native-to-javascript",
          "payload",
          "string",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
      ],
    ],
    [
      "websocket-text-delivery",
      [
        callbackOutput(
          "callback:_handleMessage/0",
          "text",
          "native-to-javascript",
          "payload",
          "string",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
      ],
    ],
    [
      "websocket-binary-delivery",
      [
        callbackOutput(
          "callback:_handleMessage/0",
          "binary",
          "native-to-javascript",
          "payload",
          "array-buffer",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
      ],
    ],
    [
      "websocket-close-delivery",
      [
        callbackOutput(
          "callback:_handleClose/0",
          "close-code",
          "native-to-javascript",
          "payload",
          "number",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
        callbackOutput(
          "callback:_handleClose/1",
          "close-reason",
          "native-to-javascript",
          "payload",
          "string",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
        callbackOutput(
          "callback:_handleClose/2",
          "clean-flag",
          "native-to-javascript",
          "payload",
          "boolean",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
      ],
    ],
    [
      "websocket-error-delivery",
      [
        callbackOutput(
          "callback:_handleError/0",
          "error-message",
          "native-to-javascript",
          "error",
          "string",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
        callbackOutput(
          "callback:_handleClose/0",
          "setup-failure-close",
          "native-to-javascript",
          "payload",
          "number",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
        callbackOutput(
          "callback:_handleClose/1",
          "setup-failure-close",
          "native-to-javascript",
          "payload",
          "string",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
        callbackOutput(
          "callback:_handleClose/2",
          "setup-failure-close",
          "native-to-javascript",
          "payload",
          "boolean",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
      ],
    ],
    [
      "websocket-bytes-sent-delivery",
      [
        callbackOutput(
          "callback:_handleBytesSent/0",
          "byte-count",
          "native-to-javascript",
          "payload",
          "number",
          "src/engine/hermes_runtime_websocket.cc#installWebSocketGlobals",
        ),
      ],
    ],
  ].map(([name, outputContracts]) =>
    fixedCallbackOutputSurface(
      name,
      outputContracts,
      implementationContainer(
        "cpp-function",
        "src/engine/hermes_runtime_websocket.cc",
        "installWebSocketGlobals",
      ),
    ),
  ),
  fixedCallbackOutputSurface(
    "ios-dispatch",
    [
      callbackOutput(
        "callback:dispatch/0",
        "array-buffer",
        "javascript-to-native",
        "payload",
        "bytes",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_callback",
      ),
      callbackOutput(
        "callback:dispatch/0",
        "array-buffer-view",
        "javascript-to-native",
        "payload",
        "bytes",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_callback",
      ),
      callbackOutput(
        "callback:dispatch/1",
        "array-buffer-length",
        "javascript-to-native",
        "payload",
        "number",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_callback",
      ),
      callbackOutput(
        "callback:dispatch/1",
        "array-buffer-view-length",
        "javascript-to-native",
        "payload",
        "number",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_callback",
      ),
    ],
    fixedEvidence(
      "public-abi",
      "src/engine/hermes_runtime_ios.cc",
      "ex_hermes_set_dispatch_callback",
    ),
  ),
  fixedCallbackOutputSurface(
    "ios-dispatch-debug-context",
    [
      callbackOutput(
        "callback:dispatch-with-debug-context/0",
        "utf8-string",
        "javascript-to-native",
        "payload",
        "bytes",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_with_debug_context_callback",
      ),
      callbackOutput(
        "callback:dispatch-with-debug-context/0",
        "array-buffer",
        "javascript-to-native",
        "payload",
        "bytes",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_with_debug_context_callback",
      ),
      callbackOutput(
        "callback:dispatch-with-debug-context/0",
        "array-buffer-view",
        "javascript-to-native",
        "payload",
        "bytes",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_with_debug_context_callback",
      ),
      callbackOutput(
        "callback:dispatch-with-debug-context/1",
        "utf8-string-length",
        "javascript-to-native",
        "payload",
        "number",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_with_debug_context_callback",
      ),
      callbackOutput(
        "callback:dispatch-with-debug-context/1",
        "array-buffer-length",
        "javascript-to-native",
        "payload",
        "number",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_with_debug_context_callback",
      ),
      callbackOutput(
        "callback:dispatch-with-debug-context/1",
        "array-buffer-view-length",
        "javascript-to-native",
        "payload",
        "number",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_with_debug_context_callback",
      ),
      callbackOutput(
        "callback:dispatch-with-debug-context/2",
        "string",
        "javascript-to-native",
        "payload",
        "string",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_with_debug_context_callback",
      ),
      callbackOutput(
        "callback:dispatch-with-debug-context/2",
        "json-stringified",
        "javascript-to-native",
        "payload",
        "string",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_with_debug_context_callback",
      ),
      callbackOutput(
        "callback:dispatch-with-debug-context/2",
        "null-or-empty",
        "javascript-to-native",
        "payload",
        "null",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_dispatch_with_debug_context_callback",
      ),
    ],
    fixedEvidence(
      "public-abi",
      "src/engine/hermes_runtime_ios.cc",
      "ex_hermes_set_dispatch_with_debug_context_callback",
    ),
  ),
  fixedCallbackOutputSurface(
    "ios-module-dispatch",
    [
      callbackOutput(
        "callback:module-dispatch/0",
        "array-buffer",
        "javascript-to-native",
        "payload",
        "bytes",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_module_dispatch_callback",
      ),
      callbackOutput(
        "callback:module-dispatch/0",
        "array-buffer-view",
        "javascript-to-native",
        "payload",
        "bytes",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_module_dispatch_callback",
      ),
      callbackOutput(
        "callback:module-dispatch/1",
        "array-buffer-length",
        "javascript-to-native",
        "payload",
        "number",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_module_dispatch_callback",
      ),
      callbackOutput(
        "callback:module-dispatch/1",
        "array-buffer-view-length",
        "javascript-to-native",
        "payload",
        "number",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_module_dispatch_callback",
      ),
    ],
    fixedEvidence(
      "public-abi",
      "src/engine/hermes_runtime_ios.cc",
      "ex_hermes_set_module_dispatch_callback",
    ),
  ),
  fixedCallbackOutputSurface(
    "ios-module-sync",
    [
      callbackOutput(
        "callback:module-sync/0",
        "array-buffer",
        "javascript-to-native",
        "payload",
        "bytes",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_module_sync_callback",
      ),
      callbackOutput(
        "callback:module-sync/0",
        "array-buffer-view",
        "javascript-to-native",
        "payload",
        "bytes",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_module_sync_callback",
      ),
      callbackOutput(
        "callback:module-sync/1",
        "array-buffer-length",
        "javascript-to-native",
        "payload",
        "number",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_module_sync_callback",
      ),
      callbackOutput(
        "callback:module-sync/1",
        "array-buffer-view-length",
        "javascript-to-native",
        "payload",
        "number",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_module_sync_callback",
      ),
      callbackOutput(
        "callback:module-sync/return",
        "status",
        "native-to-javascript",
        "return",
        "number",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_module_sync_callback",
      ),
      callbackOutput(
        "callback:module-sync/2",
        "result-bytes",
        "native-to-javascript",
        "return",
        "bytes",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_module_sync_callback",
      ),
      callbackOutput(
        "callback:module-sync/3",
        "result-length",
        "native-to-javascript",
        "return",
        "number",
        "src/engine/hermes_runtime_ios.cc#ex_hermes_set_module_sync_callback",
      ),
    ],
    fixedEvidence(
      "public-abi",
      "src/engine/hermes_runtime_ios.cc",
      "ex_hermes_set_module_sync_callback",
    ),
  ),
  fixedCallbackOutputSurface(
    "worklet-measure",
    [
      callbackOutput(
        "callback:measure/0",
        "node-id",
        "javascript-to-native",
        "payload",
        "number",
        "src/engine/hermes_runtime_worklet.cc#ex_worklet_set_measure_callback",
      ),
      callbackOutput(
        "callback:measure/return",
        "status",
        "native-to-javascript",
        "return",
        "number",
        "src/engine/hermes_runtime_worklet.cc#ex_worklet_set_measure_callback",
      ),
      callbackOutput(
        "callback:measure/1",
        "frame",
        "native-to-javascript",
        "return",
        "float32x4",
        "src/engine/hermes_runtime_worklet.cc#ex_worklet_set_measure_callback",
      ),
    ],
    fixedEvidence(
      "public-abi",
      "src/engine/hermes_runtime_worklet.cc",
      "ex_worklet_set_measure_callback",
    ),
  ),
  fixedCallbackControlSurface(
    "worklet-scheduled-drain",
    fixedEvidence(
      "public-abi",
      "src/engine/hermes_runtime_worklet.cc",
      "ex_worklet_drain_scheduled",
    ),
  ),
  fixedCallbackOutputSurface(
    "android-animation-frame",
    [
      callbackOutput(
        "callback:animation-frame/0",
        "frame-time-milliseconds",
        "native-to-javascript",
        "payload",
        "number",
        "src/engine/hermes_runtime_android.cc#android_animation_frame_callback",
      ),
    ],
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime_android.cc",
      "android_animation_frame_callback",
    ),
  ),
  fixedCallbackOutputSurface(
    "android-platform-event",
    [
      callbackOutput(
        "callback:__exactAndroidDispatchPlatformEvent/0",
        "event-json",
        "native-to-javascript",
        "payload",
        "json-string",
        "src/engine/hermes_runtime_android.cc#dispatchAndroidPlatformEvents",
      ),
      callbackOutput(
        "callback:__exactAndroidDispatchPlatformEvent/1",
        "platform-state",
        "native-to-javascript",
        "payload",
        "object",
        "src/engine/hermes_runtime_android.cc#dispatchAndroidPlatformEvents",
      ),
    ],
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime_android.cc",
      "android_platform_event_available",
    ),
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime_android.cc",
      "dispatchAndroidPlatformEvents",
    ),
  ),

  // Startup is an authority-bearing route of its own: it constructs surfaces,
  // labels trusted deputies, and closes bootstrap-only escape hatches.
  fixedSurface(
    "startup",
    "runtime-create",
    fixedEvidence(
      "public-abi",
      "src/engine/hermes_runtime.cc",
      "ex_hermes_create_armed",
    ),
  ),
  fixedSurface(
    "startup",
    "globals-install",
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_runtime.cc",
      "installGlobals",
    ),
  ),
  fixedSurface(
    "startup",
    "module-loader-install",
    implementationContainer(
      "cpp-function",
      "src/engine/hermes_bootstrap.cc",
      "installModuleLoader",
    ),
  ),
  fixedSurface(
    "startup",
    "shared-runtime-install",
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_bootstrap.cc",
      "installSharedRuntimeBundle",
    ),
  ),
  fixedSurface(
    "startup",
    "legacy-lazy-bootstrap",
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_bootstrap.cc",
      "installLegacyLazyBootstrapGetters",
    ),
  ),
  fixedSurface(
    "startup",
    "legacy-process-compat",
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_bootstrap.cc",
      "runLegacyProcessCompatFix",
    ),
  ),
  fixedSurface(
    "startup",
    "capability-hardening-seal",
    fixedEvidence(
      "cpp-data",
      "src/engine/hermes_runtime.cc",
      "kCapabilityHardeningJS",
    ),
  ),
  fixedSurface(
    "startup",
    "eager-native-seal",
    fixedEvidence(
      "cpp-data",
      "src/engine/hermes_runtime.cc",
      "kEagerInstallSealJS",
    ),
  ),
  fixedSurface(
    "startup",
    "lockdown-install",
    fixedEvidence("cpp-data", "src/engine/hermes_runtime.cc", "lockdownJS"),
  ),
  fixedSurface(
    "startup",
    "freeze-seal",
    fixedEvidence("cpp-data", "src/engine/hermes_runtime.cc", "kFreezeSealJS"),
  ),
  fixedSurface(
    "startup",
    "compartment-registry-install",
    fixedEvidence(
      "cpp-data",
      "src/engine/hermes_runtime.cc",
      "kCompartmentRegistryJS",
    ),
  ),
  // Supervisor-owned REPL history. These are deliberately fixed source
  // surfaces: no JavaScript callable or host locator exposes the storage
  // route, but every filesystem/environment effect must still join the
  // CapSec classifier and policy registry.
  fixedSurface(
    "startup",
    "supervisor-history.project-platform-data-root",
    fixedEvidence(
      "rust-function",
      "src/bin/ibex/history.rs",
      "capture_project_history_platform_data_root",
    ),
  ),
  fixedSurface(
    "startup",
    "supervisor-history.global-platform-data-root",
    fixedEvidence(
      "rust-function",
      "src/bin/ibex/history.rs",
      "capture_global_history_platform_data_root",
    ),
  ),
  fixedSurface(
    "startup",
    "supervisor-history.authenticated-project-scope",
    fixedEvidence(
      "rust-function",
      "src/bin/ibex/history.rs",
      "derive_authenticated_project_history_scope",
    ),
  ),
  fixedSurface(
    "startup",
    "supervisor-history.store-open",
    fixedEvidence(
      "rust-function",
      "src/bin/ibex/history.rs",
      "open_history_store",
    ),
  ),
  fixedSurface(
    "startup",
    "supervisor-history.legacy-probe",
    fixedEvidence(
      "rust-function",
      "src/bin/ibex/history.rs",
      "legacy_history_present",
    ),
  ),
  fixedSurface(
    "startup",
    "supervisor-history.user-key-read-create",
    fixedEvidence(
      "rust-function",
      "src/bin/ibex/history.rs",
      "load_or_create_history_user_key",
    ),
  ),
  fixedSurface(
    "startup",
    "supervisor-history.sidecar-lock-acquire",
    fixedEvidence(
      "rust-function",
      "src/bin/ibex/history.rs",
      "acquire_history_sidecar_lock",
    ),
  ),
  fixedSurface(
    "startup",
    "supervisor-history.journal-recover",
    fixedEvidence(
      "rust-function",
      "src/bin/ibex/history.rs",
      "recover_history_journal_locked",
    ),
  ),
  fixedSurface(
    "startup",
    "supervisor-history.journal-append",
    fixedEvidence(
      "rust-function",
      "src/bin/ibex/history.rs",
      "append_history_journal",
    ),
  ),
  fixedSurface(
    "startup",
    "supervisor-history.journal-compact",
    fixedEvidence(
      "rust-function",
      "src/bin/ibex/history.rs",
      "compact_history_journal_locked",
    ),
  ),
  fixedSurface(
    "startup",
    "web-streams-install",
    fixedEvidence(
      "cpp-function",
      "src/engine/hermes_bootstrap.cc",
      "installWebStreamsPolyfill",
    ),
  ),
  fixedSurface(
    "startup",
    "scheduler-principal-capture",
    fixedEvidence(
      "cpp-call",
      "src/engine/hermes_runtime.cc",
      "ex_hermes_vm_set_job_scheduler_capture",
    ),
  ),
];

const INSPECTOR_SYMBOLS = [
  "ex_hermes_debugger_enable",
  "ex_hermes_debugger_get_scripts",
  "ex_hermes_debugger_get_script_source",
  "ex_hermes_debugger_set_breakpoint",
  "ex_hermes_debugger_remove_breakpoint",
  "ex_hermes_debugger_pause",
  "ex_hermes_debugger_resume",
  "ex_hermes_debugger_next_event",
  "ex_hermes_debugger_eval",
];

for (const symbol of INSPECTOR_SYMBOLS) {
  FIXED_RUNTIME_SURFACE_DEFINITIONS.push(
    fixedSurface(
      "native-op",
      `inspector.debugger-${symbol.slice("ex_hermes_debugger_".length).replaceAll("_", "-")}`,
      fixedEvidence(
        "public-abi",
        "src/engine/hermes_runtime_debugger.cc",
        symbol,
      ),
      fixedEvidence(
        "public-abi",
        "src/engine/hermes_runtime_platform_windows.cc",
        symbol,
      ),
    ),
  );
}

function canonicalFixedEvidence(evidence, label) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    throw new Error(`${label}: fixed evidence must be an object`);
  }
  const { type, file, symbol, role } = evidence;
  if (!FIXED_EVIDENCE_TYPES.has(type)) {
    throw new Error(
      `${label}: unknown fixed evidence type ${JSON.stringify(type)}`,
    );
  }
  if (!FIXED_EVIDENCE_ROLES.has(role)) {
    throw new Error(
      `${label}: unknown fixed evidence role ${JSON.stringify(role)}`,
    );
  }
  if (
    typeof file !== "string" ||
    file.length === 0 ||
    file.includes("\\") ||
    file.includes("#") ||
    path.posix.isAbsolute(file) ||
    /^[A-Za-z]:/u.test(file) ||
    path.posix.normalize(file) !== file ||
    file === "." ||
    file.startsWith("../") ||
    file.includes("/../") ||
    file.includes("/./")
  ) {
    throw new Error(
      `${label}: non-canonical fixed evidence path ${JSON.stringify(file)}`,
    );
  }
  if (
    typeof symbol !== "string" ||
    !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(symbol)
  ) {
    throw new Error(
      `${label}: invalid fixed evidence symbol ${JSON.stringify(symbol)}`,
    );
  }
  return { type, file, symbol, role, sourceRef: sourceSymbol(file, symbol) };
}

const CALLBACK_OUTPUT_DIRECTIONS = new Set([
  "javascript-to-native",
  "native-to-javascript",
]);
const CALLBACK_OUTPUT_ROLES = new Set(["error", "payload", "return"]);
const CALLBACK_OUTPUT_VALUE_SHAPES = new Set([
  "array-buffer",
  "boolean",
  "bytes",
  "error",
  "float32x4",
  "json-string",
  "json-value",
  "null",
  "number",
  "object",
  "string",
  "uint8-array",
  "undefined",
]);

function canonicalFixedCallbackOutputContracts(definition, observedKey) {
  const contracts = definition.callbackOutputContracts;
  if (contracts === undefined) return undefined;
  if (definition.kind !== "callback") {
    throw new Error(
      `${observedKey}: callbackOutputContracts require callback kind`,
    );
  }
  if (!Array.isArray(contracts) || contracts.length === 0) {
    throw new Error(
      `${observedKey}: callbackOutputContracts must be a non-empty array`,
    );
  }
  const keys = new Set();
  return contracts.map((contract, index) => {
    const label = `${observedKey}.callbackOutputContracts[${index}]`;
    assertExactObjectKeys(
      contract,
      new Set([
        "direction",
        "returnVariant",
        "role",
        "selector",
        "sourceRefs",
        "valueShape",
      ]),
      label,
    );
    if (
      Object.keys(contract).length !== 6 ||
      typeof contract.selector !== "string" ||
      !/^callback:[A-Za-z_$][A-Za-z0-9_$-]*\/(?:[0-9]+|return)$/u.test(
        contract.selector,
      ) ||
      typeof contract.returnVariant !== "string" ||
      !/^[a-z][a-z0-9-]*$/u.test(contract.returnVariant) ||
      !CALLBACK_OUTPUT_DIRECTIONS.has(contract.direction) ||
      !CALLBACK_OUTPUT_ROLES.has(contract.role) ||
      !CALLBACK_OUTPUT_VALUE_SHAPES.has(contract.valueShape) ||
      !Array.isArray(contract.sourceRefs) ||
      contract.sourceRefs.length === 0 ||
      contract.sourceRefs.some(
        (sourceRef) =>
          typeof sourceRef !== "string" ||
          !/^[^#]+#[A-Za-z_$][A-Za-z0-9_$]*$/u.test(sourceRef),
      ) ||
      JSON.stringify(contract.sourceRefs) !==
        JSON.stringify(uniqueSorted(contract.sourceRefs))
    ) {
      throw new Error(`${label}: malformed callback output contract`);
    }
    const key = `${contract.selector}\0${contract.returnVariant}`;
    if (keys.has(key)) {
      throw new Error(
        `${observedKey}: duplicate callback output ${contract.selector}:${contract.returnVariant}`,
      );
    }
    keys.add(key);
    return structuredClone(contract);
  });
}

function canonicalFixedDefinitions(definitions) {
  if (!Array.isArray(definitions) || definitions.length === 0) {
    throw new Error(
      "fixed runtime surface definitions must be a non-empty array",
    );
  }
  const normalized = [];
  const observedKeys = new Set();
  const evidenceUses = new Map();

  for (const definition of definitions) {
    if (
      !definition ||
      typeof definition !== "object" ||
      Array.isArray(definition)
    ) {
      throw new Error("fixed runtime surface definition must be an object");
    }
    const { kind, name } = definition;
    const observedKey = `${kind}:${name}`;
    if (
      !COVERAGE_KINDS.has(kind) ||
      typeof name !== "string" ||
      name.length === 0
    ) {
      throw new Error(
        `${observedKey}: malformed fixed runtime surface definition`,
      );
    }
    const callbackOutputBoundary = definition.callbackOutputBoundary;
    if (
      callbackOutputBoundary !== undefined &&
      (kind !== "callback" || callbackOutputBoundary !== "none")
    ) {
      throw new Error(
        `${observedKey}: invalid callbackOutputBoundary ${JSON.stringify(callbackOutputBoundary)}`,
      );
    }
    const callbackOutputContracts = canonicalFixedCallbackOutputContracts(
      definition,
      observedKey,
    );
    if (
      callbackOutputBoundary !== undefined &&
      callbackOutputContracts !== undefined
    ) {
      throw new Error(
        `${observedKey}: callback output boundary and contracts are mutually exclusive`,
      );
    }
    if (observedKeys.has(observedKey)) {
      throw new Error(
        `fixed runtime surface inventory: duplicate observed key ${observedKey}`,
      );
    }
    observedKeys.add(observedKey);
    if (
      !Array.isArray(definition.evidence) ||
      definition.evidence.length === 0
    ) {
      throw new Error(
        `${observedKey}: fixed runtime surface has no structural evidence`,
      );
    }
    const evidence = definition.evidence.map((row, index) =>
      canonicalFixedEvidence(row, `${observedKey}.evidence[${index}]`),
    );
    const evidenceKeys = new Set();
    const evidenceRefs = new Set();
    for (const row of evidence) {
      const evidenceKey = `${row.type}\0${row.sourceRef}`;
      if (evidenceKeys.has(evidenceKey)) {
        throw new Error(
          `${observedKey}: duplicate fixed evidence ${row.type}:${row.sourceRef}`,
        );
      }
      evidenceKeys.add(evidenceKey);
      evidenceRefs.add(row.sourceRef);
      const uses = evidenceUses.get(row.sourceRef) ?? [];
      uses.push({ observedKey, role: row.role });
      evidenceUses.set(row.sourceRef, uses);
    }
    for (const [contractIndex, contract] of (
      callbackOutputContracts ?? []
    ).entries()) {
      for (const sourceRef of contract.sourceRefs) {
        if (!evidenceRefs.has(sourceRef)) {
          throw new Error(
            `${observedKey}.callbackOutputContracts[${contractIndex}]: source ref ${sourceRef} is not validated fixed evidence`,
          );
        }
      }
    }
    normalized.push({
      kind,
      name,
      observedKey,
      evidence,
      ...(callbackOutputBoundary === undefined
        ? {}
        : { callbackOutputBoundary }),
      ...(callbackOutputContracts === undefined
        ? {}
        : { callbackOutputContracts }),
    });
  }

  for (const [sourceRef, uses] of evidenceUses) {
    const distinctSurfaces = new Set(uses.map((use) => use.observedKey));
    const shared = distinctSurfaces.size > 1;
    for (const use of uses) {
      if (shared && use.role !== "implementation-container") {
        throw new Error(
          `${sourceRef}: shared fixed evidence for ${[...distinctSurfaces].sort(compareText).join(", ")} must use role implementation-container`,
        );
      }
      if (!shared && use.role === "implementation-container") {
        throw new Error(
          `${sourceRef}: implementation-container evidence is not shared by multiple fixed surfaces`,
        );
      }
    }
  }

  return normalized;
}

/** Return fresh rows so callers cannot mutate the module-level fixed inventory. */
export function fixedRuntimeSurfaceInventory(
  definitions = FIXED_RUNTIME_SURFACE_DEFINITIONS,
) {
  const rows = canonicalFixedDefinitions(definitions).map((definition) =>
    makeSurface(
      definition.kind,
      definition.name,
      definition.evidence.map((evidence) => evidence.sourceRef),
      {
        metadata:
          definition.callbackOutputBoundary !== undefined
            ? {
                callbackOutputBoundary: definition.callbackOutputBoundary,
              }
            : definition.callbackOutputContracts !== undefined
              ? {
                  callbackOutputContractSchema: CALLBACK_OUTPUT_CONTRACT_SCHEMA,
                  callbackOutputContracts: structuredClone(
                    definition.callbackOutputContracts,
                  ),
                }
              : undefined,
      },
    ),
  );
  assertUniqueObservedKeys(rows, "fixed runtime surface inventory");
  return sortSurfaces(rows);
}

export function validateFixedRuntimeSurfaceRefs(
  repoRoot,
  surfaces,
  definitions = FIXED_RUNTIME_SURFACE_DEFINITIONS,
) {
  const normalizedDefinitions = canonicalFixedDefinitions(definitions);
  assertUniqueObservedKeys(surfaces, "fixed runtime surface validation input");
  const surfacesByKey = new Map(
    surfaces.map((surface) => [surface.observedKey, surface]),
  );
  if (surfacesByKey.size !== normalizedDefinitions.length) {
    throw new Error(
      `fixed runtime surface validation input has ${surfacesByKey.size} rows; expected ${normalizedDefinitions.length}`,
    );
  }

  const rootPath = fs.realpathSync(repoRoot);
  const candidateCache = new Map();
  for (const definition of normalizedDefinitions) {
    const surface = surfacesByKey.get(definition.observedKey);
    if (!surface) {
      throw new Error(
        `${definition.observedKey}: fixed runtime surface is missing`,
      );
    }
    const expectedRefs = uniqueSorted(
      definition.evidence.map((evidence) => evidence.sourceRef),
    );
    if (JSON.stringify(surface.sourceRefs) !== JSON.stringify(expectedRefs)) {
      throw new Error(
        `${definition.observedKey}: fixed source refs do not match typed evidence`,
      );
    }

    for (const evidence of definition.evidence) {
      let candidates = candidateCache.get(evidence.file);
      if (!candidates) {
        const lexicalPath = path.resolve(rootPath, ...evidence.file.split("/"));
        if (
          lexicalPath !== rootPath &&
          !lexicalPath.startsWith(`${rootPath}${path.sep}`)
        ) {
          throw new Error(
            `${evidence.sourceRef}: fixed evidence escapes repository root`,
          );
        }
        const realPath = fs.realpathSync(lexicalPath);
        if (
          realPath !== rootPath &&
          !realPath.startsWith(`${rootPath}${path.sep}`)
        ) {
          throw new Error(
            `${evidence.sourceRef}: fixed evidence resolves outside repository root`,
          );
        }
        const canonicalRelative = posixPath(path.relative(rootPath, realPath));
        if (canonicalRelative !== evidence.file) {
          throw new Error(
            `${evidence.sourceRef}: fixed evidence path is not the canonical repository path ${canonicalRelative}`,
          );
        }
        candidates = scanFixedRuntimeEvidenceCandidates(
          readUtf8(realPath),
          evidence.file,
        );
        candidateCache.set(evidence.file, candidates);
      }

      const candidate = candidates.find(
        (row) =>
          row.type === evidence.type && row.sourceRef === evidence.sourceRef,
      );
      if (!candidate) {
        const observedTypes = uniqueSorted(
          candidates
            .filter((row) => row.sourceRef === evidence.sourceRef)
            .map((row) => row.type),
        );
        throw new Error(
          `${evidence.sourceRef}: expected structural ${evidence.type} definition is absent${observedTypes.length ? `; observed ${observedTypes.join(", ")}` : ""}`,
        );
      }
      if (candidate.occurrenceCount !== 1) {
        throw new Error(
          `${evidence.sourceRef}: expected exactly one structural ${evidence.type} definition; observed ${candidate.occurrenceCount}`,
        );
      }
    }
  }
}

function listFiles(root, predicate) {
  const files = [];
  const visit = (directory) => {
    const entries = fs
      .readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => compareText(left.name, right.name));
    for (const entry of entries) {
      const filePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(filePath);
      } else if (entry.isFile() && predicate(filePath)) {
        files.push(filePath);
      }
    }
  };
  visit(root);
  return files;
}

function mergePrivateNativeRows(rows) {
  const merged = new Map();
  for (const row of rows) {
    const existing = merged.get(row.observedKey);
    if (!existing) {
      merged.set(row.observedKey, structuredClone(row));
      continue;
    }
    existing.sourceRefs = uniqueSorted([
      ...existing.sourceRefs,
      ...row.sourceRefs,
    ]);
    existing.metadata.occurrenceCount += row.metadata.occurrenceCount;
  }
  return sortSurfaces([...merged.values()]);
}

const SOURCE_ASSERTED_PRIVATE_NATIVE_PROPERTY_BINDINGS = Object.freeze([
  Object.freeze({
    surfaceName: "__exactOSRelease",
    sourcePath: "src/engine/hermes_runtime_android.cc",
    globalName: "process",
    memberName: "__exactOSRelease",
    targetVariant: "android",
    valueToken: "facebook::jsi::String::createFromUtf8(rt, platform_version)",
  }),
  Object.freeze({
    surfaceName: "__exactOSVersion",
    sourcePath: "src/engine/hermes_runtime_android.cc",
    globalName: "process",
    memberName: "__exactOSVersion",
    targetVariant: "android",
    valueToken: "facebook::jsi::String::createFromUtf8(rt, android_os_version)",
  }),
]);

// The generic private-identifier scanner sees the two Android process fields
// only as string tokens. Bind those exact tokens back to the source-proven
// public property reads so output accounting and target-absence evidence do
// not invent a raw callable with the same spelling.
// @ref LLP 0023#6-path-bearing-observables — output membership follows the
// actual public projection and its target branch, not a nearby native token.
function attachPrivateNativePropertyBindings(rows, repoRoot) {
  const byObservedKey = new Map(
    rows.map((row) => [row.observedKey, structuredClone(row)]),
  );
  for (const binding of SOURCE_ASSERTED_PRIVATE_NATIVE_PROPERTY_BINDINGS) {
    const observedKey = `native-op:${binding.surfaceName}`;
    const row = byObservedKey.get(observedKey);
    const privateSourceRef = sourceSymbol(
      binding.sourcePath,
      binding.surfaceName,
    );
    if (
      !row ||
      row.metadata?.occurrenceCount !== 1 ||
      !row.sourceRefs.includes(privateSourceRef)
    ) {
      throw new Error(
        `${observedKey}: expected one source-bound private identifier at ${privateSourceRef}`,
      );
    }

    const source = readUtf8(path.join(repoRoot, binding.sourcePath));
    const functionStart = source.indexOf(
      "void installAndroidEnvironmentGlobals(ExactHermesRuntime* handle) {",
    );
    const functionEnd = source.indexOf(
      "std::free(platform_version);",
      functionStart,
    );
    const propertyLiteral = JSON.stringify(binding.memberName);
    const propertyIndex = source.indexOf(propertyLiteral, functionStart);
    const duplicatePropertyIndex = source.indexOf(
      propertyLiteral,
      propertyIndex + propertyLiteral.length,
    );
    const callStart = source.lastIndexOf("process.setProperty(", propertyIndex);
    const callEnd = source.indexOf(");", propertyIndex);
    const bindingRegion =
      callStart >= 0 && callEnd >= propertyIndex
        ? source.slice(callStart, callEnd + 2)
        : "";
    if (
      functionStart < 0 ||
      functionEnd < functionStart ||
      propertyIndex < functionStart ||
      propertyIndex > functionEnd ||
      (duplicatePropertyIndex >= 0 && duplicatePropertyIndex < functionEnd) ||
      !source
        .slice(functionStart, functionEnd)
        .includes('rt.global().getProperty(rt, "process")') ||
      !source
        .slice(functionStart, functionEnd)
        .includes("auto process = process_value.asObject(rt)") ||
      !bindingRegion.includes(propertyLiteral) ||
      !bindingRegion.includes(binding.valueToken)
    ) {
      throw new Error(
        `${observedKey}: Android process property binding source drift`,
      );
    }

    const exportName = `${binding.globalName}.${binding.memberName}`;
    const bindingSourceRef = sourceSymbol(
      binding.sourcePath,
      `jsi-global-property:${exportName}`,
    );
    const sourceRefs = uniqueSorted([...row.sourceRefs, bindingSourceRef]);
    const branches = [
      makeInstallationBranch(
        "native-jsi-global-property-alias",
        binding.targetVariant,
        sourceRefs,
      ),
    ];
    row.sourceRefs = sourceRefs;
    row.metadata = {
      ...row.metadata,
      branches,
      exportName,
      globalName: binding.globalName,
      installationBranches: branches,
      memberKinds: ["native-object-member"],
      memberName: binding.memberName,
      publicOutputAccess: {
        alias: exportName,
        kind: "property-read",
      },
      publicReadAccessSourceProven: true,
      sourceKey: "native_jsi_global",
      surfaceType: "global-api",
      valueShape: "data",
    };
  }
  return sortSurfaces([...byObservedKey.values()]);
}

function abiTargetVariant(sourceRef) {
  const sourcePath = sourceRef.slice(0, sourceRef.lastIndexOf("#"));
  if (sourcePath.startsWith("src/bin/")) return "binary";
  if (/(?:^|[_/])windows(?:[_.\/]|$)/u.test(sourcePath)) return "windows";
  if (/(?:^|[_/])ios(?:[_.\/]|$)/u.test(sourcePath)) return "ios";
  if (/(?:^|[_/])android(?:[_.\/]|$)/u.test(sourcePath)) return "android";
  return "default";
}

function mergeAbiDefinitionRows(rows) {
  const byName = new Map();
  for (const row of rows) {
    let definitions = byName.get(row.name);
    if (!definitions) {
      definitions = [];
      byName.set(row.name, definitions);
    }
    for (const sourceRef of row.sourceRefs) {
      definitions.push({
        language: row.metadata.language,
        outputContract: structuredClone(row.metadata.outputContract),
        sourceRef,
        targetVariant: abiTargetVariant(sourceRef),
        unsafe: row.metadata.unsafe,
        weak: row.metadata.weak,
      });
    }
  }

  const merged = [];
  for (const [name, definitions] of byName) {
    definitions.sort((left, right) =>
      compareText(left.sourceRef, right.sourceRef),
    );
    for (let leftIndex = 0; leftIndex < definitions.length; leftIndex += 1) {
      for (
        let rightIndex = leftIndex + 1;
        rightIndex < definitions.length;
        rightIndex += 1
      ) {
        const left = definitions[leftIndex];
        const right = definitions[rightIndex];
        if (
          left.targetVariant === right.targetVariant &&
          !left.weak &&
          !right.weak
        ) {
          throw new Error(
            `public ABI inventory: duplicate strong ${left.targetVariant} definition ${name}: ${left.sourceRef}, ${right.sourceRef}`,
          );
        }
      }
    }
    const byTargetVariant = new Map();
    for (const definition of definitions) {
      let variantDefinitions = byTargetVariant.get(definition.targetVariant);
      if (!variantDefinitions) {
        variantDefinitions = [];
        byTargetVariant.set(definition.targetVariant, variantDefinitions);
      }
      variantDefinitions.push(definition);
    }
    const alternatives = byTargetVariant.size > 1;
    const branches = [...byTargetVariant.entries()]
      .sort(([left], [right]) => compareText(left, right))
      .map(([targetVariant, variantDefinitions]) => {
        const sourceRefs = variantDefinitions.map(
          (definition) => definition.sourceRef,
        );
        const allWeak = variantDefinitions.every(
          (definition) => definition.weak,
        );
        const someWeak = variantDefinitions.some(
          (definition) => definition.weak,
        );
        return {
          id: targetVariant,
          kind: alternatives ? "alternative" : "single",
          sourceRefs,
          stubDisposition: allWeak
            ? "weak-fallback"
            : someWeak
              ? "contains-weak-fallback"
              : "not-structurally-proven",
          targetVariant,
        };
      });
    merged.push(
      makeSurface(
        "host-abi",
        name,
        definitions.map((definition) => definition.sourceRef),
        {
          metadata: {
            alternatives: branches,
            branches,
            definitions,
            outputContracts: definitions.map((definition) =>
              structuredClone(definition.outputContract),
            ),
            provenanceLimitation:
              "ABI definitions are source-structural evidence; supported/unsupported target semantics require fixtures.",
          },
        },
      ),
    );
  }
  return sortSurfaces(merged);
}

const JVM_PRIMITIVE_TYPES = new Map([
  ["B", "byte"],
  ["C", "char"],
  ["D", "double"],
  ["F", "float"],
  ["I", "int"],
  ["J", "long"],
  ["S", "short"],
  ["Z", "boolean"],
]);

function parseJvmDescriptorType(descriptor, start, { allowVoid = false } = {}) {
  const marker = descriptor[start];
  if (allowVoid && marker === "V") {
    return { end: start + 1, kind: "void", type: "void" };
  }
  if (JVM_PRIMITIVE_TYPES.has(marker)) {
    return {
      end: start + 1,
      kind: "scalar",
      type: JVM_PRIMITIVE_TYPES.get(marker),
    };
  }
  if (marker === "L") {
    const end = descriptor.indexOf(";", start + 1);
    if (end === -1) return null;
    return {
      end: end + 1,
      kind: "aggregate",
      type: descriptor.slice(start, end + 1),
    };
  }
  if (marker === "[") {
    const element = parseJvmDescriptorType(descriptor, start + 1);
    if (!element) return null;
    return {
      end: element.end,
      kind: "aggregate",
      type: descriptor.slice(start, element.end),
    };
  }
  return null;
}

function parseJvmMethodDescriptor(descriptor) {
  if (typeof descriptor !== "string" || descriptor[0] !== "(") return null;
  const parameters = [];
  let cursor = 1;
  while (cursor < descriptor.length && descriptor[cursor] !== ")") {
    const parameter = parseJvmDescriptorType(descriptor, cursor);
    if (!parameter) return null;
    parameters.push(parameter);
    cursor = parameter.end;
  }
  if (descriptor[cursor] !== ")") return null;
  const returnType = parseJvmDescriptorType(descriptor, cursor + 1, {
    allowVoid: true,
  });
  if (!returnType || returnType.end !== descriptor.length) return null;
  return { parameters, returnType };
}

function androidHostAbiOutputContract(row) {
  const descriptor = row.metadata?.cppBinding?.descriptor;
  const descriptorSignature = parseJvmMethodDescriptor(descriptor);
  const javaSignature = row.metadata?.javaSignature;
  if (
    descriptorSignature &&
    (!javaSignature ||
      descriptorSignature.returnType.kind !== javaSignature.returnType?.kind ||
      descriptorSignature.parameters.length !==
        javaSignature.parameters?.length ||
      descriptorSignature.parameters.some(
        (parameter, index) =>
          parameter.kind !== javaSignature.parameters[index]?.kind,
      ))
  ) {
    throw new Error(
      `${row.name}: Java declaration and JNI descriptor disagree on output membership`,
    );
  }
  const parsed = descriptorSignature ?? javaSignature;
  const callback = new Set([
    "java-to-native-callback",
    "provider-interface",
  ]).has(row.metadata?.bridgeRole);
  const parameters = (parsed?.parameters ?? []).map((parameter, index) => ({
    index,
    name: null,
    ownership:
      parameter.kind === "aggregate"
        ? { kind: "managed-reference" }
        : { kind: "not-applicable" },
    pointerDepth: 0,
    role: callback ? "callback-payload" : "input",
    type: { canonical: parameter.type, tokens: [parameter.type] },
    valueKind: parameter.kind,
  }));
  const returnKind = parsed?.returnType.kind ?? "unknown";
  const returnRole =
    returnKind === "void" ? "none" : parsed ? "value" : "unknown";
  const returnOwnership =
    returnKind === "aggregate"
      ? { kind: "managed-reference" }
      : returnKind === "unknown"
        ? { kind: "unknown" }
        : { kind: "not-applicable" };
  const outputChannels = [];
  if (returnRole === "value") {
    outputChannels.push({
      kind: returnKind,
      ownership: structuredClone(returnOwnership),
      role: "return",
      selector: "[[return]]",
    });
  }
  if (callback) {
    for (const parameter of parameters) {
      outputChannels.push({
        kind: parameter.valueKind,
        ownership: structuredClone(parameter.ownership),
        parameter: parameter.index,
        role: "callback-payload",
        selector: `callback:${parameter.index}`,
      });
    }
  }
  const signatureRef = descriptorSignature
    ? row.sourceRefs.find(
        (sourceRef) =>
          sourceRef.includes("#java-call:") ||
          sourceRef.includes("#jni-callback:"),
      )
    : row.sourceRefs.find(
        (sourceRef) =>
          sourceRef.includes("#java:") || sourceRef.includes("#jni:"),
      );
  return {
    bufferLengthPairs: [],
    functionName: row.name,
    language: "java-jni",
    outputChannels,
    parameters,
    return: {
      kind: returnKind,
      ownership: returnOwnership,
      role: returnRole,
      type: {
        canonical: parsed?.returnType.type ?? "unknown",
        tokens: [parsed?.returnType.type ?? "unknown"],
      },
    },
    schema: HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
    signatureDescriptor: descriptorSignature ? descriptor : null,
    sourceRef: signatureRef ?? row.sourceRefs[0],
    sourceRefs: [...row.sourceRefs],
    status: parsed ? "resolved" : "unresolved",
    unresolved: parsed ? [] : ["java-jni-signature-unbound"],
  };
}

function attachAndroidHostAbiOutputContracts(rows) {
  return rows.map((row) => {
    const outputContract = androidHostAbiOutputContract(row);
    return {
      ...row,
      metadata: {
        ...row.metadata,
        outputContract,
        outputContracts: [structuredClone(outputContract)],
      },
    };
  });
}

function assertNonemptyCategories(categories) {
  for (const [name, rows] of Object.entries(categories)) {
    if (!Array.isArray(rows) || rows.length === 0) {
      throw new Error(`repository surface inventory category ${name} is empty`);
    }
  }
}

/**
 * Discover the complete observed input set from a repository checkout.
 * Results are byte-reproducible and contain no filesystem timestamps or
 * line-number references.
 */
export async function discoverRepositorySurfaces(repoRoot) {
  const engineRoot = path.join(repoRoot, "src", "engine");
  const sourceRoot = path.join(repoRoot, "src");
  const compiledStubRoot = path.join(repoRoot, "crates", "compiled-stub", "src");
  const bootstrapRoot = path.join(engineRoot, "bootstrap");
  const embeddingHeaderPath = path.join(repoRoot, "include", "exact_runtime.h");
  const embeddingHeader = readUtf8(embeddingHeaderPath);
  const abiTypeRegistry = scanCppAbiTypeRegistry(
    embeddingHeader,
    "include/exact_runtime.h",
  );
  const nativeFiles = listFiles(
    sourceRoot,
    (candidate) =>
      NATIVE_SOURCE_EXTENSIONS.has(path.extname(candidate)) &&
      // @ref LLP 0022#7-capabilities-principals-and-affordance-parity — the
      // generated disposition projection contains reviewed property spellings;
      // it is verifier data, never independent install/reference evidence.
      path.basename(candidate) !== "root_global_disposition.generated.h",
  );

  const nativeRows = [];
  const nativeGlobalRows = [];
  const lifecycleRows = [];
  const abiRows = [];
  for (const filePath of nativeFiles) {
    const relativePath = posixPath(path.relative(repoRoot, filePath));
    const source = readUtf8(filePath);
    if (filePath.startsWith(`${engineRoot}${path.sep}`)) {
      nativeRows.push(...scanPrivateNativeIdentifiers(source, relativePath));
      nativeGlobalRows.push(
        ...scanCppGlobalPropertySurfaces(source, relativePath),
      );
      nativeGlobalRows.push(
        ...scanEvaluatedCppGlobalScripts(source, relativePath),
      );
      lifecycleRows.push(...scanNativeLifecycleSurfaces(source, relativePath));
    }
    abiRows.push(
      ...scanCppPublicAbiDefinitions(source, relativePath, {
        typeRegistry: abiTypeRegistry,
      }),
    );
  }

  for (const filePath of listFiles(
    sourceRoot,
    (candidate) => path.extname(candidate) === ".rs",
  )) {
    const relativePath = posixPath(path.relative(repoRoot, filePath));
    abiRows.push(
      ...scanRustPublicAbiDefinitions(readUtf8(filePath), relativePath),
    );
  }
  const androidJavaPath =
    "platform/android/java/dev/ibex/runtime/IbexNetworking.java";
  const androidCppPath = "src/engine/native_android_networking.cc";
  const androidJavaRows = scanAndroidJavaBridgeSurfaces(
    readUtf8(path.join(repoRoot, androidJavaPath)),
    androidJavaPath,
  );
  const androidBindings = scanAndroidCppBridgeBindings(
    readUtf8(path.join(repoRoot, androidCppPath)),
    androidCppPath,
  );
  const hostAbi = sortSurfaces([
    ...mergeAbiDefinitionRows(abiRows),
    ...attachAndroidHostAbiOutputContracts(
      joinAndroidBridgeImplementationRefs(
        androidJavaRows,
        androidBindings,
        androidCppPath,
      ),
    ),
  ]);
  assertUniqueObservedKeys(
    hostAbi,
    "public host/engine/worklet/Android ABI inventory",
  );
  const declaredEmbeddingAbi = scanCppPublicAbiDeclarations(
    embeddingHeader,
    "include/exact_runtime.h",
  ).filter((name) => /^(?:ex_android_|ex_hermes_|ex_worklet_)/u.test(name));
  const definedEmbeddingAbi = hostAbi
    .map((row) => row.name)
    .filter((name) => /^(?:ex_android_|ex_hermes_|ex_worklet_)/u.test(name));
  if (
    JSON.stringify(declaredEmbeddingAbi) !== JSON.stringify(definedEmbeddingAbi)
  ) {
    const declared = new Set(declaredEmbeddingAbi);
    const defined = new Set(definedEmbeddingAbi);
    throw new Error(
      `embedding ABI declaration/definition drift: declarations without definitions [${declaredEmbeddingAbi.filter((name) => !defined.has(name)).join(", ")}]; definitions without declarations [${definedEmbeddingAbi.filter((name) => !declared.has(name)).join(", ")}]`,
    );
  }

  const builtins = await scanBuiltinSurfaces(
    path.join(repoRoot, "modules.ts"),
    repoRoot,
    "modules.ts",
  );
  const runtimeSurfaceSource = readUtf8(
    path.join(repoRoot, "runtime-surface.json"),
  );
  const fixed = fixedRuntimeSurfaceInventory();
  const cli = mergeSurfaceEvidence(
    [
      ...fixed.filter((row) => row.kind === "cli"),
      ...scanRuntimeCliSurfaces(runtimeSurfaceSource, "runtime-surface.json"),
      ...scanRuntimeReplSurfaces(runtimeSurfaceSource, "runtime-surface.json"),
    ],
    "runtime CLI and REPL surface inventory",
  );
  assertUniqueObservedKeys(cli, "runtime CLI and REPL surface inventory");

  const globalRows = [
    ...scanSharedRuntimeGlobalSurfaces(repoRoot),
    ...nativeGlobalRows,
  ];
  const legacyEvaluatorInstallations =
    scanLegacyEvaluatorBootstrapInstallations(
      readUtf8(path.join(engineRoot, "hermes_bootstrap.cc")),
      "src/engine/hermes_bootstrap.cc",
    );
  for (const filePath of listFiles(
    bootstrapRoot,
    (candidate) => path.extname(candidate) === ".js",
  )) {
    const relativePath = posixPath(path.relative(repoRoot, filePath));
    globalRows.push(
      ...scanStaticGlobalApiSurfaces(readUtf8(filePath), relativePath, {
        evaluatorInstallation:
          legacyEvaluatorInstallations[path.basename(filePath)],
      }),
    );
  }
  const hermesEvaluatorProfiles =
    discoverHermesEvaluatorIdentityProfiles(repoRoot);
  globalRows.push(
    ...scanLockdownEvaluatorSurfaces(
      readUtf8(path.join(engineRoot, "hermes_runtime.cc")),
      "src/engine/hermes_runtime.cc",
      hermesEvaluatorProfiles,
    ),
  );
  const globals = mergeSurfaceEvidence(
    globalRows,
    "bootstrap global API inventory",
  );
  const nativeOps = mergeSurfaceEvidence(
    [
      ...globals,
      ...attachPrivateNativePropertyBindings(
        mergePrivateNativeRows(nativeRows),
        repoRoot,
      ),
      ...discoverNativeNetworkingBackendSurfaces(repoRoot),
    ],
    "native and global operation inventory",
  );

  validateFixedRuntimeSurfaceRefs(repoRoot, fixed);
  const environmentSourceAllowed = (filePath) =>
    isRuntimeEnvironmentSourceAllowed(
      posixPath(path.relative(repoRoot, filePath)),
    );
  const environmentJavaScriptFiles = [
    ...listFiles(
      bootstrapRoot,
      (candidate) => path.extname(candidate) === ".js",
    ),
    ...listFiles(
      path.join(sourceRoot, "builtins"),
      (candidate) => path.extname(candidate) === ".js",
    ),
    ...listFiles(
      path.join(repoRoot, "packages", "ibex-runtime-js", "src"),
      (candidate) =>
        new Set([".js", ".jsx", ".ts", ".tsx"]).has(path.extname(candidate)),
    ),
  ].filter(environmentSourceAllowed);
  const environmentRows = scanRuntimeEnvironmentSurfaces({
    javascript: environmentJavaScriptFiles.map((filePath) => ({
      sourcePath: posixPath(path.relative(repoRoot, filePath)),
      text: readUtf8(filePath),
    })),
    // nativeFiles already carries the shared production native extension
    // authority, including headers where inline runtime reads can live.
    native: nativeFiles
      .filter(environmentSourceAllowed)
      .map((filePath) => ({
        sourcePath: posixPath(path.relative(repoRoot, filePath)),
        text: readUtf8(filePath),
      })),
    rust: [
      ...listFiles(
        sourceRoot,
        (candidate) => path.extname(candidate) === ".rs",
      ),
      ...listFiles(
        compiledStubRoot,
        (candidate) => path.extname(candidate) === ".rs",
      ),
    ]
      .filter(environmentSourceAllowed)
      .map((filePath) => ({
        sourcePath: posixPath(path.relative(repoRoot, filePath)),
        text: readUtf8(filePath),
      })),
  });
  const loader = mergeSurfaceEvidence(
    [
      ...fixed.filter((row) => row.kind === "loader"),
      ...scanJavaScriptLoaderSurfaces(
        readUtf8(path.join(bootstrapRoot, "module-loader.js")),
        "src/engine/bootstrap/module-loader.js",
      ),
      ...scanJavaScriptLoaderRoutes(
        readUtf8(path.join(bootstrapRoot, "module-loader.js")),
        "src/engine/bootstrap/module-loader.js",
      ),
      ...scanRustLoaderSurfaces(
        readUtf8(path.join(repoRoot, "src", "module_loader", "mod.rs")),
        "src/module_loader/mod.rs",
      ),
      ...scanRustLoaderSurfaces(
        readUtf8(path.join(repoRoot, "src", "module_loader", "transpile.rs")),
        "src/module_loader/transpile.rs",
        { publicOnly: true },
      ),
      ...scanRustLoaderRoutes([
        {
          sourcePath: "src/module_loader/mod.rs",
          text: readUtf8(path.join(repoRoot, "src", "module_loader", "mod.rs")),
        },
        {
          sourcePath: "src/module_loader/transpile.rs",
          text: readUtf8(
            path.join(repoRoot, "src", "module_loader", "transpile.rs"),
          ),
        },
      ]),
    ],
    "loader source inventory",
  );
  const callbacks = mergeSurfaceEvidence(
    [
      ...fixed.filter((row) => row.kind === "callback"),
      ...lifecycleRows.filter((row) => row.kind === "callback"),
    ],
    "callback source inventory",
  );
  const startup = mergeSurfaceEvidence(
    [
      ...fixed.filter((row) => row.kind === "startup"),
      ...lifecycleRows.filter((row) => row.kind === "startup"),
      scanPrivateSessionWorkerBootstrap(
        readUtf8(
          path.join(repoRoot, "src", "bin", "ibex", "session_worker.rs"),
        ),
      ),
      ...environmentRows,
    ],
    "startup source inventory",
  );
  const inspector = mergeSurfaceEvidence(
    [
      ...fixed.filter(
        (row) => row.kind === "native-op" && row.name.startsWith("inspector."),
      ),
      ...scanCdpSurfaces(
        readUtf8(path.join(repoRoot, "src", "bin", "ibex", "cdp", "mod.rs")),
        "src/bin/ibex/cdp/mod.rs",
      ),
    ],
    "inspector route inventory",
  );
  const routedFixedKeys = new Set(
    [...cli, ...loader, ...callbacks, ...startup, ...inspector]
      .filter((row) =>
        fixed.some((fixedRow) => fixedRow.observedKey === row.observedKey),
      )
      .map((row) => row.observedKey),
  );
  const unroutedFixed = fixed.filter(
    (row) => !routedFixedKeys.has(row.observedKey),
  );
  if (unroutedFixed.length) {
    throw new Error(
      `fixed runtime surfaces are not routed into the repository inventory: ${unroutedFixed
        .map((row) => row.observedKey)
        .join(", ")}`,
    );
  }

  const discoveredLoaderKinds = uniqueSorted(
    loader
      .filter((row) => row.metadata?.evidenceType === "loader-kind-branch")
      .map((row) => row.metadata.loaderKind),
  );
  const expectedLoaderKinds = [
    "builtin",
    "commonjs",
    "esm",
    "json",
    "native-addon",
    "wasm",
  ];
  if (
    JSON.stringify(discoveredLoaderKinds) !==
    JSON.stringify(expectedLoaderKinds)
  ) {
    throw new Error(
      `loader kind inventory drift: expected ${expectedLoaderKinds.join(", ")}, discovered ${discoveredLoaderKinds.join(", ")}`,
    );
  }

  const categories = {
    nativeOps,
    hostAbi,
    builtins,
    globals,
    cli,
    loader,
    callbacks,
    startup,
    inspector,
  };
  assertNonemptyCategories(categories);

  const surfaces = sortSurfaces([
    ...nativeOps,
    ...hostAbi,
    ...builtins,
    ...cli,
    ...loader,
    ...callbacks,
    ...startup,
    ...inspector,
  ]);
  assertUniqueObservedKeys(surfaces, "repository surface inventory");

  return {
    ...categories,
    commands: cli,
    surfaces,
  };
}
