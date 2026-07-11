/**
 * Discover the concrete native Fetch and WebSocket backend implementations.
 *
 * This module deliberately records implementation provenance only. Capability
 * effects, gates, and target conformance remain the coverage model's job.
 *
 * @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — the
 * source inventory must expose every implementation branch and fail closed on
 * additions that have not been reviewed.
 * @ref LLP 0008#linux-networking — Linux has a supported libcurl profile and
 * an explicit degraded curl-CLI Fetch / unavailable-WebSocket fallback.
 * @ref LLP 0008#android-backend-matrix — Android preserves the native ABI but
 * delegates concrete HTTP and WebSocket work to OkHttp through JNI.
 */

import fs from "node:fs";
import path from "node:path";
import { scanAndroidCppBridgeBindings } from "./capsec-android-bridge-inventory.mjs";

const BACKEND_SOURCE_SPECS = Object.freeze([
  {
    sourcePath: "src/engine/native_fetch_linux.cc",
    family: "fetch",
    targetOperatingSystems: ["linux"],
  },
  {
    sourcePath: "src/engine/native_fetch_macos.mm",
    family: "fetch",
    targetOperatingSystems: ["ios", "macos"],
  },
  {
    sourcePath: "src/engine/native_fetch_windows.cc",
    family: "fetch",
    targetOperatingSystems: ["windows"],
  },
  {
    sourcePath: "src/engine/native_android_networking.cc",
    family: "combined",
    targetOperatingSystems: ["android"],
  },
  {
    sourcePath: "src/engine/native_websocket_linux.cc",
    family: "websocket",
    targetOperatingSystems: ["linux"],
  },
  {
    sourcePath: "src/engine/native_websocket_macos.mm",
    family: "websocket",
    targetOperatingSystems: ["ios", "macos"],
  },
  {
    sourcePath: "src/engine/native_websocket_windows.cc",
    family: "websocket",
    targetOperatingSystems: ["windows"],
  },
]);

const DECLARATION_SOURCE_SPECS = Object.freeze([
  {
    sourcePath: "src/engine/hermes_runtime.cc",
    declarations: [
      "native_fetch_cancel",
      "native_fetch_perform",
      "native_ws_close",
      "native_ws_connect",
      "native_ws_destroy",
      "native_ws_has_active",
      "native_ws_pause",
      "native_ws_release_context",
      "native_ws_resume",
      "native_ws_retain_context",
      "native_ws_send",
      "native_ws_set_flow_controlled",
    ],
    definitions: ["native_ws_release_context", "native_ws_retain_context"],
  },
  {
    sourcePath: "src/engine/hermes_runtime_fetch.cc",
    declarations: ["native_fetch_cancel", "native_fetch_perform"],
    definitions: [],
  },
  {
    sourcePath: "src/engine/hermes_runtime_websocket.cc",
    declarations: [
      "native_ws_close",
      "native_ws_connect",
      "native_ws_pause",
      "native_ws_resume",
      "native_ws_send",
      "native_ws_set_flow_controlled",
    ],
    definitions: [],
  },
]);

const OPERATION_SPECS = Object.freeze([
  { name: "native_fetch_cancel", family: "fetch", operation: "cancel" },
  { name: "native_fetch_perform", family: "fetch", operation: "perform" },
  { name: "native_ws_close", family: "websocket", operation: "close" },
  { name: "native_ws_connect", family: "websocket", operation: "connect" },
  { name: "native_ws_destroy", family: "websocket", operation: "destroy" },
  {
    name: "native_ws_has_active",
    family: "websocket",
    operation: "has-active",
  },
  { name: "native_ws_pause", family: "websocket", operation: "pause" },
  { name: "native_ws_resume", family: "websocket", operation: "resume" },
  { name: "native_ws_send", family: "websocket", operation: "send" },
  {
    name: "native_ws_set_flow_controlled",
    family: "websocket",
    operation: "set-flow-controlled",
  },
]);

const OPERATION_BY_NAME = new Map(
  OPERATION_SPECS.map((spec) => [spec.name, spec]),
);
const PUBLIC_OPERATION_NAMES = new Set(OPERATION_BY_NAME.keys());
const CONTEXT_HELPER_NAMES = new Set([
  "native_ws_release_context",
  "native_ws_retain_context",
]);
const INTERNAL_HELPERS_BY_PATH = new Map([
  ["src/engine/native_fetch_linux.cc", new Set(["native_fetch_perform_async"])],
]);

const ANDROID_STATIC_METHODS = Object.freeze({
  native_fetch_cancel: ["cancelFetch"],
  native_fetch_perform: ["fetch"],
  native_ws_close: ["closeWebSocket"],
  native_ws_connect: ["connectWebSocket"],
  native_ws_destroy: ["closeWebSocket"],
  native_ws_has_active: [],
  native_ws_pause: ["pauseWebSocket"],
  native_ws_resume: ["resumeWebSocket"],
  native_ws_send: ["sendWebSocket"],
  native_ws_set_flow_controlled: ["setWebSocketFlowControlled"],
});

const ANDROID_CALLBACKS = Object.freeze({
  native_fetch_cancel: [],
  native_fetch_perform: ["nativeFetchDidComplete"],
  native_ws_close: ["nativeWebSocketDidClose"],
  native_ws_connect: [
    "nativeWebSocketDidError",
    "nativeWebSocketDidMessage",
    "nativeWebSocketDidOpen",
  ],
  native_ws_destroy: [],
  native_ws_has_active: [],
  native_ws_pause: [],
  native_ws_resume: [],
  native_ws_send: ["nativeWebSocketDidBytesSent"],
  native_ws_set_flow_controlled: [],
});

const BACKEND_FILE_PATTERN =
  /^native_(?:(?:fetch|websocket)_[A-Za-z0-9_]+|android_networking(?:_[A-Za-z0-9_]+)?)\.(?:c|cc|cpp|cxx|m|mm)$/u;
const NETWORK_SYMBOL_PATTERN = /^native_(?:fetch|ws)_[A-Za-z0-9_]+$/u;

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(compareText);
}

function sameStringSet(left, right) {
  return (
    JSON.stringify(uniqueSorted(left)) === JSON.stringify(uniqueSorted(right))
  );
}

function sourceSymbol(sourcePath, symbol) {
  return `${sourcePath}#${symbol}`;
}

function normalizeDirective(text) {
  return text
    .replace(/\\\r?\n/gu, " ")
    .trim()
    .replace(/\s+/gu, " ");
}

/**
 * A deliberately small lexer for C/C++/Objective-C++ and the Rust build file.
 * It preserves identifiers, punctuation, decoded ordinary string contents,
 * and preprocessor directives while excluding comments and literal contents
 * from identifier discovery.
 */
function lexNativeSource(text, sourcePath) {
  const tokens = [];
  let index = 0;
  let lineHasOnlyWhitespace = true;

  const push = (type, value, start, end) => {
    tokens.push({ type, value, start, end });
  };

  while (index < text.length) {
    const start = index;
    const char = text[index];

    if (/\s/u.test(char)) {
      if (char === "\n" || char === "\r") lineHasOnlyWhitespace = true;
      index += 1;
      continue;
    }

    if (char === "/" && text[index + 1] === "/") {
      index += 2;
      while (index < text.length && !/[\r\n]/u.test(text[index])) index += 1;
      continue;
    }

    if (char === "/" && text[index + 1] === "*") {
      const close = text.indexOf("*/", index + 2);
      if (close === -1) {
        throw new Error(`${sourcePath}: unterminated block comment`);
      }
      const body = text.slice(index, close + 2);
      if (/[\r\n]/u.test(body)) lineHasOnlyWhitespace = true;
      index = close + 2;
      continue;
    }

    if (char === "#" && lineHasOnlyWhitespace) {
      index += 1;
      let end = index;
      for (;;) {
        const newline = text.indexOf("\n", end);
        if (newline === -1) {
          end = text.length;
          break;
        }
        let before = newline - 1;
        if (before >= index && text[before] === "\r") before -= 1;
        if (before >= index && text[before] === "\\") {
          end = newline + 1;
          continue;
        }
        end = newline;
        break;
      }
      push("directive", normalizeDirective(text.slice(index, end)), start, end);
      index = end;
      lineHasOnlyWhitespace = true;
      continue;
    }

    const rawPrefix = /^(?:u8|u|U|L)?R"/u.exec(text.slice(index))?.[0];
    if (rawPrefix) {
      const delimiterStart = index + rawPrefix.length;
      const bodyOpen = text.indexOf("(", delimiterStart);
      if (bodyOpen === -1)
        throw new Error(`${sourcePath}: malformed raw string`);
      const delimiter = text.slice(delimiterStart, bodyOpen);
      if (delimiter.length > 16 || /[\s()\\]/u.test(delimiter)) {
        throw new Error(`${sourcePath}: malformed raw string delimiter`);
      }
      const terminator = `)${delimiter}"`;
      const close = text.indexOf(terminator, bodyOpen + 1);
      if (close === -1)
        throw new Error(`${sourcePath}: unterminated raw string`);
      index = close + terminator.length;
      push("string", text.slice(bodyOpen + 1, close), start, index);
      lineHasOnlyWhitespace = false;
      continue;
    }

    if (char === "'" && /[A-Za-z_]/u.test(text[index + 1] ?? "")) {
      let lifetimeEnd = index + 2;
      while (
        lifetimeEnd < text.length &&
        /[A-Za-z0-9_]/u.test(text[lifetimeEnd])
      ) {
        lifetimeEnd += 1;
      }
      if (text[lifetimeEnd] !== "'") {
        push("punctuation", char, start, index + 1);
        index += 1;
        lineHasOnlyWhitespace = false;
        continue;
      }
    }

    if (char === '"' || char === "'") {
      const quote = char;
      let value = "";
      index += 1;
      let closed = false;
      while (index < text.length) {
        if (text[index] === quote) {
          index += 1;
          closed = true;
          break;
        }
        if (text[index] === "\\") {
          index += 1;
          if (index >= text.length) break;
          const escaped = text[index];
          value += escaped === "n" ? "\n" : escaped === "r" ? "\r" : escaped;
          index += 1;
          continue;
        }
        value += text[index];
        index += 1;
      }
      if (!closed) throw new Error(`${sourcePath}: unterminated literal`);
      push(quote === '"' ? "string" : "character", value, start, index);
      lineHasOnlyWhitespace = false;
      continue;
    }

    if (/[A-Za-z_]/u.test(char)) {
      let end = index + 1;
      while (end < text.length && /[A-Za-z0-9_]/u.test(text[end])) end += 1;
      push("identifier", text.slice(index, end), start, end);
      index = end;
      lineHasOnlyWhitespace = false;
      continue;
    }

    const pair = text.slice(index, index + 2);
    if (["::", "->", "==", "!=", "&&", "||", "[[", "]]"].includes(pair)) {
      push("punctuation", pair, start, index + 2);
      index += 2;
    } else {
      push("punctuation", char, start, index + 1);
      index += 1;
    }
    lineHasOnlyWhitespace = false;
  }
  return tokens;
}

function matchingToken(tokens, openIndex, open, close, sourcePath) {
  let depth = 0;
  for (let index = openIndex; index < tokens.length; index += 1) {
    if (tokens[index].value === open) depth += 1;
    if (tokens[index].value === close) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  throw new Error(`${sourcePath}: unmatched ${open}`);
}

function linkageBefore(tokens, nameIndex) {
  let start = nameIndex - 1;
  while (start >= 0) {
    if ([";", "{", "}"].includes(tokens[start].value)) break;
    start -= 1;
  }
  const prefix = tokens.slice(start + 1, nameIndex);
  const externIndex = prefix.findIndex((token) => token.value === "extern");
  const externC =
    externIndex !== -1 &&
    prefix
      .slice(externIndex + 1)
      .some((token) => token.type === "string" && token.value === "C");
  return {
    externC,
    static: prefix.some((token) => token.value === "static"),
  };
}

/**
 * Return top-level native networking declarations and definitions. All
 * prefixed identifiers are returned separately so a new helper/call cannot be
 * hidden merely by using syntax this bounded definition parser does not know.
 */
export function scanNativeNetworkingBackendDefinitions(
  text,
  sourcePath = "<native-network-source>",
) {
  const tokens = lexNativeSource(text, sourcePath);
  const referencedNames = uniqueSorted(
    tokens
      .filter(
        (token) =>
          token.type === "identifier" &&
          NETWORK_SYMBOL_PATTERN.test(token.value),
      )
      .map((token) => token.value),
  );
  const occurrences = [];

  for (let index = 0; index < tokens.length - 1; index += 1) {
    const token = tokens[index];
    if (
      token.type !== "identifier" ||
      !NETWORK_SYMBOL_PATTERN.test(token.value) ||
      tokens[index + 1]?.value !== "("
    ) {
      continue;
    }
    const closeParen = matchingToken(tokens, index + 1, "(", ")", sourcePath);
    let terminator = closeParen + 1;
    while (
      terminator < tokens.length &&
      !["{", ";", "="].includes(tokens[terminator].value)
    ) {
      terminator += 1;
    }
    const linkage = linkageBefore(tokens, index);
    if (!linkage.externC && !linkage.static) continue;
    if (tokens[terminator]?.value === ";" && !linkage.externC) {
      continue;
    }
    if (
      tokens[terminator]?.value !== "{" &&
      tokens[terminator]?.value !== ";"
    ) {
      continue;
    }
    const definition = tokens[terminator].value === "{";
    const bodyClose = definition
      ? matchingToken(tokens, terminator, "{", "}", sourcePath)
      : undefined;
    occurrences.push({
      name: token.value,
      kind: definition ? "definition" : "declaration",
      linkage: linkage.externC
        ? "extern-c"
        : linkage.static
          ? "static"
          : "other",
      sourceRef: sourceSymbol(
        sourcePath,
        `${definition ? "definition" : "declaration"}:${token.value}`,
      ),
      directives: definition
        ? tokens
            .slice(terminator + 1, bodyClose)
            .filter((candidate) => candidate.type === "directive")
            .map((candidate) => candidate.value)
        : [],
    });
    if (definition) index = bodyClose;
    else index = terminator;
  }

  return { occurrences, referencedNames, tokens };
}

function mapEntriesByPath(entries, expectedPaths, label) {
  if (!Array.isArray(entries)) throw new Error(`${label} must be an array`);
  const byPath = new Map();
  for (const entry of entries) {
    if (
      !entry ||
      typeof entry.sourcePath !== "string" ||
      typeof entry.text !== "string"
    ) {
      throw new Error(`${label} contains a malformed source entry`);
    }
    if (byPath.has(entry.sourcePath)) {
      throw new Error(`${label}: duplicate source ${entry.sourcePath}`);
    }
    byPath.set(entry.sourcePath, entry.text);
  }
  const actualPaths = [...byPath.keys()].sort(compareText);
  if (!sameStringSet(actualPaths, expectedPaths)) {
    const expected = new Set(expectedPaths);
    const actual = new Set(actualPaths);
    throw new Error(
      `${label}: source set drift; missing [${expectedPaths
        .filter((item) => !actual.has(item))
        .join(", ")}]; unknown [${actualPaths
        .filter((item) => !expected.has(item))
        .join(", ")}]`,
    );
  }
  return byPath;
}

function occurrencesOfKind(scan, kind) {
  return scan.occurrences.filter((occurrence) => occurrence.kind === kind);
}

function assertExactOccurrenceNames(
  sourcePath,
  occurrences,
  expectedNames,
  kind,
) {
  const names = occurrences.map((occurrence) => occurrence.name);
  if (
    !sameStringSet(names, expectedNames) ||
    names.length !== expectedNames.length
  ) {
    throw new Error(
      `${sourcePath}: ${kind} set drift; expected [${expectedNames.join(", ")}], ` +
        `observed [${names.join(", ")}]`,
    );
  }
}

function validateDeclarationSources(declarationSources) {
  const declarationRefs = new Map(
    OPERATION_SPECS.map((spec) => [spec.name, []]),
  );
  for (const specification of DECLARATION_SOURCE_SPECS) {
    const text = declarationSources.get(specification.sourcePath);
    const scan = scanNativeNetworkingBackendDefinitions(
      text,
      specification.sourcePath,
    );
    const knownNames = new Set([
      ...specification.declarations,
      ...specification.definitions,
      ...CONTEXT_HELPER_NAMES,
    ]);
    const unknownNames = scan.referencedNames.filter(
      (name) => !knownNames.has(name),
    );
    if (unknownNames.length > 0) {
      throw new Error(
        `${specification.sourcePath}: unknown native networking declaration ` +
          `symbol(s) ${unknownNames.join(", ")}`,
      );
    }
    const declarations = occurrencesOfKind(scan, "declaration");
    const definitions = occurrencesOfKind(scan, "definition");
    assertExactOccurrenceNames(
      specification.sourcePath,
      declarations,
      specification.declarations,
      "declaration",
    );
    assertExactOccurrenceNames(
      specification.sourcePath,
      definitions,
      specification.definitions,
      "definition",
    );
    for (const occurrence of declarations) {
      if (occurrence.linkage !== "extern-c") {
        throw new Error(`${occurrence.sourceRef}: declaration is not extern C`);
      }
      if (declarationRefs.has(occurrence.name)) {
        declarationRefs.get(occurrence.name).push(occurrence.sourceRef);
      }
    }
  }
  for (const [name, refs] of declarationRefs) {
    if (refs.length === 0)
      throw new Error(`${name}: no native ABI declaration evidence`);
    declarationRefs.set(name, uniqueSorted(refs));
  }
  return declarationRefs;
}

function expectedDefinitionsForBackend(specification) {
  const names = OPERATION_SPECS.filter(
    (operation) =>
      specification.family === "combined" ||
      operation.family === specification.family,
  ).map((operation) => operation.name);
  names.push(...(INTERNAL_HELPERS_BY_PATH.get(specification.sourcePath) ?? []));
  return names.sort(compareText);
}

function expectedReferencedNamesForBackend(specification) {
  const names = new Set(expectedDefinitionsForBackend(specification));
  if (
    specification.family === "websocket" ||
    specification.family === "combined"
  ) {
    for (const helper of CONTEXT_HELPER_NAMES) names.add(helper);
  }
  return names;
}

function assertSourceMarkers(sourcePath, scan) {
  const identifiers = new Set(
    scan.tokens
      .filter((token) => token.type === "identifier")
      .map((token) => token.value),
  );
  const required =
    sourcePath === "src/engine/native_fetch_linux.cc"
      ? ["curl_easy_perform", "posix_spawnp"]
      : sourcePath === "src/engine/native_websocket_linux.cc"
        ? ["curl_ws_recv"]
        : sourcePath === "src/engine/native_fetch_macos.mm"
          ? ["NSURLSession"]
          : sourcePath === "src/engine/native_websocket_macos.mm"
            ? ["NSURLSessionWebSocketTask"]
            : sourcePath.includes("windows")
              ? ["WinHttpOpen"]
              : sourcePath === "src/engine/native_android_networking.cc"
                ? ["CallStaticVoidMethod", "GetStaticMethodID"]
                : [];
  const missing = required.filter((identifier) => !identifiers.has(identifier));
  if (missing.length > 0) {
    throw new Error(
      `${sourcePath}: backend marker(s) absent: ${missing.join(", ")}`,
    );
  }
}

function validateBackendSources(backendSources) {
  const scans = new Map();
  for (const specification of BACKEND_SOURCE_SPECS) {
    const scan = scanNativeNetworkingBackendDefinitions(
      backendSources.get(specification.sourcePath),
      specification.sourcePath,
    );
    const knownNames = expectedReferencedNamesForBackend(specification);
    const unknownNames = scan.referencedNames.filter(
      (name) => !knownNames.has(name),
    );
    if (unknownNames.length > 0) {
      throw new Error(
        `${specification.sourcePath}: unknown native networking symbol(s) ${unknownNames.join(", ")}`,
      );
    }
    const definitions = occurrencesOfKind(scan, "definition");
    assertExactOccurrenceNames(
      specification.sourcePath,
      definitions,
      expectedDefinitionsForBackend(specification),
      "definition",
    );
    for (const definition of definitions) {
      const isInternal =
        INTERNAL_HELPERS_BY_PATH.get(specification.sourcePath)?.has(
          definition.name,
        ) ?? false;
      const expectedLinkage = isInternal ? "static" : "extern-c";
      if (definition.linkage !== expectedLinkage) {
        throw new Error(
          `${definition.sourceRef}: expected ${expectedLinkage} linkage, observed ${definition.linkage}`,
        );
      }
    }
    const declarations = occurrencesOfKind(scan, "declaration");
    const expectedDeclarations =
      specification.family === "websocket" ||
      specification.family === "combined"
        ? [...CONTEXT_HELPER_NAMES].sort(compareText)
        : [];
    assertExactOccurrenceNames(
      specification.sourcePath,
      declarations,
      expectedDeclarations,
      "declaration",
    );
    assertSourceMarkers(specification.sourcePath, scan);
    scans.set(specification.sourcePath, scan);
  }
  return scans;
}

function collectBuildFileSelections(buildSource) {
  const tokens = lexNativeSource(buildSource.text, buildSource.sourcePath);
  const selections = new Map();
  for (let index = 1; index < tokens.length - 2; index += 1) {
    if (
      tokens[index - 1]?.value !== "." ||
      tokens[index]?.value !== "file" ||
      tokens[index + 1]?.value !== "(" ||
      tokens[index + 2]?.type !== "string"
    ) {
      continue;
    }
    const sourcePath = tokens[index + 2].value;
    if (!BACKEND_FILE_PATTERN.test(path.posix.basename(sourcePath))) {
      continue;
    }
    if (selections.has(sourcePath)) {
      throw new Error(
        `${buildSource.sourcePath}: duplicate backend .file selection ${sourcePath}`,
      );
    }

    const containingTargets = new Set();
    for (let open = 0; open < index; open += 1) {
      if (tokens[open].value !== "{") continue;
      const close = matchingToken(
        tokens,
        open,
        "{",
        "}",
        buildSource.sourcePath,
      );
      if (close < index) continue;
      let headerStart = open - 1;
      while (
        headerStart >= 0 &&
        ![";", "{", "}"].includes(tokens[headerStart].value)
      ) {
        headerStart -= 1;
      }
      const header = tokens.slice(headerStart + 1, open);
      if (!header.some((token) => token.value === "if")) continue;
      for (let candidate = 0; candidate < header.length - 2; candidate += 1) {
        if (
          header[candidate].value === "target_os" &&
          header[candidate + 1]?.value === "==" &&
          header[candidate + 2]?.type === "string"
        ) {
          containingTargets.add(header[candidate + 2].value);
        }
      }
    }
    selections.set(sourcePath, uniqueSorted(containingTargets));
  }
  return selections;
}

function validateBuildSelections(buildSource) {
  if (
    !buildSource ||
    buildSource.sourcePath !== "build.rs" ||
    typeof buildSource.text !== "string"
  ) {
    throw new Error(
      "native backend inventory requires the exact build.rs source",
    );
  }
  const selections = collectBuildFileSelections(buildSource);
  const expectedPaths = BACKEND_SOURCE_SPECS.map(
    (specification) => specification.sourcePath,
  );
  if (!sameStringSet([...selections.keys()], expectedPaths)) {
    throw new Error(
      `${buildSource.sourcePath}: native backend .file selection set drift; observed [${[
        ...selections.keys(),
      ].join(", ")}]`,
    );
  }
  for (const specification of BACKEND_SOURCE_SPECS) {
    const targets = selections.get(specification.sourcePath);
    if (!sameStringSet(targets, specification.targetOperatingSystems)) {
      throw new Error(
        `${buildSource.sourcePath}: ${specification.sourcePath} target selection drift; ` +
          `expected [${specification.targetOperatingSystems.join(", ")}], ` +
          `observed [${targets.join(", ")}]`,
      );
    }
  }
  return selections;
}

function directiveEvidenceForLinux(scan, operationName, sourcePath) {
  const definitionName =
    operationName === "native_fetch_perform"
      ? "native_fetch_perform_async"
      : operationName;
  if (operationName === "native_fetch_cancel") return [];
  const definition = scan.occurrences.find(
    (occurrence) =>
      occurrence.kind === "definition" && occurrence.name === definitionName,
  );
  if (!definition)
    throw new Error(`${sourcePath}: ${definitionName} is absent`);
  const hasCurlBranch = definition.directives.some((directive) =>
    /^(?:if|ifdef)\b.*\bEXACT_HAS_CURL\b/u.test(directive),
  );
  const hasElse = definition.directives.some((directive) =>
    /^else\b/u.test(directive),
  );
  const hasEndif = definition.directives.some((directive) =>
    /^endif\b/u.test(directive),
  );
  if (!hasCurlBranch || !hasElse || !hasEndif) {
    throw new Error(
      `${sourcePath}#${definitionName}: EXACT_HAS_CURL supported/fallback ` +
        "branches are not structurally complete",
    );
  }
  return [
    sourceSymbol(sourcePath, "preprocessor:EXACT_HAS_CURL:defined"),
    sourceSymbol(sourcePath, "preprocessor:EXACT_HAS_CURL:undefined"),
  ];
}

function normalizeAndroidBindings(androidBindings, sourcePath) {
  if (
    !androidBindings ||
    !(androidBindings.staticMethods instanceof Map) ||
    !(androidBindings.nativeCallbacks instanceof Map)
  ) {
    throw new Error(`${sourcePath}: Android C++ JNI bindings are required`);
  }
  for (const methodNames of Object.values(ANDROID_STATIC_METHODS)) {
    for (const methodName of methodNames) {
      if (!androidBindings.staticMethods.has(methodName)) {
        throw new Error(
          `${sourcePath}: Android backend binding ${methodName} is absent`,
        );
      }
    }
  }
  for (const callbackNames of Object.values(ANDROID_CALLBACKS)) {
    for (const callbackName of callbackNames) {
      if (!androidBindings.nativeCallbacks.has(callbackName)) {
        throw new Error(
          `${sourcePath}: Android backend callback ${callbackName} is absent`,
        );
      }
    }
  }
  return androidBindings;
}

function androidBindingRefs(operationName, androidBindings, sourcePath) {
  const refs = [];
  for (const methodName of ANDROID_STATIC_METHODS[operationName]) {
    const binding = androidBindings.staticMethods.get(methodName);
    refs.push(
      sourceSymbol(
        sourcePath,
        `java-call:${methodName}:${binding.functionName}`,
      ),
    );
  }
  for (const callbackName of ANDROID_CALLBACKS[operationName]) {
    const binding = androidBindings.nativeCallbacks.get(callbackName);
    refs.push(
      sourceSymbol(
        sourcePath,
        `jni-callback:${callbackName}:${binding.functionName}`,
      ),
    );
  }
  return refs;
}

function definitionRef(scan, operationName, sourcePath) {
  const definition = scan.occurrences.find(
    (occurrence) =>
      occurrence.kind === "definition" && occurrence.name === operationName,
  );
  if (!definition)
    throw new Error(`${sourcePath}: definition ${operationName} is absent`);
  return definition.sourceRef;
}

function makeBranch({
  id,
  targetVariant,
  backend,
  implementationDisposition,
  sourceRefs,
}) {
  return {
    id,
    kind: "alternative",
    branchKind: "alternative",
    targetVariant,
    backend,
    implementationDisposition,
    sourceRefs: uniqueSorted(sourceRefs),
  };
}

function buildRef(target, sourcePath) {
  return sourceSymbol(
    "build.rs",
    `backend-selection:${target}:${path.posix.basename(sourcePath)}`,
  );
}

function operationBranches(operation, scans, androidBindings) {
  const branches = [];
  for (const specification of BACKEND_SOURCE_SPECS) {
    if (
      specification.family !== "combined" &&
      specification.family !== operation.family
    ) {
      continue;
    }
    const scan = scans.get(specification.sourcePath);
    const baseRefs = [
      definitionRef(scan, operation.name, specification.sourcePath),
    ];

    if (
      specification.sourcePath === "src/engine/native_fetch_linux.cc" &&
      operation.name === "native_fetch_perform"
    ) {
      baseRefs.push(
        definitionRef(
          scan,
          "native_fetch_perform_async",
          specification.sourcePath,
        ),
      );
    }

    if (specification.sourcePath.includes("_linux.")) {
      const conditionRefs = directiveEvidenceForLinux(
        scan,
        operation.name,
        specification.sourcePath,
      );
      branches.push(
        makeBranch({
          id: "linux-libcurl",
          targetVariant: "linux:libcurl",
          backend: "libcurl",
          implementationDisposition: "concrete",
          sourceRefs: [
            ...baseRefs,
            ...conditionRefs.filter((ref) => ref.endsWith(":defined")),
            buildRef("linux", specification.sourcePath),
          ],
        }),
      );
      branches.push(
        makeBranch({
          id: "linux-curl-cli-fallback",
          targetVariant: "linux:curl-cli-fallback",
          backend:
            operation.family === "fetch"
              ? "curl-cli"
              : "unavailable-websocket-stub",
          implementationDisposition:
            operation.family === "fetch"
              ? "degraded-concrete"
              : "unsupported-stub",
          sourceRefs: [
            ...baseRefs,
            ...conditionRefs.filter((ref) => ref.endsWith(":undefined")),
            buildRef("linux", specification.sourcePath),
          ],
        }),
      );
      continue;
    }

    if (specification.sourcePath.includes("_macos.")) {
      for (const target of ["ios", "macos"]) {
        branches.push(
          makeBranch({
            id: `${target}-foundation`,
            targetVariant: target,
            backend: "foundation-urlsession",
            implementationDisposition: "concrete",
            sourceRefs: [
              ...baseRefs,
              buildRef(target, specification.sourcePath),
            ],
          }),
        );
      }
      continue;
    }

    if (specification.sourcePath.includes("_windows.")) {
      branches.push(
        makeBranch({
          id: "windows-winhttp",
          targetVariant: "windows",
          backend: "winhttp",
          implementationDisposition: "concrete",
          sourceRefs: [
            ...baseRefs,
            buildRef("windows", specification.sourcePath),
          ],
        }),
      );
      continue;
    }

    if (
      specification.sourcePath === "src/engine/native_android_networking.cc"
    ) {
      branches.push(
        makeBranch({
          id: "android-okhttp-jni",
          targetVariant: "android",
          backend: "okhttp-jni",
          implementationDisposition: "concrete",
          sourceRefs: [
            ...baseRefs,
            ...androidBindingRefs(
              operation.name,
              androidBindings,
              specification.sourcePath,
            ),
            buildRef("android", specification.sourcePath),
          ],
        }),
      );
    }
  }
  branches.sort((left, right) => compareText(left.id, right.id));
  const expectedIds = [
    "android-okhttp-jni",
    "ios-foundation",
    "linux-curl-cli-fallback",
    "linux-libcurl",
    "macos-foundation",
    "windows-winhttp",
  ];
  if (
    !sameStringSet(
      branches.map((branch) => branch.id),
      expectedIds,
    )
  ) {
    throw new Error(
      `${operation.name}: native backend branch product is incomplete`,
    );
  }
  return branches;
}

/**
 * Pure integration seam used by the repository discovery wrapper and tests.
 * Callers must provide the closed backend/declaration source inventories.
 */
export function scanNativeNetworkingBackendInventory({
  backendSources,
  declarationSources,
  buildSource,
  androidBindings,
}) {
  const backendPaths = BACKEND_SOURCE_SPECS.map(
    (specification) => specification.sourcePath,
  );
  const declarationsPaths = DECLARATION_SOURCE_SPECS.map(
    (specification) => specification.sourcePath,
  );
  const backendByPath = mapEntriesByPath(
    backendSources,
    backendPaths,
    "native backend inventory",
  );
  const declarationByPath = mapEntriesByPath(
    declarationSources,
    declarationsPaths,
    "native backend ABI inventory",
  );
  validateBuildSelections(buildSource);
  const scans = validateBackendSources(backendByPath);
  const declarationRefs = validateDeclarationSources(declarationByPath);
  const normalizedAndroidBindings = normalizeAndroidBindings(
    androidBindings,
    "src/engine/native_android_networking.cc",
  );

  return OPERATION_SPECS.map((operation) => {
    const branches = operationBranches(
      operation,
      scans,
      normalizedAndroidBindings,
    );
    const sourceRefs = uniqueSorted([
      ...declarationRefs.get(operation.name),
      ...branches.flatMap((branch) => branch.sourceRefs),
    ]);
    return {
      kind: "native-op",
      name: operation.name,
      observedKey: `native-op:${operation.name}`,
      sourceRefs,
      metadata: {
        surfaceType: "native-network-backend",
        backendFamily: operation.family,
        operation: operation.operation,
        declarations: declarationRefs.get(operation.name),
        branches,
        provenanceLimitation:
          "Backend definitions and JNI/build selections are source-structural " +
          "inventory evidence; supported target cells still require executed fixtures.",
      },
    };
  }).sort((left, right) => compareText(left.observedKey, right.observedKey));
}

function readUtf8(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function discoverBackendPaths(repoRoot) {
  const engineRoot = path.join(repoRoot, "src", "engine");
  return fs
    .readdirSync(engineRoot, { withFileTypes: true })
    .filter((entry) => entry.isFile() && BACKEND_FILE_PATTERN.test(entry.name))
    .map((entry) => `src/engine/${entry.name}`)
    .sort(compareText);
}

/**
 * Repository-facing integration API. It enumerates the backend directory so a
 * newly added platform file cannot remain invisible to the closed inventory.
 */
export function discoverNativeNetworkingBackendSurfaces(repoRoot) {
  const expectedBackendPaths = BACKEND_SOURCE_SPECS.map(
    (specification) => specification.sourcePath,
  );
  const discoveredBackendPaths = discoverBackendPaths(repoRoot);
  if (!sameStringSet(discoveredBackendPaths, expectedBackendPaths)) {
    const expected = new Set(expectedBackendPaths);
    const discovered = new Set(discoveredBackendPaths);
    throw new Error(
      `native backend file inventory drift; missing [${expectedBackendPaths
        .filter((item) => !discovered.has(item))
        .join(", ")}]; unknown [${discoveredBackendPaths
        .filter((item) => !expected.has(item))
        .join(", ")}]`,
    );
  }

  const backendSources = discoveredBackendPaths.map((sourcePath) => ({
    sourcePath,
    text: readUtf8(path.join(repoRoot, sourcePath)),
  }));
  const declarationSources = DECLARATION_SOURCE_SPECS.map(({ sourcePath }) => ({
    sourcePath,
    text: readUtf8(path.join(repoRoot, sourcePath)),
  }));
  const androidPath = "src/engine/native_android_networking.cc";
  const androidSource = backendSources.find(
    (entry) => entry.sourcePath === androidPath,
  );
  const androidBindings = scanAndroidCppBridgeBindings(
    androidSource.text,
    androidPath,
  );
  return scanNativeNetworkingBackendInventory({
    backendSources,
    declarationSources,
    buildSource: {
      sourcePath: "build.rs",
      text: readUtf8(path.join(repoRoot, "build.rs")),
    },
    androidBindings,
  });
}
