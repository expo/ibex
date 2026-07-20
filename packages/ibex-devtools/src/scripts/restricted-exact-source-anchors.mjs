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
    new RegExp(`(?:^|\\n)[^\\n;{}]*\\b${escaped}\\s*\\([^;{}]*\\)[^;{]*\\{`, "gu"),
  ];
  return patterns.map((pattern) => [...new Set(
    [...text.matchAll(pattern)].map(
      (match) => match.index + (match[0][0] === "\n" ? 1 : 0),
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

function arrayDeclarationRange(text, name) {
  const candidates = [...new Set(declarationCandidateGroups(text, name).flat())]
    .sort((left, right) => left - right);
  if (candidates.length !== 1) return null;
  const startByte = candidates[0];
  const opening = text.indexOf("[", startByte);
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
    }
  });
  const result = { declarations, assignments, modulePublications };
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
  if (preference === "prototype") {
    return prototypeAssignments.length === 1 ? prototypeAssignments[0].node : null;
  }
  if (preference === "static") {
    return staticAssignments.length === 1 ? staticAssignments[0].node : null;
  }
  if (staticAssignments.length === 1) return staticAssignments[0].node;
  return prototypeAssignments.length === 1 ? prototypeAssignments[0].node : null;
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
  if (!sourcePath.startsWith("src/builtins/") || !sourcePath.endsWith(".js")) return null;
  if (!locator.startsWith("exports:") || !branch?.observedKey?.startsWith("builtin:export:")) return null;
  const exportPath = locator.slice("exports:".length);
  if (exportPath.includes("[[") || exportPath.includes("<")) return null;
  const parts = exportPath.split(".");
  const index = javascriptIndex(absolute, text);
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

export function validateRestrictedExactSourceBinding(binding) {
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
    if (binding.producerPaths.length !== 0) {
      throw new Error(`${binding.sourceRef}: provenance-only binding has executable paths`);
    }
    return binding;
  }
  if (binding.producerPaths.length === 0) {
    throw new Error(`${binding.sourceRef}: executable binding lacks producer paths`);
  }
  if (
    binding.resolutionPolicy === "conditioned-alternatives"
    && binding.producerPaths.length < 2
  ) {
    throw new Error(`${binding.sourceRef}: conditioned alternatives require multiple paths`);
  }
  const pathIds = binding.producerPaths.map((producerPath) => producerPath.pathId);
  const conditions = binding.producerPaths.map((producerPath) => producerPath.conditionId);
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
  for (const producerPath of binding.producerPaths) {
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
    if (!roles.includes("publication")) {
      throw new Error(`${binding.sourceRef}: producer path lacks publication site`);
    }
    if (!roles.some((role) => ["definition", "value-producer", "registration"].includes(role))) {
      throw new Error(`${binding.sourceRef}: producer path lacks definition or value producer`);
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
  if (branch.observedKey.startsWith("native-op:global:")) {
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
    for (const entry of entries.filter(({ binding }) => binding.producerPaths.length > 0)) {
      selectedEntries.add(entry);
      producerPaths.push(...entry.binding.producerPaths);
    }
  }
  if (producerPaths.length === 0) {
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
  if (producerPaths.some((producerPath) =>
    producerPath.requiredSiteIds.some((siteId) => !siteIds.has(siteId)))) {
    throw new Error(`${branch.branchId}: producer path references an unselected site`);
  }
  const conditions = producerPaths.map((producerPath) => producerPath.conditionId);
  if (producerPaths.length > 1 && new Set(conditions).size !== conditions.length) {
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
    resolutionPolicy: producerPaths.length > 1 ? "conditioned-alternatives" : "composite-path",
    sites,
    producerPaths,
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
