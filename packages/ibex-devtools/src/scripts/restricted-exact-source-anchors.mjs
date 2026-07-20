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
    plugins: ["classProperties", "classPrivateProperties", "classPrivateMethods"],
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

function objectProperty(objectNode, name) {
  if (objectNode?.type !== "ObjectExpression") return null;
  const properties = objectNode.properties.filter(
    (property) => ["ObjectProperty", "ObjectMethod"].includes(property.type)
      && !property.computed
      && propertyName(property.key) === name,
  );
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

function memberProducer(index, ownerName, memberName) {
  const owner = declarationFor(index, ownerName);
  const ownerValue = owner?.value;
  if (ownerValue?.type === "ClassDeclaration" || ownerValue?.type === "ClassExpression") {
    const methods = ownerValue.body.body.filter(
      (method) => ["ClassMethod", "ClassPrivateMethod", "ClassProperty"].includes(method.type)
        && propertyName(method.key) === memberName,
    );
    if (methods.length === 1) return methods[0];
  }
  if (owner?.node?.type === "ClassDeclaration") {
    const methods = owner.node.body.body.filter(
      (method) => ["ClassMethod", "ClassPrivateMethod", "ClassProperty"].includes(method.type)
        && propertyName(method.key) === memberName,
    );
    if (methods.length === 1) return methods[0];
  }
  const assignments = index.assignments.filter(({ segments }) =>
    segments
    && (
      JSON.stringify(segments) === JSON.stringify([ownerName, "prototype", memberName])
      || JSON.stringify(segments) === JSON.stringify([ownerName, memberName])
    )
  );
  return assignments.length === 1 ? assignments[0].node : null;
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
    rootProperty = objectProperty(moduleValue, parts[0]);
    rootValue = rootProperty?.type === "ObjectMethod" ? rootProperty : rootProperty?.value;
    if (!rootProperty) {
      const direct = index.assignments.filter(({ segments }) =>
        JSON.stringify(segments) === JSON.stringify(["module", "exports", parts[0]])
        || JSON.stringify(segments) === JSON.stringify(["exports", parts[0]])
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
    ?? builtinExportBranchBinding({ branch, sourceRef, ...loaded });
  return contextual ?? resolveRestrictedExactSourceBinding(sourceRef, root);
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
