/**
 * Generate and validate LLP 0023's output-disposition dataset.
 *
 * The output-shape catalog is derived from the source inventory and explicit
 * source assertions below. The reviewed policy is a separate input and pins
 * the complete catalog-key digest, so discovering a new output cannot silently
 * inherit `non-path`. Loaded-engine observations are a third input and must
 * join the generated dataset exactly before the evidence state is promotable.
 *
 * @ref LLP 0023#6-path-bearing-observables — output dispositions are total over
 * one canonical seven-part key and are checked against an independent catalog
 * whose surface accounts are exactly equal to the coverage registry.
 * @ref LLP 0021#generated-semantic-datasets — generated semantic datasets are
 * reproducible, digest-bound inputs rather than duplicate runtime matchers.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const OUTPUT_DISPOSITIONS = Object.freeze([
  "absent",
  "closed",
  "non-path",
  "refused",
  "reserved-constant",
  "synthetic-source-id",
  "typed-logical",
  "virtual-absolute",
  "virtual-basename",
  "virtual-relative",
]);

export const OUTPUT_KEY_FIELDS = Object.freeze([
  "surfaceId",
  "output",
  "alias",
  "mode",
  "sourceKind",
  "returnVariant",
  "contextId",
]);

const PROFILE = "ibex/capsec/1";
const CATALOG_DIGEST_DOMAIN = "ibex:capsec:output-shape-catalog-keys:2";

const OUTPUT_EXECUTION_CONTEXTS = Object.freeze({
  "host.private-native-call-initialized": Object.freeze({
    contextId: "host.private-native-call-initialized",
    principalClass: "host",
    accessPhase: "abi-call",
    runtimeState: "initialized",
    targetScope: "candidate-target-cell",
  }),
  "javascript.package-call-loaded": Object.freeze({
    contextId: "javascript.package-call-loaded",
    principalClass: "package",
    accessPhase: "call",
    runtimeState: "loaded",
    targetScope: "candidate-target-cell",
  }),
  "javascript.package-callback-loaded": Object.freeze({
    contextId: "javascript.package-callback-loaded",
    principalClass: "package",
    accessPhase: "callback-delivery",
    runtimeState: "loaded",
    targetScope: "candidate-target-cell",
  }),
  "javascript.package-import-fresh": Object.freeze({
    contextId: "javascript.package-import-fresh",
    principalClass: "package",
    accessPhase: "import",
    runtimeState: "fresh",
    targetScope: "candidate-target-cell",
  }),
  "javascript.package-module-load": Object.freeze({
    contextId: "javascript.package-module-load",
    principalClass: "package",
    accessPhase: "module-load",
    runtimeState: "loaded",
    targetScope: "candidate-target-cell",
  }),
  "javascript.package-property-read-loaded": Object.freeze({
    contextId: "javascript.package-property-read-loaded",
    principalClass: "package",
    accessPhase: "property-read",
    runtimeState: "loaded",
    targetScope: "candidate-target-cell",
  }),
  "runtime.bootstrap-native-call-loaded": Object.freeze({
    contextId: "runtime.bootstrap-native-call-loaded",
    principalClass: "runtime-bootstrap",
    accessPhase: "call",
    runtimeState: "loaded",
    targetScope: "candidate-target-cell",
  }),
});

const LIVE_VALUE_PROOF_KINDS = new Set([
  "compiled-runtime-return-record",
  "loaded-engine-descriptor",
  "loaded-engine-return-record",
]);

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort(compareText)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function taggedDigest(domain, value) {
  const hash = crypto.createHash("sha256");
  hash.update(domain, "utf8");
  hash.update(Buffer.from([0]));
  hash.update(canonicalJson(value), "utf8");
  return `sha256-${hash.digest("base64url")}`;
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label}: expected object`);
  }
  const actual = Object.keys(value).sort(compareText);
  const wanted = [...expected].sort(compareText);
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    throw new Error(
      `${label}: expected exact keys [${wanted.join(", ")}], got [${actual.join(", ")}]`,
    );
  }
}

export function canonicalOutputDispositionKey(key, label = "output key") {
  exactKeys(key, OUTPUT_KEY_FIELDS, label);
  for (const field of OUTPUT_KEY_FIELDS) {
    if (typeof key[field] !== "string" || key[field].length === 0) {
      throw new Error(`${label}.${field}: expected non-empty string`);
    }
  }
  if (!/^surface\.[a-z0-9.]+$/u.test(key.surfaceId)) {
    throw new Error(`${label}.surfaceId: expected a stable surface id`);
  }
  return canonicalJson(OUTPUT_KEY_FIELDS.map((field) => key[field]));
}

/**
 * Select the execution context from source-discovered reachability and value
 * shape. Coverage classification is intentionally absent from this API: the
 * catalog describes which values exist, while policy separately decides how
 * an armed principal may observe them.
 */
export function defaultContextIdForCatalogRow(key, sourceSurface) {
  if (!key || typeof key !== "object" || Array.isArray(key)) {
    throw new Error("catalog row context: expected a key object");
  }
  if (
    key.mode === "private-native" ||
    (key.sourceKind === "host-abi" && key.mode !== "javascript")
  ) {
    return "host.private-native-call-initialized";
  }
  if (key.sourceKind === "host-abi") {
    return "javascript.package-property-read-loaded";
  }
  if (key.output?.startsWith("callback:")) {
    return "javascript.package-callback-loaded";
  }
  if (key.sourceKind === "bridge") {
    return "runtime.bootstrap-native-call-loaded";
  }
  if (sourceSurface?.kind === "startup") {
    return "javascript.package-module-load";
  }
  if (sourceSurface?.kind === "builtin") {
    if (sourceSurface.metadata?.surfaceType !== "export") {
      return "javascript.package-import-fresh";
    }
    return sourceSurface.metadata?.valueShape === "callable"
      ? "javascript.package-call-loaded"
      : "javascript.package-property-read-loaded";
  }
  if (sourceSurface?.kind === "native-op") {
    if (
      sourceSurface.metadata?.publicInvocation?.kind ===
      "native-global-function"
    ) {
      return "runtime.bootstrap-native-call-loaded";
    }
    return sourceSurface.metadata?.valueShape === "callable"
      ? "javascript.package-call-loaded"
      : "javascript.package-property-read-loaded";
  }
  return "javascript.package-call-loaded";
}

export function outputExecutionContextsForRows(rows) {
  const contextIds = [
    ...new Set(
      rows.map((row, index) => {
        const contextId = row?.key?.contextId;
        if (
          typeof contextId !== "string" ||
          !Object.hasOwn(OUTPUT_EXECUTION_CONTEXTS, contextId)
        ) {
          throw new Error(
            `output catalog row ${index}: unknown execution context ${JSON.stringify(contextId)}`,
          );
        }
        return contextId;
      }),
    ),
  ].sort(compareText);
  return contextIds.map((contextId) =>
    structuredClone(OUTPUT_EXECUTION_CONTEXTS[contextId]),
  );
}

export function validateOutputValueProofKind(
  proofKind,
  label = "output value proof",
) {
  if (proofKind === "compiled-registrar") {
    throw new Error(
      `${label}: compiled registrar presence cannot satisfy a value observation`,
    );
  }
  if (!LIVE_VALUE_PROOF_KINDS.has(proofKind)) {
    throw new Error(`${label}: unsupported live value proof kind ${proofKind}`);
  }
  return proofKind;
}

function sortRows(rows) {
  return [...rows].sort((left, right) =>
    compareText(
      canonicalOutputDispositionKey(left.key),
      canonicalOutputDispositionKey(right.key),
    ),
  );
}

function assertUniqueRows(rows, label) {
  const seen = new Set();
  for (const [index, row] of rows.entries()) {
    const key = canonicalOutputDispositionKey(
      row.key,
      `${label}[${index}].key`,
    );
    if (seen.has(key)) {
      throw new Error(`${label}: duplicate canonical output key ${key}`);
    }
    seen.add(key);
  }
}

export function outputShapeCatalogKeyDigest(rows) {
  const keys = sortRows(rows).map((row) =>
    OUTPUT_KEY_FIELDS.map((field) => row.key[field]),
  );
  return taggedDigest(CATALOG_DIGEST_DOMAIN, keys);
}

function sourceAssertion(repoRoot, assertion, label) {
  const filePath = path.join(repoRoot, assertion.path);
  const source = fs.readFileSync(filePath, "utf8");
  for (const token of assertion.tokens) {
    if (!source.includes(token)) {
      throw new Error(
        `${label}: ${assertion.path} lacks token ${JSON.stringify(token)}`,
      );
    }
  }
  return `${assertion.path}#tokens:${assertion.tokens.join("+")}`;
}

function shape(
  output,
  alias,
  { mode = "all", sourceKind = "runtime", returnVariant = "default" } = {},
) {
  return { output, alias, mode, sourceKind, returnVariant };
}

function typedLogicalPathShapes(outputPrefix, aliasPrefix, options) {
  return [
    shape(`${outputPrefix}.schema`, `${aliasPrefix}.schema`, options),
    shape(
      `${outputPrefix}.sessionHandle`,
      `${aliasPrefix}.sessionHandle`,
      options,
    ),
    shape(`${outputPrefix}.virtualPath`, `${aliasPrefix}.virtualPath`, options),
    shape(`${outputPrefix}.logicalPath`, `${aliasPrefix}.logicalPath`, options),
    shape(
      `${outputPrefix}.logicalPath.root`,
      `${aliasPrefix}.logicalPath.root`,
      options,
    ),
    shape(
      `${outputPrefix}.logicalPath.components`,
      `${aliasPrefix}.logicalPath.components`,
      options,
    ),
    shape(
      `${outputPrefix}.logicalPath.components[]`,
      `${aliasPrefix}.logicalPath.components[]`,
      options,
    ),
    shape(
      `${outputPrefix}.logicalPath.components[].encoding`,
      `${aliasPrefix}.logicalPath.components[].encoding`,
      options,
    ),
    shape(
      `${outputPrefix}.logicalPath.components[].value`,
      `${aliasPrefix}.logicalPath.components[].value`,
      options,
    ),
    shape(
      `${outputPrefix}.logicalPath.hostBound`,
      `${aliasPrefix}.logicalPath.hostBound`,
      options,
    ),
    shape(
      `${outputPrefix}.bindingOwner`,
      `${aliasPrefix}.bindingOwner`,
      options,
    ),
    shape(
      `${outputPrefix}.bindingOwner.kind`,
      `${aliasPrefix}.bindingOwner.kind`,
      options,
    ),
    shape(
      `${outputPrefix}.bindingOwner.name`,
      `${aliasPrefix}.bindingOwner.name`,
      options,
    ),
    shape(
      `${outputPrefix}.bindingOwner.integrity`,
      `${aliasPrefix}.bindingOwner.integrity`,
      options,
    ),
    shape(
      `${outputPrefix}.bindingOwner.locator`,
      `${aliasPrefix}.bindingOwner.locator`,
      options,
    ),
  ];
}

function privateResolverPathShapes(outputPrefix, aliasPrefix) {
  const options = {
    sourceKind: "bridge",
    returnVariant: "private-compat",
  };
  return [
    shape(outputPrefix, aliasPrefix, options),
    shape(`${outputPrefix}.schema`, `${aliasPrefix}.schema`, options),
    shape(
      `${outputPrefix}.sessionHandle`,
      `${aliasPrefix}.sessionHandle`,
      options,
    ),
    shape(`${outputPrefix}.handle`, `${aliasPrefix}.handle`, options),
    shape(`${outputPrefix}.virtualPath`, `${aliasPrefix}.virtualPath`, options),
  ];
}

export function resolverRecordShapes(surfaceName) {
  const recordShapes = [
    shape("[[return]]", surfaceName, { sourceKind: "native-op" }),
    shape("field:schema", "resolver.schema", {
      sourceKind: "bridge",
      returnVariant: "record",
    }),
    shape("field:id", "resolver.id", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
    shape("field:id", "resolver.id", {
      sourceKind: "bridge",
      returnVariant: "builtin",
    }),
    shape("field:kind", "resolver.kind", {
      sourceKind: "bridge",
      returnVariant: "record",
    }),
    shape("field:error", "resolver.error", {
      sourceKind: "bridge",
      returnVariant: "refused",
    }),
    shape("field:errorCode", "resolver.errorCode", {
      sourceKind: "bridge",
      returnVariant: "refused",
    }),
    shape("field:path", "resolver.path", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
    ...typedLogicalPathShapes("field:path", "resolver.path", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
    ...privateResolverPathShapes("field:path", "resolver.path"),
    shape("field:pkgName", "resolver.pkgName", {
      sourceKind: "bridge",
      returnVariant: "package",
    }),
    shape("field:pkgRoot", "resolver.pkgRoot", {
      sourceKind: "bridge",
      returnVariant: "package",
    }),
    ...typedLogicalPathShapes("field:pkgRoot", "resolver.pkgRoot", {
      sourceKind: "bridge",
      returnVariant: "package",
    }),
    ...privateResolverPathShapes("field:pkgRoot", "resolver.pkgRoot"),
    shape("field:pkgVersion", "resolver.pkgVersion", {
      sourceKind: "bridge",
      returnVariant: "package",
    }),
    shape("field:pkgIntegrity", "resolver.pkgIntegrity", {
      sourceKind: "bridge",
      returnVariant: "package",
    }),
    shape("field:sourceId", "resolver.sourceId", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
    shape("field:sourceLabel", "resolver.sourceLabel", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
    shape("field:virtualPath", "resolver.virtualPath", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
  ];
  if (!surfaceName.endsWith("Meta")) {
    recordShapes.push(
      shape("field:source", "resolver.source", {
        sourceKind: "bridge",
        returnVariant: "file-backed",
      }),
    );
  }
  return recordShapes;
}

export function modulePackageRootShapes() {
  const options = { sourceKind: "package", returnVariant: "present" };
  return [
    shape("field:__exactPackageRoot", "module.__exactPackageRoot", options),
    ...typedLogicalPathShapes(
      "field:__exactPackageRoot",
      "module.__exactPackageRoot",
      options,
    ),
  ];
}

const VFS_HOST_ABI_NAMES = Object.freeze([
  "ex_host_vfs_bind_runtime",
  "ex_host_vfs_chdir",
  "ex_host_vfs_get_cwd",
  "ex_host_vfs_resolve_path",
  "ex_host_vfs_unbind_runtime",
]);

// @ref LLP 0023#6-path-bearing-observables — the VFS callbacks remain native
// private, while their separately typed virtual outputs are cataloged so a
// future JavaScript projection cannot silently inherit a backing path.
export function vfsHostAbiShapes(surfaceName) {
  if (!VFS_HOST_ABI_NAMES.includes(surfaceName)) {
    throw new Error(`unknown private VFS host ABI ${surfaceName}`);
  }
  const shapes = [
    shape("[[return]]", surfaceName, {
      mode: "javascript",
      sourceKind: "host-abi",
      returnVariant: "absent",
    }),
  ];
  if (
    surfaceName === "ex_host_vfs_chdir" ||
    surfaceName === "ex_host_vfs_get_cwd" ||
    surfaceName === "ex_host_vfs_resolve_path"
  ) {
    shapes.push(
      shape("out:virtual", `${surfaceName}.out_virtual`, {
        mode: "private-native",
        sourceKind: "host-abi",
        returnVariant: "success",
      }),
    );
  }
  if (surfaceName === "ex_host_vfs_resolve_path") {
    shapes.push(
      shape("out:backing", `${surfaceName}.out_backing`, {
        mode: "javascript",
        sourceKind: "host-abi",
        returnVariant: "absent",
      }),
    );
  }
  return shapes;
}

// These recipes describe structured outputs the source inventory cannot infer
// from an export descriptor alone. They intentionally contain no disposition
// or expected value. Each recipe is asserted against the named source bytes;
// the separately committed policy owns every classification decision.
const STRUCTURED_OUTPUT_RECIPES = Object.freeze([
  Object.freeze({
    surfaceName: "global:process.argv",
    assertions: [
      { path: "src/builtins/process.js", tokens: ["argv", "execArgv"] },
    ],
    shapes: [
      shape("index:0", "process.argv[0]", { mode: "file" }),
      shape("index:1", "process.argv[1]", { mode: "file" }),
      shape("index:0", "process.argv[0]", { mode: "program-stdin" }),
      shape("index:1", "process.argv[1]", {
        mode: "program-stdin",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "process.argv[0]", { mode: "eval" }),
      shape("index:1", "process.argv[1]", {
        mode: "eval",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "process.argv[0]", { mode: "repl" }),
      shape("index:1", "process.argv[1]", {
        mode: "repl",
        returnVariant: "absent",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "global:process.execArgv",
    assertions: [
      {
        path: "src/builtins/process.js",
        tokens: ["Array.isArray(proc.execArgv)", "__exactExecArgv"],
      },
    ],
    shapes: [shape("array-items", "process.execArgv[]")],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:exact_process:execArgv",
    assertions: [
      {
        path: "src/builtins/process.js",
        tokens: ["Array.isArray(process.execArgv)", "String(execArgv[ai])"],
      },
    ],
    shapes: [shape("array-items", "exact:process.execArgv[]")],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "global:Exact.argv",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["argv", "process.argv"],
      },
    ],
    shapes: [
      shape("index:0", "Exact.argv[0]", { mode: "file" }),
      shape("index:1", "Exact.argv[1]", { mode: "file" }),
      shape("index:0", "Exact.argv[0]", { mode: "program-stdin" }),
      shape("index:1", "Exact.argv[1]", {
        mode: "program-stdin",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "Exact.argv[0]", { mode: "eval" }),
      shape("index:1", "Exact.argv[1]", {
        mode: "eval",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "Exact.argv[0]", { mode: "repl" }),
      shape("index:1", "Exact.argv[1]", {
        mode: "repl",
        returnVariant: "absent",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "global:Bun.argv",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["g.Bun = E", "argv"],
      },
    ],
    shapes: [
      shape("index:0", "Bun.argv[0]", { mode: "file" }),
      shape("index:1", "Bun.argv[1]", { mode: "file" }),
      shape("index:0", "Bun.argv[0]", { mode: "program-stdin" }),
      shape("index:1", "Bun.argv[1]", {
        mode: "program-stdin",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "Bun.argv[0]", { mode: "eval" }),
      shape("index:1", "Bun.argv[1]", {
        mode: "eval",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "Bun.argv[0]", { mode: "repl" }),
      shape("index:1", "Bun.argv[1]", {
        mode: "repl",
        returnVariant: "absent",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "global:Exact.main",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["E.main =", "process.argv[1]"],
      },
    ],
    shapes: [
      shape("[[return]]", "Exact.main", {
        mode: "file",
        returnVariant: "entry",
      }),
      shape("[[return]]", "Exact.main", {
        mode: "program-stdin",
        returnVariant: "argument-or-empty",
      }),
      shape("[[return]]", "Exact.main", {
        mode: "eval",
        returnVariant: "argument-or-empty",
      }),
      shape("[[return]]", "Exact.main", {
        mode: "repl",
        returnVariant: "empty",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "global:Bun.main",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["g.Bun = E", "process.argv[1]"],
      },
    ],
    shapes: [
      shape("[[return]]", "Bun.main", { mode: "file", returnVariant: "entry" }),
      shape("[[return]]", "Bun.main", {
        mode: "program-stdin",
        returnVariant: "argument-or-empty",
      }),
      shape("[[return]]", "Bun.main", {
        mode: "eval",
        returnVariant: "argument-or-empty",
      }),
      shape("[[return]]", "Bun.main", { mode: "repl", returnVariant: "empty" }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "__filename",
    assertions: [
      {
        path: "src/engine/bootstrap/module-loader.js",
        tokens: ["__filename", "filename"],
      },
    ],
    shapes: [
      shape("[[return]]", "__filename", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("[[return]]", "__filename", {
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "__dirname",
    assertions: [
      {
        path: "src/engine/bootstrap/module-loader.js",
        tokens: ["__dirname", "dirname"],
      },
    ],
    shapes: [
      shape("[[return]]", "__dirname", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("[[return]]", "__dirname", {
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_os:userInfo",
    assertions: [
      {
        path: "src/builtins/os.js",
        tokens: ["function userInfo", "homedir", "shell"],
      },
    ],
    shapes: [
      shape("field:homedir", "os.userInfo().homedir"),
      shape("field:shell", "os.userInfo().shell"),
      shape("[[return]]", "os.userInfo()"),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "global:require.resolve",
    assertions: [
      {
        path: "src/engine/bootstrap/module-loader.js",
        tokens: ["require.resolve", "record.id"],
      },
    ],
    shapes: [
      shape("[[return]]", "require.resolve", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("[[return]]", "require.resolve", {
        sourceKind: "builtin",
        returnVariant: "builtin",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "module-loader-install",
    assertions: [
      {
        path: "src/engine/bootstrap/module-loader.js",
        tokens: ["importMeta", "filename", "dirname", "__exactPackageRoot"],
      },
    ],
    shapes: [
      shape("field:url", "import.meta.url", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:url", "import.meta.url", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "ibex-stdin",
      }),
      shape("field:url", "import.meta.url", {
        mode: "eval",
        sourceKind: "synthetic",
        returnVariant: "ibex-eval",
      }),
      shape("field:url", "import.meta.url", {
        mode: "repl",
        sourceKind: "synthetic",
        returnVariant: "repl-cell",
      }),
      shape("field:path", "import.meta.path", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:path", "import.meta.path", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
      shape("field:filename", "import.meta.filename", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:filename", "import.meta.filename", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
      shape("field:dirname", "import.meta.dirname", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:dirname", "import.meta.dirname", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
      shape("field:dirname", "import.meta.dir", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:dirname", "import.meta.dir", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
      shape("field:file", "import.meta.file", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:file", "import.meta.file", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "empty",
      }),
      shape("field:id", "module.id", { sourceKind: "file" }),
      shape("field:filename", "module.filename", { sourceKind: "file" }),
      shape("field:path", "module.path", { sourceKind: "file" }),
      shape("field:paths[]", "module.paths[]", { sourceKind: "file" }),
      shape("field:parent", "module.parent", { sourceKind: "file" }),
      shape("field:children", "module.children", { sourceKind: "file" }),
      ...modulePackageRootShapes(),
      shape("field:__exactPackageRoot", "module.__exactPackageRoot", {
        sourceKind: "project",
        returnVariant: "absent",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "export:node_fs:default",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: [
          "fsErr.path = resolvedPath",
          "fsErr.filename = resolvedFilename",
          "fsErr.dest = resolvedDest",
        ],
      },
    ],
    shapes: [
      shape("throw-field:path", "error.path", { returnVariant: "fs-error" }),
      shape("throw-field:filename", "error.filename", {
        returnVariant: "fs-error",
      }),
      shape("throw-field:dest", "error.dest", { returnVariant: "fs-error" }),
    ],
  }),
  Object.freeze({
    surfaceName: "module-loader-install",
    assertions: [
      {
        path: "src/engine/bootstrap/module-loader.js",
        tokens: ["sourceURL=", "filename"],
      },
      {
        path: "src/bin/ibex/engine/hermes.rs",
        tokens: ["rewrite_staged_source_map", '.get_mut("sources")'],
      },
      {
        path: "src/engine/evaluation.rs",
        tokens: ["pub struct SourceLabel", "repl:", "ibex:stdin", "ibex:eval"],
      },
    ],
    shapes: [
      shape("stack-frame:source", "Error.stack frame source", {
        sourceKind: "runtime-owned",
        returnVariant: "builtin-or-runtime",
      }),
      shape("source-map:sources[]", "source-map.sources[]", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("source-map:sources[]", "source-map.sources[]", {
        sourceKind: "synthetic",
        returnVariant: "source-label",
      }),
      shape("source-map:sourceURL", "sourceURL", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("source-map:sourceURL", "sourceURL", {
        sourceKind: "synthetic",
        returnVariant: "source-label",
      }),
    ],
  }),
  ...[
    ["__exactModuleResolve", "ex_host_module_resolve"],
    ["__exactModuleResolveMeta", "ex_host_module_resolve_meta"],
    ["__exactNativeModuleResolve", "ex_host_module_resolve"],
    ["__exactNativeModuleResolveMeta", "ex_host_module_resolve_meta"],
  ].map(([surfaceName, abiName]) =>
    Object.freeze({
      surfaceName,
      assertions: [
        {
          path: "src/host/abi.rs",
          tokens: [
            abiName,
            "ex_host_session_static_import_resolve",
            "ibex/module-resolution/1",
            "resolver_package_root",
            "resolver_path",
            "private_resolver_package_root",
            "private_resolver_path",
            "pkgIntegrity",
            "pkgName",
            "pkgRoot",
            "pkgVersion",
            "sourceId",
            "sourceLabel",
            "virtualPath",
          ],
        },
        {
          path: "src/engine/hermes_runtime.cc",
          tokens: [surfaceName, abiName],
        },
      ],
      shapes: resolverRecordShapes(surfaceName),
      replaceDefault: true,
    }),
  ),
  ...VFS_HOST_ABI_NAMES.map((surfaceName) =>
    Object.freeze({
      surfaceName,
      assertions: [
        {
          path: "src/host/abi.rs",
          tokens: [surfaceName, "runtime_vfs_session"],
        },
        {
          path: "src/engine/hermes_runtime.cc",
          tokens: [surfaceName],
        },
      ],
      shapes: vfsHostAbiShapes(surfaceName),
    }),
  ),
  Object.freeze({
    surfaceName: "export:node_fs:readlink",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function readlink", "__exactReadlink"],
      },
    ],
    shapes: [
      shape("[[return]]", "fs.readlink", { returnVariant: "mapped" }),
      shape("[[return]]", "fs.readlink", { returnVariant: "unmappable" }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs:readlinkSync",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function readlinkSync", "__exactReadlink"],
      },
    ],
    shapes: [
      shape("[[return]]", "fs.readlinkSync", { returnVariant: "mapped" }),
      shape("[[return]]", "fs.readlinkSync", { returnVariant: "unmappable" }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs_promises:readlink",
    assertions: [
      { path: "src/builtins/fs.js", tokens: ["readlink", "promises"] },
    ],
    shapes: [
      shape("[[return]]", "fs.promises.readlink", { returnVariant: "mapped" }),
      shape("[[return]]", "fs.promises.readlink", {
        returnVariant: "unmappable",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs:glob",
    assertions: [
      { path: "src/builtins/fs.js", tokens: ["function glob", "globSync"] },
    ],
    shapes: [
      shape("array-items", "fs.glob", { returnVariant: "relative-pattern" }),
      shape("array-items", "fs.glob", { returnVariant: "absolute-pattern" }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs:globSync",
    assertions: [
      { path: "src/builtins/fs.js", tokens: ["function globSync", "glob"] },
    ],
    shapes: [
      shape("array-items", "fs.globSync", {
        returnVariant: "relative-pattern",
      }),
      shape("array-items", "fs.globSync", {
        returnVariant: "absolute-pattern",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_path:posix",
    assertions: [
      {
        path: "src/builtins/path.js",
        tokens: ["posix", "resolve", "relative"],
      },
    ],
    shapes: [
      shape("field:resolve", "path.posix.resolve"),
      shape("field:relative", "path.posix.relative"),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_path:win32",
    assertions: [
      {
        path: "src/builtins/path.js",
        tokens: ["win32", "resolve", "relative"],
      },
    ],
    shapes: [
      shape("field:resolve", "path.win32.resolve", {
        sourceKind: "foreign-dialect",
      }),
      shape("field:relative", "path.win32.relative", {
        sourceKind: "foreign-dialect",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs:watch",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function watch", "recursive", "filename"],
      },
    ],
    shapes: [
      shape("callback:filename", "fs.watch event path", {
        returnVariant: "non-recursive",
      }),
      shape("callback:filename", "fs.watch event path", {
        returnVariant: "recursive",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs:Dirent",
    assertions: [
      { path: "src/builtins/fs.js", tokens: ["function Dirent", "parentPath"] },
    ],
    shapes: [
      shape("field:parentPath", "Dirent.parentPath"),
      shape("field:path", "Dirent.path"),
      shape("field:name", "Dirent.name"),
    ],
  }),
  Object.freeze({
    surfaceName: "export:node_fs_promises:FileHandle",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function FileHandlePromise", "this.path"],
      },
    ],
    shapes: [shape("field:path", "FileHandle.path")],
  }),
  Object.freeze({
    surfaceName: "export:node_fs:ReadStream",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function ReadStream", "rs.path"],
      },
    ],
    shapes: [shape("field:path", "ReadStream.path")],
  }),
  Object.freeze({
    surfaceName: "export:node_fs:WriteStream",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function WriteStream", "ws.path"],
      },
    ],
    shapes: [shape("field:path", "WriteStream.path")],
  }),
  Object.freeze({
    surfaceName: "global:Exact.file",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["defineExactValue('file'", "ExactFile", "this.name"],
      },
    ],
    shapes: [shape("field:name", "ExactFile.name")],
  }),
  Object.freeze({
    surfaceName: "global:Bun.file",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["g.Bun = E", "ExactFile", "this.name"],
      },
    ],
    shapes: [shape("field:name", "Bun.ExactFile.name")],
  }),
]);

function implementationEvidenceByEdge(implementationRows) {
  const byEdge = new Map();
  for (const row of implementationRows) {
    const entry = byEdge.get(row.edgeId) ?? {
      observedKeys: new Set(),
      sourceRefs: new Set(),
    };
    entry.observedKeys.add(row.observedKey);
    row.sourceRefs.forEach((sourceRef) => entry.sourceRefs.add(sourceRef));
    byEdge.set(row.edgeId, entry);
  }
  return byEdge;
}

function sourceSurfaceMap(surfaces) {
  const rows = Array.isArray(surfaces) ? surfaces : surfaces?.surfaces;
  if (!Array.isArray(rows)) {
    throw new Error(
      "output catalog requires the live source surface inventory",
    );
  }
  const byObservedKey = new Map();
  for (const [index, surface] of rows.entries()) {
    const observedKey = `${surface?.kind}:${surface?.name}`;
    if (
      typeof surface?.kind !== "string" ||
      typeof surface?.name !== "string" ||
      surface.observedKey !== observedKey
    ) {
      throw new Error(
        `output catalog source surface ${index}: malformed observed identity`,
      );
    }
    if (byObservedKey.has(observedKey)) {
      throw new Error(
        `output catalog source inventory duplicates ${observedKey}`,
      );
    }
    byObservedKey.set(observedKey, surface);
  }
  return byObservedKey;
}

function genericOutputContract(surface) {
  const metadata = surface.metadata ?? {};
  if (surface.kind === "builtin" && metadata.importReachability === "public") {
    if (metadata.surfaceType !== "export") {
      return { output: "[[binding]]", outputKind: "public-import" };
    }
    if (metadata.valueShape === "callable") {
      return { output: "[[return]]", outputKind: "public-invocation" };
    }
    return { output: "[[value]]", outputKind: "public-property-read" };
  }
  if (
    surface.kind === "native-op" &&
    metadata.surfaceType === "global-api" &&
    metadata.publicInvocation?.kind === "native-global-function"
  ) {
    return { output: "[[return]]", outputKind: "native-invocation" };
  }
  if (
    surface.kind === "native-op" &&
    metadata.surfaceType === "global-api" &&
    metadata.publicReadAccessSourceProven === true
  ) {
    return metadata.valueShape === "callable"
      ? { output: "[[return]]", outputKind: "public-invocation" }
      : { output: "[[value]]", outputKind: "public-property-read" };
  }
  return null;
}

function structuralReasonCode(surface) {
  const metadata = surface.metadata ?? {};
  if (
    surface.kind === "builtin" &&
    metadata.importReachability === "bootstrap-internal"
  ) {
    return "bootstrap-internal-builtin";
  }
  if (surface.kind === "cli") return "cli-structural-surface";
  if (surface.kind === "loader") return "loader-structural-route";
  if (surface.kind === "startup") return "startup-structural-route";
  if (
    surface.kind === "native-op" &&
    metadata.surfaceType === "native-network-backend"
  ) {
    return "native-network-backend";
  }
  return null;
}

function unresolvedReasonCode(surface) {
  if (surface.kind === "callback") return "callback-payload-contract-missing";
  if (surface.kind === "host-abi") {
    return "host-abi-signature-contract-missing";
  }
  if (surface.kind === "native-op") {
    return surface.metadata?.surfaceType === "global-api"
      ? "native-global-reachability-contract-missing"
      : "native-surface-contract-missing";
  }
  return "output-contract-missing";
}

function surfaceAccount({ edge, surface, implementation, recipeSurfaceIds }) {
  const generic = genericOutputContract(surface);
  const structured = recipeSurfaceIds.has(edge.id);
  const outputKinds = [
    ...(generic ? [generic.outputKind] : []),
    ...(structured ? ["structured-output"] : []),
  ].sort(compareText);
  const structuralReason =
    generic || structured ? null : structuralReasonCode(surface);
  const status =
    generic || structured
      ? "output-bearing"
      : structuralReason
        ? "structural-only"
        : "unresolved";
  const sourceRefs = [
    ...new Set([...(surface.sourceRefs ?? []), ...implementation.sourceRefs]),
  ].sort(compareText);
  if (sourceRefs.length === 0) {
    throw new Error(`output catalog account ${edge.id} has no source evidence`);
  }
  return {
    surfaceId: edge.id,
    status,
    reasonCode:
      status === "output-bearing"
        ? structured && !generic
          ? "source-asserted-structured-output"
          : "source-derived-public-output"
        : status === "structural-only"
          ? structuralReason
          : unresolvedReasonCode(surface),
    sourceRefs,
    outputKinds,
  };
}

export function validateOutputShapeCatalogAccounts({
  coverage,
  surfaceAccounts,
  rows,
  promotionStatus = "unpromotable",
}) {
  if (!Array.isArray(surfaceAccounts) || !Array.isArray(rows)) {
    throw new Error("output catalog accounts and rows must be arrays");
  }
  assertUniqueRows(rows, "output shape catalog rows");
  const coverageIds = coverage
    ? coverage.edges.map((edge) => edge.id)
    : surfaceAccounts.map((account) => account.surfaceId);
  if (new Set(coverageIds).size !== coverageIds.length) {
    throw new Error("output catalog coverage ids are not unique");
  }
  const accountsById = new Map();
  for (const [index, account] of surfaceAccounts.entries()) {
    exactKeys(
      account,
      ["surfaceId", "status", "reasonCode", "sourceRefs", "outputKinds"],
      `output surface account ${index}`,
    );
    if (
      typeof account.surfaceId !== "string" ||
      !/^surface\.[a-z0-9.]+$/u.test(account.surfaceId) ||
      !new Set(["output-bearing", "structural-only", "unresolved"]).has(
        account.status,
      ) ||
      typeof account.reasonCode !== "string" ||
      account.reasonCode.length === 0 ||
      !Array.isArray(account.sourceRefs) ||
      account.sourceRefs.length === 0 ||
      !Array.isArray(account.outputKinds)
    ) {
      throw new Error(`output surface account ${index}: malformed account`);
    }
    for (const [field, values] of [
      ["sourceRefs", account.sourceRefs],
      ["outputKinds", account.outputKinds],
    ]) {
      if (
        values.some(
          (value) => typeof value !== "string" || value.length === 0,
        ) ||
        canonicalJson(values) !==
          canonicalJson([...new Set(values)].sort(compareText))
      ) {
        throw new Error(
          `output surface account ${index}.${field}: expected a canonical string set`,
        );
      }
    }
    if (
      (account.status === "output-bearing") !==
      account.outputKinds.length > 0
    ) {
      throw new Error(
        `output surface account ${account.surfaceId}: output kinds disagree with status`,
      );
    }
    if (accountsById.has(account.surfaceId)) {
      throw new Error(`output surface accounts duplicate ${account.surfaceId}`);
    }
    accountsById.set(account.surfaceId, account);
  }
  const expectedIds = [...coverageIds].sort(compareText);
  const expectedIdSet = new Set(expectedIds);
  const actualIds = [...accountsById.keys()].sort(compareText);
  const missing = expectedIds.filter((id) => !accountsById.has(id));
  const unknown = actualIds.filter((id) => !expectedIdSet.has(id));
  if (
    missing.length ||
    unknown.length ||
    canonicalJson(expectedIds) !== canonicalJson(actualIds)
  ) {
    throw new Error(
      `output surface accounts are not set-equal to coverage; missing=[${missing.slice(0, 8).join(", ")}] unknown=[${unknown.slice(0, 8).join(", ")}]`,
    );
  }
  const rowsBySurface = Map.groupBy(rows, (row) => row.key.surfaceId);
  for (const [index, row] of rows.entries()) {
    if (row.requiredValueProof !== "live-value-observation") {
      throw new Error(
        `output shape catalog row ${index}: value rows require live value observation`,
      );
    }
    if (!accountsById.has(row.key.surfaceId)) {
      throw new Error(
        `output shape catalog row ${index}: unknown surface ${row.key.surfaceId}`,
      );
    }
  }
  for (const account of surfaceAccounts) {
    const rowCount = rowsBySurface.get(account.surfaceId)?.length ?? 0;
    if (account.status === "output-bearing" && rowCount === 0) {
      throw new Error(
        `output-bearing surface ${account.surfaceId} has no output rows`,
      );
    }
    if (account.status !== "output-bearing" && rowCount !== 0) {
      throw new Error(
        `${account.status} surface ${account.surfaceId} has output rows`,
      );
    }
  }
  const counts = Object.fromEntries(
    ["output-bearing", "structural-only", "unresolved"].map((status) => [
      status,
      surfaceAccounts.filter((account) => account.status === status).length,
    ]),
  );
  if (promotionStatus === "verified" && counts.unresolved > 0) {
    throw new Error(
      `verified output catalog has ${counts.unresolved} unresolved surface accounts`,
    );
  }
  if (!new Set(["unpromotable", "verified"]).has(promotionStatus)) {
    throw new Error(
      `unknown output catalog promotion status ${promotionStatus}`,
    );
  }
  return counts;
}

export function buildOutputShapeCatalog({
  coverage,
  implementationRows,
  surfaces,
  repoRoot,
  liveEvidence,
}) {
  if (
    !liveEvidence ||
    typeof liveEvidence.requiredExecutor !== "string" ||
    liveEvidence.requiredExecutor.length === 0 ||
    !["unpromotable", "verified"].includes(liveEvidence.status)
  ) {
    throw new Error("output shape discovery has malformed live-evidence state");
  }
  const edgeByName = new Map();
  for (const edge of coverage.edges) {
    const rows = edgeByName.get(edge.surface.name) ?? [];
    rows.push(edge);
    edgeByName.set(edge.surface.name, rows);
  }
  const implementationByEdge = implementationEvidenceByEdge(implementationRows);
  const sourcesByObservedKey = sourceSurfaceMap(surfaces);
  const replacementIds = new Set();
  const recipeSurfaceIds = new Set();
  const recipeRows = [];
  for (const [recipeIndex, recipe] of STRUCTURED_OUTPUT_RECIPES.entries()) {
    const edges = edgeByName.get(recipe.surfaceName) ?? [];
    if (edges.length !== 1) {
      throw new Error(
        `output shape recipe ${recipeIndex}: expected one ${recipe.surfaceName} surface, got ${edges.length}`,
      );
    }
    const edge = edges[0];
    const sourceSurface = sourcesByObservedKey.get(
      `${edge.surface.kind}:${edge.surface.name}`,
    );
    if (!sourceSurface) {
      throw new Error(
        `output shape recipe ${recipeIndex}: missing source surface ${edge.surface.kind}:${edge.surface.name}`,
      );
    }
    recipeSurfaceIds.add(edge.id);
    if (recipe.replaceDefault) replacementIds.add(edge.id);
    const sourceRefs = recipe.assertions
      .map((assertion, assertionIndex) =>
        sourceAssertion(
          repoRoot,
          assertion,
          `output shape recipe ${recipeIndex} assertion ${assertionIndex}`,
        ),
      )
      .sort(compareText);
    for (const recipeShape of recipe.shapes) {
      const partialKey = {
        surfaceId: edge.id,
        output: recipeShape.output,
        alias: recipeShape.alias,
        mode: recipeShape.mode,
        sourceKind: recipeShape.sourceKind,
        returnVariant: recipeShape.returnVariant,
      };
      recipeRows.push({
        key: {
          ...partialKey,
          contextId: defaultContextIdForCatalogRow(partialKey, sourceSurface),
        },
        discovery: {
          kind: "source-asserted-structured-output",
          sourceRefs,
        },
        requiredValueProof: "live-value-observation",
      });
    }
  }

  const baselineRows = coverage.edges
    .filter((edge) => {
      const sourceSurface = sourcesByObservedKey.get(
        `${edge.surface.kind}:${edge.surface.name}`,
      );
      if (!sourceSurface) {
        throw new Error(
          `output catalog surface ${edge.id} lacks source inventory metadata`,
        );
      }
      return (
        genericOutputContract(sourceSurface) !== null &&
        !replacementIds.has(edge.id)
      );
    })
    .map((edge) => {
      const implementation = implementationByEdge.get(edge.id);
      if (!implementation) {
        throw new Error(
          `output catalog surface ${edge.id} lacks source inventory evidence`,
        );
      }
      const sourceSurface = sourcesByObservedKey.get(
        `${edge.surface.kind}:${edge.surface.name}`,
      );
      const outputContract = genericOutputContract(sourceSurface);
      const partialKey = {
        surfaceId: edge.id,
        output: outputContract.output,
        alias: edge.surface.name,
        mode: "all",
        sourceKind: edge.surface.kind,
        returnVariant: "default",
      };
      return {
        key: {
          ...partialKey,
          contextId: defaultContextIdForCatalogRow(partialKey, sourceSurface),
        },
        discovery: {
          kind: "source-inventory-surface",
          observedKeys: [...implementation.observedKeys].sort(compareText),
          sourceRefs: [...implementation.sourceRefs].sort(compareText),
        },
        requiredValueProof: "live-value-observation",
      };
    });
  const rows = sortRows([...baselineRows, ...recipeRows]);
  assertUniqueRows(rows, "output shape catalog rows");
  const surfaceAccounts = coverage.edges
    .map((edge) => {
      const implementation = implementationByEdge.get(edge.id);
      if (!implementation) {
        throw new Error(
          `output catalog account ${edge.id} lacks source inventory evidence`,
        );
      }
      const sourceSurface = sourcesByObservedKey.get(
        `${edge.surface.kind}:${edge.surface.name}`,
      );
      if (!sourceSurface) {
        throw new Error(
          `output catalog account ${edge.id} lacks source inventory metadata`,
        );
      }
      return surfaceAccount({
        edge,
        surface: sourceSurface,
        implementation,
        recipeSurfaceIds,
      });
    })
    .sort((left, right) => compareText(left.surfaceId, right.surfaceId));
  const accountCounts = validateOutputShapeCatalogAccounts({
    coverage,
    surfaceAccounts,
    rows,
    promotionStatus: liveEvidence.status,
  });
  const contexts = outputExecutionContextsForRows(rows);
  return {
    outputShapeCatalogSchema: "ibex/capsec-output-shape-catalog/2",
    profile: PROFILE,
    discovery: {
      status: liveEvidence.status,
      method:
        "source-inventory-surface-accounting-plus-source-asserted-structured-outputs",
      requiredExecutor: liveEvidence.requiredExecutor,
      ...(liveEvidence.status === "unpromotable"
        ? { reason: liveEvidence.reason }
        : {
            sourceRevision: liveEvidence.sourceRevision,
            engineBinaryDigest: liveEvidence.engineBinaryDigest,
          }),
    },
    contexts,
    surfaceAccounts,
    catalogKeyDigest: outputShapeCatalogKeyDigest(rows),
    counts: {
      coverageSurfaces: coverage.edges.length,
      outputBearingSurfaces: accountCounts["output-bearing"],
      structuralOnlySurfaces: accountCounts["structural-only"],
      unresolvedSurfaces: accountCounts.unresolved,
      catalogRows: rows.length,
      sourceInventoryRows: baselineRows.length,
      structuredRows: recipeRows.length,
    },
    rows,
  };
}

export function validateOutputDispositionJoin(catalogRows, dispositionRows) {
  assertUniqueRows(catalogRows, "output shape catalog rows");
  assertUniqueRows(dispositionRows, "output disposition rows");
  const catalogKeys = new Set(
    catalogRows.map((row) => canonicalOutputDispositionKey(row.key)),
  );
  const dispositionKeys = new Set(
    dispositionRows.map((row) => canonicalOutputDispositionKey(row.key)),
  );
  const uncovered = [...catalogKeys].filter((key) => !dispositionKeys.has(key));
  const unknown = [...dispositionKeys].filter((key) => !catalogKeys.has(key));
  if (uncovered.length || unknown.length) {
    throw new Error(
      `output disposition join is not bidirectional; uncovered=[${uncovered.slice(0, 8).join(", ")}] unknown=[${unknown.slice(0, 8).join(", ")}]`,
    );
  }
}

function validateOutputShapeCatalogDocument(catalog, evidence) {
  if (
    catalog?.outputShapeCatalogSchema !==
      "ibex/capsec-output-shape-catalog/2" ||
    catalog.profile !== PROFILE ||
    !Array.isArray(catalog.contexts) ||
    !Array.isArray(catalog.surfaceAccounts) ||
    !Array.isArray(catalog.rows)
  ) {
    throw new Error("output shape catalog is not a complete v2 document");
  }
  const discovery = catalog.discovery;
  if (
    !discovery ||
    typeof discovery !== "object" ||
    discovery.method !==
      "source-inventory-surface-accounting-plus-source-asserted-structured-outputs" ||
    !evidence ||
    typeof evidence !== "object" ||
    discovery.status !== evidence.status ||
    discovery.requiredExecutor !== evidence.requiredExecutor
  ) {
    throw new Error(
      "output shape catalog discovery does not bind the loaded-engine evidence state",
    );
  }
  if (
    discovery.status === "unpromotable" &&
    discovery.reason !== evidence.reason
  ) {
    throw new Error(
      "output shape catalog discovery does not bind the unpromotable evidence reason",
    );
  }
  if (
    discovery.status === "verified" &&
    (discovery.sourceRevision !== evidence.sourceRevision ||
      discovery.engineBinaryDigest !== evidence.engineBinaryDigest)
  ) {
    throw new Error(
      "output shape catalog discovery does not bind the verified engine identity",
    );
  }
  if (catalog.catalogKeyDigest !== outputShapeCatalogKeyDigest(catalog.rows)) {
    throw new Error("output shape catalog key digest does not match its rows");
  }
  const expectedContexts = outputExecutionContextsForRows(catalog.rows);
  if (canonicalJson(catalog.contexts) !== canonicalJson(expectedContexts)) {
    throw new Error(
      "output shape catalog execution contexts do not match its rows",
    );
  }
  const accountCounts = validateOutputShapeCatalogAccounts({
    surfaceAccounts: catalog.surfaceAccounts,
    rows: catalog.rows,
    promotionStatus: evidence.status,
  });
  const expectedCounts = {
    coverageSurfaces: catalog.surfaceAccounts.length,
    outputBearingSurfaces: accountCounts["output-bearing"],
    structuralOnlySurfaces: accountCounts["structural-only"],
    unresolvedSurfaces: accountCounts.unresolved,
    catalogRows: catalog.rows.length,
    sourceInventoryRows: catalog.rows.filter(
      (row) => row.discovery.kind === "source-inventory-surface",
    ).length,
    structuredRows: catalog.rows.filter(
      (row) => row.discovery.kind === "source-asserted-structured-output",
    ).length,
  };
  if (canonicalJson(catalog.counts) !== canonicalJson(expectedCounts)) {
    throw new Error(
      "output shape catalog counts do not match its accounts and rows",
    );
  }
  return accountCounts;
}

function buildDispositionRows(catalog, policy) {
  if (
    policy?.outputDispositionPolicySchema !==
      "ibex/capsec-output-disposition-policy/2" ||
    policy.profile !== PROFILE
  ) {
    throw new Error("output disposition policy is not a complete v2 document");
  }
  if (policy.catalogKeyDigest !== catalog.catalogKeyDigest) {
    throw new Error(
      `output disposition policy has unreviewed catalog fields: expected ${policy.catalogKeyDigest}, discovered ${catalog.catalogKeyDigest}`,
    );
  }
  if (policy.defaultDisposition !== "non-path") {
    throw new Error(
      "output disposition policy default must be explicit non-path",
    );
  }
  assertUniqueRows(policy.overrides, "output disposition policy overrides");
  const overrides = new Map(
    policy.overrides.map((row) => [
      canonicalOutputDispositionKey(row.key),
      row,
    ]),
  );
  const rows = catalog.rows.map((catalogRow) => {
    const key = canonicalOutputDispositionKey(catalogRow.key);
    const override = overrides.get(key);
    if (override) {
      overrides.delete(key);
      return {
        key: structuredClone(catalogRow.key),
        disposition: override.disposition,
        expectation: structuredClone(override.expectation),
        rationale: override.rationale,
      };
    }
    return {
      key: structuredClone(catalogRow.key),
      disposition: "non-path",
      expectation: {
        outcome: "return",
        normalizedValue: "non-path",
      },
      rationale: policy.defaultRationale,
    };
  });
  if (overrides.size) {
    throw new Error(
      `output disposition policy references unknown catalog keys: ${[...overrides.keys()].slice(0, 8).join(", ")}`,
    );
  }
  validateOutputDispositionJoin(catalog.rows, rows);
  return sortRows(rows);
}

export function validateOutputDispositionEvidence(dispositionRows, evidence) {
  if (
    evidence?.outputDispositionEvidenceSchema !==
      "ibex/capsec-output-disposition-evidence/2" ||
    evidence.profile !== PROFILE ||
    typeof evidence.requiredExecutor !== "string" ||
    evidence.requiredExecutor.length === 0 ||
    !Array.isArray(evidence.observations)
  ) {
    throw new Error(
      "output disposition evidence is not a complete v2 document",
    );
  }
  assertUniqueRows(evidence.observations, "output disposition observations");
  if (evidence.status === "unpromotable") {
    if (typeof evidence.reason !== "string" || evidence.reason.length === 0) {
      throw new Error(
        "unpromotable output evidence requires an explicit reason",
      );
    }
    if (evidence.sourceRevision || evidence.engineBinaryDigest) {
      throw new Error(
        "unpromotable output evidence cannot claim engine identity",
      );
    }
    if (evidence.observations.length !== 0) {
      throw new Error(
        "unpromotable output evidence must not carry observations",
      );
    }
    return { status: "unpromotable", reason: evidence.reason };
  }
  if (
    evidence.status !== "verified" ||
    !/^[0-9a-f]{40}$/u.test(evidence.sourceRevision ?? "") ||
    !/^sha256-[A-Za-z0-9_-]{43}$/u.test(evidence.engineBinaryDigest ?? "")
  ) {
    throw new Error(
      "verified output evidence lacks exact source and engine identity",
    );
  }
  const expectedByKey = new Map(
    dispositionRows.map((row) => [canonicalOutputDispositionKey(row.key), row]),
  );
  const observationsByKey = new Map(
    evidence.observations.map((row) => [
      canonicalOutputDispositionKey(row.key),
      row,
    ]),
  );
  const uncovered = [...expectedByKey.keys()].filter(
    (key) => !observationsByKey.has(key),
  );
  const unknown = [...observationsByKey.keys()].filter(
    (key) => !expectedByKey.has(key),
  );
  if (uncovered.length || unknown.length) {
    throw new Error(
      `loaded-engine output evidence is incomplete; uncovered=[${uncovered.slice(0, 8).join(", ")}] unknown=[${unknown.slice(0, 8).join(", ")}]`,
    );
  }
  for (const [key, expected] of expectedByKey) {
    const actual = observationsByKey.get(key);
    validateOutputValueProofKind(
      actual.proofKind,
      `loaded-engine output evidence ${key}`,
    );
    if (
      actual.disposition !== expected.disposition ||
      canonicalJson(actual.observation) !== canonicalJson(expected.expectation)
    ) {
      throw new Error(`loaded-engine output value mismatch for ${key}`);
    }
  }
  return {
    status: "verified",
    sourceRevision: evidence.sourceRevision,
    engineBinaryDigest: evidence.engineBinaryDigest,
  };
}

export function buildOutputDispositionDataset({ catalog, policy, evidence }) {
  validateOutputShapeCatalogDocument(catalog, evidence);
  const rows = buildDispositionRows(catalog, policy);
  const evidenceState = validateOutputDispositionEvidence(rows, evidence);
  const dispositionCounts = Object.fromEntries(
    OUTPUT_DISPOSITIONS.map((disposition) => [
      disposition,
      rows.filter((row) => row.disposition === disposition).length,
    ]),
  );
  const absentDispositions = OUTPUT_DISPOSITIONS.filter(
    (disposition) => dispositionCounts[disposition] === 0,
  );
  if (absentDispositions.length) {
    throw new Error(
      `output disposition dataset does not exercise the closed disposition set: ${absentDispositions.join(", ")}`,
    );
  }
  return {
    outputDispositionDatasetSchema: "ibex/capsec-output-dispositions/2",
    profile: PROFILE,
    catalogKeyDigest: catalog.catalogKeyDigest,
    evidence: evidenceState,
    dispositions: OUTPUT_DISPOSITIONS,
    rows,
    counts: {
      catalogRows: catalog.rows.length,
      dispositionRows: rows.length,
      byDisposition: dispositionCounts,
    },
  };
}

function markdownCell(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}

export function renderOutputDispositionMarkdown(dataset) {
  const materialRows = dataset.rows.filter(
    (row) => row.disposition !== "non-path",
  );
  const lines = [
    "# Output dispositions",
    "",
    "<!-- @generated by packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs; do not edit -->",
    "",
    `Evidence status: **${dataset.evidence.status}**.`,
    "",
    ...(dataset.evidence.status === "unpromotable"
      ? [`Reason: ${dataset.evidence.reason}`, ""]
      : []),
    `The machine dataset contains ${dataset.counts.dispositionRows} canonical rows; ${dataset.counts.byDisposition["non-path"]} are explicit \`non-path\` decisions pinned by catalog digest \`${dataset.catalogKeyDigest}\`.`,
    "",
    "The table below projects every material (non-`non-path`) decision. The JSON artifact is normative and total.",
    "",
    "| Surface ID | Output | Alias | Mode | Source kind | Variant | Execution context | Disposition | Expected observation |",
    "|---|---|---|---|---|---|---|---|---|",
  ];
  for (const row of materialRows) {
    lines.push(
      `| \`${markdownCell(row.key.surfaceId)}\` | \`${markdownCell(row.key.output)}\` | \`${markdownCell(row.key.alias)}\` | \`${markdownCell(row.key.mode)}\` | \`${markdownCell(row.key.sourceKind)}\` | \`${markdownCell(row.key.returnVariant)}\` | \`${markdownCell(row.key.contextId)}\` | \`${markdownCell(row.disposition)}\` | \`${markdownCell(canonicalJson(row.expectation))}\` |`,
    );
  }
  return `${lines.join("\n")}\n`;
}
