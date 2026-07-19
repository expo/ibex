/**
 * Validate the terminal-session constants annex and generate its Rust module.
 *
 * The annex is the cross-language authority. Generation also audits the Rust
 * consumer and the interrupt-model status vocabulary, so a second handwritten
 * copy cannot silently diverge from it.
 *
 * @ref LLP 0022#10-terminal-interrupt-exit-and-history — the prompt and
 * operator-visible interrupt behavior share this versioned vocabulary.
 * @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker — trusted
 * prompt/render tokens and the hostile IBDX wire grammar are pinned together.
 * @ref LLP 0025#6-interruption-and-cancellation — notice text and interrupt
 * disposition are data consumed by the generated interrupt implementation.
 * @ref LLP 0025#8-exit-and-lifecycle — fixed exit statuses and lifecycle
 * budgets must agree across the supervisor and worker boundary.
 * @ref LLP 0025#12-constants — v1 bounds, units, and overflow behavior are
 * carried by a canonical, digest-bound annex rather than handwritten code.
 */

import Ajv2020 from "ajv/dist/2020.js";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const repoRoot = path.resolve(__dirname, "..", "..", "..", "..");
export const sessionConstantsSourcePath = path.join(
  repoRoot,
  "session",
  "session-constants.v1.json",
);
export const sessionConstantsSchemaPath = path.join(
  repoRoot,
  "session",
  "schema",
  "session-constants.schema.json",
);
export const terminalSessionSourcePath = path.join(
  repoRoot,
  "src",
  "bin",
  "ibex",
  "terminal_session.rs",
);
export const interruptMachineSourcePath = path.join(
  repoRoot,
  "session",
  "interrupt-machine.v1.json",
);
export const generatedSessionConstantsPath = path.join(
  repoRoot,
  "vendored-generated",
  "session_constants.generated.rs",
);
export const generatorPath = __filename;

const REQUIRED_TERMINAL_BINDINGS = Object.freeze([
  "PROMPT_DEFAULT_TEXT",
  "PROMPT_INTERRUPT_BYTE",
  "PROMPT_EDITOR_ERASE_BYTES",
  "PROMPT_TRANSCRIPT_BOUNDARY_BYTES",
  "ANSI_RESET",
  "ANSI_SESSION_PROMPT",
  "ANSI_SESSION_NOTICE",
  "ANSI_SESSION_ERROR",
  "ANSI_DISPLAY_STRING",
  "ANSI_DISPLAY_NUMBER",
  "ANSI_DISPLAY_KEYWORD",
  "ANSI_DISPLAY_ERROR",
  "ANSI_DISPLAY_KEY",
  "ANSI_DISPLAY_TYPE_TAG",
  "ANSI_DISPLAY_TRUNCATION",
  "NOTICE_ORDERLY_PROMISE",
  "NOTICE_CANCELLING_WORK",
  "NOTICE_WORK_IN_FLIGHT",
  "NOTICE_CANCELLING_COMPLETION",
  "NOTICE_INPUT_DISCARDED",
  "EXIT_STATUS_ENGINE_FAULT",
  "EXIT_STATUS_INTERRUPT",
  "EXIT_STATUS_BROKEN_PIPE",
  "POSIX_EXIT_STATUS_MASK",
  "BROKER_QUEUE_BOUND_BYTES",
  "DISPLAY_TREE_MAX_SERIALIZED_BYTES",
  "DISPLAY_RENDER_DEPTH",
  "DISPLAY_RENDER_BREADTH",
  "DISPLAY_PAYLOAD_SCALARS",
  "BROKER_FLUSH_BUDGET_MILLIS",
  "MAX_LIVE_RELAYS",
  "RENDER_CHILDREN_OPEN",
  "RENDER_CHILDREN_SEPARATOR",
  "RENDER_CHILDREN_CLOSE",
  "RENDER_PAYLOAD_TRUNCATION_SEPARATOR",
  "TRUNCATION_PREFIX",
  "TRUNCATION_SUFFIX",
  "DISPLAY_FALLBACK_PREFIX",
  "DISPLAY_FALLBACK_SUFFIX",
  "UNKNOWN_DISPLAY_NODE_PREFIX",
  "UNKNOWN_DISPLAY_NODE_SUFFIX",
  "DISPLAY_FALLBACK_REASON_OVERSIZE_TREE",
  "DISPLAY_FALLBACK_REASON_MALFORMED_OR_UNKNOWN_TREE",
  "DISPLAY_FALLBACK_REASON_RENDERED_TOO_LARGE",
  "DISPLAY_TREE_MAGIC",
  "DISPLAY_TREE_WIRE_VERSION",
  "DISPLAY_TREE_LITTLE_ENDIAN",
  "DISPLAY_TREE_ROOT_DEPTH",
  "DISPLAY_TREE_MAGIC_BITS",
  "DISPLAY_TREE_VERSION_BITS",
  "DISPLAY_TREE_KIND_BITS",
  "DISPLAY_TREE_PAYLOAD_LENGTH_BITS",
  "DISPLAY_TREE_CHILD_COUNT_BITS",
  "DISPLAY_NODE_TAG_TEXT",
  "DISPLAY_NODE_TAG_STRING",
  "DISPLAY_NODE_TAG_NUMBER",
  "DISPLAY_NODE_TAG_BOOLEAN",
  "DISPLAY_NODE_TAG_NULL",
  "DISPLAY_NODE_TAG_UNDEFINED",
  "DISPLAY_NODE_TAG_ERROR",
  "DISPLAY_NODE_TAG_KEY",
  "DISPLAY_NODE_TAG_TYPE_TAG",
  "DISPLAY_NODE_TAG_CYCLE",
  "DISPLAY_NODE_TAG_TRUNCATION",
]);

function sha256(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function relative(filePath) {
  return path.relative(repoRoot, filePath).split(path.sep).join("/");
}

function splitTemplate(template, placeholder, label) {
  const first = template.indexOf(placeholder);
  const last = template.lastIndexOf(placeholder);
  if (first < 0 || first !== last) {
    throw new Error(`${label} must contain exactly one ${placeholder} placeholder`);
  }
  return [
    template.slice(0, first),
    template.slice(first + placeholder.length),
  ];
}

function rustString(value) {
  let output = '"';
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    switch (character) {
      case "\\":
        output += "\\\\";
        break;
      case '"':
        output += '\\"';
        break;
      case "\n":
        output += "\\n";
        break;
      case "\r":
        output += "\\r";
        break;
      case "\t":
        output += "\\t";
        break;
      default:
        output +=
          codePoint < 0x20 || (codePoint >= 0x7f && codePoint <= 0x9f)
            ? `\\u{${codePoint.toString(16)}}`
            : character;
    }
  }
  return `${output}"`;
}

function rustUtf8Bytes(value) {
  return `&[${[...Buffer.from(value, "utf8")].join(", ")}]`;
}

function rustStringSlice(values) {
  return `&[${values.map((value) => rustString(value)).join(", ")}]`;
}

function assertUnique(values, label) {
  if (values.length !== new Set(values).size) {
    throw new Error(`${label} contains duplicate values`);
  }
}

function validateSemanticAnnex(annex) {
  const tagValues = Object.values(annex.displayTreeWire.nodeTags);
  assertUnique(tagValues, "displayTreeWire.nodeTags");
  if (tagValues.some((value) => value <= 0 || value > 0xffff)) {
    throw new Error("displayTreeWire.nodeTags must fit a nonzero u16");
  }
  if (!/^[\x20-\x7e]{4}$/.test(annex.displayTreeWire.magic)) {
    throw new Error("displayTreeWire.magic must be exactly four printable ASCII bytes");
  }
  if (annex.displayTreeWire.endianness !== "little") {
    throw new Error("only the v1 little-endian IBDX grammar is supported");
  }
  if (
    annex.displayTreeWire.headerOrder.join(",") !== "magic,version" ||
    annex.displayTreeWire.nodeOrder.join(",") !==
      "kind,payloadLength,payload,childCount,children"
  ) {
    throw new Error("displayTreeWire field order does not describe IBDX v1");
  }
  splitTemplate(
    annex.renderText.truncationTemplate,
    "{omitted}",
    "renderText.truncationTemplate",
  );
  splitTemplate(
    annex.renderText.fallbackTemplate,
    "{reason}",
    "renderText.fallbackTemplate",
  );
  splitTemplate(
    annex.renderText.unknownNodeTemplate,
    "{tag}",
    "renderText.unknownNodeTemplate",
  );
  const styles = [
    annex.ansiStyles.reset,
    ...Object.values(annex.ansiStyles.session),
    ...Object.values(annex.ansiStyles.display),
  ];
  if (styles.some((style) => !/^\x1b\[[0-9;]+m$/.test(style))) {
    throw new Error("ansiStyles may contain only fixed SGR tokens");
  }
  const unbound = [
    annex.timings.shutdownDrain,
    annex.timings.cancellation,
    annex.timings.completion,
    annex.timings.asyncStormCoalescingWindow,
  ];
  if (
    unbound.some(
      (timing) =>
        timing.milliseconds !== null ||
        timing.onExpiry !== "unbound-engine-dependent",
    )
  ) {
    throw new Error("engine-dependent v1 timing values must remain explicitly unbound");
  }
}

export function loadSessionConstants(
  filePath = sessionConstantsSourcePath,
  { requireCanonical = true } = {},
) {
  const source = fs.readFileSync(filePath, "utf8");
  const annex = JSON.parse(source);
  if (requireCanonical && source !== canonicalJson(annex)) {
    throw new Error(`${relative(filePath)} is not canonical two-space JSON`);
  }
  const schemaSource = fs.readFileSync(sessionConstantsSchemaPath, "utf8");
  const schema = JSON.parse(schemaSource);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(schema);
  if (!validate(annex)) {
    throw new Error(
      `session constants schema validation failed:\n${JSON.stringify(validate.errors, null, 2)}`,
    );
  }
  validateSemanticAnnex(annex);
  return { annex, source, schemaSource };
}

export function validateInterruptStatusBinding(
  annex,
  interruptSource = fs.readFileSync(interruptMachineSourcePath, "utf8"),
) {
  const labels = [...interruptSource.matchAll(/interrupt-(\d+)/g)].map(
    (match) => Number(match[1]),
  );
  if (labels.length === 0) {
    throw new Error("interrupt machine exposes no numeric interrupt status vocabulary");
  }
  const unexpected = [...new Set(labels)].filter(
    (status) => status !== annex.exitStatuses.interrupt,
  );
  if (unexpected.length > 0) {
    throw new Error(
      `interrupt machine status vocabulary diverges from annex: ${unexpected.join(", ")}`,
    );
  }
}

export function validateTerminalBinding(
  annex,
  terminalSource = fs.readFileSync(terminalSessionSourcePath, "utf8"),
) {
  const testModuleMarker = "\n#[cfg(test)]\nmod tests {";
  const testModuleIndex = terminalSource.indexOf(testModuleMarker);
  if (testModuleIndex < 0) {
    throw new Error("terminal_session.rs is missing its expected test-module boundary");
  }
  const production = terminalSource.slice(0, testModuleIndex);
  const generatedModule =
    '#[path = "../../../vendored-generated/session_constants.generated.rs"]\nmod session_constants;';
  if (!production.includes(generatedModule)) {
    throw new Error("terminal_session.rs does not load the generated session constants module");
  }
  const missing = REQUIRED_TERMINAL_BINDINGS.filter(
    (name) => !new RegExp(`\\b${name}\\b`).test(production),
  );
  if (missing.length > 0) {
    throw new Error(
      `terminal_session.rs is missing generated constant bindings: ${missing.join(", ")}`,
    );
  }

  const forbiddenDeclarations = [
    "BROKER_QUEUE_BOUND_BYTES",
    "DISPLAY_TREE_MAX_SERIALIZED_BYTES",
    "DISPLAY_RENDER_DEPTH",
    "DISPLAY_RENDER_BREADTH",
    "DISPLAY_PAYLOAD_SCALARS",
    "BROKER_FLUSH_BUDGET_MILLIS",
    "MAX_LIVE_RELAYS",
    "DISPLAY_TREE_WIRE_VERSION",
    "DISPLAY_TREE_MAGIC",
  ];
  for (const name of forbiddenDeclarations) {
    const declaration = new RegExp(
      `(?:pub\\s+)?const\\s+${name}\\s*[:=]`,
    );
    if (declaration.test(production)) {
      throw new Error(`terminal_session.rs redeclares generated constant ${name}`);
    }
  }

  const forbiddenText = [
    annex.promptTokens.defaultText,
    ...Object.values(annex.notices),
    annex.renderText.truncationTemplate,
    annex.renderText.fallbackTemplate,
    annex.renderText.unknownNodeTemplate,
    ...Object.values(annex.renderText.fallbackReasons),
  ];
  for (const literal of forbiddenText) {
    if (production.includes(literal)) {
      throw new Error(
        `terminal_session.rs contains annex-owned literal ${JSON.stringify(literal)}`,
      );
    }
  }
  const forbiddenPatterns = [
    [/b"IBDX"/, "IBDX magic literal"],
    [/\\x1b\[[0-9;]+m/, "handwritten ANSI SGR token"],
    [/b"\\r\\x1b\[2K"/, "handwritten prompt erase token"],
    [/\b0x03\b/, "handwritten interrupt byte"],
    [/status\s*&\s*0xff/, "handwritten POSIX status mask"],
    [/latch_cause\([^;]*,\s*(?:70|141)\s*\)/s, "handwritten fixed exit status"],
    [/Text\s*=\s*1\b/, "handwritten IBDX node tags"],
  ];
  for (const [pattern, label] of forbiddenPatterns) {
    if (pattern.test(production)) {
      throw new Error(`terminal_session.rs contains ${label}`);
    }
  }

  const grammarBindings = [
    [
      /cursor\.take\(DISPLAY_TREE_MAGIC\.len\(\)\)\?\s*!=\s*DISPLAY_TREE_MAGIC/,
      "IBDX magic check",
    ],
    [
      /cursor\.u16\(\)\?\s*!=\s*DISPLAY_TREE_WIRE_VERSION/,
      "IBDX version check",
    ],
    [
      /let raw_kind = cursor\.u16\(\)\?;\s*let payload_length =\s*usize::try_from\(cursor\.u32\(\)\?\)[^;]*;\s*let payload = cursor\.take\(payload_length\)\?;\s*let child_count = cursor\.u32\(\)\?;/s,
      "IBDX node field order",
    ],
    [/u16::from_le_bytes\(bytes\)/, "little-endian u16 decoder"],
    [/u32::from_le_bytes\(bytes\)/, "little-endian u32 decoder"],
    [
      /Some\(generated::StatusClass::Interrupt130\)\s*if status == EXIT_STATUS_INTERRUPT/,
      "interrupt-status equality guard",
    ],
  ];
  for (const [pattern, label] of grammarBindings) {
    if (!pattern.test(production)) {
      throw new Error(`terminal_session.rs is missing the annex-bound ${label}`);
    }
  }
}

function renderRust(annex, binding) {
  const [truncationPrefix, truncationSuffix] = splitTemplate(
    annex.renderText.truncationTemplate,
    "{omitted}",
    "renderText.truncationTemplate",
  );
  const [fallbackPrefix, fallbackSuffix] = splitTemplate(
    annex.renderText.fallbackTemplate,
    "{reason}",
    "renderText.fallbackTemplate",
  );
  const [unknownNodePrefix, unknownNodeSuffix] = splitTemplate(
    annex.renderText.unknownNodeTemplate,
    "{tag}",
    "renderText.unknownNodeTemplate",
  );
  const { promptTokens, ansiStyles, notices, exitStatuses, timings, limits } =
    annex;
  const { renderText, displayTreeWire } = annex;
  const lines = [
    "// @generated by packages/ibex-devtools/src/scripts/generate-session-constants.mjs",
    "// Source: session/session-constants.v1.json",
    `// Source SHA-256: ${binding.sourceDigest}`,
    "// Schema: session/schema/session-constants.schema.json",
    `// Schema SHA-256: ${binding.schemaDigest}`,
    `// Generator SHA-256: ${binding.generatorDigest}`,
    "// Do not edit by hand.",
    "// @ref LLP 0025#12-constants — generated projection of the v1 annex",
    "",
    "#![allow(dead_code)]",
    "",
    "pub const SESSION_CONSTANTS_SOURCE_SHA256: &str =",
    `    ${rustString(binding.sourceDigest)};`,
    "pub const SESSION_CONSTANTS_SCHEMA_SHA256: &str =",
    `    ${rustString(binding.schemaDigest)};`,
    "pub const SESSION_CONSTANTS_GENERATOR_SHA256: &str =",
    `    ${rustString(binding.generatorDigest)};`,
    `pub const SESSION_CONSTANTS_VERSION: u32 = ${annex.version};`,
    "",
    `pub const PROMPT_DEFAULT_TEXT: &str = ${rustString(promptTokens.defaultText)};`,
    `pub const PROMPT_INTERRUPT_BYTE: u8 = ${promptTokens.interruptByte};`,
    `pub const PROMPT_EDITOR_ERASE_BYTES: &[u8] = ${rustUtf8Bytes(promptTokens.editorErase)};`,
    `pub const PROMPT_TRANSCRIPT_BOUNDARY_BYTES: &[u8] = ${rustUtf8Bytes(promptTokens.transcriptBoundary)};`,
    `pub const ANSI_RESET: &str = ${rustString(ansiStyles.reset)};`,
    `pub const ANSI_SESSION_PROMPT: &str = ${rustString(ansiStyles.session.prompt)};`,
    `pub const ANSI_SESSION_NOTICE: &str = ${rustString(ansiStyles.session.notice)};`,
    `pub const ANSI_SESSION_ERROR: &str = ${rustString(ansiStyles.session.error)};`,
    `pub const ANSI_DISPLAY_STRING: &str = ${rustString(ansiStyles.display.string)};`,
    `pub const ANSI_DISPLAY_NUMBER: &str = ${rustString(ansiStyles.display.number)};`,
    `pub const ANSI_DISPLAY_KEYWORD: &str = ${rustString(ansiStyles.display.keyword)};`,
    `pub const ANSI_DISPLAY_ERROR: &str = ${rustString(ansiStyles.display.error)};`,
    `pub const ANSI_DISPLAY_KEY: &str = ${rustString(ansiStyles.display.key)};`,
    `pub const ANSI_DISPLAY_TYPE_TAG: &str = ${rustString(ansiStyles.display.typeTag)};`,
    `pub const ANSI_DISPLAY_TRUNCATION: &str = ${rustString(ansiStyles.display.truncation)};`,
    "",
    `pub const NOTICE_ORDERLY_PROMISE: &str = ${rustString(notices.orderlyPromise)};`,
    `pub const NOTICE_CANCELLING_WORK: &str = ${rustString(notices.cancellingWork)};`,
    `pub const NOTICE_WORK_IN_FLIGHT: &str = ${rustString(notices.workInFlight)};`,
    "pub const NOTICE_CANCELLING_COMPLETION: &str =",
    `    ${rustString(notices.cancellingCompletion)};`,
    `pub const NOTICE_INPUT_DISCARDED: &str = ${rustString(notices.inputDiscarded)};`,
    "",
    `pub const EXIT_STATUS_ORDERLY_DEFAULT: i32 = ${exitStatuses.orderlyDefault};`,
    `pub const EXIT_STATUS_NON_INTERACTIVE_FAILURE: i32 = ${exitStatuses.nonInteractiveFailure};`,
    `pub const EXIT_STATUS_WORKER_COMMIT_UNACKNOWLEDGED: i32 = ${exitStatuses.workerCommitUnacknowledged};`,
    `pub const EXIT_STATUS_ENGINE_FAULT: i32 = ${exitStatuses.cancellationOrEngineFault};`,
    `pub const EXIT_STATUS_STARTUP_FAILURE: i32 = ${exitStatuses.startupFailure};`,
    `pub const EXIT_STATUS_SIGHUP: i32 = ${exitStatuses.sighup};`,
    `pub const EXIT_STATUS_INTERRUPT: i32 = ${exitStatuses.interrupt};`,
    `pub const EXIT_STATUS_SIGQUIT: i32 = ${exitStatuses.sigquit};`,
    `pub const EXIT_STATUS_BROKEN_PIPE: i32 = ${exitStatuses.brokenPipe};`,
    `pub const EXIT_STATUS_SIGTERM: i32 = ${exitStatuses.sigterm};`,
    `pub const POSIX_EXIT_STATUS_MASK: i32 = ${exitStatuses.posixStatusMask};`,
    "",
    `pub const BROKER_FLUSH_BUDGET_MILLIS: u64 = ${timings.brokerFlush.milliseconds};`,
    `pub const HISTORY_LOCK_ACQUISITION_MILLIS: u64 = ${timings.historyLockAcquisition.milliseconds};`,
    `pub const LIFECYCLE_COMMIT_ACK_MILLIS: u64 = ${timings.lifecycleCommitAck.milliseconds};`,
    "pub const SHUTDOWN_DRAIN_BUDGET_MILLIS: Option<u64> = None;",
    "pub const CANCELLATION_BUDGET_MILLIS: Option<u64> = None;",
    "pub const COMPLETION_BUDGET_MILLIS: Option<u64> = None;",
    "pub const ASYNC_STORM_COALESCING_WINDOW_MILLIS: Option<u64> = None;",
    "",
    `pub const DISPLAY_RENDER_DEPTH: usize = ${limits.rendererDepth.value};`,
    `pub const DISPLAY_RENDER_BREADTH: usize = ${limits.rendererBreadth.value};`,
    `pub const DISPLAY_PAYLOAD_SCALARS: usize = ${limits.rendererPayload.value};`,
    `pub const HISTORY_MAX_ENTRIES: usize = ${limits.historyEntries.value};`,
    `pub const HISTORY_MAX_BYTES: usize = ${limits.historyBytes.value};`,
    `pub const HISTORY_RECORD_MAX_BYTES: usize = ${limits.historyRecordBytes.value};`,
    `pub const BROKER_QUEUE_BOUND_BYTES: usize = ${limits.brokerQueueBytes.value};`,
    `pub const DISPLAY_TREE_MAX_SERIALIZED_BYTES: usize = ${limits.displayTreeSerializedBytes.value};`,
    `pub const MAX_LIVE_RELAYS: usize = ${limits.liveRelays.value};`,
    `pub const MAX_INPUT_BYTES: usize = ${limits.inputBytes.value};`,
    "",
    `pub const RENDER_CHILDREN_OPEN: &[u8] = ${rustUtf8Bytes(renderText.childrenOpen)};`,
    `pub const RENDER_CHILDREN_SEPARATOR: &[u8] = ${rustUtf8Bytes(renderText.childrenSeparator)};`,
    `pub const RENDER_CHILDREN_CLOSE: &[u8] = ${rustUtf8Bytes(renderText.childrenClose)};`,
    `pub const RENDER_PAYLOAD_TRUNCATION_SEPARATOR: &[u8] = ${rustUtf8Bytes(renderText.payloadTruncationSeparator)};`,
    `pub const TRUNCATION_PREFIX: &str = ${rustString(truncationPrefix)};`,
    `pub const TRUNCATION_SUFFIX: &str = ${rustString(truncationSuffix)};`,
    `pub const DISPLAY_FALLBACK_PREFIX: &str = ${rustString(fallbackPrefix)};`,
    `pub const DISPLAY_FALLBACK_SUFFIX: &str = ${rustString(fallbackSuffix)};`,
    `pub const UNKNOWN_DISPLAY_NODE_PREFIX: &str = ${rustString(unknownNodePrefix)};`,
    `pub const UNKNOWN_DISPLAY_NODE_SUFFIX: &str = ${rustString(unknownNodeSuffix)};`,
    `pub const DISPLAY_FALLBACK_REASON_OVERSIZE_TREE: &str = ${rustString(renderText.fallbackReasons.oversizeTree)};`,
    "pub const DISPLAY_FALLBACK_REASON_MALFORMED_OR_UNKNOWN_TREE: &str =",
    `    ${rustString(renderText.fallbackReasons.malformedOrUnknownTree)};`,
    "pub const DISPLAY_FALLBACK_REASON_RENDERED_TOO_LARGE: &str =",
    `    ${rustString(renderText.fallbackReasons.renderedDisplayTooLarge)};`,
    "",
    `pub const DISPLAY_TREE_MAGIC: &[u8; 4] = b${rustString(displayTreeWire.magic)};`,
    `pub const DISPLAY_TREE_WIRE_VERSION: u16 = ${displayTreeWire.version};`,
    `pub const DISPLAY_TREE_ENDIANNESS: &str = ${rustString(displayTreeWire.endianness)};`,
    "pub const DISPLAY_TREE_LITTLE_ENDIAN: bool = true;",
    `pub const DISPLAY_TREE_ROOT_DEPTH: usize = ${displayTreeWire.rootDepth};`,
    `pub const DISPLAY_TREE_HEADER_ORDER: &[&str] = ${rustStringSlice(displayTreeWire.headerOrder)};`,
    "pub const DISPLAY_TREE_NODE_ORDER: &[&str] =",
    `    ${rustStringSlice(displayTreeWire.nodeOrder)};`,
    `pub const DISPLAY_TREE_MAGIC_BITS: u8 = ${displayTreeWire.fieldWidthsBits.magic};`,
    `pub const DISPLAY_TREE_VERSION_BITS: u8 = ${displayTreeWire.fieldWidthsBits.version};`,
    `pub const DISPLAY_TREE_KIND_BITS: u8 = ${displayTreeWire.fieldWidthsBits.kind};`,
    `pub const DISPLAY_TREE_PAYLOAD_LENGTH_BITS: u8 = ${displayTreeWire.fieldWidthsBits.payloadLength};`,
    `pub const DISPLAY_TREE_CHILD_COUNT_BITS: u8 = ${displayTreeWire.fieldWidthsBits.childCount};`,
    `pub const DISPLAY_NODE_TAG_TEXT: u16 = ${displayTreeWire.nodeTags.text};`,
    `pub const DISPLAY_NODE_TAG_STRING: u16 = ${displayTreeWire.nodeTags.string};`,
    `pub const DISPLAY_NODE_TAG_NUMBER: u16 = ${displayTreeWire.nodeTags.number};`,
    `pub const DISPLAY_NODE_TAG_BOOLEAN: u16 = ${displayTreeWire.nodeTags.boolean};`,
    `pub const DISPLAY_NODE_TAG_NULL: u16 = ${displayTreeWire.nodeTags.null};`,
    `pub const DISPLAY_NODE_TAG_UNDEFINED: u16 = ${displayTreeWire.nodeTags.undefined};`,
    `pub const DISPLAY_NODE_TAG_ERROR: u16 = ${displayTreeWire.nodeTags.error};`,
    `pub const DISPLAY_NODE_TAG_KEY: u16 = ${displayTreeWire.nodeTags.key};`,
    `pub const DISPLAY_NODE_TAG_TYPE_TAG: u16 = ${displayTreeWire.nodeTags.typeTag};`,
    `pub const DISPLAY_NODE_TAG_CYCLE: u16 = ${displayTreeWire.nodeTags.cycle};`,
    `pub const DISPLAY_NODE_TAG_TRUNCATION: u16 = ${displayTreeWire.nodeTags.truncation};`,
    "",
  ];
  return lines.join("\n");
}

export function renderSessionConstants(
  annex,
  {
    source = canonicalJson(annex),
    schemaSource = fs.readFileSync(sessionConstantsSchemaPath, "utf8"),
    generatorSource = fs.readFileSync(generatorPath, "utf8"),
  } = {},
) {
  validateSemanticAnnex(annex);
  const binding = {
    sourceDigest: sha256(source),
    schemaDigest: sha256(schemaSource),
    generatorDigest: sha256(generatorSource),
  };
  return { rust: renderRust(annex, binding), binding };
}

export function checkSessionConstantsArtifact(rendered) {
  try {
    assertConfinedGeneratedFile(
      repoRoot,
      generatedSessionConstantsPath,
      "session constants Rust module",
    );
  } catch {
    return [relative(generatedSessionConstantsPath)];
  }
  return fs.readFileSync(generatedSessionConstantsPath, "utf8") === rendered.rust
    ? []
    : [relative(generatedSessionConstantsPath)];
}

export function writeSessionConstantsArtifact(rendered) {
  writeGeneratedFilesTransactionally(
    repoRoot,
    [
      {
        path: generatedSessionConstantsPath,
        content: rendered.rust,
        label: "session constants Rust module",
      },
    ],
    () => {
      const stale = checkSessionConstantsArtifact(rendered);
      if (stale.length > 0) {
        throw new Error(
          `generated session constants failed validation: ${stale.join(", ")}`,
        );
      }
    },
  );
}

function main(argv) {
  const write = argv.includes("--write");
  const check = argv.includes("--check");
  const unknown = argv.filter((argument) => !["--write", "--check"].includes(argument));
  if (unknown.length > 0 || write === check) {
    throw new Error(
      "usage: bun packages/ibex-devtools/src/scripts/generate-session-constants.mjs (--write|--check)",
    );
  }
  const { annex, source, schemaSource } = loadSessionConstants();
  validateInterruptStatusBinding(annex);
  validateTerminalBinding(annex);
  const rendered = renderSessionConstants(annex, { source, schemaSource });
  if (write) {
    writeSessionConstantsArtifact(rendered);
    console.log(`wrote ${relative(generatedSessionConstantsPath)}`);
    return;
  }
  const stale = checkSessionConstantsArtifact(rendered);
  if (stale.length > 0) {
    console.error(`session constants generated artifacts are stale: ${stale.join(", ")}`);
    process.exitCode = 1;
  } else {
    console.log(
      `session constants checked: v${annex.version} source ${rendered.binding.sourceDigest}`,
    );
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.stack : String(error));
    process.exitCode = 1;
  }
}
